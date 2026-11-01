#!/usr/bin/env python3
"""Threat notifier.

Watches CISA's Known Exploited Vulnerabilities (KEV) catalog, high-severity CVEs
from NVD (filtered by EPSS, exposure and a tiered vendor watchlist) and security
news feeds, then pushes alerts to your phone (ntfy, Telegram or Pushover) and
urgent ones to Alexa through Voice Monkey.

Built to run on a GitHub Actions schedule. No AI services or paid APIs are used.
"""

from __future__ import annotations

import argparse
import calendar
import hashlib
import html
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, fields
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable
from zoneinfo import ZoneInfo

import feedparser
import requests
import yaml

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"
VOICEMONKEY_URL = "https://api-v3.voicemonkey.io/announce"
PUSHOVER_URL = "https://api.pushover.net/1/messages.json"
TELEGRAM_URL = "https://api.telegram.org/bot{token}/sendMessage"
RANSOMWARE_LIVE_URL = "https://api-pro.ransomware.live/victims/recent"  # free key, sent as X-API-KEY
RANSOMWARE_LIVE_VICTIMS_URL = "https://api-pro.ransomware.live/victims/"  # filtered by country and month
USER_AGENT = "threat-notifier/1.1 (personal security alerting script)"

PRIORITY_RANK = {"normal": 0, "high": 1, "urgent": 2}
NTFY_TAGS = {"normal": ["newspaper"], "high": ["warning"], "urgent": ["rotating_light"]}
TELEGRAM_ICON = {"normal": "\U0001F4F0", "high": "⚠️", "urgent": "\U0001F6A8"}

FAILURE_WARN_AFTER = 12      # consecutive failed runs before a source-health alert
EPSS_RECHECK = timedelta(hours=6)
ALERTED_RETENTION = timedelta(days=60)
OUTBOX_MAX_ATTEMPTS = 6
FEED_SEEN_LIMIT = 2000       # must exceed the longest feed (Huntress returns ~750 items)

# Paths and file names in CVE text ("/admin/login.php") must not count as product names.
PATH_TOKENS = re.compile(r"\S*[/\\]\S*|\b[\w.-]+\.(?:php|aspx?|jsp|cgi|html?|do|action)\b", re.IGNORECASE)

# Story grouping: one news alert per story, however many outlets cover it.
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
STORY_WORD = re.compile(r"[a-z0-9]+")


def story_word(word: str) -> str:
    """Light normalisation so 'patches' and 'patch' or 'networks' and 'network' compare equal."""
    if len(word) > 4 and word.endswith("ies"):
        return word[:-3] + "y"
    if len(word) > 4 and word.endswith("es") and word[-3] in "sxz":
        return word[:-2]
    if len(word) > 3 and word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


# Words that say nothing about which story it is, so they never count as shared words.
STORY_STOPWORDS = {story_word(w) for w in """
    a about after against all amid an and any are as at be been but by can could did does for from
    has have how in into is it its may more new no not now of on or our out over says said than that the
    their these this those to under up via was what when which who why will with without you your
    security vulnerability vulnerabilities flaw flaws bug bugs issue issues patch patches patched
    update updates fix fixes fixed critical severe high attack attacks attacked attacker attackers
    hacker hackers exploit exploits exploited exploiting exploitation actively active zero day warns
    warning urges users customers researchers report reports news week today
""".split()}

SLEEP: Callable[[float], None] = time.sleep  # swapped out in tests


@dataclass
class Alert:
    key: str
    title: str
    body: str
    url: str
    priority: str          # normal | high | urgent
    speech: str = ""       # what Alexa says; empty means never announce
    source: str = ""
    attempts: int = 0
    private: bool = False  # names a ransomware victim: phone only, never logs, summaries or saved state
    public_label: str = ""  # what logs and summaries show instead of the title when private


# --------------------------------------------------------------------------- helpers

def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def clean_text(value: str | None, limit: int) -> str:
    text = re.sub(r"<[^>]+>", " ", value or "")
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def scrub_paths(text: str) -> str:
    return re.sub(r"\s+", " ", PATH_TOKENS.sub(" ", text or "")).strip()


def fmt_epss(score: tuple[float, float]) -> str:
    probability, percentile = score
    pct = probability * 100
    shown = f"{pct:.1f}%" if pct < 10 else f"{pct:.0f}%"
    return f"EPSS {shown} (percentile {percentile * 100:.0f})"


def unauth_network(vector: str | None) -> bool | None:
    """True when the CVSS vector says network attack with no privileges; None when unknown."""
    if not vector:
        return None
    return "AV:N" in vector and "PR:N" in vector


class TermMatcher:
    """Whole-term, case-insensitive matching. 'sap' never matches 'sapphire', and
    'palo alto networks' also matches 'paloaltonetworks' as written in CPE names.
    With plurals=True a term also matches with 's' or 'es' on the end ('backdoor' matches
    'backdoors'); it still reports the term as written."""

    def __init__(self, terms: Iterable[str], plurals: bool = False) -> None:
        variants: set[str] = set()
        for term in terms:
            term = str(term or "").strip().lower()
            if not term:
                continue
            variants.add(term)
            squashed = re.sub(r"[\s\-_.]+", "", term)
            if len(squashed) >= 4:
                variants.add(squashed)
        ordered = sorted(variants, key=len, reverse=True)
        self.pattern = (
            re.compile(r"(?<![a-z0-9])(" + "|".join(re.escape(t) for t in ordered) + r")"
                       + (r"(?:e?s)?" if plurals else "") + r"(?![a-z0-9])", re.IGNORECASE)
            if ordered
            else None
        )

    def find(self, text: str) -> list[str]:
        if not self.pattern or not text:
            return []
        found: list[str] = []
        for match in self.pattern.finditer(text):
            term = match.group(1).lower()
            if term not in found:
                found.append(term)
        return found


def in_quiet_hours(local_time: dtime, spec: str | None) -> bool:
    if not spec:
        return False
    try:
        start_s, end_s = spec.split("-")
        start, end = dtime.fromisoformat(start_s.strip()), dtime.fromisoformat(end_s.strip())
    except ValueError:
        return False
    if start <= end:
        return start <= local_time < end
    return local_time >= start or local_time < end


DAY_NAMES = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


def quiet_range_for(day: Any, spec: Any) -> tuple[dtime, dtime] | None:
    """The quiet range for the morning of `day`. `spec` is one "HH:MM-HH:MM" string for
    every day, or a mapping with weekdays/weekends and optional single-day overrides."""
    if isinstance(spec, dict):
        name = DAY_NAMES[day.weekday()]
        spec = spec[name] if name in spec else spec.get("weekends" if day.weekday() >= 5 else "weekdays")
    if not spec:
        return None
    try:
        start_s, end_s = str(spec).split("-")
        start, end = dtime.fromisoformat(start_s.strip()), dtime.fromisoformat(end_s.strip())
    except ValueError:
        return None
    return None if start == end else (start, end)


def quiet_until(local: datetime, spec: Any) -> datetime | None:
    """When the quiet period that `local` falls in ends, or None if Alexa may speak.
    Each range belongs to the morning it ends on, so an overnight range such as
    23:00-08:00 for Monday starts at 23:00 on Sunday."""
    for day in (local.date(), local.date() + timedelta(days=1)):
        window = quiet_range_for(day, spec)
        if not window:
            continue
        start, end = window
        start_day = day - timedelta(days=1) if start > end else day
        start_at = datetime.combine(start_day, start, tzinfo=local.tzinfo)
        end_at = datetime.combine(day, end, tzinfo=local.tzinfo)
        if start_at <= local < end_at:
            return end_at
    return None


# --------------------------------------------------------------------------- HTTP

class Http:
    """Thin wrapper around requests so tests can swap in canned responses."""

    def __init__(self, timeout: int = 45) -> None:
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.timeout = timeout

    def _get(self, url: str, params: dict | None = None, headers: dict | None = None,
             retries: int = 3, backoff: float = 6.0) -> requests.Response:
        error: Exception | None = None
        for attempt in range(retries):
            try:
                resp = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
            except requests.RequestException as exc:
                error = exc
            else:
                if resp.status_code in (403, 429) or resp.status_code >= 500:
                    error = RuntimeError(f"HTTP {resp.status_code}")
                elif resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}")
                else:
                    return resp
            if attempt < retries - 1:
                SLEEP(backoff * (attempt + 1))
        raise RuntimeError(str(error))

    def get_json(self, url: str, params: dict | None = None, headers: dict | None = None, **kw: Any) -> Any:
        return self._get(url, params=params, headers=headers, **kw).json()

    def get_bytes(self, url: str, **kw: Any) -> bytes:
        return self._get(url, **kw).content

    def post(self, url: str, json_body: Any = None, form: dict | None = None, headers: dict | None = None) -> None:
        resp = self.session.post(url, json=json_body, data=form, headers=headers, timeout=self.timeout)
        if resp.status_code >= 400:
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:200]}")


# --------------------------------------------------------------------------- sources

def fetch_kev(http: Http) -> list[dict]:
    return http.get_json(KEV_URL).get("vulnerabilities", [])


def nvd_time(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def fetch_nvd(http: Http, start: datetime, end: datetime, api_key: str | None, page_size: int = 2000) -> list[dict]:
    headers = {"apiKey": api_key} if api_key else None
    pause = 1.0 if api_key else 6.5  # NVD allows 5 requests per 30 seconds without a key
    results: list[dict] = []
    index = 0
    while True:
        params = {
            "lastModStartDate": nvd_time(start),
            "lastModEndDate": nvd_time(end),
            "startIndex": index,
            "resultsPerPage": page_size,
        }
        data = http.get_json(NVD_URL, params=params, headers=headers, backoff=10.0)
        batch = data.get("vulnerabilities") or []
        results.extend(item.get("cve", {}) for item in batch)
        index += len(batch)
        if not batch or index >= int(data.get("totalResults", 0)):
            return results
        SLEEP(pause)


def fetch_nvd_cve(http: Http, cve_id: str, api_key: str | None) -> dict | None:
    """One CVE's NVD record, or None if NVD doesn't have it."""
    headers = {"apiKey": api_key} if api_key else None
    data = http.get_json(NVD_URL, params={"cveId": cve_id}, headers=headers, backoff=10.0)
    for item in data.get("vulnerabilities") or []:
        if (item.get("cve") or {}).get("id") == cve_id:
            return item["cve"]
    return None


def fetch_epss(http: Http, cve_ids: Iterable[str]) -> dict[str, tuple[float, float]]:
    scores: dict[str, tuple[float, float]] = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), 100):
        data = http.get_json(EPSS_URL, params={"cve": ",".join(ids[i:i + 100])})
        for row in data.get("data") or []:
            try:
                scores[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
    return scores


def fetch_feed(http: Http, url: str) -> list[dict]:
    parsed = feedparser.parse(http.get_bytes(url, retries=1))
    if parsed.bozo and not parsed.entries:
        raise RuntimeError(f"could not parse feed ({parsed.get('bozo_exception')})")
    items = []
    for entry in parsed.entries:
        link = entry.get("link") or ""
        stamp = entry.get("published_parsed") or entry.get("updated_parsed")
        items.append({
            "id": entry.get("id") or link or entry.get("title", ""),
            "title": clean_text(entry.get("title"), 200),
            "link": link,
            "summary": clean_text(entry.get("summary"), 400),
            "published": datetime.fromtimestamp(calendar.timegm(stamp), tz=timezone.utc) if stamp else None,
        })
    return items


SOCIAL_TITLE_LENGTH = 140  # posts have no title: the alert title is the start of the post


def mastodon_feed_url(account: str) -> str:
    """https://server/@user or @user@server -> the profile's public RSS feed."""
    account = account.strip()
    if account.startswith("@") and account.count("@") == 2:
        user, server = account[1:].split("@")
        account = f"https://{server}/@{user}"
    if not re.match(r"https://[^/\s]+/@[\w.]+(\.rss)?$", account):
        raise ValueError(f"not a Mastodon profile: {account!r} (use https://server/@user)")
    return account if account.endswith(".rss") else account + ".rss"


def bluesky_feed_url(handle: str) -> str:
    """handle, @handle or https://bsky.app/profile/handle -> the profile's public RSS feed."""
    handle = re.sub(r"^https://bsky\.app/profile/", "", handle.strip()).strip("/").removesuffix("/rss").lstrip("@")
    if not re.match(r"^[\w-]+(\.[\w-]+)+$", handle):
        raise ValueError(f"not a Bluesky handle: {handle!r} (use e.g. name.bsky.social)")
    return f"https://bsky.app/profile/{handle}/rss"


def social_feeds(cfg: dict, errors: list[str]) -> list[dict]:
    """The social section's accounts as feeds. They always use the keyword filter."""
    social = cfg.get("social") or {}
    if social.get("enabled") is False:
        return []
    feeds = []
    for account in social.get("accounts") or []:
        if not isinstance(account, dict) or account.get("enabled") is False:
            continue
        name = account.get("name") or account.get("mastodon") or account.get("bluesky")
        try:
            if account.get("mastodon"):
                url = mastodon_feed_url(str(account["mastodon"]))
            elif account.get("bluesky"):
                url = bluesky_feed_url(str(account["bluesky"]))
            else:
                raise ValueError("needs a mastodon or bluesky entry")
        except ValueError as exc:
            errors.append(f"social account {name}: {exc}")
            continue
        feeds.append({"name": name, "url": url, "filter": "keywords",
                      "keywords": account.get("keywords") or social.get("keywords"), "social": True})
    return feeds


def post_title(item: dict) -> str:
    """A social post's title: the start of its text, cut at a word."""
    text = item["title"] or item["summary"]
    if len(text) <= SOCIAL_TITLE_LENGTH:
        return text
    return text[:SOCIAL_TITLE_LENGTH].rsplit(" ", 1)[0].rstrip(" ,.;:…") + "…"


def fetch_ransomware_victims(http: Http, url: str, api_key: str, params: dict | None = None) -> list[dict]:
    """Victims posted on ransomware leak sites, from ransomware.live's PRO API."""
    data = http.get_json(url, params=params, headers={"X-API-KEY": api_key}, retries=2)
    if isinstance(data, dict):
        for key in ("victims", "data", "results"):
            if isinstance(data.get(key), list):
                return data[key]
        return []
    return data if isinstance(data, list) else []


# --------------------------------------------------------------------------- CVE parsing

def best_cvss(metrics: dict) -> tuple[float, str, str] | None:
    """Highest base score across CVSS 4.0 and 3.x, from NVD or the CNA: (score, version, vector)."""
    best: tuple[float, str, str] | None = None
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            if data.get("baseScore") is None:
                continue
            score = float(data["baseScore"])
            if best is None or score > best[0]:
                best = (score, str(data.get("version", "")), str(data.get("vectorString", "")))
    return best


def cve_products(cve: dict) -> str:
    names: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                parts = (match.get("criteria") or "").split(":")
                if len(parts) > 4:
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in names:
                        names.append(name)
    return ", ".join(names[:4])


def cve_description(cve: dict) -> str:
    for desc in cve.get("descriptions") or []:
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


# --------------------------------------------------------------------------- watchlists

@dataclass
class Watchlists:
    core: TermMatcher
    extended: TermMatcher
    ignore: TermMatcher
    auto_vendors: list[str]
    msp_critical: TermMatcher  # a sub-list of core: RMM, PSA, remote access and identity providers


def build_watchlists(cfg: dict, state: dict, kev: list[dict] | None) -> Watchlists:
    raw = cfg.get("watchlist") or {}
    if isinstance(raw, list):  # older config: one flat list counts as core
        raw = {"core": raw}
    ignore_terms = list(raw.get("ignore") or [])
    ignore = TermMatcher(ignore_terms)
    auto: list[str] = list(state.get("kev_vendors") or [])
    if raw.get("auto_from_kev", True) and kev:
        counts: dict[str, int] = {}
        for entry in kev:
            vendor = (entry.get("vendorProject") or "").strip().lower()
            if vendor:
                counts[vendor] = counts.get(vendor, 0) + 1
        threshold = int(raw.get("auto_min_kev_entries", 5))
        auto = sorted(v for v, n in counts.items() if n >= threshold and not ignore.find(v))
        state["kev_vendors"] = auto
    elif not raw.get("auto_from_kev", True):
        auto = []
    msp_critical = list(raw.get("msp_critical") or [])
    return Watchlists(
        core=TermMatcher(list(raw.get("core") or []) + msp_critical),  # msp_critical vendors count as core
        extended=TermMatcher(list(raw.get("extended") or []) + auto),
        ignore=ignore,
        auto_vendors=auto,
        msp_critical=TermMatcher(msp_critical),
    )


# --------------------------------------------------------------------------- news stories

def story_fingerprint(title: str, lists: Watchlists) -> dict:
    """What identifies a story in a headline: CVE IDs, watchlist vendors and the remaining
    significant words. Vendor words and STORY_STOPWORDS are not counted as shared words."""
    cves = sorted({m.upper() for m in CVE_ID.findall(title)})
    vendor_hits = lists.core.find(title) + lists.extended.find(title)
    vendors = sorted({re.sub(r"[\s\-_.]+", "", v) for v in vendor_hits})
    vendor_words = {story_word(w) for v in vendor_hits for w in STORY_WORD.findall(v)}
    words = {story_word(w) for w in STORY_WORD.findall(CVE_ID.sub(" ", title.lower()))}
    words = sorted(w for w in words - STORY_STOPWORDS - vendor_words if len(w) >= 3 and not w.isdigit())
    return {"cves": cves, "vendors": vendors, "words": words}


def news_matcher(terms: Iterable[str] | None, news_cfg: dict) -> TermMatcher:
    """Matcher for the news word lists (keywords, hot and breach words): plurals count
    unless news.match_plurals is false."""
    return TermMatcher(terms or [], plurals=news_cfg.get("match_plurals", True) is not False)


def vendor_breach_priority(title: str, lists: Watchlists, breach_words: TermMatcher) -> str | None:
    """A headline naming a core vendor together with a breach word (breached, hacked, stolen...):
    high, or urgent when the vendor is on the msp_critical sub-list. None otherwise."""
    if not breach_words.find(title) or not lists.core.find(title):
        return None
    return "urgent" if lists.msp_critical.find(title) else "high"


def same_story(a: dict, b: dict, min_shared_words: int = 3) -> bool:
    """Same CVE ID in both titles, or the same vendor plus enough shared significant words."""
    if set(a.get("cves") or []) & set(b.get("cves") or []):
        return True
    return bool(set(a.get("vendors") or []) & set(b.get("vendors") or [])) and \
        len(set(a.get("words") or []) & set(b.get("words") or [])) >= min_shared_words


def group_news(candidates: list[dict], news_cfg: dict, state: dict, lists: Watchlists,
               now: datetime) -> list[Alert]:
    """One alert per story. Items covering the same story in this run are merged; items
    matching a story already alerted in the last story_window_hours are dropped. The
    alert keeps the highest priority, the earliest item's title and lists the other outlets."""
    window = timedelta(hours=float(news_cfg.get("story_window_hours", 24)))
    min_words = int(news_cfg.get("story_min_shared_words", 3))
    grouping = news_cfg.get("group_stories", True) is not False
    recent = [s for s in state.get("news_stories") or [] if (parse_iso(s.get("at")) or now) >= now - window]
    ordered = sorted(candidates, key=lambda c: c["item"]["published"] or now)
    groups: list[dict] = []
    for cand in ordered:
        fp = story_fingerprint(cand["item"]["title"], lists)
        if grouping:
            if any(same_story(fp, old, min_words) for old in recent):
                continue  # this story already alerted recently
            match = next((g for g in groups if any(same_story(fp, f, min_words) for f in g["fps"])), None)
            if match:
                match["members"].append(cand)
                match["fps"].append(fp)
                continue
        groups.append({"members": [cand], "fps": [fp]})

    alerts = []
    for group in groups:
        first = group["members"][0]
        item, name = first["item"], first["name"]
        others = []
        for member in group["members"][1:]:
            if member["name"] != name and member["name"] not in others:
                others.append(member["name"])
        body = item["summary"] or item["title"]
        if others:
            body += "\nAlso covered by: " + ", ".join(others)
        alerts.append(Alert(
            key=f"news:{name}:{first['ident']}",
            title=f"{name}: {item['title']}",
            body=body,
            url=item["link"],
            priority=max((m["priority"] for m in group["members"]), key=lambda p: PRIORITY_RANK[p]),
            speech=f"Security news from {name}. {item['title']}",
            source="news",
        ))
        if grouping:
            for member, fp in zip(group["members"], group["fps"]):
                recent.append(dict(fp, at=iso(now), outlet=member["name"]))
    if grouping and recent:
        state["news_stories"] = recent
    else:
        state.pop("news_stories", None)
    return alerts


# --------------------------------------------------------------------------- watched organisations

def watch_orgs(cfg: dict, env: dict) -> list[str]:
    """Clients and key suppliers to watch: config.yaml's watch_orgs plus the WATCH_ORGS
    secret (comma separated). The secret keeps real names out of the repository."""
    names = [str(n) for n in cfg.get("watch_orgs") or []]
    names += (env.get("WATCH_ORGS") or "").replace("\n", ",").split(",")
    out: list[str] = []
    for name in (n.strip() for n in names):
        if name and name.lower() not in {o.lower() for o in out}:
            out.append(name)
    return out


def mask_in_logs(values: Iterable[str], env: dict) -> None:
    """Ask GitHub Actions to hide these strings anywhere they appear in the run log."""
    if env.get("GITHUB_ACTIONS") == "true":
        for value in values:
            value = str(value or "").strip()
            if value:
                print(f"::add-mask::{value}")


def site_domain(website: str | None) -> str:
    domain = re.sub(r"^[a-z]+://", "", (website or "").strip().lower()).split("/")[0]
    return domain.removeprefix("www.")


COUNTRY_ALIASES = {"UK": "GB"}
COUNTRY_SPOKEN = {"GB": "the UK", "US": "the US"}


def watch_countries(rl: dict) -> list[str]:
    """ransomware_live.countries as ISO 3166-1 alpha-2 codes; UK is accepted for GB."""
    out: list[str] = []
    for code in (str(c).strip().upper() for c in rl.get("countries") or []):
        code = COUNTRY_ALIASES.get(code, code)
        if len(code) == 2 and code not in out:
            out.append(code)
    return out


def months_back(now: datetime, max_age: timedelta) -> list[tuple[int, int]]:
    """(year, month) pairs from the month max_age ago up to this month."""
    start = now - max_age
    year, month = start.year, start.month
    out = []
    while (year, month) <= (now.year, now.month):
        out.append((year, month))
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    return out


def ransomware_alerts(cfg: dict, state: dict, http: Http, env: dict, now: datetime,
                      errors: list[str], health_alerts: list[Alert]) -> list[Alert]:
    """Ransomware leak-site victims that matter to you: every victim in ransomware_live.countries,
    and any victim whose name or website matches watch_orgs. Alerts are private: the victim's
    name goes to the phone only, never to logs, run summaries or saved state."""
    rl = cfg.get("ransomware_live") or {}
    orgs = watch_orgs(cfg, env)
    countries = watch_countries(rl)
    if rl.get("enabled", True) is False or (not orgs and not countries):
        return []
    mask_in_logs(orgs, env)
    api_key = env.get("RANSOMWARE_LIVE_API_KEY")
    if not api_key:
        errors.append("ransomware.live: add the free RANSOMWARE_LIVE_API_KEY secret to use it")
        return []
    max_age = timedelta(days=float(rl.get("max_age_days", 7)))

    batches: list[list[dict]] = []
    try:
        if orgs:
            batches.append(fetch_ransomware_victims(http, rl.get("url") or RANSOMWARE_LIVE_URL, api_key))
        for country in countries:
            for year, month in months_back(now, max_age):
                batches.append(fetch_ransomware_victims(
                    http, rl.get("country_url") or RANSOMWARE_LIVE_VICTIMS_URL, api_key,
                    params={"country": country, "year": str(year), "month": f"{month:02d}"}))
        record_health(state, "ransomware.live", True, health_alerts, now)
    except Exception as exc:  # noqa: BLE001
        errors.append(f"ransomware.live: {exc}")
        record_health(state, "ransomware.live", False, health_alerts, now)
        return []
    victims: dict[str, dict] = {}
    for batch in batches:
        for victim in batch:
            if isinstance(victim, dict):
                name = str(victim.get("victim") or victim.get("post_title") or "").strip()
                group = str(victim.get("group") or victim.get("group_name") or "unknown group").strip()
                victims.setdefault(str(victim.get("id") or f"{name}@{group}"), victim)

    matcher = TermMatcher(orgs)
    alerted = state.get("alerted") or {}
    watch_priority = rl.get("priority") if rl.get("priority") in PRIORITY_RANK else "urgent"
    country_priority = rl.get("country_priority") if rl.get("country_priority") in PRIORITY_RANK else "high"
    alerts = []
    for ident, victim in victims.items():
        name = str(victim.get("victim") or victim.get("post_title") or "").strip()
        domain = site_domain(victim.get("website"))
        country = str(victim.get("country") or "").strip().upper()
        hits = matcher.find(f"{name} {domain}") if orgs else []
        in_country = country in countries
        if not name or not (hits or in_country):
            continue
        if hits:
            mask_in_logs([name, domain], env)
        key = "ransomware:" + hashlib.sha1(ident.encode("utf-8")).hexdigest()[:16]
        discovered = parse_iso(str(victim.get("discovered") or "").replace(" ", "T", 1))
        if key in alerted or (discovered and discovered < now - max_age):
            continue
        group = str(victim.get("group") or victim.get("group_name") or "unknown group").strip()
        attack = str(victim.get("attackdate") or victim.get("published") or "")[:10]
        details = [f"Group: {group}", f"discovered {discovered:%Y-%m-%d}" if discovered else "",
                   f"attack date {attack}" if attack else ""]
        place = [country, str(victim.get("activity") or "")]
        priorities = ([watch_priority] if hits else []) + ([country_priority] if in_country else [])
        if hits:
            speech = ("Ransomware alert. One of your watched organisations has been listed on a ransomware "
                      "leak site. Check your phone.")
            label = "Ransomware: a watched organisation was listed (details on your phone only)"
        else:
            speech = (f"Ransomware alert. An organisation in {COUNTRY_SPOKEN.get(country, country)} has been "
                      "listed on a ransomware leak site. Check your phone.")
            label = f"Ransomware: an organisation in {country} was listed (details on your phone only)"
        alerts.append(Alert(
            key=key,
            title=f"Ransomware: {name} listed by {group}",
            body="\n".join(filter(None, [
                f"Matches your watch list: {', '.join(hits)}" if hits else f"Ransomware victim in {country}",
                "; ".join(filter(None, details)),
                f"Website: {domain}" if domain else "",
                " · ".join(filter(None, place)),
                "Source: Ransomware.live",
            ])),
            url=str(victim.get("permalink") or "https://www.ransomware.live"),
            priority=max(priorities, key=lambda p: PRIORITY_RANK[p]),
            speech=speech,
            source="ransomware",
            private=True,
            public_label=label,
        ))
    return alerts


def public_title(alert: Alert) -> str:
    """What logs and run summaries may show. Private alerts never name the organisation."""
    if alert.private:
        return alert.public_label or "Ransomware: an organisation was listed (details on your phone only)"
    return alert.title


# --------------------------------------------------------------------------- alert builders

def kev_alert(entry: dict, epss: dict, candidates: dict, lists: Watchlists, urgent_epss: float = 0.50,
              cvss: float | None = None, critical: bool = False) -> Alert:
    """A new KEV entry. Urgent with known ransomware use, a core watchlist vendor, EPSS at
    urgent_epss, or when critical (the caller decides: CVSS 9+, network, no login)."""
    cve_id = entry["cveID"]
    vendor, product = entry.get("vendorProject", "").strip(), entry.get("product", "").strip()
    ransomware = (entry.get("knownRansomwareCampaignUse") or "").strip().lower() == "known"
    text = f"{vendor} {product} {entry.get('vulnerabilityName', '')}"
    core_hits = lists.core.find(text)
    facts = [f"Added {entry.get('dateAdded', '?')}, CISA due date {entry.get('dueDate', '?')}"]
    if ransomware:
        facts.append("known ransomware use")
    scores = []
    if cvss is None and cve_id in candidates:
        cvss = candidates[cve_id]["cvss"]
    if cvss is not None:
        scores.append(f"CVSS {cvss:.1f}")
    if cve_id in epss:
        scores.append(fmt_epss(epss[cve_id]))
    if scores:
        facts.append(", ".join(scores))
    if core_hits:
        facts.append("core watchlist: " + ", ".join(core_hits))
    likely = cve_id in epss and epss[cve_id][0] >= urgent_epss
    if likely:
        facts.append(f"EPSS at or above {urgent_epss:.0%}")
    if critical:
        facts.append("critical, exploitable over the network")
    body = "\n".join(filter(None, [
        entry.get("vulnerabilityName", "").strip(),
        "; ".join(facts),
        clean_text(entry.get("shortDescription"), 400),
    ]))
    speech = f"Security alert. CISA has added a {vendor} {product} vulnerability to its known exploited list."
    if ransomware:
        speech += " Ransomware groups are using it."
    return Alert(
        key=f"kev:{cve_id}",
        title=f"KEV: {cve_id} {vendor} {product}".strip(),
        body=body,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        priority="urgent" if (ransomware or core_hits or likely or critical) else "high",
        speech=speech,
        source="kev",
    )


def cve_alert(cve_id: str, cand: dict, score: tuple[float, float] | None, hits: list[str],
              reasons: list[str], priority: str) -> Alert:
    bits = [f"CVSS {cand['cvss']:.1f}"]
    if score:
        bits.append(fmt_epss(score))
    first_product = (cand.get("products") or "").split(",")[0].strip()
    vendor = (hits[0] if hits else first_product).strip()
    speech = "Security alert. A critical" + (f" {vendor}" if vendor else "") + \
        f" vulnerability scored {cand['cvss']:.1f}, and exploitation looks likely."
    body = "\n".join(filter(None, [
        ", ".join(bits),
        cand.get("products", ""),
        cand.get("summary", ""),
        "Why: " + "; ".join(reasons),
    ]))
    title = f"{cve_id} {first_product} (CVSS {cand['cvss']:.1f})"
    return Alert(
        key=f"cve:{cve_id}",
        title=re.sub(r"\s+", " ", title),
        body=body,
        url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        priority=priority,
        speech=speech,
        source="cve",
    )


# --------------------------------------------------------------------------- state, stats and health

def bump(counter: dict, key: str, amount: int = 1) -> None:
    counter[key] = counter.get(key, 0) + amount


def record_health(state: dict, source: str, ok: bool, alerts: list[Alert], now: datetime) -> None:
    health = state.setdefault("health", {}).setdefault(source, {"fails": 0, "warned": False})
    if ok:
        health.update(fails=0, warned=False)
        return
    health["fails"] = health.get("fails", 0) + 1
    if health["fails"] >= FAILURE_WARN_AFTER and not health.get("warned"):
        health["warned"] = True
        alerts.append(Alert(
            key=f"health:{source}:{iso(now)}",
            title=f"Notifier: {source} is failing",
            body=f"{source} has failed {health['fails']} runs in a row. Check the Actions log and the feed URL.",
            url="",
            priority="normal",
            source="health",
        ))


def restore_outbox(state: dict) -> list[Alert]:
    names = {f.name for f in fields(Alert)}
    restored = []
    for item in state.pop("outbox", []) or []:
        alert = Alert(**{k: v for k, v in item.items() if k in names})
        if alert.attempts < OUTBOX_MAX_ATTEMPTS:
            restored.append(alert)
    return restored


def finalise_state(state: dict, alerts: list[Alert], failed: list[Alert], now: datetime) -> None:
    failed_keys = {a.key for a in failed}
    alerted = state.setdefault("alerted", {})
    stats = state.setdefault("stats", {"since": iso(now)})
    for alert in alerts:
        if alert.key in failed_keys:
            continue
        alerted[alert.key] = iso(now)
        if alert.source == "kev":
            alerted["cve:" + alert.key.split(":", 1)[1]] = iso(now)
        if alert.source in ("kev", "cve", "news", "ransomware") and alert.attempts == 0:
            bump(stats, f"alerts_{alert.priority}")
            bump(stats, f"{alert.source}_alerts")
    outbox = []
    for alert in failed:
        if alert.private:
            continue  # never saved with a client's name; it is found and retried on the next run anyway
        alert.attempts += 1
        outbox.append(asdict(alert))
    if outbox:
        state["outbox"] = outbox
    cutoff = now - ALERTED_RETENTION
    for key, stamp in list(alerted.items()):
        when = parse_iso(stamp)
        if when and when < cutoff:
            del alerted[key]


# --------------------------------------------------------------------------- the run

def collect(cfg: dict, state: dict, http: Http, env: dict, now: datetime) -> tuple[list[Alert], list[str]]:
    """Gathers alerts and updates state in place. Returns (alerts, source errors)."""
    errors: list[str] = []
    alerts: list[Alert] = restore_outbox(state)
    seeding = not state.get("initialised")
    run = {"nvd_reviewed": 0, "new_high_severity": 0, "dropped_as_noise": 0}
    state["last_run"] = run
    stats = state.setdefault("stats", {"since": iso(now)})

    cve_cfg = cfg.get("cve") or {}
    min_cvss = float(cve_cfg.get("min_cvss", 7.0))
    epss_threshold = float(cve_cfg.get("epss_threshold", 0.10))
    urgent_epss = float(cve_cfg.get("urgent_epss", 0.50))
    watch_min = float(cve_cfg.get("watchlist_min_cvss", 9.0))
    require_unauth = bool(cve_cfg.get("watchlist_requires_unauthenticated", True))
    watch_days = int(cve_cfg.get("watch_days", 14))
    max_published_age = timedelta(days=int(cve_cfg.get("max_published_age_days", 30)))
    max_window = timedelta(hours=int(cve_cfg.get("max_window_hours", 168)))
    alerted = state.setdefault("alerted", {})
    candidates: dict = state.setdefault("candidates", {})
    kev_seen = set(state.get("kev_seen") or [])

    # 1. CISA KEV
    kev_urgent_epss = float((cfg.get("kev") or {}).get("urgent_epss", urgent_epss))
    kev: list[dict] | None = None
    kev_ids: set[str] = set(kev_seen)  # falls back to what we already know if the fetch fails
    kev_new: list[dict] = []
    kev_baseline = seeding or not kev_seen  # never alert on the whole catalogue at once
    if (cfg.get("kev") or {}).get("enabled", True):
        try:
            kev = fetch_kev(http)
            kev_ids = {e["cveID"] for e in kev if e.get("cveID")}
            if not kev_baseline:
                kev_new = [e for e in kev if e.get("cveID") and e["cveID"] not in kev_seen]
            record_health(state, "CISA KEV", True, alerts, now)
        except Exception as exc:  # noqa: BLE001 - one bad source must not stop the rest
            errors.append(f"CISA KEV: {exc}")
            record_health(state, "CISA KEV", False, alerts, now)
    lists = build_watchlists(cfg, state, kev)

    # 2. NVD: CVEs modified since the last run, kept as candidates when CVSS is high enough
    if seeding:
        state["nvd_last_mod"] = iso(now)
    else:
        last = parse_iso(state.get("nvd_last_mod")) or now - timedelta(hours=2)
        start = max(last - timedelta(hours=1), now - max_window)  # one hour of overlap for late indexing
        try:
            for cve in fetch_nvd(http, start, now, env.get("NVD_API_KEY") or None):
                run["nvd_reviewed"] += 1
                cve_id = cve.get("id")
                if not cve_id or cve.get("vulnStatus") == "Rejected":
                    continue
                published = parse_iso(cve.get("published"))
                if published and published < now - max_published_age:
                    continue  # old CVEs only alert through KEV
                scored = best_cvss(cve.get("metrics") or {})
                if not scored or scored[0] < min_cvss:
                    continue
                products = cve_products(cve)
                description = cve_description(cve)
                if lists.ignore.find(f"{products} {description}"):
                    if cve_id not in candidates:
                        run["dropped_as_noise"] += 1
                    candidates.pop(cve_id, None)
                    continue
                cand = candidates.get(cve_id)
                if cand is None:
                    cand = {"first_seen": iso(now)}
                    run["new_high_severity"] += 1
                cand.update(
                    cvss=scored[0],
                    version=scored[1],
                    vector=scored[2],
                    products=products or cand.get("products", ""),
                    match_text=products or clean_text(scrub_paths(description), 240),
                    summary=clean_text(description, 240),
                )
                candidates[cve_id] = cand
            state["nvd_last_mod"] = iso(now)
            record_health(state, "NVD", True, alerts, now)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"NVD: {exc}")
            record_health(state, "NVD", False, alerts, now)
    for key in ("nvd_reviewed", "new_high_severity", "dropped_as_noise"):
        bump(stats, key, run[key])

    # 3. EPSS for new KEV entries and candidates not checked recently
    for cve_id, cand in list(candidates.items()):
        if (parse_iso(cand.get("first_seen")) or now) < now - timedelta(days=watch_days):
            del candidates[cve_id]
    epss: dict[str, tuple[float, float]] = {}
    if not seeding:
        stale = [
            cve_id for cve_id, cand in candidates.items()
            if f"cve:{cve_id}" not in alerted and cve_id not in kev_ids
            and (parse_iso(cand.get("epss_checked")) or datetime.min.replace(tzinfo=timezone.utc)) < now - EPSS_RECHECK
        ]
        wanted = set(stale) | {e["cveID"] for e in kev_new}
        if wanted:
            try:
                epss = fetch_epss(http, wanted)
                for cve_id in stale:
                    candidates[cve_id]["epss_checked"] = iso(now)
                    if cve_id in epss:
                        candidates[cve_id]["epss"] = list(epss[cve_id])
                record_health(state, "EPSS", True, alerts, now)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"EPSS: {exc}")
                record_health(state, "EPSS", False, alerts, now)

    # 4. KEV alerts: every new entry; urgent with known ransomware use, a core watchlist vendor,
    #    EPSS at kev.urgent_epss, or (kev.urgent_if_critical) a critical score. An entry that
    #    isn't a recent candidate has its score looked up in NVD.
    if not seeding:
        if_critical = (cfg.get("kev") or {}).get("urgent_if_critical", True) is not False
        for i, entry in enumerate(kev_new):
            cve_id = entry["cveID"]
            cand = candidates.get(cve_id)
            scored = (cand["cvss"], cand.get("vector")) if cand else None
            if scored is None and if_critical:
                try:
                    if i:
                        SLEEP(1.0 if env.get("NVD_API_KEY") else 6.5)
                    record = fetch_nvd_cve(http, cve_id, env.get("NVD_API_KEY") or None)
                    best = best_cvss((record or {}).get("metrics") or {})
                    scored = (best[0], best[2]) if best else None
                except Exception as exc:  # noqa: BLE001 - the alert still goes out, just without the score
                    errors.append(f"NVD lookup for {cve_id}: {exc}")
            critical = bool(if_critical and scored and scored[0] >= watch_min
                            and (unauth_network(scored[1]) is not False or not require_unauth))
            alerts.append(kev_alert(entry, epss, candidates, lists, kev_urgent_epss,
                                    cvss=scored[0] if scored else None, critical=critical))
    state["kev_seen"] = sorted(kev_seen | kev_ids)

    # 5. CVE alerts
    if not seeding:
        for cve_id, cand in candidates.items():
            if f"cve:{cve_id}" in alerted or cve_id in kev_ids:
                continue
            score = tuple(cand["epss"]) if cand.get("epss") else None
            text = cand.get("match_text") or cand.get("products") or ""
            core_hits = lists.core.find(text)
            ext_hits = lists.extended.find(text)
            unauth = unauth_network(cand.get("vector"))
            critical = cand["cvss"] >= watch_min and (unauth is not False or not require_unauth)
            high_epss = bool(score and score[0] >= epss_threshold)
            very_high_epss = bool(score and score[0] >= urgent_epss and cand["cvss"] >= watch_min)
            access = ", network, no login needed" if unauth else ""
            reasons = []
            if high_epss:
                reasons.append(f"EPSS at or above {epss_threshold:.0%}")
            if critical and core_hits:
                reasons.append(f"core watchlist ({', '.join(core_hits)}), CVSS {watch_min:.1f}+{access}")
            elif critical and ext_hits:
                reasons.append(f"watchlist ({', '.join(ext_hits)}), CVSS {watch_min:.1f}+{access}")
            if not reasons:
                continue
            if (high_epss and critical and core_hits) or very_high_epss:
                priority = "urgent"
            elif high_epss or (critical and core_hits):
                priority = "high"
            else:
                priority = "normal"  # a critical on the extended list: worth knowing, not worth a buzz
            alerts.append(cve_alert(cve_id, cand, score, core_hits or ext_hits, reasons, priority))

    # 6. News feeds
    news = cfg.get("news") or {}
    hot = news_matcher(news.get("hot_keywords"), news)
    breach_words = news_matcher(news.get("vendor_breach_keywords"), news)
    default_keywords = news.get("keywords") or []
    max_age = timedelta(days=float(news.get("max_age_days", 3)))
    feed_state = state.setdefault("feeds", {})
    news_candidates: list[dict] = []
    social_priority = (cfg.get("social") or {}).get("hot_vendor_priority", "high")
    if social_priority not in PRIORITY_RANK:
        social_priority = "high"
    for feed in list(news.get("feeds") or []) + social_feeds(cfg, errors):
        url = feed.get("url")
        if not url or feed.get("enabled") is False:
            continue
        name = feed.get("name") or url
        record = feed_state.setdefault(name, {"seen": []})
        seen = list(record.get("seen") or [])
        seen_set = set(seen)
        try:
            items = fetch_feed(http, url)
            record_health(state, name, True, alerts, now)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {exc}")
            record_health(state, name, False, alerts, now)
            continue
        feed_baseline = seeding or not record.get("initialised")  # a new feed starts silently
        record["initialised"] = True
        keywords = news_matcher(feed.get("keywords") or default_keywords, news)
        keyword_mode = feed.get("filter", "keywords") != "all"
        for item in items:
            ident = hashlib.sha1(item["id"].encode("utf-8")).hexdigest()[:16]
            if ident in seen_set:
                continue
            seen.append(ident)
            seen_set.add(ident)
            if feed_baseline or (item["published"] and item["published"] < now - max_age):
                continue
            if feed.get("social"):
                # Keyword filter only. Above normal only with a hot keyword plus a core vendor.
                text = f"{item['title']} {item['summary']}"
                if not keywords.find(text):
                    continue
                priority = social_priority if (hot.find(text) and lists.core.find(text)) else "normal"
                item = dict(item, title=post_title(item))
                news_candidates.append({"name": name, "ident": ident, "item": item, "priority": priority})
                continue
            text = f"{item['title']} {item['summary']}"
            vendor_breach = vendor_breach_priority(item["title"], lists, breach_words)
            if keyword_mode and not keywords.find(text) and not vendor_breach:
                continue
            hot_hits = hot.find(item["title"])
            priority = "urgent" if (hot_hits and lists.core.find(text)) else ("high" if hot_hits else "normal")
            if vendor_breach and PRIORITY_RANK[vendor_breach] > PRIORITY_RANK[priority]:
                priority = vendor_breach
            news_candidates.append({"name": name, "ident": ident, "item": item, "priority": priority})
        record["seen"] = seen[-FEED_SEEN_LIMIT:]
    alerts.extend(group_news(news_candidates, news, state, lists, now))

    # 7. Ransomware leak-site victims that match your watched organisations
    if not seeding:
        alerts.extend(ransomware_alerts(cfg, state, http, env, now, errors, alerts))

    if seeding:
        state["initialised"] = iso(now)
        feeds_count = len([f for f in news.get("feeds") or [] if f.get("enabled") is not False]) + \
            len(social_feeds(cfg, []))
        alerts.append(Alert(
            key=f"system:live:{iso(now)}",
            title="Threat notifier is live",
            body=f"Baseline taken: {len(kev_ids)} KEV entries, {len(lists.auto_vendors)} vendors added "
                 f"from KEV history, {feeds_count} news feeds. New alerts start from the next run.",
            url="",
            priority="normal",
            source="system",
        ))
    return alerts, errors


# --------------------------------------------------------------------------- delivery

def send_ntfy(http: Http, alert: Alert, cfg: dict, env: dict, silent: bool = False) -> None:
    delivery = cfg.get("delivery") or {}
    server = (env.get("NTFY_SERVER") or delivery.get("ntfy_server") or "https://ntfy.sh").rstrip("/")
    levels = {"normal": 2 if delivery.get("normal_silent", True) else 3, "high": 4, "urgent": 5}
    payload: dict[str, Any] = {
        "topic": env["NTFY_TOPIC"],
        "title": alert.title[:250],
        "message": alert.body[:3500] or alert.title,
        "priority": 2 if silent else levels[alert.priority],  # ntfy priority 2 shows without sound
        "tags": NTFY_TAGS[alert.priority],
    }
    if alert.url:
        payload["click"] = alert.url
    headers = {"Authorization": f"Bearer {env['NTFY_TOKEN']}"} if env.get("NTFY_TOKEN") else None
    http.post(server, json_body=payload, headers=headers)


def send_telegram(http: Http, alert: Alert, cfg: dict, env: dict, silent: bool = False) -> None:
    silent = silent or (alert.priority == "normal" and (cfg.get("delivery") or {}).get("normal_silent", True))
    text = f"{TELEGRAM_ICON[alert.priority]} <b>{html.escape(alert.title[:250])}</b>\n{html.escape(alert.body[:3000])}"
    if alert.url:
        text += f'\n<a href="{html.escape(alert.url, quote=True)}">Open</a>'
    http.post(TELEGRAM_URL.format(token=env["TELEGRAM_BOT_TOKEN"]), json_body={
        "chat_id": env["TELEGRAM_CHAT_ID"],
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "disable_notification": bool(silent),
    })


def send_pushover(http: Http, alert: Alert, cfg: dict, env: dict, silent: bool = False) -> None:
    delivery = cfg.get("delivery") or {}
    levels = {
        "normal": -1 if delivery.get("normal_silent", True) else 0,
        "high": 0,
        "urgent": int(delivery.get("pushover_urgent_priority", 1)),
    }
    priority = -1 if silent else levels[alert.priority]  # Pushover -1 arrives without sound
    form: dict[str, Any] = {
        "token": env["PUSHOVER_APP_TOKEN"],
        "user": env["PUSHOVER_USER_KEY"],
        "title": alert.title[:250],
        "message": alert.body[:1000] or alert.title,
        "priority": priority,
    }
    if alert.url:
        form.update(url=alert.url, url_title="Open")
    if priority == 2:  # emergency priority repeats until acknowledged
        form.update(retry=60, expire=1800)
    http.post(PUSHOVER_URL, form=form)


def send_voicemonkey(http: Http, speech: str, cfg: dict, env: dict) -> None:
    alexa = cfg.get("alexa") or {}
    payload = {"token": env["VOICEMONKEY_TOKEN"], "device": env["VOICEMONKEY_DEVICE"], "speech": speech[:400]}
    if alexa.get("voice"):
        payload["voice"] = alexa["voice"]
    if alexa.get("chime"):
        payload["chime"] = alexa["chime"]
    http.post(VOICEMONKEY_URL, json_body=payload)


def phone_channels(env: dict) -> list[tuple[str, Callable[..., None]]]:
    channels = []
    if env.get("NTFY_TOPIC"):
        channels.append(("ntfy", send_ntfy))
    if env.get("TELEGRAM_BOT_TOKEN") and env.get("TELEGRAM_CHAT_ID"):
        channels.append(("telegram", send_telegram))
    if env.get("PUSHOVER_APP_TOKEN") and env.get("PUSHOVER_USER_KEY"):
        channels.append(("pushover", send_pushover))
    return channels


def phone_quiet_until(cfg: dict, now: datetime) -> datetime | None:
    """When the phone's quiet hours end, or None when alerts may make a sound.
    delivery.phone_quiet_hours is "alexa" (Alexa's schedule), a schedule in the same
    format as alexa.quiet_hours, or empty for no phone quiet hours."""
    spec = (cfg.get("delivery") or {}).get("phone_quiet_hours", "")
    if spec == "alexa":
        spec = (cfg.get("alexa") or {}).get("quiet_hours")
    local = now.astimezone(ZoneInfo(cfg.get("timezone") or "Europe/London"))
    return quiet_until(local, spec)


def alexa_ready(env: dict) -> bool:
    return bool(env.get("VOICEMONKEY_TOKEN") and env.get("VOICEMONKEY_DEVICE"))


def alexa_allowed(cfg: dict, state: dict, now: datetime) -> tuple[bool, str]:
    alexa = cfg.get("alexa") or {}
    if alexa.get("enabled", True) is False:
        return False, "disabled in config"
    local = now.astimezone(ZoneInfo(cfg.get("timezone") or "Europe/London"))
    until = quiet_until(local, alexa.get("quiet_hours"))
    if until:
        return False, f"quiet hours until {until:%a %H:%M}"
    month = local.strftime("%Y-%m")
    usage = state.setdefault("alexa", {"month": month, "count": 0})
    if usage.get("month") != month:
        usage.update(month=month, count=0)
    if usage["count"] >= int(alexa.get("monthly_cap", 150)):
        return False, "monthly cap reached"
    return True, ""


def deliver(alerts: list[Alert], cfg: dict, state: dict, http: Http, env: dict, now: datetime,
            dry_run: bool = False, log: Callable[[str], None] = print) -> list[Alert]:
    """Sends alerts. Returns the ones that failed on every phone channel."""
    ordered = sorted(alerts, key=lambda a: PRIORITY_RANK[a.priority], reverse=True)
    cap = int((cfg.get("delivery") or {}).get("max_alerts_per_run", 12))
    to_send, overflow = ordered[:cap], ordered[cap:]
    if overflow:
        top = max(PRIORITY_RANK[a.priority] for a in overflow)
        to_send.append(Alert(
            key=f"digest:{iso(now)}",
            title=f"{len(overflow)} more security alerts",
            body="\n".join(f"- {a.title}" for a in overflow[:25]),
            url="",
            priority="high" if top >= PRIORITY_RANK["high"] else "normal",
            source="digest",
        ))

    channels = phone_channels(env)
    if not channels and not dry_run:
        log("No phone channel configured: add the NTFY_TOPIC secret (or Telegram or Pushover).")
    quiet_end = phone_quiet_until(cfg, now)
    ring_urgent = bool((cfg.get("delivery") or {}).get("phone_quiet_ring_urgent", False))
    if quiet_end and to_send:
        log(f"Phone: quiet hours until {quiet_end:%a %H:%M}, alerts arrive without sound"
            + (" (urgent ones still ring)" if ring_urgent else ""))
    failed: list[Alert] = []
    for alert in to_send:
        silent = bool(quiet_end) and not (ring_urgent and alert.priority == "urgent")
        if dry_run:
            note = " (silent: quiet hours)" if silent else ""
            body = "(hidden)" if alert.private else alert.body.replace(chr(10), " | ")
            log(f"[dry-run] {alert.priority.upper()}{note}: {public_title(alert)}\n"
                f"    {body}\n    {'' if alert.private else alert.url}")
            continue
        delivered = False
        for name, sender in channels:
            try:
                sender(http, alert, cfg, env, silent=silent)
                delivered = True
            except Exception as exc:  # noqa: BLE001
                log(f"{name} failed for {alert.key}: {exc}")
        if channels and not delivered and alert.source != "digest":
            failed.append(alert)

    alexa_cfg = cfg.get("alexa") or {}
    min_rank = PRIORITY_RANK.get(alexa_cfg.get("min_priority", "urgent"), 2)
    spoken = [a for a in ordered if a.speech and PRIORITY_RANK[a.priority] >= min_rank and a.attempts == 0]
    if alexa_ready(env):
        announce_on_alexa(spoken, cfg, state, http, env, now, dry_run, log)
    return failed


def announce_on_alexa(spoken: list[Alert], cfg: dict, state: dict, http: Http, env: dict, now: datetime,
                      dry_run: bool, log: Callable[[str], None]) -> None:
    """One Alexa announcement per run. During quiet hours announcements are held in the
    state and spoken by the first run after quiet hours end."""
    alexa_cfg = cfg.get("alexa") or {}
    use_queue = alexa_cfg.get("queue_during_quiet_hours", True)
    max_age = timedelta(hours=float(alexa_cfg.get("queue_max_age_hours", 24)))
    queue = [q for q in state.get("alexa_queue") or [] if (parse_iso(q.get("queued")) or now) >= now - max_age]
    new = [{"key": a.key, "speech": a.speech, "priority": a.priority, "queued": iso(now)} for a in spoken]
    if not new and not queue:
        state.pop("alexa_queue", None)
        return
    allowed, reason = alexa_allowed(cfg, state, now)
    if not allowed:
        if use_queue and reason.startswith("quiet hours"):
            queue += new
            if new:
                log(f"Alexa: {len(new)} announcement(s) held, {reason}")
        elif new:
            log(f"Alexa skipped: {reason}")
        if queue:
            state["alexa_queue"] = queue
        else:
            state.pop("alexa_queue", None)
        return

    items = sorted(queue + new, key=lambda q: PRIORITY_RANK.get(q["priority"], 0), reverse=True)
    cap = int(alexa_cfg.get("monthly_cap", 150))
    reserve = int(alexa_cfg.get("reserve_for_vulnerabilities", 30))
    if state["alexa"]["count"] >= cap - reserve:
        # The last announcements of the month are kept for exploited vulnerabilities (KEV, CVEs).
        vulns = [q for q in items if str(q.get("key", "")).split(":", 1)[0] in ("kev", "cve")]
        if len(vulns) < len(items):
            log(f"Alexa: {len(items) - len(vulns)} announcement(s) left to the phone, keeping the last "
                f"{reserve} of {cap} this month for exploited vulnerabilities")
        items = vulns
        if not items:
            state.pop("alexa_queue", None)
            return
    speech = items[0]["speech"]
    if len(items) > 1:
        first = items[0]["speech"].removeprefix("Security alert. ")
        speech = f"{len(items)} urgent security alerts, check your phone. The first one: {first}"
    if queue:
        speech = "Catching up after quiet hours. " + speech
    if dry_run:
        log(f"[dry-run] Alexa: {speech}")
        return
    try:
        send_voicemonkey(http, speech, cfg, env)
        state["alexa"]["count"] += 1
        state.pop("alexa_queue", None)
    except Exception as exc:  # noqa: BLE001
        log(f"Voice Monkey failed: {exc}")
        if use_queue:
            state["alexa_queue"] = queue + new  # try again on the next run


def send_test(cfg: dict, http: Http, env: dict, log: Callable[[str], None] = print) -> int:
    alert = Alert(
        key="test",
        title="Threat notifier test",
        body="Phone alerts work. Urgent alerts will also be announced on Alexa.",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        priority="high",
        speech="This is a test of your security alerts.",
        source="test",
    )
    ok = True
    channels = phone_channels(env)
    if not channels:
        log("No phone channel configured: add the NTFY_TOPIC secret.")
        ok = False
    for name, sender in channels:
        try:
            sender(http, alert, cfg, env)
            log(f"{name}: sent")
        except Exception as exc:  # noqa: BLE001
            log(f"{name}: FAILED {exc}")
            ok = False
    if alexa_ready(env):
        try:
            send_voicemonkey(http, alert.speech, cfg, env)
            log("Alexa (Voice Monkey): sent")
        except Exception as exc:  # noqa: BLE001
            log(f"Alexa (Voice Monkey): FAILED {exc}")
            ok = False
    else:
        log("Alexa: not configured (VOICEMONKEY_TOKEN and VOICEMONKEY_DEVICE)")
    return 0 if ok else 1


# --------------------------------------------------------------------------- entry point

def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load_state(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("State file unreadable, starting a fresh baseline.", file=sys.stderr)
    return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding="utf-8")
    tmp.replace(path)


def summary_lines(state: dict, alerts: list[Alert]) -> list[str]:
    run = state.get("last_run") or {}
    stats = state.get("stats") or {}
    counts = {p: sum(1 for a in alerts if a.priority == p and a.source in ("kev", "cve", "news", "ransomware"))
              for p in ("urgent", "high", "normal")}
    total = sum(stats.get(f"alerts_{p}", 0) for p in ("urgent", "high", "normal"))
    return [
        f"This run: {run.get('nvd_reviewed', 0)} NVD records reviewed, {run.get('new_high_severity', 0)} new CVEs "
        f"at CVSS 7+, {run.get('dropped_as_noise', 0)} dropped as noise; alerts: {counts['urgent']} urgent, "
        f"{counts['high']} high, {counts['normal']} normal.",
        f"Since {(stats.get('since') or '')[:10]}: {stats.get('nvd_reviewed', 0)} NVD records reviewed, "
        f"{stats.get('new_high_severity', 0)} CVEs at CVSS 7+, {stats.get('dropped_as_noise', 0)} dropped as noise, "
        f"{total} alerts sent ({stats.get('alerts_urgent', 0)} urgent, {stats.get('alerts_high', 0)} high, "
        f"{stats.get('alerts_normal', 0)} normal; {stats.get('kev_alerts', 0)} KEV, {stats.get('cve_alerts', 0)} CVE, "
        f"{stats.get('news_alerts', 0)} news, {stats.get('ransomware_alerts', 0)} ransomware).",
    ]


def write_summary(env: dict, mode: str, state: dict, alerts: list[Alert], failed: list[Alert], errors: list[str]) -> None:
    path = env.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    ranked = sorted(alerts, key=lambda a: PRIORITY_RANK[a.priority], reverse=True)
    lines = [f"### Threat notifier ({mode})", "", *summary_lines(state, alerts), "",
             f"Failed to send: {len(failed)}", ""]
    lines += [f"- **{a.priority}** {public_title(a)}" for a in ranked[:40]]
    if errors:
        lines += ["", "**Source errors**", *[f"- {e}" for e in errors]]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="KEV, CVE and security news notifier")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--state", default="state/state.json")
    parser.add_argument("--mode", choices=["run", "dry-run", "test"], default="run")
    args = parser.parse_args(argv)

    cfg = load_config(Path(args.config))
    env = dict(os.environ)
    http = Http()
    if args.mode == "test":
        return send_test(cfg, http, env)

    state = load_state(Path(args.state))
    now = utcnow()
    alerts, errors = collect(cfg, state, http, env, now)
    failed = deliver(alerts, cfg, state, http, env, now, dry_run=args.mode == "dry-run")
    if args.mode == "run":
        finalise_state(state, alerts, failed, now)
        save_state(Path(args.state), state)
    for error in errors:
        print(f"WARNING: {error}", file=sys.stderr)
    for line in summary_lines(state, alerts):
        print(line)
    print(f"Failed to send: {len(failed)}, source errors: {len(errors)}")
    write_summary(env, args.mode, state, alerts, failed, errors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
