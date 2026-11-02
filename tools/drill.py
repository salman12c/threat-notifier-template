#!/usr/bin/env python3
"""Live drill: send one real alert through the notifier, labelled DRILL.

CVE drill: treats a real CVE as if NVD had just published it. Its real NVD record and
today's EPSS score go through the notifier's own collect() and deliver(), so priority
and Alexa decisions are exactly what a scheduled run would make. The CVE is hidden from
the KEV catalogue (otherwise the notifier leaves it to the KEV alert) and news feeds
are skipped.

KEV drill: treats a real KEV entry as if CISA had just added it, with its real NVD
score and today's EPSS.

News drill: treats a headline as if one of your news feeds had just posted it, through
that feed's own filter. Give it as "Feed name: headline". Several headlines in one drill
are grouped exactly as a scheduled run would group them.

Ransomware drill: takes one real ransomware.live listing from the last 30 days in your
ransomware_live.countries (or --country) and sends it exactly as a new listing would be
sent. Needs RANSOMWARE_LIVE_API_KEY. The victim's name goes to the phone only.

No drill touches the saved state.

  python tools/drill.py CVE-2026-111497                        # dry run, sends nothing
  python tools/drill.py CVE-2026-111497 --live                 # really sends
  python tools/drill.py --kev CVE-2026-111497                  # as a new KEV entry
  python tools/drill.py --news "BleepingComputer: ConnectWise breached by state-backed hackers"
  python tools/drill.py --ransomware --live                    # a recent listing in your countries
  python tools/drill.py --ransomware --country IE --live --ignore-quiet-hours
"""

from __future__ import annotations

import argparse
import os
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable, Iterator

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import notifier  # noqa: E402

RANSOMWARE_LOOKBACK_DAYS = 30  # far enough back that there is always a listing to send


@contextmanager
def patched(**replacements) -> Iterator[None]:
    """Swap notifier functions (fetch_kev, fetch_nvd, fetch_feed) for a drill, then put them back."""
    saved = {name: getattr(notifier, name) for name in replacements}
    for name, fn in replacements.items():
        setattr(notifier, name, fn)
    try:
        yield
    finally:
        for name, fn in saved.items():
            setattr(notifier, name, fn)


def only_this_source(cfg: dict, keep_feeds: list[dict] | None = None) -> None:
    """Turn off the sources a drill isn't about, so only its own alert comes out."""
    cfg.setdefault("news", {})["feeds"] = list(keep_feeds or [])
    cfg.setdefault("social", {})["enabled"] = False
    cfg.setdefault("ransomware_live", {})["enabled"] = False


def run_twice(cfg: dict, env: dict, http: notifier.Http, now: datetime, source: str,
              phase: dict) -> tuple[dict, list, list[str]]:
    """A baseline run half an hour ago, then the run in which the drilled item is new.
    phase["new"] is False during the baseline and True for the second run."""
    state: dict = {}
    phase["new"] = False
    notifier.collect(cfg, state, http, env, now - timedelta(minutes=30))
    phase["new"] = True
    alerts, errors = notifier.collect(cfg, state, http, env, now)
    return state, [a for a in alerts if a.source == source], errors


def send_drill(alerts: list, cfg: dict, state: dict, env: dict, http: notifier.Http, now: datetime,
               live: bool, log: Callable[[str], None]) -> int:
    for alert in alerts:
        log(f"Decision: {alert.priority.upper()} - {alert.title}\n  {alert.body.replace(chr(10), chr(10) + '  ')}")
        alert.title = "DRILL: " + alert.title
        alert.speech = "This is a drill. " + alert.speech if alert.speech else ""
    note_if_alexa_stays_silent(cfg, alerts, log)
    failed = notifier.deliver(alerts, cfg, state, http, env, now, dry_run=not live, log=log)
    report_delivery(state, env, live, failed, log)
    return 1 if failed else 0


def split_headline(text: str, feeds: list[dict]) -> tuple[dict | None, str]:
    """'BleepingComputer: headline' -> (that feed, 'headline'). The longest matching name wins."""
    for feed in sorted(feeds, key=lambda f: -len(f.get("name") or "")):
        name = (feed.get("name") or "").strip()
        if name and text.lower().startswith(name.lower() + ":"):
            return feed, text[len(name) + 1:].strip()
    return None, text.strip()


def find_item(title: str, items: list[dict]) -> dict | None:
    """The live feed item with this headline (ignoring case, spacing and punctuation), if still there."""
    def norm(text: str) -> str:
        return " ".join("".join(c if c.isalnum() else " " for c in text.lower()).split())
    wanted = norm(title)
    return next((item for item in items if wanted and norm(item.get("title") or "") == wanted), None)


def explain_headline(title: str, summary: str, feed: dict, cfg: dict, lists: notifier.Watchlists) -> str:
    """Which words the notifier's rules find, for the drill log. Like the notifier, the filter
    and vendor lists read the headline and summary; hot and breach words only the headline."""
    news = cfg.get("news") or {}
    text = f"{title} {summary}"
    found = {
        "filter words": notifier.news_matcher(feed.get("keywords") or news.get("keywords"), news).find(text),
        "hot words in headline": notifier.news_matcher(news.get("hot_keywords"), news).find(title),
        "breach words in headline": notifier.news_matcher(news.get("vendor_breach_keywords"), news).find(title),
        "MSP-critical in headline": lists.msp_critical.find(title),
        "core": lists.core.find(text),
        "extended": lists.extended.find(text),
    }
    keyword_mode = feed.get("filter", "keywords") != "all"
    mode = "keyword-filtered" if keyword_mode else "every post"
    hits = "; ".join(f"{k}: {', '.join(v)}" for k, v in found.items() if v) or "none of the rule words"
    priority = notifier.headline_priority(
        title, text, lists, notifier.news_matcher(news.get("hot_keywords"), news),
        notifier.news_matcher(news.get("vendor_breach_keywords"), news),
        news.get("vendor_breach_extended", True) is not False)
    min_priority = news.get("min_priority", "high")
    if keyword_mode and priority == "normal" and not found["filter words"]:
        why = "\n  -> DROPPED: no filter word, so this feed's filter doesn't let it through"
    elif notifier.PRIORITY_RANK[priority] < notifier.PRIORITY_RANK.get(min_priority, 1):
        why = (f"\n  -> DROPPED: it ranks {priority}, below news.min_priority ({min_priority}): "
               "no hot word, and no vendor named with a breach word")
    else:
        why = ""
    return f"{feed.get('name')} ({mode}) finds {hits}" + why


def news_drill(headlines: list[str], cfg: dict, env: dict, http: notifier.Http, now: datetime, live: bool,
               log: Callable[[str], None] = print) -> int:
    """Send headlines as if your feeds had just posted them, without saving anything."""
    feeds = [f for f in (cfg.get("news") or {}).get("feeds") or []
             if f.get("url") and f.get("enabled") is not False]
    drilled: list[tuple[dict, str]] = []
    for text in headlines:
        feed, title = split_headline(text, feeds)
        if not feed or not title:
            log("Start each headline with one of your feed names and a colon, for example "
                f"'BleepingComputer: ...'. Feeds: {', '.join(f.get('name') or f['url'] for f in feeds)}")
            return 1
        drilled.append((feed, title))

    live_items: dict[str, list[dict]] = {}
    items: dict[str, list[dict]] = {}
    explained: list[tuple[dict, dict]] = []
    for i, (feed, title) in enumerate(drilled):  # the first headline is the earliest
        if feed["url"] not in live_items:
            try:
                live_items[feed["url"]] = notifier.fetch_feed(http, feed["url"])
            except Exception as exc:  # noqa: BLE001
                log(f"WARNING: {feed.get('name')}: {exc}")
                live_items[feed["url"]] = []
        real = find_item(title, live_items[feed["url"]])
        if real:
            when = f"{real['published']:%Y-%m-%d %H:%M} UTC" if real.get("published") else "an unknown time"
            log(f"Found in {feed.get('name')}'s feed (posted {when}); using its summary and link.")
        else:
            log(f"Not in {feed.get('name')}'s feed any more; drilling the headline alone, with no summary.")
        item = {"id": f"drill-{i}", "title": real["title"] if real else notifier.clean_text(title, 200),
                "link": real["link"] if real else "", "summary": real["summary"] if real else "",
                "published": now - timedelta(minutes=len(drilled) - i)}
        items.setdefault(feed["url"], []).append(item)
        explained.append((feed, item))
    only_this_source(cfg, [f for f in feeds if f["url"] in items])

    kev = notifier.fetch_kev(http)
    lists = notifier.build_watchlists(cfg, {}, kev)
    for feed, item in explained:
        log(f"Headline: {item['title']}\n  {explain_headline(item['title'], item['summary'], feed, cfg, lists)}")

    phase: dict = {}
    with patched(fetch_kev=lambda _http: kev, fetch_nvd=lambda *_a, **_k: [],
                 fetch_feed=lambda _http, url: items.get(url, []) if phase["new"] else []):
        state, alerts, errors = run_twice(cfg, env, http, now, "news", phase)
    for error in errors:
        log(f"WARNING: {error}")
    if not alerts:
        log("The notifier would NOT alert: see DROPPED above. News alerts need a hot word (zero-day, "
            "exploited...) or a watchlist vendor named with a breach word, unless news.min_priority is normal.")
        return 0
    return send_drill(alerts, cfg, state, env, http, now, live, log)


def kev_drill(cve_id: str, cfg: dict, env: dict, http: notifier.Http, now: datetime, live: bool,
              log: Callable[[str], None] = print) -> int:
    """Send one real KEV entry as if CISA had just added it, without saving anything."""
    kev = notifier.fetch_kev(http)
    entry = next((e for e in kev if e.get("cveID") == cve_id), None)
    if not entry:
        log(f"{cve_id} is not in CISA's KEV catalogue.")
        return 1
    log(f"{cve_id}: really added to KEV {entry.get('dateAdded')}; treated as added just now.")
    before = [e for e in kev if e is not entry]
    headers = {"apiKey": env["NVD_API_KEY"]} if env.get("NVD_API_KEY") else None
    found = http.get_json(notifier.NVD_URL, params={"cveId": cve_id}, headers=headers).get("vulnerabilities") or []
    records = [v["cve"] for v in found if v.get("cve", {}).get("id") == cve_id][:1]
    for record in records:
        record["published"] = now.isoformat()  # so its CVSS score shows, as it would for a recent CVE
    only_this_source(cfg)

    phase: dict = {}
    with patched(fetch_kev=lambda _http: kev if phase["new"] else before,
                 fetch_nvd=lambda *_a, **_k: records):
        state, alerts, errors = run_twice(cfg, env, http, now, "kev", phase)
    for error in errors:
        log(f"WARNING: {error}")
    return send_drill(alerts, cfg, state, env, http, now, live, log)


def report_delivery(state: dict, env: dict, live: bool, failed: list, log: Callable[[str], None]) -> None:
    if live:
        log("Sent." if not failed else "FAILED on every phone channel.")
        if notifier.alexa_ready(env) and state.get("alexa", {}).get("count"):
            log("Alexa (Voice Monkey): sent")
    if state.get("alexa_queue"):
        log("Alexa: held for quiet hours. A drill's state is not saved, so it will not be spoken later; "
            "rerun with --ignore-quiet-hours to hear it now.")


def note_if_alexa_stays_silent(cfg: dict, alerts: list, log: Callable[[str], None]) -> None:
    min_priority = (cfg.get("alexa") or {}).get("min_priority", "urgent")
    never = notifier.never_announced(cfg)
    if alerts and all(a.source in never for a in alerts):
        log(f"Alexa: stays silent, because alexa.never_announce lists {', '.join(sorted({a.source for a in alerts}))}.")
    elif all(notifier.PRIORITY_RANK[a.priority] < notifier.PRIORITY_RANK.get(min_priority, 2) for a in alerts):
        log(f"Alexa: stays silent, because Alexa only speaks {min_priority} alerts.")


def ransomware_drill(cfg: dict, env: dict, http: notifier.Http, now: datetime, live: bool,
                     country: str | None = None, log: Callable[[str], None] = print) -> int:
    """Send one real recent listing in your countries as a DRILL, without saving anything."""
    rl = cfg.setdefault("ransomware_live", {})
    if country:
        rl["countries"] = [country]
    rl["max_age_days"] = RANSOMWARE_LOOKBACK_DAYS
    cfg["watch_orgs"] = []
    env = {k: v for k, v in env.items() if k != "WATCH_ORGS"}  # country listings only, no client names
    countries = notifier.watch_countries(rl)
    if not countries:
        log("No countries to drill: set ransomware_live.countries in config.yaml or pass --country.")
        return 1

    state: dict = {}
    errors: list[str] = []
    alerts = notifier.ransomware_alerts(cfg, state, http, env, now, errors, [])
    for error in errors:
        log(f"WARNING: {error}")
    if not alerts:
        log(f"No ransomware.live listing in {', '.join(countries)} in the last {RANSOMWARE_LOOKBACK_DAYS} days.")
        return 1 if errors else 0

    alert = alerts[0]
    log(f"Decision: {alert.priority.upper()} - {alert.public_label}")  # never the victim's name
    alert.title = "DRILL: " + alert.title
    alert.public_label = "DRILL: " + alert.public_label
    alert.speech = "This is a drill. " + alert.speech
    note_if_alexa_stays_silent(cfg, [alert], log)
    failed = notifier.deliver([alert], cfg, state, http, env, now, dry_run=not live, log=log)
    report_delivery(state, env, live, failed, log)
    return 1 if failed else 0


def cve_drill(cve_id: str, cfg: dict, env: dict, http: notifier.Http, now: datetime, live: bool,
              log: Callable[[str], None] = print) -> int:
    """Send one real CVE as if NVD had just published it, without saving anything."""
    kev = [e for e in notifier.fetch_kev(http) if e.get("cveID") != cve_id]
    headers = {"apiKey": env["NVD_API_KEY"]} if env.get("NVD_API_KEY") else None
    found = http.get_json(notifier.NVD_URL, params={"cveId": cve_id}, headers=headers).get("vulnerabilities") or []
    if not found:
        log(f"{cve_id} is not in NVD.")
        return 1
    record = found[0]["cve"]
    log(f"{cve_id}: really published {record.get('published')}; treated as published just now.")
    record["published"] = now.isoformat()
    only_this_source(cfg)

    with patched(fetch_kev=lambda _http: kev, fetch_nvd=lambda *_a, **_k: [record]):
        state, alerts, errors = run_twice(cfg, env, http, now, "cve", {})
    for error in errors:
        log(f"WARNING: {error}")
    if not alerts:
        cand = state.get("candidates", {}).get(cve_id)
        log("The notifier would NOT alert on this CVE. " + (f"Candidate data: {cand}" if cand else "It is below CVSS 7."))
        return 0
    return send_drill(alerts, cfg, state, env, http, now, live, log)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cve", nargs="?", help="CVE ID for a CVE drill")
    parser.add_argument("--kev", metavar="CVE", help="drill a real KEV entry as if CISA had just added it")
    parser.add_argument("--news", action="append", metavar="'FEED: HEADLINE'",
                        help="drill a headline as if that feed had just posted it; repeat it, or separate "
                             "headlines with ||, to drill several as one run")
    parser.add_argument("--ransomware", action="store_true", help="drill a recent ransomware listing instead")
    parser.add_argument("--country", help="country for the ransomware drill (default: ransomware_live.countries)")
    parser.add_argument("--live", action="store_true", help="really send (default is a dry run)")
    parser.add_argument("--ignore-quiet-hours", action="store_true",
                        help="let Alexa speak and the phone ring during quiet hours")
    args = parser.parse_args()
    if not (args.ransomware or args.cve or args.kev or args.news):
        parser.error("give a CVE ID, --kev CVE, --news 'FEED: HEADLINE' or --ransomware")

    cfg = notifier.load_config(ROOT / "config.yaml")
    if args.ignore_quiet_hours:
        cfg.setdefault("alexa", {})["quiet_hours"] = ""
        cfg.setdefault("delivery", {})["phone_quiet_hours"] = ""
    env = dict(os.environ)
    http = notifier.Http()
    now = notifier.utcnow()
    if args.ransomware:
        return ransomware_drill(cfg, env, http, now, args.live, country=args.country)
    if args.kev:
        return kev_drill(args.kev.strip().upper(), cfg, env, http, now, args.live)
    if args.news:
        headlines = [h.strip() for text in args.news for h in text.split("||") if h.strip()]
        return news_drill(headlines, cfg, env, http, now, args.live)
    return cve_drill(args.cve.strip().upper(), cfg, env, http, now, args.live)


if __name__ == "__main__":
    sys.exit(main())
