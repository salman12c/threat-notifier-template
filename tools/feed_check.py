#!/usr/bin/env python3
"""Monthly feed check: test every news feed and social account in config.yaml.

A feed needs attention when it fails to load, or when its newest post is older than
feed_check.silent_days. For each one the check looks for a fix: a Mastodon account that
moved, a feed address advertised on the site's homepage, or a feed at a common path.
Suggestions are only made after the new address has been fetched and parsed. It never
edits config.yaml: you decide what to change.

The result goes to your phone as one message without sound, and to the run summary.

  python tools/feed_check.py             # check and print, sends nothing
  python tools/feed_check.py --send      # also send the phone message
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable
from urllib.parse import urljoin, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import notifier  # noqa: E402

COMMON_FEED_PATHS = ["/feed/", "/feed", "/rss", "/rss.xml", "/feed.xml", "/atom.xml", "/index.xml", "/blog/rss.xml"]
FEED_LINK = re.compile(r"<link\b[^>]*>", re.IGNORECASE)
MAX_CANDIDATES = 8  # addresses tried per broken feed
RETRY_PAUSE = 15    # seconds before fetching a failed feed a second time
TRANSIENT = re.compile(r"timed out|timeout|connection|HTTP (429|5\d\d)", re.IGNORECASE)


def short_error(error: str) -> str:
    """'HTTPSConnectionPool(host=..., port=443): Read timed out. (read timeout=30)' -> 'read timed out'."""
    if re.search(r"timed out|timeout", error, re.IGNORECASE):
        return "read timed out" if "Read timed out" in error else "timed out"
    if re.search(r"connection", error, re.IGNORECASE):
        return "could not connect"
    return error[:120]


def all_feeds(cfg: dict) -> list[dict]:
    """Every enabled news feed and social account, as the notifier reads them."""
    feeds = [dict(f, kind="news") for f in (cfg.get("news") or {}).get("feeds") or []
             if f.get("url") and f.get("enabled") is not False]
    errors: list[str] = []
    for feed in notifier.social_feeds(cfg, errors):
        feeds.append(dict(feed, kind="bluesky" if "bsky.app/profile/" in feed["url"] else "mastodon"))
    for error in errors:  # a social entry the notifier can't turn into a feed
        feeds.append({"name": error.split(":")[0].removeprefix("social account "), "url": "", "kind": "invalid",
                      "error": error.split(": ", 1)[-1]})
    return feeds


def newest_post(items: list[dict]) -> datetime | None:
    dates = [i["published"] for i in items if i.get("published")]
    return max(dates) if dates else None


def try_feed(http: notifier.Http, url: str, now: datetime, silent_days: float) -> str | None:
    """A description of a working, recently active feed at url, or None."""
    try:
        items = notifier.fetch_feed(http, url)
    except Exception:  # noqa: BLE001
        return None
    newest = newest_post(items)
    if not items or (newest and now - newest > timedelta(days=silent_days)):
        return None
    return f"{len(items)} posts, newest {(now - newest).days} days ago" if newest else f"{len(items)} posts"


def advertised_feeds(http: notifier.Http, page_url: str) -> list[str]:
    """Feed addresses a web page advertises with <link rel="alternate" type="...rss/atom...">."""
    try:
        page = http.get_bytes(page_url, retries=1).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        return []
    found = []
    for tag in FEED_LINK.findall(page):
        if re.search(r"rel=[\"']?alternate", tag, re.I) and re.search(r"(rss|atom)\+xml", tag, re.I):
            href = re.search(r"href=[\"']([^\"']+)", tag, re.I)
            if href:
                found.append(urljoin(page_url, href.group(1).replace("&amp;", "&")))
    return found


def news_fix(http: notifier.Http, feed: dict, now: datetime, silent_days: float) -> str | None:
    url = feed["url"]
    host = urlparse(url).netloc.lower()
    if "reddit.com" in host and re.search(r"HTTP (403|429)", feed.get("error", "")):
        return "Reddit blocks GitHub's servers. Remove this feed or add enabled: false."
    site = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    candidates: list[str] = []
    for found in advertised_feeds(http, url) + advertised_feeds(http, site + "/"):
        if found not in candidates:
            candidates.append(found)
    candidates += [site + p for p in COMMON_FEED_PATHS if site + p not in candidates]
    for candidate in candidates[:MAX_CANDIDATES]:
        if candidate.rstrip("/") == url.rstrip("/"):
            continue
        works = try_feed(http, candidate, now, silent_days)
        if works:
            return f"Change url to {candidate} (checked: {works})."
    return None


def mastodon_fix(http: notifier.Http, feed: dict, now: datetime, silent_days: float) -> str | None:
    match = re.match(r"https://([^/]+)/@([\w.]+)\.rss$", feed["url"])
    if not match:
        return None
    server, user = match.groups()
    try:
        account = http.get_json(f"https://{server}/api/v1/accounts/lookup", params={"acct": user}, retries=1)
    except RuntimeError as exc:
        if "HTTP 404" in str(exc):
            return f"The account @{user}@{server} no longer exists. Remove it, or find where they moved."
        return None
    moved = (account or {}).get("moved") or {}
    if moved.get("url"):
        new_feed = moved["url"].rstrip("/") + ".rss"
        works = try_feed(http, new_feed, now, silent_days)
        if works:
            return f"The account moved: change mastodon to {moved['url']} (checked: {works})."
        return f"The account moved to {moved['url']}, but that feed isn't active either."
    return None


def bluesky_fix(http: notifier.Http, feed: dict) -> str | None:
    handle = feed["url"].split("/profile/")[1].split("/")[0]
    try:
        http.get_json("https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile", params={"actor": handle},
                      retries=1)
    except RuntimeError:
        return f"The handle {handle} no longer exists. They may have changed it: search for them on bsky.app."
    return None


def check_feed(http: notifier.Http, feed: dict, now: datetime, silent_days: float) -> dict:
    """{name, url, kind, status: ok | failed | silent, detail, fix}"""
    result = {"name": feed["name"], "url": feed["url"], "kind": feed["kind"], "status": "ok", "detail": "", "fix": None}
    if feed["kind"] == "invalid":
        return dict(result, status="failed", detail=feed["error"],
                    fix="Use a profile URL (https://server/@user) for mastodon, or a handle for bluesky.")
    try:
        try:
            items = notifier.fetch_feed(http, feed["url"])
        except Exception:  # noqa: BLE001
            notifier.SLEEP(RETRY_PAUSE)  # one more go: a single timeout is usually nothing
            items = notifier.fetch_feed(http, feed["url"])
    except Exception as exc:  # noqa: BLE001
        error = str(exc)
        result.update(status="failed", detail=short_error(error))
        feed = dict(feed, error=error)
        if TRANSIENT.search(error) and not (feed["kind"] == "news" and "reddit.com" in feed["url"]):
            result["fix"] = ("Looks temporary (a timeout or server error): leave it for now. The notifier warns "
                             "you if it fails 12 runs in a row.")
            return result
    else:
        newest = newest_post(items)
        if not items:
            result.update(status="silent", detail="the feed is empty")
        elif newest and now - newest > timedelta(days=silent_days):
            result.update(status="silent", detail=f"last post {(now - newest).days} days ago ({newest:%d %b %Y})")
        else:
            result["detail"] = f"newest post {(now - newest).days} days ago" if newest else f"{len(items)} posts, undated"
            return result
    if feed["kind"] == "news":
        result["fix"] = news_fix(http, feed, now, silent_days)
    elif feed["kind"] == "mastodon":
        result["fix"] = mastodon_fix(http, feed, now, silent_days)
    elif feed["kind"] == "bluesky" and result["status"] == "failed":
        result["fix"] = bluesky_fix(http, feed)
    if not result["fix"] and result["status"] == "silent" and feed["kind"] != "news":
        result["fix"] = "If they've stopped posting here, add enabled: false to the account."
    return result


def report(results: list[dict], silent_days: float, run_url: str = "") -> notifier.Alert | None:
    """One quiet phone message listing the feeds that need attention, or None when all are fine."""
    bad = [r for r in results if r["status"] != "ok"]
    if not bad:
        return None
    lines = []
    for r in bad:
        label = "FAILED" if r["status"] == "failed" else f"SILENT {int(silent_days)}+ days"
        lines.append(f"{r['name']}: {label}, {r['detail']}")
        lines.append(f"  Suggested fix: {r['fix']}" if r["fix"] else "  No fix found: check the site, or remove the feed.")
    lines.append("config.yaml was not changed.")
    return notifier.Alert(
        key=f"system:feed-check:{len(bad)}",
        title=f"Feed check: {len(bad)} of {len(results)} feeds need attention",
        body="\n".join(lines),
        url=run_url,
        priority="normal",
        source="system",
    )


def summary_markdown(results: list[dict], silent_days: float) -> str:
    rows = ["## Feed check", "", f"A feed needs attention when it fails, or has posted nothing for {int(silent_days)} days. "
            "config.yaml is never changed.", "", "| Feed | Type | Status | Detail | Suggested fix |",
            "| --- | --- | --- | --- | --- |"]
    order = {"failed": 0, "silent": 1, "ok": 2}
    for r in sorted(results, key=lambda r: (order[r["status"]], r["name"].lower())):
        cells = [r["name"], r["kind"], r["status"], r["detail"], r["fix"] or ""]
        rows.append("| " + " | ".join(c.replace("|", "/") for c in cells) + " |")
    return "\n".join(rows) + "\n"


def send_quietly(alert: notifier.Alert, cfg: dict, http: notifier.Http, env: dict,
                 log: Callable[[str], None]) -> bool:
    channels = notifier.phone_channels(env)
    if not channels:
        log("No phone channel configured: add the NTFY_TOPIC secret.")
        return False
    sent = False
    for name, sender in channels:
        try:
            sender(http, alert, cfg, env, silent=True)
            log(f"{name}: sent without sound")
            sent = True
        except Exception as exc:  # noqa: BLE001
            log(f"{name}: FAILED {exc}")
    return sent


def run_check(cfg: dict, http: notifier.Http, env: dict, now: datetime, send: bool,
              log: Callable[[str], None] = print) -> int:
    check_cfg = cfg.get("feed_check") or {}
    if check_cfg.get("enabled") is False:
        log("Feed check is turned off (feed_check.enabled: false).")
        return 0
    silent_days = float(check_cfg.get("silent_days", 14))
    quiet_ok = {n.lower() for n in check_cfg.get("quiet_ok") or []}
    results = []
    for feed in all_feeds(cfg):
        result = check_feed(http, feed, now, silent_days)
        if result["status"] == "silent" and result["name"].lower() in quiet_ok:
            result.update(status="ok", detail=result["detail"] + " (in quiet_ok)", fix=None)
        results.append(result)
        mark = {"ok": "ok    ", "failed": "FAILED", "silent": "SILENT"}[result["status"]]
        log(f"{mark} {result['name']}: {result['detail']}" + (f"\n       Suggested fix: {result['fix']}" if result["fix"] else ""))

    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write(summary_markdown(results, silent_days))
    run_url = ""
    if env.get("GITHUB_RUN_ID"):
        run_url = f"{env.get('GITHUB_SERVER_URL', 'https://github.com')}/{env.get('GITHUB_REPOSITORY')}/actions/runs/{env['GITHUB_RUN_ID']}"
    alert = report(results, silent_days, run_url)
    if alert is None and check_cfg.get("notify_when_all_ok"):
        alert = notifier.Alert(key="system:feed-check:ok", title=f"Feed check: all {len(results)} feeds are fine",
                               body="Every feed loaded and posted recently.", url=run_url, priority="normal",
                               source="system")
    if alert is None:
        log(f"All {len(results)} feeds are fine: nothing to send.")
        return 0
    log(f"\n{alert.title}\n{alert.body}")
    if not send:
        log("[dry-run] not sent")
        return 0
    return 0 if send_quietly(alert, cfg, http, env, log) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--send", action="store_true", help="send the phone message (default: print only)")
    args = parser.parse_args()
    cfg = notifier.load_config(ROOT / "config.yaml")
    return run_check(cfg, notifier.Http(), dict(os.environ), notifier.utcnow(), args.send)


if __name__ == "__main__":
    sys.exit(main())
