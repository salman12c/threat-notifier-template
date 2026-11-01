#!/usr/bin/env python3
"""Live drill: send one real alert through the notifier, labelled DRILL.

CVE drill: treats a real CVE as if NVD had just published it. Its real NVD record and
today's EPSS score go through the notifier's own collect() and deliver(), so priority
and Alexa decisions are exactly what a scheduled run would make. The CVE is hidden from
the KEV catalogue (otherwise the notifier leaves it to the KEV alert) and news feeds
are skipped.

Ransomware drill: takes one real ransomware.live listing from the last 30 days in your
ransomware_live.countries (or --country) and sends it exactly as a new listing would be
sent. Needs RANSOMWARE_LIVE_API_KEY. The victim's name goes to the phone only.

Neither drill touches the saved state.

  python tools/drill.py CVE-2026-111497                        # dry run, sends nothing
  python tools/drill.py CVE-2026-111497 --live                 # really sends
  python tools/drill.py --ransomware --live                    # a recent listing in your countries
  python tools/drill.py --ransomware --country IE --live --ignore-quiet-hours
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import notifier  # noqa: E402

RANSOMWARE_LOOKBACK_DAYS = 30  # far enough back that there is always a listing to send


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
    if all(notifier.PRIORITY_RANK[a.priority] < notifier.PRIORITY_RANK.get(min_priority, 2) for a in alerts):
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
    cfg.setdefault("news", {})["feeds"] = []
    kev = [e for e in notifier.fetch_kev(http) if e.get("cveID") != cve_id]
    headers = {"apiKey": env["NVD_API_KEY"]} if env.get("NVD_API_KEY") else None
    found = http.get_json(notifier.NVD_URL, params={"cveId": cve_id}, headers=headers).get("vulnerabilities") or []
    if not found:
        log(f"{cve_id} is not in NVD.")
        return 1
    record = found[0]["cve"]
    log(f"{cve_id}: really published {record.get('published')}; treated as published just now.")
    record["published"] = now.isoformat()

    notifier.fetch_kev = lambda _http: kev
    notifier.fetch_nvd = lambda *_a, **_k: [record]
    cfg.setdefault("ransomware_live", {})["enabled"] = False  # only the CVE

    state: dict = {}
    notifier.collect(cfg, state, http, env, now - timedelta(minutes=30))  # baseline run
    alerts, errors = notifier.collect(cfg, state, http, env, now)
    alerts = [a for a in alerts if a.source == "cve"]
    for error in errors:
        log(f"WARNING: {error}")
    if not alerts:
        cand = state.get("candidates", {}).get(cve_id)
        log("The notifier would NOT alert on this CVE. " + (f"Candidate data: {cand}" if cand else "It is below CVSS 7."))
        return 0

    for alert in alerts:
        log(f"Decision: {alert.priority.upper()} - {alert.title}\n  {alert.body.replace(chr(10), chr(10) + '  ')}")
        alert.title = "DRILL: " + alert.title
        alert.speech = "This is a drill. " + alert.speech if alert.speech else ""
    note_if_alexa_stays_silent(cfg, alerts, log)
    failed = notifier.deliver(alerts, cfg, state, http, env, now, dry_run=not live, log=log)
    report_delivery(state, env, live, failed, log)
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cve", nargs="?", help="CVE ID for a CVE drill")
    parser.add_argument("--ransomware", action="store_true", help="drill a recent ransomware listing instead")
    parser.add_argument("--country", help="country for the ransomware drill (default: ransomware_live.countries)")
    parser.add_argument("--live", action="store_true", help="really send (default is a dry run)")
    parser.add_argument("--ignore-quiet-hours", action="store_true",
                        help="let Alexa speak and the phone ring during quiet hours")
    args = parser.parse_args()
    if not args.ransomware and not args.cve:
        parser.error("give a CVE ID, or --ransomware")

    cfg = notifier.load_config(ROOT / "config.yaml")
    if args.ignore_quiet_hours:
        cfg.setdefault("alexa", {})["quiet_hours"] = ""
        cfg.setdefault("delivery", {})["phone_quiet_hours"] = ""
    env = dict(os.environ)
    http = notifier.Http()
    now = notifier.utcnow()
    if args.ransomware:
        return ransomware_drill(cfg, env, http, now, args.live, country=args.country)
    return cve_drill(args.cve.strip().upper(), cfg, env, http, now, args.live)


if __name__ == "__main__":
    sys.exit(main())
