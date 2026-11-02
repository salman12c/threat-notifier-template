"""Offline tests: every network call is served from the fixtures below."""

import copy
import sys
import unittest
from datetime import datetime, time as dtime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import notifier  # noqa: E402

notifier.SLEEP = lambda seconds: None

CONFIG = notifier.load_config(Path(__file__).resolve().parents[1] / "config.yaml")
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=timezone.utc)  # 12:00 in London
UNAUTH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
AUTH_HIGH = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H"


def nvd_time(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000")


def kev_entry(cve, vendor, product, ransomware="Unknown"):
    return {
        "cveID": cve, "vendorProject": vendor, "product": product,
        "vulnerabilityName": f"{vendor} {product} Vulnerability", "dateAdded": "2026-11-02",
        "shortDescription": f"{vendor} {product} contains a flaw.", "dueDate": "2026-11-23",
        "knownRansomwareCampaignUse": ransomware,
    }


KEV_V1 = {"vulnerabilities": [
    kev_entry("CVE-2024-1709", "ConnectWise", "ScreenConnect", "Known"),
    kev_entry("CVE-2023-0001", "Acme", "Gateway"),
]}
KEV_V2 = {"vulnerabilities": KEV_V1["vulnerabilities"] + [
    kev_entry("CVE-2026-40001", "Fortinet", "FortiOS"),
    kev_entry("CVE-2026-40002", "Widgetco", "Widget Server"),
]}


def nvd_cve(cve_id, score, version="3.1", vendor="acme", product="tool", days_old=1, status="Analyzed",
            description="A flaw allows remote code execution.", vector=UNAUTH, cpe=True):
    key = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31"}[version]
    cve = {
        "id": cve_id, "published": nvd_time(days_old), "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {key: [{"type": "Secondary",
                           "cvssData": {"version": version, "baseScore": score, "vectorString": vector}}]},
    }
    if cpe:
        cve["configurations"] = [{"nodes": [{"cpeMatch": [
            {"criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}]}]}]
    return {"cve": cve}


NVD_ITEMS = [
    nvd_cve("CVE-2026-50001", 9.8, vendor="fortinet", product="fortiweb"),        # core critical, low EPSS
    nvd_cve("CVE-2026-50002", 8.7, version="4.0", vendor="acme", product="portal"),  # high EPSS, CVSS 4.0
    nvd_cve("CVE-2026-50003", 7.5),                                                # low EPSS for now
    nvd_cve("CVE-2026-50004", 6.1),                                                # below CVSS floor
    nvd_cve("CVE-2026-50005", 9.9, status="Rejected"),
    nvd_cve("CVE-2017-0144", 8.8, vendor="microsoft", product="windows", days_old=3000),  # too old
    nvd_cve("CVE-2026-40001", 9.6, vendor="fortinet", product="fortios"),        # also in KEV
    nvd_cve("CVE-2026-50006", 9.1, vendor="microsoft", product="windows"),       # core critical, high EPSS
    nvd_cve("CVE-2026-50007", 9.8, cpe=False, description=(                      # student project noise
        "A vulnerability was found in SourceCodester Online Exam System 1.0. "
        "The file /admin/login.php allows SQL injection.")),
    nvd_cve("CVE-2026-50008", 9.1, vendor="wordpress", product="wordpress"),     # extended critical
    nvd_cve("CVE-2026-50009", 9.1, vendor="fortinet", product="fortimanager", vector=AUTH_HIGH),  # needs login
    nvd_cve("CVE-2026-50010", 9.8, cpe=False, description=(                      # php only as a file name
        "Foo Shop 1.0 allows SQL injection via the id parameter of /cart/index.php.")),
    nvd_cve("CVE-2026-50011", 9.8, vendor="php", product="php"),                 # PHP itself, extended
    nvd_cve("CVE-2026-50012", 9.4, vendor="acme", product="gateway"),            # very high EPSS, no list
]
NVD = {"totalResults": len(NVD_ITEMS), "vulnerabilities": NVD_ITEMS}

EPSS_SCORES = {
    "CVE-2026-50001": (0.02, 0.80), "CVE-2026-50002": (0.35, 0.99), "CVE-2026-50003": (0.01, 0.50),
    "CVE-2026-50006": (0.50, 0.99), "CVE-2026-40001": (0.70, 0.99), "CVE-2026-40002": (0.05, 0.90),
    "CVE-2017-0144": (0.97, 1.0), "CVE-2026-50007": (0.20, 0.97), "CVE-2026-50008": (0.01, 0.40),
    "CVE-2026-50009": (0.01, 0.40), "CVE-2026-50010": (0.01, 0.40), "CVE-2026-50011": (0.01, 0.40),
    "CVE-2026-50012": (0.60, 0.99),
}


def rss(items):
    body = "".join(
        f"<item><title>{t}</title><link>https://news.example/{i}</link><guid>news-{i}</guid>"
        f"<pubDate>{d}</pubDate><description>{s}</description></item>"
        for i, (t, s, d) in enumerate(items)
    )
    return f"<?xml version='1.0'?><rss version='2.0'><channel><title>x</title>{body}</channel></rss>".encode()


def story_rss(items):
    """Like rss(), but each item's ID comes from its title, so new stories never look already seen."""
    body = "".join(
        f"<item><title>{t}</title><link>https://example.com/{abs(hash(t))}</link><guid>{t}</guid>"
        f"<pubDate>{d}</pubDate><description>{s}</description></item>"
        for t, s, d in items
    )
    return f"<?xml version='1.0'?><rss version='2.0'><channel><title>x</title>{body}</channel></rss>".encode()


def rfc822(days_ago):
    return (NOW - timedelta(days=days_ago)).strftime("%a, %d %b %Y %H:%M:%S +0000")


NEWS_V1 = rss([("Old story about patching", "Routine.", rfc822(1))])
NEWS_V2 = rss([
    ("Old story about patching", "Routine.", rfc822(1)),
    ("Fortinet warns of new FortiWeb zero-day exploited in attacks", "Patch now.", rfc822(0)),
    ("Microsoft announces new Teams feature", "Nice update.", rfc822(0)),
    ("Ransomware gang leaks data stolen from retailer", "Extortion.", rfc822(0)),
    ("Ancient breach story", "Old.", rfc822(10)),
])
ATOM_V1 = b"""<?xml version='1.0'?><feed xmlns='http://www.w3.org/2005/Atom'><title>dp</title></feed>"""
ATOM_V2 = f"""<?xml version='1.0'?><feed xmlns='http://www.w3.org/2005/Atom'><title>dp</title>
<entry><title>Big vendor hacked via a developer tool</title><id>dp-1</id>
<link href='https://dp.example/1'/><updated>{NOW.strftime('%Y-%m-%dT%H:%M:%SZ')}</updated>
<summary>Long read.</summary></entry></feed>""".encode()


def test_config():
    cfg = copy.deepcopy(CONFIG)
    cfg["news"]["feeds"] = [
        {"name": "News", "url": "https://news.example/feed", "filter": "keywords"},
        {"name": "DoublePulsar", "url": "https://dp.example/feed", "filter": "all"},
    ]
    cfg.setdefault("delivery", {}).update(normal_silent=True, phone_quiet_hours="alexa",
                                          phone_quiet_ring_urgent=False)  # tests don't depend on live settings
    cfg.setdefault("alexa", {}).update(quiet_hours=dict(QUIET), queue_during_quiet_hours=True,
                                       queue_max_age_hours=24)
    cfg["news"]["vendor_breach_keywords"] = list(BREACH_WORDS)
    cfg["watchlist"]["msp_critical"] = ["connectwise", "screenconnect", "kaseya", "okta"]
    cfg["watch_orgs"] = []
    cfg["ransomware_live"] = {"enabled": True, "url": notifier.RANSOMWARE_LIVE_URL, "priority": "urgent",
                              "max_age_days": 7, "countries": [], "country_priority": "high",
                              "country_url": notifier.RANSOMWARE_LIVE_VICTIMS_URL}
    cfg["social"] = {"enabled": True, "hot_vendor_priority": "high", "accounts": []}
    # The older, wider rules, so each test below shows one rule at a time; the stricter shipped
    # settings have their own tests in StricterAlertTests.
    cfg["cve"]["require_epss"] = False
    cfg["news"].update(min_priority="normal", vendor_breach_extended=False)
    cfg["alexa"]["never_announce"] = []
    return cfg


def victim(name, website="", group="akira", days_ago=0.1, vid=None):
    return {"victim": name, "website": website, "group": group, "country": "GB", "activity": "Manufacturing",
            "discovered": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "attackdate": (NOW - timedelta(days=days_ago + 1)).strftime("%Y-%m-%d"),
            "id": vid or f"{name}@{group}", "permalink": f"https://www.ransomware.live/id/{abs(hash(name))}"}


BREACH_WORDS = ["breach", "breached", "compromised", "hacked", "supply chain attack", "stolen",
                "malicious update", "backdoored"]


QUIET = {"weekdays": "23:00-08:00", "weekends": "01:00-11:00"}


class FakeHttp:
    def __init__(self, kev=KEV_V1, nvd=NVD, epss=EPSS_SCORES, news=NEWS_V1, atom=ATOM_V1, fail=(), ransomware=(),
                 social=None):
        self.kev, self.nvd, self.epss, self.news, self.atom = kev, nvd, epss, news, atom
        self.social = dict(social or {})  # feed URL -> bytes
        self.ransomware = list(ransomware)
        self.fail = set(fail)
        self.posts = []
        self.gets = []
        self.post_error = None

    def get_json(self, url, params=None, headers=None, **kw):
        self.gets.append((url, headers))
        if url in self.fail:
            raise RuntimeError("HTTP 503")
        if url == notifier.RANSOMWARE_LIVE_URL:
            return {"victims": self.ransomware}
        if url == notifier.RANSOMWARE_LIVE_VICTIMS_URL:  # filtered by country and discovery month
            month = f"{params['year']}-{params['month']}"
            return [v for v in self.ransomware
                    if v.get("country") == params["country"] and v["discovered"].startswith(month)]
        if url == notifier.KEV_URL:
            return self.kev
        if url == notifier.NVD_URL:
            return self.nvd
        if url == notifier.EPSS_URL:
            ids = params["cve"].split(",")
            return {"data": [{"cve": c, "epss": str(self.epss[c][0]), "percentile": str(self.epss[c][1])}
                             for c in ids if c in self.epss]}
        raise AssertionError(f"unexpected GET {url}")

    def get_bytes(self, url, **kw):
        if url in self.fail:
            raise RuntimeError("HTTP 403")
        return {"https://news.example/feed": self.news, "https://dp.example/feed": self.atom, **self.social}[url]

    def post(self, url, json_body=None, form=None, headers=None):
        if self.post_error:
            raise self.post_error
        self.posts.append((url, json_body or form))


def run_once(state, http, cfg=None, env=None, now=NOW, dry_run=False):
    cfg = cfg or test_config()
    env = env if env is not None else {"NTFY_TOPIC": "t"}
    alerts, errors = notifier.collect(cfg, state, http, env, now)
    failed = notifier.deliver(alerts, cfg, state, http, env, now, dry_run=dry_run, log=lambda m: None)
    if not dry_run:
        notifier.finalise_state(state, alerts, failed, now)
    return alerts, errors, failed


def seeded_state(http=None):
    state = {}
    run_once(state, http or FakeHttp())
    return state


class CollectTests(unittest.TestCase):
    def test_first_run_takes_a_baseline_and_sends_one_message(self):
        state, http = {}, FakeHttp()
        alerts, errors, _ = run_once(state, http)
        self.assertEqual([a.source for a in alerts], ["system"])
        self.assertEqual(errors, [])
        self.assertEqual(state["kev_seen"], ["CVE-2023-0001", "CVE-2024-1709"])
        self.assertIn("initialised", state)
        self.assertEqual(len(http.posts), 1)

    def test_second_run_alerts_on_the_right_things(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        alerts, errors, _ = run_once(state, http, now=NOW + timedelta(minutes=30))
        got = {a.key: a.priority for a in alerts}
        self.assertEqual(errors, [])
        expected = {
            "kev:CVE-2026-40001": "urgent",   # Fortinet is on the core list
            "kev:CVE-2026-40002": "high",
            "cve:CVE-2026-50001": "high",     # core critical, no login, low EPSS
            "cve:CVE-2026-50002": "high",     # EPSS 35%, CVSS 4.0 score used
            "cve:CVE-2026-50006": "urgent",   # core critical plus high EPSS
            "cve:CVE-2026-50008": "normal",   # extended list critical
            "cve:CVE-2026-50011": "normal",   # PHP itself
            "cve:CVE-2026-50012": "urgent",   # EPSS 60% on a critical, no list needed
        }
        for key, priority in expected.items():
            self.assertEqual(got.get(key), priority, key)
        for absent in ("cve:CVE-2026-50003", "cve:CVE-2026-50004", "cve:CVE-2026-50005", "cve:CVE-2017-0144",
                       "cve:CVE-2026-40001", "cve:CVE-2026-50007", "cve:CVE-2026-50009", "cve:CVE-2026-50010"):
            self.assertNotIn(absent, got)
        news = {a.title: a.priority for a in alerts if a.source == "news"}
        self.assertEqual(news.get("News: Fortinet warns of new FortiWeb zero-day exploited in attacks"), "urgent")
        self.assertEqual(news.get("News: Ransomware gang leaks data stolen from retailer"), "normal")
        self.assertEqual(news.get("DoublePulsar: Big vendor hacked via a developer tool"), "normal")
        self.assertEqual(len(news), 3)

    def test_run_stats_feed_the_summary(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        alerts, _, _ = run_once(state, http, now=NOW + timedelta(minutes=30))
        self.assertEqual(state["last_run"], {"nvd_reviewed": len(NVD_ITEMS), "new_high_severity": 10,
                                             "dropped_as_noise": 1})
        self.assertEqual(state["stats"]["alerts_urgent"], 4)
        self.assertEqual(state["stats"]["kev_alerts"], 2)
        lines = notifier.summary_lines(state, alerts)
        self.assertIn("1 dropped as noise", lines[0])
        self.assertIn("11 alerts sent (4 urgent, 3 high, 4 normal; 2 KEV, 6 CVE, 3 news, 0 ransomware)", lines[1])

    def test_nothing_repeats_on_the_next_run(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        run_once(state, http, now=NOW + timedelta(minutes=30))
        alerts, _, _ = run_once(state, http, now=NOW + timedelta(minutes=60))
        self.assertEqual(alerts, [])

    def test_a_later_epss_jump_alerts(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2)
        run_once(state, http, now=NOW + timedelta(minutes=30))
        http.epss = dict(EPSS_SCORES, **{"CVE-2026-50003": (0.25, 0.97)})
        alerts, _, _ = run_once(state, http, now=NOW + timedelta(hours=1))
        self.assertNotIn("cve:CVE-2026-50003", {a.key for a in alerts})  # EPSS not re-checked yet
        alerts, _, _ = run_once(state, http, now=NOW + timedelta(hours=7))
        self.assertIn("cve:CVE-2026-50003", {a.key for a in alerts})

    def test_vendors_come_in_from_kev_history_except_ignored_ones(self):
        many = [kev_entry(f"CVE-2020-{i:04d}", "Widgetco", "Hub") for i in range(5)]
        many += [kev_entry(f"CVE-2021-{i:04d}", "D-Link", "Router") for i in range(5)]
        kev = {"vulnerabilities": KEV_V1["vulnerabilities"] + many}
        nvd_items = [nvd_cve("CVE-2026-60001", 9.8, vendor="widgetco", product="hub"),
                     nvd_cve("CVE-2026-60002", 9.8, vendor="d-link", product="dir-600")]
        http = FakeHttp(kev=kev, nvd={"totalResults": 2, "vulnerabilities": nvd_items},
                        epss={"CVE-2026-60001": (0.01, 0.4), "CVE-2026-60002": (0.01, 0.4)})
        state = seeded_state(http)
        self.assertEqual(state["kev_vendors"], ["widgetco"])
        alerts, _, _ = run_once(state, http, now=NOW + timedelta(minutes=30))
        got = {a.key: a.priority for a in alerts}
        self.assertEqual(got, {"cve:CVE-2026-60001": "normal"})

    def test_flat_watchlist_from_an_older_config_counts_as_core(self):
        cfg = test_config()
        cfg["watchlist"] = ["acme"]
        state = seeded_state()
        alerts, _, _ = run_once(state, FakeHttp(), cfg=cfg, now=NOW + timedelta(minutes=30))
        self.assertEqual({a.key: a.priority for a in alerts}.get("cve:CVE-2026-50012"), "urgent")

    def test_nvd_failure_keeps_the_window_and_reports_it(self):
        state = seeded_state()
        before = state["nvd_last_mod"]
        _, errors, _ = run_once(state, FakeHttp(fail={notifier.NVD_URL}), now=NOW + timedelta(minutes=30))
        self.assertEqual(state["nvd_last_mod"], before)
        self.assertTrue(any(e.startswith("NVD") for e in errors))

    def test_kev_outage_at_first_run_does_not_flood_later(self):
        state = {}
        run_once(state, FakeHttp(fail={notifier.KEV_URL}))
        alerts, _, _ = run_once(state, FakeHttp(kev=KEV_V2), now=NOW + timedelta(minutes=30))
        self.assertFalse([a for a in alerts if a.source == "kev"])
        self.assertIn("CVE-2026-40002", state["kev_seen"])

    def test_repeated_feed_failure_warns_once(self):
        state = seeded_state()
        http = FakeHttp(fail={"https://news.example/feed"})
        warnings = []
        for i in range(notifier.FAILURE_WARN_AFTER + 3):
            alerts, _, _ = run_once(state, http, now=NOW + timedelta(minutes=30 * (i + 1)))
            warnings += [a for a in alerts if a.source == "health"]
        self.assertEqual(len(warnings), 1)

    def test_a_long_feed_does_not_repeat_old_posts(self):
        # Huntress's feed returns ~750 items; none of them may come back as new on later runs.
        def feed(titles):
            body = "".join(f"<item><title>{t}</title><guid>{t}</guid><pubDate>{d}</pubDate></item>"
                           for t, d in titles)
            return f"<?xml version='1.0'?><rss version='2.0'><channel><title>x</title>{body}</channel></rss>".encode()

        old = [(f"Recent post {i}", rfc822(1)) for i in range(800)]
        fresh = [("Brand new post", rfc822(0))]
        state = seeded_state(FakeHttp(atom=feed(old)))
        alerts, _, _ = run_once(state, FakeHttp(atom=feed(fresh + old)), now=NOW + timedelta(minutes=30))
        self.assertEqual([a.title for a in alerts if a.source == "news"], ["DoublePulsar: Brand new post"])
        for i in range(2, 6):
            alerts, _, _ = run_once(state, FakeHttp(atom=feed(fresh + old)), now=NOW + timedelta(minutes=30 * i))
            self.assertEqual([a.title for a in alerts if a.source == "news"], [], f"run {i}")

    def test_same_cve_from_two_outlets_is_one_alert(self):
        state = seeded_state()
        news = story_rss([("CVE-2026-1234 in Acme Gateway exploited to breach networks", "Patch now.", rfc822(0.2))])
        dp = story_rss([("Inside CVE-2026-1234: a zero-day in the Acme Gateway login page", "Analysis.", rfc822(0.1))])
        alerts, _, _ = run_once(state, FakeHttp(news=news, atom=dp), now=NOW + timedelta(minutes=30))
        news_alerts = [a for a in alerts if a.source == "news"]
        self.assertEqual(len(news_alerts), 1)
        alert = news_alerts[0]
        self.assertEqual(alert.title, "News: CVE-2026-1234 in Acme Gateway exploited to breach networks")  # earliest
        self.assertEqual(alert.priority, "high")  # the zero-day headline lifts the group
        self.assertTrue(alert.body.endswith("Also covered by: DoublePulsar"))

    def test_vendor_plus_three_shared_words_is_one_story(self):
        state = seeded_state()
        news = story_rss([("Ivanti EPMM authentication bypass chained for remote takeover", "Exploited.", rfc822(0.2))])
        dp = story_rss([("Attackers chain Ivanti EPMM authentication bypass in zero-day attacks", "Long read.",
                   rfc822(0.1))])
        alerts, _, _ = run_once(state, FakeHttp(news=news, atom=dp), now=NOW + timedelta(minutes=30))
        news_alerts = [a for a in alerts if a.source == "news"]
        self.assertEqual([a.title for a in news_alerts],
                         ["News: Ivanti EPMM authentication bypass chained for remote takeover"])
        self.assertEqual(news_alerts[0].priority, "urgent")  # zero-day naming a core vendor, from DoublePulsar

    def test_different_stories_stay_separate(self):
        state = seeded_state()
        news = story_rss([("Ivanti EPMM authentication bypass exploited", "Exploited.", rfc822(0.2)),
                    ("Fortinet FortiWeb path traversal exploited", "Exploited.", rfc822(0.2))])
        dp = story_rss([("Ivanti Workspace Control leaks stored credentials", "Read.", rfc822(0.1)),       # vendor only
                  ("Acme EPMM authentication bypass for remote takeover", "Read.", rfc822(0.1))])  # words only
        alerts, _, _ = run_once(state, FakeHttp(news=news, atom=dp), now=NOW + timedelta(minutes=30))
        self.assertEqual(len([a for a in alerts if a.source == "news"]), 4)

    def test_a_story_seen_again_within_the_window_does_not_realert(self):
        state = seeded_state()
        first = story_rss([("CVE-2026-1234 in Acme Gateway exploited to breach networks", "Patch now.", rfc822(0))])
        alerts, _, _ = run_once(state, FakeHttp(news=first), now=NOW + timedelta(minutes=30))
        self.assertEqual(len([a for a in alerts if a.source == "news"]), 1)
        self.assertEqual(state["news_stories"][0]["cves"], ["CVE-2026-1234"])

        later = NOW + timedelta(hours=20)
        again = story_rss([("Acme confirms CVE-2026-1234 breach of customer networks", "Update.", rfc822(-0.8))])
        alerts, _, _ = run_once(state, FakeHttp(atom=again), now=later)
        self.assertEqual([a for a in alerts if a.source == "news"], [])

        after_window = NOW + timedelta(hours=26)
        third = story_rss([("CVE-2026-1234 exploited again in fresh breach", "New wave.", rfc822(-1.05))])
        alerts, _, _ = run_once(state, FakeHttp(news=third), now=after_window)
        self.assertEqual(len([a for a in alerts if a.source == "news"]), 1)
        self.assertTrue(all(notifier.parse_iso(s["at"]) >= after_window - timedelta(hours=24)
                            for s in state["news_stories"]))

    def test_story_grouping_can_be_turned_off(self):
        cfg = test_config()
        cfg["news"]["group_stories"] = False
        state = seeded_state()
        news = story_rss([("CVE-2026-1234 in Acme Gateway exploited to breach networks", "Patch now.", rfc822(0.2))])
        dp = story_rss([("Inside CVE-2026-1234: a zero-day in the Acme Gateway login page", "Analysis.", rfc822(0.1))])
        alerts, _, _ = run_once(state, FakeHttp(news=news, atom=dp), cfg=cfg, now=NOW + timedelta(minutes=30))
        self.assertEqual(len([a for a in alerts if a.source == "news"]), 2)
        self.assertNotIn("news_stories", state)

    def news_priorities(self, news=NEWS_V1, dp=ATOM_V1, cfg=None):
        state = seeded_state()
        alerts, _, _ = run_once(state, FakeHttp(news=news, atom=dp), cfg=cfg, now=NOW + timedelta(minutes=30))
        return {a.title: a.priority for a in alerts if a.source == "news"}

    def test_core_vendor_breach_headline_is_high(self):
        got = self.news_priorities(dp=story_rss([("Fortinet confirms customer data stolen", "Read.", rfc822(0.1))]))
        self.assertEqual(got, {"DoublePulsar: Fortinet confirms customer data stolen": "high"})

    def test_msp_critical_breach_headline_is_urgent(self):
        got = self.news_priorities(dp=story_rss([
            ("ConnectWise breached by state-backed hackers", "Read.", rfc822(0.1)),
            ("Okta support system backdoored for months", "Read.", rfc822(0.1)),
        ]))
        self.assertEqual(set(got.values()), {"urgent"})
        self.assertEqual(len(got), 2)

    def test_breach_rule_needs_vendor_and_word_in_the_title(self):
        got = self.news_priorities(dp=story_rss([
            ("Retailer hacked after phishing campaign", "Attackers used stolen Okta credentials.", rfc822(0.1)),
            ("Fortinet ships new FortiGate models", "Product news.", rfc822(0.1)),
        ]))
        self.assertEqual(got, {"DoublePulsar: Retailer hacked after phishing campaign": "normal",
                               "DoublePulsar: Fortinet ships new FortiGate models": "normal"})

    def test_vendor_breach_gets_past_the_keyword_filter(self):
        got = self.news_priorities(news=story_rss([
            ("Kaseya pushes malicious update to VSA servers", "Read more.", rfc822(0.1)),
            ("Kaseya announces new pricing", "Read more.", rfc822(0.1)),
        ]))
        self.assertEqual(got, {"News: Kaseya pushes malicious update to VSA servers": "urgent"})

    def test_zero_day_wording_still_wins(self):
        # hot keyword plus a core vendor was already urgent; the breach rule never lowers it
        got = self.news_priorities(dp=story_rss([("Fortinet zero-day used to breach networks", "Read.",
                                                  rfc822(0.1))]))
        self.assertEqual(got, {"DoublePulsar: Fortinet zero-day used to breach networks": "urgent"})

    def test_msp_critical_vendors_count_as_core(self):
        cfg = test_config()
        cfg["watchlist"]["msp_critical"].append("acmeremote")
        lists = notifier.build_watchlists(cfg, {}, None)
        self.assertEqual(lists.core.find("AcmeRemote agent"), ["acmeremote"])
        got = self.news_priorities(dp=story_rss([("AcmeRemote breached", "Read.", rfc822(0.1))]), cfg=cfg)
        self.assertEqual(got, {"DoublePulsar: AcmeRemote breached": "urgent"})

    def test_new_feed_starts_silently(self):
        state = seeded_state()
        cfg = test_config()
        cfg["news"]["feeds"].append({"name": "Fresh", "url": "https://dp.example/feed", "filter": "all"})
        alerts, _, _ = run_once(state, FakeHttp(atom=ATOM_V2), cfg=cfg, now=NOW + timedelta(minutes=30))
        self.assertEqual([a.title for a in alerts if a.title.startswith("Fresh")], [])


class DeliveryTests(unittest.TestCase):
    ENV = {"NTFY_TOPIC": "topic", "VOICEMONKEY_TOKEN": "vm", "VOICEMONKEY_DEVICE": "echo"}

    def second_run(self, now, state=None, env=None):
        state = state or seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        alerts, _, failed = run_once(state, http, env=env or self.ENV, now=now)
        return state, http, alerts, failed

    def test_ntfy_payloads_and_one_alexa_announcement(self):
        _, http, alerts, _ = self.second_run(NOW + timedelta(minutes=30))
        ntfy = [p for u, p in http.posts if u == "https://ntfy.sh"]
        alexa = [p for u, p in http.posts if u == notifier.VOICEMONKEY_URL]
        self.assertEqual(len(ntfy), min(len(alerts), 12) + (1 if len(alerts) > 12 else 0))
        self.assertEqual(ntfy[0]["priority"], 5)
        self.assertEqual(ntfy[0]["topic"], "topic")
        self.assertTrue(ntfy[0]["click"].startswith("https://"))
        self.assertIn(2, {p["priority"] for p in ntfy})  # normal alerts arrive silently
        self.assertEqual(len(alexa), 1)
        self.assertIn("urgent security alerts", alexa[0]["speech"])
        self.assertEqual(alexa[0]["device"], "echo")

    def test_normal_alerts_make_sound_when_not_silent(self):
        cfg = test_config()
        cfg["delivery"]["normal_silent"] = False
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        run_once(seeded_state(), http, cfg=cfg, env=self.ENV, now=NOW + timedelta(minutes=30))
        priorities = {p["priority"] for u, p in http.posts if u == "https://ntfy.sh"}
        self.assertNotIn(2, priorities)
        self.assertIn(3, priorities)  # ntfy's default priority, with sound

    def test_alexa_stays_quiet_at_night(self):
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        state = seeded_state()
        state["nvd_last_mod"] = notifier.iso(night - timedelta(minutes=30))
        _, http, _, _ = self.second_run(night, state=state)
        self.assertFalse([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL])

    def test_phone_alerts_arrive_silently_during_quiet_hours(self):
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)  # Monday night
        state = seeded_state()
        state["nvd_last_mod"] = notifier.iso(night - timedelta(minutes=30))
        _, http, alerts, _ = self.second_run(night, state=state)
        ntfy = [p for u, p in http.posts if u == "https://ntfy.sh"]
        self.assertTrue(alerts)
        self.assertEqual(len(ntfy), len(alerts))       # nothing is held back
        self.assertEqual({p["priority"] for p in ntfy}, {2})
        self.assertIn(["rotating_light"], [p["tags"] for p in ntfy])  # urgent still looks urgent

    def test_urgent_can_still_ring_during_quiet_hours(self):
        cfg = test_config()
        cfg["delivery"]["phone_quiet_ring_urgent"] = True
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        alerts = [notifier.Alert(key="u", title="U", body="b", url="", priority="urgent"),
                  notifier.Alert(key="h", title="H", body="b", url="", priority="high")]
        http = FakeHttp()
        notifier.deliver(alerts, cfg, {}, http, {"NTFY_TOPIC": "t"}, night, log=lambda m: None)
        self.assertEqual({p["title"]: p["priority"] for _, p in http.posts}, {"U": 5, "H": 2})

    def test_phone_quiet_hours_for_telegram_and_pushover(self):
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        env = {"TELEGRAM_BOT_TOKEN": "bot", "TELEGRAM_CHAT_ID": "1",
               "PUSHOVER_APP_TOKEN": "app", "PUSHOVER_USER_KEY": "user"}
        alert = notifier.Alert(key="u", title="U", body="b", url="", priority="urgent")
        for when, quiet in ((night, True), (NOW, False)):
            http = FakeHttp()
            notifier.deliver([alert], test_config(), {}, http, env, when, log=lambda m: None)
            telegram = next(p for u, p in http.posts if "telegram" in u)
            pushover = next(p for u, p in http.posts if u == notifier.PUSHOVER_URL)
            self.assertEqual(telegram["disable_notification"], quiet)
            self.assertEqual(pushover["priority"], -1 if quiet else 1)

    def test_phone_quiet_hours_can_have_their_own_schedule_or_be_off(self):
        cfg = test_config()
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        early = datetime(2026, 11, 3, 6, 30, tzinfo=timezone.utc)
        cfg["delivery"]["phone_quiet_hours"] = "00:00-06:00"
        self.assertIsNone(notifier.phone_quiet_until(cfg, night))
        self.assertIsNone(notifier.phone_quiet_until(cfg, early))
        self.assertEqual(notifier.phone_quiet_until(cfg, night + timedelta(hours=1)),
                         datetime(2026, 11, 3, 6, 0, tzinfo=notifier.ZoneInfo("Europe/London")))
        cfg["delivery"]["phone_quiet_hours"] = ""
        self.assertIsNone(notifier.phone_quiet_until(cfg, night))
        del cfg["delivery"]["phone_quiet_hours"]  # older configs: the phone always rings
        self.assertIsNone(notifier.phone_quiet_until(cfg, night))

    def test_dry_run_shows_which_alerts_would_be_silent(self):
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        alert = notifier.Alert(key="h", title="H", body="b", url="", priority="high")
        lines: list[str] = []
        http = FakeHttp()
        notifier.deliver([alert], test_config(), {}, http, {"NTFY_TOPIC": "t"}, night, dry_run=True,
                         log=lines.append)
        self.assertEqual(http.posts, [])
        self.assertTrue(any("HIGH (silent: quiet hours): H" in line for line in lines))
        self.assertTrue(any(line.startswith("Phone: quiet hours until Tue 08:00") for line in lines))

    def test_alexa_holds_announcements_until_quiet_hours_end(self):
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)  # Monday night, London is on UTC
        state = seeded_state()
        state["nvd_last_mod"] = notifier.iso(night - timedelta(minutes=30))
        _, http, _, _ = self.second_run(night, state=state)
        self.assertFalse([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL])
        self.assertTrue(state["alexa_queue"])

        still_quiet = datetime(2026, 11, 3, 7, 37, tzinfo=timezone.utc)
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        run_once(state, http, env=self.ENV, now=still_quiet)
        self.assertFalse([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL])
        self.assertTrue(state["alexa_queue"])

        morning = datetime(2026, 11, 3, 8, 7, tzinfo=timezone.utc)
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        alerts, _, _ = run_once(state, http, env=self.ENV, now=morning)
        self.assertEqual(alerts, [])
        alexa = [p for u, p in http.posts if u == notifier.VOICEMONKEY_URL]
        self.assertEqual(len(alexa), 1)
        self.assertTrue(alexa[0]["speech"].startswith("Catching up after quiet hours."))
        self.assertNotIn("alexa_queue", state)

    def test_held_announcements_expire(self):
        state = seeded_state()
        state["alexa_queue"] = [{"key": "kev:old", "speech": "Old news.", "priority": "urgent",
                                 "queued": notifier.iso(NOW - timedelta(hours=25))}]
        http = FakeHttp()
        run_once(state, http, env=self.ENV, now=NOW + timedelta(minutes=30))
        for url, payload in http.posts:
            if url == notifier.VOICEMONKEY_URL:  # fresh alerts may still be spoken, the expired one not
                self.assertNotIn("Old news", payload["speech"])
                self.assertFalse(payload["speech"].startswith("Catching up"))
        self.assertNotIn("alexa_queue", state)

    def test_queue_can_be_turned_off(self):
        cfg = test_config()
        cfg["alexa"]["queue_during_quiet_hours"] = False
        night = datetime(2026, 11, 2, 23, 30, tzinfo=timezone.utc)
        state = seeded_state()
        state["nvd_last_mod"] = notifier.iso(night - timedelta(minutes=30))
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        run_once(state, http, cfg=cfg, env=self.ENV, now=night)
        self.assertFalse([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL])
        self.assertNotIn("alexa_queue", state)

    def test_alexa_monthly_cap(self):
        state = seeded_state()
        state["alexa"] = {"month": "2026-11", "count": 150}
        _, http, _, _ = self.second_run(NOW + timedelta(minutes=30), state=state)
        self.assertFalse([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL])

    def test_overflow_becomes_one_digest(self):
        cfg = test_config()
        cfg["delivery"]["max_alerts_per_run"] = 3
        alerts = [notifier.Alert(key=f"k{i}", title=f"Alert {i}", body="b", url="", priority="normal")
                  for i in range(10)]
        http = FakeHttp()
        notifier.deliver(alerts, cfg, {}, http, {"NTFY_TOPIC": "t"}, NOW, log=lambda m: None)
        self.assertEqual(len(http.posts), 4)
        self.assertEqual(http.posts[-1][1]["title"], "7 more security alerts")

    def test_failed_sends_are_retried_next_run(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        http.post_error = RuntimeError("ntfy down")
        alerts, _, failed = run_once(state, http, env={"NTFY_TOPIC": "t"}, now=NOW + timedelta(minutes=30))
        sent_individually = sorted(alerts, key=lambda a: notifier.PRIORITY_RANK[a.priority], reverse=True)[:12]
        self.assertEqual({a.key for a in failed}, {a.key for a in sent_individually})
        http.post_error = None
        retried, _, failed = run_once(state, http, env={"NTFY_TOPIC": "t"}, now=NOW + timedelta(minutes=60))
        self.assertEqual({a.key for a in retried}, {a.key for a in sent_individually})
        self.assertEqual(failed, [])
        self.assertNotIn("outbox", state)

    def test_dry_run_sends_nothing(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, news=NEWS_V2, atom=ATOM_V2)
        run_once(state, http, env=self.ENV, now=NOW + timedelta(minutes=30), dry_run=True)
        self.assertEqual(http.posts, [])


class WatchOrgTests(unittest.TestCase):
    ENV = {"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "rl-key", "WATCH_ORGS": "Zorblax Holdings, globex.com"}
    VICTIMS = [victim("Zorblax Holdings Ltd", "https://www.zorblax-holdings.co.uk/"),
               victim("Initech", "https://shop.globex.com"),
               victim("Zorblaxsupplies", "zorblaxsupplies.example"),  # 'zorblax holdings' is not a whole-word match
               victim("Umbrella Corp", "umbrella.example")]

    def run_with(self, victims, env=None, now=NOW + timedelta(minutes=30), state=None, cfg=None):
        state = state if state is not None else seeded_state()
        http = FakeHttp(ransomware=victims)
        alerts, errors, failed = run_once(state, http, cfg=cfg, env=env or self.ENV, now=now)
        return state, http, [a for a in alerts if a.source == "ransomware"], errors, failed

    def test_watch_orgs_come_from_config_and_the_secret(self):
        cfg = {"watch_orgs": ["Acme Holdings", "Contoso"]}
        env = {"WATCH_ORGS": " contoso ,Globex.com,\nInitech , "}
        self.assertEqual(notifier.watch_orgs(cfg, env), ["Acme Holdings", "Contoso", "Globex.com", "Initech"])
        self.assertEqual(notifier.watch_orgs({}, {}), [])

    def test_a_watched_victim_alerts_by_name_or_domain(self):
        state, http, alerts, errors, _ = self.run_with(self.VICTIMS)
        self.assertEqual(errors, [])
        self.assertEqual(sorted(a.title for a in alerts),
                         ["Ransomware: Initech listed by akira", "Ransomware: Zorblax Holdings Ltd listed by akira"])
        alert = next(a for a in alerts if "Zorblax" in a.title)
        self.assertEqual(alert.priority, "urgent")
        self.assertTrue(alert.private)
        self.assertIn("Matches your watch list: zorblax holdings", alert.body)
        self.assertIn("Source: Ransomware.live", alert.body)
        self.assertTrue(alert.url.startswith("https://www.ransomware.live/"))
        self.assertNotIn("zorblax", alert.key.lower())
        self.assertNotIn("Zorblax", alert.speech)
        self.assertIn(("rl-key"), [(h or {}).get("X-API-KEY") for u, h in http.gets if u == notifier.RANSOMWARE_LIVE_URL])

    def test_each_listing_alerts_once_and_old_ones_not_at_all(self):
        state, _, alerts, _, _ = self.run_with(self.VICTIMS)
        self.assertEqual(len(alerts), 2)
        _, _, alerts, _, _ = self.run_with(self.VICTIMS, state=state, now=NOW + timedelta(hours=1))
        self.assertEqual(alerts, [])
        _, _, alerts, _, _ = self.run_with([victim("Zorblax Holdings", days_ago=8)])
        self.assertEqual(alerts, [])

    def test_skipped_without_orgs_and_reported_without_a_key(self):
        _, http, alerts, errors, _ = self.run_with(self.VICTIMS, env={"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "k"})
        self.assertEqual((alerts, errors), ([], []))
        self.assertNotIn(notifier.RANSOMWARE_LIVE_URL, [u for u, _ in http.gets])
        _, http, alerts, errors, _ = self.run_with(self.VICTIMS, env={"NTFY_TOPIC": "t", "WATCH_ORGS": "Acme"})
        self.assertEqual(alerts, [])
        self.assertTrue(errors and "RANSOMWARE_LIVE_API_KEY" in errors[0])
        self.assertNotIn(notifier.RANSOMWARE_LIVE_URL, [u for u, _ in http.gets])

    def test_no_alerts_on_the_baseline_run(self):
        state = {}
        alerts, _, _ = run_once(state, FakeHttp(ransomware=self.VICTIMS), env=self.ENV)
        self.assertEqual([a.source for a in alerts], ["system"])

    def test_names_stay_out_of_logs_summaries_and_saved_state(self):
        import io
        import json
        import os
        import tempfile
        from contextlib import redirect_stdout

        names = ("Zorblax", "zorblax-holdings", "Initech", "globex")
        state = seeded_state()
        http = FakeHttp(ransomware=self.VICTIMS)
        env = dict(self.ENV, GITHUB_ACTIONS="true")
        out, lines = io.StringIO(), []
        with redirect_stdout(out):
            alerts, errors = notifier.collect(test_config(), state, http, env, NOW + timedelta(minutes=30))
        masked = {line.removeprefix("::add-mask::") for line in out.getvalue().splitlines()}
        self.assertTrue({"Zorblax Holdings", "globex.com", "Zorblax Holdings Ltd", "zorblax-holdings.co.uk"} <= masked)

        http.post_error = RuntimeError("ntfy down")  # failed sends must not park names in the outbox
        failed = notifier.deliver(alerts, test_config(), state, http, env, NOW + timedelta(minutes=30),
                                  log=lines.append)
        notifier.deliver(alerts, test_config(), state, FakeHttp(), env, NOW + timedelta(minutes=30), dry_run=True,
                         log=lines.append)
        notifier.finalise_state(state, alerts, failed, NOW + timedelta(minutes=30))
        with tempfile.TemporaryDirectory() as tmp:
            summary = os.path.join(tmp, "summary.md")
            notifier.write_summary({"GITHUB_STEP_SUMMARY": summary}, "run", state, alerts, failed, errors)
            summary_text = open(summary, encoding="utf-8").read()
        everything = "\n".join(lines) + summary_text + json.dumps(state)
        for name in names:
            self.assertNotIn(name.lower(), everything.lower(), name)
        self.assertIn("a watched organisation was listed", summary_text)

        # nothing was saved for the failed alerts, so the next run finds and sends them again
        alerts, _, _ = run_once(state, FakeHttp(ransomware=self.VICTIMS), env=self.ENV, now=NOW + timedelta(hours=1))
        self.assertEqual(len([a for a in alerts if a.source == "ransomware"]), 2)


class CountryTests(unittest.TestCase):
    ENV = {"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "rl-key"}

    def cfg(self, countries=("UK",), **extra):
        cfg = test_config()
        cfg["ransomware_live"].update(countries=list(countries), **extra)
        return cfg

    def run_with(self, victims, cfg=None, env=None, now=NOW + timedelta(minutes=30), state=None):
        state = state if state is not None else seeded_state()
        http = FakeHttp(ransomware=victims)
        alerts, errors, _ = run_once(state, http, cfg=cfg or self.cfg(), env=env or self.ENV, now=now)
        return state, http, [a for a in alerts if a.source == "ransomware"], errors

    def test_every_uk_victim_alerts_once_at_high_priority(self):
        victims = [victim("Northwind Traders", "northwind.co.uk"), victim("Fabrikam", "fabrikam.fr")]
        victims[1]["country"] = "FR"
        state, http, alerts, errors = self.run_with(victims)
        self.assertEqual(errors, [])
        self.assertEqual([(a.title, a.priority) for a in alerts],
                         [("Ransomware: Northwind Traders listed by akira", "high")])
        alert = alerts[0]
        self.assertTrue(alert.private)
        self.assertIn("Ransomware victim in GB", alert.body)
        self.assertEqual(notifier.public_title(alert),
                         "Ransomware: an organisation in GB was listed (details on your phone only)")
        self.assertIn("the UK", alert.speech)
        calls = [(u, h.get("X-API-KEY")) for u, h in http.gets if u == notifier.RANSOMWARE_LIVE_VICTIMS_URL]
        self.assertTrue(calls and all(key == "rl-key" for _, key in calls))
        self.assertNotIn(notifier.RANSOMWARE_LIVE_URL, [u for u, _ in http.gets])  # no watch list: no recent call
        _, _, alerts, _ = self.run_with(victims, state=state, now=NOW + timedelta(hours=1))
        self.assertEqual(alerts, [])

    def test_month_boundary_and_age_limit(self):
        self.assertEqual(notifier.months_back(datetime(2026, 11, 3, tzinfo=timezone.utc), timedelta(days=7)),
                         [(2026, 10), (2026, 11)])
        self.assertEqual(notifier.months_back(datetime(2027, 1, 2, tzinfo=timezone.utc), timedelta(days=7)),
                         [(2026, 12), (2027, 1)])
        _, _, alerts, _ = self.run_with([victim("Old Ltd", days_ago=9), victim("New Ltd", days_ago=1.5)])
        self.assertEqual([a.title for a in alerts], ["Ransomware: New Ltd listed by akira"])

    def test_a_watched_uk_organisation_is_urgent_and_says_so(self):
        env = dict(self.ENV, WATCH_ORGS="Northwind")
        _, _, alerts, _ = self.run_with([victim("Northwind Traders"), victim("Contoso UK")], env=env)
        got = {a.title: (a.priority, notifier.public_title(a)) for a in alerts}
        self.assertEqual(got["Ransomware: Northwind Traders listed by akira"][0], "urgent")
        self.assertIn("a watched organisation", got["Ransomware: Northwind Traders listed by akira"][1])
        self.assertEqual(got["Ransomware: Contoso UK listed by akira"][0], "high")

    def test_countries_accept_uk_and_can_be_turned_off(self):
        self.assertEqual(notifier.watch_countries({"countries": ["uk", "GB", "ie", "bad"]}), ["GB", "IE"])
        _, http, alerts, errors = self.run_with([victim("Northwind Traders")], cfg=self.cfg(countries=()))
        self.assertEqual((alerts, errors), ([], []))
        self.assertNotIn(notifier.RANSOMWARE_LIVE_VICTIMS_URL, [u for u, _ in http.gets])

    def test_country_priority_switches_alexa_on_and_off(self):
        env = dict(self.ENV, VOICEMONKEY_TOKEN="vm", VOICEMONKEY_DEVICE="echo")
        for priority, spoken in (("urgent", True), ("high", False)):
            state = seeded_state()
            http = FakeHttp(ransomware=[victim("Northwind Traders", "northwind.co.uk")],
                            nvd={"totalResults": 0, "vulnerabilities": []})  # only the listing is new
            alerts, _, _ = run_once(state, http, cfg=self.cfg(country_priority=priority), env=env,
                                    now=NOW + timedelta(minutes=30))
            self.assertEqual([a.priority for a in alerts if a.source == "ransomware"], [priority])
            ntfy = [p for u, p in http.posts if u == "https://ntfy.sh" and "Northwind" in p["title"]]
            self.assertEqual(len(ntfy), 1)  # the phone gets it either way
            alexa = [p["speech"] for u, p in http.posts if u == notifier.VOICEMONKEY_URL]
            if spoken:
                self.assertEqual(alexa, ["Ransomware alert. An organisation in the UK has been listed on a "
                                         "ransomware leak site. Check your phone."])
            else:
                self.assertEqual(alexa, [])

    def test_a_failed_lookup_is_a_source_error(self):
        state = seeded_state()
        http = FakeHttp(ransomware=[victim("Northwind Traders")], fail={notifier.RANSOMWARE_LIVE_VICTIMS_URL})
        alerts, errors, _ = run_once(state, http, cfg=self.cfg(), env=self.ENV, now=NOW + timedelta(minutes=30))
        self.assertEqual([a for a in alerts if a.source == "ransomware"], [])
        self.assertEqual(errors, ["ransomware.live: HTTP 503"])

    def test_country_alerts_never_name_the_victim_in_summaries(self):
        import os
        import tempfile
        _, _, alerts, errors = self.run_with([victim("Northwind Traders", "northwind.co.uk")])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "s.md")
            notifier.write_summary({"GITHUB_STEP_SUMMARY": path}, "run", {}, alerts, [], errors)
            text = open(path, encoding="utf-8").read()
        self.assertNotIn("northwind", text.lower())
        self.assertIn("an organisation in GB was listed", text)


MASTODON = "https://cyberplace.social/@GossiTheDog.rss"
BLUESKY = "https://bsky.app/profile/troyhunt.com/rss"


def social_rss(posts):
    """A Mastodon or Bluesky feed: posts have text and a link, but no title."""
    body = "".join(
        f"<item><link>https://social.example/{abs(hash(text))}</link><guid>{abs(hash(text))}</guid>"
        f"<pubDate>{rfc822(days)}</pubDate><description>&lt;p&gt;{text}&lt;/p&gt;</description></item>"
        for text, days in posts
    )
    return f"<?xml version='1.0'?><rss version='2.0'><channel><title>s</title>{body}</channel></rss>".encode()


class SocialTests(unittest.TestCase):
    def cfg(self, **social):
        cfg = test_config()
        cfg["social"].update(accounts=[{"name": "Kevin Beaumont", "mastodon": "https://cyberplace.social/@GossiTheDog"},
                                       {"name": "Troy Hunt", "bluesky": "troyhunt.com"}], **social)
        return cfg

    def run_posts(self, mastodon, bluesky=(), cfg=None, news=NEWS_V1):
        cfg = cfg or self.cfg()
        state = seeded_state()
        baseline = FakeHttp(social={MASTODON: social_rss([]), BLUESKY: social_rss([])})
        _, errors, _ = run_once(state, baseline, cfg=cfg, now=NOW + timedelta(minutes=30))  # new feeds start silently
        self.assertEqual(errors, [])
        http = FakeHttp(news=news, social={MASTODON: social_rss(mastodon), BLUESKY: social_rss(bluesky)})
        alerts, errors, _ = run_once(state, http, cfg=cfg, now=NOW + timedelta(hours=1))
        return [a for a in alerts if a.source == "news"], errors

    def test_feed_urls_from_profiles_and_handles(self):
        self.assertEqual(notifier.mastodon_feed_url("https://infosec.exchange/@cyb3rops"),
                         "https://infosec.exchange/@cyb3rops.rss")
        self.assertEqual(notifier.mastodon_feed_url("@cyb3rops@infosec.exchange"),
                         "https://infosec.exchange/@cyb3rops.rss")
        for handle in ("troyhunt.com", "@troyhunt.com", "https://bsky.app/profile/troyhunt.com"):
            self.assertEqual(notifier.bluesky_feed_url(handle), BLUESKY)
        errors = []
        cfg = self.cfg()
        cfg["social"]["accounts"] += [{"name": "Broken", "mastodon": "cyb3rops"}, {"name": "Muted", "bluesky": "x.y",
                                                                                     "enabled": False}]
        feeds = notifier.social_feeds(cfg, errors)
        self.assertEqual([f["url"] for f in feeds], [MASTODON, BLUESKY])
        self.assertTrue(all(f["filter"] == "keywords" for f in feeds))
        self.assertEqual(len(errors), 1)
        self.assertIn("Broken", errors[0])
        cfg["social"]["enabled"] = False
        self.assertEqual(notifier.social_feeds(cfg, []), [])

    def test_keyword_filter_and_priority_rule(self):
        alerts, errors = self.run_posts([
            ("FortiGate zero-day exploited in the wild, patch now", 0),   # hot keyword + core vendor
            ("Seeing a zero-day in some obscure blogging plugin", 0),     # hot keyword, no core vendor
            ("Okta breached, customer data stolen", 0),                   # core vendor, no hot keyword
            ("Lovely weather in London today", 0),                        # no keyword at all
        ], bluesky=[("New breach loaded into Have I Been Pwned", 0)])
        self.assertEqual(errors, [])
        got = {a.title: a.priority for a in alerts}
        self.assertEqual(got, {
            "Kevin Beaumont: FortiGate zero-day exploited in the wild, patch now": "high",
            "Kevin Beaumont: Seeing a zero-day in some obscure blogging plugin": "normal",
            "Kevin Beaumont: Okta breached, customer data stolen": "normal",  # news would make this urgent
            "Troy Hunt: New breach loaded into Have I Been Pwned": "normal",
        })

    def test_hot_vendor_priority_is_configurable(self):
        alerts, _ = self.run_posts([("FortiGate zero-day exploited in the wild", 0)],
                                   cfg=self.cfg(hot_vendor_priority="urgent"))
        self.assertEqual([a.priority for a in alerts], ["urgent"])

    def test_long_posts_get_a_short_title_and_keep_the_text(self):
        text = "Ransomware " + "word " * 60 + "end."
        alerts, _ = self.run_posts([(text, 0)])
        title = alerts[0].title.removeprefix("Kevin Beaumont: ")
        self.assertLessEqual(len(title), notifier.SOCIAL_TITLE_LENGTH + 1)
        self.assertTrue(title.endswith("…"))
        self.assertEqual(alerts[0].body, text.strip())

    def test_a_post_on_a_news_story_is_grouped_with_it(self):
        news = story_rss([("Ivanti patches CVE-2026-4242 zero-day in Connect Secure", "Patch now.", rfc822(0.1))])
        alerts, _ = self.run_posts([("CVE-2026-4242 is being exploited, patch your Ivanti boxes", 0)], news=news)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].title, "News: Ivanti patches CVE-2026-4242 zero-day in Connect Secure")
        self.assertIn("Also covered by: Kevin Beaumont", alerts[0].body)

    def test_old_posts_are_ignored(self):
        alerts, _ = self.run_posts([("FortiGate zero-day exploited in the wild", 5)])
        self.assertEqual(alerts, [])


def load_tool(name):
    import importlib.util
    path = Path(__file__).resolve().parents[1] / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_drill():
    return load_tool("drill")


class FakeWeb:
    """Every URL answers from `pages` (bytes, a JSON-able dict, or an exception); anything else is a 404."""

    def __init__(self, pages):
        self.pages = pages
        self.posts = []

    def _answer(self, url, params=None):
        key = f"{url}?{'&'.join(f'{k}={v}' for k, v in params.items())}" if params else url
        answer = self.pages.get(key, RuntimeError("HTTP 404"))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def get_bytes(self, url, **kw):
        return self._answer(url)

    def get_json(self, url, params=None, headers=None, **kw):
        return self._answer(url, params)

    def post(self, url, json_body=None, form=None, headers=None):
        self.posts.append((url, json_body or form))


FRESH = rss([("Fresh post", "x", rfc822(1))])
STALE = rss([("Old post", "x", rfc822(40))])
HOMEPAGE = b"""<html><head><link rel="alternate" type="application/rss+xml" title="Blog"
href="/blog/feed.xml"></head></html>"""


class FeedCheckTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool("feed_check")

    def cfg(self, feeds=(), accounts=(), **check):
        return {"news": {"feeds": list(feeds)}, "social": {"enabled": True, "accounts": list(accounts)},
                "feed_check": dict({"enabled": True, "silent_days": 14}, **check), "delivery": {}}

    def run_check(self, cfg, pages, send=True, env=None):
        web, lines = FakeWeb(pages), []
        cfg_before = copy.deepcopy(cfg)
        code = self.tool.run_check(cfg, web, env if env is not None else {"NTFY_TOPIC": "t"}, NOW, send,
                                   log=lines.append)
        self.assertEqual(cfg, cfg_before)  # never edits the config
        return code, web, "\n".join(lines)

    def test_a_moved_feed_is_found_on_the_homepage(self):
        cfg = self.cfg([{"name": "Lab", "url": "https://lab.example/rss/", "filter": "all"}])
        code, web, out = self.run_check(cfg, {"https://lab.example/": HOMEPAGE,
                                              "https://lab.example/blog/feed.xml": FRESH})
        self.assertEqual(code, 0)
        self.assertIn("Lab: FAILED, HTTP 404", out)
        self.assertIn("Suggested fix: Change url to https://lab.example/blog/feed.xml (checked: 1 posts, newest 1 "
                      "days ago)", out)
        [(url, msg)] = web.posts
        self.assertEqual(msg["priority"], 2)  # arrives without sound
        self.assertEqual(msg["title"], "Feed check: 1 of 1 feeds need attention")
        self.assertIn("config.yaml was not changed.", msg["message"])

    def test_silent_feed_without_a_working_alternative(self):
        cfg = self.cfg([{"name": "Quiet", "url": "https://quiet.example/feed/"}])
        _, web, out = self.run_check(cfg, {"https://quiet.example/feed/": STALE,
                                           "https://quiet.example/rss": STALE})  # an alternative, but just as stale
        self.assertIn("Quiet: SILENT 14+ days, last post 40 days ago", web.posts[0][1]["message"])
        self.assertIn("No fix found", web.posts[0][1]["message"])

    def test_timeouts_are_retried_and_called_temporary(self):
        cfg = self.cfg([{"name": "Slow", "url": "https://slow.example/feed/"}])
        timeout = RuntimeError("HTTPSConnectionPool(host='slow.example', port=443): Read timed out. (read timeout=30)")
        pages = {"https://slow.example/feed/": timeout, "https://slow.example/rss": FRESH}
        _, web, _ = self.run_check(cfg, pages)
        message = web.posts[0][1]["message"]
        self.assertIn("Slow: FAILED, read timed out", message)
        self.assertIn("Looks temporary", message)
        self.assertNotIn("Change url", message)  # a slow server is not a moved feed

        class Flaky(FakeWeb):  # fails once, then works
            def get_bytes(self, url, **kw):
                self.calls = getattr(self, "calls", 0) + 1
                if self.calls == 1:
                    raise timeout
                return FRESH
        web, lines = Flaky({}), []
        self.tool.run_check(cfg, web, {"NTFY_TOPIC": "t"}, NOW, True, log=lines.append)
        self.assertEqual(web.posts, [])
        self.assertIn("ok     Slow", "\n".join(lines))

    def test_reddit_blocking_has_its_own_advice(self):
        cfg = self.cfg([{"name": "r/x", "url": "https://www.reddit.com/r/x/new/.rss"}])
        _, _, out = self.run_check(cfg, {"https://www.reddit.com/r/x/new/.rss": RuntimeError("HTTP 429")})
        self.assertIn("Reddit blocks GitHub's servers", out)

    def test_mastodon_moves_and_deletions(self):
        moved = {"name": "Moved", "mastodon": "https://old.example/@ana"}
        gone = {"name": "Gone", "mastodon": "https://old.example/@bob"}
        pages = {
            "https://old.example/@ana.rss": social_rss([("hello", 60)]),
            "https://old.example/api/v1/accounts/lookup?acct=ana": {"moved": {"url": "https://new.example/@ana"}},
            "https://new.example/@ana.rss": social_rss([("still here", 2)]),
            "https://old.example/@bob.rss": RuntimeError("HTTP 410"),
        }
        _, _, out = self.run_check(self.cfg(accounts=[moved, gone]), pages)
        self.assertIn("The account moved: change mastodon to https://new.example/@ana", out)
        self.assertIn("The account @bob@old.example no longer exists", out)

    def test_bluesky_handle_gone_and_quiet_accounts(self):
        accounts = [{"name": "Renamed", "bluesky": "old.bsky.social"}, {"name": "Rare", "bluesky": "rare.bsky.social"}]
        pages = {"https://bsky.app/profile/rare.bsky.social/rss": social_rss([("hi", 30)])}
        _, _, out = self.run_check(self.cfg(accounts=accounts), pages)
        self.assertIn("The handle old.bsky.social no longer exists", out)
        self.assertIn("Rare: SILENT 14+ days", out)
        self.assertIn("add enabled: false to the account", out)

    def test_quiet_ok_all_fine_and_dry_run(self):
        accounts = [{"name": "Rare", "bluesky": "rare.bsky.social"}]
        pages = {"https://bsky.app/profile/rare.bsky.social/rss": social_rss([("hi", 30)])}
        _, web, out = self.run_check(self.cfg(accounts=accounts, quiet_ok=["rare"]), pages)
        self.assertEqual(web.posts, [])
        self.assertIn("nothing to send", out)
        _, web, _ = self.run_check(self.cfg(accounts=accounts, quiet_ok=["Rare"], notify_when_all_ok=True), pages)
        self.assertEqual([m["title"] for _, m in web.posts], ["Feed check: all 1 feeds are fine"])
        _, web, out = self.run_check(self.cfg(accounts=accounts), pages, send=False)
        self.assertEqual(web.posts, [])
        self.assertIn("[dry-run] not sent", out)

    def test_invalid_account_and_disabled_feeds(self):
        cfg = self.cfg([{"name": "Off", "url": "https://off.example/feed", "enabled": False}],
                       [{"name": "Typo", "mastodon": "ana"}])
        _, web, out = self.run_check(cfg, {})
        self.assertNotIn("Off", out)
        self.assertIn("Typo: FAILED, not a Mastodon profile", web.posts[0][1]["message"])

    def test_turned_off_and_no_phone_channel(self):
        cfg = self.cfg([{"name": "Lab", "url": "https://lab.example/rss/"}], enabled=False)
        code, web, out = self.run_check(cfg, {})
        self.assertEqual((code, web.posts), (0, []))
        code, _, out = self.run_check(self.cfg([{"name": "Lab", "url": "https://lab.example/rss/"}]), {}, env={})
        self.assertEqual(code, 1)
        self.assertIn("No phone channel configured", out)


class RansomwareDrillTests(unittest.TestCase):
    ENV = {"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "rl-key", "VOICEMONKEY_TOKEN": "vm",
           "VOICEMONKEY_DEVICE": "echo", "WATCH_ORGS": "Northwind"}

    def drill(self, victims, live, countries=("UK",), country=None):
        cfg = test_config()
        cfg["ransomware_live"].update(countries=list(countries), country_priority="urgent")
        http, lines = FakeHttp(ransomware=victims), []
        code = load_drill().ransomware_drill(cfg, dict(self.ENV), http, NOW, live, country=country,
                                             log=lines.append)
        return code, http, "\n".join(lines)

    def test_dry_run_sends_nothing_and_never_logs_the_name(self):
        code, http, out = self.drill([victim("Northwind Traders", "northwind.co.uk", days_ago=20)], live=False)
        self.assertEqual(code, 0)
        self.assertEqual(http.posts, [])
        self.assertIn("DRILL: Ransomware: an organisation in GB was listed", out)
        self.assertIn("[dry-run] Alexa: This is a drill. Ransomware alert. An organisation in the UK", out)
        self.assertNotIn("northwind", out.lower())

    def test_live_drill_rings_the_phone_and_alexa(self):
        code, http, out = self.drill([victim("Northwind Traders", "northwind.co.uk")], live=True)
        self.assertEqual(code, 0)
        ntfy = [p for u, p in http.posts if u == "https://ntfy.sh"]
        self.assertEqual([p["title"] for p in ntfy], ["DRILL: Ransomware: Northwind Traders listed by akira"])
        alexa = [p["speech"] for u, p in http.posts if u == notifier.VOICEMONKEY_URL]
        self.assertEqual(len(alexa), 1)
        self.assertTrue(alexa[0].startswith("This is a drill. Ransomware alert. An organisation in the UK"))
        self.assertNotIn("watched", alexa[0])  # WATCH_ORGS is ignored: a drill never handles client names
        self.assertNotIn("northwind", out.lower())

    def test_no_listing_or_no_country(self):
        code, http, out = self.drill([], live=True)
        self.assertEqual((code, http.posts), (0, []))
        self.assertIn("No ransomware.live listing in GB", out)
        old = victim("Old Ltd", days_ago=40)
        code, http, _ = self.drill([old], live=True)
        self.assertEqual(http.posts, [])
        code, _, out = self.drill([victim("Northwind Traders")], live=True, countries=())
        self.assertEqual(code, 1)
        self.assertIn("No countries to drill", out)

    def test_country_flag_overrides_config(self):
        fr = victim("Fabrikam", "fabrikam.fr")
        fr["country"] = "FR"
        code, http, out = self.drill([victim("Northwind Traders"), fr], live=True, country="FR")
        self.assertEqual([p["title"] for u, p in http.posts if u == "https://ntfy.sh"],
                         ["DRILL: Ransomware: Fabrikam listed by akira"])


class KevAndNewsDrillTests(unittest.TestCase):
    ENV = {"NTFY_TOPIC": "t", "VOICEMONKEY_TOKEN": "vm", "VOICEMONKEY_DEVICE": "echo"}

    def run_drill(self, kind, arg, live=True, http=None):
        http, lines = http or FakeHttp(kev=KEV_V2), []
        drill = load_drill()
        fn = drill.kev_drill if kind == "kev" else drill.news_drill
        code = fn(arg, test_config(), dict(self.ENV), http, NOW, live, log=lines.append)
        return code, http, "\n".join(lines)

    @staticmethod
    def sent(http):
        phone = [p["title"] for u, p in http.posts if u == "https://ntfy.sh"]
        alexa = [p["speech"] for u, p in http.posts if u == notifier.VOICEMONKEY_URL]
        return phone, alexa

    def test_kev_drill_treats_the_entry_as_just_added(self):
        originals = (notifier.fetch_kev, notifier.fetch_nvd, notifier.fetch_feed)
        code, http, out = self.run_drill("kev", "CVE-2026-40001")  # Fortinet: core vendor
        self.assertEqual(code, 0)
        self.assertIn("treated as added just now", out)
        self.assertIn("Decision: URGENT - KEV: CVE-2026-40001", out)
        phone, alexa = self.sent(http)
        self.assertEqual(len(phone), 1)
        self.assertTrue(phone[0].startswith("DRILL: KEV: CVE-2026-40001"))
        self.assertEqual(len(alexa), 1)
        self.assertTrue(alexa[0].startswith("This is a drill. "))
        self.assertEqual((notifier.fetch_kev, notifier.fetch_nvd, notifier.fetch_feed), originals)

    def test_kev_drill_for_a_vendor_off_the_core_list_stays_off_alexa(self):
        code, http, out = self.run_drill("kev", "CVE-2026-40002")
        self.assertIn("Decision: HIGH", out)
        self.assertIn("Alexa: stays silent", out)
        self.assertEqual(self.sent(http)[1], [])

    def test_kev_drill_needs_a_kev_entry(self):
        code, http, out = self.run_drill("kev", "CVE-2099-0001")
        self.assertEqual((code, http.posts), (1, []))
        self.assertIn("not in CISA's KEV catalogue", out)

    def test_news_drill_ranks_a_headline_like_a_new_feed_item(self):
        code, http, out = self.run_drill("news", ["News: ConnectWise breached by state-backed hackers"])
        self.assertEqual(code, 0)
        self.assertIn("Not in News's feed any more", out)
        self.assertIn("MSP-critical in headline: connectwise", out)
        self.assertIn("Decision: URGENT - News: ConnectWise breached by state-backed hackers", out)
        phone, alexa = self.sent(http)
        self.assertEqual(phone, ["DRILL: News: ConnectWise breached by state-backed hackers"])
        self.assertEqual(len(alexa), 1)

    def test_news_drill_uses_the_real_item_when_it_is_still_in_the_feed(self):
        code, http, out = self.run_drill("news", ["news: old story about patching"], live=False)
        self.assertIn("Found in News's feed", out)
        self.assertEqual(http.posts, [])

    def test_news_drill_reports_a_headline_the_filter_drops(self):
        code, http, out = self.run_drill("news", ["News: Lunch menu updated for the canteen"])
        self.assertEqual((code, http.posts), (0, []))
        self.assertIn("DROPPED", out)
        self.assertIn("would NOT alert", out)

    def test_news_drill_groups_headlines_about_one_story(self):
        title = "Fortinet zero-day CVE-2026-40001 exploited in FortiGate attacks"
        code, http, out = self.run_drill("news", [f"News: {title}", f"DoublePulsar: {title}"], live=False)
        self.assertEqual(out.count("Decision:"), 1)
        self.assertIn("Also covered by: DoublePulsar", out)

    def test_news_drill_needs_a_known_feed(self):
        code, http, out = self.run_drill("news", ["Nowhere Times: something happened"])
        self.assertEqual((code, http.posts), (1, []))
        self.assertIn("Feeds: News, DoublePulsar", out)


class StricterAlertTests(unittest.TestCase):
    """cve.require_epss, news.min_priority, news.vendor_breach_extended and alexa.never_announce."""

    def strict(self):
        cfg = test_config()
        cfg["cve"]["require_epss"] = True
        cfg["news"].update(min_priority="high", vendor_breach_extended=True)
        cfg["alexa"]["never_announce"] = ["ransomware"]
        return cfg

    def second_run(self, cfg, news=NEWS_V2, atom=ATOM_V2, **http):
        state = seeded_state()
        alerts, errors, _ = run_once(state, FakeHttp(kev=KEV_V2, news=news, atom=atom, **http), cfg=cfg,
                                     now=NOW + timedelta(minutes=30))
        self.assertEqual(errors, [])
        return {a.key if a.source != "news" else a.title: a.priority for a in alerts}

    def test_shipped_config_uses_the_stricter_rules(self):
        self.assertIs(CONFIG["cve"]["require_epss"], True)
        self.assertEqual(CONFIG["news"]["min_priority"], "high")
        self.assertIs(CONFIG["news"]["vendor_breach_extended"], True)
        self.assertIn("never_announce", CONFIG["alexa"])

    def test_shipped_config_ranks_real_november_headlines(self):
        news = CONFIG["news"]
        lists = notifier.build_watchlists(CONFIG, {}, None)
        hot = notifier.news_matcher(news["hot_keywords"], news)
        breach = notifier.news_matcher(news["vendor_breach_keywords"], news)
        rank = lambda title: notifier.headline_priority(title, title, lists, hot, breach, True)  # noqa: E731
        self.assertEqual(rank("Ivanti patches two more Connect Secure zero-days chained in attacks"), "urgent")
        for title in ("Over 1,000 GitLab servers vulnerable to ongoing RCE attacks",
                      "Synology warns of C3RB3R ransomware attacks targeting NAS devices",
                      "Hackers exploit critical PHP flaw"):
            self.assertEqual(rank(title), "high", title)
        for title in ("Fintech platform Sageworks taken offline after suspected cyberattack",
                      "Google Disrupts 1.3 Million-Device Android Botnet",
                      "Weekly Recap: Critical CVEs, Linux DDoS Botnet, Device-Code Phishing"):
            self.assertEqual(rank(title), "normal", title)  # dropped at news.min_priority: high

    def test_cves_need_a_high_epss_and_kev_always_alerts(self):
        got = self.second_run(self.strict())
        cves = {k: v for k, v in got.items() if k.startswith("cve:")}
        self.assertEqual(cves, {"cve:CVE-2026-50002": "high",      # EPSS 35%
                                "cve:CVE-2026-50006": "urgent",    # core critical, EPSS 50%
                                "cve:CVE-2026-50012": "urgent"})   # EPSS 60% on a critical
        self.assertEqual((got["kev:CVE-2026-40001"], got["kev:CVE-2026-40002"]), ("urgent", "high"))

    def test_news_below_high_is_dropped(self):
        got = self.second_run(self.strict())
        news = {k: v for k, v in got.items() if not k.startswith(("kev:", "cve:"))}
        self.assertEqual(news, {"News: Fortinet warns of new FortiWeb zero-day exploited in attacks": "urgent"})

    def test_exploited_wording_and_extended_vendor_breaches_get_through(self):
        dp = story_rss([("Hackers exploit critical PHP flaw to hijack servers", "Read.", rfc822(0.1)),
                        ("Salesforce confirms customer data stolen", "Read.", rfc822(0.1)),
                        ("Retailer hacked after phishing campaign", "Read.", rfc822(0.1)),
                        ("Our favourite conference talks this year", "Read.", rfc822(0.1))])
        news = story_rss([("Windows servers under attack", "No filter word in this summary.", rfc822(0.1))])
        got = self.second_run(self.strict(), news=news, atom=dp, nvd={"totalResults": 0, "vulnerabilities": []})
        news_got = {k: v for k, v in got.items() if not k.startswith(("kev:", "cve:"))}
        self.assertEqual(news_got, {
            "DoublePulsar: Hackers exploit critical PHP flaw to hijack servers": "high",
            "DoublePulsar: Salesforce confirms customer data stolen": "high",  # extended vendor
            "News: Windows servers under attack": "urgent",                     # past the keyword filter
        })
        cfg = self.strict()
        cfg["news"]["vendor_breach_extended"] = False
        got = self.second_run(cfg, news=news, atom=dp, nvd={"totalResults": 0, "vulnerabilities": []})
        self.assertNotIn("DoublePulsar: Salesforce confirms customer data stolen", got)

    def test_social_posts_also_need_high(self):
        cfg = self.strict()
        cfg["social"]["accounts"] = [{"name": "Kevin Beaumont", "mastodon": "https://cyberplace.social/@GossiTheDog"}]
        state = seeded_state()
        run_once(state, FakeHttp(social={MASTODON: social_rss([])}), cfg=cfg, now=NOW + timedelta(minutes=30))
        http = FakeHttp(social={MASTODON: social_rss([("FortiGate zero-day exploited in the wild", 0),
                                                       ("Okta breached, customer data stolen", 0)])})
        alerts, _, _ = run_once(state, http, cfg=cfg, now=NOW + timedelta(hours=1))
        self.assertEqual([(a.title, a.priority) for a in alerts if a.source == "news"],
                         [("Kevin Beaumont: FortiGate zero-day exploited in the wild", "high")])

    def test_never_announce_keeps_ransomware_on_the_phone_only(self):
        cfg = self.strict()
        cfg["ransomware_live"].update(countries=["GB"], country_priority="urgent")
        env = {"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "k", "VOICEMONKEY_TOKEN": "vm", "VOICEMONKEY_DEVICE": "e"}
        state = seeded_state()
        state["alexa_queue"] = [{"key": "ransomware:abc", "speech": "Held ransomware.", "priority": "urgent",
                                 "queued": notifier.iso(NOW)}]
        http = FakeHttp(ransomware=[victim("Northwind Traders")], nvd={"totalResults": 0, "vulnerabilities": []})
        alerts, _, _ = run_once(state, http, cfg=cfg, env=env, now=NOW + timedelta(minutes=30))
        self.assertEqual([a.priority for a in alerts if a.source == "ransomware"], ["urgent"])
        ntfy = [p for u, p in http.posts if u == "https://ntfy.sh" and "Northwind" in p["title"]]
        self.assertEqual([p["priority"] for p in ntfy], [5])  # still max priority on the phone
        self.assertEqual([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL], [])
        self.assertNotIn("alexa_queue", state)  # a held ransomware announcement is dropped too
        # other sources are still spoken
        kev = notifier.Alert(key="kev:CVE-1", title="t", body="", url="", priority="urgent", speech="KEV.",
                             source="kev")
        http = FakeHttp()
        notifier.announce_on_alexa([kev], cfg, {"alexa": {"month": "2026-11", "count": 0}}, http, env, NOW, False,
                                   lambda m: None)
        self.assertEqual([p["speech"] for _, p in http.posts], ["KEV."])

    def test_drills_explain_the_stricter_rules(self):
        drill = load_drill()
        lines = []
        cfg = self.strict()
        cfg["ransomware_live"].update(countries=["GB"], country_priority="urgent")
        http = FakeHttp(ransomware=[victim("Northwind Traders")])
        drill.ransomware_drill(cfg, {"NTFY_TOPIC": "t", "RANSOMWARE_LIVE_API_KEY": "k", "VOICEMONKEY_TOKEN": "v",
                                     "VOICEMONKEY_DEVICE": "e"}, http, NOW, True, log=lines.append)
        self.assertIn("alexa.never_announce lists ransomware", "\n".join(lines))
        self.assertEqual([u for u, _ in http.posts if u == notifier.VOICEMONKEY_URL], [])
        lines = []
        code = drill.news_drill(["DoublePulsar: Our favourite conference talks this year"], self.strict(),
                                {"NTFY_TOPIC": "t"}, FakeHttp(kev=KEV_V2), NOW, False, log=lines.append)
        out = "\n".join(lines)
        self.assertEqual(code, 0)
        self.assertIn("DROPPED: it ranks normal, below news.min_priority (high)", out)
        self.assertIn("would NOT alert", out)


class HelperTests(unittest.TestCase):
    def test_quiet_schedule_for_weekdays_and_weekends(self):
        london = notifier.ZoneInfo("Europe/London")

        def at(day, hh, mm=0):  # November 2026: the 2nd is a Monday
            return datetime(2026, 11, day, hh, mm, tzinfo=london)

        until = lambda when, spec=QUIET: notifier.quiet_until(when, spec)  # noqa: E731
        self.assertEqual(until(at(2, 7, 59)), at(2, 8))      # Monday morning
        self.assertIsNone(until(at(2, 8)))
        self.assertIsNone(until(at(2, 22, 59)))
        self.assertEqual(until(at(2, 23)), at(3, 8))         # Monday night runs into Tuesday
        self.assertIsNone(until(at(6, 23, 30)))              # Friday night is free until 01:00
        self.assertIsNone(until(at(7, 0, 30)))
        self.assertEqual(until(at(7, 1)), at(7, 11))         # Saturday
        self.assertEqual(until(at(8, 10, 59)), at(8, 11))    # Sunday
        self.assertIsNone(until(at(8, 11)))
        self.assertEqual(until(at(8, 23, 30)), at(9, 8))     # Sunday night is a work night
        self.assertEqual(until(at(4, 23), "22:00-07:30"), at(5, 7, 30))
        self.assertIsNone(until(at(4, 12), "22:00-07:30"))
        no_friday = dict(QUIET, friday="")
        self.assertIsNone(until(at(6, 7), no_friday))
        self.assertEqual(until(at(5, 7), no_friday), at(5, 8))
        self.assertIsNone(until(at(5, 7), None))

    def test_story_fingerprints(self):
        lists = notifier.build_watchlists(test_config(), {}, None)
        a = notifier.story_fingerprint("Palo Alto Networks patches portal auth bypass in GlobalProtect", lists)
        b = notifier.story_fingerprint("PaloAltoNetworks portal auth bypass exploited", lists)
        self.assertIn("paloaltonetworks", a["vendors"])
        self.assertNotIn("patch", a["words"])          # generic words never count
        self.assertNotIn("palo", a["words"])           # nor do the vendor's own words
        self.assertIn("auth", a["words"])
        self.assertTrue(notifier.same_story(a, b))
        self.assertFalse(notifier.same_story(a, b, min_shared_words=4))
        c = notifier.story_fingerprint("Fresh look at cve-2026-0001", lists)
        self.assertEqual(c["cves"], ["CVE-2026-0001"])
        self.assertTrue(notifier.same_story(c, {"cves": ["CVE-2026-0001"]}))

    def test_quiet_hours_across_midnight(self):
        self.assertTrue(notifier.in_quiet_hours(dtime(23, 0), "22:00-07:30"))
        self.assertTrue(notifier.in_quiet_hours(dtime(6, 0), "22:00-07:30"))
        self.assertFalse(notifier.in_quiet_hours(dtime(12, 0), "22:00-07:30"))

    def test_best_cvss_takes_the_highest_score(self):
        metrics = {
            "cvssMetricV31": [{"cvssData": {"version": "3.1", "baseScore": 7.5, "vectorString": "v31"}}],
            "cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 9.3, "vectorString": "v40"}}],
        }
        self.assertEqual(notifier.best_cvss(metrics), (9.3, "4.0", "v40"))
        self.assertIsNone(notifier.best_cvss({}))

    def test_watchlist_matches_whole_terms_and_cpe_spellings(self):
        matcher = notifier.TermMatcher(["sap", "node.js", "palo alto networks", "d-link"])
        self.assertEqual(matcher.find("SAP NetWeaver and Node.js"), ["sap", "node.js"])
        self.assertEqual(matcher.find("sapphire"), [])
        self.assertEqual(matcher.find("paloaltonetworks pan-os, dlink dir-600"), ["paloaltonetworks", "dlink"])

    def test_file_names_do_not_count_as_products(self):
        php = notifier.TermMatcher(["php"])
        self.assertEqual(php.find(notifier.scrub_paths("SQL injection in /admin/login.php and view.php")), [])
        self.assertEqual(php.find(notifier.scrub_paths("A flaw in PHP 8.3 via /index.php")), ["php"])

    def test_plurals_count_for_news_words_only_when_asked(self):
        words = ["backdoor", "breach", "zero-day"]
        text = "SSH backdoors, two breaches and zero-days"
        self.assertEqual(notifier.TermMatcher(words).find(text), [])
        self.assertEqual(notifier.TermMatcher(words, plurals=True).find(text), ["backdoor", "breach", "zero-day"])
        self.assertEqual(notifier.TermMatcher(["backdoor"], plurals=True).find("backdoorsx"), [])
        self.assertEqual(notifier.news_matcher(words, {}).find(text), ["backdoor", "breach", "zero-day"])
        self.assertEqual(notifier.news_matcher(words, {"match_plurals": False}).find(text), [])

    def test_kev_entry_with_high_epss_is_urgent(self):
        lists = notifier.build_watchlists(test_config(), {}, None)
        entry = kev_entry("CVE-2026-40002", "Widgetco", "Widget Server")
        high = notifier.kev_alert(entry, {"CVE-2026-40002": (0.49, 0.99)}, {}, lists, urgent_epss=0.50)
        urgent = notifier.kev_alert(entry, {"CVE-2026-40002": (0.50, 0.99)}, {}, lists, urgent_epss=0.50)
        self.assertEqual((high.priority, urgent.priority), ("high", "urgent"))
        self.assertIn("EPSS at or above 50%", urgent.body)
        off = notifier.kev_alert(entry, {"CVE-2026-40002": (1.0, 1.0)}, {}, lists, urgent_epss=1.01)
        self.assertEqual(off.priority, "high")

    def test_kev_urgent_epss_setting_is_used_by_collect(self):
        state = seeded_state()
        http = FakeHttp(kev=KEV_V2, epss=dict(EPSS_SCORES, **{"CVE-2026-40002": (0.60, 0.99)}))
        cfg = test_config()
        alerts, _, _ = run_once(state, http, cfg=cfg, now=NOW + timedelta(minutes=30))
        self.assertEqual({a.key: a.priority for a in alerts}["kev:CVE-2026-40002"], "urgent")
        cfg["kev"]["urgent_epss"] = 0.70
        state = seeded_state()
        alerts, _, _ = run_once(state, http, cfg=cfg, now=NOW + timedelta(minutes=30))
        self.assertEqual({a.key: a.priority for a in alerts}["kev:CVE-2026-40002"], "high")

    def test_critical_kev_entry_is_urgent_using_its_nvd_score(self):
        old_critical = nvd_cve("CVE-2026-40002", 9.8, vendor="widgetco", product="widget server", days_old=200)
        nvd = {"totalResults": len(NVD_ITEMS) + 1, "vulnerabilities": NVD_ITEMS + [old_critical]}
        for setting, expected in ((True, "urgent"), (False, "high")):
            cfg = test_config()
            cfg["kev"]["urgent_if_critical"] = setting
            state = seeded_state()
            http = FakeHttp(kev=KEV_V2, nvd=nvd)
            alerts, errors, _ = run_once(state, http, cfg=cfg, now=NOW + timedelta(minutes=30))
            alert = {a.key: a for a in alerts}["kev:CVE-2026-40002"]
            self.assertEqual(alert.priority, expected)
            self.assertEqual(errors, [])
            if setting:
                self.assertIn("CVSS 9.8", alert.body)
                self.assertIn("critical, exploitable over the network", alert.body)
        self.assertNotIn("cve:CVE-2026-40002", {a.key for a in alerts})  # too old for the CVE path

    def test_last_alexa_announcements_are_kept_for_vulnerabilities(self):
        def spoken(count, alerts):
            cfg, http, lines = test_config(), FakeHttp(), []
            cfg["alexa"].update(monthly_cap=150, reserve_for_vulnerabilities=30)
            state = {"alexa": {"month": "2026-11", "count": count}}
            notifier.announce_on_alexa(alerts, cfg, state, http, {"VOICEMONKEY_TOKEN": "v", "VOICEMONKEY_DEVICE": "e"},
                                       NOW, False, lines.append)
            return [p["speech"] for u, p in http.posts if u == notifier.VOICEMONKEY_URL], "\n".join(lines)

        news = notifier.Alert(key="news:abc", title="t", body="", url="", priority="urgent", speech="News story.")
        kev = notifier.Alert(key="kev:CVE-2026-1", title="t", body="", url="", priority="urgent", speech="KEV entry.")
        self.assertEqual(len(spoken(119, [news])[0]), 1)       # under the reserve: everything urgent
        said, log = spoken(120, [news])
        self.assertEqual(said, [])
        self.assertIn("keeping the last 30 of 150 this month for exploited vulnerabilities", log)
        said, _ = spoken(120, [news, kev])
        self.assertEqual(said, ["KEV entry."])
        self.assertEqual(spoken(150, [kev])[0], [])            # the cap itself still holds

    def test_shipped_config_ranks_the_october_stories(self):
        news = CONFIG["news"]
        lists = notifier.build_watchlists(CONFIG, {}, None)
        breach = notifier.news_matcher(news["vendor_breach_keywords"], news)
        rank = lambda title: notifier.vendor_breach_priority(title, lists, breach)  # noqa: E731
        self.assertEqual(rank("ConnectWise (SkyKick) Vendor Credentials Abused in M365 Attacks"), "urgent")
        self.assertEqual(rank("Anthropic hacked to deliver remote access trojan to Claude developer laptops"), "high")
        for term in ("anthropic", "claude code", "cursor ide"):
            self.assertEqual(lists.core.find(f"news about {term}"), [term])
        keywords = notifier.news_matcher(news["keywords"], news)
        self.assertTrue(keywords.find("Malicious Claude Code extension on Cursor planted SSH backdoors"))

    def test_unauthenticated_network_check(self):
        self.assertTrue(notifier.unauth_network(UNAUTH))
        self.assertFalse(notifier.unauth_network(AUTH_HIGH))
        self.assertIsNone(notifier.unauth_network(""))


if __name__ == "__main__":
    unittest.main()
