# Threat Notifier

**Threat Notifier is a free, self-hosted way to stay on top of what's happening in security: what's being exploited, which ransomware groups are active in your country, and what the people who track this are saying.** Every 30 minutes it checks the sources that matter: CISA's Known Exploited Vulnerabilities, new CVEs from NVD scored by EPSS, ransomware leak sites, security news, and posts from well-known researchers on Mastodon and Bluesky. When something is exploited, critical or about a vendor you depend on, it pushes an alert to your phone, and the urgent ones are read out by Alexa. It's a personal-awareness tool for security people, MSP engineers and anyone who looks after IT, not a service for monitoring specific companies. It runs entirely on GitHub Actions: no server to maintain, no AI, no paid APIs, and every threshold, list and schedule lives in one file, `config.yaml`.

**What you get**

- **A phone alert within about 30 minutes** of a new KEV entry, a CVE that's likely to be exploited, or a zero-day headline about a vendor you use.
- **A running picture of ransomware in your country.** Every leak-site listing there arrives with the group's name and the victim's sector, so you can see which groups are active in your market and who they're hitting.
- **Alexa announcements for the urgent ones**, with quiet hours so she never wakes you. Anything urgent overnight is held and read out in the morning.
- **One alert per story.** When five outlets cover the same zero-day, you get one alert that lists the other four.
- **Little noise.** A tiered vendor watchlist builds itself from CISA's history, EPSS filters out CVEs nobody is attacking, and keyword filters keep noisy feeds in check.
- **A monthly check of every feed**, telling you which have broken or gone quiet and how to fix them.
- **Privacy built in.** Secrets stay in GitHub, and ransomware victim names never appear in logs or on Alexa.

---

## Contents

1. [How it works](#how-it-works)
2. [What you need](#what-you-need)
3. [Quick start](#quick-start-about-20-minutes)
4. [Keys and tokens: where to get each one](#keys-and-tokens-where-to-get-each-one)
5. [How alerts are ranked](#how-alerts-are-ranked)
6. [Phone or Alexa: choosing where alerts go](#phone-or-alexa-choosing-where-alerts-go)
7. [Quiet hours](#quiet-hours)
8. [Ransomware in your country](#ransomware-in-your-country)
9. [Vendor watchlists](#vendor-watchlists)
10. [News feeds](#news-feeds)
11. [Recommended researchers (Mastodon and Bluesky)](#recommended-researchers-mastodon-and-bluesky)
12. [Monthly feed check](#monthly-feed-check)
13. [Every setting in config.yaml](#every-setting-in-configyaml)
14. [Testing: test runs, dry runs and drills](#testing-test-runs-dry-runs-and-drills)
15. [Costs and limits](#costs-and-limits)
16. [Privacy and security](#privacy-and-security)
17. [Troubleshooting](#troubleshooting)
18. [Data sources and credits](#data-sources-and-credits)
19. [License](#license)

---

## How it works

```
GitHub Actions, every 30 minutes
        │
        ├─ CISA KEV ──────────┐
        ├─ NVD + FIRST EPSS ──┤
        ├─ ransomware.live ───┼──▶  filter, rank, ──▶  phone (ntfy / Telegram / Pushover)
        ├─ news RSS feeds ────┤     group stories        └─▶ urgent only: Alexa (Voice Monkey)
        └─ Mastodon/Bluesky ──┘
```

Each run fetches the sources, compares them with what it has already seen, ranks anything new as **urgent**, **high** or **normal**, and sends it. What has been sent is remembered in the GitHub Actions cache, so nothing alerts twice. The very first run only takes a baseline and sends "Threat notifier is live"; real alerts start from the next run.

---

## What you need

Everything below has a free option.

| What | Needed? | Why |
| --- | --- | --- |
| A [GitHub](https://github.com) account | Yes | Runs the notifier on a schedule (GitHub Actions) |
| A phone with the [ntfy](https://ntfy.sh) app | Yes (or Telegram, or Pushover) | Receives the alerts |
| A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) | Recommended | Makes CVE lookups faster and more reliable |
| A free [ransomware.live API key](https://my.ransomware.live) | For ransomware alerts | Victims posted on ransomware leak sites (free for non-commercial use) |
| An Amazon Echo and a free [Voice Monkey](https://voicemonkey.io) account | Optional | Alexa reads out urgent alerts |

---

## Quick start (about 20 minutes)

### 1. Make your own copy

Click **Use this template** at the top of this page, then **Create a new repository**. Give it a name, choose **Private** (recommended: see [Costs and limits](#costs-and-limits)), and click **Create repository**. ([GitHub's guide](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-repository-from-a-template).)

Until you add a phone secret in step 3, scheduled runs stop straight away with the notice "Not set up yet", so nothing runs before you're ready.

### 2. Set up your phone

1. Install ntfy: [Android](https://play.google.com/store/apps/details?id=io.heckel.ntfy) or [iPhone](https://apps.apple.com/us/app/ntfy/id1625396347).
2. Make up a long random topic name. **Anyone who knows it can read your alerts, so treat it like a password.** To generate one:
   ```bash
   python3 -c "import secrets; print('ti-' + secrets.token_urlsafe(16))"
   ```
3. In the app, tap **+** and subscribe to that topic on the default server (`ntfy.sh`).

### 3. Add your secrets

In your new repository, go to **Settings > Secrets and variables > Actions > New repository secret**, and add `NTFY_TOPIC` with the topic name from step 2. Add any optional keys from [the next section](#keys-and-tokens-where-to-get-each-one) the same way.

Or, with the [GitHub CLI](https://cli.github.com) installed and signed in (`gh auth login`), run this and paste the value when asked:

```bash
gh secret set NTFY_TOPIC --repo YOUR-NAME/YOUR-REPO
```

### 4. Choose what to watch

Open `config.yaml` (click it on GitHub, then the pencil icon) and check these three things:

- **`timezone`**: your time zone, for example `Europe/London` or `America/New_York`. It controls quiet hours.
- **`ransomware_live.countries`**: the countries whose ransomware activity you want to follow. The default is `[GB]` (the UK); use `[US]`, `[IE, GB]`, or `[]` to turn this off. See [Ransomware](#ransomware-in-your-country).
- **`alexa.quiet_hours`**: when Alexa must stay quiet. See [Quiet hours](#quiet-hours).

Commit the change. Everything else can wait.

### 5. Send a test

Open the **Actions** tab. If GitHub asks, click **I understand my workflows, go ahead and enable them**. Pick **threat-notifier**, click **Run workflow**, choose **test** and run it. Your phone should buzz within a minute (and your Echo should speak, if you set up Alexa).

### 6. Go live

Run **threat-notifier** once more with **run**, or just wait for the schedule. The first run takes a baseline and sends "Threat notifier is live". From then on, new things alert.

### 7. Check after a day

Open any run under **Actions** and scroll to its summary. It shows what was reviewed, what was sent and any **source errors** (a feed that has moved, for example). A source that fails 12 runs in a row also sends you one warning.

---

## Keys and tokens: where to get each one

Every key goes in as a **GitHub Actions secret** (see [Quick start, step 3](#3-add-your-secrets)), never in `config.yaml`. GitHub keeps secrets encrypted and hides them in logs ([how secrets work](https://docs.github.com/en/actions/security-for-github-actions/security-guides/using-secrets-in-github-actions)).

| Secret | Needed? | What it unlocks |
| --- | --- | --- |
| `NTFY_TOPIC` | **Yes** (or Telegram, or Pushover) | Phone alerts through ntfy |
| `NVD_API_KEY` | Recommended | Faster, more reliable CVE lookups |
| `RANSOMWARE_LIVE_API_KEY` | For ransomware alerts | Ransomware leak-site victims |
| `VOICEMONKEY_TOKEN` | For Alexa | Lets the notifier make Alexa speak |
| `VOICEMONKEY_DEVICE` | For Alexa | Which Echo speaks |
| `WATCH_ORGS` | Optional | Specific organisations to watch on leak sites ([personal use only](#watching-specific-organisations-optional)) |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Optional | Also (or instead) send to Telegram |
| `PUSHOVER_APP_TOKEN`, `PUSHOVER_USER_KEY` | Optional | Also (or instead) send to Pushover |
| `NTFY_TOKEN` | Optional | Only for an access-protected ntfy topic |

### ntfy (phone): `NTFY_TOPIC`

Free, with no account needed. Follow [Quick start, step 2](#2-set-up-your-phone). For more privacy, you can [protect a topic](https://docs.ntfy.sh/config/#access-control) or run your own server: set `delivery.ntfy_server` to its address and put an access token in `NTFY_TOKEN`. ntfy's own guide: [docs.ntfy.sh](https://docs.ntfy.sh/subscribe/phone/).

### NVD (new CVEs): `NVD_API_KEY`

Free. Without a key NVD allows 5 requests per 30 seconds; with one, 50.

1. Open [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).
2. Enter your organisation name, email address and organisation type, accept the terms, and submit.
3. Open the link in the email NVD sends you. The page shows your key once; copy it into the `NVD_API_KEY` secret.

### ransomware.live (leak sites): `RANSOMWARE_LIVE_API_KEY`

Free for non-commercial use, which is how the notifier is meant to be used: as a personal-awareness tool that keeps you up to date on ransomware activity in your country.

1. Sign up at [my.ransomware.live](https://my.ransomware.live).
2. Copy your API key from the dashboard into the `RANSOMWARE_LIVE_API_KEY` secret.
3. Read their [Terms & Conditions](https://www.ransomware.live/t&c). The source must be credited; every alert ends with "Source: Ransomware.live".

**Anyone using it as part of a paid service needs ransomware.live's written approval first.** That includes an MSSP or MSP watching its clients, feeding the alerts into a service you sell, or running the notifier for a customer. Ask them at api@ransomware.live before you start.

No key? Set `ransomware_live.countries: []` in `config.yaml`. Otherwise every run summary shows a reminder to add one.

### Alexa via Voice Monkey: `VOICEMONKEY_TOKEN` and `VOICEMONKEY_DEVICE`

Voice Monkey lets a script make an Echo speak. The free plan allows 200 requests a month; the notifier caps itself at 150 and merges several urgent alerts into one announcement.

1. Sign up at [voicemonkey.io](https://voicemonkey.io) and enable the Voice Monkey skill in your Alexa app, following [their getting-started guide](https://voicemonkey.io/docs).
2. In the console, add a **Speaker** for the Echo that should talk ([app.voicemonkey.io/speakers](https://app.voicemonkey.io/speakers); see [Devices](https://voicemonkey.io/docs/devices)). Its **device ID** is shown next to it, something like `living-room-echo-3f7k2`. Put it in `VOICEMONKEY_DEVICE`.
3. In the console, open **API Tokens**, create a token named, for example, "threat-notifier", and copy it into `VOICEMONKEY_TOKEN` ([Authentication](https://voicemonkey.io/docs/api/authentication)).

### Telegram (optional): `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`

1. In Telegram, message [@BotFather](https://t.me/BotFather), send `/newbot` and follow the prompts. It gives you a token: that's `TELEGRAM_BOT_TOKEN`.
2. Send any message to your new bot.
3. Open `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` in a browser, find `"chat":{"id":…}` and copy the number into `TELEGRAM_CHAT_ID`. ([Telegram's bot tutorial](https://core.telegram.org/bots/tutorial).)

### Pushover (optional): `PUSHOVER_APP_TOKEN` and `PUSHOVER_USER_KEY`

Pushover is a paid app (a one-off licence after a 30-day trial) with strong urgent-alert features.

1. Sign up at [pushover.net](https://pushover.net). Your **user key** is on the dashboard: put it in `PUSHOVER_USER_KEY`.
2. [Create an application](https://pushover.net/apps/build) named "Threat Notifier" and copy its API token into `PUSHOVER_APP_TOKEN`.

### Watched organisations (optional): `WATCH_ORGS`

A comma-separated list of organisation names or domains, for example `Acme Holdings, acme.com, Globex`. Most people leave it empty. See [Watching specific organisations](#watching-specific-organisations-optional).

### Sources that need no key

| Source | What it gives you |
| --- | --- |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Vulnerabilities confirmed as exploited in the wild |
| [FIRST EPSS](https://www.first.org/epss/) | The chance a CVE is exploited in the next 30 days |
| News RSS feeds | NCSC, BleepingComputer, The Hacker News and more ([list](#news-feeds)) |
| Mastodon and Bluesky | Public RSS feeds of researchers' posts ([list](#recommended-researchers-mastodon-and-bluesky)) |

---

## How alerts are ranked

| Priority | What triggers it | Where it goes |
| --- | --- | --- |
| **Urgent** | A new KEV entry with known ransomware use or on a core-watchlist vendor · a core-vendor critical CVE with EPSS 10%+ · any critical with EPSS 50%+ · a zero-day or actively-exploited headline naming a core vendor · a breach headline naming an MSP-critical vendor · a watched organisation on a leak site · a leak-site victim in your countries, if you set `country_priority: urgent` | Phone at maximum priority **plus Alexa** (one announcement per run; held during quiet hours) |
| **High** | Any other new KEV entry · a CVE at CVSS 7+ with EPSS 10%+ · a core-vendor critical · zero-day or actively-exploited headlines · a breach headline naming a core vendor · a researcher's post with a zero-day word and a core vendor · leak-site victims in your countries (`country_priority: high`, the default) | Phone, with sound |
| **Normal** | A critical CVE on an extended-watchlist vendor · news and posts that match your keywords | Phone, with sound (or silent, with `normal_silent: true`) |

"Critical" means CVSS 9.0 or higher, exploitable over the network with no login. All of these thresholds are in `config.yaml`.

---

## Phone or Alexa: choosing where alerts go

By default only **urgent** alerts reach Alexa; high and normal alerts go to your phone only. To keep more things phone-only:

| You want | Set this in `config.yaml` |
| --- | --- |
| No Alexa at all | `alexa.enabled: false` (or don't add the Voice Monkey secrets) |
| Ransomware victims in your countries on the phone only | `ransomware_live.country_priority: high` (the default) |
| Alexa announces every ransomware victim in your countries | `ransomware_live.country_priority: urgent` (about 40 announcements a month for the UK) |
| Watched organisations on leak sites on the phone only | `ransomware_live.priority: high` |
| Researchers' posts never on Alexa | `social.hot_vendor_priority: high` (the default; `urgent` makes Alexa read them) |
| Alexa speaks high alerts too | `alexa.min_priority: high` (uses the monthly allowance much faster) |
| Normal alerts arrive without sound | `delivery.normal_silent: true` |
| Fewer Alexa announcements a month | Lower `alexa.monthly_cap` (default 150, the free Voice Monkey plan allows 200 requests) |

---

## Quiet hours

Alexa never speaks during quiet hours. Urgent announcements that arrive then are **held and read out when quiet hours end**, starting "Catching up after quiet hours". Your phone still gets every alert straight away, just **without sound**.

**Why it works this way:** urgent alerts overnight stay silent on the phone and are read out by Alexa when quiet hours end, so you start the day with a briefing instead of being woken by news.

```yaml
timezone: Europe/London

alexa:
  quiet_hours:
    weekdays: "23:00-08:00"   # Monday to Friday mornings
    weekends: "01:00-11:00"   # Saturday and Sunday mornings
  queue_during_quiet_hours: true   # false: skip held announcements instead
  queue_max_age_hours: 24          # drop held announcements older than this

delivery:
  phone_quiet_hours: alexa         # use Alexa's schedule for the phone too
  phone_quiet_ring_urgent: false   # true: urgent alerts still ring at night
```

- **Each range belongs to the morning it ends on.** `weekdays: "23:00-08:00"` covers Sunday night to Monday morning through Thursday night to Friday morning. Friday night falls under `weekends`, so it's free until 01:00.
- **Other forms:** one range for every day, `quiet_hours: "22:00-07:30"`; a single day overriding the rest, for example `friday: "00:00-09:00"`; or `quiet_hours: ""` for none.
- **Phone schedule:** `phone_quiet_hours` can be `alexa` (same schedule), its own schedule in the same format (for example `"00:00-07:00"`), or `""` to always ring.

---

## Ransomware in your country

Data comes from [ransomware.live](https://www.ransomware.live), which tracks the leak sites where ransomware groups post their victims. You need the free [API key](#ransomwarelive-leak-sites-ransomware_live_api_key).

**The main use is following the ransomware landscape in your market.** Every time a group lists a victim in one of your countries, you get an alert naming the group and the victim's sector. Over a few weeks that shows you which groups are active where you work, which sectors they're going after, and when things are getting busier, without having to check a leak-site tracker yourself.

```yaml
ransomware_live:
  countries: [GB]            # ISO country codes; UK is accepted for GB. [] turns this off
  country_priority: high     # high: phone with sound · urgent: Alexa announces every listing too
  max_age_days: 7            # ignore listings discovered longer ago than this
```

- **What arrives:** the phone alert has the victim, the group, the discovery and attack dates, the website and the sector, with a link to the listing. By default it's **high** priority, so your phone rings and Alexa stays quiet.
- **Hearing them on Alexa:** set `country_priority: urgent` and Alexa says, for example, "An organisation in the UK has been listed on a ransomware leak site. Check your phone." She never says the name. At about 9 UK listings a week, this would use roughly 40 of Alexa's 150 monthly announcements.
- **Nothing is missed:** each run looks up this month's listings for your countries (and last month's near the start of a month), so a skipped GitHub run doesn't lose any. Each listing alerts once.
- **Names stay on your phone.** Run summaries and dry runs show only "an organisation in GB was listed", the saved state keeps a hash, and Alexa never says a name. This also keeps ransomware.live's data off public run pages.
- **It's for your own awareness**, within ransomware.live's free non-commercial terms. Using it as part of a paid service needs their written approval (see [Keys and tokens](#ransomwarelive-leak-sites-ransomware_live_api_key)).

To turn ransomware alerts off completely, set `countries: []` and leave `WATCH_ORGS` empty (or set `enabled: false`).

### Watching specific organisations (optional)

You can also name organisations, and a listing that matches one alerts at `ransomware_live.priority` (default `urgent`), wherever the victim is. Put them in the `WATCH_ORGS` secret, comma separated, for example `Acme Holdings, acme.com`. (`watch_orgs:` in `config.yaml` works too, but anyone who can see the repository can read it.)

This isn't a client-monitoring feature. An MSSP or MSP will normally hear about a client incident from the client, or from its own tools, well before a leak site posts it, and watching clients as part of a paid service needs ransomware.live's written approval. Matching is on whole words in the victim's name or website, the list never leaves GitHub, and matched names are masked in logs.

---

## Vendor watchlists

The watchlist decides when a CVE or headline is loud. It has layers, so you don't have to maintain it from scratch:

| Layer | What it is | Effect |
| --- | --- | --- |
| **From KEV history** (automatic) | Every vendor CISA has listed at least `auto_min_kev_entries` (5) times, refreshed each run | Criticals arrive at normal priority |
| **`core`** | Edge devices, VPNs, identity, remote access and RMM, hypervisors, backup, file transfer, the biggest targets | KEV entries are urgent; criticals are high, or urgent with high EPSS; zero-day headlines are urgent |
| **`msp_critical`** (part of core) | RMM, PSA, remote access and identity providers whose breach reaches every client at once (ConnectWise, Kaseya, NinjaOne, TeamViewer, Okta…) | A breach headline naming one is urgent |
| **`extended`** | Everything else worth knowing about: productivity, dev and AI tools, web stack, SaaS, security vendors | Criticals arrive at normal priority |
| **`ignore`** | Sources that flood NVD with criticals nobody runs (student PHP projects, consumer routers) | Dropped (never blocks KEV alerts) |

Names match as whole words, case doesn't matter. Edit the lists in `config.yaml` to match what you and your clients actually run.

---

## News feeds

Default feeds: NCSC, BleepingComputer, The Hacker News, The Record, SANS ISC, Huntress, DoublePulsar, watchTowr Labs, Krebs on Security, r/sysadmin, Have I Been Pwned (latest breaches), DataBreaches.net and Securelist (Kaspersky's research team).

```yaml
news:
  feeds:
    - name: BleepingComputer
      url: https://www.bleepingcomputer.com/feed/
      filter: keywords        # only items matching news.keywords
    - name: Huntress
      url: https://www.huntress.com/blog/rss.xml
      filter: all             # every new post
    - name: r/sysadmin
      url: https://www.reddit.com/r/sysadmin/new/.rss
      filter: keywords
      keywords: [breach, zero-day, outage]   # this feed's own filter words
    - name: Some feed
      url: https://example.com/feed
      enabled: false          # muted, but kept
```

- **Adding a feed:** add a `name` and `url` (RSS or Atom). A new feed starts silently: its first run only notes what's already there.
- **Priority:** a headline with a `hot_keywords` word (zero-day, actively exploited, emergency patch…) is high, or urgent when it names a core vendor. A headline naming a core vendor plus a `vendor_breach_keywords` word (breached, hacked, backdoored…) is high, or urgent for MSP-critical vendors, and always gets through the keyword filter.
- **One alert per story:** headlines that share a CVE ID, or the same vendor plus at least 3 significant words, are grouped into one alert that ends "Also covered by: …". Stories are remembered for 24 hours so a late outlet doesn't alert again.
- **Reddit** sometimes blocks GitHub's servers. If r/sysadmin keeps failing, remove it.

---

## Recommended researchers (Mastodon and Bluesky)

Researchers often post about mass exploitation hours before the news sites catch up. The notifier reads their **public RSS feeds**, so you need no account, login or API key. Each account below was checked to exist and have a working feed (November 2026).

| Researcher or account | Platform | Known for |
| --- | --- | --- |
| [Kevin Beaumont](https://cyberplace.social/@GossiTheDog) | Mastodon | DoublePulsar; usually first on mass exploitation (UK) |
| [Will Dormann](https://infosec.exchange/@wdormann) | Mastodon | Vulnerability analysis, ex-CERT/CC |
| [Shadowserver](https://infosec.exchange/@shadowserver) | Mastodon | Internet-wide scans of exposed and exploited devices |
| [Brian Krebs](https://infosec.exchange/@briankrebs) | Mastodon | Investigative cybercrime reporting |
| [Florian Roth](https://infosec.exchange/@cyb3rops) | Mastodon | Nextron Systems, Sigma and THOR (rarely posts here now) |
| [Marcus Hutchins](https://infosec.exchange/@malwaretech) | Mastodon | MalwareTech (UK) |
| [Boris Larin](https://mastodon.social/@oct0xor) | Mastodon | Kaspersky GReAT zero-day hunter |
| [Troy Hunt](https://bsky.app/profile/troyhunt.com) | Bluesky | Have I Been Pwned |
| [Catalin Cimpanu](https://bsky.app/profile/campuscodi.risky.biz) | Bluesky | Risky Business News |
| [Kim Zetter](https://bsky.app/profile/kimzetter.bsky.social) | Bluesky | Investigative security journalism |
| [Scott Helme](https://bsky.app/profile/scotthelme.bsky.social) | Bluesky | Web security, Report URI (UK) |
| [Graham Cluley](https://bsky.app/profile/grahamcluley.com) | Bluesky | Smashing Security podcast (UK) |
| [Joe Tidy](https://bsky.app/profile/joetidy.bsky.social) | Bluesky | BBC cyber correspondent (UK) |
| [NCSC](https://bsky.app/profile/ncsc.gov.uk) | Bluesky | UK National Cyber Security Centre |
| [Costin Raiu](https://bsky.app/profile/craiu.bsky.social) | Bluesky | Led Kaspersky GReAT, now TLPBLACK |
| [Kurt Baumgartner](https://bsky.app/profile/kurtisj.bsky.social) | Bluesky | Ex-Kaspersky GReAT, co-founder of TLPBLACK |

**Adding your own:**

```yaml
social:
  enabled: true                 # false turns every account off
  hot_vendor_priority: high     # posts with a zero-day word AND a core vendor; urgent = Alexa reads them
  accounts:
    - name: Someone
      mastodon: https://infosec.exchange/@someone   # or @someone@infosec.exchange
    - name: Someone else
      bluesky: someone.bsky.social                  # the handle, or a domain like troyhunt.com
      keywords: [ransomware, zero-day]              # optional: this account's own filter words
      enabled: false                                # optional: mute without deleting
```

- **Check an account first** by opening its feed in a browser: a Mastodon profile's feed is its URL plus `.rss`; a Bluesky profile's is `https://bsky.app/profile/HANDLE/rss`.
- **Every post must match your keywords**, so posts about lunch don't get through. They stay normal priority unless they contain a hot keyword *and* a core vendor.
- **Posts have no headline**, so the alert title is the first 140 characters and the body is the post, with a link to it.
- **X (Twitter) and LinkedIn** have no free feeds, so people who only post there can't be followed.

---

## Monthly feed check

Feeds move and people stop posting. Early each month the **feed-check** workflow tests every feed and account and sends **one message without sound** listing the ones that need attention, with a suggested fix where it can find one. It never edits `config.yaml`; you decide what to change.

```yaml
feed_check:
  enabled: true
  silent_days: 14               # no new post in this long counts as gone silent
  quiet_ok: [Florian Roth, Costin Raiu, Boris Larin, Marcus Hutchins, Kim Zetter]  # allowed to be quiet
  notify_when_all_ok: false     # true also sends "all feeds are fine"
```

- **Suggested fixes:** a new feed address advertised on the site or found at a common path (only suggested after it has been fetched and found to have recent posts), a Mastodon account that moved, a Bluesky handle that no longer exists, Reddit blocking, or "add `enabled: false`" for a quiet account. A feed that times out twice is called temporary rather than moved.
- **When:** 09:23 UTC on the first day of the month, with retries on days 2 to 7 in case GitHub skips a run. It reports once a month.
- **Run it now:** **Actions > feed-check > Run workflow** (untick "send" for a dry run). The run summary has a table of every feed.

---

## Every setting in config.yaml

Edit `config.yaml`, commit, and the next run uses it. Defaults are what ships in this repository.

### General

| Setting | Default | What it does |
| --- | --- | --- |
| `timezone` | `Europe/London` | Time zone for quiet hours ([list of names](https://en.wikipedia.org/wiki/List_of_tz_database_time_zones)) |
| `kev.enabled` | `true` | Alert on new CISA KEV entries |

### New CVEs (`cve`)

| Setting | Default | What it does |
| --- | --- | --- |
| `min_cvss` | `7.0` | Ignore CVEs scored below this |
| `epss_threshold` | `0.10` | EPSS (chance of exploitation in 30 days) that makes a CVE alert |
| `urgent_epss` | `0.50` | EPSS that makes any critical urgent |
| `watchlist_min_cvss` | `9.0` | What counts as "critical" for watchlist vendors |
| `watchlist_requires_unauthenticated` | `true` | Criticals must be exploitable over the network with no login |
| `watch_days` | `14` | Keep re-checking EPSS this long, so a later jump still alerts |
| `max_published_age_days` | `30` | Older CVEs only alert through KEV |
| `max_window_hours` | `168` | How far back to look after downtime |

### Watchlists (`watchlist`)

| Setting | Default | What it does |
| --- | --- | --- |
| `auto_from_kev` | `true` | Add vendors from CISA's KEV history automatically |
| `auto_min_kev_entries` | `5` | KEV entries a vendor needs to be added |
| `core` | 88 vendors and products | Loud tier ([see above](#vendor-watchlists)) |
| `msp_critical` | 24 RMM, PSA, remote access and identity vendors | Breach headlines are urgent; also counts as core |
| `extended` | 135 vendors and products | Quieter tier |
| `ignore` | student-project and consumer-router sources | Dropped from CVE alerts (never from KEV) |

### News (`news`)

| Setting | Default | What it does |
| --- | --- | --- |
| `max_age_days` | `3` | Ignore items older than this |
| `group_stories` | `true` | One alert per story across outlets |
| `story_window_hours` | `24` | How long a story is remembered |
| `story_min_shared_words` | `3` | Significant words two headlines must share (besides the vendor) to count as one story |
| `hot_keywords` | zero-day, actively exploited, emergency patch… | Make a headline high, or urgent with a core vendor |
| `vendor_breach_keywords` | breach, hacked, stolen, backdoored… | With a core vendor in the headline: high (urgent for MSP-critical) |
| `keywords` | 30 security words | The filter for feeds set to `filter: keywords` |
| `feeds[]` | 13 feeds | Each has `name`, `url`, `filter` (`all` or `keywords`), optional `keywords` and `enabled` |

### Mastodon and Bluesky (`social`)

| Setting | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Read the accounts below |
| `hot_vendor_priority` | `high` | Priority of a post with a hot keyword and a core vendor (`urgent` = Alexa too) |
| `keywords` | uses `news.keywords` | Filter words for every account |
| `accounts[]` | 16 accounts | Each has `name`, `mastodon` or `bluesky`, optional `keywords` and `enabled` |

### Ransomware (`watch_orgs`, `ransomware_live`)

| Setting | Default | What it does |
| --- | --- | --- |
| `watch_orgs` | `[]` | Organisations to watch; combined with the `WATCH_ORGS` secret (prefer the secret) |
| `ransomware_live.enabled` | `true` | Use ransomware.live |
| `ransomware_live.countries` | `[GB]` | Every victim in these countries alerts; `[]` turns it off |
| `ransomware_live.country_priority` | `high` | `high` = phone only, `urgent` = phone + Alexa for every listing |
| `ransomware_live.priority` | `urgent` | Priority for a watched organisation |
| `ransomware_live.max_age_days` | `7` | Ignore listings discovered longer ago |
| `ransomware_live.url`, `country_url` | ransomware.live API addresses | Only change if their API moves |

### Feed check (`feed_check`)

| Setting | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Run the monthly check |
| `silent_days` | `14` | Days without a post that count as silent |
| `quiet_ok` | five rarely-posting researchers | Names allowed to be quiet (failures are still reported) |
| `notify_when_all_ok` | `false` | Also send a message when every feed is fine |

### Delivery (`delivery`)

| Setting | Default | What it does |
| --- | --- | --- |
| `max_alerts_per_run` | `12` | Anything over this arrives as one digest message |
| `normal_silent` | `false` | `true` lands normal alerts without sound |
| `ntfy_server` | `https://ntfy.sh` | Your own ntfy server, if you run one |
| `pushover_urgent_priority` | `1` | Pushover: `1` skips your quiet hours, `2` repeats until acknowledged |
| `phone_quiet_hours` | `alexa` | Phone quiet schedule: `alexa`, your own schedule, or `""` |
| `phone_quiet_ring_urgent` | `false` | `true` lets urgent alerts ring during quiet hours |

### Alexa (`alexa`)

| Setting | Default | What it does |
| --- | --- | --- |
| `enabled` | `true` | Use Alexa (needs the Voice Monkey secrets) |
| `min_priority` | `urgent` | Lowest priority Alexa speaks |
| `quiet_hours` | weekdays `23:00-08:00`, weekends `01:00-11:00` | When Alexa stays quiet ([format](#quiet-hours)) |
| `queue_during_quiet_hours` | `true` | Hold announcements and speak them afterwards |
| `queue_max_age_hours` | `24` | Drop held announcements older than this |
| `monthly_cap` | `150` | Maximum announcements a month |
| `voice` | `""` | Optional Alexa voice, for example `Brian` or `Amy` |
| `chime` | `""` | Optional sound before speaking, from Voice Monkey's sound library |

---

## Testing: test runs, dry runs and drills

All of these are under the **Actions** tab, **Run workflow**.

| Workflow | Option | What it does |
| --- | --- | --- |
| threat-notifier | `test` | Sends one test alert to your phone and Alexa |
| threat-notifier | `dry-run` | Shows in the run log what would be sent, sends nothing, saves nothing |
| threat-notifier | `run` | A normal run, the same as the schedule |
| drill | `cve` + a CVE ID | Sends one real CVE as if NVD had just published it, labelled DRILL |
| drill | `ransomware` | Sends one real recent listing from your countries, labelled DRILL (Alexa reads it only with `country_priority: urgent`) |
| feed-check | send on/off | Tests every feed now |

Drills never touch the saved state. Tick **ignore quiet hours** to hear Alexa at night.

**Running it on your own computer** (Python 3.10 or newer):

```bash
git clone https://github.com/YOUR-NAME/YOUR-REPO.git && cd YOUR-REPO
python3 -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m unittest discover -s tests                 # offline tests
NTFY_TOPIC=your-topic python notifier.py --mode dry-run
python tools/drill.py CVE-2026-111497                # how a CVE would be rated (dry run)
python tools/feed_check.py                           # test every feed (add --send to message your phone)
```

---

## Costs and limits

- **GitHub Actions:** a private repository gets 2,000 free minutes a month, and a run every 30 minutes uses about 1,440, so don't schedule it more often. Public repositories have unlimited minutes, but GitHub pauses their schedules after 60 days without a commit, and your `config.yaml` is visible to everyone.
- **Timing:** GitHub can delay or occasionally skip scheduled runs when it's busy, so alerts arrive within about 30 minutes, sometimes later.
- **Voice Monkey:** the free plan allows 200 requests a month; the notifier stops at `monthly_cap` (150).
- **NVD:** 5 requests per 30 seconds without a key, 50 with one.
- **ransomware.live:** free for non-commercial use with credit, which covers the notifier as a personal-awareness tool; its data refreshes every 30 minutes. Anyone using it as part of a paid service, including watching clients for an MSSP, needs ransomware.live's written approval first.
- **Pushover:** a one-off licence after the trial. ntfy and Telegram are free.

---

## Privacy and security

- **Keys and tokens live only in GitHub Actions secrets**, never in the repository. Don't paste them into `config.yaml`, issues or chats.
- **Your ntfy topic name is effectively a password.** Make it long and random, or [protect it](https://docs.ntfy.sh/config/#access-control).
- **Watched organisation names belong in the `WATCH_ORGS` secret**, especially if your repository is public.
- **Ransomware victim names go to your phone only.** They're kept out of logs, run summaries and the saved state, and Alexa never says them.

---

## Troubleshooting

**The run says "Not set up yet".** Add the `NTFY_TOPIC` secret (or the Telegram or Pushover pair). Secret names must match exactly.

**The test run worked but my phone got nothing.** Check that the topic in the app is exactly the same as the secret, on the server `ntfy.sh`.

**Alexa didn't speak.** Only urgent alerts are spoken. Check the run log for "Alexa": it says whether the announcement was sent, held for quiet hours, or skipped (monthly cap reached, or no Voice Monkey secrets). Check `VOICEMONKEY_DEVICE` is the Speaker's device ID from the Voice Monkey console.

**The run summary lists a source error.** One error now and then is normal. A feed that keeps failing has probably moved: the monthly feed check suggests a fix. Reddit sometimes blocks GitHub; remove that feed if it keeps failing.

**"ransomware.live: add the free RANSOMWARE_LIVE_API_KEY secret".** Add the key, or set `ransomware_live.countries: []`.

**Runs aren't exactly every 30 minutes.** GitHub delays scheduled runs when it's busy. Nothing is lost: each run catches up on what it missed.

**I changed the schedule but it didn't take effect.** The schedule is in `.github/workflows/notifier.yml` (`cron`, in UTC). It's read from the default branch.

---

## Data sources and credits

- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (US Cybersecurity and Infrastructure Security Agency)
- [NVD](https://nvd.nist.gov) (US National Institute of Standards and Technology). This product uses the NVD API but is not endorsed or certified by the NVD.
- [EPSS](https://www.first.org/epss/) by FIRST
- [ransomware.live](https://www.ransomware.live), used under its [terms](https://www.ransomware.live/t&c)
- News feeds and social posts belong to their publishers and authors; alerts link back to the original.
- Delivery through [ntfy](https://ntfy.sh), [Telegram](https://telegram.org), [Pushover](https://pushover.net) and [Voice Monkey](https://voicemonkey.io).

---

## License

[MIT](LICENSE): use it, change it and share it, including commercially, as long as you keep the copyright notice. The data sources keep their own terms (see above): in particular, ransomware.live needs written approval for commercial use.
