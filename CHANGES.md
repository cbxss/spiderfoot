# Changelog

## v4.1.0 — Revival (2026-02-06)

Modernization release forked from [smicallef/spiderfoot](https://github.com/smicallef/spiderfoot). Brings SpiderFoot up to date with Python 3.12+, removes 26 dead modules, fixes bugs, and addresses security issues.

### Removed Modules (26)

The following modules have been removed because their backing services are offline, defunct, or have sunset their APIs:

| Module | Reason |
|--------|--------|
| sfp_bgpview | API shut down Nov 2025; replaced by new sfp_bgptools module |
| sfp_bitcoinabuse | Merged into Chainabuse (TRM Labs); free tier too limited (10 calls/month) |
| sfp_bitcoinwhoswho | Free API limited to 1 call/day; requires corporate email |
| sfp_callername | No documented free API for automation |
| sfp_clearbit | Acquired by HubSpot; API sunset Apr 2025 |
| sfp_crobat_api | sonar.omnisint.io taken offline; Rapid7 revoked public access |
| sfp_crxcavator | CRXcavator project defunct (Duo Labs) |
| sfp_emailcrawlr | Service unreliable/abandoned (SSL cert expired 2023) |
| sfp_fsecure_riddler | EOL since 2020 |
| sfp_multiproxy | Proxy list no longer maintained |
| sfp_myspace | Platform effectively dead |
| sfp_onioncity | Tor2web gateway discontinued |
| sfp_onionsearchengine | Service discontinued |
| sfp_psbdmp | Service permanently shut down |
| sfp_riskiq | Acquired by Microsoft; community edition EOL Jan 2025 |
| sfp_searchcode | Ceased operations Aug 2025 |
| sfp_slideshare | HTML scraping broken by redesign |
| sfp_sorbs | DNSBL decommissioned by Proofpoint Jun 2024 |
| sfp_sublist3r | API defunct; already covered by sfp_securitytrails and sfp_crt |
| sfp_threatcrowd | Service defunct; already covered by sfp_alienvault |
| sfp_threatjammer | Service dormant; domain potentially compromised |
| sfp_trashpanda | Private API; creator won't publish |
| sfp_trumail | Absorbed by Emailable; different API |
| sfp_twitter | X API free tier removed; paid starts at $100/month |
| sfp_venmo | API retired by PayPal |
| sfp_zonefiles | Paid-only API; low OSINT value |

**Retained after review:** sfp_mnemonic (PassiveDNS API still operational, free tier: 10 req/min) and sfp_abusix (DNS-based abuse contact lookup still operational and free) were initially flagged but verified as still working.

All associated unit and integration tests for removed modules were also removed. Dead module references in `sfp_names.py` (sfp_clearbit, sfp_twitter) were cleaned up.

### Bug Fixes

- **db.py: REGEXP function not registered on fresh databases** -- `create_function("REGEXP")` was inside the branch that only ran when the database already existed. Moved it to run unconditionally so that REGEXP queries work on first launch.
- **sfp_phishstats.py: Wrong API port** -- API URL used port `:2096` which no longer works. Removed the port to use the default HTTPS port.
- **sfcli.py: `-e` argument crash** -- The `-e` flag read a file into a string but the downstream code expected a file-like object. Wrapped the string in `io.StringIO()`.
- **sflib.py: `ssl.wrap_socket()` deprecated** -- Replaced with `ssl.SSLContext` + `ctx.wrap_socket()` to fix deprecation warnings and prepare for Python 3.14+ where the old API is removed.
- **sf.py: `-u` flag case sensitivity** -- The `-u` (use case) argument rejected capitalized values like "Passive". Added `type=str.lower` so any case is accepted.

### Security Fixes

- **HTTP to HTTPS for API calls** -- Three modules were sending API keys over plaintext HTTP:
  - `sfp_nameapi` -- `http://api.nameapi.org` changed to `https://`
  - `sfp_numverify` -- `http://apilayer.net` changed to `https://` (free tier now supports HTTPS)
  - `sfp_vxvault` -- `http://vxvault.net` changed to `https://`
- **PyPDF2 replaced with pypdf** -- PyPDF2 is archived and no longer maintained. Dependency changed to `pypdf>=3.0.0,<5` (code was already updated in the revival commit).
- **Removed `ipaddr` dependency** -- The `ipaddr` package is unnecessary since Python 3.3+ includes `ipaddress` in the standard library.

### New Modules

- **sfp_bgptools** -- BGP.tools whois service for BGP routing data (replaces sfp_bgpview; free, no API key)
- **sfp_internetdb** -- Shodan InternetDB (free, no API key required)
- **sfp_leakcheck** -- LeakCheck.io paid API
- **sfp_leakcheck_public** -- LeakCheck.io free/public API
- **sfp_whoisfreaks** -- WhoisFreaks WHOIS/DNS lookup API
- **sfp_ip2locationio** -- ip2location.io geolocation API

### New Modules (wave 2)

- **sfp_epss** -- FIRST.org Exploit Prediction Scoring System. Enriches every discovered CVE with its probability of being exploited in the next 30 days and its percentile rank. (free, no API key)
- **sfp_cvedb** -- Shodan CVEDB vulnerability lookup. Adds CVSS scores, CISA KEV (Known Exploited Vulnerability) status, ransomware campaign data, affected CPEs, and references for discovered CVEs. (free, no API key)
- **sfp_bluesky** -- Bluesky (AT Protocol) social media module. Searches posts mentioning target domains and looks up user profiles by username. (free, no API key)
- **sfp_mastodon** -- Mastodon/Fediverse social media module. Searches posts and looks up user profiles on configurable Mastodon instances (default: mastodon.social). (free, no API key)
- **sfp_reddit** -- Reddit social media module. Searches posts mentioning target domains and retrieves user profiles via the Reddit OAuth API. (free API key required -- create at reddit.com/prefs/apps)

### Social Network Identifier Modernization

The `sfp_social` module's URL regex list has been overhauled:
- **Added:** TikTok, Bluesky, Mastodon, Threads, Reddit, Pinterest, Medium
- **Updated:** YouTube (added @handle and /c/ patterns), Twitter (added x.com domain)
- **Removed:** Google+ (shut down 2019), MySpace (dead), SlideShare (dead)

### Infrastructure

- Migrated from `requirements.txt` to `pyproject.toml` (PEP 621)
- Switched to `uv` for package management
- Updated Docker images: Alpine 3.20, Python 3.12-bookworm, uv-based installs
- Updated CI: Python 3.10--3.13 matrix, GitHub Actions v4/v5, uv
- Fixed test infrastructure: per-worker DB paths for pytest-xdist parallel safety

### Cherry-picked Upstream Fixes

The following fixes were cherry-picked from upstream PRs:

- WhatsMyName field updates (#1894)
- Nmap XML parsing fix (#1879)
- DNS for Family IP resolution (#1872)
- Nuclei/wafw00f/whatweb JSON output parsing (#1952)
- db.py UnboundLocalError on query failure (#1787)
- Dev port correlation rule (#1827)
- Accounts module `strip_bad_char` support (#1828)

### Other Fixes (from revival commit)

- Fixed `secure` library API for 1.x compatibility (was pinned to 0.3.x)
- Fixed PyPDF2 deprecated API calls in `sfp_filemeta.py` to use pypdf style
- Fixed 14 `type(x) == Y` comparisons to use `isinstance()`
