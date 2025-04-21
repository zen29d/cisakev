# CISA KEV

A modular Python-based threat intelligence project centered around the [CISA Known Exploited Vulnerabilities (KEV) catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). The goal is to create an extensible system for tracking, enriching, and acting on KEV data for defenders, CTI analysts, and researchers.

This project is divided into multiple sub-projects/modules.

## Sub-Projects

### 1. CISA KEV Watcher

`cisa_kev_watcher` is a Python script that monitors the CISA KEV catalog and notifies you when new KEVs are added. It’s ideal for CTI teams, SOC automation, home labs, and threat research environments.

#### Features

- 🛡️ Monitors and detects new CISA KEV entries
- 🔔 Sends alerts when new CVEs are added
- 🥓 Supports both cron job and manual execution
- 🧠 Designed with future enrichment and intelligence in mind

#### Requirements

- Python 3.6+
- `requests`
- Your preferred notification (webhook)

Install dependencies:

```bash
pip install -r requirements.txt
```
Configure webhook: For notification add in below file under config/

webhook.conf
```
# This is comment, add without #
# APP=https://youwebhookapp.com
Slack=https://hooks.slack.com/services/slack323joinxRandom
```

#### Usage

Run manually:

```bash
python3 cisa_kev_watcher.py
```

Or add to cron:

```bash
# Run every 6 hours
0 */6 * * * /usr/bin/python3 /path/to/cisa_kev_watcher.py
```


#### Example Notification

![KEV Watcher Notification](media/slack_notification.png)

#### Logging

![KEV Watcher Logs](media/logs.png)

---

## TODO (Project-Wide)

- [ ] **CVE Enrichment**  
  Add data from NVD and other source to enrich each CVE with:
  - CWE
  - CVSS scores
  - References
  - Exploitability metrics


- [x] **Queryable Data Store**  
  Store KEVs in SQLite/JSON to support:
  - CLI queries by CVE ID, vendor, date, etc.
  - Generate cli stats
  - Export filtered data

> [!CAUTION]
> 'cisakev' CLI entry point is not yet active; use 'cisa_kev_cli.py' instead.

#### Usage
```bash
python3 cisa_kev_cli.py
```
![CLI](media/cli_help.png)

#### Example
![CLI](media/cli.png)


- [ ] **Public PoC Scraper**  
  Automatically search for PoCs linked to each KEV using:
  - GitHub (via GitHub Search API)
  - ExploitDB
  - Other OSINT sources



---

## Ideal For

- Internal vulnerability tracking
- Security team workflows




## Author

Zen — [GitHub](https://github.com/zen29d)  
Part of ongoing CVE automation research

