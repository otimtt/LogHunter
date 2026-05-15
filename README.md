# LogHunter

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![No Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)

SIEM-lite log analyzer and threat detection engine. Parse Apache/Nginx and SSH logs, automatically detect attack patterns, and generate an interactive HTML dashboard.

```
 ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║     ██╔═══██╗██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║     ██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ███████╗╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
```

## Features

- **Apache/Nginx parser** — Combined Log Format, full field extraction
- **SSH auth log parser** — syslog format, failed/successful logins
- **Rules-based threat detection:**
  - SSH Brute Force (configurable threshold, default >10 failures/IP)
  - SQL Injection payloads in request paths
  - XSS payloads in request paths
  - Directory/Path Traversal sequences
  - Known scanner User-Agents (Nikto, sqlmap, Gobuster, Masscan, Hydra...)
  - Repeated 401/403 errors
- **SQLite persistence** — query the event database with any SQL tool
- **Interactive HTML dashboard** with Chart.js graphs
- **JSON export** for integration with other tools
- **Demo mode** — synthetic attack data, no real logs needed
- **Zero external dependencies** — pure Python stdlib

## Installation

```bash
git clone https://github.com/otimtt/LogHunter
cd loghunter
python loghunter.py --help
```

> Requires Python 3.10+. No `pip install` needed.

## Usage

```bash
# Run with demo data (no real logs needed)
python loghunter.py --demo --html dashboard.html

# Analyze Apache/Nginx access log
python loghunter.py --apache /var/log/nginx/access.log --html report.html

# Analyze SSH auth log
python loghunter.py --ssh /var/log/auth.log

# Analyze both at once
python loghunter.py \
  --apache /var/log/apache2/access.log \
  --ssh /var/log/auth.log \
  --html dashboard.html \
  --json alerts.json

# Reset database and re-run
python loghunter.py --reset --apache access.log --html dashboard.html

# Use custom database path
python loghunter.py --demo --db /tmp/hunt.db --html report.html
```

## Detection Rules

| Rule ID | Severity | Trigger |
|---------|----------|---------|
| `BRUTE001` | HIGH | >10 failed SSH logins from same IP |
| `SQLI001` | HIGH | SQL injection keywords in request path |
| `PATH001` | HIGH | Directory traversal sequences (`../`, `%2e%2e`) |
| `XSS001` | MEDIUM | XSS payloads (`<script>`, `onerror=`, etc.) |
| `SCAN001` | MEDIUM | Known security scanner User-Agent |
| `AUTH001` | MEDIUM | Repeated HTTP 401 errors from same IP |

## Dashboard

The HTML dashboard (generated with `--html`) includes:

- **Summary cards** — total events, threat events, alerts, unique IPs
- **Top Threat IPs** bar chart
- **HTTP Status Distribution** doughnut chart
- **Alert table** — sortable by severity and count

## Output Example

```
══════════════════════════════════════════════════════════
  ANALYSIS SUMMARY
────────────────────────────────────────────────────────
  Total Events  : 620
  Threat Events : 56
  Alerts        : 14
  Unique IPs    : 23

  TOP THREAT IPs:
  192.168.1.100        ████████████████████ 20
  10.0.0.55            ████████████████████ 20

  TOP ALERTS:
  [HIGH  ] SSH Brute Force          192.168.1.100  (50x)
  [HIGH  ] SQL Injection Attempt    10.0.0.55      (12x)
  [MEDIUM] Scanner: sqlmap          172.16.0.99    (12x)
```

## Privacy

Real log files may contain sensitive IP addresses and URLs. The `.gitignore` excludes `*.log`, `*.db`, and `*.html` — **never commit real log data to a public repository.**

## License

MIT © Timoteo Silva
