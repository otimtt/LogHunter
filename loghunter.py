#!/usr/bin/env python3
"""
LogHunter — SIEM Lite / Log Analyzer
Parses Apache/Nginx + SSH logs, detects threats, generates dashboard
"""

import os
import sys
import json
import random
import sqlite3
import argparse
from datetime import datetime
from collections import defaultdict, Counter
from typing import Optional

# ─── Colors ─────────────────────────────────────────────────────────────────
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"
C="\033[96m"; W="\033[97m"; DIM="\033[2m"; BOLD="\033[1m"; RESET="\033[0m"

BANNER = f"""
{Y}{BOLD}
 ██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║     ██╔═══██╗██╔════╝ ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║     ██║   ██║██║  ███╗███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║     ██║   ██║██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ███████╗╚██████╔╝╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{RESET}{DIM}                      SIEM Lite — Log Analysis & Threat Detection{RESET}
"""

DB_PATH = "loghunter.db"

# ─── Rules Engine ────────────────────────────────────────────────────────────
BRUTE_THRESHOLD = 10
ALERT_RULES = [
    {
        "id": "BRUTE001",
        "name": "SSH Brute Force",
        "desc": "More than {threshold} failed SSH logins from same IP",
        "severity": "HIGH",
    },
    {
        "id": "SCAN001",
        "name": "Web Scanner Detected",
        "desc": "Known scanner User-Agent detected",
        "severity": "MEDIUM",
    },
    {
        "id": "SQLI001",
        "name": "SQL Injection Attempt",
        "desc": "SQLi payload detected in request",
        "severity": "HIGH",
    },
    {
        "id": "XSS001",
        "name": "XSS Attempt",
        "desc": "XSS payload detected in request",
        "severity": "MEDIUM",
    },
    {
        "id": "PATH001",
        "name": "Path Traversal Attempt",
        "desc": "Directory traversal in request path",
        "severity": "HIGH",
    },
    {
        "id": "AUTH001",
        "name": "Multiple 401 Errors",
        "desc": "Repeated unauthorized access attempts",
        "severity": "MEDIUM",
    },
]


# ─── Database ─────────────────────────────────────────────────────────────────

def init_db(path: str = DB_PATH):
    con = sqlite3.connect(path)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            source    TEXT,
            timestamp TEXT,
            ip        TEXT,
            type      TEXT,
            method    TEXT DEFAULT '',
            path      TEXT DEFAULT '',
            status    INTEGER DEFAULT 0,
            ua        TEXT DEFAULT '',
            threats   TEXT DEFAULT '[]',
            raw       TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id   TEXT,
            severity  TEXT,
            name      TEXT,
            ip        TEXT,
            detail    TEXT,
            count     INTEGER DEFAULT 1,
            first_seen TEXT,
            last_seen  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
    """)
    con.commit()
    return con


def insert_events(con, events: list[dict]):
    for e in events:
        threats = json.dumps(e.get("threats", []))
        con.execute(
            "INSERT INTO events (source,timestamp,ip,type,method,path,status,ua,threats,raw) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                e.get("source", ""),
                e.get("timestamp", ""),
                e.get("ip", ""),
                e.get("type", "request"),
                e.get("method", ""),
                e.get("path", ""),
                int(e.get("status", 0)),
                e.get("ua", ""),
                threats,
                e.get("raw", ""),
            )
        )
    con.commit()


# ─── Analysis Engine ──────────────────────────────────────────────────────────

def detect_brute_force(con) -> list[dict]:
    rows = con.execute("""
        SELECT ip, COUNT(*) as cnt
        FROM events
        WHERE type='failed_login' AND ip != 'unknown'
        GROUP BY ip
        HAVING cnt >= ?
        ORDER BY cnt DESC
    """, (BRUTE_THRESHOLD,)).fetchall()
    return [{"ip": r[0], "count": r[1]} for r in rows]


def get_threat_ips(con) -> dict:
    rows = con.execute("""
        SELECT ip, threats FROM events WHERE threats != '[]' AND ip != ''
    """).fetchall()
    threat_map = defaultdict(Counter)
    for ip, threats_str in rows:
        for t in json.loads(threats_str):
            threat_map[ip][t] += 1
    return dict(threat_map)


def generate_alerts(con) -> list[dict]:
    alerts = []

    # Brute force
    for bf in detect_brute_force(con):
        alerts.append({
            "rule_id": "BRUTE001",
            "severity": "HIGH",
            "name": "SSH Brute Force",
            "ip": bf["ip"],
            "detail": f"{bf['count']} failed login attempts",
            "count": bf["count"],
        })

    # Web threats
    threat_ips = get_threat_ips(con)
    for ip, threats in threat_ips.items():
        for threat, count in threats.items():
            if threat == "SQLi":
                alerts.append({"rule_id": "SQLI001", "severity": "HIGH", "name": "SQL Injection Attempt",
                                "ip": ip, "detail": f"{count} SQLi requests", "count": count})
            elif threat == "XSS":
                alerts.append({"rule_id": "XSS001", "severity": "MEDIUM", "name": "XSS Attempt",
                                "ip": ip, "detail": f"{count} XSS requests", "count": count})
            elif threat == "PathTraversal":
                alerts.append({"rule_id": "PATH001", "severity": "HIGH", "name": "Path Traversal",
                                "ip": ip, "detail": f"{count} traversal requests", "count": count})
            elif threat.startswith("Scanner:"):
                alerts.append({"rule_id": "SCAN001", "severity": "MEDIUM", "name": f"Scanner: {threat.split(':')[1]}",
                                "ip": ip, "detail": f"Known scanner UA detected ({count}x)", "count": count})

    return alerts


def save_alerts(con, alerts: list[dict]):
    for a in alerts:
        now = datetime.now().isoformat()
        con.execute(
            "INSERT INTO alerts (rule_id,severity,name,ip,detail,count,first_seen,last_seen) VALUES (?,?,?,?,?,?,?,?)",
            (a["rule_id"], a["severity"], a["name"], a["ip"], a["detail"], a["count"], now, now)
        )
    con.commit()


def print_summary(con):
    total_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_threats = con.execute("SELECT COUNT(*) FROM events WHERE threats != '[]'").fetchone()[0]
    total_alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unique_ips = con.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ip != ''").fetchone()[0]

    print(f"\n{Y}{'═'*60}{RESET}")
    print(f"  {BOLD}ANALYSIS SUMMARY{RESET}")
    print(f"{'─'*60}")
    print(f"  {BOLD}Total Events  :{RESET} {W}{total_events:,}{RESET}")
    print(f"  {BOLD}Threat Events :{RESET} {R}{total_threats:,}{RESET}")
    print(f"  {BOLD}Alerts        :{RESET} {R}{total_alerts:,}{RESET}")
    print(f"  {BOLD}Unique IPs    :{RESET} {C}{unique_ips:,}{RESET}")

    print(f"\n  {BOLD}TOP THREAT IPs:{RESET}")
    rows = con.execute("""
        SELECT ip, COUNT(*) as n FROM events
        WHERE threats != '[]' AND ip != ''
        GROUP BY ip ORDER BY n DESC LIMIT 10
    """).fetchall()
    for ip, n in rows:
        bar = R + "█" * min(n, 30) + RESET
        print(f"  {W}{ip:<20}{RESET} {bar} {n}")

    print(f"\n  {BOLD}TOP ALERTS:{RESET}")
    rows = con.execute(
        "SELECT severity, name, ip, count FROM alerts ORDER BY count DESC LIMIT 10"
    ).fetchall()
    sev_colors = {"HIGH": R, "MEDIUM": Y, "LOW": C, "INFO": B}
    for sev, name, ip, count in rows:
        color = sev_colors.get(sev, W)
        print(f"  {color}[{sev:<6}]{RESET} {name:<35} {DIM}{ip}{RESET} ({count}x)")

    print(f"\n  {BOLD}STATUS CODE DISTRIBUTION (Web):{RESET}")
    rows = con.execute("""
        SELECT status, COUNT(*) as n FROM events
        WHERE source='apache' GROUP BY status ORDER BY n DESC LIMIT 10
    """).fetchall()
    for status, n in rows:
        color = G if status < 400 else (Y if status < 500 else R)
        print(f"  {color}{status}{RESET}  {DIM}{'█' * min(n // max(1, total_events // 30), 40)}{RESET} {n:,}")

    print(f"{Y}{'═'*60}{RESET}\n")


def generate_html_dashboard(con, output: str):
    total_events = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    total_alerts = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unique_ips = con.execute("SELECT COUNT(DISTINCT ip) FROM events WHERE ip != ''").fetchone()[0]
    threat_events = con.execute("SELECT COUNT(*) FROM events WHERE threats != '[]'").fetchone()[0]

    # Top IPs
    top_ips = con.execute("""
        SELECT ip, COUNT(*) as n FROM events
        WHERE threats != '[]' AND ip != ''
        GROUP BY ip ORDER BY n DESC LIMIT 15
    """).fetchall()

    # Status codes
    status_dist = con.execute("""
        SELECT status, COUNT(*) as n FROM events WHERE source='apache'
        GROUP BY status ORDER BY n DESC LIMIT 10
    """).fetchall()

    # Recent alerts
    alerts = con.execute(
        "SELECT severity, name, ip, detail, count, last_seen FROM alerts ORDER BY count DESC LIMIT 30"
    ).fetchall()

    alert_rows = ""
    sev_colors_html = {"HIGH": "#ff3333", "MEDIUM": "#ffcc00", "LOW": "#00ccff", "INFO": "#aaa"}
    for sev, name, ip, detail, count, ts in alerts:
        color = sev_colors_html.get(sev, "#fff")
        alert_rows += f"""<tr>
          <td><span style="color:{color};font-weight:bold">{sev}</span></td>
          <td>{name}</td><td>{ip}</td><td>{detail}</td>
          <td style="text-align:center">{count}</td>
          <td style="color:#555;font-size:.75rem">{ts[:19] if ts else ''}</td>
        </tr>"""

    ip_chart_labels = json.dumps([r[0] for r in top_ips])
    ip_chart_values = json.dumps([r[1] for r in top_ips])
    status_labels = json.dumps([str(r[0]) for r in status_dist])
    status_values = json.dumps([r[1] for r in status_dist])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LogHunter Dashboard</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0 }}
    body {{ background:#0a0a0f; color:#e0e0e0; font-family:'Courier New',monospace; padding:1.5rem }}
    h1 {{ color:#ffcc00; margin-bottom:.3rem }}
    .sub {{ color:#555; font-size:.8rem; margin-bottom:2rem }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:1rem; margin-bottom:2rem }}
    .card {{ background:#111; border:1px solid #1e1e2e; border-radius:6px; padding:1.2rem; text-align:center }}
    .card-val {{ font-size:2rem; font-weight:bold; color:#ffcc00 }}
    .card-label {{ font-size:.75rem; color:#555; margin-top:.3rem }}
    .charts {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:2rem }}
    @media(max-width:700px) {{ .charts {{ grid-template-columns:1fr }} }}
    .chart-box {{ background:#111; border:1px solid #1e1e2e; border-radius:6px; padding:1rem }}
    .chart-box h3 {{ color:#ffcc00; font-size:.9rem; margin-bottom:1rem }}
    h2 {{ color:#ffcc00; margin-bottom:1rem; font-size:1rem }}
    table {{ width:100%; border-collapse:collapse }}
    th {{ background:#1a1500; color:#ffcc00; padding:.5rem 1rem; text-align:left; font-size:.75rem; text-transform:uppercase }}
    td {{ padding:.5rem 1rem; border-bottom:1px solid #1a1a1a; font-size:.8rem; vertical-align:top }}
    tr:hover td {{ background:#111 }}
    .footer {{ margin-top:2rem; color:#333; font-size:.7rem; text-align:center }}
  </style>
</head>
<body>
  <h1>&#9888; LogHunter Dashboard</h1>
  <div class="sub">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>

  <div class="cards">
    <div class="card"><div class="card-val">{total_events:,}</div><div class="card-label">Total Events</div></div>
    <div class="card"><div class="card-val" style="color:#ff3333">{threat_events:,}</div><div class="card-label">Threat Events</div></div>
    <div class="card"><div class="card-val" style="color:#ff3333">{total_alerts:,}</div><div class="card-label">Alerts</div></div>
    <div class="card"><div class="card-val" style="color:#00ccff">{unique_ips:,}</div><div class="card-label">Unique IPs</div></div>
  </div>

  <div class="charts">
    <div class="chart-box">
      <h3>Top Threat IPs</h3>
      <canvas id="ipChart"></canvas>
    </div>
    <div class="chart-box">
      <h3>HTTP Status Distribution</h3>
      <canvas id="statusChart"></canvas>
    </div>
  </div>

  <h2>&#9660; Active Alerts</h2>
  <table>
    <thead><tr><th>Severity</th><th>Rule</th><th>IP</th><th>Detail</th><th>Count</th><th>Last Seen</th></tr></thead>
    <tbody>{alert_rows or '<tr><td colspan="6" style="color:#555;text-align:center">No alerts</td></tr>'}</tbody>
  </table>

  <div class="footer">LogHunter v1.0 — For authorized use only</div>

  <script>
    const chartDefaults = {{ responsive: true, plugins: {{ legend: {{ display: false }} }} }};
    new Chart(document.getElementById('ipChart'), {{
      type: 'bar',
      data: {{ labels: {ip_chart_labels}, datasets: [{{ data: {ip_chart_values}, backgroundColor: '#ff3333' }}] }},
      options: {{ ...chartDefaults, scales: {{ x: {{ ticks: {{ color:'#555', font:{{size:10}} }}, grid:{{color:'#111'}} }}, y: {{ ticks:{{color:'#555'}}, grid:{{color:'#1a1a1a'}} }} }} }}
    }});
    const statusColors = {status_labels}.map(s => +s >= 500 ? '#ff3333' : +s >= 400 ? '#ffcc00' : '#00cc88');
    new Chart(document.getElementById('statusChart'), {{
      type: 'doughnut',
      data: {{ labels: {status_labels}, datasets: [{{ data: {status_values}, backgroundColor: statusColors }}] }},
      options: {{ responsive: true, plugins: {{ legend: {{ labels: {{ color:'#aaa', font:{{size:10}} }} }} }} }}
    }});
  </script>
</body>
</html>"""

    with open(output, "w") as f:
        f.write(html)
    print(f"  {G}[✓]{RESET} Dashboard saved → {BOLD}{output}{RESET}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="LogHunter — SIEM Lite Log Analyzer")
    parser.add_argument("--apache", nargs="+", metavar="FILE", help="Apache/Nginx access log files")
    parser.add_argument("--ssh", nargs="+", metavar="FILE", help="SSH auth log files")
    parser.add_argument("--db", default=DB_PATH, help="SQLite database path")
    parser.add_argument("--html", help="Output HTML dashboard file")
    parser.add_argument("--json", help="Export alerts as JSON")
    parser.add_argument("--reset", action="store_true", help="Reset database before analysis")
    parser.add_argument("--demo", action="store_true", help="Generate demo data for testing")
    args = parser.parse_args()

    if args.reset and os.path.exists(args.db):
        os.remove(args.db)
        print(f"  {Y}[!]{RESET} Database reset.")

    con = init_db(args.db)

    if args.demo:
        generate_demo_data(con)
    else:
        from parsers import apache as apache_parser, ssh as ssh_parser

        total_parsed = 0
        if args.apache:
            for path in args.apache:
                print(f"  {C}[*]{RESET} Parsing Apache log: {path}")
                events = apache_parser.parse_file(path)
                insert_events(con, events)
                total_parsed += len(events)
                print(f"      {G}→ {len(events):,} events{RESET}")

        if args.ssh:
            for path in args.ssh:
                print(f"  {C}[*]{RESET} Parsing SSH log: {path}")
                events = ssh_parser.parse_file(path)
                insert_events(con, events)
                total_parsed += len(events)
                print(f"      {G}→ {len(events):,} events{RESET}")

        if total_parsed == 0 and not args.demo:
            print(f"  {Y}[!]{RESET} No events parsed. Use --apache / --ssh / --demo")

    print(f"\n  {C}[*]{RESET} Running threat detection rules...")
    alerts = generate_alerts(con)
    save_alerts(con, alerts)
    print(f"  {G}[✓]{RESET} {len(alerts)} alert(s) generated")

    print_summary(con)

    if args.html:
        generate_html_dashboard(con, args.html)

    if args.json:
        rows = con.execute(
            "SELECT rule_id,severity,name,ip,detail,count,last_seen FROM alerts"
        ).fetchall()
        data = [dict(zip(["rule_id","severity","name","ip","detail","count","last_seen"], r))
                for r in rows]
        with open(args.json, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {G}[✓]{RESET} JSON → {args.json}")

    con.close()


def generate_demo_data(con):
    """Inject synthetic log data for demo/testing."""
    print(f"  {Y}[*]{RESET} Generating demo data...")
    attacker_ips = ["192.168.1.100", "10.0.0.55", "172.16.0.99", "203.0.113.42"]
    normal_ips = [f"198.51.100.{i}" for i in range(1, 20)]

    events = []
    # Normal traffic
    for _ in range(500):
        events.append({
            "source": "apache", "ip": random.choice(normal_ips),
            "timestamp": datetime.now().isoformat(),
            "type": "request", "method": "GET",
            "path": random.choice(["/", "/about", "/contact", "/api/v1/users"]),
            "status": random.choice([200, 200, 200, 304]),
            "ua": "Mozilla/5.0 (Windows NT 10.0)", "threats": [],
        })

    # Attack traffic
    sqli_paths = ["/?id=1' OR '1'='1", "/?q=union select NULL--", "/search?q=' AND SLEEP(3)--"]
    xss_paths = ["/?name=<script>alert(1)</script>", "/search?q=<img src=x onerror=alert(1)>"]
    traversal_paths = ["/?file=../../../etc/passwd", "/?page=..%2F..%2Fetc%2Fpasswd"]
    scanner_ua = "sqlmap/1.7.8#stable (https://sqlmap.org)"

    for ip in attacker_ips:
        for path in sqli_paths:
            events.append({"source": "apache", "ip": ip, "timestamp": datetime.now().isoformat(),
                           "type": "request", "method": "GET", "path": path, "status": 200,
                           "ua": scanner_ua, "threats": ["SQLi", "Scanner:sqlmap"]})
        for path in xss_paths:
            events.append({"source": "apache", "ip": ip, "timestamp": datetime.now().isoformat(),
                           "type": "request", "method": "GET", "path": path, "status": 200,
                           "ua": "Mozilla/5.0", "threats": ["XSS"]})
        for path in traversal_paths:
            events.append({"source": "apache", "ip": ip, "timestamp": datetime.now().isoformat(),
                           "type": "request", "method": "GET", "path": path, "status": 200,
                           "ua": "Nikto/2.1.6", "threats": ["PathTraversal", "Scanner:nikto"]})

    # SSH brute force
    for _ in range(50):
        events.append({
            "source": "ssh", "ip": attacker_ips[0], "timestamp": datetime.now().isoformat(),
            "type": "failed_login", "user": random.choice(["root", "admin", "ubuntu", "pi"]),
            "threats": ["BruteForce"],
        })

    insert_events(con, events)
    print(f"  {G}[✓]{RESET} {len(events)} demo events injected")


if __name__ == "__main__":
    main()
