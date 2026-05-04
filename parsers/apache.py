"""Apache/Nginx Combined Log Format parser."""
import re
from datetime import datetime
from typing import Optional

PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

SQLI_PATTERNS = [
    "union select", "' or '", "or 1=1", "drop table", "information_schema",
    "sleep(", "benchmark(", "' and '", "-- -", "xp_cmdshell",
]
XSS_PATTERNS = [
    "<script", "onerror=", "onload=", "javascript:", "alert(",
    "document.cookie", "eval(", "<img src=x",
]
PATH_TRAVERSAL = ["../", "..%2f", "..\\", "%2e%2e", "etc/passwd", "win.ini"]
SCANNERS = ["nikto", "sqlmap", "nmap", "masscan", "dirbuster", "gobuster", "burpsuite", "hydra"]


def parse_line(line: str) -> Optional[dict]:
    m = PATTERN.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    try:
        ts = datetime.strptime(g["time"], TIME_FMT)
    except Exception:
        ts = None
    status = int(g["status"])
    path_lower = g["path"].lower()
    ua_lower = (g.get("ua") or "").lower()

    threats = []
    for p in SQLI_PATTERNS:
        if p in path_lower:
            threats.append("SQLi")
            break
    for p in XSS_PATTERNS:
        if p in path_lower:
            threats.append("XSS")
            break
    for p in PATH_TRAVERSAL:
        if p in path_lower:
            threats.append("PathTraversal")
            break
    for s in SCANNERS:
        if s in ua_lower:
            threats.append(f"Scanner:{s}")
            break
    if status == 401:
        threats.append("Unauthorized")
    elif status == 403:
        threats.append("Forbidden")

    return {
        "ip": g["ip"],
        "timestamp": ts.isoformat() if ts else g["time"],
        "method": g["method"],
        "path": g["path"],
        "status": status,
        "size": g["size"],
        "ua": g.get("ua", ""),
        "threats": threats,
        "source": "apache",
    }


def parse_file(path: str) -> list[dict]:
    events = []
    try:
        with open(path, "r", errors="replace") as f:
            for line in f:
                ev = parse_line(line)
                if ev:
                    events.append(ev)
    except Exception as e:
        print(f"[!] Error reading {path}: {e}")
    return events
