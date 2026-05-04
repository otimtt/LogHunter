"""SSH auth log parser (syslog format)."""
import re
from datetime import datetime
from typing import Optional

# Matches: May  4 13:22:01 host sshd[1234]: ...
SYSLOG_RE = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.+)'
)

MONTH_MAP = {m: i+1 for i, m in enumerate(
    ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
)}

def parse_line(line: str, year: int = None) -> Optional[dict]:
    import datetime as dt_mod
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    g = m.groupdict()
    msg = g["msg"]
    yr = year or dt_mod.datetime.now().year
    month = MONTH_MAP.get(g["month"], 1)
    try:
        ts = dt_mod.datetime(yr, month, int(g["day"]),
                             *[int(x) for x in g["time"].split(":")])
    except Exception:
        ts = None

    event = {"timestamp": ts.isoformat() if ts else "", "raw": msg, "source": "ssh"}

    if "Failed password" in msg or "Invalid user" in msg:
        ip_m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        user_m = re.search(r'(?:for|user) (\S+)', msg)
        event.update({
            "type": "failed_login",
            "ip": ip_m.group(1) if ip_m else "unknown",
            "user": user_m.group(1) if user_m else "unknown",
            "threats": ["BruteForce"],
        })
    elif "Accepted password" in msg or "Accepted publickey" in msg:
        ip_m = re.search(r'from (\d+\.\d+\.\d+\.\d+)', msg)
        user_m = re.search(r'for (\S+)', msg)
        event.update({
            "type": "successful_login",
            "ip": ip_m.group(1) if ip_m else "unknown",
            "user": user_m.group(1) if user_m else "unknown",
            "threats": [],
        })
    elif "Connection closed" in msg or "Disconnected" in msg:
        event["type"] = "disconnect"
        event["threats"] = []
    elif "POSSIBLE BREAK-IN ATTEMPT" in msg:
        event.update({"type": "break_in_attempt", "threats": ["BreakIn"]})
    else:
        event.update({"type": "misc", "threats": []})

    return event


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
