"""
Real Windows Event Log parser + real remote port scanner.
"""

import socket
import concurrent.futures
from collections import defaultdict
from datetime import datetime, timedelta

# Windows Event Log
try:
    import win32evtlog
    import win32con
    WIN32_OK = True
except ImportError:
    WIN32_OK = False

# ── REAL WINDOWS AUTH LOG ──────────────────────────────────────────────
FAIL_EVENT_ID = 4625   # Windows failed login
SUCCESS_EVENT_ID = 4624  # Windows successful login


def generate_mock_auth_logs():
    """Generates highly realistic mock Windows auth logs for demonstration."""
    import random
    from collections import defaultdict
    from datetime import datetime, timedelta
    
    mock_ips = ["185.220.101.5", "45.33.32.156", "203.0.113.99", "198.51.100.7", "109.236.80.12", "88.198.24.11"]
    mock_users = ["admin", "root", "administrator", "guest", "dbuser", "user1", "test"]
    
    events = []
    ip_fails = defaultdict(int)
    ip_success = defaultdict(int)
    
    now = datetime.now()
    
    # Mock a brute force attacker on 185.220.101.5
    bf_ip = "185.220.101.5"
    for i in range(12):
        ts = now - timedelta(minutes=15 - i * 1.2)
        user = random.choice(mock_users)
        ip_fails[bf_ip] += 1
        events.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "type": "FAILED",
            "user": user,
            "ip": bf_ip
        })
        
    # Another smaller brute force from 109.236.80.12
    bf_ip2 = "109.236.80.12"
    for i in range(4):
        ts = now - timedelta(hours=2, minutes=20 - i * 2)
        ip_fails[bf_ip2] += 1
        events.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "type": "FAILED",
            "user": "administrator",
            "ip": bf_ip2
        })
        
    # Generate random normal successes and failures
    for i in range(50):
        ts = now - timedelta(minutes=i * 25 + random.randint(1, 15))
        ip = random.choice(mock_ips)
        user = random.choice(mock_users)
        kind = "FAILED" if random.random() < 0.25 else "SUCCESS"
        
        if kind == "FAILED":
            ip_fails[ip] += 1
        else:
            ip_success[ip] += 1
            
        events.append({
            "time": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "type": kind,
            "user": user,
            "ip": ip
        })
        
    # Sort events by time descending
    events.sort(key=lambda x: x["time"], reverse=True)
    
    brute_force = [
        {"ip": ip, "fails": cnt}
        for ip, cnt in ip_fails.items() if cnt >= 3
    ]
    brute_force.sort(key=lambda x: x["fails"], reverse=True)
    
    return {
        "is_simulated": True,
        "brute_force": brute_force,
        "suspicious_ips": list(ip_fails.keys()),
        "ip_fails": dict(ip_fails),
        "ip_success": dict(ip_success),
        "events": events[:100],
        "total_scanned": len(events)
    }


def read_windows_auth_log(hours_back=24, max_events=500):
    """Read real Windows Security Event Log, fallback to simulation mode on error/non-Windows."""
    if not WIN32_OK:
        return generate_mock_auth_logs()

    events = []
    ip_fails = defaultdict(int)
    ip_success = defaultdict(int)

    try:
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        cutoff = datetime.now() - timedelta(hours=hours_back)
        count = 0

        while count < max_events:
            records = win32evtlog.ReadEventLog(hand, flags, 0)
            if not records:
                break
            for rec in records:
                try:
                    ts = rec.TimeGenerated
                    if hasattr(ts, 'year'):
                        dt = datetime(ts.year, ts.month, ts.day,
                                      ts.hour, ts.minute, ts.second)
                        if dt < cutoff:
                            continue
                    eid = rec.EventID & 0xFFFF
                    if eid not in (FAIL_EVENT_ID, SUCCESS_EVENT_ID):
                        continue

                    strings = rec.StringInserts or []
                    user = strings[5] if len(strings) > 5 else "unknown"
                    ip = strings[19] if len(strings) > 19 else "-"
                    ip = ip.strip() if ip else "-"

                    kind = "FAILED" if eid == FAIL_EVENT_ID else "SUCCESS"
                    if eid == FAIL_EVENT_ID and ip not in ("-", "", "::1", "127.0.0.1"):
                        ip_fails[ip] += 1
                    if eid == SUCCESS_EVENT_ID and ip not in ("-", "", "::1", "127.0.0.1"):
                        ip_success[ip] += 1

                    events.append({
                        "time": str(ts)[:19],
                        "type": kind,
                        "user": user,
                        "ip": ip
                    })
                    count += 1
                except Exception:
                    continue

        win32evtlog.CloseEventLog(hand)
    except Exception as e:
        # If open event log fails (e.g. not Administrator on Windows), fallback to simulation
        return generate_mock_auth_logs()

    brute_force = [
        {"ip": ip, "fails": cnt}
        for ip, cnt in ip_fails.items() if cnt >= 3
    ]
    brute_force.sort(key=lambda x: x["fails"], reverse=True)

    return {
        "is_simulated": False,
        "brute_force": brute_force,
        "suspicious_ips": list(ip_fails.keys()),
        "ip_fails": dict(ip_fails),
        "ip_success": dict(ip_success),
        "events": events[:100],
        "total_scanned": count
    }


# ── REAL REMOTE PORT SCANNER ───────────────────────────────────────────
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    135: "RPC", 139: "NETBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 1521: "ORACLE", 3306: "MYSQL",
    3389: "RDP", 5432: "POSTGRES", 5900: "VNC", 6379: "REDIS",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT", 27017: "MONGODB"
}


def scan_single_port(host, port, timeout=0.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return port, result == 0
    except Exception:
        return port, False


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def scan_ports_real(host="127.0.0.1", port_range=(1, 1024), custom_ports=None, timeout=0.5, max_workers=100):
    """Real concurrent port scanner. Works on any host."""
    ip = resolve_host(host)
    if not ip:
        return {"error": f"Cannot resolve host: {host}", "open": [], "host": host}

    if custom_ports:
        ports = custom_ports
    else:
        ports = list(range(port_range[0], port_range[1] + 1))

    open_ports = []
    closed_count = 0
    start_time = datetime.now()

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(scan_single_port, ip, p, timeout): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                service = COMMON_PORTS.get(port, "UNKNOWN")
                open_ports.append({"port": port, "service": service})
            else:
                closed_count += 1

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - start_time).total_seconds()

    return {
        "host": host,
        "ip": ip,
        "open": open_ports,
        "closed": closed_count,
        "total_scanned": len(ports),
        "elapsed": round(elapsed, 2)
    }


def quick_scan_common(host="127.0.0.1"):
    """Scan only well-known ports fast."""
    return scan_ports_real(host, custom_ports=list(COMMON_PORTS.keys()), timeout=0.3)
