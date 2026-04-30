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


def _capture_loop(iface, duration):
    global capture_running
    try:
        sniff(iface=iface, prn=process_packet, timeout=duration, store=False)
    except Exception as e:
        captured_packets.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "src": "ERROR", "dst": "", "proto": "", "sport": 0, "dport": 0,
            "payload": str(e), "threats": [], "flagged": True
        })
    finally:
        capture_running = False


def start_capture(iface=None, duration=30):
    global capture_running, capture_thread
    if not SCAPY_OK:
        return False, "Scapy not installed. Run: pip install scapy"
    if capture_running:
        return False, "Already capturing"
    capture_running = True
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
        return []
    try:
        return get_if_list()
    except Exception:
        return []


def get_status():
    return {
        "scapy_ok": SCAPY_OK,
        "running": capture_running,
        "total": len(captured_packets),
        "flagged": sum(1 for p in captured_packets if p["flagged"])
    }
