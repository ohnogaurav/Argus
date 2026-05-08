"""
CyberOPS Visualization Module.
Generates charts and dashboard data from existing system events.
Reuses data from log_scanner, packet_capture, threat_intel.
"""

import json
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List

# ── CHART DATA GENERATORS ──────────────────────────────────────────────

def generate_auth_timeline(events: list) -> dict:
    """
    Generate timeline of auth events for chart.
    Returns {labels: [times], failed: [counts], success: [counts]}
    """
    timeline = defaultdict(lambda: {"failed": 0, "success": 0})

    for event in events:
        hour = event["time"][:13] + ":00"  # Round to hour
        if event["type"] == "FAILED":
            timeline[hour]["failed"] += 1
        else:
            timeline[hour]["success"] += 1

    labels = sorted(timeline.keys())
    failed_data = [timeline[h]["failed"] for h in labels]
    success_data = [timeline[h]["success"] for h in labels]

    return {
        "labels": labels,
        "failed": failed_data,
        "success": success_data,
        "type": "line"
    }


def generate_top_ips_chart(ip_fails: dict, ip_success: dict) -> dict:
    """
    Generate top attacking IPs chart.
    Returns {labels: [IPs], failures: [counts]}
    """
    sorted_ips = sorted(ip_fails.items(), key=lambda x: x[1], reverse=True)[:10]
    labels = [ip for ip, _ in sorted_ips]
    values = [cnt for _, cnt in sorted_ips]

    return {
        "labels": labels,
        "values": values,
        "type": "bar"
    }


def generate_protocol_distribution(packets: list) -> dict:
    """
    Generate protocol distribution from packets.
    Returns {labels: [protocols], values: [counts]}
    """
    proto_count = Counter(p.get("proto", "OTHER") for p in packets)

    return {
        "labels": list(proto_count.keys()),
        "values": list(proto_count.values()),
        "type": "pie"
    }


def generate_threat_distribution(packets: list) -> dict:
    """
    Generate threat type distribution from packet analysis.
    Returns {labels: [threat_types], values: [counts]}
    """
    flagged = [p for p in packets if p.get("flagged")]
    if not flagged:
        return {"labels": [], "values": [], "type": "pie"}

    threat_count = Counter()
    for p in flagged:
        threats = p.get("threats", [])
        for t in threats:
            threat_count[t] += 1

    if not threat_count:
        threat_count["Other"] = len(flagged)

    return {
        "labels": list(threat_count.keys())[:10],
        "values": list(threat_count.values())[:10],
        "type": "pie"
    }


def generate_security_score_gauge(log_data: dict, packet_data: dict) -> dict:
    """
    Generate overall security score from available metrics.
    Returns {score: 0-100, level: str, threats: count, risks: count}
    """
    score = 100

    # Auth events
    brute_force = log_data.get("brute_force", [])
    if brute_force:
        score -= min(30, len(brute_force) * 5)

    # Packet threats
    packets = packet_data.get("packets", [])
    flagged = sum(1 for p in packets if p.get("flagged"))
    if flagged:
        score -= min(20, flagged)

    # Determine level
    if score >= 80:
        level = "SECURE"
    elif score >= 60:
        level = "FAIR"
    elif score >= 40:
        level = "RISKY"
    else:
        level = "CRITICAL"

    return {
        "score": max(0, score),
        "level": level,
        "threats_detected": len(brute_force),
        "flagged_packets": flagged,
        "total_events": len(log_data.get("events", []))
    }


def generate_port_scan_summary(recent_scans: list) -> dict:
    """
    Generate summary of recent port scans.
    Returns {hosts_scanned: count, total_open_ports: count, risky_ports: count}
    """
    return {
        "hosts_scanned": len(recent_scans),
        "total_open_ports": sum(len(s.get("open", [])) for s in recent_scans),
        "risky_ports": sum(
            1 for s in recent_scans
            for port in s.get("open", [])
            if port.get("service", "").upper() in [
                "RDP", "TELNET", "VNC", "FTP"
            ]
        ),
        "scans": recent_scans[:5]
    }


# ── DASHBOARD AGGREGATOR ──────────────────────────────────────────────

def generate_dashboard_data(log_data: dict, packet_data: dict, scan_history: list = None) -> dict:
    """
    Aggregate all dashboard metrics and charts.
    Used by /dashboard route to feed frontend.
    """
    if scan_history is None:
        scan_history = []

    security_gauge = generate_security_score_gauge(log_data, packet_data)
    packets = packet_data.get("packets", [])

    return {
        "timestamp": datetime.now().isoformat(),
        "security_gauge": security_gauge,
        "auth_timeline": generate_auth_timeline(log_data.get("events", [])),
        "top_ips": generate_top_ips_chart(
            log_data.get("ip_fails", {}),
            log_data.get("ip_success", {})
        ),
        "protocol_dist": generate_protocol_distribution(packets),
        "threat_dist": generate_threat_distribution(packets),
        "port_scan": generate_port_scan_summary(scan_history),
        "stats": {
            "total_events": len(log_data.get("events", [])),
            "brute_force_ips": len(log_data.get("brute_force", [])),
            "suspicious_ips": len(log_data.get("suspicious_ips", [])),
            "packets_captured": len(packets),
            "flagged_packets": sum(1 for p in packets if p.get("flagged")),
        }
    }


# ── HTML DASHBOARD GENERATOR ──────────────────────────────────────────

def render_dashboard_html() -> str:
    """Return HTML for dashboard with embedded charts."""
    return """
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <div id="security-gauge" style="width:100%;height:300px;margin-bottom:20px"></div>
    <div id="auth-timeline" style="width:100%;height:400px;margin-bottom:20px"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:20px">
        <div id="top-ips" style="height:300px"></div>
        <div id="protocol-dist" style="height:300px"></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
        <div id="threat-dist" style="height:300px"></div>
        <div id="stats-box" style="background:var(--panel);border:1px solid var(--border);padding:20px;border-radius:3px">
            <div style="font-family:Orbitron;color:var(--accent);margin-bottom:20px">SYSTEM STATS</div>
            <table style="width:100%;font-size:.8rem">
                <tr><td style="padding:8px;color:var(--dim)">Total Events</td><td id="stat-events" style="text-align:right;color:var(--accent)">-</td></tr>
                <tr><td style="padding:8px;color:var(--dim)">Brute Force IPs</td><td id="stat-bf" style="text-align:right;color:var(--accent2)">-</td></tr>
                <tr><td style="padding:8px;color:var(--dim)">Suspicious IPs</td><td id="stat-sus" style="text-align:right;color:var(--accent3)">-</td></tr>
                <tr><td style="padding:8px;color:var(--dim)">Packets Captured</td><td id="stat-pkts" style="text-align:right;color:var(--accent)">-</td></tr>
                <tr><td style="padding:8px;color:var(--dim)">Threats Detected</td><td id="stat-threats" style="text-align:right;color:var(--accent2)">-</td></tr>
            </table>
        </div>
    </div>
    """
