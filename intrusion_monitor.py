"""
CyberOPS Intrusion Alert Monitor.
Analyzes auth logs and packets for intrusion patterns.
Generates alerts for suspicious activity.
Follows captured_packets pattern (deque-based).
"""

from collections import deque, defaultdict
from datetime import datetime, timedelta
import json

# ── CONFIG ──────────────────────────────────────────────────────────────
ALERT_STORAGE_LIMIT = 500  # Max alerts in memory
ALERT_RETENTION_HOURS = 24

# Alert severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# Intrusion patterns
PATTERNS = {
    "brute_force": {"threshold": 5, "window": 300, "severity": SEVERITY_CRITICAL},
    "distributed_attack": {"threshold": 10, "window": 600, "severity": SEVERITY_HIGH},
    "sql_injection": {"threshold": 3, "window": 300, "severity": SEVERITY_CRITICAL},
    "port_scan": {"threshold": 20, "window": 60, "severity": SEVERITY_HIGH},
    "credential_reuse": {"threshold": 5, "window": 3600, "severity": SEVERITY_MEDIUM},
    "suspicious_payload": {"threshold": 5, "window": 300, "severity": SEVERITY_MEDIUM},
}

# ── STATE ───────────────────────────────────────────────────────────────
alerts_deque = deque(maxlen=ALERT_STORAGE_LIMIT)
event_history = defaultdict(list)  # For pattern detection


def _cleanup_old_events():
    """Remove events older than retention period."""
    cutoff = datetime.now() - timedelta(hours=ALERT_RETENTION_HOURS)
    for key in list(event_history.keys()):
        event_history[key] = [
            e for e in event_history[key]
            if datetime.fromisoformat(e["ts"]) > cutoff
        ]


def generate_alert(
    pattern_type: str,
    severity: str,
    source_ip: str,
    description: str,
    evidence: dict = None
) -> dict:
    """
    Generate alert for intrusion pattern.
    Returns alert dict and stores in deque.
    """
    if evidence is None:
        evidence = {}

    alert = {
        "id": len(alerts_deque) + 1,
        "timestamp": datetime.now().isoformat(),
        "pattern": pattern_type,
        "severity": severity,
        "source_ip": source_ip,
        "description": description,
        "evidence": evidence,
        "status": "ACTIVE"
    }

    alerts_deque.appendleft(alert)
    return alert


def analyze_auth_events(events: list, brute_force_ips: list) -> list:
    """
    Analyze auth events for intrusion patterns.
    Returns list of generated alerts.
    """
    generated_alerts = []

    # Brute force detection
    for item in brute_force_ips:
        ip = item["ip"]
        fails = item["fails"]

        alert = generate_alert(
            pattern_type="brute_force",
            severity=SEVERITY_CRITICAL if fails > 10 else SEVERITY_HIGH,
            source_ip=ip,
            description=f"Brute force attack detected: {fails} failed login attempts",
            evidence={
                "failed_attempts": fails,
                "time_window": "Last 24 hours",
                "detected_at": datetime.now().isoformat()
            }
        )
        generated_alerts.append(alert)

    # Distributed attack detection (multiple IPs, same timeframe)
    ip_events = defaultdict(int)
    for event in events:
        if event.get("type") == "FAILED":
            ip = event.get("ip", "unknown")
            if ip not in ("-", "", "::1", "127.0.0.1"):
                ip_events[ip] += 1

    if len(ip_events) > 10:
        alert = generate_alert(
            pattern_type="distributed_attack",
            severity=SEVERITY_HIGH,
            source_ip="MULTIPLE",
            description=f"Distributed attack detected: {len(ip_events)} unique source IPs with failures",
            evidence={
                "source_ips": len(ip_events),
                "total_attempts": len(events),
                "top_sources": list(sorted(ip_events.items(), key=lambda x: x[1], reverse=True)[:3])
            }
        )
        generated_alerts.append(alert)

    return generated_alerts


def analyze_packets(packets: list) -> list:
    """
    Analyze packets for attack patterns.
    Returns list of generated alerts.
    """
    generated_alerts = []

    # SQL injection detection
    sql_threats = [p for p in packets if "UNION SELECT" in str(p.get("threats", []))]
    if len(sql_threats) > 0:
        alert = generate_alert(
            pattern_type="sql_injection",
            severity=SEVERITY_CRITICAL,
            source_ip=sql_threats[0].get("src", "unknown"),
            description=f"SQL injection attempts detected: {len(sql_threats)} suspicious packets",
            evidence={
                "packets": len(sql_threats),
                "threat_type": "SQL Injection",
                "first_detected": sql_threats[0].get("time")
            }
        )
        generated_alerts.append(alert)

    # Port scan detection (many destinations in short time)
    port_scan_threshold = 20
    if len(packets) > port_scan_threshold:
        unique_dests = set(p.get("dst") for p in packets)
        if len(unique_dests) > port_scan_threshold * 0.5:
            src_ip = packets[0].get("src", "unknown")
            alert = generate_alert(
                pattern_type="port_scan",
                severity=SEVERITY_HIGH,
                source_ip=src_ip,
                description=f"Possible port scan detected: {len(unique_dests)} unique destinations",
                evidence={
                    "source_ip": src_ip,
                    "destinations": len(unique_dests),
                    "packets": len(packets)
                }
            )
            generated_alerts.append(alert)

    # Suspicious payload detection
    suspicious_packets = [p for p in packets if p.get("flagged")]
    if len(suspicious_packets) > 5:
        alert = generate_alert(
            pattern_type="suspicious_payload",
            severity=SEVERITY_MEDIUM,
            source_ip=suspicious_packets[0].get("src", "unknown"),
            description=f"Multiple suspicious payloads detected: {len(suspicious_packets)} flagged packets",
            evidence={
                "flagged_packets": len(suspicious_packets),
                "threat_keywords": list(set(
                    t for p in suspicious_packets
                    for t in p.get("threats", [])
                ))[:5]
            }
        )
        generated_alerts.append(alert)

    return generated_alerts


def get_alerts(severity_filter: str = None, limit: int = 100) -> list:
    """Get alerts with optional filtering."""
    alerts = list(alerts_deque)[:limit]

    if severity_filter:
        alerts = [a for a in alerts if a["severity"] == severity_filter]

    return alerts


def get_alert_stats() -> dict:
    """Get alert statistics."""
    alerts = list(alerts_deque)
    if not alerts:
        return {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "last_alert": None
        }

    return {
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a["severity"] == SEVERITY_CRITICAL),
        "high": sum(1 for a in alerts if a["severity"] == SEVERITY_HIGH),
        "medium": sum(1 for a in alerts if a["severity"] == SEVERITY_MEDIUM),
        "low": sum(1 for a in alerts if a["severity"] == SEVERITY_LOW),
        "last_alert": alerts[0]["timestamp"] if alerts else None,
        "pattern_breakdown": dict(
            (a["pattern"], sum(1 for x in alerts if x["pattern"] == a["pattern"]))
            for a in alerts
        )
    }


def acknowledge_alert(alert_id: int) -> bool:
    """Mark alert as acknowledged."""
    for alert in alerts_deque:
        if alert["id"] == alert_id:
            alert["status"] = "ACKNOWLEDGED"
            return True
    return False


def clear_alerts(older_than_hours: int = 24) -> int:
    """Clear old alerts. Returns count cleared."""
    global alerts_deque
    cutoff = datetime.now() - timedelta(hours=older_than_hours)
    initial_count = len(alerts_deque)

    # Create new deque with only recent alerts
    alerts_deque = deque(
        (a for a in alerts_deque if datetime.fromisoformat(a["timestamp"]) > cutoff),
        maxlen=ALERT_STORAGE_LIMIT
    )

    return initial_count - len(alerts_deque)
