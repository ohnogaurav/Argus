"""
CyberOPS Visualization Module.
Generates charts and dashboard data from existing system events.
Reuses data from log_scanner, packet_capture, threat_intel.
Uses Plotly for interactive charts.
"""

import json
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List

# Try to import plotly
try:
    import plotly.graph_objects as go
    import plotly.express as px
    PLOTLY_OK = True
except ImportError:
    PLOTLY_OK = False

# ── PLOTLY CHART GENERATORS ────────────────────────────────────────────

def generate_auth_timeline_chart(events: list) -> str:
    """Generate Plotly auth timeline chart as HTML."""
    if not PLOTLY_OK:
        return "<div>Plotly not installed</div>"
    
    timeline = defaultdict(lambda: {"failed": 0, "success": 0})
    for event in events:
        hour = event["time"][:13] + ":00"
        if event["type"] == "FAILED":
            timeline[hour]["failed"] += 1
        else:
            timeline[hour]["success"] += 1
    
    labels = sorted(timeline.keys())
    failed = [timeline[h]["failed"] for h in labels]
    success = [timeline[h]["success"] for h in labels]
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=labels, y=failed, mode='lines+markers', name='Failed', 
                             line=dict(color='#f43f5e', width=3)))
    fig.add_trace(go.Scatter(x=labels, y=success, mode='lines+markers', name='Success',
                             line=dict(color='#10b981', width=3)))
    
    fig.update_layout(
        title="Authentication Events Timeline",
        xaxis_title="Time", yaxis_title="Count",
        hovermode='x unified',
        template="plotly_dark",
        plot_bgcolor='#0f172a',
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        margin=dict(l=40, r=20, t=40, b=40)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_auth")


def generate_top_ips_chart_html(ip_fails: dict) -> str:
    """Generate Plotly top attacking IPs chart as HTML."""
    if not PLOTLY_OK:
        return "<div>Plotly not installed</div>"
    
    sorted_ips = sorted(ip_fails.items(), key=lambda x: x[1], reverse=True)[:10]
    ips = [ip for ip, _ in sorted_ips]
    counts = [cnt for _, cnt in sorted_ips]
    
    # Reverse order for horizontal bar chart
    ips.reverse()
    counts.reverse()
    
    fig = go.Figure(data=[
        go.Bar(x=counts, y=ips, orientation='h', 
               marker=dict(color=counts, colorscale='Reds', showscale=False))
    ])
    
    fig.update_layout(
        title="Top Flagged IP Addresses",
        xaxis_title="Failed Attempts",
        yaxis_title="IP Address",
        template="plotly_dark",
        plot_bgcolor='#0f172a',
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        margin=dict(l=100, r=20, t=40, b=40)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_ips")


def generate_protocol_distribution_chart_html(packets: list) -> str:
    """Generate Plotly protocol distribution chart."""
    if not PLOTLY_OK:
        return "<div>Plotly not installed</div>"
    
    proto_count = Counter(p.get("proto", "OTHER") for p in packets)
    
    fig = go.Figure(data=[
        go.Pie(labels=list(proto_count.keys()), values=list(proto_count.values()),
               hole=.4,
               marker=dict(colors=['#00f2fe', '#f43f5e', '#fb923c', '#10b981']))
    ])
    
    fig.update_layout(
        title="Sniffed Protocol Distribution",
        template="plotly_dark",
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_proto")


def generate_security_score_trend_chart_html(history: list) -> str:
    """Generate Security Score trend over time."""
    if not PLOTLY_OK or not history:
        return "<div>No historical data</div>"
    
    times = [h["ts"] for h in history]
    scores = [h["score"] for h in history]
    
    fig = go.Figure(data=[
        go.Scatter(x=times, y=scores, mode='lines+markers',
                   line=dict(color='#00f2fe', width=3),
                   fill='tozeroy', fillcolor='rgba(0, 242, 254, 0.1)')
    ])
    
    fig.update_layout(
        title="Security Score Trend",
        xaxis_title="Time", yaxis_title="Score",
        template="plotly_dark",
        plot_bgcolor='#0f172a',
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        yaxis=dict(range=[0, 105]),
        margin=dict(l=40, r=20, t=40, b=40)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_score_trend")


def generate_threat_timeline_chart(packets: list) -> str:
    """Generate Plotly threat detection timeline."""
    if not PLOTLY_OK:
        return "<div>Plotly not installed</div>"
    
    flagged = [p for p in packets if p.get("flagged")]
    if not flagged:
        return "<div style='text-align:center;padding:100px 0;color:var(--text-dark);font-family:var(--font-mono);font-size:0.8rem;'>NO TELEMETRY THREATS LOGGED</div>"
    
    # Sort packets chronologically for timeline
    flagged_sorted = sorted(flagged, key=lambda x: x.get("time", ""))
    times = [p.get("time", "unknown") for p in flagged_sorted]
    threat_counts = [len(p.get("threats", [])) for p in flagged_sorted]
    
    fig = go.Figure(data=[
        go.Scatter(x=times, y=threat_counts, mode='markers+lines',
                   marker=dict(size=8, color='#f43f5e', symbol='diamond'),
                   line=dict(color='#f43f5e', width=1.5))
    ])
    
    fig.update_layout(
        title="Threat Flags Timeline",
        xaxis_title="Time",
        yaxis_title="Threat Count",
        template="plotly_dark",
        plot_bgcolor='#0f172a',
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        margin=dict(l=40, r=20, t=40, b=40)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_threat_time")


def generate_alert_severity_chart(alert_stats: dict) -> str:
    """Generate Plotly alert severity distribution."""
    if not PLOTLY_OK:
        return "<div>Plotly not installed</div>"
    
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    counts = [alert_stats.get(s.lower(), 0) for s in severities]
    
    # If no alerts, show empty chart message
    if sum(counts) == 0:
        return "<div style='text-align:center;padding:100px 0;color:var(--text-dark);font-family:var(--font-mono);font-size:0.8rem;'>NO INTRUSION ALERTS GENERATED</div>"

    colors = ['#f43f5e', '#fb923c', '#3b82f6', '#10b981']
    
    fig = go.Figure(data=[
        go.Pie(labels=severities, values=counts, marker=dict(colors=colors), hole=.4)
    ])
    
    fig.update_layout(
        title="Alert Severity Distribution",
        template="plotly_dark",
        paper_bgcolor='#030712',
        font=dict(color='#e2e8f0', family="Inter"),
        height=320,
        margin=dict(l=20, r=20, t=40, b=20)
    )
    return fig.to_html(include_plotlyjs=False, div_id="chart_alert_sev")


# ── CHART DATA GENERATORS ──────────────────────────────────────────────

def generate_auth_timeline(events: list) -> dict:
    """Generate timeline data (for non-plotly fallback)."""
    timeline = defaultdict(lambda: {"failed": 0, "success": 0})
    for event in events:
        try:
            # Handle different time formats
            ts = event["time"]
            hour = ts[:13] + ":00"
            if event["type"] == "FAILED":
                timeline[hour]["failed"] += 1
            else:
                timeline[hour]["success"] += 1
        except: continue
    
    labels = sorted(timeline.keys())
    return {
        "labels": labels,
        "failed": [timeline[hour]["failed"] for hour in labels],
        "success": [timeline[hour]["success"] for hour in labels]
    }


def generate_top_ips_data(ip_fails: dict) -> dict:
    """Generate top attacking IPs data."""
    sorted_ips = sorted(ip_fails.items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        "labels": [ip for ip, _ in sorted_ips],
        "values": [cnt for _, cnt in sorted_ips]
    }


def generate_protocol_distribution_data(packets: list) -> dict:
    """Generate protocol distribution data."""
    proto_count = Counter(p.get("proto", "OTHER") for p in packets)
    return {
        "labels": list(proto_count.keys()),
        "values": list(proto_count.values())
    }


def generate_security_score_gauge(log_data: dict, packet_data: dict) -> dict:
    """Generate security score gauge data."""
    score = 100
    bf_ips = len(log_data.get("brute_force", []))
    flagged = sum(1 for p in packet_data.get("packets", []) if p.get("flagged"))
    
    score -= min(40, bf_ips * 8)
    score -= min(30, flagged * 2)
    
    level = "SECURE"
    if score < 40: level = "CRITICAL"
    elif score < 60: level = "RISKY"
    elif score < 85: level = "FAIR"
    
    return {
        "score": max(0, score),
        "level": level,
        "threats": bf_ips,
        "flagged": flagged
    }


# ── DASHBOARD AGGREGATOR ──────────────────────────────────────────────

def generate_dashboard_data(log_data: dict, packet_data: dict, scan_history: list = None) -> dict:
    """Aggregate all metrics for dashboard."""
    packets = packet_data.get("packets", [])
    events = log_data.get("events", [])
    
    # Generate Plotly HTML components
    charts = {
        "auth_timeline": generate_auth_timeline_chart(events),
        "top_ips": generate_top_ips_chart_html(log_data.get("ip_fails", {})),
        "protocol_dist": generate_protocol_distribution_chart_html(packets),
        "threat_timeline": generate_threat_timeline_chart(packets),
        "alert_severity": generate_alert_severity_chart(log_data.get("alert_stats", {})) # Pass dummy/real alert stats
    }
    
    gauge = generate_security_score_gauge(log_data, packet_data)
    
    return {
        "charts": charts,
        "gauge": gauge,
        "stats": {
            "total_events": len(events),
            "threats": gauge["threats"],
            "flagged": gauge["flagged"],
            "packets": len(packets)
        },
        "top_ips_table": generate_top_ips_data(log_data.get("ip_fails", {})),
        "protocol_dist_table": generate_protocol_distribution_data(packets)
    }
