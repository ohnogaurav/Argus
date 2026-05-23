"""
Argus — Advanced Security Operations & Network Telemetry Console
"""

import os
from flask import Flask, render_template, request, jsonify, redirect, make_response
from auth_manager import require_login, login_user, create_user

app = Flask(__name__)

# --- GLOBAL TEMPLATE VARIABLES ---
def is_simulation_mode():
    """Check if the system is running in simulated mode due to missing system/OS privileges."""
    from log_scanner import WIN32_OK
    from packet_capture import SCAPY_OK
    return not (WIN32_OK and SCAPY_OK)

@app.context_processor
def inject_global_vars():
    """Inject current session user and system simulation mode status to all templates."""
    from auth_manager import get_current_user
    user = get_current_user(request)
    return {
        "current_user": user,
        "is_simulation": is_simulation_mode()
    }

# --- ROUTES ---

@app.route("/")
def landing():
    return render_template("landing.html", active="landing", title="WELCOME")


@app.route("/guide")
def guide():
    return render_template("guide.html", active="guide", title="USER GUIDE")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    fail_data = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr
        result = login_user(username, password, ip=ip)
        
        if result["success"]:
            next_page = request.args.get("redirect", "/dashboard")
            resp_obj = make_response(redirect(next_page))
            resp_obj.set_cookie("session_token", result["token"], max_age=3600, httponly=True)
            return resp_obj
        else:
            error = result.get("error", "Login failed")
            if "count" in result:
                fail_data = {"user": username, "count": result["count"], "msg": error}
                # Integrate threat event generation
                from intrusion_monitor import generate_alert
                generate_alert(
                    pattern_type="auth_failure",
                    severity="HIGH" if result["count"] >= 3 else "MEDIUM",
                    source_ip=ip,
                    description=f"Failed credential authentication attempt for user: {username} (Attempt {result['count']})",
                    evidence={"user": username, "attempt": result["count"]}
                )
    
    return render_template("login.html", active="login", title="LOGIN", error=error, fail_data=fail_data)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = False
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        from password_auditor import audit_password_pair
        pwd_audit = audit_password_pair(password, password2)
        
        if not pwd_audit["match"]:
            error = "Passwords do not match"
        elif pwd_audit["verdict"] == "FAIL":
            error = "Password does not meet policy requirements. " + (pwd_audit["issues"][0] if pwd_audit["issues"] else "")
        else:
            result = create_user(username, password)
            if result["success"]:
                success = True
            else:
                error = result.get("error", "Registration failed")

    return render_template("register.html", active="login", title="REGISTER", error=error, success=success)


@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session_token")
    return resp


@app.route("/tools")
@require_login
def tools(user):
    return render_template("tools.html", active="tools", title="TOOLS")


@app.route("/dashboard")
@require_login
def dashboard(user):
    from log_scanner import read_windows_auth_log
    from packet_capture import get_packets
    from visualizer import generate_dashboard_data
    from intrusion_monitor import get_alert_stats

    log_data = read_windows_auth_log(hours_back=24)
    log_data["alert_stats"] = get_alert_stats()
    packets = get_packets(limit=500)
    packet_data = {"packets": packets}

    data = generate_dashboard_data(log_data, packet_data, [])
    return render_template("dashboard.html", active="dashboard", title="DASHBOARD", data=data)


@app.route("/log")
@require_login
def log(user):
    from log_scanner import read_windows_auth_log
    d = read_windows_auth_log(hours_back=24)
    return render_template("log.html",
        active="tools", title="AUTH LOG",
        error=d.get("error"),
        brute_force=d.get("brute_force", []),
        events=d.get("events", []),
        bf_count=len(d.get("brute_force", [])),
        si_count=len(d.get("suspicious_ips", [])),
        ev_count=d.get("total_scanned", 0)
    )


@app.route("/scan")
@require_login
def scan(user):
    from log_scanner import scan_ports_real, quick_scan_common
    host = request.args.get("host", "")
    mode = request.args.get("mode", "common")
    result = None
    if host:
        if mode == "common":
            result = quick_scan_common(host)
        elif mode == "range":
            result = scan_ports_real(host, port_range=(1, 1024))
        else:
            result = scan_ports_real(host, port_range=(1, 65535), max_workers=200)
    return render_template("scan.html", active="tools", title="PORT SCAN", host=host, mode=mode, result=result)


@app.route("/packet")
@require_login
def packet(user):
    from packet_capture import get_packets, get_interfaces, get_status
    status = get_status()
    pkts = get_packets(limit=80)
    return render_template("packet.html",
        active="tools", title="PACKETS",
        scapy_ok=status["scapy_ok"],
        interfaces=get_interfaces(),
        packets=pkts,
        total=status["total"],
        flagged=status["flagged"],
        running=status["running"]
    )


@app.route("/packet/start", methods=["POST"])
@require_login
def packet_start(user):
    from packet_capture import start_capture
    data = request.get_json() or {}
    ok, msg = start_capture(iface=data.get("iface"), duration=data.get("duration", 30))
    return jsonify({"ok": ok, "message": msg})


@app.route("/packet/stop", methods=["POST"])
@require_login
def packet_stop(user):
    from packet_capture import stop_capture
    stop_capture()
    return jsonify({"ok": True})


@app.route("/packet/data")
@require_login
def packet_data(user):
    from packet_capture import get_packets, get_status
    flagged_only = request.args.get("flagged_only") == "1"
    status = get_status()
    pkts = get_packets(limit=80, flagged_only=flagged_only)
    return jsonify({
        "packets": pkts,
        "total": status["total"],
        "flagged": status["flagged"],
        "running": status["running"]
    })


@app.route("/threat")
@require_login
def threat(user):
    from threat_intel import check_ip_full, get_local_blacklist
    query_ip = request.args.get("ip", "")
    result = None
    if query_ip:
        result = check_ip_full(query_ip.strip())
    return render_template("threat.html",
        active="tools", title="THREAT INTEL",
        query_ip=query_ip,
        result=result,
        blacklist=get_local_blacklist()
    )


@app.route("/extract", methods=["GET", "POST"])
@require_login
def extract(user):
    from threat_extractor import extract as extract_data, extract_from_url
    result = None
    if request.method == "POST":
        mode = request.form.get("mode", "text")
        content = request.form.get("content", "").strip()
        if content:
            if mode == "url":
                result = extract_from_url(content)
            else:
                result = extract_data(content)
    return render_template("extract.html", active="tools", title="IOC EXTRACT", result=result)


@app.route("/scan-url", methods=["GET", "POST"])
@require_login
def scan_url(user):
    from web_fetcher import fetch_and_clean
    from threat_extractor import extract as extract_data
    url = request.form.get("url", "") if request.method == "POST" else request.args.get("url", "")
    url = url.strip() if url else ""
    result = None
    if url:
        fetch_result = fetch_and_clean(url)
        if fetch_result.get("error"):
            result = {"error": fetch_result["error"], "url": url}
        else:
            content = fetch_result.get("content", "")
            result = extract_data(content, source_url=url)
    return render_template("scan_url.html", active="tools", title="SCAN URL", url=url, result=result)


@app.route("/audit-pwd", methods=["GET", "POST"])
@require_login
def audit_pwd(user):
    from password_auditor import audit_password
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password:
            result = audit_password(password)
    return render_template("audit_pwd.html", active="tools", title="PWD AUDIT", result=result)


@app.route("/alerts")
@require_login
def alerts(user):
    from intrusion_monitor import get_alerts, get_alert_stats, analyze_auth_events, analyze_packets
    from log_scanner import read_windows_auth_log
    from packet_capture import get_packets

    log_data = read_windows_auth_log(hours_back=24)
    packets = get_packets(limit=200)

    # Trigger threat detection on current states
    analyze_auth_events(
        log_data.get("events", []),
        log_data.get("brute_force", [])
    )
    analyze_packets(packets)

    alerts_list = get_alerts(limit=100)
    stats = get_alert_stats()

    return render_template("alerts.html", active="alerts", title="ALERTS", alerts=alerts_list, stats=stats)


@app.route("/alerts/data")
@require_login
def alerts_data(user):
    from intrusion_monitor import get_alerts, get_alert_stats
    alerts_list = get_alerts(limit=50)
    stats = get_alert_stats()
    return jsonify({
        "alerts": alerts_list,
        "stats": stats
    })


@app.route("/feed")
@require_login
def feed(user):
    from web_scraper import PRESET_SOURCES, scrape_preset
    source_key = request.args.get("source", "thehackernews")
    
    if source_key not in PRESET_SOURCES:
        source_key = "thehackernews"
        
    feed_data = scrape_preset(source_key)
    return render_template("feed.html",
        active="tools", title="THREAT FEED",
        sources=PRESET_SOURCES,
        active_source=source_key,
        feed_data=feed_data
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7860))
    print("\n" + "="*55)
    print("  ARGUS — Security Intelligence Console")
    print(f"  http://127.0.0.1:{port}")
    print("="*55 + "\n")
    app.run(debug=False, host="0.0.0.0", port=port)
