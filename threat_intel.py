"""
Real Threat Intelligence.
Uses AbuseIPDB free API (1000 checks/day free).
Get free key: https://www.abuseipdb.com/register
"""

import urllib.request
import urllib.parse
import json
import os
import time
from datetime import datetime

# ── CONFIG ─────────────────────────────────────────────────────────────
# Set your key here OR set environment variable ABUSEIPDB_KEY
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_KEY", "YOUR_API_KEY_HERE")
API_URL = "https://api.abuseipdb.com/api/v2/check"

# Fallback hardcoded known-bad list (always active even without API)
LOCAL_BLACKLIST = {
    "192.168.1.10": "Internal brute-force source",
    "10.0.0.55": "Repeated auth failures",
    "203.0.113.99": "Known scanner",
    "45.33.32.156": "Shodan scanner",
    "198.51.100.7": "Test malicious IP",
    "185.220.101.0": "Tor exit node",
    "91.108.4.0": "Known botnet C2",
}

# Simple in-memory cache — avoid hammering API
_cache = {}
CACHE_TTL = 3600  # 1 hour


def _cache_get(ip):
    entry = _cache.get(ip)
    if entry and (time.time() - entry["ts"]) < CACHE_TTL:
        return entry["data"]
    return None


def _cache_set(ip, data):
    _cache[ip] = {"ts": time.time(), "data": data}


def check_ip_abuseipdb(ip: str) -> dict:
    """Check single IP against AbuseIPDB."""
    if ABUSEIPDB_KEY == "YOUR_API_KEY_HERE":
        return {"api": False, "reason": "No API key set"}

    cached = _cache_get(ip)
    if cached:
        return cached

    try:
        params = urllib.parse.urlencode({
            "ipAddress": ip,
            "maxAgeInDays": "90",
            "verbose": ""
        })
        url = f"{API_URL}?{params}"
        req = urllib.request.Request(url)
        req.add_header("Key", ABUSEIPDB_KEY)
        req.add_header("Accept", "application/json")

        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = json.loads(resp.read().decode())
            d = raw.get("data", {})
            result = {
                "api": True,
                "ip": ip,
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", "??"),
                "isp": d.get("isp", "Unknown"),
                "domain": d.get("domain", ""),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", "Never"),
                "is_tor": d.get("isTor", False),
                "is_malicious": d.get("abuseConfidenceScore", 0) >= 25
            }
            _cache_set(ip, result)
            return result
    except Exception as e:
        return {"api": False, "reason": str(e)}


def check_local_blacklist(ip: str) -> dict:
    if ip in LOCAL_BLACKLIST:
        return {"local_hit": True, "reason": LOCAL_BLACKLIST[ip]}
    return {"local_hit": False}


def check_ip_full(ip: str) -> dict:
    """Full check: local blacklist + AbuseIPDB."""
    local = check_local_blacklist(ip)
    api_result = check_ip_abuseipdb(ip)
    is_bad = local["local_hit"] or api_result.get("is_malicious", False)
    return {
        "ip": ip,
        "is_malicious": is_bad,
        "local": local,
        "api": api_result,
        "verdict": "🔴 MALICIOUS" if is_bad else "🟢 CLEAN"
    }


def bulk_check(ip_list: list) -> list:
    results = []
    for ip in ip_list:
        if ip and ip not in ("-", "::1", "127.0.0.1", "0.0.0.0"):
            results.append(check_ip_full(ip))
        time.sleep(0.1)  # rate-limit courtesy
    return results


def get_local_blacklist():
    return LOCAL_BLACKLIST
