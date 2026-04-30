"""
Threat Indicator Extractor — Extract IoCs from raw content.
Complements web_scraper.py by extracting structured indicators.
"""

import re
import json
import os
import time
from datetime import datetime
from collections import defaultdict

# ── CONFIG ─────────────────────────────────────────────────────────────
CACHE_FILE = "extracted_iocs.json"
CACHE_MAX_AGE = 86400  # 24 hours

# ── REGEX PATTERNS ─────────────────────────────────────────────────────
# IPv4
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

# IPv6 (simplified)
IPV6_RE = re.compile(r'(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}', re.I)

# Domain names
DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
    re.I
)

# Email addresses
EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# MD5 hash
MD5_RE = re.compile(r'\b[a-f0-9]{32}\b', re.I)

# SHA1 hash
SHA1_RE = re.compile(r'\b[a-f0-9]{40}\b', re.I)

# SHA256 hash
SHA256_RE = re.compile(r'\b[a-f0-9]{64}\b', re.I)

# URL patterns
URL_RE = re.compile(
    r'https?://(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:[/?#][^\s]*)?',
    re.I
)

# File paths (Windows/Unix)
FILEPATH_RE = re.compile(
    r'(?:[a-zA-Z]:\\|/)[^\s]+?\.(?:exe|dll|sh|ps1|bat|vbs|scr|sys|bin)',
    re.I
)

# Malware family signatures
MALWARE_KEYWORDS = [
    "emotet", "trickbot", "maze", "revil", "darkside", "conti",
    "lockbit", "egregor", "netwalker", "sodinokibi", "ragnarlocker",
    "snake", "babuk", "blackmatter", "blackcat", "alphv",
    "struts2", "log4shell", "zerodart", "spooler",
    "mimikatz", "psexec", "cobalt", "beacon"
]

# Known suspicious domains
SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".su", ".top"]


# ── HELPER FUNCTIONS ───────────────────────────────────────────────────
def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/loopback."""
    return ip.startswith((
        "127.", "0.", "255.", "10.", "192.168.", "172.", "169.254.", "::1"
    )) or ip.endswith(".0")


def _is_valid_domain(domain: str) -> bool:
    """Validate domain (not too short, has valid TLD)."""
    if len(domain) < 5 or len(domain) > 253:
        return False
    if domain.endswith((".local", ".test", ".localhost", ".example")):
        return False
    return True


def _is_suspicious_domain(domain: str) -> bool:
    """Check if domain uses suspicious TLD."""
    return any(domain.lower().endswith(tld) for tld in SUSPICIOUS_TLDS)


def _cache_get():
    """Load cached extractions."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        mtime = os.path.getmtime(CACHE_FILE)
        if time.time() - mtime > CACHE_MAX_AGE:
            return {}
        with open(CACHE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _cache_set(data: dict):
    """Save extractions to cache."""
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass


# ── EXTRACTION FUNCTIONS ──────────────────────────────────────────────
def extract_ipv4(text: str) -> list:
    """Extract and deduplicate IPv4 addresses."""
    found = IPV4_RE.findall(text)
    return sorted(set(ip for ip in found if not _is_private_ip(ip)))


def extract_ipv6(text: str) -> list:
    """Extract IPv6 addresses."""
    found = IPV6_RE.findall(text)
    return sorted(set(found))


def extract_domains(text: str) -> dict:
    """Extract domains with suspicion flags."""
    found = DOMAIN_RE.findall(text)
    clean = {}
    suspicious = {}

    for domain in set(found):
        if not _is_valid_domain(domain):
            continue
        if _is_suspicious_domain(domain):
            suspicious[domain] = "Suspicious TLD"
        else:
            clean[domain] = "Normal"

    return {"clean": clean, "suspicious": suspicious}


def extract_emails(text: str) -> list:
    """Extract email addresses."""
    found = EMAIL_RE.findall(text)
    return sorted(set(found))


def extract_hashes(text: str) -> dict:
    """Extract MD5/SHA1/SHA256 hashes."""
    results = {
        "md5": sorted(set(MD5_RE.findall(text))),
        "sha1": sorted(set(SHA1_RE.findall(text))),
        "sha256": sorted(set(SHA256_RE.findall(text))),
    }
    # Remove duplicates (SHA256 contains SHA1 subset)
    results["sha1"] = [h for h in results["sha1"] if h not in results["sha256"]]
    return results


def extract_urls(text: str) -> list:
    """Extract URLs."""
    found = URL_RE.findall(text)
    return sorted(set(found))


def extract_filepaths(text: str) -> list:
    """Extract suspicious file paths."""
    found = FILEPATH_RE.findall(text)
    return sorted(set(found))


def find_malware_mentions(text: str) -> dict:
    """Find malware family names and count occurrences."""
    text_lower = text.lower()
    findings = {}

    for malware in MALWARE_KEYWORDS:
        count = text_lower.count(malware)
        if count > 0:
            findings[malware] = count

    return dict(sorted(findings.items(), key=lambda x: x[1], reverse=True))


# ── MAIN EXTRACTION ────────────────────────────────────────────────────
def extract(content: str, source_url: str = None) -> dict:
    """Extract all IoCs from content."""
    if not content or not isinstance(content, str):
        return {
            "error": "Invalid content",
            "extracted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source": source_url,
            "stats": {}
        }

    # Normalize
    text = content.strip()

    ipv4_list = extract_ipv4(text)
    ipv6_list = extract_ipv6(text)
    domains = extract_domains(text)
    emails = extract_emails(text)
    hashes = extract_hashes(text)
    urls = extract_urls(text)
    filepaths = extract_filepaths(text)
    malware = find_malware_mentions(text)

    stats = {
        "ipv4_count": len(ipv4_list),
        "ipv6_count": len(ipv6_list),
        "domain_count": len(domains.get("clean", {})) + len(domains.get("suspicious", {})),
        "suspicious_domain_count": len(domains.get("suspicious", {})),
        "email_count": len(emails),
        "hash_count": sum(len(v) for v in hashes.values()),
        "url_count": len(urls),
        "filepath_count": len(filepaths),
        "malware_families": len(malware),
        "threat_level": _calculate_threat_level(ipv4_list, domains, hashes, malware)
    }

    result = {
        "extracted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source_url,
        "error": None,
        "indicators": {
            "ipv4": ipv4_list,
            "ipv6": ipv6_list,
            "domains": domains,
            "emails": emails,
            "hashes": hashes,
            "urls": urls,
            "filepaths": filepaths,
            "malware_families": malware
        },
        "stats": stats
    }

    return result


def _calculate_threat_level(ips: list, domains: dict, hashes: dict, malware: dict) -> str:
    """Calculate overall threat level."""
    score = 0

    if len(ips) >= 5:
        score += 2
    elif len(ips) >= 1:
        score += 1

    if len(domains.get("suspicious", {})) >= 3:
        score += 2
    elif len(domains.get("suspicious", {})) >= 1:
        score += 1

    total_hashes = sum(len(v) for v in hashes.values())
    if total_hashes >= 5:
        score += 2
    elif total_hashes >= 1:
        score += 1

    if len(malware) >= 3:
        score += 2
    elif len(malware) >= 1:
        score += 1

    if score >= 6:
        return "🔴 CRITICAL"
    elif score >= 4:
        return "🟠 HIGH"
    elif score >= 2:
        return "🟡 MEDIUM"
    else:
        return "🟢 LOW"


def extract_from_url(url: str) -> dict:
    """Fetch content from URL and extract IoCs."""
    try:
        import requests
        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; CyberOPS-Extractor/1.0)"
        }
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return extract(resp.text, source_url=url)
    except Exception as e:
        return {
            "error": f"Failed to fetch URL: {str(e)}",
            "source": url,
            "extracted_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": {}
        }


def batch_extract(content_list: list) -> list:
    """Extract from multiple contents."""
    return [extract(content) for content in content_list]


def export_indicators(result: dict, fmt: str = "txt") -> str:
    """Export indicators in various formats."""
    indicators = result.get("indicators", {})

    if fmt == "txt":
        lines = []
        if indicators.get("ipv4"):
            lines.append("=== IPv4 ADDRESSES ===")
            lines.extend(indicators["ipv4"])
        if indicators.get("domains", {}).get("clean"):
            lines.append("\n=== DOMAINS ===")
            lines.extend(indicators["domains"]["clean"].keys())
        if indicators.get("suspicious_domain_count", 0) > 0:
            lines.append("\n=== SUSPICIOUS DOMAINS ===")
            lines.extend(indicators["domains"]["suspicious"].keys())
        if indicators.get("hashes", {}).get("md5"):
            lines.append("\n=== MD5 HASHES ===")
            lines.extend(indicators["hashes"]["md5"])
        if indicators.get("hashes", {}).get("sha256"):
            lines.append("\n=== SHA256 HASHES ===")
            lines.extend(indicators["hashes"]["sha256"])
        if indicators.get("malware_families"):
            lines.append("\n=== MALWARE FAMILIES ===")
            lines.extend(list(indicators["malware_families"].keys()))
        return "\n".join(lines)

    elif fmt == "json":
        return json.dumps(indicators, indent=2, default=str)

    elif fmt == "csv":
        lines = ["Type,Value,Details"]
        for ip in indicators.get("ipv4", []):
            lines.append(f"IPv4,{ip},")
        for domain, reason in indicators.get("domains", {}).get("clean", {}).items():
            lines.append(f"Domain,{domain},{reason}")
        for domain, reason in indicators.get("domains", {}).get("suspicious", {}).items():
            lines.append(f"Suspicious Domain,{domain},{reason}")
        for h in indicators.get("hashes", {}).get("md5", []):
            lines.append(f"MD5,{h},")
        for h in indicators.get("hashes", {}).get("sha256", []):
            lines.append(f"SHA256,{h},")
        return "\n".join(lines)

    return ""
