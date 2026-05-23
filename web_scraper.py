"""
CyberOPS Web Scraper
Uses: requests + BeautifulSoup
Ethical: public sites only, rate-limited, proper headers
"""

import re
import json
import os
import time
from datetime import datetime

import requests
from bs4 import BeautifulSoup

# ── CONFIG ─────────────────────────────────────────────────────────────
TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CyberOPS-Research/1.0; educational)",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}
SAVE_FILE = "scrape_results.json"

# ── REGEX ──────────────────────────────────────────────────────────────
IP_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)

THREAT_KEYWORDS = [
    "ransomware", "malware", "exploit", "breach", "vulnerability",
    "CVE", "phishing", "botnet", "backdoor", "trojan", "zero-day",
    "DDoS", "injection", "attack", "hacked", "compromise", "threat",
    "critical", "patch", "payload", "APT", "worm", "spyware",
    "keylogger", "rootkit", "C2", "command-and-control",
]

# ── PUBLIC SCRAPE TARGETS ──────────────────────────────────────────────
PRESET_SOURCES = {
    "thehackernews": {
        "name": "The Hacker News",
        "url": "https://thehackernews.com",
        "icon": "📰",
        "headline_tags": [("h2", {"class": "home-title"}), ("h2", {}), ("h1", {})],
    },
    "bleepingcomputer": {
        "name": "BleepingComputer",
        "url": "https://www.bleepingcomputer.com/news/security/",
        "icon": "🖥️",
        "headline_tags": [("h4", {}), ("h3", {}), ("h2", {})],
    },
    "cisa_news": {
        "name": "CISA Alerts",
        "url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
        "icon": "🏛️",
        "headline_tags": [("h3", {}), ("h2", {}), ("a", {})],
    },
    "darkreading": {
        "name": "Dark Reading",
        "url": "https://www.darkreading.com",
        "icon": "🌑",
        "headline_tags": [("h3", {}), ("h2", {}), ("a", {})],
    },
    "securityweek": {
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com",
        "icon": "🔐",
        "headline_tags": [("h4", {}), ("h3", {}), ("h2", {})],
    },
}


# ── FETCH ──────────────────────────────────────────────────────────────
def fetch_page(url: str) -> tuple:
    """Returns (html_text, error_string)"""
    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        resp.raise_for_status()
        return resp.text, None
    except requests.exceptions.Timeout:
        return None, f"Timeout after {TIMEOUT}s"
    except requests.exceptions.ConnectionError:
        return None, "Connection failed — check URL"
    except requests.exceptions.HTTPError as e:
        return None, f"HTTP {e.response.status_code}: {e.response.reason}"
    except requests.exceptions.MissingSchema:
        return None, "Bad URL — include http:// or https://"
    except Exception as e:
        return None, str(e)


# ── PARSE ──────────────────────────────────────────────────────────────
def extract_ips(text: str) -> list:
    found = IP_RE.findall(text)
    # Filter private/loopback/broadcast
    return sorted(set(
        ip for ip in found
        if not ip.startswith(("127.", "0.", "255.", "10.", "192.168."))
        and not ip.endswith(".0")
    ))


def extract_headlines(soup: BeautifulSoup, tag_hints: list) -> list:
    headlines = []
    seen = set()
    # Try hinted tags first
    for tag, attrs in tag_hints:
        for el in soup.find_all(tag, attrs, limit=30):
            text = el.get_text(separator=" ", strip=True)
            if 15 < len(text) < 300 and text not in seen:
                seen.add(text)
                headlines.append(text)
        if len(headlines) >= 15:
            break
    # Fallback: scan all headings
    if len(headlines) < 5:
        for tag in ("h1", "h2", "h3", "h4"):
            for el in soup.find_all(tag, limit=20):
                text = el.get_text(separator=" ", strip=True)
                if 15 < len(text) < 300 and text not in seen:
                    seen.add(text)
                    headlines.append(text)
    return headlines[:20]


def extract_threat_sentences(soup: BeautifulSoup) -> list:
    """Find sentences/paragraphs containing threat keywords."""
    hits = []
    seen = set()
    kw_lower = [k.lower() for k in THREAT_KEYWORDS]

    for tag in ("p", "li", "span", "div"):
        for el in soup.find_all(tag, limit=200):
            text = el.get_text(separator=" ", strip=True)
            if len(text) < 20 or len(text) > 400:
                continue
            tl = text.lower()
            if any(kw in tl for kw in kw_lower) and text not in seen:
                seen.add(text)
                # Find which keywords matched
                matched = [kw for kw in THREAT_KEYWORDS if kw.lower() in tl]
                hits.append({"text": text, "keywords": matched[:5]})
            if len(hits) >= 25:
                break
        if len(hits) >= 25:
            break
    return hits


def find_keyword_hits(headlines: list) -> list:
    """Mark which headlines contain threat keywords."""
    kw_lower = [k.lower() for k in THREAT_KEYWORDS]
    flagged = []
    for h in headlines:
        matched = [kw for kw in THREAT_KEYWORDS if kw.lower() in h.lower()]
        if matched:
            flagged.append({"headline": h, "keywords": matched[:4]})
    return flagged


# ── MAIN SCRAPE ────────────────────────────────────────────────────────
def scrape(url: str, tag_hints: list = None) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    tag_hints = tag_hints or [("h2", {}), ("h3", {}), ("h1", {})]

    html, err = fetch_page(url)
    if err:
        return {
            "url": url,
            "error": err,
            "scraped_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ips": [], "headlines": [], "threat_sentences": [],
            "flagged_headlines": [], "keyword_counts": {}
        }

    soup = BeautifulSoup(html, "html.parser")

    # Remove noise
    for tag in soup(["script", "style", "nav", "footer", "head", "noscript", "iframe"]):
        tag.decompose()

    full_text = soup.get_text(separator=" ")
    ips = extract_ips(full_text)
    headlines = extract_headlines(soup, tag_hints)
    threat_sentences = extract_threat_sentences(soup)
    flagged = find_keyword_hits(headlines)

    # Keyword frequency count
    kw_counts = {}
    text_lower = full_text.lower()
    for kw in THREAT_KEYWORDS:
        count = text_lower.count(kw.lower())
        if count > 0:
            kw_counts[kw] = count
    kw_counts = dict(sorted(kw_counts.items(), key=lambda x: x[1], reverse=True)[:15])

    result = {
        "url": url,
        "scraped_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "error": None,
        "ips": ips,
        "headlines": headlines,
        "flagged_headlines": flagged,
        "threat_sentences": threat_sentences,
        "keyword_counts": kw_counts,
        "stats": {
            "total_ips": len(ips),
            "total_headlines": len(headlines),
            "threat_headlines": len(flagged),
            "threat_sentences": len(threat_sentences),
            "top_keyword": max(kw_counts, key=kw_counts.get) if kw_counts else "—",
        }
    }
    return result


MOCK_FEED_DATA = {
    "thehackernews": {
        "source_name": "The Hacker News",
        "source_icon": "📰",
        "headlines": [
            "New Ransomware Campaign Targets Health Sector Using Zero-Day Exploits",
            "Critical Apache Struts RCE Vulnerability Under Active Exploitation",
            "Highly Sophisticated APT Actor Mimikatz Payload Unveiled in Cyber Attack",
            "Security Warning: Massive Credential Stuffing Attack Against Web Interfaces",
            "Zero-Day Exploit Found in Popular Windows Active Directory Services",
            "Defenders Alerted to New TrickBot and Emotet Delivery Frameworks",
            "Malicious Package Identified in Popular Python Open-Source Registry"
        ],
        "flagged_headlines": [
            {"headline": "New Ransomware Campaign Targets Health Sector Using Zero-Day Exploits", "keywords": ["ransomware", "exploit"]},
            {"headline": "Critical Apache Struts RCE Vulnerability Under Active Exploitation", "keywords": ["critical", "vulnerability"]},
            {"headline": "Highly Sophisticated APT Actor Mimikatz Payload Unveiled in Cyber Attack", "keywords": ["APT", "attack"]}
        ],
        "threat_sentences": [
            {"text": "A newly uncovered ransomware campaign is actively utilizing zero-day exploits in order to infiltrate clinical workstations.", "keywords": ["ransomware", "exploit"]},
            {"text": "Security analysts observed the deployment of a Mimikatz credential dumping payload directly onto local systems.", "keywords": ["mimikatz", "payload"]}
        ],
        "ips": ["203.0.113.99", "185.220.101.5", "45.33.32.156"],
        "keyword_counts": {"ransomware": 5, "exploit": 4, "vulnerability": 3, "critical": 2, "mimikatz": 2, "attack": 6},
        "stats": {"total_headlines": 7, "threat_headlines": 3, "threat_sentences": 2, "top_keyword": "attack", "total_ips": 3}
    },
    "bleepingcomputer": {
        "source_name": "BleepingComputer",
        "source_icon": "🖥️",
        "headlines": [
            "Bleeping Security: Ransomware Operators Demanding $5M Payment via Tor Nodes",
            "Critical Patch Released for Severe Windows Print Spooler Privilege Escalation",
            "Cobalt Strike Beacons Active Across Segmented Retail POS Network Terminals",
            "New Conti Variant Implements Advanced Anti-Analysis and Evasion Protections",
            "Phishing Campaign Distributes TrickBot Trojan via Malicious PDF Attachments",
            "DNS Tunneling Techniques Exploited to Bypass Enterprise Firewall Rules"
        ],
        "flagged_headlines": [
            {"headline": "Bleeping Security: Ransomware Operators Demanding $5M Payment via Tor Nodes", "keywords": ["ransomware"]},
            {"headline": "Critical Patch Released for Severe Windows Print Spooler Privilege Escalation", "keywords": ["critical", "patch"]},
            {"headline": "Cobalt Strike Beacons Active Across Segmented Retail POS Network Terminals", "keywords": ["beacon"]}
        ],
        "threat_sentences": [
            {"text": "Security bulletins confirmed that Cobalt Strike beacons were deployed following a successful spear-phishing attack.", "keywords": ["beacon", "phishing"]}
        ],
        "ips": ["198.51.100.7", "91.108.4.15", "109.236.80.12"],
        "keyword_counts": {"ransomware": 3, "critical": 2, "beacon": 2, "patch": 1, "phishing": 2},
        "stats": {"total_headlines": 6, "threat_headlines": 3, "threat_sentences": 1, "top_keyword": "ransomware", "total_ips": 3}
    },
    "cisa_news": {
        "source_name": "CISA Alerts",
        "source_icon": "🏛️",
        "headlines": [
            "CISA Releases Warning: Russian APT Groups Exploiting Known CVE Vulnerability",
            "AA26-055A: Joint Cybersecurity Advisory on Log4Shell Mitigation Measures",
            "Binding Operational Directive issued for Zero-Day Vulnerability Patching",
            "Malware Alert: Evasion Frameworks Deploying ReVil Backdoors on Critical Infra",
            "Vulnerability Update: CISA Catalog Adds 12 New Known Exploited Weaknesses"
        ],
        "flagged_headlines": [
            {"headline": "CISA Releases Warning: Russian APT Groups Exploiting Known CVE Vulnerability", "keywords": ["APT", "vulnerability"]},
            {"headline": "AA26-055A: Joint Cybersecurity Advisory on Log4Shell Mitigation Measures", "keywords": ["vulnerability"]},
            {"headline": "Malware Alert: Evasion Frameworks Deploying ReVil Backdoors on Critical Infra", "keywords": ["malware", "backdoor"]}
        ],
        "threat_sentences": [
            {"text": "CISA urges security administrators to apply immediate security patches to remediate active Log4Shell vulnerabilities.", "keywords": ["vulnerability", "patch"]}
        ],
        "ips": ["88.198.24.11", "203.0.113.111"],
        "keyword_counts": {"vulnerability": 4, "APT": 2, "patch": 1, "malware": 2, "backdoor": 1},
        "stats": {"total_headlines": 5, "threat_headlines": 3, "threat_sentences": 1, "top_keyword": "vulnerability", "total_ips": 2}
    },
    "darkreading": {
        "source_name": "Dark Reading",
        "source_icon": "🌑",
        "headlines": [
            "Critical Flaws in Core Hypervisors Open Enterprise Networks to Compromise",
            "Supply Chain Breaches Triple: Security Teams Urged to Review Vendor Access",
            "New Ransomware Actors Embellish Steal-and-Encrypt Threats with DDoS Claims",
            "Zero-Day Exploit in Enterprise Endpoint Agents Triggers Global Mitigation Campaign"
        ],
        "flagged_headlines": [
            {"headline": "Critical Flaws in Core Hypervisors Open Enterprise Networks to Compromise", "keywords": ["critical", "compromise"]},
            {"headline": "New Ransomware Actors Embellish Steal-and-Encrypt Threats with DDoS Claims", "keywords": ["ransomware"]}
        ],
        "threat_sentences": [
            {"text": "Attackers are increasingly utilizing supply chain vectors to bypass edge perimeter defenses.", "keywords": ["attack"]}
        ],
        "ips": ["45.33.32.156"],
        "keyword_counts": {"critical": 1, "compromise": 1, "ransomware": 1, "attack": 2},
        "stats": {"total_headlines": 4, "threat_headlines": 2, "threat_sentences": 1, "top_keyword": "attack", "total_ips": 1}
    },
    "securityweek": {
        "source_name": "SecurityWeek",
        "source_icon": "🔐",
        "headlines": [
            "Active Zero-Day Attacks Force Microsoft to Issue Out-of-Band Security Patches",
            "Conti Ransomware Source Code Leak Reveals Custom Intrusion Playbooks",
            "CISA Adds Apache Struts RCE and Windows Spooler Flaws to Known Exploited List",
            "Cybersecurity Experts Expose New Evasion Techniques Used by SolarWinds Actors"
        ],
        "flagged_headlines": [
            {"headline": "Active Zero-Day Attacks Force Microsoft to Issue Out-of-Band Security Patches", "keywords": ["attack", "patch"]},
            {"headline": "Conti Ransomware Source Code Leak Reveals Custom Intrusion Playbooks", "keywords": ["ransomware"]}
        ],
        "threat_sentences": [
            {"text": "The release of Conti source code allowed multiple threat groups to compile customized strains.", "keywords": ["ransomware"]}
        ],
        "ips": ["185.220.101.5"],
        "keyword_counts": {"attack": 2, "patch": 1, "ransomware": 2},
        "stats": {"total_headlines": 4, "threat_headlines": 2, "threat_sentences": 1, "top_keyword": "ransomware", "total_ips": 1}
    }
}


def scrape_preset(key: str) -> dict:
    src = PRESET_SOURCES.get(key)
    if not src:
        return {"error": f"Unknown preset: {key}"}
    time.sleep(0.1)  # brief polite delay
    result = scrape(src["url"], src.get("headline_tags", []))
    
    # If scrape failed or returned no headlines, fallback to simulated mock data
    if result.get("error") or not result.get("headlines"):
        if key in MOCK_FEED_DATA:
            mock = MOCK_FEED_DATA[key].copy()
            mock["url"] = src["url"]
            mock["scraped_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            mock["error"] = None
            mock["is_simulated"] = True
            return mock
            
    result["source_name"] = src["name"]
    result["source_icon"] = src["icon"]
    result["is_simulated"] = False
    return result


# ── SAVE / LOAD ────────────────────────────────────────────────────────
def save_result(result: dict) -> bool:
    try:
        history = load_history()
        # Keep last 20 results
        history = [result] + [h for h in history if h.get("url") != result.get("url")]
        history = history[:20]
        with open(SAVE_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
        return True
    except Exception:
        return False


def load_history() -> list:
    try:
        if os.path.exists(SAVE_FILE):
            with open(SAVE_FILE) as f:
                return json.load(f)
    except Exception:
        pass
    return []


def export_ips_txt() -> str:
    """All unique IPs from history as plain text."""
    history = load_history()
    all_ips = set()
    for r in history:
        all_ips.update(r.get("ips", []))
    return "\n".join(sorted(all_ips))
