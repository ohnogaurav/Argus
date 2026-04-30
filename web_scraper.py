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


def scrape_preset(key: str) -> dict:
    src = PRESET_SOURCES.get(key)
    if not src:
        return {"error": f"Unknown preset: {key}"}
    time.sleep(0.5)  # polite delay
    result = scrape(src["url"], src.get("headline_tags", []))
    result["source_name"] = src["name"]
    result["source_icon"] = src["icon"]
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
