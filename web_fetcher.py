"""
Web Fetcher — Clean webpage content extraction.
Fetches URL, removes scripts/styles, returns plain text for threat extraction.
"""

import requests
from bs4 import BeautifulSoup

# ── CONFIG ─────────────────────────────────────────────────────────────
TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; CyberOPS-Fetcher/1.0; educational)",
    "Accept": "text/html,application/xhtml+xml,*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


# ── FETCH ──────────────────────────────────────────────────────────────
def fetch_url(url: str) -> dict:
    """Fetch webpage and return status."""
    if not url:
        return {"error": "URL cannot be empty"}

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        resp = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        resp.raise_for_status()
        return {"html": resp.text, "url": url, "error": None}
    except requests.exceptions.Timeout:
        return {"error": f"Timeout after {TIMEOUT}s", "url": url}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection failed — check URL", "url": url}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTP {e.response.status_code}: {e.response.reason}", "url": url}
    except requests.exceptions.MissingSchema:
        return {"error": "Bad URL — include http:// or https://", "url": url}
    except Exception as e:
        return {"error": str(e), "url": url}


# ── PARSE ──────────────────────────────────────────────────────────────
def clean_content(html: str) -> str:
    """Parse HTML and extract clean text (remove scripts/styles)."""
    try:
        soup = BeautifulSoup(html, "html.parser")

        # Remove noise
        for tag in soup(["script", "style", "nav", "footer", "head", "noscript", "iframe", "meta"]):
            tag.decompose()

        text = soup.get_text(separator=" ", strip=True)
        # Collapse multiple spaces
        text = " ".join(text.split())
        return text
    except Exception:
        return ""


# ── MAIN FETCH + CLEAN ─────────────────────────────────────────────────
def fetch_and_clean(url: str) -> dict:
    """Fetch URL and return cleaned text for extraction."""
    fetch_result = fetch_url(url)

    if fetch_result.get("error"):
        return {
            "error": fetch_result["error"],
            "url": url,
            "content": None
        }

    html = fetch_result.get("html", "")
    content = clean_content(html)

    if not content:
        return {
            "error": "No text content found in page",
            "url": url,
            "content": None
        }

    return {
        "error": None,
        "url": url,
        "content": content
    }
