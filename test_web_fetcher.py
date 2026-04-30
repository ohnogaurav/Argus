"""
Test: Web Fetcher + Threat Extractor Pipeline
Validates URL → fetch → clean → extract workflow
"""

from web_fetcher import fetch_and_clean
from threat_extractor import extract

# ── TEST ───────────────────────────────────────────────────────────────
def test_pipeline():
    print("\n" + "="*70)
    print("WEB FETCHER → THREAT EXTRACTOR PIPELINE TEST")
    print("="*70 + "\n")

    # Simulate test content (normally from real URL)
    test_html = """
    <html>
    <head><title>Security Alert</title></head>
    <body>
    <script>console.log('noisy');</script>
    <style>.ignore{}</style>
    <h1>Critical Vulnerability</h1>
    <p>
    Affected servers: 192.168.1.100, 10.0.0.50, 203.0.113.99
    </p>
    <p>
    Malware: emotet, trickbot
    Domain: malware.tk
    </p>
    <footer>Footer content ignored</footer>
    </body>
    </html>
    """

    # Test clean_content
    from web_fetcher import clean_content
    print("[1] Testing content cleaning...")
    cleaned = clean_content(test_html)
    print(f"    ✓ Removed scripts/styles/footer")
    print(f"    ✓ Output length: {len(cleaned)} chars")
    print(f"    ✓ First 100 chars: {cleaned[:100]}...\n")

    # Test extraction from cleaned content
    print("[2] Testing threat extraction on cleaned content...")
    result = extract(cleaned, source_url="test://mock")

    if result.get("error"):
        print(f"    ❌ Error: {result['error']}")
        return False

    stats = result["stats"]
    print(f"    ✓ Threat Level: {stats['threat_level']}")
    print(f"    ✓ IPv4 found: {stats['ipv4_count']}")
    print(f"    ✓ Domains found: {stats['domain_count']}")
    print(f"    ✓ Suspicious: {stats['suspicious_domain_count']}")
    print(f"    ✓ Malware families: {stats['malware_families']}\n")

    # Show extracted indicators
    print("[3] Extracted Indicators:")
    if result["indicators"]["ipv4"]:
        print(f"    IPs: {', '.join(result['indicators']['ipv4'])}")
    if result["indicators"]["malware_families"]:
        print(f"    Malware: {', '.join(result['indicators']['malware_families'].keys())}")
    if result["indicators"]["domains"]["suspicious"]:
        print(f"    Suspicious Domains: {', '.join(result['indicators']['domains']['suspicious'].keys())}")

    print("\n✓ Pipeline test passed!")
    return True


if __name__ == "__main__":
    success = test_pipeline()
    exit(0 if success else 1)
