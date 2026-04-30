"""
Demo: Threat Indicator Extractor
Validates threat_extractor module integration with project context.
"""

from threat_extractor import (
    extract, extract_from_url, export_indicators, find_malware_mentions
)

# ── TEST DATA ──────────────────────────────────────────────────────────
TEST_CONTENT = """
SECURITY ALERT: Ransomware Campaign Detected

Multiple organizations have reported infections with Emotet and TrickBot malware.
The C2 servers are located at:
- 192.168.1.100
- 10.0.0.55
- 203.0.113.99

Affected domains include:
- malicious.tk
- threatfeed.ml
- suspicious-site.cf

File hashes (MD5):
5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6

SHA256:
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
2c26b46911185131006ba89c2478f1a2f7b05b0e23f8eda2c7b0e7f4e2a4e8a0

Malware families identified: emotet, trickbot, maze, conti
Contact: security@organization.com
Visit: https://example.com/alert
"""


def test_extraction():
    """Test IoC extraction."""
    print("\n" + "="*60)
    print("THREAT EXTRACTOR — DEMO & VALIDATION")
    print("="*60 + "\n")

    print("[*] Extracting indicators from test content...\n")
    result = extract(TEST_CONTENT, source_url="demo://test")

    if result.get("error"):
        print(f"❌ Error: {result['error']}")
        return False

    print(f"✓ Extracted at: {result['extracted_at']}")
    print(f"✓ Threat Level: {result['stats']['threat_level']}\n")

    # IPv4
    stats = result["stats"]
    print(f"IPv4 Addresses:      {stats['ipv4_count']}")
    for ip in result["indicators"]["ipv4"]:
        print(f"  → {ip}")

    # Domains
    domains = result["indicators"]["domains"]
    print(f"\nDomains (clean):     {len(domains['clean'])}")
    for d in domains["clean"]:
        print(f"  → {d}")
    print(f"Domains (suspicious): {len(domains['suspicious'])}")
    for d in domains["suspicious"]:
        print(f"  ⚠ {d}")

    # Hashes
    hashes = result["indicators"]["hashes"]
    print(f"\nMD5 Hashes:          {len(hashes['md5'])}")
    for h in hashes["md5"]:
        print(f"  → {h[:16]}...")
    print(f"SHA256 Hashes:       {len(hashes['sha256'])}")
    for h in hashes["sha256"]:
        print(f"  → {h[:16]}...")

    # Malware
    malware = result["indicators"]["malware_families"]
    print(f"\nMalware Families:    {len(malware)}")
    for m, count in malware.items():
        print(f"  → {m}: {count} mention(s)")

    print(f"\n📊 STATISTICS:")
    print(f"  Domains:             {stats['domain_count']}")
    print(f"  Suspicious:          {stats['suspicious_domain_count']}")
    print(f"  Total Hashes:        {stats['hash_count']}")
    print(f"  URLs:                {stats['url_count']}")
    print(f"  Filepaths:           {stats['filepath_count']}")
    print(f"  Emails:              {stats['email_count']}")

    # Export test
    print("\n[*] Testing export formats...\n")
    txt_export = export_indicators(result, fmt="txt")
    print("TXT Export (first 300 chars):")
    print(txt_export[:300] + "..." if len(txt_export) > 300 else txt_export)

    print("\n✓ Threat Extractor validated successfully!")
    return True


if __name__ == "__main__":
    success = test_extraction()
    exit(0 if success else 1)
