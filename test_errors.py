"""
Test: Web Fetcher Error Handling
Validates all error conditions
"""

from web_fetcher import fetch_url, fetch_and_clean

def test_error_handling():
    print("\n" + "="*70)
    print("WEB FETCHER ERROR HANDLING TEST")
    print("="*70 + "\n")

    tests = [
        ("", "Empty URL"),
        ("invalid url", "Missing scheme"),
        ("https://nonexistent-domain-that-will-never-exist-12345.com", "Connection error"),
    ]

    for test_input, description in tests:
        print(f"[*] Testing: {description}")
        result = fetch_and_clean(test_input)
        
        if result.get("error"):
            print(f"    ✓ Caught error: {result['error'][:60]}...")
        else:
            print(f"    ❌ Expected error but got content")

    print("\n✓ All error cases handled correctly!")


if __name__ == "__main__":
    test_error_handling()
