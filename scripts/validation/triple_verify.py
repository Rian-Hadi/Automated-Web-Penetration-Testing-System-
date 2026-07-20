#!/usr/bin/env python3
"""
Triple Verification Script
Usage: python3 triple_verify.py <url>
"""

import requests
import json
import re
import sys
from html import unescape

import urllib3
urllib3.disable_warnings()

def v1_same_payload(url, extract_func):
    """V1: Reproduce dengan payload sama"""
    print("[V1] Testing dengan payload sama...")
    results = []
    for i in range(3):
        try:
            data = extract_func(url)
            results.append(data)
        except Exception as e:
            print(f"  Error: {e}")
            return False
    
    if all(r == results[0] for r in results):
        print("  ✅ Konsisten")
        return True
    else:
        print("  ❌ Tidak konsisten")
        return False

def v2_different_payloads(base_url, extract_func):
    """V2: Variasi payload berbeda"""
    print("[V2] Testing dengan variasi payload...")
    urls = [
        base_url,
        f"{base_url}?page=2",
        f"{base_url}?test=123"
    ]
    
    results = []
    for test_url in urls:
        try:
            data = extract_func(test_url)
            results.append(data is not None)
        except Exception as e:
            print(f"  Error on {test_url}: {e}")
            results.append(False)
    
    if all(results):
        print("  ✅ Konsisten di semua variasi")
        return True
    else:
        print("  ❌ Tidak konsisten")
        return False

def v3_clean_context(url, extract_func):
    """V3: Clean context / fresh session"""
    print("[V3] Testing dengan clean context...")
    
    try:
        # Test tanpa cookies
        r = requests.get(url, cookies={}, verify=False, timeout=30)
        match = re.search(r'data-page="([^"]+)"', r.text)
        if match:
            data = json.loads(unescape(match.group(1)))
            if 'props' in data:
                print("  ✅ Vulnerability tetap ada tanpa cookies")
                return True
    except Exception as e:
        print(f"  Error: {e}")
    
    print("  ❌ Vulnerability tidak ada tanpa cookies")
    return False

def extract_inertia_data(url):
    """Extract data from Laravel/Inertia.js page"""
    r = requests.get(url, verify=False, timeout=30)
    match = re.search(r'data-page="([^"]+)"', r.text)
    if match:
        json_str = unescape(match.group(1))
        data = json.loads(json_str)
        return data.get('props')
    return None

def triple_verify(url):
    """Run Triple Verification"""
    print("=" * 60)
    print("TRIPLE VERIFICATION PROTOCOL")
    print("=" * 60)
    print(f"Target: {url}")
    print()
    
    v1 = v1_same_payload(url, extract_inertia_data)
    v2 = v2_different_payloads(url, extract_inertia_data)
    v3 = v3_clean_context(url, extract_inertia_data)
    
    print()
    print("=" * 60)
    print("HASIL:")
    print(f"  V1 (Same Payload): {'✅' if v1 else '❌'}")
    print(f"  V2 (Different Payload): {'✅' if v2 else '❌'}")
    print(f"  V3 (Clean Context): {'✅' if v3 else '❌'}")
    print("=" * 60)
    
    if v1 and v2 and v3:
        print("\n🎯 STATUS: CONFIRMED - Bukan False Positive!")
        return True
    elif v1 and v2:
        print("\n⚠️ STATUS: PARTIAL - Perlu investigasi lebih lanjut")
        return False
    else:
        print("\n❌ STATUS: FALSE POSITIVE - Jangan laporkan")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 triple_verify.py <url>")
        print("Example: python3 triple_verify.py https://target.com/page")
        sys.exit(1)
    
    target_url = sys.argv[1]
    triple_verify(target_url)
