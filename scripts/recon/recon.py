#!/usr/bin/env python3
"""
Quick web application recon scanner.
Usage: python3 recon.py https://target.com

Extracts: headers, technology stack, robots.txt paths, sitemap URLs, 
form fields, CSRF tokens, cookie attributes.
"""
import requests
import re
import sys
import warnings
warnings.filterwarnings("ignore")

def scan(target):
    target = target.rstrip("/")
    s = requests.Session()
    s.verify = False
    
    print(f"{'='*60}")
    print(f"  RECON SCAN — {target}")
    print(f"{'='*60}")
    
    # 1. Headers & Technology
    print(f"\n[*] HTTP Headers & Technology Stack:")
    r = s.get(target, timeout=10)
    tech_headers = ["server", "x-powered-by", "platform", "panel", "x-hcdn-request-id"]
    for h in tech_headers:
        val = r.headers.get(h, "")
        if val:
            print(f"  {h}: {val}")
    
    # Cookie analysis
    for cookie in s.cookies:
        attrs = []
        if cookie.has_nonstandard_attr('httponly'): attrs.append("HttpOnly")
        if cookie.secure: attrs.append("Secure")
        samesite = cookie.get_nonstandard_attr('samesite')
        if samesite: attrs.append(f"SameSite={samesite}")
        print(f"  Cookie: {cookie.name} ({', '.join(attrs) if attrs else 'NO SECURITY FLAGS'})")
    
    # 2. robots.txt
    print(f"\n[*] robots.txt paths:")
    try:
        r = s.get(f"{target}/robots.txt", timeout=5)
        if r.status_code == 200:
            disallowed = re.findall(r'Disallow:\s*(/\S*)', r.text)
            for path in disallowed:
                print(f"  {path}")
    except:
        print("  [not found]")
    
    # 3. sitemap.xml
    print(f"\n[*] sitemap.xml URLs:")
    try:
        r = s.get(f"{target}/sitemap.xml", timeout=5)
        if r.status_code == 200:
            urls = re.findall(r'<loc>(.*?)</loc>', r.text)
            for url in urls[:20]:
                print(f"  {url}")
            if len(urls) > 20:
                print(f"  ... and {len(urls)-20} more")
    except:
        print("  [not found]")
    
    # 4. Form analysis
    print(f"\n[*] Forms found:")
    forms = re.findall(r'<form[^>]*action="([^"]*)"[^>]*method="([^"]*)"[^>]*>(.*?)</form>', r.text, re.DOTALL | re.IGNORECASE)
    for action, method, body in forms:
        inputs = re.findall(r'name="([^"]+)"', body)
        csrf = re.search(r'csrf[^"]*value="([^"]+)"', body)
        print(f"  {method.upper()} {action}")
        print(f"    Fields: {inputs}")
        if csrf:
            print(f"    CSRF: {csrf.group(1)[:20]}...")
    
    # 5. JS files
    print(f"\n[*] JavaScript files:")
    js_files = set(re.findall(r'(?:src|href)="([^"]*\.js[^"]*)"', r.text))
    for js in js_files:
        print(f"  {js}")
    
    # 6. Security headers check
    print(f"\n[*] Security Headers:")
    sec_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY/SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=...",
        "Content-Security-Policy": "default-src...",
        "Referrer-Policy": "strict-origin...",
        "Permissions-Policy": "restrictive",
    }
    for header, expected in sec_headers.items():
        val = r.headers.get(header, "")
        status = "✓" if val else "✗ MISSING"
        print(f"  {header}: {status} {val[:60] if val else ''}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} https://target.com")
        sys.exit(1)
    scan(sys.argv[1])
