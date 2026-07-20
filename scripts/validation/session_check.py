#!/usr/bin/env python3
"""
Quick session cookie security checker.
Usage: python3 session_check.py https://target.com

Checks: HttpOnly, Secure, SameSite, session fixation, cookie scope.
"""
import requests
import sys
import warnings
warnings.filterwarnings("ignore")

def check(target):
    target = target.rstrip("/")
    s = requests.Session()
    s.verify = False
    
    print(f"{'='*60}")
    print(f"  SESSION COOKIE CHECK — {target}")
    print(f"{'='*60}\n")
    
    # Initial request
    r = s.get(target, timeout=10)
    initial_cookies = {c.name: c for c in s.cookies}
    
    print(f"[*] Cookies found: {len(initial_cookies)}\n")
    
    issues = []
    for name, cookie in initial_cookies.items():
        print(f"  Cookie: {name}")
        print(f"    Value: {cookie.value[:30]}...")
        
        # HttpOnly
        httponly = cookie.has_nonstandard_attr('httponly')
        print(f"    HttpOnly: {'✓ YES' if httponly else '✗ NO'}")
        if not httponly:
            issues.append(f"[MEDIUM] {name}: Missing HttpOnly — cookie accessible via JavaScript (document.cookie)")
        
        # Secure
        print(f"    Secure: {'✓ YES' if cookie.secure else '✗ NO'}")
        if not cookie.secure:
            issues.append(f"[MEDIUM] {name}: Missing Secure — cookie sent over HTTP")
        
        # SameSite
        samesite = cookie.get_nonstandard_attr('samesite')
        print(f"    SameSite: {samesite or '✗ NOT SET'}")
        if not samesite:
            issues.append(f"[LOW] {name}: Missing SameSite — may be vulnerable to CSRF")
        
        # Path
        print(f"    Path: {cookie.path or '/'}")
        
        # Domain
        print(f"    Domain: {cookie.domain or '(current)'}")
        
        print()
    
    # Check if login changes session
    login_paths = ["/login", "/auth/login", "/signin"]
    for path in login_paths:
        try:
            r = s.get(f"{target}{path}", timeout=5)
            if r.status_code == 200:
                print(f"[*] Testing session fixation on {path}...")
                pre_login = {c.name: c.value for c in s.cookies}
                
                # We can't actually login without credentials, but note the finding
                print(f"    Pre-login cookies: {list(pre_login.keys())}")
                print(f"    [!] Manual test needed: login and check if session ID changes")
                break
        except:
            pass
    
    # Summary
    print(f"\n{'='*60}")
    print("  FINDINGS")
    print(f"{'='*60}\n")
    
    if issues:
        for issue in issues:
            print(f"  {issue}")
    else:
        print("  [✓] All cookies have proper security attributes")
    
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} https://target.com")
        sys.exit(1)
    check(sys.argv[1])
