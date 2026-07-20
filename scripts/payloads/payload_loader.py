#!/usr/bin/env python3
"""
Browser Bug Bounty - Automated Payload Loader
Loads SecLists payloads for use in browser testing
"""

import os
import sys
import json

SECLISTS_PATH = "/usr/share/seclists"

def load_wordlist(filepath, max_lines=100):
    """Load a wordlist file and return lines"""
    full_path = os.path.join(SECLISTS_PATH, filepath)
    if not os.path.exists(full_path):
        return []
    
    with open(full_path, 'r', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    return lines[:max_lines]

def get_xss_payloads(category="all", max_payloads=50):
    """Get XSS payloads from SecLists"""
    payloads = []
    
    if category in ["all", "basic"]:
        payloads.extend(load_wordlist("Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt", max_payloads))
    
    if category in ["all", "polyglot"]:
        payloads.extend(load_wordlist("Fuzzing/XSS/Polyglots/XSS-Polyglots.txt", max_payloads))
    
    if category in ["all", "portswigger"]:
        payloads.extend(load_wordlist("Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt", max_payloads))
    
    if category in ["all", "jhaddix"]:
        payloads.extend(load_wordlist("Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt", max_payloads))
    
    # Deduplicate
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    
    return unique[:max_payloads]

def get_sqli_payloads(category="all", max_payloads=50):
    """Get SQLi payloads from SecLists"""
    payloads = []
    
    if category in ["all", "generic"]:
        payloads.extend(load_wordlist("Fuzzing/Databases/SQLi/Generic-SQLi.txt", max_payloads))
    
    if category in ["all", "blind"]:
        payloads.extend(load_wordlist("Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt", max_payloads))
    
    if category in ["all", "mysql"]:
        payloads.extend(load_wordlist("Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt", max_payloads))
    
    if category in ["all", "auth_bypass"]:
        payloads.extend(load_wordlist("Fuzzing/Databases/SQLi/sqli.auth.bypass.txt", max_payloads))
    
    if category in ["all", "polyglot"]:
        payloads.extend(load_wordlist("Fuzzing/Databases/SQLi/SQLi-Polyglots.txt", max_payloads))
    
    # Deduplicate
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    
    return unique[:max_payloads]

def get_lfi_payloads(category="all", max_payloads=50):
    """Get LFI payloads from SecLists"""
    payloads = []
    
    if category in ["all", "jhaddix"]:
        payloads.extend(load_wordlist("Fuzzing/LFI/LFI-Jhaddix.txt", max_payloads))
    
    if category in ["all", "linux"]:
        payloads.extend(load_wordlist("Fuzzing/LFI/LFI-gracefulsecurity-linux.txt", max_payloads))
    
    if category in ["all", "windows"]:
        payloads.extend(load_wordlist("Fuzzing/LFI/LFI-gracefulsecurity-windows.txt", max_payloads))
    
    # Deduplicate
    seen = set()
    unique = []
    for p in payloads:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    
    return unique[:max_payloads]

def get_ssti_payloads(max_payloads=30):
    """Get SSTI payloads from SecLists"""
    return load_wordlist("Fuzzing/template-engines-expression.txt", max_payloads)

def get_cmd_injection_payloads(max_payloads=50):
    """Get command injection payloads from SecLists"""
    return load_wordlist("Fuzzing/command-injection-commix.txt", max_payloads)

def get_api_endpoints(max_endpoints=100):
    """Get API endpoints from SecLists"""
    endpoints = []
    endpoints.extend(load_wordlist("Discovery/Web-Content/api/api-endpoints.txt", max_endpoints))
    endpoints.extend(load_wordlist("Discovery/Web-Content/api/api-endpoints-res.txt", max_endpoints))
    endpoints.extend(load_wordlist("Discovery/Web-Content/api/api-seen-in-wild.txt", max_endpoints))
    endpoints.extend(load_wordlist("Discovery/Web-Content/common-api-endpoints-mazen160.txt", max_endpoints))
    
    # Deduplicate
    seen = set()
    unique = []
    for e in endpoints:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    
    return unique[:max_endpoints]

def get_directory_wordlist(size="medium", max_words=200):
    """Get directory wordlist"""
    if size == "small":
        return load_wordlist("Discovery/Web-Content/common.txt", max_words)
    elif size == "medium":
        return load_wordlist("Discovery/Web-Content/combined_directories.txt", max_words)
    elif size == "large":
        return load_wordlist("Discovery/Web-Content/big.txt", max_words)
    else:
        return load_wordlist("Discovery/Web-Content/common.txt", max_words)

def generate_browser_script(payload_type, **kwargs):
    """Generate a browser console script with payloads"""
    max_payloads = kwargs.get('max_payloads', 20)
    
    if payload_type == "xss":
        payloads = get_xss_payloads(max_payloads=max_payloads)
    elif payload_type == "sqli":
        payloads = get_sqli_payloads(max_payloads=max_payloads)
    elif payload_type == "lfi":
        payloads = get_lfi_payloads(max_payloads=max_payloads)
    elif payload_type == "ssti":
        payloads = get_ssti_payloads(max_payloads=max_payloads)
    elif payload_type == "cmd":
        payloads = get_cmd_injection_payloads(max_payloads=max_payloads)
    else:
        return f"Unknown payload type: {payload_type}"
    
    # Escape payloads for JavaScript
    escaped_payloads = []
    for p in payloads:
        escaped = p.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r')
        escaped_payloads.append(f'    "{escaped}"')
    
    js_payloads = ',\n'.join(escaped_payloads)
    
    script = f"""
// Auto-generated {payload_type.upper()} testing script
// Payloads from SecLists

(async () => {{
    const payloads = [
{js_payloads}
    ];
    
    console.log('=== {payload_type.upper()} Testing ===');
    console.log('Loaded', payloads.length, 'payloads');
    
    // Find all input fields
    const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea, input:not([type])');
    
    if (inputs.length === 0) {{
        console.log('No input fields found on this page');
        return;
    }}
    
    console.log('Found', inputs.length, 'input fields');
    
    for (const input of inputs) {{
        console.log(`\\nTesting: ${{input.name || input.id || input.placeholder}}`);
        
        for (const payload of payloads) {{
            // Set value using native setter
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            ).set;
            nativeInputValueSetter.call(input, payload);
            
            // Trigger events
            input.dispatchEvent(new Event('input', {{bubbles: true}}));
            input.dispatchEvent(new Event('change', {{bubbles: true}}));
            
            // Check reflection
            await new Promise(r => setTimeout(r, 200));
            
            if (document.body.innerHTML.includes(payload)) {{
                console.log('  REFLECTED:', payload.substring(0, 50) + '...');
            }}
        }}
    }}
}})();
"""
    return script

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 payload_loader.py <command> [options]")
        print("\nCommands:")
        print("  xss [category] [max]     - Load XSS payloads")
        print("  sqli [category] [max]    - Load SQLi payloads")
        print("  lfi [category] [max]     - Load LFI payloads")
        print("  ssti [max]               - Load SSTI payloads")
        print("  cmd [max]                - Load command injection payloads")
        print("  api [max]                - Load API endpoints")
        print("  dirs [size] [max]        - Load directory wordlist")
        print("  script <type> [max]      - Generate browser script")
        print("\nCategories:")
        print("  XSS: basic, polyglot, portswigger, jhaddix, all")
        print("  SQLi: generic, blind, mysql, auth_bypass, polyglot, all")
        print("  LFI: jhaddix, linux, windows, all")
        print("  Dirs: small, medium, large")
        return
    
    command = sys.argv[1]
    
    if command == "xss":
        category = sys.argv[2] if len(sys.argv) > 2 else "all"
        max_payloads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        payloads = get_xss_payloads(category, max_payloads)
        print(json.dumps(payloads, indent=2))
    
    elif command == "sqli":
        category = sys.argv[2] if len(sys.argv) > 2 else "all"
        max_payloads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        payloads = get_sqli_payloads(category, max_payloads)
        print(json.dumps(payloads, indent=2))
    
    elif command == "lfi":
        category = sys.argv[2] if len(sys.argv) > 2 else "all"
        max_payloads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        payloads = get_lfi_payloads(category, max_payloads)
        print(json.dumps(payloads, indent=2))
    
    elif command == "ssti":
        max_payloads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        payloads = get_ssti_payloads(max_payloads)
        print(json.dumps(payloads, indent=2))
    
    elif command == "cmd":
        max_payloads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        payloads = get_cmd_injection_payloads(max_payloads)
        print(json.dumps(payloads, indent=2))
    
    elif command == "api":
        max_endpoints = int(sys.argv[2]) if len(sys.argv) > 2 else 50
        endpoints = get_api_endpoints(max_endpoints)
        print(json.dumps(endpoints, indent=2))
    
    elif command == "dirs":
        size = sys.argv[2] if len(sys.argv) > 2 else "medium"
        max_words = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        words = get_directory_wordlist(size, max_words)
        print(json.dumps(words, indent=2))
    
    elif command == "script":
        if len(sys.argv) < 3:
            print("Usage: python3 payload_loader.py script <type> [max]")
            print("Types: xss, sqli, lfi, ssti, cmd")
            return
        
        payload_type = sys.argv[2]
        max_payloads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
        script = generate_browser_script(payload_type, max_payloads=max_payloads)
        print(script)
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
