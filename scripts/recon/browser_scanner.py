#!/usr/bin/env python3
"""
Browser Bug Bounty - Automated Scanner
Combines browser automation with SecLists payloads for comprehensive testing
"""

import os
import sys
import json
import re
from datetime import datetime

SECLISTS_PATH = "/usr/share/seclists"

class BrowserScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.findings = []
        self.tested_endpoints = set()
        
    def load_payloads(self, payload_type, max_payloads=20):
        """Load payloads from SecLists"""
        payloads = []
        
        payload_files = {
            "xss": [
                "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
                "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
            ],
            "sqli": [
                "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
                "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
            ],
            "lfi": [
                "Fuzzing/LFI/LFI-Jhaddix.txt",
            ],
            "ssti": [
                "Fuzzing/template-engines-expression.txt",
            ],
            "cmd": [
                "Fuzzing/command-injection-commix.txt",
            ],
        }
        
        for filepath in payload_files.get(payload_type, []):
            full_path = os.path.join(SECLISTS_PATH, filepath)
            if os.path.exists(full_path):
                with open(full_path, 'r', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            payloads.append(line)
        
        # Deduplicate
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)
        
        return unique[:max_payloads]
    
    def generate_recon_script(self):
        """Generate browser console script for reconnaissance"""
        return """
// Automated Recon Script
(async () => {
    const results = {
        url: window.location.href,
        title: document.title,
        timestamp: new Date().toISOString(),
        
        // Technology detection
        technologies: {
            generator: document.querySelector('meta[name="generator"]')?.content,
            jquery: !!document.querySelector('script[src*="jquery"]'),
            react: !!document.querySelector('script[src*="react"]'),
            vue: !!document.querySelector('script[src*="vue"]'),
            angular: !!document.querySelector('script[src*="angular"]'),
            wordpress: document.querySelector('meta[name="generator"][content*="WordPress"]') !== null,
        },
        
        // Security headers
        security: {
            csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]')?.content,
            xFrame: document.querySelector('meta[http-equiv="X-Frame-Options"]')?.content,
        },
        
        // Forms
        forms: Array.from(document.querySelectorAll('form')).map(f => ({
            action: f.action,
            method: f.method,
            inputs: Array.from(f.querySelectorAll('input')).map(i => ({
                name: i.name,
                type: i.type,
                required: i.required,
            })),
        })),
        
        // Links
        links: {
            internal: Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => h.includes(location.hostname))
                .filter((v,i,a) => a.indexOf(v) === i)
                .length,
            external: Array.from(document.querySelectorAll('a[href]'))
                .map(a => a.href)
                .filter(h => !h.includes(location.hostname) && h.startsWith('http'))
                .filter((v,i,a) => a.indexOf(v) === i)
                .length,
        },
        
        // Scripts
        scripts: Array.from(document.querySelectorAll('script[src]'))
            .map(s => s.src)
            .filter(s => s.includes(location.hostname)),
        
        // Cookies
        cookies: document.cookie,
        
        // Local storage
        localStorage: Object.keys(localStorage),
        sessionStorage: Object.keys(sessionStorage),
    };
    
    console.log(JSON.stringify(results, null, 2));
    return results;
})();
"""
    
    def generate_xss_test_script(self, payloads):
        """Generate XSS testing script"""
        escaped_payloads = []
        for p in payloads[:20]:  # Limit to 20 payloads
            escaped = p.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            escaped_payloads.append(f'    "{escaped}"')
        
        js_payloads = ',\n'.join(escaped_payloads)
        
        return f"""
// Automated XSS Testing
(async () => {{
    const payloads = [
{js_payloads}
    ];
    
    const results = [];
    const inputs = document.querySelectorAll('input[type="text"], input[type="search"], textarea, input:not([type])');
    
    console.log('Testing', payloads.length, 'XSS payloads on', inputs.length, 'inputs');
    
    for (const input of inputs) {{
        const fieldName = input.name || input.id || input.placeholder;
        
        for (const payload of payloads) {{
            const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
                window.HTMLInputElement.prototype, 'value'
            ).set;
            nativeInputValueSetter.call(input, payload);
            
            input.dispatchEvent(new Event('input', {{bubbles: true}}));
            input.dispatchEvent(new Event('change', {{bubbles: true}}));
            
            await new Promise(r => setTimeout(r, 200));
            
            if (document.body.innerHTML.includes(payload)) {{
                results.push({{
                    field: fieldName,
                    payload: payload,
                    type: 'reflected',
                }});
                console.log('REFLECTED:', fieldName, '-', payload.substring(0, 50));
            }}
        }}
    }}
    
    return results;
}})();
"""
    
    def generate_sqli_test_script(self, payloads):
        """Generate SQLi testing script"""
        escaped_payloads = []
        for p in payloads[:15]:  # Limit to 15 payloads
            escaped = p.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
            escaped_payloads.append(f'    "{escaped}"')
        
        js_payloads = ',\n'.join(escaped_payloads)
        
        return f"""
// Automated SQLi Testing
(async () => {{
    const payloads = [
{js_payloads}
    ];
    
    const results = [];
    const url = new URL(window.location.href);
    const params = url.searchParams;
    
    const sqlErrors = ['sql', 'mysql', 'syntax', 'query', 'oracle', 'postgresql', 'mssql'];
    
    console.log('Testing', payloads.length, 'SQLi payloads on', params.size, 'parameters');
    
    for (const [key, value] of params.entries()) {{
        for (const payload of payloads) {{
            const testUrl = new URL(url);
            testUrl.searchParams.set(key, payload);
            
            const startTime = Date.now();
            try {{
                const r = await fetch(testUrl.href, {{redirect: 'manual'}});
                const endTime = Date.now();
                const body = await r.text();
                
                const isTimeBased = (endTime - startTime) > 2500;
                const hasError = sqlErrors.some(e => body.toLowerCase().includes(e));
                
                if (isTimeBased || hasError) {{
                    results.push({{
                        parameter: key,
                        payload: payload,
                        type: isTimeBased ? 'time-based' : 'error-based',
                        time: endTime - startTime,
                    }});
                    console.log('VULNERABLE:', key, '-', payload.substring(0, 50));
                }}
            }} catch(e) {{}}
        }}
    }}
    
    return results;
}})();
"""
    
    def generate_path_discovery_script(self):
        """Generate path discovery script"""
        paths = self.load_payloads("dirs", 30)
        
        escaped_paths = []
        for p in paths:
            escaped = p.replace('\\', '\\\\').replace('"', '\\"')
            escaped_paths.append(f'    "{escaped}"')
        
        js_paths = ',\n'.join(escaped_paths)
        
        return f"""
// Automated Path Discovery
(async () => {{
    const paths = [
{js_paths}
    ];
    
    const results = [];
    
    console.log('Testing', paths.length, 'paths');
    
    for (const path of paths) {{
        try {{
            const r = await fetch(path, {{method: 'HEAD', redirect: 'manual'}});
            if (r.status !== 404 && r.status !== 0) {{
                results.push({{
                    path: path,
                    status: r.status,
                    type: r.headers.get('content-type'),
                }});
                console.log(r.status, path);
            }}
        }} catch(e) {{}}
    }}
    
    return results;
}})();
"""
    
    def add_finding(self, severity, title, description, evidence=None):
        """Add a finding to results"""
        self.findings.append({
            'severity': severity,
            'title': title,
            'description': description,
            'evidence': evidence,
            'timestamp': datetime.now().isoformat(),
        })
    
    def generate_report(self):
        """Generate findings report"""
        report = {
            'target': self.target_url,
            'timestamp': datetime.now().isoformat(),
            'findings': self.findings,
            'summary': {
                'critical': len([f for f in self.findings if f['severity'] == 'critical']),
                'high': len([f for f in self.findings if f['severity'] == 'high']),
                'medium': len([f for f in self.findings if f['severity'] == 'medium']),
                'low': len([f for f in self.findings if f['severity'] == 'low']),
                'info': len([f for f in self.findings if f['severity'] == 'info']),
            }
        }
        
        return json.dumps(report, indent=2)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 browser_scanner.py <command> [target_url]")
        print("\nCommands:")
        print("  recon <url>     - Generate recon script")
        print("  xss <url>       - Generate XSS testing script")
        print("  sqli <url>      - Generate SQLi testing script")
        print("  paths <url>     - Generate path discovery script")
        print("  full <url>      - Generate full scan script")
        return
    
    command = sys.argv[1]
    target_url = sys.argv[2] if len(sys.argv) > 2 else "https://example.com"
    
    scanner = BrowserScanner(target_url)
    
    if command == "recon":
        script = scanner.generate_recon_script()
        print(script)
    
    elif command == "xss":
        payloads = scanner.load_payloads("xss", 20)
        script = scanner.generate_xss_test_script(payloads)
        print(script)
    
    elif command == "sqli":
        payloads = scanner.load_payloads("sqli", 15)
        script = scanner.generate_sqli_test_script(payloads)
        print(script)
    
    elif command == "paths":
        script = scanner.generate_path_discovery_script()
        print(script)
    
    elif command == "full":
        print("=== RECON SCRIPT ===")
        print(scanner.generate_recon_script())
        print("\n=== PATH DISCOVERY SCRIPT ===")
        print(scanner.generate_path_discovery_script())
        print("\n=== XSS TEST SCRIPT ===")
        xss_payloads = scanner.load_payloads("xss", 10)
        print(scanner.generate_xss_test_script(xss_payloads))
        print("\n=== SQLi TEST SCRIPT ===")
        sqli_payloads = scanner.load_payloads("sqli", 10)
        print(scanner.generate_sqli_test_script(sqli_payloads))
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
