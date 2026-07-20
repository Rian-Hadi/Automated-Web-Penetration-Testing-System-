# 🔬 Referensi Scanning & Enumeration

Dokumen ini berisi referensi command untuk fase Scanning & Enumeration (OWASP WSTG Core Testing).
Mencakup WSTG-CONF, WSTG-IDNT, WSTG-ATHN, dan WSTG-SESS.

---

## 1. Automated Vulnerability Scanning (Nuclei, Nikto, WPScan, Dalfox, XSSChecker, Nessus, Burp, ZAP)

### 1.1 Nuclei — Template-based Scanner
```bash
# Scan dengan semua templates default
nuclei -u https://example.com -o nuclei_results.txt

# Scan berdasarkan severity
nuclei -u https://example.com -severity critical,high -o nuclei_critical.txt

# Headless browser scan (untuk JS-rendered pages)
nuclei -u https://example.com -headless -o nuclei_headless.txt
```

### 1.2 Nikto — Web Server Scanner
```bash
# Basic scan
nikto -h https://example.com -o nikto_results.txt
```

### 1.3 WPScan — WordPress Vulnerability Scanner
```bash
# Scan situs WordPress untuk mendeteksi kerentanan plugin, theme, dan user
wpscan --url https://example.com --enumerate vp,vt,u --api-token <WPSCAN_API_TOKEN> -o wpscan_results.txt
```

### 1.4 Dalfox & XSSChecker — Dedicated XSS Scanners
```bash
# Dalfox — Parameter analysis & XSS scanner
dalfox url https://example.com/page.php?id=1 --custom-payload /path/to/payloads.txt

# Dalfox scan dari pipe stdin (misal input dari gau/waybackurls)
cat unique_param_urls.txt | dalfox pipe --concurrency 50

# XSSChecker — custom script/tool to check for reflected XSS
xsschecker -u "https://example.com/page.php?q=FUZZ" -p payloads.txt -o xss_results.txt
```

### 1.5 Nessus — Network & Web Vulnerability Assessment
```bash
# Jalankan command scan menggunakan Nessus Command Line (nessuscli)
/opt/nessus/sbin/nessuscli scan launch --scan-id <SCAN_ID> --policy-id <POLICY_ID>
```

### 1.6 Intercept Proxies (Burp Suite & OWASP ZAP)
```bash
# Burp Suite — Run headlessly atau intercept traffic secara manual (GUI)
# Konfigurasi upstream proxy pada tools lain agar traffic tertangkap Burp:
curl -x http://127.0.0.1:8080 -k https://example.com

# OWASP ZAP — Jalankan active scan via daemon mode / API
zap-cli -p 8090 quick-scan --self-contained --start-options "-config api.disablekey=true" https://example.com
```

---

## 2. Configuration Testing (WSTG-CONF)

### 2.1 TLS/SSL Testing (WSTG-CONF-09)

```bash
# Nmap SSL scripts
nmap --script ssl-enum-ciphers -p 443 <TARGET>
nmap --script ssl-cert -p 443 <TARGET>

# OpenSSL manual check
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -text

# Check certificate chain
openssl s_client -connect example.com:443 -showcerts </dev/null 2>/dev/null

# Check specific TLS versions
openssl s_client -connect example.com:443 -tls1   2>&1 | head -5  # TLS 1.0
openssl s_client -connect example.com:443 -tls1_1 2>&1 | head -5  # TLS 1.1
openssl s_client -connect example.com:443 -tls1_2 2>&1 | head -5  # TLS 1.2
openssl s_client -connect example.com:443 -tls1_3 2>&1 | head -5  # TLS 1.3

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 <TARGET> | grep -E "TLSv1\.[01]|NULL|EXPORT|DES|RC4|MD5"
```

### 2.2 HTTP Methods Testing (WSTG-CONF-06)

```bash
# Check allowed HTTP methods
curl -X OPTIONS -I https://example.com
nmap --script http-methods -p 80,443 <TARGET>

# Test dangerous methods
curl -X PUT -d "test" https://example.com/test.txt -v
curl -X DELETE https://example.com/test.txt -v
curl -X TRACE https://example.com -v
```

### 2.3 Security Headers Check (WSTG-CONF-07)

```bash
# Check all security headers
curl -s -I https://example.com | grep -iE "^(x-frame|x-content|x-xss|strict-transport|content-security|referrer-policy|permissions-policy|x-permitted|access-control|x-download|x-dns|feature-policy|expect-ct|cross-origin)"

# Headers yang harus ada:
# Strict-Transport-Security (HSTS)
# Content-Security-Policy (CSP)
# X-Frame-Options
# X-Content-Type-Options: nosniff
# Referrer-Policy
# Permissions-Policy

# Headers yang TIDAK boleh ada (info disclosure):
curl -s -I https://example.com | grep -iE "^(server:|x-powered-by:|x-aspnet|x-aspnetmvc)"
```

### 2.4 Error Handling & Stack Trace (WSTG-CONF-10)

```bash
# Trigger error pages
curl -s https://example.com/nonexistent_page_12345
curl -s "https://example.com/page?id='"
curl -s "https://example.com/page?id=<script>"
curl -s https://example.com/%00
curl -s https://example.com/..%2f..%2fetc%2fpasswd
```

---

## 3. Identity Management Testing (WSTG-IDNT)

### 3.1 Role & Permission Enumeration (WSTG-IDNT-01)

```
Checklist manual:
- [ ] Identifikasi semua role yang ada (admin, user, moderator, etc.)
- [ ] Mapping endpoint per role
- [ ] Test akses endpoint role A dengan credential role B
- [ ] Cek apakah registration memungkinkan role escalation
```

### 3.2 Username Enumeration (WSTG-IDNT-04)

```bash
# Enumerate via login response differences
# Perhatikan perbedaan response untuk:
# - Username valid + password salah
# - Username invalid + password salah
# Jika response berbeda = username enumerable

# Timing-based enumeration
# Response time berbeda antara username valid vs invalid

# Via registration page
# "Username sudah digunakan" vs berhasil register

# Ffuf username enumeration
ffuf -u https://example.com/login -X POST \
  -d "username=FUZZ&password=invalid" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt \
  -mr "incorrect password" -o username_enum.json
```

---

## 4. Authentication Testing (WSTG-ATHN)

### 4.1 Default Credentials (WSTG-ATHN-02)

```bash
# Cek default credentials untuk CMS/services yang ditemukan
# Referensi: https://default-password.info/
# Referensi: https://cirt.net/passwords

# Brute force dengan Hydra
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  https-post-form "example.com:/login:username=^USER^&password=^PASS^:F=incorrect" -V

# Hydra HTTP Basic Auth
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  example.com http-get /admin -V
```

### 4.2 Login Bypass (WSTG-ATHN-04)

```bash
# SQL Injection pada form login
# Referensi payloads: /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt

# Test payloads umum:
# admin' --
# admin' #
# admin'/*
# ' OR 1=1 --
# ' OR '1'='1
# ') OR ('1'='1

# Ffuf login bypass
ffuf -u https://example.com/login -X POST \
  -d "username=FUZZ&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt \
  -fc 401,403 -o login_bypass.json
```

### 4.3 Password Policy Testing (WSTG-ATHN-07)

```
Checklist manual:
- [ ] Minimum password length (harus ≥ 8, idealnya ≥ 12)
- [ ] Complexity requirements (upper, lower, number, special)
- [ ] Brute force protection (account lockout / rate limiting)
- [ ] Password reset flow (token predictability, expiration)
- [ ] Multi-factor authentication (tersedia / bypass-able?)
```

---

## 5. Session Management Testing (WSTG-SESS)

### 5.1 Cookie Analysis (WSTG-SESS-02)

```bash
# Inspect cookies
curl -v -c cookies.txt https://example.com/login -d "username=test&password=test" 2>&1 | grep -i "set-cookie"

# Checklist cookie attributes:
# - [ ] Secure flag (hanya dikirim via HTTPS)
# - [ ] HttpOnly flag (tidak bisa diakses JavaScript)
# - [ ] SameSite attribute (Strict/Lax/None)
# - [ ] Domain scope (tidak terlalu luas)
# - [ ] Path scope
# - [ ] Expires/Max-Age (session timeout)

# Test session fixation
# 1. Ambil session cookie sebelum login
# 2. Login
# 3. Cek apakah session cookie berubah setelah login
# Jika TIDAK berubah = Session Fixation vulnerability
```

### 5.2 Session Token Entropy (WSTG-SESS-01)

```bash
# Kumpulkan multiple session tokens
for i in $(seq 1 20); do
  curl -s -c - https://example.com/ 2>/dev/null | grep -i "session\|token\|sid" >> session_tokens.txt
done

# Analisis pattern:
# - Apakah sequential/predictable?
# - Cukup panjang? (minimal 128-bit)
# - Mengandung data user yang bisa di-decode?
```

### 5.3 JWT Testing (WSTG-SESS-XX)

```bash
# Decode JWT (header.payload.signature)
echo "<JWT_TOKEN>" | cut -d'.' -f1 | base64 -d 2>/dev/null
echo "<JWT_TOKEN>" | cut -d'.' -f2 | base64 -d 2>/dev/null

# Test JWT attacks:
# 1. Algorithm None attack
#    Ubah header "alg" menjadi "none", hapus signature
# 2. Algorithm confusion (RS256 → HS256)
#    Gunakan public key sebagai secret untuk HMAC
# 3. Weak secret brute force
#    hashcat -a 0 -m 16500 <JWT> /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt
# 4. JWT token expiration test
#    Cek apakah expired token masih diterima
# 5. JWT injection
#    Modifikasi payload claims (user ID, role, etc.)

# Hashcat JWT cracking
hashcat -a 0 -m 16500 jwt.txt /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt --force

# === Flask Session Cookie Cracking & Signing (Flask-Unsign) ===

# Decode Flask Session Cookie
flask-unsign --decode --cookie ".eJyrVopXslIyNNFRKi1OLfJNzEvMTY1PTMxJTc5JrUwtSk1VqgUA2ZcM9w.Yx5v7Q.abCdEfGhIjKlMnOpQrStUvWxYzI"

# Brute force Flask session secret key
flask-unsign --unsign --cookie ".eJyrVopXslIyNNFRKi1OLfJNzEvMTY1PTMxJTc5JrUwtSk1VqgUA2ZcM9w.Yx5v7Q.abCdEfGhIjKlMnOpQrStUvWxYzI" --wordlist /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Sign a custom modified session cookie using the cracked secret key
flask-unsign --sign --cookie "{'logged_in': True, 'user_id': 1}" --secret "secretkey123"
```

### 5.4 CSRF Testing (WSTG-SESS-05)

```
Checklist CSRF:
- [ ] Apakah ada CSRF token di form?
- [ ] Apakah CSRF token validated server-side?
- [ ] Apakah CSRF token tied to session?
- [ ] Test: Hapus CSRF token → apakah request tetap berhasil?
- [ ] Test: Ubah CSRF token → apakah request tetap berhasil?
- [ ] Test: Gunakan CSRF token dari session lain
- [ ] Cek SameSite cookie attribute
```

---

## 6. Entry Point Identification

### 6.1 Parameter Discovery

```bash
# Parameter fuzzing via ffuf
ffuf -u "https://example.com/page?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <SIZE_TO_FILTER> -o params_found.json

# Header injection points
ffuf -u https://example.com -H "FUZZ: test_value" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <SIZE_TO_FILTER>

# POST parameter fuzzing
ffuf -u https://example.com/api/endpoint -X POST \
  -d "FUZZ=test" -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fs <SIZE_TO_FILTER>
```

### 6.2 API Endpoint Discovery

```bash
# Common API paths
ffuf -u https://example.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt \
  -mc 200,201,301,302,401,403,405 -o api_endpoints.json

# GraphQL endpoint detection
curl -s https://example.com/graphql -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'

# Swagger/OpenAPI detection
for path in /swagger.json /swagger-ui.html /api-docs /openapi.json /v1/swagger.json /v2/swagger.json /swagger/v1/swagger.json; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com$path")
  [ "$status" != "404" ] && echo "[${status}] https://example.com$path"
done
```

---

## 7. Dokumentasi Scanning

```
📋 Scanning & Enumeration Report:
- Vulnerabilities Found:
  - Critical : [jumlah]
  - High     : [jumlah]
  - Medium   : [jumlah]
  - Low      : [jumlah]
  - Info     : [jumlah]
- TLS/SSL Status    : [versi, cipher strength]
- Security Headers  : [missing headers]
- Authentication    : [mekanisme, kelemahan]
- Session Mgmt      : [cookie flags, token entropy]
- Entry Points      : [parameter, header, cookie yang injectable]
- Next Step         : Lanjut ke Fase 4 — Exploitation
```
