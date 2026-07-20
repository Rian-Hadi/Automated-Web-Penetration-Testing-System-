# 🔍 Referensi Command Reconnaissance

Dokumen ini berisi command lengkap untuk fase Reconnaissance (OWASP WSTG-INFO).
Semua command menggunakan tools yang terinstall di sistem dan wordlist dari `/usr/share/seclists/`.

---

## 1. Passive Reconnaissance (WSTG-INFO-01 to 03)

### 1.1 WHOIS & DNS Lookup

```bash
# WHOIS lookup
whois example.com

# DNS Records lengkap
dig example.com ANY +noall +answer
dig example.com A +short
dig example.com AAAA +short
dig example.com MX +short
dig example.com NS +short
dig example.com TXT +short
dig example.com CNAME +short
dig example.com SOA +short

# Reverse DNS
dig -x <IP_ADDRESS> +short

# DNS Zone Transfer (jika diizinkan)
dig axfr @<NS_SERVER> example.com

# DNS History via multiple nameservers
for ns in 8.8.8.8 1.1.1.1 9.9.9.9; do
  echo "=== NS: $ns ==="
  dig @$ns example.com A +short
done
```

### 1.2 OSINT & Informasi Publik

```bash
# theHarvester — email, subdomain, IP dari sumber publik
theHarvester -d example.com -b google,bing,linkedin,twitter,crtsh -l 500

# Certificate Transparency logs
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u

# Wayback Machine — URL historis
waybackurls example.com | sort -u | tee wayback_urls.txt

# Google Dorking (jalankan manual di browser)
# site:example.com filetype:pdf
# site:example.com inurl:admin
# site:example.com intitle:"index of"
# site:example.com ext:sql | ext:db | ext:log
# site:example.com inurl:api

# GitHub Dorking — cari leak di repository publik
# "example.com" password
# "example.com" api_key
# "example.com" secret
# "example.com" token
```

### 1.3 Shodan & Censys

```bash
# Shodan CLI (perlu API key)
shodan search "hostname:example.com"
shodan host <IP_ADDRESS>
shodan search "ssl.cert.subject.CN:example.com"

# Censys CLI (perlu API key)
censys search "example.com"
```

---

## 2. Active Reconnaissance (WSTG-INFO-04 to 10)

### 2.1 Subdomain Enumeration & Asset Discovery

```bash
# 1. Subfinder — passive discovery
subfinder -d example.com -all -o subdomains_subfinder.txt

# 2. Assetfinder — find related domains/subdomains
assetfinder --subs-only example.com > subdomains_assetfinder.txt

# 3. Sublister — subdomain enumeration
sublist3r -d example.com -o subdomains_sublister.txt

# 4. CRT.sh lookup using custom curl command
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subdomains_crtsh.txt

# 5. Chaos lookup (projectdiscovery Chaos API client)
chaos -d example.com -o subdomains_chaos.txt

# 6. GitHub Subdomains search
github-subdomains -d example.com -t <GITHUB_TOKEN> -o subdomains_github.txt

# 7. Shosubgo — find subdomains from Shodan
shosubgo -d example.com -s <SHODAN_API_KEY> > subdomains_shodan.txt

# === Gabungkan & Deduplikasi Menggunakan ANEW ===
cat subdomains_*.txt | anew all_subdomains.txt

# === Cek Subdomain Takeover dengan Subzy ===
subzy run --targets all_subdomains.txt --concurrency 100 --hide_fails --output takeover_results.txt

# === HTTP Probing (Temukan Host Aktif) ===

# Httprobe — basic alive check
cat all_subdomains.txt | httprobe -c 50 | anew live_hosts_raw.txt

# HTTPX — advanced HTTP toolkit with tech detect & status codes
cat all_subdomains.txt | httpx -silent -sc -title -td -ip -o live_hosts_detailed.txt
```

### 2.2 Port Scanning (Nmap, Naabu, Rustscan)

```bash
# === NMAP (Standard) ===
# Quick scan — top 1000 ports
nmap -sV -sC -oN nmap_quick.txt <TARGET>

# Full TCP scan — semua 65535 port
nmap -p- -sV -sC -oN nmap_full_tcp.txt <TARGET>

# === RUSTSCAN (Sangat Cepat) ===
# Scan port dengan kecepatan tinggi lalu serahkan ke nmap untuk enumerasi service
rustscan -a <TARGET> --ulimit 5000 -- -sV -sC -oN rustscan_output.txt

# === NAABU (Go-based Port Scanner) ===
# Scan port aktif dari list host
naabu -l live_hosts_raw.txt -rate 1000 -top-ports 1000 -o active_ports.txt

# Scan semua port naabu
naabu -host <TARGET> -p - -o naabu_full.txt
```

### 2.3 Directory & File Bruteforcing (FFUF, Gobuster, Dirb, Dirsearch, Dirhunt)

```bash
# === FFUF (Tercepat) ===
# Directory discovery — common.txt
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o ffuf_common.json

# File extension bruteforce
ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.js,.txt,.bak,.old,.zip,.sql,.xml,.json,.yml,.env,.config -mc 200,301,302,403

# === GOBUSTER ===
# Directory mode
gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/common.txt -o gobuster_results.txt -t 50

# === DIRB ===
# Default scan
dirb https://example.com /usr/share/seclists/Discovery/Web-Content/common.txt -o dirb_results.txt

# === DIRSEARCH ===
# Advanced web path scanner
dirsearch -u https://example.com -e php,html,js,json,txt,zip,sql -i 200,301,302 -t 50 -o dirsearch_results.txt

# === DIRHUNT ===
# Search directories without brute-forcing (based on link analysis and common patterns)
dirhunt https://example.com --stdout > dirhunt_results.txt
```

### 2.4 Technology Fingerprinting

```bash
# WhatWeb — identify technologies
whatweb https://example.com -v
whatweb --aggression 3 https://example.com

# Nmap HTTP scripts
nmap --script http-headers,http-server-header,http-title -p 80,443 <TARGET>

# Curl — header inspection manual
curl -I -L https://example.com
curl -s -D - https://example.com -o /dev/null

# Check security headers
curl -s -I https://example.com | grep -iE "x-frame|x-content|x-xss|strict-transport|content-security|referrer-policy|permissions-policy|x-permitted"
```

### 2.5 Web Application Mapping & Crawling (Katana, Hakrawler, GAU, Waybackurls, ParamSpider, Arjun, Unfurl, Urldedupe, Anew)

```bash
# === CRAWLING & SPIDERING ===

# Katana — Next-gen web crawler
katana -u https://example.com -jc -d 3 -o katana_urls.txt

# Hakrawler — Fast web crawler
echo "https://example.com" | hakrawler -d 3 > hakrawler_urls.txt

# === URL GATHERING FROM ARCHIVES ===

# GAU (GetAllUrls) — fetch archive URLs
gau example.com --subs --threads 10 > gau_urls.txt

# Waybackurls — fetch from wayback machine
waybackurls example.com > wayback_urls.txt

# Gabungkan semua URL dan simpan yang unik menggunakan anew
cat katana_urls.txt hakrawler_urls.txt gau_urls.txt wayback_urls.txt | anew all_urls.txt

# === URL PARSING & DEDUPLICATION ===

# Unfurl — format/extract parts of URLs (e.g. keys/parameters)
cat all_urls.txt | unfurl keys | anew all_parameters.txt

# Urldedupe — remove duplicate URLs with same parameters
urldedupe -u all_urls.txt > unique_param_urls.txt

# === PARAMETER MINING & DISCOVERY ===

# ParamSpider — mine parameters for a domain from archives (excludes static assets)
python3 paramspider.py -d example.com -o paramspider_urls.txt

# Arjun — find hidden HTTP parameters
arjun -u https://example.com/page.php -m GET -oT arjun_params.txt
arjun -u https://example.com/api/endpoint -m POST --json
```

---

## 3. Wordlist Reference (SecLists)

### Path Penting di `/usr/share/seclists/`

| Kategori | Path | Deskripsi |
|---|---|---|
| **DNS Subdomain** | `Discovery/DNS/subdomains-top1million-5000.txt` | Top 5000 subdomain |
| **Web Dirs (small)** | `Discovery/Web-Content/common.txt` | Wordlist umum |
| **Web Dirs (medium)** | `Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt` | Medium wordlist |
| **Web Dirs (big)** | `Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt` | Big wordlist |
| **API Endpoints** | `Discovery/Web-Content/api/` | API specific wordlists |
| **Parameters** | `Discovery/Web-Content/burp-parameter-names.txt` | Burp parameter names |
| **Passwords** | `Passwords/` | Password wordlists |
| **Usernames** | `Usernames/` | Username wordlists |

---

## 4. Output & Dokumentasi

Setelah recon selesai, dokumentasikan temuan:

```
📋 Reconnaissance Report:
- Target          : [domain/IP]
- Subdomains      : [jumlah ditemukan, file: all_subdomains.txt]
- Open Ports      : [daftar port & service]
- Technologies    : [web server, framework, CMS, bahasa]
- Directories     : [path menarik yang ditemukan]
- Entry Points    : [parameter, form, API endpoint]
- Informasi Publik: [email, leak, credential exposure]
- Next Step       : Lanjut ke Fase 3 — Scanning & Enumeration
```
