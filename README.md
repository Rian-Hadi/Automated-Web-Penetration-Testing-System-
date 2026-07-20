# Automated Web Penetration Testing System

Sistem Pengujian Penetrasi Web Multi-Agen berbasis CrewAI yang mengintegrasikan berbagai alat keamanan siber profesional untuk mengotomatiskan siklus hidup pentest secara sequential (berurutan) dari perencanaan hingga pembuatan laporan.

---
<<<<<<< HEAD
 
## Arsitektur & Teknologi Utama
=======

## Arsitektur and Teknologi Utama
>>>>>>> 4ff4402 (Configure dynamic pathing for RAG env and knowledge minification scripts, remove hardcoded user directory paths, and push updates)
Sistem ini dibangun dengan stack teknologi modern:
1. **Core Orchestration**: Python 3 and CrewAI framework (Sequential Process).
2. **AI and LLM Integration**: Mendukung MiMo API (Xiaomi) dengan model mimo-v2.5-pro (default) atau OpenAI API standar, dikonfigurasi secara dinamis dan aman.
3. **Environment and Security**: Menggunakan library python-dotenv untuk mengelola konfigurasi lokal melalui .env tanpa mengekspos kunci API pada repositori publik.
4. **Keamanan Kredensial**: Dilengkapi dengan mekanisme prompt interaktif di CLI untuk meminta API Key dan Model LLM jika belum dikonfigurasi di environment lokal.

---

## 5 Fase Pentest, Agen, dan Alat (Tools)

Sistem ini menjalankan alur kerja sequential di mana output dari satu fase otomatis menjadi konteks masukan untuk fase berikutnya.

<<<<<<< HEAD
### 1. Fase Planning & Scoping
* **Agen**: `Security Consultant & Scope Planner`
=======
### 1. Fase Planning and Scoping
* **Agen**: Security Consultant and Scope Planner
>>>>>>> 4ff4402 (Configure dynamic pathing for RAG env and knowledge minification scripts, remove hardcoded user directory paths, and push updates)
* **Deskripsi**: Fase awal untuk memvalidasi scope domain/URL target, memastikan target dapat dijangkau (reachable), dan mengidentifikasi keberadaan Web Application Firewall (WAF) sebelum memulai pemindaian aktif.
* **Alat Keamanan**:
  - scope_validator: Melakukan DNS lookup untuk memetakan domain ke IP Address.
  - target_reachability: Mengirim probe HTTP, memindai port web dasar (80/443), dan mendeteksi jenis WAF.

### 2. Fase Reconnaissance (Information Gathering)
<<<<<<< HEAD
* **Agen**: `OSINT Specialist & Reconnaissance Expert`
=======
* **Agen**: OSINT Specialist and Reconnaissance Expert
>>>>>>> 4ff4402 (Configure dynamic pathing for RAG env and knowledge minification scripts, remove hardcoded user directory paths, and push updates)
* **Deskripsi**: Mengumpulkan informasi sebanyak mungkin tentang target secara pasif dan aktif (OSINT, subdomains, crawling).
* **Alat Keamanan**:
  - subfinder: Menemukan subdomain secara pasif.
  - crtsh: Membaca log Certificate Transparency (CT).
  - httpx: Memvalidasi subdomain yang aktif/live.
  - nmap: Melakukan port scanning dan identifikasi versi service.
  - whatweb: Melakukan fingerprinting teknologi web (CMS, Web Server, Framework).
  - katana and gau: Meng-crawl website dan mengumpulkan daftar URL/endpoint historis.
  - theHarvester: Mengumpulkan data email publik dan info OSINT terkait target.

<<<<<<< HEAD
### 3. Fase Scanning & Enumeration
* **Agen**: `Vulnerability Researcher & Security Scanner`
=======
### 3. Fase Scanning and Enumeration
* **Agen**: Vulnerability Researcher and Security Scanner
>>>>>>> 4ff4402 (Configure dynamic pathing for RAG env and knowledge minification scripts, remove hardcoded user directory paths, and push updates)
* **Deskripsi**: Mencari celah keamanan potensial secara otomatis pada port, endpoint, dan parameter web yang ditemukan.
* **Alat Keamanan**:
  - nuclei: Melakukan vulnerability scan berbasis template (CVE, salah konfigurasi).
  - nikto: Melakukan audit konfigurasi web server umum.
  - ffuf: Melakukan fuzzing direktori dan endpoint sensitif.
  - arjun: Menemukan parameter HTTP tersembunyi yang rentan.
  - gf: Memfilter daftar URL berdasarkan pola kerentanan tertentu (XSS, SQLi, LFI, SSRF).
  - wpscan: Memindai kerentanan khusus pada platform WordPress (jika terdeteksi).
  - security_headers and sslscan: Menganalisis keamanan HTTP Headers dan sertifikat SSL/TLS.

<<<<<<< HEAD
### 4. Fase Exploitation & WAF Bypass
* **Agen**: `Red Team Operator & Exploitation Expert`
=======
### 4. Fase Exploitation and WAF Bypass
* **Agen**: Red Team Operator and Exploitation Expert
>>>>>>> 4ff4402 (Configure dynamic pathing for RAG env and knowledge minification scripts, remove hardcoded user directory paths, and push updates)
* **Deskripsi**: Melakukan verifikasi aktif terhadap kandidat celah keamanan dari fase pemindaian. Jika terdapat pemblokiran oleh WAF, agen akan memformulasikan payload bypass.
* **Alat Keamanan**:
  - dalfox: Pemindai dan verifikator celah XSS (Cross-Site Scripting).
  - sqlmap: Otomatisasi eksploitasi celah SQL Injection.
  - ssrf_tester, lfi_tester, cmdi_tester, ssti_tester: Skrip custom untuk validasi celah SSRF, LFI, Command Injection, dan SSTI.
  - payload_generator and waf_bypass: Menghasilkan payload yang telah diobfuskasi untuk melewati proteksi WAF.

### 5. Fase Reporting and Verification
* **Agen**: Security Report Writer and Verification Specialist
* **Deskripsi**: Fase validasi ganda untuk memastikan laporan bebas dari false positive, menghitung skor tingkat keparahan celah (CVSS), memetakan temuan ke CWE/OWASP Top 10, dan menyusun laporan akhir.
* **Alat Keamanan**:
  - triple_verification: Melakukan pengujian ulang 3x untuk validitas temuan.
  - cvss_scorer: Menghitung skor CVSS v3.1 secara akurat.
  - report_generator: Menyusun dokumen laporan pentest dalam format Markdown (.md) dan JSON yang siap pakai.

---

## Cara Penggunaan

### 1. Persiapan Environment
Salin template konfigurasi .env.example ke .env di folder root proyek Anda:
```bash
cp .env.example .env
```
Isi variabel di dalam file .env dengan kredensial API Anda (opsional, jika dikosongkan sistem akan menanyakan secara interaktif saat dijalankan).

### 2. Instalasi Dependensi
Jalankan skrip instalasi untuk memasang semua alat keamanan sistem yang diperlukan:
```bash
bash scripts/core/install_missing_tools.sh
```

### 3. Menjalankan Pipeline Pentest
Jalankan file entrypoint utama (contoh: run.py atau script eksekusi):
```bash
python3 scripts/crewai_pentest/run.py
```
Saat pertama kali berjalan tanpa kredensial di .env, Anda akan dipandu oleh CLI:
1. Masukkan API Key Anda (misal: Xiaomi API Key atau OpenAI API Key):
2. Masukkan model LLM yang diinginkan [default: mimo-v2.5-pro]:

Semua hasil analisis dan laporan akhir akan disimpan secara terstruktur di bawah direktori output domain target di:
`results/<target_domain>/` (di dalam folder root proyek ini)
