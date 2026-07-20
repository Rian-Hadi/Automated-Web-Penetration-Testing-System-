# 📝 Template Laporan Vulnerability

Dokumen ini berisi template standar untuk mendokumentasikan temuan vulnerability.
Format kompatibel dengan platform bug bounty (HackerOne, Bugcrowd) dan laporan pentest profesional.

---

## 1. Template Laporan Vulnerability (Single Finding)

```markdown
# [Severity] Vulnerability Title — Short Description

## Summary
[Deskripsi singkat vulnerability dalam 1-2 kalimat. Jelaskan apa yang ditemukan dan dampaknya.]

## Severity
- **Rating**: [Critical / High / Medium / Low / Informational]
- **CVSS v3.1 Score**: [0.0 - 10.0]
- **CVSS Vector**: [AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H]
- **CWE ID**: [CWE-XXX]
- **OWASP Category**: [OWASP Top 10 - A01:2021 Broken Access Control, etc.]
- **WSTG ID**: [WSTG-INPV-XX]

## Affected Asset
- **URL/Endpoint**: `https://example.com/vulnerable/endpoint`
- **Parameter**: `id` (GET/POST/Cookie/Header)
- **Method**: GET / POST / PUT / DELETE

## Description
[Deskripsi teknis detail tentang vulnerability:
- Apa penyebabnya (root cause)
- Bagaimana bisa dieksploitasi
- Dalam konteks apa vulnerability ini berbahaya]

## Steps to Reproduce (PoC)

### Prerequisites
- [Browser / Tool yang dibutuhkan]
- [Account / credential yang dibutuhkan]

### Steps
1. Navigate ke `https://example.com/page`
2. Intercept request menggunakan Burp Suite
3. Modify parameter `id` menjadi: `[PAYLOAD]`
4. Forward request
5. Observe response menunjukkan [hasil eksploitasi]

### HTTP Request
```http
GET /vulnerable/endpoint?id=PAYLOAD HTTP/1.1
Host: example.com
Cookie: session=abc123
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
```

### HTTP Response
```http
HTTP/1.1 200 OK
Content-Type: text/html

[Response body yang menunjukkan vulnerability]
```

### Screenshot / Evidence
[Sertakan screenshot atau recording yang membuktikan vulnerability]

## Impact
[Jelaskan dampak nyata dari vulnerability ini:
- Apa yang bisa dilakukan attacker?
- Data apa yang bisa diakses/diubah/dihapus?
- Berapa banyak user yang terpengaruh?
- Apakah bisa di-chain dengan vulnerability lain?]

### Attack Scenario
1. Attacker mengirimkan [payload/link] ke victim
2. Victim [membuka link / mengisi form / dll]
3. Attacker mendapatkan [session/data/akses]

## Remediation
[Rekomendasi perbaikan yang spesifik dan actionable:]

1. **[Perbaikan Utama]**: [Deskripsi teknis perbaikan]
   ```python
   # Contoh kode perbaikan
   sanitized_input = escape(user_input)
   ```
2. **[Perbaikan Tambahan]**: [Defense in depth]
3. **[Best Practice]**: [Referensi ke OWASP ASVS / standar keamanan]

### References
- [OWASP - Vulnerability Name](https://owasp.org/...)
- [CWE-XXX](https://cwe.mitre.org/data/definitions/XXX.html)
- [Relevant blog/research]
```

---

## 2. CVSS v3.1 Quick Scoring Guide

### Base Metrics

| Metric | Value | Score Impact |
|---|---|---|
| **Attack Vector (AV)** | Network (N) / Adjacent (A) / Local (L) / Physical (P) | N = highest |
| **Attack Complexity (AC)** | Low (L) / High (H) | L = higher |
| **Privileges Required (PR)** | None (N) / Low (L) / High (H) | N = highest |
| **User Interaction (UI)** | None (N) / Required (R) | N = higher |
| **Scope (S)** | Unchanged (U) / Changed (C) | C = higher |
| **Confidentiality (C)** | None (N) / Low (L) / High (H) | H = highest |
| **Integrity (I)** | None (N) / Low (L) / High (H) | H = highest |
| **Availability (A)** | None (N) / Low (L) / High (H) | H = highest |

### Severity Ranges

| Score | Severity |
|---|---|
| 9.0 - 10.0 | 🔴 Critical |
| 7.0 - 8.9 | 🟠 High |
| 4.0 - 6.9 | 🟡 Medium |
| 0.1 - 3.9 | 🟢 Low |
| 0.0 | ⚪ Informational |

### Common CVSS Vectors per Vulnerability Type

| Vulnerability | Typical CVSS Vector | Score |
|---|---|---|
| **RCE (unauthenticated)** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| **SQLi (data dump)** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| **SSRF (cloud metadata)** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N | 8.6 |
| **Stored XSS** | AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N | 5.4 |
| **Reflected XSS** | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| **IDOR (read)** | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 |
| **IDOR (write)** | AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N | 6.5 |
| **CSRF** | AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N | 6.5 |
| **Open Redirect** | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| **Info Disclosure** | AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N | 5.3 |
| **Missing Security Headers** | AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N | 5.3 |

---

## 3. CWE Reference per Vulnerability Type

| Vulnerability | CWE ID | OWASP Top 10 2021 |
|---|---|---|
| SQL Injection | CWE-89 | A03: Injection |
| XSS (Reflected) | CWE-79 | A03: Injection |
| XSS (Stored) | CWE-79 | A03: Injection |
| Command Injection | CWE-78 | A03: Injection |
| XXE | CWE-611 | A05: Security Misconfiguration |
| SSRF | CWE-918 | A10: Server-Side Request Forgery |
| IDOR / BOLA | CWE-639 | A01: Broken Access Control |
| Path Traversal / LFI | CWE-22 | A01: Broken Access Control |
| CSRF | CWE-352 | A01: Broken Access Control |
| Open Redirect | CWE-601 | A01: Broken Access Control |
| Broken Authentication | CWE-287 | A07: Identification & Auth Failures |
| Session Fixation | CWE-384 | A07: Identification & Auth Failures |
| Insecure Deserialization | CWE-502 | A08: Software & Data Integrity |
| Security Misconfiguration | CWE-16 | A05: Security Misconfiguration |
| Sensitive Data Exposure | CWE-200 | A02: Cryptographic Failures |

---

## 4. Template Laporan Pentest (Full Report)

```markdown
# 🛡️ Penetration Test Report

## Informasi Proyek
| Item | Detail |
|---|---|
| **Client** | [Nama organisasi] |
| **Target** | [Domain / IP / aplikasi] |
| **Tester** | [Nama penguji] |
| **Tanggal Test** | [DD/MM/YYYY — DD/MM/YYYY] |
| **Jenis Test** | [Black Box / Grey Box / White Box] |
| **Methodology** | OWASP Web Security Testing Guide (WSTG) |

## Executive Summary
[Ringkasan eksekutif non-teknis untuk management:
- Berapa vulnerability ditemukan per severity
- Risiko utama yang harus segera ditangani
- Rekomendasi prioritas]

## Scope & Rules of Engagement
- **In-Scope**: [daftar target yang diuji]
- **Out-of-Scope**: [daftar target yang dikecualikan]
- **Restrictions**: [batasan testing: no DoS, specific time window, dll]

## Ringkasan Temuan

| # | Vulnerability | Severity | CVSS | Status |
|---|---|---|---|---|
| 1 | [Nama Vuln] | Critical | 9.8 | Open |
| 2 | [Nama Vuln] | High | 7.5 | Open |
| 3 | [Nama Vuln] | Medium | 5.4 | Open |
| ... | ... | ... | ... | ... |

### Statistik Severity
| Severity | Jumlah |
|---|---|
| 🔴 Critical | X |
| 🟠 High | X |
| 🟡 Medium | X |
| 🟢 Low | X |
| ⚪ Info | X |
| **Total** | **XX** |

## Detail Temuan
[Masukkan setiap vulnerability menggunakan Template Single Finding di atas]

### Finding 1: [Vulnerability Title]
[... detail finding ...]

### Finding 2: [Vulnerability Title]
[... detail finding ...]

## Metodologi Testing
Daftar pengujian yang dilakukan berdasarkan OWASP WSTG:

| WSTG Category | Status | Temuan |
|---|---|---|
| WSTG-INFO: Information Gathering | ✅ Done | X findings |
| WSTG-CONF: Configuration Testing | ✅ Done | X findings |
| WSTG-IDNT: Identity Management | ✅ Done | X findings |
| WSTG-ATHN: Authentication Testing | ✅ Done | X findings |
| WSTG-ATHZ: Authorization Testing | ✅ Done | X findings |
| WSTG-SESS: Session Management | ✅ Done | X findings |
| WSTG-INPV: Input Validation | ✅ Done | X findings |
| WSTG-BUSL: Business Logic | ✅ Done | X findings |
| WSTG-CLNT: Client-side Testing | ✅ Done | X findings |

## Tools yang Digunakan
| Tool | Versi | Tujuan |
|---|---|---|
| Nmap | X.X | Port scanning & service detection |
| Nuclei | X.X | Automated vulnerability scanning |
| Burp Suite | X.X | Manual testing & interception |
| SQLMap | X.X | SQL injection testing |
| Ffuf | X.X | Directory & parameter fuzzing |
| [dll] | | |

## Rekomendasi Prioritas

### Immediate (0-7 hari)
1. [Perbaikan Critical/High severity]

### Short-term (1-4 minggu)
1. [Perbaikan Medium severity]

### Long-term (1-3 bulan)
1. [Improvement & hardening]

## Appendix
- Raw scan results
- Full HTTP request/response logs
- Additional evidence
```

---

## 5. Bug Bounty Platform Format

### HackerOne Report Format

```markdown
## Summary
[1-2 kalimat ringkasan]

## Steps To Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Supporting Material/References
- [Screenshot]
- [Video PoC]

## Impact
[Dampak dari vulnerability]
```

### Bugcrowd Report Format

```markdown
## Title
[Severity] - [Vulnerability Type] di [Endpoint]

## URL
https://example.com/vulnerable/endpoint

## Description
[Deskripsi vulnerability]

## Steps to Reproduce
1. [Step 1]
2. [Step 2]

## Proof of Concept
[Screenshot / HTTP request-response]

## Suggested Fix
[Rekomendasi perbaikan]
```
