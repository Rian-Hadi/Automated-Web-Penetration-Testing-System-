#!/usr/bin/env python3
"""
PoC Report Generator — Auto-generate vulnerability report dalam format Markdown.

Menghasilkan laporan PoC (Proof of Concept) yang siap submit ke platform
bug bounty (HackerOne, Bugcrowd) atau sebagai bagian dari laporan pentest.

Usage:
    # Interactive mode
    python scripts/poc_report_generator.py

    # From command line arguments
    python scripts/poc_report_generator.py \
        --title "Stored XSS via Profile Bio" \
        --vuln-type xss \
        --severity high \
        --url "https://example.com/profile" \
        --parameter "bio" \
        --method POST \
        --payload '<script>alert(document.domain)</script>' \
        --impact "Attacker can steal session cookies of other users" \
        --steps "1. Login to account\\n2. Go to profile settings\\n3. Insert XSS payload in bio field\\n4. Save profile\\n5. Visit profile page" \
        --output report.md

    # From JSON file
    python scripts/poc_report_generator.py --from-json finding.json --output report.md

    # Generate full pentest report
    python scripts/poc_report_generator.py --full-report --from-json findings.json --output pentest_report.md
"""

import argparse
import json
import sys
import os
from datetime import datetime, timezone


# ═══════════════════════════════════════════════════════════
# CVSS & CWE DATABASE
# ═══════════════════════════════════════════════════════════

VULN_DATABASE = {
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "cwe": "CWE-79",
        "owasp": "A03:2021 — Injection",
        "wstg": "WSTG-INPV-01",
        "cvss_vectors": {
            "reflected": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "score": 6.1,
                "severity": "Medium",
            },
            "stored": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
                "score": 5.4,
                "severity": "Medium",
            },
            "dom": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "score": 6.1,
                "severity": "Medium",
            },
        },
        "remediation": [
            "Implementasikan output encoding yang sesuai dengan konteks (HTML, JavaScript, URL, CSS)",
            "Gunakan Content Security Policy (CSP) header yang ketat",
            "Validasi dan sanitasi semua input dari user di server-side",
            "Gunakan framework yang secara default melakukan auto-escaping (React, Angular, Vue)",
            "Set HttpOnly dan Secure flag pada cookie session",
        ],
    },
    "sqli": {
        "name": "SQL Injection",
        "cwe": "CWE-89",
        "owasp": "A03:2021 — Injection",
        "wstg": "WSTG-INPV-05",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "score": 9.1,
                "severity": "Critical",
            },
        },
        "remediation": [
            "Gunakan Parameterized Queries / Prepared Statements untuk SEMUA query SQL",
            "Implementasikan input validation dengan whitelist approach",
            "Gunakan ORM (Object-Relational Mapping) yang secara default aman",
            "Terapkan principle of least privilege pada database user",
            "Implementasikan WAF sebagai defense-in-depth",
        ],
    },
    "ssrf": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwe": "CWE-918",
        "owasp": "A10:2021 — Server-Side Request Forgery",
        "wstg": "WSTG-INPV-19",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "score": 8.6,
                "severity": "High",
            },
        },
        "remediation": [
            "Validasi dan sanitasi semua URL yang diterima dari user",
            "Implementasikan allowlist untuk domain/IP yang diizinkan",
            "Block akses ke internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254)",
            "Disable protocol selain HTTP/HTTPS (block file://, dict://, gopher://)",
            "Gunakan IMDSv2 untuk cloud metadata endpoint (AWS)",
        ],
    },
    "xxe": {
        "name": "XML External Entity (XXE)",
        "cwe": "CWE-611",
        "owasp": "A05:2021 — Security Misconfiguration",
        "wstg": "WSTG-INPV-07",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "score": 7.5,
                "severity": "High",
            },
        },
        "remediation": [
            "Disable XML External Entity processing di XML parser",
            "Gunakan format data yang lebih sederhana (JSON) jika memungkinkan",
            "Patch dan update semua XML processor dan library",
            "Implementasikan server-side input validation dan sanitization",
            "Disable DTD processing sepenuhnya jika tidak dibutuhkan",
        ],
    },
    "lfi": {
        "name": "Local File Inclusion / Path Traversal",
        "cwe": "CWE-22",
        "owasp": "A01:2021 — Broken Access Control",
        "wstg": "WSTG-INPV-12",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "score": 7.5,
                "severity": "High",
            },
        },
        "remediation": [
            "Gunakan whitelist untuk file yang boleh diakses",
            "Jangan gunakan input user langsung dalam file path",
            "Gunakan chroot jail atau container untuk membatasi akses filesystem",
            "Validasi dan normalisasi path — hapus ../ dan variasi encoding-nya",
            "Implementasikan proper access control pada file system level",
        ],
    },
    "cmdi": {
        "name": "OS Command Injection",
        "cwe": "CWE-78",
        "owasp": "A03:2021 — Injection",
        "wstg": "WSTG-INPV-12",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
                "severity": "Critical",
            },
        },
        "remediation": [
            "HINDARI menjalankan OS command dari input user — gunakan API/library native",
            "Jika harus menjalankan command, gunakan parameterized approach (subprocess dengan list, bukan string)",
            "Implementasikan strict input validation dengan whitelist karakter",
            "Jalankan aplikasi dengan privilege minimum",
            "Gunakan sandboxing / containerization",
        ],
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR/BOLA)",
        "cwe": "CWE-639",
        "owasp": "A01:2021 — Broken Access Control",
        "wstg": "WSTG-AUTH-04",
        "cvss_vectors": {
            "read": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "score": 6.5,
                "severity": "Medium",
            },
            "write": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
                "score": 6.5,
                "severity": "Medium",
            },
        },
        "remediation": [
            "Implementasikan proper authorization check di setiap endpoint",
            "Gunakan indirect reference maps (bukan sequential ID)",
            "Validasi ownership: pastikan user yang request adalah pemilik resource",
            "Gunakan UUID/GUID sebagai pengganti sequential integer ID",
            "Implementasikan rate limiting untuk mencegah enumeration",
        ],
    },
    "csrf": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "cwe": "CWE-352",
        "owasp": "A01:2021 — Broken Access Control",
        "wstg": "WSTG-SESS-05",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
                "score": 6.5,
                "severity": "Medium",
            },
        },
        "remediation": [
            "Implementasikan anti-CSRF token (synchronizer token pattern)",
            "Set SameSite attribute pada cookies (Strict atau Lax)",
            "Verifikasi Origin/Referer header di server-side",
            "Gunakan custom request headers untuk API (CSRF token di header)",
            "Require re-authentication untuk operasi sensitif",
        ],
    },
    "open_redirect": {
        "name": "Open Redirect",
        "cwe": "CWE-601",
        "owasp": "A01:2021 — Broken Access Control",
        "wstg": "WSTG-CLNT-04",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "score": 6.1,
                "severity": "Medium",
            },
        },
        "remediation": [
            "Jangan gunakan URL dari user input untuk redirect",
            "Gunakan whitelist domain yang diizinkan untuk redirect",
            "Gunakan mapping/lookup table — redirect berdasarkan key, bukan URL langsung",
            "Validasi URL: pastikan hanya redirect ke domain sendiri",
            "Tampilkan warning page sebelum redirect ke external URL",
        ],
    },
    "misconfig": {
        "name": "Security Misconfiguration",
        "cwe": "CWE-16",
        "owasp": "A05:2021 — Security Misconfiguration",
        "wstg": "WSTG-CONF",
        "cvss_vectors": {
            "default": {
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "score": 5.3,
                "severity": "Medium",
            },
        },
        "remediation": [
            "Implementasikan security headers yang lengkap (HSTS, CSP, X-Frame-Options, dll)",
            "Hapus informasi versi dari response headers (Server, X-Powered-By)",
            "Disable fitur dan service yang tidak digunakan",
            "Gunakan secure defaults pada semua konfigurasi",
            "Lakukan security hardening secara berkala",
        ],
    },
}


# ═══════════════════════════════════════════════════════════
# REPORT GENERATION
# ═══════════════════════════════════════════════════════════

def get_severity_emoji(severity: str) -> str:
    """Get emoji untuk severity level."""
    mapping = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "informational": "⚪",
        "info": "⚪",
    }
    return mapping.get(severity.lower(), "⚪")


def generate_single_report(finding: dict) -> str:
    """Generate Markdown report untuk satu vulnerability."""
    vuln_type = finding.get("vuln_type", "").lower()
    vuln_info = VULN_DATABASE.get(vuln_type, {})

    # Determine CVSS info
    subtype = finding.get("subtype", "default")
    cvss_info = {}
    if vuln_info and "cvss_vectors" in vuln_info:
        cvss_vectors = vuln_info["cvss_vectors"]
        cvss_info = cvss_vectors.get(subtype, cvss_vectors.get("default", {}))

    severity = finding.get("severity", cvss_info.get("severity", "Medium"))
    cvss_score = finding.get("cvss_score", cvss_info.get("score", "N/A"))
    cvss_vector = finding.get("cvss_vector", cvss_info.get("vector", "N/A"))
    emoji = get_severity_emoji(severity)

    title = finding.get("title", f"{vuln_info.get('name', 'Vulnerability')} di {finding.get('url', 'N/A')}")
    cwe = finding.get("cwe", vuln_info.get("cwe", "N/A"))
    owasp = finding.get("owasp", vuln_info.get("owasp", "N/A"))
    wstg = finding.get("wstg", vuln_info.get("wstg", "N/A"))

    # Build steps
    steps = finding.get("steps", "")
    if isinstance(steps, list):
        steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))
    elif isinstance(steps, str) and "\\n" in steps:
        steps_text = steps.replace("\\n", "\n")
    else:
        steps_text = steps or "1. [Langkah 1]\n2. [Langkah 2]\n3. [Langkah 3]"

    # Build remediation
    remediation = finding.get("remediation", vuln_info.get("remediation", []))
    if isinstance(remediation, list):
        remediation_text = "\n".join(f"{i+1}. {r}" for i, r in enumerate(remediation))
    else:
        remediation_text = remediation

    report = f"""# {emoji} [{severity}] {title}

## Summary
{finding.get("description", f"Ditemukan vulnerability {vuln_info.get('name', vuln_type)} pada target.")}

## Severity
| Metric | Value |
|---|---|
| **Rating** | {emoji} {severity} |
| **CVSS v3.1 Score** | {cvss_score} |
| **CVSS Vector** | `{cvss_vector}` |
| **CWE** | [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html) |
| **OWASP** | {owasp} |
| **WSTG ID** | {wstg} |

## Affected Asset
| Item | Detail |
|---|---|
| **URL/Endpoint** | `{finding.get("url", "N/A")}` |
| **Parameter** | `{finding.get("parameter", "N/A")}` |
| **Method** | {finding.get("method", "GET")} |

## Description
{finding.get("description", f"Pada endpoint yang disebutkan, parameter `{finding.get('parameter', 'N/A')}` rentan terhadap serangan {vuln_info.get('name', vuln_type)}. Penyerang dapat memanfaatkan vulnerability ini untuk {finding.get('impact', 'mengakses data atau mengeksekusi kode tidak sah')}.")}

## Steps to Reproduce (PoC)

### Prerequisites
- Browser modern (Chrome/Firefox)
- {finding.get("prerequisites", "Akun user terdaftar (jika dibutuhkan)")}

### Steps
{steps_text}

### Payload
```
{finding.get("payload", "[PAYLOAD]")}
```

### HTTP Request
```http
{finding.get("method", "GET")} {finding.get("url", "/endpoint")} HTTP/1.1
Host: {finding.get("host", "example.com")}
{finding.get("headers", "Cookie: session=<session_value>")}

{finding.get("body", "")}
```

## Impact
{finding.get("impact", "[Jelaskan dampak nyata dari vulnerability ini]")}

### Attack Scenario
{finding.get("attack_scenario", "1. Attacker mengirimkan payload ke target\\n2. Payload dieksekusi di browser victim\\n3. Attacker mendapatkan akses ke data sensitif")}

## Remediation
{remediation_text}

### References
- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace("CWE-", "")}.html)
- [OWASP — {owasp}](https://owasp.org/Top10/)
- [OWASP WSTG — {wstg}](https://owasp.org/www-project-web-security-testing-guide/)

---
*Report generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}*
"""
    return report


def generate_full_pentest_report(findings: list, meta: dict = None) -> str:
    """Generate full pentest report dari list of findings."""
    meta = meta or {}

    # Count severities
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        vuln_type = f.get("vuln_type", "").lower()
        vuln_info = VULN_DATABASE.get(vuln_type, {})
        subtype = f.get("subtype", "default")
        cvss_info = {}
        if vuln_info and "cvss_vectors" in vuln_info:
            cvss_vectors = vuln_info["cvss_vectors"]
            cvss_info = cvss_vectors.get(subtype, cvss_vectors.get("default", {}))
        sev = f.get("severity", cvss_info.get("severity", "Medium"))
        if sev in severity_count:
            severity_count[sev] += 1

    # Build findings table
    findings_table = ""
    for i, f in enumerate(findings, 1):
        vuln_type = f.get("vuln_type", "").lower()
        vuln_info = VULN_DATABASE.get(vuln_type, {})
        subtype = f.get("subtype", "default")
        cvss_info = {}
        if vuln_info and "cvss_vectors" in vuln_info:
            cvss_vectors = vuln_info["cvss_vectors"]
            cvss_info = cvss_vectors.get(subtype, cvss_vectors.get("default", {}))

        sev = f.get("severity", cvss_info.get("severity", "Medium"))
        score = f.get("cvss_score", cvss_info.get("score", "N/A"))
        title = f.get("title", vuln_info.get("name", vuln_type))
        emoji = get_severity_emoji(sev)
        findings_table += f"| {i} | {title} | {emoji} {sev} | {score} | Open |\n"

    # Build detail sections
    detail_sections = ""
    for i, f in enumerate(findings, 1):
        detail_sections += f"\n---\n\n## Finding {i}\n\n"
        detail_sections += generate_single_report(f)

    report = f"""# 🛡️ Penetration Test Report

## Informasi Proyek
| Item | Detail |
|---|---|
| **Client** | {meta.get("client", "[Nama Organisasi]")} |
| **Target** | {meta.get("target", "[Domain / IP]")} |
| **Tester** | {meta.get("tester", "[Nama Penguji]")} |
| **Tanggal Test** | {meta.get("date_start", "[DD/MM/YYYY]")} — {meta.get("date_end", "[DD/MM/YYYY]")} |
| **Jenis Test** | {meta.get("test_type", "Grey Box")} |
| **Methodology** | OWASP Web Security Testing Guide (WSTG) |

## Executive Summary
Penetration testing dilakukan pada {meta.get("target", "[target]")} untuk mengidentifikasi vulnerability keamanan.
Testing dilakukan menggunakan metodologi OWASP WSTG.

Ditemukan total **{len(findings)} vulnerability** dengan rincian severity sebagai berikut:

## Ringkasan Temuan

| # | Vulnerability | Severity | CVSS | Status |
|---|---|---|---|---|
{findings_table}

### Statistik Severity
| Severity | Jumlah |
|---|---|
| 🔴 Critical | {severity_count["Critical"]} |
| 🟠 High | {severity_count["High"]} |
| 🟡 Medium | {severity_count["Medium"]} |
| 🟢 Low | {severity_count["Low"]} |
| ⚪ Informational | {severity_count["Informational"]} |
| **Total** | **{len(findings)}** |

## Rekomendasi Prioritas

### Immediate (0-7 hari)
Perbaiki semua vulnerability dengan severity **Critical** dan **High**:
{chr(10).join(f"- {f.get('title', VULN_DATABASE.get(f.get('vuln_type', '').lower(), {}).get('name', 'Unknown'))}" for f in findings if f.get('severity', '').lower() in ['critical', 'high'])}

### Short-term (1-4 minggu)
Perbaiki semua vulnerability dengan severity **Medium**:
{chr(10).join(f"- {f.get('title', VULN_DATABASE.get(f.get('vuln_type', '').lower(), {}).get('name', 'Unknown'))}" for f in findings if f.get('severity', '').lower() == 'medium')}

### Long-term (1-3 bulan)
- Implementasikan security headers yang lengkap
- Lakukan security code review
- Implementasikan automated security testing di CI/CD pipeline

{detail_sections}

---
*Report generated: {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}*
*Methodology: OWASP Web Security Testing Guide (WSTG)*
"""
    return report


# ═══════════════════════════════════════════════════════════
# INTERACTIVE MODE
# ═══════════════════════════════════════════════════════════

def interactive_mode():
    """Interactive mode untuk mengisi detail vulnerability."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  📝 PoC Report Generator — Interactive Mode                 ║
╚══════════════════════════════════════════════════════════════╝
""")

    print("Available vulnerability types:")
    for key, info in VULN_DATABASE.items():
        print(f"  [{key}] {info['name']}")

    finding = {}
    finding["vuln_type"] = input("\n🔹 Vulnerability type: ").strip().lower()
    finding["title"] = input("🔹 Report title: ").strip()
    finding["url"] = input("🔹 Affected URL/endpoint: ").strip()
    finding["parameter"] = input("🔹 Vulnerable parameter: ").strip()
    finding["method"] = input("🔹 HTTP method (GET/POST/PUT/DELETE): ").strip().upper() or "GET"
    finding["payload"] = input("🔹 Payload used: ").strip()
    finding["description"] = input("🔹 Description: ").strip()
    finding["impact"] = input("🔹 Impact: ").strip()

    severity_input = input("🔹 Severity override (or press Enter for auto): ").strip()
    if severity_input:
        finding["severity"] = severity_input

    print("\n🔹 Steps to reproduce (enter each step, empty line to finish):")
    steps = []
    while True:
        step = input(f"   Step {len(steps)+1}: ").strip()
        if not step:
            break
        steps.append(step)
    finding["steps"] = steps

    return finding


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="📝 PoC Report Generator — Auto-generate vulnerability reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python poc_report_generator.py

  # CLI mode
  python poc_report_generator.py --title "Stored XSS" --vuln-type xss \\
    --url "https://example.com/profile" --parameter "bio" \\
    --payload "<script>alert(1)</script>" --output report.md

  # From JSON
  python poc_report_generator.py --from-json finding.json --output report.md

  # Full pentest report
  python poc_report_generator.py --full-report --from-json findings.json --output pentest_report.md

  # List vulnerability types
  python poc_report_generator.py --list-types
        """,
    )
    parser.add_argument("--title", help="Vulnerability title")
    parser.add_argument("--vuln-type", help="Vulnerability type (xss, sqli, ssrf, etc.)")
    parser.add_argument("--subtype", default="default", help="Vulnerability subtype (reflected, stored, etc.)")
    parser.add_argument("--severity", help="Override severity (Critical/High/Medium/Low)")
    parser.add_argument("--url", help="Affected URL/endpoint")
    parser.add_argument("--parameter", help="Vulnerable parameter")
    parser.add_argument("--method", default="GET", help="HTTP method")
    parser.add_argument("--payload", help="Payload used")
    parser.add_argument("--description", help="Vulnerability description")
    parser.add_argument("--impact", help="Impact description")
    parser.add_argument("--steps", help="Steps to reproduce (separated by \\n)")
    parser.add_argument("--from-json", help="Load finding(s) from JSON file")
    parser.add_argument("--output", "-o", help="Output Markdown file")
    parser.add_argument("--full-report", action="store_true",
                        help="Generate full pentest report (requires --from-json with array)")
    parser.add_argument("--list-types", action="store_true",
                        help="List all vulnerability types")
    parser.add_argument("--format", choices=["standard", "hackerone", "bugcrowd"],
                        default="standard", help="Report format (default: standard)")

    args = parser.parse_args()

    if args.list_types:
        print("\n📋 Available Vulnerability Types:\n")
        for key, info in VULN_DATABASE.items():
            cvss_info = list(info["cvss_vectors"].values())[0]
            emoji = get_severity_emoji(cvss_info["severity"])
            print(f"  {emoji} [{key}] {info['name']}")
            print(f"     CWE: {info['cwe']} | OWASP: {info['owasp']} | WSTG: {info['wstg']}")
            print(f"     Default CVSS: {cvss_info['score']} ({cvss_info['severity']})")
            if len(info["cvss_vectors"]) > 1:
                subtypes = ", ".join(info["cvss_vectors"].keys())
                print(f"     Subtypes: {subtypes}")
            print()
        return

    # Load from JSON
    if args.from_json:
        if not os.path.exists(args.from_json):
            print(f"[ERROR] File not found: {args.from_json}")
            sys.exit(1)

        with open(args.from_json, "r") as f:
            data = json.load(f)

        if args.full_report:
            if isinstance(data, dict):
                findings = data.get("findings", [data])
                meta = data.get("meta", {})
            elif isinstance(data, list):
                findings = data
                meta = {}
            else:
                print("[ERROR] JSON must be an array of findings or an object with 'findings' key")
                sys.exit(1)

            report = generate_full_pentest_report(findings, meta)
        else:
            if isinstance(data, list):
                data = data[0]
            report = generate_single_report(data)

    elif args.vuln_type:
        # CLI mode
        finding = {
            "vuln_type": args.vuln_type,
            "subtype": args.subtype,
            "title": args.title or "",
            "url": args.url or "",
            "parameter": args.parameter or "",
            "method": args.method or "GET",
            "payload": args.payload or "",
            "description": args.description or "",
            "impact": args.impact or "",
            "steps": args.steps or "",
        }
        if args.severity:
            finding["severity"] = args.severity

        report = generate_single_report(finding)
    else:
        # Interactive mode
        finding = interactive_mode()
        report = generate_single_report(finding)

    # Output
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"\n✅ Report saved to: {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
