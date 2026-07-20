#!/usr/bin/env python3
"""
Recon Automation (Upgraded) — Automasi reconnaissance untuk web penetration testing.

Menjalankan serangkaian tool recon secara berurutan dan menghasilkan
JSON report yang terstruktur. Mendukung integrasi seluruh tools Bug Bounty
dan Security Consulting secara dinamis.

Usage:
    python scripts/recon_automation.py --target example.com
    python scripts/recon_automation.py --target example.com --takeover
    python scripts/recon_automation.py --target example.com --portscan-tool rustscan
    python scripts/recon_automation.py --target example.com --vuln-tools nuclei,dalfox
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs

# Colors for terminal output
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_RED = "\033[91m"
C_BLUE = "\033[94m"
C_BOLD = "\033[1m"
C_END = "\033[0m"

# ═══════════════════════════════════════════════════════════
# HELPERS & UTILITIES
# ═══════════════════════════════════════════════════════════

def print_banner():
    print(f"""{C_BLUE}{C_BOLD}
╔══════════════════════════════════════════════════════════════╗
║      🔍 Advanced Recon Automation — Pentest & Bug Bounty    ║
║      OWASP WSTG-INFO: Reconnaissance Phase                   ║
╚══════════════════════════════════════════════════════════════╝{C_END}""")

def log_info(msg):
    print(f"[{C_BLUE}INFO{C_END}] {msg}")

def log_success(msg):
    print(f"[{C_GREEN}SUCCESS{C_END}] {msg}")

def log_warn(msg):
    print(f"[{C_YELLOW}WARNING{C_END}] {msg}")

def log_error(msg):
    print(f"[{C_RED}ERROR{C_END}] {msg}")

def print_phase(phase: str, description: str):
    print(f"\n{C_BOLD}{'=' * 60}{C_END}")
    print(f"  📡 {C_BLUE}{C_BOLD}{phase}{C_END}: {description}")
    print(f"{C_BOLD}{'=' * 60}{C_END}\n")

def run_cmd(cmd: list, timeout: int = 300, dry_run: bool = False, stdin_data: str = None) -> tuple:
    """Run command dan return (stdout, stderr, returncode)."""
    cmd_str = " ".join(cmd)
    print(f"  [CMD] {cmd_str}")

    if dry_run:
        print(f"  [DRY-RUN] Skipping execution")
        return ("", "", 0)

    try:
        if stdin_data:
            result = subprocess.run(
                cmd, input=stdin_data, capture_output=True, text=True, timeout=timeout
            )
        else:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        return (result.stdout, result.stderr, result.returncode)
    except subprocess.TimeoutExpired:
        log_warn(f"Command timed out after {timeout}s: {cmd[0]}")
        return ("", f"Timeout after {timeout}s", 1)
    except FileNotFoundError:
        log_error(f"Command not found: {cmd[0]}")
        return ("", f"Command not found: {cmd[0]}", 127)

def check_tool(tool: str) -> bool:
    """Check if a tool is available in PATH."""
    return shutil.which(tool) is not None

def run_anew(input_list: list, output_file: str, dry_run: bool = False) -> list:
    """Simulate or call 'anew' to append unique lines to output_file."""
    existing_lines = set()
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            existing_lines = set(line.strip() for line in f if line.strip())

    new_lines = []
    for item in input_list:
        clean_item = item.strip()
        if clean_item and clean_item not in existing_lines:
            new_lines.append(clean_item)
            existing_lines.add(clean_item)

    if not dry_run and new_lines:
        if check_tool("anew"):
            # Call actual anew tool if available
            stdin_data = "\n".join(new_lines) + "\n"
            run_cmd(["anew", output_file], dry_run=dry_run, stdin_data=stdin_data)
        else:
            # Fallback to python file writing
            with open(output_file, 'a') as f:
                for line in new_lines:
                    f.write(line + "\n")
    
    return sorted(list(existing_lines))

def normalize_urls(urls: list) -> list:
    """Normalize and clean URLs (python implementation of normalizer)."""
    normalized = set()
    for url in urls:
        url = url.strip()
        if not url:
            continue
        # Remove trailing slash for root URL, clean port, etc.
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            # Reconstruct clean URL
            path = parsed.path
            if path == "/":
                path = ""
            clean_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            normalized.add(clean_url)
        else:
            normalized.add(url)
    return sorted(list(normalized))

def run_unfurl_keys(urls: list) -> list:
    """Extract query parameters from URLs (python implementation of unfurl)."""
    keys = set()
    for url in urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for key in params.keys():
            keys.add(key)
    return sorted(list(keys))

def run_gf_filter(urls: list, pattern: str) -> list:
    """Filter URLs matching common vulnerability patterns (python fallback for gf)."""
    # Quick regex mappings for gf patterns
    gf_patterns = {
        "xss": re.compile(r"(q=|s=|search=|id=|query=|keyword=|lang=|url=|redirect=|callback=)", re.IGNORECASE),
        "sqli": re.compile(r"(id=|select=|order=|limit=|sort=|query=|category=|type=)", re.IGNORECASE),
        "ssrf": re.compile(r"(url=|dest=|destination=|redirect=|uri=|path=|continue=|next=|to=|out=|view=|image=|file=)", re.IGNORECASE),
        "lfi": re.compile(r"(file=|path=|doc=|page=|folder=|root=|dir=|include=|template=|name=|view=)", re.IGNORECASE),
        "rce": re.compile(r"(cmd=|command=|exec=|run=|ping=|shell=|eval=|process=)", re.IGNORECASE),
        "redirect": re.compile(r"(url=|redirect=|next=|dest=|destination=|to=|out=|uri=|path=|link=)", re.IGNORECASE)
    }
    
    if pattern in gf_patterns:
        rx = gf_patterns[pattern]
        return [url for url in urls if rx.search(url)]
    return urls

# ═══════════════════════════════════════════════════════════
# RECON PIPELINE MODULES
# ═══════════════════════════════════════════════════════════

def dns_lookup(target: str, dry_run: bool = False) -> dict:
    """Basic DNS lookup."""
    print_phase("Phase 1a", f"DNS Lookup — {target}")
    results = {"A": [], "AAAA": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}

    if not check_tool("dig"):
        log_warn("dig is not installed. Skipping DNS lookup.")
        return results

    for record_type in results.keys():
        stdout, _, rc = run_cmd(["dig", "+short", target, record_type], dry_run=dry_run)
        if rc == 0 and stdout.strip():
            results[record_type] = [
                line.strip() for line in stdout.strip().split("\n") if line.strip()
            ]
            log_success(f"{record_type} records: {', '.join(results[record_type])}")

    return results

def subdomain_enum(target: str, requested_tools: list, output_dir: str, dry_run: bool = False) -> list:
    """Subdomain enumeration utilizing multiple requested tools with fallbacks."""
    print_phase("Phase 1b", f"Subdomain Enumeration — {target}")
    
    subdomain_file = os.path.join(output_dir, "discovered_subdomains.txt")
    temp_subs = []

    # 1. Subfinder
    if "subfinder" in requested_tools and check_tool("subfinder"):
        stdout, _, rc = run_cmd(["subfinder", "-d", target, "-silent", "-all"], timeout=180, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            found = [l.strip() for l in stdout.split("\n") if l.strip()]
            temp_subs.extend(found)
            log_info(f"Subfinder found {len(found)} subdomains.")
    elif "subfinder" in requested_tools:
        log_warn("subfinder is requested but not installed.")

    # 2. Assetfinder
    if "assetfinder" in requested_tools and check_tool("assetfinder"):
        stdout, _, rc = run_cmd(["assetfinder", "--subs-only", target], timeout=120, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            found = [l.strip() for l in stdout.split("\n") if l.strip()]
            temp_subs.extend(found)
            log_info(f"Assetfinder found {len(found)} subdomains.")
    elif "assetfinder" in requested_tools:
        log_warn("assetfinder is requested but not installed.")

    # 3. Sublist3r / Sublister
    sublist3r_cmd = None
    if "sublister" in requested_tools or "sublist3r" in requested_tools:
        if check_tool("sublist3r"):
            sublist3r_cmd = "sublist3r"
        elif check_tool("sublister"):
            sublist3r_cmd = "sublister"
        
        if sublist3r_cmd:
            temp_sublister_out = os.path.join(output_dir, "temp_sublister.txt")
            _, _, rc = run_cmd([sublist3r_cmd, "-d", target, "-n", "-o", temp_sublister_out], timeout=240, dry_run=dry_run)
            if rc == 0 and os.path.exists(temp_sublister_out):
                with open(temp_sublister_out, 'r') as f:
                    found = [l.strip() for l in f if l.strip()]
                temp_subs.extend(found)
                log_info(f"{sublist3r_cmd} found {len(found)} subdomains.")
                try: os.remove(temp_sublister_out)
                except: pass
        else:
            log_warn("sublist3r/sublister is requested but not installed.")

    # 4. Chaos
    if "chaos" in requested_tools and check_tool("chaos"):
        stdout, _, rc = run_cmd(["chaos", "-d", target, "-silent"], timeout=120, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            found = [l.strip() for l in stdout.split("\n") if l.strip()]
            temp_subs.extend(found)
            log_info(f"Chaos found {len(found)} subdomains.")
    elif "chaos" in requested_tools:
        log_warn("chaos is requested but not installed.")

    # 5. Github Subdomains
    if "github-subdomains" in requested_tools and check_tool("github-subdomains"):
        # Requires github token (check env)
        if os.environ.get("GITHUB_TOKEN"):
            stdout, _, rc = run_cmd(["github-subdomains", "-d", target, "-t", os.environ["GITHUB_TOKEN"], "-silent"], timeout=180, dry_run=dry_run)
            if rc == 0 and stdout.strip():
                found = [l.strip() for l in stdout.split("\n") if l.strip()]
                temp_subs.extend(found)
                log_info(f"Github-subdomains found {len(found)} subdomains.")
        else:
            log_warn("github-subdomains requested but GITHUB_TOKEN environment variable not set.")
    elif "github-subdomains" in requested_tools:
        log_warn("github-subdomains is requested but not installed.")

    # 6. Shosubgo
    if "shosubgo" in requested_tools and check_tool("shosubgo"):
        shodan_key = os.environ.get("SHODAN_API_KEY")
        if shodan_key:
            stdout, _, rc = run_cmd(["shosubgo", "-d", target, "-s", shodan_key], timeout=120, dry_run=dry_run)
            if rc == 0 and stdout.strip():
                found = [l.strip() for l in stdout.split("\n") if l.strip()]
                temp_subs.extend(found)
                log_info(f"Shosubgo found {len(found)} subdomains.")
        else:
            log_warn("shosubgo requested but SHODAN_API_KEY environment variable not set.")
    elif "shosubgo" in requested_tools:
        log_warn("shosubgo is requested but not installed.")

    # 7. Crt.sh lookup (Python Fallback)
    if "crtsh" in requested_tools:
        log_info("Querying crt.sh CT logs...")
        try:
            import urllib.request
            import urllib.parse
            url = f"https://crt.sh/?q={urllib.parse.quote('%.' + target)}&output=json"
            req = urllib.request.Request(
                url, 
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
            )
            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode())
                found = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.replace('*.', '').strip().lower()
                        if sub and sub.endswith(target):
                            found.add(sub)
                temp_subs.extend(list(found))
                log_info(f"crt.sh lookup found {len(found)} subdomains.")
        except Exception as e:
            log_warn(f"Failed to query crt.sh: {e}")

    # Deduplicate with anew logic
    unique_subs = run_anew(temp_subs, subdomain_file, dry_run=dry_run)
    log_success(f"Subdomain enumeration complete. {len(unique_subs)} unique subdomains saved to {subdomain_file}")
    return unique_subs

def subdomain_takeover(subdomain_file: str, output_dir: str, dry_run: bool = False) -> str:
    """Run subzy to check for subdomain takeover."""
    print_phase("Subdomain Takeover Check", "Checking for takeover vulnerabilities")
    
    output_file = os.path.join(output_dir, "takeover_results.txt")
    if not check_tool("subzy"):
        log_warn("subzy is not installed. Skipping takeover check.")
        return ""

    run_cmd(["subzy", "run", "--targets", subdomain_file, "--concurrency", "50", "--output", output_file], timeout=300, dry_run=dry_run)
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        log_success(f"Takeover results saved to {output_file}")
        return output_file
    return ""

def http_probing(subdomain_file: str, output_dir: str, probe_tool: str = "httpx", dry_run: bool = False) -> list:
    """Run httpx or httprobe to find active HTTP servers."""
    print_phase("Phase 2", "HTTP Probing (Alive check)")
    
    live_hosts_file = os.path.join(output_dir, "live_hosts.txt")
    temp_hosts = []

    if probe_tool == "httpx" and check_tool("httpx"):
        stdout, _, rc = run_cmd(["httpx", "-l", subdomain_file, "-silent", "-sc", "-title", "-td", "-ip"], timeout=300, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            # Parse URLs from httpx output (lines start with http:// or https://)
            for line in stdout.split("\n"):
                match = re.match(r"(https?://\S+)", line.strip())
                if match:
                    temp_hosts.append(match.group(1))
    elif probe_tool == "httprobe" and check_tool("httprobe"):
        # httprobe reads from stdin
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r') as f:
                stdin_data = f.read()
            stdout, _, rc = run_cmd(["httprobe", "-c", "50"], timeout=300, dry_run=dry_run, stdin_data=stdin_data)
            if rc == 0 and stdout.strip():
                temp_hosts = [l.strip() for l in stdout.split("\n") if l.strip()]
    else:
        log_warn(f"{probe_tool} is not installed or available. Using basic python socket alive probing.")
        # Python-based alive probing as fallback
        import socket
        if os.path.exists(subdomain_file):
            with open(subdomain_file, 'r') as f:
                subs = [line.strip() for line in f if line.strip()]
            for sub in subs:
                try:
                    # check port 80/443
                    socket.gethostbyname(sub)
                    temp_hosts.append(f"https://{sub}")
                    temp_hosts.append(f"http://{sub}")
                except socket.gaierror:
                    pass

    # Save unique active hosts
    unique_hosts = run_anew(temp_hosts, live_hosts_file, dry_run=dry_run)
    log_success(f"HTTP Probing complete. Found {len(unique_hosts)} active endpoints. Saved to {live_hosts_file}")
    return unique_hosts

def port_scanning(target: str, scan_tool: str = "nmap", ports: str = None, output_dir: str = None, dry_run: bool = False) -> list:
    """Port scanning using rustscan, naabu, or standard nmap."""
    print_phase("Phase 3", f"Port Scanning ({scan_tool}) — {target}")
    
    open_ports = []
    output_file = os.path.join(output_dir, f"portscan_{scan_tool}.txt")

    if scan_tool == "rustscan" and check_tool("rustscan"):
        # Rustscan prints output and then optionally pipes to nmap
        rust_cmd = ["rustscan", "-a", target, "--ulimit", "5000"]
        if ports:
            rust_cmd.extend(["-p", ports])
        rust_cmd.extend(["--", "-sV", "-sC", "-oN", output_file])
        
        stdout, _, rc = run_cmd(rust_cmd, timeout=400, dry_run=dry_run)
        if rc == 0:
            log_success(f"Rustscan port scan complete. Saved output to {output_file}")
            
    elif scan_tool == "naabu" and check_tool("naabu"):
        naabu_cmd = ["naabu", "-host", target, "-o", output_file]
        if ports:
            naabu_cmd.extend(["-p", ports])
        else:
            naabu_cmd.extend(["-top-ports", "1000"])
            
        stdout, _, rc = run_cmd(naabu_cmd, timeout=300, dry_run=dry_run)
        if rc == 0 and os.path.exists(output_file):
            with open(output_file, 'r') as f:
                ports_list = [line.strip().split(":")[-1] for line in f if line.strip()]
            log_success(f"Naabu found open ports: {', '.join(ports_list)}. Saved to {output_file}")
            
    else:
        # Default to nmap
        if not check_tool("nmap"):
            log_warn("nmap is not installed. Skipping port scan.")
            return open_ports
            
        nmap_cmd = ["nmap", "-sV", "--open", "-T4"]
        if ports:
            nmap_cmd.extend(["-p", ports])
        else:
            nmap_cmd.extend(["--top-ports", "1000"])
        nmap_cmd.extend(["-oN", output_file, target])
        
        stdout, _, rc = run_cmd(nmap_cmd, timeout=600, dry_run=dry_run)
        if rc == 0:
            log_success(f"Nmap scan complete. Saved to {output_file}")

    return open_ports

def tech_fingerprint(target: str, dry_run: bool = False) -> dict:
    """Technology fingerprinting using whatweb."""
    print_phase("Technology Fingerprinting", f"Identifying technologies on {target}")
    results = {"detected": []}
    
    if not check_tool("whatweb"):
        log_warn("whatweb is not installed. Skipping technology fingerprinting.")
        return results

    for scheme in ["https", "http"]:
        url = f"{scheme}://{target}"
        stdout, _, rc = run_cmd(["whatweb", "--color=never", "-v", url], timeout=60, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            # Parse basic technology information
            for line in stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("http") and not line.startswith("WhatWeb"):
                    if "[" in line and "]" in line:
                        results["detected"].append(line)
            log_success(f"Fingerprinting successful for {url}")
            break
            
    if results["detected"]:
        for tech in results["detected"][:10]:
            print(f"     └── {tech}")
    return results

def crawl_and_gather_urls(live_hosts_file: str, target: str, tools_list: list, output_dir: str, dry_run: bool = False) -> list:
    """Gather and crawl URLs using katana, hakrawler, gau, and waybackurls."""
    print_phase("Phase 4", "URL Crawling & Archive Gathering")
    
    all_urls_file = os.path.join(output_dir, "discovered_urls.txt")
    deduped_urls_file = os.path.join(output_dir, "unique_param_urls.txt")
    
    temp_urls = []

    # 1. Katana
    if "katana" in tools_list and check_tool("katana"):
        output_katana = os.path.join(output_dir, "temp_katana.txt")
        run_cmd(["katana", "-l", live_hosts_file, "-jc", "-d", "3", "-o", output_katana], timeout=400, dry_run=dry_run)
        if os.path.exists(output_katana):
            with open(output_katana, 'r') as f:
                temp_urls.extend([line.strip() for line in f if line.strip()])
            try: os.remove(output_katana)
            except: pass

    # 2. Hakrawler
    if "hakrawler" in tools_list and check_tool("hakrawler"):
        if os.path.exists(live_hosts_file):
            with open(live_hosts_file, 'r') as f:
                stdin_data = f.read()
            stdout, _, rc = run_cmd(["hakrawler", "-d", "3"], timeout=300, dry_run=dry_run, stdin_data=stdin_data)
            if rc == 0 and stdout.strip():
                temp_urls.extend([line.strip() for line in stdout.split("\n") if line.strip()])

    # 3. GAU
    if "gau" in tools_list and check_tool("gau"):
        stdout, _, rc = run_cmd(["gau", target, "--subs", "--threads", "10"], timeout=300, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            temp_urls.extend([line.strip() for line in stdout.split("\n") if line.strip()])

    # 4. Waybackurls
    if "waybackurls" in tools_list and check_tool("waybackurls"):
        stdout, _, rc = run_cmd(["waybackurls", target], timeout=200, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            temp_urls.extend([line.strip() for line in stdout.split("\n") if line.strip()])

    # Deduplicate raw URLs using anew logic
    run_anew(temp_urls, all_urls_file, dry_run=dry_run)
    
    # Read back all gathered URLs to run url parsing/deduping
    if os.path.exists(all_urls_file):
        with open(all_urls_file, 'r') as f:
            all_urls = [line.strip() for line in f if line.strip()]
    else:
        all_urls = []

    # Run Normalizer
    normalized_urls = normalize_urls(all_urls)
    
    # Deduplicate parameters (using urldedupe if available, otherwise python logic)
    unique_param_urls = []
    if check_tool("urldedupe"):
        # Write normalized to file first
        temp_norm_file = os.path.join(output_dir, "temp_normalized.txt")
        with open(temp_norm_file, 'w') as f:
            f.write("\n".join(normalized_urls) + "\n")
        
        stdout, _, rc = run_cmd(["urldedupe", "-u", temp_norm_file], timeout=180, dry_run=dry_run)
        if rc == 0 and stdout.strip():
            unique_param_urls = [line.strip() for line in stdout.split("\n") if line.strip()]
            
        try: os.remove(temp_norm_file)
        except: pass
    else:
        # Python urldedupe simulation
        seen_keys = set()
        for url in normalized_urls:
            parsed = urlparse(url)
            query_keys = tuple(sorted(parse_qs(parsed.query).keys()))
            # Create a unique key using (scheme, netloc, path, query_param_keys)
            dedupe_key = (parsed.scheme, parsed.netloc, parsed.path, query_keys)
            if dedupe_key not in seen_keys:
                seen_keys.add(dedupe_key)
                unique_param_urls.append(url)

    # Save the deduplicated URLs
    with open(deduped_urls_file, 'w') as f:
        f.write("\n".join(unique_param_urls) + "\n")

    log_success(f"URL gathering complete: {len(all_urls)} total URLs -> {len(unique_param_urls)} parameter-unique URLs.")
    log_success(f"Saved unique URLs to {deduped_urls_file}")
    
    # Parse parameter keys (Python implementation of unfurl keys)
    keys_discovered = run_unfurl_keys(unique_param_urls)
    if keys_discovered:
        keys_file = os.path.join(output_dir, "discovered_parameters.txt")
        with open(keys_file, 'w') as f:
            f.write("\n".join(keys_discovered) + "\n")
        log_info(f"Extracted {len(keys_discovered)} unique parameter keys to {keys_file}")

    # Apply GF patterns
    for pattern in ["xss", "sqli", "ssrf", "lfi", "rce", "redirect"]:
        pattern_urls = []
        if check_tool("gf"):
            stdout, _, rc = run_cmd(["gf", pattern, deduped_urls_file], timeout=60, dry_run=dry_run)
            if rc == 0 and stdout.strip():
                pattern_urls = [line.strip() for line in stdout.split("\n") if line.strip()]
        else:
            # Fallback to python gf simulation
            pattern_urls = run_gf_filter(unique_param_urls, pattern)
            
        if pattern_urls:
            pat_file = os.path.join(output_dir, f"gf_{pattern}.txt")
            with open(pat_file, 'w') as f:
                f.write("\n".join(pattern_urls) + "\n")
            log_info(f"GF [{pattern}] found {len(pattern_urls)} matching URLs. Saved to {pat_file}")

    return unique_param_urls

def parameter_mining(target_domain: str, tools_list: list, unique_urls: list, output_dir: str, dry_run: bool = False):
    """Run arjun or paramspider to discover parameters."""
    print_phase("Parameter Mining", "Searching for hidden parameters")
    
    # 1. ParamSpider
    if "paramspider" in tools_list and check_tool("paramspider"):
        output_file = os.path.join(output_dir, "paramspider_results.txt")
        # Run paramspider CLI
        run_cmd(["paramspider", "-d", target_domain, "-o", output_file], timeout=300, dry_run=dry_run)
        if os.path.exists(output_file):
            log_success(f"ParamSpider mined parameters saved to {output_file}")
            
    # 2. Arjun
    if "arjun" in tools_list and check_tool("arjun"):
        # Select first 3 unique URLs with query params/paths to run arjun on
        test_urls = [url for url in unique_urls if "?" in url][:3]
        if not test_urls:
            # Fallback to main target
            test_urls = [f"https://{target_domain}"]
            
        for idx, url in enumerate(test_urls):
            output_arjun = os.path.join(output_dir, f"arjun_results_{idx}.json")
            run_cmd(["arjun", "-u", url, "-m", "GET", "-oJ", output_arjun], timeout=200, dry_run=dry_run)
            if os.path.exists(output_arjun):
                log_success(f"Arjun mined parameters for {url} saved to {output_arjun}")

def vulnerability_scanning(target: str, live_hosts_file: str, unique_urls_file: str, tools_list: list, output_dir: str, dry_run: bool = False):
    """Run automated vulnerability scanning (nuclei, dalfox, nikto, wpscan)."""
    print_phase("Phase 5", "Vulnerability Scanning")

    # 1. Nuclei
    if "nuclei" in tools_list and check_tool("nuclei"):
        nuclei_out = os.path.join(output_dir, "nuclei_results.txt")
        log_info("Running Nuclei templates scan...")
        run_cmd(["nuclei", "-l", live_hosts_file, "-severity", "critical,high", "-o", nuclei_out], timeout=600, dry_run=dry_run)
        if os.path.exists(nuclei_out) and os.path.getsize(nuclei_out) > 0:
            log_success(f"Nuclei found vulnerabilities. Report saved to {nuclei_out}")

    # 2. Dalfox (XSS Scanner)
    if "dalfox" in tools_list and check_tool("dalfox"):
        dalfox_out = os.path.join(output_dir, "dalfox_results.txt")
        log_info("Running Dalfox XSS scanner...")
        # Check if we have GF XSS urls
        gf_xss_file = os.path.join(output_dir, "gf_xss.txt")
        scan_source = gf_xss_file if os.path.exists(gf_xss_file) else unique_urls_file
        
        if os.path.exists(scan_source) and os.path.getsize(scan_source) > 0:
            run_cmd(["dalfox", "file", scan_source, "-o", dalfox_out], timeout=400, dry_run=dry_run)
            if os.path.exists(dalfox_out):
                log_success(f"Dalfox XSS scan complete. Results: {dalfox_out}")

    # 3. Nikto (Web Server Vulnerability Scanner)
    if "nikto" in tools_list and check_tool("nikto"):
        nikto_out = os.path.join(output_dir, "nikto_results.txt")
        log_info("Running Nikto web server scanner...")
        run_cmd(["nikto", "-h", f"https://{target}", "-o", nikto_out], timeout=600, dry_run=dry_run)
        if os.path.exists(nikto_out):
            log_success(f"Nikto scan complete. Results: {nikto_out}")

    # 4. WPScan
    if "wpscan" in tools_list and check_tool("wpscan"):
        wpscan_out = os.path.join(output_dir, "wpscan_results.txt")
        log_info("Running WPScan check...")
        wpscan_cmd = ["wpscan", "--url", f"https://{target}", "--enumerate", "vp,vt", "-o", wpscan_out]
        # Include API token if available
        if os.environ.get("WPSCAN_API_TOKEN"):
            wpscan_cmd.extend(["--api-token", os.environ["WPSCAN_API_TOKEN"]])
            
        run_cmd(wpscan_cmd, timeout=300, dry_run=dry_run)
        if os.path.exists(wpscan_out):
            log_success(f"WPScan complete. Results: {wpscan_out}")

# ═══════════════════════════════════════════════════════════
# MAIN CONTROL BLOCK
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Advanced Recon Automation — Pentest & Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", "-t", required=True, help="Target domain or IP")
    parser.add_argument("--output", "-o", default="./recon_results", help="Output directory")
    
    # Tool configurations
    parser.add_argument("--subdomain-tools", default="subfinder,assetfinder,crtsh", 
                        help="Comma-separated subdomain tools: subfinder,assetfinder,sublister,chaos,github-subdomains,shosubgo,crtsh")
    parser.add_argument("--takeover", action="store_true", help="Run subdomain takeover check using subzy")
    parser.add_argument("--portscan-tool", default="nmap", choices=["nmap", "naabu", "rustscan"], help="Port scanning tool to use")
    parser.add_argument("--ports", help="Specific ports to scan (comma-separated)")
    parser.add_argument("--probe-tool", default="httpx", choices=["httpx", "httprobe"], help="HTTP probing tool to use")
    parser.add_argument("--crawl-tools", default="katana,hakrawler,gau,waybackurls", 
                        help="Comma-separated crawling tools: katana,hakrawler,gau,waybackurls")
    parser.add_argument("--param-tools", default="arjun,paramspider", 
                        help="Comma-separated parameter mining tools: arjun,paramspider")
    parser.add_argument("--vuln-tools", default="nuclei,dalfox,nikto", 
                        help="Comma-separated vulnerability scanners: nuclei,dalfox,nikto,wpscan")
    
    # Skips
    parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enum phase")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip port scanning phase")
    parser.add_argument("--skip-crawling", action="store_true", help="Skip URL crawling & gathering phase")
    parser.add_argument("--skip-param-mining", action="store_true", help="Skip parameter mining")
    parser.add_argument("--skip-vulnscan", action="store_true", help="Skip automated vulnerability scanning")
    
    # Dry run
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing")

    args = parser.parse_args()

    print_banner()
    
    # Setup directories
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)
    log_info(f"Target: {args.target}")
    log_info(f"Output directory: {output_dir}")

    # Parse comma-separated tools lists
    sub_tools = [t.strip().lower() for t in args.subdomain_tools.split(",") if t.strip()]
    crawl_tools = [t.strip().lower() for t in args.crawl_tools.split(",") if t.strip()]
    param_tools = [t.strip().lower() for t in args.param_tools.split(",") if t.strip()]
    vuln_tools = [t.strip().lower() for t in args.vuln_tools.split(",") if t.strip()]

    # Collect list of all tools to check
    all_tools_to_check = set(["dig", "curl", "anew"])
    if not args.skip_subdomains:
        all_tools_to_check.update([t for t in sub_tools if t != "crtsh"])
        if args.takeover:
            all_tools_to_check.add("subzy")
    all_tools_to_check.add(args.probe_tool)
    if not args.skip_portscan:
        all_tools_to_check.add(args.portscan_tool) # rustscan / naabu / nmap
    if not args.skip_crawling:
        all_tools_to_check.update(crawl_tools)
        all_tools_to_check.add("urldedupe")
        all_tools_to_check.add("unfurl")
        all_tools_to_check.add("gf")
    if not args.skip_param_mining:
        all_tools_to_check.update(param_tools)
    if not args.skip_vulnscan:
        all_tools_to_check.update(vuln_tools)

    log_info("Checking requested tools availability...")
    avail_status = {}
    for t in sorted(list(all_tools_to_check)):
        # Normalize tool names for checking
        chk = t
        if t == "sublister" or t == "sublist3r":
            # Check either
            avail = check_tool("sublist3r") or check_tool("sublister")
        else:
            avail = check_tool(t)
        
        avail_status[t] = avail
        status_icon = f"{C_GREEN}Available{C_END}" if avail else f"{C_YELLOW}Not Found (Fallback or skip will be used){C_END}"
        print(f"  [+] {t:<18}: {status_icon}")

    # Execution tracking report
    start_time = time.time()
    report = {
        "target": args.target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "args": vars(args),
        "phases": {},
        "tool_availability": avail_status
    }

    # 1. DNS Lookup
    report["phases"]["dns"] = dns_lookup(args.target, args.dry_run)

    # 2. Subdomains Gathering
    subdomains = [args.target]
    if not args.skip_subdomains:
        subdomains = subdomain_enum(args.target, sub_tools, output_dir, args.dry_run)
        report["phases"]["subdomains"] = subdomains
        
        # Takeover checks
        if args.takeover:
            subdomain_file = os.path.join(output_dir, "discovered_subdomains.txt")
            if os.path.exists(subdomain_file):
                report["phases"]["takeover_report"] = subdomain_takeover(subdomain_file, output_dir, args.dry_run)
    else:
        log_info("Subdomain enumeration skipped.")

    # Write subdomains list if not already written
    subdomain_file = os.path.join(output_dir, "discovered_subdomains.txt")
    if not os.path.exists(subdomain_file) and not args.dry_run:
        with open(subdomain_file, 'w') as f:
            f.write("\n".join(subdomains) + "\n")

    # 3. HTTP Probing (Alive check)
    live_hosts = http_probing(subdomain_file, output_dir, args.probe_tool, args.dry_run)
    report["phases"]["live_hosts"] = live_hosts

    # Write fallback live hosts file if empty
    live_hosts_file = os.path.join(output_dir, "live_hosts.txt")
    if not live_hosts and not args.dry_run:
        live_hosts = [f"https://{args.target}", f"http://{args.target}"]
        with open(live_hosts_file, 'w') as f:
            f.write("\n".join(live_hosts) + "\n")

    # 4. Port Scanning
    if not args.skip_portscan:
        port_scanning(args.target, args.portscan_tool, args.ports, output_dir, args.dry_run)
    else:
        log_info("Port scanning skipped.")

    # 5. Technology Fingerprinting
    report["phases"]["technologies"] = tech_fingerprint(args.target, args.dry_run)

    # 6. Crawling & URL Gathering
    unique_urls = []
    unique_urls_file = os.path.join(output_dir, "unique_param_urls.txt")
    if not args.skip_crawling:
        unique_urls = crawl_and_gather_urls(live_hosts_file, args.target, crawl_tools, output_dir, args.dry_run)
        report["phases"]["unique_urls_count"] = len(unique_urls)
    else:
        log_info("URL Crawling & archive gathering skipped.")

    # 7. Parameter Mining
    if not args.skip_param_mining:
        parameter_mining(args.target, param_tools, unique_urls, output_dir, args.dry_run)
    else:
        log_info("Parameter mining skipped.")

    # 8. Vulnerability Scanning
    if not args.skip_vulnscan:
        vulnerability_scanning(args.target, live_hosts_file, unique_urls_file, vuln_tools, output_dir, args.dry_run)
    else:
        log_info("Vulnerability scanning skipped.")

    # Calculate duration
    elapsed = time.time() - start_time
    report["duration_seconds"] = round(elapsed, 2)

    # Save final JSON report
    report_file = os.path.join(output_dir, f"recon_{args.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
    if not args.dry_run:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

    # Summary
    print(f"\n{C_BOLD}{'=' * 60}{C_END}")
    print(f"  📋 {C_GREEN}{C_BOLD}RECON SUMMARY — {args.target}{C_END}")
    print(f"{C_BOLD}{'=' * 60}{C_END}")
    print(f"  ⏱️  Duration      : {elapsed:.1f} seconds")
    print(f"  🌐 Target Domain  : {args.target}")
    print(f"  🔍 Subdomains     : {len(subdomains)} subdomains discovered")
    print(f"  📡 Active Hosts   : {len(live_hosts)} hosts alive")
    print(f"  🔗 Unique URLs    : {len(unique_urls)} parameter-unique URLs gathered")
    print(f"  💾 Report Saved   : {report_file}")
    print(f"{C_BOLD}{'=' * 60}{C_END}\n")

if __name__ == "__main__":
    main()
