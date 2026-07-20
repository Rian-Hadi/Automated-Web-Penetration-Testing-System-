#!/usr/bin/env python3
"""
Pentest Tools Verification Script
Checks all tools are properly installed and configured.
Run: python3 ~/Skills/Pentest/scripts/verify_tools.py
"""

import subprocess
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def check_tool(name: str, path: str = None, version_cmd: str = None) -> Tuple[bool, str]:
    """Check if a tool is installed and get its version."""
    try:
        # Check if tool exists in PATH
        result = subprocess.run(['which', name], capture_output=True, text=True)
        if result.returncode == 0:
            tool_path = result.stdout.strip()
            version = ""
            if version_cmd:
                try:
                    ver_result = subprocess.run(version_cmd.split(), capture_output=True, text=True, timeout=5)
                    version = ver_result.stdout.strip().split('\n')[0]
                except:
                    version = "version check failed"
            return True, f"{tool_path} {version}"
        
        # Check specific path
        if path and os.path.exists(os.path.expanduser(path)):
            return True, path
            
        return False, "not found"
    except Exception as e:
        return False, str(e)

def check_directory(path: str) -> bool:
    """Check if a directory exists."""
    return os.path.exists(os.path.expanduser(path))

def check_file(path: str) -> bool:
    """Check if a file exists."""
    return os.path.exists(os.path.expanduser(path))

def main():
    print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{BLUE}  [ARES] Pentest Tools Verification{NC}")
    print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    
    # Set Go PATH
    os.environ['GOPATH'] = os.path.expanduser('~/go')
    os.environ['PATH'] = f"{os.environ['PATH']}:{os.environ['GOPATH']}/bin"
    
    results = {
        'recon': {'pass': 0, 'fail': 0, 'tools': []},
        'scanning': {'pass': 0, 'fail': 0, 'tools': []},
        'exploitation': {'pass': 0, 'fail': 0, 'tools': []},
        'post_exploitation': {'pass': 0, 'fail': 0, 'tools': []},
        'reporting': {'pass': 0, 'fail': 0, 'tools': []},
        'automation': {'pass': 0, 'fail': 0, 'tools': []},
        'configs': {'pass': 0, 'fail': 0, 'items': []},
    }
    
    # ============================================================
    # PHASE 1: RECON
    # ============================================================
    print(f"\n{YELLOW}[PHASE 1] RECONNAISSANCE{NC}")
    
    recon_tools = [
        ("subfinder", "subfinder -version"),
        ("amass", None),
        ("assetfinder", None),
        ("findomain", None),
        ("crtsh", None),
        ("dnsx", "dnsx -version"),
        ("dnsrecon", None),
        ("dnsenum", None),
        ("fierce", None),
        ("dig", None),
        ("httpx", None),
        ("httprobe", None),
        ("whatweb", None),
        ("wafw00f", None),
        ("theHarvester", None),
        ("recon-ng", None),
        ("spiderfoot", None),
        ("shodan", None),
        ("censys", None),
        ("gau", None),
        ("waybackurls", None),
        ("katana", "katana -version"),
        ("hakrawler", None),
        ("paramspider", None),
        ("arjun", None),
        ("qsreplace", None),
        ("unfurl", None),
        ("gf", None),
        ("anew", None),
        ("cewl", None),
        ("cutycapt", None),
        ("subjack", None),
        ("subzy", "subzy version"),
        ("sublist3r", None),
        ("certspotter", None),
        ("gitdorker", None),
    ]
    
    for tool_name, version_cmd in recon_tools:
        found, info = check_tool(tool_name, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['recon']['pass'] += 1
        else:
            results['recon']['fail'] += 1
        results['recon']['tools'].append((tool_name, found, info))
    
    # ============================================================
    # PHASE 2: SCANNING
    # ============================================================
    print(f"\n{YELLOW}[PHASE 2] SCANNING & ENUMERATION{NC}")
    
    scanning_tools = [
        ("nmap", "nmap --version"),
        ("masscan", None),
        ("naabu", "naabu -version"),
        ("nuclei", "nuclei -version"),
        ("nikto", "nikto -Version"),
        ("feroxbuster", None),
        ("gobuster", None),
        ("dirsearch", None),
        ("ffuf", "ffuf -V"),
        ("wfuzz", None),
        ("dirb", None),
        ("sslyze", None),
        ("sslscan", None),
        ("testssl.sh", None, "~/tools/testssl.sh/testssl.sh"),
        ("wpscan", None),
        ("cadaver", None),
        ("davtest", None),
        ("linkfinder", None),
    ]
    
    for tool_entry in scanning_tools:
        tool_name = tool_entry[0]
        version_cmd = tool_entry[1] if len(tool_entry) > 1 else None
        alt_path = tool_entry[2] if len(tool_entry) > 2 else None
        found, info = check_tool(tool_name, path=alt_path, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['scanning']['pass'] += 1
        else:
            results['scanning']['fail'] += 1
        results['scanning']['tools'].append((tool_name, found, info))
    
    # ============================================================
    # PHASE 3: EXPLOITATION
    # ============================================================
    print(f"\n{YELLOW}[PHASE 3] EXPLOITATION{NC}")
    
    exploitation_tools = [
        ("sqlmap", "sqlmap --version"),
        ("dalfox", "dalfox version"),
        ("xsstrike", None, "/usr/bin/xsstrike"),
        ("sstimap", None),
        ("commix", "commix --version"),
        ("jwt_tool", None),
        ("hydra", "hydra -V"),
        ("medusa", None),
        ("patator", None),
        ("john", None),
        ("hashcat", None),
        ("crunch", None),
        ("msfconsole", "msfconsole --version"),
        ("msfvenom", None),
        ("searchsploit", None),
        ("burpsuite", None),
        ("zaproxy", None),
        ("mitmproxy", None),
        ("wireshark", None),
        ("ssrfmap", None),
        ("crlfsuite", None),
        ("nosqlmap", None),
        ("corsy", None),
        ("gitleaks", None),
        ("trufflehog", None),
    ]
    
    for tool_entry in exploitation_tools:
        tool_name = tool_entry[0]
        version_cmd = tool_entry[1] if len(tool_entry) > 1 else None
        alt_path = tool_entry[2] if len(tool_entry) > 2 else None
        found, info = check_tool(tool_name, path=alt_path, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['exploitation']['pass'] += 1
        else:
            results['exploitation']['fail'] += 1
        results['exploitation']['tools'].append((tool_name, found, info))
    
    # ============================================================
    # PHASE 4: POST-EXPLOITATION
    # ============================================================
    print(f"\n{YELLOW}[PHASE 4] POST-EXPLOITATION{NC}")
    
    post_tools = [
        ("socat", None),
        ("nc", None),
        ("evil-winrm", None),
        ("proxychains", None),
        ("responder", None),
        ("enum4linux", None),
        ("smbclient", None),
        ("tor", None),
        ("tcpdump", None),
    ]
    
    for tool_name, version_cmd in post_tools:
        found, info = check_tool(tool_name, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['post_exploitation']['pass'] += 1
        else:
            results['post_exploitation']['fail'] += 1
        results['post_exploitation']['tools'].append((tool_name, found, info))
    
    # ============================================================
    # PHASE 5: REPORTING & DOCUMENTATION
    # ============================================================
    print(f"\n{YELLOW}[PHASE 5] REPORTING & DOCUMENTATION{NC}")
    
    reporting_tools = [
        ("pandoc", "pandoc --version"),
        ("weasyprint", "weasyprint --version"),
        ("dradis", None),
    ]
    
    for tool_name, version_cmd in reporting_tools:
        found, info = check_tool(tool_name, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['reporting']['pass'] += 1
        else:
            results['reporting']['fail'] += 1
        results['reporting']['tools'].append((tool_name, found, info))
        
    # ============================================================
    # PHASE 6: AUTOMATION FRAMEWORKS
    # ============================================================
    print(f"\n{YELLOW}[PHASE 6] AUTOMATION FRAMEWORKS{NC}")
    
    automation_tools = [
        ("reconftw", None),
        ("osmedeus", None),
        ("interlace", None),
        ("pocsuite3", None),
        ("xray", None),
        ("afrog", None),
    ]
    
    for tool_name, version_cmd in automation_tools:
        found, info = check_tool(tool_name, version_cmd=version_cmd)
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {tool_name:20s} {info}")
        if found:
            results['automation']['pass'] += 1
        else:
            results['automation']['fail'] += 1
        results['automation']['tools'].append((tool_name, found, info))
        
    # ============================================================
    # CONFIGURATIONS
    # ============================================================
    print(f"\n{YELLOW}[CONFIGURATIONS]{NC}")
    
    configs = [
        ("GF Patterns", "~/.gf/*.json", "ls ~/.gf/*.json 2>/dev/null | wc -l"),
        ("Nuclei Config", "~/.config/nuclei/config.yaml", None),
        ("Nuclei Templates", "~/.local/nuclei-templates", None),
        ("SecLists", "/usr/share/seclists", None),
        ("Pentest Workspace", "~/pentest", None),
    ]
    
    for name, path, cmd in configs:
        if cmd:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                count = result.stdout.strip()
                found = int(count) > 0 if count.isdigit() else False
                info = f"{count} files" if found else "empty"
            except:
                found = False
                info = "check failed"
        else:
            found = check_directory(path)
            info = path if found else "not found"
        
        status = f"{GREEN}[OK]{NC}" if found else f"{RED}[FAIL]{NC}"
        print(f"  {status} {name:20s} {info}")
        if found:
            results['configs']['pass'] += 1
        else:
            results['configs']['fail'] += 1
        results['configs']['items'].append((name, found, info))
    
    # ============================================================
    # SUMMARY
    # ============================================================
    print(f"\n{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    print(f"{BLUE}  SUMMARY{NC}")
    print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    
    total_pass = sum(r['pass'] for r in results.values())
    total_fail = sum(r['fail'] for r in results.values())
    total = total_pass + total_fail
    
    for phase, data in results.items():
        phase_total = data['pass'] + data['fail']
        if phase_total > 0:
            pct = (data['pass'] / phase_total) * 100
            color = GREEN if pct == 100 else YELLOW if pct >= 80 else RED
            print(f"  {color}{phase:20s}: {data['pass']}/{phase_total} ({pct:.0f}%){NC}")
    
    print(f"\n  {BLUE}TOTAL: {total_pass}/{total} tools configured{NC}")
    
    if total_fail > 0:
        print(f"\n  {YELLOW}[!] {total_fail} tools need attention{NC}")
        for phase, data in results.items():
            tools_key = 'tools' if 'tools' in data else 'items'
            for item in data[tools_key]:
                if isinstance(item, tuple) and len(item) >= 2 and not item[1]:
                    print(f"      - {item[0]}: {item[2] if len(item) > 2 else 'not found'}")
    
    print(f"\n{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    if total_fail == 0:
        print(f"{GREEN}  [DONE] All tools configured and ready!{NC}")
    else:
        print(f"{YELLOW}  [WARN] Some tools need configuration{NC}")
    print(f"{BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{NC}")
    
    return 0 if total_fail == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
