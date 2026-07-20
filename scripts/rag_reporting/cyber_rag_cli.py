#!/usr/bin/env python3
"""
Cyber RAG CLI Helper — Quick access to cybersecurity knowledge base
Usage: python3 ~/Skills/Pentest/scripts/cyber_rag_cli.py [command] [args]

Commands:
  query <question>                    — Query the knowledge base
  analyze-recon <tool> <output_file>  — Analyze recon output
  analyze-vuln <tool> <output_file>   — Analyze vuln scan output
  recommend <phase> <findings>        — Get recommendations
  exploit <vuln_type> <endpoint>      — Get exploitation guidance
  cvss <description>                  — Get CVSS scoring
  health                              — Check MCP server status
"""

import sys
import json
import requests
from pathlib import Path

MCP_BASE_URL = "http://127.0.0.1:8642"

# Colors
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def check_health():
    """Check if MCP server is running."""
    try:
        resp = requests.get(f"{MCP_BASE_URL}/health", timeout=5)
        return resp.status_code == 200
    except:
        return False

def call_tool(tool_name: str, arguments: dict) -> str:
    """Call an MCP tool via SSE endpoint."""
    import httpx_sse
    import httpx
    
    url = f"{MCP_BASE_URL}/sse"
    
    # For simplicity, we'll use the HTTP endpoint if available
    # Otherwise, fall back to direct function call
    try:
        # Try direct HTTP call to tool endpoint
        resp = requests.post(
            f"{MCP_BASE_URL}/tools/{tool_name}",
            json=arguments,
            timeout=120
        )
        if resp.status_code == 200:
            return resp.json().get("result", resp.text)
    except:
        pass
    
    # Fallback: Import and call directly
    try:
        sys.path.insert(0, str(Path.home() / "Documents" / "Cyber_RAG_LLM"))
        from src.chat import CyberSecurityRAG
        
        rag = CyberSecurityRAG()
        
        if tool_name == "cyber_rag_query":
            result = rag.query(arguments["question"])
            return result.get("answer", str(result))
        elif tool_name == "analyze_recon_output":
            result = rag.analyze_recon(arguments["scan_output"], arguments["tool_name"])
            return result.get("analysis", str(result))
        elif tool_name == "analyze_vuln_scan":
            result = rag.analyze_vuln(arguments["scan_output"], arguments["tool_name"])
            return result.get("analysis", str(result))
        elif tool_name == "pentest_recommend":
            result = rag.recommend(arguments["current_phase"], arguments.get("findings_summary", ""))
            return result.get("recommendations", str(result))
        elif tool_name == "exploit_guidance":
            result = rag.exploit_guide(arguments["vuln_type"], arguments.get("endpoint", ""), arguments.get("waf_detected", False))
            return result.get("guidance", str(result))
        elif tool_name == "cvss_scoring":
            result = rag.cvss_score(arguments["vuln_description"])
            return result.get("score", str(result))
        else:
            return f"Unknown tool: {tool_name}"
    except Exception as e:
        return f"Error: {str(e)}"

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    
    command = sys.argv[1].lower()
    
    # Check health first
    if command == "health":
        if check_health():
            print(f"{GREEN}[OK] MCP server running at {MCP_BASE_URL}{NC}")
        else:
            print(f"{RED}[FAIL] MCP server not running{NC}")
            print(f"{YELLOW}Start with: ~/Skills/Pentest/scripts/start_cyber_rag.sh{NC}")
        return
    
    if not check_health():
        print(f"{RED}[ERROR] MCP server not running{NC}")
        print(f"{YELLOW}Start with: ~/Skills/Pentest/scripts/start_cyber_rag.sh{NC}")
        return
    
    if command == "query":
        if len(sys.argv) < 3:
            print("Usage: cyber_rag_cli.py query <question>")
            return
        question = " ".join(sys.argv[2:])
        result = call_tool("cyber_rag_query", {"question": question})
        print(f"\n{BLUE}=== Cyber RAG Response ==={NC}\n")
        print(result)
    
    elif command == "analyze-recon":
        if len(sys.argv) < 4:
            print("Usage: cyber_rag_cli.py analyze-recon <tool_name> <output_file>")
            return
        tool_name = sys.argv[2]
        output_file = sys.argv[3]
        try:
            with open(output_file, 'r') as f:
                scan_output = f.read()
        except FileNotFoundError:
            print(f"{RED}File not found: {output_file}{NC}")
            return
        result = call_tool("analyze_recon_output", {"scan_output": scan_output, "tool_name": tool_name})
        print(f"\n{BLUE}=== Recon Analysis ({tool_name}) ==={NC}\n")
        print(result)
    
    elif command == "analyze-vuln":
        if len(sys.argv) < 4:
            print("Usage: cyber_rag_cli.py analyze-vuln <tool_name> <output_file>")
            return
        tool_name = sys.argv[2]
        output_file = sys.argv[3]
        try:
            with open(output_file, 'r') as f:
                scan_output = f.read()
        except FileNotFoundError:
            print(f"{RED}File not found: {output_file}{NC}")
            return
        result = call_tool("analyze_vuln_scan", {"scan_output": scan_output, "tool_name": tool_name})
        print(f"\n{BLUE}=== Vuln Scan Analysis ({tool_name}) ==={NC}\n")
        print(result)
    
    elif command == "recommend":
        if len(sys.argv) < 3:
            print("Usage: cyber_rag_cli.py recommend <phase> [findings]")
            return
        phase = sys.argv[2]
        findings = " ".join(sys.argv[3:]) if len(sys.argv) > 3 else ""
        result = call_tool("pentest_recommend", {"current_phase": phase, "findings_summary": findings})
        print(f"\n{BLUE}=== Recommendations ({phase}) ==={NC}\n")
        print(result)
    
    elif command == "exploit":
        if len(sys.argv) < 3:
            print("Usage: cyber_rag_cli.py exploit <vuln_type> [endpoint] [waf=true/false]")
            return
        vuln_type = sys.argv[2]
        endpoint = sys.argv[3] if len(sys.argv) > 3 else ""
        waf = sys.argv[4].lower() == "true" if len(sys.argv) > 4 else False
        result = call_tool("exploit_guidance", {"vuln_type": vuln_type, "endpoint": endpoint, "waf_detected": waf})
        print(f"\n{BLUE}=== Exploitation Guidance ({vuln_type}) ==={NC}\n")
        print(result)
    
    elif command == "cvss":
        if len(sys.argv) < 3:
            print("Usage: cyber_rag_cli.py cvss <vulnerability_description>")
            return
        description = " ".join(sys.argv[2:])
        result = call_tool("cvss_scoring", {"vuln_description": description})
        print(f"\n{BLUE}=== CVSS Scoring ==={NC}\n")
        print(result)
    
    else:
        print(f"{RED}Unknown command: {command}{NC}")
        print(__doc__)

if __name__ == "__main__":
    main()
