#!/bin/bash
###############################################################################
# Cyber RAG + Pentest Integration Script
# Manages MCP server and proxy services via systemd
###############################################################################

set -e

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}  🛡️ Cyber RAG + Pentest Integration${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

# 1. Check Cyber RAG MCP Server
echo -e "\n${YELLOW}[1/4] Checking Cyber RAG MCP Server...${NC}"
if systemctl --user is-active cyber-rag-mcp.service &>/dev/null; then
    echo -e "${GREEN}  [OK] Cyber RAG MCP Server running${NC}"
else
    echo -e "${YELLOW}  [WARN] Starting Cyber RAG MCP Server...${NC}"
    systemctl --user start cyber-rag-mcp.service
    sleep 2
    if systemctl --user is-active cyber-rag-mcp.service &>/dev/null; then
        echo -e "${GREEN}  [OK] Cyber RAG MCP Server started${NC}"
    else
        echo -e "${RED}  [FAIL] Failed to start Cyber RAG MCP Server${NC}"
        echo -e "${YELLOW}  Check logs: journalctl --user -u cyber-rag-mcp.service${NC}"
    fi
fi

# 2. Check MCP Proxy
echo -e "\n${YELLOW}[2/4] Checking MCP Proxy...${NC}"
if systemctl --user is-active cyber-rag-proxy.service &>/dev/null; then
    echo -e "${GREEN}  [OK] MCP Proxy running${NC}"
else
    echo -e "${YELLOW}  [WARN] Starting MCP Proxy...${NC}"
    systemctl --user start cyber-rag-proxy.service
    sleep 2
    if systemctl --user is-active cyber-rag-proxy.service &>/dev/null; then
        echo -e "${GREEN}  [OK] MCP Proxy started${NC}"
    else
        echo -e "${RED}  [FAIL] Failed to start MCP Proxy${NC}"
        echo -e "${YELLOW}  Check logs: journalctl --user -u cyber-rag-proxy.service${NC}"
    fi
fi

# 3. Check Ollama
echo -e "\n${YELLOW}[3/4] Checking Ollama service...${NC}"
if curl -s "http://localhost:11434/api/tags" > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] Ollama running${NC}"
    
    # Check embedding model
    if curl -s "http://localhost:11434/api/tags" 2>/dev/null | grep -q "nomic-embed-text"; then
        echo -e "${GREEN}  [OK] Embedding model (nomic-embed-text) available${NC}"
    else
        echo -e "${YELLOW}  [WARN] Embedding model not found${NC}"
    fi
else
    echo -e "${YELLOW}  [WARN] Ollama not running${NC}"
    echo -e "${YELLOW}  Start with: ollama serve &${NC}"
fi

# 4. Health Check
echo -e "\n${YELLOW}[4/4] Health Check...${NC}"
if curl -s "http://127.0.0.1:8642/health" > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] MCP Server healthy (port 8642)${NC}"
else
    echo -e "${RED}  [FAIL] MCP Server not responding${NC}"
fi

if curl -s "http://127.0.0.1:8643/mcp" -X POST -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}' > /dev/null 2>&1; then
    echo -e "${GREEN}  [OK] MCP Proxy healthy (port 8643)${NC}"
else
    echo -e "${RED}  [FAIL] MCP Proxy not responding${NC}"
fi

# Summary
echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Integration Status${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

echo -e "\n  Services:"
echo -e "    • cyber-rag-mcp.service   — MCP Server (SSE, port 8642)"
echo -e "    • cyber-rag-proxy.service — SSE-to-StreamableHTTP Proxy (port 8643)"

echo -e "\n  Hermes MCP Config:"
echo -e "    • cyber_rag.url = http://127.0.0.1:8643/mcp"

echo -e "\n  Available MCP Tools:"
echo -e "    • cyber_rag_query — Query cybersecurity knowledge base"
echo -e "    • analyze_recon_output — Analyze recon tool output"
echo -e "    • analyze_vuln_scan — Analyze vulnerability scanner output"
echo -e "    • pentest_recommend — Get next-step recommendations"
echo -e "    • exploit_guidance — Get exploitation guidance"
echo -e "    • cvss_scoring — CVSS v3.1 assessment"

echo -e "\n  Management Commands:"
echo -e "    • systemctl --user status cyber-rag-mcp cyber-rag-proxy"
echo -e "    • systemctl --user restart cyber-rag-mcp cyber-rag-proxy"
echo -e "    • journalctl --user -u cyber-rag-mcp -f"
echo -e "    • journalctl --user -u cyber-rag-proxy -f"

echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  [DONE] Cyber RAG integration ready!${NC}"
echo -e "${YELLOW}  [NOTE] Restart Hermes Agent to discover MCP tools${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
