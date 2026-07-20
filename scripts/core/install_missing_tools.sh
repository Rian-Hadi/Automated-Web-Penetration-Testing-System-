#!/bin/bash
# Install missing pentest tools from tools_config.yaml
# Run: bash install_missing_tools.sh

echo "=========================================="
echo "  INSTALLING MISSING PENTEST TOOLS"
echo "=========================================="

# Colors
GREEN='\033[0;92m'
RED='\033[0;91m'
YELLOW='\033[0;93m'
NC='\033[0m'

install_go_tool() {
    local tool=$1
    local repo=$2
    echo -e "${YELLOW}Installing $tool...${NC}"
    go install -v "$repo@latest" 2>/dev/null && echo -e "${GREEN}✅ $tool installed${NC}" || echo -e "${RED}❌ Failed to install $tool${NC}"
}

# Update Go path
export PATH=$PATH:~/go/bin

echo ""
echo "--- Go-based Tools ---"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}Go is not installed. Installing...${NC}"
    sudo apt install -y golang-go 2>/dev/null || echo "Install Go manually: https://golang.org/dl/"
fi

# Install Go tools
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "dalfox" "github.com/hahwul/dalfox/v2"
install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
install_go_tool "hakrawler" "github.com/hakluke/hakrawler"
install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace"
install_go_tool "unfurl" "github.com/tomnomnom/unfurl"
install_go_tool "anew" "github.com/tomnomnom/anew"
install_go_tool "gf" "github.com/tomnomnom/gf"
install_go_tool "httprobe" "github.com/tomnomnom/httprobe"
install_go_tool "subzy" "github.com/PentestPad/subzy"
install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu"
install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx"
install_go_tool "findomain" "github.com/findomain/findomain"

echo ""
echo "--- Python Tools ---"

# Install Python tools
pip3 install shodan censys pyjwt 2>/dev/null && echo -e "${GREEN}✅ Python tools installed${NC}"

echo ""
echo "--- Setup GF Patterns ---"

# Setup GF patterns
if [ ! -d ~/.gf ]; then
    mkdir -p ~/.gf
    git clone https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns 2>/dev/null
    cp /tmp/gf-patterns/*.json ~/.gf/ 2>/dev/null
    echo -e "${GREEN}✅ GF patterns installed${NC}"
else
    echo -e "${GREEN}✅ GF patterns already exist${NC}"
fi

echo ""
echo "=========================================="
echo "  INSTALLATION COMPLETE"
echo "=========================================="
echo ""
echo "Run 'source ~/.bashrc' or restart terminal"
echo "Then verify: python3 pentest_toolkit.py --check"
