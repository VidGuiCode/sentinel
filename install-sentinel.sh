#!/bin/bash
# Sentinel v0.3 - Universal Linux System Monitor
# Multi-distro Installation Script

set -e

VERSION="0.3.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║   SENTINEL v${VERSION} - System Monitor        ║"
    echo "║   Universal Linux Installer                   ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
    elif [ -f /etc/debian_version ]; then
        DISTRO="debian"
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
    elif [ -f /etc/arch-release ]; then
        DISTRO="arch"
    else
        DISTRO="unknown"
    fi
    echo "$DISTRO"
}

install_deps() {
    local distro=$1
    echo -e "${YELLOW}[1/4] Installing dependencies for ${distro}...${NC}"
    
    case $distro in
        ubuntu|debian|pop|linuxmint|raspbian)
            apt-get update -qq 2>/dev/null || true
            apt-get install -y python3 curl 2>/dev/null || true
            # Optional: lm-sensors for temperature
            apt-get install -y lm-sensors 2>/dev/null || echo "  Note: lm-sensors optional"
            ;;
        fedora|rhel|centos|rocky|alma)
            dnf install -y python3 curl 2>/dev/null || yum install -y python3 curl 2>/dev/null || true
            dnf install -y lm_sensors 2>/dev/null || yum install -y lm_sensors 2>/dev/null || true
            ;;
        arch|manjaro|endeavouros)
            pacman -Sy --noconfirm python curl lm_sensors 2>/dev/null || true
            ;;
        opensuse*|suse)
            zypper install -y python3 curl sensors 2>/dev/null || true
            ;;
        alpine)
            apk add python3 curl lm-sensors 2>/dev/null || true
            ;;
        *)
            echo -e "${YELLOW}  Unknown distro, assuming Python3 is installed${NC}"
            ;;
    esac
    echo -e "${GREEN}  ✓ Dependencies ready${NC}"
}

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run with sudo${NC}"
    echo "  sudo bash $0"
    exit 1
fi

print_header

# Detect distro
DISTRO=$(detect_distro)
echo -e "Detected: ${CYAN}${DISTRO}${NC}"

# Detect script directory (if run locally)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" 2>/dev/null )" 2>/dev/null && pwd )"
GITHUB_RAW="https://raw.githubusercontent.com/VidGuiCode/sentinal/main"

# Install dependencies
install_deps "$DISTRO"

echo -e "${YELLOW}[2/4] Configuring sensors...${NC}"
# Auto-detect sensors (non-interactive, silent)
if command -v sensors-detect &> /dev/null; then
    yes | sensors-detect >/dev/null 2>&1 || sensors-detect --auto >/dev/null 2>&1 || true
fi
echo -e "${GREEN}  ✓ Sensor detection complete${NC}"

echo -e "${YELLOW}[3/4] Installing Sentinel...${NC}"
# Try local file first, then download from GitHub
if [ -f "$SCRIPT_DIR/sentinel-monitor.py" ]; then
    cp "$SCRIPT_DIR/sentinel-monitor.py" /usr/local/bin/sentinel
else
    echo "  Downloading from GitHub..."
    curl -sL "$GITHUB_RAW/sentinel-monitor.py" -o /usr/local/bin/sentinel
fi
chmod 755 /usr/local/bin/sentinel

# Create short alias
ln -sf /usr/local/bin/sentinel /usr/local/bin/sen
echo -e "${GREEN}  ✓ Installed to /usr/local/bin/sentinel${NC}"

echo -e "${YELLOW}[4/4] Setting up shell aliases...${NC}"
# Detect user who ran sudo
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo ~$REAL_USER)

# Add to user's bashrc if not already present
if ! grep -q "alias sentinel=" "$REAL_HOME/.bashrc" 2>/dev/null; then
    echo "" >> "$REAL_HOME/.bashrc"
    echo "# Sentinel System Monitor" >> "$REAL_HOME/.bashrc"
    echo "alias sentinel='/usr/local/bin/sentinel'" >> "$REAL_HOME/.bashrc"
    echo "alias sen='/usr/local/bin/sentinel'" >> "$REAL_HOME/.bashrc"
    chown $REAL_USER:$REAL_USER "$REAL_HOME/.bashrc"
fi
echo -e "${GREEN}  ✓ Aliases configured${NC}"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Sentinel v${VERSION} installed successfully!  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo "  sentinel      - Launch Sentinel monitor"
echo "  sen           - Short alias"
echo ""
echo -e "${CYAN}Controls:${NC}"
echo "  q - Quit    r - Refresh    t - Theme    i - Check IP"
echo ""
echo -e "${CYAN}v0.3 Features:${NC}"
echo "  - Docker container and volume monitoring"
echo "  - Kubernetes pod/node monitoring"
echo "  - 5 color themes (press t to cycle)"
echo "  - Config file support (~/.config/sentinel/config.json)"
echo "  - Systemd service mode (--service)"
echo "  - Per-core CPU bars"
echo ""
echo -e "${CYAN}Options:${NC}"
echo "  sentinel --theme nord    Use Nord theme"
echo "  sentinel --init-config   Create config file"
echo "  sentinel --service       Headless mode"
echo ""
echo -e "Try it now: ${GREEN}sentinel${NC}"
echo ""
