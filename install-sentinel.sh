#!/bin/bash
# Sentinel: Linux System Monitor
# Install Script for many Linux forms
#
# Use it to update too: run it again. It replaces /usr/local/bin/sentinel.
# It never touches your configuration file (~/.config/sentinel/config.json).

set -e

# Read the version from the file that gets installed, never write it here.
# A fixed value in this script goes stale at each release. Then it prints
# a wrong version at the end of a good install.
VERSION=""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BOX_W=47

# Fill a line to the box width, so edges line up for all text lengths.
box_line() {
    local text="$1"
    local len=${#text}
    local pad=$(( BOX_W - len ))
    [ $pad -lt 0 ] && pad=0
    printf "║%s%*s║\n" "$text" "$pad" ""
}

installed_version() {
    /usr/local/bin/sentinel --version 2>/dev/null | awk '{print $NF}' | tr -d 'v'
}

print_header() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    box_line "   SENTINEL - System Monitor"
    box_line "   Universal Linux Installer"
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
    echo -e "${YELLOW}[1/4] Install packages for ${distro}...${NC}"
    
    case $distro in
        ubuntu|debian|pop|linuxmint|raspbian)
            apt-get update -qq 2>/dev/null || true
            apt-get install -y python3 curl 2>/dev/null || true
            # Optional: lm-sensors for temperature reads
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
            echo -e "${YELLOW}  Unknown Linux form, Sentinel needs Python3${NC}"
            ;;
    esac
    echo -e "${GREEN}  Done: packages ready${NC}"
}

# Need root rights
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run with sudo${NC}"
    echo "  sudo bash $0"
    exit 1
fi

print_header

# Find the Linux form
DISTRO=$(detect_distro)
echo -e "Detected: ${CYAN}${DISTRO}${NC}"

# Find the script directory (for a local run)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" 2>/dev/null )" 2>/dev/null && pwd )"
GITHUB_RAW="https://raw.githubusercontent.com/VidGuiCode/sentinel/main"

# Install the needed packages
install_deps "$DISTRO"

echo -e "${YELLOW}[2/4] Set up sensors...${NC}"
# Find sensors (no questions, no output)
if command -v sensors-detect &> /dev/null; then
    yes | sensors-detect >/dev/null 2>&1 || sensors-detect --auto >/dev/null 2>&1 || true
fi
echo -e "${GREEN}  Done: sensor check complete${NC}"

echo -e "${YELLOW}[3/4] Install Sentinel...${NC}"
# Read the old version first, so an update can print old to new.
PREV_VERSION=""
if [ -x /usr/local/bin/sentinel ]; then
    PREV_VERSION=$(installed_version)
fi
# Take the local file first, else fetch it from GitHub
if [ -f "$SCRIPT_DIR/sentinel-monitor.py" ]; then
    cp "$SCRIPT_DIR/sentinel-monitor.py" /usr/local/bin/sentinel
else
    echo "  Fetch from GitHub..."
    curl -sL "$GITHUB_RAW/sentinel-monitor.py" -o /usr/local/bin/sentinel
fi
chmod 755 /usr/local/bin/sentinel

# Create short alias
ln -sf /usr/local/bin/sentinel /usr/local/bin/sen
echo -e "${GREEN}  Done: installed to /usr/local/bin/sentinel${NC}"

echo -e "${YELLOW}[4/4] Set up shell aliases...${NC}"
# Find the user who ran sudo
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo ~$REAL_USER)

# Add the lines to user bashrc when missing
if ! grep -q "alias sentinel=" "$REAL_HOME/.bashrc" 2>/dev/null; then
    echo "" >> "$REAL_HOME/.bashrc"
    echo "# Sentinel System Monitor" >> "$REAL_HOME/.bashrc"
    echo "alias sentinel='/usr/local/bin/sentinel'" >> "$REAL_HOME/.bashrc"
    echo "alias sen='/usr/local/bin/sentinel'" >> "$REAL_HOME/.bashrc"
    chown $REAL_USER:$REAL_USER "$REAL_HOME/.bashrc"
fi
echo -e "${GREEN}  Done: aliases set${NC}"

VERSION=$(installed_version)
[ -z "$VERSION" ] && VERSION="(unknown)"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
if [ -n "$PREV_VERSION" ] && [ "$PREV_VERSION" != "$VERSION" ]; then
    echo -e "${GREEN}$(box_line "  Sentinel updated: v${PREV_VERSION} to v${VERSION}")${NC}"
else
    echo -e "${GREEN}$(box_line "  Sentinel v${VERSION} installed")${NC}"
fi
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Usage:${NC}"
echo "  sentinel      - Open the Sentinel panel"
echo "  sen           - Short alias"
echo ""
echo -e "${CYAN}Controls:${NC}"
echo "  q - Quit       r - Refresh    t - Theme"
echo "  l - Layout     h - Help       i - Refresh public IP"
echo "  j/k - Mark container   x - Restart (asks first)"
echo "  s - Stop (asks first)  k - Kill PID (asks first)"
echo "  u - Check updates      a - Apply updates (asks first)"
echo "  p - Ping a host"
echo "  d - Diagnostics (why a panel is empty and how to fix it)"
echo "  +/- Set the refresh rate (1-10s)"
echo ""
echo -e "${CYAN}v0.6 New:${NC}"
echo "  - Panel never waits: slow collectors run off the UI thread"
echo "  - No calls on the draw path (Docker talks through the socket API)"
echo "  - Repaint only on change, far fewer wakeups"
echo "  - Panels state why they are empty, press d for the fix command"
echo "  - Rights re-checked every 30s, no restart needed"
echo "  - Light --light mode (near 21MB, not 31MB RSS)"
echo ""
echo -e "${CYAN}Past Features:${NC}"
echo "  - Security log reads, brute force find"
echo "  - 6 views: default, cpu, network, docker, security, minimal"
echo "  - Docker and Kubernetes data, proxy traffic numbers"
echo "  - Set the refresh rate, 5 color themes"
echo ""
echo -e "${CYAN}Options:${NC}"
echo "  sentinel --light         Small memory mode (use it on Raspberry Pi)"
echo "  sentinel --theme nord    Set the Nord theme"
echo "  sentinel --init-config   Create the configuration file"
echo "  sentinel --service       Headless mode"
echo "  sentinel --host hosts.json  Fleet view of many hosts through SSH"
echo ""
echo -e "${CYAN}To update later:${NC} run this installer again (it keeps your configuration file)"
echo ""
echo -e "Try it now: ${GREEN}sentinel${NC}"
echo ""
