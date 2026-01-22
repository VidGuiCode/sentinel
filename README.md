# Sentinel v0.5 - Universal Linux System Monitor

A lightweight terminal UI (TUI) system monitor for Linux with real-time graphs, container monitoring, security log analysis, and infrastructure-focused design. Inspired by btop. Optimized for low-power devices.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-0.5.0-cyan.svg)

## Quick start

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

## Features

### System Monitoring
- **CPU** - Per-core usage bars, gradient graph, temperature, frequency, governor
- **Memory** - Usage with history graph, available memory tracking
- **Disk** - Mount points with progress bars, Docker volume names & sizes
- **Network** - Live traffic (KB/s), sparkline graphs, VPN status, proxy stats
- **Energy** - RAPL power (desktops), battery stats (laptops)
- **Docker** - Dynamic container list, running/stopped count, volume sizes
- **Kubernetes** - Pod status, node health, failed/pending alerts
- **Processes** - Task count, top CPU/memory consumers
- **Proxy** - Nginx/Caddy traffic monitoring (requests per second)
- **Security** - Authentication log analysis, failed login tracking, brute force detection

### v0.5 Features
- **Security log monitoring** - Real-time analysis of auth.log, syslog, and secure logs
- **Failed login tracking** - Monitor authentication failures with IP address tracking
- **Brute force detection** - Automatic alerts for >20 failed logins from same IP in 5 minutes
- **Security statistics** - Top suspicious IPs, failed vs successful login ratios, error type tracking
- **Regex-based log parsing** - Extract timestamps, hostnames, programs, PIDs, usernames, and IPs
- **Security layout mode** - Press `l` to emphasize security monitoring panel
- **Windowed analysis** - Time-based metrics for failed logins per 5-minute windows

### v0.4 Features
- **Loading modal** - Shows spinner during initial data load
- **Help overlay** - Press `h` to see all keybindings
- **Adjustable refresh rate** - Press `+`/`-` to speed up or slow down (1-10s)
- **Layout modes** - Press `l` to cycle: default, cpu, network, docker, security, minimal
- **Dynamic container lists** - Auto-adjusts to available space
- **Improved temperature detection** - Works on ARM, VMs, containers
- **Proxy traffic monitoring** - Shows nginx/caddy requests per second
- **Wider graphs** - 100 data points for full-width terminal graphs
- **Performance optimized** - Fast startup on low-power devices
- **Enhanced network panel** - Connection quality meter, VPN handshake age, proper link speed
- **Docker volumes with sizes** - Shows actual volume names and storage used

### Themes
5 built-in color themes (press `t` to cycle):

| Theme | Description |
|-------|-------------|
| `default` | Cyan/green terminal colors |
| `nord` | Arctic, bluish color palette |
| `dracula` | Dark purple/pink theme |
| `gruvbox` | Retro, warm colors |
| `monokai` | Classic editor theme |

Use `--theme <name>` or press `t` in the TUI to switch.

### Alerts
- CPU usage warnings (configurable thresholds)
- Temperature color coding (green/yellow/red)
- Memory pressure indicators
- Battery low warnings
- Docker stopped container alerts
- Kubernetes failed pod alerts

### Network
- Local IP detection
- Public IP detection (cached, non-blocking)
- WireGuard VPN status with peer count and handshake age
- Real-time traffic graphs with speed indicators
- Total RX/TX statistics
- Reverse proxy traffic (nginx/caddy)
- Connection quality signal meter
- Link speed display (Mbps/Gbps)

## Installation

### One-Line Install

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

### From Source

```bash
git clone https://github.com/VidGuiCode/sentinel.git
cd sentinel
sudo bash install-sentinel.sh
```

### Manual (No Installer)

```bash
sudo apt-get install python3 lm-sensors curl
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/sentinel-monitor.py | sudo tee /usr/local/bin/sentinel > /dev/null
sudo chmod +x /usr/local/bin/sentinel
```

## Usage

```bash
sentinel                      # Run TUI
sentinel --theme nord         # Use Nord theme
sentinel --service            # Headless service mode
sentinel --init-config        # Create config file
sentinel --help               # Show options
```

### Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Force refresh |
| `t` | Cycle themes |
| `l` | Cycle layouts |
| `h` | Toggle help overlay |
| `i` | Check public IP |
| `+` | Faster refresh (min 1s) |
| `-` | Slower refresh (max 10s) |

### Layout Modes

Press `l` to cycle through layouts:
- **default** - Balanced view of all panels
- **cpu** - Emphasize CPU monitoring
- **network** - Emphasize network stats
- **docker** - Emphasize container info
- **security** - Emphasize security log monitoring
- **minimal** - Compact essential stats only

### Configuration

Create config with `sentinel --init-config`:

```json
{
  "theme": "default",
  "layout": "default",
  "refresh_rate": 2,
  "alerts": {
    "cpu_high": 85,
    "cpu_critical": 95,
    "mem_high": 80,
    "temp_high": 75,
    "battery_low": 20
  },
  "proxy_logs": {
    "nginx": "/var/log/nginx/access.log",
    "caddy": "/var/log/caddy/access.log"
  },
  "security_logs": {
    "auth": "/var/log/auth.log",
    "secure": "/var/log/secure",
    "syslog": "/var/log/syslog"
  },
  "security_alerts": {
    "failed_login_threshold": 20,
    "failed_login_window": 300,
    "suspicious_ip_threshold": 10,
    "error_rate_threshold": 10,
    "error_rate_window": 60
  }
}
```

### Systemd Service

```bash
sudo cp sentinel.service /etc/systemd/system/
sudo systemctl enable --now sentinel
journalctl -u sentinel -f
```

## Requirements

- Python 3.6+
- Linux kernel 4.0+
- Optional: lm-sensors, curl, docker, kubectl

## Changelog

### v0.5.0
- **Security log monitoring** - Real-time analysis of Linux authentication logs
- **Failed login tracking** - Monitor and track authentication failures by IP and user
- **Brute force detection** - Alert system for suspicious login patterns (>20 attempts/5min)
- **Security statistics** - Top 10 suspicious IPs, failed/successful login ratios, error type breakdown
- **Regex-based parsing** - Extract minimum 3 fields per log entry (timestamp, hostname, program, PID, user, IP)
- **Security layout mode** - New layout emphasizing security monitoring panel
- **Windowed metrics** - Time-based analysis with 5-minute sliding windows
- **Configurable alerts** - Customizable thresholds for failed login detection
- **Multi-log support** - Parses auth.log (Debian/Ubuntu), secure (RHEL/CentOS), and syslog
- Security alerts integrated into main alert system with color-coded severity

### v0.4.0
- Loading modal with spinner on startup
- Help overlay (press `h`)
- Adjustable refresh rate (`+`/`-` keys, 1-10 seconds)
- Layout modes: default, cpu, network, docker, minimal
- Dynamic Docker/K8s container lists (auto-adjusts to space)
- Improved temperature detection (ARM, VMs, containers)
- Reverse proxy traffic monitoring (nginx/caddy)
- Wider graphs (100 data points)
- Docker volumes with names and sizes
- Performance optimized for low-power devices
- Enhanced network panel:
  - Connection quality signal meter (5-bar indicator)
  - VPN peer handshake age display
  - Fixed link speed (hides invalid -1 values, shows Gbps)
  - Full VPN peer IPs (no more truncation)

### v0.3.0
- Docker container and volume monitoring
- Kubernetes pod/node monitoring  
- Config file support
- 5 color themes
- Alert thresholds
- Systemd service mode
- Per-core CPU bars

### v0.2.0
- btop-inspired UI redesign
- RAPL energy monitoring
- Performance optimization
- Gradient graphs and bars

### v0.1.0
- Initial release

## Open Source

Sentinel is MIT-licensed and built for homelab and Linux users. You can:

- Use it freely on any Linux machine
- Open issues or feature requests on GitHub
- Send pull requests (new panels, themes, bug fixes)
- Fork it and adapt it for your own infrastructure

## License

MIT License - See LICENSE file.
