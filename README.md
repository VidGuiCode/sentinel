# Sentinel v0.6 - Universal Linux System Monitor

A lightweight terminal UI (TUI) system monitor for Linux with real-time graphs, container monitoring, security log analysis, and infrastructure-focused design. Inspired by btop. Optimized for low-power devices.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-0.6.0-cyan.svg)

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

### v0.6 Features
- **Non-blocking collectors** - Docker, Kubernetes, logs and network lookups run
  on background threads with per-feature intervals; the UI never waits on them
- **No subprocesses on the render path** - Docker Engine API over
  `/var/run/docker.sock`, `urllib` instead of `curl`, no `shell=True` anywhere
- **Change-driven rendering** - the screen repaints only when something actually
  changed, and the input loop sleeps until the next change instead of ticking
- **Self-explaining panels** - an unavailable feature says whether it is not
  installed, permission-denied or failed; press `d` for the exact fix command
- **Retryable permissions** - fix a permission mid-session and it is picked up
  within 30s, no restart
- **Leaner light mode** - skips the public-IP and update checks, saving ~10MB
  RSS (21MB vs 31MB); recommended on Raspberry Pi
- **Benchmark harness** (`bench/`) - measures CPU, RSS, wakeups and throttling
  under simulated device profiles, verifies graceful degradation, and
  smoke-tests aarch64/armv7 under QEMU

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
sentinel --light              # Lightweight mode (low-end VMs, Pi3)
sentinel --host hosts.json    # Fleet overview of many hosts over SSH
sentinel --help               # Show options
```

### Fleet Mode (`--host`)

One screen for the whole homelab - no agent, just SSH + `python3` on each node:

```json
{
  "nodes": [
    {"name": "pi4", "host": "192.168.1.10", "user": "pi", "port": 22},
    {"name": "vps-ams", "host": "vps.example.com", "user": "root"},
    {"name": "homelab", "host": "10.0.0.5", "user": "admin", "key": "~/.ssh/homelab"}
  ]
}
```

```bash
# copy this same file to each host first, then:
sentinel --host sentinel-hosts.json
```

Each row shows CPU%, MEM%, load, uptime, containers, pods and alert count.
`j`/`k` to move, `Enter` to SSH into that host and launch Sentinel there,
`r` to re-probe all hosts in parallel, `q` to quit. Dark hosts show *why*
(timeout, auth failure, missing file) instead of vanishing.

### Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Force refresh |
| `t` | Cycle themes |
| `l` | Cycle layouts |
| `h` | Toggle help overlay |
| `d` | Diagnostics / Permission check |
| `i` | Check public IP |
| `+` | Faster refresh (min 1s) |
| `-` | Slower refresh (max 10s) |

### Permission Status

Sentinel now detects and displays permission status for all features in the header:

- **D** = Docker, **K** = Kubernetes, **W** = WireGuard
- **S** = Security logs, **P** = Proxy logs, **R** = RAPL energy
- **Green** = working, **Red** = permission denied, **Hidden** = not installed

Press `d` to see a full diagnostics panel with:
- Which features are available vs. permission-denied
- Exact commands to fix permissions
- Real-time status of Docker, K8s, WireGuard, logs, and more

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
  },
  "health_checks": {
    "nginx-proxy": {"url": "http://localhost:80", "expect": 200},
    "nextcloud": {"url": "http://localhost:8080/login", "expect": 200}
  },
  "listeners": [22, 80, 443]
}
```

A container can be "running" while the app inside has crashed, so a green
`●` (healthy) or red `✗` (down) is shown next to each running container name
in the Docker panel. Listener ports that fail to connect raise a `PORT
CLOSED` alert; containers whose check fails raise `SERVICE DOWN`. Both also
appear in `sentinel --dump` (`health_healthy`, `health_down`,
`health_listeners`) and in the fleet table.

### Systemd Service

```bash
sudo cp sentinel.service /etc/systemd/system/
sudo systemctl enable --now sentinel
journalctl -u sentinel -f
```

## Requirements

- Python 3.6+ (standard library only - no pip packages)
- Linux kernel 4.0+
- Architectures: x86_64, aarch64, armv7 (ARM verified under QEMU emulation)
- Optional, for the features that use them: `docker` (read access to
  `/var/run/docker.sock`), `kubectl`, `wg` (WireGuard), `iwgetid` (WiFi SSID),
  lm-sensors

Anything missing or unreadable is reported in the diagnostics overlay (`d`)
with the command to fix it - Sentinel degrades rather than failing.

> On Raspberry Pi and other low-memory hosts, run with `--light`.
> See [PERFORMANCE.md](PERFORMANCE.md) for measured numbers.

## Windows (WSL2)

Sentinel runs on Windows via WSL2 (Windows Subsystem for Linux):

```bash
# In your WSL2 terminal (Ubuntu/Debian/Arch)
sudo apt install python3
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

**Notes:**
- All features work except temperature sensors and RAPL energy (VM limitation)
- Docker monitoring works if Docker Desktop WSL2 integration is enabled
- WireGuard may be limited due to WSL2's NAT network stack
- Security logs are typically empty unless `sshd` is running inside WSL2

## Changelog

Full detail with rationale for each change: [CHANGELOG.md](CHANGELOG.md).
Measured numbers: [PERFORMANCE.md](PERFORMANCE.md).

### v0.6.1
- **Fleet mode (`--host`)** - one table for the whole homelab over plain SSH:
  per-host CPU/RAM/load/uptime/containers/pods/alerts, `Enter` to SSH in,
  `r` to refresh in parallel. No agent - the probe is `sentinel --dump`
  (one JSON line) on the remote side.

### v0.6.0
- **Non-blocking UI** - slow collectors (Docker, Kubernetes, logs, network
  lookups) moved to background threads with per-feature intervals. Worst-case
  CPU spike on a Pi 3 profile dropped from 12.9% to 1.3% of CPU quota.
- **No subprocesses on the render path** - Docker CLI replaced by the Engine
  API over `/var/run/docker.sock`, `curl` replaced by `urllib`, `shell=True`
  removed entirely.
- **Repaint only on change** - full-screen redraws cut by ~75% at the default
  refresh rate, and the input loop no longer wakes every 500ms to do nothing.
- **Panels explain themselves** - a feature that is unavailable now states
  whether it is not installed, permission-denied, or failed, and press `d`
  for the exact fix command. 36 bare `except:` blocks removed.
- **Retryable permissions** - fixing a permission mid-session is picked up
  within 30s; no restart needed.
- **Lower memory in `--light`** - light mode skips the public-IP and update
  checks, avoiding a ~10MB `urllib`/`ssl` import (21MB vs 31MB RSS).
  **Recommended on Pi-class hardware.**
- **Benchmark harness** - `bench/` measures CPU, RSS, wakeups and throttling
  under simulated device profiles, and verifies graceful degradation.
- **ARM verified** - aarch64 and armv7 smoke-tested under QEMU emulation
  (16/16 checks). Compatibility only; all published performance numbers are
  x86_64.

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
