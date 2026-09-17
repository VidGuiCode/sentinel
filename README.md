# Sentinel v0.6 - Linux Host Monitor

Sentinel monitors Linux hosts in the terminal. It shows live graphs, data from containers, data from security logs, and data from services. It uses one Python file and only the standard library. btop gave the idea for the design. It runs on hosts with small CPUs and small memory.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-0.6.2-cyan.svg)

## Quick start

To start Sentinel fast, do these steps:

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

- Install Sentinel with the command in the code block.
- Type `sentinel` in the terminal.

## Features

### Core data

- **CPU** - Sentinel shows bars for each core, a graph for load, heat data, clock speed, and the governor name.
- **Memory** - Sentinel shows use of memory, free memory, and a graph for past use.
- **Disk** - Sentinel shows mount points, free space bars, volume names from Docker, and size data.
- **Network** - Sentinel shows traffic in KB/s, small graphs, VPN state, and proxy facts.
- **Energy** - Sentinel shows power data from RAPL on desk hosts and battery data on portable hosts.
- **Docker** - Sentinel shows the list of containers, the count of containers that run, the count of containers that stop, and the size of volumes.
- **Kubernetes** - Sentinel shows the state of pods, the state of nodes, and alerts for pods that fail or wait.
- **Processes** - Sentinel shows the task count and the top users of CPU and memory.
- **Proxy** - Sentinel shows requests per second for Nginx and Caddy.
- **Security** - Sentinel reads auth logs, counts failed logins, and raises alerts for brute force attacks.

### v0.6 Features

- **Collectors that do not block** - Collectors run in background threads.
  Collectors cover Docker, Kubernetes, logs, and network lookups. Each
  collector uses its own interval. The screen never waits for a collector.
- **Zero child acts on the screen path** - Sentinel talks to the Docker
  Engine API through `/var/run/docker.sock`. It uses `urllib` in place of
  `curl`. It starts zero child processes and uses zero `shell=True`.
- **Paint only on change** - The screen paints again only when a fact changes. The input loop sleeps till the next change.
- **Panels that state the cause** - A panel that lacks data states the
  cause. The cause is one of three: the tool misses on the host, access
  fails, or the probe fails. Press `d` for the exact fix command.
- **Access fix with zero restart** - You fix access in mid-session. Sentinel picks up the fix in 30s. You need zero restart.
- **Light mode with less memory** - Light mode skips the public-IP check
  and the update check. It saves ~10MB RSS (21MB vs 31MB). Use it on
  Raspberry Pi.
- **Test rig in `bench/`** - The `bench/` folder measures CPU, RSS,
  wakeups, and throttle facts. It uses simulated host profiles. It checks
  that Sentinel slows in safe steps. It tests aarch64 and armv7 under QEMU.

### v0.5 Features

- **Security log read** - Sentinel reads auth.log, syslog, and secure logs as facts arrive.
- **Failed login count** - Sentinel counts failed logins with the IP address for each case.
- **Brute force alert** - Sentinel raises an alert for more than 20 failed logins from one IP in 5 minutes.
- **Security facts** - Sentinel shows top suspect IPs, the ratio of failed to good logins, and error type counts.
- **Pattern parse** - Sentinel pulls time, host name, program, PID, user name, and IP from each log line with patterns.
- **Security view** - Press `l` to stress the security panel.
- **Span counts** - Sentinel counts failed logins per 5-minute span.

### v0.4 Features

- **Load modal** - Sentinel shows a spinner while it loads first data.
- **Help overlay** - Press `h` to see all keys.
- **Refresh speed** - Press `+` to raise the refresh speed. Press `-` to lower the refresh speed. The range spans 1s to 10s.
- **Views** - Press `l` to cycle the views: default, cpu, network, docker, security, minimal.
- **Container lists** - Sentinel fits the container list to free screen space.
- **Heat read** - Sentinel reads heat data on ARM, VMs, and containers.
- **Proxy facts** - Sentinel shows requests per second for nginx and caddy.
- **Wide graphs** - Graphs hold 100 points and fill the full terminal width.
- **Fast start** - Sentinel starts fast on hosts with small CPUs.
- **Network panel** - The network panel shows more facts:
  - A 5-bar meter shows link quality.
  - It shows the age of each WireGuard peer handshake.
  - It hides bad -1 values and shows Gbps speed.
  - It shows full VPN peer IPs with zero cut text.
- **Volume facts** - Sentinel shows true volume names and used space.

### Themes

Sentinel has 5 color themes. Press `t` to cycle through them.

| Theme | Description |
|-------|-------------|
| `default` | Cyan/green terminal colors |
| `nord` | Arctic, bluish color palette |
| `dracula` | Dark purple/pink theme |
| `gruvbox` | Retro, warm colors |
| `monokai` | Classic editor theme |

Use `--theme <name>` or press `t` in the terminal to change the theme.

### Alerts

- Sentinel alerts on high CPU use with limits that you set.
- Sentinel marks heat with green, yellow, or red.
- Sentinel flags memory strain.
- Sentinel alerts on low battery.
- Sentinel alerts on stopped containers in Docker.
- Sentinel alerts on failed pods in Kubernetes.

### Network

- Sentinel finds the local IP.
- Sentinel finds the public IP with a stored value and zero block.
- Sentinel shows WireGuard VPN state with peer count and handshake age.
- Sentinel shows live traffic graphs with speed facts.
- Sentinel shows total RX and TX counts.
- Sentinel shows proxy traffic for nginx and caddy.
- Sentinel shows a signal meter for link quality.
- Sentinel shows link speed in Mbps or Gbps.

## Installation

### One-Line Install

Pick one command. Type it in the terminal.

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

You can also use wget.

```bash
wget -qO- https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

### From Source

To build from source, do these steps in order:

```bash
git clone https://github.com/VidGuiCode/sentinel.git
cd sentinel
sudo bash install-sentinel.sh
```

### Manual (No Installer)

To install by hand with zero installer, do these steps in order:

```bash
sudo apt-get install python3 lm-sensors curl
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/sentinel-monitor.py | sudo tee /usr/local/bin/sentinel > /dev/null
sudo chmod +x /usr/local/bin/sentinel
```

## Usage

Type one of these commands in the terminal:

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

One screen covers the full homelab. It needs zero agent. It needs only SSH and `python3` on each host:

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

Each row shows CPU%, MEM%, load, uptime, containers, pods, and alert count.

- Press `j` or `k` to move the mark.
- Press `Enter` to open SSH to that host. Then start Sentinel on that host.
- Press `r` to probe all hosts again at the same time.
- Press `q` to quit.

A dark host states the cause: timeout, auth failure, or lost file.

### Keyboard Controls

Press these keys in the terminal.

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

### Permission state

Sentinel marks access for all tools in the header:

- D means Docker, K means Kubernetes, and W means WireGuard.
- S means security logs, P means proxy logs, and R means RAPL energy.
- Green means the tool acts, red means access fails, and zero mark means the host lacks the tool.

Press `d` to open the diagnostics overlay. It lists:

- Tools that act and tools with failed access.
- Exact commands that fix access.
- Live state of Docker, Kubernetes, WireGuard, logs, and more tools.

### Views

Press `l` to cycle through the views.

- **default** shows all panels in balance.
- **cpu** puts CPU facts first.
- **network** puts network facts first.
- **docker** puts container facts first.
- **security** puts security log facts first.
- **minimal** shows only core facts.

### Configuration

Create the configuration file with `sentinel --init-config`:

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

A container can run while the app in it dies. Sentinel puts a green `●` (healthy) or a red `✗` (down) near the name of each container that runs in the Docker panel. A check name can be short: `web` matches a container named `project-web-1`. A full name always wins over a short name. A listener port that fails to connect raises a `PORT CLOSED` alert. A container with a failed health check raises a `SERVICE DOWN` alert. The `sentinel --dump` output and the fleet table also hold `health_healthy`, `health_down`, and `health_listeners`. Light mode skips HTTP checks (they need `urllib`, which costs ~10MB). TCP listener checks still run in light mode.

### Systemd Service

To run Sentinel as a service, type these commands in order:

```bash
sudo cp sentinel.service /etc/systemd/system/
sudo systemctl enable --now sentinel
journalctl -u sentinel -f
```

## Requirements

You need Python 3.6+. Sentinel uses only the standard library with zero pip packages.

You need Linux kernel 4.0+.

Sentinel runs on x86_64, aarch64, and armv7. Tests cover ARM under QEMU.

Some tools add facts when the host has them: `docker` with read access to `/var/run/docker.sock`, `kubectl`, `wg` (WireGuard), `iwgetid` (WiFi SSID), and lm-sensors.

Sentinel lists each lost or locked tool in the diagnostics overlay (`d`) with the command that fixes it. Sentinel still runs with less facts.

> On Raspberry Pi and hosts with small memory, use `--light`.
> See [PERFORMANCE.md](PERFORMANCE.md) for measured numbers.

## Windows (WSL2)

Sentinel runs on Windows through WSL2:

```bash
# In your WSL2 terminal (Ubuntu/Debian/Arch)
sudo apt install python3
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

**Notes:**

- All tools act except heat sensors and RAPL energy, a VM limit.
- Sentinel reads Docker facts when you enable integration of Docker Desktop with WSL2.
- WSL2 NAT stack can curb WireGuard.
- Security logs stay empty unless `sshd` acts in WSL2.

## Changelog

The full facts for each change stay in [CHANGELOG.md](CHANGELOG.md). Measured numbers stay in [PERFORMANCE.md](PERFORMANCE.md).

### v0.6.1

Fleet mode (`--host`) shows one table for the full homelab through plain SSH. Each host row holds CPU, RAM, load, uptime, containers, pods, and alerts. Press `Enter` to open SSH to that host. Press `r` to probe all hosts at the same time. It needs zero agent. The probe is `sentinel --dump` (one JSON line) on the far host.

### v0.6.0

- **No block from slow collectors** - Slow collectors (Docker, Kubernetes,
  logs, network lookups) run in background threads with own intervals.
  Worst CPU use on a Pi 3 profile dropped from 12.9% to 1.3% of CPU quota.
- **Zero child acts on the screen path** - Sentinel talks to the Docker
  Engine API through `/var/run/docker.sock`. It uses `urllib` in place of
  `curl`. The code holds zero `shell=True`.
- **Paint only on change** - Full screen paints fell by ~75% at the default
  refresh speed. The input loop no longer wakes each 500ms with zero task.
- **Panels state the cause** - A tool that lacks data states the cause.
  The cause is one of three: the host lacks the tool, access fails, or the
  probe fails. Press `d` for the exact fix command. 36 bare `except:`
  blocks left the code.
- **Access fix with zero restart** - A fix to access in mid-session acts in 30s. You need zero restart.
- **Less memory in `--light`** - Light mode skips the public-IP check and
  the update check. It avoids a ~10MB `urllib`/`ssl` load (21MB vs 31MB
  RSS). Use it on Pi-class hosts.
- **Test rig in `bench/`** - `bench/` measures CPU, RSS, wakeups, and throttle facts in simulated host profiles. It checks safe slowdown.
- **ARM tests pass** - aarch64 and armv7 pass 16 of 16 checks under QEMU. These tests prove fit only. All speed facts come from x86_64.

### v0.5.0

- **Security log read** - Sentinel reads Linux auth logs as facts arrive.
- **Failed login count** - Sentinel counts failed logins by IP and user.
- **Brute force alert** - Sentinel alerts on suspect login runs with more than 20 tries in 5 minutes.
- **Security facts** - Sentinel shows top 10 suspect IPs, ratios of failed to good logins, and error type parts.
- **Pattern parse** - Sentinel pulls at least 3 fields per log line: time, host name, program, PID, user, IP.
- **Security view** - New view puts the security panel first.
- **Span metrics** - Time-span counts with 5-minute spans.
- **Alert limits** - You set own limits for failed login alerts.
- **Many log types** - Sentinel reads auth.log (Debian/Ubuntu), secure (RHEL/CentOS), and syslog.
- **Main alert set** - Alerts join the main alert set with color marks for risk.

### v0.4.0

- **Load modal** - Sentinel shows a load modal with a spinner at start.
- **Help overlay** - Press `h` for help.
- **Refresh speed** - Press `+` to raise the refresh speed. Press `-` to lower the refresh speed. The range spans 1s to 10s.
- **Views** - Views hold default, cpu, network, docker, and minimal.
- **Container lists** - Docker and Kubernetes lists fit free screen space.
- **Heat read** - Sentinel reads heat on ARM, VMs, and containers.
- **Proxy facts** - Sentinel shows nginx and caddy traffic.
- **Wide graphs** - Graphs hold 100 points.
- **Volume facts** - Docker volumes show names and size.
- **Fast start** - Sentinel starts fast on hosts with small CPUs.
- **Network panel** - The network panel shows more facts:
  - A 5-bar meter shows link quality.
  - It shows the age of each WireGuard peer handshake.
  - It hides bad -1 values and shows Gbps speed.
  - It shows full VPN peer IPs with zero cut text.

### v0.3.0

- **Docker facts** - Sentinel reads Docker containers and volumes.
- **Kubernetes facts** - Sentinel reads Kubernetes pods and nodes.
- **Configuration file** - Sentinel reads the configuration file.
- **Themes** - Sentinel holds 5 color themes.
- **Alert limits** - You set alert limits.
- **Service mode** - Sentinel runs as a systemd service.
- **CPU bars** - Sentinel shows CPU bars for each core.

### v0.2.0

- **New screen** - New screen follows the btop style.
- **Energy facts** - Sentinel reads RAPL energy facts.
- **Fast start** - Sentinel starts fast on hosts with small CPUs.
- **Graphs** - Sentinel draws slope graphs and bars.

### v0.1.0

Sentinel saw first release.

## Open Source

The MIT License covers Sentinel. Sentinel serves homelab and Linux users. You can:

- Use it free on each Linux host.
- Open issues or feature requests on GitHub.
- Send pull requests for new panels, themes, or bug fixes.
- Fork it and fit it to your own hosts.

## License

The MIT License rules. See the LICENSE file.
