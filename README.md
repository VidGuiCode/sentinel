# Sentinel v0.6 - Linux Host Monitor

Sentinel monitors Linux hosts in the terminal. It shows live graphs, data
from containers, data from security logs, and data from services. One
Python file holds all code. It uses only the standard library. It runs on
hosts with small CPUs and small memory.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-0.6.6-cyan.svg)

## Quick start

Type two commands. Sentinel starts in seconds.

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

Done. No pip packages. No daemon. No account.

## Why Sentinel

btop shows one host. Grafana needs a server, agents, and a weekend of
setup. Sentinel sits between them: one file, full facts, zero setup.

| Task | Sentinel | btop | Grafana stack |
|------|----------|------|---------------|
| Install | one command | package install | server + agents + DB |
| One host live view | yes | yes | yes |
| Full fleet on one screen | yes (`--host`) | no | yes, after setup |
| Act on the host (restart, kill, update) | yes, with confirm | no (view only) | no |
| Empty panel states the cause | yes (`d`) | n/a | n/a |
| Needs an account or cloud | never | never | often |

## Fleet mode: all hosts, one screen

This is the part other TUI monitors lack. One Sentinel shows each host.

```bash
# 1. Copy the same file to each host.
# 2. List the hosts in JSON:
sentinel --host sentinel-hosts.json
```

```json
{
  "nodes": [
    {"name": "pi4", "host": "192.168.1.10", "user": "pi", "port": 22},
    {"name": "vps-ams", "host": "vps.example.com", "user": "root"},
    {"name": "homelab", "host": "10.0.0.5", "user": "admin", "key": "~/.ssh/homelab"}
  ]
}
```

```
  HOST               CPU%   MEM%   LOAD            UPTIME      CTNRS  PODS  ALERTS / STATUS
  pi4                  12     44   0.50,0.40,0.30  3d 1h 2m      2/3     5  ok ●2
  vps-ams               8     61   0.20,0.15,0.10  12d 4h 9m     4/4     0  ok
  homelab               -      -   -               -             -       -  ERR: timeout after 15s

  j/k select  Enter ssh  r refresh  q quit
```

Each row shows CPU, RAM, load, uptime, containers, pods, and alerts.
A green `●2` means 2 health checks pass. A red `✗1` means 1 fails.
A dark host states the cause: timeout, auth failure, or lost file.

- Press `Enter` to open SSH to the marked host and start Sentinel on it.
- Press `r` to probe all hosts again at the same time.
- It needs zero agent. Each host runs `sentinel --dump` (one JSON line)
  through plain SSH.

## Fix things here, not in a second terminal

Sentinel is a workbench, not just a view. Each act asks first.

| Key | Act |
|-----|-----|
| `x` | Restart the marked container (asks first) |
| `s` | Stop the marked container (asks first) |
| `k` | Type a PID, then kill it (asks first, guards PID 1 and Sentinel) |
| `u` | Count OS updates (apt, dnf, pacman) |
| `a` | Install the counted updates (asks first, needs `u` first) |
| `p` | Ping a host, see latency in plain text |

Move the mark with `Up`/`Down`. Press `y` to run, `n` or `Esc` to stop.
Prompts check input: bad PIDs and bad host names get a clear error, not
a crash.

## Health checks: "running" is not "healthy"

A container can run while the app in it dies. Sentinel probes the app.

```json
{
  "health_checks": {
    "nginx-proxy": {"url": "http://localhost:80", "expect": 200},
    "nextcloud": {"url": "http://localhost:8080/login", "expect": 200}
  },
  "listeners": [22, 80, 443]
}
```

- A green `●` near the name means the app answers. A red `✗` means it fails.
- A short name matches part of the name: `web` matches `project-web-1`.
  A full name always wins.
- A link-local target (the cloud-metadata range) is refused before any
  request. Plain LAN and `localhost` checks stay allowed.
- A shut listener port raises a `PORT CLOSED` alert. A failed app raises
  a `SERVICE DOWN` alert.
- The fleet table shows the same marks per host.
- Light mode skips HTTP checks (they need `urllib`, ~10MB). TCP checks
  still run.

## Empty panels state the cause

Most monitors show blank space when facts miss. Sentinel states why, and
press `d` shows the exact fix command.

```
dk: not installed          start the docker daemon
k8s: not installed         install kubectl
security: no permission    sudo usermod -aG adm $USER (then re-login)
```

Header letters mark each tool: **D** Docker, **K** Kubernetes,
**W** WireGuard, **S** security logs, **P** proxy logs, **R** RAPL.
Green means the tool acts. Red means access fails. No letter means the
host lacks the tool. Fix access mid-session: Sentinel picks it up in 30s
with zero restart.

## Core facts

<details>
<summary>CPU, memory, disk, network, energy</summary>

- **CPU** - Bars for each core, load graph, heat data, clock speed,
  governor name. Heat reads on ARM, VMs, and containers.
- **Memory** - Used and free memory with a past-use graph.
- **Disk** - Mount points with free space bars, Docker volume names
  and size data.
- **Network** - Traffic in KB/s with small graphs, VPN state with peer
  handshake age, link speed in Mbps or Gbps, signal meter, proxy facts
  for nginx and caddy.
- **Energy** - Power data from RAPL on desk hosts, battery data with
  health and cycle count on portable hosts.

</details>

<details>
<summary>Docker, Kubernetes, processes, proxy, security</summary>

- **Docker** - List of containers with CPU and memory per container,
  count of containers that run and stop, volume names and size data.
- **Kubernetes** - State of pods and nodes, alerts for pods that fail
  or wait.
- **Processes** - Task count, top users of CPU and memory.
- **Proxy** - Requests per second for nginx and caddy access logs.
- **Security** - Reads auth logs as facts arrive. Counts failed logins
  by IP and user. Raises an alert for more than 20 failed logins from
  one IP in 5 minutes. Press `l` for the security view.

</details>

<details>
<summary>Themes, views, alerts</summary>

- **Themes** - 5 color themes: default, nord, dracula, gruvbox, monokai.
  Press `t` to cycle. Use `--theme <name>` to start with one.
- **Views** - 6 views: default, cpu, network, docker, security, minimal.
  Press `l` to cycle.
- **Alerts** - High CPU, heat, memory strain, low battery, stopped
  containers, failed pods, shut ports, dead services. You set the
  limits in the config file.

</details>

## All keys

| Key | Act |
|-----|-----|
| `q` | Quit |
| `r` | Force refresh |
| `t` | Cycle themes |
| `l` | Cycle views |
| `h` | Help overlay |
| `d` | Diagnostics / access check |
| `i` | Check public IP |
| `Up`/`Down` | Move container mark |
| `x` / `s` / `k` / `u` / `a` / `p` | Acts (see Fix things here) |
| `y` / `n` / `Esc` | Confirm or cancel an act |
| `j` / `k` / `Enter` | In fleet mode: mark host, open SSH |
| `+` | Faster refresh (min 1s) |
| `-` | Slower refresh (max 10s) |

## Install options

**One line** (best for most hosts):

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

**From source:**

```bash
git clone https://github.com/VidGuiCode/sentinel.git
cd sentinel
sudo bash install-sentinel.sh
```

**By hand** (zero installer):

```bash
sudo apt-get install python3 lm-sensors curl
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/sentinel-monitor.py | sudo tee /usr/local/bin/sentinel > /dev/null
sudo chmod +x /usr/local/bin/sentinel
```

**As a service:**

```bash
sudo cp sentinel.service /etc/systemd/system/
sudo systemctl enable --now sentinel
journalctl -u sentinel -f
```

## Config file

Create it with `sentinel --init-config`, then edit to fit the host.
Health checks and listeners are off till you set them.
Edits act at once. Sentinel reads the file on each refresh.
No restart serves for safe keys (theme, limits, checks).
`light_mode` and CLI flags wait for restart and state it.

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

`intervals` sets a refresh interval per panel. It maps a collector
name to seconds.

```json
{
  "intervals": {
    "docker": 10,
    "security": 2
  }
}
```

The known names and built-in defaults, in seconds, are: `docker` 5,
`docker_df` 30, `kubernetes` 15, `wireguard` 10, `proxy` 5 (10 in
light mode), `security` 5, `processes` 5, `public_ip` 300,
`update_check` 86400 (604800 in light mode), `probes` 30, `ssid` 60,
and `health` 30. The default `{}` keeps these defaults.

- Edits act at once: each collector re-reads its interval every
  cycle, no restart.
- A removed entry restores that panel's default. An emptied key
  restores every default.
- An explicit value wins over the light-mode derivation.
- The range is 1 to 604800 seconds.
- A bad value (unknown name, out of range, wrong type) rejects the
  whole key: the old cadence stays, and the footer notes the cause.
- `sentinel --dump` includes the effective `intervals` map, so a
  host reports how fresh its own panels are.

`notifications` sends each panel alert to webhooks. It holds a list
of `webhooks` and a `cooldown` in seconds.

```json
{
  "notifications": {
    "webhooks": ["https://discord.com/api/webhooks/..."],
    "cooldown": 300
  }
}
```

- An alert state change POSTs one JSON object to each webhook. It
  fires for every alert the panel already raises: CPU, TEMP, MEM,
  BATTERY, DOCKER STOPPED, SERVICE DOWN, PORT CLOSED, K8S
  FAILED/PENDING, and the security alerts.
- Three events fire: `fired` for a new alert, `still firing` for the
  same alert after the cooldown passed, `resolved` when the alert
  clears. The cooldown is the minimum seconds between two sends for
  the same alert name (60-86400, default 300).
- One notification state covers one alert name. Two containers down
  at once merge into one notification; the cooldown reminder catches
  the second.
- The body carries the same line under four keys: `title`, `message`,
  `content`, `text`. Discord, Slack, and Gotify-style endpoints all
  find their field. `title` is `Sentinel <hostname>`.
- Edits act at once: `notifications` is a safe key, no restart.
  Delivery runs on one background thread that starts on the first
  event.
- Light mode skips webhook delivery (HTTP needs `urllib`, ~2MB RSS,
  the same promise as the health checks). `--dump` and fleet probes
  never send notifications; the panel and `--service` mode do.
- Each webhook URL passes the same guard as the health checks:
  http/https only, the host must resolve, link-local addresses (the
  cloud-metadata range) are refused. LAN and localhost webhooks
  (self-hosted Gotify/ntfy) stay allowed.
- Run `sentinel --test-notify` to verify the setup. It sends one test
  message to every webhook, prints `OK`/`FAIL` per URL, exits 0 on
  full success and 1 on any failure.

## Needs

- Python 3.6+ with only the standard library. Zero pip packages.
- Linux kernel 4.0+ on x86_64, aarch64, or armv7 (ARM tests pass under QEMU).
- Extra facts when the host has the tools: `docker` with read access to
  `/var/run/docker.sock`, `kubectl`, `wg`, `iwgetid`, lm-sensors.
- Lost or locked tools appear in the diagnostics overlay (`d`) with the
  fix command. Sentinel still runs with less facts.

> On Raspberry Pi and hosts with small memory, use `--light`.
> See [PERFORMANCE.md](PERFORMANCE.md) for measured numbers.

## Windows (WSL2)

```bash
sudo apt install python3
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
sentinel
```

Heat sensors and RAPL stay off (a VM limit). Docker facts act with
Docker Desktop WSL2 integration. Security logs stay empty unless `sshd`
acts in WSL2.

## Test rig

`bench/` measures CPU, RSS, wakeups, and throttle facts in simulated
host profiles (Pi 3, Pi 4). `bench/capture_frame.py` catches true
screen frames from a pty, so tests assert on what users see. ARM smoke
tests pass 16 of 16 under QEMU. The `tests/` directory holds three
stub-based suites - reload, actions, intervals - with 157 checks in
total. No check starts a collector or a child process.

Worst CPU burst on a Pi 3 profile: **12.9% in v0.5.1, 1.3% in v0.6.0.**
Full facts in [PERFORMANCE.md](PERFORMANCE.md).

## Changelog

Full facts for each change stay in [CHANGELOG.md](CHANGELOG.md).

- **v0.6.6** - Webhook notifications: a new `notifications` key
  POSTs every panel alert to Discord, Slack, or Gotify-style
  endpoints. Edits apply live, no restart. `--test-notify` verifies
  the setup.
- **v0.6.5** - Per-panel refresh intervals: a new `intervals` key
  maps each panel to seconds. Edits apply live, no restart.
- **v0.6.4** - Config hot-reload: file edits act at once, no restart.
  Safe keys (theme, limits, checks) apply live. Held keys
  (`light_mode`, CLI flags) wait for restart and state it.
- **v0.6.3** - Quick acts with a confirm step: restart/stop containers,
  kill by PID, count and install OS updates, ping hosts.
- **v0.6.2** - Health checks per container plus TCP listener checks.
  `●`/`✗` marks in Docker, fleet, and `--dump`.
- **v0.6.1** - Fleet mode (`--host`): one table for the full homelab
  through plain SSH. Zero agent.
- **v0.6.0** - Collectors that do not block, zero child acts on the
  screen path, paint only on change, panels that state the cause,
  less memory in `--light`.

## Open Source

The MIT License covers Sentinel. See the LICENSE file. Use it free,
open issues on GitHub, send pull requests for panels, themes, or fixes.
