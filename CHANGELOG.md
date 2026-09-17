# Changelog

## Unreleased - v0.6.2 service health checks (in progress)

A container that runs is not a service that works.
Sentinel adds `health_checks` for each container.
`health_checks` holds an HTTP url and an expected status.
Sentinel adds `listeners` for each container.
`listeners` holds TCP ports that must accept calls.
A background collector checks both items each 30s.

The collector uses stdlib only (`urllib`, `socket`).
The Docker panel shows green `●` for health.
The Docker panel shows red `✗` for failure.

Failures trigger `SERVICE DOWN` and `PORT CLOSED` alerts.
The diagnostics overlay shows failures (`d`, `H` header letter).
`sentinel --dump` includes failures.
The fleet table includes failures.

## v0.6.1 - multi-host fleet over SSH

Sentinel needs no agent.
Sentinel needs no daemon.
Sentinel needs no new dependency.
`sentinel --host hosts.json` shows one table for all hosts.
The table shows these items:

- name
- CPU%
- MEM%
- load
- uptime
- containers
- pods
- alerts per host

`j/k` and arrows move the cursor.
`Enter` opens an SSH session to the selected host.
`Enter` starts Sentinel on that host.
`r` probes all hosts again at the same time.
`q` quits the fleet table.

A host that fails stays visible.
The row shows the reason (`timeout`, `Permission denied (publickey)`, ...).

Each host runs `python3 sentinel-monitor.py --dump`.
The command writes one JSON line.
The command reuses the same readers as the TUI.
So the fleet table and the local panel always agree.
The remote host needs only `python3` and this file.
Sentinel runs one probe per host on a daemon thread.

Each probe stops after a 15s timeout.
Sentinel calls `ssh` with an argv list.
Sentinel never passes hostnames to a shell.
Sentinel sets `BatchMode=yes`.
So a password prompt never stops the table.

## v0.6.0 - performance, resilience, and clear failure reports

This release lowers load on the host.
An empty panel states the reason for the blank view.

Each change below includes the reason for the change.
[PERFORMANCE.md](PERFORMANCE.md) holds all measured numbers.
All numbers come from simulated device profiles.
The profiles limit CPU and memory with Docker containers.
The profiles are not physical hardware.

---

### Architecture - the fetch loop no longer blocks the UI

**Background collectors replace the sequential fetch loop.**
`update_data()` fetched CPU, memory, disk, network, processes, Docker, Kubernetes, proxy logs and security logs in sequence.
`update_data()` ran on the render thread.
So one slow call froze the full UI.

Slow work now runs on 10 to 12 daemon threads (`Collector`).
Each collector uses its own interval.
`update_data()` only merges the latest snapshot.
`update_data()` never waits for a collector.

Sentinel sets each interval from the change rate of the data.
Sentinel does not set intervals from the refresh rate.
The intervals are:

- processes 5s
- Docker 5s
- Docker disk usage 30s
- Kubernetes 15s
- WireGuard 10s
- security logs 5s
- permission probes 30s
- SSID 60s
- public IP 300s
- update check daily (weekly in light mode)

Sentinel no longer polls Docker and Kubernetes each 2 seconds.
That data changes only each few minutes.

The collector publishes results with a single tuple swap.
Readers on the UI thread take no lock.
Readers cannot block.
A collector that fails keeps the last good result.
The collector records the error.
The collector does not stop.

**Why:** one slow subprocess stalled all panels.
It also stalled cheap `/proc` reads.
Those reads had no link to the slow call.

### Subprocesses removed from the hot path

- **Docker Engine API replaces Docker CLI.** `docker ps`, `docker stats` and
  `docker system df -v` spawned subprocesses with `shell=True` on each
  cycle. Each spawn used a double fork. The volume fallback spawned
  `docker system df -v | grep | awk` once per volume. Sentinel now uses a
  small stdlib HTTP client for `/var/run/docker.sock`. Sentinel reports a
  non-local `DOCKER_HOST` value as `unsupported_host`.
- **Sentinel replaces `curl` with `urllib`.** `urllib` serves the public IP lookup. `urllib` serves the GitHub update check.
- **Sentinel removes `shell=True` fully (1 to 0 occurrences).** The single `subprocess.run` call takes an argv list. It never takes a shell string.
- **WiFi SSID now uses a 60s collector.** `get_network_info()` ran inline on
  the render path. It spawned `iwgetid` from the UI thread. That spawn was
  the last subprocess on the UI thread. The SSID changes only on roam or
  reconnect.

**Why:** `shell=True` costs two forks per call.
A block in any fork froze the UI.

### Process scan made cheap

The scan read two files for each PID.
The files were `/proc/<pid>/stat` and `/proc/<pid>/status`.
RSS now comes from field 24 of `stat`.
So Sentinel needs no second file.

Sentinel needs no line scan of that file.
The full scan now runs on a 5s collector.
The scan no longer runs on each refresh.

### Display - repaint only what changed (P5)

The draw loop painted the full screen each 500ms.
It painted even with no change in data.
It used roughly 2000 `addstr` calls for an identical frame.
Sentinel now builds a cheap frame signature.
The signature uses these items:

- data-cache generation
- feature-status revision
- terminal size
- theme
- layout
- refresh rate
- open overlay

The signature decides if the frame can change.
If the frame cannot change, Sentinel skips the full repaint.
Sentinel then updates only the header clock with one `addstr`.
At the default 2s refresh, this cuts full repaints by roughly 75%.

`getch()` returns at once on a keypress.
It waits no extra time for its timeout.
Sentinel sets the timeout to the first of two events.
The events are the next data refresh and the next clock second.
The old fixed timeout was 500ms.
Key latency stays the same.

The loop wakes only for work.
`SENTINEL_NO_FRAMESKIP=1` forces the old always-repaint action.
Use it only for terminals that mishandle partial updates.

### Memory

Sentinel imports `http.client` (~8MB, it pulls in `email.parser`) at the call site.
Sentinel imports `urllib.request` (~2MB) at the call site.
Sentinel no longer imports both modules at start.
A host with no Docker daemon loads no Docker client.

Light mode starts no network collectors.
The two collectors are public IP and update check.
They were the sole cause for `urllib` use.
Through `urllib`, they also caused `ssl` and `email` use.
That use cost ~10MB RSS for a public-IP readout and a version check.

Test in isolation gives 23.6MB normal and 13.7MB light.
Both features show `disabled in light mode` in the diagnostics overlay.
The overlay shows the control to restore them.

### Failure reports - no more silent blanks (P6)

- **Sentinel cuts 36 bare `except:` blocks to 0.** Each handler names the
  exceptions that it expects. Broad `except Exception` handlers stay only
  for two aims. One aim keeps collector threads alive. One aim keeps the
  profile side-channel safe. Sentinel documents both cases.
- **Per-feature status registry.** Each degradable feature holds a state.
  The state has a detail string and a fix hint. The state is one of
  (`ok`, `no_permission`, `not_installed`, `socket_missing`,
  `unsupported_host`, `unavailable`, `error`). The header shows a colored
  letter for each feature. The diagnostics overlay (`d`) lists all features
  with detail and exact command. The command fixes the issue.
- **Panels state their own status.** A blank panel once showed no text.
  So "no permission" looked the same as "no data". Docker and Kubernetes
  state status inline. Security and the proxy readout state status inline.
  Each panel points to `d` when action can fix the cause.
- **Sentinel retries permission probes each 30 seconds.** Sentinel finds a fix with no restart. The fixes include:
  - join the `docker` group
  - change mode on a log with `chmod`
  - start a daemon
- **A configuration file that fails to parse appears in the diagnostics overlay.** Sentinel does not fall back to defaults in silence.

### Benchmark and verification harness (new - `bench/`)

Sentinel had no way to measure this work in the past.

- `bench/runner.py` samples data for a target process. It samples these items:
  - CPU%
  - RSS
  - voluntary/involuntary context switches
  - cgroup CPU/throttling
  It drives the process through a real pty.
- `bench/run_profiles.sh` runs a tool under labeled device profiles. Pi 3
  uses `--cpus=0.5 --memory=256m`. Pi 4 and small VPS use `--cpus=1
  --memory=512m`. `SENTINEL_SCRIPT` selects the revision to measure.
  Produce before/after numbers in one session under the same host load. It
  retries a run that gives no samples (see Known issues).
- `bench/capture_frame.py` draws Sentinel in a pty of fixed size. It
  replays the ANSI stream to a text grid. Assert the frame on the text
  grid. `docker run -t` in a non-interactive shell gives a pty of size 0x0.
  Curses draws no output there. A plain smoke test then passes on a blank
  screen.
- `bench/degraded.sh` and `bench/Dockerfile.degraded` cover five permission cases. The cases are:
  - no docker socket
  - unreadable socket
  - unreadable `/var/log`
  - dropped capabilities with read-only rootfs
  - Pi 3 limits
  Each case draws the UI. Each case states the absent item. All five pass.
- `bench/arm_smoke.sh` and `bench/Dockerfile.arm` run Sentinel on aarch64
  and armv7 under QEMU user-mode emulation (`binfmt_misc`). The script
  starts Sentinel. The script parses `/proc`. The ARM `/proc/cpuinfo`
  layout has no `model name` field. The script paints a frame in normal
  mode and light mode. It still explains degraded features.

  16/16 checks pass on both architectures. QEMU timings describe the emulator, not the hardware. Sentinel publishes no ARM performance numbers.
- `SENTINEL_PROFILE=<path>` writes counts as JSONL. It writes these items:
  - per-stage timings
  - per-collector durations
  - subprocess counts
  - frame-drawn/skipped counts

### Not done

Sentinel has no rewrite in Rust or Go.
The evidence does not support a rewrite (see [PERFORMANCE.md](PERFORMANCE.md#should-this-be-rewritten)).
Sentinel CPU cost stays at or below btop cost.
The rest of the gap is resident memory.
The Python interpreter causes that gap, not interpreted execution speed.
