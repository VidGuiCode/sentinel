# Changelog

## v0.6.1 - multi-host fleet over SSH

No agent, no daemon, no new dependency: `sentinel --host hosts.json` shows
one table for the whole homelab (name, CPU%, MEM%, load, uptime, containers,
pods, alerts per host). `j/k` + arrows move, `Enter` SSHes into the selected
host and launches Sentinel there, `r` re-probes all hosts in parallel, `q`
quits. Unreachable hosts stay visible with the reason (`timeout`, `Permission
denied (publickey)`, ...) instead of silently disappearing.

The probe each host runs is `python3 sentinel-monitor.py --dump`: one JSON
line reusing the same readers as the TUI, so the fleet table and the local
dashboard can never disagree. The remote side needs nothing but `python3`
and this file. Probes run on one daemon thread per host with a 15s timeout,
argv-list `ssh` only (hostnames from a user-edited JSON file are never passed
to a shell), and `BatchMode=yes` so a password prompt can never hang the
table.

## v0.6.0 — performance, resilience, and honest failure reporting

The theme of this release: **the host should not notice Sentinel is running,
and when a panel is empty it should say why.**

Every change below is paired with the reason it was made. Measured numbers are
in [PERFORMANCE.md](PERFORMANCE.md); all of them come from simulated device
profiles (CPU/memory-limited Docker containers), not physical hardware.

---

### Architecture — the fetch loop no longer blocks the UI

**Background collectors replace the sequential fetch loop.**
`update_data()` used to fetch CPU, memory, disk, network, processes, Docker,
Kubernetes, proxy logs and security logs one after another on the render
thread, so a single slow call froze the whole UI. Slow and IO-bound work now
runs on 10–12 daemon threads (`Collector`), each with its own interval, and
`update_data()` only merges their most recent published snapshot. It never
waits for a collector.

Intervals are set by how fast the data actually changes, not by the refresh
rate: processes 5s, Docker 5s, Docker disk usage 30s, Kubernetes 15s,
WireGuard 10s, security logs 5s, permission probes 30s, SSID 60s, public IP
300s, update check daily (weekly in light mode). Docker and Kubernetes no
longer get polled every 2 seconds for data that changes every few minutes.

Results are published by swapping a single tuple reference, so readers on the
UI thread take no lock and cannot block. A collector that raises keeps serving
its last good result and records the error instead of dying.

**Why:** one slow subprocess used to stall every panel, including the cheap
`/proc` reads that had nothing to do with it.

### Subprocesses removed from the hot path

- **Docker CLI → Docker Engine API over the unix socket.** `docker ps`,
  `docker stats` and `docker system df -v` were `shell=True` subprocess spawns
  (double fork) on every cycle; the volume fallback spawned
  `docker system df -v | grep | awk` *once per volume*. Replaced with a small
  stdlib HTTP client speaking to `/var/run/docker.sock`. `DOCKER_HOST` values
  that are not local unix sockets are reported as `unsupported_host` rather
  than silently ignored or shelling out to ssh.
- **`curl` → `urllib`** for the public IP lookup and the GitHub update check.
- **`shell=True` is gone entirely** (1 → 0 occurrences). The single remaining
  `subprocess.run` call site takes an argv list, never a shell string.
- **WiFi SSID moved to a 60s collector.** `iwgetid` was still being spawned
  from `get_network_info()`, which runs inline on the render path — the last
  subprocess left on the UI thread. The SSID only changes on roam/reconnect.

**Why:** `shell=True` costs two forks per call, and any of them blocking meant
a visibly frozen UI.

### Process scan made cheap

The per-refresh scan read both `/proc/<pid>/stat` and `/proc/<pid>/status` for
every PID. RSS now comes from field 24 of `stat`, so the second file — and its
line-by-line scan — is gone, and the whole scan runs on a 5s collector instead
of every refresh.

### Rendering — repaint only what changed (P5)

The draw loop repainted the entire screen every 500ms regardless of the
refresh rate or whether anything had changed: roughly 2000 `addstr` calls to
produce an identical frame.

Now a cheap frame signature (data-cache generation, feature-status revision,
terminal size, theme, layout, refresh rate, open overlay) decides whether the
frame can change at all. If it cannot, the full repaint is skipped and only
the header clock is updated — one `addstr`. At the default 2s refresh this
cuts full repaints by roughly 75%.

Idle wakeups dropped too. `getch()` returns immediately on a keypress no
matter how long its timeout is, so the timeout is now set to whichever comes
first — the next data refresh or the next clock second — instead of a fixed
500ms. Key latency is unchanged; the loop simply stops waking up to do
nothing.

`SENTINEL_NO_FRAMESKIP=1` forces the old always-repaint behaviour, as an
escape hatch for terminals that mishandle partial updates.

### Memory

`http.client` (~8MB, it pulls in `email.parser`) and `urllib.request` (~2MB)
are now imported at their call sites rather than at module import. A host with
no Docker daemon never pays for the Docker client.

**Light mode no longer starts the two network collectors** (public IP, update
check). They were the only reason `urllib` — and through it `ssl` and
`email` — got imported at all, costing ~10MB RSS for a public-IP readout and a
version check. Measured in isolation: **23.6MB normal, 13.7MB light.** Both
features report themselves as `disabled in light mode` in the diagnostics
overlay, with the setting to change if you want them back.

### Failure reporting — no more silent blanks (P6)

- **36 bare `except:` blocks → 0.** Every handler now names the exceptions it
  expects. The broad `except Exception` handlers that remain are deliberate
  and documented: collector threads must never die, and the profiling
  side-channel must never take the monitor down.
- **Per-feature status registry.** Each degradable feature carries a state
  (`ok`, `no_permission`, `not_installed`, `socket_missing`,
  `unsupported_host`, `unavailable`, `error`), a detail string, and a fix
  hint. The header shows a coloured letter per feature; the diagnostics
  overlay (`d`) lists all of them with the detail and the exact command to
  fix it.
- **Panels explain themselves.** Previously a panel with nothing to show drew
  nothing, so "you lack permission" and "there is nothing here" looked
  identical — the "infos don't appear" bug. Docker/Kubernetes/security and the
  proxy readout now state their status inline, and point at `d` when the cause
  is actionable.
- **Permission probes are retried every 30 seconds.** Fixing a permission
  mid-session (adding yourself to the `docker` group, `chmod`-ing a log,
  starting a daemon) is picked up without restarting Sentinel.
- **A config file that fails to parse is reported** in the diagnostics
  overlay instead of silently falling back to defaults.

### Benchmark and verification harness (new — `bench/`)

There was no way to measure any of this before.

- `bench/runner.py` — samples CPU%, RSS, voluntary/involuntary context
  switches and cgroup CPU/throttling for a target process, driving it through
  a real pty.
- `bench/run_profiles.sh` — runs a tool under labelled device profiles
  (Pi 3: `--cpus=0.5 --memory=256m`; Pi 4 / small VPS: `--cpus=1
  --memory=512m`). `SENTINEL_SCRIPT` selects which revision to measure, so
  before/after numbers can be produced in one session under the same host
  load. Retries a run that produces no samples (see Known issues).
- `bench/capture_frame.py` — renders Sentinel into a pty of a fixed size and
  replays the ANSI stream into a text grid, so a frame can be asserted on.
  This exists because `docker run -t` in a non-interactive shell gives a pty
  of size 0x0: curses draws nothing and a naive smoke test passes against a
  blank screen.
- `bench/degraded.sh` + `bench/Dockerfile.degraded` — five permission-degraded
  scenarios (no docker socket, unreadable socket, unreadable `/var/log`,
  dropped capabilities + read-only rootfs, Pi 3 limits). Each asserts the UI
  renders *and* explains what is missing. All five pass.
- `bench/arm_smoke.sh` + `bench/Dockerfile.arm` — runs Sentinel on aarch64 and
  armv7 under QEMU user-mode emulation (`binfmt_misc`) and checks that it
  starts, parses `/proc` (the ARM `/proc/cpuinfo` layout has no `model name`
  field), paints a frame in both normal and light mode, and still explains
  degraded features. **16/16 checks pass on both architectures.** Compatibility
  only — QEMU timings would describe the emulator, so no ARM performance
  numbers are published.
- `SENTINEL_PROFILE=<path>` writes per-stage timings, per-collector durations,
  subprocess counts and frame-drawn/skipped counts as JSONL.

### Not done

No rewrite in Rust or Go. The evidence does not support one — see
[PERFORMANCE.md](PERFORMANCE.md#should-this-be-rewritten). Sentinel's CPU cost
is at or below btop's; the remaining gap is resident memory, which is the
Python interpreter itself, not interpreted execution speed.
