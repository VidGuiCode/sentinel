# Sentinel Performance

Sentinel targets low-end servers, Raspberry Pis and resource-constrained
environments. This document reports what was **measured** (below), then
documents the optimisation techniques used in the codebase.

---

# Measured performance (v0.6.0)

## How these numbers were produced - read this first

**No physical hardware was used.** Every number comes from CPU- and
memory-limited Docker containers on an x86_64 host, approximating device
classes:

| Profile | Container limits | Approximates |
|---------|------------------|--------------|
| `pi3` | `--cpus=0.5 --memory=256m` | Raspberry Pi 3 |
| `pi4` | `--cpus=1 --memory=512m` | Raspberry Pi 4 / small VPS |

These constrain CPU share and memory ceiling. They do **not** reproduce ARM
instruction timing, slower RAM, SD-card IO latency, or thermal throttling. Real
Pi hardware will be slower in absolute terms. The *relative* before/after
comparison is the meaningful result; the absolute figures are not a prediction
of Pi performance.

Before and after were measured **in the same session, back to back, under the
same host load** - results from different sessions are not comparable. 30s per
run, first samples discarded as startup transient.

Reproduce with:

```bash
DURATION=30 SENTINEL_SCRIPT=<old-revision.py> ./bench/run_profiles.sh before
DURATION=30 ./bench/run_profiles.sh after
python3 bench/summarize.py bench/results/after
```

## v0.5.1 → v0.6.0

`Cgroup CPU%` is the share of the container's CPU quota - the figure that
matters on a constrained device. `max` is the worst single sample, i.e. the
spike a user would feel as a stutter.

**Pi 3 profile (`--cpus=0.5 --memory=256m`)**

| Tool | CPU% mean | Cgroup CPU% mean (max) | RSS MB | ctx/s (voluntary) |
|------|-----------|------------------------|--------|-------------------|
| v0.5.1 TUI | 0.4 | 0.9 (**12.9**) | 20.1 | 2.2 |
| v0.6.0 TUI | 0.2 | 0.3 (**1.3**) | 31.5 | 1.7 |
| v0.5.1 `--light` | 0.4 | 0.9 (10.0) | 20.0 | 2.2 |
| v0.6.0 `--light` | 0.2 | 0.3 (1.1) | 21.4 | 1.5 |
| v0.5.1 `--service` | 0.1 | 0.8 (23.3) | 19.3 | 0.8 |
| v0.6.0 `--service` | 0.1 | 0.2 (0.9) | 31.0 | 0.5 |

**Pi 4 / small VPS profile (`--cpus=1 --memory=512m`)**

| Tool | CPU% mean | Cgroup CPU% mean (max) | RSS MB | ctx/s (voluntary) |
|------|-----------|------------------------|--------|-------------------|
| v0.5.1 TUI | 0.4 | 0.9 (12.3) | 19.8 | 2.2 |
| v0.6.0 TUI | 0.2 | 0.3 (1.2) | 31.4 | 1.9 |
| v0.5.1 `--light` | 0.4 | 0.8 (16.5) | 19.9 | 2.2 |
| v0.6.0 `--light` | 0.2 | 0.3 (1.0) | 21.7 | 1.7 |

### What improved

- **Worst-case CPU spike: 12.9% → 1.3% of quota (Pi 3 TUI), 23.3% → 0.9%
  headless.** This is the headline result. The old sequential fetch loop
  bunched all its work - including subprocess spawns - into one burst on the
  render thread; that burst *was* the UI freeze. Spreading collectors across
  threads with their own intervals removed it.
- **Mean CPU roughly halved** (0.9% → 0.3% of quota).
- **Fewer wakeups**: the render loop now sleeps until the next data refresh or
  clock second instead of waking every 500ms, and skips the repaint entirely
  when nothing changed - about 75% of full repaints eliminated at the default
  2s refresh.

### What regressed

- **RSS: 20MB → 31MB in normal mode.** Replacing the `curl` subprocess with
  `urllib` means `urllib.request` → `ssl` → `email.parser` are imported into
  Sentinel's own address space (~10MB) instead of living in a short-lived
  child process. The CPU win came at a memory cost.
- **`--light` mode does not pay this**: it no longer starts the public-IP and
  update-check collectors, so `urllib` is never imported. **21.4MB vs 31.5MB.**
  On a 256MB Pi 3 that is the difference between 8% and 12% of total RAM.
  **Use `--light` on Pi-class hardware.** (Measured in isolation, without the
  TUI's history buffers: 13.7MB light vs 23.6MB normal.)
- Container CPU-throttle events went slightly up on the Pi 3 profile (2 → 5
  over 30s). Work is now spread across threads, which schedules more burstily
  against a 0.5-CPU quota even though total CPU is lower. Counts are small and
  noisy; no user-visible effect was observed.

## Comparison against btop and htop

Same containers, same 30s duration, same session.

**Pi 3 profile**

| Tool | CPU% mean | Cgroup CPU% mean (max) | RSS MB | ctx/s (voluntary) |
|------|-----------|------------------------|--------|-------------------|
| sentinel v0.6.0 `--light` | 0.2 | 0.3 (1.1) | 21.4 | 1.5 |
| sentinel v0.6.0 TUI | 0.2 | 0.3 (1.3) | 31.5 | 1.7 |
| btop | 0.6 | 0.7 (1.4) | 5.6 | 98.9 |
| htop | 0.1 | 0.2 (0.5) | 3.8 | 0.7 |

- **CPU: Sentinel now uses less than btop** (0.3% vs 0.7% of quota) and is
  within noise of htop.
- **Wakeups: Sentinel is far quieter than btop** - 1.5 voluntary context
  switches/sec vs btop's ~99/s. btop redraws on a fixed fast tick; Sentinel
  sleeps until something changes.
- **Memory: Sentinel is 4–6× larger.** ~14MB of that is the CPython
  interpreter and stdlib before a line of Sentinel runs. This is the one
  dimension where a compiled monitor wins outright, and no amount of Python
  optimisation closes it.

htop is the floor: it monitors far less (no Docker, Kubernetes, WireGuard,
security logs, power).

## Should this be rewritten?

**No - the evidence does not support a Rust or Go rewrite.**

The rewrite was gated on profiling showing the Python interpreter to be the
bottleneck after optimisation. It is not:

- Sentinel's CPU cost is now **below btop's**, a C++ monitor, on the same
  workload. Interpreted execution is not the limiting factor.
- The remaining gap is **resident memory**, and it is interpreter baseline
  (~14MB), not interpreted execution speed. A rewrite would fix that - but it
  would be a memory rewrite, not a performance rewrite, and it would trade a
  single dependency-free 3.8k-line file that runs anywhere Python 3 exists for
  a per-architecture build and release pipeline.
- The costs that actually hurt were architectural - a blocking fetch loop,
  subprocess spawns on the render thread, unconditional full repaints - and
  those were fixable in place. They have been fixed.

If ~21MB (light mode) is unacceptable for a target device, that is the
argument for a rewrite. Speed is not.

## ARM verification (aarch64 + armv7)

**Compatibility was verified; ARM performance was not measured, and cannot be
from this setup.**

No rewrite happened, so there is nothing to cross-compile - Sentinel is a
single pure-Python file. What needed proving is that it *runs* correctly on
ARM: imports, `/proc` and `/sys` parsing (which differs from x86 - ARM has no
`model name` field in `/proc/cpuinfo`), curses rendering, and both entry-point
modes.

Both architectures were smoke-tested under QEMU user-mode emulation via
`binfmt_misc`:

```bash
docker run --privileged --rm tonistiigi/binfmt --install arm64,arm
./bench/arm_smoke.sh
```

| Check | aarch64 | armv7l |
|-------|---------|--------|
| Runs on target architecture | ✅ | ✅ |
| `--version` / `--help` | ✅ | ✅ |
| `--service` emits real sampled values | ✅ | ✅ |
| `--service --light` emits real sampled values | ✅ | ✅ |
| TUI paints a frame | ✅ | ✅ |
| `--light` TUI paints a frame | ✅ | ✅ |
| Degraded features explained, not blank | ✅ | ✅ |

**16 of 16 checks passed.** CPU detection resolves correctly through the ARM
path - an aarch64 container reports `ARMv8 Processor rev 0 (v8l)`, read from
the `Processor`/`Hardware` fields rather than x86's `model name`.

**Why no ARM numbers are published:** QEMU user-mode emulation translates ARM
instructions on an x86_64 host with a large and uneven slowdown, so any timing
taken here would describe the emulator, not a Pi. Resident memory is equally
unusable, since the RSS visible in the container belongs to the QEMU process
and includes translation-cache overhead. **QEMU validates compatibility, not
performance.** Every performance figure in this document is x86_64.

Getting real ARM performance numbers requires a physical Pi. Until someone runs
`bench/run_profiles.sh` on one, treat the relative before/after improvements as
the transferable result - they come from removing blocking work and repaints,
which is architecture-independent - and treat the absolute figures as x86_64
only.

## Known issues

- **Benchmark flakiness on Docker Desktop for Windows.** Roughly 1 run in 6
  under tight memory limits dies during interpreter startup with an `OSError`
  from an import reading the bind-mounted checkout - before any Sentinel code
  runs. It reproduces on v0.5.1 as well, so it is a host artifact, not a code
  regression. `bench/run_profiles.sh` retries a run that yields no samples.
- **No ARM performance data.** aarch64 and armv7 are verified to *run*
  correctly (see above), but every performance number in this document is
  x86_64. QEMU cannot produce meaningful ARM timings, and no physical Pi was
  available.
- **`bench/capture_frame.py` does not model terminal scrolling**, so its
  captured grid can be one row off and may show remnants from earlier frames.
  Assert on content presence, not exact positions. This affects the test tool
  only.
- **Temperature sensors and RAPL do not work inside WSL2, VMs or containers.**
  This is a platform limitation - those interfaces are not exposed to the
  guest - not a bug. Panels report it rather than showing zeros silently.

---

# Optimisation techniques used in the codebase

## How Sentinel collects data

Two tiers, split by cost:

**Inline, on the render thread** - only sub-millisecond `/proc` and `/sys`
reads: CPU, memory, disk (`os.statvfs`), network counters, uptime, battery,
RAPL energy. These are cheap enough that threading them would cost more than
it saves.

**Background collectors** - everything slow or IO-bound runs on its own daemon
thread at its own interval. `update_data()` merges the latest published
snapshot and never waits. A collector that fails keeps serving its last good
result and records the error for the diagnostics overlay.

| Collector | Interval | Why |
|-----------|----------|-----|
| `processes` | 5s | Full `/proc` PID scan |
| `docker` | 5s | Engine API over the unix socket |
| `docker_df` | 30s | Volume disk usage; changes slowly |
| `kubernetes` | 15s | `kubectl` subprocess |
| `wireguard` | 10s | `wg show` subprocess |
| `security` | 5s | Log tail + regex parsing |
| `proxy` | 5s (10s light) | Log tail |
| `probes` | 30s | Re-check permissions so fixes apply without restart |
| `ssid` | 60s | `iwgetid` subprocess; changes only on roam |
| `public_ip` | 300s | Network round-trip *(disabled in light mode)* |
| `update_check` | 24h (7d light) | Network round-trip *(disabled in light mode)* |

Intervals reflect how fast the data actually changes, not the refresh rate.
Docker and Kubernetes are not polled every 2 seconds for data that changes
every few minutes.

## Techniques in use

### Direct `/proc` and `/sys` reads, no subprocesses

Spawning a process to read a file costs a fork, an exec and a pipe. Sentinel
reads the file.

```python
# BAD - spawns a process
temp = subprocess.run(['cat', '/sys/class/thermal/thermal_zone0/temp'], ...)

# GOOD - direct read
with open('/sys/class/thermal/thermal_zone0/temp') as f:
    temp = int(f.read()) / 1000
```

`shell=True` does not appear anywhere in the codebase. The single remaining
`subprocess.run` call site takes an argv list - used only by `kubectl`,
`wg` and `iwgetid`, all on background collectors, never on the render path.

### Docker over the unix socket, not the CLI

`docker ps`, `docker stats` and `docker system df -v` were subprocess spawns
every cycle; the volume fallback ran `docker system df -v | grep | awk` *once
per volume*. Sentinel now speaks HTTP to `/var/run/docker.sock` with a small
stdlib client. `DOCKER_HOST` values that are not local unix sockets are
reported as `unsupported_host` rather than silently ignored.

### One `/proc/stat` read per cycle

Aggregate CPU and per-core usage come from a single read, parsed once, instead
of one read per core.

### Process scan reads `stat` only

RSS comes from field 24 of `/proc/<pid>/stat`, so `/proc/<pid>/status` - and
its line-by-line scan - is never opened. Halves the syscalls on a scan that
touches every PID.

### Repaint only when something changed

A frame signature (data generation, feature-status revision, terminal size,
theme, layout, refresh rate, open overlay) decides whether a repaint could
change anything. If it cannot, the ~2000-`addstr` redraw is skipped and only
the header clock is updated. Roughly 75% of full repaints disappear at the
default 2s refresh.

`SENTINEL_NO_FRAMESKIP=1` restores unconditional repainting.

### Sleep until the next change, not on a fixed tick

`getch()` returns immediately on a keypress regardless of its timeout, so the
timeout is set to whichever comes first - the next data refresh or the next
clock second - instead of a fixed 500ms. Fewer idle wakeups, identical key
latency.

### Deferred imports

`http.client` (~8MB, it pulls in `email.parser`) and `urllib.request` (~2MB)
are imported at their call sites. A host with no Docker daemon never pays for
the Docker client.

### Pre-compiled regex

Security-log patterns are compiled once at startup and reused, rather than
re-compiled per line on every parse.

### Fixed-size ring buffers

All history uses `collections.deque(maxlen=N)` - 100 points normally, 50 in
light mode. Bounded by construction, so history cannot leak.

### Windowed cleanup for security events

Failed-login and suspicious-IP trackers keep a 5-minute window
(`failed_login_window`) and drop older entries, so memory stays flat on a host
under sustained attack.

## Update checker

- Fetches only the first 8KB of `sentinel-monitor.py` from GitHub via
  `urllib`, with a 3-second timeout - no `curl` subprocess.
- Runs on a background collector: once per 24 hours, weekly in light mode.
- Compares semantic versions and only notifies when the remote version is
  higher.
- Failures are recorded as `update_check: error` in the diagnostics overlay
  rather than shown as a popup.
- **Disabled entirely in light mode** (see below).
- Shows a dimmed notice in the footer when an update exists.

To update:

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

The installer preserves existing config files.

## Light mode

**Recommended on Pi-class hardware** - measured at 21.4MB RSS versus 31.5MB
normal (Pi 3 profile).

Enabled by `--light`, by `light_mode: true` in the config, or automatically
when `/proc/cpuinfo` looks like low-resource hardware (Raspberry Pi 4 /
BCM2711, or a low core and RAM count).

What it changes:

| Setting | Normal | Light |
|---------|--------|-------|
| Minimum refresh rate | 2s | 3s |
| Graph history points | 100 | 50 |
| Proxy log interval | 5s | 10s |
| Security log tail | 1000 lines | 200 lines |
| Update check | daily | weekly |
| Public IP collector | on | **off** |
| Update check collector | on | **off** |

Disabling the two network collectors is what saves the ~10MB: they are the
only reason `urllib` - and through it `ssl` and `email.parser` - is imported
at all. Both report themselves as `disabled in light mode` in the diagnostics
overlay, with the setting to change if you want them back.

## Tuning for low-end hosts

**1. Use light mode.** The single biggest win.

```bash
sentinel --light
```

**2. Slow the refresh rate.** Press `-` in the TUI (up to 10s), or set
`refresh_rate` in the config. Fewer data refreshes means fewer repaints, since
repaints are now driven by data changes.

**3. Use a lighter layout.** Press `l` to cycle; `minimal` draws the fewest
panels.

**4. Turn off the public IP lookup** if you do not need it:

```json
{ "public_ip_check": false }
```

**5. Filter large log files.** Security-log parsing cost scales with how much
log there is to read. Pointing Sentinel at a pre-filtered file keeps the
parser cheap:

```json
{ "security_logs": { "auth": "/var/log/auth-filtered.log" } }
```

**6. Use service mode on headless hosts.** No curses, no rendering:

```bash
sentinel --service
```

## Troubleshooting

### A panel is empty

Press `d`. The diagnostics overlay lists every degradable feature with its
state (`ok`, `no permission`, `not installed`, `socket missing`,
`unsupported host`, `disabled`, `error`), the detail, and the exact command to
fix it. Panels also state their status inline.

Permissions are re-probed every 30 seconds, so fixing one mid-session - adding
yourself to the `docker` group, `chmod`-ing a log, starting a daemon - is
picked up without restarting.

### High CPU

```bash
SENTINEL_PROFILE=/tmp/sentinel-profile.jsonl sentinel
```

Writes one JSON line per data refresh: per-stage timings, per-collector
durations and errors, subprocess counts, and frames drawn versus skipped. That
identifies which collector is expensive rather than guessing.

Common causes: a host with very many containers, or very large security logs
(see tuning above).

### Diagnosing feature detection

```bash
SENTINEL_DEBUG=1 sentinel
```

Logs every feature-status transition to `/tmp/sentinel-debug.log`.

### Rendering artifacts

If your terminal mishandles partial updates:

```bash
SENTINEL_NO_FRAMESKIP=1 sentinel
```

## Comparison with other tools

Measured numbers are in [Comparison against btop and
htop](#comparison-against-btop-and-htop) above. Summary: Sentinel's CPU cost is
now below btop's and it wakes far less often, but it uses 4–6× more resident
memory, most of which is the CPython interpreter itself.

htop is the floor for resource use, and monitors far less - no Docker,
Kubernetes, WireGuard, security logs or power.

## Possible future work

- Reduce resident memory further. The remaining floor is the interpreter
  (~14MB); beyond that only a compiled rewrite moves it, which the measured
  data does not currently justify - see [Should this be
  rewritten?](#should-this-be-rewritten).
- Real ARM performance numbers from physical hardware. Compatibility is
  verified under QEMU; performance is not measurable that way.
- Per-panel refresh intervals exposed in the config, so users can trade
  freshness for CPU per feature rather than globally.
