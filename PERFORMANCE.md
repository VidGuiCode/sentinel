# Sentinel Performance

Sentinel serves:

- low-end servers
- Raspberry Pi units
- hosts with small resources

This file gives test results first.
Then it shows design methods that keep CPU and memory low.

---

# Measured performance (v0.6.0)

## How the team made these numbers - read this first

The team used no physical hardware.
All numbers come from CPU and memory caps in Docker containers on an x86_64 host.
The caps stand for device classes:

| Profile | Container limits | Approximates |
|---------|------------------|--------------|
| `pi3` | `--cpus=0.5 --memory=256m` | Raspberry Pi 3 |
| `pi4` | `--cpus=1 --memory=512m` | Raspberry Pi 4 / small VPS |

These caps bound CPU share and memory size.
They do not copy these traits:

- ARM command time
- slow RAM
- SD card delay
- heat limits

A real Pi runs slow in true terms.
The before and after change is the true result.
The absolute values do not predict Pi speed.

The team took before and after values in the same session, back to back, at the same host load.
Values from separate sessions do not compare.
Each run lasts 30s.
The team drops first samples as start effect.

Reproduce with:

```bash
DURATION=30 SENTINEL_SCRIPT=<old-revision.py> ./bench/run_profiles.sh before
DURATION=30 ./bench/run_profiles.sh after
python3 bench/summarize.py bench/results/after
```

## v0.5.1 → v0.6.0

`Cgroup CPU%` shows the share of the container CPU quota.
This share is the value that counts on a small device.
`max` shows the worst single sample.
It shows the spike that a user feels as a stutter.

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

- **Worst-case CPU spike fell.** Numbers fell from 12.9% to 1.3% of quota
  (Pi 3 TUI) and from 23.3% to 0.9% (headless). The old fetch loop did all
  work in one burst on the render thread. That burst froze the view.
  Threads now spread collectors at separate times. Each collector keeps its
  own interval. The burst is gone.
- **Mean CPU use fell to half the old value (0.9% → 0.3% of quota).**
- **Fewer wakeups.** The render loop now sleeps until the next data
  refresh or clock second. It no longer wakes each 500ms. It skips the full
  repaint when data shows no change. This drops near 75% of full repaints
  at the normal 2s refresh.

### What regressed

- **RSS grew in normal mode (20MB → 31MB).** Sentinel now imports
  `urllib.request`, `ssl`, and `email.parser` in its own address space
  (~10MB). The old code kept that cost in a short child process. The CPU
  gain has a memory cost.
- **`--light` mode avoids this cost.** It never starts the public IP
  collector or the update check collector. Thus it never imports `urllib`.
  **21.4MB vs 31.5MB.** On a 256MB Pi 3, this is the gap between 8% and
  12% of total RAM. **Use `--light` on Pi-class hardware.** (The team took
  these values without the TUI history buffers: 13.7MB light vs 23.6MB
  normal.)
- **Throttle events rose a small count on the Pi 3 profile.** The count
  rose from 2 to 5 over 30s. Threads now spread work, so short bursts hit
  the 0.5-CPU quota more often. Total CPU use is still low. Counts stay
  small and shift between runs. No user felt an effect.

## Comparison against btop and htop

The team used the same containers, the same 30s duration, and the same session.

**Pi 3 profile**

| Tool | CPU% mean | Cgroup CPU% mean (max) | RSS MB | ctx/s (voluntary) |
|------|-----------|------------------------|--------|-------------------|
| sentinel v0.6.0 `--light` | 0.2 | 0.3 (1.1) | 21.4 | 1.5 |
| sentinel v0.6.0 TUI | 0.2 | 0.3 (1.3) | 31.5 | 1.7 |
| btop | 0.6 | 0.7 (1.4) | 5.6 | 98.9 |
| htop | 0.1 | 0.2 (0.5) | 3.8 | 0.7 |

- **CPU: Sentinel now takes less CPU than btop (0.3% vs 0.7% of quota).** The gap to htop stays in test noise.
- **Wakeups: Sentinel wakes far less than btop.** It makes 1.5 voluntary
  context switches/sec against btop ~99/s. btop repaints on a fixed fast
  tick. Sentinel sleeps until a value alters.
- **Memory: Sentinel takes 4-6x more memory.** Near 14MB of that is the
  CPython interpreter and stdlib, present before Sentinel starts. A
  compiled monitor wins in this one area. No Python fix closes this gap.

htop sets the low mark.
It monitors far less:

- Docker
- Kubernetes
- WireGuard
- security logs
- power

## Should this be rewritten?

**No - the evidence does not back a Rust or Go rewrite.**

The team sets one gate for a rewrite: proof that the Python interpreter caps speed after all fixes.
That proof is absent:

- Sentinel CPU cost now stays **below btop**, a C++ monitor, at the same load. Thus interpreter speed does not cap Sentinel.
- The rest of the gap is **resident memory** from interpreter baseline
  (~14MB), not from interpreter execution speed. A rewrite would fix
  memory, not speed. It would trade a single dependency-free 3.8k-line
  file for a per-architecture build and release pipeline. That file runs
  where Python 3 exists.
- The true costs were design faults, and the team fixed those faults in place:
  - a fetch loop that blocks
  - subprocess starts on the render path
  - full repaints with no test

If ~21MB (light mode) still breaks a target device, that fact backs a rewrite.
Speed alone does not back it.

## ARM verification (aarch64 + armv7)

**The team proved ARM run; the team took no ARM performance values, and this rig cannot take them.**

No rewrite took place, so Sentinel needs no cross build.
It is one pure-Python file.
The team proved correct ARM run for these parts:

- imports
- reads of `/proc` and `/sys` (differs from x86: ARM has no `model name` field in `/proc/cpuinfo`)
- curses display
- both entry-point modes

Both chip types passed a smoke test in QEMU user-mode emulation through `binfmt_misc`:

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

**16 of 16 checks passed.**
CPU detection takes the ARM path.
An aarch64 container reports `ARMv8 Processor rev 0 (v8l)` from the `Processor`/`Hardware` fields, not from x86 `model name`.

**Why the file gives no ARM values:** QEMU user-mode emulation turns ARM commands to x86_64 commands on the host, with big rough delay.
Thus a time value here would show the emulator, not a Pi.
Stored memory values also fail: the RSS in the container fits the QEMU process and adds translation-cache overhead.
**QEMU proves that code runs; it does not prove speed.**
Each performance value in this file is x86_64.

Only a real Pi gives true ARM performance values.
Until a user runs `bench/run_profiles.sh` on a Pi, take the change values as the firm result.
They stem from cut of work that blocks and of full repaints.
That gain holds for each chip type the same.
Take absolute values as x86_64 only.

## Known issues

- **Runs fail at times on Docker Desktop for Windows.** Near 1 run in 6
  at tight memory caps dies at tool start. The cause is an `OSError` from
  an import that reads the bind-mounted checkout. This hits before
  Sentinel code starts. It also hits v0.5.1, so the host causes it, not new
  code. `bench/run_profiles.sh` starts the run anew when the run yields no
  samples.
- **No ARM performance values exist.** aarch64 and armv7 run in a correct
  way (see above), but each performance value in this file is x86_64. QEMU
  cannot give true ARM time values, and the team had no real Pi.
- **`bench/capture_frame.py` does not copy terminal scroll.** So its grid
  can sit one row off and can show bits of past frames. Test for content,
  not for exact spot. This fault hits the test tool alone.
- **Temperature sensors and RAPL fail in WSL2, VMs, or containers.** The
  platform hides those ports from the guest. This is a platform cap, not a
  fault. Panels say so; they never show false zeros.

---

# Optimisation techniques used in the codebase

## How Sentinel collects data

Cost splits the reads in two ranks:

**The render thread holds inline reads.** It takes only fast reads from `/proc` and `/sys`:

- CPU
- memory
- disk (`os.statvfs`)
- network counters
- uptime
- battery
- RAPL power

These reads cost so small that a thread for them would cost more than it saves.

**Background collectors hold slow reads.** Each slow read and each read that waits runs on a daemon thread at an interval of its own.
`update_data()` merges the latest sent snapshot and never waits.
A collector that fails still serves its last good value.
It logs the fault for the diagnostics overlay.

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

Intervals track how fast values truly alter, not the refresh rate.
Sentinel never polls Docker or Kubernetes each 2 seconds for values that alter each few minutes.

## Techniques in use

### Direct `/proc` and `/sys` reads, no subprocesses

A child start that reads a file has three costs:

- a fork
- an exec
- a pipe

Sentinel reads the file.

```python
# BAD - spawns a process
temp = subprocess.run(['cat', '/sys/class/thermal/thermal_zone0/temp'], ...)

# GOOD - direct read
with open('/sys/class/thermal/thermal_zone0/temp') as f:
    temp = int(f.read()) / 1000
```

`shell=True` never shows in the code.
One `subprocess.run` call site stays, and it takes a list of terms.
Only these three commands use it:

- `kubectl`
- `wg`
- `iwgetid`

All three run on background collectors, never on the render path.

### Docker over the unix socket, not the CLI

Old code started a child per cycle for:

- `docker ps`
- `docker stats`
- `docker system df -v`

The old volume path ran `docker system df -v | grep | awk` once per volume.
Sentinel now sends HTTP to `/var/run/docker.sock` with a small stdlib client.
Sentinel marks a `DOCKER_HOST` value that is not a local unix socket as `unsupported_host`.
It never drops the value with no note.

### One `/proc/stat` read per cycle

Total CPU and per-core use come from one read.
Sentinel reads once and splits the text once, not once per core.

### Process scan reads `stat` only

RSS lives in field 24 of `/proc/<pid>/stat`, so Sentinel never opens `/proc/<pid>/status` with its line scan.
This cuts the call count in half on a scan that meets each PID.

### Repaint only when something changed

A frame signature tells if a repaint can alter the view.
It holds:

- data generation
- feature-status revision
- terminal size
- theme
- layout
- refresh rate
- open overlay

When a repaint cannot alter the view, Sentinel skips the ~2000-`addstr` redraw and only writes the header clock.
This drops near 75% of full repaints at the normal 2s refresh.

`SENTINEL_NO_FRAMESKIP=1` brings back repaints with no test.

### Sleep until the next change, not on a fixed tick

`getch()` stops at once on a key, whatever its wait cap.
Thus the wait cap fits the first of two events:

- the next data refresh
- the next clock second

It is not a fixed 500ms.
Idle wakeups fall, and key delay stays the same.

### Deferred imports

`http.client` (~8MB, it brings `email.parser`) and `urllib.request` (~2MB) load at the call spot.
A host with no Docker daemon never pays for the Docker client.

### Pre-compiled regex

Sentinel compiles security log patterns once at start and reuses them.
It never builds them per line per read.

### Fixed-size ring buffers

All history uses `collections.deque(maxlen=N)` with 100 points in normal use and 50 in light mode.
Bounds live in the form, so history cannot leak.

### Windowed cleanup for security events

Failed login and suspicious IP lists keep a 5-minute frame (`failed_login_window`) and drop old terms.
Thus memory stays flat while bad logins strike for a long time.

## Update checker

- It takes only the first 8KB of `sentinel-monitor.py` from GitHub through `urllib`, with a 3-second cap, and starts no `curl` child.
- It runs on a background collector: one time per 24 hours, one time per week in light mode.
- It compares semantic versions and warns only when the remote version is new.
- Faults show as `update_check: error` in the diagnostics overlay, never as a popup.
- **Light mode turns it off in full** (see below).
- Sentinel shows a dim note in the footer when a new version waits.

To update:

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinel/main/install-sentinel.sh | sudo bash
```

The installer keeps each old configuration file.

## Light mode

**First choice for Pi-class hosts**; tests show 21.4MB RSS versus 31.5MB normal (Pi 3 profile).

Turn it on with `--light` or with `light_mode: true` in the configuration file.
Sentinel also turns it on when `/proc/cpuinfo` looks like weak hardware.
Weak hardware means Raspberry Pi 4 / BCM2711, or a low core and RAM count.

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

The two network collectors stay off, and that saves the ~10MB.
No other code loads `urllib`, so `ssl` and `email.parser` stay out too.
Both mark themselves as `disabled in light mode` in the diagnostics overlay, with the setting to turn them back.

## Tune Sentinel for a low-end host

**1. Use light mode.** It gives the top gain.

```bash
sentinel --light
```

**2. Slow the refresh rate.** Press `-` in the TUI (up to 10s), or set `refresh_rate` in the configuration file.
Slow refresh means slow repaints, since data change now fires repaints.

**3. Use a lighter layout.** Press `l` to cycle; `minimal` draws the least panels.

**4. Turn off the public IP lookup** when the host does not need it:

```json
{ "public_ip_check": false }
```

**5. Send small log files to the security log parser.** Read cost grows with log size.
A pre-filtered file keeps the parser fast:

```json
{ "security_logs": { "auth": "/var/log/auth-filtered.log" } }
```

**6. Use service mode on headless hosts.** It uses no curses and writes no display:

```bash
sentinel --service
```

## Troubleshooting

### A panel is empty

Press `d`.
The diagnostics overlay lists each degradable feature with its state and its note.
States use fixed terms: `ok`, `no permission`, `not installed`, `socket missing`, `unsupported host`, `disabled`, `error`.
It also gives the exact command that fixes the fault.
Panels also say their state in place.

Sentinel tests permissions each 30 seconds, so a fix in the same session takes hold with no restart.
This holds for a group join, a log `chmod`, or a daemon start.

### High CPU

```bash
SENTINEL_PROFILE=/tmp/sentinel-profile.jsonl sentinel
```

It writes one JSON line per data refresh.
The line holds per-stage times, per-collector times and faults, subprocess counts, and frames drawn versus skipped.
That shows which collector costs most, so the user need not guess.

A host with a high count of containers strains the scan.
Large security logs also strain the parser (see tips above).

### How to check feature detection

```bash
SENTINEL_DEBUG=1 sentinel
```

It logs each feature-status transition to `/tmp/sentinel-debug.log`.

### Terminal display faults

When the terminal fails on partial updates, run:

```bash
SENTINEL_NO_FRAMESKIP=1 sentinel
```

## Comparison with other tools

True test values sit in [Comparison against btop and htop](#comparison-against-btop-and-htop) above.
In short: Sentinel CPU cost now sits below btop cost, and it wakes far less.
But it takes 4–6× more resident memory, most of it the CPython interpreter itself.

htop sets the low mark for cost, and it monitors far less:

- Docker
- Kubernetes
- WireGuard
- security logs
- power

## Possible future work

- Cut resident memory more. The firm floor is the interpreter (~14MB).
  Past that, only a compiled rewrite shifts it. The evidence does not back
  it now - see [Should this be rewritten?](#should-this-be-rewritten).
- Take true ARM performance values on real hardware. QEMU proves that code runs; it cannot test speed.
- Put per-panel intervals in the configuration file, so users can trade freshness for CPU per feature, not just for the whole tool.
