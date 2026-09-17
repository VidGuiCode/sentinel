#!/usr/bin/env python3
"""Benchmark runner: start a tool, read CPU, RSS, and context changes for
N seconds, write JSON.

Usage: python3 bench/runner.py --name X --duration 30 --out /path/X.json [--tty] -- cmd args...

With --tty the target runs on a new pty (120x35, TERM=xterm-256color).
At the end of the run it receives 'q', then SIGTERM. Without --tty
stdout and stderr go to /dev/null.

Read every 0.5s:
  - /proc/<pid>/stat   (utime and stime give % of one core)
  - /proc/<pid>/status (VmRSS, voluntary and nonvoluntary context changes)
  - container cgroup CPU (v2: /sys/fs/cgroup/cpu.stat usage_usec,
    nr_throttled, throttled_usec; v1 path: cpuacct.usage). This catches
    short child calls that per-pid reads miss.

Drop the first 2 reads (startup jump).
"""

import argparse
import fcntl
import json
import os
import select
import signal
import struct
import subprocess
import sys
import termios
import time

CLK_TCK = os.sysconf('SC_CLK_TCK')
SAMPLE_INTERVAL = 0.5
DISCARD_SAMPLES = 2
TERM_ROWS, TERM_COLS = 35, 120


def read_proc_stat(pid):
    """Return utime and stime in jiffies. Return None when the call ends."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            data = f.read()
        # comm can hold spaces and parens. Fields after the last ')'
        # start at field 3.
        rest = data[data.rindex(')') + 2:].split()
        utime = int(rest[11])  # field 14
        stime = int(rest[12])  # field 15
        return utime + stime
    except (OSError, ValueError, IndexError):
        return None


def read_proc_status(pid):
    """Return (VmRSS in kB, voluntary changes, nonvoluntary changes)."""
    rss = vol = nonvol = None
    try:
        with open(f'/proc/{pid}/status', 'r') as f:
            for line in f:
                if line.startswith('VmRSS:'):
                    rss = int(line.split()[1])
                elif line.startswith('voluntary_ctxt_switches:'):
                    vol = int(line.split()[1])
                elif line.startswith('nonvoluntary_ctxt_switches:'):
                    nonvol = int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return rss, vol, nonvol


def detect_cgroup_v2():
    return os.path.exists('/sys/fs/cgroup/cpu.stat')


def read_cgroup_cpu(v2):
    """Return (usage_usec, nr_throttled, throttled_usec). Use None when missing."""
    if v2:
        usage = nr_thr = thr_usec = None
        try:
            with open('/sys/fs/cgroup/cpu.stat', 'r') as f:
                for line in f:
                    key, _, val = line.partition(' ')
                    val = val.strip()
                    if key == 'usage_usec':
                        usage = int(val)
                    elif key == 'nr_throttled':
                        nr_thr = int(val)
                    elif key == 'throttled_usec':
                        thr_usec = int(val)
        except (OSError, ValueError):
            pass
        return usage, nr_thr, thr_usec
    try:
        with open('/sys/fs/cgroup/cpuacct.usage', 'r') as f:
            return int(f.read().strip()) // 1000, None, None  # ns -> us
    except (OSError, ValueError):
        return None, None, None


def percentile(values, pct):
    if not values:
        return None
    vals = sorted(values)
    k = (len(vals) - 1) * pct / 100.0
    lo = int(k)
    hi = min(lo + 1, len(vals) - 1)
    frac = k - lo
    return vals[lo] + (vals[hi] - vals[lo]) * frac


def stats_block(values):
    if not values:
        return {'mean': None, 'p50': None, 'p95': None, 'max': None}
    return {
        'mean': round(sum(values) / len(values), 2),
        'p50': round(percentile(values, 50), 2),
        'p95': round(percentile(values, 95), 2),
        'max': round(max(values), 2),
    }


def spawn_target(args, use_tty):
    """Start the target command. Return (Popen, master_fd or None)."""
    if not use_tty:
        proc = subprocess.Popen(
            args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc, None

    master_fd, slave_fd = os.openpty()
    # Set the window size. Then curses tools draw a true layout
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ,
                struct.pack('HHHH', TERM_ROWS, TERM_COLS, 0, 0))

    env = dict(os.environ)
    env['TERM'] = 'xterm-256color'

    def _preexec():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    proc = subprocess.Popen(
        args,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        env=env,
        preexec_fn=_preexec,
        close_fds=True,
    )
    os.close(slave_fd)
    os.set_blocking(master_fd, False)
    return proc, master_fd


def drain_pty(master_fd, timeout):
    """Read and drop pty output for up to `timeout` seconds."""
    if master_fd is None:
        time.sleep(timeout)
        return
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        r, _, _ = select.select([master_fd], [], [], remaining)
        if not r:
            return
        try:
            if not os.read(master_fd, 65536):
                return
        except OSError:
            return


def stop_target(proc, master_fd):
    """Send 'q', wait a short time, then send SIGTERM (call group),
    then send SIGKILL."""
    if master_fd is not None and proc.poll() is None:
        try:
            os.write(master_fd, b'q')
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    if proc.poll() is None:
        try:
            if master_fd is not None:
                os.killpg(proc.pid, signal.SIGTERM)
            else:
                proc.terminate()
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                if master_fd is not None:
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except (ProcessLookupError, PermissionError):
                pass
            proc.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description='Benchmark runner')
    parser.add_argument('--name', required=True)
    parser.add_argument('--duration', type=float, default=30)
    parser.add_argument('--out', required=True)
    parser.add_argument('--tty', action='store_true')
    parser.add_argument('cmd', nargs=argparse.REMAINDER)
    ns = parser.parse_args()

    cmd = ns.cmd
    if cmd and cmd[0] == '--':
        cmd = cmd[1:]
    if not cmd:
        parser.error('no target command given (use -- cmd args...)')

    os.makedirs(os.path.dirname(os.path.abspath(ns.out)), exist_ok=True)

    proc, master_fd = spawn_target(cmd, ns.tty)
    cg_v2 = detect_cgroup_v2()

    samples = []
    start = time.monotonic()
    first_cg_usage, first_nr_thr, first_thr_usec = read_cgroup_cpu(cg_v2)
    prev = None  # (wall_time, proc_jiffies, cg_usage_usec, vol, nonvol)

    try:
        while time.monotonic() - start < ns.duration:
            t0 = time.monotonic()
            jiff = read_proc_stat(proc.pid)
            rss, vol, nonvol = read_proc_status(proc.pid)
            cg_usage, nr_thr, thr_usec = read_cgroup_cpu(cg_v2)

            if prev is not None and jiff is not None:
                dt = t0 - prev[0]
                if dt > 0:
                    cpu_pct = 100.0 * (jiff - prev[1]) / (dt * CLK_TCK)
                    cg_pct = None
                    if cg_usage is not None and prev[2] is not None:
                        cg_pct = 100.0 * (cg_usage - prev[2]) / (dt * 1e6)
                    samples.append({
                        't': round(t0 - start, 2),
                        'cpu_percent': round(cpu_pct, 2),
                        'cgroup_cpu_percent': None if cg_pct is None else round(cg_pct, 2),
                        'rss_kb': rss,
                        'voluntary_ctx': vol,
                        'nonvoluntary_ctx': nonvol,
                    })
            prev = (t0, jiff, cg_usage, vol, nonvol)

            if proc.poll() is not None and jiff is None:
                break
            drain_pty(master_fd, max(0.0, SAMPLE_INTERVAL - (time.monotonic() - t0)))
    finally:
        last_cg_usage, last_nr_thr, last_thr_usec = read_cgroup_cpu(cg_v2)
        stop_target(proc, master_fd)
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass

    # Drop the startup jump
    kept = samples[DISCARD_SAMPLES:]

    cpu_vals = [s['cpu_percent'] for s in kept]
    cg_vals = [s['cgroup_cpu_percent'] for s in kept if s['cgroup_cpu_percent'] is not None]
    rss_vals = [s['rss_kb'] for s in kept if s['rss_kb'] is not None]

    # Count context changes per second from the first and last kept reads
    ctx_vol = ctx_nonvol = None
    ctx_samples = [s for s in kept if s['voluntary_ctx'] is not None]
    if len(ctx_samples) >= 2:
        span = ctx_samples[-1]['t'] - ctx_samples[0]['t']
        if span > 0:
            ctx_vol = round((ctx_samples[-1]['voluntary_ctx'] - ctx_samples[0]['voluntary_ctx']) / span, 1)
            ctx_nonvol = round((ctx_samples[-1]['nonvoluntary_ctx'] - ctx_samples[0]['nonvoluntary_ctx']) / span, 1)

    result = {
        'name': ns.name,
        'duration': ns.duration,
        'exit_code': proc.returncode,
        'samples': len(kept),
        'cpu_percent': stats_block(cpu_vals),
        'cgroup_cpu_percent': {
            'mean': round(sum(cg_vals) / len(cg_vals), 2) if cg_vals else None,
            'max': round(max(cg_vals), 2) if cg_vals else None,
        },
        'rss_kb': {
            'mean': round(sum(rss_vals) / len(rss_vals), 1) if rss_vals else None,
            'max': max(rss_vals) if rss_vals else None,
        },
        'ctx_switches_per_sec': {'voluntary': ctx_vol, 'nonvoluntary': ctx_nonvol},
        'nr_throttled_delta': (last_nr_thr - first_nr_thr) if (first_nr_thr is not None and last_nr_thr is not None) else None,
        'throttled_usec_delta': (last_thr_usec - first_thr_usec) if (first_thr_usec is not None and last_thr_usec is not None) else None,
        'cgroup_total_cpu_percent': (
            round(100.0 * (last_cg_usage - first_cg_usage) / ((time.monotonic() - start) * 1e6), 2)
            if (first_cg_usage is not None and last_cg_usage is not None) else None),
        'raw_samples': kept,
    }

    with open(ns.out, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"[runner] {ns.name}: {len(kept)} samples -> {ns.out} "
          f"(exit={proc.returncode}, cpu_mean={result['cpu_percent']['mean']}%)")


if __name__ == '__main__':
    main()
