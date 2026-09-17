#!/usr/bin/env python3
"""
Sentinel - Universal Linux System Monitor
A single-screen TUI dashboard to monitor a home lab in real time

Features:
- Single-screen adaptive layout (fits any terminal size)
- Layout modes: default, cpu, network, docker, minimal (press L)
- Docker and Kubernetes container lists (they fit the free space)
- Docker volumes with names and sizes
- Energy use (RAPL for desktops, battery for laptops)
- Reverse proxy traffic (nginx and caddy access logs)
- Network panel with signal meter, VPN handshake age, and link speed
- Direct /proc and /sys reads, few subprocesses
- Braille sparklines and gradient colors
- Refresh rate 1-10 seconds (press +/-)
- Configuration file with custom themes and alert limits
- Systemd service mode for headless operation

Controls:
- q: Quit
- r: Refresh data now
- t: Cycle themes (default, nord, dracula, gruvbox, monokai)
- l: Cycle layouts (default, cpu, network, docker, minimal)
- h: Toggle help overlay
- i: Refresh public IP
- +/-: Set the refresh rate (faster/slower)

GitHub: https://github.com/VidGuiCode/sentinel
License: MIT
"""

import curses
import time
import os
import re
import sys
import json
import argparse
import socket
import subprocess
import threading
import shutil
import shlex
# urllib.request (~2MB RSS) and http.client (~8MB, they load email.parser)
# load at first use only: the public-IP collector, the update collector,
# and the Docker socket client. A Pi with no Docker and public_ip_check
# off never loads them. See _docker_conn_cls() and _collect_public_ip().
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path

VERSION = "0.6.2"

# Profile record (active only when SENTINEL_PROFILE holds a path)
_PROFILE_PATH = os.environ.get('SENTINEL_PROFILE')
_RUN_CMD_COUNT = 0

# Debug log (active only when SENTINEL_DEBUG holds a true value):
# feature_status changes and frame-skip numbers go to /tmp/sentinel-debug.log
_DEBUG_ENABLED = os.environ.get('SENTINEL_DEBUG', '') not in ('', '0')
_DEBUG_PATH = '/tmp/sentinel-debug.log'


def _debug_log(msg):
    """Write one line to the debug log. Do nothing when SENTINEL_DEBUG is off."""
    if not _DEBUG_ENABLED:
        return
    try:
        with open(_DEBUG_PATH, 'a') as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} {msg}\n")
    except OSError:
        pass

# Layout modes
LAYOUT_MODES = ['default', 'cpu', 'network', 'docker', 'security', 'minimal']

# Default configuration
DEFAULT_CONFIG = {
    'theme': 'default',
    'layout': 'default',
    'refresh_rate': 2,
    'alerts': {
        'cpu_high': 85,
        'cpu_critical': 95,
        'mem_high': 80,
        'mem_critical': 95,
        'temp_high': 75,
        'temp_critical': 90,
        'battery_low': 20,
        'battery_critical': 10,
    },
    'show_per_core': True,
    'show_vpn': True,
    'public_ip_check': True,
    'light_mode': False,
    'log_file': '/var/log/sentinel.log',
    'proxy_logs': {
        'nginx': '/var/log/nginx/access.log',
        'caddy': '/var/log/caddy/access.log',
    },
    'security_logs': {
        'auth': '/var/log/auth.log',
        'secure': '/var/log/secure',
        'syslog': '/var/log/syslog',
    },
    'security_alerts': {
        'failed_login_threshold': 20,
        'failed_login_window': 300,  # 5 minutes in seconds
        'suspicious_ip_threshold': 10,
        'error_rate_threshold': 10,
        'error_rate_window': 60,  # 1 minute in seconds
    },
    # Service health checks (v0.6.2): HTTP probing per container name plus
    # plain TCP listener checks. A container can be "running" while the app
    # inside has crashed; these say whether it actually answers.
    'health_checks': {
        # 'nginx-proxy': {'url': 'http://localhost:80', 'expect': 200},
    },
    'listeners': [
        # 22, 80, 443,
    ],
}

# Color themes
THEMES = {
    'default': {
        'primary': curses.COLOR_CYAN,
        'success': curses.COLOR_GREEN,
        'warning': curses.COLOR_YELLOW,
        'danger': curses.COLOR_RED,
        'info': curses.COLOR_BLUE,
        'accent': curses.COLOR_MAGENTA,
        'text': curses.COLOR_WHITE,
        'muted': 240,
    },
    'nord': {
        'primary': 109,   # Nord frost
        'success': 108,   # Nord green
        'warning': 179,   # Nord yellow
        'danger': 131,    # Nord red
        'info': 67,       # Nord blue
        'accent': 139,    # Nord purple
        'text': 253,      # Nord snow
        'muted': 60,      # Nord gray
    },
    'dracula': {
        'primary': 141,   # Purple
        'success': 84,    # Green
        'warning': 228,   # Yellow
        'danger': 203,    # Red/Pink
        'info': 117,      # Cyan
        'accent': 212,    # Pink
        'text': 253,      # Foreground
        'muted': 61,      # Comment
    },
    'gruvbox': {
        'primary': 108,   # Aqua
        'success': 142,   # Green
        'warning': 214,   # Yellow
        'danger': 167,    # Red
        'info': 109,      # Blue
        'accent': 175,    # Purple
        'text': 223,      # Foreground
        'muted': 102,     # Gray
    },
    'monokai': {
        'primary': 81,    # Cyan
        'success': 148,   # Green
        'warning': 186,   # Yellow
        'danger': 197,    # Red
        'info': 141,      # Purple
        'accent': 208,    # Orange
        'text': 231,      # White
        'muted': 242,     # Gray
    },
}


def load_config():
    """Read the configuration file. Return defaults when no file exists."""
    config = DEFAULT_CONFIG.copy()
    config_paths = [
        Path.home() / '.config' / 'sentinel' / 'config.json',
        Path.home() / '.sentinel.json',
        Path('/etc/sentinel/config.json'),
    ]
    
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge with the defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in config:
                            config[key].update(value)
                        else:
                            config[key] = value
                    config['_loaded_from'] = str(config_path)
                    break
            except (OSError, ValueError) as e:
                # A bad or unreadable configuration file that falls back
                # to defaults without a message hides user edits. The
                # user changes a value, nothing changes, nothing explains
                # why. Record the error so the diagnostics overlay shows it.
                config['_config_error'] = f"{config_path}: {e}"
                _debug_log(f"config load failed: {config_path}: {e}")

    return config


def save_default_config():
    """Write the default configuration file to the user configuration directory."""
    config_dir = Path.home() / '.config' / 'sentinel'
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / 'config.json'
    
    with open(config_path, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    
    return config_path


def _format_size(b):
    """Format a byte count. Use the same format as the disk panel."""
    for unit in ['B', 'K', 'M', 'G', 'T']:
        if b < 1024:
            return f"{b:.0f}{unit}" if unit == 'B' else f"{b:.1f}{unit}"
        b /= 1024
    return f"{b:.1f}P"


class DockerError(Exception):
    """Docker Engine API failure with a state that Sentinel can classify.

    state: 'socket_missing' | 'no_permission' | 'unsupported_host' | 'error'
    """
    def __init__(self, state, detail):
        super().__init__(detail)
        self.state = state
        self.detail = detail


_DOCKER_CONN_CLS = None


def _docker_conn_cls():
    """Build the unix-socket HTTP connection class at first use.

    The http.client import costs ~8MB RSS (it loads email.parser with
    it). On a Pi with no Docker daemon that cost buys a feature that
    never runs. So Sentinel imports http.client only when it contacts
    a socket. Later calls find it in sys.modules and cost nothing.
    """
    global _DOCKER_CONN_CLS
    if _DOCKER_CONN_CLS is None:
        import http.client

        class _DockerUnixHTTPConnection(http.client.HTTPConnection):
            """Minimal HTTP/1.1 connection over the Docker unix socket."""
            def __init__(self, socket_path, timeout=2):
                http.client.HTTPConnection.__init__(
                    self, 'localhost', timeout=timeout)
                self._socket_path = socket_path

            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.settimeout(self.timeout)
                self.sock.connect(self._socket_path)

        _DOCKER_CONN_CLS = _DockerUnixHTTPConnection
    return _DOCKER_CONN_CLS


class DockerClient:
    """Read-only Docker Engine API client. Use the unix socket.

    This client replaces all `docker ...` CLI calls. It accepts local
    unix sockets only. It reports tcp:// and ssh:// DOCKER_HOST values
    as 'unsupported_host'. It never starts ssh and never ignores the value.
    """
    API_VERSION = 'v1.41'

    def __init__(self, timeout=2):
        host = os.environ.get('DOCKER_HOST', '')
        if host.startswith('unix://'):
            self.socket_path = host[len('unix://'):]
        elif host:
            raise DockerError('unsupported_host',
                              f'DOCKER_HOST={host} is not a local unix socket')
        else:
            self.socket_path = '/var/run/docker.sock'
        self.timeout = timeout
        # Last CPU sample per container, for delta math
        # {container_id: (total_usage, system_cpu_usage)}
        self._prev_cpu_samples = {}

    def _get_json(self, path, timeout=None):
        """Read one API endpoint and parse the JSON body. Raise DockerError."""
        if not os.path.exists(self.socket_path):
            raise DockerError('socket_missing', f'{self.socket_path} not found')
        import http.client  # deferred; see _docker_conn_cls()
        conn = _docker_conn_cls()(self.socket_path,
                                  timeout=timeout or self.timeout)
        status = None
        try:
            conn.request('GET', f'/{self.API_VERSION}{path}')
            resp = conn.getresponse()
            status = resp.status
            body = resp.read()
        except PermissionError as e:
            raise DockerError('no_permission',
                              f'cannot access {self.socket_path}: {e}')
        except (OSError, http.client.HTTPException) as e:
            raise DockerError('error', f'GET {path} failed: {e}')
        finally:
            conn.close()
        if status != 200:
            raise DockerError('error', f'GET {path} -> HTTP {status}')
        try:
            return json.loads(body.decode('utf-8', 'replace'))
        except ValueError as e:
            raise DockerError('error', f'GET {path} -> invalid JSON: {e}')

    def ping(self):
        """Check that the daemon answers. Read /version (the lightest endpoint)."""
        self._get_json('/version')
        return True

    def containers(self):
        """Return the container list with one-shot CPU% and mem% values."""
        raw = self._get_json('/containers/json?all=1')
        containers = []
        running = 0
        stopped = 0
        for c in raw:
            cid_full = c.get('Id', '')
            cid = cid_full[:12]
            names = c.get('Names') or []
            name = (names[0].lstrip('/') if names else cid)[:20]
            is_running = c.get('State') == 'running'
            image = (c.get('Image') or '').split('/')[-1][:15]
            cpu_pct = 0.0
            mem_pct = 0.0
            if is_running:
                running += 1
                try:
                    cpu_pct, mem_pct = self.container_stats(cid_full)
                except DockerError:
                    pass  # leave 0.0 for this container
            else:
                stopped += 1
            containers.append({
                'id': cid,
                'name': name,
                'status': 'running' if is_running else 'stopped',
                'image': image,
                'cpu': cpu_pct,
                'mem': mem_pct,
            })
        containers = sorted(containers, key=lambda x: (x['status'] != 'running', -x['cpu']))
        return {
            'running': running,
            'stopped': stopped,
            'total': len(containers),
            'containers': containers[:10],
        }

    def container_stats(self, container_id):
        """Read one-shot stats. Return (cpu_percent, mem_percent) like the CLI.

        CPU% = (cpu_delta / system_delta) * online_cpus * 100. Take the
        delta against precpu_stats when the daemon sends them. If not,
        use the last sample (one collector interval old).
        """
        data = self._get_json(f'/containers/{container_id}/stats?stream=false&one-shot=true')
        cpu_pct = 0.0
        cpu_stats = data.get('cpu_stats') or {}
        precpu_stats = data.get('precpu_stats') or {}
        try:
            total_usage = (cpu_stats.get('cpu_usage') or {}).get('total_usage', 0)
            system_usage = cpu_stats.get('system_cpu_usage', 0)
            prev_total = (precpu_stats.get('cpu_usage') or {}).get('total_usage', 0)
            prev_system = precpu_stats.get('system_cpu_usage', 0)
            if not prev_system:
                # The daemon sent no old sample. Use the last one, if any
                prev_total, prev_system = self._prev_cpu_samples.get(
                    container_id, (0, 0))
            self._prev_cpu_samples[container_id] = (total_usage, system_usage)
            cpu_delta = total_usage - prev_total
            system_delta = system_usage - prev_system
            online_cpus = (cpu_stats.get('online_cpus')
                           or len((cpu_stats.get('cpu_usage') or {}).get('percpu_usage') or [])
                           or 1)
            if system_delta > 0 and cpu_delta >= 0:
                cpu_pct = (cpu_delta / system_delta) * online_cpus * 100.0
        except (TypeError, AttributeError):
            cpu_pct = 0.0
        mem_pct = 0.0
        try:
            mem_stats = data.get('memory_stats') or {}
            usage = mem_stats.get('usage', 0)
            limit = mem_stats.get('limit', 0)
            if limit > 0:
                mem_pct = (usage / limit) * 100.0
        except (TypeError, AttributeError, ZeroDivisionError):
            mem_pct = 0.0
        return cpu_pct, mem_pct

    def disk_usage_volumes(self):
        """Return volume sizes in the disk-panel shape. Show '-' when the
        daemon omits SizeBytes (there is no shell fallback per volume).

        Verbose df can take seconds on hosts with many images. So this
        call uses a long timeout. It falls back to the plain /volumes list.
        """
        volumes = []
        raw_volumes = None
        try:
            df = self._get_json('/system/df?verbose=true', timeout=15)
            raw_volumes = df.get('Volumes')
        except DockerError:
            pass  # fall through to the plain volume list
        if raw_volumes is None:
            data = self._get_json('/volumes')
            raw_volumes = data.get('Volumes')
        for v in (raw_volumes or [])[:5]:
            name = (v.get('Name') or '')[:14]
            if not name:
                continue
            size = '-'
            usage = v.get('UsageData') or {}
            size_bytes = usage.get('SizeBytes', -1)
            if isinstance(size_bytes, int) and size_bytes >= 0:
                size = _format_size(size_bytes)
            volumes.append({
                'mount': name,
                'used': size,
                'total': '',
                'percent': 0,
                'type': 'docker',
            })
        return volumes


class Collector:
    """Background data collector. Run fn() every `interval` seconds.

    Publish each result by swap of one tuple reference (_published).
    The GIL makes the swap atomic. So readers on the UI thread use no
    lock and never wait for the collector.
    """
    def __init__(self, name, interval, fn, stop_event):
        self.name = name
        self.interval = interval
        self.fn = fn
        self._stop_event = stop_event
        self._wake_event = threading.Event()
        self._thread = None
        # (result, error, duration_s, finished_at, generation): one atomic value
        self._published = (None, None, 0.0, 0.0, 0)
        self.subprocess_count = 0

    def start(self):
        self._thread = threading.Thread(
            target=self._loop, name=f'sentinel-collector-{self.name}', daemon=True)
        self._thread.start()

    def wake(self):
        """Ask for a run outside the plan (example: user pressed refresh)."""
        self._wake_event.set()

    def _loop(self):
        while not self._stop_event.is_set():
            self.run_once()
            # Wait for the interval. Wake early on request or shutdown
            self._wake_event.wait(self.interval)
            self._wake_event.clear()

    def run_once(self):
        global _RUN_CMD_COUNT
        start = time.monotonic()
        spawns_before = _RUN_CMD_COUNT
        result = None
        error = None
        try:
            result = self.fn()
        except Exception as e:  # collector threads must never die
            error = e
        duration = time.monotonic() - start
        self.subprocess_count += _RUN_CMD_COUNT - spawns_before
        prev = self._published
        if result is None:
            result = prev[0]  # keep the last good result on error
        self._published = (result, error, duration, time.time(), prev[4] + 1)

    def snapshot(self):
        """Return (result, error, duration_s, finished_at, generation). Never wait."""
        return self._published


class SentinelMonitor:
    """System monitor with a single-screen adaptive layout."""

    def __init__(self, config=None, service_mode=False):
        self.config = config or load_config()
        self.service_mode = service_mode
        self.start_time = datetime.now()
        self.last_update = 0
        self.cache = {}
        self.hostname = socket.gethostname()
        self.wg_permission_denied = False
        self.alerts = self.config.get('alerts', DEFAULT_CONFIG['alerts'])
        self.theme_name = self.config.get('theme', 'default')
        
        # Network numbers
        self.last_net_bytes = {'rx': 0, 'tx': 0, 'time': time.time()}
        self.default_iface = self._detect_default_interface()
        
        # CPU numbers for delta math
        self.last_cpu_times = None
        
        # RAPL energy numbers (for desktops and servers with no battery)
        self.last_rapl = {'energy': 0, 'time': time.time()}
        self.rapl_path = self._detect_rapl_path()
        self.power_history = deque([0] * 100, maxlen=100)
        
        # History for sparklines (100 points fill wide terminals)
        self.cpu_history = deque([0] * 100, maxlen=100)
        self.mem_history = deque([0] * 100, maxlen=100)
        self.rx_history = deque([0] * 100, maxlen=100)
        self.tx_history = deque([0] * 100, maxlen=100)
        
        # Cache the CPU model (it never changes)
        self.cpu_model = self._get_cpu_model()
        self.cpu_cores = os.cpu_count() or 1
        
        # Startup: cache tool checks so the first frame starts fast
        self._docker_available = None
        self._kubectl_available = None
        self._first_render = True  # Skip expensive ops on first frame
        self._loading = False  # Loading state for modal
        self._show_help = False  # Help overlay toggle
        self._show_diagnostics = False  # Diagnostics overlay toggle

        # P5 frame-skip state. A full draw costs ~2k addstr calls. So it
        # runs only when a visible value changed. _frame_signature() folds
        # all renderer input into one value. Between changes the loop
        # ticks the clock with 1 addstr call, not a full repaint.
        self._last_frame_sig = None
        self._last_clock = ''
        # Escape: repaint each cycle (v0.5.x mode). Use it for terminals
        # that mishandle partial updates, and for A/B tests.
        self._no_frameskip = os.environ.get('SENTINEL_NO_FRAMESKIP') == '1'
        self.frames_drawn = 0
        self.frames_skipped = 0


        # Layout mode
        self.layout_mode = self.config.get('layout', 'default')
        
        # Refresh rate (change it with +/-)
        self.refresh_rate = self.config.get('refresh_rate', 2)
        
        # Proxy traffic monitoring
        self.proxy_logs = self.config.get('proxy_logs', DEFAULT_CONFIG['proxy_logs'])
        self.proxy_history = deque([0] * 100, maxlen=100)
        self._last_proxy_check = 0
        self._proxy_stats = {'requests': 0, 'bytes': 0, 'rps': 0.0}

        # Security log monitoring
        self.security_logs = self.config.get('security_logs', DEFAULT_CONFIG['security_logs'])
        self.security_alerts_config = self.config.get('security_alerts', DEFAULT_CONFIG['security_alerts'])
        self.failed_login_history = deque([0] * 100, maxlen=100)
        self.suspicious_ip_history = deque([0] * 100, maxlen=100)
        self._last_security_check = 0
        self._security_cache = {}
        self._security_events = []  # Store recent events with timestamps for windowed analysis
        self._ip_failure_tracker = {}  # Track failures per IP with timestamps

        # Permission map: probe what is available at startup
        self._permissions = self._detect_permissions()

        # Service health checks (v0.6.2): one HTTP probe per container
        # name plus a plain port list. They run on their own slow
        # collector. update_data() merges the results into the snapshot.
        self.health_checks = self.config.get('health_checks', {}) or {}
        self.listeners = self.config.get('listeners', []) or []
        
        # Cache /proc/stat for merged CPU reads (fast path)
        self._proc_stat_cache = None
        self._proc_stat_time = 0
        
        # Light mode: auto-detect low-resource hardware or take --light
        self._is_light_hw = self._detect_light_hardware()
        # Also accept manual --light on any low-end machine
        self._light_mode = self._is_light_hw or self.config.get('light_mode', False)
        if self._light_mode:
            # Reduce defaults for low-resource machines
            self.refresh_rate = max(3, self.refresh_rate)
            self.cpu_history = deque([0] * 50, maxlen=50)
            self.mem_history = deque([0] * 50, maxlen=50)
            self.rx_history = deque([0] * 50, maxlen=50)
            self.tx_history = deque([0] * 50, maxlen=50)
            self.power_history = deque([0] * 50, maxlen=50)
            self.failed_login_history = deque([0] * 50, maxlen=50)
            self.suspicious_ip_history = deque([0] * 50, maxlen=50)
        
        # Non-blocking update checker
        self._update_available = None
        self._last_update_check = 0
        self._update_check_interval = 604800 if self._light_mode else 86400  # Weekly in light mode
        self._compiled_regex = {}  # Cache compiled regex patterns for performance

        # Cached tool paths (skip repeat PATH search and repeat spawns)
        self._iwgetid_path = shutil.which('iwgetid')

        # Frame-signature numbers (P5): repaint only when a value changed
        self._data_revision = 0    # bumped by update_data on every cache rebuild
        self._status_revision = 0  # bumped on every feature_status transition
        self._frames_drawn = 0
        self._frame_ticks = 0

        # Status map per feature (P6): probes and collectors update it.
        # The diagnostics overlay and panel placeholders read it.
        self.feature_status = {}
        self._init_feature_status()

        # Collectors (P1): all slow or IO-bound features run off
        # the UI thread. update_data() merges their latest snapshots only.
        self._collector_stop = threading.Event()
        self.collectors = {}
        self._docker_client = None
        proxy_interval = 10 if self._light_mode else 5
        self._register_collector('docker', 5, self._collect_docker)
        self._register_collector('docker_df', 30, self._collect_docker_df)
        self._register_collector('kubernetes', 15, self._collect_kubernetes)
        self._register_collector('wireguard', 10, self._collect_wireguard)
        self._register_collector('proxy', proxy_interval, self.get_proxy_stats)
        self._register_collector('security', 5, self.get_security_logs)
        self._register_collector('processes', 5, self._collect_processes)
        # The two network collectors explain the whole urllib.request
        # import (with ssl and email.parser through it): ~10MB RSS, a
        # third of the Sentinel size, for a public-IP readout and a
        # version check. Light mode fits the Pi 3 and the small VPS
        # case. It skips both and stays near 21MB, not 31MB.
        if self._light_mode:
            self._set_feature_status(
                'public_ip', 'unavailable',
                'disabled in light mode (saves ~10MB RSS)',
                'run without --light, or set light_mode: false in the config')
            self._set_feature_status(
                'update_check', 'unavailable',
                'disabled in light mode (saves ~10MB RSS)',
                'run without --light, or set light_mode: false in the config')
        else:
            self._register_collector('public_ip', 300, self._collect_public_ip)
            self._register_collector('update_check', self._update_check_interval,
                                     self._collect_update_check)
        self._register_collector('probes', 30, self._collect_probes)
        self._register_collector('ssid', 60, self._collect_ssid)
        self._register_collector('health', 30, self._collect_health)
        for collector in self.collectors.values():
            collector.start()

    def _register_collector(self, name, interval, fn):
        self.collectors[name] = Collector(name, interval, fn, self._collector_stop)

    def _collector_result(self, name):
        """Return the latest published collector result. Return None when it never ran."""
        collector = self.collectors.get(name)
        if collector is None:
            return None
        return collector.snapshot()[0]

    def wake_collector(self, name):
        collector = self.collectors.get(name)
        if collector is not None:
            collector.wake()

    def stop_collectors(self):
        """Tell all collector threads to stop. All threads are daemonic and
        all I/O uses timeouts. So no collector can block process exit."""
        self._collector_stop.set()
        for collector in self.collectors.values():
            collector.wake()  # cut the interval wait short for a fast exit

    def _set_feature_status(self, name, state, detail='', fix=''):
        """Update one feature status entry. On change bump the status
        number (so the TUI repaints). Log it when SENTINEL_DEBUG=1."""
        old = self.feature_status.get(name)
        if old is not None and old.get('state') == state \
                and old.get('detail') == detail and old.get('fix') == fix:
            return  # no change
        self.feature_status[name] = {'state': state, 'detail': detail, 'fix': fix}
        self._status_revision += 1
        if old is None or old.get('state') != state:
            _debug_log(f"feature {name}: "
                       f"{old.get('state') if old else 'init'} -> {state}"
                       f"{(' | ' + detail) if detail else ''}")

    def _apply_feature_perm(self, feature, state):
        """Copy a collector state into the old _permissions map. The header
        and diagnostics render code reads that map."""
        mapping = {'ok': 'ok', 'no_permission': 'no_perm',
                   'not_installed': 'not_installed', 'socket_missing': 'not_installed',
                   'unsupported_host': 'not_installed'}
        if state in mapping:
            self._permissions[feature] = mapping[state]

    def _init_feature_status(self):
        fixes = {
            'docker': 'sudo usermod -aG docker $USER  (then re-login)',
            'kubernetes': 'install kubectl and configure a context',
            'wireguard': 'sudo setcap cap_net_admin+ep $(which wg)  or  NOPASSWD sudoers entry for wg',
        }
        for feature in ('docker', 'kubernetes', 'wireguard'):
            perm = self._permissions.get(feature, 'not_installed')
            state = {'ok': 'ok', 'no_perm': 'no_permission'}.get(perm, 'not_installed')
            self._set_feature_status(feature, state, '',
                                     fixes.get(feature, '') if state != 'ok' else '')
        # Probe-owned features (security, proxy, rapl, battery, ...)
        self._sync_probe_feature_status()
        # Collector-owned meta features
        self._set_feature_status('public_ip', 'ok' if self.config.get('public_ip_check', True)
                                 else 'unavailable',
                                 '' if self.config.get('public_ip_check', True)
                                 else 'disabled in config (public_ip_check: false)')
        self._set_feature_status('update_check', 'ok')
        if not self.health_checks and not self.listeners:
            self._set_feature_status('health', 'unavailable', 'no health_checks or listeners configured',
                                     "set health_checks / listeners in config.json (see README)")

    def _collect_probes(self):
        """Collector (30s): repeat cheap availability and permission probes.

        A feature fixed mid-session (group add, chmod, new log file)
        recovers with no restart. Probes use only os.path, os.access,
        and shutil.which checks, plus at most one `wg show` call."""
        self._permissions = self._detect_permissions()
        self._sync_probe_feature_status()
        return True

    def _sync_probe_feature_status(self):
        """Refresh feature_status for probe-owned features from the new
        _permissions map."""
        p = self._permissions

        # Security logs
        if p.get('security') == 'ok':
            self._set_feature_status('security', 'ok')
        elif any(s == 'no_perm' for s in p.get('security_logs', {}).values()):
            self._set_feature_status('security', 'no_permission',
                                     'log files exist but are not readable',
                                     'sudo usermod -aG adm,syslog $USER  (then re-login)')
        else:
            self._set_feature_status('security', 'not_installed',
                                     'no auth.log / secure / syslog found')

        # Proxy logs
        if p.get('proxy') == 'ok':
            self._set_feature_status('proxy', 'ok')
        elif any(s == 'no_perm' for s in p.get('proxy_logs', {}).values()):
            self._set_feature_status('proxy', 'no_permission',
                                     'access log exists but is not readable',
                                     'sudo chmod o+r the proxy access log')
        else:
            self._set_feature_status('proxy', 'not_installed',
                                     'no nginx/caddy access log found')

        # RAPL energy
        rapl = p.get('rapl')
        if rapl == 'ok':
            self._set_feature_status('rapl', 'ok')
        elif rapl == 'no_perm':
            self._set_feature_status('rapl', 'no_permission',
                                     'RAPL energy_uj not readable',
                                     'sudo chmod 644 /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj')
        else:
            self._set_feature_status('rapl', 'not_installed',
                                     'no RAPL powercap sysfs on this machine')

        # Battery
        if p.get('battery') == 'ok':
            self._set_feature_status('battery', 'ok')
        else:
            self._set_feature_status('battery', 'not_installed',
                                     'no battery detected')

        # Temperature sensors
        if p.get('temperature') == 'ok':
            self._set_feature_status('temperature', 'ok')
        else:
            self._set_feature_status('temperature', 'not_installed',
                                     'no thermal_zone/hwmon sensors')

        # Wireless (info only: interface found, plus iwgetid for SSID)
        try:
            ifaces = os.listdir('/sys/class/net')
        except OSError:
            ifaces = []
        if any(n.startswith(('wl', 'wi')) for n in ifaces):
            if self._iwgetid_path:
                self._set_feature_status('wireless', 'ok')
            else:
                self._set_feature_status('wireless', 'not_installed',
                                         'wireless iface present but iwgetid missing',
                                         'install wireless-tools')
        else:
            self._set_feature_status('wireless', 'not_installed',
                                     'no wireless interface')

    def _detect_light_hardware(self):
        """Detect low-resource hardware (Raspberry Pi, low-RAM VPS). Use light defaults."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                cpuinfo = f.read()
            # Raspberry Pi 4
            if 'BCM2711' in cpuinfo or 'Raspberry Pi 4' in cpuinfo:
                return True
            # Read the device tree model
            model_path = Path('/sys/firmware/devicetree/base/model')
            if model_path.exists():
                model = model_path.read_text().strip('\x00')
                if 'Pi 4' in model or 'Raspberry Pi 4' in model:
                    return True
            # Treat under 1GB RAM as low-resource
            try:
                with open('/proc/meminfo', 'r') as f:
                    for line in f:
                        if line.startswith('MemTotal'):
                            mem_kb = int(line.split()[1])
                            if mem_kb < 1024 * 1024:  # Less than 1GB
                                return True
                            break
            except (OSError, ValueError, IndexError):
                pass
        except (OSError, UnicodeDecodeError):
            pass
        return False

    def _detect_permissions(self):
        """Detect which features are available. Return one status per feature.
        Status values: 'ok', 'no_perm', 'not_installed', 'disabled'.
        """
        perms = {}
        
        # Docker - check socket access
        docker_sock = '/var/run/docker.sock'
        if os.path.exists(docker_sock):
            if os.access(docker_sock, os.R_OK) or os.access(docker_sock, os.W_OK):
                perms['docker'] = 'ok'
            else:
                perms['docker'] = 'no_perm'
        else:
            perms['docker'] = 'not_installed'
        
        # Kubernetes: find kubectl (no call needed)
        kubectl_path = shutil.which('kubectl')
        if kubectl_path:
            perms['kubernetes'] = 'ok'
        else:
            perms['kubernetes'] = 'not_installed'
        
        # WireGuard: find the wg tool and check that it runs
        wg_path = shutil.which('wg')
        if wg_path:
            # Fast check with a short timeout. Dead sockets must not hang it.
            # Judge success by exit code (wg prints nothing when no
            # interface exists, and that still means a working setup).
            _out, rc = self.run_cmd_full([wg_path, 'show'], timeout=2, stderr=True)
            if rc == 0:
                perms['wireguard'] = 'ok'
            else:
                perms['wireguard'] = 'no_perm'
        else:
            perms['wireguard'] = 'not_installed'
        
        # RAPL energy: check that the path is readable
        if self.rapl_path and os.path.exists(self.rapl_path):
            if os.access(self.rapl_path, os.R_OK):
                perms['rapl'] = 'ok'
            else:
                perms['rapl'] = 'no_perm'
        else:
            perms['rapl'] = 'not_installed'
        
        # Security logs: check each log file
        log_status = {}
        has_any = False
        for log_name, log_path in self.security_logs.items():
            if os.path.exists(log_path):
                if os.access(log_path, os.R_OK):
                    log_status[log_name] = 'ok'
                    has_any = True
                else:
                    log_status[log_name] = 'no_perm'
            else:
                log_status[log_name] = 'not_found'
        perms['security_logs'] = log_status
        perms['security'] = 'ok' if has_any else 'no_perm'
        
        # Proxy logs: check each log file
        proxy_status = {}
        has_any_proxy = False
        for proxy_name, log_path in self.proxy_logs.items():
            if os.path.exists(log_path):
                if os.access(log_path, os.R_OK):
                    proxy_status[proxy_name] = 'ok'
                    has_any_proxy = True
                else:
                    proxy_status[proxy_name] = 'no_perm'
            else:
                proxy_status[proxy_name] = 'not_found'
        perms['proxy_logs'] = proxy_status
        perms['proxy'] = 'ok' if has_any_proxy else 'not_installed'
        
        # Battery - always readable (if exists)
        perms['battery'] = 'ok' if os.path.exists('/sys/class/power_supply/BAT0') else 'not_installed'
        
        # Temperature sensors: check that they are readable
        if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
            perms['temperature'] = 'ok'
        elif os.path.exists('/sys/class/hwmon'):
            perms['temperature'] = 'ok'
        else:
            perms['temperature'] = 'not_installed'
        
        return perms

    def get_permission_help(self):
        """Return permission fix commands for the user."""
        help_text = []
        if self._permissions.get('docker') == 'no_perm':
            help_text.append("Docker: sudo usermod -aG docker $USER  (then re-login)")
        if self._permissions.get('wireguard') == 'no_perm':
            help_text.append("WireGuard: sudo setcap cap_net_admin+ep $(which wg)  or  sudo visudo -> add NOPASSWD for wg")
        if self._permissions.get('rapl') == 'no_perm':
            help_text.append("RAPL: sudo chmod 644 /sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj")
        
        # Check security logs
        for log_name, status in self._permissions.get('security_logs', {}).items():
            if status == 'no_perm':
                help_text.append(f"Logs: sudo usermod -aG adm,syslog $USER  (for {log_name})")
                break
        
        return help_text

    def _detect_default_interface(self):
        """Find the default network interface from the routing table."""
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == '00000000':
                        return parts[0]
        except (OSError, IndexError):
            pass
        return None

    def _detect_rapl_path(self):
        """Find the RAPL energy path for power use."""
        rapl_paths = [
            '/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj',
            '/sys/class/powercap/intel-rapl:0/energy_uj',
            '/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0/energy_uj',
        ]
        for path in rapl_paths:
            if os.path.exists(path):
                return path
        # Check the AMD path
        amd_path = '/sys/class/powercap/amd-rapl/amd-rapl:0/energy_uj'
        if os.path.exists(amd_path):
            return amd_path
        return None

    def _get_cpu_model(self):
        """Read the CPU model name (cache it, call it once)."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        model = line.split(':', 1)[1].strip()
                        # Strip vendor suffixes
                        for remove in ['(R)', '(TM)', 'CPU', '  ']:
                            model = model.replace(remove, ' ' if remove == '  ' else '')
                        return ' '.join(model.split())[:40]
        except (OSError, IndexError):
            pass
        return "Unknown CPU"

    def run_cmd(self, cmd, timeout=2, stderr=False):
        """Run a command with no shell. Return stdout (return '' on failure).

        `cmd` must be an argv list. Split a plain string with shlex
        (never pass it to a shell). Set stderr=True to merge stderr
        into the output.
        """
        stdout, _rc = self.run_cmd_full(cmd, timeout=timeout, stderr=stderr)
        return stdout

    def run_cmd_full(self, cmd, timeout=2, stderr=False):
        """Act like run_cmd but return (stdout, returncode). Return -1 when
        the process fails to start or times out."""
        global _RUN_CMD_COUNT
        _RUN_CMD_COUNT += 1
        argv = cmd if isinstance(cmd, (list, tuple)) else shlex.split(cmd)
        try:
            result = subprocess.run(
                argv, shell=False, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT if stderr else subprocess.DEVNULL,
                text=True, timeout=timeout)
            return result.stdout.strip(), result.returncode
        except (OSError, subprocess.SubprocessError, ValueError):
            return "", -1

    def read_sys_file(self, path, cast=str):
        """Read a value from /sys. Cast it when `cast` is set."""
        try:
            with open(path, "r") as f:
                value = f.read().strip()
                return cast(value) if value and cast else value
        except (OSError, ValueError):
            return None

    def get_cpu_info(self):
        """Read CPU data with one /proc/stat read."""
        # Read /proc/stat once. Cache it for per-core use too
        proc_stat_lines = []
        try:
            with open('/proc/stat', 'r') as f:
                proc_stat_lines = f.readlines()
            self._proc_stat_cache = proc_stat_lines
            self._proc_stat_time = time.time()
            
            # Parse the first line (total CPU)
            line = proc_stat_lines[0]
            parts = line.split()[1:8]  # user, nice, system, idle, iowait, irq, softirq
            times = [int(x) for x in parts]
            idle = times[3] + times[4]  # idle + iowait
            total = sum(times)
            
            if self.last_cpu_times:
                idle_delta = idle - self.last_cpu_times['idle']
                total_delta = total - self.last_cpu_times['total']
                cpu_usage = 100.0 * (1.0 - idle_delta / total_delta) if total_delta > 0 else 0.0
            else:
                cpu_usage = 0.0
            
            self.last_cpu_times = {'idle': idle, 'total': total}
        except (OSError, ValueError, IndexError):
            cpu_usage = 0.0
        
        self.cpu_history.append(cpu_usage)

        # Read CPU temperature from hwmon (faster than the sensors command)
        cpu_temp = self._get_cpu_temp()

        # Read CPU frequency from /proc/cpuinfo
        cpu_freq = self._get_cpu_freq()

        # Read fan speed
        fan_rpm = self._get_fan_rpm()

        # Read governor and EPP from sysfs
        cpu_gov = self.read_sys_file('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor') or "N/A"
        cpu_epp = self.read_sys_file('/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference') or ""
        cpu_epp = cpu_epp.replace("balance_", "bal").replace("_", "-") if cpu_epp else "N/A"

        # Read load average from /proc/loadavg
        try:
            with open('/proc/loadavg', 'r') as f:
                loads = f.read().split()[:3]
                load_avg = [float(x) for x in loads]
        except (OSError, ValueError, IndexError):
            load_avg = [0.0, 0.0, 0.0]

        # Set CPU status from frequency
        cpu_status = "normal"
        if cpu_freq > 3.5:
            cpu_status = "high"
        elif cpu_freq < 1.5:
            cpu_status = "low"

        return {
            'usage': cpu_usage,
            'temp': cpu_temp,
            'freq': cpu_freq,
            'model': self.cpu_model,
            'gov': cpu_gov,
            'epp': cpu_epp,
            'cores': self.cpu_cores,
            'load': load_avg,
            'status': cpu_status,
            'fan_rpm': fan_rpm
        }

    def _get_per_core_usage(self):
        """Read per-core CPU use from cached /proc/stat data."""
        lines = self._proc_stat_cache if self._proc_stat_cache else []
        if not lines:
            return [0.0] * self.cpu_cores
        
        try:
            core_usages = []
            for line in lines[1:]:  # Skip first line (total)
                if not line.startswith('cpu'):
                    break
                parts = line.split()[1:8]
                times = [int(x) for x in parts]
                idle = times[3] + times[4]
                total = sum(times)
                
                core_id = len(core_usages)
                key = f'core_{core_id}'
                
                if hasattr(self, '_last_core_times') and key in self._last_core_times:
                    last = self._last_core_times[key]
                    idle_delta = idle - last['idle']
                    total_delta = total - last['total']
                    usage = 100.0 * (1.0 - idle_delta / total_delta) if total_delta > 0 else 0.0
                else:
                    usage = 0.0
                
                if not hasattr(self, '_last_core_times'):
                    self._last_core_times = {}
                self._last_core_times[key] = {'idle': idle, 'total': total}
                core_usages.append(usage)
            
            return core_usages
        except (ValueError, IndexError):
            return [0.0] * self.cpu_cores

    def _get_cpu_temp(self):
        """Read CPU temperature from hwmon sysfs (faster than sensors)."""
        # Try thermal zones first (they work on ARM, VMs, and containers)
        thermal_zone = Path('/sys/class/thermal/thermal_zone0/temp')
        if thermal_zone.exists():
            try:
                temp = int(thermal_zone.read_text().strip())
                return temp / 1000.0
            except (OSError, ValueError):
                pass
        
        hwmon_base = Path('/sys/class/hwmon')
        if not hwmon_base.exists():
            return 0.0
        
        try:
            for hwmon in hwmon_base.iterdir():
                name_file = hwmon / 'name'
                if name_file.exists():
                    name = name_file.read_text().strip()
                    # Find CPU thermal sensors (wider list)
                    if name in ('coretemp', 'k10temp', 'zenpower', 'acpitz', 'thinkpad', 
                                'cpu_thermal', 'soc_thermal', 'armada_thermal', 'rpi_thermal'):
                        # Read temp1_input first (package temperature), then the rest
                        for temp_file in ['temp1_input', 'temp2_input', 'temp3_input']:
                            temp_path = hwmon / temp_file
                            if temp_path.exists():
                                temp = int(temp_path.read_text().strip())
                                return temp / 1000.0  # Convert from millidegrees
                
                # Fallback: read any temp*_input in hwmon
                for temp_file in sorted(hwmon.glob('temp*_input')):
                    try:
                        temp = int(temp_file.read_text().strip())
                        if temp > 0:
                            return temp / 1000.0
                    except (OSError, ValueError):
                        continue
        except OSError:
            pass
        return 0.0

    def _get_cpu_freq(self):
        """Read mean CPU frequency from /proc/cpuinfo."""
        try:
            total_freq = 0.0
            count = 0
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('cpu MHz'):
                        freq = float(line.split(':')[1].strip())
                        total_freq += freq
                        count += 1
            return (total_freq / count / 1000.0) if count > 0 else 0.0  # Convert to GHz
        except (OSError, ValueError, IndexError):
            return 0.0

    def _get_fan_rpm(self):
        """Read fan speed from hwmon sysfs."""
        hwmon_base = Path('/sys/class/hwmon')
        if not hwmon_base.exists():
            return 0
        
        try:
            for hwmon in hwmon_base.iterdir():
                for fan_file in hwmon.glob('fan*_input'):
                    rpm = int(fan_file.read_text().strip())
                    if rpm > 0:
                        return rpm
        except (OSError, ValueError):
            pass
        return 0

    def get_memory_info(self):
        """Read memory use with a direct /proc/meminfo read."""
        try:
            meminfo = {}
            with open('/proc/meminfo', 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].rstrip(':')
                        value = int(parts[1])  # Value in kB
                        meminfo[key] = value
            
            total = meminfo.get('MemTotal', 0) // 1024  # Convert to MB
            available = meminfo.get('MemAvailable', 0) // 1024
            used = total - available
            percent = (used / total * 100) if total > 0 else 0
            
            self.mem_history.append(percent)
            return {
                'used': used,
                'total': total,
                'available': available,
                'percent': percent
            }
        except (OSError, ValueError, IndexError):
            return {'used': 0, 'total': 0, 'available': 0, 'percent': 0}

    def get_battery_info(self):
        """Read battery data."""
        base = "/sys/class/power_supply/BAT0"
        if not os.path.exists(base):
            return {'exists': False}

        def read(name, caster=str):
            return self.read_sys_file(os.path.join(base, name), caster)

        try:
            capacity = read("capacity", int) or 0
            status = read("status") or "Unknown"
            power_now = read("power_now", int) or read("current_now", int) or 0
            power_watts = (power_now / 1_000_000) if power_now else 0

            # Find whether charge_* or energy_* files exist
            full = read("charge_full", int)
            design = read("charge_full_design", int)
            capacity_mode = "charge" if full and design else "energy"
            if capacity_mode == "energy":
                full = read("energy_full", int)
                design = read("energy_full_design", int)

            def convert_capacity(value):
                if value is None:
                    return None
                if capacity_mode == "charge":
                    return value / 1000  # microAh -> mAh
                return value / 1_000_000  # microWh -> Wh

            full_capacity = convert_capacity(full)
            design_capacity = convert_capacity(design)
            health = ((full / design) * 100) if full and design else 0

            voltage = read("voltage_now", int)
            voltage_now = (voltage / 1_000_000) if voltage else None

            battery_info = {
                'exists': True,
                'level': capacity,
                'status': status,
                'power': power_watts,
                'health': health,
                'full_capacity': full_capacity,
                'design_capacity': design_capacity,
                'capacity_mode': 'mAh' if capacity_mode == 'charge' else 'Wh',
                'voltage': voltage_now,
                'technology': read("technology") or "",
                'model': read("model_name") or "",
                'vendor': read("manufacturer") or "",
                'serial': read("serial_number") or "",
                'cycle_count': read("cycle_count", int) or None
            }
            return battery_info
        except (OSError, ValueError, TypeError):
            return {'exists': False}

    def get_disk_usage(self):
        """Read disk use with os.statvfs only (no call). Docker volumes
        join in update_data() from the docker_df collector."""
        disks = []
        
        # Local mount points
        for mount in ['/', '/home']:
            try:
                if not os.path.exists(mount):
                    continue
                stat = os.statvfs(mount)
                total_bytes = stat.f_blocks * stat.f_frsize
                free_bytes = stat.f_bfree * stat.f_frsize
                used_bytes = total_bytes - free_bytes
                
                percent = int((used_bytes / total_bytes) * 100) if total_bytes > 0 else 0
                disks.append({
                    'mount': mount,
                    'used': _format_size(used_bytes),
                    'total': _format_size(total_bytes),
                    'percent': percent,
                    'type': 'disk'
                })
            except OSError:
                pass
        
        return disks

    def get_energy_info(self):
        """Read system energy use (RAPL for desktops, battery for laptops)."""
        energy = {
            'source': None,
            'power_watts': 0.0,
            'available': False
        }
        
        # Try RAPL first (it fits desktops and servers with Intel or AMD CPUs)
        if self.rapl_path and os.path.exists(self.rapl_path):
            try:
                current_energy = int(Path(self.rapl_path).read_text().strip())
                current_time = time.time()
                
                time_delta = current_time - self.last_rapl['time']
                if time_delta > 0 and self.last_rapl['energy'] > 0:
                    # Energy is in microjoules. Convert it to watts
                    energy_delta = current_energy - self.last_rapl['energy']
                    # Handle counter wrap
                    if energy_delta < 0:
                        energy_delta = current_energy
                    power_watts = (energy_delta / 1_000_000) / time_delta
                    energy['power_watts'] = power_watts
                    energy['available'] = True
                    energy['source'] = 'rapl'
                
                self.last_rapl = {'energy': current_energy, 'time': current_time}
                self.power_history.append(energy['power_watts'])
            except (OSError, ValueError, ZeroDivisionError):
                pass
        
        # With no RAPL, read battery power draw
        if not energy['available']:
            battery = self.get_battery_info()
            if battery.get('exists') and battery.get('power', 0) > 0:
                energy['power_watts'] = battery['power']
                energy['available'] = True
                energy['source'] = 'battery'
                self.power_history.append(energy['power_watts'])
        
        return energy

    def get_network_info(self):
        """Read network data with direct sysfs reads."""
        default_iface = self.default_iface
        vpn_connections = self.get_vpn_connections()

        # Read local IP from /proc/net/fib_trie, else use a socket
        local_ip = self._get_local_ip(default_iface)
        
        # Check WireGuard state
        wg_ip = self.read_sys_file('/sys/class/net/wg0/address') if os.path.exists('/sys/class/net/wg0') else None
        wg_active = os.path.exists('/sys/class/net/wg0')

        public_ip = getattr(self, '_public_ip_cache', "Checking...")

        current_time = time.time()
        rx_speed = tx_speed = 0
        rx_total = tx_total = 0
        
        if default_iface:
            # Read network counters direct from sysfs
            rx_bytes = self.read_sys_file(f'/sys/class/net/{default_iface}/statistics/rx_bytes', int) or 0
            tx_bytes = self.read_sys_file(f'/sys/class/net/{default_iface}/statistics/tx_bytes', int) or 0

            time_delta = current_time - self.last_net_bytes['time']
            if time_delta > 0 and self.last_net_bytes['rx'] > 0:
                rx_speed = max(0, (rx_bytes - self.last_net_bytes['rx']) / time_delta / 1024)
                tx_speed = max(0, (tx_bytes - self.last_net_bytes['tx']) / time_delta / 1024)

            self.rx_history.append(rx_speed)
            self.tx_history.append(tx_speed)

            self.last_net_bytes = {'rx': rx_bytes, 'tx': tx_bytes, 'time': current_time}
            rx_total = rx_bytes / (1024**3)
            tx_total = tx_bytes / (1024**3)

        # Read connection state from sysfs
        operstate = self.read_sys_file(f'/sys/class/net/{default_iface}/operstate') if default_iface else ""
        carrier = self.read_sys_file(f'/sys/class/net/{default_iface}/carrier') if default_iface else ""
        wired_connected = carrier == "1" if carrier else operstate == "up"
        link_speed_val = self.read_sys_file(f'/sys/class/net/{default_iface}/speed', int) if default_iface else None

        # Detect connection type
        conn_type = ""
        if default_iface:
            if default_iface.startswith(("en", "eth")):
                conn_type = "wired"
            elif default_iface.startswith(("wl", "wi")):
                conn_type = "wireless"
            else:
                conn_type = "virtual"

        # The SSID comes from the collector: iwgetid starts a call with
        # a 1s timeout, and get_network_info() runs inline on the render
        # path. So a call here stalled the UI once per refresh.
        ssid = self._collector_result('ssid') or ""

        connected_peers = sum(1 for peer in vpn_connections if peer.get('connected'))
        total_peers = len(vpn_connections)
        wg_peers = total_peers if total_peers else (1 if wg_active else 0)
        wg_peers_connected = connected_peers if total_peers else (1 if wg_active else 0)

        return {
            'interface': default_iface,
            'local_ip': local_ip,
            'public_ip': public_ip,
            'wg_active': wg_active,
            'wg_ip': wg_ip,
            'wg_peers': wg_peers,
            'rx_speed': rx_speed,
            'tx_speed': tx_speed,
            'rx_total': rx_total,
            'tx_total': tx_total,
            'operstate': operstate,
            'wired_connected': wired_connected,
            'link_speed': link_speed_val,
            'connection_type': conn_type,
            'ssid': ssid,
            'vpn_connections': vpn_connections,
            'vpn_warning': "permission" if self.wg_permission_denied else "",
            'wg_peers_connected': wg_peers_connected
        }

    def _get_local_ip(self, iface):
        """Find the local IP address for one interface. Cache it. Make no call
        to an outside network."""
        if not iface:
            return "N/A"
        
        # Cache the local IP (it rarely changes)
        current_time = time.time()
        if hasattr(self, '_cached_local_ip') and hasattr(self, '_cached_local_ip_time'):
            if current_time - self._cached_local_ip_time < 30:
                return self._cached_local_ip
        
        try:
            # Read from /proc/net/dev or use a socket (cached)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)  # 1 second timeout to prevent hanging
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            self._cached_local_ip = ip
            self._cached_local_ip_time = current_time
            return ip
        except OSError:
            self._cached_local_ip = "N/A"
            self._cached_local_ip_time = current_time
            return "N/A"

    def get_vpn_connections(self):
        """Return the latest WireGuard peers from the collector. Never wait
        and never start a call on the UI thread."""
        return self._collector_result('wireguard') or []

    def _collect_wireguard(self):
        """Collector (10s): read WireGuard peers with fast numbers."""
        wg_path = shutil.which('wg')
        if not wg_path:
            self._permissions['wireguard'] = 'not_installed'
            self._set_feature_status('wireguard', 'not_installed',
                                     'wg binary not found in PATH',
                                     'install wireguard-tools')
            return []

        dump, permission_denied = self._wireguard_dump(wg_path)
        self.wg_permission_denied = permission_denied and not dump
        if permission_denied and not dump:
            self._permissions['wireguard'] = 'no_perm'
            self._set_feature_status('wireguard', 'no_permission',
                                     'wg show requires elevated privileges',
                                     'sudo setcap cap_net_admin+ep $(which wg)  or  NOPASSWD sudoers entry for wg')
            return []
        self._permissions['wireguard'] = 'ok'
        self._set_feature_status('wireguard', 'ok')

        connections = []
        if not dump:
            return connections

        iface_ports = {}
        now = time.time()

        for line in dump.splitlines():
            if not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) == 5:
                iface_ports[parts[0]] = parts[3]
                continue
            if len(parts) < 9:
                continue

            iface = parts[0]
            endpoint = parts[3] if parts[3] != "(none)" else ""
            allowed_ips = parts[4]

            def safe_int(value):
                try:
                    return int(value)
                except (ValueError, TypeError):
                    return 0

            handshake = safe_int(parts[5])
            rx = safe_int(parts[6])
            tx = safe_int(parts[7])
            keepalive = parts[8] if len(parts) > 8 else ""

            handshake_age = (now - handshake) if handshake else None
            connected = handshake_age is not None and handshake_age < 180
            
            # Format handshake age as a latency value
            if handshake_age is not None:
                if handshake_age < 60:
                    latency = f"{int(handshake_age)}s"
                elif handshake_age < 3600:
                    latency = f"{int(handshake_age // 60)}m"
                else:
                    latency = f"{int(handshake_age // 3600)}h"
            else:
                latency = ""

            connections.append({
                'interface': iface,
                'endpoint': endpoint or "N/A",
                'allowed_ips': allowed_ips,
                'handshake_age': handshake_age,
                'connected': connected,
                'rx': rx,
                'tx': tx,
                'keepalive': keepalive,
                'port': iface_ports.get(iface),
                'latency': latency
            })
        return connections

    def _wireguard_dump(self, wg_path):
        """Return raw 'wg show all dump' output (argv list, no shell). Try
        sudo -n when plain wg fails."""
        commands = [[wg_path, 'show', 'all', 'dump']]
        sudo_path = shutil.which('sudo')
        if sudo_path:
            commands.append([sudo_path, '-n', wg_path, 'show', 'all', 'dump'])
        permission_seen = False
        for cmd in commands:
            output = self.run_cmd(cmd, timeout=3, stderr=True)
            if not output:
                continue
            lower = output.lower()
            if "operation not permitted" in lower or "permission denied" in lower or "password is required" in lower:
                permission_seen = True
                continue
            return output, False
        return "", permission_seen

    def _collect_ssid(self):
        """Collector (60s): read WiFi SSID with iwgetid.

        iwgetid starts a call with a 1s timeout. get_network_info() runs
        inline on the render path. So the old inline call stalled the UI
        once per refresh. The SSID changes only on roam or reconnect.
        So 60s is enough.
        """
        if not self._iwgetid_path:
            return ""
        iface = self._detect_default_interface()
        if not iface or not iface.startswith(("wl", "wi")):
            return ""
        return self.run_cmd([self._iwgetid_path, '-r'], timeout=1)

    def _collect_public_ip(self):
        """Collector (300s): read public IP with urllib (no call)."""
        if not self.config.get('public_ip_check', True):
            self._public_ip_cache = "N/A"
            self._set_feature_status('public_ip', 'unavailable',
                                     'disabled in config (public_ip_check: false)')
            return "N/A"
        # Late import: urllib.request adds ~2MB RSS. Only this collector
        # and the update check need it.
        import urllib.request
        import urllib.error
        for url in ('https://ifconfig.me', 'https://icanhazip.com'):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'curl/8.0'})
                with urllib.request.urlopen(req, timeout=3) as resp:
                    ip = resp.read(64).decode('ascii', 'replace').strip()
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    self._public_ip_cache = ip
                    self._set_feature_status('public_ip', 'ok')
                    return ip
            except (OSError, ValueError, urllib.error.URLError):
                continue
        self._public_ip_cache = "N/A"
        self._set_feature_status('public_ip', 'error',
                                 'all public-IP endpoints unreachable')
        return "N/A"

    def get_processes(self):
        """Return the latest process summary from the collector. Never wait."""
        result = self._collector_result('processes')
        if result is None:
            return {'total': 0, 'top_cpu': '', 'top_mem': ''}
        return result

    def _collect_processes(self):
        """Collector (5s): scan /proc/<pid>/stat only.

        Take RSS from stat field 24 (pages). Skip the old scan of
        /proc/<pid>/status lines.
        """
        try:
            pids = [d for d in os.listdir('/proc') if d.isdigit()]
        except OSError:
            pids = []
        total = len(pids)

        current_time = time.time()
        prev_cpu_map = getattr(self, '_prev_proc_cpu', {})
        prev_time = getattr(self, '_prev_proc_time', None)
        interval = (current_time - prev_time) if prev_time else 0

        try:
            ticks_per_sec = os.sysconf('SC_CLK_TCK')
            page_size = os.sysconf('SC_PAGE_SIZE')
        except (ValueError, OSError, AttributeError):
            ticks_per_sec = 100
            page_size = 4096
        if ticks_per_sec <= 0:
            ticks_per_sec = 100
        if page_size <= 0:
            page_size = 4096

        top_cpu_name = ""
        top_cpu_delta = 0
        top_mem_name = ""
        top_mem_kb = 0
        current_cpu = {}

        for pid_str in pids:
            try:
                with open(f'/proc/{pid_str}/stat', 'r') as f:
                    stat = f.read().strip()
            except OSError:
                continue  # process vanished between listdir and read

            try:
                # Shape: "pid (comm) state utime stime ... rss ..."
                # comm can hold spaces and parens. Fields after the last
                # ')' start at field 3 (state).
                rparen = stat.rfind(')')
                lparen = stat.find('(')
                if lparen == -1 or rparen <= lparen:
                    continue
                comm = stat[lparen + 1:rparen]
                parts = stat[rparen + 2:].split()
                utime = int(parts[11])       # field 14
                stime = int(parts[12])       # field 15
                rss_pages = int(parts[21])   # field 24
            except (ValueError, IndexError):
                continue  # short read / PID reused mid-parse

            total_cpu = utime + stime
            current_cpu[pid_str] = total_cpu

            prev = prev_cpu_map.get(pid_str)
            if prev is not None:
                delta = total_cpu - prev
                if delta > top_cpu_delta:
                    top_cpu_delta = delta
                    top_cpu_name = comm

            mem_kb = (rss_pages * page_size) // 1024
            if mem_kb > top_mem_kb:
                top_mem_kb = mem_kb
                top_mem_name = comm

        # Save current CPU times for the next delta math
        self._prev_proc_cpu = current_cpu
        self._prev_proc_time = current_time

        if interval > 0:
            cpu_pct = (top_cpu_delta / ticks_per_sec / interval) * 100
        else:
            cpu_pct = 0.0

        def shorten(s, max_len=22):
            if not s or len(s) <= max_len:
                return s
            return s[:max_len-1] + "…"

        return {
            'total': total,
            'top_cpu': f"{shorten(top_cpu_name)} {cpu_pct:.1f}%" if top_cpu_name else "",
            'top_mem': f"{shorten(top_mem_name)} {top_mem_kb / 1024:.1f}M" if top_mem_name else "",
        }

    def get_docker_info(self):
        """Return the latest Docker data from the collector. Never wait."""
        result = self._collector_result('docker')
        if result is None:
            return {'available': False, 'running': 0, 'stopped': 0,
                    'total': 0, 'containers': []}
        return result

    def _get_docker_client(self):
        """Create the shared Docker API client at first use. Raise DockerError."""
        if self._docker_client is None:
            self._docker_client = DockerClient(timeout=2)
        return self._docker_client

    def _collect_docker(self):
        """Collector (5s): read containers with CPU and mem through the socket."""
        result = {'available': False, 'running': 0, 'stopped': 0,
                  'total': 0, 'containers': []}
        try:
            client = self._get_docker_client()
            data = client.containers()
        except DockerError as e:
            self._docker_available = False
            self._apply_feature_perm('docker', e.state)
            fix = ''
            if e.state == 'no_permission':
                fix = 'sudo usermod -aG docker $USER  (then re-login)'
            elif e.state == 'socket_missing':
                fix = 'start the docker daemon / check /var/run/docker.sock'
            self._set_feature_status('docker', e.state, e.detail, fix)
            return result
        result.update(data)
        result['available'] = True
        self._docker_available = True
        self._apply_feature_perm('docker', 'ok')
        self._set_feature_status('docker', 'ok')
        return result

    def _collect_docker_df(self):
        """Collector (30s): read Docker volume sizes through the socket."""
        try:
            client = self._get_docker_client()
            return client.disk_usage_volumes()
        except DockerError:
            return []

    def _collect_health(self):
        """Collector (30s): check service health. Probe HTTP per container
        name and check each TCP listener.

        Run all work on this thread with short timeouts. Use stdlib only
        (urllib for HTTP, socket for TCP). Map each entry to one state:
        'healthy' (right status), 'down' (wrong status, refused, timeout,
        or bad configuration), or 'unconfigured' (no check matches it).
        update_data() merges the per-container map into the Docker data.
        Listeners land under their own 'health' key.
        """
        import urllib.request
        import urllib.error
        checks = self.health_checks if isinstance(self.health_checks, dict) else {}
        ports = self.listeners if isinstance(self.listeners, list) else []
        per_container = {}
        for name, spec in checks.items():
            if not isinstance(spec, dict):
                per_container[name] = {'state': 'down', 'detail': 'not a {url, expect} object'}
                continue
            url = spec.get('url', '')
            try:
                expect = int(spec.get('expect', 200))
            except (TypeError, ValueError):
                per_container[name] = {'state': 'down', 'detail': 'bad expect status'}
                continue
            if not isinstance(url, str) or not url.startswith(('http://', 'https://')):
                per_container[name] = {'state': 'down', 'detail': 'bad url (need http:// or https://)'}
                continue
            try:
                req = urllib.request.Request(url, headers={'User-Agent': f'sentinel/{VERSION}'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    status = resp.status
            except (OSError, ValueError, urllib.error.URLError) as e:
                per_container[name] = {'state': 'down', 'detail': str(e)[:60] or 'unreachable'}
                continue
            if status == expect:
                per_container[name] = {'state': 'healthy', 'detail': f'{status}'}
            else:
                per_container[name] = {'state': 'down', 'detail': f'got {status}, want {expect}'}
        listeners = {}
        for port in ports:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            key = str(port)
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=3):
                    listeners[key] = {'state': 'healthy', 'detail': 'open'}
            except (OSError, OverflowError, ValueError) as e:
                listeners[key] = {'state': 'down', 'detail': (str(e)[:60] or 'closed')}
        healthy = sum(1 for v in per_container.values() if v['state'] == 'healthy')
        down = sum(1 for v in per_container.values() if v['state'] == 'down')
        healthy += sum(1 for v in listeners.values() if v['state'] == 'healthy')
        down += sum(1 for v in listeners.values() if v['state'] == 'down')
        if down:
            self._set_feature_status('health', 'error', f'{down} check(s) down',
                                     'curl the failing url / check the port is listening')
        elif healthy:
            self._set_feature_status('health', 'ok')
        else:
            self._set_feature_status('health', 'unavailable', 'no health_checks or listeners configured',
                                     "set health_checks / listeners in config.json (see README)")
        return {'containers': per_container, 'listeners': listeners,
                'healthy': healthy, 'down': down}


    def get_kubernetes_info(self):
        """Return the latest Kubernetes data from the collector. Never wait."""
        result = self._collector_result('kubernetes')
        if result is None:
            return {'available': False, 'nodes': 0, 'nodes_ready': 0,
                    'pods_running': 0, 'pods_pending': 0, 'pods_failed': 0,
                    'pods': [], 'context': ''}
        return result

    def _collect_kubernetes(self):
        """Collector (15s): read kubectl node and pod data. kubectl stays a
        call (kubeconfig auth has no stdlib path). It runs off-thread with
        argv lists and a 5s timeout. With kubectl missing it starts no call."""
        result = {
            'available': False,
            'nodes': 0,
            'nodes_ready': 0,
            'pods_running': 0,
            'pods_pending': 0,
            'pods_failed': 0,
            'pods': [],
            'context': ''
        }

        kubectl_path = shutil.which('kubectl')
        if not kubectl_path:
            self._kubectl_available = False
            self._apply_feature_perm('kubernetes', 'not_installed')
            self._set_feature_status('kubernetes', 'not_installed',
                                     'kubectl not found in PATH',
                                     'install kubectl')
            return result
        self._kubectl_available = True

        # Read current context
        context = self.run_cmd([kubectl_path, 'config', 'current-context'],
                               timeout=5, stderr=True)
        if not context or "error" in context.lower():
            self._apply_feature_perm('kubernetes', 'ok')
            self._set_feature_status('kubernetes', 'error',
                                     'no current context or cluster unreachable',
                                     'kubectl config use-context <name>')
            return result

        result['available'] = True
        result['context'] = context.split('\n')[0][:20]
        self._apply_feature_perm('kubernetes', 'ok')
        self._set_feature_status('kubernetes', 'ok')

        # Read node status
        nodes_output = self.run_cmd([kubectl_path, 'get', 'nodes', '--no-headers'],
                                    timeout=5)
        if nodes_output:
            for line in nodes_output.strip().split('\n'):
                if line:
                    result['nodes'] += 1
                    if 'Ready' in line and 'NotReady' not in line:
                        result['nodes_ready'] += 1

        # Read pod status (all namespaces, first 50 lines)
        pods_output = self.run_cmd([kubectl_path, 'get', 'pods', '-A', '--no-headers'],
                                   timeout=5)
        if pods_output:
            pods = []
            for line in pods_output.strip().split('\n')[:50]:
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    namespace = parts[0][:10]
                    name = parts[1][:25]
                    ready = parts[2]
                    status = parts[3]

                    if status == 'Running':
                        result['pods_running'] += 1
                    elif status == 'Pending':
                        result['pods_pending'] += 1
                    elif status in ('Failed', 'Error', 'CrashLoopBackOff'):
                        result['pods_failed'] += 1

                    # Parse the ready count
                    ready_count = 0
                    total_count = 0
                    if '/' in ready:
                        try:
                            ready_count, total_count = map(int, ready.split('/'))
                        except ValueError:
                            pass

                    pods.append({
                        'namespace': namespace,
                        'name': name,
                        'ready': ready,
                        'status': status,
                        'ready_count': ready_count,
                        'total_count': total_count
                    })

            # Sort failed first, then pending, then by name
            result['pods'] = sorted(pods, key=lambda x: (
                x['status'] == 'Running',
                x['status'] != 'Failed',
                x['name']
            ))[:10]

        return result

    def get_uptime(self):
        """Count system uptime with a direct /proc read."""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            uptime = timedelta(seconds=int(uptime_seconds))
            return uptime.days, uptime.seconds // 3600, (uptime.seconds % 3600) // 60
        except (OSError, ValueError, IndexError):
            return 0, 0, 0

    def _read_log_tail(self, log_path, max_lines=100):
        """Read the last N lines of a log file. Seek from the end.
        This is much faster than a full read, above all for large logs."""
        try:
            if not os.path.exists(log_path) or not os.access(log_path, os.R_OK):
                return []
            
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                # Seek near the end to skip most of a large log
                try:
                    f.seek(0, 2)  # Seek to end
                    size = f.tell()
                    # Need: ~256 bytes per line times max_lines, plus margin
                    buf_size = min(32768, size)  # Read up to 32KB from end
                    if size > buf_size:
                        f.seek(-buf_size, 2)
                    else:
                        f.seek(0)
                    
                    raw = f.read()
                    lines = raw.split('\n')
                    # A seek past 0 leaves a cut first line. Drop it
                    if size > buf_size and len(lines) > 1:
                        lines = lines[1:]
                    # Keep the last max_lines only
                    return lines[-max_lines:] if len(lines) > max_lines else lines
                except OSError:
                    # Fallback: read from the start (for tiny files or errors)
                    f.seek(0)
                    lines = []
                    for line in f:
                        lines.append(line.rstrip('\n'))
                        if len(lines) > max_lines * 2:
                            lines = lines[-max_lines:]
                    return lines[-max_lines:] if len(lines) > max_lines else lines
        except OSError:
            return []

    def get_proxy_stats(self):
        """Read reverse proxy traffic numbers from nginx and caddy access logs."""
        current_time = time.time()
        
        # Check at most every 10 seconds (light mode used 5s before)
        check_interval = 10 if self._light_mode else 5
        if current_time - self._last_proxy_check < check_interval:
            return self._proxy_stats
        
        self._last_proxy_check = current_time
        stats = {'requests': 0, 'bytes': 0, 'rps': 0.0, 'source': None}
        
        # Quit early when the proxy panel has no read rights
        if self._permissions.get('proxy') == 'not_installed':
            self._proxy_stats = stats
            return stats
        
        # Read nginx first, then caddy
        for proxy_name, log_path in self.proxy_logs.items():
            log_status = self._permissions.get('proxy_logs', {}).get(proxy_name, 'not_found')
            if log_status != 'ok':
                continue
            
            try:
                lines = self._read_log_tail(log_path, max_lines=100)
                if not lines:
                    continue
                
                recent_count = 0
                total_bytes = 0
                
                for line in lines:
                    try:
                        parts = line.split()
                        if len(parts) >= 10:
                            bytes_str = parts[9] if parts[9].isdigit() else parts[-1]
                            if bytes_str.isdigit():
                                total_bytes += int(bytes_str)
                        recent_count += 1
                    except (ValueError, IndexError):
                        recent_count += 1
                
                if recent_count > 0:
                    stats['requests'] = recent_count
                    stats['bytes'] = total_bytes
                    stats['rps'] = recent_count / 60.0
                    stats['source'] = proxy_name
                    break
                    
            except OSError:
                pass
        
        self._proxy_stats = stats
        self.proxy_history.append(stats.get('rps', 0) * 10)
        return stats

    def _collect_update_check(self):
        """Collector (86400s, 604800s in light mode): ask GitHub for a new
        version with urllib (no call). Fetch at most once per interval."""
        github_raw = "https://raw.githubusercontent.com/VidGuiCode/sentinel/main/sentinel-monitor.py"
        import urllib.request  # deferred; see _collect_public_ip
        import urllib.error
        try:
            req = urllib.request.Request(github_raw, headers={'User-Agent': f'sentinel/{VERSION}'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                head = resp.read(8192).decode('utf-8', 'replace')
        except (OSError, ValueError, urllib.error.URLError):
            self._update_available = False
            self._set_feature_status('update_check', 'error',
                                     'update check fetch failed (offline?)')
            return self._update_available

        remote_version = None
        for line in head.splitlines():
            if line.startswith('VERSION = '):
                parts = line.split('"')
                if len(parts) >= 2:
                    remote_version = parts[1]
                break

        self._set_feature_status('update_check', 'ok')

        if remote_version and remote_version != VERSION:
            try:
                remote_parts = [int(x) for x in remote_version.split('.')]
                current_parts = [int(x) for x in VERSION.split('.')]
                self._update_available = remote_version if remote_parts > current_parts else False
            except ValueError:
                self._update_available = False
        else:
            self._update_available = False

        return self._update_available

    def get_security_logs(self):
        """Read security events from system logs with a direct file read."""
        current_time = time.time()

        # Check at most every 5 seconds
        if current_time - self._last_security_check < 5:
            return self._security_cache

        self._last_security_check = current_time

        # Build regex objects once (fast path)
        if not self._compiled_regex:
            self._compiled_regex = {
                'invalid_user': re.compile(r'Invalid user (\S+) from ([\d.]+)'),
                'failed_password': re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)'),
                'connection_closed': re.compile(r'Connection closed by invalid user'),
                'accepted_key': re.compile(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)'),
            }

        stats = {
            'available': False,
            'total_parsed': 0,
            'total_unparsed': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'failed_ratio': 0.0,
            'top_ips': {},
            'top_users': {},
            'error_types': {},
            'recent_events': [],
            'alerts': [],
        }

        # Drop old events (older than 5 minutes)
        cutoff_time = current_time - self.security_alerts_config['failed_login_window']
        self._security_events = [e for e in self._security_events if e['timestamp'] > cutoff_time]

        # Drop old IP failure records
        for ip in list(self._ip_failure_tracker.keys()):
            self._ip_failure_tracker[ip] = [t for t in self._ip_failure_tracker[ip] if t > cutoff_time]
            if not self._ip_failure_tracker[ip]:
                del self._ip_failure_tracker[ip]

        # Quit early when the security panel has no read rights
        if self._permissions.get('security') == 'no_perm':
            self._security_cache = stats
            return stats

        # Read auth.log first (Debian and Ubuntu), then secure (RHEL and
        # CentOS), then syslog. Light mode reads fewer lines (fast path)
        max_lines = 200 if self._light_mode else 1000
        
        for log_name, log_path in self.security_logs.items():
            log_status = self._permissions.get('security_logs', {}).get(log_name, 'not_found')
            if log_status != 'ok':
                continue

            try:
                lines = self._read_log_tail(log_path, max_lines=max_lines)
                if not lines:
                    continue

                stats['available'] = True

                for line in lines:
                    if not line.strip():
                        continue

                    stats['total_parsed'] += 1

                    invalid_match = self._compiled_regex['invalid_user'].search(line)
                    if invalid_match:
                        username, ip = invalid_match.groups()
                        stats['failed_logins'] += 1
                        stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
                        stats['top_users'][username] = stats['top_users'].get(username, 0) + 1
                        stats['error_types']['Invalid user attempt'] = stats['error_types'].get('Invalid user attempt', 0) + 1

                        if ip not in self._ip_failure_tracker:
                            self._ip_failure_tracker[ip] = []
                        self._ip_failure_tracker[ip].append(current_time)

                        event = {
                            'timestamp': current_time,
                            'type': 'failed_login',
                            'user': username,
                            'ip': ip,
                        }
                        self._security_events.append(event)
                        continue

                    failed_match = self._compiled_regex['failed_password'].search(line)
                    if failed_match:
                        username, ip = failed_match.groups()
                        stats['failed_logins'] += 1
                        stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
                        stats['top_users'][username] = stats['top_users'].get(username, 0) + 1
                        stats['error_types']['Failed password'] = stats['error_types'].get('Failed password', 0) + 1

                        if ip not in self._ip_failure_tracker:
                            self._ip_failure_tracker[ip] = []
                        self._ip_failure_tracker[ip].append(current_time)
                        continue

                    if self._compiled_regex['connection_closed'].search(line):
                        stats['error_types']['Connection closed (invalid user)'] = stats['error_types'].get('Connection closed (invalid user)', 0) + 1
                        continue

                    success_match = self._compiled_regex['accepted_key'].search(line)
                    if success_match:
                        username, ip = success_match.groups()
                        stats['successful_logins'] += 1
                        stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
                        continue

                # Count failed against successful logins
                total_logins = stats['failed_logins'] + stats['successful_logins']
                if total_logins > 0:
                    stats['failed_ratio'] = stats['failed_logins'] / total_logins

                # Keep the top 10 IPs and users only
                stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
                stats['top_users'] = dict(sorted(stats['top_users'].items(), key=lambda x: x[1], reverse=True)[:10])

                # Keep the last 5 events only
                stats['recent_events'] = stats['recent_events'][-5:]

                # Find alert states
                for ip, timestamps in self._ip_failure_tracker.items():
                    if len(timestamps) >= self.security_alerts_config['failed_login_threshold']:
                        stats['alerts'].append({
                            'type': 'brute_force',
                            'message': f'Possible brute force from {ip} ({len(timestamps)} attempts)',
                            'severity': 'danger'
                        })

                # Alert 2: many errors in the last minute
                recent_errors = sum(1 for e in self._security_events
                                   if e['timestamp'] > current_time - self.security_alerts_config['error_rate_window']
                                   and e['type'] == 'failed_login')
                if recent_errors >= self.security_alerts_config['error_rate_threshold']:
                    stats['alerts'].append({
                        'type': 'high_error_rate',
                        'message': f'{recent_errors} failed logins in 1 min',
                        'severity': 'warning'
                    })

                break  # Successfully parsed a log file

            except Exception as e:
                stats['total_unparsed'] += 1
                pass

        # Feed history for graphs
        self.failed_login_history.append(stats['failed_logins'])
        self.suspicious_ip_history.append(len([ip for ip, count in stats['top_ips'].items() if count >= 3]))

        self._security_cache = stats
        return stats

    def draw_loading_modal(self, stdscr, h, w, message="Loading..."):
        """Draw a centered loading overlay."""
        modal_w = max(len(message) + 6, 24)
        modal_h = 5
        
        start_y = (h - modal_h) // 2
        start_x = (w - modal_w) // 2
        
        try:
            # Draw the box
            border = curses.color_pair(1)
            fill = curses.color_pair(8)
            
            # Draw the top edge of the loading box
            stdscr.addstr(start_y, start_x, "╭" + "─" * (modal_w - 2) + "╮", border)
            
            # Draw the middle rows
            for i in range(1, modal_h - 1):
                stdscr.addstr(start_y + i, start_x, "│", border)
                stdscr.addstr(start_y + i, start_x + 1, " " * (modal_w - 2), fill)
                stdscr.addstr(start_y + i, start_x + modal_w - 1, "│", border)
            
            # Draw the bottom edge
            stdscr.addstr(start_y + modal_h - 1, start_x, "╰" + "─" * (modal_w - 2) + "╯", border)
            
            # Draw the spinner frame
            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spin_char = spinner[int(time.time() * 10) % len(spinner)]
            
            # Draw the message
            msg_x = start_x + (modal_w - len(message) - 2) // 2
            stdscr.addstr(start_y + 2, msg_x, f"{spin_char} {message}", curses.color_pair(7) | curses.A_BOLD)
            
        except curses.error:
            pass

    def draw_help_modal(self, stdscr, h, w):
        """Draw the help overlay with keys and permission states."""
        help_lines = [
            "╭────────────── HELP ──────────────╮",
            "│                                  │",
            "│  q      Quit                     │",
            "│  r      Refresh now              │",
            "│  t      Cycle themes             │",
            "│  l      Cycle layouts            │",
            "│  i      Refresh public IP        │",
            "│  h      Toggle this help         │",
            "│  d      Diagnostics / Permissions│",
            "│  +/-    Adjust refresh rate      │",
            "│                                  │",
            "│  Layouts: default, cpu, network, │",
            "│    docker, security, minimal     │",
            "│                                  │",
            "╰──────────────────────────────────╯",
        ]
        
        modal_h = len(help_lines)
        modal_w = len(help_lines[0])
        start_y = (h - modal_h) // 2
        start_x = (w - modal_w) // 2
        
        try:
            for i, line in enumerate(help_lines):
                if start_y + i >= h:
                    break
                # Cut the line to terminal width
                if start_x + len(line) > w:
                    line = line[:max(0, w - start_x - 1)]
                if len(line) > 0 and start_x < w - 1:
                    stdscr.addstr(start_y + i, start_x, line, curses.color_pair(1))
        except curses.error:
            pass

    # Status text per panel. Full detail and fix commands live in the
    # diagnostics overlay. These lines answer "why is this panel empty".
    _STATE_LABELS = {
        'no_permission': 'no permission',
        'error': 'failed',
        'socket_missing': 'socket missing',
        'unsupported_host': 'unsupported host',
        'unavailable': 'disabled',
        'not_installed': 'not installed',
    }
    # States the user can act on come first.
    _STATE_ORDER = {'no_permission': 0, 'error': 1, 'socket_missing': 2,
                    'unsupported_host': 3, 'unavailable': 4, 'not_installed': 5}

    def _degraded_notes(self, features):
        """Return [(text, color_pair)] for each feature in `features` that
        is not ok.

        Panels once drew nothing when a feature was missing. So "no
        permission" looked the same as "nothing to show". Sort states
        the user can act on first. Draw them in red. The diagnostics
        overlay holds the fix command.
        """
        notes = []
        for label, key in features:
            state = self.feature_status.get(key, {}).get('state', 'not_installed')
            if state == 'ok':
                continue
            color = 4 if state in ('no_permission', 'error') else 8
            notes.append((self._STATE_ORDER.get(state, 9),
                          f"{label}: {self._STATE_LABELS.get(state, state)}",
                          color))
        notes.sort(key=lambda n: n[0])
        return [(text, color) for _order, text, color in notes]

    def draw_diagnostics_modal(self, stdscr, h, w):
        """Draw the diagnostics overlay: live view of the feature_status map
        (state, detail, and fix hint per degradable feature)."""
        features = [
            ('Docker', 'docker'),
            ('Kubernetes', 'kubernetes'),
            ('WireGuard', 'wireguard'),
            ('Security Logs', 'security'),
            ('Proxy Logs', 'proxy'),
            ('Service Health', 'health'),
            ('RAPL Energy', 'rapl'),
            ('Battery', 'battery'),
            ('Temperature', 'temperature'),
            ('Wireless', 'wireless'),
            ('Public IP', 'public_ip'),
            ('Update Check', 'update_check'),
        ]

        state_map = {
            'ok': ('✓', 2),
            'no_permission': ('✗', 4),
            'error': ('!', 4),
            'not_installed': ('-', 8),
            'unavailable': ('~', 8),
            'socket_missing': ('○', 8),
            'unsupported_host': ('~', 8),
        }

        # Build rows as (text, color_pair). Add box edges below
        rows = []
        for name, key in features:
            entry = self.feature_status.get(key, {})
            state = entry.get('state', 'not_installed')
            icon, color = state_map.get(state, ('?', 8))
            rows.append((f"{icon} {name:14} {state.replace('_', ' ')}", color))
            if state != 'ok':
                detail = entry.get('detail') or ''
                fix = entry.get('fix') or ''
                if detail:
                    rows.append((f"    {detail}", 8))
                if fix:
                    rows.append((f"    fix: {fix}", 3))

        # A configuration file that fails to parse shows here too. Then
        # "my value does nothing" has a visible cause.
        config_error = self.config.get('_config_error')
        if config_error:
            rows.append(("! config file    failed to load", 4))
            rows.append((f"    {config_error}", 8))
            rows.append(("    fix: validate the JSON, or delete it to "
                         "fall back to defaults", 3))

        content_w = max(len(text) for text, _c in rows) if rows else 20
        content_w = min(content_w + 2, max(20, w - 6))
        modal_w = content_w + 2
        modal_h = len(rows) + 4
        start_y = max(0, (h - modal_h) // 2)
        start_x = max(0, (w - modal_w) // 2)

        try:
            # Draw the top edge with title
            title = " DIAGNOSTICS "
            stdscr.addstr(start_y, start_x, "╭" + title
                          + "─" * max(0, modal_w - 2 - len(title)) + "╮",
                          curses.color_pair(1))
            # Draw content rows
            for i, (text, color) in enumerate(rows):
                row_y = start_y + 1 + i
                if row_y >= h - 1:
                    break
                # Keep one column free at left. Then a full-width row
                # cannot cross the right edge.
                text = text[:content_w - 1]
                stdscr.addstr(row_y, start_x, "│", curses.color_pair(1))
                stdscr.addstr(row_y, start_x + 1,
                              " " + text + " " * max(0, content_w - len(text) - 1),
                              curses.color_pair(color))
                if start_x + modal_w - 1 < w:
                    stdscr.addstr(row_y, start_x + modal_w - 1, "│",
                                  curses.color_pair(1))
            # Draw the footer
            foot_y = start_y + len(rows) + 1
            if foot_y < h:
                stdscr.addstr(foot_y, start_x, "│" + " " * (modal_w - 2) + "│",
                              curses.color_pair(1))
            if foot_y + 1 < h:
                close = "─ Press d to close "
                stdscr.addstr(foot_y + 1, start_x, "╰" + close
                              + "─" * max(0, modal_w - 2 - len(close)) + "╯",
                              curses.color_pair(1))
        except curses.error:
            pass

    def draw_graph(self, stdscr, y, x, width, height, data, max_val=100, title="", show_current=True):
        """Draw a filled area graph.

        Batch the output: send each row as runs of filled cells
        (the row color never changes). Send no call per cell."""
        if width <= 2 or height <= 1:
            return

        blocks = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        points = list(data)[-(width):]
        if not points:
            points = [0]

        current_val = points[-1] if points else 0
        actual_max = max(max(points), max_val, 1)

        try:
            # Draw the graph rows
            for row in range(height):
                row_y = y + row
                threshold_low = 1.0 - ((row + 1) / height)
                threshold_high = 1.0 - (row / height)

                # Set color by row height (same color per row)
                if row < height * 0.3:
                    color = curses.color_pair(4)  # Red top
                elif row < height * 0.6:
                    color = curses.color_pair(3)  # Yellow mid
                else:
                    color = curses.color_pair(2)  # Green bottom

                tail = points[-width:]
                x_offset = x + (width - len(tail))
                run_chars = []
                run_x = 0
                for col, value in enumerate(tail):
                    if col >= width:
                        break
                    normalized = min(value / actual_max, 1.0) if actual_max > 0 else 0

                    # Pick the cell shape
                    if normalized >= threshold_high:
                        char = "█"
                    elif normalized > threshold_low:
                        frac = (normalized - threshold_low) / (threshold_high - threshold_low)
                        char = blocks[int(frac * 8)]
                    else:
                        char = " "

                    if char == " ":
                        if run_chars:
                            stdscr.addstr(row_y, run_x, ''.join(run_chars), color)
                            run_chars = []
                        continue
                    if not run_chars:
                        run_x = x_offset + col
                    run_chars.append(char)
                if run_chars:
                    stdscr.addstr(row_y, run_x, ''.join(run_chars), color)

            # Show the current value
            if show_current and title:
                val_str = f"{current_val:.1f}%" if current_val < 100 else f"{current_val:.0f}%"
                stdscr.addstr(y, x + width + 1, val_str, curses.color_pair(7) | curses.A_BOLD)
        except curses.error:
            pass

    def draw_mini_graph(self, stdscr, y, x, width, data, max_val=100, color=2):
        """Draw a compact one-line sparkline (one batched addstr call)."""
        if not data or width <= 0:
            return

        bars = "▁▂▃▄▅▆▇█"
        points = list(data)[-width:]
        actual_max = max(max(points), max_val, 1) if points else max_val

        chars = []
        for i, value in enumerate(points):
            if i >= width:
                break
            normalized = min(value / actual_max, 1.0) if actual_max > 0 else 0
            chars.append(bars[int(normalized * 7)])
        if not chars:
            return
        try:
            stdscr.addstr(y, x, ''.join(chars), curses.color_pair(color))
        except curses.error:
            pass

    def draw_braille_sparkline(self, stdscr, y, x, width, data, max_val=100, color=1):
        """Draw a high-detail sparkline with braille shapes (2x height detail).
        Send it in one addstr call (the row color never changes)."""
        if not data or width <= 0:
            return

        # Braille shapes for 0-4 dots in a column. Bottom to top order
        braille_base = 0x2800
        points = list(data)[-(width * 2):]  # 2 data points per character

        chars = []
        for i in range(min(width, (len(points) + 1) // 2)):
            idx = i * 2
            v1 = points[idx] if idx < len(points) else 0
            v2 = points[idx + 1] if idx + 1 < len(points) else 0

            # Scale to the 0-3 range for braille dots
            n1 = int(min(v1 / max_val, 1.0) * 3) if max_val > 0 else 0
            n2 = int(min(v2 / max_val, 1.0) * 3) if max_val > 0 else 0

            # Build the braille shape (dots 1,2,3 left, dots 4,5,6 right)
            char = braille_base
            for dot in range(n1):
                char |= (1 << dot)  # Dots 1,2,3
            for dot in range(n2):
                char |= (1 << (dot + 3))  # Dots 4,5,6
            chars.append(chr(char))

        if not chars:
            return
        try:
            stdscr.addstr(y, x, ''.join(chars), curses.color_pair(color))
        except curses.error:
            pass

    def draw_header(self, stdscr, width, uptime_str):
        """Draw a minimal header with permission marks."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            # One line with key data
            stdscr.addstr(0, 1, "sentinel", curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 10, f"v{VERSION}", curses.color_pair(8))
            
            # Draw permission letters after the version
            perm_x = 16
            perm_icons = []
            # D = Docker, K = K8s, W = WireGuard, S = Security, P = Proxy,
            # R = RAPL, H = Service Health
            # Read it from the live feature_status map: ok shows green,
            # no_permission and error show red, the rest stay hidden.
            for char, key in (('D', 'docker'), ('K', 'kubernetes'), ('W', 'wireguard'),
                              ('S', 'security'), ('P', 'proxy'), ('R', 'rapl'),
                              ('H', 'health')):
                state = self.feature_status.get(key, {}).get('state', 'not_installed')
                if state == 'ok':
                    perm_icons.append((char, 2))  # Green
                elif state in ('no_permission', 'error'):
                    perm_icons.append((char, 4))  # Red
            
            for char, color in perm_icons:
                if perm_x < width - 30:
                    stdscr.addstr(0, perm_x, char, curses.color_pair(color) | curses.A_BOLD)
                    perm_x += 2
            
            # Draw the hostname centered
            host_text = self.hostname
            host_x = (width - len(host_text)) // 2
            if host_x > perm_x + 2:
                stdscr.addstr(0, host_x, host_text, curses.color_pair(7))
            
            # Draw uptime and time at right
            right_text = f"up {uptime_str}  {timestamp}"
            if width - len(right_text) - 1 > 0:
                stdscr.addstr(0, width - len(right_text) - 1, f"up {uptime_str}", curses.color_pair(2))
            stdscr.addstr(0, width - len(timestamp) - 1, timestamp, curses.color_pair(8))
        except curses.error:
            pass

    def draw_bar(self, stdscr, y, x, width, percent, label="", show_val=True):
        """Draw a gradient progress bar.

        Batch the output: the gradient has at most 4 color runs plus the
        empty run. So the bar costs 6 addstr calls at most, not one call
        per cell."""
        if width <= 0:
            return

        filled = int((width * min(percent, 100)) / 100)

        def seg_color(i):
            pos_ratio = i / max(width - 1, 1)
            if pos_ratio < 0.5:
                return curses.color_pair(2)   # Green
            if pos_ratio < 0.75:
                return curses.color_pair(1)   # Cyan
            if pos_ratio < 0.9:
                return curses.color_pair(3)   # Yellow
            return curses.color_pair(4)       # Red

        try:
            # Draw the filled part: one call per same-color run
            run_start = 0
            while run_start < filled:
                color = seg_color(run_start)
                run_end = run_start + 1
                while run_end < filled and seg_color(run_end) == color:
                    run_end += 1
                stdscr.addstr(y, x + run_start, "━" * (run_end - run_start), color)
                run_start = run_end

            # Draw the empty part in one run
            if filled < width:
                stdscr.addstr(y, x + filled, "━" * (width - filled), curses.color_pair(8))

            # Draw the percent value
            if show_val:
                val_str = f"{percent:5.1f}%"
                stdscr.addstr(y, x + width + 1, val_str, curses.color_pair(7))
        except curses.error:
            pass

    def draw_meter(self, stdscr, y, x, width, percent, label="", color=2):
        """Draw a labeled meter bar (the bar itself costs 2 addstr calls)."""
        if width <= 0:
            return

        bar_width = width - len(label) - 8 if label else width - 6
        if bar_width < 4:
            bar_width = width - 2

        try:
            if label:
                stdscr.addstr(y, x, label, curses.color_pair(7))
                bar_x = x + len(label) + 1
            else:
                bar_x = x

            filled = int((bar_width * min(percent, 100)) / 100)

            # The fill color comes from percent only. So it is one run
            pos_ratio = percent / 100
            if pos_ratio < 0.6:
                c = curses.color_pair(2)
            elif pos_ratio < 0.85:
                c = curses.color_pair(3)
            else:
                c = curses.color_pair(4)
            if filled > 0:
                stdscr.addstr(y, bar_x, "┃" * filled, c)
            if filled < bar_width:
                stdscr.addstr(y, bar_x + filled, "┃" * (bar_width - filled),
                              curses.color_pair(8))

            # Draw the value
            val_str = f"{percent:5.1f}%"
            stdscr.addstr(y, bar_x + bar_width + 1, val_str, curses.color_pair(7))
        except curses.error:
            pass

    def draw_box(self, stdscr, top, left, height, width, title="", accent=8):
        """Draw a box with an optional title. Return inner coordinates."""
        if height < 2 or width < 4:
            return top, left, 0, 0
        
        border = curses.color_pair(accent)
        try:
            # Draw the top edge with title
            stdscr.addstr(top, left, "┌", border)
            if title:
                stdscr.addstr(top, left + 1, title, curses.color_pair(7) | curses.A_BOLD)
                stdscr.addstr(top, left + 1 + len(title), "─" * (width - 2 - len(title)), border)
            else:
                stdscr.addstr(top, left + 1, "─" * (width - 2), border)
            stdscr.addstr(top, left + width - 1, "┐", border)
            
            # Draw the sides
            for row in range(1, height - 1):
                stdscr.addstr(top + row, left, "│", border)
                stdscr.addstr(top + row, left + width - 1, "│", border)
            
            # Draw the bottom edge
            stdscr.addstr(top + height - 1, left, "└" + "─" * (width - 2) + "┘", border)
        except curses.error:
            pass
        
        return top + 1, left + 1, height - 2, width - 2

    def format_bytes(self, value, precision=1):
        """Format a byte count."""
        if value is None:
            return "0B"
        units = ["B", "KB", "MB", "GB", "TB"]
        value = float(value)
        for unit in units:
            if abs(value) < 1024 or unit == units[-1]:
                return f"{value:.{precision}f}{unit}"
            value /= 1024
        return f"{value:.{precision}f}TB"

    def format_duration(self, seconds):
        """Format a duration for VPN handshakes."""
        if seconds is None:
            return "never"
        if seconds < 1:
            return "now"
        minutes, secs = divmod(int(seconds), 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {secs}s"
        return f"{secs}s"

    def update_data(self):
        """Refresh all system data. Never wait.

        Run fast sync reads (sub-millisecond /proc and /sys file reads)
        inline. Merge all slow or IO-bound features from the latest
        collector snapshot. Before a collector first publishes, panels
        use the same placeholders as on the first render. So the first
        paint is instant.
        """
        current_time = time.time()

        if current_time - self.last_update < self.refresh_rate:
            return self.cache

        # At first render set the public IP placeholder (the collector fills it)
        is_first = self._first_render
        if is_first:
            self._first_render = False
            # Light mode starts no public_ip collector. So "Checking..."
            # stays for ever without this default.
            self._public_ip_cache = "off" if self._light_mode else "Checking..."

        # Profile each stage, active only when SENTINEL_PROFILE holds a path
        if _PROFILE_PATH:
            _prof_stages = {}
            _prof_t0 = time.monotonic()
            def _timed(name, fn):
                _s = time.monotonic()
                _r = fn()
                _prof_stages[name] = round((time.monotonic() - _s) * 1000, 3)
                return _r
        else:
            def _timed(name, fn):
                return fn()

        # Disk: inline statvfs plus Docker volumes from the docker_df collector
        disks = _timed('disk', self.get_disk_usage)
        docker_volumes = self._collector_result('docker_df')
        if docker_volumes:
            disks = disks + docker_volumes

        # Slow features: take the latest collector snapshots (never wait)
        docker = self._collector_result('docker') or {
            'available': False, 'running': 0, 'stopped': 0, 'total': 0, 'containers': []}
        kubernetes = self._collector_result('kubernetes') or {
            'available': False, 'nodes': 0, 'nodes_ready': 0, 'pods_running': 0,
            'pods_pending': 0, 'pods_failed': 0, 'pods': [], 'context': ''}
        proxy = self._collector_result('proxy') or {
            'requests': 0, 'bytes': 0, 'rps': 0.0, 'source': None}
        security = self._collector_result('security') or {
            'available': False, 'total_parsed': 0, 'total_unparsed': 0,
            'failed_logins': 0, 'successful_logins': 0, 'failed_ratio': 0.0,
            'top_ips': {}, 'top_users': {}, 'error_types': {},
            'recent_events': [], 'alerts': []}
        health = self._collector_result('health')
        if health:
            per_container = health.get('containers', {})
            for container in docker.get('containers', []):
                entry = per_container.get(container.get('name'))
                container['health'] = entry['state'] if entry else 'unconfigured'
                container['health_detail'] = entry['detail'] if entry else ''

        self.cache = {
            'cpu': _timed('cpu', self.get_cpu_info),
            'mem': _timed('mem', self.get_memory_info),
            'battery': _timed('battery', self.get_battery_info),
            'disk': disks,
            'network': _timed('network', self.get_network_info),
            'processes': _timed('processes', self.get_processes),
            'uptime': _timed('uptime', self.get_uptime),
            'energy': _timed('energy', self.get_energy_info),
            'docker': docker,
            'kubernetes': kubernetes,
            'proxy': proxy,
            'security': security,
            'health': health or {'containers': {}, 'listeners': {},
                                 'healthy': 0, 'down': 0},
        }

        self.last_update = current_time

        if _PROFILE_PATH:
            try:
                _prof_collectors = {}
                for _name, _c in self.collectors.items():
                    _res, _err, _dur, _fin, _gen = _c.snapshot()
                    _prof_collectors[_name] = {
                        'duration_ms': round(_dur * 1000, 3),
                        'age_s': round(current_time - _fin, 1) if _fin else None,
                        'generation': _gen,
                        'subprocesses': _c.subprocess_count,
                        'error': str(_err) if _err else None,
                    }
                with open(_PROFILE_PATH, 'a') as _f:
                    _f.write(json.dumps({
                        'ts': current_time,
                        'stages': _prof_stages,
                        'collectors': _prof_collectors,
                        'total_ms': round((time.monotonic() - _prof_t0) * 1000, 3),
                        'run_cmd_count': _RUN_CMD_COUNT,
                        'frames_drawn': self.frames_drawn,
                        'frames_skipped': self.frames_skipped,
                    }) + '\n')
            except (OSError, TypeError, ValueError) as e:
                # Profile output is a debug channel. It must never stop
                # the monitor. But it must not hide real bugs.
                _debug_log(f"profile write failed: {e}")

        return self.cache

    def check_alerts(self, data):
        """Find alert states. Return the list of active alerts."""
        alerts = []
        cpu = data.get('cpu', {})
        mem = data.get('mem', {})
        battery = data.get('battery', {})
        
        # Find CPU alerts
        if cpu.get('usage', 0) >= self.alerts.get('cpu_critical', 95):
            alerts.append(('CPU CRITICAL', f"{cpu['usage']:.0f}%", 'danger'))
        elif cpu.get('usage', 0) >= self.alerts.get('cpu_high', 85):
            alerts.append(('CPU HIGH', f"{cpu['usage']:.0f}%", 'warning'))
        
        # Find temperature alerts
        if cpu.get('temp', 0) >= self.alerts.get('temp_critical', 90):
            alerts.append(('TEMP CRITICAL', f"{cpu['temp']:.0f}°C", 'danger'))
        elif cpu.get('temp', 0) >= self.alerts.get('temp_high', 75):
            alerts.append(('TEMP HIGH', f"{cpu['temp']:.0f}°C", 'warning'))
        
        # Find memory alerts
        if mem.get('percent', 0) >= self.alerts.get('mem_critical', 95):
            alerts.append(('MEM CRITICAL', f"{mem['percent']:.0f}%", 'danger'))
        elif mem.get('percent', 0) >= self.alerts.get('mem_high', 80):
            alerts.append(('MEM HIGH', f"{mem['percent']:.0f}%", 'warning'))
        
        # Find battery alerts
        if battery.get('exists') and battery.get('status') != 'Charging':
            level = battery.get('level', 100)
            if level <= self.alerts.get('battery_critical', 10):
                alerts.append(('BATTERY CRITICAL', f"{level}%", 'danger'))
            elif level <= self.alerts.get('battery_low', 20):
                alerts.append(('BATTERY LOW', f"{level}%", 'warning'))
        
        # Find Docker alerts
        docker = data.get('docker', {})
        if docker.get('available'):
            stopped = docker.get('stopped', 0)
            if stopped > 0:
                alerts.append(('DOCKER STOPPED', f"{stopped}", 'warning'))
            for container in docker.get('containers', []):
                if container.get('health') == 'down':
                    alerts.append(('SERVICE DOWN',
                                   f"{container.get('name')}: {container.get('health_detail', 'check failed')}",
                                   'danger'))

        # Find listener alerts (ports that stay closed but must be open)
        health = data.get('health', {})
        for port, entry in health.get('listeners', {}).items():
            if entry.get('state') == 'down':
                alerts.append(('PORT CLOSED', f"{port}: {entry.get('detail', 'closed')}", 'danger'))
        
        # Find Kubernetes alerts
        k8s = data.get('kubernetes', {})
        if k8s.get('available'):
            failed = k8s.get('pods_failed', 0)
            pending = k8s.get('pods_pending', 0)
            if failed > 0:
                alerts.append(('K8S FAILED', f"{failed} pods", 'danger'))
            elif pending > 0:
                alerts.append(('K8S PENDING', f"{pending} pods", 'warning'))

        # Find security alerts
        security = data.get('security', {})
        if security.get('available'):
            # Add the alerts from security log scan
            for alert in security.get('alerts', []):
                alert_type = alert['type'].upper().replace('_', ' ')
                alerts.append((alert_type, alert['message'], alert['severity']))

        return alerts

    def setup_colors(self):
        """Set color pairs from the theme."""
        theme = THEMES.get(self.theme_name, THEMES['default'])
        
        curses.start_color()
        curses.use_default_colors()
        
        # Map theme colors to pairs (names follow the color list order)
        curses.init_pair(1, theme['primary'], -1)
        curses.init_pair(2, theme['success'], -1)
        curses.init_pair(3, theme['warning'], -1)
        curses.init_pair(4, theme['danger'], -1)
        curses.init_pair(5, theme['info'], -1)
        curses.init_pair(6, theme['accent'], -1)
        curses.init_pair(7, theme['text'], -1)
        curses.init_pair(8, theme['muted'], -1)

    def _frame_signature(self, h, w):
        """Build a cheap identity of all renderer input.

        An equal value means the next repaint shows the same screen
        (except the header clock, which _tick_clock handles). So skip
        the draw.

        self.last_update is the key term: update_data() moves it only
        when it re-reads data. All collector results reach the screen
        through that same cache. So one float covers all of them.
        """
        if self._no_frameskip:
            return time.monotonic()  # never equal -> always repaint
        return (
            self.last_update,       # data cache generation
            self._status_revision,  # feature/permission transitions
            h, w,                   # terminal geometry
            self.theme_name,
            self.layout_mode,
            self.refresh_rate,
            self._show_help,
            self._show_diagnostics,
        )

    def _tick_clock(self, stdscr, w):
        """Redraw the header clock only (the one value that must move
        while the rest of the screen stays still).

        Send one addstr call, not a full repaint. Skip it while a modal
        is open, so the overlay keeps its pixels."""
        if self._show_help or self._show_diagnostics:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        if timestamp == self._last_clock:
            return
        self._last_clock = timestamp
        try:
            x = w - len(timestamp) - 1
            if x > 0:
                stdscr.addstr(0, x, timestamp, curses.color_pair(8))
                stdscr.refresh()
        except curses.error:
            pass

    def _input_timeout_ms(self):
        """Wait in getch() for the next screen change.

        getch() returns at once on a key press, whatever the timeout. So
        a long timeout adds no input delay. It only removes idle wakeups.
        Wake at the first of these: next data refresh, next clock second."""
        now = time.time()
        next_data = self.last_update + self.refresh_rate
        next_second = int(now) + 1
        ms = int((min(next_data, next_second) - now) * 1000)
        return max(20, min(1000, ms))

    def _handle_key(self, stdscr, key):
        """Handle one key. Return True to quit the main loop.

        The full-draw and frame-skip paths share this code. Each branch
        that changes screen content also changes _frame_signature(). So
        the next pass repaints alone, with no extra refresh call."""
        if key == curses.KEY_RESIZE:
            # The terminal changed size. Build the layout again
            self._cached_layout = None
            self._last_layout_dims = (0, 0, 0, 0, '')
        elif key == ord('q') or key == ord('Q'):
            self.stop_collectors()
            return True
        elif key == ord('r') or key == ord('R'):
            self.last_update = 0
            self._first_render = False  # Don't skip data on manual refresh
        elif key == ord('i') or key == ord('I'):
            self._last_ip_check = 0
            self.wake_collector('public_ip')
        elif key == ord('h') or key == ord('H'):
            self._show_help = not self._show_help
            self._show_diagnostics = False  # Close diagnostics if help opened
        elif key == ord('d') or key == ord('D'):
            self._show_diagnostics = not self._show_diagnostics
            self._show_help = False  # Close help if diagnostics opened
        elif key == ord('t') or key == ord('T'):
            # Move to the next theme
            theme_list = list(THEMES.keys())
            current_idx = theme_list.index(self.theme_name) if self.theme_name in theme_list else 0
            self.theme_name = theme_list[(current_idx + 1) % len(theme_list)]
            self.setup_colors()
        elif key == ord('l') or key == ord('L'):
            # Move to the next layout
            current_idx = LAYOUT_MODES.index(self.layout_mode) if self.layout_mode in LAYOUT_MODES else 0
            self.layout_mode = LAYOUT_MODES[(current_idx + 1) % len(LAYOUT_MODES)]
        elif key == ord('+') or key == ord('='):
            # Shorten the refresh interval (faster)
            self.refresh_rate = max(1, self.refresh_rate - 1)
        elif key == ord('-') or key == ord('_'):
            # Lengthen the refresh interval (slower)
            self.refresh_rate = min(10, self.refresh_rate + 1)
        return False

    def draw(self, stdscr):
        """Draw the main screen."""
        curses.curs_set(0)

        # Set theme colors
        self.setup_colors()

        while True:
            try:
                h, w = stdscr.getmaxyx()

                # Show the loading box at first render
                if self._first_render:
                    stdscr.erase()
                    self.draw_loading_modal(stdscr, h, w, "Initializing...")
                    stdscr.refresh()

                data = self.update_data()

                # P5: no visible change. Skip the ~2k-addstr repaint.
                # Tick the clock. Wait in getch() for the next change.
                sig = self._frame_signature(h, w)
                if sig == self._last_frame_sig:
                    self.frames_skipped += 1
                    self._tick_clock(stdscr, w)
                    stdscr.timeout(self._input_timeout_ms())
                    if self._handle_key(stdscr, stdscr.getch()):
                        break
                    continue

                self._last_frame_sig = sig
                self.frames_drawn += 1
                stdscr.erase()
                cpu = data['cpu']
                mem = data['mem']
                battery = data['battery']
                net = data['network']
                energy = data['energy']
                proc = data['processes']
                disks = data['disk']

                days, hours, mins = data['uptime']
                uptime_str = f"{days}d {hours}h {mins}m"

                # === HEADER (line 0) ===
                self.draw_header(stdscr, w, uptime_str)

                # === LAYOUT CALCULATION ===
                # 3-column for wide (>=100), 2-column for medium (>=60), stacked for narrow
                # Widths follow the layout mode
                row = 1
                available_h = h - 2  # header + footer
                
                # Width ratios per layout
                layout = self.layout_mode
                if w >= 100:
                    if layout == 'cpu':
                        # CPU view: 50% | 25% | 25%
                        col1_w = w // 2
                        col2_w = w // 4
                        col3_w = w - col1_w - col2_w
                    elif layout == 'network':
                        # Network view: 25% | 25% | 50%
                        col1_w = w // 4
                        col2_w = w // 4
                        col3_w = w - col1_w - col2_w
                    elif layout == 'docker':
                        # Docker view: 30% | 20% | 50% (the power box
                        # is wider to fit containers)
                        col1_w = int(w * 0.30)
                        col2_w = int(w * 0.20)
                        col3_w = w - col1_w - col2_w
                    elif layout == 'security':
                        # Security view: 25% | 20% | 55% (the power box
                        # is wider to fit security events)
                        col1_w = w // 4
                        col2_w = int(w * 0.20)
                        col3_w = w - col1_w - col2_w
                    elif layout == 'minimal':
                        # Minimal view: equal small columns
                        col1_w = w // 3
                        col2_w = w // 3
                        col3_w = w - col1_w - col2_w
                    else:  # default
                        col1_w = w // 3
                        col2_w = w // 3
                        col3_w = w - col1_w - col2_w
                    top_h = available_h
                elif w >= 60:
                    # Two columns next to each other
                    if layout == 'cpu':
                        col1_w = int(w * 0.6)
                    elif layout == 'network' or layout == 'docker' or layout == 'security':
                        col1_w = int(w * 0.4)
                    else:
                        col1_w = w // 2
                    col2_w = w - col1_w
                    col3_w = col2_w  # reuse for bottom
                    top_h = available_h
                else:
                    # One column stacked
                    col1_w = w
                    col2_w = w
                    col3_w = w
                    top_h = max(6, available_h // 3)

                # === COLUMN 1: CPU ===
                cpu_h = top_h if w >= 100 else top_h // 2
                iy, ix, ih, iw = self.draw_box(stdscr, row, 0, cpu_h, col1_w, "cpu")
                
                if ih > 0 and iw > 0:
                    line = 0
                    
                    # Draw the CPU model and core count
                    model_text = cpu['model'][:iw - 12] if len(cpu['model']) > iw - 12 else cpu['model']
                    stdscr.addstr(iy + line, ix, model_text, curses.color_pair(8))
                    cores_text = f"{cpu['cores']} cores"
                    stdscr.addstr(iy + line, ix + iw - len(cores_text), cores_text, curses.color_pair(8))
                    line += 1
                    
                    # Draw the main CPU bar with percent
                    if line < ih:
                        self.draw_bar(stdscr, iy + line, ix, iw - 8, cpu['usage'])
                        line += 1
                    
                    # Draw small bars per core (when space and data exist)
                    num_cores = cpu.get('cores', 0)
                    if num_cores > 0 and line < ih - 4:
                        # Read per-core use from /proc/stat
                        core_usages = self._get_per_core_usage()
                        cores_to_show = min(num_cores, ih - line - 4)  # Leave room for stats
                        bar_w = max(8, iw - 6)
                        
                        for i in range(cores_to_show):
                            if line >= ih - 3:
                                break
                            core_pct = core_usages[i] if i < len(core_usages) else 0
                            label = f"{i:2d}"
                            stdscr.addstr(iy + line, ix, label, curses.color_pair(8))
                            self.draw_bar(stdscr, iy + line, ix + 3, bar_w - 3, core_pct, show_val=False)
                            line += 1
                    
                    # Draw the CPU graph in the free space
                    graph_start = line
                    graph_h = max(2, ih - line - 2)
                    if graph_h >= 2:
                        self.draw_graph(stdscr, iy + line, ix, iw, graph_h, self.cpu_history, max_val=100, show_current=False)
                        line += graph_h
                    
                    # Draw the numbers row at bottom
                    stats_y = iy + ih - 2
                    if stats_y > iy + line - 1:
                        freq_color = curses.color_pair(2) if cpu['status'] == 'normal' else curses.color_pair(3) if cpu['status'] == 'low' else curses.color_pair(4)
                        stdscr.addstr(stats_y, ix, f"{cpu['freq']:.2f}GHz", freq_color | curses.A_BOLD)
                        
                        temp_color = curses.color_pair(2) if cpu['temp'] < 60 else curses.color_pair(3) if cpu['temp'] < 75 else curses.color_pair(4)
                        stdscr.addstr(stats_y, ix + 10, f"{cpu['temp']:.0f}°C", temp_color)
                        
                        if cpu['fan_rpm']:
                            stdscr.addstr(stats_y, ix + 17, f"{cpu['fan_rpm']}rpm", curses.color_pair(8))
                        
                        gov_text = cpu['gov'][:10]
                        stdscr.addstr(stats_y, ix + iw - len(gov_text), gov_text, curses.color_pair(8))
                    
                    # Draw load average on the last line
                    if stats_y + 1 < iy + ih:
                        load_text = f"load {cpu['load'][0]:.2f} {cpu['load'][1]:.2f} {cpu['load'][2]:.2f}"
                        stdscr.addstr(stats_y + 1, ix, load_text, curses.color_pair(8))
                        
                        # Draw uptime at right
                        up_text = f"up {uptime_str}"
                        stdscr.addstr(stats_y + 1, ix + iw - len(up_text), up_text, curses.color_pair(2))


                # === COLUMN 2: Memory + Disks ===
                if w >= 100:
                    # 3-column: column 2 sits next to CPU
                    col2_x = col1_w
                    mem_box_h = top_h // 2
                    disk_box_h = top_h - mem_box_h
                    col2_row = row
                elif w >= 60:
                    # 2-column: memory and disk sit below CPU, at left
                    col2_x = 0
                    mem_box_h = (available_h - cpu_h) // 2
                    disk_box_h = available_h - cpu_h - mem_box_h
                    col2_row = row + cpu_h
                else:
                    # 1-column: stacked below CPU
                    col2_x = 0
                    mem_box_h = max(4, available_h // 4)
                    disk_box_h = mem_box_h
                    col2_row = row + cpu_h
                
                if col2_w > 0 and mem_box_h > 2:
                    # Draw the memory box
                    my, mx, mh, mw = self.draw_box(stdscr, col2_row, col2_x, mem_box_h, col2_w, "mem")
                    if mh > 0 and mw > 0:
                        mem_total_gb = mem['total'] / 1024 if mem['total'] else 0
                        mem_used_gb = mem['used'] / 1024 if mem['used'] else 0
                        self.draw_bar(stdscr, my, mx, mw - 8, mem['percent'])
                        
                        if mh > 2:
                            graph_h = max(2, mh - 3)
                            self.draw_graph(stdscr, my + 1, mx, mw, graph_h, self.mem_history, max_val=100, show_current=False)
                        
                        stats_y = my + mh - 1
                        if stats_y > my:
                            stdscr.addstr(stats_y, mx, f"{mem_used_gb:.1f}G/{mem_total_gb:.1f}G", curses.color_pair(7))
                    
                    # Draw the disks box
                    disk_y = col2_row + mem_box_h
                    dy, dx, dh, dw = self.draw_box(stdscr, disk_y, col2_x, disk_box_h, col2_w, "disks")
                    if dh > 0 and dw > 0:
                        for i, disk in enumerate(disks[:dh]):
                            disk_type = disk.get('type', 'disk')
                            
                            if disk_type == 'docker':
                                # Docker volumes: show dk prefix, name, and size
                                mount = disk['mount'][:dw - 14]
                                size_text = disk['used'][:8] if disk['used'] else '-'
                                stdscr.addstr(dy + i, dx, "dk:", curses.color_pair(5))
                                stdscr.addstr(dy + i, dx + 3, mount, curses.color_pair(8))
                                stdscr.addstr(dy + i, dx + dw - len(size_text), size_text, curses.color_pair(7))
                            else:
                                # Local disk: show a bar and percent
                                mount = disk['mount'][:8]
                                pct = disk['percent']
                                bar_w = max(6, dw - 16)
                                stdscr.addstr(dy + i, dx, f"{mount:>6}", curses.color_pair(8))
                                self.draw_bar(stdscr, dy + i, dx + 7, bar_w, pct, show_val=False)
                                stdscr.addstr(dy + i, dx + 8 + bar_w, f"{pct:3.0f}%", curses.color_pair(7))

                # === COLUMN 3: Network + Power ===
                if w >= 100:
                    # 3-column: column 3 sits at right
                    col3_x = col1_w + col2_w
                    # Set heights from the layout mode
                    if layout == 'network':
                        net_box_h = int(top_h * 0.7)  # Network gets 70%
                        pwr_box_h = top_h - net_box_h
                    elif layout == 'docker':
                        net_box_h = int(top_h * 0.3)  # Network smaller
                        pwr_box_h = top_h - net_box_h  # Power/Docker gets more
                    elif layout == 'security':
                        net_box_h = int(top_h * 0.3)  # Network smaller
                        pwr_box_h = top_h - net_box_h  # Power/Security gets more
                    else:
                        net_box_h = top_h // 2
                        pwr_box_h = top_h - net_box_h
                    col3_actual_w = col3_w
                    col3_row = row
                elif w >= 60:
                    # 2-column: network and power sit at right, full height
                    col3_x = col1_w
                    net_box_h = available_h // 2
                    pwr_box_h = available_h - net_box_h
                    col3_actual_w = col2_w
                    col3_row = row
                else:
                    # 1-column: stacked at bottom
                    col3_x = 0
                    net_box_h = max(4, available_h // 4)
                    pwr_box_h = available_h - cpu_h - mem_box_h - disk_box_h - net_box_h
                    col3_actual_w = w
                    col3_row = row + cpu_h + mem_box_h + disk_box_h
                
                if col3_actual_w > 0 and net_box_h > 0:
                    # Draw the network box (full layout)
                    ny, nx, nh, nw = self.draw_box(stdscr, col3_row, col3_x, net_box_h, col3_actual_w, "net")
                    if nh > 0 and nw > 0:
                        line = 0
                        
                        # Draw interface and connection type
                        iface = net['interface'] or "-"
                        conn_type = net.get('connection_type', '')
                        stdscr.addstr(ny + line, nx, iface, curses.color_pair(1) | curses.A_BOLD)
                        if conn_type:
                            stdscr.addstr(ny + line, nx + len(iface) + 1, f"({conn_type})", curses.color_pair(8))
                        
                        # Draw link speed at right (only when valid and above 0)
                        link_speed = net.get('link_speed')
                        if link_speed and link_speed > 0 and nw > 20:
                            if link_speed >= 1000:
                                speed_text = f"{link_speed // 1000}Gbps"
                            else:
                                speed_text = f"{link_speed}Mbps"
                            stdscr.addstr(ny + line, nx + nw - len(speed_text), speed_text, curses.color_pair(2))
                        line += 1
                        
                        # Draw the IPs
                        if line < nh:
                            local_ip = net['local_ip'] or "-"
                            stdscr.addstr(ny + line, nx, local_ip, curses.color_pair(7))
                            public_ip = net['public_ip'] or "N/A"
                            if nw > 20:
                                stdscr.addstr(ny + line, nx + nw - len(public_ip), public_ip, curses.color_pair(8))
                            line += 1
                        
                        # Draw download with graph
                        if line < nh:
                            rx_text = f"↓ {net['rx_speed']:6.1f} KB/s"
                            stdscr.addstr(ny + line, nx, rx_text, curses.color_pair(2))
                            graph_x = nx + len(rx_text) + 1
                            graph_w = nw - len(rx_text) - 2
                            if graph_w > 4:
                                max_rx = max(max(self.rx_history) if self.rx_history else 1, 1)
                                self.draw_mini_graph(stdscr, ny + line, graph_x, graph_w, self.rx_history, max_val=max_rx, color=2)
                            line += 1
                        
                        # Draw upload with graph
                        if line < nh:
                            tx_text = f"↑ {net['tx_speed']:6.1f} KB/s"
                            stdscr.addstr(ny + line, nx, tx_text, curses.color_pair(6))
                            graph_x = nx + len(tx_text) + 1
                            graph_w = nw - len(tx_text) - 2
                            if graph_w > 4:
                                max_tx = max(max(self.tx_history) if self.tx_history else 1, 1)
                                self.draw_mini_graph(stdscr, ny + line, graph_x, graph_w, self.tx_history, max_val=max_tx, color=6)
                            line += 1
                        
                        # Draw totals
                        if line < nh:
                            totals = f"total: ↓{net['rx_total']:.2f}G ↑{net['tx_total']:.2f}G"
                            stdscr.addstr(ny + line, nx, totals, curses.color_pair(8))
                            line += 1
                        
                        # Draw VPN peers
                        if line < nh:
                            peers = net.get('wg_peers', 0)
                            connected = net.get('wg_peers_connected', 0)
                            if peers > 0:
                                vpn_color = curses.color_pair(2) if connected > 0 else curses.color_pair(4)
                                vpn_icon = "●" if connected > 0 else "○"
                                stdscr.addstr(ny + line, nx, f"vpn {vpn_icon} {connected}/{peers} peers", vpn_color)
                            else:
                                # With no VPN show SSID for wifi
                                ssid = net.get('ssid')
                                if ssid:
                                    stdscr.addstr(ny + line, nx, f"wifi: {ssid}", curses.color_pair(8))
                            line += 1
                        
                        # Draw VPN details when space allows
                        vpn_list = net.get('vpn_connections', [])
                        for peer in vpn_list[:nh - line]:
                            if line >= nh:
                                break
                            # Take the full IP (no port). Cut it to the free width
                            endpoint_full = peer['endpoint'].split(':')[0] if peer.get('endpoint') else "-"
                            max_ip_len = nw - 4  # Leave room for status icon
                            endpoint = endpoint_full[:max_ip_len]
                            status = "●" if peer['connected'] else "○"
                            color = curses.color_pair(2) if peer['connected'] else curses.color_pair(4)
                            # Draw latency when present
                            latency = peer.get('latency', '')
                            if latency and len(endpoint) + len(latency) + 5 < nw:
                                stdscr.addstr(ny + line, nx, f"  {status} {endpoint}", color)
                                stdscr.addstr(ny + line, nx + nw - len(latency) - 1, latency, curses.color_pair(8))
                            else:
                                stdscr.addstr(ny + line, nx, f"  {status} {endpoint}", color)
                            line += 1
                        
                        # Draw proxy traffic numbers when present
                        proxy = data.get('proxy', {})
                        if proxy.get('source') and line < nh:
                            rps = proxy.get('rps', 0)
                            source = proxy['source'][:6]
                            stdscr.addstr(ny + line, nx, f"proxy:", curses.color_pair(8))
                            stdscr.addstr(ny + line, nx + 7, source, curses.color_pair(5))
                            stdscr.addstr(ny + line, nx + 7 + len(source) + 1, f"{rps:.1f}rps", curses.color_pair(2))
                            line += 1
                        elif line < nh:
                            # The proxy logs exist but are unreadable. Say so.
                            # Do not leave the row blank with no message.
                            pstate = self.feature_status.get('proxy', {}).get('state', '')
                            if pstate in ('no_permission', 'error'):
                                label = self._STATE_LABELS.get(pstate, pstate)
                                stdscr.addstr(ny + line, nx,
                                              f"proxy: {label}"[:nw - 1],
                                              curses.color_pair(4))
                                line += 1
                        
                        # Draw the signal mark when space allows
                        if line < nh and net.get('operstate') == 'up':
                            # Grade quality from speed and stability
                            rx_speed = net.get('rx_speed', 0)
                            tx_speed = net.get('tx_speed', 0)
                            if rx_speed > 1000 or tx_speed > 1000:
                                quality = "▰▰▰▰▰"
                                q_color = curses.color_pair(2)
                            elif rx_speed > 100 or tx_speed > 100:
                                quality = "▰▰▰▰▱"
                                q_color = curses.color_pair(2)
                            elif rx_speed > 10 or tx_speed > 10:
                                quality = "▰▰▰▱▱"
                                q_color = curses.color_pair(3)
                            elif rx_speed > 0 or tx_speed > 0:
                                quality = "▰▰▱▱▱"
                                q_color = curses.color_pair(3)
                            else:
                                quality = "▰▱▱▱▱"
                                q_color = curses.color_pair(4)
                            stdscr.addstr(ny + line, nx, "signal:", curses.color_pair(8))
                            stdscr.addstr(ny + line, nx + 8, quality, q_color)
                            line += 1
                    
                    # Power and energy box: wider layout
                    pwr_y = col3_row + net_box_h
                    py, px, ph, pw = self.draw_box(stdscr, pwr_y, col3_x, pwr_box_h, col3_actual_w, "power")
                    if ph > 0 and pw > 0:
                        line = 0
                        
                        # Draw RAPL and CPU power use
                        if energy['available']:
                            watts = energy['power_watts']
                            pwr_color = curses.color_pair(2) if watts < 15 else curses.color_pair(3) if watts < 30 else curses.color_pair(4)
                            
                            # Draw the power value with a bar
                            max_watts = 65  # TDP estimate
                            pwr_pct = min(100, (watts / max_watts) * 100)
                            bar_w = min(12, pw - 12)
                            
                            stdscr.addstr(py + line, px, f"{watts:5.1f}W", pwr_color | curses.A_BOLD)
                            if bar_w > 4:
                                self.draw_bar(stdscr, py + line, px + 7, bar_w, pwr_pct, show_val=False)
                            stdscr.addstr(py + line, px + pw - 4, energy['source'].upper()[:4], curses.color_pair(8))
                            line += 1
                            
                            # Draw the power history graph
                            if line < ph and len(self.power_history) > 1:
                                max_pwr = max(max(self.power_history), 10)
                                graph_w = min(pw - 2, 24)
                                self.draw_mini_graph(stdscr, py + line, px, graph_w, self.power_history, max_val=max_pwr, color=1)
                                line += 1
                        
                        # Draw the battery block
                        if battery.get('exists'):
                            if line > 0 and line < ph:
                                line += 1  # spacing
                            
                            if line < ph:
                                batt_pct = battery['level']
                                batt_color = curses.color_pair(2) if batt_pct > 50 else curses.color_pair(3) if batt_pct > 20 else curses.color_pair(4)
                                
                                # Draw the battery icon from level
                                if batt_pct > 75:
                                    icon = "█"
                                elif batt_pct > 50:
                                    icon = "▆"
                                elif batt_pct > 25:
                                    icon = "▄"
                                else:
                                    icon = "▂"
                                
                                status = battery['status']
                                status_icon = "+" if "Charg" in status else "=" if "Full" in status else "-"
                                
                                stdscr.addstr(py + line, px, f"{icon}", batt_color)
                                stdscr.addstr(py + line, px + 2, f"{batt_pct:3d}%", batt_color | curses.A_BOLD)
                                stdscr.addstr(py + line, px + 8, status_icon, curses.color_pair(3) if "Charg" in status else curses.color_pair(8))
                                stdscr.addstr(py + line, px + 10, status[:8], curses.color_pair(8))
                                line += 1
                            
                            # Draw the battery bar
                            if line < ph:
                                bar_w = min(pw - 2, 20)
                                self.draw_bar(stdscr, py + line, px, bar_w, batt_pct, show_val=False)
                                line += 1
                            
                            # Draw health and cycles
                            if line < ph and battery.get('health'):
                                health = battery['health']
                                cycles = battery.get('cycle_count') or '-'
                                health_color = curses.color_pair(2) if health > 80 else curses.color_pair(3) if health > 60 else curses.color_pair(4)
                                stdscr.addstr(py + line, px, f"health:", curses.color_pair(8))
                                stdscr.addstr(py + line, px + 7, f"{health:.0f}%", health_color)
                                stdscr.addstr(py + line, px + 13, f"cycles:{cycles}", curses.color_pair(8))
                                line += 1
                            
                            # Draw power draw when present
                            if line < ph and battery.get('power'):
                                pwr = battery['power']
                                if pwr > 0:
                                    stdscr.addstr(py + line, px, f"draw: {pwr:.1f}W", curses.color_pair(8))
                                    line += 1
                        
                        # With no energy and no battery, say so
                        if not energy['available'] and not battery.get('exists'):
                            stdscr.addstr(py + line, px, "no power data", curses.color_pair(8))
                            line += 1
                            if line < ph:
                                stdscr.addstr(py + line, px, "RAPL needs root", curses.color_pair(8))
                        
                        # Docker, Kubernetes, and security data at bottom
                        docker = data.get('docker', {})
                        k8s = data.get('kubernetes', {})
                        security = data.get('security', {})

                        if line < ph - 1:
                            line += 1  # spacing
                            remaining_lines = ph - line

                            # Plan space for Docker, Kubernetes, and security
                            has_docker = docker.get('available', False)
                            has_k8s = k8s.get('available', False)
                            has_security = security.get('available', False)

                            # Count active features. Split the lines
                            active_features = sum([has_docker, has_k8s, has_security])

                            if active_features == 0:
                                docker_lines = 0
                                k8s_lines = 0
                                security_lines = 0
                            elif active_features == 1:
                                # One feature takes all lines
                                if has_docker:
                                    docker_lines = remaining_lines
                                    k8s_lines = 0
                                    security_lines = 0
                                elif has_k8s:
                                    docker_lines = 0
                                    k8s_lines = remaining_lines
                                    security_lines = 0
                                else:
                                    docker_lines = 0
                                    k8s_lines = 0
                                    security_lines = remaining_lines
                            elif active_features == 2:
                                # Two features share the space
                                if has_docker and has_k8s:
                                    docker_lines = remaining_lines // 2
                                    k8s_lines = remaining_lines - docker_lines
                                    security_lines = 0
                                elif has_docker and has_security:
                                    docker_lines = remaining_lines // 2
                                    k8s_lines = 0
                                    security_lines = remaining_lines - docker_lines
                                else:  # k8s and security
                                    docker_lines = 0
                                    k8s_lines = remaining_lines // 2
                                    security_lines = remaining_lines - k8s_lines
                            else:  # All three features
                                # In security view security takes more space
                                if layout == 'security':
                                    security_lines = int(remaining_lines * 0.5)
                                    docker_lines = (remaining_lines - security_lines) // 2
                                    k8s_lines = remaining_lines - security_lines - docker_lines
                                else:
                                    # Split the rest across all three
                                    docker_lines = remaining_lines // 3
                                    k8s_lines = remaining_lines // 3
                                    security_lines = remaining_lines - docker_lines - k8s_lines
                            
                            # Draw Docker when present
                            if has_docker and docker_lines > 0:
                                running = docker['running']
                                stopped = docker['stopped']
                                color = curses.color_pair(2) if running > 0 else curses.color_pair(8)
                                stdscr.addstr(py + line, px, "dk", curses.color_pair(5))
                                stdscr.addstr(py + line, px + 2, f"{running}", color | curses.A_BOLD)
                                stdscr.addstr(py + line, px + 2 + len(str(running)), f"/{docker['total']}", curses.color_pair(8))
                                line += 1
                                docker_lines -= 1
                                
                                # List containers to fit the free space
                                containers_to_show = min(len(docker['containers']), docker_lines)
                                for container in docker['containers'][:containers_to_show]:
                                    if line >= ph:
                                        break
                                    name = container['name'][:pw - 8]
                                    status_icon = "●" if container['status'] == 'running' else "○"
                                    status_color = curses.color_pair(2) if container['status'] == 'running' else curses.color_pair(4)
                                    stdscr.addstr(py + line, px, f" {status_icon}", status_color)
                                    stdscr.addstr(py + line, px + 3, name, curses.color_pair(8))
                                    # Health (v0.6.2): green dot means healthy,
                                    # red cross means down. Stopped containers
                                    # show their status icon only.
                                    health_mark = ''
                                    health_pair = 8
                                    if container.get('status') == 'running':
                                        if container.get('health') == 'healthy':
                                            health_mark, health_pair = ' ●', 2
                                        elif container.get('health') == 'down':
                                            health_mark, health_pair = ' ✗', 4
                                    if health_mark and px + 3 + len(name) + len(health_mark) < px + pw:
                                        stdscr.addstr(py + line, px + 3 + len(name), health_mark,
                                                      curses.color_pair(health_pair))
                                    line += 1
                            
                            # Draw Kubernetes when present
                            if has_k8s and k8s_lines > 0 and line < ph:
                                pods_ok = k8s['pods_running']
                                pods_bad = k8s['pods_failed'] + k8s['pods_pending']
                                color = curses.color_pair(2) if pods_bad == 0 else curses.color_pair(3)
                                stdscr.addstr(py + line, px, "k8", curses.color_pair(5))
                                stdscr.addstr(py + line, px + 2, f"{pods_ok}", color | curses.A_BOLD)
                                if pods_bad > 0:
                                    stdscr.addstr(py + line, px + 2 + len(str(pods_ok)) + 1, f"!{pods_bad}", curses.color_pair(4))
                                line += 1
                                k8s_lines -= 1
                                
                                # List pods to fit the free space
                                pods_to_show = min(len(k8s['pods']), k8s_lines)
                                for pod in k8s['pods'][:pods_to_show]:
                                    if line >= ph:
                                        break
                                    name = pod['name'][:pw - 4]
                                    if pod['status'] == 'Running':
                                        stdscr.addstr(py + line, px + 1, f"● {name}", curses.color_pair(2))
                                    else:
                                        status_color = curses.color_pair(4) if pod['status'] in ('Failed', 'Error', 'CrashLoopBackOff') else curses.color_pair(3)
                                        stdscr.addstr(py + line, px + 1, f"! {name}", status_color)
                                    line += 1

                            # Draw security when present
                            if has_security and security_lines > 0 and line < ph:
                                failed = security.get('failed_logins', 0)
                                successful = security.get('successful_logins', 0)
                                total_logins = failed + successful

                                # Draw the security header with failed login count
                                color = curses.color_pair(2) if failed == 0 else curses.color_pair(3) if failed < 10 else curses.color_pair(4)
                                stdscr.addstr(py + line, px, "sec", curses.color_pair(5))
                                stdscr.addstr(py + line, px + 3, f" {failed}", color | curses.A_BOLD)
                                if total_logins > 0:
                                    stdscr.addstr(py + line, px + 3 + len(str(failed)), f"/{total_logins}", curses.color_pair(8))
                                line += 1
                                security_lines -= 1

                                # Draw the top suspect IPs
                                top_ips = security.get('top_ips', {})
                                ips_to_show = min(len(top_ips), security_lines)
                                for ip, count in list(top_ips.items())[:ips_to_show]:
                                    if line >= ph:
                                        break
                                    # Cut the IP to fit the width
                                    ip_display = ip[:pw - 6]
                                    count_str = f"×{count}"
                                    # Set the color from severity
                                    ip_color = curses.color_pair(4) if count >= 10 else curses.color_pair(3) if count >= 5 else curses.color_pair(2)
                                    stdscr.addstr(py + line, px, f" {ip_display}", ip_color)
                                    # Draw the count at right when space allows
                                    if len(ip_display) + len(count_str) + 2 < pw:
                                        stdscr.addstr(py + line, px + pw - len(count_str), count_str, curses.color_pair(8))
                                    line += 1

                            # With no Docker, Kubernetes, or security, show tasks
                            if not has_docker and not has_k8s and not has_security and line < ph:
                                # Draw each line, then move down. Do not test
                                # the next line here. The old test pushed
                                # the notes onto the process line.
                                stdscr.addstr(py + line, px, f"{proc['total']} tasks", curses.color_pair(7))
                                line += 1
                                if proc.get('top_cpu') and line < ph:
                                    top = proc['top_cpu'][:pw - 1]
                                    stdscr.addstr(py + line, px, top, curses.color_pair(3))
                                    line += 1

                                # State why Docker, Kubernetes, and security
                                # are absent. Do not show tasks alone.
                                notes = self._degraded_notes(
                                    [('docker', 'docker'), ('k8s', 'kubernetes'),
                                     ('security', 'security')])
                                actionable = any(c == 4 for _t, c in notes)
                                for text, color in notes:
                                    if line >= ph:
                                        break
                                    stdscr.addstr(py + line, px, text[:pw - 1],
                                                  curses.color_pair(color))
                                    line += 1
                                if actionable and line < ph:
                                    stdscr.addstr(py + line, px,
                                                  "press d to fix"[:pw - 1],
                                                  curses.color_pair(3))
                                    line += 1

                # === FOOTER ===
                footer_y = h - 1
                
                # Find alerts
                active_alerts = self.check_alerts(data)
                
                try:
                    col = 1
                    # Draw the keys
                    stdscr.addstr(footer_y, col, "q", curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(footer_y, col + 1, "uit ", curses.color_pair(8))
                    col += 5
                    stdscr.addstr(footer_y, col, "r", curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(footer_y, col + 1, "efresh ", curses.color_pair(8))
                    col += 8
                    stdscr.addstr(footer_y, col, "t", curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(footer_y, col + 1, "heme ", curses.color_pair(8))
                    col += 6
                    stdscr.addstr(footer_y, col, "l", curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(footer_y, col + 1, "ayout ", curses.color_pair(8))
                    col += 7
                    stdscr.addstr(footer_y, col, "h", curses.color_pair(3) | curses.A_BOLD)
                    stdscr.addstr(footer_y, col + 1, "elp ", curses.color_pair(8))
                    col += 5
                    stdscr.addstr(footer_y, col, "+/-", curses.color_pair(3) | curses.A_BOLD)
                    col += 4
                    
                    # Draw the theme, layout, and refresh rate
                    theme_text = f"[{self.theme_name}]"
                    stdscr.addstr(footer_y, col + 1, theme_text, curses.color_pair(1))
                    layout_text = f"[{self.layout_mode}]"
                    stdscr.addstr(footer_y, col + 2 + len(theme_text), layout_text, curses.color_pair(5))
                    rate_text = f"[{self.refresh_rate}s]"
                    stdscr.addstr(footer_y, col + 3 + len(theme_text) + len(layout_text), rate_text, curses.color_pair(2))

                    # Draw the update note when present (quiet, left of alerts)
                    update_x = col + 4 + len(theme_text) + len(layout_text) + len(rate_text)
                    if self._update_available and isinstance(self._update_available, str):
                        update_text = f" v{self._update_available} available "
                        if update_x + len(update_text) < w - 30:  # Leave room for alerts
                            stdscr.addstr(footer_y, update_x, update_text, curses.color_pair(2) | curses.A_DIM)

                    # Draw alerts at right. Use color only, no blink
                    # (blink costs speed and hurts use)
                    if active_alerts:
                        alert_x = w - 2
                        for alert_name, alert_val, alert_type in reversed(active_alerts[:3]):
                            alert_text = f" {alert_name} "
                            alert_x -= len(alert_text)
                            color = curses.color_pair(4) if alert_type == 'danger' else curses.color_pair(3)
                            stdscr.addstr(footer_y, alert_x, alert_text, color | curses.A_BOLD | curses.A_REVERSE)
                except curses.error:
                    pass

                # Draw the help overlay when active
                if self._show_help:
                    self.draw_help_modal(stdscr, h, w)
                
                # Draw the diagnostics overlay when active
                if self._show_diagnostics:
                    self.draw_diagnostics_modal(stdscr, h, w)

                stdscr.refresh()

                # Read the next key
                stdscr.timeout(self._input_timeout_ms())
                if self._handle_key(stdscr, stdscr.getch()):
                    break

            except curses.error:
                pass
            except Exception as e:
                with open('/tmp/sentinel.log', 'a') as f:
                    f.write(f"{datetime.now()}: {e}\n")


def dump_snapshot(config):
    """Print one JSON status line and exit (--dump).

    Fleet mode (--host) runs this probe on each remote node through SSH.
    The remote side needs only python3 and this one file. It reuses the
    same readers as the TUI (SentinelMonitor). So the fleet table and
    the local panel can never define a metric two ways.

    The snapshot uses only fast sync reads (/proc, /sys, statvfs, and
    the unix-socket Docker API). It starts no collector, makes no
    network call, and starts no thread. So it stays cheap enough to
    run each fleet refresh.
    """
    monitor = SentinelMonitor(config=config, service_mode=True)
    try:
        # Only the smallest sync readers run here (cpu, mem, uptime).
        # The rest (disk statvfs, network sysfs, collectors) is optional
        # or OS-gated below. --dump must send JSON even on a broken or
        # foreign host. It must never send a traceback.
        try:
            cpu = monitor.get_cpu_info()
        except Exception:  # noqa: BLE001 - probe always sends JSON
            cpu = {'usage': 0.0, 'load': [0.0, 0.0, 0.0]}
        try:
            mem = monitor.get_memory_info()
        except Exception:  # noqa: BLE001 - probe always sends JSON
            mem = {'percent': 0.0}
        # Docker and Kubernetes use argv-list paths with no call where
        # possible. Start no collector here.
        try:
            docker_data = DockerClient(timeout=5).containers()
            docker = {'available': True, **docker_data}
        except DockerError as e:
            docker = {'available': False, 'running': 0, 'stopped': 0,
                      'total': 0, 'error': e.state, 'detail': e.detail}
        except Exception as e:  # always send JSON from --dump
            docker = {'available': False, 'running': 0, 'stopped': 0,
                      'total': 0, 'error': 'error', 'detail': str(e)}
        k8s = {'available': False, 'pods_running': 0, 'pods_pending': 0,
               'pods_failed': 0}
        kubectl_path = shutil.which('kubectl')
        if kubectl_path is not None:
            try:
                out = subprocess.run(
                    [kubectl_path, 'get', 'pods', '-A', '--no-headers'],
                    shell=False, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, text=True,
                    timeout=10).stdout.strip()
                if out:
                    k8s['available'] = True
                    for line in out.split('\n'):
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        status = parts[3]
                        if status == 'Running':
                            k8s['pods_running'] += 1
                        elif status == 'Pending':
                            k8s['pods_pending'] += 1
                        elif status in ('Failed', 'Error', 'CrashLoopBackOff'):
                            k8s['pods_failed'] += 1
            except (OSError, subprocess.SubprocessError, ValueError):
                pass
        try:
            days, hours, mins = monitor.get_uptime()
        except Exception:  # noqa: BLE001 - probe always sends JSON
            days, hours, mins = 0, 0, 0
        try:
            data = monitor.update_data()
            alerts = [{'name': name, 'value': value, 'severity': severity}
                      for name, value, severity in monitor.check_alerts(data)]
            health = data.get('health', {}) or {}
        except Exception:  # noqa: BLE001 - probe always sends JSON
            alerts = []
            health = {}
        snapshot = {
            'sentinel_version': VERSION,
            'hostname': monitor.hostname,
            'cpu_percent': round(cpu.get('usage', 0.0), 1),
            'mem_percent': round(mem.get('percent', 0.0), 1),
            'load': cpu.get('load', [0.0, 0.0, 0.0]),
            'uptime': f"{days}d {hours}h {mins}m",
            'containers_running': docker.get('running', 0),
            'containers_total': docker.get('total', 0),
            'docker_available': docker.get('available', False),
            'pods_running': k8s.get('pods_running', 0),
            'pods_pending': k8s.get('pods_pending', 0),
            'pods_failed': k8s.get('pods_failed', 0),
            'k8s_available': k8s.get('available', False),
            'alert_count': len(alerts),
            'alerts': alerts[:5],
            'health_healthy': health.get('healthy', 0),
            'health_down': health.get('down', 0),
            'health_listeners': health.get('listeners', {}),
        }
        print(json.dumps(snapshot))
    finally:
        monitor.stop_collectors()


# ---------------------------------------------------------------------------
# Fleet mode (v0.6.1): one-screen view of many hosts through plain SSH.
#
# Why it looks like this:
# - No agent, no daemon, no new package. The probe command is
#   `python3 <sentinel-path> --dump`. It prints one JSON line. The
#   remote side needs only python3 and this file.
# - `ssh` stays an argv-list call (never shell=True). Host names come
#   from a user-edited JSON file. They must not read as shell code.
# - Refresh uses parallel threads (one per host, 15s timeout). So one
#   dead host cannot stall the table. Results land in a locked map.
#   The curses loop reads only the latest snapshot.
# ---------------------------------------------------------------------------

FLEET_PROBE_TIMEOUT = 15


def load_hosts_file(path):
    """Read and check a fleet hosts file.

    Take {"nodes": [...]} or a bare [...] list. Each node needs at least
    "host" (or "name", used as SSH target when "host" is missing).
    "name", "user", "port", and "key" are optional. Return (nodes, error).
    nodes holds normalized maps. error is None on success.

    Skip bad entries, never stop: one bad line must not hide the rest
    of the fleet.
    """
    try:
        with open(os.path.expanduser(path), 'r') as f:
            raw = json.load(f)
    except OSError as e:
        return [], f"cannot read {path}: {e}"
    except ValueError as e:
        return [], f"{path}: invalid JSON: {e}"
    entries = raw.get('nodes') if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        return [], (f"{path}: expected {{\"nodes\": [...]}} "
                     "or a bare [...] list")
    nodes = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        target = entry.get('host') or entry.get('name')
        if not target:
            continue
        try:
            port = int(entry.get('port', 22))
        except (TypeError, ValueError):
            continue
        nodes.append({
            'name': str(entry.get('name') or target),
            'host': str(target),
            'user': str(entry.get('user') or ''),
            'port': port,
            'key': str(entry.get('key') or ''),
            'index': i,
        })
    if not nodes:
        return [], f"{path}: no usable nodes (each needs a host or name)"
    return nodes, None


def fleet_probe_host(node, sentinel_path, timeout=FLEET_PROBE_TIMEOUT):
    """Ask one node for its --dump snapshot through SSH. Return the map.

    Never raise: report each failure (timeout, auth, missing python3,
    bad JSON) as {'ok': False, 'error': ...}. Then the table can show
    why a host is dark. It does not hide the host.
    """
    target = node['host']
    if node['user']:
        target = f"{node['user']}@{target}"
    argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
            '-p', str(node['port'])]
    if node['key']:
        argv += ['-i', os.path.expanduser(node['key'])]
    argv += [target, 'python3', sentinel_path, '--dump']
    try:
        proc = subprocess.run(
            argv, shell=False, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': f'timeout after {timeout}s'}
    except OSError as e:
        if 'ssh' in str(e).lower() or isinstance(e, FileNotFoundError):
            return {'ok': False, 'error': 'ssh binary not found in PATH'}
        return {'ok': False, 'error': f'cannot spawn ssh: {e}'}
    if proc.returncode != 0:
        err = (proc.stderr or '').strip().split('\n')
        detail = err[-1][:100] if err and err[-1] else f'exit {proc.returncode}'
        return {'ok': False, 'error': detail}
    try:
        data = json.loads((proc.stdout or '').strip().split('\n')[-1])
    except (ValueError, IndexError) as e:
        return {'ok': False, 'error': f'bad probe JSON: {e}'}
    if not isinstance(data, dict):
        return {'ok': False, 'error': 'bad probe JSON: not an object'}
    data['ok'] = True
    return data


class FleetMonitor:
    """Fleet view TUI: parallel SSH snapshots in one table to select from."""

    def __init__(self, config=None, nodes=None, hosts_path='',
                 sentinel_path='sentinel-monitor.py'):
        self.config = config or load_config()
        self.nodes = nodes or []
        self.hosts_path = hosts_path
        # Remote path: how the remote shell finds this same file.
        self.sentinel_path = sentinel_path
        self.theme_name = self.config.get('theme', 'default')
        self.results = {}   # node name -> snapshot dict
        self.errors = {}    # node name -> error string (unreachable detail)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self.selected = 0
        self.last_refresh = 0.0
        self.refreshing = False

    def refresh(self, force=False):
        """Ask all hosts again in parallel (one daemon thread per host).

        force=True skips the 30s guard (the `r` key). Threads are daemonic
        with a hard SSH timeout. So a dead host slows only its own row,
        never the table and never process exit.
        """
        now = time.time()
        if not force and now - self.last_refresh < 30:
            return
        self.last_refresh = now
        self.refreshing = True

        def _probe(node):
            snap = fleet_probe_host(node, self.sentinel_path)
            with self._lock:
                if snap.get('ok'):
                    self.results[node['name']] = snap
                    self.errors.pop(node['name'], None)
                else:
                    self.errors[node['name']] = snap.get('error', 'unknown')
                if len(self.results) + len(self.errors) >= len(self.nodes):
                    self.refreshing = False

        for node in self.nodes:
            threading.Thread(target=_probe, args=(node,),
                             name=f'sentinel-fleet-{node["name"]}',
                             daemon=True).start()

    def _row_state(self, node):
        """Return (snapshot-or-None, error-or-None) for one node."""
        with self._lock:
            return (self.results.get(node['name']),
                    self.errors.get(node['name']))

    def draw(self, stdscr):
        """Run the fleet table. j, k, and arrows move. r refreshes. Enter
        opens SSH to the marked host. q quits."""
        curses.curs_set(0)
        self.setup_colors()
        self.refresh(force=True)
        while True:
            try:
                h, w = stdscr.getmaxyx()
                stdscr.erase()
                self._draw_table(stdscr, h, w)
                stdscr.refresh()
                stdscr.timeout(1000)
                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    break
                elif key in (ord('r'), ord('R')):
                    self.refresh(force=True)
                elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
                    self.selected = min(len(self.nodes) - 1, self.selected + 1)
                elif key in (curses.KEY_UP, ord('k'), ord('K')):
                    self.selected = max(0, self.selected - 1)
                elif key in (curses.KEY_ENTER, 10, 13):
                    self._ssh_into_selected(stdscr)
                elif key == curses.KEY_RESIZE:
                    pass
            except curses.error:
                pass
            except Exception as e:
                with open('/tmp/sentinel.log', 'a') as f:
                    f.write(f"{datetime.now()}: fleet: {e}\n")

    def _ssh_into_selected(self, stdscr):
        """Stop curses. Open SSH with the local terminal. Then resume. The
        remote command starts Sentinel there when present. If not, it
        opens a plain shell."""
        if not self.nodes:
            return
        node = self.nodes[self.selected]
        target = node['host']
        if node['user']:
            target = f"{node['user']}@{target}"
        remote_cmd = (
            f"if [ -f {shlex.quote(self.sentinel_path)} ]; then "
            f"python3 {shlex.quote(self.sentinel_path)}; else "
            f"echo 'sentinel not found at {self.sentinel_path}, "
            "dropping to shell'; exec $SHELL -l; fi")
        argv = ['ssh', '-p', str(node['port'])]
        if node['key']:
            argv += ['-i', os.path.expanduser(node['key'])]
        argv += ['-t', target, remote_cmd]
        curses.endwin()
        try:
            subprocess.run(argv)
        except OSError:
            pass
        finally:
            stdscr.refresh()

    def setup_colors(self):
        theme = THEMES.get(self.theme_name, THEMES['default'])
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, theme['primary'], -1)
        curses.init_pair(2, theme['success'], -1)
        curses.init_pair(3, theme['warning'], -1)
        curses.init_pair(4, theme['danger'], -1)
        curses.init_pair(7, theme['text'], -1)
        curses.init_pair(8, theme['muted'], -1)

    def _draw_table(self, stdscr, h, w):
        # Draw the header
        try:
            stdscr.addstr(0, 1, 'sentinel', curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 10, f"v{VERSION}", curses.color_pair(8))
            title = f"fleet: {self.hosts_path} ({len(self.nodes)} hosts)"
            stdscr.addstr(0, 20, title[:max(0, w - 32)],
                          curses.color_pair(7) | curses.A_BOLD)
            if self.refreshing:
                stdscr.addstr(0, w - 15, 'refreshing...', curses.color_pair(3))
            else:
                ts = datetime.now().strftime('%H:%M:%S')
                stdscr.addstr(0, w - len(ts) - 1, ts, curses.color_pair(8))
        except curses.error:
            pass
        # Draw the column header
        cols = '  {:<16} {:>5} {:>5} {:>14} {:>10} {:>6} {:>4}  {}'
        try:
            stdscr.addstr(2, 0, cols.format(
                'HOST', 'CPU%', 'MEM%', 'LOAD', 'UPTIME', 'CTNRS',
                'PODS', 'ALERTS / STATUS')[:w], curses.color_pair(8))
        except curses.error:
            pass
        # Draw the rows
        for i, node in enumerate(self.nodes):
            y = 3 + i
            if y >= h - 2:
                break
            snap, err = self._row_state(node)
            if snap is not None:
                alert_n = snap.get('alert_count', 0)
                health_down = snap.get('health_down', 0)
                health_healthy = snap.get('health_healthy', 0)
                if health_down > 0:
                    health_mark = f" ✗{health_down}"
                elif health_healthy > 0:
                    health_mark = f" ●{health_healthy}"
                else:
                    health_mark = ''
                if alert_n > 0:
                    state = f"{alert_n} alert{'s' if alert_n != 1 else ''}{health_mark}"
                else:
                    state = ('ok' + health_mark) if health_mark else 'ok'
                line = cols.format(
                    node['name'][:16],
                    f"{snap.get('cpu_percent', 0.0):.0f}",
                    f"{snap.get('mem_percent', 0.0):.0f}",
                    ','.join(f"{v:.2f}" for v in
                              (snap.get('load') or [0, 0, 0])[:3]),
                    snap.get('uptime', '?')[:10],
                    (f"{snap.get('containers_running', 0)}/"
                     f"{snap.get('containers_total', 0)}"),
                    str(snap.get('pods_running', 0)),
                    state)[:w]
                color = (curses.color_pair(4) if (alert_n > 0 or health_down > 0)
                         else curses.color_pair(2))
            elif err is not None:
                line = cols.format(node['name'][:16], '-', '-', '-',
                                   '-', '-', '-', f'ERR: {err}'[:40])[:w]
                color = curses.color_pair(4)
            else:
                line = cols.format(node['name'][:16], '?', '?', '?', '?',
                                   '?', '?', 'probing...')[:w]
                color = curses.color_pair(8)
            try:
                attr = color | curses.A_REVERSE if i == self.selected else color
                stdscr.addstr(y, 0, line.ljust(max(0, w - 1))[:max(0, w - 1)],
                              attr)
            except curses.error:
                pass
        # Footer
        try:
            footer = ('j/k select  Enter ssh  r refresh  q quit'
                      + ('  |  remote: ' + self.sentinel_path
                         if w > 90 else ''))
            stdscr.addstr(h - 1, 1, footer[:w - 2], curses.color_pair(8))
        except curses.error:
            pass


def run_fleet_mode(config, hosts_path, sentinel_path):
    """Start here for --host: check the hosts file, then run the table."""
    nodes, error = load_hosts_file(hosts_path)
    if error is not None:
        print(f"Error: {error}")
        return
    if shutil.which('ssh') is None:
        print("Error: ssh binary not found in PATH "
              "(fleet mode shells out to OpenSSH).")
        return
    print(f"Sentinel v{VERSION} - Fleet Mode ({len(nodes)} hosts)")
    print(f"Hosts file: {hosts_path}")
    print("Probing hosts (15s timeout each, in parallel)...")
    fleet = FleetMonitor(config=config, nodes=nodes,
                         hosts_path=hosts_path,
                         sentinel_path=sentinel_path)
    try:
        curses.wrapper(fleet.draw)
    except KeyboardInterrupt:
        pass


def run_service_mode(config):
    """Run headless service mode. Write to the log file and stdout."""
    import signal
    
    log_file = config.get('log_file', '/var/log/sentinel.log')
    interval = config.get('refresh_rate', 2)
    
    monitor = SentinelMonitor(config=config, service_mode=True)
    running = True
    
    def handle_signal(signum, frame):
        nonlocal running
        running = False
    
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    
    print(f"Sentinel v{VERSION} - Service Mode")
    print(f"Logging to: {log_file}")
    print(f"Refresh interval: {interval}s")
    print("-" * 40)
    
    while running:
        try:
            data = monitor.update_data()
            alerts = monitor.check_alerts(data)
            
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cpu = data['cpu']
            mem = data['mem']
            energy = data['energy']
            
            # Build the log line
            log_line = (
                f"{timestamp} | "
                f"CPU: {cpu['usage']:5.1f}% {cpu['temp']:4.1f}°C | "
                f"MEM: {mem['percent']:5.1f}% | "
            )
            
            if energy['available']:
                log_line += f"PWR: {energy['power_watts']:5.1f}W | "
            
            if alerts:
                alert_str = ", ".join([f"{a[0]}:{a[1]}" for a in alerts])
                log_line += f"ALERTS: {alert_str}"
            else:
                log_line += "OK"
            
            # Write to stdout and also to the file when possible
            print(log_line)
            
            try:
                with open(log_file, 'a') as f:
                    f.write(log_line + "\n")
            except PermissionError:
                pass  # No write to the log file. Use stdout only
            
            time.sleep(interval)
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(interval)
    
    monitor.stop_collectors()
    print("\nSentinel service stopped.")


def main():
    parser = argparse.ArgumentParser(
        description=f'Sentinel v{VERSION} - Universal Linux System Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel                    # Open the interactive panel
  sentinel --theme nord       # Use the Nord color theme
  sentinel --light            # Light mode (low-end VMs, Pi3)
  sentinel --service          # Run headless (service mode)
  sentinel --init-config      # Create the default configuration file
  sentinel --dump             # Print one JSON status line (fleet probe)
  sentinel --host hosts.json  # Show the fleet view of many hosts through SSH

Fleet hosts file (--host): {"nodes": [{"name": "pi4", "host": "192.168.1.10",
  "user": "pi", "port": 22, "key": "~/.ssh/id_rsa"}]}. Each node needs this
same file at --sentinel-path on the remote side. Default: the same
relative path as local. So copy sentinel-monitor.py there first.

Themes: default, nord, dracula, gruvbox, monokai

Configuration file paths (first match wins):
  ~/.config/sentinel/config.json
  ~/.sentinel.json
  /etc/sentinel/config.json
"""
    )
    
    parser.add_argument('--version', action='version', version=f'Sentinel v{VERSION}')
    parser.add_argument('--theme', '-t', choices=list(THEMES.keys()), 
                        help='Set the color theme')
    parser.add_argument('--service', '-s', action='store_true',
                        help='Run headless (service mode for systemd)')
    parser.add_argument('--init-config', action='store_true',
                        help='Create the default configuration file')
    parser.add_argument('--config', '-c', type=str,
                        help='Read the configuration file at this path')
    parser.add_argument('--light', action='store_true',
                        help='Use light mode: short history, slow refresh, '
                             'small data set (for low-end VMs)')
    parser.add_argument('--dump', action='store_true',
                        help='Print one JSON status line to stdout and exit '
                             '(probe for --host fleet mode)')
    parser.add_argument('--host', type=str, metavar='HOSTS_FILE',
                        help='Show the fleet view of many hosts through SSH '
                             '(JSON file with {"nodes": [{"name", "host", "user", "port", "key"}]})')
    parser.add_argument('--sentinel-path', type=str,
                        default='sentinel-monitor.py',
                        help='Remote path of sentinel-monitor.py on fleet '
                             'hosts (default: sentinel-monitor.py)')
    
    args = parser.parse_args()
    
    # Handle --init-config
    if args.init_config:
        config_path = save_default_config()
        print(f"Created default configuration file at: {config_path}")
        print("\nYou can change:")
        print("  - theme: default, nord, dracula, gruvbox, monokai")
        print("  - alerts: cpu_high, cpu_critical, mem_high, temp_high, and more")
        print("  - light_mode: true/false (light defaults for small machines)")
        print("  - refresh_rate: refresh interval in seconds")
        return
    
    # Read the configuration file
    config = load_config()
    
    # Take values from command line args
    if args.theme:
        config['theme'] = args.theme
    
    if args.light:
        config['light_mode'] = True
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            print(f"Error reading the configuration file: {e}")
            return
    
    # Pick the run mode (--dump and --host first: fleet calls must work
    # even where curses is missing or /proc is absent, as on probe targets)
    if args.dump:
        dump_snapshot(config)
    elif args.host:
        run_fleet_mode(config, args.host, args.sentinel_path)
    elif args.service:
        run_service_mode(config)
    else:
        monitor = None
        try:
            monitor = SentinelMonitor(config=config)
            curses.wrapper(monitor.draw)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if monitor is not None:
                monitor.stop_collectors()


if __name__ == "__main__":
    main()
