#!/usr/bin/env python3
"""
Sentinel v0.4 - Universal Linux System Monitor
A beautiful, real-time single-screen TUI dashboard for homelab monitoring

Features:
- Single-screen adaptive layout (fits any terminal size)
- Multiple layout modes: default, cpu, network, docker, minimal (press L)
- Dynamic Docker/K8s container lists (auto-adjusts to available space)
- Docker volumes with actual names and sizes
- Energy consumption monitoring (RAPL for desktops, battery for laptops)
- Reverse proxy traffic monitoring (nginx/caddy access logs)
- Enhanced network panel with signal meter, VPN handshake age, link speed
- Performance optimized (direct /proc and /sys reads, minimal subprocesses)
- Enhanced visuals with braille sparklines and gradient colors
- Adjustable refresh rate (1-10 seconds, press +/-)
- Config file support with custom themes and alert thresholds
- Systemd service mode for headless logging

Controls:
- q: Quit
- r: Refresh data now
- t: Cycle themes (default, nord, dracula, gruvbox, monokai)
- l: Cycle layouts (default, cpu, network, docker, minimal)
- h: Toggle help overlay
- i: Refresh public IP
- +/-: Adjust refresh rate (faster/slower)

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
from datetime import datetime, timedelta
from collections import deque
from pathlib import Path

VERSION = "0.5.0"

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
    """Load configuration from file or return defaults."""
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
                    # Merge with defaults
                    for key, value in user_config.items():
                        if isinstance(value, dict) and key in config:
                            config[key].update(value)
                        else:
                            config[key] = value
                    config['_loaded_from'] = str(config_path)
                    break
            except Exception as e:
                pass
    
    return config


def save_default_config():
    """Save default config to user's config directory."""
    config_dir = Path.home() / '.config' / 'sentinel'
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / 'config.json'
    
    with open(config_path, 'w') as f:
        json.dump(DEFAULT_CONFIG, f, indent=2)
    
    return config_path

class SentinelMonitor:
    """High-performance system monitor with single-screen adaptive layout."""

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
        
        # Network tracking
        self.last_net_bytes = {'rx': 0, 'tx': 0, 'time': time.time()}
        self.default_iface = self._detect_default_interface()
        
        # CPU tracking for accurate delta calculation
        self.last_cpu_times = None
        
        # RAPL energy tracking (for desktops/servers without battery)
        self.last_rapl = {'energy': 0, 'time': time.time()}
        self.rapl_path = self._detect_rapl_path()
        self.power_history = deque([0] * 100, maxlen=100)
        
        # History for sparklines (100 points to fill wide terminals)
        self.cpu_history = deque([0] * 100, maxlen=100)
        self.mem_history = deque([0] * 100, maxlen=100)
        self.rx_history = deque([0] * 100, maxlen=100)
        self.tx_history = deque([0] * 100, maxlen=100)
        
        # Cache CPU model (doesn't change)
        self.cpu_model = self._get_cpu_model()
        self.cpu_cores = os.cpu_count() or 1
        
        # Startup optimization: cache tool availability checks
        self._docker_available = None
        self._kubectl_available = None
        self._first_render = True  # Skip expensive ops on first frame
        self._loading = False  # Loading state for modal
        self._show_help = False  # Help overlay toggle
        
        # Layout mode
        self.layout_mode = self.config.get('layout', 'default')
        
        # Dynamic refresh rate (can be adjusted with +/-)
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

        # Update checker (non-blocking, checks once per day)
        self._update_available = None  # None=unknown, False=up-to-date, version string=available
        self._last_update_check = 0
        self._update_check_interval = 86400  # 24 hours
        self._compiled_regex = {}  # Cache compiled regex patterns for performance

    def _detect_default_interface(self):
        """Detect default network interface from routing table."""
        try:
            with open('/proc/net/route', 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] == '00000000':
                        return parts[0]
        except:
            pass
        return None

    def _detect_rapl_path(self):
        """Detect Intel/AMD RAPL energy path for power monitoring."""
        rapl_paths = [
            '/sys/class/powercap/intel-rapl/intel-rapl:0/energy_uj',
            '/sys/class/powercap/intel-rapl:0/energy_uj',
            '/sys/devices/virtual/powercap/intel-rapl/intel-rapl:0/energy_uj',
        ]
        for path in rapl_paths:
            if os.path.exists(path):
                return path
        # Check for AMD
        amd_path = '/sys/class/powercap/amd-rapl/amd-rapl:0/energy_uj'
        if os.path.exists(amd_path):
            return amd_path
        return None

    def _get_cpu_model(self):
        """Get CPU model name (cached, only called once)."""
        try:
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        model = line.split(':', 1)[1].strip()
                        # Clean up common cruft
                        for remove in ['(R)', '(TM)', 'CPU', '  ']:
                            model = model.replace(remove, ' ' if remove == '  ' else '')
                        return ' '.join(model.split())[:40]
        except:
            pass
        return "Unknown CPU"

    def run_cmd(self, cmd, timeout=1):
        """Run shell command and return output"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout.strip()
        except:
            return ""

    def read_sys_file(self, path, cast=str):
        """Read a value from /sys and optionally cast it"""
        try:
            with open(path, "r") as f:
                value = f.read().strip()
                return cast(value) if value and cast else value
        except:
            return None

    def get_cpu_info(self):
        """Get CPU information - optimized with direct /proc reads."""
        # Calculate CPU usage from /proc/stat (much faster than top)
        try:
            with open('/proc/stat', 'r') as f:
                line = f.readline()
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
        except:
            cpu_usage = 0.0
        
        self.cpu_history.append(cpu_usage)

        # Get CPU temperature from hwmon (faster than sensors command)
        cpu_temp = self._get_cpu_temp()

        # Get CPU frequency from /proc/cpuinfo
        cpu_freq = self._get_cpu_freq()

        # Get fan RPM
        fan_rpm = self._get_fan_rpm()

        # Read governor and EPP from sysfs
        cpu_gov = self.read_sys_file('/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor') or "N/A"
        cpu_epp = self.read_sys_file('/sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference') or ""
        cpu_epp = cpu_epp.replace("balance_", "bal").replace("_", "-") if cpu_epp else "N/A"

        # Load average from /proc/loadavg
        try:
            with open('/proc/loadavg', 'r') as f:
                loads = f.read().split()[:3]
                load_avg = [float(x) for x in loads]
        except:
            load_avg = [0.0, 0.0, 0.0]

        # Determine CPU status based on frequency
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
        """Get per-core CPU usage from /proc/stat."""
        try:
            with open('/proc/stat', 'r') as f:
                lines = f.readlines()
            
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
        except:
            return [0.0] * self.cpu_cores

    def _get_cpu_temp(self):
        """Get CPU temperature from hwmon sysfs (faster than sensors)."""
        # Try thermal zones first (works on ARM, VMs, containers)
        thermal_zone = Path('/sys/class/thermal/thermal_zone0/temp')
        if thermal_zone.exists():
            try:
                temp = int(thermal_zone.read_text().strip())
                return temp / 1000.0
            except:
                pass
        
        hwmon_base = Path('/sys/class/hwmon')
        if not hwmon_base.exists():
            return 0.0
        
        try:
            for hwmon in hwmon_base.iterdir():
                name_file = hwmon / 'name'
                if name_file.exists():
                    name = name_file.read_text().strip()
                    # Look for CPU thermal sensors (expanded list)
                    if name in ('coretemp', 'k10temp', 'zenpower', 'acpitz', 'thinkpad', 
                                'cpu_thermal', 'soc_thermal', 'armada_thermal', 'rpi_thermal'):
                        # Try temp1_input first (package temp), then others
                        for temp_file in ['temp1_input', 'temp2_input', 'temp3_input']:
                            temp_path = hwmon / temp_file
                            if temp_path.exists():
                                temp = int(temp_path.read_text().strip())
                                return temp / 1000.0  # Convert from millidegrees
                
                # Fallback: check any temp*_input in hwmon
                for temp_file in sorted(hwmon.glob('temp*_input')):
                    try:
                        temp = int(temp_file.read_text().strip())
                        if temp > 0:
                            return temp / 1000.0
                    except:
                        continue
        except:
            pass
        return 0.0

    def _get_cpu_freq(self):
        """Get average CPU frequency from /proc/cpuinfo."""
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
        except:
            return 0.0

    def _get_fan_rpm(self):
        """Get fan RPM from hwmon sysfs."""
        hwmon_base = Path('/sys/class/hwmon')
        if not hwmon_base.exists():
            return 0
        
        try:
            for hwmon in hwmon_base.iterdir():
                for fan_file in hwmon.glob('fan*_input'):
                    rpm = int(fan_file.read_text().strip())
                    if rpm > 0:
                        return rpm
        except:
            pass
        return 0

    def get_memory_info(self):
        """Get memory usage - optimized with direct /proc/meminfo read."""
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
        except:
            return {'used': 0, 'total': 0, 'available': 0, 'percent': 0}

    def get_battery_info(self):
        """Get battery information"""
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

            # Determine whether charge_* or energy_* is available
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
        except:
            return {'exists': False}

    def get_disk_usage(self):
        """Get disk usage - optimized with os.statvfs (no subprocess)."""
        disks = []
        
        def format_size(b):
            for unit in ['B', 'K', 'M', 'G', 'T']:
                if b < 1024:
                    return f"{b:.0f}{unit}" if unit == 'B' else f"{b:.1f}{unit}"
                b /= 1024
            return f"{b:.1f}P"
        
        # Regular mount points
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
                    'used': format_size(used_bytes),
                    'total': format_size(total_bytes),
                    'percent': percent,
                    'type': 'disk'
                })
            except:
                pass
        
        # Docker volumes (if Docker is available)
        docker_volumes = self._get_docker_volumes()
        if docker_volumes:
            disks.extend(docker_volumes)
        
        return disks

    def _get_docker_volumes(self):
        """Get Docker volume usage information."""
        volumes = []
        
        if not os.path.exists('/var/run/docker.sock'):
            return volumes
        
        try:
            # Get volume sizes using docker system df -v (volumes section)
            output = self.run_cmd("docker system df -v 2>/dev/null")
            if output and "permission denied" not in output.lower():
                in_volumes = False
                for line in output.strip().split('\n'):
                    # Look for VOLUME NAME header
                    if 'VOLUME NAME' in line:
                        in_volumes = True
                        continue
                    # Stop at next section (empty line or new header)
                    if in_volumes:
                        if not line.strip() or line.startswith('REPOSITORY') or line.startswith('CONTAINER'):
                            break
                        parts = line.split()
                        if len(parts) >= 2:
                            name = parts[0][:14]
                            # Size is typically the 3rd column (after LINKS)
                            size = parts[-1] if len(parts) >= 3 else '—'
                            volumes.append({
                                'mount': name,
                                'used': size,
                                'total': '',
                                'percent': 0,
                                'type': 'docker'
                            })
                if volumes:
                    return volumes[:5]  # Limit to 5 volumes
            
            # Fallback: get volume names and try to get sizes individually
            output = self.run_cmd("docker volume ls --format '{{.Name}}' 2>/dev/null")
            if not output or "permission denied" in output.lower():
                return volumes
            
            vol_names = output.strip().split('\n') if output.strip() else []
            for name in vol_names[:5]:
                if not name:
                    continue
                # Try to get size via inspect
                size_out = self.run_cmd(f"docker system df -v 2>/dev/null | grep -E '^{name[:20]}' | awk '{{print $NF}}'")
                size = size_out.strip() if size_out and size_out.strip() else '—'
                volumes.append({
                    'mount': name[:14],
                    'used': size,
                    'total': '',
                    'percent': 0,
                    'type': 'docker'
                })
        except:
            pass
        
        return volumes

    def get_energy_info(self):
        """Get system energy consumption (RAPL for desktops, battery for laptops)."""
        energy = {
            'source': None,
            'power_watts': 0.0,
            'available': False
        }
        
        # Try RAPL first (works on desktops/servers with Intel/AMD CPUs)
        if self.rapl_path and os.path.exists(self.rapl_path):
            try:
                current_energy = int(Path(self.rapl_path).read_text().strip())
                current_time = time.time()
                
                time_delta = current_time - self.last_rapl['time']
                if time_delta > 0 and self.last_rapl['energy'] > 0:
                    # Energy is in microjoules, convert to watts
                    energy_delta = current_energy - self.last_rapl['energy']
                    # Handle counter overflow
                    if energy_delta < 0:
                        energy_delta = current_energy
                    power_watts = (energy_delta / 1_000_000) / time_delta
                    energy['power_watts'] = power_watts
                    energy['available'] = True
                    energy['source'] = 'rapl'
                
                self.last_rapl = {'energy': current_energy, 'time': current_time}
                self.power_history.append(energy['power_watts'])
            except:
                pass
        
        # If no RAPL, check for battery power draw
        if not energy['available']:
            battery = self.get_battery_info()
            if battery.get('exists') and battery.get('power', 0) > 0:
                energy['power_watts'] = battery['power']
                energy['available'] = True
                energy['source'] = 'battery'
                self.power_history.append(energy['power_watts'])
        
        return energy

    def get_network_info(self):
        """Get network information - optimized with direct sysfs reads."""
        default_iface = self.default_iface
        vpn_connections = self.get_vpn_connections()

        # Get local IP from /proc/net/fib_trie or fallback to socket
        local_ip = self._get_local_ip(default_iface)
        
        # Check WireGuard
        wg_ip = self.read_sys_file('/sys/class/net/wg0/address') if os.path.exists('/sys/class/net/wg0') else None
        wg_active = os.path.exists('/sys/class/net/wg0')

        public_ip = getattr(self, '_public_ip_cache', "Checking...")

        current_time = time.time()
        rx_speed = tx_speed = 0
        rx_total = tx_total = 0
        
        if default_iface:
            # Direct sysfs read for network stats
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

        # Connection state from sysfs
        operstate = self.read_sys_file(f'/sys/class/net/{default_iface}/operstate') if default_iface else ""
        carrier = self.read_sys_file(f'/sys/class/net/{default_iface}/carrier') if default_iface else ""
        wired_connected = carrier == "1" if carrier else operstate == "up"
        link_speed_val = self.read_sys_file(f'/sys/class/net/{default_iface}/speed', int) if default_iface else None

        # Connection type detection
        conn_type = ""
        if default_iface:
            if default_iface.startswith(("en", "eth")):
                conn_type = "wired"
            elif default_iface.startswith(("wl", "wi")):
                conn_type = "wireless"
            else:
                conn_type = "virtual"

        ssid = self.run_cmd("iwgetid -r 2>/dev/null") if conn_type == "wireless" else ""

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
        """Get local IP address for interface."""
        if not iface:
            return "N/A"
        try:
            # Try to get IP from socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "N/A"

    def get_vpn_connections(self):
        """Return WireGuard peers with quick stats"""
        dump, permission_denied = self.get_wireguard_dump()
        self.wg_permission_denied = permission_denied and not dump
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
                except:
                    return 0

            handshake = safe_int(parts[5])
            rx = safe_int(parts[6])
            tx = safe_int(parts[7])
            keepalive = parts[8] if len(parts) > 8 else ""

            handshake_age = (now - handshake) if handshake else None
            connected = handshake_age is not None and handshake_age < 180
            
            # Format handshake age as latency indicator
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

    def get_wireguard_dump(self):
        """Return raw wg dump output, attempting sudo if necessary"""
        commands = [
            "wg show all dump 2>&1",
            "sudo -n wg show all dump 2>&1"
        ]
        permission_seen = False
        for cmd in commands:
            output = self.run_cmd(cmd)
            if not output:
                continue
            lower = output.lower()
            if "operation not permitted" in lower or "permission denied" in lower or "password is required" in lower:
                permission_seen = True
                continue
            return output, False
        return "", permission_seen

    def get_public_ip(self):
        """Get public IP"""
        try:
            ip = self.run_cmd("curl -s --max-time 2 ifconfig.me 2>/dev/null || curl -s --max-time 2 icanhazip.com")
            if ip and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                self._public_ip_cache = ip
            else:
                self._public_ip_cache = "N/A"
        except:
            self._public_ip_cache = "N/A"

    def get_processes(self):
        """Get process information - optimized with /proc reads."""
        try:
            # Count processes from /proc
            total = len([d for d in os.listdir('/proc') if d.isdigit()])
        except:
            total = 0
        
        # Cache top processes - only update every 5 seconds (expensive ps calls)
        current_time = time.time()
        if not hasattr(self, '_last_proc_check') or current_time - self._last_proc_check > 5:
            self._last_proc_check = current_time
            # Still use ps for top processes (complex to replicate efficiently)
            top_cpu = self.run_cmd("ps aux --sort=-%cpu | head -2 | tail -1 | awk '{print $11\" \"$3\"%\"}'") 
            top_mem = self.run_cmd("ps aux --sort=-%mem | head -2 | tail -1 | awk '{print $11\" \"$4\"%\"}'")

            # Shorten names
            def shorten(s, max_len=25):
                if not s or len(s) <= max_len:
                    return s
                parts = s.rsplit(' ', 1)
                if len(parts) == 2:
                    return parts[0][:max_len-4] + "… " + parts[1]
                return s[:max_len]
            
            self._cached_top_cpu = shorten(top_cpu)
            self._cached_top_mem = shorten(top_mem)
        
        return {
            'total': total,
            'top_cpu': getattr(self, '_cached_top_cpu', ''),
            'top_mem': getattr(self, '_cached_top_mem', '')
        }

    def get_docker_info(self, skip_stats=False):
        """Get Docker container information.
        
        Args:
            skip_stats: If True, skip per-container stats (faster startup)
        """
        result = {
            'available': False,
            'running': 0,
            'stopped': 0,
            'total': 0,
            'containers': []
        }
        
        # Cache docker availability check
        if self._docker_available is None:
            docker_check = self.run_cmd("which docker 2>/dev/null")
            self._docker_available = bool(docker_check) and os.path.exists('/var/run/docker.sock')
        
        if not self._docker_available:
            return result
        
        # Cache docker stats - only fetch every 10 seconds (very expensive)
        current_time = time.time()
        use_cached_stats = hasattr(self, '_docker_stats_cache') and (current_time - getattr(self, '_docker_stats_time', 0) < 10)
        
        try:
            # Get container list
            output = self.run_cmd("docker ps -a --format '{{.ID}}|{{.Names}}|{{.Status}}|{{.Image}}' 2>/dev/null")
            if not output or "permission denied" in output.lower() or "Cannot connect" in output:
                self._docker_available = False
                return result
            
            result['available'] = True
            containers = []
            running_ids = []
            
            for line in output.strip().split('\n'):
                if not line:
                    continue
                parts = line.split('|')
                if len(parts) >= 4:
                    container_id, name, status, image = parts[:4]
                    is_running = status.lower().startswith('up')
                    
                    cpu_pct = mem_pct = 0.0
                    if is_running:
                        running_ids.append(container_id[:12])
                        # Use cached stats if available
                        if use_cached_stats and container_id[:12] in self._docker_stats_cache:
                            cpu_pct, mem_pct = self._docker_stats_cache[container_id[:12]]
                    
                    containers.append({
                        'id': container_id[:12],
                        'name': name[:20],
                        'status': 'running' if is_running else 'stopped',
                        'image': image.split('/')[-1][:15],
                        'cpu': cpu_pct,
                        'mem': mem_pct
                    })
                    
                    if is_running:
                        result['running'] += 1
                    else:
                        result['stopped'] += 1
            
            # Fetch stats for all running containers in ONE call (much faster)
            if running_ids and not skip_stats and not use_cached_stats:
                stats_output = self.run_cmd("docker stats --no-stream --format '{{.ID}}|{{.CPUPerc}}|{{.MemPerc}}' 2>/dev/null", timeout=3)
                if stats_output:
                    self._docker_stats_cache = {}
                    self._docker_stats_time = current_time
                    for line in stats_output.strip().split('\n'):
                        if '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 3:
                                cid = parts[0][:12]
                                try:
                                    cpu = float(parts[1].replace('%', ''))
                                    mem = float(parts[2].replace('%', ''))
                                    self._docker_stats_cache[cid] = (cpu, mem)
                                    # Update container in list
                                    for c in containers:
                                        if c['id'] == cid:
                                            c['cpu'] = cpu
                                            c['mem'] = mem
                                            break
                                except:
                                    pass
            
            result['total'] = len(containers)
            result['containers'] = sorted(containers, key=lambda x: (x['status'] != 'running', -x['cpu']))[:10]
            
        except Exception as e:
            pass
        
        return result

    def get_kubernetes_info(self):
        """Get Kubernetes pod/node information."""
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
        
        # Cache kubectl availability check
        if self._kubectl_available is None:
            kubectl_check = self.run_cmd("which kubectl 2>/dev/null")
            self._kubectl_available = bool(kubectl_check)
        
        if not self._kubectl_available:
            return result
        
        try:
            # Get current context
            context = self.run_cmd("kubectl config current-context 2>/dev/null")
            if not context or "error" in context.lower():
                return result
            
            result['available'] = True
            result['context'] = context[:20]
            
            # Get node status
            nodes_output = self.run_cmd("kubectl get nodes --no-headers 2>/dev/null")
            if nodes_output:
                for line in nodes_output.strip().split('\n'):
                    if line:
                        result['nodes'] += 1
                        if 'Ready' in line and 'NotReady' not in line:
                            result['nodes_ready'] += 1
            
            # Get pod status (all namespaces, limit output)
            pods_output = self.run_cmd("kubectl get pods -A --no-headers 2>/dev/null | head -50")
            if pods_output:
                pods = []
                for line in pods_output.strip().split('\n'):
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
                        
                        # Parse ready count
                        ready_count = 0
                        total_count = 0
                        if '/' in ready:
                            try:
                                ready_count, total_count = map(int, ready.split('/'))
                            except:
                                pass
                        
                        pods.append({
                            'namespace': namespace,
                            'name': name,
                            'ready': ready,
                            'status': status,
                            'ready_count': ready_count,
                            'total_count': total_count
                        })
                
                # Sort: failed first, then pending, then by name
                result['pods'] = sorted(pods, key=lambda x: (
                    x['status'] == 'Running',
                    x['status'] != 'Failed',
                    x['name']
                ))[:10]
            
        except Exception as e:
            pass
        
        return result

    def get_uptime(self):
        """Calculate system uptime - direct /proc read."""
        try:
            with open('/proc/uptime', 'r') as f:
                uptime_seconds = float(f.read().split()[0])
            uptime = timedelta(seconds=int(uptime_seconds))
            return uptime.days, uptime.seconds // 3600, (uptime.seconds % 3600) // 60
        except:
            return 0, 0, 0

    def get_proxy_stats(self):
        """Get reverse proxy traffic stats from nginx/caddy access logs."""
        current_time = time.time()
        
        # Only check every 5 seconds
        if current_time - self._last_proxy_check < 5:
            return self._proxy_stats
        
        self._last_proxy_check = current_time
        stats = {'requests': 0, 'bytes': 0, 'rps': 0.0, 'source': None}
        
        # Try nginx first, then caddy
        for proxy_name, log_path in self.proxy_logs.items():
            if not os.path.exists(log_path):
                continue
            
            try:
                # Get last 100 lines and count requests in last minute
                output = self.run_cmd(f"tail -100 {log_path} 2>/dev/null")
                if not output:
                    continue
                
                lines = output.strip().split('\n')
                now = time.time()
                recent_count = 0
                total_bytes = 0
                
                for line in lines:
                    # Parse common log format or JSON
                    try:
                        # Try to extract bytes (common log format: ... 200 1234)
                        parts = line.split()
                        if len(parts) >= 10:
                            # Bytes is usually the 10th field in common log format
                            bytes_str = parts[9] if parts[9].isdigit() else parts[-1]
                            if bytes_str.isdigit():
                                total_bytes += int(bytes_str)
                        recent_count += 1
                    except:
                        recent_count += 1
                
                if recent_count > 0:
                    stats['requests'] = recent_count
                    stats['bytes'] = total_bytes
                    stats['rps'] = recent_count / 60.0  # Approximate RPS
                    stats['source'] = proxy_name
                    break
                    
            except:
                pass
        
        self._proxy_stats = stats
        self.proxy_history.append(stats.get('rps', 0) * 10)  # Scale for visibility
        return stats

    def check_for_updates(self):
        """Check GitHub for newer version (non-blocking, cached for 24h)."""
        current_time = time.time()

        # Only check once per day to avoid GitHub rate limits and reduce overhead
        if current_time - self._last_update_check < self._update_check_interval:
            return self._update_available

        self._last_update_check = current_time

        try:
            # Quick, lightweight check using curl with timeout
            # Fetches the VERSION line from the raw GitHub file
            github_raw = "https://raw.githubusercontent.com/VidGuiCode/sentinal/main/sentinel-monitor.py"
            cmd = f"curl -s -m 3 {github_raw} | grep -m 1 '^VERSION = ' | cut -d'\"' -f2"
            remote_version = self.run_cmd(cmd, timeout=4)

            if remote_version and remote_version != VERSION:
                # Parse versions to compare (e.g., "0.5.0" vs "0.4.0")
                try:
                    remote_parts = [int(x) for x in remote_version.split('.')]
                    current_parts = [int(x) for x in VERSION.split('.')]

                    # Compare major.minor.patch
                    if remote_parts > current_parts:
                        self._update_available = remote_version
                    else:
                        self._update_available = False
                except:
                    self._update_available = False
            else:
                self._update_available = False

        except:
            # If check fails, silently continue (don't bother the user)
            self._update_available = False

        return self._update_available

    def get_security_logs(self):
        """Get security events from system logs (auth, syslog, secure)."""
        current_time = time.time()

        # Only check every 5 seconds
        if current_time - self._last_security_check < 5:
            return self._security_cache

        self._last_security_check = current_time

        # Pre-compile regex patterns for performance (cached in self._compiled_regex)
        # These patterns match the EXACT same format as the working log analyzer
        if not self._compiled_regex:
            self._compiled_regex = {
                # Event patterns - search WITHIN message, not match from start (like working analyzer)
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
            'top_ips': {},  # IP -> count mapping
            'top_users': {},  # user -> count mapping
            'error_types': {},  # error type -> count mapping
            'recent_events': [],  # Last few parsed events
            'alerts': [],  # Active security alerts
        }

        # Clean up old events (older than 5 minutes)
        cutoff_time = current_time - self.security_alerts_config['failed_login_window']
        self._security_events = [e for e in self._security_events if e['timestamp'] > cutoff_time]

        # Clean up old IP failure tracking
        for ip in list(self._ip_failure_tracker.keys()):
            self._ip_failure_tracker[ip] = [t for t in self._ip_failure_tracker[ip] if t > cutoff_time]
            if not self._ip_failure_tracker[ip]:
                del self._ip_failure_tracker[ip]

        # Try auth.log first (Debian/Ubuntu), then secure (RHEL/CentOS), then syslog
        for log_name, log_path in self.security_logs.items():
            if not os.path.exists(log_path):
                continue

            try:
                # Get last 1000 lines for analysis (increased for better threat detection)
                output = self.run_cmd(f"tail -1000 {log_path} 2>/dev/null", timeout=3)
                if not output:
                    continue

                lines = output.strip().split('\n')
                stats['available'] = True

                for line in lines:
                    if not line.strip():
                        continue

                    # Parse each line using search (not match) to find patterns WITHIN the line
                    # This matches the working log analyzer's approach
                    stats['total_parsed'] += 1  # Count all lines as parsed

                    # Check for invalid user attempts
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

                    # Check for failed password attempts
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

                    # Check for connection closed events
                    if self._compiled_regex['connection_closed'].search(line):
                        stats['error_types']['Connection closed (invalid user)'] = stats['error_types'].get('Connection closed (invalid user)', 0) + 1
                        continue

                    # Check for successful logins
                    success_match = self._compiled_regex['accepted_key'].search(line)
                    if success_match:
                        username, ip = success_match.groups()
                        stats['successful_logins'] += 1
                        stats['top_ips'][ip] = stats['top_ips'].get(ip, 0) + 1
                        continue

                # Calculate failed vs successful ratio
                total_logins = stats['failed_logins'] + stats['successful_logins']
                if total_logins > 0:
                    stats['failed_ratio'] = stats['failed_logins'] / total_logins

                # Only keep top 10 IPs and users
                stats['top_ips'] = dict(sorted(stats['top_ips'].items(), key=lambda x: x[1], reverse=True)[:10])
                stats['top_users'] = dict(sorted(stats['top_users'].items(), key=lambda x: x[1], reverse=True)[:10])

                # Keep only last 5 events
                stats['recent_events'] = stats['recent_events'][-5:]

                # Check for alerts
                # Alert 1: >20 failed logins from same IP in 5 minutes
                for ip, timestamps in self._ip_failure_tracker.items():
                    if len(timestamps) >= self.security_alerts_config['failed_login_threshold']:
                        stats['alerts'].append({
                            'type': 'brute_force',
                            'message': f'Possible brute force from {ip} ({len(timestamps)} attempts)',
                            'severity': 'danger'
                        })

                # Alert 2: High error rate in last minute
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

        # Update history for graphs
        self.failed_login_history.append(stats['failed_logins'])
        self.suspicious_ip_history.append(len([ip for ip, count in stats['top_ips'].items() if count >= 3]))

        self._security_cache = stats
        return stats

    def draw_loading_modal(self, stdscr, h, w, message="Loading..."):
        """Draw a centered loading modal overlay."""
        modal_w = max(len(message) + 6, 24)
        modal_h = 5
        
        start_y = (h - modal_h) // 2
        start_x = (w - modal_w) // 2
        
        try:
            # Draw modal box
            border = curses.color_pair(1)
            fill = curses.color_pair(8)
            
            # Top border
            stdscr.addstr(start_y, start_x, "╭" + "─" * (modal_w - 2) + "╮", border)
            
            # Middle rows
            for i in range(1, modal_h - 1):
                stdscr.addstr(start_y + i, start_x, "│", border)
                stdscr.addstr(start_y + i, start_x + 1, " " * (modal_w - 2), fill)
                stdscr.addstr(start_y + i, start_x + modal_w - 1, "│", border)
            
            # Bottom border
            stdscr.addstr(start_y + modal_h - 1, start_x, "╰" + "─" * (modal_w - 2) + "╯", border)
            
            # Loading spinner animation
            spinner = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
            spin_char = spinner[int(time.time() * 10) % len(spinner)]
            
            # Message
            msg_x = start_x + (modal_w - len(message) - 2) // 2
            stdscr.addstr(start_y + 2, msg_x, f"{spin_char} {message}", curses.color_pair(7) | curses.A_BOLD)
            
        except curses.error:
            pass

    def draw_help_modal(self, stdscr, h, w):
        """Draw help overlay with keybindings."""
        help_lines = [
            "╭─────────── HELP ───────────╮",
            "│                            │",
            "│  q      Quit               │",
            "│  r      Refresh now        │",
            "│  t      Cycle themes       │",
            "│  l      Cycle layouts      │",
            "│  i      Refresh public IP  │",
            "│  h      Toggle this help   │",
            "│  +/-    Adjust refresh     │",
            "│                            │",
            "│  Layouts: default, cpu,    │",
            "│    network, docker, minimal│",
            "│                            │",
            "╰────────────────────────────╯",
        ]
        
        modal_h = len(help_lines)
        modal_w = len(help_lines[0])
        start_y = (h - modal_h) // 2
        start_x = (w - modal_w) // 2
        
        try:
            for i, line in enumerate(help_lines):
                stdscr.addstr(start_y + i, start_x, line, curses.color_pair(1))
        except curses.error:
            pass

    def draw_graph(self, stdscr, y, x, width, height, data, max_val=100, title="", show_current=True):
        """Draw a btop-style filled area graph."""
        if width <= 2 or height <= 1:
            return
        
        blocks = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        points = list(data)[-(width):]
        if not points:
            points = [0]
        
        current_val = points[-1] if points else 0
        actual_max = max(max(points), max_val, 1)
        
        try:
            # Draw graph area
            for row in range(height):
                row_y = y + row
                threshold_low = 1.0 - ((row + 1) / height)
                threshold_high = 1.0 - (row / height)
                
                for col, value in enumerate(points[-width:]):
                    if col >= width:
                        break
                    normalized = min(value / actual_max, 1.0) if actual_max > 0 else 0
                    col_x = x + col + (width - len(points[-width:]))
                    
                    # Determine character and color
                    if normalized >= threshold_high:
                        char = "█"
                    elif normalized > threshold_low:
                        frac = (normalized - threshold_low) / (threshold_high - threshold_low)
                        char = blocks[int(frac * 8)]
                    else:
                        char = " "
                    
                    # Color based on height position (gradient effect)
                    if row < height * 0.3:
                        color = curses.color_pair(4)  # Red top
                    elif row < height * 0.6:
                        color = curses.color_pair(3)  # Yellow mid
                    else:
                        color = curses.color_pair(2)  # Green bottom
                    
                    if char != " ":
                        stdscr.addstr(row_y, col_x, char, color)
            
            # Show current value
            if show_current and title:
                val_str = f"{current_val:.1f}%" if current_val < 100 else f"{current_val:.0f}%"
                stdscr.addstr(y, x + width + 1, val_str, curses.color_pair(7) | curses.A_BOLD)
        except curses.error:
            pass

    def draw_mini_graph(self, stdscr, y, x, width, data, max_val=100, color=2):
        """Draw a compact single-line sparkline."""
        if not data or width <= 0:
            return
        
        bars = "▁▂▃▄▅▆▇█"
        points = list(data)[-width:]
        actual_max = max(max(points), max_val, 1) if points else max_val
        
        try:
            for i, value in enumerate(points):
                if i >= width:
                    break
                normalized = min(value / actual_max, 1.0) if actual_max > 0 else 0
                char = bars[int(normalized * 7)]
                stdscr.addstr(y, x + i, char, curses.color_pair(color))
        except curses.error:
            pass

    def draw_braille_sparkline(self, stdscr, y, x, width, data, max_val=100, color=1):
        """Draw high-resolution sparkline using braille characters (2x vertical resolution)."""
        if not data or width <= 0:
            return
        
        # Braille patterns for 0-4 dots vertically: ⠀⡀⡄⡆⡇ (bottom to top)
        braille_base = 0x2800
        points = list(data)[-(width * 2):]  # 2 data points per character
        
        try:
            for i in range(min(width, (len(points) + 1) // 2)):
                idx = i * 2
                v1 = points[idx] if idx < len(points) else 0
                v2 = points[idx + 1] if idx + 1 < len(points) else 0
                
                # Normalize to 0-3 range for braille dots
                n1 = int(min(v1 / max_val, 1.0) * 3) if max_val > 0 else 0
                n2 = int(min(v2 / max_val, 1.0) * 3) if max_val > 0 else 0
                
                # Build braille character (dots 1,2,3 for left column, 4,5,6 for right)
                char = braille_base
                for dot in range(n1):
                    char |= (1 << dot)  # Dots 1,2,3
                for dot in range(n2):
                    char |= (1 << (dot + 3))  # Dots 4,5,6
                
                stdscr.addstr(y, x + i, chr(char), curses.color_pair(color))
        except:
            pass

    def draw_header(self, stdscr, width, uptime_str):
        """Draw clean minimal header - btop style."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        try:
            # Single clean line with key info
            stdscr.addstr(0, 1, "sentinel", curses.color_pair(1) | curses.A_BOLD)
            stdscr.addstr(0, 10, f"v{VERSION}", curses.color_pair(8))
            
            # Hostname centered
            host_text = self.hostname
            host_x = (width - len(host_text)) // 2
            stdscr.addstr(0, host_x, host_text, curses.color_pair(7))
            
            # Right side: uptime and time
            right_text = f"up {uptime_str}  {timestamp}"
            stdscr.addstr(0, width - len(right_text) - 1, f"up {uptime_str}", curses.color_pair(2))
            stdscr.addstr(0, width - len(timestamp) - 1, timestamp, curses.color_pair(8))
        except curses.error:
            pass

    def draw_bar(self, stdscr, y, x, width, percent, label="", show_val=True):
        """Draw a clean gradient progress bar - btop style."""
        if width <= 0:
            return
        
        filled = int((width * min(percent, 100)) / 100)
        
        try:
            # Draw filled portion with gradient
            for i in range(filled):
                pos_ratio = i / max(width - 1, 1)
                if pos_ratio < 0.5:
                    color = curses.color_pair(2)  # Green
                elif pos_ratio < 0.75:
                    color = curses.color_pair(1)  # Cyan  
                elif pos_ratio < 0.9:
                    color = curses.color_pair(3)  # Yellow
                else:
                    color = curses.color_pair(4)  # Red
                stdscr.addstr(y, x + i, "━", color)
            
            # Draw empty portion
            for i in range(filled, width):
                stdscr.addstr(y, x + i, "━", curses.color_pair(8))
            
            # Show percentage
            if show_val:
                val_str = f"{percent:5.1f}%"
                stdscr.addstr(y, x + width + 1, val_str, curses.color_pair(7))
        except curses.error:
            pass

    def draw_meter(self, stdscr, y, x, width, percent, label="", color=2):
        """Draw a labeled meter bar."""
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
            
            # Gradient bar
            for i in range(bar_width):
                if i < filled:
                    pos_ratio = percent / 100
                    if pos_ratio < 0.6:
                        c = curses.color_pair(2)
                    elif pos_ratio < 0.85:
                        c = curses.color_pair(3)
                    else:
                        c = curses.color_pair(4)
                    stdscr.addstr(y, bar_x + i, "┃", c)
                else:
                    stdscr.addstr(y, bar_x + i, "┃", curses.color_pair(8))
            
            # Value
            val_str = f"{percent:5.1f}%"
            stdscr.addstr(y, bar_x + bar_width + 1, val_str, curses.color_pair(7))
        except curses.error:
            pass

    def draw_box(self, stdscr, top, left, height, width, title="", accent=8):
        """Draw a clean box with optional title - returns inner coordinates."""
        if height < 2 or width < 4:
            return top, left, 0, 0
        
        border = curses.color_pair(accent)
        try:
            # Top border with title
            stdscr.addstr(top, left, "┌", border)
            if title:
                stdscr.addstr(top, left + 1, title, curses.color_pair(7) | curses.A_BOLD)
                stdscr.addstr(top, left + 1 + len(title), "─" * (width - 2 - len(title)), border)
            else:
                stdscr.addstr(top, left + 1, "─" * (width - 2), border)
            stdscr.addstr(top, left + width - 1, "┐", border)
            
            # Sides
            for row in range(1, height - 1):
                stdscr.addstr(top + row, left, "│", border)
                stdscr.addstr(top + row, left + width - 1, "│", border)
            
            # Bottom
            stdscr.addstr(top + height - 1, left, "└" + "─" * (width - 2) + "┘", border)
        except curses.error:
            pass
        
        return top + 1, left + 1, height - 2, width - 2

    def format_bytes(self, value, precision=1):
        """Human friendly byte formatter"""
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
        """Human friendly duration for VPN handshakes"""
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
        """Update all system data."""
        current_time = time.time()

        if current_time - self.last_update < self.refresh_rate:
            return self.cache

        # On first render, skip slow operations for instant UI
        is_first = self._first_render
        if is_first:
            self._first_render = False
            # Set public IP to checking state, will be fetched later
            self._public_ip_cache = "Checking..."
        
        # Defer public IP check (slow network call)
        if not is_first and (not hasattr(self, '_last_ip_check') or current_time - self._last_ip_check > 30):
            self.get_public_ip()
            self._last_ip_check = current_time

        # Check for updates once per day (non-blocking, silent)
        if not is_first and current_time - self._last_update_check > self._update_check_interval:
            self.check_for_updates()

        self.cache = {
            'cpu': self.get_cpu_info(),
            'mem': self.get_memory_info(),
            'battery': self.get_battery_info(),
            'disk': self.get_disk_usage() if not is_first else [],  # Skip docker volume check on first
            'network': self.get_network_info(),
            'processes': self.get_processes() if not is_first else {'total': 0, 'top_cpu': '', 'top_mem': ''},
            'uptime': self.get_uptime(),
            'energy': self.get_energy_info(),
            'docker': self.get_docker_info(skip_stats=is_first),  # Skip per-container stats on first
            'kubernetes': self.get_kubernetes_info() if not is_first else {'available': False, 'nodes': 0, 'nodes_ready': 0, 'pods_running': 0, 'pods_pending': 0, 'pods_failed': 0, 'pods': [], 'context': ''},
            'proxy': self.get_proxy_stats() if not is_first else {'requests': 0, 'bytes': 0, 'rps': 0.0, 'source': None},
            'security': self.get_security_logs() if not is_first else {'available': False, 'total_parsed': 0, 'total_unparsed': 0, 'failed_logins': 0, 'successful_logins': 0, 'failed_ratio': 0.0, 'top_ips': {}, 'top_users': {}, 'error_types': {}, 'recent_events': [], 'alerts': []},
        }

        self.last_update = current_time
        return self.cache

    def check_alerts(self, data):
        """Check for alert conditions and return list of active alerts."""
        alerts = []
        cpu = data.get('cpu', {})
        mem = data.get('mem', {})
        battery = data.get('battery', {})
        
        # CPU alerts
        if cpu.get('usage', 0) >= self.alerts.get('cpu_critical', 95):
            alerts.append(('CPU CRITICAL', f"{cpu['usage']:.0f}%", 'danger'))
        elif cpu.get('usage', 0) >= self.alerts.get('cpu_high', 85):
            alerts.append(('CPU HIGH', f"{cpu['usage']:.0f}%", 'warning'))
        
        # Temperature alerts
        if cpu.get('temp', 0) >= self.alerts.get('temp_critical', 90):
            alerts.append(('TEMP CRITICAL', f"{cpu['temp']:.0f}°C", 'danger'))
        elif cpu.get('temp', 0) >= self.alerts.get('temp_high', 75):
            alerts.append(('TEMP HIGH', f"{cpu['temp']:.0f}°C", 'warning'))
        
        # Memory alerts
        if mem.get('percent', 0) >= self.alerts.get('mem_critical', 95):
            alerts.append(('MEM CRITICAL', f"{mem['percent']:.0f}%", 'danger'))
        elif mem.get('percent', 0) >= self.alerts.get('mem_high', 80):
            alerts.append(('MEM HIGH', f"{mem['percent']:.0f}%", 'warning'))
        
        # Battery alerts
        if battery.get('exists') and battery.get('status') != 'Charging':
            level = battery.get('level', 100)
            if level <= self.alerts.get('battery_critical', 10):
                alerts.append(('BATTERY CRITICAL', f"{level}%", 'danger'))
            elif level <= self.alerts.get('battery_low', 20):
                alerts.append(('BATTERY LOW', f"{level}%", 'warning'))
        
        # Docker alerts
        docker = data.get('docker', {})
        if docker.get('available'):
            stopped = docker.get('stopped', 0)
            if stopped > 0:
                alerts.append(('DOCKER STOPPED', f"{stopped}", 'warning'))
        
        # Kubernetes alerts
        k8s = data.get('kubernetes', {})
        if k8s.get('available'):
            failed = k8s.get('pods_failed', 0)
            pending = k8s.get('pods_pending', 0)
            if failed > 0:
                alerts.append(('K8S FAILED', f"{failed} pods", 'danger'))
            elif pending > 0:
                alerts.append(('K8S PENDING', f"{pending} pods", 'warning'))

        # Security alerts
        security = data.get('security', {})
        if security.get('available'):
            # Add alerts from security log analysis
            for alert in security.get('alerts', []):
                alert_type = alert['type'].upper().replace('_', ' ')
                alerts.append((alert_type, alert['message'], alert['severity']))

        return alerts

    def setup_colors(self):
        """Setup color pairs based on theme."""
        theme = THEMES.get(self.theme_name, THEMES['default'])
        
        curses.start_color()
        curses.use_default_colors()
        
        # Map theme colors to pairs
        # 1=primary, 2=success, 3=warning, 4=danger, 5=info, 6=accent, 7=text, 8=muted
        curses.init_pair(1, theme['primary'], -1)
        curses.init_pair(2, theme['success'], -1)
        curses.init_pair(3, theme['warning'], -1)
        curses.init_pair(4, theme['danger'], -1)
        curses.init_pair(5, theme['info'], -1)
        curses.init_pair(6, theme['accent'], -1)
        curses.init_pair(7, theme['text'], -1)
        curses.init_pair(8, theme['muted'], -1)

    def draw(self, stdscr):
        """Main draw function - clean btop-inspired layout."""
        curses.curs_set(0)
        stdscr.timeout(500)

        # Setup theme colors
        self.setup_colors()

        while True:
            try:
                h, w = stdscr.getmaxyx()
                stdscr.erase()

                # Show loading modal on first render
                if self._first_render:
                    self.draw_loading_modal(stdscr, h, w, "Initializing...")
                    stdscr.refresh()

                data = self.update_data()
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
                # Layout mode affects column widths
                row = 1
                available_h = h - 2  # header + footer
                
                # Layout-specific width ratios
                layout = self.layout_mode
                if w >= 100:
                    if layout == 'cpu':
                        # CPU emphasized: 50% | 25% | 25%
                        col1_w = w // 2
                        col2_w = w // 4
                        col3_w = w - col1_w - col2_w
                    elif layout == 'network':
                        # Network emphasized: 25% | 25% | 50%
                        col1_w = w // 4
                        col2_w = w // 4
                        col3_w = w - col1_w - col2_w
                    elif layout == 'docker':
                        # Docker emphasized: 30% | 20% | 50% (power box gets more for containers)
                        col1_w = int(w * 0.30)
                        col2_w = int(w * 0.20)
                        col3_w = w - col1_w - col2_w
                    elif layout == 'security':
                        # Security emphasized: 25% | 20% | 55% (power box gets more for security events)
                        col1_w = w // 4
                        col2_w = int(w * 0.20)
                        col3_w = w - col1_w - col2_w
                    elif layout == 'minimal':
                        # Minimal: equal small columns
                        col1_w = w // 3
                        col2_w = w // 3
                        col3_w = w - col1_w - col2_w
                    else:  # default
                        col1_w = w // 3
                        col2_w = w // 3
                        col3_w = w - col1_w - col2_w
                    top_h = available_h
                elif w >= 60:
                    # 2 columns side by side
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
                    # Single column stacked
                    col1_w = w
                    col2_w = w
                    col3_w = w
                    top_h = max(6, available_h // 3)

                # === COLUMN 1: CPU ===
                cpu_h = top_h if w >= 100 else top_h // 2
                iy, ix, ih, iw = self.draw_box(stdscr, row, 0, cpu_h, col1_w, "cpu")
                
                if ih > 0 and iw > 0:
                    line = 0
                    
                    # CPU model and cores
                    model_text = cpu['model'][:iw - 12] if len(cpu['model']) > iw - 12 else cpu['model']
                    stdscr.addstr(iy + line, ix, model_text, curses.color_pair(8))
                    cores_text = f"{cpu['cores']} cores"
                    stdscr.addstr(iy + line, ix + iw - len(cores_text), cores_text, curses.color_pair(8))
                    line += 1
                    
                    # Main CPU usage bar with percentage
                    if line < ih:
                        self.draw_bar(stdscr, iy + line, ix, iw - 8, cpu['usage'])
                        line += 1
                    
                    # Per-core mini bars (if we have space and core data)
                    num_cores = cpu.get('cores', 0)
                    if num_cores > 0 and line < ih - 4:
                        # Get per-core usage from /proc/stat
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
                    
                    # CPU graph in remaining space
                    graph_start = line
                    graph_h = max(2, ih - line - 2)
                    if graph_h >= 2:
                        self.draw_graph(stdscr, iy + line, ix, iw, graph_h, self.cpu_history, max_val=100, show_current=False)
                        line += graph_h
                    
                    # Stats row at bottom
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
                    
                    # Load average on last line
                    if stats_y + 1 < iy + ih:
                        load_text = f"load {cpu['load'][0]:.2f} {cpu['load'][1]:.2f} {cpu['load'][2]:.2f}"
                        stdscr.addstr(stats_y + 1, ix, load_text, curses.color_pair(8))
                        
                        # Uptime on right
                        up_text = f"up {uptime_str}"
                        stdscr.addstr(stats_y + 1, ix + iw - len(up_text), up_text, curses.color_pair(2))


                # === COLUMN 2: Memory + Disks ===
                if w >= 100:
                    # 3-col: column 2 is next to CPU
                    col2_x = col1_w
                    mem_box_h = top_h // 2
                    disk_box_h = top_h - mem_box_h
                    col2_row = row
                elif w >= 60:
                    # 2-col: memory/disk below CPU on left side
                    col2_x = 0
                    mem_box_h = (available_h - cpu_h) // 2
                    disk_box_h = available_h - cpu_h - mem_box_h
                    col2_row = row + cpu_h
                else:
                    # 1-col: stacked below CPU
                    col2_x = 0
                    mem_box_h = max(4, available_h // 4)
                    disk_box_h = mem_box_h
                    col2_row = row + cpu_h
                
                if col2_w > 0 and mem_box_h > 2:
                    # Memory box
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
                    
                    # Disks box
                    disk_y = col2_row + mem_box_h
                    dy, dx, dh, dw = self.draw_box(stdscr, disk_y, col2_x, disk_box_h, col2_w, "disks")
                    if dh > 0 and dw > 0:
                        for i, disk in enumerate(disks[:dh]):
                            disk_type = disk.get('type', 'disk')
                            
                            if disk_type == 'docker':
                                # Docker volumes - show with docker prefix, name and size
                                mount = disk['mount'][:dw - 14]
                                size_text = disk['used'][:8] if disk['used'] else '—'
                                stdscr.addstr(dy + i, dx, "dk:", curses.color_pair(5))
                                stdscr.addstr(dy + i, dx + 3, mount, curses.color_pair(8))
                                stdscr.addstr(dy + i, dx + dw - len(size_text), size_text, curses.color_pair(7))
                            else:
                                # Regular disk - show bar and percentage
                                mount = disk['mount'][:8]
                                pct = disk['percent']
                                bar_w = max(6, dw - 16)
                                stdscr.addstr(dy + i, dx, f"{mount:>6}", curses.color_pair(8))
                                self.draw_bar(stdscr, dy + i, dx + 7, bar_w, pct, show_val=False)
                                stdscr.addstr(dy + i, dx + 8 + bar_w, f"{pct:3.0f}%", curses.color_pair(7))

                # === COLUMN 3: Network + Power ===
                if w >= 100:
                    # 3-col: column 3 is rightmost
                    col3_x = col1_w + col2_w
                    # Adjust heights based on layout mode
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
                    # 2-col: network/power on right side, full height
                    col3_x = col1_w
                    net_box_h = available_h // 2
                    pwr_box_h = available_h - net_box_h
                    col3_actual_w = col2_w
                    col3_row = row
                else:
                    # 1-col: stacked at bottom
                    col3_x = 0
                    net_box_h = max(4, available_h // 4)
                    pwr_box_h = available_h - cpu_h - mem_box_h - disk_box_h - net_box_h
                    col3_actual_w = w
                    col3_row = row + cpu_h + mem_box_h + disk_box_h
                
                if col3_actual_w > 0 and net_box_h > 0:
                    # Network box - fuller layout
                    ny, nx, nh, nw = self.draw_box(stdscr, col3_row, col3_x, net_box_h, col3_actual_w, "net")
                    if nh > 0 and nw > 0:
                        line = 0
                        
                        # Interface and connection type
                        iface = net['interface'] or "—"
                        conn_type = net.get('connection_type', '')
                        stdscr.addstr(ny + line, nx, iface, curses.color_pair(1) | curses.A_BOLD)
                        if conn_type:
                            stdscr.addstr(ny + line, nx + len(iface) + 1, f"({conn_type})", curses.color_pair(8))
                        
                        # Link speed on right (only show if valid positive value)
                        link_speed = net.get('link_speed')
                        if link_speed and link_speed > 0 and nw > 20:
                            if link_speed >= 1000:
                                speed_text = f"{link_speed // 1000}Gbps"
                            else:
                                speed_text = f"{link_speed}Mbps"
                            stdscr.addstr(ny + line, nx + nw - len(speed_text), speed_text, curses.color_pair(2))
                        line += 1
                        
                        # IPs
                        if line < nh:
                            local_ip = net['local_ip'] or "—"
                            stdscr.addstr(ny + line, nx, local_ip, curses.color_pair(7))
                            public_ip = net['public_ip'] or "N/A"
                            if nw > 20:
                                stdscr.addstr(ny + line, nx + nw - len(public_ip), public_ip, curses.color_pair(8))
                            line += 1
                        
                        # Download with graph
                        if line < nh:
                            rx_text = f"↓ {net['rx_speed']:6.1f} KB/s"
                            stdscr.addstr(ny + line, nx, rx_text, curses.color_pair(2))
                            graph_x = nx + len(rx_text) + 1
                            graph_w = nw - len(rx_text) - 2
                            if graph_w > 4:
                                max_rx = max(max(self.rx_history) if self.rx_history else 1, 1)
                                self.draw_mini_graph(stdscr, ny + line, graph_x, graph_w, self.rx_history, max_val=max_rx, color=2)
                            line += 1
                        
                        # Upload with graph
                        if line < nh:
                            tx_text = f"↑ {net['tx_speed']:6.1f} KB/s"
                            stdscr.addstr(ny + line, nx, tx_text, curses.color_pair(6))
                            graph_x = nx + len(tx_text) + 1
                            graph_w = nw - len(tx_text) - 2
                            if graph_w > 4:
                                max_tx = max(max(self.tx_history) if self.tx_history else 1, 1)
                                self.draw_mini_graph(stdscr, ny + line, graph_x, graph_w, self.tx_history, max_val=max_tx, color=6)
                            line += 1
                        
                        # Totals
                        if line < nh:
                            totals = f"total: ↓{net['rx_total']:.2f}G ↑{net['tx_total']:.2f}G"
                            stdscr.addstr(ny + line, nx, totals, curses.color_pair(8))
                            line += 1
                        
                        # VPN peers
                        if line < nh:
                            peers = net.get('wg_peers', 0)
                            connected = net.get('wg_peers_connected', 0)
                            if peers > 0:
                                vpn_color = curses.color_pair(2) if connected > 0 else curses.color_pair(4)
                                vpn_icon = "●" if connected > 0 else "○"
                                stdscr.addstr(ny + line, nx, f"vpn {vpn_icon} {connected}/{peers} peers", vpn_color)
                            else:
                                # Show SSID for wifi if no VPN
                                ssid = net.get('ssid')
                                if ssid:
                                    stdscr.addstr(ny + line, nx, f"wifi: {ssid}", curses.color_pair(8))
                            line += 1
                        
                        # VPN connection details if space
                        vpn_list = net.get('vpn_connections', [])
                        for peer in vpn_list[:nh - line]:
                            if line >= nh:
                                break
                            # Get full IP (without port), limit to available width
                            endpoint_full = peer['endpoint'].split(':')[0] if peer.get('endpoint') else "—"
                            max_ip_len = nw - 4  # Leave room for status icon
                            endpoint = endpoint_full[:max_ip_len]
                            status = "●" if peer['connected'] else "○"
                            color = curses.color_pair(2) if peer['connected'] else curses.color_pair(4)
                            # Show latency if available
                            latency = peer.get('latency', '')
                            if latency and len(endpoint) + len(latency) + 5 < nw:
                                stdscr.addstr(ny + line, nx, f"  {status} {endpoint}", color)
                                stdscr.addstr(ny + line, nx + nw - len(latency) - 1, latency, curses.color_pair(8))
                            else:
                                stdscr.addstr(ny + line, nx, f"  {status} {endpoint}", color)
                            line += 1
                        
                        # Proxy traffic stats if available
                        proxy = data.get('proxy', {})
                        if proxy.get('source') and line < nh:
                            rps = proxy.get('rps', 0)
                            source = proxy['source'][:6]
                            stdscr.addstr(ny + line, nx, f"proxy:", curses.color_pair(8))
                            stdscr.addstr(ny + line, nx + 7, source, curses.color_pair(5))
                            stdscr.addstr(ny + line, nx + 7 + len(source) + 1, f"{rps:.1f}rps", curses.color_pair(2))
                            line += 1
                        
                        # Show connection quality indicator if space
                        if line < nh and net.get('operstate') == 'up':
                            # Calculate quality based on speed and stability
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
                    
                    # Power/Energy box - improved layout
                    pwr_y = col3_row + net_box_h
                    py, px, ph, pw = self.draw_box(stdscr, pwr_y, col3_x, pwr_box_h, col3_actual_w, "power")
                    if ph > 0 and pw > 0:
                        line = 0
                        
                        # RAPL/CPU power consumption
                        if energy['available']:
                            watts = energy['power_watts']
                            pwr_color = curses.color_pair(2) if watts < 15 else curses.color_pair(3) if watts < 30 else curses.color_pair(4)
                            
                            # Power value with bar visualization
                            max_watts = 65  # TDP estimate
                            pwr_pct = min(100, (watts / max_watts) * 100)
                            bar_w = min(12, pw - 12)
                            
                            stdscr.addstr(py + line, px, f"{watts:5.1f}W", pwr_color | curses.A_BOLD)
                            if bar_w > 4:
                                self.draw_bar(stdscr, py + line, px + 7, bar_w, pwr_pct, show_val=False)
                            stdscr.addstr(py + line, px + pw - 4, energy['source'].upper()[:4], curses.color_pair(8))
                            line += 1
                            
                            # Power history graph
                            if line < ph and len(self.power_history) > 1:
                                max_pwr = max(max(self.power_history), 10)
                                graph_w = min(pw - 2, 24)
                                self.draw_mini_graph(stdscr, py + line, px, graph_w, self.power_history, max_val=max_pwr, color=1)
                                line += 1
                        
                        # Battery section
                        if battery.get('exists'):
                            if line > 0 and line < ph:
                                line += 1  # spacing
                            
                            if line < ph:
                                batt_pct = battery['level']
                                batt_color = curses.color_pair(2) if batt_pct > 50 else curses.color_pair(3) if batt_pct > 20 else curses.color_pair(4)
                                
                                # Battery icon based on level
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
                            
                            # Battery bar
                            if line < ph:
                                bar_w = min(pw - 2, 20)
                                self.draw_bar(stdscr, py + line, px, bar_w, batt_pct, show_val=False)
                                line += 1
                            
                            # Health and cycles
                            if line < ph and battery.get('health'):
                                health = battery['health']
                                cycles = battery.get('cycle_count') or '—'
                                health_color = curses.color_pair(2) if health > 80 else curses.color_pair(3) if health > 60 else curses.color_pair(4)
                                stdscr.addstr(py + line, px, f"health:", curses.color_pair(8))
                                stdscr.addstr(py + line, px + 7, f"{health:.0f}%", health_color)
                                stdscr.addstr(py + line, px + 13, f"cycles:{cycles}", curses.color_pair(8))
                                line += 1
                            
                            # Power draw if available
                            if line < ph and battery.get('power'):
                                pwr = battery['power']
                                if pwr > 0:
                                    stdscr.addstr(py + line, px, f"draw: {pwr:.1f}W", curses.color_pair(8))
                                    line += 1
                        
                        # No power info available
                        if not energy['available'] and not battery.get('exists'):
                            stdscr.addstr(py + line, px, "no power data", curses.color_pair(8))
                            line += 1
                            if line < ph:
                                stdscr.addstr(py + line, px, "RAPL needs root", curses.color_pair(8))
                        
                        # Docker/K8s/Security info at bottom
                        docker = data.get('docker', {})
                        k8s = data.get('kubernetes', {})
                        security = data.get('security', {})

                        if line < ph - 1:
                            line += 1  # spacing
                            remaining_lines = ph - line

                            # Calculate space for docker, k8s, and security
                            has_docker = docker.get('available', False)
                            has_k8s = k8s.get('available', False)
                            has_security = security.get('available', False)

                            # Count active features and distribute lines
                            active_features = sum([has_docker, has_k8s, has_security])

                            if active_features == 0:
                                docker_lines = 0
                                k8s_lines = 0
                                security_lines = 0
                            elif active_features == 1:
                                # One feature gets all lines
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
                                # Two features split space
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
                                # In security layout, give more space to security
                                if layout == 'security':
                                    security_lines = int(remaining_lines * 0.5)
                                    docker_lines = (remaining_lines - security_lines) // 2
                                    k8s_lines = remaining_lines - security_lines - docker_lines
                                else:
                                    # Split evenly among all three
                                    docker_lines = remaining_lines // 3
                                    k8s_lines = remaining_lines // 3
                                    security_lines = remaining_lines - docker_lines - k8s_lines
                            
                            # Show Docker if available
                            if has_docker and docker_lines > 0:
                                running = docker['running']
                                stopped = docker['stopped']
                                color = curses.color_pair(2) if running > 0 else curses.color_pair(8)
                                stdscr.addstr(py + line, px, "dk", curses.color_pair(5))
                                stdscr.addstr(py + line, px + 2, f"{running}", color | curses.A_BOLD)
                                stdscr.addstr(py + line, px + 2 + len(str(running)), f"/{docker['total']}", curses.color_pair(8))
                                line += 1
                                docker_lines -= 1
                                
                                # Show containers dynamically based on available space
                                containers_to_show = min(len(docker['containers']), docker_lines)
                                for container in docker['containers'][:containers_to_show]:
                                    if line >= ph:
                                        break
                                    name = container['name'][:pw - 8]
                                    status_icon = "●" if container['status'] == 'running' else "○"
                                    status_color = curses.color_pair(2) if container['status'] == 'running' else curses.color_pair(4)
                                    stdscr.addstr(py + line, px, f" {status_icon}", status_color)
                                    stdscr.addstr(py + line, px + 3, name, curses.color_pair(8))
                                    line += 1
                            
                            # Show K8s if available
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
                                
                                # Show pods dynamically
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

                            # Show Security if available
                            if has_security and security_lines > 0 and line < ph:
                                failed = security.get('failed_logins', 0)
                                successful = security.get('successful_logins', 0)
                                total_logins = failed + successful

                                # Security header with failed login count
                                color = curses.color_pair(2) if failed == 0 else curses.color_pair(3) if failed < 10 else curses.color_pair(4)
                                stdscr.addstr(py + line, px, "sec", curses.color_pair(5))
                                stdscr.addstr(py + line, px + 3, f" {failed}", color | curses.A_BOLD)
                                if total_logins > 0:
                                    stdscr.addstr(py + line, px + 3 + len(str(failed)), f"/{total_logins}", curses.color_pair(8))
                                line += 1
                                security_lines -= 1

                                # Show top suspicious IPs
                                top_ips = security.get('top_ips', {})
                                ips_to_show = min(len(top_ips), security_lines)
                                for ip, count in list(top_ips.items())[:ips_to_show]:
                                    if line >= ph:
                                        break
                                    # Truncate IP to fit width
                                    ip_display = ip[:pw - 6]
                                    count_str = f"×{count}"
                                    # Color code by severity
                                    ip_color = curses.color_pair(4) if count >= 10 else curses.color_pair(3) if count >= 5 else curses.color_pair(2)
                                    stdscr.addstr(py + line, px, f" {ip_display}", ip_color)
                                    # Show count on the right if space
                                    if len(ip_display) + len(count_str) + 2 < pw:
                                        stdscr.addstr(py + line, px + pw - len(count_str), count_str, curses.color_pair(8))
                                    line += 1

                            # Fallback to processes if no docker/k8s/security
                            if not has_docker and not has_k8s and not has_security and line < ph:
                                stdscr.addstr(py + line, px, f"{proc['total']} tasks", curses.color_pair(7))
                                if proc.get('top_cpu') and line + 1 < ph:
                                    line += 1
                                    top = proc['top_cpu'][:pw - 1]
                                    stdscr.addstr(py + line, px, top, curses.color_pair(3))

                # === FOOTER ===
                footer_y = h - 1
                
                # Check for alerts
                active_alerts = self.check_alerts(data)
                
                try:
                    col = 1
                    # Controls
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
                    
                    # Show current theme, layout, and refresh rate
                    theme_text = f"[{self.theme_name}]"
                    stdscr.addstr(footer_y, col + 1, theme_text, curses.color_pair(1))
                    layout_text = f"[{self.layout_mode}]"
                    stdscr.addstr(footer_y, col + 2 + len(theme_text), layout_text, curses.color_pair(5))
                    rate_text = f"[{self.refresh_rate}s]"
                    stdscr.addstr(footer_y, col + 3 + len(theme_text) + len(layout_text), rate_text, curses.color_pair(2))

                    # Show update notification if available (non-intrusive, left of alerts)
                    update_x = col + 4 + len(theme_text) + len(layout_text) + len(rate_text)
                    if self._update_available and isinstance(self._update_available, str):
                        update_text = f" v{self._update_available} available "
                        if update_x + len(update_text) < w - 30:  # Leave room for alerts
                            stdscr.addstr(footer_y, update_x, update_text, curses.color_pair(2) | curses.A_DIM)

                    # Show alerts on right side
                    if active_alerts:
                        alert_x = w - 2
                        for alert_name, alert_val, alert_type in reversed(active_alerts[:3]):
                            alert_text = f" {alert_name} "
                            alert_x -= len(alert_text)
                            color = curses.color_pair(4) if alert_type == 'danger' else curses.color_pair(3)
                            stdscr.addstr(footer_y, alert_x, alert_text, color | curses.A_BOLD | curses.A_BLINK)
                except curses.error:
                    pass

                # Draw help overlay if active
                if self._show_help:
                    self.draw_help_modal(stdscr, h, w)

                stdscr.refresh()

                # Input handling
                key = stdscr.getch()
                if key == ord('q') or key == ord('Q'):
                    break
                elif key == ord('r') or key == ord('R'):
                    self.last_update = 0
                    self._first_render = False  # Don't skip data on manual refresh
                elif key == ord('i') or key == ord('I'):
                    self._last_ip_check = 0
                elif key == ord('h') or key == ord('H'):
                    self._show_help = not self._show_help
                elif key == ord('t') or key == ord('T'):
                    # Cycle through themes
                    theme_list = list(THEMES.keys())
                    current_idx = theme_list.index(self.theme_name) if self.theme_name in theme_list else 0
                    self.theme_name = theme_list[(current_idx + 1) % len(theme_list)]
                    self.setup_colors()
                elif key == ord('l') or key == ord('L'):
                    # Cycle through layouts
                    current_idx = LAYOUT_MODES.index(self.layout_mode) if self.layout_mode in LAYOUT_MODES else 0
                    self.layout_mode = LAYOUT_MODES[(current_idx + 1) % len(LAYOUT_MODES)]
                elif key == ord('+') or key == ord('='):
                    # Decrease refresh interval (faster)
                    self.refresh_rate = max(1, self.refresh_rate - 1)
                elif key == ord('-') or key == ord('_'):
                    # Increase refresh interval (slower)
                    self.refresh_rate = min(10, self.refresh_rate + 1)

            except curses.error:
                pass
            except Exception as e:
                with open('/tmp/sentinel.log', 'a') as f:
                    f.write(f"{datetime.now()}: {e}\n")


def run_service_mode(config):
    """Run in headless service mode - logs to file/stdout."""
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
            
            # Build log line
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
            
            # Output to stdout and optionally to file
            print(log_line)
            
            try:
                with open(log_file, 'a') as f:
                    f.write(log_line + "\n")
            except PermissionError:
                pass  # Can't write to log file, just use stdout
            
            time.sleep(interval)
            
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(interval)
    
    print("\nSentinel service stopped.")


def main():
    parser = argparse.ArgumentParser(
        description=f'Sentinel v{VERSION} - Universal Linux System Monitor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel                    # Run interactive TUI
  sentinel --theme nord       # Use Nord color theme
  sentinel --service          # Run in headless service mode
  sentinel --init-config      # Create default config file

Themes: default, nord, dracula, gruvbox, monokai

Config file locations (in order of priority):
  ~/.config/sentinel/config.json
  ~/.sentinel.json
  /etc/sentinel/config.json
"""
    )
    
    parser.add_argument('--version', action='version', version=f'Sentinel v{VERSION}')
    parser.add_argument('--theme', '-t', choices=list(THEMES.keys()), 
                        help='Color theme to use')
    parser.add_argument('--service', '-s', action='store_true',
                        help='Run in headless service mode (for systemd)')
    parser.add_argument('--init-config', action='store_true',
                        help='Create default config file')
    parser.add_argument('--config', '-c', type=str,
                        help='Path to config file')
    
    args = parser.parse_args()
    
    # Handle --init-config
    if args.init_config:
        config_path = save_default_config()
        print(f"Created default config at: {config_path}")
        print("\nYou can customize:")
        print("  - theme: default, nord, dracula, gruvbox, monokai")
        print("  - alerts: cpu_high, cpu_critical, mem_high, temp_high, etc.")
        print("  - refresh_rate: update interval in seconds")
        return
    
    # Load config
    config = load_config()
    
    # Override with command line args
    if args.theme:
        config['theme'] = args.theme
    
    if args.config:
        try:
            with open(args.config, 'r') as f:
                user_config = json.load(f)
                config.update(user_config)
        except Exception as e:
            print(f"Error loading config: {e}")
            return
    
    # Run in appropriate mode
    if args.service:
        run_service_mode(config)
    else:
        try:
            monitor = SentinelMonitor(config=config)
            curses.wrapper(monitor.draw)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
