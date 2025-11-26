# Sentinel v0.3 - Universal Linux System Monitor

A lightweight terminal UI (TUI) system monitor for Linux with real-time graphs, container monitoring, and infrastructure-focused design. Inspired by btop.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.6+-green.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey.svg)
![Version](https://img.shields.io/badge/version-0.3.0-cyan.svg)

## Features

### System Monitoring
- **CPU** - Per-core usage bars, gradient graph, temperature, frequency, governor
- **Memory** - Usage with history graph, available memory tracking
- **Disk** - Mount points with progress bars, Docker volume sizes
- **Network** - Live traffic (KB/s), sparkline graphs, VPN status
- **Energy** - RAPL power (desktops), battery stats (laptops)
- **Docker** - Container status, running/stopped count
- **Kubernetes** - Pod status, node health, failed/pending alerts
- **Processes** - Task count, top CPU/memory consumers

### v0.3 Features
- Docker container and volume monitoring
- Kubernetes pod/node monitoring
- Config file support (`~/.config/sentinel/config.json`)
- 5 color themes: default, nord, dracula, gruvbox, monokai
- Configurable alert thresholds
- Systemd service mode for headless logging
- Per-core CPU usage bars
- Theme switching with `t` key

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
- WireGuard VPN status with peer count
- Real-time traffic graphs
- Total RX/TX statistics

## Installation

### One-Line Install

```bash
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinal/main/install-sentinel.sh | sudo bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/VidGuiCode/sentinal/main/install-sentinel.sh | sudo bash
```

### From Source

```bash
git clone https://github.com/VidGuiCode/sentinal.git
cd sentinal
sudo bash install-sentinel.sh
```

### Manual (No Installer)

```bash
sudo apt-get install python3 lm-sensors curl
curl -sL https://raw.githubusercontent.com/VidGuiCode/sentinal/main/sentinel-monitor.py | sudo tee /usr/local/bin/sentinel > /dev/null
sudo chmod +x /usr/local/bin/sentinel
```

## Usage

```bash
sentinel                      # Run TUI
sentinel --theme nord         # Use Nord theme
sentinel --service            # Headless service mode
sentinel --init-config        # Create config file
sentinel --help               # Show options
```

### Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `r` | Force refresh |
| `t` | Cycle themes |
| `i` | Check public IP |

### Configuration

Create config with `sentinel --init-config`:

```json
{
  "theme": "default",
  "refresh_rate": 2,
  "alerts": {
    "cpu_high": 85,
    "cpu_critical": 95,
    "mem_high": 80,
    "temp_high": 75,
    "battery_low": 20
  }
}
```

### Systemd Service

```bash
sudo cp sentinel.service /etc/systemd/system/
sudo systemctl enable --now sentinel
journalctl -u sentinel -f
```

## Requirements

- Python 3.6+
- Linux kernel 4.0+
- Optional: lm-sensors, curl, docker, kubectl

## Changelog

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

## License

MIT License - See LICENSE file.
