# Security Log Monitor - Implementation Notes

## Overview

Sentinel reads the Linux logs for authentication and system events. Sentinel shows the results in the terminal in real time. The collector runs apart from the render loop.

## Project Requirements Fulfillment

### 1. Input Data ✓

**Logs That Sentinel Reads:**

- `/var/log/auth.log` - Authentication events on Debian and Ubuntu
- `/var/log/secure` - Authentication events on RHEL and CentOS
- `/var/log/syslog` - General system events

**Configuration:**

```json
"security_logs": {
  "auth": "/var/log/auth.log",
  "secure": "/var/log/secure",
  "syslog": "/var/log/syslog"
}
```

### 2. Parse With Regular Expressions ✓

**Minimum 3 Fields Per Event:**

Each event gives these fields:

1. The timestamp uses `(\w+\s+\d+\s+\d+:\d+:\d+)` and gives the date and time of the event.
2. The host uses `(\S+)` and gives the name of the host.
3. The process name uses `(\w+)` and gives the name of the process.
4. The process ID uses `\[(\d+)\]` and gives the ID of the process.
5. The user name uses `(\S+)` and identifies the user name.
6. The IP address uses `from (\S+)` and gives the source IP address.
7. The message gives the full description of the event.

**Patterns That Sentinel Uses:**

```python
# Failed password attempts
r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[(\d+)\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)'

# Successful authentication
r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\w+)\[(\d+)\]:\s+Accepted (?:password|publickey) for (\S+) from (\S+)'

# Permission denied
r'(permission denied|authentication failure|invalid user|illegal user)'

# Sudo commands
r'^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*COMMAND=(.+)'
```

### 3. Monitor and Analysis ✓

#### 3.1 Statistics and Counters (4 Items)

**Statistic 1: Failed Logins by IP Address - Top 10**

Sentinel counts failed logins for each IP address. Sentinel sorts the IP addresses by count with the highest count first. The panel shows the list with colors.

**Statistic 2: Failed Login Ratio Per User Name**

Sentinel divides failed logins by total logins for each user name. The formula is `failed_logins / (failed_logins + successful_logins)`. Sentinel records login patterns for each user name. Sentinel finds user names under attack.

**Statistic 3: Common Error Types**

Sentinel counts each error type. Sentinel stores the count for each error type.

- "permission denied"
- "authentication failure"
- "invalid user"
- "illegal user"

**Statistic 4: Failed Logins by User Name - Top 10**

Sentinel maps each user name to a failed login count. Sentinel sorts the user names by count. Sentinel finds targets of brute force.

#### 3.2 Time Metrics (2 Items)

**Metric 1: Failed Logins Per 5-Minute Window**

Sentinel checks failed logins in a 5-minute window that moves in time. Sentinel uses a default of 300 seconds for the window size. Sentinel uses the result to find brute force.

**Metric 2: Error Rate Per 1-Minute Window**

Sentinel checks errors in a 1-minute window that moves in time. Sentinel uses a default threshold of 10 errors per minute. Sentinel sends an alert on a sudden rise in activity.

**Implementation:**

The code below cleans old events from the window.

```python
# Windowed analysis with automatic cleanup
cutoff_time = current_time - security_alerts_config['failed_login_window']
self._security_events = [e for e in self._security_events if e['timestamp'] > cutoff_time]

# Per-IP tracking with time windows
for ip in self._ip_failure_tracker.keys():
    self._ip_failure_tracker[ip] = [t for t in self._ip_failure_tracker[ip] if t > cutoff_time]
```

### 4. Alert Rule ✓

**Alert Rules That Sentinel Uses (3 Rules):**

#### Alert 1: Brute Force Detection

The condition is >20 failed logins from one IP address in 5 minutes. The type is danger with red color. The message is `"Possible brute force from {IP} ({count} attempts)"`. The purpose is to find automatic password attacks.

```python
for ip, timestamps in self._ip_failure_tracker.items():
    if len(timestamps) >= self.security_alerts_config['failed_login_threshold']:
        stats['alerts'].append({
            'type': 'brute_force',
            'message': f'Possible brute force from {ip} ({len(timestamps)} attempts)',
            'severity': 'danger'
        })
```

#### Alert 2: High Error Rate

The condition is ≥10 failed logins in 1 minute. The type is warning with yellow color. The message is `"{count} failed logins in 1 min"`. The purpose is to find login storms or faults in the configuration file.

#### Alert 3: Suspicious IP Address

The condition is one IP address with many failed logins. The type is warning with yellow color. The purpose is to record attackers that persist.

**How Sentinel Shows Alerts:**

- Sentinel shows alerts in the footer alert area.
- The text blinks with color for clear view.
- Sentinel shows the top 3 active alerts.
- Sentinel uses red for danger and yellow for warning.

### 5. Output Requirements ✓

**The Terminal Shows:**

1. Sentinel stores the total parsed lines in `stats['total_parsed']`.
2. Sentinel stores the total unparsed lines in `stats['total_unparsed']`.
3. Sentinel counts failed logins in real time.
4. Sentinel counts successful logins.
5. Sentinel gives the failed to success ratio as a percent.
6. Sentinel lists the top 10 IP addresses with attempt counts.
7. Sentinel lists the top 10 user names with failure counts.
8. Sentinel groups failures by error category.
9. Sentinel shows active alerts for brute force and high error rates.

**Security Panel Display:**

The panel below is an example.

```
┌─ power ──────────────────────┐
│  5.2W ████████░░░░ RAPL      │
│ ██████████████▌              │
│                              │
│ sec 23/45                    │ ← Header: 23 failed / 45 total logins
│  192.168.1.100        ×15    │ ← Top suspicious IP with count
│  10.0.0.50            ×8     │
│  172.16.0.99          ×4     │
└──────────────────────────────┘

Footer: [BRUTE FORCE Possible brute force from 192.168.1.100 (23 attempts)]
```

### 6. Technical Implementation Details

#### Architecture Integration

**How Sentinel Works:**

1. **Data Collection Method**
   - The `get_security_logs()` function starts at line 1178.
   - The function uses the same pattern as `get_proxy_stats()`.
   - Sentinel caches results for 5 seconds to reduce file reads.
   - The collector does not block the render loop.
2. **State Management**
   - The `self.failed_login_history` deque and the `self.suspicious_ip_history` deque store past events.
   - The `self._security_events` list records events in the current window.
   - The `self._ip_failure_tracker` dictionary records failures per IP address.
   - Sentinel removes old events automatically.
3. **How Sentinel Draws the Panel**
   - Sentinel draws the results in the power box in column 3.
   - Sentinel shares space with Docker and K8s.
   - The panel adapts to the size of the terminal.
   - Sentinel uses colors for severity.
4. **Layout System**
   - Sentinel provides a "security" layout mode.
   - The security panel uses 55% width in 3-column view.
   - Press `l` to change the layout in this order:
     - `default`
     - `cpu`
     - `network`
     - `docker`
     - `security`
     - `minimal`
5. **How Sentinel Sends Alerts**
   - Sentinel calls `check_alerts()` for each alert.
   - The alert works with all themes.
   - The footer shows alerts with colors.
   - The color reflects the severity.

#### Performance Optimizations

- Background collector: The collector reads logs on a separate thread.
  The collector runs each 5 seconds. The render loop never waits for the
  collector (v0.6).
- Limited read: Sentinel reads the last 1000 lines per check and 200 lines in light mode. Sentinel reads directly with `deque(maxlen=N)` and never calls `tail`.
- Windowed cleanup: Sentinel deletes old events from the window. Memory use stays flat in a long attack.
- Efficient patterns: Sentinel pre-compiles the patterns.
- Clear failure: If Sentinel cannot read a log, the panel reports `no
  permission`. The diagnostics overlay (`d`) shows the fix command. The
  panel never shows an empty view.

#### Configuration

**Thresholds That You Can Change:**

Edit the values in the configuration file.

```json
"security_alerts": {
  "failed_login_threshold": 20,      // Brute force detection
  "failed_login_window": 300,        // 5 minutes
  "suspicious_ip_threshold": 10,     // IP tracking
  "error_rate_threshold": 10,        // High error rate
  "error_rate_window": 60            // 1 minute
}
```

**Log File Paths:**

- Sentinel selects `auth.log` on Debian and Ubuntu. Sentinel selects `secure` on RHEL and CentOS.
- If the main log is absent, Sentinel uses syslog.
- Change the paths in the configuration file.

## Implementation Assessment

### 1. Practical Use

- Sentinel finds real brute force attacks in live systems.
- The patterns match real attacks on SSH with stolen passwords.
- The thresholds use common industry values.

### 2. Study Value

- The code shows regex with complex patterns.
- The code shows time analysis with 5-minute and 1-minute windows.
- The code applies real security monitor concepts.
- The code follows a clear structure.

### 3. Technical Points

- The code joins the current Sentinel code without conflict.
- The main monitor keeps the same speed.
- The code uses the same patterns as the current code.
- The code checks errors on all file reads.

### 4. Beyond Minimum Requirements

- Sentinel provides 4 statistics where the minimum is 2.
- Sentinel provides 2 time metrics where the minimum is 1.
- Sentinel provides 3 alert rules where the minimum is 1.
- Sentinel extracts 7 fields where the minimum is 3.
- Sentinel reads logs from more than one source:
  - `auth`
  - `secure`
  - `syslog`

### 5. Display

- Sentinel shows results in the text interface.
- Sentinel uses colors for severity.
- Sentinel refreshes the view in real time.
- Change the thresholds and paths in the configuration file.

## Usage Examples

### Basic Usage

Start Sentinel with the commands below.

```bash
# Run Sentinel with security monitoring
sentinel

# Use security-focused layout
sentinel --layout security

# Configure custom thresholds
sentinel --init-config
# Edit ~/.config/sentinel/config.json
```

### View Security Events

Start Sentinel with `sentinel`. Press `l` to select the security layout. Watch the right column for security results. The footer shows alerts when an event exceeds a threshold.

### Configuration Example

The example below sets a theme and thresholds.

```json
{
  "theme": "nord",
  "layout": "security",
  "refresh_rate": 2,
  "security_logs": {
    "auth": "/var/log/auth.log"
  },
  "security_alerts": {
    "failed_login_threshold": 15,
    "failed_login_window": 300
  }
}
```

## Test and Validation

### Tests for Log Parse

- ✓ The test checks failed password attempts with SSH.
- ✓ The test checks successful logins.
- ✓ The test checks invalid user names.
- ✓ The test checks permission denied events.
- ✓ The test checks sudo commands.

### Alert Tests

- ✓ The test checks brute force with >20 failures.
- ✓ The test checks high error rate.
- ✓ The test checks records for more than one IP address.
- ✓ The test checks removal of old events from the window.

### Integration Tests

- ✓ The test confirms no loss in speed.
- ✓ The test passes on these systems:
  - Debian
  - Ubuntu
  - RHEL
- ✓ Sentinel acts safely if a log is absent.
- ✓ The panel adapts to a new terminal size.

## Code Quality

- The security code uses ~200 lines.
- Sentinel uses 4 regex patterns.
- Sentinel uses deques and dictionaries.
- Sentinel uses try and except on all file reads.
- Inline notes describe the logic.
- The style matches the current code and PEP 8.

## Conclusion

This monitor provides a security monitor that:

- The monitor meets all school project requirements.
- The monitor exceeds the minimum values.
- The monitor joins the current Sentinel design.
- The monitor shows clear software methods.
- The monitor gives useful security facts.

Sentinel includes the feature as a normal part of the design. The feature helps administrators who watch security events.

---

**Author:** Biren Gil (with Claude Code)
**Date:** 2026-01-22
**Version:** Sentinel v0.5.0 includes this function. Sentinel v0.6.0 adds the collector and clear permission reports.
**Project:** Linux Log Analyser and Monitor (School Assignment)
