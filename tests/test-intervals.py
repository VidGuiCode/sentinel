"""Test the v0.6.5 per-panel refresh intervals without curses or threads.

Cover valid_intervals, the COLLECTOR_NAMES roster, the DEFAULT_CONFIG
entry, apply_config's live interval overrides (fallback to base,
reset of absent entries, empty map, bad values, first-run note, CLI
skip, absent key), and the one-level dict merge in load_config_from.
No test starts a collector, spawns a child process, or writes outside
temp files. Exit nonzero on failure.
"""
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import types

_curses = types.ModuleType('curses')
for _n in ['COLOR_CYAN', 'COLOR_GREEN', 'COLOR_YELLOW', 'COLOR_RED',
           'COLOR_BLUE', 'COLOR_MAGENTA', 'COLOR_WHITE', 'A_BOLD',
           'A_REVERSE', 'A_DIM', 'COLOR_BLACK', 'KEY_RESIZE', 'KEY_ENTER',
           'KEY_BACKSPACE', 'KEY_UP', 'KEY_DOWN']:
    setattr(_curses, _n, 0)
_curses.color_pair = lambda n: n
_curses.error = Exception
sys.modules.setdefault('curses', _curses)

spec = importlib.util.spec_from_file_location(
    'sm_intervals', pathlib.Path(__file__).resolve().parent.parent / 'sentinel-monitor.py')
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


class _FakeCollector:
    """Stand-in for Collector with only the cadence fields."""

    def __init__(self, name, base):
        self.name = name
        self.base_interval = base
        self.interval = base


# Representative code defaults; only the base/interval pair matters.
_BASE_INTERVALS = {
    'docker': 5, 'docker_df': 30, 'kubernetes': 15, 'wireguard': 10,
    'proxy': 10, 'security': 5, 'processes': 5, 'public_ip': 300,
    'update_check': 21600, 'probes': 30, 'ssid': 60, 'health': 30,
}


def stub(**fields):
    mon = sm.SentinelMonitor.__new__(sm.SentinelMonitor)
    mon.config = dict(sm.DEFAULT_CONFIG)
    mon.config['_loaded_from'] = ''
    mon.config['_config_mtime'] = 0.0
    mon.config['_cli_keys'] = []
    mon.theme_name = 'default'
    mon.layout_mode = 'default'
    mon.refresh_rate = 2
    mon.alerts = dict(sm.DEFAULT_CONFIG['alerts'])
    mon.health_checks = {}
    mon.listeners = []
    mon.proxy_logs = dict(sm.DEFAULT_CONFIG['proxy_logs'])
    mon.security_logs = dict(sm.DEFAULT_CONFIG['security_logs'])
    mon.security_alerts_config = dict(sm.DEFAULT_CONFIG['security_alerts'])
    mon.show_per_core = True
    mon.show_vpn = True
    mon.public_ip_check = True
    mon._action_msg = ''
    mon._action_msg_at = 0.0
    mon._status_revision = 0
    mon._config_note = ''
    mon._config_note_at = 0.0
    mon._set_action_msg = sm.SentinelMonitor._set_action_msg.__get__(mon)
    mon.collectors = {name: _FakeCollector(name, base)
                      for name, base in _BASE_INTERVALS.items()}
    for key, value in fields.items():
        setattr(mon, key, value)
    return mon


def write_config(path, payload):
    pathlib.Path(path).write_text(json.dumps(payload))


# Temp files live in the repo tree: the sandbox blocks writes to the
# system temp dir. Clean the dir at start and at end.
_TMP = str(pathlib.Path(__file__).resolve().parent / '.tmp-intervals')
shutil.rmtree(_TMP, ignore_errors=True)
os.makedirs(_TMP, exist_ok=True)


# version tag
check('version is 0.6.5', sm.VERSION == '0.6.5')

# valid_intervals: the shape rules
check('empty map is valid', sm.valid_intervals({}) is True)
check('one entry is valid',
      sm.valid_intervals({'docker': 7}) is True)
check('multi entry map is valid',
      sm.valid_intervals({'docker': 7, 'ssid': 90, 'probes': 2}) is True)
check('low boundary 1 is valid', sm.valid_intervals({'docker': 1}) is True)
check('high boundary 604800 is valid',
      sm.valid_intervals({'update_check': 604800}) is True)
check('zero is invalid', sm.valid_intervals({'docker': 0}) is False)
check('above ceiling 604801 is invalid',
      sm.valid_intervals({'docker': 604801}) is False)
check('unknown panel name is invalid',
      sm.valid_intervals({'not_a_panel': 5}) is False)
check('string seconds are invalid',
      sm.valid_intervals({'docker': 'fast'}) is False)
check('bool seconds are invalid',
      sm.valid_intervals({'docker': True}) is False)
check('None seconds are invalid',
      sm.valid_intervals({'docker': None}) is False)
check('non-dict string is invalid', sm.valid_intervals('fast') is False)
check('non-dict list is invalid',
      sm.valid_intervals([('docker', 5)]) is False)
check('non-dict None is invalid', sm.valid_intervals(None) is False)
check('float seconds 2.5 are valid',
      sm.valid_intervals({'docker': 2.5}) is True)

# module structure: default map and the panel roster
check('default intervals empty', sm.DEFAULT_CONFIG['intervals'] == {})
check('COLLECTOR_NAMES is the 12 panels',
      sm.COLLECTOR_NAMES == frozenset({
          'docker', 'docker_df', 'kubernetes', 'wireguard', 'proxy',
          'security', 'processes', 'public_ip', 'update_check', 'probes',
          'ssid', 'health'}))

# apply_config: a valid map overrides named collectors and the rest
# fall back to their base_interval
a = stub()
a.collectors['health'].interval = 45  # make the fallback observable
a.apply_config({'intervals': {'docker': 7}, '_cli_keys': []})
check('apply overrides named collector',
      a.collectors['docker'].interval == 7)
check('apply resets others to base', a.collectors['health'].interval == 30)

# a later map without an entry resets that collector; named ones apply
a.apply_config({'intervals': {'security': 9}, '_cli_keys': []})
check('later map resets absent entry to base',
      a.collectors['docker'].interval == 5
      and a.collectors['security'].interval == 9)

# an empty map resets every collector to its base
a.apply_config({'intervals': {}, '_cli_keys': []})
check('empty map resets all to base',
      a.collectors['docker'].interval == 5
      and a.collectors['security'].interval == 5
      and a.collectors['health'].interval == 30)

# invalid maps keep every live interval and show the reason
b = stub()
b.collectors['docker'].interval = 7
b.collectors['security'].interval = 9
note_b1 = b.apply_config({'intervals': {'not_a_panel': 5}, '_cli_keys': []})
check('unknown name keeps live note',
      'bad intervals value kept' in note_b1)
note_b2 = b.apply_config({'intervals': {'docker': 0}, '_cli_keys': []})
check('zero keeps live note', 'bad intervals value kept' in note_b2)
note_b3 = b.apply_config({'intervals': {'docker': 'fast'}, '_cli_keys': []})
check('string value keeps live note',
      'bad intervals value kept' in note_b3)
check('bad maps keep live values',
      b.collectors['docker'].interval == 7
      and b.collectors['security'].interval == 9)

# first_run returns the note but stores nothing (fresh stub: earlier
# applies on b already stored their notes)
c = stub()
note_c = c.apply_config({'intervals': {'docker': 0}}, first_run=True)
check('first run returns the bad note',
      'bad intervals value kept' in note_c)
check('first run does not store the note',
      c._config_note == '' and c._status_revision == 0)

# the intervals key on the CLI list is skipped
b.apply_config({'intervals': {'docker': 3}, '_cli_keys': ['intervals']})
check('cli intervals key is skipped', b.collectors['docker'].interval == 7)

# a config without the key at all leaves intervals alone
b.apply_config({'theme': 'default', '_cli_keys': []})
check('missing key leaves intervals alone',
      b.collectors['docker'].interval == 7)

# load_config_from merges the intervals dict without clobbering defaults
tmp = os.path.join(_TMP, 'case1')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'intervals': {'docker': 7}})
    got = sm.load_config_from(path)
    check('load merges intervals from file',
          got.get('intervals') == {'docker': 7})
    check('load keeps other defaults', got.get('refresh_rate') == 2)
    check('load keeps globals clean',
          sm.DEFAULT_CONFIG['intervals'] == {})

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(('PASS' if ok else 'FAIL'), '-', name)
shutil.rmtree(_TMP, ignore_errors=True)
if failed:
    raise SystemExit('FAILURES: %s' % failed)
print('INTERVALS-TEST-OK')
