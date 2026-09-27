"""Test the v0.6.4 config hot-reload logic without curses or threads.

Drive only non-destructive paths: config mtime helpers, reload merge
rules, apply_config field rules, diagnostics error text, and the
curses-missing guard. No test starts a collector, spawns a child
process, or writes outside temp files. Exit nonzero on failure.
"""
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import tempfile
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
    'sm_reload', pathlib.Path(__file__).resolve().parent.parent / 'sentinel-monitor.py')
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


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
    for key, value in fields.items():
        setattr(mon, key, value)
    return mon


def write_config(path, payload):
    pathlib.Path(path).write_text(json.dumps(payload))


def write_bad(path):
    """Write one malformed config file, the input for the error paths."""
    pathlib.Path(path).write_text('{bad json')


# Temp files live in the repo tree: the sandbox blocks writes to the
# system temp dir. Clean the dir at start and at end.
_TMP = str(pathlib.Path(__file__).resolve().parent / '.tmp-reload')
shutil.rmtree(_TMP, ignore_errors=True)
os.makedirs(_TMP, exist_ok=True)


# version tag
check('version is 0.6.5', sm.VERSION == '0.6.5')

# config_mtime: missing path gives 0.0
check('mtime missing is 0.0',
      sm.config_mtime('/nonexistent/sentinel-test.json') == 0.0)

# load_config_from: reads one file, tags source and mtime
tmp = os.path.join(_TMP, 'case1')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'theme': 'nord', 'refresh_rate': 5})
    got = sm.load_config_from(path)
    check('load_from reads theme', got.get('theme') == 'nord')
    check('load_from reads rate', got.get('refresh_rate') == 5)
    check('load_from tags source', got.get('_loaded_from') == path)
    check('load_from tags mtime', got.get('_config_mtime', 0.0) > 0.0)
    # bad json keeps defaults and records the error
    write_bad(path)
    bad = sm.load_config_from(path)
    check('bad file records error', '_config_error' in bad)
    check('bad file keeps theme default', bad.get('theme') == 'default')
    # missing file gives defaults with no error
    missing = sm.load_config_from(os.path.join(tmp, 'absent.json'))
    check('absent file has no error', '_config_error' not in missing)
    check('absent file keeps defaults', missing.get('theme') == 'default')

# reload_config: fresh file values win, CLI keys stay
tmp = os.path.join(_TMP, 'case2')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'theme': 'nord', 'refresh_rate': 5})
    old = dict(sm.DEFAULT_CONFIG)
    old['_loaded_from'] = path
    old['_config_mtime'] = 0.0
    old['_cli_keys'] = ['theme']
    old['theme'] = 'dracula'
    new = sm.reload_config(old, path)
    check('reload keeps cli theme', new.get('theme') == 'dracula')
    check('reload takes file rate', new.get('refresh_rate') == 5)
    check('reload refreshes mtime', new.get('_config_mtime', 0.0) > 0.0)
    # bad file keeps old live values and records the error
    write_bad(path)
    keep = sm.reload_config({'theme': 'nord', '_loaded_from': path,
                             '_config_mtime': 1.0, '_cli_keys': []})
    check('reload bad file keeps live', keep.get('theme') == 'nord')
    check('reload bad file records error', '_config_error' in keep)

# maybe_reload_config: no change means no reload
m = stub()
m.config['_loaded_from'] = ''
check('maybe no path is false', sm.maybe_reload_config(m) is False)
check('maybe no path keeps config', m.config.get('theme') == 'default')

tmp = os.path.join(_TMP, 'case3')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'theme': 'nord'})
    m2 = stub()
    m2.config = sm.load_config_from(path)
    m2.theme_name = m2.config.get('theme')
    check('maybe same mtime is false', sm.maybe_reload_config(m2) is False)
    check('maybe same mtime keeps theme', m2.theme_name == 'nord')
    # touch the file with a new theme: reload fires
    mtime_before = m2.config.get('_config_mtime', 0.0)
    os.utime(path, (mtime_before - 100, mtime_before - 100))
    m2.config['_config_mtime'] = mtime_before - 100
    write_config(path, {'theme': 'dracula'})
    check('maybe new mtime is true', sm.maybe_reload_config(m2) is True)
    check('maybe new mtime applies theme', m2.theme_name == 'dracula')
    # bad file edit: no reload, old values stay
    m2.config['_config_mtime'] = 0.0
    write_bad(path)
    check('maybe bad file is false', sm.maybe_reload_config(m2) is False)
    check('maybe bad file keeps theme', m2.theme_name == 'dracula')

# apply_config: safe keys update live fields at once
a = stub()
full_alerts = dict(sm.DEFAULT_CONFIG['alerts'])
full_alerts['cpu_high'] = 50
note = a.apply_config({'theme': 'nord', 'refresh_rate': 3,
                       'alerts': full_alerts,
                       'health_checks': {'web': {'url': 'http://localhost:80',
                                                 'expect': 200}},
                       'listeners': [80],
                       '_cli_keys': []})
check('apply theme', a.theme_name == 'nord')
check('apply rate', a.refresh_rate == 3)
check('apply alerts', a.alerts.get('cpu_high') == 50)
check('apply alerts keep rest', len(a.alerts) == 8
      and a.alerts.get('mem_high') == 80)
check('apply checks', a.health_checks.get('web', {}).get('expect') == 200)
check('apply listeners', a.listeners == [80])
check('apply clean gives empty note', note == '')
check('apply note leaves action msg alone',
      a._action_msg == '')

# apply_config: bad values keep old fields and show a note
b = stub()
note_b = b.apply_config({'theme': 'nope', 'refresh_rate': 99,
                         'listeners': 'not-a-list', '_cli_keys': []})
check('bad theme keeps old', b.theme_name == 'default')
check('bad rate keeps old', b.refresh_rate == 2)
check('bad listeners keep old', b.listeners == [])
check('bad values note shown', bool(note_b))

# apply_config: held keys wait for restart
c = stub()
note_c = c.apply_config({'light_mode': True, 'log_file': '/tmp/x.log',
                         '_cli_keys': []})
check('held light stays off note', 'light_mode' in note_c)
check('held log stays off note', 'log_file' in note_c)

# apply_config: CLI keys stay over file values
d = stub()
d.theme_name = 'dracula'
note_d = d.apply_config({'theme': 'nord', '_cli_keys': ['theme']})
check('cli theme wins', d.theme_name == 'dracula')
check('cli hold shows note', 'theme' in note_d)

# apply_config: the file is the source of truth for live keys
e = stub()
e.layout_mode = 'cpu'
note_e = e.apply_config({'layout': 'network', '_cli_keys': []})
check('file layout applies', e.layout_mode == 'network')
check('no spurious hold note', 'waits for restart' not in note_e)

# M1: a bad edit surfaces the error in the live config and stops
# re-parsing on each cycle (mtime moves past the bad write)
tmp = os.path.join(_TMP, 'case4')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'theme': 'nord'})
    m3 = stub()
    m3.config = sm.load_config_from(path)
    m3.theme_name = 'nord'
    m3.config['_config_mtime'] = 0.0
    write_bad(path)
    check('maybe bad edit is false', sm.maybe_reload_config(m3) is False)
    check('bad edit keeps live theme', m3.theme_name == 'nord')
    check('bad edit records error text',
          '_config_error' in m3.config)
    check('bad edit moves mtime past write',
          m3.config.get('_config_mtime', 0.0) > 0.0)
    check('bad edit parses once only',
          sm.maybe_reload_config(m3) is False)

# M2: a removed nested key stops at once (no stale linger)
tmp = os.path.join(_TMP, 'case5')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'health_checks':
                        {'web': {'url': 'http://localhost:80',
                                 'expect': 200}}})
    m4 = stub()
    m4.config = sm.load_config_from(path)
    m4.health_checks = dict(m4.config.get('health_checks', {}))
    m4.config['_config_mtime'] = 0.0
    write_config(path, {})
    check('maybe delete fires', sm.maybe_reload_config(m4) is True)
    check('deleted check stops', m4.health_checks == {})

# M3: loads never write into DEFAULT_CONFIG (deep copy)
tmp = os.path.join(_TMP, 'case6')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    before = dict(sm.DEFAULT_CONFIG['alerts'])
    write_config(path, {'alerts': {'cpu_high': 50}})
    sm.load_config_from(path)
    check('load keeps globals clean',
          sm.DEFAULT_CONFIG['alerts'] == before)
    old = dict(sm.DEFAULT_CONFIG)
    old['_loaded_from'] = path
    old['_config_mtime'] = 0.0
    old['_cli_keys'] = []
    sm.reload_config(old, path)
    check('reload keeps globals clean',
          sm.DEFAULT_CONFIG['alerts'] == before)

# M4 order: --config merge runs before CLI flags, so CLI wins.
# Trace the main() merge order by hand: config file sets nord,
# then the CLI flag sets dracula and tags _cli_keys.
tmp = os.path.join(_TMP, 'case7')
os.makedirs(tmp, exist_ok=True)
if True:
    path = os.path.join(tmp, 'config.json')
    write_config(path, {'theme': 'nord'})
    cfg = sm.load_config_from(path)
    cfg['_cli_keys'] = []
    cfg['theme'] = 'dracula'
    cfg['_cli_keys'].append('theme')
    write_config(path, {'theme': 'monokai'})
    cfg['_config_mtime'] = 0.0
    m5 = stub()
    m5.config = cfg
    m5.theme_name = 'dracula'
    check('maybe cli pin holds', sm.maybe_reload_config(m5) is True)
    check('cli theme wins over file', m5.theme_name == 'dracula')

# m5: a good load after a bad first path drops the stale error.
# Point HOME/USERPROFILE at a workspace dir with a bad first-path
# file and a good second-path file, then load and check.
tmp = os.path.join(_TMP, 'case8')
os.makedirs(os.path.join(tmp, '.config', 'sentinel'), exist_ok=True)
if True:
    bad_path = os.path.join(tmp, '.config', 'sentinel', 'config.json')
    good_path = os.path.join(tmp, '.sentinel.json')
    write_bad(bad_path)
    write_config(good_path, {'theme': 'nord'})
    saved_home = os.environ.get('USERPROFILE')
    saved_home2 = os.environ.get('HOME')
    os.environ['USERPROFILE'] = tmp
    os.environ['HOME'] = tmp
    try:
        cfg8 = sm.load_config()
    finally:
        if saved_home is None:
            os.environ.pop('USERPROFILE', None)
        else:
            os.environ['USERPROFILE'] = saved_home
        if saved_home2 is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = saved_home2
    check('good second path loads', cfg8.get('theme') == 'nord')
    check('stale error dropped', '_config_error' not in cfg8)

# require_curses: clear fix text when curses is missing
saved = sm.curses
try:
    sm.curses = None
    try:
        sm.require_curses()
        check('missing curses raises', False)
    except SystemExit as ex:
        text = str(ex)
        check('missing curses names fix', 'python3-curses' in text)
        check('missing curses names windows fix', 'windows-curses' in text)
        check('missing curses probe modes stay curses-free',
              '--dump' in text and '--host' not in text)
finally:
    sm.curses = saved
check('curses present passes', sm.require_curses() is None)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(('PASS' if ok else 'FAIL'), '-', name)
shutil.rmtree(_TMP, ignore_errors=True)
if failed:
    raise SystemExit('FAILURES: %s' % failed)
print('RELOAD-TEST-OK')
