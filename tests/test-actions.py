"""Test the v0.6.3 quick-action logic without curses or Docker.

Drive only non-destructive paths: dry-run acts, input validators,
output parsers, confirm/prompt state code, header text, and the key
map. No test restarts a container, stops a container, kills a PID,
applies updates, or starts a child process. Exit nonzero on failure.
"""
import importlib.util
import os
import pathlib
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
    'sm_actions', pathlib.Path(__file__).resolve().parent.parent / 'sentinel-monitor.py')
sm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sm)

checks = []


def check(name, cond):
    checks.append((name, bool(cond)))


def blank():
    mon = sm.SentinelMonitor.__new__(sm.SentinelMonitor)
    mon.cache = {'docker': {'containers': []}}
    mon._docker_cursor = 0
    mon._action_mode = None
    mon._confirm = None
    mon._prompt_kind = None
    mon._prompt_text = ''
    mon._prompt_error = ''
    mon._action_msg = ''
    mon._action_msg_at = 0.0
    mon._pkg_last = None
    mon._pkg_pending = None
    mon._pkg_error = ''
    mon._status_revision = 0
    mon._show_help = False
    mon._show_diagnostics = False
    mon.wake_collector = lambda name: None
    mon._set_action_msg = sm.SentinelMonitor._set_action_msg.__get__(mon)
    return mon


# apt parser
check('apt counts two', sm.count_apt_upgradable(
    'Listing...\nfoo/jammy 1.2 amd64 [upgradable]\n'
    'bar/jammy 3.4 amd64 [upgradable]\n') == 2)
check('apt skips header', sm.count_apt_upgradable('Listing...\n') == 0)
check('apt empty is zero', sm.count_apt_upgradable('') == 0)

# dnf parser
check('dnf counts two', sm.count_dnf_updates(
    'Last metadata check.\nfoo.x86_64  1.2  updates\n'
    'bar.noarch  3.4  updates\n') == 2)
check('dnf empty is zero', sm.count_dnf_updates('') == 0)

# pacman parser
check('pacman counts two', sm.count_pacman_updates('foo 1.2 -> 1.3\nbar 2 -> 3\n') == 2)
check('pacman blank lines skipped',
      sm.count_pacman_updates('foo 1.2 -> 1.3\n\n') == 1)

# manager detect + argv
check('detect apt', sm.detect_pkg_manager(which=lambda t: '/usr/bin/apt' if t == 'apt' else None) == 'apt')
check('detect dnf', sm.detect_pkg_manager(which=lambda t: '/usr/bin/dnf' if t == 'dnf' else None) == 'dnf')
check('detect none', sm.detect_pkg_manager(which=lambda t: None) is None)
check('check argv apt', sm.pkg_check_argv('apt') == ['apt', 'list', '--upgradable'])
check('check argv dnf', sm.pkg_check_argv('dnf') == ['dnf', 'check-update'])
check('check argv pacman', sm.pkg_check_argv('pacman') == ['pacman', '-Qu'])
check('check argv unknown', sm.pkg_check_argv('zypper') is None)
apply_argv = sm.apply_updates_argv('apt')
check('apply argv uses sudo', apply_argv is not None and apply_argv[0] == 'sudo')
check('apply argv has no shell', all(' ' not in str(p) or p == 'apt-get' for p in apply_argv))
check('apply argv unknown', sm.apply_updates_argv('zypper') is None)

# ping parser
check('ping linux rtt', sm.parse_ping_avg(
    'rtt min/avg/max/mdev = 1.1/2.5/3.3/0.4 ms\n') == '2.5 ms')
check('ping macos round-trip', sm.parse_ping_avg(
    'round-trip min/avg/max/stddev = 10.1/12.0/15.2/1.0 ms\n') == '12.0 ms')
check('ping empty is none', sm.parse_ping_avg('') is None)

# host validator (no shell chars pass)
check('host ok', sm.validate_ping_host('pi4.lan') == ('pi4.lan', None))
check('host empty rejected', sm.validate_ping_host('')[0] is None)
check('host shell rejected', sm.validate_ping_host('a; rm -rf /')[0] is None)
check('host space rejected', sm.validate_ping_host('my host')[0] is None)

# pid validator
me = os.getpid()
check('pid ok', sm.validate_action_pid('1234', me) == (1234, None))
check('pid text rejected', sm.validate_action_pid('abc', me)[0] is None)
check('pid 1 rejected', sm.validate_action_pid('1', me)[0] is None)
check('pid self rejected', sm.validate_action_pid(str(me), me)[0] is None)

# docker action paths
check('restart path', sm.docker_action_path('abc123', 'restart') == '/containers/abc123/restart?t=10')
check('stop path', sm.docker_action_path('abc123', 'stop') == '/containers/abc123/stop?t=10')
try:
    sm.docker_action_path('abc123', 'rm')
    check('bad action raises', False)
except sm.DockerError:
    check('bad action raises', True)
try:
    sm.docker_action_path('a; evil', 'restart')
    check('bad id raises', False)
except sm.DockerError:
    check('bad id raises', True)

# dry-run acts change nothing
m = blank()
m.cache = {'docker': {'containers': [{'id': 'abc123', 'name': 'web', 'status': 'running'}]}}
check('restart dry-run text', m.docker_restart_target(dry_run=True) == 'Restart container web?')
check('stop dry-run text', m.docker_stop_target(dry_run=True) == 'Stop container web?')
check('kill dry-run text', m.kill_pid(999999, dry_run=True) == 'Kill PID 999999?')
check('kill dry-run self blocked', 'Sentinel itself' in m.kill_pid(me, dry_run=True))
check('kill dry-run pid1 blocked', 'init process' in m.kill_pid(1, dry_run=True))
m2 = blank()
check('restart empty', m2.docker_restart_target(dry_run=True) == 'No containers to restart')
check('stop empty', m2.docker_stop_target(dry_run=True) == 'No containers to stop')

# cursor clamp
m3 = blank()
m3.cache = {'docker': {'containers': [
    {'id': 'a', 'name': 'a', 'status': 'running'},
    {'id': 'b', 'name': 'b', 'status': 'running'},
    {'id': 'c', 'name': 'c', 'status': 'running'}]}}
check('cursor down', m3.docker_cursor_move(1) == 1)
check('cursor clamp top', m3.docker_cursor_move(99) == 2)
check('cursor clamp bottom', m3.docker_cursor_move(-99) == 0)
check('docker target follows cursor',
      (m3.docker_cursor_move(2), m3._docker_target()['name']) == (2, 'c'))

# confirm box flow: open, cancel, state cleared
m4 = blank()
m4.cache = {'docker': {'containers': [{'id': 'abc', 'name': 'web', 'status': 'running'}]}}
m4._confirm_open('restart', 'web')
check('confirm opens', m4._action_mode == 'confirm' and m4._confirm['kind'] == 'restart')
check('confirm title', m4._action_confirm_title('restart', 'web') == 'Restart container web?')
check('confirm explain two lines',
      len(m4._action_explain('restart', 'web')) == 2)
m4._confirm_handle_key(ord('n'))
check('confirm cancel clears', m4._action_mode is None and m4._confirm is None)
check('confirm cancel message', m4._action_msg == 'Cancelled')
m4._confirm_open('stop', 'web')
m4._confirm_handle_key(27)
check('confirm esc cancels', m4._action_mode is None and m4._confirm is None)

# confirm y calls the act once (stub the act, record calls)
m5 = blank()
calls = []
m5.docker_restart_target = lambda dry_run=False: (calls.append('restart'), 'Restarted container web')[1]
m5._confirm_open('restart', 'web')
m5._confirm_handle_key(ord('y'))
check('confirm y runs act', calls == ['restart'])
check('confirm y closes', m5._action_mode is None)
check('confirm y shows result', m5._action_msg == 'Restarted container web')

# apply confirm from check result: needs count
m6 = blank()
m6.run_cmd_full = lambda argv, timeout=2, stderr=False: ('', 0)
m6._pkg_last = None
m6._handle_key(None, ord('a'))
check('apply without check blocked', 'Press u' in m6._action_msg)
m6._pkg_last = {'manager': 'apt', 'count': 3, 'at': 0.0}
m6._handle_key(None, ord('a'))
check('apply opens confirm', m6._action_mode == 'confirm' and m6._confirm['kind'] == 'apply')

# prompt flow: open pid, type, enter moves to confirm (no kill yet)
m7 = blank()
kills = []
m7.kill_pid = lambda pid, dry_run=False: (kills.append(pid), 'x')[1]
m7._handle_key(None, ord('k'))
check('pid prompt opens', m7._action_mode == 'prompt' and m7._prompt_kind == 'pid')
for ch in '4242':
    m7._handle_key(None, ord(ch))
m7._handle_key(None, 13)
check('pid enter opens confirm', m7._action_mode == 'confirm' and m7._confirm.get('pid') == 4242)
check('pid enter kills nothing', kills == [])
killed = []
m7.kill_pid = lambda pid, dry_run=False: (killed.append(pid), 'Killed PID 4242')[1]
m7._confirm_handle_key(ord('y'))
check('kill confirm runs once', killed == [4242])

# prompt flow: bad pid stays in prompt with error
m8 = blank()
m8._handle_key(None, ord('k'))
m8._prompt_text = 'abc'
m8._handle_key(None, 13)
check('bad pid shows error', m8._action_mode == 'prompt' and bool(m8._prompt_error))

# prompt flow: esc cancels
m8._handle_key(None, 27)
check('prompt esc cancels', m8._action_mode is None and m8._prompt_kind is None)

# u check fills header via stubbed runner (no child process)
m9 = blank()
m9.run_cmd_full = lambda argv, timeout=2, stderr=False: (
    'Listing...\nfoo/jammy 1.2 amd64 [upgradable]\n', 0)
orig_which = sm.shutil.which
sm.shutil.which = lambda t: '/usr/bin/apt' if t == 'apt' else None
try:
    msg = m9.check_pkg_updates()
finally:
    sm.shutil.which = orig_which
check('u message counts', msg == '1 update available')
check('u fills header', m9.pkg_header_text() == '1 update')

# ping runs through stubbed runner (no child process)
m10 = blank()
m10.run_cmd_full = lambda argv, timeout=2, stderr=False: (
    'rtt min/avg/max/mdev = 1.0/4.2/9.0/0.5 ms\n', 0)
sm.shutil.which = lambda t: '/usr/bin/ping' if t == 'ping' else None
try:
    out = m10.ping_host_text('pi4.lan')
finally:
    sm.shutil.which = orig_which
check('ping message', out == 'pi4.lan: 4.2 ms')
check('ping needs no confirm', m10._action_mode is None)

# check_pkg_updates merges no manager cleanly
m11 = blank()
sm.shutil.which = lambda t: None
try:
    err = m11.check_pkg_updates()
finally:
    sm.shutil.which = orig_which
check('no manager message', 'no package manager' in err)
check('no manager header hidden', m11.pkg_header_text() is None)

failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(('PASS' if ok else 'FAIL'), '-', name)
if failed:
    raise SystemExit('FAILURES: %s' % failed)
print('ACTIONS-TEST-OK')
