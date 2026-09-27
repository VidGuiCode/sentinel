"""Test the v0.6.6 webhook notifications without curses or network.

Cover valid_notifications, the DEFAULT_CONFIG entry, the SSRF url
guard on literal IPs only (no DNS, no sockets), _webhook_post against
a stub urllib.request namespace, apply_config's notifications key
(normalize, bad value, CLI skip, stub safety, feature status), the
alert edge diff (fired / still / resolved, cooldown, skip paths,
same-name merge), the message text shapes, and one real worker thread
driven by a monkeypatched _webhook_post and a stop event. No test
opens a socket, starts a collector, or writes outside temp files.
Exit nonzero on failure.
"""
import importlib.util
import json
import os
import pathlib
import queue
import shutil
import sys
import threading
import time
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
    'sm_notify', pathlib.Path(__file__).resolve().parent.parent / 'sentinel-monitor.py')
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
    mon.refresh_rate = 2
    mon.alerts = dict(sm.DEFAULT_CONFIG['alerts'])
    mon.health_checks = {}
    mon.listeners = []
    mon._action_msg = ''
    mon._action_msg_at = 0.0
    mon._status_revision = 0
    mon._config_note = ''
    mon._config_note_at = 0.0
    mon._light_mode = False
    mon.notifications = {'webhooks': [], 'cooldown': 300}
    mon._alert_state = {}
    mon._notify_queue = queue.Queue()
    # The worker-start flag is on by default, so no test ever spawns a
    # thread unless it opts out explicitly (the worker section only).
    mon._notify_worker_started = True
    mon._collector_stop = threading.Event()
    mon.hostname = 'notify-test'
    mon.cache = {'cpu': {}, 'mem': {}, 'battery': {}, 'docker': {},
                 'health': {}, 'kubernetes': {}, 'security': {}}
    mon._set_action_msg = sm.SentinelMonitor._set_action_msg.__get__(mon)
    for key, value in fields.items():
        setattr(mon, key, value)
    return mon


def stub_with_status(**fields):
    """A stub that also carries the feature status map, so the guarded
    status callback in apply_config and the worker can record states."""
    mon = stub(feature_status={}, **fields)
    mon._set_feature_status = sm.SentinelMonitor._set_feature_status.__get__(mon)
    return mon


def drain(q):
    out = []
    while True:
        try:
            out.append(q.get_nowait())
        except queue.Empty:
            return out


def notify_threads():
    return sum(1 for t in threading.enumerate()
               if t.name == 'sentinel-notify')


def wait_status(mon, state, timeout=5.0):
    """Poll for one feature status state with a deadline. The worker
    writes the status right after the fake returns, so the fake's
    event alone would race that write."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        entry = mon.feature_status.get('notify')
        if entry and entry.get('state') == state:
            return True
        time.sleep(0.02)
    return False


# Temp files live in the repo tree: the sandbox blocks writes to the
# system temp dir. Clean the dir at start and at end.
_TMP = str(pathlib.Path(__file__).resolve().parent / '.tmp-notify')
shutil.rmtree(_TMP, ignore_errors=True)
os.makedirs(_TMP, exist_ok=True)


# version tag and the config default
check('version is 0.6.6', sm.VERSION == '0.6.6')
check('default notifications shape',
      sm.DEFAULT_CONFIG['notifications'] == {'webhooks': [], 'cooldown': 300})

# valid_notifications: the shape rules
VN = sm.valid_notifications
check('valid empty hooks and default cooldown', VN({'webhooks': []}) is True)
check('valid one hook and float cooldown',
      VN({'webhooks': ['https://hooks.example/a'], 'cooldown': 90.5}) is True)
check('cooldown bounds 60 and 86400 valid',
      VN({'webhooks': [], 'cooldown': 60}) is True
      and VN({'webhooks': [], 'cooldown': 86400}) is True)
check('cooldown out of range invalid',
      all(not VN({'webhooks': [], 'cooldown': c})
          for c in (59, 59.9, 86401, True, '300')))
check('bad webhook entries invalid',
      not VN({'webhooks': ['https://a/', 'ftp://b/']})
      and not VN({'webhooks': [42]})
      and not VN({'webhooks': 'https://a/'})
      and not VN('nope') and not VN(None)
      and not VN([('webhooks', [])]))
check('eleven hooks invalid',
      not VN({'webhooks': ['https://h/%d' % i for i in range(11)]}))

# load_config_from passes the notifications key through the merge
path = os.path.join(_TMP, 'config.json')
pathlib.Path(path).write_text(json.dumps(
    {'notifications': {'webhooks': ['https://hooks.example/a'],
                       'cooldown': 120}}))
got = sm.load_config_from(path)
check('load reads notifications from file',
      got.get('notifications') == {'webhooks': ['https://hooks.example/a'],
                                   'cooldown': 120})

# _url_guard_detail: literal IPs only, no DNS is touched
GUARD = sm._url_guard_detail
check('localhost and LAN literal pass',
      GUARD('http://127.0.0.1:80/metrics') is None
      and GUARD('https://192.168.1.5:8080/hook') is None)
check('link-local literal is blocked',
      GUARD('http://169.254.169.254/latest/meta-data/')
      == 'blocked url (link-local host)')
check('bad scheme and non-string refused',
      GUARD('ftp://hooks.example/') == 'bad url (need http:// or https://)'
      and GUARD(None) == 'bad url (need http:// or https://)')
check('missing host refused', GUARD('http:///path') == 'bad url (no host)')

# unresolvable host: getaddrinfo is stubbed, so the refusal is
# deterministic and no DNS query leaves the process
_real_getaddrinfo = sm.socket.getaddrinfo


def _no_dns(host, *args, **kwargs):
    raise OSError('test: dns disabled')


try:
    sm.socket.getaddrinfo = _no_dns
    got_guard = GUARD('https://hooks.unreachable.invalid/hook')
finally:
    sm.socket.getaddrinfo = _real_getaddrinfo
check('unresolvable host refused',
      got_guard == 'cannot resolve hooks.unreachable.invalid')


# _webhook_post: a stub urllib.request namespace, no network
class _FakeResp:
    """A context-manager response, since _webhook_post uses `with`."""

    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FakeOpener:
    def __init__(self, status, exc=None):
        self.addheaders = []
        self._status = status
        self._exc = exc
        self.opened = None

    def open(self, url, data=None, timeout=None):
        self.opened = (url, data, timeout)
        if self._exc is not None:
            raise self._exc
        return _FakeResp(self._status)


class _FakeUrllib:
    def __init__(self, status, exc=None):
        self.last = None
        self._status = status
        self._exc = exc

    def build_opener(self):
        self.last = _FakeOpener(self._status, self._exc)
        return self.last


fake = _FakeUrllib(200)
ok200, detail200 = sm._webhook_post(fake, 'http://127.0.0.1:9911/hook',
                                    {'a': 1})
check('post 2xx returns ok', (ok200, detail200) == (True, 'HTTP 200'))
check('post sets UA and json headers',
      ('User-Agent', 'sentinel/0.6.6') in fake.last.addheaders
      and ('Content-Type', 'application/json') in fake.last.addheaders)
check('post body is json bytes',
      fake.last.opened[0] == 'http://127.0.0.1:9911/hook'
      and fake.last.opened[1] == json.dumps({'a': 1}).encode('utf-8'))
fake5 = _FakeUrllib(503)
fakeerr = _FakeUrllib(200, exc=OSError('conn refused'))
ok5, detail5 = sm._webhook_post(fake5, 'http://127.0.0.1:9911/hook', {})
oke, detaile = sm._webhook_post(fakeerr, 'http://127.0.0.1:9911/hook', {})
check('post failures return false detail',
      (ok5, detail5) == (False, 'HTTP 503')
      and (oke, detaile) == (False, 'conn refused'))


# apply_config: notifications is a safe key
bare = stub()
check('stub is bare (no feature status map)',
      'feature_status' not in vars(bare)
      and '_set_feature_status' not in vars(bare))
note_a = bare.apply_config({'notifications':
                            {'webhooks': ['https://hooks.example/a'],
                             'cooldown': 90.7}, '_cli_keys': []})
check('apply normalizes notifications',
      bare.notifications == {'webhooks': ['https://hooks.example/a'],
                             'cooldown': 90}
      and note_a == '')

kept = stub()
kept.notifications = {'webhooks': ['https://keep/'], 'cooldown': 300}
note_b = kept.apply_config({'notifications': {'webhooks': 'oops'},
                            '_cli_keys': []})
check('bad notifications kept with note',
      kept.notifications == {'webhooks': ['https://keep/'], 'cooldown': 300}
      and 'bad notifications value kept' in note_b)
note_c = kept.apply_config({'notifications':
                            {'webhooks': ['https://new/']},
                            '_cli_keys': ['notifications']})
check('cli notifications key skipped',
      kept.notifications['webhooks'] == ['https://keep/'] and note_c == '')

# feature status states come through the guarded apply callback
s_ok = stub_with_status()
s_ok.apply_config({'notifications': {'webhooks': ['https://hooks.example/a'],
                                     'cooldown': 300}, '_cli_keys': []})
check('apply sets notify ok with hooks',
      s_ok.feature_status['notify']['state'] == 'ok')
s_none = stub_with_status()
s_none.apply_config({'notifications': {'webhooks': [], 'cooldown': 300},
                     '_cli_keys': []})
check('apply sets notify unavailable without hooks',
      s_none.feature_status['notify']['state'] == 'unavailable'
      and 'no webhooks' in s_none.feature_status['notify']['detail'])
s_light = stub_with_status(_light_mode=True)
s_light.apply_config({'notifications':
                      {'webhooks': ['https://hooks.example/a'],
                       'cooldown': 300}, '_cli_keys': []})
check('apply sets notify unavailable in light mode',
      s_light.feature_status['notify']['state'] == 'unavailable'
      and 'urllib' in s_light.feature_status['notify']['detail'])


# _check_alert_edges: the fired / still / resolved diff
hooks_on = {'webhooks': ['https://hooks.example/a'], 'cooldown': 300}

e = stub(notifications=dict(hooks_on))
e.cache['cpu'] = {'usage': 91}
e._check_alert_edges()
jobs = drain(e._notify_queue)
check('new alert fires and records state',
      jobs == [('fired', 'CPU HIGH', '91%')]
      and 'CPU HIGH' in e._alert_state
      and e._alert_state['CPU HIGH']['last_sent'] > 0)

# same alert next tick inside the cooldown: silent
e._check_alert_edges()
check('second tick inside cooldown is silent', drain(e._notify_queue) == [])

# past the cooldown: one reminder
e._alert_state['CPU HIGH']['last_sent'] = 0.0
e._check_alert_edges()
check('stale state sends still',
      drain(e._notify_queue) == [('still', 'CPU HIGH', '91%')])

# alert gone from the active set: resolved and the state clears
e.cache['cpu'] = {'usage': 10}
e._check_alert_edges()
check('gone alert resolves and clears state',
      drain(e._notify_queue) == [('resolved', 'CPU HIGH', '')]
      and e._alert_state == {})

# skip paths: no jobs, no state
h = stub()
h.cache['cpu'] = {'usage': 91}
h._check_alert_edges()
check('no webhooks skips edges',
      drain(h._notify_queue) == [] and h._alert_state == {})
f = stub(notifications=dict(hooks_on), _light_mode=True)
f.cache['cpu'] = {'usage': 91}
f._check_alert_edges()
g = stub(notifications=dict(hooks_on), _no_notify=True)
g.cache['cpu'] = {'usage': 91}
g._check_alert_edges()
check('light mode and no_notify skip edges',
      drain(f._notify_queue) == [] and f._alert_state == {}
      and drain(g._notify_queue) == [] and g._alert_state == {})

# one state per alert name: two down containers merge into one job
m = stub(notifications=dict(hooks_on))
m.cache['docker'] = {'available': True, 'stopped': 0,
                     'containers': [{'name': 'web', 'health': 'down',
                                     'health_detail': 'timeout'},
                                    {'name': 'db', 'health': 'down',
                                     'health_detail': 'refused'}]}
m._check_alert_edges()
jobs_m = drain(m._notify_queue)
check('same-name alerts merge to one job',
      jobs_m == [('fired', 'SERVICE DOWN', 'web: timeout')]
      and list(m._alert_state) == ['SERVICE DOWN'])


# _notify_text: the three message shapes
t = stub(hostname='box7')
check('notify text shapes',
      t._notify_text('fired', 'CPU HIGH', '91%')
      == '[Sentinel box7] CPU HIGH fired: 91%'
      and t._notify_text('still', 'CPU HIGH', '91%')
      == '[Sentinel box7] CPU HIGH still firing: 91%'
      and t._notify_text('resolved', 'MEM HIGH', '')
      == '[Sentinel box7] MEM HIGH resolved')


# _enqueue_notify with the started flag set: queue only, no thread
n = stub()
n._enqueue_notify('fired', 'PORT CLOSED', '80: closed')
check('enqueue with started flag puts job without thread',
      n._notify_queue.qsize() == 1 and notify_threads() == 0)


# _notify_worker: the one real-thread check. The monkeypatched
# _webhook_post records the delivery and the worker is stopped after.
# The stub webhook is a literal loopback IP: the url guard resolves it
# without DNS, so no query leaves the process on the worker path.
worker_hooks = {'webhooks': ['http://127.0.0.1:9911/hook'], 'cooldown': 300}
w = stub_with_status(notifications=dict(worker_hooks),
                     _notify_worker_started=False)
calls = []
done = threading.Event()


def fake_post(_urllib, url, payload, timeout=5):
    calls.append((url, payload))
    done.set()
    return (True, 'HTTP 200')


saved_post = sm._webhook_post
try:
    sm._webhook_post = fake_post
    w._enqueue_notify('fired', 'CPU HIGH', '91%')
    w._ensure_notify_worker()
    delivered = done.wait(5.0)
    status_ok = wait_status(w, 'ok') if delivered else False
    threads_now = notify_threads()
finally:
    w._collector_stop.set()
    sm._webhook_post = saved_post

check('worker delivers to webhook',
      bool(calls) and calls[0][0] == 'http://127.0.0.1:9911/hook')
check('worker payload carries all four keys',
      bool(calls)
      and {'title', 'message', 'content', 'text'} <= set(calls[0][1])
      and calls[0][1]['message'] == '[Sentinel notify-test] CPU HIGH fired: 91%'
      and calls[0][1]['title'] == 'Sentinel notify-test')
check('worker thread ran and status is ok',
      threads_now == 1 and status_ok
      and w.feature_status['notify']['state'] == 'ok')

# a delivery failure flips the status to error with the detail
w2 = stub_with_status(notifications=dict(worker_hooks),
                      _notify_worker_started=False)
done2 = threading.Event()


def fake_fail(_urllib, url, payload, timeout=5):
    done2.set()
    return (False, 'boom')


saved_post = sm._webhook_post
try:
    sm._webhook_post = fake_fail
    w2._enqueue_notify('fired', 'DISK FULL', '95%')
    got2 = done2.wait(5.0)
    status_err = wait_status(w2, 'error') if got2 else False
finally:
    w2._collector_stop.set()
    sm._webhook_post = saved_post

check('failed delivery sets error status',
      status_err
      and w2.feature_status['notify']['state'] == 'error'
      and 'boom' in w2.feature_status['notify']['detail'])


failed = [name for name, ok in checks if not ok]
for name, ok in checks:
    print(('PASS' if ok else 'FAIL'), '-', name)
shutil.rmtree(_TMP, ignore_errors=True)
if failed:
    raise SystemExit('FAILURES: %s' % failed)
print('NOTIFY-TEST-OK')
