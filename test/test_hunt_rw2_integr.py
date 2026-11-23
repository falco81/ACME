#!/usr/bin/env python3
"""Hunt w2 - alerts and integrations.

    python3 test/test_hunt_rw2_integr.py

- the SMS gateway failing is an alert whoever sent the SMS: only a code's SMS was counted, so a
  gateway that failed every notice of the certificates by SMS was never said (and a code in
  what the gateway said stays out of the alert);
- the alerts of a directory out of reach and of a node long in maintenance link to a part of
  Settings that is there (people, upgrade) - 'dir' and 'maintenance' opened the first part;
- a mail of something over with nothing new says so ("✔ 1 over, 1 still so"), not
  "✖ 1 problem - Something is wrong";
- the SNMP traps are in English whatever the mails' language, as acmeAlertTable and /metrics;
- the trouble of a trap receiver taken out of Where traps go ends (the alert "SNMP traps do not
  go" stayed for good);
- an isemon line cut at isemon_max_bytes inside a quoted value has the quote closed.
"""
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-w2-integr-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
ME = E.node_name()


def swap(name, value):
    had = E.__dict__[name]
    E.__dict__[name] = value
    return had


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Gateway(http.server.BaseHTTPRequestHandler):
    status = 200
    answer = b'OK'
    got = []

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        Gateway.got.append(self.rfile.read(n))
        self.send_response(Gateway.status)
        self.send_header('Content-Length', str(len(Gateway.answer)))
        self.end_headers()
        self.wfile.write(Gateway.answer)

    def log_message(self, *a):
        pass


class SmsHealth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(('127.0.0.1', 0), Gateway)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = 'http://127.0.0.1:%d/send' % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        E.SMS_HEALTH.update(ok_at=0.0, fail_at=0.0, fails=0, said='')
        E.CONFIG.update(sms_mode='http', sms_url=self.url, sms_method='POST',
                        sms_body='to={to}&text={text}', sms_ok_status='')
        Gateway.status, Gateway.answer = 200, b'OK'

    def tearDown(self):
        E.CONFIG.update(sms_mode='off', sms_url='')

    def test_a_notice_that_fails_is_counted_and_alerted(self):
        Gateway.status, Gateway.answer = 500, b'gateway broken'
        from acmelib.certs import notices
        E.CONFIG['certs_notify_sms'] = '+420600000001'
        try:
            for i in range(3):
                notices.send_plain(STORE, 'w2:x%d' % i, 'subject', 'words', force=True)
        finally:
            E.CONFIG['certs_notify_sms'] = ''
        self.assertEqual(E.SMS_HEALTH['fails'], 3)
        self.assertIn('500', E.SMS_HEALTH['said'])
        STORE.set_meta('host:health:' + ME, json.dumps({'at': time.time(),
                                                        'sms': dict(E.SMS_HEALTH)}))
        try:
            self.assertIn('sms:' + ME, E.alert_problems(STORE))
            # one that goes again: no longer failing
            Gateway.status, Gateway.answer = 200, b'OK'
            E.sms_send('+420600000001', 'hello')
            self.assertEqual(E.SMS_HEALTH['fails'], 0)
        finally:
            STORE.db.run("DELETE FROM meta WHERE k = ?", ('host:health:' + ME,))

    def test_a_code_stays_out_of_what_the_alert_says(self):
        Gateway.status, Gateway.answer = 400, b'refused: 482913 is not allowed'
        with self.assertRaises(E.SmsError) as ctx:
            E.code_send(STORE, 'sms', '+420600000001', '482913', purpose='admin', name='x')
        self.assertNotIn('482913', str(ctx.exception))
        self.assertEqual(E.SMS_HEALTH['fails'], 1, 'counted once, not twice')
        self.assertNotIn('482913', E.SMS_HEALTH['said'])

    def test_off_is_not_a_failure(self):
        E.CONFIG['sms_mode'] = 'off'
        with self.assertRaises(E.SmsError):
            E.sms_send('+420600000001', 'x')
        self.assertEqual(E.SMS_HEALTH['fails'], 0)


class TeamWebhook(unittest.TestCase):
    def test_what_it_answered_is_said(self):
        srv = http.server.HTTPServer(('127.0.0.1', 0), Gateway)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            from acmelib.certs import teamgov
            url = 'http://127.0.0.1:%d/hook/SECRETPATH' % srv.server_address[1]
            Gateway.status, Gateway.answer = 503, b'busy'
            got = teamgov._deliver(STORE, 'Web', 'team', 'subj', 'text', [], {'slack': url},
                                   wait=True)
            self.assertEqual(got, {'slack': 'answered 503'})
            Gateway.status, Gateway.answer = 200, b'ok'
            got = teamgov._deliver(STORE, 'Web', 'team', 'subj', 'text', [], {'slack': url},
                                   wait=True)
            self.assertEqual(got, {'slack': 'sent'})
            self.assertEqual(json.loads(Gateway.got[-1])['text'], 'subj\ntext')
        finally:
            srv.shutdown()


def pane_ids():
    ids = set()
    import re
    for name in ('index.php', 'certs-ui.php'):
        with open(os.path.join(ROOT, 'web', 'admin', name), encoding='utf-8') as f:
            ids |= set(re.findall(r'id="pane-([a-z0-9_]+)"', f.read()))
    return ids


class Panes(unittest.TestCase):
    def tearDown(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'host:health:%' OR k LIKE 'maint%'")

    def test_directory_and_maintenance_link_to_a_pane_there(self):
        STORE.set_meta('host:health:' + ME, json.dumps({'at': time.time(), 'dirs_down': ['ad1']}))
        had = swap('maintenance_row', lambda store, n: {'on': True, 'why': 'by hand',
                                                         'at': time.time() - 7 * 3600})
        try:
            got = E.alert_problems(STORE)
        finally:
            E.__dict__['maintenance_row'] = had
        self.assertEqual(got['dir:%s:ad1' % ME]['pane'], 'people')
        self.assertEqual(got['maint:' + ME]['pane'], 'upgrade')
        ids = pane_ids()
        for k, p in got.items():
            if p.get('pane'):
                self.assertIn(p['pane'], ids, k)


class Sent(object):
    def __init__(self):
        self.got = []

    def __call__(self, store, msg, to, **kw):
        self.got.append(msg)
        return [{'ok': True, 'said': '250 ok'}]


class OverMail(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:%'")
        E.CONFIG.update(alerts=1, alerts_to='ops@example.test', alerts_delay_min=0,
                        mail_from='acme@example.test', mail_mode='smtp', alerts_lang='en')

    def tearDown(self):
        E.CONFIG.update(alerts=0, alerts_to='', mail_mode='off', alerts_lang='')

    def test_one_over_one_still(self):
        now = {'x:one': {'level': 'bad', 'title': 'One', 'said': 'one', 'pane': 'db'},
               'x:two': {'level': 'warn', 'title': 'Two', 'said': 'two', 'pane': 'ha'}}
        sent = Sent()
        had_p = swap('alert_problems', lambda store, lang='en': {k: dict(v) for k, v in now.items()})
        had_d = swap('mail_deliver', sent)
        try:
            E.alerts_evaluate(STORE)
            self.assertTrue(sent.got[-1]['Subject'].startswith('[acme] ✖ 2 problems'))
            del now['x:two']
            E.alerts_evaluate(STORE)
            self.assertEqual(len(sent.got), 2)
            subj = str(sent.got[-1]['Subject'])
            self.assertTrue(subj.startswith('[acme] ✔ 1 over, 1 still so'), subj)
            body = sent.got[-1].get_body(('plain',)).get_content()
            self.assertIn('Some of it is over', body)
            self.assertIn('One', body)                  # what is still so is named too
            now['x:three'] = {'level': 'warn', 'title': 'Three', 'said': 'three', 'pane': 'ha'}
            E.alerts_evaluate(STORE)
            self.assertIn('✖', str(sent.got[-1]['Subject']))   # something new: a problem mail
            now.clear()
            E.alerts_evaluate(STORE)
            self.assertTrue(str(sent.got[-1]['Subject']).startswith('[acme] ✔ Back to normal'))
        finally:
            E.__dict__['alert_problems'], E.__dict__['mail_deliver'] = had_p, had_d


class TrapsInEnglish(unittest.TestCase):
    def test_traps_get_the_english_words(self):
        seen = []
        E.CONFIG.update(alerts=1, alerts_lang='cs', snmp=1, snmp_traps=1, alerts_to='',
                        report=0)
        had = [swap('alert_problems', lambda store, lang='en': {
            'x': {'level': 'bad', 'title': 'Česky' if lang == 'cs' else 'English', 'said': '',
                  'pane': 'db'}}),
            swap('snmp_traps_tick', lambda daemon, cur: seen.append(cur)),
            swap('health_publish', lambda daemon: None),
            swap('logs_start', lambda daemon: None)]

        class D(object):
            store = STORE
        try:
            E.ALERT_WORK.update(at=0.0, busy=False)
            E.alerts_tick(D())
            until = time.time() + 10
            while not seen and time.time() < until:
                time.sleep(0.05)
        finally:
            for name, h in zip(('alert_problems', 'snmp_traps_tick', 'health_publish',
                                'logs_start'), had):
                E.__dict__[name] = h
            E.CONFIG.update(alerts=0, alerts_lang='', snmp=0, snmp_traps=0)
        self.assertEqual(seen and seen[0]['x']['title'], 'English')


class TrapErrorOfAReceiverGone(unittest.TestCase):
    def tearDown(self):
        E.SNMP_STATE['trap_error'] = ''
        E.CONFIG['snmp_trap_to'] = ''

    def test_tidy(self):
        E.CONFIG['snmp_trap_to'] = 'good.example.test, [2001:db8::1]:1162'
        E.SNMP_STATE['trap_error'] = 'bad.example.test:162: [Errno -2] Name or service not known'
        E.snmp_trap_error_tidy()
        self.assertEqual(E.SNMP_STATE['trap_error'], '')
        E.SNMP_STATE['trap_error'] = '[2001:db8::1]:1162: [Errno 101] Network is unreachable'
        E.snmp_trap_error_tidy()
        self.assertTrue(E.SNMP_STATE['trap_error'])              # still one of them: kept
        E.SNMP_STATE['trap_error'] = 'good.example.test:162: timed out'
        E.snmp_trap_error_tidy()
        self.assertTrue(E.SNMP_STATE['trap_error'])


class IsemonCut(unittest.TestCase):
    def test_quote_closed(self):
        line = E.event_kv('certificates', 'x' * 50 + ' a "quoted" b' + 'y' * 500, 'info', 'acme')
        for most in range(40, 120):
            got = E._kv_cut(line.encode()[:most].decode())
            self.assertTrue(got.endswith('...TRUNCATED') or got.endswith('...TRUNCATED"'))
            # an even number of quotes not escaped: every value closed
            n, esc = 0, False
            for ch in got:
                if esc:
                    esc = False
                elif ch == '\\':
                    esc = True
                elif ch == '"':
                    n += 1
            self.assertEqual(n % 2, 0, got)
        self.assertEqual(E._kv_cut('level=info kind=x'), 'level=info kind=x ...TRUNCATED')

    def test_put_cuts_that_way(self):
        E.CONFIG.update(ship_files=1, isemon_max_bytes=120)
        sh = E.Shipper.__new__(E.Shipper)
        import queue
        sh.q = queue.Queue()
        sh.dropped = 0
        try:
            sh.put('acme-certs', 'daemon', E.event_kv('certificates', 'w ' * 200, 'info', 'acme'))
            _pri, line, _f = sh.q.get_nowait()
        finally:
            E.CONFIG.update(ship_files=0, isemon_max_bytes=E.DEFAULTS.get('isemon_max_bytes'))
        self.assertTrue(line.endswith(' ...TRUNCATED"'), line)


class CommandLine(unittest.TestCase):
    """acme --alerts [check|test|forget] and --metrics-preview, run as typed, and the console's
    items for them."""
    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.sp = subprocess
        cls.tmp = tempfile.mkdtemp(prefix='acme-hunt-w2-cli-')
        with open(os.path.join(cls.tmp, 'config.json'), 'w') as f:
            f.write('{}')
        cls.env = {k: v for k, v in os.environ.items() if not k.startswith('ACME_')}
        cls.env.update(ACME_STAY_ROOT='1', ACME_CONFIG=os.path.join(cls.tmp, 'config.json'),
                       ACME_STATE=cls.tmp, ACME_RUN=cls.tmp, ACME_LOGDIR=cls.tmp, NO_COLOR='1')
        cls.run_acme('--selfsigned', 'web1', '--names', 'web1.example.com')
        got = cls.sp.run([sys.executable, '-c', 'import sys; sys.path.insert(0, %r)\n'
                          'import acme\nfrom acmelib import engine as E\n'
                          'E.Storage(E.open_db()).db.run("UPDATE certs SET state = \'failed\', '
                          'last_error = \'the CA said no\'")' % ROOT],
                         env=cls.env, capture_output=True, text=True, timeout=120)
        assert got.returncode == 0, got.stderr

    @classmethod
    def run_acme(cls, *args):
        return cls.sp.run([sys.executable, os.path.join(ROOT, 'acme.py')] + list(args),
                          env=cls.env, capture_output=True, text=True, timeout=240)

    def test_show(self):
        got = self.run_acme('--alerts')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('renewing the certificate web1 failed', got.stdout)
        self.assertIn('this node sends the alerts', got.stdout)
        js = json.loads(self.run_acme('--alerts', '--json').stdout)
        self.assertTrue([p for p in js['problems'] if p['key'].startswith('mod:cert-failed:')])

    def test_test_without_an_address_fails(self):
        got = self.run_acme('--alerts', 'test')
        self.assertEqual(got.returncode, 1)
        self.assertIn('no address', got.stderr)

    def test_check_and_forget(self):
        self.assertEqual(self.run_acme('--alerts', 'check').returncode, 0)
        self.assertEqual(self.run_acme('--alerts', 'forget').returncode, 1)     # --yes wanted
        self.assertEqual(self.run_acme('--alerts', 'forget', '--yes').returncode, 0)

    def test_metrics_preview(self):
        got = self.run_acme('--metrics-preview')
        self.assertEqual(got.returncode, 0, got.stderr)
        self.assertIn('# TYPE acme_info gauge', got.stdout)
        self.assertIn('acme_alert{key="mod:cert-failed:', got.stdout)

    def test_documented_and_in_the_console(self):
        with open(os.path.join(ROOT, 'docs', 'monitoring.md'), encoding='utf-8') as f:
            doc = f.read()
        for words in ('acme --alerts', 'acme --alerts check', 'acme --alerts test',
                      'acme --metrics-preview'):
            self.assertIn(words, doc)
        with open(os.path.join(ROOT, 'acmelib', 'engine', '445_the_console_acme_run.py'),
                  encoding='utf-8') as f:
            con = f.read()
        for words in ("self.act('--alerts')", "self.act('--alerts', 'check')",
                      "self.act('--alerts', 'test')", "self.act('--metrics-preview')"):
            self.assertIn(words, con)


if __name__ == '__main__':
    unittest.main()
