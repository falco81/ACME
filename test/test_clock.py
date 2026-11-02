#!/usr/bin/env python3
"""The clocks and the health of the nodes - gray failures (docs/clock-guard.md).

    python3 test/test_clock.py            (or python3 -m unittest test.test_clock)

In one process, SQLite, as otp 1.0.222's tests/clock/t_clock.py: a fake SNTP server on
localhost answers with this machine's time plus an offset of its own (RFC 4330's packet);
the other node's clock, its state row and the directory are played by the test -
clock_step(store, now, ref=, skew=, dir_ok=, peer=). SNTP itself (right, ahead, not
synchronised, silent, the median of three); the reference servers; every row of the
decision; "as until now" running nothing at all (no SNTP packet, no database question, no
directory, no thread, no row, no alert; the codes, the pauses, the heartbeats and the lease
as before); watch; the second step's codes by the corrected time (the real route); the
pauses; the heartbeats and the lead's lease by the measured difference; guard stepping aside
through maintenance_now and back; the directory (a mock LDAP server); switched off while
aside; the alerts; the API of the card (try answered by the node's loop); the card's pieces
on the pages, the relay and the Czech texts.
"""
import json
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-clock-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)

import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import renewer  # noqa: E402

ENG = sys.modules['acmelib.engine'].__dict__
STORE = E.Storage(E.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)
DAEMON = E.Daemon(STORE, serve=False)
KEYS = ('clock_mode', 'clock_warn_s', 'clock_aside_s', 'clock_ref', 'clock_codes', 'clock_beat',
        'clock_locks', 'health_dir')
NTP_EPOCH = 2208988800


class FakeNtp(object):
    """An SNTP server on 127.0.0.1: this machine's time plus `offset`; `stratum` 0 is an
    unsynchronised one, `silent` answers nothing."""
    def __init__(self, offset=0.0, stratum=2, silent=False):
        self.offset, self.stratum, self.silent = offset, stratum, silent
        self.asked = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.addr = '127.0.0.1:%d' % self.port
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)
        self.t.start()

    @staticmethod
    def stamp(t):
        return struct.pack('!II', int(t) + NTP_EPOCH, int((t - int(t)) * (1 << 32)))

    def run(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                return
            self.asked += 1
            if self.silent or len(data) < 48:
                continue
            got = time.time() + self.offset
            out = bytearray(48)
            out[0] = (0 << 6) | (4 << 3) | 4             # LI 0, version 4, mode 4 (server)
            out[1] = self.stratum
            out[24:32] = data[40:48]                     # their transmit time as the originate
            out[32:40] = self.stamp(got)
            out[40:48] = self.stamp(time.time() + self.offset)
            self.sock.sendto(bytes(out), peer)

    def close(self):
        self.stop.set()
        self.sock.close()


def beat(name, at=None):
    STORE.set_meta('node:' + name, json.dumps({'at': time.time() if at is None else at,
                                              'address': '127.0.0.1', 'version': E.__version__}))


def reset(**conf):
    """A replicated pair acme1 (this one) + acme2, everything at its default."""
    for k in KEYS:
        E.CONFIG[k] = E.DEFAULTS[k]
    E.CONFIG.update(ha_mode='replicated', ha_peer='192.0.2.250', ha_slot=1, node_name='acme1',
                    split_mode='off')
    E.CONFIG.update(conf)
    E.CLOCK.update(ref=None, ref_src='', ref_err='', ref_at=0.0, refs=[], ref_mono=0.0,
                   ref_wall=0.0, skew=None, skew_err='', skew_at=0.0, skew_of='', dir_ok=None,
                   dir_at=0.0, dirs=[], role='serve', why='', written=0.0)
    E.CLOCK.pop('peer_ref_seen', None)
    E.CLOCK.pop('measure_now', None)
    E.CLOCK.pop('peer_ref_at', None)
    E.MAINT_CACHE['at'] = 0
    STORE.db.run("DELETE FROM meta WHERE k LIKE 'clock:%' OR k LIKE 'node:%' OR "
                 "k = 'certs:leader' OR k LIKE 'ask:%' OR k LIKE 'maint:%' OR k = 'ntp:conf'")
    beat('acme1')
    beat('acme2')


def well(**kw):
    """The other node's row, well: fresh, serving, its clock right, reaching the directory."""
    row = {'fresh': True, 'role': 'serve', 'maintenance': False, 'ref': 0.01, 'dir_ok': True}
    row.update(kw)
    return row


class Spy(object):
    """SNTP, the other side's clock and the directory - asked, they count it."""
    def __init__(self):
        self.sntp = self.skew = self.dirs = 0
        self._was = {k: ENG[k] for k in ('sntp_offset', 'clock_peer_skew', 'clock_dir_check')}

    def __enter__(self):
        def sntp(server, timeout=1.5):
            self.sntp += 1
            return 0.0, 0.001

        def skew(store):
            self.skew += 1
            return 'acme2', 0.0

        def dirs(store):
            self.dirs += 1
            return True, []
        ENG.update(sntp_offset=sntp, clock_peer_skew=skew, clock_dir_check=dirs)
        return self

    def __exit__(self, *a):
        ENG.update(self._was)


class FakeDaemon(object):
    def __init__(self):
        self.store = STORE
        self.stop_flag = threading.Event()


# ---------------------------------------------------------------------------
class Sntp(unittest.TestCase):
    def test_right_ahead_unsynchronised_silent(self):
        right, ahead, kod, silent = FakeNtp(0.0), FakeNtp(300.0), FakeNtp(0.0, 0), FakeNtp(silent=True)
        try:
            off, delay = E.sntp_offset(right.addr)
            self.assertLess(abs(off), 0.05)
            self.assertLess(delay, 0.5)
            off, _d = E.sntp_offset(ahead.addr)
            self.assertAlmostEqual(off, 300.0, delta=0.05)      # this clock is behind it
            with self.assertRaises(ValueError):
                E.sntp_offset(kod.addr)
            t = time.time()
            with self.assertRaises(OSError):
                E.sntp_offset(silent.addr, timeout=0.5)
            self.assertLess(time.time() - t, 2)
        finally:
            for s in (right, ahead, kod, silent):
                s.close()

    def test_an_answer_to_another_question_is_not_taken(self):
        """The originate time must be ours: an old or forged answer is ignored."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(('127.0.0.1', 0))

        def liar():
            data, peer = srv.recvfrom(512)
            out = bytearray(48)
            out[0], out[1] = 0x24, 2
            out[24:32] = b'\x00' * 8                       # not what was asked
            srv.sendto(bytes(out), peer)
        threading.Thread(target=liar, daemon=True).start()
        try:
            with self.assertRaises(OSError):
                E.sntp_offset('127.0.0.1:%d' % srv.getsockname()[1], timeout=0.6)
        finally:
            srv.close()

    def test_the_median_of_three(self):
        a, b, c = FakeNtp(0.0), FakeNtp(0.2), FakeNtp(500.0)
        try:
            got, med = E.clock_ref_check([a.addr, b.addr, c.addr])
            self.assertAlmostEqual(med, 0.2, delta=0.05)
            self.assertEqual(len(got), 3)
            got, med = E.clock_ref_check([])
            self.assertIsNone(med)
        finally:
            for s in (a, b, c):
                s.close()

    def test_lost_once_asked_again(self):
        s = FakeNtp(silent=True)
        try:
            got, med = E.clock_ref_check([s.addr])
            self.assertIsNone(med)
            self.assertIsNone(got[0][1])
            self.assertEqual(s.asked, 2)                   # asked a second time
        finally:
            s.close()

    def test_the_reference_servers(self):
        reset()
        self.assertEqual(E.clock_ref_servers(store=STORE), [])
        STORE.set_meta('ntp:conf', json.dumps({'servers': [{'host': 'tik.cesnet.cz'},
                                                           {'host': 'tak.cesnet.cz'}]}))
        self.assertEqual(E.clock_ref_servers(store=STORE), ['tik.cesnet.cz', 'tak.cesnet.cz'])
        E.CONFIG['clock_ref'] = 'ntp.local, 10.0.0.1:123'
        self.assertEqual(E.clock_ref_servers(store=STORE), ['ntp.local', '10.0.0.1:123'])
        self.assertEqual(E.clock_view(STORE)['common'], ['tik.cesnet.cz', 'tak.cesnet.cz'])
        reset()


class Decide(unittest.TestCase):
    """Every row of the table (docs/clock-guard.md 5)."""
    def d(self, ref, peer, codes=False, dir_ok=None, health=False, aside_now=False, newer=True,
          mode='guard'):
        return E.clock_decide(mode, ref, 20, codes, dir_ok, health, peer, aside_now=aside_now,
                              back_s=18, peer_newer=newer)[0]

    def test_the_table(self):
        self.assertEqual(self.d(5, well()), 'serve')                      # within aside_s
        self.assertEqual(self.d(300, well(), codes=True), 'serve')        # codes corrected
        self.assertEqual(self.d(300, well()), 'aside')                    # the other well
        self.assertEqual(self.d(-300, well()), 'aside')                   # ahead too
        self.assertEqual(self.d(300, well(ref=300)), 'serve')             # the other off too
        self.assertEqual(self.d(300, well(fresh=False)), 'serve')         # not heard from
        self.assertEqual(self.d(300, None), 'serve')
        self.assertEqual(self.d(300, well(role='aside')), 'serve')        # itself aside
        self.assertEqual(self.d(300, well(maintenance=True)), 'serve')    # in maintenance
        self.assertEqual(self.d(300, well(ref=None)), 'serve')            # no reference there
        self.assertEqual(self.d(None, well()), 'serve')                   # judged by nothing
        self.assertEqual(self.d(19, well(), aside_now=True), 'aside')     # hysteresis...
        self.assertEqual(self.d(17, well(), aside_now=True), 'serve')     # ...back below 18
        self.assertEqual(self.d(300, well(), newer=False), 'serve')       # its word older
        self.assertEqual(self.d(300, well(), newer=False, aside_now=True), 'aside')
        self.assertEqual(self.d(None, well(), dir_ok=False, health=True), 'aside')
        self.assertEqual(self.d(None, well(dir_ok=False), dir_ok=False, health=True), 'serve')
        self.assertEqual(self.d(None, well(dir_ok=None), dir_ok=False, health=True), 'serve')
        self.assertEqual(self.d(None, well(), dir_ok=False, health=False), 'serve')
        for mode in ('off', 'watch'):
            self.assertEqual(self.d(300, well(), mode=mode), 'serve')

    def test_never_both(self):
        """Each node stepping aside only for the other being better: both cannot."""
        for a in (None, 0.0, 5.0, 300.0, -300.0):
            for b in (None, 0.0, 5.0, 300.0, -300.0):
                ra = self.d(a, well(ref=b))
                rb = self.d(b, well(ref=a))
                self.assertFalse(ra == rb == 'aside', (a, b))


class AsUntilNow(unittest.TestCase):
    def setUp(self):
        reset()

    def test_default_is_as_until_now(self):
        for k, v in (('clock_mode', 'off'), ('clock_warn_s', 2), ('clock_aside_s', 20),
                     ('clock_ref', ''), ('clock_codes', 0), ('clock_beat', 0),
                     ('clock_locks', 0), ('health_dir', 0)):
            self.assertEqual(E.DEFAULTS[k], v)
        self.assertFalse(E.clock_engaged())

    def test_nothing_runs(self):
        """No SNTP packet, no question to the other database, no directory, no thread, no
        row, no alert - whatever the switches say."""
        E.CONFIG.update(clock_codes=1, clock_beat=1, clock_locks=1, health_dir=1)
        with Spy() as spy:
            for i in range(5):
                E.clock_step(STORE, now=time.time() + i * 100)
            d = FakeDaemon()
            E.CLOCK['thread'] = None
            E.clock_tick(d)
            time.sleep(0.3)
            self.assertIsNone(E.CLOCK['thread'])          # never started
            # The daemon's whole loop step for the clocks too.
            self.assertFalse(E.clock_watching())
        self.assertEqual((spy.sntp, spy.skew, spy.dirs), (0, 0, 0))
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM meta WHERE k LIKE 'clock:%'"), 0)
        self.assertFalse(E.maintenance_now(STORE).get('clock'))
        self.assertFalse([k for k in E.alert_problems(STORE) if k.startswith('clock')])

    def test_the_codes_the_pauses_the_beats_as_before(self):
        E.CONFIG.update(clock_codes=1, clock_beat=1, clock_locks=1)
        E.CLOCK.update(ref=300.0, ref_mono=time.monotonic(), ref_wall=time.time() - time.monotonic(),
                       skew=-600.0, skew_at=time.time(), skew_of='acme2')
        self.assertAlmostEqual(E.clock_now('codes'), time.time(), delta=0.05)
        self.assertAlmostEqual(E.clock_now('locks'), time.time(), delta=0.05)
        beat('acme2', time.time() - 600)
        n = [x for x in E.ha_nodes(STORE) if x['name'] == 'acme2'][0]
        self.assertFalse(n['alive'])                       # as before: looks dead
        self.assertEqual(E.clock_their_time(STORE, 'acme2', 1000.0), 1000.0)


class Watch(unittest.TestCase):
    def test_measured_written_warned(self):
        reset(clock_mode='watch')
        srv = FakeNtp(300.0)                                # this clock 300 s behind
        try:
            E.CONFIG['clock_ref'] = srv.addr
            with_skew = ENG['clock_peer_skew']
            ENG['clock_peer_skew'] = lambda store: ('acme2', 0.004)
            try:
                E.clock_step(STORE)
            finally:
                ENG['clock_peer_skew'] = with_skew
        finally:
            srv.close()
        self.assertAlmostEqual(E.CLOCK['ref'], 300.0, delta=0.1)
        row = json.loads(STORE.get_meta('clock:state:acme1'))
        self.assertAlmostEqual(row['ref'], 300.0, delta=0.1)
        self.assertEqual((row['role'], row['skew_of'], row['codes_fixed']), ('serve', 'acme2', False))
        al = E.alert_problems(STORE)
        self.assertEqual(al['clock:skew:acme1']['level'], 'bad')
        self.assertIn('behind', al['clock:skew:acme1']['title'])
        self.assertIn('pozadu', E.alert_problems(STORE, 'cs')['clock:skew:acme1']['title'])
        self.assertEqual(al['clock:skew:acme1']['pane'], 'time')
        self.assertAlmostEqual(E.clock_now('codes'), time.time(), delta=0.05)   # not corrected
        self.assertFalse(E.maintenance_now(STORE).get('on'))
        reset()

    def test_no_reference_an_alert(self):
        reset(clock_mode='watch')
        E.clock_step(STORE, skew=('acme2', 0.0), peer='none')
        self.assertIsNone(E.CLOCK['ref'])
        self.assertIn('no time server given', E.CLOCK['ref_err'])
        self.assertIn('clock:ref:acme1', E.alert_problems(STORE))
        reset()

    def test_one_lost_answer_keeps_the_last(self):
        reset(clock_mode='watch')
        srv = FakeNtp(100.0)
        E.CONFIG['clock_ref'] = srv.addr
        try:
            E.clock_step(STORE, skew=('acme2', 0.0), peer='none')
            self.assertAlmostEqual(E.CLOCK['ref'], 100.0, delta=0.1)
            srv.silent = True
            E.CLOCK['measure_now'] = True
            E.clock_step(STORE, skew=('acme2', 0.0), peer='none')
            self.assertAlmostEqual(E.CLOCK['ref'], 100.0, delta=0.1)
            self.assertIn('the last measurement is used', E.CLOCK['ref_err'])
        finally:
            srv.close()
        reset()

    def test_the_other_nodes_skew_alert(self):
        reset(clock_mode='watch')
        E.clock_step(STORE, ref=0.01, skew=('acme2', 42.0), peer='none')
        self.assertIn('clock:peer:acme1', E.alert_problems(STORE))
        reset()


class Codes(unittest.TestCase):
    """The second step's code (admin_2fa, the app) by the corrected time - the real route."""
    @classmethod
    def setUpClass(cls):
        try:
            STORE.add_account('boss', 'fulladmin', 'A-Long-Password-1!')
        except Exception:
            pass

    def setUp(self):
        reset(admin_2fa=1, admin_2fa_app=1)
        self.secret = E.b32_new(20)
        STORE.set_meta(E.mfa_key('boss'), json.dumps({'kind': 'app', 'step': 0,
                                                      'secret': E.seal_secret(self.secret, E.mfa_key('boss'))}))
        STORE.db.run("DELETE FROM used_once")
        DAEMON.login_fails.clear()
        self._done = ENG['_mfa_done']
        ENG['_mfa_done'] = lambda h, s, how, kind='admin': 'token'

    def tearDown(self):
        ENG['_mfa_done'] = self._done
        reset()

    def check(self, code):
        class H(E.CliApiHandler):
            def session(self, kind='admin'):
                return {'id': 'sid', 'name': 'boss', 'data': {'mfa': 'check'}, 'expires': time.time() + 600}
        h = H(DAEMON, 'boss', {'action': 'check', 'code': code}, {}, '/api/auth/mfa')
        try:
            return E.ROUTES[('POST', '/api/auth/mfa')](h).get('done')
        except E.ApiError as e:
            return e.status

    def behind(self, codes):
        """This node 300 s behind the reference."""
        E.CONFIG.update(clock_mode='watch', clock_codes=codes)
        E.clock_step(STORE, ref=300.0, skew=('acme2', 0.0), peer='none')

    def test_refused_without_let_in_with(self):
        right = E.totp(self.secret, time.time() + 300)    # the code of the right time
        mine = E.totp(self.secret, time.time())           # the one of this wrong clock
        self.behind(0)
        self.assertEqual(self.check(right), 400)
        self.behind(1)
        self.assertTrue(E.clock_state_here()['codes_fixed'])
        self.assertTrue(self.check(right) is True)
        self.assertEqual(self.check(mine), 400)           # the machine's own wrong time
        self.assertAlmostEqual(E.clock_now('codes'), time.time() + 300, delta=0.1)
        self.assertAlmostEqual(E.clock_now('locks'), time.time(), delta=0.1)   # its own switch

    def test_no_correction_within_the_warning_or_old(self):
        E.CONFIG.update(clock_mode='watch', clock_codes=1)
        E.clock_step(STORE, ref=1.5, skew=('acme2', 0.0), peer='none')
        self.assertEqual(E.clock_correction(), 0.0)
        E.clock_step(STORE, ref=300.0, skew=('acme2', 0.0), peer='none')
        self.assertEqual(E.clock_correction(), 300.0)
        E.CLOCK['ref_mono'] = time.monotonic() - 1000      # measured long ago
        E.CLOCK['ref_wall'] = time.time() - time.monotonic()
        self.assertEqual(E.clock_correction(), 0.0)
        E.clock_step(STORE, ref=300.0, skew=('acme2', 0.0), peer='none')
        E.CLOCK['ref_wall'] -= 120                         # the machine's clock stepped since
        self.assertEqual(E.clock_correction(), 0.0)


class Locks(unittest.TestCase):
    def test_the_pauses_on_the_corrected_time(self):
        reset(clock_mode='watch', clock_locks=1)
        E.clock_step(STORE, ref=300.0, skew=('acme2', 0.0), peer='none')
        DAEMON.login_fails.clear()
        h = E.CliApiHandler(DAEMON, 'x', {}, {}, '/api/auth/login')
        h.throttle('admin', 5, 5, name='someone')
        times = DAEMON.login_fails[('admin', '127.0.0.1')]
        self.assertAlmostEqual(times[-1], time.time() + 300, delta=1)
        rows = E.lockouts_view(DAEMON)
        self.assertTrue(rows and rows[0]['fails'] == 1)    # read with the same time
        DAEMON.login_fails.clear()
        reset()


class Beats(unittest.TestCase):
    def test_a_node_behind_ahead(self):
        reset(clock_mode='watch', clock_beat=1)
        # acme2's clock 10 min behind this one: its fresh beat reads 600 s old.
        beat('acme2', time.time() - 600)
        self.assertFalse(E.CONFIG.get('clock_beat') and
                         [n for n in E.ha_nodes(STORE) if n['name'] == 'acme2' and n['alive']])
        E.clock_step(STORE, ref=0.0, skew=('acme2', -600.0), peer='none')
        self.assertTrue([n for n in E.ha_nodes(STORE) if n['name'] == 'acme2' and n['alive']])
        # Ahead by 10 min: a beat 100 s old reads from the future without it, dead with it.
        beat('acme2', time.time() + 500)
        E.CONFIG['clock_beat'] = 0
        self.assertTrue([n for n in E.ha_nodes(STORE) if n['name'] == 'acme2' and n['alive']])
        E.CONFIG['clock_beat'] = 1
        E.clock_step(STORE, ref=0.0, skew=('acme2', 600.0), peer='none')
        self.assertFalse([n for n in E.ha_nodes(STORE) if n['name'] == 'acme2' and n['alive']])
        reset()

    def test_one_shared_database_server(self):
        reset(clock_mode='watch', clock_beat=1, ha_mode='shared')
        E.clock_step(STORE, ref=0.0, skew=(E.CLOCK_DB_SERVER, 5.0), peer='none')
        STORE.set_meta('clock:state:acme2', json.dumps({'at': time.time(), 'skew': 605.0,
                                                         'skew_of': E.CLOCK_DB_SERVER}))
        # acme2 against the server +605, this one +5: acme2's clock is 600 s behind this one.
        self.assertAlmostEqual(E.clock_skew_of(STORE, 'acme2'), -600.0)
        reset()

    def test_the_lead_lease(self):
        """The other node's lease of the renewals, judged in this node's time."""
        reset(clock_mode='watch', clock_beat=1)
        STORE.set_meta('certs:leader', json.dumps({'node': 'acme2', 'until': time.time() - 30,
                                                   'vip': False}))
        self.assertIsNone(renewer.leader(STORE))           # ran out, as written
        E.clock_step(STORE, ref=0.0, skew=('acme2', -600.0), peer='none')
        self.assertEqual(renewer.leader(STORE)['node'], 'acme2')   # 600 s behind: live
        reset()


class Guard(unittest.TestCase):
    def test_aside_and_back(self):
        reset(clock_mode='guard')
        E.clock_step(STORE, ref=300.0, skew=('acme2', -300.0), peer=well())
        self.assertTrue(E.clock_aside())
        m = E.maintenance_now(STORE)
        self.assertTrue(m['on'] and m.get('clock'))
        self.assertIn('stepped aside', m['why'])
        self.assertTrue(E.split_no_lead() is False)        # the split's own switch untouched
        self.assertIn('clock:aside:acme1', E.alert_problems(STORE))
        ev = STORE.db.rows("SELECT words FROM events WHERE kind = 'time' ORDER BY id DESC LIMIT 1")
        self.assertIn('steps aside', ev[0]['words'])
        # The other gone quiet: serves at once.
        E.clock_step(STORE, ref=300.0, peer=well(fresh=False))
        self.assertFalse(E.clock_aside())
        self.assertFalse(E.maintenance_now(STORE).get('on'))
        # Aside again, then the clock mended: serves.
        E.clock_step(STORE, ref=300.0, peer=well())
        self.assertTrue(E.clock_aside())
        E.clock_step(STORE, ref=0.1, peer=well())
        self.assertFalse(E.clock_aside())
        reset()

    def test_with_the_codes_never_aside(self):
        reset(clock_mode='guard', clock_codes=1)
        E.clock_step(STORE, ref=300.0, peer=well())
        self.assertFalse(E.clock_aside())
        reset()

    def test_the_peer_row_fresh_by_the_measured_skew(self):
        """A row "300 s old" from a node 300 s behind is fresh."""
        reset(clock_mode='guard')
        E.clock_step(STORE, ref=0.0, skew=('acme2', -300.0), peer='none')
        STORE.set_meta('clock:state:acme2', json.dumps({'at': time.time() - 300, 'role': 'serve',
                                                         'ref': 0.0}))
        p = E.clock_peer_row(STORE)
        self.assertTrue(p['fresh'])
        STORE.set_meta('clock:state:acme2', json.dumps({'at': time.time() - 340, 'role': 'serve'}))
        self.assertFalse(E.clock_peer_row(STORE)['fresh'])
        # Its maintenance as written, not only by its heartbeat.
        STORE.set_meta('maint:acme2', json.dumps({'on': True}))
        self.assertTrue(E.clock_peer_row(STORE)['maintenance'])
        reset()

    def test_aside_through_the_real_rows(self):
        """The other node's row as it comes over, measured after this node's own."""
        reset(clock_mode='guard')
        E.clock_step(STORE, ref=300.0, skew=('acme2', 0.0), peer='none')
        self.assertFalse(E.clock_aside())
        STORE.set_meta('clock:state:acme2', json.dumps({'at': time.time(), 'role': 'serve',
                                                         'ref': 0.01, 'ref_at': time.time()}))
        E.clock_step(STORE, skew=('acme2', 0.0))           # the reference kept (30 s)
        self.assertTrue(E.clock_aside())
        reset()

    def test_one_node_never(self):
        reset(clock_mode='guard', ha_mode='', ha_peer='')
        STORE.db.run("DELETE FROM meta WHERE k = 'node:acme2'")
        E.clock_step(STORE, ref=300.0, skew='none')
        self.assertFalse(E.clock_aside())
        reset()

    def test_switched_off_while_aside(self):
        reset(clock_mode='guard')
        E.clock_step(STORE, ref=300.0, peer=well())
        self.assertTrue(E.clock_aside())
        E.CONFIG['clock_mode'] = 'off'
        E.CLOCK['role'] = 'aside'
        E.clock_tick(FakeDaemon())                          # the daemon's loop: once
        self.assertEqual(E.CLOCK['role'], 'serve')
        self.assertIsNone(E.CLOCK['ref'])                   # nothing kept from then
        self.assertFalse(E.maintenance_now(STORE).get('on'))
        reset()

    def test_the_watch_thread(self):
        reset(clock_mode='watch')
        with Spy() as spy:
            d = FakeDaemon()
            E.CLOCK['thread'] = None
            E.clock_tick(d)
            time.sleep(0.5)
            self.assertTrue(E.clock_watching())
            E.CONFIG['clock_mode'] = 'off'
            d.stop_flag.set()
            E.CLOCK['thread'].join(8)
            self.assertFalse(E.clock_watching())
        self.assertGreaterEqual(spy.sntp, 0)
        self.assertGreaterEqual(spy.skew, 1)
        reset()


class Directory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mockldap
        cls.port, cls.stop = mockldap.serve(0)
        base = 'DC=corpnet,DC=loc'
        STORE.directory_save({'name': 'corp', 'hosts': '127.0.0.1', 'port': cls.port, 'tls': 'none',
                              'verify': 0, 'base': base, 'bind_dn': 'CN=isemon,OU=Service,' + base,
                              'bind_pw': 'the-service-password', 'enabled': 1}, 'test')
        s = socket.socket()
        s.bind(('127.0.0.1', 0))
        dead = s.getsockname()[1]
        s.close()
        STORE.directory_save({'name': 'dead', 'hosts': '127.0.0.1', 'port': dead, 'tls': 'none',
                              'verify': 0, 'base': base, 'bind_dn': 'CN=isemon,OU=Service,' + base,
                              'bind_pw': 'x', 'enabled': 1}, 'test')

    @classmethod
    def tearDownClass(cls):
        cls.stop.set()

    def test_none_reached_not_reached(self):
        reset()
        self.assertEqual(E.clock_dir_check(STORE), (None, []))
        E.CONFIG['admin_directory'] = 'corp'
        ok, dirs = E.clock_dir_check(STORE)
        self.assertTrue(ok, dirs)
        E.CONFIG.update(portal=1, portal_directory='dead')
        ok, dirs = E.clock_dir_check(STORE)
        self.assertFalse(ok)
        self.assertEqual({d[0]: d[1] for d in dirs}, {'corp': True, 'dead': False})
        E.CONFIG.update(admin_directory='', portal=0, portal_directory='')

    def test_guard_aside_and_back(self):
        reset(clock_mode='guard', health_dir=1)
        E.clock_step(STORE, ref=0.0, skew=('acme2', 0.0), dir_ok=False, peer=well())
        self.assertTrue(E.clock_aside())
        self.assertIn('directory', E.CLOCK['why'])
        self.assertIn('clock:dir:acme1', E.alert_problems(STORE))
        E.clock_step(STORE, ref=0.0, dir_ok=True, peer=well())
        self.assertFalse(E.clock_aside())
        # Without the switch, never for the directory.
        E.CONFIG['health_dir'] = 0
        E.clock_step(STORE, ref=0.0, dir_ok=False, peer=well())
        self.assertFalse(E.clock_aside())
        reset()


class SplitSeesIt(unittest.TestCase):
    def test_maintenance_now_order(self):
        """Through the one gate: the split's aside first, then the clock's."""
        reset(clock_mode='guard')
        E.clock_step(STORE, ref=300.0, peer=well())
        self.assertEqual(E.maintenance_now(STORE).get('clock'), True)
        reset()


# ---------------------------------------------------------------------------
class Card(unittest.TestCase):
    def call(self, method, path, body=None):
        h = E.CliApiHandler(DAEMON, 'tester', body, {}, path)
        return E.ROUTES[(method, path)](h)

    def status(self, *a):
        try:
            self.call(*a)
            return 200
        except (E.ApiError, E.BadSetting) as e:
            return getattr(e, 'status', 400)

    def tearDown(self):
        for k in KEYS + ('clock_ref@acme1', 'clock_ref@acme2'):
            STORE.drop_setting(k)
        E.load_config()
        reset()

    def test_view(self):
        reset()
        v = self.call('GET', '/api/clock')
        self.assertFalse(v['engaged'])
        self.assertEqual([n['name'] for n in v['nodes']], ['acme1', 'acme2'])
        self.assertEqual(set(v['conf']), set(E.CLOCK_KEYS))
        self.assertTrue(v['cluster'])
        self.assertEqual(v['nodes'][1]['state'], {})          # nothing shown switched off

    def test_save(self):
        reset()
        self.assertEqual(self.status('POST', '/api/clock', {
            'action': 'save', 'conf': {'clock_mode': 'guard'}}), 409)     # not tried
        self.assertEqual(self.status('POST', '/api/clock', {
            'action': 'save', 'conf': {'clock_warn_s': 30, 'clock_aside_s': 20}}), 400)
        self.assertEqual(self.status('POST', '/api/clock', {
            'action': 'save', 'conf': {'clock_mode': 'nope'}}), 400)
        self.assertEqual(self.status('POST', '/api/clock', {
            'action': 'save', 'refs': {'acme2': 'a/b'}}), 400)
        self.assertEqual(self.status('POST', '/api/clock', {
            'action': 'save', 'refs': {'acme9': 'ntp.local'}}), 400)
        self.assertEqual(self.status('POST', '/api/clock', {'action': 'what'}), 400)
        got = self.call('POST', '/api/clock', {
            'action': 'save', 'checked': True,
            'conf': {'clock_mode': 'guard', 'clock_warn_s': 3, 'clock_aside_s': 30,
                     'clock_codes': 1, 'health_dir': True},
            'refs': {'acme2': 'ntp.local:123'}})
        self.assertIn('kept', got['message'])
        saved = STORE.settings_saved()
        self.assertEqual((saved['clock_mode'], int(saved['clock_warn_s']), int(saved['clock_aside_s']),
                          int(saved['clock_codes']), int(saved['health_dir'])), ('guard', 3, 30, 1, 1))
        self.assertEqual(saved['clock_ref@acme2'], 'ntp.local:123')
        self.assertEqual({n['name']: n['ref'] for n in got['view']['nodes']}['acme2'], 'ntp.local:123')
        got = self.call('POST', '/api/clock', {'action': 'save', 'conf': {'clock_mode': 'off'}})
        self.assertIn(STORE.settings_saved().get('clock_mode'), ('off', None))
        self.assertFalse(got['view']['engaged'])
        # Past the card: the same rule.
        with self.assertRaises(E.BadSetting):
            DAEMON.save_settings({'clock_aside_s': 2}, by='test', node='*')
        with self.assertRaises(E.BadSetting):
            DAEMON.save_settings({'clock_ref': 'a/b'}, by='test', node='acme1')

    def test_try_from_every_node(self):
        reset()
        srv = FakeNtp(12.0)
        try:
            asked = self.call('POST', '/api/clock', {'action': 'try', 'refs': {'acme1': srv.addr}})
            self.assertIn('acme1', asked['nodes'])
            E.node_ask_tick(type('D', (), {'store': STORE, 'serving': True})())
            for _ in range(80):
                got = self.call('POST', '/api/clock', {'action': 'poll', 'id': asked['id']})
                if (got['nodes'] or {}).get('acme1'):
                    break
                time.sleep(0.1)
            one = got['nodes']['acme1']
            self.assertTrue(one['ok'])
            self.assertAlmostEqual(one['refs'][0]['offset'], 12.0, delta=0.1)
            self.assertEqual(one['servers'], [srv.addr])
        finally:
            srv.close()

    def test_not_in_the_settings_lists(self):
        keys = {s['key'] for s in DAEMON.settings_state(True)}
        self.assertFalse([k for k in keys if k.startswith('clock_') or k == 'health_dir'])
        self.assertTrue(set(KEYS) <= set(E.PANES['time']))
        self.assertTrue(set(KEYS) <= set(E.CARD_DRAWN))
        self.assertIn('clock_ref', E.NODE_KEYS)

    def test_the_card_on_the_pages(self):
        php = open(os.path.join(ROOT, 'web', 'admin', 'index.php'), encoding='utf-8').read()
        js = open(os.path.join(ROOT, 'web', 'assets', 'admin.js'), encoding='utf-8').read()
        css = open(os.path.join(ROOT, 'web', 'assets', 'acme.css'), encoding='utf-8').read()
        for piece in ('id="clock-card"', 'id="clock-state"', 'id="clock-guard"'):
            self.assertIn(piece, php)
        self.assertLess(php.index('id="ntp-host"'), php.index('id="clock-card"'))
        # The relay passes it on, read and write (otp 1.0.222): else only the title shows.
        self.assertEqual(len(re.findall(r"'clock' => '/api/clock'", php)), 2)
        for piece in ('function loadClock(', 'function drawClock(', 'function clockScenarios(',
                      "pendingSet('clock'", 'loadClock(true);', "k: 'clock_codes'",
                      'var r_ = drawClockIn();', "'plain split-scen', {free: true}"):
            self.assertIn(piece, js)
        self.assertNotIn('RADIUS', js[js.index('var CLOCKC ='):js.index('function drawClockIn')])
        for piece in ('.split-line.warn svg,.split-line.warn{color:var(--warn)}',
                      '.split-fields .set-item.bad input{border-color:var(--crit)}'):
            self.assertIn(piece, css)
        cs = json.load(open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8'))
        src = {v['source']: v['text'] for sec in ('strings', 'patterns')
               for v in cs[sec].values()}
        for en, czech in (('The clocks of the nodes', 'Hodiny uzlů'),
                          ('Measure and warn', 'Měřit a varovat'),
                          ('Codes by the corrected time', 'Kódy podle opraveného času'),
                          ('Reference of {0}', 'Reference uzlu {0}'),
                          ('{0} cannot reach the directory, {1} can', '{0} nedosáhne na adresář, {1} ano')):
            self.assertEqual(src.get(en), czech)
        # Every text of the card has its Czech.
        block = js[js.index('var CLOCKC ='):js.index('/* ---- Settings → Time (1.0.120)')]
        missing = []
        for m in re.finditer(r"(?:el\([^,]+, '[^']*', |t: |s: |toast\(|good: \[|bad: \[|formField\()'((?:[^'\\]|\\.)+)'", block):
            w = m.group(1).replace("\\u2019", '’').replace("\\u2026", '…').strip()
            pat = block[m.end():m.end() + 4].lstrip().startswith('+')
            if pat and any(k.startswith(w) and '{0}' in k for k in src):
                continue                                    # a pattern's words, {0} after them
            if w and not re.match(r'^[\W\d]*$', w) and w not in src:
                missing.append(w)
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
