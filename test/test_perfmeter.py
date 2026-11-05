#!/usr/bin/env python3
"""The performance meter in the header (1.0.48): off unless chosen, a full administrator's only,
/proc read when asked.

    python3 test/test_perfmeter.py
"""
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-perf-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acmelib.engine as E  # noqa: E402


def read(*p):
    with open(os.path.join(ROOT, *p), encoding='utf-8') as f:
        return f.read()


class Reading(unittest.TestCase):
    def test_the_summary_and_its_rates(self):
        E.LOAD_LAST.update(at=0.0, raw=None, out=None)
        first = E.server_load()
        self.assertIn('mem_total', first)
        self.assertNotIn('cpu', first)          # nothing to tell a rate from yet
        self.assertIs(E.server_load(), first)   # asked within the second: the same reading
        time.sleep(1.1)
        second = E.server_load()
        self.assertIn('cpu', second)
        self.assertGreaterEqual(second['cpu'], 0)
        self.assertLessEqual(second['cpu'], 100)

    def test_the_details(self):
        got = E.api_load(detail=True)
        d = got['detail']
        for k in ('cores', 'disks', 'filesystems', 'nics', 'top_cpu', 'top_mem', 'mem'):
            self.assertIn(k, d)


def put(path, text):
    with open(path, 'w') as f:
        f.write(text)


class Sensors(unittest.TestCase):
    """As plexmon found (1.0.48): the cores' temperatures by the topology; drivetemp read as it is."""

    def fake_sys(self, ids, labels):
        root = tempfile.mkdtemp(dir=TMP)
        hw = os.path.join(root, 'class/hwmon')
        os.makedirs(os.path.join(root, 'devices/platform/coretemp.0'))
        h1 = os.path.join(hw, 'hwmon1')
        os.makedirs(h1)
        put(os.path.join(h1, 'name'), 'coretemp\n')
        os.symlink(os.path.join(root, 'devices/platform/coretemp.0'), os.path.join(h1, 'device'))
        for i, (lab, t) in enumerate(labels, 2):
            put(os.path.join(h1, 'temp%d_label' % i), lab + '\n')
            put(os.path.join(h1, 'temp%d_input' % i), '%d\n' % (t * 1000))
        # a SATA disk's drivetemp: read as it is here (acme's disks are not put to sleep)
        h0 = os.path.join(hw, 'hwmon0')
        os.makedirs(os.path.join(h0, 'device', 'block', 'sda'))
        put(os.path.join(h0, 'name'), 'drivetemp\n')
        put(os.path.join(h0, 'temp1_input'), '37000\n')
        for n, cid in enumerate(ids):
            topo = os.path.join(root, 'devices/system/cpu/cpu%d/topology' % n)
            os.makedirs(topo)
            put(os.path.join(topo, 'core_id'), '%d\n' % cid)
            put(os.path.join(topo, 'physical_package_id'), '0\n')
        return root

    def run_with(self, root, cores):
        import threading
        from unittest import mock
        got = {}

        def go():
            with mock.patch.object(E, 'LOAD_SYS', root):
                got['t'] = E.load_temps()
        th = threading.Thread(target=go, daemon=True)
        th.start()
        th.join(5)
        self.assertFalse(th.is_alive())
        return got['t']

    def test_a_sata_disks_temperature(self):
        t = self.run_with(self.fake_sys([0, 1], [('Core 0', 48), ('Core 1', 44)]), 2)
        self.assertEqual(t['disks'], {'sda': 37.0})
        self.assertEqual(t['pkg_cores'], {'0:0': 48.0, '0:1': 44.0})

    def test_every_thread_its_cores_temperature(self):
        from unittest import mock
        for ids, labels in (([0, 1, 0, 1], [('Core 0', 48), ('Core 1', 44)]),
                            ([0, 4, 0, 4], [('Core 0', 50), ('Core 4', 41)])):
            root = self.fake_sys(ids, labels)
            raw = {'at': time.time(), 'cores': {n: (0, 100) for n in range(4)}, 'disks': {}, 'nics': {},
                   'procs': {}}
            with mock.patch.object(E, 'LOAD_SYS', root), \
                    mock.patch.object(E, '_load_detail_raw', return_value=raw):
                E.LOAD_DETAIL.update(at=0.0, raw=None, out=None)
                d = E.load_detail()
            temps = [c['temp'] for c in d['cores']]
            self.assertTrue(all(x is not None for x in temps), (ids, temps))
            self.assertEqual(temps[0], temps[2])

    def test_free_space_only_of_the_kernels_filesystems(self):
        for k in ('ext4', 'xfs', 'btrfs', 'zfs'):
            self.assertIn(k, E.LOAD_FS_KINDS)
        for k in ('nfs', 'nfs4', 'cifs', 'smb3', 'fuseblk', 'fuse.sshfs', 'vfat', 'msdos'):
            self.assertNotIn(k, E.LOAD_FS_KINDS)


class Bars(unittest.TestCase):
    def test_nothing_at_zero(self):
        import subprocess
        js = read('web', 'assets', 'hload.js')
        i = js.index('function hlWidth(')
        fn = js[i:js.index('\n}', i) + 2]
        out = subprocess.run(['node', '-e', fn + ';console.log(JSON.stringify([hlWidth(0), hlWidth(0.49), '
                              'hlWidth(0.5), hlWidth(140), hlWidth(null)]))'],
                             capture_output=True, text=True)
        if out.returncode:
            self.skipTest('no node here')
        self.assertEqual(out.stdout.strip(), '[0,0,1,100,0]')
        self.assertNotIn('100 * v / top', js)
        self.assertIn('stroke-dasharray^="0.0 "', read('web', 'assets', 'hload.css'))


class History(unittest.TestCase):
    def test_the_last_two_minutes_for_a_page_loaded_again(self):
        E.LOAD_HIST.clear()
        t = time.time()
        for i in range(60):
            E.LOAD_HIST.append((t - 200 + i * 3, float(i), 50.0, 1000, 2000))
        got = E.load_history()
        self.assertTrue(0 < len(got['cpu']) <= 40)
        self.assertEqual(len(got['cpu']), len(got['mem']))
        self.assertTrue(all(v >= 19 for v in got['cpu']))      # only the last 125 s
        self.assertIn('hist', E.api_load(hist=True))

    def test_the_page_asks_it_once(self):
        js = read('web', 'assets', 'hload.js')
        self.assertIn("(withHist ? '&hist=1' : '')", js)


class Choices(unittest.TestCase):
    def test_the_choice_is_kept_with_the_account(self):
        self.assertIn("prefs.update(h.store.clean_prefs({k: b[k] for k in ('hload', 'hpanel') if k in b}))",
                      read('acmelib', 'engine', '355_editing_the_columns_switched.py'))

    def test_off_unless_chosen_and_only_known_ones(self):
        st = E.Storage(E.open_db())
        self.assertEqual(st.clean_prefs({'hload': 'graphs', 'hpanel': 'map'}),
                         {'hload': 'graphs', 'hpanel': 'map'})
        with self.assertRaises(ValueError):
            st.clean_prefs({'hload': '<script>'})
        self.assertEqual(E.HLOAD_LOOKS[0], 'off')
        js = read('web', 'assets', 'hload.js')
        self.assertIn("HLOAD.look = prefs().hload || 'off';", js)
        self.assertNotIn("|| 'graphs'", js)


class Pages(unittest.TestCase):
    def test_a_full_administrators_only(self):
        self.assertIn("h.me('fulladmin')", read('acmelib', 'engine', '468_how_busy_the_server_is.py'))
        php = read('web', 'admin', 'index.php')
        i = php.index('id="hload"')
        self.assertIn("(($me['role'] ?? '') === 'fulladmin')", php[i - 300:i])
        self.assertIn("'load' => '/api/load'", php)

    def test_no_colours_of_its_own(self):
        self.assertNotIn(':root{', read('web', 'assets', 'hload.css'))


if __name__ == '__main__':
    unittest.main()
