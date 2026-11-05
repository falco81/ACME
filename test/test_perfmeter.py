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
