#!/usr/bin/env python3
"""Hunt R, run 1, SELinux and the upgrade band: functions of web/assets/admin.js run in node with
stubs.

  * seBusy: a node not heard from is not waited for - the card was drawn again every two seconds
    for as long as it stayed away (its step, or its first look, pending);
  * seReport: "Download the report" does not wait three minutes for a node not heard from, and
    says which node made no new report instead of "every node's report is in it";
  * upgradeAway: root's file of an upgrade done (kept ten minutes) does not hide a daemon that is
    not answering - only one still running does.
"""
import json
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ADMIN = os.path.join(HERE, '..', 'web', 'assets', 'admin.js')
NODE = shutil.which('node')


def js_function(src, name):
    """The source of `function name(...) {...}` in src, braces counted (strings and comments are
    simple enough in these functions)."""
    start = src.index('\nfunction %s(' % name) + 1
    i = src.index('{', start)
    depth = 0
    q = None
    while True:
        c = src[i]
        if not q and src.startswith('/*', i):
            i = src.index('*/', i) + 2
            continue
        if not q and src.startswith('//', i):
            i = src.index('\n', i)
            continue
        if q:
            if c == '\\':
                i += 2
                continue
            if c == q:
                q = None
        elif c in '\'"':
            q = c
        elif c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return src[start:i + 1]
        i += 1


def run_js(code):
    got = subprocess.run([NODE, '-e', code], capture_output=True, text=True, timeout=60)
    if got.returncode != 0:
        raise AssertionError(got.stderr)
    return json.loads(got.stdout.strip().splitlines()[-1])


@unittest.skipUnless(NODE, 'node is not installed')
class SelinuxCard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(ADMIN, encoding='utf-8') as f:
            cls.src = f.read()

    def test_busy_skips_a_node_not_heard_from(self):
        code = js_function(self.src, 'seBusy') + """
var a = {name: 'a', alive: true, state: {mode: 'Enforcing'}};
console.log(JSON.stringify([
  seBusy({nodes: [a, {name: 'b', alive: false, state: {}}]}),
  seBusy({nodes: [a, {name: 'b', alive: false, pending: 'enforce', state: {mode: 'Permissive'}}]}),
  seBusy({nodes: [a, {name: 'b', alive: true, pending: 'enforce', state: {mode: 'Permissive'}}]}),
  seBusy({nodes: [{name: 'a', alive: true, state: {}}]})
]));"""
        self.assertEqual(run_js(code), [False, False, True, True])

    def _report(self, nodes, reports_after, missing=()):
        code = """
var SE = {d: {nodes: %(nodes)s, reports: {a: {at: 100}, b: {at: 100}}}, rep: null};
var asked = [], polls = 0, drawn = [];
function busy() {}
function drawSelinux() { drawn.push(SE.rep && SE.rep.words); }
function oops(e) { drawn.push('oops ' + e); }
function seShown() { return SE.d.nodes[0]; }
function el() { return {remove: function () {}, click: function () {}}; }
var document = {body: {appendChild: function () {}}};
var URL = {createObjectURL: function () { return 'x'; }, revokeObjectURL: function () {}};
function Blob() {}
function atob() { return ''; }
var realSet = setTimeout;
setTimeout = function (f) { realSet(f, 0); };
function api(what, body) {
  if (!body) {
    polls++;
    return Promise.resolve({nodes: %(nodes)s, reports: %(after)s});
  }
  asked.push(body);
  if (body.action === 'report') return Promise.resolve({busy: []});
  return Promise.resolve({file: '', name: 'r.tar.gz', missing: %(missing)s});
}
%(fn)s
seReport(null, true);
realSet(function () { console.log(JSON.stringify({polls: polls, words: SE.rep.words, bad: !!SE.rep.bad})); }, 300);
""" % {'nodes': json.dumps(nodes), 'after': json.dumps(reports_after), 'missing': json.dumps(list(missing)),
       'fn': js_function(self.src, 'seReport')}
        return run_js(code)

    def test_report_does_not_wait_for_a_node_not_heard_from(self):
        nodes = [{'name': 'a', 'me': True, 'alive': True}, {'name': 'b', 'alive': False}]
        got = self._report(nodes, {'a': {'at': 200}, 'b': {'at': 100}})
        # one look: a made its report, b is not waited for (before: every 3 s for 3 minutes)
        self.assertEqual(got['polls'], 1)
        self.assertTrue(got['bad'])
        self.assertIn('no new report of: b', got['words'])

    def test_report_every_node_new(self):
        nodes = [{'name': 'a', 'me': True, 'alive': True}, {'name': 'b', 'alive': True}]
        got = self._report(nodes, {'a': {'at': 200}, 'b': {'at': 300}})
        self.assertEqual(got['words'], "Downloaded: every node's report is in it.")
        self.assertFalse(got['bad'])

    def test_report_missing_said_as_before(self):
        nodes = [{'name': 'a', 'me': True, 'alive': True}, {'name': 'b', 'alive': False}]
        got = self._report(nodes, {'a': {'at': 200}}, ['b: no report (the node did not answer)'])
        self.assertEqual(got['words'], 'Downloaded - without: b: no report (the node did not answer)')


@unittest.skipUnless(NODE, 'node is not installed')
class UpgradeBand(unittest.TestCase):
    def test_away_only_while_running(self):
        with open(ADMIN, encoding='utf-8') as f:
            src = f.read()
        code = """
var UPG = {api: true, away: 0}, fetched = 0;
var expected = false;
function upgradeExpected() { return expected; }
function upgradeDraw() {}
function upgSeenNow() {}
function fetch() { fetched++; return new Promise(function () {}); }
%s
var out = [upgradeAway({upgrading: {state: 'running'}}),
           upgradeAway({upgrading: {state: 'done'}}),
           upgradeAway({upgrading: {state: 'failed'}}),
           upgradeAway({message: 'x'})];
expected = true;
out.push(upgradeAway({upgrading: {state: 'done'}}));
console.log(JSON.stringify(out));
""" % js_function(src, 'upgradeAway')
        self.assertEqual(run_js(code), [True, False, False, False, True])


if __name__ == '__main__':
    unittest.main(verbosity=2)
