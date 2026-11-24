#!/usr/bin/env python3
"""Hunt w9 (1.0.144), area agentsui: the administration's pages of target agents.

    python3 test/test_hunt_rw9_agentsui.py
    ACME_TEST_CS_EXTRA=FILE   {English: Czech} merged into a copy of cs.json for the pages

* The pages' relay (web/admin/index.php) took a route's last word only of letters and "_":
  agents/confirm-many was answered "unknown endpoint" - Confirm selected… and Confirm all of this
  code… on Settings → Target agents never confirmed an agent. A last word of two (a-b) is
  relayed as it is now; certs-one and the rest as before.
* The take-over of a certificate found on a server (fleet.takeover_preview): a source that does
  not issue for its names (the default, a public CA, for internal names) - the preview said
  "the agent's policy allows all of it" and Take over was refused by the daemon. The preview
  says it now (`refused`, a step "bad"); the page keeps Take over off, and asks the preview
  again when the source is changed (it went on saying the first one).
* Taken over and not deployed yet, the certificate found stayed "not managed" with Take over…:
  a second take-over made a second certificate ("NAME 2") deployed to the same files. It is
  listed as taken over now (`taken`; acme --fleet-unmanaged: "taken: NAME", the console says
  it), and a take-over of it refused (acme --fleet-takeover too; there a source that does not
  issue for the names is said before anything is asked).
* The pages (Chromium, test/hunt_rw9_agentsui_page.js; skipped without node/playwright/php):
  the confirming of several, a long target name on a phone (390 px: the page was wider), the
  policy designer's "Start from" (one click on "nothing" emptied what was typed - asked first
  now), the take-over above, the Czech of the designer's template notes.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import test_f138_fleet as F  # noqa: E402  (its engine and folders, its daemon pages)

STORE, A, S, G, FL = F.STORE, F.A, F.S, F.G, F.FL
CS_EXTRA = os.environ.get('ACME_TEST_CS_EXTRA', '')


def src(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as fh:
        return fh.read()


class Relay(unittest.TestCase):
    """The pattern of the certificate manager's routes in web/admin/index.php, run by PHP."""

    def test_routes_with_a_dash(self):
        if not shutil.which('php'):
            self.skipTest('no php here')
        text = src('web/admin/index.php')
        at = text.index("if (preg_match('#^(certs|")
        pat = text[at + len("if (preg_match('"):text.index("', $what, $road)", at)]
        code = ('$p = %s; foreach (json_decode($argv[1]) as $w) { if (preg_match($p, $w, $r)) '
                'echo $w, " ", "/api/" . $r[1] . (isset($r[2]) && $r[2] !== "" ? "/" . $r[2] : ""),'
                ' "\\n"; else echo $w, " -\\n"; }') % ("'" + pat.replace("'", "\\'") + "'")
        words = ['agents/confirm-many', 'certs-one', 'certs/one', 'agents/design/forget',
                 'agents/guard/rotate', 'targets-test', 'agents', 'certs/one/two/three',
                 'agents/Confirm', 'isemon-sync']
        got = subprocess.run(['php', '-r', code, json.dumps(words)], capture_output=True,
                             text=True, timeout=60)
        self.assertEqual(got.returncode, 0, got.stderr)
        said = dict(line.split(' ', 1) for line in got.stdout.strip().splitlines())
        self.assertEqual(said, {
            'agents/confirm-many': '/api/agents/confirm-many',
            'certs-one': '/api/certs/one', 'certs/one': '/api/certs/one',
            'agents/design/forget': '/api/agents/design/forget',
            'agents/guard/rotate': '/api/agents/guard/rotate',
            'targets-test': '/api/targets/test', 'agents': '/api/agents',
            'certs/one/two/three': '-', 'agents/Confirm': '-', 'isemon-sync': '-'})
        # every route the pages ask with a dash in it is one the daemon has
        self.assertIn("ask('agents/confirm-many'", src('web/assets/agents.js'))
        self.assertIn("@A.api('POST', '/api/agents/confirm-many'",
                      src('acmelib/certs/api_agents.py'))


class TakeOver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from acmelib.certs import defaults as DF
        DF.ensure(STORE)
        F.route('POST', '/api/cas/create', body={'name': 'W9 Root', 'subject': {
            'CN': 'W9 Root CA'}, 'key_type': 'ec-256', 'days': 3650})
        A.family_save(STORE, 'issuer', {'name': 'w9own', 'kind': 'internal_ca',
                                        'config': {'ca': 'W9 Root', 'days': 90}}, 'tester')
        cls.row = F.target('w9-web', text=F.NGINX)
        F.discovery(cls.row, '9A' * 20, 5)

    def test_refused_names_said(self):
        from acmelib.certs import defaults as DF
        di = DF.default_issuer(STORE)
        self.assertTrue(di, 'a default source (Let\'s Encrypt)')
        before = STORE.db.value('SELECT COUNT(*) FROM certs', (), 0)
        p = FL.takeover_preview(STORE, {'target': 'w9-web', 'service': 'nginx-0'})
        self.assertEqual(p['cert']['issuer'], di['name'])
        self.assertIn('ends in .test, a name that is never public', p['refused'])
        self.assertIn('bad', [s[0] for s in p['steps']])
        # the daemon refuses it with the same words
        with self.assertRaises(Exception) as e:
            FL.takeover(STORE, {'target': 'w9-web', 'service': 'nginx-0', 'confirm': True},
                        'tester', True)
        self.assertIn('ends in .test', str(e.exception))
        self.assertEqual(STORE.db.value('SELECT COUNT(*) FROM certs', (), 0), before)
        # a source that issues for them: nothing said
        q = FL.takeover_preview(STORE, {'target': 'w9-web', 'service': 'nginx-0',
                                        'issuer': 'w9own'})
        self.assertEqual(q['refused'], '')
        self.assertNotIn('bad', [s[0] for s in q['steps']])
        self.assertEqual(q['steps'][-1][0], 'ok')

    def test_taken_not_offered_again(self):
        mine = lambda: [r for r in FL.unmanaged(STORE) if r['target'] == 'w9-web'  # noqa: E731
                        and r['service']][0]
        r = mine()
        self.assertTrue(r['can_take'])
        self.assertEqual(r['taken'], '')
        got = FL.takeover(STORE, {'target': 'w9-web', 'service': 'nginx-0', 'issuer': 'w9own',
                                  'confirm': True, 'name': 'w9api'}, 'tester', True)
        self.assertEqual(got['name'], 'w9api')
        r = mine()
        self.assertEqual((r['taken'], r['can_take']), ('w9api', False))
        with self.assertRaises(ValueError) as e:
            FL.takeover_preview(STORE, {'target': 'w9-web', 'service': 'nginx-0',
                                        'issuer': 'w9own'})
        self.assertIn('taken over already: the certificate w9api', str(e.exception))
        n = STORE.db.value("SELECT COUNT(*) FROM certs WHERE name LIKE 'w9api%'", (), 0)
        with self.assertRaises(ValueError):
            FL.takeover(STORE, {'target': 'w9-web', 'service': 'nginx-0', 'issuer': 'w9own',
                                'confirm': True}, 'tester', True)
        self.assertEqual(STORE.db.value("SELECT COUNT(*) FROM certs WHERE name LIKE 'w9api%'",
                                        (), 0), n)
        # its deployment taken away: offered again
        STORE.db.run('DELETE FROM cert_deploys WHERE id = ?', (got['deploy_id'],))
        r = mine()
        self.assertEqual((r['taken'], r['can_take']), ('', True))

    def test_out_paths(self):
        self.assertEqual(FL._out_paths({'outputs': ['fullchain-pem /a/b.crt 0644 root:root',
                                                    'key-pem /a/b.key']}), {'/a/b.crt', '/a/b.key'})
        self.assertEqual(FL._out_paths({'outputs': 'fullchain-pem /k/x.crt\nkey-pem /k/x.key\n'}),
                         {'/k/x.crt', '/k/x.key'})
        self.assertEqual(FL._out_paths({}), set())
        self.assertEqual(FL._out_paths(None), set())


class Source(unittest.TestCase):
    def test_page_words(self):
        pb = src('web/assets/policybuilder.js')
        self.assertIn("modalSure('Start again from it? What was changed here is lost.', go, "
                      "'Start again')", pb)
        fl = src('web/assets/fleet.js')
        self.assertIn('ss.onchange = function () { F.issuer = ss.value; refreshPreview(); };', fl)
        self.assertIn('if (tb) tb.disabled = !!p.refused;', fl)
        self.assertIn('.ag-name .dbs-tile-n{min-width:0;overflow-wrap:anywhere}',
                      src('web/assets/agents.css'))


class Pages(F.Pages):
    """Settings → Target agents and Agent fleet in Chromium against a daemon (php -S)."""

    def seed_more(self):
        """Three agents waiting to be confirmed (each with its CSR), a target of a long name."""
        for n in ('w9-wait-01', 'w9-wait-02', 'w9-wait-03'):
            self.ok('POST', '/api/targets/save', {'name': n, 'kind': 'agent', 'config': {
                'mode': 'passive', 'host': n + '.example.test'}})
        self.ok('POST', '/api/targets/save', {'name': 'w9-long-' + 'x' * 56, 'kind': 'agent',
                                              'config': {'mode': 'passive',
                                                         'host': 'long.example.test'}})
        rows = self.ok('GET', '/api/targets')
        rows = rows.get('rows') if isinstance(rows, dict) else rows
        ids = {r['name']: r['id'] for r in rows}
        tmp = tempfile.mkdtemp(dir=self.tmp)
        meta = {}
        for i, n in enumerate(('w9-wait-01', 'w9-wait-02', 'w9-wait-03')):
            key = os.path.join(tmp, 'k%d' % i)
            csr = subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
                                  'ec_paramgen_curve:P-256', '-nodes', '-keyout', key,
                                  '-subj', '/CN=x'], capture_output=True, text=True,
                                 timeout=60).stdout
            self.assertIn('CERTIFICATE REQUEST', csr)
            meta['agents:t:%d' % ids[n]] = {'pending': {
                'fp': ('%02x' % (0x91 + i)) * 32, 'at': time.time() - 30 * i, 'host': n,
                'fqdn': n + '.example.test', 'ip': '192.0.2.%d' % (10 + i), 'os': 'Debian 12',
                'platform': 'linux', 'version': '1.0.144', 'csr': csr, 'enc_pub': 'x' * 44,
                'agent_id': 'ag-%012x' % (0x900000 + ids[n])}}
        fn = os.path.join(self.tmp, 'seed-w9.json')
        with open(fn, 'w') as fh:
            json.dump(meta, fh)
        got = subprocess.run([sys.executable, '-c', (
            'import sys, json; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); d = json.load(open(%r)); '
            '[st.set_meta(k, json.dumps(v, sort_keys=True)) for k, v in d.items()]') % (ROOT, fn)],
            env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])

    def test_pages(self):
        node = shutil.which('node')
        self.seed()
        self.seed_more()
        web = os.path.join(self.tmp, 'web')
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        extra = {}
        for fn in [x for x in CS_EXTRA.split(os.pathsep) if x]:
            if os.path.isfile(fn):
                with open(fn, encoding='utf-8') as fh:
                    extra.update(json.load(fh))
        if extra:
            cs = os.path.join(web, 'lang', 'cs.json')
            with open(cs, encoding='utf-8') as fh:
                pack = json.load(fh)
            have = {v.get('source') for part in ('strings', 'patterns')
                    for v in pack.get(part, {}).values()}
            for i, (k, v) in enumerate(sorted(extra.items())):
                if k not in have:
                    part = 'patterns' if '{0}' in k else 'strings'
                    pack[part]['xrw9%04d' % i] = {'source': k, 'text': v}
            with open(cs, 'w', encoding='utf-8') as fh:
                json.dump(pack, fh, ensure_ascii=False, indent=1)
        port = self.TCC.free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               env=dict(os.environ, PHP_CLI_SERVER_WORKERS='4'),
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=5)
                    break
                except urllib.error.HTTPError:
                    break
                except OSError:
                    time.sleep(0.2)
            got = subprocess.run([node, os.path.join(HERE, 'hunt_rw9_agentsui_page.js'),
                                  'http://127.0.0.1:%d' % port, self.pw], cwd=ROOT,
                                 capture_output=True, text=True, timeout=900)
        finally:
            php.terminate()
            php.wait(10)
        self.assertEqual(got.returncode, 0, got.stderr[-3000:])
        out = json.loads(got.stdout.strip().splitlines()[-1])
        self.assertFalse(out.get('error'), out)
        self.assertEqual(out['errors'], [], out['errors'])
        c = out['checks']
        # several confirmed at once, through the relay
        self.assertGreaterEqual(c['waiting_before'], 3, c)
        self.assertEqual(c['selected_words'], 'Confirm selected (2)…')
        self.assertEqual(c['waiting_after'], ['w9-wait-03'], c)
        self.assertEqual(c['confirmed_toast'], '2 confirmed')
        # Start from: asked; No keeps, Yes empties; unchanged - not asked
        self.assertIn('/srv/w9-typed', c['typed'])
        self.assertIn('Start again from it?', c['start_asked'])
        self.assertEqual(c['kept_on_no'], c['typed'])
        self.assertEqual(c['empty_on_yes'], [])
        self.assertIs(c['not_asked_unchanged'], True)
        self.assertEqual(c['server_again'], ['/etc/nginx/ssl'])
        # a long name on a phone
        for lang in ('en', 'cs'):
            self.assertLessEqual(c[lang + '_phone_width'], 390, lang)
            self.assertIs(c[lang + '_long_tile'], True, lang)
        # the take-over
        self.assertIn('ends in .test', c['to_public']['refused'])
        self.assertIs(c['to_public']['take'], True)
        self.assertEqual(c['to_own']['refused'], '')
        self.assertIs(c['to_own']['take'], False)
        self.assertIn('from own', ' '.join(c['to_own']['steps']))
        self.assertNotIn('from own', ' '.join(c['to_public']['steps']))
        self.assertIn('taken over', c['to_toast'])
        self.assertEqual(c['en_taken'], {'taken': 'taken over shop.example.test', 'take': False})
        self.assertFalse(c['cs_taken']['take'])
        self.assertIn('shop.example.test', c['cs_taken']['taken'])
        if extra:
            self.assertEqual(c['cs_notes'], [1, 1, 1, 1], c['cs_notes'])
        # the command line says the same: taken over, and not taken over twice
        cli = lambda *a: self.TCC.CertsCore.cli(self, *a)  # noqa: E731
        got = cli('--fleet-unmanaged')
        self.assertEqual(got.returncode, 0, got.stderr[-2000:])
        self.assertIn('taken: shop.example.test', got.stdout)
        svc = [r for r in self.ok('GET', '/api/fleet/unmanaged')['rows']
               if r.get('taken')][0]['service']
        got = cli('--fleet-takeover', 'web-prague-02', svc, '--issuer', 'own', '--yes')
        self.assertNotEqual(got.returncode, 0, got.stdout)
        self.assertIn('taken over already: the certificate shop.example.test', got.stderr +
                      got.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
