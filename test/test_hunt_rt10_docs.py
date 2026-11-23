#!/usr/bin/env python3
"""Hunt T10 - the documentation checked against the code:

    python3 test/test_hunt_rt10_docs.py

* every link between the docs (docs/*.md, README.md, INSTALL.md) leads to a file that is there
  and, with #anchor, to a heading of it (GitHub's anchors);
* every setting of DEFAULTS a person can change is named in the docs (`key`);
* the defaults the portal's table and the agent's enrollment API say are the code's;
* `--secret -` (no such option) is not offered as a way to type a secret.
"""
import glob
import os
import re
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-rt10-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{"node_name": "acme1", "upgrade_check": 0}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP, ACME_RUN=TMP,
                  ACME_LOGDIR=TMP, ACME_PLUGINS=os.path.join(TMP, 'plugins'))
sys.path.insert(0, ROOT)

from acmelib import engine as E  # noqa: E402

DOCS = sorted(glob.glob(os.path.join(ROOT, 'docs', '*.md'))) + \
    [os.path.join(ROOT, 'README.md'), os.path.join(ROOT, 'INSTALL.md')]
# Kept by the daemon itself, never set by a person.
NOT_SETTINGS = {'db_guard_kept_off'}


def read(p):
    with open(p, encoding='utf-8') as f:
        return f.read()


def anchors(path):
    """GitHub's anchors of a Markdown file's headings (and explicit <a name/id>)."""
    out, seen = set(), {}
    text = read(path)
    in_code = False
    for line in text.splitlines():
        if line.startswith('```'):
            in_code = not in_code
            continue
        m = None if in_code else re.match(r'#{1,6}\s+(.*?)\s*#*\s*$', line)
        if not m:
            continue
        a = m.group(1).strip().lower()
        a = re.sub(r'[^\w\- ]', '', a).replace(' ', '-')
        n = seen.get(a, 0)
        seen[a] = n + 1
        out.add(a if not n else '%s-%d' % (a, n))
    out |= set(re.findall(r'<a (?:name|id)="([^"]+)"', text))
    return out


class Links(unittest.TestCase):
    def test_links_between_docs_resolve(self):
        bad = []
        for f in DOCS:
            text = re.sub(r'```.*?```', '', read(f), flags=re.S)
            for m in re.finditer(r'\]\(([^)\s]+)\)', text):
                url = m.group(1)
                if re.match(r'^[a-z]+:', url):
                    continue
                path, _, frag = url.partition('#')
                target = os.path.normpath(os.path.join(os.path.dirname(f), path)) if path else f
                if not os.path.exists(target):
                    bad.append('%s: %s (no such file)' % (os.path.relpath(f, ROOT), url))
                elif frag and target.endswith('.md') and frag not in anchors(target):
                    bad.append('%s: %s (no such heading)' % (os.path.relpath(f, ROOT), url))
        self.assertEqual(bad, [])


class Settings(unittest.TestCase):
    def test_every_setting_is_documented(self):
        text = '\n'.join(read(f) for f in DOCS)
        missing = [k for k in E.DEFAULTS if k not in NOT_SETTINGS
                   and not re.search(r'\b%s\b' % re.escape(k), text)]
        self.assertEqual(missing, [], 'settings no doc names - add them to the docs')

    def test_portal_table_defaults(self):
        text = read(os.path.join(ROOT, 'docs', 'certificate-portal.md'))
        row = re.search(r'^\| `portal` \| (\S+) \|', text, re.M)
        self.assertEqual(row.group(1), str(E.DEFAULTS['portal']))
        row = re.search(r'^\| `portal_certlogin`, `portal_certlogin_match`, '
                        r'`portal_certlogin_crl` \| ([^|]+) \|', text, re.M)
        self.assertEqual([x.strip() for x in row.group(1).split(',')],
                         [str(E.DEFAULTS['portal_certlogin']),
                          E.DEFAULTS['portal_certlogin_match'],
                          str(E.DEFAULTS['portal_certlogin_crl'])])

    def test_no_secret_option(self):
        text = read(os.path.join(ROOT, 'docs', 'operations.md'))
        self.assertNotIn('`--secret -`', text)


class Agents(unittest.TestCase):
    def test_enroll_api_says_team(self):
        from acmelib.certs import api_agents  # noqa: F401 - the route takes `team`
        src = read(os.path.join(ROOT, 'acmelib', 'certs', 'api_agents.py'))
        self.assertIn("team=A._text(b, 'team'", src)
        doc = read(os.path.join(ROOT, 'docs', 'target-agent.md'))
        self.assertIn('{title, mode, port, days, most, auto, team}', doc)


if __name__ == '__main__':
    unittest.main(verbosity=2)
