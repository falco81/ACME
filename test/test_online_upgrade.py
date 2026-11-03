#!/usr/bin/env python3
"""New versions from the web: Settings → Upgrades → Look now (1.0.36).

    python3 test/test_online_upgrade.py

GitHub is played by the test. Its raw.githubusercontent.com keeps a branch's file
5 minutes: just after a release the branch's index.json is the one before it. The
look asks the API for the branch's newest commit and reads the index of that commit -
the new version is found at once; without the API, the branch's index as before.
"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-online-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402

SHA = 'cb70936629cecede2729fef89a2d72f7311e0bdf'
URL = 'https://github.com/falco81/ACME/tree/main/release'


def index(*versions):
    return json.dumps([{'name': 'acme-%s.tar.gz' % v, 'version': v, 'size': 1, 'sha256': '0' * 64,
                        'download_url': 'https://raw.githubusercontent.com/falco81/ACME/main/release/'
                                        'acme-%s.tar.gz' % v} for v in versions]).encode()


class TestLook(unittest.TestCase):
    def play(self, api_up=True):
        asked = []

        def get(url, limit=0, accept='*/*', timeout=30):
            asked.append(url)
            if url.startswith('https://api.github.com/repos/falco81/ACME/commits/'):
                if not api_up:
                    raise ValueError('rate limited')
                return SHA.encode(), 'text/plain', url
            if url == 'https://raw.githubusercontent.com/falco81/ACME/%s/release/index.json' % SHA:
                return index('9.0.1', '9.0.0'), 'application/json', url
            if url == 'https://raw.githubusercontent.com/falco81/ACME/main/release/index.json':
                return index('9.0.0'), 'application/json', url        # the stale one
            raise ValueError('not played: %s' % url)
        was = E._online_get
        E._online_get = get
        try:
            return E.online_list(URL), asked
        finally:
            E._online_get = was

    def test_the_new_one_at_once(self):
        got, asked = self.play()
        self.assertEqual([g['version'] for g in got], ['9.0.1', '9.0.0'])
        self.assertTrue(any('/commits/main' in a for a in asked))
        self.assertEqual(got[0]['sha256'], '0' * 64)

    def test_without_the_api_the_branch(self):
        got, _asked = self.play(api_up=False)
        self.assertEqual([g['version'] for g in got], ['9.0.0'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
