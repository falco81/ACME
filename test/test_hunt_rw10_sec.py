#!/usr/bin/env python3
"""Hunt 1.0.144, run w10, area sec: a security review of everything changed since 1.0.143.

What was found and fixed:

- the webhook's More headers are kept sealed as a secret since 1.0.143 - but a receiver that
  refused the request and echoed a header back ("X-Tenant t0p-s3cret is not ours") put its value
  into the error: the job's words, the target's and the deployment's last error, the notices -
  for every viewer. sent_secrets() knew a secret only by a header's name (Authorization,
  X-Api-Key...); the values of the module's own secret settings (each line of More headers,
  what follows its "Name:") are taken out of the error too now (HttpTarget.own_secrets);
- the HTTPS test's More headers (sealed too): a line that was not "Name: value" - a token pasted
  on a line of its own - was quoted whole in the test's result; it is named by its line now.

    python3 test/test_hunt_rw10_sec.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from acmelib.plugins.base import PluginError                    # noqa: E402
from acmelib.plugins.targets.webhook import WebhookTarget       # noqa: E402
from acmelib.plugins.checks.tls import HttpsCheck               # noqa: E402

SECRET1 = 'tenant-zz-secret-1'
SECRET2 = 'zz-two-secret-2'
TOKEN = 'tok-ZZ-9f8e7d6c5b'


class EchoCtx(object):
    """A receiver that refuses and says back what it was sent."""

    def __init__(self, status=400):
        self.status = status

    def debug(self, *a, **k):
        pass

    def step(self, *a, **k):
        pass

    def http(self, method, url, body=None, headers=None, **kw):
        said = ' '.join('%s=%s' % (k, v) for k, v in sorted((headers or {}).items()))
        return self.status, {}, ('{"error": "refused - %s"}' % said).encode()


class WebhookEcho(unittest.TestCase):
    def target(self, headers, secret=''):
        cfg = {'url': 'https://hooks.example.test/x', 'headers': headers}
        if secret:
            cfg['secret'] = secret
        return WebhookTarget(cfg, EchoCtx())

    def said(self, t):
        with self.assertRaises(PluginError) as e:
            t.test()
        return str(e.exception) + '\n' + str(getattr(e.exception, 'detail', '') or '')

    def test_any_header_name(self):
        got = self.said(self.target('X-Tenant: %s\nX-Other: Bearer %s' % (SECRET1, SECRET2)))
        self.assertNotIn(SECRET1, got)
        self.assertNotIn(SECRET2, got)
        self.assertIn('the device said 400', got)
        self.assertIn('X-Tenant=', got)            # the rest of the answer as it was

    def test_old_list(self):
        # kept as a list before 1.0.143, not opened yet
        got = self.said(self.target(['X-Tenant: %s' % SECRET1]))
        self.assertNotIn(SECRET1, got)

    def test_signing_secret_and_named_header(self):
        got = self.said(self.target('Authorization: Bearer %s' % TOKEN, secret='sign-zz-key-77'))
        self.assertNotIn(TOKEN, got)

    def test_nothing_secret_left_as_it_was(self):
        # a module without the secrets set: the answer is not touched
        t = WebhookTarget({'url': 'https://hooks.example.test/x'}, EchoCtx())
        self.assertEqual(t.own_secrets(), set())
        got = self.said(t)
        self.assertIn('X-Acme-Event=ping', got)

    def test_short_values_not_taken(self):
        t = self.target('X-A: 1\nX-B: abc')
        self.assertFalse({'1', 'abc'} & t.own_secrets())


class HttpsCheckHeaders(unittest.TestCase):
    def test_bad_line_by_its_number(self):
        t = HttpsCheck({'http': True, 'headers': 'X-A: 1\nBearer %s' % TOKEN}, None)
        with self.assertRaises(PluginError) as e:
            t.http_lines('a.example.test', 443)
        self.assertNotIn(TOKEN, str(e.exception))
        self.assertIn('line 2 of More headers is not a header', str(e.exception))

    def test_good_lines_as_before(self):
        t = HttpsCheck({'http': True, 'headers': 'X-A: 1\nAuthorization: Bearer %s' % TOKEN},
                       None)
        lines = t.http_lines('a.example.test', 443)[0]
        self.assertIn('Authorization: Bearer %s' % TOKEN, lines)


if __name__ == '__main__':
    unittest.main(verbosity=2)
