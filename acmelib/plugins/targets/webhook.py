# -*- coding: utf-8 -*-
"""
A webhook: the certificate POSTed to a URL as JSON or multipart, signed with
an HMAC header so the receiver can tell it came from acme. A dual certificate:
the twin as "alt" in the JSON (its own cert_pem, chain_pem, fullchain_pem,
key_type...), and as files fmt@alt in a multipart body.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, fp_of, multipart, label_of, text,
    tls_fields, verify_fields, PFX_FORMATS, alt_of, variant_of)


def sign(secret, ts, body):
    """sha256=<hex of HMAC-SHA256(secret, "<timestamp>." + body)>"""
    mac = hmac.new(secret.encode(), str(ts).encode() + b'.' + body, hashlib.sha256)
    return 'sha256=' + mac.hexdigest()


class WebhookTarget(HttpTarget):
    kind = 'webhook'
    title = 'Webhook'
    vendor = 'Generic'
    description = ('POSTs the certificate to a URL - JSON or multipart - with an HMAC '
                   'signature header, for anything acme has no module for.')
    doc = 'targets.md'
    dual = True             # a dual certificate: the twin as "alt" in the body
    fields = [
        field('url', 'URL', 'text', required=True, placeholder='https://hooks.example.com/cert'),
        field('secret', 'Signing secret', 'secret',
              help='X-Acme-Signature: sha256=HMAC(secret, timestamp + "." + body)'),
        field('headers', 'More headers', 'list', advanced=True,
              placeholder='Authorization: Bearer …'),
        field('include_key', 'Send the private key', 'bool', default=False,
              help='off: only the certificate and chain leave acme'),
    ] + tls_fields(proxy=True)
    deploy_fields = [
        field('body', 'Body', 'select', default='json',
              options=[['json', 'JSON'], ['multipart', 'multipart/form-data (files)']]),
        field('formats', 'Files (multipart)', 'list', default='fullchain-pem\nkey-pem',
              show_if={'body': ['multipart']},
              help='formats, one a line; key formats only when the target sends keys'),
        field('pfx_password', 'PKCS#12 password', 'secret', advanced=True),
        field('extra', 'Extra JSON fields', 'textarea', advanced=True, placeholder='{"env": "prod"}'),
    ] + verify_fields()

    def ident(self):
        return self.c('url')

    def base_url(self):
        return text(self.c('url')).rstrip('/')

    def headers(self, body):
        h = {'User-Agent': 'acme', 'X-Acme-Event': 'certificate'}
        for line in lines(self.c('headers')):
            k, _, v = line.partition(':')
            if k.strip() and v.strip():
                h[k.strip()] = v.strip()
        ts = int(time.time())
        h['X-Acme-Timestamp'] = str(ts)
        if self.c('secret'):
            h['X-Acme-Signature'] = sign(self.c('secret'), ts, body)
        return h

    def payload(self, bundle, options):
        key = as_bool(self.c('include_key'))
        d = {'event': 'certificate.deployed', 'name': bundle.name,
             'names': list(bundle.names or []), 'serial': bundle.serial,
             'fingerprint': fp_of(bundle), 'not_before': bundle.not_before,
             'not_after': bundle.not_after, 'cert_pem': bundle.cert_pem,
             'chain_pem': ''.join(bundle.chain_pems or []),
             'fullchain_pem': bundle.fullchain_pem}
        if key:
            d['key_pem'] = text(bundle.key_pem)
        alt = alt_of(bundle)
        if alt is not None:
            d['key_type'] = getattr(bundle, 'key_type', '')
            d['alt'] = {'key_type': getattr(alt, 'key_type', ''), 'serial': alt.serial,
                        'fingerprint': fp_of(alt), 'not_before': alt.not_before,
                        'not_after': alt.not_after, 'cert_pem': alt.cert_pem,
                        'chain_pem': ''.join(alt.chain_pems or []),
                        'fullchain_pem': alt.fullchain_pem}
            if key:
                d['alt']['key_pem'] = text(alt.key_pem)
        extra = (options.get('extra') or '').strip()
        if extra:
            try:
                d['extra'] = json.loads(extra)
            except ValueError:
                raise PluginError('the extra JSON fields are not JSON', retry=False)
        return d, key

    def test(self):
        body = json.dumps({'event': 'ping', 'from': 'acme'}).encode()
        h = self.headers(body)
        h['X-Acme-Event'] = 'ping'
        h['Content-Type'] = 'application/json'
        st, hd, d = self.req('POST', self.base_url(), body, h, what='pinging the webhook')
        return 'the webhook answered %d' % st

    def deploy(self, bundle, options):
        options = options or {}
        if self.unchanged(bundle, options):
            return self.same(bundle, 'sent')
        d, key = self.payload(bundle, options)
        if (options.get('body') or 'json') == 'multipart':
            parts = [(k, json.dumps(v) if isinstance(v, (list, dict)) else text(v))
                     for k, v in d.items() if not k.endswith('_pem') and k != 'alt']
            name = label_of(bundle, options)
            fmts = lines(self.opt(options, 'formats'))
            if alt_of(bundle) is not None:
                fmts += [f + '@alt' for f in fmts if '@' not in f]
            for fmt in fmts:
                base, _, which = fmt.partition('@')
                if base not in bundle.FORMATS:
                    raise PluginError('not a format: %s' % fmt, retry=False)
                if not key and (base.startswith('key') or base in PFX_FORMATS or
                                base == 'combined-pem'):
                    raise PluginError('%s holds the private key, and this webhook does not '
                                      'send keys' % fmt, retry=False)
                one = variant_of(bundle, which)
                if one is None:
                    raise PluginError('%s: the certificate has no such one' % fmt, retry=False)
                data = one.as_format(base, password=options.get('pfx_password') or None,
                                     alias=name)
                parts.append((fmt, ('%s.%s' % (name, fmt), data, 'application/octet-stream')))
            body, ctype = multipart(parts)
        else:
            body, ctype = json.dumps(d).encode(), 'application/json'
        h = self.headers(body)
        h['Content-Type'] = ctype
        st, hd, r = self.req('POST', self.base_url(), body, h, what='posting to the webhook')
        self.remember(bundle, options)
        return 'posted to %s (%d)' % (self.base_url().split('?')[0], st)
