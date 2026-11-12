# -*- coding: utf-8 -*-
"""
An application of ours - otp, isemon, zigmon, another acme - that takes its
certificates from acme over "acme push" (docs/acme-push-protocol.md): the
application's own Settings → Certificates and TLS → Certificates from acme.

    pairing     the application shows a one-time pairing code; it goes into
                "Pairing code" here, and Try (or the first deployment) pairs the
                two: the application keeps acme's Ed25519 key, acme keeps the
                application's id and X25519 key (each proved to the other by the
                code). Or acme's key, pasted in the application (Try says it).
    discovery   Discover asks the application which slots it has (each node's
                pages, the VIP address's, a server in front, a broker...) and
                what is in them; Certificates → Discover makes the certificates
                and the deployments for them.
    a deploy    the certificate, its chain and its key - the key sealed to the
                application's X25519 key (X25519 + HKDF-SHA256 + AES-256-GCM),
                the request signed - put into the slots asked for; then a TLS
                handshake to each slot's name says it is served.
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse

from acmelib import engine as E
from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, as_int, fp_of, text, alt_of, check_served,
    split_hostport)

SLOT_WORDS = {'auto': 'every slot whose names the certificate holds',
              'nodes': 'the pages of every node', 'vip': 'the VIP address',
              'this': 'the node that answers'}
MANAGED_WORDS = {'manual': 'put in by hand', 'own-acme': 'its own ACME (Automatic certificates)',
                 'acme-push': 'acme (acme push)', 'none': 'nothing yet'}


def _when(ts):
    try:
        return time.strftime('%Y-%m-%d', time.gmtime(float(ts))) if ts else '?'
    except (TypeError, ValueError):
        return '?'


class AcmePushTarget(HttpTarget):
    kind = 'acme_push'
    discovery = False       # nothing to find: its fields are the pairing itself
    title = 'An application of ours (acme push: otp, isemon, zigmon, acme)'
    vendor = 'acme'
    default_name = 'app'
    description = ('The certificate put on another application of ours - its nodes, its VIP '
                   'address, its server in front - through its Certificates and TLS, '
                   'over HTTPS with a signed request and the key sealed to the application. '
                   'Discover tells which certificates it needs.')
    doc = 'acme-push-protocol.md'
    dual = True
    fields = [
        field('url', 'Address of its administration', 'text', required=True,
              placeholder='https://otp.example.com/admin/',
              help='as you open it in a browser: https://NAME/admin/ for otp and acme, '
                   'https://NAME/ for isemon and zigmon. acme must be among the addresses '
                   'that may reach those pages there.'),
        field('pair_code', 'Pairing code', 'secret',
              help='Shown by the application at Settings → Certificates and TLS → '
                   'Certificates from acme → Pair (15 minutes, once). Try pairs them; after '
                   'that it is not needed.'),
        field('verify_tls', 'Check the application\'s certificate', 'bool', default=True,
              help='off only while it still has a self-signed one - the pairing code '
                   'still proves who answers, and the key travels sealed to it'),
        field('ca_pem', 'CA certificate', 'pem', advanced=True,
              help='the CA of the application\'s current certificate, when not a public one'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('slots', 'Slots', 'list', default='auto', picker='push_slots',
              placeholder='auto\nnode:otp1\nvip',
              help='Where on the application the certificate goes: auto (each slot whose '
                   'names the certificate holds), nodes, vip, this, or the slots themselves - '
                   'Find the slots asks the application for them (node:otp1, vip, front, '
                   'broker...). On the command line one a line.'),
        field('check_names', 'The certificate must hold the slot\'s names', 'bool',
              default=True, advanced=True,
              help='off is taken only where the application allows it (Certificates from '
                   'acme → Take certificates of other names)'),
        field('verify_served', 'Check that it is served', 'bool', default=True,
              advanced=True,
              help='a TLS handshake to each slot\'s name (SNI) after the push, until the '
                   'new certificate is served'),
        field('verify', 'Check these instead', 'list', advanced=True,
              placeholder='otp1.example.com:443',
              help='host:port, one a line; empty: the names of the slots it went to'),
    ]
    actions = [{'key': 'discover', 'label': 'Discover',
                'help': 'Which certificates the application has, and needs - changes nothing',
                'changes': False}]

    # -- addresses ------------------------------------------------------------------------
    def ident(self):
        return self.base_url()

    def base_url(self):
        u = text(self.c('url')).strip()
        if not re.match(r'^https?://', u):
            u = 'https://' + u
        p = urllib.parse.urlsplit(u)
        if not p.hostname:
            raise PluginError('the address of the application is like '
                              'https://otp.example.com/admin/', retry=False)
        path = p.path or '/admin/'
        return urllib.parse.urlunsplit((p.scheme, p.netloc, path, p.query, ''))

    def endpoint(self, op):
        b = self.base_url()
        return b + ('&' if '?' in b else '?') + 'api=acme-push-' + op

    # -- talking ----------------------------------------------------------------------------
    def _call(self, op, body=None, app_id='', headers=None):
        url = self.endpoint(op)
        h = {'Accept': 'application/json'}
        raw = None
        if op != 'hello':
            raw = json.dumps(body or {}, sort_keys=True).encode('utf-8')
            me = self.ctx.push_identity()
            h.update(E.push_signed(me['seed'], op, app_id, raw, **(headers or {})))
            h['Content-Type'] = 'application/json'
        try:
            st, _hd, got = self.ctx.http(
                'GET' if op == 'hello' else 'POST', url, body=raw, headers=h,
                timeout=as_int(self.c('timeout', 30), 30),
                verify=as_bool(self.c('verify_tls', True), True),
                ca_pem=self.c('ca_pem') or None, proxy=False)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s cannot be reached: %s' % (self.base_url(), e))
        data = None
        try:
            data = json.loads((got or b'{}').decode('utf-8', 'replace'))
        except ValueError:
            pass
        if not isinstance(data, dict):
            words = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', text(got)))[:160].strip()
            raise PluginError('%s does not speak acme push (HTTP %s%s) - is the address that '
                              'of its administration, and is it a version that has '
                              '"Certificates from acme"?' % (url.split('?')[0], st,
                                                             ': ' + words if words else ''),
                              retry=st >= 500)
        if st >= 300 or not data.get('ok'):
            code = str(data.get('code') or '')
            raise PluginError('the application said %s%s: %s' % (
                st, ' (%s)' % code if code else '', data.get('error') or 'no'),
                detail=json.dumps(data)[:2000],
                retry=st >= 500 or code in ('stale', 'replay'))
        return data

    def hello(self):
        h = self._call('hello')
        if 1 not in (h.get('protocol') or []):
            raise PluginError('the application speaks acme push %s, acme speaks 1'
                              % h.get('protocol'), retry=False)
        if not h.get('on'):
            raise PluginError('%s (%s %s) takes no certificates from acme: switch it on at its '
                              'Settings → Certificates and TLS → Certificates from acme'
                              % (self.base_url(), h.get('app') or '?', h.get('version') or ''),
                              retry=False)
        for k in ('app_id', 'enc_key'):
            if not h.get(k):
                raise PluginError('the application\'s hello says no %s' % k, retry=False)
        return h

    def paired(self, h=None):
        """The application, paired: its hello and the pin acme keeps of it."""
        h = h or self.hello()
        pin = self.ctx.push_pin(self.base_url()) or {}
        me = self.ctx.push_identity()
        code = text(self.c('pair_code')).strip()
        if pin and pin.get('app_id') == h['app_id'] and pin.get('enc_key') == h['enc_key']:
            return h, pin
        if pin and not code:
            raise PluginError('the application at %s is not the one paired (its keys changed: '
                              'set up again, or somebody in between) - make a new pairing code '
                              'there and put it in "Pairing code"' % self.base_url(), retry=False)
        if code:
            return h, self.pair(h, code, me)
        # No code: maybe acme's key was pasted there - then a signed inventory answers.
        if not as_bool(self.c('verify_tls', True), True):
            # Not without TLS checked (1.0.51): nothing in the answer is signed by the
            # application, and anyone in between would be pinned as it - the private keys
            # sealed to them.
            raise PluginError('the first pairing without a pairing code needs "Check the application'
                              '\'s certificate" on: make a pairing code on the application and put it '
                              'in "Pairing code" here', retry=False)
        try:
            self._call('inventory', {}, h['app_id'])
        except PluginError as e:
            if '(unknown_key)' in str(e) or '(not_paired)' in str(e):
                raise PluginError('not paired yet: on the application make a pairing code '
                                  '(Settings → Certificates and TLS → Certificates from acme → '
                                  'Pair) and put it in "Pairing code" here - or paste this '
                                  'acme\'s key there: %s' % me['text'], retry=False)
            raise
        pin = {'app_id': h['app_id'], 'enc_key': h['enc_key'], 'how': 'first seen',
               'app': h.get('app'), 'at': int(time.time()), 'url': self.base_url()}
        self.ctx.push_pin(self.base_url(), pin)
        self.ctx.step('acme\'s key is taken there (pasted); the application\'s key %s is kept '
                      'as first seen' % E.push_key_id(E.push_unb64(h['enc_key'], 32))[:16], 'ok')
        return h, pin

    def pair(self, h, code, me):
        nonce = E.secrets.token_hex(16)
        body = {'acme_key': me['text'], 'acme_name': 'acme %s on %s' % (E.__version__,
                                                                        self.ctx.node or '?'),
                'proof': E.push_proof(code, 'pair', h['app_id'], me['id'], nonce)}
        got = self._call('pair', body, h['app_id'], headers={'nonce': nonce})
        want = E.push_proof(code, 'paired', h['app_id'], me['id'], nonce, got.get('enc_key'))
        if not E.hmac.compare_digest(want, str(got.get('confirm') or '')) or \
                got.get('app_id') != h['app_id']:
            raise PluginError('the answer to the pairing is not proved by the code - somebody '
                              'in between? Nothing is kept.', retry=False)
        if got.get('enc_key') != h['enc_key']:
            raise PluginError('the application\'s key in the pairing is not the one of its '
                              'hello - somebody in between? Nothing is kept.', retry=False)
        pin = {'app_id': h['app_id'], 'enc_key': h['enc_key'], 'how': 'pairing code',
               'app': h.get('app'), 'at': int(time.time()), 'url': self.base_url()}
        self.ctx.push_pin(self.base_url(), pin)
        self.ctx.step('paired with %s %s at %s (acme\'s key %s)' % (
            h.get('app'), h.get('version') or '', self.base_url(), me['id']), 'ok')
        return pin

    # -- discovery ----------------------------------------------------------------------------
    def inventory(self):
        h, pin = self.paired()
        inv = self._call('inventory', {}, pin['app_id'])
        keep = {'at': int(time.time()), 'app': inv.get('app'), 'version': inv.get('version'),
                'cluster': inv.get('cluster'), 'slots': inv.get('slots') or []}
        self.ctx.kv_set('inventory', keep)
        return keep

    @staticmethod
    def slot_line(s):
        cur = s.get('current') or {}
        words = '%s: %s' % (s.get('id'), ', '.join(s.get('names') or []) or 'no name')
        if cur:
            words += ' - has %s until %s (%s)' % (', '.join(cur.get('names') or [])[:80] or '?',
                                                 _when(cur.get('not_after')),
                                                 MANAGED_WORDS.get(s.get('managed_by'),
                                                                   s.get('managed_by')))
        else:
            words += ' - nothing yet'
        if str(s.get('managed_by') or '').startswith('follows:'):
            words += ' - follows %s by itself' % s['managed_by'][8:]
        if not s.get('installable', True):
            words += ' - cannot be put in: %s' % (s.get('why_not') or '?')
        return words

    def action(self, key):
        if key != 'discover':
            return HttpTarget.action(self, key)
        inv = self.inventory()
        for s in inv['slots']:
            self.ctx.step(self.slot_line(s))
        return '%d slot(s) at %s %s' % (len(inv['slots']), inv.get('app') or '?',
                                        self.base_url())

    def test(self):
        h, pin = self.paired()
        inv = self._call('inventory', {}, pin['app_id'])
        slots = inv.get('slots') or []
        self.ctx.kv_set('inventory', {'at': int(time.time()), 'app': inv.get('app'),
                                      'version': inv.get('version'),
                                      'cluster': inv.get('cluster'), 'slots': slots})
        return '%s %s answers, paired (%s); slots: %s' % (
            h.get('app'), h.get('version') or '', pin.get('how'),
            '; '.join(self.slot_line(s) for s in slots) or 'none')

    # -- the contract ---------------------------------------------------------------------------
    def _sealed(self, b, pin):
        enc = E.push_unb64(pin['enc_key'], 32)
        fp = fp_of(b)
        return {'cert_pem': b.cert_pem, 'chain_pem': ''.join(
            text(p).strip() + '\n' for p in (b.chain_pems or []) if text(p).strip()),
            'fingerprint': fp, 'key': E.push_seal_key(text(b.key_pem), enc, pin['app_id'], fp),
            'key_type': getattr(b, 'key_type', '') or ''}

    def deploy(self, bundle, options):
        options = options or {}
        if not text(bundle.key_pem).strip():
            raise PluginError('the certificate has no private key here to put there',
                              retry=False)
        h, pin = self.paired()
        body = self._sealed(bundle, pin)
        body.update(slots=lines(self.opt(options, 'slots', 'auto')) or ['auto'],
                    names=list(bundle.names or []), not_after=bundle.not_after,
                    check_names=as_bool(self.opt(options, 'check_names', True), True),
                    force=as_bool(options.get('force')))
        alt = alt_of(bundle)
        if alt is not None:
            body['alt'] = self._sealed(alt, pin)
        got = self._call('install', body, pin['app_id'])
        self._installed = got.get('installed') or []
        for one in self._installed:
            self.ctx.step('%s (%s): %s' % (one.get('slot'), ', '.join(one.get('names') or [])
                                           or '-', 'already there' if one.get('state') ==
                                           'already' else 'put in'),
                          'ok')
        return got.get('said') or 'pushed'

    def verify(self, bundle, options):
        options = options or {}
        if lines(options.get('verify')):
            return HttpTarget.verify(self, bundle, options)
        if not as_bool(self.opt(options, 'verify_served', True), True):
            return None
        names = []
        for one in getattr(self, '_installed', None) or []:
            names += [n for n in (one.get('names') or []) if n and not n.startswith('*')]
        names = list(dict.fromkeys(names))
        if not names:
            return None
        out = True
        for n in names:
            host, port = split_hostport(n, 443)
            seen = check_served(self.ctx, bundle, ['%s:%d' % (host, port)], sni=host,
                                tries=as_int(options.get('verify_tries', 6), 6),
                                wait=float(options.get('verify_wait', 3) or 3),
                                sleep=getattr(self, '_sleep', time.sleep))
            if seen is False:
                return False
            if seen is None:
                out = None if out is True else out
        return out
