# -*- coding: utf-8 -*-
"""HTTP-01 answered by this server itself: its nginx on port 80 serves
/.well-known/acme-challenge/<token> (web/acme.php reads meta acme:chal:<token>)."""
from __future__ import annotations

import binascii
import os

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import HttpChallenge, as_list


class HttpLocal(HttpChallenge):
    kind = 'http_local'
    title = 'HTTP-01 on this server'
    vendor = 'HTTP'
    description = ('The CA fetches http://NAME/.well-known/acme-challenge/… from acme itself, on '
                   'port 80 - the name must point at acme (or a proxy that sends that path to '
                   'it). Not for wildcards.')
    fields = [
        field('self_check', 'Check before the CA is asked', 'bool', default=False,
              help='Fetch http://NAME/.well-known/acme-challenge/TOKEN from here first. Off '
                   'where this machine cannot reach its own public name (no hairpin NAT).'),
        field('test_url', 'Address tried by Test', 'text', default='http://127.0.0.1',
              advanced=True,
              help='Where Test fetches a probe token from: this machine\'s nginx on port 80.'),
        field('public_addresses', 'Addresses in front of acme', 'list', default='',
              advanced=True, placeholder='198.51.100.7',
              help='Where the names point when acme is not reached at its own addresses: a '
                   'NAT, a port forward or a proxy that sends port 80 to acme. The guide '
                   'takes a name pointing at one of these as pointing at acme.'),
    ]

    # A commercial CA's DCV file (/.well-known/pki-validation/...) is answered here too:
    # nginx sends that path to acme.php as it does the ACME tokens (deploy/nginx-acme.conf).
    proofs = ('http-file-any',)
    DCV_DAYS = 30

    @classmethod
    def place_problem(cls, proof, where, config, settings):
        bad = HttpChallenge.place_problem.__func__(cls, proof, where, config, settings)
        if bad or proof != 'http-file-any':
            return bad
        if not str(where or '/.well-known/pki-validation/').startswith(
                '/.well-known/pki-validation/'):
            return ('this server answers only /.well-known/acme-challenge/ and '
                    '/.well-known/pki-validation/, not %s' % where)
        return ''

    def place_file(self, name, path, data):
        if not path.startswith('/.well-known/pki-validation/'):
            raise PluginError('this server answers only /.well-known/pki-validation/ for a CA\'s '
                              'DCV file, not %s' % path, retry=False)
        put = getattr(self.ctx, 'http_file_put', None)
        if not callable(put):
            raise PluginError('this version of acme cannot answer a DCV file', retry=False)
        put(name, path, data.decode('utf-8'), self.DCV_DAYS * 86400)
        return {'host': name, 'path': path}

    def unplace_file(self, handle):
        drop = getattr(self.ctx, 'http_file_drop', None)
        if callable(drop):
            drop(handle.get('name'), handle.get('path'))

    def dcv_self_check(self):
        return self.flag('self_check')

    def present(self, name, token, key_authorization, txt_value):
        n = self.check_name(name)
        self.check_token(token)
        self.ctx.http_token_put(token, key_authorization)
        self.ctx.step('http://%s/.well-known/acme-challenge/%s is answered by acme' % (n, token))
        return {'token': token, 'ka': key_authorization, 'name': n}

    def ready(self, name, handle):
        handle = handle or {}
        if not self.flag('self_check'):
            return True
        ok, words = self.fetch('http://%s/.well-known/acme-challenge/%s' % (
            handle.get('name') or name, handle.get('token')), handle.get('ka'))
        self.ctx.step(words, 'ok' if ok else 'info')
        return ok

    def cleanup(self, name, handle):
        handle = handle or {}
        if handle.get('token'):
            try:
                self.ctx.http_token_drop(handle['token'])
            except Exception as e:                      # noqa: BLE001
                self.ctx.step('the token could not be taken away: %s' % e, 'warn')

    def test(self):
        token = 'acme-probe-' + binascii.hexlify(os.urandom(8)).decode()
        ka = token + '.' + binascii.hexlify(os.urandom(8)).decode()
        base = str(self.c('test_url', 'http://127.0.0.1')).rstrip('/')
        self.ctx.http_token_put(token, ka)
        try:
            ok, words = self.fetch('%s/.well-known/acme-challenge/%s' % (base, token), ka)
        finally:
            try:
                self.ctx.http_token_drop(token)
            except Exception:                           # noqa: BLE001
                pass
        if not ok:
            raise PluginError('this server does not answer a probe token: %s - is nginx '
                              'serving /.well-known/acme-challenge/ on port 80?' % words)
        return words + ' (a probe token, taken away again)'

    # -- what a person is told ---------------------------------------------------------
    def answering(self, name):
        own = self.ctx.own_addresses() or {}
        out = []
        for a in ([own.get('vip')] if own.get('vip') else []) + list(own.get('nodes') or []):
            if a and a not in out:
                out.append(str(a))
        return out

    def guide(self, name):
        bad = self.guide_wildcard(name)
        if bad:
            return guide_of(bad)
        n = D.norm(name)
        own = self.answering(name)
        front = as_list(self.c('public_addresses', ''))
        want = front + [a for a in own if a not in front]
        # acme known only by private addresses, the name public: a NAT may well be in
        # front - said, but no reason to keep the CA from asking
        got, _inside = self.ca_view(n)
        soft = not front and bool(own) and all(_private(a) for a in own) and \
            any(not _private(a) for a in got)
        steps = [self.guide_points(
            n, want, (front or own or [''])[0],
            'Point %s at acme (%s) - or, when a NAT or a proxy in front of acme sends port 80 '
            'to it, put that address under "Addresses in front of acme"' % (
                n, ', '.join(want) or 'its address'), soft=soft)]
        fw = self.ctx.port_open('tcp', int(self.http_port))
        steps.append(guide_step(
            'port80', 'The firewall of acme lets port %d in from anywhere' % int(self.http_port),
            where='acme', done=fw, blocking=fw is False,
            said={True: 'it is let in', False: 'it is not let in from anywhere',
                  None: 'acme\'s firewall cannot be asked from here'}[fw],
            fix='Settings → Firewall: let TCP port %d in from anywhere - the CA asks from the '
                'internet' % int(self.http_port)))
        probe = self.ctx.http_probe()
        if probe:
            token, ka = probe
            for addr in own[:4]:
                ok, words = self.fetch(self.url(addr, token), ka, host=n)
                steps.append(guide_step(
                    'probe', 'acme answers /.well-known/acme-challenge/ on port %d of %s'
                    % (int(self.http_port), addr), where='acme', done=ok, said=words,
                    fix='Is nginx of acme serving port %d? (Settings → Certificates and TLS)'
                        % int(self.http_port)))
            ok, words = self.fetch(self.url(n, token), ka)
            steps.append(guide_step(
                'by_name', 'A probe is served at http://%s/' % n, where=n, done=ok, said=words,
                blocking=False,
                fix='From here the name does not reach acme - the CA asks from the internet, '
                    'where it may: the dry run says more'))
            if ok:
                # the name reaches acme: wherever it points, it works
                steps[0]['blocking'] = False
        return guide_of(steps)


def _private(addr):
    import ipaddress
    try:
        ip = ipaddress.ip_address(str(addr))
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local
