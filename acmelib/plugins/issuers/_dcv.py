# -*- coding: utf-8 -*-
"""A commercial CA's domain validation (DCV) put in place by the certificate's
own validations - what DigiCert's and SSLmarket's modules share (the name
starts with "_": the registry does not take it for a module).

A CA that is not ACME asks for records of its own shape - DigiCert a TXT at
NAME or _dnsauth.NAME holding a random value, a CNAME _dnsauth.NAME to
VALUE.dcv.digicert.com, or the file /.well-known/pki-validation/fileauth.txt;
Sectigo (SSLmarket) a TXT/CNAME of its own or a file. Every validation that can
put any record or file in place says so (base.Challenge.proofs_for, place,
placed_ready, unplace); acmelib/certs/compat.py refuses a pairing that cannot
before anything is ordered. Here the records are put in place:

    recs = [{'domain': 'example.com', 'type': 'txt' | 'cname' | 'file',
             'fqdn': '_dnsauth.example.com' (txt, cname) | 'path': '/.well-known/...' (file),
             'value': 'the random value' (txt, file) | 'target.dcv.digicert.com' (cname)}]
    p = Placer(issuer)                         issuer: its ctx, c('wait_ready'), _sleep
    placed = p.place_all(req, recs)            [{'rec', 'name', 'how', 'handle', 'kind'}] -
                                               JSON, kept with the pending order
    p.wait_visible(req, placed)                until each can be seen (wait_ready s at most)
    p.refresh(req, placed)                     a later run: what went away with the job put
                                               back (acme's own DNS server keeps a job's
                                               records only while it runs)
    p.cleanup(req, placed)                     taken away again, quietly

`how` is 'placed' (by the validation's place()), or 'manual' (no validation of
the certificate can: the record is said in the job, for a person to create).
"""
from __future__ import annotations

import time

from acmelib.plugins.base import PluginError

# Validations whose records do not outlive the job that put them in place.
SHORT_LIVED = ('dns_builtin',)


def base_of(name):
    n = str(name or '').strip().lower().rstrip('.')
    return n[2:] if n.startswith('*.') else n


def record_words(rec):
    if rec.get('type') == 'file':
        return 'http://%s%s holding "%s"' % (rec.get('domain'), rec.get('path'), rec.get('value'))
    return '%s. %s "%s"' % (rec.get('fqdn'), str(rec.get('type') or '').upper(), rec.get('value'))


class Placer(object):
    def __init__(self, issuer):
        self.issuer = issuer
        self.ctx = issuer.ctx

    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                               # noqa: BLE001
            pass

    def _sleep(self, s):
        fn = getattr(self.issuer, '_sleep', None) or time.sleep
        fn(s)

    def _num(self, key, default):
        try:
            return float(self.issuer.c(key) or default)
        except (TypeError, ValueError):
            return float(default)

    # -- which validation of the certificate puts a domain's record in place ---------------
    @staticmethod
    def challenge_for(req, domain):
        """(name, Challenge) of the certificate that proves `domain` (its own name,
        its wildcard, else the closest name under or above it), or (None, None)."""
        ch = getattr(req, 'challenges', None) or {}
        for n in (domain, '*.' + domain):
            if n in ch:
                return n, ch[n]
        best = None
        for n, c in ch.items():
            b = base_of(n)
            if domain == b or domain.endswith('.' + b) or b.endswith('.' + domain):
                if best is None or len(b) > len(base_of(best[0])):
                    best = (n, c)
        return best if best else (None, None)

    def _one(self, req, rec):
        name, ch = self.challenge_for(req, rec['domain'])
        where = rec.get('path') if rec['type'] == 'file' else rec.get('fqdn')
        if ch is None:
            return {'rec': rec, 'name': name, 'how': 'manual', 'handle': None, 'kind': '',
                    'why': 'no validation of the certificate is for %s' % rec['domain']}
        try:
            h = ch.place(rec['type'], rec['domain'] if rec['type'] == 'file' else (name or
                                                                                   rec['domain']),
                         where, rec['value'])
        except NotImplementedError as e:
            return {'rec': rec, 'name': name, 'how': 'manual', 'handle': None,
                    'kind': getattr(ch, 'kind', ''), 'why': str(e) or 'it cannot'}
        return {'rec': rec, 'name': name, 'how': 'placed', 'handle': h,
                'kind': getattr(ch, 'kind', '')}

    def place_all(self, req, recs):
        placed = []
        try:
            for rec in recs or []:
                p = self._one(req, rec)
                if p['how'] == 'manual':
                    self._say('put in place by hand, for the CA: %s (%s)' % (
                        record_words(rec), p.get('why')), 'warn')
                placed.append(p)
        except PluginError:
            self.cleanup(req, placed)
            raise
        return placed

    def refresh(self, req, placed):
        for p in placed or []:
            if p.get('how') == 'placed' and p.get('kind') in SHORT_LIVED:
                try:
                    q = self._one(req, p['rec'])
                    if q['how'] == 'placed':
                        p['handle'] = q['handle']
                except PluginError as e:
                    self._say('the DCV record of %s could not be put back: %s'
                              % (p['rec']['domain'], e), 'warn')

    def _module(self, req, p):
        _n, ch = self.challenge_for(req, p['rec']['domain'])
        if ch is None or (p.get('kind') and getattr(ch, 'kind', '') != p.get('kind')):
            # the names changed since: a module of the same kind takes it away
            ch = next((c for c in (getattr(req, 'challenges', None) or {}).values()
                       if getattr(c, 'kind', '') == p.get('kind')), ch)
        return ch

    def wait_visible(self, req, placed, wait=None):
        end = time.time() + (self._num('wait_ready', 300) if wait is None else float(wait))
        todo = [p for p in placed or [] if p.get('how') == 'placed']
        while todo:
            left = []
            for p in todo:
                ch = self._module(req, p)
                try:
                    ok = ch is None or bool(ch.placed_ready(p['handle']))
                except PluginError as e:
                    self._say('whether the DCV record is visible could not be told: %s' % e,
                              'warn')
                    ok = True
                except Exception as e:                  # noqa: BLE001
                    self.ctx.debug('placed_ready: %s' % e)
                    ok = False
                if not ok:
                    left.append(p)
            todo = left
            if not todo or time.time() >= end or self.ctx.cancelled():
                break
            self._sleep(min(10, max(1, end - time.time())))
        if todo:
            self._say('the DCV record of %s is not visible yet - the CA checks again by itself'
                      % ', '.join(p['rec']['domain'] for p in todo), 'warn')
        return not todo

    def cleanup(self, req, placed):
        for p in placed or []:
            if p.get('how') != 'placed':
                continue
            ch = self._module(req, p)
            if ch is None:
                self._say('the DCV record of %s is left (no validation module of kind %s here) '
                          '- take it away by hand' % (p['rec']['domain'], p.get('kind') or '?'),
                          'warn')
                continue
            try:
                ch.unplace(p['handle'])
            except Exception as e:                      # noqa: BLE001
                self._say('the DCV record of %s could not be taken away: %s'
                          % (p['rec']['domain'], e), 'warn')
