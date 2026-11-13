# -*- coding: utf-8 -*-
"""
Kemp / Progress LoadMaster through its RESTful API (the JSON form, APIv2,
LoadMaster 7.2.50 and later): the certificate added under a dated name, the
intermediates added once, the virtual services asked for pointed at it,
older acme ones deleted.

    POST https://<lm>/accessv2   {"cmd": "listcert", "apikey": ...}
                                 {"cmd": "addcert", "cert": NAME, "replace": 0,
                                  "data": base64(full chain + key)}
                                 {"cmd": "addintermediate", "cert": NAME, "data": ...}
                                 {"cmd": "modvs", "vs": IP, "port": PORT, "prot": "tcp",
                                  "CertFile": NAME}
                                 {"cmd": "delcert", "cert": NAME}
    (sign-in with "apikey", or "apiuser" + "apipass")

Rights: System Configuration → Remote Access → Enable API Interface; an API
key (Certificates & Security → API keys) or a user with the Certificate
Creation and Virtual Services rights.

Sources:
    https://docs.progress.com/bundle/loadmaster-technical-note-restful-api-programmer-guide-ga/page/Introduction.html
    https://docs.progress.com/bundle/loadmaster-interface-description-restful-api-ga/page/Certificates-and-Security.html
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/kemplm.sh
Checked against api-docs/kemp/notes.md and its two Postman collections
(loadmaster_restful_apiv1/apiv2.postman_collection.json): "modvs ... CertFile"
takes "the entire list of certificates required for the VS", so the list the
virtual service has ("showvs") is kept and only acme's older one in it is
swapped; "the connection drops if more than 30 calls are performed in less
than 3 seconds", so acme makes at most 25 in any 3 seconds.
Uncertain: "addintermediate" and the answer of "listcert" ("cert": [{"name"}])
are taken from the APIv1 descriptions written as JSON; the collection's
examples show the "CertFile" of showvs as a hash-like value - when the list
holds anything that is not a certificate's name, acme cannot keep it and sets
its own alone (as before), saying so.
"""
from __future__ import annotations

import base64
import re
import time

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, text, chain_list, chain_id, ours)

# "The connection drops if more than 30 calls are performed in less than 3
# seconds over all API interfaces." - acme stays below it.
RATE_CALLS, RATE_WINDOW = 25, 3.0


class KempTarget(HttpTarget):
    kind = 'kemp'
    discovery = False       # nothing to find: its fields are the sign-in
    title = 'Kemp / Progress LoadMaster'
    vendor = 'Progress Kemp'
    description = ('Adds the certificate through the LoadMaster REST API under a new name, '
                   'points the virtual services at it and deletes the older ones.')
    doc = 'targets.md'
    fields = http_fields(443, 'lm.example.local') + [
        field('auth', 'Sign in with', 'select', default='apikey',
              options=[['apikey', 'an API key'], ['password', 'a user and password']]),
        field('apikey', 'API key', 'secret', show_if={'auth': ['apikey']}),
        field('user', 'User', 'text', default='bal', show_if={'auth': ['password']}),
        field('password', 'Password', 'secret', show_if={'auth': ['password']}),
    ] + tls_fields()
    deploy_fields = [
        field('virtual_services', 'Virtual services', 'list', placeholder='192.0.2.10:443',
              help='one a line: address:port[:tcp|udp] of each virtual service to use it'),
        field('intermediates', 'Add the intermediates', 'bool', default=True, advanced=True),
        keep_field(1),
    ] + verify_fields()

    _clock = staticmethod(time.monotonic)
    _sleep = staticmethod(time.sleep)

    def throttle(self):
        """At most RATE_CALLS calls in any RATE_WINDOW seconds."""
        calls = self.__dict__.setdefault('_recent', [])
        now = self._clock()
        calls[:] = [t for t in calls if now - t < RATE_WINDOW]
        if len(calls) >= RATE_CALLS:
            self._sleep(max(0.0, RATE_WINDOW - (now - calls[0])) + 0.05)
            now = self._clock()
            calls[:] = [t for t in calls if now - t < RATE_WINDOW]
        calls.append(now)

    def cmd(self, cmd, what=None, ok_fail=False, **params):
        self.throttle()
        body = {'cmd': cmd}
        if (self.c('auth') or 'apikey') == 'apikey':
            body['apikey'] = self.c('apikey') or ''
        else:
            body['apiuser'] = self.c('user') or ''
            body['apipass'] = self.c('password') or ''
        body.update(params)
        st, hd, d = self.req('POST', '/accessv2', body, ok=range(0, 600), what=what or cmd)
        if not isinstance(d, dict):
            raise PluginError('%s: the LoadMaster did not answer with JSON (is it 7.2.50 or '
                              'later, the API on?)' % (what or cmd), detail=text(d)[:2000])
        status = text(d.get('status')).lower()
        if st >= 300 or status not in ('ok', 'success'):
            msg = text(d.get('message') or d.get('error') or status)
            if ok_fail:
                return None
            code = d.get('code') or st
            raise PluginError('%s: the LoadMaster said %s - %s' % (what or cmd, code, msg),
                              detail=text(d)[:2000],
                              retry=code not in (401, 403, 422) and 'nauthori' not in msg)
        return d

    def certs(self):
        d = self.cmd('listcert', what='listing the certificates')
        out = []
        for c in d.get('cert') or []:
            if isinstance(c, dict) and c.get('name'):
                out.append(text(c['name']))
            elif isinstance(c, str):
                out.append(c)
        return out

    def test(self):
        n = self.certs()
        return 'signed in to %s; %d certificate%s there' % (self.c('host'), len(n),
                                                           '' if len(n) == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=60)
        prefix = name_prefix(bundle, options, maxlen=60)
        have = self.certs()
        if self.unchanged(bundle, options, present=lambda: name in have):
            return self.same(bundle, 'as %s' % name)
        did = []
        force = as_bool(options.get('force'))
        if name in have and not force:
            self.ctx.step('%s is there already' % name)
        else:
            data = base64.b64encode(bundle.as_format('fullchain-pem') +
                                    bundle.as_format('key-pem')).decode()
            self.cmd('addcert', what='adding %s' % name, cert=name,
                     replace=1 if name in have else 0, data=data)
            self.ctx.step('added %s' % name, 'ok')
            did.append('added %s' % name)
        if as_bool(self.opt(options, 'intermediates', True), True):
            for pem in chain_list(bundle):
                iname = 'acme-ca-%s' % chain_id(pem)
                if self.cmd('addintermediate', ok_fail=True, cert=iname,
                            data=base64.b64encode(pem.encode()).decode()) is not None:
                    self.ctx.step('added the intermediate %s' % iname)
                else:
                    self.ctx.step('the intermediate %s was not added (the LoadMaster refused it: '
                                  'there already?)' % iname)
        for vs in lines(options.get('virtual_services')):
            m6 = re.match(r'^\[([^\]]+)\]:(\d+)(?::(\w+))?$', vs.strip())
            if m6:                  # [IPv6]:port[:protocol] (1.0.88: the protocol was the port)
                parts = [m6.group(1), m6.group(2), m6.group(3) or 'tcp']
            else:
                parts = vs.rsplit(':', 2) if vs.count(':') >= 2 and not vs.startswith('[') \
                    else vs.rsplit(':', 1) + ['tcp']
            if len(parts) != 3 or not parts[1].isdigit():
                raise PluginError('"%s" is not address:port[:tcp]' % vs, retry=False)
            addr, port, prot = parts[0].strip('[]'), parts[1], parts[2] or 'tcp'
            now = self.vs_certs(addr, port, prot)
            want = self.cert_list(now, name, prefix, set(have) | {name}, vs)
            if now == want:
                self.ctx.step('%s uses %s already' % (vs, name))
                continue
            self.cmd('modvs', what='pointing %s at %s' % (vs, name), vs=addr,
                     port=port, prot=prot, CertFile=' '.join(want))
            self.ctx.step('%s uses %s' % (vs, ' '.join(want)), 'ok')
            did.append(vs)
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def vs_certs(self, addr, port, prot):
        """The certificates a virtual service has now (showvs CertFile); [] when unknown."""
        d = self.cmd('showvs', ok_fail=True, vs=addr, port=port, prot=prot)
        raw = (d or {}).get('CertFile')
        if isinstance(raw, list):
            return [text(x) for x in raw if text(x).strip()]
        return text(raw or '').split()

    def cert_list(self, now, name, prefix, known, vs):
        """The whole CertFile list to send: the virtual service's own, acme's older one
        swapped for `name` in its place (first when it had none of acme's)."""
        others = [c for c in now if c != name and not ours(c, prefix)]
        unknown = [c for c in others if c not in known]
        if unknown:
            self.ctx.step('%s lists certificates acme cannot name (%s): it gets %s alone - '
                          'add the others to it again by hand' % (vs, ' '.join(unknown), name),
                          'warn')
            return [name]
        out, placed = [], False
        for c in now:
            if c == name or ours(c, prefix):
                if not placed:
                    out.append(name)
                    placed = True
            else:
                out.append(c)
        return out if placed else [name] + out

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        for old in prune(self.certs(), prefix, keep, current):
            try:
                self.cmd('delcert', what='deleting %s' % old, cert=old)
                self.ctx.step('deleted the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')

    def remove(self, bundle, options):
        self.cmd('delcert', cert=object_name(bundle, options, maxlen=60), ok_fail=True)
