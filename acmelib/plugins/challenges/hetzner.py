# -*- coding: utf-8 -*-
"""DNS-01 at Hetzner: the DNS zones of the Hetzner Console / Cloud API
(api.hetzner.cloud, where Hetzner DNS has moved):

    GET  https://api.hetzner.cloud/v1/zones?name={zone}                {zones: [{id, name}]}
    GET  .../zones/{id}/rrsets/{name}/TXT                                {rrset: {ttl, records: [{value}]}}
    POST .../zones/{id}/rrsets/{name}/TXT/actions/add_records  {records: [{value}], ttl}
    POST .../zones/{id}/rrsets/{name}/TXT/actions/remove_records  {records: [{value}]}
    GET  .../zones/actions/{action id}                                   {action: {status}}

Authorization: Bearer <a project's API token>. The name is relative to the
zone ("_acme-challenge.www", "@" for the apex), a TXT value is written in
double quotes. add_records appends to the RRset (made when there is none);
the TTL is sent only for a new RRset, as "if set, and the RRSet being updated
already has a TTL, the values must be the same". remove_records takes away
exactly the values given, so other orders' values stay; it is sent only when
our value is there. Each write answers an action, waited for until "success"
(or its error said); a 423 "locked" (another action running) is tried again.

The old DNS Console API (dns.hetzner.com) was switched off by Hetzner on
2026-05-27 (status.hetzner.com: "The DNS console and API was removed"): a
validation still set to it is refused with words saying so.

Sources (the user's collection, api-docs/hetzner/): cloud-dns-zones-rrsets.json
(from https://docs.hetzner.cloud/cloud.spec.json - /zones, the rrset actions,
the action object, the errors, rate limiting) and notes.md, quoting
https://docs.hetzner.cloud/changelog, https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44
and the TXT format of Hetzner's Terraform provider (docs/resources/zone_rrset.md).

Less certain: what add_records does with a value the RRset has already (not
documented - acme reads the RRset first and adds only what is missing); how
long an action runs (waited for 60 s at most, then left - the name servers
are asked anyway).
"""
from __future__ import annotations

import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _common as C
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api,
                                                relative, unquote_txt)

API = 'https://api.hetzner.cloud/v1'
ACTION_WAIT_S = 60
LOCKED_TRIES = 4


class Hetzner(DnsChallenge):
    kind = 'hetzner'
    api_provider = True             # its zones are asked of its API (guide)
    title = 'Hetzner DNS'
    vendor = 'Hetzner'
    description = 'TXT records in a zone at Hetzner, with an API token.'
    fields = [
        field('token', 'API token', 'secret', required=True,
              help='Hetzner Console → the project of the zone → Security → API tokens: a token '
                   'with Read & Write. Tokens of the old DNS Console (dns.hetzner.com, switched '
                   'off in May 2026) do not work.'),
        field('zone', 'Zone', 'text', default='', help='Empty: found by the name.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='60 or more; used for a new RRset only (one there keeps its own).'),
    ] + PROPAGATION_FIELDS

    def _check_api(self):
        if str(self.config.get('api') or 'cloud') == 'dns':
            raise PluginError('Hetzner switched the old DNS Console API (dns.hetzner.com) off in '
                              'May 2026 - set this validation to a Hetzner Console project\'s API '
                              'token (its zones moved there) and save it again', retry=False)

    def ttl(self):
        return max(int(self.num('ttl', 60) or 60), 60)

    def _call(self, method, path, body=None, missing_ok=False):
        self._check_api()
        h = {'Authorization': 'Bearer ' + str(self.c('token', ''))}
        for attempt in range(LOCKED_TRIES):
            try:
                return api(self.ctx, method, API + path, body, h, who='Hetzner',
                           missing_ok=missing_ok)[1]
            except PluginError as e:
                if 'said 423' not in str(e) or attempt + 1 >= LOCKED_TRIES:
                    raise
                self.ctx.step('Hetzner: the zone is busy with another change (423) - tried '
                              'again in a moment', 'warn')
                C.SLEEP(2 * (attempt + 1))

    def _zone(self, fqdn):
        want = D.norm(self.c('zone', ''))
        labels = D.norm(fqdn).split('.')
        cands = [want] if want else ['.'.join(labels[i:]) for i in range(len(labels) - 1)]
        for cand in cands:
            got = self._call('GET', '/zones?name=' + urllib.parse.quote(cand)) or {}
            for z in got.get('zones') or []:
                if D.norm(z.get('name')) == cand:
                    return str(z.get('id')), cand
        raise PluginError('Hetzner has no zone for %s that this token may see' % fqdn,
                          retry=False)

    def zone_hint(self, fqdn):
        self._check_api()
        try:
            return self._zone(fqdn)[1]
        except PluginError:
            return None

    def _rrset_path(self, zid, rel):
        return '/zones/%s/rrsets/%s/TXT' % (zid, urllib.parse.quote(rel, safe='@'))

    def _rrset(self, zid, rel):
        """(ttl or None, [values as stored]) - ([], None) when there is no such RRset."""
        got = self._call('GET', self._rrset_path(zid, rel), missing_ok=True) or {}
        rs = got.get('rrset') or {}
        return rs.get('ttl'), [str(r.get('value') or '') for r in rs.get('records') or []
                               if isinstance(r, dict)]

    def _wait(self, got, what):
        """Wait for the action a write answered (status running -> success | error)."""
        act = (got or {}).get('action') or {}
        until = time.time() + ACTION_WAIT_S
        pause = 1
        while str(act.get('status') or '') == 'running' and act.get('id') is not None:
            if getattr(self.ctx, 'cancelled', lambda: False)():
                return
            if time.time() > until:
                self.ctx.step('Hetzner: %s is still running after %d s - the name servers are '
                              'asked anyway' % (what, ACTION_WAIT_S), 'warn')
                return
            C.SLEEP(pause)
            pause = min(pause * 2, 8)
            act = (self._call('GET', '/zones/actions/%s' % act.get('id')) or {}).get('action') \
                or {}
        if str(act.get('status') or '') == 'error':
            err = act.get('error') or {}
            raise PluginError('Hetzner could not %s: %s' % (what, err.get('message') or
                                                             err.get('code') or 'error'),
                              detail=str(err))

    def add_txt(self, fqdn, value):
        zid, zone = self._zone(fqdn)
        rel = relative(fqdn, zone)
        ttl, have = self._rrset(zid, rel)
        if value not in [unquote_txt(v) for v in have]:
            body = {'records': [{'value': '"%s"' % value}]}
            if not have:
                body['ttl'] = self.ttl()
            got = self._call('POST', self._rrset_path(zid, rel) + '/actions/add_records', body)
            self._wait(got, 'add the TXT record %s' % fqdn)
        return {'zone_id': zid, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        if not h.get('zone_id') or not h.get('rel'):
            zid, zone = self._zone(fqdn)
            h = {'zone_id': zid, 'rel': relative(fqdn, zone)}
        _ttl, have = self._rrset(h['zone_id'], h['rel'])
        mine = [v for v in have if unquote_txt(v) == value]
        if not mine:
            return
        got = self._call('POST', self._rrset_path(h['zone_id'], h['rel']) +
                         '/actions/remove_records', {'records': [{'value': v} for v in mine]},
                         missing_ok=True)
        self._wait(got, 'remove the TXT record %s' % fqdn)

    def test(self):
        got = self._call('GET', '/zones') or {}
        names = [z.get('name') for z in got.get('zones') or []]
        return 'the token sees %d zone(s): %s' % (len(names), ', '.join(names[:20]))
