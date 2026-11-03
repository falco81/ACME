# -*- coding: utf-8 -*-
"""DNS-01 at Rackspace Cloud DNS, through its API v1.0:

    POST   https://identity.api.rackspacecloud.com/v2.0/tokens
           {auth: {"RAX-KSKEY:apiKeyCredentials": {username, apiKey}}}
                -> {access: {token: {id, expires, tenant: {id}},
                             serviceCatalog: [{type: "rax:dns", endpoints: [{publicURL}]}]}}
    GET    {dns}/domains?limit=100&offset=N                              {domains: [{id, name}], totalEntries}
    GET    {dns}/domains/{id}/records?type=TXT&name={fqdn}               {records: [{id, name, type, data, ttl}]}
    POST   {dns}/domains/{id}/records  {records: [{name, type, data, ttl}]}       202 {status, callbackUrl}
    DELETE {dns}/domains/{id}/records/{record id}                                 202 {status, callbackUrl}
    GET    {callbackUrl}?showDetails=true                                {status: RUNNING | COMPLETED | ERROR, response | error}

{dns} is the public address of the rax:dns service in the catalog
(https://dns.api.rackspacecloud.com/v1.0/{account}); X-Auth-Token on every
call. The token is kept (and shared) until a little before it runs out, a
401 signs in once more. A change is a job: acme follows its callback until
it is COMPLETED (or says the ERROR). Each value is a record of its own; the
name is written whole. Rackspace takes no TTL under 300.

Sources: Rackspace's Python SDK pyrax (https://github.com/pycontribs/pyrax,
first published by Rackspace as rackspace/pyrax: pyrax/identity/
rax_identity.py - the identity address and RAX-KSKEY:apiKeyCredentials;
pyrax/base_identity.py - tokens, access.token, serviceCatalog;
pyrax/clouddns.py - domains (list, ?name=), search_records,
add_records, delete_record, _async_call and the /status/ callback;
pyrax/fakes.py - the rax:dns endpoint); the reference is
https://developer.rackspace.com/docs/cloud-dns/v1/. Cross-checked with lego's
providers/dns/rackspace.
"""
from __future__ import annotations

import datetime
import json
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _common as C
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns

IDENTITY = 'https://identity.api.rackspacecloud.com/v2.0'
JOB_WAITS = 30                  # times the callback is asked, 2 s apart


def _until(expires):
    """Seconds until an identity time (2026-11-03T10:00:00.000Z), or 3600."""
    try:
        t = datetime.datetime.strptime(str(expires)[:19], '%Y-%m-%dT%H:%M:%S').replace(
            tzinfo=datetime.timezone.utc)
        return max(60.0, (t - datetime.datetime.now(datetime.timezone.utc)).total_seconds())
    except ValueError:
        return 3600.0


class Rackspace(RecordApiDns):
    kind = 'rackspace'
    discover_keys = ['user', 'api_key', 'identity']                # how one signs in
    title = 'Rackspace Cloud DNS'
    vendor = 'Rackspace'
    who = 'Rackspace'
    min_ttl = 300
    description = 'TXT records in a domain at Rackspace Cloud DNS, with a user name and API key.'
    fields = [
        field('user', 'User name', 'text', required=True,
              help='A Rackspace Cloud user allowed to change DNS (best one of its own for '
                   'acme) and, below, its API key.'),
        field('api_key', 'API key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=300, advanced=True,
              help='Rackspace takes 300 or more.'),
        field('identity', 'Identity address', 'text', default=IDENTITY, advanced=True),
    ] + PROPAGATION_FIELDS

    # -- signing in -------------------------------------------------------------
    def _sign_in(self):
        _st, got = api(self.ctx, 'POST', str(self.c('identity', IDENTITY)).rstrip('/') +
                       '/tokens', {'auth': {'RAX-KSKEY:apiKeyCredentials': {
                           'username': self.c('user', ''), 'apiKey': self.c('api_key', '')}}},
                       who='Rackspace Identity')
        acc = (got or {}).get('access') or {}
        tok = (acc.get('token') or {}).get('id')
        url = None
        for svc in acc.get('serviceCatalog') or []:
            if svc.get('type') == 'rax:dns' or svc.get('name') == 'cloudDNS':
                for ep in svc.get('endpoints') or []:
                    url = url or ep.get('publicURL')
        if not tok or not url:
            raise PluginError('Rackspace: signed in, but no token or no Cloud DNS service came '
                              'back - does the user have the DNS role?', retry=False)
        life = _until((acc.get('token') or {}).get('expires'))
        return json.dumps([tok, url.rstrip('/')]), max(60.0, life - 300)

    def _session(self):
        if limits.sharing(self.ctx):
            return json.loads(limits.session(limits.key_of(self, 'token'), self._sign_in))
        if getattr(self, '_tok', None) and self._tok[1] > time.time():
            return json.loads(self._tok[0])
        tok, life = self._sign_in()
        self._tok = (tok, time.time() + life)
        return json.loads(tok)

    def _call(self, method, path, body=None, missing_ok=False):
        for again in (True, False):
            tok, base = self._session()
            url = path if path.startswith('https://') else base + path
            try:
                st, got = api(self.ctx, method, url, body, {'X-Auth-Token': tok},
                              who='Rackspace', missing_ok=missing_ok)
            except PluginError as e:
                if again and 'said 401' in str(e):
                    if limits.sharing(self.ctx):
                        limits.session_drop(limits.key_of(self, 'token'),
                                            json.dumps([tok, base]))
                    self._tok = None
                    continue
                raise
            if st == 404 and missing_ok:
                return None
            if st == 202 and isinstance(got, dict) and got.get('callbackUrl'):
                return self._job(got)
            return got if isinstance(got, dict) else {}

    def _job(self, got):
        """Follow a change's callback until it is done; its answer."""
        url = str(got['callbackUrl'])
        url += ('&' if '?' in url else '?') + 'showDetails=true'
        for _ in range(JOB_WAITS):
            status = str(got.get('status') or '').upper()
            if status == 'COMPLETED':
                return got.get('response') or {}
            if status == 'ERROR':
                err = got.get('error') or {}
                faults = (err.get('failedItems') or {}).get('faults') or [err]
                words = '; '.join(str(f.get('details') or f.get('message') or f)
                                  for f in faults if isinstance(f, dict)) or str(err)
                raise PluginError('Rackspace could not do it: %s' % words, detail=str(got),
                                  retry=False)
            if getattr(self.ctx, 'cancelled', lambda: False)():
                raise PluginError('stopped while Rackspace was still at it')
            C.SLEEP(2)
            got = self._call('GET', url) or {}
            if got.get('callbackUrl') is None and 'status' not in got:
                return got
        raise PluginError('Rackspace did not finish the change in a minute')

    # -- zones and records ----------------------------------------------------------
    def _domains(self):
        if getattr(self, '_doms', None) is None:
            self._doms, offset = {}, 0
            for _page in range(50):
                got = self._call('GET', '/domains?limit=100&offset=%d' % offset) or {}
                rows = got.get('domains') or []
                self._doms.update({D.norm(d.get('name')): d.get('id') for d in rows
                                   if isinstance(d, dict) and d.get('name')})
                offset += len(rows)
                if not rows or offset >= int(got.get('totalEntries') or 0):
                    break
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(D.norm(zone))
        if did is None:
            got = self._call('GET', '/domains?name=' + urllib.parse.quote(D.norm(zone))) or {}
            did = next((d.get('id') for d in got.get('domains') or []
                        if D.norm(d.get('name')) == D.norm(zone)), None)
        if did is None:
            raise PluginError('Rackspace has no domain %s on this account' % zone, retry=False)
        return did

    def txt_records(self, zone, fqdn):
        got = self._call('GET', '/domains/%s/records?%s' % (self._id(zone), urllib.parse.urlencode(
            {'type': 'TXT', 'name': D.norm(fqdn)})), missing_ok=True) or {}
        return [(r.get('id'), r.get('data')) for r in got.get('records') or []
                if isinstance(r, dict) and str(r.get('type', 'TXT')).upper() == 'TXT' and
                D.norm(r.get('name') or '') == D.norm(fqdn)]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/domains/%s/records' % self._id(zone), {'records': [
            {'name': D.norm(fqdn), 'type': 'TXT', 'data': value, 'ttl': self.ttl()}]}) or {}
        recs = got.get('records') or []
        return recs[0].get('id') if recs and isinstance(recs[0], dict) else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/domains/%s/records/%s' % (self._id(zone), record_id),
                   missing_ok=True)
