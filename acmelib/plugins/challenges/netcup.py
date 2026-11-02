# -*- coding: utf-8 -*-
"""DNS-01 at netcup, through the CCP DNS API (JSON, every call a POST to
https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON):

    {"action": "login", "param": {customernumber, apikey, apipassword}}    -> apisessionid
    infoDnsZone      {domainname, ...}                 is it a zone of the account
    infoDnsRecords   {domainname, ...}                 {dnsrecords: [{id, hostname, type, destination}]}
    updateDnsRecords {domainname, ..., dnsrecordset: {dnsrecords: [...]}}
                     a record without id is added; with id and deleterecord: true, removed
    logout

Answers: {status: "success"|"error", statuscode, shortmessage, longmessage};
statuscode 5029 ("no records") is an empty zone. netcup has no call that lists
the zones: the candidates (longest first) are asked with infoDnsZone. Its
name servers take a while (often 5 to 15 minutes) - the propagation check
waits for them; the TTL is the zone's, not a record's.
"""
from __future__ import annotations

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, api, no_zone,
                                                relative, suffixes, unquote_txt)

API = 'https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON'


class Netcup(ApiDns):
    kind = 'netcup'
    title = 'netcup'
    vendor = 'netcup'
    who = 'netcup'
    description = 'TXT records in a domain at netcup, through the CCP DNS API.'
    fields = [
        field('customer', 'Customer number', 'text', required=True, placeholder='123456'),
        field('api_key', 'API key', 'secret', required=True,
              help='Customer Control Panel (CCP) → Master Data → API: create an API key and '
                   'an API password.'),
        field('api_password', 'API password', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: found by asking netcup for the name and each name above it.'),
    ] + PROPAGATION_FIELDS

    _session = None

    def _raw(self, action, param):
        _st, got = api(self.ctx, 'POST', API, {'action': action, 'param': param}, who='netcup')
        got = got if isinstance(got, dict) else {}
        return got

    def _login(self):
        if self._session:
            return
        if limits.sharing(self.ctx):
            # one API session for every run with these settings (netcup ends one
            # after 15 minutes without use)
            self._session = limits.session(limits.key_of(self, 'session'),
                                           lambda: (self._sign_in(), 600.0))
            return
        self._session = self._sign_in()

    def _sign_in(self):
        got = self._raw('login', {'customernumber': str(self.c('customer', '')),
                                  'apikey': str(self.c('api_key', '')),
                                  'apipassword': str(self.c('api_password', ''))})
        if got.get('status') != 'success':
            raise PluginError('netcup did not sign in: %s' % (
                got.get('longmessage') or got.get('shortmessage') or got.get('statuscode')),
                detail=got, retry=False)
        return (got.get('responsedata') or {}).get('apisessionid')

    def _call(self, action, param=None, quiet=()):
        self._login()
        p = {'customernumber': str(self.c('customer', '')), 'apikey': str(self.c('api_key', '')),
             'apisessionid': self._session}
        p.update(param or {})
        got = self._raw(action, p)
        if got.get('status') != 'success':
            code = int(got.get('statuscode') or 0)
            if code in quiet:
                return None
            if code == 4001:                    # the session ran out
                if limits.sharing(self.ctx):
                    limits.session_drop(limits.key_of(self, 'session'), self._session)
                self._session = None
            raise PluginError('netcup said %s: %s' % (code, got.get('longmessage') or
                              got.get('shortmessage')), detail=got, retry=code == 4001)
        return got.get('responsedata') or {}

    def zone_names(self):
        return None

    def zone_hint(self, fqdn):
        want = D.norm(self.c('zone', ''))
        if want and D.in_zone(fqdn, want):
            return want
        for cand in suffixes(fqdn)[1:]:
            try:
                if self._call('infoDnsZone', {'domainname': cand}) is not None:
                    return cand
            except PluginError as e:
                if 'did not sign in' in str(e):
                    raise
        raise no_zone('netcup', fqdn)

    def _records(self, zone):
        got = self._call('infoDnsRecords', {'domainname': zone}, quiet=(5029,)) or {}
        return got.get('dnsrecords') or []

    def _ours(self, zone, rel, value):
        return [r for r in self._records(zone) if r.get('type') == 'TXT' and
                r.get('hostname') == rel and unquote_txt(r.get('destination')) == value]

    def _update(self, zone, recs):
        self._call('updateDnsRecords', {'domainname': zone,
                                        'dnsrecordset': {'dnsrecords': recs}})

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        if not self._ours(zone, rel, value):
            self._update(zone, [{'hostname': rel, 'type': 'TXT', 'destination': value,
                                 'deleterecord': False}])
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        mine = self._ours(zone, h.get('rel') or relative(fqdn, zone), value)
        if mine:
            self._update(zone, [{'id': r.get('id'), 'hostname': r.get('hostname'),
                                 'type': 'TXT', 'destination': r.get('destination'),
                                 'deleterecord': True} for r in mine])

    def test(self):
        if self.c('zone'):
            zone = D.norm(self.c('zone'))
            info = self._call('infoDnsZone', {'domainname': zone}) or {}
            words = 'netcup: signed in; the zone %s is there (TTL %s s)' % (
                info.get('name') or zone, info.get('ttl') or '?')
        else:
            self._login()
            words = 'netcup: signed in (netcup lists no zones: set the domain to check one)'
        if limits.sharing(self.ctx):
            return words                # the session is shared: it runs out by itself
        try:
            self._call('logout')
        except PluginError:
            pass
        self._session = None
        return words
