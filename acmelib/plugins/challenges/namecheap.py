# -*- coding: utf-8 -*-
"""DNS-01 at Namecheap, through its XML API (https://api.namecheap.com/xml.response):

    namecheap.domains.getList                    the domains of the account
    namecheap.domains.dns.getHosts SLD TLD       every host record of the domain
    namecheap.domains.dns.setHosts SLD TLD ...   EVERY host record of the domain, written whole

Namecheap has no call to add or remove one record: setHosts replaces all of
them. So each change is read-modify-write - every record getHosts gave
(name, type, address, MX preference, TTL) and the domain's EmailType are sent
back unchanged with our TXT value added or taken away; one change at a time
on this node (a lock), and refused when the domain does not use Namecheap's
own DNS. What getHosts does not show is lost on setHosts - Namecheap says it
shows every record, but check a domain with unusual records (CAA, URL
redirects) by hand once after the first certificate.

The API is switched on per account (Profile → Tools → Business & Dev Tools →
Namecheap API Access; Namecheap grants it to accounts that meet its terms) and
answers only the addresses whitelisted there: ClientIp must be the public
address acme reaches the internet from.
"""
from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, http_call, relative,
                                                rmw_lock, said_error, unquote_txt)

APIS = {'production': 'https://api.namecheap.com/xml.response',
        'sandbox': 'https://api.sandbox.namecheap.com/xml.response'}


def _tag(e):
    return e.tag.rsplit('}', 1)[-1]


def _find(x, name):
    return [e for e in x.iter() if _tag(e) == name]


class Namecheap(ApiDns):
    kind = 'namecheap'
    discover_keys = ['api_user', 'api_key', 'client_ip', 'user_name', 'endpoint']
    title = 'Namecheap'
    vendor = 'Namecheap'
    who = 'Namecheap'
    parallel = False
    description = 'TXT records in a domain at Namecheap (its own DNS), through the XML API.'
    fields = [
        field('api_user', 'API user', 'text', required=True,
              help='Your Namecheap user name. The API is switched on under Profile → Tools → '
                   'Business & Dev Tools → Namecheap API Access.'),
        field('api_key', 'API key', 'secret', required=True,
              help='From that page. Namecheap answers only the addresses whitelisted there.'),
        field('client_ip', 'Client IP', 'text', required=True, placeholder='203.0.113.10',
              help='The public IPv4 address acme reaches the internet from (through the proxy, '
                   'the proxy\'s): it must be whitelisted under Namecheap API Access.'),
        field('user_name', 'User name the calls are for', 'text', default='', advanced=True,
              help='Empty: the API user.'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True,
              help='Namecheap takes 60 to 60000.'),
        field('endpoint', 'Endpoint', 'select', default='production', advanced=True,
              options=[['production', 'api.namecheap.com'],
                       ['sandbox', 'api.sandbox.namecheap.com (the sandbox)']]),
        field('rewrite_ok', 'Allow rewriting every record', 'bool', default=True, advanced=True,
              help='Namecheap\'s setHosts replaces ALL records of the domain: acme reads them '
                   'all, adds or removes its TXT value and writes them all back, one change at '
                   'a time. A record changed by hand at that very moment can be lost. Off: '
                   'acme refuses to change the domain.'),
    ] + PROPAGATION_FIELDS

    def _call(self, command, params=None, post=False):
        q = {'ApiUser': str(self.c('api_user', '')), 'ApiKey': str(self.c('api_key', '')),
             'UserName': str(self.c('user_name', '') or self.c('api_user', '')),
             'ClientIp': str(self.c('client_ip', '')), 'Command': command}
        q.update(params or {})
        url = APIS.get(self.c('endpoint', 'production'), APIS['production'])
        data = urllib.parse.urlencode(q)
        if post:
            st, _rh, got = http_call(self.ctx, 'POST', url, data.encode(), {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'acme-challenge'}, who='Namecheap')
        else:
            st, _rh, got = http_call(self.ctx, 'GET', url + '?' + data,
                                     headers={'User-Agent': 'acme-challenge'}, who='Namecheap')
        if st != 200:
            raise said_error('Namecheap', st, None, got)
        try:
            x = ET.fromstring(got)
        except ET.ParseError:
            raise PluginError('Namecheap answered something that is not its XML', detail=got)
        if x.get('Status') != 'OK':
            errs = ['%s (%s)' % ((e.text or '').strip(), e.get('Number')) for e in _find(x, 'Error')]
            words = '; '.join(errs) or 'status %s' % x.get('Status')
            hint = ''
            if any(n in words for n in ('1011150', 'Invalid request IP', '1011102')):
                hint = ' - whitelist the client IP (and check the API key) under Namecheap ' \
                       'API Access'
            raise PluginError('Namecheap said no: %s%s' % (words, hint), detail=got,
                              retry=False)
        return x

    def zone_names(self):
        out = []
        for page in range(1, 51):
            x = self._call('namecheap.domains.getList', {'PageSize': '100', 'Page': str(page)})
            got = [d.get('Name') for d in _find(x, 'Domain')]
            out += got
            total = int((_find(x, 'TotalItems') or [ET.Element('x')])[0].text or 0)
            if not got or len(out) >= total:
                break
        return out

    @staticmethod
    def _split(zone):
        sld, _dot, tld = D.norm(zone).partition('.')
        return {'SLD': sld, 'TLD': tld}

    def _hosts(self, zone):
        x = self._call('namecheap.domains.dns.getHosts', self._split(zone))
        res = (_find(x, 'DomainDNSGetHostsResult') or [None])[0]
        if res is None:
            raise PluginError('Namecheap gave no host records for %s' % zone, detail=x)
        if str(res.get('IsUsingOurDNS', 'true')).lower() != 'true':
            raise PluginError('%s does not use Namecheap\'s DNS - its records are elsewhere'
                              % zone, retry=False)
        hosts = [{'name': h.get('Name'), 'type': h.get('Type'), 'address': h.get('Address'),
                  'mx': h.get('MXPref') or '10', 'ttl': h.get('TTL') or '1800'}
                 for h in _find(res, 'host')]
        return res.get('EmailType') or '', hosts

    def _set(self, zone, email_type, hosts):
        p = self._split(zone)
        if email_type:
            p['EmailType'] = email_type
        for i, h in enumerate(hosts, 1):
            p.update({'HostName%d' % i: h['name'], 'RecordType%d' % i: h['type'],
                      'Address%d' % i: h['address'], 'MXPref%d' % i: h['mx'],
                      'TTL%d' % i: h['ttl']})
        x = self._call('namecheap.domains.dns.setHosts', p, post=True)
        res = (_find(x, 'DomainDNSSetHostsResult') or [None])[0]
        if res is not None and str(res.get('IsSuccess', 'true')).lower() != 'true':
            raise PluginError('Namecheap did not take the host records of %s' % zone, detail=x)

    def _allowed(self):
        if not self.flag('rewrite_ok'):
            raise PluginError('changing a Namecheap domain is switched off ("Allow rewriting '
                              'every record")', retry=False)

    def add_txt(self, fqdn, value):
        self._allowed()
        zone = self.zone_for(fqdn)
        rel = relative(fqdn, zone)
        with rmw_lock('namecheap:' + zone):
            email, hosts = self._hosts(zone)
            if not any(h['type'] == 'TXT' and h['name'] == rel and
                       unquote_txt(h['address']) == value for h in hosts):
                self._set(zone, email, hosts + [{'name': rel, 'type': 'TXT', 'address': value,
                                                 'mx': '10', 'ttl': str(self.ttl())}])
        return {'zone': zone, 'rel': rel}

    def del_txt(self, fqdn, value, handle):
        self._allowed()
        h = handle or {}
        zone = h.get('zone') or self.zone_for(fqdn)
        rel = h.get('rel') or relative(fqdn, zone)
        with rmw_lock('namecheap:' + zone):
            email, hosts = self._hosts(zone)
            left = [x for x in hosts if not (x['type'] == 'TXT' and x['name'] == rel and
                                             unquote_txt(x['address']) == value)]
            if len(left) != len(hosts):
                self._set(zone, email, left)
