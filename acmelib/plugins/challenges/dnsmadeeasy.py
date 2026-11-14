# -*- coding: utf-8 -*-
"""DNS-01 at DNS Made Easy, through its REST API V2.0, each request signed:

    x-dnsme-apiKey: KEY
    x-dnsme-requestDate: an HTTP date (Sat, 12 Feb 2011 20:59:04 GMT)
    x-dnsme-hmac: hex(HMAC-SHA1(secret, that date))

    GET    https://api.dnsmadeeasy.com/V2.0/dns/managed/?page=N                {data: [{id, name}], page, totalPages}
    GET    .../dns/managed/{id}/records?type=TXT&recordName={name}             {data: [{id, name, type, value, ttl}]}
    POST   .../dns/managed/{id}/records   {name, type: "TXT", value, ttl}      {id, ...}
    DELETE .../dns/managed/{id}/records/{record id}

"name" is relative to the domain ("" the apex); a TXT value comes back in
quotes. The domain list comes in pages (page from 0, totalPages, totalRecords in
each answer, as the V2.0 list answers are documented): every page is read, at
most 50 (1.0.102); an answer without totalPages is the whole list. This machine's clock has to be right (the date is checked).

Sources: https://api-docs.dnsmadeeasy.com/ - not reachable from where this
was written; as lego's providers/dns/dnsmadeeasy and Posh-ACME's DMEasy
plugin send it. The sandbox is https://api.sandbox.dnsmadeeasy.com/V2.0.
"""
from __future__ import annotations

import email.utils
import hashlib
import hmac
import urllib.parse

from acmelib.plugins.base import field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://api.dnsmadeeasy.com/V2.0'


def dme_headers(key, secret, date=None):
    date = date or email.utils.formatdate(usegmt=True)
    return {'x-dnsme-apiKey': key, 'x-dnsme-requestDate': date,
            'x-dnsme-hmac': hmac.new(secret.encode('utf-8'), date.encode('utf-8'),
                                     hashlib.sha1).hexdigest()}


class DnsMadeEasy(RecordApiDns):
    kind = 'dnsmadeeasy'
    title = 'DNS Made Easy'
    vendor = 'DNS Made Easy'
    who = 'DNS Made Easy'
    min_ttl = 30
    description = 'TXT records in a managed domain at DNS Made Easy, with an API key and secret.'
    fields = [
        field('key', 'API key', 'text', required=True,
              help='DNS Made Easy control panel → Account Information → API key and secret key '
                   '(a user with access to the domains).'),
        field('secret', 'Secret key', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest managed domain the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='https://api.sandbox.dnsmadeeasy.com/V2.0 for the sandbox.'),
    ] + PROPAGATION_FIELDS

    def _call(self, method, path, body=None, missing_ok=False):
        _st, got = api(self.ctx, method, str(self.c('api', API)).rstrip('/') + path, body,
                       dme_headers(str(self.c('key', '')), str(self.c('secret', ''))),
                       who='DNS Made Easy', missing_ok=missing_ok)
        return got

    def _domains(self):
        if getattr(self, '_doms', None) is None:
            doms, page, first = {}, None, None
            for _n in range(50):
                got = self._call('GET', '/dns/managed/' + ('' if page is None else
                                                           '?page=%d' % page)) or {}
                new = {D.norm(d.get('name')): d.get('id') for d in got.get('data') or []
                       if isinstance(d, dict) and d.get('name')}
                if not set(new) - set(doms):         # nothing new: the end (or no paging)
                    break
                doms.update(new)
                try:
                    now, pages = int(got.get('page') or 0), int(got.get('totalPages') or 0)
                except (TypeError, ValueError):
                    break
                first = now if first is None else first     # pages counted from 0 (or 1)
                if now + 1 - first >= pages:
                    break
                page = now + 1
            self._doms = doms
        return self._doms

    def zone_names(self):
        return list(self._domains())

    def _id(self, zone):
        did = self._domains().get(D.norm(zone))
        if did is None:
            got = self._call('GET', '/dns/managed/name?' + urllib.parse.urlencode(
                {'domainname': zone})) or {}
            did = got.get('id')
        return did

    def txt_records(self, zone, fqdn):
        name = rel_name(fqdn, zone, apex='')
        got = self._call('GET', '/dns/managed/%s/records?%s' % (self._id(zone), urllib.parse.urlencode(
            {'type': 'TXT', 'recordName': name}))) or {}
        return [(r.get('id'), r.get('value')) for r in got.get('data') or []
                if str(r.get('type')).upper() == 'TXT' and (r.get('name') or '') == name]

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/dns/managed/%s/records' % self._id(zone), {
            'name': rel_name(fqdn, zone, apex=''), 'type': 'TXT', 'value': '"%s"' % value,
            'ttl': self.ttl()}) or {}
        return got.get('id')

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('DELETE', '/dns/managed/%s/records/%s' % (self._id(zone), record_id),
                   missing_ok=True)
