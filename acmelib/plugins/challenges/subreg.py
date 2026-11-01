# -*- coding: utf-8 -*-
"""DNS-01 at Subreg.cz (and Gransy, which runs the same system), through its
SOAP API - an envelope written here by hand, sent with ctx.http:

    POST https://soap.subreg.cz/cmd.php   SOAPAction: http://soap.subreg.cz/soap#COMMAND
    <ns1:COMMAND><data><ssid>..</ssid> ...</data></ns1:COMMAND>

    Login             {login, password}                   -> {ssid}
    Domains_List      {ssid}                              -> {domains: [{name, expire}], count}
    Get_DNS_Zone      {ssid, domain}                      -> {domain, records: [{id, name, type, content, prio, ttl}]}
    Add_DNS_Record    {ssid, domain, record: {name, type, content, prio, ttl}}   -> {record_id}
    Delete_DNS_Record {ssid, domain, record: {id}}

Each answer is a PHP-SOAP map: {status: ok|error, data: {...}} or
{status: error, error: {errormsg, errorcode: {major, minor}}}.

Sources: https://soap.subreg.cz/manual/?cmd=Login (and ?cmd=Add_DNS_Record,
?cmd=Get_DNS_Zone, ?cmd=Delete_DNS_Record, ?cmd=Domains_List) - the manual
could not be fetched from where this was written; the envelope, the
SOAPAction and the field names are as acme.sh's dnsapi/dns_subreg.sh and the
python-subreg library (PyPI) send and read them. Less certain: whether
"name" in Get_DNS_Zone is relative to the domain (as Add_DNS_Record takes it)
- both a relative and a full name are taken here. The API user is made in
Subreg's administration (Settings → API) with the addresses it may call from.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, http_call, suffixes
from acmelib.plugins.challenges._records import RecordApiDns, rel_name

API = 'https://soap.subreg.cz/cmd.php'
NS = 'http://soap.subreg.cz/soap'


def envelope(command, data):
    """The SOAP request: data a dict (nested dicts become nested elements)."""
    def put(d):
        out = []
        for k, v in d.items():
            if isinstance(v, dict):
                out.append('<%s>%s</%s>' % (k, put(v), k))
            else:
                out.append('<%s>%s</%s>' % (k, escape(str(v)), k))
        return ''.join(out)
    return ('<?xml version="1.0" encoding="UTF-8"?>'
            '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
            'xmlns:ns1="%s" xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            'xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" '
            'SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<SOAP-ENV:Body><ns1:%s><data>%s</data></ns1:%s></SOAP-ENV:Body>'
            '</SOAP-ENV:Envelope>' % (NS, command, put(data), command)).encode('utf-8')


def _local(tag):
    return str(tag).rsplit('}', 1)[-1]


def soap_value(el):
    """A PHP-SOAP value as Python: a map ({key, value} items) a dict, an
    array (items without a key) a list, else its text."""
    items = [c for c in el if _local(c.tag) == 'item']
    if not items:
        return (el.text or '').strip()
    if any(_local(k.tag) == 'key' for k in items[0]):
        out = {}
        for it in items:
            key = val = None
            for c in it:
                if _local(c.tag) == 'key':
                    key = (c.text or '').strip()
                elif _local(c.tag) == 'value':
                    val = c
            if key is not None:
                out[key] = soap_value(val) if val is not None else ''
        return out
    return [soap_value(it) for it in items]


def soap_answer(raw):
    """The map an answer holds (the return of the response element)."""
    root = ET.fromstring(raw)
    for el in root.iter():
        if _local(el.tag) == 'Fault':
            raise PluginError('Subreg said: %s' % ' '.join(
                (c.text or '').strip() for c in el.iter() if _local(c.tag) == 'faultstring'),
                detail=raw)
    for el in root.iter():
        if _local(el.tag) == 'return':
            return soap_value(el)
    for el in root.iter():
        if _local(el.tag).endswith('Response'):
            for c in el:
                return soap_value(c)
    return {}


class Subreg(RecordApiDns):
    kind = 'subreg'
    title = 'Subreg.cz'
    vendor = 'Subreg'
    who = 'Subreg'
    min_ttl = 60
    description = 'TXT records in a domain at Subreg.cz (or Gransy), through its SOAP API.'
    fields = [
        field('login', 'API login', 'text', required=True,
              help='Subreg administration → Settings → API: the login of the API user (it '
                   'may be the account\'s own), and the IP address acme calls from allowed '
                   'there.'),
        field('password', 'API password', 'secret', required=True),
        field('zone', 'Domain', 'text', default='', placeholder='example.cz',
              help='Empty: the longest domain of the account the name is in.'),
        field('ttl', 'TTL (s)', 'number', default=120, advanced=True),
        field('api', 'API address', 'text', default=API, advanced=True,
              help='Gransy and Subreg\'s test system have their own address of the same API.'),
    ] + PROPAGATION_FIELDS

    def _post(self, command, data):
        st, _rh, got = http_call(self.ctx, 'POST', str(self.c('api', API)), envelope(command, data), {
            'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '%s#%s' % (NS, command),
            'User-Agent': 'acme-challenge'}, who='Subreg')
        try:
            ans = soap_answer(got or b'')
        except ET.ParseError:
            raise PluginError('Subreg said %s, and not in SOAP' % st, detail=got)
        if not isinstance(ans, dict) or ans.get('status') != 'ok':
            err = (ans.get('error') if isinstance(ans, dict) else None) or {}
            code = err.get('errorcode') if isinstance(err, dict) else {}
            words = 'Subreg said no to %s: %s' % (command, (err.get('errormsg') if isinstance(
                err, dict) else '') or st)
            if isinstance(code, dict) and code.get('major'):
                words += ' (%s.%s)' % (code.get('major'), code.get('minor'))
            raise PluginError(words, detail=got, retry=st >= 500)
        return ans.get('data') or {}

    def _call(self, command, data=None):
        if not getattr(self, '_ssid', None):
            got = self._post('Login', {'login': str(self.c('login', '')),
                                       'password': str(self.c('password', ''))})
            self._ssid = got.get('ssid') if isinstance(got, dict) else None
            if not self._ssid:
                raise PluginError('Subreg: signed in, but no session came back', retry=False)
        d = {'ssid': self._ssid}
        d.update(data or {})
        return self._post(command, d)

    def zone_names(self):
        got = self._call('Domains_List').get('domains') or []
        if isinstance(got, dict):
            got = list(got.values())
        return [d.get('name') if isinstance(d, dict) else d for d in got]

    def zone_hint(self, fqdn):
        z = D.norm(self.c('zone', ''))
        if z and D.in_zone(fqdn, z):
            return z
        try:
            return RecordApiDns.zone_hint(self, fqdn)
        except PluginError:
            pass
        for cand in suffixes(fqdn):              # a zone in Subreg's DNS not registered there
            try:
                self._call('Get_DNS_Zone', {'domain': cand})
                return cand
            except PluginError:
                continue
        raise PluginError('Subreg has no zone for %s that this login may see' % D.norm(fqdn),
                          retry=False)

    def txt_records(self, zone, fqdn):
        recs = self._call('Get_DNS_Zone', {'domain': zone}).get('records') or []
        if isinstance(recs, dict):
            recs = list(recs.values())
        rel = rel_name(fqdn, zone, apex='')
        out = []
        for r in recs:
            if not isinstance(r, dict) or str(r.get('type')).upper() != 'TXT':
                continue
            n = D.norm(r.get('name') or '')
            if n in (rel, fqdn) or (not n and fqdn == zone):
                out.append((r.get('id'), r.get('content')))
        return out

    def create_txt(self, zone, fqdn, value):
        got = self._call('Add_DNS_Record', {'domain': zone, 'record': {
            'name': rel_name(fqdn, zone, apex=''), 'type': 'TXT', 'content': value, 'prio': 0,
            'ttl': self.ttl()}})
        return got.get('record_id') if isinstance(got, dict) else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._call('Delete_DNS_Record', {'domain': zone, 'record': {'id': record_id}})

    def test(self):
        self._ssid = None
        return RecordApiDns.test(self)
