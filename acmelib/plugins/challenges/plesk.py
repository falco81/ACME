# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a Plesk server, through its XML API (API-RPC):

    POST https://{plesk}:8443/enterprise/control/agent.php     Content-Type: text/xml

    <packet><site><get><filter><name>example.com</name></filter><dataset><gen_info/></dataset></get></site></packet>
                                         the site (domain) and its id; an empty filter: every site
    <packet><dns><get_rec><filter><site-id>12</site-id></filter></get_rec></dns></packet>
                                         its records: <result><id/><data><type/><host/><value/></data></result>
    <packet><dns><add_rec><site-id>12</site-id><type>TXT</type><host>_acme-challenge.www</host>
            <value>..</value></add_rec></dns></packet>   -> <result><status>ok</status><id/></result>
    <packet><dns><del_rec><filter><id>34</id></filter></del_rec></dns></packet>

Signed in with the headers HTTP_AUTH_LOGIN and HTTP_AUTH_PASSWD (an
administrator or the customer owning the domains), or KEY with a secret
key of the XML API (secret_key create, tied to the address acme calls
from). "host" is written relative to the domain; Plesk lists it whole (with
its final dot) - both are read. Each value is a record of its own; cleanup
deletes only the records holding ours.

Sources: Plesk's official PHP library of the XML API
(https://github.com/plesk/api-php-lib: src/Api/Client.php - the address
/enterprise/control/agent.php on 8443, the KEY / HTTP_AUTH_LOGIN /
HTTP_AUTH_PASSWD headers, the packet; src/Api/Operator/Dns.php - add_rec,
get_rec, del_rec; src/Api/Operator/Site.php and Operator.php - get with
filter and dataset gen_info; src/Api/Struct/Dns/Info.php; tests/DnsTest.php -
a TXT record by site-id, type, host, value). The reference is
https://docs.plesk.com/en-US/obsidian/api-rpc/about-xml-api/reference.28784/.
Cross-checked with lego's providers/dns/plesk.
"""
from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, as_bool, http_call,
                                                said_error)
from acmelib.plugins.challenges._records import RecordApiDns, rel_name, xml_text


def packet(op, cmd, items):
    """<packet><op><cmd>items</cmd></op></packet> - items a list of (tag, value
    or a list of (tag, value)) pairs."""
    root = ET.Element('packet')
    c = ET.SubElement(ET.SubElement(root, op), cmd)

    def put(parent, pairs):
        for tag, v in pairs:
            e = ET.SubElement(parent, tag)
            if isinstance(v, list):
                put(e, v)
            elif v is not None:
                e.text = str(v)
    put(c, items)
    return b'<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(root)


class Plesk(RecordApiDns):
    kind = 'plesk'
    title = 'Plesk'
    vendor = 'Plesk'
    who = 'Plesk'
    min_ttl = 60
    description = 'TXT records in the DNS of a Plesk server, through its XML API.'
    fields = [
        field('host', 'Plesk address', 'text', required=True, placeholder='plesk.example.com',
              help='The Plesk server as its panel is reached (name, name:port or https://…); '
                   'the port is 8443 when not given.'),
        field('auth', 'Sign in with', 'select', default='password',
              options=[['password', 'login and password'], ['key', 'a secret key']]),
        field('user', 'Login', 'text', default='', show_if={'auth': ['password']},
              help='An administrator, or the customer the domains belong to.'),
        field('password', 'Password', 'secret', default='', show_if={'auth': ['password']}),
        field('secret_key', 'Secret key', 'secret', default='', show_if={'auth': ['key']},
              help='A secret key of the XML API made for acme (secret_key create, tied to '
                   'acme\'s address).'),
        field('zone', 'Domain', 'text', default='', placeholder='example.com',
              help='Empty: the longest domain of the server the name is in.'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _url(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the Plesk address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the Plesk address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d/enterprise/control/agent.php' % (u.scheme or 'https', host,
                                                            port or 8443)

    def _call(self, op, cmd, items):
        h = {'Content-Type': 'text/xml', 'User-Agent': 'acme-challenge'}
        if self.c('auth', 'password') == 'key':
            h['KEY'] = str(self.c('secret_key', ''))
        else:
            h['HTTP_AUTH_LOGIN'] = str(self.c('user', ''))
            h['HTTP_AUTH_PASSWD'] = str(self.c('password', ''))
        st, _rh, got = http_call(self.ctx, 'POST', self._url(), packet(op, cmd, items), h,
                                 who='Plesk', verify=as_bool(self.c('verify_tls', True)))
        if st != 200:
            raise said_error('Plesk', st, None, got)
        try:
            x = ET.fromstring(got)
        except ET.ParseError:
            raise PluginError('Plesk answered something that is not XML', detail=str(got[:300]))
        sysx = x.find('system')
        if sysx is not None and xml_text(sysx, 'status') == 'error':
            words = xml_text(sysx, 'errtext') or 'error %s' % xml_text(sysx, 'errcode')
            raise PluginError('Plesk said no: %s' % words, detail=words,
                              retry=xml_text(sysx, 'errcode') not in ('1001', '1002', '1006'))
        return x.findall('./%s/%s/result' % (op, cmd))

    @staticmethod
    def _ok(results, what):
        for r in results:
            if xml_text(r, 'status') == 'error':
                words = xml_text(r, 'errtext') or 'error %s' % xml_text(r, 'errcode')
                raise PluginError('Plesk could not %s: %s' % (what, words), detail=words,
                                  retry=False)
        return results

    def zone_names(self):
        out = []
        for r in self._call('site', 'get', [('filter', []), ('dataset', [('gen_info', [])])]):
            gi = r.find('./data/gen_info')
            name = xml_text(gi, 'ascii-name') or xml_text(gi, 'name')
            if xml_text(r, 'status') == 'ok' and name:
                out.append(name)
        return out

    def _site(self, zone):
        if not hasattr(self, '_sites'):
            self._sites = {}
        z = D.norm(zone)
        if z not in self._sites:
            got = self._ok(self._call('site', 'get', [('filter', [('name', z)]), (
                'dataset', [('gen_info', [])])]), 'find the domain %s' % z)
            ids = [xml_text(r, 'id') for r in got if xml_text(r, 'id')]
            if not ids:
                raise PluginError('Plesk has no domain %s for this login' % z, retry=False)
            self._sites[z] = ids[0]
        return self._sites[z]

    def txt_records(self, zone, fqdn):
        rel = rel_name(fqdn, zone, apex='')
        out = []
        for r in self._call('dns', 'get_rec', [('filter', [('site-id', self._site(zone))])]):
            d = r.find('data')
            host = xml_text(d, 'host')
            if xml_text(r, 'status') == 'ok' and xml_text(d, 'type').upper() == 'TXT' and \
                    (D.norm(host) == D.norm(fqdn) or host == rel):
                out.append((xml_text(r, 'id'), xml_text(d, 'value')))
        return out

    def create_txt(self, zone, fqdn, value):
        got = self._ok(self._call('dns', 'add_rec', [
            ('site-id', self._site(zone)), ('type', 'TXT'),
            ('host', rel_name(fqdn, zone, apex='')), ('value', value)]),
            'add the TXT record %s' % fqdn)
        return xml_text(got[0], 'id') if got else None

    def delete_txt(self, zone, fqdn, record_id, value):
        self._ok(self._call('dns', 'del_rec', [('filter', [('id', record_id)])]),
                 'delete the TXT record %s' % fqdn)
