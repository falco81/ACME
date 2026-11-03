# -*- coding: utf-8 -*-
"""DNS-01 at Netim, through its REST API 1.0 (1.0.26):

    POST   https://rest.netim.com/1.0/session/      Authorization: Basic <reseller id:API password>
                                                    -> {access_token}
    GET    .../domains/*                            [{domain, dateCreate, dateExpiration}]
    GET    .../domain/{domain}/zone/                [{hostname (host in the WSDL), type, value, options}]
    POST   .../domain/{domain}/zone/  {subdomain, type: TXT, value, options: {ttl}}
    DELETE .../domain/{domain}/zone/  {subdomain, type: TXT, value}   that one record away
    GET    .../operation/{ID_OPE}                   {ID_OPE, STATUS, MESSAGE, TYPE, DATE}
    DELETE .../session/                             the session closed

Every call after the first carries Authorization: Bearer <access_token>. A
change of the zone answers an operation (StructOperationResponse): Done, or
Pending - then acme asks /operation/{ID_OPE} until it is Done (or says why it
Failed or was Cancelled), as Netim's operations management describes; a
session is synchronous by default, so it is mostly Done at once. Each value
is a record of its own and is deleted by subdomain + type + value - other
values at the name stay. Netim allows 10 sessions at once by default: acme
opens one for each piece of work and closes it at the end.

Sources (the user's collection of Netim's documentation, api-docs/netim/):
api-secured.wsdl (the SOAP API 2.0, https://api.netim.com/2.0/api-secured.wsdl:
sessionOpen, queryDomainList, queryZoneList, domainZoneCreate,
domainZoneDelete, queryOpe, StructQueryZoneList) and notes.md, quoting
https://support.netim.com/en/docs/api-rest-1-0/get-started (the addresses,
the credentials), .../sessions-management/open-session and close-session,
.../domain-names/get-domains-list,
.../domain-names/domain-services/get-dns-records-list, create-dns-zone and
delete-domain-dns-zone, .../api-objects/structoptionszone and
structoperationresponse, .../operation-management/get-operation-information,
https://support.netim.com/en/docs/resellers/manage-my-reseller-account/sessions-management
(10 sessions, synchronous by default) and Netim's official Python client
https://github.com/netim-com/netim-apirest-client-for-python (APIRest.py - the
DELETE with its JSON body).

Less certain (the documentation leaves it open): no example of a real JSON
answer is published - a record listed is read with "hostname" or "host" (the
REST page and the WSDL differ), relative or whole; that "subdomain" is
relative to the domain (as the example "www"); how a TXT value is quoted (it
is written as it is; the value deleted is the one listed); the TTL's unit and
limits (the example has 365; 3600 is used when not set); a STATUS other than
Done, Pending, Failed and Cancelled (taken as done, the job says so); how
long a session lives without being closed. OT&E is reached over plain HTTP,
as Netim gives its address.
"""
from __future__ import annotations

import contextlib
import time
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _common as C
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, api, relative
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, basic, zone_field

ENDPOINTS = {'live': 'https://rest.netim.com/1.0', 'ote': 'http://oterest.netim.com/1.0'}
OP_WAIT_S = 300             # how long a Pending operation is waited for
OP_POLL_S = 5


class Netim(SoftZones, RecordApiDns):
    kind = 'netim'
    title = 'Netim'
    vendor = 'Netim'
    who = 'Netim'
    min_ttl = 1                     # no lowest TTL documented
    description = 'TXT records in a domain at Netim, through its REST API (a reseller account).'
    fields = [
        field('reseller', 'Reseller ID', 'text', required=True,
              help='The ID of your Netim reseller account.'),
        field('password', 'API password', 'secret', required=True,
              help='The DAS password from Netim\'s interface, section "API – DAS – OTE" - not '
                   'the account\'s password. Production and OT&E have different ones.'),
        zone_field(['reseller', 'password', 'endpoint'], label='Domain'),
        field('ttl', 'TTL (s)', 'number', default=3600, advanced=True),
        field('endpoint', 'API', 'select', default='live', advanced=True,
              options=[['live', 'rest.netim.com (production)'],
                       ['ote', 'oterest.netim.com (OT&E, the test system - plain HTTP)']]),
    ] + PROPAGATION_FIELDS

    def _base(self):
        return ENDPOINTS.get(str(self.c('endpoint') or 'live'), ENDPOINTS['live'])

    # -- the session --------------------------------------------------------------------------
    def _open(self):
        st, got = api(self.ctx, 'POST', self._base() + '/session/', None, {
            'Authorization': basic(self.c('reseller', ''), self.c('password', '')),
            'Content-Type': 'application/json', 'Accept-Language': 'EN'},
            who='Netim (sign-in)', raw_body=b'')
        tok = got.get('access_token') if isinstance(got, dict) else None
        if not tok:
            raise PluginError('Netim: signed in, but no access_token came back', retry=False)
        return str(tok)

    def _close(self, tok):
        try:
            api(self.ctx, 'DELETE', self._base() + '/session/', None, {
                'Authorization': 'Bearer ' + tok, 'Content-Type': 'application/json'},
                who='Netim')
        except PluginError as e:
            self.ctx.debug('Netim: the session was not closed (%s)' % e)

    @contextlib.contextmanager
    def session(self):
        """One session for the work inside, closed at the end (Netim allows 10 at once)."""
        if getattr(self, '_tok', None):
            yield
            return
        self._tok = self._open()
        try:
            yield
        finally:
            tok, self._tok = self._tok, None
            if tok:
                self._close(tok)

    def _call(self, method, path, body=None):
        with self.session():
            for again in (True, False):
                try:
                    st, got = api(self.ctx, method, self._base() + path, body, {
                        'Authorization': 'Bearer ' + self._tok, 'Accept-Language': 'EN'},
                        who='Netim')
                    return got
                except PluginError as e:
                    if not (again and 'said 401' in str(e)):
                        raise
                    self.ctx.debug('Netim: the session was refused - a new one')
                    self._tok = self._open()

    def _done(self, got, what):
        """Wait for a zone change's operation to be Done (it says so when it Failed)."""
        op = got if isinstance(got, dict) else {}
        until = time.time() + OP_WAIT_S
        while True:
            status = str(op.get('STATUS') or '').strip().lower()
            if status != 'pending':
                break
            if getattr(self.ctx, 'cancelled', lambda: False)():
                raise PluginError('stopped while Netim was still at %s' % what)
            if time.time() > until:
                raise PluginError('Netim: %s is still pending after %d s (operation %s)' % (
                    what, OP_WAIT_S, op.get('ID_OPE')))
            C.SLEEP(OP_POLL_S)
            op = self._call('GET', '/operation/%s' % urllib.parse.quote(str(op.get('ID_OPE')))) \
                or {}
        if status in ('failed', 'cancelled'):
            words = op.get('MESSAGE') or status
            raise PluginError('Netim could not %s: %s' % (what, words), detail=str(op),
                              retry=False)
        if status not in ('done', ''):
            self.ctx.step('Netim: %s answered the status %s - taken as done' % (
                what, op.get('STATUS')), 'warn')
        return op

    # -- zones and records --------------------------------------------------------------------
    def zone_names(self):
        got = self._call('GET', '/domains/*') or []
        if isinstance(got, dict):
            got = got.get('domains') or got.get('data') or []
        return [d.get('domain') if isinstance(d, dict) else d for d in got
                if (isinstance(d, dict) and d.get('domain')) or isinstance(d, str)]

    def _zone_rows(self, zone):
        got = self._call('GET', '/domain/%s/zone/' % urllib.parse.quote(D.norm(zone))) or []
        if isinstance(got, dict):
            got = got.get('records') or got.get('data') or []
        return [r for r in got if isinstance(r, dict)]

    def txt_records(self, zone, fqdn):
        rel = relative(fqdn, zone).lower()
        out = []
        for r in self._zone_rows(zone):
            host = r.get('hostname') if r.get('hostname') is not None else r.get('host')
            host = D.norm(host)                     # relative or whole: both read
            if str(r.get('type') or '').upper() == 'TXT' and (
                    host == rel or host == D.norm(fqdn) or (rel == '@' and host in ('', '@'))):
                out.append((str(r.get('value')), str(r.get('value'))))
        return out

    def create_txt(self, zone, fqdn, value):
        got = self._call('POST', '/domain/%s/zone/' % urllib.parse.quote(D.norm(zone)), {
            'subdomain': relative(fqdn, zone), 'type': 'TXT', 'value': value,
            'options': {'ttl': self.ttl()}})
        self._done(got, 'add the TXT record %s' % fqdn)
        return value

    def delete_txt(self, zone, fqdn, record_id, value):
        got = self._call('DELETE', '/domain/%s/zone/' % urllib.parse.quote(D.norm(zone)), {
            'subdomain': relative(fqdn, zone), 'type': 'TXT', 'value': record_id})
        self._done(got, 'delete the TXT record %s' % fqdn)

    def add_txt(self, fqdn, value):
        with self.session():
            return RecordApiDns.add_txt(self, fqdn, value)

    def del_txt(self, fqdn, value, handle):
        with self.session():
            return RecordApiDns.del_txt(self, fqdn, value, handle)

    def test(self):
        with self.session():
            z = D.norm(self.c('zone', ''))
            if z:
                n = len(self._zone_rows(z))
                return 'Netim: signed in; the domain %s has %d record(s)' % (z, n)
            return RecordApiDns.test(self)

    def catalog(self, key):
        with self.session():
            return SoftZones.catalog(self, key)

