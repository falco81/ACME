# -*- coding: utf-8 -*-
"""
Certificates from GlobalSign's Managed SSL (MSSL, GCC) through its SOAP API: the
domains of the certificate must be approved in the account's MSSL profile
(pre-vetted) - acme finds them there (GetDomains), or, with the DNS method,
adds and verifies a domain itself (AddDomainToProfile, the TXT record put in
place by the certificate's own validation, VerifyMsslDomain). The request (CSR)
is then reissued inside an order bought already (ReIssue), or ordered (PVOrder -
a purchase, only when "Allow new orders (paid)" is on), the order read until
it is issued (GetOrderByOrderID, with the certificate and its CA certificates).
The account's orders are listed for Certificates → Import from a source.

GlobalSign Atlas (HVCA) is the `globalsign_atlas` source; this module is for an
MSSL account of GCC (GlobalSign Certificate Center).

What the API is, and from where - GlobalSign's own documents (read 2026-11): the
"MSSL API User Guide v2.19"
(https://www.globalsign.com/en/repository/globalsign-mssl-api-user-guide.pdf) and
the WSDLs of the services (https://system.globalsign.com/kb/ws/v1/ManagedSSLService?wsdl,
https://system.globalsign.com/kb/ws/v1/GASService?wsdl):

* SOAP 1.1 document/literal, namespace https://system.globalsign.com/kb/ws/v1/, the
  child elements unqualified. ManagedSSLService: GetMSSLProfiles, GetDomains,
  AddDomainToProfile, VerifyMsslDomain, PVOrder, RevokeMSSLOrder. GASService:
  GetOrderByOrderID, GetOrderByDateRange, ReIssue. Production
  https://system.globalsign.com/kb/ws/v1/..., test https://test-gcc.globalsign.com/kb/ws/v1/...
* Every request: <Request><OrderRequestHeader> (or <QueryRequestHeader>)
  <AuthToken><UserName/><Password/></AuthToken>; every answer a header with
  <SuccessCode> (0 done, 1 a warning, -1 failed) and <Errors><Error><ErrorCode/>
  <ErrorMessage/></Error></Errors>.
* GetDomains {ProfileID} -> DomainDetails/DomainDetail {DomainID, DomainName,
  DomainStatus (3 approved; 7, 9, 10 being renewed - may issue; 0, 1, 2 being
  vetted), DomainValidationCode}.
* AddDomainToProfile {MSSLProfileID, DomainName, VettingLevel OV, VettingType DNS,
  ContactInfo} -> {MSSLDomainID, DnsTXT}; the TXT record at the domain (a
  TagLocation: the domain or one above it) holds DnsTXT; then VerifyMsslDomain
  {DomainID, TagLocation, VettingType DNS}.
* PVOrder {OrderRequestParameter {ProductCode, BaseOption, OrderKind new, Licenses 1,
  Options/Option {OptionName SAN, OptionValue true}, ValidityPeriod/Months, CSR},
  MSSLProfileID, MSSLDomainID, ContactInfo, SANEntries/SANEntry {SANOptionType,
  SubjectAltName}} -> {OrderID}.
* ReIssue {OrderParameter {CSR}, TargetOrderID} -> {OrderID (the new one),
  TargetOrderID} - "replaces the first certificate with an identical one, except
  for a new key pair".
* GetOrderByOrderID {OrderID, OrderQueryOption {ReturnOrderOption,
  ReturnCertificateInfo, ReturnFulfillment, ReturnCACerts, ReturnSANEntries}} ->
  OrderDetail {OrderInfo {OrderStatus: 1 initial, 2 phishing check, 3 cancelled, 4
  issued, 5 cancelled (issued), 6 waiting for revocation, 7 revoked},
  CertificateInfo, SANEntries, Fulfillment {ServerCertificate/X509Cert,
  CACertificates/CACertificate/CACert}}.
* GetOrderByDateRange {FromDate, ToDate, OrderQueryOption} -> OrderDetails (at most
  500 an answer - asked 30 days at a time).
* RevokeMSSLOrder {OrderID, RevokeReason 0 | 1 | 3 | 4 | 5}.

LESS CERTAIN (the documents leave it open): whether DnsTXT holds the prefix
"globalsign-domain-verification=" (the TXT holds DnsTXT as answered); which domain a
name needs (the shortest approved domain of the profile it ends in is taken; a
domain added by acme is the name itself without "*." and "www." - set "Domain to
add" for another); the SANOptionType of a name (7 FQDN SAN, 13 for a wildcard);
whether a SAN may be of another approved domain than the common name's (the common
name's MSSLDomainID is sent); the HTTP method of the domain validation is not
offered (what gsdv.txt holds is not said - the MetaTag is a meta tag); the date-time
format of the queries (YYYY-MM-DDTHH:MM:SS.000Z, the guide's "XML Simple Type").
A renewal order (OrderKind renewal) is not made: a certificate is reissued inside
its order, or a new order is made (only with "Allow new orders (paid)").
"""
from __future__ import annotations

import calendar
import json
import re
import time
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

NS = 'https://system.globalsign.com/kb/ws/v1/'
HOSTS = {'production': 'https://system.globalsign.com', 'test': 'https://test-gcc.globalsign.com'}
MSSL = '/kb/ws/v1/ManagedSSLService'
GAS = '/kb/ws/v1/GASService'
# MSSL API User Guide 8.9: the products of PVOrder that take a CSR.
PRODUCTS = [('PV_SHA2', 'OrganizationSSL (SHA-256)'), ('PEV_SHA2', 'ExtendedSSL (EV, SHA-256)'),
            ('PV_CLOUD', 'CloudSSL (SHA-256)'), ('PV_CLOUD_ECC2', 'CloudSSL (ECDSA)'),
            ('PV_INTRA_SHA2', 'IntranetSSL (SHA-256)'),
            ('PV_INTRA_ECCP256', 'IntranetSSL (ECDSA)')]
APPROVED = ('3', '7', '9', '10')     # 10.3: "Can Issue: Yes"
VETTING = ('0', '1', '2')
ISSUED = '4'
WAITING = ('1', '2')
STATUS_WORDS = {'1': 'initial', '2': 'waiting for the phishing check', '3': 'cancelled - not issued',
                '4': 'issued', '5': 'cancelled - issued', '6': 'waiting for revocation',
                '7': 'revoked'}
REVOKE = {0: '0', 1: '1', 3: '3', 4: '4', 5: '5'}


# ---------------------------------------------------------------------------
# SOAP by hand
# ---------------------------------------------------------------------------
def _xml(items):
    out = []
    for k, v in items:
        if v is None or v == '':
            continue
        if isinstance(v, list):
            out.append('<%s>%s</%s>' % (k, _xml(v), k))
        elif isinstance(v, bool):
            out.append('<%s>%s</%s>' % (k, 'true' if v else 'false', k))
        else:
            out.append('<%s>%s</%s>' % (k, escape(str(v)), k))
    return ''.join(out)


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def kids(el, name):
    return [c for c in list(el) if _local(c.tag) == name] if el is not None else []


def kid(el, name):
    got = kids(el, name)
    return got[0] if got else None


def text(el, name, default=''):
    c = kid(el, name)
    return (c.text or '').strip() if c is not None and c.text else default


def find(el, name):
    if el is None:
        return None
    for c in el.iter():
        if _local(c.tag) == name:
            return c
    return None


def find_all(el, name):
    return [c for c in el.iter() if _local(c.tag) == name] if el is not None else []


def _stamp(epoch):
    return time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime(epoch))


def _when(v):
    s = str(v or '').strip()
    for fmt, n in (('%Y-%m-%dT%H:%M:%S', 19), ('%Y-%m-%d', 10)):
        try:
            return calendar.timegm(time.strptime(s[:n], fmt))
        except ValueError:
            continue
    return None


class GlobalSignMsslIssuer(Issuer):
    kind = 'globalsign_mssl'
    title = 'GlobalSign MSSL (GCC API)'
    description = ('Certificates of a GlobalSign Managed SSL account through its SOAP API: the '
                   'domains approved in the MSSL profile (or added and verified by a DNS TXT '
                   'record put in place by the certificate\'s validation), reissued inside an '
                   'order or ordered (only when paid orders are allowed). Lists the account\'s '
                   'orders for importing.')
    vendor = 'GlobalSign'
    doc = 'docs/sources.md'
    needs_challenge = False         # per instance: True for the DNS method (see __init__)
    challenge_types = ('dns-01',)
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # GetOrderByDateRange + GetOrderByOrderID: Import
    dcv_field = 'dcv'
    dcv_default = 'profile'
    dcv = {
        'profile': {'proof': None, 'words': 'Approved in the MSSL profile already',
                    'record': 'nothing: the domain is approved in the profile (GCC → MSSL → '
                              'Manage Domains)'},
        'dns': {'proof': 'txt-any', 'words': 'DNS TXT record (AddDomainToProfile, DNS)',
                'record': 'TXT at the domain holding GlobalSign\'s value (DnsTXT)'},
    }
    fields = [
        field('user', 'API user', 'text', required=True,
              help='The GCC user GlobalSign set up for API access.'),
        field('password', 'Password', 'secret', required=True),
        field('environment', 'Environment', 'select', default='production',
              options=[['production', 'Production (system.globalsign.com)'],
                       ['test', 'Test (test-gcc.globalsign.com - an account on request)']]),
        field('profile_id', 'MSSL profile', 'catalog', catalog='profiles', required=True,
              placeholder='01_SSL_1234', depends=['user', 'password', 'environment'],
              help='Load the list: the MSSL profiles of the account (GetMSSLProfiles) - an ID '
                   'can be typed too (GCC → MSSL → Manage Domains & Profiles).'),
        field('dcv', 'Domain validation (DCV)', 'select', default='profile',
              options=[['profile', 'The domains are approved in the profile already'],
                       ['dns', 'DNS TXT record (a domain not approved is added and verified by '
                               'the certificate\'s DNS validation)']],
              help='MSSL validates domains, not certificates: an approved domain covers its '
                   'names for 199 days.'),
        field('dcv_domain', 'Domain to add', 'text', placeholder='example.com',
              show_if={'dcv': ['dns']},
              help='The domain added to the profile for names not covered (its TXT record is put '
                   'in place). Empty: each name itself, without "*." and "www.".'),
        field('order_id', 'Order to reuse', 'text', placeholder='CE20261103123456',
              help='An order bought already: its certificate is reissued with acme\'s request '
                   '(ReIssue). Empty: the order acme made last for the certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything - it only reissues inside orders bought '
                   'already, and stops with words where a purchase would be needed.'),
        field('product', 'Product of a new order', 'catalog', catalog='products',
              default='PV_SHA2', placeholder='PV_SHA2',
              help='Load the list: the MSSL products of GlobalSign\'s guide - a code can be '
                   'typed too.'),
        field('months', 'Validity of a new order', 'select', default='6',
              options=[['6', '6 months (199 days; OrganizationSSL, ExtendedSSL)'],
                       ['3', '3 months (90 days; CloudSSL)'],
                       ['13', '13 months (IntranetSSL)'], ['24', '24 months (IntranetSSL)'],
                       ['36', '36 months (IntranetSSL)'], ['60', '60 months (IntranetSSL)']]),
        field('contact_firstname', 'Contact: first name', 'text', required=True),
        field('contact_lastname', 'Contact: last name', 'text', required=True),
        field('contact_phone', 'Contact: phone', 'text', required=True, placeholder='+420123456789'),
        field('contact_email', 'Contact: e-mail', 'text', required=True),
        field('list_days', 'Orders listed (days back)', 'number', default=400, advanced=True,
              help='Import from a source reads the orders of this many days, 30 at a time.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=300, advanced=True,
              help='Longer: it is asked for again at the next try - nothing is ordered twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=20, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') == 'dns'
        self._sleep = time.sleep

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _host(self):
        return HOSTS.get(self._s('environment') or 'production') or HOSTS['production']

    def _auth(self, header):
        return [(header, [('AuthToken', [('UserName', self._s('user')),
                                         ('Password', self._s('password'))])])]

    def call(self, service, op, items, what='', query=False):
        """The answer's <Response>, or a PluginError in words."""
        if not self._s('user') or not self._s('password'):
            raise PluginError('set the API user and the password', retry=False)
        req = self._auth('QueryRequestHeader' if query else 'OrderRequestHeader') + list(items)
        body = ('<?xml version="1.0" encoding="UTF-8"?>'
                '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
                'xmlns:ws="%s"><soapenv:Body><ws:%s><Request>%s</Request></ws:%s>'
                '</soapenv:Body></soapenv:Envelope>' % (NS, op, _xml(req), op)).encode('utf-8')
        status, _h, data = sc.http(self.ctx, 'POST', self._host() + service, body,
                                   {'Content-Type': 'text/xml; charset=utf-8', 'SOAPAction': '""',
                                    'Accept': 'text/xml'}, who='GlobalSign')
        pw = self._s('password')
        said = (data or b'').decode('utf-8', 'replace')
        if pw:
            said = said.replace(escape(pw), '********').replace(pw, '********')
        try:
            root = ET.fromstring(data or b'')
        except ET.ParseError:
            raise PluginError('GlobalSign answered %s to %s, and not in SOAP' % (
                status, what or op), detail=said[:3000], retry=status >= 500)
        fault = find(root, 'Fault')
        if fault is not None:
            raise PluginError('GlobalSign refused %s: %s' % (
                what or op, text(fault, 'faultstring') or 'a SOAP fault'),
                detail=said[:3000], retry=status >= 500)
        resp = find(find(root, op + 'Response'), 'Response')
        code = (find(resp, 'SuccessCode').text or '').strip() if find(resp, 'SuccessCode') \
            is not None else ''
        errs = ['%s%s' % (text(e, 'ErrorCode') or '?', (' ' + text(e, 'ErrorMessage'))
                          if text(e, 'ErrorMessage') else '') for e in find_all(resp, 'Error')]
        if resp is None or code not in ('0', '1'):
            wrong = any(e.startswith('-4001') for e in errs)
            raise PluginError('GlobalSign refused %s: %s%s' % (
                what or op, '; '.join(errs) or ('SuccessCode %s' % (code or '?')),
                ' - the API user or password is wrong' if wrong else ''),
                detail=said[:3000], retry=any(e.startswith('-300') for e in errs))
        if code == '1':
            sc.say(self.ctx, 'GlobalSign warns about %s: %s' % (what or op,
                                                                 '; '.join(errs) or '?'), 'warn')
        return resp

    @staticmethod
    def _oid(v):
        v = str(v or '').strip()
        if not re.match(r'^[A-Za-z0-9_-]{4,50}\Z', v):
            raise PluginError('"%s" is not a GlobalSign order ID' % v, retry=False)
        return v

    def _profile(self):
        p = self._s('profile_id')
        if not p:
            raise PluginError('set the MSSL profile (its ID - Load the list)', retry=False)
        return p

    # -- the lists of the form ------------------------------------------------------------------
    def profiles(self):
        resp = self.call(MSSL, 'GetMSSLProfiles', [], what='the MSSL profiles', query=True)
        out = []
        for d in find_all(resp, 'SearchMsslProfileDetail'):
            pid = text(d, 'MSSLProfileId')
            org = find(d, 'OrganizationName')
            if pid:
                out.append([pid, '%s - %s%s' % (
                    pid, (org.text or '').strip() if org is not None and org.text else '?',
                    (' (%s)' % text(d, 'VettingLevel')) if text(d, 'VettingLevel') else '')])
        return out

    def catalog(self, key):
        """The MSSL profiles (GetMSSLProfiles), or the products of the guide. Read-only."""
        if key == 'profiles':
            opts = self.profiles()
            return {'options': opts, 'said': '%d MSSL profile(s)' % len(opts)}
        if key == 'products':
            return {'options': [[c, '%s - %s' % (c, w)] for c, w in PRODUCTS],
                    'said': '%d MSSL products (GlobalSign\'s guide)' % len(PRODUCTS)}
        raise PluginError('there is no list called %s here' % key, retry=False)

    def test(self):
        n = len(self.profiles())
        words = 'GlobalSign answers: signed in; %d MSSL profile(s)' % n
        if self._s('profile_id'):
            approved = [d for d in self.domains() if d['status'] in APPROVED]
            words += '; profile %s has %d approved domain(s)' % (self._s('profile_id'),
                                                                 len(approved))
        return words + '; new paid orders %s' % (
            'ALLOWED' if sc.as_bool(self.c('allow_paid')) else 'not allowed')

    # -- the domains of the profile ---------------------------------------------------------------
    def domains(self):
        resp = self.call(MSSL, 'GetDomains', [('ProfileID', self._profile())],
                         what='the domains of the profile', query=True)
        out = []
        for d in find_all(resp, 'DomainDetail'):
            out.append({'id': text(d, 'DomainID'), 'name': text(d, 'DomainName').lower()
                        .rstrip('.'), 'status': text(d, 'DomainStatus'),
                        'code': text(d, 'DomainValidationCode')})
        return out

    @staticmethod
    def covering(domains, name, statuses=APPROVED):
        """The shortest domain of `statuses` that `name` is or ends in."""
        n = _dcv.base_of(name)
        got = [d for d in domains if d['status'] in statuses and d['name'] and
               (n == d['name'] or n.endswith('.' + d['name']))]
        return min(got, key=lambda d: len(d['name'])) if got else None

    def _to_add(self, name):
        want = self._s('dcv_domain').lower().rstrip('.')
        n = _dcv.base_of(name)
        if want and (n == want or n.endswith('.' + want)):
            return want
        return n[4:] if n.startswith('www.') and n.count('.') > 1 else n

    def _contact(self, native=False):
        c = []
        for k, f in (('FirstName', 'contact_firstname'), ('LastName', 'contact_lastname'),
                     ('Phone', 'contact_phone'), ('Email', 'contact_email')):
            v = self._s(f)
            if not v:
                raise PluginError('set the contact (first and last name, phone, e-mail)',
                                  retry=False)
            c.append((k, v))
            if native and k in ('FirstName', 'LastName'):
                c.append((k + 'Native', v))
        return c

    def _domain_dcv(self, req, slot, held, placer):
        """Every name covered by an approved domain of the profile; with the DNS method
        the missing domains added and verified (the TXT records put in place first)."""
        doms = self.domains()
        missing = [n for n in req.names if not self.covering(doms, n)]
        if not missing:
            return doms
        if (self.c('dcv') or 'profile') != 'dns':
            raise PluginError('no approved domain of profile %s covers %s - approve the domain in '
                              'GCC (MSSL → Manage Domains) or choose the DNS TXT method' % (
                                  self._profile(), ', '.join(missing)), retry=False)
        todo = held.get('domains') or []
        for n in missing:
            dn = self._to_add(n)
            if any(t['name'] == dn for t in todo):
                continue
            have = next((d for d in doms if d['name'] == dn and d['status'] in VETTING
                         and d['code']), None)
            if have:
                todo.append({'name': dn, 'id': have['id'], 'txt': have['code']})
                continue
            resp = self.call(MSSL, 'AddDomainToProfile', [
                ('MSSLProfileID', self._profile()), ('DomainName', dn), ('VettingLevel', 'OV'),
                ('VettingType', 'DNS'), ('ContactInfo', self._contact(native=True))],
                what='adding %s to the profile' % dn)
            did, txt = text(resp, 'MSSLDomainID'), text(resp, 'DnsTXT')
            if not did or not txt:
                raise PluginError('GlobalSign added %s but said no domain ID or TXT value' % dn,
                                  retry=False)
            sc.say(self.ctx, 'the domain %s was added to profile %s (%s)' % (
                dn, self._profile(), did), 'ok')
            todo.append({'name': dn, 'id': did, 'txt': txt})
        held['domains'] = todo
        sc.pending_put(self.ctx, slot, req, held, ttl_days=30)
        recs = [{'domain': t['name'], 'type': 'txt', 'fqdn': t['name'], 'value': t['txt']}
                for t in todo]
        if not held.get('dcv'):
            held['dcv'] = placer.place_all(req, recs)
            sc.pending_put(self.ctx, slot, req, held, ttl_days=30)
        else:
            placer.refresh(req, held['dcv'])
        if any(p.get('how') == 'placed' for p in held['dcv']):
            placer.wait_visible(req, held['dcv'])
        for t in todo:
            self.call(MSSL, 'VerifyMsslDomain', [('DomainID', t['id']), ('TagLocation', t['name']),
                                                 ('VettingType', 'DNS')],
                      what='the verification of %s' % t['name'])
            sc.say(self.ctx, 'GlobalSign verified the domain %s' % t['name'], 'ok')
        placer.cleanup(req, held.get('dcv') or [])
        held['dcv'], held['domains'] = [], []
        sc.pending_put(self.ctx, slot, req, held, ttl_days=30)
        doms = self.domains()
        still = [n for n in req.names if not self.covering(doms, n)]
        if still:
            raise PluginError('the profile\'s domains do not cover %s yet - acme asks again at '
                              'the next try' % ', '.join(still))
        return doms

    # -- the order ---------------------------------------------------------------------------
    def detail(self, oid, fulfillment=True):
        # in the WSDL's order: ... ReturnCertificateInfo, ReturnFulfillment, ReturnCACerts,
        # ReturnOriginalCSR, ReturnPKCS12, ReturnSANEntries
        opts = [('ReturnOrderOption', 'true'), ('ReturnCertificateInfo', 'true'),
                ('ReturnFulfillment', 'true' if fulfillment else None),
                ('ReturnCACerts', 'true' if fulfillment else None),
                ('ReturnSANEntries', 'true')]
        return self.call(GAS, 'GetOrderByOrderID', [('OrderID', self._oid(oid)),
                                                   ('OrderQueryOption', opts)],
                         what='the order %s' % oid, query=True)

    @staticmethod
    def names_of(det):
        info = find(det, 'CertificateInfo')
        cn = text(info, 'CommonName').lower() or text(find(det, 'OrderInfo'), 'DomainName').lower()
        names = [cn] + [(s.text or '').strip().lower() for s in find_all(det, 'SubjectAltName')]
        names += [x.strip().lower() for x in text(info, 'DNSNames').split(',')]
        return [n for i, n in enumerate(names) if n and n not in names[:i]]

    def _sans(self, req):
        out = []
        for n in req.names[1:]:
            out.append(('SANEntry', [('SANOptionType', '13' if n.startswith('*.') else '7'),
                                     ('SubjectAltName', n)]))
        return out

    def _order(self, req, kept, doms):
        """(how, order id)."""
        oid = str(getattr(req, 'ref', None) or '').strip() or self._s('order_id') or \
            str((kept or {}).get('id') or '')
        why = 'there is no order to reissue in (set "Order to reuse")'
        if oid:
            det = self.detail(oid, fulfillment=False)
            st = text(find(det, 'OrderInfo'), 'OrderStatus')
            end = _when(text(find(det, 'CertificateInfo'), 'EndDate'))
            same = sorted(self.names_of(det)) == sorted(n.lower() for n in req.names)
            if st == ISSUED and same and (end is None or end > time.time() + 86400):
                resp = self.call(GAS, 'ReIssue', [('OrderParameter', [('CSR', sc.csr_pem(req))]),
                                                  ('TargetOrderID', self._oid(oid))],
                                 what='the reissue of order %s' % oid)
                new = text(resp, 'OrderID') or oid
                sc.say(self.ctx, 'reissue of order %s asked for: order %s (no new purchase)' % (
                    oid, new), 'ok')
                return 'reissue', self._oid(new)
            if st != ISSUED:
                why = 'the order %s is %s' % (oid, STATUS_WORDS.get(st, st or '?'))
            elif not same:
                why = 'the order %s is for other names (%s)' % (oid, ', '.join(self.names_of(det)))
            else:
                why = 'the certificate of order %s ends' % oid
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing ordered: %s, and paid orders are not allowed for this '
                              'source - set "Order to reuse" to an order you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        product = self._s('product') or 'PV_SHA2'
        if not re.match(r'^[A-Z0-9_]{2,30}\Z', product):
            raise PluginError('"%s" is not a GlobalSign product code' % product, retry=False)
        dom = self.covering(doms, req.names[0])
        param = [('ProductCode', product),
                 ('BaseOption', 'wildcard' if req.names[0].startswith('*.') else None),
                 ('OrderKind', 'new'), ('Licenses', '1'),
                 ('Options', [('Option', [('OptionName', 'SAN'), ('OptionValue', 'true')])]
                  if req.names[1:] else None),
                 ('ValidityPeriod', [('Months', self._s('months') or '6')]),
                 ('CSR', sc.csr_pem(req))]
        sc.say(self.ctx, '%s - a new order is made (paid: allowed for this source)' % why, 'warn')
        resp = self.call(MSSL, 'PVOrder', [
            ('OrderRequestParameter', param), ('MSSLProfileID', self._profile()),
            ('MSSLDomainID', dom['id'] if dom else None), ('ContactInfo', self._contact()),
            ('SANEntries', self._sans(req) or None)], what='the new order')
        oid = text(resp, 'OrderID')
        if not re.match(r'^[A-Za-z0-9_-]{4,50}\Z', oid):
            raise PluginError('GlobalSign took the order but said no order ID - look in GCC '
                              'before trying again (a second order would be paid again)',
                              retry=False)
        sc.say(self.ctx, 'order %s made at GlobalSign: %s for %s' % (
            oid, product, ', '.join(req.names)), 'ok')
        return 'new', oid

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        ck = str(req.cert_id or '') or sc.pending_slot('x', '', req).split(':')[-1]
        made_key = 'gsmssl-order:%s' % ck
        slot = sc.pending_slot('gsmssl', self._host() + self._profile(), req)
        held = sc.pending_get(self.ctx, slot, req) or {}
        r = sc.held_request(req, held if held.get('id') else None)
        placer = _dcv.Placer(self)
        if held.get('id'):
            oid = held['id']
            sc.say(self.ctx, 'the order %s waits at GlobalSign since %s - asked for again, '
                             'nothing is ordered' % (oid, time.strftime(
                                 '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
        else:
            held = dict(held, csr_pem=sc.csr_pem(req))
            doms = self._domain_dcv(req, slot, held, placer)
            kept = sc.parse_json(self.ctx.kv_get(made_key) or '') or {}
            kind, oid = self._order(req, kept, doms)
            if kind == 'new':
                self.ctx.kv_set(made_key, json.dumps({'id': oid, 'at': time.time()}),
                                ttl_s=5 * 366 * 86400)
            held = sc.pending_put(self.ctx, slot, req, {'id': oid, 'how': kind,
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=30)
            r = req
        return self._await(r, req, slot, oid)

    def fetch(self, det):
        """(the certificate, the CA certificates) of an order's Fulfillment (DER)."""
        ful = find(det, 'Fulfillment')
        leaf = sc.certs_of(text(find(ful, 'ServerCertificate'), 'X509Cert'))
        cas = []
        for c in find_all(ful, 'CACertificate'):
            cas += sc.certs_of(text(c, 'CACert'))
        return leaf, cas

    def _await(self, r, req, slot, oid):
        end = time.time() + sc.num(self.c('wait_issue'), 300)
        every = max(1.0, sc.num(self.c('poll_every'), 20))
        while True:
            det = self.detail(oid)
            st = text(find(det, 'OrderInfo'), 'OrderStatus')
            if st == ISSUED:
                leaf, cas = self.fetch(det)
                if leaf:
                    out = sc.finish(self.ctx, r, leaf, cas, who='GlobalSign',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'globalsign_order': oid, 'ref': oid})
                    sc.pending_drop(self.ctx, slot)
                    self.ctx.kv_set('gsmssl-cert:%s' % sc.fingerprint(out.cert_pem)[:40], oid,
                                    ttl_s=5 * 366 * 86400)
                    if getattr(req, 'cert_id', None):
                        self.ctx.kv_set('gsmssl-order:%s' % req.cert_id,
                                        json.dumps({'id': oid, 'at': time.time()}),
                                        ttl_s=5 * 366 * 86400)
                    return out
            elif st and st not in WAITING:
                sc.pending_drop(self.ctx, slot)
                raise PluginError('GlobalSign did not issue: the order %s is %s' % (
                    oid, STATUS_WORDS.get(st, st)), retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('GlobalSign has not issued yet (order %s: %s) - acme asks again '
                                  'at the next try' % (oid, STATUS_WORDS.get(st, st or '?')))
            self._sleep(every)

    # -- revocation -------------------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        oid = self.ctx.kv_get('gsmssl-cert:%s' % sc.fingerprint(cert_pem)[:40])
        if not oid:
            raise PluginError('acme does not know the certificate\'s order at GlobalSign - revoke '
                              'it in GCC', retry=False)
        why = REVOKE.get(sc.reason_code(reason), '0')
        self.call(MSSL, 'RevokeMSSLOrder', [('OrderID', self._oid(oid)), ('RevokeReason', why)],
                  what='the revocation')
        return 'GlobalSign revoked order %s (reason %s)' % (oid, why)

    # -- the orders of the account (Certificates → Import from a source) ---------------------
    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('gsmssl-order:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """The orders of the last "Orders listed (days back)" days (GetOrderByDateRange, 30
        days at a time) - read only."""
        mine = self._acme_ids()
        now = time.time()
        days = max(30, int(sc.num(self.c('list_days'), 400)))
        seen, out = set(), []
        to = now
        while to > now - days * 86400 and not self.ctx.cancelled():
            frm = max(now - days * 86400, to - 30 * 86400)
            resp = self.call(GAS, 'GetOrderByDateRange', [
                ('FromDate', _stamp(frm)), ('ToDate', _stamp(to)),
                ('OrderQueryOption', [('ReturnCertificateInfo', 'true'),
                                      ('ReturnSANEntries', 'true')])],
                what='the orders', query=True)
            for det in find_all(resp, 'OrderDetail'):
                info = find(det, 'OrderInfo')
                oid = text(info, 'OrderId')
                if not oid or oid in seen:
                    continue
                seen.add(oid)
                st = text(info, 'OrderStatus')
                ci = find(det, 'CertificateInfo')
                names = self.names_of(det)
                serial = text(ci, 'SerialNumber').replace(':', '').upper()
                out.append({'ref': oid, 'cn': names[0] if names else '', 'names': names,
                            'product': text(info, 'ProductCode'),
                            'status': STATUS_WORDS.get(st, st or '?'),
                            'serial': serial or None,
                            'not_before': _when(text(ci, 'StartDate')),
                            'not_after': _when(text(ci, 'EndDate')),
                            'downloadable': st == ISSUED,
                            'renewable': 'reissue' if st == ISSUED else 'order',
                            'note': '' if st == ISSUED else 'the order is %s' % (
                                STATUS_WORDS.get(st, st or '?')),
                            'acme_cert_id': mine.get(oid)})
            to = frm
        return out

    def fetch_existing(self, ref):
        """The certificate of order `ref` and its CA certificates - read only."""
        oid = self._oid(ref)
        det = self.detail(oid)
        leaf, cas = self.fetch(det)
        if not leaf:
            st = text(find(det, 'OrderInfo'), 'OrderStatus')
            raise PluginError('the order %s has no certificate (it is %s)' % (
                oid, STATUS_WORDS.get(st, st or '?')), retry=False)
        out = sc.existing(leaf, cas, who='GlobalSign', ref=oid)
        self.ctx.kv_set('gsmssl-cert:%s' % sc.fingerprint(out['cert_pem'])[:40], oid,
                        ttl_s=5 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(oid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['user', 'password', 'environment']

    def discover_setup(self):
        """Read-only: the MSSL profiles and products (the form's lists), the approved domains
        of the profile (GetDomains) and the issued orders of "Orders listed" days
        (GetOrderByDateRange) - one to reissue in, never picked by itself."""
        out = Plugin.discover_setup(self)
        prof = self._s('profile_id') or (out['choices'].get('profile_id') or {}).get('pick')
        if prof:
            with sc.assumed(self, {'profile_id': prof}):
                try:
                    ok = sorted(d['name'] for d in self.domains() if d['status'] in APPROVED)
                    out['facts'].append(['Approved domains', ', '.join(ok[:20]) + (
                        ' …' if len(ok) > 20 else '') if ok else '0'])
                except PluginError as e:
                    out['notes'].append('the domains of the profile %s could not be read: %s'
                                        % (prof, e))
        rows = self.list_existing()
        out['facts'].append(['Orders', str(len(rows))])
        sc.reuse_choice(self, out, 'order_id', rows,
                        'Empty: the order acme made last for the certificate')
        return out
