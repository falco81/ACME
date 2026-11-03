# -*- coding: utf-8 -*-
"""
Certificates bought at Namecheap through its API (namecheap.ssl.*): an SSL
certificate bought (create - only when "Allow new orders (paid)" is on), then
activated with acme's request (CSR) and a domain validation (DCV) - the CNAME or
file Namecheap answers with put in place by the certificate's own validation
(base.Challenge.place; acmelib/plugins/issuers/_dcv.py) - or reissued inside a
certificate bought already (free); the certificate read by getInfo once it is
active. The account's certificates are listed for Certificates → Import from a
source.

What the API is, and from where - Namecheap's own pages (read 2026-11 from their
2025 copies in the Wayback Machine, as namecheap.com refuses scripts):
https://www.namecheap.com/support/api/intro/, .../global-parameters/,
.../error-codes/, .../methods/ssl/create/, .../ssl/activate/, .../ssl/get-info/,
.../ssl/reissue/, .../ssl/get-list/, .../ssl/revokecertificate/,
.../ssl/resend-approver-email/, .../ssl/editdcvmethod/,
.../ssl/get-approver-email-list/:

* https://api.namecheap.com/xml.response (sandbox: https://api.sandbox.namecheap.com/
  xml.response), GET or POST, URL-encoded; every call ApiUser, ApiKey, UserName,
  ClientIp (an IPv4 address on the account's allow list) and Command. The answer:
  <ApiResponse Status="OK|ERROR"><Errors><Error Number="..">words</Error></Errors>
  <CommandResponse>...</CommandResponse></ApiResponse>.
* namecheap.ssl.create {Years, Type, SANStoADD} -> SSLCreateResult/SSLCertificate
  {CertificateID, Status NewPurchase}.
* namecheap.ssl.activate {CertificateID, CSR, AdminEmailAddress, WebServerType,
  DNSDCValidation | HTTPDCValidation (true) | ApproverEmail; a multi-domain one:
  DNSNames and DNSApproverEmails, one method for each name: an address,
  HTTPCSRHASH or CNAMECSRHASH} -> SSLActivateResult {HttpDCValidation/DNS[@domain]
  {FileName, FileContent}, DNSDCValidation/DNS[@domain] {HostName, Target}}.
  (editDCVMethod spells the methods HTTP_CSR_HASH, CNAME_CSR_HASH - it is not used.)
* The records: CNAME HostName -> Target (both whole names); the file
  http://NAME/.well-known/pki-validation/FileName holding FileContent.
* namecheap.ssl.resendApproverEmail {CertificateID} - "retries HTTP/DNS validation
  after the file is uploaded / CNAME record created".
* namecheap.ssl.reissue {CertificateID, CSR, the same DCV parameters} - "ACTIVE"
  certificates only; a child certificate in PURCHASED, the parent REPLACED (its
  ReplacedBy) once done.
* namecheap.ssl.getInfo {CertificateID, Returncertificate true, Returntype
  Individual} -> SSLGetInfoResult {Status active | newpurchase | newrenewal |
  purchased | purchaseerror | cancelled | replaced, Type, Expires, ReplacedBy,
  CertificateDetails/Certificates/Certificate (PEM), CaCertificates/Certificate/
  Certificate (PEM)}.
* namecheap.ssl.getList {ListType ALL, Page, PageSize 10..100} -> SSLListResult/SSL
  {CertificateID, HostName, SSLType, PurchaseDate, ExpireDate, Status}, Paging/
  TotalItems: Import from a source.
* namecheap.ssl.revokecertificate {CertificateID, CertificateType} - "revokes a
  reissued SSL certificate" (one replaced by a reissue).

LESS CERTAIN: whether the ID a reissue answers is the child's (acme follows
ReplacedBy of getInfo until it gets the certificate of its key); whether a
multi-domain activation wants ApproverEmail=CNAMECSRHASH beside DNSApproverEmails
(sent so); whether FileContent's words go into the file on one line as answered
(they are written as answered); revoking a certificate that was not replaced (said
as Namecheap answers). There is no API to list the products: the Type values of
namecheap.ssl.create are a fixed list here.
"""
from __future__ import annotations

import calendar
import ipaddress
import json
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET

from acmelib.plugins.base import Issuer, Plugin, PluginError, field
from acmelib.plugins.issuers import _dcv
from acmelib.plugins.issuers import _source_common as sc

ENDPOINTS = {'production': 'https://api.namecheap.com/xml.response',
             'sandbox': 'https://api.sandbox.namecheap.com/xml.response'}
# "Possible values for Type parameter" of namecheap.ssl.create: (Type, validation,
# kind: single | wildcard | multi)
TYPES = [
    ('PositiveSSL', 'DV', 'single'), ('EssentialSSL', 'DV', 'single'),
    ('InstantSSL', 'OV', 'single'), ('InstantSSL Pro', 'OV', 'single'),
    ('PremiumSSL', 'OV', 'single'), ('EV SSL', 'EV', 'single'),
    ('PositiveSSL Wildcard', 'DV', 'wildcard'), ('EssentialSSL Wildcard', 'DV', 'wildcard'),
    ('PremiumSSL Wildcard', 'OV', 'wildcard'),
    ('PositiveSSL Multi Domain', 'DV', 'multi'), ('Multi Domain SSL', 'OV', 'multi'),
    ('Unified Communications', 'OV', 'multi'), ('EV Multi Domain SSL', 'EV', 'multi'),
]
INCLUDED = 3                        # a multi-domain certificate: "Domains included 3"
ISSUED = ('active',)
WAITING = ('purchased', 'newpurchase', 'newrenewal')
FAILED = ('purchaseerror', 'cancelled', 'canceled')
STATUS_WORDS = {'active': 'active', 'newpurchase': 'bought, not activated',
                'newrenewal': 'a renewal bought, not activated',
                'purchased': 'activated, waiting for issuance',
                'purchaseerror': 'an error at the certificate provider',
                'cancelled': 'cancelled', 'replaced': 'replaced by a reissue'}
MAILBOXES = ('admin', 'administrator', 'hostmaster', 'postmaster', 'webmaster')


def _local(tag):
    return tag.rsplit('}', 1)[-1]


def _all(el, name):
    return [c for c in el.iter() if _local(c.tag) == name] if el is not None else []


def _one(el, name):
    got = _all(el, name)
    return got[0] if got else None


def _text(el):
    return (el.text or '').strip() if el is not None else ''


def _day(v):
    try:
        return calendar.timegm(time.strptime(str(v or '').strip()[:10], '%m/%d/%Y'))
    except (TypeError, ValueError):
        return None


class NamecheapSslIssuer(Issuer):
    kind = 'namecheap_ssl'
    title = 'Namecheap SSL (API)'
    description = ('Certificates bought at Namecheap through its API: bought (only when paid '
                   'orders are allowed), activated with acme\'s request or reissued inside a '
                   'certificate bought already, the CNAME or file put in place by the '
                   'certificate\'s validation. Lists the account\'s certificates for importing.')
    vendor = 'Namecheap'
    doc = 'docs/sources.md'
    needs_challenge = True          # per instance: False for e-mail DCV (see __init__)
    challenge_types = ('dns-01', 'http-01')
    wildcards = True
    ip_names = False
    public_names = True
    lists_existing = True           # getList + getInfo: Import from a source
    dcv_field = 'dcv'
    dcv_default = 'cname'
    dcv = {
        'cname': {'proof': 'cname-any', 'words': 'DNS CNAME record (CNAMECSRHASH)',
                  'record': 'CNAME HostName to Target, as the activation answers'},
        'http': {'proof': 'http-file-any', 'words': 'HTTP file (HTTPCSRHASH)',
                 'record': 'http://NAME/.well-known/pki-validation/FileName holding '
                           'FileContent'},
        'email': {'proof': None, 'words': 'E-mail (a person approves)',
                  'record': 'an e-mail to admin@, administrator@, hostmaster@, postmaster@ or '
                            'webmaster@ the domain'},
    }
    per_cert = [{'key': 'template', 'field': 'ssl_type', 'catalog': 'types',
                 'label': 'Certificate type', 'placeholder': 'PositiveSSL',
                 'help': 'The Namecheap SSL type of a new certificate bought for this one. '
                         'Empty: the source\'s own.'}]
    fields = [
        field('env', 'Namecheap', 'select', default='production',
              options=[['production', 'Production (api.namecheap.com)'],
                       ['sandbox', 'Sandbox (api.sandbox.namecheap.com)']]),
        field('api_user', 'API user', 'text', required=True,
              help='Profile → Tools → Namecheap API Access: the account\'s user name.'),
        field('api_key', 'API key', 'secret', required=True),
        field('user_name', 'User name', 'text',
              help='The user the commands are for. Empty: the API user.'),
        field('client_ip', 'Client IP', 'text', required=True, placeholder='198.51.100.7',
              help='The IPv4 address acme calls from - it must be on the API access allow '
                   'list.'),
        field('cert_id', 'Certificate to reuse', 'text', placeholder='123456',
              help='A CertificateID bought already: one not activated yet is activated, an '
                   'active one is reissued (free). Empty: the one acme had last for the '
                   'certificate.'),
        field('allow_paid', 'Allow new orders (paid)', 'bool', default=False,
              help='Off: acme never buys anything (namecheap.ssl.create) - it only activates '
                   'or reissues certificates bought already.'),
        field('ssl_type', 'Type of a new certificate', 'catalog', catalog='types',
              default='PositiveSSL',
              help='The SSL product Namecheap sells (namecheap.ssl.create Type). Load the list; '
                   'a type can be typed too.'),
        field('years', 'Years of a new certificate', 'select', default='1',
              options=[['1', '1 year'], ['2', '2 years'], ['3', '3 years'], ['4', '4 years'],
                       ['5', '5 years']]),
        field('admin_email', 'Administrator e-mail', 'text', required=True,
              help='AdminEmailAddress of the activation: where Namecheap sends the certificate.'),
        field('dcv', 'Domain validation (DCV)', 'select', default='cname',
              options=[['cname', 'DNS CNAME record (by the certificate\'s DNS validation)'],
                       ['http', 'HTTP file in /.well-known/pki-validation/ (by the '
                                'certificate\'s HTTP validation; no wildcards)'],
                       ['email', 'E-mail to an approver address of the domain']],
              help='How the CA checks the domains (Namecheap offers no TXT record). The '
                   'certificate\'s validation must be able to put that record or file in '
                   'place.'),
        field('approver', 'Approver mailbox', 'select', default='admin',
              options=[['admin', 'admin@'], ['administrator', 'administrator@'],
                       ['hostmaster', 'hostmaster@'], ['postmaster', 'postmaster@'],
                       ['webmaster', 'webmaster@']],
              show_if={'dcv': ['email']}),
        field('webserver', 'Web server type', 'text', advanced=True, placeholder='nginx',
              help='WebServerType of the activation (empty: not sent).'),
        field('more', 'More fields of the activation', 'list', advanced=True,
              placeholder='AdminOrganizationName=Firma s.r.o.',
              help='Name=value, one a line, sent as they are (what an OV/EV activation wants).'),
        field('api_url', 'API address', 'text', advanced=True,
              placeholder='https://api.namecheap.com/xml.response',
              help='Empty: as "Namecheap" says.'),
        field('wait_issue', 'Wait for the certificate (s)', 'number', default=600,
              advanced=True,
              help='Longer: it is asked for again at the next try - nothing is bought twice.'),
        field('wait_ready', 'Wait for the DCV record to be visible (s)', 'number', default=300,
              advanced=True),
        field('poll_every', 'Ask again every (s)', 'number', default=20, advanced=True),
    ]

    def __init__(self, config, ctx):
        Issuer.__init__(self, config, ctx)
        self.needs_challenge = self.c('dcv') != 'email'
        self._sleep = time.sleep

    # -- the API ---------------------------------------------------------------------------
    def _s(self, key):
        return str(self.c(key) or '').strip()

    def _url(self):
        url = self._s('api_url') or ENDPOINTS.get(self._s('env') or 'production')
        if not url or not re.match(r'^https://[^\s?]+\Z', url):
            raise PluginError('the Namecheap API address is an https address', retry=False)
        return url

    def call(self, command, params=None, what=''):
        """The answer's <CommandResponse>, or a PluginError in words."""
        user, key, ip = self._s('api_user'), self._s('api_key'), self._s('client_ip')
        if not user or not key:
            raise PluginError('set the API user and the API key', retry=False)
        try:
            if ipaddress.ip_address(ip).version != 4:
                raise ValueError(ip)
        except ValueError:
            raise PluginError('the client IP is the IPv4 address acme calls from', retry=False)
        form = {'ApiUser': user, 'ApiKey': key, 'UserName': self._s('user_name') or user,
                'ClientIp': ip, 'Command': command}
        form.update({k: v for k, v in (params or {}).items() if v not in (None, '')})
        status, _h, data = sc.http(self.ctx, 'POST', self._url(), urllib.parse.urlencode(form),
                                   {'Content-Type': 'application/x-www-form-urlencoded',
                                    'Accept': 'text/xml'}, who='Namecheap')
        said = (data or b'').decode('utf-8', 'replace').replace(key, '********')
        try:
            root = ET.fromstring(data or b'')
        except ET.ParseError:
            raise PluginError('Namecheap answered %s to %s, and not in XML' % (status,
                                                                                what or command),
                              detail=said[:3000], retry=status >= 500)
        if str(root.get('Status') or '').upper() != 'OK':
            errs = ['%s %s' % (e.get('Number') or '?', _text(e)) for e in _all(root, 'Error')]
            words = '; '.join(errs) or 'status %s' % (root.get('Status') or status)
            hint = ''
            if re.search(r'\b(1011150|1017150|1017105|1011102|1010102|1017101|1050900)\b', words):
                hint = ' - the API key is wrong, or the client IP is not on the allow list'
            raise PluginError('Namecheap refused %s: %s%s' % (what or command,
                                                             words.replace(key, '********'),
                                                             hint), detail=said[:3000],
                              retry=status >= 500)
        return _one(root, 'CommandResponse')

    @staticmethod
    def _cid(v):
        v = str(v or '').strip()
        if not re.match(r'^\d{1,10}\Z', v):
            raise PluginError('"%s" is not a Namecheap CertificateID' % v, retry=False)
        return v

    # -- the types (the form's list) ---------------------------------------------------------
    def catalog(self, key):
        """The SSL types of namecheap.ssl.create - a fixed list (no API lists them)."""
        if key != 'types':
            raise PluginError('there is no list called %s here' % key, retry=False)
        kinds = {'single': 'one name', 'wildcard': 'wildcard',
                 'multi': 'multi-domain, 3 names included'}
        return {'options': [[t, '%s - %s, %s' % (t, lv, kinds[k])] for t, lv, k in TYPES],
                'said': '%d types Namecheap sells (namecheap.ssl.create)' % len(TYPES)}

    def test(self):
        got = self.call('namecheap.ssl.getList', {'ListType': 'ALL', 'Page': 1, 'PageSize': 10},
                        what='the list of certificates')
        total = _text(_one(got, 'TotalItems')) or '?'
        return 'Namecheap answers: the API key and client IP are let in; %s certificate(s); ' \
               'new paid certificates %s' % (total, 'ALLOWED' if sc.as_bool(self.c('allow_paid'))
                                             else 'not allowed')

    # -- the certificate ---------------------------------------------------------------------
    def info(self, cid, cert=False):
        p = {'CertificateID': self._cid(cid)}
        if cert:
            p.update({'Returncertificate': 'true', 'Returntype': 'Individual'})
        got = self.call('namecheap.ssl.getInfo', p, what='the certificate %s' % cid)
        res = _one(got, 'SSLGetInfoResult')
        if res is None:
            raise PluginError('Namecheap said nothing of the certificate %s' % cid)
        return res

    def _certs(self, res):
        leaf, chain = [], []
        certs = _one(res, 'Certificates')
        for c in list(certs) if certs is not None else []:
            if _local(c.tag) == 'Certificate':
                leaf += sc.certs_of(_text(c))
            elif _local(c.tag) == 'CaCertificates':
                for x in _all(c, 'Certificate'):
                    if _text(x):
                        chain += sc.certs_of(_text(x))
        return leaf, chain

    def _ssl_type(self, req):
        t = str((req.profile or {}).get('template') or self._s('ssl_type') or 'PositiveSSL')
        known = next((x for x in TYPES if x[0].lower() == t.lower()), None)
        if known is None:
            sc.say(self.ctx, '"%s" is not one of the types Namecheap lists - sent as it is' % t,
                   'warn')
            return t, 'multi' if len(req.names) > 1 else 'single'
        return known[0], known[2]

    def _dcv_params(self, req, multi):
        how = self.c('dcv') or 'cname'
        p = {}
        box = self.c('approver') or 'admin'
        if box not in MAILBOXES:
            box = 'admin'
        mails = ['%s@%s' % (box, _dcv.base_of(n)) for n in req.names]
        method = {'cname': 'CNAMECSRHASH', 'http': 'HTTPCSRHASH'}.get(how)
        if multi and len(req.names) > 1:
            p['DNSNames'] = ','.join(req.names[1:])
            p['DNSApproverEmails'] = ','.join([method] * (len(req.names) - 1) if method
                                              else mails[1:])
            p['ApproverEmail'] = method or mails[0]
        elif how == 'cname':
            p['DNSDCValidation'] = 'true'
        elif how == 'http':
            p['HTTPDCValidation'] = 'true'
        else:
            p['ApproverEmail'] = mails[0]
        return p

    def _activation(self, req, multi):
        p = {'CSR': sc.csr_pem(req), 'AdminEmailAddress': self._s('admin_email'),
             'WebServerType': self._s('webserver')}
        if not p['AdminEmailAddress']:
            raise PluginError('set the administrator e-mail', retry=False)
        p.update(self._dcv_params(req, multi))
        for line in sc.lines(self.c('more')):
            if '=' not in line:
                raise PluginError('a field of the activation is Name=value: %s' % line,
                                  retry=False)
            k, v = line.split('=', 1)
            p[k.strip()] = v.strip()
        return p

    def _order(self, req, kept):
        """(how, CertificateID, the activation's answer)."""
        cid = str(getattr(req, 'ref', None) or '').strip() or self._s('cert_id') or \
            str((kept or {}).get('id') or '')
        t, kind = self._ssl_type(req)
        why = 'there is no certificate to activate or reissue (set "Certificate to reuse")'
        if cid:
            res = self.info(cid)
            st = str(res.get('Status') or '').lower()
            multi = int(sc.num(res.get('SANSCount'), 0)) > 0 or len(req.names) > 1
            if st in ('newpurchase', 'newrenewal'):
                p = dict(self._activation(req, multi), CertificateID=self._cid(cid))
                got = self.call('namecheap.ssl.activate', p, what='the activation of %s' % cid)
                sc.say(self.ctx, 'certificate %s activated with the request' % cid, 'ok')
                return 'activate', cid, got
            if st in ISSUED:
                p = dict(self._activation(req, multi), CertificateID=self._cid(cid))
                p.pop('AdminEmailAddress', None)     # "not possible to change ... in reissue"
                got = self.call('namecheap.ssl.reissue', p, what='the reissue of %s' % cid)
                sc.say(self.ctx, 'reissue of certificate %s asked for (free)' % cid, 'ok')
                return 'reissue', cid, got
            why = 'the certificate %s is %s' % (cid, STATUS_WORDS.get(st, st or '?'))
        if not sc.as_bool(self.c('allow_paid')):
            raise PluginError('nothing bought: %s, and paid certificates are not allowed for this '
                              'source - set "Certificate to reuse" to one you bought, or switch '
                              'on "Allow new orders (paid)"' % why, retry=False)
        if kind == 'single' and len(req.names) > 1:
            raise PluginError('the type %s takes one name - choose a multi-domain type' % t,
                              retry=False)
        if kind != 'wildcard' and any(n.startswith('*.') for n in req.names):
            raise PluginError('the type %s takes no wildcard name' % t, retry=False)
        sc.say(self.ctx, '%s - a new certificate is bought (paid: allowed for this source)' % why,
               'warn')
        p = {'Years': int(sc.num(self.c('years'), 1)), 'Type': t}
        if kind == 'multi' and len(req.names) > INCLUDED:
            p['SANStoADD'] = len(req.names) - INCLUDED
        got = self.call('namecheap.ssl.create', p, what='the purchase')
        cert = _one(got, 'SSLCertificate')
        cid = str(cert.get('CertificateID') if cert is not None else '')
        if not re.match(r'^\d+\Z', cid):
            raise PluginError('Namecheap sold the certificate but said no CertificateID - look '
                              'in the account before trying again (a second one would be paid '
                              'again)', retry=False)
        sc.say(self.ctx, 'certificate %s bought at Namecheap: %s for %d year(s)' % (
            cid, t, p['Years']), 'ok')
        self._remember(req, cid)
        p = dict(self._activation(req, kind == 'multi'), CertificateID=cid)
        got = self.call('namecheap.ssl.activate', p, what='the activation of %s' % cid)
        return 'new', cid, got

    def _remember(self, req, cid):
        if getattr(req, 'cert_id', None):
            self.ctx.kv_set('namecheap-made:%s' % req.cert_id,
                            json.dumps({'id': cid, 'at': time.time()}), ttl_s=5 * 366 * 86400)

    def dcv_records(self, got):
        how = self.c('dcv') or 'cname'
        recs = []
        if how == 'cname':
            for d in _all(_one(got, 'DNSDCValidation'), 'DNS'):
                host = _text(_one(d, 'HostName')).rstrip('.').lower()
                target = _text(_one(d, 'Target')).rstrip('.').lower()
                if host and target:
                    recs.append({'domain': _dcv.base_of(d.get('domain') or host), 'type': 'cname',
                                 'fqdn': host, 'value': target})
        elif how == 'http':
            for d in _all(_one(got, 'HttpDCValidation'), 'DNS'):
                name = _text(_one(d, 'FileName'))
                content = _text(_one(d, 'FileContent'))
                if name and content and re.match(r'^[A-Za-z0-9._-]+\Z', name):
                    recs.append({'domain': _dcv.base_of(d.get('domain') or ''), 'type': 'file',
                                 'path': '/.well-known/pki-validation/' + name, 'value': content})
        return recs

    def _place(self, req, slot, held, placer, recs, ttl=90):
        """The records kept with the order first (a try that stops while they are put in
        place puts them again the next time), then put in place."""
        held['recs'] = recs
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        held['dcv'] = placer.place_all(req, recs)
        sc.pending_put(self.ctx, slot, req, held, ttl_days=ttl)
        return any(p.get('how') == 'placed' for p in held['dcv'])

    def issue(self, req):
        if not req.names:
            raise PluginError('the certificate has no names', retry=False)
        how = self.c('dcv') or 'cname'
        if how == 'http' and any(n.startswith('*.') for n in req.names):
            raise PluginError('a wildcard name is proved by a CNAME or e-mail, not by an HTTP '
                              'file - choose the DNS CNAME record', retry=False)
        slot = sc.pending_slot('namecheap_ssl', self._url(), req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held)
        placer = _dcv.Placer(self)
        if held:
            sc.say(self.ctx, 'the certificate %s waits at Namecheap since %s - asked for again, '
                             'nothing is bought' % (held['id'], time.strftime(
                                 '%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0))))
            if held.get('recs') and not held.get('dcv'):
                if self._place(req, slot, held, placer, held['recs']):
                    placer.wait_visible(req, held['dcv'])
                    self._retry_dcv(held['id'])
            elif held.get('dcv'):
                placer.refresh(req, held['dcv'])
        else:
            kept = sc.parse_json(self.ctx.kv_get('namecheap-made:%s' % req.cert_id) or '') \
                if req.cert_id else None
            how_made, cid, got = self._order(req, kept)
            res = _one(got, 'SSLActivateResult')
            new_id = str(res.get('ID') if res is not None and res.get('ID') else cid)
            held = sc.pending_put(self.ctx, slot, req, {'id': new_id, 'parent': cid,
                                                        'how': how_made, 'dcv': [],
                                                        'csr_pem': sc.csr_pem(req)}, ttl_days=90)
            r = req
            if how == 'email':
                sc.say(self.ctx, 'the CA mails the approver address of each domain - someone '
                                 'there approves the certificate')
            else:
                recs = self.dcv_records(got)
                if not recs:
                    raise PluginError('Namecheap said no DCV record for the certificate %s - '
                                      'look in the account' % cid, retry=False)
                if self._place(req, slot, held, placer, recs):
                    placer.wait_visible(req, held['dcv'])
                    self._retry_dcv(new_id)
        return self._await(r, req, slot, held, placer)

    def _retry_dcv(self, cid):
        try:
            self.call('namecheap.ssl.resendApproverEmail', {'CertificateID': self._cid(cid)},
                      what='the DCV retry')
            sc.say(self.ctx, 'Namecheap was asked to check the domain validation again')
        except PluginError as e:
            sc.say(self.ctx, 'the CA checks the domain validation by itself (%s)' % e, 'info')

    def _await(self, r, req, slot, held, placer):
        cid = held['id']
        end = time.time() + sc.num(self.c('wait_issue'), 600)
        every = max(1.0, sc.num(self.c('poll_every'), 20))
        seen = set()
        while True:
            res = self.info(cid, cert=True)
            st = str(res.get('Status') or '').lower()
            if st == 'replaced' and res.get('ReplacedBy') and cid not in seen:
                seen.add(cid)
                cid = self._cid(res.get('ReplacedBy'))
                held['id'] = cid
                sc.pending_put(self.ctx, slot, req, held, ttl_days=90)
                continue
            if st in ISSUED:
                leaf, chain = self._certs(res)
                try:
                    out = sc.finish(self.ctx, r, leaf, chain, who='Namecheap',
                                    key_pem=r.key_pem if r is not req else None,
                                    info={'namecheap_id': cid, 'ref': cid})
                except PluginError:
                    out = None              # the parent's old certificate still: the reissue waits
                if out is not None:
                    placer.cleanup(req, held.get('dcv') or [])
                    sc.pending_drop(self.ctx, slot)
                    self._remember(req, cid)
                    self.ctx.kv_set('namecheap-cert:%s' % sc.fingerprint(out.cert_pem)[:40],
                                    json.dumps({'id': cid, 'type': res.get('Type') or ''}),
                                    ttl_s=5 * 366 * 86400)
                    return out
            elif st in FAILED:
                placer.cleanup(req, held.get('dcv') or [])
                sc.pending_drop(self.ctx, slot)
                raise PluginError('Namecheap did not issue: the certificate %s is %s' % (
                    cid, STATUS_WORDS.get(st, st)), retry=False)
            if time.time() >= end or self.ctx.cancelled():
                raise PluginError('Namecheap has not issued yet (certificate %s: %s) - the DCV '
                                  'records stay in place; acme asks again at the next try' % (
                                      cid, STATUS_WORDS.get(st, st or '?')))
            self._sleep(every)

    # -- revocation ---------------------------------------------------------------------------
    def revoke(self, cert_pem, reason='unspecified', key_pem=None):
        kept = sc.parse_json(self.ctx.kv_get('namecheap-cert:%s' %
                                             sc.fingerprint(cert_pem)[:40]) or '') or {}
        if not kept.get('id'):
            raise PluginError('acme does not know the certificate\'s ID at Namecheap - revoke it '
                              'in the Namecheap account', retry=False)
        self.call('namecheap.ssl.revokecertificate',
                  {'CertificateID': self._cid(kept['id']),
                   'CertificateType': str(kept.get('type') or '').lower() or 'positivessl'},
                  what='the revocation')
        return 'Namecheap revoked certificate %s (Namecheap revokes certificates replaced by a ' \
               'reissue)' % kept['id']

    # -- the certificates of the account (Certificates → Import from a source) ---------------
    def _acme_ids(self):
        out = {}
        try:
            kept = self.ctx.kv_keys('namecheap-made:')
        except (AttributeError, NotImplementedError):
            return out
        for k, v in kept.items():
            v = sc.parse_json(v) if isinstance(v, (str, bytes)) else v
            cid = k.split(':', 1)[1] if ':' in k else ''
            if isinstance(v, dict) and v.get('id') and cid.isdigit():
                out[str(v['id'])] = int(cid)
        return out

    def list_existing(self):
        """Every SSL certificate of the account (getList, 100 a page) - read only."""
        mine = self._acme_ids()
        out, page, per = [], 1, 100
        while page <= 100:
            got = self.call('namecheap.ssl.getList', {'ListType': 'ALL', 'Page': page,
                                                      'PageSize': per},
                            what='the list of certificates')
            items = _all(got, 'SSL')
            for s in items:
                cid = str(s.get('CertificateID') or '').strip()
                if not cid:
                    continue
                st = str(s.get('Status') or '').lower()
                host = str(s.get('HostName') or '').strip()
                out.append({'ref': cid, 'cn': host, 'names': [host] if host else [],
                            'product': str(s.get('SSLType') or ''),
                            'status': STATUS_WORDS.get(st, st or '?'),
                            'not_before': None, 'not_after': _day(s.get('ExpireDate')),
                            'downloadable': st in ISSUED,
                            'renewable': 'reissue' if st in ISSUED else 'order',
                            'note': '' if st in ISSUED else 'Namecheap says it is %s' % (
                                STATUS_WORDS.get(st, st or '?')),
                            'acme_cert_id': mine.get(cid)})
            total = int(sc.num(_text(_one(got, 'TotalItems')), 0))
            if len(items) < per or (total and page * per >= total):
                break
            page += 1
        return out

    def fetch_existing(self, ref):
        """The certificate `ref` and its CA certificates (getInfo, Individual) - read only."""
        cid = self._cid(ref)
        res = self.info(cid, cert=True)
        leaf, chain = self._certs(res)
        out = sc.existing(leaf, chain, who='Namecheap', ref=cid)
        self.ctx.kv_set('namecheap-cert:%s' % sc.fingerprint(out['cert_pem'])[:40],
                        json.dumps({'id': cid, 'type': res.get('Type') or ''}),
                        ttl_s=5 * 366 * 86400)
        out['acme_cert_id'] = self._acme_ids().get(cid)
        return out

    # -- discovery (1.0.29): the form filled in from the account -------------------------------
    discover_keys = ['env', 'api_user', 'api_key', 'user_name', 'client_ip', 'api_url']

    def discover_setup(self):
        """Read-only: the types (the form's list) and the certificates of the account
        (getList): one bought and not activated yet, or an active one to reissue, offered
        as the certificate to reuse (never picked by itself), its type with it."""
        out = Plugin.discover_setup(self)
        rows = self.list_existing()
        out['facts'].append(['Certificates', str(len(rows))])
        unused = (STATUS_WORDS['newpurchase'], STATUS_WORDS['newrenewal'])
        names = {t for t, _lv, _k in TYPES}
        for r in rows:
            if r.get('status') in unused:
                r['renewable'] = 'reissue'          # activated with acme's request
            if r.get('product') in names:
                r['sets'] = {'ssl_type': r['product']}
        n = sc.reuse_choice(self, out, 'cert_id', rows,
                            'Empty: the one acme had last for the certificate')
        out['facts'].append(['Certificates to reuse', str(n)])
        return out
