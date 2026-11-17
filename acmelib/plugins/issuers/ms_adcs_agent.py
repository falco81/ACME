# -*- coding: utf-8 -*-
"""
Certificates from a Microsoft CA (Active Directory Certificate Services) WITHOUT its web
service (1.0.125, docs/ms-adcs-agent.md): acme sends the CSR it made to a Windows member server
of the domain running acme-agent (a target "Windows server with acme-agent"); its root side
(LocalSystem) submits it to the CA over the CA's own request interface - ICertRequest over RPC /
DCOM (MS-ICPR), what `certreq -submit -config "HOST\\CA" -attrib "CertificateTemplate:NAME"` does
- signed in by Kerberos as the computer account. The certificate and its chain come back with
the job's answer.

acme holds no credential of the domain at all: no user, no password, no client certificate. What
the agent may ask the CA for is its own policy's word (deploy/agent/acme_agent_wincert.py):

    allow adcs "HOST\\CA Name" template=WebServer,WebServer2     (template=* any template)
    allow adcs-read                                             the lists, of every CA

A request the template holds for a certificate manager (pending) is remembered - its request id,
the key and the CSR, as ms_adcs keeps them - and asked for again at the next tries (retrieve);
one the manager denied is said in words and let go.
"""
from __future__ import annotations

import base64
import binascii
import re
import time

from acmelib.plugins.base import Issuer, Issued, PluginError, field
from acmelib.plugins.issuers import _source_common as sc
from acmelib.plugins.issuers import _scep_pkcs7 as der

CA_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\[^\x00-\x1f\x7f"\\/:*?<>|]{1,128}\Z')
TEMPLATE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9 _.()-]{0,63}\Z')


class MsAdcsAgentIssuer(Issuer):
    kind = 'ms_adcs_agent'
    dual = True
    title = 'Microsoft AD CS (through acme-agent)'
    description = ('Certificates from a Microsoft CA without its web service: the acme-agent '
                   'of a Windows member server submits the request to the CA (RPC, Kerberos as '
                   'the computer account). acme holds no credential; the agent\'s policy names '
                   'the CA and the templates.')
    vendor = 'Microsoft'
    doc = 'docs/ms-adcs-agent.md'
    needs_challenge = False
    wildcards = True
    ip_names = True
    fields = [
        field('agent', 'Windows server with acme-agent', 'select', required=True,
              options=[['', 'choose a server']], options_from='agent_windows_targets',
              help='A member server of the domain whose acme-agent submits the requests '
                   '(Targets: Windows server with acme-agent). Its computer account needs '
                   'Read and Enroll on the template and Request Certificates on the CA.'),
        field('ca', 'Certification authority', 'catalog', catalog='cas', required=True,
              depends=['agent'], placeholder='ca01.example.local\\Example Issuing CA',
              help='The CA\'s config string: its server, a backslash, its name. Load the list: '
                   'the CAs of the domain the agent may name (allow adcs, allow adcs-read).'),
        field('template', 'Template', 'catalog', catalog='templates', required=True,
              depends=['agent', 'ca'], placeholder='WebServer',
              help='The template\'s name (not its display name). Load the list: the templates '
                   'the CA offers, as the agent reads them; its policy allows them by '
                   'name (allow adcs ... template=).'),
        field('key_kinds', 'Key types the template takes', 'select', default='any',
              options=[['any', 'RSA and ECDSA (a template of schema 2 or later, Key Storage '
                               'Provider)'],
                       ['rsa', 'RSA only (a template of schema 1, e.g. WebServer, or a legacy '
                               'CSP)'],
                       ['ec', 'ECDSA only']],
              help='What the template\'s Cryptography tab allows. The certificate\'s key type '
                   'is checked against it before the CA is asked.'),
        field('san_attr', 'Send the names as a SAN attribute too', 'bool', default=False,
              advanced=True,
              help='Only for a CA that takes names from the request\'s attributes '
                   '(EDITF_ATTRIBUTESUBJECTALTNAME2): the agent makes the attribute of the '
                   'CSR\'s own DNS names and addresses - nothing else. Off: the names go in the '
                   'CSR only (a template set to "Supply in the request").'),
        field('timeout', 'Timeout (s)', 'number', default=120, advanced=True,
              help='How long the agent waits for the CA.'),
    ]

    per_cert = [{'key': 'template', 'label': 'Certificate template', 'field': 'template',
                 'catalog': 'templates', 'placeholder': 'WebServer',
                 'help': 'The template on the Windows CA for this certificate (the agent\'s '
                         'policy must allow it). Empty: the source\'s own.'}]

    @classmethod
    def key_types_for(cls, config):
        k = str((config or {}).get('key_kinds') or 'any')
        if k == 'rsa':
            return ['rsa-2048', 'rsa-3072', 'rsa-4096']
        if k == 'ec':
            return ['ec-256', 'ec-384']
        return ['ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096']

    @classmethod
    def dual_for(cls, config):
        return str((config or {}).get('key_kinds') or 'any') == 'any'

    # -- the settings ------------------------------------------------------------------
    def _say(self, words, level='info'):
        try:
            self.ctx.step(words, level)
        except Exception:                           # noqa: BLE001
            pass

    def _agent(self):
        name = str(self.c('agent') or '').strip()
        if not name:
            raise PluginError('choose the Windows server whose acme-agent asks the CA',
                              retry=False)
        return name

    def _ca(self):
        ca = str(self.c('ca') or '').strip()
        if not ca:
            raise PluginError('set the certification authority (HOST\\CA Name)', retry=False)
        if not CA_RE.match(ca):
            raise PluginError('%r is not the config string of a CA: its server, a backslash, '
                              'its name (ca01.example.local\\Example Issuing CA)' % ca[:120],
                              retry=False)
        return ca

    def _template(self, req=None):
        t = str(((req.profile or {}) if req is not None else {}).get('template') or
                self.c('template') or '').strip()
        if not t:
            raise PluginError('set the template', retry=False)
        if not TEMPLATE_RE.match(t):
            raise PluginError('%r is not the name of a template (its name, not its display '
                              'name: WebServer)' % t[:80], retry=False)
        return t

    def _timeout(self):
        try:
            return max(10, min(int(self.c('timeout') or 120), 600))
        except (TypeError, ValueError):
            return 120

    # -- asking the agent --------------------------------------------------------------
    def _call(self, args):
        """One job (op adcs) for the agent of the target chosen -> its `adcs` answer, or
        PluginError in the agent's words (a refusal of its policy with the line that allows
        it)."""
        call = getattr(self.ctx, 'agent_call', None)
        if not callable(call):
            raise PluginError('this acme cannot reach agents', retry=False)
        name = self._agent()
        args = dict(args, timeout=self._timeout())
        got = call('adcs', args, timeout=self._timeout() + 60, target=name)
        if not got.get('ok'):
            said = got.get('said') or 'the agent refused'
            allow = [n.get('allow') for n in got.get('needs') or [] if n.get('allow')]
            if allow:
                said += ' - allow it on %s (an elevated prompt): %s' % (name, '; '.join(allow))
            elif 'not an operation' in said:
                said += ' - the agent of %s is older than 1.0.125: update it' % name
            raise PluginError(said, retry=not got.get('refused'))
        a = got.get('adcs')
        if not isinstance(a, dict):
            raise PluginError('the agent of %s did not answer about the CA (an agent older '
                              'than 1.0.125?)' % name, retry=False)
        return a

    def test(self):
        ca = self._ca()
        a = self._call({'action': 'templates', 'ca': ca})
        ts = a.get('templates') or []
        mine = str(self.c('template') or '').strip()
        words = 'the agent of %s reaches %s: %d template%s' % (
            self._agent(), ca, len(ts), '' if len(ts) == 1 else 's')
        if mine:
            hit = [t for t in ts if str(t.get('name')).lower() == mine.lower()]
            if not hit:
                raise PluginError('%s does not offer the template %s (it offers %s)' % (
                    ca, mine, ', '.join(t.get('name') for t in ts[:12]) or 'none'),
                    retry=False)
            words += '; %s is offered%s' % (mine, '' if hit[0].get('allowed') else
                                            ' - but the agent\'s policy does not allow it')
        return words

    # -- the form's lists --------------------------------------------------------------
    discover_keys = ['agent', 'ca']

    def discover_setup(self):
        return sc.discover_lists(self)

    def catalog(self, key):
        """Read-only, through the agent: the CAs of the domain ('cas', ICertConfig - as
        certutil -dump) or the templates a CA offers ('templates', CR_PROP_TEMPLATES - as
        certutil -CATemplates), each marked whether the agent's policy allows it."""
        if key == 'cas':
            a = self._call({'action': 'cas'})
            opts = []
            for c in a.get('cas') or []:
                words = '%s (%s)' % (c.get('config'), c.get('name')) if c.get('name') else \
                    c.get('config')
                if not c.get('allowed'):
                    words += ' - not allowed by the agent\'s policy'
                opts.append([c.get('config'), words])
            return {'options': opts, 'said': '%d CA%s the agent of %s lists' % (
                len(opts), '' if len(opts) == 1 else 's', self._agent())}
        if key == 'templates':
            a = self._call({'action': 'templates', 'ca': self._ca()})
            opts = []
            for t in a.get('templates') or []:
                words = t.get('display') or t.get('name')
                if t.get('display') and t.get('display') != t.get('name'):
                    words = '%s (%s)' % (t.get('name'), t.get('display'))
                if not t.get('allowed'):
                    words += ' - not allowed by the agent\'s policy'
                opts.append([t.get('name'), words])
            return {'options': opts, 'said': '%d templates %s offers' % (len(opts), self._ca())}
        raise PluginError('there is no list called %s here' % key, retry=False)

    # -- a certificate -----------------------------------------------------------------
    def issue(self, req):
        if not req.csr_pem:
            raise PluginError('there is no request (CSR) to send to the CA', retry=False)
        ca = self._ca()
        template = self._template(req)
        name = self._agent()
        # kept by the certificate (and its key type), with its key and CSR - as ms_adcs keeps
        # a request waiting for a certificate manager
        slot = sc.pending_slot('ms_adcs_agent', ca, req)
        held = sc.pending_get(self.ctx, slot, req)
        r = sc.held_request(req, held) if held and held.get('csr_pem') else req
        if held and held.get('id'):
            rid = str(held['id'])
            template = str(held.get('template') or template)
            self._say('the request %s waits at %s since %s - the agent of %s asks for it again' % (
                rid, ca, time.strftime('%Y-%m-%d %H:%M', time.gmtime(held.get('at') or 0)),
                name))
            a = self._call({'action': 'retrieve', 'ca': ca, 'template': template, 'req_id': rid})
        else:
            self._say('the agent of %s submits the request to %s (template %s)' % (
                name, ca, template))
            a = self._call({'action': 'submit', 'ca': ca, 'template': template,
                            'csr': req.csr_pem, 'san_attr': bool(self.c('san_attr'))})
            rid = str(a.get('req_id') or '')
        state = a.get('state') or 'error'
        if state == 'pending':
            if not held and rid:
                sc.pending_put(self.ctx, slot, req, {'id': rid, 'template': template,
                                                     'csr_pem': req.csr_pem}, ttl_days=90)
            raise PluginError('%s holds the request %s for a certificate manager to approve '
                              '(Certification Authority: Pending Requests - Issue); acme asks '
                              'for it again at the next try' % (ca, rid or '?'), retry=True)
        if state != 'issued':
            sc.pending_drop(self.ctx, slot)
            words = a.get('said') or 'the CA did not issue the certificate'
            raise PluginError('%s %s the request%s: %s' % (
                ca, 'denied' if state == 'denied' else 'did not issue', (' %s' % rid)
                if rid else '', words), retry=False)
        out = self._issued(a, r, rid, ca)
        if r is not req and r.key_pem:
            out.key_pem = r.key_pem                 # the key of the request held
        sc.pending_drop(self.ctx, slot)
        return out

    def _issued(self, a, req, rid, ca):
        try:
            leaf = base64.b64decode(a.get('cert') or '', validate=True)
        except (binascii.Error, ValueError):
            leaf = b''
        if leaf[:1] != b'\x30':
            raise PluginError('the agent sent no certificate for request %s' % rid)
        try:
            cert = der.Cert(leaf)
        except Exception:                           # noqa: BLE001
            raise PluginError('the certificate of request %s cannot be read' % rid)
        if req.csr_der and cert.spki_der != der.csr_spki(req.csr_der):
            raise PluginError('the certificate of request %s is for another key than this '
                              'request - it is not used' % rid, retry=False)
        chain = []
        if a.get('chain'):
            try:
                chain = [d for d in der.certs_from_pkcs7(base64.b64decode(a['chain']))
                         if d != leaf]
            except Exception:                       # noqa: BLE001
                chain = []
        chain = der.order_chain(leaf, chain) if chain else []
        if not chain:
            self._say('the CA sent no chain with request %s - only the certificate' % rid, 'warn')
        self._say('the certificate came: request %s, serial %x, until %s, from %s' % (
            rid, cert.serial, time.strftime('%Y-%m-%d', time.gmtime(cert.not_after)),
            cert.issuer_cn or '?'), 'ok')
        return Issued(der.pem(leaf), [der.pem(c) for c in chain],
                      info={'req_id': rid, 'ca': ca, 'agent': self._agent()})
