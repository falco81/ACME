# -*- coding: utf-8 -*-
"""
Sophos Firewall (SFOS, formerly XG) through its XML API: the certificate
uploaded as PKCS#12 under a dated name (SFOS does not let a certificate in
use be replaced), the firewall (WAF) rules asked for pointed at it, older
acme ones removed.

    POST https://<fw>:4444/webconsole/APIController
         multipart: reqxml = <Request><Login>..</Login><Set operation="add">
                    <Certificate><Action>UploadCertificate</Action><Name>..</Name>
                    <CertificateFormat>pkcs12</CertificateFormat>
                    <CertificateFile>NAME.p12</CertificateFile><Password>..</Password>
                    </Certificate></Set></Request>
                    file   = the .p12
    <Get><Certificate/></Get>, <Get><FirewallRule>..</FirewallRule></Get>,
    <Set operation="update"><FirewallRule>..</FirewallRule></Set>,
    <Remove><Certificate><Name>..</Name></Certificate></Remove>

Rights: Administration → Device access → API: on, with acme's address in the
allowed IP addresses; an administrator with a profile that may change
Certificates (and Firewall rules for the WAF rules).

Sources:
    https://docs.sophos.com/nsg/sophos-firewall/21.0/api/index.html  (API, Certificate entity)
    https://docs.sophos.com/nsg/sophos-firewall/21.0/help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/index.html
    https://community.sophos.com/sophos-xg-firewall/f/discussions/102208/upload-certificate-using-api
Uncertain: the multipart part's name for the file ("file" - what the
community's working examples use; SFOS matches it by CertificateFile); the
place of the certificate in a WAF rule is found by its element name
<Certificate> anywhere in the rule, as in SFOS 18-21.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

from acmelib.plugins.targets._common import (
    HttpTarget, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    http_fields, tls_fields, verify_fields, keep_field, multipart, random_password, text)

OK_CODES = ('200', '202', '216')


class SophosTarget(HttpTarget):
    kind = 'sophos'
    title = 'Sophos Firewall (SFOS / XG)'
    vendor = 'Sophos'
    description = ('Uploads the certificate through the Sophos Firewall XML API under a new '
                   'name, points the web server protection (WAF) rules at it and removes the '
                   'older ones.')
    doc = 'targets.md'
    fields = http_fields(4444, 'fw.example.local') + [
        field('user', 'User', 'text', required=True, default='acme'),
        field('password', 'Password', 'secret', required=True),
    ] + tls_fields()
    deploy_fields = [
        field('rules', 'Firewall (WAF) rules', 'list', placeholder='WAF www.example.com',
              help='one a line: the names of the web server protection rules to use it'),
        keep_field(1),
    ] + verify_fields()

    def login_xml(self):
        return '<Login><Username>%s</Username><Password>%s</Password></Login>' % (
            escape(text(self.c('user'))), escape(text(self.c('password'))))

    def api(self, inner, files=None, what='the XML API'):
        """One request -> the <Response> element. A refused sign-in or a status
        that is not a success is a PluginError."""
        xml = '<Request>%s%s</Request>' % (self.login_xml(), inner)
        parts = [('reqxml', xml)] + list(files or [])
        body, ctype = multipart(parts)
        st, hd, raw = self.req('POST', '/webconsole/APIController', body,
                               {'Content-Type': ctype, 'Accept': 'application/xml'}, what=what)
        try:
            root = ET.fromstring(raw if isinstance(raw, bytes) else text(raw).encode())
        except ET.ParseError:
            raise PluginError('%s: the firewall did not answer with XML' % what,
                              detail=text(raw)[:2000])
        login = root.find('Login/status')
        if login is not None and 'success' not in text(login.text).lower():
            raise PluginError('the firewall does not let acme in: %s (is the API on, and acme\'s '
                              'address allowed?)' % text(login.text).strip(), retry=False)
        for st_el in root.iter('Status'):
            code = st_el.get('code') or ''
            if code and code not in OK_CODES:
                raise PluginError('%s: the firewall said %s - %s' % (what, code,
                                                                     text(st_el.text).strip()),
                                  detail=text(raw)[:4000], retry=code.startswith('5') and
                                  code not in ('510', '541', '502'))
        return root

    def certificates(self):
        root = self.api('<Get><Certificate></Certificate></Get>', what='listing the certificates')
        return [text(c.findtext('Name')) for c in root.iter('Certificate') if c.findtext('Name')]

    def test(self):
        names = self.certificates()
        return 'signed in to %s; %d certificate%s there' % (self.c('host'), len(names),
                                                           '' if len(names) == 1 else 's')

    def point_rule(self, rule, name):
        root = self.api('<Get><FirewallRule><Filter><key name="Name" criteria="=">%s</key>'
                        '</Filter></FirewallRule></Get>' % escape(rule),
                        what='reading the rule %s' % rule)
        el = None
        for r in root.iter('FirewallRule'):
            if text(r.findtext('Name')) == rule:
                el = r
                break
        if el is None:
            raise PluginError('there is no firewall rule "%s"' % rule, retry=False)
        certs = [c for c in el.iter('Certificate')]
        if not certs:
            raise PluginError('the rule "%s" has no certificate (not a WAF rule with HTTPS?)'
                              % rule, retry=False)
        if all(text(c.text) == name for c in certs):
            return 'unchanged'
        for c in certs:
            c.text = name
        for k in list(el.attrib):
            if k == 'transactionid':
                del el.attrib[k]
        self.api('<Set operation="update">%s</Set>' % ET.tostring(el, encoding='unicode'),
                 what='pointing the rule %s at %s' % (rule, name))
        return 'updated'

    def deploy(self, bundle, options):
        options = options or {}
        # SFOS names: up to 50, letters digits - _ . and spaces
        name = object_name(bundle, options, maxlen=50, serial_len=6)
        prefix = name_prefix(bundle, options, maxlen=50, serial_len=6)
        names = self.certificates()
        if self.unchanged(bundle, options, present=lambda: name in names):
            return self.same(bundle, 'as %s' % name)
        did = []
        if name in names and not as_bool(options.get('force')):
            self.ctx.step('%s is there already' % name)
        else:
            if name in names:
                self.ctx.step('%s is there already; a firewall does not take it twice' % name)
            else:
                pw = random_password(16)
                p12 = bundle.as_format('p12-legacy', password=pw, alias=name)
                self.api('<Set operation="add"><Certificate><Action>UploadCertificate</Action>'
                         '<Name>%s</Name><CertificateFormat>pkcs12</CertificateFormat>'
                         '<CertificateFile>%s.p12</CertificateFile><Password>%s</Password>'
                         '</Certificate></Set>' % (escape(name), escape(name), escape(pw)),
                         files=[('file', ('%s.p12' % name, p12, 'application/x-pkcs12'))],
                         what='uploading %s' % name)
                self.ctx.step('uploaded %s' % name, 'ok')
                did.append('uploaded %s' % name)
        for rule in lines(options.get('rules')):
            how = self.point_rule(rule, name)
            self.ctx.step('rule %s %s' % (rule, how), 'ok')
            did.append('rule %s %s' % (rule, how))
        self.cleanup(prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, prefix, current, keep):
        if keep < 0:
            return
        for old in prune(self.certificates(), prefix, keep, current):
            try:
                self.api('<Remove><Certificate><Name>%s</Name></Certificate></Remove>'
                         % escape(old), what='removing %s' % old)
                self.ctx.step('removed the old %s' % old)
            except PluginError as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')

    def remove(self, bundle, options):
        name = object_name(bundle, options, maxlen=50, serial_len=6)
        self.api('<Remove><Certificate><Name>%s</Name></Certificate></Remove>' % escape(name),
                 what='removing %s' % name)

