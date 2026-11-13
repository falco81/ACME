# -*- coding: utf-8 -*-
"""
TrueNAS (SCALE / Community Edition, and CORE) over SSH with the middleware
client midclt: the certificate imported under a dated name, made the web
interface's certificate (and FTP's, when asked), the web interface
restarted, older acme ones deleted. midclt speaks to the middleware on the
machine itself, so it works on releases whose REST API is gone (25.04
deprecated it).

    midclt call certificate.query
    midclt call -j certificate.create '{"name", "create_type": "CERTIFICATE_CREATE_IMPORTED",
                                        "certificate", "privatekey"}'
    midclt call system.general.update '{"ui_certificate": ID}'
    midclt call system.general.ui_restart
    midclt call ftp.update '{"ssltls_certificate": ID}'
    midclt call -j certificate.delete ID

Rights: root, or an admin user with sudo (truenas_admin on SCALE 24.04+);
SSH on (System → Services → SSH).

Sources:
    https://api.truenas.com/v25.04/api_methods_certificate.create.html
    https://api.truenas.com/v25.04/api_methods_system.general.update.html
    https://www.truenas.com/docs/scale/scaletutorials/systemsettings/certificatesscale/
    https://github.com/acmesh-official/acme.sh/blob/master/deploy/truenas_ws.sh
Uncertain: TrueNAS 26 renames some certificate.create parameters
(acme.sh notes a "--plain" option of midclt there); what midclt answers
is read as JSON either way.
"""
from __future__ import annotations

import json
import re
import secrets

from acmelib.plugins.targets._common import (join_hostport, 
    Base, SshMixin, PluginError, field, as_bool, object_name, name_prefix, prune,
    ssh_fields, verify_fields, keep_field, quote, text)


def tn_name(n):
    """TrueNAS takes letters, digits, - and _ in a certificate's name."""
    return re.sub(r'[^A-Za-z0-9_-]', '_', n)


class TrueNasTarget(SshMixin, Base):
    kind = 'truenas'
    discovery = False       # nothing to find: a server over SSH
    title = 'TrueNAS (midclt over SSH)'
    vendor = 'iXsystems'
    description = ('Imports the certificate into TrueNAS with midclt over SSH, makes it the web '
                   'interface\'s (and FTP\'s) certificate, restarts the web interface and deletes '
                   'the older ones.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True, user_default='truenas_admin') + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('ui', 'Web interface certificate', 'bool', default=True),
        field('ftp', 'FTP certificate', 'bool', default=False),
        keep_field(1),
    ] + verify_fields()

    def midclt(self, s, args, what, job=False, check=True):
        cmd = 'midclt call %s%s' % ('-j ' if job else '', args)
        rc, out, err = self.sh(s, cmd, timeout=300, check=False)
        if rc != 0 and check:
            raise PluginError('%s: midclt said %s' % (what, (text(err).strip() or
                                                            text(out).strip())[-300:]),
                              detail='$ %s\n%s\n%s' % (cmd[:200], out, err))
        out = text(out).strip()
        # a job prints its progress first, the result last
        last = out.splitlines()[-1] if out else ''
        try:
            return json.loads(last) if last else None
        except ValueError:
            try:
                return json.loads(out)
            except ValueError:
                return out

    def certs(self, s):
        d = self.midclt(s, 'certificate.query', 'listing the certificates')
        return [c for c in (d or []) if isinstance(c, dict)] if isinstance(d, list) else []

    def test(self):
        with self.ssh() as s:
            ver = self.midclt(s, 'system.version', 'signing in')
            n = len(self.certs(s))
        return 'signed in: %s, %d certificate%s' % (ver, n, '' if n == 1 else 's')

    def deploy(self, bundle, options):
        options = options or {}
        name = tn_name(object_name(bundle, options))
        prefix = tn_name(name_prefix(bundle, options))
        did = []
        with self.ssh() as s:
            have = {c.get('name'): c.get('id') for c in self.certs(s)}
            gen = None
            if as_bool(self.opt(options, 'ui', True), True):
                gen = self.midclt(s, 'system.general.config', 'reading the web interface')
            ui_id = ((gen or {}).get('ui_certificate') or {}) if isinstance(gen, dict) else {}
            ui_id = ui_id.get('id') if isinstance(ui_id, dict) else ui_id
            if not as_bool(options.get('force')) and name in have and \
                    (gen is None or ui_id == have[name]) and self.unchanged(bundle, options):
                return self.same(bundle, 'as %s' % name)
            if name not in have:
                body = json.dumps({'name': name, 'create_type': 'CERTIFICATE_CREATE_IMPORTED',
                                   'certificate': text(bundle.as_format('fullchain-pem')),
                                   'privatekey': text(bundle.as_format('key-pem'))})
                tmp = '/tmp/.acme-truenas-%s' % secrets.token_hex(6)
                s.put(body.encode(), tmp, 0o600)
                try:
                    # The key never on a command line (1.0.51): "$(cat tmp)" put it into midclt's
                    # arguments, for any user of the NAS to read in ps. Its own client reads the
                    # file; midclt as before only where that client is not there.
                    code = ('import json, sys\n'
                            'try:\n    from truenas_api_client import Client\n'
                            'except ImportError:\n    from middlewared.client import Client\n'
                            'with Client() as c:\n'
                            '    print(json.dumps(c.call("certificate.create", '
                            'json.load(open(sys.argv[1])), job=True)))\n')
                    rc, out, err = self.sh(s, 'python3 -c %s %s' % (quote(code), quote(tmp)),
                                           timeout=300, check=False)
                    if rc != 0 and re.search(r'ImportError|ModuleNotFoundError|python3: not '
                                             r'found|command not found',
                                             text(err) + text(out)):
                        self.ctx.step('no client of the middleware for python here - imported '
                                      'with midclt', 'warn')
                        self.midclt(s, 'certificate.create "$(cat %s)"' % quote(tmp),
                                    'importing %s' % name, job=True)
                    elif rc != 0:
                        raise PluginError('importing %s: %s' % (name, (text(err).strip() or
                                                                      text(out).strip())[-300:]))
                finally:
                    s.run('rm -f %s' % quote(tmp), check=False)
                have = {c.get('name'): c.get('id') for c in self.certs(s)}
                if name not in have:
                    raise PluginError('TrueNAS does not list %s after importing it' % name)
                self.ctx.step('imported %s (id %s)' % (name, have[name]), 'ok')
                did.append('imported %s' % name)
            cid = have[name]
            if gen is not None and ui_id != cid:
                self.midclt(s, 'system.general.update %s' % quote(json.dumps(
                    {'ui_certificate': cid})), 'setting the web interface certificate')
                self.midclt(s, 'system.general.ui_restart', 'restarting the web interface',
                            check=False)
                self.ctx.step('the web interface uses %s and restarts' % name, 'ok')
                did.append('web interface')
            if as_bool(options.get('ftp')):
                self.midclt(s, 'ftp.update %s' % quote(json.dumps({'ssltls_certificate': cid})),
                            'setting the FTP certificate')
                self.ctx.step('FTP uses %s' % name, 'ok')
                did.append('FTP')
            self.cleanup(s, have, prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did) or 'already %s' % name

    def cleanup(self, s, have, prefix, current, keep):
        if keep < 0:
            return
        for old in prune([n for n in have if n], prefix, keep, current):
            try:
                self.midclt(s, 'certificate.delete %s' % int(have[old]), 'deleting %s' % old,
                            job=True)
                self.ctx.step('deleted the old %s' % old)
            except (PluginError, TypeError, ValueError) as e:
                self.ctx.step('the old %s stays (still used?): %s' % (old, e), 'warn')

    served_wait = (8, 5)

    def served_places(self, options):
        if not self.c('host') or not as_bool(self.opt(options or {}, 'ui', True), True):
            return []
        return [(self.c('host'), 443)]

    def verify(self, bundle, options):
        options = dict(options or {})
        if not options.get('verify') and as_bool(self.opt(options, 'ui', True), True):
            options['verify'] = join_hostport(self.c('host'), 443)
            options.setdefault('verify_tries', 8)
        return Base.verify(self, bundle, options)
