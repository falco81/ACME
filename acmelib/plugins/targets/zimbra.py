# -*- coding: utf-8 -*-
"""
Zimbra Collaboration (8.7 and later) over SSH: the certificate deployed as
Zimbra's commercial certificate with its own tool - the key put in
/opt/zimbra/ssl/zimbra/commercial/commercial.key, the certificate and the
chain (which must end in the root) checked with "zmcertmgr verifycrt comm",
deployed with "zmcertmgr deploycrt comm", then the services restarted. The
previous key is put back when the check fails.

    su - zimbra -c 'zmcertmgr verifycrt comm <key> <cert> <chain>'
    su - zimbra -c 'zmcertmgr deploycrt comm <cert> <chain>'
    su - zimbra -c 'zmcontrol restart'

Rights: root (or a user who may sudo to root) on each mailbox/proxy/MTA
server; in a multi-server install each one is a target of its own.

Sources:
    https://wiki.zimbra.com/wiki/Installing_a_LetsEncrypt_SSL_Certificate
    https://wiki.zimbra.com/wiki/Administration_Console_and_CLI_Certificate_Tools
Let's Encrypt's chain does not hold its root: give it (ISRG Root X1 for an
RSA chain, ISRG Root X2 or X1 for ECDSA) as "Root CA certificate".
"""
from __future__ import annotations

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, ssh_fields, verify_fields, quote, text)
from acmelib.plugins.targets._x509 import split_chain
from acmelib.plugins.targets import _files as F

COMM = '/opt/zimbra/ssl/zimbra/commercial'
WORK = '/opt/zimbra/ssl/acme'


class ZimbraTarget(SshMixin, Base):
    kind = 'zimbra'
    discovery = False       # nothing to find: a server over SSH
    title = 'Zimbra Collaboration'
    vendor = 'Zimbra'
    description = ('Deploys the certificate as Zimbra\'s commercial certificate with zmcertmgr '
                   'over SSH (checked first, the old key put back when it fails) and restarts '
                   'the services.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('root_pem', 'Root CA certificate', 'pem',
              help='the root the chain ends in - zmcertmgr wants the whole chain up to it '
                   '(ISRG Root X1 for Let\'s Encrypt); empty: the chain must hold it'),
        field('restart', 'Restart', 'select', default='zmcontrol',
              options=[['zmcontrol', 'every Zimbra service (zmcontrol restart)'],
                       ['proxy_mailbox', 'proxy, mailbox and MTA only'],
                       ['none', 'nothing (done by hand)']]),
    ] + F.file_fields() + verify_fields()

    def zm(self, s, cmd, what, timeout=600, check=True):
        return self.sh(s, 'su - zimbra -c %s' % quote(cmd), timeout=timeout, check=check,
                       what=what)

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.zm(s, 'zmcontrol -v', 'signing in', timeout=60)
        return 'signed in to %s: %s' % (self.c('host'), out.strip().splitlines()[0]
                                        if out.strip() else '?')

    def deploy(self, bundle, options):
        options = options or {}
        inter, root = split_chain(bundle, options.get('root_pem'))
        if not root:
            raise PluginError('zmcertmgr wants the chain up to the root, and the chain holds no '
                              'root: give the root CA certificate (ISRG Root X1 for Let\'s '
                              'Encrypt)', retry=False)
        chain = ''.join(inter) + root
        work = [{'path': WORK + '/cert.pem', 'data': bundle.as_format('cert-pem'), 'mode': 0o640,
                 'owner': 'zimbra:zimbra'},
                {'path': WORK + '/chain.pem', 'data': chain.encode(), 'mode': 0o640,
                 'owner': 'zimbra:zimbra'}]
        key = [{'path': COMM + '/commercial.key', 'data': bundle.as_format('key-rsa'),
                'mode': 0o640, 'owner': 'zimbra:zimbra'}]
        with self.ssh() as s:
            if F.skip_same(options) and not self.pending() and \
                    F.all_same_said(self, s, key + [{'path': COMM + '/commercial.crt',
                                                'data': bundle.as_format('cert-pem')}]):
                self.remember(bundle, options)
                return self.same(bundle, 'deployed in Zimbra')
            self.mark_pending(bundle)       # done_pending() once through (1.0.79)
            F.write_files(self, s, work)
            existed = F.write_files(self, s, key, options=options)
            try:
                rc, out, err = self.zm(s, 'zmcertmgr verifycrt comm %s %s %s' % (
                    COMM + '/commercial.key', WORK + '/cert.pem', WORK + '/chain.pem'),
                    'checking', check=False)
                if rc != 0 or 'does not match' in text(out) or 'ERROR' in text(out):
                    F.put_back(self, s, key, existed)
                    raise PluginError('zmcertmgr does not take it, the previous key is back: %s'
                                      % (text(out).strip() or text(err).strip())[-300:],
                                      retry=False)
                self.ctx.step('zmcertmgr verifycrt: the key, certificate and chain match', 'ok')
                rc, out, err = self.zm(s, 'zmcertmgr deploycrt comm %s %s' % (
                    WORK + '/cert.pem', WORK + '/chain.pem'), 'deploying', check=False)
                if rc != 0:
                    F.put_back(self, s, key, existed)
                    raise PluginError('zmcertmgr deploycrt failed, the previous key is back: %s'
                                      % (text(out).strip() or text(err).strip())[-300:])
                self.ctx.step('zmcertmgr deploycrt comm: deployed', 'ok')
            finally:
                self.sh(s, 'rm -f %s/cert.pem %s/chain.pem' % (WORK, WORK), check=False)
            F.drop_previous(self, s, key, options)
            how = self.opt(options, 'restart', 'zmcontrol')
            cmd = {'zmcontrol': 'zmcontrol restart',
                   'proxy_mailbox': 'zmproxyctl restart; zmmailboxdctl restart; zmmtactl restart'
                   }.get(how)
            if cmd:
                rc, out, err = self.zm(s, cmd, 'restarting', timeout=900, check=False)
                self.ctx.step('ran %s%s' % (cmd, '' if rc == 0 else ' - it said: %s'
                                            % (text(err) or text(out)).strip()[-200:]),
                              'ok' if rc == 0 else 'warn')
        self.remember(bundle, options)
        self.done_pending()
        return 'deployed as Zimbra\'s commercial certificate%s' % (', restarted' if cmd else '')
