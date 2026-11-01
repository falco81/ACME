# -*- coding: utf-8 -*-
"""DNS-01 through an acme-dns server (github.com/joohoi/acme-dns): its /update
API; _acme-challenge.NAME is a CNAME to the account's fulldomain, once."""
from __future__ import annotations

import json
import time

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge, api, as_bool,
                                                base_name, check_txt)


class AcmeDns(DnsChallenge):
    kind = 'acme_dns'
    title = 'acme-dns'
    vendor = 'DNS'
    description = ('An acme-dns server answers the TXT records; your DNS has _acme-challenge.NAME '
                   'as a CNAME to the account\'s fulldomain, put in once.')
    fields = [
        field('url', 'acme-dns server', 'text', required=True, placeholder='https://auth.acme-dns.io',
              help='Its API address.'),
        field('username', 'Username', 'text', default='',
              help='Of the account (from POST /register).'),
        field('password', 'Password (API key)', 'secret'),
        field('subdomain', 'Subdomain', 'text', default=''),
        field('fulldomain', 'Full domain', 'text', default='',
              placeholder='d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.acme-dns.io',
              help='What _acme-challenge.NAME is a CNAME to.'),
        field('accounts', 'Accounts by name (JSON)', 'secret', multiline=True, default='',
              advanced=True,
              help='Several accounts, as acme-dns-client / lego keep them: {"example.com": '
                   '{"username": .., "password": .., "subdomain": .., "fulldomain": ..}, ...}. '
                   'An acme-dns account keeps two TXT values only, so a certificate of more '
                   'than two names needs one account per name.'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def account(self, name):
        base = base_name(name)
        raw = self.c('accounts', '')
        if raw:
            try:
                accts = json.loads(raw)
            except ValueError:
                raise PluginError('the accounts are not JSON', retry=False)
            for key in (base, '*.' + base, name):
                if key in accts:
                    return accts[key]
        if not self.c('username') or not self.c('subdomain'):
            raise PluginError('no acme-dns account for %s' % base, retry=False)
        return {'username': self.c('username'), 'password': self.c('password', ''),
                'subdomain': self.c('subdomain'), 'fulldomain': self.c('fulldomain', '')}

    def present(self, name, token, key_authorization, txt_value):
        check_txt(txt_value)
        acct = self.account(name)
        rr = self.record_name(name)
        url = str(acct.get('server_url') or self.c('url', '')).rstrip('/')
        api(self.ctx, 'POST', url + '/update', {'subdomain': acct['subdomain'], 'txt': txt_value},
            {'X-Api-User': acct['username'], 'X-Api-Key': acct.get('password', '')},
            who='acme-dns', verify=as_bool(self.c('verify_tls', True)))
        fqdn = D.norm(acct.get('fulldomain')) or self.target(rr)
        self.ctx.step('acme-dns has %s TXT "%s"' % (fqdn, txt_value))
        return {'rr': rr, 'fqdn': fqdn, 'txt': txt_value, 'at': time.time(), 'h': None}

    def cleanup(self, name, handle):
        pass                    # acme-dns keeps the last two values; nothing to take away

    def test(self):
        url = str(self.c('url', '')).rstrip('/')
        api(self.ctx, 'GET', url + '/health', who='acme-dns', verify=as_bool(self.c('verify_tls', True)))
        out = ['%s answers' % url]
        fd = D.norm(self.c('fulldomain', ''))
        if fd:
            out.append('put in your DNS, once per name: _acme-challenge.NAME. CNAME %s.' % fd)
        return '\n'.join(out)

    # -- what a person is told -------------------------------------------------------
    def guide(self, name):
        try:
            base = base_name(name)
            acct = self.account(name)
        except PluginError as e:
            return guide_of([guide_step('account', 'There is an acme-dns account for the name',
                                        where='acme', done=False, said=str(e),
                                        fix='Register an account at the acme-dns server and '
                                            'set it in the validation')])
        steps = self.guide_access()
        rr = '_acme-challenge.' + base
        full = D.norm(acct.get('fulldomain'))
        home = self.home_of(base)
        if not full:
            steps.append(guide_step('cname', 'The name is pointed at acme-dns by a CNAME',
                                    where='your DNS at %s' % home, done=False,
                                    said='the account has no full domain set',
                                    fix='Set the full domain of the account (from /register)'))
            return guide_of(steps)
        rec = {'name': rr, 'type': 'CNAME', 'value': full + '.', 'ttl': 3600}
        chain = self.cname_chain(rr)
        if chain[-1] == full:
            steps.append(guide_step('cname', 'The name is pointed at acme-dns by a CNAME',
                                    where='your DNS at %s' % home, record=rec, done=True,
                                    said='%s is a CNAME to %s' % (rr, full)))
        else:
            steps.append(guide_step('cname', 'The name is pointed at acme-dns by a CNAME',
                                    where='your DNS at %s' % home, record=rec, done=False,
                                    said=('%s leads to %s' % (rr, chain[-1])) if len(chain) > 1
                                    else '%s has no CNAME' % rr,
                                    fix='Create in the DNS of %s: %s. CNAME %s.' % (home, rr,
                                                                                   full)))
        steps.append(self.guide_wait())
        return guide_of(steps)

