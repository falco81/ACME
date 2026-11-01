# -*- coding: utf-8 -*-
"""DNS-01 by a hook script of your own on this machine (as dehydrated, lego's
exec provider or certbot's manual hooks call them)."""
from __future__ import annotations

import os
import subprocess

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, as_list


class Script(DnsChallenge):
    kind = 'script'
    title = 'A script of your own'
    vendor = 'DNS'
    description = ('A program on this machine puts the TXT record in and takes it away - for a '
                   'DNS acme has no module for.')
    parallel = False
    fields = [
        field('path', 'Program', 'text', required=True, placeholder='/etc/acme/hooks/dns.sh',
              help='Run as the user acme, with the environment below. It must exit 0. Keep it '
                   'where only root can change it (/etc/acme/hooks).'),
        field('style', 'Called as', 'select', default='acme',
              options=[['acme', 'PROGRAM present|cleanup RECORD VALUE (and ACME_* variables)'],
                       ['dehydrated', 'PROGRAM deploy_challenge|clean_challenge NAME TOKEN VALUE'],
                       ['lego', 'PROGRAM present|cleanup RECORD. VALUE (lego exec)']],
              help='The environment always has ACME_ACTION, ACME_NAME, ACME_RECORD (where the TXT '
                   'goes, its CNAME followed), ACME_CHALLENGE_NAME (_acme-challenge.NAME), '
                   'ACME_TXT, ACME_TOKEN, ACME_ZONE (when known), ACME_TTL.'),
        field('env', 'More environment', 'list', default='', placeholder='DNS_API_KEY=...',
              help='KEY=VALUE, one a line.'),
        field('secret_env', 'Secret environment', 'secret', multiline=True, default='',
              help='KEY=VALUE lines kept sealed (API keys for the script).'),
        field('timeout', 'Timeout (s)', 'number', default=120, advanced=True),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    def _run(self, action, name, fqdn, rr, value, token=''):
        path = self.c('path', '')
        if not path or not os.path.isabs(path):
            raise PluginError('the program must be given with its full path', retry=False)
        if not os.access(path, os.X_OK):
            raise PluginError('%s is not there or not executable' % path, retry=False)
        style = self.c('style', 'acme')
        if style == 'dehydrated':
            args = [path, 'deploy_challenge' if action == 'present' else 'clean_challenge',
                    name, token or '-', value]
        elif style == 'lego':
            args = [path, action, fqdn + '.', value]
        else:
            args = [path, action, fqdn, value]
        env = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
               'HOME': os.environ.get('HOME', '/'), 'LANG': 'C.UTF-8'}
        for line in as_list(self.c('env', '')) + as_list(self.c('secret_env', '')):
            if '=' in line:
                k, _, v = line.partition('=')
                env[k.strip()] = v.strip()
        zone = self._zones.get(fqdn) or ''
        env.update({'ACME_ACTION': action, 'ACME_NAME': name, 'ACME_RECORD': fqdn,
                    'ACME_CHALLENGE_NAME': rr, 'ACME_TXT': value, 'ACME_TOKEN': token or '',
                    'ACME_ZONE': zone, 'ACME_TTL': str(self.ttl())})
        try:
            got = subprocess.run(args, env=env, capture_output=True, timeout=self.num('timeout', 120),
                                 stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise PluginError('%s did not finish within %d s' % (path, self.num('timeout', 120)))
        except OSError as e:
            raise PluginError('%s could not be run: %s' % (path, e), retry=False)
        out = (got.stdout + got.stderr).decode('utf-8', 'replace').strip()
        if out:
            self.ctx.debug('%s %s: %s' % (os.path.basename(path), action, out[-2000:]))
        if got.returncode != 0:
            raise PluginError('%s %s ended with %d: %s' % (os.path.basename(path), action,
                                                           got.returncode, out[-300:]),
                              detail=out)
        return out

    def present(self, name, token, key_authorization, txt_value):
        self._token = token
        return DnsChallenge.present(self, name, token, key_authorization, txt_value)

    def add_txt(self, fqdn, value):
        self._run('present', self._name, fqdn, self._rr, value, getattr(self, '_token', ''))
        return {'name': self._name, 'rr': self._rr}

    def del_txt(self, fqdn, value, handle):
        h = handle or {}
        self._run('cleanup', h.get('name') or fqdn, fqdn, h.get('rr') or fqdn, value)

    def record_name(self, name):
        rr = DnsChallenge.record_name(self, name)
        self._name, self._rr = rr[len('_acme-challenge.'):], rr
        return rr

    def test(self):
        path = self.c('path', '')
        if not path or not os.path.isabs(path) or not os.access(path, os.X_OK):
            raise PluginError('%s is not there or not executable' % (path or 'the program'),
                              retry=False)
        return '%s is there and may be run (it is only run for real orders)' % path
