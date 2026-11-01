# -*- coding: utf-8 -*-
"""
Linux / Unix over SSH: the certificate written as files (any formats, any
places), the service tested and reloaded, rolled back when it does not take it.
"""
from __future__ import annotations

import hashlib
import secrets
import time

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, label_of, stamp,
    parse_outputs, subst, quote, ssh_fields, verify_fields, PFX_FORMATS)


# A preset fills what is left empty: outputs, commands, the port to check.
# {name} is the certificate's name made safe, {service} the field below.
PRESETS = {
    'custom': {'title': 'Custom (fill the fields)'},
    'nginx': {
        'title': 'nginx',
        'outputs': ['fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/nginx/ssl/{name}.key 0600 root:root'],
        'test_cmd': ['nginx -t'], 'reload_cmd': ['systemctl reload nginx'], 'port': 443},
    'apache': {
        'title': 'Apache httpd',
        'outputs': ['cert-pem /etc/ssl/acme/{name}.crt 0644 root:root',
                    'chain-pem /etc/ssl/acme/{name}.chain.crt 0644 root:root',
                    'key-pem /etc/ssl/acme/{name}.key 0600 root:root'],
        'test_cmd': ['apachectl -t'],
        'reload_cmd': ['systemctl reload apache2 2>/dev/null || systemctl reload httpd'],
        'port': 443},
    'haproxy': {
        'title': 'HAProxy (key + chain in one PEM)',
        'outputs': ['combined-pem /etc/haproxy/certs/{name}.pem 0600 root:root'],
        'test_cmd': ['haproxy -c -q -f /etc/haproxy/haproxy.cfg'],
        'reload_cmd': ['systemctl reload haproxy'], 'port': 443},
    'postfix': {
        'title': 'Postfix',
        'outputs': ['fullchain-pem /etc/postfix/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/postfix/ssl/{name}.key 0600 root:root'],
        'test_cmd': ['postfix check'], 'reload_cmd': ['postfix reload'], 'port': 465},
    'dovecot': {
        'title': 'Dovecot',
        'outputs': ['fullchain-pem /etc/dovecot/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/dovecot/ssl/{name}.key 0600 root:root'],
        'test_cmd': ['doveconf -n >/dev/null'], 'reload_cmd': ['systemctl reload dovecot'],
        'port': 993},
    'exim': {
        'title': 'Exim',
        'outputs': ['fullchain-pem /etc/exim4/{name}.crt 0644 root:Debian-exim',
                    'key-pem /etc/exim4/{name}.key 0640 root:Debian-exim'],
        'test_cmd': ['exim -bV >/dev/null'], 'reload_cmd': ['systemctl restart exim4'],
        'port': 465},
    'proxmox': {
        'title': 'Proxmox VE (pveproxy)',
        'outputs': ['fullchain-pem /etc/pve/local/pveproxy-ssl.pem 0640',
                    'key-pem /etc/pve/local/pveproxy-ssl.key 0640'],
        'reload_cmd': ['systemctl restart pveproxy'], 'port': 8006},
    'pbs': {
        'title': 'Proxmox Backup Server',
        'outputs': ['fullchain-pem /etc/proxmox-backup/proxy.pem 0640 root:backup',
                    'key-pem /etc/proxmox-backup/proxy.key 0640 root:backup'],
        'reload_cmd': ['systemctl reload proxmox-backup-proxy'], 'port': 8007},
    'tomcat': {
        'title': 'Tomcat / Java keystore',
        'outputs': ['jks /etc/tomcat/{name}.jks 0640 root:tomcat'],
        'reload_cmd': ['systemctl restart {service}'], 'service': 'tomcat', 'port': 8443},
    'docker': {
        'title': 'Docker volume (container restarted)',
        'outputs': ['fullchain-pem /srv/docker/certs/{name}/fullchain.pem 0644',
                    'key-pem /srv/docker/certs/{name}/privkey.pem 0600'],
        'reload_cmd': ['docker restart {service}'], 'service': 'web', 'port': 443},
    'kubernetes': {
        'title': 'Kubernetes TLS secret (kubectl)',
        'outputs': ['fullchain-pem /run/acme-k8s/{name}.crt 0600',
                    'key-pem /run/acme-k8s/{name}.key 0600'],
        'reload_cmd': [
            'kubectl create secret tls {service} --cert=/run/acme-k8s/{name}.crt '
            '--key=/run/acme-k8s/{name}.key --dry-run=client -o yaml | kubectl apply -f -',
            'rm -f /run/acme-k8s/{name}.crt /run/acme-k8s/{name}.key'],
        'service': 'web-tls', 'backup': False},
    'webmin': {
        'title': 'Webmin',
        'outputs': ['combined-pem /etc/webmin/miniserv.pem 0600 root:root',
                    'chain-pem /etc/webmin/miniserv.chain 0644 root:root'],
        'reload_cmd': ['systemctl restart webmin'], 'port': 10000},
    'cockpit': {
        'title': 'Cockpit',
        'outputs': ['fullchain-pem /etc/cockpit/ws-certs.d/90-acme.crt 0644 root:root',
                    'key-pem /etc/cockpit/ws-certs.d/90-acme.key 0640 root:cockpit-ws'],
        'reload_cmd': ['systemctl restart cockpit'], 'port': 9090},
    'vsftpd': {
        'title': 'vsftpd',
        'outputs': ['combined-pem /etc/ssl/private/vsftpd.pem 0600 root:root'],
        'reload_cmd': ['systemctl restart vsftpd']},
    'openldap': {
        'title': 'OpenLDAP (slapd)',
        'outputs': ['cert-pem /etc/ldap/ssl/{name}.crt 0644 root:openldap',
                    'chain-pem /etc/ldap/ssl/{name}.chain.crt 0644 root:openldap',
                    'key-pem /etc/ldap/ssl/{name}.key 0640 root:openldap'],
        'reload_cmd': ['systemctl restart slapd'], 'port': 636},
    'grafana': {
        'title': 'Grafana',
        'outputs': ['fullchain-pem /etc/grafana/{name}.crt 0644 root:grafana',
                    'key-pem /etc/grafana/{name}.key 0640 root:grafana'],
        'reload_cmd': ['systemctl restart grafana-server'], 'port': 3000},
    'plex': {
        'title': 'Plex Media Server (PKCS#12)',
        'outputs': ['pfx /var/lib/plexmediaserver/{name}.p12 0640 plex:plex'],
        'reload_cmd': ['systemctl restart plexmediaserver'], 'port': 32400},
    'mariadb': {
        'title': 'MySQL / MariaDB',
        'outputs': ['fullchain-pem /etc/mysql/ssl/{name}.crt 0644 root:mysql',
                    'key-pem /etc/mysql/ssl/{name}.key 0640 root:mysql'],
        'reload_cmd': ['systemctl restart {service}'], 'service': 'mariadb'},
    'unifi': {
        'title': 'UniFi Network (keystore)',
        'outputs': ['jks /usr/lib/unifi/data/keystore 0640 unifi:unifi'],
        'jks_alias': 'unifi', 'pfx_password': 'aircontrolenterprise',
        'reload_cmd': ['systemctl restart unifi'], 'port': 8443},
}


def _preset_fills():
    out = {}
    for k, p in PRESETS.items():
        d = {}
        for key in ('outputs', 'test_cmd', 'reload_cmd'):
            if p.get(key):
                d[key] = '\n'.join(p[key])
        for key in ('service', 'jks_alias', 'backup'):
            if key in p:
                d[key] = p[key]
        if p.get('port'):
            d['verify'] = '{host}:%d' % p['port']
        out[k] = d
    return out


SAMPLE = ('fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root\n'
          'key-pem /etc/nginx/ssl/{name}.key 0600 root:root\n'
          'pfx /opt/app/keystore.p12 0640 app:app')


class SshTarget(SshMixin, Base):
    kind = 'ssh'
    title = 'Linux / Unix server (SSH)'
    vendor = 'Linux / Unix'
    description = ('Writes the certificate as files in the formats and places asked '
                   '(atomically, the old ones kept as .bak), tests the configuration, '
                   'reloads the service and puts the old files back when it fails.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('tmp_dir', 'Folder for uploads', 'text', default='/tmp', advanced=True,
              help='where files are put first, before they are moved into place'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('preset', 'Service', 'select', default='custom',
              options=[[k, p['title']] for k, p in PRESETS.items()],
              fills=_preset_fills(),
              help='fills the files and commands below with what that service usually '
                   'wants; whatever you set yourself wins'),
        field('outputs', 'Files', 'list', placeholder=SAMPLE,
              help='one a line: format path [mode] [owner[:group]]. Formats: cert-pem, '
                   'fullchain-pem, chain-pem, key-pem, key-rsa, combined-pem (key + '
                   'fullchain), cert-der, key-der, p7b, pfx/p12, p12-legacy, jks. '
                   'In paths: {name} {cn} {service} {date}'),
        field('pfx_password', 'PKCS#12 / keystore password', 'secret',
              help='for pfx, p12, p12-legacy and jks files (jks needs one)'),
        field('jks_alias', 'Keystore alias', 'text', advanced=True,
              help='the alias in a jks or pfx; empty: the certificate\'s name'),
        field('service', 'Service / container / secret name', 'text', advanced=True,
              help='{service} in the paths and commands'),
        field('backup', 'Keep the previous files as .bak', 'bool', default=True),
        field('pre_cmd', 'Before writing', 'list', advanced=True,
              help='commands run first; one failing stops the deployment'),
        field('test_cmd', 'Test command', 'list', placeholder='nginx -t',
              help='run after writing; when one fails the previous files are put back'),
        field('reload_cmd', 'Reload / restart', 'list', placeholder='systemctl reload nginx',
              help='run after the test; when one fails the previous files are put back '
                   'and these run again'),
        field('post_cmd', 'After reloading', 'list', advanced=True,
              help='run last; a failure here is only a warning'),
    ] + verify_fields()

    _sleep = staticmethod(time.sleep)

    # -- what the options say, the preset filling in ------------------------
    def resolved(self, bundle, options):
        options = dict(options or {})
        preset = PRESETS.get(options.get('preset') or 'custom') or PRESETS['custom']
        out = {}
        for key in ('outputs', 'test_cmd', 'reload_cmd', 'service', 'jks_alias', 'pfx_password',
                    'backup'):
            v = options.get(key)
            if v in (None, '', []) and key in preset:
                v = preset[key]
            out[key] = v
        for key in ('pre_cmd', 'post_cmd'):
            out[key] = options.get(key)
        out['backup'] = as_bool(out['backup'], True)
        name = label_of(bundle, options)
        cn = label_of(bundle, {'object_name': (list(bundle.names or [name]))[0]})
        vars = {'name': name, 'cn': cn, 'date': stamp(bundle),
                'service': out['service'] or name, 'host': self.c('host')}
        out['vars'] = vars
        out['files'] = parse_outputs(out['outputs'], vars)
        if not out['files']:
            raise PluginError('no files to write: choose a service or fill in "Files"',
                              retry=False)
        for key in ('pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd'):
            out[key] = [subst(c, vars) for c in lines(out[key])]
        return out

    def render(self, bundle, r):
        """The bytes of each file."""
        alias = r['jks_alias'] or r['vars']['name']
        datas = []
        for f in r['files']:
            pw = None
            if f['format'] in PFX_FORMATS:
                pw = r['pfx_password'] or None
                if f['format'] == 'jks' and (not pw or len(pw) < 6):
                    raise PluginError('a jks keystore needs a password of 6 characters '
                                      'or more', retry=False)
            data = bundle.as_format(f['format'], password=pw, alias=alias)
            if isinstance(data, str):
                data = data.encode()
            datas.append(data)
        return datas

    # -- try ------------------------------------------------------------------
    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'id -un; uname -sr', sudo=False, what='signing in')
            who = out.split('\n')
            words = 'signed in as %s on %s' % (who[0].strip(), (who[1:] or ['?'])[0].strip())
            if as_bool(self.c('sudo')):
                rc, out, err = self.sh(s, 'id -un', check=False)
                if rc != 0 or out.strip() != 'root':
                    raise PluginError('signed in, but sudo does not work: %s'
                                      % (err.strip() or out.strip())[-200:], retry=False)
                words += '; sudo works'
        return words

    # -- deploy -----------------------------------------------------------------
    def deploy(self, bundle, options):
        options = options or {}
        r = self.resolved(bundle, options)
        datas = self.render(bundle, r)
        files = r['files']
        force = as_bool(options.get('force'))
        tmpdir = (self.c('tmp_dir') or '/tmp').rstrip('/')
        token = secrets.token_hex(6)
        suffix = '.bak' if r['backup'] else '.acme-prev'

        with self.ssh() as s:
            if not force and self._all_same(s, files, datas, bundle, options):
                return self.same(bundle, 'in every file')
            for c in r['pre_cmd']:
                self.sh(s, c, what='"%s"' % c)
                self.ctx.step('ran %s' % c)
            tmps = []
            try:
                for i, (f, data) in enumerate(zip(files, datas)):
                    tmp = '%s/.acme-%s-%d' % (tmpdir, token, i)
                    s.put(data, tmp, 0o600)
                    tmps.append(tmp)
                existed = self._install(s, files, tmps, suffix)
                self.ctx.step('wrote %s' % ', '.join(f['path'] for f in files), 'ok')
                failed = self._commands(s, r['test_cmd'], 'test')
                if failed:
                    self._rollback(s, files, existed, suffix)
                    raise PluginError('the test "%s" failed, the previous files are back: %s'
                                      % failed, retry=False)
                failed = self._commands(s, r['reload_cmd'], 'reload')
                if failed:
                    self._rollback(s, files, existed, suffix)
                    self._commands(s, r['reload_cmd'], 'reload with the previous files')
                    raise PluginError('"%s" failed, the previous files are back: %s' % failed)
                if not r['backup']:
                    self.sh(s, 'rm -f ' + ' '.join(quote(f['path'] + suffix) for f in files),
                            check=False)
                for c in r['post_cmd']:
                    rc, out, err = self.sh(s, c, check=False)
                    self.ctx.step('ran %s%s' % (c, '' if rc == 0 else ' - failed: %s'
                                                % (err.strip() or out.strip())[-200:]),
                                  'info' if rc == 0 else 'warn')
            finally:
                if tmps:
                    try:
                        s.run('rm -f ' + ' '.join(quote(t) for t in tmps), check=False)
                    except Exception:                       # noqa: BLE001
                        pass
        self.remember(bundle, options)
        return '%d file%s written on %s%s' % (
            len(files), '' if len(files) == 1 else 's', self.c('host'),
            ', reloaded' if r['reload_cmd'] else '')

    def _all_same(self, s, files, datas, bundle, options):
        """Every text file there already holds exactly this (PEM is the same
        every time; PKCS#12 and keystores are not, so they ask the memory)."""
        want = [(f['path'], hashlib.sha256(d).hexdigest()) for f, d in zip(files, datas)
                if f['format'] not in PFX_FORMATS and f['format'] != 'p7b']
        if want:
            rc, out, err = self.sh(s, 'sha256sum %s 2>/dev/null; true'
                                   % ' '.join(quote(p) for p, _ in want), check=False)
            have = {}
            for line in out.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2:
                    have[parts[1].strip().lstrip('*')] = parts[0].lower()
            if any(have.get(p) != h for p, h in want):
                return False
        if len(want) == len(files):
            return True
        return self.unchanged(bundle, options)

    def _install(self, s, files, tmps, suffix):
        """mkdir -p, the old file copied aside, the new one copied next to its
        place, its mode and owner set, then moved over (rename: atomic).
        -> [True/False: was there one before], one a file."""
        script = ['set -e']
        for i, (f, tmp) in enumerate(zip(files, tmps)):
            p = quote(f['path'])
            new = quote(f['path'] + '.acme-new')
            script += [
                'mkdir -p "$(dirname %s)"' % p,
                'if [ -e %s ]; then cp -p %s %s; echo "EXISTED %d"; fi' % (
                    p, p, quote(f['path'] + suffix), i),
                'cp %s %s' % (quote(tmp), new),
                'chmod %o %s' % (f['mode'], new),
            ]
            if f['owner']:
                script.append('chown %s %s' % (quote(f['owner']), new))
            script.append('mv -f %s %s' % (new, p))
        rc, out, err = self.sh(s, '\n'.join(script), check=False)
        existed = [False] * len(files)
        for line in out.splitlines():
            if line.startswith('EXISTED '):
                existed[int(line.split()[1])] = True
        if rc != 0:
            self._rollback(s, files, existed, suffix)
            raise PluginError('the files could not be written, the previous ones are back: %s'
                              % (err.strip() or out.strip())[-300:],
                              detail='\n'.join(script) + '\n' + out + err)
        return existed

    def _rollback(self, s, files, existed, suffix):
        script = []
        for f, was in zip(files, existed):
            p = quote(f['path'])
            if was:
                script.append('cp -p %s %s' % (quote(f['path'] + suffix), p))
            else:
                script.append('rm -f %s' % p)
            script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
        rc, out, err = self.sh(s, '\n'.join(script), check=False)
        self.ctx.step('the previous files are back' if rc == 0 else
                      'putting the previous files back failed: %s' % err.strip()[-200:],
                      'warn' if rc == 0 else 'bad')

    def _commands(self, s, cmds, what):
        """Run each; -> None, or (command, what it said) of the first failing."""
        for c in cmds:
            rc, out, err = self.sh(s, c, check=False, timeout=300)
            if rc != 0:
                said = (err.strip() or out.strip())[-300:] or 'exit %s' % rc
                self.ctx.step('%s: %s failed: %s' % (what, c, said), 'bad')
                return (c, said)
            self.ctx.step('%s: %s' % (what, c), 'ok')
        return None

    def verify(self, bundle, options):
        options = dict(options or {})
        if not lines(options.get('verify')):
            preset = PRESETS.get(options.get('preset') or 'custom') or {}
            if preset.get('port'):
                options['verify'] = '%s:%d' % (self.c('host'), preset['port'])
        else:
            options['verify'] = '\n'.join(subst(x, {'host': self.c('host')})
                                          for x in lines(options['verify']))
        return Base.verify(self, bundle, options)
