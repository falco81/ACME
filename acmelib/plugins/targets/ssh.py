# -*- coding: utf-8 -*-
"""
Linux / Unix over SSH: the certificate written as files (any formats, any
places), the service tested and reloaded, rolled back when it does not take it.

A dual certificate (ECDSA and RSA of the same names): an output line names
one of the two with a suffix - fullchain-pem@rsa, key-pem@ec, @alt, @main -
and the presets of the services that serve both (nginx, Apache, HAProxy,
Postfix, Dovecot, Exim) write the twin's files beside the main ones by
themselves: {name}.crt / {name}.key and {name}.rsa.crt / {name}.rsa.key
({alt} in a path is the twin's kind: rsa or ec). HAProxy gets two files,
{name}.ecdsa.pem and {name}.rsa.pem - "crt /etc/haproxy/certs/" (the folder:
HAProxy loads every file in it and gives each client the ECDSA or the RSA one
of the same name) or a crt-list; not the multi-certificate bundle
(crt site.pem loading site.pem.ecdsa / .rsa), which HAProxy 2.3 took away.

The files a deployment wrote are remembered (per deployment); when the set
changes - a certificate becomes dual, or no longer is, or its outputs are
edited - the ones written before and not now are taken away (only those acme
wrote itself, never another file), put back if the test or reload fails.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, label_of, stamp,
    parse_outputs, subst, quote, ssh_fields, verify_fields, PFX_FORMATS, alt_of, family_of,
    variants_of, outputs_for, service_of)
from acmelib.plugins.targets import _files as F
from acmelib.plugins.targets import _script as SC


# A preset fills what is left empty: outputs, commands, the port to check.
# {name} is the certificate's name made safe, {service} the field below.
# A dual certificate: 'alt_outputs' are written too (the twin's files, {alt}
# its kind: rsa or ec), or 'dual_outputs' are written instead of 'outputs'
# (HAProxy's bundle) when the two are one ECDSA and one RSA.
PRESETS = {
    'custom': {'title': 'Custom (fill the fields)'},
    'nginx': {
        'title': 'nginx',
        'outputs': ['fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/nginx/ssl/{name}.key 0600 root:root'],
        # nginx: ssl_certificate and ssl_certificate_key twice, one pair each
        'alt_outputs': ['fullchain-pem@alt /etc/nginx/ssl/{name}.{alt}.crt 0644 root:root',
                        'key-pem@alt /etc/nginx/ssl/{name}.{alt}.key 0600 root:root'],
        'test_cmd': ['nginx -t'], 'reload_cmd': ['systemctl reload nginx'], 'port': 443},
    'apache': {
        'title': 'Apache httpd',
        'outputs': ['cert-pem /etc/ssl/acme/{name}.crt 0644 root:root',
                    'chain-pem /etc/ssl/acme/{name}.chain.crt 0644 root:root',
                    'key-pem /etc/ssl/acme/{name}.key 0600 root:root'],
        # Apache 2.4.8+: a second SSLCertificateFile / SSLCertificateKeyFile pair (the
        # twin's file holds its own chain - its intermediate is not the main one's)
        'alt_outputs': ['fullchain-pem@alt /etc/ssl/acme/{name}.{alt}.crt 0644 root:root',
                        'key-pem@alt /etc/ssl/acme/{name}.{alt}.key 0600 root:root'],
        'test_cmd': ['apachectl -t'],
        'reload_cmd': ['systemctl reload apache2 2>/dev/null || systemctl reload httpd'],
        'port': 443},
    'haproxy': {
        'title': 'HAProxy (key + chain in one PEM)',
        'outputs': ['combined-pem /etc/haproxy/certs/{name}.pem 0600 root:root'],
        # a dual certificate: two files, "crt /etc/haproxy/certs/" (the folder) or a
        # crt-list loads both - not the bundle (site.pem.ecdsa), gone since HAProxy 2.3
        'dual_outputs': ['combined-pem@ec /etc/haproxy/certs/{name}.ecdsa.pem 0600 root:root',
                         'combined-pem@rsa /etc/haproxy/certs/{name}.rsa.pem 0600 root:root'],
        'test_cmd': ['haproxy -c -q -f /etc/haproxy/haproxy.cfg'],
        'reload_cmd': ['systemctl reload haproxy'], 'port': 443},
    'postfix': {
        'title': 'Postfix',
        'outputs': ['fullchain-pem /etc/postfix/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/postfix/ssl/{name}.key 0600 root:root'],
        # smtpd_tls_chain_files = {name}.key, {name}.crt, {name}.rsa.key, {name}.rsa.crt
        'alt_outputs': ['fullchain-pem@alt /etc/postfix/ssl/{name}.{alt}.crt 0644 root:root',
                        'key-pem@alt /etc/postfix/ssl/{name}.{alt}.key 0600 root:root'],
        'test_cmd': ['postfix check'], 'reload_cmd': ['postfix reload'], 'port': 465},
    'dovecot': {
        'title': 'Dovecot',
        'outputs': ['fullchain-pem /etc/dovecot/ssl/{name}.crt 0644 root:root',
                    'key-pem /etc/dovecot/ssl/{name}.key 0600 root:root'],
        # ssl_alt_cert / ssl_alt_key
        'alt_outputs': ['fullchain-pem@alt /etc/dovecot/ssl/{name}.{alt}.crt 0644 root:root',
                        'key-pem@alt /etc/dovecot/ssl/{name}.{alt}.key 0600 root:root'],
        'test_cmd': ['doveconf -n >/dev/null'], 'reload_cmd': ['systemctl reload dovecot'],
        'port': 993},
    'exim': {
        'title': 'Exim',
        'outputs': ['fullchain-pem /etc/exim4/{name}.crt 0644 root:Debian-exim',
                    'key-pem /etc/exim4/{name}.key 0640 root:Debian-exim'],
        # tls_certificate and tls_privatekey as lists of two (Exim 4.92+)
        'alt_outputs': ['fullchain-pem@alt /etc/exim4/{name}.{alt}.crt 0644 root:Debian-exim',
                        'key-pem@alt /etc/exim4/{name}.{alt}.key 0640 root:Debian-exim'],
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
        'service': 'web-tls', 'backup': 'none'},
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


INTERPS = ('bash', 'sh', 'python3')

SAMPLE = ('fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root\n'
          'key-pem /etc/nginx/ssl/{name}.key 0600 root:root\n'
          'pfx /opt/app/keystore.p12 0640 app:app')


class SshTarget(SshMixin, Base):
    kind = 'ssh'
    discovery = False       # nothing to find: a server over SSH
    title = 'Linux / Unix server (SSH)'
    vendor = 'Linux / Unix'
    description = ('Writes the certificate as files in the formats and places asked '
                   '(atomically, the old ones kept as .bak), tests the configuration, '
                   'reloads the service and puts the old files back when it fails.')
    doc = 'targets.md'
    dual = True             # a dual certificate: both written, as the outputs say (@rsa, @ec)
    fields = ssh_fields(sudo=True) + [
        field('tmp_dir', 'Folder for uploads', 'text', default='/tmp', advanced=True,
              help='where files are put first, before they are moved into place'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ] + SC.script_fields(INTERPS, deploy=False)
    deploy_fields = [
        field('preset', 'Service', 'select', default='custom',
              options=[[k, p['title']] for k, p in PRESETS.items()],
              fills=_preset_fills(),
              help='fills the files and commands below with what that service usually '
                   'wants; whatever you set yourself wins. A dual certificate (ECDSA + '
                   'RSA): the twin\'s files are written too - for HAProxy {name}.ecdsa.pem '
                   'and {name}.rsa.pem, loaded by "crt /etc/haproxy/certs/" (the folder) '
                   'or a crt-list'),
        field('outputs', 'Files', 'list', placeholder=SAMPLE, ui='files',
              help='one a line: format path [mode] [owner[:group]]. Formats: cert-pem, '
                   'fullchain-pem, chain-pem, key-pem, key-rsa, combined-pem (key + '
                   'fullchain), cert-der, key-der, p7b, pfx/p12, p12-legacy, jks. '
                   'In paths: {name} {cn} {service} {date} {alt}. A dual certificate: '
                   'format@rsa, format@ec (or @main, @alt) for one of its two - a '
                   'preset writes both by itself'),
    ] + SC.password_fields() + [
        field('service', 'Service / container / secret name', 'text', advanced=True,
              help='{service} in the paths and commands'),
        F.same_field(),
    ] + F.backup_fields() + [
    ] + SC.script_fields(INTERPS) + [
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

    files_ui = SC.files_ui('posix', INTERPS, SC.layouts('/etc/ssl/acme'),
                           presets=[[k, p['title']] for k, p in PRESETS.items()])

    _sleep = staticmethod(time.sleep)

    # -- what the options say, the preset filling in ------------------------
    @staticmethod
    def preset_outputs(preset, bundle):
        """The preset's files for this certificate: a dual one's twin's too."""
        outs = list(preset.get('outputs') or [])
        alt = alt_of(bundle)
        if alt is None:
            return outs
        fams = sorted(family_of(b) for b in variants_of(bundle))
        if preset.get('dual_outputs') and fams == ['ec', 'rsa']:
            return list(preset['dual_outputs'])
        return outs + list(preset.get('alt_outputs') or [])

    def resolved(self, bundle, options, partial=False):
        options = dict(options or {})
        preset = PRESETS.get(options.get('preset') or 'custom') or PRESETS['custom']
        out = {}
        for key in ('outputs', 'test_cmd', 'reload_cmd', 'service', 'jks_alias', 'pfx_password',
                    'backup', 'skip_same', 'backup_keep'):
            v = options.get(key)
            if key == 'outputs' and preset.get('outputs') and \
                    lines(v) in ([], lines(preset['outputs'])):
                # The preset's own files (left empty, or filled in by the page as the
                # preset has them): a dual certificate's twin's files with them.
                v = self.preset_outputs(preset, bundle)
            elif v in (None, '', []) and key in preset:
                v = preset[key]
            out[key] = v
        for key in ('pre_cmd', 'post_cmd'):
            out[key] = options.get(key)
        out['backup'] = F.backup_mode({'backup': out['backup']})
        out['skip_same'] = F.skip_same({'skip_same': out['skip_same']})
        out['backup_keep'] = F.backup_keep({'backup_keep': out['backup_keep']})
        name = label_of(bundle, options)
        cn = label_of(bundle, {'object_name': (list(bundle.names or [name]))[0]})
        alt = alt_of(bundle)
        vars = {'name': name, 'cn': cn, 'date': stamp(bundle),
                'service': service_of(out['service'], name), 'host': self.c('host'),
                'alt': family_of(alt) if alt is not None else 'alt'}
        out['vars'] = vars
        files = parse_outputs(out['outputs'], vars)
        out['pairs'] = outputs_for(self.ctx, bundle, files)
        out['files'] = [f for f, _b in out['pairs']]
        if not out['files'] and not partial:
            raise PluginError('no files to write: choose a service or fill in "Files"',
                              retry=False)
        for key in ('pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd'):
            out[key] = [subst(c, vars) for c in lines(out[key])]
        out['password'] = SC.password_of(dict(options, pfx_password=out['pfx_password']))
        out['script'] = SC.script_of(self, options, vars, INTERPS)
        return out

    def render(self, bundle, r):
        """The bytes of each file."""
        alias = r['jks_alias'] or r['vars']['name']
        datas = []
        for f, b in r.get('pairs') or [(f, bundle) for f in r['files']]:
            pw = None
            if f['format'] in PFX_FORMATS:
                pw = r.get('password', r.get('pfx_password')) or None
                if f['format'] == 'jks' and (not pw or len(pw) < 6):
                    raise PluginError('a jks keystore needs a password of 6 characters '
                                      'or more', retry=False)
            data = b.as_format(f['format'], password=pw, alias=alias)
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
        mode = r['backup']
        suffix = F.backup_suffix(mode)

        before = self._written(options)
        stale = [p for p in before if p not in {f['path'] for f in files}]
        with self.ssh() as s:
            # Each file compared with the one there (1.0.77): the same one left alone.
            same = self._same_files(s, files, datas, bundle, options) \
                if r['skip_same'] and not force else [False] * len(files)
            if all(same) and not stale:
                if self.unchanged(bundle, options):
                    return self.same(bundle, 'in every file')
                # The files are there but this deployment did not get through to its reload
                # (or its commands changed): nothing written, the rest done.
                self.ctx.step('every file holds it already (the same SHA-256) - none replaced; '
                              'the commands run all the same', 'ok')
            todo = [i for i, x in enumerate(same) if not x]
            F.describe_same(self, [f['path'] for f, x in zip(files, same) if x])
            wfiles = [files[i] for i in todo]
            wdatas = [datas[i] for i in todo]
            for c in r['pre_cmd']:
                self.sh(s, c, what='"%s"' % c)
                self.ctx.step('ran %s' % c)
            tmps = []
            try:
                for i, data in enumerate(wdatas):
                    tmp = '%s/.acme-%s-%d' % (tmpdir, token, i)
                    s.put(data, tmp, 0o600)
                    tmps.append(tmp)
                existed = self._install(s, wfiles, tmps, suffix) if wfiles else []
                if wfiles:
                    self.ctx.step('wrote %s%s' % (', '.join(f['path'] for f in wfiles), '' if mode == 'none'
                                                  else ' (the previous kept as *%s)' % suffix), 'ok')
                moved = self._stale_aside(s, stale)
                failed = self._commands(s, r['test_cmd'], 'test')
                if failed:
                    self._rollback(s, wfiles, existed, suffix)
                    self._stale_back(s, moved)
                    raise PluginError('the test "%s" failed, the previous files are back: %s'
                                      % failed, retry=False)
                if r['script']:
                    env = SC.env_for(self, bundle, r['pairs'], r['vars'], r['password'])
                    rc, out, err = SC.run_posix(self, s, r['script'], env, tmpdir)
                    said = SC.tell(self, r['script'], rc, out, err)
                    if rc != 0:
                        self._rollback(s, wfiles, existed, suffix)
                        self._stale_back(s, moved)
                        raise PluginError('%s failed (exit %s), the previous files are back%s'
                                          % (SC._what(r['script']), rc,
                                             (': ' + said.splitlines()[-1][-200:]) if said
                                             else ''), retry=False)
                failed = self._commands(s, r['reload_cmd'], 'reload')
                if failed:
                    self._rollback(s, wfiles, existed, suffix)
                    self._stale_back(s, moved)
                    self._commands(s, r['reload_cmd'], 'reload with the previous files')
                    raise PluginError('"%s" failed, the previous files are back: %s' % failed)
                self._stale_gone(s, moved)
                self._after_backup(s, wfiles, existed, mode, suffix, r['backup_keep'])
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
        self._written(options, [f['path'] for f in files])
        kept = len(files) - len(wfiles)
        return '%d file%s written on %s%s%s%s' % (
            len(wfiles), '' if len(wfiles) == 1 else 's', self.c('host'),
            (', %d the same left as %s' % (kept, 'it was' if kept == 1 else 'they were'))
            if kept else '',
            ', the script ran' if r['script'] else '', ', reloaded' if r['reload_cmd'] else '')

    def _same_files(self, s, files, datas, bundle, options):
        """[True: the file there holds exactly this already], one a file. PEM and DER are
        compared by SHA-256; PKCS#12, keystores and p7b differ every time they are made, so
        they are the same only when this certificate was deployed here as it is now."""
        want = {f['path']: hashlib.sha256(d).hexdigest() for f, d in zip(files, datas)}
        have = F.hashes(self, s, list(want))
        remembered = None
        out = []
        for f in files:
            if f['format'] in PFX_FORMATS or f['format'] == 'p7b':
                if remembered is None:
                    remembered = self.unchanged(bundle, options)
                out.append(bool(remembered) and f['path'] in have)
            else:
                out.append(have.get(f['path']) == want[f['path']])
        return out

    def _after_backup(self, s, files, existed, mode, suffix, keep):
        """After a deployment that went through: the copies only for putting back removed;
        of dated ones, the older beyond `keep` deleted."""
        if not files:
            return
        if mode == 'none':
            self.sh(s, 'rm -f ' + ' '.join(quote(f['path'] + suffix) for f in files), check=False)
        elif mode in ('dated', 'daily') and keep:
            script = [F.prune_posix(f['path'], keep) for f, was in zip(files, existed) if was]
            if script:
                self.sh(s, '\n'.join(script), check=False)

    # -- what it would do: the page's preview, and a test that changes nothing ---------
    def preview(self, bundle, options):
        problems = []
        try:
            r = self.resolved(bundle, options, partial=True)
            pairs, vars = r['pairs'], r['vars']
        except PluginError as e:
            problems.append({'level': 'bad', 'words': str(e)})
            pairs, vars = [], self._vars(bundle, options)
        o = dict(options or {})
        if not o.get('pfx_password') and (PRESETS.get(o.get('preset') or '') or {}).get(
                'pfx_password'):
            o['pfx_password'] = PRESETS[o['preset']]['pfx_password']
        got = SC.preview(self, bundle, o, pairs, vars, problems, interps=INTERPS)
        if pairs:
            got['commands'] = {k: r[k] for k in ('pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd')}
        return got

    def _vars(self, bundle, options):
        name = label_of(bundle, options)
        return {'name': name, 'cn': name, 'date': stamp(bundle),
                'service': service_of((options or {}).get('service'), name), 'alt': 'alt'}

    def dry_run(self, bundle, options, run_script=True):
        """Signed in; the files made and written into a temporary folder (not
        their places), where they go looked at; the script run there with
        ACME_DRY_RUN=1; the folder deleted. Nothing of the service is touched:
        the commands before, test and reload are not run."""
        options = dict(options or {})
        r = self.resolved(bundle, options)
        datas = self.render(bundle, r)
        files = r['files']
        tmpdir = (self.c('tmp_dir') or '/tmp').rstrip('/') or '/tmp'
        with self.ssh() as s:
            rc, out, err = self.sh(s, 'id -un', what='signing in')
            self.ctx.step('signed in as %s on %s' % (out.strip(), self.c('host')), 'ok')
            rc, out, err = self.sh(s, 'mktemp -d %s/.acme-test-XXXXXXXX' % quote(tmpdir),
                                   what='a temporary folder')
            tdir = out.strip().splitlines()[-1] if out.strip() else ''
            if not tdir.startswith(tmpdir + '/.acme-test-') or '..' in tdir:
                raise PluginError('the temporary folder is not where it was asked: %r' % tdir)
            try:
                self._look_at_places(s, files)
                pairs = []
                for i, ((f, b), data) in enumerate(zip(r['pairs'], datas)):
                    p = '%s/%d-%s' % (tdir, i + 1, f['path'].rstrip('/').split('/')[-1])
                    s.put(data, p, 0o600)
                    fix = 'chmod %o %s' % (f['mode'], quote(p))
                    if f['owner']:
                        fix += ' && { chown %s %s || echo "OWNER"; }' % (quote(f['owner']), quote(p))
                    rc, out, err = self.sh(s, fix, check=False)
                    if 'OWNER' in out or rc != 0:
                        self.ctx.step('%s: the owner %s cannot be set there (%s)' % (
                            f['path'], f['owner'], (err.strip() or out.strip())[-160:]), 'warn')
                    pairs.append((dict(f, path=p), b))
                self.ctx.step('made %d file%s (%s) in %s - not in their places' % (
                    len(files), '' if len(files) == 1 else 's',
                    ', '.join('%s %d B' % (f['format'], len(d)) for f, d in zip(files, datas)),
                    tdir), 'ok')
                for c in r['pre_cmd'] + r['test_cmd'] + r['reload_cmd'] + r['post_cmd']:
                    self.ctx.step('not run on a test: %s' % c)
                if r['script'] and run_script:
                    env = SC.env_for(self, bundle, pairs, r['vars'], r['password'], dry_run=True,
                                     extra={'ACME_TEST_DIR': tdir})
                    rc, out, err = SC.run_posix(self, s, r['script'], env, tmpdir)
                    SC.tell(self, r['script'], rc, out, err, dry_run=True)
                    if rc != 0:
                        raise PluginError('%s failed on the test (exit %s)' % (
                            SC._what(r['script']), rc), retry=False)
                elif r['script']:
                    self.ctx.step('the script is not run on this test')
            finally:
                self.sh(s, 'rm -rf %s' % quote(tdir), check=False)
                self.ctx.step('the temporary folder is gone')
        return 'the test passed: %d file%s%s' % (
            len(files), '' if len(files) == 1 else 's',
            ', the script ran with ACME_DRY_RUN=1' if r['script'] and run_script else '')

    def _look_at_places(self, s, files):
        """Where each file goes: is its folder there, may it be written, is a file there now."""
        script = []
        for i, f in enumerate(files):
            p = quote(f['path'])
            script.append('d=$(dirname %s); printf "%d %%s %%s %%s\\n" "$([ -d "$d" ] && echo 1 || '
                          'echo 0)" "$([ -w "$d" ] && echo 1 || echo 0)" "$([ -e %s ] && echo 1 || '
                          'echo 0)"' % (p, i, p))
        rc, out, err = self.sh(s, '\n'.join(script), check=False)
        seen = {}
        for line in out.splitlines():
            bits = line.split()
            if len(bits) == 4 and bits[0].isdigit():
                seen[int(bits[0])] = bits[1:]
        for i, f in enumerate(files):
            d, w, e = seen.get(i, ['?', '?', '?'])
            if d == '0':
                self.ctx.step('%s: its folder is not there yet - it is made' % f['path'], 'warn')
            elif w == '0':
                self.ctx.step('%s: its folder cannot be written%s' % (
                    f['path'], '' if as_bool(self.c('sudo')) else ' (sudo is off)'), 'bad')
            else:
                self.ctx.step('%s: %s' % (f['path'], 'replaces the one there' if e == '1'
                                          else 'a new file'))

    # -- the files this deployment wrote, and the ones it no longer writes --------------
    def _written_key(self, options):
        dep = getattr(self.ctx, 'deploy_id', None)
        if dep not in (None, ''):
            return 'written:%s:%s:%s' % (self.kind, self.ident(), dep)
        return self.state_key(options).replace('deployed:', 'written:', 1)

    def _written(self, options, paths=None):
        """The paths acme wrote for this deployment last time; with `paths`, kept."""
        key = self._written_key(options)
        if paths is not None:
            try:
                self.ctx.kv_set(key, json.dumps(sorted(set(paths))))
            except Exception as e:                          # noqa: BLE001
                self.ctx.debug('cannot remember the files written: %s' % e)
            return paths
        try:
            got = self.ctx.kv_get(key)
        except Exception:                                   # noqa: BLE001
            got = None
        if isinstance(got, str):
            try:
                got = json.loads(got)
            except ValueError:
                got = None
        return [str(p) for p in got if isinstance(p, str) and p.startswith('/')] \
            if isinstance(got, list) else []

    def _stale_aside(self, s, stale):
        """Files acme wrote before and does not write now, moved aside. -> moved."""
        if not stale:
            return []
        script = ['for p in %s; do if [ -e "$p" ] && [ ! -L "$p" ]; then mv -f "$p" "$p.acme-stale" '
                  '&& echo "MOVED $p"; fi; done' % ' '.join(quote(p) for p in stale)]
        rc, out, err = self.sh(s, '\n'.join(script), check=False)
        moved = [line[6:].strip() for line in out.splitlines() if line.startswith('MOVED ')]
        if moved:
            self.ctx.step('taken away (written by acme before, not any more): %s'
                          % ', '.join(moved))
        return moved

    def _stale_back(self, s, moved):
        if moved:
            self.sh(s, '; '.join('mv -f %s %s' % (quote(p + '.acme-stale'), quote(p))
                                 for p in moved), check=False)

    def _stale_gone(self, s, moved):
        if moved:
            self.sh(s, 'rm -f ' + ' '.join(quote(p + x) for p in moved
                                           for x in ('.acme-stale', '.bak', '.acme-prev')),
                    check=False)

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
            script.append('echo "PLACED %d"' % i)
        rc, out, err = self.sh(s, '\n'.join(script), check=False)
        existed = [False] * len(files)
        placed = [False] * len(files)
        for line in out.splitlines():
            if line.startswith('EXISTED '):
                existed[int(line.split()[1])] = True
            elif line.startswith('PLACED '):
                placed[int(line.split()[1])] = True
        if rc != 0:
            # Only the files put in place are put back (1.0.48): the ones after the failure
            # were never touched - "not there before" had them deleted, live ones too.
            self._rollback(s, files, existed, suffix, placed)
            raise PluginError('the files could not be written, the previous ones are back: %s'
                              % (err.strip() or out.strip())[-300:],
                              detail='\n'.join(script) + '\n' + out + err)
        return existed

    def _rollback(self, s, files, existed, suffix, placed=None):
        script = []
        for i, (f, was) in enumerate(zip(files, existed)):
            p = quote(f['path'])
            if placed is not None and not placed[i]:
                script.append('rm -f %s' % quote(f['path'] + '.acme-new'))
                continue
            if was:
                script.append('cp -p %s %s' % (quote(f['path'] + suffix), p))
                if suffix == '.acme-prev':      # only for putting back: done with (1.0.77)
                    script.append('rm -f %s' % quote(f['path'] + suffix))
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
