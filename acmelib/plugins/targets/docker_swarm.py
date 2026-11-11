# -*- coding: utf-8 -*-
"""
Docker Swarm secrets over SSH (on a manager node): the certificate and the
key made Docker secrets under dated names (a secret cannot be changed, only
replaced), each service asked for updated to mount the new ones where it
mounted the old ones (a rolling update), older acme secrets removed.

    docker secret create <name>.crt <file>     docker secret create <name>.key <file>
    docker service inspect <svc> --format '{{json .Spec.TaskTemplate.ContainerSpec.Secrets}}'
    docker service update --secret-rm <old> --secret-add source=<new>,target=<file>,mode=0400 <svc>
    docker secret ls --format '{{.Name}}'      docker secret rm <old>

Rights: a user in the docker group (or root, or through sudo) on a manager.

Sources:
    https://docs.docker.com/engine/swarm/secrets/#example-rotate-a-secret
    https://docs.docker.com/reference/cli/docker/secret/create/
    https://docs.docker.com/reference/cli/docker/service/update/#add-or-remove-secrets
"""
from __future__ import annotations

import json
import re
import secrets as _secrets

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, lines, as_bool, object_name, name_prefix, prune,
    ssh_fields, verify_fields, keep_field, quote, text)

_SVC_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]*$')


class DockerSwarmTarget(SshMixin, Base):
    kind = 'docker_swarm'
    discovery = False       # nothing to find: a server over SSH
    title = 'Docker Swarm secrets'
    vendor = 'Docker'
    description = ('Makes the certificate and key Docker Swarm secrets under new names over SSH, '
                   'rolls the services onto them and removes the older secrets.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=True) + [
        field('docker', 'docker command', 'text', default='docker', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]
    deploy_fields = [
        field('services', 'Services', 'list', placeholder='web_proxy',
              help='one a line: the services to roll onto the new secrets'),
        field('cert_target', 'Certificate file in the container', 'text', default='tls.crt',
              help='the target of the secret (under /run/secrets/ unless absolute); full chain'),
        field('key_target', 'Key file in the container', 'text', default='tls.key'),
        keep_field(1),
    ] + verify_fields()

    def docker(self):
        d = text(self.c('docker') or 'docker').strip()
        if not re.match(r'^[A-Za-z0-9/_.-]+$', d):
            raise PluginError('the docker command is not a plain path', retry=False)
        return d

    def secrets(self, s):
        rc, out, err = self.sh(s, '%s secret ls --format "{{.Name}}"' % self.docker(),
                               what='listing the secrets')
        return [x.strip() for x in out.splitlines() if x.strip()]

    def test(self):
        with self.ssh() as s:
            rc, out, err = self.sh(s, '%s info --format "{{.Swarm.LocalNodeState}} '
                                      '{{.Swarm.ControlAvailable}} {{.ServerVersion}}"'
                                   % self.docker(), what='asking docker')
        parts = out.split()
        if len(parts) < 2 or parts[0] != 'active' or parts[1] != 'true':
            raise PluginError('signed in, but this is not a manager of an active swarm (%s)'
                              % out.strip(), retry=False)
        return 'signed in: a swarm manager, Docker %s' % (parts[2] if len(parts) > 2 else '?')

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options, maxlen=58)
        prefix = name_prefix(bundle, options, maxlen=58)
        crt, key = name + '.crt', name + '.key'
        targets = {'crt': text(self.opt(options, 'cert_target', 'tls.crt')).strip(),
                   'key': text(self.opt(options, 'key_target', 'tls.key')).strip()}
        svcs = lines(options.get('services'))
        for sv in svcs:
            if not _SVC_RE.match(sv):
                raise PluginError('"%s" is not a service name' % sv, retry=False)
        d = self.docker()
        did = []
        with self.ssh() as s:
            have = self.secrets(s)
            mounts = {sv: self.mounted(s, sv) for sv in svcs}
            uses = all(any(m.get('SecretName') == crt for m in ms) and
                       any(m.get('SecretName') == key for m in ms) for ms in mounts.values())
            if not as_bool(options.get('force')) and crt in have and key in have and uses:
                self.remember(bundle, options)
                return self.same(bundle, 'as %s' % name)
            for sname, fmt in ((crt, 'fullchain-pem'), (key, 'key-pem')):
                if sname in have:
                    continue
                tmp = '/tmp/.acme-secret-%s' % _secrets.token_hex(6)
                s.put(bundle.as_format(fmt), tmp, 0o600)
                try:
                    self.sh(s, '%s secret create --label managed-by=acme %s %s >/dev/null'
                            % (d, quote(sname), quote(tmp)), what='making the secret %s' % sname)
                finally:
                    s.run('rm -f %s' % quote(tmp), check=False)
                self.ctx.step('made the secret %s' % sname, 'ok')
            did.append('secrets %s' % name)
            for sv, ms in mounts.items():
                args = []
                for ext, new in (('crt', crt), ('key', key)):
                    tgt = targets[ext]
                    # ours by the whole name (1.0.79): acme-www- is not acme-www-api-...
                    ours = re.compile(r'^%s\d{8}-[0-9a-f]+\.%s$' % (re.escape(prefix), ext))
                    was = {}
                    for m in ms:
                        file_name = (m.get('File') or {}).get('Name')
                        if (file_name == tgt or ours.match(m.get('SecretName') or '')) \
                                and m.get('SecretName') != new:
                            args.append('--secret-rm %s' % quote(m['SecretName']))
                            if file_name == tgt:
                                was = m.get('File') or {}
                    if not any(m.get('SecretName') == new for m in ms):
                        # the owner and mode the service had for the file stay (1.0.79)
                        spec = 'source=%s,target=%s' % (new, tgt)
                        for k, w in (('UID', 'uid'), ('GID', 'gid')):
                            if re.match(r'^\d+$', text(was.get(k) or '')):
                                spec += ',%s=%s' % (w, was[k])
                        mode = was.get('Mode')
                        spec += ',mode=0%s' % (('%o' % int(mode)) if isinstance(mode, int)
                                               and 0 < mode < 0o1000 else
                                               '444' if ext == 'crt' else '400')
                        args.append('--secret-add %s' % quote(spec))
                if not args:
                    continue
                self.sh(s, '%s service update --quiet --detach=false %s %s'
                        % (d, ' '.join(args), quote(sv)), timeout=900,
                        what='rolling %s onto the new secrets' % sv)
                self.ctx.step('service %s rolled onto %s' % (sv, name), 'ok')
                did.append(sv)
            self.cleanup(s, prefix, name, self.keep(options))
        self.remember(bundle, options)
        return ', '.join(did)

    def mounted(self, s, sv):
        rc, out, err = self.sh(s, '%s service inspect %s --format '
                                  '"{{json .Spec.TaskTemplate.ContainerSpec.Secrets}}"'
                               % (self.docker(), quote(sv)), check=False)
        if rc != 0:
            raise PluginError('there is no service "%s": %s' % (sv, (err or out).strip()[-200:]),
                              retry=False)
        try:
            v = json.loads(out.strip() or 'null')
        except ValueError:
            v = None
        return [m for m in (v or []) if isinstance(m, dict)]

    def cleanup(self, s, prefix, current, keep):
        if keep < 0:
            return
        names = {}
        for n in self.secrets(s):
            if n.endswith(('.crt', '.key')):
                names.setdefault(n[:-4], []).append(n)
        for old in prune(list(names), prefix, keep, current):
            for n in names[old]:
                rc, out, err = self.sh(s, '%s secret rm %s' % (self.docker(), quote(n)),
                                       check=False)
                if rc == 0:
                    self.ctx.step('removed the old secret %s' % n)
                else:
                    self.ctx.step('the old secret %s stays (still used?): %s'
                                  % (n, (err or out).strip()[-200:]), 'warn')
