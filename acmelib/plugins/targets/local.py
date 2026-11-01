# -*- coding: utf-8 -*-
"""
This machine: files written under one folder only (/etc/acme/out by default)
and, when asked, one command run - only a command the target itself allows.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import tempfile

from acmelib.plugins.targets._common import (
    Base, PluginError, field, lines, label_of, stamp, parse_outputs, subst, PFX_FORMATS,
    verify_fields, as_int, text, alt_of, family_of, outputs_for)


class LocalTarget(Base):
    kind = 'local'
    title = 'This machine (files)'
    vendor = 'acme'
    description = ('Writes the certificate as files under one folder of this machine, for '
                   'something else to pick up; runs one command it is allowed to.')
    doc = 'targets.md'
    dual = True             # a dual certificate: format@rsa, format@ec lines write each
    fields = [
        field('base', 'Folder', 'text', default='/etc/acme/out', required=True,
              help='every file goes under this folder, nowhere else'),
        field('allow_commands', 'Commands allowed', 'list', advanced=True,
              help='the exact commands a deployment may run, one a line (no shell: '
                   'pipes and ; are not); empty: none'),
    ]
    deploy_fields = [
        field('outputs', 'Files', 'list',
              placeholder='fullchain-pem {name}/fullchain.pem\nkey-pem {name}/privkey.pem 0600',
              help='one a line: format path [mode] - the path inside the folder; of a dual '
                   'certificate format@rsa / format@ec (@main, @alt) for one of its two, '
                   '{alt} its twin\'s kind'),
        field('pfx_password', 'PKCS#12 / keystore password', 'secret'),
        field('command', 'Then run', 'text', advanced=True,
              help='one of the commands the target allows'),
    ] + verify_fields()

    def ident(self):
        return self.c('base')

    def _base(self):
        b = os.path.realpath(self.c('base') or '/etc/acme/out')
        if b in ('/', '') or not os.path.isabs(b):
            raise PluginError('the folder of this target is not allowed: %s' % b, retry=False)
        return b

    def _place(self, base, rel):
        rel = rel.lstrip('/') if not rel.startswith(base + '/') else rel[len(base) + 1:]
        full = os.path.normpath(os.path.join(base, rel))
        if not full.startswith(base + os.sep):
            raise PluginError('%s is outside %s' % (rel, base), retry=False)
        d = os.path.dirname(full)
        os.makedirs(d, mode=0o750, exist_ok=True)
        if not os.path.realpath(d).startswith(base + os.sep) and os.path.realpath(d) != base:
            raise PluginError('%s leads outside %s (a link)' % (rel, base), retry=False)
        if os.path.islink(full):
            raise PluginError('%s is a link: not written' % full, retry=False)
        return full

    def test(self):
        b = self._base()
        if not os.path.isdir(b):
            return '%s does not exist yet: it is made on the first deployment' % b
        if not os.access(b, os.W_OK):
            raise PluginError('acme cannot write in %s' % b, retry=False)
        return '%s can be written' % b

    def deploy(self, bundle, options):
        options = options or {}
        base = self._base()
        alt = alt_of(bundle)
        vars = {'name': label_of(bundle, options), 'date': stamp(bundle),
                'cn': label_of(bundle, {'object_name': (bundle.names or ['cert'])[0]}),
                'alt': family_of(alt) if alt is not None else 'alt'}
        pairs = outputs_for(self.ctx, bundle,
                            parse_outputs(options.get('outputs'), vars, absolute=False))
        outs = [o for o, _b in pairs]
        if not outs:
            raise PluginError('no files to write', retry=False)
        cmd = (options.get('command') or '').strip()
        if cmd and cmd not in lines(self.c('allow_commands')):
            raise PluginError('the command "%s" is not one this target allows' % cmd,
                              retry=False)
        if self.unchanged(bundle, options, present=lambda: all(
                os.path.exists(os.path.join(base, o['path'].lstrip('/'))) for o in outs)):
            return self.same(bundle, 'in %s' % base)
        os.makedirs(base, mode=0o750, exist_ok=True)
        for o, b in pairs:
            full = self._place(base, o['path'])
            pw = options.get('pfx_password') if o['format'] in PFX_FORMATS else None
            data = b.as_format(o['format'], password=pw or None, alias=vars['name'])
            if isinstance(data, str):
                data = data.encode()
            fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=os.path.dirname(full))
            try:
                with os.fdopen(fd, 'wb') as fh:
                    fh.write(data)
                os.chmod(tmp, o['mode'])
                os.replace(tmp, full)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
            self.ctx.step('wrote %s' % full)
        if cmd:
            self._run(subst(cmd, vars))
        self.remember(bundle, options)
        return '%d file%s in %s%s' % (len(outs), '' if len(outs) == 1 else 's', base,
                                       ', ran %s' % cmd if cmd else '')

    def _run(self, cmd):
        argv = shlex.split(cmd)
        runner = getattr(self.ctx, 'run_local', None)
        if runner:
            rc, out, err = runner(argv, timeout=120)
        else:
            try:
                p = subprocess.run(argv, capture_output=True, timeout=120, shell=False,
                                   env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                        'LANG': 'C.UTF-8'})
            except (OSError, subprocess.TimeoutExpired) as e:
                raise PluginError('%s could not be run: %s' % (argv[0], e))
            rc, out, err = p.returncode, p.stdout, p.stderr
        if as_int(rc, 1) != 0:
            said = text(err).strip() or text(out).strip()
            raise PluginError('%s failed (exit %s): %s' % (cmd, rc, said[-300:]))
        self.ctx.step('ran %s' % cmd, 'ok')
