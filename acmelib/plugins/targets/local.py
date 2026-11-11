# -*- coding: utf-8 -*-
"""
This machine: files written under one folder only (/etc/acme/out by default)
and, when asked, one command run - only a command the target itself allows -
or a script written in the deployment, only where the target allows scripts
(it runs here, on acme's own machine, as acme).
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import time

from acmelib.plugins.targets._common import (
    Base, PluginError, field, lines, label_of, stamp, parse_outputs, subst, PFX_FORMATS,
    verify_fields, as_int, as_bool, text, alt_of, family_of, outputs_for, service_of)
from acmelib.plugins.targets import _files as F
from acmelib.plugins.targets import _script as SC

INTERPS = ('bash', 'sh', 'python3')


class LocalTarget(Base):
    kind = 'local'
    discovery = False       # nothing to find: this server's own folders
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
        field('allow_scripts', 'Scripts written in a deployment may run here', 'bool',
              default=False, advanced=True,
              help='off: a deployment runs only a command allowed above. On: a script '
                   'written in the deployment (by a full administrator) runs on this machine '
                   'as acme, after the files'),
    ]
    deploy_fields = [
        field('outputs', 'Files', 'list', ui='files',
              placeholder='fullchain-pem {name}/fullchain.pem\nkey-pem {name}/privkey.pem 0600',
              help='one a line: format path [mode] - the path inside the folder; of a dual '
                   'certificate format@rsa / format@ec (@main, @alt) for one of its two, '
                   '{alt} its twin\'s kind'),
    ] + SC.password_fields() + [
        field('command', 'Then run', 'text', advanced=True,
              help='one of the commands the target allows'),
    ] + F.file_fields() + SC.script_fields(INTERPS) + verify_fields()
    files_ui = SC.files_ui('local', INTERPS, SC.layouts('', 'posix'), owners=False,
                           base='/etc/acme/out')

    def ident(self):
        return self.c('base')

    def _base(self):
        b = os.path.realpath(self.c('base') or '/etc/acme/out')
        if b in ('/', '') or not os.path.isabs(b):
            raise PluginError('the folder of this target is not allowed: %s' % b, retry=False)
        return b

    @staticmethod
    def _where(base, rel):
        """The file a path stands for, as _place() writes it - nothing made, nothing checked."""
        rel = rel.lstrip('/') if not rel.startswith(base + '/') else rel[len(base) + 1:]
        return os.path.normpath(os.path.join(base, rel))

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

    def _vars(self, bundle, options):
        alt = alt_of(bundle)
        name = label_of(bundle, options)
        return {'name': name, 'date': stamp(bundle),
                'cn': label_of(bundle, {'object_name': (bundle.names or ['cert'])[0]}),
                'service': service_of((options or {}).get('service'), name),
                'alt': family_of(alt) if alt is not None else 'alt'}

    def _pairs(self, bundle, options, vars):
        return outputs_for(self.ctx, bundle,
                           parse_outputs(options.get('outputs'), vars, absolute=False))

    def _script(self, options, vars):
        """The script after the files, as this target lets it run - PluginError if not."""
        sc = SC.script_of(self, options, vars, INTERPS)
        why = self._script_refused(sc, options)
        if why:
            raise PluginError(why, retry=False)
        return sc

    def _script_refused(self, sc, options=None):
        if sc is None:
            return ''
        if sc['mode'] == 'inline' and not as_bool(self.c('allow_scripts')):
            return ('this target does not let scripts run on this machine (its setting '
                    '"Scripts written in a deployment may run here" is off)')
        if sc['mode'] == 'path':
            o = options or {}
            raw = ('%s %s' % (o.get('script_path') or '', o.get('script_args') or '')).strip()
            allowed = lines(self.c('allow_commands'))
            if raw not in allowed and (o.get('script_args') or sc['path'] not in allowed):
                return 'the command "%s" is not one this target allows' % raw
        return ''

    def _render(self, pairs, options, vars):
        pw = SC.password_of(options)
        out = []
        for o, b in pairs:
            data = b.as_format(o['format'], password=(pw if o['format'] in PFX_FORMATS else None),
                               alias=options.get('jks_alias') or vars['name'])
            out.append(data.encode() if isinstance(data, str) else data)
        return out

    def deploy(self, bundle, options):
        options = options or {}
        base = self._base()
        vars = self._vars(bundle, options)
        pairs = self._pairs(bundle, options, vars)
        outs = [o for o, _b in pairs]
        if not outs:
            raise PluginError('no files to write', retry=False)
        cmd = (options.get('command') or '').strip()
        if cmd and cmd not in lines(self.c('allow_commands')):
            raise PluginError('the command "%s" is not one this target allows' % cmd,
                              retry=False)
        sc = self._script(options, vars)
        # Where each file is written (1.0.19): a path already under the folder is
        # the folder's, as _place() takes it - joined again it was never there.
        skip = F.skip_same(options) and not as_bool(options.get('force'))
        if skip and self.unchanged(bundle, options, present=lambda: all(
                os.path.exists(self._where(base, o['path'])) for o in outs)):
            return self.same(bundle, 'in %s' % base)
        os.makedirs(base, mode=0o750, exist_ok=True)
        datas = self._render(pairs, options, vars)
        mode = F.backup_mode(options)
        stamp = time.time()
        before = []                 # (path, the bytes there before or None)
        written = []
        left = []
        try:
            for (o, b), data in zip(pairs, datas):
                full = self._place(base, o['path'])
                try:
                    with open(full, 'rb') as fh:
                        had = fh.read()
                except OSError:
                    had = None
                written.append((o, full))
                # The same bytes there (1.0.77): PEM and DER only - PKCS#12 and keystores
                # are new bytes every time, and are written when the certificate is not.
                if skip and had is not None and had == data and \
                        o['format'] not in PFX_FORMATS and o['format'] != 'p7b':
                    left.append(full)
                    continue
                before.append((full, had))
                if had is not None and mode != 'none':
                    self._keep(full, had, F.backup_path(full, mode, stamp))
                self._write(full, data, o['mode'])
                self.ctx.step('wrote %s%s' % (full, '' if had is None or mode == 'none'
                                              else ' (the previous kept as %s)'
                                              % F.backup_path(full, mode, stamp)))
        except Exception:
            # One file refused (outside the folder, a link, the disk full) - 1.0.51: those
            # written before it stayed new, the new chain beside the old key.
            self._put_back(before)
            raise
        F.describe_same(self, left)
        if not before:
            self.ctx.step('every file holds it already (the same SHA-256) - none replaced', 'ok')
        if sc:
            env = SC.env_for(self, bundle, [(dict(o, path=full), b) for (o, full), (_o, b)
                                            in zip(written, pairs)], vars, SC.password_of(options))
            rc, out, err = self._run_script(sc, env, base)
            said = SC.tell(self, sc, rc, out, err)
            if rc != 0:
                self._put_back(before)
                raise PluginError('%s failed (exit %s), the previous files are back%s' % (
                    SC._what(sc), rc, (': ' + said.splitlines()[-1][-200:]) if said else ''),
                    retry=False)
        if cmd:
            try:
                self._run(subst(cmd, vars))
            except Exception:
                self._put_back(before)          # as when the script fails (1.0.51)
                raise
        if mode in ('dated', 'daily', 'folder'):
            for full, had in before:
                if had is not None:
                    self._prune(full, mode, F.backup_keep(options))
        self.remember(bundle, options)
        n = len(before)
        return '%d file%s written in %s%s%s%s' % (
            n, '' if n == 1 else 's', base,
            (', %d the same left as %s' % (len(left), 'it was' if len(left) == 1 else 'they were'))
            if left else '', ', the script ran' if sc else '', ', ran %s' % cmd if cmd else '')

    def _keep(self, full, had, dest):
        """The file there kept beside it (or in .acme-backup beside it) before it is replaced
        - not through a link."""
        d = os.path.dirname(dest)
        if not os.path.isdir(d):
            os.makedirs(d, mode=0o750, exist_ok=True)
        if os.path.islink(d) or os.path.islink(dest):
            if os.path.islink(d):
                raise PluginError('%s is a link: no copy kept there' % d, retry=False)
            os.unlink(dest)
            os.unlink(dest)
        self._write(dest, had, os.stat(full).st_mode & 0o777)

    def _prune(self, full, mode, keep):
        pat = F.dated_pattern(full, mode)
        if not keep or not pat:
            return
        folder, name = pat[0], pat[1][:-1]
        if not os.path.isdir(folder):
            return
        got = []
        for x in os.listdir(folder):
            rest = x[len(name) + 1:] if x.startswith(name + '.') else ''
            if rest.endswith('.bak') and rest[:4].isdigit() and \
                    set(rest[:-4]) <= set('0123456789-'):
                got.append(os.path.join(folder, x))
        got.sort(key=lambda p: os.stat(p).st_mtime, reverse=True)
        for p in got[keep:]:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _write(self, full, data, mode):
        fd, tmp = tempfile.mkstemp(prefix='.acme-', dir=os.path.dirname(full))
        try:
            with os.fdopen(fd, 'wb') as fh:
                fh.write(data)
            os.chmod(tmp, mode)
            os.replace(tmp, full)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _put_back(self, before):
        for full, data in before:
            try:
                if data is None:
                    os.unlink(full)
                else:
                    self._write(full, data, os.stat(full).st_mode & 0o777)
            except OSError as e:
                self.ctx.step('%s could not be put back: %s' % (full, e), 'bad')
        self.ctx.step('the previous files are back', 'warn')

    def _run_script(self, sc, env, cwd, timeout=300):
        """The script run here, in a private temporary folder, with a small PATH
        and the ACME_* variables only - never through a shell."""
        argv_args = shlex.split(sc['args']) if sc['args'] else []
        folder = tempfile.mkdtemp(prefix='acme-script-')
        try:
            if sc['mode'] == 'inline':
                path = os.path.join(folder, 'script' + SC.INTERPS[sc['interp']][2])
                with open(path, 'w', encoding='utf-8') as fh:
                    fh.write(sc['body'])
                os.chmod(path, 0o700)
                argv = [SC.INTERPS[sc['interp']][1], path] + argv_args
            else:
                argv = [sc['path']] + argv_args
            e = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                 'LANG': 'C.UTF-8', 'HOME': folder}
            e.update({k: str(v) for k, v in env.items()})
            runner = getattr(self.ctx, 'run_local', None)
            if runner:
                try:
                    return runner(argv, timeout=timeout, env=e, cwd=cwd)
                except TypeError:
                    pass
            try:
                p = subprocess.run(argv, capture_output=True, timeout=timeout, shell=False,
                                   env=e, cwd=cwd if os.path.isdir(cwd) else folder)
            except (OSError, subprocess.TimeoutExpired) as ex:
                return 127, b'', str(ex).encode()
            return p.returncode, p.stdout, p.stderr
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def preview(self, bundle, options):
        options = dict(options or {})
        problems = []
        vars = self._vars(bundle, options)
        try:
            pairs = self._pairs(bundle, options, vars)
        except PluginError as e:
            problems.append({'level': 'bad', 'words': str(e)})
            pairs = []
        base = os.path.realpath(self.c('base') or '/etc/acme/out')
        for o, _b in pairs:
            full = os.path.normpath(os.path.join(base, o['path'].lstrip('/')))
            if not full.startswith(base + os.sep):
                problems.append({'level': 'bad', 'words': '%s is outside %s' % (o['path'], base)})
        cmd = (options.get('command') or '').strip()
        if cmd and cmd not in lines(self.c('allow_commands')):
            problems.append({'level': 'bad', 'words': 'the command "%s" is not one this target '
                             'allows' % cmd})
        got = SC.preview(self, bundle, options, pairs, vars, problems, base=base, owners=False,
                         interps=INTERPS, script_ok=lambda sc: self._script_refused(sc, options))
        full = [(dict(o, path=os.path.join(base, o['path'].lstrip('/'))), b) for o, b in pairs]
        env = SC.env_for(self, bundle, full, vars)
        env.update({k: v for k, v in got['env'].items() if k == 'ACME_PASSWORD'})
        got['env'] = env
        return got

    def dry_run(self, bundle, options, run_script=True):
        """The files made into a temporary folder (not under the target's folder),
        the script run there with ACME_DRY_RUN=1, the folder deleted."""
        options = dict(options or {})
        base = self._base()
        vars = self._vars(bundle, options)
        pairs = self._pairs(bundle, options, vars)
        if not pairs:
            raise PluginError('no files to write', retry=False)
        sc = self._script(options, vars)
        if os.path.isdir(base) and not os.access(base, os.W_OK):
            self.ctx.step('acme cannot write in %s' % base, 'bad')
        datas = self._render(pairs, options, vars)
        folder = tempfile.mkdtemp(prefix='acme-test-')
        try:
            moved = []
            for i, ((o, b), data) in enumerate(zip(pairs, datas)):
                p = os.path.join(folder, '%d-%s' % (i + 1, os.path.basename(o['path'])))
                self._write(p, data, o['mode'])
                moved.append((dict(o, path=p), b))
                self.ctx.step('%s: %s, %d B' % (os.path.join(base, o['path'].lstrip('/')),
                                                o['format'], len(data)))
            if sc and run_script:
                env = SC.env_for(self, bundle, moved, vars, SC.password_of(options), dry_run=True,
                                 extra={'ACME_TEST_DIR': folder})
                rc, out, err = self._run_script(sc, env, folder)
                SC.tell(self, sc, rc, out, err, dry_run=True)
                if rc != 0:
                    raise PluginError('%s failed on the test (exit %s)' % (SC._what(sc), rc),
                                      retry=False)
        finally:
            shutil.rmtree(folder, ignore_errors=True)
        return 'the test passed: %d file%s%s' % (len(pairs), '' if len(pairs) == 1 else 's',
                                                 ', the script ran with ACME_DRY_RUN=1'
                                                 if sc and run_script else '')

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
