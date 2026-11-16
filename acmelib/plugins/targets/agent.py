# -*- coding: utf-8 -*-
"""
A server with acme-agent (1.0.116, docs/target-agent.md): acme holds none of its credentials -
no SSH key, no password, no sudo. The agent on the server does what its own policy allows
(/etc/acme-agent/policy, root's): files in the folders it names, with the owners and modes it
allows, a reload of the units it names, the tests and scripts it lists by their hash.

The deployment is the one of "Linux / Unix server (SSH)": the same files and formats, presets,
before / test / script / reload / after, the copies kept, the same certificate again changes
nothing, the previous files back when the test or the reload fails. What differs is how it is
done: the commands are not run by a shell - each line is read as what it asks for:

    systemctl reload nginx            the unit nginx.service, reload (allow unit)
    nginx -t                          that command line, exactly (allow test)
    /usr/local/bin/x.sh ARGS          that script, its SHA-256 checked (allow script)
    A || B                            A, else B (each one of the above)
    ... >/dev/null, 2>/dev/null       what it says is dropped (it is anyway)

Anything else (a pipe, ;, $, a redirection into a file) is refused before anything is sent:
put it into a script the policy allows. A script written in acme runs only when the policy
allows its SHA-256 (allow script-hash).
"""
from __future__ import annotations

import base64
import hashlib
import re
import shlex

from acmelib.plugins.targets._common import Base, PluginError, field, as_int, PFX_FORMATS, quote
from acmelib.plugins.targets import _script as SC
from acmelib.plugins.targets import ssh as SSH

INTERPS = ('bash', 'sh', 'python3')
KEY_FORMATS = ('key-pem', 'key-rsa', 'key-der', 'combined-pem', 'pfx', 'p12', 'p12-legacy', 'jks')
VERBS = ('reload', 'restart', 'try-reload-or-restart', 'reload-or-restart', 'try-restart')
SHELL_RE = re.compile(r'[|;&$`<>(){}*?!~\\\n]')
QUIET_RE = re.compile(r'\s+(?:2>&1\s*>\s*/dev/null|>\s*/dev/null(?:\s+2>&1)?|2>\s*/dev/null|'
                      r'&>\s*/dev/null)')


def cmd_ops(line):
    """One command line of a deployment as the operation the agent runs - or PluginError."""
    text = str(line or '').strip()
    if not text:
        raise PluginError('an empty command', retry=False)
    alts = [x.strip() for x in text.split('||')]
    ops = []
    for a in alts:
        a = QUIET_RE.sub('', ' ' + a).strip()
        if not a or SHELL_RE.search(a.replace('||', '')):
            raise PluginError('"%s" is a line of a shell: the agent runs no shell - a systemctl '
                              'verb of a unit, a fixed command or a script allowed on the '
                              'server (put the rest into such a script)' % text, retry=False)
        try:
            argv = shlex.split(a)
        except ValueError:
            raise PluginError('"%s" cannot be read as a command' % text, retry=False)
        if argv and argv[0] in ('systemctl', '/usr/bin/systemctl', '/bin/systemctl'):
            rest = [x for x in argv[1:] if x not in ('-q', '--quiet', '--no-block')]
            if len(rest) >= 2 and rest[0] in VERBS:
                ops += [{'unit': u, 'verb': rest[0]} for u in rest[1:]]
                if len(alts) > 1 and len(rest) > 2:
                    raise PluginError('"%s": one unit a line where there are alternatives'
                                      % text, retry=False)
                continue
            raise PluginError('"%s": systemctl %s is not one the agent does (%s)' % (
                text, (rest or ['?'])[0], ', '.join(VERBS)), retry=False)
        if argv and argv[0] in ('service', '/usr/sbin/service') and len(argv) == 3 and \
                argv[2] in ('reload', 'restart'):
            ops.append({'unit': argv[1], 'verb': argv[2]})
            continue
        if argv and argv[0].startswith('/') and re.search(r'\.(sh|py|bash)$', argv[0]):
            ops.append({'script': argv[0], 'args': argv[1:]})
            continue
        ops.append({'argv': argv})
    if len(alts) > 1:
        return [{'any': ops}]
    return ops


def op_words(op):
    if 'any' in op:
        return ' || '.join(op_words(a) for a in op['any'])
    if 'unit' in op:
        return 'systemctl %s %s' % (op['verb'], op['unit'])
    if 'argv' in op:
        return ' '.join(quote(a) for a in op['argv'])
    return ' '.join([op.get('script') or '?'] + [quote(a) for a in op.get('args') or []])


class AgentTarget(Base):
    kind = 'agent'
    discovery = False
    title = 'Server with acme-agent'
    vendor = 'Linux / Unix'
    description = ('acme holds none of the server\'s credentials: a small agent on it writes the '
                   'certificate as files, tests and reloads - only what its own policy allows. '
                   'The deployment is the one of the SSH server: formats, presets, script, '
                   'rollback.')
    doc = 'target-agent.md'
    dual = True
    fields = [
        field('mode', 'Who connects', 'select', default='passive', required=True,
              options=[['passive', 'acme connects to the agent (it listens, 8446)'],
                       ['active', 'the agent connects to acme (nothing open on the server)']],
              help='passive: the agent listens and lets in only acme\'s certificate - acme needs '
                   'nothing open. Active: nothing listens on the server, the agent asks acme '
                   'for its jobs on the agents\' port (Settings → Target agents)'),
        field('host', 'Address', 'text', placeholder='web1.example.local',
              help='where acme reaches the agent (passive); for an active one only what the '
                   'cards say'),
        field('port', 'Port of the agent', 'number', default=8446, advanced=True,
              show_if={'mode': ['passive']},
              help='where the agent listens (passive) - acme-agent join takes it from the code'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ] + SC.script_fields(INTERPS, deploy=False)
    deploy_fields = SSH.SshTarget.deploy_fields
    files_ui = SC.files_ui('posix', INTERPS, SC.layouts('/etc/ssl/acme'),
                           presets=[[k, p['title']] for k, p in SSH.PRESETS.items()])

    # the deployment worked out as the SSH server's
    preset_outputs = SSH.SshTarget.preset_outputs
    resolved = SSH.SshTarget.resolved
    render = SSH.SshTarget.render
    _vars = SSH.SshTarget._vars
    _written_key = SSH.SshTarget._written_key
    _written = SSH.SshTarget._written
    served_places = SSH.SshTarget.served_places
    verify = SSH.SshTarget.verify

    def ident(self):
        name = getattr(self.ctx, 'target_name', '') or self.c('host') or '-'
        return 'agent:%s' % name

    # -- asking the agent --------------------------------------------------------------------
    def _call(self, op, args=None, timeout=900):
        if not hasattr(self.ctx, 'agent_call'):
            raise PluginError('this acme cannot reach agents', retry=False)
        return self.ctx.agent_call(op, args or {}, timeout=timeout)

    def test(self):
        got = self._call('hello', {}, timeout=as_int(self.c('timeout', 30), 30))
        if not got.get('ok'):
            raise PluginError(got.get('said') or 'the agent refused', retry=False)
        pol = got.get('policy') or {}
        words = 'acme-agent %s on %s answers; its policy: %d folder%s, %d unit%s, %d test%s, ' \
                '%d script%s' % (
                    got.get('version') or '?', got.get('host') or '?',
                    len(pol.get('files') or []), '' if len(pol.get('files') or []) == 1 else 's',
                    len(pol.get('units') or {}), '' if len(pol.get('units') or {}) == 1 else 's',
                    len(pol.get('tests') or []), '' if len(pol.get('tests') or []) == 1 else 's',
                    len(pol.get('scripts') or []) + len(pol.get('script_hashes') or []),
                    '' if len(pol.get('scripts') or []) + len(pol.get('script_hashes') or []) == 1
                    else 's')
        for p in (pol.get('problems') or [])[:3]:
            self.ctx.step('the policy: %s' % p, 'warn')
        return words

    # -- what is sent ----------------------------------------------------------------------
    def plan(self, bundle, options, r, datas, sealed=True):
        """The job's arguments: the files (keys sealed to the agent), the commands as
        operations, the script, the copies, what is remembered."""
        stale = [p for p in self._written(options) if p not in {f['path'] for f in r['files']}]
        remembered = None
        files = []
        for f, data in zip(r['files'], datas):
            one = {'path': f['path'], 'mode': f['mode'], 'owner': f['owner'] or '',
                   'format': f['format']}
            if f['format'] in PFX_FORMATS or f['format'] == 'p7b':
                if remembered is None:
                    remembered = self.unchanged(bundle, dict(options, force=False))
                one['keep_if_there'] = bool(remembered)
            if sealed and f['format'] in KEY_FORMATS:
                one['sealed'] = self.ctx.agent_seal('file ' + f['path'], data)
            elif sealed:
                one['data'] = base64.b64encode(data).decode('ascii')
            files.append(one)
        ops = {}
        for key, out in (('pre_cmd', 'pre'), ('test_cmd', 'test'), ('reload_cmd', 'reload'),
                         ('post_cmd', 'post')):
            ops[out] = [o for c in r[key] for o in cmd_ops(c)]
        sc = None
        env, secret = {}, {}
        if r['script']:
            s = r['script']
            sc = {'mode': s['mode'], 'args': s.get('args') or ''}
            if s['mode'] == 'inline':
                sc.update(body=s['body'], interp=s['interp'])
            else:
                sc['path'] = s['path']
            env = SC.env_for(self, bundle, r['pairs'], r['vars'], r['password'])
            if 'ACME_PASSWORD' in env:
                secret['ACME_PASSWORD'] = env.pop('ACME_PASSWORD')
        args = {'files': files, 'stale': stale, 'script': sc, 'env': env,
                'backup': r['backup'], 'backup_keep': r['backup_keep'],
                'skip_same': r['skip_same'], 'pending': self.pending()}
        args.update(ops)
        if secret and sealed:
            import json
            args['env_sealed'] = self.ctx.agent_seal('env', json.dumps(secret).encode())
        return args

    def deploy(self, bundle, options):
        options = options or {}
        r = self.resolved(bundle, options)
        datas = self.render(bundle, r)
        args = self.plan(bundle, options, r, datas)
        self.mark_pending(bundle)
        got = self._call('deploy', args, timeout=1800)
        for lv, words in got.get('steps') or []:
            self.ctx.step(words, lv)
        if not got.get('ok'):
            needs = got.get('needs') or []
            if needs:
                self.ctx.step('allow it on the server (as root), then deploy again:', 'bad')
                for n in needs:
                    self.ctx.step('  ' + n['allow'], 'bad')
            raise PluginError(got.get('said') or 'the agent refused', detail='\n'.join(
                n['allow'] for n in needs) or None, retry=not got.get('refused') and
                not needs)
        self._check_written(got, r, datas)
        self.remember(bundle, options)
        self.done_pending()
        self._written(options, [f['path'] for f in r['files']])
        host = got.get('host') or self.c('host') or self.ident()
        if got.get('unchanged'):
            return 'unchanged: every file on %s holds it already (the same SHA-256) - nothing ' \
                   'replaced, nothing run' % host
        return '%s on %s' % (got.get('said') or 'deployed', host)

    def _check_written(self, got, r, datas):
        """What the agent says it wrote is what was sent (its SHA-256)."""
        said = {f.get('path'): f.get('sha256') for f in got.get('files') or []}
        for f, data in zip(r['files'], datas):
            want = hashlib.sha256(data).hexdigest()
            if said.get(f['path']) not in (None, want):
                raise PluginError('the agent says %s holds another file than the one sent'
                                  % f['path'], retry=False)

    def dry_run(self, bundle, options, run_script=True):
        """The deployment as the agent would run it, against its policy - nothing written,
        nothing run."""
        options = dict(options or {})
        r = self.resolved(bundle, options)
        datas = self.render(bundle, r)
        args = self.plan(bundle, options, r, datas, sealed=False)
        got = self._call('check', args, timeout=120)
        for f in got.get('files') or []:
            self.ctx.step('%s: %s' % (f.get('path'), f.get('said') or ''),
                          'bad' if f.get('bad') else 'info')
        for c in args['pre'] + args['test'] + args['reload'] + args['post']:
            self.ctx.step('not run on a test: %s' % op_words(c))
        if not got.get('ok'):
            for n in got.get('needs') or []:
                self.ctx.step('needed: %s' % n['allow'], 'bad')
            raise PluginError(got.get('said') or 'the policy does not allow it', retry=False)
        self.ctx.step('the policy of the server allows every file, command and script', 'ok')
        return 'the test passed: the agent allows all of it (%d file%s)' % (
            len(r['files']), '' if len(r['files']) == 1 else 's')

    # -- what the page shows before anything runs ------------------------------------------
    def preview(self, bundle, options):
        got = SSH.SshTarget.preview(self, bundle, options)
        got['agent'] = self.needs(bundle, options)
        bad = [it for it in got['agent'].get('items') or [] if it.get('ok') is False]
        if bad:
            got.setdefault('problems', []).append(
                {'level': 'bad', 'words': 'the agent\'s policy does not allow %d of what this '
                                          'deployment does - the lines to run on the server are '
                                          'below' % len(bad)})
        return got

    def needs(self, bundle, options):
        """Each file, command and script of the deployment against the policy the agent last
        reported: ok (allowed), False (not - with the line that allows it), None (not known)."""
        info = self.ctx.agent_info() if hasattr(self.ctx, 'agent_info') else {}
        pol = (info or {}).get('policy')
        out = {'state': (info or {}).get('state') or 'new', 'policy_hash':
               (pol or {}).get('hash') if pol else None, 'policy_at': (info or {}).get(
                   'policy_at'), 'items': []}
        try:
            r = self.resolved(bundle, options, partial=True)
        except PluginError as e:
            out['error'] = str(e)
            return out
        try:
            args = self.plan(bundle, options, r, [b'' for _ in r['files']], sealed=False)
        except PluginError as e:
            out['error'] = str(e)
            return out
        check = self.ctx.agent_plan_check if hasattr(self.ctx, 'agent_plan_check') else None

        def judge(kind, label, what, part, allow_guess):
            if pol is None or check is None:
                out['items'].append({'kind': kind, 'label': label, 'what': what, 'ok': None,
                                     'allow': allow_guess})
                return
            needs = check(pol, part)
            out['items'].append({'kind': kind, 'label': label, 'what': what, 'ok': not needs,
                                 'allow': '\n'.join(n['allow'] for n in needs) if needs
                                 else allow_guess})
        for f in args['files']:
            u = f['owner'] or 'root:root'
            d = f['path'].rsplit('/', 1)[0] or '/'
            judge('file', 'file', '%s  %04o %s' % (f['path'], f['mode'], u), {'files': [f]},
                  'acme-agent allow file %s --owner %s --mode %04o' % (
                      quote(d), u if ':' in u else u + ':' + u, f['mode']))
        for key, words in (('pre', 'before'), ('test', 'test'), ('reload', 'reload'),
                           ('post', 'after')):
            for o in args[key]:
                judge(key, words, op_words(o), {key: [o]}, _allow_of(o))
        if args['script']:
            s = args['script']
            if s['mode'] == 'inline':
                h = hashlib.sha256(s['body'].encode('utf-8')).hexdigest()
                judge('script', 'the script written here', 'sha256 %s…' % h[:16], {'script': s},
                      'acme-agent allow script-hash %s' % h)
            else:
                judge('script', 'the script', s['path'], {'script': s},
                      'acme-agent allow script %s' % quote(s['path']))
        return out


def _allow_of(o):
    if 'any' in o:
        return '\n'.join(_allow_of(a) for a in o['any'][:1])
    if 'unit' in o:
        u = o['unit'] if '.' in o['unit'] else o['unit'] + '.service'
        return 'acme-agent allow unit %s %s' % (u, o['verb'])
    if 'argv' in o:
        return 'acme-agent allow test -- %s' % ' '.join(quote(a) for a in o['argv'])
    return 'acme-agent allow script %s' % quote(o.get('script') or '')
