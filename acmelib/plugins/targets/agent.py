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

Phase 3:

* the key made by the agent (device_key_optional - chosen per certificate, "Key made by the
  device"): device_csr() asks the agent (`keygen`) - root makes the key, keeps it, and answers
  a CSR; the deployment of the certificate then puts that key into its files (root renders
  key-pem, combined-pem, pfx... itself). acme never holds the key. A certificate deployed to
  several targets keeps acme's key (sealed to each agent);
* the tests of what it serves run through the agent (`probe`: the agent's server connects to
  host:port, as `allow probe` names it) - by default for the tests made from its deployments;
* a passive agent reached through an SSH connector (`via`), and the agent as a connector of
  other SSH targets (`allow connect`, runtime.SshSession).
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import shlex
import time

from acmelib.plugins.targets._common import Base, PluginError, field, as_int, PFX_FORMATS, quote
from acmelib.plugins.targets import _script as SC
from acmelib.plugins.targets import ssh as SSH

INTERPS = ('bash', 'sh', 'python3')
KEY_FORMATS = ('key-pem', 'key-rsa', 'key-der', 'key-traditional', 'key-pem-enc', 'combined-pem',
               'pfx', 'p12', 'p12-legacy', 'jks')
# a key the agent made: the formats its root side writes it in (deploy/agent/acme_agent.py) -
# combined-pem and pfx/p12 get the certificate's files from acme and the key put in there
AGENT_KEY_FORMATS = ('key-pem', 'key-traditional', 'key-rsa', 'key-der', 'combined-pem', 'pfx',
                     'p12')
WITH_CHAIN = ('combined-pem', 'pfx', 'p12')
# a test through the agent (`openssl s_client -starttls`): what each test module speaks
STARTTLS = {'smtp': 'smtp', 'imap': 'imap', 'pop3': 'pop3', 'ftp': 'ftp', 'xmpp': 'xmpp',
            'ldap': 'ldap', 'postgres': 'postgres', 'mysql': 'mysql'}
NO_PROBE = ('mssql', 'rdp')
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


class _ReqBundle(object):
    """The certificate asked for (device_csr), as far as the deployment's files need it: its
    names - no certificate, no key yet."""
    def __init__(self, req):
        self.name = req.name or (req.names or ['certificate'])[0]
        self.names = list(req.names or [self.name])
        self.key_type = req.key_type or 'ec-256'
        self.alt = None
        self.serial = ''
        self.fingerprint = ''
        self.cert_pem = ''
        self.key_pem = None
        self.chain_pems = []
        self.version = 0
        self.not_before = time.time()
        self.not_after = self.not_before + 90 * 86400

    def as_format(self, fmt, password=None, alias=None):
        raise PluginError('not issued yet', retry=False)


def probe_how(kind):
    """How the agent tests a test module's protocol: '' TLS at once, a STARTTLS protocol, or
    None - one it cannot speak (TDS, RDP)."""
    if kind in NO_PROBE:
        return None
    return STARTTLS.get(kind, '')


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
    # the key made by the agent, where the certificate says so (phase 3): chosen per
    # certificate - this target takes certificates with acme's key too
    device_key_optional = True
    device_key_types = ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096')
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
        field('via', 'Through a connector', 'select', default='', options=[['', 'directly']],
              options_from='agent_hops', advanced=True, show_if={'mode': ['passive']},
              help='a passive agent only another network reaches: acme signs in to the connector '
                   '(Targets → Connector over SSH) and reaches the agent\'s port from there - '
                   'nothing installed there'),
    ] + SC.script_fields(INTERPS, deploy=False)
    deploy_fields = SSH.SshTarget.deploy_fields
    files_ui = SC.files_ui('posix', INTERPS, SC.layouts('/etc/ssl/acme'),
                           presets=[[k, p['title']] for k, p in SSH.PRESETS.items()])

    # the deployment worked out as the SSH server's
    # a staticmethod there: taken as it is (a plain function here would be handed self)
    preset_outputs = staticmethod(SSH.SshTarget.preset_outputs)
    resolved = SSH.SshTarget.resolved
    _vars = SSH.SshTarget._vars
    _written_key = SSH.SshTarget._written_key
    _written = SSH.SshTarget._written
    verify = SSH.SshTarget.verify

    def served_places(self, options):
        """Where it serves the certificate, as its tests (through the agent) connect: the
        server itself (127.0.0.1 - `allow probe local`) on the preset's port."""
        preset = SSH.PRESETS.get((options or {}).get('preset') or 'custom') or {}
        return [('127.0.0.1', int(preset['port']))] if preset.get('port') else []

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

    # -- the key made by the agent (phase 3) ---------------------------------------------
    def _slot(self):
        dep = getattr(self.ctx, 'deploy_id', None)
        return ('dep-%s' % dep) if dep not in (None, '') else 'dep-new'

    def agent_key_of(self, bundle):
        """Whether this deployment's key is made by the agent: the certificate holds no key of
        acme's (its key is made here - devicekey), or the certificate says so."""
        if getattr(bundle, 'key_pem', '') is None:
            return True
        store = getattr(self.ctx, 'store', None)
        dep = getattr(self.ctx, 'deploy_id', None)
        if store is None or dep in (None, ''):
            return False
        try:
            got = store.db.row('SELECT c.csr_from FROM cert_deploys d JOIN certs c ON '
                               'c.id = d.cert_id WHERE d.id = ?', (int(dep),))
        except Exception:                               # noqa: BLE001
            return False
        name = getattr(self.ctx, 'target_name', '') or ''
        return bool(got and name and str(got.get('csr_from') or '') == name)

    def _key_files(self, r):
        files = [f for f in r['files'] if f['format'] in KEY_FORMATS]
        bad = [f for f in files if f['format'] not in AGENT_KEY_FORMATS]
        if bad:
            raise PluginError('%s: a key the agent makes cannot be written as %s - it writes %s '
                              '(or let acme make the key)' % (
                                  bad[0]['path'], bad[0]['format'], ', '.join(AGENT_KEY_FORMATS)),
                              retry=False)
        if not files:
            raise PluginError('the deployment writes no file that holds the key - give it one '
                              '(key-pem, combined-pem, pfx...): the agent puts the key it makes '
                              'there', retry=False)
        return files

    def device_csr(self, req):
        """The agent makes a new key (its root side, kept there) and answers its CSR - checked
        first: the files of this deployment that will hold it are allowed by its policy."""
        r = self.resolved(_ReqBundle(req), dict(req.options or {}))
        files = self._key_files(r)
        args = {'slot': self._slot(), 'key_type': req.key_type, 'names': list(req.names),
                'keep': bool(getattr(req, 'reuse_key', False)),
                'files': [{'path': f['path'], 'mode': f['mode'], 'owner': f['owner'] or '',
                           'format': f['format']} for f in files]}
        got = self._call('keygen', args, timeout=240)
        if not got.get('ok'):
            needs = got.get('needs') or []
            for n in needs:
                self.ctx.step('allow it on the server (as root): %s' % n['allow'], 'bad')
            raise PluginError(got.get('said') or 'the agent made no key', detail='\n'.join(
                n['allow'] for n in needs) or None, retry=not needs and not got.get('refused'))
        fp = str(got.get('key_fp') or '')
        # (What happens has no key: its fingerprint is not said there)
        # in acme's words: what the agent says is from the server's side ("made here")
        self.ctx.step('%s and its CSR made by the agent on %s%s - the key stays there, for '
                      '%s' % (
                          ('a %s key (the one in use kept, where there is one)' if args['keep']
                           else 'a new %s key') % (
                              req.key_type or 'ec-256'), getattr(self.ctx, 'target_name', '')
                          or self.c('host') or 'the server',
                          ' (its key %s…)' % fp[:16] if fp else '',
                          ', '.join(f['path'] for f in files)), 'ok')
        return got.get('csr') or ''

    def render(self, bundle, r, agent_key=False):
        """The bytes of each file; with the key made by the agent, a file holding the key is
        made there - acme sends what goes with it (the certificate and its chain)."""
        if not agent_key:
            return SSH.SshTarget.render(self, bundle, r)
        self._key_files(r)
        datas = []
        for f, b in r.get('pairs') or [(f, bundle) for f in r['files']]:
            if f['format'] in KEY_FORMATS:
                datas.append(b.as_format('fullchain-pem') if f['format'] in WITH_CHAIN else b'')
                continue
            got = SSH.SshTarget.render(self, b, dict(r, pairs=[(f, b)], files=[f]))
            datas.append(got[0])
        return datas

    # -- what is sent ----------------------------------------------------------------------
    def plan(self, bundle, options, r, datas, sealed=True, agent_key=False):
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
            if agent_key and f['format'] in KEY_FORMATS:
                # the key is the agent's own: what goes with it (the certificate files) only
                one['agent_key'] = True
                if sealed:
                    one['data'] = base64.b64encode(data).decode('ascii')
            elif sealed and f['format'] in KEY_FORMATS:
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
            args['env_sealed'] = self.ctx.agent_seal('env', json.dumps(secret).encode())
        if agent_key:
            ak = {'slot': self._slot()}
            if sealed:
                ak['cert_pem'] = getattr(bundle, 'cert_pem', '') or ''
                if any(f['format'] in PFX_FORMATS for f in r['files']):
                    ak['alias'] = r['jks_alias'] or r['vars']['name']
                    if r.get('password'):
                        ak['pass_sealed'] = self.ctx.agent_seal('pfx', str(r['password'])
                                                                .encode('utf-8'))
            args['agent_key'] = ak
        return args

    def plan_meta(self, options, r):
        """What a plan says of the files besides the job (1.0.123): how a PKCS#12/JKS is
        protected, its alias - the password itself never."""
        mode = SC.password_mode(options)
        if mode == 'fixed' and not (options or {}).get('pfx_password'):
            mode = 'none'
        return {'password': mode, 'alias': r.get('jks_alias') or (r.get('vars') or {}).get('name')
                or ''}

    def deploy(self, bundle, options):
        options = options or {}
        r = self.resolved(bundle, options)
        ak = self.agent_key_of(bundle)
        self._agent_key_now = ak
        if ak and getattr(bundle, 'key_pem', None):
            raise PluginError('the key of this certificate is made by the agent: a certificate '
                              'with acme\'s key does not go with it', retry=False)
        datas = self.render(bundle, r, agent_key=ak)
        args = self.plan(bundle, options, r, datas, agent_key=ak)
        self.mark_pending(bundle)
        if hasattr(self.ctx, 'agent_meta'):
            # What happens only (1.0.123): what the job's files are made with that the job
            # itself does not carry - never sent to the agent, no secret in it
            self.ctx.agent_meta(self.plan_meta(options, r))
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
        host = got.get('host') or self.c('host') or getattr(self.ctx, 'target_name', '') or \
            self.ident()
        if got.get('unchanged'):
            return 'unchanged: every file on %s holds it already (the same SHA-256) - nothing ' \
                   'replaced, nothing run' % host
        return '%s on %s' % (got.get('said') or 'deployed', host)

    def _check_written(self, got, r, datas):
        """What the agent says it wrote is what was sent (its SHA-256)."""
        said = {f.get('path'): f.get('sha256') for f in got.get('files') or []}
        for f, data in zip(r['files'], datas):
            if f['format'] in KEY_FORMATS and getattr(self, '_agent_key_now', False):
                continue                    # made there, with the agent's own key
            want = hashlib.sha256(data).hexdigest()
            if said.get(f['path']) not in (None, want):
                raise PluginError('the agent says %s holds another file than the one sent'
                                  % f['path'], retry=False)

    def dry_run(self, bundle, options, run_script=True):
        """The deployment as the agent would run it, against its policy - nothing written,
        nothing run."""
        options = dict(options or {})
        r = self.resolved(bundle, options)
        ak = self.agent_key_of(bundle)
        if ak:
            self._key_files(r)
            datas = [b'' for _ in r['files']]
        else:
            datas = self.render(bundle, r)
        args = self.plan(bundle, options, r, datas, sealed=False, agent_key=ak)
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
        if got['agent'].get('error'):
            # what the agent cannot do at all: a line of a shell (the Kubernetes preset), a key
            # it makes in a file it cannot write it in (jks...) or in none
            got.setdefault('problems', []).append({'level': 'bad',
                                                   'words': got['agent']['error']})
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
                   'policy_at'), 'items': [],
               # the target, for the policy builder the card opens (1.0.118)
               'target': {'id': (info or {}).get('id'), 'name': getattr(
                   self.ctx, 'target_name', '') or ''}}
        try:
            r = self.resolved(bundle, options, partial=True)
        except PluginError as e:
            out['error'] = str(e)
            return out
        ak = self.agent_key_of(bundle)
        out['agent_key'] = ak
        try:
            if ak:
                self._key_files(r)
            args = self.plan(bundle, options, r, [b'' for _ in r['files']], sealed=False,
                             agent_key=ak)
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
            it = {'kind': kind, 'label': label, 'what': what, 'ok': not needs,
                  'allow': '\n'.join(n['allow'] for n in needs if n.get('allow')) if needs
                  else allow_guess}
            why = '; '.join(str(n.get('what') or '') for n in needs if not n.get('allow'))
            if why:
                it['why'] = why             # never allowed there (no line allows it)
            out['items'].append(it)
        for f in args['files']:
            u = f['owner'] or 'root:root'
            d = f['path'].rsplit('/', 1)[0] or '/'
            judge('key' if f.get('agent_key') else 'file',
                  'the key, made there' if f.get('agent_key') else 'file',
                  '%s  %04o %s' % (f['path'], f['mode'], u), {'files': [f]},
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
        # the tests of what it serves, through the agent (phase 3): each place a probe
        for host, port in self.served_places(options)[:5]:
            hp = ('[%s]:%d' % (host, port)) if ':' in str(host) else '%s:%d' % (host, port)
            m = self._mod()
            if pol is None or m is None:
                out['items'].append({'kind': 'probe', 'label': 'test', 'what': hp, 'ok': None,
                                     'allow': 'acme-agent allow probe %s' % (
                                         'local' if host in m_local() else hp)})
                continue
            try:
                h, p = m.split_hostport(hp)
                ok = m.dest_allowed(dict(m.parse_policy(''), **{
                    'probe': list(pol.get('probe') or []),
                    'probe_local': bool(pol.get('probe_local'))}), h, p, 'probe')
            except Exception:                           # noqa: BLE001
                ok = False
            out['items'].append({'kind': 'probe', 'label': 'test', 'what': hp, 'ok': ok,
                                 'allow': '' if ok else 'acme-agent allow probe %s' % (
                                     'local' if host in m_local() else hp)})
        return out

    def _mod(self):
        try:
            from acmelib.certs import agents
            return agents.agent_mod()
        except Exception:                               # noqa: BLE001
            return None


def m_local():
    return ('127.0.0.1', '::1', 'localhost')


def _allow_of(o):
    if 'any' in o:
        return '\n'.join(_allow_of(a) for a in o['any'][:1])
    if 'unit' in o:
        u = o['unit'] if '.' in o['unit'] else o['unit'] + '.service'
        return 'acme-agent allow unit %s %s' % (u, o['verb'])
    if 'argv' in o:
        return 'acme-agent allow test -- %s' % ' '.join(quote(a) for a in o['argv'])
    return 'acme-agent allow script %s' % quote(o.get('script') or '')
