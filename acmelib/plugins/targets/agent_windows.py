# -*- coding: utf-8 -*-
"""
A Windows server with acme-agent (1.0.120, docs/target-agent.md "Windows"): the agent of
"Server with acme-agent" (targets/agent.py) - the same join, modes, ports, connector, tests
through the agent, keys made by the agent, What happens - with the deployment of Windows:

    the machine store       the certificate imported into Cert:\\LocalMachine\\My (key not
                            exportable unless asked); the older ones this agent imported for
                            the deployment removed beyond Keep        (allow store)
    IIS bindings            site | host name | port [| ip], one a line - https bindings set
                            to it (an SNI one by host name), made when missing
                                                                      (allow iis SITE)
    Remote Desktop          the listener's certificate                 (allow rdp)
    Files                   besides the store: C:\\ paths, the same formats (no owner, no
                            mode: a folder's readers are the policy's)  (allow file C:\\certs)
    commands                Restart-Service [-Name] W3SVC [-Force]  -> the service, restart
                            Start-Service NAME                      -> the service, start
                            iisreset                                -> that command line
                            C:\\scripts\\x.ps1 ARGS                  -> that script, its SHA-256
                            a line of a shell (| ; & $ ` ( ) { } < >) -> refused: a script
    PowerShell after        a script written here (allow script-hash) or one on the server

What the agent cannot do: Exchange (Enable-ExchangeCertificate) and the Windows roles of
"Windows server (OpenSSH + PowerShell)" (AD FS, RD Gateway, WinRM...) - those stay with that
target.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re

from acmelib.plugins.targets._common import (
    PluginError, field, as_int, as_bool, lines, PFX_FORMATS, label_of, stamp, alt_of, family_of,
    service_of, subst, parse_outputs, outputs_for, keep_field, verify_fields, object_name,
    random_password)
from acmelib.plugins.targets import _files as F
from acmelib.plugins.targets import _script as SC
from acmelib.plugins.targets import agent as AG

WIN_INTERPS = ('powershell',)
WIN_VERBS = ('restart', 'try-restart', 'start')
STORE_PFX = ('p12-legacy', 'pfx')
# a line of a shell: the agent runs none (put it into a script the policy allows)
WIN_SHELL_RE = re.compile(r'[|;&$`(){}<>\n\r]')
WIN_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|(\S+)')
PS1_RE = re.compile(r'[A-Za-z]:[\\/].*\.ps1\Z', re.I)
DRIVE_RE = re.compile(r'[A-Za-z]:[\\/]')


def win_path(p):
    """C:/certs/x.pem -> C:\\certs\\x.pem (the drive letter upper-case) - as the agent
    keeps it."""
    p = str(p or '').replace('/', '\\')
    if DRIVE_RE.match(p):
        p = p[0].upper() + p[1:]
    while '\\\\' in p[2:]:
        p = p[:2] + p[2:].replace('\\\\', '\\')
    return p


def cmd_word(s):
    """A word of a command line as an administrator types it (cmd.exe, PowerShell)."""
    s = str(s)
    return '"%s"' % s if (not s or re.search(r'[\s&|<>^%;,()\'`$]', s)) else s


def _tokens(text):
    out = []
    for m in WIN_TOKEN_RE.finditer(text):
        dq, sq, bare = m.group(1), m.group(2), m.group(3)
        out.append(dq if dq is not None and m.group(0).startswith('"') else
                   sq if sq is not None and m.group(0).startswith("'") else bare)
    return out


def _service_names(text, cmd):
    """Restart-Service [-Name] W3SVC[,WAS] [-Force] -> ['W3SVC', 'WAS']"""
    argv = _tokens(text)
    names, i = [], 1
    while i < len(argv):
        a = argv[i]
        low = a.lower()
        if low in ('-name', '-n'):
            if i + 1 >= len(argv):
                raise PluginError('"%s": -Name without a service' % text, retry=False)
            names += [x for x in argv[i + 1].split(',') if x]
            i += 2
            continue
        if low in ('-force', '-confirm:$false', '-nowait'):
            i += 1
            continue
        if low.startswith('-'):
            raise PluginError('"%s": %s %s is not one the agent does (%s [-Name] NAME '
                              '[-Force])' % (text, cmd, a, cmd), retry=False)
        names += [x for x in a.split(',') if x]
        i += 1
    for n in names:
        if not re.match(r'[A-Za-z0-9_.$@ -]{1,256}\Z', n) or '*' in n:
            raise PluginError('"%s": %r is not the name of a service' % (text, n), retry=False)
    if not names:
        raise PluginError('"%s": which service? (%s NAME)' % (text, cmd), retry=False)
    return names


def cmd_ops(line):
    """One command line of a Windows deployment as the operation the agent runs - or
    PluginError: a service's verb, a fixed command line, a PowerShell script."""
    text = str(line or '').strip()
    if not text:
        raise PluginError('an empty command', retry=False)
    if WIN_SHELL_RE.search(text.replace('-Confirm:$false', '')):
        raise PluginError('"%s" is a line of a shell: the agent runs no shell - a service to '
                          'restart (Restart-Service NAME), a fixed command or a PowerShell script '
                          'allowed on the server (put the rest into such a script)' % text,
                          retry=False)
    argv = _tokens(text)
    head = argv[0].lower()
    if head in ('restart-service', 'start-service'):
        verb = 'restart' if head == 'restart-service' else 'start'
        cmd = 'Restart-Service' if verb == 'restart' else 'Start-Service'
        return [{'unit': n, 'verb': verb} for n in _service_names(text, cmd)]
    if head in ('stop-service',):
        raise PluginError('"%s": a service is only restarted or started by the agent '
                          '(Restart-Service NAME)' % text, retry=False)
    if head in ('net', 'net.exe', 'sc', 'sc.exe') and len(argv) >= 2 and \
            argv[1].lower() in ('stop', 'start'):
        raise PluginError('"%s": net stop / net start is not what the agent runs - use '
                          'Restart-Service %s (one line: the service restarted)' % (
                              text, argv[2] if len(argv) > 2 else 'NAME'), retry=False)
    if PS1_RE.match(argv[0]):
        return [{'script': win_path(argv[0]), 'args': argv[1:]}]
    if re.search(r'\.(bat|cmd)\Z', argv[0], re.I):
        raise PluginError('"%s": a .bat or .cmd runs in cmd.exe (a shell) - write it as a '
                          'PowerShell script (.ps1) the policy allows' % text, retry=False)
    if head in ('cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'):
        raise PluginError('"%s" is a shell: put what it runs into a PowerShell script the policy '
                          'allows (C:\\scripts\\x.ps1)' % text, retry=False)
    if DRIVE_RE.match(argv[0]):
        argv[0] = win_path(argv[0])
    return [{'argv': argv}]


def op_words(op):
    if 'any' in op:
        return ' || '.join(op_words(a) for a in op['any'])
    if 'unit' in op:
        return {'restart': 'Restart-Service %s', 'start': 'Start-Service %s',
                'try-restart': 'Restart-Service %s (when it runs)'}.get(
                    op['verb'], op['verb'] + ' %s') % cmd_word(op['unit'])
    if 'argv' in op:
        return ' '.join(cmd_word(a) for a in op['argv'])
    return ' '.join([op.get('script') or '?'] + [cmd_word(a) for a in op.get('args') or []])


def allow_of(o):
    if 'any' in o:
        return '\n'.join(allow_of(a) for a in o['any'][:1])
    if 'unit' in o:
        return 'acme-agent allow service %s %s' % (cmd_word(o['unit']), o['verb'])
    if 'argv' in o:
        return 'acme-agent allow test -- %s' % ' '.join(cmd_word(a) for a in o['argv'])
    return 'acme-agent allow script %s' % cmd_word(o.get('script') or '')


def iis_lines(v):
    """The IIS bindings field -> [{site, host, port, ip}]"""
    out = []
    for n, line in enumerate(lines(v), 1):
        parts = [p.strip() for p in line.split('|')]
        if not parts[0]:
            raise PluginError('IIS line %d has no site' % n, retry=False)
        if '"' in parts[0]:
            raise PluginError('IIS line %d: a site\'s name holds no "' % n, retry=False)
        host = parts[1].lower().rstrip('.') if len(parts) > 1 else ''
        port = as_int(parts[2], 443) if len(parts) > 2 and parts[2] else 443
        ip = parts[3] if len(parts) > 3 and parts[3] else '*'
        if not 0 < port < 65536:
            raise PluginError('IIS line %d: %s is not a port' % (n, parts[2]), retry=False)
        out.append({'site': parts[0], 'host': host, 'port': port, 'ip': ip})
    return out


def _wc():
    """deploy/agent/acme_agent_wincert.py - the agent's own words for the store, IIS, RDP."""
    from acmelib.certs import agents
    return agents.wincert_mod()


def win_needs(pol, win):
    """What the policy lacks for the `win` part of a job ([{kind, what, allow}]) - the agent's
    own check (acme_agent_wincert.win_check) of the store, the bindings, the listener."""
    W = _wc()
    out = []
    if (win or {}).get('store') and not W.pol_store(pol):
        out.append({'kind': 'store', 'what': 'the certificate imported into the machine store '
                    '(LocalMachine\\My)', 'allow': 'acme-agent allow store'})
    asked = set()
    for b in (win or {}).get('iis') or []:
        if not W.iis_allowed(pol, b['site']) and b['site'].lower() not in asked:
            asked.add(b['site'].lower())
            out.append({'kind': 'iis', 'what': 'the https bindings of the IIS site %s' % b['site'],
                        'allow': W.allow_iis_words(b['site'])})
    if (win or {}).get('rdp') and not W.pol_rdp(pol):
        out.append({'kind': 'rdp', 'what': 'the certificate of the Remote Desktop listener',
                    'allow': 'acme-agent allow rdp'})
    return out


class AgentWindowsTarget(AG.AgentTarget):
    kind = 'agent_windows'
    discovery = False
    title = 'Windows server with acme-agent'
    vendor = 'Microsoft'
    description = ('acme holds none of the server\'s credentials: a small agent on it imports the '
                   'certificate into the machine store, binds it to IIS sites and the Remote '
                   'Desktop listener, writes files, restarts services - only what its own policy '
                   'allows. Exchange and the Windows roles stay with the OpenSSH target.')
    doc = 'target-agent.md'
    dual = False
    fields = [f for f in AG.AgentTarget.fields if not f['key'].startswith('script_')] + \
        SC.script_fields(WIN_INTERPS, deploy=False, default='powershell')
    deploy_fields = [
        field('store', 'Machine store', 'bool', default=True,
              help='the certificate imported into Cert:\\LocalMachine\\My - the IIS bindings and '
                   'the Remote Desktop listener take it from there (the policy: allow store)'),
        field('iis', 'IIS bindings', 'list',
              placeholder='Default Web Site | www.example.com | 443',
              help='site | host name | port [| ip], one a line. A host name makes an SNI '
                   'binding; none binds the port for all names. Missing https bindings '
                   'are made (the policy: allow iis SITE)'),
        field('rdp', 'Remote Desktop listener', 'bool', default=False,
              help='the certificate of the RDP listener (the policy: allow rdp). Exchange is '
                   'not done by the agent - the target "Windows server (OpenSSH + PowerShell)" '
                   'does it'),
        field('pfx_format', 'PKCS#12 kind', 'select', default='p12-legacy', advanced=True,
              options=[['p12-legacy', '3DES (any Windows)'],
                       ['pfx', 'AES-256 (Windows Server 2019 and later)']]),
        field('exportable', 'Key exportable', 'bool', default=False, advanced=True),
        dict(keep_field(1), help='older certificates this agent imported for this deployment '
                                 'are removed from the store beyond this many (0 to 10) - '
                                 'never one still bound'),
        field('outputs', 'Files', 'list', ui='files', advanced=True,
              placeholder='pfx C:/certs/{name}.pfx\nfullchain-pem C:/nginx/conf/{name}.crt',
              help='besides the machine store, when asked: one a line, format path - the '
                   'same formats as on Linux; no owner, no mode (who reads them is said by the '
                   'policy\'s readers=); {name} {cn} {service} {date} in paths'),
    ] + SC.password_fields() + [
        field('service', 'Service name', 'text', advanced=True,
              help='{service} in the paths and commands, ACME_SERVICE for the script'),
    ] + F.file_fields() + SC.script_fields(WIN_INTERPS, default='powershell') + [
        field('pre_cmd', 'Before writing', 'list', advanced=True,
              help='commands run first; one failing stops the deployment'),
        field('test_cmd', 'Test command', 'list', advanced=True,
              placeholder='C:\\scripts\\test-site.ps1',
              help='run after the store and the bindings; when one fails the bindings, the '
                   'store and the files are put back'),
        field('reload_cmd', 'Restart', 'list', placeholder='Restart-Service W3SVC',
              help='Restart-Service NAME, Start-Service NAME, iisreset or a PowerShell script '
                   '(C:\\scripts\\x.ps1) - no shell: one failing puts everything back'),
        field('post_cmd', 'After restarting', 'list', advanced=True,
              help='run last; a failure here is only a warning'),
    ] + verify_fields()
    files_ui = SC.files_ui('windows', WIN_INTERPS, SC.layouts('C:/certs', 'windows'),
                           owners=False)

    # -- what the options say ---------------------------------------------------------------
    def resolved(self, bundle, options, partial=False):
        options = dict(options or {})
        out = {}
        for key in ('outputs', 'test_cmd', 'reload_cmd', 'pre_cmd', 'post_cmd', 'service',
                    'jks_alias', 'pfx_password', 'backup', 'backup_format', 'skip_same',
                    'backup_keep'):
            out[key] = options.get(key)
        out['backup'] = F.backup_mode({'backup': out['backup'],
                                       'backup_format': out['backup_format']})
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
        for f in files:
            if f.get('owner'):
                raise PluginError('%s: Windows files have no owner (who reads them is the '
                                  'policy\'s readers= of their folder)' % f['path'], retry=False)
            if not DRIVE_RE.match(f['path']):
                raise PluginError('%s is not a path of Windows (C:\\...)' % f['path'],
                                  retry=False)
            f['path'] = win_path(f['path'])
            f['owner'] = ''
        out['pairs'] = outputs_for(self.ctx, bundle, files)
        out['files'] = [f for f, _b in out['pairs']]
        for key in ('pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd'):
            out[key] = [subst(c, vars) for c in lines(out[key])]
        out['password'] = SC.password_of(dict(options, pfx_password=out['pfx_password']))
        out['script'] = SC.script_of(self, options, vars, WIN_INTERPS)
        out['iis'] = iis_lines(options.get('iis'))
        out['rdp'] = as_bool(options.get('rdp'))
        out['store'] = as_bool(options.get('store'), True) or bool(out['iis']) or out['rdp']
        keep = as_int(options.get('keep', 1), 1)
        out['keep'] = 10 if keep < 0 else min(keep, 10)
        out['pfx_format'] = options.get('pfx_format') if options.get('pfx_format') in \
            STORE_PFX else 'p12-legacy'
        out['exportable'] = as_bool(options.get('exportable'))
        if not out['files'] and not out['store'] and not partial:
            raise PluginError('nothing to do: the machine store is off and no files are '
                              'written', retry=False)
        return out

    def served_places(self, options):
        """Where it serves the certificate, as its tests (through the agent) connect: IIS on
        the server itself (127.0.0.1, `allow probe local`) - one place a port. The Remote
        Desktop listener is not probed (the agent does not speak RDP)."""
        try:
            iis = iis_lines((options or {}).get('iis'))
        except PluginError:
            return []
        ports = []
        for b in iis:
            if b['port'] not in ports:
                ports.append(b['port'])
        return [('127.0.0.1', p) for p in ports]

    def verify(self, bundle, options):
        from acmelib.plugins.targets._common import Base
        return Base.verify(self, bundle, options)

    # -- the key made by the agent -----------------------------------------------------------
    def _key_files(self, r):
        """With the key made by the agent the store's PKCS#12 is made there: no file needs to
        hold it - the files that do are the ones of the agent's formats."""
        files = [f for f in r['files'] if f['format'] in AG.KEY_FORMATS]
        bad = [f for f in files if f['format'] not in AG.AGENT_KEY_FORMATS]
        if bad:
            raise PluginError('%s: a key the agent makes cannot be written as %s - it writes %s '
                              '(or let acme make the key)' % (
                                  bad[0]['path'], bad[0]['format'], ', '.join(
                                      AG.AGENT_KEY_FORMATS)), retry=False)
        if not files and not r.get('store'):
            raise PluginError('the deployment puts the key nowhere - switch the machine store on '
                              'or give it a file that holds the key', retry=False)
        return files

    def device_csr(self, req):
        r = self.resolved(AG._ReqBundle(req), dict(req.options or {}))
        files = self._key_files(r)
        args = {'slot': self._slot(), 'key_type': req.key_type, 'names': list(req.names),
                'keep': bool(getattr(req, 'reuse_key', False)),
                'files': [{'path': f['path'], 'format': f['format']} for f in files]}
        if r['store']:
            args['store'] = True
        got = self._call('keygen', args, timeout=240)
        if not got.get('ok'):
            needs = got.get('needs') or []
            for n in needs:
                self.ctx.step('allow it on the server (as an administrator): %s' % n['allow'],
                              'bad')
            raise PluginError(got.get('said') or 'the agent made no key', detail='\n'.join(
                n['allow'] for n in needs) or None, retry=not needs and not got.get('refused'))
        fp = str(got.get('key_fp') or '')
        self.ctx.step('%s and its CSR made by the agent on %s%s - the key stays there, for %s' % (
            ('a %s key (the one in use kept, where there is one)' if args['keep']
             else 'a new %s key') % (req.key_type or 'ec-256'),
            getattr(self.ctx, 'target_name', '') or self.c('host') or 'the server',
            ' (its key %s…)' % fp[:16] if fp else '',
            ', '.join(['the machine store'] * bool(r['store']) + [f['path'] for f in files])),
            'ok')
        return got.get('csr') or ''

    def render(self, bundle, r, agent_key=False):
        if not agent_key:
            return self._render_files(bundle, r)
        self._key_files(r)
        datas = []
        for f, b in r.get('pairs') or [(f, bundle) for f in r['files']]:
            if f['format'] in AG.KEY_FORMATS:
                datas.append(b.as_format('fullchain-pem') if f['format'] in AG.WITH_CHAIN
                             else b'')
                continue
            datas.append(self._render_files(b, dict(r, pairs=[(f, b)], files=[f]))[0])
        return datas

    def _render_files(self, bundle, r):
        alias = r['jks_alias'] or r['vars']['name']
        datas = []
        for f, b in r.get('pairs') or [(f, bundle) for f in r['files']]:
            pw = None
            if f['format'] in PFX_FORMATS:
                pw = r.get('password') or None
                if f['format'] == 'jks' and (not pw or len(pw) < 6):
                    raise PluginError('a jks keystore needs a password of 6 characters or more',
                                      retry=False)
            data = b.as_format(f['format'], password=pw, alias=alias)
            datas.append(data.encode() if isinstance(data, str) else data)
        return datas

    # -- what is sent -------------------------------------------------------------------------
    def plan(self, bundle, options, r, datas, sealed=True, agent_key=False):
        """The job's arguments - the agent's (files, commands, script, copies) for Windows:
        files without owner or mode, the commands of Windows, and `win`: the store, the IIS
        bindings, the Remote Desktop listener."""
        stale = [p for p in self._written(options) if p not in {f['path'] for f in r['files']}]
        remembered = None
        files = []
        for f, data in zip(r['files'], datas):
            one = {'path': f['path'], 'format': f['format']}
            if f['format'] in PFX_FORMATS or f['format'] == 'p7b':
                if remembered is None:
                    remembered = self.unchanged(bundle, dict(options, force=False))
                one['keep_if_there'] = bool(remembered)
            if agent_key and f['format'] in AG.KEY_FORMATS:
                one['agent_key'] = True
                if sealed:
                    one['data'] = base64.b64encode(data).decode('ascii')
            elif sealed and f['format'] in AG.KEY_FORMATS:
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
                sc['path'] = win_path(s['path'])
            env = SC.env_for(self, bundle, r['pairs'], r['vars'], r['password'])
            if getattr(bundle, 'cert_pem', ''):
                try:
                    env['ACME_THUMBPRINT'] = _wc().thumb_of(bundle.cert_pem)
                except Exception:                       # noqa: BLE001
                    pass
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
        args['win'] = self._win(bundle, options, r, args, sealed, agent_key)
        return args

    def _win(self, bundle, options, r, args, sealed, agent_key):
        win = {'store': None, 'iis': [dict(b) for b in r['iis']], 'rdp': r['rdp']}
        if not r['store']:
            return win
        pem = getattr(bundle, 'cert_pem', '') or ''
        try:
            chain = bundle.as_format('fullchain-pem') if pem else ''
        except Exception:                               # noqa: BLE001
            chain = pem
        chain = chain.decode() if isinstance(chain, bytes) else (chain or '')
        st = {'pfx_index': None, 'cert_pem': chain or pem,
              'friendly': object_name(bundle, options) if pem else 'acme',
              'exportable': r['exportable'], 'keep': r['keep'], 'slot': self._slot(),
              'legacy': r['pfx_format'] == 'p12-legacy'}
        if not agent_key:
            # a PKCS#12 only for the store: never written as a file there
            one = {'path': '', 'format': r['pfx_format']}
            if sealed:
                pw = random_password()
                data = bundle.as_format(r['pfx_format'], password=pw,
                                        alias=object_name(bundle, options))
                one['sealed'] = self.ctx.agent_seal('win store', data if isinstance(
                    data, bytes) else data.encode())
                st['password_sealed'] = self.ctx.agent_seal('win store password',
                                                            pw.encode('utf-8'))
            st['pfx_index'] = len(args['files'])
            args['files'].append(one)
        win['store'] = st
        return win

    def _check_written(self, got, r, datas):
        said = {str(f.get('path') or '').lower(): f.get('sha256') for f in got.get('files') or []}
        for f, data in zip(r['files'], datas):
            if f['format'] in AG.KEY_FORMATS and getattr(self, '_agent_key_now', False):
                continue
            want = hashlib.sha256(data).hexdigest()
            if said.get(f['path'].lower()) not in (None, want):
                raise PluginError('the agent says %s holds another file than the one sent'
                                  % f['path'], retry=False)

    def dry_run(self, bundle, options, run_script=True):
        """The deployment as the agent would run it, against its policy: the store, the
        bindings (is the site there, is the binding) and the files looked at - nothing changed,
        nothing run."""
        options = dict(options or {})
        r = self.resolved(bundle, options)
        ak = self.agent_key_of(bundle)
        if ak:
            self._key_files(r)
            datas = [b'' for _ in r['files']]
        else:
            datas = self._render_files(bundle, r)
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
        self.ctx.step('the policy of the server allows every file, command, script and binding',
                      'ok')
        return 'the test passed: the agent allows all of it (%s)' % ', '.join(
            ['the machine store'] * bool(r['store']) +
            ['%d IIS binding%s' % (len(r['iis']), '' if len(r['iis']) == 1 else 's')] *
            bool(r['iis']) + ['Remote Desktop'] * bool(r['rdp']) +
            ['%d file%s' % (len(r['files']), '' if len(r['files']) == 1 else 's')] *
            bool(r['files']))

    # -- what the page shows before anything runs ------------------------------------------
    def preview(self, bundle, options):
        options = dict(options or {})
        problems = []
        try:
            r = self.resolved(bundle, options, partial=True)
            pairs, vars = r['pairs'], r['vars']
        except PluginError as e:
            problems.append({'level': 'bad', 'words': str(e)})
            r = None
            pairs = []
            vars = {'name': label_of(bundle, options), 'cn': label_of(bundle, options),
                    'date': stamp(bundle), 'service': service_of(options.get('service'),
                                                                 label_of(bundle, options)),
                    'alt': 'alt'}
        got = SC.preview(self, bundle, options, pairs, vars, problems, owners=False,
                         interps=WIN_INTERPS, windows=True)
        got['problems'] = [p for p in got['problems'] if p['words'] != 'no files are written']
        if r is not None:
            got['commands'] = {k: r[k] for k in ('pre_cmd', 'test_cmd', 'reload_cmd',
                                                 'post_cmd')}
        got['agent'] = self.needs(bundle, options)
        if got['agent'].get('error'):
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
        """Each file, command, script, the store and each binding against the policy the agent
        last reported: ok, False (with the line that allows it), None (not known)."""
        info = self.ctx.agent_info() if hasattr(self.ctx, 'agent_info') else {}
        pol = (info or {}).get('policy')
        out = {'state': (info or {}).get('state') or 'new', 'policy_hash':
               (pol or {}).get('hash') if pol else None, 'policy_at': (info or {}).get(
                   'policy_at'), 'items': [], 'platform': 'windows',
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

        def judge(kind, label, what, part, allow_guess, needs=None):
            if pol is None or (check is None and needs is None):
                out['items'].append({'kind': kind, 'label': label, 'what': what, 'ok': None,
                                     'allow': allow_guess})
                return
            if needs is None:
                needs = check(pol, dict(part, platform='windows'))
            it = {'kind': kind, 'label': label, 'what': what, 'ok': not needs,
                  'allow': '\n'.join(n['allow'] for n in needs if n.get('allow')) if needs
                  else allow_guess}
            why = '; '.join(str(n.get('what') or '') for n in needs if not n.get('allow'))
            if why:
                it['why'] = why
            out['items'].append(it)
        win = args['win']
        if win.get('store'):
            judge('store', 'the machine store', 'Cert:\\LocalMachine\\My%s' % (
                ' (key exportable)' if r['exportable'] else ''), None, 'acme-agent allow store',
                needs=win_needs(pol, {'store': True}) if pol is not None else None)
        for b in win.get('iis') or []:
            judge('iis', 'IIS', '%s  https %s:%d' % (b['site'], b['host'] or b['ip'], b['port']),
                  None, _wc().allow_iis_words(b['site']),
                  needs=win_needs(pol, {'iis': [b]}) if pol is not None else None)
        if win.get('rdp'):
            judge('rdp', 'Remote Desktop', 'the listener\'s certificate', None,
                  'acme-agent allow rdp',
                  needs=win_needs(pol, {'rdp': True}) if pol is not None else None)
        for f in args['files']:
            if not f['path']:
                continue                    # the store's PKCS#12: never written
            d = f['path'].rsplit('\\', 1)[0] or f['path']
            judge('key' if f.get('agent_key') else 'file',
                  'the key, made there' if f.get('agent_key') else 'file',
                  f['path'], {'files': [f]}, 'acme-agent allow file %s' % cmd_word(d))
        for key, words in (('pre', 'before'), ('test', 'test'), ('reload', 'restart'),
                           ('post', 'after')):
            for o in args[key]:
                judge(key, words, op_words(o), {key: [o]}, allow_of(o))
        if args['script']:
            s = args['script']
            if s['mode'] == 'inline':
                h = hashlib.sha256(s['body'].encode('utf-8')).hexdigest()
                judge('script', 'the script written here', 'sha256 %s…' % h[:16], {'script': s},
                      'acme-agent allow script-hash %s' % h)
            else:
                judge('script', 'the script', s['path'], {'script': s},
                      'acme-agent allow script %s' % cmd_word(s['path']))
        for host, port in self.served_places(options)[:5]:
            hp = '%s:%d' % (host, port)
            m = self._mod()
            if pol is None or m is None:
                out['items'].append({'kind': 'probe', 'label': 'test', 'what': hp, 'ok': None,
                                     'allow': 'acme-agent allow probe local'})
                continue
            try:
                h, p = m.split_hostport(hp)
                ok = m.dest_allowed(dict(m.parse_policy(''), **{
                    'probe': list(pol.get('probe') or []),
                    'probe_local': bool(pol.get('probe_local'))}), h, p, 'probe')
            except Exception:                           # noqa: BLE001
                ok = False
            out['items'].append({'kind': 'probe', 'label': 'test', 'what': hp, 'ok': ok,
                                 'allow': '' if ok else 'acme-agent allow probe local'})
        return out
