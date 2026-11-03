# -*- coding: utf-8 -*-
"""
What happens: the run plan of a certificate (1.0.20) - everything a renewal
of it would do, step by step, worked out without doing any of it.

    plan(store, cert, deploys, full=False) -> {cert, head, phases, made}

Phases, in the order a renewal goes:

    key         the key (new, kept, or the CSR sent in) and the request
    source      where it comes from: the ACME protocol in order (written here),
                an own authority (written here), any other source as its module's
                own issue() was recorded
    validation  per name, the module's present() / ready() / cleanup() recorded
    deploy      per deployment, the target's deploy() and verify() recorded
    after       who is told, when it comes again, what only the first time does

How a module is recorded (plansandbox.py): its own code is run in a process of
its own that can reach nothing - no socket, no program but openssl, no file
outside its temporary folder, no sleep - against a Context that answers every
call (an HTTP 200 with {}, an SSH command that printed nothing) and writes
each down. It never sees a secret: each secret setting is handed as a
stand-in, masked again on the way out; the certificate is a stand-in of the
same names and key type made there for the run. The answers it had to make
up are marked: what the device answers decides there.

A step: {kind, words, detail?, branch?, note?, invented?, secret?}
    kind     call | connect | file | command | dns | wait | check | key | sign |
             mail | delete | save | info | stop | read
    detail   {method, url, headers, body} | {command, input} |
             {path, mode, owner, size, format, body?} | {record} | {text} |
             {files: [...]} | {pairs: [[label, value]]}
"""
from __future__ import annotations

import base64
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S

RUN_S = 8                       # each module's recording at most
ALL_S = 75                      # the whole recording at most
NAMES_MOST = 8                  # names whose validation is recorded one by one
DOTS = '••••'
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# What the sandbox puts where the CA's answer goes (plansandbox.TOKEN, TXT, KEYAUTH).
SHOWN = (('PLAN-TOKEN-from-the-CA-0000000000.PLANthumbprintOfTheAccountKey00000000000000',
          '‹key authorization: token.thumbprint›'),
         ('PLANTXTvalueComputedFromTheToken0000000000a',
          '‹value computed at the time from the token›'),
         ('PLAN-TOKEN-from-the-CA-0000000000', '‹token from the CA›'),
         ('PLANSESSION0token', '‹session›'))

# Second runs: what a device answers once the certificate is there already.
LATER = {
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/[^/?]+$',
         'body': {'errorcode': 0, 'sslcertkey': [{'certkey': '{TAIL}', 'cert': 'earlier.crt',
                                                  'linkcertkeyname': ''}]}},
        {'method': 'GET', 'url': r'/nitro/v1/config/systemfile\?',
         'body': {'errorcode': 0, 'systemfile': []}},
    ],
}
# What a module needs answered to go on at all (a sign-in's token where it looks for it, a
# zone or domain found) - made up, as every answer of the recording is.
ANSWERS = {
    'f5': [{'method': 'POST', 'url': r'/authn/login', 'body': {'token': {'token': '{SESSION}'}}}],
    'webglobe': [{'method': 'GET', 'url': r'/domains/[^/?]+$',
                  'body': {'success': True, 'data': {'domain': '{TAIL}', 'domain_id': '1001'}}},
                 {'method': 'GET', 'url': r'/\d+/dns$', 'body': {'success': True, 'data': {
                     'records': [], 'soa': {}}}},
                 {'method': 'POST', 'url': r'/\d+/dns$', 'body': {'success': True, 'data': {
                     'id': '\u2039record id\u203a'}}}],
    'cloudflare': [{'method': 'GET', 'url': r'/zones\?name=', 'body': {
        'success': True, 'result': [{'id': '\u2039zone id\u203a', 'name': '{TAIL}'}]}},
        {'method': 'POST', 'url': r'/dns_records$', 'body': {'success': True, 'result': {
            'id': '\u2039record id\u203a'}}},
        {'body': {'success': True, 'result': []}}],
    'synology': [{'url': r'auth', 'body': {'success': True, 'data': {
        'sid': '{SESSION}', 'synotoken': '{SESSION}'}}},
        {'body': {'success': True, 'data': {}}}],
    'cloudflare_ssl': [{'method': 'GET', 'url': r'/zones\?name=', 'body': {
        'success': True, 'result': [{'id': '\u2039zone id\u203a', 'name': 'zone'}]}},
        {'body': {'success': True, 'result': []}}],
    'aws_acm': [{'method': 'POST', 'body': {
        'CertificateArn': 'arn:aws:acm:\u2039region\u203a:\u2039account\u203a:certificate/'
                          '\u2039new\u203a'}}],
}
FIRST = {
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/', 'status': 404,
         'body': {'errorcode': 1540, 'message': 'Certificate does not exist'}},
    ],
}


# ---------------------------------------------------------------------------
# The modules and their secrets
# ---------------------------------------------------------------------------
def _stand_in(n):
    return base64.b64encode(('plansecret%02d' % n).encode()).decode()


class Secrets(object):
    """Every secret of the modules taking part: the real ones (masked out at the
    end) and the stand-ins the recording gets instead."""
    def __init__(self):
        self.real = set()
        self.n = 0

    def stand_ins(self, fields, cfg):
        """cfg with every secret field a stand-in -> (cfg, {stand-in: label})."""
        out, marks = dict(cfg or {}), {}
        for f in fields or []:
            k = f.get('key')
            if not (f.get('type') == 'secret' or f.get('secret')):
                continue
            v = out.get(k)
            if v in (None, ''):
                continue
            self.keep(v)
            self.n += 1
            si = _stand_in(self.n)
            out[k] = si
            marks[si] = str(f.get('label') or k)
        for k, v in list(out.items()):
            if isinstance(v, str) and (v.startswith('sealed:') or '-----BEGIN' in v and
                                       'PRIVATE' in v):
                self.keep(v)
                self.n += 1
                si = _stand_in(self.n)
                out[k] = si
                marks[si] = k
        return out, marks

    def keep(self, v):
        if isinstance(v, (bytes, bytearray)):
            v = v.decode('utf-8', 'replace')
        v = str(v)
        if len(v) >= 4:
            self.real.add(v)
            for line in v.splitlines():
                if len(line.strip()) >= 12:
                    self.real.add(line.strip())


def _cls(family, kind, row=None):
    return S.row_class(family, row, kind) if row else S.plugin_class(family, kind)


def _fields_of(cls, attr='fields'):
    return list(getattr(cls, attr, None) or []) if cls else []


def facts_of(cls, cfg, secrets_set=(), attr='fields'):
    """[[label, value]] of a module's settings as they are: secrets said, never shown."""
    out = []
    seen = set()
    for f in _fields_of(cls, attr):
        k = f.get('key')
        seen.add(k)
        v = (cfg or {}).get(k)
        if f.get('type') == 'secret' or f.get('secret') or k in secrets_set:
            if v not in (None, ''):
                out.append([f.get('label') or k, DOTS + ' (set, not shown)', 'words'])
            continue
        if v in (None, '', []):
            continue
        if f.get('type') == 'bool':
            out.append([f.get('label') or k, 'yes' if v is True or str(v).lower() in (
                '1', 'true', 'yes', 'on') else 'no', 'words'])
            continue
        elif f.get('type') == 'pem':
            out.append([f.get('label') or k, '(a certificate is set)', 'words'])
            continue
        elif f.get('type') == 'select':
            for o in f.get('options') or []:
                if isinstance(o, (list, tuple)) and len(o) >= 2 and str(o[0]) == str(v):
                    v = '%s (%s)' % (o[1], o[0]) if str(o[1]) != str(o[0]) else o[1]
                    break
        elif isinstance(v, list):
            v = '\n'.join(str(x) for x in v)
        out.append([f.get('label') or k, str(v)[:2000]])
    return out


# ---------------------------------------------------------------------------
# The recording
# ---------------------------------------------------------------------------
def record(job, timeout=ALL_S):
    """The sandbox run: plansandbox.main() in a process of its own -> {id: result}."""
    folder = tempfile.mkdtemp(prefix='acme-plan-')
    try:
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': folder,
               'HOME': folder}
        for k in ('ACME_PLAN_TRACE',):
            if os.environ.get(k):
                env[k] = os.environ[k]
        job = dict(job, root=ROOT, folder=folder,
                   plugin_dirs=[d for d in base.REGISTRY.dirs[1:] if os.path.isdir(d)])
        code = ('import sys; sys.path.insert(0, %r); '
                'from acmelib.certs import plansandbox as m; m.main()' % ROOT)
        try:
            got = subprocess.run([sys.executable, '-I', '-c', code],
                                 input=json.dumps(job, default=str).encode('utf-8'),
                                 capture_output=True, timeout=timeout, env=env, cwd=folder,
                                 start_new_session=True)
        except subprocess.TimeoutExpired:
            return {}, 'the recording took more than %d s' % timeout
        if got.returncode != 0:
            tail = got.stderr.decode('utf-8', 'replace').strip().splitlines()[-1:]
            return {}, 'the recording failed: %s' % (' '.join(tail)[:300] or got.returncode)
        try:
            return json.loads(got.stdout.decode('utf-8')).get('runs') or {}, ''
        except ValueError:
            return {}, 'the recording said nothing that can be read'
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _host(url):
    try:
        return urllib.parse.urlsplit(url).netloc or url
    except ValueError:
        return url


def _sig(ev):
    """What one recorded event is, for comparing two runs."""
    k = ev.get('kind')
    if k == 'http':
        u = re.sub(r'[0-9a-f]{8,}|\d{8}', '#', ev.get('url') or '')
        b = ev.get('body')
        keys = ''
        if isinstance(b, dict):
            keys = ','.join(sorted(b))
            inner = next(iter(b.values())) if len(b) == 1 else None
            if isinstance(inner, dict):
                keys += ':' + ','.join(sorted(inner))
        return 'http %s %s %s' % (ev.get('method'), u, keys)
    if k == 'ssh-run':
        return 'run ' + re.sub(r'[0-9a-f]{8,}', '#', ev.get('command') or '')[:200]
    return '%s %s' % (k, re.sub(r'[0-9a-f]{8,}|\d{8}', '#', str(ev.get('path') or '')))


LOGIN = re.compile(r'(/login|/logon|/signin|/sign-in|/auth\b|/authn|/token\b|/oauth|session)',
                   re.I)
LOGOUT = re.compile(r'(logout|logoff|signout)', re.I)


def _cmd(argv):
    return ' '.join(shlex.quote(str(a)) for a in argv)


def steps_of(events, sandbox_err=None, later=None, invented_note=True, proxy_on=False):
    """The recorded events as steps of the plan, in order."""
    out = []
    branch_of = {}
    if later is not None:
        a = [_sig(e) for e in events]
        b = [_sig(e) for e in later]
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        extra = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ('replace', 'delete'):
                for i in range(i1, i2):
                    branch_of[i] = 'first'
            if tag in ('replace', 'insert'):
                extra.append((i2, later[j1:j2]))
        merged = []
        ins = {}
        for at, evs in extra:
            ins.setdefault(at, []).extend(evs)
        for i, ev in enumerate(events):
            for e2 in ins.get(i, []):
                merged.append((e2, 'later'))
            merged.append((ev, branch_of.get(i)))
        for e2 in ins.get(len(events), []):
            merged.append((e2, 'later'))
    else:
        merged = [(e, None) for e in events]
    sub = None
    i = 0
    while i < len(merged):
        ev, br = merged[i]
        k = ev.get('kind')
        st = None
        if k == 'phase':
            sub = ev.get('what')
            if sub == 'verify':
                out.append({'kind': 'head', 'words': 'After it is put in place'})
            elif sub == 'ready':
                out.append({'kind': 'head', 'words': 'Until it can be seen'})
            elif sub == 'cleanup':
                out.append({'kind': 'head', 'words': 'After the CA has looked: taken away again'})
            i += 1
            continue
        if k == 'http':
            url, m = ev.get('url') or '', ev.get('method') or 'GET'
            host = _host(url)
            path = urllib.parse.urlsplit(url).path
            if m == 'POST' and LOGIN.search(path) and not LOGOUT.search(path):
                words, kind = 'Signs in to {0}', 'connect'
            elif LOGOUT.search(path):
                words, kind = 'Signs out of {0}', 'connect'
            elif m == 'GET':
                words, kind = 'Reads from {0}', 'read'
            elif m == 'DELETE':
                words, kind = 'Deletes on {0}', 'delete'
            elif m in ('PUT', 'PATCH'):
                words, kind = 'Changes on {0}', 'call'
            else:
                words, kind = 'Sends a request to {0}', 'call'
            if re.search(r'save|commit|write_mem|saveconfig', url, re.I):
                kind = 'save'
            st = {'kind': kind, 'words': words.replace('{0}', host),
                  'detail': {'method': m, 'url': url, 'headers': ev.get('headers') or {},
                             'body': ev.get('body')}}
            # the request as it goes on the wire (1.0.37): every header, the ones acme
            # and Python add too, and the body as sent - secrets left out by scrub()
            try:
                from acmelib.certs import runtime as _rt
                st['detail']['wire'] = _rt.wire_request(m, url, ev.get('headers') or {},
                                                        ev.get('body'))
            except Exception:                           # noqa: BLE001
                pass
            notes = []
            if not ev.get('verify', True):
                notes.append('the device\'s TLS certificate is not checked')
            if ev.get('client_cert'):
                notes.append('signed in with a client certificate')
            if ev.get('proxy') and proxy_on:
                notes.append('through the proxy of Settings → Proxy')
            if notes:
                st['note'] = '; '.join(notes)
            if m == 'GET' and invented_note and later is None:
                st['invented'] = True
        elif k == 'ssh-open':
            st = {'kind': 'connect', 'words': 'Connects over SSH to {0}'.replace(
                '{0}', '%s@%s:%s' % (ev.get('user'), ev.get('host'), ev.get('port'))),
                'detail': {'pairs': [
                    ['Host', '%s port %s' % (ev.get('host'), ev.get('port'))],
                    ['User', ev.get('user') or ''],
                    ['Signs in with', {'key': 'an SSH key (not shown)',
                                       'password': 'a password (not shown)'}.get(
                                           ev.get('auth'), 'nothing set'), 'words'],
                    ['Host key', ', '.join(ev.get('hostkey') or [])] if ev.get('hostkey') else
                    ['Host key', 'none pinned: the first one seen is trusted and kept'
                     if ev.get('trust_first') else 'none pinned: refused until it is', 'words']]}}
        elif k == 'ssh-run':
            cmd = ev.get('command') or ''
            kind = 'delete' if re.match(r"^(sudo -[nS] (-p '' )?sh -c ')?rm ", cmd) else 'command'
            st = {'kind': kind, 'words': 'Runs a command on {0}'.replace('{0}', ev.get('host') or ''),
                  'detail': {'command': cmd}}
            if ev.get('script'):
                st['detail']['script'] = ev['script']
            if ev.get('input'):
                inp = ev['input']
                st['detail']['input'] = '%s (%s, %d B)' % (
                    DOTS if inp.get('secret') else 'input', inp.get('format') or 'text',
                    inp.get('size') or 0)
            if 'sudo -S' in cmd:
                st['note'] = 'through sudo - its password goes on the command\'s input, not shown'
            elif 'sudo -n' in cmd:
                st['note'] = 'through sudo (it must not ask for a password)'
            if sub == 'ready':
                st['invented'] = True
        elif k == 'ssh-put':
            st = {'kind': 'file', 'words': 'Uploads a file to {0}'.replace('{0}',
                                                                           ev.get('host') or ''),
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'owner': ev.get('owner'), 'size': ev.get('size'),
                             'format': ev.get('format'), 'via': ev.get('via')}}
            if ev.get('body') is not None:
                st['detail']['body'] = ev['body']
            if ev.get('secret'):
                st['secret'] = True
        elif k == 'ssh-get':
            st = {'kind': 'read', 'words': 'Reads a file from {0}'.replace('{0}',
                                                                           ev.get('host') or ''),
                  'detail': {'path': ev.get('path')}, 'invented': True}
        elif k == 'file':
            st = {'kind': 'file', 'words': 'Writes a file on this machine',
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'size': ev.get('size'), 'format': ev.get('format')}}
            if ev.get('body') is not None:
                st['detail']['body'] = ev['body']
            if ev.get('secret'):
                st['secret'] = True
        elif k == 'mkdir':
            if any(o.get('kind') == 'file' and (o.get('detail') or {}).get('path') == ev.get(
                    'path') for o in out) or any(
                    (o.get('detail') or {}).get('mkdir') == ev.get('path') for o in out):
                i += 1
                continue
            st = {'kind': 'file', 'words': 'Makes the folder where it is not there yet',
                  'detail': {'path': ev.get('path'), 'mkdir': ev.get('path')}}
        elif k in ('chmod', 'chown'):
            st = {'kind': 'file', 'words': 'Sets who may read it',
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'owner': ev.get('owner')}}
        elif k == 'delete':
            st = {'kind': 'delete', 'words': 'Deletes on this machine',
                  'detail': {'path': ev.get('path')}}
        elif k == 'move':
            st = {'kind': 'file', 'words': 'Moves a file on this machine',
                  'detail': {'path': ev.get('path'), 'text': '%s → %s' % (ev.get('from'),
                                                                          ev.get('path'))}}
        elif k == 'command':
            st = {'kind': 'command', 'words': 'Runs on this machine',
                  'detail': {'command': _cmd(ev.get('argv') or [])}}
            if ev.get('env'):
                st['note'] = 'with the variables %s' % ', '.join(ev['env'])
        elif k == 'dns-ask':
            servers = [ev.get('server')]
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') == 'dns-ask' and \
                    merged[j][0].get('name') == ev.get('name') and \
                    merged[j][0].get('qtype') == ev.get('qtype'):
                if merged[j][0].get('server') not in servers:
                    servers.append(merged[j][0].get('server'))
                j += 1
            i = j - 1
            port = ev.get('port') or 53
            st = {'kind': 'dns', 'words': 'Asks DNS for the {0} record of {1}'.replace(
                '{0}', ev.get('qtype') or '?').replace('{1}', ev.get('name') or '?'),
                'detail': {'command': '\n'.join('dig %s@%s %s %s' % (
                    '-p %s ' % port if int(port) != 53 else '', s, ev.get('name'),
                    ev.get('qtype')) for s in servers)},
                'invented': True}
        elif k == 'dns-update':
            lines = ['server %s' % ev.get('server'), 'zone %s' % ev.get('zone')]
            for r in ev.get('records') or []:
                if r.get('delete'):
                    lines.append('update delete %s %s%s' % (r['name'], r['type'], (
                        ' "%s"' % r['value']) if r.get('value') else ''))
                else:
                    lines.append('update add %s %s %s "%s"' % (r['name'], r.get('ttl') or 60,
                                                               r['type'], r.get('value') or ''))
            lines.append('send')
            st = {'kind': 'dns', 'words': 'Sends a DNS UPDATE to {0}'.replace(
                '{0}', ev.get('server') or ''), 'detail': {'command': '\n'.join(lines)}}
            if ev.get('tsig'):
                st['note'] = 'signed with its TSIG key (not shown)'
        elif k == 'own-dns':
            st = {'kind': 'dns', 'words': 'Puts the record into acme\'s own DNS server',
                  'detail': {'record': {'name': ev.get('name'), 'type': ev.get('type'),
                                        'value': ev.get('value'), 'ttl': ev.get('ttl')}}}
        elif k == 'own-dns-drop':
            st = {'kind': 'delete', 'words': 'Takes the record out of acme\'s own DNS server',
                  'detail': {'record': {'name': ev.get('name'), 'type': ev.get('type')}}}
        elif k == 'own-http':
            st = {'kind': 'file', 'words': 'Answers the file on this server\'s port 80',
                  'detail': {'path': '/.well-known/acme-challenge/%s' % ev.get('token')}}
        elif k == 'own-http-drop':
            st = {'kind': 'delete', 'words': 'Stops answering the file on port 80',
                  'detail': {'path': '/.well-known/acme-challenge/%s' % ev.get('token')}}
        elif k == 'own-file':
            st = {'kind': 'file', 'words': 'Answers the file on this server\'s port 80',
                  'detail': {'path': 'http://%s%s' % (ev.get('host'), ev.get('path'))}}
        elif k == 'wait':
            secs = float(ev.get('seconds') or 0)
            times = int(ev.get('times') or 1)
            if secs < 0.5:
                i += 1
                continue
            st = {'kind': 'wait', 'words': ('Waits {0} s' if times <= 1 else
                                            'Waits up to {0} s, asking again every {1} s').replace(
                '{0}', '%g' % round(secs)).replace('{1}', '%g' % round(secs / times, 1))}
        elif k == 'check':
            hp = '%s:%s' % (ev.get('host'), ev.get('port'))
            tries = 1
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') in ('check', 'wait', 'say'):
                e2 = merged[j][0]
                if e2.get('kind') == 'check':
                    if '%s:%s' % (e2.get('host'), e2.get('port')) != hp or \
                            (e2.get('only') or '') != (ev.get('only') or ''):
                        break
                    tries += 1
                j += 1
            while i < j - 1 and merged[j - 1][0].get('kind') != 'check':
                j -= 1
            i = j - 1
            fam = {'ec': 'ECDSA', 'ed': 'ECDSA', 'rsa': 'RSA'}.get(ev.get('only') or '')
            st = {'kind': 'check', 'words': ('Checks with a TLS handshake that {0} serves the new '
                                             '{1} certificate' if fam else
                                             'Checks with a TLS handshake that {0} serves the new '
                                             'certificate').replace('{0}', hp).replace('{1}', fam or ''),
                  'detail': {'command': 'openssl s_client -connect %s%s%s </dev/null | openssl '
                             'x509 -noout -fingerprint -sha256' % (
                                 hp, ' -servername %s' % ev['sni'] if ev.get('sni') else '',
                                 ' -cipher a%s' % ('ECDSA' if ev.get('only') in ('ec', 'ed')
                                                   else 'RSA') if ev.get('only') else '')}}
            if tries > 1:
                st['note'] = 'tried up to %d times, a few seconds apart, until it is so' % tries
        elif k == 'pages':
            st = {'kind': 'save', 'words': 'Puts it into acme\'s own pages ({0})'.replace(
                '{0}', ev.get('where') or '')}
        elif k == 'preview':
            files = ev.get('files') or []
            if files:
                st = {'kind': 'file', 'words': 'The files it writes',
                      'detail': {'files': files}}
                out.append(st)
            sc = ev.get('script')
            if sc:
                d = {'pairs': [['Script', sc.get('path')] if sc.get('path') else
                               ['Script', 'written in the deployment (%s)' % (
                                   sc.get('interp') or 'sh'), 'words'],
                               ['Arguments', sc.get('args') or '–'],
                               ['Variables', ', '.join(ev.get('env') or []) or '–']]}
                if sc.get('body'):
                    d['script'] = sc['body']
                out.append({'kind': 'command', 'words': 'The script after the files',
                            'detail': d})
            i += 1
            continue
        if st is not None:
            if br == 'first':
                st['branch'] = 'Only the first time - when it is not there yet'
            elif br == 'later':
                st['branch'] = 'Only at later renewals - when it is there already'
            if sub == 'ready' and st.get('kind') in ('read', 'dns'):
                st['invented'] = True
            out.append(st)
        i += 1
    if sandbox_err:
        out.append({'kind': 'stop', 'words': 'From here on, what it does depends on what it is '
                    'answered', 'note': sandbox_err})
    return out


# ---------------------------------------------------------------------------
# The phases
# ---------------------------------------------------------------------------
def _names(cert):
    v = cert.get('names')
    if isinstance(v, str):
        v = S.jload(v, [])
    return [str(x) for x in (v or [])]


def key_phase(cert, profile, irow, icls):
    steps = []
    given = str(cert.get('csr_given') or '').strip()
    kts = [cert.get('key_type') or 'ec-256'] + ([cert['key_type_alt']] if cert.get(
        'key_type_alt') and not given else [])
    names = _names(cert)
    sans = S.sans_of(names, profile) if names else []
    if given:
        steps.append({'kind': 'key', 'words': 'The CSR that was sent in is used - its key '
                      'stays with whoever made it, acme does not hold it',
                      'detail': {'pairs': [['Names', ', '.join(names)],
                                           ['Subject', ', '.join('%s=%s' % kv for kv in (
                                               profile.get('subject') or {}).items()) or '–']]}})
    else:
        for i, kt in enumerate(kts):
            sealed = cert.get('alt_key_sealed' if i else 'key_sealed')
            if cert.get('reuse_key') and sealed and cert.get('state') != 'revoked':
                words = 'The {0} key it has is kept (sealed in acme\'s database)'
            else:
                words = 'A new {0} key is made here, on this machine'
            st = {'kind': 'key', 'words': words.replace('{0}', kt),
                  'detail': {'command': 'openssl genpkey %s' % (
                      '-algorithm RSA -pkeyopt rsa_keygen_bits:%s' % kt[4:] if kt.startswith(
                          'rsa') else '-algorithm EC -pkeyopt ec_paramgen_curve:P-%s' % kt[3:]
                      if kt.startswith('ec') else '-algorithm ED25519')}}
            if i:
                st['branch'] = 'The twin of a dual certificate: the same names, another key'
            if cert.get('reuse_key') and not sealed:
                st['note'] = 'it keeps this key at the renewals after'
            steps.append(st)
        subj = dict(profile.get('subject') or {})
        pairs = [['Subject', ', '.join('%s=%s' % kv for kv in subj.items()) or
                  'CN=%s' % (names[0] if names else '?')],
                 ['subjectAltName', ', '.join(sans)]]
        if profile.get('eku'):
            pairs.append(['Extended key usage', ', '.join(profile['eku'])])
        if profile.get('must_staple'):
            pairs.append(['OCSP must-staple', 'yes', 'words'])
        if profile.get('days'):
            pairs.append(['Validity asked for', '%s days' % profile['days'], 'words'])
        if profile.get('acme_profile'):
            pairs.append(['ACME profile', profile['acme_profile']])
        steps.append({'kind': 'sign', 'words': 'The request (CSR) is made and signed with that '
                      'key', 'detail': {'pairs': pairs}})
    if icls is not None and getattr(icls, 'makes_key', False):
        steps.append({'kind': 'info', 'words': 'This source makes the key itself and sends it '
                      'with the certificate'})
    return {'key': 'key', 'title': 'Key and request', 'steps': steps}


def acme_steps(store, irow, icls, cfg, cert, names, challenges):
    """The ACME protocol as it goes (RFC 8555), written here - it needs a CA to record."""
    from acmelib.plugins.issuers import _acme_client as ac
    d = str(cfg.get('directory') or 'letsencrypt')
    url = str(cfg.get('directory_url') or '').strip() if d == 'custom' else \
        ac.DIRECTORIES.get(d, '?')
    base_ = url.rsplit('/', 1)[0] if url.endswith('/directory') else url.rstrip('/')
    le = d in ('letsencrypt', 'letsencrypt-staging')

    def ep(name, le_path):
        return base_ + '/acme/' + le_path if le else '‹%s from the directory›' % name
    acct = None
    try:
        from acmelib.certs import runtime
        inst = icls(cfg, runtime.RunContext(store, None, scope='issuer:%s' % irow['name']))
        acct = inst.ctx.kv_get(inst.account_slot(url))
        if isinstance(acct, (str, bytes)):
            acct = json.loads(acct)
    except Exception:                                   # noqa: BLE001
        acct = None
    contacts = cfg.get('contacts') or []
    if isinstance(contacts, str):
        contacts = [x for x in re.split(r'[\s,;]+', contacts) if x]
    jws = {'alg': 'ES256' if str(cfg.get('account_key') or 'ec-256').startswith('ec')
           else 'RS256', 'nonce': '‹from newNonce›'}
    steps = [{'kind': 'read', 'words': 'Reads the CA\'s directory',
              'detail': {'method': 'GET', 'url': url, 'headers': {}, 'body': None}},
             {'kind': 'read', 'words': 'Asks for a nonce (each signed request uses one)',
              'detail': {'method': 'HEAD', 'url': ep('newNonce', 'new-nonce'), 'headers': {},
                         'body': None}}]
    if isinstance(acct, dict) and acct.get('url'):
        steps.append({'kind': 'connect', 'words': 'Uses its ACME account (made before, its key '
                      'sealed in acme\'s database)',
                      'detail': {'pairs': [['Account', acct.get('url')],
                                           ['Contacts', ', '.join(acct.get('contacts') or [])
                                            or '–']]}})
    else:
        body = {'protected': dict(jws, jwk='‹the account\'s public key›',
                                  url=ep('newAccount', 'new-acct')),
                'payload': {'termsOfServiceAgreed': True,
                            'contact': ['mailto:%s' % c for c in contacts]}}
        if cfg.get('eab_kid'):
            body['payload']['externalAccountBinding'] = {
                'protected': {'alg': 'HS256', 'kid': cfg.get('eab_kid'),
                              'url': ep('newAccount', 'new-acct')},
                'payload': '‹the account\'s public key›',
                'signature': DOTS + ' (HMAC with the EAB key)'}
        steps.append({'kind': 'connect', 'words': 'Makes an ACME account at the CA (the first '
                      'time only; its key is made here and kept sealed)',
                      'branch': 'Only the first time - when it is not there yet',
                      'detail': {'method': 'POST', 'url': ep('newAccount', 'new-acct'),
                                 'headers': {'Content-Type': 'application/jose+json'},
                                 'body': body}})
    kid = (acct or {}).get('url') or '‹the account URL›'
    order = {'identifiers': [{'type': 'ip' if re.match(r'^[\d.:]+$', n) else 'dns',
                              'value': n} for n in names]}
    prof = (S.jload(cert.get('profile'), {}) or {}).get('acme_profile') if isinstance(
        cert.get('profile'), str) else (cert.get('profile') or {}).get('acme_profile')
    prof = prof or cfg.get('profile')
    if prof:
        order['profile'] = prof
    if cert.get('cert_pem'):
        order['replaces'] = '‹ARI id of the certificate now (if the CA has ARI)›'
    steps.append({'kind': 'call', 'words': 'Orders the certificate for its names',
                  'detail': {'method': 'POST', 'url': ep('newOrder', 'new-order'),
                             'headers': {'Content-Type': 'application/jose+json'},
                             'body': {'protected': dict(jws, kid=kid,
                                                        url=ep('newOrder', 'new-order')),
                                      'payload': order}}})
    auth_steps = []
    for n in names:
        mod = challenges.get(n) or {}
        kinds = list(mod.get('types') or [])
        pick = 'dns-01' if n.startswith('*.') else next(
            (t for t in kinds if t in ('dns-01', 'http-01', 'dns-persist-01')), 'dns-01')
        auth_steps.append({'kind': 'read', 'words': 'Reads the authorization of {0}'.replace(
            '{0}', n), 'detail': {'method': 'POST', 'url': '‹authorization URL of the '
                                  'order›', 'headers': {}, 'body': {
                                      'protected': dict(jws, kid=kid), 'payload': ''}},
            'note': 'POST-as-GET (an empty payload); if the CA still holds the name as proved, '
                    'nothing below is done for it'})
        auth_steps.append({'kind': 'info', 'words': 'Chooses the {0} challenge, put in place by '
                           '{1}'.replace('{0}', pick).replace('{1}', mod.get('name') or '?'),
                           'note': 'the validation phase below says how'})
    steps += auth_steps
    steps.append({'kind': 'wait', 'words': 'Waits until every proof can be seen (at most {0} s)'
                  .replace('{0}', '%g' % float(cfg.get('wait_ready') or 300))})
    steps.append({'kind': 'call', 'words': 'Tells the CA to check each name',
                  'detail': {'method': 'POST', 'url': '‹challenge URL›', 'headers': {},
                             'body': {'protected': dict(jws, kid=kid), 'payload': {}}}})
    steps.append({'kind': 'wait', 'words': 'Asks again every {0} s until each name is valid (at '
                  'most {1} s)'.replace('{0}', '%g' % float(cfg.get('poll_every') or 5))
                  .replace('{1}', '%g' % float(cfg.get('wait_valid') or 180))})
    steps.append({'kind': 'sign', 'words': 'Finalizes the order with the request (CSR)',
                  'detail': {'method': 'POST', 'url': '‹finalize URL of the order›',
                             'headers': {}, 'body': {'protected': dict(jws, kid=kid),
                                                     'payload': {'csr': '‹the CSR, '
                                                                 'DER, base64url›'}}}})
    steps.append({'kind': 'read', 'words': 'Downloads the certificate and its chain',
                  'detail': {'method': 'POST', 'url': '‹certificate URL of the order›',
                             'headers': {'Accept': 'application/pem-certificate-chain'},
                             'body': {'protected': dict(jws, kid=kid), 'payload': ''}},
                  'note': ('the chain that ends at "%s" is taken where the CA offers several '
                           '(Link: rel="alternate")' % cfg['preferred_chain'])
                  if cfg.get('preferred_chain') else 'the chain the CA sends first'})
    steps.append({'kind': 'read', 'words': 'Afterwards, every 6 hours: asks the CA when to renew '
                  '(ARI, RFC 9773)', 'detail': {'method': 'GET', 'url': '‹renewalInfo from '
                                                'the directory›/‹ARI id›',
                                                'headers': {}, 'body': None}})
    for s in steps:
        if s.get('detail', {}).get('body') and isinstance(s['detail']['body'], dict) and \
                'protected' in s['detail']['body']:
            s['detail']['note_jws'] = True
            s.setdefault('note', 'shown as it is signed (JWS): protected header and payload; '
                                 'the signature is made with the account key')
    pairs = [['CA', ac.DIRECTORY_WORDS.get(d) or d], ['Directory', url],
             ['Account', (acct or {}).get('url')] if (acct or {}).get('url') else
             ['Account', 'made at the first order', 'words'],
             ['Contacts', ', '.join(contacts) or '–']]
    if cfg.get('eab_kid'):
        pairs.append(['EAB key id', cfg['eab_kid']])
    return steps, pairs


def internal_ca_steps(store, cfg, cert, names, profile):
    from acmelib.certs import ca as CA
    pairs, steps = [], []
    try:
        got = CA.ca_get(store, int(cfg['ca']) if str(cfg.get('ca') or '').isdigit()
                        else cfg.get('ca'))
    except Exception as e:                              # noqa: BLE001
        return [{'kind': 'stop', 'words': 'The authority cannot be read', 'note': str(e)}], []
    info = got.get('info') or {}
    pairs += [['Authority', got.get('name')], ['Its subject', info.get('subject') or
                                               got.get('subject_dn') or '?'],
              ['Valid until', time.strftime('%Y-%m-%d', time.gmtime(float(
                  got.get('not_after') or 0)))]]
    days = profile.get('days') or cfg.get('days') or 397
    eku = profile.get('eku') or cfg.get('eku') or ['serverAuth', 'clientAuth']
    if isinstance(eku, str):
        eku = [x for x in re.split(r'[\s,]+', eku) if x]
    ext = [['Validity', '%s days (never past the end of the authority)' % days, 'words'],
           ['Extended key usage', ', '.join(eku)],
           ['subjectAltName', ', '.join(names)]]
    try:
        from acmelib.certs import publish
        v = publish.view(store, got['id'])
        if v.get('crl_url'):
            ext.append(['CRL distribution point', v['crl_url']])
        if v.get('aia_url'):
            ext.append(['Authority information (AIA)', v['aia_url']])
    except Exception:                                   # noqa: BLE001
        pass
    if got.get('ocsp_url'):
        ext.append(['OCSP', got['ocsp_url']])
    steps.append({'kind': 'sign', 'words': 'The authority {0} signs it here, at once - no '
                  'network, no validation'.replace('{0}', got.get('name') or '?'),
                  'detail': {'pairs': ext}})
    steps.append({'kind': 'save', 'words': 'What it signed is written into the authority\'s '
                  'list (for its revocation list)'})
    return steps, pairs


def _hostish(cfg):
    for k in ('host', 'url', 'base', 'api', 'server', 'endpoint', 'address'):
        v = (cfg or {}).get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ''


def persist_steps(store, crow, cfg, names, irow):
    """dns-persist-01 (challenges/dns_persist.py): nothing is put in place at an order;
    the record set once is looked up and - with "Write the record through" and "Write it
    by itself when missing" - written through that validation first."""
    from acmelib.plugins.challenges import dns_persist as DP
    from acmelib.plugins.challenges import _dns as D
    wild = str(cfg.get('wildcard', True)).strip().lower() not in ('0', 'false', 'no', 'off')
    doms = []
    own = [D.norm(x).lstrip('*.') for x in re.split(r'[\s,]+', str(cfg.get('domains') or ''))
           if x.strip()]
    for n in names:
        b = D.norm(n)
        b = b[2:] if b.startswith('*.') else b
        if re.match(r'^[\d.:]+\Z', b):
            continue
        hits = [d for d in own if b == d or b.endswith('.' + d)]
        d = (max(hits, key=len) if hits else D.registrable(b)) if wild else b
        if d not in doms:
            doms.append(d)
    writer = str(cfg.get('writer') or '').strip()
    auto = str(cfg.get('write_missing', True)).strip().lower() not in ('0', 'false', 'no',
                                                                       'off', '')
    acct = '‹the URL of the ACME account›'
    preset = str(S.plugin_config('issuer', irow).get('directory') or '') if irow else ''
    idn = D.norm(cfg.get('issuer_domain') or '') or (DP.ISSUER_DOMAINS.get(preset) or [''])[0] \
        or '‹the CA\'s issuer domain name›'
    value = '%s; accounturi=%s%s' % (idn, acct, '; policy=wildcard' if wild else '')
    steps = [{'kind': 'info', 'words': 'Nothing is put in place at an order: the CA reads the '
              'record set once (if it offers dns-persist-01 in the authorization)'}]
    wrow = S.plugin_row(store, 'challenge', writer) if writer else None
    for d in doms:
        rec = {'name': DP.PREFIX + d, 'type': 'TXT', 'value': value, 'ttl': None}
        steps.append({'kind': 'read', 'words': 'Looks the record up at {0}'.replace(
            '{0}', DP.PREFIX + d), 'detail': {'record': rec}})
        if writer and auto:
            steps.append({'kind': 'dns', 'words': 'Writes it through {0} ({1}) when it is '
                          'missing or not right'.replace('{0}', writer).replace(
                              '{1}', (wrow or {}).get('kind') or '?'),
                          'branch': 'Only when the record is missing or not right',
                          'detail': {'record': rec},
                          'note': 'only a value acme wrote itself is replaced; other TXT '
                                  'records at the name stay'})
        elif writer:
            steps.append({'kind': 'info', 'words': 'Not written at an order: "Write the records '
                          'to DNS" at the validation writes it through {0}'.replace('{0}',
                                                                                    writer)})
        else:
            steps.append({'kind': 'info', 'words': 'Set by hand, once - acme writes nothing'})
    fb = str(cfg.get('fallback') or '').strip()
    steps.append({'kind': 'info', 'words': ('Until the CA offers dns-persist-01: {0} proves the '
                                            'names').replace('{0}', fb) if fb else
                  'No fallback validation: until the CA offers dns-persist-01 nothing can be '
                  'issued'})
    return steps


def plan(store, cert, deploys, full=False):
    """The plan of `cert` (a row of certs, or a draft of one) with `deploys` (rows
    of cert_deploys, or [{target, options}])."""
    t0 = time.time()
    secrets_ = Secrets()
    names = _names(cert)
    profile = cert.get('profile')
    profile = S.jload(profile, {}) if isinstance(profile, str) else dict(profile or {})
    irow = S.plugin_row(store, 'issuer', cert.get('issuer')) if cert.get('issuer') else None
    icls = _cls('issuer', irow.get('kind'), irow) if irow else None
    icfg = S.plugin_config('issuer', irow) if irow else {}
    icfg = S.config_over(icls, icfg, S.cert_over({'profile': profile}, 'issuer'))
    runs = []
    rid = [0]

    def run(**kw):
        rid[0] += 1
        kw['id'] = 'r%d' % rid[0]
        kw.setdefault('seconds', RUN_S)
        runs.append(kw)
        return kw['id']

    # the validations, per name
    needs = bool(icls and icls.needs_challenge_for(icfg))
    chal = {}
    groups = {}
    if needs:
        for n in names:
            which = S.challenge_for(cert, n)
            chal[n] = which
            groups.setdefault(which, []).append(n)
    vinfo = {}
    for which, ns in groups.items():
        crow = S.plugin_row(store, 'challenge', which) if which else None
        ccls = _cls('challenge', crow.get('kind'), crow) if crow else None
        if not crow or not ccls:
            vinfo[which] = {'row': crow, 'cls': ccls, 'runs': []}
            continue
        ccfg = S.config_over(ccls, S.plugin_config('challenge', crow),
                             S.cert_over({'profile': profile}, 'challenge', crow['name']))
        scfg, marks = secrets_.stand_ins(_fields_of(ccls), ccfg)
        vinfo[which] = {'row': crow, 'cls': ccls, 'cfg': ccfg, 'runs': []}
        if crow.get('kind') == 'dns_persist':
            continue                    # nothing put in place per order: persist_steps()
        for n in ns[:NAMES_MOST]:
            vinfo[which]['runs'].append((n, run(family='challenge', kind=crow['kind'],
                                                name=crow['name'], op='challenge', names=[n],
                                                config=scfg, marks=marks,
                                                answers=ANSWERS.get(crow['kind'], []))))
    # the source, where it is not written here
    iid = None
    if irow and icls and irow.get('kind') not in ('acme', 'internal_ca', 'selfsigned'):
        scfg, marks = secrets_.stand_ins(_fields_of(icls), icfg)
        iid = run(family='issuer', kind=irow['kind'], name=irow['name'], op='issue',
                  config=scfg, marks=marks, answers=ANSWERS.get(irow['kind'], []))
    elif icfg:
        secrets_.stand_ins(_fields_of(icls), icfg)
    # the deployments
    dinfo = []
    for dep in deploys or []:
        trow = S.plugin_row(store, 'target', dep.get('target'))
        tcls = _cls('target', trow.get('kind'), trow) if trow else None
        item = {'dep': dep, 'row': trow, 'cls': tcls}
        dinfo.append(item)
        if not trow or not tcls:
            continue
        tcfg = S.plugin_config('target', trow)
        opts = dep.get('_options')
        if opts is None:
            opts = S.deploy_options(store, dep) if dep.get('id') else dict(dep.get('options')
                                                                         or {})
        scfg, marks = secrets_.stand_ins(_fields_of(tcls), tcfg)
        sopts, m2 = secrets_.stand_ins(_fields_of(tcls, 'deploy_fields') + [
            {'key': 'pfx_password', 'type': 'secret', 'label': 'password of the files'}], opts)
        marks.update(m2)
        item.update(cfg=tcfg, opts=opts)
        kw = dict(family='target', kind=trow['kind'], name=trow['name'], op='deploy',
                  config=scfg, options=sopts, marks=marks, deploy_id=dep.get('id'))
        kw['answers'] = FIRST.get(trow['kind'], []) + ANSWERS.get(trow['kind'], [])
        if trow['kind'] in LATER:
            kw['later_answers'] = LATER[trow['kind']] + ANSWERS.get(trow['kind'], [])
        item['run'] = run(**kw)
    # the recording
    resolvers = {}
    try:
        from acmelib.certs import dnssets
        for p in ('validation', 'public', 'targets'):
            r = dnssets.resolver(p, store, None)
            resolvers[p] = [str(x) for x in r] or ['the system\'s resolvers']
    except Exception:                                   # noqa: BLE001
        pass
    chain = S.chain_list(cert.get('chain_pem')) if cert.get('chain_pem') else []
    job = {'settings': S.settings_view(), 'resolvers': resolvers, 'node': E.node_name(),
           'cert': {'name': cert.get('name') or (names[0] if names else 'certificate'),
                    'names': names, 'key_type': cert.get('key_type') or 'ec-256',
                    'key_type_alt': cert.get('key_type_alt') or '',
                    'serial': cert.get('serial'), 'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'), 'version': cert.get('version'),
                    'chain': chain, 'id': cert.get('id'),
                    'ref': cert.get('issuer_ref') or None},
           'runs': runs}
    got, rec_err = record(job) if runs else ({}, '')
    try:
        proxy_on = bool(E.proxy_full('acme'))
    except Exception:                                   # noqa: BLE001
        proxy_on = False

    def result(i):
        return got.get(i) or {'events': [], 'error': rec_err or 'not recorded'}

    phases = []
    # 1. key
    phases.append(key_phase(cert, profile, irow, icls))
    # 2. the source
    src = {'key': 'source', 'title': 'The source', 'steps': []}
    if not irow:
        src['steps'].append({'kind': 'info', 'words': 'It has no source acme asks: it is '
                             'imported, or answered by an outside CA - nothing is ordered'})
    elif not icls:
        src['steps'].append({'kind': 'stop', 'words': 'The module of this source is missing'})
    elif irow['kind'] == 'acme':
        st, pairs = acme_steps(store, irow, icls, icfg, cert, names,
                               {n: {'name': chal.get(n), 'types': list(getattr(
                                   (vinfo.get(chal.get(n)) or {}).get('cls'), 'types', ())
                                   or ())} for n in names})
        src['steps'], src['facts'] = st, pairs
    elif irow['kind'] == 'internal_ca':
        st, pairs = internal_ca_steps(store, icfg, cert, names, profile)
        src['steps'], src['facts'] = st, pairs
    elif irow['kind'] == 'selfsigned':
        src['steps'] = [{'kind': 'sign', 'words': 'It signs itself with its own key, here - '
                         'nothing is asked of anybody'}]
        src['facts'] = facts_of(icls, icfg)
    else:
        r = result(iid)
        src['facts'] = facts_of(icls, icfg)
        src['steps'] = steps_of(r['events'], r.get('error'), proxy_on=proxy_on)
        if not r['events']:
            src['steps'] = [{'kind': 'info', 'words': (icls.description or icls.title)},
                            {'kind': 'stop', 'words': 'The detailed steps could not be worked '
                             'out', 'note': r.get('error') or ''}]
    if irow:
        src['module'] = {'name': irow['name'], 'kind': irow['kind'],
                         'title': (icls.title if icls else irow['kind'])}
    phases.append(src)
    # 3. validation
    val = {'key': 'validation', 'title': 'Validation, per name', 'groups': []}
    if not needs:
        val['steps'] = [{'kind': 'info', 'words': 'This source needs no validation: the names '
                         'are not proved to anybody'}]
    for which, ns in groups.items():
        vi = vinfo.get(which) or {}
        g = {'title': which or 'none', 'names': ns}
        if not vi.get('row'):
            g['steps'] = [{'kind': 'stop', 'words': 'There is no validation for these names'}]
            val['groups'].append(g)
            continue
        cls = vi['cls']
        g['module'] = {'name': vi['row']['name'], 'kind': vi['row']['kind'],
                       'title': cls.title or cls.kind}
        g['facts'] = facts_of(cls, vi['cfg'])
        if vi['row'].get('kind') == 'dns_persist':
            g['steps'] = persist_steps(store, vi['row'], vi['cfg'], ns, irow)
            val['groups'].append(g)
            continue
        g['per_name'] = []
        for n, i in vi['runs']:
            r = result(i)
            steps = steps_of(r['events'], r.get('error'), proxy_on=proxy_on)
            if not r['events']:
                steps = [{'kind': 'info', 'words': cls.description or cls.title},
                         {'kind': 'stop', 'words': 'The detailed steps could not be worked '
                          'out', 'note': r.get('error') or ''}]
            g['per_name'].append({'name': n, 'steps': steps})
        if len(ns) > NAMES_MOST:
            g['more'] = len(ns) - NAMES_MOST
        val['groups'].append(g)
    phases.append(val)
    # 4. deployments
    dp = {'key': 'deploy', 'title': 'Deployments', 'groups': []}
    if not dinfo:
        dp['steps'] = [{'kind': 'info', 'words': 'It is deployed nowhere: it is only kept here'}]
    for item in dinfo:
        dep, trow, cls = item['dep'], item['row'], item['cls']
        g = {'title': dep.get('target') or '?', 'enabled': bool(dep.get('enabled', 1)) and
             str(dep.get('enabled')) not in ('0', 'False')}
        if not trow or not cls:
            g['steps'] = [{'kind': 'stop', 'words': 'There is no such target (or its module '
                           'is missing)'}]
            dp['groups'].append(g)
            continue
        g['module'] = {'name': trow['name'], 'kind': trow['kind'], 'title': cls.title or cls.kind}
        g['host'] = _hostish(item['cfg'])
        g['facts'] = facts_of(cls, item['cfg'])
        g['options'] = facts_of(cls, item['opts'], attr='deploy_fields')
        if not trow.get('enabled', 1):
            g['off'] = True
        r = result(item['run'])
        steps = steps_of(r['events'], r.get('error'), later=r.get('later'), proxy_on=proxy_on)
        if not [s for s in steps if s['kind'] not in ('head', 'stop')]:
            steps = [{'kind': 'info', 'words': cls.description or cls.title},
                     {'kind': 'stop', 'words': 'The detailed steps could not be worked out',
                      'note': r.get('error') or ''}]
        g['steps'] = steps
        dp['groups'].append(g)
    phases.append(dp)
    # 5. the tests of what the servers serve (1.0.32)
    tp = checks_phase(store, cert, names)
    phases.append(tp)
    # 6. after
    phases.append(after_phase(store, cert, irow, dinfo))
    out = {'cert': {'id': cert.get('id'), 'name': cert.get('name'), 'names': names,
                    'key_type': cert.get('key_type') or 'ec-256',
                    'key_type_alt': cert.get('key_type_alt') or '',
                    'state': cert.get('state') or 'new', 'issued': bool(cert.get('cert_pem')),
                    'not_after': cert.get('not_after'), 'draft': not cert.get('id')},
           'head': {'source': src.get('module'),
                    'validations': [g.get('module') for g in val['groups'] if g.get('module')],
                    'deploys': len(dinfo), 'tests': len(tp.get('groups') or [])},
           'phases': phases, 'made': time.time(), 'took_ms': int((time.time() - t0) * 1000),
           'recording': rec_err or ''}
    return scrub(out, secrets_.real)


SECRET_HEADERS = re.compile(r'^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|'
                            r'api-key|x-api-token)$', re.I)


def _test_steps(cls, cfg, names, via=None):
    """What one test does, from its settings - a test only reads, so nothing needs to be
    recorded: the connection, what it says first, TLS, HTTP, the comparison - each as
    it goes on the wire (1.0.37): what is sent before TLS, the ClientHello's settings,
    the HTTP request whole (a header that signs in left out)."""
    full = {f['key']: f.get('default') for f in cls.fields or [] if f.get('key')}
    full.update({k: v for k, v in (cfg or {}).items() if v not in (None, '')})
    cfg = full
    first = next((n for n in names or [] if not str(n).startswith('*.')), '')
    host = str(cfg.get('host') or '').strip() or first or '?'
    port = int(cfg.get('port') or cls.default_port or 0)
    sni = str(cfg.get('sni') or '').strip() or first or host
    steps = []
    fam = {'4': 'IPv4 only', '6': 'IPv6 only'}.get(str(cfg.get('family') or ''), 'whichever the name gives')
    pairs = [['Address', host], ['Port', str(port)], ['Address family', fam, 'words'],
             ['From the address', str(cfg.get('source') or '') or 'as the system chooses',
              'words' if not cfg.get('source') else None],
             ['Time limit', '%s s' % (cfg.get('timeout') or 15)]]
    if via:
        steps.append({'kind': 'connect', 'words': 'From {0}, a connection to {1}:{2} (ssh -W)'
                      .replace('{0}', via).replace('{1}', host).replace('{2}', str(port)),
                      'detail': {'pairs': pairs}})
    else:
        steps.append({'kind': 'connect', 'words': 'Connects to {0}:{1}'.replace(
            '{0}', host).replace('{1}', str(port)), 'note': 'the address set in the test' if
            cfg.get('host') else 'the certificate\'s first name: "Connect to" is empty',
            'detail': {'pairs': pairs}})
    try:
        mod = cls(cfg, None)
    except Exception:                                   # noqa: BLE001
        mod = None
    talk = []
    try:
        talk = mod.talk(host, sni) if mod is not None and hasattr(mod, 'talk') else []
    except Exception:                                   # noqa: BLE001
        talk = []
    if talk or getattr(cls, 'starttls', False):
        text = []
        for t in talk:
            if t.get('send') is not None:
                text.append('→ ' + str(t['send']))
            elif t.get('send_hex'):
                hx = str(t['send_hex'])
                text.append('→ %s (%d bytes)' % (t.get('what') or 'bytes', len(hx) // 2))
                text.append('  ' + ' '.join(hx[i:i + 2] for i in range(0, len(hx), 2)))
            elif t.get('wait'):
                text.append('← waits for ' + str(t['wait']))
        steps.append({'kind': 'call', 'words': 'Speaks {0} first, then asks for TLS'.replace(
            '{0}', cls.protocol or cls.kind), 'note': cls.description or '',
            'detail': {'text': '\n'.join(text)} if text else None})
    want_key = str(cfg.get('key_want') or '').lower()
    tmax = str(cfg.get('tls_max') or '')
    ciphers = str(cfg.get('ciphers') or '')
    if want_key in ('rsa', 'ecdsa', 'both'):
        tmax = tmax if tmax in ('TLSv1', 'TLSv1_1', 'TLSv1_2') else 'TLSv1_2'
    TLSW = {'TLSv1': 'TLS 1.0', 'TLSv1_1': 'TLS 1.1', 'TLSv1_2': 'TLS 1.2', 'TLSv1_3': 'TLS 1.3'}
    tmax = TLSW.get(tmax, tmax)
    cfg = dict(cfg, tls_min=TLSW.get(str(cfg.get('tls_min') or ''), cfg.get('tls_min')))
    kw = {'rsa': 'RSA', 'ecdsa': 'ECDSA', 'both': 'both: once RSA, once ECDSA - two connections'}.get(
        want_key, 'whichever the server picks')
    tls_pairs = [
        ['Name sent (SNI)', '(none)' if sni == '-' else sni],
        ['TLS at least', str(cfg.get('tls_min') or '') or 'as the server and this machine agree',
         None if cfg.get('tls_min') else 'words'],
        ['TLS at most', tmax or 'as the server and this machine agree', None if tmax else 'words'],
        ['Ciphers', ciphers or ({'rsa': 'aRSA (RSA ones only)', 'ecdsa': 'aECDSA (ECDSA ones only)',
                                 'both': 'aRSA, then aECDSA'}.get(want_key) or
                                'what this machine offers'),
         None if ciphers else 'words'],
        ['ALPN', str(cfg.get('alpn') or '') or 'none offered', None if cfg.get('alpn') else 'words'],
        ['Key asked for', kw, 'words'],
        ['The chain', 'checked against this machine\'s CAs, and read whole without that when it '
         'is not trusted here', 'words']]
    steps.append({'kind': 'read', 'words': 'TLS handshake, the name {0} sent as SNI'.replace(
        '{0}', '(none)' if sni == '-' else sni), 'detail': {'pairs': tls_pairs},
        'note': 'twice: once asking for RSA, once for ECDSA' if want_key == 'both' else None})
    if str(cfg.get('http', '')).lower() in ('1', 'true', 'yes', 'on') and hasattr(mod, 'http_lines'):
        try:
            lines, method, path, hosth = mod.http_lines(sni if sni not in ('', '-') else host, port)
        except Exception as e:                          # noqa: BLE001
            lines, method, path, hosth = None, str(cfg.get('method') or 'HEAD'), str(
                cfg.get('path') or '/'), str(cfg.get('host_header') or sni)
            steps.append({'kind': 'stop', 'words': str(e)})
        if lines:
            hdrs = []
            for ln in lines[1:]:
                k, _, v = ln.partition(':')
                v = v.strip()
                if SECRET_HEADERS.match(k.strip()):
                    v = DOTS
                hdrs.append([k.strip(), v, k.strip().lower() in ('user-agent', 'accept', 'connection')
                             and not any(str(h).lower().startswith(k.strip().lower() + ':')
                                         for h in (cfg.get('headers') or []))])
            steps.append({'kind': 'call', 'words': 'Asks {0} {1} with Host: {2}'.replace(
                '{0}', method).replace('{1}', path).replace('{2}', hosth),
                'note': 'the status expected: %s%s' % (cfg.get('expect_status') or 'any', (
                    '; the answer holds "%s"' % cfg['body_contains']) if cfg.get('body_contains')
                    else ''),
                'detail': {'method': method, 'url': 'https://%s%s%s' % (
                    host, '' if port == 443 else ':%d' % port, path),
                    'headers': {h[0]: h[1] for h in hdrs},
                    'wire': {'line': lines[0], 'headers': hdrs, 'body': None}}})
    want = {'current': 'the version deployed now (or its twin)', 'main': 'the main one only',
            'alt': 'the twin only', 'any': 'any version of it'}.get(
        str(cfg.get('expect') or 'current'), 'the version deployed now')
    steps.append({'kind': 'check', 'words': 'The certificate served compared with this one: '
                  '{0}'.replace('{0}', want), 'note': 'its fingerprint, the name %s among its '
                  'names, the chain sent with it, how long it runs%s' % (
                      cfg.get('check_name') or sni, '; it must be trusted here' if str(
                          cfg.get('require_trusted', '')).lower() in ('1', 'true', 'on', 'yes')
                      else '')})
    return steps


def checks_phase(store, cert, names):
    """The tests attached to the certificate: one group each (a connector: the tests it
    carries, from its server), as the deployments are."""
    ph = {'key': 'checks', 'title': 'Tests', 'groups': []}
    rows = store.db.rows('SELECT * FROM cert_checks WHERE cert_id = ? ORDER BY position, id',
                         (cert['id'],)) if cert.get('id') else []
    if not rows:
        ph['steps'] = [{'kind': 'info', 'words': 'No test is attached: what the servers serve '
                        'is not looked at (the certificate → Tests → Attach a test)'}]
        return ph
    after = bool(E.CONFIG.get('certs_checks_after_deploy', 1))
    auto = bool(E.CONFIG.get('certs_checks_auto'))
    for r in rows:
        trow = S.plugin_row(store, 'check', r['test'])
        cls = S.row_class('check', trow) if trow else None
        g = {'title': r['test'], 'enabled': bool(r.get('enabled', 1)) and
             str(r.get('enabled')) not in ('0', 'False')}
        if not trow or not cls:
            g['steps'] = [{'kind': 'stop', 'words': 'There is no such test (or its module is '
                           'missing)'}]
            ph['groups'].append(g)
            continue
        cfg = S.plugin_config('check', trow)
        g['module'] = {'name': trow['name'], 'kind': trow['kind'],
                       'title': cls.title or cls.kind}
        g['facts'] = facts_of(cls, cfg)
        if not trow.get('enabled', 1):
            g['off'] = True
        steps = []
        if getattr(cls, 'composite', False):
            g['host'] = '%s@%s:%s' % (cfg.get('user') or 'root', cfg.get('host') or '?',
                                      cfg.get('port') or 22)
            steps.append({'kind': 'connect', 'words': 'Signs in over SSH to {0}'.replace(
                '{0}', g['host']), 'note': 'with its key or password, as a Linux / Unix (SSH) '
                'target does - nothing is installed there'})
            for mname in cfg.get('tests') or []:
                mrow = S.plugin_row(store, 'check', mname)
                mcls = S.row_class('check', mrow) if mrow else None
                steps.append({'kind': 'head', 'words': mname})
                if not mcls:
                    steps.append({'kind': 'stop', 'words': 'There is no test %s' % mname})
                    continue
                steps += _test_steps(mcls, S.plugin_config('check', mrow), names,
                                     via=str(cfg.get('host') or '?'))
        else:
            mcfg = cfg
            first = next((n for n in names or [] if not str(n).startswith('*.')), '')
            g['host'] = '%s:%s' % (cfg.get('host') or first or '?',
                                   cfg.get('port') or cls.default_port)
            steps += _test_steps(cls, mcfg, names)
        steps.append({'kind': 'wait', 'words': 'When: after the deployments%s' % (
            ', and by themselves every %s min' % E.CONFIG.get('certs_checks_every_min')
            if auto else '') if after else ('by themselves every %s min' % E.CONFIG.get(
                'certs_checks_every_min') if auto else 'only when asked'),
            'note': 'a test that starts failing is an event and a notice (Settings → '
            'Renewal and notices)' if E.CONFIG.get('certs_checks_alert', 1) else
            'no notice is sent when it fails'})
        if r.get('last_at'):
            steps.append({'kind': 'info', 'words': 'Last time: {0}'.replace(
                '{0}', str(r.get('last_said') or r.get('last_state') or '?'))})
        g['steps'] = steps
        ph['groups'].append(g)
    return ph


def after_phase(store, cert, irow, dinfo):
    steps = []
    try:
        from acmelib.certs import notices
        to = notices.recipients(store, cert) if cert.get('id') else \
            [x for x in re.split(r'[\s,;]+', str(E.CONFIG.get('certs_notify_mail') or '')) if x]
        ok = notices.ok_wanted()
    except Exception:                                   # noqa: BLE001
        to, ok = [], False
    if to:
        steps.append({'kind': 'mail', 'words': 'When something fails, a mail goes to {0}'.replace(
            '{0}', ', '.join(to)), 'note': 'and when it went well too' if ok else
            'nothing is sent when it goes well (Settings → Renewal and notices)'})
    else:
        steps.append({'kind': 'mail', 'words': 'Nobody is mailed: no address is set for '
                      'notices (Settings → Renewal and notices)'})
    steps.append({'kind': 'save', 'words': 'Every step is written into the job\'s log, and an '
                  'event (syslog, SIEM) says what was done'})
    days = int(cert.get('renew_days') or E.CONFIG.get('certs_renew_days') or 30)
    auto = cert.get('auto_renew') not in (0, '0', False, None) or not cert.get('id')
    if not auto:
        steps.append({'kind': 'info', 'words': 'It is renewed only when somebody asks - '
                      'nothing repeats by itself'})
    elif cert.get('not_after'):
        at = float(cert['not_after']) - days * 86400
        ari = S.jload(cert.get('ari'), {}) if isinstance(cert.get('ari'), str) else {}
        if ari and ari.get('at'):
            at = min(at, float(ari['at']))
        steps.append({'kind': 'wait', 'words': 'Next renewal: {0}'.replace(
            '{0}', time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(max(at, time.time())))),
            'note': '%d days before the end, or sooner in the window its CA suggests (ARI)'
            % days})
    else:
        steps.append({'kind': 'wait', 'words': 'Issued at the next look (within minutes), or '
                      'at once with Issue now'})
    if auto:
        steps.append({'kind': 'info', 'words': 'At each renewal all of the above repeats - the '
                      'steps marked "only the first time" are not done again'})
        steps.append({'kind': 'info', 'words': 'A deployment that fails is tried again by '
                      'itself: after 5 minutes, then twice as long each time'})
    return {'key': 'after', 'title': 'After', 'steps': steps}


PRIV_RE = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')


def scrub(out, real):
    """The plan as it leaves: every real secret, every private key and every
    stand-in left out once more; the CA's placeholders in words."""
    text = json.dumps(out, ensure_ascii=False, default=str)
    for a, b in SHOWN:
        text = text.replace(a, b)
    for v in sorted(real, key=len, reverse=True):
        for form in {v, json.dumps(v, ensure_ascii=False)[1:-1]}:
            if len(form) >= 6 and form in text:
                text = text.replace(form, DOTS)
            elif form and ('"%s"' % form) in text:
                text = text.replace('"%s"' % form, '"%s"' % DOTS)
    text = re.sub(r'cGxhbnNlY3JldD[A-Za-z0-9+/=]{2,6}', DOTS, text)
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                  DOTS + ' (private key)', text)
    return json.loads(text)
