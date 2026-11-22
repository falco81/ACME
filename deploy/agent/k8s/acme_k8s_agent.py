#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
acme-agent for Kubernetes (1.0.138, docs/agent-fleet.md "Kubernetes"): acme-agent in a pod of
its own that writes `kubernetes.io/tls` Secrets - and restarts a Deployment that uses one - only
in the namespaces and under the names its policy allows. For clusters without cert-manager.

It IS acme-agent (deploy/agent/acme_agent.py, imported - not a copy): the same protocol, the same
join (`acme-k8s-agent join CODE`, or the code in ACME_AGENT_JOIN_CODE on the first start), the
same enrollment codes, the same signed jobs (Ed25519, a nonce, the time, the agent's id) and the
same sealing of keys to the agent (X25519 + AES-256-GCM), both modes (passive: acme connects to
the pod's port; active: the pod connects to acme). What differs is only what a deployment does:

    a file /k8s/NAMESPACE/NAME/tls.crt   ->  the Secret NAMESPACE/NAME, key tls.crt
    a file /k8s/NAMESPACE/NAME/tls.key   ->  ...its tls.key (sealed to the agent until here)
    a file /k8s/NAMESPACE/NAME/ca.crt    ->  ...its ca.crt
    kubectl rollout restart deployment/D -n NAMESPACE   ->  the Deployment D restarted (its pod
                                             template annotated, as kubectl does)

The policy is a file the cluster's administrator writes - a ConfigMap mounted read-only into the
pod (/etc/acme-agent-k8s/policy); acme can never change it, and the ServiceAccount's RBAC lets the
pod touch nothing else (deploy/agent/k8s/manifests.yaml):

    allow secret NAMESPACE/NAME     the Secret NAME in NAMESPACE (NAME * : any Secret there)
    allow restart NAMESPACE/NAME    the Deployment NAME in NAMESPACE may be restarted
    allow discover                  acme may list the TLS Secrets of the namespaces named above
                                    (read-only: only each certificate's facts - never a key)
    allow from ADDRESS[/BITS]       passive: acme only from there
    allow issuer sha256=HEX         what goes into a Secret chains to this CA (1.0.140, repeatable)
    allow names NAME [NAME...]      every name of it is one of these (*.example.com: one label)
    limit files N | limit size B    as acme-agent's

acme is told this policy as acme-agent's own (a folder /k8s/NAMESPACE/NAME, a test line
`kubectl rollout restart ...`), so a deployment's form says, before it runs, what the policy
allows - green, red with the line to add.

    acme-k8s-agent serve            both sides in this pod (never as root)
    acme-k8s-agent join CODE [--listen ADDRESS] [--no-wait]
    acme-k8s-agent policy [show]    the policy as acme-agent's lines, and what was not read
    acme-k8s-agent status | fingerprint | version
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import re
import secrets
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

# the pod's places (a volume of its own for the state; the policy a ConfigMap, read-only) -
# set before acme_agent reads them
_BASE = os.environ.get('ACME_K8S_STATE') or '/var/lib/acme-agent'
os.environ.setdefault('ACME_AGENT_ETC', os.path.join(_BASE, 'etc'))
os.environ.setdefault('ACME_AGENT_STATE', os.path.join(_BASE, 'net'))
os.environ.setdefault('ACME_AGENT_ROOT_STATE', os.path.join(_BASE, 'work'))
os.environ.setdefault('ACME_AGENT_RUN', os.environ.get('ACME_K8S_RUN') or '/run/acme-agent')

_HERE = os.path.dirname(os.path.realpath(__file__))
for _p in (_HERE, os.path.dirname(_HERE)):
    if os.path.exists(os.path.join(_p, 'acme_agent.py')):
        if _p not in sys.path:
            sys.path.insert(0, _p)
        break
import acme_agent as A  # noqa: E402  (the agent itself: protocol, join, sealing, network side)

POLICY_FILE = os.environ.get('ACME_K8S_POLICY') or '/etc/acme-agent-k8s/policy'
SA_DIR = '/var/run/secrets/kubernetes.io/serviceaccount'
PREFIX = '/k8s'
NS_RE = re.compile(r'[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?\Z')
NAME_RE = re.compile(r'[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?\Z')
PATH_RE = re.compile(r'/k8s/([a-z0-9][-a-z0-9]{0,62})/([a-z0-9][-a-z0-9.]{0,252})/'
                     r'(tls\.crt|tls\.key|ca\.crt)\Z')
KEYS = {'tls.crt': ('cert-pem', 'fullchain-pem'), 'tls.key': ('key-pem', 'key-traditional',
                                                             'key-rsa'),
        'ca.crt': ('chain-pem', 'cert-pem', 'fullchain-pem')}
KUBECTL = ('kubectl', '/usr/bin/kubectl', '/usr/local/bin/kubectl')
DEPLOY_WORDS = ('deployment', 'deployments', 'deploy', 'deployment.apps', 'deployments.apps')
API_S = 20
MANAGED_BY = 'acme-agent'
RESTARTED = 'kubectl.kubernetes.io/restartedAt'
CERT_SHA = 'acme-agent/certificate-sha256'


# ---- the policy ---------------------------------------------------------------------------------
def _pair(word, what):
    if '/' not in str(word):
        raise A.Refused('allow %s NAMESPACE/NAME' % what)
    ns, name = str(word).split('/', 1)
    if not NS_RE.match(ns):
        raise A.Refused('%r is not a namespace (lowercase letters, digits, -)' % ns[:80])
    if what == 'secret' and name == '*':
        return ns, '*'
    if not NAME_RE.match(name):
        raise A.Refused('%r is not a name of Kubernetes (lowercase letters, digits, - and .)'
                        % name[:120])
    return ns, name


def parse(text):
    """The policy file -> {secrets, restarts, discover, from, limits, problems}: a line not
    read is left out and said, as acme-agent's."""
    kp = {'secrets': [], 'restarts': [], 'discover': False, 'from': [],
          'limits': {'files': A.FILES_MOST, 'size': A.FILE_MOST}, 'problems': [],
          'issuers': [], 'names': []}
    for n, raw in enumerate(str(text or '').splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        w = line.split()
        try:
            if w[:2] == ['allow', 'secret'] and len(w) == 3:
                p = _pair(w[2], 'secret')
                if p not in kp['secrets']:
                    kp['secrets'].append(p)
            elif w[:2] == ['allow', 'restart'] and len(w) == 3:
                p = _pair(w[2], 'restart')
                if p not in kp['restarts']:
                    kp['restarts'].append(p)
            elif w == ['allow', 'discover']:
                kp['discover'] = True
            elif w[:2] in (['allow', 'issuer'], ['allow', 'names']):
                # 1.0.140 (A1): what a deployment writes into a Secret, checked here first
                one = A.parse_policy(line)
                if one['problems']:
                    raise A.Refused(one['problems'][0].split(': ', 1)[-1])
                for k in ('issuers', 'names'):
                    kp[k] += [x for x in one.get(k) or [] if x not in kp[k]]
            elif w[:1] == ['require']:
                raise A.Refused('the Kubernetes agent makes no key (every key comes from acme) - '
                                'require key local cannot hold here')
            elif w[:2] == ['allow', 'from'] or w[:1] == ['limit']:
                one = A.parse_policy(line)
                if one['problems']:
                    raise A.Refused(one['problems'][0].split(': ', 1)[-1])
                kp['from'] += [x for x in one['from'] if x not in kp['from']]
                if w[:1] == ['limit']:
                    kp['limits'][w[1]] = one['limits'][w[1]]
            else:
                raise A.Refused('allow secret NAMESPACE/NAME | allow restart NAMESPACE/NAME | '
                                'allow discover | allow from ADDRESS | limit files|size N')
        except A.Refused as e:
            kp['problems'].append('line %d: %s' % (n, e))
    return kp


def policy_text():
    """(the text or '', the problem or ''): the ConfigMap's file - one the agent itself cannot
    change (mounted read-only; as root - never in a pod - only a file of root's, not writable by
    others), at most acme-agent's size."""
    try:
        real = os.path.realpath(POLICY_FILE)
        st = os.stat(real)
    except FileNotFoundError:
        return '', ''
    except OSError as e:
        return '', '%s cannot be read (%s) - nothing is allowed' % (POLICY_FILE, e)
    import stat as _st
    if not _st.S_ISREG(st.st_mode):
        return '', '%s is not a plain file - nothing is allowed' % POLICY_FILE
    if os.getuid() == 0:
        if st.st_uid != 0 or st.st_mode & 0o022:
            return '', '%s may be written by somebody else than root - nothing is allowed' % (
                POLICY_FILE)
    elif os.access(real, os.W_OK):
        return '', '%s may be written by the agent itself - mount it read-only (a ConfigMap) - ' \
                   'nothing is allowed' % POLICY_FILE
    if st.st_size > A.POLICY_MOST:
        return '', '%s is bigger than %d bytes - nothing is allowed' % (POLICY_FILE,
                                                                        A.POLICY_MOST)
    with open(real, encoding='utf-8', errors='replace') as f:
        return f.read(A.POLICY_MOST + 1), ''


def load():
    text, problem = policy_text()
    kp = parse(text)
    if problem:
        kp = parse('')
        kp['problems'].append(problem)
    return kp


def as_agent(kp):
    """The policy as acme-agent's own - what acme reasons with: a folder per Secret (/k8s/NS/NAME,
    /k8s/NS for NS/*), a test line per Deployment that may be restarted."""
    pol = A.parse_policy('')
    for ns, name in kp['secrets']:
        pol['files'].append({'dir': '%s/%s' % (PREFIX, ns) + ('' if name == '*' else '/' + name),
                             'owner': 'root', 'group': 'root', 'mode': 0o644})
    for ns, name in kp['restarts']:
        pol['tests'].append(['kubectl', 'rollout', 'restart', 'deployment/%s' % name, '-n', ns])
    pol['from'] = list(kp['from'])
    pol['limits'] = dict(kp['limits'])
    if kp['discover']:
        pol['discover'] = ['*']
    for k in ('issuers', 'names'):                      # 1.0.140 (A1)
        if kp.get(k):
            pol[k] = list(kp[k])
    pol['problems'] = list(kp['problems'])
    return pol


def canon(kp):
    keep = {k: kp[k] for k in ('secrets', 'restarts', 'discover', 'from', 'limits')}
    for k in ('issuers', 'names'):                      # 1.0.140: only when used (its hash)
        if kp.get(k):
            keep[k] = kp[k]
    return json.dumps(keep, sort_keys=True, separators=(',', ':'))


def policy_load():
    """acme_agent's policy_load, for this pod: (acme-agent's policy, its hash, the text)."""
    kp = load()
    pol = as_agent(kp)
    return pol, A._sha('k8s:' + canon(kp)), policy_text()[0]


def lines(kp):
    out = ['allow secret %s/%s' % p for p in kp['secrets']]
    out += ['allow restart %s/%s' % p for p in kp['restarts']]
    if kp['discover']:
        out.append('allow discover')
    out += ['allow from %s' % x for x in kp['from']]
    out += A.guard_lines({'issuers': kp.get('issuers'), 'names': kp.get('names')})
    if kp['limits']['files'] != A.FILES_MOST:
        out.append('limit files %d' % kp['limits']['files'])
    if kp['limits']['size'] != A.FILE_MOST:
        out.append('limit size %d' % kp['limits']['size'])
    return out


def secret_allowed(kp, ns, name):
    return (ns, name) in kp['secrets'] or (ns, '*') in kp['secrets']


# ---- the Kubernetes API (the pod's ServiceAccount) -------------------------------------------
class KubeError(Exception):
    def __init__(self, status, words):
        Exception.__init__(self, words)
        self.status = status


class Kube(object):
    """The API server, as the pod's ServiceAccount: its token (read anew each time - it is
    rotated), the cluster's CA. ACME_K8S_API names another (the tests' fake one)."""

    def __init__(self):
        host, port = os.environ.get('KUBERNETES_SERVICE_HOST'), \
            os.environ.get('KUBERNETES_SERVICE_PORT') or '443'
        self.base = (os.environ.get('ACME_K8S_API') or
                     ('https://%s:%s' % ('[%s]' % host if host and ':' in host else host, port)
                      if host else '')).rstrip('/')
        self.token_file = os.environ.get('ACME_K8S_TOKEN_FILE') or os.path.join(SA_DIR, 'token')
        self.ca_file = os.environ.get('ACME_K8S_CA_FILE') or os.path.join(SA_DIR, 'ca.crt')

    def ctx(self):
        c = ssl.create_default_context(cafile=self.ca_file if os.path.exists(self.ca_file)
                                       else None)
        c.minimum_version = ssl.TLSVersion.TLSv1_2
        return c

    def req(self, method, path, body=None, ctype='application/json', ok404=False):
        if not self.base:
            raise KubeError(0, 'no Kubernetes API here (KUBERNETES_SERVICE_HOST is not set)')
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method)
        r.add_header('Accept', 'application/json')
        if data is not None:
            r.add_header('Content-Type', ctype)
        try:
            with open(self.token_file) as f:
                tok = f.read().strip()
            if tok:
                r.add_header('Authorization', 'Bearer ' + tok)
        except OSError:
            pass
        try:
            kw = {'context': self.ctx()} if self.base.startswith('https:') else {}
            with urllib.request.urlopen(r, timeout=API_S, **kw) as resp:
                raw = resp.read(A.BODY_MOST + 1)
                return resp.status, json.loads(raw or b'{}')
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return 404, None
            try:
                msg = json.loads(e.read(65536) or b'{}').get('message') or ''
            except (ValueError, AttributeError):
                msg = ''
            raise KubeError(e.code, 'the Kubernetes API said %d%s' % (
                e.code, (': ' + str(msg)[:300]) if msg else ''))
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise KubeError(0, 'the Kubernetes API cannot be reached: %s' % str(e)[:300])

    def secret(self, ns, name):
        return self.req('GET', '/api/v1/namespaces/%s/secrets/%s' % (ns, name), ok404=True)[1]

    def secrets_tls(self, ns):
        q = urllib.parse.urlencode({'fieldSelector': 'type=kubernetes.io/tls'})
        got = self.req('GET', '/api/v1/namespaces/%s/secrets?%s' % (ns, q))[1] or {}
        return got.get('items') or []

    def put_secret(self, ns, name, obj):
        return self.req('PUT', '/api/v1/namespaces/%s/secrets/%s' % (ns, name), obj)[1]

    def create_secret(self, ns, obj):
        return self.req('POST', '/api/v1/namespaces/%s/secrets' % ns, obj)[1]

    def delete_secret(self, ns, name):
        return self.req('DELETE', '/api/v1/namespaces/%s/secrets/%s' % (ns, name), ok404=True)

    def restart(self, ns, name, sha):
        when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        patch = {'spec': {'template': {'metadata': {'annotations': {RESTARTED: when,
                                                                    CERT_SHA: sha}}}}}
        return self.req('PATCH', '/apis/apps/v1/namespaces/%s/deployments/%s' % (ns, name), patch,
                        ctype='application/strategic-merge-patch+json')[1]

    def version(self):
        try:
            return (self.req('GET', '/version')[1] or {}).get('gitVersion') or ''
        except KubeError:
            return ''


KUBE = Kube()


def restart_of(op):
    """`kubectl rollout restart deployment/NAME -n NS` (an operation acme sends) -> (NS, NAME)."""
    argv = list(op.get('argv') or []) if isinstance(op, dict) else []
    if len(argv) < 4 or argv[0] not in KUBECTL or argv[1:3] != ['rollout', 'restart']:
        return None
    ns, what, rest = '', '', argv[3:]
    i = 0
    while i < len(rest):
        w = rest[i]
        if w in ('-n', '--namespace') and i + 1 < len(rest):
            ns = rest[i + 1]
            i += 2
            continue
        if w.startswith('--namespace='):
            ns = w.split('=', 1)[1]
        elif what == '' and '/' in w:
            what = w
        else:
            return None
        i += 1
    if not what or not ns:
        return None
    kind, _, name = what.partition('/')
    if kind not in DEPLOY_WORDS or not NS_RE.match(ns) or not NAME_RE.match(name):
        return None
    return ns, name


def _restart_words(ns, name):
    return 'allow restart %s/%s' % (ns, name)


# ---- the root side, in this pod --------------------------------------------------------------
class K8sRoot(A.Root):
    """acme_agent's root side (every job's signature, nonce, time and agent checked as there),
    with what a deployment does in a cluster."""

    @staticmethod
    def conf():
        # one account in the pod: what the join pinned is the pod's own (its volume)
        c = A._json(A.CONF, {})
        return c if isinstance(c, dict) else {}

    def status(self):
        pol, h, _t = policy_load()
        c = self.conf()
        k = self.enc_key()
        return {'version': A.VERSION, 'code': A.CODE, 'policy': self.report(pol, h),
                'agent_id': c.get('agent_id') or '', 'joined': bool(c.get('joined')),
                'enc_pub': A._b64(A.x25519_public(k)) if k else ''}

    @staticmethod
    def report(pol, h):
        out = A.policy_report(pol, h)
        kp = load()
        out['k8s'] = {'secrets': ['%s/%s' % p for p in kp['secrets']],
                      'restarts': ['%s/%s' % p for p in kp['restarts']]}
        return out

    def op_hello(self, args, job, msg):
        out = super(K8sRoot, self).op_hello(args, job, msg)
        out['policy'] = self.status()['policy']
        # hunt R f1: no audit chain in a pod (its policy has no `audit chain` line) - it said it
        # had one, and acme's card asked for `acme-agent audit on` there
        out['features'] = [f for f in out.get('features') or [] if f != 'audit-chain']
        ver = KUBE.version()
        ns = ''
        try:
            with open(os.path.join(SA_DIR, 'namespace')) as f:
                ns = f.read().strip()[:63]
        except OSError:
            pass
        out['os'] = ('Kubernetes %s' % ver).strip() + (' (namespace %s)' % ns if ns else '')
        out['host'] = (os.environ.get('ACME_K8S_CLUSTER') or socket.gethostname())[:120]
        return out

    def op_keygen(self, args, job, msg):
        raise A.Refused('the Kubernetes agent takes the key acme makes (sealed to this agent) - '
                        'choose the key made by acme for this certificate')

    def op_update(self, args, job, msg):
        raise A.Refused('the Kubernetes agent is updated with its image (deploy/agent/k8s), '
                        'never by acme', [{'kind': 'self-update', 'what': 'the image',
                                           'allow': 'kubectl set image deployment/acme-agent'}])

    def op_fingerprints(self, args, job, msg):
        kp = load()
        out = []
        for p in (args.get('paths') or [])[:200]:
            m = PATH_RE.match(str(p or ''))
            if not m or not secret_allowed(kp, m.group(1), m.group(2)):
                out.append({'path': str(p)[:300], 'sha256': None,
                            'said': 'not a Secret the policy allows'})
                continue
            try:
                s = KUBE.secret(m.group(1), m.group(2))
            except KubeError as e:
                out.append({'path': p, 'sha256': None, 'said': str(e)})
                continue
            v = ((s or {}).get('data') or {}).get(m.group(3))
            out.append({'path': p, 'sha256': A._sha(base64.b64decode(v)) if v else None})
        return {'ok': True, 'files': out}

    def op_check(self, args, job, msg):
        pol, h, _t = policy_load()
        try:
            plan = plan_of(load(), args, need_data=False)
        except A.Refused as e:
            return {'ok': False, 'refused': True, 'said': str(e), 'needs': e.needs,
                    'policy_hash': h}
        out = []
        for (ns, name), keys in sorted(plan['secrets'].items()):
            try:
                have = KUBE.secret(ns, name)
            except KubeError as e:
                return {'ok': False, 'said': str(e), 'policy_hash': h}
            for k in sorted(keys):
                out.append({'path': '%s/%s/%s/%s' % (PREFIX, ns, name, k),
                            'said': 'replaces the one in the Secret' if have else
                            'a new Secret is made'})
        return {'ok': True, 'said': 'the policy allows all of it', 'files': out,
                'policy_hash': h}

    def op_deploy(self, args, job, msg):
        with self.work:
            return K8sDeploy(self, args).run()

    def op_discover(self, args, job, msg):
        kp = load()
        h = policy_load()[1]
        if not kp['discover']:
            raise A.Refused('not allowed by the policy of this cluster: a discovery - allow it in '
                            'the agent\'s ConfigMap: allow discover',
                            [{'kind': 'discover', 'what': 'a discovery',
                              'allow': 'allow discover'}])
        got = discover(kp)
        return {'ok': True, 'discover': got, 'policy_hash': h,
                'said': '%d TLS Secret(s) of %d namespace(s)' % (
                    len(got['found']), len({ns for ns, _n in kp['secrets']}))}


def _pem_ok(data, key):
    if key == 'tls.key':
        return b'PRIVATE KEY-----' in data
    return b'-----BEGIN CERTIFICATE-----' in data


def plan_of(kp, args, need_data=True, priv=None, agent_id=''):
    """A deployment's job against this pod's policy: {secrets: {(ns, name): {key: bytes}},
    restarts: [(ns, name)]} - or Refused with what the policy lacks (and its lines), before
    anything is written."""
    needs = []
    files = args.get('files') if isinstance(args.get('files'), list) else []
    if len(files) > kp['limits']['files']:
        raise A.Refused('%d files - the policy allows %d in one deployment' % (
            len(files), kp['limits']['files']))
    plan = {'secrets': {}, 'restarts': []}
    for f in files:
        if not isinstance(f, dict):
            raise A.Refused('a file is an object')
        path = str(f.get('path') or '')
        m = PATH_RE.match(path)
        if not m:
            raise A.Refused('%s is not a place of a Secret - the Kubernetes agent writes '
                            '/k8s/NAMESPACE/NAME/tls.crt, tls.key or ca.crt' % path[:200])
        ns, name, key = m.groups()
        fmt = str(f.get('format') or '')
        if fmt and fmt not in KEYS[key]:
            raise A.Refused('%s takes %s - not %s' % (path, ' or '.join(KEYS[key]), fmt[:30]))
        if f.get('agent_key'):
            raise A.Refused('the Kubernetes agent makes no key - the key comes from acme')
        if not secret_allowed(kp, ns, name):
            needs.append({'kind': 'file', 'what': 'the Secret %s/%s' % (ns, name),
                          'allow': 'allow secret %s/%s' % (ns, name)})
        keys = plan['secrets'].setdefault((ns, name), {})
        if key in keys:
            raise A.Refused('%s twice' % path)
        data = b''
        if need_data:
            if f.get('sealed'):
                if priv is None:
                    raise A.Refused('this agent has no key to open secrets with (join again)')
                data = A.unseal(f['sealed'], priv, agent_id, 'file ' + path)
            else:
                data = A._unb64(f.get('data'), None, path)
            if len(data) > kp['limits']['size']:
                raise A.Refused('%s is %d bytes - the policy allows %d' % (
                    path, len(data), kp['limits']['size']))
            if not _pem_ok(data, key):
                raise A.Refused('%s is not PEM of what a Secret of kubernetes.io/tls holds there'
                                % path)
        keys[key] = data
    for k in ('pre', 'test'):
        if args.get(k):
            raise A.Refused('the Kubernetes agent runs no command %s the files - only a restart '
                            'of a Deployment after them (kubectl rollout restart deployment/NAME '
                            '-n NAMESPACE)' % ('before' if k == 'pre' else 'to test'))
    for k in ('reload', 'post'):
        for op in args.get(k) or []:
            alts = op['any'] if isinstance(op, dict) and 'any' in op else [op]
            r = None
            for a in alts:
                r = restart_of(a)
                if r:
                    break
            if not r:
                raise A.Refused('the Kubernetes agent restarts a Deployment only: kubectl rollout '
                                'restart deployment/NAME -n NAMESPACE')
            if r not in kp['restarts']:
                needs.append({'kind': 'test', 'what': 'a restart of the Deployment %s/%s' % r,
                              'allow': _restart_words(*r)})
            if r not in plan['restarts']:
                plan['restarts'].append(r)
    if args.get('script'):
        raise A.Refused('the Kubernetes agent runs no script')
    for (ns, name), keys in plan['secrets'].items():
        if need_data and ('tls.crt' in keys) != ('tls.key' in keys):
            raise A.Refused('a Secret of kubernetes.io/tls takes its certificate and its key '
                            'together: %s/%s has only %s' % (ns, name, ', '.join(sorted(keys))))
    if needs:
        raise A.Refused('not allowed by the policy of this cluster: %s' % '; '.join(
            n['what'] for n in needs[:6]), needs)
    return plan


class K8sDeploy(object):
    """One deployment: every Secret checked first, written, the Deployments restarted - or the
    Secrets as they were back."""

    def __init__(self, root, args):
        self.root, self.args = root, args
        self.steps = []
        self.agent_id = root.conf().get('agent_id') or ''

    def step(self, words, level='info'):
        self.steps.append([level, str(words)[:600]])

    def run(self):
        kp = load()
        h = policy_load()[1]
        plan = plan_of(kp, self.args, True, self.root.enc_key(), self.agent_id)
        pol = as_agent(kp)
        if A.guard_on(pol):
            # 1.0.140 (A1): what goes into the Secrets checked against allow issuer / allow names
            gd = self.args.get('guard') if isinstance(self.args.get('guard'), dict) else {}
            mats = [('%s/%s/%s/%s' % (PREFIX, ns, name, k), v, '', None)
                    for (ns, name), keys in sorted(plan['secrets'].items())
                    for k, v in sorted(keys.items())]
            pool = [str(x) for x in (gd.get('chain') or [])[:A.GUARD_CERTS_MOST]
                    if isinstance(x, str) and len(x) < 20000]
            self.step(A.guard_check(pol, mats, pool, own=[]), 'ok')
        # every Secret read first: one of another type is refused before anything is written
        have = {}
        for (ns, name) in sorted(plan['secrets']):
            try:
                s = KUBE.secret(ns, name)
            except KubeError as e:
                raise A.Refused('the Secret %s/%s cannot be read: %s' % (ns, name, e))
            if s and s.get('type') not in (None, 'kubernetes.io/tls'):
                raise A.Refused('the Secret %s/%s is of the type %s - not kubernetes.io/tls; '
                                'acme-agent does not change it' % (ns, name, s.get('type')))
            have[(ns, name)] = s
        files, done, changed = [], [], []
        try:
            for (ns, name), keys in sorted(plan['secrets'].items()):
                old = have[(ns, name)]
                data = dict((old or {}).get('data') or {})
                new = {k: base64.b64encode(v).decode('ascii') for k, v in keys.items()}
                for k, v in keys.items():
                    files.append({'path': '%s/%s/%s/%s' % (PREFIX, ns, name, k),
                                  'sha256': A._sha(v)})
                if old and self.args.get('skip_same', True) and \
                        all(data.get(k) == v for k, v in new.items()):
                    self.step('the Secret %s/%s holds it already - left as it is' % (ns, name))
                    continue
                data.update(new)
                when = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                if old:
                    obj = dict(old)
                    meta = dict(obj.get('metadata') or {})
                    ann = dict(meta.get('annotations') or {})
                    ann['acme-agent/updated'] = when
                    meta['annotations'] = ann
                    obj['metadata'] = meta
                    obj['data'] = data
                    obj['type'] = 'kubernetes.io/tls'
                    KUBE.put_secret(ns, name, obj)
                    done.append(('put', ns, name, old))
                    self.step('the Secret %s/%s replaced (%s)' % (ns, name, ', '.join(sorted(
                        keys))), 'ok')
                else:
                    KUBE.create_secret(ns, {
                        'apiVersion': 'v1', 'kind': 'Secret', 'type': 'kubernetes.io/tls',
                        'metadata': {'name': name, 'namespace': ns,
                                     'labels': {'app.kubernetes.io/managed-by': MANAGED_BY},
                                     'annotations': {'acme-agent/updated': when}},
                        'data': data})
                    done.append(('new', ns, name, None))
                    self.step('the Secret %s/%s made (%s)' % (ns, name, ', '.join(sorted(keys))),
                              'ok')
                changed.append((ns, name))
            sha = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()[:16]
            if changed:
                for ns, name in plan['restarts']:
                    KUBE.restart(ns, name, sha)
                    self.step('the Deployment %s/%s restarted (its pods take the new Secret)'
                              % (ns, name), 'ok')
            elif plan['restarts']:
                self.step('nothing changed - no Deployment restarted')
        except KubeError as e:
            self.step(str(e), 'bad')
            self.back(done)
            A.audit(op='deploy', ok=False, said=str(e)[:300])
            return {'ok': False, 'said': 'the cluster refused it: %s - the Secrets as they were '
                                         'are back' % e, 'steps': self.steps, 'files': files,
                    'policy_hash': h}
        A.audit(op='deploy', ok=True, said='%d Secret(s) changed' % len(changed),
                files=[(f['path'], f['sha256']) for f in files][:40])
        if not changed:
            return {'ok': True, 'unchanged': True, 'said': 'every Secret holds it already',
                    'steps': self.steps, 'files': files, 'policy_hash': h,
                    'host': os.environ.get('ACME_K8S_CLUSTER') or ''}
        return {'ok': True, 'said': '%d Secret(s) written%s' % (len(changed), (
            ', %d Deployment(s) restarted' % len(plan['restarts'])) if plan['restarts'] else ''),
            'steps': self.steps, 'files': files, 'policy_hash': h,
            'host': os.environ.get('ACME_K8S_CLUSTER') or ''}

    def back(self, done):
        for how, ns, name, old in reversed(done):
            try:
                if how == 'new':
                    KUBE.delete_secret(ns, name)
                else:
                    o = dict(old)
                    meta = dict(o.get('metadata') or {})
                    meta.pop('resourceVersion', None)
                    o['metadata'] = meta
                    KUBE.put_secret(ns, name, o)
                self.step('the Secret %s/%s as it was is back' % (ns, name), 'warn')
            except KubeError as e:
                self.step('the Secret %s/%s could not be put back: %s' % (ns, name, e), 'bad')


def discover(kp):
    """The TLS Secrets of the namespaces the policy names (NS/*: every one there; NS/NAME: that
    one) - each certificate's facts only: the key is never kept nor said."""
    t0 = time.time()
    found, certs, skipped = [], [], []
    seen = set()
    wanted = {}
    for ns, name in kp['secrets']:
        wanted.setdefault(ns, set()).add(name)
    for ns in sorted(wanted):
        try:
            if '*' in wanted[ns]:
                items = KUBE.secrets_tls(ns)
            else:
                items = [s for s in (KUBE.secret(ns, n) for n in sorted(wanted[ns])) if s]
        except KubeError as e:
            skipped.append({'kind': 'files', 'why': '%s: %s' % (ns, e)})
            continue
        for s in items[:A.DISCOVER_CERTS_MOST]:
            if s.get('type') != 'kubernetes.io/tls':
                continue
            name = str((s.get('metadata') or {}).get('name') or '')
            if (ns, name) in seen or not NAME_RE.match(name):
                continue
            seen.add((ns, name))
            raw = (s.get('data') or {}).get('tls.crt')
            facts = None
            if raw:
                try:
                    pem = base64.b64decode(raw).decode('ascii', 'replace')
                    facts = A.cert_facts(pem)
                except (ValueError, A.Refused):
                    facts = None
            base = '%s/%s/%s' % (PREFIX, ns, name)
            one = {'kind': 'files', 'title': 'Secret %s/%s' % (ns, name),
                   'config': 'secret %s/%s' % (ns, name), 'preset': 'custom',
                   'names': list((facts or {}).get('sans') or [])[:40],
                   'files': [{'role': 'cert', 'format': 'fullchain-pem', 'path': base + '/tls.crt',
                              'there': bool(raw), 'mode': '0644', 'owner': 'root',
                              'group': 'root'},
                             {'role': 'key', 'format': 'key-pem', 'path': base + '/tls.key',
                              'there': 'tls.key' in (s.get('data') or {}), 'mode': '0600',
                              'owner': 'root', 'group': 'root'}],
                   'cert': facts, 'site': '%s/%s' % (ns, name)}
            if facts:
                facts['where'] = ['secret %s/%s' % (ns, name)]
                certs.append(facts)
            found.append(one)
    return {'platform': 'linux', 'kinds': ['files'], 'at': time.time(),
            'ms': int((time.time() - t0) * 1000), 'found': found[:A.DISCOVER_FOUND_MOST],
            'certs': certs[:A.DISCOVER_CERTS_MOST], 'skipped': skipped, 'truncated': False}


# ---- the pod's life ----------------------------------------------------------------------------
def install():
    """acme_agent made the Kubernetes agent: its policy is this pod's."""
    A.policy_load = policy_load
    A.Root = K8sRoot


def places():
    for d in (A.ETC, A.STATE, A.ROOT_STATE, A.RUN):
        os.makedirs(d, mode=0o700, exist_ok=True)


def serve_root(root):
    """The root side's socket - in the pod, only for the pod's own account."""
    try:
        os.unlink(A.SOCK)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        srv.bind(A.SOCK)
    finally:
        os.umask(old)
    srv.listen(16)
    me = os.getuid()
    room = threading.BoundedSemaphore(A.ROOT_THREADS)

    def one(conn):
        try:
            cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
            _pid, uid, _gid = struct.unpack('3i', cred)
            if uid != me:
                A.audit(op='refused', ok=False, said='a connection of uid %d' % uid)
                return
            conn.settimeout(900)
            while True:
                try:
                    msg = A._recv(conn)
                except (EOFError, OSError, ValueError):
                    return
                if not isinstance(msg, dict):
                    return
                A._send(conn, root.handle(msg, uid))
        finally:
            conn.close()
            room.release()

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            if not room.acquire(timeout=30):
                conn.close()
                continue
            threading.Thread(target=one, args=(conn,), daemon=True).start()
    threading.Thread(target=loop, daemon=True, name='acme-agent-root').start()
    return srv


def joined():
    return bool(K8sRoot.conf().get('joined'))


def join(code, listen='', wait=False):
    """acme-agent join, in the pod: a new identity (its TLS key, the key secrets are sealed to),
    the join code's pins - then the network side joins (serve)."""
    c = A.read_code(code)
    places()
    key, crt = A.tls_paths()
    for p in (crt, os.path.join(A.STATE, 'join-status.json'),
              os.path.join(A.STATE, 'joining.crt'), A.CA_FILE):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass
    kpem = A._openssl(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256'])
    A._write(key, kpem, 0o600)
    A._write(os.path.join(A.ROOT_STATE, 'enc.key'), secrets.token_bytes(32).hex(), 0o600)
    A._write(A.CONF, json.dumps({'joined': False}, indent=1), 0o600)
    pins = {'ca': c['ca'], 'ck': c['ck'], 'i': c['i'], 't': c['t'], 'n': c.get('n') or '',
            'm': c['m'], 'p': int(c.get('p') or A.PASSIVE_PORT), 'a': c.get('a') or [],
            'until': time.time() + 3 * 3600}
    if listen:
        pins['listen'] = listen
    j = {'i': c['i'], 's': c['s'], 'm': c['m'], 'a': c.get('a') or [], 'p': pins['p'],
         't': c['t'], 'n': c.get('n') or '', 'ca': c['ca'], 'ck': c['ck'],
         'listen': pins.get('listen') or ''}
    if c.get('e'):
        A.enroll_pins(c, pins, j)
    A._write(os.path.join(A.ROOT_STATE, 'join-pins.json'), json.dumps(pins), 0o600)
    A._write(os.path.join(A.STATE, 'join.json'), json.dumps(j), 0o600)
    fp = A.spki_fp(kpem)
    print('acme-agent (Kubernetes): joining acme as %s (%s mode)' % (
        c.get('n') or c.get('t') or c.get('e'), c['m']))
    print('  The fingerprint of this agent - acme shows the same; confirm it there:')
    print('    %s' % A.fp_words(fp))
    sys.stdout.flush()
    if wait:
        return A.wait_joined(fp)
    return 0


def serve(argv=()):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise SystemExit('acme-k8s-agent serve never runs as root (runAsNonRoot in its pod)')
    install()
    places()
    code = os.environ.get('ACME_AGENT_JOIN_CODE', '').strip()
    if code and not joined() and not os.path.exists(os.path.join(A.STATE, 'join.json')):
        join(code, os.environ.get('ACME_AGENT_LISTEN', ''))
    srv = serve_root(K8sRoot())
    net = A.Net()

    def bye(*_):
        net.stopping = True
        try:
            srv.close()
        except OSError:
            pass
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    A.audit(op='start', ok=True, said='acme-agent %s for Kubernetes' % A.VERSION)
    return A.net_loop(net)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == 'serve':
        return serve(rest)
    if cmd == 'join':
        if not rest:
            raise SystemExit('acme-k8s-agent join CODE [--listen ADDRESS] [--no-wait]')
        listen = ''
        if '--listen' in rest:
            i = rest.index('--listen')
            listen = rest[i + 1] if i + 1 < len(rest) else ''
            if not listen.strip():
                raise SystemExit('acme-k8s-agent join CODE [--listen ADDRESS]')
        install()
        return join(rest[0], listen, wait='--no-wait' not in rest)
    if cmd == 'policy':
        kp = load()
        if '--json' in rest:
            print(json.dumps(K8sRoot.report(*policy_load()[:2]), indent=1))
            return 0
        print('# the policy of this pod (%s)' % POLICY_FILE)
        print('\n'.join(lines(kp)) or '# nothing is allowed: acme can do nothing here')
        for p in kp['problems']:
            print('# NOT READ: %s' % p)
        return 0
    if cmd == 'status':
        install()
        print(json.dumps({'joined': joined(), 'version': A.VERSION,
                          'state': A._json(os.path.join(A.STATE, 'join-status.json'), {})},
                         indent=1))
        return 0
    if cmd == 'fingerprint':
        key, _crt = A.tls_paths()
        if not os.path.exists(key):
            raise SystemExit('acme-k8s-agent: no key yet (join first)')
        print(A.fp_words(A.spki_fp(A._read(key, ''))))
        return 0
    if cmd == 'version':
        print(A.VERSION)
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
