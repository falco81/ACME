# -*- coding: utf-8 -*-
"""
The policy builder of a target with acme-agent (1.0.118, docs/target-agent.md "Designing the
policy"): what the pages' builder starts from, and the design acme keeps of it.

    builder(store, row)     the builder's facts: the agent as acme knows it (its policy, as it
                            last said it), the lists the agent checks a policy with (its own -
                            deploy/agent/acme_agent.py policy_facts), the templates, what each
                            deployment of the target needs of the policy (the needs card's
                            items, as parts of a policy), acme's addresses (allow from), the
                            saved design
    templates()             one click, a coherent set: the folders of the deployment presets
                            (plugins/targets/ssh.py PRESETS - the same paths, owners and modes),
                            the units and tests of "After the files → From a template"
                            (web/assets/deployfiles.js SVC_APPS, mirrored in SVC below)
    design_*                the policy as designed, kept with the target (meta
                            agents:design:<target id>) - documentation only: acme never sends
                            it; the server's root writes it (acme-agent policy apply)

A design is checked as the agent checks a policy file: every line read, none refused.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import time

from acmelib import engine as E
from acmelib.plugins.base import PluginError

DESIGN_TEXT_MOST = 32 * 1024
DESIGN_STATE_MOST = 48 * 1024
DESIGN_KEPT = 10
TITLE_MOST = 120
NOTE_MOST = 2000


def M_DESIGN(tid):
    return 'agents:design:%d' % int(tid)


def _G():
    from acmelib.certs import agents
    return agents


def _txt(v, most):
    return re.sub(r'[\x00-\x08\x0b-\x1f\x7f]', '', str(v if v is not None else ''))[:most]


# ---- templates ---------------------------------------------------------------------------------
# "After the files → From a template" (web/assets/deployfiles.js SVC_APPS): key -> (unit, test,
# reload). test_policybuilder checks this mirror against the page's own table.
SVC = {
    'nginx': ('nginx', 'nginx -t', 'systemctl reload nginx'),
    'httpd': ('httpd', 'apachectl configtest', 'systemctl reload httpd'),
    'apache2': ('apache2', 'apache2ctl configtest', 'systemctl reload apache2'),
    'lighttpd': ('lighttpd', 'lighttpd -tt -f /etc/lighttpd/lighttpd.conf', ''),
    'caddy': ('caddy', 'caddy validate --config /etc/caddy/Caddyfile', 'systemctl reload caddy'),
    'haproxy': ('haproxy', 'haproxy -c -q -f /etc/haproxy/haproxy.cfg',
                'systemctl reload haproxy'),
    'traefik': ('traefik', '', ''),
    'squid': ('squid', 'squid -k parse', 'squid -k reconfigure'),
    'postfix': ('postfix', 'postfix check', 'postfix reload'),
    'dovecot': ('dovecot', 'doveconf -n >/dev/null', 'systemctl reload dovecot'),
    'exim4': ('exim4', 'exim4 -bV >/dev/null', ''),
    'slapd': ('slapd', 'slaptest -u', ''),
    'postgresql': ('postgresql', '', 'systemctl reload postgresql'),
    'mysql': ('mysql', '', 'mysql -e "ALTER INSTANCE RELOAD TLS"'),
    'mariadb': ('mariadb', '', 'mariadb -e "FLUSH SSL"'),
    'pveproxy': ('pveproxy', '', ''),
    'pbs': ('proxmox-backup-proxy', '', 'systemctl reload proxmox-backup-proxy'),
    'webmin': ('webmin', '', ''),
    'cockpit': ('cockpit', '', ''),
    'grafana': ('grafana-server', '', ''),
    'gitlab': ('', '', 'gitlab-ctl hup nginx'),
    'vsftpd': ('vsftpd', '', ''),
    'proftpd': ('proftpd', 'proftpd -t', 'systemctl reload proftpd'),
    'tomcat': ('tomcat', '', ''),
    'mosquitto': ('mosquitto', '', ''),
}

# key, title, group, the deployment preset (its folders, owners, modes, test and reload), the
# template of the commands (SVC), its own folders where no preset has them, more
TEMPLATES = [
    ('nginx', 'nginx', 'Web servers', 'nginx', 'nginx', None,
     {'note': 'The same paths on RHEL and Debian (/etc/nginx/ssl).'}),
    ('httpd', 'Apache httpd (RHEL, Rocky, Alma)', 'Web servers', 'apache', 'httpd', None, {}),
    ('apache2', 'Apache 2 (Debian, Ubuntu)', 'Web servers', 'apache', 'apache2', None, {}),
    ('lighttpd', 'lighttpd', 'Web servers', None, 'lighttpd',
     [('/etc/lighttpd/ssl', 'root', 'root', 0o600)], {}),
    ('caddy', 'Caddy', 'Web servers', None, 'caddy', [('/etc/caddy/certs', 'root', 'caddy', 0o640)],
     {}),
    ('haproxy', 'HAProxy', 'Proxies and load balancers', 'haproxy', 'haproxy', None, {}),
    ('traefik', 'Traefik', 'Proxies and load balancers', None, 'traefik',
     [('/etc/traefik/certs', 'root', 'root', 0o600)],
     {'note': 'A file provider\'s folder is read by itself - the restart only where it is not.'}),
    ('squid', 'Squid', 'Proxies and load balancers', None, 'squid',
     [('/etc/squid/ssl', 'root', 'squid', 0o640)], {}),
    ('postfix', 'Postfix', 'Mail', 'postfix', 'postfix', None, {}),
    ('dovecot', 'Dovecot', 'Mail', 'dovecot', 'dovecot', None, {}),
    ('exim', 'Exim (Debian, exim4)', 'Mail', 'exim', 'exim4', None, {}),
    ('zimbra', 'Zimbra', 'Mail', None, None, [('/opt/zimbra/ssl/acme', 'zimbra', 'zimbra', 0o640)],
     {'scripts': ['/usr/local/sbin/acme-zimbra-deploy.sh'],
      'note': 'zmcertmgr deploycrt runs as zimbra: put it into a script of your own (the path '
              'below), pinned by its SHA-256 on the server.'}),
    ('openldap', 'OpenLDAP (slapd)', 'Directories', 'openldap', 'slapd', None,
     {'note': 'Debian\'s folder; on RHEL it is /etc/openldap/certs.'}),
    ('postgresql', 'PostgreSQL', 'Databases', None, 'postgresql',
     [('/etc/ssl/postgresql', 'root', 'postgres', 0o640)], {}),
    ('mysql', 'MySQL 8', 'Databases', 'mariadb', 'mysql', None, {'service': 'mysql'}),
    ('mariadb', 'MariaDB', 'Databases', 'mariadb', 'mariadb', None, {}),
    ('grafana', 'Grafana', 'Panels and appliances', 'grafana', 'grafana', None, {}),
    ('cockpit', 'Cockpit', 'Panels and appliances', 'cockpit', 'cockpit', None, {}),
    ('webmin', 'Webmin', 'Panels and appliances', 'webmin', 'webmin', None, {}),
    ('proxmox', 'Proxmox VE (pveproxy)', 'Panels and appliances', 'proxmox', 'pveproxy', None, {}),
    ('pbs', 'Proxmox Backup Server', 'Panels and appliances', 'pbs', 'pbs', None, {}),
    ('gitlab', 'GitLab (Omnibus)', 'Panels and appliances', None, 'gitlab',
     [('/etc/gitlab/ssl', 'root', 'root', 0o644)], {}),
    ('mosquitto', 'Mosquitto (MQTT)', 'Application servers', None, 'mosquitto',
     [('/etc/mosquitto/certs', 'root', 'mosquitto', 0o640)], {}),
    ('tomcat', 'Tomcat', 'Application servers', 'tomcat', 'tomcat', None, {}),
    ('vsftpd', 'vsftpd', 'File transfer', 'vsftpd', 'vsftpd', None, {}),
    ('proftpd', 'ProFTPD', 'File transfer', None, 'proftpd',
     [('/etc/proftpd/ssl', 'root', 'root', 0o640)], {}),
    ('docker', 'A Docker container', 'Containers', 'docker', None, None,
     {'note': 'The container is called web - change it to yours (the test line).'}),
    ('systemd', 'Any systemd service', 'Any other', None, None,
     [('/etc/ssl/myservice', 'root', 'root', 0o640)],
     {'units': {'myservice.service': ['reload', 'restart']},
      'note': 'Its unit and its folder are examples - change them to yours.'}),
    ('folder', 'A folder for certificates', 'Any other', None, None,
     [('/etc/ssl/acme', 'root', 'root', 0o644)], {'probe_local': False}),
]


def _unit(name):
    name = str(name)
    return name if '.' in name.rsplit('@', 1)[-1] else name + '.service'


def _add_ops(out, line, service, prefer=''):
    from acmelib.plugins.targets import agent as AT
    try:
        ops = AT.cmd_ops(str(line).replace('{service}', service or ''))
    except PluginError:
        return
    for o in ops:
        alts = o['any'] if 'any' in o else [o]
        # A || B (apache2, else httpd): the alternative of the template's own unit
        mine = [a for a in alts if prefer and _unit(a.get('unit') or '') == _unit(prefer)]
        for a in mine or alts:
            if 'unit' in a:
                vs = out['units'].setdefault(_unit(a['unit']), [])
                if a['verb'] not in vs:
                    vs.append(a['verb'])
            elif 'argv' in a:
                if a['argv'] not in out['tests']:
                    out['tests'].append(a['argv'])
            if 'any' in o:
                break                                   # the first alternative of A || B


def templates():
    """The templates of the builder: folders with owner, group and mode, units with their
    verbs, test command lines, scripts, a test of what the server serves (probe local)."""
    from acmelib.plugins.targets import ssh as SSH
    from acmelib.plugins.targets._common import parse_outputs
    out = []
    for key, title, group, preset, svc, dirs, more in TEMPLATES:
        t = {'key': key, 'title': title, 'group': group, 'note': more.get('note') or '',
             'preset': preset or '', 'files': [], 'units': {}, 'tests': [], 'scripts': [],
             'probe_local': more.get('probe_local', True)}
        p = SSH.PRESETS.get(preset) if preset else None
        service = more.get('service') or (p or {}).get('service') or ''
        if p:
            files = parse_outputs('\n'.join(p.get('outputs') or []), {
                'name': 'NAME', 'cn': 'NAME', 'date': 'DATE', 'service': service, 'host': '',
                'alt': 'rsa'})
            for f in files:
                parts = f['path'].split('/')
                # the deepest folder without a name of the certificate in it ({name}/...)
                keep = []
                for x in parts[:-1]:
                    if 'NAME' in x or 'DATE' in x:
                        break
                    keep.append(x)
                d = '/'.join(keep) or '/'
                u, _, g = (f.get('owner') or 'root:root').partition(':')
                g = g or u
                have = [x for x in t['files'] if x['dir'] == d]
                if have:
                    have[0]['mode'] |= int(f['mode'])
                else:
                    t['files'].append({'dir': d, 'owner': u, 'group': g,
                                       'mode': int(f['mode'])})
            for line in (p.get('test_cmd') or []) + (p.get('reload_cmd') or []):
                _add_ops(t, line, service, SVC[svc][0] if svc else '')
        for d, u, g, m in dirs or []:
            t['files'].append({'dir': d, 'owner': u, 'group': g, 'mode': m})
        if svc:
            unit, test, rel = SVC[svc]
            if test:
                _add_ops(t, test, service)
            if rel.startswith('systemctl '):
                _add_ops(t, rel, service)
            elif rel:
                _add_ops(t, rel, service)               # postfix reload, squid -k reconfigure
            elif unit and not t['units']:
                t['units'][_unit(unit)] = ['restart']   # no reload of its own: restarted
        for u, vs in (more.get('units') or {}).items():
            t['units'][u] = list(vs)
        t['scripts'] = [{'path': s, 'sha256': ''} for s in more.get('scripts') or []]
        out.append(t)
    return out


# ---- what each deployment of the target needs ----------------------------------------------------
def deploy_needs(store, row):
    """Each deployment to the target: what it needs of the policy, as parts of a policy - a
    file (its path, mode, owner), a unit's verb, a command line, a script by its path, a
    script written in acme by its hash, a test of what it serves - with the line that allows
    it. What the agent cannot do at all (a line of a shell) is said as an error."""
    from acmelib.certs import api_deploys, runtime, store as S
    from acmelib.plugins.targets import agent as AT
    out = []
    for dep in store.db.rows('SELECT d.id, d.cert_id, d.enabled, c.name AS cert FROM cert_deploys '
                             'd LEFT JOIN certs c ON c.id = d.cert_id WHERE d.target = ? '
                             'ORDER BY c.name, d.id', (row['name'],))[:60]:
        one = {'id': dep['id'], 'cert': dep.get('cert') or '?',
               'enabled': dep.get('enabled') is None or bool(int(dep.get('enabled') or 0)),
               'items': []}
        out.append(one)
        ctx = None
        try:
            trow, cls, cert, d, opts, _saved = api_deploys._setup(store, {'id': dep['id']}, None)
            bundle = api_deploys._bundle(cert, {}, cls)
            ctx = runtime.RunContext(store, None, scope='target:%s' % trow['name'])
            ctx.target_name = trow['name']
            ctx.deploy_id = dep['id']
            if isinstance(bundle, api_deploys.SampleBundle) and trow['name'] == str(
                    (cert or {}).get('csr_from') or ''):
                bundle.key_pem = None
            t = cls(S.plugin_config('target', trow), ctx)
            r = t.resolved(bundle, opts, partial=True)
            ak = t.agent_key_of(bundle)
            if ak:
                t._key_files(r)
            args = t.plan(bundle, opts, r, [b'' for _ in r['files']], sealed=False, agent_key=ak)
        except Exception as e:                          # noqa: BLE001
            one['error'] = _txt(e, 400)
            continue
        finally:
            if ctx is not None:
                try:
                    ctx.tidy()
                except Exception:                       # noqa: BLE001
                    pass
        items = one['items']
        if len(args['files']) > 20:
            items.append({'kind': 'limit', 'files': len(args['files']),
                          'allow': 'acme-agent limit files %d' % len(args['files'])})
        for f in args['files']:
            u = f['owner'] or ''
            uu, _, gg = u.partition(':')
            d = f['path'].rsplit('/', 1)[0] or '/'
            items.append({'kind': 'file', 'path': f['path'], 'mode': int(f['mode']),
                          'owner': uu, 'group': gg, 'key': bool(f.get('agent_key')),
                          'allow': 'acme-agent allow file %s --owner %s --mode %04o' % (
                              d, (uu or 'root') + ':' + (gg or uu or 'root'), f['mode'])})

        def op_item(o, step):
            if 'unit' in o:
                return {'kind': 'unit', 'unit': _unit(o['unit']), 'verb': o['verb'],
                        'step': step, 'allow': AT._allow_of(o)}
            if 'argv' in o:
                return {'kind': 'test', 'argv': o['argv'], 'step': step,
                        'allow': AT._allow_of(o)}
            return {'kind': 'script', 'path': o.get('script') or '', 'step': step,
                    'allow': AT._allow_of(o)}
        for key in ('pre', 'test', 'reload', 'post'):
            for o in args[key]:
                if 'any' in o:
                    alts = [op_item(a, key) for a in o['any']]
                    items.append({'kind': 'any', 'any': alts, 'step': key,
                                  'allow': alts[0]['allow'] if alts else ''})
                else:
                    items.append(op_item(o, key))
        s = args.get('script')
        if s and s.get('mode') == 'inline':
            h = hashlib.sha256(s['body'].encode('utf-8')).hexdigest()
            items.append({'kind': 'hash', 'hash': h, 'interp': s.get('interp') or '',
                          'allow': 'acme-agent allow script-hash %s' % h})
        elif s and s.get('mode') == 'path':
            items.append({'kind': 'script', 'path': s.get('path') or '', 'step': 'script',
                          'allow': 'acme-agent allow script %s' % (s.get('path') or '')})
        try:
            places = t.served_places(opts)[:5]
        except Exception:                               # noqa: BLE001
            places = []
        for host, port in places:
            local = host in ('127.0.0.1', '::1', 'localhost')
            hp = ('[%s]:%d' % (host, port)) if ':' in str(host) else '%s:%d' % (host, port)
            items.append({'kind': 'probe', 'local': local, 'hp': hp,
                          'allow': 'acme-agent allow probe %s' % ('local' if local else hp)})
    return out


def acme_addresses(store):
    """Where acme connects from (allow from of a passive agent): each node's address."""
    import ipaddress
    out = []
    try:
        if E.CONFIG.get('ha_mode'):
            for n in E.ha_nodes(store):
                out.append(str(n.get('address') or '').split('/')[0])
    except Exception:                                   # noqa: BLE001
        pass
    if not out:
        try:
            out.append(str(E.node_address() or ''))
        except Exception:                               # noqa: BLE001
            pass
    good = []
    for a in out:
        try:
            a = str(ipaddress.ip_address(a.strip('[] ')))
        except ValueError:
            continue
        if a not in good and not a.startswith('127.') and a != '::1':
            good.append(a)
    return good[:8]


def builder(store, row):
    G = _G()
    m = G.agent_mod()
    a = G.info(store, row)
    return {'agent': a, 'facts': m.policy_facts(), 'templates': templates(),
            'needs': deploy_needs(store, row), 'acme_from': acme_addresses(store),
            'design': design_view(store, row, a.get('policy'))}


# ---- the design kept with the target --------------------------------------------------------------
def _canon_lines(m, pol_or_text):
    """The policy as its lines (`acme-agent policy show`): of a policy the agent said, or of
    a file's text - the two compared line by line."""
    if isinstance(pol_or_text, dict):
        p = m.parse_policy('')
        for k in ('files', 'units', 'tests', 'scripts', 'script_hashes', 'from', 'self_update',
                  'connect', 'probe', 'probe_local', 'limits'):
            if pol_or_text.get(k) is not None:
                p[k] = pol_or_text[k]
        return m.policy_lines(p)
    return m.policy_lines(m.parse_policy(pol_or_text or ''))


def compare(design_text, policy):
    """The server's policy (as the agent last said it) against a design: 'matches', 'differs'
    (with the lines only in the design - to apply - and only on the server), 'unknown'."""
    m = _G().agent_mod()
    if not isinstance(policy, dict):
        return {'state': 'unknown', 'added': [], 'removed': []}
    want = _canon_lines(m, design_text)
    have = _canon_lines(m, policy)
    added = [x for x in want if x not in have]
    removed = [x for x in have if x not in want]
    return {'state': 'differs' if added or removed else 'matches', 'added': added,
            'removed': removed,
            'diff': [x for x in difflib.unified_diff(have, want, 'the server', 'the design',
                                                     lineterm='', n=0)
                     if not x.startswith('@@')][:400]}


def _load(store, tid):
    try:
        got = json.loads(store.get_meta(M_DESIGN(tid)) or 'null')
    except (TypeError, ValueError):
        got = None
    return got if isinstance(got, dict) and isinstance(got.get('versions'), list) else \
        {'versions': []}


STATE_KEYS = {'files': list, 'units': list, 'tests': list, 'scripts': list, 'hashes': list,
              'from': list, 'probe': list, 'connect': list, 'probe_local': bool,
              'self_update': bool, 'connect_on': bool, 'limits': dict}


def clean_state(state):
    """The builder's own state, as kept: its known keys of their shapes - nothing else."""
    if not isinstance(state, dict):
        raise ValueError('the builder\'s state is an object')
    out = {}
    for k, t in STATE_KEYS.items():
        v = state.get(k)
        if v is None:
            continue
        if not isinstance(v, t):
            raise ValueError('the builder\'s state: %s is not of its shape' % k)
        out[k] = v
    raw = json.dumps(out, sort_keys=True)
    if len(raw) > DESIGN_STATE_MOST:
        raise ValueError('the builder\'s state is %d bytes at most' % DESIGN_STATE_MOST)
    for f in out.get('files') or []:
        if not isinstance(f, dict) or not isinstance(f.get('dir'), str):
            raise ValueError('the builder\'s state: a folder is {dir, owner, group, mode}')
    return json.loads(raw)


def design_save(store, row, text, state, title, note, by):
    """A design kept with the target - documentation only: acme never sends it. Its text is
    read as the agent reads a policy file: a line it would not read is refused."""
    text = str(text or '')
    if not text.strip():
        raise ValueError('the design has no policy text')
    if len(text.encode('utf-8')) > DESIGN_TEXT_MOST:
        raise ValueError('a design is %d bytes at most' % DESIGN_TEXT_MOST)
    if '\x00' in text:
        raise ValueError('the design holds a NUL byte')
    m = _G().agent_mod()
    got = m.policy_check(text)
    if got['errors']:
        e = got['errors'][0]
        raise ValueError('line %d of the design: %s' % (e['line'], e['words']))
    st = clean_state(state if state is not None else {})
    d = _load(store, row['id'])
    n = max([int(v.get('n') or 0) for v in d['versions']] + [0]) + 1
    v = {'n': n, 'at': time.time(), 'by': _txt(by, 120), 'title': _txt(title, TITLE_MOST).strip(),
         'note': _txt(note, NOTE_MOST).strip() if note is not None else '', 'text': text,
         'state': st, 'hash': hashlib.sha256(text.encode('utf-8')).hexdigest(),
         'entries': len(got['lines']), 'warnings': len(got['warnings'])}
    d['versions'] = (d['versions'] + [v])[-DESIGN_KEPT:]
    store.set_meta(M_DESIGN(row['id']), json.dumps(d, sort_keys=True))
    store.add_event('certificates', 'the policy design of the agent of target %s was saved by %s '
                    '(version %d%s, %d entr%s) - acme never sends it: root applies it on the '
                    'server' % (row['name'], by, n, (': ' + v['title']) if v['title'] else '',
                                v['entries'], 'y' if v['entries'] == 1 else 'ies'), who=by)
    return v


def design_forget(store, row, by):
    d = _load(store, row['id'])
    if not d['versions']:
        raise LookupError('the agent of %s has no saved design' % row['name'])
    store.db.run('DELETE FROM meta WHERE k = ?', (M_DESIGN(row['id']),))
    store.add_event('certificates', 'the policy design of the agent of target %s was deleted by '
                    '%s' % (row['name'], by), 'warn', who=by)


def design_gone(store, row):
    """The target deleted: its design with it."""
    try:
        store.db.run('DELETE FROM meta WHERE k = ?', (M_DESIGN(row['id']),))
    except Exception:                                   # noqa: BLE001
        pass


def design_view(store, row, policy=None):
    """The saved design (the last version) with its history and how the server's policy
    compares - or None."""
    d = _load(store, row['id'])
    if not d['versions']:
        return None
    cur = dict(d['versions'][-1])
    cur['compare'] = compare(cur['text'], policy)
    cur['history'] = [{k: v.get(k) for k in ('n', 'at', 'by', 'title', 'note', 'text', 'state',
                                              'hash', 'entries', 'warnings')}
                      for v in reversed(d['versions'])]
    return cur


def design_summary(store, row, policy=None):
    """For the tiles: the title, when, by whom, and matches / differs / unknown."""
    d = _load(store, row['id'])
    if not d['versions']:
        return None
    cur = d['versions'][-1]
    c = compare(cur['text'], policy)
    return {'n': cur.get('n'), 'title': cur.get('title') or '', 'at': cur.get('at'),
            'by': cur.get('by') or '', 'state': c['state'], 'added': len(c['added']),
            'removed': len(c['removed'])}
