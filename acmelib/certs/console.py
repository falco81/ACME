# -*- coding: utf-8 -*-
"""
The "Certificates" menu of the console (acme --console), at the top of the
main menu. As every other menu there, it only runs `acme ...` commands of the
command line (acmelib/certs/cli.py) - nothing here can do more than they do,
and what the pages can do, it can do.

    c  Certificates
         1 Browse them (Enter: show, renew, deploy, deployments, edit, export,
                        CSR and its answer, revoke, delete)
         2 Add one                         3 Renew what is due now
         4 Jobs (Enter: followed live)     5 The live log of the certificates
         6 Sources        7 Validations    8 Targets
                          (Enter: show, edit, test, its actions, delete; + add one)
         9 Deployments (Enter: run, edit, switch, delete)
         a Authorities (show, CRL, export, sign a CSR, revoke, delete; new root,
                        new intermediate, import)
         d acme's DNS server (its records: add, delete)
         0 Modules (Enter: what one takes)

A module's form is drawn from its `fields` (acme --plugin KIND --json): a
choice for a select and an on/off, a secret typed as stars and handed over
in the environment (ACME_VALUE_KEY, --set KEY=@env), never on a command line;
a PEM read from a file (@file:PATH).
"""
from __future__ import annotations

import os
import re
import time

FAMS = {'issuer': ('source', 'sources', 'Sources: where certificates come from'),
        'challenge': ('validation', 'validations', 'Validations: how names are proved'),
        'target': ('target', 'targets', 'Targets: where certificates go')}


def main_items(con):
    return [('c', 'Certificates: renewing, deploying, authorities, DNS', lambda: menu(con))]


def _when(ts, fmt='%Y-%m-%d'):
    if not ts:
        return '-'
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)


TONES = {'ok': 'ok', 'failed': 'bad', 'expired': 'bad', 'revoked': 'dim', 'disabled': 'dim',
         'new': 'warn', 'pending': 'warn', 'renewing': 'warn', 'due': 'warn',
         'deploying': 'warn', 'changed': 'warn', 'outdated': 'warn'}


def _tone(r):
    if r.get('days_left') is not None and r['days_left'] < 14 and r.get('state') == 'ok':
        return 'warn'
    return TONES.get(r.get('state') or '', '')


def menu(con):
    def load():
        return con._rows(con.out('--certs'), 'rows')

    cols = [('certificate', lambda r: r.get('name'), 28, None),
            ('state', lambda r: r.get('state') or '', 9, _tone),
            ('left', lambda r: '-' if r.get('days_left') is None else '%d d' % r['days_left'], 6,
             _tone),
            ('issuer', lambda r: r.get('issuer') or '-', 16, None),
            ('names', lambda r: ', '.join(r.get('names') or []), 50, lambda r: 'dim')]
    return con.sub('Certificates', [
        ('1', 'Browse them (Enter: what to do with one)',
         lambda: con.pick('Certificates', load, cols, lambda r: cert_do(con, r),
                          'no certificate yet')),
        ('2', 'Add one', lambda: cert_add(con)),
        ('3', 'Renew every one that is due, now', lambda: con.act('--renew', 'all')),
        ('4', 'Jobs (Enter: every step, live)', lambda: jobs(con)),
        ('5', 'The live log of the certificates', lambda: live_log(con)),
        ('6', FAMS['issuer'][2], lambda: family(con, 'issuer')),
        ('7', FAMS['challenge'][2], lambda: family(con, 'challenge')),
        ('8', FAMS['target'][2], lambda: family(con, 'target')),
        ('9', 'Deployments: which certificate goes where', lambda: deploys(con)),
        ('a', 'Authorities of acme\'s own', lambda: cas(con)),
        ('d', 'acme\'s own DNS server', lambda: dns(con)),
        ('0', 'Modules (Enter: what one takes)', lambda: modules(con)),
    ])


def live_log(con):
    """The daemon's log, only the certificates' lines (and the jobs' steps go
    with Jobs, live)."""
    fn = getattr(con, 'live_log', None)
    if fn is None:
        return con.act('--events', '--search', 'certificates')
    con.live(lambda: fn('certificates'))


# ---------------------------------------------------------------------------
# A module's form, from its fields
# ---------------------------------------------------------------------------
def _norm(v):
    if isinstance(v, bool):
        return '1' if v else '0'
    s = str(v if v is not None else '')
    return {'true': '1', 'false': '0', 'yes': '1', 'no': '0', 'on': '1', 'off': '0'}.get(
        s.lower(), s)


def _shown(f, vals):
    for k, want in (f.get('show_if') or {}).items():
        if _norm(vals.get(k, '')) not in [_norm(x) for x in (want or [])]:
            return False
    return True


def _text_of(f, v):
    if v is None:
        return ''
    if isinstance(v, (list, tuple)):
        return ', '.join(str(x) for x in v)
    if f.get('type') == 'bool':
        return _norm(v)
    return str(v)


def _form_fields(fields, cur, secret_set):
    out = []
    for f in fields:
        t = f.get('type') or 'text'
        have = cur.get(f['key'], f.get('default'))
        one = {'key': f['key'], 'label': (f.get('label') or f['key'])[:28],
               'help': f.get('help') or ''}
        if t == 'select' and f.get('options'):
            opts = [(str(o[0]), str(o[1] if len(o) > 1 else o[0])) for o in f['options']]
            if not f.get('required'):
                opts = [('', '–')] + [o for o in opts if o[0] != '']
            one.update(kind='choice', options=opts, value=_text_of(f, have))
        elif t == 'bool':
            one.update(kind='choice', options=[('1', 'yes'), ('0', 'no')],
                       value=_norm(have if have not in (None, '') else False))
        elif t == 'secret':
            # Typed as stars; the one kept as dots and its last two (root's console).
            one.update(kind='secret', value='',
                       help=('(set: %s - empty keeps it) ' % (
                           have if isinstance(have, str) and have.startswith('\u2022') else
                           '\u2022' * 8) if f['key'] in secret_set else '') + one['help'])
        elif t == 'pem':
            one.update(value='', help='A file on this machine to read it from (or empty to '
                       'keep it as it is). ' + one['help'])
            one['label'] = (f.get('label') or f['key'])[:20] + ' (file)'
        elif t == 'list':
            one.update(value=_text_of(f, have), help='Comma between them. ' + one['help'])
        elif t == 'number':
            one.update(value=_text_of(f, have),
                       check=lambda v, _vals: None if re.match(r'^-?\d+(\.\d+)?\Z', v)
                       else 'a number')
        else:
            one.update(value=_text_of(f, have))
        if f.get('required') and t not in ('secret', 'pem') and \
                f.get('default') in (None, '', []):
            one['need'] = True
        if f.get('show_if'):
            one['when'] = (lambda vals, _f=f: _shown(_f, vals))
        out.append(one)
    return out


def module_form(con, title, fields, cur=None, secret_set=(), words=''):
    """The fields asked for (the main ones, then - when wanted - those under
    "More"). Returns (argv of --set, env) of what changed, or None (Esc)."""
    cur = dict(cur or {})
    main = [f for f in fields if not f.get('advanced')]
    more = [f for f in fields if f.get('advanced')]
    got = {}
    if main:
        g = con.form(title, _form_fields(main, cur, secret_set), words)
        if g is None:
            return None
        got.update(g)
    if more and con.confirm('More', 'Change the settings under "More" too (%s)?' % ', '.join(
            f['key'] for f in more)[:300], 'Yes', 'No'):
        g = con.form(title + ' - more', _form_fields(more, dict(cur, **got), secret_set))
        if g is None:
            return None
        got.update(g)
    argv, env = [], {}
    by_key = {f['key']: f for f in fields}
    for k, v in got.items():
        f = by_key[k]
        t = f.get('type') or 'text'
        if t == 'secret':
            if v:
                env['ACME_VALUE_' + re.sub(r'[^A-Za-z0-9]', '_', k).upper()] = v
                argv += ['--set', '%s=@env' % k]
            continue
        if t == 'pem':
            if v.strip():
                argv += ['--set', '%s=@file:%s' % (k, os.path.expanduser(v.strip()))]
            continue
        if cur:
            # Changed: only what differs from what is set now.
            if v == _text_of(f, cur.get(k, f.get('default'))):
                continue
        elif v == '':
            continue
        if t == 'list':
            v = '\n'.join(x.strip() for x in v.split(',') if x.strip())
        argv += ['--set', '%s=%s' % (k, v)]
    return argv, env


def _plugin(con, fam, kind):
    got = con.out('--plugin', '%s/%s' % (fam, kind)) or {}
    mods = got.get('modules') or []
    return mods[0] if mods else None


# ---------------------------------------------------------------------------
# Sources, validations, targets
# ---------------------------------------------------------------------------
def family(con, fam):
    word, path, title = FAMS[fam]

    def load():
        return [{'name': '+ add a %s' % word, 'kind': '', '_add': True}] + \
            con._rows(con.out('--' + path), 'rows')

    cols = [(word, lambda r: r.get('name') + (' *' if r.get('is_default') else ''), 28,
             lambda r: 'ok' if r.get('_add') else None),
            ('kind', lambda r: r.get('kind'), 14, None),
            ('', lambda r: '' if r.get('_add') else ('on' if r.get('enabled', 1) else 'off'), 3,
             lambda r: '' if r.get('enabled', 1) else 'dim'),
            ('used by', lambda r: '' if r.get('_add') else r.get('used_by'), 7, None),
            ('last error', lambda r: r.get('last_error') or '', 50,
             lambda r: 'bad' if r.get('last_error') else 'dim')]

    def do(r):
        if r.get('_add'):
            return fam_add(con, fam)
        return fam_do(con, fam, r)
    con.pick(title, load, cols, do, 'none yet',
             '* what a new certificate takes when none is said' if fam != 'target' else '')


def fam_add(con, fam):
    word, path, _t = FAMS[fam]
    mods = con._rows(con.out('--plugins'), fam)
    if not mods:
        con.note('No module', 'There is no %s module (acme --plugins).' % word, 'bad')
        return
    kind = con.choose('Which kind of %s' % word, [(d['kind'], '%s  (%s)' % (d['title'], d.get(
        'vendor') or d['kind'])) for d in mods])
    if not kind:
        return
    d = _plugin(con, fam, kind) or {}
    name = con.ask_one('A new %s' % word, 'its name', '', 'What acme calls it - certificates '
                       'and deployments refer to it by this name.')
    if not name:
        return
    got = module_form(con, '%s %s (%s)' % (word, name, kind), d.get('fields') or [],
                      words=d.get('description') or '')
    if got is None:
        return
    argv, env = got
    rc = con.act('--%s-add' % word, name, '--kind', kind, *argv, env=env)
    if rc == 0 and fam != 'target' and con.confirm('Try it', 'Try %s now, changing nothing?'
                                                   % name, 'Try it', 'Later'):
        con.live(lambda: (con.cmd('--%s-test' % word, name), con.pause()))
    elif rc == 0 and fam == 'target' and con.confirm('Try it', 'Reach %s, sign in, change '
                                                     'nothing?' % name, 'Try it', 'Later'):
        con.live(lambda: (con.cmd('--target-test', name), con.pause()))


def fam_do(con, fam, r):
    word, path, _t = FAMS[fam]
    name = r['name']
    opts = [('show', 'Show it all'), ('test', 'Try it (nothing is changed)'),
            ('edit', 'Change its settings'), ('rename', 'Rename it'),
            ('switch', 'Switch it %s' % ('off' if r.get('enabled', 1) else 'on'))]
    for a in r.get('actions') or []:
        opts.append(('act:' + a['key'], a.get('label') or a['key']))
    if fam == 'target':
        opts.append(('deploys', 'Its deployments'))
    opts.append(('del', 'Delete it'))
    what = con.choose(name, opts, '%s, used by %s' % (r.get('kind'), r.get('used_by') or 0))
    if what == 'show':
        con.act('--%s-show' % word, name)
    elif what == 'test':
        flag = '--target-test' if fam == 'target' else '--%s-test' % word
        con.live(lambda: (con.cmd(flag, name), con.pause()))
    elif what == 'edit':
        d = _plugin(con, fam, r.get('kind')) or {}
        got = module_form(con, '%s %s (%s)' % (word, name, r.get('kind')),
                          d.get('fields') or [], r.get('config') or {},
                          r.get('secret_set') or [])
        if got is None:
            return
        argv, env = got
        if not argv:
            con.note('Nothing changed', 'Nothing was changed.')
            return
        con.act('--%s-edit' % word, name, *argv, env=env)
    elif what == 'rename':
        new = con.ask_one('Rename %s' % name, 'its new name', name)
        if new and new != name:
            con.act('--%s-edit' % word, name, '--name', new)
    elif what == 'switch':
        con.act('--%s-edit' % word, name, '--enabled', 'off' if r.get('enabled', 1) else 'on')
    elif what and what.startswith('act:'):
        key = what[4:]
        a = next((x for x in r.get('actions') or [] if x['key'] == key), {})
        if con.confirm(a.get('label') or key, a.get('confirm') or a.get('help') or
                       'Run %s on %s?' % (key, name), 'Run it'):
            con.live(lambda: (con.cmd('--%s-action' % word, name, key, '--yes'), con.pause()))
    elif what == 'deploys':
        deploy_list(con, target=name)
    elif what == 'del':
        if con.confirm('Delete %s' % name, 'Delete the %s %s with its settings and secrets?'
                       % (word, name), 'Delete it', danger=True):
            con.act('--%s-del' % word, name, '--yes')
    return None


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------
def cert_do(con, r):
    name = r['name']
    opts = [('show', 'Show it all'), ('renew', 'Renew it now'), ('deploy', 'Deploy it now'),
            ('deploys', 'Its deployments (add, run, change, take away)'),
            ('edit', 'Change it (names, issuer, validation, renewing)'),
            ('export', 'Export it into a file'), ('csr', 'A CSR for an outside authority'),
            ('answer', 'The answer to its CSR (a file)'), ('revoke', 'Revoke it'),
            ('del', 'Delete it')]
    what = con.choose(name, opts, '%s, %s, ends %s' % (r.get('state'), r.get('issuer') or
                                                        'imported', _when(r.get('not_after'))))
    if what == 'show':
        con.act('--cert', name)
    elif what in ('renew', 'deploy'):
        con.live(lambda: (con.cmd('--' + what, name), con.pause()))
    elif what == 'deploys':
        deploy_list(con, cert=name)
    elif what == 'edit':
        cert_edit(con, r)
    elif what == 'export':
        got = con.form('Export ' + name, [
            {'key': 'format', 'label': 'format', 'kind': 'choice', 'options': [
                ('fullchain-pem', 'the certificate and its chain (PEM)'),
                ('cert-pem', 'the certificate (PEM)'), ('cert-der', 'the certificate (DER)'),
                ('chain-pem', 'the chain (PEM)'), ('p7b', 'PKCS#7 (P7B)'),
                ('combined-pem', 'key + certificate + chain (PEM)'),
                ('pfx', 'PKCS#12 (PFX), locked'), ('jks', 'Java keystore (JKS), locked'),
                ('key-pem', 'the private key (PEM)')]},
            {'key': 'out', 'label': 'into the file', 'value': '/root/%s.pem' % name,
             'need': True}])
        if got:
            args = ['--export', name, '--format', got['format'], '--out', got['out']]
            if got['format'] in ('pfx', 'jks'):
                con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
            else:
                con.act(*args)
    elif what == 'csr':
        out = con.ask_one('A CSR for ' + name, 'into the file', '/root/%s.csr' % name,
                          'The request is written there; the key waits in acme for the answer.')
        if out:
            con.act('--csr', name, '--out', out)
    elif what == 'answer':
        f = con.ask_one('The answer to the CSR of ' + name, 'the file', '/root/%s.pem' % name,
                        'The certificate the authority sent back (PEM, DER, P7B).')
        if f:
            con.live(lambda: (con.cmd('--csr-answer', name, f), con.pause()))
    elif what == 'revoke':
        got = con.form('Revoke ' + name, [
            {'key': 'reason', 'label': 'why', 'kind': 'choice', 'options': [
                (x, x) for x in ('unspecified', 'keyCompromise', 'superseded',
                                 'cessationOfOperation', 'affiliationChanged',
                                 'privilegeWithdrawn')]}],
            'It is revoked where it was issued, and cannot be taken back.')
        if got and con.confirm('Revoke ' + name, 'Revoke %s (%s)?' % (name, got['reason']),
                               'Revoke it', danger=True):
            con.live(lambda: (con.cmd('--revoke', name, '--reason', got['reason'], '--yes'),
                              con.pause()))
    elif what == 'del':
        if con.confirm('Delete ' + name, 'Delete %s, its versions and its deployments? Where '
                       'it is deployed stays as it is.' % name, 'Delete it', danger=True):
            con.act('--cert-del', name, '--yes')
    return None


KEYS = [('ec-256', 'EC P-256'), ('ec-384', 'EC P-384'), ('rsa-2048', 'RSA 2048'),
        ('rsa-3072', 'RSA 3072'), ('rsa-4096', 'RSA 4096'), ('ed25519', 'Ed25519')]


def _names_of(con, flag):
    return [(r['name'], '%s  (%s)%s' % (r['name'], r.get('kind'), '  - the default'
                                         if r.get('is_default') else ''))
            for r in con._rows(con.out(flag), 'rows')]


def cert_add(con):
    sources = _names_of(con, '--sources')
    vals = _names_of(con, '--validations')
    dflt_s = next((n for n, w in sources if w.endswith('the default')), '')
    dflt_v = next((n for n, w in vals if w.endswith('the default')), '')
    got = con.form('A certificate to keep', [
        {'key': 'name', 'label': 'its name', 'need': True,
         'help': 'What acme calls it: www, vpn-gateway, intranet...'},
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'help': 'The DNS names (and addresses) in it; the first is the common name.'},
        {'key': 'issuer', 'label': 'issuer', 'kind': 'choice', 'value': dflt_s,
         'options': sources or [('', '(no source yet)')],
         'help': 'Where it comes from (Sources).'},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice', 'value': dflt_v,
         'options': [('', '– (not an ACME CA)')] + vals,
         'help': 'For an ACME CA: how the names are proved (Validations).'},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': KEYS}])
    if not got:
        return
    args = ['--cert-add', got['name'], '--names', got['names'], '--key-type', got['key_type'],
            '--challenge', got.get('challenge') or '']
    if got.get('issuer'):
        args += ['--issuer', got['issuer']]
    if con.act(*args) == 0 and con.confirm('Issue it', 'Issue %s now?' % got['name'],
                                           'Issue it now', 'Later'):
        con.live(lambda: (con.cmd('--renew', got['name']), con.pause()))


def cert_edit(con, r):
    one = (con.out('--cert', r['name']) or {}).get('cert') or r
    sources = _names_of(con, '--sources')
    vals = _names_of(con, '--validations')
    got = con.form('Change ' + r['name'], [
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'value': ', '.join(one.get('names') or [])},
        {'key': 'issuer', 'label': 'issuer', 'kind': 'choice', 'value': one.get('issuer') or '',
         'options': [('', '– (none: imported, or a CSR)')] + sources},
        {'key': 'challenge', 'label': 'validation', 'kind': 'choice',
         'value': one.get('challenge') or '', 'options': [('', '–')] + vals},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice',
         'value': one.get('key_type') or 'ec-256', 'options': KEYS},
        {'key': 'auto_renew', 'label': 'renewed by itself', 'kind': 'choice',
         'value': '1' if one.get('auto_renew') else '0', 'options': [('1', 'yes'), ('0', 'no')]},
        {'key': 'renew_days', 'label': 'days before the end', 'kind': 'number',
         'value': str(one.get('renew_days') or ''), 'range': (0, 3650),
         'help': 'Empty or 0: the setting certs_renew_days.'},
        {'key': 'reuse_key', 'label': 'keep its key', 'kind': 'choice',
         'value': '1' if one.get('reuse_key') else '0', 'options': [('0', 'no'), ('1', 'yes')]},
        {'key': 'owner', 'label': 'owner', 'value': one.get('owner') or ''},
        {'key': 'tags', 'label': 'tags (comma)', 'value': ', '.join(one.get('tags') or [])},
        {'key': 'note', 'label': 'note', 'value': one.get('note') or ''}])
    if not got:
        return
    args = ['--cert-edit', r['name'], '--names', got['names'], '--issuer', got['issuer'],
            '--challenge', got['challenge'], '--key-type', got['key_type'],
            '--set', 'auto_renew=%s' % got['auto_renew'],
            '--set', 'renew_days=%s' % (got['renew_days'] or '0'),
            '--set', 'reuse_key=%s' % got['reuse_key'], '--set', 'owner=%s' % got['owner'],
            '--set', 'tags=%s' % got['tags'], '--set', 'note=%s' % got['note']]
    con.act(*args)


def jobs(con):
    def load():
        return con._rows(con.out('--jobs', '--limit', '500'), 'rows')
    cols = [('job', lambda r: r.get('id'), 7, None),
            ('when', lambda r: _when(r.get('ts'), '%m-%d %H:%M'), 11, None),
            ('kind', lambda r: r.get('kind'), 7, None),
            ('of', lambda r: r.get('cert_name') or r.get('target') or '-', 24, None),
            ('state', lambda r: r.get('state'), 8,
             lambda r: {'ok': 'ok', 'failed': 'bad', 'running': 'warn'}.get(r.get('state'), '')),
            ('said', lambda r: r.get('said') or '', 60, lambda r: 'dim')]

    def do(r):
        if r.get('state') in ('queued', 'running'):
            what = con.choose('Job %s' % r['id'], [('follow', 'Follow it, live'),
                                                   ('stop', 'Stop it')])
            if what == 'stop':
                con.act('--job-stop', r['id'])
                return
            if what != 'follow':
                return
        con.live(lambda: (con.cmd('--job', r['id']), con.pause()))
    con.pick('Jobs', load, cols, do, 'no job yet')


# ---------------------------------------------------------------------------
# Deployments
# ---------------------------------------------------------------------------
def deploys(con):
    deploy_list(con)


def deploy_list(con, cert=None, target=None):
    def load():
        if target:
            got = con.out('--target-show', target) or {}
            rows = got.get('deploys') or []
        else:
            rows = con._rows(con.out('--deploys', cert) if cert else con.out('--deploys'),
                             'rows')
        return [{'id': '+', 'cert_name': cert or '', 'target': target or '', '_add': True,
                 'state': 'add one'}] + rows

    cols = [('id', lambda r: r.get('id'), 5, lambda r: 'ok' if r.get('_add') else None),
            ('certificate', lambda r: r.get('cert_name') or '', 24, None),
            ('target', lambda r: r.get('target') or '', 20, None),
            ('state', lambda r: 'outdated' if r.get('outdated') and r.get('state') == 'ok'
             else (r.get('state') or ''), 9,
             lambda r: TONES.get('outdated' if r.get('outdated') else r.get('state') or '', '')),
            ('', lambda r: '' if r.get('_add') else ('on' if r.get('enabled', 1) else 'off'), 3,
             None),
            ('error', lambda r: r.get('last_error') or '', 50,
             lambda r: 'bad' if r.get('last_error') else 'dim')]

    def do(r):
        if r.get('_add'):
            return deploy_add(con, cert, target)
        return deploy_do(con, r)
    con.pick('Deployments' + (' of %s' % cert if cert else ' to %s' % target if target else ''),
             load, cols, do, 'none yet')


def deploy_add(con, cert=None, target=None):
    if not cert:
        certs = [(r['name'], '%s  (%s)' % (r['name'], ', '.join(r.get('names') or [])[:50]))
                 for r in con._rows(con.out('--certs'), 'rows')]
        cert = con.choose('Which certificate', certs)
        if not cert:
            return
    if not target:
        ts = [(r['name'], '%s  (%s)' % (r['name'], r.get('kind')))
              for r in con._rows(con.out('--targets'), 'rows')]
        if not ts:
            con.note('No target', 'There is no target yet: Targets → add one.', 'bad')
            return
        target = con.choose('Where it goes', ts)
        if not target:
            return
    t = (con.out('--target-show', target) or {})
    d = _plugin(con, 'target', t.get('kind')) or {}
    got = module_form(con, '%s on %s' % (cert, target), d.get('deploy_fields') or [])
    if got is None:
        return
    argv, env = got
    if con.act('--deploy-add', cert, target, *argv, env=env) == 0 and \
            con.confirm('Deploy it', 'Put %s on %s now?' % (cert, target), 'Deploy it now',
                        'Later'):
        con.live(lambda: (con.cmd('--deploy', cert), con.pause()))


def deploy_do(con, r):
    ident = str(r['id'])
    what = con.choose('Deployment %s: %s on %s' % (ident, r.get('cert_name'), r.get('target')),
                      [('run', 'Run it now'), ('edit', 'Change its options'),
                       ('switch', 'Switch it %s' % ('off' if r.get('enabled', 1) else 'on')),
                       ('del', 'Take it away')])
    if what == 'run':
        con.live(lambda: (con.cmd('--deploy-run', ident), con.pause()))
    elif what == 'edit':
        t = con.out('--target-show', r.get('target')) or {}
        d = _plugin(con, 'target', t.get('kind') or r.get('target_kind')) or {}
        got = module_form(con, 'Deployment %s' % ident, d.get('deploy_fields') or [],
                          r.get('options') or {}, r.get('secret_set') or [])
        if got is None:
            return
        argv, env = got
        if argv:
            con.act('--deploy-edit', ident, *argv, env=env)
    elif what == 'switch':
        con.act('--deploy-edit', ident, '--enabled', 'off' if r.get('enabled', 1) else 'on')
    elif what == 'del':
        if con.confirm('Take it away', 'Take the deployment %s away? %s keeps what it has.'
                       % (ident, r.get('target')), 'Take it away', danger=True):
            con.act('--deploy-del', ident, '--yes')


# ---------------------------------------------------------------------------
# Authorities
# ---------------------------------------------------------------------------
def cas(con):
    def load():
        return [{'name': '+ a new root authority', '_new': 'root'},
                {'name': '+ a new intermediate', '_new': 'sub'},
                {'name': '+ import one (a file)', '_new': 'import'}] + \
            con._rows(con.out('--cas'), 'rows')

    cols = [('authority', lambda r: r.get('name'), 28,
             lambda r: 'ok' if r.get('_new') else None),
            ('key', lambda r: r.get('key_type') or '', 8, None),
            ('ends', lambda r: '' if r.get('_new') else _when(r.get('not_after')), 10, None),
            ('signs', lambda r: '' if r.get('_new') else ('yes' if r.get('has_key') else 'no'),
             5, None),
            ('subject', lambda r: r.get('subject_dn') or '', 50, lambda r: 'dim')]

    def do(r):
        if r.get('_new') in ('root', 'sub'):
            return ca_new(con, r['_new'])
        if r.get('_new') == 'import':
            got = con.form('Import an authority', [
                {'key': 'file', 'label': 'the file', 'need': True,
                 'help': 'Its certificate and key: a PEM with both, or a PFX / P12.'},
                {'key': 'key', 'label': 'its key (a file)', 'help': 'Where the key is a file '
                 'of its own.'},
                {'key': 'name', 'label': 'its name in acme'},
                {'key': 'pw', 'label': 'locked with a password', 'kind': 'choice',
                 'options': [('0', 'no'), ('1', 'yes')]}])
            if got:
                args = ['--ca-import', got['file']]
                if got.get('key'):
                    args += ['--key', got['key']]
                if got.get('name'):
                    args += ['--name', got['name']]
                if got.get('pw') == '1':
                    con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
                else:
                    con.act(*args)
            return
        return ca_do(con, r)
    con.pick('Authorities', load, cols, do, 'none yet')


def ca_new(con, how):
    parents = [(r['name'], r['name']) for r in con._rows(con.out('--cas'), 'rows')
               if r.get('has_key')]
    if how == 'sub' and not parents:
        con.note('No authority', 'There is no authority that can sign an intermediate yet.',
                 'bad')
        return
    fields = [{'key': 'name', 'label': 'its name', 'need': True},
              {'key': 'subject', 'label': 'subject', 'need': True,
               'value': 'CN=Example %s CA,O=Example' % ('Root' if how == 'root' else
                                                       'Issuing'),
               'help': 'CN=..,O=..,OU=..,C=..'},
              {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': [
                  ('ec-384', 'EC P-384'), ('ec-256', 'EC P-256'), ('rsa-4096', 'RSA 4096'),
                  ('rsa-3072', 'RSA 3072')]},
              {'key': 'days', 'label': 'valid for (days)', 'kind': 'number',
               'value': '3650' if how == 'root' else '1825', 'range': (30, 36500)},
              {'key': 'crl_url', 'label': 'CRL address', 'help': 'Written into what it signs '
               '(empty: none).'}]
    if how == 'sub':
        fields.insert(1, {'key': 'parent', 'label': 'signed by', 'kind': 'choice',
                          'options': parents})
    got = con.form('A new %s authority' % ('root' if how == 'root' else 'intermediate'),
                   fields)
    if not got:
        return
    args = ['--ca-create' if how == 'root' else '--ca-sub', got['name'], '--subject',
            got['subject'], '--key-type', got['key_type'], '--days', got['days']]
    if how == 'sub':
        args += ['--parent', got['parent']]
    if got.get('crl_url'):
        args += ['--set', 'crl_url=%s' % got['crl_url']]
    con.act(*args)


def ca_do(con, r):
    name = r['name']
    what = con.choose(name, [('show', 'Show it and what it signed'), ('crl', 'A new CRL'),
                             ('export', 'Export it into a file'),
                             ('sign', 'Sign a CSR from elsewhere'),
                             ('revoke', 'Revoke something it signed'), ('del', 'Delete it')])
    if what == 'show':
        con.act('--ca-show', name)
    elif what == 'crl':
        out = con.ask_one('A new CRL of ' + name, 'into the file', '/root/%s.crl.pem' % name)
        if out:
            con.act('--ca-crl', name, '--out', out)
    elif what == 'export':
        got = con.form('Export ' + name, [
            {'key': 'what', 'label': 'what', 'kind': 'choice', 'options': [
                ('cert', 'its certificate (PEM)'), ('cert-der', 'its certificate (DER)'),
                ('chain', 'its chain (PEM)'), ('bundle', 'certificate, chain and CRL'),
                ('crl', 'its CRL (PEM)'), ('p7b', 'PKCS#7'), ('key', 'its private key'),
                ('p12', 'PKCS#12 with its key, locked')]},
            {'key': 'out', 'label': 'into the file', 'value': '/root/%s.pem' % name,
             'need': True}])
        if got:
            args = ['--ca-export', name, '--what', got['what'], '--out', got['out']]
            if got['what'] == 'p12':
                con.live(lambda: (con.cmd(*args), con.pause()))
            else:
                con.act(*args)
    elif what == 'sign':
        got = con.form('Sign a CSR with ' + name, [
            {'key': 'csr', 'label': 'the CSR (a file)', 'need': True},
            {'key': 'out', 'label': 'the certificate into', 'need': True,
             'value': '/root/signed.pem'},
            {'key': 'days', 'label': 'valid for (days)', 'kind': 'number', 'value': '397',
             'range': (1, 36500)},
            {'key': 'eku', 'label': 'for', 'kind': 'choice', 'options': [
                ('serverAuth', 'servers (TLS)'), ('clientAuth', 'clients'),
                ('serverAuth,clientAuth', 'both')]}])
        if got:
            con.act('--ca-sign', name, '--csr', got['csr'], '--out', got['out'], '--days',
                    got['days'], '--set', 'eku=%s' % got['eku'])
    elif what == 'revoke':
        got = con.form('Revoke what %s signed' % name, [
            {'key': 'serial', 'label': 'its serial', 'need': True,
             'help': 'As --ca-show lists it (hex).'},
            {'key': 'reason', 'label': 'why', 'kind': 'choice', 'options': [
                (x, x) for x in ('unspecified', 'keyCompromise', 'superseded',
                                 'cessationOfOperation', 'affiliationChanged')]}])
        if got:
            con.act('--ca-revoke', name, got['serial'], '--reason', got['reason'], '--yes')
    elif what == 'del':
        if con.confirm('Delete ' + name, 'Delete the authority %s and its key? What it signed '
                       'stays valid until it ends.' % name, 'Delete it', danger=True):
            con.act('--ca-del', name, '--yes')


# ---------------------------------------------------------------------------
# acme's own DNS server, the modules
# ---------------------------------------------------------------------------
def dns(con):
    def load():
        got = con.out('--dns-records') or {}
        return [{'id': '+', 'name': '+ add a record', '_add': True}] + \
            list(got.get('records') or [])

    cols = [('id', lambda r: r.get('id'), 5, lambda r: 'ok' if r.get('_add') else None),
            ('name', lambda r: r.get('name'), 36, None),
            ('type', lambda r: r.get('rtype') or '', 6, None),
            ('value', lambda r: r.get('value') or '', 40, None),
            ('ttl', lambda r: r.get('ttl') or '', 6, None),
            ('expires', lambda r: '' if r.get('_add') else (_when(r.get('expires'),
                                                                  '%m-%d %H:%M')
                                                            if r.get('expires') else 'never'),
             12, lambda r: 'dim')]

    def do(r):
        if r.get('_add'):
            got = con.form('A record of acme\'s DNS server', [
                {'key': 'name', 'label': 'name', 'need': True, 'help': '@ for the zone itself.'},
                {'key': 'type', 'label': 'type', 'kind': 'choice', 'options': [
                    (x, x) for x in ('A', 'AAAA', 'TXT', 'CNAME', 'MX', 'NS', 'CAA', 'SRV',
                                     'PTR')]},
                {'key': 'value', 'label': 'value', 'need': True},
                {'key': 'ttl', 'label': 'TTL (s)', 'kind': 'number', 'value': '60',
                 'range': (0, 604800)}])
            if got:
                con.act('--dns-add', got['name'], got['type'], got['value'], '--ttl',
                        got['ttl'] or '60')
            return
        if con.confirm('Take it away', 'Take %s %s %s away?' % (r['name'], r['rtype'],
                                                                 r.get('value')), 'Take it away',
                       danger=True):
            con.act('--dns-del', str(r['id']), '--yes')
    con.pick('acme\'s own DNS server', load, cols, do, 'no record',
             'Its zone and whether it listens: Settings → DNS server (acme --dns-records).')


def modules(con):
    def load():
        got = con.out('--plugins') or {}
        rows = []
        for fam in ('issuer', 'challenge', 'target'):
            for d in got.get(fam) or []:
                rows.append(dict(d, family=fam))
        return rows
    cols = [('kind', lambda r: r.get('kind'), 16, None),
            ('is a', lambda r: FAMS[r['family']][0], 10, lambda r: 'dim'),
            ('title', lambda r: r.get('title'), 40, None),
            ('vendor', lambda r: r.get('vendor') or '', 18, lambda r: 'dim'),
            ('actions', lambda r: ', '.join(a['key'] for a in r.get('actions') or []), 12,
             None)]
    con.pick('Modules', load, cols,
             lambda r: con.act('--plugin', '%s/%s' % (r['family'], r['kind'])), 'none')
