# -*- coding: utf-8 -*-
"""
The "Certificates" menu of the console (acme --console), at the top of the
main menu. As every other menu there, it only runs `acme ...` commands of the
command line (acmelib/certs/cli.py) - nothing here can do more than they do.

    c  Certificates
         1 Browse them (Enter: details, renew, deploy, export, jobs)
         2 Add one                     3 Renew what is due now
         4 Jobs (Enter: followed live)
         5 Authorities                 6 Sources (issuers)
         7 Validation (challenges)     8 Targets (Enter: try one)
         9 DNS server                  0 Modules
"""
from __future__ import annotations

import time


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
         'new': 'warn', 'pending': 'warn', 'renewing': 'warn', 'due': 'warn'}


def menu(con):
    def load():
        return con._rows(con.out('--certs'), 'rows')

    def tone(r):
        if r.get('days_left') is not None and r['days_left'] < 14 and r.get('state') == 'ok':
            return 'warn'
        return TONES.get(r.get('state') or '', '')

    cols = [('certificate', lambda r: r.get('name'), 28, None),
            ('state', lambda r: r.get('state') or '', 9, tone),
            ('left', lambda r: '-' if r.get('days_left') is None else '%d d' % r['days_left'], 6,
             tone),
            ('issuer', lambda r: r.get('issuer') or '-', 16, None),
            ('names', lambda r: ', '.join(r.get('names') or []), 50, lambda r: 'dim')]
    return con.sub('Certificates', [
        ('1', 'Browse them (Enter: what to do with one)',
         lambda: con.pick('Certificates', load, cols, lambda r: cert_do(con, r),
                          'no certificate yet')),
        ('2', 'Add one', lambda: cert_add(con)),
        ('3', 'Renew every one that is due, now', lambda: con.act('--renew', 'all')),
        ('4', 'Jobs (Enter: every step, live)', lambda: jobs(con)),
        ('5', 'Authorities of acme\'s own', lambda: cas(con)),
        ('6', 'Sources: where certificates come from', lambda: con.act('--sources')),
        ('7', 'Validation: how names are proved', lambda: con.act('--validations')),
        ('8', 'Targets: where certificates go (Enter: try one)', lambda: targets(con)),
        ('9', 'acme\'s own DNS server', lambda: con.act('--dns-records')),
        ('0', 'Modules (issuers, challenges, targets)', lambda: con.act('--plugins')),
    ])


def cert_do(con, r):
    name = r['name']
    opts = [('show', 'Show it all'), ('renew', 'Renew it now'), ('deploy', 'Deploy it now'),
            ('export', 'Export it into a file')]
    what = con.choose(name, opts, '%s, %s, ends %s' % (r.get('state'), r.get('issuer') or
                                                        'imported', _when(r.get('not_after'))))
    if what == 'show':
        con.act('--cert', name)
    elif what in ('renew', 'deploy'):
        con.live(lambda: (con.cmd('--' + what, name), con.pause()))
    elif what == 'export':
        got = con.form('Export ' + name, [
            {'key': 'format', 'label': 'format', 'kind': 'choice', 'options': [
                ('fullchain-pem', 'the certificate and its chain (PEM)'),
                ('cert-pem', 'the certificate (PEM)'), ('cert-der', 'the certificate (DER)'),
                ('chain-pem', 'the chain (PEM)'), ('p7b', 'PKCS#7 (P7B)'),
                ('combined-pem', 'key + certificate + chain (PEM)'),
                ('pfx', 'PKCS#12 (PFX), locked'), ('key-pem', 'the private key (PEM)')]},
            {'key': 'out', 'label': 'into the file', 'value': '/root/%s.pem' % name,
             'need': True}])
        if got:
            args = ['--export', name, '--format', got['format'], '--out', got['out']]
            if got['format'] in ('pfx',):
                con.live(lambda: (con.cmd(*(args + ['--password'])), con.pause()))
            else:
                con.act(*args)
    return None


def cert_add(con):
    got = con.form('A certificate to keep', [
        {'key': 'name', 'label': 'its name', 'need': True,
         'help': 'What acme calls it: www, vpn-gateway, intranet...'},
        {'key': 'names', 'label': 'names (comma)', 'need': True,
         'help': 'The DNS names (and addresses) in it; the first is the common name.'},
        {'key': 'issuer', 'label': 'issuer', 'need': True,
         'help': 'Where it comes from - a name from Sources (acme --sources).'},
        {'key': 'challenge', 'label': 'challenge', 'need': False,
         'help': 'For ACME: how the names are proved - a name from Validation.'},
        {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': [
            ('ec-256', 'EC P-256'), ('ec-384', 'EC P-384'), ('rsa-2048', 'RSA 2048'),
            ('rsa-3072', 'RSA 3072'), ('rsa-4096', 'RSA 4096'), ('ed25519', 'Ed25519')]}])
    if not got:
        return
    args = ['--cert-add', got['name'], '--names', got['names'], '--issuer', got['issuer'],
            '--key-type', got['key_type']]
    if got.get('challenge'):
        args += ['--challenge', got['challenge']]
    if con.act(*args) == 0 and con.confirm('Issue it', 'Issue %s now?' % got['name'],
                                           'Issue it now', 'Later'):
        con.live(lambda: (con.cmd('--renew', got['name']), con.pause()))


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
    con.pick('Jobs', load, cols,
             lambda r: con.live(lambda: (con.cmd('--job', r['id']), con.pause())), 'no job yet')


def cas(con):
    what = con.choose('Authorities', [('list', 'The authorities'),
                                      ('new', 'Make a new root authority')])
    if what == 'list':
        con.act('--cas')
    elif what == 'new':
        got = con.form('A new root authority', [
            {'key': 'name', 'label': 'its name', 'need': True},
            {'key': 'subject', 'label': 'subject', 'value': 'CN=Example Root CA,O=Example',
             'need': True, 'help': 'CN=..,O=..,OU=..,C=..'},
            {'key': 'key_type', 'label': 'key', 'kind': 'choice', 'options': [
                ('ec-384', 'EC P-384'), ('ec-256', 'EC P-256'), ('rsa-4096', 'RSA 4096'),
                ('rsa-3072', 'RSA 3072')]},
            {'key': 'days', 'label': 'valid for (days)', 'kind': 'number', 'value': '3650',
             'range': (30, 36500)}])
        if got:
            con.act('--ca-create', got['name'], '--subject', got['subject'], '--key-type',
                    got['key_type'], '--days', got['days'])


def targets(con):
    def load():
        return con._rows(con.out('--targets'), 'rows')
    cols = [('target', lambda r: r.get('name'), 26, None),
            ('kind', lambda r: r.get('kind'), 12, None),
            ('used by', lambda r: r.get('used_by'), 7, None),
            ('last error', lambda r: r.get('last_error') or '', 60,
             lambda r: 'bad' if r.get('last_error') else 'dim')]

    def do(r):
        if con.confirm('Try it', 'Reach %s, sign in, change nothing?' % r['name'], 'Try it'):
            con.live(lambda: (con.cmd('--target-test', r['name']), con.pause()))
    con.pick('Targets', load, cols, do, 'no target yet')
