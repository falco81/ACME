# -*- coding: utf-8 -*-
"""
The command line of the certificate manager (docs/command-line.md):

    acme --certs [--search TEXT]          every certificate
    acme --cert NAME                      one, with its versions, deployments, jobs
    acme --cert-add NAME --names a,b --issuer X [--challenge Y] [--key-type T]
    acme --renew NAME|all [--force]       now, the steps as they come
    acme --deploy NAME                    every enabled deployment of it, now
    acme --import FILE [--name N] [--password]
    acme --export NAME --format F --out FILE [--password]
    acme --selfsigned NAME --names a,b    a self-signed certificate, made now
    acme --cas                            acme's own authorities
    acme --ca-create NAME --subject "CN=..,O=.." [--key-type T] [--days N]
    acme --sources | --validations | --targets
    acme --target-test NAME
    acme --jobs [--limit N]   acme --job ID (followed while it runs)
    acme --plugins            acme --dns-records

Each is the page's own API route run here (as 'command line', a full
administrator), so the checks, the events and the words are the same;
renewals and deployments run in this process, their steps printed as they
come. --json answers JSON.

Only argparse is imported here at first: `acme --version` stays fast.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time

MINE = ('certs', 'cert', 'cert_add', 'renew', 'deploy', 'import_file', 'export', 'selfsigned',
        'cas', 'ca_create', 'sources', 'validations', 'targets', 'target_test', 'jobs', 'job',
        'plugins', 'dns_records')


def add_args(p):
    g = p.add_argument_group('CERTIFICATES', 'Certificates kept, renewed and deployed by acme '
                             '(docs/command-line.md).')
    g.add_argument('--certs', action='store_true', help='every certificate (--search TEXT)')
    g.add_argument('--cert', metavar='NAME', help='one certificate: its versions, deployments '
                   'and jobs')
    g.add_argument('--cert-add', metavar='NAME', help='a certificate to keep: with --names, '
                   '--issuer and (for ACME) --challenge; issued by the next look, or --renew')
    g.add_argument('--issuer', metavar='NAME', help='with --cert-add: where it comes from '
                   '(acme --sources)')
    g.add_argument('--challenge', metavar='NAME', help='with --cert-add: how its names are '
                   'proved (acme --validations)')
    g.add_argument('--key-type', metavar='TYPE', help='with --cert-add, --selfsigned, '
                   '--ca-create: ec-256 ec-384 rsa-2048 rsa-3072 rsa-4096 ed25519')
    g.add_argument('--renew', metavar='NAME|all', help='renew it now (all: every one due; with '
                   '--force every one acme can renew)')
    g.add_argument('--force', action='store_true', help='with --renew all: not only those due')
    g.add_argument('--deploy', metavar='NAME', help='run its deployments now')
    g.add_argument('--import', dest='import_file', metavar='FILE', help='a certificate from a '
                   'file (PEM, DER, PFX/P12, P7B, JKS...) - --name, --password')
    g.add_argument('--name', metavar='NAME', help='with --import: the name it is kept under')
    g.add_argument('--password', action='store_true', help='with --import / --export: ask for '
                   'the file\'s password (or ACME_FILE_PASSWORD)')
    g.add_argument('--export', metavar='NAME', help='a certificate into a file: --format, --out')
    g.add_argument('--format', metavar='F', default='fullchain-pem', help='with --export: '
                   'cert-pem cert-der chain-pem fullchain-pem p7b key-pem key-rsa key-der '
                   'combined-pem pfx p12 p12-legacy jks [fullchain-pem]')
    g.add_argument('--out', metavar='FILE', help='with --export: where it goes (- for stdout)')
    g.add_argument('--selfsigned', metavar='NAME', help='a self-signed certificate for --names, '
                   'made now')
    g.add_argument('--cas', action='store_true', help='acme\'s own certificate authorities')
    g.add_argument('--ca-create', metavar='NAME', help='a new root authority: --subject, '
                   '--key-type, --days')
    g.add_argument('--subject', metavar='DN', help='with --ca-create: "CN=Example Root,O=Example"')
    g.add_argument('--sources', action='store_true', help='where certificates come from (issuers)')
    g.add_argument('--validations', action='store_true', help='how names are proved (challenges)')
    g.add_argument('--targets', action='store_true', help='where certificates go')
    g.add_argument('--target-test', metavar='NAME', help='try a target: reach it, sign in, '
                   'change nothing')
    g.add_argument('--jobs', action='store_true', help='the jobs, newest first (--limit)')
    g.add_argument('--job', metavar='ID', type=int, help='one job, every step (followed while it '
                   'runs)')
    g.add_argument('--plugins', action='store_true', help='the modules: issuers, challenges, '
                   'targets (and those that did not load)')
    g.add_argument('--dns-records', action='store_true', help='what acme\'s own DNS server '
                   'answers')


def asked(args):
    return any(getattr(args, k, None) not in (None, False, '') for k in MINE)


# ---------------------------------------------------------------------------
class _Daemon(object):
    """What a route asks of the daemon: the store (and the reader)."""
    def __init__(self, store):
        self.store = store
        self.stop_flag = __import__('threading').Event()

    def reader(self):
        return self.store


def _when(ts, fmt='%Y-%m-%d %H:%M'):
    if not ts:
        return '-'
    try:
        return time.strftime(fmt, time.localtime(float(ts)))
    except (TypeError, ValueError):
        return str(ts)


class Cli(object):
    WHO = 'command line'

    def __init__(self, args):
        from acmelib import engine as E
        self.E = E
        self.args = args
        self.pal = E.TABLE_PAL or E.Palette(False)
        self.json = bool(getattr(args, 'json', False))

    def open(self):
        E = self.E
        self.store = E.cli_store()
        from acmelib.certs import api  # noqa: F401  (the routes)
        self.d = _Daemon(self.store)

    def api(self, method, path, body=None, args=None):
        return self.E.cli_api(self.d, self.WHO, method, path, body=body, args=args)

    def out(self, data):
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))

    def table(self, rows, heads):
        print(self.E.table(rows, heads))

    def echo(self, step):
        t, level, words = step
        p = self.pal
        tone = {'ok': p.good, 'warn': p.warn, 'bad': p.bad, 'debug': p.dim}.get(level, str)
        mark = {'ok': '✔', 'warn': '!', 'bad': '✘', 'debug': '·'}.get(level, ' ') if p.on else \
            {'ok': '[ ok ]', 'warn': '[warn]', 'bad': '[fail]', 'debug': '[ .. ]'}.get(level,
                                                                                       '      ')
        print('  %s %s %s' % (p.dim(time.strftime('%H:%M:%S', time.localtime(t))), tone(mark),
                              tone(words) if level in ('bad', 'warn') else words))
        sys.stdout.flush()

    def cert_ref(self, name):
        from acmelib.certs import store as S
        row = S.cert_get(self.store, name)
        if not row:
            raise SystemExit('acme: there is no certificate %s (acme --certs)' % name)
        return row

    # ---- the options -------------------------------------------------------------------
    def run(self):
        a = self.args
        # Files read as whoever typed it, before the service's account takes over.
        data = None
        if a.import_file:
            try:
                with open(a.import_file, 'rb') as f:
                    data = f.read()
            except OSError as e:
                raise SystemExit('acme: %s' % e)
        self.open()
        if a.cert_add:
            return self.cert_add()
        if a.selfsigned:
            return self.selfsigned()
        if a.ca_create:
            return self.ca_create()
        if a.import_file:
            return self.do_import(data)
        if a.renew:
            return self.renew()
        if a.deploy:
            return self.deploy()
        if a.export:
            return self.export()
        if a.target_test:
            return self.target_test()
        if a.job:
            return self.job()
        if a.cert:
            return self.cert()
        if a.certs:
            return self.certs()
        if a.cas:
            return self.cas()
        if a.sources or a.validations or a.targets:
            return self.family('sources' if a.sources else 'validations' if a.validations
                               else 'targets')
        if a.jobs:
            return self.jobs()
        if a.plugins:
            return self.plugins()
        if a.dns_records:
            return self.dns()
        return None

    def certs(self):
        got = self.api('GET', '/api/certs', args={'search': self.args.search or '',
                                                  'per': '1000'})
        if self.json:
            self.out(got)
            return 0
        rows = []
        for r in got['rows']:
            dl = r.get('days_left')
            rows.append([r['name'], r.get('state') or '', '-' if dl is None else '%d d' % dl,
                         _when(r.get('not_after'), '%Y-%m-%d'), r.get('issuer') or '-',
                         'auto' if r.get('auto_renew') else 'by hand',
                         ('%d (%d failed)' % (r['deploys'], r['deploys_failed'])
                          if r.get('deploys_failed') else str(r.get('deploys') or 0)),
                         ', '.join(r.get('names') or [])[:60]])
        self.table(rows, ['certificate', 'state', 'left', 'ends', 'issuer', 'renewed',
                          'deploys', 'names'])
        print(self.pal.dim('  %d certificate(s)' % got['total']))
        return 0

    def cert(self):
        row = self.cert_ref(self.args.cert)
        got = self.api('GET', '/api/certs/one', args={'id': str(row['id'])})
        if self.json:
            self.out(got)
            return 0
        c = got['cert']
        p = self.pal
        print(p.head(c['name']) + '  ' + str(c.get('state') or ''))
        for k, v in (('names', ', '.join(c.get('names') or [])), ('key type', c.get('key_type')),
                     ('issuer', c.get('issuer') or '(none: imported)'),
                     ('challenge', c.get('challenge') or '-'),
                     ('challenge map', json.dumps(c.get('challenge_map') or {}) if c.get(
                         'challenge_map') else ''),
                     ('renewed', 'by itself, %s days before the end' % (
                         c.get('renew_days') or self.E.CONFIG.get('certs_renew_days'))
                      if c.get('auto_renew') else 'by hand'),
                     ('subject', c.get('subject_dn')), ('issued by', c.get('issuer_dn')),
                     ('serial', c.get('serial')), ('sha-256', c.get('fingerprint')),
                     ('valid', '%s - %s' % (_when(c.get('not_before')), _when(c.get('not_after')))
                      if c.get('not_after') else ''),
                     ('days left', c.get('days_left')), ('version', c.get('version')),
                     ('last error', c.get('last_error')),
                     ('next try', _when(c.get('next_try')) if c.get('next_try') else ''),
                     ('due', c.get('due')), ('owner', c.get('owner')), ('note', c.get('note')),
                     ('tags', ', '.join(c.get('tags') or []))):
            if v not in (None, '', []):
                print('  %-14s %s' % (k, v))
        if got['versions']:
            print(p.head('\nversions'))
            self.table([[v['version'], _when(v['created']), v.get('why') or '',
                         v.get('serial') or '', _when(v.get('not_after'), '%Y-%m-%d'),
                         'revoked' if v.get('revoked') else ''] for v in got['versions']],
                       ['v', 'made', 'why', 'serial', 'ends', ''])
        if got['deploys']:
            print(p.head('\ndeployments'))
            self.table([[d['id'], d['target'], d.get('state') or '', d.get('deployed_version') or
                         '-', _when(d.get('last_ok')), 'on' if d.get('enabled', 1) else 'off',
                         (d.get('last_error') or '')[:60]] for d in got['deploys']],
                       ['id', 'target', 'state', 'version', 'last ok', '', 'error'])
        if got['jobs']:
            print(p.head('\njobs'))
            self._job_table(got['jobs'][:10])
        return 0

    def cert_add(self):
        a = self.args
        body = {'name': a.cert_add, 'names': [n for n in (a.names or '').split(',') if n.strip()],
                'issuer': a.issuer or '', 'challenge': a.challenge or '',
                'key_type': a.key_type or 'ec-256', 'auto_renew': 1}
        got = self.api('POST', '/api/certs/save', body=body)
        if self.json:
            self.out(got)
        else:
            print(self.pal.ok_line('%s added (id %s) - acme --renew %s issues it now'
                                   % (a.cert_add, got['id'], a.cert_add)))
        return 0

    def _run_job(self, kind, fn, cert_id, said):
        from acmelib.certs import jobs
        if not self.json:
            print(self.pal.dim('  %s: %s' % (kind, said)))
        try:
            job = jobs.run_now(self.store, kind, fn, cert_id=cert_id, by=self.WHO, said=said,
                               echo=None if self.json else self.echo)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        if self.json:
            self.out({'job_id': job.id, 'ok': job.ok, 'said': job.said, 'steps': job.steps})
        else:
            line = 'job %d: %s' % (job.id, job.said or job.state)
            print(self.pal.ok_line(line) if job.ok else self.pal.bad_line(line))
        return job

    def renew(self):
        from acmelib.certs import renewer, store as S
        a = self.args
        if a.renew == 'all':
            rows = self.store.db.rows("SELECT * FROM certs WHERE COALESCE(issuer, '') <> '' AND "
                                      "COALESCE(enabled, 1) <> 0 ORDER BY name")
            todo = [r for r in rows if a.force or renewer.due_why(r)]
            if not todo:
                if self.json:
                    self.out({'jobs': []})
                else:
                    print('nothing is due (--force renews every one)')
                return 0
            bad = 0
            for r in todo:
                job = self._run_job('renew', renewer.renew_job(r['id'], a.force, self.WHO),
                                    r['id'], '%s: %s' % (r['name'], renewer.due_why(r) or
                                                         'forced'))
                bad += 0 if job.ok else 1
            return 1 if bad else 0
        row = self.cert_ref(a.renew)
        if not row.get('issuer'):
            raise SystemExit('acme: %s has no issuer (imported?) - import the new one instead'
                             % row['name'])
        job = self._run_job('renew', renewer.renew_job(row['id'], a.force, self.WHO), row['id'],
                            '%s, asked on the command line' % S.cert_get(self.store,
                                                                         row['id'])['name'])
        return 0 if job.ok else 1

    def deploy(self):
        from acmelib.certs import deployer
        row = self.cert_ref(self.args.deploy)
        if not row.get('cert_pem'):
            raise SystemExit('acme: %s has not been issued yet' % row['name'])
        job = self._run_job('deploy', deployer.deploy_job(row['id']), row['id'],
                            'the deployments of %s' % row['name'])
        return 0 if job.ok else 1

    def _password(self, twice):
        if not self.args.password:
            return ''
        return self.E.ask_password('the file\'s password', twice=twice, env='ACME_FILE_PASSWORD')

    def do_import(self, data):
        a = self.args
        pw = self._password(False)
        body = {'data_b64': base64.b64encode(data).decode('ascii'),
                'filename': os.path.basename(a.import_file), 'password': pw}
        if a.name:
            body['name'] = a.name
        parsed = self.api('POST', '/api/certs/parse', body=dict(body))
        if parsed.get('needs_password') and not pw:
            raise SystemExit('acme: %s is locked - add --password' % a.import_file)
        got = self.api('POST', '/api/certs/import', body=body)
        if self.json:
            self.out(dict(got, parsed=parsed))
        else:
            print(self.pal.ok_line('imported as %s (id %s)%s' % (
                self.store.db.value('SELECT name FROM certs WHERE id = ?', (got['id'],)),
                got['id'], '' if parsed.get('has_key') else ' - without a private key')))
        return 0

    def export(self):
        a = self.args
        row = self.cert_ref(a.export)
        if not a.out:
            raise SystemExit('acme: --export needs --out FILE (or --out - for stdout)')
        pw = self._password(True)
        if a.format in ('pfx', 'p12', 'p12-legacy', 'jks') and not pw:
            pw = os.environ.get('ACME_FILE_PASSWORD') or ''
            if not pw:
                raise SystemExit('acme: a %s is locked with a password: add --password'
                                 % a.format)
        got = self.api('POST', '/api/certs/export', body={'id': row['id'], 'format': a.format,
                                                          'password': pw})
        data = base64.b64decode(got['data_b64'])
        if a.out == '-':
            sys.stdout.flush()
            out = getattr(sys.stdout, 's', sys.stdout)
            out = getattr(out, 'buffer', None)
            if out is None:
                sys.stdout.write(data.decode('utf-8', 'replace'))
            else:
                out.write(data)
            return 0
        try:
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        except OSError as e:
            raise SystemExit('acme: %s: %s' % (a.out, e))
        if self.json:
            self.out({'file': a.out, 'format': a.format, 'bytes': len(data)})
        else:
            print(self.pal.ok_line('%s written (%s, %d bytes)' % (a.out, a.format, len(data))))
        return 0

    def selfsigned(self):
        from acmelib.certs import renewer, store as S
        a = self.args
        iss = self.store.db.row("SELECT * FROM cert_issuers WHERE kind = 'selfsigned' "
                                "ORDER BY id LIMIT 1")
        if not iss:
            if not S.plugin_class('issuer', 'selfsigned'):
                raise SystemExit('acme: there is no self-signed module (acme --plugins)')
            self.api('POST', '/api/sources/save', body={'name': 'self-signed', 'kind':
                                                        'selfsigned', 'config': {},
                                                        'enabled': 1})
            iss = self.store.db.row("SELECT * FROM cert_issuers WHERE kind = 'selfsigned' "
                                    "ORDER BY id LIMIT 1")
        names = [n for n in (a.names or a.selfsigned).split(',') if n.strip()]
        row = S.cert_get(self.store, a.selfsigned)
        body = {'name': a.selfsigned, 'names': names, 'issuer': iss['name'],
                'key_type': a.key_type or 'ec-256', 'auto_renew': 1}
        if row:
            body['id'] = row['id']
        if a.days != 825:
            body['profile'] = {'days': a.days}
        got = self.api('POST', '/api/certs/save', body=body)
        job = self._run_job('renew', renewer.renew_job(got['id'], True, self.WHO), got['id'],
                            'a self-signed certificate for %s' % ', '.join(names))
        return 0 if job.ok else 1

    def cas(self):
        got = self.api('GET', '/api/cas')
        if self.json:
            self.out(got)
            return 0
        self.table([[r['id'], r['name'], r.get('key_type') or '', _when(r.get('not_after'),
                                                                        '%Y-%m-%d'),
                     'yes' if r.get('has_key') else 'no', r.get('issued') or 0,
                     (r.get('subject_dn') or '')[:60]] for r in got['rows']],
                   ['id', 'authority', 'key', 'ends', 'can sign', 'signed', 'subject'])
        return 0

    def ca_create(self):
        a = self.args
        subj = {}
        for part in (a.subject or 'CN=%s' % a.ca_create).split(','):
            if '=' in part:
                k, v = part.split('=', 1)
                subj[k.strip()] = v.strip()
        got = self.api('POST', '/api/cas/create', body={
            'name': a.ca_create, 'subject': subj, 'key_type': a.key_type or 'ec-384',
            'days': a.days if a.days != 825 else 3650})
        if self.json:
            self.out(got)
        else:
            print(self.pal.ok_line('authority %s made (id %s)' % (a.ca_create, got.get('id'))))
        return 0

    def family(self, path):
        got = self.api('GET', '/api/%s' % path)
        if self.json:
            self.out(got)
            return 0
        self.table([[r['id'], r['name'], r['kind'] + (' (module missing)' if r.get(
            'module_missing') else ''), 'on' if r.get('enabled', 1) else 'off', r.get('used_by'),
            _when(r.get('last_ok')), (r.get('last_error') or '')[:50]] for r in got['rows']],
            ['id', 'name', 'kind', '', 'used by', 'last ok', 'last error'])
        return 0

    def target_test(self):
        from acmelib.certs import api, store as S
        row = S.plugin_row(self.store, 'target', self.args.target_test)
        if not row:
            raise SystemExit('acme: there is no target %s (acme --targets)' % self.args.target_test)
        got = api.family_test(self.store, 'target', {'id': row['id']}, self.WHO,
                              echo=None if self.json else self.echo)
        if self.json:
            self.out(got)
        else:
            print(self.pal.ok_line(got['said']) if got['ok'] else self.pal.bad_line(got['said']))
        return 0 if got['ok'] else 1

    def _job_table(self, rows):
        self.table([[r['id'], _when(r['ts'], '%m-%d %H:%M:%S'), r['kind'], r.get('cert_name') or
                     r.get('target') or '-', r.get('state') or '', r.get('node') or '',
                     '%.1f s' % ((r.get('took_ms') or 0) / 1000.0) if r.get('took_ms') else '-',
                     (r.get('said') or '')[:70]] for r in rows],
                   ['job', 'when', 'kind', 'of', 'state', 'node', 'took', 'said'])

    def jobs(self):
        got = self.api('GET', '/api/certs/jobs', args={'per': str(self.args.limit or 40)})
        if self.json:
            self.out(got)
            return 0
        self._job_table(got['rows'])
        return 0

    def job(self):
        from acmelib.certs import jobs
        ident = self.args.job
        try:
            v = jobs.job_view(self.store, ident)
        except LookupError as e:
            raise SystemExit('acme: %s' % e)
        if self.json:
            self.out({'job': v})
            return 0
        p = self.pal
        print('%s %d  %s %s  %s on %s, by %s' % (p.head('job'), v['id'], v['kind'],
                                                 v.get('cert_name') or v.get('target') or '',
                                                 _when(v['ts']), v.get('node'), v.get('by_who')))
        seen = 0
        while True:
            for st in v['steps'][seen:]:
                self.echo(st)
            seen = len(v['steps'])
            if not v.get('live'):
                break
            time.sleep(1)
            v = jobs.job_view(self.store, ident)
        line = '%s%s' % (v.get('state'), (': ' + v['said']) if v.get('said') else '')
        print(p.ok_line(line) if v.get('ok') else p.bad_line(line))
        return 0 if v.get('ok') else 1

    def plugins(self):
        from acmelib.certs import api
        got = api.plugins_view(self.store)
        if self.json:
            self.out(got)
            return 0
        for fam in ('issuer', 'challenge', 'target'):
            print(self.pal.head(fam + 's'))
            self.table([[d['kind'], d['title'], d.get('vendor') or '', len(d.get('fields') or []),
                         os.path.basename(d.get('module') or '')] for d in got.get(fam, [])],
                       ['kind', 'title', 'vendor', 'fields', 'file'])
        if got.get('broken'):
            print(self.pal.bad('did not load'))
            for b in got['broken']:
                print('  %s: %s' % (b['file'], b['words']))
        return 0

    def dns(self):
        got = self.api('GET', '/api/dns')
        if self.json:
            self.out(got)
            return 0
        s = got['settings']
        print('acme\'s DNS server: %s, zone %s, port %s' % (
            'on' if s.get('dns_server') else 'off', s.get('dns_zone') or '(none)',
            s.get('dns_port')))
        self.table([[r['id'], r['name'], r['rtype'], (r.get('value') or '')[:60], r.get('ttl'),
                     _when(r.get('expires')) if r.get('expires') else 'never',
                     r.get('owner') or ''] for r in got['records']],
                   ['id', 'name', 'type', 'value', 'ttl', 'expires', 'by'])
        return 0


def run(args):
    if not asked(args):
        return None
    return Cli(args).run()
