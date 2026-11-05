# -*- coding: utf-8 -*-
"""
The command line of the certificate manager (docs/command-line.md). What the
pages can do, it can do: each option runs the page's own API route here (as
'command line', a full administrator), so the checks, the events and the
words are the same; renewals, deployments, tests and actions run in this
process, their steps printed as they come. --json answers JSON.

    certificates   --certs --cert --cert-add --cert-edit --cert-del --renew --deploy
                   --revoke --csr --csr-answer --import --export --selfsigned
                   --jobs --job --job-stop --acme-contact
    before one     --check-names N1,N2 --cert-check NAME --dry-run NAME|N1,N2
    modules        --sources --validations --targets (lists), --source NAME ...,
                   --source-add/-edit/-del/-test/-action/-default (and validation-,
                   target-), --validation-check NAME HOST,
                   --plugins, --plugin NAME
    deployments    --deploys [CERT] --deploy-add CERT TARGET --deploy-edit ID
                   --deploy-del ID --deploy-run ID
    authorities    --cas --ca-show --ca-create --ca-sub --ca-import --ca-revoke --ca-crl
                   --ca-export --ca-sign --ca-del --ca-default --ca-publish
                   --ca-pki-urls --ca-pki-check --ca-edit --ca-renew --ca-versions
                   --ca-install-cert
    DNS server     --dns-records --dns-add --dns-del

A module's settings are --set KEY=VALUE (again for more), checked against the
module's own fields (their type, whether needed, the choices of a select):
KEY=- asks for a secret (or reads one line of stdin, or ACME_VALUE_KEY) and it
is never shown; KEY=@env reads ACME_VALUE_KEY; KEY=@file:PATH reads a file (a
PEM); KEY+=V adds V to a list, KEY-=V takes it away.

Only argparse is imported here at first: `acme --version` stays fast.
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import time

MINE = ('certs', 'cert', 'cert_add', 'cert_edit', 'cert_del', 'renew', 'deploy', 'revoke',
        'csr', 'csr_answer', 'import_file', 'export', 'selfsigned', 'cas', 'ca_show',
        'ca_create', 'ca_sub', 'ca_import', 'ca_revoke', 'ca_crl', 'ca_export', 'ca_sign',
        'ca_del', 'sources', 'validations', 'targets', 'target_test', 'jobs', 'job', 'job_stop',
        'plugins', 'plugin', 'plugins_sync', 'module_mark', 'module_marks_export', 'checks',
        'check_run', 'check_attach', 'check_detach', 'tests', 'check_show', 'check_add',
        'check_edit', 'check_del', 'check_test', 'check_action', 'check_discover',
        'check_default', 'check_key', 'dns_records', 'dns_add', 'dns_del', 'deploys', 'deploy_add',
        'deploy_edit', 'deploy_del', 'deploy_run', 'acme_contact',
        'source_show', 'source_add', 'source_edit', 'source_del', 'source_test', 'source_action',
        'source_discover', 'validation_discover', 'target_discover',
        'validation_show', 'validation_add', 'validation_edit', 'validation_del',
        'validation_test', 'validation_action',
        'target_show', 'target_add', 'target_edit', 'target_del', 'target_action',
        'source_default', 'validation_default', 'target_default', 'ca_default',
        'ca_publish', 'ca_pki_urls', 'ca_pki_check', 'validation_check',
        'ca_edit', 'ca_renew', 'ca_versions', 'ca_install_cert',
        'check_names', 'cert_check', 'dry_run', 'target_key', 'validation_key',
        'dns_sets', 'dns_set_add', 'dns_set_edit', 'dns_set_del', 'dns_set_test', 'dns_assign',
        'teams', 'team_add', 'team_edit', 'team_del', 'tag_add', 'tag_del', 'teams_adopt')

# family: (the word of the options, the API's path, the words of one)
FAMILIES = {'issuer': ('source', 'sources', 'source'),
            'challenge': ('validation', 'validations', 'validation'),
            'target': ('target', 'targets', 'target'),
            'check': ('check', 'tests', 'test')}
CA_FORMATS = ('cert', 'cert-der', 'chain', 'crl', 'crl-der', 'p7b', 'bundle', 'csr', 'key',
              'p12', 'pfx')
CERT_SETS = ('names', 'issuer', 'challenge', 'key_type', 'key_type_alt', 'auto_renew',
             'renew_days', 'reuse_key', 'tags', 'note', 'owner', 'enabled', 'challenge_map.NAME',
             'profile.KEY')


def add_args(p):
    g = p.add_argument_group('CERTIFICATES', 'Certificates kept, renewed and deployed by acme. '
                             'What the pages do, these do (docs/command-line.md); with --json '
                             'each answers JSON.')
    g.add_argument('--certs', action='store_true', help='every certificate (--search TEXT)')
    g.add_argument('--cert', metavar='NAME', help='one certificate: its versions, deployments '
                   'and jobs')
    g.add_argument('--cert-add', metavar='NAME', help='a certificate to keep: --names, and '
                   '--issuer and --challenge (Let\'s Encrypt and this server\'s HTTP-01 when not '
                   'said); --set for more; issued by the next look, or --renew')
    g.add_argument('--cert-edit', metavar='NAME', help='change one: --names, --issuer, '
                   '--challenge, --key-type, --name NEW, --note, and --set KEY=VALUE for '
                   'auto_renew renew_days reuse_key tags owner enabled challenge_map.NAME '
                   'profile.KEY')
    g.add_argument('--cert-del', metavar='NAME', help='delete it, its versions and deployments '
                   '(--yes)')
    g.add_argument('--issuer', metavar='NAME', help='with --cert-add, --cert-edit: where it '
                   'comes from (acme --sources)')
    g.add_argument('--challenge', metavar='NAME', help='with --cert-add, --cert-edit: how its '
                   'names are proved (acme --validations)')
    g.add_argument('--key-type', metavar='TYPE', help='with --cert-add, --cert-edit, '
                   '--selfsigned, --ca-create, --ca-sub: ec-256 ec-384 rsa-2048 rsa-3072 '
                   'rsa-4096 ed25519')
    g.add_argument('--key-type-alt', metavar='TYPE|none', help='with --cert-add, --cert-edit: '
                   'a dual certificate - a twin of the same names with this key type too '
                   '(rsa-2048 beside ec-256, or ec-256 beside rsa-*), for clients that cannot '
                   'use ECDSA; none: no twin')
    g.add_argument('--renew', metavar='NAME|all', help='renew it now (all: every one due; with '
                   '--force every one acme can renew)')
    g.add_argument('--force', action='store_true', help='with --renew all: not only those due; '
                   'with --csr: a new request; with --acme-contact: on every ACME source')
    g.add_argument('--deploy', metavar='NAME', help='run its deployments now')
    g.add_argument('--revoke', metavar='NAME', help='revoke it where it was issued (--reason)')
    g.add_argument('--reason', metavar='WHY', default='unspecified', help='with --revoke, '
                   '--ca-revoke: unspecified keyCompromise cACompromise affiliationChanged '
                   'superseded cessationOfOperation certificateHold privilegeWithdrawn')
    g.add_argument('--csr', metavar='NAME|FILE', help='a request (CSR) for a certificate, for '
                   'an authority acme does not speak to: printed (or --out); with --ca-sign: '
                   'the CSR file to sign')
    g.add_argument('--csr-answer', nargs=2, metavar=('NAME', 'FILE'), help='the certificate '
                   'the authority sent back for that CSR')
    g.add_argument('--import', dest='import_file', metavar='FILE', help='a certificate from a '
                   'file (PEM, DER, PFX/P12, P7B, JKS...) - --name, --password')
    g.add_argument('--name', metavar='NAME', help='with --import, --ca-import: the name it is '
                   'kept under; with --*-edit: its new name')
    g.add_argument('--password', action='store_true', help='with --import, --export, '
                   '--ca-import, --ca-export: ask for the file\'s password (or '
                   'ACME_FILE_PASSWORD)')
    g.add_argument('--export', metavar='NAME', help='a certificate into a file: --format, --out')
    g.add_argument('--format', metavar='F', default='fullchain-pem', help='with --export: '
                   'cert-pem cert-der chain-pem fullchain-pem p7b key-pem key-rsa key-der '
                   'combined-pem pfx p12 p12-legacy jks [fullchain-pem]')
    g.add_argument('--variant', metavar='main|alt', default='main', help='with --export: of a '
                   'dual certificate the main one or its twin (alt; or ec, rsa) [main]')
    g.add_argument('--out', metavar='FILE', help='with --export, --csr, --ca-export, --ca-crl, '
                   '--ca-sign: where it goes (- for stdout)')
    g.add_argument('--selfsigned', metavar='NAME', help='a self-signed certificate for --names, '
                   'made now')
    g.add_argument('--jobs', action='store_true', help='the jobs, newest first (--limit)')
    g.add_argument('--job', metavar='ID', type=int, help='one job, every step (followed while it '
                   'runs)')
    g.add_argument('--job-stop', metavar='ID', type=int, help='stop a job that runs')
    g.add_argument('--acme-contact', metavar='MAIL', help='the contact e-mail of the ACME '
                   'sources that have none (Let\'s Encrypt mails about expiry and policy there)')
    g.add_argument('--check-names', metavar='N1,N2', help='before a certificate: what its names '
                   'need for validation and where (grouped by domain), each step checked now, '
                   'the exact records to create - nothing is changed (--issuer, --challenge)')
    g.add_argument('--cert-check', metavar='NAME', help='the same for a certificate acme keeps')
    g.add_argument('--dry-run', metavar='NAME|N1,N2', help='its validation tried for real '
                   'without a CA: a test record or file put in place, looked for from outside, '
                   'taken away (a job, followed; --issuer, --challenge for names)')

    g = p.add_argument_group('CERTIFICATES: SOURCES, VALIDATIONS AND TARGETS',
                             'Where certificates come from (sources: issuers), how names are '
                             'proved (validations: challenges), where they go (targets). Each '
                             'is a module (acme --plugins); its settings are --set KEY=VALUE '
                             '(acme --plugin KIND lists them; a secret as KEY=- is asked for, '
                             'never shown).')
    g.add_argument('--sources', action='store_true', help='where certificates come from')
    g.add_argument('--validations', action='store_true', help='how names are proved')
    g.add_argument('--targets', action='store_true', help='where certificates go')
    g.add_argument('--tests', action='store_true', help='the tests of what the servers serve '
                   '(defined as targets are; --check-add NAME --kind https --set ...)')
    for fam, (word, _path, _one) in FAMILIES.items():
        g.add_argument('--%s-show' % word, dest='%s_show' % word, metavar='NAME',
                       help='one %s: its settings (secrets: eight dots and their last two)%s' % (
                           word, ' and its deployments' if fam == 'target' else ''))
        g.add_argument('--%s-add' % word, dest='%s_add' % word, metavar='NAME',
                       help='a new %s: --kind and --set KEY=VALUE' % word)
        g.add_argument('--%s-edit' % word, dest='%s_edit' % word, metavar='NAME',
                       help='change one: --set KEY=VALUE (the others kept), --name NEW, '
                            '--enabled on|off, --kind (its settings then from nothing)')
        g.add_argument('--%s-del' % word, dest='%s_del' % word, metavar='NAME',
                       help='delete one nothing uses (--yes)')
        if fam != 'target':
            g.add_argument('--%s-test' % word, dest='%s_test' % word, metavar='NAME',
                           help='try it, changing nothing (--set: with these over its own)')
        g.add_argument('--%s-action' % word, dest='%s_action' % word, nargs=2,
                       metavar=('NAME', 'ACTION'), help='one of its module\'s actions (acme '
                       '--plugin KIND says which), e.g. --validation-action web prepare')
        g.add_argument('--%s-discover' % word, dest='%s_discover' % word, metavar='NAME',
                       help='find its settings from the account (read-only): what the module '
                            'reads there, shown; --fill puts it into the settings left empty '
                            '(--set: sign-in over its own; NAME - with --kind: one not saved)')
        g.add_argument('--%s-default' % word, dest='%s_default' % word, metavar='NAME',
                       help='make it the default %s (%s); none: no default' % (
                           word, {'issuer': 'a new certificate comes from it',
                                  'challenge': 'a new ACME certificate is proved by it',
                                  'target': 'offered first for a new deployment',
                                  'check': 'offered first when a test is attached'}[fam]))
    g.add_argument('--fill', action='store_true',
                   help='with --*-discover: save what was found into the settings left empty '
                        '(a choice: the one picked); nothing set is replaced')
    g.add_argument('--validation-check', nargs=2, metavar=('NAME', 'HOST'),
                   help='HTTP-01 answered by acme: a probe token put in place and fetched at '
                        'http://HOST/.well-known/acme-challenge/ from here, step by step')
    g.add_argument('--target-test', metavar='NAME', help='try a target: reach it, sign in, '
                   'change nothing')
    for word in ('target', 'validation', 'check'):
        g.add_argument('--%s-key' % word, dest='%s_key' % word, nargs='+', metavar='ARG',
                       help='NAME WHAT - the SSH key of a %s, as the key card of the page: '
                            'make [ed25519|rsa4096], show, public (its public half; --out), '
                            'own FILE (a private key of your own; its passphrase from '
                            'ACME_KEY_PASSWORD), private (the private half; --out), forget '
                            '(--yes), try (a sign-in that changes nothing)' % word)
    g.add_argument('--kind', metavar='KIND', help='with --*-add, --*-edit: the module '
                   '(acme --plugins)')
    g.add_argument('--enabled', choices=('on', 'off'), help='with --*-edit, --deploy-edit, '
                   '--cert-edit: switched on or off')
    g.add_argument('--plugins', action='store_true', help='the modules: issuers, challenges, '
                   'targets (and those that did not load)')
    g.add_argument('--plugins-sync', dest='plugins_sync', metavar='NODE',
                   help='modules of your own: write the files NODE keeps in the database '
                        '(every node keeps what it has) into this node\'s ACME_PLUGINS folder - '
                        'after a copy was put back, or to make a second node the same; '
                        '--remove also takes away files here NODE does not have (root, --yes)')
    g.add_argument('--remove', action='store_true', help='with --plugins-sync')
    g.add_argument('--checks', nargs='?', const='*', metavar='CERT',
                   help='the tests attached to the certificates (to one): how each went last')
    g.add_argument('--check-run', dest='check_run', metavar='WHAT',
                   help='run attached tests now: an ID, cert:NAME, test:NAME or all - each '
                        'result said')
    g.add_argument('--check-attach', dest='check_attach', nargs='+', metavar=('CERT', 'TEST'),
                   help='attach tests (Certificates → Tests) to a certificate')
    g.add_argument('--check-detach', dest='check_detach', metavar='ID',
                   help='take an attached test off its certificate (acme --checks says the ID)')
    g.add_argument('--module-mark', dest='module_mark', nargs=2, metavar=('MODULE', 'STATE'),
                   help='mark a module: family/kind[@version] tested|works|problem|none '
                        '(--note WORDS) - e.g. target/netscaler@14.1 works')
    g.add_argument('--module-marks-export', dest='module_marks_export', action='store_true',
                   help='the marks set here as acmelib/plugins/verified.json takes them - '
                        'what a release ships as checked')
    g.add_argument('--plugin', metavar='KIND', help='one module: its fields (what --set takes), '
                   'those of a deployment, its actions and help (family/kind where two '
                   'families have the kind)')

    g = p.add_argument_group('CERTIFICATES: DEPLOYMENTS', 'One certificate on one target, with '
                             'the options there (--set: the target module\'s deploy fields).')
    g.add_argument('--deploys', nargs='?', const='*', metavar='CERT', help='the deployments '
                   '(of one certificate)')
    g.add_argument('--deploy-add', nargs=2, metavar=('CERT', 'TARGET'), help='put CERT on '
                   'TARGET from now on: --set KEY=VALUE, --enabled')
    g.add_argument('--deploy-edit', metavar='ID', type=int, help='change one: --set, --enabled')
    g.add_argument('--deploy-del', metavar='ID', type=int, help='take one away (the device keeps '
                   'what it has; --yes)')
    g.add_argument('--deploy-run', metavar='ID', type=int, help='run one now (forced)')

    g = p.add_argument_group('CERTIFICATES: AUTHORITIES OF ACME\'S OWN')
    g.add_argument('--cas', action='store_true', help='acme\'s own certificate authorities')
    g.add_argument('--ca-show', metavar='CA', help='one authority and what it signed')
    g.add_argument('--ca-create', metavar='NAME', help='a new root authority: --subject, '
                   '--key-type, --days; --set crl_days crl_url aia_url ocsp_url path_len '
                   'name_constraints')
    g.add_argument('--ca-sub', metavar='NAME', help='a new intermediate under --parent (as '
                   '--ca-create)')
    g.add_argument('--parent', metavar='CA', help='with --ca-sub: the authority that signs it')
    g.add_argument('--subject', metavar='DN', help='with --ca-create, --ca-sub: "CN=Example '
                   'Root,O=Example"')
    g.add_argument('--ca-import', metavar='FILE', help='an authority from a file (PEM or PFX, '
                   'with its key; --key FILE, --name, --password)')
    g.add_argument('--key', metavar='FILE', help='with --ca-import: its key, in a file of its '
                   'own (password: ACME_KEY_PASSWORD)')
    g.add_argument('--ca-revoke', nargs=2, metavar=('CA', 'SERIAL'), help='revoke what it signed '
                   '(--reason); in its next CRL')
    g.add_argument('--ca-crl', metavar='CA', help='a new CRL, printed (or --out)')
    g.add_argument('--ca-export', metavar='CA', help='into a file: --what, --out [--password]')
    g.add_argument('--what', metavar='FORMAT', default='cert', help='with --ca-export: %s '
                   '[cert]' % ' '.join(CA_FORMATS))
    g.add_argument('--ca-sign', metavar='CA', help='sign a CSR from elsewhere: --csr FILE '
                   '[--days] [--set eku=serverAuth,clientAuth] [--out]')
    g.add_argument('--ca-del', metavar='CA', help='delete an authority no source uses (--yes)')
    g.add_argument('--ca-default', metavar='CA', help='make it the default authority (offered '
                   'first for an own-CA source and for signing a CSR); none: no default')
    g.add_argument('--ca-publish', nargs=2, metavar=('CA', 'on|off'), help='its CRL and '
                   'certificate published on acme at /pki/ (port 80), or not')
    g.add_argument('--ca-pki-urls', metavar='CA', help='acme\'s own /pki/ addresses put into '
                   'what it signs from now on (CRL and CA certificate)')
    g.add_argument('--ca-pki-check', metavar='CA', help='its published CRL and certificate '
                   'fetched over HTTP from here and checked with openssl')
    g.add_argument('--ca-edit', metavar='CA', help='change what is not in its certificate: '
                   '--set name= days_default= crl_days= crl_url= aia_url= ocsp_url= (own: '
                   'acme\'s own; for what it signs from now on) note= disabled=yes|no eku=')
    g.add_argument('--ca-renew', metavar='CA', help='its certificate made again with the same '
                   'key and subject: [--days N] [--path-len N|none] [--name-constraints '
                   'LIST|none]; what it signed stays valid')
    g.add_argument('--path-len', metavar='N', help='with --ca-renew: its new path length '
                   '(none: no limit; left out: as it is)')
    g.add_argument('--name-constraints', metavar='LIST', help='with --ca-renew: e.g. '
                   '"corp.example,IP:10.0.0.0/8,!DNS:bad.corp.example" (none: none; left out: '
                   'as they are)')
    g.add_argument('--ca-versions', metavar='CA', help='every certificate it has had')
    g.add_argument('--ca-install-cert', nargs=2, metavar=('CA', 'FILE'), help='the certificate '
                   'a CA elsewhere signed for it (its first, or a renewal\'s answer)')

    g = p.add_argument_group('CERTIFICATES: ACME\'S OWN DNS SERVER')
    g.add_argument('--dns-records', action='store_true', help='what acme\'s own DNS server '
                   'answers')
    g.add_argument('--dns-add', nargs=3, metavar=('NAME', 'TYPE', 'VALUE'), help='a record of '
                   'your own (@ for the zone; --ttl, --note)')
    g.add_argument('--ttl', type=int, metavar='S', help='with --dns-add: its TTL')
    g.add_argument('--dns-del', nargs='+', metavar='ID|NAME', help='take a record away: its id, '
                   'or NAME [TYPE [VALUE]] (--yes for more than one)')

    # Settings → DNS (acmelib/certs/api_dnssets.py, docs/dns-sets.md)
    g = p.add_argument_group('DNS SETS', 'Named sets of DNS servers, and which of them each '
                             'function of acme asks (Settings → DNS).')
    g.add_argument('--dns-sets', action='store_true', help='every set, and the set of each '
                   'function')
    g.add_argument('--dns-set-add', metavar='NAME', help='a new set: --servers ADDR,ADDR '
                   '(ADDR:PORT, [IPv6]:PORT), --protocol udp|tcp|dot, --tls-name, '
                   '--dns-timeout S, --note')
    g.add_argument('--dns-set-edit', metavar='NAME', help='change one: the same, --name NEW')
    g.add_argument('--dns-set-del', metavar='NAME', help='delete one (the functions it was '
                   'chosen for go back to their default)')
    g.add_argument('--dns-set-test', nargs='+', metavar='ARG', help='NAME QNAME [TYPE]: a name '
                   'looked up through a set (A AAAA TXT CNAME NS MX SOA ...), every server')
    g.add_argument('--dns-assign', nargs=2, metavar=('FUNCTION', 'SET'), help='a function '
                   '(validation public apis targets acme mail) asks SET; SET default: its default')
    g.add_argument('--servers', metavar='ADDR,ADDR', help='with --dns-set-add/-edit')
    g.add_argument('--protocol', choices=('udp', 'tcp', 'dot'), help='with --dns-set-add/-edit')
    g.add_argument('--tls-name', metavar='NAME', help='with --protocol dot: the server\'s name')
    g.add_argument('--dns-timeout', metavar='S', type=float, help='with --dns-set-add/-edit')

    # Settings → Owners and teams (acmelib/certs/api_teams.py, docs/teams.md)
    from acmelib.certs import api_teams
    api_teams.add_args(p)


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


def _onoff(v):
    return 'on' if v not in (0, '0', False, None) else 'off'


def _short(v, most=60):
    if isinstance(v, (list, tuple)):
        v = ', '.join(str(x) for x in v)
    elif isinstance(v, dict):
        v = json.dumps(v, ensure_ascii=False)
    v = str(v if v is not None else '')
    v = v.replace('\n', ' ')
    return v if len(v) <= most else v[:most - 1] + '…'


TRUE = ('1', 'true', 'yes', 'on', 'y')
FALSE = ('0', 'false', 'no', 'off', 'n', '')


def shown(f, cfg):
    """Is the field asked for, with these settings (its show_if)?"""
    cond = f.get('show_if') or {}
    for k, want in cond.items():
        v = cfg.get(k)
        if isinstance(v, bool):
            v = '1' if v else '0'
        if str(v if v is not None else '') not in [str(x) for x in (want or [])]:
            return False
    return True


def field_value(f, raw, cur=None):
    """One --set value made what the field's type wants - or SystemExit saying why."""
    t = f.get('type') or 'text'
    k = f['key']
    if t == 'number':
        try:
            n = float(raw)
        except ValueError:
            raise SystemExit('acme: %s is a number, not %r' % (k, raw))
        if 'min' in f and f['min'] is not None and n < float(f['min']):
            raise SystemExit('acme: %s: at least %s' % (k, f['min']))
        if 'max' in f and f['max'] is not None and n > float(f['max']):
            raise SystemExit('acme: %s: at most %s' % (k, f['max']))
        return int(n) if n == int(n) else n
    if t == 'bool':
        low = str(raw).strip().lower()
        if low in TRUE:
            return True
        if low in FALSE:
            return False
        raise SystemExit('acme: %s is on or off (yes/no, 1/0), not %r' % (k, raw))
    if t == 'select':
        opts = [str(o[0]) for o in (f.get('options') or [])]
        if opts and str(raw) not in opts and not (raw == '' and not f.get('required')):
            raise SystemExit('acme: %s is one of: %s' % (k, ', '.join(opts)))
        return str(raw)
    if t == 'list':
        s = str(raw)
        parts = s.split('\n') if '\n' in s else s.split(',')
        return [x.strip() for x in parts if x.strip()]
    return str(raw)


def as_list(v):
    if v in (None, ''):
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    return [x.strip() for x in re.split(r'[\n,]+', str(v)) if x.strip()]


class Cli(object):
    WHO = 'command line'

    def __init__(self, args):
        from acmelib import engine as E
        self.E = E
        self.args = args
        self.pal = E.TABLE_PAL or E.Palette(False)
        self.json = bool(getattr(args, 'json', False))
        self.files = {}

    def open(self):
        E = self.E
        self.store = E.cli_store()
        from acmelib.certs import api  # noqa: F401  (the routes)
        from acmelib.certs import defaults, notices, renewer
        notices.install(renewer)
        defaults.ensure(self.store)
        self.d = _Daemon(self.store)

    def api(self, method, path, body=None, args=None):
        return self.E.cli_api(self.d, self.WHO, method, path, body=body, args=args)

    def out(self, data):
        print(json.dumps(data, indent=2, default=str, ensure_ascii=False))

    def table(self, rows, heads):
        print(self.E.table(rows, heads))

    def done(self, words, data=None, ok=True):
        if self.json:
            self.out(data if data is not None else {'ok': ok, 'message': words})
        else:
            print(self.pal.ok_line(words) if ok else self.pal.bad_line(words))
        return 0 if ok else 1

    def kv(self, pairs, width=16):
        for k, v in pairs:
            if v in (None, '', [], {}):
                continue
            print('  %s %s' % (self.pal.info(('%-' + str(width) + 's') % k), _short(v, 200)))

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

    def sure(self, what):
        self.E.cli_sure(self.args, what)

    # ---- files: read as whoever typed it, before the service's account takes over ----------
    def _read(self, path, most=20 << 20):
        try:
            with open(path, 'rb') as f:
                data = f.read(most + 1)
        except OSError as e:
            raise SystemExit('acme: %s' % e)
        if len(data) > most:
            raise SystemExit('acme: %s is far bigger than a certificate file' % path)
        return data

    def read_files(self):
        a = self.args
        for one in a.set or []:
            k, _, v = one.partition('=')
            if v.startswith('@file:'):
                self.files[v[6:]] = self._read(v[6:]).decode('utf-8', 'replace')
        for path in (a.import_file, a.ca_import, a.key, (a.csr_answer or [None, None])[1],
                     a.csr if a.ca_sign else None,
                     (getattr(a, 'ca_install_cert', None) or [None, None])[1]):
            if path:
                self.files[path] = self._read(path)

    # ---- --set KEY=VALUE against a module's fields ----------------------------------------
    def sets(self):
        """[(key, op, value)] of --set: op '=' '+=' '-='."""
        out = []
        for one in self.args.set or []:
            m = re.match(r'^([A-Za-z0-9_.-]{1,80})([+-]?=)(.*)\Z', one, re.S)
            if not m:
                raise SystemExit('acme: --set takes KEY=VALUE (KEY+=VALUE adds to a list)')
            out.append((m.group(1), m.group(2), m.group(3)))
        return out

    def secret(self, key, v):
        E = self.E
        if v == '-':
            return E.ask_secret_value(key)
        if v == '@env':
            env = 'ACME_VALUE_' + re.sub(r'[^A-Za-z0-9]', '_', key).upper()
            if env not in os.environ:
                raise SystemExit('acme: %s=@env, and %s is not set - nothing saved' % (key, env))
            return os.environ[env]
        if v.startswith('@file:'):
            return self.files.get(v[6:], '')
        if v == '':
            return ''
        E.not_on_command_line(key, v, '--set %s=- asks for it (or reads one line of stdin, or '
                              'ACME_VALUE_%s)' % (key, key.upper()))
        return v

    def module_config(self, fields, cur=None, adding=False, what='', sets=None, need=True):
        """The settings of a module (or a deployment's options): what is set now
        (`cur`, secrets "" = kept) with --set over it, each checked against the
        module's fields. SystemExit says what is wrong."""
        fields = list(fields or [])
        by_key = {f['key']: f for f in fields}
        cfg = dict(cur or {})
        given = set()
        for k, op, v in (self.sets() if sets is None else sets):
            f = by_key.get(k)
            if f is None:
                raise SystemExit('acme: %s has no setting %s - it has: %s' % (
                    what or 'that module', k, ', '.join(by_key) or 'none'))
            if f.get('type') == 'secret' or (f.get('secret') and not v.startswith('@file:')):
                if op != '=':
                    raise SystemExit('acme: %s is a secret: %s=- asks for it' % (k, k))
                cfg[k] = self.secret(k, v)
            else:
                if v.startswith('@file:'):
                    v = self.files.get(v[6:], '')
                elif v in ('-', '@env') and f.get('type') in ('pem', 'textarea', 'text'):
                    v = self.secret(k, v)
                if op == '=':
                    cfg[k] = field_value(f, v)
                else:
                    if f.get('type') != 'list':
                        raise SystemExit('acme: %s is not a list: %s=VALUE' % (k, k))
                    have = as_list(cfg.get(k))
                    add = field_value(f, v)
                    cfg[k] = have + [x for x in add if x not in have] if op == '+=' else \
                        [x for x in have if x not in add]
            given.add(k)
        if adding:
            # A choice that fills others in (`fills`), as the page does.
            for f in fields:
                fills = f.get('fills') or {}
                if f['key'] in given and fills.get(str(cfg.get(f['key']))):
                    for k, v in fills[str(cfg[f['key']])].items():
                        if k not in given:
                            cfg[k] = v
        missing = []
        for f in fields if need else ():
            if not f.get('required') or not shown(f, cfg):
                continue
            v = cfg.get(f['key'])
            if (f.get('type') == 'secret' or f.get('secret')) and (
                    v == '' or self.E.is_masked(v)) and f['key'] in (cur or {}).get(
                    '__secret_set__', ()):
                continue
            if v in (None, '', []) and f.get('default') in (None, '', []):
                missing.append(f['key'])
        if missing:
            raise SystemExit('acme: %s needs %s (--set %s=...)' % (
                what or 'it', ', '.join(missing), missing[0]))
        cfg.pop('__secret_set__', None)
        return cfg

    # ---- the options -------------------------------------------------------------------
    def run(self):
        a = self.args
        self.read_files()
        self.open()
        if any(getattr(a, k, None) not in (None, False, '') for k in (
                'dns_sets', 'dns_set_add', 'dns_set_edit', 'dns_set_del', 'dns_set_test',
                'dns_assign')):
            from acmelib.certs import api_dnssets
            return api_dnssets.cli(self)
        if any(getattr(a, k, None) not in (None, False, '') for k in (
                'teams', 'team_add', 'team_edit', 'team_del', 'tag_add', 'tag_del',
                'teams_adopt')):
            from acmelib.certs import api_teams
            return api_teams.cli(self)
        for fam, word in (('target', 'target'), ('challenge', 'validation'), ('check', 'check')):
            if getattr(a, '%s_key' % word, None):
                from acmelib.certs import api_sshkeys
                return api_sshkeys.cli(self, fam, getattr(a, '%s_key' % word))
        for fam, (word, _p, _o) in FAMILIES.items():
            if getattr(a, '%s_add' % word, None):
                return self.fam_add(fam, getattr(a, '%s_add' % word))
            if getattr(a, '%s_edit' % word, None):
                return self.fam_edit(fam, getattr(a, '%s_edit' % word))
            if getattr(a, '%s_del' % word, None):
                return self.fam_del(fam, getattr(a, '%s_del' % word))
            if getattr(a, '%s_action' % word, None):
                return self.fam_action(fam, *getattr(a, '%s_action' % word))
            if getattr(a, '%s_discover' % word, None):
                return self.fam_discover(fam, getattr(a, '%s_discover' % word))
            if fam != 'target' and getattr(a, '%s_test' % word, None):
                return self.fam_test(fam, getattr(a, '%s_test' % word))
            if getattr(a, '%s_default' % word, None) is not None:
                return self.fam_default(fam, getattr(a, '%s_default' % word))
            if getattr(a, '%s_show' % word, None):
                return self.fam_show(fam, getattr(a, '%s_show' % word))
        if getattr(a, 'checks', None):
            return self.checks_list()
        if getattr(a, 'validation_check', None):
            return self.validation_check(*a.validation_check)
        if getattr(a, 'ca_default', None) is not None:
            return self.ca_default()
        for key in ('ca_edit', 'ca_renew', 'ca_versions', 'ca_install_cert'):
            if getattr(a, key, None):
                from acmelib.certs import api_cas
                ref = getattr(a, key)
                if key == 'ca_install_cert':
                    return api_cas.cli_install(self, ref[0], ref[1])
                return getattr(api_cas, 'cli_' + key[3:])(self, ref)
        steps = [('cert_add', self.cert_add), ('cert_edit', self.cert_edit),
                 ('cert_del', self.cert_del), ('selfsigned', self.selfsigned),
                 ('ca_create', self.ca_create), ('ca_sub', self.ca_create),
                 ('ca_import', self.ca_import), ('ca_revoke', self.ca_revoke),
                 ('ca_crl', self.ca_crl), ('ca_export', self.ca_export),
                 ('ca_sign', self.ca_sign), ('ca_del', self.ca_del), ('ca_show', self.ca_show),
                 ('ca_publish', self.ca_publish), ('ca_pki_urls', self.ca_pki_urls),
                 ('ca_pki_check', self.ca_pki_check),
                 ('import_file', self.do_import), ('renew', self.renew),
                 ('revoke', self.revoke), ('csr_answer', self.csr_answer), ('csr', self.csr),
                 ('deploy_add', self.deploy_add), ('deploy_edit', self.deploy_edit),
                 ('deploy_del', self.deploy_del), ('deploy_run', self.deploy_run),
                 ('deploy', self.deploy), ('deploys', self.deploys), ('export', self.export),
                 ('target_test', self.target_test), ('job_stop', self.job_stop),
                 ('job', self.job), ('cert', self.cert), ('certs', self.certs),
                 ('cas', self.cas), ('jobs', self.jobs), ('plugin', self.plugin),
                 ('plugins', self.plugins), ('plugins_sync', self.plugins_sync),
                 ('module_mark', self.module_mark), ('check_run', self.check_run),
                 ('check_attach', self.check_attach), ('check_detach', self.check_detach),
                 ('module_marks_export', self.module_marks_export), ('dns_add', self.dns_add), ('dns_del', self.dns_del),
                 ('dns_records', self.dns), ('acme_contact', self.acme_contact),
                 ('check_names', self.check_names), ('cert_check', self.cert_check),
                 ('dry_run', self.dry_run)]
        for key, fn in steps:
            if getattr(a, key, None) not in (None, False, ''):
                return fn()
        if a.sources or a.validations or a.targets or getattr(a, 'tests', False):
            return self.family('issuer' if a.sources else 'challenge' if a.validations
                               else 'check' if getattr(a, 'tests', False) else 'target')
        return None

    # ---- certificates ----------------------------------------------------------------------
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
        self.contact_hint()
        return 0

    def contact_hint(self):
        from acmelib.certs import defaults
        miss = defaults.contact_missing(self.store)
        if miss and not self.json:
            print(self.pal.dim('  %s %s no contact e-mail: acme --acme-contact you@example.com '
                               '(the CA mails about expiry and policy there)' % (
                                   ', '.join(miss), 'has' if len(miss) == 1 else 'have')))

    def cert(self):
        row = self.cert_ref(self.args.cert)
        got = self.api('GET', '/api/certs/one', args={'id': str(row['id'])})
        if self.json:
            self.out(got)
            return 0
        c = got['cert']
        p = self.pal
        print(p.head(c['name']) + '  ' + self.E.tone_cell(str(c.get('state') or ''), p))
        for k, v in (('names', ', '.join(c.get('names') or [])), ('key type', c.get('key_type')),
                     ('issuer', c.get('issuer') or '(none: imported)'),
                     ('challenge', c.get('challenge') or '-'),
                     ('challenge map', json.dumps(c.get('challenge_map') or {}) if c.get(
                         'challenge_map') else ''),
                     ('renewed', 'by itself, %s days before the end' % (
                         c.get('renew_days') or self.E.CONFIG.get('certs_renew_days'))
                      if c.get('auto_renew') else 'by hand'),
                     ('reuse key', 'yes' if c.get('reuse_key') else ''),
                     ('profile', json.dumps(c.get('profile')) if c.get('profile') else ''),
                     ('subject', c.get('subject_dn')), ('issued by', c.get('issuer_dn')),
                     ('serial', c.get('serial')), ('sha-256', c.get('fingerprint')),
                     ('valid', '%s - %s' % (_when(c.get('not_before')), _when(c.get('not_after')))
                      if c.get('not_after') else ''),
                     ('days left', c.get('days_left')), ('version', c.get('version')),
                     ('twin', self._twin_words(c)),
                     ('last error', c.get('last_error')),
                     ('next try', _when(c.get('next_try')) if c.get('next_try') else ''),
                     ('due', c.get('due')), ('owner', c.get('owner')), ('note', c.get('note')),
                     ('tags', ', '.join(c.get('tags') or [])),
                     ('switched', 'off' if not c.get('enabled', 1) else '')):
            if v not in (None, '', []):
                print('  %s %s' % (p.info('%-14s' % k), v))
        if got['versions']:
            print(p.head('\nversions'))
            self.table([[v['version'], _when(v['created']), v.get('why') or '',
                         v.get('serial') or '', _when(v.get('not_after'), '%Y-%m-%d'),
                         ('twin ' if v.get('variant') == 'alt' else '') +
                         ('revoked' if v.get('revoked') else '')] for v in got['versions']],
                       ['v', 'made', 'why', 'serial', 'ends', ''])
        if got['deploys']:
            print(p.head('\ndeployments'))
            self._deploy_table(got['deploys'], cert=False)
        if got['jobs']:
            print(p.head('\njobs'))
            self._job_table(got['jobs'][:10])
        return 0

    @staticmethod
    def _twin_words(c):
        """The twin of a dual certificate, in one line."""
        if not c.get('key_type_alt'):
            return ''
        alt = [v for v in c.get('variants') or [] if v.get('variant') == 'alt']
        alt = alt[0] if alt else {}
        if not alt.get('issued'):
            return '%s - not issued yet%s' % (c['key_type_alt'], (': ' + alt['error'])
                                              if alt.get('error') else '')
        return '%s, version %s, serial %s, until %s%s%s' % (
            c['key_type_alt'], alt.get('version'), alt.get('serial') or '?',
            _when(alt.get('not_after'), '%Y-%m-%d'),
            ', sha-256 %s' % alt['fingerprint'] if alt.get('fingerprint') else '',
            ' - FAILED: %s' % alt['error'] if alt.get('state') == 'failed' else '')

    def _cert_body(self, row=None):
        """--names, --issuer, --challenge, --key-type, --name, --note, --enabled
        and --set KEY=VALUE as the fields of /api/certs/save."""
        a = self.args
        b = {}
        if a.names:
            b['names'] = [n.strip() for n in a.names.split(',') if n.strip()]
        if a.issuer is not None:
            b['issuer'] = a.issuer
        if a.challenge is not None:
            b['challenge'] = a.challenge
        if a.key_type:
            b['key_type'] = a.key_type
        if getattr(a, 'key_type_alt', None) is not None:
            b['key_type_alt'] = '' if a.key_type_alt.strip().lower() in ('none', '-', '') \
                else a.key_type_alt.strip()
        if row is not None and a.name:
            b['name'] = a.name
        if a.note:
            b['note'] = a.note
        if a.enabled:
            b['enabled'] = 1 if a.enabled == 'on' else 0
        cur = None
        if row is not None:
            cur = self.api('GET', '/api/certs/one', args={'id': str(row['id'])})['cert']
        for k, op, v in self.sets():
            if k in ('auto_renew', 'reuse_key', 'enabled'):
                low = v.strip().lower()
                if low not in TRUE + FALSE:
                    raise SystemExit('acme: %s is on or off' % k)
                b[k] = 1 if low in TRUE else 0
            elif k == 'renew_days':
                if v.strip() in ('', '0'):
                    b[k] = None
                elif not v.strip().isdigit():
                    raise SystemExit('acme: renew_days is a number of days (0: the setting\'s)')
                else:
                    b[k] = int(v)
            elif k in ('names', 'tags'):
                have = list((cur or {}).get(k) or []) if op != '=' else []
                vals = as_list(v)
                b[k] = have + [x for x in vals if x not in have] if op != '-=' else \
                    [x for x in list((cur or {}).get(k) or []) if x not in vals]
            elif k in ('issuer', 'challenge', 'key_type', 'note', 'owner'):
                b[k] = v
            elif k == 'key_type_alt':
                b[k] = '' if v.strip().lower() in ('none', '-', '') else v.strip()
            elif k.startswith('challenge_map.') and len(k) > 14:
                cmap = b.setdefault('challenge_map', dict((cur or {}).get('challenge_map') or {}))
                if v:
                    cmap[k[14:]] = v
                else:
                    cmap.pop(k[14:], None)
            elif k.startswith('profile.') and len(k) > 8:
                prof = b.setdefault('profile', dict((cur or {}).get('profile') or {}))
                path = k[8:].split('.')
                at = prof
                for part in path[:-1]:
                    at = at.setdefault(part, {}) if isinstance(at.get(part, {}), dict) else {}
                last = path[-1]
                if v == '':
                    at.pop(last, None)
                elif last in ('eku',) or op != '=':
                    at[last] = as_list(v)
                elif last in ('must_staple',):
                    at[last] = v.strip().lower() in TRUE
                elif last == 'days' and v.strip().isdigit():
                    at[last] = int(v)
                else:
                    at[last] = v
            else:
                raise SystemExit('acme: a certificate has no %s - --set takes %s' % (
                    k, ' '.join(CERT_SETS)))
        return b

    def cert_add(self):
        a = self.args
        b = self._cert_body()
        b['name'] = a.cert_add
        b.setdefault('names', [])
        b.setdefault('key_type', 'ec-256')
        b.setdefault('auto_renew', 1)
        got = self.api('POST', '/api/certs/save', body=b)
        from acmelib.certs import store as S
        row = S.cert_get(self.store, got['id']) or {}
        if self.json:
            self.out(dict(got, issuer=row.get('issuer'), challenge=row.get('challenge')))
        else:
            print(self.pal.ok_line('%s added (id %s, from %s%s) - acme --renew %s issues it now'
                                   % (a.cert_add, got['id'], row.get('issuer') or 'nowhere yet',
                                      ', proved by %s' % row['challenge'] if row.get('challenge')
                                      else '', a.cert_add)))
            self.contact_hint()
        return 0

    def cert_edit(self):
        row = self.cert_ref(self.args.cert_edit)
        b = self._cert_body(row)
        if not b:
            raise SystemExit('acme: nothing to change - --names, --issuer, --challenge, '
                             '--key-type, --key-type-alt, --name, --note, --enabled, --set %s' % ' '.join(
                                 CERT_SETS))
        b['id'] = row['id']
        got = self.api('POST', '/api/certs/save', body=b)
        return self.done('%s changed: %s' % (b.get('name') or row['name'], ', '.join(
            sorted(k for k in b if k != 'id'))), got)

    def cert_del(self):
        row = self.cert_ref(self.args.cert_del)
        self.sure('the certificate %s is deleted, with its versions and deployments' %
                  row['name'])
        got = self.api('POST', '/api/certs/delete', body={'id': row['id']})
        return self.done(got.get('message') or 'deleted', got)

    def _run_job(self, kind, fn, cert_id, said, target=None):
        from acmelib.certs import jobs
        if not self.json:
            print(self.pal.dim('  %s: %s' % (kind, said)))
        try:
            job = jobs.run_now(self.store, kind, fn, cert_id=cert_id, target=target, by=self.WHO,
                               said=said, echo=None if self.json else self.echo)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        if self.json:
            one = {'job_id': job.id, 'ok': job.ok, 'said': job.said, 'steps': job.steps}
            if getattr(self, '_jobs_json', None) is not None:
                self._jobs_json.append(one)     # one document for them all (1.0.45)
            else:
                self.out(one)
        else:
            line = 'job %d: %s' % (job.id, job.said or job.state)
            print(self.pal.ok_line(line) if job.ok else self.pal.bad_line(line))
        return job

    def _follow(self, job_id):
        """A job started in this process's pool, waited for (steps as they come)."""
        from acmelib.certs import jobs
        seen = 0
        while True:
            v = jobs.job_view(self.store, job_id)
            if not self.json:
                for st in v['steps'][seen:]:
                    self.echo(st)
            seen = len(v['steps'])
            if v.get('state') not in ('queued', 'running'):
                return v
            time.sleep(0.3)

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
            self._jobs_json = [] if self.json else None
            for r in todo:
                if r.get('state') in ('pending-approval', 'declined'):
                    continue                    # never past the approval (1.0.45)
                only = 'alt' if not a.force and not renewer.main_due(r) else None
                try:
                    job = self._run_job('renew', renewer.renew_job(r['id'], a.force, self.WHO,
                                                                   only),
                                        r['id'], '%s: %s' % (r['name'], renewer.due_why(r) or
                                                             'forced'))
                except SystemExit as e:
                    # One busy (a job on it already): said, and the others go on (1.0.45).
                    bad += 1
                    if self._jobs_json is not None:
                        self._jobs_json.append({'cert': r['name'], 'ok': False, 'said': str(e)})
                    else:
                        print(str(e), file=sys.stderr)
                    continue
                bad += 0 if job.ok else 1
            if self._jobs_json is not None:
                self.out({'jobs': self._jobs_json})
                self._jobs_json = None
            return 1 if bad else 0
        row = self.cert_ref(a.renew)
        if not row.get('issuer'):
            raise SystemExit('acme: %s has no issuer (imported?) - import the new one instead'
                             % row['name'])
        job = self._run_job('renew', renewer.renew_job(row['id'], a.force, self.WHO), row['id'],
                            '%s, asked on the command line' % S.cert_get(self.store,
                                                                         row['id'])['name'])
        return 0 if job.ok else 1

    # ---- before a certificate: what its validation needs ------------------------------------
    def _names_arg(self, text):
        names = [x.strip() for x in re.split(r'[\s,;]+', str(text or '')) if x.strip()]
        if not names:
            raise SystemExit('acme: no names (N1,N2,...)')
        return names

    def _plan_ref(self):
        from acmelib.certs import store as S
        a = self.args
        if a.issuer and not S.plugin_row(self.store, 'issuer', a.issuer):
            raise SystemExit('acme: there is no source %s (acme --sources)' % a.issuer)
        if a.challenge and not S.plugin_row(self.store, 'challenge', a.challenge):
            raise SystemExit('acme: there is no validation %s (acme --validations)' % a.challenge)
        return a.issuer or None, a.challenge or None

    def check_names(self):
        from acmelib.certs import readiness
        issuer, challenge = self._plan_ref()
        got = readiness.plan(self.store, self._names_arg(self.args.check_names), issuer=issuer,
                             challenge=challenge)
        return self.show_plan(got)

    def cert_check(self):
        from acmelib.certs import readiness
        row = self.cert_ref(self.args.cert_check)
        names, issuer, _challenge, _cmap = readiness.cert_args(row)
        got = readiness.plan(self.store, names, issuer=issuer, cert=row)
        return self.show_plan(got, row['name'])

    def show_plan(self, got, title=None):
        from acmelib.certs import readiness
        if self.json:
            self.out(got)
            return 0 if got.get('ok') else 1
        p = self.pal
        mark = {True: p.good('✔' if p.on else '[ ok ]'), False: p.bad('✘' if p.on else '[fail]'),
                None: p.dim('?' if p.on else '[ ?? ]')}
        print(p.info('%s - source %s%s' % (title or 'these names', got.get('issuer') or '(none)',
                                          '' if got.get('issuer_needs_validation') else
                                          ' (no validation needed)')))
        for st in (got.get('head') or {}).get('steps') or []:
            print('  %s %s' % (mark[st['done']], readiness.step_line(st)))
        for g in got.get('groups') or []:
            print('')
            print('%s  %s' % (p.info(g['domain']), ', '.join(g['names'])))
            print('  %s %s' % (p.dim('validation'), ('%s (%s)' % (g['validation'], g['kind']))
                               if g['validation'] else '-'))
            for st in (g.get('guide') or {}).get('steps') or []:
                done = st['done']
                tone = (lambda x: x) if done is not False else (p.bad if st['blocking'] else p.warn)
                where = ('  [%s]' % st['where']) if st.get('where') else ''
                line = st['what'] + (': ' + st['said'] if st.get('said') else '')
                print('  %s %s%s' % (mark[done], tone(line), p.dim(where)))
                if done is not True and st.get('fix'):
                    print('      %s %s' % (p.dim('->'), st['fix']))
                if st.get('record') and done is not True and \
                        not str(st['record'].get('value') or '').startswith('('):
                    print('      %s %s' % (p.dim('record'), readiness.record_text(st['record'])))
            for s in g.get('suggested') or []:
                print('  %s %s - %s' % (p.dim('could be'), s['validation'] or
                                        '(new) ' + s['kind'], s['why']))
        print('')
        if not got.get('complete', True):
            print(p.warn('not every check finished in time'))
        if got.get('ok'):
            print(p.ok_line('nothing that blocks was found - a dry run tries it for real '
                            '(acme --dry-run)'))
            return 0
        print(p.bad_line('%d thing(s) to set up first: %s' % (len(got.get('blocking') or []),
                                                               readiness.fixes(got))))
        return 1

    def dry_run(self):
        from acmelib.certs import readiness, store as S
        a = self.args
        row = S.cert_get(self.store, a.dry_run) if ',' not in a.dry_run else None
        try:
            if row:
                names = readiness.cert_args(row)[0]
                jid = readiness.dry_run(self.store, names, cert=row, by=self.WHO,
                                        cert_id=row['id'])
            else:
                issuer, challenge = self._plan_ref()
                jid = readiness.dry_run(self.store, self._names_arg(a.dry_run), issuer=issuer,
                                        challenge=challenge, by=self.WHO)
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        if not self.json:
            print(self.pal.dim('  dry run: job %d' % jid))
        v = self._follow(jid)
        if self.json:
            self.out({'job_id': jid, 'ok': bool(v.get('ok')), 'said': v.get('said'),
                      'result': readiness.dry_run_result(self.store, jid),
                      'steps': v.get('steps')})
        else:
            line = 'job %d: %s' % (jid, v.get('said') or v.get('state'))
            print(self.pal.ok_line(line) if v.get('ok') else self.pal.bad_line(line))
        return 0 if v.get('ok') else 1

    def revoke(self):
        from acmelib.certs import api, renewer
        a = self.args
        row = self.cert_ref(a.revoke)
        if a.reason not in api.REVOKE_REASONS:
            raise SystemExit('acme: the reason is one of %s' % ', '.join(api.REVOKE_REASONS))
        self.sure('%s is revoked at %s (%s) - it cannot be taken back' % (
            row['name'], row.get('issuer') or '?', a.reason))
        by = self.WHO

        def fn(job):
            return renewer.revoke_cert(job.store, job, row['id'], a.reason, by)
        job = self._run_job('revoke', fn, row['id'], 'reason: %s' % a.reason)
        return 0 if job.ok else 1

    def csr(self):
        a = self.args
        row = self.cert_ref(a.csr)
        got = self.api('POST', '/api/certs/csr', body={'id': row['id'], 'again': bool(a.force)})
        if a.out and a.out != '-':
            self._write(a.out, got['csr_pem'].encode('ascii'), 0o644)
            return self.done('%s written: the request of %s - give it to the authority, then acme '
                             '--csr-answer %s FILE' % (a.out, row['name'], row['name']),
                             dict(got, file=a.out))
        if self.json:
            self.out(got)
        else:
            sys.stdout.write(got['csr_pem'] if got['csr_pem'].endswith('\n') else
                             got['csr_pem'] + '\n')
        return 0

    def csr_answer(self):
        name, path = self.args.csr_answer
        row = self.cert_ref(name)
        got = self.api('POST', '/api/certs/csr_answer', body={
            'id': row['id'], 'data_b64': base64.b64encode(self.files[path]).decode('ascii'),
            'filename': os.path.basename(path)})
        ok = True
        if got.get('job_id'):
            if not self.json:
                print(self.pal.dim('  its deployments: job %s' % got['job_id']))
            v = self._follow(got['job_id'])
            ok = bool(v.get('ok'))
            got['deploy'] = {'ok': ok, 'said': v.get('said')}
        return self.done('the answer of %s is version %s%s' % (
            row['name'], got.get('version'), (' - deployed: %s' % got['deploy']['said'])
            if got.get('deploy') else ''), got, ok)

    def deploy(self):
        from acmelib.certs import deployer
        row = self.cert_ref(self.args.deploy)
        if not row.get('cert_pem'):
            raise SystemExit('acme: %s has not been issued yet' % row['name'])
        job = self._run_job('deploy', deployer.deploy_job(row['id'], force=True), row['id'],
                            'the deployments of %s' % row['name'])
        return 0 if job.ok else 1

    def _password(self, twice):
        if not self.args.password:
            return ''
        return self.E.ask_password('the file\'s password', twice=twice, env='ACME_FILE_PASSWORD')

    def do_import(self):
        a = self.args
        data = self.files[a.import_file]
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

    def _write(self, path, data, mode=0o600):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
        except OSError as e:
            raise SystemExit('acme: %s: %s' % (path, e))

    def _stdout(self, data):
        sys.stdout.flush()
        out = getattr(sys.stdout, 's', sys.stdout)
        out = getattr(out, 'buffer', None)
        if out is None:
            sys.stdout.write(data.decode('utf-8', 'replace'))
        else:
            out.write(data)
            out.flush()

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
                                                          'password': pw,
                                                          'variant': a.variant or 'main'})
        data = base64.b64decode(got['data_b64'])
        if a.out == '-':
            self._stdout(data)
            return 0
        self._write(a.out, data)
        if self.json:
            self.out({'file': a.out, 'format': a.format, 'bytes': len(data)})
        else:
            print(self.pal.ok_line('%s written (%s%s, %d bytes)' % (
                a.out, a.format, ', the twin (%s)' % got.get('key_type')
                if got.get('variant') == 'alt' else '', len(data))))
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
        body = {'name': a.selfsigned, 'names': names, 'issuer': iss['name'], 'challenge': '',
                'key_type': a.key_type or 'ec-256', 'auto_renew': 1}
        if row:
            # Asked first (1.0.45): a certificate of that name - one of Let's Encrypt's - was
            # made self-signed, issued and deployed without a word.
            if row.get('issuer') != iss['name'] or json.dumps(sorted(S.jload(row.get('names'), []) or [])) \
                    != json.dumps(sorted(names)):
                self.sure('%s is there already (from %s): it becomes a self-signed certificate '
                          'for %s, issued and deployed now' % (row['name'], row.get('issuer') or '-',
                                                                ', '.join(names)))
            body['id'] = row['id']
        if a.days is not None:
            if a.days < 1 or a.days > 36500:
                raise SystemExit('acme: --days is 1 to 36500')
            body['profile'] = {'days': a.days}
        got = self.api('POST', '/api/certs/save', body=body)
        job = self._run_job('renew', renewer.renew_job(got['id'], True, self.WHO), got['id'],
                            'a self-signed certificate for %s' % ', '.join(names))
        return 0 if job.ok else 1

    def acme_contact(self):
        from acmelib.certs import api
        try:
            done = api.acme_contact(self.store, self.args.acme_contact, self.WHO,
                                    every=bool(self.args.force))
        except ValueError as e:
            raise SystemExit('acme: %s' % e)
        return self.done(('the contact e-mail of %s is %s' % (', '.join(done),
                                                               self.args.acme_contact))
                         if done else 'every ACME source has a contact e-mail already (--force '
                         'sets it on all)', {'sources': done})

    # ---- jobs --------------------------------------------------------------------------------
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
        try:
            while True:
                for st in v['steps'][seen:]:
                    self.echo(st)
                seen = len(v['steps'])
                if not v.get('live'):
                    break
                time.sleep(1)
                v = jobs.job_view(self.store, ident)
        except KeyboardInterrupt:
            print('\n' + p.dim('no longer followed here - it goes on (acme --job-stop %d stops '
                               'it)' % ident))
            return 0
        line = '%s%s' % (v.get('state'), (': ' + v['said']) if v.get('said') else '')
        print(p.ok_line(line) if v.get('ok') else p.bad_line(line))
        return 0 if v.get('ok') else 1

    def job_stop(self):
        got = self.api('POST', '/api/certs/job_stop', body={'id': self.args.job_stop})
        return self.done(got.get('message') or 'asked to stop', got)

    # ---- sources, validations, targets ------------------------------------------------------
    def fam_row(self, fam, name):
        from acmelib.certs import store as S
        row = S.plugin_row(self.store, fam, name)
        if not row:
            word, path, _o = FAMILIES[fam]
            raise SystemExit('acme: there is no %s %s (acme --%s)' % (word, name, path))
        return row

    def fam_fields(self, fam, kind, attr='fields'):
        from acmelib.certs import api, store as S
        cls = S.plugin_class(fam, kind)
        if cls is None:
            word = FAMILIES[fam][0]
            have = sorted(S.registry().all(fam))
            raise SystemExit('acme: there is no %s module "%s" - there are: %s' % (
                word, kind, ', '.join(have)))
        return cls, api._resolve(self.store, getattr(cls, attr, None) or [])

    def family(self, fam):
        path = FAMILIES[fam][1]
        got = self.api('GET', '/api/%s' % path)
        if self.json:
            self.out(got)
            return 0
        self.table([[r['id'], r['name'] + (' *' if r.get('is_default') else ''),
                     r['kind'] + (' (module missing)' if r.get('module_missing') else ''),
                     _onoff(r.get('enabled', 1)), r.get('used_by'), _when(r.get('last_ok')),
                     (r.get('last_error') or '')[:50]] for r in got['rows']],
                   ['id', 'name', 'kind', '', 'used by', 'last ok', 'last error'])
        if any(r.get('is_default') for r in got['rows']):
            print(self.pal.dim('  * what a new certificate takes when none is said'))
        if fam == 'issuer':
            self.contact_hint()
        return 0

    def fam_show(self, fam, name):
        from acmelib.certs import store as S
        row = self.fam_row(fam, name)
        pub = S.plugin_public(self.store, fam, row, True)
        cls = S.row_class(fam, row)
        deps = []
        if fam == 'target':
            from acmelib.certs import api
            deps = api.deploy_rows(self.store, target=row['name'], full=True)
        if self.json:
            self.out(dict(pub, deploys=deps) if fam == 'target' else pub)
            return 0
        p = self.pal
        print('%s  %s (%s)%s' % (p.head(row['name']), row['kind'], pub.get('title'),
                                 '' if row.get('enabled', 1) else '  ' + p.bad('off')))
        cfg = pub.get('config') or {}
        rows = []
        for f in (cls.fields if cls else []) or []:
            k = f['key']
            if f.get('type') == 'secret' or f.get('secret'):
                # Dots and its last two (the command line is root on the box).
                v = cfg.get(k) or 'not set'
            else:
                v = cfg.get(k)
                v = _short(v, 70) if v not in (None, '', []) else (
                    p.dim('(%s)' % _short(f.get('default'), 40)) if f.get('default') not in
                    (None, '', []) else '-')
            rows.append([k, v, f.get('label') or ''])
        extra = [k for k in cfg if not any(f['key'] == k for f in (cls.fields if cls else []))]
        for k in extra:
            rows.append([k, _short(cfg[k], 70), p.dim('(not a field of the module)')])
        if rows:
            self.table(rows, ['setting', 'value', 'what'])
        self.kv([('used by', pub.get('used_by')), ('last ok', _when(pub.get('last_ok'))
                                                   if pub.get('last_ok') else ''),
                 ('last error', pub.get('last_error')), ('note', pub.get('note')),
                 ('actions', ', '.join('%s (%s)' % (a['key'], a.get('label') or '')
                                       for a in pub.get('actions') or [])),
                 ('default', 'yes - a new certificate takes it' if pub.get('is_default') else '')])
        if fam == 'target':
            print(p.head('\ndeployments'))
            self._deploy_table(deps, target=False)
        if fam == 'challenge':
            self.http_info(row)
            if row.get('kind') == 'dns_persist':
                self.persist_info(row)
        return 0

    def persist_info(self, row):
        """dns-persist-01: the record for each ACME source, whether it is there, and
        whether each CA offers it yet (POST /api/validations/persist)."""
        got = (self.api('POST', '/api/validations/persist', body={'id': row['id']}) or {}).get(
            'persist') or {}
        p = self.pal
        print(p.head('\nthe record to set once (dns-persist-01)'))
        for c in got.get('cas') or []:
            print('  %s %s' % (p.good('✔') if c.get('offered') else p.dim('·'), c.get('words')))
        for r in got.get('records') or []:
            rec = r.get('record') or {}
            mark = p.good('✔') if r.get('ok') else p.bad('✘') if r.get('ok') is False else '?'
            print('  %s %s (%s)%s' % (mark, r.get('title') or r['source'], r['source'],
                                      (' ' + r['domain']) if r.get('domain') else ''))
            if rec.get('value'):
                print('      %s. TXT "%s"' % (rec['name'], rec['value']))
            if r.get('error') or r.get('said'):
                print('      ' + p.dim(r.get('error') or r.get('said')))
        if not got.get('domains'):
            print(p.dim('  set the domains of the validation to see the exact record'))
        print(p.dim('  acme --validation-action %s record   makes the ACME accounts where there '
                    'are none and prints the record' % row['name']))

    def http_info(self, row):
        """HTTP-01 answered by acme: how it works here (GET /api/validations/info)."""
        got = self.api('GET', '/api/validations/info', args={'id': str(row['id'])})
        if not got.get('applies'):
            return
        p = self.pal
        print(p.head('\nhow it works here'))
        print('  the CA fetches  http://NAME%s<token>  (port 80, plain HTTP - the path is '
              'fixed by the ACME standard, RFC 8555)' % got['path'])
        rows = [[n['name'] + (' (this one)' if n.get('me') else ''), n.get('dns') or '-',
                 n.get('address') or '-', 'alive' if n.get('alive') else p.bad('not heard'),
                 'holds the VIP' if n.get('vip_here') else ''] for n in got['nodes']]
        v = got.get('vip') or {}
        if v.get('on'):
            rows.append(['VIP', v.get('fqdn') or '-', ', '.join(x for x in (
                v.get('address'), v.get('address6')) if x) or '-', '',
                'on %s' % v['holder'] if v.get('holder') else ''])
        self.table(rows, ['answered by', 'name', 'address', '', ''])
        print(p.head('\nport 80'))
        self.table([[f['node'], ('open' if f.get('open') else p.bad('closed')) if
                     f.get('open') is not None else '?',
                     'from anywhere' if f.get('from_anywhere') else '', f.get('why') or '']
                    for f in got.get('firewall') or []], ['node', 'port 80', '', 'why'])
        print(p.head('\nnames proved by it'))
        if not got.get('names'):
            print('  ' + p.dim('no certificate uses it yet'))
        else:
            self.table([[n['name'], n.get('cert') or '', ', '.join(n.get('addresses') or [])
                         or '-', (p.good('✔') if n.get('ours') else p.bad('✘') if
                                  n.get('ours') is False else '?'), _short(n.get('words'), 90)]
                        for n in got['names']], ['name', 'certificate', 'resolves to', '',
                                                 'what that means'])
        if got.get('names_more'):
            print('  ' + p.dim('and %d more' % got['names_more']))
        print(p.dim('\n  acme --validation-check %s NAME   fetches a probe token at that name '
                    'from here' % row['name']))

    def validation_check(self, name, host):
        row = self.fam_row('challenge', name)
        got = self.api('POST', '/api/validations/check', body={'id': row['id'], 'host': host})
        if self.json:
            self.out(got)
            return 0 if got.get('ok') else 1
        for st in got.get('steps') or []:
            self.echo(st)
        return self.done(got.get('said') or '', got, ok=bool(got.get('ok')))

    def fam_default(self, fam, name):
        word, path, _o = FAMILIES[fam]
        name = '' if str(name).strip().lower() in ('', 'none', '-') else name
        if name:
            name = self.fam_row(fam, name)['name']
        got = self.api('POST', '/api/%s/default' % path, body={'name': name})
        return self.done(got.get('message') or 'done', got)

    def _enabled(self):
        e = self.args.enabled
        return None if not e else (1 if e == 'on' else 0)

    def fam_add(self, fam, name):
        a = self.args
        word, path, _o = FAMILIES[fam]
        if not a.kind:
            from acmelib.certs import store as S
            raise SystemExit('acme: which module? --kind (one of: %s)' % ', '.join(
                sorted(S.registry().all(fam))))
        cls, fields = self.fam_fields(fam, a.kind)
        cfg = self.module_config(fields, {}, adding=True, what='%s (%s)' % (name, a.kind))
        body = {'name': name, 'kind': a.kind, 'config': cfg, 'note': a.note or ''}
        if self._enabled() is not None:
            body['enabled'] = self._enabled()
        got = self.api('POST', '/api/%s/save' % path, body=body)
        return self.done('%s %s added (id %s, %s)%s' % (
            word, name, got['id'], a.kind, ' - acme --%s-test %s tries it' % (word, name)
            if fam != 'target' else ' - acme --target-test %s tries it' % name), got)

    def fam_edit(self, fam, name):
        from acmelib.certs import store as S
        a = self.args
        word, path, _o = FAMILIES[fam]
        row = self.fam_row(fam, name)
        kind = a.kind or row['kind']
        cls, fields = self.fam_fields(fam, kind)
        pub = S.plugin_public(self.store, fam, row, True)
        cur = dict(pub.get('config') or {}) if kind == row['kind'] else {}
        if kind == row['kind']:
            cur['__secret_set__'] = list(pub.get('secret_set') or [])
        body = {'id': row['id'], 'kind': kind}
        if self.sets() or kind != row['kind']:
            body['config'] = self.module_config(fields, cur, adding=kind != row['kind'],
                                                what='%s (%s)' % (row['name'], kind))
        if a.name:
            body['name'] = a.name
        if a.note:
            body['note'] = a.note
        if self._enabled() is not None:
            body['enabled'] = self._enabled()
        if len(body) == 2 and kind == row['kind']:
            raise SystemExit('acme: nothing to change - --set KEY=VALUE, --name, --note, '
                             '--enabled, --kind')
        got = self.api('POST', '/api/%s/save' % path, body=body)
        return self.done('%s %s changed' % (word, a.name or row['name']), got)

    def fam_del(self, fam, name):
        word, path, _o = FAMILIES[fam]
        row = self.fam_row(fam, name)
        self.sure('the %s %s is deleted, with its settings and secrets' % (word, row['name']))
        got = self.api('POST', '/api/%s/delete' % path, body={'id': row['id']})
        return self.done(got.get('message') or 'deleted', got)

    def fam_test(self, fam, name):
        from acmelib.certs import api
        row = self.fam_row(fam, name)
        body = {'id': row['id']}
        if self.sets():
            _cls, fields = self.fam_fields(fam, row['kind'])
            body['config'] = self.module_config(fields, {}, what=row['name'], need=False)
        got = api.family_test(self.store, fam, body, self.WHO,
                              echo=None if self.json else self.echo)
        if self.json:
            self.out(got)
        else:
            print(self.pal.ok_line(got['said']) if got['ok'] else self.pal.bad_line(got['said']))
        return 0 if got['ok'] else 1

    def fam_discover(self, fam, name):
        """--source-discover NAME (--validation-, --target-): what discovery finds
        (api_discover.py, read-only), shown; --fill saves it into the empty settings."""
        from acmelib.certs import api_discover
        from acmelib.certs import store as S
        a = self.args
        word, path, _o = FAMILIES[fam]
        row = None if name == '-' else self.fam_row(fam, name)
        kind = (row or {}).get('kind') or a.kind
        if not kind:
            raise SystemExit('acme: --%s-discover - needs --kind' % word)
        cls, fields = self.fam_fields(fam, kind)
        if not cls.discover_offered():
            raise SystemExit('acme: %s finds no settings by itself - set them with --set'
                             % (cls.title or kind))
        body = {'kind': kind, 'name': (row or {}).get('name') or 'unsaved'}
        if row:
            body['id'] = row['id']
        if self.sets() or not row:
            body['config'] = self.module_config(fields, {}, what=kind, need=False)
        got = api_discover.discover(self.store, fam, body, self.WHO)
        found = got.get('found') or {}
        saved = S.plugin_config(fam, row) if row else dict(body.get('config') or {})
        label = {f['key']: f.get('label') or f['key'] for f in fields}

        def empty(k):
            v = saved.get(k)
            f = next((x for x in fields if x['key'] == k), {})
            return v in (None, '', []) or ('default' in f and v == f['default'])
        fill = {}
        for k, v in (found.get('sets') or {}).items():
            if empty(k) and v not in (None, ''):
                fill[k] = v
        for k, c in (found.get('choices') or {}).items():
            if empty(k) and c.get('pick') not in (None, ''):
                fill[k] = c['pick']
                fill.update({mk: mv for mk, mv in ((c.get('sets') or {}).get(c['pick']) or {})
                             .items() if empty(mk)})
        if self.json and not a.fill:
            got['would_fill'] = fill
            self.out(got)
            return 0 if got.get('ok') else 1
        p = self.pal
        print(p.ok_line(got.get('said') or '') if got.get('ok') else
              p.bad_line(got.get('said') or ''))
        if not got.get('ok'):
            return 1
        for f in found.get('facts') or []:
            print('  %s %s' % (p.info('%-28s' % f[0]), f[1]))
        for n in found.get('notes') or []:
            print('  ' + p.warn('! ' + n))
        rows = []
        for k, v in (found.get('sets') or {}).items():
            rows.append([label.get(k, k), _short(saved.get(k, ''), 40), _short(v, 60),
                         'fill' if k in fill else ('same' if str(saved.get(k)) == str(v)
                                                   else 'set otherwise - kept')])
        for k, c in (found.get('choices') or {}).items():
            opts = c.get('options') or []
            rows.append([label.get(k, k), _short(saved.get(k, ''), 40), '%d to choose%s' % (
                len(opts), (': ' + c['pick']) if c.get('pick') else ''),
                'fill' if k in fill else 'choose with --set %s=...' % k])
        if rows:
            self.table(rows, ['setting', 'now', 'from the account', ''])
        for k, c in (found.get('choices') or {}).items():
            print(p.head('\n%s (--set %s=VALUE)' % (label.get(k, k), k)))
            for o in (c.get('options') or [])[:60]:
                print('  %s  %s' % (p.info('%-30s' % (o[0] or "''")), o[1]))
        if not a.fill:
            if fill:
                print(p.dim('\n  acme --%s-discover %s --fill   saves the ones marked "fill"%s'
                            % (word, name, ' (with --kind and --set into a new one: '
                               '--%s-add NAME)' % word if not row else '')))
            return 0
        if not row:
            raise SystemExit('acme: --fill saves into a saved %s - add it first (--%s-add)'
                             % (word, word))
        if not fill:
            return self.done('nothing to fill in - the settings say it already', got)
        pub = S.plugin_public(self.store, fam, row, True)
        cur = dict(pub.get('config') or {})
        cur['__secret_set__'] = list(pub.get('secret_set') or [])
        sets = [(k, '=', '\n'.join(map(str, v)) if isinstance(v, list) else
                 ('on' if v is True else 'off' if v is False else str(v)))
                for k, v in fill.items()]
        body = {'id': row['id'], 'kind': kind,
                'config': self.module_config(fields, cur, what=row['name'], sets=sets)}
        saved_now = self.api('POST', '/api/%s/save' % path, body=body)
        return self.done('%s %s: filled in %s' % (word, row['name'], ', '.join(
            label.get(k, k) for k in fill)), saved_now)

    def target_test(self):
        return self.fam_test('target', self.args.target_test)

    def fam_action(self, fam, name, key):
        from acmelib.certs import api
        row = self.fam_row(fam, name)
        cls, _f = self.fam_fields(fam, row['kind'])
        act = next((x for x in cls.actions or [] if x.get('key') == key), None)
        if not act:
            raise SystemExit('acme: %s (%s) can do %s' % (row['name'], row['kind'], ', '.join(
                x['key'] for x in cls.actions or []) or 'nothing besides its work'))
        if act.get('confirm'):
            self.sure('%s: %s' % (row['name'], act['confirm'].rstrip('?')))
        try:
            got = api.family_action(self.store, fam, {'id': row['id'], 'action': key}, self.WHO,
                                    echo=None if (self.json or act.get('file')) else self.echo)
        except (ValueError, LookupError) as e:
            raise SystemExit('acme: %s' % e)
        if self.json:
            self.out(got)
        elif got.get('file'):
            # a file handed over (the nginx config): printed as it is, to redirect into a file
            sys.stdout.write(got['file']['text'])
        else:
            print(self.pal.ok_line(got['said'].split('\n')[0]) if got['ok']
                  else self.pal.bad_line(got['said']))
        return 0 if got['ok'] else 1

    # ---- the modules ---------------------------------------------------------------------------
    def plugins(self):
        from acmelib.certs import api
        got = api.plugins_view(self.store)
        if self.json:
            self.out(got)
            return 0
        for fam in ('issuer', 'challenge', 'target'):
            print(self.pal.head(fam + 's'))
            rows = []
            for d in got.get(fam, []):
                origin = {'builtin': ''}.get(d.get('origin'), 'OVERRIDE' if d.get('overrides')
                                             else 'own')
                vers = d.get('versions') or []
                if vers:
                    words = ', '.join('%s%s%s' % (v.get('version') or '(plain)',
                                                  '*' if v.get('default') else '',
                                                  '' if v.get('origin') == 'builtin' else
                                                  (' override' if v.get('overrides') else ' own'))
                                      for v in vers)
                else:
                    words = d.get('version') or ''
                rows.append([d['kind'], d['title'], d.get('vendor') or '', origin, words,
                             ', '.join(x['key'] for x in d.get('actions') or []) or '-',
                             d.get('module') if d.get('origin') == 'custom' else
                             os.path.basename(d.get('module') or '')])
            self.table(rows, ['kind', 'title', 'vendor', 'origin', 'versions (* default)',
                              'actions', 'file'])
        if got.get('broken'):
            print(self.pal.bad('did not load'))
            for b in got['broken']:
                print('  %s: %s' % (b['file'], b['words']))
        cm = got.get('custom') or {}
        if cm.get('files') or cm.get('others'):
            print(self.pal.head('\nmodules of your own on %s (%s)' % (cm.get('node'),
                                                                     cm.get('dir'))))
            for f in cm.get('files') or []:
                print('  %s  %s' % (f['path'], self.pal.dim(f['sha256'][:16])))
            for o in cm.get('others') or []:
                bad = o['missing_here'] or o['only_here'] or o['different']
                print('  %s %s' % (self.pal.warn('!') if bad else self.pal.good('✔'),
                                   'node %s: %s' % (o['node'], '; '.join(filter(None, [
                                       'not here: ' + ', '.join(o['missing_here'])
                                       if o['missing_here'] else '',
                                       'only here: ' + ', '.join(o['only_here'])
                                       if o['only_here'] else '',
                                       'different: ' + ', '.join(o['different'])
                                       if o['different'] else ''])) or 'the same')))
            if any(o['missing_here'] or o['different'] for o in cm.get('others') or []):
                print(self.pal.dim('  acme --plugins-sync NODE   writes that node\'s files here'))
        print(self.pal.dim('  acme --plugin KIND: what one of them takes'))
        return 0

    def checks_list(self):
        from acmelib.certs import checks as C
        want = None if self.args.checks in (None, '', '*') else self.args.checks
        rows = C.rows(self.store, cert_id=self.cert_ref(want)['id'] if want else None)
        if self.json:
            self.out({'checks': rows})
            return 0
        if not rows:
            print('  no test attached%s - acme --check-attach CERT TEST' % (
                ' to ' + want if want else ''))
            return 0
        p = self.pal
        tone = {'ok': p.good, 'warn': p.warn}
        self.table([[r['id'], r.get('cert') or '', r.get('test') or '', r.get('where') or '',
                     tone.get(r.get('last_state'), p.bad)(r.get('last_state') or '-')
                     if r.get('last_state') else '-', _short(r.get('last_said') or '', 70)]
                    for r in rows], ['ID', 'CERTIFICATE', 'TEST', 'WHAT', 'LAST', 'SAID'])
        return 0

    def check_run(self):
        from acmelib.certs import checks as C
        what = str(self.args.check_run or '').strip()
        if what.isdigit():
            ids = [int(what)]
        elif what.startswith('test:'):
            ids = [r['id'] for r in C.rows(self.store, test=what[5:])]
        elif what.startswith('cert:'):
            cert = self.cert_ref(what[5:])
            ids = [r['id'] for r in C.rows(self.store, cert_id=cert['id'])]
        elif what == 'all':
            ids = [r['id'] for r in C.rows(self.store)]
        else:
            raise SystemExit('acme: --check-run ID, cert:NAME, test:NAME or all')
        if not ids:
            raise SystemExit('acme: there is no test to run')
        bad, out = 0, []
        for i in ids:
            got = C.run(self.store, i)
            out.append(dict(got, id=i))
            if not got['ok']:
                bad += 1
            if not self.json:
                line = '%s  %s' % (i, got['said'])
                print(self.pal.ok_line(line) if got['ok'] else self.pal.bad_line(line))
        if self.json:
            self.out({'results': out})
        return 1 if bad else 0

    def check_attach(self):
        args = self.args.check_attach
        if len(args) < 2:
            raise SystemExit('acme: --check-attach CERT TEST [TEST...]')
        cert = self.cert_ref(args[0])
        got = self.api('POST', '/api/checks/attach', body={'cert_id': cert['id'],
                                                           'tests': args[1:]})
        return self.done(got.get('message') or 'attached', got)

    def check_detach(self):
        got = self.api('POST', '/api/checks/detach', body={'id': self.args.check_detach})
        return self.done(got.get('message') or 'taken off', got)

    def module_mark(self):
        mod, state = self.args.module_mark
        m = re.match(r'^(source|validation|target|issuer|challenge)s?/([a-z0-9_]+)(?:@(.*))?\Z',
                     mod.strip())
        if not m:
            raise SystemExit('acme: the module as family/kind[@version], e.g. '
                             'target/netscaler@14.1')
        fam = {'source': 'issuer', 'validation': 'challenge'}.get(m.group(1), m.group(1))
        state = '' if state in ('none', '-', '') else state
        got = self.api('POST', '/api/modules/mark', body={
            'family': fam, 'kind': m.group(2), 'version': m.group(3) or '', 'state': state,
            'note': self.args.note or ''})
        return self.done(got.get('message') or 'done', got)

    def module_marks_export(self):
        from acmelib.certs import custom_modules as CM
        from acmelib import __version__
        self.out(CM.export_marks(self.store, __version__))
        return 0

    def plugins_sync(self):
        from acmelib.certs import custom_modules as CM
        node = self.args.plugins_sync
        a = self.args
        self.sure('the modules of your own that %s keeps in the database are written into %s%s'
                  % (node, CM.plugins_dir(), ' and the files it does not have taken away'
                     if a.remove else ''))
        try:
            done = CM.sync(self.store, node, remove=bool(a.remove),
                           say=lambda w: print('  ' + self.pal.warn(w)))
        except (ValueError, OSError) as e:
            raise SystemExit('acme: %s' % e)
        for what, rel in done:
            print('  %s %s' % (what, rel))
        CM.record(self.store)
        return self.done('%d file(s) changed - restart acme (systemctl restart acme) to load '
                         'them' % len(done) if done else 'nothing to change: the files are the '
                         'same', {'ok': True, 'changed': done})

    def _fields_table(self, fields):
        rows = []
        for f in fields:
            t = f.get('type') or 'text'
            if t == 'select' and f.get('options'):
                t = 'one of: ' + ' '.join(str(o[0]) for o in f['options'])
            cond = ' '.join('%s=%s' % (k, '|'.join(str(x) for x in v))
                            for k, v in (f.get('show_if') or {}).items())
            rows.append([f['key'], _short(t, 60), 'yes' if f.get('required') else '',
                         _short(f.get('default'), 24) if f.get('default') not in (None, '', [])
                         else '', ('when ' + cond) if cond else ('more' if f.get('advanced')
                                                                 else ''),
                         f.get('label') or ''])
        self.table(rows, ['key', 'type', 'needed', 'default', 'shown', 'what'])
        import textwrap
        for f in fields:
            if f.get('help'):
                for i, line in enumerate(textwrap.wrap(f['help'], max(40, self.pal.width - 26))):
                    print('  %s %s' % (self.pal.info('%-20s' % (f['key'] if i == 0 else '')),
                                       self.pal.dim(line)))

    def plugin(self):
        from acmelib.certs import api
        want = self.args.plugin
        fam_want = None
        if '/' in want:
            fam_want, want = want.split('/', 1)
            fam_want = {'source': 'issuer', 'sources': 'issuer', 'issuers': 'issuer',
                        'validation': 'challenge', 'validations': 'challenge',
                        'challenges': 'challenge', 'targets': 'target'}.get(fam_want, fam_want)
        got = api.plugins_view(self.store)
        found = [(fam, d) for fam in ('issuer', 'challenge', 'target') for d in got.get(fam, [])
                 if d['kind'] == want and (not fam_want or fam == fam_want)]
        if not found:
            raise SystemExit('acme: there is no module %s (acme --plugins)' % self.args.plugin)
        if self.json:
            self.out({'modules': [dict(d, family=fam) for fam, d in found]})
            return 0
        p = self.pal
        for fam, d in found:
            word = FAMILIES[fam][0]
            print('%s  %s - %s (%s)' % (p.head(d['kind']), word, d['title'], d.get('vendor')))
            if d.get('description'):
                print('  ' + d['description'])
            if d.get('doc'):
                print(p.dim('  docs/%s' % os.path.basename(d['doc'])))
            print(p.head('\nits settings') + p.dim('   acme --%s-add NAME --kind %s --set '
                                                  'KEY=VALUE ...' % (word, d['kind'])))
            if d.get('fields'):
                self._fields_table(d['fields'])
            else:
                print('  (none)')
            if fam == 'target':
                print(p.head('\na deployment\'s options') + p.dim('   acme --deploy-add CERT '
                                                                  'TARGET --set KEY=VALUE ...'))
                if d.get('deploy_fields'):
                    self._fields_table(d['deploy_fields'])
                else:
                    print('  (none)')
            if d.get('discover'):
                print(p.head('\nfound from the account') + p.dim(
                    '   acme --%s-discover NAME (--fill)' % word))
                print('  asks only: %s' % ', '.join((d['discover'].get('keys') or [])))
            if d.get('actions'):
                print(p.head('\nwhat it can do besides') + p.dim('   acme --%s-action NAME '
                                                                 'ACTION' % word))
                for x in d['actions']:
                    print('  %s  %s' % (p.good('%-12s' % x['key']), x.get('label') or ''))
                    if x.get('help'):
                        print('  %s  %s' % (' ' * 12, p.dim(x['help'])))
            print()
        return 0

    # ---- deployments -------------------------------------------------------------------------
    def _deploy_table(self, rows, cert=True, target=True):
        heads = ['id'] + (['certificate'] if cert else []) + (['target'] if target else []) + \
            ['state', 'version', 'last ok', '', 'options', 'error']
        out = []
        for d in rows:
            opts = dict(d.get('options') or {})
            for k in d.get('secret_set') or []:
                opts[k] = opts.get(k) or '(set)'          # dots and its last two
            st = d.get('state') or ''
            if d.get('outdated') and st == 'ok':
                st = 'outdated'
            out.append([d['id']] + ([d.get('cert_name') or d.get('cert_id')] if cert else []) +
                       ([d['target']] if target else []) +
                       [st, d.get('deployed_version') or '-', _when(d.get('last_ok')),
                        _onoff(d.get('enabled', 1)),
                        _short(' '.join('%s=%s' % (k, _short(v, 30)) for k, v in
                                        sorted(opts.items()) if v not in (None, '', [])), 50),
                        (d.get('last_error') or '')[:50]])
        self.table(out, heads)

    def deploys(self):
        from acmelib.certs import api
        cert = '' if self.args.deploys == '*' else self.args.deploys
        if cert:
            self.cert_ref(cert)
        try:
            rows = api.deploy_rows(self.store, cert=cert, full=True)
        except LookupError as e:
            raise SystemExit('acme: %s' % e)
        if self.json:
            self.out({'rows': rows, 'total': len(rows)})
            return 0
        self._deploy_table(rows, cert=not cert)
        print(self.pal.dim('  %d deployment(s)' % len(rows)))
        return 0

    def _deploy_fields(self, target):
        row = self.fam_row('target', target)
        cls, fields = self.fam_fields('target', row['kind'], 'deploy_fields')
        return row, fields

    def deploy_add(self):
        cert, target = self.args.deploy_add
        c = self.cert_ref(cert)
        trow, fields = self._deploy_fields(target)
        opts = self.module_config(fields, {}, adding=True, what='a deployment to %s (%s)' % (
            trow['name'], trow['kind']))
        body = {'cert_id': c['id'], 'target': trow['name'], 'options': opts,
                'enabled': 1 if self._enabled() is None else self._enabled()}
        if self.args.note:
            body['note'] = self.args.note
        got = self.api('POST', '/api/deploys/save', body=body)
        return self.done('%s goes to %s from now on (deployment %s) - acme --deploy-run %s puts '
                         'it there now' % (c['name'], trow['name'], got['id'], got['id']), got)

    def _deploy_row(self, ident):
        row = self.store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (ident,))
        if not row:
            raise SystemExit('acme: there is no deployment %s (acme --deploys)' % ident)
        return row

    def deploy_edit(self):
        from acmelib.certs import store as S
        row = self._deploy_row(self.args.deploy_edit)
        trow, fields = self._deploy_fields(row['target'])
        pub = S.deploy_public(self.store, row, True)
        cur = dict(pub.get('options') or {})
        cur['__secret_set__'] = list(pub.get('secret_set') or [])
        body = {'id': row['id']}
        if self.sets():
            body['options'] = self.module_config(fields, cur, what='the deployment to %s' %
                                                 trow['name'])
        if self._enabled() is not None:
            body['enabled'] = self._enabled()
        if self.args.note:
            body['note'] = self.args.note
        if len(body) == 1:
            raise SystemExit('acme: nothing to change - --set KEY=VALUE, --enabled, --note')
        got = self.api('POST', '/api/deploys/save', body=body)
        return self.done('deployment %s changed' % row['id'], got)

    def deploy_del(self):
        row = self._deploy_row(self.args.deploy_del)
        self.sure('the deployment %s (to %s) is taken away - the device keeps what it has' % (
            row['id'], row['target']))
        got = self.api('POST', '/api/deploys/delete', body={'id': row['id']})
        return self.done('deployment %s taken away' % row['id'], got)

    def deploy_run(self):
        from acmelib.certs import deployer, store as S
        row = self._deploy_row(self.args.deploy_run)
        c = S.cert_need(self.store, row['cert_id'])
        if not c.get('cert_pem'):
            raise SystemExit('acme: %s has not been issued yet' % c['name'])
        job = self._run_job('deploy', deployer.deploy_job(c['id'], [row['id']], force=True),
                            c['id'], '%s to %s' % (c['name'], row['target']))
        return 0 if job.ok else 1

    # ---- the authorities ---------------------------------------------------------------------
    def cas(self):
        got = self.api('GET', '/api/cas')
        if self.json:
            self.out(got)
            return 0
        names = {r['id']: r['name'] for r in got['rows']}
        self.table([[r['id'], r['name'], names.get(r.get('parent_id')) or '(root)',
                     r.get('key_type') or '', _when(r.get('not_after'), '%Y-%m-%d'),
                     'yes' if r.get('has_key') else 'no', r.get('issued') or 0,
                     (r.get('subject_dn') or '')[:50]] for r in got['rows']],
                   ['id', 'authority', 'under', 'key', 'ends', 'can sign', 'signed', 'subject'])
        return 0

    def ca_default(self):
        ref = str(self.args.ca_default).strip()
        ident = '' if ref.lower() in ('', 'none', '-') else self.ca_ref(ref)['id']
        got = self.api('POST', '/api/cas/default', body={'id': ident})
        return self.done(got.get('message') or 'done', got)

    def ca_publish(self):
        ca, yes = self.args.ca_publish
        if yes.lower() not in ('on', 'off'):
            raise SystemExit('acme: --ca-publish CA on|off')
        r = self.ca_ref(ca)
        got = self.api('POST', '/api/cas/publish', body={'id': r['id'],
                                                         'published': yes.lower() == 'on'})
        pki = got.get('pki') or {}
        words = got.get('message') or ''
        if yes.lower() == 'on' and not pki.get('on'):
            words += ' - but publishing is switched off (pki_publish)'
        elif yes.lower() == 'on':
            words += ': %s' % (pki.get('urls') or {}).get('crl', '')
        return self.done(words, got)

    def ca_pki_urls(self):
        r = self.ca_ref(self.args.ca_pki_urls)
        got = self.api('POST', '/api/cas/pki_urls', body={'id': r['id']})
        return self.done('%s: CRL %s, CA certificate %s - for what it signs from now on' % (
            r['name'], got.get('crl_url'), got.get('aia_url')), got)

    def ca_pki_check(self):
        r = self.ca_ref(self.args.ca_pki_check)
        got = self.api('POST', '/api/cas/pki_check', body={'id': r['id']})
        if self.json:
            self.out(got)
            return 0 if got.get('ok') else 1
        p = self.pal
        for level, words in got.get('steps') or []:
            mark = {'ok': p.good('ok  '), 'bad': p.bad('bad '), 'warn': p.warn('warn')}.get(
                level, p.dim('    '))
            print('  %s %s' % (mark, words))
        return 0 if got.get('ok') else 1

    def ca_ref(self, ref):
        from acmelib.certs import api
        try:
            return api.ca_row(self.store, ref)
        except LookupError as e:
            raise SystemExit('acme: %s (acme --cas)' % str(e).strip('\'"'))

    def ca_show(self):
        r = self.ca_ref(self.args.ca_show)
        got = self.api('GET', '/api/cas/one', args={'id': str(r['id']),
                                                     'per': str(self.args.limit or 40)})
        if self.json:
            self.out(got)
            return 0
        ca = got['ca']
        p = self.pal
        print(p.head(ca.get('name') or r['name']))
        self.kv([('subject', ca.get('subject_dn') or r.get('subject_dn')),
                 ('key', r.get('key_type')), ('can sign', 'yes' if ca.get('has_key') else 'no'),
                 ('valid', '%s - %s' % (_when(r.get('not_before')), _when(r.get('not_after')))),
                 ('sha-256', r.get('fingerprint')), ('path length', r.get('path_len')),
                 ('CRL', 'every %s days, last %s' % (r.get('crl_days'), _when(r.get('crl_at')))),
                 ('CRL address', r.get('crl_url')), ('AIA address', r.get('aia_url')),
                 ('under it', ', '.join(got.get('children') or [])),
                 ('default', 'yes - offered first' if ca.get('is_default') else '')])
        pki = got.get('pki') or {}
        if pki.get('urls'):
            u = pki['urls']
            print(p.head('\npublished on acme'))
            self.kv([('published', 'yes' if pki.get('published') else (
                'no - publishing is off (pki_publish)' if not pki.get('on') else
                'no - its switch is off (acme --ca-publish %s on)' % r['name'])),
                ('CRL', u.get('crl')), ('CRL (PEM)', u.get('crl_pem')),
                ('certificate', u.get('cert')), ('certificate (PEM)', u.get('cert_pem')),
                ('last CRL', _when(pki.get('this_update'))),
                ('next update', _when(pki.get('next_update'))),
                ('made again', _when(pki.get('refresh_due'))),
                ('in what it signs', 'acme\'s own addresses' if pki.get('own_urls') else
                 'other addresses (acme --ca-pki-urls %s)' % r['name'])])
        print(p.head('\nwhat it signed'))
        self.table([[i.get('serial'), _short(i.get('subject_dn') or i.get('names'), 40),
                     _when(i.get('not_after'), '%Y-%m-%d'),
                     ('revoked %s' % (i.get('reason') or '')) if i.get('revoked') else 'valid',
                     i.get('by_who') or ''] for i in got.get('issued') or []],
                   ['serial', 'subject', 'ends', 'state', 'by'])
        return 0

    def _ca_extra(self, body):
        for k, op, v in self.sets():
            if k in ('crl_days', 'path_len', 'days'):
                if not v.strip().lstrip('-').isdigit():
                    raise SystemExit('acme: %s is a number' % k)
                body[k] = int(v)
            elif k in ('crl_url', 'aia_url', 'ocsp_url'):
                body[k] = v
            elif k == 'name_constraints':
                body[k] = as_list(v)
            else:
                raise SystemExit('acme: an authority takes --set crl_days crl_url aia_url '
                                 'ocsp_url path_len name_constraints, not %s' % k)
        return body

    def ca_create(self):
        a = self.args
        name = a.ca_create or a.ca_sub
        subj = {}
        for part in (a.subject or 'CN=%s' % name).split(','):
            if '=' in part:
                k, v = part.split('=', 1)
                subj[k.strip()] = v.strip()
        body = {'name': name, 'subject': subj,
                'key_type': a.key_type or ('ec-384' if a.ca_create else 'ec-256'),
                'days': a.days if a.days is not None else (3650 if a.ca_create else 1825)}
        if a.ca_sub:
            if not a.parent:
                raise SystemExit('acme: --ca-sub needs --parent CA (the authority that signs it)')
            body['parent_id'] = self.ca_ref(a.parent)['id']
        got = self.api('POST', '/api/cas/create', body=self._ca_extra(body))
        return self.done('authority %s made (id %s)%s' % (
            name, got.get('id'), (', under %s' % a.parent) if a.ca_sub else ''), got)

    def ca_import(self):
        a = self.args
        data = self.files[a.ca_import]
        body = {'data_b64': base64.b64encode(data).decode('ascii'),
                'filename': os.path.basename(a.ca_import), 'password': self._password(False)}
        if a.key:
            body['key_b64'] = base64.b64encode(self.files[a.key]).decode('ascii')
            body['key_password'] = os.environ.get('ACME_KEY_PASSWORD') or body['password']
        if a.name:
            body['name'] = a.name
        got = self.api('POST', '/api/cas/import', body=body)
        return self.done('authority imported (id %s)' % got.get('id'), got)

    def ca_revoke(self):
        from acmelib.certs import api
        ca, serial = self.args.ca_revoke
        r = self.ca_ref(ca)
        if self.args.reason not in api.REVOKE_REASONS:
            raise SystemExit('acme: the reason is one of %s' % ', '.join(api.REVOKE_REASONS))
        self.sure('serial %s of %s is revoked (%s)' % (serial, r['name'], self.args.reason))
        got = self.api('POST', '/api/cas/revoke', body={'id': r['id'], 'serial': serial,
                                                        'reason': self.args.reason})
        return self.done('%s - acme --ca-crl %s makes its CRL now' % (
            got.get('message') or 'revoked', r['name']), got)

    def _give(self, data, what, mode=0o644):
        """Into --out, or printed (text) / to stdout."""
        a = self.args
        if a.out and a.out != '-':
            self._write(a.out, data, mode)
            return self.done('%s written (%s, %d bytes)' % (a.out, what, len(data)),
                             {'file': a.out, 'bytes': len(data), 'what': what})
        if self.json:
            self.out({'what': what, 'data_b64': base64.b64encode(data).decode('ascii')})
            return 0
        if not a.out and (b'\x00' in data or not data.strip().startswith(b'-----')):
            raise SystemExit('acme: that is not text - --out FILE (or --out - for stdout)')
        self._stdout(data if data.endswith(b'\n') else data + b'\n')
        return 0

    def ca_crl(self):
        r = self.ca_ref(self.args.ca_crl)
        got = self.api('POST', '/api/cas/crl', body={'id': r['id']})
        return self._give(base64.b64decode(got['data_b64']), 'the CRL of %s' % r['name'])

    def ca_export(self):
        a = self.args
        r = self.ca_ref(a.ca_export)
        what = (a.what or 'cert').lower()
        if what not in CA_FORMATS:
            raise SystemExit('acme: --what is one of %s' % ' '.join(CA_FORMATS))
        pw = ''
        if what in ('p12', 'pfx') or a.password:
            pw = self.E.ask_password('the file\'s password', twice=True,
                                     env='ACME_FILE_PASSWORD')
        if what in ('key', 'p12', 'pfx') and not a.out:
            raise SystemExit('acme: the key goes into a file only: --out FILE')
        got = self.api('POST', '/api/cas/export', body={'id': r['id'], 'format': what,
                                                        'password': pw})
        return self._give(base64.b64decode(got['data_b64']), '%s of %s' % (what, r['name']),
                          0o600 if what in ('key', 'p12', 'pfx') else 0o644)

    def ca_sign(self):
        a = self.args
        r = self.ca_ref(a.ca_sign)
        if not a.csr:
            raise SystemExit('acme: --ca-sign needs --csr FILE (the request to sign)')
        csr = self.files[a.csr].decode('ascii', 'replace')
        body = {'id': r['id'], 'csr_pem': csr}
        if a.days is not None:
            body['days'] = a.days
        for k, op, v in self.sets():
            if k != 'eku':
                raise SystemExit('acme: --ca-sign takes --set eku=serverAuth,clientAuth only')
            body['eku'] = as_list(v)
        got = self.api('POST', '/api/cas/sign_csr', body=body)
        pem = (got['cert_pem'].rstrip('\n') + '\n' + got.get('chain_pem', '')).strip() + '\n'
        if self.json and not a.out:
            self.out(got)
            return 0
        return self._give(pem.encode('ascii'), 'the certificate %s signed' % r['name'])

    def ca_del(self):
        r = self.ca_ref(self.args.ca_del)
        self.sure('the authority %s is deleted, with its key' % r['name'])
        got = self.api('POST', '/api/cas/delete', body={'id': r['id']})
        return self.done(got.get('message') or 'deleted', got)

    # ---- acme's own DNS server -----------------------------------------------------------------
    def dns(self):
        got = self.api('GET', '/api/dns')
        if self.json:
            self.out(got)
            return 0
        s = got['settings']
        srv = got.get('server') or {}
        print('acme\'s DNS server: %s, zone %s, port %s%s' % (
            'on' if s.get('dns_server') else 'off', s.get('dns_zone') or '(none)',
            s.get('dns_port'), (', %s queries here' % srv['queries']) if srv.get('queries')
            else ''))
        self.table([[r['id'], r['name'], r['rtype'], (r.get('value') or '')[:60], r.get('ttl'),
                     _when(r.get('expires')) if r.get('expires') else 'never',
                     r.get('owner') or ''] for r in got['records']],
                   ['id', 'name', 'type', 'value', 'ttl', 'expires', 'by'])
        return 0

    def dns_add(self):
        name, rtype, value = self.args.dns_add
        body = {'name': name, 'rtype': rtype, 'value': value, 'note': self.args.note or ''}
        if self.args.ttl is not None:
            body['ttl'] = self.args.ttl
        got = self.api('POST', '/api/dns/record', body=body)
        return self.done('DNS record %s %s %s saved (id %s)' % (name, rtype.upper(), value,
                                                                got['id']), got)

    def dns_del(self):
        words = self.args.dns_del
        if len(words) == 1 and words[0].isdigit():
            rows = self.store.db.rows('SELECT * FROM dns_records WHERE id = ?', (int(words[0]),))
        else:
            name = words[0].strip().lower().rstrip('.')
            if name == '@':
                name = str(self.E.CONFIG.get('dns_zone') or '').strip().lower().rstrip('.')
            sql, args = 'SELECT * FROM dns_records WHERE name = ?', [name]
            if len(words) > 1:
                sql += ' AND rtype = ?'
                args.append(words[1].upper())
            if len(words) > 2:
                sql += ' AND value = ?'
                args.append(' '.join(words[2:]))
            rows = self.store.db.rows(sql, args)
        if not rows:
            raise SystemExit('acme: no such record (acme --dns-records)')
        if len(rows) > 1:
            self.sure('%d records go: %s' % (len(rows), ', '.join(
                '%s %s %s' % (r['name'], r['rtype'], r['value']) for r in rows[:5])))
        for r in rows:
            self.api('POST', '/api/dns/record_delete', body={'id': r['id']})
        return self.done('%d record(s) taken away' % len(rows), {'deleted': [r['id'] for r in
                                                                             rows]})


def run(args):
    if not asked(args):
        return None
    return Cli(args).run()
