# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The certificate manager, put into the engine
# ---------------------------------------------------------------------------
# Its tables into SCHEMA (so made, given new columns, backed up, exported and
# replicated as every other), its settings into DEFAULTS and the pages'
# panes, and its daemon thread, API, command line, console, alerts, report,
# metrics and status through HOOKS. What does the work (acmelib/certs) is
# imported only when it is needed - `acme --version` reads none of it.
import importlib as _importlib

from acmelib.certs import schema as _cert_schema
from acmelib.certs import texts as _cert_texts

for _cs_name, _cs_ddl in _cert_schema.SCHEMA:
    if _cs_name not in TABLES:
        SCHEMA.append((_cs_name, _cs_ddl))
        TABLES.append(_cs_name)
for _cs_ix in _cert_schema.INDEXES:
    if _cs_ix not in INDEXES:
        INDEXES.append(_cs_ix)
del _cs_name, _cs_ddl, _cs_ix

CERT_DEFAULTS = {
    # --- certificates: renewing, deploying, telling ---------------------------------
    'certs_renew_days': 30,
    'certs_check_min': 5,
    'certs_parallel': 4,
    'certs_retry_max_h': 6,
    'certs_notify_days': 14,
    'certs_notify_mail': '',
    'certs_notify_sms': '',
    'certs_notify_ok': 0,
    'certs_keep_versions': 10,
    'certs_keep_jobs_days': 90,
    'certs_precheck': 1,
    'certs_dry_run_s': 120,
    # --- the CRLs and certificates of acme's own authorities, on acme (port 80) --------
    'pki_publish': 1,
    'pki_base_url': '',
    # --- the certificate portal (on the enrolment pages) -------------------------------
    'portal_cert': 0,
    'portal_cert_suffixes': '',
    'portal_cert_issuers': '',
    'portal_cert_max': 10,
    'portal_cert_auto': 0,
    'portal_cert_keys': 0,
    'portal_cert_challenge': '',
    # --- acme's own DNS server (DNS-01) ---------------------------------------------
    'dns_server': 0,
    'dns_listen': '0.0.0.0,::',
    'dns_port': 53,
    'dns_zone': '',
    'dns_ns_names': '',
    'dns_ns_addresses': '',
    'dns_soa_mail': '',
    'dns_ttl': 60,
    'dns_static': '',
    'dns_rate': 100,
    'dns_expose': 'both',
    'dns_cache': 1,
    # --- who sees which certificates (Settings → Owners and teams, docs/teams.md) ------
    'certs_certadmin_all': 1,
    'certs_readonly_all': 1,
}
for _k, _v in CERT_DEFAULTS.items():
    DEFAULTS.setdefault(_k, _v)
    CONFIG.setdefault(_k, _v)
    FILE_CONFIG.setdefault(_k, _v)
del _k, _v

NAMES.update({
    'certs_renew_days': 'Renew this many days before the end',
    'certs_check_min': 'Look for what is due every (min)',
    'certs_parallel': 'Jobs at once',
    'certs_retry_max_h': 'Longest wait before trying again (h)',
    'certs_notify_days': 'Warn this many days before the end',
    'certs_notify_mail': 'Tell by mail',
    'certs_notify_sms': 'Tell by SMS',
    'certs_notify_ok': 'Tell what went well too',
    'certs_keep_versions': 'Old certificates kept (each)',
    'certs_keep_jobs_days': 'Jobs kept (days)',
    'certs_precheck': 'Check the validation before the CA is asked',
    'certs_dry_run_s': 'A dry run waits at most (s)',
    'pki_publish': 'Publish CRLs on acme',
    'pki_base_url': 'Their address',
    'portal_cert': 'Certificates on the portal',
    'portal_cert_suffixes': 'Names people may ask for',
    'portal_cert_issuers': 'Sources people may ask',
    'portal_cert_challenge': 'How their names are proved (ACME)',
    'portal_cert_max': 'Requests one person may make',
    'portal_cert_auto': 'Issued without an administrator',
    'portal_cert_keys': 'People may take their key (PFX)',
    'dns_server': 'acme’s own DNS server',
    'dns_listen': 'Listens on',
    'dns_port': 'Port',
    'dns_zone': 'Its zone',
    'dns_ns_names': 'Its name servers (NS)',
    'dns_ns_addresses': 'Their addresses',
    'dns_soa_mail': 'Mail of the zone’s keeper (SOA)',
    'dns_ttl': 'TTL of its answers (s)',
    'dns_static': 'Records of your own',
    'dns_rate': 'Answers per second to one network',
    'dns_expose': 'Where it answers',
    'dns_cache': 'How long records are cached (s)',
    'certs_certadmin_all': 'Certificate administrators manage every certificate',
    'certs_readonly_all': 'Read-only accounts see every certificate',
})
SAYS.update({
    'certs_renew_days': 'A certificate renewed by itself is renewed this many days before it '
                        'ends, unless it says otherwise or its CA suggests a window of its own '
                        '(ARI). 30 suits the 90 days of Let’s Encrypt.',
    'certs_check_min': 'How often the node that leads looks for certificates due and '
                       'deployments to try again.',
    'certs_parallel': 'How many renewals and deployments run side by side.',
    'certs_retry_max_h': 'A failed renewal or deployment is tried again after 5 minutes, then '
                         'after twice as long each time - never longer than this.',
    'certs_notify_days': 'A certificate that ends sooner and is not renewed by itself (or '
                         'whose renewal fails) is an event, an alert and a mail every day.',
    'certs_notify_mail': 'Addresses told when a renewal or a deployment fails, or a '
                         'certificate is about to end (comma between them). Empty: nobody.',
    'certs_notify_sms': 'Numbers told the same by SMS (Settings → Codes by mail and SMS '
                        'says how SMS go out). Empty: nobody.',
    'certs_notify_ok': 'Also a mail and an SMS when a certificate is renewed or deployed - not '
                       'only when something fails or runs out. The words are on Settings → '
                       'Message texts.',
    'certs_keep_versions': 'Each certificate keeps this many of the certificates it had.',
    'certs_keep_jobs_days': 'Jobs older than this are deleted, with their steps.',
    'certs_precheck': 'Before the first certificate of a name, and after a renewal that failed '
                      'on its validation, acme checks what the validation needs (the CNAME, '
                      'the zone, the address the name points at) - and while something is '
                      'missing it does not ask the CA but says what to set up where. Let’s '
                      'Encrypt counts failed validations and stops a domain for an hour.',
    'certs_dry_run_s': 'How long a dry run of a validation waits for its test record or file '
                       'to be seen before it says it is not.',
    'pki_publish': 'Every node and the VIP address serve the CRL and the certificate of each of '
                   'acme’s own authorities over plain HTTP at /pki/ (port 80, no sign-in, '
                   'from the database), and keep each CRL fresh. A new authority puts these '
                   'addresses into what it signs; port 80 is let in from anywhere.',
    'pki_base_url': 'Where they are found, http://NAME/pki/. Empty: http:// and the VIP '
                    'address’s name when it is on, else this server’s name, and /pki/.',
    'portal_cert': 'People signed in on the portal see the certificates they own - their '
                   'own, or owned by a directory group they are in - with when each runs out, '
                   'download the certificate and its chain, and may ask for a new one.',
    'portal_cert_suffixes': 'The names they may ask for: these domains and the names under them '
                            '(comma between them). Empty: nobody may ask.',
    'portal_cert_issuers': 'The sources (Certificates → Sources) a certificate asked for there '
                           'may come from, by name, comma between them. Empty: nobody may ask.',
    'portal_cert_challenge': 'The validation (Certificates → Validation) that proves the names '
                             'of a certificate asked for there, for a source that needs one - '
                             'ACME. Empty: only sources that need none (own CA, self-signed).',
    'portal_cert_max': 'How many certificates one person may ask for there; those declined do '
                       'not count, deleted ones neither.',
    'portal_cert_auto': 'On: what is asked for is issued at once. Off: it waits under '
                        'Certificates (waiting for approval) until an administrator approves '
                        'or declines it - and the person is told by mail.',
    'portal_cert_keys': 'On: people may download their certificate with its private key, as '
                        'a PFX file locked with a password they choose. Off: the certificate '
                        'and the chain only.',
    'dns_server': 'acme answers DNS itself for the zone below - the _acme-challenge TXT '
                  'records of DNS-01, and records of your own. Delegate _acme-challenge (or a '
                  'zone) to this machine with NS records.',
    'dns_listen': 'Addresses it listens on, comma between them.',
    'dns_port': 'UDP and TCP. 53 is what the world asks.',
    'dns_zone': 'The zone it answers for, e.g. acme.example.com.',
    'dns_ns_names': 'The names of its name servers, as the NS records of the zone.',
    'dns_ns_addresses': 'Their addresses (A / AAAA of those names), comma between them.',
    'dns_soa_mail': 'The address in the SOA record (hostmaster@example.com).',
    'dns_ttl': 'How long resolvers may keep an answer.',
    'dns_static': 'One record a line: name type value (www A 192.0.2.10).',
    'dns_rate': 'Past this many answers a second to one /24 (IPv6: /56), every other answer goes back truncated, so a real resolver asks again over TCP and a flood gets nothing.',
    'dns_expose': 'On the cluster\'s VIP address only, on the nodes\' own addresses only, or on both. '
                  'The VIP only: one address in your NS records, whichever node holds it answers. '
                  'The nodes only: each node by its own address (two NS records, no VIP needed). '
                  'Their addresses below are filled in from this when left empty.',
    'dns_cache': 'Records are read from the database at most this often; both nodes of a cluster answer the same within it.',
    'certs_certadmin_all': 'On (as before): a certificate administrator sees and manages every '
                           'certificate. Off: only those of the teams where they are a member '
                           'with the right to manage (or to see, to approve); a certificate '
                           'without an owner only a full administrator sees. A full '
                           'administrator always sees and does everything.',
    'certs_readonly_all': 'On (as before): a read-only account sees every certificate. Off: '
                          'only those of the teams where it is a member with the right to see.',
})
SAYS_SHORT.update({
    'dns_static': 'One record a line: name type value.',
})
TUNABLE.update({
    'certs_renew_days': (1, 3650), 'certs_check_min': (1, 1440), 'certs_parallel': (1, 32),
    'certs_retry_max_h': (1, 168), 'certs_notify_days': (0, 365), 'certs_notify_ok': (0, 1),
    'certs_keep_versions': (1, 1000), 'certs_keep_jobs_days': (1, 3650),
    'certs_precheck': (0, 1), 'certs_dry_run_s': (10, 1800),
    'pki_publish': (0, 1),
    'portal_cert': (0, 1), 'portal_cert_max': (1, 1000), 'portal_cert_auto': (0, 1),
    'portal_cert_keys': (0, 1),
    'dns_server': (0, 1), 'dns_port': (1, 65535), 'dns_ttl': (0, 86400),
    'dns_expose': ('both', 'vip', 'nodes'),
    'dns_rate': (1, 100000), 'dns_cache': (0, 60),
    'certs_certadmin_all': (0, 1), 'certs_readonly_all': (0, 1),
})
PANES['certs'] = ['certs_renew_days', 'certs_check_min', 'certs_parallel', 'certs_retry_max_h',
                  'certs_notify_days', 'certs_notify_mail', 'certs_notify_sms',
                  'certs_notify_ok', 'certs_precheck', 'certs_dry_run_s', 'pki_publish',
                  'pki_base_url']
ONLY_WHEN.update({'pki_base_url': ['pki_publish', '1']})
# How long the certificate manager keeps things, on The database pane beside
# how long the events are kept - where otp kept its own retention.
PANES['db'] = list(PANES['db']) + ['certs_keep_jobs_days', 'certs_keep_versions']
# The certificate portal's settings, on the pane of the portal (the enrolment
# pages), after the engine's own of who may sign in there.
PORTAL_CERT_KEYS = ['portal_cert', 'portal_cert_suffixes', 'portal_cert_issuers',
                    'portal_cert_challenge', 'portal_cert_auto', 'portal_cert_max',
                    'portal_cert_keys']
PANES['portal'] = [k for k in PANES.get('portal', []) if k not in PORTAL_CERT_KEYS
                   and k != 'portal_help'] + PORTAL_CERT_KEYS + (
    ['portal_help'] if 'portal_help' in PANES.get('portal', []) else [])
PANES['dnssrv'] = ['dns_server', 'dns_expose', 'dns_listen', 'dns_port', 'dns_zone', 'dns_ns_names',
                   'dns_ns_addresses', 'dns_soa_mail', 'dns_ttl', 'dns_static', 'dns_rate', 'dns_cache']
ONLY_WHEN.update({k: ['dns_server', '1'] for k in PANES['dnssrv'] if k != 'dns_server'})
ONLY_WHEN.update({k: ['portal_cert', '1'] for k in PORTAL_CERT_KEYS if k != 'portal_cert'})
SETTING_TALL = tuple(SETTING_TALL) + ('dns_static',)
PANES['teams'] = ['certs_certadmin_all', 'certs_readonly_all']

# The words of its notifications (acmelib/certs/texts.py) into the registry of
# Settings → Message texts: both languages, edited there as every other.
for _ct_m in _cert_texts.messages():
    if not any(m['id'] == _ct_m['id'] for m in TEXT_MESSAGES):
        TEXT_MESSAGES.append(_ct_m)
TEXT_GROUPS[_cert_texts.GROUP] = _cert_texts.W
for _ct_k, _ct_v in _cert_texts.PLACEHOLDERS.items():
    TEXT_PLACEHOLDERS.setdefault(_ct_k, _ct_v)
for _ct_k, _ct_v in _cert_texts.SAMPLES.items():
    TEXT_SAMPLES.setdefault(_ct_k, _ct_v)
del _ct_m, _ct_k, _ct_v


def certs_mod(name):
    """acmelib.certs.<name>, imported the first time it is asked for."""
    return _importlib.import_module('acmelib.certs.' + name)


def _certs_hook(kind):
    def wrap(fn):
        HOOKS.setdefault(kind, []).append(fn)
        return fn
    return wrap


@_certs_hook('daemon_start')
def certs_daemon_start(daemon):
    certs_mod('api')                    # the routes
    # The notifications in the words of Settings → Message texts.
    certs_mod('notices').install(certs_mod('renewer'))
    # Let's Encrypt first: the sources and validations a new installation has.
    certs_mod('defaults').ensure(daemon.store)
    certs_mod('dnssets').ensure(daemon.store)      # Settings → DNS: the set "Public", once
    certs_mod('renewer').start(daemon)


@_certs_hook('daemon_stop')
def certs_daemon_stop(daemon):
    if 'acmelib.certs.renewer' in sys.modules:
        certs_mod('renewer').stop(daemon)


@_certs_hook('cli_args')
def certs_cli_args(parser):
    certs_mod('cli').add_args(parser)


@_certs_hook('cli_run')
def certs_cli_run(args):
    return certs_mod('cli').run(args)


@_certs_hook('console_main')
def certs_console_main(console):
    return certs_mod('console').main_items(console)


@_certs_hook('status')
def certs_status(store, pal):
    try:
        return certs_mod('renewer').status_lines(store, pal)
    except Exception as e:                              # noqa: BLE001
        return ['certificates      ? (%s)' % e]


@_certs_hook('alerts')
def certs_alerts(store):
    return certs_mod('renewer').alerts(store)


@_certs_hook('report')
def certs_report(store, since):
    return certs_mod('renewer').report(store, since)


@_certs_hook('metrics')
def certs_metrics(store):
    return certs_mod('monitor').metrics(store)


@_certs_hook('snmp')
def certs_snmp(store):
    return certs_mod('monitor').snmp_rows(store)


@_certs_hook('event_fields')
def certs_event_fields(kind, words, level):
    if kind != 'certificates':
        return {}
    return certs_mod('monitor').event_fields(kind, words, level)


# The configuration's tables (Export and import of the configuration): what is
# set up, not what happened (cert_jobs, cert_versions stay out).
CERT_CARRY_TABLES = ['cert_issuers', 'cert_challenges', 'cert_targets', 'cert_cas',
                     'cert_ca_issued', 'certs', 'cert_deploys', 'dns_records',
                     'dns_sets', 'dns_set_uses', 'cert_teams', 'cert_tags']


@_certs_hook('carry_tables')
def certs_carry_tables(*_args):
    return list(CERT_CARRY_TABLES)


@_certs_hook('carry_row_out')
def certs_carry_row_out(table, row, whole):
    return certs_mod('store').carry_out(table, row, whole)


@_certs_hook('carry_row_in')
def certs_carry_row_in(store, table, ident, old):
    return certs_mod('store').carry_in(store, table, ident, old)


def certs_port80_why(store):
    """Why the certificate manager needs port 80 from anywhere, even when "Who
    may reach the pages" keeps the pages to some networks: [reasons] - the CRLs
    and certificates of acme's own authorities published at /pki/, and HTTP-01
    answered here (a validation of kind http_local switched on)."""
    out = []
    try:
        if int(CONFIG.get('pki_publish', 1) or 0):
            out.append('pki')
    except (TypeError, ValueError):
        pass
    try:
        if store is not None and store.db.value(
                "SELECT COUNT(*) FROM cert_challenges WHERE kind = 'http_local' AND "
                "COALESCE(enabled, 1) <> 0", (), 0):
            out.append('http-01')
    except Exception:                                   # noqa: BLE001
        pass
    return out


# acme's own DNS server (Settings → DNS server) let in by the firewall on every
# node by itself: a card of its own under "What acme lets in by itself", there
# while the server is switched on, gone when it is switched off, its port
# following dns_port. From anywhere - the CAs and the public resolvers ask it.
# It may be turned off on that card like the others (a rule of your own then).
@_certs_hook('firewall')
def certs_firewall(store, node):
    try:
        on = int(CONFIG.get('dns_server') or 0)
    except (TypeError, ValueError):
        on = 0
    if not on:
        return []
    try:
        port = int(CONFIG.get('dns_port') or 53)
    except (TypeError, ValueError):
        port = 53
    return [{'key': 'dns', 'title': 'DNS server (DNS-01)',
             'why': 'acme\'s own DNS server, switched on under Settings → DNS server: the '
                    'CAs and the public resolvers ask it for the _acme-challenge records, '
                    'so from anywhere, UDP and TCP',
             'rules': [{'family': f, 'proto': p, 'port': str(port), 'source': ''}
                       for f in (4, 6) for p in ('udp', 'tcp')]}]


CHOICE_WORDS['dns_expose'] = {'both': 'on the VIP address and on the nodes',
                              'vip': 'on the VIP address only',
                              'nodes': 'on the nodes only'}


# The private keys of the certificate manager are sealed under binds of their
# own (acmelib/certs/store.py key_place, acmelib/certs/ca.py): told to the
# engine, so a backup's check and the configuration's export open them.
SEAL_BINDS[('cert_cas', 'key_sealed')] = lambda r: 'cert_cas:%d:key' % int(r['id'])
SEAL_BINDS[('certs', 'key_sealed')] = \
    lambda r: 'certs:%s:key_sealed:%s' % (r['id'], r.get('version') or 0)
SEAL_BINDS[('cert_versions', 'key_sealed')] = \
    lambda r: 'certs:%s:%s:%s' % (r['cert_id'], 'alt_key_sealed' if r.get('variant') == 'alt'
                                  else 'key_sealed', r.get('version') or 0)
# The twin of a dual certificate (key_type_alt): its key under a bind of its own.
SEAL_BINDS[('certs', 'alt_key_sealed')] = \
    lambda r: 'certs:%s:alt_key_sealed:%s' % (r['id'], r.get('alt_version') or 0)
