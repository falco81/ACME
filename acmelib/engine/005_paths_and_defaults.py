# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# Paths and defaults
# ---------------------------------------------------------------------------
CONFIG_FILE = Path(os.environ.get('ACME_CONFIG', '/etc/acme/config.json'))
STATE_DIR = Path(os.environ.get('ACME_STATE', '/var/lib/acme'))
DB_FILE = STATE_DIR / 'acme.db'
BACKUP_DIR = STATE_DIR / 'backups'
RUN_DIR = Path(os.environ.get('ACME_RUN', '/run/acme'))
TOKEN_FILE = RUN_DIR / 'api-token'
LOG_DIR = Path(os.environ.get('ACME_LOGDIR', '/var/log/acme'))
SERVICE_USER = 'acme'
WEB_GROUP = 'acme-web'

# Who may do what on the administration pages. `tokenadmin` is the help
# desk: it may look at everything and look after people's tokens - make one,
# switch one off, give new recovery codes, take one away - and nothing else:
# no setting, no RADIUS client, no realm, no account.
ROLES_ALL = ('fulladmin', 'tokenadmin', 'readonly')
ROLE_WORDS = {'fulladmin': 'full admin', 'tokenadmin': 'token admin',
              'readonly': 'read only'}

DEFAULTS = {
    # --- the RADIUS server ------------------------------------------------
    'radius_bind': '0.0.0.0',
    'radius_auth_port': 1812,
    'radius_acct_port': 1813,
    'radius_status_server': 1,
    'radius_reply_ma': 1,
    'radius_dup_window_s': 30,
    'radius_workers': 16,
    'radius_unknown_log': 1,
    'radius_reject_delay_ms': 0,
    'radius_reject_reason': 0,
    'radius_ma_sticky': 1,
    # --- sign-in protection (1.0.137) ----------------------------------------
    'radius_guard': 0,
    'radius_guard_tries': 20,
    'radius_guard_names': 5,
    'radius_guard_window_min': 15,
    'radius_guard_block_min': 30,
    'radius_guard_trusted': '',
    'net_confirm_min': 10,
    'fw_confirm_min': 5,
    # --- the tokens ---------------------------------------------------------
    'totp_issuer': 'ACME',
    'totp_label': '{user}',
    'totp_digits': 6,
    'totp_period': 30,
    'totp_algorithm': 'SHA1',
    'totp_window': 1,
    'admin_show_key': 1,
    'high_security': 0,
    'totp_disallow_reuse': 1,
    # --- upgrades from the web (1.0.123) ----------------------------------
    'upgrade_check': 1,
    'upgrade_downgrade': 0,
    'upgrade_url': 'https://github.com/falco81/ACME/tree/main/release',
    'rate_limit_tries': 3,
    'lockout_after': 10,
    'lockout_min': 15,
    'rate_limit_s': 30,
    'scratch_count': 5,
    'scratch_digits': 8,
    'token_names_case': 'lower',
    'names_czsk_letters': 0,
    'names_any_letters': 0,
    # --- the enrolment pages -------------------------------------------------
    'portal': 1,
    'portal_title': '',
    'portal_realm': '',
    'default_realm': '',
    'portal_hint': '',
    'portal_who': 'realm_groups',
    'portal_groups': '',
    'portal_confirm': 1,
    'portal_reissue': 1,
    'portal_show_secret': 1,
    'portal_scratch': 1,
    'portal_codes_view': 0,
    'portal_session_min': 15,
    'portal_help': '',
    'portal_tries': 5,
    'portal_wait_min': 15,
    # --- the administration pages -------------------------------------------
    'session_hours': 12,
    'session_idle_min': 120,
    'login_tries': 5,
    'login_wait_min': 15,
    'admin_directory': '',
    'admin_group_full': '',
    'admin_group_token': '',
    'admin_group_readonly': '',
    # --- a second step for the administration (1.0.125) -------------------
    'admin_2fa': 0,
    'admin_2fa_app': 1,
    'admin_2fa_mail': 1,
    'admin_2fa_sms': 1,
    # --- isemon ---------------------------------------------------------------
    'isemon': 0,
    'isemon_targets': '',
    'isemon_hostname': '',
    'isemon_detail': 1,
    'isemon_events': 0,
    'isemon_max_bytes': 1800,
    'isemon_ca': '',
    # --- Prometheus (1.0.173) ----------------------------------------------------
    'metrics': 0,
    'ssh_gate_port': 18129,
    'metrics_token': '',
    'metrics_from': '',
    # --- SNMPv3 (1.0.182) ------------------------------------------------------
    'snmp': 0,
    'snmp_port': 161,
    'snmp_bind': '',
    'snmp_from': '',
    'snmp_user': '',
    'snmp_auth': 'SHA-256',
    'snmp_auth_pass': '',
    'snmp_priv': 'AES-128',
    'snmp_priv_pass': '',
    'snmp_contact': '',
    'snmp_location': '',
    'snmp_traps': 0,
    'snmp_trap_to': '',
    'isemon_verify': 1,
    'isemon_mtls': 0,
    'ship_files': 1,
    # --- sending mail (1.0.20) ----------------------------------------------
    'mail_mode': 'off',
    'smtp_host': '',
    'smtp_port': 0,
    'smtp_security': 'starttls',
    'smtp_auth': 'auto',
    'smtp_user': '',
    'smtp_password': '',
    'smtp_verify': 1,
    'smtp_timeout_s': 20,
    'mail_from': '',
    'mail_from_name': '',
    'mail_reply_to': '',
    'mail_helo': '',
    'mail_direct_port': 25,
    'mail_direct_tls': 'if-offered',
    'mail_dns': '',
    'mail_lang': 'cs',
    'mail_codes': 1,
    'mail_retry_hours': 24,
    'mail_keep_days': 14,
    # --- codes sent by mail or SMS (1.0.76) -------------------------------------
    'code_digits': 6,
    'code_ttl_s': 300,
    'code_tries': 3,
    'code_send_max': 5,
    'code_send_window_min': 15,
    'code_lang': '',
    'code_mail_fmt': 'html',
    'sms_mode': 'off',
    'sms_url': '',
    'sms_method': 'POST',
    'sms_body': '',
    'sms_headers': '',
    'sms_token': '',
    'sms_spool_dir': '/var/spool/sms/outgoing',
    'sms_prefix': '+420',
    'sms_ok_status': '',
    # Teltonika (TRB140 and its kin, RutOS), as zigmon speaks to it (1.0.81).
    'sms_tel_host': '',
    'sms_tel_https': 1,
    'sms_tel_verify': 0,
    'sms_tel_user': 'admin',
    'sms_tel_password': '',
    'sms_tel_api': 'rest',
    'sms_tel_modem': '',
    'sms_plain': 1,
    # --- keeping things -------------------------------------------------------
    'retain_radius_days': 180,
    'retain_acme_days': 180,
    'retain_events_days': 365,
    'backup_daily': 1,
    'backup_keep': 14,
    'backup_at': '03:30',
    # --- backups to another machine (1.0.109) -------------------------------------
    'rbackup': 0,
    'rbackup_at': '04:15',
    'rbackup_every': 'daily',
    'rbackup_day': 7,
    'rbackup_keep': 30,
    'rbackup_keep_days': 0,
    'rbackup_verify': 'off',
    'rbackup_password': '',
    # --- alerts by mail, and the report (1.0.162) -----------------------------
    'alerts': 0,
    'alerts_to': '',
    'alerts_delay_min': 5,
    'alerts_repeat_h': 24,
    'alerts_resolved': 1,
    'alerts_nodes': 1,
    'alerts_db': 1,
    'alerts_vrrp': 1,
    'alerts_backup': 1,
    'alerts_cert_days': 21,
    'alerts_disk_pct': 85,
    'alerts_time': 1,
    'alerts_updates': 1,
    'alerts_dir': 1,
    'alerts_sms': 1,
    'alerts_guard': 0,
    'alerts_url': '',
    'alerts_lang': '',
    'report_lang': '',
    'report': 0,
    'report_to': '',
    'report_every': 'weekly',
    'report_day': '1',
    'report_at': '07:30',
    # --- updates and restarts on a schedule (1.0.164) ----------------------
    'osup_check': 0,
    'osup_check_at': '06:15',
    'osup_auto': 0,
    'osup_auto_what': 'security',
    'osup_auto_every': 'weekly',
    'osup_auto_day': '7',
    'osup_auto_at': '04:45',
    'osup_auto_reboot': 'auto',
    'power_auto': 0,
    'power_auto_every': 'weekly',
    'power_auto_day': '7',
    'power_auto_at': '05:40',
    'power_auto_needed': 1,
    'siem': 0,
    'siem_targets': '',
    'siem_format': 'json',
    'siem_events': 1,
    'siem_signins': 1,
    'siem_facility': 13,
    'siem_hostname': '',
    'siem_verify': 1,
    'siem_ca': '',
    'proxy': 0,
    'proxy_url': '',
    'proxy_user': '',
    'proxy_password': '',
    'proxy_no': 'localhost, 127.0.0.1, ::1',
    'proxy_update': 0,
    'proxy_os': 0,
    'proxy_acme': 0,
    'proxy_acme_dns': 0,
    'proxy_sms': 0,
    'logs_journal_mb': 0,
    'logs_journal_days': 0,
    'logs_keep': 30,
    'logs_max_mb': 200,
    'acme': 0,
    'acme_email': '',
    'acme_ca': 'letsencrypt',
    'acme_url': '',
    'acme_ca_pem': '',
    'acme_for': 'vip',
    'acme_node_name': '',
    'acme_days': 30,
    'acme_key': 'dual',
    'acme_account_key': 'ec',
    'acme_profile': '',
    'acme_challenge': 'http-01',
    'acme_dns': 'manual',
    'acme_dns_server': '',
    'acme_dns_zone': '',
    'acme_dns_tsig_name': '',
    'acme_dns_tsig_alg': 'hmac-sha256',
    'acme_dns_tsig_secret': '',
    'acme_dns_token': '',
    'acme_dns_url': '',
    'acme_dns_user': '',
    'acme_dns_key': '',
    'acme_dns_subdomain': '',
    'acme_desec_domain': '',
    'acme_desec_token': '',
    'acme_dns_alias': '',
    'acme_dns_wait': 30,
    'acme_resolvers': '',
    # --- the database ---------------------------------------------------------
    'db_engine': 'sqlite',
    'db_host': '',
    'db_port': 0,
    'db_name': 'acme',
    'db_user': 'acme',
    'db_password': '',
    'db_timeout_s': 10,
    'db_tls': '',
    'db_tls_ca': '',
    # --- this installation ----------------------------------------------------
    'node_name': '',
    'ha_mode': '',
    'ha_slot': 0,
    'ha_peer': '',
    'ha_peer_port': 5432,
    'ha_address': '',
    # The link to the other node's PostgreSQL, its own (1.0.104): set by the
    # High availability page's button, apart from Database → TLS.
    'ha_tls': '',
    'ha_tls_ca': '',
    'site_name': '',
    'ui_lang': 'cs',
    'api_port': 9861,
    'debug': False,
    'debug_radius': 1,
    'debug_ldap': 1,
    'debug_api': 0,
    'debug_codes': 1,
}

# The settings that are a database's own address. A database cannot hold the
# address of itself, so these live in config.json and are written there.
DB_KEYS = ('db_engine', 'db_host', 'db_port', 'db_name', 'db_user', 'db_password',
           'db_timeout_s', 'db_tls', 'db_tls_ca')

# ...and the name of this node of a cluster, which is this machine's own.
FILE_ONLY_KEYS = DB_KEYS + ('node_name', 'ha_mode', 'ha_slot', 'ha_peer', 'ha_peer_port',
                             'ha_address', 'ha_tls', 'ha_tls_ca')

# Settings of one node of a cluster, not of the cluster (1.0.37): saved as
# `key@node` and read only by that node; without one it takes the cluster's.
# The address RADIUS listens on is this machine's own, and so are the port
# the pages ask the daemon on, the name it greets mail servers with, the
# name isemon files its lines under and the debug switches.
NODE_KEYS = ('radius_bind', 'radius_auth_port', 'radius_acct_port', 'api_port', 'mail_helo',
             'isemon_hostname', 'siem_hostname', 'acme_node_name', 'backup_daily', 'backup_at', 'backup_keep', 'debug',
             'debug_radius', 'debug_ldap', 'debug_api', 'debug_codes', 'snmp_bind')
# 1.0.67: the RADIUS ports (a node behind its own NAT, or a second instance),
# and its copies of the database - each node keeps its own on its own disk:
# when, whether, how many.


def this_node_name(conf=None):
    said = str((conf or CONFIG).get('node_name') or '').strip()
    return said or (socket.gethostname().split('.')[0] or 'acme')


METRICS_TOKEN_RE_HEAD = re.compile(r'^[A-Za-z0-9_.~+/=-]{24,200}\Z')
SECRET_KEYS = ('db_password', 'smtp_password', 'sms_token', 'sms_tel_password',
               'rbackup_password', 'proxy_password', 'acme_dns_tsig_secret', 'acme_dns_token',
               'acme_dns_key', 'acme_desec_token', 'metrics_token', 'snmp_auth_pass',
               'snmp_priv_pass')
# Secrets kept in the database, sealed with the key that seals the tokens.
SEALED_KEYS = ('smtp_password', 'sms_token', 'sms_tel_password', 'rbackup_password',
               'proxy_password', 'acme_dns_tsig_secret', 'acme_dns_token', 'acme_dns_key',
               'acme_desec_token', 'metrics_token', 'snmp_auth_pass', 'snmp_priv_pass')

# What each setting may be: a list of words, or the lowest and highest number.
TUNABLE = {
    'radius_auth_port': (1, 65535), 'radius_acct_port': (0, 65535),
    'radius_status_server': (0, 1), 'radius_reply_ma': (0, 1),
    'radius_dup_window_s': (0, 600), 'radius_workers': (1, 256),
    'radius_unknown_log': (0, 1), 'radius_reject_delay_ms': (0, 10000),
    'totp_digits': (6, 8), 'totp_period': (15, 120),
    'totp_algorithm': ('SHA1', 'SHA256', 'SHA512'),
    'totp_window': (0, 10), 'admin_show_key': (0, 1), 'high_security': (0, 1), 'totp_disallow_reuse': (0, 1),
    'upgrade_check': (0, 1), 'upgrade_downgrade': (0, 1),
    'rate_limit_tries': (0, 100), 'rate_limit_s': (1, 86400),
    'lockout_after': (0, 1000), 'lockout_min': (1, 10080),
    'radius_reject_reason': (0, 1), 'radius_ma_sticky': (0, 1),
    'radius_guard': (0, 1), 'radius_guard_tries': (2, 10000), 'radius_guard_names': (0, 1000),
    'radius_guard_window_min': (1, 1440), 'radius_guard_block_min': (1, 10080),
    'net_confirm_min': (0, 120), 'fw_confirm_min': (0, 120),
    'scratch_count': (0, 20), 'scratch_digits': (6, 12),
    'token_names_case': ('lower', 'as-typed'),
    'names_czsk_letters': (0, 1),
    'names_any_letters': (0, 1),
    'portal': (0, 1), 'portal_who': ('realm_groups', 'groups', 'anyone'),
    'portal_confirm': (0, 1), 'portal_reissue': (0, 1), 'portal_show_secret': (0, 1),
    'portal_scratch': (0, 1), 'portal_codes_view': (0, 1), 'portal_session_min': (1, 240),
    'portal_tries': (1, 100), 'portal_wait_min': (1, 1440),
    'session_hours': (1, 168), 'session_idle_min': (5, 1440),
    'login_tries': (1, 100), 'login_wait_min': (1, 1440),
    'admin_2fa': (0, 1), 'admin_2fa_app': (0, 1), 'admin_2fa_mail': (0, 1), 'admin_2fa_sms': (0, 1),
    'isemon': (0, 1), 'isemon_detail': (0, 1), 'isemon_events': (0, 1),
    'isemon_verify': (0, 1), 'isemon_mtls': (0, 1), 'metrics': (0, 1),
    'ssh_gate_port': (1025, 65535),
    'snmp': (0, 1), 'snmp_port': (1, 65535), 'snmp_auth': ('SHA-256', 'SHA-512', 'SHA-1'),
    'snmp_priv': ('AES-128', 'AES-256'), 'snmp_traps': (0, 1),
    'isemon_max_bytes': (480, 65000), 'ship_files': (0, 1),
    'retain_radius_days': (0, 36500), 'retain_acme_days': (0, 36500),
    'retain_events_days': (0, 36500), 'backup_daily': (0, 1), 'backup_keep': (1, 365),
    'rbackup': (0, 1), 'rbackup_every': ('daily', 'weekly'), 'rbackup_day': (1, 7),
    'rbackup_keep': (1, 1000), 'rbackup_keep_days': (0, 3650),
    'rbackup_verify': ('off', 'after', 'weekly'),
    'alerts': (0, 1), 'alerts_delay_min': (0, 120), 'alerts_repeat_h': (0, 168),
    'alerts_resolved': (0, 1), 'alerts_nodes': (0, 1), 'alerts_backup': (0, 1),
    'alerts_db': (0, 1), 'alerts_vrrp': (0, 1),
    'alerts_cert_days': (0, 120), 'alerts_disk_pct': (0, 99), 'alerts_time': (0, 1),
    'alerts_updates': (0, 1), 'alerts_dir': (0, 1), 'alerts_sms': (0, 1), 'alerts_guard': (0, 1),
    'report': (0, 1), 'report_every': ('daily', 'weekly', 'monthly'),
    'report_day': ('1', '2', '3', '4', '5', '6', '7'),
    'alerts_lang': ('', 'cs', 'en'), 'report_lang': ('', 'cs', 'en'),
    'osup_check': (0, 1), 'osup_auto': (0, 1), 'osup_auto_what': ('security', 'all'),
    'osup_auto_every': ('daily', 'weekly', 'monthly'),
    'osup_auto_day': ('1', '2', '3', '4', '5', '6', '7'), 'osup_auto_reboot': ('ask', 'auto'),
    'power_auto': (0, 1), 'power_auto_every': ('weekly', 'monthly'),
    'power_auto_day': ('1', '2', '3', '4', '5', '6', '7'), 'power_auto_needed': (0, 1),
    'siem': (0, 1), 'siem_format': ('json', 'cef', 'rfc5424'), 'siem_events': (0, 1),
    'siem_signins': (0, 1), 'siem_facility': (0, 23), 'siem_verify': (0, 1),
    'proxy': (0, 1), 'proxy_update': (0, 1), 'proxy_os': (0, 1), 'proxy_acme': (0, 1),
    'proxy_acme_dns': (0, 1), 'proxy_sms': (0, 1),
    'logs_journal_mb': (0, 100000), 'logs_journal_days': (0, 3650), 'logs_keep': (1, 3650),
    'logs_max_mb': (1, 100000),
    'acme': (0, 1), 'acme_ca': ('letsencrypt', 'letsencrypt-staging', 'custom'),
    'acme_for': ('vip', 'node', 'both'), 'acme_days': (7, 60), 'acme_key': ('dual', 'dual-strong', 'ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'),
    'acme_account_key': ('ec', 'ec384', 'rsa2048', 'rsa3072', 'rsa4096'),
    'acme_profile': ('', 'classic', 'tlsserver', 'shortlived'),
    'acme_challenge': ('http-01', 'dns-01'), 'acme_dns': ('manual', 'rfc2136', 'cloudflare', 'acmedns',
                                                                             'desec'),
    'acme_dns_tsig_alg': ('hmac-sha256', 'hmac-sha512', 'hmac-sha384', 'hmac-sha224', 'hmac-sha1',
                          'hmac-md5'),
    'acme_dns_wait': (0, 600),
    'db_engine': ('sqlite', 'mariadb', 'postgres'), 'db_port': (0, 65535),
    'db_timeout_s': (1, 300), 'ui_lang': ('cs', 'en'), 'api_port': (1024, 65535),
    'debug_radius': (0, 1), 'debug_ldap': (0, 1), 'debug_api': (0, 1), 'debug_codes': (0, 1),
    'mail_mode': ('off', 'smtp', 'direct'), 'smtp_port': (0, 65535),
    'smtp_security': ('starttls', 'tls', 'starttls-if', 'none'),
    'db_tls': ('', 'require', 'verify-ca', 'verify-full'),
    'mail_direct_tls': ('if-offered', 'required'),
    'smtp_auth': ('none', 'auto', 'plain', 'login', 'cram-md5', 'xoauth2'),
    'smtp_verify': (0, 1), 'smtp_timeout_s': (3, 300), 'mail_direct_port': (1, 65535),
    'mail_lang': ('cs', 'en'), 'mail_codes': (0, 1),
    'mail_retry_hours': (1, 168), 'mail_keep_days': (1, 365),
    'code_digits': (4, 10), 'code_ttl_s': (60, 1800), 'code_tries': (1, 10),
    'code_send_max': (1, 100), 'code_send_window_min': (1, 1440), 'code_lang': ('', 'cs', 'en'),
    'code_mail_fmt': ('html', 'text'),
    'sms_mode': ('off', 'http', 'spool', 'teltonika'), 'sms_method': ('POST', 'GET'),
    'sms_tel_https': (0, 1), 'sms_tel_verify': (0, 1), 'sms_tel_api': ('rest', 'cgi'),
    'sms_plain': (0, 1),
}

CHOICE_WORDS = {
    'acme_challenge': {'http-01': 'HTTP-01 - the CA asks port 80 of the name',
                       'dns-01': 'DNS-01 - a TXT record in DNS (no port open to the internet)'},
    'acme_dns': {'manual': 'by hand - the record is shown here, you put it in',
                 'rfc2136': 'RFC 2136 dynamic update with a TSIG key (BIND, PowerDNS, Knot...)',
                 'cloudflare': 'Cloudflare, with an API token', 'acmedns': 'an acme-dns server',
                 'desec': 'deSEC.io (free), with an API token - a CNAME in your DNS'},
    'acme_ca': {'letsencrypt': 'Let\u2019s Encrypt', 'letsencrypt-staging': 'Let\u2019s Encrypt - staging (to try it)',
                'custom': 'another ACME CA (step-ca, an internal CA...)'},
    'acme_for': {'vip': 'the VIP address (or this node, where there is none)',
                 'node': 'each node\u2019s own name', 'both': 'the VIP address and each node'},
    'acme_key': {'dual': 'Both: RSA 2048 + ECDSA P-256 (advised)',
                 'dual-strong': 'Both: RSA 4096 + ECDSA P-384',
                 'ec': 'ECDSA P-256', 'ec384': 'ECDSA P-384',
                 'rsa2048': 'RSA 2048', 'rsa3072': 'RSA 3072', 'rsa4096': 'RSA 4096'},
    'acme_account_key': {'ec': 'ECDSA P-256 (ES256)', 'ec384': 'ECDSA P-384 (ES384)',
                         'rsa2048': 'RSA 2048 (RS256)', 'rsa3072': 'RSA 3072 (RS256)',
                         'rsa4096': 'RSA 4096 (RS256)'},
    'acme_profile': {'': 'the CA\u2019s own (classic at Let\u2019s Encrypt)',
                     'classic': 'classic - 90 days', 'tlsserver': 'tlsserver - 90 days, for TLS servers only',
                     'shortlived': 'shortlived - 6 days'},
    'rbackup_verify': {'off': 'only by hand', 'after': 'after every backup, the one just sent',
                       'weekly': 'once a week, the newest one'},
    'mail_mode': {'off': 'off - no mail is sent',
                  'smtp': 'through a mail server (SMTP relay)',
                  'direct': 'straight to the recipient’s mail server (MX), no relay'},
    'mail_direct_tls': {'if-offered': 'encrypted where the server offers it',
                        'required': 'encrypted, or not sent at all'},
    'smtp_security': {'starttls': 'STARTTLS - plain, then encrypted (587)',
                      'tls': 'TLS from the start - SMTPS (465)',
                      'starttls-if': 'STARTTLS if the server offers it',
                      'none': 'none - plain text (25)'},
    'smtp_auth': {'none': 'none - the server lets this machine send',
                  'auto': 'whatever the server offers best (PLAIN, LOGIN, CRAM-MD5)',
                  'plain': 'PLAIN', 'login': 'LOGIN', 'cram-md5': 'CRAM-MD5',
                  'xoauth2': 'XOAUTH2 - an OAuth access token as the password'},
    'mail_lang': {'cs': 'Čeština', 'en': 'English'},
    'code_lang': {'': 'as the mail (Language of the mail)', 'cs': 'Čeština', 'en': 'English'},
    'code_mail_fmt': {'html': 'HTML, as a token’s mail looks - with the plain text beside it',
                      'text': 'plain text only'},
    'sms_mode': {'off': 'off - no SMS is sent',
                 'http': 'an SMS gateway with an HTTP API',
                 'spool': 'a modem on this machine - a file into the spool of smstools / gammu',
                 'teltonika': 'a Teltonika gateway (TRB140, RUT…) on the network - as zigmon uses it'},
    'sms_tel_api': {'rest': 'RutOS’s own API (/api, RutOS 7 - the default)',
                    'cgi': 'the older Post/Get SMS service (/cgi-bin/sms_send)'},
    'sms_method': {'POST': 'POST', 'GET': 'GET'},
    'totp_algorithm': {'SHA1': 'SHA-1 (what every phone app understands)',
                       'SHA256': 'SHA-256', 'SHA512': 'SHA-512'},
    'token_names_case': {'lower': 'small letters - Novak and novak are one person',
                         'as-typed': 'exactly as written'},
    'portal_who': {'realm_groups': 'whoever passes the realm’s group filter',
                   'groups': 'members of the groups named below',
                   'anyone': 'anybody the directory lets sign in'},
    'db_engine': {'sqlite': 'a file on this machine (SQLite)', 'mariadb': 'MariaDB / MySQL',
                  'postgres': 'PostgreSQL'},
    'ui_lang': {'cs': 'Čeština', 'en': 'English'},
    'report_every': {'daily': 'every day, of the day before',
                     'weekly': 'every week, of the week before',
                     'monthly': 'every month, of the month before'},
    'alerts_lang': {'': 'as the mails (Settings → Mail)', 'cs': 'Čeština', 'en': 'English'},
    'report_lang': {'': 'as the alerts', 'cs': 'Čeština', 'en': 'English'},
    'osup_auto_what': {'security': 'only the security updates', 'all': 'every update'},
    'osup_auto_every': {'daily': 'every day', 'weekly': 'every week, on the day below',
                        'monthly': 'on the first of every month'},
    'osup_auto_day': {'1': 'Monday', '2': 'Tuesday', '3': 'Wednesday', '4': 'Thursday', '5': 'Friday', '6': 'Saturday', '7': 'Sunday'},
    'osup_auto_reboot': {'auto': 'restarted by itself where an update needs it',
                         'ask': 'a restart offered on the page'},
    'power_auto_every': {'weekly': 'every week, on the day below',
                         'monthly': 'on the first of every month'},
    'power_auto_day': {'1': 'Monday', '2': 'Tuesday', '3': 'Wednesday', '4': 'Thursday', '5': 'Friday', '6': 'Saturday', '7': 'Sunday'},
    'siem_format': {'json': 'JSON - one object to a line (Graylog, Splunk, Elastic, Wazuh)',
                    'cef': 'CEF - ArcSight, QRadar, Sentinel',
                    'rfc5424': 'RFC 5424 with structured data, key="value"'},
    'report_day': {'1': 'Monday', '2': 'Tuesday', '3': 'Wednesday', '4': 'Thursday',
                   '5': 'Friday', '6': 'Saturday', '7': 'Sunday'},
}

NAMES = {
    'mail_mode': 'Sending mail',
    'smtp_host': 'Mail server',
    'smtp_port': 'Port',
    'smtp_security': 'Encryption',
    'smtp_auth': 'Signing in',
    'smtp_user': 'Account',
    'smtp_password': 'Password',
    'smtp_verify': 'Check the server’s certificate',
    'smtp_timeout_s': 'Wait for the server (s)',
    'mail_from': 'From (address)',
    'mail_from_name': 'From (name)',
    'mail_reply_to': 'Replies to',
    'mail_helo': 'This machine calls itself (EHLO)',
    'mail_direct_port': 'Port of the recipients’ servers',
    'mail_direct_tls': 'Encryption to the recipients’ servers',
    'mail_dns': 'DNS servers for the recipients’ domains',
    'mail_lang': 'Language of the mail',
    'mail_codes': 'Recovery codes in the mail',
    'mail_retry_hours': 'Try a mail not delivered for (hours)',
    'mail_keep_days': 'Keep the list of mails sent for (days)',
    'code_digits': 'Digits of a code sent by mail or SMS',
    'code_ttl_s': 'A sent code is good for (seconds)',
    'code_tries': 'Wrong codes before it has to be sent again',
    'code_send_max': 'Codes sent to one person at most',
    'code_send_window_min': '… in (minutes)',
    'code_lang': 'Language of the codes and of the VPN’s question',
    'code_mail_fmt': 'A mail with a code is',
    'sms_mode': 'How SMS is sent',
    'sms_url': 'The gateway’s address (URL)',
    'sms_method': 'HTTP method',
    'sms_body': 'What is sent (body)',
    'sms_headers': 'Headers',
    'sms_token': 'The gateway’s key ({token})',
    'sms_spool_dir': 'The spool folder',
    'sms_prefix': 'Country code for numbers written without one',
    'sms_ok_status': 'The gateway said it was sent when the answer holds',
    'sms_tel_host': 'The Teltonika’s address',
    'sms_tel_https': 'Over HTTPS',
    'sms_tel_verify': 'Check its certificate',
    'sms_tel_user': 'Its user',
    'sms_tel_password': 'Its password',
    'sms_tel_api': 'Its interface',
    'sms_tel_modem': 'Its modem',
    'sms_plain': 'Without accents (one SMS, not two)',
    'radius_bind': 'Listen on the address',
    'radius_auth_port': 'Authentication port',
    'radius_acct_port': 'Accounting port',
    'radius_status_server': 'Answer Status-Server',
    'radius_reply_ma': 'Sign every answer (Message-Authenticator)',
    'radius_dup_window_s': 'A repeated request is the same one for (s)',
    'radius_workers': 'Requests answered at once',
    'radius_unknown_log': 'Write down requests from unknown clients',
    'radius_reject_delay_ms': 'Wait before a refusal (ms)',
    'totp_issuer': 'The issuer, as the phone shows it',
    'totp_label': 'The account name, as the phone shows it',
    'totp_digits': 'Digits in a code',
    'totp_period': 'A code lasts (s)',
    'totp_algorithm': 'The hash',
    'totp_window': 'Steps of clock drift allowed',
    'admin_show_key': 'Administrators may show a token\'s QR code and key',
    'high_security': 'High security',
    'upgrade_check': 'Look for a new version every day',
    'upgrade_downgrade': 'Offer going back to an older version',
    'upgrade_url': 'Where new versions are looked for',
    'totp_disallow_reuse': 'A code works only once',
    'rate_limit_tries': 'Wrong codes before a pause',
    'lockout_after': 'Wrong codes in a row before a lockout',
    'lockout_min': 'Locked out for (min)',
    'radius_reject_reason': 'Say why in a refusal',
    'radius_ma_sticky': 'Hold a client to the Message-Authenticator',
    'radius_guard': 'Block a place that keeps guessing',
    'radius_guard_tries': 'Wrong sign-ins from one place before it is blocked',
    'radius_guard_names': 'Different names refused from one place before it is blocked',
    'radius_guard_window_min': '...counted over (min)',
    'radius_guard_block_min': 'Blocked for (min)',
    'radius_guard_trusted': 'Never blocked',
    'net_confirm_min': 'A new network goes back unless kept within (min)',
    'fw_confirm_min': 'A firewall change goes back unless kept within (min)',
    'rate_limit_s': '...counted over (s)',
    'scratch_count': 'Recovery codes per token',
    'scratch_digits': 'Digits in a recovery code',
    'token_names_case': 'Names of tokens are kept in',
    'names_czsk_letters': 'Czech and Slovak letters in names',
    'names_any_letters': 'Letters of other languages in names',
    'portal': 'The enrolment pages are open',
    'portal_title': 'The title of the enrolment pages',
    'portal_realm': 'Realm added to a name signed in without one',
    'default_realm': 'The default realm',
    'portal_hint': 'What to type as the name (shown on the sign-in)',
    'portal_who': 'Who may enrol a token',
    'portal_groups': 'Groups that may enrol',
    'portal_confirm': 'A new token must be confirmed with a code',
    'portal_reissue': 'People may replace their own token',
    'portal_show_secret': 'Show the key as text beside the QR code',
    'portal_scratch': 'Show the recovery codes',
    'portal_codes_view': 'People may look at their recovery codes again',
    'portal_session_min': 'An enrolment sign-in lasts (min)',
    'portal_help': 'Help text on the enrolment pages',
    'portal_tries': 'Wrong passwords on the enrolment pages before a pause',
    'portal_wait_min': '...and the pause (min)',
    'session_hours': 'A sign-in lasts (h)',
    'session_idle_min': '...and may sit untouched (min)',
    'login_tries': 'Wrong passwords before a pause',
    'login_wait_min': '...and the pause (min)',
    'admin_directory': 'Sign administrators in against the directory',
    'admin_group_full': 'Group of full administrators',
    'admin_group_token': 'Group of token administrators',
    'admin_group_readonly': 'Group of read-only accounts',
    'admin_2fa': 'A second step when signing in to these pages',
    'admin_2fa_app': '...with an authenticator app',
    'admin_2fa_mail': '...with a code by e-mail',
    'admin_2fa_sms': '...with a code by SMS',
    'isemon': 'Send the logs to isemon',
    'isemon_targets': 'isemon’s syslog receivers',
    'isemon_hostname': 'The name this machine is written under',
    'isemon_detail': 'Send the RADIUS packets as well (radius-detail)',
    'isemon_events': 'Send this daemon’s own events as well',
    'isemon_max_bytes': 'Longest message (bytes)',
    'isemon_ca': 'isemon’s certificate authority (TLS)',
    'metrics': 'Prometheus metrics (/metrics)',
    'metrics_token': 'Its token (Bearer)',
    'metrics_from': 'Only from',
    'ssh_gate_port': 'acme\u2019s gate for SSH: the port tried first',
    'snmp': 'SNMPv3',
    'snmp_port': 'Port (UDP)',
    'snmp_bind': 'Listen on',
    'snmp_from': 'SNMP only from',
    'snmp_user': 'User',
    'snmp_auth': 'Authentication',
    'snmp_auth_pass': 'Its passphrase (authentication)',
    'snmp_priv': 'Encryption',
    'snmp_priv_pass': 'Its passphrase (encryption)',
    'snmp_contact': 'Contact (sysContact)',
    'snmp_location': 'Location (sysLocation)',
    'snmp_traps': 'Traps when something is wrong',
    'snmp_trap_to': 'Where traps go',
    'isemon_verify': 'Check isemon’s certificate (TLS)',
    'isemon_mtls': 'Each node shows isemon a certificate of its own (TLS)',
    'ship_files': 'Write the same lines into files here too',
    'retain_radius_days': 'Keep the RADIUS requests (days)',
    'retain_acme_days': 'Keep the token checks (days)',
    'retain_events_days': 'Keep the events (days)',
    'backup_daily': 'A copy of the database every day',
    'backup_keep': 'Copies kept',
    'rbackup': 'Backups to the destinations on a schedule',
    'rbackup_at': 'At',
    'rbackup_every': 'How often',
    'rbackup_day': 'On (1 Monday - 7 Sunday)',
    'rbackup_keep': 'Backups kept at each destination',
    'rbackup_keep_days': 'And none older than (days)',
    'rbackup_verify': 'Try the backups',
    'rbackup_password': 'The password of the backups',
    'alerts': 'Alerts by mail',
    'alerts_to': 'Send them to',
    'alerts_delay_min': 'Only once it has lasted (min)',
    'alerts_repeat_h': 'Remind every (hours)',
    'alerts_resolved': 'Say when it is over',
    'alerts_nodes': 'A node, RADIUS, the replication or the database down',
    'alerts_db': 'The database and its replication',
    'alerts_vrrp': 'The VIP address (VRRP)',
    'alerts_backup': 'A backup that failed or did not come',
    'alerts_cert_days': 'A certificate running out within (days)',
    'alerts_disk_pct': 'A disk fuller than (%)',
    'alerts_time': 'A clock that is off',
    'alerts_updates': 'Security updates and a restart waiting',
    'alerts_dir': 'Active Directory out of reach',
    'alerts_sms': 'The SMS gateway failing',
    'alerts_guard': 'A source blocked for guessing',
    'alerts_url': 'The administration’s address in the mails',
    'alerts_lang': 'Language of the alerts',
    'report_lang': 'Language of the report',
    'osup_check': 'Look for updates every day',
    'osup_check_at': 'At',
    'osup_auto': 'Updates on a schedule',
    'osup_auto_what': 'Which',
    'osup_auto_every': 'How often',
    'osup_auto_day': 'On the day',
    'osup_auto_at': 'At',
    'osup_auto_reboot': 'After the update',
    'power_auto': 'A restart on a schedule',
    'power_auto_every': 'How often',
    'power_auto_day': 'On the day',
    'power_auto_at': 'At',
    'power_auto_needed': 'Only the nodes that need one',
    'siem': 'Send to a syslog server or a SIEM',
    'siem_targets': 'Where to send them',
    'siem_format': 'In the shape of',
    'siem_events': 'Every event',
    'siem_signins': 'Every sign-in, let in or refused',
    'siem_facility': 'Syslog facility',
    'siem_hostname': 'The name this machine is written under',
    'siem_verify': 'Check the server’s certificate (TLS)',
    'siem_ca': 'The certificate authority of the server (TLS)',
    'proxy': 'Go out through a proxy',
    'proxy_url': 'The proxy',
    'proxy_user': 'User name at the proxy',
    'proxy_password': 'Password at the proxy',
    'proxy_no': 'Straight, not through the proxy',
    'proxy_update': 'The new versions of acme',
    'proxy_os': 'The system updates (dnf, apt)',
    'proxy_acme': 'ACME: the CA (Let’s Encrypt)',
    'proxy_acme_dns': 'ACME: the DNS APIs (deSEC, Cloudflare, acme-dns)',
    'proxy_sms': 'The SMS gateway',
    'logs_journal_mb': 'The system journal at most (MB)',
    'logs_journal_days': 'The system journal kept for (days)',
    'logs_keep': 'acme’s own logs kept (files)',
    'logs_max_mb': 'A log file at most (MB)',
    'acme': 'Certificates from an ACME CA',
    'acme_email': 'Mail of the account at the CA',
    'acme_ca': 'The CA',
    'acme_url': 'Its ACME directory',
    'acme_ca_pem': 'The CA\u2019s own certificate',
    'acme_for': 'For',
    'acme_node_name': 'The node\u2019s DNS name',
    'acme_days': 'Renewed when fewer days are left than',
    'acme_key': 'The key of the certificate',
    'acme_account_key': 'The key of the ACME account',
    'acme_profile': 'The profile of the certificate',
    'acme_challenge': 'How the CA checks the name',
    'acme_dns': 'Who puts the TXT record in DNS',
    'acme_dns_server': 'The DNS server taking the updates',
    'acme_dns_zone': 'The zone',
    'acme_dns_tsig_name': 'The name of the TSIG key',
    'acme_dns_tsig_alg': 'Its algorithm',
    'acme_dns_tsig_secret': 'The TSIG secret',
    'acme_dns_token': 'The Cloudflare API token',
    'acme_dns_url': 'The acme-dns server',
    'acme_dns_user': 'acme-dns user',
    'acme_dns_key': 'acme-dns key',
    'acme_dns_subdomain': 'acme-dns subdomain',
    'acme_dns_wait': 'Wait for DNS to carry it (s)',
    'acme_resolvers': 'DNS servers for ACME',
    'acme_desec_domain': 'The domain at deSEC',
    'acme_desec_token': 'The deSEC API token',
    'acme_dns_alias': 'The TXT records go into',
    'report': 'A report by mail',
    'report_to': 'Send it to',
    'report_every': 'How often',
    'report_day': 'On the day',
    'report_at': 'At',
    'backup_at': 'At',
    'db_engine': 'The database',
    'db_host': 'Server',
    'db_port': 'Port',
    'db_name': 'Database name',
    'db_user': 'Account',
    'db_password': 'Password',
    'db_timeout_s': 'Connect timeout (s)',
    'db_tls': 'Encryption to the database server',
    'db_tls_ca': 'Its certificate authority (file)',
    'node_name': 'The name of this node',
    'site_name': 'What to call this installation',
    'ui_lang': 'Language of the pages',
    'api_port': 'API port (localhost)',
    'debug': 'Debug log',
    'debug_radius': '...every RADIUS request step by step',
    'debug_ldap': '...every question asked of the directory',
    'debug_api': '...every API call',
    'debug_codes': '...every code sent by e-mail and SMS',
}

SAYS = {
    'mail_mode': 'How a token’s mail leaves this machine: through your mail server, or '
                 'straight to the server of each recipient’s domain (its MX record) with no '
                 'relay - which only works where port 25 may go out and the receiving side '
                 'trusts this machine (SPF, a reverse DNS name).',
    'smtp_host': 'The mail server’s name or address: smtp.example.cz, or a relay in your '
                 'network. Its name is what its certificate is checked against.',
    'smtp_port': '0 picks the usual one for the encryption: 587 for STARTTLS, 465 for TLS, '
                 '25 for none.',
    'smtp_security': 'STARTTLS on 587 is what most servers want; SMTPS on 465 is TLS from '
                     'the first byte; none sends everything - the password too - in the '
                     'clear, for a relay inside your own network only.',
    'smtp_auth': 'How this machine signs in to the server. None where the relay lets this '
                 'address send by itself. XOAUTH2 (Microsoft 365, Google): the password is '
                 'an access token.',
    'smtp_user': 'The account it signs in with - often the whole address.',
    'smtp_password': 'Its password (or the OAuth access token for XOAUTH2). Kept in the '
                     'database sealed with the key that seals the tokens.',
    'smtp_verify': 'Off is for a test: a server whose certificate is not checked is one '
                   'anybody on the path can pretend to be. A certificate signed by your own '
                   'authority is trusted once that authority is added below.',
    'smtp_timeout_s': 'How long to wait for the server to answer.',
    'mail_from': 'The sender’s address. Your mail server may allow only its own '
                 'addresses; going direct, the domain should have this machine in its SPF.',
    'mail_from_name': 'The name beside it, as the recipient sees it. Empty: the name of '
                      'this installation.',
    'mail_reply_to': 'Where a reply goes - a helpdesk, say. Empty: back to the sender.',
    'mail_helo': 'The name this machine greets the server with. Empty: its own full name. '
                 'Going direct, it should be the name its address resolves back to.',
    'mail_dns': 'Going direct: the DNS servers asked where each recipient’s domain takes its mail '
                '(its MX record), separated by commas - 1.1.1.1, 8.8.8.8. Empty: the ones in '
                '/etc/resolv.conf. Only for a machine whose own resolver will not answer that.',
    'mail_direct_tls': 'Going direct: whether a server that offers no STARTTLS still gets the '
                       'mail, in the clear. Required is safer - a token\'s mail holds its key, '
                       'and anybody on the way can strip the offer - but a domain whose server '
                       'has no TLS then gets nothing.',
    'mail_direct_port': 'Going direct: the port of the recipients’ servers. It is 25 '
                        'everywhere; another only to test against a server of your own.',
    'mail_lang': 'The language a token’s mail is written in unless it is chosen when the '
                 'token is made.',
    'mail_retry_hours': 'A mail the receiving side did not take yet - greylisting (a first '
                        '"try again later"), a server away, a full mailbox - waits in the '
                        'outgoing mail and is tried again: after 1, 2, 5, 10, 15 and 30 min, '
                        'then every hour, for this long. A code to sign in with is tried only '
                        'while it is good (Codes by e-mail and SMS).',
    'mail_keep_days': 'How long the outgoing mail keeps a mail that went, or that was given '
                      'up, in its list - what it said and when. What a mail held (a QR code, '
                      'a key, a code) is never kept once it went.',
    'mail_codes': 'Whether the recovery codes go in the mail as well unless chosen when '
                  'the token is made. Each signs in once in place of a code from the phone.',
    'code_digits': 'How long a code sent by mail or SMS is - for signing in through the VPN '
                   'and for proving an address or a number on the enrolment pages.',
    'code_ttl_s': 'How long a sent code can be typed. A mail can take a while; 300 s is '
                  'usual. The VPN (ASA/FTD) has to wait as long: its RADIUS timeout 30-60 s '
                  'is for the first answer, not for typing.',
    'code_tries': 'Wrong codes typed into the VPN\'s second window before that code is gone '
                  'and the person has to sign in again (and gets a new one). Every wrong code '
                  'also counts towards the token\'s lockout, as a wrong code from the phone does.',
    'code_send_max': 'So nobody fills a mailbox or a phone with codes by signing in again and '
                     'again: past this many in the time below, no more are sent until it '
                     'passes.',
    'code_send_window_min': 'The time the number above is counted over.',
    'code_lang': 'The language of the mail or SMS with the code and of the words the VPN '
                 'shows in its second window ("Type the code sent to…") - for a token that has '
                 'no language of its own. A token enrolled on the enrolment pages takes the '
                 'language of the page; an administrator changes it in the token\'s window.',
    'code_mail_fmt': 'For a token that does not say otherwise (its window can): HTML in the '
                     'look of a token\'s mail, the plain text always beside it - or plain text '
                     'alone, for mail systems that strip HTML or people who want it so.',
    'sms_mode': 'An SMS gateway with an HTTP API (most operators and services), or a GSM '
                'modem on this machine run by smstools3 or gammu-smsd: acme writes each message '
                'as a file into its spool folder, or a Teltonika gateway (TRB140, RUT…) on the '
                'network through its own API, the way zigmon sends its texts. Off: SMS cannot '
                'be chosen on the enrolment pages.',
    'sms_url': 'Where the message is sent. {to} is the number (+420…), {to_digits} the '
               'number without + , {text} the message, {token} the key below - each written '
               'as an address needs it. https://sms.example.cz/api/send?to={to}&text={text}',
    'sms_method': 'POST sends the body below; GET only the address.',
    'sms_body': 'For POST. Starting with { it is JSON and the values are written as JSON '
                'strings: {"to": "{to}", "text": "{text}"}; otherwise a form: to={to}&text={text}. '
                'Empty: the address alone.',
    'sms_headers': 'One a line, Name: value - Authorization: Bearer {token}. Content-Type is '
                   'set by itself.',
    'sms_token': 'The gateway\'s API key or password, kept sealed in the database and put '
                 'where {token} is written. Never shown again.',
    'sms_spool_dir': 'smstools3: /var/spool/sms/outgoing. A file "To: 420…" and the text is '
                     'written there and the modem\'s daemon sends it. The service runs as '
                     'acme: that user needs to be able to write into the folder (a group, '
                     'chmod g+w).',
    'sms_prefix': 'A number typed as 603 123 456 becomes +420603123456. Empty: a number has '
                  'to be typed with its country code.',
    'sms_tel_host': 'The gateway on the network: 192.168.1.1, or host:port. The same box zigmon '
                    'sends its texts through can send these too.',
    'sms_tel_https': 'A TRB serves both; HTTPS keeps its password and the codes off the wire.',
    'sms_tel_verify': 'Checked against the certificates imported below - the gateway\'s own '
                      '(read from it with one click) or the authority and chain that signed '
                      'it; with none imported, against the authorities this machine trusts. '
                      'Off: any certificate is taken.',
    'sms_tel_user': 'An account of the gateway that may use its API (admin, or one made for '
                    'this under System → Administration → User settings).',
    'sms_tel_password': 'Its password, kept sealed in the database. Never shown again.',
    'sms_tel_api': 'RutOS 7 offers its own API out of the box; the older Post/Get service has '
                   'to be switched on by hand under Services → Mobile Utilities → SMS gateway.',
    'sms_tel_modem': 'Which modem sends - 1-1, 3-1… Empty: the one the gateway names first.',
    'sms_plain': 'A letter with an accent makes the whole SMS the wide alphabet, 70 '
                 'characters a part instead of 160: the code goes in one message when the '
                 'accents are left out (kód → kod).',
    'sms_ok_status': 'Some gateways answer 200 to everything: a word their answer holds only '
                     'when it was sent - "ok", "\"status\":\"sent\"". Empty: any 2xx answer.',
    'default_realm': 'The realm a name written without one belongs to: novak is taken as '
                     'novak@ this, on the enrolment pages and in RADIUS requests from a client '
                     'that adds no realm of its own - and novak@this works as well. Every other '
                     'realm still needs its @domain. Empty: a name has to be written whole.',
    'upgrade_check': 'Once a day (and when Look now is pressed) the address below is asked for '
                     'acme-X.Y.Z.tar.gz packages; a newer one than runs here is offered on this '
                     'page - put in with one click, after its signature has been checked like '
                     'any package sent by hand. Nothing is put in by itself.',
    'upgrade_downgrade': 'Off: nothing on these pages offers going back to an older version. '
                         'On: Settings → Upgrades shows <i>Going back to an older version</i> - '
                         'only the versions it is safe to go back to, each with what changed in '
                         'it. On the server, root can always: acme --downgrade.',
    'upgrade_url': 'A GitHub folder (<code>https://github.com/OWNER/REPO/tree/BRANCH/FOLDER</code>), '
                   'a web page or folder listing that links to the packages, or one package\'s '
                   'own address. HTTPS only; a proxy is taken from https_proxy in the '
                   'service\'s environment.',
    'high_security': 'Every way of doing something less safely switched off - plain LDAP, unencrypted '
                     'mail, syslog and backups, certificates not checked, weak TLS, SSH with '
                     'passwords, exports not locked and the rest listed above. Switched on only '
                     'once nothing stands against it; off by default.',
    'admin_show_key': 'A full administrator may open a token and show its QR code and key - '
                      'for somebody whose phone cannot scan the page, or to set the same '
                      'token up again. Whoever has the key can make the codes, so every look '
                      'is written down as an event. Off: nobody sees a key after it is made.',
    'radius_bind': 'The address the RADIUS server listens on. <code>0.0.0.0</code> is every '
                   'IPv4 address this machine has; <code>::</code> every IPv6 one as well. '
                   'Changed, the server starts listening on the new one at once.',
    'radius_auth_port': 'UDP port for Access-Request. 1812 is the standard one; the old '
                        '1645 still turns up on Cisco kit.',
    'radius_acct_port': 'UDP port for Accounting-Request. The records are written down and '
                        'sent to isemon with the rest; 0 does not listen for them at all.',
    'radius_status_server': 'Answer Status-Server (RFC 5997), which is how an ASA or a '
                            'load balancer asks whether this server is alive without signing '
                            'anybody in.',
    'radius_reply_ma': 'Put a Message-Authenticator on every answer. It protects the answer '
                       'against the BlastRADIUS forgery (CVE-2024-3596) and costs nothing; '
                       'only a client too old to know the attribute minds it.',
    'radius_dup_window_s': 'A client that hears nothing sends the same request again, with '
                           'the same identifier. Within this window it gets the same answer '
                           'again rather than a second check of the code - which would '
                           'fail, because a code works only once.',
    'radius_workers': 'How many requests are worked on side by side. A request that waits '
                      'for a slow domain controller does not hold up the others.',
    'radius_unknown_log': 'A request from an address that is not one of the clients is '
                          'dropped without an answer, as RADIUS says it must be. Switched '
                          'on, it is also written down - once a minute per address - so '
                          'that a VPN pointed here before it was added says so.',
    'radius_reject_delay_ms': 'How long to wait before sending a refusal. A little slows '
                              'down somebody guessing; 0 answers at once.',
    'totp_issuer': 'The name above the code in the phone application - the company, usually. '
                   'Only a token enrolled after a change carries the new one.',
    'totp_label': 'The account name under it. <code>{user}</code> is the whole name as it '
                  'was enrolled (<code>novak@example.cz</code>), <code>{name}</code> the part '
                  'before the @.',
    'totp_digits': 'Six is what everybody expects and what every application shows. Only for '
                   'tokens made from now on: each token keeps the length it was made with, so '
                   'imported and older ones go on working beside new ones. Microsoft '
                   'Authenticator shows six whatever this says - with 8 its codes are refused.',
    'totp_period': 'Thirty seconds is the standard, and Google Authenticator knows no other. '
                   'Only for tokens made from now on; each keeps its own.',
    'totp_algorithm': 'SHA-1 is what RFC 6238 says and what every application implements - and '
                      'it is not weak here: the key is 160 random bits. Only for tokens made '
                      'from now on; each keeps its own, so imported SHA-1 tokens go on working '
                      'beside new ones. Microsoft Authenticator and Google Authenticator on '
                      'Android ignore SHA-256 and SHA-512 and make SHA-1 codes, which are then '
                      'refused: those two are for hardware tokens and applications that take '
                      'them (FreeOTP, Google Authenticator on iPhone).',
    'totp_window': 'How many periods either side of now a code is still taken in. 1 is '
                   'thirty seconds of a phone’s clock being wrong either way; 0 takes '
                   'only the code of this very period. A code from a neighbouring period '
                   'is written down as such, so a phone whose clock is drifting shows up.',
    'totp_disallow_reuse': 'Once a code has been used it is refused if it comes again - even '
                           'inside its thirty seconds. This is what makes the code one-time; '
                           'switched off it can be replayed by anybody who saw it.',
    'rate_limit_tries': 'This many wrong codes for one token inside the time below, and every '
                        'code - right ones included - is refused until it has passed. 0 '
                        'switches it off.',
    'lockout_after': 'Wrong codes one after another - however slowly they come - after which '
                     'the token takes no code at all for the time below, and again after each '
                     'further one. The pause above stops a quick guesser; this one stops a slow '
                     'one, who would otherwise get thousands of guesses a day. A right code '
                     'starts the count again; Forget them on the token ends it at once. 0 '
                     'switches it off.',
    'lockout_min': 'How long a token takes no code once it has been locked out.',
    'radius_reject_reason': 'Off: a refusal goes back with no reason in it, and the reason is '
                            'only in the log here. On: the reason goes back as a Reply-Message, '
                            'which a VPN may show to whoever is signing in - telling a '
                            'stranger whether a name has a token, or that the code was right '
                            'and the password not.',
    'radius_guard': 'Off: only each token counts its own wrong codes (and locks itself) - from '
                    'one place somebody may still try every name a few times a day, or lock '
                    'everybody\'s token on purpose. On: the place each request comes from - the '
                    'address the person connects to the VPN from, as the VPN sends it '
                    '(Calling-Station-Id) - is counted too. Too many refusals from one place, '
                    'or too many different names refused from it, and it is blocked for a '
                    'while: its requests are refused at once, nothing of them is checked, and '
                    'nobody\'s token counts them. A request without a Calling-Station-Id is not '
                    'counted. Each node counts what reaches it; who is counted and who is '
                    'blocked is below, each cleared by hand.',
    'radius_guard_tries': 'Refusals from one place within the time below after which it is '
                          'blocked - wrong passwords, wrong codes, names nobody has. Not '
                          'counted: refusals that are this server\'s trouble (a directory away, '
                          'a realm not set up).',
    'radius_guard_names': 'Different names refused from one place within the time below after '
                          'which it is blocked - somebody trying many people\'s codes. 0: not '
                          'counted.',
    'radius_guard_window_min': 'The time over which the refusals of one place are counted.',
    'radius_guard_block_min': 'How long a place is blocked. Clear it by hand below to let it '
                              'in at once.',
    'radius_guard_trusted': 'Addresses or networks never blocked, one or more, separated by '
                            'spaces or commas: an office whose people all come from one '
                            'address, a monitor that signs in now and then. Example: '
                            '198.51.100.7 203.0.113.0/24',
    'net_confirm_min': 'A node\'s new network (Settings - Network) is put in, the node '
                       'restarts with it - and the old one comes back by itself unless '
                       'somebody presses Keep it within these minutes: a typo in the gateway '
                       'or the prefix does not leave the node unreachable. 0: kept at once, as '
                       'before.',
    'fw_confirm_min': 'A change of the firewall or of who may reach the pages is put in - and '
                      'what was there before comes back by itself unless somebody presses Keep '
                      'it within these minutes: a rule that shuts SSH, the pages or RADIUS out '
                      'does not stay. 0: kept at once, as before.',
    'radius_ma_sticky': 'A client that has once sent a right Message-Authenticator must send '
                        'one with every request from then on: one that arrives without is '
                        'dropped (BlastRADIUS, CVE-2024-3596). Remembered until the service '
                        'restarts; Must send a Message-Authenticator on the client holds it '
                        'always.',
    'rate_limit_s': 'The time over which the wrong codes are counted, and which has to pass '
                    'before the token takes codes again.',
    'scratch_count': 'One-off codes made with each token, for the day the phone is lost. '
                     'Each works once, in place of a code from the phone. 0 makes none.',
    'scratch_digits': 'How long a recovery code is. Longer than a code from the phone, so '
                      'the two are never mistaken for each other.',
    'token_names_case': 'Whether <code>Novak@example.cz</code> and <code>novak@example.cz'
                        '</code> are one token. Active Directory does not care, and neither '
                        'should this, unless something else forces it to.',
    'names_czsk_letters': 'The letters of Czech and Slovak with their accents (á č ď é ě í ľ ĺ ň ó ô '
                          'ŕ ř š ť ú ů ý ž ä) in the names of people, tokens and accounts. With '
                          'both this and the one beside it off, a name takes letters without '
                          'accents, digits, . _ - and @ only, and one with any other letter is '
                          'refused: at the VPN before anything is asked, on the enrolment pages, '
                          'when a token or an account is made and when an administrator from the '
                          'directory signs in. Most directories keep their sign-in names so '
                          '(novak), and only the display names have accents - those are never '
                          'checked.',
    'names_any_letters': 'Letters of every other language in names - Cyrillic, Greek, Polish ł, '
                         'German ß and ö, and the rest. A name that only looks like another (a '
                         'Cyrillic а for a Latin a) is one way to pass for somebody: switch it on '
                         'only where such names are really used. On, it takes the Czech and '
                         'Slovak letters too.',
    'portal': 'The pages where people enrol their own token. Switched off they say so and '
              'let nobody in; administrators can still enrol anybody here.',
    'portal_title': 'The heading on every enrolment page and the title of the browser tab. Empty: One-time passwords, in the language of the page.',
    'portal_realm': 'A name typed without an @ gets this added before it is looked up: '
                    '<code>novak</code> becomes <code>novak@example.cz</code>. Empty: the '
                    'name has to be typed whole.',
    'portal_hint': 'One line under the sign-in boxes saying what to type, such as '
                   '<code>login@example.cz</code>.',
    'portal_who': 'Who may enrol a token. <b>The realm’s group filter</b> is the same '
                  'test the VPN applies, so nobody can enrol a token they could never use.',
    'portal_groups': 'With <i>members of the groups named below</i>: the groups, by name '
                     '(<code>VPN_USERS</code>) or by whole DN, separated by semicolons or new '
                     'lines.',
    'portal_confirm': 'A token made on the enrolment page is not in use until the person has '
                      'typed a code from it. Without this a QR code scanned badly - or not '
                      'at all - is a token that locks its owner out on the next sign-in.',
    'portal_reissue': 'Somebody who already has a token may replace it themselves, with '
                      'their password and a code from the old one (or a recovery code). '
                      'Somebody who lost both has to ask an administrator.',
    'portal_show_secret': 'The key written out as letters as well, for typing into an '
                          'application on a machine with no camera.',
    'portal_codes_view': 'After signing in, a person may look at their recovery codes again - which are left and which are used - after proving they have the token: a code from the app, or one sent to them now. The directory password alone never shows them. Off: they are shown once, when the token is made.',
    'portal_scratch': 'Show the recovery codes to the person who enrolled. Off: they are '
                      'still made, and only an administrator can see new ones.',
    'portal_session_min': 'How long somebody stays signed in on the enrolment pages. Short, '
                          'because the page holds a key that is somebody’s second factor.',
    'portal_help': 'Words shown on the enrolment pages under the title: where to get the '
                   'application, whom to ring. Plain text; an empty line starts a new '
                   'paragraph.',
    'portal_tries': 'Wrong passwords from one address on the enrolment pages before it has '
                    'to wait.',
    'portal_wait_min': 'How long it waits.',
    'session_hours': 'How long an administrator stays signed in, however busy.',
    'session_idle_min': 'How long a sign-in may sit without anything being asked before it '
                        'has to be done again.',
    'login_tries': 'Wrong passwords from one address before it has to wait.',
    'login_wait_min': 'How long it waits.',
    'admin_directory': 'The directory (by its name under <i>Active Directory</i>) the '
                       'administration pages sign people in against. Empty: only the '
                       'accounts made here. Whoever signs in from it gets the role of the '
                       'first group below they are in, and nobody in none of them gets in.',
    'admin_group_full': 'Members may change everything. By name or by whole DN.',
    'admin_group_token': 'Members may look at everything and look after people’s tokens.',
    'admin_group_readonly': 'Members may look at everything and change nothing.',
    'admin_2fa': 'After the password, every account - local or from the directory - gives a '
                 'code too. Its own, not a VPN token: the first time, the account chooses how '
                 'and sets it up (an authenticator app, or a code sent to an address or a phone '
                 'it proves it has). Accounts → Reset the second step, or acme --reset-2fa NAME, '
                 'makes it choose again. Sign-ins already open stay open.',
    'admin_2fa_app': 'Offered when the second step is set up: a code from an app (Google or '
                     'Microsoft Authenticator…). With nothing else on, it is offered anyway.',
    'admin_2fa_mail': 'Offered only while mail is set up (Settings → Mail).',
    'admin_2fa_sms': 'Offered only while sending SMS is set up (Settings → Codes by e-mail and '
                     'SMS).',
    'isemon': 'Send every check of a code and every RADIUS packet to isemon, as syslog, in '
              'the very shape a totpcgi token server and its FreeRADIUS write - so isemon '
              'reads it with what it already has (<i>Settings → The ACME logs</i>, with '
              '<i>RADIUS detail</i> switched on).',
    'isemon_targets': 'Where to send them: <code>host</code>, <code>host:port</code>, '
                      'and <code>/udp</code>, <code>/tcp</code> or <code>/tls</code> after it - '
                      '<code>10.1.2.3:514/tcp</code>, <code>isemon.example.cz:6514/tls</code>. '
                      'Several, separated by commas. UDP is the default; TCP does not lose a line '
                      'when the network does; TLS is TCP encrypted - <i>Encrypted sending</i> '
                      'above sets it up.',
    'metrics': 'Each node answers <code>https://NODE/metrics</code> in Prometheus\u2019 format - '
               'RADIUS, the tokens, the database, the cluster, the certificates, the mail, the '
               'alerts. Asked with the token below.',
    'metrics_token': 'What Prometheus sends as <code>Authorization: Bearer ...</code>. Kept sealed; '
                     '<i>Make a token</i> below makes one and shows it once.',
    'metrics_from': 'The addresses or networks Prometheus asks from, <code>10.0.5.0/24, '
                    '2001:db8::/64</code>. Empty: from anywhere that reaches the pages, with the '
                    'token.',
    'ssh_gate_port': 'pam_radius of each node asks acme on 127.0.0.1 at this port, never from '
                     'the network - nothing to open in the firewall. Where something else has it, '
                     'each node takes the next free one of 18129-18199 by itself and tells its '
                     'pam_radius; each node\u2019s card above says which.',
    'snmp': 'Each node answers SNMPv3 itself - an agent of acme, no snmpd: the system group and '
            'acme\u2019s own objects (ACME-MIB, <code>deploy/ACME-MIB.txt</code>), read only. '
            'authPriv only: a user with a passphrase for each.',
    'snmp_port': '161 is SNMP\u2019s. Another where snmpd of the system has it already.',
    'snmp_bind': 'Empty: every address of the node. Or one of its addresses.',
    'snmp_from': 'The addresses or networks the monitoring asks from, <code>10.0.5.0/24, '
                 '192.0.2.7</code>. Empty: anybody with the user and its passphrases. The '
                 'firewall lets in these only.',
    'snmp_user': 'The SNMPv3 user (securityName) the monitoring asks as - the same on every '
                 'node.',
    'snmp_auth': 'HMAC of every message. SHA-256 or SHA-512; SHA-1 only for old monitoring.',
    'snmp_auth_pass': '12 characters at least. Kept sealed.',
    'snmp_priv': 'Every message encrypted. AES-256 is net-snmp\u2019s and Zabbix\u2019s '
                 '(\u201cAES256\u201d, not Cisco\u2019s \u201cAES256C\u201d).',
    'snmp_priv_pass': '12 characters at least - best not the same as the other. Kept sealed.',
    'snmp_contact': 'Who looks after it - as sysContact.0 says.',
    'snmp_location': 'Where it is - as sysLocation.0 says.',
    'snmp_traps': 'An SNMPv2 trap (authPriv) when something goes wrong - what the alerts see - '
                  'and when it is right again, from the node that sends the alerts.',
    'snmp_trap_to': 'host or host:port (162 by default), separated by commas. The receiver '
                    'knows the user with each node\u2019s engine ID (shown below).',
    'isemon_ca': 'The CA certificate (PEM) isemon’s certificate is signed by - acme’s own '
                 'authority when <i>Encrypted sending</i> made it. Empty: the system’s.',
    'isemon_verify': 'isemon’s certificate checked against the authority and its name against the '
                     'address it is sent to. Off: encrypted, but whoever answers is taken.',
    'isemon_mtls': 'Each node shows isemon a certificate from acme’s own authority (made and '
                   'renewed by the node itself), so isemon can take lines from acme’s nodes only.',
    'isemon_hostname': 'The host name on every line, which is the folder isemon’s rsyslog '
                       'files them under: <code>/var/log/remote/<this>/totp.cgi.log</code>. '
                       'isemon looks in <code>/var/log/remote/acme</code> unless told otherwise, '
                       'so <code>acme</code> needs nothing changed there. Empty: this machine’s '
                       'own short name.',
    'isemon_detail': 'The RADIUS packet behind every check - the person’s own address, '
                     'the device, the tunnel group - as <code>radius-detail</code> lines. isemon '
                     'puts them beside the check of the code.',
    'isemon_events': 'This daemon’s own events as well (a token made, a setting '
                     'changed), as <code>acme</code> lines. isemon does not read those; they '
                     'are for whatever else collects the syslog.',
    'isemon_max_bytes': 'A message longer than this is cut, with <code>...TRUNCATED</code> at '
                        'the end. rsyslog cuts at 2048 bytes over UDP unless '
                        '<code>$MaxMessageSize</code> says more on both machines.',
    'ship_files': 'The very same lines go into <code>/var/log/acme/totp.cgi.log</code> and '
                  '<code>/var/log/acme/radius-detail.log</code> as well, whether or not they are '
                  'sent. Something on this machine can then forward them, and they are there '
                  'to read when the network is not.',
    'retain_radius_days': 'How long every RADIUS request is kept. 0 keeps them for ever.',
    'retain_acme_days': 'How long every check of a code is kept. 0 keeps them for ever.',
    'retain_events_days': 'How long the events are kept. 0 keeps them for ever.',
    'backup_daily': 'A copy of the database once a day, into <code>/var/lib/acme/backups'
                    '</code>, with the key that opens the tokens beside it.',
    'backup_keep': 'How many of those copies are kept; the oldest goes first.',
    'rbackup': 'Each node makes its backup and sends it to every destination switched on, at '
               'the time below. Without it, only Back up now sends one.',
    'rbackup_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
    'rbackup_every': 'daily, or weekly on the day below.',
    'rbackup_day': 'The day of a weekly backup: 1 is Monday, 7 Sunday.',
    'rbackup_keep': 'How many of this node’s backups each destination keeps; the oldest go '
                    'first, the newest never.',
    'rbackup_keep_days': 'Older ones are taken away too - 0: only the count above decides.',
    'rbackup_verify': 'The newest backup fetched back, opened with the password, every file checked, '
                      'the database read through and the tokens tried against the key in it - '
                      'nothing is put back. After every backup, or once a week.',
    'rbackup_password': 'Every backup is locked with it (AES-256, opened with acme or with openssl '
                        'alone). Keep it apart from the backups as well - in a password vault: '
                        'without it nobody, you included, opens them. Empty: the backups are '
                        'not locked, and anybody with one has every token.',
    'backup_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
    'alerts': 'A mail when something is wrong - a node, the replication, a backup, a '
              'certificate, a disk, the clock, the directory, the SMS gateway - and when it is '
              'over. One node of a cluster sends them for both. Off until switched on.',
    'alerts_to': 'Addresses, separated by commas. The mail goes the way Settings → Mail says.',
    'alerts_delay_min': 'A problem shorter than this is not mailed - a node restarted by an '
                        'update is back in a few minutes. 0: at once.',
    'alerts_repeat_h': 'While it lasts, said again this often. 0: once only.',
    'alerts_resolved': 'A mail when what was mailed is over.',
    'alerts_nodes': 'The other node not heard from, a node not listening for RADIUS, the '
                    'replication stopped, the database in trouble, the nodes on different versions.',
    'alerts_db': 'The replication stopped, or the database of a node in trouble. Not while a node '
                 'is in maintenance, being upgraded, updated or restarted, nor 10 min after - '
                 'the same outside of them is mailed.',
    'alerts_vrrp': 'The VIP address on no node or on both, a node whose keepalived gave it up '
                   '(FAULT) or is not running. Not during maintenance, upgrades, updates or '
                   'restarts, nor 10 min after.',
    'alerts_backup': 'A nightly copy older than 36 hours; a backup to the destinations that '
                     'failed, or none that went in time.',
    'alerts_cert_days': 'A certificate of a node or of the VIP address running out within so '
                        'many days. 0: never.',
    'alerts_disk_pct': 'A file system acme lives on fuller than this. 0: never.',
    'alerts_time': 'chrony out of sync, or the clock off by more than half a second - the codes '
                   'from the phones are worked out from it.',
    'alerts_updates': 'Security updates waiting, or a restart an update left - as System '
                      'updates last found them.',
    'alerts_dir': 'None of the servers of a directory answers a node.',
    'alerts_sms': 'Three SMS in a row that did not go.',
    'alerts_guard': 'Each source Sign-in protection blocks, as it is blocked.',
    'alerts_url': 'Where the links in the mails lead, <code>https://acme.example.cz/admin/</code>. '
                  'Empty: this machine’s name.',
    'report': 'A report of the period by mail: the sign-ins by day, who was refused and why, '
              'who signed in most, the clients, the blocked sources, the sign-ins to the '
              'administration, the events worth a look, the tokens, the servers and what is '
              'wrong now. One node of a cluster sends it.',
    'report_to': 'Addresses, separated by commas. Empty: the ones the alerts go to.',
    'alerts_lang': 'Czech or English, for the alerts and the test. Empty: the language of the mails.',
    'report_lang': 'Czech or English, for the report. Empty: the language of the alerts.',
    'osup_check': 'Each node looks what dnf (or apt) has waiting, every day at the time below - '
                  'for the cards here, the alerts and the report. Nothing is put in.',
    'osup_check_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
    'osup_auto': 'The updates put in by themselves in the window below, one node at a time as '
                 'by hand - each out of service while it is updated, the VIP address on the '
                 'other. Off until switched on.',
    'osup_auto_what': 'Only the security updates (dnf --security, unattended-upgrade on apt), '
                      'or every update.',
    'osup_auto_every': 'A day, a week or a month.',
    'osup_auto_day': 'The day a weekly update goes.',
    'osup_auto_at': 'When, as <code>HH:MM</code> - a quiet hour, away from the backups.',
    'osup_auto_reboot': 'A node that needs a restart after the update - restarted by itself, '
                        'one after the other, or offered on the page.',
    'power_auto': 'The nodes restarted in the window below, one after the other, each out of '
                  'service while it is. Off until switched on.',
    'power_auto_every': 'A week or a month.',
    'power_auto_day': 'The day a weekly restart goes.',
    'power_auto_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
    'power_auto_needed': 'Only the nodes an update left waiting for a restart; off: every node, '
                         'every time.',
    'siem': 'Every event and every sign-in, as syslog (RFC 5424), to the servers below - '
            'from each node, as it happens. Sent by a thread of its own: a sign-in never waits '
            'for it. Off until switched on.',
    'siem_targets': '<code>tls://siem.example.cz:6514</code>, <code>tcp://host:514</code> or '
                    '<code>udp://host:514</code>, separated by commas.',
    'siem_format': 'What the message is, after the syslog header.',
    'siem_events': 'All that the Events page lists: a setting changed, a token made, a node '
                   'gone, a source blocked.',
    'siem_signins': 'Each Access-Request: who, from where, let in or refused and why. The code '
                    'typed is never sent.',
    'siem_facility': '13 (log audit) is the usual; 16-23 are local0-local7, 10 authpriv.',
    'siem_hostname': 'The host name on every line. Empty: the node’s name.',
    'siem_verify': 'Off only for a test: anyone between could read and change the lines.',
    'siem_ca': 'The CA certificate (PEM) the server’s certificate is signed by, where it is not '
               'one the system trusts already.',
    'proxy': 'An HTTP proxy for what is switched on below, and for nothing else; all of them '
             'off, it is used nowhere. Mail, Active Directory, the database, syslog, isemon, '
             'the backups, the other node and the VIP address’s check never use it.',
    'proxy_url': '<code>http://proxy.example.cz:3128</code>',
    'proxy_user': 'Where the proxy asks for one. Empty: none.',
    'proxy_password': 'Kept sealed, like the other passwords.',
    'proxy_no': 'Names and addresses reached without it, separated by commas: '
                '<code>.example.cz</code> is every name under it, <code>10.0.0.0/8</code> a net.',
    'proxy_update': 'Looking for a new version of acme and fetching it (Upgrades).',
    'proxy_os': 'dnf or apt fetch the updates of System updates through it.',
    'proxy_acme': 'Ordering and renewing the certificates, and the CA’s renewal window. A proxy '
                  'down then stops the renewals - they are tried again, well before one runs out.',
    'proxy_acme_dns': 'The TXT record put in and taken away again (DNS-01) through the API of '
                      'deSEC, Cloudflare or acme-dns. RFC 2136 updates are DNS, never through it.',
    'proxy_sms': 'The HTTP SMS gateway asked through it. A proxy down then stops the codes by '
                 'SMS - leave it off unless the gateway can be reached no other way.',
    'logs_journal_mb': 'How much room systemd’s journal may take on each node; the oldest goes '
                       'first. 0: as the system has it.',
    'logs_journal_days': 'Nothing older is kept. 0: as the system has it.',
    'logs_keep': 'How many old files of /var/log/acme are kept, one a day.',
    'logs_max_mb': 'A file bigger than this is put aside sooner than once a day.',
    'acme': 'The certificates ordered from the CA by HTTP-01 and renewed by themselves - port 80 '
            'of the name must reach a node. In a cluster the answer is kept in the database, so '
            'whichever node has the VIP address gives it. Off until switched on.',
    'acme_email': 'Where the CA writes when a certificate runs out unrenewed. Empty: none.',
    'acme_ca': 'Let\u2019s Encrypt, its staging (certificates browsers do not trust - to try '
               'it), or another.',
    'acme_url': 'The directory of another ACME CA, <code>https://ca.example.cz/acme/acme/directory</code>.',
    'acme_ca_pem': 'The CA\u2019s root (PEM), where the system does not trust it already.',
    'acme_for': 'Which certificates are ordered.',
    'acme_node_name': 'The name a node\u2019s own certificate is for - each node its own, the others\u2019 '
                      'under the box. Empty: the name of the certificate it has now, else its full host '
                      'name. The VIP address\u2019s: <i>Its name\u2026</i> on its card above.',
    'acme_days': 'Let\u2019s Encrypt\u2019s certificates last 90 days; 30 is what it advises.',
    'acme_profile': 'What the CA makes the certificate as, where it offers profiles (Let\u2019s '
                    'Encrypt does): shortlived lasts 6 days and is renewed every two or three - '
                    'no revoking needed if its key is lost. Another CA without profiles: its own.',
    'acme_key': 'Let\u2019s Encrypt takes RSA keys of 2048, 3072 or 4096 bits and ECDSA keys on P-256 or P-384. '
                'Both - what Let\u2019s Encrypt advises - orders two certificates for the name: RSA served by default, '
                'the much smaller ECDSA one to the clients that say they take it.',
    'acme_account_key': 'The key the account with the CA signs with - never one of a certificate. '
                        'RSA 2048, 3072, 4096 or ECDSA P-256, P-384. A change makes a new account at the next order.',
    'acme_challenge': 'HTTP-01 needs port 80 of the name reachable from the internet (or from the CA, '
                      'for a CA of your own). DNS-01 needs nothing open: the CA reads a TXT record.',
    'acme_dns': 'By hand the order waits up to an hour for you; the others renew by themselves.',
    'acme_dns_server': 'The primary DNS server of the zone, <code>ns1.example.cz</code> or with a port '
                       '<code>10.0.0.53:53</code>.',
    'acme_dns_zone': 'Where the record goes, <code>example.cz</code>. Empty: as the server finds it.',
    'acme_dns_tsig_name': 'As the DNS server knows it, <code>acme-acme.</code>; allowed to update '
                          '_acme-challenge records only.',
    'acme_dns_tsig_alg': 'As the key was made (tsig-keygen makes hmac-sha256).',
    'acme_dns_tsig_secret': 'The key\u2019s secret (base64). Kept sealed; written to a file only acme '
                            'reads for the moment nsupdate runs.',
    'acme_dns_token': 'A token with Zone - DNS - Edit for the zone. Kept sealed.',
    'acme_dns_url': '<code>https://auth.acme-dns.example.cz</code>; _acme-challenge.NAME is a CNAME to '
                    'the subdomain below.',
    'acme_dns_user': 'From the registration at acme-dns.',
    'acme_dns_key': 'From the registration at acme-dns. Kept sealed.',
    'acme_dns_subdomain': 'From the registration at acme-dns.',
    'acme_dns_wait': 'How long the record is given to reach every DNS server before the CA is asked.',
    'acme_resolvers': 'The DNS servers asked for everything on this page: the address of the CA and '
                      'of the DNS API, <i>Check DNS</i>, <i>Try port 80</i>, and whether the TXT '
                      'record can be seen before the CA is asked - <code>1.1.1.1, 9.9.9.9</code> '
                      'to see what the internet sees. Empty: the machine\u2019s own '
                      '(/etc/resolv.conf).',
    'acme_desec_domain': 'Your domain at deSEC, <code>example.dedyn.io</code> (free) or one of your own '
                         'whose DNS is there. The records go into it; your DNS has a CNAME to it for each '
                         'name - <i>In your DNS</i> above says which.',
    'acme_desec_token': 'A token from deSEC (Token management) - one that may change this domain\u2019s '
                        'records. Kept sealed.',
    'acme_dns_alias': 'A zone the records go into instead of the name\u2019s own '
                      '(<code>acme.example.net</code>), each name with a CNAME to it in your DNS - '
                      '<i>In your DNS</i> above says which. Empty: _acme-challenge.NAME itself.',
    'report_every': 'A day, a week (Monday to Sunday) or a month - the one that has just ended.',
    'report_day': 'The day a weekly report goes.',
    'report_at': 'When, as <code>HH:MM</code> on this machine’s clock.',
    'db_engine': 'Where everything is kept: the tokens, the clients, the realms, the '
                 'settings, the logs. A file on this machine needs nothing; MariaDB and '
                 'PostgreSQL need their server and their Python driver.',
    'db_host': 'The database server’s address.',
    'db_port': '0 is the engine’s usual one: 3306 or 5432.',
    'db_name': 'The database on that server. It has to exist; the tables are made in it.',
    'db_user': 'The account this daemon signs in to the database with.',
    'db_password': 'Its password.',
    'db_timeout_s': 'How long to wait for the server before saying it cannot be reached.',
    'db_tls': 'TLS to a database on another machine - and to the other node of a cluster '
              'until Settings → High availability encrypts that link with its own setting. '
              'Empty: as the '
              'driver decides - encrypted where the server offers it, and nothing stops '
              'somebody on the way from saying it does not. require: always encrypted. '
              'verify-full: encrypted, and the server\'s certificate checked against the '
              'authority below and the host name - the only one that stops somebody in '
              'between. The server must have TLS switched on.',
    'db_tls_ca': 'The file of the authority that signed the database server\'s certificate, '
                 'for verify-ca and verify-full: /etc/acme/db-ca.pem.',
    'node_name': 'What this server is called among the nodes of a cluster - in the list of nodes, in its events and on the pages it answers. Kept in config.json, since it belongs to this machine and not to the database both share. Empty: the machine\'s own name.',
    'site_name': 'The name at the top of the administration pages. Empty: the machine’s '
                 'own name.',
    'ui_lang': 'The language every page opens in until somebody chooses another for '
               'themselves.',
    'api_port': 'The port on 127.0.0.1 the web pages ask this daemon on. The pages read it '
                'from <code>/run/acme/api-port</code>, written when the daemon starts.',
    'debug': 'Write everything into <code>/var/log/acme/acme.log</code>. Loud: for finding '
             'something out, not for leaving on.',
    'debug_radius': 'Every request, every step of its decision.',
    'debug_ldap': 'Every question asked of a directory and how many answers came back. Never '
                  'a password.',
    'debug_api': 'Every API call the web pages make.',
    'debug_codes': 'Every code sent by e-mail and SMS, step by step: each request to the SMS gateway and its answer with how long it took, each line of the conversation with the mail server. Passwords, tokens and the messages themselves are never written.',
}

# A line under the box where the whole of SAYS is long (1.0.156): the whole is
# shown when the pointer rests on the name or its (i).
SAYS_SHORT = {
    'names_czsk_letters': 'á č ď é ě í ľ ň ó ř š ť ú ů ý ž in sign-in names. Off: letters '
                          'without accents only.',
    'names_any_letters': 'Cyrillic, Greek, ł, ß, ö... in sign-in names - and the Czech ones too.',
}

# Which settings sit on which page of Settings, in order. A setting the
# daemon knows and this does not name lands on "Everything else".
PANES = {
    'realms': ['default_realm'],
    'guard': ['radius_guard', 'radius_guard_tries', 'radius_guard_names',
              'radius_guard_window_min', 'radius_guard_block_min', 'radius_guard_trusted'],
    # Where the change they take back is made (1.0.150), not under sign-ins.
    'network': ['net_confirm_min'],
    'fw': ['fw_confirm_min'],
    'radius': ['radius_bind', 'radius_auth_port', 'radius_acct_port', 'radius_status_server',
               'radius_reply_ma', 'radius_dup_window_s', 'radius_workers',
               'radius_unknown_log', 'radius_reject_delay_ms', 'radius_reject_reason',
               'radius_ma_sticky'],
    'tokens': ['totp_issuer', 'totp_label', 'totp_digits', 'totp_period', 'totp_algorithm',
               'totp_window', 'totp_disallow_reuse', 'rate_limit_tries', 'rate_limit_s',
               'lockout_after', 'lockout_min', 'admin_show_key',
               'scratch_count', 'scratch_digits', 'token_names_case', 'names_czsk_letters',
               'names_any_letters'],
    'portal': ['portal', 'portal_title', 'portal_realm', 'portal_hint', 'portal_who',
               'portal_groups', 'portal_confirm', 'portal_reissue', 'portal_show_secret',
               'portal_scratch', 'portal_codes_view', 'portal_session_min', 'portal_tries', 'portal_wait_min',
               'portal_help'],
    'isemon': ['isemon', 'isemon_targets', 'isemon_hostname', 'isemon_detail',
               'isemon_events', 'isemon_max_bytes', 'isemon_verify', 'isemon_mtls',
               'isemon_ca', 'ship_files'],
    'people': ['session_hours', 'session_idle_min', 'login_tries', 'login_wait_min',
               'admin_2fa', 'admin_2fa_app', 'admin_2fa_mail', 'admin_2fa_sms',
               'admin_directory', 'admin_group_full', 'admin_group_token',
               'admin_group_readonly'],
    'db': ['db_engine', 'db_host', 'db_port', 'db_name', 'db_user', 'db_password',
           'db_timeout_s', 'db_tls', 'db_tls_ca', 'backup_daily', 'backup_keep', 'backup_at',
           'retain_radius_days', 'retain_acme_days', 'retain_events_days'],
    'ha': ['node_name'],
    'backup': ['rbackup', 'rbackup_at', 'rbackup_every', 'rbackup_day', 'rbackup_keep',
               'rbackup_keep_days', 'rbackup_password', 'rbackup_verify'],
    'osup': ['osup_check', 'osup_check_at', 'osup_auto', 'osup_auto_what', 'osup_auto_every',
             'osup_auto_day', 'osup_auto_at', 'osup_auto_reboot'],
    'power': ['power_auto', 'power_auto_every', 'power_auto_day', 'power_auto_at',
              'power_auto_needed'],
    'hisec': ['high_security'],
    'siem': ['siem', 'siem_targets', 'siem_format', 'siem_events', 'siem_signins',
             'siem_facility', 'siem_hostname', 'siem_verify', 'siem_ca'],
    'proxy': ['proxy', 'proxy_url', 'proxy_user', 'proxy_password', 'proxy_no', 'proxy_update',
              'proxy_os', 'proxy_acme', 'proxy_acme_dns', 'proxy_sms'],
    'sshd': ['ssh_gate_port'],
    'monitor': ['snmp', 'snmp_port', 'snmp_bind', 'snmp_from', 'snmp_user', 'snmp_auth',
                'snmp_auth_pass', 'snmp_priv', 'snmp_priv_pass', 'snmp_contact', 'snmp_location',
                'snmp_traps', 'snmp_trap_to', 'metrics', 'metrics_token', 'metrics_from'],
    'logs': ['logs_journal_mb', 'logs_journal_days', 'logs_keep', 'logs_max_mb'],
    'acme': ['acme', 'acme_for', 'acme_email', 'acme_ca', 'acme_url', 'acme_ca_pem',
             'acme_node_name', 'acme_days', 'acme_key', 'acme_account_key', 'acme_profile', 'acme_challenge', 'acme_dns',
             'acme_dns_server', 'acme_dns_zone', 'acme_dns_tsig_name', 'acme_dns_tsig_alg',
             'acme_dns_tsig_secret', 'acme_dns_token', 'acme_dns_url', 'acme_dns_user',
             'acme_dns_key', 'acme_dns_subdomain', 'acme_desec_domain', 'acme_desec_token',
             'acme_dns_alias', 'acme_dns_wait', 'acme_resolvers'],
    'alerts': ['alerts', 'alerts_to', 'alerts_delay_min', 'alerts_repeat_h', 'alerts_resolved',
               'alerts_nodes', 'alerts_db', 'alerts_vrrp', 'alerts_backup', 'alerts_cert_days', 'alerts_disk_pct',
               'alerts_time', 'alerts_updates', 'alerts_dir', 'alerts_sms', 'alerts_guard',
               'alerts_lang', 'alerts_url', 'report', 'report_to', 'report_lang', 'report_every', 'report_day', 'report_at'],
    'codes': ['code_digits', 'code_ttl_s', 'code_tries', 'code_send_max',
              'code_send_window_min', 'code_lang', 'code_mail_fmt', 'sms_mode', 'sms_url', 'sms_method',
              'sms_body', 'sms_headers', 'sms_token', 'sms_spool_dir', 'sms_prefix',
              'sms_ok_status', 'sms_tel_host', 'sms_tel_https', 'sms_tel_verify',
              'sms_tel_user', 'sms_tel_password', 'sms_tel_api', 'sms_tel_modem', 'sms_plain'],
    'mail': ['mail_mode', 'smtp_host', 'smtp_port', 'smtp_security', 'smtp_auth', 'smtp_user',
             'smtp_password', 'smtp_verify', 'smtp_timeout_s', 'mail_direct_port', 'mail_direct_tls', 'mail_dns', 'mail_from',
             'mail_from_name', 'mail_reply_to', 'mail_helo', 'mail_lang', 'mail_codes',
             'mail_retry_hours', 'mail_keep_days'],
    'upgrade': ['upgrade_check', 'upgrade_url', 'upgrade_downgrade'],
    'about': ['site_name', 'ui_lang', 'api_port', 'debug', 'debug_radius', 'debug_ldap',
              'debug_api', 'debug_codes'],
}

# A setting that only means something while another one says so. Shown
# greyed out with the reason beside it, as on isemon.
ONLY_WHEN = {
    'radius_guard_tries': ['radius_guard', '1'], 'radius_guard_names': ['radius_guard', '1'],
    'radius_guard_window_min': ['radius_guard', '1'],
    'radius_guard_block_min': ['radius_guard', '1'],
    'radius_guard_trusted': ['radius_guard', '1'],
    'portal_title': ['portal', '1'], 'portal_realm': ['portal', '1'],
    'portal_hint': ['portal', '1'], 'portal_who': ['portal', '1'],
    'portal_groups': ['portal_who', 'groups'], 'portal_confirm': ['portal', '1'],
    'portal_reissue': ['portal', '1'], 'portal_show_secret': ['portal', '1'],
    'portal_scratch': ['portal', '1'], 'portal_session_min': ['portal', '1'],
    'portal_help': ['portal', '1'], 'portal_tries': ['portal', '1'],
    'portal_wait_min': ['portal', '1'],
    'isemon_targets': ['isemon', '1'], 'isemon_hostname': ['isemon', '1'],
    'isemon_detail': ['isemon', '1'], 'isemon_events': ['isemon', '1'],
    'isemon_max_bytes': ['isemon', '1'], 'isemon_ca': ['isemon', '1'],
    'metrics_token': ['metrics', '1'], 'metrics_from': ['metrics', '1'],
    'snmp_port': ['snmp', '1'], 'snmp_bind': ['snmp', '1'], 'snmp_from': ['snmp', '1'],
    'snmp_user': ['snmp', '1'], 'snmp_auth': ['snmp', '1'], 'snmp_auth_pass': ['snmp', '1'],
    'snmp_priv': ['snmp', '1'], 'snmp_priv_pass': ['snmp', '1'], 'snmp_contact': ['snmp', '1'],
    'snmp_location': ['snmp', '1'], 'snmp_traps': ['snmp', '1'],
    'snmp_trap_to': ['snmp_traps', '1'],
    'isemon_verify': ['isemon', '1'], 'isemon_mtls': ['isemon', '1'],
    'admin_group_full': ['admin_directory', '*'], 'admin_group_token': ['admin_directory', '*'],
    'admin_group_readonly': ['admin_directory', '*'],
    'admin_2fa_app': ['admin_2fa', '1'], 'admin_2fa_mail': ['admin_2fa', '1'],
    'admin_2fa_sms': ['admin_2fa', '1'],
    'db_host': ['db_engine', 'sqlite-not'], 'db_port': ['db_engine', 'sqlite-not'],
    'db_name': ['db_engine', 'sqlite-not'], 'db_user': ['db_engine', 'sqlite-not'],
    'db_password': ['db_engine', 'sqlite-not'], 'db_timeout_s': ['db_engine', 'sqlite-not'],
    'backup_keep': ['backup_daily', '1'], 'backup_at': ['backup_daily', '1'],
    'rbackup_at': ['rbackup', '1'], 'rbackup_every': ['rbackup', '1'],
    'rbackup_day': ['rbackup_every', 'weekly'],
    'alerts_to': ['alerts', '1'], 'alerts_delay_min': ['alerts', '1'],
    'alerts_repeat_h': ['alerts', '1'], 'alerts_resolved': ['alerts', '1'],
    'alerts_nodes': ['alerts', '1'], 'alerts_backup': ['alerts', '1'],
    'alerts_db': ['alerts', '1'], 'alerts_vrrp': ['alerts', '1'],
    'alerts_cert_days': ['alerts', '1'], 'alerts_disk_pct': ['alerts', '1'],
    'alerts_time': ['alerts', '1'], 'alerts_updates': ['alerts', '1'],
    'alerts_dir': ['alerts', '1'], 'alerts_sms': ['alerts', '1'], 'alerts_guard': ['alerts', '1'],
    'report_to': ['report', '1'], 'report_every': ['report', '1'],
    'alerts_lang': ['alerts', '1'], 'report_lang': ['report', '1'],
    'osup_check_at': ['osup_check', '1'], 'osup_auto_what': ['osup_auto', '1'],
    'osup_auto_every': ['osup_auto', '1'], 'osup_auto_day': ['osup_auto_every', 'weekly'],
    'osup_auto_at': ['osup_auto', '1'], 'osup_auto_reboot': ['osup_auto', '1'],
    'power_auto_every': ['power_auto', '1'], 'power_auto_day': ['power_auto_every', 'weekly'],
    'power_auto_at': ['power_auto', '1'], 'power_auto_needed': ['power_auto', '1'],
    'siem_targets': ['siem', '1'], 'siem_format': ['siem', '1'], 'siem_events': ['siem', '1'],
    'siem_signins': ['siem', '1'], 'siem_facility': ['siem', '1'],
    'siem_hostname': ['siem', '1'], 'siem_verify': ['siem', '1'], 'siem_ca': ['siem', '1'],
    'proxy_url': ['proxy', '1'], 'proxy_user': ['proxy', '1'], 'proxy_password': ['proxy', '1'],
    'proxy_no': ['proxy', '1'], 'proxy_update': ['proxy', '1'], 'proxy_os': ['proxy', '1'],
    'proxy_acme': ['proxy', '1'], 'proxy_acme_dns': ['proxy', '1'], 'proxy_sms': ['proxy', '1'],
    'acme_for': ['acme', '1'], 'acme_email': ['acme', '1'], 'acme_ca': ['acme', '1'],
    'acme_url': ['acme_ca', 'custom'], 'acme_ca_pem': ['acme_ca', 'custom'],
    'acme_node_name': ['acme_for', 'vip-not'], 'acme_days': ['acme', '1'], 'acme_key': ['acme', '1'], 'acme_account_key': ['acme', '1'], 'acme_profile': ['acme', '1'],
    'acme_challenge': ['acme', '1'], 'acme_dns': ['acme_challenge', 'dns-01'],
    'acme_dns_wait': ['acme_challenge', 'dns-01'],
    'acme_dns_server': ['acme_dns', 'rfc2136'], 'acme_dns_zone': ['acme_dns', 'rfc2136'],
    'acme_dns_tsig_name': ['acme_dns', 'rfc2136'], 'acme_dns_tsig_alg': ['acme_dns', 'rfc2136'],
    'acme_dns_tsig_secret': ['acme_dns', 'rfc2136'], 'acme_dns_token': ['acme_dns', 'cloudflare'],
    'acme_dns_url': ['acme_dns', 'acmedns'], 'acme_dns_user': ['acme_dns', 'acmedns'],
    'acme_dns_key': ['acme_dns', 'acmedns'], 'acme_dns_subdomain': ['acme_dns', 'acmedns'],
    'acme_desec_domain': ['acme_dns', 'desec'], 'acme_desec_token': ['acme_dns', 'desec'],
    'acme_dns_alias': ['acme_dns', 'acmedns-not'], 'acme_resolvers': ['acme', '1'],
    'report_day': ['report_every', 'weekly'], 'report_at': ['report', '1'],
    'debug_radius': ['debug', '1'], 'debug_ldap': ['debug', '1'], 'debug_api': ['debug', '1'], 'debug_codes': ['debug', '1'],
    'smtp_host': ['mail_mode', 'smtp'], 'smtp_port': ['mail_mode', 'smtp'],
    'smtp_security': ['mail_mode', 'smtp'], 'smtp_auth': ['mail_mode', 'smtp'],
    'smtp_user': ['smtp_auth', 'none-not'], 'smtp_password': ['smtp_auth', 'none-not'],
    'smtp_verify': ['mail_mode', 'off-not'], 'smtp_timeout_s': ['mail_mode', 'off-not'],
    'mail_direct_port': ['mail_mode', 'direct'], 'mail_dns': ['mail_mode', 'direct'], 'mail_direct_tls': ['mail_mode', 'direct'], 'mail_from': ['mail_mode', 'off-not'],
    'mail_from_name': ['mail_mode', 'off-not'], 'mail_reply_to': ['mail_mode', 'off-not'],
    'mail_helo': ['mail_mode', 'off-not'], 'mail_lang': ['mail_mode', 'off-not'],
    'mail_codes': ['mail_mode', 'off-not'],
    'mail_retry_hours': ['mail_mode', 'off-not'], 'mail_keep_days': ['mail_mode', 'off-not'],
    'sms_url': ['sms_mode', 'http'], 'sms_method': ['sms_mode', 'http'],
    'sms_body': ['sms_mode', 'http'], 'sms_headers': ['sms_mode', 'http'],
    'sms_token': ['sms_mode', 'http'], 'sms_ok_status': ['sms_mode', 'http'],
    'sms_spool_dir': ['sms_mode', 'spool'], 'sms_prefix': ['sms_mode', 'off-not'],
    'sms_tel_host': ['sms_mode', 'teltonika'], 'sms_tel_https': ['sms_mode', 'teltonika'],
    'sms_tel_verify': ['sms_mode', 'teltonika'], 'sms_tel_user': ['sms_mode', 'teltonika'],
    'sms_tel_password': ['sms_mode', 'teltonika'], 'sms_tel_api': ['sms_mode', 'teltonika'],
    'sms_tel_modem': ['sms_mode', 'teltonika'], 'sms_plain': ['sms_mode', 'off-not'],
}

CONFIG = dict(DEFAULTS)
FILE_CONFIG = dict(DEFAULTS)
FILE_KEYS = set()
FROM_ARGV = {}
BAD_CONFIG = []


class BadSetting(ValueError):
    """A value that cannot be read as the setting it was given for."""


class NodeMoved(BadSetting):
    """Saved on another machine than the one meant (1.0.110)."""


def _coerce(current, value):
    """A value made to look like the default beside it - or refused.

    Refused rather than quietly replaced, as on isemon: a setting nobody can
    read must be a setting nobody accepts, so that what runs is either what
    was asked for or plainly said to be otherwise.
    """
    if isinstance(current, bool):
        if isinstance(value, str):
            said = value.strip().lower()
            if said in ('1', 'true', 'yes', 'on'):
                return True
            if said in ('0', 'false', 'no', 'off', ''):
                return False
            raise BadSetting('%r is not yes or no' % value)
        if value is None:
            raise BadSetting('a yes-or-no setting cannot be nothing')
        return bool(value)
    if isinstance(current, int):
        if value is None or (isinstance(value, str) and not value.strip()):
            raise BadSetting('a number is needed, and nothing was given')
        if isinstance(value, bool):
            return int(value)
        try:
            return int(float(value))
        except (TypeError, ValueError, OverflowError):
            raise BadSetting('%r is not a number' % (value,))
    if isinstance(current, list):
        if isinstance(value, str):
            return [p.strip() for p in re.split(r'[,;\n\r]', value) if p.strip()]
        if isinstance(value, (list, tuple)):
            return list(value)
        raise BadSetting('%r is not a list' % (value,))
    if isinstance(current, str):
        if value is None:
            raise BadSetting('nothing was given')
        if isinstance(value, (list, tuple)):
            return ', '.join(str(one).strip() for one in value if str(one).strip())
        if isinstance(value, (dict, set)):
            raise BadSetting('%r is not something this setting can hold' % (value,))
        if isinstance(value, bool):
            return 'yes' if value else ''
        return str(value)
    return value


# Settings of several lines (1.0.103): the rest are one line each.
SETTING_TALL = ('portal_help', 'portal_groups', 'sms_body', 'sms_headers', 'isemon_targets', 'isemon_ca', 'siem_ca', 'acme_ca_pem',
                'admin_group_full', 'admin_group_token', 'admin_group_readonly', 'mail_ca')


def check_setting(key, value):
    """The value as it will be kept, or BadSetting saying why not."""
    if key not in DEFAULTS:
        raise BadSetting('%s is not a setting this version knows' % key)
    got = _coerce(DEFAULTS[key], value)
    shape = TUNABLE.get(key)
    if isinstance(shape, tuple) and shape and isinstance(shape[0], str):
        if str(got) not in shape:
            raise BadSetting('%s: %r is not one of %s' % (key, got, ', '.join(shape)))
    elif isinstance(shape, tuple) and len(shape) == 2:
        if not (shape[0] <= int(got) <= shape[1]):
            raise BadSetting('%s must be between %d and %d' % (key, shape[0], shape[1]))
    if key.startswith(('mail_', 'smtp_')) and isinstance(got, str) and \
            key not in ('smtp_password',) and re.search(r'[\x00-\x1f\x7f]', got):
        # A new line in a header (1.0.94): refused here, not a ValueError out
        # of the mail library at the moment a token's mail goes.
        raise BadSetting('%s: no line breaks or control characters' % key)
    if isinstance(got, str) and key not in SECRET_KEYS:
        # A length and no control characters for every text (1.0.103): an
        # issuer of 3000 letters made every token's QR code fail after its key
        # was replaced, and a name held a NUL and new lines.
        tall = key in SETTING_TALL
        most = 64 if key in ('totp_issuer', 'totp_label') else (20000 if tall else 500)
        if len(got) > most:
            raise BadSetting('%s: %d characters at most' % (key, most))
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]' if tall else r'[\x00-\x1f\x7f]', got):
            raise BadSetting('%s: no line breaks or other control characters' % key)
    if key in ('alerts_to', 'report_to'):
        for one in [w for w in re.split(r'[\s,;]+', str(got)) if w]:
            if not re.match(r'^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z', one):
                raise BadSetting('%s: %r is not a mail address' % (key, one))
        if len([w for w in re.split(r'[\s,;]+', str(got)) if w]) > 20:
            raise BadSetting('%s: 20 addresses at most' % key)
    if key == 'alerts_url' and str(got).strip() and \
            not re.match(r'^https?://[^\s"<>]+\Z', str(got).strip()):
        raise BadSetting('alerts_url: an address starting https://')
    if key in ('backup_at', 'rbackup_at', 'report_at', 'osup_check_at', 'osup_auto_at',
               'power_auto_at') and \
            not re.match(r'^([01]?\d|2[0-3]):[0-5]\d\Z', str(got).strip()):
        raise BadSetting('%s is a time of day, written HH:MM' % key)
    # What reaches a command line, an option file or pg_hba.conf (1.0.33):
    # a database name like --result-file=/x was an option to mariadb-dump,
    # and a new line in a password a line of its own in the option file.
    if key in ('db_name', 'db_user') and str(got).strip() and \
            not re.match(r'^[A-Za-z_][A-Za-z0-9_]{0,62}\Z', str(got).strip()):
        raise BadSetting('%s: letters, digits and _ only, starting with a letter' % key)
    if key in ('db_host', 'ha_address', 'ha_peer') and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9_:\[][A-Za-z0-9_.:%\[\]-]{0,252}$|^/[A-Za-z0-9/._-]{1,200}\Z',
                         str(got).strip()):
        raise BadSetting('%s: a host name, an address, or the path of a socket' % key)
    if key in SECRET_KEYS and any(ord(ch) < 32 or ord(ch) == 127 for ch in str(got or '')):
        raise BadSetting('%s: no line breaks or other control characters' % key)
    if key == 'node_name' and str(got or '').strip() and \
            not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z', str(got).strip()):
        raise BadSetting('node_name: letters, digits, dots, dashes and _ - 63 at most')
    if key == 'radius_bind':
        try:
            ipaddress.ip_address(str(got).strip())
        except ValueError:
            raise BadSetting('radius_bind: %r is not an address' % got)
    if key == 'radius_guard_trusted':
        for one in [w for w in re.split(r'[\s,;]+', str(got)) if w]:
            try:
                ipaddress.ip_network(one, strict=False)
            except ValueError:
                raise BadSetting('radius_guard_trusted: %r is not an address or a network' % one)
    if key in ('mail_dns', 'acme_resolvers'):
        for one in [w for w in re.split(r'[\s,;]+', str(got)) if w]:
            try:
                ipaddress.ip_address(one)
            except ValueError:
                raise BadSetting('%s: %r is not the address of a DNS server' % (key, one))
    if key == 'isemon_targets':
        for one in syslog_targets(str(got), strict=True):
            pass
    if key == 'metrics_from':
        for one in [w for w in re.split(r'[\s,;]+', str(got)) if w]:
            try:
                ipaddress.ip_network(one, strict=False)
            except ValueError:
                raise BadSetting('metrics_from: %r is not an address or a network' % one)
    if key in ('snmp_from',):
        for one in [w for w in re.split(r'[\s,;]+', str(got)) if w]:
            try:
                ipaddress.ip_network(one, strict=False)
            except ValueError:
                raise BadSetting('snmp_from: %r is not an address or a network' % one)
    if key == 'snmp_bind' and str(got).strip():
        try:
            ipaddress.ip_address(str(got).strip())
        except ValueError:
            raise BadSetting('snmp_bind: one address of the node, or empty for every one')
    if key == 'snmp_user' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9._-]{1,32}\Z', str(got).strip()):
        raise BadSetting('snmp_user: 1 to 32 letters, digits and . _ -')
    if key in ('snmp_auth_pass', 'snmp_priv_pass') and str(got) and not is_masked(got) and \
            not 12 <= len(str(got)) <= 128:
        raise BadSetting('%s: 12 to 128 characters' % key)
    if key in ('snmp_contact', 'snmp_location') and len(str(got)) > 255:
        raise BadSetting('%s: 255 characters at most' % key)
    if key == 'snmp_trap_to' and str(got).strip():
        snmp_trap_targets(str(got), strict=True)
    if key == 'metrics_token' and str(got).strip() and not is_masked(got) and \
            not METRICS_TOKEN_RE_HEAD.match(str(got).strip()):
        raise BadSetting('metrics_token: 24 to 200 letters, digits and -_.~+/=')
    if key == 'isemon_ca' and str(got).strip() and \
            '-----BEGIN CERTIFICATE-----' not in str(got):
        raise BadSetting('isemon_ca: a certificate in PEM, -----BEGIN CERTIFICATE-----')
    if key == 'acme_email' and str(got).strip() and \
            not re.match(r'^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z', str(got).strip()):
        raise BadSetting('acme_email: a mail address')
    if key == 'acme_url' and str(got).strip() and \
            not re.match(r'^https://[^\s"<>]+\Z', str(got).strip()):
        raise BadSetting('acme_url: an address starting https://')
    if key == 'acme_dns_url' and str(got).strip() and \
            not re.match(r'^(https://[^\s"<>]+|http://(127\.0\.0\.1|localhost)(:\d+)?(/[^\s"<>]*)?)\Z',
                         str(got).strip()):
        raise BadSetting('acme_dns_url: an address starting https://')
    if key in ('acme_dns_server',) and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9.\-:\[\]]{1,260}\Z', str(got).strip()):
        raise BadSetting('acme_dns_server: a name or an address, :port if not 53')
    if key in ('acme_desec_domain', 'acme_dns_alias') and str(got).strip() and \
            not re.match(r'^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\.?\Z',
                         str(got).strip()):
        raise BadSetting('%s: a DNS name, like example.dedyn.io' % key)
    if key == 'acme_desec_token' and str(got).strip() and not is_masked(got) and \
            not re.match(r'^[A-Za-z0-9_.-]{20,100}\Z', str(got).strip()):
        raise BadSetting('acme_desec_token: the token as deSEC shows it')
    if key in ('acme_dns_zone', 'acme_dns_tsig_name') and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9][A-Za-z0-9.\-_]{0,252}\Z', str(got).strip()):
        raise BadSetting('%s: a DNS name' % key)
    if key == 'acme_dns_tsig_secret' and str(got).strip() and not is_masked(got) and \
            not re.match(r'^[A-Za-z0-9+/=]{8,512}\Z', str(got).strip()):
        raise BadSetting('acme_dns_tsig_secret: the secret in base64, as tsig-keygen makes it')
    if key in ('acme_dns_user', 'acme_dns_subdomain') and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9-]{1,64}\Z', str(got).strip()):
        raise BadSetting('%s: letters, digits and dashes' % key)
    if key == 'acme_ca_pem' and str(got).strip() and '-----BEGIN CERTIFICATE-----' not in str(got):
        raise BadSetting('acme_ca_pem: a certificate in PEM, -----BEGIN CERTIFICATE-----')
    if key == 'acme_node_name' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\Z', str(got).strip()):
        raise BadSetting('acme_node_name: a DNS name')
    if key == 'siem_targets':
        if len(siem_targets(str(got), strict=True)) > 8:
            raise BadSetting('siem_targets: 8 servers at most')
    if key == 'siem_ca' and str(got).strip() and \
            '-----BEGIN CERTIFICATE-----' not in str(got):
        raise BadSetting('siem_ca: a certificate in PEM, -----BEGIN CERTIFICATE-----')
    if key == 'siem_hostname' and str(got).strip() \
            and not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z', str(got).strip()):
        raise BadSetting('siem_hostname: a host name has letters, digits, dots and dashes '
                         'and nothing else')
    if key == 'proxy_url' and str(got).strip() and \
            not re.match(r'^https?://[A-Za-z0-9.\-]+(?::\d{1,5})?/?\Z|^https?://\[[0-9a-fA-F:]+\]'
                         r'(?::\d{1,5})?/?\Z', str(got).strip()):
        raise BadSetting('proxy_url: http://host:port - the user name and the password go '
                         'in the fields below, not in the address')
    if key in ('proxy_url', 'sms_tel_host') and str(got).strip():
        # A port that is one, and an address a URL can be made of (1.0.206):
        # :99999 or a bare IPv6 address was taken, and every try of it failed.
        u = str(got).strip()
        try:
            sp = urllib.parse.urlsplit(u if '://' in u else 'http://' + u)
            port_ = sp.port
            host_ = sp.hostname
        except ValueError:
            port_, host_ = -1, None
        if not host_ or (port_ is not None and not 1 <= port_ <= 65535) or u.endswith(':'):
            raise BadSetting('%s: host or host:port (1-65535), an IPv6 address in brackets - '
                             '[fd00::1]:443' % key)
    if key == 'proxy_user' and re.search(r'[\s:@/]', str(got)):
        raise BadSetting('proxy_user: no spaces, no : @ or /')
    if key == 'proxy_no' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9.*:/\[\]_-]+([\s,;]+[A-Za-z0-9.*:/\[\]_-]+)*[\s,;]*\Z',
                         str(got).strip()):
        raise BadSetting('proxy_no: names, .domains and addresses, separated by commas')
    if key == 'upgrade_url' and str(got).strip() and \
            not re.match(r'^https://[^\s]+\Z', str(got).strip()):
        raise BadSetting('upgrade_url: an address starting https://')
    if key == 'sms_url' and str(got).strip() and \
            not re.match(r'^https?://[^\s]+\Z', str(got).strip()):
        raise BadSetting('sms_url: an address starting https:// (or http://)')
    if key == 'sms_spool_dir' and str(got).strip() and \
            not re.match(r'^/[A-Za-z0-9/._-]{1,200}\Z', str(got).strip()):
        raise BadSetting('sms_spool_dir: the whole path of a folder, /var/spool/sms/outgoing')
    if key == 'sms_tel_host' and str(got).strip() and \
            not re.match(r'^(https?://)?[A-Za-z0-9.\-\[\]:]+/?\Z', str(got).strip()):
        raise BadSetting('sms_tel_host: an address or a name, with :port if it is not the usual one')
    if key == 'sms_tel_modem' and str(got).strip() and \
            not re.match(r'^[A-Za-z0-9_.-]{1,20}\Z', str(got).strip()):
        raise BadSetting('sms_tel_modem: the modem\'s id as the gateway names it, such as 1-1')
    if key == 'sms_prefix' and str(got).strip() and not re.match(r'^\+[1-9][0-9]{0,3}\Z',
                                                                    str(got).strip()):
        raise BadSetting('sms_prefix: + and the country code, +420')
    if key == 'totp_issuer' and ':' in str(got):
        # The otpauth label is "issuer:account" (1.0.207): an issuer with a colon in
        # it was read by the apps as a part of the account's name.
        raise BadSetting('totp_issuer: no colon in it - the apps take what follows one as '
                         'the account\'s name')
    if key == 'totp_label' and '{user}' not in str(got) and '{name}' not in str(got):
        raise BadSetting('totp_label needs {user} or {name} in it, or every token on a '
                         'phone has the same name')
    if key in ('isemon_hostname',) and str(got).strip() \
            and not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,62}\Z', str(got).strip()):
        raise BadSetting('isemon_hostname: a host name has letters, digits, dots and '
                         'dashes and nothing else')
    if key in ('mail_from', 'mail_reply_to') and str(got).strip():
        # An address, and only that (1.0.206): "ACME <acme@firma.cz>" was taken, and
        # every mail went out with a From the server refused - the name goes in
        # From (name). The address in it taken as the value.
        import email.utils as _eu
        addr = _eu.parseaddr(str(got).strip())[1]
        if not re.match(r'^[^@\s<>"]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z', addr or ''):
            raise BadSetting('%s: %r is not a mail address' % (key, got))
        got = addr
    if isinstance(got, str) and key in SETTING_STRIPPED:
        # As it was checked (1.0.206): "127.0.0.1 " passed as an address and was
        # kept with its space - RADIUS bound to it, and to nothing.
        got = got.strip()
    return got


SETTING_STRIPPED = frozenset((
    'radius_bind', 'snmp_bind', 'snmp_user', 'snmp_trap_to', 'node_name', 'db_host', 'db_name',
    'db_user', 'ha_address', 'ha_peer', 'alerts_url', 'backup_at', 'rbackup_at', 'report_at',
    'osup_check_at', 'osup_auto_at', 'power_auto_at', 'acme_email', 'acme_url', 'acme_dns_url',
    'acme_dns_server', 'acme_desec_domain', 'acme_dns_alias', 'acme_dns_zone',
    'acme_dns_tsig_name', 'acme_dns_user', 'acme_dns_subdomain', 'acme_node_name',
    'siem_hostname', 'isemon_hostname', 'proxy_url'))


CONFIG_LOADED = [False]


NAME_HELD = [False]               # the daemon running: its node's name kept until it starts again


def load_config(path=None, saved=None):
    """The defaults, with config.json over them and anything saved over that."""
    global CONFIG, FILE_CONFIG, FILE_KEYS
    where = Path(path) if path else CONFIG_FILE
    fresh = dict(DEFAULTS)
    named, refused, unknown = set(), [], []
    try:
        with open(where, encoding='utf-8') as f:
            given = json.load(f)
        if not isinstance(given, dict):
            raise ValueError('the config file is not an object')
        for key, value in given.items():
            if key in fresh:
                try:
                    fresh[key] = _coerce(fresh[key], value)
                    named.add(key)
                except BadSetting as bad:
                    refused.append('%s (%s)' % (key, bad))
            elif not key.startswith('_'):
                unknown.append(key)
    except FileNotFoundError:
        # Gone at a reload, as one unreadable (1.0.139): node_name, ha_mode,
        # the database went back to the defaults without a word.
        if CONFIG_LOADED[0] and Path(where) == Path(CONFIG_FILE):
            try:
                log('%s is not there: the settings in effect are kept until it is put back'
                    % where, 'error')
            except Exception:                           # noqa: BLE001
                pass
            return CONFIG
    except (ValueError, OSError) as e:
        # Never the defaults in its place (1.0.94): a typo in config.json
        # started the daemon on an empty SQLite of its own - every person
        # refused, a node quietly out of its cluster. A reload keeps what is
        # in effect; a start stops, saying why.
        if CONFIG_LOADED[0]:
            sys.stderr.write('acme: %s could not be read (%s); the settings in effect are '
                             'kept\n' % (where, e))
            try:
                log('%s could not be read (%s): the settings in effect are kept until it is '
                    'mended' % (where, e), 'error')
            except Exception:                           # noqa: BLE001
                pass
            return CONFIG
        raise SystemExit('acme: %s could not be read: %s - mend it (it is JSON) and start '
                         'again; nothing was started on the defaults' % (where, e))
    was_loaded = CONFIG_LOADED[0]
    CONFIG_LOADED[0] = True
    FILE_CONFIG = dict(fresh)
    if was_loaded and CONFIG and NAME_HELD[0] and this_node_name(fresh) != this_node_name(CONFIG):
        # The name it runs under kept until it starts again (1.0.206), as the page
        # says: read again at once, every setting of the node's old name stopped
        # applying - RADIUS went to the cluster's address and port on the spot.
        fresh['node_name'] = this_node_name(CONFIG)
    FILE_KEYS = named
    whole = dict(fresh)
    if saved:
        for key, value in saved.items():
            if key in DEFAULTS and key not in FILE_ONLY_KEYS:
                try:
                    whole[key] = _coerce(DEFAULTS[key], value)
                except BadSetting:
                    pass
        me = this_node_name(fresh)
        for key in NODE_KEYS:
            if key + '@' + me in saved:
                try:
                    whole[key] = _coerce(DEFAULTS[key], saved[key + '@' + me])
                except BadSetting:
                    pass
        # The proxy for each thing on its own (1.0.202), all off by default: one
        # switched on before goes on fetching the new versions and the system
        # updates through it, as it did, until changed.
        if saved.get('proxy'):
            for key in ('proxy_update', 'proxy_os'):
                if key not in saved:
                    whole[key] = 1
    whole.update(FROM_ARGV)
    CONFIG = whole
    if unknown:
        sys.stderr.write('acme: %s holds settings this version does not know: %s\n'
                         % (where, ', '.join(sorted(unknown)[:12])))
    BAD_CONFIG[:] = sorted(refused)
    return CONFIG


def service_ids():
    """The uid and gid of the daemon's account, or None."""
    try:
        import pwd
        pw = pwd.getpwnam(SERVICE_USER)
        return pw.pw_uid, pw.pw_gid
    except (KeyError, ImportError):
        return None


def write_replacing(path, text, mode=0o640, owner=None):
    """A file written beside itself and renamed over: never half of one.
    Its mode and owner set on the open file, not by name (1.0.101): run by
    root in a folder the service's account can write, a name can be made a
    link to any file of the machine between the write and the chmod."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='.' + path.name + '.', dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        if owner is not None and os.geteuid() == 0:
            os.fchown(fd, owner[0], owner[1])
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(text)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def write_file_settings(changes, path=None):
    """Change a few settings in config.json and leave the rest of it alone.
    Only the database's own address lives there; everything else is saved
    in the database."""
    where = Path(path) if path else CONFIG_FILE
    had = {}
    try:
        with open(where, encoding='utf-8') as f:
            got = json.load(f)
        if not isinstance(got, dict):
            raise ValueError('it is not an object')
        had = got
    except FileNotFoundError:
        had = {}
    except ValueError as e:
        raise OSError('%s is there but cannot be read (%s); put it right first - nothing '
                      'was written to it' % (where, str(e)[:120]))
    for key, value in changes.items():
        if key not in DEFAULTS:
            continue
        if value == DEFAULTS[key]:
            had.pop(key, None)
        else:
            had[key] = value
    try:
        was = os.stat(where)
        mode = (was.st_mode & 0o770) or 0o640
    except OSError:
        mode = 0o640
    write_replacing(where, json.dumps(had, indent=2, sort_keys=True, ensure_ascii=False)
                    + '\n', mode)
    return where


