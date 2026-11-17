# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- a template for Zabbix 7.0 (1.0.108) ---------------------------------------------------
# "acme by SNMP": made from ACME-MIB itself (deploy/ACME-MIB.txt) each time it is asked - every
# OID, unit, value map and description taken from the MIB the agent answers by, so the two
# never part. Zabbix 7.0's own way of asking: a few SNMP walks (walk[...]) and everything else
# dependent on them (SNMP walk value, SNMP walk to JSON for the discoveries) - one bulk walk per
# table, not a GET per value. The template: the items of the node, a discovery of every table
# (certificates, deployments, tests, modules, authorities, the certificates of the pages, the
# nodes, the disks, where the backups go, the CRLs, where the logs go), their triggers and
# graphs, the value maps of every state, tags, the SNMP traps and dashboards. YAML written here
# (the standard library has none), every value quoted as Zabbix's own exports quote it.
# docs/monitoring.md, Zabbix.
ZBX_NAME = 'acme by SNMP'
ZBX_GROUP = 'Templates/Applications'
ZBX_VENDOR_VERSION = '7.0-1'
ZBX_HEARTBEAT = '1h'
ZBX_PALETTE = ('1A7C11', 'F63100', '2774A4', 'A54F10', 'FC6EA3', '6C59DC', 'AC8C14', '611F27',
               'F230E0', '5CCD18', 'BB2A02', '5A2B57', '89ABF8', '7EC25C', '274482', '2B5429')


# ---- the MIB, read ---------------------------------------------------------------------------
def zbx_mib(text=None):
    """{name: {oid, syntax, units, desc, access}} and {TC name: {number: label}} of ACME-MIB."""
    text = snmp_mib_text() if text is None else text
    clean = '\n'.join(re.sub(r'--(?:[^-\n]|-(?!-))*(?:--|$)', '', line) for line in text.split('\n'))
    parents = {'acme': SNMP_BASE}
    defs = []
    for m in re.finditer(r'^(\w+)\s+(OBJECT IDENTIFIER|OBJECT-TYPE|NOTIFICATION-TYPE|'
                         r'OBJECT-GROUP|NOTIFICATION-GROUP|MODULE-COMPLIANCE)(.*?)::=\s*'
                         r'\{\s*(\w+)\s+(\d+)\s*\}', clean, re.M | re.S):
        defs.append((m.group(1), m.group(2), m.group(3), m.group(4), int(m.group(5))))
    objs = {}
    for _ in range(12):                         # parents defined after their children too
        for name, kind, body, parent, n in defs:
            if parent in parents and name not in parents:
                parents[name] = parents[parent] + (n,)
    for name, kind, body, parent, n in defs:
        if kind != 'OBJECT-TYPE' or name not in parents:
            continue
        syn = re.search(r'SYNTAX\s+(.+?)\s+(?:UNITS|MAX-ACCESS)', body, re.S)
        desc = re.search(r'DESCRIPTION\s+"(.*?)"', body, re.S)
        units = re.search(r'UNITS\s+"(.*?)"', body)
        acc = re.search(r'MAX-ACCESS\s+([\w-]+)', body)
        objs[name] = {'oid': parents[name], 'syntax': re.sub(r'\s+', ' ', syn.group(1)) if syn else '',
                      'units': units.group(1) if units else '',
                      'desc': re.sub(r'\s+', ' ', desc.group(1)).strip() if desc else '',
                      'access': acc.group(1) if acc else ''}
    tcs = {}
    for m in re.finditer(r'^(\w+)\s+::=\s+TEXTUAL-CONVENTION.*?SYNTAX\s+INTEGER\s*\{(.*?)\}', clean,
                         re.M | re.S):
        tcs[m.group(1)] = {int(v): k for k, v in re.findall(r'(\w+)\s*\(\s*(-?\d+)\s*\)', m.group(2))}
    return objs, tcs, parents


def _zbx_uuid(*parts):
    """A UUIDv4 of its own for each thing, the same each time the template is made (Zabbix
    matches a template imported again by them)."""
    h = bytearray(hashlib.sha256(('acme-zabbix|' + '|'.join(str(p) for p in parts))
                                 .encode('utf-8')).digest()[:16])
    h[6] = (h[6] & 0x0F) | 0x40
    h[8] = (h[8] & 0x3F) | 0x80
    return bytes(h).hex()


# ---- YAML, as Zabbix writes it ---------------------------------------------------------------
ZBX_YAML_PLAIN_KEY = re.compile(r'^[a-z_][a-z0-9_.]*\Z')
ZBX_YAML_BOOLISH = ('y', 'n', 'yes', 'no', 'on', 'off', 'true', 'false', 'null')


def _zbx_q(v):
    return "'" + str(v).replace("'", "''") + "'"


def _zbx_key(k):
    return k if ZBX_YAML_PLAIN_KEY.match(k) and k.lower() not in ZBX_YAML_BOOLISH else _zbx_q(k)


def _zbx_scalar(v, indent):
    if isinstance(v, bool):
        v = 'YES' if v else 'NO'
    v = str(v)
    if '\n' in v:
        pad = ' ' * (indent + 2)
        return '|' + ('-' if not v.endswith('\n') else '') + '\n' + '\n'.join(
            (pad + line) if line else '' for line in v.rstrip('\n').split('\n'))
    return _zbx_q(v)


def zbx_yaml(obj, indent=0):
    """dicts, lists and strings to YAML: every scalar quoted, the keys bare where they may be."""
    pad = ' ' * indent
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if v is None or v == [] or v == {}:
                continue
            if isinstance(v, (dict, list)):
                out.append('%s%s:' % (pad, _zbx_key(k)))
                out.append(zbx_yaml(v, indent + 2))
            else:
                out.append('%s%s: %s' % (pad, _zbx_key(k), _zbx_scalar(v, indent)))
    elif isinstance(obj, list):
        for v in obj:
            if isinstance(v, (dict, list)):
                inner = zbx_yaml(v, indent + 2)
                out.append(pad + '- ' + inner[indent + 2:])
            else:
                out.append('%s- %s' % (pad, _zbx_scalar(v, indent)))
    return '\n'.join(x for x in out if x != '')


# ---- what the template holds ---------------------------------------------------------------
# Value maps besides the MIB's textual conventions.
ZBX_MAPS_MORE = {
    'acme: up or down': {0: 'Down', 1: 'Up'},
    'acme: days left': None,                   # none: a number stays a number
    'zabbix.host.available': {0: 'not available', 1: 'available', 2: 'unknown'},
}
# The MIB's Integer32 (0..1) objects of before 1.0.108 read with a map of their own.
ZBX_OLD_TRUTH = {'acmeHighSecurity': 'ACME-MIB::AcmeTruth', 'acmeInCluster': 'ACME-MIB::AcmeTruth',
                 'acmeDbUp': 'acme: up or down', 'acmeManagedLeader': 'ACME-MIB::AcmeTruth',
                 'acmeManagedCertAutoRenew': 'ACME-MIB::AcmeTruth',
                 'acmeDeployEnabled': 'ACME-MIB::AcmeTruth', 'acmeTestEnabled': 'ACME-MIB::AcmeTruth',
                 'acmeModuleEnabled': 'ACME-MIB::AcmeTruth', 'acmeCaEnabled': 'ACME-MIB::AcmeTruth',
                 'acmeCaSigns': 'ACME-MIB::AcmeTruth', 'acmeNodeUp': 'acme: up or down',
                 'acmeDnsServerUp': 'acme: up or down'}

# Each item of the node: (MIB object, key, name, value type, units, component, extra) - extra:
# mult (a multiplier), rate (per second), map (a value map not of the MIB), hist, trends.
ZBX_ITEMS = [
    # acme itself
    ('acmeVersion', 'acme.version', 'Version', 'CHAR', '', 'system', {}),
    ('acmeNode', 'acme.node', 'Node name', 'CHAR', '', 'system', {}),
    ('acmeSite', 'acme.site', 'Site', 'CHAR', '', 'system', {}),
    ('acmeDbEngine', 'acme.db.engine', 'Database engine', 'CHAR', '', 'database', {}),
    ('acmeHighSecurity', 'acme.high_security', 'High security', 'UNSIGNED', '', 'security', {}),
    ('acmeInCluster', 'acme.cluster', 'In a cluster', 'UNSIGNED', '', 'cluster', {}),
    ('acmeUptime', 'acme.uptime', 'Daemon uptime', 'UNSIGNED', 'uptime', 'system',
     {'mult': '0.01', 'nodiscard': 1}),
    ('acmeNewestVersion', 'acme.version.newest', 'Newest version available', 'CHAR', '', 'system',
     {}),
    ('acmeUpdateAvailable', 'acme.version.update', 'Update of acme available', 'UNSIGNED', '',
     'system', {}),
    ('acmeStartTime', 'acme.started', 'Daemon started', 'UNSIGNED', 'unixtime', 'system', {}),
    ('acmeMaintenance', 'acme.maintenance', 'In maintenance', 'UNSIGNED', '', 'system', {}),
    ('acmeAlertsLead', 'acme.alerts.lead', 'Sends the alerts', 'UNSIGNED', '', 'alerts', {}),
    ('acmeUpdateChecked', 'acme.version.checked', 'Updates last looked for', 'UNSIGNED',
     'unixtime', 'system', {}),
    # the database
    ('acmeDbUp', 'acme.db.up', 'Database', 'UNSIGNED', '', 'database', {}),
    ('acmeDbLatency', 'acme.db.latency', 'Database latency', 'FLOAT', 's', 'database',
     {'mult': '0.000001', 'nodiscard': 1}),
    ('acmeDbSize', 'acme.db.size', 'Database size', 'UNSIGNED', 'B', 'database', {}),
    ('acmeDbGuard', 'acme.db.guard', 'Database guard', 'UNSIGNED', '', 'database', {}),
    ('acmeDbGuardRefused', 'acme.db.guard.refused', 'Rows refused by the guard (1 h)', 'UNSIGNED',
     '', 'database', {}),
    ('acmeDbTrouble', 'acme.db.trouble', 'Database trouble', 'CHAR', '', 'database', {}),
    # the alerts
    ('acmeAlertsBad', 'acme.alerts.bad', 'Alerts: bad', 'UNSIGNED', '', 'alerts', {}),
    ('acmeAlertsWarn', 'acme.alerts.warn', 'Alerts: warnings', 'UNSIGNED', '', 'alerts', {}),
    ('acmeAlertsWorst', 'acme.alerts.worst', 'Alerts: the worst now', 'UNSIGNED', '', 'alerts', {}),
    # the certificates, counted
    ('acmeManagedTotal', 'acme.certs.total', 'Certificates kept', 'UNSIGNED', '', 'certificate', {}),
    ('acmeManagedOk', 'acme.certs.ok', 'Certificates valid', 'UNSIGNED', '', 'certificate', {}),
    ('acmeManagedFailed', 'acme.certs.failed', 'Certificates whose renewal failed', 'UNSIGNED', '',
     'certificate', {}),
    ('acmeManagedExpired', 'acme.certs.expired', 'Certificates expired', 'UNSIGNED', '',
     'certificate', {}),
    ('acmeManagedExpiring', 'acme.certs.expiring', 'Certificates expiring soon', 'UNSIGNED', '',
     'certificate', {}),
    ('acmeManagedDeploysFailed', 'acme.deploys.failed', 'Deployments failed', 'UNSIGNED', '',
     'deployment', {}),
    ('acmeManagedLeader', 'acme.certs.leader', 'Renews and deploys (holds the lease)',
     'UNSIGNED', '', 'certificate', {}),
    ('acmeManagedJobsFailed', 'acme.jobs.failed', 'Certificate jobs failed (24 h)', 'UNSIGNED', '',
     'job', {}),
    ('acmeManagedDnsQueries', 'acme.dns.queries', 'DNS server: queries per second', 'FLOAT', 'qps',
     'dns', {'rate': 1}),
    ('acmeManagedWaiting', 'acme.certs.waiting', 'Certificates waiting (new, due, renewing)',
     'UNSIGNED', '', 'certificate', {}),
    ('acmeManagedTests', 'acme.tests.total', 'Tests', 'UNSIGNED', '', 'test', {}),
    ('acmeManagedTestsFailed', 'acme.tests.failed', 'Tests failing', 'UNSIGNED', '', 'test', {}),
    ('acmeManagedJobsRunning', 'acme.jobs.running', 'Certificate jobs running', 'UNSIGNED', '',
     'job', {}),
    ('acmeManagedModulesFailing', 'acme.modules.failing', 'Modules failing', 'UNSIGNED', '',
     'module', {}),
    ('acmeManagedCasEnding', 'acme.cas.ending', 'Authorities ending within 90 days', 'UNSIGNED',
     '', 'authority', {}),
    ('acmeManagedDeploys', 'acme.deploys.total', 'Deployments', 'UNSIGNED', '', 'deployment', {}),
    ('acmeManagedJobsOk', 'acme.jobs.ok', 'Certificate jobs done (24 h)', 'UNSIGNED', '', 'job', {}),
    ('acmeManagedLastScan', 'acme.certs.scanned', 'Last look for what is due', 'UNSIGNED',
     'unixtime', 'certificate', {'nodiscard': 1}),
    ('acmeManagedRevoked', 'acme.certs.revoked', 'Certificates revoked', 'UNSIGNED', '',
     'certificate', {}),
    ('acmeManagedPendingApproval', 'acme.certs.approval', 'Requests waiting for an approval',
     'UNSIGNED', '', 'certificate', {}),
    ('acmeManagedRenewalsFailed', 'acme.renewals.failed', 'Renewals failed (24 h)', 'UNSIGNED', '',
     'job', {}),
    ('acmeManagedRenewalsOk', 'acme.renewals.ok', 'Renewals done (24 h)', 'UNSIGNED', '', 'job', {}),
    ('acmeManagedDeploysOk24h', 'acme.deploys.ok24h', 'Deployments done (24 h)', 'UNSIGNED', '',
     'job', {}),
    ('acmeManagedDeploysFailed24h', 'acme.deploys.failed24h', 'Deployments failed (24 h)',
     'UNSIGNED', '', 'job', {}),
    # acme's DNS server
    ('acmeDnsServerOn', 'acme.dns.on', 'DNS server', 'UNSIGNED', '', 'dns', {}),
    ('acmeDnsServerUp', 'acme.dns.up', 'DNS server answers', 'UNSIGNED', '', 'dns', {}),
    ('acmeDnsRecords', 'acme.dns.records', 'DNS server: records', 'UNSIGNED', '', 'dns', {}),
    ('acmeDnsAnswered', 'acme.dns.answered', 'DNS server: answers per second', 'FLOAT', 'qps',
     'dns', {'rate': 1}),
    ('acmeDnsRefused', 'acme.dns.refused', 'DNS server: refused per second', 'FLOAT', 'qps', 'dns',
     {'rate': 1}),
    ('acmeDnsFailed', 'acme.dns.failed', 'DNS server: failed per second', 'FLOAT', 'qps', 'dns',
     {'rate': 1}),
    ('acmeDnsRateLimited', 'acme.dns.limited', 'DNS server: rate limited per second', 'FLOAT', 'qps',
     'dns', {'rate': 1}),
    # the cluster
    ('acmeHaMode', 'acme.ha.mode', 'Cluster mode', 'CHAR', '', 'cluster', {}),
    ('acmeVipAddress', 'acme.vip.address', 'VIP address', 'CHAR', '', 'cluster', {}),
    ('acmeVipHolders', 'acme.vip.holders', 'Nodes holding the VIP address', 'UNSIGNED', '',
     'cluster', {}),
    ('acmeVipOwner', 'acme.vip.owner', 'VIP address held by', 'CHAR', '', 'cluster', {}),
    ('acmeReplState', 'acme.repl.state', 'Replication', 'UNSIGNED', '', 'cluster', {}),
    ('acmeReplBehind', 'acme.repl.behind', 'Replication behind', 'UNSIGNED', 'B', 'cluster',
     {'nodiscard': 1}),
    ('acmeReplErrors', 'acme.repl.errors', 'Replication errors', 'UNSIGNED', '', 'cluster', {}),
    ('acmeSplitState', 'acme.split.state', 'Split', 'UNSIGNED', '', 'cluster', {}),
    ('acmeSplitRole', 'acme.split.role', 'Split: what this node does', 'CHAR', '', 'cluster', {}),
    ('acmeCertLeader', 'acme.certs.leader.node', 'Node renewing the certificates', 'CHAR', '',
     'cluster', {}),
    ('acmeNodesUp', 'acme.nodes.up', 'Nodes up', 'UNSIGNED', '', 'cluster', {}),
    ('acmeNodesKnown', 'acme.nodes.known', 'Nodes', 'UNSIGNED', '', 'cluster', {}),
    # the machine
    ('acmeCpuCores', 'acme.cpu.cores', 'CPU cores', 'UNSIGNED', '', 'cpu', {}),
    ('acmeCpuBusy', 'acme.cpu.util', 'CPU utilization', 'FLOAT', '%', 'cpu', {'nodiscard': 1}),
    ('acmeLoad1', 'acme.cpu.load1', 'Load average (1m)', 'FLOAT', '', 'cpu',
     {'mult': '0.01', 'nodiscard': 1}),
    ('acmeLoad5', 'acme.cpu.load5', 'Load average (5m)', 'FLOAT', '', 'cpu',
     {'mult': '0.01', 'nodiscard': 1}),
    ('acmeLoad15', 'acme.cpu.load15', 'Load average (15m)', 'FLOAT', '', 'cpu',
     {'mult': '0.01', 'nodiscard': 1}),
    ('acmeMemTotal', 'acme.mem.total', 'Memory total', 'UNSIGNED', 'B', 'memory', {}),
    ('acmeMemUsed', 'acme.mem.used', 'Memory used', 'UNSIGNED', 'B', 'memory', {'nodiscard': 1}),
    ('acmeSwapUsed', 'acme.swap.used', 'Swap used', 'UNSIGNED', 'B', 'memory', {'nodiscard': 1}),
    ('acmeDiskRead', 'acme.disk.read', 'Disks: read', 'FLOAT', 'Bps', 'storage', {'rate': 1}),
    ('acmeDiskWritten', 'acme.disk.written', 'Disks: written', 'FLOAT', 'Bps', 'storage',
     {'rate': 1}),
    ('acmeNetIn', 'acme.net.in', 'Network: received', 'FLOAT', 'bps', 'network',
     {'rate': 1, 'mult': '8'}),
    ('acmeNetOut', 'acme.net.out', 'Network: sent', 'FLOAT', 'bps', 'network',
     {'rate': 1, 'mult': '8'}),
    ('acmeBootTime', 'acme.boot', 'Machine started', 'UNSIGNED', 'unixtime', 'system', {}),
    ('acmeClockSkew', 'acme.clock.skew', 'Clock: skew', 'FLOAT', 's',
     'time', {'mult': '0.001'}),
    ('acmeClockOffset', 'acme.clock.offset', 'Clock: offset from NTP', 'FLOAT', 's', 'time',
     {'mult': '0.001'}),
    ('acmeClockSync', 'acme.clock.sync', 'Clock: in sync', 'UNSIGNED', '', 'time', {}),
    ('acmeClockProblem', 'acme.clock.problem', 'Clock: problem', 'CHAR', '', 'time', {}),
    ('acmeSelinuxMode', 'acme.selinux', 'SELinux', 'UNSIGNED', '', 'security', {}),
    ('acmeSelinuxDenials', 'acme.selinux.denials', 'SELinux denials', 'UNSIGNED', '', 'security',
     {}),
    ('acmeFirewallOn', 'acme.firewall', 'Firewall', 'UNSIGNED', '', 'security', {}),
    ('acmeOsUpdates', 'acme.os.updates', 'System updates waiting', 'UNSIGNED', '', 'os', {}),
    ('acmeOsSecurityUpdates', 'acme.os.security', 'Security updates waiting', 'UNSIGNED', '', 'os',
     {}),
    ('acmeOsRebootNeeded', 'acme.os.reboot', 'Restart needed', 'UNSIGNED', '', 'os', {}),
    ('acmeOsUpdatesChecked', 'acme.os.checked', 'System updates last looked for', 'UNSIGNED',
     'unixtime', 'os', {}),
    ('acmeSshdState', 'acme.sshd', 'sshd set up', 'CHAR', '', 'security', {}),
    ('acmeKeyLost', 'acme.key.lost', 'Sealing key missing', 'UNSIGNED', '', 'security', {}),
    ('acmeNameClash', 'acme.name.clash', 'Name clash', 'CHAR', '', 'system', {}),
    ('acmeSnmpAsked', 'acme.snmp.asked', 'SNMP agent: requests per second', 'FLOAT', 'rps',
     'snmp', {'rate': 1}),
    ('acmeSnmpAnswered', 'acme.snmp.answered', 'SNMP agent: answers per second', 'FLOAT', 'rps',
     'snmp', {'rate': 1}),
    ('acmeSnmpTraps', 'acme.snmp.traps', 'SNMP agent: traps sent', 'UNSIGNED', '', 'snmp', {}),
    ('acmeHandWaiting', 'acme.hand', 'Things to do by hand', 'UNSIGNED', '', 'system', {}),
    # the backups
    ('acmeBackupLast', 'acme.backup.last', 'Backup: newest kept here', 'UNSIGNED', 'unixtime',
     'backup', {}),
    ('acmeBackupAge', 'acme.backup.age', 'Backup: age of the newest', 'UNSIGNED', 's', 'backup',
     {'nodiscard': 1}),
    ('acmeBackupsKept', 'acme.backup.kept', 'Backups kept here', 'UNSIGNED', '', 'backup', {}),
    ('acmeBackupDaily', 'acme.backup.daily', 'Backup every night', 'UNSIGNED', '', 'backup', {}),
    ('acmeRemoteBackupOn', 'acme.rbackup.on', 'Backups sent away', 'UNSIGNED', '', 'backup', {}),
    ('acmeRemoteBackupLast', 'acme.rbackup.last', 'Backup sent away last', 'UNSIGNED', 'unixtime',
     'backup', {}),
    ('acmeRemoteBackupLastOk', 'acme.rbackup.last_ok', 'Backup sent away last with success',
     'UNSIGNED', 'unixtime', 'backup', {}),
    ('acmeRemoteBackupResult', 'acme.rbackup.result', 'Backup sent away: result', 'UNSIGNED', '',
     'backup', {}),
    ('acmeRemoteBackupError', 'acme.rbackup.error', 'Backup sent away: error', 'CHAR', '',
     'backup', {}),
    ('acmeBackupVerify', 'acme.backup.verify', 'Backup tried: result', 'UNSIGNED', '', 'backup', {}),
    ('acmeBackupVerifyAt', 'acme.backup.verify_at', 'Backup tried last', 'UNSIGNED', 'unixtime',
     'backup', {}),
    # signing in
    ('acmeAccounts', 'acme.accounts', 'Accounts', 'UNSIGNED', '', 'signin', {}),
    ('acmeAccountsLocal', 'acme.accounts.local', 'Local accounts', 'UNSIGNED', '', 'signin', {}),
    ('acmeSessions', 'acme.sessions', 'Sign-ins open', 'UNSIGNED', '', 'signin', {}),
    ('acmeLockedOut', 'acme.lockouts', 'Locked out now', 'UNSIGNED', '', 'signin', {}),
    ('acmeFailsCounted', 'acme.signin.fails', 'Wrong sign-ins counted', 'UNSIGNED', '', 'signin',
     {}),
    ('acmeKerberosOn', 'acme.kerberos', 'Sign-in with Windows', 'UNSIGNED', '', 'signin', {}),
    ('acmeKeytabWritten', 'acme.kerberos.keytab', 'Keytab written here', 'UNSIGNED', '', 'signin',
     {}),
    ('acmeKeytabEntries', 'acme.kerberos.entries', 'Keytab keys', 'UNSIGNED', '', 'signin', {}),
    ('acmeKerberosError', 'acme.kerberos.error', 'Sign-in with Windows: error', 'CHAR', '',
     'signin', {}),
    ('acmeCertLoginOn', 'acme.certlogin', 'Sign-in with a certificate', 'UNSIGNED', '', 'signin',
     {}),
    ('acmeCertLoginListening', 'acme.certlogin.listening', 'Sign-in with a certificate: port open',
     'UNSIGNED', '', 'signin', {}),
    ('acmeCertLoginAuthorities', 'acme.certlogin.cas', 'Sign-in with a certificate: authorities',
     'UNSIGNED', '', 'signin', {}),
    ('acmeCertLoginError', 'acme.certlogin.error', 'Sign-in with a certificate: error', 'CHAR', '',
     'signin', {}),
    # services
    ('acmeIsemonOn', 'acme.isemon', 'Logs to isemon', 'UNSIGNED', '', 'logs', {}),
    ('acmeSiemOn', 'acme.siem', 'Logs to syslog (SIEM)', 'UNSIGNED', '', 'logs', {}),
    ('acmeShipDropped', 'acme.logs.dropped', 'Log lines dropped', 'UNSIGNED', '', 'logs',
     {'nodiscard': 1}),
    ('acmeMailWaiting', 'acme.mail.waiting', 'Mails waiting', 'UNSIGNED', '', 'mail', {}),
    ('acmeMailFailed', 'acme.mail.failed', 'Mails failed', 'UNSIGNED', '', 'mail', {}),
    ('acmeMailSent', 'acme.mail.sent', 'Mails sent (kept in the queue)', 'UNSIGNED', '', 'mail', {}),
    ('acmeDirectories', 'acme.dirs', 'Directories', 'UNSIGNED', '', 'directory', {}),
    ('acmeDirectoriesDown', 'acme.dirs.down', 'Directories not answering', 'UNSIGNED', '',
     'directory', {}),
    ('acmeSmsFails', 'acme.sms.fails', 'SMS failed in a row', 'UNSIGNED', '', 'sms', {}),
]

# The subtrees the master walk of the node reads (the tables among them are small).
ZBX_NODE_WALK = ['acmeInfo', 'acmeDatabase', 'acmeAlertsBad', 'acmeAlertsWarn', 'acmeAlertsWorst',
                 'acmeManagedCounts', 'acmeDnsServer', 'acmeCluster', 'acmeSystem', 'acmeBackup',
                 'acmeSignIn', 'acmeServices']


# The discoveries: one master walk each, the LLD macros from columns, the item prototypes.
# Item prototype: (column, key part, name, value type, units, extra).
ZBX_TABLES = [
    {'id': 'cert', 'table': 'acmeManagedCertTable', 'what': 'Certificates', 'component': 'certificate',
     'name': 'Certificates discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#CERT.ID}', 'acmeManagedCertIndex'), ('{#CERT.NAME}', 'acmeManagedCertName'),
                ('{#CERT.CN}', 'acmeManagedCertCN'), ('{#CERT.ISSUER}', 'acmeManagedCertIssuer'),
                ('{#CERT.OWNER}', 'acmeManagedCertOwner'),
                ('{#CERT.KEYTYPE}', 'acmeManagedCertKeyType'),
                ('{#CERT.KEYTYPE.ALT}', 'acmeManagedCertKeyTypeAlt'),
                ('{#CERT.AUTO}', 'acmeManagedCertAutoRenew')],
     'key': '{#CERT.ID}', 'label': 'Certificate {#CERT.NAME}',
     'filter': [('{#CERT.NAME}', '{$ACME.CERT.NAME.MATCHES}', 'MATCHES_REGEX'),
                ('{#CERT.NAME}', '{$ACME.CERT.NAME.NOT_MATCHES}', 'NOT_MATCHES_REGEX'),
                ('{#CERT.OWNER}', '{$ACME.CERT.OWNER.MATCHES}', 'MATCHES_REGEX')],
     'tags': [('cert', '{#CERT.NAME}'), ('owner', '{#CERT.OWNER}'), ('issuer', '{#CERT.ISSUER}')],
     'items': [
         ('acmeManagedCertDaysLeft', 'days', 'days left', 'FLOAT', '!days', {'nodiscard': 1}),
         ('acmeManagedCertNotAfter', 'not_after', 'expires', 'UNSIGNED', 'unixtime', {}),
         ('acmeManagedCertNotBefore', 'not_before', 'valid from', 'UNSIGNED', 'unixtime', {}),
         ('acmeManagedCertStateEnum', 'state', 'state', 'UNSIGNED', '', {}),
         ('acmeManagedCertAutoRenew', 'auto', 'renewed by itself', 'UNSIGNED', '', {}),
         ('acmeManagedCertDeploysFailed', 'deploys_failed', 'deployments failed', 'UNSIGNED', '',
          {}),
         ('acmeManagedCertTestsFailed', 'tests_failed', 'tests failing', 'UNSIGNED', '', {}),
         ('acmeManagedCertDeploys', 'deploys', 'deployments', 'UNSIGNED', '', {}),
         ('acmeManagedCertTests', 'tests', 'tests', 'UNSIGNED', '', {}),
         ('acmeManagedCertFails', 'fails', 'renewals failed in a row', 'UNSIGNED', '', {}),
         ('acmeManagedCertLastError', 'error', 'last error', 'CHAR', '', {}),
         ('acmeManagedCertLastOk', 'last_ok', 'last renewal', 'UNSIGNED', 'unixtime', {}),
         ('acmeManagedCertNextTry', 'next_try', 'next try', 'UNSIGNED', 'unixtime', {}),
         ('acmeManagedCertVersion', 'version', 'version', 'UNSIGNED', '', {}),
         ('acmeManagedCertSerial', 'serial', 'serial number', 'CHAR', '', {}),
         ('acmeManagedCertSource', 'source', 'how it came', 'CHAR', '', {}),
         ('acmeManagedCertNames', 'names', 'names', 'UNSIGNED', '', {}),
         ('acmeManagedCertAltDaysLeft', 'alt_days', 'twin (dual) days left', 'FLOAT', '!days',
          {'nodiscard': 1, 'alt': 1})]},
    {'id': 'deploy', 'table': 'acmeDeployTable', 'what': 'Deployments', 'component': 'deployment',
     'name': 'Deployments discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#DEPLOY.ID}', 'acmeDeployIndex'), ('{#DEPLOY.CERT}', 'acmeDeployCert'),
                ('{#DEPLOY.TARGET}', 'acmeDeployTarget'), ('{#DEPLOY.ENABLED}', 'acmeDeployEnabled')],
     'key': '{#DEPLOY.ID}', 'label': 'Deployment {#DEPLOY.CERT} to {#DEPLOY.TARGET}',
     'filter': [('{#DEPLOY.TARGET}', '{$ACME.TARGET.MATCHES}', 'MATCHES_REGEX'),
                ('{#DEPLOY.TARGET}', '{$ACME.TARGET.NOT_MATCHES}', 'NOT_MATCHES_REGEX'),
                ('{#DEPLOY.ENABLED}', '{$ACME.DEPLOY.ENABLED.MATCHES}', 'MATCHES_REGEX')],
     'tags': [('cert', '{#DEPLOY.CERT}'), ('deploy', '{#DEPLOY.TARGET}')],
     'items': [
         ('acmeDeployStateNum', 'state', 'state', 'UNSIGNED', '', {}),
         ('acmeDeployFails', 'fails', 'failures in a row', 'UNSIGNED', '', {}),
         ('acmeDeployLastOk', 'last_ok', 'last deployed', 'UNSIGNED', 'unixtime', {}),
         ('acmeDeployLastTry', 'last_try', 'last tried', 'UNSIGNED', 'unixtime', {}),
         ('acmeDeployVersion', 'version', 'version deployed', 'UNSIGNED', '', {}),
         ('acmeDeployLastError', 'error', 'last error', 'CHAR', '', {})]},
    {'id': 'test', 'table': 'acmeTestTable', 'what': 'Tests', 'component': 'test',
     'name': 'Tests discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#TEST.ID}', 'acmeTestIndex'), ('{#TEST.CERT}', 'acmeTestCert'),
                ('{#TEST.NAME}', 'acmeTestName'), ('{#TEST.KIND}', 'acmeTestKind'),
                ('{#TEST.ENABLED}', 'acmeTestEnabled')],
     'key': '{#TEST.ID}', 'label': 'Test {#TEST.NAME} of {#TEST.CERT}',
     'filter': [('{#TEST.ENABLED}', '{$ACME.TEST.ENABLED.MATCHES}', 'MATCHES_REGEX')],
     'tags': [('cert', '{#TEST.CERT}'), ('test', '{#TEST.NAME}'), ('kind', '{#TEST.KIND}')],
     'items': [
         ('acmeTestStateNum', 'state', 'result', 'UNSIGNED', '', {}),
         ('acmeTestFails', 'fails', 'failures in a row', 'UNSIGNED', '', {}),
         ('acmeTestLastAt', 'last_at', 'last run', 'UNSIGNED', 'unixtime', {}),
         ('acmeTestLastOk', 'last_ok', 'last passed', 'UNSIGNED', 'unixtime', {}),
         ('acmeTestSaid', 'said', 'what it said', 'CHAR', '', {})]},
    {'id': 'module', 'table': 'acmeModuleTable', 'what': 'Modules', 'component': 'module',
     'name': 'Sources, validations, targets and tests discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#MODULE.ID}', 'acmeModuleIndex'), ('{#MODULE.FAMILY}', 'acmeModuleFamily'),
                ('{#MODULE.NAME}', 'acmeModuleName'), ('{#MODULE.KIND}', 'acmeModuleKind'),
                ('{#MODULE.ENABLED}', 'acmeModuleEnabled')],
     'key': '{#MODULE.ID}', 'label': 'Module {#MODULE.FAMILY} {#MODULE.NAME}',
     'filter': [('{#MODULE.ENABLED}', '{$ACME.MODULE.ENABLED.MATCHES}', 'MATCHES_REGEX')],
     'tags': [('family', '{#MODULE.FAMILY}'), ('module', '{#MODULE.NAME}'), ('kind', '{#MODULE.KIND}')],
     'items': [
         ('acmeModuleFailing', 'failing', 'failing', 'UNSIGNED', '', {}),
         ('acmeModuleLastOk', 'last_ok', 'last worked', 'UNSIGNED', 'unixtime', {}),
         ('acmeModuleLastError', 'error', 'last error', 'CHAR', '', {})]},
    {'id': 'ca', 'table': 'acmeCaTable', 'what': 'Authorities', 'component': 'authority',
     'name': 'Authorities discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#CA.ID}', 'acmeCaIndex'), ('{#CA.NAME}', 'acmeCaName'),
                ('{#CA.SUBJECT}', 'acmeCaSubject'), ('{#CA.ENABLED}', 'acmeCaEnabled'),
                ('{#CA.SIGNS}', 'acmeCaSigns')],
     'key': '{#CA.ID}', 'label': 'Authority {#CA.NAME}',
     'filter': [('{#CA.ENABLED}', '{$ACME.CA.ENABLED.MATCHES}', 'MATCHES_REGEX')],
     'tags': [('authority', '{#CA.NAME}')],
     'items': [
         ('acmeCaDaysLeft', 'days', 'days left', 'FLOAT', '!days', {'nodiscard': 1}),
         ('acmeCaNotAfter', 'not_after', 'expires', 'UNSIGNED', 'unixtime', {}),
         ('acmeCaCrlNext', 'crl_next', 'CRL due', 'UNSIGNED', 'unixtime', {}),
         ('acmeCaCrlHoursLeft', 'crl_hours', 'CRL hours left', 'FLOAT', '!h', {'nodiscard': 1})]},
    {'id': 'agent', 'table': 'acmeAgentTable', 'what': 'Target agents', 'component': 'agent',
     'name': 'Target agents discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#AGENT.ID}', 'acmeAgentIndex'), ('{#AGENT.NAME}', 'acmeAgentName'),
                ('{#AGENT.MODE}', 'acmeAgentMode')],
     'key': '{#AGENT.ID}', 'label': 'Agent of {#AGENT.NAME}', 'filter': [],
     'tags': [('target', '{#AGENT.NAME}'), ('mode', '{#AGENT.MODE}')],
     'items': [
         ('acmeAgentStateNum', 'state', 'state', 'UNSIGNED', '', {}),
         ('acmeAgentLastSeen', 'last_seen', 'last heard from', 'UNSIGNED', 'unixtime', {}),
         ('acmeAgentCertDaysLeft', 'days', 'certificate days left', 'FLOAT', '!days',
          {'nodiscard': 1}),
         ('acmeAgentVersion', 'version', 'version', 'CHAR', '', {}),
         ('acmeAgentNewer', 'newer', 'newer version offered', 'UNSIGNED', '', {}),
         ('acmeAgentBlocked', 'blocked', 'policy blocks a deployment', 'UNSIGNED', '', {}),
         ('acmeAgentClockSkew', 'skew', 'server clock skew', 'FLOAT', 's', {}),
         ('acmeAgentRebootPending', 'reboot', 'server restart pending', 'UNSIGNED', '', {})]},
    {'id': 'pages', 'table': 'acmeCertTable', 'what': 'Certificates of the pages',
     'component': 'web', 'name': 'Certificates of the pages discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#PAGES.TARGET}', 'acmeCertTarget'), ('{#PAGES.CN}', 'acmeCertName')],
     'key': '{#PAGES.TARGET}', 'label': 'Pages of {#PAGES.TARGET} ({#PAGES.CN})',
     'filter': [], 'tags': [('pages', '{#PAGES.TARGET}')],
     'items': [
         ('acmeCertDaysLeft', 'days', 'certificate days left', 'FLOAT', '!days', {'nodiscard': 1}),
         ('acmeCertEnd', 'not_after', 'certificate expires', 'UNSIGNED', 'unixtime', {})]},
    {'id': 'node', 'table': 'acmeNodeTable', 'what': 'Nodes', 'component': 'cluster',
     'name': 'Cluster nodes discovery', 'delay': '{$ACME.INTERVAL}',
     'macros': [('{#NODE.NAME}', 'acmeNodeName'), ('{#NODE.THIS}', 'acmeNodeIsThis')],
     'key': '{#NODE.NAME}', 'label': 'Node {#NODE.NAME}', 'filter': [],
     'tags': [('node', '{#NODE.NAME}')],
     'items': [
         ('acmeNodeUp', 'up', 'heard from', 'UNSIGNED', '', {}),
         ('acmeNodeAge', 'age', 'last heard from', 'UNSIGNED', 's', {'nodiscard': 1}),
         ('acmeNodeVersion', 'version', 'version', 'CHAR', '', {}),
         ('acmeNodeMaintenance', 'maintenance', 'in maintenance', 'UNSIGNED', '', {}),
         ('acmeNodeVipHere', 'vip', 'holds the VIP address', 'UNSIGNED', '', {}),
         ('acmeNodeVrrpRole', 'vrrp', 'keepalived role', 'UNSIGNED', '', {}),
         ('acmeNodeStarted', 'started', 'daemon started', 'UNSIGNED', 'unixtime', {})]},
    {'id': 'disk', 'table': 'acmeDiskTable', 'what': 'Disks', 'component': 'storage',
     'name': 'File systems discovery', 'delay': '{$ACME.INTERVAL}',
     'macros': [('{#DISK.PATH}', 'acmeDiskPath')],
     'key': '{#DISK.PATH}', 'label': 'FS [{#DISK.PATH}]',
     'filter': [('{#DISK.PATH}', '{$ACME.DISK.MATCHES}', 'MATCHES_REGEX'),
                ('{#DISK.PATH}', '{$ACME.DISK.NOT_MATCHES}', 'NOT_MATCHES_REGEX')],
     'tags': [('filesystem', '{#DISK.PATH}')],
     'items': [
         ('acmeDiskSize', 'total', 'total space', 'UNSIGNED', 'B', {}),
         ('acmeDiskUsed', 'used', 'used space', 'UNSIGNED', 'B', {'nodiscard': 1}),
         ('acmeDiskFree', 'free', 'free space', 'UNSIGNED', 'B', {'nodiscard': 1}),
         ('acmeDiskUsedPct', 'pused', 'space utilization', 'FLOAT', '%', {'nodiscard': 1}),
         ('acmeDiskInodesPct', 'iused', 'inodes utilization', 'FLOAT', '%', {'nodiscard': 1})]},
    {'id': 'rbackup', 'table': 'acmeRemoteBackupTable', 'what': 'Backup places',
     'component': 'backup', 'name': 'Backup places discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#RBACKUP.NAME}', 'acmeRemoteBackupName')],
     'key': '{#RBACKUP.NAME}', 'label': 'Backup to {#RBACKUP.NAME}', 'filter': [],
     'tags': [('place', '{#RBACKUP.NAME}')],
     'items': [
         ('acmeRemoteBackupTargetResult', 'result', 'result', 'UNSIGNED', '', {}),
         ('acmeRemoteBackupTargetAt', 'at', 'last sent', 'UNSIGNED', 'unixtime', {}),
         ('acmeRemoteBackupTargetLastOk', 'last_ok', 'last sent with success', 'UNSIGNED',
          'unixtime', {}),
         ('acmeRemoteBackupTargetError', 'error', 'error', 'CHAR', '', {})]},
    {'id': 'crl', 'table': 'acmeCrlTable', 'what': 'CRLs', 'component': 'signin',
     'name': 'CRLs of the sign-in with a certificate discovery', 'delay': '{$ACME.INTERVAL.TABLES}',
     'macros': [('{#CRL.URL}', 'acmeCrlUrl')],
     'key': '{#CRL.URL}', 'label': 'CRL {#CRL.URL}', 'filter': [],
     'tags': [('crl', '{#CRL.URL}')],
     'items': [
         ('acmeCrlOk', 'ok', 'kept', 'UNSIGNED', '', {}),
         ('acmeCrlFetched', 'fetched', 'fetched', 'UNSIGNED', 'unixtime', {}),
         ('acmeCrlNextUpdate', 'next', 'next update', 'UNSIGNED', 'unixtime', {}),
         ('acmeCrlHoursLeft', 'hours', 'hours left', 'FLOAT', '!h', {'nodiscard': 1}),
         ('acmeCrlError', 'error', 'error', 'CHAR', '', {})]},
    {'id': 'ship', 'table': 'acmeShipTable', 'what': 'Log destinations', 'component': 'logs',
     'name': 'Log destinations discovery', 'delay': '{$ACME.INTERVAL}',
     'macros': [('{#SHIP.KIND}', 'acmeShipKind'), ('{#SHIP.TARGET}', 'acmeShipTarget')],
     'key': '{#SHIP.KIND},{#SHIP.TARGET}', 'label': 'Logs to {#SHIP.KIND} {#SHIP.TARGET}',
     'filter': [], 'tags': [('destination', '{#SHIP.TARGET}')],
     'items': [
         ('acmeShipSent', 'sent', 'lines per second', 'FLOAT', 'lps', {'rate': 1}),
         ('acmeShipTrouble', 'trouble', 'in trouble', 'UNSIGNED', '', {}),
         ('acmeShipSaid', 'said', 'trouble said', 'CHAR', '', {})]},
]

ZBX_MACROS = [
    ('{$ACME.INTERVAL}', '1m', 'How often the node is walked.'),
    ('{$ACME.INTERVAL.TABLES}', '5m', 'How often the certificates, deployments, tests, modules, '
     'authorities, backups and CRLs are walked.'),
    ('{$SNMP.TIMEOUT}', '5m', 'For how long no SNMP answer means the agent is not available.'),
    ('{$ACME.CERT.WARN}', '30', 'A certificate ending within so many days: a warning. A context '
     'per certificate: {$ACME.CERT.WARN:"name"}.'),
    ('{$ACME.CERT.CRIT}', '7', 'A certificate ending within so many days: high. A context per '
     'certificate: {$ACME.CERT.CRIT:"name"}.'),
    ('{$ACME.CERT.NAME.MATCHES}', '.*', 'Certificates discovered: their names match.'),
    ('{$ACME.CERT.NAME.NOT_MATCHES}', 'CHANGE_IF_NEEDED', 'Certificates left out: their names '
     'match.'),
    ('{$ACME.CERT.OWNER.MATCHES}', '.*', 'Certificates discovered: their owners match (an empty '
     'owner matches .*).'),
    ('{$ACME.TARGET.MATCHES}', '.*', 'Deployments discovered: their targets match.'),
    ('{$ACME.TARGET.NOT_MATCHES}', 'CHANGE_IF_NEEDED', 'Deployments left out: their targets '
     'match.'),
    ('{$ACME.DEPLOY.ENABLED.MATCHES}', '^1$', 'Deployments discovered: 1 those in use only, .* all.'),
    ('{$ACME.TEST.ENABLED.MATCHES}', '^1$', 'Tests discovered: 1 those that run only, .* all.'),
    ('{$ACME.MODULE.ENABLED.MATCHES}', '^1$', 'Modules discovered: 1 those switched on only, .* all.'),
    ('{$ACME.CA.ENABLED.MATCHES}', '^1$', 'Authorities discovered: 1 those switched on only, .* all.'),
    ('{$ACME.CA.WARN}', '90', 'An authority of acme ending within so many days: a warning.'),
    ('{$ACME.CA.CRIT}', '30', 'An authority of acme ending within so many days: high.'),
    ('{$ACME.PAGES.WARN}', '21', 'The certificate of the pages ending within so many days: a '
     'warning.'),
    ('{$ACME.PAGES.CRIT}', '7', 'The certificate of the pages ending within so many days: high.'),
    ('{$ACME.TEST.MAX.AGE}', '2d', 'A test that has not run for so long: information.'),
    ('{$ACME.DISK.MATCHES}', '.*', 'File systems discovered: their paths match.'),
    ('{$ACME.DISK.NOT_MATCHES}', 'CHANGE_IF_NEEDED', 'File systems left out: their paths match.'),
    ('{$ACME.DISK.PUSED.WARN}', '85', 'A file system this full (%): a warning. A context per '
     'path.'),
    ('{$ACME.DISK.PUSED.CRIT}', '95', 'A file system this full (%): high. A context per path.'),
    ('{$ACME.CPU.UTIL.CRIT}', '90', 'The processors this busy (%) for 5 minutes: a warning.'),
    ('{$ACME.MEM.UTIL.MAX}', '90', 'The memory this used (%) for 5 minutes: a warning.'),
    ('{$ACME.LOAD.PER.CPU.MAX}', '1.5', 'The load of 5 minutes per core above this: a warning.'),
    ('{$ACME.DB.LATENCY.MAX}', '0.5', 'SELECT 1 slower than this (seconds) for 5 minutes: a '
     'warning.'),
    ('{$ACME.BACKUP.AGE.MAX}', '36h', 'The newest backup kept on the node older than this, with '
     'a backup every night: a warning.'),
    ('{$ACME.RBACKUP.AGE.MAX}', '8d', 'No good backup sent away for so long: a warning.'),
    ('{$ACME.REPL.BEHIND.MAX}', '104857600', 'The other node behind by more than so many bytes '
     'for 10 minutes: a warning.'),
    ('{$ACME.CLOCK.OFFSET.MAX}', '0.5', 'The clock off by more than so many seconds: a warning.'),
    ('{$ACME.CRL.HOURS.WARN}', '12', 'A CRL of the sign-in with a certificate due within so many '
     'hours, and not fetched again: a warning.'),
    ('{$ACME.SNMP.USER}', 'acme', 'The SNMPv3 security name (Settings, Monitoring, SNMPv3) - '
     'for the host\'s SNMP interface.'),
    ('{$ACME.SNMP.AUTHPASS}', '', 'Its authentication passphrase - for the host\'s SNMP '
     'interface.', 'SECRET_TEXT'),
    ('{$ACME.SNMP.PRIVPASS}', '', 'Its privacy passphrase - for the host\'s SNMP interface.',
     'SECRET_TEXT'),
]


class _Zbx(object):
    """The template being made: the MIB's objects at hand."""

    def __init__(self, mib_text=None):
        self.objs, self.tcs, self.oids = zbx_mib(mib_text)
        self.used_maps = set()
        self.keys = set()

    def oid(self, name):
        return '.'.join(str(x) for x in self.oids[name])

    def mapname(self, obj):
        syn = self.objs[obj]['syntax'].split(' ')[0]
        if syn in self.tcs:
            m = 'ACME-MIB::' + syn
        else:
            m = ZBX_OLD_TRUTH.get(obj)
        if m:
            self.used_maps.add(m)
        return m

    def describe(self, obj, more=''):
        o = self.objs[obj]
        words = o['desc']
        syn = o['syntax'].split(' ')[0]
        if syn in self.tcs:
            words += ' (' + ', '.join('%d %s' % kv for kv in sorted(self.tcs[syn].items())) + ')'
        return ('%s%s\nMIB: ACME-MIB::%s (%s)' % (words, ('\n' + more) if more else '', obj,
                                                 self.oid(obj))).strip()

    def fmt(self, name):
        """How Zabbix takes the value from the walk: text as UTF-8 (net-snmp says a string with
        a letter not of ASCII as a Hex-STRING), a number as it is."""
        return '1' if self.objs[name]['syntax'].startswith('DisplayString') else '0'

    def preprocessing(self, oid, value_type, extra):
        steps = [{'type': 'SNMP_WALK_VALUE',
                  'parameters': [oid, '1' if value_type in ('CHAR', 'TEXT') else '0']}]
        if extra.get('rate'):
            steps.append({'type': 'CHANGE_PER_SECOND', 'parameters': ['']})
        if extra.get('mult'):
            steps.append({'type': 'MULTIPLIER', 'parameters': [extra['mult']]})
        if not extra.get('rate') and not extra.get('nodiscard'):
            steps.append({'type': 'DISCARD_UNCHANGED_HEARTBEAT', 'parameters': [ZBX_HEARTBEAT]})
        return steps

    def key(self, k):
        if k in self.keys:
            raise ValueError('the key %s twice' % k)
        self.keys.add(k)
        return k


def _zbx_tags(*pairs):
    return [{'tag': t, 'value': v} for t, v in pairs]


def _zbx_item(z, obj, key, name, vtype, units, comp, extra, master):
    it = {'uuid': _zbx_uuid('item', key), 'name': name, 'type': 'DEPENDENT', 'key': z.key(key),
          'delay': '0', 'history': '90d' if vtype in ('FLOAT', 'UNSIGNED') else '30d',
          'value_type': vtype}
    if vtype in ('CHAR', 'TEXT'):
        it['trends'] = '0'
    if units:
        it['units'] = units
    it['description'] = z.describe(obj)
    m = extra.get('map') or z.mapname(obj)
    if m:
        it['valuemap'] = {'name': m}
    it['preprocessing'] = z.preprocessing(z.oid(obj) + '.0', vtype, extra)
    it['master_item'] = {'key': master}
    it['tags'] = _zbx_tags(('component', comp))
    return it


def _zbx_trigger(expr, name, priority, desc, opdata='', tags=(), deps=(), event='', manual=False,
                 recovery=''):
    t = {'uuid': _zbx_uuid('trigger', name, expr), 'expression': expr}
    if recovery:
        t['recovery_mode'] = 'RECOVERY_EXPRESSION'
        t['recovery_expression'] = recovery
    t['name'] = name
    if event:
        t['event_name'] = event
    if opdata:
        t['opdata'] = opdata
    t['priority'] = priority
    t['description'] = desc
    if manual:
        t['manual_close'] = 'YES'
    if deps:
        t['dependencies'] = [{'name': n, 'expression': e} for n, e in deps]
    t['tags'] = _zbx_tags(*tags) if tags else None
    return t


def zabbix_template(mib_text=None):
    """The template as Zabbix 7.0 exports it (a dict, before YAML)."""
    z = _Zbx(mib_text)
    H = ZBX_NAME

    def last(key, fn='last', arg=''):
        return '%s(/%s/%s%s)' % (fn, H, key, (',' + arg) if arg else '')
    items = []
    # the master walks of the node: acme's subtrees and the system group
    node_walk = 'walk[%s]' % ','.join(z.oid(n) for n in ZBX_NODE_WALK)
    items.append({'uuid': _zbx_uuid('item', 'acme.walk'), 'name': 'SNMP walk: the node',
                  'type': 'SNMP_AGENT', 'snmp_oid': node_walk, 'key': z.key('acme.walk'),
                  'delay': '{$ACME.INTERVAL}', 'history': '0', 'value_type': 'TEXT', 'trends': '0',
                  'description': 'One bulk walk of acme\'s objects of this node (ACME-MIB: '
                  'acmeInfo, acmeDatabase, the counts of the alerts and the certificates, '
                  'acmeDnsServer, the cluster, acmeSystem, acmeBackup, acmeSignIn, '
                  'acmeServices) - every item of the node is read from it.',
                  'tags': _zbx_tags(('component', 'raw'))})
    items.append({'uuid': _zbx_uuid('item', 'acme.walk.system'), 'name': 'SNMP walk: system',
                  'type': 'SNMP_AGENT', 'snmp_oid': 'walk[1.3.6.1.2.1.1]',
                  'key': z.key('acme.walk.system'), 'delay': '{$ACME.INTERVAL}', 'history': '0',
                  'value_type': 'TEXT', 'trends': '0',
                  'description': 'SNMPv2-MIB::system of the node\'s agent.',
                  'tags': _zbx_tags(('component', 'raw'))})
    for oid_tail, key, name, vtype, units, desc, extra in (
            ('1.0', 'acme.sys.descr', 'System description', 'CHAR', '', 'SNMPv2-MIB::sysDescr: '
             'acme, its version and the node.', {}),
            ('3.0', 'acme.sys.uptime', 'SNMP agent uptime', 'UNSIGNED', 'uptime',
             'SNMPv2-MIB::sysUpTime: since the agent (the daemon) started.',
             {'mult': '0.01', 'nodiscard': 1}),
            ('4.0', 'acme.sys.contact', 'System contact', 'CHAR', '', 'SNMPv2-MIB::sysContact '
             '(Settings, Monitoring).', {}),
            ('5.0', 'acme.sys.name', 'System name', 'CHAR', '', 'SNMPv2-MIB::sysName.', {}),
            ('6.0', 'acme.sys.location', 'System location', 'CHAR', '', 'SNMPv2-MIB::sysLocation '
             '(Settings, Monitoring).', {})):
        it = {'uuid': _zbx_uuid('item', key), 'name': name, 'type': 'DEPENDENT', 'key': z.key(key),
              'delay': '0', 'history': '30d' if vtype == 'CHAR' else '90d', 'value_type': vtype}
        if vtype == 'CHAR':
            it['trends'] = '0'
        if units:
            it['units'] = units
        it['description'] = desc + '\nOID: 1.3.6.1.2.1.1.' + oid_tail
        it['preprocessing'] = z.preprocessing('1.3.6.1.2.1.1.' + oid_tail, vtype, extra)
        it['master_item'] = {'key': 'acme.walk.system'}
        it['tags'] = _zbx_tags(('component', 'system'))
        items.append(it)
    by_key = {}
    for obj, key, name, vtype, units, comp, extra in ZBX_ITEMS:
        it = _zbx_item(z, obj, key, name, vtype, units, comp, extra, 'acme.walk')
        items.append(it)
        by_key[key] = it
    # calculated and internal items
    for key, name, formula, units, comp, desc in (
            ('acme.mem.util', 'Memory utilization',
             '100*last(//acme.mem.used)/last(//acme.mem.total)', '%', 'memory',
             'Memory used, of the whole.'),
            ('acme.cpu.load_per_core', 'Load average (5m) per core',
             'last(//acme.cpu.load5)/last(//acme.cpu.cores)', '', 'cpu',
             'The load of 5 minutes for each core.'),
            ('acme.certs.valid.pct', 'Certificates valid, of all',
             '100*last(//acme.certs.ok)/max(last(//acme.certs.total),1)', '%', 'certificate',
             'Certificates in the state ok, of all those kept.')):
        items.append({'uuid': _zbx_uuid('item', key), 'name': name, 'type': 'CALCULATED',
                      'key': z.key(key), 'delay': '{$ACME.INTERVAL}', 'value_type': 'FLOAT',
                      'units': units, 'params': formula, 'description': desc,
                      'tags': _zbx_tags(('component', comp))})
    items.append({'uuid': _zbx_uuid('item', 'zabbix[host,snmp,available]'),
                  'name': 'SNMP agent availability', 'type': 'INTERNAL',
                  'key': z.key('zabbix[host,snmp,available]'),
                  'description': 'Availability of the SNMP checks of the host (the icon in the '
                  'list of hosts): 0 not available, 1 available, 2 unknown.',
                  'valuemap': {'name': 'zabbix.host.available'},
                  'tags': _zbx_tags(('component', 'health'), ('component', 'snmp'))})
    z.used_maps.add('zabbix.host.available')
    # the traps (Settings, Monitoring, SNMPv3, the receivers)
    # no backslash anywhere: a trigger's strings would need each one doubled
    trap_rx = 'acmeAlertRaised|acmeAlertCleared|acmeTestTrap|8072[.]9999[.]9999[.]7[.]0[.][123]'
    items.append({'uuid': _zbx_uuid('item', 'acme.traps'), 'name': 'SNMP traps of acme',
                  'type': 'SNMP_TRAP', 'key': z.key('snmptrap["%s"]' % trap_rx),
                  'delay': '0', 'history': '30d', 'value_type': 'LOG', 'trends': '0',
                  'description': 'The traps of the node that sends the alerts: acmeAlertRaised '
                  '(something went wrong, or worse), acmeAlertCleared (it is right again) and '
                  'acmeTestTrap (Settings, Monitoring, Send a test trap) - each with '
                  'acmeTrapKey, acmeTrapLevel (bad, warn, ok, info), acmeTrapTitle, acmeTrapSaid '
                  'and acmeTrapNode. Needs snmptrapd and the Zabbix trap receiver '
                  '(docs/monitoring.md, Zabbix).',
                  'logtimefmt': 'hh:mm:sszyyyy/MM/dd',
                  'tags': _zbx_tags(('component', 'alerts'), ('component', 'snmp'))})
    items.append({'uuid': _zbx_uuid('item', 'snmptrap.fallback'), 'name': 'SNMP traps (fallback)',
                  'type': 'SNMP_TRAP', 'key': z.key('snmptrap.fallback'), 'delay': '0',
                  'history': '7d', 'value_type': 'LOG', 'trends': '0',
                  'description': 'Every trap of the host no other snmptrap item took.',
                  'logtimefmt': 'hh:mm:sszyyyy/MM/dd',
                  'tags': _zbx_tags(('component', 'snmp'))})
    # the alerts, as a list: the table walked and said in lines
    items.append({'uuid': _zbx_uuid('item', 'acme.walk.alerts'), 'name': 'SNMP walk: the alerts',
                  'type': 'SNMP_AGENT', 'snmp_oid': 'walk[%s]' % z.oid('acmeAlertTable'),
                  'key': z.key('acme.walk.alerts'), 'delay': '{$ACME.INTERVAL}', 'history': '0',
                  'value_type': 'TEXT', 'trends': '0',
                  'description': 'acmeAlertTable: each thing the alerts see wrong now.',
                  'tags': _zbx_tags(('component', 'raw'))})
    items.append({'uuid': _zbx_uuid('item', 'acme.alerts.list'), 'name': 'Alerts now',
                  'type': 'DEPENDENT', 'key': z.key('acme.alerts.list'), 'delay': '0',
                  'history': '30d', 'value_type': 'TEXT', 'trends': '0',
                  'description': 'What the alerts see wrong now, one a line: the level, the node '
                  'and the title - as the mails of the alerts say it. Empty: nothing.',
                  'preprocessing': [
                      {'type': 'SNMP_WALK_TO_JSON', 'parameters': [
                          '{#LEVEL}', z.oid('acmeAlertLevel'), '1',
                          '{#NODE}', z.oid('acmeAlertNode'), '1',
                          '{#TITLE}', z.oid('acmeAlertTitle'), '1'],
                       'error_handler': 'CUSTOM_VALUE', 'error_handler_params': '[]'},
                      {'type': 'JAVASCRIPT', 'parameters': [
                          "var rows = JSON.parse(value), out = [];\n"
                          "rows.sort(function (a, b) { return a['{#LEVEL}'] === b['{#LEVEL}'] ? 0 : "
                          "(a['{#LEVEL}'] === 'bad' ? -1 : 1); });\n"
                          "for (var i = 0; i < rows.length; i++) {\n"
                          "    var r = rows[i];\n"
                          "    out.push(r['{#LEVEL}'] + ': ' + (r['{#NODE}'] ? r['{#NODE}'] + ': ' : '') "
                          "+ r['{#TITLE}']);\n"
                          "}\n"
                          "return out.join('\\n');"]},
                      {'type': 'DISCARD_UNCHANGED_HEARTBEAT', 'parameters': [ZBX_HEARTBEAT]}],
                  'master_item': {'key': 'acme.walk.alerts'},
                  'tags': _zbx_tags(('component', 'alerts'))})

    # ---- the triggers of the node, each on its item -------------------------------------
    T = []

    def trig(key, expr, name, prio, desc, opdata='{ITEM.LASTVALUE1}', tags=(), deps=(), event='',
             manual=False, recovery=''):
        t = _zbx_trigger(expr, 'acme: ' + name, prio, desc, opdata, tags, deps, event, manual,
                         recovery)
        if key and key in by_key:
            by_key[key].setdefault('triggers', []).append(t)
        else:
            T.append(t)
        return ('acme: ' + name, expr)
    trig('acme.db.up', last('acme.db.up') + '=0', 'The database does not answer', 'DISASTER',
         'SELECT 1 failed on this node: nothing is renewed, deployed or signed in here.',
         tags=(('scope', 'availability'),))
    trig('acme.db.latency', 'min(/%s/acme.db.latency,5m)>{$ACME.DB.LATENCY.MAX}' % H,
         'The database is slow', 'WARNING', 'SELECT 1 took longer than {$ACME.DB.LATENCY.MAX} s '
         'for 5 minutes.', tags=(('scope', 'performance'),))
    trig('acme.db.trouble', 'length(%s)>0' % last('acme.db.trouble'),
         'The daemon lost the database lately', 'HIGH', 'The daemon was without its database in '
         'the last 5 minutes.', tags=(('scope', 'availability'),))
    trig('acme.db.guard.refused', last('acme.db.guard.refused') + '>0',
         'Rows of the database not written by acme refused', 'HIGH', 'The guard of the database '
         'refused rows in the last hour - another server writes into acme\'s database.',
         tags=(('scope', 'security'),))
    bad = trig('acme.alerts.worst', last('acme.alerts.worst') + '=3', 'Alerts: something is bad',
               'HIGH', 'The alerts of acme see something bad (acmeAlertTable; the list in the '
               'item "Alerts now"). The same as the mails of the alerts and the traps.',
               opdata='{ITEM.LASTVALUE1}', tags=(('scope', 'notice'),))
    trig('acme.alerts.worst', last('acme.alerts.worst') + '=2', 'Alerts: a warning', 'WARNING',
         'The alerts of acme see something to look at (the item "Alerts now").',
         tags=(('scope', 'notice'),), deps=(bad,))
    trig('acme.version.update', last('acme.version.update') + '=1',
         'A newer version of acme is available', 'INFO', 'acme {ITEM.LASTVALUE2} is offered '
         '(Maintenance, Upgrade); this node runs {ITEM.LASTVALUE3}.',
         opdata='', tags=(('scope', 'notice'),),
         event='acme: version {ITEM.LASTVALUE2} is available')
    # the expression above names only the first item; the newest and this version for the words
    by_key['acme.version.update']['triggers'][-1]['expression'] = '%s=1 and length(%s)>0 and ' \
        'length(%s)>0' % (last('acme.version.update'), last('acme.version.newest'),
                          last('acme.version'))
    trig('acme.maintenance', last('acme.maintenance') + '=1', 'The node is in maintenance',
         'INFO', 'The node is in maintenance (Maintenance): its work is done by the other one.',
         tags=(('scope', 'notice'),))
    trig(None, 'last(/%s/acme.sys.uptime)<10m' % H, 'The daemon has been restarted', 'INFO',
         'The agent (the daemon) started less than 10 minutes ago.',
         tags=(('scope', 'notice'),), manual=True,
         event='acme: {HOST.NAME} has been restarted (uptime < 10m)')
    trig(None, 'max(/%s/zabbix[host,snmp,available],{$SNMP.TIMEOUT})=0' % H,
         'No SNMP data collection', 'WARNING', 'The agent of acme does not answer: SNMPv3 off, '
         'the user or a passphrase not the one set, the address not among the managers\' '
         '(Settings, Monitoring), or the node down.', tags=(('scope', 'availability'),))
    trig('acme.jobs.failed', last('acme.jobs.failed') + '>0', 'Certificate jobs failed in the '
         'last 24 hours', 'INFO', 'Renewals, issues or deployments failed in the last 24 hours '
         '(Certificates, Jobs).', tags=(('scope', 'notice'),))
    trig('acme.dns.up', '%s=0 and %s=1' % (last('acme.dns.up'), last('acme.dns.on')),
         'acme\'s DNS server does not answer', 'HIGH', 'The DNS server of acme is switched on, '
         'but does not answer on this node: dns-01 validations through it fail.',
         tags=(('scope', 'availability'),))
    trig('acme.vip.holders', '%s<>1 and length(%s)>0' % (last('acme.vip.holders'),
                                                       last('acme.vip.address')),
         'The VIP address is not held by one node', 'HIGH', 'The VIP address is held by '
         '{ITEM.LASTVALUE1} nodes: 0 - the pages do not answer at it; 2 - both hold it.',
         tags=(('scope', 'availability'),))
    lost = trig('acme.repl.state', last('acme.repl.state') + '=3', 'Replication lost',
                'DISASTER', 'A slot of the replication is lost: the other node has to be made '
                'again from this one (High availability).', tags=(('scope', 'availability'),))
    trig('acme.repl.state', last('acme.repl.state') + '=2', 'Replication broken', 'HIGH',
         'A way of the replication between the nodes does not run.', deps=(lost,),
         tags=(('scope', 'availability'),))
    # Neither the subscription nor the slot there (1.0.115): down(4), as the pages say it.
    trig('acme.repl.state', last('acme.repl.state') + '=4', 'Replication down', 'HIGH',
         'The nodes are replicated, but neither the subscription nor the slot of the '
         'replication is there: changes on one node do not reach the other (High '
         'availability).', tags=(('scope', 'availability'),))
    trig('acme.repl.behind', 'min(/%s/acme.repl.behind,10m)>{$ACME.REPL.BEHIND.MAX}' % H,
         'Replication behind', 'WARNING', 'The other node is behind in taking this node\'s rows '
         'for 10 minutes.', tags=(('scope', 'performance'),))
    trig('acme.split.state', last('acme.split.state') + '=2', 'The nodes are apart (split)',
         'HIGH', 'The two nodes do not reach each other: the split-brain guard decides what each '
         'does ({ITEM.LASTVALUE2}).', opdata='{ITEM.LASTVALUE2}',
         tags=(('scope', 'availability'),))
    by_key['acme.split.state']['triggers'][-1]['expression'] = '%s=2 and length(%s)>=0' % (
        last('acme.split.state'), last('acme.split.role'))
    trig('acme.cpu.util', 'min(/%s/acme.cpu.util,5m)>{$ACME.CPU.UTIL.CRIT}' % H,
         'High CPU utilization', 'WARNING', 'The processors are busier than '
         '{$ACME.CPU.UTIL.CRIT}% for 5 minutes.', tags=(('scope', 'performance'),))
    trig(None, 'min(/%s/acme.mem.util,5m)>{$ACME.MEM.UTIL.MAX}' % H, 'High memory utilization',
         'WARNING', 'More than {$ACME.MEM.UTIL.MAX}% of the memory used for 5 minutes.',
         tags=(('scope', 'capacity'),))
    trig(None, 'min(/%s/acme.cpu.load_per_core,5m)>{$ACME.LOAD.PER.CPU.MAX}' % H,
         'Load average is too high', 'WARNING', 'The load of 5 minutes per core is above '
         '{$ACME.LOAD.PER.CPU.MAX} for 5 minutes.', tags=(('scope', 'performance'),))
    trig('acme.clock.sync', last('acme.clock.sync') + '=2', 'The clock is not in sync', 'HIGH',
         'The clock is not kept in time ({ITEM.LASTVALUE2}): the dates of the certificates and '
         'the codes of the app are worked out from it.', opdata='{ITEM.LASTVALUE2}',
         tags=(('scope', 'notice'),))
    by_key['acme.clock.sync']['triggers'][-1]['expression'] = '%s=2 and length(%s)>=0' % (
        last('acme.clock.sync'), last('acme.clock.problem'))
    trig('acme.clock.offset', 'abs(%s)>{$ACME.CLOCK.OFFSET.MAX}' % last('acme.clock.offset'),
         'The clock is off', 'WARNING', 'The clock is more than {$ACME.CLOCK.OFFSET.MAX} s from '
         'its NTP reference.', tags=(('scope', 'notice'),))
    trig('acme.os.security', last('acme.os.security') + '>0', 'Security updates are waiting',
         'WARNING', '{ITEM.LASTVALUE1} security update(s) of the system wait (Settings, System '
         'updates).', tags=(('scope', 'security'),))
    trig('acme.os.reboot', last('acme.os.reboot') + '=1', 'A restart is needed', 'INFO',
         'A new kernel or libraries come into use only after a restart.',
         tags=(('scope', 'notice'),))
    trig('acme.key.lost', last('acme.key.lost') + '=1', 'The key of the sealed secrets is missing',
         'DISASTER', 'The key that opens the sealed secrets is not on this node: nothing sealed '
         'can be read here.', tags=(('scope', 'security'),))
    trig('acme.name.clash', 'length(%s)>0' % last('acme.name.clash'),
         'Another machine answers to the name of this node', 'HIGH', '{ITEM.LASTVALUE1}',
         tags=(('scope', 'availability'),))
    trig('acme.hand', last('acme.hand') + '>0', 'Something waits to be done by hand', 'WARNING',
         'Settings, Things to do by hand: a command after an update, SELinux switched off...',
         tags=(('scope', 'notice'),))
    trig('acme.selinux', '%s>=2 and %s<=3' % (last('acme.selinux'), last('acme.selinux')),
         'SELinux is not enforcing', 'INFO', 'SELinux on the node is {ITEM.LASTVALUE1} '
         '(Settings, SELinux).', tags=(('scope', 'security'),))
    trig('acme.backup.age', '%s>{$ACME.BACKUP.AGE.MAX} and %s=1' % (last('acme.backup.age'),
                                                                   last('acme.backup.daily')),
         'No recent backup', 'WARNING', 'The newest backup kept on the node is older than '
         '{$ACME.BACKUP.AGE.MAX}, and a backup should be made every night.',
         tags=(('scope', 'notice'),))
    trig('acme.rbackup.result', last('acme.rbackup.result') + '=2',
         'The last backup sent away failed', 'HIGH', '{ITEM.LASTVALUE2}',
         opdata='{ITEM.LASTVALUE2}', tags=(('scope', 'notice'),))
    by_key['acme.rbackup.result']['triggers'][-1]['expression'] = '%s=2 and length(%s)>=0' % (
        last('acme.rbackup.result'), last('acme.rbackup.error'))
    trig('acme.rbackup.last_ok', '%s=1 and now()-%s>{$ACME.RBACKUP.AGE.MAX}' % (
        last('acme.rbackup.on'), last('acme.rbackup.last_ok')), 'No good backup went away lately',
         'WARNING', 'Backups are sent away, but none went through for {$ACME.RBACKUP.AGE.MAX}.',
         opdata='{ITEM.LASTVALUE2}', tags=(('scope', 'notice'),))
    trig('acme.backup.verify', last('acme.backup.verify') + '=2',
         'A backup cannot be put back', 'HIGH', 'The last try of putting a backup back (without '
         'putting it back) failed.', tags=(('scope', 'notice'),))
    trig('acme.lockouts', last('acme.lockouts') + '>0', 'Sign-ins held back', 'INFO',
         '{ITEM.LASTVALUE1} address(es) or name(s) are locked out after wrong sign-ins (Settings, '
         'Lockouts).', tags=(('scope', 'security'),))
    trig('acme.kerberos.keytab', '%s=1 and %s=0' % (last('acme.kerberos'),
                                                   last('acme.kerberos.keytab')),
         'The keytab is not written out', 'HIGH', 'Signing in with Windows is on, but its keytab '
         'is not written on this node: {ITEM.LASTVALUE3}', opdata='{ITEM.LASTVALUE3}',
         tags=(('scope', 'availability'),))
    by_key['acme.kerberos.keytab']['triggers'][-1]['expression'] += \
        ' and length(%s)>=0' % last('acme.kerberos.error')
    trig('acme.certlogin.listening', '%s=1 and %s=0' % (last('acme.certlogin'),
                                                       last('acme.certlogin.listening')),
         'The port of the sign-in with a certificate is not open', 'HIGH',
         'Signing in with a certificate is on, but its port is not open on this node.',
         tags=(('scope', 'availability'),))
    trig('acme.dirs.down', last('acme.dirs.down') + '>0', 'A directory does not answer', 'HIGH',
         'None of the servers of {ITEM.LASTVALUE1} directory(ies) answers this node: '
         'administrators from it cannot sign in.', tags=(('scope', 'availability'),))
    trig('acme.mail.failed', last('acme.mail.failed') + '>0', 'Mails do not go', 'WARNING',
         '{ITEM.LASTVALUE1} mail(s) failed or ran out (Settings, Mail queue).',
         tags=(('scope', 'notice'),))
    trig('acme.sms.fails', last('acme.sms.fails') + '>=3', 'The SMS gateway does not send', 'HIGH',
         '{ITEM.LASTVALUE1} SMS failed in a row on this node.', tags=(('scope', 'availability'),))
    trig('acme.logs.dropped', 'change(/%s/acme.logs.dropped)>0' % H, 'Log lines dropped',
         'WARNING', 'Lines meant for isemon or the syslog servers were dropped, their queue full.',
         tags=(('scope', 'notice'),))
    # the traps: each alert raised a problem of its own, closed by hand or by its "cleared"
    trap_key = 'snmptrap["%s"]' % trap_rx
    raised = 'acmeAlertRaised|9999[.]7[.]0[.]1([^0-9]|$)'
    trig(None, 'find(/%s/%s,,"regexp","%s")=1 and find(/%s/%s,,"regexp","[^a-z]bad([^a-z]|$)")=1'
         % (H, trap_key, raised, H, trap_key),
         'Trap: something went wrong', 'HIGH', 'acmeAlertRaised with the level bad - the node '
         'that sends the alerts says so. Closed by hand (the matching acmeAlertCleared comes as '
         'a trap of its own).', opdata='', manual=True,
         event='acme trap: {ITEM.VALUE}', tags=(('scope', 'notice'),))
    T[-1]['type'] = 'MULTIPLE'
    trig(None, 'find(/%s/%s,,"regexp","%s")=1 and find(/%s/%s,,"regexp","[^a-z]warn([^a-z]|$)")=1'
         % (H, trap_key, raised, H, trap_key),
         'Trap: a warning', 'WARNING', 'acmeAlertRaised with the level warn. Closed by hand.',
         opdata='', manual=True, event='acme trap: {ITEM.VALUE}', tags=(('scope', 'notice'),))
    T[-1]['type'] = 'MULTIPLE'
    trig(None, 'nodata(/%s/%s,{$ACME.TRAP.TEST.WINDOW})=0 and find(/%s/%s,,"regexp",'
         '"acmeTestTrap|9999[.]7[.]0[.]3([^0-9]|$)")=1' % (H, trap_key, H, trap_key),
         'Trap: the test trap came', 'INFO', 'The test trap (Settings, Monitoring, Send a test '
         'trap) arrived - the receiver works. It closes by itself.', opdata='',
         event='acme trap: a test trap arrived', tags=(('scope', 'notice'),))

    # ---- the discoveries ------------------------------------------------------------------
    rules = []
    for tb in ZBX_TABLES:
        rule, walk = _zbx_rule(z, tb, H)
        items.append(walk)
        rules.append(rule)

    # ---- graphs ---------------------------------------------------------------------------
    def g(name, keys, kind='NORMAL', extra=None, colors=None):
        out = {'uuid': _zbx_uuid('graph', name), 'name': 'acme: ' + name}
        if kind != 'NORMAL':
            out['type'] = kind
        out.update(extra or {})
        out['graph_items'] = []
        for i, k in enumerate(keys):
            gi = {}
            if i:
                gi['sortorder'] = str(i)
            if kind in ('NORMAL', 'STACKED'):
                gi['drawtype'] = 'GRADIENT_LINE' if kind == 'NORMAL' else 'FILLED_REGION'
            gi['color'] = colors[i] if colors else ZBX_PALETTE[i % len(ZBX_PALETTE)]
            gi['item'] = {'host': H, 'key': k}
            out['graph_items'].append(gi)
        return out
    # the colours of the states, as the dashboards have them
    ok_, blue_, red_, orange_, brown_, grey_ = ('43A047', '1E88E5', 'E53935', 'FF8F00', '6D4C41',
                                                '90A4AE')
    graphs = [
        g('CPU utilization', ['acme.cpu.util'], extra={'ymin_type_1': 'FIXED',
                                                       'ymax_type_1': 'FIXED'}),
        g('Load average', ['acme.cpu.load1', 'acme.cpu.load5', 'acme.cpu.load15']),
        g('Memory', ['acme.mem.used', 'acme.swap.used', 'acme.mem.total']),
        g('Disk I/O', ['acme.disk.read', 'acme.disk.written']),
        g('Network traffic', ['acme.net.in', 'acme.net.out']),
        # each certificate once (one expiring soon is valid too: not stacked on top of it)
        g('Certificates by state', ['acme.certs.ok', 'acme.certs.waiting', 'acme.certs.failed',
                                    'acme.certs.expired'], 'STACKED',
          extra={'show_triggers': 'NO'}, colors=(ok_, blue_, red_, brown_)),
        g('Certificate jobs (24 h)', ['acme.renewals.ok', 'acme.renewals.failed',
                                      'acme.deploys.ok24h', 'acme.deploys.failed24h',
                                      'acme.jobs.running'],
          extra={'show_triggers': 'NO'}, colors=(ok_, red_, blue_, orange_, grey_)),
        g('Deployments and tests', ['acme.deploys.total', 'acme.deploys.failed', 'acme.tests.total',
                                    'acme.tests.failed', 'acme.modules.failing'],
          extra={'show_triggers': 'NO'}, colors=(blue_, red_, ok_, orange_, '8E24AA')),
        g('Alerts', ['acme.alerts.bad', 'acme.alerts.warn'], 'STACKED'),
        g('Database latency', ['acme.db.latency']),
        g('Database size', ['acme.db.size']),
        g('Replication behind', ['acme.repl.behind']),
        g('SNMP agent requests', ['acme.snmp.asked', 'acme.snmp.answered']),
        g('DNS server', ['acme.dns.queries', 'acme.dns.answered', 'acme.dns.refused',
                         'acme.dns.failed', 'acme.dns.limited']),
        g('Sign-ins', ['acme.sessions', 'acme.lockouts', 'acme.signin.fails']),
        g('Mail queue', ['acme.mail.waiting', 'acme.mail.failed']),
        g('Certificates valid', ['acme.certs.ok', 'acme.certs.waiting', 'acme.certs.failed',
                                 'acme.certs.expired'], 'PIE', colors=(ok_, blue_, red_, brown_)),
    ]

    macros = []
    for m in ZBX_MACROS:
        row = {'macro': m[0], 'value': m[1]}
        if len(m) > 3:
            row['type'] = m[3]
        row['description'] = m[2]
        macros.append(row)
    macros.append({'macro': '{$ACME.TRAP.TEST.WINDOW}', 'value': '10m',
                   'description': 'For how long the problem "the test trap came" stays open.'})

    valuemaps = []
    for name in sorted(z.used_maps):
        if name.startswith('ACME-MIB::'):
            mp = z.tcs[name.split('::', 1)[1]]
        else:
            mp = ZBX_MAPS_MORE[name]
        # the MIB's labels in words: pendingApproval -> pending approval
        valuemaps.append({'uuid': _zbx_uuid('valuemap', name), 'name': name,
                          'mappings': [{'value': str(k), 'newvalue': re.sub(
                              r'([a-z])([A-Z])', r'\1 \2', str(v)).lower()
                              if name.startswith('ACME-MIB::') else str(v)}
                              for k, v in sorted(mp.items())]})

    tpl = {'uuid': _zbx_uuid('template', H), 'template': H, 'name': H,
           'description': ZBX_DESCRIPTION.strip() % {'version': __version__},
           'vendor': {'name': 'acme', 'version': ZBX_VENDOR_VERSION},
           'groups': [{'name': ZBX_GROUP}],
           'items': items, 'discovery_rules': rules,
           'tags': _zbx_tags(('class', 'application'), ('target', 'acme')),
           'macros': macros, 'dashboards': zbx_dashboards(H), 'valuemaps': valuemaps}
    return {'zabbix_export': {'version': '7.0',
                              'template_groups': [{'uuid': _zbx_uuid('group', ZBX_GROUP),
                                                   'name': ZBX_GROUP}],
                              'templates': [tpl], 'triggers': T, 'graphs': graphs}}


ZBX_DESCRIPTION = '''
acme - certificates kept, renewed and deployed: each node, by its own SNMPv3 agent (ACME-MIB).

Made by acme %(version)s from the ACME-MIB it answers by (Settings, Monitoring, SNMPv3: the
"Zabbix 7 template" button, or acme --snmp-zabbix-template). Link it to each node of acme, by the
node's own address (not the VIP address).

The host's SNMP interface: SNMPv3, authPriv, the security name, the authentication (SHA-1,
SHA-256 or SHA-512) and privacy (AES-128 or AES-256) protocols and passphrases set in Settings,
Monitoring - the macros {$ACME.SNMP.USER}, {$ACME.SNMP.AUTHPASS} and {$ACME.SNMP.PRIVPASS} can
hold them. acme answers no SNMPv1 or v2c.

What it does: one bulk walk of the node every {$ACME.INTERVAL}, one of each table every
{$ACME.INTERVAL.TABLES}; the certificates, deployments, tests, modules, authorities, the
certificates of the pages, the nodes, the file systems, the places backups go, the CRLs and the
destinations of the logs discovered, with their triggers and graphs; the alerts of acme as
problems; the traps of acme (snmptrapd and the Zabbix trap receiver); dashboards.

docs/monitoring.md, Zabbix.
'''


def _zbx_rule(z, tb, H):
    """One discovery: its master walk, the rule, its item, trigger and graph prototypes."""
    cols = [m[1] for m in tb['macros']] + [x[0] for x in tb['items']]
    seen = []
    for c in cols:
        if c not in seen:
            seen.append(c)
    master = 'acme.walk.%s' % tb['id']
    # The columns named one by one - or the whole row (the table's entry) where they do not fit
    # in Zabbix's snmp_oid of 512 characters (the certificates: 948 - configuration.import
    # refused the template, "value is too long", on a real Zabbix 7.0.32).
    oid = 'walk[%s]' % ','.join(z.oid(c) for c in seen)
    if len(oid) > 512:
        oid = 'walk[%s]' % z.oid(tb['table'].replace('Table', 'Entry'))
    walk = {'uuid': _zbx_uuid('item', master), 'name': 'SNMP walk: %s' % tb['what'].lower(),
            'type': 'SNMP_AGENT', 'snmp_oid': oid, 'key': z.key(master), 'delay': tb['delay'],
            'history': '0', 'value_type': 'TEXT', 'trends': '0',
            'description': 'ACME-MIB::%s, the columns the discovery and its items need, in one '
            'bulk walk.' % tb['table'], 'tags': _zbx_tags(('component', 'raw'))}
    params = []
    for macro, col in tb['macros']:
        params += [macro, z.oid(col), z.fmt(col)]
    protos = []
    gp = []
    trig = []
    by = {}
    for col, part, name, vtype, units, extra in tb['items']:
        key = 'acme.%s.%s[%s]' % (tb['id'], part, tb['key'])
        it = {'uuid': _zbx_uuid('item_prototype', key), 'name': '%s: %s' % (tb['label'], name),
              'type': 'DEPENDENT', 'key': z.key(key), 'delay': '0',
              'history': '90d' if vtype in ('FLOAT', 'UNSIGNED') else '30d', 'value_type': vtype}
        if vtype in ('CHAR', 'TEXT'):
            it['trends'] = '0'
        if units:
            it['units'] = units
        it['description'] = z.describe(col)
        m = z.mapname(col)
        if m:
            it['valuemap'] = {'name': m}
        it['preprocessing'] = z.preprocessing(z.oid(col) + '.{#SNMPINDEX}', vtype, extra)
        it['master_item'] = {'key': master}
        it['tags'] = _zbx_tags(('component', tb['component']), *tb['tags'])
        protos.append(it)
        by[part] = it

    def lst(part, fn='last', arg=''):
        return '%s(/%s/%s%s)' % (fn, H, by[part]['key'], (',' + arg) if arg else '')

    def tp(part, expr, name, prio, desc, opdata='{ITEM.LASTVALUE1}', deps=(), scope='notice',
           manual=False):
        t = _zbx_trigger(expr, 'acme: ' + name, prio, desc, opdata, (('scope', scope),), deps,
                         manual=manual)
        if part:
            by[part].setdefault('trigger_prototypes', []).append(t)
        else:
            trig.append(t)
        return ('acme: ' + name, expr)
    i = tb['id']
    if i == 'cert':
        ctx = '"{#CERT.NAME}"'
        # Three ranges that do not overlap - not triggers depending on each other: one that
        # depends on a problem is not evaluated, and its first evaluation (the end of the
        # certificate not read yet) stayed "unknown" (seen on a real Zabbix 7.0.32).
        tp('days', '%s<0 and %s>0' % (lst('days'), lst('not_after')),
           'Certificate {#CERT.NAME} has expired', 'DISASTER',
           'The certificate {#CERT.NAME} ({#CERT.CN}) has expired (days left: '
           '{ITEM.LASTVALUE1}) - whatever uses it is refused.', scope='availability')
        tp('days', '%s>=0 and %s<{$ACME.CERT.CRIT:%s} and %s>0' % (
            lst('days'), lst('days'), ctx, lst('not_after')),
           'Certificate {#CERT.NAME} expires in less than {$ACME.CERT.CRIT:%s} days' % ctx,
           'HIGH', 'The certificate {#CERT.NAME} ({#CERT.CN}, from {#CERT.ISSUER}) ends in '
           '{ITEM.LASTVALUE1}. It renews itself when "renewed by itself" is on - look at '
           'its last error.')
        tp('days', '%s>={$ACME.CERT.CRIT:%s} and %s<{$ACME.CERT.WARN:%s} and %s>0' % (
            lst('days'), ctx, lst('days'), ctx, lst('not_after')),
           'Certificate {#CERT.NAME} expires in less than {$ACME.CERT.WARN:%s} days' % ctx,
           'WARNING', 'The certificate {#CERT.NAME} ({#CERT.CN}) ends in {ITEM.LASTVALUE1}.')
        tp('state', '%s=4 and length(%s)>=0' % (lst('state'), lst('error')),
           'Certificate {#CERT.NAME}: renewal failed', 'HIGH',
           'Renewing {#CERT.NAME} failed: {ITEM.LASTVALUE2}', opdata='{ITEM.LASTVALUE2}')
        tp('state', '%s=9' % lst('state'), 'Certificate {#CERT.NAME}: revocation failed',
           'AVERAGE', 'Revoking {#CERT.NAME} failed.')
        tp('state', '%s=11' % lst('state'), 'Certificate {#CERT.NAME} waits for an approval',
           'INFO', 'A request for {#CERT.NAME} waits for an approval (Certificates).')
        alt = tp('alt_days', '%s<{$ACME.CERT.CRIT:%s}' % (lst('alt_days'), ctx),
                 'Certificate {#CERT.NAME}: the twin ({#CERT.KEYTYPE.ALT}) expires in less than '
                 '{$ACME.CERT.CRIT:%s} days' % ctx, 'HIGH',
                 'The twin of the dual certificate {#CERT.NAME} ends in {ITEM.LASTVALUE1}.')
        tp('alt_days', '%s<{$ACME.CERT.WARN:%s}' % (lst('alt_days'), ctx),
           'Certificate {#CERT.NAME}: the twin ({#CERT.KEYTYPE.ALT}) expires in less than '
           '{$ACME.CERT.WARN:%s} days' % ctx, 'WARNING',
           'The twin of the dual certificate {#CERT.NAME} ends in {ITEM.LASTVALUE1}.', deps=(alt,))
        gp.append(('Certificate {#CERT.NAME}: days left', ['days', 'alt_days']))
        gp.append(('Certificate {#CERT.NAME}: failures', ['fails', 'deploys_failed',
                                                          'tests_failed']))
    elif i == 'deploy':
        tp('state', '%s=4 and length(%s)>=0' % (lst('state'), lst('error')),
           'Deployment of {#DEPLOY.CERT} to {#DEPLOY.TARGET} failed', 'HIGH',
           'Putting {#DEPLOY.CERT} on {#DEPLOY.TARGET} failed: {ITEM.LASTVALUE2}',
           opdata='{ITEM.LASTVALUE2}')
        tp('state', 'min(%s,1d)=2' % ('/%s/%s' % (H, by['state']['key'])),
           'Deployment of {#DEPLOY.CERT} to {#DEPLOY.TARGET} waits for a day', 'WARNING',
           'A newer version of {#DEPLOY.CERT} has been waiting to go to {#DEPLOY.TARGET} for a '
           'day.')
        gp.append(('Deployment {#DEPLOY.CERT} to {#DEPLOY.TARGET}: failures', ['fails']))
    elif i == 'test':
        tp('state', '%s>=3 and length(%s)>=0' % (lst('state'), lst('said')),
           'Test {#TEST.NAME} of {#TEST.CERT} fails', 'AVERAGE',
           'The test {#TEST.NAME} ({#TEST.KIND}) of {#TEST.CERT}: {ITEM.LASTVALUE1} - '
           '{ITEM.LASTVALUE2}', opdata='{ITEM.LASTVALUE1}: {ITEM.LASTVALUE2}')
        tp('state', '%s=2 and length(%s)>=0' % (lst('state'), lst('said')),
           'Test {#TEST.NAME} of {#TEST.CERT} warns', 'INFO',
           'The test {#TEST.NAME} ({#TEST.KIND}) of {#TEST.CERT} passes, with a warning: '
           '{ITEM.LASTVALUE2}', opdata='{ITEM.LASTVALUE2}')
        tp('last_at', '%s>0 and now()-%s>{$ACME.TEST.MAX.AGE}' % (lst('last_at'), lst('last_at')),
           'Test {#TEST.NAME} of {#TEST.CERT} has not run lately', 'INFO',
           'It last ran {ITEM.LASTVALUE1}.')
    elif i == 'module':
        tp('failing', '%s=1 and length(%s)>=0' % (lst('failing'), lst('error')),
           'Module {#MODULE.NAME} ({#MODULE.FAMILY}): its last use failed', 'INFO',
           'The {#MODULE.FAMILY} {#MODULE.NAME} ({#MODULE.KIND}): {ITEM.LASTVALUE2}',
           opdata='{ITEM.LASTVALUE2}')
    elif i == 'ca':
        crit = tp('days', '%s<{$ACME.CA.CRIT}' % lst('days'),
                  'Authority {#CA.NAME} expires in less than {$ACME.CA.CRIT} days', 'HIGH',
                  'The authority {#CA.NAME} ({#CA.SUBJECT}) ends in {ITEM.LASTVALUE1}: what it '
                  'signed ends with it.')
        tp('days', '%s<{$ACME.CA.WARN}' % lst('days'),
           'Authority {#CA.NAME} expires in less than {$ACME.CA.WARN} days', 'WARNING',
           'The authority {#CA.NAME} ({#CA.SUBJECT}) ends in {ITEM.LASTVALUE1}.', deps=(crit,))
        tp('crl_hours', '%s<0 and %s>0' % (lst('crl_hours'), lst('crl_next')),
           'Authority {#CA.NAME}: its CRL is late', 'HIGH',
           'The CRL of {#CA.NAME} is late (hours left: {ITEM.LASTVALUE1}) - certificates it signed are '
           'refused where revocation is checked.')
        gp.append(('Authority {#CA.NAME}: days left', ['days']))
    elif i == 'agent':
        tp('state', '%s=2' % lst('state'), 'The agent of {#AGENT.NAME} is not heard from',
           'WARNING', 'The acme-agent of the target {#AGENT.NAME} ({#AGENT.MODE}) has not been '
           'heard from for ten minutes: its deployments wait.')
        tp('state', '%s=3' % lst('state'), 'The agent of {#AGENT.NAME} is refused', 'AVERAGE',
           'acme refused the acme-agent of {#AGENT.NAME} - join it again (its card).')
        tp('days', '%s<7 and %s>0' % (lst('days'), lst('days')),
           'The certificate of the agent of {#AGENT.NAME} ends within 7 days', 'WARNING',
           'It is renewed over the channel 10 days before its end: the agent is not reached.')
        tp('blocked', '%s=1' % lst('blocked'),
           'The policy of the agent of {#AGENT.NAME} blocks a deployment', 'WARNING',
           'The server\'s policy refused the last deployment: Settings, Target agents and the '
           'deployment say what to allow (acme-agent allow ...).')
        tp('skew', 'abs(%s)>120' % lst('skew'),
           'The clock of the server of {#AGENT.NAME} is off by more than 120 s', 'WARNING',
           'Its agent refuses every job beyond 300 s: set the server\'s time right (NTP).',
           opdata='{ITEM.LASTVALUE1}')
        tp('reboot', '%s=1' % lst('reboot'), 'The server of {#AGENT.NAME} waits for a restart',
           'INFO', 'Its agent says a restart is pending (a newer kernel, Windows Update...).')
        tp('newer', '%s=1' % lst('newer'), 'A newer agent is offered for {#AGENT.NAME}', 'INFO',
           'acme ships a newer acme-agent: update it on the server (or from its card, where its '
           'policy allows self-update).')
    elif i == 'pages':
        crit = tp('days', '%s<{$ACME.PAGES.CRIT}' % lst('days'),
                  'The certificate of the pages of {#PAGES.TARGET} expires in less than '
                  '{$ACME.PAGES.CRIT} days', 'HIGH',
                  '{#PAGES.CN} ends in {ITEM.LASTVALUE1} (Settings, TLS).')
        tp('days', '%s<{$ACME.PAGES.WARN}' % lst('days'),
           'The certificate of the pages of {#PAGES.TARGET} expires in less than '
           '{$ACME.PAGES.WARN} days', 'WARNING', '{#PAGES.CN} ends in {ITEM.LASTVALUE1}.',
           deps=(crit,))
    elif i == 'node':
        tp('up', '%s=0' % lst('up'), 'Node {#NODE.NAME} is not heard from', 'HIGH',
           'The node {#NODE.NAME} last wrote its heartbeat {ITEM.LASTVALUE2} ago.',
           opdata='{ITEM.LASTVALUE2}', scope='availability')
        by['up']['trigger_prototypes'][-1]['expression'] += ' and %s>=0' % lst('age')
        tp('version', '%s<>%s' % (lst('version'), '(last(/%s/acme.version))' % H),
           'Node {#NODE.NAME} runs another version', 'WARNING',
           '{#NODE.NAME} runs {ITEM.LASTVALUE1}, this node {ITEM.LASTVALUE2} - finish the '
           'upgrade (Maintenance).', opdata='{ITEM.LASTVALUE1}')
        tp('vrrp', '%s=3' % lst('vrrp'), 'Node {#NODE.NAME}: keepalived in fault', 'AVERAGE',
           'keepalived on {#NODE.NAME} is in the FAULT state: it cannot take the VIP address.')
        gp.append(('Node {#NODE.NAME}: last heard from', ['age']))
    elif i == 'disk':
        ctx = '"{#DISK.PATH}"'
        crit = tp('pused', 'min(%s,5m)>{$ACME.DISK.PUSED.CRIT:%s}' % (
            '/%s/%s' % (H, by['pused']['key']), ctx),
            'FS [{#DISK.PATH}]: space is critically low', 'HIGH',
            '{#DISK.PATH} is {ITEM.LASTVALUE1} full - acme stops writing its backups and logs '
            'when it is full.', scope='capacity')
        tp('pused', 'min(%s,5m)>{$ACME.DISK.PUSED.WARN:%s}' % (
            '/%s/%s' % (H, by['pused']['key']), ctx), 'FS [{#DISK.PATH}]: space is low',
            'WARNING', '{#DISK.PATH} is {ITEM.LASTVALUE1} full.', deps=(crit,), scope='capacity')
        tp('iused', 'min(%s,5m)>{$ACME.DISK.PUSED.CRIT:%s}' % (
            '/%s/%s' % (H, by['iused']['key']), ctx),
            'FS [{#DISK.PATH}]: running out of inodes', 'HIGH',
            '{ITEM.LASTVALUE1} of the inodes of {#DISK.PATH} are used.', scope='capacity')
        gp.append(('FS [{#DISK.PATH}]: space', ['used', 'free'], 'PIE'))
        gp.append(('FS [{#DISK.PATH}]: utilization', ['pused', 'iused']))
    elif i == 'rbackup':
        tp('result', '%s=2 and length(%s)>=0' % (lst('result'), lst('error')),
           'Backup to {#RBACKUP.NAME} failed', 'HIGH', '{ITEM.LASTVALUE2}',
           opdata='{ITEM.LASTVALUE2}')
        tp('last_ok', 'now()-%s>{$ACME.RBACKUP.AGE.MAX}' % lst('last_ok'),
           'No good backup to {#RBACKUP.NAME} lately', 'WARNING',
           'The last good backup to {#RBACKUP.NAME} went {ITEM.LASTVALUE1}.')
    elif i == 'crl':
        tp('hours', '%s<0 and %s>0' % (lst('hours'), lst('next')), 'CRL {#CRL.URL} is out of date',
           'HIGH', 'Its next update is past (hours left: {ITEM.LASTVALUE1}) and no newer one could be '
           'fetched - certificates of its authority are refused at the sign-in.',
           scope='availability')
        tp('hours', '%s<{$ACME.CRL.HOURS.WARN} and %s>=0 and length(%s)>0' % (
            lst('hours'), lst('hours'), lst('error')), 'CRL {#CRL.URL} cannot be fetched',
            'WARNING', '{ITEM.LASTVALUE3}', opdata='{ITEM.LASTVALUE3}')
    elif i == 'ship':
        tp('trouble', '%s=1 and length(%s)>=0' % (lst('trouble'), lst('said')),
           'Logs do not reach {#SHIP.KIND} {#SHIP.TARGET}', 'WARNING', '{ITEM.LASTVALUE2}',
           opdata='{ITEM.LASTVALUE2}')
        gp.append(('Logs to {#SHIP.KIND} {#SHIP.TARGET}', ['sent']))
    graph_protos = []
    for spec in gp:
        name, parts = spec[0], spec[1]
        kind = spec[2] if len(spec) > 2 else 'NORMAL'
        gr = {'uuid': _zbx_uuid('graph_prototype', tb['id'], name), 'name': 'acme: ' + name}
        if kind != 'NORMAL':
            gr['type'] = kind
        gr['graph_items'] = []
        for k, part in enumerate(parts):
            gi = {}
            if k:
                gi['sortorder'] = str(k)
            if kind == 'NORMAL':
                gi['drawtype'] = 'GRADIENT_LINE'
            gi['color'] = ZBX_PALETTE[k % len(ZBX_PALETTE)]
            gi['item'] = {'host': H, 'key': by[part]['key']}
            gr['graph_items'].append(gi)
        graph_protos.append(gr)
    rule = {'uuid': _zbx_uuid('discovery_rule', tb['id']), 'name': tb['name'], 'type': 'DEPENDENT',
            'key': z.key('acme.%s.discovery' % tb['id']), 'delay': '0'}
    if tb['filter']:
        rule['filter'] = {'evaltype': 'AND', 'conditions': [
            dict({'macro': m, 'value': v}, **({'operator': op} if op != 'MATCHES_REGEX' else {}),
                 formulaid=chr(65 + n)) for n, (m, v, op) in enumerate(tb['filter'])]}
    rule['lifetime'] = '7d'
    rule['enabled_lifetime_type'] = 'DISABLE_NEVER'
    rule['description'] = 'ACME-MIB::%s - %s, each with its items, triggers and graphs.' % (
        tb['table'], tb['what'].lower())
    rule['item_prototypes'] = protos
    rule['trigger_prototypes'] = trig or None
    rule['graph_prototypes'] = graph_protos or None
    rule['master_item'] = {'key': master}
    rule['preprocessing'] = [
        {'type': 'SNMP_WALK_TO_JSON', 'parameters': params, 'error_handler': 'DISCARD_VALUE'},
        {'type': 'DISCARD_UNCHANGED_HEARTBEAT', 'parameters': [ZBX_HEARTBEAT]}]
    if tb['id'] == 'cert':
        rule['overrides'] = [{'name': 'Not dual: no twin', 'step': '1', 'filter': {
            'conditions': [{'macro': '{#CERT.KEYTYPE.ALT}', 'value': '.+',
                            'operator': 'NOT_MATCHES_REGEX', 'formulaid': 'A'}]},
            'operations': [{'operationobject': 'ITEM_PROTOTYPE', 'operator': 'LIKE',
                            'value': 'twin (dual)', 'discover': 'NO_DISCOVER'},
                           {'operationobject': 'TRIGGER_PROTOTYPE', 'operator': 'LIKE',
                            'value': 'the twin', 'discover': 'NO_DISCOVER'}]}]
    elif tb['id'] == 'node':
        rule['overrides'] = [{'name': 'This node: no "not heard from"', 'step': '1', 'filter': {
            'conditions': [{'macro': '{#NODE.THIS}', 'value': '^1$', 'formulaid': 'A'}]},
            'operations': [{'operationobject': 'TRIGGER_PROTOTYPE', 'operator': 'REGEXP',
                            'value': 'not heard from|another version', 'discover': 'NO_DISCOVER'}]}]
    return rule, walk


# ---- the dashboards ---------------------------------------------------------------------------
def _w_field(t, name, value):
    return {'type': t, 'name': name, 'value': value}


class _Page(object):
    def __init__(self, name):
        self.name = name
        self.widgets = []
        self.ref = 0

    def add(self, typ, name, x, y, w, h, fields, hide=False):
        self.widgets.append({'type': typ, 'name': name, 'x': str(x), 'y': str(y), 'width': str(w),
                             'height': str(h), 'hide_header': 'YES' if hide else None,
                             'fields': fields})

    def page(self, prefix):
        out = []
        for n, w in enumerate(self.widgets):
            w = dict(w)
            ref = ''
            k = n + prefix * 100
            for _ in range(5):
                ref = chr(65 + k % 26) + ref
                k //= 26
            w['fields'] = sorted(list(w['fields']) + [_w_field('STRING', 'reference', ref)],
                                 key=lambda f: f['name'])
            out.append({k2: v for k2, v in w.items() if v is not None})
        return {'name': self.name, 'widgets': out}


def zbx_dashboards(H):
    """One dashboard of six pages, the certificates first (looked at on a real Zabbix 7.0.32,
    1.0.109): Certificates; Deployments and tests; Authorities and CRLs; then the machine, the
    cluster and backups, sign-in and services. The tiles plain, red or orange only when there
    is something to see; the honeycombs coloured by days left or state; the problems of each
    page with their tags (the certificate, its owner and source, the target, the test)."""
    def item(key):
        return {'host': H, 'key': key}

    red, orange, amber, green, grey, blue = 'E53935', 'FF8F00', 'FFB300', '43A047', '90A4AE', '1E88E5'

    def tile(p, name, key, x, y, w=12, h=2, thresholds=(), dec=0, words=False):
        """A number with its name; plain, coloured by its thresholds ([(from, colour)]). Words
        (a mapped state, "no (0)", a name) smaller: at the size of a number they were cut."""
        f = [_w_field('ITEM', 'itemid.0', item(key)), _w_field('STRING', 'description', name),
             _w_field('INTEGER', 'desc_v_pos', '0'), _w_field('INTEGER', 'desc_size', '20'),
             _w_field('INTEGER', 'show.0', '1'), _w_field('INTEGER', 'show.1', '2'),
             _w_field('INTEGER', 'value_size', '28' if words else '42'), _w_field('INTEGER', 'units_size', '30'),
             _w_field('INTEGER', 'decimal_places', str(dec))]
        for n, (t, color) in enumerate(thresholds):
            f += [_w_field('STRING', 'thresholds.%d.color' % n, color),
                  _w_field('STRING', 'thresholds.%d.threshold' % n, t)]
        p.add('item', name, x, y, w, h, f, hide=True)

    def bad_if_any(color=red):
        return (('1', color),)

    def graph(p, name, x, y, w, h):
        p.add('graph', '', x, y, w, h, [_w_field('GRAPH', 'graphid.0',
                                                 {'host': H, 'name': 'acme: ' + name})])

    def honey(p, name, pattern, x, y, w, h, thresholds, label=r'{{ITEM.NAME}.regsub("^[^ ]+ (.*?):", "\1")}',
              mapped=False):
        """Each item of the pattern a cell: its name (the certificate, the deployment...) and
        its value. A state (mapped): the name alone, the colour says the state (a honeycomb
        shows a number, never the words of its value map) - the colours in the widget's name."""
        f = [_w_field('STRING', 'items.0', pattern), _w_field('STRING', 'primary_label', label),
             _w_field('INTEGER', 'primary_label_size_type', '1')]
        if mapped:
            f += [_w_field('INTEGER', 'show.0', '1'), _w_field('INTEGER', 'primary_label_size', '14'),
                  _w_field('INTEGER', 'primary_label_bold', '1')]
        else:
            f += [_w_field('INTEGER', 'primary_label_size', '20'),
                  _w_field('INTEGER', 'secondary_label_size_type', '1'),
                  _w_field('INTEGER', 'secondary_label_size', '26'),
                  _w_field('INTEGER', 'secondary_label_decimal_places', '0')]
        for n, (t, color) in enumerate(thresholds):
            f += [_w_field('STRING', 'thresholds.%d.color' % n, color),
                  _w_field('STRING', 'thresholds.%d.threshold' % n, t)]
        p.add('honeycomb', name, x, y, w, h, f)

    def problems(p, name, components, x, y, w, h, tags):
        """The problems of the host of these components, worst first, with these tags shown."""
        f = [_w_field('INTEGER', 'show', '3'), _w_field('INTEGER', 'evaltype', '0'),
             _w_field('INTEGER', 'show_tags', '3'), _w_field('INTEGER', 'tag_name_format', '0'),
             _w_field('STRING', 'tag_priority', ','.join(tags)),
             _w_field('INTEGER', 'show_opdata', '1'), _w_field('INTEGER', 'sort_triggers', '1'),
             _w_field('INTEGER', 'show_lines', '25')]
        for n, c in enumerate(components):
            f += [_w_field('STRING', 'tags.%d.tag' % n, 'component'),
                  _w_field('INTEGER', 'tags.%d.operator' % n, '1'),
                  _w_field('STRING', 'tags.%d.value' % n, c)]
        p.add('problems', name, x, y, w, h, f)

    def gauge(p, name, key, x, y, w=12, h=4, color='2774A4'):
        p.add('gauge', name, x, y, w, h, [
            _w_field('ITEM', 'itemid.0', item(key)), _w_field('STRING', 'description', name),
            _w_field('INTEGER', 'desc_v_pos', '0'), _w_field('INTEGER', 'desc_size', '12'),
            _w_field('STRING', 'value_arc_color', color),
            _w_field('STRING', 'min', '0'), _w_field('STRING', 'max', '100'),
            _w_field('INTEGER', 'decimal_places', '0'),
            _w_field('STRING', 'units', '%'), _w_field('INTEGER', 'show.0', '1'),
            _w_field('INTEGER', 'show.1', '2'), _w_field('INTEGER', 'show.2', '5'),
            _w_field('INTEGER', 'show.3', '4'),
            _w_field('STRING', 'thresholds.0.color', amber),
            _w_field('STRING', 'thresholds.0.threshold', '80'),
            _w_field('STRING', 'thresholds.1.color', red),
            _w_field('STRING', 'thresholds.1.threshold', '90')], hide=True)

    def pie(p, name, x, y, w, h, parts):
        f = [_w_field('INTEGER', 'ds.0.dataset_type', '0'),
             _w_field('STRING', 'ds.0.data_set_label', name)]
        for n, (k, col) in enumerate(parts):
            f += [_w_field('ITEM', 'ds.0.itemids.%d' % n, item(k)),
                  _w_field('STRING', 'ds.0.color.%d' % n, col),
                  _w_field('INTEGER', 'ds.0.type.%d' % n, '0')]
        f += [_w_field('INTEGER', 'draw_type', '1'), _w_field('INTEGER', 'width', '40'),
              _w_field('INTEGER', 'total_show', '1'), _w_field('INTEGER', 'decimal_places', '0'),
              _w_field('INTEGER', 'legend_lines', str(len(parts))),
              _w_field('INTEGER', 'legend_value', '1')]
        p.add('piechart', name, x, y, w, h, f)

    days = [('-100000', red), ('7', orange), ('30', green)]
    cert_states = [('0', blue), ('1', green), ('2', blue), ('4', red), ('5', red), ('6', blue),
                   ('7', grey), ('8', grey), ('9', orange), ('11', amber), ('12', grey), ('13', grey)]
    deploy_states = [('0', grey), ('1', green), ('2', amber), ('3', blue), ('4', red)]
    test_states = [('0', grey), ('1', green), ('2', amber), ('3', red)]

    # 1. Certificates: how many in each state, the days each has left, what is wrong with them
    c = _Page('Certificates')
    tile(c, 'Certificates', 'acme.certs.total', 0, 0)
    tile(c, 'Valid', 'acme.certs.ok', 12, 0)
    tile(c, 'Expiring soon', 'acme.certs.expiring', 24, 0, thresholds=bad_if_any(orange))
    tile(c, 'Expired', 'acme.certs.expired', 36, 0, thresholds=bad_if_any())
    tile(c, 'Renewal failed', 'acme.certs.failed', 48, 0, thresholds=bad_if_any())
    tile(c, 'Renewals failed (24 h)', 'acme.renewals.failed', 60, 0, thresholds=bad_if_any(orange))
    honey(c, 'Days left', 'Certificate *: days left', 0, 2, 36, 6, days)
    honey(c, 'State: green ok, blue renewing, amber to approve, red failed or expired, grey off',
          'Certificate *: state', 36, 2, 36, 6, cert_states, mapped=True)
    problems(c, 'Certificate problems', ['certificate'], 0, 8, 72, 5,
             ['cert', 'owner', 'issuer'])
    pie(c, 'Certificates by state', 0, 13, 24, 6, (
        ('acme.certs.ok', green), ('acme.certs.waiting', blue), ('acme.certs.failed', red),
        ('acme.certs.expired', '6D4C41'), ('acme.certs.revoked', grey)))
    graph(c, 'Certificates by state', 24, 13, 48, 6)
    # 2. Deployments and tests: where each certificate went, what the servers serve
    d = _Page('Deployments and tests')
    tile(d, 'Deployments', 'acme.deploys.total', 0, 0)
    tile(d, 'Deployments failed', 'acme.deploys.failed', 12, 0, thresholds=bad_if_any())
    tile(d, 'Deployed (24 h)', 'acme.deploys.ok24h', 24, 0)
    tile(d, 'Failed (24 h)', 'acme.deploys.failed24h', 36, 0, thresholds=bad_if_any(orange))
    tile(d, 'Tests', 'acme.tests.total', 48, 0)
    tile(d, 'Tests failing', 'acme.tests.failed', 60, 0, thresholds=bad_if_any())
    honey(d, 'Deployments: green ok, amber a newer version waits, blue deploying, red failed',
          'Deployment *: state', 0, 2, 72, 4, deploy_states, mapped=True,
          label=r'{{ITEM.NAME}.regsub("^Deployment (.*?) to (.*?):", "\1 > \2")}')
    honey(d, 'Tests: green ok, amber a warning, red failing, grey not run yet', 'Test *: result',
          0, 6, 72, 4, test_states, mapped=True,
          label=r'{{ITEM.NAME}.regsub("^Test (.*) of (.*?):", "\2: \1")}')
    problems(d, 'Deployment and test problems', ['deployment', 'test'], 0, 10, 72, 5,
             ['cert', 'deploy', 'test'])
    graph(d, 'Certificate jobs (24 h)', 0, 15, 36, 5)
    graph(d, 'Deployments and tests', 36, 15, 36, 5)
    honey(d, 'Sources, validations, targets and tests: red - its last use failed',
          'Module *: failing', 0, 20, 72, 3, [('0', green), ('1', red)],
          label=r'{{ITEM.NAME}.regsub("^Module (.*?):", "\1")}', mapped=True)
    # 3. Authorities and CRLs: acme's own authorities, the CRLs, the certificate of the pages
    a = _Page('Authorities and CRLs')
    tile(a, 'Authorities ending (90 d)', 'acme.cas.ending', 0, 0, thresholds=bad_if_any(orange))
    tile(a, 'Revoked', 'acme.certs.revoked', 12, 0)
    tile(a, 'Waiting for approval', 'acme.certs.approval', 24, 0, thresholds=bad_if_any(amber))
    tile(a, 'Certificate sign-in', 'acme.certlogin', 36, 0, words=True)
    tile(a, 'Its port open', 'acme.certlogin.listening', 48, 0, words=True)
    tile(a, 'Its authorities', 'acme.certlogin.cas', 60, 0)
    honey(a, 'Authorities: days left', 'Authority *: days left', 0, 2, 18, 4,
          [('-100000', red), ('30', orange), ('90', green)])
    honey(a, 'Authorities: hours to the next CRL', 'Authority *: CRL hours left', 18, 2, 18, 4,
          [('-100000', red), ('12', orange), ('24', green)])
    honey(a, 'CRLs of the sign-in: hours left', 'CRL *: hours left', 36, 2, 18, 4,
          [('-100000', red), ('12', orange), ('48', green)],
          label=r'{{ITEM.NAME}.regsub("/([^/]*): hours left$", "\1")}')
    honey(a, 'Pages of acme: days left', 'Pages of *: certificate days left', 54, 2, 18, 4, days)
    problems(a, 'Authority and CRL problems', ['authority', 'signin', 'web'], 0, 6, 72, 4,
             ['authority', 'crl', 'pages'])
    # 4. System
    s = _Page('System')
    tile(s, 'Version', 'acme.version', 0, 0, words=True)
    tile(s, 'Update available', 'acme.version.update', 12, 0, thresholds=bad_if_any(amber),
         words=True)
    tile(s, 'Alerts', 'acme.alerts.worst', 24, 0, thresholds=(('2', amber), ('3', red)),
         words=True)
    tile(s, 'Database', 'acme.db.up', 36, 0, words=True)
    tile(s, 'Daemon uptime', 'acme.uptime', 48, 0, words=True)
    tile(s, 'Security updates', 'acme.os.security', 60, 0, thresholds=bad_if_any(orange))
    gauge(s, 'CPU', 'acme.cpu.util', 0, 2, 12, 4)
    gauge(s, 'Memory', 'acme.mem.util', 12, 2, 12, 4, color='6C59DC')
    honey(s, 'File systems', 'FS *: space utilization', 24, 2, 24, 4,
          [('0', green), ('85', orange), ('95', red)],
          label=r'{{ITEM.NAME}.regsub("\[(.*?)\]", "\1")}')
    tile(s, 'Load (5m) per core', 'acme.cpu.load_per_core', 48, 2, 24, 2, dec=2)
    tile(s, 'Clock', 'acme.clock.sync', 48, 4, 24, 2, thresholds=(('2', red),), words=True)
    s.add('itemhistory', 'Alerts now', 0, 6, 72, 4, [
        _w_field('ITEM', 'columns.0.itemid', item('acme.alerts.list')),
        _w_field('STRING', 'columns.0.name', 'What the alerts of acme see'),
        _w_field('INTEGER', 'show_column_header', '0'),
        _w_field('INTEGER', 'show_lines', '1'), _w_field('INTEGER', 'show_timestamp', '1')])
    graph(s, 'CPU utilization', 0, 10, 36, 5)
    graph(s, 'Load average', 36, 10, 36, 5)
    graph(s, 'Memory', 0, 15, 36, 5)
    graph(s, 'Network traffic', 36, 15, 36, 5)
    graph(s, 'Disk I/O', 0, 20, 36, 5)
    graph(s, 'Database latency', 36, 20, 36, 5)
    # 5. Cluster and backups
    k = _Page('Cluster and backups')
    tile(k, 'Cluster', 'acme.ha.mode', 0, 0, words=True)
    tile(k, 'Nodes up', 'acme.nodes.up', 12, 0)
    tile(k, 'Replication', 'acme.repl.state', 24, 0, thresholds=(('2', red),), words=True)
    tile(k, 'Split', 'acme.split.state', 36, 0, thresholds=(('2', red),), words=True)
    tile(k, 'VIP address held by', 'acme.vip.owner', 48, 0, words=True)
    tile(k, 'Renewing node', 'acme.certs.leader.node', 60, 0, words=True)
    tile(k, 'Newest backup, age', 'acme.backup.age', 0, 2, words=True)
    tile(k, 'Backups kept here', 'acme.backup.kept', 12, 2)
    tile(k, 'Sent away', 'acme.rbackup.result', 24, 2, thresholds=(('2', red),), words=True)
    tile(k, 'Last good send', 'acme.rbackup.last_ok', 36, 2, words=True)
    tile(k, 'Backup tried', 'acme.backup.verify', 48, 2, thresholds=(('2', red),), words=True)
    tile(k, 'Database size', 'acme.db.size', 60, 2, dec=1)
    honey(k, 'Backup places: green ok, red failed', 'Backup to *: result', 0, 4, 24, 4,
          [('0', grey), ('1', green), ('2', red)], mapped=True,
          label=r'{{ITEM.NAME}.regsub("^Backup to (.*?):", "\1")}')
    honey(k, 'Nodes: red - not heard from', 'Node *: heard from', 24, 4, 24, 4,
          [('0', red), ('1', green)], mapped=True)
    graph(k, 'Replication behind', 48, 4, 24, 4)
    problems(k, 'Cluster and backup problems', ['cluster', 'backup', 'database'], 0, 8, 72, 4,
             ['place', 'node'])
    graph(k, 'Database size', 0, 12, 72, 4)
    # 6. Sign-in and services
    g = _Page('Sign-in and services')
    tile(g, 'Accounts', 'acme.accounts', 0, 0)
    tile(g, 'Sign-ins open', 'acme.sessions', 12, 0)
    tile(g, 'Locked out', 'acme.lockouts', 24, 0, thresholds=bad_if_any(orange))
    tile(g, 'Sign-in with Windows', 'acme.kerberos', 36, 0, words=True)
    tile(g, 'Mails waiting', 'acme.mail.waiting', 48, 0)
    tile(g, 'Mails failed', 'acme.mail.failed', 60, 0, thresholds=bad_if_any())
    honey(g, 'Logs: red - in trouble', 'Logs to *: in trouble', 0, 2, 24, 4,
          [('0', green), ('1', red)], mapped=True,
          label=r'{{ITEM.NAME}.regsub("^Logs to (.*?):", "\1")}')
    graph(g, 'Sign-ins', 24, 2, 24, 4)
    graph(g, 'Mail queue', 48, 2, 24, 4)
    problems(g, 'Sign-in and service problems', ['signin', 'logs', 'mail', 'directory', 'sms',
                                                 'dns'], 0, 6, 72, 4, ['crl', 'destination'])
    graph(g, 'DNS server', 0, 10, 36, 5)
    graph(g, 'SNMP agent requests', 36, 10, 36, 5)
    pages = [p.page(n) for n, p in enumerate((c, d, a, s, k, g))]
    return [{'uuid': _zbx_uuid('dashboard', 'acme'), 'name': 'acme', 'display_period': '60',
             'auto_start': 'NO', 'pages': pages}]


def zabbix_template_yaml(mib_text=None):
    return zbx_yaml(zabbix_template(mib_text)) + '\n'
