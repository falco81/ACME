#!/usr/bin/env python3
"""The SNMPv3 agent, ACME-MIB and the Zabbix 7.0 template made from it (1.0.108).

    python3 test/test_snmp.py          (or python3 -m unittest test.test_snmp)

No root, no network: a daemon is started in a folder of its own (as test_certs_core does) with
SNMPv3 on, on a port of its own on 127.0.0.1, the user and its passphrases in config.json. A
certificate is issued and deployed (and one deployment fails), then the agent is asked as a
manager asks it - by net-snmp's snmpwalk and snmpget when they are installed (apt-get install
snmp), by acme's own small manager when not: every object it answers is one of ACME-MIB, every
object of 1.0.108 is answered, the tables have their rows. The template: YAML that parses, every
UUID a UUIDv4 of its own, every key once, every OID it walks or reads one of ACME-MIB (and
answered by the agent), every value map, item, graph and macro it names there, every table of
the MIB discovered; the route on the SNMP page and the command line give the same file.
"""
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from acmelib import engine as E  # noqa: E402

try:
    import yaml
except ImportError:                                     # pragma: no cover
    yaml = None

BASE = '1.3.6.1.4.1.8072.9999.9999.7'
USER, AUTH_PASS, PRIV_PASS = 'zabbix', 'Auth-Pass-4711-xy', 'Priv-Pass-4711-xy'

FAKE_TARGET = r'''
from acmelib.plugins.base import Target, PluginError, field


class SnmpFake(Target):
    kind = 'snmpfake'
    title = 'Fake target (SNMP tests)'
    vendor = 'Test'
    fields = [field('fail', 'Fail', 'bool', default=False)]
    deploy_fields = [field('file', 'File', 'text')]

    def test(self):
        return 'answers'

    def deploy(self, bundle, options):
        if self.c('fail'):
            raise PluginError('the fake target said no')
        return 'put in place'
'''


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def mib_oids():
    objs, tcs, oids = E.zbx_mib()
    return objs, tcs, {'.'.join(map(str, v)): k for k, v in oids.items()}


class Template(unittest.TestCase):
    """The template alone: no daemon."""

    @classmethod
    def setUpClass(cls):
        cls.text = E.zabbix_template_yaml()
        cls.objs, cls.tcs, cls.by_oid = mib_oids()

    def setUp(self):
        if yaml is None:
            self.skipTest('PyYAML is not installed')
        self.data = yaml.safe_load(self.text)
        self.tpl = self.data['zabbix_export']['templates'][0]

    def every(self, node, key):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == key:
                    yield v
                yield from self.every(v, key)
        elif isinstance(node, list):
            for v in node:
                yield from self.every(v, key)

    def test_yaml_and_version(self):
        self.assertEqual(self.data['zabbix_export']['version'], '7.0')
        self.assertEqual(self.tpl['template'], 'acme by SNMP')
        # every scalar a string, as Zabbix's own exports have them
        for v in self.every(self.data, 'value_type'):
            self.assertIsInstance(v, str)
        self.assertTrue(self.text.endswith('\n'))
        # the same each time it is made
        self.assertEqual(E.zabbix_template_yaml(), self.text)

    def test_uuids(self):
        got = list(self.every(self.data, 'uuid'))
        self.assertGreater(len(got), 200)
        self.assertEqual(len(got), len(set(got)), 'a UUID twice')
        for u in got:
            self.assertRegex(u, r'^[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\Z', u)

    def test_keys_once(self):
        keys = [i['key'] for i in self.tpl['items']]
        for r in self.tpl['discovery_rules']:
            keys.append(r['key'])
            keys += [p['key'] for p in r['item_prototypes']]
            for p in r['item_prototypes']:
                self.assertIn('{#', p['key'], p['key'])
        self.assertEqual(len(keys), len(set(keys)), [k for k in keys if keys.count(k) > 1])

    def test_every_table_discovered(self):
        tables = sorted(n for n, o in self.objs.items() if n.endswith('Table'))
        walked = {}
        for i in self.tpl['items']:
            if i.get('snmp_oid', '').startswith('walk['):
                for o in i['snmp_oid'][5:-1].split(','):
                    walked[o] = i['key']
        rules = {r['master_item']['key'] for r in self.tpl['discovery_rules']}
        # each table but the samples of Prometheus (acmeMetricTable) and the alerts (said as
        # one item, "Alerts now") has a discovery whose walk reads it
        for t in tables:
            if t in ('acmeMetricTable', 'acmeAlertTable'):
                continue
            entry = self.objs[t]['oid'] + (1,)
            masters = {k for o, k in walked.items()
                       if tuple(map(int, o.split('.')))[:len(entry)] == entry}
            self.assertTrue(masters & rules, 'no discovery of %s' % t)
        self.assertEqual(len(self.tpl['discovery_rules']), 11)

    def test_every_oid_of_the_mib(self):
        n = 0
        for i in self.tpl['items']:
            if i.get('snmp_oid', '').startswith('walk['):
                for o in i['snmp_oid'][5:-1].split(','):
                    if o.startswith('1.3.6.1.2.1.1'):
                        continue
                    self.assertTrue(o in self.by_oid or o == BASE, o)
                    n += 1
        for step in self.every(self.data, 'preprocessing'):
            for s in step:
                if s['type'] == 'SNMP_WALK_VALUE':
                    o = re.sub(r'\.(0|\{#SNMPINDEX\})\Z', '', s['parameters'][0])
                    if not o.startswith('1.3.6.1.2.1.1'):
                        self.assertIn(o, self.by_oid, s)
                        n += 1
                elif s['type'] == 'SNMP_WALK_TO_JSON':
                    p = s['parameters']
                    self.assertEqual(len(p) % 3, 0)
                    for k in range(0, len(p), 3):
                        self.assertRegex(p[k], r'^\{#[A-Z0-9_.]+\}\Z')
                        self.assertIn(p[k + 1], self.by_oid)
                        n += 1
        self.assertGreater(n, 250)

    def test_references(self):
        maps = {m['name'] for m in self.tpl['valuemaps']}
        for v in self.every(self.data, 'valuemap'):
            self.assertIn(v['name'], maps)
        # every enumeration of the MIB has its map, with every value
        for tc, values in self.tcs.items():
            m = [x for x in self.tpl['valuemaps'] if x['name'] == 'ACME-MIB::' + tc]
            if m:
                self.assertEqual({int(x['value']) for x in m[0]['mappings']}, set(values))
        keys = {i['key'] for i in self.tpl['items']}
        protos = {p['key'] for r in self.tpl['discovery_rules'] for p in r['item_prototypes']}
        names = [i['name'] for i in self.tpl['items']] + \
            [p['name'] for r in self.tpl['discovery_rules'] for p in r['item_prototypes']]
        for i in self.tpl['items'] + [p for r in self.tpl['discovery_rules']
                                      for p in r['item_prototypes']]:
            if i.get('master_item'):
                self.assertIn(i['master_item']['key'], keys)
        for g in self.data['zabbix_export']['graphs']:
            for gi in g['graph_items']:
                self.assertIn(gi['item']['key'], keys, g['name'])
        for r in self.tpl['discovery_rules']:
            for g in r.get('graph_prototypes') or []:
                for gi in g['graph_items']:
                    self.assertIn(gi['item']['key'], protos, g['name'])
        # the expressions name only items there are, with the template's name
        exprs = list(self.every(self.data, 'expression')) + \
            list(self.every(self.data, 'recovery_expression'))
        self.assertGreater(len(exprs), 60)
        for e in exprs:
            for host, key in re.findall(r'/([^/]+)/([^,)]+?\]|[a-z0-9_.]+)(?=[,)])', e):
                self.assertEqual(host, 'acme by SNMP', e)
                self.assertTrue(key in keys or key in protos, '%s: %s' % (e, key))
        for f in self.every(self.data, 'params'):
            for key in re.findall(r'last\(//([a-z0-9_.]+)\)', f):
                self.assertIn(key, keys)
        # the macros used are there
        defined = {m['macro'] for m in self.tpl['macros']}
        used = set(re.findall(r'\{\$[A-Z0-9_.]+', self.text))
        for m in used:
            self.assertIn(m + '}', defined)
        # the dashboards: the items, graphs and patterns they show are there
        graphs = {g['name'] for g in self.data['zabbix_export']['graphs']}
        for d in self.tpl['dashboards']:
            self.assertGreaterEqual(len(d['pages']), 4)
            # the certificates first, then their deployments and tests (1.0.109)
            self.assertEqual([p['name'] for p in d['pages']][:3], [
                'Certificates', 'Deployments and tests', 'Authorities and CRLs'])
            for p in d['pages']:
                refs = []
                for w in p['widgets']:
                    self.assertIn(w['type'], ('item', 'graph', 'honeycomb', 'gauge', 'piechart',
                                              'itemhistory', 'svggraph', 'graphprototype',
                                              'problems'))
                    self.assertLessEqual(int(w['x']) + int(w['width']), 72, w)
                    refs += [f['value'] for f in w['fields'] if f['name'] == 'reference']
                    # a field's value fits in Zabbix's widget_field.value_str (255)
                    for f in w['fields']:
                        if isinstance(f['value'], str):
                            self.assertLessEqual(len(f['value']), 255, f)
                    for f in w['fields']:
                        if f['type'] == 'ITEM':
                            self.assertIn(f['value']['key'], keys)
                        elif f['type'] == 'GRAPH':
                            self.assertIn(f['value']['name'], graphs)
                        elif f['name'] == 'items.0':
                            rx = '^' + re.escape(f['value']).replace(r'\*', '.*') + '$'
                            self.assertTrue(any(re.match(rx, n) for n in names), f['value'])
                self.assertEqual(len(refs), len(set(refs)))

    def test_triggers_and_discoveries(self):
        rules = {r['key']: r for r in self.tpl['discovery_rules']}
        self.assertEqual(set(rules), {'acme.%s.discovery' % x for x in (
            'cert', 'deploy', 'test', 'module', 'ca', 'pages', 'node', 'disk', 'rbackup', 'crl',
            'ship')})
        certs = rules['acme.cert.discovery']
        names = [t['name'] for p in certs['item_prototypes'] for t in p.get('trigger_prototypes') or []]
        for want in ('has expired', 'expires in less than {$ACME.CERT.CRIT:"{#CERT.NAME}"} days',
                     'expires in less than {$ACME.CERT.WARN:"{#CERT.NAME}"} days',
                     'renewal failed'):
            self.assertTrue(any(want in n for n in names), want)
        # a failed deployment or test: a problem of its own, not one more of its certificate
        # (1.0.109, seen on a real Zabbix 7.0: the two said the same twice)
        for r, want in (('acme.deploy.discovery', 'Deployment of {#DEPLOY.CERT} to '
                                                  '{#DEPLOY.TARGET} failed'),
                        ('acme.test.discovery', 'Test {#TEST.NAME} of {#TEST.CERT} fails')):
            got = [t['name'] for p in rules[r]['item_prototypes']
                   for t in p.get('trigger_prototypes') or []]
            self.assertIn('acme: ' + want, got)
        self.assertFalse(any('deployment(s) failed' in n or 'test(s) failing' in n for n in names))
        # the walks fit in Zabbix's snmp_oid (512 characters)
        for i in self.tpl['items']:
            self.assertLessEqual(len(i.get('snmp_oid', '')), 512, i['key'])
        node = [t['name'] for i in self.tpl['items'] for t in i.get('triggers') or []] + \
            [t['name'] for t in self.data['zabbix_export']['triggers']]
        for want in ('The database does not answer', 'Replication lost', 'Replication behind',
                     'Replication down',
                     'The nodes are apart (split)', 'No recent backup', 'A newer version of acme',
                     'The keytab is not written out', 'Trap: something went wrong',
                     'No SNMP data collection', 'Security updates are waiting'):
            self.assertTrue(any(want in n for n in node), want)
        crl = [t['name'] for p in rules['acme.crl.discovery']['item_prototypes']
               for t in p.get('trigger_prototypes') or []]
        self.assertTrue(any('out of date' in n for n in crl))
        traps = [i for i in self.tpl['items'] if i['type'] == 'SNMP_TRAP']
        self.assertEqual(len(traps), 2)
        for i in self.tpl['items']:
            self.assertTrue(i.get('description'), i['key'])
            self.assertTrue(i.get('tags'), i['key'])


class Stable(unittest.TestCase):
    """1.0.115, no daemon: each table's rows numbered by what names them, not by their place;
    the node table's columns from one list; the age of a backup never made; the replication
    down."""

    def setUp(self):
        self.saved = {}

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(E, k, v)

    def patch(self, **kw):
        for k, v in kw.items():
            self.saved.setdefault(k, getattr(E, k))
            setattr(E, k, v)

    def test_index_by_name(self):
        a = E.snmp_index(['/', '/var', '/home'])
        b = E.snmp_index(['/home', '/'])                # /var gone, the order changed
        self.assertEqual(a['/'], b['/'])
        self.assertEqual(a['/home'], b['/home'])
        self.assertEqual(a['/'], __import__('zlib').crc32(b'/') % 65535 + 1)
        self.assertTrue(all(1 <= v <= 65535 for v in a.values()))
        # two on one number: each its own, the same on every walk
        c = E.snmp_index(['a', 'b', 'c'], 3)
        self.assertEqual(sorted(c.values()), [1, 2, 3])
        self.assertEqual(c, E.snmp_index(['c', 'b', 'a'], 3))
        big = E.snmp_index(['k%d' % i for i in range(3000)])
        self.assertEqual(len(set(big.values())), 3000)

    def rows(self, facts):
        self.patch(snmp_facts=lambda daemon, fresh=False: facts)
        return {sub: v for sub, _k, v in E.snmp_more_rows(None)}

    def test_tables_by_name(self):
        nodes = [{'name': 'b', 'alive': True, 'age': 3, 'version': '2', 'web': {}},
                 {'name': 'a', 'alive': False, 'age': 99, 'version': '1', 'web': {}}]
        c = {'mode': 'replicated', 'nodes': nodes, 'vip': '', 'holders': [], 'repl': 4,
             'behind': 0, 'repl_errors': 0, 'split': 0, 'split_role': '', 'leader': '',
             'up': 1, 'known': 2}
        disks = [{'path': '/var', 'total': 10, 'used': 1, 'free': 9, 'pct': 10},
                 {'path': '/', 'total': 10, 'used': 5, 'free': 5, 'pct': 50}]
        sysf = {'disks': disks, 'cores': 1, 'busy': 0, 'load': [0, 0, 0], 'mem_total': 1,
                'mem_used': 1, 'swap_used': 0, 'disk_rd': 0, 'disk_wr': 0, 'net_rx': 0,
                'net_tx': 0, 'boot': 0, 'skew': 0, 'offset': 0, 'sync': 0, 'problem': '',
                'selinux': 0, 'denials': 0, 'fw': False, 'updates': 0, 'security': 0,
                'reboot': False, 'checked': 0, 'sshd': '', 'key_lost': False, 'clash': '',
                'hand': 0}
        got = self.rows({'cluster': c, 'system': sysf})
        at = E.snmp_index(['a', 'b'])
        for name, n in (('a', nodes[1]), ('b', nodes[0])):
            k = at[name]
            # every column of the row, the first four too, of the same node
            self.assertEqual(got[(7, 1, 1, 1, k)], k)
            self.assertEqual(got[(7, 1, 1, 2, k)], name)
            self.assertEqual(got[(7, 1, 1, 3, k)], 1 if n['alive'] else 0)
            self.assertEqual(got[(7, 1, 1, 4, k)], n['age'])
            self.assertEqual(got[(7, 1, 1, 5, k)], n['version'])
        self.assertEqual(got[(7, 6, 0)], 4)
        d = E.snmp_index(['/', '/var'])
        self.assertEqual(got[(10, 1, 1, 2, d['/'])], '/')
        self.assertEqual(got[(10, 1, 1, 6, d['/'])], 50)
        # /var gone: / keeps its number
        got2 = self.rows({'system': dict(sysf, disks=[disks[1]])})
        self.assertEqual(got2[(10, 1, 1, 2, d['/'])], '/')

    def test_backup_never_made_and_replication_down(self):
        class Db(object):
            engine = 'sqlite'
        store = type('S', (), {'db': Db()})()
        self.patch(backups=lambda: [], kept_dumps=lambda engine: [], rb_history=lambda st: [],
                   rb_verified=lambda st: [])
        daemon = type('D', (), {'started': time.time() - 7200})()
        b = E._sf_backup(daemon, store, {})
        self.assertEqual(b['last'], 0)
        self.assertTrue(7190 <= b['age'] <= 7300, b)
        b = E._sf_backup(daemon, store, {'last_backup': time.time() - 60})
        self.assertTrue(55 <= b['age'] <= 120, b)
        # replicated, neither the subscription nor the slot: down (4), as the pages say
        self.patch(ha_nodes=lambda st: [], vip_conf=lambda st: {}, split_active=lambda: False,
                   ha_repl_state=lambda st: {'mode': 'replicated', 'incoming': [],
                                             'outgoing': [], 'healthy': False, 'lost': False})
        was = E.CONFIG.get('ha_mode')
        E.CONFIG['ha_mode'] = 'replicated'
        try:
            self.assertEqual(E._sf_cluster(store)['repl'], 4)
            self.patch(ha_repl_state=lambda st: {'mode': 'replicated', 'incoming': [
                {'enabled': True, 'running': False}], 'outgoing': [], 'healthy': False})
            self.assertEqual(E._sf_cluster(store)['repl'], 2)
        finally:
            E.CONFIG['ha_mode'] = was
        _, tcs, _ = mib_oids()
        self.assertEqual(tcs['AcmeReplication'].get(4) or tcs['AcmeReplication'].get('4'), 'down')

    def test_backup_age_of_a_shared_database(self):
        """1.0.115: one database for both nodes - one node makes the copy of the night for both:
        the age is the cluster's newest (any node's, or the night's claim, backup_day), not the
        node's own - the one that did not win said "no recent backup" for good."""
        import datetime
        meta = {}

        class Db(object):
            engine = 'postgres'
        store = type('S', (), {'db': Db(), 'get_meta': lambda self, k, d=None: meta.get(k, d)})()
        self.patch(backups=lambda: [], kept_dumps=lambda engine: [], rb_history=lambda st: [],
                   rb_verified=lambda st: [],
                   ha_nodes=lambda st: [{'name': 'a'}, {'name': 'b'}],
                   _meta_obj=lambda st, k: json.loads(meta.get(k) or '{}'))
        daemon = type('D', (), {'started': time.time() - 7 * 86400})()
        was = {k: E.CONFIG.get(k) for k in ('ha_mode', 'backup_at')}
        try:
            E.CONFIG['ha_mode'] = 'shared'
            E.CONFIG['backup_at'] = '03:30'
            self.assertGreater(E._sf_backup(daemon, store, {})['age'], 6 * 86400)
            # the other node made it an hour ago
            meta['host:health:b'] = json.dumps({'last_backup': time.time() - 3600})
            b = E._sf_backup(daemon, store, {})
            self.assertTrue(3590 <= b['age'] <= 3700, b)
            # the night's claim only (the other node's row gone): its day at backup_at at most
            del meta['host:health:b']
            today = datetime.datetime.now()
            meta['backup_day'] = today.strftime('%Y-%m-%d')
            at = today.replace(hour=3, minute=30, second=0, microsecond=0).timestamp()
            b = E._sf_backup(daemon, store, {})
            self.assertLessEqual(b['age'], max(0, int(time.time() - at)) + 5, b)
            # replicated: each node its own copy, as before
            E.CONFIG['ha_mode'] = 'replicated'
            meta['host:health:b'] = json.dumps({'last_backup': time.time() - 3600})
            self.assertGreater(E._sf_backup(daemon, store, {})['age'], 6 * 86400)
        finally:
            E.CONFIG.update(was)

    def test_crl_rows_by_the_whole_address(self):
        """1.0.115: two CRLs whose addresses differ only after the 255th character are two rows,
        each numbered by its whole address (the text shown cut to 255)."""
        long = 'http://crl.example.test/' + 'x' * 300
        crls = [{'url': long + 'a', 'ok': True, 'at': 1, 'next': 2, 'left': 0, 'error': ''},
                {'url': long + 'b', 'ok': False, 'at': 1, 'next': 0, 'left': 0, 'error': 'gone'}]
        g = {'accounts': 0, 'local': 0, 'sessions': 0, 'locked': 0, 'fails': 0, 'krb': False,
             'keytab': False, 'entries': 0, 'krb_error': '', 'cl': True, 'cl_listening': True,
             'cl_cas': 1, 'cl_error': '', 'crls': crls}
        got = self.rows({'signin': g})
        at = E.snmp_index([long + 'a', long + 'b'])
        self.assertNotEqual(at[long + 'a'], at[long + 'b'])
        for x in crls:
            k = at[x['url']]
            self.assertEqual(got[(12, 14, 1, 1, k)], k)
            self.assertEqual(got[(12, 14, 1, 2, k)], x['url'][:255])
            self.assertEqual(got[(12, 14, 1, 3, k)], 1 if x['ok'] else 0)
        self.patch(cl_node_state=lambda st, me: {'crls': [{'url': long + 'a', 'ok': True}]},
                   krb_node_state=lambda st, me: {}, krb_keytab_row=lambda st: {},
                   cl_cas_row=lambda st: [], krb_usable=lambda p, st: False,
                   cl_usable=lambda p, st: False)

        class Db(object):
            def rows(self, sql, args=()):
                return []

            def value(self, sql, args=(), default=None):
                return 0
        store = type('S', (), {'db': Db()})()
        self.assertEqual(E._sf_signin(object(), store)['crls'][0]['url'], long + 'a')


class Agent(unittest.TestCase):
    """The agent of a real daemon, asked as a manager asks it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='acme-snmp-test-')
        for d in ('state', 'run', 'log', 'plugins/targets'):
            os.makedirs(os.path.join(cls.tmp, d), exist_ok=True)
        with open(os.path.join(cls.tmp, 'plugins/targets/snmp_fake.py'), 'w') as f:
            f.write(FAKE_TARGET)
        cls.port = free_port()
        cls.snmp_port = free_port(socket.SOCK_DGRAM)
        conf = {'api_port': cls.port, 'radius_bind': '127.0.0.1',
                'radius_auth_port': free_port(), 'radius_acct_port': free_port(),
                'ssh_gate_port': free_port(), 'node_name': 'snmpnode', 'upgrade_check': 0,
                'snmp': 1, 'snmp_port': cls.snmp_port, 'snmp_bind': '127.0.0.1',
                'snmp_user': USER, 'snmp_auth': 'SHA-256', 'snmp_priv': 'AES-128',
                'snmp_auth_pass': AUTH_PASS, 'snmp_priv_pass': PRIV_PASS,
                'snmp_contact': 'ops@example.test', 'snmp_location': 'rack 7'}
        cls.conf = os.path.join(cls.tmp, 'config.json')
        with open(cls.conf, 'w') as f:
            json.dump(conf, f)
        cls.env = dict(os.environ, ACME_CONFIG=cls.conf,
                       ACME_STATE=os.path.join(cls.tmp, 'state'),
                       ACME_RUN=os.path.join(cls.tmp, 'run'),
                       ACME_LOGDIR=os.path.join(cls.tmp, 'log'),
                       ACME_PLUGINS=os.path.join(cls.tmp, 'plugins'),
                       ACME_STAY_ROOT='1', NO_COLOR='1', PYTHONDONTWRITEBYTECODE='1')
        cls.pw = 'Test-Password-4711!'
        made = subprocess.run([sys.executable, '-c', (
            'import sys; sys.path.insert(0, %r); import acme; acme.load_config(); '
            'st = acme.Storage(acme.open_db()); '
            'st.add_account("tester", "fulladmin", %r); '
            'st.add_account("viewer", "readonly", %r)') % (ROOT, cls.pw, cls.pw)],
            env=cls.env, capture_output=True, text=True, timeout=120)
        if made.returncode != 0:
            raise RuntimeError('the accounts could not be made: %s' % made.stderr[-2000:])
        cls.daemon = subprocess.Popen([sys.executable, os.path.join(ROOT, 'acme.py'), '--daemon'],
                                      env=cls.env, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, cwd=cls.tmp)
        end = time.time() + 60
        while time.time() < end:
            if cls.daemon.poll() is not None:
                raise RuntimeError('the daemon stopped: %s' % cls.daemon.stdout.read()
                                   .decode('utf-8', 'replace')[-3000:])
            try:
                urllib.request.urlopen('http://127.0.0.1:%d/api/health' % cls.port, timeout=2)
                break
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.3)
        else:
            raise RuntimeError('the daemon did not answer within a minute')
        with open(os.path.join(cls.tmp, 'run', 'api-token')) as f:
            cls.token = f.read().strip()
        cls.admin = cls.login('tester')
        cls.ro = cls.login('viewer')
        cls.make_certificates()
        cls.walked = None

    @classmethod
    def tearDownClass(cls):
        d = getattr(cls, 'daemon', None)
        if d is not None and d.poll() is None:
            d.send_signal(signal.SIGTERM)
            try:
                d.wait(20)
            except subprocess.TimeoutExpired:
                d.kill()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def call(cls, method, path, body=None, session=None, args=None):
        url = 'http://127.0.0.1:%d%s' % (cls.port, path)
        if args:
            url += '?' + urllib.parse.urlencode(args)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header('X-Acme-Token', cls.token)
        req.add_header('Content-Type', 'application/json')
        if session:
            req.add_header('X-Acme-Session', session)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    @classmethod
    def login(cls, name):
        st, got = cls.call('POST', '/api/auth/login', {'name': name, 'password': cls.pw})
        if st != 200:
            raise RuntimeError('signing in as %s: %s %s' % (name, st, got))
        return got['token']

    @classmethod
    def ok(cls, method, path, body=None, session=None, args=None):
        st, got = cls.call(method, path, body, session or cls.admin, args)
        if st != 200 or not got.get('ok'):
            raise AssertionError('%s %s -> %s %s' % (method, path, st, got))
        return got

    @classmethod
    def wait_job(cls, job_id, secs=120):
        end = time.time() + secs
        while time.time() < end:
            got = cls.ok('GET', '/api/certs/job', args={'id': job_id})['job']
            if got['state'] not in ('queued', 'running'):
                return got
            time.sleep(0.3)
        raise AssertionError('job %s did not end' % job_id)

    @classmethod
    def make_certificates(cls):
        cls.ok('POST', '/api/sources/save', {'name': 'self', 'kind': 'selfsigned',
                                             'config': {'days': 40}})
        cls.cid = cls.ok('POST', '/api/certs/save', {
            'name': 'web', 'names': ['www.example.test', 'example.test'], 'issuer': 'self',
            'key_type': 'ec-256', 'auto_renew': 0, 'owner': 'novak'})['id']
        cls.ok('POST', '/api/targets/save', {'name': 'good', 'kind': 'snmpfake', 'config': {}})
        cls.ok('POST', '/api/targets/save', {'name': 'bad', 'kind': 'snmpfake',
                                             'config': {'fail': True}})
        for t in ('good', 'bad'):
            cls.ok('POST', '/api/deploys/save', {'cert_id': cls.cid, 'target': t,
                                                 'options': {'file': 'x'}})
        cls.job = cls.wait_job(cls.ok('POST', '/api/certs/renew', {'id': cls.cid})['job_id'])

    # ---- asking the agent --------------------------------------------------------------------
    def snmp_cmd(self, tool, *oids):
        if not shutil.which(tool):
            return None
        got = subprocess.run([tool, '-v3', '-l', 'authPriv', '-u', USER, '-a', 'SHA-256', '-A',
                              AUTH_PASS, '-x', 'AES', '-X', PRIV_PASS, '-On', '-Oe', '-Ot', '-OU', '-r',
                              '1', '-t', '10', '-m', '', '127.0.0.1:%d' % self.snmp_port] +
                             list(oids), capture_output=True, text=True, timeout=180,
                             env=dict(os.environ, MIBS='', MIBDIRS='/nonexistent'))
        self.assertEqual(got.returncode, 0, got.stderr)
        out = {}
        for line in got.stdout.splitlines():
            m = re.match(r'^\.?([\d.]+) = (?:([\w-]+): )?(.*)$', line)
            if m:
                out[m.group(1)] = (m.group(2) or '', m.group(3).strip().strip('"'))
        return out

    def walk(self):
        if self.__class__.walked is None:
            got = self.snmp_cmd('snmpbulkwalk', BASE) or self.snmp_cmd('snmpwalk', BASE)
            if got is None:
                self.skipTest('net-snmp\'s snmpwalk is not installed (apt-get install snmp)')
            self.__class__.walked = got
        return self.__class__.walked

    def test_01_own_test_through_the_api(self):
        got = self.ok('POST', '/api/snmp', {'action': 'test'})
        self.assertIn('id', got)

    def test_02_every_object_answered_is_of_the_mib(self):
        got = self.walk()
        _, _, by_oid = mib_oids()
        self.assertGreater(len(got), 150)
        for o in got:
            if not o.startswith(BASE + '.'):
                continue
            parts = o.split('.')
            # a scalar's .0 or a column's index, the rest an object of ACME-MIB
            self.assertIn('.'.join(parts[:-1]), by_oid, o)

    def test_03_the_objects_of_1_0_108(self):
        got = self.walk()
        objs, tcs, by_oid = mib_oids()

        def val(name, index='0'):
            o = '.'.join(map(str, objs[name]['oid'])) + '.' + str(index)
            self.assertIn(o, got, name)
            return got[o][1]
        # every scalar the MIB has, answered (no cluster here: acmeNodeTable stays empty)
        for name, o in objs.items():
            oid = '.'.join(map(str, o['oid']))
            if o['access'] != 'read-only' or 'Table' in name or 'Entry' in name:
                continue
            parent = by_oid.get('.'.join(oid.split('.')[:-1]), '')
            if parent.endswith('Entry'):
                continue
            self.assertIn(oid + '.0', got, '%s (%s) is not answered' % (name, oid))
        self.assertEqual(val('acmeVersion'), E.__version__)
        self.assertEqual(val('acmeNode'), 'snmpnode')
        self.assertEqual(val('acmeDbUp'), '1')
        self.assertGreater(int(val('acmeDbSize')), 0)
        self.assertGreaterEqual(int(val('acmeCpuCores')), 1)
        self.assertGreater(int(val('acmeMemTotal')), 0)
        self.assertGreaterEqual(int(val('acmeAccounts')), 2)
        self.assertEqual(val('acmeAccountsLocal'), val('acmeAccounts'))
        self.assertIn(val('acmeAlertsWorst'), ('0', '1', '2', '3'))
        self.assertEqual(val('acmeHaMode'), '')
        self.assertEqual(val('acmeNodesKnown'), '1')
        self.assertEqual(val('acmeReplState'), '0')
        self.assertEqual(val('acmeSplitState'), '0')
        self.assertEqual(val('acmeDnsServerOn'), '0')
        self.assertGreaterEqual(int(val('acmeSnmpAsked')), 1)
        self.assertGreaterEqual(int(val('acmeStartTime')), 1600000000)
        # the file systems: at least /, each with a path and a fill between 0 and 100
        disks = {o: v for o, v in got.items() if o.startswith(
            '.'.join(map(str, objs['acmeDiskPath']['oid'])) + '.')}
        self.assertTrue(disks)
        self.assertIn('/', [v[1] for v in disks.values()])
        for o in disks:
            k = o.rsplit('.', 1)[1]
            self.assertTrue(0 <= int(val('acmeDiskUsedPct', k)) <= 100)
        # the counts, as 64-bit counters where a gauge of 32 bits is too small
        o = '.'.join(map(str, objs['acmeMemTotal']['oid'])) + '.0'
        self.assertEqual(got[o][0].lower(), 'counter64')

    def test_04_certificates_deployments_tests(self):
        got = self.walk()
        objs, _, _ = mib_oids()
        cid = self.cid

        def cell(name, index):
            o = '.'.join(map(str, objs[name]['oid'])) + '.' + str(index)
            self.assertIn(o, got, name)
            return got[o][1]
        self.assertEqual(cell('acmeManagedCertName', cid), 'web')
        self.assertEqual(cell('acmeManagedCertOwner', cid), 'novak')
        self.assertEqual(cell('acmeManagedCertStateEnum', cid), cell('acmeManagedCertStateNum', cid))
        self.assertEqual(cell('acmeManagedCertVersion', cid), '1')
        self.assertEqual(cell('acmeManagedCertNames', cid), '2')
        self.assertEqual(cell('acmeManagedCertDeploys', cid), '2')
        self.assertGreater(int(cell('acmeManagedCertLastOk', cid)), 1600000000)
        self.assertTrue(cell('acmeManagedCertSerial', cid))
        self.assertTrue(38 <= int(cell('acmeManagedCertDaysLeft', cid)) <= 40)
        self.assertGreater(int(cell('acmeManagedCertNotBefore', cid)), 1600000000)
        deploys = {cell('acmeDeployTarget', o.rsplit('.', 1)[1]): o.rsplit('.', 1)[1]
                   for o in got if o.startswith('.'.join(map(str, objs['acmeDeployTarget']['oid'])) + '.')}
        self.assertEqual(set(deploys), {'good', 'bad'})
        self.assertEqual(cell('acmeDeployStateNum', deploys['good']), '1')
        self.assertEqual(cell('acmeDeployStateNum', deploys['bad']), '4')
        self.assertIn('said no', cell('acmeDeployLastError', deploys['bad']))
        self.assertEqual(cell('acmeManagedCertDeploysFailed', cid), '1')
        self.assertEqual(cell('acmeManagedDeploysFailed', 0), '1')
        # the job of the first issue counted (it deployed too: one deployment failed in it)
        self.assertGreaterEqual(int(cell('acmeManagedRenewalsOk', 0)) +
                                int(cell('acmeManagedRenewalsFailed', 0)), 1)
        self.assertGreaterEqual(int(cell('acmeManagedDeploysFailed24h', 0)), 0)  # jobs of their own
        # the modules: the targets, the bad one failing
        mods = {cell('acmeModuleName', o.rsplit('.', 1)[1]): o.rsplit('.', 1)[1]
                for o in got if o.startswith('.'.join(map(str, objs['acmeModuleName']['oid'])) + '.')}
        self.assertIn('bad', mods)
        self.assertEqual(cell('acmeModuleFailing', mods['bad']), '1')
        self.assertEqual(cell('acmeModuleFailing', mods['good']), '0')

    def test_05_the_alerts_have_their_new_columns(self):
        got = self.walk()
        objs, _, _ = mib_oids()
        lv = '.'.join(map(str, objs['acmeAlertLevelNum']['oid'])) + '.'
        rows = [o for o in got if o.startswith(lv)]
        for o in rows:
            self.assertIn(got[o][1], ('1', '2', '3'))
            k = o.rsplit('.', 1)[1]
            self.assertIn('.'.join(map(str, objs['acmeAlertArea']['oid'])) + '.' + k, got)

    def test_06_get_and_the_metrics(self):
        got = self.snmp_cmd('snmpget', BASE + '.10.2.0', BASE + '.12.1.0', BASE + '.1.1.0',
                            '1.3.6.1.2.1.1.4.0', '1.3.6.1.2.1.1.6.0')
        if got is None:
            self.skipTest('net-snmp\'s snmpget is not installed')
        self.assertEqual(got['1.3.6.1.2.1.1.4.0'][1], 'ops@example.test')
        self.assertEqual(got['1.3.6.1.2.1.1.6.0'][1], 'rack 7')
        self.assertEqual(got[BASE + '.1.1.0'][1], E.__version__)
        # the same facts in Prometheus' samples (the table of them, acmeMetricTable)
        walked = self.walk()
        names = {v[1] for o, v in walked.items() if o.startswith(BASE + '.9.1.1.2.')}
        for want in ('acme_load', 'acme_memory_bytes', 'acme_accounts', 'acme_os_updates',
                     'acme_backup_verify_result', 'acme_signin_locked', 'acme_update_available'):
            self.assertIn(want, names)

    def test_07_the_files_on_the_snmp_page(self):
        for session in (self.admin, self.ro):          # nothing secret: a reader takes them too
            z = self.ok('GET', '/api/snmp', session=session, args={'get': 'zabbix'})
            self.assertEqual(z['name'], 'acme_zabbix7_template.yaml')
            self.assertIn("version: '7.0'", z['text'])
            self.assertEqual(z['text'], E.zabbix_template_yaml())
            m = self.ok('GET', '/api/snmp', session=session, args={'get': 'mib'})
            self.assertTrue(m['text'].startswith('ACME-MIB DEFINITIONS'))
        st, err = self.call('GET', '/api/snmp', None, self.ro, {'get': 'other'})
        self.assertEqual(st, 400, err)
        # the command line: the same file, made without the daemon
        out = os.path.join(self.tmp, 'tpl.yaml')
        cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'),
                              '--snmp-zabbix-template', '--out', out], env=self.env,
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        with open(out) as f:
            self.assertEqual(f.read(), z['text'])
        cli = subprocess.run([sys.executable, os.path.join(ROOT, 'acme.py'), '--snmp-mib'],
                             env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        self.assertEqual(cli.stdout, m['text'] if m['text'].endswith('\n') else m['text'] + '\n')

    def test_08_every_template_oid_answered(self):
        """What the template reads, the agent answers: each scalar of the node, each column."""
        if yaml is None:
            self.skipTest('PyYAML is not installed')
        got = self.walk()
        tpl = yaml.safe_load(E.zabbix_template_yaml())['zabbix_export']['templates'][0]
        cols = {o.rsplit('.', 1)[0] for o in got}
        missing = []
        for i in tpl['items']:
            for s in i.get('preprocessing') or []:
                if s['type'] == 'SNMP_WALK_VALUE' and s['parameters'][0].startswith(BASE):
                    if s['parameters'][0] not in got:
                        missing.append(s['parameters'][0])
                        continue
                    # as Zabbix walks (numeric enums and timeticks, no units): a number where
                    # the item keeps one, never below 0 where it keeps no sign
                    typ, value = got[s['parameters'][0]]
                    if i['value_type'] in ('UNSIGNED', 'FLOAT'):
                        self.assertRegex(value, r'^-?\d+$', (i['key'], typ, value))
                        if i['value_type'] == 'UNSIGNED':
                            self.assertGreaterEqual(int(value), 0, i['key'])
                    else:
                        self.assertIn(typ.upper(), ('STRING', ''), (i['key'], typ))
        self.assertEqual(missing, [])
        # the columns of the tables with rows here: each one the template reads is answered
        objs, _, _ = mib_oids()
        for r in tpl['discovery_rules']:
            if r['key'] not in ('acme.cert.discovery', 'acme.deploy.discovery',
                                'acme.module.discovery', 'acme.disk.discovery'):
                continue
            for p in r['item_prototypes']:
                for s in p['preprocessing']:
                    if s['type'] == 'SNMP_WALK_VALUE':
                        self.assertIn(s['parameters'][0].replace('.{#SNMPINDEX}', ''), cols,
                                      p['key'])

    def test_09_the_pane(self):
        """In Chromium (Playwright), English and Czech, wide and a phone: the SNMPv3 card of
        Settings -> Monitoring with its two downloads, from a copy of web/ whose acme-api.php
        asks this daemon (as test_osusers does)."""
        node = shutil.which('node')
        if not node or not shutil.which('php'):
            self.skipTest('no node or php here')
        if subprocess.run([node, '-e', 'require("playwright")'], capture_output=True,
                          cwd=ROOT).returncode != 0:
            self.skipTest('no playwright for node here')
        web = os.path.join(self.tmp, 'web')
        shutil.rmtree(web, ignore_errors=True)
        shutil.copytree(os.path.join(ROOT, 'web'), web)
        api_php = os.path.join(web, 'acme-api.php')
        with open(api_php, encoding='utf-8') as f:
            text = f.read()
        with open(api_php, 'w', encoding='utf-8') as f:
            f.write(text.replace('/run/acme/', os.path.join(self.tmp, 'run') + '/'))
        port = free_port()
        php = subprocess.Popen(['php', '-S', '127.0.0.1:%d' % port], cwd=web,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            end = time.time() + 20
            while time.time() < end:
                try:
                    urllib.request.urlopen('http://127.0.0.1:%d/admin/index.php' % port, timeout=2)
                    break
                except OSError:
                    time.sleep(0.3)
            got = subprocess.run([node, os.path.join(HERE, 'snmp_page.js'),
                                  'http://127.0.0.1:%d' % port, 'viewer', self.pw],
                                 capture_output=True, text=True, timeout=600, cwd=ROOT)
            self.assertEqual(got.returncode, 0, got.stderr[-2000:])
            seen = json.loads(got.stdout.strip().splitlines()[-1])
        finally:
            php.terminate()
            php.wait(10)
        self.assertNotIn('error', seen, seen.get('error'))
        for lang in ('en', 'cs'):
            for width in (1300, 390):
                s = seen[lang + str(width)]
                self.assertEqual(s['errors'], [], (lang, width))
                self.assertLessEqual(s['overflow'], 0, (lang, width))
                self.assertIn('Zabbix', s['zabbix_button'])
                self.assertIn('ACME-MIB', s['mib_button'])
            # a reader downloads both (nothing secret in them)
            dl = seen[lang + '1300']
            self.assertEqual(dl['dl_zabbix']['name'], 'acme_zabbix7_template.yaml')
            self.assertTrue(dl['dl_zabbix']['head'].startswith('zabbix_export:'))
            self.assertGreater(dl['dl_zabbix']['size'], 100000)
            self.assertEqual(dl['dl_mib']['name'], 'ACME-MIB.txt')
            self.assertTrue(dl['dl_mib']['head'].startswith('ACME-MIB DEFINITIONS'))


class Mib(unittest.TestCase):
    def test_smilint_and_snmptranslate(self):
        mib = os.path.join(ROOT, 'deploy', 'ACME-MIB.txt')
        if shutil.which('snmptranslate'):
            got = subprocess.run(['snmptranslate', '-M', '+' + os.path.dirname(mib), '-m',
                                  '+ACME-MIB', '-On', 'ACME-MIB::acmeSnmpTraps'],
                                 capture_output=True, text=True, timeout=60)
            if 'Cannot find module' not in got.stderr:
                self.assertEqual(got.stdout.strip(), '.' + BASE + '.10.31', got.stderr)
        if shutil.which('smilint'):
            path = ':'.join(p for p in ('/usr/share/snmp/mibs/ietf', '/usr/share/snmp/mibs',
                                        '/usr/share/snmp/mibs/iana', '/var/lib/mibs/ietf')
                            if os.path.isdir(p))
            got = subprocess.run(['smilint', '-l', '6', '-s', mib], capture_output=True,
                                 text=True, timeout=60, env=dict(os.environ, SMIPATH=path))
            if 'failed to locate MIB module' in got.stderr:
                self.skipTest('the IETF MIBs are not installed (snmp-mibs-downloader)')
            lines = [x for x in got.stderr.splitlines() + got.stdout.splitlines() if x.strip()
                     # the indexes are readable on purpose: walked, each row says its id
                     and 'should be not-accessible' not in x]
            self.assertEqual(lines, [])

    def test_old_objects_kept(self):
        """1.0.108 only adds: every object of before keeps its OID."""
        objs, _, _ = mib_oids()
        for name, oid in (('acmeVersion', '1.1'), ('acmeUptime', '1.7'), ('acmeDbLatency', '3.2'),
                          ('acmeAlertSaid', '5.3.1.5'), ('acmeCertEnd', '6.1.1.5'),
                          ('acmeManagedCertTestsFailed', '6.2.1.15'),
                          ('acmeManagedDeploys', '6.3.16'), ('acmeDeployLastError', '6.4.1.11'),
                          ('acmeTestSaid', '6.5.1.12'), ('acmeModuleLastError', '6.6.1.7'),
                          ('acmeCaCrlNext', '6.7.1.8'), ('acmeNodeAge', '7.1.1.4'),
                          ('acmeTrapNode', '8.5'), ('acmeMetricValue', '9.1.1.4')):
            self.assertEqual('.'.join(map(str, objs[name]['oid'])), BASE + '.' + oid, name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
