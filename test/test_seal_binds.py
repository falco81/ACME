#!/usr/bin/env python3
"""Every secret sealed for its place (1.0.102).

    python3 test/test_seal_binds.py

An installation upgraded from 1.0.101 holds its settings and directories' passwords sealed
without a place (sealed:1:), and may hold an older module secret or key in clear. Once
(seal_bind_all) every one is sealed again for its place - and from then on a value sealed
without a place, or one in clear, is refused wherever a place is asked for: a sealed setting
copied into a module's secret field, a key of one's own written in clear over a certificate's
(Hunt N r_bind.py). The backup's check, the configuration's export and a copy put back keep
working.
"""
import json
import os
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-sealbind-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write(json.dumps({'snmp_auth_pass': 'from-the-file-1'}))
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme as E  # noqa: E402
from acmelib.certs import ca as CA, pki, store as S  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)
E.load_config()
KEY_PEM = pki.make_key('ec-256')


def setting(k, v):
    STORE.save_setting(k, v, by='1.0.101')


def raw_setting(k):
    return json.loads(STORE.db.value('SELECT v FROM settings WHERE k = ?', (k,)))


class SealBinds(unittest.TestCase):
    """In order: the old forms as 1.0.101 left them, sealed for their places once, refused
    after."""

    @classmethod
    def setUpClass(cls):
        # As 1.0.101 kept them: settings sealed without a place, one in clear, a directory's
        # password sealed without one, a certificate's key and an authority's key in clear or
        # unbound, a module's secret in clear, an ACME account key kept in clear.
        setting('smtp_password', E.seal_secret('smtp-pw-1'))
        setting('proxy_password', E.seal_secret('proxy-pw-1'))
        setting('sms_token', 'sms-in-clear-1')
        setting('acme_dns_key@node2', E.seal_secret('dnskey-node2'))
        cls.dir_id = STORE.db.insert('directories', {
            'name': 'ad', 'hosts': 'dc1.example.test', 'port': 636, 'tls': 'ldaps', 'verify': 1,
            'base': 'DC=example,DC=test', 'bind_dn': 'CN=svc', 'bind_pw': E.seal_secret('dir-pw-1'),
            'user_attr': 'sAMAccountName', 'nested': 1, 'timeout_s': 10, 'enabled': 1,
            'created': time.time()})
        cls.ca_id = CA.ca_create(STORE, 'Root', {'CN': 'Root'}, key_type='ec-256', by='t')
        ca_key = E.unseal_secret(STORE.db.value('SELECT key_sealed FROM cert_cas WHERE id = ?',
                                                (cls.ca_id,)), 'cert_cas:%d:key' % cls.ca_id)
        STORE.db.update('cert_cas', cls.ca_id, {'key_sealed': E.seal_secret(ca_key)})
        cls.cid = STORE.db.insert('certs', {'name': 'web', 'names': json.dumps(['web.example']),
                                            'key_type': 'ec-256', 'created': time.time(),
                                            'version': 3, 'key_sealed': KEY_PEM})
        cls.tid = STORE.db.insert('cert_targets', {
            'name': 'mt', 'kind': 'mikrotik', 'enabled': 1, 'created': time.time(),
            'config': json.dumps({'host': 'mt.example.test', 'ssh_key': 'KEY-IN-CLEAR',
                                  'other': E.seal_secret('module-v1')})})
        cls.kv = 'certs:kv:issuer:le:acme-account:https://acme.example/dir:0123456789abcdef'
        STORE.set_meta(cls.kv, json.dumps({'v': json.dumps({'url': 'https://acme.example/a/1',
                                                            'key': KEY_PEM}), 'exp': None}))

    def test_1_before_every_old_form_opens(self):
        self.assertFalse(E.seal_bound(STORE.db, fresh=True))
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('smtp_password'), 'smtp-pw-1')
        self.assertEqual(E.setting_secret('sms_token'), 'sms-in-clear-1')
        self.assertEqual(STORE.directory('ad', with_secret=True)['bind_pw'], 'dir-pw-1')
        self.assertEqual(E.unseal_secret(KEY_PEM, 'certs:1:key_sealed:3'), KEY_PEM)
        # ...and a setting saved now is sealed as 1.0.101 opens it (a node of the cluster
        # still on it, until every secret is sealed for its place)
        self.assertTrue(E.seal_setting('smtp_password', 'x').startswith(E.SEALED))

    def test_2_sealed_for_their_places_once(self):
        got = E.seal_bind_all(STORE)
        self.assertTrue(got, got)
        self.assertEqual(got.get('setting v1'), 3, got)
        self.assertEqual(got.get('setting clear'), 1, got)
        self.assertEqual(got.get('directory password v1'), 1, got)
        self.assertEqual(got.get('cert_cas.key_sealed v1'), 1, got)
        self.assertEqual(got.get('certs.key_sealed clear'), 1, got)
        self.assertEqual(got.get('cert_targets.config clear'), 1, got)
        self.assertEqual(got.get('cert_targets.config v1'), 1, got)
        self.assertEqual(got.get('module state clear'), 1, got)
        self.assertTrue(E.seal_bound(STORE.db, fresh=True))
        self.assertTrue(STORE.get_meta(E.SEAL_BOUND_MARK))
        self.assertTrue(os.path.exists(str(E.seal_bound_path())))
        # done once: the next start does nothing
        self.assertIsNone(E.seal_bind_all(STORE))
        for k in ('smtp_password', 'proxy_password', 'sms_token', 'acme_dns_key@node2'):
            self.assertTrue(raw_setting(k).startswith(E.SEALED2), k)
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('smtp_password'), 'smtp-pw-1')
        self.assertEqual(E.setting_secret('proxy_password'), 'proxy-pw-1')
        self.assertEqual(E.setting_secret('sms_token'), 'sms-in-clear-1')
        self.assertEqual(E.setting_secret('acme_dns_key@node2', raw_setting('acme_dns_key@node2')),
                         'dnskey-node2')
        STORE._dirs = None
        self.assertEqual(STORE.directory('ad', with_secret=True)['bind_pw'], 'dir-pw-1')
        # the authority signs with its key, the certificate's key opens for its version
        key = pki.make_key('ec-256')
        csr, _der = pki.make_csr(key, ['a.example'])
        cert, _chain = CA.ca_sign(STORE, self.ca_id, csr, 30)
        self.assertIn('BEGIN CERTIFICATE', cert)
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (self.cid,))
        self.assertEqual(S.cert_key(row) if hasattr(S, 'cert_key') else
                         E.unseal_secret(row['key_sealed'], 'certs:%d:key_sealed:3' % self.cid),
                         KEY_PEM)
        trow = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (self.tid,))
        cfg = S.plugin_config('target', trow)
        self.assertEqual(cfg['ssh_key'], 'KEY-IN-CLEAR')
        self.assertEqual(cfg['other'], 'module-v1')
        acct = json.loads(json.loads(STORE.get_meta(self.kv))['v'])
        self.assertTrue(acct['key'].startswith(E.SEALED2))
        self.assertEqual(E.unseal_secret(acct['key'], 'certs:' + self.kv.split(':', 4)[4]), KEY_PEM)
        # a setting saved now is sealed for its name
        self.assertTrue(E.seal_setting('smtp_password', 'x').startswith(E.SEALED2))

    def test_3_old_forms_refused_after(self):
        # Hunt N r_bind.py: a sealed setting opened where a module's secret is expected
        v1 = E.seal_secret('proxy-password-123')
        self.assertIsNone(E.unseal_secret(v1, 'cert_targets:7:password'))
        self.assertIsNone(E.unseal_secret(E.seal_secret('t', 'cert_targets:7:password'),
                                          'cert_targets:8:password'))
        self.assertIsNone(E.unseal_secret('-----BEGIN PRIVATE KEY----- mine', 'cert_cas:1:key'))
        self.assertEqual(E.unseal_secret('', 'cert_cas:1:key'), '')
        # the sealed proxy password (bound to its name now) copied into a module's secret
        cfg = json.loads(STORE.db.value('SELECT config FROM cert_targets WHERE id = ?', (self.tid,)))
        cfg['ssh_key'] = raw_setting('proxy_password')
        cfg['other'] = v1
        STORE.db.update('cert_targets', self.tid, {'config': json.dumps(cfg)})
        trow = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (self.tid,))
        got = S.plugin_config('target', trow)
        self.assertEqual(got['ssh_key'], '')
        self.assertEqual(got['other'], '')
        # ...or into another setting
        self.assertEqual(E.setting_secret('smtp_password', raw_setting('proxy_password')), '')
        # a key in clear written over a certificate's
        STORE.db.update('certs', self.cid, {'key_sealed': pki.make_key('ec-256')})
        row = STORE.db.row('SELECT * FROM certs WHERE id = ?', (self.cid,))
        self.assertIsNone(E.unseal_secret(row['key_sealed'], 'certs:%d:key_sealed:3' % self.cid))
        # a setting written into the database sealed without a place, or in clear: refused
        setting('smtp_password', E.seal_secret('planted'))
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('smtp_password'), '')
        setting('smtp_password', 'planted-in-clear')
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('smtp_password'), '')
        # ...but one written in config.json by whoever runs the machine is taken as it is
        self.assertEqual(E.setting_secret('snmp_auth_pass'), 'from-the-file-1')
        # a directory's password sealed without a place: refused
        STORE.db.update('directories', self.dir_id, {'bind_pw': E.seal_secret('dir-planted')})
        STORE._dirs = None
        d = STORE.directory('ad', with_secret=True)
        self.assertFalse(d['bind_pw'])
        # saved on the page: sealed for its row
        STORE.directory_save({'id': self.dir_id, 'name': 'ad', 'hosts': 'dc1.example.test',
                              'port': 636, 'tls': 'ldaps', 'base': 'DC=example,DC=test',
                              'bind_dn': 'CN=svc', 'bind_pw': 'dir-pw-2', 'verify': 1}, by='t')
        STORE._dirs = None
        self.assertEqual(STORE.directory('ad', with_secret=True)['bind_pw'], 'dir-pw-2')
        self.assertTrue(STORE.db.value('SELECT bind_pw FROM directories WHERE id = ?',
                                       (self.dir_id,)).startswith(E.SEALED2))

    def test_4_backup_check_and_export(self):
        setting('smtp_password', E.seal_setting('smtp_password', 'smtp-pw-3'))
        path = os.path.join(TMP, 'copy.json.gz')
        with open(path, 'wb') as f:
            E.dump_tables(STORE.db, f)
        got = E.copy_read_through(path, E.sealing_key(), child=True)
        self.assertGreaterEqual(got['tried'], 5)
        self.assertEqual(got['opened'], got['tried'], got)
        tried, opened, bad = E._sealed_check(STORE.db, E.sealing_key())
        self.assertGreater(tried, 0)
        self.assertEqual(bad, [k for k in bad if 'certs' in k or 'cert_targets' in k], bad)
        self.assertTrue(E.sealed_opens(STORE.db))
        conf = E.config_export(STORE, True)
        self.assertEqual(conf['settings']['smtp_password'], 'smtp-pw-3')
        self.assertEqual(conf['settings']['proxy_password'], 'proxy-pw-1')

    def test_5_a_copy_put_back_is_sealed_again(self):
        # a copy made before 1.0.102 put back: its settings sealed without a place
        setting('smtp_password', E.seal_secret('from-the-old-copy'))
        STORE.db.update('directories', self.dir_id, {'bind_pw': E.seal_secret('dir-old-copy')})
        got = E.seal_bind_all(STORE, force=True, why='a copy put back by t')
        self.assertEqual(got.get('setting v1'), 1, got)
        self.assertEqual(got.get('directory password v1'), 1, got)
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('smtp_password'), 'from-the-old-copy')
        STORE._dirs = None
        self.assertEqual(STORE.directory('ad', with_secret=True)['bind_pw'], 'dir-old-copy')

    def test_6_a_node_that_read_them_before(self):
        """Rolling upgrade (r1_stale_node.py): another node sealed them for their names after
        this one read them in - not '' meanwhile, and read in again once."""
        setting('smtp_password', E.seal_secret('stale-mail'))
        setting('sms_token', E.seal_secret('stale-sms'))
        conf = E.load_config(saved=STORE.settings_saved())  # this node, holding the v1 forms
        E.seal_bind_all(STORE, force=True, why='the other node')
        serial = STORE.get_meta('conf_serial', '0')
        self.assertTrue(raw_setting('smtp_password').startswith(E.SEALED2))
        self.assertTrue(conf['smtp_password'].startswith(E.SEALED), conf['smtp_password'])
        self.assertFalse(conf['smtp_password'].startswith(E.SEALED2))
        E.seal_bound_forget()
        self.assertEqual(E.setting_secret('smtp_password'), 'stale-mail')
        self.assertEqual(E.setting_secret('sms_token'), 'stale-sms')
        # what was changed told every node (conf_serial), so each reads its settings again
        self.assertNotEqual(serial, '0')
        # one written so past acme in the database is still refused
        setting('sms_token', 'planted')
        E.load_config(saved=STORE.settings_saved())
        self.assertEqual(E.setting_secret('sms_token'), '')
        # the daemon reads its settings again once, when the mark turns up
        d = E.Daemon.__new__(E.Daemon)
        d.store, d.seal_bound_seen, got = STORE, False, []
        d.reload_all = lambda why='': got.append(why)
        self.assertTrue(d.sealed_bound_tick())
        self.assertFalse(d.sealed_bound_tick())
        self.assertEqual(len(got), 1)

    def test_7_a_copy_put_back_whose_module_step_failed(self):
        """r4_force_retry.py: tried again at the next tick, though this node's file is there."""
        calls = []

        def flaky(_st):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError('not loaded yet')
            return {'module state v1': 1}
        E.HOOKS.setdefault('seal_bind_all', []).insert(0, flaky)
        try:
            setting('smtp_password', E.seal_secret('old-copy-2'))
            self.assertIsNone(E.seal_bind_all(STORE, force=True, why='a copy put back by t'))
            self.assertTrue(E.seal_again_path().exists())
            got = E.seal_bind_all(STORE)
            self.assertEqual(got.get('module state v1'), 1, got)
            self.assertFalse(E.seal_again_path().exists())
            self.assertIsNone(E.seal_bind_all(STORE))
            self.assertEqual(len(calls), 2)
        finally:
            E.HOOKS['seal_bind_all'].remove(flaky)

    def test_8_a_module_secret_in_clear_after_the_mark(self):
        """r2_clear_field.py: a field kept in clear the migration did not seal (its module not
        loaded then, or marked secret since) - taken and sealed for its place, not ''."""
        self.assertTrue(E.seal_bound(STORE.db, fresh=True))
        cfg = json.loads(STORE.db.value('SELECT config FROM cert_targets WHERE id = ?', (self.tid,)))
        cfg['ssh_key'] = 'LATE-KEY-IN-CLEAR'
        STORE.db.update('cert_targets', self.tid, {'config': json.dumps(cfg)})
        trow = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (self.tid,))
        self.assertEqual(S.plugin_config('target', trow)['ssh_key'], 'LATE-KEY-IN-CLEAR')
        kept = json.loads(STORE.db.value('SELECT config FROM cert_targets WHERE id = ?',
                                         (self.tid,)))['ssh_key']
        self.assertTrue(kept.startswith(E.SEALED2), kept)
        trow = STORE.db.row('SELECT * FROM cert_targets WHERE id = ?', (self.tid,))
        self.assertEqual(S.plugin_config('target', trow)['ssh_key'], 'LATE-KEY-IN-CLEAR')
        # a value sealed without a place copied there is still refused
        cfg = dict(json.loads(trow['config']), ssh_key=E.seal_secret('copied'))
        self.assertEqual(S.config_open(cfg, 'cert_targets:%d' % self.tid, {'ssh_key'})['ssh_key'],
                         '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
