"""Where a person's e-mail address and mobile number are read from the directory (1.0.40, as
otp 1.0.229): each directory's own attributes, proxyAddresses as Exchange keeps it, and the
whole entry of one person to choose from.

    python3 test/test_dir_attrs.py
"""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix='acme-dirattr-')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, 'test'))
import acme as E  # noqa: E402

STORE = E.Storage(E.open_db())
E.sealing_key(make=True)


class TestAttrs(unittest.TestCase):
    def test_defaults_as_until_now(self):
        self.assertEqual(E.dir_attr_list('', E.DIR_MAIL_DEFAULT), ('mail',))
        self.assertEqual(E.dir_attr_list(None, E.DIR_MOBILE_DEFAULT), ('mobile', 'telephoneNumber'))

    def test_checked(self):
        self.assertEqual(E.dir_attr_checked('extensionAttribute5,  mail', 'x'), 'extensionAttribute5, mail')
        with self.assertRaises(ValueError):
            E.dir_attr_checked('a b c d e', 'x')
        with self.assertRaises(ValueError):
            E.dir_attr_checked('bad!name', 'x')

    def test_proxy_addresses_as_exchange_keeps_them(self):
        a = {'proxyaddresses': ['smtp:alias@corp.cz', 'SMTP:jan.novak@corp.cz', 'X500:/o=x']}
        self.assertEqual(E.entry_mail(a, ('proxyAddresses',)), 'jan.novak@corp.cz')
        self.assertEqual(E.entry_mail({'mail': ['m@corp.cz']}, ('extensionAttribute1', 'mail')), 'm@corp.cz')
        self.assertEqual(E.entry_first({'telephonenumber': ['+420 1']}, ('mobile', 'telephoneNumber')), '+420 1')

    def test_the_card_keeps_them(self):
        ident = STORE.directory_save({'name': 'corp', 'hosts': 'dc1.corp.local', 'tls': 'ldaps',
                                      'base': 'DC=corp,DC=local', 'mail_attr': 'proxyAddresses, mail',
                                      'mobile_attr': 'mobile, telephoneNumber'})
        row = next(d for d in STORE.directories() if d['id'] == ident)
        self.assertEqual(row['mail_attr'], 'proxyAddresses, mail')
        self.assertEqual(row['mobile_attr'], '')          # the default, kept as empty
        d = E.Directory(row)
        self.assertEqual(d.mail_attrs, ('proxyAddresses', 'mail'))
        self.assertIn('proxyAddresses', d.user_attrs)

    def test_an_attribute_fits(self):
        self.assertEqual(E.dir_attr_fits('mail', ['a@b.cz']), (True, False))
        self.assertEqual(E.dir_attr_fits('mobile', ['+420 603 000 000']), (False, True))


if __name__ == '__main__':
    unittest.main()
