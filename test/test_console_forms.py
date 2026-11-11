#!/usr/bin/env python3
"""The console's module forms (acmelib/certs/console.py, 1.0.77): a choice whose value is not
offered now is kept, not changed to the first one; a field under "More" shown by a main field;
a key kept secret typed unseen; a value of several lines kept whole.

    python3 test/test_console_forms.py
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from acmelib.certs import console as C  # noqa: E402


class FakeCon(object):
    def __init__(self, answers):
        self.answers = list(answers)
        self.forms = []

    def form(self, title, fields, words=''):
        self.forms.append(fields)
        vals = {f['key']: f.get('value', '') for f in fields}
        vals.update(self.answers.pop(0) if self.answers else {})
        return vals

    def confirm(self, *a, **k):
        return True


class Forms(unittest.TestCase):
    def test_a_choice_not_offered_is_kept(self):
        f = [{'key': 'ca', 'type': 'select', 'options': [['caA', 'caA']], 'required': True}]
        got = C._form_fields(f, {'ca': 'caB'}, ())
        self.assertEqual(got[0]['value'], 'caB')
        self.assertIn('caB', [o[0] for o in got[0]['options']])
        argv, env = C.module_form(FakeCon([]), 'x', f, {'ca': 'caB'})
        self.assertEqual(argv, [])                       # nothing touched, nothing sent

    def test_more_sees_the_main_form(self):
        fields = [{'key': 'flavour', 'type': 'select', 'options': [['a', 'a'], ['bind', 'b']]},
                  {'key': 'rndc', 'type': 'text', 'advanced': True, 'show_if': {'flavour': ['bind']}}]
        con = FakeCon([{'flavour': 'bind'}, {}])
        C.module_form(con, 'x', fields, {'flavour': 'a'})
        more = con.forms[1][0]
        self.assertTrue(more['when']({'rndc': ''}))
        self.assertFalse(C._form_fields(fields[1:], {}, (), base={'flavour': 'a'})[0]['when']({}))

    def test_a_secret_key_is_typed_unseen(self):
        f = [{'key': 'ssh_key', 'type': 'sshkey', 'secret': True}]
        self.assertEqual(C._form_fields(f, {}, ())[0]['kind'], 'secret')
        argv, env = C.module_form(FakeCon([{'ssh_key': 'PRIVATE'}]), 'x', f, {'x': 1})
        self.assertEqual(argv, ['--set', 'ssh_key=@env'])
        self.assertEqual(env, {'ACME_VALUE_SSH_KEY': 'PRIVATE'})

    def test_lines_kept(self):
        f = [{'key': 'outputs', 'type': 'list'}, {'key': 'script', 'type': 'textarea'}]
        cur = {'outputs': 'a /x\nb /y', 'script': 'one\ntwo'}
        got = {x['key']: x['value'] for x in C._form_fields(f, cur, ())}
        self.assertEqual(got['outputs'], 'a /x, b /y')
        self.assertNotIn('\n', got['script'])
        argv, env = C.module_form(FakeCon([{'script': got['script'] + C.NL + 'three'}]), 'x', f, cur)
        self.assertEqual(argv, ['--set', 'script=one\ntwo\nthree'])

    def test_old_bool_of_a_choice(self):
        f = [{'key': 'backup', 'type': 'select', 'options': [['bak', 'b'], ['none', 'n']],
              'from_bool': ['bak', 'none']}]
        self.assertEqual(C._form_fields(f, {'backup': False}, ())[0]['value'], 'none')


if __name__ == '__main__':
    unittest.main(verbosity=2)
