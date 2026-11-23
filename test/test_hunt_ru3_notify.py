#!/usr/bin/env python3
"""Hunt u3 - notifications and texts sent to people.

    python3 test/test_hunt_ru3_notify.py

- the alerts' 15 minutes after a failure: a report (or a report of the tests) to other
  addresses that was refused no longer holds the alerts back, and a mail to the alerts'
  addresses that went ends the wait;
- the mail to a team's approvers in Czech says who is wanted in Czech;
- the titles of the certificates' notifications in Settings -> Message texts have their
  Czech words (scratch translations of this hunt, or web/lang/cs.json once merged).
"""
import json
import os
import sys
import tempfile
try:
    import tmpclean  # noqa: F401,E402  (what the tests make taken away at exit, also when stopped)
except ImportError:
    from test import tmpclean  # noqa: F401,E402
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TMP = tempfile.mkdtemp(prefix='acme-hunt-u3-notify-')
with open(os.path.join(TMP, 'config.json'), 'w') as f:
    f.write('{}')
os.environ.update(ACME_CONFIG=os.path.join(TMP, 'config.json'), ACME_STATE=TMP,
                  ACME_RUN=TMP, ACME_LOGDIR=TMP)
sys.path.insert(0, ROOT)
import acme  # noqa: E402,F401
from acmelib import engine as E  # noqa: E402
from acmelib.certs import api as A  # noqa: E402
from acmelib.certs import teams as T, teampolicy as TP  # noqa: E402

STORE = acme.Storage(acme.open_db())
E.HA_STORE['store'] = STORE
E.sealing_key(make=True)


class Sent(object):
    """mail_deliver replaced: what was asked to go, failing when `fail` says so."""
    def __init__(self, fail=None):
        self.fail, self.got = fail, []

    def __call__(self, store, msg, to, **kw):
        self.got.append((msg, list(to), kw))
        if self.fail:
            raise E.MailError(self.fail, [], permanent=True)
        return [{'ok': True, 'said': '250 ok'}]


def swap(name, value):
    had = E.__dict__[name]
    E.__dict__[name] = value
    return had


class AlertsWait(unittest.TestCase):
    def setUp(self):
        STORE.db.run("DELETE FROM meta WHERE k LIKE 'alerts:%'")
        E.CONFIG.update(alerts=1, alerts_to='ops@example.test', alerts_delay_min=0,
                        mail_from='acme@example.test', mail_mode='smtp')

    def tearDown(self):
        E.CONFIG.update(alerts=0, alerts_to='', mail_mode='off')

    def _evaluate_with_problem(self, sent):
        had_p, had_d = swap('alert_problems', lambda store, lang='en': {
            'x:one': {'level': 'bad', 'title': 'Something', 'said': 'it is broken'}}), \
            swap('mail_deliver', sent)
        try:
            return E.alerts_evaluate(STORE)
        finally:
            E.__dict__['alert_problems'], E.__dict__['mail_deliver'] = had_p, had_d

    def test_refused_report_does_not_hold_alerts(self):
        boom = Sent(fail='550 no such user')
        had = swap('mail_deliver', boom)
        try:
            entry = E.alert_send(STORE, E._al_msg('[acme] report', '<p>r</p>', 'r',
                                                  ['typo@example.test']),
                                 ['typo@example.test'], 'report', [])
        finally:
            E.__dict__['mail_deliver'] = had
        self.assertFalse(entry['ok'])
        self.assertNotIn('fail_at', E._alert_state(STORE))
        ok = Sent()
        got = self._evaluate_with_problem(ok)
        self.assertEqual(got['new'], 1)
        self.assertEqual(len(ok.got), 1, 'the alert was held back by the refused report')
        self.assertEqual(ok.got[0][1], ['ops@example.test'])

    def test_failed_alert_waits_and_a_test_that_went_ends_it(self):
        boom = Sent(fail='454 try later')
        self._evaluate_with_problem(boom)
        self.assertEqual(len(boom.got), 1)
        self.assertTrue(E._alert_state(STORE).get('fail_at'))
        again = Sent()
        self._evaluate_with_problem(again)
        self.assertEqual(again.got, [], 'right after a failure the alerts wait (as before)')
        # the test alert to the same addresses went: the mail works again
        had = swap('mail_deliver', Sent())
        try:
            E.alert_send(STORE, E._al_msg('[acme] test', '<p>t</p>', 't', ['ops@example.test']),
                         ['ops@example.test'], 'test', [])
        finally:
            E.__dict__['mail_deliver'] = had
        self.assertNotIn('fail_at', E._alert_state(STORE))
        last = Sent()
        self._evaluate_with_problem(last)
        self.assertEqual(len(last.got), 1, 'the alert waited on after the mail went again')


class ApproverMail(unittest.TestCase):
    def setUp(self):
        for t in ('certs', 'cert_teams'):
            STORE.db.run('DELETE FROM %s' % t)
        if not STORE.db.row("SELECT id FROM cert_issuers WHERE name = 'self'"):
            STORE.db.insert('cert_issuers', {'name': 'self', 'kind': 'selfsigned',
                                             'config': '{}', 'enabled': 1})
        T.save_team(STORE, {'name': 'Europe', 'kind': 'unit',
                            'contact_mail': 'eu@example.test'}, 'x')
        T.save_team(STORE, {'name': 'Web', 'parent': 'Europe',
                            'contact_mail': 'web@example.test'}, 'x')
        self.cid = A.cert_save(STORE, {'name': 'w1', 'names': ['w1.example.test'],
                                       'issuer': 'self', 'key_type': 'ec-256', 'auto_renew': 0,
                                       'owner': 'Web'}, 'test')
        E.CONFIG.update(mail_mode='smtp', mail_from='acme@example.test')

    def tearDown(self):
        E.CONFIG.update(mail_mode='off', ui_lang='cs')

    def _mails(self, lang):
        E.CONFIG['ui_lang'] = lang
        sent = Sent()
        had = swap('mail_deliver', sent)
        real = threading.Thread

        class Now(object):
            def __init__(self, target=None, **kw):
                self.t = target

            def start(self):
                self.t()
        TP.threading.Thread = Now
        try:
            TP.notify_approvers(STORE, self.cid, 'Web', ['team_or_parent'])
        finally:
            TP.threading.Thread = real
            E.__dict__['mail_deliver'] = had
        return {tuple(to): msg.get_content() for msg, to, _kw in sent.got}

    def test_czech_mail_says_who_in_czech(self):
        got = self._mails('cs')
        self.assertEqual(set(got), {('web@example.test',), ('eu@example.test',)})
        for body in got.values():
            self.assertNotIn('an approver', body)
        self.assertIn('schvalovatel týmu Web.', got[('web@example.test',)])
        self.assertIn('schvalovatel týmu Europe (nad týmem Web)', got[('eu@example.test',)])

    def test_english_mail_as_before(self):
        got = self._mails('en')
        self.assertIn('an approver of the team Web.', got[('web@example.test',)])
        self.assertIn('an approver of the team Europe (above Web)', got[('eu@example.test',)])
        # the events stay in English, as every event
        words = [r['words'] for r in STORE.db.rows(
            "SELECT words FROM events WHERE words LIKE 'w1 waits for%'")]
        self.assertIn('w1 waits for an approver of the team Europe (above Web)', words)


class TitlesInCzech(unittest.TestCase):
    def test_every_title_of_a_message_has_its_czech(self):
        with open(os.path.join(ROOT, 'web', 'lang', 'cs.json'), encoding='utf-8') as f:
            cs = {v['source']: v['text'] for v in json.load(f)['strings'].values()
                  if v.get('text')}
        scratch = os.environ.get('ACME_HUNT_CS') or os.path.join(
            '/tmp/claude-0/-home-user-ACME/845070b5-9900-5dee-8b93-2de7397138a5/scratchpad/'
            'huntr/cs_ru3_notify.json')
        if os.path.exists(scratch):
            with open(scratch, encoding='utf-8') as f:
                cs.update(json.load(f))
        missing = [m['title'] for m in E.TEXT_MESSAGES
                   if m['group'] == 'certs' and m['title'] not in cs]
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
