# -*- coding: utf-8 -*-
"""DNS-01 by hand: acme says what to put in DNS and waits until it is seen
there (or until somebody says it is there)."""
from __future__ import annotations

import time

from acmelib.plugins.base import field, guide_step
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge, check_txt


class Manual(DnsChallenge):
    kind = 'manual'
    title = 'By hand'
    vendor = 'DNS'
    description = ('acme shows the TXT record to put in your DNS and waits until the zone\'s '
                   'name servers have it. For a renewal nobody watches, choose another way.')
    fields = [
        field('remove_note', 'Say to take it away afterwards', 'bool', default=True),
    ] + PROPAGATION_FIELDS

    def _key(self, handle):
        return 'manual:confirmed:%s:%s' % (handle.get('rr'), handle.get('txt'))

    def present(self, name, token, key_authorization, txt_value):
        check_txt(txt_value)
        rr = self.record_name(name)
        fqdn = self.target(rr)
        self.ctx.step('Put this in your DNS now:   %s.  60  IN  TXT  "%s"   - acme waits until '
                      'the name servers of the zone have it' % (fqdn, txt_value), 'warn')
        h = {'rr': rr, 'fqdn': fqdn, 'txt': txt_value, 'at': time.time(), 'h': None}
        try:
            self.ctx.kv_set('manual:waiting:%s' % rr, txt_value, ttl_s=86400)
        except Exception:                               # noqa: BLE001
            pass
        return h

    def ready(self, name, handle):
        handle = handle or {}
        try:
            if self.ctx.kv_get(self._key(handle)):
                self.say_once('confirmed', 'said to be in DNS', 'ok')
                return True
        except Exception:                               # noqa: BLE001
            pass
        if self.c('propagation', 'auth') == 'none':
            return False                                # only the confirmation counts
        return DnsChallenge.ready(self, name, handle)

    def cleanup(self, name, handle):
        handle = handle or {}
        try:
            self.ctx.kv_set('manual:waiting:%s' % handle.get('rr'), '', ttl_s=1)
        except Exception:                               # noqa: BLE001
            pass
        if self.flag('remove_note') and handle.get('fqdn'):
            self.ctx.step('the TXT record %s "%s" may be taken out of your DNS again'
                          % (handle['fqdn'], handle.get('txt')))

    def add_cname(self, fqdn, target):
        self.ctx.step('Put this in your DNS now:   %s.  60  IN  CNAME  %s.   - acme waits until '
                      'the name servers of the zone have it' % (D.norm(fqdn), D.norm(target)),
                      'warn')
        return None

    def del_cname(self, fqdn, target, handle):
        if self.flag('remove_note'):
            self.ctx.step('the CNAME record %s may be taken out of your DNS again' % fqdn)

    def add_txt(self, fqdn, value):
        return None

    def del_txt(self, fqdn, value, handle):
        pass

    def test(self):
        return 'nothing to try: the record is put in by hand at every order'

    # -- what a person is told -------------------------------------------------------
    def guide_access(self):
        return []

    def guide_txt(self, fqdn, rr=None):
        try:
            waiting = self.ctx.kv_get('manual:waiting:%s' % (rr or fqdn))
        except Exception:                               # noqa: BLE001
            waiting = None
        what = 'You put the TXT record in by hand at every order'
        try:
            zone = self.zone_for(fqdn)
        except Exception:                               # noqa: BLE001
            zone = D.registrable(fqdn)
        where = 'your DNS at %s' % zone
        if not waiting:
            return guide_step('txt', what, where=where,
                              record={'name': fqdn, 'type': 'TXT',
                                      'value': '(acme shows it at every order)', 'ttl': 60},
                              done=None, blocking=False,
                              said='at each order acme shows the value and waits until the '
                                   'name servers of %s have it' % zone)
        state = self.seen_by_authority(fqdn, waiting)
        return guide_step('txt', what, where=where,
                          record={'name': fqdn, 'type': 'TXT', 'value': waiting, 'ttl': 60},
                          done=state, blocking=False,
                          said={True: 'every name server of %s has it' % zone,
                                False: 'not on every name server of %s yet' % zone,
                                None: 'the name servers of %s cannot be asked' % zone}[state],
                          fix='Put it in your DNS now: %s. 60 IN TXT "%s"' % (fqdn, waiting))

