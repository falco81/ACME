# -*- coding: utf-8 -*-
"""DNS-01 through acme's own DNS server (acmelib/certs/dnsserver.py).

The customer's DNS points each _acme-challenge name at acme once:

    _acme-challenge.www.example.com.  CNAME  www.example.com.acme.example.net.

and acme.example.net is delegated to acme (NS records in example.net). acme
then writes the TXT records into its own zone and needs no credentials of
anybody's DNS at all.
"""
from __future__ import annotations

import time

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (DnsChallenge, as_list, base_name, check_txt,
                                                settings)


class BuiltinDns(DnsChallenge):
    kind = 'dns_builtin'
    title = 'acme\'s own DNS server'
    vendor = 'acme'
    description = ('The TXT records are answered by acme\'s own DNS server. Your DNS points '
                   '_acme-challenge.NAME at it once with a CNAME (or delegates a zone to it '
                   'with NS records); no DNS credentials are needed.')
    doc = 'docs/dns-server.md'
    fields = [
        field('zone', 'acme\'s zone', 'text', default='', placeholder='acme.example.net',
              help='One of the zones acme\'s DNS server serves (Settings → DNS server). '
                   'Empty: the first one.'),
        field('scheme', 'Where in that zone', 'select', default='name',
              options=[['name', 'NAME.zone - one record per name (www.example.com.acme.example.net)'],
                       ['label', 'a fixed label - every name in one place (LABEL.zone)'],
                       ['direct', '_acme-challenge.NAME itself - its zone is delegated to acme']],
              help='What _acme-challenge.NAME is made a CNAME to in your DNS. "NAME.zone" '
                   'keeps each name apart; "a fixed label" lets every name share one CNAME '
                   'target (the CA reads all the values there); "itself" is for a zone (or '
                   'the _acme-challenge.NAME subzone) delegated to acme by NS and listed '
                   'among its zones.'),
        field('label', 'The fixed label', 'text', default='validation',
              show_if={'scheme': ['label']},
              help='_acme-challenge.NAME CNAME LABEL.zone for every name.'),
        field('ttl', 'TTL of the records (s)', 'number', default=60, advanced=True),
        field('strict_cname', 'Refuse a name not pointed at acme', 'bool', default=False,
              help='Before the CA is asked, _acme-challenge.NAME is looked up: on, a name '
                   'whose CNAME does not lead to acme fails at once with what to put in your '
                   'DNS; off, it is only said.'),
        field('check_names', 'Names to check in Test', 'list', default='',
              placeholder='www.example.com\nexample.com',
              help='Test looks up each one\'s _acme-challenge CNAME as the CA will.'),
        field('probe', 'Test from outside', 'bool', default=True,
              help='Test puts a short-lived TXT record in and asks public resolvers for it: '
                   'proof that the internet reaches acme\'s DNS server.'),
        field('public_resolvers', 'Public resolvers', 'list', default='1.1.1.1\n8.8.8.8\n9.9.9.9',
              advanced=True),
        field('resolvers', 'Resolvers', 'list', default='', advanced=True,
              help='For looking up the CNAMEs. Empty: Settings → ACME resolvers, else this '
                   'machine\'s.'),
    ]

    # -- acme's zone ----------------------------------------------------------
    def zones(self):
        return [D.norm(z) for z in as_list(settings(self.ctx).get('dns_zone')) if D.norm(z)]

    def zone(self):
        want = D.norm(self.c('zone', ''))
        zs = self.zones()
        if want:
            if zs and want not in zs and not any(D.in_zone(want, z) for z in zs):
                raise PluginError('%s is not a zone of acme\'s DNS server (%s) - Settings → '
                                  'DNS server' % (want, ', '.join(zs)), retry=False)
            return want
        if not zs:
            raise PluginError('acme\'s DNS server has no zone yet: Settings → DNS server → '
                              'zone (e.g. acme.example.net)', retry=False)
        return zs[0]

    def target_of(self, name):
        """Where the TXT record for a name is written in acme's zone."""
        base = base_name(name)
        scheme = self.c('scheme', 'name')
        if scheme == 'direct':
            rr = '_acme-challenge.' + base
            if not any(D.in_zone(rr, z) for z in self.zones()):
                raise PluginError('%s is not inside a zone of acme\'s DNS server (%s): delegate '
                                  'it (or its zone) to acme by NS and add it under Settings → '
                                  'DNS server → zones' % (rr, ', '.join(self.zones()) or 'none'),
                                  retry=False)
            return rr
        zone = self.zone()
        if scheme == 'label':
            label = D.norm(self.c('label', 'validation')) or 'validation'
            return label + '.' + zone
        out = base + '.' + zone
        try:
            D.name_labels(out)
        except ValueError:
            raise PluginError('%s is too long for a name in %s - use a fixed label' % (out, zone),
                              retry=False)
        return out

    def record_name(self, name):
        return '_acme-challenge.' + base_name(name)

    def target(self, rr):
        return self.target_of(rr[len('_acme-challenge.'):])

    def zone_for(self, fqdn):
        for z in sorted(self.zones(), key=len, reverse=True):
            if D.in_zone(fqdn, z):
                return z
        return self.zone()

    def zone_hint(self, fqdn):
        return self.zone_for(fqdn)

    # -- the contract ---------------------------------------------------------
    def present(self, name, token, key_authorization, txt_value):
        check_txt(txt_value)
        rr = self.record_name(name)
        fqdn = self.target_of(name)
        if self.flag('strict_cname') and fqdn != rr:
            ok, words = self.cname_ok(rr, fqdn)
            if not ok:
                raise PluginError(words, retry=False)
        self.add_txt(fqdn, txt_value)
        self.ctx.step('%s TXT "%s" put in acme\'s own DNS server' % (fqdn, txt_value))
        return {'rr': rr, 'fqdn': fqdn, 'txt': txt_value, 'at': time.time(), 'h': None}

    def add_txt(self, fqdn, value):
        self.ctx.dns_put(fqdn, 'TXT', value, ttl=self.ttl())
        return None

    def del_txt(self, fqdn, value, handle):
        try:
            self.ctx.dns_drop(fqdn, 'TXT', value)
        except Exception as e:                          # noqa: BLE001
            self.ctx.step('%s TXT could not be taken away: %s' % (fqdn, e), 'warn')

    def ready(self, name, handle):
        handle = handle or {}
        fqdn, rr, txt = handle.get('fqdn'), handle.get('rr'), handle.get('txt')
        if fqdn and rr and fqdn != rr and not self._said.get('cname:' + rr):
            ok, words = self.cname_ok(rr, fqdn)
            self.say_once('cname:' + rr, words, 'ok' if ok else 'warn')
        host, port = D.own_server_address(settings(self.ctx))
        try:
            got = D.txt_at(host, fqdn, port=port, timeout=2.0)
        except (D.DnsError, D.FormErr, OSError) as e:
            n = self._said.get('fails', 0) + 1
            self._said['fails'] = n
            if n >= 3:
                raise PluginError('acme\'s own DNS server does not answer on %s port %d (%s) - '
                                  'Settings → DNS server says why' % (host, port, e))
            return False
        if txt in got:
            self.say_once('own:' + fqdn, '%s TXT is answered by acme\'s DNS server' % fqdn, 'ok')
            return True
        return False

    # -- the customer's side ------------------------------------------------------
    def cname_ok(self, rr, fqdn):
        """(ok, words): whether _acme-challenge.NAME leads to acme's record."""
        try:
            chain = D.follow_cname(rr, self.resolvers())
        except D.DnsError as e:
            return False, '%s could not be looked up (%s)' % (rr, e)
        if chain[-1] == D.norm(fqdn):
            return True, '%s is a CNAME to %s, as it should be' % (rr, fqdn)
        if len(chain) == 1:
            return False, ('%s is not pointed at acme: put "%s. CNAME %s." in your DNS'
                           % (rr, rr, fqdn))
        return False, ('%s leads to %s, not %s: change that CNAME to "%s."'
                       % (rr, chain[-1], fqdn, fqdn))

    def instructions(self):
        cfg = settings(self.ctx)
        zone = self.zone()
        ns = [D.norm(x) for x in as_list(cfg.get('dns_ns_names'))] or ['ns1.' + zone]
        lines = ['Once, in the zone above %s (its parent): %s' % (
            zone, '; '.join('%s. NS %s.' % (zone, n) for n in ns))]
        glue = as_list(cfg.get('dns_ns_addresses'))
        if any(D.in_zone(n, zone) for n in ns):
            lines.append('  and glue for the name servers inside it: %s' % (
                ', '.join(glue) or 'Settings → DNS server → addresses (none set!)'))
        scheme = self.c('scheme', 'name')
        if scheme == 'name':
            lines.append('Once for each name, in its own DNS: _acme-challenge.NAME. CNAME '
                         'NAME.%s.  (e.g. _acme-challenge.www.example.com. CNAME '
                         'www.example.com.%s.; a wildcard *.example.com uses example.com)'
                         % (zone, zone))
        elif scheme == 'label':
            lines.append('Once for each name, in its own DNS: _acme-challenge.NAME. CNAME '
                         '%s.%s.' % (D.norm(self.c('label', 'validation')), zone))
        else:
            lines.append('Delegate _acme-challenge.NAME (or the whole zone) to acme: '
                         '_acme-challenge.NAME. NS %s. - and add it to acme\'s zones'
                         % ns[0])
        lines.append('acme\'s DNS server must be reachable from the internet on UDP and TCP '
                     'port 53 (a port forward or a public address).')
        return lines

    def test(self):
        out, bad = list(self.instructions()), []
        cfg = settings(self.ctx)
        zone = self.zone()
        host, port = D.own_server_address(cfg)
        try:
            m = D.query(host, zone, 6, port=port, rd=False, timeout=2.0)
            if m.rcode == D.NOERROR and m.records(6):
                out.append('acme\'s DNS server answers for %s on %s port %d' % (zone, host, port))
            else:
                bad.append('acme\'s DNS server said %s for %s - is %s among its zones?'
                           % (D.RCODES.get(m.rcode, m.rcode), zone, zone))
        except (D.DnsError, D.FormErr, OSError) as e:
            bad.append('acme\'s DNS server does not answer on %s port %d (%s) - Settings → '
                       'DNS server says why' % (host, port, e))
        pub = self.lst('public_resolvers') or list(D.PUBLIC_RESOLVERS)
        want_ns = set(D.norm(x) for x in as_list(cfg.get('dns_ns_names'))) or {'ns1.' + zone}
        try:
            m = D.ask_any(pub, zone, 2)
            got = {D.norm(r.text) for r in m.answer if r.rtype == 2}
            if got and got & want_ns:
                out.append('the internet sends %s to %s' % (zone, ', '.join(sorted(got))))
            elif got:
                bad.append('the internet sends %s to %s, not to acme (%s)' % (
                    zone, ', '.join(sorted(got)), ', '.join(sorted(want_ns))))
            else:
                bad.append('%s is not delegated to acme yet: the NS records above are missing'
                           % zone)
        except D.DnsError as e:
            out.append('the delegation of %s could not be checked: %s' % (zone, e))
        if self.flag('probe') and not bad:
            label = D.random_label() + '.' + zone
            val = D.random_label(16)
            try:
                self.ctx.dns_put(label, 'TXT', val, ttl=5)
                time.sleep(1.5)
                seen = False
                for srv in pub:
                    try:
                        if val in D.txt_at(srv, label, rd=True):
                            seen = True
                            out.append('a test record was seen through %s: the internet '
                                       'reaches acme\'s DNS server' % srv)
                            break
                    except (D.DnsError, D.FormErr, OSError):
                        continue
                if not seen:
                    bad.append('a test record in %s was not seen through %s - is UDP/TCP port '
                               '53 of acme reachable from the internet?' % (zone, ', '.join(pub)))
            finally:
                try:
                    self.ctx.dns_drop(label, 'TXT', val)
                except Exception:                       # noqa: BLE001
                    pass
        for n in self.lst('check_names'):
            try:
                ok, words = self.cname_ok(self.record_name(n), self.target_of(n))
            except PluginError as e:
                ok, words = False, str(e)
            (out if ok else bad).append(words)
        if bad:
            raise PluginError('; '.join(bad), detail='\n'.join(out + bad))
        return '\n'.join(out)
