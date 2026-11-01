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

from acmelib.plugins.base import PluginError, field, guide_of, guide_step
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
        field('public_resolvers', 'Public resolvers', 'list', default='',
              placeholder='1.1.1.1\n8.8.8.8\n9.9.9.9', advanced=True,
              help='Asked by Test from outside - an override. Empty: Settings → DNS (The '
                   'public view).'),
        field('resolvers', 'Resolvers', 'list', default='', advanced=True,
              help='For looking up the CNAMEs - an override. Empty: Settings → DNS '
                   '(Validation checks).'),
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

    # -- a commercial CA's DCV record: only inside acme's own zones -----------------------
    # acme's DNS server answers its zones and nothing else; _dnsauth.NAME (DigiCert) or
    # NAME itself sits in the customer's DNS, so the record can be written here only
    # when that name is inside a zone of acme's (delegated to it by NS).
    def add_cname(self, fqdn, target):
        self.ctx.dns_put(fqdn, 'CNAME', D.norm(target) + '.', ttl=self.ttl())
        return None

    def del_cname(self, fqdn, target, handle):
        try:
            self.ctx.dns_drop(fqdn, 'CNAME', D.norm(target) + '.')
        except Exception as e:                          # noqa: BLE001
            self.ctx.step('%s CNAME could not be taken away: %s' % (fqdn, e), 'warn')

    @staticmethod
    def _zones_of(settings_):
        return [D.norm(z) for z in as_list((settings_ or {}).get('dns_zone')) if D.norm(z)]

    @classmethod
    def place_problem(cls, proof, where, config, settings_):
        if proof == 'acme-dns-01':
            return ''
        if proof not in ('txt-any', 'cname-any'):
            return 'acme\'s own DNS server writes DNS records, not files'
        zones = cls._zones_of(settings_)
        fq = D.norm(where)
        if fq and any(D.in_zone(fq, z) for z in zones):
            return ''
        return ('acme\'s own DNS server answers only its own zones (%s): %s is in your DNS, so '
                'the CA\'s DCV record cannot be put there through it - choose a validation that '
                'writes to your DNS (an API, RFC 2136), or delegate that name to acme by NS'
                % (', '.join(zones) or 'none set', fq or 'the name'))

    def place(self, kind, name, where, content):
        fq = D.norm(where)
        bad = self.place_problem({'txt': 'txt-any', 'cname': 'cname-any'}.get(kind, 'file'), fq,
                                 self.config, settings(self.ctx))
        if bad:
            raise PluginError(bad, retry=False)
        if kind == 'txt':
            self.add_txt(fq, str(content))
            return {'kind': 'txt', 'rr': fq, 'fqdn': fq, 'txt': str(content), 'at': time.time(),
                    'h': None}
        self.add_cname(fq, str(content))
        return {'kind': 'cname', 'rr': fq, 'target': D.norm(content), 'at': time.time(),
                'h': None}

    def placed_ready(self, handle):
        return True                     # answered by acme itself at once

    def del_txt(self, fqdn, value, handle):
        try:
            self.ctx.dns_drop(fqdn, 'TXT', value)
        except Exception as e:                          # noqa: BLE001
            self.ctx.step('%s TXT could not be taken away: %s' % (fqdn, e), 'warn')

    def _own_address(self, cfg):
        """(host, port) acme's DNS server is asked at: where it really answers -
        the VIP when it answers on the VIP only (Settings → DNS server)."""
        answering = None
        info = getattr(self.ctx, 'dns_server_info', None)
        if callable(info):
            try:
                answering = (info() or {}).get('answering')
            except Exception:                           # noqa: BLE001
                answering = None
        return D.own_server_address(cfg, answering)

    def ready(self, name, handle):
        handle = handle or {}
        fqdn, rr, txt = handle.get('fqdn'), handle.get('rr'), handle.get('txt')
        if fqdn and rr and fqdn != rr and not self._said.get('cname:' + rr):
            ok, words = self.cname_ok(rr, fqdn)
            self.say_once('cname:' + rr, words, 'ok' if ok else 'warn')
        host, port = self._own_address(settings(self.ctx))
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

    # -- what a person is told -------------------------------------------------------
    def guide(self, name):
        try:
            base = base_name(name)
        except PluginError as e:
            return guide_of([guide_step('name', 'The name can be proved by DNS-01', done=False,
                                        said=str(e), fix='Correct the name')])
        info = self.ctx.dns_server_info() or {}
        steps = []
        try:
            self.zone()
            target = self.target_of(name)
        except PluginError as e:
            return guide_of([guide_step('server', 'acme\'s own DNS server has a zone',
                                        where='acme', done=False, said=str(e),
                                        fix='Settings → DNS server: switch it on and give it '
                                            'its zone (e.g. acme.example.net)')])
        rr = self.record_name(name)
        scheme = self.c('scheme', 'name')
        served = self.zone_for(target)
        steps.append(self.guide_server(served, info))
        steps += self.guide_delegation(served, info)
        home = self.home_of(base)
        if scheme == 'direct':
            pass                # the delegation of the zone holding rr is the whole of it
        else:
            chain = self.cname_chain(rr)
            rec = {'name': rr, 'type': 'CNAME', 'value': target + '.', 'ttl': 3600}
            what = 'The name is pointed at acme\'s DNS server by a CNAME'
            where = 'your DNS at %s' % home
            if chain[-1] == D.norm(target):
                steps.append(guide_step('cname', what, where=where, record=rec, done=True,
                                        said='%s is a CNAME to %s' % (rr, target)))
            elif len(chain) == 1:
                steps.append(guide_step('cname', what, where=where, record=rec, done=False,
                                        said='%s has no CNAME' % rr,
                                        fix='Create in the DNS of %s: %s. CNAME %s.' % (
                                            home, rr, target)))
            else:
                steps.append(guide_step('cname', what, where=where, record=rec, done=False,
                                        said='%s is a CNAME that leads to %s' % (rr, chain[-1]),
                                        fix='Change the CNAME in the DNS of %s: %s. CNAME %s.'
                                            % (home, rr, target)))
        port = int(info.get('port') or 53)
        fw = [self.ctx.port_open(p, port) for p in ('udp', 'tcp')]
        if False in fw:
            steps.append(guide_step(
                'reach', 'The internet reaches acme\'s DNS server', where='acme', done=False,
                said='acme\'s firewall does not let UDP and TCP port %d in from anywhere' % port,
                fix='Settings → Firewall: let in UDP and TCP port %d (the card "DNS server")'
                    % port))
        else:
            steps.append(guide_step(
                'reach', 'The internet reaches acme\'s DNS server', where='acme', done=None,
                blocking=False,
                said='UDP and TCP port %d must reach acme from the internet (a public address '
                     'or a port forward) - the dry run tries it' % port))
        steps.append(guide_step('txt', 'acme writes the TXT record itself at every order',
                                where='acme', record={'name': target, 'type': 'TXT',
                                                      'value': '(new at every order)',
                                                      'ttl': self.ttl()},
                                done=None, blocking=False,
                                said='nothing to create by hand: acme\'s own DNS server '
                                     'answers %s' % target))
        return guide_of(steps)

    def guide_server(self, zone, info):
        host, port = self._own_address(settings(self.ctx))
        what = 'acme\'s own DNS server answers for its zone'
        try:
            m = D.query(host, zone, 6, port=port, rd=False, timeout=self.guide_timeout)
        except (D.DnsError, D.FormErr, OSError) as e:
            return guide_step('server', what, where='acme', done=False,
                              said='no answer on %s port %d: %s' % (host, port, e),
                              fix='Settings → DNS server: switch it on (it says why it does '
                                  'not listen)')
        if m.rcode == D.NOERROR and m.records(6):
            return guide_step('server', what, where='acme', done=True,
                              said='it answers for %s on %s port %d' % (zone, host, port))
        return guide_step('server', what, where='acme', done=False,
                          said='it said %s for %s' % (D.RCODES.get(m.rcode, m.rcode), zone),
                          fix='Settings → DNS server: add %s to its zones' % zone)

    def guide_delegation(self, zone, info):
        """The steps: acme's zone delegated to it by NS records in its parent,
        with glue for name servers inside it, reaching the addresses acme
        answers on."""
        zone = D.norm(zone)
        parent = zone.split('.', 1)[1] if '.' in zone else zone
        want_ns = [D.norm(n) for n in (info.get('ns') or [])] or ['ns1.' + zone]
        glue = {D.norm(k): list(v) for k, v in (info.get('glue') or {}).items()}
        expect = set(info.get('answering') or []) | {a for v in glue.values() for a in v}
        steps = []
        got_ns, err = set(), ''
        try:
            m = D.ask_any(self.resolvers(), zone, 2, self.guide_timeout)
            got_ns = {D.norm(r.text) for r in m.answer + m.authority if r.rtype == 2 and
                      D.norm(r.name) == zone}
        except (D.DnsError, D.FormErr, OSError) as e:
            err = str(e)
        where = 'the DNS of %s (the parent zone)' % parent
        for ns in want_ns:
            rec = {'name': zone, 'type': 'NS', 'value': ns + '.', 'ttl': 3600}
            what = 'acme\'s zone is delegated to acme\'s DNS server'
            if ns in got_ns:
                steps.append(guide_step('delegation', what, where=where, record=rec, done=True,
                                        said='%s NS %s' % (zone, ns)))
            elif err:
                steps.append(guide_step('delegation', what, where=where, record=rec, done=None,
                                        blocking=False,
                                        said='the NS records of %s could not be looked up: %s'
                                             % (zone, err)))
            else:
                steps.append(guide_step(
                    'delegation', what, where=where, record=rec, done=False,
                    said=('%s is sent to %s' % (zone, ', '.join(sorted(got_ns)))) if got_ns
                    else '%s is not delegated' % zone,
                    fix='Create in the DNS of %s: %s. NS %s.' % (parent, zone, ns)))
        for ns in want_ns:
            inside = D.in_zone(ns, zone)
            addrs = glue.get(ns) or sorted(expect)
            what = 'The name server %s has acme\'s address' % ns
            if not addrs:
                steps.append(guide_step(
                    'glue', what, where=where if inside else 'your DNS', done=None,
                    blocking=False, said='acme knows no public address of its own',
                    fix='Settings → DNS server: set its addresses'))
                continue
            seen = D.addresses(ns, self.resolvers(), timeout=self.guide_timeout)
            ok = bool(set(seen) & (expect or set(addrs)))
            for a in addrs[:2]:
                rec = {'name': ns, 'type': 'AAAA' if ':' in a else 'A', 'value': a, 'ttl': 3600}
                # another address than acme knows (a NAT in front): said, not blocking
                steps.append(guide_step(
                    'glue', what, where=(where + ', as glue') if inside else 'the DNS of %s'
                    % D.registrable(ns), record=rec, done=ok, blocking=not seen,
                    said=('%s has the address %s' % (ns, ', '.join(seen))) if seen else
                    '%s has no address' % ns,
                    fix='Create the record %s. %s %s%s' % (ns, rec['type'], a, ' (glue, at the registrar '
                                                'or in %s)' % parent if inside else '')))
        return steps

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
        host, port = self._own_address(cfg)
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
        pub = D.resolver('public', self.lst('public_resolvers'), self.ctx)
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
