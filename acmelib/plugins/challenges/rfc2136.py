# -*- coding: utf-8 -*-
"""DNS-01 by RFC 2136 dynamic update, signed with TSIG (RFC 8945) - BIND, Knot,
PowerDNS; Windows DNS with "nonsecure and secure" updates and no key (it signs
only with GSS-TSIG). The UPDATE is written and signed here, no nsupdate needed."""
from __future__ import annotations

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import PROPAGATION_FIELDS, DnsChallenge

ALGS = [['hmac-sha256', 'hmac-sha256'], ['hmac-sha512', 'hmac-sha512'],
        ['hmac-sha384', 'hmac-sha384'], ['hmac-sha224', 'hmac-sha224'],
        ['hmac-sha1', 'hmac-sha1'], ['hmac-md5', 'hmac-md5 (old)']]

WHY = {
    D.REFUSED: 'the server refuses updates from acme with this key: allow it in its '
               'update-policy / allow-update (BIND), ACL (Knot), TSIG-ALLOW-DNSUPDATE '
               '(PowerDNS) or "Dynamic updates" (Windows)',
    D.NOTAUTH: 'the server is not the primary of that zone, or the TSIG key is not known to it',
    D.NOTZONE: 'the name is not inside the zone the update was sent for',
    D.SERVFAIL: 'the server failed to apply it (its log says why: a journal it cannot write?)',
    D.NOTIMP: 'the server does not take dynamic updates',
    D.FORMERR: 'the server could not read the update',
    D.YXDOMAIN: 'a prerequisite failed', D.NXRRSET: 'a prerequisite failed',
}


class Rfc2136(DnsChallenge):
    kind = 'rfc2136'
    title = 'RFC 2136 dynamic update (BIND, Knot, PowerDNS, Windows DNS)'
    vendor = 'DNS'
    description = ('Dynamic DNS UPDATE, signed with a TSIG key, sent to the zone\'s primary '
                   'name server.')
    fields = [
        field('server', 'Primary server', 'hostport', required=True,
              placeholder='ns1.example.com:53',
              help='The name server that takes updates (the zone\'s primary), host or '
                   'address, port 53 unless said.'),
        field('zone', 'Zone', 'text', default='', placeholder='example.com',
              help='Empty: found by asking the server (then DNS) for the SOA of the name.'),
        field('tsig_name', 'TSIG key name', 'text', default='', placeholder='acme-key',
              help='As in the server\'s key statement (tsig-keygen -a hmac-sha256 acme-key). '
                   'Empty: unsigned (only for a server that allows it by address).'),
        field('tsig_alg', 'TSIG algorithm', 'select', default='hmac-sha256', options=ALGS),
        field('tsig_secret', 'TSIG secret', 'secret',
              help='The base64 secret of the key (secret "...";).'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('transport', 'Sent over', 'select', default='tcp', advanced=True,
              options=[['tcp', 'TCP'], ['udp', 'UDP (TCP when cut short)']]),
    ] + PROPAGATION_FIELDS

    def _server(self):
        host, port = D.split_hostport(self.c('server', ''))
        if not host:
            raise PluginError('the primary server is not set', retry=False)
        addrs = D.addresses(host, self.resolvers())
        if not addrs:
            raise PluginError('%s cannot be looked up' % host)
        return addrs[0], port, host

    def _key(self):
        name = (self.c('tsig_name', '') or '').strip()
        if not name:
            return None, None, None
        secret = self.c('tsig_secret', '')
        if not secret:
            raise PluginError('the TSIG key %s has no secret set' % name, retry=False)
        try:
            D.tsig_secret(secret)
        except ValueError as e:
            raise PluginError(str(e), retry=False)
        return name, secret, self.c('tsig_alg', 'hmac-sha256')

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        try:
            addr, port, _h = self._server()
            labels = D.norm(fqdn).split('.')
            for i in range(len(labels) - 1):
                cand = '.'.join(labels[i:])
                m = D.query(addr, cand, 6, port=port, rd=False)
                for r in m.answer + m.authority:
                    if r.rtype == 6 and D.in_zone(fqdn, r.name):
                        return D.norm(r.name)
                if m.rcode == D.REFUSED:
                    break
        except (D.DnsError, D.FormErr, OSError, PluginError):
            pass
        return None

    def _send(self, msg, what):
        addr, port, host = self._server()
        name, secret, alg = self._key()
        try:
            ans = D.send_update(addr, msg, port=port, keyname=name, secret=secret, alg=alg,
                                tcp=self.c('transport', 'tcp') == 'tcp')
        except D.DnsError as e:
            raise PluginError('%s: %s' % (host, e))
        except D.FormErr as e:
            raise PluginError('%s answered something that cannot be read: %s' % (host, e))
        if ans.rcode != D.NOERROR:
            rc = D.RCODES.get(ans.rcode, str(ans.rcode))
            raise PluginError('%s said %s to %s: %s' % (host, rc, what, WHY.get(ans.rcode, rc)),
                              retry=ans.rcode in (D.SERVFAIL,))
        return ans

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        self._send(D.make_update(zone, add=[(fqdn, 'TXT', self.ttl(), value)]),
                   'the update of %s' % fqdn)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        self._send(D.make_update(zone, delete=[(fqdn, 'TXT', value)]),
                   'taking %s away' % fqdn)

    def test(self):
        addr, port, host = self._server()
        zone = D.norm(self.c('zone', ''))
        if not zone:
            try:
                D.query(addr, '.', 6, port=port, rd=False)
            except (D.DnsError, D.FormErr, OSError) as e:
                raise PluginError('%s does not answer DNS on port %d: %s' % (host, port, e))
            return ('%s answers DNS (port %d); set the zone to try the key against it'
                    % (host, port))
        # An UPDATE with one prerequisite (the zone's SOA is there) and nothing
        # to change: the key, the zone and the server are tried, nothing is written.
        self._send(D.make_update(zone, prereq=[(zone, 'SOA')]), 'a trial update of %s' % zone)
        name = self.c('tsig_name', '') or 'no key'
        return ('%s takes updates for %s with %s (a trial update without changes was '
                'accepted)' % (host, zone, name))
