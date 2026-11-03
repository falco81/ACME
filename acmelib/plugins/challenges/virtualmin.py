# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a Virtualmin server, through its Remote API
(remote.cgi, 1.0.27) - a POST that runs one of Virtualmin's command-line
programs, its parameters as CGI parameters:

    POST https://{server}:10000/virtual-server/remote.cgi
         program=list-domains&with-feature=dns&name-only=      the virtual servers with DNS
         program=get-dns&domain=Z&type=TXT&multiline=          the TXT records of the zone
         program=modify-dns&domain=Z&add-record-with-ttl=<"NAME. TXT TTL VALUE">
         program=modify-dns&domain=Z&remove-record=<"NAME. TXT VALUE">

HTTP basic authentication as the master administrator (the Remote API is open
to it only). The answer is the program's output followed by "Exit status: N";
a status other than 0 (or an "ERROR:" answer) is said in words. A parameter
`name=value` is the option `--name value`, an empty value the bare option.

The name is written whole with its final dot (Virtualmin takes a name ending
in a dot as it is, and appends the domain to any other). The record is always
taken away with its value: --remove-record "without values" deletes every
record of that name and type, "you can also optionally include the record
values" - so other orders' values at the name stay. modify-dns raises the
serial and reloads BIND (or a cloud DNS provider set in Virtualmin) itself.
It does not refuse a record that clashes or is outside the domain - it only
prints a line - so after each change the zone's TXT records are read again
and a change that did not happen is said in the job.

The zone is the virtual server (its DNS domain); a sub-server may keep its
records in its parent's zone - set the zone then.

Sources (the user's collection, api-docs/virtualmin/notes.md):
https://www.virtualmin.com/docs/development/remote-api/,
https://www.virtualmin.com/docs/development/api-programs/modify-dns/,
https://www.virtualmin.com/docs/development/api-programs/get-dns/,
https://www.virtualmin.com/docs/development/api-programs/list-domains/ and the
source of virtualmin-gpl (remote.cgi - parameters to options, the exit status
line; modify-dns.pl - add/remove, the values filter; feature-dns.pl
expand_dns_record).

Less certain: the output of get-dns is not documented beyond its options -
acme only looks for our value in it (with --multiline, the full values); the
JSON form (json=1) is not documented and is not used; whether a TXT value is
stored with quotes (sent without; the removal compares values as Virtualmin
reads them); no lowest TTL is documented (60 is used); the Remote API has no
token or address limit of its own - only the master administrator's
password.
"""
from __future__ import annotations

import re
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, ApiDns, as_bool, http_call,
                                                rmw_lock, said_error)
from acmelib.plugins.challenges._records import SoftZones, basic, zone_field

EXIT = re.compile(r'^Exit status:\s*(-?\d+)\s*$', re.M)


class Virtualmin(SoftZones, ApiDns):
    kind = 'virtualmin'
    title = 'Virtualmin'
    vendor = 'Virtualmin'
    who = 'Virtualmin'
    min_ttl = 60
    description = 'TXT records in the DNS of a Virtualmin server, through its Remote API.'
    fields = [
        field('host', 'Virtualmin address', 'text', required=True,
              placeholder='server.example.com',
              help='The Webmin/Virtualmin server (name, name:port or https://…); the port is '
                   '10000 when not given.'),
        field('user', 'Master administrator', 'text', required=True, default='root',
              help='Virtualmin opens its Remote API to the master administrator only.'),
        field('password', 'Password', 'secret', required=True),
        zone_field(['host', 'user', 'password'], label='Virtual server',
                   help='The domain whose DNS zone holds the name. Load the list and pick it, '
                        'or type it. Empty: the longest of the servers with DNS the name is in '
                        '- else the zone by its SOA.'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _url(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the Virtualmin address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the Virtualmin address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d/virtual-server/remote.cgi' % (u.scheme or 'https', host,
                                                          port or 10000)

    def _run(self, program, params):
        """The output of one program (its "Exit status:" line checked)."""
        body = urllib.parse.urlencode([('program', program)] + list(params)).encode()
        st, _rh, got = http_call(self.ctx, 'POST', self._url(), body, {
            'Authorization': basic(self.c('user', ''), self.c('password', '')),
            'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'acme-challenge'},
            who='Virtualmin', verify=as_bool(self.c('verify_tls', True)))
        text = (got or b'').decode('utf-8', 'replace') if isinstance(got, bytes) else \
            str(got or '')
        if st != 200:
            raise said_error('Virtualmin', st, None, got)
        if text.lstrip().startswith('ERROR'):
            raise PluginError('Virtualmin refused %s: %s' % (program, text.strip()[:300]),
                              detail=text, retry=False)
        m = EXIT.findall(text)
        if not m:
            raise PluginError('Virtualmin answered %s without an exit status - is this the '
                              'Virtualmin address?' % program, detail=text[:300])
        if int(m[-1]) != 0:
            said = EXIT.sub('', text).strip()
            raise PluginError('Virtualmin: %s ended with %s: %s' % (program, m[-1],
                                                                    said[-300:] or 'no words'),
                              detail=text)
        return EXIT.sub('', text)

    # -- zones and records ----------------------------------------------------------
    def zone_names(self):
        out = self._run('list-domains', [('with-feature', 'dns'), ('name-only', '')])
        return [D.norm(line) for line in out.splitlines()
                if line.strip() and ' ' not in line.strip()]

    def _txt_text(self, zone):
        return self._run('get-dns', [('domain', D.norm(zone)), ('type', 'TXT'),
                                     ('multiline', '')])

    def _has(self, zone, value):
        """Whether the zone's TXT records show our value (as a word of its own)."""
        return re.search(r'(?<![A-Za-z0-9_-])%s(?![A-Za-z0-9_-])' % re.escape(value),
                         self._txt_text(zone)) is not None

    def add_txt(self, fqdn, value):
        zone = self.zone_for(fqdn)
        with rmw_lock('virtualmin|%s|%s' % (self._url(), zone)):
            if not self._has(zone, value):
                self._run('modify-dns', [('domain', D.norm(zone)), (
                    'add-record-with-ttl', '%s. TXT %d %s' % (D.norm(fqdn), self.ttl(), value))])
                if not self._has(zone, value):
                    raise PluginError('Virtualmin did not add the TXT record %s to %s (a clash, '
                                      'or the name is not in that domain\'s zone - set the '
                                      'virtual server)' % (fqdn, zone), retry=False)
        return {'zone': zone}

    def del_txt(self, fqdn, value, handle):
        zone = (handle or {}).get('zone') or self.zone_for(fqdn)
        with rmw_lock('virtualmin|%s|%s' % (self._url(), zone)):
            if not self._has(zone, value):
                return
            self._run('modify-dns', [('domain', D.norm(zone)), (
                'remove-record', '%s. TXT %s' % (D.norm(fqdn), value))])
            if self._has(zone, value):
                self.ctx.step('Virtualmin still lists %s TXT "%s" - take it away by hand' % (
                    fqdn, value), 'warn')

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            n = len([x for x in self._txt_text(z).splitlines() if x.strip()])
            return 'Virtualmin: signed in; get-dns reads the zone %s (%d line(s) of TXT ' \
                   'records)' % (z, n)
        return ApiDns.test(self)
