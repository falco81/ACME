# -*- coding: utf-8 -*-
"""DNS-01 in the DNS of a HestiaCP server, through its API (1.0.27) - a POST
of a form to /api/ that runs one v-* command:

    hash=ACCESS_KEY:SECRET_KEY&returncode=no&cmd=v-list-dns-domains&arg1=USER&arg2=json
                                                     {example.com: {...}, ...}
    ...cmd=v-list-dns-records&arg1=USER&arg2=DOMAIN&arg3=json
                                                     {ID: {RECORD, TYPE, VALUE, ID, TTL}, ...}
    ...returncode=yes&cmd=v-add-dns-record&arg1=USER&arg2=DOMAIN&arg3=RECORD&arg4=TXT&arg5=VALUE
         [&arg6=(priority)&arg7=(id)&arg8=yes&arg9=TTL]                       -> 0
    ...returncode=yes&cmd=v-delete-dns-record&arg1=USER&arg2=DOMAIN&arg3=ID   -> 0

https://{server}:8083/api/. With returncode=yes the answer is the command's
exit code (0 OK, 1 E_ARGS, 2 E_INVALID, 3 E_NOTEXIST, 4 E_EXISTS, 10
E_FORBIDEN, 11 E_DISABLED, 20 E_RESTART, ...), said in words when it is not 0.
The access key is the user's own (its "user" argument must be the key's user)
or an administrator's; the API answers only the addresses allowed for it.

Each value is a record of its own with its ID: v-add-dns-record returns no ID,
so the records at the name are listed and ours found by its value; cleanup
deletes only those IDs. The name is relative to the zone, the value without
quotes ("Rest of record types will be striped of quotes"). Each command raises
the zone's serial, writes the zone and reloads the DNS server itself (and
queues the change for a DNS cluster). The TTL is sent only when it is set
(else the zone's).

Sources (the user's collection, api-docs/hestiacp/notes.md):
https://hestiacp.com/docs/server-administration/rest-api.html (access keys,
allowed addresses, the exit codes), https://hestiacp.com/docs/reference/api.html
(the "hash" form), https://hestiacp.com/docs/reference/cli.html
(v-add-dns-record, v-delete-dns-record, v-list-dns-domains, v-list-dns-records),
https://github.com/hestiacp/hestiacp-api-examples and the source of
web/api/index.php and bin/v-add-dns-record, bin/v-delete-dns-record,
bin/v-list-dns-records (the JSON they print).

Less certain: the JSON of v-list-dns-domains is not documented in detail (its
keys are taken for the domains); how empty arguments 6 and 7 are taken when
a TTL (argument 9) is sent (as "not given" - the command then picks the next
free ID); no lowest or highest TTL is documented; which HTTP status an exit
code other than 0 maps to with returncode=no (any status other than 200/204
is an error said in words).
"""
from __future__ import annotations

import json
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, as_bool, http_call,
                                                relative, said_error)
from acmelib.plugins.challenges._records import RecordApiDns, SoftZones, rel_name, zone_field

EXIT_WORDS = {1: 'not enough arguments (E_ARGS)',
              2: 'an object or argument is not valid (E_INVALID)',
              3: 'the object does not exist (E_NOTEXIST)',
              4: 'the object exists already (E_EXISTS)',
              8: 'the package\'s limit of DNS records is reached (E_LIMIT)',
              10: 'this user may not do it (E_FORBIDEN)',
              11: 'the subsystem is disabled (E_DISABLED)',
              20: 'the service restart failed (E_RESTART)'}


class HestiaCp(SoftZones, RecordApiDns):
    kind = 'hestiacp'
    title = 'HestiaCP'
    vendor = 'HestiaCP'
    who = 'HestiaCP'
    min_ttl = 1                     # none documented
    description = 'TXT records in the DNS zones of a HestiaCP server, through its API.'
    fields = [
        field('host', 'HestiaCP address', 'text', required=True, placeholder='server.example.com',
              help='The HestiaCP server (name, name:port or https://…); the port is 8083 when '
                   'not given.'),
        field('user', 'User', 'text', required=True, default='admin',
              help='The HestiaCP user the DNS domains belong to.'),
        field('access_key', 'Access key', 'text', required=True,
              help='v-add-access-key (or the panel: the user → Access keys): the key\'s ID. '
                   'Allowed: v-list-dns-domains, v-list-dns-records, v-add-dns-record and '
                   'v-delete-dns-record; acme\'s address in the API\'s allowed addresses.'),
        field('secret_key', 'Secret key', 'secret', required=True),
        zone_field(['host', 'user', 'access_key', 'secret_key']),
        field('ttl', 'TTL (s)', 'number', default=0, advanced=True,
              help='0: the zone\'s own TTL.'),
        field('verify_tls', 'Check the server\'s certificate', 'bool', default=True,
              advanced=True),
    ] + PROPAGATION_FIELDS

    def _url(self):
        h = str(self.c('host', '') or '').strip().rstrip('/')
        if not h:
            raise PluginError('the HestiaCP address is not set', retry=False)
        u = urllib.parse.urlsplit(h if '://' in h else 'https://' + h)
        try:
            port = u.port
        except ValueError:
            raise PluginError('the HestiaCP address %s has a port that is not a number' % h,
                              retry=False)
        host = u.hostname or ''
        if ':' in host:
            host = '[%s]' % host
        return '%s://%s:%d/api/' % (u.scheme or 'https', host, port or 8083)

    def _cmd(self, cmd, args, output=False):
        """Run one command: its output parsed (output) or its exit code checked."""
        form = [('hash', '%s:%s' % (self.c('access_key', ''), self.c('secret_key', ''))),
                ('returncode', 'no' if output else 'yes'), ('cmd', cmd)]
        form += [('arg%d' % (i + 1), str(a)) for i, a in enumerate(args)]
        st, rh, got = http_call(self.ctx, 'POST', self._url(), urllib.parse.urlencode(form)
                                .encode(), {'Content-Type': 'application/x-www-form-urlencoded',
                                            'Accept': 'application/json',
                                            'User-Agent': 'acme-challenge'},
                                who='HestiaCP', verify=as_bool(self.c('verify_tls', True)))
        text = (got or b'').decode('utf-8', 'replace') if isinstance(got, bytes) else \
            str(got or '')
        if st not in (200, 204):
            raise said_error('HestiaCP (%s)' % cmd, st, None, got)
        if 'Error:' in text[:200] and not text.lstrip().startswith(('{', '[')):
            raise PluginError('HestiaCP refused %s: %s' % (cmd, text.strip()[:300]),
                              detail=text, retry=False)
        if output:
            if not text.strip():
                return {}
            try:
                got = json.loads(text)
            except ValueError:
                raise PluginError('HestiaCP answered %s with something that is not JSON' % cmd,
                                  detail=text[:300])
            if isinstance(got, int) and not isinstance(got, bool) and got:
                raise PluginError('HestiaCP: %s ended with %d - %s' % (
                    cmd, got, EXIT_WORDS.get(got, 'an error')), retry=got == 20, detail=text)
            return got
        try:
            code = int(text.strip() or '0')
        except ValueError:
            raise PluginError('HestiaCP answered %s with something that is not an exit code'
                              % cmd, detail=text[:300])
        if code:
            raise PluginError('HestiaCP: %s ended with %d - %s' % (
                cmd, code, EXIT_WORDS.get(code, 'an error')), retry=code == 20,
                detail=text)
        return 0

    # -- zones and records ----------------------------------------------------------
    def zone_names(self):
        got = self._cmd('v-list-dns-domains', [self.c('user', ''), 'json'], output=True)
        return [D.norm(k) for k in got] if isinstance(got, dict) else []

    def _rows(self, zone):
        got = self._cmd('v-list-dns-records', [self.c('user', ''), D.norm(zone), 'json'],
                        output=True)
        return [r for r in (got.values() if isinstance(got, dict) else got or [])
                if isinstance(r, dict)]

    def txt_records(self, zone, fqdn):
        rel = relative(fqdn, zone).lower()
        out = []
        for r in self._rows(zone):
            name = str(r.get('RECORD') or '').strip().lower()
            if name.endswith('.'):
                same = D.norm(name) == D.norm(fqdn)
            else:
                same = name == rel or (rel == '@' and name in ('', '@'))
            if str(r.get('TYPE') or '').upper() == 'TXT' and same and r.get('ID'):
                out.append((str(r.get('ID')), str(r.get('VALUE') or '')))
        return out

    def create_txt(self, zone, fqdn, value):
        args = [self.c('user', ''), D.norm(zone), rel_name(fqdn, zone), 'TXT', value]
        ttl = int(self.num('ttl', 0) or 0)
        if ttl > 0:
            args += ['', '', 'yes', ttl]
        self._cmd('v-add-dns-record', args)
        return None                     # no ID comes back: found by its value at cleanup

    def delete_txt(self, zone, fqdn, record_id, value):
        try:
            self._cmd('v-delete-dns-record', [self.c('user', ''), D.norm(zone), record_id])
        except PluginError as e:
            if 'ended with 3 ' not in str(e):           # E_NOTEXIST: gone already
                raise

    def ttl(self):
        return int(self.num('ttl', 0) or 0)

    def test(self):
        z = D.norm(self.c('zone', ''))
        if z:
            return 'HestiaCP: signed in as %s; the zone %s has %d record(s)' % (
                self.c('user', ''), z, len(self._rows(z)))
        return RecordApiDns.test(self)
