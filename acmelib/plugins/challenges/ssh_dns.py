# -*- coding: utf-8 -*-
"""DNS-01 by commands run over SSH on the DNS server itself - the record put
straight into the zones the server there holds:

    BIND        nsupdate -l (its local session key), nsupdate -k KEYFILE, or the
                zone file edited (acme's own lines only, the serial raised,
                named-checkzone, rndc reload - rndc freeze/thaw for a dynamic zone)
    PowerDNS    pdnsutil (add-record / replace-rrset / delete-rrset, rectify-zone),
                or its HTTP API on that machine (curl there, the key never on a
                command line)
    Knot DNS    knotc zone-begin / zone-set / zone-unset / zone-commit (abort on error)
    NSD         the zone file edited, nsd-checkzone, nsd-control reload
    dnsmasq     txt-record lines in a file of acme's own, dnsmasq --test, a restart
    Unbound     unbound-control local_data / local_data_remove (in memory)
    Windows DNS PowerShell's DnsServer cmdlets (OpenSSH for Windows)
    custom      commands of your own

"Find out what runs there" (discover(), the page's button, the action "discover")
signs in and runs read-only commands only (_sshdns.READ_ONLY): which server, its
zones, their files, keys, whether sudo works - and fills in the form; every field
can be set by hand as well."""
from __future__ import annotations

import json
import re
import urllib.parse

from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges import _dns as D
from acmelib.plugins.challenges import _sshdns as X
from acmelib.plugins.challenges._common import (PROPAGATION_FIELDS, DnsChallenge,
                                                longest_zone, relative, rmw_lock, shq, ssh_conn,
                                                ssh_fields, unquote_txt)

SAFE = re.compile(r'^[A-Za-z0-9_.@*-]+$')
UNIX = ('bind_file', 'pdnsutil', 'pdns_api', 'knot', 'nsd', 'dnsmasq', 'unbound')
BIND = ['nsupdate_local', 'nsupdate_key', 'bind_file']
ZONEFILE = ['bind_file', 'nsd']


def _ps(s):
    """A word for PowerShell, in single quotes."""
    return "'" + str(s).replace("'", "''") + "'"


def _curl_q(s):
    """A value of a curl config file, in double quotes."""
    return '"' + str(s).replace('\\', '\\\\').replace('"', '\\"') + '"'


class SshDns(DnsChallenge):
    kind = 'ssh_dns'
    guide_needs_dry_run = True
    title = 'Commands on the DNS server over SSH'
    vendor = 'DNS'
    description = ('acme signs in to the DNS server over SSH and puts the record straight '
                   'into its zones: BIND (nsupdate or the zone file), PowerDNS, Knot DNS, NSD, '
                   'dnsmasq, Unbound, Windows DNS, or commands of your own. "Find out what runs '
                   'there" reads what the server is and fills the form in.')
    actions = [{'key': 'discover', 'label': 'Find out what runs there',
                'help': 'Signs in over SSH and runs read-only commands only: which DNS server '
                        'runs there, its zones, their files and keys, whether sudo works. '
                        'Nothing is written, reloaded or restarted.', 'changes': False}]
    fields = [
        field('host', 'DNS server', 'hostport', required=True, placeholder='ns1.example.com:22'),
    ] + ssh_fields(user='acme') + [
        field('flavour', 'How', 'select', default='nsupdate_local',
              options=[['nsupdate_local', 'nsupdate -l (BIND on that machine, its session key)'],
                       ['nsupdate_key', 'nsupdate -k KEYFILE (a TSIG key file there)'],
                       ['bind_file', 'BIND: the zone file edited, then rndc reload'],
                       ['pdnsutil', 'PowerDNS: pdnsutil'],
                       ['pdns_api', 'PowerDNS: its HTTP API on that machine'],
                       ['knot', 'Knot DNS: knotc, in a transaction'],
                       ['nsd', 'NSD: the zone file edited, then nsd-control reload'],
                       ['dnsmasq', 'dnsmasq: txt-record lines in a file of acme\'s own'],
                       ['unbound', 'Unbound: unbound-control local_data (in memory)'],
                       ['powershell', 'Windows DNS: PowerShell DnsServer cmdlets'],
                       ['custom', 'commands of my own']],
              help='"Find out what runs there" below chooses it for you.'),
        field('sudo', 'Through sudo', 'bool', default=False,
              help='Commands run as "sudo -n ..." (a sudoers line for exactly them). Where a '
                   'zone file is edited (BIND\'s zone file, NSD, dnsmasq) the whole script runs '
                   'as "sudo -n sh -s".'),
        field('zone', 'Zone', 'text', default='',
              help='Empty: the longest of "Zones there" the name is in, else found by its SOA. '
                   'Windows DNS needs it right (the zone as in DNS Manager).'),
        field('zones', 'Zones there', 'list', default='', placeholder='example.com\nexample.net',
              help='The zones this server holds (Find out what runs there fills them in): a '
                   'record goes in the longest of them its name is in.'),
        # -- BIND
        field('session_key', 'Session key file', 'text', default='',
              show_if={'flavour': ['nsupdate_local']}, placeholder='/run/named/session.key',
              advanced=True,
              help='Empty: where nsupdate -l looks by itself. Set it when named.conf has a '
                   'session-keyfile of its own.'),
        field('keyfile', 'Key file there', 'text', default='/etc/bind/acme.key',
              show_if={'flavour': ['nsupdate_key']}),
        field('nsupdate_server', 'Server nsupdate sends to', 'text', default='127.0.0.1',
              show_if={'flavour': ['nsupdate_key']}),
        field('zone_files', 'Zone files', 'list', default='',
              show_if={'flavour': ZONEFILE},
              placeholder='example.com /var/lib/bind/db.example.com',
              help='A line a zone: the zone and its file there. acme adds and takes away only '
                   'lines of its own (marked "; acme-challenge"), raises the SOA serial, checks '
                   'the new file before the server reloads it, keeps the old one beside it '
                   '(.FILE.acme-bak) and puts it back when the reload fails. A file it cannot '
                   'read safely ($INCLUDE, no single SOA) is refused.'),
        field('serial', 'Raising the SOA serial', 'select', default='auto',
              show_if={'flavour': ZONEFILE}, advanced=True,
              options=[['auto', 'as it is written: a date (YYYYMMDDnn) or a number + 1'],
                       ['date', 'a date, YYYYMMDDnn'], ['unixtime', 'the time, Unix seconds'],
                       ['increment', 'the number + 1']]),
        field('bind_freeze', 'Freeze a dynamic zone while its file is edited', 'bool',
              default=True, show_if={'flavour': ['bind_file']}, advanced=True,
              help='A zone with a journal (.jnl): rndc freeze before, rndc thaw after. Off: '
                   'such a zone is refused - use nsupdate for it.'),
        field('rndc', 'rndc command', 'text', default='rndc', show_if={'flavour': ['bind_file']},
              advanced=True, placeholder='rndc -c /etc/bind/rndc.conf'),
        field('checkzone', 'Zone check command', 'text', default='named-checkzone',
              show_if={'flavour': ['bind_file']}, advanced=True),
        field('named_conf', 'named.conf', 'text', default='', advanced=True,
              show_if={'flavour': BIND}, placeholder='/etc/bind/named.conf',
              help='Empty: the one named-checkconf reads by itself. Read by "Find out what runs '
                   'there" only.'),
        # -- PowerDNS
        field('pdns_config_dir', 'PowerDNS configuration directory', 'text', default='',
              show_if={'flavour': ['pdnsutil']}, advanced=True, placeholder='/etc/powerdns'),
        field('pdns_api_url', 'PowerDNS API there', 'text', default='http://127.0.0.1:8081',
              show_if={'flavour': ['pdns_api']},
              help='Asked by curl on that machine - the API needs to listen on localhost only.'),
        field('pdns_api_key', 'API key', 'secret', show_if={'flavour': ['pdns_api']},
              help='api-key of pdns.conf. Handed to curl on its input, never on a command line.'),
        field('pdns_server_id', 'Server id', 'text', default='localhost',
              show_if={'flavour': ['pdns_api']}, advanced=True),
        field('pdns_rectify', 'Rectify the zone after a change', 'bool', default=True,
              show_if={'flavour': ['pdnsutil', 'pdns_api']}, advanced=True,
              help='pdnsutil rectify-zone (the API: PUT .../rectify) - what a DNSSEC-signed '
                   'zone needs; harmless for any other.'),
        field('pdns_serial', 'Raise the SOA serial after a change', 'bool', default=True,
              show_if={'flavour': ['pdnsutil']}, advanced=True,
              help='pdnsutil increase-serial - for secondaries that transfer the zone.'),
        # -- Knot
        field('knot_conf', 'knot.conf', 'text', default='', show_if={'flavour': ['knot']},
              advanced=True, placeholder='/etc/knot/knot.conf'),
        field('knot_socket', 'Control socket', 'text', default='', show_if={'flavour': ['knot']},
              advanced=True, placeholder='/run/knot/knot.sock'),
        # -- NSD
        field('nsd_conf', 'nsd.conf', 'text', default='/etc/nsd/nsd.conf',
              show_if={'flavour': ['nsd']}, advanced=True),
        field('nsd_control', 'nsd-control command', 'text', default='nsd-control',
              show_if={'flavour': ['nsd']}, advanced=True),
        field('nsd_checkzone', 'Zone check command', 'text', default='nsd-checkzone',
              show_if={'flavour': ['nsd']}, advanced=True),
        # -- dnsmasq
        field('dnsmasq_file', 'File of acme\'s own', 'text',
              default='/etc/dnsmasq.d/acme-challenge.conf', show_if={'flavour': ['dnsmasq']},
              help='Holds only acme\'s txt-record lines; dnsmasq must read the directory '
                   '(conf-dir=/etc/dnsmasq.d/,*.conf).'),
        field('dnsmasq_reload', 'Restart command', 'text', default='systemctl restart dnsmasq',
              show_if={'flavour': ['dnsmasq']},
              help='dnsmasq reads txt-record lines only when it starts - a SIGHUP does not '
                   'reload them, so it is restarted (its cache is lost). dnsmasq --test runs '
                   'first; a failed restart puts the file back.'),
        field('dnsmasq_conf', 'dnsmasq.conf', 'text', default='', show_if={'flavour': ['dnsmasq']},
              advanced=True, placeholder='/etc/dnsmasq.conf',
              help='Empty: its own. For dnsmasq --test (-C).'),
        # -- Unbound
        field('unbound_conf', 'unbound.conf', 'text', default='', show_if={'flavour': ['unbound']},
              advanced=True, placeholder='/etc/unbound/unbound.conf',
              help='Empty: its own. unbound-control -c.'),
        # -- Windows, custom
        field('computer', 'DNS server for the cmdlets', 'text', default='',
              show_if={'flavour': ['powershell']},
              help='-ComputerName: empty for the machine signed in to.'),
        field('add_command', 'Command to add', 'textarea', default='',
              show_if={'flavour': ['custom']},
              placeholder='echo "{fqdn}. {ttl} IN TXT \\"{value}\\"" >> /var/named/acme.inc && '
                          'rndc reload {zone}',
              help='{fqdn} {relative} {zone} {value} {ttl} {name} are put in, shell-quoted.'),
        field('del_command', 'Command to take away', 'textarea', default='',
              show_if={'flavour': ['custom']},
              placeholder='sed -i "/{value}/d" /var/named/acme.inc && rndc reload {zone}'),
        field('test_command', 'Command to try', 'text', default='',
              show_if={'flavour': ['custom']}, placeholder='rndc status'),
        field('ttl', 'TTL (s)', 'number', default=60, advanced=True),
    ] + PROPAGATION_FIELDS

    # -- reaching it --------------------------------------------------------------------
    def _conn(self):
        host, port = D.split_hostport(self.c('host', ''), 22)
        if not host:
            raise PluginError('the DNS server is not set', retry=False)
        return ssh_conn(self, host, port)

    def _how(self):
        return self.c('flavour', 'nsupdate_local') or 'nsupdate_local'

    def _sudo(self, cmd):
        return ('sudo -n ' + cmd) if self.flag('sudo') else cmd

    def _tool(self, cmd):
        """A tool's command for a Unix server: its sbin in PATH, through sudo when set."""
        return X.PATH_PRE + self._sudo(cmd)

    def _raw(self, cmd, stdin=None, timeout=120):
        """(rc, out, err) - the exit not checked."""
        conn = self._conn()
        try:
            with self.ctx.ssh(conn) as s:
                rc, out, err = s.run(cmd, input=stdin, timeout=timeout, check=False)
        except PluginError:
            raise
        except Exception as e:                          # noqa: BLE001
            raise PluginError('%s over SSH: %s' % (conn['host'], e))
        return rc, out, err

    def _run(self, cmd, stdin=None, check=True):
        rc, out, err = self._raw(cmd, stdin)
        if rc != 0 and check:
            said = X.text_of(err) or X.text_of(out)
            raise PluginError('%s: "%s" ended with %s: %s' % (
                self._conn()['host'], self._prog(cmd), rc, said.strip()[-300:]), detail=said)
        return out

    @staticmethod
    def _prog(cmd):
        c = X.read_only_core(cmd)
        for w in c.split():
            if '=' not in w and w not in ('sudo', '-n', 'timeout') and not w.isdigit():
                return w
        return c.split()[0] if c.split() else c

    def _words(self, fqdn, value):
        zone = self.zone_for(fqdn)
        for w in (fqdn, zone, value):
            if not SAFE.match(str(w)):
                raise PluginError('%r is not something acme will put on a command line' % w,
                                  retry=False)
        return zone, relative(fqdn, zone)

    # -- which zone ----------------------------------------------------------------------
    def zone_files(self):
        """{zone: path} of "Zone files"."""
        out = {}
        v = self.c('zone_files', '')
        for line in (v if isinstance(v, (list, tuple)) else str(v or '').splitlines()):
            line = str(line).strip()
            bits = line.split()
            if len(bits) >= 2:
                out[D.norm(bits[0])] = bits[1]
        return out

    def known_zones(self):
        z = [D.norm(x) for x in self.lst('zones')]
        if self._how() in ZONEFILE:
            z += list(self.zone_files())
        return [x for i, x in enumerate(z) if x and x not in z[:i]]

    def zone_hint(self, fqdn):
        z = DnsChallenge.zone_hint(self, fqdn)
        if z:
            return z
        return longest_zone(fqdn, self.known_zones())

    def zone_for(self, fqdn):
        if self._how() in ('dnsmasq', 'unbound') and not self.zone_hint(fqdn):
            # these need no zone: the record is put at its name
            try:
                return DnsChallenge.zone_for(self, fqdn)
            except PluginError:
                return D.norm(fqdn)
        return DnsChallenge.zone_for(self, fqdn)

    # -- BIND: nsupdate --------------------------------------------------------------------
    def _nsupdate(self, op, fqdn, value):
        zone, _rel = self._words(fqdn, value)
        script = ''
        if self._how() == 'nsupdate_key':
            script += 'server %s\n' % self.c('nsupdate_server', '127.0.0.1')
            cmd = 'nsupdate -k %s' % shq(self.c('keyfile', ''))
        else:
            cmd = 'nsupdate -l'
            if str(self.c('session_key', '') or '').strip():
                cmd += ' -k %s' % shq(X.safe_path(self.c('session_key'), 'session key file'))
        script += 'zone %s\n' % zone
        if op == 'add':
            script += 'update add %s. %d TXT "%s"\n' % (fqdn, self.ttl(), value)
        else:
            script += 'update delete %s. TXT "%s"\n' % (fqdn, value)
        script += 'send\n'
        self._run(self._sudo(cmd), stdin=script.encode())

    # -- a zone file (BIND, NSD) -------------------------------------------------------------
    def _zone_file(self, zone):
        f = self.zone_files().get(D.norm(zone))
        if not f:
            raise PluginError('no zone file is set for %s - add the line "%s /path/to/its/file" '
                              'to Zone files (Find out what runs there fills them in)'
                              % (zone, zone), retry=False)
        return X.safe_path(f, 'zone file')

    def _read_file(self, path, missing_ok=False):
        """(text, sha256) of a file there; (None, None) when missing_ok and it is not there."""
        rc, out, err = self._raw(self._sudo('cat -- %s' % shq(path)))
        if rc != 0:
            said = X.text_of(err) or X.text_of(out)
            if missing_ok and 'No such file' in said:
                return None, None
            raise PluginError('%s could not be read there: %s' % (path, said.strip()[-300:]),
                              retry=False)
        text = X.text_of(out)
        return text, X.sha256(text)

    def _put_file(self, path, text, sha, check, reload, check_after=False):
        script = X.write_script(path, text, sha, check=check, reload=reload,
                                check_after=check_after)
        cmd = 'sudo -n sh -s' if self.flag('sudo') else 'sh -s'
        rc, out, err = self._raw(cmd, stdin=script.encode('utf-8'), timeout=180)
        if rc != 0:
            said = (X.text_of(err) or X.text_of(out)).strip()
            raise PluginError('%s: %s' % (path, said[-500:] or 'the script ended with %d' % rc),
                              detail=said, retry=rc == 4)
        return out

    def _file_edit(self, op, fqdn, value):
        how = self._how()
        zone, _rel = self._words(fqdn, value)
        path = self._zone_file(zone)
        zq = shq(X.safe_name(zone, 'zone'))
        with rmw_lock(('ssh_dns', self.c('host'), path)):
            frozen = False
            if how == 'bind_file':
                rndc = X.safe_cmd(self.c('rndc', 'rndc') or 'rndc', 'rndc command')
                check = '%s %s "$t"' % (X.safe_cmd(self.c('checkzone', 'named-checkzone') or
                                                   'named-checkzone', 'zone check'), zq)
                rc, _o, _e = self._raw(self._sudo('test -e %s' % shq(path + '.jnl')))
                if rc == 0:
                    if not self.flag('bind_freeze'):
                        raise PluginError('%s is a dynamic zone (%s.jnl is there): its file is not '
                                          'edited while named writes it - use nsupdate, or '
                                          'switch on freezing' % (zone, path), retry=False)
                    self._run(self._tool('%s freeze %s' % (rndc, zq)))
                    frozen = True
                reload = '%s %s %s' % (rndc, 'thaw' if frozen else 'reload', zq)
            else:
                check = '%s %s "$t"' % (X.safe_cmd(self.c('nsd_checkzone', 'nsd-checkzone') or
                                                   'nsd-checkzone', 'zone check'), zq)
                reload = '%s reload %s' % (self._nsd_ctl(), zq)
            done = False
            try:
                text, sha = self._read_file(path)
                new, changed, old, serial = X.edit_zone_text(
                    text, fqdn, value, self.ttl(), op, path=path,
                    serial_mode=self.c('serial', 'auto') or 'auto')
                if not changed:
                    self.ctx.debug('%s: nothing to change in %s' % (fqdn, path))
                    return
                self._put_file(path, new, sha, check, reload)
                done = True
                self.ctx.step('%s: %s, serial %d -> %d' % (
                    path, 'the TXT line added' if op == 'add' else 'the TXT line taken away',
                    old, serial))
            finally:
                if frozen and not done:
                    self._raw(self._tool('%s thaw %s' % (rndc, zq)))

    def _nsd_ctl(self):
        ctl = X.safe_cmd(self.c('nsd_control', 'nsd-control') or 'nsd-control',
                         'nsd-control command')
        conf = str(self.c('nsd_conf', '') or '').strip()
        if conf and conf != '/etc/nsd/nsd.conf':
            ctl += ' -c ' + shq(X.safe_path(conf, 'nsd.conf'))
        return ctl

    # -- PowerDNS ----------------------------------------------------------------------------
    def _pdnsutil(self):
        cmd = 'pdnsutil'
        d = str(self.c('pdns_config_dir', '') or '').strip()
        if d:
            cmd += ' --config-dir=' + shq(X.safe_path(d, 'configuration directory'))
        return cmd

    def _pdns_rrset(self, zone, fqdn):
        """(ttl or None, [content as written]) of the TXT records at fqdn."""
        out = X.text_of(self._run(self._tool('%s list-zone %s' % (self._pdnsutil(), shq(zone)))))
        ttl, got = None, []
        for line in out.splitlines():
            bits = line.split('\t', 4) if '\t' in line else line.split(None, 4)
            if len(bits) == 5 and D.norm(bits[0]) == D.norm(fqdn) and bits[3].upper() == 'TXT':
                ttl = int(bits[1]) if bits[1].isdigit() else ttl
                got.append(bits[4].strip())
        return ttl, got

    def _pdns(self, op, fqdn, value):
        zone, rel = self._words(fqdn, value)
        pu, zq, rq = self._pdnsutil(), shq(zone), shq(rel)
        with rmw_lock(('ssh_dns', self.c('host'), 'pdns', zone)):
            ttl, have = self._pdns_rrset(zone, fqdn)
            mine = [c for c in have if unquote_txt(c) == value]
            if op == 'add':
                if mine:
                    return
                self._run(self._tool('%s add-record %s %s TXT %d %s' % (
                    pu, zq, rq, ttl or self.ttl(), shq('"%s"' % value))))
            else:
                if not mine:
                    return
                rest = [c for c in have if unquote_txt(c) != value]
                if rest:
                    self._run(self._tool('%s replace-rrset %s %s TXT %d %s' % (
                        pu, zq, rq, ttl or self.ttl(), ' '.join(shq(c) for c in rest))))
                else:
                    self._run(self._tool('%s delete-rrset %s %s TXT' % (pu, zq, rq)))
            if self.flag('pdns_serial'):
                self._run(self._tool('%s increase-serial %s' % (pu, zq)), check=False)
            if self.flag('pdns_rectify'):
                self._run(self._tool('%s rectify-zone %s' % (pu, zq)), check=False)

    def _api_base(self):
        url = str(self.c('pdns_api_url', '') or 'http://127.0.0.1:8081').rstrip('/')
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ('http', 'https') or not p.hostname or not re.match(
                r'^[A-Za-z0-9_.:\[\]/-]+$', url):
            raise PluginError('%r is not the address of the PowerDNS API' % url, retry=False)
        sid = str(self.c('pdns_server_id', 'localhost') or 'localhost')
        if not re.match(r'^[A-Za-z0-9_.-]+$', sid):
            raise PluginError('%r is not a server id' % sid, retry=False)
        return '%s/api/v1/servers/%s' % (url, sid)

    def _api(self, method, path, body=None, ok=(200, 201, 204)):
        key = str(self.c('pdns_api_key', '') or '')
        if not key:
            raise PluginError('the API key of PowerDNS is not set', retry=False)
        url = self._api_base() + path
        conf = 'header = %s\n' % _curl_q('X-API-Key: ' + key)
        if method != 'GET':
            conf += 'request = %s\n' % _curl_q(method)
        if body is not None:
            conf += 'header = %s\ndata = %s\n' % (_curl_q('Content-Type: application/json'),
                                                  _curl_q(json.dumps(body)))
        out = X.text_of(self._run("curl -sS -K - -w '\\n%%{http_code}' %s" % shq(url),
                                  stdin=conf.encode('utf-8')))
        body_text, _sep, code = out.rstrip('\n').rpartition('\n')
        status = int(code) if code.strip().isdigit() else 0
        if status not in ok:
            raise PluginError('the PowerDNS API said %s: %s' % (status or '?', body_text[-300:]
                                                                or code[-300:]),
                              retry=status >= 500)
        try:
            return json.loads(body_text) if body_text.strip() else None
        except ValueError:
            return None

    def _pdns_api(self, op, fqdn, value):
        zone, _rel = self._words(fqdn, value)
        zid = urllib.parse.quote(zone + '.')
        name = fqdn + '.'
        with rmw_lock(('ssh_dns', self.c('host'), 'pdns-api', zone)):
            got = self._api('GET', '/zones/%s?rrsets=true&rrset_name=%s&rrset_type=TXT' % (
                zid, urllib.parse.quote(name))) or {}
            have, ttl = [], None
            for rr in got.get('rrsets') or []:
                if D.norm(rr.get('name')) == D.norm(fqdn) and rr.get('type') == 'TXT':
                    ttl = rr.get('ttl')
                    have = [r for r in rr.get('records') or []]
            mine = [r for r in have if unquote_txt(r.get('content')) == value]
            if op == 'add':
                if mine:
                    return
                records = have + [{'content': '"%s"' % value, 'disabled': False}]
            else:
                if not mine:
                    return
                records = [r for r in have if unquote_txt(r.get('content')) != value]
            rr = {'name': name, 'type': 'TXT', 'ttl': int(ttl or self.ttl())}
            if records:
                rr.update(changetype='REPLACE', records=[
                    {'content': r.get('content'), 'disabled': bool(r.get('disabled'))}
                    for r in records])
            else:
                rr['changetype'] = 'DELETE'
            self._api('PATCH', '/zones/%s' % zid, {'rrsets': [rr]})
            if self.flag('pdns_rectify') and got.get('dnssec'):
                self._api('PUT', '/zones/%s/rectify' % zid, ok=(200, 204, 422))

    # -- Knot -------------------------------------------------------------------------------
    def _knotc(self):
        cmd = 'knotc'
        for k, opt in (('knot_conf', '-c'), ('knot_socket', '-s')):
            v = str(self.c(k, '') or '').strip()
            if v:
                cmd += ' %s %s' % (opt, shq(X.safe_path(v)))
        return cmd

    def _knot(self, op, fqdn, value):
        zone, _rel = self._words(fqdn, value)
        k, zq, nq = self._knotc(), shq(zone), shq(fqdn + '.')
        with rmw_lock(('ssh_dns', self.c('host'), 'knot', zone)):
            rc, out, err = self._raw(self._tool('%s zone-read %s %s TXT' % (k, zq, nq)))
            said = X.text_of(out) + X.text_of(err)
            if rc != 0 and 'no such node' not in said and 'not exist' not in said:
                raise PluginError('knotc zone-read %s: %s' % (zone, said.strip()[-300:]))
            ttl, have = None, []
            for line in X.text_of(out).splitlines():
                m = re.match(r'^\[[^\]]+\]\s+(\S+)\s+(\d+)\s+TXT\s+(.*)$', line.strip())
                if m and D.norm(m.group(1)) == D.norm(fqdn):
                    ttl = int(m.group(2))
                    have.append(unquote_txt(m.group(3)))
            if (op == 'add') == (value in have):
                return
            self._run(self._tool('%s zone-begin %s' % (k, zq)))
            try:
                if op == 'add':
                    self._run(self._tool('%s zone-set %s %s %d TXT %s' % (
                        k, zq, nq, ttl or self.ttl(), shq('"%s"' % value))))
                else:
                    self._run(self._tool('%s zone-unset %s %s TXT %s' % (
                        k, zq, nq, shq('"%s"' % value))))
                self._run(self._tool('%s zone-commit %s' % (k, zq)))
            except PluginError:
                self._raw(self._tool('%s zone-abort %s' % (k, zq)))
                raise

    # -- dnsmasq ----------------------------------------------------------------------------
    def _dnsmasq(self, op, fqdn, value):
        X.safe_name(fqdn)
        path = X.safe_path(self.c('dnsmasq_file', '') or '/etc/dnsmasq.d/acme-challenge.conf',
                           'dnsmasq file')
        if not path.endswith('.conf'):
            raise PluginError('the dnsmasq file must end in .conf (dnsmasq reads *.conf of its '
                              'directory)', retry=False)
        check = 'dnsmasq --test'
        conf = str(self.c('dnsmasq_conf', '') or '').strip()
        if conf:
            check += ' -C ' + shq(X.safe_path(conf, 'dnsmasq.conf'))
        reload = X.safe_cmd(self.c('dnsmasq_reload', '') or 'systemctl restart dnsmasq',
                            'restart command')
        with rmw_lock(('ssh_dns', self.c('host'), path)):
            text, sha = self._read_file(path, missing_ok=True)
            new, changed = X.edit_dnsmasq_text(text or '', fqdn, value, op)
            if not changed:
                return
            self._put_file(path, new, sha, check, reload, check_after=True)

    # -- Unbound ----------------------------------------------------------------------------
    def _unbound_ctl(self):
        cmd = 'unbound-control'
        conf = str(self.c('unbound_conf', '') or '').strip()
        if conf:
            cmd += ' -c ' + shq(X.safe_path(conf, 'unbound.conf'))
        return cmd

    def _unbound(self, op, fqdn, value):
        X.safe_name(fqdn)
        u = self._unbound_ctl()
        with rmw_lock(('ssh_dns', self.c('host'), 'unbound')):
            out = X.text_of(self._run(self._tool('%s list_local_data' % u)))
            at = []
            for line in out.splitlines():
                bits = line.split(None, 4)
                if len(bits) == 5 and D.norm(bits[0]) == D.norm(fqdn):
                    at.append((bits[3].upper(), bits[4].strip(), line.strip()))
            mine = [a for a in at if a[0] == 'TXT' and unquote_txt(a[1]) == value]
            if op == 'add':
                if not mine:
                    self._run(self._tool('%s local_data %s' % (u, shq('%s. %d IN TXT "%s"' % (
                        fqdn, self.ttl(), value)))))
                return
            if not mine:
                return
            self._run(self._tool('%s local_data_remove %s' % (u, shq(fqdn + '.'))))
            for typ, data, line in at:
                if (typ, data) in [(m[0], m[1]) for m in mine]:
                    continue
                self._run(self._tool('%s local_data %s' % (u, shq(' '.join(line.split())))))

    # -- Windows DNS, your own commands --------------------------------------------------------
    def _powershell(self, op, fqdn, value):
        zone, rel = self._words(fqdn, value)
        comp = (' -ComputerName ' + _ps(self.c('computer'))) if self.c('computer') else ''
        if op == 'add':
            ps = ('Add-DnsServerResourceRecord%s -ZoneName %s -Name %s -Txt -DescriptiveText %s '
                  '-TimeToLive (New-TimeSpan -Seconds %d)' % (comp, _ps(zone), _ps(rel),
                                                             _ps(value), self.ttl()))
        else:
            ps = ('Get-DnsServerResourceRecord%s -ZoneName %s -Name %s -RRType Txt '
                  '-ErrorAction SilentlyContinue | Where-Object { $_.RecordData.DescriptiveText '
                  '-eq %s } | Remove-DnsServerResourceRecord%s -ZoneName %s -Force'
                  % (comp, _ps(zone), _ps(rel), _ps(value), comp, _ps(zone)))
        self._run('powershell -NoProfile -NonInteractive -Command "%s"' % ps.replace('"', '\\"'))

    def _custom(self, op, fqdn, value):
        zone, rel = self._words(fqdn, value)
        tpl = self.c('add_command' if op == 'add' else 'del_command', '')
        if not tpl:
            if op == 'add':
                raise PluginError('the command to add is not set', retry=False)
            return
        words = {'fqdn': fqdn, 'relative': rel, 'zone': zone, 'value': value,
                 'ttl': str(self.ttl()), 'name': fqdn}
        cmd = tpl
        for k, v in words.items():
            cmd = cmd.replace('{%s}' % k, shq(v))
        self._run(self._sudo(cmd) if self.flag('sudo') else cmd)

    # -- the contract ---------------------------------------------------------------------------
    def _do(self, op, fqdn, value):
        how = self._how()
        if how in ('nsupdate_local', 'nsupdate_key'):
            self._nsupdate(op, fqdn, value)
        elif how in ZONEFILE:
            self._file_edit(op, fqdn, value)
        elif how == 'pdnsutil':
            self._pdns(op, fqdn, value)
        elif how == 'pdns_api':
            self._pdns_api(op, fqdn, value)
        elif how == 'knot':
            self._knot(op, fqdn, value)
        elif how == 'dnsmasq':
            self._dnsmasq(op, fqdn, value)
        elif how == 'unbound':
            self._unbound(op, fqdn, value)
        elif how == 'powershell':
            self._powershell(op, fqdn, value)
        else:
            self._custom(op, fqdn, value)

    def add_txt(self, fqdn, value):
        self._do('add', fqdn, value)
        return None

    def del_txt(self, fqdn, value, handle):
        self._do('del', fqdn, value)

    def dry_said(self, name, handle):
        h = handle or {}
        return '%s TXT "%s" (%s on %s)' % (h.get('fqdn') or '?', h.get('txt') or '',
                                          self._how(), self.c('host', ''))

    # -- Test: read-only --------------------------------------------------------------------------
    def _out(self, cmd):
        return X.text_of(self._run(cmd)).strip()

    def test(self):
        how = self._how()
        host = self._conn()['host']
        if how in ('nsupdate_local', 'nsupdate_key'):
            if how == 'nsupdate_local':
                key = str(self.c('session_key', '') or '').strip()
                cmd = self._sudo('nsupdate -V') if not key else self._sudo(
                    'test -r %s && nsupdate -V' % shq(X.safe_path(key)))
            else:
                cmd = self._sudo('test -r %s && nsupdate -V' % shq(self.c('keyfile', '')))
            out = self._out(cmd)
            words = '%s: %s' % (host, out[:400] or 'it worked')
            if how == 'nsupdate_local':
                words += (' - nsupdate -l cannot be tried without changing the zone: a dry run '
                          'puts a test record in and takes it away')
            return words
        if how in ZONEFILE:
            files = self.zone_files()
            if not files:
                raise PluginError('no zone files are set - Find out what runs there, or add '
                                  '"ZONE /path/to/file" lines', retry=False)
            said = []
            for zone, path in list(files.items())[:8]:
                X.safe_name(zone, 'zone')
                path = X.safe_path(path, 'zone file')
                text, _sha = self._read_file(path)
                serial, _a, _b = X.find_serial(text, path)
                chk = X.safe_cmd(self.c('checkzone' if how == 'bind_file' else 'nsd_checkzone',
                                        '') or ('named-checkzone' if how == 'bind_file'
                                                else 'nsd-checkzone'))
                rc, out, err = self._raw(self._tool('%s %s %s' % (chk, shq(zone), shq(path))))
                if rc != 0:
                    raise PluginError('%s: %s refuses %s as it is: %s' % (
                        zone, chk.split()[0], path, (X.text_of(err) or X.text_of(out))
                        .strip()[-300:]), retry=False)
                said.append('%s (%s, serial %d)' % (zone, path, serial))
            if how == 'bind_file':
                self._out(self._tool('%s status' % X.safe_cmd(self.c('rndc', 'rndc') or 'rndc')))
            else:
                self._out(self._tool('%s status' % self._nsd_ctl()))
            return '%s: the zone files can be edited safely - %s' % (host, '; '.join(said))
        if how == 'pdnsutil':
            out = self._out(self._tool('%s list-all-zones' % self._pdnsutil()))
            zones = [D.norm(x) for x in out.split() if X.NAME_RE.match(D.norm(x) or '-')]
            return self._zones_words(host, 'pdnsutil', zones)
        if how == 'pdns_api':
            got = self._api('GET', '/zones') or []
            return self._zones_words(host, 'the PowerDNS API', [z.get('name') for z in got
                                                                if isinstance(z, dict)])
        if how == 'knot':
            out = self._out(self._tool('%s zone-status' % self._knotc()))
            zones = re.findall(r'^\[([^\]]+)\]', out, re.M)
            return self._zones_words(host, 'knotc', zones)
        if how == 'dnsmasq':
            path = X.safe_path(self.c('dnsmasq_file', '') or '/etc/dnsmasq.d/acme-challenge.conf')
            chk = 'dnsmasq --test'
            if str(self.c('dnsmasq_conf', '') or '').strip():
                chk += ' -C ' + shq(X.safe_path(self.c('dnsmasq_conf')))
            self._out(self._tool('test -d %s' % shq(path.rsplit('/', 1)[0] or '/')))
            out = self._out(self._tool(chk))
            return '%s: %s; acme\'s lines go in %s, then "%s"' % (
                host, out.splitlines()[-1] if out else 'dnsmasq --test passed', path,
                self.c('dnsmasq_reload', 'systemctl restart dnsmasq'))
        if how == 'unbound':
            out = self._out(self._tool('%s list_local_zones' % self._unbound_ctl()))
            return '%s: unbound-control answers (%d local zones)' % (host, len(out.splitlines()))
        if how == 'powershell':
            cmd = 'powershell -NoProfile -NonInteractive -Command "Get-DnsServerZone%s | ' \
                  'Select-Object -First 20 -ExpandProperty ZoneName"' % (
                      (' -ComputerName ' + _ps(self.c('computer'))) if self.c('computer') else '')
        else:
            cmd = self.c('test_command', '') or 'true'
            cmd = self._sudo(cmd)
        out = self._out(cmd)
        return '%s: %s' % (host, out[:400] or 'it worked')

    def _zones_words(self, host, who, zones):
        zones = [D.norm(z) for z in zones if z]
        want = [z for z in self.known_zones() + ([D.norm(self.c('zone'))] if self.c('zone')
                                                 else []) if z]
        missing = [z for z in want if z not in zones]
        if missing:
            raise PluginError('%s: %s has no zone %s (it has %s)' % (
                host, who, ', '.join(missing), ', '.join(zones[:20]) or 'none'), retry=False)
        return '%s: %s answers, %d zone(s): %s' % (host, who, len(zones),
                                                   ', '.join(zones[:20]) or 'none')

    # -- Find out what runs there ----------------------------------------------------------------
    def discover(self):
        """What runs on the DNS server, by read-only commands only (_sshdns.Discovery):
        {ok, server, version, flavour_suggested, zones, keys, sudo, problems,
        fields, commands}. A failure to sign in is said in problems (ok False)."""
        conn = self._conn()
        try:
            with self.ctx.ssh(conn) as s:
                def run(cmd, timeout):
                    return s.run(cmd, timeout=timeout, check=False)
                d = X.Discovery(run, self.config, step=self.ctx.step)
                got = d.run()
        except PluginError as e:
            return {'ok': False, 'host': conn['host'], 'problems': [str(e)], 'fields': {},
                    'zones': [], 'keys': [], 'servers': [], 'commands': []}
        except Exception as e:                          # noqa: BLE001
            return {'ok': False, 'host': conn['host'], 'problems': ['%s over SSH: %s' % (
                conn['host'], e)], 'fields': {}, 'zones': [], 'keys': [], 'servers': [],
                'commands': []}
        got['host'] = conn['host']
        return got

    def action(self, key):
        if key != 'discover':
            return DnsChallenge.action(self, key)
        got = self.discover()
        for p in got.get('problems') or []:
            self.ctx.step(p, 'warn')
        if not got.get('ok'):
            raise PluginError('%s: discovery failed - every field can be set by hand' % (
                got.get('host')), retry=False)
        if not got.get('server'):
            return '%s: no DNS server acme knows was found there' % got.get('host')
        lines = ['%s: %s %s, suggested: %s' % (got['host'], got['server'], got.get('version')
                                               or '', got.get('flavour_suggested') or '-')]
        for z in got.get('zones') or []:
            lines.append('  %s - %s' % (z['name'], z.get('how_writable') or ''))
        for k, v in sorted((got.get('fields') or {}).items()):
            lines.append('  set %s = %s' % (k, ', '.join(v) if isinstance(v, list) else v))
        return '\n'.join(lines)
