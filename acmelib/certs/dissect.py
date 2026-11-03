# -*- coding: utf-8 -*-
"""
Bytes taken apart, as Wireshark shows a packet (1.0.37): for What happens with its
debug details - what a test says before TLS (LDAP, PostgreSQL, MySQL, TDS, RDP) and
what a module sends over UDP itself (SNMP, DNS, syslog).

    dissect(data, proto=None, port=None) -> {'proto', 'summary', 'fields', 'hex'}

    fields  [[depth, offset, length, name, value]] - a tree, each field with the
            bytes it comes from (offset, length), as Wireshark's packet details
    hex     the bytes as its bytes pane: offset, 16 bytes in hex, the same as text

Nothing here is sent or read anywhere: it only reads bytes it is given. A stand-in
of a secret (the run plan's, plansecretNN in base64) is never shown - neither its
text nor its bytes - and an SNMP community, a password in effect, neither.
"""
from __future__ import annotations

import re
import struct

DOTS = '••••'
STAND_IN = re.compile(rb'cGxhbnNlY3JldD[A-Za-z0-9+/=]{2,6}')


class _Out(object):
    def __init__(self, data):
        self.data = bytes(data)
        self.fields = []
        self.hidden = []                  # (offset, length) never shown

    def add(self, depth, off, ln, name, value=''):
        self.fields.append([depth, off, ln, name, str(value)])

    def hide(self, off, ln):
        self.hidden.append((off, ln))


def _flags(v, names):
    on = [n for bit, n in names if v & bit]
    return ' | '.join(on) or 'none'


def hexdump(data, hidden=()):
    """Wireshark's bytes pane: 0000  30 29 02 01 ...  0).. - hidden bytes as ••."""
    data = bytes(data)
    mask = set()
    for off, ln in hidden:
        mask.update(range(off, off + ln))
    for m in STAND_IN.finditer(data):
        mask.update(range(m.start(), m.end()))
    lines = []
    for at in range(0, len(data), 16):
        chunk = data[at:at + 16]
        hx = ' '.join('••' if at + i in mask else '%02x' % b for i, b in enumerate(chunk))
        tx = ''.join('•' if at + i in mask else (chr(b) if 32 <= b < 127 else '.')
                     for i, b in enumerate(chunk))
        lines.append('%04x  %-47s  %s' % (at, hx, tx))
    return lines


# ---- BER / ASN.1 (SNMP, LDAP) --------------------------------------------------------
UNIVERSAL = {1: 'BOOLEAN', 2: 'INTEGER', 3: 'BIT STRING', 4: 'OCTET STRING', 5: 'NULL',
             6: 'OBJECT IDENTIFIER', 10: 'ENUMERATED', 16: 'SEQUENCE', 17: 'SET',
             64: 'IpAddress', 65: 'Counter32', 66: 'Gauge32', 67: 'TimeTicks', 68: 'Opaque',
             70: 'Counter64'}
OIDS = {
    '1.3.6.1.2.1.1.1.0': 'sysDescr.0', '1.3.6.1.2.1.1.2.0': 'sysObjectID.0',
    '1.3.6.1.2.1.1.3.0': 'sysUpTime.0', '1.3.6.1.2.1.1.4.0': 'sysContact.0',
    '1.3.6.1.2.1.1.5.0': 'sysName.0', '1.3.6.1.2.1.1.6.0': 'sysLocation.0',
    '1.3.6.1.6.3.1.1.4.1.0': 'snmpTrapOID.0',
    '1.3.6.1.4.1.1466.20037': 'StartTLS (RFC 4511)',
    '1.3.6.1.4.1.4203.1.11.3': 'Who am I? (RFC 4532)',
    '1.3.6.1.4.1.4203.1.11.1': 'Modify Password (RFC 3062)',
}


def _ber_len(d, i):
    b = d[i]
    if b < 0x80:
        return b, i + 1
    n = b & 0x7F
    return int.from_bytes(d[i + 1:i + 1 + n], 'big'), i + 1 + n


def _oid(v):
    if not v:
        return ''
    out = [str(v[0] // 40), str(v[0] % 40)]
    n = 0
    for b in v[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            out.append(str(n))
            n = 0
    return '.'.join(out)


def _ber(o, i, end, depth, names=None, path=()):
    """One level of BER, names: {(path..., tag): name} for what the protocol calls it."""
    k = 0
    d = o.data
    while i < end:
        start = i
        tag = d[i]
        cls = tag >> 6
        cons = bool(tag & 0x20)
        num = tag & 0x1F
        ln, j = _ber_len(d, i + 1)
        if j + ln > len(d) and not cons:
            raise ValueError('cut short')
        val = d[j:j + ln]
        key = path + (k,)
        name = (names or {}).get(key) or (names or {}).get(('tag', tag))
        if cls == 0:
            kind = UNIVERSAL.get(num, 'tag %d' % num)
        else:
            kind = '[%s %d]' % ({1: 'APPLICATION', 2: '', 3: 'PRIVATE'}.get(cls, ''), num)
            kind = kind.replace('[ ', '[')
        shown = ''
        if not cons:
            if cls == 0 and num in (2, 10, 65, 66, 67, 70):
                shown = str(int.from_bytes(val, 'big', signed=num in (2, 10))) if val else '0'
            elif cls == 0 and num == 6 or (cls == 2 and name and 'OID' in name):
                oid = _oid(val) if not (cls == 2) else val.decode('ascii', 'replace')
                shown = oid + ((' (%s)' % OIDS[oid]) if oid in OIDS else '')
            elif cls == 0 and num == 5:
                shown = '(null)'
            elif cls == 0 and num == 64 and len(val) == 4:
                shown = '.'.join(str(x) for x in val)
            elif cls == 0 and num == 1:
                shown = 'TRUE' if val and val[0] else 'FALSE'
            else:
                txt = val.decode('utf-8', 'replace')
                shown = ('"%s"' % txt) if all(32 <= c < 127 for c in val) else val.hex()
            if cls == 2 and name and 'OID' in name:
                txt = val.decode('ascii', 'replace')
                shown = txt + ((' (%s)' % OIDS[txt]) if txt in OIDS else '')
        label = '%s: %s' % (name, kind) if name else kind
        if name and name.startswith('secret:'):
            label = '%s: %s' % (name[7:], kind)
            shown = DOTS + ' (%d bytes)' % len(val)
            o.hide(j, ln)
        o.add(depth, start, j + ln - start, label, shown if not cons else '%d bytes' % ln)
        if cons:
            _ber(o, j, j + ln, depth + 1, names, key)
        i = j + ln
        k += 1


PDU = {0xA0: 'GetRequest', 0xA1: 'GetNextRequest', 0xA2: 'Response', 0xA3: 'SetRequest',
       0xA4: 'Trap (v1)', 0xA5: 'GetBulkRequest', 0xA6: 'InformRequest', 0xA7: 'SNMPv2-Trap',
       0xA8: 'Report'}


def snmp(o):
    d = o.data
    names = {(0,): 'SNMP message', (0, 0): 'version', (0, 1): 'secret:community',
             (0, 2): 'PDU', (0, 2, 0): 'request-id', (0, 2, 1): 'error-status',
             (0, 2, 2): 'error-index', (0, 2, 3): 'variable-bindings'}
    for n in range(8):
        names[(0, 2, 3, n)] = 'varbind %d' % (n + 1)
        names[(0, 2, 3, n, 0)] = 'name'
        names[(0, 2, 3, n, 1)] = 'value'
    try:
        _ber(o, 0, len(d), 0, names)
    finally:
        ver = {0: 'v1', 1: 'v2c', 3: 'v3'}
        for f in o.fields:
            if f[3].startswith('version'):
                f[4] = '%s (%s)' % (f[4], ver.get(int(f[4]) if f[4].isdigit() else -1, '?'))
            if f[3].startswith('PDU'):
                f[3] = 'PDU: %s' % PDU.get(d[f[1]], 'tag 0x%02x' % d[f[1]])
    pdu = next((f[3][5:] for f in o.fields if f[3].startswith('PDU: ')), None)
    return 'SNMP %s' % (pdu or '')


def ldap(o):
    names = {(0,): 'LDAPMessage', (0, 0): 'messageID', (0, 1): 'protocolOp',
             (0, 1, 0): 'requestName (OID)', (0, 1, 1): 'requestValue'}
    _ber(o, 0, len(o.data), 0, names)
    for f in o.fields:
        if f[3].startswith('protocolOp'):
            tag = o.data[f[1]] & 0x1F
            f[3] = 'protocolOp: %s' % {23: 'extendedReq [APPLICATION 23]', 0: 'bindRequest',
                                       3: 'searchRequest', 2: 'unbindRequest'}.get(tag, 'op %d' % tag)
    return 'LDAP extended request'


# ---- DNS ------------------------------------------------------------------------------
QTYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
          33: 'SRV', 43: 'DS', 48: 'DNSKEY', 52: 'TLSA', 65: 'HTTPS', 99: 'SPF', 257: 'CAA',
          255: 'ANY', 250: 'TSIG'}


def dns(o):
    d = o.data
    if len(d) < 12:
        return None
    qid, fl, qd, an, ns, ar = struct.unpack('>HHHHHH', d[:12])
    o.add(0, 0, 12, 'Header')
    o.add(1, 0, 2, 'Transaction ID', '0x%04x' % qid)
    op = (fl >> 11) & 0xF
    o.add(1, 2, 2, 'Flags', '0x%04x' % fl)
    o.add(2, 2, 2, 'QR', 'response' if fl & 0x8000 else 'query')
    o.add(2, 2, 2, 'Opcode', '%d (%s)' % (op, {0: 'QUERY', 4: 'NOTIFY', 5: 'UPDATE'}.get(op, '?')))
    o.add(2, 2, 2, 'RD - recursion desired', 'yes' if fl & 0x0100 else 'no')
    o.add(2, 2, 2, 'CD - checking disabled', 'yes' if fl & 0x0010 else 'no')
    o.add(1, 4, 2, 'Questions' if op != 5 else 'Zones', qd)
    o.add(1, 6, 2, 'Answers' if op != 5 else 'Prerequisites', an)
    o.add(1, 8, 2, 'Authority' if op != 5 else 'Updates', ns)
    o.add(1, 10, 2, 'Additional', ar)
    i = 12
    for n in range(min(qd, 8)):
        start = i
        labels = []
        while i < len(d) and d[i]:
            ln = d[i]
            labels.append(d[i + 1:i + 1 + ln].decode('ascii', 'replace'))
            i += 1 + ln
        i += 1
        qt, qc = struct.unpack('>HH', d[i:i + 4]) if i + 4 <= len(d) else (0, 0)
        o.add(0, start, i + 4 - start, 'Question %d' % (n + 1), '%s %s' % ('.'.join(labels) or '.', QTYPES.get(qt, qt)))
        o.add(1, start, i - start, 'Name', '.'.join(labels) or '.')
        o.add(1, i, 2, 'Type', '%s (%d)' % (QTYPES.get(qt, '?'), qt))
        o.add(1, i + 2, 2, 'Class', '%s (%d)' % ({1: 'IN', 255: 'ANY', 254: 'NONE'}.get(qc, '?'), qc))
        i += 4
    return 'DNS %s' % ({0: 'query', 5: 'UPDATE'}.get(op, 'opcode %d' % op))


# ---- what the tests say before TLS ---------------------------------------------------
def postgres(o):
    d = o.data
    ln, code = struct.unpack('>II', d[:8])
    o.add(0, 0, 8, 'PostgreSQL startup packet')
    o.add(1, 0, 4, 'Length', ln)
    o.add(1, 4, 4, 'Request code', '%d (%d.%d: %s)' % (code, code >> 16, code & 0xFFFF,
                                                      'SSLRequest' if code == 80877103 else
                                                      'GSSENCRequest' if code == 80877104 else '?'))
    return 'PostgreSQL SSLRequest'


MYSQL_CAPS = [(0x1, 'CLIENT_LONG_PASSWORD'), (0x2, 'CLIENT_FOUND_ROWS'), (0x4, 'CLIENT_LONG_FLAG'),
              (0x8, 'CLIENT_CONNECT_WITH_DB'), (0x200, 'CLIENT_PROTOCOL_41'),
              (0x800, 'CLIENT_SSL'), (0x8000, 'CLIENT_SECURE_CONNECTION'),
              (0x10000, 'CLIENT_MULTI_STATEMENTS'), (0x80000, 'CLIENT_PLUGIN_AUTH'),
              (0x200000, 'CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA')]


def mysql(o):
    d = o.data
    ln = int.from_bytes(d[:3], 'little')
    o.add(0, 0, 4, 'MySQL packet header')
    o.add(1, 0, 3, 'Payload length', ln)
    o.add(1, 3, 1, 'Sequence id', d[3])
    caps, mx, cs = struct.unpack('<IIB', d[4:13])
    o.add(0, 4, len(d) - 4, 'SSLRequest')
    o.add(1, 4, 4, 'Client capabilities', '0x%08x' % caps)
    for bit, n in MYSQL_CAPS:
        o.add(2, 4, 4, n, 'set' if caps & bit else 'not set')
    o.add(1, 8, 4, 'Max packet size', '%d (%d MB)' % (mx, mx >> 20))
    o.add(1, 12, 1, 'Character set', '%d (%s)' % (cs, {45: 'utf8mb4_general_ci', 255: 'utf8mb4_0900_ai_ci', 33: 'utf8_general_ci'}.get(cs, '?')))
    o.add(1, 13, 23, 'Filler', '23 zero bytes')
    return 'MySQL SSLRequest'


TDS_OPT = {0: 'VERSION', 1: 'ENCRYPTION', 2: 'INSTOPT', 3: 'THREADID', 4: 'MARS',
           5: 'TRACEID', 6: 'FEDAUTHREQUIRED', 7: 'NONCEOPT', 0xFF: 'TERMINATOR'}
TDS_ENC = {0: 'ENCRYPT_OFF', 1: 'ENCRYPT_ON', 2: 'ENCRYPT_NOT_SUP', 3: 'ENCRYPT_REQ'}


def tds(o):
    d = o.data
    typ, st, ln, spid, pid, win = struct.unpack('>BBHHBB', d[:8])
    o.add(0, 0, 8, 'TDS packet header')
    o.add(1, 0, 1, 'Type', '0x%02x (%s)' % (typ, {0x12: 'PRELOGIN', 0x04: 'Tabular result'}.get(typ, '?')))
    o.add(1, 1, 1, 'Status', '0x%02x (%s)' % (st, 'end of message' if st & 1 else 'more follows'))
    o.add(1, 2, 2, 'Length', ln)
    o.add(1, 4, 2, 'SPID', spid)
    o.add(1, 6, 1, 'Packet id', pid)
    o.add(1, 7, 1, 'Window', win)
    body = d[8:ln]
    o.add(0, 8, len(body), 'PRELOGIN options')
    i = 0
    opts = []
    while i < len(body) and body[i] != 0xFF:
        tok = body[i]
        off, size = struct.unpack('>HH', body[i + 1:i + 5])
        opts.append((tok, off, size))
        o.add(1, 8 + i, 5, 'Option %s' % TDS_OPT.get(tok, tok), 'at %d, %d bytes' % (off, size))
        i += 5
    o.add(1, 8 + i, 1, 'TERMINATOR', '0xff')
    for tok, off, size in opts:
        v = body[off:off + size]
        if tok == 0 and size >= 6:
            shown = '%d.%d.%d (sub-build %d)' % (v[0], v[1], int.from_bytes(v[2:4], 'big'), int.from_bytes(v[4:6], 'big'))
        elif tok == 1 and size >= 1:
            shown = '%d (%s)' % (v[0], TDS_ENC.get(v[0], '?'))
        elif tok == 4 and size >= 1:
            shown = 'on' if v[0] else 'off'
        else:
            shown = v.hex() or '(empty)'
        o.add(1, 8 + off, size, TDS_OPT.get(tok, str(tok)), shown)
    return 'TDS PRELOGIN'


RDP_PROTO = [(1, 'PROTOCOL_SSL (TLS)'), (2, 'PROTOCOL_HYBRID (CredSSP)'), (4, 'PROTOCOL_RDSTLS'),
             (8, 'PROTOCOL_HYBRID_EX (CredSSP with Early User Authorization)')]


def rdp(o):
    d = o.data
    ver, _r, ln = struct.unpack('>BBH', d[:4])
    o.add(0, 0, 4, 'TPKT (RFC 1006)')
    o.add(1, 0, 1, 'Version', ver)
    o.add(1, 2, 2, 'Length', ln)
    li, code = d[4], d[5]
    o.add(0, 4, li + 1, 'X.224 (ISO 8073)')
    o.add(1, 4, 1, 'Length indicator', li)
    o.add(1, 5, 1, 'PDU type', '0x%02x (%s)' % (code, {0xE0: 'Connection Request', 0xD0: 'Connection Confirm', 0x80: 'Disconnect Request'}.get(code & 0xF0, '?')))
    dst, src, cl = struct.unpack('>HHB', d[6:11])
    o.add(1, 6, 2, 'Destination reference', dst)
    o.add(1, 8, 2, 'Source reference', src)
    o.add(1, 10, 1, 'Class', cl)
    i = 11
    if i + 8 <= len(d) and d[i] == 1:
        t, fl, nl, req = struct.unpack('<BBHI', d[i:i + 8])
        o.add(0, i, 8, 'RDP Negotiation Request')
        o.add(1, i, 1, 'Type', '0x%02x (TYPE_RDP_NEG_REQ)' % t)
        o.add(1, i + 1, 1, 'Flags', '0x%02x' % fl)
        o.add(1, i + 2, 2, 'Length', nl)
        o.add(1, i + 4, 4, 'Requested protocols', '0x%08x' % req)
        for bit, n in RDP_PROTO:
            o.add(2, i + 4, 4, n, 'requested' if req & bit else 'not requested')
    return 'RDP Connection Request'


def syslog(o):
    txt = o.data.decode('utf-8', 'replace')
    m = re.match(r'^<(\d{1,3})>', txt)
    if m:
        pri = int(m.group(1))
        o.add(0, 0, len(m.group(0)), 'Priority', '%d (facility %d, severity %d)' % (pri, pri >> 3, pri & 7))
        o.add(0, len(m.group(0)), len(o.data) - len(m.group(0)), 'Message', txt[len(m.group(0)):][:300])
        return 'syslog'
    return None


BY_PROTO = {'snmp': snmp, 'ldap': ldap, 'dns': dns, 'postgres': postgres, 'mysql': mysql,
            'mssql': tds, 'tds': tds, 'rdp': rdp, 'syslog': syslog}
BY_PORT = {161: 'snmp', 162: 'snmp', 53: 'dns', 514: 'syslog', 389: 'ldap', 5432: 'postgres',
           3306: 'mysql', 1433: 'mssql', 3389: 'rdp'}


def dissect(data, proto=None, port=None):
    """The bytes taken apart, as far as they can be read: {proto, summary, fields, hex}.
    What cannot be read is the bytes pane alone (fields empty)."""
    data = bytes(data or b'')
    proto = proto or BY_PORT.get(int(port or 0))
    o = _Out(data)
    summary = None
    fn = BY_PROTO.get(proto or '')
    if fn:
        try:
            summary = fn(o)
        except Exception:                               # noqa: BLE001 - never more than shown
            # as Wireshark: what could be read stays, the rest is said cut short
            if o.fields:
                o.add(0, o.fields[-1][1], 0, '[Malformed packet: cut short or not %s]'
                      % (proto or '?').upper(), '')
                summary = '%s (malformed)' % (proto or '').upper()
            else:
                summary = None
    # a stand-in of a secret never shown, in a field neither
    for f in o.fields:
        if STAND_IN.search(f[4].encode('utf-8', 'replace')):
            f[4] = DOTS
    mask = set()
    for off, ln in o.hidden:
        mask.update(range(off, off + ln))
    for m in STAND_IN.finditer(data):
        mask.update(range(m.start(), m.end()))
    cells = ['••' if i in mask else '%02x' % b for i, b in enumerate(data[:4096])]
    return {'proto': proto or '', 'summary': summary or ('%d bytes' % len(data)),
            'fields': o.fields, 'hex': hexdump(data, o.hidden), 'cells': cells,
            'bytes': len(data)}
