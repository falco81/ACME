# -*- coding: utf-8 -*-
"""What a target's agent tells about its server (1.0.120, docs/target-agent.md "What the agent
tells about its server").

The agent (deploy/agent/acme_agent.py, acme_agent_win.py) sends basic facts of its machine with
every hello (`system`: the OS and its version, the host's names and addresses, the CPU, the
memory, the disks of the policy's folders, the uptime, the time zone, its clock, SELinux, the
services or Windows roles a certificate is used by, a pending reboot, its Python and OpenSSL) and
their hash with every active poll (`system_hash`, and its `clock`). Nothing of it is a secret -
and everything of it is the agent's word: cleaned here strictly (known keys of known types, one
line each, cut to size, numbers finite) before it is kept in the target's state.

acme works out how far the server's clock is from its own (`skew`): a job is refused by the agent
beyond 300 s, so above 60 s it is said (amber), above 120 s it is an alert (red).
"""
from __future__ import annotations

import ipaddress
import math
import re
import time

SKEW_WARN = 60                  # s: amber - the jobs are refused at 300
SKEW_BAD = 120                  # s: red, an alert
DISK_WARN = 85                  # % used: amber
DISK_BAD = 95                   # % used: red
HEX64 = re.compile(r'[0-9a-f]{64}\Z')
ASK_EVERY_S = 120               # its hello asked for changed facts at most this often

# key: (kind, most) - text: characters; int: (low, high); enum: the words
_TEXT = {'os': 120, 'os_id': 30, 'os_version': 40, 'os_like': 60, 'edition': 60, 'build': 40,
         'kernel': 120, 'install': 30, 'arch': 20, 'machine': 120, 'cpu': 120, 'hostname': 120,
         'fqdn': 255, 'domain': 255, 'ad_domain': 80, 'workgroup': 80, 'tz': 80, 'init': 30,
         'python': 30, 'openssl': 120, 'openssl_cli': 160, 'reboot_why': 300}
_INT = {'cores': (0, 65536), 'mem_total': (0, 2 ** 56), 'mem_avail': (0, 2 ** 56),
        'boot': (0, 2 ** 33), 'uptime': (0, 2 ** 33), 'tz_offset': (-1080, 1080)}
_ENUM = {'platform': ('linux', 'windows'), 'selinux': ('enforcing', 'permissive', 'disabled')}
_BOOL = ('reboot', 'apparmor')
LISTS = {'addrs': 16, 'disks': 8, 'services': 40}


def _line(v, most):
    """The agent's words as one line of text: no control characters, cut."""
    if not isinstance(v, str):
        return ''
    t = re.sub(r'[\t\r\n  \x85\x0b\x0c]+', ' ', v)
    t = re.sub(r'[\x00-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]', '', t)
    return t.strip()[:most]


def _num(v, lo, hi, integer=True):
    """A finite number in [lo, hi] (a bool, a string, NaN, Infinity: None)."""
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        if not math.isfinite(v) or v < lo or v > hi:
            return None
    except (TypeError, OverflowError):
        return None
    return int(v) if integer else float(v)


def _ip(v):
    t = _line(v, 60)
    addr, _s, bits = t.partition('/')
    try:
        a = ipaddress.ip_address(addr)
    except ValueError:
        return ''
    if bits and not (bits.isdigit() and int(bits) <= (32 if a.version == 4 else 128)):
        bits = ''
    return str(a) + ('/' + bits if bits else '')


def clean(d):
    """The facts as acme keeps them - or None when it is nothing of the kind."""
    if not isinstance(d, dict):
        return None
    out = {}
    for k, most in _TEXT.items():
        t = _line(d.get(k), most)
        if t:
            out[k] = t
    for k, (lo, hi) in _INT.items():
        n = _num(d.get(k), lo, hi)
        if n is not None:
            out[k] = n
    for k, words in _ENUM.items():
        if d.get(k) in words:
            out[k] = d[k]
    for k in _BOOL:
        if isinstance(d.get(k), bool):
            out[k] = d[k]
    clock = _num(d.get('clock'), 0, 2 ** 33, integer=False)
    if clock is not None:
        out['clock'] = round(clock, 3)
    if isinstance(d.get('hash'), str) and HEX64.match(d['hash']):
        out['hash'] = d['hash']
    if 'mem_avail' in out and 'mem_total' in out and out['mem_avail'] > out['mem_total']:
        out.pop('mem_avail')
    load = d.get('load')
    if isinstance(load, list):
        ld = [_num(x, 0, 1e6, integer=False) for x in load[:3]]
        if ld and all(x is not None for x in ld):
            out['load'] = [round(x, 2) for x in ld]
    addrs = []
    for a in (d.get('addrs') if isinstance(d.get('addrs'), list) else [])[:64]:
        if isinstance(a, dict):
            ip = _ip(a.get('ip'))
            if ip:
                addrs.append({'if': _line(a.get('if'), 20), 'ip': ip})
        if len(addrs) >= LISTS['addrs']:
            break
    if addrs:
        out['addrs'] = addrs
    disks = []
    for x in (d.get('disks') if isinstance(d.get('disks'), list) else [])[:64]:
        if not isinstance(x, dict):
            continue
        size = _num(x.get('size'), 1, 2 ** 60)
        free = _num(x.get('free'), 0, 2 ** 60)
        path = _line(x.get('path'), 260)
        if size is None or free is None or not path or free > size:
            continue
        one = {'path': path, 'size': size, 'free': free}
        fs = _line(x.get('fs'), 20)
        if fs:
            one['fs'] = fs
        disks.append(one)
        if len(disks) >= LISTS['disks']:
            break
    if disks:
        out['disks'] = disks
    svcs = []
    for x in (d.get('services') if isinstance(d.get('services'), list) else [])[:200]:
        if not isinstance(x, dict):
            continue
        name = _line(x.get('name'), 40)
        if not name:
            continue
        one = {'name': name, 'state': 'active' if x.get('state') == 'active' else 'present'}
        det = _line(x.get('detail'), 60)
        if det:
            one['detail'] = det
        svcs.append(one)
        if len(svcs) >= LISTS['services']:
            break
    if svcs:
        out['services'] = svcs
    return out if out else None


def clean_hash(v):
    return v if isinstance(v, str) and HEX64.match(v) else ''


def skew_of(clock, at):
    """The server's clock against acme's (s, + ahead) - None for no clock or a mad one."""
    c = _num(clock, 0, 2 ** 33, integer=False)
    if c is None:
        return None
    s = c - float(at)
    return round(s, 1) if abs(s) < 10 * 365 * 86400 else None


def skew_level(s):
    if s is None:
        return ''
    return 'bad' if abs(s) > SKEW_BAD else ('warn' if abs(s) > SKEW_WARN else 'ok')


def seen_skew(st, skew, now=None):
    """The skew kept in the state -> True when it is worth writing (changed, or said long ago)."""
    if skew is None:
        return False
    now = now or time.time()
    old = st.get('skew')
    if isinstance(old, (int, float)) and abs(old - skew) < 1 and \
            now - float(st.get('skew_at') or 0) < 300:
        return False
    st['skew'], st['skew_at'] = skew, now
    return True


def seen_hello(st, got, t0, t1):
    """A hello's answer (cleaned): its facts kept, with when they were said and the skew - or,
    an agent that said none, that it is too old to tell."""
    facts = got.get('system') if isinstance(got.get('system'), dict) else None
    if not facts:
        if got.get('ok') and got.get('version'):
            st['system_none'] = True
        return
    st.pop('system_none', None)
    st['system'] = facts
    st['system_at'] = t1
    dur = max(0.0, t1 - t0)
    # the clock read on the server between asking and the answer: the middle, when that is
    # short enough to mean something (an active agent's job waits for its poll: its poll's
    # own clock says the skew)
    if dur <= 4:
        seen_skew(st, skew_of(facts.get('clock'), t0 + dur / 2), t1)


def asked_for(st, sys_hash):
    """Its poll says facts acme does not hold: ask its hello (at most every ASK_EVERY_S)."""
    h = clean_hash(sys_hash)
    held = (st.get('system') or {}).get('hash') if isinstance(st.get('system'), dict) else ''
    return bool(h) and h != held


def _pct(d):
    try:
        return round(100.0 * (d['size'] - d['free']) / d['size'], 1)
    except (KeyError, TypeError, ZeroDivisionError):
        return None


def view(st, now=None):
    """What the pages, the command line and the console show: the facts, how old, the skew,
    what is worth a look (warnings) - or why there are none."""
    now = now or time.time()
    f = st.get('system') if isinstance(st.get('system'), dict) else None
    out = {'state': 'ok' if f else ('old' if st.get('system_none') else 'unknown'),
           'at': st.get('system_at') if f else None, 'facts': None, 'skew': None,
           'skew_at': None, 'skew_level': '', 'uptime': None, 'warnings': []}
    skew = st.get('skew') if isinstance(st.get('skew'), (int, float)) else None
    if skew is not None:
        out.update(skew=skew, skew_at=st.get('skew_at'), skew_level=skew_level(skew))
    if not f:
        return out
    f = dict(f)
    out['facts'] = f
    at = float(st.get('system_at') or now)
    if isinstance(f.get('uptime'), int):
        out['uptime'] = int(f['uptime'] + max(0.0, now - at))
    for dk in f.get('disks') or []:
        dk['used_pct'] = _pct(dk)
    w = out['warnings']
    if out['skew_level'] in ('warn', 'bad'):
        w.append({'key': 'skew', 'level': out['skew_level'],
                  'words': 'its clock is %d s %s acme\'s' % (abs(skew), 'ahead of' if skew > 0
                                                              else 'behind')})
    for dk in f.get('disks') or []:
        p = dk.get('used_pct')
        if p is not None and p > DISK_WARN:
            w.append({'key': 'disk', 'level': 'bad' if p > DISK_BAD else 'warn',
                      'words': '%s is %d %% full' % (dk['path'], int(p))})
    if f.get('reboot'):
        w.append({'key': 'reboot', 'level': 'warn',
                  'words': 'a restart is pending' + (' (%s)' % f['reboot_why']
                                                     if f.get('reboot_why') else '')})
    return out


# ---- in words: the command line, the console ----------------------------------------------------
def _bytes(n):
    n = float(n or 0)
    for unit in ('B', 'kB', 'MB', 'GB', 'TB', 'PB'):
        if n < 1024 or unit == 'PB':
            return ('%d %s' % (n, unit)) if unit == 'B' else '%.1f %s' % (n, unit)
        n /= 1024
    return '%d B' % n


def span(s):
    """Seconds as '3 d 4 h' / '5 h 12 min' / '42 min' / '17 s'."""
    s = int(s or 0)
    d, h, m = s // 86400, s % 86400 // 3600, s % 3600 // 60
    if d:
        return '%d d %d h' % (d, h)
    if h:
        return '%d h %d min' % (h, m)
    if m:
        return '%d min' % m
    return '%d s' % s


def _when(ts):
    try:
        return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(ts))) if ts else '-'
    except (TypeError, ValueError):
        return '-'


def lines(v, now=None):
    """[(key, words)] of a view(), as `acme --target-agent NAME system` prints them."""
    now = now or time.time()
    if not v or v.get('state') != 'ok':
        if v and v.get('state') == 'old':
            return [('server', 'the agent is too old to tell (update it)')]
        return [('server', 'not said yet (look asks it)')]
    f = v['facts']
    rows = []
    osw = f.get('os') or '?'
    ver = f.get('os_version') or ''
    if ver and ver not in osw:
        osw += ' (%s)' % ver
    rows.append(('os', osw))
    if f.get('edition'):
        rows.append(('edition', f['edition'] + (' - %s' % f['install'] if f.get('install')
                                                else '')))
    if f.get('build') or f.get('kernel'):
        rows.append(('build' if f.get('platform') == 'windows' else 'kernel',
                     f.get('build') or f.get('kernel')))
    if f.get('arch'):
        rows.append(('architecture', f['arch']))
    if f.get('machine'):
        rows.append(('machine', f['machine']))
    rows.append(('hostname', f.get('hostname') or '-'))
    if f.get('fqdn'):
        rows.append(('fqdn', f['fqdn']))
    if f.get('ad_domain'):
        rows.append(('AD domain', f['ad_domain']))
    elif f.get('workgroup'):
        rows.append(('workgroup', f['workgroup']))
    elif f.get('domain'):
        rows.append(('domain', f['domain']))
    if f.get('addrs'):
        rows.append(('addresses', ', '.join(('%s %s' % (a['if'], a['ip'])).strip()
                                            for a in f['addrs'])))
    if f.get('cpu') or f.get('cores'):
        rows.append(('cpu', '%s%s' % (f.get('cpu') or '', (' (%d cores)' % f['cores'])
                                      if f.get('cores') else '')))
    if f.get('mem_total'):
        avail = f.get('mem_avail')
        rows.append(('memory', '%s%s' % (_bytes(f['mem_total']), (', %s available' %
                                                                  _bytes(avail)) if avail
                                         is not None else '')))
    for dk in f.get('disks') or []:
        rows.append(('disk %s' % dk['path'], '%s, %s free (%s %% used)%s' % (
            _bytes(dk['size']), _bytes(dk['free']), dk.get('used_pct'),
            ' ' + dk['fs'] if dk.get('fs') else '')))
    if v.get('uptime') is not None:
        rows.append(('uptime', span(v['uptime'])))
    if f.get('boot'):
        rows.append(('started', _when(f['boot'])))
    if f.get('tz'):
        off = f.get('tz_offset')
        rows.append(('time zone', f['tz'] + (' (UTC%+03d:%02d)' % (int(off / 60), abs(off) % 60)
                                             if isinstance(off, int) else '')))
    if v.get('skew') is not None:
        s = v['skew']
        rows.append(('clock', '%s%s' % ('%+.1f s against acme\'s' % s, {
            'warn': ' - check its time (jobs are refused at 300 s)',
            'bad': ' - SET ITS CLOCK RIGHT (jobs are refused at 300 s)'}.get(v['skew_level'],
                                                                         ''))))
    if f.get('selinux'):
        rows.append(('SELinux', f['selinux']))
    if f.get('init'):
        rows.append(('init', f['init']))
    if 'reboot' in f:
        rows.append(('restart pending', ('yes' + (' - %s' % f['reboot_why']
                                                  if f.get('reboot_why') else ''))
                     if f['reboot'] else 'no'))
    svcs = f.get('services') or []
    if svcs:
        rows.append(('roles' if f.get('platform') == 'windows' else 'services', ', '.join(
            '%s%s%s' % (x['name'], ' (%s)' % x['detail'] if x.get('detail') else '',
                        '' if x['state'] == 'active' else ' [not running]') for x in svcs)))
    if f.get('python'):
        rows.append(('python', f['python']))
    if f.get('openssl'):
        rows.append(('openssl', f['openssl'] + (' / %s' % f['openssl_cli']
                                                if f.get('openssl_cli') and
                                                f['openssl_cli'] != f['openssl'] else '')))
    rows.append(('said', '%s (%s ago)' % (_when(v.get('at')), span(now - float(v.get('at')
                                                                              or now)))))
    return rows
