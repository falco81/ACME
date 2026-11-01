# -*- coding: utf-8 -*-
"""
The CRLs and certificates of acme's own authorities, published over plain
HTTP by acme itself (docs/own-ca.md, "Publishing on acme"):

    http://NAME/pki/                  a page listing what is published
    http://NAME/pki/<slug>.crl        the newest CRL, DER (application/pkix-crl)
    http://NAME/pki/<slug>.crl.pem    the same, PEM
    http://NAME/pki/<slug>.crt        the authority's certificate, DER (application/pkix-cert)
    http://NAME/pki/<slug>.pem        the same, PEM

nginx sends /pki/ (port 80 and 443, no sign-in, no redirect to HTTPS - a CRL
fetcher seldom follows one) to web/pki.php, which asks the daemon's public,
read-only routes GET /api/pki/{index,crl,cert}. Everything comes from the
database, so every node and the VIP address answer alike.

    on()                         pki_publish is on
    base_url(store)              pki_base_url, else http://<VIP name | this server's name>/pki/
    slug_of(store, row)          the authority's name in the URLs - kept in its profile, so it
                                 never changes once certificates carry it
    is_published(store, ca)      on, the authority's own switch on, a certificate, not off
    urls(store, row)             {crl, crl_pem, cert, cert_pem, index}
    serve(store, what, slug, fmt) -> (bytes, mime, filename)   only what is published
    refresh(store)               the leader's: every CRL made again past half its life
    check(store, ca_id)          fetched over HTTP from here and checked with openssl
    view(store, ca_id)           what the authority's page shows
"""
from __future__ import annotations

import json
import re
import threading
import time
import urllib.error
import urllib.request

from acmelib import engine as E
from acmelib.certs import pki
from acmelib.certs.pki import PkiError

SLUG_RX = re.compile(r'^[a-z0-9][a-z0-9._-]{0,79}\Z')
REFRESH_META = 'certs:pki:refresh'


def _ca():
    from acmelib.certs import ca
    return ca


def on():
    try:
        return bool(int(E.CONFIG.get('pki_publish', 1) or 0))
    except (TypeError, ValueError):
        return False


def _j(v, default):
    try:
        got = json.loads(v) if isinstance(v, str) and v else v
    except ValueError:
        return default
    return got if isinstance(got, type(default)) else default


def host_name(store):
    """The name the URLs are made of: the VIP address's when it is on, else
    this server's."""
    try:
        v = E.vip_conf(store)
        if v.get('on') and str(v.get('fqdn') or '').strip():
            return str(v['fqdn']).strip()
    except Exception:                                   # noqa: BLE001
        pass
    try:
        name = E.acme_name_of(store, E.node_name())
    except Exception:                                   # noqa: BLE001
        name = ''
    return str(name or E.node_name() or 'localhost').strip()


def base_url(store):
    got = str(E.CONFIG.get('pki_base_url') or '').strip()
    try:
        got = check_base_url(got)
    except ValueError:
        got = ''
    if not got:
        got = 'http://%s/pki/' % host_name(store)
    return got if got.endswith('/') else got + '/'


def check_base_url(v):
    """pki_base_url as saved: '' or an http(s) URL."""
    v = str(v or '').strip()
    if v and not re.match(r'^https?://[A-Za-z0-9._\[\]:-]+(/[A-Za-z0-9._~%/-]*)?\Z', v):
        raise ValueError('the address is http://NAME/pki/ (or empty: acme\'s own name)')
    return v


def _slugify(name):
    s = re.sub(r'[^a-z0-9._-]+', '-', str(name or '').lower()).strip('-._')
    return (s or 'ca')[:60]


def slug_of(store, row):
    """The authority's part of the URLs: made from its name the first time,
    kept in its profile from then on (unique)."""
    prof = _j(row.get('profile'), {})
    got = prof.get('pki_slug')
    if got and SLUG_RX.match(str(got)):
        return got
    taken = set()
    for r in store.db.rows('SELECT id, profile FROM cert_cas'):
        if int(r['id']) != int(row['id']):
            s = _j(r.get('profile'), {}).get('pki_slug')
            if s:
                taken.add(s)
    base = _slugify(row.get('name'))
    got = base
    if got in taken:
        got = '%s-%d' % (base, int(row['id']))
    prof['pki_slug'] = got
    store.db.run('UPDATE cert_cas SET profile = ? WHERE id = ?', (json.dumps(prof),
                                                                   int(row['id'])))
    row['profile'] = json.dumps(prof)
    return got


def _row(store, ca):
    if isinstance(ca, dict) and 'profile' in ca and 'cert_pem' in ca:
        return ca
    return store.db.row('SELECT * FROM cert_cas WHERE id = ?', (int(ca['id'] if isinstance(
        ca, dict) else ca),))


def own_switch(row):
    """The authority's own "published" switch (on unless switched off)."""
    return _j(row.get('profile'), {}).get('pki_published', True) is not False


def is_published(store, ca):
    row = _row(store, ca)
    return bool(row) and on() and own_switch(row) and bool(row.get('cert_pem')) and \
        not row.get('disabled')


def urls(store, row):
    b = base_url(store)
    s = slug_of(store, row)
    return {'index': b, 'crl': b + s + '.crl', 'crl_pem': b + s + '.crl.pem',
            'cert': b + s + '.crt', 'cert_pem': b + s + '.pem', 'slug': s}


def set_published(store, ca_id, yes, by=''):
    row = _row(store, ca_id)
    if not row:
        raise LookupError('there is no such authority')
    prof = _j(row.get('profile'), {})
    prof['pki_published'] = bool(yes)
    store.db.run('UPDATE cert_cas SET profile = ? WHERE id = ?', (json.dumps(prof),
                                                                   int(row['id'])))
    store.add_event('certificates', 'the CRL and certificate of authority %s %s on acme '
                    '(by %s)' % (row['name'], 'published' if yes else 'no longer published',
                                 by or '?'), who=by or None)
    return bool(yes)


def use_own_urls(store, ca_id, by=''):
    """crl_url and aia_url made acme's own - for what it signs from now on."""
    row = _row(store, ca_id)
    if not row:
        raise LookupError('there is no such authority')
    u = urls(store, row)
    store.db.run('UPDATE cert_cas SET crl_url = ?, aia_url = ? WHERE id = ?',
                 (u['crl'], u['cert'], int(row['id'])))
    store.add_event('certificates', 'authority %s puts acme\'s own addresses into what it signs '
                    'from now on: CRL %s, CA certificate %s (by %s)' % (
                        row['name'], u['crl'], u['cert'], by or '?'), who=by or None)
    return u


def fill_new(store, ca_id, crl_given='', aia_given=''):
    """A new (or imported) authority, with publishing on: the addresses not
    given are acme's own, so whatever it signs points here."""
    if not on():
        return {}
    row = _row(store, ca_id)
    if not row or not own_switch(row):
        return {}
    u = urls(store, row)
    crl = crl_given or row.get('crl_url') or u['crl']
    aia = aia_given or row.get('aia_url') or u['cert']
    if crl != row.get('crl_url') or aia != row.get('aia_url'):
        store.db.run('UPDATE cert_cas SET crl_url = ?, aia_url = ? WHERE id = ?',
                     (crl, aia, int(row['id'])))
    return {'crl_url': crl, 'aia_url': aia}


def find(store, slug):
    """The published authority of that slug, or None."""
    slug = str(slug or '').strip().lower()
    if not SLUG_RX.match(slug) or not on():
        return None
    for r in store.db.rows('SELECT * FROM cert_cas ORDER BY id'):
        if slug_of(store, r) == slug:
            return r if is_published(store, r) else None
    return None


def _crl_now(store, row):
    """The CRL served: the one kept, made anew only when there is none or it
    has run out (the leader keeps it fresh; this is the last resort)."""
    crl = row.get('crl_pem') or ''
    stale = not crl
    if crl:
        try:
            nu = pki.crl_info(crl).get('next_update') or 0
            stale = bool(nu) and nu <= time.time()
        except PkiError:
            stale = True
    if stale and row.get('key_sealed'):
        try:
            crl = _ca().ca_crl(store, row['id'])
        except PkiError as e:
            E.log_sparing('pki-crl:%s' % row['id'], 'the CRL of %s could not be made for '
                          'publishing: %s' % (row['name'], e), 'warn', every=3600)
    return crl


def serve(store, what, slug, fmt='der'):
    """(data, mime, filename) of a published authority's CRL or certificate -
    LookupError for anything not published."""
    row = find(store, slug)
    if not row:
        raise LookupError('nothing is published as %s' % str(slug)[:80])
    s = slug_of(store, row)
    pem = fmt == 'pem'
    if what == 'crl':
        crl = _crl_now(store, row)
        if not crl:
            raise LookupError('%s has no CRL yet' % s)
        if pem:
            return crl.encode('ascii'), 'application/x-pem-file', s + '.crl.pem'
        return pki.pem_to_der(crl), 'application/pkix-crl', s + '.crl'
    if what == 'cert':
        cert = row['cert_pem']
        if pem:
            return cert.encode('ascii'), 'application/x-pem-file', s + '.pem'
        return pki.pem_to_der(cert), 'application/pkix-cert', s + '.crt'
    raise LookupError('only crl and cert are published')


def crl_state(row):
    crl = row.get('crl_pem') or ''
    if not crl:
        return {'this_update': None, 'next_update': None, 'number': None, 'revoked': 0}
    try:
        i = pki.crl_info(crl)
    except PkiError:
        return {'this_update': None, 'next_update': None, 'number': None, 'revoked': 0}
    return {'this_update': i.get('this_update'), 'next_update': i.get('next_update'),
            'number': i.get('number'), 'revoked': len(i.get('revoked') or [])}


def index(store):
    """What the page /pki/ lists."""
    out = []
    if not on():
        return out
    for r in store.db.rows('SELECT * FROM cert_cas ORDER BY name'):
        if not is_published(store, r):
            continue
        u = urls(store, r)
        st = crl_state(r)
        out.append({'name': r['name'], 'slug': u['slug'], 'subject': r.get('subject_dn') or '',
                    'crl': u['crl'], 'crl_pem': u['crl_pem'], 'cert': u['cert'],
                    'cert_pem': u['cert_pem'], 'this_update': st['this_update'],
                    'next_update': st['next_update'], 'not_after': r.get('not_after'),
                    'fingerprint': r.get('fingerprint') or ''})
    return out


# ---------------------------------------------------------------------------
# Fresh CRLs (the leader, every certs_check_min minutes)
# ---------------------------------------------------------------------------
def refresh(store, now=None):
    """Every authority that signs (and is not switched off) given a new CRL
    past half the life of its last one, so a published CRL never runs out.
    Returns the names made anew."""
    ca = _ca()
    made = []
    for r in store.db.rows("SELECT id, name, cert_pem, key_sealed, disabled FROM cert_cas"):
        if not r.get('cert_pem') or not r.get('key_sealed') or r.get('disabled'):
            continue
        try:
            if not ca.crl_due(store, r['id']):
                continue
            ca.ca_crl(store, r['id'])
            made.append(r['name'])
        except Exception as e:                          # noqa: BLE001
            E.log_sparing('pki-refresh:%s' % r['id'], 'the CRL of %s was not made again: %s'
                          % (r['name'], e), 'warn', every=3600)
    if made:
        store.add_event('certificates', 'CRL made again (half its life was over): %s'
                        % ', '.join(made))
    store.set_meta(REFRESH_META, json.dumps({'at': time.time() if now is None else now,
                                              'node': E.node_name(), 'made': made}))
    return made


# ---------------------------------------------------------------------------
# Public asking: a few a second, whoever asks
# ---------------------------------------------------------------------------
_RATE = {'t': 0.0, 'tokens': 100.0}
_RATE_LOCK = threading.Lock()
RATE_PER_S = 50.0
RATE_BURST = 200.0


def allowed():
    with _RATE_LOCK:
        t = time.monotonic()
        _RATE['tokens'] = min(RATE_BURST, _RATE['tokens'] + (t - _RATE['t']) * RATE_PER_S)
        _RATE['t'] = t
        if _RATE['tokens'] < 1:
            return False
        _RATE['tokens'] -= 1
        return True


# ---------------------------------------------------------------------------
# "Check it": fetched over HTTP from here, read with openssl
# ---------------------------------------------------------------------------
def _fetch(url, timeout=8):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, headers={'User-Agent': 'acme-pki-check'})
    with opener.open(req, timeout=timeout) as r:
        return r.status, r.headers.get('Content-Type', ''), r.read(2 << 20)


def check(store, ca_id):
    """{ok, steps: [[level, words]]} - the CRL and the certificate fetched at
    their published URLs and checked."""
    row = _row(store, ca_id)
    if not row:
        raise LookupError('there is no such authority')
    steps = []
    ok = True

    def say(level, words):
        steps.append([level, words])
    if not on():
        say('bad', 'publishing is switched off (Settings → Certificates: Publish CRLs on acme)')
        return {'ok': False, 'steps': steps}
    if not is_published(store, row):
        say('bad', '%s is not published (its switch is off, or it has no certificate yet)'
            % row['name'])
        return {'ok': False, 'steps': steps}
    u = urls(store, row)
    say('info', 'fetching %s' % u['crl'])
    try:
        status, ctype, data = _fetch(u['crl'])
        say('ok', 'HTTP %s, %s, %d bytes' % (status, ctype or 'no content type', len(data)))
        if 'pkix-crl' not in ctype:
            say('warn', 'the content type is %r, application/pkix-crl was expected' % ctype)
        pki.openssl(['crl', '-inform', 'DER', '-noout', '-text'], data)
        say('ok', 'openssl crl -inform DER reads it')
        info = pki.crl_info(data)
        cinfo = pki.cert_info(row['cert_pem'])
        if info['issuer_dn'] == cinfo['subject_dn']:
            say('ok', 'issuer %s - the authority' % info['issuer_dn'])
        else:
            ok = False
            say('bad', 'issuer %s is not the authority (%s)' % (info['issuer_dn'],
                                                                 cinfo['subject_dn']))
        with pki.workdir() as d:
            ca_file = pki.wfile(d, 'ca.pem', row['cert_pem'])
            crl_file = pki.wfile(d, 'crl.der', data)
            try:
                pki.openssl(['crl', '-inform', 'DER', '-in', crl_file, '-CAfile', ca_file,
                             '-noout'])
                say('ok', 'its signature is the authority\'s')
            except PkiError as e:
                ok = False
                say('bad', 'its signature does not verify: %s' % e)
        nu = info.get('next_update') or 0
        if nu and nu > time.time():
            say('ok', 'next update %s (in %s)' % (
                time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(nu)),
                E.human_span(nu - time.time())))
        else:
            ok = False
            say('bad', 'it has run out (next update %s)' % (
                time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(nu)) if nu else 'none'))
        say('info', 'CRL number %s, %d revoked' % (info.get('number'),
                                                   len(info.get('revoked') or [])))
    except urllib.error.HTTPError as e:
        ok = False
        say('bad', 'HTTP %s from %s' % (e.code, u['crl']))
    except (urllib.error.URLError, OSError) as e:
        ok = False
        say('bad', 'could not be fetched: %s - does %s point at acme, and is port 80 open?' % (
            getattr(e, 'reason', e), u['crl'].split('/')[2]))
    except PkiError as e:
        ok = False
        say('bad', 'openssl does not read it as a CRL: %s' % e)
    say('info', 'fetching %s' % u['cert'])
    try:
        status, ctype, data = _fetch(u['cert'])
        got = pki.cert_info(data)
        if got['sha256'] == row.get('fingerprint') or got['sha256'] == pki.cert_info(
                row['cert_pem'])['sha256']:
            say('ok', 'HTTP %s, %s: the authority\'s certificate' % (status, ctype))
        else:
            ok = False
            say('bad', 'HTTP %s: a certificate that is not the authority\'s' % status)
    except urllib.error.HTTPError as e:
        ok = False
        say('bad', 'HTTP %s from %s' % (e.code, u['cert']))
    except (urllib.error.URLError, OSError) as e:
        ok = False
        say('bad', 'could not be fetched: %s' % getattr(e, 'reason', e))
    except PkiError as e:
        ok = False
        say('bad', 'not a certificate: %s' % e)
    if ok:
        say('ok', 'what is published is right')
    return {'ok': ok, 'steps': steps, 'urls': u}


def view(store, ca_id):
    """What the authority's page shows of its publishing."""
    row = _row(store, ca_id)
    if not row:
        raise LookupError('there is no such authority')
    u = urls(store, row)
    st = crl_state(row)
    last = _j(store.get_meta(REFRESH_META), {})
    return {'on': on(), 'switch': own_switch(row), 'published': is_published(store, row),
            'urls': u, 'base_url': base_url(store), 'crl_at': row.get('crl_at'),
            'crl_days': row.get('crl_days'), 'this_update': st['this_update'],
            'next_update': st['next_update'], 'number': st['number'],
            'own_urls': row.get('crl_url') == u['crl'] and row.get('aia_url') == u['cert'],
            'crl_url': row.get('crl_url') or '', 'aia_url': row.get('aia_url') or '',
            'refresh_due': (st['this_update'] + (st['next_update'] - st['this_update']) / 2.0)
            if st['this_update'] and st['next_update'] else None,
            'last_refresh': last or None}
