# -*- coding: utf-8 -*-
from __future__ import annotations
# ---- new versions from the web (1.0.123) ---------------------------------------------
# Settings → Upgrades → upgrade_url is asked once a day (upgrade_check) and when
# Look now is pressed, for acme-X.Y.Z.tar.gz: a GitHub folder by the index.json
# tools/release.py writes into it (from raw.githubusercontent.com - no API and
# its limit), else through GitHub's API, else its page; an index.json, a JSON
# list or any other page by the links in it; or one package's own address.
# index.json is a list, newest first, of
#   {"name": "acme-X.Y.Z.tar.gz", "version": "X.Y.Z", "size": N,
#    "sha256": "...", "date": "...Z", "download_url": "https://raw..."}
# and a package fetched is held to its sha256 before it is even checked. The
# newest one newer than what runs here is offered (any newer one there can be
# chosen instead, 1.0.142); one click fetches it, and it
# goes the road of a package sent by hand - its signature checked, kept in the
# database for every node, and the upgrade begun. Nothing is put in by itself.
ONLINE_PKG_RE = re.compile(r'(?:^|/)(acme-(\d+)\.(\d+)\.(\d+)\.tar\.gz)(?:\?|#|$)')
ONLINE_EVERY_S = 86400
ONLINE_WORK = {'busy': False, 'at': 0.0}
ONLINE_LOCK = threading.Lock()


def _online_get(url, limit=4 * 1024 * 1024, accept='*/*', timeout=30):
    if not str(url).startswith('https://'):
        raise ValueError('only https:// addresses are asked: %s' % url)
    req = urllib.request.Request(url, headers={
        'User-Agent': 'acme/%s (+upgrade check)' % __version__, 'Accept': accept})
    ctx = ssl.create_default_context()
    with url_open(req, timeout=timeout, context=ctx, purpose='update') as r:
        final = r.geturl()
        if not str(final).startswith('https://'):
            raise ValueError('it was sent on to an address that is not https: %s' % final)
        data = r.read(limit + 1)
        if len(data) > limit:
            raise ValueError('the answer from %s is bigger than %d MB' % (url, limit >> 20))
        return data, r.headers.get('Content-Type') or '', final


def _online_ver(m):
    return tuple(int(x) for x in m.group(2, 3, 4))


# Where the releases were before 1.0.138: a value saved as it was the default
# then is taken as the new place.
ONLINE_URL_OLD = 'https://github.com/falco81/Utils/tree/main/acme'


def online_url():
    url = str(CONFIG.get('upgrade_url') or '').strip()
    return DEFAULTS['upgrade_url'] if url.rstrip('/') == ONLINE_URL_OLD else url


def online_list(url):
    """The packages at `url`: [{'name', 'version', 'url', 'bytes'}], newest first."""
    url = str(url or '').strip()
    if not url:
        raise ValueError('no address to look at (Settings → Upgrades)')
    found = {}

    def add(name, link, size=None, sha256=None, date=None):
        m = ONLINE_PKG_RE.search('/' + name)
        if not m or not str(link).startswith('https://'):
            return
        found[m.group(1)] = {'name': m.group(1), 'version': '%d.%d.%d' % _online_ver(m),
                             'v': _online_ver(m), 'url': link, 'bytes': size}
        if sha256 and re.match(r'^[0-9a-f]{64}\Z', str(sha256)):
            found[m.group(1)]['sha256'] = str(sha256)
        if date:
            found[m.group(1)]['date'] = str(date)[:40]

    def add_index(items, final):
        """The entries of an index.json (or any JSON list of packages)."""
        for it in items:
            if isinstance(it, dict):
                link = it.get('download_url') or it.get('url') or ''
                add(str(it.get('name') or link), urllib.parse.urljoin(final, str(link)),
                    it.get('size'), it.get('sha256'), it.get('date'))

    gh = re.match(r'^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)'
                  r'(?:/tree/([^/]+)(?:/(.*?))?)?/?$', url)
    m1 = ONLINE_PKG_RE.search(urllib.parse.urlparse(url).path)
    if m1:
        # One package's own address - a GitHub page of it read as the file.
        link = url
        b = re.match(r'^https://github\.com/([^/]+)/([^/]+)/blob/(.+)$', url)
        if b:
            link = 'https://raw.githubusercontent.com/%s/%s/%s' % b.groups()
        add(m1.group(1), link)
    elif gh:
        owner, repo, ref, folder = gh.group(1), gh.group(2), gh.group(3), gh.group(4) or ''
        sub = (folder.strip('/') + '/') if folder.strip('/') else ''
        raw_base = 'https://raw.githubusercontent.com/%s/%s/%s/%s' % (owner, repo, ref or 'HEAD', sub)
        # raw.githubusercontent.com keeps a file of a branch 5 minutes (max-age=300),
        # and an address with ?anything does not get past it: just after a release
        # "Look now" read the index before it (1.0.36). The branch's newest commit,
        # asked of GitHub's API (one question), names an address that never goes
        # stale; the branch's own address stays where the API does not answer.
        if not re.match(r'^[0-9a-f]{40}\Z', ref or ''):
            try:
                sha, _ct, _f = _online_get('https://api.github.com/repos/%s/%s/commits/%s' % (
                    owner, repo, urllib.parse.quote(ref or 'HEAD')), limit=4096,
                    accept='application/vnd.github.sha', timeout=15)
                sha = sha.decode('ascii', 'replace').strip()
                if re.match(r'^[0-9a-f]{40}\Z', sha):
                    raw_base = 'https://raw.githubusercontent.com/%s/%s/%s/%s' % (owner, repo, sha, sub)
            except Exception:                           # noqa: BLE001
                pass
        try:
            # The folder's own index.json first: what tools/release.py wrote,
            # with each package's sha256 - and no API, nor its 60 an hour.
            data, _ct, final = _online_get(raw_base + 'index.json', limit=1024 * 1024,
                                           accept='application/json')
            items = json.loads(data.decode('utf-8'))
            if isinstance(items, list):
                add_index(items, final)
        except Exception:                               # noqa: BLE001
            pass
        api = 'https://api.github.com/repos/%s/%s/contents/%s' % (
            owner, repo, urllib.parse.quote(folder.strip('/')))
        if ref:
            api += '?ref=' + urllib.parse.quote(ref)
        try:
            if found:
                items = []              # the index said it all
            else:
                data, _ct, _f = _online_get(api, accept='application/vnd.github+json')
                items = json.loads(data.decode('utf-8'))
        except Exception as e:                          # noqa: BLE001
            # GitHub's API refused (60 questions an hour without an account,
            # or not let through): the folder's own page, read for the names.
            try:
                data, _ct, _f = _online_get(url)
            except Exception:                           # noqa: BLE001
                raise ValueError('GitHub did not answer: %s' % (getattr(e, 'reason', None) or e))
            items = []
            base = raw_base
            for name in set(re.findall(r'acme-\d+\.\d+\.\d+\.tar\.gz',
                                       data.decode('utf-8', 'replace'))):
                items.append({'type': 'file', 'name': name, 'download_url': base + name})
        if isinstance(items, dict):
            items = [items]
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict) and it.get('type') == 'file' and it.get('download_url'):
                add(str(it.get('name') or ''), str(it['download_url']), it.get('size'))
    else:
        data, ct, final = _online_get(url)
        text = data.decode('utf-8', 'replace')
        try:
            items = json.loads(text) if 'json' in ct or text.lstrip()[:1] in '[{' else None
        except ValueError:
            items = None
        if isinstance(items, list):
            add_index(items, final)
        else:
            for href in re.findall(r'''href\s*=\s*["']([^"']+)["']''', text, re.I):
                link = urllib.parse.urljoin(final, html.unescape(href))
                mm = ONLINE_PKG_RE.search(urllib.parse.urlparse(link).path)
                if mm:
                    add(mm.group(1), link)
    out = sorted(found.values(), key=lambda x: x['v'], reverse=True)
    for x in out:
        x.pop('v', None)
    return out


def _ver_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split('.')[:3])
    except ValueError:
        return (0, 0, 0)


def online_look(store, by=''):
    """Asks the address now; what it found goes into meta 'upgrade:online'."""
    url = online_url()
    row = {'at': time.time(), 'url': url, 'by': by, 'node': node_name(), 'here': __version__}
    try:
        got = online_list(url)
        row['packages'] = got[:10]
        newest = got[0] if got else None
        row['newest'] = newest
        row['newer'] = bool(newest and _ver_tuple(newest['version']) > _ver_tuple(__version__))
        if row['newer']:
            was = _meta_obj(store, 'upgrade:online')
            if ((was.get('newest') or {}).get('version') != newest['version']):
                store.add_event('starting and stopping', 'acme %s is out (%s) - Settings → '
                                'Upgrades' % (newest['version'], url), 'info')
    except Exception as e:                              # noqa: BLE001
        row['error'] = str(getattr(e, 'reason', None) or e).split('\n')[0][:300]
    store.set_meta('upgrade:online', json.dumps(row, default=str))
    return row


def online_tick(daemon):
    """Once a day, from whichever node it falls to first."""
    if not CONFIG.get('upgrade_check') or not online_url():
        return
    if time.time() - float(ONLINE_WORK['at'] or 0) < 300:
        return
    ONLINE_WORK['at'] = time.time()
    store = daemon.store
    # One node of a replicated pair looks (1.0.56): both nodes' first look INSERTed the one
    # row and replication stopped. The other takes over when it hears no other (ha_lead).
    if CONFIG.get('ha_mode') == 'replicated' and not ha_lead_heard(store):
        return                  # looked at again in five minutes
    last = _meta_obj(store, 'upgrade:online')
    # Asked again once the address changed, or a day after the last look.
    if last.get('url') == online_url() and \
            time.time() - float(last.get('at') or 0) < ONLINE_EVERY_S:
        return
    with ONLINE_LOCK:
        if ONLINE_WORK['busy']:
            return
        ONLINE_WORK['busy'] = True

    def go():
        try:
            online_look(store)
        except Exception as e:                          # noqa: BLE001
            log('looking for a new version: %s' % e, 'warn')
        finally:
            ONLINE_WORK['busy'] = False
    threading.Thread(target=go, name='acme-online', daemon=True).start()


def online_view(store):
    row = _meta_obj(store, 'upgrade:online')
    if row:
        n = row.get('newest') or {}
        row['newer'] = bool(n and _ver_tuple(n.get('version')) > _ver_tuple(__version__))
        row['here'] = __version__
        # Every version there newer than this one, newest first (1.0.142): with
        # more than one the page lets you choose which to go to.
        row['newer_list'] = sorted(
            (p for p in row.get('packages') or []
             if _ver_tuple(p.get('version')) > _ver_tuple(__version__)),
            key=lambda p: _ver_tuple(p.get('version')), reverse=True)
    return {'online': row, 'url': online_url(),
            'check': bool(CONFIG.get('upgrade_check'))}


def online_fetch(store, version, by, older=False):
    """The package of `version` fetched from where it was found, checked and
    kept as one sent by hand would be: its meta. `older`: one to go back to
    (1.0.143), kept only if downgrade_take finds nothing in its way."""
    pk = [p for p in online_list(online_url())
          if p['version'] == str(version)]
    if not pk:
        raise ValueError('acme %s is not at %s any more' % (version, online_url()))
    pk = pk[0]
    if older and _ver_tuple(pk['version']) >= _ver_tuple(__version__):
        raise ValueError('acme %s is not older than %s, which runs here' % (pk['version'],
                                                                           __version__))
    if not older and _ver_tuple(pk['version']) <= _ver_tuple(__version__):
        raise ValueError('acme %s is not newer than %s, which runs here' % (pk['version'], __version__))
    UPGRADE_DIR.mkdir(mode=0o750, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix='online-', suffix='.tar.gz', dir=str(UPGRADE_DIR))
    os.close(fd)
    tmp = Path(tmp)
    try:
        data, _ct, final = _online_get(pk['url'], limit=UPGRADE_MOST, timeout=300)
        if pk.get('sha256') and hashlib.sha256(data).hexdigest() != pk['sha256']:
            raise ValueError('the package from %s is not the one its index.json names (its '
                             'SHA-256 differs) - fetched half, or changed' % final)
        tmp.write_bytes(data)
        try:
            info = upgrade_inspect(tmp)
        except ValueError as e:
            store.add_event('starting and stopping', 'acme %s from %s was refused: %s'
                            % (version, final, e), 'warn', who=by)
            raise ValueError('the package from %s was refused: %s' % (final, e))
        if older:
            if not info.get('older') and _ver_tuple(info['version']) >= _ver_tuple(__version__):
                raise ValueError('%s is not older than %s' % (info['version'], __version__))
            return downgrade_take(store, tmp, info, by)
        if info.get('older'):
            raise ValueError('%s is older than %s, which runs here' % (info['version'],
                                                                         info.get('installed')))
        meta = upgrade_store_package(store, tmp, info, by)
        store.add_event('starting and stopping', '%s fetched acme %s from %s (signed by %s), '
                        'ready to be put in' % (by, meta['version'], final, meta.get('signed_by')),
                        'warn', who=by)
        return meta
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


