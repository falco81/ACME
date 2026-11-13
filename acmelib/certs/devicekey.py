# -*- coding: utf-8 -*-
"""
"The device makes the key" (docs/certificates.md "Key made by the device"): a certificate
whose key a target's device makes itself - Lenovo XCC, Dell OpenManage Enterprise, Cisco
CUCM... - the devices that take only a certificate for a CSR of their own.

A certificate says where its key is made in certs.csr_from (the name of a target whose
module has device_key = True). Then:

    issue / renewal     the target's device_csr(req) is asked for a fresh CSR at every one
                        (renewer._issue_one): acme holds no key, the CSR is used as one
                        sent in (csr_given) is - its names and key type checked, the
                        certificate issued checked to be for its key; kept in csr_pending
                        ({'device': ...}) and used again until the issue is done (a source
                        holding the request), cleared when the version is saved
    deployment          to that target only, made with the certificate (cert_save); it
                        runs right after the issue in the same job: deploy() gets the
                        bundle with no key and the device installs the certificate
    refused with it     a twin (key_type_alt), reuse_key, a CSR sent in (csr_given), a
                        source that signs no CSR, a deployment to another target - and a
                        device_key target for any certificate not made for its key

    target_of(store, name)              (row, class) of a device_key target, or ValueError
    save_problem(store, cert, deploys)  why a certificate saved with csr_from cannot be so
    deploy_problem(store, cert, trow, cls)   why that certificate cannot go to that target
    version_problem(store, cert)        why the version it holds fits not where its key is made
    deploy_failed(store, job, cert, ...)     its deployment to the device failing: issued anew
    csr_for(store, job, cert, ...)      the CSR the device made, checked (renewer)
    check_csr(info, names, sans, ...)   a CSR's names against the certificate's
    dummy_csr(names, key_type)          a CSR for the names (What happens' sandbox)
"""
from __future__ import annotations

import json
import time

from acmelib.plugins import base
from acmelib.certs import store as S

HOW = ('the certificate form: "Key made by the device", or acme --cert-add NAME --names ... '
       '--csr-from TARGET')


def device_class(store, trow):
    """The module class of a target row when it makes keys (device_key), else None."""
    if not trow:
        return None
    cls = S.row_class('target', trow)
    return cls if cls is not None and getattr(cls, 'device_key', False) else None


def target_of(store, name):
    """(row, class) of the target `name` whose device makes the key. ValueError in words."""
    name = str(name or '').strip()
    trow = S.plugin_row(store, 'target', name) if name else None
    if not trow:
        raise ValueError('there is no target %s - the key is made by a target whose device '
                         'makes its own key and CSR' % name)
    cls = S.row_class('target', trow)
    if cls is None:
        raise ValueError('the module of the target %s (%s) is not there' % (trow['name'],
                                                                           trow.get('kind')))
    if not getattr(cls, 'device_key', False):
        raise ValueError('the target %s (%s) does not make keys: its module takes a certificate '
                         'with acme\'s key - choose a target whose device makes the key, or let '
                         'acme make it' % (trow['name'], cls.title or cls.kind))
    return trow, cls


def key_types_of(cls):
    """The key types the device can make, None: any."""
    kts = getattr(cls, 'device_key_types', None)
    return list(kts) if kts else None


def save_problem(store, cert, deploys=None, one_per_device=True):
    """Why `cert` (a row as it would be saved, with csr_from) cannot be so - words, or ''.
    `deploys`: its deployments' targets (None: read). `one_per_device`: another certificate
    whose key the same device makes refused - only when csr_from is set or changed (two saved
    before 1.0.96 can still be edited; the renewer warns of them, devicekey.sharing)."""
    src = str(cert.get('csr_from') or '').strip()
    if not src:
        return ''
    try:
        trow, cls = target_of(store, src)
    except ValueError as e:
        return str(e)
    if str(cert.get('csr_given') or '').strip():
        return ('it is issued for a CSR sent in - its key is where that CSR was made, not on '
                '%s' % trow['name'])
    if cert.get('key_type_alt'):
        return ('the device %s makes one key - a twin with another kind of key (%s) cannot be '
                'made: choose no twin' % (trow['name'], cert['key_type_alt']))
    if int(cert.get('reuse_key') or 0):
        return ('the device %s makes a new key at every renewal - "Keep the key" (reuse_key) '
                'is for keys acme holds: switch it off' % trow['name'])
    kts = key_types_of(cls)
    kt = cert.get('key_type') or 'ec-256'
    if kts and kt not in kts:
        return ('%s makes %s keys only - choose one of those (not %s)'
                % (trow['name'], ', '.join(kts), kt))
    if cert.get('id'):
        # what the device takes, with the options of its deployment there (1.0.96: a Synergy
        # enclosure's name an IP address was refused only at the issue)
        for d in store.db.rows('SELECT options FROM cert_deploys WHERE cert_id = ? AND '
                               'target = ?', (int(cert['id']), trow['name'])):
            why = fit_problem(cls, cert, S.jload(d.get('options'), {}) or {})
            if why:
                return why
    iss = str(cert.get('issuer') or '').strip()
    if not iss:
        return ('a certificate whose key the device makes is issued for its CSR: give it a '
                'source that signs a CSR (an ACME CA, an authority of acme\'s own...)')
    from acmelib.certs import reqprofiles as RP
    irow, icls, _info = RP.issuer_info(store, iss)
    if irow and not RP.csr_ok(irow, icls):
        return ('the source %s cannot sign a CSR made elsewhere (it signs only a key it or acme '
                'makes) - choose another source for a key the device makes' % irow['name'])
    if deploys is None and cert.get('id'):
        deploys = [r['target'] for r in store.db.rows(
            'SELECT target FROM cert_deploys WHERE cert_id = ?', (cert['id'],))]
    other = [t for t in (deploys or []) if t != trow['name']]
    if other:
        return ('it is deployed to %s too - a certificate whose key %s makes goes there alone '
                '(no other target can have its key): take those deployments away first'
                % (', '.join(sorted(set(other))), trow['name']))
    # One certificate per device: the device holds one pending key - a second certificate's
    # CSR replaced the first one's key, and each renewal took the other's certificate away.
    twin = sharing(store, cert, trow['name']) if one_per_device else None
    if twin:
        return ('the device %s already makes the key of the certificate %s - a device holds one '
                'pending key, so a second certificate would replace the key of the first: '
                'change that certificate (add these names to it), or choose another target'
                % (trow['name'], twin['name']))
    return ''


def fit_problem(cls, cert, options):
    """Why the device (module class `cls`) cannot make the key of `cert` (its names and key
    type) deployed with `options` - its module's device_key_problem, words or ''."""
    fn = getattr(cls, 'device_key_problem', None) if cls is not None else None
    if not callable(fn):
        return ''
    names = cert.get('names')
    if isinstance(names, str):
        names = S.jload(names, []) or []
    try:
        return str(fn(list(names or []), str(cert.get('key_type') or 'ec-256'),
                      dict(options or {})) or '')
    except Exception:                                   # noqa: BLE001
        return ''


def sharing(store, cert, device):
    """Another certificate whose key the device `device` makes ({'name'}), or None."""
    return store.db.row('SELECT name FROM certs WHERE csr_from = ? AND id <> ? ORDER BY name',
                        (device, int(cert.get('id') or 0)))


def deploy_problem(store, cert, trow, cls=None, version=True, saving=None):
    """Why the certificate `cert` cannot be deployed to the target `trow` - words, or ''.
    `version`: the version it holds checked to fit where its key is made too (a deployment
    run; not when a deployment is only saved). `saving`: the id of the deployment being saved
    (0: a new one) - a second deployment to the device that makes its key refused (1.0.96: the
    certificate window offered the device again, and two deployments of one certificate went
    to one device)."""
    src = str(cert.get('csr_from') or '').strip()
    if src and src != trow['name']:
        return ('the key of %s is made by %s and stays there - it can be deployed only to %s '
                '(no other target can have its key)' % (cert['name'], src, src))
    if src and saving is not None and cert.get('id') and store.db.value(
            'SELECT id FROM cert_deploys WHERE cert_id = ? AND target = ? AND id <> ?',
            (int(cert['id']), src, int(saving or 0)), None):
        return ('%s is deployed to %s already - a certificate whose key the device makes has one '
                'deployment there (change that one)' % (cert['name'], src))
    cls = cls if cls is not None else S.row_class('target', trow)
    if cls is not None and getattr(cls, 'device_key', False) and src != trow['name']:
        return ('%s makes the key itself and takes only a certificate for it - add a '
                'certificate whose key it makes (%s %s)'
                % (trow['name'], HOW.replace('TARGET', trow['name']),
                   '' if not src else '- this one\'s key is made by %s' % src))
    return version_problem(store, cert) if version else ''


def version_problem(store, cert):
    """Why the version the certificate holds does not fit where its key is made - words, or ''.
    Switched to "Key made by the device" (or away from it) after it was issued, the version
    it holds is of the other kind: acme's key for a device that makes its own, or a device's
    key, which acme does not hold, for a target that takes acme's."""
    if not cert.get('cert_pem'):
        return ''
    src = str(cert.get('csr_from') or '').strip()
    if src and cert.get('key_sealed'):
        return ('version %s of %s holds a key acme made, but its key is made by the device of %s '
                'now - that version fits no key there: it is issued anew for a key the device '
                'makes (Renew now issues it at once)' % (cert.get('version'), cert['name'], src))
    if not src and not cert.get('key_sealed') and not str(cert.get('csr_given') or '').strip():
        why = store.db.value('SELECT why FROM cert_versions WHERE cert_id = ? AND version = ? '
                             "AND COALESCE(variant, '') <> 'alt'",
                             (cert['id'], cert.get('version') or 0), None)
        if why in ('issue', 'renewal'):
            # issued with no key and no CSR sent in now: for the key a device made
            return ('version %s of %s was issued for a key its device made, which acme does '
                    'not hold - acme makes its key now: it is issued anew with acme\'s key first '
                    '(Renew now issues it at once)' % (cert.get('version'), cert['name']))
    return ''


# ---------------------------------------------------------------------------
# The CSR the device makes
# ---------------------------------------------------------------------------
def _clean(values):
    try:
        return S.clean_names(list(values or []))
    except ValueError:
        return [str(v).strip().lower().rstrip('.') for v in values or []]


def check_csr(info, names, sans=None, who='the device', strict_cn=False):
    """A CSR (pki.csr_info) against the certificate: every name asked in it, nothing else.
    Raises PluginError in words."""
    from acmelib.certs import pki
    if not pki.csr_verify(info['pem']):
        raise base.PluginError('the CSR %s made is not signed by the key in it' % who,
                               retry=False)
    want = _clean(names)
    dns = [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')]
    got = _clean(dns or ([info['cn']] if info.get('cn') else []))
    extra = [n for n in got if n not in want]
    if extra:
        raise base.PluginError('the CSR %s made names %s, which the certificate does not ask '
                               'for (it asks for %s)' % (who, ', '.join(extra), ', '.join(want)),
                               retry=False)
    missing = [n for n in want if n not in got]
    if missing:
        raise base.PluginError('the CSR %s made does not name %s (it names %s) - the device '
                               'did not take every name; give the certificate only the names '
                               'the device puts in its CSR' % (who, ', '.join(missing),
                                                               ', '.join(got) or 'nothing'),
                               retry=False)
    other = ['%s:%s' % (t.lower(), v) for t, v in info.get('san') or []
             if t not in ('DNS', 'IP')]
    allowed = [str(x).lower() for x in sans or [] if ':' in str(x)]
    odd = [x for x in other if x.lower() not in allowed]
    if odd:
        raise base.PluginError('the CSR %s made has names the certificate does not ask for: %s'
                               % (who, ', '.join(odd)), retry=False)
    cn = str(info.get('cn') or '').strip().lower().rstrip('.')
    if strict_cn and cn and cn not in want:
        raise base.PluginError('the CSR %s made has the common name %s, which is not one of the '
                               'names (%s) - the CA refuses that' % (who, info.get('cn'),
                                                                     ', '.join(want)),
                               retry=False)


def csr_for(store, job, cert, names, sans, subject, key_type, profile, needs_challenge=False,
            what=''):
    """The device of cert['csr_from'] asked for a new key and CSR, the CSR checked.
    -> pki.csr_info of it. PluginError in words when the target is gone, switched off, or
    its CSR does not fit."""
    from acmelib.certs import pki
    src = str(cert.get('csr_from') or '').strip()
    trow = S.plugin_row(store, 'target', src)
    if not trow:
        raise base.PluginError('its key is made by the target %s, which is not there any more - '
                               'choose another target whose device makes the key, or let acme '
                               'make it (the certificate → Edit → Key)' % src, retry=False)
    if not trow.get('enabled', 1):
        raise base.PluginError('its key is made by the target %s, which is switched off - '
                               'switch it on to issue it' % trow['name'], retry=False)
    cls = S.row_class('target', trow)
    if cls is None:
        raise base.PluginError('the module of the target %s (%s) is not there' % (
            trow['name'], trow.get('kind')), retry=False)
    if not getattr(cls, 'device_key', False):
        raise base.PluginError('the target %s (%s) does not make keys any more - let acme make '
                               'the key (the certificate → Edit → Key)' % (trow['name'],
                                                                         cls.title or cls.kind),
                               retry=False)
    dep = store.db.row('SELECT * FROM cert_deploys WHERE cert_id = ? AND target = ?',
                       (cert['id'], trow['name']))
    if not dep:
        raise base.PluginError('it has no deployment to %s, whose device makes its key - the '
                               'certificate would never reach the device: add it (the '
                               'certificate → Deployments)' % trow['name'], retry=False)
    if not dep.get('enabled', 1):
        raise base.PluginError('its deployment to %s, whose device makes its key, is switched '
                               'off - the certificate would never reach the device: switch it '
                               'on' % trow['name'], retry=False)
    from acmelib.certs import deployer, jobs
    scope = 'target:%s' % trow['name']
    # The CSR asked for an issue not finished yet (a source holding the request - a manager's
    # approval, an order validated later - or a try that failed): used again, so the
    # certificate that comes is for the key the device holds. A new key at every try had the
    # held request fetched for the key the device had just replaced, and never finished.
    kept = held_csr(cert, trow['name'])
    if kept:
        try:
            info = pki.csr_info(kept['csr_pem'])
            check_csr(info, names, sans, 'the device of %s' % trow['name'],
                      strict_cn=needs_challenge)
            check_key(info, key_type, trow, cls)
        except (base.PluginError, pki.PkiError, ValueError, KeyError) as e:
            jobs.step_in(job, '%sthe CSR the device of %s made for the issue before does not fit '
                         'any more (%s) - a new one is asked' % (what, trow['name'], e), 'warn',
                         scope=scope)
        else:
            jobs.step_in(job, '%sthe CSR the device of %s made (%s) is used again (its issue was '
                         'not finished; the device keeps that key until its certificate comes)'
                         % (what, trow['name'], _when(kept.get('at'))), 'ok', scope=scope)
            return info
    jobs.step_in(job, '%sthe key and the CSR are made by the device of %s (%s) - the key stays '
                 'there' % (what, trow['name'], cls.title or cls.kind), scope=scope)
    twin = sharing(store, cert, trow['name'])
    if twin:
        # two certificates on one device, saved before 1.0.96 refused that: each new CSR
        # replaces the key the device holds for the other one
        said = ('%s: the device of %s makes the key of the certificate %s too - it holds one '
                'pending key, so this new CSR replaces the key of the other one (whose '
                'certificate then fits no key there): put the names of both into one certificate'
                % (cert['name'], trow['name'], twin['name']))
        jobs.step_in(job, '%s%s' % (what, said), 'warn', scope=scope)
        store.add_event('certificates', said, 'warn')
    ctx = deployer.target_context(store, job, trow)
    ctx.deploy_id = dep['id']
    ctx.target_name = trow['name']
    try:
        target = S.plugin_instance(store, 'target', trow, ctx)
        opts = S.deploy_options(store, dep)
        req = base.CertRequest(names=list(names), sans=list(sans or names), key_type=key_type,
                               subject=dict(subject or {}), profile=dict(profile or {}),
                               options=opts, name=cert['name'], cert_id=cert['id'],
                               target=trow['name'])
        job.check()
        got = target.device_csr(req)
        job.check()
    finally:
        ctx.tidy()
    if isinstance(got, (bytes, bytearray)):
        got = bytes(got)
        if b'-----BEGIN' in got:
            got = got.decode('ascii', 'replace')
    if not got:
        raise base.PluginError('the device of %s gave no CSR' % trow['name'])
    try:
        info = pki.csr_info(got)
    except pki.PkiError as e:
        raise base.PluginError('the device of %s gave a CSR that cannot be read: %s' % (
            trow['name'], e))
    check_csr(info, names, sans, 'the device of %s' % trow['name'], strict_cn=needs_challenge)
    check_key(info, key_type, trow, cls)
    made = info.get('key_type') or '?'
    jobs.step_in(job, '%sthe device of %s made a %s key and its CSR (%s)' % (
        what, trow['name'], made, ', '.join(_clean(
            [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')] or [info.get('cn')]))),
        'ok', scope=scope)
    # kept until the certificate for it is saved (renewer: csr_pending cleared then)
    store.db.update('certs', cert['id'], {'csr_pending': json.dumps({
        'device': trow['name'], 'csr_pem': info['pem'], 'at': time.time(),
        'key_type': key_type})})
    return info


def held_csr(cert, target=None):
    """The CSR a device made for an issue not finished yet ({'device', 'csr_pem', 'at',
    'key_type'}), or None. `target`: only one that device made."""
    pend = S.jload(cert.get('csr_pending'), None)
    if not isinstance(pend, dict) or not pend.get('device') or not pend.get('csr_pem'):
        return None
    if target is not None and pend['device'] != target:
        return None
    return pend


def _when(at):
    try:
        return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(float(at)))
    except (TypeError, ValueError):
        return '?'


WEAK = ('rsa-1024', 'rsa-512', 'rsa-768')


def check_key(info, key_type, trow, cls=None):
    """The key in a device's CSR: the key type asked for (one the device makes), never a weak
    one. Raises PluginError in words."""
    made = str(info.get('key_type') or '')
    bits = int(info.get('key_bits') or 0)
    if made.startswith('rsa') and bits and bits < 2048:
        raise base.PluginError('the device of %s made a weak %s key (RSA with %d bits) - a CA '
                               'refuses it and it can be broken: set the device to make %s keys '
                               '(or choose another key type for the certificate)'
                               % (trow['name'], made, bits, key_type), retry=False)
    kts = key_types_of(cls) if cls is not None else None
    if kts and made not in kts:
        raise base.PluginError('the device of %s made a %s key, which its module does not list '
                               '(it makes %s) - choose one of those key types for the certificate'
                               % (trow['name'], made or '?', ', '.join(kts)), retry=False)
    if made != key_type:
        raise base.PluginError('the device of %s made a %s key, but %s was asked for - the '
                               'certificate would not say what its key is: choose %s as its key '
                               'type, or set the device to make %s keys'
                               % (trow['name'], made or '?', key_type, made or '?', key_type),
                               retry=False)


def dummy_csr(names, key_type='ec-256', subject=None):
    """A CSR for `names` with a throwaway key - what What happens' sandbox answers when a
    module asks its device for one (nothing is reached there)."""
    from acmelib.certs import pki
    kt = key_type if key_type in ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096') \
        else 'ec-256'
    key = pki.make_key(kt)
    csr = pki.make_csr(key, list(names), subject=subject or None)
    return csr[0] if isinstance(csr, (tuple, list)) else csr


# ---------------------------------------------------------------------------
# A deployment to the device that keeps failing
# ---------------------------------------------------------------------------
REISSUE_AFTER = 3                   # failed deployments in a row (5 + 10 + 20 minutes)
REISSUE_KEY = S.CERT_META['devkey']


def deploy_failed(store, job, cert, dep, fails, misfit=False):
    """A deployment of a certificate whose key `cert['csr_from']` makes, to that device, failed
    (`fails` in a row; `misfit`: the version held fits no key there). The device may have lost
    the key it made (a reboot, a CSR asked by someone else): the certificate kept here then
    never goes in, and it would not be renewed for weeks while the device's old one runs out.
    After REISSUE_AFTER failures (or a misfit at once) it is made due for a new issue - a new
    key and CSR asked of the device. Once only, until a deployment there works again (no loop
    of issues). One nothing renews by itself (switched off, automatic renewal off, no source)
    is not made due: "renew it by hand" is said, once. -> the words said, or ''."""
    src = str(cert.get('csr_from') or '').strip()
    if not src or str(dep.get('target') or '') != src:
        return ''
    if not misfit and int(fails or 0) < REISSUE_AFTER:
        return ''
    key = REISSUE_KEY % int(cert['id'])
    if store.get_meta(key):
        return ''
    cur = S.cert_get(store, cert['id']) or {}
    if str(cur.get('version') or '') != str(cert.get('version') or '') or \
            cur.get('state') not in ('ok', 'due') or not cur.get('cert_pem'):
        return ''
    if misfit and cur.get('state') == 'due':
        return ''                           # made due already (where its key is made changed)
    from acmelib.certs import jobs

    def on(k):
        return bool(int(cur.get(k) if cur.get(k) is not None else 1))
    by_hand = ('switched off' if not on('enabled') else
               'no source' if not str(cur.get('issuer') or '').strip() else
               'automatic renewal is off' if not on('auto_renew') else '')
    if by_hand:
        # nothing issues it by itself (1.0.96): it was made due, said "issued anew", and stayed
        # so - said once (at the failure that reaches the count), nothing changed
        if not misfit and int(fails or 0) != REISSUE_AFTER:
            return ''
        if misfit:
            said = ('%s: the version it holds fits no key on %s, whose device makes its key; it '
                    'is not renewed by itself (%s): renew it by hand (Renew now) for a new key '
                    'and CSR of the device' % (cert['name'], src, by_hand))
        else:
            said = ('%s: its deployment to %s, whose device makes its key, failed %d times - the '
                    'device may have lost the key it made; it is not renewed by itself (%s): '
                    'renew it by hand (Renew now) for a new key and CSR of the device'
                    % (cert['name'], src, int(fails), by_hand))
        jobs.step_in(job, said, 'warn', scope='target:%s' % src)
        store.add_event('certificates', said, 'warn')
        return said
    # in one step with the checks above (1.0.96): a save of the certificate in between kept
    if not store.db.run("UPDATE certs SET state = 'due', state_at = ?, csr_pending = NULL "
                        "WHERE id = ? AND version = ? AND state IN ('ok', 'due')",
                        (time.time(), int(cert['id']), int(cur.get('version') or 0))):
        return ''
    store.set_meta(key, str(cert.get('version') or 0))
    if misfit:
        said = ('%s: the version it holds fits no key on %s, whose device makes its key - it is '
                'issued anew for a new key and CSR of the device' % (cert['name'], src))
    else:
        said = ('%s: its deployment to %s, whose device makes its key, failed %d times - the '
                'device may have lost the key it made: it is issued anew (a new key and CSR '
                'asked of the device), once; should that fail too, see to the device'
                % (cert['name'], src, int(fails)))
    jobs.step_in(job, said, 'warn', scope='target:%s' % src)
    store.add_event('certificates', said, 'warn')
    return said


def deploy_worked(store, cert, dep):
    """A deployment to the device that makes its key worked: a new issue after failures may
    come again."""
    if str(cert.get('csr_from') or '') and str(dep.get('target') or '') == cert['csr_from']:
        store.db.run('DELETE FROM meta WHERE k = ?', (REISSUE_KEY % int(cert['id']),))
