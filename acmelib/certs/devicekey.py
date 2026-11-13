# -*- coding: utf-8 -*-
"""
"The device makes the key" (docs/certificates.md "Key made by the device"): a certificate
whose key a target's device makes itself - Lenovo XCC, Dell OpenManage Enterprise, Cisco
CUCM... - the devices that take only a certificate for a CSR of their own.

A certificate says where its key is made in certs.csr_from (the name of a target whose
module has device_key = True). Then:

    issue / renewal     the target's device_csr(req) is asked for a fresh CSR at every one
                        (renewer._issue_one): acme holds no key, the CSR is used as one
                        sent in (csr_given) is - its names checked, the certificate issued
                        checked to be for its key
    deployment          to that target only, made with the certificate (cert_save); it
                        runs right after the issue in the same job: deploy() gets the
                        bundle with no key and the device installs the certificate
    refused with it     a twin (key_type_alt), reuse_key, a CSR sent in (csr_given), a
                        source that signs no CSR, a deployment to another target - and a
                        device_key target for any certificate not made for its key

    target_of(store, name)              (row, class) of a device_key target, or ValueError
    save_problem(store, cert, deploys)  why a certificate saved with csr_from cannot be so
    deploy_problem(store, cert, trow, cls)   why that certificate cannot go to that target
    csr_for(store, job, cert, ...)      the CSR the device made, checked (renewer)
    check_csr(info, names, sans, ...)   a CSR's names against the certificate's
    dummy_csr(names, key_type)          a CSR for the names (What happens' sandbox)
"""
from __future__ import annotations

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


def save_problem(store, cert, deploys=None):
    """Why `cert` (a row as it would be saved, with csr_from) cannot be so - words, or ''.
    `deploys`: its deployments' targets (None: read)."""
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
    return ''


def deploy_problem(store, cert, trow, cls=None):
    """Why the certificate `cert` cannot be deployed to the target `trow` - words, or ''."""
    src = str(cert.get('csr_from') or '').strip()
    if src and src != trow['name']:
        return ('the key of %s is made by %s and stays there - it can be deployed only to %s '
                '(no other target can have its key)' % (cert['name'], src, src))
    cls = cls if cls is not None else S.row_class('target', trow)
    if cls is not None and getattr(cls, 'device_key', False) and src != trow['name']:
        return ('%s makes the key itself and takes only a certificate for it - add a '
                'certificate whose key it makes (%s %s)'
                % (trow['name'], HOW.replace('TARGET', trow['name']),
                   '' if not src else '- this one\'s key is made by %s' % src))
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
    jobs.step_in(job, '%sthe key and the CSR are made by the device of %s (%s) - the key stays '
                 'there' % (what, trow['name'], cls.title or cls.kind), scope=scope)
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
    made = info.get('key_type') or '?'
    jobs.step_in(job, '%sthe device of %s made a %s key and its CSR (%s)' % (
        what, trow['name'], made, ', '.join(_clean(
            [v for t, v in info.get('san') or [] if t in ('DNS', 'IP')] or [info.get('cn')]))),
        'ok', scope=scope)
    if made != key_type:
        jobs.step_in(job, '%s was asked for, the device made %s' % (key_type, made), 'warn',
                     scope=scope)
    return info


def dummy_csr(names, key_type='ec-256', subject=None):
    """A CSR for `names` with a throwaway key - what What happens' sandbox answers when a
    module asks its device for one (nothing is reached there)."""
    from acmelib.certs import pki
    kt = key_type if key_type in ('ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096') \
        else 'ec-256'
    key = pki.make_key(kt)
    csr = pki.make_csr(key, list(names), subject=subject or None)
    return csr[0] if isinstance(csr, (tuple, list)) else csr
