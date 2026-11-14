# -*- coding: utf-8 -*-
"""
A deployment's files and the script after them, before it is saved or run:

    POST /api/deploys/preview  {id?, cert_id?, target, options, names?}
        -> {files: [{path, format, title, what, mode, owner, size, key, ...}],
            env: {ACME_*: value}, problems: [{level, words}], script, password}
        what the target would write and what the script would be told - worked
        out by the target's own module as a deployment does (no network, nothing
        sent); a certificate not issued yet: its names, sizes guessed.
    POST /api/deploys/dry_run  {id?, cert_id?, target, options, run_script?}
        -> {ok, said, steps, job_id}
        the test: signed in, the files made and written into a temporary folder
        on the target (not their places), the script run there with
        ACME_DRY_RUN=1, the folder deleted. Nothing is reloaded or restarted
        (the commands before, test and reload are not run) - but the script runs:
        it must look at ACME_DRY_RUN and change nothing when it is 1.

Options given are laid over the saved deployment's: a secret given empty or as
the dots shown keeps the one kept. Only a full administrator may test a
script other than the one saved.
"""
from __future__ import annotations

import time

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import deployer, jobs, runtime


class SampleBundle(object):
    """A certificate not issued yet, as far as a preview needs it: its names."""
    def __init__(self, name, names, key_type='ec-256', alt_type=None):
        self.name = name
        self.names = list(names or [name])
        self.key_type = key_type or 'ec-256'
        self.family = 'rsa' if self.key_type.startswith('rsa') else (
            'ed' if self.key_type.startswith('ed') else 'ec')
        self.serial = ''
        self.fingerprint = ''
        self.cert_pem = ''
        self.key_pem = ''
        self.chain_pems = []
        self.version = 0
        self.not_before = time.time()
        self.not_after = self.not_before + 90 * 86400
        self.alt = SampleBundle(name, names, alt_type) if alt_type else None

    def as_format(self, fmt, password=None, alias=None):
        raise base.PluginError('not issued yet', retry=False)


def _setup(store, b, s):
    """-> (target row, module class, cert row, saved deployment row or None, options)."""
    dep = None
    if b.get('id') not in (None, '', 0):
        dep = store.db.row('SELECT * FROM cert_deploys WHERE id = ?', (A._id(b['id']),))
        if not dep:
            raise LookupError('there is no such deployment')
    tname = str(b.get('target') or (dep or {}).get('target') or '').strip()
    trow = S.plugin_row(store, 'target', tname)
    if not trow:
        raise LookupError('there is no target %s' % tname)
    cls = S.row_class('target', trow)
    if cls is None:
        raise ValueError('there is no target module "%s"' % trow['kind'])
    cref = b.get('cert_id') or (dep or {}).get('cert_id')
    cert = S.cert_get(store, cref) if cref not in (None, '', 0) else None
    if cref not in (None, '', 0) and not cert:
        raise LookupError('there is no certificate %s' % cref)
    saved = S.deploy_options(store, dep) if dep and dep.get('target') == trow['name'] else {}
    secret = S.secret_fields(cls, 'deploy_fields')
    opts = dict(saved)
    for k, v in (A._dict(b.get('options'), 'options') or {}).items():
        if k in secret and (v in (None, '') or E.is_masked(v)):
            continue
        opts[k] = v
    if 'script_body' in opts:
        from acmelib.plugins.targets import _script
        _script.check_body(opts['script_body'])
    return trow, cls, cert, dep, opts, saved


def _bundle(cert, b, cls):
    if cert and cert.get('cert_pem'):
        whole = S.bundle_of(cert)
        return deployer.pick_variant(whole, {}, cls) if not getattr(cls, 'dual', False) \
            else whole
    names = A._list(b.get('names'), 'names') if b.get('names') else []
    if cert:
        names = S.jload(cert.get('names'), []) or names
        return SampleBundle(cert['name'], names, cert.get('key_type') or 'ec-256',
                            cert.get('key_type_alt') if getattr(cls, 'dual', False) else None)
    names = [str(n) for n in names if str(n).strip()] or ['www.example.com']
    return SampleBundle(str(b.get('name') or names[0]), names, str(b.get('key_type') or 'ec-256'),
                        str(b.get('key_type_alt') or '') or None)


@A.api('POST', '/api/deploys/preview')
def _deploys_preview(h, s):
    b = h.body()
    trow, cls, cert, dep, opts, saved = _setup(h.store, b, s)
    if not hasattr(cls, 'preview'):
        return {'supported': False, 'files': [], 'env': {}, 'problems': []}
    ctx = runtime.RunContext(h.store, None, scope='target:%s' % trow['name'])
    ctx.target_name = trow['name']
    if dep:
        ctx.deploy_id = dep['id']
    try:
        t = cls(S.plugin_config('target', trow), ctx)
        got = t.preview(_bundle(cert, b, cls), opts)
    finally:
        ctx.tidy()
    got['supported'] = True
    got['issued'] = bool(cert and cert.get('cert_pem'))
    got['cert'] = cert['name'] if cert else None
    sc = got.get('script') or {}
    if sc.get('from') == 'target':
        got['target_script'] = True
    return got


@A.api('POST', '/api/deploys/dry_run', 'certadmin')
def _deploys_dry_run(h, s):
    b = h.body()
    store = h.store
    trow, cls, cert, dep, opts, saved = _setup(store, b, s)
    if not hasattr(cls, 'dry_run'):
        raise ValueError('%s cannot be tested this way' % (cls.title or cls.kind))
    if not cert or not cert.get('cert_pem'):
        raise ValueError('the certificate has not been issued yet: there is nothing to test with')
    if not A.may(s, 'fulladmin') and str(opts.get('script_body') or '') != \
            str(saved.get('script_body') or ''):
        raise E.ApiError(403, 'only a full administrator may test a script other than the one '
                              'saved')
    if not A.may(s, 'fulladmin') and any(str(opts.get(k) or '') != str(saved.get(k) or '')
                                         for k in A.DEPLOY_COMMANDS):
        raise E.ApiError(403, 'only a full administrator may test commands other than the ones '
                              'saved')
    if not A.may(s, 'fulladmin'):
        # where the key goes and how it is kept (1.0.51), as a save checks it: the script tried
        # was handed the key and the password of the certificate administrator's choosing
        diff = {k: opts.get(k) for k in ('outputs',) + A.key_options(cls)
                if k in opts and opts.get(k) != saved.get(k)}
        A._deploy_key_check(cls, diff, saved)
    for f in (cls.deploy_fields or []):
        # a line of text one line, a name of the device's form (1.0.101), as a save checks it
        if f.get('key'):
            A._option_line_check(f, opts.get(f['key']), f.get('label') or f['key'])
    by = A.who(s)
    run_script = A._flag(b.get('run_script'), 1)
    if opts.get('pfx_password_mode') == 'generate' and not opts.get('pfx_password'):
        from acmelib.plugins.targets._common import random_password
        opts['pfx_password'] = random_password(24)

    def fn(job):
        ctx = deployer.target_context(store, job, trow)
        ctx.target_name = trow['name']
        if dep:
            ctx.deploy_id = dep['id']
        try:
            job.step('testing the deployment of %s to %s (%s): nothing is put in place'
                     % (cert['name'], trow['name'], trow['kind']))
            t = cls(S.plugin_config('target', trow), ctx)
            said = t.dry_run(_bundle(cert, b, cls), opts, run_script=bool(run_script))
            job.step(str(said or 'the test passed'), 'ok')
            return True, str(said or 'the test passed')
        finally:
            ctx.tidy()
    job = jobs.run_now(store, 'test', fn, target=trow['name'], by=by,
                       said='a test of a deployment to %s' % trow['name'])
    store.add_event('certificates', 'a deployment of %s to %s tested by %s - %s' % (
        cert['name'], trow['name'], by, 'passed' if job.ok else 'failed: %s' % job.said),
        'info' if job.ok else 'warn', who=by)
    return {'ok': bool(job.ok), 'said': job.said, 'job_id': job.id, 'steps': job.steps}
