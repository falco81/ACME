# -*- coding: utf-8 -*-
"""
What the cloud targets share (not a module itself: the registry skips files
starting with "_"): the sign-ins of AWS, Microsoft Entra and Google, each
written once already for the DNS-01 modules and reused from there.

    sigv4(...)            AWS Signature Version 4 (challenges/route53.py)
    CloudTarget           an HttpTarget whose requests go to absolute URLs,
                          through the proxy by default
    entra_token(t, scope) an OAuth2 client-credentials token of Microsoft Entra
    google_token(t, scope) a service account's token (a JWT signed RS256 by the
                          openssl program, challenges/gcloud_dns.py)
"""
from __future__ import annotations

import json
import time
import urllib.parse

from acmelib.plugins import limits
from acmelib.plugins.base import PluginError, field
from acmelib.plugins.challenges.route53 import sigv4          # noqa: F401  (re-exported)
from acmelib.plugins.challenges.gcloud_dns import make_jwt
from acmelib.plugins.targets._common import HttpTarget, text

__all__ = ['sigv4', 'CloudTarget', 'cloud_fields', 'entra_token', 'google_token',
           'ENTRA_CLOUDS', 'service_account']

ENTRA_CLOUDS = {
    # login host, Key Vault's DNS suffix
    'public': ('https://login.microsoftonline.com', 'vault.azure.net'),
    'china': ('https://login.chinacloudapi.cn', 'vault.azure.cn'),
    'usgov': ('https://login.microsoftonline.us', 'vault.usgovcloudapi.net'),
}


def cloud_fields():
    """Proxy and timeout - a cloud API is outside, so the proxy is on by default."""
    return [
        field('proxy', 'Through the proxy', 'bool', default=True, advanced=True,
              help='go out through the proxy of Settings → Proxy'),
        field('timeout', 'Timeout (s)', 'number', default=30, advanced=True),
    ]


class CloudTarget(HttpTarget):
    """A target spoken to at absolute URLs of a cloud API (the proxy field of
    cloud_fields() is on by default)."""
    kind = ''
    _token = None
    _token_until = 0.0

    def base_url(self):
        return ''

    def ident(self):
        """Which account / vault / zone this is: every setting that is not a secret."""
        parts = ['%s=%s' % (f['key'], text(self.c(f['key'])))
                 for f in self.fields if f['type'] not in ('secret', 'sshkey', 'bool', 'number')]
        return '%s:%s' % (self.kind, ','.join(parts))

    def http_error(self, status, parsed, raw, method, path, what=None):
        msg = ''
        if isinstance(parsed, dict):
            err = parsed.get('error')
            if isinstance(err, dict):
                msg = text(err.get('message') or err.get('code') or '')
            elif parsed.get('errors') and isinstance(parsed['errors'], list):
                msg = '; '.join(text(e.get('message') if isinstance(e, dict) else e)
                                for e in parsed['errors'])
            elif parsed.get('message') or parsed.get('Message'):
                msg = text(parsed.get('message') or parsed.get('Message'))
            elif err:
                msg = text(parsed.get('error_description') or err)
        if not msg:
            msg = text(raw)[:200].strip()
        if status in (401, 403):
            head = 'not allowed (%d) - check the credentials and their rights' % status
        elif status == 404:
            head = 'not found (404)'
        else:
            head = 'said %d' % status
        return '%s: %s%s' % (what or '%s %s' % (method, urllib.parse.urlsplit(path).path),
                             head, (' - ' + msg) if msg else '')


def entra_token(t, scope):
    """A token of Microsoft Entra for an app registration with a client secret."""
    if t._token and time.time() < t._token_until - 60:
        return t._token
    if limits.sharing(t.ctx):
        # one token for every run with these settings, for its lifetime (limits.py)
        t._token = limits.session(limits.key_of(t, 'entra_token|' + str(scope)),
                                  lambda: _entra_once(t, scope))
        t._token_until = time.time() + 120
        return t._token
    tok, life = _entra_once(t, scope)
    t._token, t._token_until = tok, time.time() + life
    return tok


def _entra_once(t, scope):
    login = ENTRA_CLOUDS.get(t.c('cloud', 'public'), ENTRA_CLOUDS['public'])[0]
    body = urllib.parse.urlencode({
        'grant_type': 'client_credentials', 'client_id': t.c('client_id', ''),
        'client_secret': t.c('client_secret', ''), 'scope': scope}).encode()
    try:
        st, hd, d = t.req('POST', '%s/%s/oauth2/v2.0/token' % (
            login, urllib.parse.quote(text(t.c('tenant_id', '')), safe='')), body,
            {'Content-Type': 'application/x-www-form-urlencoded'}, auth=False,
            what='signing in to Microsoft Entra')
    except PluginError as e:
        raise PluginError(str(e), detail=e.detail, retry=False)
    if not isinstance(d, dict) or not d.get('access_token'):
        raise PluginError('Microsoft Entra gave no token', retry=False)
    return d['access_token'], float(d.get('expires_in') or 3000)


def service_account(t, key='service_account'):
    raw = t.c(key) or ''
    try:
        sa = json.loads(raw) if isinstance(raw, str) else dict(raw)
    except (ValueError, TypeError):
        raise PluginError('the service account key is not JSON (paste the whole file)',
                          retry=False)
    if not sa.get('client_email') or not sa.get('private_key'):
        raise PluginError('the service account key has no client_email or private_key',
                          retry=False)
    return sa


def google_token(t, scope='https://www.googleapis.com/auth/cloud-platform'):
    if t._token and time.time() < t._token_until - 60:
        return t._token
    if limits.sharing(t.ctx):
        # one token for every run with these settings, for its lifetime (limits.py)
        t._token = limits.session(limits.key_of(t, 'google_token|' + str(scope)),
                                  lambda: _google_once(t, scope))
        t._token_until = time.time() + 120
        return t._token
    tok, life = _google_once(t, scope)
    t._token, t._token_until = tok, time.time() + life
    return tok


def _google_once(t, scope):
    sa = service_account(t)
    body = urllib.parse.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'assertion': make_jwt(t.ctx, sa, now=getattr(t, '_now', None), scope=scope)}).encode()
    try:
        st, hd, d = t.req('POST', sa.get('token_uri') or 'https://oauth2.googleapis.com/token',
                          body, {'Content-Type': 'application/x-www-form-urlencoded'},
                          auth=False, what='signing in to Google')
    except PluginError as e:
        raise PluginError(str(e), detail=e.detail, retry=False)
    if not isinstance(d, dict) or not d.get('access_token'):
        raise PluginError('Google gave no token', retry=False)
    return d['access_token'], float(d.get('expires_in') or 3000)

