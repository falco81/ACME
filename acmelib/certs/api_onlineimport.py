# -*- coding: utf-8 -*-
"""
Import from a source, and a private key added later (acmelib/certs/onlineimport.py).

    GET  /api/certs/online_sources              the sources whose API lists the account's
                                                certificates
    POST /api/certs/online_list  {source}       what the account has there - read only, no job
    POST /api/certs/online_import {source, items: [{ref, owner, tags, challenge,
                                  auto_renew, name}]}   -> {job_id}
    GET  /api/certs/online_import_result?job=   what that job did (null while it runs)
    POST /api/certs/add_key {id, key_pem | key_b64 + key_filename, key_password,
                             alt_key_pem | alt_key_b64 ...}   the key of a certificate
                                                acme holds none of, checked to fit

All need a certificate administrator; a scoped one (docs/teams.md) imports only for the
teams they may ask for, and adds a key only to a certificate they manage (teams.guard).
"""
from __future__ import annotations

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import store as S
from acmelib.certs import onlineimport as OI


@A.api('GET', '/api/certs/online_sources', 'certadmin')
def _online_sources(h, s):
    return {'sources': OI.sources(h.store)}


@A.api('POST', '/api/certs/online_list', 'certadmin')
def _online_list(h, s):
    b = h.body()
    return OI.listing(h.store, A._text(b, 'source', 200), s)


@A.api('POST', '/api/certs/online_import', 'certadmin')
def _online_import(h, s):
    b = h.body()
    try:
        return {'job_id': OI.import_job(h.store, A._text(b, 'source', 200), b.get('items'),
                                        A.who(s))}
    except ValueError as e:
        if 'already working' in str(e):
            raise E.ApiError(409, str(e))
        raise


@A.api('GET', '/api/certs/online_import_result', 'certadmin')
def _online_import_result(h, s):
    return {'result': OI.import_result(h.store, A._id(h.arg('job'), 'job'))}


@A.api('POST', '/api/certs/add_key', 'certadmin')
def _add_key(h, s):
    b = h.body()
    row = S.cert_need(h.store, A._id(b.get('id')))
    done = OI.add_key(h.store, row, b, A.who(s))
    return {'id': row['id'], 'added': done,
            'message': 'the private key was added - it fits the certificate'}
