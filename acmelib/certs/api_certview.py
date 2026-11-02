# -*- coding: utf-8 -*-
"""
Show a certificate (1.0.23) - the viewer of the pages (web/assets/certview.js):

    POST /api/certs/inspect  {data_b64 + filename | text, password?, key_password?}

Anybody signed in may look (readonly too): what is given is read and described
(acmelib/certs/certview.py) and forgotten - nothing is kept, nothing is
contacted, no event is written. A private key is described (its type, whether
it was encrypted, which certificate it belongs to), never sent back.
"""
from __future__ import annotations

import base64
import binascii
import threading

from acmelib import engine as E
from acmelib.certs import api as A
from acmelib.certs import certview

BUSY = threading.BoundedSemaphore(3)
MOST = 6 * 1024 * 1024


@A.api('POST', '/api/certs/inspect', 'readonly')
def _inspect(h, s):
    b = h.body()
    raw = b.get('data_b64')
    if raw:
        if not isinstance(raw, str):
            raise ValueError('data_b64 is the file as base64')
        try:
            data = base64.b64decode(raw.strip(), validate=False)
        except (binascii.Error, ValueError):
            raise ValueError('data_b64 is not base64')
    else:
        data = A._text(b, 'text', MOST).encode('utf-8')
    if len(data) > MOST:
        raise E.ApiError(413, 'a file of %d MB at most is shown' % (MOST // 1024 // 1024))
    if not BUSY.acquire(timeout=30):
        raise E.ApiError(503, 'too many files are being read at once: try again in a moment')
    try:
        return certview.describe(data, A._text(b, 'filename', 300),
                                 A._text(b, 'password', 1000), A._text(b, 'key_password', 1000))
    finally:
        BUSY.release()
