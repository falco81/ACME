# Webhook - setup for acme

For anything acme has no module for: acme **POSTs the certificate to a URL** you run - as
JSON (default) or as `multipart/form-data` with the formats you list as files. Each request
carries the headers `X-Acme-Event`, `X-Acme-Timestamp` and, with a signing secret,
`X-Acme-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>` so the
receiver can tell it came from acme. **The private key is sent only if you turn on *Send
the private key*.** Any 2xx answer is success. *Try* sends `{"event": "ping"}`.

The JSON body:

```json
{"event": "certificate.deployed", "name": "www", "names": ["www.example.com"],
 "serial": "...", "fingerprint": "...", "not_before": 1793491200, "not_after": 1801267200,
 "cert_pem": "...", "chain_pem": "...", "fullchain_pem": "..."}
```

plus `key_pem` (with the key), `extra` (your *Extra JSON fields*) and, for a dual
certificate, `key_type` and `alt` (the twin's fields).

## What you need

- An HTTPS endpoint reachable from acme (or through the proxy of *Settings → Proxy*).
- A receiver that checks the signature and the timestamp, then installs the certificate.

## Set up the receiver

1. Choose a long random signing secret (e.g. `openssl rand -hex 32`) and give it to both
   acme and the receiver.
2. On the receiver, for each request:
   - read `X-Acme-Timestamp` and refuse it if it is more than a few minutes old;
   - compute `HMAC-SHA256(secret, timestamp + "." + raw body)` in hex and compare it, in
     constant time, with the part after `sha256=` in `X-Acme-Signature`;
   - answer `{"event": "ping"}` with `200`;
   - for `certificate.deployed`, write the files and reload your service; answer `2xx`
     only when it worked.

   Example check in Python:

   ```text
   import hmac, hashlib
   mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
   ok = hmac.compare_digest("sha256=" + mac, request.headers["X-Acme-Signature"])
   ```

3. Serve the endpoint over **HTTPS** - especially if it receives the private key - and
   restrict it to acme's IP if you can. Add your own authentication with *More headers*
   (e.g. `Authorization: Bearer ...`) if the endpoint expects it.

## Fill in acme

| acme field | What to put there |
|---|---|
| URL | e.g. `https://hooks.example.com/cert` |
| Signing secret | The secret from step 1 |
| More headers (advanced) | One a line, e.g. `Authorization: Bearer <token>` |
| Send the private key | Off (default) - only certificate and chain leave acme; on only if the receiver needs the key |
| Check the device's certificate | On |
| CA certificate (advanced) | The CA of the endpoint's certificate, if internal |
| Through the proxy (advanced) | On (default) to go out through *Settings → Proxy* |
| Body (deploy) | *JSON* or *multipart/form-data (files)* |
| Files (multipart) (deploy) | Formats one a line, e.g. `fullchain-pem`, `key-pem` (key formats only with *Send the private key*) |
| PKCS#12 password (deploy, advanced) | For `pfx`/`p12` files |
| Extra JSON fields (deploy, advanced) | e.g. `{"env": "prod"}` |
| Check what is served | Where the receiver installs it, e.g. `www.example.com:443` |

## Check it

- Press **Try** on the target: acme sends `{"event": "ping"}` and says
  `the webhook answered 200`.
- On the receiver, log the event, the timestamp and whether the signature matched.

## Common problems

| Problem | Fix |
|---|---|
| Signature does not match | Compute over the **raw** body bytes, not re-serialized JSON; same secret; `timestamp + "." + body`. |
| `... holds the private key, and this webhook does not send keys` | A key format is listed under *Files*: turn on *Send the private key* or remove it. |
| `the extra JSON fields are not JSON` | Fix the JSON in *Extra JSON fields*. |
| `not a format: ...` | Use format names such as `cert-pem`, `fullchain-pem`, `key-pem`, `pfx`. |
| Timeout / connection refused | Endpoint not reachable from acme; check *Through the proxy*. |
