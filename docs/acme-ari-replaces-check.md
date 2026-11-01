# ACME renewal refused after an account change: the ARI `replaces` field

A check for every project that renews certificates over ACME and sends `replaces` in
newOrder (ARI, RFC 9773). Found in acme 1.0.196, fixed in acme 1.0.199.

## The symptom

A renewal that worked before fails with:

```
the CA refused it: Could not validate ARI 'replaces' field :: requester account did not
request the certificate being replaced by this order
```

(Let's Encrypt; HTTP 409, `urn:ietf:params:acme:error:conflict`.) Nothing changed in DNS
or on port 80. The certificate in place keeps working until it runs out, but no renewal
comes, so it **will** run out.

## The cause

RFC 9773 lets a newOrder say which certificate it renews:

```json
{"identifiers": [...], "replaces": "<base64url(AKI)>.<base64url(serial)>"}
```

Let's Encrypt accepts `replaces` **only from the ACME account that ordered the replaced
certificate**. The order is refused when the account is a different one, and any of these
makes a different account:

- **The account key is changed** (ES256 → ES384, EC → RSA): a new account is registered
  with the new key. In acme the user switched "The key of the ACME account" to ECDSA
  P-384, and the next order failed. The other nodes would have failed at their next
  renewal too.
- **The account is made again**: the CA forgot it (`accountDoesNotExist`), its key was
  lost, or the stored account was wiped.
- **The CA or directory changes**: staging ↔ production, another CA. A different
  directory URL means a different account.
- **High availability / several nodes**: a certificate ordered by node A's account and
  renewed by node B with its own account. This only applies where nodes do not share one
  account.
- **A backup restored** with the certificate but not the account, or the other way round.

## What to check in your project

1. Find where `replaces` is put into the newOrder payload
   (`grep -rn "replaces" .`).
2. Is the **account URL (`kid`) that ordered each certificate stored with it**? If not,
   nothing stops `replaces` from going out under another account.
3. Can the account key type, the CA or the account itself change while a certificate
   from the old account is still in place? (Usually yes, see the list above.)
4. What happens when newOrder is refused? Does the renewal fail outright and retry with
   the same payload next time, failing forever? That is the bug.

## The fix (as done in acme 1.0.199)

Two parts. The second one also covers certificates ordered before the first part
existed.

1. **Keep the account with the certificate.** After a successful order, store the
   account's `kid` beside the certificate (acme: `acme:state:<target>` → `kid`), and keep
   it also when a later order fails. Before ordering, send `replaces` only when that
   stored `kid` equals the current account's `kid`:

   ```python
   replaces = ari_cert_id(old_cert) if old_cert_from_acme else ''
   if replaces and state.get('kid') and state['kid'] != acme.kid:
       replaces = ''          # another account ordered it: it may not say so
   ...
   state['kid'] = acme.kid    # on success
   ```

2. **Retry once without `replaces`** when the CA refuses it. When there is no stored
   `kid` (certificates from older versions), or anything else the CA objects to about
   `replaces`, order again as a new certificate. It is still a renewal, it just doesn't
   count as one towards ARI and rate limits:

   ```python
   try:
       order = new_order(payload)
   except AcmeError as e:
       if 'replaces' not in payload or 'replace' not in str(e).lower():
           raise
       log("the CA does not take it as the renewal of the one before - ordered as a new one")
       payload.pop('replaces')
       order = new_order(payload)
   ```

   Say it in the order's steps or log so the user sees why.

Related `replaces` rules worth checking at the same time:

- A certificate can be replaced **once**. A second order naming the same certificate is
  refused (RFC 9773 error `alreadyReplaced`). The retry above covers that as well.
- With **two certificates per name** (RSA + ECDSA), each order must name its own
  predecessor (RSA → old RSA, ECDSA → old ECDSA), or only one of them should carry
  `replaces`. Never the same certificate ID in both.
- The replaced certificate must share at least one identifier with the new order.

## How to test it

With a test CA that enforces the rule. acme's mock (`tests/acme/mock_acme.py`) remembers
which account ordered each serial and refuses with Let's Encrypt's own text:

1. Order a certificate. The stored state has the account's `kid`.
2. Change the account key type → a new account. Order again: it must succeed, and the
   CA must see **no** `replaces`.
3. Remove the stored `kid` (a certificate from an older version) and change the account
   key back → order: the CA sees `replaces`, refuses it, and the retry without it
   succeeds. The steps say so.

acme: `tests/acme/t_acme.py`, the last section ("Another kind of key of the account"),
67 of 67.
