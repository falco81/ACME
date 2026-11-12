# Hurricane Electric (dns.he.net) - setup for acme

acme proves names by DNS-01 at Hurricane Electric's free DNS (`dns.he.net`) through its **dynamic TXT update** (`dyn.dns.he.net/nic/update`) - dns.he.net has no other API. So the TXT record `_acme-challenge.NAME` must be **made by hand first**, with dynamic DNS enabled and its own key; acme then only changes its value.

Limits: the record holds **one value** - it is replaced, never added to. `example.com` and `*.example.com` in one certificate need two values at one name, so acme proves them one after the other. Cleanup cannot delete the record: it sets it to *Value when idle*.

## What you need

- The zone hosted at dns.he.net (the domain delegated to `ns1`-`ns5.he.net`).
- Outbound HTTPS from acme to `dyn.dns.he.net` (port 443).

## Set up dns.he.net

For **each** name a certificate holds:

1. Sign in at `dns.he.net` → the zone → **New TXT**.
2. **Name**: `_acme-challenge.www.example.com` (for `example.com` and `*.example.com`: `_acme-challenge.example.com`), **Text data**: any value (e.g. `acme-idle`), **TTL**: 5 minutes (300).
3. Tick **Enable entry for dynamic dns** and save.
4. Click the **circular-arrows button** beside the new record → **Generate a key** → copy it. One key per record.

## Fill in acme

| acme field | What to put there |
|---|---|
| Records and their keys | One line per record: its full name, then its key, e.g. `_acme-challenge.example.com  Kx9…`. A line with only a key is used for every name not listed |
| Zone | e.g. `example.com`; empty = found by its SOA |
| Value when idle | (advanced) What the record is set to on cleanup, default `acme-idle` |

Example:

```text
_acme-challenge.example.com      Kx9...
_acme-challenge.www.example.com  P2b...
```

## Check it

- **Test** in acme checks at HE's name servers that each listed record exists. **It cannot try a key without changing the record.**
- By hand (this does change the value):

  ```sh
  curl -s -d 'hostname=_acme-challenge.example.com' -d "password=$KEY" -d 'txt=test' \
    https://dyn.dns.he.net/nic/update
  dig +short TXT _acme-challenge.example.com @ns1.he.net
  ```

## Common problems

| Problem | Fix |
|---|---|
| `badauth` | Wrong key for that record, or *Enable entry for dynamic dns* is not ticked. |
| `no TXT record at HE - make it first` | Create the TXT record by hand (step 1-3). |
| `interval` | dns.he.net rate-limits updates; acme tries again later. |
| The second name of a certificate waits | Expected: one value per name at a time. |
