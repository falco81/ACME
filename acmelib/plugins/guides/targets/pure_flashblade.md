# Pure Storage FlashBlade - setup for acme

acme replaces a certificate of a FlashBlade (Purity//FB, now *Everpure*) in place, through **REST API 2.x** with an API token - the same flow as on a FlashArray, with FlashBlade's two differences:

1. `GET /api/api_version` - the REST versions it speaks; acme takes the newest `2.x` (or the one you set);
2. `POST /api/login` (no version in the path on a FlashBlade) with `api-token: <token>` → the `x-auth-token` header;
3. `GET /api/2.x/certificates?names=<name>` - the same certificate there already: nothing is changed;
4. `PATCH /api/2.x/certificates?names=<name>` with `certificate`, `intermediate_certificate` and **`private_key`** (a FlashArray calls it `key`);
5. `POST /api/2.x/logout`.

## Which versions

Purity//FB **4.x** with REST API **2.x** (the vendor guide: up to 2.30). One module.

## What you need

- The management VIP reachable from acme on **443**.
- The **name** of the certificate to replace. Pure does not document the name of a FlashBlade's management certificate (often `global` - *not verified*): list them first.

```sh
TOKEN=$(curl -k -s -D - -o /dev/null -X POST "https://fb01.example.com/api/login" -H "api-token: <api-token>" \
        | awk -F': ' 'tolower($1)=="x-auth-token"{print $2}' | tr -d '\r')
curl -k "https://fb01.example.com/api/2.30/certificates" -H "x-auth-token: $TOKEN"
```

- A certificate with the FlashBlade's FQDN in CN / SAN; the FlashBlade documents at most 3000 characters for a certificate - a long chain may not fit.

## An account and its API token

Roles: `array_admin`, `storage_admin`, `ops_admin`, `readonly`. Certificates need **`array_admin`** (no smaller role is documented; a custom policy on `purestorage.com/api/v2/certificates` may do on newer Purity//FB). Create a local admin with that role in the GUI (*Settings > Users*) or over REST, then its API token:

```sh
curl -k -X POST "https://fb01.example.com/api/2.30/admins/api-tokens?names=svc-cert" -H "x-auth-token: $TOKEN"
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the FlashBlade's management FQDN, `443` |
| API token | the token of the `array_admin` account |
| REST API version (advanced) | empty, or e.g. `2.30` |
| Check the device's certificate | on; off only while it still has its self-signed certificate |
| Certificate on the FlashBlade (deployment) | the name from `GET /api/2.x/certificates`, e.g. `global` |
| Check what is served | `fb01.example.com:443` (for `management` / `global` acme checks it by itself) |

## Check it

```sh
openssl s_client -connect fb01.example.com:443 -servername fb01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -k "https://fb01.example.com/api/2.30/certificates?names=global" -H "x-auth-token: $TOKEN"
```

## Common problems

| What you see | Why | What to do |
|---|---|---|
| `401` on the login | wrong or expired API token | make a new token |
| `400` naming `key` | the FlashArray field was sent | choose the target *Pure Storage FlashBlade*, not FlashArray |
| *has no certificate "..."* | the name is another | list the certificates and put that name into the deployment |
| clients that pinned the old certificate fail | the certificate changed | trust the CA, not the certificate |

Sources: FlashBlade REST API 2.30 reference (`/login`, `/certificates`, roles and authorization resources), Ansible `purestorage.flashblade.purefb_certs`.
