# Pure Storage FlashArray - setup for acme

acme replaces the **management certificate** of a FlashArray (Purity//FA, now *Everpure*) in place, through **REST API 2.x** with an API token:

1. `GET /api/api_version` - the REST versions the array speaks (no sign-in); acme takes the newest `2.x`, or the one you set;
2. `POST /api/2.x/login` with the header `api-token: <token>` → the session token in the answer's `x-auth-token` header;
3. `GET /api/2.x/certificates?names=management` - when it already holds this very certificate, nothing is changed;
4. `PATCH /api/2.x/certificates?names=management` with `certificate`, `intermediate_certificate` and `key` (the key comes with it, so the array's own key and CSR do not matter);
5. `POST /api/2.x/logout`.

The management web server (GUI, REST API) uses the new certificate at once; the data path (FC, iSCSI, NVMe, NFS, SMB, S3) is not touched.

## Which versions

Purity//FA **6.x** with REST API **2.x** (the vendor guide: up to 2.59). Every 2.x version has these calls - one module, no versions to choose.

## What you need

- The management address (VIF `vir0`) reachable from acme on **443**; REST is always on.
- NTP and DNS working on the array.
- A certificate whose CN / SAN hold the FQDN the array is reached by (CN at most 64 characters). RSA 2048 or more is the safe choice.

## An account and its API token

Purity's built-in roles are `readonly`, `ops_admin`, `storage_admin` and `array_admin`. Certificates change the configuration of the whole array, so count on **`array_admin`** (Pure documents no smaller role for it; on newer Purity a management access policy limited to `purestorage.com/api/v2/certificates` may do).

Over REST, signed in once as an existing administrator (`pureuser`):

```sh
curl -k -i -X POST "https://array01.example.com/api/2.59/login" -H "Content-Type: application/json" \
  -d '{"username":"pureuser","password":"<password>"}'
# take the x-auth-token header of the answer
curl -k -X POST "https://array01.example.com/api/2.59/admins?names=svc-cert" \
  -H "x-auth-token: <session-token>" -H "Content-Type: application/json" \
  -d '{"password":"<strong-password>","role":{"name":"array_admin"}}'
curl -k -X POST "https://array01.example.com/api/2.59/admins/api-tokens?names=svc-cert&timeout=7776000000" \
  -H "x-auth-token: <session-token>"
```

`timeout` is in milliseconds (here 90 days - renew the token before it ends, or leave `timeout` out). On the CLI the same is (the syntax is not in Pure's public documents - check with `pureadmin -h`):

```text
pureadmin create --role array_admin svc-cert
pureadmin create --api-token svc-cert
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the array's management FQDN, `443` |
| API token | the token of `svc-cert` |
| REST API version (advanced) | empty (the newest 2.x the array lists), or e.g. `2.59` |
| Check the device's certificate | on; off only while the array still has its self-signed certificate |
| Certificate on the array (deployment) | `management`; `vasa-ct0` / `vasa-ct1` for the VASA providers (a deployment each) |
| Check what is served | for `management` acme checks `<address>:443` by itself |

**Before the first deployment**: clients that pinned the old certificate stop trusting the array - the **VASA provider in vCenter** (register it again), Pure1 and the vSphere plug-in.

## Check it

```sh
openssl s_client -connect array01.example.com:443 -servername array01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -k "https://array01.example.com/api/2.59/certificates?names=management" -H "x-auth-token: $TOKEN"
curl -k "https://array01.example.com/api/2.59/certificates/uses" -H "x-auth-token: $TOKEN"
```

On the CLI: `purecert list` and `purecert list management --certificate`.

## Common problems

| What you see | Why | What to do |
|---|---|---|
| `401` on the login | wrong or expired API token | make a new token for `svc-cert` |
| `403` on the PATCH | the account lacks the right | give it `array_admin` (or a policy on certificates) |
| *the array has no certificate "..."* | another name | `GET /api/2.x/certificates` lists the names |
| *speaks no REST API 2.x* | Purity older than REST 2 | update Purity; acme speaks REST 2.x only |
| vCenter shows the storage provider offline | VASA trusted the old certificate | register the provider again |

Sources: FlashArray REST API 2.59 reference (`/login`, `/certificates`, `/admins`, `/admins/api-tokens`), Ansible `purestorage.flasharray.purefa_certs`.
