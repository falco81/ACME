# Dell Unisphere for PowerMax (Solutions Enabler certificate) - setup for acme

**What this target does - and what it does not.** Unisphere for PowerMax 10.x has **no API
for its own HTTPS certificate** (port 8443): Dell documents it only in the GUI (**Settings →
Security → Server Certificates**: *Replace With Self-Signed Certificate*, *Generate CSR*,
*Upload Certificates*), from a CSR Unisphere makes itself - the key never leaves it, so acme
cannot put its certificate there. Do that one by hand.

What has an API is the **Solutions Enabler (SYMAPI) server certificate** of the embedded
management (eMGMT) nodes, `Semgmt0` and `Semgmt1`: its key, certificate and trust file of one's
own. acme imports them through Unisphere's Serviceability REST API, one node after the other:

```text
GET  /univmax/restapi/version                     -> api_version (e.g. 101 = Unisphere 10.1)
POST /univmax/restapi/<api>/serviceability/symmetrix/<array>/application/solutions_enabler/custom_certificate/import
     multipart/form-data: node_name=Semgmt0, keyfile=<key PEM>, certfile=<certificate + intermediates>, trustfile=<CA certificates>
```

> **Uncertain.** These calls are the ones of Dell's Python SDK **PyU4V**
> (`serviceability.import_custom_certificate`); Unisphere's REST API reference was not read.
> Try it on one node first (*Management nodes*: `Semgmt0`).

## Which Unisphere

**Unisphere for PowerMax 10.0 - 10.4** with embedded management (PowerMaxOS 10). Unisphere 9.x
(REST API 9x) is refused before anything is changed; a newer one goes on with a warning.

## The account

Security operations need **Administrator** or **SecurityAdmin** (StorageAdmin may not do them);
SecurityAdmin is the least. Unisphere: **Settings → Users and Groups → Authorized Users &
Groups → Add** - a local user `acme`, role *SecurityAdmin*, scope the array.

## The trust file

The SE server trusts its **clients' certificates** by the CA certificates in the trust file.
Empty *Trusted CA certificates*, acme puts the intermediates of its own certificate there: right
when your SE clients' certificates come from the same CA. Otherwise paste the CA certificate(s)
of the clients (PEM) into *Trusted CA certificates*. Back to Dell's self-signed certificate:

```sh
curl -k -u admin:'<password>' -X POST "https://unisphere.example.local:8443/univmax/restapi/101/serviceability/symmetrix/000120000123/application/solutions_enabler/self_signed_certificate" \
  -H 'Content-Type: application/json' -d '{"node_name":"Semgmt0"}'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the Unisphere address, `8443` |
| User / Password | the `acme` account |
| Array ID | the 12-digit Symmetrix ID, e.g. `000120000123` |
| Check the device's certificate | on when Unisphere's own certificate is trusted (or give *CA certificate*) |
| Management nodes (deploy) | `Semgmt0` and `Semgmt1`, one a line |
| Trusted CA certificates (deploy, advanced) | empty, or the CA certificates of the SE clients |

## Check it

*Try* on the target signs in, reads the REST API version and the embedded management of the
array. On a Solutions Enabler client:

```sh
openssl s_client -connect semgmt0.example.local:2707 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

Unisphere's own certificate (not changed by acme):

```sh
openssl s_client -connect unisphere.example.local:8443 -servername unisphere.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Common problems

| Problem | Fix |
|---|---|
| `acme needs Unisphere for PowerMax 10.0` | Unisphere 9.x - not supported. |
| `401` / `403` | Wrong password, or the account is not SecurityAdmin / Administrator. |
| `404` on the import | Not an embedded management instance, wrong array ID, or the path differs on your release - use the GUI. |
| SE clients refuse the server | The trust file or the clients' trust: they must trust acme's CA. |
