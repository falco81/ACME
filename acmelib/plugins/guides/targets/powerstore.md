# Dell PowerStore - setup for acme

acme puts the certificate **with its key** on a **PowerStore cluster** as the cluster
management certificate (service `Management_HTTP`, scope `External` - PowerStore Manager and
the REST API on port 443) through the REST API:

```text
GET  /api/rest/login_session                       basic auth -> DELL-EMC-TOKEN + auth_cookie
GET  /api/rest/software_installed?select=release_version&is_cluster=eq.true
POST /api/rest/x509_certificate   {"type":"Server","service":"Management_HTTP","scope":"External",
                                   "certificate":"<server + intermediates, one string>",
                                   "private_key":"<key PEM>","is_current":true}
GET  /api/rest/x509_certificate/<id>?select=id,is_current,is_valid
POST /api/rest/logout
```

The certificate is used at once; nothing restarts and storage I/O is not touched (open
PowerStore Manager windows need to be opened again).

> **Try it first.** Dell documents the management certificate **only from a CSR the cluster
> makes itself** (Settings → Security → Signed Cluster Certificate → Generate CSR, or
> `POST /api/rest/x509_certificate/csr`, then the signed chain imported). Importing a key made
> elsewhere is the call of Dell's own SDK (PyPowerStore `create_certificate`: `certificate`,
> `private_key`, `is_current`), not documented for `Management_HTTP`. If your PowerStoreOS
> refuses it, acme says so and **nothing is changed** - then this cluster cannot take acme's
> certificate and keeps its own (or one from its CSR, by hand).

## Which PowerStoreOS

**PowerStoreOS 3.0 - 4.4** (one module: the same calls). 2.x took a management certificate
only on a single block appliance without replication - acme refuses it before changing
anything. A newer version goes on with a warning.

## The account (least privileges)

The cluster certificate is a security setting: role **Security Administrator** (role id `5`),
or Administrator. Operator only reads.

```sh
pstcli -d powerstore.example.local -u admin -p '<admin-password>' local_user create -name acme -password '<strong-password>' -role_id 5
```

Or in PowerStore Manager: **Settings → Users → Users → Add**, role *Security Administrator*.
Over REST (an admin's token from `login_session`):

```sh
curl -k -u admin:'<admin-password>' -X POST https://powerstore.example.local/api/rest/local_user \
  -H "DELL-EMC-TOKEN: <token>" -H 'Content-Type: application/json' \
  -d '{"name":"acme","password":"<strong-password>","role_id":"5"}'
```

## What the certificate must be

- RSA **2048 or 4096** key; the chain server → intermediates → root in one string (acme sends
  the server certificate and the intermediates it has; a leaf alone is refused).
- Valid for **at least 30 more days** (PowerStore refuses a shorter one).
- Its names: the cluster's DNS name and **the cluster and ICM IP addresses** (a public CA does
  not sign private IPs - Dell recommends an internal CA).
- With replication: run *Verify and Update* of the remote system after the change.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the cluster management address, `443` |
| User / Password | the `acme` account |
| Check the device's certificate | off for the first deployment over the self-signed certificate (or give *CA certificate*), then on |
| Check what is served | empty: acme checks the address of the target |

## Check it

```sh
openssl s_client -connect powerstore.example.local:443 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
pstcli -d powerstore.example.local -u acme -p '<password>' x509_certificate show
```

## Back to the self-signed certificate

```sh
pstcli -d powerstore.example.local -u admin -p '<admin-password>' x509_certificate reset_certificates -service Management_HTTP -scope External
```

## Common problems

| Problem | Fix |
|---|---|
| `does not take a key made elsewhere` | This PowerStoreOS imports the management certificate only from its own CSR - not automatable; replace it by hand. |
| `0xE09010010013` (verify your certificate chain) | The chain is incomplete or in the wrong order; the certificate valid for less than 30 days. |
| `401` / `403` | Wrong password, or the account is not Security Administrator / Administrator. |
| `runs PowerStoreOS 2.x` | Upgrade to 3.0 or later. |
| Replication sessions fail after the change | *Verify and Update* the remote system (KB 000211671). |
