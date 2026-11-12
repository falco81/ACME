# NetApp ONTAP (ONTAP 9.10.1 - 9.19) - setup for acme

acme talks to the cluster management LIF through the **ONTAP REST API** (`https://<cluster-mgmt>/api/...`, HTTP basic sign-in). For each new certificate it:

1. installs it as a **server** certificate - `POST /api/security/certificates` with `name` (`acme-<name>-<date>-<serial>`), `type: server`, `public_certificate`, `private_key` and every intermediate in `intermediate_certificates` (ONTAP refuses a server certificate with a missing intermediate); in the cluster scope, or in a data SVM (`svm.name`);
2. waits for the job when ONTAP answers `202` (`GET /api/cluster/jobs/<uuid>`);
3. makes the web services (System Manager, REST API) use it - where depends on the ONTAP version, see below; ONTAP then **restarts its web services** (open System Manager and REST sessions drop, NFS/SMB/iSCSI are not touched);
4. deletes older acme certificates of the same name beyond *Previous versions to keep* - only after the switch, never the one in use.

## Which ONTAP this guide is for

Module version **ONTAP 9.10.1 - 9.19** (`9.10`): ONTAP **9.10.1 and later** - the vendor guide checked 9.16.1, 9.17.1, 9.18.1 and 9.19.1. It binds the certificate only through the endpoints NetApp recommends since 9.10:

```text
PATCH /api/cluster/web               {"certificate": {"uuid": "<uuid>"}}   the cluster
PATCH /api/svm/svms/<svm-uuid>/web   {"certificate": {"uuid": "<uuid>"}}   a data SVM
```

acme reads the version first (`GET /api/cluster?fields=version`): a cluster on ONTAP 9.9 or older is refused before anything is changed (choose *ONTAP 9.6 - 9.9*); one newer than 9.19 is a warning. When the version cannot be read, these calls are used, with a warning. From 9.17.1 `/api/cluster/web` also holds HSTS (`hsts.enabled`) - acme does not change it.

## What you need

- HTTPS management (on by default; HTTP is off) reachable from acme on port 443.
- Working NTP on the cluster - a certificate with `notBefore` in the future is not used.
- A certificate with the cluster's FQDN (and, as NetApp's KB advises, the FQDNs/IPs of the nodes) in the SAN. RSA or EC; in FIPS mode at least 2048 bits and no MD5/SHA-1.

## An account with the least rights

The certificate commands are for cluster and SVM administrators at the admin privilege level. A traditional role with only what acme needs (admin SVM = the cluster's name, here `cluster1`):

```text
security login role create -vserver cluster1 -role cert_admin -cmddirname "security certificate" -access all
security login role create -vserver cluster1 -role cert_admin -cmddirname "security ssl" -access all
security login role create -vserver cluster1 -role cert_admin -cmddirname "vserver services web" -access readonly
security login role create -vserver cluster1 -role cert_admin -cmddirname "DEFAULT" -access none
security login create -vserver cluster1 -user-or-group-name svc_cert -application http -authentication-method password -role cert_admin
```

Or a REST role:

```text
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/security/certificates" -access all
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/cluster/web" -access read_modify
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/svm/svms" -access read_modify
security login rest-role create -vserver cluster1 -role cert_rest -api "/api/cluster" -access readonly
security login create -vserver cluster1 -user-or-group-name svc_cert -application http -authentication-method password -role cert_rest
```

- The application `http` covers the REST API (and System Manager); acme needs no `ssh`.
- *Uncertain*: NetApp has no example proving that this least set of REST roles is enough to bind the certificate (`/api/cluster/web`, `/api/svm/svms/*/web`). If a call answers `403`, use the predefined `admin` role on the admin SVM for this account.
- On ONTAP 9.6 - 9.9 binding is `PATCH /api/cluster` - give that path `read_modify` instead of `readonly`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **ONTAP 9.10.1 - 9.19** |
| Address / HTTPS port | the cluster management LIF (FQDN), `443` |
| User / Password | `svc_cert` and its password |
| Check the device's certificate | on; off only while the cluster still has its self-signed certificate (or put its CA into *CA certificate*) |
| SVM (deployment) | empty for the cluster's own web services; a data SVM's name for its web services |
| Wait for a job (s) (advanced) | how long a `202` job is waited for (`120`) |
| Previous versions to keep (advanced) | older acme certificates kept (`1`) |
| Check what is served | for an SVM its management LIF, e.g. `svm1.example.com:443` (the cluster one is checked by itself) |

After the binding ONTAP restarts its web services: the answer to that call may be cut off - acme then reads `/api/cluster/web` to see what is bound. With *Check the device's certificate* on, acme's next requests are checked against the new certificate (set *CA certificate* for a private CA).

## Check it

```sh
openssl s_client -connect cluster1.example.com:443 -servername cluster1.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -serial -dates -ext subjectAltName
curl -u svc_cert "https://cluster1.example.com/api/cluster/web?fields=certificate,state"
curl -u svc_cert "https://cluster1.example.com/api/security/certificates?type=server&fields=name,common_name,serial_number,expiry_time,svm"
```

On the CLI:

```text
security ssl show -vserver cluster1
security certificate show -vserver cluster1 -type server -fields common-name,serial,ca,expiration
```

## Common problems

| What you see | Why | What to do |
|---|---|---|
| `Failed to read the X509 from BIO` | a format ONTAP cannot read (PKCS#7) | acme sends PEM - check the certificate in acme |
| the install fails on the chain | an intermediate is missing | the issuer's chain must be complete in acme |
| `403` on `/api/cluster/web` | the REST role lacks the path | add it (`read_modify`) or use the `admin` role |
| *the module version ... is for ONTAP ...* | the cluster runs another ONTAP | choose the version named in the message (or *any version*) |
| System Manager logs you out | the web services restart after the binding | expected; sign in again |
| an old certificate is not deleted | it is still bound somewhere | acme keeps it and says so; delete it by hand later |

Sources: NetApp ONTAP REST API reference (`security/certificates`, `cluster/web`, `svm/svms/{uuid}/web`, `PATCH /cluster`), ONTAP CLI reference (`security certificate install`, `security ssl modify`, `security login role create`, `security login rest-role create`).
