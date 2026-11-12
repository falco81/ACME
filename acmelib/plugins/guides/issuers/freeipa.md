# FreeIPA / Red Hat IdM - setup for acme

The **FreeIPA / Red Hat IdM** source has certificates issued by the CA (Dogtag) of FreeIPA / Red Hat Identity Management for a **service principal**: acme signs in (`/ipa/session/login_password`), then calls the JSON-RPC `cert_request` for `SERVICE/<first name>@REALM` with the CSR it made and the certificate profile (`caIPAserviceCert` by default), adding the service first when it is missing. **The private key never leaves acme.** Revocation is `cert_revoke`; the profile list comes from `certprofile_find`; *Import from a source* uses `cert_find`. IPA issues for principals: **no wildcards**. FreeIPA 4.x, RHEL IdM 8/9/10.

## What you need

- An IPA server reachable **from acme** over HTTPS (`443`).
- A user for acme with rights to request certificates for services (and to add services, if acme should add them).
- Every certificate's first name as an IPA **host** (`ipa host-add`); further names of the certificate must be names IPA lets that service have (hosts the service's host manages).
- The IPA CA certificate (`/etc/ipa/ca.crt`).

## Set up IPA

On an IPA server (or a client with admin rights), `kinit admin` first.

1. A user and a role with the needed privileges:

   ```sh
   ipa user-add svc-acme --first=acme --last=service --password
   ipa role-add "acme certificates"
   ipa role-add-privilege "acme certificates" --privileges="Certificate Administrators"
   ipa role-add-privilege "acme certificates" --privileges="Service Administrators"   # only to add services
   ipa role-add-member "acme certificates" --users=svc-acme
   ```

   Then sign in once as `svc-acme` (`kinit svc-acme`) to replace the initial password - IPA forces a change at first login, and an expired password makes acme's sign-in fail. Set a password policy that does not expire it too soon.
2. The hosts of the names:

   ```sh
   ipa host-add web1.example.local --force          # the first name of a certificate
   ipa host-add www.example.local --force           # a further name
   ipa host-add-managedby www.example.local --hosts=web1.example.local
   ```

   (Check IPA's documentation for SANs in service certificates if a further name is refused.)
3. CA ACL: the default `hosts_services_caIPAserviceCert` lets every host and service use `caIPAserviceCert`. For another profile or sub-CA:

   ```sh
   ipa caacl-add acme-tls --servicecat=all
   ipa caacl-add-profile acme-tls --certprofiles=caIPAserviceCert
   ipa caacl-add-ca acme-tls --cas=ipa
   ```

4. Copy `/etc/ipa/ca.crt` from the IPA server.

## Fill in acme

Sources → **Add** → **FreeIPA / Red Hat IdM**.

| acme field | What to put there |
|---|---|
| IPA server | `https://ipa.example.local` |
| User / Password | `svc-acme` and its (changed) password |
| Realm | `EXAMPLE.LOCAL` |
| Service | `HTTP` (default) - the principal is `HTTP/<first name>@EXAMPLE.LOCAL` |
| Add the service when missing | on (needs *Service Administrators*); off if services are made by hand |
| Profile | `caIPAserviceCert` (default) - *Load the list* reads IPA's profiles; a certificate's own profile wins |
| CA (advanced) | `ipa` (the main CA) or a sub-CA's name |
| IPA's CA certificate | the content of `/etc/ipa/ca.crt` |
| Check the server's TLS certificate (advanced) | on |

## Check it

- Sources → the source → **Test** (Try it).
- On IPA after issuing:

```sh
ipa service-show HTTP/web1.example.local@EXAMPLE.LOCAL
ipa cert-find --services=HTTP/web1.example.local
```

## Common problems

| Problem | Fix |
|---|---|
| Sign-in `401` / password expired | change the password with `kinit svc-acme`; check the password policy |
| `Insufficient access` on `cert_request` | the role lacks *Certificate Administrators* (request certificate) |
| `service not found` | switch *Add the service when missing* on (with *Service Administrators*), or `ipa service-add HTTP/web1.example.local` |
| `host not found` | add the host: `ipa host-add <name> --force` |
| SAN refused (`... does not match`, `not allowed`) | the further name is not a host managed by the first one |
| `Principal ... not permitted to use CA ... with profile ...` | a CA ACL must allow that service, profile and CA |
| Wildcard refused | IPA does not issue wildcards - use another source |
