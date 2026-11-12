# EJBCA (REST API) - setup for acme

The **EJBCA (REST API)** source has certificates issued by EJBCA (Keyfactor; Community or Enterprise) through its REST certificate management interface: `POST /ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll` with the CSR acme made, the certificate profile, the end entity profile, the CA, the end entity name and the enrollment code - **the private key never leaves acme**. Revocation is `PUT .../v1/certificate/<issuer DN>/<serial>/revoke`; *Try it* reads `/v1/certificate/status` and `/v1/ca`; *Import from a source* uses `/v1/certificate/search`. acme signs in with an **administrator's client certificate** (mutual TLS). The lists of end entity profiles and their certificate profiles come from `/v2/endentity/...`, likely EJBCA Enterprise only - on Community, type the names.

## What you need

- EJBCA reachable **from acme** over HTTPS (the public web port, usually `443` or `8443`), with client-certificate authentication.
- The REST protocol switched on.
- A CA, an **end entity profile** and a **certificate profile** for TLS servers.
- An administrator certificate (and key) for acme, in a role with the minimal rights below.

## Set up EJBCA

1. **System Configuration → Protocol Configuration**: enable **REST Certificate Management** (and **REST Certificate Management V2** for the lists and search on Enterprise).
2. Profiles: a **Certificate Profile** (e.g. `SERVER`: key algorithms RSA/ECDSA as acme uses, Server Authentication, validity) and an **End Entity Profile** (e.g. `TLS_SERVERS`: subject CN, DNS Name SANs - as many as your certificates have, the CA and certificate profile available).
3. Issue an administrator certificate for acme: **RA Web → Make New Request** (or an end entity with a client-auth profile), download it with its key as PEM.
4. **Roles and Access Rules → Add** a role `acme-rest`; *Members*: match the acme certificate (*X509: CN, Common name* = its CN, the issuing CA). Access rules (Advanced mode), the minimal set:
   - `/ra_functionality/create_end_entity`, `/ra_functionality/edit_end_entity`, `/ra_functionality/view_end_entity`
   - `/ra_functionality/revoke_end_entity` (to revoke)
   - `/endentityprofilesrules/TLS_SERVERS/create_end_entity`, `.../edit_end_entity`, `.../view_end_entity`, `.../revoke_end_entity`
   - `/ca/IssuingCA`
   - `/administrator`
5. The CA's chain: **CA Functions → CA certificate** - for checking, and the TLS root for *CA certificate of EJBCA's TLS* if needed.

Check from a shell on acme's network:

```sh
curl --cert acme-admin.pem --key acme-admin.key \
  https://ejbca.example.local/ejbca/ejbca-rest-api/v1/ca
```

## Fill in acme

Sources → **Add** → **EJBCA (REST API)**.

| acme field | What to put there |
|---|---|
| EJBCA address | `https://ejbca.example.local` (`/ejbca/ejbca-rest-api` is added) |
| Administrator's client certificate / Client certificate's key | the PEM from step 3, its chain after it |
| CA | e.g. `IssuingCA` - *Load the list* reads `/v1/ca` |
| End entity profile | e.g. `TLS_SERVERS` (list: Enterprise; type it on Community) |
| Certificate profile | e.g. `SERVER` (default); a certificate's own profile wins |
| End entity name | `{cn}` (default) - the first name; `{id}` acme's id |
| Enrollment code | empty: one made for each request |
| E-mail, Account binding ID (advanced) | where the end entity profile wants them |
| CA certificate of EJBCA's TLS / Check EJBCA's TLS certificate (advanced) | for a private TLS certificate |

## Check it

- Sources → the source → **Test** (Try it): status and the CAs the administrator sees.
- After issuing: **RA Web → Search → End Entities** shows the end entity (`{cn}`) and its certificate.

## Common problems

| Problem | Fix |
|---|---|
| `401` / `Not authorized to resource` | the role lacks a rule above, or the member match does not fit acme's certificate |
| TLS handshake fails | EJBCA does not trust the issuer of acme's admin certificate, or the client certificate is not sent (reverse proxy without client-auth pass-through) |
| `REST ... is not enabled` / 403 | enable REST Certificate Management in Protocol Configuration |
| `Load the list` says the call is not there | EJBCA Community: type the profile names |
| Name or key refused | the end entity / certificate profile does not allow that SAN count, name or key algorithm |
| `202` - waiting for approval | an approval profile is set: approve it in EJBCA; acme asks again at the next try |
