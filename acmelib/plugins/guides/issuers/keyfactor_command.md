# Keyfactor Command - setup for acme

The **Keyfactor Command** source gets certificates through Keyfactor Command's REST API (`/KeyfactorAPI`): acme enrolls its CSR with a **template** and a **CA** (`POST Enrollment/CSR`) and takes the certificate and chain from the answer; revocation is `POST Certificates/Revoke`; the lists of templates and CAs come from `GET Enrollment/CSR/Context/My` (what the user may enroll with); *Import from a source* reads `GET Certificates` and `Certificates/Download`. **The private key never leaves acme.** Signing in is HTTP Basic (`DOMAIN\user`) or an OAuth 2.0 client (client credentials at the identity provider Command trusts). A template that needs an approval in Command leaves the request waiting there - acme says so and does not ask again by itself.

## What you need

- Keyfactor Command reachable **from acme** over HTTPS (`443`), with the API (`/KeyfactorAPI`).
- A CA known to Command (e.g. an AD CS or EJBCA CA through its gateway) and a **template** enabled for **CSR enrollment**.
- A user (or an OAuth client) for acme in a Command **security role** with the minimal permissions below.

## Set up Command

1. **Template** (Management Portal → **Locations → Certificate Templates**, *Edit*): enable it for **CSR Enrollment**; set *Template Regular Expressions* / allowed key sizes as your policy says. Leave *requires approval* off for automatic renewals. The template must also allow Command's enrollment on the CA side (e.g. AD CS: the Command service account has Enroll on the template, and the template is published).
2. **Security role** (**System Settings → Security Roles**, *Add*): e.g. `acme-enroll`, with the permissions (names as in Command 10/11 - check your version's list):
   - *Certificate Enrollment*: **Enroll CSR**
   - *Certificates*: **Read** (to list and download for *Import from a source*), **Revoke** (to revoke)
   - in older versions also *API*: **Read**
   Limit it to the collections / CAs acme needs where your version allows.
3. **Identity**: add the AD user (e.g. `EXAMPLE\svc-acme`) - or, with an identity provider (Keyfactor Identity Provider, Entra ID, Keycloak...), the OAuth client's identity - to the role (**Security Identities → Add**).
4. OAuth: in the identity provider create a confidential client for acme (client credentials grant); note the **token endpoint**, client ID, secret, and the scopes / audience Command requires.

Check the API:

```sh
curl -s -u 'EXAMPLE\svc-acme' -H 'x-keyfactor-api-version: 1' -H 'x-keyfactor-requested-with: APIClient' \
  https://keyfactor.example.local/KeyfactorAPI/Enrollment/CSR/Context/My
```

## Fill in acme

Sources → **Add** → **Keyfactor Command**.

| acme field | What to put there |
|---|---|
| Command address | `https://keyfactor.example.local` |
| Signing in | *User and password (HTTP Basic)* or *OAuth client (client ID and secret)* |
| Domain of the user / User / Password | `EXAMPLE`, `svc-acme`, its password (sent as `DOMAIN\user`) |
| Token address / Client ID / Client secret | for OAuth, e.g. `https://idp.example.local/realms/Keyfactor/protocol/openid-connect/token` |
| Scopes / Audience (advanced) | when the identity provider wants them |
| Template | *Load the list* - the CSR templates the user may use |
| Certificate authority | the template's CA as Command names it (`HOST\CA name`); set by itself when there is one |
| Template typed / Certificate authority typed (advanced) | only where the lists cannot be loaded |
| Which certificates to list (advanced) | a Command query for *Import from a source*, e.g. `IssuedCN -contains "example.com"` |
| API path (advanced) | `KeyfactorAPI` |
| CA certificate of Command's TLS / Check Command's TLS certificate (advanced) | for a private TLS certificate |

## Check it

- Sources → the source → **Test** (Try it): the templates and CAs the user may enroll with.
- After issuing: Management Portal → **Certificates → Certificate Search** shows it with the template and requester.

## Common problems

| Problem | Fix |
|---|---|
| `401` | wrong user / domain / password, or the OAuth token is refused (client, scope, audience) |
| `403` / *does not have permission* | the role lacks *Enroll CSR* (or Read / Revoke), or the identity is not in the role |
| Template missing from the list | it is not enabled for CSR enrollment, or the user may not use it |
| *waiting for approval* | the template requires approval - approve in Command, or use a template without it |
| Name or key refused | the template's regular expressions or key size rules |
| The CA refuses (`Denied`) | the CA-side template permissions for Command's enrollment account |
