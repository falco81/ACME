# CyberArk Certificate Manager Self-Hosted (Venafi TPP) - setup for acme

The **CyberArk Certificate Manager Self-Hosted (Venafi TPP)** source gets certificates from Venafi Trust Protection Platform (now CyberArk Certificate Manager, Self-Hosted) through its **WebSDK** REST API: acme signs in (`vedauth/authorize/oauth`, or a token made in the platform), sends its CSR into a **policy folder** (`vedsdk/certificates/request`), fetches the certificate when the platform's CA has issued it (`vedsdk/certificates/retrieve`), renews the same certificate object in place (`vedsdk/certificates/renew`) and revokes by thumbprint. **The private key never leaves acme.** *Import from a source* lists the folder's certificates; the folder list comes from `config/findobjectsofclass` (may need the `configuration` scope - type the folder otherwise). A request waiting for approval is asked for again at the next try.

## What you need

- The platform's address, reachable **from acme** over HTTPS (`443`), with WebSDK.
- An **API integration** (application) - by default `vcert-sdk` - with the scope `certificate:manage,revoke`, the acme user allowed to use it.
- A user for acme with rights on the policy folder (below), or an access token made for it.
- A policy folder whose policy allows a **user-provided CSR**, with a CA template.

## Set up the platform

1. **API integration** (Venafi Configuration Console / Aperture → **Platform → API → Integrations**, depending on version): use or create the integration with Application ID `vcert-sdk`, scopes **certificate: manage, revoke** (add **configuration** if you want *Load the list* of folders), and add acme's user to its *Allowed identities*. Note the token validity / refresh settings.
2. **A user** for acme (local or AD), e.g. `svc-acme`.
3. **Policy folder**, e.g. `\VED\Policy\DevOps\Web servers`: on the folder's **Permissions** give `svc-acme` **View, Read, Write, Create** (and **Revoke** to revoke). Inherit to the objects below.
4. In the folder's policy (**Certificate** tab): a **CA Template**; *CSR Generation* must allow **User Provided CSR** (not locked to *Service Generated*); the allowed key algorithms and sizes acme uses; domain whitelisting that includes your names.
5. If the folder uses **approvals** (workflow), acme waits and asks again at later tries - an approver must approve.

Check the sign-in:

```sh
curl -s https://tpp.example.local/vedauth/authorize/oauth -H 'Content-Type: application/json' \
  -d '{"client_id":"vcert-sdk","username":"svc-acme","password":"<password>","scope":"certificate:manage,revoke"}'
```

## Fill in acme

Sources → **Add** → **CyberArk Certificate Manager Self-Hosted (Venafi TPP)**.

| acme field | What to put there |
|---|---|
| Platform address | `https://tpp.example.local` |
| Signing in | *User and password (an OAuth token made by acme)* or *An access token made in the platform* |
| User / Password | `svc-acme` and its password |
| Access token | a token for the integration with `certificate:manage,revoke` - replace it before it ends |
| Policy folder | *Load the list* and pick the folder |
| Policy folder typed (advanced) | `DevOps\Web servers` (under `\VED\Policy`) where the list cannot be loaded |
| CA template (CADN) (advanced) | empty: the folder's |
| Name of the certificate object (advanced) | as the platform names it (CN), or the first name |
| Renew the same certificate object (advanced) | on |
| API application (client_id) / Scope of the token (advanced) | `vcert-sdk` / `certificate:manage,revoke` |
| Wait for the certificate (s) / Ask again every (s) (advanced) | `120` / `5` |
| CA certificate of the platform's TLS / Check the platform's TLS certificate (advanced) | for a private TLS certificate |

## Check it

- Sources → the source → **Test** (Try it): `Identity/Self` - the user acme is.
- After issuing: the certificate object in the folder (Policy tree / Aperture inventory) with its history.

## Common problems

| Problem | Fix |
|---|---|
| `invalid_grant` / `unauthorized_client` | the user is not allowed on the `vcert-sdk` integration, or the scope is not granted |
| `401` with an access token | the token expired - make a new one |
| `... does not have permission` on request | View/Read/Write/Create on the folder for the user |
| `Load the list` refused | the token lacks the `configuration` scope - type the folder |
| *CSR ... not allowed* / *Service Generated* | allow a user-provided CSR in the folder's policy |
| Waits and is never issued | an approval in the workflow, or the CA template's CA is failing - see the object's log |
