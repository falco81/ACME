# Sectigo Certificate Manager (Admin API) - setup for acme

The **Sectigo Certificate Manager (Admin API)** source gets certificates from Sectigo Certificate Manager (SCM) through its Admin API (`/api/ssl/v2`, `/api/dcv/v2`): acme first validates the domains not validated yet (**DCV** - a CNAME, TXT or file put in place by the certificate's own validation, or an e-mail a person approves), then **enrolls** its CSR with a **certificate profile** of the account for an organization, and collects the certificate. Renewals renew (or replace) the SCM certificate acme made or imported; revocation is included; *Import from a source* lists the account's certificates. **The private key never leaves acme.** Signing in is an **OAuth 2.0 API client** (recommended; `admin.<instance>.sectigo.com`) or an API administrator's login and password (`cert-manager.com`). For SCM's ACME with EAB use the ACME source instead; this source is for profiles, terms, custom fields, DCV by e-mail and the account's certificates. Also the home of former Entrust customers. No IP addresses.

## What you need

- An SCM account, the **organization (or department) ID** the certificates belong to, and an SSL **certificate profile** available to it.
- An **API client** (client ID + secret) - or an administrator allowed to use the API (login, password, customer URI).
- HTTPS access **from acme** to `admin.<instance>.sectigo.com` and `auth.sso.sectigo.com` (OAuth) or `cert-manager.com` (login), port 443.
- A validation in acme that can place the DCV proof (DNS for CNAME/TXT, HTTP for the file), or a person for e-mail.

## Set up SCM

1. **API client (OAuth 2.0)**: in SCM, create an API client for acme (Sectigo's documentation: *Authentication*; the menu is under integrations / API keys in current SCM) with the rights to enroll, collect, renew and revoke SSL certificates and to run domain validation, limited to the organization acme uses. Copy the **client ID** and **secret**, and note your **instance** (`enterprise`, `hard`, `eu`) from onboarding.
2. Or **an API administrator**: **Settings → Admins → Add** an administrator for acme (RAO/DRAO SSL admin of the organization) with API use allowed, a password, and note the account's **Customer URI**.
3. **Organization**: **Settings → Organizations** - note the **Org ID** (or a department's); its SSL settings must allow the certificate profile and term you want, and the domains must be delegated to it.
4. **Certificate profile**: note its ID (acme's *Load the list* reads `GET /api/ssl/v2/types`).
5. **Domains**: **Domains** - add the domains and delegate them to the organization; validating them ahead (DCV) means acme does not need to.
6. Mandatory **custom fields** of the account: note their names - acme sends them.

Check OAuth from a shell:

```sh
curl -s https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id="$ID" -d client_secret="$SECRET"
```

## Fill in acme

Sources → **Add** → **Sectigo Certificate Manager (Admin API)**.

| acme field | What to put there |
|---|---|
| Signing in | *OAuth 2.0 client* or *Login and password* |
| SCM instance / Client ID / Client secret | `enterprise` / `hard` / `eu`, and the API client's ID and secret |
| Token address (advanced) | default; a 401 answer names another one when your account has its own |
| Login / Password / Customer URI | for the login way |
| Organization ID | e.g. `12345` |
| Certificate profile | *Load the list*, or type the ID; a certificate's own profile wins |
| Term (days) | e.g. `365`; empty: the shortest the profile offers |
| Domain validation (DCV) | *DNS CNAME*, *DNS TXT*, *HTTP file* (no wildcards), or *E-mail* + *Approver mailbox* |
| Certificate to reuse | an SCM certificate ID to renew; empty: the one acme made last |
| A renewal (advanced) | *renews it* (default), *replaces it*, or *is a new enrollment* |
| Custom fields (advanced) | `name=value` lines - the account's mandatory ones |
| Comments, External requester, API address, Waits (advanced) | as needed |

## Check it

- Sources → the source → **Test** (Try it): signs in and reads the profiles - enrolls nothing.
- In SCM: **Certificates → SSL Certificates** shows the certificate, its status and requester.

## Common problems

| Problem | Fix |
|---|---|
| `401` | wrong client ID/secret or instance; the answer may name another token address; login: password, customer URI, API use allowed |
| `403` / not allowed for the organization | the client/admin has no rights on that organization or profile |
| Profile or term refused | the profile is not enabled for the organization, or the term is not offered |
| Domain not delegated / not allowed | add the domain and delegate it to the organization |
| DCV stays *Not validated* | the record was not visible yet (acme submits again at the next try); for e-mail, someone must approve |
| Missing custom field | add it under *Custom fields* |
| Waiting for approval | an SCM administrator must approve the request; acme collects it at a later try |
