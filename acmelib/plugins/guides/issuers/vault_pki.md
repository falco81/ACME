# HashiCorp Vault PKI - setup for acme

The **HashiCorp Vault PKI** source has the request acme made signed by the PKI secrets engine of HashiCorp Vault (or OpenBao, which keeps the same API): `POST /v1/<mount>/sign/<role>` (or `/v1/<mount>/issuer/<ref>/sign/<role>`) with the CSR, the names and the TTL - it uses **sign**, not issue, so **the private key never goes to Vault**. Revocation is `POST /v1/<mount>/revoke` with the serial. *Try it* reads `auth/token/lookup-self` and the mount's CA chain; the role list comes from `LIST /v1/<mount>/roles`; *Import from a source* lists `<mount>/certs`. Signing in is a token or an AppRole. Vault 1.x (Community, Enterprise, HCP Vault) and OpenBao.

## What you need

- A PKI secrets engine mounted (e.g. `pki_int`) with an issuer and a **role** whose rules allow your names (allowed domains, subdomains, wildcards, IP SANs, key types, max TTL).
- A **policy** for acme and either a token with it or an AppRole bound to it.
- HTTPS access **from acme** to Vault, port `8200` by default.
- Vault Enterprise / HCP: the namespace.

## Set up Vault

1. A role for acme's certificates (the role's rules decide what is signed):

   ```sh
   vault write pki_int/roles/web-servers \
       allowed_domains="example.com" allow_subdomains=true allow_wildcard_certificates=true \
       allow_ip_sans=true key_type=any max_ttl=8760h
   ```

   `key_type=any` lets acme ask for RSA and ECDSA (a dual certificate).
2. A policy with the minimal rights:

   ```hcl
   # acme-pki.hcl
   path "pki_int/sign/web-servers"   { capabilities = ["update"] }
   path "pki_int/revoke"             { capabilities = ["update"] }
   path "pki_int/roles"              { capabilities = ["list"] }      # Load the list (optional)
   path "pki_int/certs"              { capabilities = ["list"] }      # Import from a source (optional)
   ```

   ```sh
   vault policy write acme-pki acme-pki.hcl
   ```

   With an issuer chosen (`/issuer/<ref>/sign/<role>`), allow `pki_int/issuer/<ref>/sign/web-servers` instead.
3. Either a token:

   ```sh
   vault token create -policy=acme-pki -period=768h -display-name=acme
   ```

   (a periodic token must be used within its period - acme uses it at each renewal), or an AppRole:

   ```sh
   vault auth enable approle      # once
   vault write auth/approle/role/acme token_policies=acme-pki token_ttl=1h
   vault read auth/approle/role/acme/role-id
   vault write -f auth/approle/role/acme/secret-id
   ```

## Fill in acme

Sources → **Add** → **HashiCorp Vault PKI**.

| acme field | What to put there |
|---|---|
| Vault address | `https://vault.example.local:8200` |
| PKI mount | e.g. `pki_int` (default `pki`) |
| Role | e.g. `web-servers` - *Load the list* reads the mount's roles; a certificate's own role wins |
| Issuer (advanced) | an issuer name or id; empty: the role's |
| Signing in | *Token* or *AppRole (role ID and secret ID)* |
| Token / Role ID + Secret ID | from step 3 |
| AppRole mount (advanced) | `approle` unless mounted elsewhere |
| Namespace (advanced) | Vault Enterprise / HCP namespace |
| TTL (advanced) | e.g. `720h`; a certificate's days win; empty: the role's |
| Common name not in the SANs / Leave roots out of the chain (advanced) | normally off |
| CA certificate of Vault's TLS / Check Vault's TLS certificate (advanced) | for Vault with a private TLS certificate |

## Check it

- Sources → the source → **Test** (Try it): `signed in (policies ...); the mount pki_int has the CA ...`.
- By hand, with the same token:

```sh
VAULT_TOKEN=... vault token capabilities pki_int/sign/web-servers     # must include update
vault list pki_int/roles
```

## Common problems

| Problem | Fix |
|---|---|
| `403 permission denied` | the policy lacks `update` on `<mount>/sign/<role>` (or `issuer/<ref>/sign/<role>`) |
| `... is not allowed by this role` | the name is outside `allowed_domains`, or wildcards / IP SANs / subdomains are not allowed |
| `role key type ... not allowed` | set `key_type=any` or the type acme uses |
| TTL cut short | the role's or mount's `max_ttl` limits it |
| Token expired | renew it, use a periodic token, or switch to AppRole |
| `Load the list` empty | the policy has no `list` on `<mount>/roles` - type the role |
