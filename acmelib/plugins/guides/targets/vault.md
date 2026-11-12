# HashiCorp Vault (KV v2) - setup for acme

acme writes the certificate as a **secret of a KV version 2 engine**:
`<mount>/data/<path>` (default `secret/data/acme/{name}`) with the fields `certificate`,
`chain`, `fullchain`, `private_key` (unless turned off), `fingerprint`, `serial`, `names`,
`not_before`, `not_after`. A new secret version is written only when the fingerprint there
differs. Whatever needs the certificate (Vault Agent, External Secrets, your scripts) reads
it from there. A dual certificate (ECDSA + RSA) adds the twin's fields with `alt_` in front.

It signs in with a **token** or **AppRole**; Vault Enterprise namespaces are supported.
Works with HashiCorp Vault and OpenBao.

## What you need

- Network access from acme to Vault's API: usually **TCP 8200** (HTTPS).
- A **KV version 2** secrets engine (KV v1 is not supported).
- A policy allowing `create`, `update` and `read` on the path acme writes.

## Set up Vault

1. A KV v2 engine, if you do not have one (`secret/` is KV v2 on dev servers only):

   ```sh
   vault secrets enable -path=secret kv-v2
   ```

2. A policy with just what acme needs - save as `acme-deploy.hcl`:

   ```text
   path "secret/data/acme/*" {
     capabilities = ["create", "update", "read"]
   }
   ```

   ```sh
   vault policy write acme-deploy acme-deploy.hcl
   ```

   (With another mount or path, change `secret/data/acme/*` to `<mount>/data/<path>/*`.)
3. **AppRole** (recommended - acme gets a fresh token at each run):

   ```sh
   vault auth enable approle
   vault write auth/approle/role/acme token_policies=acme-deploy token_ttl=20m \
         secret_id_ttl=0 secret_id_bound_cidrs=<acme-IP>/32
   vault read -field=role_id auth/approle/role/acme/role-id
   vault write -f -field=secret_id auth/approle/role/acme/secret-id
   ```

   **Or a token**: `vault token create -policy=acme-deploy -orphan -ttl=8760h`. acme does
   not renew tokens: when it expires, deployments fail - put a new one in.
4. Enterprise: note the namespace the engine lives in.

## Fill in acme

| acme field | What to put there |
|---|---|
| Vault address | e.g. `https://vault.example.local:8200` |
| Sign in with | *AppRole* or *a token* |
| Role ID / Secret ID | From step 3 (AppRole) |
| AppRole mount (advanced) | `approle` unless enabled at another path |
| Token | The token (token sign-in) |
| Namespace (advanced) | Vault Enterprise namespace, else empty |
| KV mount | `secret` (or your KV v2 mount) |
| Check the device's certificate | On |
| CA certificate (advanced) | The CA of Vault's TLS certificate, if internal |
| Path (deploy) | `acme/{name}` (default) - inside the mount |
| With the private key (deploy) | On (default); off if consumers need only the public part |

## Check it

- Press **Try** on the target: acme signs in and reads its token
  (`auth/token/lookup-self`): `signed in to Vault as ... (policies default, acme-deploy)`.
- After a deployment:

  ```sh
  vault kv get -field=not_after secret/acme/www.example.com
  vault kv metadata get secret/acme/www.example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403 permission denied` on writing | The policy path must include `/data/` for KV v2: `secret/data/acme/*`. |
| `no token is set` / `403` on Try | Token empty, expired or revoked - make a new one, or use AppRole. |
| AppRole `invalid secret id` | Secret ID expired or used up, or `secret_id_bound_cidrs` excludes acme. |
| `404` / "no handler for route" | The mount is not a KV v2 engine, or the namespace is missing. |
| TLS error | Put Vault's CA into *CA certificate*. |
