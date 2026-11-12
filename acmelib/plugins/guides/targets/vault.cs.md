# HashiCorp Vault (KV v2) - nastavení pro acme

acme zapíše certifikát jako **secret do enginu KV verze 2**: `<mount>/data/<path>`
(výchozí `secret/data/acme/{name}`) s poli `certificate`, `chain`, `fullchain`,
`private_key` (pokud ho nevypnete), `fingerprint`, `serial`, `names`, `not_before`,
`not_after`. Novou verzi secretu zapíše jen tehdy, když se otisk liší. Kdo certifikát
potřebuje (Vault Agent, External Secrets, vaše skripty), si ho odtud přečte. Duální
certifikát (ECDSA + RSA) přidá pole dvojčete s předponou `alt_`.

Přihlašuje se **tokenem** nebo přes **AppRole**; podporuje jmenné prostory (namespaces)
Vault Enterprise. Funguje s HashiCorp Vault i OpenBao.

## Co potřebujete

- Síťový přístup z acme na API Vaultu: obvykle **TCP 8200** (HTTPS).
- Engine **KV verze 2** (KV v1 podporovaný není).
- Politiku (policy), která povoluje `create`, `update` a `read` na cestě, kam acme zapisuje.

## Nastavení Vaultu

1. Engine KV v2, pokud ho nemáte (`secret/` je KV v2 jen na dev serverech):

   ```sh
   vault secrets enable -path=secret kv-v2
   ```

2. Politika jen s tím, co acme potřebuje - uložte jako `acme-deploy.hcl`:

   ```text
   path "secret/data/acme/*" {
     capabilities = ["create", "update", "read"]
   }
   ```

   ```sh
   vault policy write acme-deploy acme-deploy.hcl
   ```

   (Pro jiný mount nebo cestu změňte `secret/data/acme/*` na `<mount>/data/<path>/*`.)
3. **AppRole** (doporučeno - acme dostane při každém běhu čerstvý token):

   ```sh
   vault auth enable approle
   vault write auth/approle/role/acme token_policies=acme-deploy token_ttl=20m \
         secret_id_ttl=0 secret_id_bound_cidrs=<IP-acme>/32
   vault read -field=role_id auth/approle/role/acme/role-id
   vault write -f -field=secret_id auth/approle/role/acme/secret-id
   ```

   **Nebo token**: `vault token create -policy=acme-deploy -orphan -ttl=8760h`. acme tokeny
   neobnovuje: po vypršení nasazení selhávají - vložte nový.
4. Enterprise: poznamenejte si jmenný prostor, ve kterém engine je.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Vault address | např. `https://vault.example.local:8200` |
| Sign in with | *AppRole* nebo *a token* |
| Role ID / Secret ID | Z kroku 3 (AppRole) |
| AppRole mount (pokročilé) | `approle`, pokud není zapnutý na jiné cestě |
| Token | Token (přihlášení tokenem) |
| Namespace (pokročilé) | Jmenný prostor Vault Enterprise, jinak prázdné |
| KV mount | `secret` (nebo váš mount KV v2) |
| Check the device's certificate | Zapnuto |
| CA certificate (pokročilé) | CA TLS certifikátu Vaultu, je-li interní |
| Path (nasazení) | `acme/{name}` (výchozí) - uvnitř mountu |
| With the private key (nasazení) | Zapnuto (výchozí); vypnout, potřebují-li odběratelé jen veřejnou část |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí a přečte svůj token
  (`auth/token/lookup-self`): `signed in to Vault as ... (policies default, acme-deploy)`.
- Po nasazení:

  ```sh
  vault kv get -field=not_after secret/acme/www.example.com
  vault kv metadata get secret/acme/www.example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403 permission denied` při zápisu | Cesta v politice musí pro KV v2 obsahovat `/data/`: `secret/data/acme/*`. |
| `no token is set` / `403` při Try | Token je prázdný, vypršel nebo byl zrušen - vytvořte nový, nebo použijte AppRole. |
| AppRole `invalid secret id` | Secret ID vypršelo nebo je vyčerpané, nebo `secret_id_bound_cidrs` vylučuje acme. |
| `404` / „no handler for route“ | Mount není engine KV v2, nebo chybí jmenný prostor. |
| Chyba TLS | Vložte CA Vaultu do *CA certificate*. |
