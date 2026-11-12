# HashiCorp Vault PKI - nastavení pro acme

Zdroj **HashiCorp Vault PKI** nechá žádost, kterou acme vytvořilo, podepsat PKI secrets enginem HashiCorp Vault (nebo OpenBao, které zachovává stejné API): `POST /v1/<mount>/sign/<role>` (nebo `/v1/<mount>/issuer/<ref>/sign/<role>`) s CSR, jmény a TTL - používá **sign**, ne issue, takže **soukromý klíč nikdy nejde do Vaultu**. Odvolání je `POST /v1/<mount>/revoke` se sériovým číslem. *Try it* čte `auth/token/lookup-self` a řetězec CA mountu; seznam rolí pochází z `LIST /v1/<mount>/roles`; *Import from a source* vypisuje `<mount>/certs`. Přihlašuje se tokenem nebo AppRole. Vault 1.x (Community, Enterprise, HCP Vault) a OpenBao.

## Co potřebujete

- Připojený PKI secrets engine (např. `pki_int`) s vydavatelem a **rolí**, jejíž pravidla povolují vaše jména (allowed domains, subdomény, wildcardy, IP SAN, typy klíčů, max TTL).
- **Politiku** pro acme a buď token s ní, nebo AppRole na ni navázanou.
- Přístup HTTPS **z acme** na Vault, výchozí port `8200`.
- Vault Enterprise / HCP: namespace.

## Nastavení Vaultu

1. Role pro certifikáty acme (pravidla role rozhodují, co se podepíše):

   ```sh
   vault write pki_int/roles/web-servers \
       allowed_domains="example.com" allow_subdomains=true allow_wildcard_certificates=true \
       allow_ip_sans=true key_type=any max_ttl=8760h
   ```

   `key_type=any` dovolí acme žádat o RSA i ECDSA (duální certifikát).
2. Politika s minimálními právy:

   ```hcl
   # acme-pki.hcl
   path "pki_int/sign/web-servers"   { capabilities = ["update"] }
   path "pki_int/revoke"             { capabilities = ["update"] }
   path "pki_int/roles"              { capabilities = ["list"] }      # Load the list (volitelné)
   path "pki_int/certs"              { capabilities = ["list"] }      # Import from a source (volitelné)
   ```

   ```sh
   vault policy write acme-pki acme-pki.hcl
   ```

   Se zvoleným vydavatelem (`/issuer/<ref>/sign/<role>`) povolte místo toho `pki_int/issuer/<ref>/sign/web-servers`.
3. Buď token:

   ```sh
   vault token create -policy=acme-pki -period=768h -display-name=acme
   ```

   (periodický token se musí použít během své periody - acme ho používá při každém obnovení), nebo AppRole:

   ```sh
   vault auth enable approle      # jednou
   vault write auth/approle/role/acme token_policies=acme-pki token_ttl=1h
   vault read auth/approle/role/acme/role-id
   vault write -f auth/approle/role/acme/secret-id
   ```

## Vyplnění v acme

Zdroje → **Přidat** → **HashiCorp Vault PKI**.

| Pole v acme | Co do něj zadat |
|---|---|
| Vault address | `https://vault.example.local:8200` |
| PKI mount | např. `pki_int` (výchozí `pki`) |
| Role | např. `web-servers` - *Load the list* načte role mountu; vlastní role certifikátu má přednost |
| Issuer (pokročilé) | jméno nebo id vydavatele; prázdné: vydavatel role |
| Signing in | *Token* nebo *AppRole (role ID and secret ID)* |
| Token / Role ID + Secret ID | z kroku 3 |
| AppRole mount (pokročilé) | `approle`, pokud není připojen jinde |
| Namespace (pokročilé) | namespace Vault Enterprise / HCP |
| TTL (pokročilé) | např. `720h`; dny certifikátu mají přednost; prázdné: TTL role |
| Common name not in the SANs / Leave roots out of the chain (pokročilé) | obvykle vypnuto |
| CA certificate of Vault's TLS / Check Vault's TLS certificate (pokročilé) | pro Vault s privátním TLS certifikátem |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `signed in (policies ...); the mount pki_int has the CA ...`.
- Ručně se stejným tokenem:

```sh
VAULT_TOKEN=... vault token capabilities pki_int/sign/web-servers     # musí obsahovat update
vault list pki_int/roles
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403 permission denied` | politice chybí `update` na `<mount>/sign/<role>` (nebo `issuer/<ref>/sign/<role>`) |
| `... is not allowed by this role` | jméno je mimo `allowed_domains`, nebo nejsou povoleny wildcardy / IP SAN / subdomény |
| `role key type ... not allowed` | nastavte `key_type=any` nebo typ, který acme používá |
| TTL zkrácené | omezuje ho `max_ttl` role nebo mountu |
| Token vypršel | obnovte ho, použijte periodický token, nebo přejděte na AppRole |
| `Load the list` prázdné | politika nemá `list` na `<mount>/roles` - roli napište ručně |
