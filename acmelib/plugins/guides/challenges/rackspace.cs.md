# Rackspace Cloud DNS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **Rackspace Cloud DNS**, přes jeho API v1.0. Přihlásí se na `https://identity.api.rackspacecloud.com/v2.0/tokens` uživatelským jménem a API klíčem, z katalogu služeb vezme endpoint `rax:dns`, vypíše domény, načte TXT záznamy, pro každou hodnotu přidá jeden záznam a smaže jen ty své. Každá změna je asynchronní úloha: acme sleduje její `callbackUrl`, dokud není `COMPLETED` (nebo ukáže `ERROR`).

## Co potřebujete

- Účet Rackspace Cloud s doménou v **Cloud DNS** a u registrátora nastavené jmenné servery Rackspace (`dns1.stabletransit.com`, `dns2.stabletransit.com`).
- HTTPS (TCP 443) z acme na `identity.api.rackspacecloud.com` a `dns.api.rackspacecloud.com`.

## Nastavení Rackspace

1. Přihlaste se do **Cloud Control Panel** (`login.rackspace.com` / `mycloud.rackspace.com`) jako vlastník účtu nebo admin.
2. **Account → User Management → Create User**: uživatelské jméno `acme`, e-mail a přístup k produktům:
   - **DNS**: **Admin** (potřeba k vytváření a mazání záznamů; možná stačí i „Creator“ - ověřte si popis rolí Rackspace pro váš účet),
   - všechny ostatní produkty: **No Access**.
3. Otevřete nového uživatele → **Rackspace API Key → Show** (nebo *Generate*) a klíč zkopírujte.

API klíč je dlouhodobé tajemství; mějte ho jen v acme. Odstraněním uživatele nebo resetem klíče acme přístup ztratí.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| User name | `acme` |
| API key | API klíč uživatele |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 300 (méně Rackspace nepřijme; pokročilé) |
| Identity address | `https://identity.api.rackspacecloud.com/v2.0` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše domény; nic nemění.
- Po objednávce: Cloud Control Panel → **Networking → Cloud DNS →** doména: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @dns1.stabletransit.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatné uživatelské jméno nebo API klíč, nebo je uživatel vypnutý. |
| `403` u POST/DELETE | Role DNS uživatele dovoluje jen čtení - dejte mu roli DNS **Admin**. |
| Chybí endpoint `rax:dns` | Účet nemá Cloud DNS (např. účet jen s dedikovanými servery). |
| Úloha `ERROR` | acme ukáže zprávu Rackspace - často TTL pod 300 nebo jméno mimo doménu. |
