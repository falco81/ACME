# GleSYS - nastavení pro acme

acme prokazuje jména přes DNS-01 u GleSYS (Švédsko): přes GleSYS API (`api.glesys.com`, funkce `domain/*`) přidá záznam TXT `_acme-challenge.JMÉNO` (`domain/addrecord`) a poté smaže jen svůj vlastní záznam (`domain/deleterecord`). Přihlašuje se názvem projektu a klíčem API.

## Co potřebujete

- Doménu v projektu GleSYS Cloud, používající DNS GleSYS.
- Odchozí HTTPS z acme na `api.glesys.com` (port 443).

## Nastavení GleSYS

1. GleSYS Cloud → projekt → **API keys → Create API key**.
2. **Permissions**: v části *domain* povolte jen `list`, `listrecords`, `addrecord` a `deleterecord`. Nic jiného.
3. **Allowed hosts**: veřejná adresa acme.
4. Zkopírujte klíč a poznamenejte si název projektu (`CL12345`) - je to uživatelské jméno pro API.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Project | Název projektu, např. `CL12345` |
| API key | Klíč API |
| Domain | např. `example.se`; prázdné = nejdelší doména projektu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` (nejméně 60) |
| API address | (pokročilé) Výchozí `https://api.glesys.com` |

## Kontrola

- **Test** v acme vypíše domény projektu (`domain/list`). Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "CL12345:$KEY" -X POST https://api.glesys.com/domain/list
  curl -s -u "CL12345:$KEY" -X POST -d domainname=example.se https://api.glesys.com/domain/listrecords
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / přístup odepřen | Špatný projekt nebo klíč, nebo adresa acme není v *Allowed hosts*. |
| Pro funkci chybí oprávnění | Přidejte chybějící oprávnění `domain` (list, listrecords, addrecord, deleterecord). |
| Doména není v seznamu | Je v jiném projektu, nebo její DNS není u GleSYS. |
