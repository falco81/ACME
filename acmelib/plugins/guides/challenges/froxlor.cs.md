# froxlor - nastavení pro acme

acme prokazuje jména přes DNS-01 v DNS serveru froxlor: přes froxlor API (`api.php`, JSON přes HTTPS, basic autentizace klíčem a secretem API) přidá do zóny domény záznam TXT `_acme-challenge.JMÉNO` (`DomainZones.add`) a poté smaže jen své vlastní záznamy (`DomainZones.delete`). froxlor zapisuje zóny cronem (`REBUILD_DNS`), takže záznam se na jmenné servery dostane až po dalším běhu cronu - acme čeká, dokud ho nemají všechny. Pro froxlor 2.x s externím API.

## Co potřebujete

- Server froxlor, který obsluhuje DNS domény (DNS server ve froxloru zapnutý, *DNS* u domény zapnuté).
- Odchozí HTTPS z acme na panel froxlor (port 443).
- Pravidelně běžící cron froxloru (ten zónu zveřejní).

## Nastavení froxloru

1. Jako admin: **Settings → System settings → Enable external API usage** - zapnout.
2. Přihlaste se jako **zákazník**, kterému doména patří (nebo jako admin - klíč admina vidí všechny domény; klíč zákazníka je menší oprávnění).
3. **(vaše jméno) → API keys → Create** (nabídka vpravo nahoře → *API keys*).
4. Upravte nový klíč: omezte **Allowed from** na veřejnou adresu acme a případně nastavte platnost.
5. Zkopírujte **API key** a **secret**.
6. Ověřte, že zákazník smí upravovat DNS (*DNS editor* povolený zákazníkovi i doméně).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| froxlor address | Panel, např. `froxlor.example.com` nebo `https://…/`; acme tam volá `api.php` |
| API key | Klíč |
| API secret | Jeho secret |
| Zone | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší hlavní doména s DNS, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| Check the server's certificate | (pokročilé) nechte zapnuté |

## Kontrola

- **Test** v acme vypíše domény - nebo při vyplněné *Zone* spočítá vlastní záznamy zóny. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "$KEY:$SECRET" -H 'Content-Type: application/json' \
    -d '{"command":"DomainZones.listing","params":{"domainname":"example.com"}}' \
    https://froxlor.example.com/api.php
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` / API není zapnuté | Zapněte *Enable external API usage* v systémovém nastavení. |
| `401` | Špatný klíč/secret, nebo adresa acme není v *Allowed from* klíče. |
| Zóna nemá DNS | Zapněte DNS pro doménu (a DNS editor pro zákazníka). |
| Záznam se objevuje dlouho | Cron froxloru ještě neběžel; spouštějte ho častěji nebo zvyšte *Wait at least (seconds)*. |
