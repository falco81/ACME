# easyDNS - nastavení pro acme

acme prokazuje jména přes DNS-01 u easyDNS: přes REST API easyDNS (`rest.easydns.net`) přidá záznam TXT `_acme-challenge.JMÉNO` (`PUT /zones/records/add/{domain}/TXT`) a poté smaže jen záznamy s jeho hodnotou. API neumí vypsat domény bez jména uživatele, takže doména je ta, kterou vyplníte, nebo se najde podle SOA.

## Co potřebujete

- Doménu s DNS u easyDNS, v tarifu s přístupem k REST API.
- API token a API key z ovládacího panelu easyDNS.
- Odchozí HTTPS z acme na `rest.easydns.net` (port 443) - nebo `sandbox.rest.easydns.net` pro sandbox.
- TTL mezi **300 a 86400** - kratší easyDNS nepřijme.

## Nastavení easyDNS

1. Přihlaste se do ovládacího panelu easyDNS.
2. Najděte stránku s přihlašovacími údaji REST API (**API** / *REST API* v nastavení účtu; easyDNS může muset přístup k API pro účet zapnout - chybí-li stránka, zeptejte se podpory).
3. Vytvořte nebo zobrazte **API token** a **API key** a oba zkopírujte.
4. Umožňuje-li panel omezit přístup k API podle IP, povolte veřejnou adresu acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | API token |
| API key | API key |
| Domain | např. `example.com`; prázdné = najde se podle SOA |
| User name | (pokročilé) Vaše uživatelské jméno easyDNS - Test pak vypíše jeho domény |
| API | (pokročilé) `easyDNS (rest.easydns.net)` nebo sandbox |
| TTL (s) | (pokročilé) Výchozí `300`; 300 až 86400 |

## Kontrola

- **Test** v acme přečte záznamy vyplněné *Domain*, nebo s *User name* vypíše domény uživatele. Bez obojího vás vyzve, ať jedno vyplníte. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "$TOKEN:$KEY" 'https://rest.easydns.net/zones/records/all/example.com?format=json'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `easyDNS: set the domain (or the user name) for Test …` | Vyplňte *Domain* nebo *User name*. |
| `401` / `403` | Špatný token/klíč, údaje ze sandboxu proti produkci, nebo přístup k API pro účet není zapnutý. |
| TTL odmítnuto | Držte *TTL (s)* mezi 300 a 86400. |
| Doména se podle SOA nenajde | Vyplňte *Domain* výslovně. |
