# DNS Made Easy - nastavení pro acme

acme prokazuje jména přes DNS-01 u DNS Made Easy: přes jeho REST API V2.0 (`api.dnsmadeeasy.com`), kde je každý požadavek podepsán HMAC-SHA1 aktuálního data, přidá do spravované domény záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam.

## Co potřebujete

- Doménu jako **managed domain** u DNS Made Easy.
- Klíč API a tajný klíč uživatele s přístupem k doméně.
- Odchozí HTTPS z acme na `api.dnsmadeeasy.com` (port 443) - nebo `api.sandbox.dnsmadeeasy.com` pro sandbox.
- **Správný čas na stroji s acme** - datum požadavku se kontroluje.

## Nastavení DNS Made Easy

1. Přihlaste se do ovládacího panelu DNS Made Easy.
2. Nejlépe: vytvořte pro acme samostatného uživatele (**Config → Users**, má-li váš účet správu uživatelů) s přístupem jen k doménám, které smí acme měnit.
3. Přihlaste se jako tento uživatel → **Account Information** (Config → Account Information): zobrazí se **API key** a **secret key**; jsou-li prázdné, vygenerujte je.
4. Omezuje-li váš účet přístup k API podle IP, povolte veřejnou adresu acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč API |
| Secret key | Tajný klíč |
| Domain | např. `example.com`; prázdné = nejdelší spravovaná doména, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` (nejméně 30) |
| API address | (pokročilé) Výchozí `https://api.dnsmadeeasy.com/V2.0`; pro sandbox `https://api.sandbox.dnsmadeeasy.com/V2.0` |

## Kontrola

- **Test** v acme vypíše spravované domény. Nic nemění.
- Po běhu se zeptejte jednoho ze jmenných serverů domény:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<jeden z těchto serverů>
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` / neplatné datum požadavku | Nesedí čas stroje s acme - zkontrolujte NTP (`timedatectl`). |
| `403` / neplatný klíč API | Špatný klíč nebo secret, nebo klíče ze sandboxu použité proti produkci. |
| Doména není v seznamu | Uživatel k ní nemá přístup; nebo vyplňte přesně *Domain*. |
