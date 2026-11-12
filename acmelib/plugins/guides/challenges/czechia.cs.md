# CZECHIA.COM (ZONER) - nastavení pro acme

acme prokazuje jména přes DNS-01 u CZECHIA.COM (registrátor a DNS společnosti ZONER): přes jeho REST API (`api.czechia.com`) přidá záznam TXT `_acme-challenge.JMÉNO` (`POST /api/DNS/{domain}/TXT`, publikováno ihned) a poté odebere přesně svou hodnotu. Ostatní hodnoty u jména zůstanou.

## Co potřebujete

- Doménu s DNS hostovaným u CZECHIA.COM.
- Přístup do administrace CZECHIA.COM pro vytvoření tokenu REST API.
- Odchozí HTTPS z acme na `api.czechia.com` (port 443).

## Nastavení CZECHIA.COM

1. Přihlaste se do administrace CZECHIA.COM → **váš účet → REST API** (popisuje to stránka nápovědy *Aktivace REST API* na napoveda.czechia.com).
2. Vytvořte token typu **ACME** - smí měnit jen záznamy TXT v DNS a funguje z libovolné adresy. Je to minimální a doporučený typ.
3. Token s **plným přístupem** funguje také, ale jen z IP adres, které tam povolíte - pak přidejte veřejnou adresu acme.
4. Zkopírujte token.

S tokenem ACME může být výpis domén odmítnut - to je v pořádku: acme najde zónu podle SOA, nebo vyplňte *Domain*.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token |
| Domain | např. `example.cz`; prázdné = najde se podle SOA |
| TTL (s) | (pokročilé) Výchozí `300`; 120 až 172800 |
| API address | (pokročilé) Výchozí `https://api.czechia.com/api` |

## Kontrola

- **Test** v acme: s vyplněnou *Domain* přečte zónu a spočítá její záznamy TXT; bez ní vypíše domény účtu (token ACME to smět nemusí - Test pak řekne, ať doménu vyplníte). Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "authorizationToken: $TOKEN" https://api.czechia.com/api/DNS/example.cz
  dig +short TXT _acme-challenge.example.cz @<jeden ze jmenných serverů domény>
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `no API token is set` | Vyplňte *API token*. |
| `CZECHIA.COM has no DNS zone ... for this token` | Doména je v jiném účtu nebo její DNS není u CZECHIA.COM; zkontrolujte *Domain*. |
| `401` / `403` s tokenem s plným přístupem | Adresa acme není pro token povolená - povolte ji, nebo použijte token ACME. |
| TTL odmítnuto | Držte *TTL (s)* mezi 120 a 172800. |
