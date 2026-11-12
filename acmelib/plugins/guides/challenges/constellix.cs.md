# Constellix - nastavení pro acme

acme prokazuje jména přes DNS-01 u Constellix (DigiCert): přes Constellix DNS API v1 (`api.dns.constellix.com`) přidá svou hodnotu do záznamu TXT `_acme-challenge.JMÉNO` (Constellix drží všechny hodnoty jména v jednom záznamu) a při úklidu záznam zapíše zpět bez své hodnoty - nebo ho smaže, byla-li jeho hodnota poslední.

## Co potřebujete

- Doménu hostovanou v Constellix DNS.
- Klíč API a tajný klíč (secret key) účtu.
- Odchozí HTTPS z acme na `api.dns.constellix.com` (port 443).
- **Správný čas na stroji s acme**: každý požadavek nese token vytvořený z aktuálního času.

## Nastavení Constellix

1. Přihlaste se do Constellix → profil účtu → **API keys** (podle verze rozhraní Edit My Profile / API Access).
2. Vygenerujte (nebo zobrazte) **API key** a **secret key**. Zkopírujte oba.
3. Má-li účet více uživatelů, vytvořte pro acme samostatného uživatele s právy jen na domény DNS, které smí acme měnit, a použijte jeho klíče - klíče jednají s právy uživatele.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč API |
| Secret key | Tajný klíč |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| API address | (pokročilé) Výchozí `https://api.dns.constellix.com` |

## Kontrola

- **Test** v acme podepíše požadavek a vypíše domény (`/v1/domains`). Nic nemění.
- Po běhu se zeptejte jednoho ze jmenných serverů domény:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<jeden z těchto serverů>
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` u každého požadavku | Špatný klíč nebo secret, nebo nesedí čas stroje s acme - zkontrolujte NTP (`timedatectl`). |
| Doména není v seznamu | Klíče patří uživateli bez práv na ni; vyplňte přesně *Domain*. |
| CA záznam nevidí | Zvyšte *Wait at least (seconds)*. |
