# DreamHost - nastavení pro acme

acme prokazuje jména přes DNS-01 u DreamHost: přes DreamHost API (`api.dreamhost.com`, příkazy `dns-*`) přidá záznam TXT `_acme-challenge.JMÉNO` (`dns-add_record`) a poté odebere přesně tuto hodnotu (`dns-remove_record`). Ostatní hodnoty u jména zůstanou. TTL nastavuje DreamHost sám.

## Co potřebujete

- Doménu, jejíž DNS je hostováno u DreamHost.
- Odchozí HTTPS z acme na `api.dreamhost.com` (port 443).
- Jmenné servery DreamHost mohou zveřejnění změny trvat několik minut - počítejte s pomalejšími běhy.

## Nastavení DreamHost

1. Přihlaste se na `panel.dreamhost.com` → **Advanced → API** (`https://panel.dreamhost.com/?tree=home.api`).
2. Vygenerujte nový klíč API s komentářem např. `acme`.
3. Z funkcí, které smí používat, zaškrtněte jen **All dns functions** (`dns-list_records`, `dns-add_record`, `dns-remove_record`) - nic jiného.
4. Zkopírujte klíč.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| API address | (pokročilé) Výchozí `https://api.dreamhost.com/` |
| Wait at least (seconds) | (pokročilé) Pokud CA záznam často nevidí, zvažte prodlevu několika minut |

## Kontrola

- **Test** v acme vypíše zóny DNS účtu (`dns-list_records`). Nic nemění.
- Pomocí curl:

  ```sh
  curl -s "https://api.dreamhost.com/?key=$KEY&format=json&cmd=dns-list_records" | head
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `invalid_api_key` | Špatný klíč, nebo byl smazán. |
| `this_key_cannot_access_this_cmd` | Klíč nemá funkce dns - vygenerujte klíč s *All dns functions*. |
| Doména se nenajde | Její DNS není hostováno u DreamHost, nebo je v jiném účtu. |
| CA záznam nevidí | DreamHost zveřejňuje pomalu: zvyšte *Wait at least (seconds)*. |
