# Subreg.cz - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně, jejíž DNS je u **Subreg.cz** (nebo **Gransy**, který běží na stejném systému), přes SOAP API Subregu (`https://soap.subreg.cz/cmd.php`). Přihlásí se (`Login`), vypíše domény (`Domains_List`), načte zónu (`Get_DNS_Zone`), pro každou hodnotu přidá jeden TXT záznam (`Add_DNS_Record`) a smaže jen záznamy s naší hodnotou (`Delete_DNS_Record`). Doménu v DNS Subregu, která tam není registrovaná, najde dotazem `Get_DNS_Zone` jméno po jménu.

## Co potřebujete

- Doménu, která používá DNS Subregu (nebo Gransy).
- HTTPS (TCP 443) z acme na `soap.subreg.cz` (nebo adresu API Gransy).
- **Veřejnou IP adresu**, ze které acme volá - API odpovídá jen povoleným adresám.

## Nastavení Subregu

1. Přihlaste se do administrace Subregu (`subreg.cz`).
2. Jděte do **Nastavení → API** (anglické UI: *Settings → API*).
3. Vytvořte API uživatele (nebo použijte vlastní API login účtu) a nastavte mu API heslo.
4. Do povolených adres přidejte **IP adresu**, ze které acme volá.
5. Umožňuje-li administrace omezit práva API uživatele, nechte mu jen funkce DNS.

Nejste-li si jisti veřejnou adresou acme:

```sh
curl -4 https://ifconfig.me
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API login | login API uživatele |
| API password | jeho heslo |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména, např. `example.cz` |
| TTL (s) | 120 (pokročilé) |
| API address | `https://soap.subreg.cz/cmd.php`; pro Gransy nebo testovací systém jejich adresa (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše domény; nic nemění.
- Po objednávce: administrace Subregu → doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.cz @ns.subreg.cz
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení odmítnuto / „Subreg said: …“ | Špatný login nebo heslo, nebo IP adresa acme není povolena v Nastavení → API. |
| Doména nenalezena | Doména používá jiné jmenné servery nebo je v jiném účtu Subregu. |
| Účet Gransy se nepřihlásí | Nastavte *API address* na endpoint Gransy. |
