# INWX - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně, jejíž DNS je u INWX. Používá JSON-RPC API INWX (DomRobot, `https://api.domrobot.com/jsonrpc/`): přihlásí se přes `account.login` (a `account.unlock` s kódem TOTP, má-li účet dvoufázové přihlášení), vypíše domény (`nameserver.list`), pro každou hodnotu přidá jeden TXT záznam (`nameserver.createRecord`) a ten pak smaže podle id (`nameserver.deleteRecord`). Ostatní hodnoty na stejném jménu zůstanou.

## Co potřebujete

- Doménu u INWX, která používá jmenné servery INWX.
- HTTPS (TCP 443) z acme na `api.domrobot.com` (nebo `api.ote.domrobot.com` pro testovací systém INWX).
- Nejlépe: dalšího uživatele INWX jen pro acme, **bez dvoufázového přihlášení**.

## Nastavení INWX

1. Přihlaste se na `www.inwx.com` hlavním účtem.
2. Jděte do **Account → Account access** (další uživatelé / podúčty) a vytvořte nového uživatele pro acme.
3. Dejte mu **jen práva k DNS** (správa nameserverů / DNS); žádná práva k převodům domén, kontaktům ani fakturaci.
4. Dvoufázové přihlášení u tohoto uživatele nechte **vypnuté**. Musíte-li použít účet s 2FA, uschovejte **tajný klíč v base32** zobrazený při zapínání 2FA (text pod QR kódem) - acme z něj počítá šestimístné kódy. Jednorázový šestimístný kód k ničemu není.
5. Nastavte dlouhé náhodné heslo.

**Pozor:** tajný klíč 2FA má stejnou moc jako heslo - zadávejte ho jen u účtu omezeného na DNS.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| User name | další uživatel INWX |
| Password | jeho heslo |
| Two-factor secret | prázdné, nebo klíč 2FA v base32 (ne šestimístný kód) |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 300 (méně INWX nepřijme; pokročilé) |
| Endpoint | `api.domrobot.com`; `api.ote.domrobot.com` jen pro testovací systém INWX (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se, vypíše domény a odhlásí se; žádný záznam nemění.
- Po objednávce: INWX → **Domains → Nameserver (DNS)** → doména: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @ns.inwx.de
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Kód 2200 / „authentication error“ | Špatný uživatel či heslo, nebo je uživatel po mnoha pokusech zablokován (počkejte a zkuste znovu). |
| Přihlášení chce TAN / druhý faktor | Zadejte *Two-factor secret*, nebo použijte uživatele bez 2FA. |
| Špatný kód 2FA, ačkoli klíč je správný | Hodiny acme jdou špatně - TOTP potřebuje čas přesný zhruba na 30 s (zkontrolujte NTP). |
| Kód 2303 „object does not exist“ | Doména není v tomto účtu nebo nepoužívá jmenné servery INWX. |
| Chyba oprávnění u `createRecord` | Další uživatel nemá k doméně práva DNS. |
