# Webglobe - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **Webglobe** (webglobe.cz / webglobe.sk, skupina Yegon), přes Webglobe API (`https://api.webglobe.com`). Přihlásí se (`POST /auth/login` s loginem a API klíčem, dostane JWT), najde doménu (`GET /domains`, případně podle jména), zapíše jeden TXT záznam (`POST /{domainId}/dns`) a uloží si jeho id; úklid smaže jen toto id (`DELETE /{domainId}/dns/{id}`), a jen dokud je to stále TXT záznam s hodnotou acme na tomto jménu - nikdy jiný záznam.

## Co potřebujete

- Doménu u Webglobe, která používá DNS Webglobe.
- HTTPS (TCP 443) z acme na `api.webglobe.com`.
- **Veřejnou IP adresu** (nebo síť), ze které acme volá - z jiné adresy Webglobe API klíč odmítne, stejně jako klíč bez povolené adresy.

## Nastavení Webglobe

1. Nejlépe: **podúčet** pro acme, který vidí jen domény, které acme potřebuje - administrace Webglobe → **Můj účet → Uživatelé** (*My account → Users*) → přidejte uživatele a dejte mu přístup k těmto doménám.
2. Přihlaste se tímto loginem, pak **Můj účet → API klíče** (*My account → API keys*) → nový klíč:
   - povolte veřejnou IP adresu (nebo síť), ze které acme volá;
   - klíč zkopírujte - zobrazí se **jen jednou**.
3. API klíč použijte i tehdy, má-li účet **dvoufázové přihlášení** (SMS, OTP, kódy e-mailem): heslem se pak stroj přihlásit nemůže.

Nejste-li si jisti veřejnou adresou acme:

```sh
curl -4 https://ifconfig.me
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Login | e-mail loginu, např. `you@example.cz` |
| Sign in with | `an API key` |
| API key | klíč z kroku 2 |
| Password | jen při *the password* (účet bez dvoufázového přihlášení) |
| Domain | prázdné (nejdelší doména, do které jméno patří), nebo doména, např. `example.cz` |
| Domain ID | jen pokud nejde načíst seznam domén - číselné ID domény (pokročilé) |
| TTL (s) | 300 (pokročilé) |
| API / API address | `api.webglobe.com`; staging jen pro testy (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se; s vyplněnou *Domain* spočítá DNS záznamy domény, jinak vypíše domény. Nic nemění.
- Po objednávce: administrace Webglobe → doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba 5 (špatné přihlášení) | Špatný login nebo API klíč. |
| Klíč odmítnut | acme volá z adresy, která pro klíč není povolená - přidejte ji v Můj účet → API klíče. |
| Kódy 1034 / 24 / 1382 | Dvoufázové přihlášení s heslem - použijte API klíč. |
| Chyba 51 | Účet je pozastavený. |
| Chyba 3 „Access to requested module is denied“ | Podúčet nemá přístup k doméně nebo jejímu DNS. |
| Doména nenalezena | Vyplňte *Domain* (nebo *Domain ID*); podúčet ji možná nevidí. |
