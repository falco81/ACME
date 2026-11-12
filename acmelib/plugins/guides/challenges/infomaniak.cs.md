# Infomaniak - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně hostované u Infomaniaku (Švýcarsko). Používá Infomaniak API v2 (`https://api.infomaniak.com/2/zones/...`) s API tokenem typu bearer: zónu najde dotazem na `/2/zones/{jméno}/exists` jméno po jménu, pro každou hodnotu přidá jeden TXT záznam na `_acme-challenge.JMÉNO` a potom tento záznam smaže podle jeho id. Ostatní hodnoty na stejném jménu zůstanou.

## Co potřebujete

- Doménu, jejíž DNS zóna je u Infomaniaku (jmenné servery Infomaniaku).
- HTTPS (TCP 443) z acme na `api.infomaniak.com`.
- Účet Infomaniak, který smí doménu spravovat.

## Nastavení Infomaniaku

1. Přihlaste se na `manager.infomaniak.com`.
2. Otevřete menu profilu → **Developer** → **API tokens** → **Create a token**.
3. Pojmenujte ho např. `acme` a zvolte scopes:
   - **`domain:read`** a **`dns:write`** - nic dalšího není potřeba.
   - (Starší tokeny místo toho používaly scopes `accounts` a `domain`.)
4. Zvolte platnost (neomezený token nemusíte obnovovat; omezený je třeba v acme vyměnit před vypršením).
5. Zkopírujte token - zobrazí se jen jednou.

Volitelná kontrola ze shellu:

```sh
curl -H 'Authorization: Bearer TOKEN' https://api.infomaniak.com/2/zones/example.ch/exists
# {"result":"success","data":true}
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API token | token z kroku 5 |
| Zone | zóna, např. `example.ch` - doporučeno, aby ji *Test* mohl ověřit; prázdné: acme se ptá jméno po jménu |
| TTL (s) | 300 (méně Infomaniak nepřijme; pokročilé) |
| API address | `https://api.infomaniak.com` (pokročilé, neměňte) |

## Ověření

- V acme stiskněte **Test**: s vyplněnou *Zone* se zeptá Infomaniaku, zda token zónu vidí. Bez zóny jen řekne, že token je zadán (API vypisuje produkty, ne zóny).
- Po objednávce v Manageru: **Domains →** doména → **DNS zone**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.ch @ns11.infomaniak.ch
```

## Časté problémy

| Problém | Řešení |
|---|---|
| „Infomaniak said no ...“ (chyba oprávnění) | Token nemá `dns:write` / `domain:read` - vytvořte nový s těmito scopes. |
| „Infomaniak has no zone for ... that this token may see“ | Doména je v jiném účtu či organizaci Infomaniak, nebo její DNS není u Infomaniaku. |
| TTL odmítnuto | Nechte *TTL (s)* na 300 nebo víc. |
| `401` po několika měsících | Token vypršel - vytvořte nový a vložte ho. |
