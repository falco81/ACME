# Joker.com - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně obsluhované jmennými servery Joker.com, přes **DMAPI** (`https://dmapi.joker.com/request/...`). Přihlásí se (`login`, dostane Auth-SID), vypíše zóny (`dns-zone-list`), načte zónu (`dns-zone-get`), přidá svůj jeden řádek (`_acme-challenge.www TXT 0 "<hodnota>" 300`) nebo odebere jen svůj TXT řádek a zónu zapíše zpět (`dns-zone-put`).

**`dns-zone-put` nahradí celou zónu.** acme zapíše všechny ostatní řádky přesně tak, jak je načetl, mění vždy jen jednu zónu najednou, nikdy nezapíše zónu načtenou prázdnou a po každém zápisu zónu znovu přečte. Neupravujte zónu ručně ve chvíli, kdy se objednává certifikát.

## Co potřebujete

- Domény, jejichž DNS obsluhuje Joker.com (jmenné servery Jokeru, „Joker.com DNS“).
- HTTPS (TCP 443) z acme na `dmapi.joker.com` (nebo `dmapi.ote.joker.com` pro testovací systém OT&E).
- Účet Joker.com s přístupem k DMAPI (DMAPI je dokumentováno pro účty resellerů - u běžného zákaznického účtu si to ověřte u Joker.com).

## Nastavení Joker.com

1. Přihlaste se na `joker.com`.
2. Otevřete **My Profile → Manage Joker.com API access keys**.
3. Vytvořte nový API klíč s oprávněním **„modifications only“** (stačí ke čtení i zápisu zón; klíč jen pro čtení zónu nezapíše).
4. Klíč zkopírujte - mějte ho jen v acme.

Alternativa: přihlášení uživatelským jménem a heslem účtu (v acme zvolte *user name and password*). Klíč je lepší: dá se zrušit samostatně.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Sign in with | `a DMAPI API key` |
| API key | klíč z kroku 3 |
| User name / Password | jen při *user name and password* |
| Zone | prázdné (vybráno ze seznamu Jokeru nebo dohledáno přes SOA), nebo zóna |
| TTL (s) | 300 (méně DMAPI nepřijme; pokročilé) |
| API | `dmapi.joker.com`; OT&E jen pro testy (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se; s vyplněnou *Zone* zónu načte a spočítá záznamy, jinak vypíše zóny. Nic nezapisuje.
- Po objednávce: Joker.com → **My Domains →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí; ostatní záznamy zůstanou beze změny.

```sh
dig +short TXT _acme-challenge.www.example.com @a.ns.joker.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení odmítnuto / `Error: authorization` | Špatný nebo zrušený klíč; vytvořte nový. |
| Zápis s klíčem odmítnut | Klíč je jen pro čtení - vytvořte klíč s „modifications only“. |
| Zóna není v `dns-zone-list` | Doména používá jiné jmenné servery nebo je v jiném účtu Joker.com. |
| Chyba TTL | Nechte *TTL (s)* na 300 nebo víc. |
| Ruční změna zmizela | Vznikla ve chvíli, kdy acme zónu zapisoval (čtení-úprava-zápis); udělejte ji znovu a během obnov zónu neupravujte. |
