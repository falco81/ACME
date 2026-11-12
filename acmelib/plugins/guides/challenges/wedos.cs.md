# WEDOS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně ve **WEDOS DNS**, přes WAPI (`https://api.wedos.com/wapi/json`, JSON). Každé volání je ověřeno hodnotou `sha1(login + sha1(WAPI heslo) + hodina v Europe/Prague)`. acme ověří přihlášení (`ping`), vypíše domény (`dns-domains-list`), načte řádky (`dns-rows-list`), pro každou hodnotu přidá jeden TXT řádek (`dns-row-add`) nebo smaže jen svůj (`dns-row-delete`) a změnu zveřejní přes `dns-domain-commit`. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu ve WEDOS DNS jako **primární, aktivní** doménu (sekundární je odmítnuta).
- HTTPS (TCP 443) z acme na `api.wedos.com`.
- **Veřejnou IP adresu**, ze které acme volá - WAPI odpovídá jen povoleným adresám.
- **Správné hodiny** acme (NTP) - ověření obsahuje aktuální hodinu.

## Nastavení WEDOS

1. Přihlaste se do zákaznické administrace WEDOS (`client.wedos.com`).
2. **Zákazník → WAPI rozhraní** (anglické UI: *Customer → WAPI interface*).
3. Není-li WAPI aktivní, objednejte ho (je zdarma).
4. Nastavte **WAPI heslo** - vlastní, ne heslo k účtu.
5. Zvolte protokol **JSON**.
6. Do povolených adres přidejte **IP adresu**, ze které acme volá.

**Pozor:** WAPI dává přístup k celému zákaznickému účtu (domény, objednávky), nejen k DNS. Více než 10 neplatných požadavků (špatné ověření, nepovolená adresa) adresu na čas zablokuje - acme pak volání WAPI pozastaví, místo aby zkoušel znovu.

Nejste-li si jisti veřejnou adresou acme:

```sh
curl -4 https://ifconfig.me
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Login | e-mail, kterým se přihlašujete do zákaznické administrace |
| WAPI password | WAPI heslo z kroku 4 |
| Domain | prázdné (nejdelší doména ve WEDOS DNS, do které jméno patří), nebo doména, např. `example.cz` |
| TTL (s) | 300 (méně WEDOS nepřijme; pokročilé) |

## Ověření

- V acme stiskněte **Test**: pošle `ping` a vypíše domény; nic nemění.
- Po objednávce: administrace → **DNS →** doména: TXT řádek `_acme-challenge` se objeví a zase zmizí. Jmenné servery WEDOS potřebují po commitu několik minut.

```sh
dig +short TXT _acme-challenge.www.example.cz @ns.wedos.net
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Kódy 2050-2053 (ověření) | Špatný login nebo WAPI heslo, nepovolená IP adresa, nebo hodiny acme jdou o hodinu jinak (časové pásmo / NTP). |
| Adresa na čas zablokovaná | Příliš mnoho neplatných požadavků - odstraňte příčinu a počkejte; WAPI se odblokuje samo. |
| Kód 2318 | Doména je ve WEDOS DNS sekundární - zapisovat lze jen do primárních domén. |
| CA záznam ještě nevidí | Nechte *Wait until it is seen by* na jmenných serverech zóny; WEDOS potřebuje několik minut. |
