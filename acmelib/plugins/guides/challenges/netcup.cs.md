# netcup - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u netcupu, přes **CCP DNS API** (JSON, `https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON`). Přihlásí se (`login` se zákaznickým číslem, API klíčem a API heslem), ověří zónu (`infoDnsZone`), načte její záznamy (`infoDnsRecords`), přidá TXT záznam nebo smaže přesně ten náš (`updateDnsRecords`) a odhlásí se (`logout`). Ostatní hodnoty na stejném jménu zůstanou.

netcup nemá volání, které vypíše zóny: bez *Domain* se acme ptá `infoDnsZone` na jméno a každé jméno nad ním. Jmenným serverům netcupu obvykle trvá **5-15 minut**, než změnu zveřejní; TTL je dané zónou, ne záznamem.

## Co potřebujete

- Doménu u netcupu, která používá jmenné servery netcupu (`root-dns.netcup.net` …).
- HTTPS (TCP 443) z acme na `ccp.netcup.net`.
- Své **zákaznické číslo** u netcupu.

## Nastavení netcupu

1. Přihlaste se do **Customer Control Panel (CCP)** na `www.customercontrolpanel.de`.
2. Jděte do **Master Data → API** (německé UI: *Stammdaten → API*).
3. Je-li třeba, přijměte podmínky API.
4. Vytvořte **API key** (**Create API key**) a **API password** (**Generate API password**). API heslo se zobrazí jen jednou.

**Pozor:** API klíč a heslo netcupu dávají přístup k DNS všech domén zákaznického účtu - omezení na doménu neexistuje. Mějte je jen v acme.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Customer number | vaše zákaznické číslo u netcupu, např. `123456` |
| API key | API klíč |
| API password | API heslo |
| Domain | doména (doporučeno: méně volání a *Test* ji ověří); prázdné: hledá se jméno po jménu |
| Wait until it is seen by | nechte *the zone's own name servers* (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se; s vyplněnou *Domain* se zeptá `infoDnsZone` a ukáže TTL zóny. Pak se odhlásí. Nic nemění.
- Po objednávce: CCP → **Domains →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @root-dns.netcup.net
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení odmítnuto (status „error“) | Špatné zákaznické číslo, API klíč nebo API heslo (API heslo není heslo do CCP). |
| „Domain not found“ | Doména používá jiné jmenné servery nebo patří jinému zákaznickému účtu. |
| statuscode 5029 „no records“ | Prázdná zóna - nejde o chybu. |
| Objednávka vyprší | Jmenné servery netcupu jsou pomalé: dejte ACME vydavateli 15-20 minut čekací doby. |
