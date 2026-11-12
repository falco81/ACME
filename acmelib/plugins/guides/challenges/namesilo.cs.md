# NameSilo - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u NameSilo, přes API NameSilo (`https://www.namesilo.com/api/...`, požadavky GET s klíčem v query): `listDomains`, `dnsListRecords`, `dnsAddRecord` (jeden TXT záznam pro každou hodnotu) a `dnsDeleteRecord` podle id záznamu. Ostatní hodnoty na stejném jménu zůstanou.

NameSilo nepřijme TTL pod **3600** a jeho jmenným serverům často trvá **15 minut i déle**, než změnu zveřejní - acme na ně čeká, než se zeptá CA.

## Co potřebujete

- Doménu u NameSilo, která používá jmenné servery NameSilo.
- HTTPS (TCP 443) z acme na `www.namesilo.com`.
- Nejlépe: veřejnou IP adresu, ze které acme volá, pro omezení klíče.

## Nastavení NameSilo

1. Přihlaste se na `namesilo.com`.
2. Otevřete **Account → API Manager** (`https://www.namesilo.com/account/api-manager`).
3. Vygenerujte nový API klíč:
   - Volbu *read-only* nechte **vypnutou** (acme musí záznamy přidávat a mazat).
   - Nabízí-li to stránka, omezte klíč na veřejnou IP adresu acme.
4. Klíč zkopírujte.

**Pozor:** klíč NameSilo umí vše, co API (včetně operací s doménami) - omezte ho na IP a mějte ho jen v acme.

Volitelná kontrola:

```sh
curl 'https://www.namesilo.com/api/listDomains?version=1&type=json&key=KLIC'
# ..."code":300,"detail":"success"...
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key | klíč |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 3600 (méně NameSilo nepřijme; pokročilé) |
| API address | `https://www.namesilo.com/api` (pokročilé) |
| Wait until it is seen by | nechte *the zone's own name servers* (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény účtu; nic nemění.
- Po objednávce: **Domain Manager →** doména → **Manage DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| kód 110 | Klíč je špatný, nebo volání přichází z adresy, pro kterou klíč není povolen. |
| kód 200 | Doména není v tomto účtu. |
| kód 280 | NameSilo hodnotu nepřijalo (např. TTL pod 3600). |
| Objednávka vyprší | Jmenné servery NameSilo jsou pomalé: prodlužte čekací dobu ACME vydavatele (20-30 minut). |
