# Netim - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Netimu, přes **REST API 1.0** Netimu (`https://rest.netim.com/1.0`) s **resellerským účtem**. Otevře relaci (`POST /session/` s basic autentizací), vypíše domény (`GET /domains/*`), načte zónu (`GET /domain/{domain}/zone/`), pro každou hodnotu přidá jeden TXT záznam (`POST` na stejnou cestu) a smaže přesně tento záznam (`DELETE` se subdoménou + typem + hodnotou). Změna vrací operaci; dokud je *Pending*, acme sleduje `GET /operation/{ID_OPE}`, dokud není *Done*. Relace se na konci každé práce zavře (`DELETE /session/`).

## Co potřebujete

- **Resellerský účet Netim** (REST API je pro resellery), ve kterém je doména se jmennými servery Netimu.
- HTTPS (TCP 443) z acme na `rest.netim.com` (testovací systém OT&E je `oterest.netim.com`, prosté HTTP).
- Netim ve výchozím stavu dovolí **10 relací najednou** - acme používá jednu na každou práci a zavírá ji.

## Nastavení Netimu

1. Přihlaste se do resellerského rozhraní Netimu.
2. Otevřete sekci **API – DAS – OTE**.
3. Nastavte (nebo zjistěte) tam **API heslo** - heslo DAS. **Není** to přihlašovací heslo účtu.
4. Produkce a OT&E mají **různá** API hesla; pro skutečné certifikáty použijte produkční.
5. Poznamenejte si své **reseller ID** (např. `NETIM1234`).

**Pozor:** API heslo dává API plný přístup k resellerskému účtu (domény, kontakty, objednávky) - Netim nemá klíč jen pro DNS. Mějte ho jen v acme.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Reseller ID | vaše reseller ID |
| API password | heslo DAS ze sekce *API – DAS – OTE* |
| Domain | prázdné (vybráno ze seznamu Netimu nebo dohledáno), nebo doména |
| TTL (s) | výchozí 3600 (pokročilé) |
| API | `rest.netim.com (production)`; OT&E jen pro testy (pokročilé) |

## Ověření

- V acme stiskněte **Test**: otevře relaci a s vyplněnou *Domain* spočítá záznamy zóny; jinak vypíše domény. Relace se zavře; nic se nemění.
- Po objednávce: Netim → doména → **DNS zone**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při otevření relace | Špatné reseller ID nebo API heslo, nebo heslo OT&E použité proti produkci. |
| Příliš mnoho relací | 10 relací Netimu drží jiné nástroje - zavřete je, nebo počkejte, až vyprší. |
| Operace *Failed* / *Cancelled* | acme ukáže zprávu Netimu - často doména není na DNS Netimu. |
| Doména není ve výpisu | Doména je v jiném resellerském účtu nebo ji pro vás Netim nespravuje. |
