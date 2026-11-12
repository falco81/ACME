# Forpsi F-DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 ve **Forpsi F-DNS** (placená služba DNS-as-a-service, DNSaaS, společnosti INTERNET CZ): přes REST API F-DNS (`api.forpsi.com/dnsaas/v1`) přidá záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam (podle jeho id).

**API má jen F-DNS.** Běžné DNS Forpsi - bezplatný DNS hosting k doméně nebo webhostingu - žádné API nemá (jen webovou administraci a import CSV). Pro takovou doménu nasměrujte `_acme-challenge.JMÉNO` záznamem CNAME do zóny, kam acme zapisovat umí (vlastní DNS server acme, acme-dns nebo poskytovatel s API), a použijte tu validaci.

## Co potřebujete

- Aktivní službu F-DNS (DNSaaS) ve vašem účtu Forpsi, s doménami v ní.
- Odchozí HTTPS z acme na `api.forpsi.com` (port 443).

## Nastavení Forpsi F-DNS

1. Přihlaste se na `admin.forpsi.com` účtem se službou F-DNS.
2. Ve službě F-DNS (DNSaaS) vygenerujte **API token** a zkopírujte ho.
3. Ověřte, že domény, které má acme prokazovat, jsou přidané do F-DNS a jejich jmenné servery vedou na F-DNS.
4. Pro doménu na běžném DNS Forpsi: v administraci Forpsi přidejte jednou pro každé jméno CNAME:

   ```text
   _acme-challenge.www.example.cz.  CNAME  www.example.cz.acme.example.net.
   ```

   (cíl je zóna, kam acme zapisuje - např. vlastní DNS server acme), a v acme zvolte tu validaci.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token F-DNS |
| Zone | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší doména F-DNS, ve které jméno leží (jinak podle SOA) |
| TTL (s) | (pokročilé) Výchozí `60`; F-DNS přijme 60 až 86400 |

## Kontrola

- **Test** v acme přečte službu (použité / povolené domény) a vypíše domény - nebo při vyplněné *Zone* spočítá její záznamy. Nic nemění.
- Pomocí curl (hlavička je `token:`, ne `Authorization:`):

  ```sh
  curl -s -H "token: $TOKEN" https://api.forpsi.com/dnsaas/v1/domains
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Invalid token` | Špatný token, nebo služba F-DNS není aktivní. |
| Doména není v seznamu | Je na běžném DNS Forpsi, ne v F-DNS - použijte CNAME do zóny, kam acme zapisovat umí. |
| `answered something that is not its API` | Mezi tím je proxy nebo špatná adresa; ověřte odchozí HTTPS na `api.forpsi.com`. |
