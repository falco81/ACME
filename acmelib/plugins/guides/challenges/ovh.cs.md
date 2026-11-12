# OVHcloud - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně u OVHcloud, přes API OVHcloud (`https://eu.api.ovh.com/1.0`, nebo endpoint pro Kanadu / USA). Každé volání je podepsané aplikačním klíčem, aplikačním tajemstvím a consumer key. acme vypíše zóny (`GET /domain/zone`), přidá TXT záznam (`POST /domain/zone/{zone}/record`), najde a smaže jen svůj záznam a po každé změně zónu obnoví (`POST /domain/zone/{zone}/refresh`). Ostatní hodnoty na jméně zůstanou.

## Co potřebujete

- Zónu u OVHcloud (DNS servery OVH `dnsXX.ovh.net` / `nsXX.ovh.net`).
- HTTPS (TCP 443) z acme na endpoint vašeho účtu OVHcloud: `eu.api.ovh.com`, `ca.api.ovh.com` nebo `api.us.ovhcloud.com`.

## Nastavení OVHcloud

1. Otevřete stránku pro tokeny svého endpointu, např. `https://eu.api.ovh.com/createToken/` (Kanada: `https://ca.api.ovh.com/createToken/`), a přihlaste se účtem OVH, který zónu vlastní.
2. Vyplňte *Application name* `acme`, popis a *Validity* **Unlimited** (jinak consumer key vyprší a acme přestane fungovat).
3. Práva - přidejte přesně tyto řádky:

   ```text
   GET     /domain/zone/*
   POST    /domain/zone/*
   DELETE  /domain/zone/*
   GET     /domain/zone
   ```

   Pro omezení na jednu zónu použijte místo `/domain/zone/*` cestu `/domain/zone/example.com/*` (a v acme pak vyplňte *Zone*).
4. Volitelně omezte token na veřejnou IP adresu acme (*Restricted IPs*).
5. **Create keys** a zkopírujte **Application key**, **Application secret** a **Consumer key**.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Endpoint | `OVH Europe`, `OVH Canada` nebo `OVH US` - kde je účet |
| Application key | aplikační klíč |
| Application secret | aplikační tajemství |
| Consumer key | consumer key |
| Zone | prázdné (nejdelší zóna, do které jméno patří), nebo zóna |
| TTL (s) | 60 (0 = TTL zóny, jinak nejméně 60; pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše zóny, které klíče vidí; nic nemění.
- Po objednávce: OVHcloud Control Panel → **Web Cloud → Domain names →** doména → **DNS zone**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| „This call has not been granted“ | Consumer key nemá danou metodu/cestu - vytvořte nový token s právy výše. |
| „Invalid signature“ | Špatné aplikační tajemství nebo consumer key, nebo hodiny acme jdou hodně špatně. |
| „This credential is not valid“ | Consumer key vypršel (platnost nebyla *Unlimited*) nebo byl zrušen. |
| Zóny jiného účtu | Token byl vytvořen jiným účtem OVH - přihlaste se vlastníkem zóny. |
| Prázdný seznam zón u tokenu pro jednu zónu | Očekávané, pokud `GET /domain/zone` není povoleno - vyplňte *Zone*. |
