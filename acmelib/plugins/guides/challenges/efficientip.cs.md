# EfficientIP SOLIDserver - nastavení pro acme

acme prokazuje jména přes DNS-01 v zóně spravované EfficientIP SOLIDserver (DDI): přes REST API v2.0 SOLIDserveru přidá záznam TXT (`/dns/rr/add`) na zadaném DNS serveru (nebo architektuře SMART) a poté smaže jen záznamy s jeho hodnotou (`/dns/rr/delete`). Změnu na DNS servery rozešle SOLIDserver sám.

## Co potřebujete

- Správcovskou appliance SOLIDserver s REST API v2.0 (`/api/v2.0`).
- Zónu spravovanou SOLIDserverem na DNS serveru nebo architektuře SMART, a její view, používá-li views.
- Odchozí HTTPS z acme na appliance (port 443, nebo zadaný port).
- Pokud certifikát appliance vydala soukromá CA: certifikát této CA.

## Nastavení SOLIDserveru

1. **Administration → Groups**: vytvořte skupinu pro acme, např. `acme-dns`.
2. V **Services** skupiny povolte jen služby DNS, které acme volá: výpis zón (`dns_zone_list`), výpis záznamů (`dns_rr_list`), přidání záznamů (`dns_rr_add`) a mazání záznamů (`dns_rr_delete`). Přesné názvy služeb se mohou podle verze lišit - zvolte služby DNS zone *list* a RR *list / add / delete*.
3. V **Resources** skupiny přidejte jen DNS server / SMART a zóny, které smí acme měnit.
4. **Administration → Users**: vytvořte lokálního uživatele, např. `acme`, se silným heslem, členem jen této skupiny, s přístupem k API (web services).
5. Omezuje-li appliance přístup k API podle zdrojové adresy, povolte veřejnou adresu acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| SOLIDserver address | Správcovská appliance, např. `sds.example.local` (`name:port` pro jiný port) |
| User | Uživatel SOLIDserveru |
| Password | Jeho heslo |
| DNS server | DNS server nebo architektura SMART se zónami, jak je SOLIDserver pojmenovává |
| DNS view | (pokročilé) View zón; prázdné = bez view |
| Zone | např. `example.com`; prázdné = nejdelší zóna tohoto serveru, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| Check the server's certificate | (pokročilé) nechte zapnuté |
| CA certificate | (pokročilé) Soukromá CA, která podepsala certifikát appliance (PEM) |

## Kontrola

- **Test** v acme vypíše zóny serveru z *DNS server*. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "acme:$PASS" --cacert ca.pem \
    "https://sds.example.local/api/v2.0/dns/zone/list?where=server_name='smart.example.local'"
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the DNS server is not set` | Vyplňte *DNS server*. |
| `401` / `403` | Špatný uživatel/heslo, nebo skupině chybí služby DNS či zóna v prostředcích. |
| Nevypíší se žádné zóny | *DNS server* není zapsán přesně tak, jak ho SOLIDserver pojmenovává, nebo jsou zóny ve view - vyplňte *DNS view*. |
| Chyba TLS | Vložte soukromou CA do *CA certificate*. |
