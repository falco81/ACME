# PowerDNS (HTTP API) - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně serveru **PowerDNS Authoritative**, přes jeho vestavěné HTTP API (`/api/v1`, hlavička `X-API-Key`). Zjistí verzi serveru, vypíše zóny a mění TXT RRset na `_acme-challenge.JMÉNO` přes `PATCH`:

- PowerDNS **4.9.12+ (v řadě 4.9), 5.0.2+ a novější**: `EXTEND` přidá jen naši hodnotu, `PRUNE` odebere jen naši hodnotu - nic jiného se nezapisuje.
- Starší servery: RRset se načte a zapíše celý přes `REPLACE` (jeho TTL zůstane), vždy jedna změna najednou; `DELETE` jen tehdy, byla-li naše hodnota poslední.

## Co potřebujete

- PowerDNS Authoritative 4.x nebo 5.x s backendem, který zónu drží (gsqlite3, gmysql, gpgsql, LMDB …) - ne jen BIND backend (soubory zón jsou pro API jen ke čtení).
- HTTP(S) z acme na webserver PowerDNS, obvykle **TCP 8081**.

## Nastavení PowerDNS

1. Zapněte API v `pdns.conf` (`/etc/powerdns/pdns.conf` nebo `/etc/pdns/pdns.conf`):

   ```text
   api=yes
   api-key=<dlouhý náhodný řetězec>
   webserver=yes
   webserver-address=0.0.0.0
   webserver-port=8081
   webserver-allow-from=127.0.0.1,203.0.113.10/32
   ```

   - `webserver-allow-from` musí obsahovat **adresu acme** a co nejméně dalšího.
   - Od verze 4.6 lze klíč uložit hashovaný: `pdnsutil hash-password` vypíše hodnotu pro `api-key=` (acme dostane klíč v čitelné podobě).
2. Restartujte PowerDNS:

   ```sh
   systemctl restart pdns
   ```

3. API klíč **není** omezen na jednu zónu - může měnit všechny zóny serveru. Pokud acme k API přistupuje přes nedůvěryhodnou síť, předřaďte TLS (reverzní proxy).

Kontrola ze sítě acme:

```sh
curl -H 'X-API-Key: KLIC' http://pdns.example.com:8081/api/v1/servers/localhost
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API address | `http://pdns.example.com:8081` (nebo adresa `https://` proxy) |
| API key | čitelný `api-key` |
| Server id | `localhost` (pokročilé) |
| Zone | prázdné (nejdelší zóna serveru, do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| Check the API's certificate | zapnuto u adresy `https://` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: zjistí typ démona a verzi a vypíše zóny; nic nemění. Podle verze poznáte, zda se použije EXTEND/PRUNE.
- Na serveru:

```sh
pdnsutil list-zone example.com | grep _acme-challenge
dig +short TXT _acme-challenge.www.example.com @127.0.0.1
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unauthorized` | Špatný klíč, nebo byl do acme vložen hashovaný klíč - acme potřebuje čitelný. |
| Connection refused / `403` | Chybí `webserver=yes`, špatná `webserver-address`, nebo acme není ve `webserver-allow-from`. |
| `422` „RRset … is not in canonical format“ | Ručně zapsaná vadná hodnota v RRsetu; opravte záznam. |
| Zóna nenalezena | Zóna je v BIND backendu, nebo *Server id* není `localhost`. |
| Sekundární servery změnu nedostanou | Nastavení SOA-EDIT-API / NOTIFY zóny - nastavte `SOA-EDIT-API` (např. `DEFAULT`), aby rostlo sériové číslo. |
