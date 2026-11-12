# Vultr - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně ve **Vultr DNS**, přes Vultr API v2 (`https://api.vultr.com/v2`, API klíč jako bearer). Vypíše domény, načte záznamy, pro každou hodnotu přidá jeden TXT záznam (`POST /domains/{domain}/records`) a ten smaže podle id. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu přidanou ve Vultr **Network → DNS** a u registrátora nastavené jmenné servery Vultr (`ns1.vultr.com`, `ns2.vultr.com`).
- HTTPS (TCP 443) z acme na `api.vultr.com`.
- **Veřejnou IP adresu**, ze které acme chodí do internetu - z jiné Vultr klíč odmítne.

## Nastavení Vultru

1. Přihlaste se na `my.vultr.com`.
2. **Account → API → Enable API**. Zkopírujte **API key**.
3. V **Access Control** přidejte veřejnou adresu acme (IPv4 `/32`, a používá-li acme IPv6, jeho `/128` nebo `/64`) a **odeberte „Allow All“**, je-li tam.
4. Lepší než klíč samotného účtu: vytvořte pro acme podřízeného uživatele - **Account → Users → Add User** jen s oprávněním **DNS** a zapnutým **API**, a použijte API klíč tohoto uživatele (s vlastním Access Control).

Nejste-li si jisti veřejnou adresou acme:

```sh
curl -4 https://ifconfig.me; curl -6 https://ifconfig.me
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key | API klíč (podřízeného uživatele) |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 60 (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény; nic nemění.
- Po objednávce: **Network → DNS →** doména: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
curl -H 'Authorization: Bearer APIKEY' https://api.vultr.com/v2/domains
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` „Unauthorized IP address“ | acme volá z adresy, která není v Access Control (zkontrolujte i IPv6). |
| `401` „Invalid API token“ | Klíč je špatný nebo byl přegenerován. |
| `403` u záznamů | Podřízenému uživateli chybí oprávnění DNS. |
| Doména nenalezena | Není přidána v Network → DNS, nebo je v jiném účtu. |
