# HestiaCP - nastavení pro acme

acme prokazuje jména přes DNS-01 v DNS serveru HestiaCP: přes API HestiaCP (`https://SERVER:8083/api/`, každé volání jeden příkaz `v-*`) přidá záznam TXT `_acme-challenge.JMÉNO` (`v-add-dns-record`) a poté smaže jen své vlastní záznamy (`v-delete-dns-record` podle ID). Každý příkaz sám zvýší sériové číslo zóny, přepíše zónu a znovu načte DNS server. Pro verze HestiaCP s přístupovými klíči (1.6 a novější).

## Co potřebujete

- Server HestiaCP, jehož DNS server obsluhuje doménu (DNS doména přidaná uživateli).
- Na serveru zapnuté API a povolenou adresu acme.
- Odchozí HTTPS z acme na port panelu **8083** (nebo zadaný port).

## Nastavení HestiaCP

1. Jako admin: **Server settings → Configure → Security → API**: zapněte API a přidejte veřejnou adresu acme mezi **povolené IP adresy** (nebo v shellu: `v-change-sys-api enable`).
2. Vytvořte přístupový klíč pro uživatele, kterému DNS domény patří, s povolenými jen čtyřmi příkazy DNS. V panelu: uživatel → **Access keys → Add** a zaškrtněte příkazy; nebo v shellu jako root:

   ```sh
   v-add-access-key alice 'v-list-dns-domains,v-list-dns-records,v-add-dns-record,v-delete-dns-record' acme json
   ```

   (přesné použití ve vaší verzi ukáže `v-add-access-key` bez argumentů).
3. Zkopírujte **ID přístupového klíče** a **secret key** (zobrazí se jen jednou).
4. Funguje i klíč administrátora, jednající za uživatele zadaného v acme - vlastní klíč uživatele je menší oprávnění.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| HestiaCP address | Server: `server.example.com`, `host:port` nebo `https://…`; bez portu 8083 |
| User | Uživatel HestiaCP, kterému DNS domény patří (výchozí `admin`) |
| Access key | ID přístupového klíče |
| Secret key | Jeho secret |
| Zone | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší z DNS domén uživatele, ve které jméno leží |
| TTL (s) | (pokročilé) `0` = vlastní TTL zóny |
| Check the server's certificate | (pokročilé) nechte zapnuté; vypněte jen má-li panel certifikát podepsaný sám sebou |

## Kontrola

- **Test** v acme se přihlásí a vypíše DNS domény uživatele - nebo při vyplněné *Zone* spočítá její záznamy. Nic nemění.
- Na serveru:

  ```sh
  v-list-dns-records alice example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `E_FORBIDEN` (10) | Klíč nesmí daný příkaz spustit, nebo IP acme není pro API povolená. |
| `E_NOTEXIST` (3) | Uživatel nebo DNS doména neexistuje - zkontrolujte *User* a *Zone*. |
| `E_DISABLED` (11) | API (nebo uživatel) je vypnuté - zapněte ho. |
| Spojení odmítnuto / vypršel čas | Port 8083 je pro adresu acme blokován firewallem. |
