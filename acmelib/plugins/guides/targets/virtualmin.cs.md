# Virtualmin - nastavení pro acme

acme volá **Remote API** Virtualminu
(`POST https://<host>:10000/virtual-server/remote.cgi`, základní autentizace HTTP) s
`program=install-cert` pro každý zadaný virtuální server a posílá certifikát, klíč a
řetězec. Virtualmin nahradí soubory certifikátu domény na místě, aktualizuje webový server
a další služby, které tento certifikát používají, a **vypne pro doménu vlastní obnovu Let's
Encrypt**. Má-li doména už stejný certifikát (`list-certs`), nic se neposílá. S volbou
*Turn SSL on where it is off* acme nejdřív spustí `enable-feature --ssl`.

Pro Virtualmin GPL i Pro nad Webminem.

## Co potřebujete

- Síťový přístup z acme na Webmin: **TCP 10000** (nebo váš port Webminu).
- **Hlavního správce** Webminu (obvykle `root`) - Remote API jiný účet nepřijme.
- Virtuální servery (domény), které mají certifikát dostat.

## Nastavení Virtualminu / Webminu

1. Povolte acme přístup k Webminu: otevřete TCP 10000 ze serveru acme ve firewallu
   (*Linux Firewall* Virtualminu / `firewalld`), a je-li **Webmin → Webmin Configuration →
   IP Access Control** omezené, přidejte IP adresu serveru acme.
2. Použijte hlavního správce (`root`) a jeho heslo. Používá-li Webmin pro tohoto uživatele
   dvoufázové ověření, může být Remote API se základní autentizací odmítnuto - ověřte přes
   **Try**.
3. Ověřte, že každý zadaný virtuální server má zapnutou funkci **SSL website** (*Virtualmin
   → Edit Virtual Server → Enabled features*), nebo v acme nastavte *Turn SSL on where it
   is off*.
4. Virtuální server, který **sdílí certifikát jiného serveru**, vlastní dostat nemůže:
   install-cert ho odmítne - dejte certifikát serveru, kterému patří.
5. API si můžete vyzkoušet v shellu serveru:

   ```sh
   virtualmin list-domains --name-only
   virtualmin list-certs --domain example.com --cert
   ```

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Server, např. `server.example.com` |
| HTTPS port | `10000` |
| User | `root` (výchozí) - hlavní správce |
| Password | Jeho heslo |
| Check the device's certificate | Zapnuto; vypnout jen dokud má Webmin self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu Webminu, pokud není veřejná |
| Virtual server (nasazení) | Doména - vyberte ji přes *Load the list*, nebo ji napište |
| More virtual servers (nasazení) | Jedna doména na řádek, např. `shop.example.com` |
| Turn SSL on where it is off (nasazení) | Zapnout, má-li se SSL zapnout serverům bez něj |
| Check what is served | např. `www.example.com:443` |

Jména certifikátu musí pokrýt všechny zadané virtuální servery.

## Ověření

- Na cíli stiskněte **Try**: acme vypíše virtuální servery:
  `signed in to Virtualmin ...; N virtual servers`.
- Na serveru:

  ```sh
  virtualmin list-certs --domain example.com --cert | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Nejde o hlavního správce, špatné heslo, nebo IP Access Control blokuje acme. |
| `no virtual server is set` | Vyplňte *Virtual server* nebo *More virtual servers*. |
| `Virtualmin said ... does not exist` | Doména tu není virtuálním serverem (zkontrolujte zápis). |
| `Virtualmin said ...` SSL není zapnuté | Zapněte *Turn SSL on where it is off*, nebo zapněte SSL ve Virtualminu. |
| Odmítnuto u serveru se sdíleným certifikátem | Nainstalujte na server, kterému certifikát patří. |
| Přestala obnova Let's Encrypt ve Virtualminu | Očekávané: certifikát teď spravuje acme. |
