# HestiaCP - nastavení pro acme

acme instaluje certifikát na webové domény HestiaCP přes **SSH**, pomocí vlastních zdokumentovaných příkazů Hestie. U každé webové domény zadaného uživatele Hestie zapíše certifikát, klíč a řetězec do nové soukromé složky (`mktemp -d`) jako `<doména>.crt`, `<doména>.key` a `<doména>.ca`, pak spustí `v-change-web-domain-sslcert` (SSL už zapnuté) nebo `v-add-web-domain-ssl` (SSL vypnuté) a složku smaže. Webový server restartuje Hestia sama. Je-li pro doménu zapnutý vlastní Let's Encrypt Hestie, acme ho nejdřív vypne příkazem `v-delete-web-domain-ssl` (jinak by cron Hestie vrátil svůj certifikát) - **tím se vypne i „force SSL“**, což acme v úloze uvede.

REST API Hestie se nepoužívá: jeho SSL příkazy berou jen složku na serveru, kterou API nedokáže bezpečně zapsat.

## Co potřebujete

- Server HestiaCP (1.x) s příkazy v `/usr/local/hestia/bin` (výchozí).
- Přístup SSH z acme na server (port 22, nebo nastavený port).
- **root**, nebo uživatele se **sudo** - příkazy Hestie `v-*` musí běžet jako root.

## Nastavení HestiaCP

1. Rozhodněte, jaký SSH uživatel:
   - `root` se SSH klíčem (nejjednodušší; v `/etc/ssh/sshd_config` nastavte `PermitRootLogin prohibit-password`, aby se přijímaly jen klíče), nebo
   - vyhrazený uživatel se sudo:

```sh
sudo useradd -m -s /bin/bash acme
echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme
sudo chmod 440 /etc/sudoers.d/acme
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# veřejný SSH klíč z acme vložte do /home/acme/.ssh/authorized_keys (práva 600, vlastník acme)
```

   **acme spouští své příkazy jako `sudo sh -c '…'`, takže pravidlo sudo omezené na jednotlivé příkazy `v-*` nefunguje - uživatel fakticky dostává root.** Podle toho chraňte jeho klíč a kde to jde, povolte SSH jen ze serveru acme (firewall, nebo `AllowUsers acme@<ip-acme>` v sshd_config).
2. Je-li zapnutý firewall Hestie, povolte SSH ze serveru acme: **Server (ikona ozubeného kola) → Firewall**.
3. Poznamenejte si uživatele Hestie, kterému webové domény patří (např. `admin`), a jména domén přesně tak, jak je Hestia vypisuje (záložka **Web**).
4. U domén s Let's Encrypt Hestie: rozhodněte, zda je má acme převzít (vypne Let's Encrypt Hestie) - a pokud jste používali **Enable SSL redirection / force SSL**, potom ho znovu zapněte.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | server s Hestií |
| SSH port | 22 (nebo váš SSH port) |
| User | `root` nebo uživatel se sudo |
| Sign in with / The SSH key / Password | klíč vytvořený v acme (jeho veřejná část v `authorized_keys`), nebo heslo |
| Host key (pokročilé) | řádek `known_hosts` serveru; prázdné s *Trust the first host key seen* |
| Use sudo / sudo password | zapnout pro uživatele, který není root; heslo prázdné, když je sudo NOPASSWD |
| Hestia's commands (pokročilé) | `/usr/local/hestia/bin` |
| Hestia user (nasazení) | uživatel, kterému webové domény patří, např. `admin` |
| Web domains (nasazení) | webové domény toho uživatele, jedna na řádek |
| Restart the web server | zapnuto (Hestia po změně restartuje/reloaduje webový server) |
| Check what is served | `example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme spustí `v-list-users json` a ohlásí, kolik uživatelů Hestie odpovídá. Tlačítko *Try* u klíče spustí `id -un; ls /usr/local/hestia/bin/v-list-users`.
- Na serveru:

```sh
sudo /usr/local/hestia/bin/v-list-web-domain-ssl admin example.com
```

   ukáže subjekt, vydavatele a data nainstalovaného certifikátu. V panelu: **Web → (doména) → Edit → SSL**.

## Časté problémy

| Problém | Řešení |
|---|---|
| `… failed (exit …): sudo: a password is required` | zadejte *sudo password*, nebo nastavte pravidlo sudo jako NOPASSWD |
| `v-list-users … not found` | příkazy Hestie jsou jinde: nastavte *Hestia's commands* |
| `"…" is not a Hestia user` / doména nenalezena | uživatel a doména musí být přesně jako v Hestii |
| Chyba z `v-add-web-domain-ssl` / `v-change-web-domain-sslcert` | Hestia certifikát odmítla - klíč nesedí, nebo je špatný řetězec; viz detail úlohy |
| `… now has NO SSL: Hestia's own Let's Encrypt was turned off …` | znovu zapněte Let's Encrypt v Hestii, nebo po odstranění příčiny nasaďte znovu |
| Web už nepřesměrovává na HTTPS | acme převzalo doménu s Let's Encrypt: v Hestii znovu zapněte *force SSL* |
