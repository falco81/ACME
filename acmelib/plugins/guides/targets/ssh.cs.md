# Linux / Unix server (SSH) - nastavení pro acme

acme se k serveru přihlásí přes SSH a zapíše certifikát jako **soubory** - ve formátech a
na místa, která zadáte (PEM, celý řetězec, klíč, kombinovaný PEM, DER, PKCS#7, PKCS#12,
JKS). Každý soubor nejdřív nahraje do dočasné složky a pak ho atomicky přesune přes starý
(starý ponechá jako kopii). Potom spustí *Test command* (např. `nginx -t`) a *Reload /
restart* (např. `systemctl reload nginx`); když některý selže, **vrátí předchozí
soubory** a službu s nimi znovu načte. Předvolby vyplní soubory a příkazy pro nginx,
Apache, HAProxy, Postfix, Dovecot, Exim, Proxmox VE, Proxmox Backup Server, Tomcat, Docker,
Kubernetes, Webmin, Cockpit, vsftpd, OpenLDAP, Grafana, Plex, MySQL/MariaDB a UniFi Network.

Pro jakýkoli Linux nebo Unix se serverem OpenSSH a POSIXovým `sh` (také BSD a zařízení s
běžným shellem).

## Co potřebujete

- SSH z acme na server, **TCP 22** (nebo váš port). Pokud server dosáhne jen jiná síť, může
  spojení předat **konektor** (*Targets → Connector over SSH*).
- Účet, který smí zapsat cílové soubory a spustit reload: `root`, nebo uživatel se `sudo`.
- Na serveru `sh`, `mkdir`, `cp`, `mv`, `chmod`, `chown` (standardně jsou).

## Nastavení serveru

1. Vytvořte samostatný účet (lepší než přihlašování jako root):

   ```sh
   sudo useradd -m -s /bin/sh acme
   ```

2. Vložte k němu veřejný klíč acme. Klíč vytvořte v acme (cíl → *The SSH key* → *Make a
   key*; *How to set it up* ukáže přesné příkazy), pak na serveru:

   ```sh
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<IP-acme>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

   `from="<IP-acme>"` zajistí, že klíč funguje jen ze serveru acme.
3. Není-li účet root, povolte sudo bez hesla. acme spouští své kroky jako
   `sudo -n sh -c '...'`, proto pravidlo musí povolit `sh`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **Pro tento účet to v podstatě znamená root** - podle toho klíč chraňte. (Nebo vyplňte
   *sudo password* a `NOPASSWD` vynechte.)
4. Ověřte, že konfigurace služby ukazuje na cesty, které zadáte do *Files* (např. nginx
   `ssl_certificate /etc/nginx/ssl/<jméno>.crt;`).
5. Ve firewallu serveru (je-li) povolte TCP 22 ze serveru acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP serveru |
| SSH port | `22` |
| User | `acme` (nebo `root`) |
| Sign in with / The SSH key | *a private key* - klíč z kroku 2 |
| Host key (pokročilé) | Řádek `known_hosts`, nebo prázdné se zapnutým *Trust the first host key seen* |
| Through a connector (pokročilé) | Konektor, je-li server dostupný jen z jiné sítě |
| Use sudo / sudo password | Zapnout pro účet, který není root; heslo prázdné při `NOPASSWD` |
| Folder for uploads (pokročilé) | `/tmp` (výchozí) - sem se soubory nahrají před přesunem |
| Service (nasazení) | Předvolba, např. *nginx*, nebo *Custom* |
| Files (nasazení) | Jeden na řádek: `formát cesta [mód] [vlastník[:skupina]]`, např. `fullchain-pem /etc/nginx/ssl/{name}.crt 0644 root:root` |
| PKCS#12 / keystore password, Keystore alias | Jen pro soubory `pfx`, `p12`, `jks` (`jks` potřebuje aspoň 6 znaků) |
| Keep a copy of a file replaced | Zapnuto (výchozí) - kopie slouží k vrácení |
| Test command | např. `nginx -t` |
| Reload / restart | např. `systemctl reload nginx` |
| Before writing / After reloading (pokročilé) | Volitelné další příkazy |
| Check what is served | např. `www.example.com:443` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, spustí `id -un; uname -sr` a se sudo ověří,
  že `sudo` dává roota: `signed in as acme on Linux ...; sudo works`.
- Na serveru po nasazení:

  ```sh
  ls -l /etc/nginx/ssl/
  openssl x509 -in /etc/nginx/ssl/<jméno>.crt -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Permission denied (publickey)` | Klíč není v `~acme/.ssh/authorized_keys`, špatná práva (700/600), nebo `from=` nesouhlasí s IP acme. |
| Změnil se klíč hostitele | Server byl přeinstalován: vložte nový řádek `known_hosts` do *Host key*. |
| `signed in, but sudo does not work` | Chybí pravidlo `NOPASSWD` pro `sh`, nebo je nastaveno `requiretty`; vyplňte *sudo password* nebo opravte řádek sudoers. |
| `no files to write` | Zvolte předvolbu *Service* nebo vyplňte *Files*. |
| Test selhal, soubory vráceny | Přečtěte výstup testu v úloze; konfigurace služby ukazuje jinam, nebo formát neodpovídá. |
| Služba ukazuje starý certifikát | Příkaz reload tuto službu nenačte znovu, nebo konfigurace ukazuje na jiné cesty. |
