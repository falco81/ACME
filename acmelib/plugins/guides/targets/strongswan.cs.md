# strongSwan (IPsec VPN) - nastavení pro acme

acme se k VPN serveru přihlásí přes SSH a zapíše certifikát, mezilehlé certifikáty a klíč
tam, odkud strongSwan čte své přihlašovací údaje, a pak je načte **bez shození tunelu**:

| Konfigurace | Soubory | Příkaz načtení |
|---|---|---|
| `swanctl.conf` (vici) | `<složka>/x509/<jméno>.crt`, `<složka>/x509ca/acme-ca-<id>.crt`, `<složka>/private/<jméno>.key` | `swanctl --load-creds` |
| `ipsec.conf` (stroke) | `<složka>/ipsec.d/certs/...`, `ipsec.d/cacerts/...`, `ipsec.d/private/...` | `ipsec rereadall` |

Selže-li příkaz načtení, vrátí se předchozí soubory. Kopie nahrazených souborů jdou ve
výchozím stavu do `.acme-backup/` vedle nich (`swanctl --load-creds` čte celé složky).

Pro strongSwan 5.x a 6.x na Linuxu.

## Co potřebujete

- SSH z acme na VPN server, **TCP 22**.
- `root`, nebo uživatele se `sudo` (soubory jsou pod `/etc` a klíč je soukromý).
- Spojení už nastavené tak, aby používalo soubor certifikátu podle jména (viz níže).

## Nastavení serveru

1. Vytvořte účet a vložte k němu veřejný klíč acme (stejně jako u cíle *Linux / Unix
   server*; *The SSH key → How to set it up* v acme ukáže příkazy):

   ```sh
   sudo useradd -m -s /bin/sh acme
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<IP-acme>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

2. Není-li to root, povolte sudo bez hesla. acme spouští kroky jako `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **Pro tento účet to znamená root.**
3. Nasměrujte spojení na soubor, který acme zapisuje (`<jméno>` = jméno certifikátu, nebo
   *File name* nastavené v acme):
   - `swanctl.conf`:

     ```text
     connections {
       rw {
         local { certs = vpn.example.com.crt  ... }
       }
     }
     ```
   - `ipsec.conf`: `leftcert=vpn.example.com.crt`

   Klíč se najde sám. Jednou načtěte konfiguraci (`swanctl --load-all` nebo `ipsec reload`).
4. Zjistěte složku: na většině distribucí `/etc/swanctl`, na RHEL/Fedoře
   `/etc/strongswan/swanctl`; pro stroke `/etc` (obsahuje `ipsec.d`).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / SSH port / User | VPN server, `22`, `acme` (nebo `root`) |
| Sign in with / The SSH key | *a private key* - klíč z kroku 1 |
| Use sudo / sudo password | Zapnout pro účet, který není root; heslo prázdné při `NOPASSWD` |
| Configured with (nasazení) | *swanctl.conf (vici)* nebo *ipsec.conf (stroke)* |
| Folder (nasazení) | `/etc/swanctl` (nebo `/etc/strongswan/swanctl`); `/etc` pro stroke |
| File name (nasazení, pokročilé) | `<toto>.crt` / `<toto>.key`; prázdné: jméno certifikátu |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Výchozí hodnoty stačí |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí a přečte `swanctl --version` (nebo
  `ipsec version`); `strongSwan not found on the PATH` znamená, že uživatel příkazy nenajde.
- Na serveru:

  ```sh
  sudo swanctl --list-certs
  sudo openssl x509 -in /etc/swanctl/x509/vpn.example.com.crt -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `strongSwan not found on the PATH` | Příkazy v `/usr/sbin` nejsou v PATH uživatele; použijte sudo nebo root. |
| `"swanctl --load-creds" failed, the previous files are back` | Přečtěte chybu; charon neběží, nebo je špatně *Configured with*. |
| Klienti vidí starý certifikát | `certs =` / `leftcert=` spojení jmenuje jiný soubor - sjednoťte s *File name*. |
| `the folder must be an absolute path` | Zadejte např. `/etc/swanctl`, bez znaků shellu. |
