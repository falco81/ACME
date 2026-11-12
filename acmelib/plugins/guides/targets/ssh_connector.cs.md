# Konektor přes SSH - nastavení pro acme

Konektor je **váš linuxový server** (AlmaLinux, RHEL, Rocky, Debian, Ubuntu - jakýkoli s
OpenSSH), ke kterému se acme přihlásí přes SSH, aby z něj dosáhlo na cíle, **na které vidí
jen tamní síť**. Cíl, který se přihlašuje přes SSH, ho zvolí v *More → Through a
connector*; acme se pak k cíli připojí přes něj (`ssh -W`, přesměrované TCP spojení).
**Na konektor se nic neinstaluje a žádný certifikát se na něj nenasazuje.**

## Co potřebujete

- Linuxový server s OpenSSH, dostupný z acme na **TCP 22** (nebo vašem portu).
- Z tohoto serveru síťový přístup na port SSH každého cíle za ním.
- Běžný účet (bez roota, bez sudo).
- Volitelně `ssh-keyscan` na konektoru (součást klienta OpenSSH). Bez něj připněte klíč
  hostitele každého cíle v jeho poli *Host key*.

## Nastavení serveru konektoru

1. Vytvořte samostatný neprivilegovaný účet:

   ```sh
   sudo useradd -m -s /bin/bash acme-relay
   ```

2. Vložte k němu veřejný klíč acme (klíč vytvořte v acme: *The SSH key* konektoru →
   *Make a key*; *How to set it up* ukáže příkazy):

   ```sh
   sudo -u acme-relay sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<IP-acme>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

   Volitelně omezte, kam smí přesměrovat, přidáním
   `permitopen="10.0.0.5:22",permitopen="10.0.0.6:22"` před klíč (jedno na cíl).
3. Ověřte, že je pro účet povoleno přesměrování TCP (výchozí stav). V
   `/etc/ssh/sshd_config` nesmí být `no`:

   ```text
   AllowTcpForwarding yes
   ```

   a po změně `sudo systemctl reload sshd`.
4. Ve firewallu konektoru povolte TCP 22 ze serveru acme a odchozí SSH z konektoru na cíle.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP konektoru |
| SSH port | `22` |
| User | `acme-relay` |
| Sign in with / The SSH key | *a private key* - klíč z kroku 2 |
| Password | Jen při přihlášení heslem |
| Host key (pokročilé) | Řádek `known_hosts` konektoru, nebo prázdné se zapnutým *Trust the first host key seen* |

Pak u každého cíle za ním: **More → Through a connector** → tento konektor.

## Ověření

- Na konektoru stiskněte **Try**: acme se přihlásí, spustí `id -un; uname -n` a odpoví
  `signed in to <host> as acme-relay - targets set to go through it are reached from there`
  (chybí-li `ssh-keyscan`, připojí poznámku).
- Stiskněte **Try** na cíli, který ho používá: přihlášení půjde přes konektor.
- Na konektoru ověříte povolené přesměrování:

  ```sh
  sudo sshd -T | grep -i allowtcpforwarding
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| Try konektoru selže s `Permission denied` | Klíč není v `authorized_keys`, špatná práva, nebo `from=` nesouhlasí s IP acme. |
| Konektor funguje, cíl za ním nedostupný | Firewall mezi konektorem a cílem, `AllowTcpForwarding no`, nebo `permitopen` cíl neuvádí. |
| `ssh-keyscan is not there` | Nainstalujte na konektor klienta OpenSSH, nebo připněte *Host key* každého cíle. |
| `... is a connector: certificates go to the targets` | Očekávané: na konektor nasazovat nelze. |
