# Zimbra Collaboration - nastavení pro acme

acme se k serveru Zimbra přihlásí přes SSH a nasadí certifikát jako **komerční certifikát**
Zimbry vlastním nástrojem Zimbry, spouštěným jako uživatel `zimbra`
(`su - zimbra -c ...`):

1. klíč se uloží do `/opt/zimbra/ssl/zimbra/commercial/commercial.key`;
2. certifikát a řetězec **až ke kořeni** se ověří příkazem `zmcertmgr verifycrt comm` -
   když selže, **vrátí se předchozí klíč**;
3. `zmcertmgr deploycrt comm` je nasadí;
4. služby se restartují: `zmcontrol restart` (výchozí), nebo jen proxy, mailbox a MTA,
   nebo nic.

Pro Zimbra Collaboration 8.7 a novější (Open Source i Network Edition). V instalaci s
**více servery** je každý mailbox / proxy / MTA server samostatným cílem.

## Co potřebujete

- SSH z acme na každý server Zimbra, **TCP 22**.
- `root`, nebo uživatele, který smí přes `sudo` na roota (acme spouští `su - zimbra` jako
  root).
- Typ klíče certifikátu **RSA** (klíč se zapisuje ve tvaru RSA/PKCS#1, který zmcertmgr
  očekává).
- **Kořenový certifikát CA** v PEM, pokud ho řetězec neobsahuje - u Let's Encrypt ho
  neobsahuje (pro řetězec RSA ISRG Root X1).
- Servisní okno: úplný `zmcontrol restart` na pár minut přeruší přístup k poště.

## Nastavení serveru Zimbra

1. Vytvořte účet pro acme a vložte k němu veřejný klíč acme (*The SSH key → How to set it
   up* v acme ukáže příkazy):

   ```sh
   sudo useradd -m -s /bin/sh acme
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<IP-acme>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

2. Povolte sudo bez hesla - acme spouští kroky jako `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **Znamená to root.** (Nebo se přihlašujte jako root a *Use sudo* nechte vypnuté.)
3. Stáhněte kořenový certifikát CA (pro Let's Encrypt ISRG Root X1) - vloží se do *Root CA
   certificate* v acme.
4. Ověřte, že složka komerčního certifikátu existuje:

   ```sh
   sudo ls -ld /opt/zimbra/ssl/zimbra/commercial
   ```

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / SSH port / User | Server Zimbra, `22`, `acme` (nebo `root`) |
| Sign in with / The SSH key | *a private key* - klíč z kroku 1 |
| Use sudo / sudo password | Zapnout pro účet, který není root; heslo prázdné při `NOPASSWD` |
| Timeout (s) (pokročilé) | `30` (zmcertmgr a restart dostanou delší čas samy) |
| Root CA certificate (nasazení) | Kořenový PEM (ISRG Root X1); prázdné jen, když řetězec kořen obsahuje |
| Restart (nasazení) | *every Zimbra service* (výchozí), *proxy, mailbox and MTA only*, nebo *nothing* |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Výchozí hodnoty stačí |
| Check what is served | např. `mail.example.com:443`, `mail.example.com:993`, `mail.example.com:465` |

## Ověření

- Na cíli stiskněte **Try**: acme spustí `zmcontrol -v` jako zimbra:
  `signed in to ...: Release 10.x ...`.
- Na serveru:

  ```sh
  sudo su - zimbra -c 'zmcertmgr viewdeployedcrt'
  sudo su - zimbra -c 'zmcontrol status'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `zmcertmgr wants the chain up to the root` | Vyplňte *Root CA certificate* (ISRG Root X1). |
| `zmcertmgr does not take it, the previous key is back` | Špatný kořen k řetězci, nebo klíč a certifikát k sobě nepatří - přečtěte zprávu. |
| `key-rsa (PKCS#1) is only for RSA keys` | Pro tento certifikát použijte typ klíče RSA. |
| `sudo: a password is required` | Chybí pravidlo `NOPASSWD`, nebo vyplňte *sudo password*. |
| Služby nenaběhly | Zkontrolujte `zmcontrol status`; výstup restartu je v úloze jako varování. |
| Další servery instalace mají starý certifikát | Každý server potřebuje vlastní cíl. |
