# Konektor přes SSH - nastavení pro acme

**Konektor** je váš linuxový server (AlmaLinux, RHEL, Rocky, Debian, Ubuntu... - libovolný s OpenSSH), ke kterému se acme přihlásí přes SSH, aby z něj spouštěl testy proti serverům, na které dosáhne jen tamější síť - intranetový web, poštovní relay, RDP serveru s Windows. Každý test si ho vybere v *More → Through a connector*; acme se pak k testovanému serveru připojí z konektoru SSH tunelem (`ssh -W host:port`, kanál pro přesměrování TCP). **Na konektor se nic neinstaluje a nic tam nezůstane**; TLS handshake i porovnání proběhnou v acme jako u každého jiného testu.

Konektory testů jsou oddělené od konektorů cílů (Cíle → Connector over SSH); může to být stejný server, nebo různé.

## Co potřebujete

- Linuxový server s OpenSSH, který dosáhne na testované servery (jejich porty: 443, 25, 3389...).
- Přístup SSH **z acme** na něj - TCP `22` (nebo jeho vlastní SSH port).
- Uživatele, za kterého se acme přihlásí. **Nepotřebuje root ani sudo** - konektor při vyzkoušení spustí jen `id -un; uname -n` a otevírá přesměrování TCP.
- `AllowTcpForwarding` v `sshd_config` nesmí být `no` (výchozí `yes` stačí).

## Nastavení serveru konektoru

1. Vytvořte vyhrazeného uživatele bez zvláštních práv:

   ```sh
   useradd -m -s /bin/bash acme-relay
   install -d -m 700 -o acme-relay -g acme-relay /home/acme-relay/.ssh
   ```

2. V acme na kartě klíče konektoru stiskněte **Make a key** (ed25519) - nebo *Use my own* - a zobrazenou veřejnou část vložte do `authorized_keys` uživatele (totéž ukáže *How to set it up on the server*):

   ```sh
   echo 'ssh-ed25519 AAAA... acme' >> /home/acme-relay/.ssh/authorized_keys
   chown acme-relay: /home/acme-relay/.ssh/authorized_keys
   chmod 600 /home/acme-relay/.ssh/authorized_keys
   ```

   Chcete-li klíč omezit jen na přesměrování k testovaným serverům, dejte před něj volby, např. `permitopen="intranet.example.local:443",permitopen="10.0.0.25:25"` (pak musí být uveden každý testovaný server:port).
3. Ověřte, že je přesměrování TCP povolené:

   ```sh
   sshd -T | grep -i allowtcpforwarding     # yes / all / local
   ```

   Pokud je `no` (často v bloku `Match`), povolte ho jen tomuto uživateli:

   ```text
   Match User acme-relay
       AllowTcpForwarding local
   ```

   pak `systemctl reload sshd`.
4. Firewally: povolte SSH z acme na konektor a TCP z konektoru na port každého testovaného serveru.

## Vyplnění v acme

Certifikáty → **Testy** → přepínač **Tests | Connectors** → přidat **Connector over SSH**.

| Pole v acme | Co do něj zadat |
|---|---|
| Address | jméno nebo IP konektoru |
| SSH port | `22`, nebo jeho vlastní SSH port |
| User | uživatel z kroku 1 (např. `acme-relay`; výchozí `root` není potřeba) |
| Sign in with | *a private key* (doporučeno) nebo *a password* |
| The SSH key | *Make a key* zde, nebo *Use my own* (OpenSSH nebo PEM, s heslem klíče) |
| Password | jen se *Sign in with: a password* |
| Host key (pokročilé) | řádek `known_hosts` konektoru; prázdné s *Trust the first host key seen* převezme první viděný |
| Trust the first host key seen (pokročilé) | zapnuto (výchozí), nebo vypnuto, jakmile je host key nastaven |
| Tests run from there (the older way) (pokročilé) | nechte prázdné - od 1.0.76 si každý test vybírá konektor v *More → Through a connector* |
| Time limit (s) (pokročilé) | `20` |

Pak v každém testu, který má jít přes něj: *More → Through a connector* = tento konektor.

## Ověření

1. Na konektoru **Try reaching it** / **Test**: acme se přihlásí a napíše `signed in to <host> as <user>`.
2. Spusťte test, který jde přes něj (**Test** u daného testu): výsledek uvede, že byl dosažen přes konektor.
3. Ručně, stejné přesměrování, jaké používá acme (`ssh -W`), ze stroje se stejným klíčem:

   ```sh
   ssh -i acme_relay_key -L 8443:intranet.example.local:443 -N acme-relay@connector.example.local &
   openssl s_client -connect 127.0.0.1:8443 -servername intranet.example.local </dev/null 2>/dev/null \
     | openssl x509 -noout -subject -issuer -enddate
   ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Permission denied (publickey)` | veřejný klíč není v `authorized_keys` toho uživatele, nebo jsou práva souboru/adresáře příliš volná (`700` / `600`) |
| Změněný host key | konektor byl přeinstalován: dejte nový řádek `known_hosts` do *Host key* (až po jeho ověření) |
| `channel open failed: administratively prohibited` | `AllowTcpForwarding no`, nebo volba `permitopen`, která daný server:port neuvádí |
| `channel open failed: connect failed` | konektor nedosáhne na testovaný server: firewall mezi nimi, špatná adresa, služba neběží |
| Test hlásí, že konektor neexistuje nebo je vypnutý | konektor byl smazán nebo vypnut - test nikdy potichu nejde napřímo: zapněte ho, nebo nastavte *directly* |
| Pomalé výsledky | zvyšte *Time limit (s)* u konektoru i testu |
