# DNS server přes SSH - nastavení pro acme

acme se přihlásí **na váš vlastní autoritativní DNS server přes SSH** a TXT záznam vloží přímo do zóny tam - bez API a bez TSIG klíče po síti. Umí BIND (`nsupdate -l`, `nsupdate -k`, nebo úprava souboru zóny + `rndc reload`), PowerDNS (`pdnsutil` nebo jeho HTTP API na localhostu), Knot DNS (transakce `knotc`), NSD (soubor zóny + `nsd-control reload`), dnsmasq (řádky `txt-record`), Unbound (`unbound-control local_data`), Windows DNS (PowerShell přes OpenSSH) a vlastní příkazy. Přidává a odebírá jen vlastní hodnotu acme; ostatní TXT záznamy na jménu zůstanou.

**Find out what runs there** (tlačítko pod formulářem) se přihlásí a spustí **jen příkazy pro čtení**, pak vyplní formulář: jaký server, jeho zóny a soubory, klíče, zda funguje sudo.

## Co potřebujete

- SSH (TCP 22 nebo váš port) z acme na DNS server - **primární** server zóny (sekundární dostanou změnu přes NOTIFY).
- Vyhrazený účet tam (např. `acme`) s veřejným SSH klíčem acme.
- Práva, která účet potřebuje pro zvolené *How* (níže) - členství ve skupině nebo úzké pravidlo sudo.

## Nastavení DNS serveru

1. Vytvořte účet a povolte klíč acme (vytvořený ve formuláři acme, ed25519):

   ```sh
   useradd -m -s /bin/sh acme
   install -d -m 700 -o acme -g acme ~acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' >> ~acme/.ssh/authorized_keys
   chown acme:acme ~acme/.ssh/authorized_keys; chmod 600 ~acme/.ssh/authorized_keys
   ```

2. Připněte v acme klíč hostitele serveru (*Host keys*):

   ```sh
   ssh-keyscan -t ed25519 ns1.example.com
   ```

3. Dejte práva pro zvolený způsob - **BIND s `nsupdate -l` je nejjednodušší** (žádný klíč ke správě):

   ```text
   zone "example.com" {
       type primary;
       file "/var/lib/bind/db.example.com";        # adresář, kam smí named zapisovat (žurnál)
       update-policy { grant local-ddns zonesub TXT; };
   };
   ```

   pak `rndc reconfig` a dovolte účtu číst `/run/named/session.key`: `usermod -aG bind acme` (Debian; na RHEL skupina `named`), nebo *Through sudo* s:

   ```text
   acme ALL=(root) NOPASSWD: /usr/bin/nsupdate
   ```

   Ostatní způsoby stručně:

   | How | Práva, která účet potřebuje |
   |---|---|
   | `nsupdate -k KEYFILE` | číst soubor s klíčem TSIG (`tsig-keygen -a hmac-sha256 acme-key`), povoleným v `update-policy` |
   | soubor zóny BIND | zapisovat do souboru a jeho adresáře, spouštět `rndc` (skupina `bind`), nebo sudo na `/bin/sh -s` (shell roota - raději skupina) |
   | `pdnsutil` | `acme ALL=(root) NOPASSWD: /usr/bin/pdnsutil` (nebo skupina backendu) |
   | HTTP API PowerDNS | `api=yes`, `api-key=…`, `webserver=yes`, `webserver-address=127.0.0.1`; `curl` na serveru |
   | Knot | skupina `knot` (řídicí socket) nebo `acme ALL=(root) NOPASSWD: /usr/sbin/knotc` |
   | NSD | proveden `nsd-control-setup`; zápis do souborů zón (sudo) |
   | dnsmasq | `conf-dir=/etc/dnsmasq.d/,*.conf`; sudo pro soubor a `systemctl restart dnsmasq` |
   | Windows DNS | OpenSSH Server; účet ve skupině **DnsAdmins** |

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| DNS server | `ns1.example.com:22` |
| User / Signs in with / The SSH key | `acme`, privátní klíč (vytvořený zde) |
| Host keys | řádek/řádky z `ssh-keyscan`; nebo *Trust the first key seen* |
| How | podle návrhu *Find out what runs there*, např. `nsupdate -l` |
| Through sudo | zapnout jen tehdy, pokud jste výše nastavili pravidlo sudo |
| Zone / Zones there | prázdné (vyplní *Find out*), nebo zóna/zóny |
| Key file there / Zone files / … | jen pole zobrazená pro zvolené *How* |
| TTL (s) | 60 (pokročilé) |

## Ověření

- **Find out what runs there**: jen čte, ukáže, co by acme dělal.
- **Test** nic nemění: ověří nsupdate a klíč, načte a zkontroluje soubory zón, spustí `rndc status` / `pdnsutil list-all-zones` / `knotc zone-status` … `nsupdate -l` nelze vyzkoušet bez změny zóny.
- **Zkušební běh (dry run)** certifikátu vloží náhodný testovací TXT záznam, počká, až ho jmenné servery odpovídají, a zase ho odebere.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.example.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Klíč hostitele odmítnut | Klíč serveru se změnil nebo není připnut - aktualizujte *Host keys*. |
| `nsupdate`: „update failed: REFUSED“ | `update-policy` nemá `local-ddns` (nebo klíč) pro TXT. |
| „permission denied“ u `session.key` | Přidejte účet do skupiny `bind`/`named`, nebo použijte sudo. |
| `sudo: a password is required` | Chybí řádek v sudoers nebo uvádí jinou cestu (`command -v nsupdate`). |
| Soubor zóny odmítnut | `$INCLUDE`, více SOA nebo zóna ve formátu raw/map - použijte dynamickou zónu (`nsupdate`). |
| Windows: záznam se neodebral | *Zone* musí být zóna přesně tak, jak ji ukazuje DNS Manager. |
