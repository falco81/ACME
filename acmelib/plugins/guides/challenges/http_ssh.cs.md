# Webové servery přes SSH (HTTP-01) - nastavení pro acme

acme prokazuje jména přes HTTP-01 na **vašich webových serverech**: přihlásí se přes SSH ke **každému** webovému serveru, na který jméno vede (DNS round-robin nebo za load balancerem), zapíše soubor s tokenem do `/var/www/acme-challenge/.well-known/acme-challenge/`, ověří ho přes HTTP, nechá ho CA stáhnout a ze všech hostitelů ho odebere. Všichni hostitelé musí uspět (CA se může zeptat kteréhokoli). Samotné acme nikdy nemusí být z internetu dosažitelné. Pro nginx (který si acme umí nastavit samo), Apache nebo jakýkoli server, který tuto složku servíruje. **Ne pro wildcardy** (ty potřebují DNS-01).

## Co potřebujete

- Přístup přes SSH z acme na každý webový server (port 22, nebo `host:port`).
- Jméno směřující na webové servery (nebo load balancer / NAT před nimi), odpovídající do internetu na **TCP portu 80**.
- Blok webového serveru na portu 80, který servíruje `/.well-known/acme-challenge/` ze složky s tokeny.

## Nastavení webových serverů

1. Na **každém** webovém serveru účet, který smí zapisovat jen do složky s tokeny:

   ```sh
   useradd -r -m -s /bin/sh acme
   install -d -o acme -g acme -m 0755 /var/www/acme-challenge/.well-known/acme-challenge
   ```

2. Veřejný klíč acme (zobrazený u *The SSH key*) vložte do `~acme/.ssh/authorized_keys`, nejlépe omezený:

   ```text
   restrict,from="203.0.113.10" ssh-ed25519 AAAA... acme
   ```

3. V acme připněte host key každého serveru (*Host keys*):

   ```sh
   ssh-keyscan -t ed25519 web1.example.com
   ```

4. **nginx**: nechte to na acme - akce **Prepare the hosts** (tlačítko na řádku validace) najde nginx, zapíše `/etc/nginx/conf.d/acme-challenge.conf` (nebo řádek include do vašich stávajících bloků na portu 80), spustí `nginx -t` a znovu načte konfiguraci; potřebuje root nebo sudo bez hesla pro `sh`. Nebo ručně blok na portu 80:

   ```text
   server {
       listen 80 default_server;
       listen [::]:80 default_server;
       server_name _;
       location ^~ /.well-known/acme-challenge/ {
           root /var/www/acme-challenge;
           default_type text/plain;
           try_files $uri =404;
       }
       location / { return 301 https://$host$request_uri; }
   }
   ```

5. **Apache**: `Alias /.well-known/acme-challenge/ /var/www/acme-challenge/.well-known/acme-challenge/` s `Require all granted`, před jakýmkoli přesměrováním.
6. Zapisuje-li účet místo toho přes sudo (*Write through sudo*), řádek sudoers přesně pro to:

   ```text
   acme ALL=(root) NOPASSWD: /usr/bin/mkdir -p /var/www/acme-challenge/.well-known/acme-challenge, \
        /usr/bin/install -m 644 /tmp/.acme-* /var/www/acme-challenge/.well-known/acme-challenge/*, \
        /usr/bin/rm -f /var/www/acme-challenge/.well-known/acme-challenge/*
   ```

7. Otevřete TCP 80 ve firewallu hostitele (`firewall-cmd --add-service=http --permanent`, `ufw allow 80/tcp`) - nebo zapněte *Open port 80 in their firewall*. Za load balancerem propouštějte `/.well-known/acme-challenge/` na portu 80 na všechny členy poolu.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Web servers | Každý stroj, který odpovídá na `http://NAME/`, jeden na řádek (`host` nebo `host:port`) |
| User, Signs in with, The SSH key, Password | Účet SSH (výchozí `acme`) a jeho klíč nebo heslo |
| Host keys, Trust the first key seen | Připnuté řádky `known_hosts`, nebo důvěra prvnímu viděnému klíči |
| Folder of the tokens | Výchozí `/var/www/acme-challenge/.well-known/acme-challenge` |
| Write through sudo | Zapnout, zapisuje-li účet přes `sudo -n install` |
| Check before the CA is asked | Každý stroj podle jeho adresy (výchozí), na jiných adresách (LB / NAT), podle jména, nebo vůbec |
| Check at, Name for Test | Pro kontrolu na load balanceru / veřejné IP a jméno Host, které posílá Test |
| Public addresses (NAT, load balancer) | Adresy před webovými servery, na které jména vedou |
| Names acme's own block answers for, How "Prepare" sets nginx up, Set nginx up by itself, Open port 80 in their firewall | Jak akce *Prepare the hosts* nastaví nginx |
| File mode, Command after writing, HTTP port for the check, nginx file "Prepare" writes | (pokročilé) |

## Kontrola

- **Test** zapíše na každého hostitele zkušební soubor, přečte ho zpět přes SSH, stáhne ho přes HTTP z tohoto hostitele (s *Host: NAME*) a odebere ho.
- Ručně:

  ```sh
  ssh acme@web1.example.com 'ls -ld /var/www/acme-challenge/.well-known/acme-challenge'
  curl -i -H 'Host: www.example.com' http://192.0.2.21/.well-known/acme-challenge/test
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| Host key odmítnut | Připněte host key (*Host keys*) nebo zapněte *Trust the first key seen*. |
| `Permission denied` při zápisu | Účet nesmí do složky zapisovat - opravte vlastnictví, nebo použijte *Write through sudo*. |
| `port 80 … does not answer` / `No route to host` | Firewall hostitele zavírá port 80 - otevřete ho (nebo *Open port 80 in their firewall*). |
| `written but not served over HTTP` | nginx tuto složku neservíruje - spusťte *Prepare the hosts* nebo přidejte blok. |
| Jeden hostitel selže, selžou všichni | Každý webový server musí uspět - opravte nebo odeberte selhávajícího hostitele. |
