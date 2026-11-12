# HTTP-01 na tomto serveru - nastavení pro acme

S touto validací si CA stahuje `http://JMÉNO/.well-known/acme-challenge/TOKEN` **přímo z acme**: token vrací vlastní nginx acme na portu 80. Nastavit je třeba síť a DNS před acme: jméno musí vést na acme (nebo na NAT / přesměrování portu / reverzní proxy, která tuto cestu pošle na acme) a port 80 musí být otevřený. **Ne pro wildcardy** (ty potřebují DNS-01).

## Co potřebujete

- Záznamy `A`/`AAAA` jména směřující na veřejnou adresu acme (VIP nebo uzel) - nebo na NAT, přesměrování portu či proxy před ním.
- **TCP port 80** dosažitelný z internetu na acme (CA ověřuje z několika míst světa - neomezujte podle zdrojové adresy).
- Nginx acme servírující `/.well-known/acme-challenge/` na portu 80 (ve výchozím stavu ano).

## Nastavení sítě

1. DNS: nasměrujte jméno na acme:

   ```text
   www.example.com.  300  IN  A  203.0.113.10
   ```

2. Firewall / router: povolte (nebo přesměrujte) TCP 80 na acme. Na samotném stroji s acme, běží-li lokální firewall:

   ```sh
   sudo ufw allow 80/tcp          # nebo
   sudo firewall-cmd --permanent --add-service=http && sudo firewall-cmd --reload
   ```

3. Za reverzní proxy nebo load balancerem, který jméno obsluhuje jinde: pošlete na acme přes HTTP jen cestu pro ověření, např. pro nginx:

   ```text
   location /.well-known/acme-challenge/ {
       proxy_pass http://203.0.113.10;
       proxy_set_header Host $host;
   }
   ```

4. Nedosáhne-li acme na své vlastní veřejné jméno (chybí hairpin NAT), nechte *Check before the CA is asked* vypnuté.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Check before the CA is asked | Zapnuto: acme si nejdřív samo stáhne `http://NAME/…/TOKEN`. Vypněte tam, kde tento stroj na své veřejné jméno nedosáhne |
| Address tried by Test | (pokročilé) Odkud Test stahuje zkušební token; výchozí `http://127.0.0.1` (vlastní nginx acme) |
| Addresses in front of acme | (pokročilé) Veřejné adresy NAT, přesměrování portu nebo proxy, na které jména vedou, jedna na řádek - průvodce je pak bere jako „vede na acme“ |

## Kontrola

- **Test** v acme vloží zkušební token a stáhne ho z *Address tried by Test* (nginx acme na portu 80).
- Ze stroje mimo vaši síť:

  ```sh
  dig +short A www.example.com
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

  `404` od nginxu acme (ne vypršení času) znamená, že cesta na acme dorazí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `this server does not answer a probe token` | Nginx acme neobsluhuje port 80 - zkontrolujte službu. |
| CA vyprší čas | Port 80 je blokovaný (firewall, ISP) nebo přesměrovaný na jiný stroj. |
| CA dosáhne na jiný server | Jméno vede jinam, nebo proxy neposílá cestu pro ověření na acme. |
| Vlastní kontrola selže, ale CA by uspěla | Chybí hairpin NAT - vypněte *Check before the CA is asked*. |
