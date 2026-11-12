# Vlastní DNS server acme - nastavení pro acme

S touto validací odpovídá acme na záznamy TXT pro DNS-01 **samo** ze svého vestavěného autoritativního DNS serveru - nepotřebuje přístupové údaje k cizímu DNS. Nastavit je třeba vaše DNS: jednou delegujete na acme zónu (např. `acme.example.net`) a jednou pro každé jméno nasměrujete `_acme-challenge.JMÉNO` na acme záznamem CNAME. Potom acme vkládá a odebírá záznamy TXT samo. Viz také `docs/dns-server.md`.

## Co potřebujete

- Zónu pro DNS server acme, např. `acme.example.net`, nastavenou v **Settings → DNS server** (`dns_zone`), s jmény NS a glue adresami (`dns_ns_names`, `dns_ns_addresses`).
- **UDP i TCP port 53** acme dosažitelný z internetu (veřejná adresa nebo přesměrování portu na firewallu). Nic jiného z acme dosažitelné být nemusí.
- Přístup k nadřazené zóně (`example.net`) pro přidání delegace a k DNS každého jména pro přidání jednoho CNAME.

## Nastavení vašeho DNS

1. V **nadřazené zóně** (`example.net`) jednou delegujte zónu acme:

   ```text
   acme.example.net.        NS   ns1.acme.example.net.
   acme.example.net.        NS   ns2.acme.example.net.   ; druhý uzel clusteru
   ns1.acme.example.net.    A    203.0.113.10            ; glue: veřejná adresa acme
   ns2.acme.example.net.    A    203.0.113.11
   ```

2. Na firewallu otevřete (nebo přesměrujte) UDP i TCP port 53 na acme.
3. Pro **každé jméno** certifikátu jednou v DNS toho jména (podle volby *Where in that zone*):

   | Where in that zone | Záznam |
   |---|---|
   | NAME.zone (výchozí) | `_acme-challenge.www.example.com. CNAME www.example.com.acme.example.net.` |
   | a fixed label | `_acme-challenge.www.example.com. CNAME validation.acme.example.net.` |
   | `_acme-challenge.NAME` itself | `_acme-challenge.www.example.com. NS ns1.acme.example.net.` - a přidejte `_acme-challenge.www.example.com` mezi zóny acme |

   Wildcard `*.example.com` používá stejný záznam jako `example.com`.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| acme's zone | Jedna ze zón v Settings → DNS server, např. `acme.example.net`; prázdné = první |
| Where in that zone | `NAME.zone`, `a fixed label` nebo `_acme-challenge.NAME itself` - musí odpovídat záznamům výše |
| The fixed label | Při *a fixed label*: návěští, výchozí `validation` |
| Refuse a name not pointed at acme | Zapnuto: jméno, jehož CNAME nevede na acme, ihned selže a acme ukáže záznam k přidání |
| Names to check in Test | Jména, jejichž CNAME má Test ověřit, jedno na řádek |
| Test from outside | Zapnuto (výchozí): Test vloží krátkodobý záznam TXT a zeptá se na něj veřejných resolverů |
| TTL of the records (s), Public resolvers, Resolvers | (pokročilé) výchozí hodnoty stačí |

## Kontrola

- **Test** v acme vypíše záznamy, které je pro vaše nastavení třeba vložit, zeptá se vlastního serveru acme, přes veřejné resolvery ověří, že internet posílá zónu na acme, vloží zkušební záznam a hledá ho zvenku, a vyhledá CNAME každého jména z *Names to check in Test*.
- Z libovolného stroje v internetu:

  ```sh
  dig +short NS acme.example.net
  dig @203.0.113.10 SOA acme.example.net +norecurse
  dig +short CNAME _acme-challenge.www.example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `acme's DNS server does not answer on … port 53` | Server je vypnutý nebo naslouchá jinde - viz Settings → DNS server. |
| `… is not delegated to acme yet` | Záznamy NS (a glue A) v nadřazené zóně chybí nebo jsou špatně. |
| `a test record … was not seen` | UDP/TCP 53 není z internetu dosažitelný - zkontrolujte firewall / přesměrování portu (i TCP). |
| Jméno selže s „not pointed at acme“ | Přidejte jeho CNAME `_acme-challenge` (Test ukáže přesný záznam). |
