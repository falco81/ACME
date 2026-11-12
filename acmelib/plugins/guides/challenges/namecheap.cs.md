# Namecheap - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u Namecheapu, která používá vlastní DNS Namecheapu (BasicDNS / PremiumDNS), přes **Namecheap XML API** (`https://api.namecheap.com/xml.response`): `namecheap.domains.getList`, `namecheap.domains.dns.getHosts` a `namecheap.domains.dns.setHosts`.

**`setHosts` nahradí VŠECHNY záznamy domény.** Namecheap nemá volání, které by přidalo nebo odebralo jeden záznam, takže acme načte všechny záznamy, přidá nebo odebere svou jednu TXT hodnotu a zapíše je všechny zpět spolu s EmailType domény - vždy jen jednu změnu najednou. Záznam ručně změněný přesně v tu chvíli se může ztratit. Po prvním certifikátu se jednou podívejte na doménu s neobvyklými záznamy (CAA, URL přesměrování), zda jsou v pořádku.

## Co potřebujete

- Účet Namecheap, kterému Namecheap povolí přístup k API (má podmínky, např. zůstatek na účtu nebo počet domén - viz stránka API Access).
- Doménu na **BasicDNS** nebo **PremiumDNS** Namecheapu (ne vlastní jmenné servery).
- **Veřejnou IPv4 adresu**, ze které acme chodí do internetu (za proxy nebo NAT: tu adresu).
- HTTPS (TCP 443) z acme na `api.namecheap.com`.

## Nastavení Namecheapu

1. Přihlaste se na `namecheap.com`.
2. **Profile → Tools → Business & Dev Tools → Namecheap API Access → Manage**.
3. Zapněte **API Access** a přijměte podmínky.
4. Zkopírujte **API Key**.
5. V **Whitelisted IPs → Edit → Add IP** přidejte veřejnou IPv4 adresu acme. Volání z jiné adresy Namecheap odmítne.
6. Nejste-li si adresou jisti, zjistěte ji ze stroje acme:

   ```sh
   curl -4 https://ifconfig.me
   ```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API user | vaše uživatelské jméno u Namecheapu |
| API key | klíč z kroku 4 |
| Client IP | povolená veřejná IPv4 adresa (krok 5) |
| User name the calls are for | prázdné = API user (pokročilé) |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 60 (Namecheap bere 60 až 60000; pokročilé) |
| Endpoint | `api.namecheap.com`; sandbox jen se sandboxovým účtem (pokročilé) |
| Allow rewriting every record | zapnuto - souhlas s popsaným čtením-úpravou-zápisem; vypnuto: acme odmítne doménu měnit (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény účtu; nic nezapisuje.
- Po objednávce: **Domain List → Manage →** doména → **Advanced DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí; ostatní záznamy jsou beze změny.

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba 1011150 „Invalid request IP“ | Adresa v *Client IP* (nebo ta, ze které acme skutečně volá) není na whitelistu. |
| „API Key is invalid or API access has not been enabled“ | Zapněte API Access; zkontrolujte jméno a klíč. |
| Doména odmítnuta: nepoužívá DNS Namecheapu | Nastavte doméně jmenné servery *Namecheap BasicDNS*, nebo použijte poskytovatele DNS, na kterého ukazuje. |
| Po objednávce zmizel záznam | Byl ve stejnou chvíli měněn ručně, nebo jde o typ, který getHosts nevrací - přidejte ho znovu. |
