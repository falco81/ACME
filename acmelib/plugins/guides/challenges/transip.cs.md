# TransIP - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **TransIP**, přes REST API v6 (`https://api.transip.nl/v6`). Přihlásí se přes `POST /v6/auth` s požadavkem podepsaným RSA-SHA512 **párem klíčů** účtu (privátní klíč nikdy neopustí acme; podepisuje openssl) a dostane krátkodobý token. Pak vypíše domény, načte DNS záznamy, pro každou hodnotu přidá jeden TXT záznam a smaže přesně tento záznam. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu u TransIP, která používá jmenné servery TransIP.
- HTTPS (TCP 443) z acme na `api.transip.nl`.
- Veřejnou IP adresu, ze které acme volá, pokud ji chcete dát na whitelist.

## Nastavení TransIP

1. Přihlaste se do **ovládacího panelu** TransIP.
2. **Account → API**: zapněte API (*API settings: On*).
3. Volitelné, ale doporučené: do **IP whitelist** přidejte veřejnou adresu, ze které acme volá.
4. **Key pairs → Generate a new key pair**:
   - popisek `acme`;
   - **Accept only from whitelisted IP addresses**: zapnuto, pokud jste udělali krok 3 (pak v acme nastavte *The key pair is not limited to whitelisted addresses* na **vypnuto**), nebo vypnuto (pole v acme nechte **zapnuté**).
5. Zkopírujte zobrazený **privátní klíč** - zobrazí se **jen jednou**. Vložte ho celý, včetně řádků `-----BEGIN …-----` a `-----END …-----`.

**Pozor:** pár klíčů dává plný přístup k API účtu TransIP (domény, VPS, …) - TransIP nemá klíč jen pro DNS. Dejte přednost IP whitelistu.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Login | jméno účtu TransIP |
| Private key | privátní klíč (PEM), celý |
| The key pair is not limited to whitelisted addresses | zapnuto = klíč funguje z libovolné adresy; vypnuto = jen z adres na whitelistu - podle toho, jak byl pár klíčů vytvořen (pokročilé) |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 60 (TransIP zná 60, 300, 3600, 86400; jiná hodnota se zvýší; pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše domény; nic nemění.
- Po objednávce: ovládací panel → **Domains →** doména → **DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.nl @ns0.transip.net
```

## Časté problémy

| Problém | Řešení |
|---|---|
| „Signature not valid“ / `401` při přihlášení | Login a pár klíčů k sobě nepatří, nebo byl klíč vložen neúplně. |
| „This key pair may only be used from whitelisted IPs“ | Přidejte adresu acme na whitelist, nebo nastavte pole v acme podle páru klíčů. |
| API odmítá, ačkoli klíč je správný | API je vypnuté v **Account → API**. |
| Doména není ve výpisu | Doména je v jiném účtu TransIP nebo používá jiné jmenné servery. |
