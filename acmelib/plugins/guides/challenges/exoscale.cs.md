# Exoscale - nastavení pro acme

acme prokazuje jména přes DNS-01 v Exoscale DNS: přes Exoscale API v2 (požadavky podepsané EXO2-HMAC-SHA256) přidá do domény DNS záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Přihlašuje se klíčem API z IAM, jehož role povoluje jen operace DNS, které používá.

## Co potřebujete

- Doménu v Exoscale DNS (předplatné DNS organizace) delegovanou na jmenné servery Exoscale.
- Odchozí HTTPS z acme na `api-ch-gva-2.exoscale.com` (nebo zvolenou zónu API), port 443.
- Správný čas na stroji s acme (podpisy vyprší).

## Nastavení Exoscale

1. Portál (`portal.exoscale.com`) → **IAM → Roles → Add**: např. `acme-dns`.
2. V politice role povolte jen operace služby **DNS**, které acme volá - vše ostatní ve výchozím stavu zakažte:
   - `list-dns-domains`
   - `list-dns-domain-records`
   - `create-dns-domain-record`
   - `delete-dns-domain-record`
3. **IAM → API keys → Add**: jméno `acme`, role `acme-dns`. Zkopírujte **key** (`EXO…`) a **secret** (zobrazí se jen jednou).
4. Nebo v Exoscale CLI (syntaxi politiky vaší verze najdete v `exo iam role create --help`):

   ```sh
   exo iam api-key create acme acme-dns
   ```

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč, `EXO…` |
| API secret | Secret |
| Domain | např. `example.com`; prázdné = nejdelší doména organizace, ve které jméno leží |
| API zone | (pokročilé) Výchozí `ch-gva-2`; DNS je ze všech zón stejné |
| TTL (s) | (pokročilé) Výchozí `60` |

## Kontrola

- **Test** v acme vypíše domény DNS organizace. Nic nemění.
- V CLI:

  ```sh
  exo dns list
  exo dns show example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` / forbidden | Role nepovoluje některou ze čtyř operací DNS. |
| `401` / chyby podpisu | Špatný secret, nebo nesedí čas stroje s acme. |
| Doména není v seznamu | Je v jiné organizaci, nebo klíč API patří jiné organizaci. |
