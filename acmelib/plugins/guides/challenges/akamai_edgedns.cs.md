# Akamai Edge DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v Akamai Edge DNS (dříve Fast DNS): přes **Zone Management API v2** Edge DNS (`/config-dns/v2`), podepsané metodou EdgeGrid, přečte sadu záznamů TXT `_acme-challenge.JMÉNO`, přidá svou hodnotu a sadu zapíše zpět; při úklidu odebere jen svou hodnotu. **Jen primární zóny** (sekundární a alias zóny zapsat nelze).

## Co potřebujete

- Smlouvu s Akamai s Edge DNS a zónu typu **PRIMARY**.
- Přístup do Akamai Control Center pro vytvoření API klienta.
- Odchozí HTTPS z acme na váš API host `akab-xxxxxxxx.luna.akamaiapis.net` (port 443).

## Nastavení Akamai

1. Control Center → **Identity and access → API clients → Create API client** (samostatný klient pro acme, ne klient vašeho uživatele).
2. Mezi službami API mu přidělte **DNS—Zone Record Management** s přístupem **READ-WRITE**. Nic dalšího není potřeba.
3. Má-li smlouva více skupin, omezte klienta na skupinu se zónami, které smí acme měnit.
4. Vytvořte credential a stáhněte ho (nebo zkopírujte sekci `.edgerc`). Obsahuje čtyři hodnoty:

   ```text
   [default]
   host = akab-xxxxxxxx.luna.akamaiapis.net
   client_token = akab-...
   client_secret = ...
   access_token = akab-...
   ```

5. Používáte-li u API klientů seznam povolených IP adres, přidejte veřejnou adresu acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API host | `host` z `.edgerc`, např. `akab-xxxxxxxx.luna.akamaiapis.net` |
| Client token | `client_token` |
| Client secret | `client_secret` |
| Access token | `access_token` |
| Zone | Zóna, např. `example.com`; prázdné = nejdelší primární zóna viditelná klientovi, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` (nejméně 30) |

## Kontrola

- **Test** v acme podepíše požadavek a vypíše primární zóny, které klient vidí. Nic nemění.
- Po běhu se zeptejte jednoho z vlastních jmenných serverů zóny (z `dig NS example.com`):

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<jeden z těchto serverů>
  ```

- V Control Center ukazuje seznam záznamů zóny (Edge DNS → zóna) záznam TXT `_acme-challenge`, dokud běh probíhá.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / chyby podpisu | Hodnota z `.edgerc` byla zkopírována s mezerami nebo prohozená; nebo nesedí čas stroje s acme (EdgeGrid podepisuje čas) - zkontrolujte NTP. |
| `403` | Klient nemá *DNS—Zone Record Management* READ-WRITE, nebo je omezen na jinou skupinu. |
| Zóna není v seznamu | Je sekundární nebo alias - zapisovat lze jen do primárních zón. |
| `no API host is set` | Vyplňte *API host* (bez `https://`). |
