# Huawei Cloud DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 ve **veřejné** zóně Huawei Cloud DNS: přes DNS API v2 regionu (`https://dns.{region}.myhuaweicloud.com`), kde je každý požadavek podepsán přístupovým klíčem (AK/SK, SDK-HMAC-SHA256), přidá svou hodnotu do sady záznamů TXT `_acme-challenge.JMÉNO` (nebo sadu vytvoří) a při úklidu sadu zapíše zpět bez ní - nebo ji smaže, byla-li jeho hodnota poslední.

## Co potřebujete

- Veřejnou zónu v Huawei Cloud DNS, s doménou delegovanou na jmenné servery Huawei Cloud.
- Uživatele IAM pro acme s přístupovým klíčem.
- Odchozí HTTPS z acme na `dns.{region}.myhuaweicloud.com` (port 443).
- **Čas stroje s acme do 15 minut** od skutečného času (podepsané požadavky).

## Nastavení Huawei Cloud

1. Konzole → **Identity and Access Management (IAM) → Users → Create User**: např. `acme-dns`, typ přístupu jen **Programmatic access** (přístupový klíč).
2. Zařaďte uživatele do skupiny (nebo přiřaďte přímo) s politikou pro DNS. Nejjednodušší je systémová politika **DNS FullAccess**; minimální je vlastní politika povolující jen:

   ```text
   dns:zone:list
   dns:recordset:list
   dns:recordset:create
   dns:recordset:update
   dns:recordset:delete
   ```

   (názvy akcí ověřte v seznamu akcí DNS v konzoli IAM pro váš region).
3. Stáhněte **přístupový klíč** (`credentials.csv`: AK a SK) - SK se zobrazí jen jednou.
4. Poznamenejte si **region**, jehož endpoint má acme použít, např. `ap-southeast-1`, `cn-north-4`.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Access key ID (AK) | AK |
| Secret access key (SK) | SK |
| Region | např. `ap-southeast-1` |
| Zone | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší veřejná zóna viditelná klíči, ve které jméno leží |
| Project ID | (pokročilé) Jen kde to Huawei Cloud vyžaduje (více projektů v regionu, Dedicated Cloud) |
| Security token | (pokročilé) Jen pro dočasný AK/SK |
| TTL (s) | (pokročilé) Výchozí `300` |
| API address | (pokročilé) Prázdné = `https://dns.{region}.myhuaweicloud.com` |

## Kontrola

- **Test** v acme vypíše veřejné zóny, které klíč vidí - nebo při vyplněné *Zone* ověří tuto zónu. Nic nemění.
- Po běhu se zeptejte jmenných serverů zóny:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<jeden z těchto serverů>
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `APIGW.0301` / chyby podpisu | Špatný SK, nebo se čas stroje s acme liší o víc než 15 minut. |
| `403` / chybí oprávnění | Politice uživatele chybí některá z akcí DNS. |
| `DNS.0314` (not in a steady state) | Sada je ještě ve stavu pending; acme počká a zkusí znovu. |
| Zóna není v seznamu | Je soukromá, nebo v jiném regionu / projektu - vyplňte *Region* (a *Project ID*). |
