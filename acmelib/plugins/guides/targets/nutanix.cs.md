# Nutanix cluster - nastavení pro acme

acme nahrazuje **SSL certifikát clusteru Nutanix** - certifikát jeho webové konzole Prism (Element) a API - přes **v4 API Prism Central** (port 9440, HTTP basic autentizace uživatele Prism Central). Přečte ETag současného certifikátu (`GET …/clusters/<extId>/ssl-certificate`), pošle certifikát, klíč a řetězec s algoritmem klíče (`PUT …/ssl-certificate` s `If-Match`) a čeká, až úloha, kterou Prism Central spustí, skončí stavem `SUCCEEDED`. Webová konzole clusteru se pak restartuje s novým certifikátem.

## Co potřebujete

- Prism Central, který poskytuje **v4** API `clustermgmt` a `prism` (v4.0 - v4.3; v acme je výchozí v4.3 - ověřte v referenci API svého Prism Central), s clusterem v něm registrovaným.
- Přístup HTTPS z acme na Prism Central, port **9440**.
- Uživatele Prism Central, který smí měnit SSL certifikát clusterů.
- Klíč certifikátu, který Nutanix přijímá: **ECDSA P-256 / P-384 / P-521 nebo RSA 2048 / 4096** (ne RSA 3072).

## Nastavení Prism Central

1. Vytvořte pro acme lokálního uživatele: **Admin Center → IAM → Identities → Local Users → Add Local User** (ve starším Prism Central: **Settings → Local User Management**), např. `acme`, se silným heslem. Funguje i uživatel z adresáře (AD/LDAP), pokud se umí přihlásit HTTP basic autentizací.
2. Dejte mu práva: **Admin Center → IAM → Authorization Policies** - přidělte na dotčených clusterech roli, která smí měnit SSL certifikát clusteru. Vestavěné **Prism Admin** / **Super Admin** to umí; u vlastní role zahrňte oprávnění správy clusteru pro změnu SSL certifikátu a pro čtení clusterů a úloh. Ověřte tlačítkem **Test** v acme a prvním nasazením.
3. Poznamenejte si **extId** nebo jméno clusteru - v acme ho vyplní *Clusters of Prism Central → Load the list*.
4. Vystavte certifikát v acme s podporovaným typem klíče (viz výše) a s virtuální IP / FQDN clusteru mezi jmény.

Ověření ze serveru acme:

```sh
curl -s -u acme:'…' https://prism-central.example.local:9440/api/clustermgmt/v4.3/config/clusters | head -40
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | adresa Prism Central |
| HTTPS port | 9440 |
| User / Password | uživatel Prism Central z kroku 1 (výchozí `admin` - lépe vyhrazený) |
| Cluster | extId nebo jméno clusteru |
| Clusters of Prism Central | *Load the list* a vybrat: vyplní *Cluster* |
| API version (pokročilé) | verze v4, kterou váš Prism Central poskytuje (výchozí `v4.3`) |
| Check the device's certificate | zapnuto; vypnout jen dokud má Prism Central self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu Prism Central, když není veřejná |
| Key algorithm (nasazení, pokročilé) | *as the certificate's key* (výchozí), nebo vynutit konkrétní |
| Wait for the task (s) (pokročilé) | 600 |
| Check what is served | VIP / FQDN clusteru, port 9440, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí do Prism Central a přečte současný certifikát clusteru (ukáže algoritmus jeho klíče).
- Po nasazení ukazuje Prism Central v **Tasks** úlohu certifikátu jako úspěšnou; pak:

```sh
openssl s_client -connect cluster.example.local:9440 -servername cluster.example.local </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

- V Prism Element: **Settings → SSL Certificate** ukazuje nový certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 | špatný uživatel/heslo, nebo uživatel nemůže použít basic autentizaci |
| 403 | role uživatele nesmí měnit SSL certifikát clusteru |
| 404 u volání clusterů | Prism Central tuto *API version* neposkytuje; zvolte starší nebo aktualizujte |
| `Prism Central has no cluster named "…"` | použijte extId nebo vyberte ze seznamu |
| `Nutanix takes ECDSA P-256/P-384/P-521 and RSA 2048/4096 keys …` | vystavte certifikát znovu s podporovaným klíčem |
| `the task … failed …` | podívejte se na úlohu v Prism Central; často jde o řetězec nebo jména |
| `the task … has not finished in … s` | zvyšte *Wait for the task (s)*; restart konzole může trvat minuty |
