# ISPConfig - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS zóně, kterou spravuje panel **ISPConfig 3**. Používá Remote API panelu (transport JSON, `https://PANEL:8080/remote/json.php`): `login`, `dns_zone_get` (zóna), `dns_rr_get_all_by_zone` (záznamy), `dns_txt_add` s `update_serial: true` (naše hodnota, zvýšené sériové číslo SOA), `dns_txt_delete` podle id záznamu a `logout`. Ostatní hodnoty na stejném jménu zůstanou. ISPConfig změny aplikuje svým serverovým cronem zhruba o minutu později; acme čeká, dokud hodnotu neodpovídají jmenné servery zóny.

Ověřeno proti ISPConfig 3.3.2p1; ostatní verze 3.x s JSON remote API fungují stejně.

## Co potřebujete

- Panel ISPConfig 3, jehož DNS modul obsluhuje zónu (BIND/PowerDNS serveru je pro ni autoritativní).
- HTTPS z acme na panel, obvykle **TCP 8080**.
- Přístup admina panelu pro vytvoření vzdáleného uživatele.

## Nastavení ISPConfigu

1. Přihlaste se do panelu jako **admin**.
2. **System → Remote Users → Add new user**:
   - *Username* `acme`, dlouhé náhodné *Password*.
   - **Remote Access**: zaškrtněte a do povolených adres (*Remote Access IPs / Hostnames*) zadejte adresu, ze které acme volá.
   - **Functions**: zaškrtněte jen **DNS zone functions** a **DNS txt functions**.
3. Ověřte, že je Remote API povoleno v bezpečnostním nastavení panelu (`/usr/local/ispconfig/security/security_settings.ini`, položka `remote_api_allowed` - výchozí je `yes`).
4. Patří-li zóna klientovi a chcete záznamy počítat jemu, poznamenejte si ID klienta (**Client →** klient; viz *Client ID* níže).

Z sítě acme ověřte, že API odpovídá:

```sh
curl -s https://panel.example.com:8080/remote/json.php?login \
  -d '{"username":"acme","password":"HESLO"}'
# {"code":"ok","message":"","response":"<id relace>"}
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Panel address | `panel.example.com:8080` (jméno, jméno:port nebo `https://…`; bez portu 8080) |
| Remote user | `acme` |
| Password | heslo vzdáleného uživatele |
| Zone | prázdné (vybráno ze seznamu panelu nebo dohledáno), nebo zóna |
| Client ID | `0` = vlastní klient vzdáleného uživatele (pokročilé); případně ID klienta ISPConfigu |
| TTL (s) | 60 (nejméně, co ISPConfig přijme; pokročilé) |
| Check the panel's certificate | zapnuto; vypněte jen u panelu se self-signed certifikátem, který nejde vyměnit |

## Ověření

- V acme stiskněte **Test**: přihlásí se a s vyplněnou *Zone* spočítá záznamy zóny; jinak vypíše zóny, které uživatel vidí. Nic nemění.
- Po objednávce: **DNS →** zóna → **Records**: TXT záznam `_acme-challenge...` se objeví a zase se smaže.

## Časté problémy

| Problém | Řešení |
|---|---|
| `remote_fault` „The login failed“ | Špatný uživatel/heslo, nebo adresa acme není mezi povolenými adresami vzdáleného uživatele. |
| „You do not have the permissions to access this function“ | Zaškrtněte vzdálenému uživateli **DNS zone functions** a **DNS txt functions**. |
| Connection refused / timeout | Port 8080 blokuje firewall mezi acme a panelem. |
| Záznam je v panelu, ale ne v DNS | Serverový cron ještě neproběhl nebo se DNS server nenačetl znovu - viz `/var/log/ispconfig/cron.log`. |
| Chyba certifikátu | Panel má self-signed certifikát: nasaďte řádný, nebo vypněte *Check the panel's certificate*. |
