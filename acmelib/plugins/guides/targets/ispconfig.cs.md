# ISPConfig - nastavení pro acme

acme zapisuje certifikát, jeho klíč a řetězec do SSL nastavení webů v ISPConfig 3 přes **Remote API** (JSON transport, `https://<panel>:8080/remote/json.php`). U každého webu ho přečte (`sites_web_domain_get`) a aktualizuje (`sites_web_domain_update`) se zapnutým SSL, s vlastním Let's Encrypt panelu pro ten web **vypnutým** a s `ssl_action=save`. Vlastní práci pak udělá **cron** ISPConfigu na serveru: zapíše soubory a reloaduje webový server, obvykle do minuty nebo dvou. Psáno pro ISPConfig 3.3 (ověřeno s 3.3.2p1).

## Co potřebujete

- ISPConfig 3 (doporučeno 3.2 a novější) s panelem dosažitelným z acme přes HTTPS - standardně port **8080**.
- **Remote uživatele** se skupinou funkcí **Sites Domain functions**.
- Běžící cron ISPConfigu na serveru (ten dělá samotnou práci).

## Nastavení ISPConfigu

1. Přihlaste se do panelu jako `admin`.
2. Jděte do **System → Remote Users → Add new user**:
   - **Username**: `acme`, silné **Password**;
   - **Remote Access**: zapnuto, a **Remote Access IPs / Hostnames**: adresa acme serveru (jen ten smí tohoto uživatele používat);
   - **Functions**: zaškrtněte jen **Sites Domain functions**.
3. Uložte.
4. Poznamenejte si domény webů, které mají certifikát dostat (**Sites → Websites**). U každého acme vypne Let's Encrypt ISPConfigu - **znovu ho nezapínejte**, jinak ISPConfig certifikát od acme nahradí.

Vyzkoušejte remote uživatele ze serveru acme:

```sh
curl -s https://panel.example.com:8080/remote/json.php?login \
     -H 'Content-Type: application/json' \
     -d '{"username":"acme","password":"…"}'
```

Odpověď musí být `{"code":"ok", … "response":"<id relace>"}`.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | jméno hostitele panelu, např. `panel.example.com` |
| HTTPS port | 8080 (výchozí port panelu ISPConfig) |
| Remote user | `acme` |
| Password | jeho heslo |
| Check the device's certificate | zapnuto; vypnout jen dokud má panel self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu panelu, když není veřejná |
| Website (nasazení) | doména webu, vybraná ze seznamu nebo napsaná |
| More websites | další domény webů, jedna na řádek |
| Client ID for the update (pokročilé) | `0`, jako v příkladu ISPConfigu |
| Check what is served | `www.example.com:443`, jeden na řádek - cron může potřebovat minutu nebo dvě |

## Ověření

- **Test** v acme se přihlásí do Remote API.
- V panelu: **Sites → Websites → (web) → SSL** ukazuje nový certifikát; **Monitor → Show Jobqueue** (nebo **System → Server Services**) ukazuje, zda cron změnu zpracoval.
- Po běhu cronu:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `ISPConfig gave no JSON (is the Remote API on, and the address the panel's?)` | špatná adresa/port, nebo místo panelu odpovídá jiná webová stránka |
| `ISPConfig said remote_fault - …` při přihlášení | špatný uživatel/heslo, vypnutý Remote Access, nebo IP acme není v Remote Access IPs |
| `ISPConfig said remote_fault - You do not have the permissions …` | zaškrtněte remote uživateli **Sites Domain functions** |
| `ISPConfig has no website "…"` | použijte hlavní doménu webu, jak je v Sites → Websites |
| Uloženo, ale podává se starý certifikát | cron ještě neběžel, nebo selhal (zkontrolujte frontu úloh a `/var/log/ispconfig/`) |
| Certifikát webu nahradil Let's Encrypt | někdo pro web znovu zapnul Let's Encrypt ISPConfigu |
