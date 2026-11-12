# froxlor - nastavení pro acme

acme nastavuje SSL certifikát domén ve froxloru přes jeho API (`api.php`, ve stylu JSON-RPC). U každé domény přečte současný certifikát (`Certificates.get`), poprvé ho přidá (`Certificates.add`), jinak nahradí (`Certificates.update`), s certifikátem, klíčem a řetězcem jako PEM text. Konfiguraci webového serveru pak zapíše **cron** froxloru - nový certifikát se podává po jeho dalším běhu. Psáno pro froxlor 2.x (ověřeno s 2.3.16).

## Co potřebujete

- froxlor 2.x se zapnutým externím API.
- Přístup HTTPS z acme na panel froxloru (kde je `api.php`), obvykle port 443.
- API klíč a secret účtu froxloru, který smí používat API a spravovat certifikáty domén (admin, nebo zákazník, kterému domény patří).
- Domény **nesmí** používat vlastní Let's Encrypt froxloru - froxlor odmítne certifikát pro doménu, kterou spravuje sám.

## Nastavení froxloru

1. Jako admin froxloru zapněte API: **System → Settings → froxlor API** (zapnout API) a uložte. Ověřte, že cron froxloru běží (`froxlor_master_cronjob` / cron `froxlor-cli`, podle instalace).
2. Povolte přístup k API účtu, který bude acme používat: v **Resources → Admins** (nebo **Resources → Customers**) upravte účet a zapněte **API access**. Použijte účet s nejmenšími právy, kterému domény patří: zákazníka pro jeho domény, admina jen když jde o domény více zákazníků.
3. Přihlaste se jako ten účet a vytvořte klíč: **(vaše jméno vpravo nahoře) → API keys → Create new key**. **Allowed from** nastavte na IP adresu acme serveru, případně i platnost. Zkopírujte **API key** a **API secret**.
4. U každé domény: **Domains → (doména) → Edit → SSL** - **vypněte** pro doménu „Let's Encrypt“ (jinak bude certifikát acme odmítnut) a SSL pro ni nechte zapnuté.

Klíč vyzkoušejte z acme serveru:

```sh
curl -s -u "$API_KEY:$API_SECRET" -H 'Content-Type: application/json' \
     -d '{"command":"Froxlor.listFunctions"}' https://froxlor.example.com/api.php
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Panel address | URL froxloru, např. `https://froxlor.example.com` (acme tam volá `api.php`) |
| API key | klíč z kroku 3 |
| API secret | secret z kroku 3 |
| Check the device's certificate | zapnuto; vypnout jen dokud má panel self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu panelu, když není veřejná |
| Domains (nasazení) | jména domén ve froxloru, jedno na řádek, přesně jak jsou tam pojmenované |
| Check what is served | `www.example.com:443`, jeden na řádek - až po běhu cronu froxloru |

## Ověření

- **Test** v acme zavolá `Froxlor.listFunctions` a ohlásí, kolik funkcí API je povoleno.
- Po nasazení ukazuje froxlor v **Domains → (doména) → SSL** nový certifikát; po běhu cronu:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

Na serveru froxloru můžete cron spustit hned, místo čekání (cesta a volby podle instalace - ověřte `froxlor-cli list` své verze), např.:

```sh
sudo /var/www/froxlor/bin/froxlor-cli froxlor:cron --force
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `froxlor does not let acme in (401/403)` | špatný klíč/secret, API je vypnuté, účet nemá přístup k API, nebo *Allowed from* nezahrnuje IP acme |
| `froxlor said 406 … sslcertificateisletsencryptmanaged` | doména používá Let's Encrypt froxloru - vypněte ho pro doménu |
| `froxlor said 404/406` u domény | jméno domény není ve froxloru nebo nepatří účtu |
| Certifikát nastaven, ale podává se starý | cron froxloru ještě neběžel (nebo je rozbitý) - zkontrolujte cron |
| `no domain is set` | vyplňte *Domains* v nasazení |
