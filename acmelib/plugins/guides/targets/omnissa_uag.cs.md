# Omnissa Unified Access Gateway - nastavení pro acme

acme nahrazuje TLS certifikát serveru Omnissa (dříve VMware) **Unified Access Gateway (UAG)** přes jeho **administrátorské REST API** na portu 9443. Vybíráte, který certifikát:

- **Internet-facing (`END_USER`)** - výchozí: HTTPS proxy a PCoIP / Blast Secure Gateway, tedy to, co vidí klienti Horizon a prohlížeče na 443;
- **Admin interface (`ADMIN`)** - certifikát administrátorského rozhraní na 9443;
- **Both** - administrátorský se posílá jako poslední, protože se s ním restartuje jeho konektor.

U každého pošle acme klíč a certifikát s mezilehlými certifikáty v jednom požadavku (`PUT /rest/v1/config/certs/ssl/end_user` nebo `/admin`). Přihlašuje se tokenem (`POST /rest/v1/jwt/login`), nebo u staršího UAG HTTP basic autentizací. Stejný certifikát se posílá znovu jen tehdy, když ho UAG už nemá.

## Co potřebujete

- Zařízení UAG (3.x nebo novější; současné verze Omnissa používají přihlášení tokenem, starší HTTP basic).
- Přístup HTTPS z acme na administrátorské rozhraní UAG, port **9443** (u nasazení se 2 nebo 3 síťovkami: správcovská síťovka).
- Administrátorského uživatele UAG s plnými právy (výměna certifikátu je administrátorská úloha; role jen pro monitoring nestačí).
- Klíč RSA nebo ECDSA (RSA je pro starší verze UAG nejjistější volba).

## Nastavení UAG

1. Přihlaste se do administrace UAG: `https://uag01.example.local:9443/admin`.
2. Volitelně vytvořte pro acme samostatného administrátora: **Advanced Settings → Account Settings** (v novějších verzích) → přidejte administrátora, např. `acme`, s plnou administrátorskou rolí (ne *Monitoring*). Jinak použijte `admin`. Pozor na nastavení vypršení hesla - **prošlé heslo zastaví obnovování**; podle toho zvolte politiku hesel, nebo ho hlídejte.
3. Omezte, kdo dosáhne na port 9443: povolte ho jen ze správcovské sítě a ze serveru acme (firewall před správcovskou síťovkou UAG).
4. Pro dvojici UAG za load balancerem: vytvořte **jeden cíl acme pro každý UAG**.

Vyzkoušejte přihlášení ze serveru acme:

```sh
curl -s -X POST https://uag01.example.local:9443/rest/v1/jwt/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"…","refreshTokenExpiryInHours":3}'
```

Odpověď musí obsahovat `accessToken`.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | UAG (jeho správcovská adresa) |
| HTTPS port | 9443 |
| Admin user | `admin` nebo administrátor z kroku 2 |
| Password | jeho heslo |
| Sign-in (pokročilé) | token (současné verze); HTTP basic pro starší UAG |
| Check the device's certificate | vypnuto (nebo zadejte jeho CA), dokud administrátorské rozhraní nemá důvěryhodný certifikát; potom zapnuto |
| CA certificate (pokročilé) | CA certifikátu administrátorského rozhraní |
| Which certificate (nasazení) | Internet-facing (END_USER), Admin interface (ADMIN), nebo Both |
| Key format (pokročilé) | RSA / EC private key (výchozí, jak ho posílá dokumentace UAG), nebo PKCS#8 |
| Check what is served | veřejné jméno na portu 443, např. `desktop.example.com:443` |

## Ověření

- **Test** v acme přečte systémová nastavení UAG a ukáže jeho jméno (`signed in to the UAG … (uagName)`).
- V administraci: **Advanced Settings → TLS Server Certificate Settings** ukazuje používaný certifikát.
- Z příkazové řádky:

```sh
openssl s_client -connect desktop.example.com:443 -servername desktop.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the UAG gave no token at sign-in` / 401 | špatný uživatel/heslo, prošlé heslo, nebo starší UAG: nastavte *Sign-in* na HTTP basic |
| 403 | uživatel není plný administrátor |
| Chyba TLS na portu 9443 | administrátorské rozhraní má ještě self-signed certifikát: zadejte jeho CA nebo vypněte kontrolu, dokud ho *Both* nenahradí |
| PUT odmítnut (400) | klíč a certifikát k sobě nepatří, nebo formát klíče není přijat: zkuste druhý *Key format*, nebo RSA klíč |
| Prohlížeče stále vidí starý certifikát | TLS ukončuje load balancer před UAG, nebo nebyl aktualizován druhý UAG z dvojice |
| Administrace je po *Both* chvíli nedostupná | očekávané: administrátorský konektor se restartuje s novým certifikátem |
