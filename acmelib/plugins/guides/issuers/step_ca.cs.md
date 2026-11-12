# Smallstep step-ca (JWK provisioner) - nastavení pro acme

Zdroj **Smallstep step-ca (JWK provisioner)** žádá step-ca o certifikáty jeho vlastním API, bez validace ACME - pro interní jména, která ACME nedokáže prokázat. Každá žádost (`POST /1.0/sign`) nese CSR vytvořené acme a **jednorázový token**: JWT podepsaný soukromým klíčem JWK provisioneru (`iss` provisioner, `aud` `https://<ca>/1.0/sign`, `sub` první jméno, `sans` všechna jména, platnost 5 minut, otisk kořene). Odvolání je stejným způsobem `POST /1.0/revoke`. **Soukromý klíč certifikátu nikdy neopustí acme.** Pro step-ca s ACME provisionerem použijte místo toho zdroj ACME (*Another ACME server*).

## Co potřebujete

- step-ca dosažitelný **z acme** přes HTTPS (často port `9000` nebo `443`).
- **JWK provisioner** pro acme a jeho soukromý klíč, dešifrovaný.
- Kořenový certifikát step-ca (`root_ca.crt`).
- Nástroj `step` na stroji s administrátorským přístupem k CA, k vytvoření provisioneru.

## Nastavení step-ca

1. Přidejte JWK provisioner pro acme (zeptá se na heslo, které šifruje klíč):

   ```sh
   step ca provisioner add acme-jwk --type JWK --create
   ```

   Nastavte jeho limity podle vaší politiky, např. délky platnosti certifikátů v `ca.json` (`claims`: `maxTLSCertDuration`, `defaultTLSCertDuration`) a podle potřeby X.509 politiku omezující jména (`--x509-allow-dns "*.example.com"` na step-ca 0.24+).
2. Pokud step-ca změnu nepřevezme, načtěte ho znovu / restartujte (`systemctl restart step-ca`).
3. Získejte soukromý klíč provisioneru, dešifrovaný:

   ```sh
   step ca provisioner list | jq -r '.[] | select(.name=="acme-jwk") | .encryptedKey' \
     | step crypto jwe decrypt        # zeptá se na heslo provisioneru, vypíše JWK
   ```

   **Tento JWK držte v tajnosti** - kdo ho má, získá certifikáty pro jakékoli jméno, které provisioner povolí.
4. Vezměte kořen: `$(step path)/certs/root_ca.crt` na stroji s CA, nebo `step ca root root_ca.crt`.

## Vyplnění v acme

Zdroje → **Přidat** → **Smallstep step-ca (JWK provisioner)**.

| Pole v acme | Co do něj zadat |
|---|---|
| step-ca address | `https://ca.example.local:9000` |
| Root certificate of the CA | `root_ca.crt` - proti němu se kontroluje TLS step-ca a jeho otisk jde do tokenu |
| Provisioner | `acme-jwk` (jak ho ukazuje `step ca provisioner list`) |
| Provisioner key | dešifrovaný JWK JSON z kroku 3 (EC nebo RSA), nebo PEM klíč |
| Key ID (pokročilé) | prázdné: `kid` z JWK, jinak se zeptá CA |
| Check the CA's TLS certificate (pokročilé) | zapnuto |

Wildcardy a IP adresy jsou povoleny, pokud je povoluje politika provisioneru; dny certifikátu se stanou požadovanou platností v mezích provisioneru.

## Ověření

- Zdroje → zdroj → **Test** (Try it).
- Na stroji s CA: `step ca provisioner list` ukáže `acme-jwk`; `step ca health` odpoví `ok`.
- Po vydání: `step certificate inspect cert.pem --short`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / neplatný token | špatné jméno provisioneru, špatný klíč (nedešifrovaný, nebo jiného provisioneru), nebo jdou hodiny acme špatně (token platí 5 minut) |
| Selhání ověření TLS | *Root certificate of the CA* není kořen step-ca |
| Požadovaná platnost odmítnuta | mimo `minTLSCertDuration` / `maxTLSCertDuration` provisioneru |
| Jméno odmítnuto | X.509 politika provisioneru nebo autority ho nepovoluje |
| Nesoulad `Key ID` | nechte *Key ID* prázdné, nebo zkopírujte `kid` z `step ca provisioner list` |
