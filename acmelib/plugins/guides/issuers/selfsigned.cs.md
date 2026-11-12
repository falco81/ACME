# Self-signed certifikát - nastavení pro acme

Zdroj **Self-signed** vytvoří certifikát podepsaný vlastním klíčem, okamžitě a uvnitř acme - bez CA, bez účtu, bez sítě. Takovému certifikátu nikdo nedůvěřuje, pokud mu to neřeknete: klient, který si připne jeho otisk, testovací systém, zařízení, které chce jen *nějaký* certifikát. Pro vše, čemu mají důvěřovat prohlížeče nebo všechny stroje firmy, použijte veřejnou CA (zdroj ACME) nebo vlastní certifikační autoritu acme (zdroj *Own certificate authority*).

## Co potřebujete

- Na straně CA nic - acme ho podepíše samo.
- Na každém klientovi, který ho má přijmout: způsob, jak důvěřovat právě tomuto certifikátu (připnutí jeho otisku SHA-256, nebo přidání certifikátu do úložiště důvěryhodných certifikátů klienta).
- Pamatujte: **každé obnovení je nový self-signed certifikát** s novým otiskem (a s novým klíčem, pokud certifikát klíč nezachovává) - každému klientovi, který si připnul starý, to musíte říct znovu.

## Nastavení klientů

1. Vytvořte certifikát v acme (viz níže) a stáhněte ho (okno certifikátu → stáhnout, PEM).
2. Dejte ho tomu, co mu má důvěřovat, například:

   ```sh
   # RHEL / AlmaLinux / Rocky
   cp device.example.local.pem /etc/pki/ca-trust/source/anchors/
   update-ca-trust
   # Debian / Ubuntu
   cp device.example.local.pem /usr/local/share/ca-certificates/device.example.local.crt
   update-ca-certificates
   ```

   ```powershell
   Import-Certificate -FilePath .\device.example.local.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

3. Nebo připněte otisk v klientovi, který to umí (API klient, monitorovací kontrola):

   ```sh
   openssl x509 -in device.example.local.pem -noout -fingerprint -sha256
   ```

4. Kde mnoho strojů musí důvěřovat mnoha takovým certifikátům, dejte přednost vlastní CA acme: jeden kořen k distribuci, certifikáty se obnovují bez zásahu do klientů.

## Vyplnění v acme

Zdroje → **Přidat** → **Self-signed**.

| Pole v acme | Co do něj zadat |
|---|---|
| Validity (days) | `365` (výchozí); vlastní dny certifikátu mají přednost |
| Extended key usage (pokročilé) | `serverAuth`, `clientAuth` (výchozí); podle potřeby `codeSigning`, `emailProtection` nebo OID |

Wildcardy i IP adresy jsou povoleny; klíče RSA i ECDSA (i oba, jako duální certifikát).

## Ověření

- Zdroje → zdroj → **Test** (Try it): není se na co ptát - ohlásí, že je zdroj připraven.
- Po vydání je vydavatel certifikátu shodný s jeho subjektem:

```sh
openssl x509 -in cert.pem -noout -subject -issuer -dates -ext subjectAltName
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Prohlížeče hlásí *nedůvěryhodný* / `self-signed certificate` | očekávané: důvěřujte mu na klientovi, nebo použijte CA |
| Klient po obnovení přestal fungovat | měl připnutý starý otisk nebo důvěřoval starému certifikátu: dejte mu nový, nebo přejděte na vlastní CA acme |
| Klient chce příznak CA nebo řetězec | self-signed koncový certifikát není CA: použijte místo něj zdroj *Own certificate authority* |
| `Validity (days)` je pro klienta příliš dlouhá | Apple a prohlížeče odmítají serverové certifikáty delší než 398 dní, i když jim důvěřují - držte nejvýš `397` |
