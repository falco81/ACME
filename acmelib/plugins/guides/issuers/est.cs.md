# EST server - nastavení pro acme

Zdroj **EST (RFC 7030)** žádá CA o certifikáty protokolem *Enrollment over Secure Transport*: acme přečte řetězec CA (`GET /.well-known/est[/<label>]/cacerts`) a pošle žádost, kterou vytvořilo (`POST .../simpleenroll`, PKCS#10 v base64) - **soukromý klíč nikdy neopustí acme**. Když CA žádost drží ke schválení (`202 Accepted` + `Retry-After`), acme chvíli počká a při dalším pokusu se zeptá znovu se stejnou žádostí. Obnovení mohou jít na `simplereenroll`, kde to server chce. Mluví jím EJBCA, Keyfactor, Cisco (IOS CA, ISE, libest), DigiCert TLM, Entrust, GlobalSign, Nexus a další. Nepodporuje se: generování klíče na serveru (`serverkeygen`) a plné CMC. EST nemá odvolání.

## Co potřebujete

- EST server přes HTTPS dosažitelný **z acme** (port 443 nebo vlastní port serveru, např. 8443), přímo nebo přes Nastavení → Proxy.
- Jeho adresu a na serveru s více CA **label** (EJBCA: EST alias).
- Přihlašovací údaje, které server přijme: uživatele a heslo (HTTP Basic), klientský certifikát, který zná, nebo obojí.
- Kořen **TLS** certifikátu EST serveru, pokud je od privátní CA (*explicit trust anchor* podle RFC 7030).

## Nastavení EST serveru

EJBCA (ověřte, že vaše edice a verze obsahuje protokol EST):

1. **System Configuration → EST Configuration → Add** alias, např. `acme`. URL pak je `https://ejbca.example.local/.well-known/est/acme/`.
2. V aliasu: *Operational Mode* **RA**, **CA**, **End Entity Profile** a **Certificate Profile** pro TLS servery (povolující DNS jména, typy klíčů, které acme používá, serverovou autentizaci).
3. Autentizace: *Require HTTP Basic* s uživatelem a heslem pro acme, nebo autentizace klientským certifikátem (vydavatel klientského certifikátu je důvěryhodný, certifikát má roli RA administrátora).
4. V end entity profilu povolte DNS jména certifikátů (tolik SAN, kolik vaše certifikáty mají).

Jiné servery: založte pro acme účet EST klienta / záznam registrační autority s právem žádat na profilu CA pro serverové TLS certifikáty; poznamenejte si label a přihlašovací údaje.

Ověřte server ze sítě acme:

```sh
curl --cacert est-tls-root.pem https://est.example.local/.well-known/est/acme/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -noout
```

## Vyplnění v acme

Zdroje → **Přidat** → **EST (RFC 7030)**.

| Pole v acme | Co do něj zadat |
|---|---|
| EST server | `https://est.example.local` - `/.well-known/est` se doplní, když v cestě chybí |
| CA label | label / alias EJBCA; prázdné: výchozí CA serveru |
| Signing in | *User and password (HTTP Basic)*, *Client certificate*, *Client certificate and password*, nebo *Nothing* |
| User / Password | pro HTTP Basic |
| Client certificate / Client certificate's key | PEM s řetězcem - pro přihlášení certifikátem |
| CA certificate of the server (trust anchor) | kořen TLS certifikátu EST serveru; prázdné: kořeny systému |
| Check the server's TLS certificate (pokročilé) | zapnuto |
| Renewals by simplereenroll (pokročilé) | vypnuto - každý certifikát přes `simpleenroll`; zapněte jen tam, kde server chce re-enrollment |
| Wait for approval (s) (pokročilé) | `60`; zadržená žádost se stejně zopakuje při dalších pokusech |

## Ověření

- Zdroje → zdroj → **Test** (Try it): acme přečte `cacerts` (a `csrattrs`) a přihlásí se - nic neobjednává.
- Pak vydejte zkušební certifikát a zkontrolujte jeho řetězec: `openssl verify -CAfile root.pem -untrusted chain.pem cert.pem`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | špatný uživatel/heslo, nebo server chce místo toho klientský certifikát |
| Chyba TLS / certificate verify failed | nastavte *CA certificate of the server* na kořen TLS certifikátu EST serveru |
| `404` | špatný label/alias, nebo cesta není `/.well-known/est` |
| Žádost čeká (202) a certifikát nepřichází | operátor ji musí na CA schválit; acme se ptá znovu při každém pokusu |
| Odmítnuto kvůli jménu nebo typu klíče | profil CA nepovoluje toto jméno, tento počet SAN nebo tento typ klíče |
| Obnovení přes `simplereenroll` odmítnuto | vypněte *Renewals by simplereenroll* - acme nemá klientský certifikát starého certifikátu |
