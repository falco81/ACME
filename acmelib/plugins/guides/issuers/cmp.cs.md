# CMP server - nastavení pro acme

Zdroj **CMP (RFC 4210 / 9480)** žádá CA o certifikáty protokolem Certificate Management Protocol (CMPv2, s aktualizacemi RFC 9480 a profilem Lightweight CMP, RFC 9483). acme spouští `openssl cmp` (OpenSSL 3.0+) pro žádost `ir`, `cr` nebo `p10cr`, potvrdí certifikát (nebo požádá o implicitní potvrzení), dotazuje se na odpověď *waiting*, posílá `rr` k odvolání a `genm` pro *Try it*. Každá zpráva jde do CA přes HTTP(S) jako `application/pkixcmp`, vlastním HTTP klientem acme (Nastavení → Proxy a nastavení TLS zdroje). Ochrana je **sdílené tajemství** (MAC odvozený z hesla: reference + tajemství) nebo **podpis** (klientský certifikát a klíč). **Soukromý klíč certifikátu nikdy neopustí acme.** Funguje s EJBCA, Nokia NetGuard, Siemens, Insta Certifier a průmyslovými PKI (IEC 62443).

## Co potřebujete

- CMP endpoint CA dosažitelný **z acme** přes HTTP nebo HTTPS.
- Buď **referenci (senderKID) a sdílené tajemství** od CA, nebo **podpisový certifikát a klíč**, kterým CA pro CMP důvěřuje.
- Jméno CA (*recipient*, `/C=../O=../CN=..`), kde ho CA chce, a její certifikát pro kontrolu podepsaných odpovědí.
- OpenSSL 3.3+ na acme jen tehdy, potřebujete-li *Certificate profile* (certProfile).

## Nastavení CA

EJBCA, režim RA se sdíleným tajemstvím (HMAC):

1. **System Configuration → CMP Configuration → Add** alias, např. `acme`. Endpoint pak je `https://ejbca.example.local/ejbca/publicweb/cmp/acme`.
2. *CMP Operational Mode*: **RA mode**. *Request authentication module*: **HMAC**, se sdíleným tajemstvím, které bude acme používat (nebo enrollment code entity).
3. Vyberte **End Entity Profile**, **Certificate Profile** a **CA** pro TLS servery (povolená DNS jména, serverová autentizace, typy klíčů, které acme používá).
4. Generování jmen RA: jak se entita pojmenuje (např. z CN subjektu) a zda se existující entity smějí znovu použít pro obnovení (*Allow automatic key update* / *Allow certificate renewal with same keys* podle vaší politiky).
5. Poznamenejte si DN subjektu CA pro *CA name (recipient)* a stáhněte certifikát CA.

Místo toho ochrana podpisem: vydejte pro acme RA/klientský certifikát od CA, které alias důvěřuje (*Request authentication module*: **EndEntityCertificate**), a dejte acme tento certifikát s klíčem.

Jiné CA: založte pro acme CMP klienta s referencí + tajemstvím (nebo podpisovým certifikátem), profil pro serverové TLS certifikáty a poznamenejte si URL endpointu (Lightweight CMP: `.../.well-known/cmp[/p/<label>]`).

Vyzkoušejte endpoint ručně ze stroje s OpenSSL 3:

```sh
openssl cmp -cmd genm -server https://ejbca.example.local/ejbca/publicweb/cmp/acme \
  -ref acme01 -secret pass:'<secret>' -recipient '/CN=Issuing CA/O=Example/C=CZ' -unprotected_errors
```

## Vyplnění v acme

Zdroje → **Přidat** → **CMP (RFC 4210 / 9480)**.

| Pole v acme | Co do něj zadat |
|---|---|
| CMP server | endpoint, např. `https://ejbca.example.local/ejbca/publicweb/cmp/acme` |
| Request | `cr` (výchozí); `ir` pro entitu, kterou CA ještě nezná; `p10cr`, kde CA chce samotné CSR |
| Protection | *Shared secret (PBM)* nebo *Signature* |
| Reference (senderKID) / Shared secret | např. `acme01` a jeho tajemství (EJBCA: jméno entity / enrollment code, nebo HMAC tajemství aliasu) |
| Signing certificate / its key | PEM, za ním řetězec - pro ochranu podpisem |
| CA name (recipient) | `/CN=Issuing CA/O=Example/C=CZ`; prázdné: `/` nebo subjekt certifikátu CA níže |
| CA certificate (answers) | certifikát CA - nutný při ochraně podpisem |
| Certificate profile (pokročilé) | certProfile, kde podle něj CA vybírá (OpenSSL 3.3+) |
| Implicit confirmation (pokročilé) | zapněte u CA, které drží transakci jen na jednom otevřeném spojení |
| Take unprotected error answers (pokročilé) | zapnuto - ukáže chybová slova CA |
| CA certificate of the server's TLS / Check the server's TLS certificate (pokročilé) | pro HTTPS s privátní CA |
| Wait for the certificate (s) (pokročilé) | `120` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): obecná zpráva `genm` - přihlásí se a přečte odpověď CA, nic neobjednává.
- Vydejte zkušební certifikát; v EJBCA ukáže *RA Web → Search* entitu a její certifikát.

## Časté problémy

| Problém | Řešení |
|---|---|
| `wrong protection` / kontrola MAC selhala | špatná reference nebo sdílené tajemství, nebo alias chce ochranu podpisem |
| `unknown recipient` / `bad request` | nastavte *CA name (recipient)* přesně na DN CA |
| CA odmítá `ir` nebo `cr` | přepněte *Request* (`ir` pro novou entitu, `cr` pro známou, `p10cr`) |
| Transakce se po certifikátu ztratí | server drží transakci na jednom spojení: zapněte *Implicit confirmation* |
| `certProfile` odmítnut | potřebuje OpenSSL 3.3+ na acme, nebo nechte *Certificate profile* prázdné |
| Čekající žádost se klade znovu od začátku | očekávané: transakce žije v openssl; schvalujte rychleji nebo zvyšte čekání |
