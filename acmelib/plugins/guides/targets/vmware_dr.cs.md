# VMware Live Site Recovery / vSphere Replication appliance - nastavení pro acme

acme vymění **certifikát appliance** VMware Live Site Recovery (VLSR, dříve Site Recovery Manager) nebo vSphere Replication (VRMS) - HTTPS 443 a rozhraní správy 5480 - přes **Configuration API** appliance na portu 5480:

1. `POST <api>/session` (základní autentizace, `admin`) → `session_id`, posílá se zpět v hlavičce `x-dr-session`;
2. `GET <api>/appliance/certificates/server` - je-li tam už stejný certifikát, nic nedělá;
3. `POST <api>/appliance/certificates/ca` s `[{"value": PEM}, ...]` - mezilehlé certifikáty a kořen mezi certifikáty CA appliance;
4. `POST <api>/appliance/certificates/server` s `{"pkcs12_format": {"certificate": <base64 PKCS#12>, "password": ...}}` - PKCS#12 obsahuje **právě jeden certifikát a jeho klíč** (řetězec šel v kroku 3), heslo má 20 znaků (dovoleno nejvýš 31).

`<api>` je standardně `https://<appliance>:5480/configure/requests`.

**Potom - acme to řekne, uděláte to vy:**

- **vSphere Replication**: restartujte appliance (vyžaduje to její dokumentace), pak *vSphere Replication → Manage → target sites → Reconnect*; replikace se mezitím pozastaví.
- **Live Site Recovery**: *Site Recovery → pár lokalit → View Details → Site Pair Summary → Reconnect* (adresa vzdáleného vCenteru a přihlašovací údaje SSO) - thumbprint se změnil. Ne během běžícího plánu obnovy nebo testu.

## Pro které verze je tento návod

VMware Live Site Recovery **9.0 / 9.1** a vSphere Replication **9.0** (VRMS Configuration API 2.0.0) - stejná volání. Ve VLSR 9.x je `POST .../appliance/certificates/server` označen jako *Deprecated*: jeho nástupce `.../server/actions/update` bere jen certifikát k CSR vytvořenému na appliance nebo self-signed, ne klíč vytvořený jinde - proto acme používá ten zastaralý, dokud existuje. SRM / VR 8.8 ověřeny nebyly.

## Nastavení appliance

1. Uživatel je **`admin`** appliance (nastavený při nasazení OVF) - jiné uživatele nebo role pro certifikáty appliance nemá. Heslo uchovávejte v trezoru a při rotaci ho změňte i v acme.
2. Port **5480** dosažitelný z acme.
3. *Vyzkoušet* v acme se přihlásí s cestou API - odpoví-li 404, zjistěte cestu Configuration API vaší appliance a vyplňte ji do *Cesta API*.
4. U vCenteru s vlastním certifikátem přidejte jeho kořen mezi certifikáty CA appliance nejdřív (v dokumentaci *How do I set up a trusted environment*) - acme přidává kořen svého certifikátu.

## Certifikát

- FQDN appliance (její *Local host*) v **SAN**; nejvýš IPv4, IPv6 ne.
- Klíč 2048 bitů a více; SHA-256 nebo silnější (SHA-1 je standardně odmítnut).
- **Live Site Recovery: EKU serverAuth A clientAuth** - certifikát jen se serverAuth odmítne. Let's Encrypt a většina veřejných CA už clientAuth nevydává: použijte CA, která ano (interní).
- Ne kořenový certifikát CA.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FQDN appliance, `5480` |
| Appliance | VMware Live Site Recovery, nebo vSphere Replication |
| Uživatel / Heslo | `admin` a jeho heslo |
| Cesta API (pokročilé) | `/configure/requests` |
| Kořenový certifikát CA (nasazení) | kořen, když jím řetězec nekončí |
| Přidat řetězec mezi certifikáty CA appliance (nasazení) | zapnuto |
| Zkontrolovat, co se servíruje | prázdné: acme ověří `<adresa>:443` a `:5480` |

## Kontrola

*Vyzkoušet* se přihlásí a ukáže předmět a konec platnosti současného certifikátu. Po nasazení:

```sh
openssl s_client -connect vlsr01.example.local:443 -servername vlsr01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -ext extendedKeyUsage
openssl s_client -connect vlsr01.example.local:5480 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

Ve vSphere Clientu musí být pár lokalit **Connected**.

## Časté potíže

| Potíž | Řešení |
|---|---|
| `404` při přihlášení - „is the API path right?" | Tato appliance má jinou cestu: nastavte *Cesta API*. |
| `401` | Heslo `admin`. |
| `400` při změně | EKU bez clientAuth (VLSR), SAN bez *Local host*, SHA-1, klíč pod 2048 bitů. |
| „certificate thumbprint mismatch" mezi lokalitami | Znovu připojte pár lokalit (Reconnect). |
| Lokality vSphere Replication ve stavu „Connection issue" | Restartujte appliance, pak Reconnect. |
