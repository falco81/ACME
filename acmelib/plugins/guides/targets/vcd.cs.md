# VMware Cloud Director (certifikát cely) - nastavení pro acme

acme dá **HTTP endpointu cel Cloud Directoru** (portál poskytovatele i tenantů, API, konzolový proxy - vše na 443) certifikát přes **VCD OpenAPI** (`/cloudapi/1.0.0`):

1. `POST /cloudapi/1.0.0/sessions/provider` (základní autentizace, `uživatel@System`) - token přijde v hlavičce `X-VMWARE-VCLOUD-ACCESS-TOKEN` a posílá se zpět jako `Authorization: Bearer`;
2. `POST /cloudapi/1.0.0/ssl/certificateLibrary` - do **Certificates Library** s `alias` (`acme-<jméno>-<datum>-<sériové číslo>`), `certificate` (koncový a mezilehlé, PEM) a `privateKey` (PKCS#8, nešifrovaný); položka se stejným aliasem se znovu neimportuje;
3. pro každou celu: `GET .../cells/<cellUrn>/accessEndpoints`, tentýž objekt zpět se změněným jen **`apiSslCertRef`** (`PUT`, 202, počká na úlohu) - certifikát JMX a porty zůstanou. Cela ukončí svá spojení a restartuje connection server (krátký výpadek);
4. na požádání celu nejdřív přepne do **údržby** a potom zpět na **aktivní** (`PUT .../cells/<cellUrn>` se `status`);
5. starší položky acme v knihovně nad *ponechat* smaže - jen ty bez spotřebitelů (consumers).

## Pro které verze je tento návod

Cloud Director **10.5.1 - 10.6.1**: od 10.5.1 čtou cely certifikát z Certificates Library a ve 10.6 už `cell-management-tool certificates` není - cestou je knihovna a `accessEndpoints` (API 38.1+). Posílaná verze API je pole: `39.0` pro 10.6, `38.1` pro 10.5.1. Vlastní certifikát správy appliance (port 5480, vestavěný PostgreSQL) je jiný: mění se v shellu (`generate-appliance-certificates.sh`).

## Nastavení Cloud Directoru

1. **Uživatel poskytovatele** v organizaci *System*: *Administration → Access Control → Users → New*, např. `svc-cert`. Jeho role:
   - **Certificate Library: Manage** (import, mazání starých položek);
   - změna endpointů cely a údržba: dokumentace uvádí jen **System Administrator** - dejte mu tuto roli (vlastní globální role s menšími právy není zdokumentovaná).
2. Za **load balancerem** zapněte *Každou celu při změně do údržby*: cely se mění jedna po druhé a žádná relace se nepřeruší. Šifruje-li load balancer TLS znovu, nastavte důvěru k novému certifikátu i na něm.
3. Po prvním nasazení ověřte, že tenantům funguje **konzolový proxy** (od 10.4 sdílí certifikát i port 443).

## Certifikát

- PEM X.509 a klíč PKCS#8 (acme posílá obojí); žádné DSA, nikde v řetězci SHA-1; 2048 bitů a více.
- SAN: veřejné FQDN (load balancer, `secureApiEndpoint`) a FQDN každé cely; wildcard je v pořádku.
- Mezilehlé certifikáty jdou s ním; kořen jen tehdy, když ho vaše CA vyžaduje.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | veřejné FQDN nebo FQDN jedné cely, např. `vcd.example.local`, `443` |
| Uživatel / Heslo | `svc-cert@System` (`@System` se doplní, když chybí) a jeho heslo |
| Verze API (pokročilé) | `39.0` (10.6), `38.1` (10.5.1) |
| Cely (nasazení) | jedna na řádek: jména cel (nebo `urn:vcloud:cell:...`); prázdné: všechny cely |
| Každou celu při změně do údržby (nasazení) | za load balancerem zapnuto |
| Kolik předchozích verzí ponechat (pokročilé) | `1` |
| Zkontrolovat, co se servíruje | `vcd.example.local:443` a každá cela `vcd-cell1.example.local:443` |

## Kontrola

*Vyzkoušet* se přihlásí a vypíše cely. Po nasazení:

```sh
openssl s_client -connect vcd.example.local:443 -servername vcd.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "Authorization: Bearer $TOKEN" -H "Accept: application/json;version=39.0" \
  "https://vcd.example.local/cloudapi/1.0.0/cells/<cellUrn>/accessEndpoints"
```

V portálu: *Administration → Certificate Management → Certificates Library* - u položky *Consumers*.

## Časté potíže

| Potíž | Řešení |
|---|---|
| `no X-VMWARE-VCLOUD-ACCESS-TOKEN` | Uživatel tenanta nebo stará verze API: použijte uživatele System, zkontrolujte *Verze API*. |
| `401` / `403` | Uživatel nebo jeho role: Certificate Library: Manage; na endpointy System Administrator. |
| `400` při importu | Klíč šifrovaný nebo ne PKCS#8, v řetězci SHA-1, DSA. |
| `Cloud Director has no cell "x"` | Jméno, jak ho ukazuje *Cloud Cells*, nebo jeho urn. |
| Stará položka zůstala | Ještě ji něco používá (*Consumers*) - acme maže jen nepoužívané. |
