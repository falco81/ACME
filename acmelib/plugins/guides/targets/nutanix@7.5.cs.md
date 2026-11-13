# Cluster Nutanix (Prism Central 7.3 - 7.5, v4.4 API) - nastavení pro acme

Tato verze cíle Nutanix je pro **Prism Central 7.3 – 7.5** spravující clustery **AOS 7.x**. Vymění SSL certifikát clusteru (jeho webové konzole Prism Element a API, port 9440) přes API **v4.4** Prism Central – cestu oficiálního SDK Nutanix 4.4.1 – a přihlašuje se **API klíčem servisního účtu Prism Central** (`X-ntnx-api-key`) nebo uživatelem:

1. `GET /api/clustermgmt/v4.4/config/clusters/<extId>/ssl-certificate` – kvůli jeho `ETag`;
2. `PUT` na stejnou cestu s `If-Match: <ETag>`, novým `NTNX-Request-Id` a `{"privateKeyAlgorithm", "privateKey", "publicCertificate", "caChain"}` – každé jako base64 obsahu souboru PEM;
3. počká na úlohu: `GET /api/prism/v4.4/config/tasks/<taskExtId>`, dokud není `SUCCEEDED`.

Webová konzole clusteru se s novým certifikátem restartuje; otevřené relace prohlížeče je potřeba obnovit. Úložiště, I/O virtuálních strojů a datová cesta zasaženy nejsou. Cluster drží **jeden** certifikát – nový přepíše starý.

## Čím se liší od základní verze

| | základní (libovolná v4) | tato verze |
|---|---|---|
| Verze API | ve výchozím stavu `v4.3` | ve výchozím stavu `v4.4` (lze zvolit `v4.0` – `v4.3`) |
| Přihlášení | uživatel (HTTP basic) | API klíč servisního účtu, nebo uživatel |
| Typy klíčů | ECDSA P-256 / P-384 / P-521, RSA 2048 / 4096 | ty z AOS 7.5: **RSA 2048, RSA 4096, ECDSA P-256, ECDSA P-384** – P-521 se odmítne dřív, než se cokoli pošle (`ncli` v AOS 7.5 už `ECDSA_521` nemá) |

*Nejisté*: od které Prism Central se API v4.4 podává – když `v4.4` odpoví 404, zvolte `v4.3`. Verzi Prism Central acme nečte (není na to dokumentované volání), takže podle ní nic neodmítá.

## Co potřebujete

- Prism Central dostupnou z acme na portu **9440**.
- Certifikát v PEM s **nešifrovaným** klíčem; řetězec jen mezilehlé certifikáty a kořen (tak ho acme posílá); žádné SHA-1. Prism Central starší než pc.2024.3 může mít s RSA 4096 potíže (KB 12775).

## Servisní účet a jeho API klíč

V Prism Central: *Admin Center > IAM > Identities > Service Accounts > + Add New Service Account*, pak *Save and Create Keys > + Add New Key*, typ **API Key**, platnost, *Generate Key* – klíč si hned zkopírujte, znovu se už neukáže. Účtu dejte roli **Cluster Admin** přes *Admin Center > IAM > Authorization Policies*, omezenou na clustery, kam acme nasazuje.

Místo toho uživatel: uživatel Prism Central s rolí *Cluster Admin*, *Prism Admin* nebo *Super Admin*.

Klíč si ověřte ze stroje acme:

```sh
curl -sS -H "X-ntnx-api-key: $KEY" "https://pc.example.local:9440/api/clustermgmt/v4.4/config/clusters?\$select=extId,name"
```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **Prism Central 7.3 - 7.5 (v4.4 API)** |
| Adresa / Port HTTPS | Prism Central, `9440` |
| Přihlásit se přes | *API klíčem servisního účtu* (nebo *uživatelem a heslem*) |
| API klíč | klíč z *Generate Key* |
| Cluster | extId nebo jméno clusteru – *Načíst seznam* ho vyplní |
| Verze API (pokročilé) | `v4.4` |
| Algoritmus klíče (nasazení, pokročilé) | *podle klíče certifikátu*, nebo typ, když acme velikost klíče nepozná |
| Zkontrolovat, co se servíruje | virtuální IP / FQDN clusteru, např. `prism01.example.com:9440` |

## Ověření

```sh
openssl s_client -connect prism01.example.com:9440 -servername prism01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sS -H "X-ntnx-api-key: $KEY" "https://pc.example.local:9440/api/clustermgmt/v4.4/config/clusters/<extId>/ssl-certificate"
```

V Prism Element: ikona ozubeného kola → *SSL Certificate*.

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| `401` | špatný nebo prošlý API klíč | vygenerujte nový klíč |
| `403` | servisní účet nemá na clusteru Cluster Admin | přidejte cluster do jeho autorizační politiky |
| `404` na `/v4.4/` | Prism Central v4.4 nepodává | v *Verze API* zvolte `v4.3` |
| *AOS 7.x takes ... not ECDSA_521* | klíč P-521 | vydejte certifikát s RSA nebo P-256 / P-384 |
| úloha selže, vrátí se výchozí certifikát | Prism neplatný certifikát zahodil | zkontrolujte typ klíče a řetězec (nesmí v něm být serverový certifikát) |
| zálohovací software (Veeam, HYCU) ztratí důvěru | připnul si starý certifikát | přijměte tam nový |

Zdroje: Nutanix Security Guide 7.5 (*SSL Certificate Management*, *Supported Key Configurations*, *Configuring a Service Account in Prism Central*), Command Reference AOS 7.5 `ncli ssl-certificate`, oficiální Python SDK `ntnx-clustermgmt-py-client` 4.4.1, Ansible `nutanix.ncp.ntnx_ssl_certificates_v2`.
