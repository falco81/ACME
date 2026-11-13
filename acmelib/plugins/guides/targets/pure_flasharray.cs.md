# Pure Storage FlashArray - nastavení pro acme

acme vymění **management certifikát** pole FlashArray (Purity//FA, nově *Everpure*) na místě, přes **REST API 2.x** s API tokenem:

1. `GET /api/api_version` – verze REST, které pole umí (bez přihlášení); acme vezme nejnovější `2.x`, nebo tu, kterou nastavíte;
2. `POST /api/2.x/login` s hlavičkou `api-token: <token>` → token relace v hlavičce odpovědi `x-auth-token`;
3. `GET /api/2.x/certificates?names=management` – když už drží přesně tento certifikát, nic se nemění;
4. `PATCH /api/2.x/certificates?names=management` s `certificate`, `intermediate_certificate` a `key` (klíč jde s ním, takže na vlastním klíči a CSR pole nezáleží);
5. `POST /api/2.x/logout`.

Webový server správy (GUI, REST API) používá nový certifikát okamžitě; datové cesty (FC, iSCSI, NVMe, NFS, SMB, S3) se to netýká.

## Pro které verze

Purity//FA **6.x** s REST API **2.x** (návod výrobce: do 2.59). Všechny verze 2.x mají tato volání – jeden modul, žádné verze k výběru.

## Co potřebujete

- Adresu správy (VIF `vir0`) dostupnou z acme na portu **443**; REST je zapnuté vždy.
- Funkční NTP a DNS na poli.
- Certifikát, jehož CN / SAN obsahují FQDN, pod kterým se na pole chodí (CN nejvýš 64 znaků). Bezpečná volba je RSA 2048 a víc.

## Účet a jeho API token

Vestavěné role Purity jsou `readonly`, `ops_admin`, `storage_admin` a `array_admin`. Certifikáty mění konfiguraci celého pole, počítejte proto s rolí **`array_admin`** (menší roli Pure nedokumentuje; v novějších Purity může stačit management access policy omezená na `purestorage.com/api/v2/certificates`).

Přes REST, jednou přihlášeni jako existující administrátor (`pureuser`):

```sh
curl -k -i -X POST "https://array01.example.com/api/2.59/login" -H "Content-Type: application/json" \
  -d '{"username":"pureuser","password":"<heslo>"}'
# z odpovědi vezměte hlavičku x-auth-token
curl -k -X POST "https://array01.example.com/api/2.59/admins?names=svc-cert" \
  -H "x-auth-token: <token-relace>" -H "Content-Type: application/json" \
  -d '{"password":"<silné-heslo>","role":{"name":"array_admin"}}'
curl -k -X POST "https://array01.example.com/api/2.59/admins/api-tokens?names=svc-cert&timeout=7776000000" \
  -H "x-auth-token: <token-relace>"
```

`timeout` je v milisekundách (zde 90 dní – token před koncem obnovte, nebo `timeout` vynechte). V CLI totéž (syntaxe není ve veřejné dokumentaci Pure – ověřte `pureadmin -h`):

```text
pureadmin create --role array_admin svc-cert
pureadmin create --api-token svc-cert
```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FQDN správy pole, `443` |
| API token | token účtu `svc-cert` |
| Verze REST API (pokročilé) | prázdné (nejnovější 2.x, kterou pole uvádí), nebo např. `2.59` |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má pole svůj self-signed certifikát |
| Certifikát na poli (nasazení) | `management`; `vasa-ct0` / `vasa-ct1` pro poskytovatele VASA (každý zvláštní nasazení) |
| Zkontrolovat, co se servíruje | u `management` acme sám kontroluje `<adresa>:443` |

**Před prvním nasazením**: klienti, kteří si připnuli starý certifikát, poli přestanou důvěřovat – **poskytovatel VASA ve vCenter** (zaregistrujte ho znovu), Pure1 a plug-in pro vSphere.

## Ověření

```sh
openssl s_client -connect array01.example.com:443 -servername array01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -k "https://array01.example.com/api/2.59/certificates?names=management" -H "x-auth-token: $TOKEN"
curl -k "https://array01.example.com/api/2.59/certificates/uses" -H "x-auth-token: $TOKEN"
```

V CLI: `purecert list` a `purecert list management --certificate`.

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| `401` při přihlášení | špatný nebo prošlý API token | vytvořte účtu `svc-cert` nový token |
| `403` na PATCH | účet nemá oprávnění | dejte mu `array_admin` (nebo politiku na certifikáty) |
| *the array has no certificate "..."* | jiné jméno | `GET /api/2.x/certificates` vypíše jména |
| *speaks no REST API 2.x* | Purity starší než REST 2 | aktualizujte Purity; acme umí jen REST 2.x |
| vCenter ukazuje storage provider offline | VASA důvěřovala starému certifikátu | zaregistrujte poskytovatele znovu |

Zdroje: FlashArray REST API 2.59 reference (`/login`, `/certificates`, `/admins`, `/admins/api-tokens`), Ansible `purestorage.flasharray.purefa_certs`.
