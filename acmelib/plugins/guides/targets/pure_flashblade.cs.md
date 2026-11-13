# Pure Storage FlashBlade - nastavení pro acme

acme vymění certifikát FlashBladu (Purity//FB, nově *Everpure*) na místě přes **REST API 2.x** s API tokenem – stejně jako u FlashArray, jen se dvěma rozdíly FlashBladu:

1. `GET /api/api_version` – verze REST, které umí; acme vezme nejnovější `2.x` (nebo tu, kterou nastavíte);
2. `POST /api/login` (na FlashBladu bez verze v cestě) s `api-token: <token>` → hlavička `x-auth-token`;
3. `GET /api/2.x/certificates?names=<jméno>` – je tam už tentýž certifikát: nic se nemění;
4. `PATCH /api/2.x/certificates?names=<jméno>` s `certificate`, `intermediate_certificate` a **`private_key`** (FlashArray mu říká `key`);
5. `POST /api/2.x/logout`.

## Pro které verze

Purity//FB **4.x** s REST API **2.x** (návod výrobce: do 2.30). Jeden modul.

## Co potřebujete

- Management VIP dostupnou z acme na portu **443**.
- **Jméno** certifikátu, který se má vyměnit. Pure jméno management certifikátu FlashBladu nedokumentuje (často `global` – *neověřeno*): nejdřív si je vypište.

```sh
TOKEN=$(curl -k -s -D - -o /dev/null -X POST "https://fb01.example.com/api/login" -H "api-token: <api-token>" \
        | awk -F': ' 'tolower($1)=="x-auth-token"{print $2}' | tr -d '\r')
curl -k "https://fb01.example.com/api/2.30/certificates" -H "x-auth-token: $TOKEN"
```

- Certifikát s FQDN FlashBladu v CN / SAN; FlashBlade uvádí pro certifikát nejvýš 3000 znaků – dlouhý řetězec se nemusí vejít.

## Účet a jeho API token

Role: `array_admin`, `storage_admin`, `ops_admin`, `readonly`. Certifikáty potřebují **`array_admin`** (menší role není dokumentována; na novějším Purity//FB může stačit vlastní politika na `purestorage.com/api/v2/certificates`). Vytvořte lokálního administrátora s touto rolí v GUI (*Settings > Users*) nebo přes REST a pak jeho API token:

```sh
curl -k -X POST "https://fb01.example.com/api/2.30/admins/api-tokens?names=svc-cert" -H "x-auth-token: $TOKEN"
```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FQDN správy FlashBladu, `443` |
| API token | token účtu s rolí `array_admin` |
| Verze REST API (pokročilé) | prázdné, nebo např. `2.30` |
| Ověřovat certifikát zařízení | zapnuto; vypnout jen dokud má svůj self-signed certifikát |
| Certifikát na FlashBladu (nasazení) | jméno z `GET /api/2.x/certificates`, např. `global` |
| Zkontrolovat, co se servíruje | `fb01.example.com:443` (u `management` / `global` ho acme kontroluje sám) |

## Ověření

```sh
openssl s_client -connect fb01.example.com:443 -servername fb01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -k "https://fb01.example.com/api/2.30/certificates?names=global" -H "x-auth-token: $TOKEN"
```

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| `401` při přihlášení | špatný nebo prošlý API token | vytvořte nový token |
| `400` zmiňující `key` | bylo posláno pole FlashArray | zvolte cíl *Pure Storage FlashBlade*, ne FlashArray |
| *has no certificate "..."* | jméno je jiné | vypište certifikáty a jméno dejte do nasazení |
| klienti s připnutým starým certifikátem selhávají | certifikát se změnil | ať důvěřují CA, ne certifikátu |

Zdroje: FlashBlade REST API 2.30 reference (`/login`, `/certificates`, role a autorizační prostředky), Ansible `purestorage.flashblade.purefb_certs`.
