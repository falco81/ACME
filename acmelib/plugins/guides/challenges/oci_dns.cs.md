# Oracle Cloud (OCI) DNS - nastavení pro acme

acme prokazuje jména metodou DNS-01 ve **veřejné zóně Oracle Cloud Infrastructure DNS**, přes DNS REST API `20180115` na `https://dns.<region>.oci.oraclecloud.com`. Každý požadavek podepisuje **API signing key** uživatele IAM (RSA, schéma HTTP podpisů OCI). acme vypíše primární zóny compartmentu a přidává či odebírá jen svou hodnotu přes `PATCH .../zones/{zone}/records/{name}/TXT` (`ADD` / `REMOVE`), takže ostatní hodnoty na jméně zůstanou.

## Co potřebujete

- Veřejnou DNS zónu v OCI (Networking → DNS Management → Zones), delegovanou od registrátora.
- HTTPS (TCP 443) z acme na `dns.<region>.oci.oraclecloud.com`.
- Práva v tenancy vytvořit uživatele, skupinu a policy (nebo administrátora, který to udělá).

## Nastavení Oracle Cloud

1. Vytvořte skupinu a uživatele pro acme: **Identity & Security → Domains →** vaše doména **→ Groups → Create group** `acme-dns`; **Users → Create user** `acme`, přidejte ho do `acme-dns`. Uživatel nepotřebuje heslo do konzole.
2. Vytvořte policy v compartmentu se zónou (nebo v rootu): **Identity & Security → Policies → Create Policy**:

   ```text
   Allow group acme-dns to manage dns in compartment <compartment-name>
   ```

   Toto je výrok, který modul dokumentuje. Užší varianta (zóny číst, záznamy měnit) je možná - před zúžením si ověřte referenci policy pro DNS v OCI.
3. Vytvořte pár klíčů RSA bez hesla:

   ```sh
   openssl genrsa -out acme-oci.pem 2048
   openssl rsa -in acme-oci.pem -pubout -out acme-oci-public.pem
   ```

4. Uživatel → **API keys → Add API key → Paste public key** (`acme-oci-public.pem`). Zkopírujte zobrazený **fingerprint**.
5. Poznamenejte si **OCID tenancy** (Profile → Tenancy), **OCID uživatele**, **identifikátor regionu** (např. `eu-frankfurt-1`) a **OCID compartmentu** se zónou.

S OCI CLI lze totéž udělat přes `oci iam group create`, `oci iam user create`, `oci iam policy create` a `oci iam user api-key upload`.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Tenancy OCID | `ocid1.tenancy.oc1..…` |
| User OCID | `ocid1.user.oc1..…` uživatele acme |
| Key fingerprint | fingerprint z kroku 4 |
| API private key | obsah `acme-oci.pem` (PEM, RSA, bez hesla) |
| Region | např. `eu-frankfurt-1` |
| Compartment OCID | kde jsou zóny; prázdné = tenancy (kořenový compartment) |
| Zone | prázdné (nejdelší zóna compartmentu, do které jméno patří), nebo zóna |
| TTL (s) | 30 (pokročilé) |
| API address | prázdné = `https://dns.<region>.oci.oraclecloud.com` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: podepíše požadavek a vypíše zóny compartmentu; nic nemění.
- S OCI CLI (jako tento uživatel):

  ```sh
  oci dns record rrset get --zone-name-or-id example.com --domain _acme-challenge.www.example.com --rtype TXT
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 NotAuthenticated` | Fingerprint, OCID uživatele nebo tenancy neodpovídají klíči; nebo hodiny acme jdou o víc než 5 minut špatně. |
| `404 NotAuthorizedOrNotFound` | Policy chybí nebo je ve špatném compartmentu, nebo *Compartment OCID* není tam, kde je zóna. |
| Klíč nejde načíst | Privátní klíč má heslo nebo není RSA PEM - vytvořte nový podle kroku 3. |
| Zóna nenalezena | Jde o privátní zónu nebo o endpoint jiného regionu - používají se jen veřejné zóny. |
