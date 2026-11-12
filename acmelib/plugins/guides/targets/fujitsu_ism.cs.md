# Fujitsu Infrastructure Manager (ISM-VA) - nastavení pro acme

acme vymění **HTTPS certifikát virtuální appliance Infrastructure Manager** (ISM, dříve
ServerView Infrastructure Manager; ISM for PRIMEFLEX) - GUI a REST API na portu **25566** -
tak, jak to popisuje ISM User's Guide (4.7.1):

```text
FTP  ism-va:21   nahrát acme-<serial>.key a acme-<serial>.crt do /Administrator/ftp
SSH  ism-va:22   ismadm sslcert set -key /Administrator/ftp/acme-<serial>.key -crt /Administrator/ftp/acme-<serial>.crt
FTP              oba soubory zase smazat (klíč tam nezůstane)
SSH              ismadm power restart
```

**ISM-VA se restartuje:** GUI, REST API, monitoring a plánované úlohy jsou několik minut
nedostupné - nejdřív dokončete běžící úlohy (aktualizace firmwaru, profily). Spravovaných
serverů se to nedotkne. Klienti, kteří certifikát ISM ověřují (soubor `certificate` v Ansible
`ism-ansible`, pluginy vCenter / SCVMM), potřebují novou CA.

**Které verze:** ISM 2.x (ověřeno na V2.9.0) a 3.x (V3.1.0) - stejné příkazy `ismadm`. ISM-VA
**nemá FTPS** („You cannot use the FTPS protocol“) - klíč jde nešifrovaným FTP po správcovské
síti; acme ho hned smaže. REST API se nepoužívá: vyžaduje heslo šifrované AES, což Python acme
neumí.

## Co potřebujete

- Z acme na ISM-VA: **TCP 21** (FTP včetně pasivních datových portů), **TCP 22** (konzole SSH),
  **TCP 25566** (kontrola servírovaného certifikátu).
- Uživatele ISM ve skupině **Administrator** s rolí **Administrator** - konzoli smí použít jen
  takový uživatel (nebo uživatel skupiny s „Manage all nodes“). Užší oprávnění neexistuje.

## Nastavení ISM

1. V GUI ISM: **Settings → Users → Add**: uživatel `svc-cert`, skupina *Administrator*, role
   *Administrator*. Používejte ho jen k tomuto účelu; vestavěný `administrator` nelze propojit
   s AD/LDAP.
2. Ověřte konzoli a oblast FTP tímto uživatelem:

   ```sh
   ssh svc-cert@ism.example.local
   ```

   ```text
   # ismadm sslcert show
   ```

   ```text
   $ ftp ism.example.local
   Name: svc-cert
   ftp> cd Administrator
   ftp> cd ftp
   ftp> ls
   ```
3. Povolte server acme na firewallu před ISM-VA (FTP, SSH).

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | ISM-VA, např. `ism.example.local` |
| Uživatel / Heslo | `svc-cert` (pro konzoli i oblast FTP) |
| Skupina uživatelů (rozšířené) | `Administrator` - soubory jdou do `/<skupina>/ftp` |
| SSH port / Port FTP (rozšířené) | `22` / `21` |
| Port HTTPS GUI (rozšířené) | `25566` |
| Klíč serveru (rozšířené) | Řádek SSH klíče ISM-VA, nebo nechte zapnuté *Věřit prvnímu viděnému klíči serveru* |
| Poslat s certifikátem i řetězec (nasazení) | Zapnuto: `.crt` obsahuje certifikát i mezilehlé certifikáty; vypněte, pokud ho ISM odmítne |
| Potom restartovat ISM-VA (nasazení) | Zapnuto (certifikát se servíruje až po `ismadm power restart`) |
| Zkontrolovat, co se servíruje | Prázdné: acme po restartu zkontroluje `ism.example.local:25566` |

## Ověření

- **Vyzkoušet** se přihlásí do oblasti FTP (vypíše ji) a spustí `ismadm sslcert show` - nic
  nemění.
- Po restartu:

  ```sh
  openssl s_client -connect ism.example.local:25566 -servername ism.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `did not let … in` na FTP | Špatné heslo, nebo uživatel není ve skupině, jejíž složka `ftp` se používá. |
| `ismadm said …` při `sslcert set` | Klíč a certifikát k sobě nepatří, nebo ISM odmítá řetězec: vypněte *Poslat s certifikátem i řetězec*. |
| Konzole odmítnuta | Uživatel nemá roli Administrator ve skupině Administrator (ani „Manage all nodes“). |
| SSH se ptá na kód (MFA) | SSH s vícefaktorovým ověřením je keyboard-interactive: pro acme použijte uživatele bez MFA. |
| ISM je zpět se self-signed certifikátem | Po změně IP/FQDN proběhlo `ismadm sslcert self-create` - nasaďte znovu (vynuceně). |
