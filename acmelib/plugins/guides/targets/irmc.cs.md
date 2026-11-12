# Fujitsu iRMC (PRIMERGY, PRIMEQUEST 4000) - nastavení pro acme

acme vloží **HTTPS certifikát iRMC** (webové rozhraní, Redfish) přes **iRMC Remote Scripting
(SCCI)** - stejnými voláními jako oficiální Ansible modul Fsas `fsas.primergy.irmc_certificate`:
jeden `POST https://<irmc>/config` (HTTP Basic) s příkazy SCCI `ConfBMCSslPrivateKey` (0x1981),
`ConfBMCSslCertificate` (0x1982) a na přání `ConfBMCSslCaCertificate` (0x1983). Potom **iRMC
resetuje** - nový certifikát iRMC použije až po resetu - voláním `POST /rest/v1/Oem/iRMC/Reset`
(tak to dělá role Fsas `irmc_set_certificate`) nebo Redfish `Manager.Reset`. **Restartuje se
jen iRMC; server a jeho operační systém běží dál.** Webové rozhraní, Redfish, AVR a virtuální
média jsou 1-3 minuty nedostupné.

**Které verze:** iRMC S6 (PRIMERGY M6/M7/M8, PRIMEQUEST 4000), iRMC S5 (FW 1.25 a novější),
iRMC S4 (FW 9.04 a novější) - kódy SCCI jsou ve všech generacích stejné, proto jeden modul.
MMB serverů PRIMEQUEST 3000 není iRMC (certifikát se tam mění jen ve webovém rozhraní MMB).

**Klíče:** jen RSA. acme posílá klíč jako PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) - klíče
PKCS#8, které OpenSSL 3 zapisuje ve výchozím stavu, iRMC odmítne. Soubory mají nejvýše 4 KB
(RSA 4096 se vejde). Pro certifikát zvolte typ klíče **RSA 2048** nebo **RSA 3072**.

## Co potřebujete

- Z acme na iRMC: **TCP 443** (HTTPS).
- Uživatele iRMC pro acme (níže). Tovární účet `admin` funguje, ale nepoužívejte ho.

## Nastavení iRMC

1. Vytvořte pro acme uživatele jen s tím, co certifikáty potřebují: oprávnění kanálu LAN
   **Administrator** (zápis přes SCCI ho vyžaduje), **Configure iRMC Settings** zapnuto,
   **Configure User Accounts** vypnuto, Video Redirection a Remote Storage vypnuto, Shell
   *None*. Kolekcí Ansible od Fsas:

   ```yaml
   - name: Certifikační účet na iRMC
     fsas.primergy.irmc_user:
       irmc_url: "{{ inventory_hostname }}"
       irmc_username: "{{ irmc_admin }}"
       irmc_password: "{{ irmc_admin_password }}"
       validate_certs: false
       command: create
       name: svc-cert
       password: "{{ svc_cert_password }}"
       enabled: true
       lan_privilege: Administrator
       serial_privilege: User
       config_bmc_enabled: true
       config_user_enabled: false
       avr_enabled: false
       storage_enabled: false
       redfish_enabled: true
       redfish_role: Administrator
       shell: None
     delegate_to: localhost
   ```

   Ve webovém rozhraní (S6): **Settings → User Management → iRMC Local User Accounts → Add**,
   se stejnými právy. Role Redfish *Administrator* je potřeba jen pro reset přes Redfish.
2. Ověřte, že Remote Scripting odpovídá (jen čte):

   ```sh
   curl -sk -u svc-cert:'<heslo>' -X POST https://irmc.example.local/config --data-binary \
    '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><CMDSEQ><CMD Context="SCCI" OC="E001" OE="1982" OI="0" CA="-1" Type="GET"><STATUS>0</STATUS></CMD></CMDSEQ>'
   ```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | Jméno nebo IP iRMC, např. `irmc.example.local` |
| Port HTTPS | `443` |
| Uživatel / Heslo | Uživatel pro acme z kroku 1 (`svc-cert`) |
| Ověřovat certifikát zařízení | Při prvním nasazení vypnuto (iRMC má vlastní self-signed certifikát), potom zapnuto |
| Certifikát CA (rozšířené) | CA současného certifikátu iRMC, není-li veřejná |
| Poslat mezilehlý certifikát jako certifikát CA (nasazení) | Zapnuto: mezilehlý certifikát jde do `ConfBMCSslCaCertificate` |
| Potom resetovat iRMC (nasazení) | *iRMC REST* (výchozí, jako role Fsas); *Redfish*, kde `/rest` není; *bez resetu* jen když iRMC resetujete sami |
| Zkontrolovat, co se servíruje | Prázdné: acme po resetu zkontroluje vlastní adresu iRMC (čeká až 10 minut) |

## Ověření

- **Vyzkoušet** u cíle přečte současný certifikát přes SCCI (nic nemění).
- Po nasazení a resetu:

  ```sh
  openssl s_client -connect irmc.example.local:443 -servername irmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný uživatel nebo heslo, případně zakázaný uživatel. |
| `status …` od SCCI při zápisu | Uživatel nemá *Configure iRMC Settings* nebo oprávnění LAN Administrator; nebo klíč není RSA. |
| Zápis selže na PRIMERGY **M8** | Známý problém Fsas („On some M8 generation devices … fails … due to an iRMC issue“) - do opravy firmwaru iRMC nahrajte certifikát ve webovém rozhraní iRMC (**Tools → Certificates → Current SSL/TLS Certificate → Load from File**). |
| `takes files of 4 KB at most` | Vypněte *Poslat mezilehlý certifikát jako certifikát CA*, nebo použijte kratší řetězec. |
| Stále se servíruje starý certifikát | Reset neproběhl: zvolte reset přes *Redfish*, nebo iRMC resetujte ve webovém rozhraní. |
| `takes RSA keys only` | Změňte typ klíče certifikátu na RSA. |
