# Fujitsu iRMC (PRIMERGY, PRIMEQUEST 4000) - setup for acme

acme puts the **HTTPS certificate of the iRMC** (web interface, Redfish) in with **iRMC Remote
Scripting (SCCI)** - the same calls as Fsas' official Ansible module
`fsas.primergy.irmc_certificate`: one `POST https://<irmc>/config` (HTTP Basic) with the SCCI
commands `ConfBMCSslPrivateKey` (0x1981), `ConfBMCSslCertificate` (0x1982) and, when asked,
`ConfBMCSslCaCertificate` (0x1983). Then it **resets the iRMC** - the iRMC serves the new
certificate only after a reset - with `POST /rest/v1/Oem/iRMC/Reset` (as Fsas' role
`irmc_set_certificate` does) or Redfish `Manager.Reset`. **Only the iRMC restarts; the server
and its operating system keep running.** Web interface, Redfish, AVR and virtual media are
away for 1-3 minutes.

**Which versions:** iRMC S6 (PRIMERGY M6/M7/M8, PRIMEQUEST 4000), iRMC S5 (FW 1.25 and later),
iRMC S4 (FW 9.04 and later) - the same SCCI codes on every generation, hence one module.
PRIMEQUEST 3000 MMB is not an iRMC (its certificate goes through the MMB web UI only).

**Keys:** RSA only. acme sends the key as PKCS#1 (`-----BEGIN RSA PRIVATE KEY-----`) - the iRMC
refuses the PKCS#8 keys OpenSSL 3 writes by default. Files are 4 KB at most (RSA 4096 fits).
Choose the key type **RSA 2048** or **RSA 3072** for the certificate.

## What you need

- From acme to the iRMC: **TCP 443** (HTTPS).
- An iRMC user for acme (below). The factory account `admin` works but should not be used.

## Set up the iRMC

1. Create a user for acme with only what certificates need: LAN channel privilege
   **Administrator** (SCCI writes need it), **Configure iRMC Settings** on, **Configure User
   Accounts** off, Video Redirection and Remote Storage off, Shell *None*. With Fsas' Ansible
   collection:

   ```yaml
   - name: Certificate account on the iRMC
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

   In the web interface (S6): **Settings → User Management → iRMC Local User Accounts → Add**,
   the same rights. Redfish role *Administrator* is needed only for the Redfish reset.
2. Check that Remote Scripting answers (it reads only):

   ```sh
   curl -sk -u svc-cert:'<password>' -X POST https://irmc.example.local/config --data-binary \
    '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><CMDSEQ><CMD Context="SCCI" OC="E001" OE="1982" OI="0" CA="-1" Type="GET"><STATUS>0</STATUS></CMD></CMDSEQ>'
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The iRMC's name or IP, e.g. `irmc.example.local` |
| HTTPS port | `443` |
| User / Password | The acme user from step 1 (`svc-cert`) |
| Check the device's certificate | Off for the first deployment (the iRMC has its own self-signed certificate), then on |
| CA certificate (advanced) | The CA of the iRMC's current certificate, if not public |
| Send the intermediate as the CA certificate (deploy) | On: the intermediate goes to `ConfBMCSslCaCertificate` |
| Reset the iRMC afterwards (deploy) | *iRMC REST* (default, as Fsas' role); *Redfish* where `/rest` is not there; *no reset* only if you reset it yourself |
| Check what is served | Empty: acme checks the iRMC's own address after the reset (it waits up to 10 minutes) |

## Check it

- **Try** on the target reads the current certificate through SCCI (nothing is changed).
- After the deployment and the reset:

  ```sh
  openssl s_client -connect irmc.example.local:443 -servername irmc.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong user or password, or the user is disabled. |
| `status …` from SCCI on the SET | The user lacks *Configure iRMC Settings* or the LAN privilege Administrator; or the key is not RSA. |
| SET fails on a PRIMERGY **M8** | Fsas' known issue: "On some M8 generation devices … fails … due to an iRMC issue" - load the certificate in the iRMC web interface (**Tools → Certificates → Current SSL/TLS Certificate → Load from File**) until an iRMC firmware fix. |
| `takes files of 4 KB at most` | Turn off *Send the intermediate as the CA certificate*, or use a shorter chain. |
| Old certificate still served | The reset did not happen: choose *Redfish* for the reset, or reset the iRMC in its web interface. |
| `takes RSA keys only` | Change the certificate's key type to RSA. |
