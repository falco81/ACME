# Omnissa Horizon Connection Server - nastavení pro acme

acme dá Connection Serveru Horizon 8 certifikát **Machine Identity** - TLS certifikát serveru, HTML Access a Blast Secure Gateway - stejně, jako to ručně popisuje dokumentace Horizonu, přes **OpenSSH a PowerShell**:

1. nahraje PKCS#12 (scp) a naimportuje ho do **Local Computer → Personal** s **exportovatelným klíčem** (`Import-PfxCertificate -Exportable`) - neexportovatelný klíč Horizon odmítne („No qualifying certificates in keystore");
2. mezilehlé certifikáty naimportuje do **Intermediate Certification Authorities** (`Cert:\LocalMachine\CA`);
3. sebere popisný název (friendly name) **`vdm`** certifikátu, který ho měl (přejmenuje ho na `acme-was-vdm-...`, nesmaže ho), a dá `vdm` novému - mít ho smí jen jeden certifikát;
4. **restartuje službu Connection Serveru** (`wsbroker`, *Omnissa Horizon Connection Server*) a počká, až běží - **probíhající provisioning a relace Blast se přeruší**;
5. smaže starší certifikáty, **které naimportovalo acme**, nad počet *ponechat* (nikdy ten s `vdm`, nikdy takový, který acme neimportovalo).

`import-certificate` z REST API se nepoužívá: neumí restartovat službu, kterou Horizon k převzetí certifikátu potřebuje.

## Pro který Horizon je tento návod

Horizon 8 **2212 - 2609** (stejné kroky). Každý Connection Server podu má vlastní Machine Identity: pro každý jeden cíl, nasazovat jeden po druhém (server nejdřív vyřaďte na load balanceru). `vdm.ec` (Machine Identity s ECDSA) od 2312.

## Nastavení Connection Serveru

1. **OpenSSH Server** na serveru s Windows (Nastavení → Volitelné funkce, nebo):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd; Set-Service sshd -StartupType Automatic
   New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Protocol TCP -LocalPort 22 -Action Allow
   ```

2. **Účet, který je místním administrátorem** serveru (import do úložiště počítače, přejmenování a restart služby jsou mimo role Horizonu) - doménový účet, např. `CORP\svc-hzn-cert`, ve skupině *Administrators*:

   ```powershell
   Add-LocalGroupMember -Group Administrators -Member 'CORP\svc-hzn-cert'
   ```

   S klíčem: veřejný klíč z acme (karta klíče v acme: *Jak to nastavit*) patří u administrátora do `C:\ProgramData\ssh\administrators_authorized_keys`.

3. **Kořenová CA** v *Trusted Root Certification Authorities* každého Connection Serveru (kořen veřejné CA tam obvykle je):

   ```powershell
   Import-Certificate -FilePath C:\certs\root.cer -CertStoreLocation Cert:\LocalMachine\Root
   ```

4. **UAG před serverem**: změní-li se CA nebo thumbprint certifikátu, aktualizujte na každém UAG *Horizon Settings → Connection Server URL Thumbprints* - jinak služba přestane fungovat.

## Certifikát

- CN/SAN: FQDN, přes které se klienti připojují (serveru nebo load balanceru).
- **EKU jen Server Authentication** - certifikátu s Client Authentication vydanému po 15. 3. 2026 prohlížeče a HTML Access nedůvěřují.
- RSA (popisný název `vdm`); ECDSA s `vdm.ec` od verze 2312.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | FQDN Connection Serveru, např. `cs01.example.local` |
| SSH port / Uživatel | `22`, `CORP\svc-hzn-cert` (nebo `Administrator`) |
| Přihlásit se přes / SSH klíč / Heslo | klíč (vytvořený v acme) nebo heslo |
| Složka pro nahrávání (pokročilé) | `C:/Windows/Temp` - PKCS#12 se hned smaže |
| Popisný název (nasazení) | `vdm`; `vdm.ec` pro certifikát ECDSA |
| Restartovat službu Connection Serveru (nasazení) | zapnuto - vypnout jen, když ji restartujete sami v servisním okně |
| Mezilehlé certifikáty do úložiště CA počítače (nasazení, pokročilé) | zapnuto |
| Kolik předchozích verzí ponechat (pokročilé) | `1` |
| Zkontrolovat, co se servíruje | prázdné: acme ověří `<adresa>:443` |

## Kontrola

*Vyzkoušet* se přihlásí, ověří, že účet je administrátor, a vypíše službu a současný certifikát `vdm`. Po nasazení:

```sh
openssl s_client -connect cs01.example.local:443 -servername cs01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext extendedKeyUsage
```

Na serveru:

```powershell
Get-ChildItem Cert:\LocalMachine\My | Where-Object FriendlyName -eq 'vdm' | Select-Object Subject, NotAfter, Thumbprint, HasPrivateKey
```

Horizon Console: dashboard (*System Health → Connection Servers*: „SSL Certificate: Valid").

## Časté potíže

| Potíž | Řešení |
|---|---|
| `not as an administrator (elevated)` | Účet není ve skupině *Administrators* serveru. |
| `there is no Horizon Connection Server service` | Není to Connection Server (nebo je služba přejmenovaná) - ověřte `Get-Service wsbroker`. |
| „No qualifying certificates in keystore", server červeně | Klíč není exportovatelný nebo `vdm` mají dva certifikáty - acme importuje s exportovatelným klíčem a název přesouvá; ověřte, že ho nemá jiný. |
| Červený stav: revokace | Server nedosáhne na CRL/OCSP CA - povolte to, nebo nastavte `CertificateRevocationCheckType` (HKLM\Software\Omnissa\Horizon\Security). |
| Klienti přes UAG po změně nefungují | Aktualizujte thumbprint Connection Serveru na UAG. |
