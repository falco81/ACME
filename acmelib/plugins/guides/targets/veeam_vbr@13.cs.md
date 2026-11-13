# Veeam Backup & Replication (VBR 13.0 - 13.1) - nastavení pro acme

acme vymění **certifikát backup serveru** Veeam Backup & Replication na **Windows** – TLS certifikát, podle kterého backup serveru důvěřují komponenty, agenti, plug-iny a konzole; ve **v13** zároveň certifikát **webového UI a REST API** (443, 9419). Přihlásí se na server přes **OpenSSH** a spustí tam PowerShell:

1. přečte verzi a právě používaný certifikát (`Get-VBRBackupServerCertificate`); když je to už tentýž, nic nemění;
2. naimportuje certifikát z jednorázového PKCS#12 do `Cert:\LocalMachine\My` (soubor hned smaže), pojmenuje ho `acme-<jméno>-<datum>-<sériové číslo>` a jeho certifikáty CA dá do *Intermediate Certification Authorities* / *Trusted Root Certification Authorities*;
3. `Get-VBRBackupServerCertificate -FromStore | Where-Object Thumbprint -eq …` a `Add-VBRBackupServerCertificate -Certificate $c` – na v13 s `-Force` (12.3 tento parametr nemá);
4. na **12.3** přesune i http.sys binding REST API: `netsh http delete sslcert ipport=0.0.0.0:9419`, pak `netsh http add sslcert ipport=0.0.0.0:9419 certhash=<thumbprint> appid={284175c4-aa3e-4c6f-a2dd-5a4c80552eb9} certstorename=MY`;
5. restartuje služby, které uvedete (ve výchozím stavu žádné), a smaže starší certifikáty acme nad počet *ponechat* (nikdy ten, který se používá nebo používal).

## Pro které verze

Verze modulu **VBR 13.0 - 13.1** (`13`): Veeam Backup & Replication **13.0.x a 13.1** na Windows (návod výrobce: 13.1.2.57). Volá

```powershell
Add-VBRBackupServerCertificate -Certificate $c -Force
```

a žádný netsh: ve v13 používají **webové UI (443)** i **REST API (443, 9419)** certifikát backup serveru samy (v13.1 i jako výchozí certifikát SAML service providera). acme nejdřív přečte verzi: server 12.x odmítne dřív, než cokoli změní (zvolte *VBR 12.3*); novější ohlásí varováním. Na linuxovém backup serveru (Veeam Software Appliance) SSH a PowerShell pro tohle nejsou – viz jeho vlastní dokumentace.

## Certifikát, který Veeam vezme – přečtěte si před vydáním

Veeam vezme **jen** certifikát **interní CA** udělaný jako certifikát podřízené CA – běžný certifikát webového serveru (a jakýkoli od **veřejné CA**, tedy i Let's Encrypt) odmítne a acme to řekne dřív, než cokoli změní:

- **Basic Constraints**: Subject Type = **CA**, **Path Length Constraint = 0** (šablona AD CS duplikovaná ze *Subordinate Certification Authority*, na kartě *Extensions* → *Basic Constraints*: *Make this extension critical* a *Do not allow subject to issue certificates to other CAs*);
- Key Usage: Digital Signature, Certificate Signing, Off-line CRL Signing, CRL Signing;
- Subject = FQDN serveru (`CN=vbr01.example.local`); SAN = FQDN **i** jméno NetBIOS (`DNS:vbr01.example.local, DNS:vbr01`);
- **RSA 2048** a víc, typ klíče *Exchange* (starý CSP) – **ne ECC, ne CNG**;
- CRL vydávající CA dostupný ze serveru přes HTTP; její kořen v *Trusted Root* (acme tam dá řetězec, který má).

Zdrojem takového certifikátu v acme je vaše interní CA (Microsoft AD CS, privátní CA v acme) s takovým profilem. *Nasadit certifikát, který není certifikátem CA* (pokročilé) kontrolu acme vypne – Veeam ho ale stejně odmítne.

## Co potřebujete na serveru

- **OpenSSH Server** na Windows (`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`, `Start-Service sshd`, `Set-Service sshd -StartupType Automatic`), port 22 otevřený z acme.
- Účet, který je **lokálním administrátorem** (úložiště certifikátů, netsh) a má roli VBR **Backup Administrator** (*Users and Roles*). PowerShell neumí MFA: v *Users & Roles > Security > Edit* ho označte jako **This is a service account (disables two-factor authentication)**.

```powershell
New-LocalUser -Name svc-veeam -Password (Read-Host -AsSecureString "Heslo") -PasswordNeverExpires
Add-LocalGroupMember -Group Administrators -Member svc-veeam
```

Pak v konzoli Veeam: *Main menu > Users and Roles > Add* → `.\svc-veeam`, role *Veeam Backup Administrator*, zaškrtněte *This is a service account*.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **VBR 13.0 - 13.1** |
| Adresa / SSH port / Uživatel | server VBR, `22`, `svc-veeam` |
| Přihlásit se přes / SSH klíč / Heslo | klíč vytvořený v acme (u administrátora do `administrators_authorized_keys`) nebo heslo |
| Složka pro nahrávání (pokročilé) | `C:/Windows/Temp` – PKCS#12 tam leží jen sekundy |
| Restartovat tyto služby (nasazení) | prázdné, nebo `VeeamBackupSvc` (a služba AHV plug-inu pro Nutanix) – **restart zastaví běžící úlohy** |
| Kolik předchozích verzí ponechat (pokročilé) | `1` |
| Zkontrolovat, co se servíruje | acme sám kontroluje `<server>:443` |

## Po změně (kroky podle Veeamu)

Veeam uvádí, že se backup služba musí restartovat (běžící úlohy se zastaví) – uveďte ji v *Restartovat tyto služby*, nebo ji restartujte v servisním okně. Pak: restartujte všechny **konzole** (přijmou nový certifikát); restartujte **Veeam AHV Service** (plug-in pro Nutanix); projděte *Edit* u RHV a CDP proxy a *I/O filter Management* u CDP clusterů; **agenty před změnou** přeskenujte a pro předinstalované agenty vyexportujte nový instalační balíček. v13.1 SAML: stáhněte nový certifikát / metadata SP pro IdP. Skripty, které si připnuly otisk REST API, potřebují nový.

## Ověření

```powershell
Get-VBRBackupServerCertificate | Format-List *
netsh http show sslcert ipport=0.0.0.0:9419
```

```sh
openssl s_client -connect vbr01.example.local:443 -servername vbr01.example.local </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName,basicConstraints,keyUsage
curl -s -H "x-api-version: 1.3-rev1" https://vbr01.example.local/api/v1/serverCertificate
```

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| *would refuse this certificate: no Basic Constraints CA* | běžný koncový certifikát | vydejte ho ze šablony podle podřízené CA (výše) |
| *-FromStore does not offer …* | žádný soukromý klíč, který Veeam umí použít (CNG, ECC), nebo nedůvěryhodný řetězec | RSA ve starém CSP; CA v *Trusted Root* |
| *the module version ... is for ...* | server běží na jiné verzi VBR | zvolte verzi uvedenou ve zprávě |
| po 13.0.1 přestanou komunikovat plug-iny (AHV, Proxmox, cloud) | KB4687: certifikát bez Basic Constraints | viz výše |
| *not as an administrator* | relace SSH není se zvýšenými právy | účet ve skupině *Administrators* |
| klient REST na 12.3 stále vidí starý certifikát | binding 9419 se nepřesunul | zapněte *Přesunout binding REST API* |

Zdroje: VBR 13 User Guide *Backup Server Certificate*, *Using Certificate Signed by Internal CA*; PowerShell reference `Add-VBRBackupServerCertificate`, `Get-VBRBackupServerCertificate` (13 a archiv 12.x); REST API 12.x *TLS Certificate* (netsh); Veeam KB4687.
