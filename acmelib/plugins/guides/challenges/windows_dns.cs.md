# Windows DNS Server - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně **DNS serveru Windows Server**. Windows DNS nemá REST API, takže se acme přihlásí přes **OpenSSH for Windows** a spustí PowerShell cmdlety DnsServer: `Add-DnsServerResourceRecord -Txt` jen tehdy, když jméno naši hodnotu nemá, a `Remove-DnsServerResourceRecord -RecordData HODNOTA -Force` jen tehdy, když ji má - **vždy s `-RecordData`**, takže ostatní TXT záznamy na jménu zůstanou. Windows sám zvýší sériové číslo zóny; zóna integrovaná v AD se k ostatním řadičům domény dostane replikací a acme čeká, dokud hodnotu nemají všechny jmenné servery.

Pro Windows Server 2016 a novější (OpenSSH Server vestavěný od 2019; na 2016 instalovatelný), s rolí DNS Server a modulem PowerShell `DnsServer`.

## Co potřebujete

- SSH (TCP 22) z acme na DNS server - nebo na správcovský stroj s **DNS Server Tools** (RSAT), který na něj dosáhne.
- Vyhrazený (doménový) účet pro acme, který smí zónu měnit.

## Nastavení Windows

1. Nainstalujte a spusťte OpenSSH Server (PowerShell jako administrátor):

   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Set-Service sshd -StartupType Automatic; Start-Service sshd
   New-NetFirewallRule -Name sshd-acme -DisplayName 'OpenSSH (acme)' -Protocol TCP -LocalPort 22 -RemoteAddress 203.0.113.10 -Action Allow
   ```

2. Vytvořte účet (příklad pro doménu) a dovolte mu měnit DNS - obvyklé je členství v **DnsAdmins**; úžeji: dejte mu *Write* / *Create all child objects* jen na zóně (DNS Manager → zóna → **Properties → Security**):

   ```powershell
   New-ADUser -Name acme-dns -AccountPassword (Read-Host -AsSecureString) -Enabled $true
   Add-ADGroupMember -Identity DnsAdmins -Members acme-dns
   ```

3. Veřejný SSH klíč acme vložte do `C:\Users\acme-dns\.ssh\authorized_keys` účtu (u účtu ve skupině **Administrators**: `C:\ProgramData\ssh\administrators_authorized_keys`, čitelný jen pro Administrators a SYSTEM).
4. Připněte v acme klíč hostitele:

   ```sh
   ssh-keyscan -t ed25519 dc1.example.com
   ```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Windows DNS server | `dc1.example.com:22` - stroj, na který se acme přihlásí |
| User | `acme-dns` (nebo `EXAMPLE\acme-dns` / `acme-dns@example.com`, jak sshd očekává) |
| Signs in with / The SSH key | privátní klíč (vytvořený zde) |
| Host keys | řádek z `ssh-keyscan`; nebo *Trust the first key seen* |
| Zone | zóna **přesně tak, jak ji ukazuje DNS Manager**; prázdné: nejdelší ze *Zones there*, jinak přes SOA |
| Zones there | vyplňte ze seznamu, který vypíše *Test* |
| DNS server for the cmdlets | prázdné = stroj, na který se acme přihlásí; jméno DNS serveru při přihlášení na správcovský stroj |
| TTL (s) | 60 (pokročilé) |

## Ověření

- V acme stiskněte **Test**: spustí `Get-DnsServerZone` a vypíše zóny; nic nemění. **Zkušební běh (dry run)** certifikátu přidá testovací záznam a zase ho odebere.
- Na serveru:

```powershell
Get-DnsServerResourceRecord -ZoneName example.com -Name _acme-challenge.www -RRType Txt
```

## Časté problémy

| Problém | Řešení |
|---|---|
| SSH „Permission denied (publickey)“ | Klíč je ve špatném souboru (administrátoři používají `administrators_authorized_keys`) nebo má soubor špatná práva. |
| „Access denied“ z cmdletu | Účet není v DnsAdmins / nemá práva na zónu. |
| „zone … not found“ | *Zone* není zapsaná tak, jak ji ukazuje DNS Manager, nebo je potřeba *DNS server for the cmdlets*. |
| CA vidí záznam pozdě | Replikace AD na ostatní řadiče chvíli trvá - dejte ACME vydavateli delší čekání. |
