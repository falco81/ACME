# Microsoft AD CS (přes acme-agent) - nastavení pro acme

Zdroj **Microsoft AD CS (přes acme-agent)** získává certifikáty od CA služby Active Directory Certificate Services **bez jakékoli webové služby**: acme pošle své CSR **agentovi acme-agent na členském serveru Windows** v doméně, ten ho předá CA nativně (rozhraním CA pro žádosti přes RPC - jako `certreq -submit`) jako **účet počítače (Kerberos)** a vrátí certifikát s řetězcem. **acme nedrží žádné přihlašovací údaje domény**, a agent žádá jen o CA a šablony, které jmenuje jeho vlastní politika. **Soukromý klíč nikdy neopustí acme.** Žádost čekající na správce certifikátů se vyzvedne při dalších pokusech.

## Co potřebujete

- **Windows Server v doméně** (2016 nebo novější) s nainstalovaným a připojeným **acme-agentem** - v acme cíl *Windows server s acme-agentem*.
- **Šablonu** s *Subject Name: Supply in the request*, publikovanou na CA.
- **Účet počítače** serveru (`EXAMPLE\WIN1$`, nebo skupinu, kde je) s právy **Read** a **Enroll** na šabloně a **Request Certificates** na CA.
- Ze serveru k CA: TCP 135 a dynamické porty RPC.

## Nastavení Windows

1. Šablona - **certtmpl.msc** → *Web Server* → **Duplicate Template**: jméno (např. `acmeWebServer`), *Subject Name*: **Supply in the request**, *Cryptography*: Key Storage Provider, *Security*: účet počítače → **Read** + **Enroll**. Publikujte ji:

   ```powershell
   Add-CATemplate -Name acmeWebServer -Force
   ```

2. CA (certsrv.msc → Properties → Security): účet počítače → **Request Certificates**. Šifrování RPC na CA nechte zapnuté (výchozí):

   ```powershell
   certutil -getreg CA\InterfaceFlags     # IF_ENFORCEENCRYPTICERTREQUEST
   ```

3. Na členském serveru ve zvýšeném příkazovém řádku - vypište CA a šablony a povolte tu, o kterou smí acme žádat:

   ```bat
   acme-agent adcs cas
   acme-agent allow adcs "ca01.example.local\Example Issuing CA" template=acmeWebServer
   ```

   Více šablon: `template=acmeWebServer,acmeWebServer2`; jakákoli šablona té CA: `template=*`. `acme-agent allow adcs-read` dovolí acme vypsat všechny CA a jejich šablony (jen čtení).

## Vyplňte v acme

Zdroje → **Přidat** → **Microsoft AD CS (přes acme-agent)**.

| Pole v acme | Co tam dát |
|---|---|
| Windows server s acme-agentem | cíl toho členského serveru |
| Certifikační autorita | `ca01.example.local\Example Issuing CA` - *Načíst seznam* se zeptá agenta |
| Šablona | `acmeWebServer` (jméno, ne zobrazované jméno) - *Načíst seznam*; vlastní šablona certifikátu má přednost |
| Typy klíčů, které šablona bere | *RSA i ECDSA* (šablona KSP), *jen RSA* (schéma 1), *jen ECDSA* |
| Poslat jména i jako atribut SAN (pokročilé) | vypnuto |
| Časový limit (s) (pokročilé) | `120` |

Žádné heslo ani certifikát se nezadává.

## Kontrola

- Zdroje → zdroj → **Test**: agent vypíše šablony CA a řekne, zda je vaše nabízená a povolená.
- **Co se stane** u certifikátu ukazuje podepsanou úlohu pro agenta a verdikt jeho politiky.

## Časté potíže

| Potíž | Řešení |
|---|---|
| not allowed by the policy of this machine | spusťte na serveru řádek `acme-agent allow adcs ...`, který chyba uvádí |
| `0x80094012` - nesmí žádat | šablona → Security: Read + Enroll pro účet počítače (skupina: restartujte server) |
| `0x80070005` - přístup odepřen | CA → Security: Request Certificates pro účet počítače |
| `0x800706ba` - server RPC není dostupný | DNS jméno CA, firewall (135 a dynamické porty) |
| Žádost čeká | schvalte ji v certsrv.msc → Pending Requests; u certifikátu zapněte **Ponechat klíč** |
