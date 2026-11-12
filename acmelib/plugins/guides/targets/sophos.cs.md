# Sophos Firewall (SFOS / XG) - nastavení pro acme

acme používá **XML API** Sophos Firewallu (`https://<fw>:4444/webconsole/APIController`).
Nahraje certifikát jako PKCS#12 pod novým jménem s datem (`UploadCertificate` - SFOS
nedovolí nahradit používaný certifikát), nasměruje na něj každé zadané **pravidlo
firewallu (WAF)** (ochrana webového serveru) a odstraní starší certifikáty acme nad počet
*Previous versions to keep* (ten, na který se něco odkazuje, zůstane).

acme nemění: certifikát správcovského/uživatelského portálu, SSL VPN a hotspotu.

Pro Sophos Firewall SFOS 18 až 22 (XG i XGS).

## Co potřebujete

- Síťový přístup z acme na správcovskou konzoli firewallu: **TCP 4444**.
- Zapnuté XML API s povolenou IP adresou acme.
- Správce, jehož profil smí měnit **Certificates** (a **pravidla firewallu / ochrany
  webového serveru**, pokud zadáváte pravidla WAF).
- Pravidla WAF, která mají certifikát používat, už existují a mají HTTPS.

## Nastavení Sophos Firewallu

1. Povolte správu přes HTTPS ze zóny, odkud acme přichází: **Administration → Device
   access** → zaškrtněte *HTTPS* pro tuto zónu (nebo přidejte výjimku local service ACL jen
   pro IP acme).
2. Zapněte API: **Backup & firmware → API** → *API configuration*: zapnuto; do *Allowed IP
   address* přidejte IP adresu serveru acme. Použijte.
3. Vytvořte profil přístupu: **Profiles → Device access → Add**, např. `acme-api`, všude
   *None* kromě **Read-write** pro oblast certifikátů a pro firewall / ochranu webového
   serveru (jen jsou-li použita pravidla WAF). Seskupení položek se mezi verzemi SFOS liší -
   ověřte, že jsou zahrnuty *Certificates*.
4. Vytvořte správce: **Authentication → Users → Add**, *User type* **Administrator**,
   *Profile* `acme-api`, např. uživatel `acme` se silným heslem.
5. Poznamenejte si přesná jména pravidel WAF (**Rules and policies → Firewall rules**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Správcovská adresa firewallu, např. `fw.example.local` |
| HTTPS port | `4444` |
| User | `acme` (výchozí) |
| Password | Jeho heslo |
| Check the device's certificate | Zapnuto; vypnout jen dokud má konzole self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu konzole, pokud není veřejná (např. appliance CA firewallu) |
| Firewall (WAF) rules (nasazení) | Jedno jméno pravidla na řádek, např. `WAF www.example.com` |
| Previous versions to keep (pokročilé) | Výchozí 1, `-1` ponechá vše |
| Check what is served | např. `www.example.com:443` |

## Ověření

- Na cíli stiskněte **Try**: acme vypíše certifikáty a odpoví
  `signed in to ...; N certificates there`.
- Ve webové správě po nasazení: **Certificates → Certificates** obsahuje `acme-...`;
  pravidlo WAF ho ukazuje jako *HTTPS certificate*.
- Volání API najdete v **Log viewer → Admin**.

## Časté problémy

| Problém | Řešení |
|---|---|
| `the firewall does not let acme in` | API vypnuté, IP acme není v *Allowed IP address*, špatné heslo. |
| Spojení na 4444 odmítnuto | Správa přes HTTPS není z dané zóny povolena (*Device access*). |
| `the firewall said <code> - ...` při nahrání | Profil nemá právo zápisu k certifikátům. |
| `there is no firewall rule "..."` | Jméno se liší (přesně, včetně velikosti písmen). |
| `the rule ... has no certificate` | Nejde o pravidlo WAF s HTTPS. |
| `the old ... stays (still used?)` | Používá ho ještě něco jiného (VPN, portál); přepněte to a později se odstraní. |
