# cPanel / WHM - nastavení pro acme

acme nainstaluje certifikát, jeho klíč a CA bundle na weby (virtuální hosty) serveru
cPanel jedním ze dvou způsobů:

- **cPanel (UAPI)**: jako samotný účet, `SSL::install_ssl` na vlastní weby účtu (port
  2083). Starší certifikáty, které acme nainstalovalo a žádný web je už nepoužívá, smaže z
  SSL úložiště účtu.
- **WHM API 1**: jako root nebo reseller, `installssl` na doménu kteréhokoli účtu (port
  2087).

cPanel certifikát virtuálního hostu nahradí a webový server restartuje sám.

Pro cPanel & WHM s API tokeny (11.64 a novější; ověřeno proti 11.138).

## Co potřebujete

- HTTPS z acme na server: **2083** (cPanel) nebo **2087** (WHM).
- **API token** účtu cPanel (UAPI), nebo uživatele root / resellera (WHM).
- Pro UAPI zapnutou funkci **SSL/TLS** účtu (WHM → Feature Manager).
- Weby (domény) už na účtu existují.

## Nastavení cPanel / WHM

**Účet cPanel (UAPI)**

1. Přihlaste se do cPanelu jako účet → **Security → Manage API Tokens → Create**.
2. Pojmenujte ho (např. `acme`), volitelně datum vypršení, **Create**, zkopírujte token
   (zobrazí se jen jednou). Tokeny cPanelu mají plná práva účtu - uchovávejte ho jen v acme.

**WHM (root nebo reseller)**

1. WHM → **Development → Manage API Tokens → Generate Token**.
2. Pojmenujte ho `acme`; zrušte **All Features** a povolte jen oprávnění SSL - **SSL Site
   Management** (`ssl`) a **SSL Information** (`ssl-info`); názvy podle toho, jak je WHM ve
   vaší verzi uvádí. Volitelně ho omezte na IP serveru acme (*Allowed IP addresses*,
   novější verze).
3. Uložte a zkopírujte token.

**Obojí**

- Blokuje-li cPHulk nebo firewall (CSF) neznámé adresy, přidejte IP acme na whitelist.
- AutoSSL může nahradit certifikáty, které považuje za k obnově; pokud se těchto webů
  dotýká, vyřaďte je (cPanel → **SSL/TLS Status → Exclude from AutoSSL**).

Test tokenu cPanelu z příkazové řádky:

```sh
curl -s -H "Authorization: cpanel ucet:<token>" https://server.example.com:2083/execute/SSL/installed_hosts | head
```

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Server cPanel nebo WHM, např. `server.example.com` |
| Through | `cPanel (UAPI) - the account's own sites` nebo `WHM API 1 - root or a reseller, any account` |
| HTTPS port | Prázdné: 2083 pro cPanel, 2087 pro WHM |
| User | Účet cPanel (UAPI), nebo `root` / reseller (WHM) |
| API token | Token z výše uvedených kroků |
| Check the device's certificate / CA certificate | Jako u každého HTTPS serveru |
| Domain (nasazení) | Hlavní doména webu, vybraná ze seznamu nebo napsaná; prázdné (UAPI): každý web, který certifikát pokrývá |
| More domains (nasazení) | Jedna na řádek, např. `shop.example.com` |
| Send the CA bundle (nasazení, pokročilé) | Zapnuto; vypnuto: bundle si cPanel dohledá sám |
| Previous versions to keep (pokročilé) | Výchozí 1 (SSL úložiště UAPI) |
| Check what is served | např. `www.example.com:443` |

Akce **List the websites** vypíše virtuální hosty a certifikát každého z nich - nic
nemění.

## Ověření

- **Try**: `signed in to ... as ucet (cPanel); N websites with SSL`.
- V cPanelu: **Security → SSL/TLS → Manage SSL sites**, nebo WHM → **SSL/TLS → Manage SSL
  Hosts**.

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 / `Access denied` | Chybný uživatel nebo token, nebo token vypršel |
| 403 u funkce WHM | Token nemá oprávnění SSL (ACL) |
| `The SSL/TLS feature is disabled` | Zapněte SSL/TLS v seznamu funkcí účtu |
| Spojení odmítnuto / blokováno | Port 2083/2087 blokován, nebo IP acme zablokoval cPHulk/CSF |
| Doména nenalezena | Není to web tohoto účtu (UAPI) - použijte WHM nebo správný účet |
| Certifikát později nahradil AutoSSL | Vyřaďte domény z AutoSSL |
