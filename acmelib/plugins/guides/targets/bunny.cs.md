# bunny.net CDN - nastavení pro acme

acme nasadí váš vlastní certifikát na **vlastní jména hostitelů pull zóny bunny.net**
místo bezplatného certifikátu bunny, přes API bunny.net (`https://api.bunny.net`, API klíč
účtu v hlavičce `AccessKey`). Pull zónu najde podle ID nebo jména; každé jméno hostitele -
zadané, nebo každé, které certifikát pokrývá - dostane celý řetězec a klíč
(`POST /pullzone/<id>/addCertificate`). bunny drží jeden certifikát na jméno hostitele:
nový nahradí předchozí, nic nezůstává k úklidu.

Pro pull zóny bunny.net CDN (jakýkoli tarif s vlastními jmény hostitelů).

## Co potřebujete

- Účet bunny.net a pull zónu (jméno nebo ID).
- Vlastní jména hostitelů **už přidaná** do pull zóny, s DNS CNAME směřujícím na zónu
  (acme jména nepřidává).
- Odchozí HTTPS z acme na `api.bunny.net` (TCP 443), přímo nebo přes proxy.

## Nastavení bunny.net

1. Přihlaste se do dashboardu bunny.net.
2. Otevřete **Account settings → API key** (API klíč účtu) a zkopírujte ho.
   **Tento klíč dává plný přístup k účtu** - bunny.net nemá užší klíč jen pro pull zóny;
   uchovávejte ho jen v acme a při úniku ho vyměňte.
3. Otevřete **CDN → pull zóna → Hostnames** a ověřte, že je tam každé jméno hostitele.
   Poznamenejte si jméno nebo ID pull zóny (je v URL stránky pull zóny).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | API klíč účtu z kroku 2 |
| Through the proxy (pokročilé) | Výchozí zapnuto: ven přes Settings → Proxy |
| Timeout (s) (pokročilé) | Výchozí 30 |
| Pull zone (nasazení) | Jméno nebo ID, např. `www-example` |
| Hostnames (nasazení) | Jedno na řádek, např. `cdn.example.com`; prázdné: každé jméno, které certifikát pokrývá |
| Check what is served | např. `cdn.example.com:443` |

Akce **List the pull zones** vypíše pull zóny a jejich jména hostitelů a zda mají
certifikát - nic nemění.

## Ověření

- **Try**: `signed in to bunny.net; N pull zones`.
- V dashboardu: **Pull zone → Hostnames** ukazuje certifikát u každého jména.

  ```sh
  openssl s_client -connect cdn.example.com:443 -servername cdn.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 při Try | Chybný API klíč - použijte klíč účtu (Account settings → API key), ne heslo storage zóny |
| `no pull zone is set` / nenalezeno | Chybné jméno nebo ID - použijte *List the pull zones* |
| Jméno hostitele se nezměnilo | Není to jméno pull zóny, nebo ho certifikát nepokrývá |
| Stále se servíruje bezplatný certifikát | Počkejte minutu na okraj sítě a ověřte znovu |
| `api.bunny.net` nedostupné | Povolte odchozí HTTPS nebo nastavte proxy |
