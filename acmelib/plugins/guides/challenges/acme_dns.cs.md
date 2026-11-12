# acme-dns - nastavení pro acme

acme prokazuje jména přes DNS-01 pomocí serveru [acme-dns](https://github.com/joohoi/acme-dns): hodnotu TXT pošle do API serveru `/update` a na dotaz CA v DNS odpovídá sám server acme-dns. Ve vašem DNS stačí jednou pro každé jméno záznam CNAME `_acme-challenge.JMÉNO` → *fulldomain* účtu. Funguje s libovolným serverem acme-dns (vlastním nebo veřejným, např. `auth.acme-dns.io`).

## Co potřebujete

- Server acme-dns dosažitelný z acme přes HTTPS (API, obvykle port 443) a z internetu na **portu 53 (UDP i TCP)** - ptá se ho CA.
- Jeden účet acme-dns na jméno, nejvýše na dvě jména: **účet si drží jen dvě nejnovější hodnoty TXT**, takže certifikát s více jmény potřebuje účet pro každé jméno (pole *Accounts by name (JSON)*).
- Přístup k vašemu DNS, kam jednou přidáte záznamy CNAME.

## Nastavení acme-dns

1. Pokud provozujete vlastní server, postupujte podle README acme-dns: jeho `config.cfg` určuje zónu, za kterou odpovídá (např. `auth.example.org`), adresy, na kterých naslouchá, a API; tuto zónu na něj delegujte záznamem `NS` (a záznamem `A` pro server) v nadřazené zóně.
2. Zaregistrujte účet. Omezte ho na adresu acme pomocí `allowfrom` (CIDR):

   ```sh
   curl -s -X POST https://auth.example.org/register \
        -H 'Content-Type: application/json' \
        -d '{"allowfrom": ["203.0.113.10/32"]}'
   ```

   Odpověď obsahuje `username`, `password`, `subdomain` a `fulldomain`. Heslo si uschovejte - acme-dns ho ukáže jen jednou.
3. Do DNS každého jména jednou přidejte:

   ```text
   _acme-challenge.example.com.  3600  IN  CNAME  d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org.
   ```

   (vpravo je `fulldomain` účtu). Pro `example.com` i `*.example.com` slouží tentýž CNAME.
4. Pro více jmén zopakujte registraci pro každé jméno a účty zapište jako JSON (formát, který používají acme-dns-client a lego):

   ```text
   {"example.com": {"username": "...", "password": "...", "subdomain": "...", "fulldomain": "..."},
    "example.org": {"username": "...", "password": "...", "subdomain": "...", "fulldomain": "..."}}
   ```

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| acme-dns server | Adresa API, např. `https://auth.example.org` |
| Username | `username` z `/register` |
| Password (API key) | `password` z `/register` |
| Subdomain | `subdomain` z `/register` |
| Full domain | `fulldomain` z `/register` - kam vede CNAME |
| Accounts by name (JSON) | (pokročilé) více účtů, jeden na jméno, viz výše - místo čtyř polí |
| Check the server's certificate | (pokročilé) nechte zapnuté; vypněte jen u testovacího serveru s certifikátem podepsaným sám sebou |
| Wait until it is seen by, Wait at least, Resolvers | (pokročilé) jak acme čeká na záznam - výchozí hodnoty stačí |

## Kontrola

- **Test** v acme se zeptá serveru na `/health` a ukáže CNAME, který je třeba vložit.
- Ověřte CNAME a server:

  ```sh
  dig +short CNAME _acme-challenge.example.com
  curl -s https://auth.example.org/health
  dig @auth.example.org TXT d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `forbidden` z `/update` | Špatné jméno/heslo, nebo adresa acme není v `allowfrom` účtu. |
| `no acme-dns account for NAME` | Jméno chybí mezi klíči v *Accounts by name (JSON)* - přidejte ho (nebo `*.JMÉNO`). |
| CA vidí starou hodnotu | Více než dvě jména na jednom účtu: použijte účet pro každé jméno. |
| CA záznam TXT nenajde | CNAME chybí nebo vede jinam; nebo je port 53 serveru acme-dns z internetu zavřený. |
| Chyba TLS | Certifikát serveru není důvěryhodný - opravte ho, nebo (jen pro test) vypněte *Check the server's certificate*. |
