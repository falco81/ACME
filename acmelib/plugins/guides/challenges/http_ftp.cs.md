# Webhosting přes FTP / FTPS / SFTP (HTTP-01) - nastavení pro acme

acme prokazuje jména přes HTTP-01 tak, že soubor s tokenem `.well-known/acme-challenge/TOKEN` nahraje do webového prostoru hostingu, který dané jméno obsluhuje - přes **FTPS** (FTP s explicitním TLS), čisté **FTP** nebo **SFTP** (přes SSH) - a poté ho odebere. CA si ho pak stáhne z `http://JMÉNO/.well-known/acme-challenge/TOKEN`. **Ne pro wildcardy** (ty potřebují DNS-01). Má-li účet shell, je lepší volbou validace `http_ssh`.

## Co potřebujete

- Webhosting, jehož webový prostor obsluhuje jméno, a k němu účet FTP nebo SFTP.
- Jméno směřující na hosting a odpovídající do internetu na **portu 80**.
- Síťový přístup z acme na hosting: **port 21** pro FTP/FTPS (plus pasivní datové porty, které server oznámí - FTP jde přímo z acme, ne přes HTTP proxy) nebo **port 22** pro SFTP.
- **Dejte přednost FTPS nebo SFTP**: čisté FTP posílá heslo nešifrovaně.

## Nastavení hostingu

1. V panelu hostingu vytvořte pro acme samostatný účet FTP (nebo SFTP), pokud možno omezený na kořen webu (nebo jen jeho složku `.well-known`).
2. Zjistěte **kořen webu**, jak ho tento účet vidí - často `/www`, `/public_html`, `/httpdocs`, `/web` nebo `/www/example.com`.
3. Nabízí-li hosting FTPS (explicitní TLS, `AUTH TLS`), zapněte ho.
4. Pro SFTP: přidejte veřejný klíč acme (zobrazený v acme u *The SSH key*) do `~/.ssh/authorized_keys` účtu, nebo použijte heslo; připněte host key serveru:

   ```sh
   ssh-keyscan -t ed25519 sftp.example.com
   ```

5. Ověřte, že web servíruje soubory z `.well-known/acme-challenge/` přes HTTP (žádné přesměrování na přihlašovací stránku; `.htaccess` blokující skryté složky musí `.well-known` povolit).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Protocol | `FTPS (FTP with explicit TLS)`, `FTP (no encryption)` nebo `SFTP (over SSH)` |
| Server | `host` nebo `host:port` (21 pro FTP/FTPS, 22 pro SFTP) |
| User / Password | Účet FTP (FTP a FTPS) |
| User, Signs in with, The SSH key, Password | Účet SFTP a jeho klíč nebo heslo (SFTP) |
| Host keys, Trust the first key seen | (SFTP) připnuté řádky host key, nebo důvěra prvnímu viděnému |
| Web root of the site | Složka, ze které se servíruje `http://NAME/`, např. `/www` |
| Check the server's certificate (FTPS) | (pokročilé) nechte zapnuté |
| Timeout (s) | (pokročilé) Výchozí `30` |
| Check before the CA is asked | `http://NAME/` (výchozí), adresa níže, nebo bez kontroly |

## Kontrola

- **Test** v acme nahraje zkušební soubor do `.well-known/acme-challenge/`, přečte ho zpět a odebere.
- Ručně:

  ```sh
  curl --ssl-reqd -u example.com ftp://ftp.example.com/www/
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `530 Login incorrect` | Špatný uživatel nebo heslo. |
| Spojení se po přihlášení zasekne | Mezi acme a serverem jsou blokované pasivní datové porty - otevřete je na firewallu. |
| Chyba TLS (FTPS) | Certifikát neodpovídá jménu serveru - použijte jméno z certifikátu, nebo kontrolu vypněte. |
| Test funguje, ale CA dostane 404 | *Web root of the site* není složka, ze které se web servíruje. |
| Účet jen pro SFTP: soubor zůstane | Nemůže spustit `rm`; soubor se místo toho vyprázdní (neškodné) a úloha to oznámí. |
