# WebDAV (HTTP-01) - nastavení pro acme

acme prokazuje jména přes HTTP-01 tak, že soubor s tokenem nahraje přes **WebDAV** do složky, ze které se servíruje web daného jména: vytvoří `.well-known/acme-challenge/` (`MKCOL`), vloží soubor (`PUT`) a poté ho smaže (`DELETE`) - čisté RFC 4918, basic autentizace. Funguje s přístupem WebDAV webhostingu, Nextcloudem, Apache `mod_dav`, IIS WebDAV. **Ne pro wildcardy** (ty potřebují DNS-01).

## Co potřebujete

- URL WebDAV, která odpovídá **kořeni webu** (`http://JMÉNO/` se servíruje z této složky).
- Uživatele WebDAV, který tam smí vytvářet složky, zapisovat a mazat soubory.
- Jméno odpovídající do internetu na **portu 80**.
- Odchozí HTTPS z acme na server WebDAV. **Používejte HTTPS** - basic autentizace posílá heslo s každým požadavkem.

## Nastavení serveru WebDAV

1. Vytvořte (nebo použijte) uživatele WebDAV omezeného na kořen webu.
2. Apache s `mod_dav`, například:

   ```text
   Alias /dav /var/www/example.com
   <Location /dav>
       DAV On
       AuthType Basic
       AuthName "acme"
       AuthUserFile /etc/apache2/dav.passwd
       Require user acme
   </Location>
   ```

   ```sh
   htpasswd -c /etc/apache2/dav.passwd acme
   ```

   Uživatel Apache musí smět zapisovat do kořene webu (aspoň do `.well-known/acme-challenge/`).
3. Na webhostingu: zapněte v panelu hostingu přístup WebDAV a poznamenejte si jeho URL, uživatele a heslo.
4. Ověřte, že web servíruje soubory z `.well-known/acme-challenge/` jako prostý text přes HTTP (žádné přesměrování na přihlašovací stránku; přesměrování na HTTPS se stejným jménem nevadí).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| WebDAV address of the web root | URL WebDAV složky, ze které se servíruje `http://NAME/`, např. `https://webdav.example.com/www/` |
| User | Uživatel WebDAV |
| Password | Jeho heslo |
| Check the server's certificate | (pokročilé) nechte zapnuté |
| Check before the CA is asked | `http://NAME/` (výchozí), adresa níže, nebo bez kontroly |
| Address the folder is served at | (pokročilé) Kde lze složku stáhnout, pokud ne přes jméno |

## Kontrola

- **Test** v acme v případě potřeby vytvoří složku, nahraje zkušební soubor, přečte ho zpět a smaže.
- Pomocí curl:

  ```sh
  curl -u acme -X PROPFIND -H 'Depth: 0' https://webdav.example.com/www/
  curl -u acme -T test.txt https://webdav.example.com/www/.well-known/acme-challenge/test
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný uživatel nebo heslo. |
| `403` / `405` u `PUT` | Uživatel tam nesmí zapisovat, nebo WebDAV pro tu cestu není zapnutý. |
| `409 Conflict` | Chybí nadřazená složka - ověřte, že adresa vede na kořen webu. |
| Test funguje, ale CA dostane 404 | Složka WebDAV není ta, ze které se web servíruje. |
