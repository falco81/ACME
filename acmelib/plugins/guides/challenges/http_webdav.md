# WebDAV (HTTP-01) - setup for acme

acme proves names by HTTP-01 by uploading the token file over **WebDAV** into the folder the name's site is served from: it creates `.well-known/acme-challenge/` (`MKCOL`), puts the file (`PUT`) and deletes it afterwards (`DELETE`) - plain RFC 4918, basic authentication. Works with a hosting's WebDAV access, Nextcloud, Apache `mod_dav`, IIS WebDAV. **Not for wildcards** (they need DNS-01).

## What you need

- A WebDAV URL that maps to the **web root** of the site (`http://NAME/` is served from that folder).
- A WebDAV user allowed to create folders, write and delete files there.
- The name answering on **port 80** to the internet.
- Outbound HTTPS from acme to the WebDAV server. **Use HTTPS** - basic authentication sends the password with each request.

## Set up the WebDAV server

1. Create (or use) a WebDAV user limited to the site's web root.
2. Apache with `mod_dav`, for example:

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

   The Apache user must be able to write into the web root (at least into `.well-known/acme-challenge/`).
3. On a web hosting: enable WebDAV access in the hosting panel and note its URL, user and password.
4. Make sure the site serves files from `.well-known/acme-challenge/` as plain text over HTTP (no redirect to a login page; a redirect to HTTPS on the same name is fine).

## Fill in acme

| acme field | What to put there |
|---|---|
| WebDAV address of the web root | The WebDAV URL of the folder `http://NAME/` is served from, e.g. `https://webdav.example.com/www/` |
| User | The WebDAV user |
| Password | Its password |
| Check the server's certificate | (advanced) leave on |
| Check before the CA is asked | `http://NAME/` (default), the address below, or no check |
| Address the folder is served at | (advanced) Where the folder can be fetched, if not by the name |

## Check it

- **Test** in acme creates the folder if needed, uploads a probe file, reads it back and deletes it.
- With curl:

  ```sh
  curl -u acme -X PROPFIND -H 'Depth: 0' https://webdav.example.com/www/
  curl -u acme -T test.txt https://webdav.example.com/www/.well-known/acme-challenge/test
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Wrong user or password. |
| `403` / `405` on `PUT` | The user may not write there, or WebDAV is not enabled for that path. |
| `409 Conflict` | A parent folder is missing - check the address points to the web root. |
| Test works but the CA gets 404 | The WebDAV folder is not the folder the site is served from. |
