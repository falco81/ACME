# FTP / FTPS / SFTP web hosting (HTTP-01) - setup for acme

acme proves names by HTTP-01 by uploading the token file `.well-known/acme-challenge/TOKEN` into the web space of a hosting that serves the name - over **FTPS** (FTP with explicit TLS), plain **FTP**, or **SFTP** (over SSH) - and taking it away afterwards. The CA then fetches `http://NAME/.well-known/acme-challenge/TOKEN` from the hosting. **Not for wildcards** (they need DNS-01). Where the account has a shell, the `http_ssh` validation is the better choice.

## What you need

- A web hosting whose web space serves the name, and an FTP or SFTP account for it.
- The name pointing at the hosting, answering on **port 80** to the internet.
- Network access from acme to the hosting: **port 21** for FTP/FTPS (plus the passive data ports the server announces - FTP goes straight from acme, not through an HTTP proxy) or **port 22** for SFTP.
- **Prefer FTPS or SFTP**: plain FTP sends the password in the clear.

## Set up the hosting

1. In the hosting panel, create a separate FTP (or SFTP) account for acme, limited if possible to the site's web root (or just its `.well-known` folder).
2. Find the **web root** as that account sees it - often `/www`, `/public_html`, `/httpdocs`, `/web` or `/www/example.com`.
3. Enable FTPS (explicit TLS, `AUTH TLS`) if the hosting offers it.
4. For SFTP: add acme's public key (shown in acme under *The SSH key*) to the account's `~/.ssh/authorized_keys`, or use a password; pin the server's host key:

   ```sh
   ssh-keyscan -t ed25519 sftp.example.com
   ```

5. Make sure the site serves files from `.well-known/acme-challenge/` over HTTP (no redirect to a login page; an `.htaccess` blocking hidden folders must allow `.well-known`).

## Fill in acme

| acme field | What to put there |
|---|---|
| Protocol | `FTPS (FTP with explicit TLS)`, `FTP (no encryption)` or `SFTP (over SSH)` |
| Server | `host` or `host:port` (21 for FTP/FTPS, 22 for SFTP) |
| User / Password | The FTP account (FTP and FTPS) |
| User, Signs in with, The SSH key, Password | The SFTP account and its key or password (SFTP) |
| Host keys, Trust the first key seen | (SFTP) the pinned host key line(s), or trust the first one seen |
| Web root of the site | The folder `http://NAME/` is served from, e.g. `/www` |
| Check the server's certificate (FTPS) | (advanced) leave on |
| Timeout (s) | (advanced) Default `30` |
| Check before the CA is asked | `http://NAME/` (default), the address below, or no check |

## Check it

- **Test** in acme uploads a probe file into `.well-known/acme-challenge/`, reads it back and takes it away.
- By hand:

  ```sh
  curl --ssl-reqd -u example.com ftp://ftp.example.com/www/
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Common problems

| Problem | Fix |
|---|---|
| `530 Login incorrect` | Wrong user or password. |
| Connection hangs after login | Passive data ports are blocked between acme and the server - open them on the firewall. |
| TLS error (FTPS) | The certificate does not match the server name - use the name on its certificate, or turn off the check. |
| Test works but the CA gets 404 | *Web root of the site* is not the folder the site is served from. |
| SFTP-only account: the file stays | It cannot run `rm`; the file is emptied instead (harmless) and the job says so. |
