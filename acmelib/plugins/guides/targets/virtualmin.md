# Virtualmin - setup for acme

acme calls the Virtualmin **Remote API**
(`POST https://<host>:10000/virtual-server/remote.cgi`, HTTP basic auth) with
`program=install-cert` for each virtual server you list, sending the certificate, key and
chain. Virtualmin replaces the domain's certificate files in place, updates the web server
and the other services that use that certificate, and **turns off its own Let's Encrypt
renewal** for that domain. If the domain already has the same certificate
(`list-certs`), nothing is sent. With *Turn SSL on where it is off* acme first runs
`enable-feature --ssl`.

For Virtualmin GPL and Pro on Webmin.

## What you need

- Network access from acme to Webmin: **TCP 10000** (or your Webmin port).
- The **master administrator** of Webmin (usually `root`) - the Remote API takes no other
  account.
- The virtual servers (domains) that should get the certificate.

## Set up Virtualmin / Webmin

1. Allow acme to reach Webmin: open TCP 10000 from the acme server in the firewall
   (Virtualmin's *Linux Firewall* / `firewalld`), and if **Webmin → Webmin Configuration →
   IP Access Control** is restricted, add the acme server's IP.
2. Use the master administrator (`root`) and its password. If Webmin uses two-factor
   authentication for this user, the Remote API with basic auth may be refused - check with
   **Try**.
3. Make sure each virtual server listed has the **SSL website** feature on (*Virtualmin →
   Edit Virtual Server → Enabled features*), or set *Turn SSL on where it is off* in acme.
4. A virtual server that **shares another server's certificate** cannot get its own:
   install-cert refuses it - give the certificate to the server that owns it.
5. You can try the API from a shell on the server:

   ```sh
   virtualmin list-domains --name-only
   virtualmin list-certs --domain example.com --cert
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The server, e.g. `server.example.com` |
| HTTPS port | `10000` |
| User | `root` (default) - the master administrator |
| Password | Its password |
| Check the device's certificate | On; off only while Webmin has its self-signed certificate |
| CA certificate (advanced) | The CA of Webmin's certificate, if not public |
| Virtual server (deploy) | A domain - pick it with *Load the list* or type it |
| More virtual servers (deploy) | One domain a line, e.g. `shop.example.com` |
| Turn SSL on where it is off (deploy) | On to enable SSL for servers without it |
| Check what is served | e.g. `www.example.com:443` |

The certificate's names must cover every virtual server listed.

## Check it

- Press **Try** on the target: acme lists the virtual servers:
  `signed in to Virtualmin ...; N virtual servers`.
- On the server:

  ```sh
  virtualmin list-certs --domain example.com --cert | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` | Not the master administrator, wrong password, or IP Access Control blocks acme. |
| `no virtual server is set` | Fill in *Virtual server* or *More virtual servers*. |
| `Virtualmin said ... does not exist` | The domain is not a virtual server here (check the spelling). |
| `Virtualmin said ... SSL` not enabled | Turn on *Turn SSL on where it is off*, or enable SSL in Virtualmin. |
| Refused for a server sharing a certificate | Install on the server that owns the certificate. |
| Virtualmin's Let's Encrypt renewal stopped | Expected: acme now manages that certificate. |
