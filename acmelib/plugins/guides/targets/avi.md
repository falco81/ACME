# VMware Avi Load Balancer (NSX ALB) - setup for acme

acme signs in to the **Avi Controller REST API** (`POST /login`), adds the intermediates
once as CA certificates (`acme-ca-<id>`, Avi builds the chain from them), adds the
certificate as an SSL key and certificate under a dated name, points the virtual services
you list at it in place of the older acme one (`PATCH /api/virtualservice/<uuid>`), and -
when asked - makes it the certificate of the Controller's own portal. Older acme
certificates beyond *keep* are deleted (Avi refuses one still in use). It signs out at the
end. A dual certificate (EC + RSA) gives a virtual service one of each kind.

For Avi Vantage / NSX Advanced Load Balancer / VMware Avi Load Balancer Controllers with
the REST API (versions that take `X-Avi-Version`, e.g. 20.x, 21.x, 22.x and later).

## What you need

- The Controller's management address (cluster IP or a node), **HTTPS, TCP 443**, from
  acme.
- A **local** or remote (LDAP/TACACS+) Controller user that may sign in with a password.
- The names of the virtual services that should use the certificate, and their tenant.

## Set up the Avi Controller

1. Create a role for acme: **Administration → Accounts → Roles → Create** (or
   *Administration → User Credentials/Roles* on older releases). Give it **Write** on:
   - **Templates → Security → SSL/TLS Certificates** (`sslkeyandcertificate`),
   - **Applications → Virtual Services** (`virtualservice`),
   - only for *Controller portal certificate*: **Administration → System Configuration**
     (`systemconfiguration`).
   Everything else can be **No Access**. Role names differ a little between releases -
   check them on yours.
2. Create the user: **Administration → Accounts → Users → Create**, a strong password,
   the role from step 1, and the **tenant** of the virtual services (for example `admin`).
3. If you restrict management access (**Administration → Settings → Access Settings**,
   allowed IPs), add the acme server's address.
4. Note the virtual service names (**Applications → Virtual Services**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Controller cluster IP / DNS name, e.g. `avi-controller.example.local` |
| HTTPS port | `443` |
| User | The user from step 2 (default `admin` - better a dedicated one) |
| Password | Its password |
| Tenant | The tenant of the virtual services and certificates (default `admin`) |
| API version (advanced) | Empty: the Controller's own version; set it (e.g. `22.1.3`) if acme cannot read it |
| Check the device's certificate | On; off only while the Controller has its self-signed certificate |
| CA certificate (advanced) | The CA of the Controller's own certificate, when not public |
| Virtual services (deploy) | One a line, e.g. `vs-www` |
| Controller portal certificate (deploy) | On: also the Controller's own web interface and API - use a separate deployment for it |
| Add the intermediates as CA certificates (deploy, advanced) | On (Avi finds the chain among its CA certificates) |
| Previous versions to keep (advanced) | Default 1; `-1` keeps all |
| Check what is served | The VIP name and port, e.g. `www.example.com:443` |

**Discover** (the form) signs in and offers the Controller's version as *API version*.

## Check it

- **Try**: `signed in to ..., (Avi 22.1.3), tenant admin; N certificates`.
- On the Controller: **Templates → Security → SSL/TLS Certificates** shows
  `acme-<name>-<date>-<serial>`, and the virtual service's **SSL Settings** reference it.
- From a shell:

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `the Controller gave no session on signing in` | Wrong user/password, or the user may not sign in to the API |
| 403 on adding the certificate or patching a virtual service | The role lacks Write on SSL/TLS Certificates or Virtual Services, or the wrong tenant |
| Virtual service not found | Wrong name or wrong *Tenant* |
| Version errors (`X-Avi-Version`) | Set *API version* to the Controller's version |
| Older certificate not deleted | Avi refuses deleting one still in use; it goes later |
| Portal change refused | The role needs Write on System Configuration |
