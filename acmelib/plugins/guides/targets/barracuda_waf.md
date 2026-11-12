# Barracuda Web Application Firewall - setup for acme

acme signs in to the WAF's **REST API** (`POST /restapi/<v>/login` gives a token) and,
because a certificate's content cannot be changed in place, **uploads the certificate
under a new dated name** (`acme-<name>-<date>-<serial>`, the private key not exportable).
For each service it reads the **SSL security** and writes it back with `certificate` (or
`ecdsa-certificate`) set to the new name; an older acme name among the SNI domain
certificates is replaced too. Older acme certificates beyond *keep* are deleted when no
service uses them. It signs out at the end.

For Barracuda WAF hardware, virtual and cloud editions with REST API v3 / v3.1 / v3.2
(firmware 9.x and later; v3.2 checked against firmware 11.0, v3.1 against 12.2).

## What you need

- The WAF's management address, REST API port **8443** (HTTPS) reachable from acme.
- The services (web applications) already set up with HTTPS; their names.
- An administrator account that may use the API.

## Set up the Barracuda WAF

1. Make sure HTTPS management is allowed: **BASIC → Administration** (*Web Interface
   HTTPS/SSL Configuration*) - the REST API is served on port 8443.
2. If management access is restricted (**BASIC → Administration → Administrator IP/Range**),
   add the acme server's IP address.
3. Create a dedicated administrator for acme: **ADVANCED → Admin Access Control**
   (role-based administration). Give its role write access to **Certificates**
   (BASIC → Certificates) and to **Services** (BASIC → Services, the SSL settings of the
   services it should change). Exact role object names vary by firmware - check yours;
   the built-in `admin` works but is broader than needed.
4. Note the service names (**BASIC → Services**).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Management IP or name, e.g. `waf.example.local` |
| HTTPS port | `8443` |
| User | The administrator from step 3 (default `admin`) |
| Password | Its password |
| API version (advanced) | `v3.2` (default), `v3.1` or `v3` - as your firmware supports |
| Check the device's certificate | On; off only while the WAF has its self-signed certificate |
| CA certificate (advanced) | The CA of the WAF's management certificate, when not public |
| Service (deploy) | A service picked from the list (*Load the list*) or typed |
| More services (deploy) | One a line, e.g. `www-https` |
| As (deploy) | `the certificate of the service`, `the ECDSA certificate of the service`, or `an SNI domain certificate only` |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | The service's VIP, e.g. `www.example.com:443` |

The action **List the services** shows the services and the certificates their SSL
security uses - it changes nothing.

## Check it

- **Try**: `signed in to the WAF ... (API v3.2); N services, M certificates`.
- On the WAF: **BASIC → Certificates** lists `acme-...`; the service's **Edit → SSL**
  shows it as its certificate.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| 401 on login | Wrong user or password, or the account may not use the API |
| Connection refused on 8443 | HTTPS management / REST API not reachable - check the port and the administrator IP range |
| 404 on `certificates/signed-certificate` | Older firmware: set *API version* to `v3` |
| Service not found | Wrong name - use *List the services* |
| Upload refused (key type) | An EC certificate must go to *the ECDSA certificate of the service* |
| Older certificate not deleted | A service still uses it; it is deleted on a later run |
