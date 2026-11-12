# Infoblox NIOS - setup for acme

acme talks to the **WAPI** of the **Grid Master** (HTTPS 443, HTTP basic) and uploads the certificate, its chain and its key - one unencrypted PEM - as the **HTTPS certificate** (`certificate_usage` `ADMIN`: Grid Manager, WAPI, DoT/DoH of the member) or the **Captive Portal** certificate of each Grid member you list, with WAPI's `fileop`:

```text
POST /wapi/v2.11/fileop?_function=uploadinit         {"filename": "acme-....pem"}  -> {"token", "url"}
POST <url>                                           multipart: file = certificate + chain + key
POST /wapi/v2.11/fileop?_function=uploadcertificate  {"certificate_usage": "ADMIN", "member": "<fqdn>", "token": "<token>"}
```

NIOS then replaces the member's certificate (the GUI's *Replace HTTPS Certificate* without asking), restarts its web server and **signs the administrators out**. Nothing is left to delete. The upload `url` may name the Grid Master by an address acme does not reach (NAT): acme sends it to the address of the target, as Infoblox-PS's `ibx-sdk` does.

## Which versions

NIOS **8.6, 9.0 and 9.1** - the same calls (the 9.1 HTTPS certificate pages follow 9.0). WAPI is versioned apart from NIOS and keeps its older versions; acme uses **2.11** by default (in 8.6 - 9.1; NIOS 9.0.6 has 2.13.6). See what your Grid offers:

```sh
curl -s -u svc-cert "https://gm.example.local/wapi/v1.0/?_schema" | python3 -m json.tool | grep -A20 supported_versions
```

Since NIOS 9.0.6 SHA-1 signed certificates are refused, and from 9.0.2 CA certificates are checked against RFC 5280 - an ACME or public CA certificate is fine.

## 1. The account acme uses

The documents do not say which limited-access permission may upload a member's HTTPS certificate; Infoblox's guidance is a **superuser group allowed only the API**:

1. *Administration → Administrators → Groups → Add (+)*: Name `cert-automation`, **Superusers** ticked, **Allowed Interfaces**: only **API (WAPI/PAPI only)** - GUI and CLI unticked. *Save & Close*.
2. *Administration → Administrators → Admins → Add*: a local admin `svc-cert` with a long password, Admin Group `cert-automation`.

The same over WAPI (as a superuser):

```sh
curl -s -u admin -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/admingroup" \
  -d '{"name":"cert-automation","superuser":true,"access_method":["API"],"comment":"acme certificates"}'
curl -s -u admin -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/adminuser" \
  -d '{"name":"svc-cert","password":"<long password>","admin_groups":["cert-automation"]}'
```

*Uncertain*: a limited-access group with the roles **Grid Admin** and **PKI Admin** (or *All Members* read-write) may be enough - try it; a 401/403 on `uploadcertificate` says it is not.

## 2. What the Grid needs

- WAPI runs on the Grid Master - nothing to turn on. `fileop` calls go to the **Grid Master** even for another member (`member` names it).
- Every member listed must exist under its host name (*Grid → Grid Manager → Members*).
- The certificate's names must cover what people and acme use: the Grid Master's FQDN (and of an HA pair its VIP name).
- Correct time (NTP) on the Grid.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the Grid Master, `443` |
| User / Password | `svc-cert` and its password |
| WAPI version (advanced) | `2.11` (or the newest your Grid lists, e.g. `2.13.7`) |
| Check the device's certificate | on (with *CA certificate* when the Grid's certificate is from a private CA); while it still has the default `www.infoblox.com` certificate, off for the first deployment |
| Grid members (deploy) | one host name a line, as the Grid knows them; the **Grid Master last** - its WAPI restarts with the new certificate |
| Use it as (deploy) | *the HTTPS certificate* (ADMIN) or *the Captive Portal certificate* |
| Check what is served (deploy) | acme tests each member on port 443 by itself (the HTTPS certificate); add more here, e.g. a VIP name |

List the **Grid Master Candidate** too: after a promotion it would otherwise serve its own (default) certificate. After the Grid Master's own upload acme waits for its WAPI to come back (asked again every 10 s for a minute).

## Check it

```sh
openssl s_client -connect gm.example.local:443 -servername gm.example.local -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

The member's certificate over WAPI:

```sh
curl -s -u svc-cert -X POST -H "Content-Type: application/json" \
  "https://gm.example.local/wapi/v2.11/fileop?_function=downloadcertificate" \
  -d '{"certificate_usage":"ADMIN","member":"gm.example.local"}'
# then GET the url it gives, and POST fileop?_function=downloadcomplete {"token": "..."}
```

In the GUI: *Grid → Grid Manager → Members → the member → Certificates → HTTPS Cert → Download Certificate*.

**Rollback** when the GUI cannot be opened: on the member's console choose an earlier certificate:

```text
Infoblox > set apache_https_cert
```

## Common problems

| Answer | Meaning | Fix |
|---|---|---|
| `401` | wrong user or password, or the group is not allowed the API | *Allowed Interfaces: API* |
| `403` / *permission* | a limited-access group without the right | a superuser group allowed only the API (step 1) |
| `400` on `uploadcertificate` | a member name the Grid does not know, a SHA-1 certificate, a key that does not match | the member's host name as in *Members*; the certificate |
| *cannot be reached* after the Grid Master's upload | its web server restarts | acme waits a minute; list the Grid Master last |
| the browser still shows the old certificate | a member not listed (a candidate, the other HA node) | list it |

*Unverified* (from the vendor guide): the least permission for non-superusers, the multipart part's name `file` (Infoblox's samples and ibx-sdk use it), what happens to an HA pair's two nodes, and whether only the web server restarts.
