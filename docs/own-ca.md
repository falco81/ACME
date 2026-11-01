# acme's own certificate authorities

For what no public CA may sign - internal names (`*.corp.local`), private IP
addresses, clients, devices, servers that must not appear in Certificate
Transparency - acme keeps certificate authorities of its own: a root, and
intermediates under it, under one another, or under a CA elsewhere (your
corporate root, AD CS).

*Settings → Authorities* (`fulladmin`), the API `/api/cas/*`, the code
`acmelib/certs/ca.py`. Certificates come from them through the
`internal_ca` issuer.

## The way it is meant to be

```
  Root CA (ec-384, 10-20 years, path length 1)      kept offline in spirit: signs only intermediates
     └─ Issuing CA (ec-256/ec-384, 5 years, path length 0)    signs the servers and clients
          ├─ www.corp.example (397 days)
          └─ vpn-client-17 (1 year, clientAuth)
```

Give the root's certificate to what must trust (Group Policy, `/usr/local/share/ca-certificates`,
MDM, the Java truststore); sign with the intermediate. When an intermediate is
lost or compromised, revoke it at the root and make another - nothing has to
trust anew.

## Making one

| Field | |
|---|---|
| Name | how acme calls it (unique) |
| Subject | CN (required), O, OU, C (two letters), ST, L |
| Key type | `ec-384` (default), `ec-256`, `rsa-2048/3072/4096`, `ed25519` (not for TLS in browsers) |
| Days | its validity; an intermediate never lasts past its parent - the days are cut there |
| Parent | none: a root (self-signed); else the authority that signs it |
| Path length | how many authorities may be under it (empty: no limit; under a parent with a limit: one less than the parent's). 0: it signs only end entities |
| CRL days | how long each CRL it makes is valid (`nextUpdate`), 7 by default |
| Publish on acme | on (the default while `pki_publish` is on): its CRL and certificate are served by acme itself at `/pki/` - see [Publishing on acme](#publishing-on-acme) - and the two addresses below, when left empty, are acme's own |
| CRL address | the URL put into what it signs (`crlDistributionPoints`) - where its CRL is published. Empty: acme's own (`http://NAME/pki/<slug>.crl`) when it is published on acme, else none |
| CA certificate address | the URL of its own certificate put into what it signs (`authorityInfoAccess caIssuers`) - lets clients find a missing intermediate. Empty: acme's own (`http://NAME/pki/<slug>.crt`) when published |
| OCSP address | put into what it signs (`authorityInfoAccess OCSP`) when you run a responder (acme does not run one) |
| Name constraints | what it may sign for: `corp.example` (that domain and below), `IP:10.0.0.0/8`, `email:corp.example`, `URI:.corp.example`; `!DNS:bad.corp.example` excludes. Written into its certificate (critical), checked by acme before signing and by every client after. An intermediate under a constrained parent takes the parent's constraints unless given its own |

The addresses are those of **what this authority signs**, so a root's CRL
address goes into its intermediates, the intermediate's into the servers.

A new authority makes its first (empty) CRL at once.

### Under a CA elsewhere

*Request for a CA elsewhere* (`ca_csr`) makes the key here and gives a CSR
(asking for `CA:TRUE` and `keyCertSign`); have it signed - on AD CS with the
*Subordinate Certification Authority* template:

    certreq -submit -attrib "CertificateTemplate:SubCA" acme-intermediate.csr

and *install* what comes back (`ca_install_cert`: PEM, DER or a P7B with the
chain). Until then the authority waits and signs nothing. The authority is
marked *external* when its parent is not one of acme's.

### Importing one

An authority made elsewhere can be brought in with its key (PEM, DER, PKCS#12
with its password, encrypted keys with theirs). It must be a CA certificate
(`CA:TRUE`, `keyCertSign` where a key usage is given) and the key must be its
key. Its parent is found among acme's authorities by itself.

## Signing

Every certificate gets

* a random 20-byte serial (positive, checked unique for the authority),
* `notBefore` an hour back (clocks that are a little behind still take it),
  `notAfter` after the days asked - never past the authority's own end,
* basicConstraints `CA:FALSE` (critical), keyUsage (critical:
  `digitalSignature`, plus `keyEncipherment` for RSA keys), extendedKeyUsage
  (`serverAuth, clientAuth` unless the profile says otherwise),
* subjectKeyIdentifier and authorityKeyIdentifier,
* the authority's CRL, CA certificate and OCSP addresses,
* the names of the request (or of the profile) as subjectAltName,
* TLS Feature `status_request` with *must staple*.

The profile of `ca_sign(store, ca_id, csr_pem, days, profile)`:

| Key | |
|---|---|
| `eku` | `['serverAuth']`, `['clientAuth']`, `['codeSigning']`, `['emailProtection']`, OIDs |
| `key_usage` | in place of the default: `digitalSignature`, `keyEncipherment`, `keyAgreement`, … |
| `must_staple` | true / false |
| `subject` | `{CN, O, OU, …}` in place of the request's subject |
| `names` | in place of the request's names |
| `is_ca`, `path_len`, `name_constraints` | sign an intermediate (for a request from elsewhere) |

Everything signed is listed under the authority (`cert_ca_issued`: serial,
subject, names, dates, fingerprint, the certificate of acme it belongs to),
so both nodes of a cluster sign and revoke from the same list: the signing
itself is `openssl ca` with a configuration and an index written for that
one run and removed after.

A CSR from elsewhere is signed with *Sign a request* (`/api/cas/sign_csr`).

## Revoking and the CRL

Revoking (by serial, with a reason: `unspecified`, `keyCompromise`,
`CACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`,
`certificateHold`) marks it in the list and makes the CRL anew. A
certificate on hold (`certificateHold`) can be released again; the others
cannot.

Each CRL (`openssl ca -gencrl`) carries the next CRL number and the
authority's key identifier, and is valid for *CRL days*. acme keeps the
newest in the authority (`crl_pem`, `crl_at`). The node that leads (the
renewer's lease, docs/certificates.md "Two nodes") makes every authority's
CRL anew once half its life is over (`ca.crl_due()`), at its look every
`certs_check_min` minutes, and after every revocation - so a CRL never runs
out; a client with an expired CRL may refuse every certificate of the
authority. acme publishes it itself ([below](#publishing-on-acme)); or export
it (*Export → CRL*, PEM or DER) and publish it elsewhere - e.g. a deployment
that copies it to a web server.

## Publishing on acme

With `pki_publish` on (the default; *Settings → Renewal and notices*), every
node and the VIP address serve the CRL and the certificate of each authority
that is published, over plain HTTP, to anybody:

| URL | |
|---|---|
| `http://NAME/pki/` | a page listing what is published (the authority, its CRL and certificate, SHA-256, the next CRL by) |
| `http://NAME/pki/<slug>.crl` | the newest CRL, DER, `application/pkix-crl` - what goes into `crlDistributionPoints` |
| `http://NAME/pki/<slug>.crl.pem` | the same, PEM |
| `http://NAME/pki/<slug>.crt` | the authority's certificate, DER, `application/pkix-cert` - what goes into `authorityInfoAccess caIssuers` |
| `http://NAME/pki/<slug>.pem` | the same, PEM |

`NAME/pki/` is `pki_base_url` when set (`http://pki.example.com/pki/` - a name
of your own that points at acme); else `http://` and the VIP address's name
when the VIP address is on, else this server's name. `<slug>` is made from
the authority's name the first time it is needed (`Example Issuing CA` →
`example-issuing-ca`) and kept in the authority, so it never changes once
certificates carry it.

**What happens.** nginx sends `/pki/` - on port 80 and on 443, with no sign-in
and, on port 80, never a redirect to HTTPS (a CRL fetcher seldom follows one,
and fetching the CRL must not depend on a certificate the CRL decides about)
- to `web/pki.php`, which asks the daemon's public, read-only routes
`GET /api/pki/index`, `/api/pki/crl?ca=<slug>[&format=pem]` and
`/api/pki/cert?ca=<slug>[&format=pem]`. They give only what is published: an
unknown slug, an authority whose switch is off, one without a certificate
yet, or anything with `pki_publish` off is 404. nginx limits each address
(`acme_all`, 10 a second, bursts of 40), the daemon all of them together (50
a second). A CRL may be kept by caches for 5 minutes, a certificate for an
hour.

**Two nodes.** Everything comes from the database, so each node and the VIP
address answer the same, and whichever node holds the VIP address serves its
name. The CRL is made by the node that leads and is in the database for both
at once.

**The firewall.** Port 80 is let in by the card *HTTP / HTTPS* of the
firewall. When *Who may reach the pages* keeps the pages to some networks,
port 80 is still let in from anywhere while publishing is on (as for HTTP-01:
`fw_auto` in the engine) - a client anywhere checks a certificate against the
CRL. Only `/.well-known/acme-challenge/` and `/pki/` answer there; everything
else on port 80 goes to HTTPS, where the lists apply.

**New authorities.** Made or imported with publishing on, an authority is
published and its CRL and CA certificate addresses are acme's own unless
given - so every certificate it signs carries a `crlDistributionPoints` and
an `authorityInfoAccess caIssuers` that point at acme. Switch *Publish on
acme* off in the form (`"published": false` in `POST /api/cas/create`) for
one that is not to be.

**An authority made before.** Its detail on *Authorities* has the section
*Published on acme*: the URLs (each with a copy button), whether it is
published (a switch: `POST /api/cas/publish {id, published}`, `acme
--ca-publish CA on|off`), the last CRL and its next update, when it is made
again, and whether what it signs carries acme's addresses. *Use acme's own
URLs* (`POST /api/cas/pki_urls {id}`, `acme --ca-pki-urls CA`) puts them into
what it signs **from then on**; certificates issued before keep the
addresses they have until they are renewed.

**Check it** (`POST /api/cas/pki_check {id}`, `acme --ca-pki-check CA`)
fetches the CRL and the certificate at their URLs over HTTP from the daemon,
as a client would, and checks them: `openssl crl -inform DER` reads it, its
issuer is the authority, its signature is the authority's, its nextUpdate is
in the future, and the certificate is the authority's. A failure says what -
the name not pointing at acme, port 80 closed, a proxy in between.

**Later.** acme runs no OCSP responder; the *OCSP address* stays for one of
your own. One served from the same database is a possible next step.

## Exports

| What | |
|---|---|
| `cert`, `cert-der` | the authority's certificate (what clients are told to trust, for a root) |
| `chain` | its certificate and every one above it, PEM |
| `p7b` | the same, PKCS#7 |
| `crl`, `crl-der` | its newest CRL (made anew when it is due) |
| `bundle` | a ZIP: the certificate, the chain, the CRL (PEM and DER) |
| `csr` | the request of an authority waiting for its certificate |
| `key` | its key (PKCS#8; encrypted with the password when one is given) - `fulladmin` only, written to the events |
| `p12` | the key, the certificate and the chain (password required) - `fulladmin` only |

## The key

An authority's key is sealed with the installation's key (`secrets.key`
beside every backup), bound to its row (`cert_cas:<id>:key`): copied into
another row it does not open. It is opened only to sign or to make a CRL, and
then written for openssl only into a private directory (0700, in `/dev/shm`
where there is one), overwritten and removed at once.

An authority with authorities under it cannot be deleted; delete those first.
Deleting an authority forgets what it signed - its certificates stay valid
until they end, and can no longer be revoked.
