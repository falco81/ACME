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
| CRL address | the URL put into what it signs (`crlDistributionPoints`) - where you publish its CRL |
| CA certificate address | the URL of its own certificate put into what it signs (`authorityInfoAccess caIssuers`) - lets clients find a missing intermediate |
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
newest in the authority (`crl_pem`, `crl_at`); export it (*Export → CRL*,
PEM or DER) and publish it at the CRL address - e.g. a deployment that copies
it to a web server. Make it again before half its life is over
(`ca.crl_due()` says when); a client with an expired CRL may refuse every
certificate of the authority.

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
