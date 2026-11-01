# Certificate formats

What acme reads when a certificate is imported (or a file is only looked at,
*Parse*), and what it writes for a target or an export. Reading is
`acmelib/certs/formats.py` (`read_any`); writing is `acmelib/certs/bundle.py`
(`CertBundle.as_format`); keys, requests and certificates are made in
`acmelib/certs/pki.py` with the `openssl` program (OpenSSL 3.0 or later) and
read in Python (`acmelib/certs/asn1.py`), with nothing from pip.

## What acme reads

| File | What it may be | Notes |
|---|---|---|
| `.pem` `.crt` `.cer` `.key` `.txt` | PEM: any number of blocks | Windows line ends, a byte-order mark, words around the blocks (mail text, `Bag Attributes`) are all fine |
| `.cer` `.crt` `.der` | a DER certificate | the extension does not matter: the content is looked at |
| `.key` `.der` | a DER key: PKCS#8, PKCS#1 (RSA), SEC1 (EC), encrypted PKCS#8 | |
| PEM keys | `PRIVATE KEY`, `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, the old OpenSSL `Proc-Type: 4,ENCRYPTED` | encrypted ones need the password |
| `.p7b` `.p7c` | PKCS#7 (PEM `PKCS7` or DER, BER with indefinite lengths too) | certificates only - a P7B never holds a key |
| `.pfx` `.p12` | PKCS#12 | modern (AES-256, PBKDF2) and legacy (RC2-40, 3DES, RC4): a legacy file is read again with `openssl pkcs12 -legacy` by itself |
| `.jks` | Java KeyStore | read in Python: Sun's key protection (SHA-1 keystream), the integrity check with the store password |
| `.jceks` | Java JCEKS | read in Python: keys protected with PBEWithMD5AndTripleDES. A *secret key* entry (a Java object) ends the reading there - certificates and keys before it are read |
| `.zip` | any of these inside | folders, `__MACOSX` and other files are passed over; members up to 20 MB, 200 of them |
| base64 alone | DER without the PEM lines (pasted) | |
| CSR, CRL | noted (`csrs`, `crls`), not imported as a certificate | |

### The certificate, its key, its chain

From everything in the file acme takes:

1. **the certificate**: the one whose public key is the key's (an end entity
   before a CA). Without a key: the end entity (not a CA) that issued none of
   the others. A file of CA certificates only gives the lowest of them.
2. **the key**: the one that belongs to it. A key that belongs to none of the
   certificates is said so in the notes, and not taken.
3. **the chain**: the certificates above it, nearest first, found by the
   issuer's name and its key identifier (AKI → SKI), so the order in the file
   does not matter; duplicates, the certificate itself and certificates of
   other chains are left out (the latter shown as `others`).

`needs_password` is true when something could not be opened without the
password (or with the one given): ask for it and read again.

## What acme writes

| Format | What | For |
|---|---|---|
| `cert-pem` | the certificate, PEM | nearly everything |
| `cert-der` | the certificate, DER | Windows, Java, appliances that want `.cer` |
| `key-pem` | the key, PKCS#8 PEM (`BEGIN PRIVATE KEY`), not encrypted | nginx, Apache, HAProxy, Postfix, Kubernetes |
| `key-rsa` | the key, PKCS#1 (`BEGIN RSA PRIVATE KEY`) - **RSA keys only** | old software, some appliances (NetScaler, old Apache) |
| `key-traditional` | PKCS#1 for RSA, SEC1 (`BEGIN EC PRIVATE KEY`) for EC | software that wants the "traditional" key of its type |
| `key-der` | the key, PKCS#8 DER | Java, some appliances |
| `key-pem-enc` | the key, PKCS#8 PEM encrypted (AES-256-CBC, PBKDF2) with the password | where the key may lie on disk only encrypted |
| `chain-pem` | the chain above the certificate, nearest first | `SSLCertificateChainFile`, `ca.crt` |
| `fullchain-pem` | the certificate and its chain | nginx `ssl_certificate`, most |
| `combined-pem` | the key, the certificate, the chain in one file | HAProxy, Pound, lighttpd, Webmin |
| `p7b` | PKCS#7, the certificate and its chain, DER (as Windows writes it) | Windows, IIS, Exchange |
| `p7b-pem` | the same, PEM | |
| `pfx` / `p12` | PKCS#12: AES-256-CBC, PBKDF2, MAC SHA-256 | Windows Server 2019+, recent Java, most |
| `p12-legacy` | PKCS#12: 3DES (`PBE-SHA1-3DES`) for key and certificates, MAC SHA-1 | Windows Server 2016 and older, Java 8 before 8u301, macOS Keychain before 2023, FortiGate, Palo Alto, older appliances |
| `jks` | a Java KeyStore with one key entry (the key, the certificate, the chain); the key protected with the store password, as `keytool` does | Tomcat, old Java applications. **A password is required.** |

The password is only ever handed to openssl in its environment
(`-passin env:` / `-passout env:`), never on a command line; a key openssl
must read from a file is written into a private directory (0700, in
`/dev/shm` where there is one) and removed at once.

The alias of a PKCS#12 (its friendly name) and of a JKS entry is the
deployment's alias, else the certificate's name. Java lowercases aliases in
JKS; acme writes them so.

### When a device refuses the file

* *"invalid password"* or *"MAC verify failure"* from an older Windows,
  Java or an appliance for a `p12`: take `p12-legacy` (AES and PBKDF2 inside
  PKCS#12 are understood only since Windows Server 2019 / Java 8u301 / OpenSSL 1.1).
* *"unable to load private key"* for `key-pem`: the device wants PKCS#1 - take
  `key-rsa` (and an RSA key).
* the chain is missing on the device: give it `fullchain-pem`, or `chain-pem`
  where it wants the chain apart.

## Keys and requests

Key types: `ec-256` (P-256, the default), `ec-384` (P-384), `rsa-2048`,
`rsa-3072`, `rsa-4096`, `ed25519`. Ed25519 is not accepted by Let's Encrypt
nor by most browsers for TLS; use it for internal CAs and clients that do.

A request (CSR) carries every name as a subjectAltName - a DNS name
(internationalised names written as `xn--`), an IP address (v4 or v6), an
e-mail address, a URI; a prefix `DNS:`, `IP:`, `email:`, `URI:` says which
where it could be mistaken. The common name is the first name when it fits in
64 characters (else the subject is empty and the subjectAltName critical, as
RFC 5280 wants). *Must staple* adds the TLS Feature `status_request`.

## Certificate details

`pki.cert_info()` gives, among others: `subject_dn` (RFC 4514, the most specific
part first: `CN=www.example.com,O=Example,C=CZ`), `serial` (hex, upper case,
no colons), `not_before` / `not_after` (epoch seconds), `sha256` / `sha1`
(the fingerprints, hex upper case), `key_type`, `eku`, `key_usage`, `ski`,
`aki`, `ocsp`, `crl`, `ca_issuers`, `must_staple`, and `ari_id` - the
certificate's identifier for ACME Renewal Information (RFC 9773):
base64url(the AKI's keyIdentifier) `.` base64url(the serial's DER bytes).

## Self-signed certificates

The `selfsigned` issuer signs the certificate with its own key: valid for
*Validity (days)*, with the names asked for, `serverAuth` and `clientAuth`
unless *Extended key usage* says otherwise. Nothing trusts it but what is told
to - pin its fingerprint, or use an own CA ([own-ca.md](own-ca.md)) instead.
