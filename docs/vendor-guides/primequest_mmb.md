# Fujitsu PRIMEQUEST 3000 MMB - no automated deployment

The **Management Board (MMB) of PRIMEQUEST 3000** takes its HTTPS certificate (Web-UI, port 432
by default) **only through its Web-UI**, and only for a CSR the MMB made itself:
**[Network Configuration] → [SSL] → [Create CSR] → [Export Key/CSR] → [Import Certificate]**. It
has no REST/Redfish API for certificates, its CLI only switches HTTPS (`set https`, `set
https_port`), and it cannot import a key made elsewhere - so acme has **no target** for it.
(Tool Reference (MMB) CA92344-1657-22, 02/2026.)

**PRIMEQUEST 4000 has no MMB**: its management is iRMC S6 - use the target **Fujitsu iRMC
(PRIMERGY, PRIMEQUEST 4000)**. The iRMC S5 of each PRIMEQUEST 3000 partition can take the same
target too.

## Doing it by hand (Administrator only)

1. MMB Web-UI as *Administrator*: **[Network Configuration] → [SSL] → [Create CSR]** - key length
   2048, Common Name = the MMB's FQDN (no IP, no wildcard; max. 56 characters). Creating a CSR makes
   the current key unusable: the HTTPS certificate stops working until the import - do it in one
   window, use HTTP (8081) meanwhile.
2. **[Export Key/CSR] → [Export CSR]** (and **[Export Key]** - keep it safe).
3. Have it signed; the MMB's CSR has **no SAN** - your CA must add `DNS:<FQDN>`. In acme you can
   sign it with an own authority: *Certificates → New* with the CSR sent in.
4. **[Import Certificate]**, then **[Network Protocols]**: HTTPS *Enable*, port 432 or 443, HTTP
   *Disable*.

```text
# set https_port 443
# set https enable
# show https
```

## Check it

```sh
openssl s_client -connect mmb.example.local:432 -servername mmb.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

acme can still watch the expiry: add a TLS test of `mmb.example.local:432` to the certificate.
