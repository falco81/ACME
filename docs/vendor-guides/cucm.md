# Cisco Unified Communications Manager (CUCM 14 / 15) - certificates by hand

acme now has a **target** for CUCM: *Cisco Unified Communications Manager (CUCM)* (kind `cucm`, its setup guide on the target's page). CUCM makes the key - Cisco Unified OS Administration takes **no private key** for `tomcat` / `CallManager` - so the target has CUCM's platform CLI make a new key and CSR at every issue (`set csr gen`), imports the certificate signed for it (`set cert import trust` / `own`) and restarts the services (certificate → Key: *Key made by the device*). Cisco documents no API for the OS certificates that acme builds on (AXL is the CM database, not the OS). This page is the same by hand - for a **multi-server (SAN)** certificate (uploaded in the OS Administration GUI only, 14SU2 and later), or without the target: have CUCM's CSR signed (a request with a CSR - *Send a CSR*, docs/request-profiles.md), then upload the certificate.

## The steps (CUCM 15 and SUs)

1. *Cisco Unified OS Administration → Security → Certificate Management → Generate CSR*: *Certificate Purpose* `tomcat` (or `CallManager`, `tomcat-ECDSA` ...), *Distribution* the node or **Multi-server (SAN)**, the SANs (FQDNs of the nodes), key type and length (at most 4096; no wildcard) → **Generate**. From 15SU5 the CN cannot be edited.
2. *Download CSR* → let acme (or your CA) sign it - key usage serverAuth + clientAuth for `tomcat`.
3. *Upload Certificate/Certificate chain*: first the root and intermediate as **`tomcat-trust`** (`CallManager-trust`), then the signed certificate as **`tomcat`** (`CallManager`). A multi-server certificate is uploaded on the **publisher** in the GUI only (14SU2 and later).
4. Restart the services: for `tomcat` **Cisco Tomcat** and **Cisco TFTP** (else phones get the cached certificate); for `CallManager` Cisco CallManager, CTIManager, HAProxy (phones register again) - in a maintenance window, publisher first, then the subscribers one by one.

The CLI (a platform account of privilege 1 is enough):

```text
admin: set csr gen tomcat
admin: show csr list
admin: set cert import trust tomcat-trust
admin: set cert import own tomcat tomcat-trust/<root-ca-file>.pem
admin: utils service restart Cisco Tomcat
admin: utils service restart Cisco Tftp
admin: show cert list own
```

## Check it

```sh
openssl s_client -connect cucm-pub.example.com:8443 -servername cucm-pub.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect cucm-pub.example.com:5061 -showcerts </dev/null | openssl x509 -noout -subject -dates
```

Sources: Administration Guide for Cisco Unified CM 15 (Manage Certificates), Security Guide 15 (Certificates), CLI Reference 15.
