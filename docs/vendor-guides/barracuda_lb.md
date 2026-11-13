# Barracuda Load Balancer ADC - by hand (no acme module)

acme has **no module** for the Barracuda Load Balancer ADC: its REST API v2 (documented for firmware 5.1 - 6.1) is described only in a PDF (`ADC_REST-API-v2.pdf` on Barracuda Campus) whose certificate calls, sign-in and ports could not be checked, and the WAF's API (`/restapi/v3.x/certificates/...`) is another product. Take the certificate from acme (*Certificates → the certificate → Download*) and install it by hand - or, once you have the PDF, write a module of your own (docs/writing-a-module.md).

## Which versions

Firmware 6.4 - 6.6 (6.6: OpenSSL 3.0, no TLS 1.0 / 1.1, the upload on *Secure Administration* fixed - use 6.6 or later for the management certificate).

## The account

*ADVANCED > Admin Access Control* → **Administrator Accounts** → **Add Local Administrator** with the role **Admin** (the documents do not say which other role may manage certificates).

## A service certificate

1. Download from acme a **PKCS#12** (the file must end in `.pfx`, or the ADC reads it as PEM; the intermediates inside) or PEM certificate + chain + **unencrypted** key:

```sh
openssl pkcs12 -export -inkey lb.key -in lb.crt -certfile chain.crt -out lb.pfx -passout pass:'<password>'
```

2. *BASIC > Certificates* → **Upload Certificate**: *Certificate Type* **PKCS12 Token** (or *PEM Certificate* with *Assign the associated key* **No**, *Certificate Key*, *Signed Certificate*, *Intermediary Certificates*), **Allow Private Key Export** (No locks the key - and then no configuration backup can be made), a new **Certificate Name** each renewal (e.g. `www-2026-11`), **Upload**.
3. *BASIC > Services* → edit the HTTPS / Secure TCP Proxy service → the new certificate → **Save** (new TLS connections get it).
4. Delete the older certificate once no service uses it. In an HA pair the certificates are synchronised.

## The management certificate

*ADVANCED > Secure Administration* - the HTTPS port and certificate of the web interface, **per unit** (not synchronised in HA): upload the certificate and key there on each unit.

## Check it

```sh
openssl s_client -connect <VIP>:443 -servername <fqdn> -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect <mgmt-host>:443 -showcerts </dev/null | openssl x509 -noout -subject -dates
```

In acme add an HTTPS test of the VIP to the certificate, so its renewal is watched.
