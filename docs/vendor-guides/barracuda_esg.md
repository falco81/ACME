# Barracuda Email Security Gateway - by hand (no acme module)

acme has **no module** for the Barracuda Email Security Gateway: its only API (XML-RPC `config.get` / `config.set` on `/cgi-mod/api.cgi`) has no documented variable for the web interface's certificate, and Barracuda says not to use undocumented ones. Email Gateway Defense (the cloud service) has no customer certificate at all - Barracuda manages it; only its TLS policies are yours. Take the certificate from acme and install it by hand on each unit.

## Which versions

ESG firmware 8.x - 9.4 (the steps are documented "for version 8 and above"; 9.1 added *Supported SSL Protocols*; 9.4.0.029 stopped the *Use* button resetting TLS to 1.1).

## The account

Only the **Admin** role reaches *ADVANCED > Secure Administration* - there is no smaller role for certificates. Limit it: *Administrator IP/Range*, *HTTPS/SSL Access Only* = Yes.

## Install it

1. From acme download the certificate with its chain (PEM, "Apache" format) and the **unencrypted** key (PKCS#12 is not documented - convert it):

```sh
openssl pkcs12 -in esg.pfx -nocerts -nodes -out esg.key
openssl pkcs12 -in esg.pfx -clcerts -nokeys -out esg.crt
openssl pkcs12 -in esg.pfx -cacerts -nokeys -out chain.crt
```

2. *ADVANCED > Secure Administration* → **Certificate Type** = **Trusted** → **Upload** the private key → **Upload** the certificate and the intermediates → **Save**.
3. Check *Supported SSL Protocols* (TLSv1.2 + TLSv1.3) after the change.
4. A cluster does **not** synchronise these certificates - repeat it on every unit.

The certificate is the one of the web interface (administration and the users' quarantine); the documents do not say whether SMTP STARTTLS on port 25 uses it - check below.

## Check it

```sh
openssl s_client -connect esg.example.com:443 -servername esg.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect esg.example.com:25 -starttls smtp -servername esg.example.com </dev/null | openssl x509 -noout -subject -issuer -dates
```

In acme add an HTTPS test (and an SMTP STARTTLS test) to the certificate, so its renewal is watched.
