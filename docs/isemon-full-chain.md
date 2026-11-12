# For isemon: send the whole chain (acme 1.0.88)

A description for the isemon side. Nothing here is needed for the pairing to work
from acme 1.0.88 on, but isemon should still be fixed.

## What happened

isemon (`https://monitor.example/`) has a public certificate from **RapidSSL TLS
RSA CA G1** (DigiCert), uploaded by hand under *Settings → Certificates and TLS*.
Pairing from acme (*Targets → An application of ours (acme push)*, the pairing
code, *Test*) failed with:

```
monitor.example could not be reached: [SSL: CERTIFICATE_VERIFY_FAILED]
certificate verify failed: unable to get local issuer certificate (_ssl.c:1082)
```

A browser showed the same address as fine.

## Why

isemon's web server sends **only its own certificate**, without the intermediate
authority that signed it (*RapidSSL TLS RSA CA G1*). The operating systems
trust only the roots (*DigiCert Global Root G2*), not the intermediates, so the
chain from the certificate to a root is missing a link:

- **browsers** fetch the missing link themselves from the address in the
  certificate (*Authority Information Access → CA Issuers*) or have it cached
  from other sites, so they say nothing;
- **everything else** - Python, curl, openssl, Java, Go, rsyslog, monitoring
  agents, mobile apps - does not, and refuses the connection.

Check it from any Linux machine:

```bash
openssl s_client -connect monitor.example:443 -servername monitor.example -showcerts </dev/null
```

The output should show at least two certificates (`0 s:CN=monitor.example`,
`1 s:CN=RapidSSL TLS RSA CA G1`) and end with `Verify return code: 0 (ok)`.
With only one, and `Verify return code: 21 (unable to verify the first
certificate)`, the chain is incomplete.

## What acme does from 1.0.88

acme now does what browsers do: when a server's chain lacks the link, it fetches
the intermediate from the certificate's *CA Issuers* address and tries again.
The fetched intermediate is trusted **only as a link to a root of the system** -
a chain ending anywhere else is still refused. The job says, as a warning:

> monitor.example does not send the intermediate authority with its certificate -
> browsers fetch it themselves, acme fetched it too (RapidSSL TLS RSA CA G1);
> better: let the server send its whole chain

So the pairing works now, but other clients of isemon still fail.

## What to change in isemon

1. **The web server sends the whole chain.** The file the web server is given
   (`ssl_certificate` in nginx, `SSLCertificateFile` in Apache 2.4.8+) must hold
   the certificate **followed by the intermediates, nearest first** - never the
   root. The key stays in its own file.

2. **Uploading a certificate by hand (*Upload*).**
   - Take the certificate with its chain: one PEM with several certificates, a
     separate *chain* field, or a PFX / PKCS#12 (its CA certificates are the chain).
   - Put them in order: from the certificate, each next one the issuer of the
     previous one (by subject/issuer and AKI/SKI), whatever order they came in.
     Leave out the root (a self-signed certificate).
   - **When the chain is missing or incomplete**, complete it as browsers do:
     read *Authority Information Access → CA Issuers* (`http://…`) of the last
     certificate, download it (DER, PEM or PKCS#7 `.p7c`), repeat until the issuer
     is a root of the system's store (at most 3-4 steps). Save the result as the
     chain.
   - **Check before saving**: `openssl verify -untrusted chain.pem cert.pem`
     against the system's roots (`/etc/pki/tls/certs/ca-bundle.crt` on
     AlmaLinux/RHEL). When it fails, do not install it - say why (*the chain is
     incomplete and could not be completed: the authority X is missing*), or
     at least install it with a clear warning.

3. **A certificate from acme (acme push).** acme sends `cert_pem` and
   `chain_pem` (the intermediates, nearest first) - see
   [acme-push-protocol.md](acme-push-protocol.md). isemon must serve
   `cert_pem + chain_pem`, not `cert_pem` alone. The same for the second
   certificate (`alt`, a different key type) when there is one.

4. **Show it in *Settings → Certificates and TLS*.** On the card of the
   certificate in place a line *Chain*: `complete (2 certificates up to DigiCert
   Global Root G2)` in green, or `incomplete - the intermediate RapidSSL TLS RSA
   CA G1 is not sent` in red, with a button *Complete the chain* that does
   step 2 for the certificate already in place.

5. **Self-check after any change of the certificate.** After the web server is
   reloaded, connect to itself (`127.0.0.1:443` with SNI of its name) as a client
   without AIA fetching (Python `ssl`, `openssl s_client -verify_return_error`)
   and record the result; a failure is an event/alert, not silence.

6. **Self-signed and *Request (CSR)*.** The same rules: a certificate signed by
   a company CA from a CSR comes with the company's intermediates - keep and send
   them; only the company's root goes into the clients' trust (and into acme:
   *Check the application's certificate* uses the system's roots, or the CA
   pasted in the target's *More*).

## For the person pairing now

- With acme 1.0.88 or later: nothing - *Test* pairs, with the warning above.
- With an older acme: on isemon, upload the certificate **with the chain** (the
  RapidSSL intermediate after the certificate in one PEM), then *Test* again.
  Switching *Check the application's certificate* off is not a fix: without it
  the first pairing needs the pairing code and nothing proves who answers.
