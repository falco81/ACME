# EST server - setup for acme

The **EST (RFC 7030)** source asks a CA for certificates by *Enrollment over Secure Transport*: acme reads the CA chain (`GET /.well-known/est[/<label>]/cacerts`) and posts the request it made (`POST .../simpleenroll`, base64 PKCS#10) - **the private key never leaves acme**. When the CA holds the request for approval (`202 Accepted` + `Retry-After`), acme waits a while and asks again with the same request at the next try. Renewals may go to `simplereenroll` where the server wants that. Spoken by EJBCA, Keyfactor, Cisco (IOS CA, ISE, libest), DigiCert TLM, Entrust, GlobalSign, Nexus and others. Not spoken: server-side key generation (`serverkeygen`) and full CMC. EST has no revocation.

## What you need

- An EST server over HTTPS reachable **from acme** (port 443 or the server's own, e.g. 8443), directly or through Settings → Proxy.
- Its address and, on a server with several CAs, the **label** (EJBCA: the EST alias).
- Credentials the server accepts: a user and password (HTTP Basic), a client certificate it knows, or both.
- The root of the EST server's **TLS** certificate when it is from a private CA (the RFC 7030 *explicit trust anchor*).

## Set up the EST server

EJBCA (check that your edition and version include the EST protocol):

1. **System Configuration → EST Configuration → Add** an alias, e.g. `acme`. The URL becomes `https://ejbca.example.local/.well-known/est/acme/`.
2. In the alias: *Operational Mode* **RA**, the **CA**, the **End Entity Profile** and **Certificate Profile** for TLS servers (allowing DNS names, the key types acme uses, server authentication).
3. Authentication: *Require HTTP Basic* with a user and password for acme, or client-certificate authentication (the client certificate's issuer trusted, the RA administrator role given to it).
4. Allow DNS names of the certificates in the end entity profile (as many SANs as your certificates have).

Other servers: create an EST client account / registration authority entry for acme with permission to enroll on the CA profile for TLS server certificates; note the label and the credentials.

Check the server from acme's network:

```sh
curl --cacert est-tls-root.pem https://est.example.local/.well-known/est/acme/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -noout
```

## Fill in acme

Sources → **Add** → **EST (RFC 7030)**.

| acme field | What to put there |
|---|---|
| EST server | `https://est.example.local` - `/.well-known/est` is added when the path lacks it |
| CA label | the label / EJBCA alias; empty: the server's default CA |
| Signing in | *User and password (HTTP Basic)*, *Client certificate*, *Client certificate and password*, or *Nothing* |
| User / Password | for HTTP Basic |
| Client certificate / Client certificate's key | PEM, with its chain - for certificate sign-in |
| CA certificate of the server (trust anchor) | the root of the EST server's TLS certificate; empty: the system's roots |
| Check the server's TLS certificate (advanced) | on |
| Renewals by simplereenroll (advanced) | off - every certificate by `simpleenroll`; on only where the server wants re-enrollment |
| Wait for approval (s) (advanced) | `60`; a held request is asked for again at later tries anyway |

## Check it

- Sources → the source → **Test** (Try it): acme reads `cacerts` (and `csrattrs`) and signs in - it orders nothing.
- Then issue a test certificate and check its chain: `openssl verify -CAfile root.pem -untrusted chain.pem cert.pem`.

## Common problems

| Problem | Fix |
|---|---|
| `401` | wrong user/password, or the server wants a client certificate instead |
| TLS error / certificate verify failed | set *CA certificate of the server* to the root of the EST server's TLS certificate |
| `404` | wrong label/alias, or the path is not `/.well-known/est` |
| The request waits (202) and never comes | an operator must approve it on the CA; acme asks again at each try |
| Refused for a name or a key type | the CA profile does not allow that name, that number of SANs, or that key type |
| Renewal refused with `simplereenroll` | switch *Renewals by simplereenroll* off - acme holds no client certificate of the old certificate |
