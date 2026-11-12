# XMPP server (STARTTLS) - setup for acme

The **XMPP (STARTTLS)** test connects to a chat (Jabber) server on port `5222`, opens a client stream to the XMPP domain, reads the stream features, asks for `<starttls/>`, waits for `<proceed/>` and makes the TLS handshake on the same connection (RFC 6120) - the certificate a chat client would get. It does not sign in. The certificate served is compared with the one acme keeps. Works with Prosody, ejabberd, Openfire and other XMPP servers.

## What you need

- An XMPP server with the certificate for the XMPP domain (and its `conference.`, `upload.` components where they are names of the certificate).
- Network access **from acme** (or its connector) to TCP `5222` (server-to-server is `5269`, not tested here).
- The XMPP domain - the part after the `@` of the addresses; the certificate must hold it.

## Set up the XMPP server

1. Give the server the certificate, its key and the **full chain**:

   Prosody - put them in `/etc/prosody/certs/` (named after the domain, `example.com.crt` / `example.com.key`) or import them:

   ```sh
   prosodyctl --root cert import /etc/acme-deploy/example.com/
   prosodyctl reload
   ```

   ejabberd (`ejabberd.yml`):

   ```text
   certfiles:
     - /etc/ejabberd/tls/example.com.pem
   ```

   then `ejabberdctl reload_config`. Openfire: Server → TLS/SSL Certificates → the identity store.
2. STARTTLS must be offered on c2s (Prosody `c2s_require_encryption = true` still offers it; ejabberd `starttls: true` or `starttls_required: true` on the 5222 listener).
3. The key file must be readable by the server's user (`prosody`, `ejabberd`).
4. Allow TCP `5222` from acme:

   ```sh
   firewall-cmd --permanent --add-service=xmpp-client && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **XMPP (STARTTLS)**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `5222` |
| Name asked for (SNI) | empty: the certificate's first name; `-`: no SNI sent (servers that pick no certificate by name) |
| Name the certificate must hold | empty: the SNI; set it when you connect by IP but the certificate holds a DNS name |
| XMPP domain | the domain the stream is opened to (after the `@` of the addresses). Empty: the SNI, else the address |
| The certificate expected | *the version deployed now* (default); *any version* only when an older one is not a fault |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* or *both* for a server with a dual (RSA + ECDSA) certificate - needs TLS 1.2 on the server |
| Check the chain sent | on - the server must send the intermediates |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (advanced) | normally empty |
| Time limit (s) (advanced) | `15`; raise it for a slow server |
| Fail when not trusted here (advanced) | on for a public CA; off for a certificate of your own CA unless its root is trusted by acme's machine |
| Through a connector (advanced) | *directly*, or a *Connector over SSH* when only another network reaches the server |

## Check it

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects, opens the stream and asks for STARTTLS and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -starttls xmpp -xmpphost example.com -connect chat.example.com:5222 </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

Prosody also: `prosodyctl check certs`.

## Common problems

| Problem | Fix |
|---|---|
| `the server does not offer STARTTLS` | TLS is off for c2s, or no certificate for that domain: check the listener's settings |
| `the XMPP server ended the stream: host-unknown` | the *XMPP domain* is not one the server hosts: set it to the domain after the `@` |
| **another certificate** | the server picked the certificate of another virtual host: set the XMPP domain / SNI to the right one |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
