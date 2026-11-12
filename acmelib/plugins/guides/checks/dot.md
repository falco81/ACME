# DNS over TLS resolver - setup for acme

The **DNS over TLS** test connects to a DNS resolver's DoT port (`853`, RFC 7858) and makes the TLS handshake at once - the certificate a system resolver or a phone (Private DNS) would get. It sends no DNS query. The certificate served is compared with the one acme keeps. Unbound, Knot Resolver, BIND 9.18+, dnsdist, AdGuard Home, Technitium.

## What you need

- A resolver with DNS over TLS on with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `853`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the resolver

1. Give the resolver the certificate, its key and the chain. Unbound (`unbound.conf`):

   ```text
   server:
     interface: 0.0.0.0@853
     tls-port: 853
     tls-service-pem: "/etc/unbound/tls/fullchain.pem"
     tls-service-key: "/etc/unbound/tls/privkey.pem"
   ```

   BIND 9.18+: a `tls` block (`cert-file`, `key-file`) and `listen-on port 853 tls <name> { any; };`. Knot Resolver: `net.tls('/path/fullchain.pem', '/path/privkey.pem')`. dnsdist: `addTLSLocal('0.0.0.0:853', cert, key)`.
2. Reload after each deployment (the target's reload command) - Unbound needs a restart for new TLS files: `systemctl restart unbound`.
3. Allow TCP `853` from acme:

   ```sh
   firewall-cmd --permanent --add-service=dns-over-tls && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **DNS over TLS**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `853` |
| Name asked for (SNI) | empty: the certificate's first name; `-`: no SNI sent (servers that pick no certificate by name) |
| Name the certificate must hold | empty: the SNI; set it when you connect by IP but the certificate holds a DNS name |
| The certificate expected | *the version deployed now* (default); *any version* only when an older one is not a fault |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* or *both* for a server with a dual (RSA + ECDSA) certificate - needs TLS 1.2 on the server |
| Check the chain sent | on - the server must send the intermediates |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (advanced) | normally empty |
| Time limit (s) (advanced) | `15`; raise it for a slow server |
| Fail when not trusted here (advanced) | on for a public CA; off for a certificate of your own CA unless its root is trusted by acme's machine |
| Through a connector (advanced) | *directly*, or a *Connector over SSH* when only another network reaches the server |

## Check it

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects with TLS at once and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -connect dns.example.com:853 -servername dns.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

`kdig +tls @dns.example.com example.com` (Knot's dig) asks a real query over TLS.

## Common problems

| Problem | Fix |
|---|---|
| `... does not answer` | DoT is not enabled (Unbound: no `interface ...@853`) or port 853 is closed |
| **an old version** | the resolver was not restarted after the deployment |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
