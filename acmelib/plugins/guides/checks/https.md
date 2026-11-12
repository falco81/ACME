# Web server (HTTPS) - setup for acme

The **HTTPS** test connects to a web server (port `443` or another), makes the TLS handshake with the certificate's name as SNI - the certificate a browser would get - and, when *Ask over HTTP too* is on, sends an HTTP request (HEAD, GET or OPTIONS, the path and Host header chosen) and checks the status and the words of the answer. The certificate served is compared with the one acme keeps. Any web server, reverse proxy, load balancer or appliance with a web interface.

## What you need

- A web server with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `443`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the web server

1. Configure the server with the certificate, its key and the **full chain** (the leaf followed by the intermediates):

   nginx:

   ```text
   ssl_certificate     /etc/nginx/tls/fullchain.pem;
   ssl_certificate_key /etc/nginx/tls/privkey.pem;
   ```

   Apache httpd 2.4.8+: `SSLCertificateFile` (the full chain) and `SSLCertificateKeyFile`. IIS: the site's **Bindings → https → SSL certificate** (with *Require Server Name Indication* for SNI sites). HAProxy: `bind :443 ssl crt /etc/haproxy/certs/`.
2. Reload the server after each deployment (the target's reload command): `systemctl reload nginx`.
3. Every virtual host of the certificate's names must answer with SNI; a server behind a load balancer: test each node by its IP in *Connect to*.
4. Allow TCP `443` from acme (or its connector):

   ```sh
   firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload
   ```
5. With *Ask over HTTP too*: the path asked (e.g. `/health`) must answer without a sign-in, with a status among those expected; a WAF must not block the request (`User-Agent` can be set in *More headers*).

## Fill in acme

Certificates → **Tests** → *Add a test* → **HTTPS**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `443` |
| Name asked for (SNI) | empty: the certificate's first name; `-`: no SNI sent (servers that pick no certificate by name) |
| Name the certificate must hold | empty: the SNI; set it when you connect by IP but the certificate holds a DNS name |
| Ask over HTTP too | on to check the site answers, not only its certificate |
| Method / Path | `HEAD` (default) or `GET`, `OPTIONS`; the path, e.g. `/` or `/health` |
| Host header | empty: the SNI; a virtual host other than the SNI |
| More headers | `Name: value`, one a line |
| Status expected | `200-399` (default), e.g. `200,301-302`; empty: any |
| The answer holds | words the answer must hold (GET only, the first 64 KB) |
| The certificate expected | *the version deployed now* (default); *any version* only when an older one is not a fault |
| Key asked for | *whichever the server picks*; *RSA*, *ECDSA* or *both* for a server with a dual (RSA + ECDSA) certificate - needs TLS 1.2 on the server |
| Check the chain sent | on - the server must send the intermediates |
| TLS at least / TLS at most, Ciphers (OpenSSL), ALPN (advanced) | normally empty |
| Time limit (s) (advanced) | `15`; raise it for a slow server |
| Fail when not trusted here (advanced) | on for a public CA; off for a certificate of your own CA unless its root is trusted by acme's machine |
| Through a connector (advanced) | *directly*, or a *Connector over SSH* when only another network reaches the server |

## Check it

1. In acme, Certificates → **Tests**, the test → **Test**: acme connects (and sends the HTTP request when asked) and shows what the server served - subject, issuer, validity, names, SHA-256, the TLS version and cipher, the chain length, whether it is trusted here.
2. **Try it on a certificate** compares what is served with a certificate before anything is kept; attached to a certificate, the test runs after each deployment (three tries over half a minute while services restart).
3. From a machine in acme's network, the same by hand:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

```sh
curl -sSI https://www.example.com/health
```

## Common problems

| Problem | Fix |
|---|---|
| **wrong answer** | the status or the words are not as set: check the path, the Host header, a redirect (add `301-302`), or a WAF blocking the request |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
