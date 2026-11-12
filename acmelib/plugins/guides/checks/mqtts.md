# MQTT broker over TLS - setup for acme

The **MQTT over TLS** test connects to a message broker's TLS port (`8883`) and makes the TLS handshake at once - the certificate a device or MQTT client would get. It sends no MQTT packet (no CONNECT, no credentials). The certificate served is compared with the one acme keeps. Mosquitto, EMQX, HiveMQ, RabbitMQ (MQTT plugin), VerneMQ.

## What you need

- An MQTT broker with a TLS listener with TLS switched on and a certificate configured - normally the files acme deploys there (a Linux / Unix (SSH) target, a Windows target...).
- Network access **from acme** (or from the connector it goes through) to the server, TCP port `8883`.
- The DNS name clients use, held by the certificate; acme sends it as SNI.

## Set up the MQTT broker

1. Give the broker's TLS listener the certificate, its key and the chain. Mosquitto (`/etc/mosquitto/conf.d/tls.conf`):

   ```text
   listener 8883
   certfile /etc/mosquitto/tls/fullchain.pem
   keyfile  /etc/mosquitto/tls/privkey.pem
   ```

   EMQX: `listeners.ssl.default.ssl_options.certfile` / `keyfile`. RabbitMQ: `mqtt.listeners.ssl.default = 8883` and `ssl_options.certfile` / `keyfile` / `cacertfile`.
2. Reload after each deployment (the target's reload command) - Mosquitto reloads its certificates on `SIGHUP`: `systemctl reload mosquitto`.
3. The key must be readable by the broker's user (`mosquitto`).
4. Allow TCP `8883` from acme:

   ```sh
   firewall-cmd --permanent --add-port=8883/tcp && firewall-cmd --reload
   ```

## Fill in acme

Certificates → **Tests** → *Add a test* → **MQTT over TLS**.

| acme field | What to put there |
|---|---|
| Connect to | the name or IP address of the server - e.g. one node behind a load balancer. Empty: the first name of the certificate the test is attached to (or the target's address) |
| Port | `8883` |
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
openssl s_client -connect mqtt.example.com:8883 -servername mqtt.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate -fingerprint -sha256
```

## Common problems

| Problem | Fix |
|---|---|
| `the TLS handshake failed` (certificate required) | the listener wants a client certificate (`require_certificate true`): acme sends none, so test a listener without it, or switch it off |
| `... does not answer` | the TLS listener is not configured or the port is closed |
| `host:port does not answer (no connection in 15 s)` / `cannot be reached` | a firewall or ACL drops acme: allow TCP from acme's address (or the connector's) to the port; check the service listens on that interface, not only on 127.0.0.1 |
| `... cannot be looked up` | acme cannot resolve the name: fix DNS, or put the IP address in *Connect to* and the name in *Name asked for (SNI)* |
| **an old version** | the renewal did not reach the server: the service was not reloaded after the deployment, or another node behind the balancer still has the old file |
| **another certificate** | the server is configured with another file than the one acme deploys, or SNI picks another virtual host / another certificate |
| **serves it - but** no intermediate | configure the full chain (certificate + intermediates) on the server, not the leaf alone |
| `the TLS handshake failed` | no common TLS version or cipher: check the server's TLS settings, or *TLS at least / at most* and *Ciphers* in the test |
