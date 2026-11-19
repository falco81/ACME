# Load balancers in front of a cluster

Two acme nodes both answer the pages - the enrolment pages (the certificate
portal), the administration and the API - so any load balancer can spread
them over both, round robin,
**without sticky sessions** (a sign-in and everything half done is in the
database). Instead of a load balancer of your own, the pages can also use the
built-in VIP address (VIP, active/standby): [tls-and-vip.md](tls-and-vip.md).
Use one or the other for the pages; with the VIP address off, a load
balancer works exactly as described here.

The renewals and deployments are not the balancer's business: one node at a
time does them (the one that leads - [high-availability.md](high-availability.md)),
whichever node the pages are asked of. acme's own DNS server, for DNS-01,
answers on each node by itself ([dns-server.md](dns-server.md)).

In the examples: the nodes `acme1` 192.0.2.11 and `acme2` 192.0.2.12, the
balancer 192.0.2.5, the name `acme.example.cz`.

---

## The health check: what it really looks at

Every node answers `GET /healthz` over HTTPS (and HTTP). It is public, short,
never cached, and checks the whole path a real request takes:

| URL | 200 means | 503 when |
|---|---|---|
| `/healthz` | nginx → PHP-FPM → the acme daemon → the database all answer; the node is not in maintenance | anything on that path is down; the database does not open; the node is in maintenance or being upgraded |
| `/healthz?check=all` | the same, and replication runs both ways | the above, or `degraded: replication not running / lost` - for **monitoring** only, not for a balancer (a node cannot fix its peer's replication, and both would be taken out) |

The body says why, on one line: `ok up`, `maintenance`,
`down: the daemon is not answering`, `down: the database does not open`,
`down: the pages cannot read the daemon's API token`. Anything else after
`?check=` is the same as `/healthz`. Match on the status code, or on the
body starting with `ok `.

`/healthz` says words only - never the node's name (since 1.0.101; it said `ok acme1`
before). Since 1.0.101, `/api/health` asked **without** the
token (the only route of the daemon's API that answers without it) says no node
name and not whether any account exists. It still says whether the daemon answers,
whether the database opens, whether the node is in maintenance, the language, and
the sign-in ways the sign-in page offers. Point a balancer at `/healthz`, not at the
daemon's port.

Recommended: check every 2-5 s, take a node out after 2-3 failures, back in
after 2 successes, timeout 3-5 s.

**Maintenance and upgrades take the node out by themselves**: from the
moment a node goes into maintenance its `/healthz` says 503, and an upgrade
(from the pages or `install.sh --upgrade`) waits 20 s after that before it
touches anything - set the balancer to notice within that time.

---

## The client's own address

Every sign-in limit, allow list and log in acme is per client address. Behind
a balancer that hides it, everybody shares the balancer's address - five
wrong passwords from anybody would then lock out everybody. Either:

- **end TLS on the balancer** and send `X-Forwarded-For`, and tell both nodes
  the balancer's address (they trust the header only from there):

  ```bash
  # Settings - Firewall and access - Behind a load balancer or WAF, once for every node;
  # or as root on each node:  acme --set web_proxy_from=192.0.2.5/32 --set web_proxy=1
  ```

- or **pass TLS through** with the **PROXY protocol**, and tell both nodes so - acme
  writes it into nginx itself (since 1.0.128; a hand edit of `acme.conf` was the way
  before, and acme's lines now take its place):

  ```bash
  # Settings - Firewall and access - Behind a load balancer or WAF, the header proxy_protocol;
  # or as root on each node:
  acme --set web_proxy_from=192.0.2.5/32 --set web_proxy_header=proxy_protocol --set web_proxy=1
  ```

  Each node's root helper then gives the 443 listen lines of this node's HTTPS server
  (IPv4 and IPv6) and of the VIP address's `proxy_protocol`, with `set_real_ip_from` the
  balancers named and `real_ip_header proxy_protocol` - checked with `nginx -t`, put back
  when nginx refuses it, and taken out again (only acme's own) when switched off. The
  certificate sign-in's own port gets the same ([below](#the-certificate-sign-in-port)).
  Two things to know:
  - From then on nginx takes **only** connections that begin with the PROXY header on
    443 - the balancer's health check must send it too (HAProxy `check-send-proxy`). A
    browser going to a node's own address directly gets nothing. The node's own checks
    keep working: acme adds `listen 127.0.0.1:443` and `[::1]:443` lines without it (the
    VIP address's health check, `install.sh`), and the other node's look at `/healthz`
    while the nodes are apart sends a `PROXY UNKNOWN` header first.
  - **Port 80** (the CAs' HTTP-01 challenges, `/pki/` CRLs, the redirect to HTTPS) is
    left as it is: no `proxy_protocol` there. A balancer that also forwards port 80 does so
    plainly (HTTP mode, or TCP without PROXY); acme's port 80 answers only public things.

Plain TCP passthrough without the PROXY protocol carries no address at all -
do not use it: every client is then the balancer, and who may reach which page is
decided by the balancer's own address ([below](#is-the-administration-published-through-the-balancer)).
**Never** `web_proxy_header=X-Forwarded-For` with TLS passed through: the balancer cannot
write the header into a TLS connection it does not end, so the client writes it himself -
any address of your own networks he likes, believed because the connection comes from
the balancer.

---

## Is the administration published through the balancer?

acme publishes everything on one port, 443: the enrolment pages (`/` and its `?api=`
requests, `/assets/`, `/pki/`), the administration (`/admin/` and its `?api=` requests),
`/healthz` and `/metrics`. What keeps the administration from the internet is
**Settings → Firewall and access → who may reach the administration pages** - nginx's
allow list of `location = /admin/`, judged on every node by the client's address. So it
depends on how the balancer forwards:

| The balancer | What it publishes | Who may reach `/admin/` is judged by |
|---|---|---|
| **TLS ended on it** (HTTP, `X-Forwarded-For`) | what you let through - the guide's blocks publish only `/`, `/index.php`, `/favicon.ico`, `/assets/`, `/pki/` and answer 404 to everything else (`/admin/`, `/healthz`, `/metrics`) | the client's address, once the nodes believe the balancer's header (`web_proxy`) |
| **TLS passed through, PROXY protocol** (`web_proxy_header=proxy_protocol`) | **everything** - it cannot see the paths | the client's address from the PROXY header: your own networks only, and the internet is kept out |
| **TLS passed through, no PROXY protocol** | **everything** | **the balancer's address**: if it is in the administration's list (it usually is - the default list is the private networks, and so is the balancer), **everybody on the internet** reaches the administration |

So acme has otp's problem only where the nodes cannot see the client: with TLS passed
through and no PROXY protocol, or with *who may reach the administration pages* set to
everybody. *Settings → High availability → Load balancer* says which it is, read from
nginx as it is now - in red where the administration is published through the balancer,
with a link to *Firewall and access*.

acme needs no port of its own for the balancer (otp's `web_proxy_port`): its allow lists
are per page in nginx (otp has one list for the whole node), and with the PROXY protocol
written by acme they see the client on every node. A balancer that must not even carry
`/admin/` ends TLS itself and publishes only the paths above.

### The certificate sign-in port

The sign-in with a certificate (a smart card) has a port of its own, `certlogin_port`
(8443, [certificate-sign-in.md](certificate-sign-in.md)). That port never serves the
administration: nginx answers there only the sign-in's own requests
(`?api=cert-login`, `?api=cert-try`, `?api=cert-alive` while the card is watched) and
404 to everything else, and each of them only to who may reach that part's pages
(the administration's or the enrolment pages'). It must be **passed through** (L4) -
the client's certificate has to reach nginx, a balancer that ends TLS swallows it - and
then, without the PROXY protocol, nginx sees the balancer's address for every card:

- every card refused counts against that one address - the sign-in pause of one person
  is everybody's;
- who may reach the port is decided by the balancer's address: everybody, or nobody.

So pass the port through **with the PROXY protocol**, and tell the nodes:

- 443 passed through too: `web_proxy_header=proxy_protocol` gives the port the PROXY
  protocol as well;
- 443 ended on the balancer (`X-Forwarded-For`) and the certificate's port passed through:
  `acme --set certlogin_proxy_protocol=1` (with `web_proxy=1` and the balancers in
  `web_proxy_from`) - only the port's servers in `acme_certlogin.conf` take the PROXY
  protocol.

The guide on the page has the balancer's side for each kind: HAProxy `mode tcp` and
`send-proxy-v2`; nginx `stream { }` with `proxy_protocol on`; an F5 Standard virtual
server **without** a clientssl profile and a PROXY iRule (or no SNAT, the F5 being the
nodes' gateway - the client's address then reaches nginx as it is, and the PROXY
protocol stays off); a NetScaler `TCP` (or `SSL_BRIDGE`) service with a TCP profile
`-proxyProtocol ENABLED`. Apache httpd cannot balance a TCP connection.

---

## HAProxy

### Ending TLS on HAProxy (recommended)

```
frontend acme_https
    bind :443 ssl crt /etc/haproxy/acme.example.cz.pem alpn h2,http/1.1
    bind :80
    mode http
    http-request redirect scheme https unless { ssl_fc } || { path_beg /pki/ }
    option forwardfor
    default_backend acme_nodes

backend acme_nodes
    mode http
    balance roundrobin
    option httpchk
    http-check send meth GET uri /healthz ver HTTP/1.1 hdr Host acme.example.cz
    http-check expect status 200
    default-server inter 3s fall 2 rise 2 check ssl verify none
    server acme1 192.0.2.11:443
    server acme2 192.0.2.12:443
```

(`verify required ca-file ...` instead of `verify none` when the nodes have
certificates from your CA.) `/pki/` stays plain HTTP on port 80, as on the nodes: a CRL
fetcher seldom follows a redirect to HTTPS. The guide on the page publishes the enrolment
pages only; HAProxy, an F5 iRule and a NetScaler policy match the path as it was sent, so its
blocks also answer 404 to a path with `/.` or `%` in it (`/assets/../admin/` is `/admin/` to
nginx). On both nodes: `acme --trusted-proxy 192.0.2.5/32`.

### Passing TLS through (PROXY protocol)

```
frontend acme_https
    bind :443
    mode tcp
    default_backend acme_nodes

backend acme_nodes
    mode tcp
    balance roundrobin
    option httpchk
    http-check send meth GET uri /healthz ver HTTP/1.1 hdr Host acme.example.cz
    http-check expect status 200
    default-server inter 3s fall 2 rise 2 check check-ssl verify none check-send-proxy send-proxy-v2
    server acme1 192.0.2.11:443
    server acme2 192.0.2.12:443
```

and on both nodes `acme --set web_proxy_from=192.0.2.5/32 --set
web_proxy_header=proxy_protocol --set web_proxy=1` (above: acme writes the PROXY-protocol
lines into nginx). The health check must send the PROXY header too (`check-send-proxy`),
or nginx refuses it. Passed through, HAProxy publishes the administration too - see
[Is the administration published through the balancer?](#is-the-administration-published-through-the-balancer).

---

## nginx as the balancer

```nginx
upstream acme_nodes {
    server 192.0.2.11:443 max_fails=2 fail_timeout=10s;
    server 192.0.2.12:443 max_fails=2 fail_timeout=10s;
    keepalive 16;
}
server {
    listen 443 ssl;
    http2 on;
    server_name acme.example.cz;
    ssl_certificate     /etc/nginx/certs/acme.example.cz.pem;
    ssl_certificate_key /etc/nginx/certs/acme.example.cz.key;
    client_max_body_size 4g;              # a database copy put back from the pages
    location / {
        proxy_pass https://acme_nodes;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 900s;
        proxy_next_upstream error timeout http_502 http_503 http_504;
        proxy_ssl_server_name on;
    }
}
```

- **Open-source nginx checks passively only**: a node is skipped after
  `max_fails` failed requests, and a 503 from a node in maintenance is
  retried on the other (`proxy_next_upstream ... http_503`). It does not ask
  `/healthz` by itself.
- **nginx Plus** checks actively:

  ```nginx
  match acme_ok { status 200; body ~ "^ok "; }
  location / { proxy_pass https://acme_nodes; health_check uri=/healthz interval=3 fails=2 passes=2 match=acme_ok; ... }
  ```

On both nodes: `acme --trusted-proxy 192.0.2.5/32`.

---

## Apache httpd (mod_proxy_balancer + mod_proxy_hcheck)

```apache
LoadModule proxy_module          modules/mod_proxy.so
LoadModule proxy_http_module     modules/mod_proxy_http.so
LoadModule proxy_balancer_module modules/mod_proxy_balancer.so
LoadModule lbmethod_byrequests_module modules/mod_lbmethod_byrequests.so
LoadModule proxy_hcheck_module   modules/mod_proxy_hcheck.so
LoadModule watchdog_module       modules/mod_watchdog.so

ProxyHCExpr acme_ok {%{REQUEST_STATUS} == 200 && hc('body') =~ /^ok /}

<VirtualHost *:443>
    ServerName acme.example.cz
    SSLEngine on
    SSLCertificateFile    /etc/pki/tls/certs/acme.example.cz.crt
    SSLCertificateKeyFile /etc/pki/tls/private/acme.example.cz.key
    SSLProxyEngine on
    SSLProxyVerify none
    SSLProxyCheckPeerName off

    <Proxy "balancer://acme">
        BalancerMember https://192.0.2.11 hcmethod=GET hcuri=/healthz hcexpr=acme_ok hcinterval=3 hcpasses=2 hcfails=2
        BalancerMember https://192.0.2.12 hcmethod=GET hcuri=/healthz hcexpr=acme_ok hcinterval=3 hcpasses=2 hcfails=2
        ProxySet lbmethod=byrequests
    </Proxy>
    ProxyPreserveHost On
    ProxyPass        "/" "balancer://acme/" timeout=900
    ProxyPassReverse "/" "balancer://acme/"
    LimitRequestBody 0
</VirtualHost>
```

Apache sends `X-Forwarded-For` by itself. On both nodes:
`acme --trusted-proxy <Apache's address>/32`.

---

## F5 BIG-IP

**Monitor** (Local Traffic → Monitors → HTTPS):

```
ltm monitor https acme_healthz {
    defaults-from https
    interval 3
    timeout 10
    send "GET /healthz HTTP/1.1\r\nHost: acme.example.cz\r\nConnection: close\r\n\r\n"
    recv "^ok "
    recv-disable "maintenance"
}
```

`recv-disable "maintenance"` lets a node in maintenance finish its
connections instead of cutting them.

**Pool and virtual server** for the pages: members 192.0.2.11:443 and
192.0.2.12:443 with `acme_healthz`, load balancing round robin, no
persistence. Either SSL offload (client SSL profile with your certificate,
server SSL profile towards the nodes, HTTP profile with *Insert
X-Forwarded-For* enabled; then `acme --trusted-proxy <self IPs>`), or
performance L4 with the PROXY protocol (iRule) as above.

---

## Citrix ADC / NetScaler

```
add lb monitor acme_healthz HTTP-ECV -send "GET /healthz" -recv "ok " -secure YES -interval 3 -resptimeout 2 -downTime 5
add server acme1 192.0.2.11
add server acme2 192.0.2.12
add serviceGroup acme_https SSL -cip ENABLED X-Forwarded-For
bind serviceGroup acme_https acme1 443
bind serviceGroup acme_https acme2 443
bind serviceGroup acme_https -monitorName acme_healthz
add lb vserver acme_vs SSL 192.0.2.5 443 -lbMethod ROUNDROBIN -persistenceType NONE
bind lb vserver acme_vs acme_https
bind ssl vserver acme_vs -certkeyName acme.example.cz
```

`-cip ENABLED X-Forwarded-For` sends the client's address on. On both nodes:
`acme --trusted-proxy <SNIP>/32`.

---

## After setting one up

```bash
for n in 192.0.2.11 192.0.2.12; do curl -sk https://$n/healthz; done   # ok up / ok up
acme --maintenance on --why "balancer test"        # on acme1: the balancer must take it out
curl -sk https://192.0.2.11/healthz                # 503 maintenance
acme --maintenance off
```

Sign in through the balancer and look at *Settings → Accounts → signed in*:
the address shown must be your own, not the balancer's.


## The client's address behind a balancer or WAF

As otp 1.0.237. *Settings → Firewall and access → Behind a load balancer or WAF*: switched on,
nginx takes the client's own address from the header the balancer sends (`X-Forwarded-For`
unless another is named - `X-Real-IP`, `True-Client-IP`, `CF-Connecting-IP`...) - **only** for
requests that come from the addresses or networks named; anybody else's header is never
believed. Then the sign-in pause, the caps of wrong passwords, who may reach which page, nginx's
limits and every log see the client. It goes into this node's HTTPS server and the VIP
address's alike, on every node, put in by each node's root helper (checked with `nginx -t`, put
back when refused). *Through more than one of them* (on): in a chain - a WAF before a balancer -
the last address that is not one of them is taken. Refused on without the balancers named.

Off (the default) nginx is left as it was - what `acme --trusted-proxy` once wrote stays.
Switched on, the setting takes its place; switched off again, only its own lines go (the 0 is
kept as a row of its own, so that "switched off" is told from "never switched on"). While it is
set on the pages, `acme --trusted-proxy` refuses and says to change it there.

```bash
acme --set web_proxy_from='192.0.2.5/32 10.20.0.0/24' --set web_proxy_header=X-Forwarded-For --set web_proxy=1
```

`web_proxy_header=proxy_protocol` (1.0.128): TLS passed through, the address in the PROXY
protocol - the 443 listen lines get `proxy_protocol` (port 80 never), and the certificate's
port too ([above](#the-certificate-sign-in-port)).


## Signed in by the balancer

A NetScaler or an F5 APM that signs people in against the directory before the certificate
portal can hand who it signed in to acme, so that the portal asks no password again - only
from the balancers named, only with a key of acme's own. *Settings → The enrolment pages →
Signed in by a load balancer or WAF*; the whole of it in docs/portal-sso.md.

## The settings by key

Settings → Firewall and access → Behind a load balancer or WAF - also `acme --set KEY=VALUE`:

| Setting | Default | |
|---------|---------|--|
| Behind a load balancer or WAF (`web_proxy`) | `0` | On: nginx takes the client's address from the balancers named below, on every node. |
| The load balancers and WAFs (`web_proxy_from`) | (none) | Their addresses or networks, as nginx sees them come in. Needed to switch it on; never every address. |
| The header with the client's address (`web_proxy_header`) | `X-Forwarded-For` | A header's name (X-Forwarded-For, X-Real-IP, True-Client-IP...) - or `proxy_protocol` (1.0.128): TLS passed through, the address in the PROXY protocol; the 443 listen lines (this node's and the VIP address's, IPv4 and IPv6) and the certificate's port get `proxy_protocol`, port 80 never. |
| Through more than one of them (`web_proxy_recursive`) | `1` | On: in a chain (a WAF in front of a balancer), the last address in the header that is not one of them is taken. Off: the last one, whoever put it there. |
| The certificate's port: the PROXY protocol (`certlogin_proxy_protocol`) | `0` | On (1.0.128): the certificate sign-in's own port is passed through an L4 balancer that sends the PROXY protocol - its servers take the client's address from it, from the balancers above only. On anyway with the header `proxy_protocol`. Off: the port as until now. |
