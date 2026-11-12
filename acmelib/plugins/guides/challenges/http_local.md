# HTTP-01 on this server - setup for acme

With this validation the CA fetches `http://NAME/.well-known/acme-challenge/TOKEN` **from acme itself**: acme's own nginx on port 80 answers the token. The counterpart to set up is the network and DNS in front of acme: the name must point at acme (or at a NAT / port forward / reverse proxy that sends that path to acme), and port 80 must be open. **Not for wildcards** (they need DNS-01).

## What you need

- The name's `A`/`AAAA` records pointing at acme's public address (the VIP or a node) - or at a NAT, port forward or proxy in front of it.
- **TCP port 80** reachable from the internet to acme (the CA validates from several places worldwide - do not restrict by source address).
- acme's nginx serving `/.well-known/acme-challenge/` on port 80 (it does by default).

## Set up the network

1. DNS: point the name at acme:

   ```text
   www.example.com.  300  IN  A  203.0.113.10
   ```

2. Firewall / router: allow (or forward) TCP 80 to acme. On the acme host itself, if a local firewall runs:

   ```sh
   sudo ufw allow 80/tcp          # or
   sudo firewall-cmd --permanent --add-service=http && sudo firewall-cmd --reload
   ```

3. Behind a reverse proxy or load balancer that serves the name elsewhere: send only the challenge path to acme over HTTP, e.g. for nginx:

   ```text
   location /.well-known/acme-challenge/ {
       proxy_pass http://203.0.113.10;
       proxy_set_header Host $host;
   }
   ```

4. If acme cannot reach its own public name (no hairpin NAT), leave *Check before the CA is asked* off.

## Fill in acme

| acme field | What to put there |
|---|---|
| Check before the CA is asked | On: acme fetches `http://NAME/…/TOKEN` itself first. Off where this machine cannot reach its own public name |
| Address tried by Test | (advanced) Where Test fetches a probe from; default `http://127.0.0.1` (acme's own nginx) |
| Addresses in front of acme | (advanced) Public addresses of a NAT, port forward or proxy the names point at, one per line, so the guide accepts them as "pointing at acme" |

## Check it

- **Test** in acme puts a probe token in and fetches it from *Address tried by Test* (acme's nginx on port 80).
- From a machine outside your network:

  ```sh
  dig +short A www.example.com
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

  A `404` from acme's nginx (not a timeout) means the path reaches acme.

## Common problems

| Problem | Fix |
|---|---|
| `this server does not answer a probe token` | acme's nginx is not serving port 80 - check the service. |
| The CA times out | Port 80 is blocked (firewall, ISP) or forwarded to another machine. |
| The CA reaches another server | The name points elsewhere, or a proxy does not send the challenge path to acme. |
| The self-check fails but the CA would succeed | No hairpin NAT - turn off *Check before the CA is asked*. |
