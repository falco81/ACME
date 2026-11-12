# Web servers over SSH (HTTP-01) - setup for acme

acme proves names by HTTP-01 on **your web servers**: it signs in over SSH to **every** web server the name points at (DNS round-robin or behind a load balancer), writes the token file into `/var/www/acme-challenge/.well-known/acme-challenge/`, checks it over HTTP, lets the CA fetch it, and removes it from every host. All hosts must succeed (the CA may ask any of them). acme itself is never reachable from the internet. For nginx (which acme can set up itself), Apache or any server that serves that folder. **Not for wildcards** (they need DNS-01).

## What you need

- SSH access from acme to each web server (port 22, or `host:port`).
- The name pointing at the web servers (or a load balancer / NAT in front of them), answering on **TCP port 80** to the internet.
- A web server block on port 80 that serves `/.well-known/acme-challenge/` from the token folder.

## Set up the web servers

1. On **each** web server, an account that can write only the token folder:

   ```sh
   useradd -r -m -s /bin/sh acme
   install -d -o acme -g acme -m 0755 /var/www/acme-challenge/.well-known/acme-challenge
   ```

2. Put acme's public key (shown under *The SSH key*) into `~acme/.ssh/authorized_keys`, best restricted:

   ```text
   restrict,from="203.0.113.10" ssh-ed25519 AAAA... acme
   ```

3. Pin each host key in acme (*Host keys*):

   ```sh
   ssh-keyscan -t ed25519 web1.example.com
   ```

4. **nginx**: let acme do it - the action **Prepare the hosts** (the button on the validation's row) finds nginx, writes `/etc/nginx/conf.d/acme-challenge.conf` (or an include line into your existing port-80 blocks), runs `nginx -t` and reloads; it needs root or passwordless sudo for `sh`. Or by hand, a port-80 block:

   ```text
   server {
       listen 80 default_server;
       listen [::]:80 default_server;
       server_name _;
       location ^~ /.well-known/acme-challenge/ {
           root /var/www/acme-challenge;
           default_type text/plain;
           try_files $uri =404;
       }
       location / { return 301 https://$host$request_uri; }
   }
   ```

5. **Apache**: `Alias /.well-known/acme-challenge/ /var/www/acme-challenge/.well-known/acme-challenge/` with `Require all granted`, before any redirect.
6. If the account writes through sudo instead (*Write through sudo*), a sudoers line for exactly that:

   ```text
   acme ALL=(root) NOPASSWD: /usr/bin/mkdir -p /var/www/acme-challenge/.well-known/acme-challenge, \
        /usr/bin/install -m 644 /tmp/.acme-* /var/www/acme-challenge/.well-known/acme-challenge/*, \
        /usr/bin/rm -f /var/www/acme-challenge/.well-known/acme-challenge/*
   ```

7. Open TCP 80 in the host firewall (`firewall-cmd --add-service=http --permanent`, `ufw allow 80/tcp`) - or turn on *Open port 80 in their firewall*. Behind a load balancer, pass `/.well-known/acme-challenge/` on port 80 to every pool member.

## Fill in acme

| acme field | What to put there |
|---|---|
| Web servers | Every machine that answers `http://NAME/`, one per line (`host` or `host:port`) |
| User, Signs in with, The SSH key, Password | The SSH account (default `acme`) and its key or password |
| Host keys, Trust the first key seen | Pinned `known_hosts` lines, or trust the first key seen |
| Folder of the tokens | Default `/var/www/acme-challenge/.well-known/acme-challenge` |
| Write through sudo | On if the account writes via `sudo -n install` |
| Check before the CA is asked | Each machine by its address (default), at other addresses (LB / NAT), by the name, or none |
| Check at, Name for Test | For checks at a load balancer / public IP, and the Host name Test sends |
| Public addresses (NAT, load balancer) | Addresses the names point at in front of the web servers |
| Names acme's own block answers for, How "Prepare" sets nginx up, Set nginx up by itself, Open port 80 in their firewall | How the *Prepare the hosts* action configures nginx |
| File mode, Command after writing, HTTP port for the check, nginx file "Prepare" writes | (advanced) |

## Check it

- **Test** writes a probe file on each host, reads it back over SSH, fetches it over HTTP from that host (with *Host: NAME*), and removes it.
- By hand:

  ```sh
  ssh acme@web1.example.com 'ls -ld /var/www/acme-challenge/.well-known/acme-challenge'
  curl -i -H 'Host: www.example.com' http://192.0.2.21/.well-known/acme-challenge/test
  ```

## Common problems

| Problem | Fix |
|---|---|
| Host key refused | Pin the host key (*Host keys*) or turn on *Trust the first key seen*. |
| `Permission denied` writing | The account cannot write the folder - fix ownership, or use *Write through sudo*. |
| `port 80 … does not answer` / `No route to host` | The host firewall closes port 80 - open it (or *Open port 80 in their firewall*). |
| `written but not served over HTTP` | nginx does not serve that folder - run *Prepare the hosts* or add the block. |
| One host fails, all fail | Every web server must succeed - fix or remove the failing host. |
