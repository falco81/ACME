# A script of your own - setup for acme

With this validation acme proves names by DNS-01 through **a program on the acme machine** that you write: acme runs it to put the TXT record in (`present`) and to take it away (`cleanup`), then waits until the zone's name servers answer the value. Use it for a DNS provider acme has no module for. The program can be called the acme way, the dehydrated way or the lego `exec` way.

## What you need

- An executable program (shell, Python, …) on **every acme node** that may run orders, at the same absolute path.
- Whatever that program needs to reach your DNS (a CLI, API keys, network access).
- The program must **exit 0** on success; anything else fails the order with its last output.

## Set up the program

1. Put it where only root can change it, e.g. `/etc/acme/hooks/dns.sh`, owned by root, mode `0755`. It runs as the user **acme**.
2. Example for *Called as* = `PROGRAM present|cleanup RECORD VALUE`:

   ```sh
   #!/bin/sh
   # /etc/acme/hooks/dns.sh present|cleanup RECORD VALUE
   set -e
   case "$1" in
     present) my-dns-cli add "$2" TXT "$3" --ttl "$ACME_TTL" ;;
     cleanup) my-dns-cli del "$2" TXT "$3" ;;
     *) exit 0 ;;
   esac
   ```

3. Rules for the program:
   - **Add** the value next to the ones already at the name, and on cleanup **remove only that value** - `example.com` and `*.example.com` use the same name with two values.
   - Return only when the provider has accepted the change; acme then waits for the name servers itself.
   - Finish within *Timeout (s)* (120 s by default).
4. The environment has only `PATH`, `HOME`, `LANG`, what you set in acme, and:

   | Variable | Value |
   |---|---|
   | `ACME_ACTION` | `present` or `cleanup` |
   | `ACME_NAME` | the name proved (`www.example.com`) |
   | `ACME_RECORD` | where the TXT goes (its CNAME followed) |
   | `ACME_CHALLENGE_NAME` | `_acme-challenge.www.example.com` |
   | `ACME_TXT` | the TXT value |
   | `ACME_TOKEN` | the ACME token |
   | `ACME_ZONE` | the zone, when known |
   | `ACME_TTL` | the TTL |

5. Copy the program to every node (`install -o root -g root -m 0755 dns.sh /etc/acme/hooks/`).

## Fill in acme

| acme field | What to put there |
|---|---|
| Program | `/etc/acme/hooks/dns.sh` - an absolute path |
| Called as | acme style, `dehydrated` (`deploy_challenge\|clean_challenge NAME TOKEN VALUE`) or `lego` (`present\|cleanup RECORD. VALUE`) |
| More environment | `KEY=VALUE` lines the program needs (not secret) |
| Secret environment | `KEY=VALUE` lines kept sealed - API keys for the program |
| Timeout (s) | 120 (advanced) |
| TTL (s) | 60, passed as `ACME_TTL` (advanced) |

## Check it

- In acme press **Test**: it only checks that the program is there and executable - **it is not run**. A dry run of the certificate runs it for real.
- By hand, as the acme user:

```sh
sudo -u acme env ACME_TTL=60 /etc/acme/hooks/dns.sh present _acme-challenge.www.example.com testvalue; echo "exit $?"
dig +short TXT _acme-challenge.www.example.com @ns1.example.com
sudo -u acme /etc/acme/hooks/dns.sh cleanup _acme-challenge.www.example.com testvalue
```

## Common problems

| Problem | Fix |
|---|---|
| "is not there or not executable" | Wrong path, missing `chmod +x`, or the file is missing on this node. |
| "ended with 1: …" | The program failed - its last output is shown; full output in the job's debug log. |
| Works by hand as root, fails in acme | It runs as user **acme** with a minimal environment - set the variables it needs. |
| "did not finish within 120 s" | The provider is slow - raise *Timeout (s)* or make the program return sooner. |
