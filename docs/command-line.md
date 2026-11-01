# The command line of the certificate manager

Each of these options runs the same API route the pages use, in this
process, as `command line` (a full administrator), so the checks, the
events and the words are the same. Renewals and deployments run here and
now, and their steps are printed as they come. `--json` answers JSON
instead of tables. `--no-color` turns colour off.

`acme --help` lists every option, including the engine's own.

## Looking

| | |
|---|---|
| `acme --certs [--search TEXT]` | every certificate: state, days left, end, issuer, deployments, names |
| `acme --cert NAME` | one certificate: its details, versions, deployments and last jobs |
| `acme --sources` | where certificates come from (the issuers) |
| `acme --validations` | how names are proved (the challenges) |
| `acme --targets` | where certificates go |
| `acme --cas` | acme's own certificate authorities |
| `acme --jobs [--limit N]` | the jobs, newest first |
| `acme --job ID` | one job and every step. While it runs, it is followed until it ends. The exit code is 0 when the job went well |
| `acme --plugins` | the modules: issuers, challenges, targets, and those that did not load |
| `acme --dns-records` | what acme's own DNS server answers |
| `acme --status` | includes the certificates, which node renews them, and the DNS server |

## Doing

| | |
|---|---|
| `acme --cert-add NAME --names a.example.com,b.example.com --issuer X [--challenge Y] [--key-type ec-256]` | a certificate to keep, renewed by itself. The renewer issues it at its next look, or `--renew NAME` issues it now |
| `acme --renew NAME` | renew it now, due or not |
| `acme --renew all [--force]` | every certificate that is due. With `--force`, every one acme can renew |
| `acme --deploy NAME` | run every enabled deployment of it now (forced: put in place even when unchanged) |
| `acme --import FILE [--name N] [--password]` | a certificate from a file: PEM, DER, PFX/P12, P7B, JKS, or a ZIP of them. `--password` asks for the file's password (or reads `ACME_FILE_PASSWORD`, or one line of stdin) |
| `acme --export NAME --format F --out FILE [--password]` | the certificate into a file (`--out -` writes it to stdout). Formats: `cert-pem`, `cert-der`, `chain-pem`, `fullchain-pem`, `p7b`, `key-pem`, `key-rsa`, `key-der`, `combined-pem`, `pfx`, `p12`, `p12-legacy`, `jks`. PFX, P12 and JKS need `--password`. The file is written with mode 0600 |
| `acme --selfsigned NAME --names a,b [--key-type T] [--days N]` | a self-signed certificate, made now. A `self-signed` source is made the first time it is needed |
| `acme --ca-create NAME --subject "CN=Example Root CA,O=Example" [--key-type ec-384] [--days 3650]` | a new root authority of acme's own |
| `acme --target-test NAME` | try a target: reach it and sign in, without changing anything |

The exit code is 0 when things went well and 1 when a job failed, so these
options can be used from scripts.

## Examples

```
acme --sources
acme --cert-add www --names www.example.com,example.com --issuer letsencrypt --challenge own-dns
acme --renew www
acme --export www --format pfx --out /root/www.pfx --password
acme --import /root/old-portal.pfx --name portal --password
acme --job 42
acme --certs --json | jq '.rows[] | select(.days_left < 14) | .name'
```

The console (`acme --console`) has the same things under **Certificates**, at
the top of its main menu.
