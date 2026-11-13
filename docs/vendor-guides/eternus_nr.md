# Fujitsu ETERNUS NR (NR1000, ONTAP) - setup for acme

ETERNUS NR1000 systems run **NetApp ONTAP** - acme deploys to them with the target **NetApp
ONTAP (REST API)** (`netapp_ontap`): it installs the certificate with its key and intermediates
(`POST /api/security/certificates`, type `server`) and points the cluster's (or an SVM's) web
services at it (`PATCH /api/cluster/web` or `security ssl modify`), then deletes older ones acme
put there. Nothing in this is Fujitsu-specific: Fujitsu's NR manuals refer to the ONTAP
documentation.

**Which versions:** ONTAP 9.10.1 and later (System Manager certificate management; checked
against ONTAP 9.19.1); for ONTAP 9.6 - 9.9 choose the module version *ONTAP 9.6 - 9.9* of the
target. Ask Fujitsu / Fsas which ONTAP release your NR1000 runs (`version` in the CLI).

## What you need

- From acme to the cluster management LIF: **TCP 443**; the web services `rest` and `ontapi`
  enabled (`vserver services web show`), the firewall policy `mgmt` allowing `https`.
- A cluster account for HTTP (REST) with a role limited to the certificate paths:

  ```text
  cluster1::> security login rest-role create -role cert_rest -api /api/security/certificates -access all
  cluster1::> security login rest-role create -role cert_rest -api /api/cluster/web -access all
  cluster1::> security login create -user-or-group-name svc_cert -application http -authentication-method password -role cert_rest
  ```

  (Check `security login rest-role` on your ONTAP release; the built-in `admin` role works too.)
- **All intermediates** - ONTAP refuses a server certificate whose chain is incomplete; acme sends
  them.

## Fill in acme

Create a target **NetApp ONTAP (REST API)**:

| acme field | What to put there |
|---|---|
| Address | The cluster management LIF, e.g. `nr01.example.local` |
| HTTPS port | `443` |
| User / Password | `svc_cert` |
| SVM (deploy) | Empty for the cluster's own certificate; an SVM name for that SVM |
| Check what is served | Empty: the cluster management address |

The rest is described in that target's own setup guide (*Setup guide* in its form).

## Check it

```sh
openssl s_client -connect nr01.example.local:443 -servername nr01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

```text
cluster1::> security certificate show -vserver cluster1 -type server
cluster1::> security ssl show
```
