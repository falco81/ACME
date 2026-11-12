# FortiADC - setup for acme

acme deploys certificates to Fortinet FortiADC through its REST API. Each deployment uploads the certificate and key as a **local certificate** under a dated name (`acme-…`), adds it to a **local certificate group** in place of the older acme member, optionally points **client SSL profiles** at that group and **virtual servers** at the profile, deletes older acme certificates that no group holds any more, and signs out.

The upload call needs **FortiADC 7.4.0 or later**.

## What you need

- FortiADC 7.4.0 or later, with the REST API reachable over HTTPS from acme (management interface, port 443 by default; HTTPS administrative access enabled on that interface).
- An administrator acme signs in as: a user with a password, or a **REST API admin** with an API key.
- A **local certificate group** that your client SSL profile presents (create it once in FortiADC if you have none).
- Optional: an **intermediate CA group** with your CA's intermediate certificate(s) - acme does not upload intermediates, it only names the group.

## Set up FortiADC

1. Create an access profile for acme: **System → Administrator → Access Profile → Create New**, e.g. `acme`, with **read-write** on the parts acme changes - the system certificates (local certificates, certificate groups) and Server Load Balance (client SSL profiles, virtual servers) - and nothing more. The exact permission names differ between versions; check them in yours.
2. Create the administrator:
   - user and password: **System → Administrator → Create New**, user `acme`, the access profile `acme`, trusted hosts limited to the acme server's address;
   - or an API key: **System → Administrator → Create New → REST API Admin**, the access profile `acme`, trusted hosts as above; copy the key.
3. If VDOMs are on, give the administrator the VDOM the certificates live in and note its name.
4. Create the local certificate group if it does not exist: **System → Certificate → Local Certificate Group** (in some versions under **System → Certificate → Local**) - name it e.g. `acme-www`. acme puts its member there.
5. Optional: create an intermediate CA group with your CA's intermediate certificate (**System → Certificate → Intermediate CA Group**).
6. Point your client SSL profile at the group (**Server Load Balance → Application Resources → Client SSL Profile**) - or let acme do it by listing the profile in the deployment.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | name or IP of the FortiADC management interface |
| HTTPS port | 443 (or the admin HTTPS port you set) |
| Sign in with | a user and password, or the key of a REST API admin |
| User / Password | the administrator from step 2 |
| API key | the REST API admin's key |
| VDOM | the VDOM name; empty on a FortiADC without VDOMs |
| Check the device's certificate | on; off only while FortiADC still has its self-signed certificate |
| CA certificate (advanced) | the CA of FortiADC's own certificate, when not public |
| Local certificate group (deployment) | the group from step 4 (button: List the certificate groups) |
| Intermediate CA group (deployment) | the group from step 5; empty: none |
| Client SSL profiles to point at the group | profile names, one a line; empty: profiles stay as they are |
| Virtual servers to point at the profile | virtual server names, one a line: they get the first profile above |
| Previous versions to keep | older acme certificates kept before deletion |
| Check what is served | `vip-address:443`, one a line |

## Check it

- **Test** in acme signs in and reads FortiADC; the action **List the certificate groups** lists the groups and their members without changing anything.
- After a deployment, in FortiADC **System → Certificate → Local** shows the new `acme-…` certificate, and the group holds it as its member.
- From a shell:

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `FortiADC gave no token on signing in` / 401 | wrong user or password, or trusted hosts do not include acme's address |
| `FortiADC said error -N` | the request was refused - often missing read-write rights in the access profile or a wrong VDOM |
| Upload fails on an older FortiADC | the upload API needs 7.4.0 or later - upgrade |
| `no local certificate group is set` | choose the group in the deployment |
| `FortiADC has no client SSL profile "…"` / virtual server | names must match exactly (case too), in the right VDOM |
| `virtual servers are given but no client SSL profile …` | list at least one client SSL profile when you list virtual servers |
| `the older … stays: a group still holds it` | another group still uses the old certificate; remove it there |
| Clients miss the intermediate | set *Intermediate CA group* to a group holding your CA's intermediate |
