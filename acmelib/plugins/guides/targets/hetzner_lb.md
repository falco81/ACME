# Hetzner Cloud Load Balancer - setup for acme

acme uploads the certificate to a Hetzner Cloud project (type `uploaded`, under a dated name, label `managed-by=acme`) through the Hetzner Cloud API (`https://api.hetzner.cloud/v1`), then puts it on the **HTTPS services** of the load balancers you name, in place of the older acme certificate. A service can hold several certificates (chosen by SNI) - by default only acme's older one is replaced and the others stay. Older acme certificates no load balancer uses any more are deleted.

## What you need

- A Hetzner Cloud project with at least one load balancer that has an **HTTPS service** (protocol `https`, TLS terminated on the load balancer).
- A project **API token with Read & Write** (tokens belong to one project).
- HTTPS access from acme to `api.hetzner.cloud` port 443 (directly or through acme's proxy).

## Set up Hetzner Cloud

1. In the Hetzner Console open the project, then **Security → API tokens → Generate API token**:
   - **Description**: `acme`
   - **Permissions**: **Read & Write** (uploading and deleting certificates and changing services need write).
2. Copy the token - it is shown only once. **Anyone with this token can change everything in the project**; use a project that holds only what needs it, if you can.
3. Make sure each load balancer has an HTTPS service (**Load Balancers → (LB) → Services**, protocol HTTPS, listen port e.g. 443). When creating one by hand you must pick some certificate; acme replaces it on its first run.

With the `hcloud` CLI you can check the same:

```sh
export HCLOUD_TOKEN=…
hcloud load-balancer list
hcloud load-balancer describe lb-www
hcloud certificate list
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | the project token (Read & Write) |
| Through the proxy (advanced) | on when acme reaches the internet only through Settings → Proxy |
| Timeout (s) (advanced) | 30 is fine |
| Load balancers (deployment) | the name or ID of each load balancer, one a line (the action **List the load balancers** shows them) |
| Listen ports (deployment) | the HTTPS services by their listen port, e.g. `443`, one a line; empty: every HTTPS service |
| Replace every certificate of the service | off: only acme's older one is replaced; on: the service holds only this certificate |
| Previous versions to keep | older acme certificates kept before deletion |
| Check what is served | `www.example.com:443` (pointing to the load balancer), one a line |

## Check it

- **Test** in acme signs in and counts the project's load balancers.
- The action **List the load balancers** shows each load balancer, its HTTPS services and their certificates, without changing anything.
- After a deployment: `hcloud load-balancer describe lb-www` shows the new `acme-…` certificate on the service, and

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| 401 `unauthorized` | wrong token, or a token of another project |
| 403 `forbidden` | the token is Read only - create one with Read & Write |
| `there is no load balancer "…" in this project` | check the name/ID with *List the load balancers*; the token's project must be the load balancer's |
| `the load balancer … has no HTTPS service` | add an HTTPS service, or fix *Listen ports* |
| `… has not finished in 120 s` / `… failed` | the load balancer action is slow or refused; check **Load Balancers → (LB) → Activity** in the console |
| `the older … stays: a load balancer still uses it` | another load balancer/service still uses it; list it as well or remove it there |
