# Nutanix cluster - setup for acme

acme replaces the **SSL certificate of a Nutanix cluster** - the certificate of its Prism (Element) web console and API - through the **v4 API of Prism Central** (port 9440, HTTP basic authentication of a Prism Central user). It reads the current certificate's ETag (`GET …/clusters/<extId>/ssl-certificate`), sends the certificate, key and chain with the key's algorithm (`PUT …/ssl-certificate` with `If-Match`), and waits for the task Prism Central starts until it has `SUCCEEDED`. The cluster's web console then restarts with the new certificate.

## What you need

- A Prism Central that serves the **v4** `clustermgmt` and `prism` APIs (v4.0 - v4.3; v4.3 is the default in acme - check your Prism Central's API reference), with the cluster registered to it.
- HTTPS access from acme to Prism Central, port **9440**.
- A Prism Central user allowed to update the clusters' SSL certificate.
- A certificate key Nutanix accepts: **ECDSA P-256 / P-384 / P-521 or RSA 2048 / 4096** (not RSA 3072).

## Set up Prism Central

1. Create a local user for acme: **Admin Center → IAM → Identities → Local Users → Add Local User** (in older Prism Central: **Settings → Local User Management**), e.g. `acme`, with a strong password. A directory (AD/LDAP) user works too, as long as it can sign in with HTTP basic authentication.
2. Give it rights: **Admin Center → IAM → Authorization Policies** - assign a role that may update the cluster's SSL certificate on the cluster(s) concerned. The built-in **Prism Admin** / **Super Admin** can; with a custom role, include the cluster management permission to update the SSL certificate and to view clusters and tasks. Check with acme's **Test** and a first deployment.
3. Note the cluster's **extId** or name - acme's *Clusters of Prism Central → Load the list* fills it in.
4. Issue the certificate in acme with a supported key type (see above) and with the cluster's virtual IP / FQDN among its names.

Check from the acme server:

```sh
curl -s -u acme:'…' https://prism-central.example.local:9440/api/clustermgmt/v4.3/config/clusters | head -40
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | Prism Central's address |
| HTTPS port | 9440 |
| User / Password | the Prism Central user from step 1 (default `admin` - better a dedicated one) |
| Cluster | the cluster's extId or name |
| Clusters of Prism Central | *Load the list* and pick: fills *Cluster* in |
| API version (advanced) | the v4 version your Prism Central serves (`v4.3` default) |
| Check the device's certificate | on; off only while Prism Central has its self-signed certificate |
| CA certificate (advanced) | the CA of Prism Central's certificate, when not public |
| Key algorithm (deployment, advanced) | *as the certificate's key* (default), or force one |
| Wait for the task (s) (advanced) | 600 |
| Check what is served | the cluster's VIP / FQDN, port 9440, one a line |

## Check it

- **Test** in acme signs in to Prism Central and reads the cluster's current certificate (it shows its key algorithm).
- After a deployment, Prism Central's **Tasks** shows the certificate task as succeeded; then:

```sh
openssl s_client -connect cluster.example.local:9440 -servername cluster.example.local </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

- In Prism Element: **Settings → SSL Certificate** shows the new certificate.

## Common problems

| Problem | Fix |
|---|---|
| 401 | wrong user/password, or the user cannot use basic authentication |
| 403 | the user's role may not update the cluster's SSL certificate |
| 404 on the clusters call | Prism Central does not serve that *API version*; choose an older one or upgrade |
| `Prism Central has no cluster named "…"` | use the extId or pick from the list |
| `Nutanix takes ECDSA P-256/P-384/P-521 and RSA 2048/4096 keys …` | reissue the certificate with a supported key |
| `the task … failed …` | see the task in Prism Central; often a chain or name problem |
| `the task … has not finished in … s` | raise *Wait for the task (s)*; the console restart can take minutes |
