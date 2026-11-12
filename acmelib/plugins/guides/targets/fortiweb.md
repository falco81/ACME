# FortiWeb - setup for acme

acme deploys certificates to Fortinet FortiWeb through its REST API v2.0. Each deployment imports the certificate and key as a **local certificate** under a dated name (`acme-…`), puts the intermediates into an **intermediate CA group** (uploaded by acme as `acme-chain-…`, or a group of yours, or none), points the **server policies** you name at both, and deletes older acme local certificates that no policy uses any more.

FortiWeb has no API tokens of its own: acme signs in with an administrator's user name and password, sent with every request (`Authorization: base64({"username", "password", "vdom"})`).

## What you need

- FortiWeb with REST API v2.0 (FortiWeb 6.x / 7.x).
- HTTPS access from acme to the FortiWeb management interface (port 443 by default), with HTTPS administrative access enabled on that interface.
- An administrator account for acme.
- At least one HTTPS **server policy** that is to use the certificate.

## Set up FortiWeb

1. Create an admin profile for acme: **System → Admin → Admin Profiles → Create New**, e.g. `acme`, with **read-write** on the areas acme changes - the system certificates (local certificates, intermediate CA and its groups) and the server policies - and read-only or none elsewhere. The area names differ between versions; check them in yours.
2. Create the administrator: **System → Admin → Administrators → Create New**:
   - **Administrator**: `acme`, type local user, a strong password;
   - **Trusted Host**: the acme server's address only;
   - **Access Profile**: `acme`;
   - with administrative domains (ADOMs/VDOMs) on, assign the domain the policies are in.
3. Note the names of the server policies (**Policy → Server Policy**) the certificate is for.
4. Decide how the intermediates are handled:
   - *uploaded by acme* (default): acme uploads the CA chain once and makes the group `acme-chain-…`;
   - *a group of mine*: create it in **System → Certificates → Intermediate CA Group** first;
   - *none*: the policy keeps its own intermediate group.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | name or IP of the FortiWeb management interface |
| HTTPS port | 443 (or the admin HTTPS port) |
| User | the administrator from step 2 |
| Password | its password |
| VDOM | the administrative domain; empty on a FortiWeb without administrative domains |
| Check the device's certificate | on; off only while FortiWeb still has its self-signed certificate |
| CA certificate (advanced) | the CA of FortiWeb's own certificate, when not public |
| Server policy (deployment) | the HTTPS server policy (pick from the list or type) |
| More server policies | more policy names, one a line |
| Intermediates | uploaded by acme as a group / a group of mine / none |
| Intermediate CA group | your group's name, when *Intermediates* is "a group of mine" |
| Previous versions to keep | older acme local certificates kept |
| Check what is served | `vip-address:443`, one a line |

## Check it

- **Test** in acme signs in and reads the system status; the action **List the server policies** shows each policy and the certificate it uses, without changing anything.
- In FortiWeb, **System → Certificates → Local** shows the new `acme-…` certificate, and the policy (**Policy → Server Policy**) names it.
- From a shell:

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| 401 or `FortiWeb said error …` on Test | wrong user/password, the trusted host does not include acme, or a wrong VDOM |
| `FortiWeb has no server policy "…"` | the name must match exactly, in the given VDOM |
| `Intermediates "a group of mine" needs the group's name` | fill in *Intermediate CA group* |
| Import refused | the admin profile lacks read-write on certificates, or the key type is not supported by your version |
| Uploading the intermediate fails | create a group yourself and choose *a group of mine* |
| `the older … stays: a server policy still uses it` | another policy still names the old certificate; move it to the new one or list it in *More server policies* |
