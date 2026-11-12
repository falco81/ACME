# VMware NSX load balancer - setup for acme

acme deploys certificates to the NSX (NSX-T Data Center / VMware NSX) load balancer through the **NSX Policy API** (`https://<nsx-manager>/policy/api/v1`, HTTP basic authentication). An NSX certificate cannot be overwritten, so each renewal **imports a new certificate** under a dated id (`PUT /infra/certificates/<id>`: certificate + chain, private key, tags). Then each virtual server you name is read whole and written back with its **client SSL binding** pointing at the new certificate - as the default certificate, as an SNI certificate (the older acme one replaced, others left), or both. Older acme certificates no virtual server refers to are deleted. The Policy API needs no separate publish step.

## What you need

- NSX-T 3.x or VMware NSX 4.x (written against the Policy API 9.1 specification), with the load balancer configured through the Policy API / Policy UI (not the old Manager API).
- HTTPS access from acme to the NSX Manager (or the cluster VIP), port 443.
- An NSX user that may import/delete certificates and change load balancer virtual servers.
- Virtual servers that already have a **client SSL profile binding** (they serve HTTPS).

## Set up NSX

1. Create a user for acme:
   - local user: **System → User Management → Local Users** (NSX 3.1+ / 4.x) - add `acme` with a strong password; or
   - an LDAP / directory user you add in **System → User Management → User Role Assignment**.
2. Give it a role: **System → User Management → User Role Assignment → Add → Role Assignment for …**. Use the narrowest role that can manage **load balancing** and **certificates** - e.g. **LB Admin**, if it can import certificates in your version; otherwise a custom role (NSX 3.2+: **Roles → Add Role**) with full access to *Networking → Load Balancing* and *System → Certificates*. Check with acme's **Test**, the action **List the virtual servers** and a first deployment. Avoid *Enterprise Admin* for acme.
3. Make sure HTTP basic authentication over the API is allowed for this user (it is by default for local and LDAP users).
4. Note the **ids** of the virtual servers (**Networking → Load Balancing → Virtual Servers**; the id is in the object's details, or use the action in acme).

Check from the acme server:

```sh
curl -s -u acme:'…' https://nsx-manager.example.local/policy/api/v1/infra/lb-virtual-servers | head -40
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the NSX Manager or its cluster VIP |
| HTTPS port | 443 |
| User / Password | the user from step 1 (default `admin` - better a dedicated one) |
| Check the device's certificate | on; off only while the Manager has its self-signed certificate |
| CA certificate (advanced) | the CA of the NSX Manager's certificate, when not public |
| Virtual server (deployment) | the id of the LB virtual server (pick from the list or type) |
| More virtual servers | more ids, one a line |
| As | the default certificate of the virtual server / an SNI certificate / both |
| Previous versions to keep | older acme certificates kept in NSX |
| Check what is served | `vip.example.com:443`, one a line |

## Check it

- **Test** in acme signs in; the action **List the virtual servers** shows each virtual server and the certificates of its client SSL binding, without changing anything.
- In NSX: **System → Certificates** shows the new `acme-…` certificate; the virtual server's **SSL Configuration → Client SSL** names it.

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| 401 / 403 | wrong user/password, or the role cannot import certificates or change virtual servers |
| `NSX has no virtual server "…"` | use the virtual server's **id**, not only its display name (see the list action) |
| `the virtual server … has no client SSL binding` | enable Client SSL on the virtual server first |
| 412 / revision error on the virtual server | it was changed at the same time; deploy again |
| Import refused | the key does not match, or the chain is incomplete - see the message |
| `the older … stays: a virtual server still uses it` | another virtual server still uses it; list it as well |
