# Infoblox NIOS - setup for acme

acme proves names by DNS-01 in an authoritative zone of an Infoblox NIOS grid. It talks to the Grid Master's REST API (WAPI) with HTTP basic authentication: it lists the authoritative zones of a DNS view (`zone_auth`), adds one `record:txt` per value at `_acme-challenge.NAME` (comment `acme DNS-01`) and deletes exactly that record afterwards. Other TXT values at the same name are never touched.

For NIOS grids that speak WAPI `2.10` or later (acme uses nothing newer than that).

## What you need

- A NIOS grid with the zone as an **authoritative zone** in a DNS view, served by grid members that the internet asks.
- HTTPS (TCP 443) from acme to the Grid Master (or its VIP).
- The CA certificate (PEM) that signed the Grid Master's certificate, if it is your organisation's own CA.

## Set up Infoblox

1. Find the WAPI version of the grid: Grid Manager → **Help → About**, or open `https://GRID-MASTER/wapi/v1.0/?_schema` in a browser.
2. Create an admin group for acme: **Administration → Administrators → Groups → Add**.
   - Do **not** make it a superuser group.
   - Under **Allowed Interfaces** tick **API** only (acme needs no GUI access).
3. Give the group permissions: **Administration → Administrators → Permissions → Add** (for the group):
   - **Read/Write** on the zone(s) acme may change, or - tighter - **Read/Write on TXT records** in those zones plus **Read-Only** on the zones themselves (acme has to list `zone_auth` of the view).
   - **Read-Only** on the DNS view, if you want acme to offer the views in its form.
4. Create a user of its own for acme: **Administration → Administrators → Admins → Add**, member of that group, local authentication, a long random password.
5. Export the CA that signed the Grid Master's HTTPS certificate (PEM), if it is not a public CA.

Quick check from any shell that can reach the Grid Master:

```sh
curl --cacert gm-ca.pem -u acme:'PASSWORD' \
  'https://gm.example.local/wapi/v2.10/zone_auth?view=default&_return_fields=fqdn'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Grid Master | `https://gm.example.local` - the Grid Master or its VIP, without `/wapi` |
| WAPI version | what the grid speaks, e.g. `2.10` (advanced) |
| User name | the acme admin user |
| Password | its password |
| DNS view | `default` unless your grid uses other views |
| Zone | empty (the longest authoritative zone of the view the name is in), or the zone |
| TTL (s) | 60 by default (advanced) |
| Check the Grid Master's certificate | leave on |
| CA of the Grid Master's certificate | the CA from step 5 (PEM); empty when the system already trusts it |

## Check it

- In acme press **Test** on the validation: it signs in and lists the zones of the view; it changes no record.
- On the grid, after an order: **Data Management → DNS → Zones →** the zone → the `_acme-challenge` TXT records with comment `acme DNS-01` appear and disappear again.

## Common problems

| Problem | Fix |
|---|---|
| `401 Unauthorized` | Wrong password, or the group lacks the **API** interface. |
| `403` / "permission denied" on POST | The group has only read rights on the zone or its TXT records. |
| Certificate verify failed | Paste the issuing CA under *CA of the Grid Master's certificate* - do **not** switch the check off. |
| "no zone" for a name | The zone is in another DNS view, or is not authoritative (a forward/stub zone) - set *DNS view*. |
| Record exists but the CA cannot see it | The grid member serving the zone has not restarted DNS service: check the grid's "restart services" setting. |
| Unknown WAPI version error | Set *WAPI version* to what the grid reports. |
