# Huawei Cloud DNS - setup for acme

acme proves names by DNS-01 in a **public** zone of Huawei Cloud DNS: through the DNS API v2 of a region (`https://dns.{region}.myhuaweicloud.com`), every request signed with an access key (AK/SK, SDK-HMAC-SHA256), it adds its value to the TXT record set `_acme-challenge.NAME` (or creates the set) and on cleanup writes the set back without it - or deletes it when its value was the last one.

## What you need

- A public zone in Huawei Cloud DNS, with the domain delegated to Huawei Cloud's name servers.
- An IAM user for acme with an access key.
- Outbound HTTPS from acme to `dns.{region}.myhuaweicloud.com` (port 443).
- **The acme machine's clock within 15 minutes** of the real time (signed requests).

## Set up Huawei Cloud

1. Console → **Identity and Access Management (IAM) → Users → Create User**: e.g. `acme-dns`, access type **Programmatic access** (access key) only.
2. Put the user in a group (or attach directly) with a policy for DNS. The simplest is the system policy **DNS FullAccess**; the minimal is a custom policy allowing only:

   ```text
   dns:zone:list
   dns:recordset:list
   dns:recordset:create
   dns:recordset:update
   dns:recordset:delete
   ```

   (check the action names in the IAM console's DNS action list for your region).
3. Download the **access key** (`credentials.csv`: AK and SK) - the SK is shown only once.
4. Note the **region** whose endpoint acme should use, e.g. `ap-southeast-1`, `cn-north-4`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Access key ID (AK) | The AK |
| Secret access key (SK) | The SK |
| Region | e.g. `ap-southeast-1` |
| Zone | Load the list and pick it, or type it; empty = the longest public zone the key sees that the name is in |
| Project ID | (advanced) Only where Huawei Cloud asks for it (several projects in a region, Dedicated Cloud) |
| Security token | (advanced) Only for a temporary AK/SK |
| TTL (s) | (advanced) Default `300` |
| API address | (advanced) Empty = `https://dns.{region}.myhuaweicloud.com` |

## Check it

- **Test** in acme lists the public zones the key sees - or, with *Zone* set, checks that zone. It changes nothing.
- After a run, ask the zone's name servers:

  ```sh
  dig +short NS example.com
  dig +short TXT _acme-challenge.example.com @<one of those name servers>
  ```

## Common problems

| Problem | Fix |
|---|---|
| `APIGW.0301` / signature errors | Wrong SK, or the acme machine's clock is off by more than 15 minutes. |
| `403` / no permission | The user's policy lacks one of the DNS actions. |
| `DNS.0314` (not in a steady state) | The set is still pending; acme waits and tries again. |
| The zone is not listed | It is a private zone, or in another region / project - set *Region* (and *Project ID*). |
