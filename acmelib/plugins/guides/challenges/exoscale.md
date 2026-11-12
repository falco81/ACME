# Exoscale - setup for acme

acme proves names by DNS-01 at Exoscale DNS: through the Exoscale API v2 (requests signed EXO2-HMAC-SHA256) it adds a TXT record `_acme-challenge.NAME` to the DNS domain and deletes only its own record afterwards. It signs in with an IAM API key whose role allows just the DNS operations it uses.

## What you need

- The domain in Exoscale DNS (a DNS subscription of the organization) and delegated to Exoscale's name servers.
- Outbound HTTPS from acme to `api-ch-gva-2.exoscale.com` (or the API zone you choose), port 443.
- A correct clock on the acme machine (signatures expire).

## Set up Exoscale

1. Portal (`portal.exoscale.com`) → **IAM → Roles → Add**: e.g. `acme-dns`.
2. In the role's policy, allow only the **DNS** service operations acme calls - deny everything else by default:
   - `list-dns-domains`
   - `list-dns-domain-records`
   - `create-dns-domain-record`
   - `delete-dns-domain-record`
3. **IAM → API keys → Add**: name `acme`, role `acme-dns`. Copy the **key** (`EXO…`) and the **secret** (shown only once).
4. Or with the Exoscale CLI (check `exo iam role create --help` for the policy syntax of your version):

   ```sh
   exo iam api-key create acme acme-dns
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The key, `EXO…` |
| API secret | The secret |
| Domain | e.g. `example.com`; empty = the longest domain of the organization the name is in |
| API zone | (advanced) Default `ch-gva-2`; DNS is the same from each zone |
| TTL (s) | (advanced) Default `60` |

## Check it

- **Test** in acme lists the organization's DNS domains. It changes nothing.
- With the CLI:

  ```sh
  exo dns list
  exo dns show example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403` / forbidden | The role does not allow one of the four DNS operations. |
| `401` / signature errors | Wrong secret, or the acme machine's clock is off. |
| The domain is not listed | It is in another organization, or the API key belongs to another one. |
