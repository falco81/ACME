# Namecheap - setup for acme

acme proves names by DNS-01 in a domain at Namecheap that uses Namecheap's own DNS (BasicDNS / PremiumDNS), through the **Namecheap XML API** (`https://api.namecheap.com/xml.response`): `namecheap.domains.getList`, `namecheap.domains.dns.getHosts` and `namecheap.domains.dns.setHosts`.

**`setHosts` replaces ALL host records of the domain.** Namecheap has no call that adds or removes one record, so acme reads every record, adds or removes its one TXT value, and writes them all back together with the domain's EmailType - one change at a time. A record changed by hand at that very moment can be lost. After the first certificate, look once at a domain with unusual records (CAA, URL redirects) to see they are intact.

## What you need

- A Namecheap account that Namecheap grants API access (it has terms, e.g. account balance or number of domains - see the API Access page).
- The domain on Namecheap **BasicDNS** or **PremiumDNS** (not custom name servers).
- The **public IPv4 address** acme reaches the internet from (behind a proxy or NAT: that address).
- HTTPS (TCP 443) from acme to `api.namecheap.com`.

## Set up Namecheap

1. Sign in at `namecheap.com`.
2. **Profile → Tools → Business & Dev Tools → Namecheap API Access → Manage**.
3. Switch **API Access** on and accept the terms.
4. Copy the **API Key**.
5. Under **Whitelisted IPs → Edit → Add IP**, add acme's public IPv4 address. Namecheap refuses calls from any other address.
6. Find your public address from the acme machine if unsure:

   ```sh
   curl -4 https://ifconfig.me
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| API user | your Namecheap user name |
| API key | the key from step 4 |
| Client IP | the whitelisted public IPv4 address (step 5) |
| User name the calls are for | empty = the API user (advanced) |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 60 (Namecheap takes 60 to 60000; advanced) |
| Endpoint | `api.namecheap.com`; the sandbox only with a sandbox account (advanced) |
| Allow rewriting every record | on - the consent to the read-modify-write above; off, acme refuses to change the domain (advanced) |

## Check it

- In acme press **Test**: it lists the domains of the account; nothing is written.
- After an order: **Domain List → Manage →** the domain → **Advanced DNS**: the `_acme-challenge` TXT record appears and is removed again; the other records are unchanged.

## Common problems

| Problem | Fix |
|---|---|
| Error 1011150 "Invalid request IP" | The address in *Client IP* (or the one acme really calls from) is not whitelisted. |
| "API Key is invalid or API access has not been enabled" | Switch API Access on; check user name and key. |
| Domain refused: not using Namecheap DNS | Set the domain's name servers to *Namecheap BasicDNS*, or use the DNS provider it points at. |
| A record vanished after an order | It was changed by hand at the same moment, or was a type getHosts does not return - add it again. |
