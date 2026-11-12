# Forpsi F-DNS - setup for acme

acme proves names by DNS-01 in **Forpsi F-DNS** (INTERNET CZ's paid DNS-as-a-service, DNSaaS): through the F-DNS REST API (`api.forpsi.com/dnsaas/v1`) it adds a TXT record `_acme-challenge.NAME` and deletes only its own record afterwards (by its id).

**Only F-DNS has an API.** Ordinary Forpsi DNS - the free DNS hosting that comes with a domain or web hosting - has none (only the web administration and a CSV import). For such a domain, point `_acme-challenge.NAME` by a CNAME to a zone acme can write (acme's own DNS server, acme-dns, or a provider with an API) and use that validation instead.

## What you need

- The F-DNS (DNSaaS) service active on your Forpsi account, with the domains in it.
- Outbound HTTPS from acme to `api.forpsi.com` (port 443).

## Set up Forpsi F-DNS

1. Sign in at `admin.forpsi.com` with the account that has the F-DNS service.
2. In the F-DNS (DNSaaS) service, generate an **API token** and copy it.
3. Make sure the domains acme should prove are added to F-DNS and that the domains' name servers point to F-DNS.
4. For a domain on ordinary Forpsi DNS: in the Forpsi administration add, once per name, a CNAME:

   ```text
   _acme-challenge.www.example.cz.  CNAME  www.example.cz.acme.example.net.
   ```

   (the target is a zone acme writes - e.g. acme's own DNS server), and choose that validation in acme.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The F-DNS token |
| Zone | Load the list and pick it, or type it; empty = the longest F-DNS domain the name is in (else by its SOA) |
| TTL (s) | (advanced) Default `60`; F-DNS takes 60 to 86400 |

## Check it

- **Test** in acme reads the service (domains used / allowed) and lists the domains - or, with *Zone* set, counts its records. It changes nothing.
- With curl (the header is `token:`, not `Authorization:`):

  ```sh
  curl -s -H "token: $TOKEN" https://api.forpsi.com/dnsaas/v1/domains
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Invalid token` | Wrong token, or the F-DNS service is not active. |
| The domain is not listed | It is on ordinary Forpsi DNS, not F-DNS - use a CNAME to a zone acme can write. |
| `answered something that is not its API` | Proxy or wrong address in between; check outbound HTTPS to `api.forpsi.com`. |
