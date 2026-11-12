# dns-persist-01 (a DNS record set once) - setup for acme

With **dns-persist-01** (draft-ietf-acme-dns-persist) a domain is proved by **one TXT record that stays**: `_validation-persist.NAME` names the CA and the ACME account allowed to issue. Nothing changes in DNS at an order and acme needs no DNS credentials at order time. Let's Encrypt announced it in February 2026; Google Trust Services (issuer domain `pki.goog`) offers it since September 2026. While a CA does not offer it yet, the **fallback validation** proves the names, and acme switches by itself once the CA offers it. Only with an ACME source (the `acme` module); not for IP addresses.

## What you need

- An ACME source (Let's Encrypt, its staging, or another CA that offers dns-persist-01). The record names its **account URI** - acme shows it, and makes the account if there is none yet.
- Access to the DNS of each domain to put the TXT record in once - by hand, or through another DNS validation acme already has (Cloudflare, Route 53, Active24, SSH DNS, RFC 2136 …).
- A **fallback validation** (any other DNS-01 or HTTP-01 validation) for as long as the CA does not offer dns-persist-01.

## Set up your DNS

1. In acme, open the validation's page (Certificates → Validation → this validation): it shows the **exact record** for each ACME source, with copy buttons. **Make the record** creates the ACME account at the CA where the source has none yet. On the command line: `acme --validation-show NAME`.
2. Put the record in the domain's DNS, once:

   ```text
   _validation-persist.example.com.  3600  IN  TXT  "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567; policy=wildcard"
   ```

   - `letsencrypt.org` - the CA's issuer domain name.
   - `accounturi=` - the ACME account's URL (required).
   - `policy=wildcard` - also covers `*.example.com` (and, per the draft, names under the domain).
   - `persistUntil=` - optional Unix time after which the CA ignores the record.
3. **Let's Encrypt today looks each name up at that name only**: `www.example.com` needs its own `_validation-persist.www.example.com`. Turn on *A record at each name (Let's Encrypt today)* and acme shows (or writes) one per name.
4. Let's Encrypt production and staging have **different account URLs**: each source needs its own record. Several TXT records may stand at the name; other TXT records there stay.
5. Or let acme write it: choose a DNS validation under *Write the record through*, then **Write the records to DNS** (or leave *Write it by itself when missing* on). acme only ever replaces or removes records it wrote itself.

## Fill in acme

| acme field | What to put there |
|---|---|
| Names with the record | Where the record stands; empty = the certificates' names (or their registered domains) |
| Cover subdomains and wildcards (policy=wildcard) | On (default) for wildcards and names under the domain |
| A record at each name (Let's Encrypt today) | On for Let's Encrypt as it works now |
| Valid until (persistUntil) | Optional date or Unix time |
| Fallback validation | The validation that proves names while the CA does not offer dns-persist-01 |
| Write the record through | Empty = by hand; or a DNS validation acme writes the record through |
| Write it by itself when missing | On (default): a missing record is written at an order |
| Sources the record is for, The CA's issuer domain name, Resolvers | (advanced) empty = every ACME source, `letsencrypt.org`, Settings → DNS |

## Check it

- **Test** (and **Check the records** on the validation's page) looks the record up at each name and the domains above it, and says exactly what is wrong: missing, another CA, unreadable, another account URI, `policy=wildcard` missing, `persistUntil` expired or expiring within 30 days. It also says whether the CA offers dns-persist-01 yet.
- By hand:

  ```sh
  dig +short TXT _validation-persist.example.com
  dig +short TXT _validation-persist.www.example.com
  ```

## Common problems

| Problem | Fix |
|---|---|
| `the CA does not offer dns-persist-01 yet - used FALLBACK` | Expected until the CA launches it; nothing to change. |
| NXDOMAIN for `_validation-persist.www.example.com` | Let's Encrypt wants a record at each name - turn on *A record at each name*. |
| Another account URI | The ACME account changed (or staging vs. production) - update the record (or *Write the records to DNS*). |
| Wildcard refused | Add `policy=wildcard`. |
| `there is no ACME source` | Add an ACME source first - the record names its account. |
