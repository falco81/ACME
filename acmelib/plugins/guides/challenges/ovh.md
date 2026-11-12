# OVHcloud - setup for acme

acme proves names by DNS-01 in a zone at OVHcloud, through the OVHcloud API (`https://eu.api.ovh.com/1.0`, or the Canada / US endpoint). Every call is signed with the application key, application secret and consumer key. acme lists the zones (`GET /domain/zone`), adds a TXT record (`POST /domain/zone/{zone}/record`), finds and deletes only its own record, and refreshes the zone after each change (`POST /domain/zone/{zone}/refresh`). Other values at the name stay.

## What you need

- The zone at OVHcloud (OVH's DNS servers `dnsXX.ovh.net` / `nsXX.ovh.net`).
- HTTPS (TCP 443) from acme to the endpoint of your OVHcloud account: `eu.api.ovh.com`, `ca.api.ovh.com` or `api.us.ovhcloud.com`.

## Set up OVHcloud

1. Open the token page of your endpoint, e.g. `https://eu.api.ovh.com/createToken/` (Canada: `https://ca.api.ovh.com/createToken/`), and sign in with the OVH account that owns the zone.
2. Fill in *Application name* `acme`, a description, and *Validity* **Unlimited** (otherwise the consumer key expires and acme stops working).
3. Rights - add exactly these lines:

   ```text
   GET     /domain/zone/*
   POST    /domain/zone/*
   DELETE  /domain/zone/*
   GET     /domain/zone
   ```

   To limit acme to one zone use `/domain/zone/example.com/*` instead of `/domain/zone/*` (then set *Zone* in acme too).
4. Optionally restrict the token to acme's public IP address (*Restricted IPs*).
5. **Create keys** and copy the **Application key**, **Application secret** and **Consumer key**.

## Fill in acme

| acme field | What to put there |
|---|---|
| Endpoint | `OVH Europe`, `OVH Canada` or `OVH US` - where the account is |
| Application key | the application key |
| Application secret | the application secret |
| Consumer key | the consumer key |
| Zone | empty (the longest zone the name is in), or the zone |
| TTL (s) | 60 (0 = the zone's, otherwise at least 60; advanced) |

## Check it

- In acme press **Test**: it lists the zones the keys see; nothing is changed.
- After an order: OVHcloud Control Panel → **Web Cloud → Domain names →** the domain → **DNS zone**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| "This call has not been granted" | The consumer key lacks the method/path - create a new token with the rights above. |
| "Invalid signature" | Application secret or consumer key wrong, or acme's clock is far off. |
| "This credential is not valid" | The consumer key expired (validity not *Unlimited*) or was revoked. |
| Zones of another account | The token was created with another OVH account - sign in with the zone's owner. |
| Empty zone list with a one-zone token | Expected when `GET /domain/zone` is not granted - set *Zone*. |
