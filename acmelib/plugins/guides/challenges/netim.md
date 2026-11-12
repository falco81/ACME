# Netim - setup for acme

acme proves names by DNS-01 in a domain at Netim, through Netim's **REST API 1.0** (`https://rest.netim.com/1.0`) with a **reseller account**. It opens a session (`POST /session/` with basic authentication), lists the domains (`GET /domains/*`), reads the zone (`GET /domain/{domain}/zone/`), adds one TXT record per value (`POST` to the same path) and deletes exactly that record (`DELETE` with subdomain + type + value). A change answers an operation; while it is *Pending*, acme follows `GET /operation/{ID_OPE}` until it is *Done*. The session is closed at the end of each piece of work (`DELETE /session/`).

## What you need

- A **Netim reseller account** (the REST API is for resellers) holding the domain, with Netim's name servers.
- HTTPS (TCP 443) from acme to `rest.netim.com` (the OT&E test system is `oterest.netim.com`, plain HTTP).
- Netim allows **10 sessions at once** by default - acme uses one per piece of work and closes it.

## Set up Netim

1. Sign in to your Netim reseller interface.
2. Open the section **API – DAS – OTE**.
3. Set (or read) the **API password** there - the DAS password. It is **not** the account's sign-in password.
4. Production and OT&E have **different** API passwords; use the production one for real certificates.
5. Note your **reseller ID** (e.g. `NETIM1234`).

**Warning:** the API password gives the API full access to the reseller account (domains, contacts, orders) - Netim has no DNS-only key. Keep it only in acme.

## Fill in acme

| acme field | What to put there |
|---|---|
| Reseller ID | your reseller ID |
| API password | the DAS password from *API – DAS – OTE* |
| Domain | empty (picked from Netim's list, or found), or the domain |
| TTL (s) | 3600 by default (advanced) |
| API | `rest.netim.com (production)`; OT&E only for tests (advanced) |

## Check it

- In acme press **Test**: it opens a session and, with *Domain* set, counts the zone's records; otherwise it lists the domains. The session is closed; nothing is changed.
- After an order: Netim → the domain → **DNS zone**: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `401` when opening the session | Wrong reseller ID or API password, or the OT&E password used against production. |
| Too many sessions | Other tools hold Netim's 10 sessions - close them, or wait until they time out. |
| Operation *Failed* / *Cancelled* | acme shows Netim's message - often the domain is not on Netim's DNS. |
| Domain not listed | The domain is in another reseller account, or not a domain Netim manages for you. |
