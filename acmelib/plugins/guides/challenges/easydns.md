# easyDNS - setup for acme

acme proves names by DNS-01 at easyDNS: through the easyDNS REST API (`rest.easydns.net`) it adds a TXT record `_acme-challenge.NAME` (`PUT /zones/records/add/{domain}/TXT`) and deletes only the records holding its value afterwards. The API cannot list domains without a user name, so the domain is the one you set, or found by its SOA.

## What you need

- A domain with DNS at easyDNS, on a plan with REST API access.
- An API token and API key from the easyDNS control panel.
- Outbound HTTPS from acme to `rest.easydns.net` (port 443) - or `sandbox.rest.easydns.net` for the sandbox.
- TTLs between **300 and 86400** - easyDNS takes nothing shorter.

## Set up easyDNS

1. Sign in to the easyDNS control panel.
2. Find the REST API credentials page (**API** / *REST API* in the account settings; easyDNS may need to enable API access for the account - ask their support if the page is missing).
3. Create or show the **API token** and **API key** and copy both.
4. If the panel lets you restrict API access by IP, allow acme's public address.

## Fill in acme

| acme field | What to put there |
|---|---|
| API token | The API token |
| API key | The API key |
| Domain | e.g. `example.com`; empty = found by its SOA |
| User name | (advanced) Your easyDNS user name - then Test lists its domains |
| API | (advanced) `easyDNS (rest.easydns.net)` or the sandbox |
| TTL (s) | (advanced) Default `300`; 300 to 86400 |

## Check it

- **Test** in acme reads the records of the set *Domain*, or with *User name* lists the user's domains. With neither set it asks you to set one. It changes nothing.
- With curl:

  ```sh
  curl -s -u "$TOKEN:$KEY" 'https://rest.easydns.net/zones/records/all/example.com?format=json'
  ```

## Common problems

| Problem | Fix |
|---|---|
| `easyDNS: set the domain (or the user name) for Test …` | Fill in *Domain* or *User name*. |
| `401` / `403` | Wrong token/key, sandbox credentials against production, or API access not enabled for the account. |
| TTL refused | Keep *TTL (s)* between 300 and 86400. |
| The domain is not found by its SOA | Set *Domain* explicitly. |
