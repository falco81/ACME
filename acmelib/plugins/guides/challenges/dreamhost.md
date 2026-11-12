# DreamHost - setup for acme

acme proves names by DNS-01 at DreamHost: through the DreamHost API (`api.dreamhost.com`, the `dns-*` commands) it adds a TXT record `_acme-challenge.NAME` (`dns-add_record`) and removes exactly that value afterwards (`dns-remove_record`). Other values at the name stay. DreamHost sets the TTL itself.

## What you need

- A domain whose DNS is hosted at DreamHost.
- Outbound HTTPS from acme to `api.dreamhost.com` (port 443).
- DreamHost's name servers can take several minutes to publish a change - expect slower runs.

## Set up DreamHost

1. Sign in at `panel.dreamhost.com` → **Advanced → API** (`https://panel.dreamhost.com/?tree=home.api`).
2. Generate a new API key with a comment such as `acme`.
3. Under the functions it may use, tick only **All dns functions** (`dns-list_records`, `dns-add_record`, `dns-remove_record`) - nothing else.
4. Copy the key.

## Fill in acme

| acme field | What to put there |
|---|---|
| API key | The key |
| Domain | e.g. `example.com`; empty = the longest domain of the account the name is in |
| API address | (advanced) Default `https://api.dreamhost.com/` |
| Wait at least (seconds) | (advanced) Consider a delay of a few minutes if the CA often misses the record |

## Check it

- **Test** in acme lists the account's DNS zones (`dns-list_records`). It changes nothing.
- With curl:

  ```sh
  curl -s "https://api.dreamhost.com/?key=$KEY&format=json&cmd=dns-list_records" | head
  ```

## Common problems

| Problem | Fix |
|---|---|
| `invalid_api_key` | Wrong key, or the key was deleted. |
| `this_key_cannot_access_this_cmd` | The key lacks the dns functions - generate one with *All dns functions*. |
| The domain is not found | Its DNS is not hosted at DreamHost, or it is in another account. |
| The CA does not see the record | DreamHost publishes slowly: raise *Wait at least (seconds)*. |
