# Active24 - setup for acme

acme proves names by DNS-01 at Active24: it adds a TXT record `_acme-challenge.NAME` to the domain's DNS through the Active24 **REST API v2** (`rest.active24.cz`, the Czech and Slovak Active24 on the Websupport platform) and deletes only its own record afterwards. The old Active24 API (`api.active24.com`, a token) is still selectable, but Active24 says it no longer works since the move to the new platform.

## What you need

- A domain whose DNS is hosted at Active24 (the domain's DNS service in the administration).
- Access to the Active24 administration to generate an API key.
- Outbound HTTPS from acme to `rest.active24.cz` (port 443).

## Set up Active24

1. Sign in to the Active24 administration.
2. Go to **(your name) → Security and login → API access → Generate new access**.
3. Copy the **identifier** (the API key) and the **secret**. The secret is shown only once - store it safely.
4. If the administration lets you restrict the access (by IP address or by service), allow acme's public IP address and the domain's DNS service. The key acts as your account, so prefer a dedicated user of the account where that is possible.
5. Optional: note the domain's **service ID** - the number in the address of the domain's page in the administration. acme normally finds it in the list of services; set it when it does not.

## Fill in acme

| acme field | What to put there |
|---|---|
| API | `REST API v2 - rest.active24.cz` (the one that works) |
| API key | The identifier from *API access* |
| API secret | The secret from *API access* |
| API token | Only for the old *Active24 API* (`api.active24.com`) |
| Domain | The domain, e.g. `example.cz`; empty = the longest domain of the account the name is in |
| Service ID | (advanced) The domain's service number; empty = found in the list of services |
| TTL (s) | (advanced) Default `600` |
| API address | (advanced) Empty = `https://rest.active24.cz` |

## Check it

- **Test** in acme asks `/v2/check` (are the key and secret accepted?) and then lists the domains - or, with a *Service ID*, reads that service's TXT records. It never changes a record.
- After a run, check the record at the authoritative name servers:

  ```sh
  dig +short NS example.cz
  dig +short TXT _acme-challenge.example.cz @<one of those name servers>
  ```

## Common problems

| Problem | Fix |
|---|---|
| `Active24 did not take the API key and secret (/v2/check: not verified)` | Wrong key or secret, or the server's clock is off (requests are signed with the time) - check NTP on the acme machine. |
| The domain is not found | Set *Domain* exactly, and if it still fails, set its *Service ID*. |
| `401` with the old API | The `api.active24.com` platform no longer works - switch *API* to REST API v2 with a key and secret. |
| The CA does not see the record | Active24's name servers can be slow; raise *Wait at least (seconds)*. |
