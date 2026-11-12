# GleSYS - setup for acme

acme proves names by DNS-01 at GleSYS (Sweden): through the GleSYS API (`api.glesys.com`, the `domain/*` functions) it adds a TXT record `_acme-challenge.NAME` (`domain/addrecord`) and deletes only its own record afterwards (`domain/deleterecord`). It signs in with the project name and an API key.

## What you need

- The domain in a GleSYS Cloud project, using GleSYS DNS.
- Outbound HTTPS from acme to `api.glesys.com` (port 443).

## Set up GleSYS

1. GleSYS Cloud → the project → **API keys → Create API key**.
2. **Permissions**: under *domain* allow only `list`, `listrecords`, `addrecord` and `deleterecord`. Nothing else.
3. **Allowed hosts**: acme's public address.
4. Copy the key, and note the project's name (`CL12345`) - it is the user name for the API.

## Fill in acme

| acme field | What to put there |
|---|---|
| Project | The project's name, e.g. `CL12345` |
| API key | The API key |
| Domain | e.g. `example.se`; empty = the longest domain of the project the name is in |
| TTL (s) | (advanced) Default `60` (60 at least) |
| API address | (advanced) Default `https://api.glesys.com` |

## Check it

- **Test** in acme lists the project's domains (`domain/list`). It changes nothing.
- With curl:

  ```sh
  curl -s -u "CL12345:$KEY" -X POST https://api.glesys.com/domain/list
  curl -s -u "CL12345:$KEY" -X POST -d domainname=example.se https://api.glesys.com/domain/listrecords
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401` / access denied | Wrong project or key, or acme's address is not in *Allowed hosts*. |
| Permission denied for a function | Add the missing `domain` permission (list, listrecords, addrecord, deleterecord). |
| The domain is not listed | It is in another project, or its DNS is not at GleSYS. |
