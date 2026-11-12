# Subreg.cz - setup for acme

acme proves names by DNS-01 in a domain whose DNS is at **Subreg.cz** (or **Gransy**, which runs the same system), through Subreg's SOAP API (`https://soap.subreg.cz/cmd.php`). It signs in (`Login`), lists the domains (`Domains_List`), reads the zone (`Get_DNS_Zone`), adds one TXT record per value (`Add_DNS_Record`) and deletes only the records holding ours (`Delete_DNS_Record`). A domain in Subreg's DNS that is not registered there is found by asking `Get_DNS_Zone` name by name.

## What you need

- A domain using Subreg's (or Gransy's) DNS.
- HTTPS (TCP 443) from acme to `soap.subreg.cz` (or Gransy's API address).
- The **public IP address** acme calls from - the API answers only allowed addresses.

## Set up Subreg

1. Sign in to the Subreg administration (`subreg.cz`).
2. Go to **Settings → API** (Czech UI: *Nastavení → API*).
3. Create an API user (or use the account's own API login) and set its API password.
4. Add the **IP address** acme calls from to the allowed addresses.
5. If the administration lets you limit the API user's rights, leave it the DNS functions only.

Find acme's public address if unsure:

```sh
curl -4 https://ifconfig.me
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API login | the API user's login |
| API password | its password |
| Domain | empty (the longest domain of the account the name is in), or the domain, e.g. `example.cz` |
| TTL (s) | 120 (advanced) |
| API address | `https://soap.subreg.cz/cmd.php`; Gransy's or the test system's address for those (advanced) |

## Check it

- In acme press **Test**: it signs in and lists the domains; nothing is changed.
- After an order: Subreg administration → the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.cz @ns.subreg.cz
```

## Common problems

| Problem | Fix |
|---|---|
| Login refused / "Subreg said: …" | Wrong login or password, or acme's IP address is not allowed under Settings → API. |
| Domain not found | The domain uses other name servers, or is in another Subreg account. |
| Gransy account does not sign in | Set *API address* to Gransy's endpoint. |
