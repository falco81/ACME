# netcup - setup for acme

acme proves names by DNS-01 in a domain at netcup, through the **CCP DNS API** (JSON, `https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON`). It signs in (`login` with customer number, API key and API password), checks the zone (`infoDnsZone`), reads its records (`infoDnsRecords`), adds a TXT record or deletes exactly ours (`updateDnsRecords`), and signs out (`logout`). Other values at the same name stay.

netcup has no call that lists zones: without *Domain* acme asks `infoDnsZone` for the name and each name above it. netcup's name servers usually take **5-15 minutes** to publish a change; the TTL is the zone's, not a record's.

## What you need

- A domain at netcup using netcup's name servers (`root-dns.netcup.net` …).
- HTTPS (TCP 443) from acme to `ccp.netcup.net`.
- Your netcup **customer number**.

## Set up netcup

1. Sign in to the **Customer Control Panel (CCP)** at `www.customercontrolpanel.de`.
2. Go to **Master Data → API** (German UI: *Stammdaten → API*).
3. Accept the API terms if asked.
4. Create an **API key** (**Create API key**) and an **API password** (**Generate API password**). The API password is shown only once.

**Warning:** the netcup API key and password give access to every domain's DNS of the customer account - there is no per-domain restriction. Keep them only in acme.

## Fill in acme

| acme field | What to put there |
|---|---|
| Customer number | your netcup customer number, e.g. `123456` |
| API key | the API key |
| API password | the API password |
| Domain | the domain (recommended: fewer calls and *Test* can check it); empty: found name by name |
| Wait until it is seen by | keep *the zone's own name servers* (advanced) |

## Check it

- In acme press **Test**: it signs in; with *Domain* set it asks `infoDnsZone` and shows the zone's TTL. Then it signs out. Nothing is changed.
- After an order: CCP → **Domains →** the domain → **DNS**: the `_acme-challenge` TXT record appears and is removed again.

```sh
dig +short TXT _acme-challenge.www.example.com @root-dns.netcup.net
```

## Common problems

| Problem | Fix |
|---|---|
| Login refused (status "error") | Customer number, API key or API password wrong (the API password is not the CCP password). |
| "Domain not found" | The domain uses other name servers or belongs to another customer account. |
| statuscode 5029 "no records" | An empty zone - not an error. |
| The order times out | netcup's name servers are slow: give the ACME issuer 15-20 minutes of waiting time. |
