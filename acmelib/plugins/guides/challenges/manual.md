# DNS by hand - setup for acme

With this validation acme changes nothing in your DNS. At every order - **renewals too** - it shows the exact TXT record to put in (`_acme-challenge.NAME. 60 IN TXT "<value>"`, or a CNAME where one is needed), then waits until every name server of the zone answers it, or until somebody says **It is in DNS**. Afterwards it tells you the record may be taken out again.

It works with any DNS provider, but someone has to act at every order (every 60-90 days per certificate, sooner with short-lived certificates). For renewals nobody watches choose another validation.

## What you need

- Access to edit the DNS zone of every name in the certificate (a provider's web panel, a zone file, ...).
- Someone available while the order runs (acme waits as long as the ACME issuer's waiting time allows).
- acme able to ask the zone's name servers on UDP/TCP 53 (otherwise it uses the resolvers, and says so).

## Set up your DNS

1. Lower nothing in advance - the record is new each time. Check that you can add a **TXT** record at a name starting with `_acme-challenge` in your provider's panel.
2. When acme shows the record (in the certificate's DNS guide and in the job log), add it exactly:

   ```text
   _acme-challenge.www.example.com.  60  IN  TXT  "gfj9Xq...Rg85nM"
   ```

   - Many panels want only the label relative to the zone: `_acme-challenge.www`.
   - Leave values already at that name in place - `example.com` and `*.example.com` need two values at the same name.
3. Wait until acme says every name server has it, or press **It is in DNS** in acme.
4. After the certificate is issued remove the record (acme reminds you when *Say to take it away afterwards* is on).

**Better:** put a CNAME once - `_acme-challenge.www.example.com CNAME` to a zone acme can write to (acme's own DNS server, acme-dns, or a provider with an API such as deSEC) - and switch to that validation; then nothing is done by hand any more.

## Fill in acme

| acme field | What to put there |
|---|---|
| Say to take it away afterwards | on: acme reminds you to delete the record after the order |
| Wait until it is seen by | the zone's own name servers (default); *nothing* = only your **It is in DNS** counts (advanced) |
| Wait at least (seconds) | extra delay for a provider that publishes slowly (advanced) |

## Check it

- **Test** has nothing to try: the record is put in by hand at every order.
- While an order waits, the certificate's DNS guide shows the exact record and whether every name server has it.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.your-provider.example
```

## Common problems

| Problem | Fix |
|---|---|
| The order timed out | The record came too late - give the ACME issuer a longer waiting time, or use a validation with an API. |
| "not on every name server yet" | A secondary name server has not transferred the zone; wait, or check the zone's serial / NOTIFY. |
| The CA sees a wrong value | An old value was replaced instead of adding the new one, or the name was typed with the zone appended twice (`..example.com.example.com`). |
| Renewal failed silently | Nobody put the record in - switch to an automatic validation (see *Better* above). |
