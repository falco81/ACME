# Duck DNS - setup for acme

acme proves names by DNS-01 at Duck DNS (free names under `duckdns.org`): through the Duck DNS update URL it sets the TXT value of one of your Duck DNS names and clears it afterwards. **Duck DNS keeps one TXT value per name**, answered for that name and every name under it - so `myhome.duckdns.org` and `*.myhome.duckdns.org` in one certificate are proved one after the other. Your own domain can be proved through a Duck DNS name by a CNAME.

## What you need

- A Duck DNS account and one or more names in it (e.g. `myhome`).
- Outbound HTTPS from acme to `www.duckdns.org` (port 443).
- For your own domain: access to its DNS to add one CNAME per name.

## Set up Duck DNS

1. Sign in at `duckdns.org` (with one of the offered sign-in providers).
2. Copy the **token** shown at the top of the page. It is the only credential Duck DNS has and it can change every name of the account - keep it secret.
3. Add the names (sub domains) you want to use, if they do not exist yet.
4. To prove a name of **your own** domain, add in its DNS, once:

   ```text
   _acme-challenge.www.example.com.  3600  IN  CNAME  myhome.duckdns.org.
   ```

   One Duck DNS name holds one value at a time, so use a separate Duck DNS name per name proved, or accept that they are proved one after another.

## Fill in acme

| acme field | What to put there |
|---|---|
| Token | The account's token |
| Duck DNS names | The names acme may set the TXT value of, one per line (`myhome` or `myhome.duckdns.org`) |
| Zone | (advanced) Empty = the Duck DNS name the record is under |
| API address | (advanced) Default `https://www.duckdns.org/update` |

## Check it

- **Test** in acme only checks that a name and token are set - **it cannot try the token without changing the TXT value**.
- Try it by hand (this does change the TXT value of the name):

  ```sh
  curl -s "https://www.duckdns.org/update?domains=myhome&token=$TOKEN&txt=test&verbose=true"
  dig +short TXT myhome.duckdns.org
  curl -s "https://www.duckdns.org/update?domains=myhome&token=$TOKEN&txt=test&clear=true"
  ```

## Common problems

| Problem | Fix |
|---|---|
| `KO` | Wrong token, or the name is not in the account. Duck DNS says nothing more. |
| The second name of a certificate waits | Expected: one value per name at a time - acme proves them in turn. |
| Your own name fails | The `_acme-challenge` CNAME is missing or points to a Duck DNS name not listed in *Duck DNS names*. |
