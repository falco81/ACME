# GlobalSign Atlas (HVCA) - setup for acme

The **GlobalSign Atlas (HVCA)** source gets publicly trusted certificates from GlobalSign Atlas through its HVCA (High Volume CA) API. Every call goes over TLS with the account's **mTLS client certificate**; acme logs in with the **API key and secret** (`POST /login`), sends `POST /certificates` with the subject, the SANs and its CSR, then reads `GET /certificates/<serial>` until it is issued and `GET /trustchain` for the chain. **The private key never leaves acme.** Revocation is `PATCH /certificates/<serial>`; *Import from a source* reads `/stats/issued` 30 days at a time. The names must be **verified domains** of the account - Atlas refuses others. A dual (RSA + ECDSA) certificate is a second, paid order, only when allowed.

## What you need

- A GlobalSign Atlas account with an HVCA API (a validation policy for TLS server certificates).
- The account's API URL (e.g. `https://emea.api.hvca.globalsign.com:8443/v2`), **API key**, **API secret** and **mTLS certificate with its key**.
- The domains of the names verified in Atlas.
- HTTPS access **from acme** to the API host on port `8443`, directly or through Settings → Proxy.

## Set up Atlas

1. In the Atlas portal, **API credentials** → create credentials for acme: an API key and secret, and generate the **mTLS certificate** (with its key, or from your CSR). Download the certificate and keep the key - both go into acme. Note the API URL shown for the account.
2. **Domains** → add and **verify** each domain acme will issue for (by DNS TXT, HTTP or e-mail as Atlas offers). Wildcards and subdomains are covered by a verified domain per Atlas's rules.
3. Look at the account's **validation policy** (what subject fields are required or allowed, e.g. `organization`, `country`, the maximum validity) - acme's *More of the subject* must give what it requires.
4. Restrict the API credentials to acme's source IP where Atlas offers it.

Check the mTLS connection and credentials:

```sh
curl --cert atlas-mtls.pem --key atlas-mtls.key -H 'Content-Type: application/json' \
  -d '{"api_key":"<key>","api_secret":"<secret>"}' https://emea.api.hvca.globalsign.com:8443/v2/login
```

## Fill in acme

Sources → **Add** → **GlobalSign Atlas (HVCA)**.

| acme field | What to put there |
|---|---|
| API address | as GlobalSign gave it, with `/v2` (default `https://emea.api.hvca.globalsign.com:8443/v2`) |
| API key / API secret | from step 1 |
| mTLS certificate / mTLS certificate's key | the client certificate of the account and its key (PEM) |
| Validity (days) | `0`: the longest the policy allows; a certificate's own days win |
| More of the subject (advanced) | `key=value` lines the policy wants, e.g. `organization=Example s.r.o.`, `country=CZ` |
| Wait for the certificate (s) (advanced) | `60` |
| CA certificate of the API's TLS / Check the API's TLS certificate (advanced) | normally empty / on |
| Allow a second (paid) order for a dual certificate (advanced) | off unless you want ECDSA + RSA twins, each paid |

## Check it

- Sources → the source → **Test** (Try it): logs in and reads the validation policy - orders nothing.
- In the Atlas portal the certificate appears under the account's issued certificates.

## Common problems

| Problem | Fix |
|---|---|
| TLS handshake error before login | the mTLS certificate or key is wrong, expired, or not the account's |
| `401` on `/login` | wrong API key / secret |
| A name refused | the domain is not verified in Atlas (Domains) |
| Subject field refused or missing | adjust *More of the subject* to the validation policy |
| Validity refused | longer than the policy allows - use `0` |
| Certificate not ready | Atlas still makes it (202/404); acme asks again; raise the wait |
