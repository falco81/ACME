# Namecheap SSL (API) - setup for acme

The **Namecheap SSL (API)** source gets SSL certificates bought at Namecheap through its API (`namecheap.ssl.*`): a certificate bought already is **activated** with acme's CSR (`namecheap.ssl.activate`), or an active one **reissued** (free); a new one is bought (`namecheap.ssl.create`) only when *Allow new orders (paid)* is on. The **domain validation (DCV)** CNAME or file Namecheap answers with is put in place by the certificate's own validation, or the CA e-mails an approver; the certificate is read by `getInfo` once active. **The private key never leaves acme.** *Import from a source* lists the account's certificates; revocation is possible only for certificates that were replaced (as Namecheap's API allows). No TXT DCV, no IP addresses.

## What you need

- A Namecheap account with **API access** enabled (Namecheap grants it to accounts that meet its conditions - balance, number of domains, or spending; see Namecheap's API access page).
- The **API user**, **API key**, and acme's public **IPv4 address on the API allow list**.
- Certificates bought already (their *CertificateID*), or balance for new ones.
- HTTPS access **from acme** to `api.namecheap.com` (sandbox: `api.sandbox.namecheap.com`) port 443.
- A validation in acme that can place the DCV proof (DNS for CNAME, HTTP for the file), or a person for e-mail.

## Set up Namecheap

1. **Profile → Tools → Business & Dev Tools → Namecheap API Access → Manage**: switch API access **ON** (accept the terms); copy the **API key**.
2. **Whitelisted IPs → Edit → Add IP**: acme's public IPv4 (the proxy's, if acme goes out through Settings → Proxy). Only IPv4 is accepted.
3. Buy the certificates acme will activate / reissue (**Account → Product List → SSL Certificates**) and note each *CertificateID*, or decide whether acme may buy.
4. For a test, the **sandbox** (`www.sandbox.namecheap.com`) is a separate account with its own API key and allow list.

Check from acme's network:

```sh
curl -s "https://api.namecheap.com/xml.response?ApiUser=$U&ApiKey=$K&UserName=$U&ClientIp=198.51.100.7&Command=namecheap.ssl.getList"
```

## Fill in acme

Sources → **Add** → **Namecheap SSL (API)**.

| acme field | What to put there |
|---|---|
| Namecheap | *Production* or *Sandbox* |
| API user / API key | the account's user name and the key from step 1 |
| User name (advanced) | empty: the API user |
| Client IP | the IPv4 acme calls from - on the allow list |
| Certificate to reuse | a *CertificateID*: activated if new, reissued if active; empty: the one acme had last |
| Allow new orders (paid) | **off** unless acme may buy |
| Type of a new certificate / Years | e.g. `PositiveSSL`, `1 year` - only for new purchases |
| Administrator e-mail | where Namecheap sends the certificate (required) |
| Domain validation (DCV) | *DNS CNAME record*, *HTTP file* (no wildcards), or *E-mail* + *Approver mailbox* |
| Web server type, More fields of the activation (advanced) | e.g. `nginx`; `Name=value` lines an OV/EV activation wants |
| API address, Waits (advanced) | empty; `600` / `300` / `20` |

## Check it

- Sources → the source → **Test** (Try it): signs in and lists the certificates - buys nothing.
- In Namecheap: **Product List → SSL Certificates** shows the state (*Active*, *Pending*).

## Common problems

| Problem | Fix |
|---|---|
| Error `1011150` / *Invalid request IP* | acme's IP is not on the allow list, or *Client IP* differs from the address acme really calls from |
| API key invalid / API access disabled | switch API access on; copy the key again |
| *a purchase would be needed* | set *Certificate to reuse*, or switch *Allow new orders (paid)* on |
| DCV pending | the CNAME / file was not visible yet - raise the wait; e-mail needs approval |
| Wildcard with HTTP DCV refused | use DNS (CNAME) |
| Revocation refused | Namecheap's API revokes only replaced certificates - use Namecheap support |
