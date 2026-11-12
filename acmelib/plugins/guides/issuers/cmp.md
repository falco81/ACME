# CMP server - setup for acme

The **CMP (RFC 4210 / 9480)** source asks a CA for certificates by the Certificate Management Protocol (CMPv2, with RFC 9480 updates and the Lightweight CMP Profile, RFC 9483). acme runs `openssl cmp` (OpenSSL 3.0+) for an `ir`, `cr` or `p10cr` request, confirms the certificate (or asks for implicit confirmation), polls a *waiting* answer, sends `rr` to revoke and `genm` for *Try it*. Each message goes to the CA over HTTP(S) as `application/pkixcmp`, through acme's own HTTP client (Settings → Proxy and the TLS settings of the source). Protection is a **shared secret** (password-based MAC: reference + secret) or a **signature** (a client certificate and key). **The private key of the certificate never leaves acme.** Works with EJBCA, Nokia NetGuard, Siemens, Insta Certifier and industrial (IEC 62443) PKIs.

## What you need

- The CA's CMP endpoint reachable **from acme** over HTTP or HTTPS.
- Either a **reference (senderKID) and shared secret** the CA gave, or a **signing certificate and key** the CA trusts for CMP.
- The CA's name (*recipient*, `/C=../O=../CN=..`) where the CA wants it, and its certificate to check signed answers.
- OpenSSL 3.3+ on acme only if you need a *Certificate profile* (certProfile).

## Set up the CA

EJBCA, RA mode with a shared secret (HMAC):

1. **System Configuration → CMP Configuration → Add** an alias, e.g. `acme`. The endpoint becomes `https://ejbca.example.local/ejbca/publicweb/cmp/acme`.
2. *CMP Operational Mode*: **RA mode**. *Request authentication module*: **HMAC**, with the shared secret acme will use (or the end entity's enrollment code).
3. Choose the **End Entity Profile**, **Certificate Profile** and **CA** for TLS servers (DNS names allowed, server authentication, the key types acme uses).
4. RA name generation: how the end entity is named (e.g. from the subject's CN), and whether existing end entities may be reused for renewals (*Allow automatic key update* / *Allow certificate renewal with same keys* as your policy says).
5. Note the CA's subject DN for *CA name (recipient)* and download the CA certificate.

Signature protection instead: issue an RA/client certificate for acme from a CA the alias trusts (*Request authentication module*: **EndEntityCertificate**), and give acme that certificate and its key.

Other CAs: create a CMP client for acme with a reference + secret (or a signing certificate), the profile for TLS server certificates, and note the endpoint URL (Lightweight CMP: `.../.well-known/cmp[/p/<label>]`).

Try the endpoint by hand from a machine with OpenSSL 3:

```sh
openssl cmp -cmd genm -server https://ejbca.example.local/ejbca/publicweb/cmp/acme \
  -ref acme01 -secret pass:'<secret>' -recipient '/CN=Issuing CA/O=Example/C=CZ' -unprotected_errors
```

## Fill in acme

Sources → **Add** → **CMP (RFC 4210 / 9480)**.

| acme field | What to put there |
|---|---|
| CMP server | the endpoint, e.g. `https://ejbca.example.local/ejbca/publicweb/cmp/acme` |
| Request | `cr` (default); `ir` for an entity the CA does not know yet; `p10cr` where the CA wants the CSR itself |
| Protection | *Shared secret (PBM)* or *Signature* |
| Reference (senderKID) / Shared secret | e.g. `acme01` and its secret (EJBCA: the end entity name / enrollment code, or the alias's HMAC secret) |
| Signing certificate / its key | PEM, chain after it - for signature protection |
| CA name (recipient) | `/CN=Issuing CA/O=Example/C=CZ`; empty: `/` or the subject of the CA certificate below |
| CA certificate (answers) | the CA's certificate - needed with signature protection |
| Certificate profile (advanced) | certProfile, where the CA chooses by it (OpenSSL 3.3+) |
| Implicit confirmation (advanced) | on for CAs that keep a transaction only on one open connection |
| Take unprotected error answers (advanced) | on - shows the CA's error words |
| CA certificate of the server's TLS / Check the server's TLS certificate (advanced) | for HTTPS with a private CA |
| Wait for the certificate (s) (advanced) | `120` |

## Check it

- Sources → the source → **Test** (Try it): a `genm` general message - signs in and reads the CA's answer, orders nothing.
- Issue a test certificate; in EJBCA, *RA Web → Search* shows the end entity and its certificate.

## Common problems

| Problem | Fix |
|---|---|
| `wrong protection` / MAC check failed | wrong reference or shared secret, or the alias wants signature protection |
| `unknown recipient` / `bad request` | set *CA name (recipient)* to the CA's exact DN |
| The CA refuses `ir` or `cr` | switch *Request* (`ir` for a new end entity, `cr` for a known one, `p10cr`) |
| Transaction lost after the certificate | the server keeps the transaction on one connection: switch *Implicit confirmation* on |
| `certProfile` refused | needs OpenSSL 3.3+ on acme, or leave *Certificate profile* empty |
| A waiting request is asked again from the start | expected: the transaction lives in openssl; approve faster or raise the wait |
