# Kemp / Progress LoadMaster - setup for acme

acme deploys certificates to a Kemp / Progress LoadMaster through its **RESTful API** in the JSON form (APIv2, `POST https://<lm>/accessv2`). Each renewal adds the certificate (full chain + key) under a dated name (`addcert`), adds the intermediates once (`addintermediate`), points the virtual services you list at it (`modvs … CertFile=`, keeping the other certificates a virtual service holds and swapping only acme's older one), and deletes older acme certificates (`delcert`). Changes apply at once; there is no separate save. acme stays below the LoadMaster's limit of 30 API calls in 3 seconds.

## What you need

- LoadMaster **7.2.50 or later** (for the JSON API `accessv2`).
- HTTPS access from acme to the LoadMaster's management interface (WUI, port 443 by default).
- The API interface enabled, and either an **API key** or a user with the **Certificate Creation** and **Virtual Services** rights.

## Set up the LoadMaster

1. Sign in to the LoadMaster web interface (WUI) as `bal` or another full administrator.
2. Enable the API: **System Configuration → Remote Access → Enable API Interface** (tick it).
3. Create a user for acme: **System Configuration → System Administration → User Management**, add user `acme` with a strong password and only the permissions **Certificate Creation** and **Virtual Services** (add intermediate-certificate rights too if your version lists them separately).
4. Either use that user's name and password in acme, or create an **API key** for it (**Certificates & Security → API keys**, or the API key section of the user, depending on the version) and copy it.
5. If you restrict the WUI by address (**System Configuration → Remote Access → Allowed WUI networks** or similar), add the acme server.
6. Note each virtual service as `address:port` (e.g. `192.0.2.10:443`) from **Virtual Services → View/Modify Services**; it must have SSL acceleration (**SSL Properties → Enabled**).

Test the API from the acme server:

```sh
curl -s https://lm.example.local/accessv2 -H 'Content-Type: application/json' \
     -d '{"cmd":"listcert","apikey":"…"}'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the LoadMaster's management address |
| HTTPS port | 443 (the WUI port) |
| Sign in with | an API key, or a user and password |
| API key | the key from step 4 |
| User / Password | the user from step 3 (default shown: `bal` - better the dedicated user) |
| Check the device's certificate | on; off only while the LoadMaster still has its self-signed certificate |
| CA certificate (advanced) | the CA of the LoadMaster's own certificate, when not public |
| Virtual services (deployment) | `address:port[:tcp\|udp]` of each virtual service, one a line |
| Add the intermediates (advanced) | on: the chain is added as intermediate certificates |
| Previous versions to keep | older acme certificates kept before deletion |
| Check what is served | `192.0.2.10:443` or `www.example.com:443`, one a line |

## Check it

- **Test** in acme signs in and lists the certificates.
- In the WUI: **Certificates & Security → SSL Certificates** shows the new `acme-…` certificate and the virtual services that use it; **Intermediate Certs** shows the chain.
- From a shell:

```sh
openssl s_client -connect 192.0.2.10:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `the LoadMaster did not answer with JSON (is it 7.2.50 or later, the API on?)` | enable the API interface; upgrade older LoadMasters |
| `the LoadMaster said … - Unauthorized` / permission errors | wrong key/password, or the user lacks Certificate Creation / Virtual Services |
| `"…" is not address:port[:tcp]` | write the virtual service as `192.0.2.10:443` |
| VS not found | the address and port must match a virtual service exactly; SSL must be enabled on it |
| `… lists certificates acme cannot name …` | the virtual service's list could not be read; acme sets its own certificate alone - re-add others by hand |
| `the old … stays (still used?)` | a virtual service still uses it; LoadMaster refuses to delete it |
| Connection drops | too many API calls from several tools at once (limit 30 in 3 s across all API users) |
