# VMware Live Site Recovery / vSphere Replication appliance - setup for acme

acme replaces the **appliance certificate** of VMware Live Site Recovery (VLSR, formerly Site Recovery Manager) or the vSphere Replication appliance (VRMS) - HTTPS 443 and the management interface 5480 - through the appliance's **Configuration API** on port 5480:

1. `POST <api>/session` (basic, `admin`) → `session_id`, sent back in the header `x-dr-session`;
2. `GET <api>/appliance/certificates/server` - the same certificate there already: nothing done;
3. `POST <api>/appliance/certificates/ca` with `[{"value": PEM}, ...]` - the intermediates and the root among the appliance's CA certificates;
4. `POST <api>/appliance/certificates/server` with `{"pkcs12_format": {"certificate": <base64 of a PKCS#12>, "password": ...}}` - the PKCS#12 holds **exactly one certificate and its key** (the chain went in step 3), a password of 20 characters (at most 31 are allowed).

`<api>` is `https://<appliance>:5480/configure/requests` by default.

**After it - acme says it, you do it:**

- **vSphere Replication**: restart the appliance (its documents ask for it), then *vSphere Replication → Manage → target sites → Reconnect*; replication pauses meanwhile.
- **Live Site Recovery**: *Site Recovery → the site pair → View Details → Site Pair Summary → Reconnect* (the remote vCenter's address and SSO credentials) - the thumbprint changed. Not during a running recovery plan or test.

## Which versions this guide is for

VMware Live Site Recovery **9.0 / 9.1** and vSphere Replication **9.0** (VRMS Configuration API 2.0.0) - the same calls. In VLSR 9.x `POST .../appliance/certificates/server` is marked *Deprecated*: its successor `.../server/actions/update` takes only a certificate for a CSR made on the appliance or a self-signed one, not a key made elsewhere - so acme uses the deprecated one while it is there. SRM / VR 8.8 were not checked.

## Set up the appliance

1. The user is the appliance's **`admin`** (set when the OVF was deployed) - the appliance has no other users or roles for certificates. Keep its password in a vault and change it in acme when you rotate it.
2. Port **5480** reachable from acme.
3. *Try* in acme signs in with the API path - if it answers 404, find the path of your appliance's Configuration API and put it into *API path*.
4. For a vCenter with a custom certificate, add its root to the appliance's CA certificates first (the documents' *How do I set up a trusted environment*) - acme adds the root of its own certificate.

## The certificate

- FQDN of the appliance (its *Local host*) in the **SAN**; IPv4 at most, no IPv6.
- Key 2048 bits or more; SHA-256 or stronger (SHA-1 refused by default).
- **Live Site Recovery: EKU serverAuth AND clientAuth** - a certificate with serverAuth only is refused. Let's Encrypt and most public CAs no longer issue clientAuth: use a CA that does (an internal one).
- Not a root CA certificate.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the appliance's FQDN, `5480` |
| Appliance | VMware Live Site Recovery, or vSphere Replication |
| User / Password | `admin` and its password |
| API path (advanced) | `/configure/requests` |
| Root CA certificate (deploy) | the root, when the chain does not end in it |
| Add the chain to the appliance's CA certificates (deploy) | on |
| Check what is served | empty: acme checks `<address>:443` and `:5480` |

## Check it

*Try* signs in and shows the current certificate's subject and end. After a deployment:

```sh
openssl s_client -connect vlsr01.example.local:443 -servername vlsr01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -ext extendedKeyUsage
openssl s_client -connect vlsr01.example.local:5480 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

In the vSphere Client the site pair must be **Connected**.

## Common problems

| Problem | Fix |
|---|---|
| `404` on signing in - "is the API path right?" | Another base path on this appliance: set *API path*. |
| `401` | The `admin` password. |
| `400` on the change | EKU without clientAuth (VLSR), the SAN without the *Local host*, SHA-1, a key under 2048 bits. |
| "certificate thumbprint mismatch" between sites | Reconnect the site pair. |
| vSphere Replication sites in "Connection issue" | Restart the appliance, then Reconnect. |
