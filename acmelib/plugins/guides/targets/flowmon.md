# Flowmon - setup for acme

acme puts a certificate and its key into Progress Flowmon through the Flowmon REST API (written against Flowmon OS 13.1). It can put it in one or both of two places:

- a **certificate pair** of a **reusable TLS setting** (Configuration center → Reusable settings → TLS: what the probes decrypt the monitored servers' TLS with) - the pair is replaced when it is there, added when not; the setting itself is made (with the issuing CA as its CA file) when there is none of that name;
- the collector's **listening ports over TLS** (the ports that take flows over TLS) - each gets the certificate, its key and the issuing CA.

**Note:** the API has no call for the certificate of Flowmon's own web interface - that one is set by hand in the Configuration center (or over SSH with acme's `ssh` target).

## What you need

- Flowmon OS 13.1 or a later version with the same REST API.
- HTTPS access from acme to the Flowmon appliance's management interface, port 443.
- A Flowmon user that may sign in to the REST API and change the Configuration center (reusable settings and listening ports).
- For a new reusable TLS setting: the certificate must come with its chain (acme uses the issuing CA as the setting's CA file).

## Set up Flowmon

1. Sign in to the Flowmon web interface as an administrator.
2. Create a dedicated user for acme (e.g. `acme`) in the user management of Configuration center, with a role allowed to change the Configuration center settings (reusable settings, collector listening ports). Check in your version which role gives that - acme does nothing else, but the API needs write access to these objects.
3. If you want the certificate in a reusable TLS setting, decide its name (**Configuration center → Reusable settings → TLS**). An existing setting is used as it is; a missing one is created by acme.
4. If you want listening ports over TLS, note the exact **names** of the collector's listening ports (e.g. `IPFIX-TLS`) - acme looks them up by name and does not create them.
5. Check that the API sign-in works from the acme server:

```sh
curl -s -X POST https://flowmon.example.local/resources/oauth/token \
     -d grant_type=password -d client_id=invea-tech \
     --data-urlencode username=acme --data-urlencode password='…'
```

The answer must contain an `access_token`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | name or IP address of the Flowmon appliance |
| HTTPS port | 443 |
| User | the Flowmon user (default `admin`; better a dedicated one) |
| Password | its password |
| OAuth client (advanced) | `invea-tech`, unless Flowmon says another `client_id` |
| Form of the uploads (advanced) | keep `entity[name], entity[tlsCaFile]`; change only when Flowmon refuses an upload |
| Check the device's certificate | on; off only while Flowmon still has its self-signed certificate |
| CA certificate (advanced) | the CA of Flowmon's own certificate, when not a public one |
| Reusable TLS setting (deployment) | its name, e.g. `Web servers`; empty: none |
| Certificate pair (deployment) | the pair's name in that setting; empty: the certificate's name |
| Listening ports over TLS (deployment) | the collector's listening port names, one a line; empty: none |
| Check what is served | `host:port` to check by a TLS handshake after deploying, one a line |

At least one of *Reusable TLS setting* and *Listening ports over TLS* must be filled in.

## Check it

- In acme, press **Test**: it signs in, reads the version and counts the reusable TLS settings and listening ports over TLS (`signed in to Flowmon 13.x at …`).
- After a deployment, in Flowmon open **Configuration center → Reusable settings → TLS → (your setting)** and check the pair's validity dates, and the listening ports in the collector settings.
- From a shell, with the token from the sign-in above:

```sh
curl -s -H "Authorization: bearer $TOKEN" https://flowmon.example.local/rest/fcc/reusable-settings-tls
```

## Common problems

| Problem | Fix |
|---|---|
| `Flowmon did not sign in …` | wrong user or password, the user may not use the API, or another *OAuth client* is needed |
| `say where the certificate goes …` | fill in a reusable TLS setting or listening ports in the deployment |
| `the TLS setting … is not there … no chain` | the setting is created with the CA from the chain; create it by hand or make sure the certificate has its chain |
| `there is no listening port …` | the port names must match exactly the names in the collector settings |
| An upload refused (400/403) | 403 can mean an invalid certificate or key; otherwise try another *Form of the uploads* |
| TLS error to the appliance | Flowmon still has a self-signed certificate: give its CA in *CA certificate*, or temporarily turn off *Check the device's certificate* |
