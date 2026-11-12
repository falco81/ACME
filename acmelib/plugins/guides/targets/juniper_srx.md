# Juniper SRX - setup for acme

acme deploys certificates to a Juniper SRX (Junos OS) through the **Junos REST API** (`https://<srx>:3443`, HTTP basic auth, the same XML RPCs as the CLI). Each renewal:

1. writes the certificate (with its chain, or alone) and the key to `/var/tmp/<id>.crt` / `.key` (mode 0600);
2. loads them into the PKI under a **new certificate id** `acme-<label>-<date>-<serial>` (at most 32 characters);
3. writes both files again **empty**, so no key stays in `/var/tmp`;
4. switches the services you choose to the new id in **one locked, committed change**: J-Web / web management, the REST API itself, SSL termination profiles, SSL proxy profiles, IKE policies;
5. removes older acme ids (`clear security pki local-certificate` and key pair) beyond *keep*.

Chassis cluster / multinode HA (a second node's PKI) is not handled.

## What you need

- An SRX with a Junos version that has the REST API (`system services rest`), e.g. Junos 15.1X49 or later; checked against the Junos 23.4 models.
- HTTPS access from acme to the SRX REST API port (3443 in this guide).
- A local Junos user with a login class allowing **configure**, **maintenance** and **security** (PKI) operations.

## Set up the SRX

1. Create a login class and a user for acme (configuration mode):

```text
set system login class acme-certs permissions [ configure maintenance security ]
set system login user acme class acme-certs authentication plain-text-password
```

   You can narrow the class further with `allow-configuration-regexps` to the statements acme sets (`system services web-management https pki-local-certificate`, `system services rest https server-certificate`, `services ssl termination profile`, `services ssl proxy profile`, `security ike policy`) - test it with acme's **Test** and a first deployment.

2. Turn on the REST API over HTTPS, limited to the acme server. HTTPS needs a certificate; on a new box generate a self-signed one first (operational mode):

```text
request security pki generate-key-pair certificate-id rest-self size 2048
request security pki local-certificate generate-self-signed certificate-id rest-self domain-name srx.example.local subject "CN=srx.example.local"
```

   then (configuration mode):

```text
set system services rest https port 3443
set system services rest https server-certificate rest-self
set system services rest control allowed-sources 192.0.2.10
commit
```

   (`192.0.2.10` = the acme server.) Also allow the REST port in the host-inbound traffic of the zone acme comes from, if you restrict it there.

3. Make sure the SSL profiles / IKE policies you want acme to switch exist (acme only changes their certificate).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the SRX's management address |
| HTTPS port | 3443 (the `rest https port`) |
| User / Password | the user from step 1 |
| Check the device's certificate | off while the REST API uses the self-signed `rest-self` (or give its CA); on once it uses acme's certificate |
| CA certificate (advanced) | the CA of the REST API's certificate |
| J-Web / web management (HTTPS) | on: `web-management https pki-local-certificate` gets the new id |
| The REST API itself | on: the REST API acme talks to uses the new certificate too |
| SSL termination profiles | profile names, one a line |
| SSL proxy profiles | profile names, one a line |
| IKE policies | policy names, one a line (the older acme id is deleted from each) |
| The certificate file holds (advanced) | the certificate and its chain (default), or only the certificate |
| Previous versions to keep | older acme ids kept in the PKI |
| Check what is served | `srx.example.local:443` (J-Web) etc., one a line |

## Check it

- **Test** in acme signs in and reads the software version (`get-software-information`).
- On the SRX:

```text
show security pki local-certificate
show configuration system services web-management
show system commit
```

## Common problems

| Problem | Fix |
|---|---|
| 401 on Test | wrong user/password, or the acme IP is not in `rest control allowed-sources` |
| Connection refused / timeout | REST over HTTPS not on, wrong port, or host-inbound traffic blocks it |
| `…: Junos said … permission denied` | the login class lacks `security`, `maintenance` or `configure` (or an allow-regexp) |
| `… (the candidate configuration may hold acme's lines …)` | the commit failed: on the SRX run `rollback 0` in configuration mode, fix the cause (see the message) and deploy again |
| `… is not a Junos name` | a profile/policy name with characters Junos does not accept |
| `nothing is switched to … (no service asked)` | choose at least one service in the deployment |
| Load fails for an ECDSA key | check that your Junos version accepts that key type for the service; use RSA otherwise |
