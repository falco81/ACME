# Cisco Secure Firewall Management Center (FMC) - setup for acme

acme signs in to the **FMC REST API** (`POST /api/fmc_platform/v1/auth/generatetoken`,
HTTP basic) and imports the certificate and key as a **new Internal Certificate object**
of a dated name (changing one in place is not reliable). In each **decryption policy** you
name, every rule (*Decrypt - Known Key*) that refers to an older acme object of this
certificate is switched to the new object. When rules changed and *Deploy to the devices*
is on, acme sends a deployment request for the devices with changes. Older acme objects no
decryption rule names are deleted.

For FMC 7.4 and later (the Internal Certificate body follows Cisco's Terraform provider),
on-premises or virtual. RA VPN identity certificates (certificate enrolments) are not
handled.

## What you need

- The FMC's management address, **HTTPS 443** reachable from acme.
- The REST API enabled (default).
- A **dedicated account for the API only**: if the same account signs in to the web
  interface, the API session signs it out (and the other way round).
- The decryption policies whose Known Key rules should use the certificate.

## Set up the FMC

1. Check **System (gear) → Configuration → REST API Preferences → Enable REST API** is on.
2. Create a user role (or use *Administrator*): **System → Users → User Roles → Create User
   Role**, with modify rights on:
   - **Object Manager** (Internal Certificates / PKI objects),
   - **Policies → Access Control → SSL / Decryption Policy** (modify),
   - **Deploy Configuration to Devices** (only if acme deploys).
   Menu names vary between FMC versions - check yours.
3. Create the user: **System → Users → Users → Create User**, e.g. `api-acme`, a strong
   password, the role from step 2, in the domain of the policies. Use it **only for acme**.
4. **The first time**: there is no older acme object yet - after the first deployment,
   open the decryption policy and pick the new `acme-...` object in the Known Key rules
   once. Later renewals switch them by themselves.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | The FMC, e.g. `fmc.example.local` / `443` |
| User | The API-only account (default `api-acme`) |
| Password | Its password |
| Domain UUID (advanced) | Empty: the domain the sign-in answers with (`DOMAIN_UUID`) |
| Check the device's certificate / CA certificate | Off only while the FMC has its self-signed certificate |
| Decryption policy (deploy) | Picked from the list (*Load the list*) |
| More decryption policies (deploy) | One a line: names or IDs |
| Deploy to the devices (deploy) | On: a deployment request after the change |
| Only these devices (deploy) | One a line: device names; empty: every device with changes to deploy |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | The server behind the firewall, e.g. `www.example.com:443` |

The action **List the internal certificates** lists the Internal Certificate objects and
the decryption policies - read-only.

## Check it

- **Try**: `signed in to the FMC ... (domain ...); N internal certificates`.
- On the FMC: **Objects → Object Management → PKI → Internal Certs** shows `acme-...`;
  **Deploy → Deployment History** shows the deployment.

## Common problems

| Problem | Fix |
|---|---|
| 401 on generatetoken | Wrong user/password, or the REST API is disabled |
| Web session (or acme) suddenly signed out | The same account is used in the browser - give acme its own |
| 403 on objects or rules | The role lacks Object Manager or decryption policy modify rights |
| Rules not switched | No rule refers to an older acme object yet - pick the new object in the rules once |
| Deployment not started | *Deploy to the devices* off, or no rights to deploy |
| Older object not deleted | A decryption rule still names it |
