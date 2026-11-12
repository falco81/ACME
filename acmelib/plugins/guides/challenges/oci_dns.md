# Oracle Cloud (OCI) DNS - setup for acme

acme proves names by DNS-01 in a **public zone of Oracle Cloud Infrastructure DNS**, through the DNS REST API `20180115` at `https://dns.<region>.oci.oraclecloud.com`. Each request is signed with an IAM user's **API signing key** (RSA, OCI's HTTP signature scheme). acme lists the primary zones of a compartment, and adds or removes only its own value with `PATCH .../zones/{zone}/records/{name}/TXT` (`ADD` / `REMOVE`), so other values at the name stay.

## What you need

- A public DNS zone in OCI (Networking → DNS Management → Zones), delegated from the registrar.
- HTTPS (TCP 443) from acme to `dns.<region>.oci.oraclecloud.com`.
- Rights in the tenancy to create a user, a group and a policy (or an administrator who does it).

## Set up Oracle Cloud

1. Create a group and a user for acme: **Identity & Security → Domains →** your domain **→ Groups → Create group** `acme-dns`; **Users → Create user** `acme`, add it to `acme-dns`. The user needs no console password.
2. Create a policy in the compartment that holds the zone (or the root): **Identity & Security → Policies → Create Policy**:

   ```text
   Allow group acme-dns to manage dns in compartment <compartment-name>
   ```

   This is the statement the module documents. A narrower one (zones read, records changed) may be possible - check OCI's DNS policy reference before tightening it.
3. Make an RSA key pair without a passphrase:

   ```sh
   openssl genrsa -out acme-oci.pem 2048
   openssl rsa -in acme-oci.pem -pubout -out acme-oci-public.pem
   ```

4. The user → **API keys → Add API key → Paste public key** (`acme-oci-public.pem`). Copy the **fingerprint** shown.
5. Note the **tenancy OCID** (Profile → Tenancy), the **user OCID**, the **region identifier** (e.g. `eu-frankfurt-1`) and the **compartment OCID** of the zone.

With the OCI CLI the same can be done with `oci iam group create`, `oci iam user create`, `oci iam policy create` and `oci iam user api-key upload`.

## Fill in acme

| acme field | What to put there |
|---|---|
| Tenancy OCID | `ocid1.tenancy.oc1..…` |
| User OCID | `ocid1.user.oc1..…` of the acme user |
| Key fingerprint | the fingerprint from step 4 |
| API private key | the content of `acme-oci.pem` (PEM, RSA, no passphrase) |
| Region | e.g. `eu-frankfurt-1` |
| Compartment OCID | where the zones are; empty = the tenancy (root compartment) |
| Zone | empty (the longest zone of the compartment the name is in), or the zone |
| TTL (s) | 30 (advanced) |
| API address | empty = `https://dns.<region>.oci.oraclecloud.com` (advanced) |

## Check it

- In acme press **Test**: it signs a request and lists the zones of the compartment; nothing is changed.
- With the OCI CLI (as that user):

  ```sh
  oci dns record rrset get --zone-name-or-id example.com --domain _acme-challenge.www.example.com --rtype TXT
  ```

## Common problems

| Problem | Fix |
|---|---|
| `401 NotAuthenticated` | Fingerprint, user OCID or tenancy OCID do not match the key; or acme's clock is off by more than 5 minutes. |
| `404 NotAuthorizedOrNotFound` | The policy is missing or in the wrong compartment, or *Compartment OCID* is not where the zone is. |
| Key cannot be read | The private key has a passphrase or is not RSA PEM - make a new one as in step 3. |
| Zone not found | It is a private zone or in another region's endpoint - only public zones are used. |
