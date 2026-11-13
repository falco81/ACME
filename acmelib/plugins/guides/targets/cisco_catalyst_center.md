# Cisco Catalyst Center (DNA Center) - setup for acme

acme replaces the **system certificate** of Catalyst Center (*Controller*: its GUI, the northbound Intent API, PnP, telemetry) and/or its **Disaster Recovery** certificate (*ipsec*) through the Intent API:

```text
POST /dna/system/api/v1/auth/token                                   (HTTP basic) -> Token
POST /dna/intent/api/v1/certificate?listOfUsers=server               certFileUpload + pkFileUpload
POST /dna/intent/api/v1/certificate-p12?listOfUsers=server&p12Password=...   p12FileUpload
GET  /dna/intent/api/v1/task/<taskId>                                 while it answers
```

The certificate goes with its chain in one PEM file in the order of the chain (server certificate, then the subordinate CA, then the root), its key in another - or, when you choose *PKCS#12*, all in one PKCS#12 with a one-time password.

## Which versions

Catalyst Center **2.3.7.x, 3.1.x and 3.3.x** - the same two calls in all (Cisco's SDK `dnacentersdk` for 3.1.6.0 and the Ansible modules `authentication_import_certificate[_p12]` from 2.3.7.6 on). One module version.

## What happens on Catalyst Center

- The certificate replaces the one *Used For* says: **Controller** (`server`), **Disaster Recovery** (`ipsec`) or both.
- Catalyst Center then restarts its web services: **everybody is signed out**, the GUI and API are away for about **2 minutes**. Plan it outside working hours.
- **Devices and integrations trust Catalyst Center by this certificate** (PnP, telemetry/Assurance, NETCONF callbacks, ISE pxGrid/ERS, ITSM, IPAM, your scripts): before the first switch to a certificate of a new CA make sure they trust that CA. With *device controllability* on, Catalyst Center usually updates the devices itself.
- Disaster Recovery: replace it on both sites in step.

## Set up Catalyst Center

1. A user for acme: **System → Users & Roles → User Management → Add**. Replacing the system certificate is a system setting: **SUPER-ADMIN-ROLE**. NETWORK-ADMIN-ROLE is not enough ("no access to system-related functions"). A role of its own (**System → Users & Roles → Role Based Access Control → Create a New Role**) with only *System → System Management* and *Platform → APIs* is the least - *uncertain*: the exact names of the permissions were not in the documents the guide could read.
2. On 2.3.x enable the REST API: **Platform → Manage → Bundles → Catalyst Center REST API → Enable** (on 3.x not needed as far as the documents say).
3. The certificate: RSA or ECDSA, at least 2048 bits; every name the clients use in the SAN (the FQDN of Catalyst Center; in practice also the cluster VIP and `pnpserver.<domain>` for PnP); key usage for **server and client authentication** (Cisco's requirement for its CSRs).

Try the sign-in from acme's machine:

```sh
curl -s -u acme -X POST https://catalyst.example.com/dna/system/api/v1/auth/token
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | `catalyst.example.com` / `443` |
| User / Password | the user of step 1 |
| Check the device's certificate | on (set *CA certificate* for a private CA); off only while it has its self-signed one |
| Used for (deploy) | *Controller* (the GUI, API, PnP), *Disaster Recovery*, or both |
| Upload as (advanced) | PEM chain + key (default) or PKCS#12 |
| Wait for the import (s) (advanced) | how long acme follows the import task |

acme cannot read which system certificate Catalyst Center holds (no call lists it): the same certificate is not sent twice because acme remembers what it sent; *force* sends it again.

## Check it

```sh
openssl s_client -connect catalyst.example.com:443 -servername catalyst.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

In the GUI: **System → Settings → Certificates → System Certificates → Action → View**. On each node of the cluster (maglev shell):

```sh
sudo maglev-config certs info
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| `401` at signing in | wrong user or password | the user of step 1 |
| `403` at the import | the role may not change system settings | SUPER-ADMIN-ROLE or the role of step 1 |
| *Catalyst Center refused the certificate: ...* | the import task failed (chain in the wrong order, key too short, the key does not fit) | read the reason; RSA/ECDSA 2048+ |
| *the task ... cannot be read any more* | expected: Catalyst Center restarts and signs acme out | the test of what is served says whether it took |
| devices stop reporting after the change | they do not trust the new CA | add the CA to the devices' trustpool (or let device controllability do it) |

*Uncertain*: the shape of the import's answer (`response.taskId`) and of the task (`isError`, `failureReason`, `endTime`) are the usual Intent API ones; whether an unencrypted key needs `pkPassword` (acme sends none).

Sources: Cisco Catalyst Center Administrator Guide 3.3.x (Manage Certificates, Certificate and Private Key Support, About user roles), the Intent API *Import Certificate*, Cisco's `dnacentersdk` 3.1.6.0 `authentication_management.py`, the `cisco.catalystcenter` Ansible collection.
