# Cisco Secure Firewall Management Center (FMC 7.7 - 10.0) - setup for acme

This version of the target does what the plain one does - the certificate as a new **Internal Certificate** object, the *Decrypt - Known Key* rules of the decryption policies you name switched to it, a deployment - and, from FMC **7.7**, it also puts the certificate on the **devices** (Devices → Certificates: the trustpoint of **RA VPN**, SAML, S2S VPN):

```text
GET  /api/fmc_platform/v1/info/serverversion                          the FMC version (7.7 or later)
GET  /api/fmc_config/v1/domain/<d>/object/certenrollments             the enrollment object by name
POST /api/fmc_config/v1/domain/<d>/object/certenrollments             the first time
PUT  /api/fmc_config/v1/domain/<d>/object/certenrollments/<id>        each renewal: its new PKCS#12
     {"type": "CertEnrollment", "name", "enrollmentType": "PKCS12",
      "pkcs12Content": {"base64Certificate", "passPhrase"},
      "validationUsage": {"ipsecClient": true, "sslServer": true}}
GET  /api/fmc_config/v1/domain/<d>/devices/devicerecords              the devices by name
GET  /api/fmc_config/v1/domain/<d>/devices/certificates?filter=deviceId:<id>&expanded=true
POST /api/fmc_config/v1/domain/<d>/devices/operational/managecertificates
     {"action": "ENROLL" (the first time on a device) | "RE_ENROLL",
      "deviceCertificates": [{"deviceId", "certificates": [{"certificate": {"id": <enrollment>}}]}]}
```

The enrollment object keeps **one name**, so the trustpoint on the devices keeps it too: the RA VPN connection profiles (Access Interfaces → *Certificate Enrollment*) that name it need no change.

## Which FMC

Module version **"FMC 7.7 - 10.0"**: FMC **7.7.x and 10.0**. FMC 7.4 and 7.6 cannot enrol a certificate on a device over the API (`managecertificates` and `devices/certificates` are 7.7 and later; their `certenrollments` takes only PKCS12 and MANUAL CA-only) - use the plain version there, which handles the Internal Certificates only. On another FMC this version refuses before changing anything.

| Module version | FMC | Internal Certificate + decryption rules | Device certificate (trustpoint) |
|---|---|---|---|
| (the plain one) | 7.4 - 10.0 | yes | no |
| FMC 7.7 - 10.0 | 7.7 - 10.0 | yes (or off) | yes |

## What happens on the devices

- **Enrolment happens at once, without a deployment** (Devices → Certificates shows the trustpoint *Available*). Using a trustpoint in a policy needs a deployment - once, when you first name it in RA VPN.
- RA VPN: new client connections get the new certificate, tunnels up stay. Secure Client must trust the CA (else "Untrusted server"). S2S IKEv2: at the next negotiation.
- `managecertificates` runs as a task: acme asks for it and does not wait for its end - check *Devices → Certificates*.

## Set up the FMC

1. **REST API**: *Administration → Configuration → REST API Preferences → Enable REST API* (10.0; on 7.7 *System (gear) → Configuration*). In HA only on the active FMC.
2. **A role for acme** (*Administration → Users → User Roles*): copy *Network Admin*, keep the rights to the PKI objects (Object Manager), **Devices → Certificates** and, if acme deploys, **Deploy Configuration to Devices** - *uncertain*: the exact names of these rights; check them in *User Roles*.
3. **A user for the API only** (*Administration → Users → Create User*), e.g. `api-acme`, with that role, in the domain of the devices. Do not use it in the web interface: the same account signed in there signs the API out.
4. Note the names of the devices (*Devices → Device Management*) and choose the name of the enrollment object, e.g. `RAVPN-acme`. After the first deployment pick that trustpoint once in the RA VPN connection profile and deploy.

Try the sign-in:

```sh
curl -sk -i -X POST -u 'api-acme:<password>' https://fmc.example.com/api/fmc_platform/v1/auth/generatetoken
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **FMC 7.7 - 10.0** |
| Address / HTTPS port | the FMC, e.g. `fmc.example.com` / `443` |
| User / Password | the API-only account of step 3 |
| Domain UUID (advanced) | empty: the domain the sign-in answers with |
| Cert Enrollment object (PKCS12) (deploy) | e.g. `RAVPN-acme`; empty: no device certificate |
| Enrol on these devices (deploy) | one a line: device names, e.g. `ftd-1` |
| Also an Internal Certificate (deploy) | on: as the plain version (decryption rules); off: only the device certificate |
| Decryption policy, More decryption policies, Deploy to the devices, Only these devices (deploy) | as in the plain version |
| Previous versions to keep (advanced) | for the Internal Certificates, default `1` |

## Check it

On the FMC: *Devices → Certificates* (the trustpoint, *Available*, its expiry); over the API:

```sh
curl -sk -H "X-auth-access-token: $TOKEN" "https://fmc.example.com/api/fmc_config/v1/domain/$DOMAIN/devices/certificates?filter=deviceId:<device-uuid>&expanded=true"
```

On the device (`system support diagnostic-cli`):

```text
show crypto ca certificates RAVPN-acme
show crypto ca trustpoints
```

From outside:

```sh
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| *this device runs FMC 7.6...* | FMC before 7.7 | the plain version of the target |
| *the FMC has no device ...* | a name not in Device Management | the exact device name |
| *the Cert Enrollment ... is of the type SCEP* | the name belongs to another kind of enrollment | another name (a PKCS12 one acme owns) |
| `400` / `422` at the enrollment | the PKCS#12 refused (over 24 kB, the chain, the key type) | the certificate's size and key (RSA 2048+ / ECDSA) |
| the device keeps the old certificate after RE_ENROLL | see *Uncertain* | *Devices → Certificates → Refresh*, or re-enrol it there once |

*Uncertain* (the guide marks them): the fields of `certenrollments` are from Cisco's Terraform provider (`fmc_certificate_enrollment`, `fmc_device_certificate`), not from the API reference; whether `RE_ENROLL` of a PKCS12 object takes the PKCS#12 put into it by `PUT` was not checked on a device; `serverversion` is the FMC's usual call, not quoted by the guide.

Sources: FMC REST API Quick Start Guide 10.0 (Objects in the REST API, About the FMC REST API - Certificates / Manage Certificates from 7.7), FMC Device Configuration Guide 10.0 (Certificates), Cisco's Terraform provider `CiscoDevNet/fmc`.
