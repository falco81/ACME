# HPE Aruba Networking Central (AOS 10) - setup for acme

AOS 10 gateways and APs have no configuration of their own: their certificates live in the **certificate store of Aruba Central**, and a profile (the captive portal of a gateway, 802.1X termination, the gateway's WebUI, a VPN) names one. acme keeps **one name** there: the first deployment uploads the certificate as a PKCS#12 under that name, every renewal **replaces it under the same name** - the profiles keep naming it and Central pushes the new one to the devices. The same holds for Instant APs and CX switches managed by Central.

```text
POST /oauth2/token?client_id=...&client_secret=...&grant_type=refresh_token&refresh_token=...
GET  /configuration/v1/certificates?limit=20&offset=0&q=<name>
POST /configuration/v1/certificates          the first time
PUT  /configuration/v1/non_msp/certificate   each renewal
     {"cert_name", "cert_type": "SERVER_CERT", "cert_format": "PKCS12",
      "passphrase": <base64 of a one-time password>, "cert_data": <base64 of the PKCS#12>}
```

## Which Central

**Classic Central** (the API Gateway, `apigw-...central.arubanetworks.com`). **New Central** (HPE GreenLake) has no certificate store API in the official index yet - not this module. **AOS 8 Mobility Conductors and controllers** are not managed this way: the guide found no documented API that uploads a certificate file to them (only the CLI `crypto pki-import` after copying the file to flash) - acme has no module for them.

## Set up Central

1. A role for the API: *Account Home → Global Settings → Users and Roles* - a role with **Network Operations: Modify** (write to the configuration), no *Account Home* administration. A user with only read access gets `403 No write access to upload certificates`. *Uncertain*: the menu names are from the guide's general knowledge.
2. An API client and a token: *Organization → Platform Integration → REST API*: make a system app and a token for that user. Note the **client ID**, **client secret** and the **refresh token** of the token, and the **API gateway** URL shown on that page (e.g. `https://apigw-prod2.central.arubanetworks.com` for US-2, `https://eu-apigw.central.arubanetworks.com` for EU-1).
3. In the group's configuration name the certificate (captive portal, 802.1X server certificate...) once - after the first deployment, by the name you give acme.

A refresh token is **used up** by a refresh: acme keeps the new one Central gives (in its own state, shared by a cluster). If acme says the refresh was refused (the token was refreshed elsewhere, or acme was not run for longer than the refresh token lives), make a new token and put its refresh token into the target.

Try a refresh by hand only with a token acme does not use:

```sh
curl -s -X POST "https://apigw-prod2.central.arubanetworks.com/oauth2/token?client_id=<id>&client_secret=<secret>&grant_type=refresh_token&refresh_token=<refresh>"
```

## Fill in acme

| acme field | What to put there |
|---|---|
| API gateway | the URL of step 2 |
| Client ID / Client secret | of the API client |
| Refresh token | the refresh token of the token of step 2 |
| Name in Central (deploy) | the name the profiles use, e.g. `captive-portal` |

## Check it

```sh
curl -s -H "Authorization: Bearer <access token>" "https://apigw-prod2.central.arubanetworks.com/configuration/v1/certificates?limit=20&offset=0&q=captive-portal"
openssl s_client -connect <gateway-captive-ip>:443 -servername captive.example.com </dev/null | openssl x509 -noout -subject -dates
```

In Central: the certificate store (*Organization → Network Structure → Certificates*), its expiry date. On a gateway (*Tools → Console*):

```text
show crypto-local pki ServerCert
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| *Central refused the token refresh* | the refresh token is used up or expired | a new token; its refresh token into the target |
| `403` | the role cannot write the configuration | Network Operations: Modify |
| `400` at the replacement | the same certificate again (Central refuses the same checksum), or another type of that name | *force* only with a new certificate; another name |
| *... is a CA_CERT, not a server certificate* | the name belongs to another kind of certificate | another name |
| `429` | Central's rate limit | acme waits by itself |

An MSP account's customers are updated by another call (`msp_update_certificate`) - not used by acme.

*Uncertain*: the shape of the list's answer (`items` with `cert_name`); the restart of the service on a gateway after the push is not in the documents.

Sources: Aruba Central API reference (Configuration → Certificates: upload, get, delete, update for non-MSP customers), Aruba's `pycentral` (`base.py`: the token refresh).
