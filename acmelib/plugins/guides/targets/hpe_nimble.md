# HPE Alletra 5000/6000, Nimble Storage (NimbleOS) - setup for acme

acme replaces the group's **custom certificate** - used by the HTTPS GUI (port 443) and/or
the REST API (port 5392) - through the NimbleOS REST API:

1. signs in: `POST /v1/tokens` `{"data": {"username", "password", "app_name": "acme"}}`,
   the `session_token` in the `X-Auth-Token` header;
2. imports the key, certificate and chain as **PKCS#12** (base64, one-time password):
   `POST /v1/certificates/actions/import`
   `{"data": {"name": "custom", "input": "<base64>", "pkcs12": true, "password": "...", "force": true}}`;
3. puts it to use: `POST /v1/certificates/actions/use`
   `{"data": {"name": "custom", "https": true, "apis": true}}`;
4. signs out (`DELETE /v1/tokens/<id>`).

The GUI web server and/or the REST API then **reload**: their sessions are cut. **Host I/O
(iSCSI/FC) is not touched**, the controllers are not restarted.

> **Check the action names first.** HPE's public SDKs give the fields of the
> `certificates` object (`name`, `input`, `pkcs12`, `password`, `force`, `https`, `apis`,
> `reload_https`, `reload_apis`) and the URL convention `/v1/<object>/actions/<action>`,
> but the NimbleOS REST API Reference (on HPE InfoSight, behind a sign-in) was not
> readable - the names `import` and `use` are acme's assumption. They are settings of the
> deployment (*More*): if your NimbleOS names them otherwise, put its paths there. A
> wrong name answers 404 and acme says so; nothing is changed then.

## Which versions

One module for **NimbleOS 5.x and 6.x** (HPE Alletra 5000/6000, Nimble AF/HF): the SDKs
show no difference of the certificates object. Not for HPE Alletra 9000 / Alletra Storage
MP B10000 (another OS: their CLI makes the key on the array and takes no key of acme's).

## What you need

- Network access from acme to the group's management IP: **TCP 5392** (REST API, on by
  default) - and 443 for acme's check of the GUI.
- A NimbleOS user with the role **administrator** (whether *poweruser* is enough is not
  documented).
- NTP on the group.

## Set up the array

Create the user - in the GUI (*Administration → Users and Groups*), with Ansible
(`hpe.nimble`):

```text
- name: acme service account
  hpe.nimble.hpe_nimble_user:
    host: "{{ nimble_host }}"
    username: "{{ admin_user }}"
    password: "{{ admin_pass }}"
    name: svc-acme
    user_password: "<strong-password>"
    role: administrator
    description: "acme certificate manager"
    state: present
```

or with the REST API:

```sh
TOKEN=$(curl -sk -X POST "https://nimble.example.com:5392/v1/tokens" -H "Content-Type: application/json" \
  -d '{"data":{"username":"admin","password":"<admin-password>"}}' | jq -r .data.session_token)
curl -sk -X POST "https://nimble.example.com:5392/v1/users" -H "X-Auth-Token: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data":{"name":"svc-acme","password":"<strong-password>","role":"administrator"}}'
```

Look at the certificates the group has (`custom` is the one acme replaces):

```sh
curl -sk "https://nimble.example.com:5392/v1/certificates/detail" -H "X-Auth-Token: $TOKEN" \
  | jq '.data[] | {name, trusted, subject}'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the group's management FQDN or IP, e.g. `nimble.example.com` |
| HTTPS port | `5392` (the REST API) |
| User / Password | `svc-acme` from above |
| Check the device's certificate | on; off only while the group still has its self-signed certificate |
| CA certificate (advanced) | the CA of the group's current certificate, if not public |
| Use it for the HTTPS GUI (443) (deploy) | on |
| Use it for the REST API (5392) (deploy) | on - clients that pin the old one must take the new one |
| Certificate name (deploy, advanced) | `custom` |
| Import action / Use action (deploy, advanced) | `/v1/certificates/actions/import`, `/v1/certificates/actions/use` - or what your NimbleOS REST reference says |
| Check what is served (deploy) | empty: acme checks 443 and/or 5392 of the address |

The certificate: the group's management FQDN and IP (and those clients reach it by) in it.

## Check it

```sh
openssl s_client -connect nimble.example.com:443 -servername nimble.example.com </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect nimble.example.com:5392 -servername nimble.example.com </dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | wrong user or password |
| `403` | the user is not an *administrator* |
| *the group has no action ...* | the action name differs in your NimbleOS - look it up in the REST API Reference (InfoSight) and set *Import action* / *Use action* |
| vCenter plugin / VASA provider stops working | vCenter remembers the old certificate's fingerprint - register them again |
| PowerShell Toolkit refuses the group | `Connect-NSGroup -ImportServerCertificate` again (Windows) |

Sources: HPE nimble-python-sdk (`restclient.py`: port 5392, `v1/tokens`, `X-Auth-Token`,
`/{object}/actions/{action}`), HPE nimble-golang-sdk (`certificate.go`, `ns_cert_data.go`,
`ns_user_roles.go`), HPE nimble-ansible-modules 1.1.4.
