# FortiManager / FortiAnalyzer - setup for acme

acme talks to the **JSON-RPC API** (`POST /jsonrpc`, HTTPS) of a FortiManager or FortiAnalyzer with an **API token** (`Authorization: Bearer <token>`). It adds the certificate as a **local certificate** of the system under a dated name (`acme-<name>-<date>-<serial>`, at most 35 characters) - its key encrypted with a one-time password, as the CLI takes it -, adds the intermediates as CA certificates, makes it the **HTTPS certificate of the GUI and the API** and deletes older acme certificates beyond *keep*:

```text
add    /cli/global/system/certificate/local   {"name", "comment", "password", "private-key", "certificate"}
add    /cli/global/system/certificate/ca      {"name", "ca"}
set    /cli/global/system/admin/setting       {"admin_server_cert": "<name>"}
delete /cli/global/system/certificate/local/<older acme name>
```

The same in the CLI:

```text
config system certificate local
    edit "acme-fmg.example.com-20261112-a1b2c3"
        set password <password>
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY----- ... -----END ENCRYPTED PRIVATE KEY-----"
        set certificate "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----"
    next
end
config system admin setting
    set admin_server_cert "acme-fmg.example.com-20261112-a1b2c3"
end
```

This is the box's own certificate - not the certificates of the FortiGates it manages (point acme at each FortiGate for those) and not the FGFM certificate between FortiGate and FortiManager.

## Which versions

FortiManager and FortiAnalyzer **7.2.2 - 7.6** (API tokens exist from 7.2.2; from **7.4.7 / 7.6.2** the token is taken only in the header - acme always sends it there). The GUI moved the setting from *System Settings > Admin > Admin Settings* (7.2) to *System Settings > Settings → HTTPS & Web Service Certificate* (7.4 and later); the API is the same.

## 1. The API user and its token

```text
config system admin user
    edit "acme"
        set trusthost1 192.0.2.10 255.255.255.255
        set profileid "Super_User"
        set user_type api
        set rpc-permit read-write
    next
end
execute api-user generate-key acme
```

- `192.0.2.10` is an example: acme's address (`trusthost2` ... for a second node).
- `rpc-permit read-write` is **required** for JSON-RPC.
- The KB uses the profile `Super_User`; a smaller profile that may write the system certificates and the admin setting is not documented - try one with *System Settings* read-write, and go back to `Super_User` if acme gets `-11` (no permission).
- The token is shown once; `execute api-user generate-key acme` again makes a new one (the old one stops working).

## 2. HTTPS

The GUI's HTTPS port is `https_port` in `config system admin setting` (default 443). Allow HTTPS on the interface acme reaches (`config system interface` → `set allowaccess https ...`).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the FortiManager / FortiAnalyzer, `443` |
| API token | the key from `execute api-user generate-key` |
| Check the device's certificate | on; off only while the box still has its own `server.crt` |
| HTTPS certificate of the GUI and API (deploy) | on (`admin_server_cert`); off to only add the certificate |
| Add the intermediates as CA certificates (deploy, advanced) | on |
| Previous versions to keep (deploy, advanced) | older acme certificates kept; the one the GUI uses is never deleted |

The GUI and the API switch to the new certificate at once: with *Check the device's certificate* on, acme's next requests are checked against it (for a private CA set *CA certificate*).

## Check it

```sh
openssl s_client -connect fmg.example.local:443 -servername fmg.example.local -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"id":1,"method":"get","params":[{"url":"/cli/global/system/admin/setting"}]}' \
  "https://fmg.example.local/jsonrpc"
```

On the CLI:

```text
get system certificate local
show system admin setting
```

## Common problems

| Answer (status code) | Meaning | Fix |
|---|---|---|
| HTTP `401` | the token is wrong, or the request came from outside the trusted hosts | a new token; acme's address in `trusthost1` |
| `-11` No permission | the profile or `rpc-permit` does not allow writing | `set rpc-permit read-write`; the profile (`Super_User`) |
| `-6` Invalid url | the box does not know the path (an old firmware) | 7.2.2 or later |
| `-2` / *already exist* on add | a certificate of this name is there | acme looks first; deploy again with *force* only after deleting it |
| the browser still shows `server.crt` | *HTTPS certificate of the GUI and API* off | turn it on |
| the older certificate stays | still used (another setting) | acme says it and keeps it |

*Unverified* (from the vendor guide): the JSON-RPC body of the `add` (an unofficial how-to; the fields are the official CLI's and Ansible's), the CA certificate's field `ca` (Ansible), the least admin profile, and whether the web server restarts and signs sessions out.
