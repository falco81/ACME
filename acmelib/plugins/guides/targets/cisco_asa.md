# Cisco Secure Firewall ASA - setup for acme

acme uses the **ASA HTTP Interface for Automation** - the CLI over HTTPS (`/admin/exec/...`
and `POST /admin/config`) that Cisco recommends instead of the old ASA REST API. A
trustpoint enrolled from PKCS#12 cannot be renewed, so each renewal is a **new trustpoint**
of a dated name:

```text
crypto ca trustpoint <tp>
exit
crypto ca import <tp> pkcs12 <random passphrase> nointeractive
<the PKCS#12 with its chain, base64>
quit
```

Then `ssl trust-point <tp> <interface>` for each line you give (and wherever an older acme
trustpoint of this certificate was named), older acme trustpoints no `ssl trust-point`
names are removed (`no crypto ca trustpoint <old> noconfirm`), and `write memory` saves
it. Every answer is read for `ERROR:` / `% Invalid`, as a 200 also comes with a failed
command.

For ASA software with the HTTP interface (ASDM access), physical, ASAv and Firepower in ASA
mode. Typical use: AnyConnect / Secure Client VPN and the ASDM / WebVPN portal.

## What you need

- HTTPS management (the ASDM port, 443 by default) reachable from acme on the interface
  you use.
- A **privilege 15** local user (or AAA user) allowed to use HTTP.
- The interface names (`nameif`) or domains that should present the certificate.

## Set up the ASA

1. Enable the HTTP server and allow acme's address on the management interface:

   ```text
   configure terminal
   http server enable
   http 198.51.100.10 255.255.255.255 management
   ```

2. Create the user and let HTTP use the local database:

   ```text
   username acme password <strong-password> privilege 15
   aaa authentication http console LOCAL
   ```

3. Basic authentication is taken only from allowed User-Agent strings. `ASDM` is allowed
   by default; if you restricted it with `http server basic-auth-client`, add the string
   acme sends:

   ```text
   http server basic-auth-client ASDM
   write memory
   ```

4. Note where the certificate goes: `show running-config ssl` (e.g. `outside`,
   `outside vpnlb-ip`, `domain vpn.example.com`).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | The ASA's management address and ASDM port (`443`) |
| User | The privilege 15 user (`aaa authentication http console LOCAL`) |
| Password | Its password |
| User-Agent (advanced) | Default `ASDM` - must be allowed by `http server basic-auth-client` |
| Check the device's certificate / CA certificate | Off only while the ASA has its self-signed certificate |
| ssl trust-point (deploy) | One a line: an interface (`outside`), `outside vpnlb-ip`, `domain vpn.example.com`, or `-` for the fallback of every interface; empty: only where an older acme trustpoint was named |
| PKCS#12 kind (deploy, advanced) | `3DES (older ASA)` (default) or `AES-256` |
| Save the configuration (write memory) (deploy) | On |
| Previous versions to keep (advanced) | Default 1; **`-1` if the trustpoints are also used for IKEv2/IPsec** (acme does not look there) |
| Check what is served | e.g. `vpn.example.com:443` |

## Check it

- **Try** runs `show version` and counts the trustpoints:
  `signed in to ...: Cisco Adaptive Security Appliance Software Version 9.x; N trustpoints`.
- On the ASA:

  ```text
  show crypto ca certificates
  show running-config ssl
  ```

## Common problems

| Problem | Fix |
|---|---|
| 401 / 403 | Wrong credentials, user not privilege 15, or `aaa authentication http console LOCAL` missing |
| Refused because of User-Agent | Add `http server basic-auth-client ASDM` (or set acme's *User-Agent*) |
| Connection timeout | `http <acme-ip> <mask> <interface>` missing, or a wrong port |
| `Import PKCS12 operation` not completed | Try *PKCS#12 kind* `3DES` on older ASA software |
| `ERROR: ... trustpoint` while removing | The old trustpoint is used elsewhere (IPsec) - set *keep* to `-1` |
| Lost after reload | Turn on *Save the configuration* |
| Failover pair | Configuration replicates to the standby only if failover replication is on - check it |
