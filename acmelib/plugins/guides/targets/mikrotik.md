# MikroTik RouterOS - setup for acme

acme puts the certificate (full chain) and its key on the router as files over **SSH** (SCP/SFTP), imports them (`/certificate import`), names the result `acme-<name>-<date>-<serial>`, deletes the uploaded files and binds it to the services you choose - `www-ssl`, `api-ssl`, `reverse-proxy` (RouterOS 7.22+), the SSTP server and the OpenVPN server. Older acme certificates no service uses any more are removed. Two ways to talk to the router:

- **REST API (RouterOS 7) + SSH for the files** - the default;
- **SSH only (RouterOS 6)** - the same with CLI commands.

## What you need

- RouterOS 7 (REST) or RouterOS 6 (SSH only).
- From acme: SSH (port 22) to the router, and for REST also HTTPS (`www-ssl`, port 443).
- A RouterOS user in a group with the policies `read`, `write`, `api`, `rest-api`, `ssh`, `ftp` (`ftp` is what lets SCP/SFTP write files; `rest-api` exists only in RouterOS 7).

## Set up RouterOS

1. Create a group and a user for acme, allowed only from the acme server (`192.0.2.10` here):

```text
/user group add name=acme policy=read,write,api,rest-api,ssh,ftp
/user add name=acme group=acme password="a-strong-password" address=192.0.2.10/32
```

   (On RouterOS 6 leave out `rest-api`.)

2. Optional but recommended: sign in over SSH with a key. Upload the public key made in acme (e.g. as `acme.pub` via Winbox **Files**), then:

```text
/user ssh-keys import public-key-file=acme.pub user=acme
```

3. Make sure SSH is on and reachable from acme:

```text
/ip service set ssh disabled=no address=192.0.2.10/32,10.0.0.0/8
```

4. For REST (RouterOS 7): `www-ssl` must be on. On a new router it has no certificate - make a self-signed one for the first run:

```text
/certificate add name=selfsigned common-name=router.example.local key-usage=digital-signature,key-encipherment,tls-server
/certificate sign selfsigned
/ip service set www-ssl certificate=selfsigned disabled=no
```

   Add the acme server to the `address` of `www-ssl` if you limit it. **Keep the plain `www` (HTTP) service off** - the password travels in every REST request.

5. For SSTP / OpenVPN: the servers must exist (`/interface sstp-server server`, `/interface ovpn-server server`); acme only changes their certificate.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the router's address |
| Speak through | REST API (RouterOS 7) + SSH for the files, or SSH only (RouterOS 6) |
| User | `acme` |
| Password | its password (for REST, and for SSH when no key is given) |
| HTTPS port | 443 (the `www-ssl` port) |
| SSH port | 22 |
| The SSH key | the key made in acme (public half imported in step 2); empty: the password is used |
| SSH host key / Trust the first host key seen (advanced) | the router's host key, or trust the first one seen |
| Check the device's certificate | off for the first run while `www-ssl` is self-signed (or paste it as *CA certificate*); on afterwards |
| Use it for (deployment) | one a line: `www-ssl`, `api-ssl`, `reverse-proxy`, `sstp`, `ovpn` |
| Previous versions to keep | older acme certificates kept on the router |
| Check what is served | `router.example.com:443`, one a line |

## Check it

- **Test** in acme reads `/system/resource` (REST) or `/system resource print` (SSH) and shows the RouterOS version. The SSH key's *Try* runs `/system identity print`.
- On the router:

```text
/certificate print detail where name~"acme-"
/ip service print detail where name~"ssl"
```

## Common problems

| Problem | Fix |
|---|---|
| 401 on Test (REST) | wrong password, the group lacks `rest-api`/`read`, or the user's `address` excludes acme |
| SSH sign-in refused | `ssh` service off or limited by address, the group lacks `ssh`, or the key is not imported for the user |
| File upload fails | the group lacks `ftp` (needed for SCP/SFTP writes) |
| TLS error on the first REST run | `www-ssl` is self-signed: turn off *Check the device's certificate* once or give its certificate as CA |
| `the router took the certificate without its key` | the key upload failed or did not match; check the files and free space on the router |
| `not a service acme can bind on RouterOS` | use only `www-ssl`, `api-ssl`, `reverse-proxy`, `sstp`, `ovpn` |
| `the old … is still used: kept` | another service (e.g. IPsec, hotspot) uses it; switch that one by hand |
