# Dell Unity (service shell) - setup for acme

acme installs the certificate as the **Unisphere management certificate** of a Dell Unity,
Unity XT or UnityVSA (GUI, REST API and uemcli on port 443). Unity has **no REST call nor
uemcli command** for this certificate: Dell's way (KB 000021122) is the **service shell**, and
that is what acme does over SSH as the `service` user:

```text
put  /home/service/user/acmecert.crt     the certificate (+ the intermediates), PEM only
put  /home/service/user/acmecert.pk      the RSA key, PEM, not encrypted, mode 0600
run  svc_custom_cert acmecert            "Successfully installed custom certificate files."
run  rm -f /home/service/user/acmecert.crt /home/service/user/acmecert.pk    (always)
```

`svc_custom_cert` **restarts Unisphere's web server**: the GUI, REST API and uemcli are gone
for a moment and their sessions are logged out. Block and file I/O is not affected.

## Which Unity OE

**Unity OE 5.x** (5.3, 5.4, 5.5.x; 5.5.1 or later recommended) - the same command in each,
hence one module. The OE version cannot be read in the service shell, so:

- **OE 5.5.0** refuses a file with CA certificates in it (`Unable to validate the specified
  certificate`, KB 000317557) and may fail with `Could not determine private key strength`
  (KB 000308965): there turn **Include the intermediates** off, or better upgrade to 5.5.1+.
- Only **RSA** keys are documented (Dell's example: RSA 2048) - acme refuses an ECDSA one.

## The account

Only the **service** account can do it (its password is set at the initial configuration and
differs from the Unisphere admin's). A Unisphere role is not enough.

Enable SSH for the service account - Unisphere: **Settings → Service → Service Tasks → Enable
SSH** - or with uemcli (check the syntax on your OE):

```sh
uemcli -d unity.example.local -u admin -p '<admin-password>' /service/ssh set -enabled yes
```

SSH to the **management address** lands on the primary SP, where the files must be. Check it
from the acme server:

```sh
ssh service@unity.example.local 'id -un; ls -d /home/service/user'
```

The service password is a powerful secret: give acme its own target and turn SSH off again if
you deploy only now and then (acme then fails to connect until it is on).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the Unity management address (`unity.example.local`) |
| SSH port | `22` |
| User | `service` |
| Sign in with / Password | *a password*, the service account's password |
| Host key (advanced) | the Unity's SSH host key, or leave *Trust the first host key seen* on |
| Unisphere HTTPS port (advanced) | `443` - where acme checks what is served |
| Include the intermediates (deploy) | on; **off on OE 5.5.0** |
| File name (deploy, advanced) | `acmecert` - the base of the `.crt` / `.pk` files |

## Check it

```sh
openssl s_client -connect unity.example.local:443 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
uemcli -d unity.example.local -u admin -p '<admin-password>' /sys/cert show
```

How many certificates are in the file (OE 5.5.0):

```sh
openssl crl2pkcs7 -nocrl -certfile unitycert.crt | openssl pkcs7 -print_certs -noout | grep -E "Issuer:|Subject:"
```

## Common problems

| Problem | Fix |
|---|---|
| `/home/service/user is not there` | You signed in as another user - use `service`. |
| `ERROR: File <acmecert.pk> does not exist` | The session landed on the secondary SP: use the management address. |
| `ERROR: Certificate ... is invalid` | Not PEM - acme always writes PEM; check the key type is RSA. |
| `Unable to validate the specified certificate (0x1000100)` | OE 5.5.0: turn *Include the intermediates* off, or upgrade to 5.5.1+. |
| Unisphere Central reports validation errors | Remove the Unity from Unisphere Central and add it again. |
| uemcli asks to accept the certificate again | Expected after a change: accept and store it (or `uemcli -certImport`). |
