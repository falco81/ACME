# HPE Alletra 9000 / Alletra Storage MP B10000 - key made by the array - setup for acme

The array's CLI makes the key and CSR of its **unified-server** certificate itself (the one
certificate of WSAPI, the UI / SSMC connection and CIM) and imports the certificate signed for
it - a key made elsewhere cannot be imported. So the **array makes the key**: at every issue
and renewal acme signs in over SSH, runs `createcert unified-server -csr ...` for exactly the
certificate's names, has the CSR signed by the certificate's source and right away imports the
certificate (`importcert unified-server`), the intermediates first. The CSR changes nothing on
the array; the import restarts the management services (WSAPI, UI) for a moment - host I/O is
not touched.

Versions: HPE Alletra 9000 (OS 9.x) and Alletra Storage MP B10000 (OS 10.x) - the CLI they
carry on from Primera and 3PAR. Keys: RSA 2048, 3072 or 4096.

**Not tried on an array by acme** - HPE's CLI reference was not readable when this was made.
Check on yours, before the first renewal, that `help createcert` lists `-csr -keysize -C -ST
-L -O -OU -CN -SAN` and `help importcert` takes `stdin` as the file; a different answer stops
the job with the CLI's own words, nothing changed.

## What you need

- From acme to the array's management address: **TCP 22** (SSH).
- A CLI user with the role **super** in the domain **all** (certificates are system-wide).
- A source that signs a CSR made elsewhere - an ACME CA (DNS-01 validation for the names),
  acme's own authority, a commercial CA. Not *Self-signed*, CMP or SCEP.

## Set up the array

1. A user for acme (as an administrator, in the CLI):

   ```text
   cli% createuser -c '<password>' svc-cert all super
   cli% setsshkey -user svc-cert
   ```

   `setsshkey` asks for the public key (paste the one acme shows at *The SSH key*); or sign in
   with the password.
2. Look at the current certificate and the CLI's help:

   ```text
   cli% showcert -service unified-server
   cli% help createcert
   cli% help importcert
   ```

3. The names: the array's management FQDN and its management IP - all go into the CSR
   (`-SAN DNS:...,IP:...`).

## Fill in acme

The target (**Targets → Add → HPE Alletra 9000 / Alletra Storage MP B10000 - key made by the
array**):

| acme field | What to put there |
|---|---|
| Address | The array's management FQDN or IP, e.g. `alletra01.example.local` |
| SSH port | `22` |
| User | `svc-cert` |
| Sign in with / The SSH key / Password | The key set with `setsshkey`, or the password |
| Country (C), State or region (ST), City (L), Organization (O), Unit (OU) | The CSR's subject; the certificate's own subject (its profile) wins |
| HTTPS port of WSAPI / UI | `443` - where acme's test looks |

Then the certificate: **Add a certificate → Key → Key made by the device → pick this target**.
Its names: the array's FQDN and management IP. Its key type: `rsa-2048`, `rsa-3072` or
`rsa-4096`. acme makes the deployment to the array (option *Import the intermediates first*,
on by default); it runs right after each issue.

```sh
acme --cert-add alletra01 --names alletra01.example.local,10.0.0.60 --key-type rsa-2048 --issuer "Own CA" --csr-from alletra01
acme --renew alletra01
```

## Check it

- **Test** on the target signs in and runs `showversion` and `showcert -service
  unified-server` - nothing is changed.
- **Renew now** on the certificate: the job shows the `createcert` command, the issue, then the
  two `importcert` commands.

  ```sh
  openssl s_client -connect alletra01.example.local:443 -servername alletra01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  After the change, check in DSCC (and in vCenter's VASA provider, if registered) that the
  array is still connected - a client that pins the old certificate must accept the new one.

## Common problems

| Problem | Fix |
|---|---|
| SSH refused / `Permission denied` | User, key or password; the user must be allowed SSH. |
| `the array's CLI said ... invalid option` | The CLI of this OS takes other options - see `help createcert` / `help importcert` and tell us. |
| `cannot be given to the array's CLI` | Remove `"`, `[ ]`, `{ }`, `$` or `\` from the subject on the target. |
| `printed no CSR` | The user is not *super* in *all*, or the CLI printed the CSR elsewhere - look at the job's detail. |
| The import refused | Another CSR was made on the array since (by hand) - **Renew now** makes a new one. |
| Deployments held | The array keeps its old certificate; the next issue asks it for a new key and CSR. |
