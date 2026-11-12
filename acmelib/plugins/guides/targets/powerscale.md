# Dell PowerScale OneFS - setup for acme

acme puts the certificate on a **PowerScale (Isilon) cluster** as an HTTPS server certificate
and makes it the **default HTTPS certificate** of the WebUI and the Platform API
(`https://<cluster>:8080`). It uses only the OneFS REST API on port 8080 with HTTP basic
authentication:

1. reads the OneFS version (`GET /platform/1/cluster/config`);
2. writes the certificate (with its intermediates) and the key as files to `/ifs/local`
   through the RESTful Access to Namespace (RAN, `PUT /namespace/ifs/local/<name>.crt|.key`,
   mode 0600) - OneFS imports certificates **only from files on /ifs**;
3. imports them (`POST /platform/4/certificate/server` with `certificate_path` and
   `certificate_key_path`), under a dated name `acme-<name>-<date>-<serial>`;
4. **deletes both files** at once (also when the import fails) - the key does not stay on /ifs;
5. makes it the default (`PUT /platform/7/certificate/settings`
   `{"default_https_certificate": "<id>"}`);
6. deletes older acme certificates beyond *keep* (never the one that is the default).

## Which OneFS

**OneFS 8.2 - 9.12** (checked against the 9.5 - 9.12 documents, PAPI `v9_12_0`): every
version uses the same calls, hence one module. OneFS 8.0/8.1 set the default another way
(`isi certificate server modify --default`) - acme refuses them before changing anything.
A newer OneFS goes on with a warning. Data protocols (SMB, NFS, S3) are not affected.

## The account (least privileges)

| Privilege | Why |
|---|---|
| `ISI_PRIV_LOGIN_PAPI` (read) | sign in to the Platform API |
| `ISI_PRIV_CERTIFICATE` (write) | import, set the default, delete certificates |
| `ISI_PRIV_NS_IFS_ACCESS` (read) + write access to `/ifs/local` | write and delete the two files through RAN |

On any node, in the System zone (OneFS 9.x; 8.x uses `--add-priv`):

```sh
isi auth users create acme --enabled=true --set-password --zone=System
isi auth roles create AcmeCert --description "acme: TLS certificates" --zone=System
isi auth roles modify AcmeCert --add-priv-read=ISI_PRIV_LOGIN_PAPI --add-priv-write=ISI_PRIV_CERTIFICATE --add-priv-read=ISI_PRIV_NS_IFS_ACCESS --add-user=acme --zone=System
isi auth roles view AcmeCert
```

Check the privilege names on your OneFS first (they are not in every guide):

```sh
isi auth privileges | grep -Ei 'cert|papi|ifs_access'
```

The folder for the files (only acme and root may enter it):

```sh
mkdir -p /ifs/local
chown acme /ifs/local
chmod 700 /ifs/local
```

The built-in role **SystemAdmin** has everything, if you prefer it.

## What to enable

- The WebUI / Platform API on **TCP 8080** from acme (`isi http settings view`; HTTPS is on by
  default).
- Basic authentication for the Platform API (on by default).
- The certificate's names must include **every SmartConnect name** clients use: OneFS picks the
  certificate by the name asked for.
- An RSA key (Dell's example: RSA 2048); ECDSA is not documented.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the cluster's SmartConnect name or a node's address, `8080` |
| User / Password | the `acme` account |
| Check the device's certificate | off for the first deployment over the self-signed certificate (or give *CA certificate*), then on |
| Make it the default HTTPS certificate (deploy) | on (off only imports it) |
| Folder on /ifs for the import (deploy, advanced) | `/ifs/local` |
| Previous versions to keep (deploy, advanced) | older acme certificates to keep |
| Check what is served | empty: acme checks the address and port of the target |

## Check it

```sh
isi certificate server list -v
isi certificate settings view
openssl s_client -connect cluster.example.local:8080 -servername cluster.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Over the API:

```sh
curl -s -u acme:'<password>' https://cluster.example.local:8080/platform/7/certificate/settings
```

## Common problems

| Problem | Fix |
|---|---|
| `401` on signing in | Wrong password, or the account has no `ISI_PRIV_LOGIN_PAPI`. |
| `403` on `PUT /namespace/...` | No `ISI_PRIV_NS_IFS_ACCESS` or no write access to the folder. |
| `403` on `/platform/4/certificate/server` | No `ISI_PRIV_CERTIFICATE` (write). |
| Import refused, key does not match | The key and certificate differ - deploy again (acme always sends a matching pair). |
| `runs OneFS 8.1` | Upgrade to 8.2 or later, or set the default by hand. |
| The old certificate is still served | The OneFS 9.5 guide restarts the WebUI service after the change - do it in a maintenance window: `isi services -a isi_webui disable` and `isi services -a isi_webui enable` (check the syntax on your OneFS). |
| A browser warns about the name | Add the SmartConnect names to the certificate. |
