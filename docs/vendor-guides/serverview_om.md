# Fujitsu ServerView Operations Manager (CMS) - setup for acme

ServerView Operations Manager (SVOM 10.x, the Central Management Station) has **no API, CLI or
GUI function for its certificate**: TomEE and ApacheDS (CAS / single sign-on) read the Java
keystore `…\tomee\svconf\pki\keystore` with the key under the alias **`svs_cms`**. acme can
write that keystore with the generic targets - **Windows server (OpenSSH + PowerShell)** or
**Linux / Unix server (SSH)** - in the format `jks` with the alias `svs_cms`, then restart the
services. There is no module of its own: there is nothing SVOM-specific to call, and **several
steps are not confirmed** by Fujitsu's manual "User Management in ServerView" (not available in
full): the keystore password TomEE expects, JKS vs. PKCS#12, the trust store's file name and the
`<system_name>.scs.pem` of the Remote Connector Service. Try it on a test CMS first, with a copy
of the keystore kept.

## What you need

- SSH from acme to the CMS (Windows: OpenSSH Server); a local administrator (Windows) or `root`
  (Linux).
- The keystore password of your SVOM installation.
- A maintenance window: GUI, SSO and data collection are away for 5-10 minutes; managed servers
  are not touched. iRMCs that check the CAS server's certificate need the new CA ("CA Certificate
  for CAS and SMTP" in the iRMC).

## Windows CMS - target "Windows server (OpenSSH + PowerShell)"

| acme field | What to put there |
|---|---|
| Files (deploy) | `jks "C:/Program Files (x86)/Fujitsu/ServerView Suite/tomee/svconf/pki/keystore"` |
| Keystore alias (deploy) | `svs_cms` |
| Password of PKCS#12 / keystore files / PKCS#12 / keystore password (deploy) | the keystore password of the installation |
| Keep a copy of a file replaced (deploy) | on |
| PowerShell after (deploy) | see below |
| Check what is served | `svom.example.local:3170` |

```text
Stop-Service SVTomEE; Stop-Service SVApacheDSService
Start-Service SVApacheDSService; Start-Service SVTomEE
Restart-Service -DisplayName 'ServerView Services'
```

## Linux CMS - target "Linux / Unix server (SSH)"

The folder `/opt/fujitsu/ServerViewSuite/tomee/svconf/pki` is derived from the Windows layout -
check it. Restart: `/usr/bin/sv_services restart` (*Reload / restart*).

## Check it

```sh
openssl s_client -connect svom.example.local:3170 -servername svom.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
keytool -list -keystore keystore -storepass '<password>' -alias svs_cms
```

If logging in fails after a "change installation", Fujitsu's workaround copies the keystore back
from `%LocalAppData%\certificates\private\keystore` and restarts `SVApacheDSService` and
`SVTomEE`.
