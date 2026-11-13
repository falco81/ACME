# Fujitsu ETERNUS SF (Web Console certificate) - setup for acme

ETERNUS SF Express / Storage Cruiser / AdvancedCopy Manager (Version 16) has **no API, CLI or
GUI function for its certificate**: the Web Console's Apache reads `server.crt` and `server.key`
on the Management Server. acme replaces them with the generic targets - **Linux / Unix server
(SSH)** or **Windows server (OpenSSH + PowerShell)** - and restarts the web services. There is no
module of its own because there is nothing ETERNUS-specific to call.

**Less certain** (Fujitsu's Web Console Guide pages were only seen in excerpts): the exact
folder (`conf` itself or a sub-folder), the Windows service names, the path of the scripts on
Linux and the port (usually 9855). Check them on your Management Server before the first run.

## What you need

- SSH from acme to the Management Server (Windows: OpenSSH Server).
- Linux: `root`, or a user with `sudo` for the two files and the two scripts. Windows: a member of
  the local Administrators.
- An unencrypted PEM key (Apache does not start with an encrypted one).

## Linux Management Server - target "Linux / Unix server (SSH)"

| acme field | What to put there |
|---|---|
| Address / User | the Management Server, `root` (or a sudo user with *Use sudo*) |
| Files (deploy) | see below |
| Before writing (deploy) | `/opt/FJSVesfcm/bin/stop-webservice.sh` |
| Reload / restart (deploy) | `/opt/FJSVesfcm/bin/start-webservice.sh` |
| Keep a copy of a file replaced (deploy) | on |
| Check what is served | `esf.example.local:9855` |

```text
fullchain-pem /etc/opt/FJSVesfcm/conf/apache/server.crt 0644 root:root
key-pem /etc/opt/FJSVesfcm/conf/apache/server.key 0600 root:root
```

## Windows Management Server - target "Windows server (OpenSSH + PowerShell)"

| acme field | What to put there |
|---|---|
| Files (deploy) | see below (default install folder `C:\ETERNUS_SF`) |
| PowerShell after (deploy) | see below |
| Check what is served | `esf.example.local:9855` |

```text
fullchain-pem C:/ETERNUS_SF/Common/sys/apache/conf/server.crt
key-pem C:/ETERNUS_SF/Common/sys/apache/conf/server.key
```

```text
Stop-Service -DisplayName 'ETERNUS SF Manager Apache Service','ETERNUS SF Manager Tomcat Service'
Start-Service -DisplayName 'ETERNUS SF Manager Tomcat Service','ETERNUS SF Manager Apache Service'
```

(Find the service names first: `Get-Service | Where-Object DisplayName -like 'ETERNUS SF Manager*'`.)

## Check it

```sh
openssl s_client -connect esf.example.local:9855 -servername esf.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

On the server: the key and certificate must match -

```sh
openssl x509 -in /etc/opt/FJSVesfcm/conf/apache/server.crt -noout -modulus | openssl md5
openssl rsa -in /etc/opt/FJSVesfcm/conf/apache/server.key -noout -modulus | openssl md5
```

An upgrade or reinstallation of ETERNUS SF Manager may put a new self-signed certificate back -
deploy again (force) after one.
