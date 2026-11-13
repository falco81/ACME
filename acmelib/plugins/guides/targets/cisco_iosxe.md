# Cisco IOS XE (switches, routers) (any version (detects it)) - setup for acme

acme signs in to the device over **SSH**, copies the certificate with its key and chain as a **PKCS#12** to `bootflash:` with **SCP**, imports it into a new trustpoint named `acme-<name>-<date>-<serial>` (`crypto pki import ... pkcs12`), points the HTTPS server of the device (WebUI, RESTCONF, NETCONF over HTTPS) at it, restarts that server, saves the configuration (`write memory`) and removes older acme trustpoints beyond *keep*. The PKCS#12 file is deleted from `bootflash:` right after the import.

## Which IOS XE this guide is for

Module version **"any version (detects it)"**: IOS XE **17.3 - 26.1**. acme reads `show version` and makes the PKCS#12 to fit: 3DES with a SHA-1 MAC before 17.12, AES-256 with a SHA-256 MAC from 17.12 on. When the version cannot be read it sends the 3DES kind.

| Module version | IOS XE | PKCS#12 acme sends |
|---|---|---|
| any version (detects it) | 17.3 - 26.1 | by the version `show version` says |
| IOS XE 17.3 - 17.11 | 17.3 - 17.11 | 3DES, SHA-1 MAC |
| IOS XE 17.12 - 26.1 | 17.12 - 26.1 | AES-256, SHA-256 MAC |

Everything else - `crypto pki import`, `ip http secure-trustpoint`, restarting the HTTPS server, `write memory` - is the same in 17.3 - 26.1 (Cisco TN 213917, the IOS XE 17.x PKI configuration guide). Not sure? `show version | include Version` on the device.

## What acme changes on the device

| acme option | IOS XE configuration | Effect |
|---|---|---|
| (always) | `crypto pki trustpoint acme-...` (made by the import, with its key; a chain of several CAs adds `acme-...-rrr1` ...) | the new certificate; older acme trustpoints beyond *keep* removed (`no crypto pki trustpoint`, `crypto key zeroize`) unless still used |
| HTTPS server (WebUI, RESTCONF) | `ip http secure-trustpoint acme-...`, then `no ip http secure-server` / `ip http secure-server` | the HTTPS server restarts: GUI and RESTCONF sessions are cut for a moment; traffic is not affected |
| Save the configuration | `write memory` | without it the trustpoint is gone after a reload |

## Set up the device

### 1. An account for acme

The PKI commands, `ip http ...` are configuration commands: the account needs **privilege 15** (or TACACS+ command authorization allowing only them).

```text
configure terminal
 aaa new-model
 aaa authentication login default local
 aaa authorization exec default local
 username acme privilege 15 algorithm-type scrypt secret <a-strong-password>
end
write memory
```

With TACACS+ (ISE Device Admin) a command set for acme can allow only: `crypto pki *`, `crypto key zeroize *`, `ip http secure-trustpoint *`, `ip http secure-server`, `ip http server`, `show *`, `delete /force bootflash:acme-*`, `write memory` (*uncertain*: Cisco gives no such list for PKI - a general principle).

### 2. SSH key (optional) and SCP

acme signs in with a password or with its SSH key (the key card of the target: *Make a key*, then put its public half on the device). SCP must be on - acme copies the PKCS#12 with it (the old SCP protocol; IOS XE has no SFTP server for this):

```text
configure terminal
 ip ssh version 2
 ip scp server enable
 ip ssh pubkey-chain
  username acme
   key-string
    <the public key of acme, in lines of at most 254 characters>
   exit
  exit
 exit
end
write memory
```

### 3. Time, names, HTTPS

- NTP (`ntp server ...`): with a wrong clock the import of a certificate fails.
- `ip http secure-server` on (it is restarted by acme).
- The certificate's names must be the names the clients use (FQDN of the device).

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **any version (detects it)** |
| Address | the management address of the device, e.g. `sw01.example.com` |
| SSH port / User | `22` / `acme` |
| Sign in with, The SSH key / Password | the key of acme (step 2) or the password |
| Host key (advanced) | the device's known_hosts line; empty with *Trust the first host key seen* takes the first one |
| File system (advanced) | `bootflash:` (or `flash:`) |
| HTTPS port (advanced) | the port of the WebUI (`ip http secure-port`), for the test of what is served |
| HTTPS server (WebUI, RESTCONF) (deploy) | on |
| Save the configuration (write memory) (deploy) | on |
| Previous versions to keep (advanced) | `1` |

## Check it

On the device:

```text
show crypto pki trustpoints status
show crypto pki certificates verbose acme-www.example.com-20261112-a1b2c3d4
show ip http server secure status
show running-config | include ^ip http secure-trustpoint
```

From acme's machine:

```sh
openssl s_client -connect sw01.example.com:443 -servername sw01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| `scp to ...: ...` | SCP refused | `ip scp server enable`; the account needs privilege 15 |
| `... Bad HMAC` / `PKCS12 import failed` | IOS XE does not take this PKCS#12 | before 17.12.1 choose *IOS XE 17.3 - 17.11* (or *any version*) |
| `the device said "% Invalid input ..."` | a command not allowed or not known | privilege 15 / the TACACS+ command set; check the IOS XE version |
| *the module version ... is for IOS XE ...* | the device runs another IOS XE | choose the version named in the message |
| the test of what is served fails right after | the HTTPS server is still restarting | it waits by itself; else `show ip http server secure status` |

*Uncertain*: acme sends the configuration lines to an SSH shell session without a terminal (as Ansible does); `delete /force`, the `yes` answers of `no crypto pki trustpoint` and `crypto key zeroize` are the usual IOS XE words - the clean-up only warns when they fail.

Sources: Cisco TN 213917 (CSR, PKCS#12, web admin and webauth trustpoints on the 9800), TN 221047, the IOS XE 17.x PKI configuration guide, the 9800 configuration guide 26.1 (PKI management), the IOS XE 17.15 programmability guide.
