# Cisco NX-OS (Nexus, NX-API) - setup for acme

acme makes **NX-API** (the HTTPS API of a Nexus 9000) serve the certificate. It copies the certificate with its key and chain as a **PKCS#12** to `bootflash:` with **SCP**, then through NX-API (JSON-RPC, `POST /ins`) creates a trustpoint `acme-<name>-<date>-<serial>`, imports the PKCS#12 into it (`crypto ca import ... pkcs12`), deletes the file, points NX-API at the trustpoint (`nxapi certificate trustpoint`), removes older acme trustpoints beyond *keep* (never the one `show nxapi` names) and saves the configuration last.

## Which NX-OS

**NX-OS 10.2(3)F - 10.6.** `nxapi certificate trustpoint` exists from 10.2(3)F; on an older NX-OS acme refuses before changing anything (there the certificate goes in by hand, as `nxapi certificate httpscrt` / `httpskey` files of at most 8 kB). The calls are the same in 10.2 - 10.6, so there is one module version.

## What acme changes on the Nexus

| Step | NX-OS command | Effect |
|---|---|---|
| copy | SCP to `bootflash:acme-....pfx` | the file, deleted right after the import |
| import | `crypto ca trustpoint acme-...`, `crypto ca import acme-... pkcs12 bootflash:acme-....pfx <one-time password>` | a new trustpoint with the key and certificate |
| save | `copy running-config startup-config` | the trustpoint survives a reload |
| NX-API HTTPS | `nxapi certificate trustpoint acme-...` | NX-API (nginx) restarts: API sessions are cut, the answer may not come back - acme expects that |
| clean-up | `delete certificate force`, `delete ca-certificate`, `no crypto ca trustpoint <older>` | older acme trustpoints beyond *keep*, after NX-API has left them |

`nxapi certificate` lines are **not** in the running configuration: after a `reload ascii` or a config replace NX-API may fall back to its own certificate - deploy again with *force*.

## Set up the Nexus

### 1. NX-API and SCP

```text
configure terminal
 feature nxapi
 nxapi use-vrf management
 feature scp-server
 ip domain-name example.com
 ntp server 192.0.2.123 use-vrf management
end
copy running-config startup-config
```

NX-API listens on HTTPS 443 from 9.2(1) on (HTTP 80 is off). The clock must be right - a certificate outside its validity is refused.

### 2. An account with the least rights

The built-in role `network-admin` can do everything acme needs. A role of its own (*uncertain*: the exact `rule` syntax should be checked in the NX-OS security guide):

```text
configure terminal
 role name acme-pki
  rule 1 permit command configure terminal
  rule 2 permit command crypto *
  rule 3 permit command nxapi certificate *
  rule 4 permit command copy *
  rule 5 permit command delete bootflash:*
  rule 6 permit command show *
 username acme password 0 <a-strong-password> role acme-pki
end
copy running-config startup-config
```

NX-API's JSON-RPC needs the right to `configure terminal`. acme signs in to NX-API (HTTP basic) and to SCP with the same user and password.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the management address of the Nexus, e.g. `n9k01.example.com`, and `443` |
| User / Password | `acme` and its password |
| SSH port (SCP) | `22` |
| Host key (advanced) | the switch's known_hosts line; empty with *Trust the first host key seen* takes the first one |
| Check the device's certificate | on once NX-API serves a certificate of your CA (set *CA certificate* for a private CA); off only while it has its self-signed one |
| NX-API HTTPS (deploy) | on |
| Save the configuration (copy running-config startup-config) (deploy) | on |
| Previous versions to keep (advanced) | `1` |

## Check it

On the switch:

```text
show crypto ca trustpoints
show crypto ca certificates acme-www.example.com-20261112-a1b2c3d4
show nxapi
```

From acme's machine:

```sh
openssl s_client -connect n9k01.example.com:443 -servername n9k01.example.com </dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -u acme -H 'Content-Type: application/json-rpc' -X POST https://n9k01.example.com/ins \
  -d '[{"jsonrpc":"2.0","method":"cli","params":{"cmd":"show version","version":1},"id":1}]'
```

## Common problems

| What acme says | Meaning | Fix |
|---|---|---|
| `scp to ...` | SCP refused | `feature scp-server`; the role must allow it |
| `NX-OS said "% Invalid ..."` | a command refused (rights, syntax) | the role of step 2, or `network-admin` |
| *runs NX-OS 10.2(2)...* | too old for `nxapi certificate trustpoint` | upgrade, or put the certificate there by hand |
| *NX-API restarted before it answered* | expected: NX-API restarts with the new certificate | the test of what is served says whether it took |
| `401` | wrong user or password, or NX-API off | `show nxapi`, the account |

*Uncertain*: the answer of the JSON-RPC batch and `nxos_ver_str` of `show version` are NX-API's usual ones; removing an older trustpoint (`delete certificate force`, `delete ca-certificate`) is NX-OS's usual way - the clean-up only warns when it fails.

Sources: Cisco Nexus 9000 NX-OS Security Configuration Guide 10.6(x) - Configuring PKI; NX-OS Programmability Guide 10.6(x) - NX-API CLI.
