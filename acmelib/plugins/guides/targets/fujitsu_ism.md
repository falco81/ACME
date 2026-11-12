# Fujitsu Infrastructure Manager (ISM-VA) - setup for acme

acme replaces the **HTTPS certificate of an Infrastructure Manager virtual appliance** (ISM,
formerly ServerView Infrastructure Manager; ISM for PRIMEFLEX) - the GUI and REST API on port
**25566** - the way the ISM User's Guide (4.7.1) does it:

```text
FTP  ism-va:21   put acme-<serial>.key and acme-<serial>.crt into /Administrator/ftp
SSH  ism-va:22   ismadm sslcert set -key /Administrator/ftp/acme-<serial>.key -crt /Administrator/ftp/acme-<serial>.crt
FTP              delete both files again (the key does not stay there)
SSH              ismadm power restart
```

**The ISM-VA restarts:** GUI, REST API, monitoring and scheduled tasks are away for several
minutes - finish running jobs (firmware updates, profiles) first. The managed servers are not
touched. Clients that pin the ISM's certificate (Ansible `ism-ansible`'s `certificate` file,
vCenter / SCVMM plug-ins) need the new CA.

**Which versions:** ISM 2.x (checked against V2.9.0) and 3.x (V3.1.0) - the same `ismadm`
commands. The ISM-VA has **no FTPS** ("You cannot use the FTPS protocol") - the key travels
over plain FTP on the management network; acme deletes it at once. The REST API is not used: it
needs the password encrypted with AES, which acme's Python cannot do.

## What you need

- From acme to the ISM-VA: **TCP 21** (FTP, with passive data ports), **TCP 22** (SSH console),
  **TCP 25566** (the check of what is served).
- An ISM user in the **Administrator** user group with the **Administrator** role - only such a
  user (or one of a group with "Manage all nodes") may use the console. There is no narrower
  right for this.

## Set up the ISM

1. In the ISM GUI: **Settings → Users → Add**: user `svc-cert`, user group *Administrator*, role
   *Administrator*. Use it only for this; it cannot be linked to AD/LDAP if you use the built-in
   `administrator`.
2. Check the console and the FTP area with that user:

   ```sh
   ssh svc-cert@ism.example.local
   ```

   ```text
   # ismadm sslcert show
   ```

   ```text
   $ ftp ism.example.local
   Name: svc-cert
   ftp> cd Administrator
   ftp> cd ftp
   ftp> ls
   ```
3. Allow the acme server through any firewall in front of the ISM-VA (FTP, SSH).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The ISM-VA, e.g. `ism.example.local` |
| User / Password | `svc-cert` (used for both the console and the FTP area) |
| User group (advanced) | `Administrator` - the files go to `/<group>/ftp` |
| SSH port / FTP port (advanced) | `22` / `21` |
| HTTPS port of the GUI (advanced) | `25566` |
| Host key (advanced) | The ISM-VA's SSH key line, or leave *Trust the first host key seen* on |
| Send the chain with the certificate (deploy) | On: the `.crt` holds the certificate and the intermediates; off if this ISM refuses it |
| Restart the ISM-VA afterwards (deploy) | On (the certificate is served only after `ismadm power restart`) |
| Check what is served | Empty: acme checks `ism.example.local:25566` after the restart |

## Check it

- **Try** logs in to the FTP area (lists it) and runs `ismadm sslcert show` - nothing is changed.
- After the restart:

  ```sh
  openssl s_client -connect ism.example.local:25566 -servername ism.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

## Common problems

| Problem | Fix |
|---|---|
| `did not let … in` on FTP | Wrong password, or the user is not in the group whose `ftp` folder is used. |
| `ismadm said …` on `sslcert set` | Key and certificate are no pair, or the chain is refused: turn off *Send the chain with the certificate*. |
| Console refused | The user lacks the Administrator role in the Administrator group (or "Manage all nodes"). |
| With MFA on, SSH asks a code | SSH with multi-factor authentication is keyboard-interactive: use a user without MFA for acme. |
| ISM back with the self-signed certificate | After an IP/FQDN change `ismadm sslcert self-create` was run - deploy again (force). |
