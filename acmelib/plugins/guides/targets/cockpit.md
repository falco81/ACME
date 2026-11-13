# Cockpit web console (Linux, SSH) - setup for acme

Cockpit has no API and no page for its own certificate: it takes the **last file by name** in `/etc/cockpit/ws-certs.d/` - a `.crt` / `.cert` with the certificate and its chain, and beside it a `.key` of the same name (unencrypted). Over SSH acme:

1. uploads the two files to the upload folder (`/tmp`) and installs them, each with **one sudo command**:
   `install -m 0644 -o root -g root … /etc/cockpit/ws-certs.d/90-acme-<name>-<date>-<serial>.crt` and the `.key` with `0600`;
2. runs `cockpit-certificate-ensure --check` (`/usr/libexec/…` on RHEL / Fedora, `/usr/lib/cockpit/…` on Debian / Ubuntu): when Cockpit would take another file, the new files are removed again and the deployment fails - the old certificate keeps being served;
3. when asked, adds the certificate's CA certificates to the **system trust store** (below);
4. `systemctl restart cockpit.service` (open Cockpit sessions sign out; the system's services are not touched) - without it cockpit-tls takes the new file the next time it starts (it stops after 90 s idle);
5. deletes older acme files beyond *Previous versions to keep*.

A new file each time (not overwritten), so a failure never leaves Cockpit without a working certificate.

## Which versions

Cockpit with `/etc/cockpit/ws-certs.d` and a separate `.key` (Cockpit Guide, Cockpit 371; RHEL 8, 9, 10 web console, Fedora, Debian 13, Ubuntu 24.04, SLES / openSUSE). One module.

## What you need

- Cockpit installed and on: `dnf install cockpit` or `apt install cockpit`, `systemctl enable --now cockpit.socket`; the firewall open for port **9090** (`firewall-cmd --add-service=cockpit --permanent; firewall-cmd --reload`).
- A certificate with the FQDN (and the IP) users open Cockpit by. The system crypto policy applies (RHEL DEFAULT: RSA at least 2048).
- An account for acme with **sudo for exactly these commands** - no shell through sudo:

```sh
useradd -r -m -s /bin/bash svc-cert
cat > /etc/sudoers.d/svc-cert <<'EOF'
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/bin/install -m 0600 -o root -g root /tmp/acme-* /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/bin/rm -f /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/libexec/cockpit-certificate-ensure --check, \
                              /usr/bin/systemctl restart cockpit.service
EOF
visudo -cf /etc/sudoers.d/svc-cert
```

On Debian / Ubuntu the check is `/usr/lib/cockpit/cockpit-certificate-ensure --check`. With *Add its CA certificates to the system trust store* on, add the store's lines too:

```text
# RHEL, Fedora
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/pki/ca-trust/source/anchors/acme-ca-*, /usr/bin/update-ca-trust extract
# Debian, Ubuntu
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /usr/local/share/ca-certificates/acme-ca-*, /usr/sbin/update-ca-certificates
# SLES, openSUSE
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/pki/trust/anchors/acme-ca-*, /usr/sbin/update-ca-certificates
```

The sudoers lines are a proposal (no source gives one); check `sudo -l -U svc-cert`. Signing in as `root` (without *Use sudo*) works too. RHEL 8 with SELinux: acme writes with `install` as root, no `semanage` change is needed (that is for certmonger writing the folder itself).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | the server, `22`, `svc-cert` |
| Sign in with / The SSH key | a key made in acme |
| Use sudo | on (off when signing in as root); *sudo password* empty with `NOPASSWD` |
| Cockpit port | `9090` (what acme checks) |
| Folder for uploads (advanced) | `/tmp` - the sudoers lines name it |
| File name prefix (deployment, advanced) | `90` - higher than `10-ipa.cert` and other files there |
| Restart cockpit.service (deployment) | on |
| Add its CA certificates to the system trust store (deployment) | on for a certificate of your own CA that the server itself should trust |

## Check it

```sh
openssl s_client -connect server01.example.com:9090 -servername server01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
sudo /usr/libexec/cockpit-certificate-ensure --check
ls -l /etc/cockpit/ws-certs.d/
trust list --filter=ca-anchors | grep -i -A2 "Example CA"
```

## Common problems

| What you see | Why | What to do |
|---|---|---|
| *Cockpit would not use the new certificate (it takes 99-….crt)* | a file sorting later wins | raise *File name prefix* (e.g. `99`) or remove that file |
| `sudo: a password is required` | the sudoers line does not match the command | compare with the job's command; the prefix and the upload folder must match |
| the old certificate is still shown | *Restart cockpit.service* is off | wait until cockpit-tls restarts (90 s idle), or turn it on |
| `update-ca-certificates` ignores the file | Debian wants `.crt`, one certificate a file | acme writes `acme-ca-<id>.crt`, one each |
| RHEL 7 / 8: the distrust folder | `blacklist` there, `blocklist` from RHEL 9 | acme only adds anchors |

Sources: Cockpit Guide *SSL/TLS Usage*, `cockpit-tls(8)`, `update-ca-trust(8)` (Fedora ca-certificates), `update-ca-certificates(8)` (Debian trixie), Linux System Roles `certificate`.
