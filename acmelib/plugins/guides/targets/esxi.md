# VMware ESXi host - setup for acme

acme signs in to the ESXi host over **SSH**, writes the host certificate to
`/etc/vmware/ssl/rui.crt` (full chain) and `/etc/vmware/ssl/rui.key`, then restarts
`hostd` and `vpxa` (or every service) so the Host Client and vCenter see it. If the
restart fails, the old files are put back and the services restarted again. When both
files already hold exactly this certificate, nothing is changed.

For ESXi 6.7, 7.0 and 8.0. **ESXi before 8.0 takes RSA keys only** - choose an RSA key
type for the certificate.

## What you need

- SSH from acme to the host (TCP 22), with SSH enabled on the host.
- The **root** account (or another administrator who may write `/etc/vmware/ssl` and
  restart services).
- **If the host is managed by vCenter** in the default VMCA mode, vCenter renews the host
  certificate and overwrites acme's: set vCenter's `vpxd.certmgmt.mode` to `custom` (or
  `thumbprint`) first.
- A certificate whose names include the host's name as vCenter and browsers reach it.

## Set up the ESXi host

1. Enable SSH: **Host Client → Host → Actions → Services → Enable Secure Shell (SSH)**,
   and set its policy to *Start and stop with host* (**Manage → Services → TSM-SSH**) so
   it survives a reboot. Or with vCenter: *host → Configure → System → Services → SSH*.
2. Add acme's public key for root (key login avoids password lockout):

   ```sh
   cat >> /etc/ssh/keys-root/authorized_keys <<'EOF'
   ssh-ed25519 AAAA... acme
   EOF
   ```

3. Only if vCenter manages the host: **vCenter → Configure → Settings → Advanced
   Settings → Edit**, `vpxd.certmgmt.mode` = `custom`, then restart the vCenter service
   (vpxd) as Broadcom describes.
4. If the host's lockdown mode is on, add root (or acme's user) to the *Exception Users*,
   or SSH sign-in is refused.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The host's name or IP, e.g. `esxi01.example.local` |
| SSH port / User | `22` / `root` |
| Sign in with / The SSH key / Password | A key made in acme (recommended) or root's password |
| Host key / Trust the first host key seen (advanced) | The host's SSH key, or trust the first one |
| Timeout (s) (advanced) | Default 30 |
| Restart (deploy) | `hostd and vpxa` (default), `every service (services.sh restart)`, or `nothing (done by hand)` |
| Leave a file alone when it is the same / Keep a copy of a file replaced | File handling of `rui.crt` / `rui.key` |
| Check what is served | Default: the host on port 443 |

## Check it

- **Try** runs `vmware -v`: `signed in as root: VMware ESXi 8.0.x build-...`.
- On the host:

  ```sh
  openssl x509 -in /etc/vmware/ssl/rui.crt -noout -subject -enddate
  /etc/init.d/hostd status
  ```

## Common problems

| Problem | Fix |
|---|---|
| Connection refused on 22 | SSH is not enabled on the host (or it was stopped at reboot) |
| Permission denied | Wrong key/password; lockdown mode without an exception user |
| `"/etc/init.d/hostd restart ..." failed, the previous certificate is back` | Often a key the host does not take (EC on ESXi before 8.0) - use RSA |
| vCenter shows the host disconnected | After a new certificate vCenter may ask to accept it - reconnect the host |
| Certificate replaced again by vCenter | `vpxd.certmgmt.mode` is still `vmca` - set it to `custom` |
| Host Client shows the old certificate | Wait a minute for hostd, reload the page |
