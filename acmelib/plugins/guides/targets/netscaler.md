# NetScaler / Citrix ADC - setup for acme

acme deploys certificates to NetScaler (Citrix ADC) through the **NITRO REST API**:

1. signs in (`login`, session cookie `NITRO_AUTH_TOKEN`);
2. uploads `acme-<name>-<date>-<serial>.crt` and `.key` to `/nsconfig/ssl` (`systemfile`);
3. **updates the certkey in place** (default name `acme-<certificate name>`, kept across renewals, `update … -noDomainCheck`) so its bindings stay - or adds it the first time;
4. adds each intermediate as a certkey `acme-ca-<id>` and links the certificate up the chain;
5. binds the certkey to the SSL virtual servers you list (optionally as an SNI certificate);
6. saves the configuration (`save ns config`), deletes older acme files beyond *keep* and signs out.

An HA pair syncs the files and the configuration by itself.

## What you need

- NetScaler / Citrix ADC 12.1 or later (EC keys need 12.1+; RSA works on every release).
- HTTPS access from acme to the NSIP (or a SNIP with management access), port 443.
- A system user with a command policy allowing the commands above - or the built-in `superuser` policy.

## Set up NetScaler

On the NetScaler CLI (SSH to the NSIP as `nsroot`):

```text
add system cmdPolicy acme_certs ALLOW "(^show\s+ns\s+version)|(^(show|add|rm)\s+system\s+file)|(^(show|add|update|link|unlink)\s+ssl\s+certKey)|(^(show|bind)\s+ssl\s+vserver)|(^save\s+ns\s+config)"
add system user acme -timeout 900
bind system user acme acme_certs 100
save ns config
```

`add system user acme` asks for the password. Check the policy with a first deployment - if a step is refused, the job names the NITRO call; widen the regular expression for that command only. **Do not use `nsroot` for acme.**

In the GUI the same is **System → User Administration → Command Policies** (add `acme_certs`) and **System → User Administration → Users** (add `acme`, bind the policy).

Optionally restrict management access to the acme server (e.g. with an ACL on the NSIP or `set ns ip <NSIP> -mgmtAccess ENABLED -restrictAccess ENABLED` as your setup requires).

Note the names of the SSL virtual servers (**Traffic Management → Load Balancing / Content Switching → Virtual Servers**, protocol SSL).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the NSIP (or a management SNIP) |
| HTTPS port | 443 |
| User / Password | `acme` and its password |
| Check the device's certificate | on; off only while the management interface has the default self-signed certificate |
| CA certificate (advanced) | the CA of the NetScaler's management certificate, when not public |
| Certkey name (deployment) | the certkey kept across renewals, e.g. `www`; empty: `acme-<certificate name>` |
| SSL virtual servers (deployment) | one a line, e.g. `vs_www_ssl`; `vs_portal sni` binds it as an SNI certificate |
| Key as (advanced) | traditional RSA (default, works everywhere; EC keys go as PKCS#8), or PKCS#8 |
| Previous versions to keep | older acme files kept in `/nsconfig/ssl` |
| Check what is served | `vip.example.com:443`, one a line |

To take over an existing certkey (with all its bindings), put its name in *Certkey name* - acme updates it in place.

## Check it

- **Test** in acme signs in and reads `nsversion`.
- On the NetScaler:

```text
show ssl certKey www
show ssl vserver vs_www_ssl
shell ls -l /nsconfig/ssl | grep acme-
```

## Common problems

| Problem | Fix |
|---|---|
| `the NetScaler gave no session on signing in` / 401 | wrong user/password, or the user is external-auth only |
| `…: Not authorized to execute this command` | the command policy misses that command; widen it for that command |
| `there is no SSL virtual server …` | the name must match exactly (case too) |
| Update refused with a key error | try *Key as* PKCS#8 (or traditional RSA on old releases) |
| Clients miss the intermediate | the link failed - check `show ssl certKey <name>` for *Linked to* |
| Configuration lost after reboot | `save ns config` refused - allow `save ns config` in the policy |
