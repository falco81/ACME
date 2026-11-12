# VMware ESXi 8.0 U3 - 9.1 through vCenter - setup for acme

acme replaces the host's **machine SSL certificate** (port 443 - hostd/rhttpproxy, what vCenter and the Host Client see) **through vCenter's vSphere Web Services API** (VI JSON API) - no SSH, no maintenance mode, no restart:

1. `GET /sdk/vim25/<release>/ServiceInstance/ServiceInstance/content` (no sign-in), `POST .../SessionManager/<id>/Login`;
2. reads the host (`HostSystem/<host-id>/summary`: its ESX version) - **an ESXi older than 8.0 U3 is refused before anything changes**;
3. adds the intermediates and the root to **vCenter's trusted roots** (`POST /api/vcenter/certificate-management/vcenter/trusted-root-chains`) - without them vCenter disconnects the host or puts a VMCA certificate back;
4. `HostCertificateManager.ProvisionServerPrivateKey` (the key), `InstallServerCertificate` (the certificate), `NotifyAffectedServices` (open connections keep the old certificate, new ones get the new one).

## Which ESXi this guide is for

| Module version | ESXi | How |
|---|---|---|
| plain - *VMware ESXi host (SSH)* | any | `rui.crt` / `rui.key` over SSH, hostd and vpxa restarted, saved with `/sbin/auto-backup.sh` |
| **ESXi 8.0 U3 - 9.1 (through vCenter)** (`8.0.3`) | 8.0 U3, 9.0, 9.1 | this guide - `ProvisionServerPrivateKey` and `NotifyAffectedServices` exist from API 8.0.3.0 |

A newer ESX than 9.1 is used with a warning. A standalone host (no vCenter) - use the plain version over SSH.

## Set up vCenter

### 1. Certificate mode `custom`

vCenter must not renew the host's certificate by VMCA over acme's: *vSphere Client → vCenter → Configure → Settings → Advanced Settings → Edit Settings*, filter `vpxd.certmgmt`, set **`vpxd.certmgmt.mode` = `custom`** (case-sensitive), *Save*, then on vCenter:

```sh
service-control --restart vpxd
```

### 2. A user with the least rights

The privilege is **Certificates → Manage Certificates** (`Certificate.Manage`) on the vCenter object, propagated. acme also adds the chain to the trusted roots: that needs **Certificate Management → Manage** and **Administer** (`CertificateManagement.Manage`, `CertificateManagement.Administer`) - or turn *Add the chain to vCenter's trusted roots* off and add the root yourself once.

PowerCLI (create the SSO user `svc-esxcert` first: *Administration → Single Sign On → Users and Groups → Add*):

```powershell
Connect-VIServer -Server vcenter.example.local -User administrator@vsphere.local
$priv = Get-VIPrivilege -Id 'Certificate.Manage','CertificateManagement.Manage','CertificateManagement.Administer'
$role = New-VIRole -Name 'acme ESX certificates' -Privilege $priv
New-VIPermission -Entity (Get-Folder -NoRecursion) -Principal 'VSPHERE.LOCAL\svc-esxcert' -Role $role -Propagate:$true
```

### 3. The host's id

acme names the host by its managed object id (`host-12`): it is in the vSphere Client's address when the host is selected, or:

```powershell
(Get-VMHost esx01.example.local).ExtensionData.MoRef.Value
```

### 4. The root CA certificate

Let's Encrypt and most public CAs do not send the root: download it (ISRG Root X1 for Let's Encrypt) and paste it into *Root CA certificate*. Or add it once yourself:

```sh
/usr/lib/vmware-vmafd/bin/dir-cli trustedcert publish --cert /tmp/root.pem --login administrator@vsphere.local
```

## The certificate

- **RSA only**, 2048 - 8192 bits (acme refuses another key before sending anything); FIPS: 2048 or 3072.
- The host's **FQDN in the SAN** - the name it was added to vCenter by; no wildcard.
- Key usage Digital Signature and Key Encipherment; no SHA-1 and no RSASSA-PSS in the chain.

## Fill in acme

| acme field | What to put there |
|---|---|
| Version of the module | **ESXi 8.0 U3 - 9.1 (through vCenter)** |
| vCenter address / HTTPS port | the vCenter's FQDN, `443` |
| User / Password | `svc-esxcert@vsphere.local` and its password |
| ESX host (managed object id) | `host-12` |
| ESX host name | `esx01.example.local` - where acme checks the served certificate; empty: the name vCenter has |
| API release (advanced) | `8.0.3.0` (the vCenter serves it from 8.0 U3, 9.x too) |
| Root CA certificate (deploy) | the root PEM, when the chain does not end in it |
| Add the chain to vCenter's trusted roots (deploy) | on |
| Tell the host's services (deploy, advanced) | on |

## Check it

*Try* signs in, reads the host's version and its certificate manager. After a deployment:

```sh
openssl s_client -connect esx01.example.local:443 -servername esx01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

In the vSphere Client: *host → Configure → System → Certificate*.

## Common problems

| Problem | Fix |
|---|---|
| `the host runs VMware ESXi 8.0.2` | Older than 8.0 U3: choose the plain version (SSH) of the target. |
| `500` / HostConfigFault on installing | The certificate does not match the key, or is refused (SAN, algorithm). acme sends the key first; check the SAN holds the host's FQDN. |
| The host disconnects after the change | The root/intermediates are not in vCenter's TRUSTED_ROOTS: give *Root CA certificate*, keep the chain option on. |
| vCenter puts a VMCA certificate back (KB 454050) | `vpxd.certmgmt.mode` is not `custom`. |
| The task succeeded, the old certificate is still served | Disconnect and Connect the host in vCenter (KB 410036). |
| `404` on `/sdk/vim25/8.0.3.0/...` | vCenter older than 8.0 U3 - update it, or use the plain version. |
