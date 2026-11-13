# VMware NSX Manager (its own certificate) - setup for acme

acme puts the certificate on **NSX Manager itself** - the UI/API of the manager nodes and the cluster's virtual IP - through the **NSX Manager API** (MP API, HTTP basic authentication). For the load balancer's virtual servers use the other target, *VMware NSX load balancer (Policy API)* (`nsx`).

1. `GET /api/v1/trust-management/certificates` - imported already (same name)? then not again;
2. `POST /api/v1/trust-management/certificates?action=import` with `display_name` (`acme-<name>-<date>-<serial>`), `pem_encoded` (leaf → intermediates → root, no empty lines) and `private_key` - a platform certificate, **not** a service certificate;
3. `GET .../certificates/<id>?action=validate&usage=SERVER` - anything but `"status": "OK"` stops it before it is applied;
4. `POST .../certificates/<id>?action=apply_certificate&service_type=API&node_id=<uuid>` for each node listed, then `...&service_type=MGMT_CLUSTER` for the virtual IP;
5. older acme certificates beyond *keep* deleted - only those whose `used_by` is empty.

Applying restarts the HTTPS service of the node (tens of seconds; the browser must be reloaded). acme applies one after another and asks again a few times while the node's web service comes back.

## Which NSX this guide is for

NSX **4.2.x and 9.0 / 9.1** (VCF 9) - the same calls (one module). From 4.2 the nodes' API certificate and the VIP's are by default one shared certificate: give it both (the SAN must then name the VIP and every node). In **VCF 9**, NSX certificates are managed by VCF Operations (*Fleet management → Certificates → VCF Instances*): a certificate replaced here is shown as externally managed, and the root must be in SDDC Manager's trust store (the `sddc_manager` target).

## Set up NSX

1. A user with the right to manage certificates. The RBAC matrix gives **Enterprise Admin** and **Security Admin** (`security_engineer`) full access to *System → Certificates*; the documents say "admin privileges" for applying - try Security Admin, else use Enterprise Admin. A local user (NSX 4.1.1+):

   ```sh
   curl -k -u 'admin:<password>' -X POST "https://nsx-mgr01.example.local/api/v1/node/users?action=create_user" \
     -H "Content-Type: application/json" \
     -d '{"username": "svc-acme", "full_name": "acme certificates", "password": "<strong password>", "password_change_frequency": 90}'
   curl -k -u 'admin:<password>' -X POST "https://nsx-mgr01.example.local/api/v1/aaa/role-bindings" \
     -H "Content-Type: application/json" \
     -d '{"name": "svc-acme", "type": "local_user", "roles_for_paths": [{"path": "/", "roles": [{"role": "security_engineer"}]}]}'
   ```

   An LDAP user or group: *System → User Management → User Role Assignment → Add → Role Assignment for LDAP*, role *Security Admin*. In VCF 9 the local users follow VCF Operations' password policy.

2. For the virtual IP: a VIP must be set (*System → Appliances → Set Virtual IP*) - a CA-signed certificate on `MGMT_CLUSTER` is refused without one.
3. The node UUIDs: *System → Appliances → NSX Manager → View Details*, or on a node as `admin`:

   ```text
   get cluster status
   ```

4. Point acme at **a node's own address**, not the VIP (the VIP may move while it changes).

## The certificate

- CN/SAN: the VIP's FQDN (and IP) **and** every node's when shared; Basic Constraints `CA:FALSE`.
- RSA 2048 or more (EC is taken too); every certificate of the chain with a supported signature (no SHA-1, KB 380830).
- The private key goes with it (KB 400892).

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | a manager node, e.g. `nsx-mgr01.example.local`, `443` |
| User / Password | `svc-acme` (or `admin`) and its password |
| The cluster's virtual IP (MGMT_CLUSTER) (deploy) | on, to give the VIP the certificate |
| Manager nodes (API) (deploy) | one node UUID a line - the nodes whose own UI/API takes it |
| Root CA certificate (deploy, advanced) | the root, when the chain does not end in it |
| Previous versions to keep (advanced) | `1` - older acme ones still used are never deleted |
| Check what is served | `nsx.example.local:443` (the VIP), and the nodes |

## Check it

*Try* lists the certificates. After a deployment:

```sh
for n in nsx-mgr01 nsx-mgr02 nsx-mgr03; do echo | openssl s_client -connect $n.example.local:443 2>/dev/null | openssl x509 -noout -subject -enddate; done
```

On a node (NSX CLI): `get certificate api` and `get certificate cluster`; in the UI *System → Certificates* (column *Used By*).

## Common problems

| Problem | Fix |
|---|---|
| validate says the chain does not verify (KB 415779) | Give the root in *Root CA certificate*, or import the root as a CA certificate in NSX. |
| "Certificate data is missing the private key" (KB 400892) | A certificate imported without a key - acme always sends it; delete a hand-made one of the same name. |
| No *Apply Certificate* in the UI (KB 416689) | It was imported as a service certificate (Policy API) - acme's MP import is not. |
| `403` on apply | Security Admin is not enough on this version: use Enterprise Admin. |
| VIP refused | No virtual IP set on the cluster. |
| Federation: GM loses the LM | Update the Local Manager's thumbprint on the Global Manager (*System → Location Manager*). |
| VCF: "Private key does not match" in VCF Operations (KB 449554) | VCF expects one certificate per component - run an inventory sync after the change. |
