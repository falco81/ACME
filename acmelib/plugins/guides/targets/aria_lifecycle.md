# VMware Aria Suite Lifecycle (product certificates) - setup for acme

acme puts the certificate on **Aria products through Aria Suite Lifecycle 8.18** - the documented way for Aria Operations (its web certificate is set only in its Admin UI), Aria Operations for Logs (only in its UI), Aria Automation / Orchestrator and Workspace ONE Access. Suite Lifecycle's *Replace Certificate* also makes the other products trust the new certificate (*Retrust*) and can take a snapshot.

1. `GET /lcm/locker/api/v2/certificates` - in the Locker already (same alias)? then not imported again;
2. `POST /lcm/locker/api/v2/certificates/import` with `alias` (`acme-<name>-<date>-<serial>`), `certificateChain` (leaf → intermediates → root), `privateKey`, `passphrase` "";
3. for each product line: `POST .../environments/<env>/products/<product>/certificates/<vmid>/pre-validate`, then `PUT .../environments/<env>/products/<product>/certificates/<vmid>` - a request;
4. `GET /lcm/request/api/v2/requests/<requestId>` every 30 s until it is `COMPLETED` (a `FAILED` request stops the deployment);
5. older acme certificates beyond *keep* deleted from the Locker (one still used is refused and kept).

Authentication: HTTP basic (`admin@local`, or a Certificate Administrator).

## Which versions this guide is for

Aria Suite Lifecycle **8.18** (Aria Suite 8.18, standalone or in VCF 5.x). In **VCF 9** the products are VCF management components managed by VCF Operations (*Fleet management → Certificates*), which takes only certificates for its own CSRs - not this target.

## Set up Suite Lifecycle

1. **A user**: `admin@local`, or - least rights - a Workspace ONE Access user (e.g. AD `svc-aria-cert`) with **only** the role **Certificate Administrator**: *Lifecycle Operations → User Management → ADD USER/GROUP → the user → Next → Certificate Administrator → Next → Submit* (a user with another role mapped before cannot take it).
2. **The environment and product ids**: *Lifecycle Operations → Environments → the environment → View Details* - the environment id is in the address; the products are `vrops` (Aria Operations), `vra` (Automation), `vrli` (Operations for Logs), `vidm` (Workspace ONE Access, environment `globalenvironment`), `vro` ... Or:

   ```sh
   curl -sk -u 'admin@local:<password>' https://lcm.example.local/lcm/lcops/api/v2/environments
   ```

3. **Snapshots**: *Opt-in for Snapshot* is in the UI wizard; through the API take them yourself before the first run (Operations for Logs clusters: non-memory snapshots).
4. **Load balancers** in front of a product are not updated by Suite Lifecycle (KB 424473) - change them yourself.

## The certificate

- RSA 2048 or 4096; SAN with every node's FQDN **and** the load balancer's (Aria Automation: the node IPs too, no wildcard - KB 325876, KB 420444).
- Operations for Logs: the CA must allow *SSL Client* too (KB 442507).
- The Locker refuses a certificate that expires within 15 days.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | Suite Lifecycle's FQDN, `443` |
| User / Password | `admin@local` (or the Certificate Administrator) and its password |
| Products (deploy) | one a line: `<environment id> <product id>`, e.g. `8a2b...e1 vrops`; empty: only into the Locker |
| Root CA certificate (deploy, advanced) | the root, when the chain does not end in it |
| Pre-validate first (deploy, advanced) | on |
| Wait for each request (minutes) (deploy, advanced) | `60`; `0`: start the request and go on |
| Previous versions to keep (advanced) | `1` |
| Check what is served | the product's address, e.g. `vrops.example.local:443` |

## Check it

*Try* lists the Locker. The requests: *Lifecycle Operations → Requests*; a product's certificate:

```sh
curl -sk -u 'admin@local:<password>' https://lcm.example.local/lcm/lcops/api/v2/environments/<env>/products/vrops/certificates
openssl s_client -connect vrops.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

## Suite Lifecycle's own certificate

It is two files and nginx (techdocs 8.18 "Replace your custom Lifecycle certificate") - use acme's **SSH** target with these files and this command:

```text
cert-pem /opt/vmware/vlcm/cert/server.crt 0644
key-pem  /opt/vmware/vlcm/cert/server.key 0600
```

```sh
systemctl restart nginx
```

## Common problems

| Problem | Fix |
|---|---|
| "Failed to parse private key" (KB 408525) | The key missing or encrypted - acme sends it unencrypted; check nothing changed it. |
| Validation of the chain fails (KB 430787) | Give *Root CA certificate*: the chain must be complete and in order. |
| A request FAILED (LCMCOMMON80066, LCMVRLISYSTEM45038 ...) | Read it in *Requests*; for Operations for Logs a new Locker certificate often helps (KB 411526). |
| An expired certificate cannot be replaced (KB 411526) | Put a valid one by hand first (Aria Operations: KB 326393). |
| `the product line ... is "<environment id> <product id>"` | Two words a line. |
