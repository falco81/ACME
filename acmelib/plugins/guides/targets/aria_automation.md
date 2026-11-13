# VMware Aria Automation / Orchestrator (vracli) - setup for acme

acme sets the **ingress certificate** of Aria Automation or Automation Orchestrator 8.18 (the UI and API on 443) with `vracli` over **SSH as root**:

1. `vracli certificate ingress --list` - this certificate there already: nothing done;
2. writes `/root/acme-ingress-<random>.pem` (0600): **the RSA private key, the certificate, the intermediates, the root** - each block on lines of its own (KB 325876, KB 423843);
3. `vracli certificate ingress --validate stdin --parse < the file` - a refusal stops it before anything changes;
4. `vracli certificate ingress --set <the file>`;
5. **`/opt/scripts/deploy.sh`** - every service of every node redeployed: **the product is away for tens of minutes**;
6. the file removed, whatever happened.

In a cluster one node is enough: `deploy.sh` applies it to all.

## Which versions this guide is for

Aria Automation and Automation Orchestrator (standalone too) **8.18.x**. Managed by **Aria Suite Lifecycle**? Prefer the `aria_lifecycle` target: its *Replace Certificate* makes the other products trust the new certificate. **VCF Automation 9.x** is managed by VCF Operations (fleet management), which takes only its own CSRs - not this target.

## Set up the appliance

1. SSH as **root** is on by default on the appliance. Put acme's public key (the key card in acme) into `/root/.ssh/authorized_keys`, or use the root password.
2. Try it by hand once:

   ```sh
   ssh root@vra01.example.local 'vracli certificate ingress --list | openssl x509 -noout -subject -dates'
   ```

3. Plan the deployments in a **maintenance window**: `deploy.sh` stops and starts every service. Take a snapshot first.
4. Behind a load balancer that terminates TLS, change its certificate too (Suite Lifecycle does not).

## The certificate

- **RSA** key (acme refuses another before connecting).
- SAN: **every node's FQDN and IP and the load balancer's FQDN**; **no wildcard** (KB 325876; the precheck fails without the nodes, KB 420444).
- The root at the end of the PEM: give *Root CA certificate* when the chain does not end in it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | a node, e.g. `vra01.example.local` |
| SSH port / User | `22`, `root` |
| Sign in with / The SSH key / Password | a key (made in acme) or the root password |
| Root CA certificate (deploy) | the root PEM (ISRG Root X1 for Let's Encrypt) |
| Run /opt/scripts/deploy.sh (deploy) | on; off: run it yourself later - the certificate is used only after it |
| Wait for deploy.sh (minutes) (deploy, advanced) | `90` |
| Check what is served | `vra.example.local:443` (the load balancer) and the nodes |

## Check it

*Try* signs in and says whether an ingress certificate is set. After a deployment:

```sh
vracli certificate ingress --list | openssl x509 -noout -subject -dates
openssl s_client -connect vra.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

## Common problems

| Problem | Fix |
|---|---|
| `vracli does not take the certificate` | Read vracli's words in the job: a wrong SAN, the chain incomplete (give the root). |
| it asks for `--sha256` (KB 423843) | The PEM's blocks are not on lines of their own - acme writes them so; report it. |
| `deploy.sh` failed or is slow | acme's job has its last output; run it again by hand on the node to see it all. A standalone Orchestrator 8.18.1 with a custom certificate: KB 384243. |
| Other products lost trust | Use the `aria_lifecycle` target (Retrust), or update the trust in each product by hand. |
