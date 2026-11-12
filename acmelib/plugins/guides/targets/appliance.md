# This acme server - setup for acme

acme makes a certificate it manages the certificate of **its own pages** - each node's,
the VIP address's, or both - just as **Settings → Certificates and TLS** would take an
uploaded one. Every node puts it into nginx within seconds; the VIP's certificate is
served by whichever node holds the address. A renewal deploys it again by itself, so the
pages are renewed on every node. From then on the engine's own ACME (**Settings →
Automatic certificates**) leaves those pages alone. The TLS settings of the pages
(protocols, ciphers, DH, HSTS) stay as they are.

For this acme appliance, a single node or a cluster.

## What you need

- A certificate in acme that holds the **names the pages are reached by**: each node's
  own name and, in a cluster with a VIP address, the VIP's name (a SAN certificate
  covering all, or one certificate per page).
- Its private key kept in acme (a certificate without a key cannot be deployed).
- In a cluster: the nodes' names and the VIP address as set in **Settings → High
  availability**.

## Set up acme's pages

There is nothing to sign in to - the target has no settings.

1. Look up the names: **Settings → High availability** shows each node's name and the
   VIP address's name.
2. Create (or pick) a certificate in **Certificates** whose names include those names,
   and let it be issued.
3. Add the target **This acme server (its pages)** in **Targets**, then a deployment of the
   certificate to it.
4. Note that a certificate uploaded by hand or the automatic ACME of the pages stops
   being used for the pages acme deploys to.

## Fill in acme

| acme field | What to put there |
|---|---|
| Which pages (deploy) | `auto` - every node and the VIP address in a cluster that has one; `nodes` - every node's own pages; `this` - the node that deploys; `vip` - the VIP address only; `list` - the ones named below |
| Nodes (or vip) (deploy) | With `list`: one a line, a node's name as the cluster knows it, or `vip` |
| The certificate must hold the names (deploy, advanced) | On: refuse the certificate when a node's or the VIP's name is not among its names (a browser would refuse it there) |

Command line example:

```sh
acme --target-add pages --kind appliance
acme --deploy-add acme-pages pages --set where=auto
```

## Check it

- **Try** on the target says which node this is, the nodes and the VIP address, and which
  certificate each page holds now (`acme1: www.example.com, put in`).
- After a deployment open each node's pages and the VIP address in a browser, or:

  ```sh
  openssl s_client -connect acme1.example.com:443 -servername acme1.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Common problems

| Problem | Fix |
|---|---|
| `there is no VIP address here` | `vip` chosen but no VIP address is set in Settings → High availability |
| `not a node of this cluster (nor vip)` | A name in *Nodes* is not a node's name as the cluster knows it - use the names Try shows |
| The certificate is refused for missing names | Add the node's / VIP's names to the certificate, or turn off *The certificate must hold the names* (not recommended) |
| The other node still shows the old certificate | Give it a few seconds; check the node is up and the cluster database is replicating |
| A dual certificate | The twin becomes the pages' second certificate on every node / the VIP; both are checked |
