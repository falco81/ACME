# Nutanix cluster (Prism Central 7.3 - 7.5, v4.4 API) - setup for acme

This version of the Nutanix target is for **Prism Central 7.3 - 7.5** managing **AOS 7.x** clusters. It replaces the SSL certificate of a cluster (its Prism Element web console and API, port 9440) through Prism Central's **v4.4** API - the path of Nutanix's official SDK 4.4.1 - and signs in with the **API key of a Prism Central service account** (`X-ntnx-api-key`) or a user:

1. `GET /api/clustermgmt/v4.4/config/clusters/<extId>/ssl-certificate` - for its `ETag`;
2. `PUT` the same path with `If-Match: <ETag>`, a new `NTNX-Request-Id` and `{"privateKeyAlgorithm", "privateKey", "publicCertificate", "caChain"}` - each the base64 of the PEM file;
3. waits for the task: `GET /api/prism/v4.4/config/tasks/<taskExtId>` until `SUCCEEDED`.

The cluster's web console restarts with the new certificate; open browser sessions must reload. Storage, VM I/O and the data path are not touched. A cluster keeps **one** certificate - the new one replaces the old.

## What differs from the plain version

| | plain (any v4) | this version |
|---|---|---|
| API version | `v4.3` by default | `v4.4` by default (`v4.0` - `v4.3` can be chosen) |
| Sign-in | a user (HTTP basic) | a service account's API key, or a user |
| Key types | ECDSA P-256 / P-384 / P-521, RSA 2048 / 4096 | AOS 7.5's: **RSA 2048, RSA 4096, ECDSA P-256, ECDSA P-384** - P-521 is refused before anything is sent (AOS 7.5 `ncli` no longer has `ECDSA_521`) |

*Uncertain*: from which Prism Central the v4.4 API is served - if `v4.4` answers 404, choose `v4.3`. acme does not read the Prism Central version (no documented call), so it refuses nothing by it.

## What you need

- Prism Central reachable from acme on **9440**.
- A certificate in PEM with an **unencrypted** key; the chain only intermediates and the root (acme sends it so); no SHA-1. A Prism Central older than pc.2024.3 may have trouble with RSA 4096 (KB 12775).

## A service account and its API key

In Prism Central: *Admin Center > IAM > Identities > Service Accounts > + Add New Service Account*, then *Save and Create Keys > + Add New Key*, type **API Key**, an expiry, *Generate Key* - copy the key now, it is not shown again. Give the account the role **Cluster Admin** through *Admin Center > IAM > Authorization Policies*, limited to the clusters acme deploys to.

A user instead: a Prism Central user with *Cluster Admin*, *Prism Admin* or *Super Admin*.

Check the key from acme's machine:

```sh
curl -sS -H "X-ntnx-api-key: $KEY" "https://pc.example.local:9440/api/clustermgmt/v4.4/config/clusters?\$select=extId,name"
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Module version | **Prism Central 7.3 - 7.5 (v4.4 API)** |
| Address / HTTPS port | Prism Central, `9440` |
| Sign in with | *a service account's API key* (or *a user and password*) |
| API key | the key from *Generate Key* |
| Cluster | the cluster's extId or name - *Load the list* fills it in |
| API version (advanced) | `v4.4` |
| Key algorithm (deployment, advanced) | *as the certificate's key*, or the type when acme cannot tell the key's size |
| Check what is served | the cluster's virtual IP / FQDN, e.g. `prism01.example.com:9440` |

## Check it

```sh
openssl s_client -connect prism01.example.com:9440 -servername prism01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -sS -H "X-ntnx-api-key: $KEY" "https://pc.example.local:9440/api/clustermgmt/v4.4/config/clusters/<extId>/ssl-certificate"
```

In Prism Element: the gear icon → *SSL Certificate*.

## Common problems

| What you see | Why | What to do |
|---|---|---|
| `401` | a wrong or expired API key | generate a new key |
| `403` | the service account has no Cluster Admin on that cluster | add the cluster to its authorization policy |
| `404` on `/v4.4/` | Prism Central does not serve v4.4 | choose `v4.3` in *API version* |
| *AOS 7.x takes ... not ECDSA_521* | a P-521 key | issue the certificate with RSA or P-256 / P-384 |
| the task fails, the default certificate is back | Prism discarded an invalid certificate | check the key type and the chain (no server certificate in it) |
| backup software (Veeam, HYCU) loses trust | it pinned the old certificate | accept the new one there |

Sources: Nutanix Security Guide 7.5 (*SSL Certificate Management*, *Supported Key Configurations*, *Configuring a Service Account in Prism Central*), Command Reference AOS 7.5 `ncli ssl-certificate`, the official Python SDK `ntnx-clustermgmt-py-client` 4.4.1, Ansible `nutanix.ncp.ntnx_ssl_certificates_v2`.
