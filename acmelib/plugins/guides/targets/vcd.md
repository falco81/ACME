# VMware Cloud Director (cell certificate) - setup for acme

acme gives the **HTTP endpoint of the Cloud Director cells** (provider and tenant portals, the API, the console proxy - all on 443) its certificate through the **VCD OpenAPI** (`/cloudapi/1.0.0`):

1. `POST /cloudapi/1.0.0/sessions/provider` (basic, `user@System`) - the token comes in the header `X-VMWARE-VCLOUD-ACCESS-TOKEN`, sent back as `Authorization: Bearer`;
2. `POST /cloudapi/1.0.0/ssl/certificateLibrary` - into the **Certificates Library** with `alias` (`acme-<name>-<date>-<serial>`), `certificate` (the leaf and the intermediates, PEM) and `privateKey` (PKCS#8, unencrypted); one with the same alias is not imported again;
3. for each cell: `GET .../cells/<cellUrn>/accessEndpoints`, the same object back with only **`apiSslCertRef`** changed (`PUT`, 202, a task waited for) - the JMX certificate and the ports stay as they are. The cell closes its connections and restarts its connection server (a short break);
4. when asked, the cell is put into **maintenance** first and made **active** again after (`PUT .../cells/<cellUrn>` with `status`);
5. older acme items of the library beyond *keep* deleted - only those with no consumer.

## Which versions this guide is for

Cloud Director **10.5.1 - 10.6.1**: from 10.5.1 the cells read their certificate from the Certificates Library, and in 10.6 `cell-management-tool certificates` is gone - the library and `accessEndpoints` (API 38.1+) are the way. The API version sent is a field: `39.0` for 10.6, `38.1` for 10.5.1. The appliance's own management certificate (port 5480, embedded PostgreSQL) is not this one: it is changed in the shell (`generate-appliance-certificates.sh`).

## Set up Cloud Director

1. **A provider user** in the organisation *System*: *Administration → Access Control → Users → New*, e.g. `svc-cert`. Its role:
   - **Certificate Library: Manage** (the import, the deletion of old items);
   - changing a cell's endpoints and maintenance: the documents name only the **System Administrator** - give it that role (a custom global role with fewer rights is not documented).
2. Behind a **load balancer** turn *Each cell in maintenance while it changes* on: the cells change one after another, no session is cut. With TLS re-encryption on the load balancer, trust the new certificate there too.
3. After the first deployment check that the tenants' **console proxy** works (it shares the certificate and port 443 from 10.4).

## The certificate

- PEM X.509 and a PKCS#8 key (acme sends both); no DSA, no SHA-1 anywhere in the chain; 2048 bits or more.
- SAN: the public FQDN (the load balancer, `secureApiEndpoint`) and every cell's FQDN; a wildcard is fine.
- The intermediates go with it; the root only when your CA asks for it.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / HTTPS port | the public FQDN, or one cell's, e.g. `vcd.example.local`, `443` |
| User / Password | `svc-cert@System` (`@System` is added when missing) and its password |
| API version (advanced) | `39.0` (10.6), `38.1` (10.5.1) |
| Cells (deploy) | one a line: the cells' names (or `urn:vcloud:cell:...`); empty: every cell |
| Each cell in maintenance while it changes (deploy) | on behind a load balancer |
| Previous versions to keep (advanced) | `1` |
| Check what is served | `vcd.example.local:443` and each cell's `vcd-cell1.example.local:443` |

## Check it

*Try* signs in and lists the cells. After a deployment:

```sh
openssl s_client -connect vcd.example.local:443 -servername vcd.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -H "Authorization: Bearer $TOKEN" -H "Accept: application/json;version=39.0" \
  "https://vcd.example.local/cloudapi/1.0.0/cells/<cellUrn>/accessEndpoints"
```

In the portal: *Administration → Certificate Management → Certificates Library* - the item's *Consumers*.

## Common problems

| Problem | Fix |
|---|---|
| `no X-VMWARE-VCLOUD-ACCESS-TOKEN` | A tenant user, or an old API version: use a System user, check *API version*. |
| `401` / `403` | The user or its role: Certificate Library: Manage; a System Administrator for the endpoints. |
| `400` on the import | The key encrypted or not PKCS#8, SHA-1 in the chain, DSA. |
| `Cloud Director has no cell "x"` | The name as *Cloud Cells* shows it, or its urn. |
| An old item stays | Something still uses it (*Consumers*) - acme deletes only unused ones. |
