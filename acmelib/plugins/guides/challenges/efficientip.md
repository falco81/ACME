# EfficientIP SOLIDserver - setup for acme

acme proves names by DNS-01 in a zone managed by an EfficientIP SOLIDserver (DDI): through the SOLIDserver REST API v2.0 it adds a TXT resource record (`/dns/rr/add`) on the DNS server (or SMART architecture) you name and deletes only the records holding its value afterwards (`/dns/rr/delete`). SOLIDserver pushes the change to the DNS servers itself.

## What you need

- A SOLIDserver management appliance with REST API v2.0 (`/api/v2.0`).
- The zone managed by SOLIDserver on a DNS server or SMART architecture, and its view if it uses views.
- Outbound HTTPS from acme to the appliance (port 443, or the port you give).
- If the appliance's certificate comes from a private CA: that CA certificate.

## Set up SOLIDserver

1. **Administration → Groups**: create a group for acme, e.g. `acme-dns`.
2. In the group's **Services**, allow only the DNS services acme calls: list zones (`dns_zone_list`), list resource records (`dns_rr_list`), add resource records (`dns_rr_add`) and delete resource records (`dns_rr_delete`). Exact service names may differ by version - choose the DNS zone *list* and RR *list / add / delete* services.
3. In the group's **Resources**, add only the DNS server / SMART and the zones acme may change.
4. **Administration → Users**: create a local user, e.g. `acme`, with a strong password, member of that group only, with API (web services) access.
5. If the appliance restricts API access by source address, allow acme's public address.

## Fill in acme

| acme field | What to put there |
|---|---|
| SOLIDserver address | The management appliance, e.g. `sds.example.local` (`name:port` for another port) |
| User | The SOLIDserver user |
| Password | Its password |
| DNS server | The DNS server or SMART architecture the zones are on, as SOLIDserver names it |
| DNS view | (advanced) The view of the zones; empty = no view |
| Zone | e.g. `example.com`; empty = the longest zone of that server the name is in |
| TTL (s) | (advanced) Default `60` |
| Check the server's certificate | (advanced) leave on |
| CA certificate | (advanced) The private CA that signed the appliance's certificate (PEM) |

## Check it

- **Test** in acme lists the zones of the *DNS server*. It changes nothing.
- With curl:

  ```sh
  curl -s -u "acme:$PASS" --cacert ca.pem \
    "https://sds.example.local/api/v2.0/dns/zone/list?where=server_name='smart.example.local'"
  ```

## Common problems

| Problem | Fix |
|---|---|
| `the DNS server is not set` | Fill in *DNS server*. |
| `401` / `403` | Wrong user/password, or the group lacks the DNS services or the zone in its resources. |
| No zones listed | *DNS server* is not written exactly as SOLIDserver names it, or the zones are in a view - set *DNS view*. |
| TLS error | Paste the private CA under *CA certificate*. |
