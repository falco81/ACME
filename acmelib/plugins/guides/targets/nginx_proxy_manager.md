# Nginx Proxy Manager - setup for acme

acme talks to the Nginx Proxy Manager (NPM) API (`http://<npm>:81/api`). It adds the certificate as a **custom certificate** (provider "other") under a dated name, uploads the certificate, key and intermediates, and points the proxy hosts, redirection hosts and 404 hosts you list - and, by default, every host that used the older acme certificate - at it. NPM then writes those hosts' nginx configuration and reloads nginx. Older acme certificates no host uses any more are deleted; Let's Encrypt certificates NPM made itself are never touched.

## What you need

- Nginx Proxy Manager 2.x with its admin interface (port 81 by default) reachable from acme.
- An NPM user **without two-factor sign-in**, allowed to manage certificates and the hosts acme changes.

## Set up Nginx Proxy Manager

1. Sign in to the NPM admin interface as an administrator.
2. **Users → Add User**:
   - **Full Name** `acme`, **Email** e.g. `acme@example.com` (used to sign in), not an administrator;
   - set a strong password (**⋮ → Change Password**).
3. **⋮ → Permissions** for that user:
   - **Item Visibility**: *All Items* (acme must see the hosts and certificates it changes, including those made by others);
   - **Certificates**: *Manage*;
   - **Proxy Hosts**: *Manage*; **Redirection Hosts** / **404 Hosts**: *Manage* only if acme is to change them, else *View*;
   - **Streams**, **Access Lists**: *Hidden*.
4. Do **not** enable two-factor sign-in for this user (acme cannot answer a second factor).
5. Keep port 81 off the internet; allow it only from your admins and the acme server. **Without HTTPS in front of port 81 the password travels in clear text** - put the admin interface behind an NPM proxy host with a certificate and use its `https://` address if acme is on another network.

Test the sign-in from the acme server:

```sh
curl -s http://npm.example.local:81/api/tokens -H 'Content-Type: application/json' \
     -d '{"identity":"acme@example.com","secret":"…"}'
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the NPM admin address with scheme and port, e.g. `http://npm.example.local:81` |
| E-mail | the NPM user's e-mail |
| Password | its password |
| Check the device's certificate | for an `https://` address: on, unless self-signed |
| CA certificate (advanced) | the CA of that address's certificate, when not public |
| Proxy hosts (deployment) | one a line: a domain name a proxy host serves, or its ID |
| Redirection hosts / 404 hosts (advanced) | one a line: a domain name or ID |
| Also the hosts that use the older one | on: every host on the older acme certificate moves to the new one |
| Previous versions to keep | older acme certificates kept (deleted only when no host uses them) |
| Check what is served | `www.example.com:443`, one a line |

## Check it

- **Test** in acme signs in and reads NPM.
- In NPM: **SSL Certificates** shows the new custom certificate (`acme-…`) with its expiry; **Hosts → Proxy Hosts** shows the host using it.
- From a shell:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `this NPM user signs in with a second factor …` | give acme its own user without 2FA |
| `Nginx Proxy Manager gave no token on signing in` / 401 | wrong e-mail or password |
| 403 when uploading or changing a host | the user lacks *Manage* on Certificates or that host type, or visibility is *Created Items* only |
| `there is no proxy host "…" in Nginx Proxy Manager` | use a domain the host serves exactly as listed, or its ID |
| Host shows an error after the change | NPM could not reload nginx - see the host's status and NPM's logs (`docker logs <npm>`) |
| `the older … stays: N hosts still use it` | some hosts were not moved; list them or keep *Also the hosts that use the older one* on |
