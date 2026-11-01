# Bringing a totpcgi + FreeRADIUS server over

The old server: CentOS 6, totpcgi and totpcgi-provisioning, FreeRADIUS 2, and
a Perl handler (`totpcgi-handler.pl`) that checked the code with totpcgi and
the person against LDAP filters. acme replaces all of it, and takes everything
over in one command, so nobody enrols again.

## What comes over

| From the old server | Becomes in acme |
|---|---|
| `etc/totpcgi/totp/*.totp` — one per person | a token each: the same key, the same recovery codes, its window (`WINDOW_SIZE w` becomes `(w-1)/2` steps either way), rate limit and reuse settings |
| `etc/raddb/clients.conf` | the RADIUS clients, with their shared secrets |
| `etc/raddb/hints` (`User-Name += "@dpmo.cz"`) | the realm added to names that come without one, per client |
| the handler's YAML: the LDAP servers, the bind account, the base, the user and group filters | a directory (`AD`) and a realm with those groups |
| `etc/totpcgi/provisioning.conf` | the issuer, the label and the length of the codes |

Nested groups are off after the import (the old handler did not follow
them); switch *Groups inside groups count* on in the realm if you want them.

## Doing it

On the new server, with the old server's files unpacked (its `etc/raddb` and
`etc/totpcgi` — the `acme.zip` it was archived as):

```bash
mkdir /root/old-acme && cd /root/old-acme && unzip /root/acme.zip
acme --import-legacy /root/old-acme            # or: ./install.sh --import-legacy /root/old-acme
```

Run it again and the tokens that are already here are kept; add `--replace`
to overwrite them. Only tokens: Settings → Bringing tokens over on the pages,
or `acme --import-totpcgi DIR`.

## What to check afterwards

1. **The directory.** Settings → Active Directory → *Check it*. The old
   handler talked to the domain controllers by LDAPS with `verify=0`; acme
   checks the certificate. Paste the CA certificate of your domain (PEM) into
   the directory, or switch *Check its certificate* off for the first test
   only.
2. **The bind password.** It came over from the handler's file; if it has
   changed since, set it again.
3. **The clients.** The ASA's address and secret came from `clients.conf`.
   Look at *Must send a Message-Authenticator*: every current ASA sends it,
   and requiring it closes BlastRADIUS.
4. **A test.** The Test tab, or on the server:

   ```bash
   acme --radtest falco 135830
   radtest falco 135830 127.0.0.1 1812 <the localhost secret>
   ```

   A right code gives Access-Accept; the same code again gives
   `Token has already been used once`, as before.
5. **The ASA.** Point the `aaa-server` at the new address (or move the old
   address to the new server). Nothing else changes for it: the same port,
   the same secret, the same answers.
6. **The old server's secrets.** Its files held the bind password and the
   shared secrets in the clear. Once acme is in use, change them — the bind
   account's password in AD and on the directory here, the shared secret on
   the ASA and on the client here — and destroy the old archive.

## Differences worth knowing

- The code alone is still the password, as before (the ASA asks the directory
  password elsewhere). A realm can instead take the directory password
  followed by the code, making acme the only server the ASA asks.
- The Reply-Message on a refusal reads as the old handler's did
  (`Denied by the token server: Not a valid token`, `account does not pass
  LDAP group filter(s)`, `LDAP server(s) have gone away`), so whatever reads
  them reads them the same.
- The logs isemon reads come out unchanged ([isemon.md](isemon.md)).
