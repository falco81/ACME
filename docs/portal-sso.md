# Signed in by a load balancer or WAF (SSO)

As in otp 1.0.239. The certificate portal (*the enrolment pages*, `/`) published to the internet
through a NetScaler (Citrix ADC), an F5 BIG-IP APM or another balancer that signs people in
against the directory first: they come to the portal signed in already, and are not asked for
the password a second time. The administration pages (`/admin`) are not concerned and are
never published this way.

**Off by default** - the portal is then exactly as it was.

## How it works

```
browser ──TLS──▶ balancer / WAF ──TLS──▶ nginx (node) ──▶ PHP ──▶ acme daemon
                 1. signs the person in (LDAP, nFactor, APM...)
                 2. takes away X-Acme-User and X-Acme-Sso-Key the client sent
                 3. puts in X-Acme-User: <who signed in> and X-Acme-Sso-Key: <the key>
```

acme believes the name only when all of these hold:

- the request came **from one of the balancers named** (*The balancers that sign people in*) -
  the address of the machine the connection came from, as nginx sees it
  (`$realip_remote_addr`, passed to the page as `ACME_PEER`), never the client's address from
  `X-Forwarded-For`;
- it carries **the key** in `X-Acme-Sso-Key` - made on the pages (*Make a key*) or with
  `acme --sso-key`, shown once, kept sealed like the other secrets, compared in constant time;
- the directory of the portal (*Settings → The enrolment pages → the directory*) knows the name,
  the account may sign in, and only one account answers to it.

Everything after the password is as it is for a password sign-in:

- *Who may sign in* (anybody of the directory, or the groups named, and the group of the
  enrolment-only accounts) decides;
- the person sees the certificates their teams and ownership give them, as with a password;
- the same person on the next page goes on in the same session; another person on the same
  browser (a shared machine) ends the session before;
- switched off, a sign-in made by the balancer ends at the next page.

acme's own accounts (*Accounts*, `portal_local`) are not signed in this way - they keep their
password and their second step.

Every refusal is in *Events* (portal) with its reason - not from the balancers named, the key
wrong or not there, no name, a name the directory does not know, not in the groups. The card on
*Settings → The enrolment pages* shows the last sign-in by the balancer each node saw (the last
that went well and the last refused, each node its own): the name, the balancer's address, the
client's address, signed in or refused and why (`acme --sso-status` on the command line).
*Alerts and reports → Sign-ins by the load balancer refused* (off by default) mails each one.

A password sign-in stays possible: somebody who reaches a node directly (inside the network)
signs in as before.

**Signing in with Windows (Kerberos)** (1.0.99, [kerberos-sso.md](kerberos-sso.md)) may be on
beside it: the two do not touch each other - each has its own switch and its own refusals, and
switching one off ends only its own sign-ins.

## Switching it on

1. *Settings → Firewall and access → Behind a load balancer or WAF*: the balancer's address,
   switched on - otherwise every client is the balancer's address (one person's sign-in
   pause is everybody's, the logs do not say who). See docs/load-balancers.md.
2. If the portal is published to the internet: *who may reach the enrolment pages* must take
   the clients' addresses as the balancer passes them on.
3. *Settings → The enrolment pages → Signed in by a load balancer or WAF*:
   - *The balancers that sign people in*: their addresses towards the nodes (SNIP on a
     NetScaler, the self IP / SNAT pool on an F5);
   - *The header with who signed in*: `X-Acme-User`, or the one the balancer sends already;
   - *Make a key* - and put it into the balancer;
   - *Where signing out goes*: the balancer's own sign-out (NetScaler `/cgi/tmlogout`,
     F5 `/vdesk/hangup.php3`); empty, *Sign out* holds the sign-in by the balancer until the
     person asks for it again on the sign-in page;
   - switch it on. Without the balancers named or without a key it is refused.

Switched on, each node's root helper adds one line to the portal's `location = /` in nginx
(`fastcgi_param ACME_PEER $realip_remote_addr; # ACME-SSO-PEER`), checked with `nginx -t` and
put back when refused; switched off, only that line goes. Both nodes of a cluster, the VIP
address's server too (it is made from the node's). A configuration of nginx without
`location = /` is said in the log of the helper and holds up nothing else of the request
(the certificates, the VIP address and the firewall still go in).

The card then shows the configuration for NetScaler, F5 APM and nginx / oauth2-proxy, filled
in with the values set there.

## NetScaler (Citrix ADC)

- An authentication virtual server (LDAPS against a domain controller, or nFactor) and an
  authentication profile on the load balancing virtual server of the portal.
- Rewrite policies on that virtual server, in this order: delete `X-Acme-User`,
  `X-Acme-Sso-Key` and `X-Forwarded-For` as the client sent them; insert
  `X-Acme-User: AAA.USER.NAME` and `X-Acme-Sso-Key` only when `AAA.USER.IS_AUTHENTICATED`;
  insert `X-Forwarded-For: CLIENT.IP.SRC`.
- A responder policy that drops `/admin`.
- The Web App Firewall profile on the same virtual server.

## F5 BIG-IP APM

- An access profile: Logon Page → AD Auth (or LDAP Auth) → Allow.
- An iRule on the virtual server: in `HTTP_REQUEST` refuse `/admin`, remove the client's
  `X-Acme-User` and `X-Acme-Sso-Key`, replace `X-Forwarded-For`; in `ACCESS_ACL_ALLOWED` put in
  `X-Acme-User` from `session.logon.last.username` (or
  `session.ad.last.attr.userPrincipalName`) and the key.
- Advanced WAF / ASM policy on the virtual server, where licensed.

## Checking it

From a machine that is not a balancer, a request with the headers set by hand gets the sign-in
page (with the password) - and a refusal in *Events*:

```
curl -sk -H "X-Acme-User: novak" -H "X-Acme-Sso-Key: guess" https://acme.example.cz/ | grep -c in-pass
```

Through the balancer, signed in: the person's own certificates, no password. *Look again* on
the card shows "signed in", the balancer's address and the client's.

## Command line

```
acme --sso-status           # on or off, the balancers, the header, the last sign-in on each node
acme --sso-key              # a new key, shown once (the one before is no longer taken)
acme --set portal_sso_from="10.40.0.5/32" --set portal_sso=1
acme --set portal_sso=0     # off: the portal as before, the nginx line taken out
```

The console (`acme --console`): *Encryption, sending out, time, network, high security* →
*Signed in by a load balancer (SSO)*.
