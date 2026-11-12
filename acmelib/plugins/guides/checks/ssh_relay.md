# Connector over SSH - setup for acme

A **connector** is a Linux server of yours (AlmaLinux, RHEL, Rocky, Debian, Ubuntu... - any with OpenSSH) that acme signs in to over SSH, to run tests from it against servers only that network reaches - an intranet web server, a mail relay, a Windows server's RDP. Each test chooses it under *More → Through a connector*; acme then connects to the tested server from the connector through an SSH tunnel (`ssh -W host:port`, a TCP forwarding channel). **Nothing is installed on the connector and nothing is left behind**; the TLS handshake and the comparison run in acme as for any other test.

The tests' connectors are separate from the targets' connectors (Targets → Connector over SSH); they may be the same server or different ones.

## What you need

- A Linux server with OpenSSH that reaches the servers to be tested (their ports: 443, 25, 3389...).
- SSH access **from acme** to it - TCP `22` (or its own SSH port).
- A user acme signs in as. **It does not need root or sudo** - the connector runs only `id -un; uname -n` when tried, and opens TCP forwards.
- `AllowTcpForwarding` in `sshd_config` must not be `no` (the default `yes` is fine).

## Set up the connector server

1. Make a dedicated user with no special rights:

   ```sh
   useradd -m -s /bin/bash acme-relay
   install -d -m 700 -o acme-relay -g acme-relay /home/acme-relay/.ssh
   ```

2. In acme, on the connector's key card press **Make a key** (ed25519) - or *Use my own* - and put the public half shown into the user's `authorized_keys` (*How to set it up on the server* shows the same):

   ```sh
   echo 'ssh-ed25519 AAAA... acme' >> /home/acme-relay/.ssh/authorized_keys
   chown acme-relay: /home/acme-relay/.ssh/authorized_keys
   chmod 600 /home/acme-relay/.ssh/authorized_keys
   ```

   To restrict the key to forwarding toward the tested servers only, prefix it with options, e.g. `permitopen="intranet.example.local:443",permitopen="10.0.0.25:25"` (then every server:port tested must be listed).
3. Check TCP forwarding is allowed:

   ```sh
   sshd -T | grep -i allowtcpforwarding     # yes / all / local
   ```

   If it is `no` (often in a `Match` block), allow it for this user only:

   ```text
   Match User acme-relay
       AllowTcpForwarding local
   ```

   then `systemctl reload sshd`.
4. Firewalls: allow SSH from acme to the connector, and TCP from the connector to each tested server's port.

## Fill in acme

Certificates → **Tests** → switch **Tests | Connectors** → add a **Connector over SSH**.

| acme field | What to put there |
|---|---|
| Address | the connector's name or IP |
| SSH port | `22`, or its own SSH port |
| User | the user from step 1 (e.g. `acme-relay`; the default `root` is not needed) |
| Sign in with | *a private key* (recommended) or *a password* |
| The SSH key | *Make a key* here, or *Use my own* (OpenSSH or PEM, with its passphrase) |
| Password | only with *Sign in with: a password* |
| Host key (advanced) | the connector's `known_hosts` line; empty with *Trust the first host key seen* takes the one seen first |
| Trust the first host key seen (advanced) | on (default), or off once the host key is set |
| Tests run from there (the older way) (advanced) | leave empty - since 1.0.76 each test chooses its connector under *More → Through a connector* |
| Time limit (s) (advanced) | `20` |

Then in each test that should go through it: *More → Through a connector* = this connector.

## Check it

1. On the connector, **Try reaching it** / **Test**: acme signs in and says `signed in to <host> as <user>`.
2. Run a test that goes through it (**Test** on that test): the result says it was reached through the connector.
3. By hand, the same forwarding acme uses (`ssh -W`), from a machine with the same key:

   ```sh
   ssh -i acme_relay_key -L 8443:intranet.example.local:443 -N acme-relay@connector.example.local &
   openssl s_client -connect 127.0.0.1:8443 -servername intranet.example.local </dev/null 2>/dev/null \
     | openssl x509 -noout -subject -issuer -enddate
   ```

## Common problems

| Problem | Fix |
|---|---|
| `Permission denied (publickey)` | the public key is not in `authorized_keys` of that user, or the file/dir permissions are too open (`700` / `600`) |
| Host key changed | the connector was reinstalled: put the new `known_hosts` line in *Host key* (only after checking it) |
| `channel open failed: administratively prohibited` | `AllowTcpForwarding no`, or a `permitopen` option not listing that server:port |
| `channel open failed: connect failed` | the connector cannot reach the tested server: firewall between them, wrong address, the service down |
| The test says the connector is not there or switched off | the connector was deleted or disabled - a test never quietly goes direct: switch it on, or set *directly* |
| Slow results | raise *Time limit (s)* on the connector and the test |
