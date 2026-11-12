# Connector over SSH - setup for acme

A connector is **a Linux server of yours** (AlmaLinux, RHEL, Rocky, Debian, Ubuntu - any
with OpenSSH) that acme signs in to over SSH to reach targets **only that network
reaches**. A target that signs in over SSH chooses it under *More → Through a connector*;
acme then connects to the target through it (`ssh -W`, a forwarded TCP connection).
**Nothing is installed on the connector and no certificate is deployed on it.**

## What you need

- A Linux server with OpenSSH, reachable from acme on **TCP 22** (or your port).
- From that server: network access to the SSH port of each target behind it.
- An ordinary account on it (no root, no sudo needed).
- Optional: `ssh-keyscan` on the connector (part of the OpenSSH client). Without it, pin
  each target's host key in the target's *Host key* field.

## Set up the connector server

1. Create a dedicated, unprivileged account:

   ```sh
   sudo useradd -m -s /bin/bash acme-relay
   ```

2. Put acme's public key on it (make the key in acme: the connector's *The SSH key* →
   *Make a key*; *How to set it up* shows the commands):

   ```sh
   sudo -u acme-relay sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<acme-IP>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

   Optionally limit where it may forward to by adding
   `permitopen="10.0.0.5:22",permitopen="10.0.0.6:22"` before the key (one per target).
3. Make sure TCP forwarding is allowed for that account (on by default). In
   `/etc/ssh/sshd_config` it must not be `no`:

   ```text
   AllowTcpForwarding yes
   ```

   then `sudo systemctl reload sshd` if you changed it.
4. Allow TCP 22 from the acme server in the connector's firewall, and outgoing SSH from the
   connector to the targets.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | The connector's name or IP |
| SSH port | `22` |
| User | `acme-relay` |
| Sign in with / The SSH key | *a private key* - the key from step 2 |
| Password | Only with password sign-in |
| Host key (advanced) | The connector's `known_hosts` line, or empty with *Trust the first host key seen* |

Then on each target behind it: **More → Through a connector** → this connector.

## Check it

- Press **Try** on the connector: acme signs in and runs `id -un; uname -n`, answering
  `signed in to <host> as acme-relay - targets set to go through it are reached from there`
  (it adds a note if `ssh-keyscan` is missing).
- Press **Try** on a target that uses it: that sign-in goes through the connector.
- On the connector, to see forwarding is allowed:

  ```sh
  sudo sshd -T | grep -i allowtcpforwarding
  ```

## Common problems

| Problem | Fix |
|---|---|
| Connector Try fails with `Permission denied` | Key not in `authorized_keys`, wrong permissions, or `from=` does not match acme's IP. |
| Connector works, target behind it times out | Firewall between connector and target, or `AllowTcpForwarding no`, or a `permitopen` not listing the target. |
| `ssh-keyscan is not there` | Install the OpenSSH client on the connector, or pin each target's *Host key*. |
| `... is a connector: certificates go to the targets` | Expected: you cannot deploy to a connector. |
