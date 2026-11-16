# acme-agent

A server that takes its certificates from acme **without acme holding any of its credentials**:
no SSH key, no password, no sudo. acme proposes, signed; this machine decides by its own policy
(`/etc/acme-agent/policy`, root's - acme can never change it). The default policy allows nothing.

The whole story - the design, the threat model, the protocol, the policy, the ports - is in
acme's documentation: `docs/target-agent.md`.

## Install and join

```
sha256sum acme-agent-X.Y.Z.tar.gz        # the same as acme shows
tar xzf acme-agent-X.Y.Z.tar.gz && cd acme-agent-X.Y.Z
sudo ./install.sh                         # checks the package's signature, installs, allows nothing
sudo acme-agent join CODE                 # the code made on the target's card in acme (an hour, once)
```

`join` prints the agent's fingerprint; acme shows the same on the target's card - confirm it
there only when the two are the same.

## Allow what acme may do

```
sudo acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0640
sudo acme-agent allow unit nginx reload,restart
sudo acme-agent allow test -- nginx -t
sudo acme-agent allow script /usr/local/bin/after-cert.sh     # its SHA-256 pinned now
sudo acme-agent allow script-hash SHA256                      # a script written in acme
sudo acme-agent allow from 192.0.2.10                         # passive: acme only from there
sudo acme-agent allow probe local                             # tests of what this server serves
sudo acme-agent allow probe www.example.com:443               # ...or of exactly that place
sudo acme-agent allow connect 10.0.5.21:22                    # acme reaches it through this agent
sudo acme-agent allow self-update                             # acme may send a newer agent (signed)
sudo acme-agent deny unit nginx restart
acme-agent policy show
```

acme's pages show for each deployment what it needs that the policy does not allow, with these
very lines to copy.

Keys can be made here: when a certificate says so in acme, root makes the key (kept in
`/var/lib/acme-agent-root/keys`, 0600) and writes it only into the files of its deployment that the
policy allows - acme gets the CSR, never the key.

## Two processes

* `acme-agent-root.service` - root, never the network: a Unix socket for the network side alone;
  every job checked again (acme's signature, the agent's id, a nonce, the time) and every file,
  owner, mode, unit, command and script checked against the policy.
* `acme-agent.service` - the account `acme-agent`, no privileges: TLS 1.3 with certificates both
  ways. Passive: it listens on 8446 for acme. Active: it connects to acme's agents' port (8444)
  and nothing listens here.

## Other commands

```
acme-agent status          what is here (JSON)
acme-agent fingerprint     the fingerprint to confirm in acme
sudo acme-agent forget     leave acme: keys, certificate and pins taken away (the policy stays)
sudo ./install.sh --uninstall [--purge]
```

Every operation is written to the journal (`journalctl -t acme-agent`) and to
`/var/lib/acme-agent-root/audit.log`.
