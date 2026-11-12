# Zimbra Collaboration - setup for acme

acme signs in to the Zimbra server over SSH and deploys the certificate as Zimbra's
**commercial certificate** with Zimbra's own tool, running as the `zimbra` user
(`su - zimbra -c ...`):

1. the key goes to `/opt/zimbra/ssl/zimbra/commercial/commercial.key`;
2. the certificate and the chain **up to the root** are checked with
   `zmcertmgr verifycrt comm` - if that fails, **the previous key is put back**;
3. `zmcertmgr deploycrt comm` deploys them;
4. the services are restarted: `zmcontrol restart` (default), or only proxy, mailbox and
   MTA, or nothing.

For Zimbra Collaboration 8.7 and later (Open Source and Network Edition). In a
**multi-server** installation each mailbox / proxy / MTA server is a target of its own.

## What you need

- SSH from acme to each Zimbra server, **TCP 22**.
- `root`, or a user who may `sudo` to root (acme runs `su - zimbra` as root).
- An **RSA** key type for the certificate (the key is written in the RSA/PKCS#1 form
  zmcertmgr expects).
- The **root CA certificate** in PEM when the chain does not contain it - Let's Encrypt's
  does not (ISRG Root X1 for an RSA chain).
- A maintenance window: a full `zmcontrol restart` interrupts mail access for a few minutes.

## Set up the Zimbra server

1. Create an account for acme and put acme's public key on it (*The SSH key → How to set
   it up* in acme shows the commands):

   ```sh
   sudo useradd -m -s /bin/sh acme
   sudo -u acme sh -c 'mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
     echo "from=\"<acme-IP>\" ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys && \
     chmod 600 ~/.ssh/authorized_keys'
   ```

2. Allow sudo without a password - acme runs its steps as `sudo -n sh -c ...`:

   ```sh
   echo 'acme ALL=(root) NOPASSWD: /bin/sh' | sudo tee /etc/sudoers.d/acme
   sudo chmod 440 /etc/sudoers.d/acme && sudo visudo -c
   ```

   **This amounts to root.** (Or sign in as root and leave *Use sudo* off.)
3. Download the root CA certificate (ISRG Root X1 for Let's Encrypt) - it goes into *Root
   CA certificate* in acme.
4. Check that the commercial certificate folder exists:

   ```sh
   sudo ls -ld /opt/zimbra/ssl/zimbra/commercial
   ```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address / SSH port / User | The Zimbra server, `22`, `acme` (or `root`) |
| Sign in with / The SSH key | *a private key* - the key from step 1 |
| Use sudo / sudo password | On for a non-root account; password empty with `NOPASSWD` |
| Timeout (s) (advanced) | `30` (zmcertmgr and the restart get longer by themselves) |
| Root CA certificate (deploy) | The root PEM (ISRG Root X1); empty only if the chain holds the root |
| Restart (deploy) | *every Zimbra service* (default), *proxy, mailbox and MTA only*, or *nothing* |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Defaults are fine |
| Check what is served | e.g. `mail.example.com:443`, `mail.example.com:993`, `mail.example.com:465` |

## Check it

- Press **Try** on the target: acme runs `zmcontrol -v` as zimbra:
  `signed in to ...: Release 10.x ...`.
- On the server:

  ```sh
  sudo su - zimbra -c 'zmcertmgr viewdeployedcrt'
  sudo su - zimbra -c 'zmcontrol status'
  ```

## Common problems

| Problem | Fix |
|---|---|
| `zmcertmgr wants the chain up to the root` | Fill in *Root CA certificate* (ISRG Root X1). |
| `zmcertmgr does not take it, the previous key is back` | Wrong root for the chain, or key/certificate mismatch - read the message. |
| `key-rsa (PKCS#1) is only for RSA keys` | Use an RSA key type for this certificate. |
| `sudo: a password is required` | Missing `NOPASSWD` rule, or fill in *sudo password*. |
| Services did not come back | Check `zmcontrol status`; the restart output is in the job as a warning. |
| Other servers of the install still show the old certificate | Each server needs its own target. |
