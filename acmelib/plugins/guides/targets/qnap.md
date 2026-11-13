# QNAP QTS / QuTS hero (SSH) - setup for acme

**Read this first.** QNAP publishes **no API** for certificates: its manuals (QTS 5.2, QuTS hero h5.2 / h5.3) give only the GUI - *Control Panel > System > Security > SSL Certificate & Private Key > Replace Certificate > Import certificate*. What acme does over SSH is what acme.sh's `ssh` deploy hook documents for QNAP (tested there with QTS 4.2.3), **not checked against QNAP's documentation for QTS 5.2 / QuTS hero h5.x**. Try it on your NAS with *Try reaching it* and one deployment you watch; if it does not take, import in the GUI.

Over SSH acme:

1. reads the certificate in `/etc/stunnel/stunnel.pem` - the same one already: nothing is changed;
2. keeps the files it replaces as `stunnel.pem.acme-prev` and `uca.pem.acme-prev`;
3. writes `/etc/stunnel/stunnel.pem` (the private key, then the certificate - one file, mode 600) and `/etc/stunnel/uca.pem` (the intermediates);
4. runs `/etc/init.d/stunnel.sh restart` - if it fails, the previous files are put back and stunnel restarted again;
5. when asked, `/etc/init.d/Qthttpd.sh restart` too.

The NAS administration pages (and the Web Server, which shares the system certificate) use it once stunnel is back; SMB / NFS shares are not touched.

## Which versions

QTS 5.2.x, QuTS hero h5.2.x and h5.3.x, QuTScloud (assumed to be like QTS). One module.

## What you need

- **SSH on**: *Control Panel > Network & File Services > Telnet / SSH > Allow SSH connection (Only administrators can login remotely.)*; with *Edit Access Permission* allow only the account acme uses.
- An account in the **`administrators`** group - only administrators may sign in over SSH and the files are root's. QNAP advises to disable the default `admin` and use an administrator account of your own. Do not turn on 2-step verification for it (SSH key sign-in is fine).
- HTTPS for the administration on: *Control Panel > System > General Settings > System Administration > Enable secure connection (HTTPS)*, its port (here 443).
- The certificate in X.509 PEM with an unencrypted RSA key (2048 or more; QTS 5.2 uses OpenSSL 3.0 and refuses SHA-1 and short keys; ECC is not documented by QNAP).

Put acme's public key on the NAS for the account (the key card's *How to set it up* shows it), for example:

```sh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Check by hand that the files are where acme writes them:

```sh
ls -l /etc/stunnel/stunnel.pem /etc/stunnel/uca.pem /etc/init.d/stunnel.sh
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | the NAS's name or IP |
| SSH port / User | `22`, the administrator account |
| Sign in with / The SSH key | a key made in acme (or a password) |
| HTTPS port of the NAS | the administration HTTPS port (`443`) |
| Restart the web server too (Qthttpd) (deployment, advanced) | on only when the pages still show the old certificate after stunnel's restart |
| Check what is served | acme checks `<address>:<HTTPS port>` by itself; add a Web Server virtual host if you use one |

*Try reaching it* signs in and checks that `/etc/stunnel/stunnel.pem` and `/etc/init.d/stunnel.sh` are there.

## Check it

```sh
openssl s_client -connect nas01.example.com:443 -servername nas01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

In the GUI: *Control Panel > System > Security > SSL Certificate & Private Key* shows the issuer and validity.

## Common problems

| What you see | Why | What to do |
|---|---|---|
| *... is not there* on *Try reaching it* | this firmware keeps the certificate elsewhere | import it in the GUI; tell us the firmware version |
| SSH opens the Console Management menu | an interactive login | acme runs commands, which do not open the menu; if they do on your firmware, this module cannot be used |
| stunnel did not restart | a bad key or certificate | acme put the previous files back; check the certificate (RSA, PEM) |
| the old certificate comes back after a reboot or update | QTS wrote its own copy back | deploy again (*Deploy now*), or import in the GUI |
| HTTPS does not answer at all | an invalid certificate | open the NAS on `http://<nas>:8080` and restore the default certificate in *SSL Certificate & Private Key* |
| QuTS hero HA cluster: the passive node shows the old one | not known whether it is copied | deploy to each node's address |

Sources: QTS 5.2 / QuTS hero h5.2, h5.3 manuals (*Replacing the server certificate*, *Enabling SSH*, *System Administration*), acme.sh wiki *Deploy hooks* (QNAP over SSH).
