# This machine (files) - setup for acme

This target writes the certificate as files on **the acme server itself**, under one folder only (*Folder*, default `/etc/acme/out`), for something else to pick up - a web server on the same machine, a backup job, a container volume. Each file is written to a temporary file in the same folder and renamed into place; a path leading outside the folder (`..`, an absolute path elsewhere, a symlink) is refused. Afterwards acme can run **one command** - only one listed exactly in the target's *Commands allowed* - or, if the target allows it, a script written in the deployment. Commands and scripts run on this machine **as the acme user**, without a shell, with a plain `PATH`.

## What you need

- Shell access (root) to the acme server, to prepare the folder.
- The acme service runs as user `acme` under systemd with `ProtectSystem=strict` and `NoNewPrivileges=yes`: it can write only to the folders the service lets in, and **cannot use sudo**.

## Set up this machine

1. Create the folder, owned by acme (the default needs no more):

```sh
sudo install -d -o acme -g acme -m 0750 /etc/acme/out
```

2. A folder **outside `/etc/acme`** must also be let into the service's sandbox, otherwise writing fails with *Read-only file system*:

```sh
sudo install -d -o acme -g acme -m 0750 /srv/certs
sudo systemctl edit acme
#   [Service]
#   ReadWritePaths=/srv/certs
sudo systemctl restart acme
```

3. Let the program that reads the files in, without opening the key to everyone: e.g. give the folder group `ssl-cert` (or the web server's group) and write the key with mode `0640`:

```sh
sudo chgrp ssl-cert /srv/certs && sudo chmod 2750 /srv/certs
```

4. Reloading a service after the files change: acme **cannot** run `sudo` or `systemctl reload` of another service (NoNewPrivileges). Let systemd watch the file instead, e.g. for nginx:

```ini
# /etc/systemd/system/certs-reload.path
[Path]
PathChanged=/srv/certs/www.example.com/fullchain.pem
[Install]
WantedBy=multi-user.target

# /etc/systemd/system/certs-reload.service
[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl reload nginx
```

```sh
sudo systemctl daemon-reload && sudo systemctl enable --now certs-reload.path
```

5. If a deployment is to run a command, a full administrator lists it, exactly, in *Commands allowed* (no pipes, no `;`). Turn on *Scripts written in a deployment may run here* only if you trust everyone who may edit deployments - **such a script runs on the acme server as acme**.

## Fill in acme

| acme field | What to put there |
|---|---|
| Folder | the folder from step 1/2, e.g. `/etc/acme/out` or `/srv/certs` |
| Commands allowed (advanced) | the exact commands a deployment may run, one a line; empty: none |
| Scripts written in a deployment may run here (advanced) | off (default) unless you need inline scripts |
| Files (deployment) | one a line: `format path [mode]`, the path inside the folder, e.g. `fullchain-pem {name}/fullchain.pem` and `key-pem {name}/privkey.pem 0640`; formats: `cert-pem`, `key-pem`, `chain-pem`, `fullchain-pem`, `combined-pem`, `cert-der`, `key-der`, `key-rsa`, `p7b`, `pfx`, `p12`, `p12-legacy`, `jks`; dual: `format@rsa` / `format@ec` |
| Password of PKCS#12 / keystore files / Keystore alias | for `pfx` / `p12` / `jks` outputs |
| Then run (advanced) | one of the allowed commands |
| After the files / The script | a script after the files (only when allowed) |
| Leave a file alone when it is the same (SHA-256) | on: unchanged files are not rewritten |
| Keep a copy of a file replaced | copies go beside the files; choose `.acme-backup/…` or switch it off when the reader must see only certificates |
| Check what is served | `www.example.com:443` of the service that reads the files, one a line |

## Check it

- **Test** in acme says whether the folder can be written (or that it will be made on the first deployment).
- On the server:

```sh
sudo -u acme test -w /srv/certs && echo writable
ls -l /srv/certs/*/
openssl x509 -in /srv/certs/www.example.com/fullchain.pem -noout -subject -enddate
```

## Common problems

| Problem | Fix |
|---|---|
| `Read-only file system` | add the folder to `ReadWritePaths` of the acme service (step 2) |
| `acme cannot write in …` | fix the owner/mode: `chown acme:acme`, `chmod 0750` |
| `… is outside …` / `… is a link` | paths must stay inside the folder; no symlinks |
| `the command "…" is not one this target allows` | list it exactly in *Commands allowed* |
| A command using `sudo` fails | not possible under `NoNewPrivileges`; use a systemd path unit (step 4) |
| `… failed (exit N), the previous files are back` | the command/script failed - acme restored the previous files; see its output in the job |
