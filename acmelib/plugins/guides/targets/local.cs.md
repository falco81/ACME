# Tento stroj (soubory) - nastavení pro acme

Tento cíl zapisuje certifikát jako soubory na **samotném serveru acme**, a to jen do jedné složky (*Folder*, výchozí `/etc/acme/out`), odkud si je vezme něco jiného - webový server na stejném stroji, záloha, svazek kontejneru. Každý soubor se zapíše do dočasného souboru ve stejné složce a přejmenuje na místo; cesta vedoucí mimo složku (`..`, absolutní cesta jinam, symbolický odkaz) je odmítnuta. Poté může acme spustit **jeden příkaz** - jen takový, který je přesně uvedený v *Commands allowed* cíle - nebo, pokud to cíl dovolí, skript napsaný v nasazení. Příkazy a skripty běží na tomto stroji **jako uživatel acme**, bez shellu, s prostou `PATH`.

## Co potřebujete

- Přístup do shellu (root) na serveru acme, kvůli přípravě složky.
- Služba acme běží jako uživatel `acme` pod systemd s `ProtectSystem=strict` a `NoNewPrivileges=yes`: zapisovat může jen do složek, které jí služba povolí, a **nemůže používat sudo**.

## Nastavení tohoto stroje

1. Vytvořte složku patřící acme (pro výchozí nic dalšího není potřeba):

```sh
sudo install -d -o acme -g acme -m 0750 /etc/acme/out
```

2. Složku **mimo `/etc/acme`** je navíc nutné pustit do sandboxu služby, jinak zápis selže s *Read-only file system*:

```sh
sudo install -d -o acme -g acme -m 0750 /srv/certs
sudo systemctl edit acme
#   [Service]
#   ReadWritePaths=/srv/certs
sudo systemctl restart acme
```

3. Pusťte k souborům program, který je čte, aniž byste klíč otevřeli všem: např. dejte složce skupinu `ssl-cert` (nebo skupinu webového serveru) a klíč zapisujte s právy `0640`:

```sh
sudo chgrp ssl-cert /srv/certs && sudo chmod 2750 /srv/certs
```

4. Reload služby po změně souborů: acme **nemůže** spustit `sudo` ani `systemctl reload` jiné služby (NoNewPrivileges). Nechte místo toho soubor hlídat systemd, např. pro nginx:

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

5. Má-li nasazení spouštět příkaz, plný administrátor ho přesně uvede v *Commands allowed* (žádné roury, žádné `;`). *Scripts written in a deployment may run here* zapněte jen tehdy, když věříte každému, kdo smí upravovat nasazení - **takový skript běží na serveru acme jako acme**.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Folder | složka z kroku 1/2, např. `/etc/acme/out` nebo `/srv/certs` |
| Commands allowed (pokročilé) | přesné příkazy, které smí nasazení spustit, jeden na řádek; prázdné: žádné |
| Scripts written in a deployment may run here (pokročilé) | vypnuto (výchozí), pokud nepotřebujete skripty přímo v nasazení |
| Files (nasazení) | jeden na řádek: `formát cesta [práva]`, cesta uvnitř složky, např. `fullchain-pem {name}/fullchain.pem` a `key-pem {name}/privkey.pem 0640`; formáty: `cert-pem`, `key-pem`, `chain-pem`, `fullchain-pem`, `combined-pem`, `cert-der`, `key-der`, `key-rsa`, `p7b`, `pfx`, `p12`, `p12-legacy`, `jks`; duální: `format@rsa` / `format@ec` |
| Password of PKCS#12 / keystore files / Keystore alias | pro výstupy `pfx` / `p12` / `jks` |
| Then run (pokročilé) | jeden z povolených příkazů |
| After the files / The script | skript po souborech (jen když je povolen) |
| Leave a file alone when it is the same (SHA-256) | zapnuto: nezměněné soubory se nepřepisují |
| Keep a copy of a file replaced | kopie jdou vedle souborů; zvolte `.acme-backup/…` nebo je vypněte, když čtenář smí vidět jen certifikáty |
| Check what is served | `www.example.com:443` služby, která soubory čte, jeden na řádek |

## Ověření

- **Test** v acme řekne, zda lze do složky zapisovat (nebo že se vytvoří při prvním nasazení).
- Na serveru:

```sh
sudo -u acme test -w /srv/certs && echo writable
ls -l /srv/certs/*/
openssl x509 -in /srv/certs/www.example.com/fullchain.pem -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Read-only file system` | přidejte složku do `ReadWritePaths` služby acme (krok 2) |
| `acme cannot write in …` | opravte vlastníka/práva: `chown acme:acme`, `chmod 0750` |
| `… is outside …` / `… is a link` | cesty musí zůstat uvnitř složky; žádné symbolické odkazy |
| `the command "…" is not one this target allows` | uveďte ho přesně v *Commands allowed* |
| Příkaz se `sudo` selže | pod `NoNewPrivileges` to nejde; použijte systemd path unit (krok 4) |
| `… failed (exit N), the previous files are back` | příkaz/skript selhal - acme vrátilo předchozí soubory; jeho výstup je v úloze |
