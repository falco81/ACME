# NGINX Unit - nastavení pro acme

acme se přihlásí na server s Unit přes **SSH** a s **řídicím API** Unitu mluví přes jeho řídicí socket pomocí `curl` na tom stroji. Nahraje balík certifikátu (celý řetězec + klíč) jako `PUT /certificates/acme-<jméno>-<datum>-<sériové číslo>`, nasměruje na něj každý zadaný listener (`PUT /config/listeners/<listener>/tls/certificate`; v seznamu certifikátů se nahradí jen starší certifikát acme) a smaže starší balíky acme. Unit nový certifikát převezme ihned - **bez restartu, bez přerušeného spojení**. Balík, který se ještě používá, Unit odmítne smazat a zůstane.

## Co potřebujete

- NGINX Unit (1.x) na Linuxu s řídicím socketem (`/var/run/control.unit.sock`, na některých systémech `/run/unit/control.sock` - viz `unitd --help` / volba `--control`).
- `curl` na serveru s Unit.
- Přístup SSH z acme (port 22) s uživatelem, který smí používat řídicí socket: root, nebo uživatel se sudo.
- Listenery už definované v konfiguraci Unitu.

## Nastavení serveru s Unit

1. Pokud chybí, nainstalujte curl (`sudo apt install curl` / `sudo dnf install curl`).
2. Zjistěte řídicí socket:

```sh
ps -o args= -C unitd | head -1        # hledejte --control
ls -l /var/run/control.unit.sock /run/unit/control.sock 2>/dev/null
```

3. Vytvořte pro acme uživatele se sudo (řídicí socket je standardně jen pro roota):

```sh
sudo useradd -m -s /bin/bash acme
echo 'acme ALL=(root) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/acme && sudo chmod 440 /etc/sudoers.d/acme
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# veřejný SSH klíč z acme vložte do /home/acme/.ssh/authorized_keys (práva 600, vlastník acme)
```

   **acme spouští své příkazy jako `sudo sh -c '…'`, takže pravidlo sudo omezené na `curl` nefunguje - a plný přístup k řídicímu socketu je stejně rovný rootovi.** Případně použijte `root` jen se SSH klíčem.

4. Ověřte, že listener existuje a je určen pro TLS, např. v konfiguraci Unitu:

```json
"listeners": { "*:443": { "pass": "routes", "tls": { "certificate": "initial" } } }
```

   Pokud listener ještě nemá sekci `tls`, jednou ručně nahrajte libovolný certifikát (`curl -X PUT --data-binary @bundle.pem --unix-socket … http://localhost/certificates/initial`) a přidejte `tls` jako výše; acme ho pak nahradí.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | server s Unit |
| SSH port | 22 |
| User | `acme` (nebo root) |
| Sign in with / The SSH key / Password | klíč vytvořený v acme (jeho veřejná část v `authorized_keys`), nebo heslo |
| Host key (pokročilé) | řádek `known_hosts` serveru; prázdné s *Trust the first host key seen* |
| Use sudo / sudo password | zapnout pro uživatele, který není root; heslo prázdné, když je sudo NOPASSWD |
| Control socket | `/var/run/control.unit.sock` (nebo co ukázal krok 2) |
| Timeout (s) (pokročilé) | 30 |
| Listeners (nasazení) | jeden na řádek, přesně jako v konfiguraci Unitu, např. `*:443` |
| Previous versions to keep | kolik starších balíků acme zůstane |
| Check what is served | `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí a vypíše balíky certifikátů (`signed in; Unit answers, N certificate bundles`).
- Na serveru:

```sh
sudo curl -s --unix-socket /var/run/control.unit.sock http://localhost/certificates | head -40
sudo curl -s --unix-socket /var/run/control.unit.sock http://localhost/config/listeners
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the control socket … cannot be reached` | špatná cesta k socketu, chybí curl, nebo chybí práva (zapněte *Use sudo*) |
| `sudo: a password is required` | zadejte *sudo password* nebo nastavte pravidlo jako NOPASSWD |
| `Unit has no listener "…"` | jméno listeneru se musí přesně shodovat s konfigurací (`*:443`, `127.0.0.1:8443`) |
| `Unit said 400 - …` při nahrání | balík byl odmítnut (např. klíč nesedí); viz zprávu |
| `Unit said 404/400` při nasměrování listeneru | listener ještě nemá sekci `tls` - viz krok 4 |
| `the old bundle … stays (still used?)` | používá ho ještě jiný listener; přidejte ho do *Listeners* nebo ho změňte ručně |
