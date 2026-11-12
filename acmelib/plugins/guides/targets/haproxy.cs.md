# HAProxy - nastavení pro acme

acme se přihlásí na server s HAProxy přes SSH, zapíše certifikát (klíč + celý řetězec v jednom PEM) do jeho souboru a vymění ho v **běžícím** HAProxy přes Runtime API na stats socketu (`set ssl cert` + `commit ssl cert`, posláno přes `socat`) - **bez reloadu, bez přerušeného spojení**. Soubor s certifikátem, který HAProxy ještě nezná, se vytvoří přes `new ssl cert` a přidá do crt-listu. Když Runtime API použít nejde, může acme místo toho spustit váš příkaz pro reload. Pro HAProxy 2.2 a novější.

## Co potřebujete

- HAProxy **2.2 nebo novější** na Linuxu, se stats socketem na úrovni **level admin**.
- Nainstalovaný `socat` na serveru s HAProxy.
- Přístup SSH z acme na server (port 22) s uživatelem, který smí zapisovat soubor s certifikátem a používat socket (root, sudo, nebo skupinová práva jako níže).

## Nastavení HAProxy

1. Nainstalujte socat:

```sh
sudo apt install socat        # Debian / Ubuntu
sudo dnf install socat        # RHEL / Fedora
```

2. Dejte HAProxy stats socket na úrovni admin v sekci `global` souboru `/etc/haproxy/haproxy.cfg` (většina balíčků ho už má):

```text
global
    stats socket /run/haproxy/admin.sock mode 660 level admin user haproxy group haproxy
```

3. Uveďte soubor s certifikátem v řádku `bind` (nebo v crt-listu), např.:

```text
frontend https
    bind :443 ssl crt /etc/haproxy/certs/www.example.com.pem
```

   Pokud soubor ještě neexistuje, jednou ho vytvořte (např. kopií současného certifikátu), nebo použijte crt-list a vyplňte *crt-list for a new certificate*.

4. Vytvořte uživatele pro acme a umožněte mu přístup k socketu a složce s certifikáty bez sudo:

```sh
sudo useradd -m -s /bin/bash acme
sudo usermod -aG haproxy acme
sudo chgrp haproxy /etc/haproxy/certs && sudo chmod 2770 /etc/haproxy/certs
sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
# veřejný SSH klíč z acme vložte do /home/acme/.ssh/authorized_keys (práva 600, vlastník acme)
sudo systemctl reload haproxy
```

   Nebo použijte roota / uživatele se sudo a zapněte *Use sudo*. **Soubor s certifikátem obsahuje soukromý klíč: ať ho čte jen HAProxy a acme (acme ho zapisuje s právy 600).** Pokud soubor patří rootovi a HAProxy ho čte jako root při startu, skupinová práva pro samotné HAProxy nejsou potřeba.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | server s HAProxy |
| SSH port | 22 |
| User | `acme` (nebo root / uživatel se sudo) |
| Sign in with / The SSH key / Password | klíč vytvořený v acme (jeho veřejná část v `authorized_keys`), nebo heslo |
| Host key (pokročilé) | řádek `known_hosts` serveru; prázdné s *Trust the first host key seen* |
| Use sudo / sudo password | zapnout jen když uživatel potřebuje sudo k zápisu souboru a k socketu |
| Stats socket | `/run/haproxy/admin.sock` (jako v haproxy.cfg); `ipv4@host:port` pro TCP socket |
| Certificate file (nasazení) | absolutní cesta k PEM, jak ji uvádí haproxy.cfg nebo crt-list |
| crt-list for a new certificate (pokročilé) | crt-list, do kterého se přidá certifikát, který HAProxy ještě nezná; prázdné: musí být známý |
| Reload when the Runtime API cannot (pokročilé) | např. `systemctl reload haproxy` (potřebuje k tomu práva); prázdné: místo toho chyba |
| Leave a file alone when it is the same (SHA-256) | zapnuto: nezměněný soubor se nepřepisuje |
| Keep a copy of a file replaced | kopie jdou do `.acme-backup/` vedle něj (složka crt se načítá celá) |
| Check what is served | `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí, ověří, že je tam `socat`, a zeptá se socketu `show info` (`signed in; HAProxy 2.x answers on …`).
- Na serveru:

```sh
echo "show ssl cert /etc/haproxy/certs/www.example.com.pem" | socat stdio /run/haproxy/admin.sock
```

   ukáže sériové číslo a data certifikátu, který HAProxy právě podává.

## Časté problémy

| Problém | Řešení |
|---|---|
| `socat is not on the machine` | nainstalujte socat (krok 1) |
| `the Runtime API cannot be reached on …` | špatná cesta k socketu, socket není `level admin`, nebo ho uživatel nesmí otevřít (skupina/sudo) |
| `HAProxy does not know …` | uveďte soubor v haproxy.cfg (`crt`) a jednou reloadujte, nebo zadejte crt-list |
| `set ssl cert …` odmítnuto | HAProxy starší než 2.2, nebo se cesta liší od té, kterou HAProxy načetl (musí to být přesně stejná cesta) |
| `the certificate file must be an absolute path …` | použijte absolutní cestu bez mezer a znaků shellu |
| Po restartu HAProxy podává starý certifikát | nový certifikát přidaný přes Runtime API musí být i v souboru crt-listu na disku |
