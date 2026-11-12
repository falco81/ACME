# Docker Swarm secrets - nastavení pro acme

acme se přihlásí přes **SSH na manager uzel Swarmu**. Protože Docker secret nelze změnit,
jen nahradit, vytvoří dva nové secrety se jmény s datem -
`acme-<jméno>-<datum>-<sériové číslo>.crt` (celý řetězec) a `.key` (se štítkem
`managed-by=acme`) - a každou zadanou službu na ně převede (`docker service update
--secret-rm <old> --secret-add source=<new>,target=tls.crt,...`, rolling update; vlastník a
práva souboru, které služba měla, zůstanou). Starší secrety acme odstraní; používaný
zůstane.

Pro Docker Engine v režimu Swarm (jakákoli podporovaná verze) na Linuxu.

## Co potřebujete

- Přístup SSH z acme na **manager** uzel (výchozí TCP 22).
- Uživatele, který tam smí spouštět `docker`: root, člen skupiny `docker`, nebo přes sudo.
  **Členství ve skupině `docker` je na daném stroji ekvivalentní rootu.**
- Služby už existují a čtou certifikát a klíč ze secretů (soubory pod `/run/secrets/`).

## Nastavení manager uzlu Swarmu

1. Na manageru vytvořte pro acme uživatele a přidejte veřejný SSH klíč acme:

   ```sh
   sudo useradd -m -s /bin/bash acme
   sudo usermod -aG docker acme
   sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' | sudo tee /home/acme/.ssh/authorized_keys
   ```

   (Nebo ho do skupiny `docker` nedávejte a v acme zapněte *Use sudo*.)
2. Ověřte, že jde o manager aktivního swarmu:

   ```sh
   docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'
   # active true
   ```

3. Nechte služby číst soubory ze secretů. Ve stack souboru například:

   ```yaml
   services:
     proxy:
       secrets:
         - source: www_crt
           target: tls.crt
         - source: www_key
           target: tls.key
   ```

   acme nahradí secret připojený jako `tls.crt` / `tls.key` (nebo starší secret acme)
   svým. Pokud stack soubor později znovu nasadíte (`docker stack deploy`), vrátí do služby
   secrety, které uvádí - odkazujte ve stack souboru na externí secrety, nebo znovu
   spusťte nasazení acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP manager uzlu |
| SSH port / User | `22` / `acme` (nebo `root`) |
| Sign in with / The SSH key / Password | Klíč vytvořený v acme (doporučeno) nebo heslo |
| Use sudo / sudo password | Zapnuto, pokud uživatel není ve skupině `docker` ani root |
| docker command (pokročilé) | Výchozí `docker` (prostá cesta) |
| Timeout (s) (pokročilé) | Výchozí 30 |
| Services (nasazení) | Jedna na řádek, např. `web_proxy` (služby stacku jsou `<stack>_<služba>`) |
| Certificate file in the container (nasazení) | Výchozí `tls.crt` (pod `/run/secrets/`, není-li absolutní); celý řetězec |
| Key file in the container (nasazení) | Výchozí `tls.key` |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | Publikovaná služba, např. `www.example.com:443` |

## Ověření

- **Try**: `signed in: a swarm manager, Docker 27.x`.
- Na manageru:

  ```sh
  docker secret ls --filter label=managed-by=acme
  docker service inspect web_proxy --format '{{json .Spec.TaskTemplate.ContainerSpec.Secrets}}'
  docker service ps web_proxy
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `this is not a manager of an active swarm` | Přihlaste se na manager uzel, ne na worker |
| `permission denied ... docker.sock` | Přidejte uživatele do skupiny `docker` nebo zapněte *Use sudo* |
| `there is no service "..."` | Chybné jméno - použijte celé jméno `<stack>_<služba>` (`docker service ls`) |
| Rolling update visí nebo selže | Viz `docker service ps <svc>`; nové úlohy možná nenastartují |
| `the old secret ... stays (still used?)` | Jiná služba ho ještě připojuje; odstraní se, až nebude používán |
| Po `docker stack deploy` jsou zpět staré secrety | Stack soubor je uvádí - použijte externí secrety nebo znovu nasaďte přes acme |
