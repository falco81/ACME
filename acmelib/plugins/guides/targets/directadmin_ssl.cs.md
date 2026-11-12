# DirectAdmin - nastavení pro acme

acme nahradí TLS certifikát **domény v DirectAdmin**. Přihlašuje se HTTP basic
autentizací a **login klíčem**:

- **Nové API** (`/api/domain-tls`, nebo `/api/admin-domain-tls` jako administrátor):
  vypíše sloty certifikátů domény, vybere slot (zadaný, jediný, nebo ten, jehož jména
  certifikát pokrývá), soubory ověří **zkušebním během** (dry run), pak je nahradí na místě
  a - ve výchozím stavu - zařadí doménu na skip list ACME, aby ji vlastní ACME DirectAdmin
  (Let's Encrypt) nechalo být.
- **Starší API** (starší DirectAdmin): `CMD_API_SSL` s `type=paste` a pak CA certifikát
  (`type=cacert`).

DirectAdmin webový server znovu načte sám. Žádné starší kopie k úklidu nejsou: slot se
nahrazuje.

Pro DirectAdmin s novým API (novější verze 1.6x) nebo, s *legacy*, starší.

## Co potřebujete

- HTTPS z acme na port DirectAdmin, výchozí **2222**.
- Doménu už existující v DirectAdmin, a pro nové API **se slotem certifikátu** (certifikát
  jednou vytvořený v DirectAdmin - acme slot nahrazuje, nevytváří; jinak použijte starší
  API).
- Login klíč uživatele domény, nebo admina / resellera jednajícího za něj.

## Nastavení DirectAdmin

1. Přihlaste se jako uživatel domény (nebo admin / reseller, který bude jednat za něj).
2. Otevřete **Login Keys** (uživatel: *Advanced Features → Login Keys*; admin: v nabídce
   účtu) → **Create Key**.
3. Jméno klíče `acme`, dlouhá náhodná hodnota, případně platnost, a **Allowed IPs**:
   adresa serveru acme. Pokud formulář umožňuje omezit příkazy, povolte jen to, co acme
   používá (legacy: `CMD_API_SSL`); ověřte, že je nové API s klíčem dostupné (**Try**).
4. Ověřte, že má doména zapnuté SSL (**Account Manager → Domain Setup → doména → Secure
   SSL**) a pro nové API, že pro ni existuje certifikát (**SSL Certificates**).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | Server DirectAdmin, např. `server.example.com` / `2222` |
| User | Uživatel domény, nebo admin / reseller jednající za něj |
| Login key | Login klíč z kroku 3 (nebo heslo) |
| Act as the user (pokročilé) | U admina / resellera: uživatel (přihlášení jako `admin\|user`) |
| API | `the new API (/api/domain-tls)`, `the new API as an administrator` nebo `the legacy CMD_API_SSL` |
| Check the device's certificate / CA certificate | Jako u každého HTTPS serveru |
| Domain (nasazení) | Doména v DirectAdmin, např. `example.com` |
| Certificate slot (nasazení) | Vybraný ze seznamu (nové API); prázdné: jediný, nebo ten, jehož jména certifikát pokrývá |
| Keep DirectAdmin's ACME off it (nasazení) | Zapnuto: vlastní ACME DirectAdmin ho nenahradí |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try**: `signed in to DirectAdmin ... as <user>` (legacy: `reached DirectAdmin ...`).
- V DirectAdmin: **SSL Certificates** domény ukazuje nový certifikát.

  ```sh
  openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null | openssl x509 -noout -issuer -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `DirectAdmin does not let acme in (401/403)` | Chybný klíč, vypršel, nebo IP acme není v *Allowed IPs* |
| Příliš mnoho neúspěšných přihlášení / IP zablokována | Ochrana proti brute-force zablokovala acme - odblokujte a opravte klíč |
| Žádný slot certifikátu | Nejdřív v DirectAdmin vytvořte certifikát domény, nebo použijte starší API |
| 409 při PUT | Certifikát a klíč k sobě nepatří, nebo je slot používán - viz detail |
| Nahradilo ho Let's Encrypt DirectAdminu | Zapněte *Keep DirectAdmin's ACME off it* |
| 404 na `/api/...` | Starší DirectAdmin: nastavte *API* na legacy |
