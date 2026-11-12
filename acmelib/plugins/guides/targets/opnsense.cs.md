# OPNsense - nastavení pro acme

acme se přihlásí k API OPNsense klíčem a tajemstvím API, přidá mezilehlé certifikáty jako
CA (`/api/trust/ca/add`, pod jménem `acme-ca-<id>`), naimportuje certifikát s klíčem do
**System → Trust → Certificates** jako `acme-<jméno>-<datum>-<sériové číslo>`
(`/api/trust/cert/add`, `action: import`) a smaže starší certifikáty acme nad počet
*Previous versions to keep* (ten, který se ještě používá, zůstane). Se zapnutým *Replace
in place* zapíše každé obnovení do staršího certifikátu acme (`/api/trust/cert/set/<uuid>`),
takže služby, které jste na něj nasměrovali, ho dál používají. Certifikát webového GUI v API
není: s volbou *Web GUI certificate* ho acme nastaví **přes SSH jako root** malým PHP
skriptem a spustí `configctl webgui restart`.

Pro OPNsense **24.7 a novější** (trust API).

## Co potřebujete

- OPNsense 24.7 nebo novější.
- Síťový přístup z acme na webové GUI / API: **TCP 443** (nebo port, na kterém GUI běží).
- Jen pro *Web GUI certificate*: SSH z acme, **TCP 22**, jako `root`.

## Nastavení OPNsense

1. Vytvořte samostatného uživatele: **System → Access → Users → +**, např. `acme`. Shell ani
   skupinu s plnými právy správce nepotřebuje.
2. Dejte mu jen potřebná oprávnění: u uživatele (nebo skupiny) **Effective Privileges** →
   přidejte **System: Certificate Manager** a na verzích, které ho nabízejí, i **System:
   Trust**. Uložte.
3. Vytvořte klíč API: úprava uživatele → **API keys → +**. OPNsense stáhne soubor s
   `key=` a `secret=` - uschovejte ho, tajemství se už znovu nezobrazí.
4. Pokud přístup ke GUI omezujete (**System → Settings → Administration → Listen
   Interfaces**, pravidla firewallu na správcovském rozhraní), povolte IP adresu serveru
   acme na port GUI.
5. Jen pro *Web GUI certificate*: **System → Settings → Administration → Secure Shell** →
   *Enable Secure Shell*, *Permit root user login*; pak vložte veřejný klíč acme rootovi:
   **System → Access → Users → root → Authorized keys**. Přihlášení klíčem je lepší než
   heslem.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP webového GUI OPNsense, např. `opnsense.example.local` |
| HTTPS port | `443`, nebo port GUI |
| API key | `key` ze staženého souboru |
| API secret | `secret` ze staženého souboru |
| Check the device's certificate | Zapnuto; vypnout jen dokud má OPNsense self-signed certifikát |
| CA certificate (pokročilé) | CA současného certifikátu GUI, pokud není veřejná |
| SSH port / User / Sign in with / The SSH key (pokročilé) | Jen pro webové GUI: `22`, `root`, klíč, jehož veřejná část je u roota |
| Web GUI certificate (nasazení) | Zapnout, má-li webové GUI používat nový certifikát (potřebuje SSH) |
| Replace in place (nasazení, pokročilé) | Zapnout, pokud na certifikát acme ukazují služby (HAProxy, OpenVPN, captive portal...) a mají ho dál používat |
| Previous versions to keep (pokročilé) | Kolik starších certifikátů acme ponechat (výchozí 2, `-1` ponechá vše) |
| Check what is served | např. `opnsense.example.local:443` |

## Ověření

- Na cíli stiskněte **Try**: acme přečte verzi (`/api/core/firmware/info`) a seznam
  certifikátů a odpoví `signed in to ..., OPNsense x.y, N certificates`.
- Po nasazení je certifikát v **System → Trust → Certificates**, mezilehlé v **System →
  Trust → Authorities**.
- Na zařízení (SSH) odkaz na certifikát GUI:

  ```sh
  grep -A3 '<webgui>' /conf/config.xml | grep ssl-certref
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `403` při Try | Špatný klíč nebo tajemství, nebo uživateli chybí *System: Certificate Manager* / *System: Trust*. Je-li odmítnuto jen čtení verze, ověřte, které oprávnění na vaší verzi pokrývá `core/firmware`. |
| `404` na `/api/trust/...` | OPNsense starší než 24.7 - aktualizujte. |
| Chyba TLS | GUI má ještě self-signed certifikát: vložte jeho CA do *CA certificate*, nebo do prvního nasazení vypněte *Check the device's certificate*. |
| `the web GUI is set over SSH` | *Web GUI certificate* je zapnuté, ale přihlášení SSH je prázdné. |
| `the old ... stays (still used?)` | Starší certifikát ještě používá nějaká služba („Item in use by“); přesuňte službu nebo použijte *Replace in place*. |
| Služba po *Replace in place* ukazuje starý certifikát | Služby ho načtou znovu až po restartu - restartujte je v OPNsense. |
