# pfSense - nastavení pro acme

pfSense CE nemá oficiální REST API, proto acme pracuje **přes SSH**: spustí PHP skript s
vlastními funkcemi pfSense (`cert_import()`), který přidá certifikát (celý řetězec + klíč)
do správce certifikátů jako `acme-<jméno>-<datum>-<sériové číslo>`, nastaví ho webovému
GUI (a spustí `/etc/rc.restart_webgui`), odstraní starší certifikáty acme nad počet
*Previous versions to keep*, které nic nepoužívá (kontrola funkcí pfSense `cert_in_use()`,
kde existuje), a uloží vše přes `write_config()` - jedna revize konfigurace na obnovení.
*Force* na certifikát, který už tam je, ho upraví na místě, takže služby, které na něj
ukazují, ho dál používají.

Pro pfSense CE i pfSense Plus s přístupem přes SSH.

## Co potřebujete

- SSH z acme na pfSense, **TCP 22** (nebo váš port SSH).
- Účet, který smí spouštět PHP s konfigurací pfSense: `admin` (výchozí) nebo `root`.
- SSH klíč acme (vytvořený v acme u pole *The SSH key* cíle, nebo váš vlastní).

## Nastavení pfSense

1. Zapněte SSH: **System → Advanced → Admin Access → Secure Shell** → zaškrtněte *Enable
   Secure Shell*. Při přihlašování klíčem (doporučeno) nastavte *SSHd Key Only* na **Public
   Key Only**. Uložte.
2. Přidejte veřejný klíč acme k účtu: **System → User Manager → Users → admin (úprava)** →
   *Authorized SSH Keys* → vložte veřejný klíč → Save.
3. Povolte serveru acme průchod firewallem na port SSH na rozhraní, kudy acme přichází
   (**Firewall → Rules → <rozhraní>**: pass TCP z IP acme na *This Firewall*, port 22).
   Omezte to jen na tuto IP.
4. Volitelně ověřte, že PHP je ve výchozí cestě:

   ```sh
   ls -l /usr/local/bin/php
   ```

**Pozor**: účet musí být `admin` nebo `root` (nebo jiný se stejnými právy v shellu) -
skript zapisuje přímo konfiguraci. Omezený uživatel to nezvládne.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP pfSense |
| SSH port | `22` |
| User | `admin` (výchozí) nebo `root` |
| Sign in with | *a private key* (doporučeno) nebo *a password* |
| The SSH key | Klíč, jehož veřejnou část jste přidali v kroku 2 |
| Password | Jen při přihlášení heslem |
| Host key (pokročilé) | Řádek `known_hosts`, nebo prázdné se zapnutým *Trust the first host key seen* |
| Through a connector (pokročilé) | Server konektoru, je-li pfSense dostupný jen z jiné sítě |
| PHP (pokročilé) | `/usr/local/bin/php` |
| Timeout (s) (pokročilé) | `60` |
| Web GUI certificate (nasazení) | Zapnuto (výchozí): webové GUI použije nový certifikát |
| Previous versions to keep (pokročilé) | Výchozí 2, `-1` ponechá vše |
| Check what is served | např. `pfsense.example.local:443` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí přes SSH, spustí PHP a odpoví
  `signed in to ..., pfSense <verze>`.
- V pfSense: **System → Cert. Manager → Certificates** obsahuje `acme-...`;
  **System → Advanced → Admin Access → SSL/TLS Certificate** ho ukazuje pro GUI.
- **Diagnostics → Backup & Restore → Config History** má záznam
  `acme: certificate acme-...`.

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení SSH odmítnuto | Veřejný klíč není u účtu, nebo nesedí *SSHd Key Only* a přihlášení heslem; chybí pravidlo firewallu. |
| Objeví se konzolové menu / skript nic neudělá | Použijte `admin` nebo `root`; zkontrolujte cestu *PHP*. |
| `the PHP script on pfSense failed` | Přečtěte zobrazený výstup; neobvyklé verzi pfSense mohou funkce chybět - podívejte se do `/etc/inc/certs.inc`. |
| `the old ... is still used: kept` | Používá ho OpenVPN, IPsec, captive portal nebo balíček; přepněte je na nový certifikát, příště se odstraní. |
| GUI je chvíli nedostupné | Očekávané: webové GUI se po změně restartuje. |
