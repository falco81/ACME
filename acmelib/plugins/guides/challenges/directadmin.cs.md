# DirectAdmin - nastavení pro acme

acme prokazuje jména přes DNS-01 v DNS serveru DirectAdmin: přes starší (legacy) API DirectAdminu (`CMD_API_DNS_CONTROL`, port 2222) přidá záznam TXT `_acme-challenge.JMÉNO` a znovu ho odebere podle jména a hodnoty; každou změnu si zpětně přečte. Nové API DirectAdminu (`/api/…`) volání pro DNS nemá, proto se používá to starší. Přihlašuje se jako uživatel DirectAdminu s **login key**.

## Co potřebujete

- Uživatele DirectAdminu, kterému domény patří, s povolenou správou DNS (zónu obsluhuje server, nebo jeho DNS cluster).
- Odchozí HTTPS z acme na port panelu **2222** (nebo zadaný port).
- TTL se neposílá: záznam dostane TTL zóny.

## Nastavení DirectAdminu

1. Přihlaste se do DirectAdminu jako uživatel, kterému domény patří.
2. **Account Manager → Login Keys → Create Key** (ve starších vzhledech: *Login Keys* v Advanced Features).
3. Vyplňte:
   - **Key Name**: `acme`; nastavte dlouhou náhodnou **Key Value** (nebo ji nechte vygenerovat) a zkopírujte ji.
   - **Expires On**: datum, nebo nikdy - nezapomeňte klíč obnovit.
   - **Allowed Commands**: jen `CMD_API_SHOW_DOMAINS` a `CMD_API_DNS_CONTROL`.
   - **Allowed IPs**: veřejná adresa acme.
4. Potvrďte heslem uživatele a uložte.
5. Admin nebo reseller může jednat za uživatele: jméno `admin|alice` s login key admina.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| DirectAdmin address | Panel, jak je dosažitelný: `server.example.com`, `host:port` nebo `https://…`; bez portu 2222 |
| User name | Uživatel, kterému domény patří (nebo `admin|user`) |
| Login key | Hodnota login key (funguje i heslo uživatele, ale nedoporučuje se) |
| Domain | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší z domén uživatele, ve které jméno leží |
| Check the server's certificate | (pokročilé) nechte zapnuté; vypněte jen má-li panel certifikát podepsaný sám sebou |

## Kontrola

- **Test** v acme se přihlásí a vypíše domény - nebo při vyplněné *Domain* spočítá její záznamy TXT. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -u "alice:$LOGIN_KEY" 'https://server.example.com:2222/CMD_API_SHOW_DOMAINS'
  curl -s -u "alice:$LOGIN_KEY" 'https://server.example.com:2222/CMD_API_DNS_CONTROL?domain=example.com&urlencoded=yes'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení odmítnuto / `401` | Špatný uživatel nebo klíč, klíč vypršel, nebo IP acme není v jeho *Allowed IPs*. |
| `error=1` … příkaz není povolen | Přidejte `CMD_API_DNS_CONTROL` (a `CMD_API_SHOW_DOMAINS`) do *Allowed Commands* klíče. |
| Spojení odmítnuto / vypršel čas | Port 2222 je pro adresu acme blokován firewallem serveru (CSF apod.). |
| Úloha hlásí, že záznam po smazání stále existuje | Odeberte ho ručně v **DNS Management** a nahlaste verzi DirectAdminu. |
