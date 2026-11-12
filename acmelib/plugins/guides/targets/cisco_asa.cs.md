# Cisco Secure Firewall ASA - nastavení pro acme

acme používá **ASA HTTP Interface for Automation** - CLI přes HTTPS (`/admin/exec/...` a
`POST /admin/config`), které Cisco doporučuje místo starého ASA REST API. Trustpoint
zapsaný z PKCS#12 nelze obnovit, proto je každá obnova **novým trustpointem** se jménem s
datem:

```text
crypto ca trustpoint <tp>
exit
crypto ca import <tp> pkcs12 <nahodna-heslova-fraze> nointeractive
<PKCS#12 s řetězcem, base64>
quit
```

Pak `ssl trust-point <tp> <rozhraní>` pro každý zadaný řádek (a všude, kde byl uveden
starší trustpoint acme tohoto certifikátu), starší trustpointy acme, které žádné
`ssl trust-point` neuvádí, se odstraní (`no crypto ca trustpoint <old> noconfirm`) a
`write memory` vše uloží. Každá odpověď se čte kvůli `ERROR:` / `% Invalid`, protože 200
přijde i u neúspěšného příkazu.

Pro software ASA s HTTP rozhraním (přístup ASDM), fyzická zařízení, ASAv i Firepower v
režimu ASA. Typicky: VPN AnyConnect / Secure Client a portál ASDM / WebVPN.

## Co potřebujete

- Správu přes HTTPS (port ASDM, výchozí 443) dostupnou z acme na použitém rozhraní.
- Lokálního uživatele (nebo uživatele AAA) s **privilege 15**, který smí používat HTTP.
- Jména rozhraní (`nameif`) nebo domény, které mají certifikát prezentovat.

## Nastavení ASA

1. Zapněte HTTP server a povolte adresu acme na správcovském rozhraní:

   ```text
   configure terminal
   http server enable
   http 198.51.100.10 255.255.255.255 management
   ```

2. Vytvořte uživatele a nechte HTTP používat lokální databázi:

   ```text
   username acme password <silne-heslo> privilege 15
   aaa authentication http console LOCAL
   ```

3. Basic autentizaci ASA přijímá jen od povolených řetězců User-Agent. `ASDM` je povolen
   ve výchozím stavu; pokud jste to omezili přes `http server basic-auth-client`, přidejte
   řetězec, který acme posílá:

   ```text
   http server basic-auth-client ASDM
   write memory
   ```

4. Poznamenejte si, kam certifikát patří: `show running-config ssl` (např. `outside`,
   `outside vpnlb-ip`, `domain vpn.example.com`).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | Správcovská adresa ASA a port ASDM (`443`) |
| User | Uživatel s privilege 15 (`aaa authentication http console LOCAL`) |
| Password | Jeho heslo |
| User-Agent (pokročilé) | Výchozí `ASDM` - musí být povolen v `http server basic-auth-client` |
| Check the device's certificate / CA certificate | Vypnout jen dokud má ASA self-signed certifikát |
| ssl trust-point (nasazení) | Jeden na řádek: rozhraní (`outside`), `outside vpnlb-ip`, `domain vpn.example.com`, nebo `-` pro výchozí všech rozhraní; prázdné: jen tam, kde byl starší trustpoint acme |
| PKCS#12 kind (nasazení, pokročilé) | `3DES (older ASA)` (výchozí) nebo `AES-256` |
| Save the configuration (write memory) (nasazení) | Zapnuto |
| Previous versions to keep (pokročilé) | Výchozí 1; **`-1`, pokud se trustpointy používají i pro IKEv2/IPsec** (acme tam nehledá) |
| Check what is served | např. `vpn.example.com:443` |

## Ověření

- **Try** spustí `show version` a spočítá trustpointy:
  `signed in to ...: Cisco Adaptive Security Appliance Software Version 9.x; N trustpoints`.
- Na ASA:

  ```text
  show crypto ca certificates
  show running-config ssl
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 / 403 | Chybné údaje, uživatel nemá privilege 15, nebo chybí `aaa authentication http console LOCAL` |
| Odmítnuto kvůli User-Agent | Přidejte `http server basic-auth-client ASDM` (nebo nastavte *User-Agent* v acme) |
| Vypršení spojení | Chybí `http <ip-acme> <maska> <rozhraní>`, nebo chybný port |
| `Import PKCS12 operation` nedokončena | Na starším softwaru ASA zkuste *PKCS#12 kind* `3DES` |
| `ERROR: ... trustpoint` při odstraňování | Starý trustpoint se používá jinde (IPsec) - nastavte *keep* na `-1` |
| Po restartu ztraceno | Zapněte *Save the configuration* |
| Failover pár | Konfigurace se na standby replikuje, jen je-li zapnutá replikace failoveru - ověřte |
