# Virtualmin - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS (BIND) serveru **Virtualmin**, přes jeho Remote API (`POST https://SERVER:10000/virtual-server/remote.cgi`), které spouští programy příkazové řádky Virtualminu: `list-domains --with-feature dns` (zóny), `modify-dns --add-record-with-ttl` pro přidání naší TXT hodnoty, `modify-dns --remove-record "NAME. TXT VALUE"` - **vždy s hodnotou**, takže ostatní hodnoty na jménu zůstanou - a `get-dns --type TXT` pro zpětné načtení zóny po každé změně. `modify-dns` sám zvýší sériové číslo a znovu načte BIND.

## Co potřebujete

- Server Virtualmin (GPL nebo Pro), jehož BIND je pro doménu autoritativní, a virtuální server se zapnutou funkcí **DNS domain**.
- HTTPS z acme na Webmin/Virtualmin, obvykle **TCP 10000**.
- Přihlašovací údaje **master administrátora** - Virtualmin otevírá Remote API jen master administrátorovi. Vlastní token ani API klíč nemá.

## Nastavení Virtualminu

1. Rozhodněte, kterého master administrátora acme použije: `root`, nebo vyhrazeného uživatele Webminu, kterého Virtualmin bere jako master administrátora (Webmin → **Webmin Users** → uživatel s plným přístupem k modulu *Virtualmin Virtual Servers*; **Test** v acme řekne, zda ho Remote API přijme).
2. Dvoufázové ověření musí mít tento uživatel **vypnuté** (Remote API používá HTTP basic autentizaci).
3. Omezte, kdo se k Webminu dostane, na acme a své administrátory: **Webmin → Webmin Configuration → IP Access Control** → *Only allow from listed addresses*, přidejte adresu acme.
4. Ověřte, že doména má DNS: **Virtualmin →** virtuální server → **Edit Virtual Server → Enabled features → DNS domain enabled**.

Kontrola ze sítě acme:

```sh
curl -u 'root:HESLO' -d 'program=list-domains&with-feature=dns&name-only=' \
  https://server.example.com:10000/virtual-server/remote.cgi
# example.com ... Exit status: 0
```

**Pozor:** master administrátor ovládá celý server - heslo mějte jen v acme a IP Access Control přísné.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Virtualmin address | `server.example.com` (bez portu 10000; lze i `https://…`) |
| Master administrator | `root` (nebo váš master admin) |
| Password | jeho heslo |
| Virtual server | doména, jejíž zóna jméno obsahuje (načtěte seznam a vyberte); prázdné: dohledá se |
| TTL (s) | 60 (pokročilé) |
| Check the server's certificate | zapnuto; vypněte jen u self-signed certifikátu Webminu (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se; s vyplněným *Virtual server* načte TXT záznamy zóny přes `get-dns`, jinak vypíše virtuální servery s DNS. Nic nemění.
- Po objednávce: **Virtualmin →** server → **DNS Settings → DNS Records**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / vrácena přihlašovací stránka | Špatné heslo, zapnuté 2FA, nebo uživatel není master administrátor. |
| Connection refused | Port 10000 je blokovaný, nebo adresa acme není v IP Access Control Webminu. |
| „change did not happen“ v úloze | Jméno není v zóně tohoto virtuálního serveru - podřízený server má záznamy v zóně rodiče: nastavte *Virtual server* na rodiče. |
| `Exit status: 1` z `modify-dns` | Virtuální server nemá funkci DNS, nebo se BIND nepodařilo znovu načíst - viz modul BIND ve Webminu. |
