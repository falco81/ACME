# Plesk - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS serveru **Plesk** (Plesk Obsidian a Onyx s XML API), přes jeho XML API (`POST https://PLESK:8443/enterprise/control/agent.php`). Najde doménu (`site get`), načte její záznamy (`dns get_rec`), pro každou hodnotu přidá jeden TXT záznam (`dns add_rec`) a ten smaže podle id (`dns del_rec`). Ostatní hodnoty na jméně zůstanou.

## Co potřebujete

- Server Plesk, jehož DNS server (BIND) je pro doménu autoritativní - jmenné servery domény ukazují na Plesk.
- HTTPS z acme na panel Plesku, obvykle **TCP 8443**.
- Buď přihlášení do Plesku, které smí spravovat DNS domény (administrátor, nebo **zákazník**, kterému doména patří), nebo **secret key** XML API.

## Nastavení Plesku

**Varianta A - secret key (doporučeno):** na serveru Plesk jako root vytvořte klíč vázaný na adresu acme:

```sh
plesk bin secret_key --create -ip-address 203.0.113.10 -description "acme DNS-01"
```

Příkaz vypíše klíč. Je přijímán jen z této IP adresy. (Výpis klíčů `plesk bin secret_key --list`, odstranění `plesk bin secret_key --delete -key KLIC`.)

**Varianta B - jméno a heslo:** použijte raději účet **zákazníka**, kterému doména patří, než `admin`:

1. **Customers →** zákazník → ověřte, že je zapnuto *Access to Customer Panel* a zákazník má oprávnění ke správě DNS zóny (Service Plan → **Permissions → Management of DNS zone**).
2. V acme použijte přihlašovací jméno a heslo tohoto zákazníka.

Ověřte také, že je DNS pro doménu zapnuté: **Websites & Domains →** doména → **DNS Settings** (zóna není vypnutá ani *Secondary*).

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Plesk address | `plesk.example.com` (bez portu 8443; lze i `https://…`) |
| Sign in with | `a secret key` nebo `login and password` |
| Secret key | klíč z varianty A |
| Login / Password | údaje zákazníka (nebo administrátora), varianta B |
| Domain | prázdné (nejdelší doména serveru, do které jméno patří), nebo doména |
| Check the server's certificate | zapnuto; vypněte jen u self-signed certifikátu panelu (pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše domény; nic nemění.
- Po objednávce: **Websites & Domains →** doména → **DNS Settings**: TXT záznam `_acme-challenge` se objeví a zase zmizí. Na serveru:

```sh
dig +short TXT _acme-challenge.www.example.com @localhost
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Chyba 1001 „Authentication failed“ | Špatné jméno/heslo, nebo je secret key použit z jiné IP, než pro kterou byl vytvořen. |
| Odepřeno u `add_rec` | Zákazník nemá v plánu *Management of DNS zone*. |
| Doména nenalezena | Doména patří jinému zákazníkovi, nebo je jméno alias / subdoména jiného webu - vyplňte *Domain*. |
| Záznam je v Plesku, ale ne veřejně | Registrátor neukazuje na jmenné servery Plesku, nebo je zóna vypnutá/sekundární. |
