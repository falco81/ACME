# Vlastní skript - nastavení pro acme

S touto validací acme prokazuje jména metodou DNS-01 pomocí **programu na stroji acme**, který si napíšete: acme ho spustí, aby TXT záznam vložil (`present`) a zase odebral (`cleanup`), a pak čeká, dokud hodnotu neodpovídají jmenné servery zóny. Hodí se pro poskytovatele DNS, pro kterého acme nemá modul. Program lze volat způsobem acme, dehydrated nebo lego `exec`.

## Co potřebujete

- Spustitelný program (shell, Python, …) na **každém uzlu acme**, který může spouštět objednávky, na stejné absolutní cestě.
- Vše, co program potřebuje k přístupu do vašeho DNS (CLI, API klíče, síťový přístup).
- Program musí při úspěchu **skončit kódem 0**; cokoli jiného objednávku shodí s jeho posledním výstupem.

## Nastavení programu

1. Umístěte ho tam, kde ho smí měnit jen root, např. `/etc/acme/hooks/dns.sh`, vlastník root, práva `0755`. Běží jako uživatel **acme**.
2. Příklad pro *Called as* = `PROGRAM present|cleanup RECORD VALUE`:

   ```sh
   #!/bin/sh
   # /etc/acme/hooks/dns.sh present|cleanup RECORD VALUE
   set -e
   case "$1" in
     present) my-dns-cli add "$2" TXT "$3" --ttl "$ACME_TTL" ;;
     cleanup) my-dns-cli del "$2" TXT "$3" ;;
     *) exit 0 ;;
   esac
   ```

3. Pravidla pro program:
   - Hodnotu **přidejte** vedle těch, které už na jméně jsou, a při úklidu **odeberte jen ji** - `example.com` a `*.example.com` používají stejné jméno se dvěma hodnotami.
   - Vraťte se až poté, co poskytovatel změnu přijal; na jmenné servery pak acme čeká sám.
   - Skončete do *Timeout (s)* (výchozí 120 s).
4. Prostředí obsahuje jen `PATH`, `HOME`, `LANG`, co nastavíte v acme, a:

   | Proměnná | Hodnota |
   |---|---|
   | `ACME_ACTION` | `present` nebo `cleanup` |
   | `ACME_NAME` | prokazované jméno (`www.example.com`) |
   | `ACME_RECORD` | kam patří TXT (po následování CNAME) |
   | `ACME_CHALLENGE_NAME` | `_acme-challenge.www.example.com` |
   | `ACME_TXT` | hodnota TXT |
   | `ACME_TOKEN` | ACME token |
   | `ACME_ZONE` | zóna, je-li známa |
   | `ACME_TTL` | TTL |

5. Zkopírujte program na všechny uzly (`install -o root -g root -m 0755 dns.sh /etc/acme/hooks/`).

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Program | `/etc/acme/hooks/dns.sh` - absolutní cesta |
| Called as | styl acme, `dehydrated` (`deploy_challenge\|clean_challenge NAME TOKEN VALUE`) nebo `lego` (`present\|cleanup RECORD. VALUE`) |
| More environment | řádky `KEY=VALUE`, které program potřebuje (ne tajné) |
| Secret environment | řádky `KEY=VALUE` uložené zapečetěně - API klíče pro program |
| Timeout (s) | 120 (pokročilé) |
| TTL (s) | 60, předává se jako `ACME_TTL` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: jen ověří, že program existuje a je spustitelný - **nespouští ho**. Zkušební běh (dry run) certifikátu ho spustí doopravdy.
- Ručně jako uživatel acme:

```sh
sudo -u acme env ACME_TTL=60 /etc/acme/hooks/dns.sh present _acme-challenge.www.example.com testvalue; echo "exit $?"
dig +short TXT _acme-challenge.www.example.com @ns1.example.com
sudo -u acme /etc/acme/hooks/dns.sh cleanup _acme-challenge.www.example.com testvalue
```

## Časté problémy

| Problém | Řešení |
|---|---|
| „is not there or not executable“ | Špatná cesta, chybí `chmod +x`, nebo soubor na tomto uzlu chybí. |
| „ended with 1: …“ | Program selhal - zobrazí se jeho poslední výstup; celý je v debug logu úlohy. |
| Ručně jako root funguje, v acme ne | Běží jako uživatel **acme** s minimálním prostředím - nastavte proměnné, které potřebuje. |
| „did not finish within 120 s“ | Poskytovatel je pomalý - zvyšte *Timeout (s)*, nebo ať program skončí dřív. |
