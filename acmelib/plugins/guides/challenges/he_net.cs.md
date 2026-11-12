# Hurricane Electric (dns.he.net) - nastavení pro acme

acme prokazuje jména přes DNS-01 v bezplatném DNS Hurricane Electric (`dns.he.net`) pomocí jeho **dynamické aktualizace TXT** (`dyn.dns.he.net/nic/update`) - jiné API dns.he.net nemá. Záznam TXT `_acme-challenge.JMÉNO` proto musí být **nejprve vytvořen ručně**, se zapnutým dynamickým DNS a vlastním klíčem; acme pak jen mění jeho hodnotu.

Omezení: záznam drží **jednu hodnotu** - ta se nahrazuje, nikdy nepřidává. `example.com` a `*.example.com` v jednom certifikátu potřebují u jednoho jména dvě hodnoty, proto je acme prokazuje postupně. Úklid záznam smazat nemůže: nastaví ho na *Value when idle*.

## Co potřebujete

- Zónu hostovanou na dns.he.net (doména delegovaná na `ns1`-`ns5.he.net`).
- Odchozí HTTPS z acme na `dyn.dns.he.net` (port 443).

## Nastavení dns.he.net

Pro **každé** jméno certifikátu:

1. Přihlaste se na `dns.he.net` → zóna → **New TXT**.
2. **Name**: `_acme-challenge.www.example.com` (pro `example.com` i `*.example.com`: `_acme-challenge.example.com`), **Text data**: libovolná hodnota (např. `acme-idle`), **TTL**: 5 minut (300).
3. Zaškrtněte **Enable entry for dynamic dns** a uložte.
4. Klikněte na **tlačítko s kruhovými šipkami** vedle nového záznamu → **Generate a key** → zkopírujte klíč. Jeden klíč na záznam.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Records and their keys | Jeden řádek na záznam: celé jméno, pak jeho klíč, např. `_acme-challenge.example.com  Kx9…`. Řádek jen s klíčem platí pro všechna neuvedená jména |
| Zone | např. `example.com`; prázdné = najde se podle SOA |
| Value when idle | (pokročilé) Na co se záznam při úklidu nastaví, výchozí `acme-idle` |

Příklad:

```text
_acme-challenge.example.com      Kx9...
_acme-challenge.www.example.com  P2b...
```

## Kontrola

- **Test** v acme ověří na jmenných serverech HE, že každý uvedený záznam existuje. **Klíč nelze vyzkoušet bez změny záznamu.**
- Ručně (toto hodnotu změní):

  ```sh
  curl -s -d 'hostname=_acme-challenge.example.com' -d "password=$KEY" -d 'txt=test' \
    https://dyn.dns.he.net/nic/update
  dig +short TXT _acme-challenge.example.com @ns1.he.net
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `badauth` | Špatný klíč pro daný záznam, nebo není zaškrtnuto *Enable entry for dynamic dns*. |
| `no TXT record at HE - make it first` | Vytvořte záznam TXT ručně (kroky 1-3). |
| `interval` | dns.he.net omezuje četnost aktualizací; acme to zkusí později. |
| Druhé jméno certifikátu čeká | Očekávané: jedna hodnota na jméno najednou. |
