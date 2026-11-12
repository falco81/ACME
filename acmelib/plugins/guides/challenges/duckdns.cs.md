# Duck DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 u Duck DNS (bezplatná jména pod `duckdns.org`): přes aktualizační URL Duck DNS nastaví hodnotu TXT jednoho z vašich jmen Duck DNS a poté ji vymaže. **Duck DNS drží jednu hodnotu TXT na jméno**, kterou vrací pro toto jméno i všechna jména pod ním - proto se `myhome.duckdns.org` a `*.myhome.duckdns.org` v jednom certifikátu prokazují postupně. Přes jméno Duck DNS lze záznamem CNAME prokázat i vaši vlastní doménu.

## Co potřebujete

- Účet Duck DNS s jedním nebo více jmény (např. `myhome`).
- Odchozí HTTPS z acme na `www.duckdns.org` (port 443).
- Pro vlastní doménu: přístup k jejímu DNS pro přidání jednoho CNAME na jméno.

## Nastavení Duck DNS

1. Přihlaste se na `duckdns.org` (některým z nabízených poskytovatelů přihlášení).
2. Zkopírujte **token** zobrazený nahoře na stránce. Je to jediný přihlašovací údaj Duck DNS a může měnit všechna jména účtu - chraňte ho.
3. Přidejte jména (sub domains), která chcete používat, pokud ještě neexistují.
4. Chcete-li prokázat jméno **vlastní** domény, přidejte jednou do jejího DNS:

   ```text
   _acme-challenge.www.example.com.  3600  IN  CNAME  myhome.duckdns.org.
   ```

   Jedno jméno Duck DNS drží najednou jen jednu hodnotu, proto použijte pro každé prokazované jméno samostatné jméno Duck DNS, nebo počítejte s tím, že se prokazují postupně.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Token | Token účtu |
| Duck DNS names | Jména, jejichž hodnotu TXT smí acme nastavit, jedno na řádek (`myhome` nebo `myhome.duckdns.org`) |
| Zone | (pokročilé) Prázdné = jméno Duck DNS, pod kterým záznam leží |
| API address | (pokročilé) Výchozí `https://www.duckdns.org/update` |

## Kontrola

- **Test** v acme jen ověří, že je vyplněno jméno a token - **token nelze vyzkoušet bez změny hodnoty TXT**.
- Ručně (toto hodnotu TXT jména změní):

  ```sh
  curl -s "https://www.duckdns.org/update?domains=myhome&token=$TOKEN&txt=test&verbose=true"
  dig +short TXT myhome.duckdns.org
  curl -s "https://www.duckdns.org/update?domains=myhome&token=$TOKEN&txt=test&clear=true"
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `KO` | Špatný token, nebo jméno není v účtu. Víc Duck DNS neřekne. |
| Druhé jméno certifikátu čeká | Očekávané: jedna hodnota na jméno najednou - acme je prokazuje postupně. |
| Vlastní jméno selže | CNAME `_acme-challenge` chybí nebo vede na jméno Duck DNS, které není v *Duck DNS names*. |
