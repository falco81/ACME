# bunny.net DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v zóně bunny.net DNS: přes API bunny.net (`api.bunny.net`) přidá do zóny záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam. Každá hodnota je samostatný záznam, takže se souběžné objednávky navzájem neruší.

## Co potřebujete

- Zónu přidanou v sekci **DNS** v rozhraní bunny.net, s doménou delegovanou na jmenné servery bunny.net.
- Klíč API účtu. **bunny.net nemá klíč omezený jen na DNS: tento klíč smí v účtu cokoli** - chraňte ho stejně jako heslo.
- Odchozí HTTPS z acme na `api.bunny.net` (port 443).

## Nastavení bunny.net

1. Přihlaste se na `dash.bunny.net`.
2. Přejděte na **Account settings → API key** (v novějším rozhraní: nabídka účtu → **Account settings → API**).
3. Zkopírujte klíč API. Při podezření na únik ho tam resetujte a aktualizujte v acme.
4. Zvažte samostatný účet bunny.net (nebo účet člena týmu, pokud to váš tarif nabízí), který drží jen zóny DNS, aby klíč nedosáhl na CDN a úložiště.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API key | Klíč API účtu |
| Zone | např. `example.com`; prázdné = nejdelší zóna účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `60` |
| Wait until it is seen by, Wait at least, Resolvers | (pokročilé) jak acme čeká na záznam - výchozí hodnoty stačí |

## Kontrola

- **Test** v acme vypíše zóny DNS účtu. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "AccessKey: $BUNNY_API_KEY" 'https://api.bunny.net/dnszone?page=1&perPage=10'
  dig +short TXT _acme-challenge.example.com @kiki.bunny.net
  ```

  (použijte jeden ze jmenných serverů zóny z `dig NS example.com`).

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný klíč API, nebo byl resetován - zkopírujte ho znovu. |
| Zóna se nenajde | Zóna není v tomto účtu bunny.net; vyplňte přesně *Zone*. |
| CA záznam nevidí | Doména není delegovaná na jmenné servery bunny.net - zkontrolujte `dig NS example.com`. |
