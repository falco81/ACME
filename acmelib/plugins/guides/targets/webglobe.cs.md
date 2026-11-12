# Webglobe hosting - nastavení pro acme

acme uloží certifikát jako **vlastní SSL certifikát** domény hostované u Webglobe, a to
přes Webglobe API (`api.webglobe.com`). Přihlásí se (`POST /auth/login` s loginem a API
klíčem, nebo heslem), najde doménu podle jména (`GET /domains`), nechá Webglobe nejdřív
zkontrolovat certifikát, klíč a řetězec (`POST /{domainId}/ssl/validate`) a pak je uloží
(`POST /{domainId}/ssl/own-certificate`). Volitelně zapne nebo vypne přesměrování
http → https (`POST /{domainId}/ssl/httpsRedirect`). acme nic nemaže: starší vlastní
certifikáty můžete odstranit v administraci Webglobe.

**Webglobe přijímá vlastní certifikáty zákazníků jen s placenou podporou.** Bez ní API
odmítne s kódem 3 („Access to requested module is denied“) a acme to oznámí.

Přihlášení je stejné jako u validace přes DNS Webglobe.

## Co potřebujete

- Účet Webglobe s **webhostingem** domény a placenou podporou, která vlastní certifikáty
  povoluje.
- Odchozí HTTPS z acme na `api.webglobe.com` (**TCP 443**).
- **Veřejnou IP adresu** acme (nebo síť) - API klíče Webglobe fungují jen z povolených IP.

## Nastavení Webglobe

1. Doporučeno: vytvořte podúčet, který vidí jen domény potřebné pro acme: administrace
   Webglobe → **My account → Users** → přidejte uživatele a dejte mu přístup k doméně.
2. Přihlaste se jako tento uživatel a vytvořte API klíč: **My account → API keys** → nový
   klíč → povolte veřejnou IP adresu acme (nebo síť). Webglobe odmítne klíč z jakékoli jiné
   adresy i klíč bez adresy. **Klíč se zobrazí jen jednou** - zkopírujte si ho.
3. Nemůžete-li použít API klíč, heslo funguje jen u účtu **bez dvoufázového přihlášení**.
4. Poznamenejte si doménu přesně tak, jak ji administrace uvádí (nebo její číselné ID).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Login | Login (e-mail) (pod)účtu, např. `you@example.cz` |
| Sign in with | *an API key* (doporučeno; funguje i s dvoufázovým přihlášením) nebo *the password* |
| API key | Klíč z kroku 2 |
| Password | Jen pro přihlášení heslem |
| API (pokročilé) | `api.webglobe.com` (produkce) |
| API address (pokročilé) | Prázdné |
| Domain | Hostovaná doména, např. `example.cz` (nebo její ID) |
| Let Webglobe check it first (nasazení) | Zapnuto (výchozí) |
| Redirect http to https (nasazení) | *leave as it is*, *on* nebo *off* |
| Check what is served | např. `www.example.cz:443` |

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, najde doménu a přečte její certifikáty (nic
  nemění): `Webglobe: signed in; the domain example.cz is ID 12345, N certificate(s) there`.
- V administraci Webglobe ukazuje sekce SSL domény nový vlastní certifikát.
- Z libovolného počítače:

  ```sh
  openssl s_client -connect www.example.cz:443 -servername www.example.cz </dev/null 2>/dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Webglobe refused ...: ... paid support (code 3)` | Vlastní certifikáty vyžadují placenou podporu Webglobe - objednejte ji, nebo použijte certifikát od Webglobe. |
| Přihlášení API klíčem odmítnuto | Veřejná IP acme není u klíče povolena, nebo login ke klíči nepatří. |
| Přihlášení heslem odmítnuto | Účet má dvoufázové přihlášení - použijte API klíč. |
| `the domain ... is not in this Webglobe account` | Překlep, nebo ji podúčet nevidí. |
| Kontrola Webglobe selže | Klíč a certifikát k sobě nepatří, nebo je neúplný řetězec - viz detail úlohy. |
