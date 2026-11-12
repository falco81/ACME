# NS1 (IBM NS1 Connect) - nastavení pro acme

acme prokazuje jména metodou DNS-01 v zóně u NS1 / IBM NS1 Connect, přes API v1 (`https://api.nsone.net/v1`, hlavička `X-NSONE-Key`). Vypíše zóny, načte TXT záznam na `_acme-challenge.JMÉNO`, přidá svou odpověď a záznam zapíše zpět (`PUT` pro vytvoření, `POST` pro změnu) a při úklidu odebere jen svou odpověď (`DELETE`, nezbude-li žádná). Ostatní odpovědi zapíše zpět přesně tak, jak je načetl.

NS1 nemá volání, které odebere jednu odpověď, takže změna **stejného** TXT záznamu provedená jinde ve stejné sekundě se může ztratit.

## Co potřebujete

- Zónu u NS1 (managed DNS) a u registrátora nastavené jmenné servery NS1.
- HTTPS (TCP 443) z acme na `api.nsone.net` (nebo na adresu vašeho privátního nasazení NS1 DDI).

## Nastavení NS1

1. Přihlaste se do portálu NS1 (`my.nsone.net` / IBM NS1 Connect).
2. **Account settings → Users & teams → API keys → Add key**, název `acme`.
3. Oprávnění - povolte jen:
   - **DNS → View zones**
   - **DNS → Manage zones**
   - vše ostatní (Data, Monitoring, Account, Security…) vypnuto.
4. V **omezení zón** klíče (allow list) vyberte jen zóny, které smí acme měnit.
5. Volitelně omezte klíč na IP adresu acme (**IP whitelist**).
6. Uložte a klíč zkopírujte.

Volitelná kontrola:

```sh
curl -H 'X-NSONE-Key: KLIC' https://api.nsone.net/v1/zones
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| API key | klíč |
| Zone | prázdné (nejdelší zóna účtu, do které jméno patří), nebo zóna |
| TTL (s) | 60 (pokročilé) |
| API address | `https://api.nsone.net/v1`; u privátního nasazení NS1 (DDI) jeho adresa (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše zóny, které klíč vidí; nic nemění.
- Po objednávce: portál → **Zones →** zóna: TXT záznam `_acme-challenge…` s odpovědí acme se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` „Unauthorized“ | Klíč je špatný, smazaný, nebo použitý z adresy mimo jeho IP whitelist. |
| `403` u PUT/POST | Klíč nemá **Manage zones**, nebo zóna není v jeho allow listu. |
| Zóna chybí ve výpisu | Omezení zón klíče ji vynechává, nebo je v jiném účtu. |
