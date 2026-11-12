# Hetzner DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v zóně DNS u Hetzneru přes **Hetzner Console / Cloud API** (`api.hetzner.cloud`), kam se Hetzner DNS přesunulo: přidá svou hodnotu do sady TXT `_acme-challenge.JMÉNO` (`add_records`) a při úklidu odebere přesně svou hodnotu (`remove_records`), přičemž čeká na dokončení každé akce. **Staré API DNS Console (`dns.hetzner.com`) bylo vypnuto 2026-05-27; jeho tokeny nefungují.**

## Co potřebujete

- Zónu v projektu Hetzner Console (zóny ze starého DNS Console je třeba tam převést).
- Odchozí HTTPS z acme na `api.hetzner.cloud` (port 443).

## Nastavení Hetzneru

1. Hetzner Console → **projekt, ve kterém je zóna** → **Security → API tokens → Generate API token**.
2. Popis `acme`, oprávnění **Read & Write** (tokeny Hetzneru platí pro projekt; token jen pro čtení záznamy měnit nemůže).
3. Zkopírujte token (zobrazí se jen jednou).
4. Token smí v projektu cokoli: obsahuje-li projekt i servery, držte zóny DNS v samostatném projektu.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API token | Token projektu |
| Zone | např. `example.com`; prázdné = najde se podle jména |
| TTL (s) | (pokročilé) Výchozí `60`; použije se jen pro novou sadu (existující si ponechá svůj) |

## Kontrola

- **Test** v acme vypíše zóny, které token vidí. Nic nemění.
- Pomocí CLI `hcloud` nebo curl:

  ```sh
  curl -s -H "Authorization: Bearer $HCLOUD_TOKEN" 'https://api.hetzner.cloud/v1/zones?name=example.com'
  dig +short TXT _acme-challenge.example.com @hydrogen.ns.hetzner.com
  ```

  (použijte jeden ze jmenných serverů zóny z `dig NS example.com`).

## Časté problémy

| Problém | Řešení |
|---|---|
| Odmítnutí s tím, že staré DNS Console už není | Použijte token projektu Hetzner Console, ne token `dns.hetzner.com`. |
| `401 unauthorized` | Špatný token, nebo token jiného projektu. |
| `403 forbidden` | Token jen pro čtení - vytvořte token s Read & Write. |
| `423 locked` | Na zóně běží jiná akce; acme to zkusí znovu. |
| Zóna se nenajde | Zóna je v jiném projektu. |
