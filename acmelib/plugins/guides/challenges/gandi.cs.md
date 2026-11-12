# Gandi LiveDNS - nastavení pro acme

acme prokazuje jména přes DNS-01 u Gandi: přes LiveDNS API v5 přidá svou hodnotu do sady záznamů TXT `_acme-challenge.JMÉNO` (`PATCH … add_rrset_values`, nebo `POST` pro novou sadu) a poté odebere jen svou hodnotu (`remove_rrset_values`). Přihlašuje se **osobním přístupovým tokenem** (personal access token; funguje i starší API klíč).

## Co potřebujete

- Doménu u Gandi, která používá **LiveDNS** (jmenné servery Gandi).
- Odchozí HTTPS z acme na `api.gandi.net` (port 443).
- TTL **300 s a více** - kratší Gandi nepřijme.

## Nastavení Gandi

1. Přihlaste se na `admin.gandi.net` → **Organizations → (vaše organizace) → Sharing → Personal Access Tokens → Create a token** (nebo *User settings → Authentication options* pro osobní token).
2. Zvolte organizaci, **název** (`acme`) a **platnost** (nezapomeňte token před vypršením obnovit).
3. **Resources**: *Restrict to selected products* → jen domény, které smí acme měnit.
4. **Permissions**: jen **Manage domain name technical configurations**.
5. Vytvořte a zkopírujte token (zobrazí se jen jednou).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Signs in with | `a personal access token` (nebo `an API key (older)`) |
| Token | Token |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `300`; 300 a více |
| API address | (pokročilé) Výchozí `https://api.gandi.net/v5/livedns` |

## Kontrola

- **Test** v acme vypíše domény LiveDNS, které token vidí. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: Bearer $TOKEN" https://api.gandi.net/v5/livedns/domains
  curl -s -H "Authorization: Bearer $TOKEN" \
    https://api.gandi.net/v5/livedns/domains/example.com/records/_acme-challenge/TXT
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | Špatný nebo prošlý token; nebo *Signs in with* neodpovídá druhu údaje. |
| `403` | Token nemá *Manage domain name technical configurations*, nebo doména není mezi jeho prostředky. |
| Doména není v seznamu | Nepoužívá LiveDNS (externí jmenné servery) - přepněte ji na LiveDNS nebo použijte jinou validaci. |
| TTL odmítnuto | Nastavte *TTL (s)* na 300 a více. |
