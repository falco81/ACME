# GoDaddy - nastavení pro acme

acme prokazuje jména přes DNS-01 u GoDaddy: přes **Domains API v3** GoDaddy přidá záznam TXT `_acme-challenge.JMÉNO` a poté smaže jen svůj vlastní záznam (podle jeho `recordId`). Přihlašuje se **osobním přístupovým tokenem** (personal access token). Starší Domains API v1 s klíčem a secretem API (`sso-key`) zůstává na výběr pro nastavení s ním vytvořená; GoDaddy ho pro domény označilo za zastaralé.

## Co potřebujete

- Doménu u GoDaddy, používající DNS GoDaddy.
- **Oprávněný účet**: GoDaddy zpřístupňuje API pro správu domén jen účtům, které drží aspoň jednu doménu nebo mají tarif s přístupem k API; ostatní dostanou `403` s `code`, který říká proč.
- Odchozí HTTPS z acme na `api.godaddy.com` (port 443) - nebo `api.ote-godaddy.com` pro testovací prostředí GoDaddy (OTE).
- TTL **600 s a více**.

## Nastavení GoDaddy

1. Přihlaste se na `developer.godaddy.com` účtem, kterému doména patří.
2. **Personal Access Token → Create** (ve vývojářském portálu).
3. Rozsahy (scopes): jen **`domains.domain:read`** a **`domains.dns:update`**.
4. Nastavte **platnost**, kterou si zapamatujete, a zkopírujte token (zobrazí se jen jednou).
5. Jen pro starší v1: **API Keys → Create New API Key** (Production) a zkopírujte klíč a secret.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| API | `Domains API v3 with a personal access token` (nebo v1 pro starší klíč) |
| Personal access token | Token (v3) |
| API key / API secret | Starší klíč a secret (jen v1) |
| Domain | např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `600`; 600 a více |
| Endpoint | (pokročilé) `api.godaddy.com`, nebo `api.ote-godaddy.com` (testovací prostředí) |

## Kontrola

- **Test** v acme vypíše aktivní domény účtu. Nic nemění.
- Pomocí curl (v3):

  ```sh
  curl -s -H "Authorization: Bearer $PAT" \
    'https://api.godaddy.com/v3/domains/zones/example.com/dns-records?type=TXT&pageSize=10'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403` s kódem jako `ACCESS_DENIED` | Účet není pro API oprávněný, nebo tokenu chybí rozsah - přečtěte si kód v úloze. |
| `401` | Špatný nebo prošlý token; nebo `sso-key` použitý s v3 (funguje jen s v1). |
| TTL odmítnuto | Nastavte *TTL (s)* na 600 a více. |
| Klíče OTE proti produkci | Nastavte *Endpoint* podle klíče. |
