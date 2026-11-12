# Sectigo Certificate Manager (Admin API) - nastavení pro acme

Zdroj **Sectigo Certificate Manager (Admin API)** získává certifikáty ze Sectigo Certificate Manager (SCM) přes jeho Admin API (`/api/ssl/v2`, `/api/dcv/v2`): acme nejdřív ověří dosud neověřené domény (**DCV** - CNAME, TXT nebo soubor umístěný validací certifikátu, nebo e-mail, který schválí člověk), pak **zaregistruje** (enroll) své CSR s **certifikačním profilem** účtu pro organizaci a certifikát vyzvedne. Obnovení obnovují (nebo nahrazují) certifikát SCM, který acme vytvořilo nebo importovalo; odvolání je součástí; *Import from a source* vypíše certifikáty účtu. **Soukromý klíč nikdy neopustí acme.** Přihlášení je **OAuth 2.0 API klient** (doporučeno; `admin.<instance>.sectigo.com`) nebo login a heslo API administrátora (`cert-manager.com`). Pro ACME s EAB v SCM použijte místo toho zdroj ACME; tento zdroj je pro profily, doby platnosti, vlastní pole, DCV e-mailem a certifikáty účtu. Patří sem i bývalí zákazníci Entrustu. Žádné IP adresy.

## Co potřebujete

- Účet SCM, **ID organizace (nebo oddělení)**, ke které certifikáty patří, a SSL **certifikační profil**, který má k dispozici.
- **API klienta** (client ID + secret) - nebo administrátora, který smí používat API (login, heslo, customer URI).
- Přístup HTTPS **z acme** na `admin.<instance>.sectigo.com` a `auth.sso.sectigo.com` (OAuth) nebo `cert-manager.com` (login), port 443.
- Validaci v acme, která umí umístit důkaz DCV (DNS pro CNAME/TXT, HTTP pro soubor), nebo člověka pro e-mail.

## Nastavení SCM

1. **API klient (OAuth 2.0)**: v SCM vytvořte pro acme API klienta (dokumentace Sectiga: *Authentication*; v aktuálním SCM je nabídka v integracích / API klíčích) s právy registrovat, vyzvedávat, obnovovat a odvolávat SSL certifikáty a provádět ověření domén, omezeného na organizaci, kterou acme používá. Zkopírujte **client ID** a **secret** a poznamenejte si svou **instanci** (`enterprise`, `hard`, `eu`) z onboardingu.
2. Nebo **API administrátor**: **Settings → Admins → Add** administrátora pro acme (RAO/DRAO SSL admin organizace) s povoleným použitím API, heslem, a poznamenejte si **Customer URI** účtu.
3. **Organizace**: **Settings → Organizations** - poznamenejte si **Org ID** (nebo oddělení); její nastavení SSL musí povolovat požadovaný certifikační profil a dobu platnosti a domény na ni musí být delegovány.
4. **Certifikační profil**: poznamenejte si jeho ID (*Load the list* v acme čte `GET /api/ssl/v2/types`).
5. **Domény**: **Domains** - přidejte domény a delegujte je na organizaci; když je ověříte předem (DCV), acme to dělat nemusí.
6. Povinná **vlastní pole** účtu: poznamenejte si jejich jména - acme je posílá.

Ověření OAuth z příkazové řádky:

```sh
curl -s https://auth.sso.sectigo.com/auth/realms/apiclients/protocol/openid-connect/token \
  -d grant_type=client_credentials -d client_id="$ID" -d client_secret="$SECRET"
```

## Vyplnění v acme

Zdroje → **Přidat** → **Sectigo Certificate Manager (Admin API)**.

| Pole v acme | Co do něj zadat |
|---|---|
| Signing in | *OAuth 2.0 client* nebo *Login and password* |
| SCM instance / Client ID / Client secret | `enterprise` / `hard` / `eu` a ID a secret API klienta |
| Token address (pokročilé) | výchozí; odpověď 401 uvede jinou, má-li ji váš účet vlastní |
| Login / Password / Customer URI | pro přihlášení loginem |
| Organization ID | např. `12345` |
| Certificate profile | *Load the list*, nebo napište ID; vlastní profil certifikátu má přednost |
| Term (days) | např. `365`; prázdné: nejkratší, kterou profil nabízí |
| Domain validation (DCV) | *DNS CNAME*, *DNS TXT*, *HTTP file* (bez wildcardů), nebo *E-mail* + *Approver mailbox* |
| Certificate to reuse | ID certifikátu SCM k obnovení; prázdné: ten, který acme vytvořilo naposledy |
| A renewal (pokročilé) | *renews it* (výchozí), *replaces it*, nebo *is a new enrollment* |
| Custom fields (pokročilé) | řádky `name=value` - povinná pole účtu |
| Comments, External requester, API address, čekání (pokročilé) | podle potřeby |

## Ověření

- Zdroje → zdroj → **Test** (Try it): přihlásí se a přečte profily - nic neregistruje.
- V SCM: **Certificates → SSL Certificates** ukáže certifikát, jeho stav a žadatele.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` | špatné client ID/secret nebo instance; odpověď může uvést jinou adresu tokenu; login: heslo, customer URI, povolené API |
| `403` / nepovoleno pro organizaci | klient/admin nemá práva na tu organizaci nebo profil |
| Profil nebo doba platnosti odmítnuty | profil není pro organizaci zapnutý, nebo se doba nenabízí |
| Doména není delegovaná / povolená | přidejte doménu a delegujte ji na organizaci |
| DCV zůstává *Not validated* | záznam ještě nebyl vidět (acme odešle znovu při dalším pokusu); u e-mailu musí někdo schválit |
| Chybí vlastní pole | přidejte ho do *Custom fields* |
| Čeká na schválení | žádost musí schválit administrátor SCM; acme ji vyzvedne při pozdějším pokusu |
