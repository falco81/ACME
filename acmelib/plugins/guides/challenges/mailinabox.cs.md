# Mail-in-a-Box - nastavení pro acme

acme prokazuje jména metodou DNS-01 v DNS, kterou server **Mail-in-a-Box** obsluhuje sám (svým nsd), přes API ovládacího panelu (`https://BOX/admin`). Načte zóny (`GET /admin/dns/zones`), přidá TXT hodnotu přes `POST /admin/dns/custom/{qname}/TXT` (vedle hodnot, které tam už jsou) a přesně tuto hodnotu odebere přes `DELETE` s hodnotou v těle. Box pak přepíše soubory zón a znovu načte nsd; TTL si určuje sám.

## Co potřebujete

- Server Mail-in-a-Box, který je autoritativním DNS pro doménu (u registrátora nastavené jmenné servery boxu).
- HTTPS (TCP 443) z acme na box.
- **Účet administrátora bez dvoufázového přihlášení** (basic autentizace neumí přenést kód TOTP).

## Nastavení Mail-in-a-Boxu

1. Přihlaste se do ovládacího panelu `https://box.example.com/admin` jako administrátor.
2. **Mail → Users → Add a mail user**: e-mail např. `acme@example.com`, dlouhé náhodné heslo, oprávnění **Administrator**.
   (API ovládacího panelu je jen pro administrátory; role jen pro DNS neexistuje.)
3. U tohoto uživatele **ne**zapínejte dvoufázové ověření (**System → Two-Factor Authentication**).
4. Volitelně: nechcete-li na tu adresu poštu, schránku prostě nepoužívejte.

**Pozor:** tento uživatel je plnohodnotný administrátor boxu - heslo mějte jen v acme.

Ověřte, že API odpovídá:

```sh
curl -u 'acme@example.com:HESLO' https://box.example.com/admin/dns/zones
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Box address | `box.example.com` (nebo `https://box.example.com`) |
| Administrator e-mail | `acme@example.com` |
| Password | jeho heslo |
| Zone | prázdné (nejdelší zóna boxu, do které jméno patří), nebo zóna |
| Check the server's certificate | zapnuto (box má vlastní certifikát Let's Encrypt; pokročilé) |

## Ověření

- V acme stiskněte **Test**: přihlásí se a vypíše zóny boxu; nic nemění.
- Po objednávce: ovládací panel → **System → Custom DNS**: TXT záznam `_acme-challenge` se objeví a zase zmizí.

```sh
dig +short TXT _acme-challenge.www.example.com @box.example.com
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / „invalid-credentials“ | Špatný e-mail nebo heslo. |
| „missing-totp-token“ | Uživatel má dvoufázové přihlášení - použijte administrátora bez něj. |
| `403` | Uživatel není administrátor. |
| Zóna nenalezena | Doménu tento box neobsluhuje (přidejte uživatele nebo alias v té doméně, aby box zónu vytvořil). |
