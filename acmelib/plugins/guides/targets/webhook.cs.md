# Webhook - nastavení pro acme

Pro vše, na co acme nemá modul: acme **pošle certifikát `POST`em na URL**, kterou
provozujete - jako JSON (výchozí), nebo jako `multipart/form-data` se zadanými formáty jako
soubory. Každý požadavek nese hlavičky `X-Acme-Event`, `X-Acme-Timestamp` a se zadaným
tajemstvím i `X-Acme-Signature: sha256=<hex HMAC-SHA256(tajemství, timestamp + "." + tělo)>`,
podle které příjemce pozná, že požadavek přišel od acme. **Soukromý klíč se posílá jen se
zapnutým *Send the private key*.** Úspěch je jakákoli odpověď 2xx. *Try* pošle
`{"event": "ping"}`.

Tělo JSON:

```json
{"event": "certificate.deployed", "name": "www", "names": ["www.example.com"],
 "serial": "...", "fingerprint": "...", "not_before": 1793491200, "not_after": 1801267200,
 "cert_pem": "...", "chain_pem": "...", "fullchain_pem": "..."}
```

navíc `key_pem` (s klíčem), `extra` (vaše *Extra JSON fields*) a u duálního certifikátu
`key_type` a `alt` (pole dvojčete).

## Co potřebujete

- HTTPS endpoint dostupný z acme (nebo přes proxy z *Settings → Proxy*).
- Příjemce, který ověří podpis a časové razítko a pak certifikát nainstaluje.

## Nastavení příjemce

1. Zvolte dlouhé náhodné tajemství pro podpis (např. `openssl rand -hex 32`) a dejte ho
   acme i příjemci.
2. U příjemce pro každý požadavek:
   - přečtěte `X-Acme-Timestamp` a odmítněte požadavek starší než pár minut;
   - spočítejte `HMAC-SHA256(tajemství, timestamp + "." + surové tělo)` v hex a porovnejte
     ho (v konstantním čase) s částí za `sha256=` v `X-Acme-Signature`;
   - na `{"event": "ping"}` odpovězte `200`;
   - u `certificate.deployed` zapište soubory a načtěte službu znovu; `2xx` vraťte, jen
     když se to povedlo.

   Příklad kontroly v Pythonu:

   ```text
   import hmac, hashlib
   mac = hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
   ok = hmac.compare_digest("sha256=" + mac, request.headers["X-Acme-Signature"])
   ```

3. Endpoint provozujte přes **HTTPS** - zvlášť když přijímá soukromý klíč - a pokud to jde,
   omezte ho na IP acme. Vyžaduje-li endpoint vlastní autentizaci, přidejte ji přes *More
   headers* (např. `Authorization: Bearer ...`).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| URL | např. `https://hooks.example.com/cert` |
| Signing secret | Tajemství z kroku 1 |
| More headers (pokročilé) | Jedna na řádek, např. `Authorization: Bearer <token>` |
| Send the private key | Vypnuto (výchozí) - z acme odejde jen certifikát a řetězec; zapnout jen, potřebuje-li příjemce klíč |
| Check the device's certificate | Zapnuto |
| CA certificate (pokročilé) | CA certifikátu endpointu, je-li interní |
| Through the proxy (pokročilé) | Zapnuto (výchozí) - ven přes *Settings → Proxy* |
| Body (nasazení) | *JSON* nebo *multipart/form-data (files)* |
| Files (multipart) (nasazení) | Formáty, jeden na řádek, např. `fullchain-pem`, `key-pem` (formáty klíče jen s *Send the private key*) |
| PKCS#12 password (nasazení, pokročilé) | Pro soubory `pfx`/`p12` |
| Extra JSON fields (nasazení, pokročilé) | např. `{"env": "prod"}` |
| Check what is served | Kam ho příjemce instaluje, např. `www.example.com:443` |

## Ověření

- Na cíli stiskněte **Try**: acme pošle `{"event": "ping"}` a odpoví
  `the webhook answered 200`.
- U příjemce logujte událost, časové razítko a to, zda podpis souhlasil.

## Časté problémy

| Problém | Řešení |
|---|---|
| Podpis nesouhlasí | Počítejte ze **surových** bajtů těla, ne ze znovu serializovaného JSON; stejné tajemství; `timestamp + "." + tělo`. |
| `... holds the private key, and this webhook does not send keys` | V *Files* je formát s klíčem: zapněte *Send the private key*, nebo ho odeberte. |
| `the extra JSON fields are not JSON` | Opravte JSON v *Extra JSON fields*. |
| `not a format: ...` | Použijte jména formátů jako `cert-pem`, `fullchain-pem`, `key-pem`, `pfx`. |
| Timeout / spojení odmítnuto | Endpoint není z acme dostupný; zkontrolujte *Through the proxy*. |
