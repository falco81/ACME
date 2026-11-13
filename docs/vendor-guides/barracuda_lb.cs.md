# Barracuda Load Balancer ADC - ručně (bez modulu acme)

acme **nemá modul** pro Barracuda Load Balancer ADC: jeho REST API v2 (dokumentované pro firmware 5.1 - 6.1) je popsané jen v PDF (`ADC_REST-API-v2.pdf` na Barracuda Campus), jehož volání pro certifikáty, přihlášení a porty nešlo ověřit, a API WAF (`/restapi/v3.x/certificates/...`) patří jinému produktu. Certifikát si vezměte z acme (*Certifikáty → certifikát → Stáhnout*) a nainstalujte ho ručně - nebo si podle PDF napište vlastní modul (docs/writing-a-module.md).

## Pro které verze

Firmware 6.4 - 6.6 (6.6: OpenSSL 3.0, bez TLS 1.0 / 1.1, opravené nahrávání na *Secure Administration* - pro certifikát správy použijte 6.6 nebo novější).

## Účet

*ADVANCED > Admin Access Control* → **Administrator Accounts** → **Add Local Administrator** s rolí **Admin** (dokumentace neuvádí, která jiná role smí spravovat certifikáty).

## Certifikát služby

1. Stáhněte z acme **PKCS#12** (soubor musí končit `.pfx`, jinak ho ADC čte jako PEM; mezilehlé certifikáty uvnitř) nebo PEM certifikát + řetězec + **nešifrovaný** klíč:

```sh
openssl pkcs12 -export -inkey lb.key -in lb.crt -certfile chain.crt -out lb.pfx -passout pass:'<heslo>'
```

2. *BASIC > Certificates* → **Upload Certificate**: *Certificate Type* **PKCS12 Token** (nebo *PEM Certificate* s *Assign the associated key* **No**, *Certificate Key*, *Signed Certificate*, *Intermediary Certificates*), **Allow Private Key Export** (No klíč zamkne - a pak nejde udělat zálohu konfigurace), při každé obnově nové **Certificate Name** (např. `www-2026-11`), **Upload**.
3. *BASIC > Services* → upravit službu HTTPS / Secure TCP Proxy → nový certifikát → **Save** (nová TLS spojení ho dostanou).
4. Starší certifikát smažte, až ho žádná služba nepoužívá. V HA páru se certifikáty synchronizují.

## Certifikát správy

*ADVANCED > Secure Administration* - HTTPS port a certifikát webového rozhraní, **pro každou jednotku zvlášť** (v HA se nesynchronizuje): certifikát a klíč nahrajte tam na každé jednotce.

## Ověřte to

```sh
openssl s_client -connect <VIP>:443 -servername <fqdn> -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect <mgmt-host>:443 -showcerts </dev/null | openssl x509 -noout -subject -dates
```

V acme k certifikátu přidejte HTTPS test VIP, aby se hlídala jeho obnova.
