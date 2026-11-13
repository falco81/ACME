# Barracuda Email Security Gateway - ručně (bez modulu acme)

acme **nemá modul** pro Barracuda Email Security Gateway: jeho jediné API (XML-RPC `config.get` / `config.set` na `/cgi-mod/api.cgi`) nemá zdokumentovanou proměnnou pro certifikát webového rozhraní a Barracuda nedoporučuje používat nezdokumentované. Email Gateway Defense (cloudová služba) zákaznický certifikát vůbec nemá - spravuje ho Barracuda; vaše jsou jen politiky TLS. Certifikát si vezměte z acme a na každou jednotku ho nainstalujte ručně.

## Pro které verze

Firmware ESG 8.x - 9.4 (postup je zdokumentovaný „pro verzi 8 a novější“; 9.1 přidala *Supported SSL Protocols*; 9.4.0.029 opravila, že tlačítko *Use* vracelo TLS na 1.1).

## Účet

Na *ADVANCED > Secure Administration* se dostane jen role **Admin** - menší role pro certifikáty neexistuje. Omezte ji: *Administrator IP/Range*, *HTTPS/SSL Access Only* = Yes.

## Instalace

1. Z acme stáhněte certifikát s řetězcem (PEM, formát „Apache“) a **nešifrovaný** klíč (PKCS#12 není zdokumentovaný - převeďte ho):

```sh
openssl pkcs12 -in esg.pfx -nocerts -nodes -out esg.key
openssl pkcs12 -in esg.pfx -clcerts -nokeys -out esg.crt
openssl pkcs12 -in esg.pfx -cacerts -nokeys -out chain.crt
```

2. *ADVANCED > Secure Administration* → **Certificate Type** = **Trusted** → **Upload** privátního klíče → **Upload** certifikátu a mezilehlých certifikátů → **Save**.
3. Po změně zkontrolujte *Supported SSL Protocols* (TLSv1.2 + TLSv1.3).
4. Cluster tyto certifikáty **nesynchronizuje** - zopakujte to na každé jednotce.

Jde o certifikát webového rozhraní (administrace a karanténa uživatelů); dokumentace neuvádí, zda ho používá i SMTP STARTTLS na portu 25 - ověřte níže.

## Ověřte to

```sh
openssl s_client -connect esg.example.com:443 -servername esg.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect esg.example.com:25 -starttls smtp -servername esg.example.com </dev/null | openssl x509 -noout -subject -issuer -dates
```

V acme k certifikátu přidejte HTTPS test (a test SMTP STARTTLS), aby se hlídala jeho obnova.
