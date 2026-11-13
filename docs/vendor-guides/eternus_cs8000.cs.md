# Fujitsu ETERNUS CS8000 - bez automatického nasazení

ETERNUS CS8000 (V8.x, V9) servíruje **Web GUI** přes HTTPS z VLP (a po failoveru ze SVLP). Jak
se jeho certifikát vyměňuje - sekce „certificate management“ ve Web GUI, umístění souborů,
restart - **nepotvrzuje žádný dostupný oficiální dokument** (V9 User Guide vyžaduje přihlášení
k podpoře; white paper a datasheet to nepopisují). CLI přes SSH je skriptovatelné, ale žádný
příkaz pro certifikáty není zdokumentovaný. acme proto pro něj **nemá cíl**.

## Co dělat

1. Vyhledejte „certificate management“ v ETERNUS CS8000 V9 User Guide (kapitola Web GUI), nebo
   se obraťte na servis Fujitsu / Fsas (role *Service*).
2. Přijímá-li Web GUI certifikát s klíčem: vytvořte ho v acme (RSA 3072, jména VLP **i** SVLP /
   virtuální adresy), stáhněte ho jako klíč PEM + celý řetězec a tam ho naimportujte.
3. Použijte účet s rolí *ETERNUS CS8000 Administrator* (nebo *Operating System Administrator*,
   podle příručky).

## Ověření - oba uzly

```sh
openssl s_client -connect cs8000-vlp.example.local:443 -servername cs8000.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -ext subjectAltName
openssl s_client -connect cs8000-svlp.example.local:443 -servername cs8000.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

Přidejte k certifikátu v acme test TLS obou adres, ať se hlídá jeho vypršení.
