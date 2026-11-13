# Cisco Unified Communications Manager (CUCM 14 / 15) - certifikáty ručně (bez cíle v acme)

acme pro CUCM **nemá cíl**: Cisco pro OS certifikáty CUCM nedokumentuje **žádné API** (AXL je databáze CM, ne OS) a **Cisco Unified OS Administration nepřijme soukromý klíč** pro `tomcat` / `CallManager` - klíč vždy vzniká na CUCM při *Generate CSR*. Certifikát, který acme vydá s vlastním klíčem, tam vložit nelze. Co acme umí: nechat podepsat CSR z CUCM (žádost s CSR - *Send a CSR*, docs/request-profiles.md) a certifikát pak nahrajete vy.

## Postup (CUCM 15 a SU)

1. *Cisco Unified OS Administration → Security → Certificate Management → Generate CSR*: *Certificate Purpose* `tomcat` (nebo `CallManager`, `tomcat-ECDSA` ...), *Distribution* uzel nebo **Multi-server (SAN)**, SAN (FQDN uzlů), typ a délka klíče (nejvýš 4096; wildcard ne) → **Generate**. Od 15SU5 nelze CN upravit.
2. *Download CSR* → nechte ho podepsat acme (nebo vaší CA) - pro `tomcat` použití klíče serverAuth + clientAuth.
3. *Upload Certificate/Certificate chain*: nejdřív kořenovou a mezilehlou CA jako **`tomcat-trust`** (`CallManager-trust`), pak podepsaný certifikát jako **`tomcat`** (`CallManager`). Multi-server certifikát se nahrává na **publisheru** a jen v GUI (od 14SU2).
4. Restartujte služby: pro `tomcat` **Cisco Tomcat** a **Cisco TFTP** (jinak telefony dostávají certifikát z cache); pro `CallManager` Cisco CallManager, CTIManager, HAProxy (telefony se znovu registrují) - v okně údržby, nejdřív publisher, pak subscribery po jednom.

CLI (stačí platformový účet s privilege 1):

```text
admin: set csr gen tomcat
admin: show csr list
admin: set cert import trust tomcat-trust
admin: set cert import own tomcat tomcat-trust/<root-ca-file>.pem
admin: utils service restart Cisco Tomcat
admin: utils service restart Cisco Tftp
admin: show cert list own
```

## Ověření

```sh
openssl s_client -connect cucm-pub.example.com:8443 -servername cucm-pub.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
openssl s_client -connect cucm-pub.example.com:5061 -showcerts </dev/null | openssl x509 -noout -subject -dates
```

Zdroje: Administration Guide for Cisco Unified CM 15 (Manage Certificates), Security Guide 15 (Certificates), CLI Reference 15.
