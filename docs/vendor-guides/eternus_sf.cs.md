# Fujitsu ETERNUS SF (certifikát Web Console) - nastavení pro acme

ETERNUS SF Express / Storage Cruiser / AdvancedCopy Manager (Version 16) **nemá pro svůj
certifikát žádné API, CLI ani funkci v GUI**: Apache konzole Web Console čte `server.crt`
a `server.key` na Management Serveru. acme je vymění obecnými cíli - **Server Linux / Unix
(SSH)** nebo **Server Windows (OpenSSH + PowerShell)** - a restartuje webové služby. Vlastní modul
neexistuje, protože není co specifického pro ETERNUS volat.

**Méně jisté** (stránky Web Console Guide od Fujitsu byly vidět jen ve výňatcích): přesná složka
(přímo `conf`, nebo podsložka), názvy služeb ve Windows, cesta ke skriptům v Linuxu a port
(obvykle 9855). Před prvním během je na Management Serveru ověřte.

## Co potřebujete

- SSH z acme na Management Server (Windows: OpenSSH Server).
- Linux: `root`, nebo uživatele se `sudo` pro dva soubory a dva skripty. Windows: člena místní
  skupiny Administrators.
- Nešifrovaný klíč PEM (s šifrovaným Apache nenastartuje).

## Management Server s Linuxem - cíl „Server Linux / Unix (SSH)“

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Uživatel | Management Server, `root` (nebo uživatel se sudo a *Použít sudo*) |
| Soubory (nasazení) | viz níže |
| Před zápisem (nasazení) | `/opt/FJSVesfcm/bin/stop-webservice.sh` |
| Znovu načíst / restartovat (nasazení) | `/opt/FJSVesfcm/bin/start-webservice.sh` |
| Zálohovat nahrazovaný soubor (nasazení) | zapnuto |
| Zkontrolovat, co se servíruje | `esf.example.local:9855` |

```text
fullchain-pem /etc/opt/FJSVesfcm/conf/apache/server.crt 0644 root:root
key-pem /etc/opt/FJSVesfcm/conf/apache/server.key 0600 root:root
```

## Management Server s Windows - cíl „Server Windows (OpenSSH + PowerShell)“

| Pole v acme | Co tam patří |
|---|---|
| Soubory (nasazení) | viz níže (výchozí instalační složka `C:\ETERNUS_SF`) |
| PowerShell potom (nasazení) | viz níže |
| Zkontrolovat, co se servíruje | `esf.example.local:9855` |

```text
fullchain-pem C:/ETERNUS_SF/Common/sys/apache/conf/server.crt
key-pem C:/ETERNUS_SF/Common/sys/apache/conf/server.key
```

```text
Stop-Service -DisplayName 'ETERNUS SF Manager Apache Service','ETERNUS SF Manager Tomcat Service'
Start-Service -DisplayName 'ETERNUS SF Manager Tomcat Service','ETERNUS SF Manager Apache Service'
```

(Názvy služeb nejdřív zjistěte: `Get-Service | Where-Object DisplayName -like 'ETERNUS SF Manager*'`.)

## Ověření

```sh
openssl s_client -connect esf.example.local:9855 -servername esf.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Na serveru musí klíč a certifikát patřit k sobě -

```sh
openssl x509 -in /etc/opt/FJSVesfcm/conf/apache/server.crt -noout -modulus | openssl md5
openssl rsa -in /etc/opt/FJSVesfcm/conf/apache/server.key -noout -modulus | openssl md5
```

Aktualizace nebo přeinstalace ETERNUS SF Manager může vrátit nový self-signed certifikát - potom
nasaďte znovu (vynuceně).
