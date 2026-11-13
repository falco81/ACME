# Fujitsu ServerView Operations Manager (CMS) - nastavení pro acme

ServerView Operations Manager (SVOM 10.x, Central Management Station) **nemá pro svůj certifikát
žádné API, CLI ani funkci v GUI**: TomEE a ApacheDS (CAS / jednotné přihlášení) čtou úložiště
klíčů Java `…\tomee\svconf\pki\keystore` s klíčem pod aliasem **`svs_cms`**. acme ho umí zapsat
obecnými cíli - **Server Windows (OpenSSH + PowerShell)** nebo **Server Linux / Unix (SSH)** -
ve formátu `jks` s aliasem `svs_cms` a potom restartovat služby. Vlastní modul neexistuje: není
co specifického pro SVOM volat a **několik kroků není potvrzeno** příručkou Fujitsu „User
Management in ServerView“ (celá nebyla k dispozici): heslo úložiště, které TomEE čeká, JKS vs.
PKCS#12, název souboru úložiště důvěryhodných certifikátů a `<system_name>.scs.pem` služby Remote
Connector. Nejdřív to vyzkoušejte na testovací CMS a ponechte si kopii úložiště.

## Co potřebujete

- SSH z acme na CMS (Windows: OpenSSH Server); místního administrátora (Windows) nebo `root`
  (Linux).
- Heslo úložiště klíčů vaší instalace SVOM.
- Servisní okno: GUI, SSO a sběr dat jsou 5-10 minut nedostupné; spravovaných serverů se to
  nedotkne. iRMC, která ověřují certifikát serveru CAS, potřebují novou CA („CA Certificate for
  CAS and SMTP“ v iRMC).

## CMS s Windows - cíl „Server Windows (OpenSSH + PowerShell)“

| Pole v acme | Co tam patří |
|---|---|
| Soubory (nasazení) | `jks "C:/Program Files (x86)/Fujitsu/ServerView Suite/tomee/svconf/pki/keystore"` |
| Alias v keystore (nasazení) | `svs_cms` |
| Heslo souborů PKCS#12 / keystore, Heslo PKCS#12 / keystore (nasazení) | heslo úložiště klíčů instalace |
| Zálohovat nahrazovaný soubor (nasazení) | zapnuto |
| PowerShell potom (nasazení) | viz níže |
| Zkontrolovat, co se servíruje | `svom.example.local:3170` |

```text
Stop-Service SVTomEE; Stop-Service SVApacheDSService
Start-Service SVApacheDSService; Start-Service SVTomEE
Restart-Service -DisplayName 'ServerView Services'
```

## CMS s Linuxem - cíl „Server Linux / Unix (SSH)“

Složka `/opt/fujitsu/ServerViewSuite/tomee/svconf/pki` je odvozená z rozložení ve Windows -
ověřte ji. Restart: `/usr/bin/sv_services restart` (*Znovu načíst / restartovat*).

## Ověření

```sh
openssl s_client -connect svom.example.local:3170 -servername svom.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
keytool -list -keystore keystore -storepass '<heslo>' -alias svs_cms
```

Pokud po „change installation“ nejde přihlášení, obejití od Fujitsu zkopíruje úložiště zpět
z `%LocalAppData%\certificates\private\keystore` a restartuje `SVApacheDSService` a `SVTomEE`.
