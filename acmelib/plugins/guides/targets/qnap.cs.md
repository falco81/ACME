# QNAP QTS / QuTS hero (SSH) - nastavení pro acme

**Nejdřív si přečtěte.** QNAP pro certifikáty **nezveřejňuje žádné API**: jeho příručky (QTS 5.2, QuTS hero h5.2 / h5.3) popisují jen GUI – *Control Panel > System > Security > SSL Certificate & Private Key > Replace Certificate > Import certificate*. To, co acme dělá přes SSH, je postup, který pro QNAP dokumentuje deploy hook `ssh` z acme.sh (tam vyzkoušený s QTS 4.2.3), **není ověřený proti dokumentaci QNAP pro QTS 5.2 / QuTS hero h5.x**. Vyzkoušejte ho na svém NAS přes *Zkusit spojení* a jedno nasazení, které budete sledovat; když se neujme, importujte certifikát v GUI.

acme přes SSH:

1. přečte certifikát v `/etc/stunnel/stunnel.pem` – když je tam už tentýž, nic nemění;
2. nahrazované soubory si ponechá jako `stunnel.pem.acme-prev` a `uca.pem.acme-prev`;
3. zapíše `/etc/stunnel/stunnel.pem` (soukromý klíč a za ním certifikát – jeden soubor, práva 600) a `/etc/stunnel/uca.pem` (mezilehlé certifikáty);
4. spustí `/etc/init.d/stunnel.sh restart` – když selže, vrátí předchozí soubory a stunnel restartuje znovu;
5. na požádání i `/etc/init.d/Qthttpd.sh restart`.

Administrační stránky NAS (a Web Server, který systémový certifikát sdílí) ho používají, jakmile stunnel znovu naběhne; sdílení SMB / NFS se to netýká.

## Pro které verze

QTS 5.2.x, QuTS hero h5.2.x a h5.3.x, QuTScloud (předpokládá se, že je jako QTS). Jeden modul.

## Co potřebujete

- **Zapnuté SSH**: *Control Panel > Network & File Services > Telnet / SSH > Allow SSH connection (Only administrators can login remotely.)*; v *Edit Access Permission* povolte jen účet, který acme používá.
- Účet ve skupině **`administrators`** – přes SSH se smějí přihlásit jen administrátoři a soubory patří rootovi. QNAP doporučuje výchozí `admin` zakázat a používat vlastní administrátorský účet. Dvoufázové ověření mu nezapínejte (přihlášení SSH klíčem je v pořádku).
- Zapnuté HTTPS administrace: *Control Panel > System > General Settings > System Administration > Enable secure connection (HTTPS)* a jeho port (zde 443).
- Certifikát X.509 PEM s nešifrovaným RSA klíčem (2048 a víc; QTS 5.2 používá OpenSSL 3.0 a odmítá SHA-1 a krátké klíče; ECC QNAP nedokumentuje).

Veřejný klíč acme dejte na NAS k účtu (karta klíče ho ukáže v *Jak ho nastavit*), například:

```sh
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-ed25519 AAAA... acme" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

Ručně si ověřte, že soubory jsou tam, kam je acme zapisuje:

```sh
ls -l /etc/stunnel/stunnel.pem /etc/stunnel/uca.pem /etc/init.d/stunnel.sh
```

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | jméno nebo IP NAS |
| SSH port / Uživatel | `22`, administrátorský účet |
| Přihlásit se přes / SSH klíč | klíč vytvořený v acme (nebo heslo) |
| HTTPS port NAS | HTTPS port administrace (`443`) |
| Restartovat i webový server (Qthttpd) (nasazení, pokročilé) | zapnout jen tehdy, když stránky po restartu stunnelu stále ukazují starý certifikát |
| Zkontrolovat, co se servíruje | `<adresa>:<HTTPS port>` acme kontroluje sám; přidejte virtuální host Web Serveru, pokud ho používáte |

*Zkusit spojení* se přihlásí a zkontroluje, že `/etc/stunnel/stunnel.pem` a `/etc/init.d/stunnel.sh` existují.

## Ověření

```sh
openssl s_client -connect nas01.example.com:443 -servername nas01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

V GUI: *Control Panel > System > Security > SSL Certificate & Private Key* ukazuje vydavatele a platnost.

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| *... is not there* při *Zkusit spojení* | tento firmware drží certifikát jinde | importujte ho v GUI; dejte nám vědět verzi firmwaru |
| SSH otevře menu Console Management | interaktivní přihlášení | acme spouští příkazy, které menu neotevírají; pokud na vašem firmwaru ano, tento modul použít nejde |
| stunnel se nerestartoval | vadný klíč nebo certifikát | acme vrátil předchozí soubory; zkontrolujte certifikát (RSA, PEM) |
| po restartu nebo aktualizaci se vrátí starý certifikát | QTS zapsal zpět svou kopii | nasaďte znovu (*Nasadit hned*), nebo importujte v GUI |
| HTTPS vůbec neodpovídá | neplatný certifikát | otevřete NAS na `http://<nas>:8080` a v *SSL Certificate & Private Key* obnovte výchozí certifikát |
| HA cluster QuTS hero: pasivní uzel ukazuje starý | není známo, zda se kopíruje | nasaďte na adresu každého uzlu |

Zdroje: příručky QTS 5.2 / QuTS hero h5.2, h5.3 (*Replacing the server certificate*, *Enabling SSH*, *System Administration*), wiki acme.sh *Deploy hooks* (QNAP přes SSH).
