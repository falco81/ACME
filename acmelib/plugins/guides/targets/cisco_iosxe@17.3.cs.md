# Cisco IOS XE (switche, routery) (IOS XE 17.3 - 17.11) - nastavení pro acme

acme se k zařízení přihlásí přes **SSH**, zkopíruje certifikát s klíčem a řetězcem jako **PKCS#12** přes **SCP** do `bootflash:`, naimportuje ho do nového trustpointu `acme-<název>-<datum>-<sériové číslo>` (`crypto pki import ... pkcs12`), nasměruje na něj HTTPS server zařízení (WebUI, RESTCONF, NETCONF přes HTTPS), ten server restartuje, uloží konfiguraci (`write memory`) a odstraní starší trustpointy acme nad počet *ponechat*. Soubor PKCS#12 z `bootflash:` hned po importu smaže.

## Pro které IOS XE je tento návod

Verze modulu **„IOS XE 17.3 - 17.11“**: IOS XE **17.3 - 17.11** (17.3, 17.6, 17.9 ...). Tyto verze nepřijmou PKCS#12 s MAC SHA-256 (chyba CSCvz41428), proto ho acme vytvoří postaru: 3DES, MAC SHA-1 (to, co dělá `openssl pkcs12 -export -legacy -macalg sha1 -descert`). Na jiném IOS XE acme nasazení odmítne dřív, než cokoli změní, a řekne, kterou verzi zvolit.

| Verze modulu | IOS XE | PKCS#12, který acme posílá |
|---|---|---|
| jakákoli verze (zjistí ji) | 17.3 - 26.1 | podle verze, kterou ukáže `show version` |
| IOS XE 17.3 - 17.11 | 17.3 - 17.11 | 3DES, MAC SHA-1 |
| IOS XE 17.12 - 26.1 | 17.12 - 26.1 | AES-256, MAC SHA-256 |

Vše ostatní - `crypto pki import`, `ip http secure-trustpoint`, restart HTTPS serveru, `write memory` - je v 17.3 - 26.1 stejné (Cisco TN 213917, průvodce PKI pro IOS XE 17.x). Nevíte jistě? Na zařízení `show version | include Version`.

## Co acme na zařízení mění

| Volba v acme | Konfigurace IOS XE | Dopad |
|---|---|---|
| (vždy) | `crypto pki trustpoint acme-...` (vznikne importem i s klíčem; řetězec více CA přidá `acme-...-rrr1` ...) | nový certifikát; starší trustpointy acme nad *ponechat* odstraní (`no crypto pki trustpoint`, `crypto key zeroize`), pokud se ještě nepoužívají |
| HTTPS server (WebUI, RESTCONF) | `ip http secure-trustpoint acme-...`, pak `no ip http secure-server` / `ip http secure-server` | HTTPS server se restartuje: relace GUI a RESTCONF se na okamžik přeruší; provoz to neovlivní |
| Uložit konfiguraci (write memory) | `write memory` | bez něj trustpoint po reloadu zmizí |

## Nastavení zařízení

### 1. Účet pro acme

Příkazy PKI, `ip http ...` jsou konfigurační: účet potřebuje **privilege 15** (nebo autorizaci příkazů přes TACACS+, která povolí jen je).

```text
configure terminal
 aaa new-model
 aaa authentication login default local
 aaa authorization exec default local
 username acme privilege 15 algorithm-type scrypt secret <silne-heslo>
end
write memory
```

S TACACS+ (ISE Device Admin) může sada příkazů pro acme povolit jen: `crypto pki *`, `crypto key zeroize *`, `ip http secure-trustpoint *`, `ip http secure-server`, `ip http server`, `show *`, `delete /force bootflash:acme-*`, `write memory` (*nejisté*: Cisco takový seznam pro PKI neuvádí - jde o obecný princip).

### 2. Klíč SSH (volitelně) a SCP

acme se přihlásí heslem nebo svým klíčem SSH (karta klíče u cíle: *Vytvořit klíč*, pak jeho veřejnou část vložte do zařízení). SCP musí být zapnuté - acme jím kopíruje PKCS#12 (starší protokol SCP; server SFTP na to IOS XE nemá):

```text
configure terminal
 ip ssh version 2
 ip scp server enable
 ip ssh pubkey-chain
  username acme
   key-string
    <veřejný klíč acme, v řádcích po nejvýš 254 znacích>
   exit
  exit
 exit
end
write memory
```

### 3. Čas, jména, HTTPS

- NTP (`ntp server ...`): se špatným časem import certifikátu selže.
- `ip http secure-server` zapnutý (acme ho restartuje).
- Jména v certifikátu musí odpovídat jménům, která používají klienti (FQDN zařízení).

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Verze modulu | **IOS XE 17.3 - 17.11** |
| Adresa | adresa správy zařízení, např. `sw01.example.com` |
| SSH port / Uživatel | `22` / `acme` |
| Přihlásit se přes, SSH klíč / Heslo | klíč acme (krok 2) nebo heslo |
| Klíč serveru (rozšířené) | řádek known_hosts zařízení; prázdné s *Věřit prvnímu viděnému klíči serveru* vezme první |
| Souborový systém (rozšířené) | `bootflash:` (nebo `flash:`) |
| Port HTTPS (rozšířené) | port WebUI (`ip http secure-port`) pro test toho, co se servíruje |
| HTTPS server (WebUI, RESTCONF) (nasazení) | zapnuto |
| Uložit konfiguraci (write memory) (nasazení) | zapnuto |
| Kolik předchozích verzí ponechat (rozšířené) | `1` |

## Ověření

Na zařízení:

```text
show crypto pki trustpoints status
show crypto pki certificates verbose acme-www.example.com-20261112-a1b2c3d4
show ip http server secure status
show running-config | include ^ip http secure-trustpoint
```

Ze stroje acme:

```sh
openssl s_client -connect sw01.example.com:443 -servername sw01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| `scp to ...: ...` | SCP odmítnuto | `ip scp server enable`; účet potřebuje privilege 15 |
| `... Bad HMAC` / `PKCS12 import failed` | IOS XE tento PKCS#12 nepřijme | před 17.12.1 zvolte *IOS XE 17.3 - 17.11* (nebo *jakákoli verze*) |
| `the device said "% Invalid input ..."` | příkaz není povolený nebo známý | privilege 15 / sada příkazů TACACS+; zkontrolujte verzi IOS XE |
| *the module version ... is for IOS XE ...* | zařízení má jiné IOS XE | zvolte verzi uvedenou ve zprávě |
| test servírovaného certifikátu hned poté selže | HTTPS server se ještě restartuje | acme sám počká; jinak `show ip http server secure status` |

*Nejisté*: acme posílá konfigurační řádky do relace SSH shellu bez terminálu (jako Ansible); `delete /force` a odpovědi `yes` u `no crypto pki trustpoint` a `crypto key zeroize` jsou běžná slova IOS XE - úklid při jejich selhání jen varuje.

Zdroje: Cisco TN 213917 (CSR, PKCS#12, trustpointy pro web admin a webauth na 9800), TN 221047, průvodce PKI pro IOS XE 17.x, konfigurační průvodce 9800 26.1 (PKI management), průvodce programovatelností IOS XE 17.15.
