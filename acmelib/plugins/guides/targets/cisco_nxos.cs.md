# Cisco NX-OS (Nexus, NX-API) - nastavení pro acme

acme zařídí, aby certifikát servírovalo **NX-API** (HTTPS API Nexusu 9000). Certifikát s klíčem a řetězcem zkopíruje jako **PKCS#12** přes **SCP** do `bootflash:`, pak přes NX-API (JSON-RPC, `POST /ins`) vytvoří trustpoint `acme-<název>-<datum>-<sériové číslo>`, naimportuje do něj PKCS#12 (`crypto ca import ... pkcs12`), soubor smaže, uloží konfiguraci, nasměruje NX-API na nový trustpoint (`nxapi certificate trustpoint`) a odstraní starší trustpointy acme nad počet *ponechat*.

## Pro které NX-OS

**NX-OS 10.2(3)F - 10.6.** `nxapi certificate trustpoint` existuje od 10.2(3)F; na starším NX-OS acme odmítne dřív, než cokoli změní (tam se certifikát vkládá ručně jako soubory `nxapi certificate httpscrt` / `httpskey` do 8 kB). Volání jsou v 10.2 - 10.6 stejná, proto je modul v jediné verzi.

## Co acme na Nexusu mění

| Krok | Příkaz NX-OS | Dopad |
|---|---|---|
| kopie | SCP do `bootflash:acme-....pfx` | soubor, smazaný hned po importu |
| import | `crypto ca trustpoint acme-...`, `crypto ca import acme-... pkcs12 bootflash:acme-....pfx <jednorázové heslo>` | nový trustpoint s klíčem a certifikátem |
| uložení | `copy running-config startup-config` | trustpoint přežije reload |
| NX-API HTTPS | `nxapi certificate trustpoint acme-...` | NX-API (nginx) se restartuje: relace API se přeruší a odpověď nemusí dorazit - acme s tím počítá |
| úklid | `delete certificate force`, `delete ca-certificate`, `no crypto ca trustpoint <starší>` | starší trustpointy acme nad *ponechat*, až je NX-API přestane používat |

Řádky `nxapi certificate` **nejsou** v běžící konfiguraci: po `reload ascii` nebo config replace se NX-API může vrátit k vlastnímu certifikátu - nasaďte znovu s volbou *vynutit*.

## Nastavení Nexusu

### 1. NX-API a SCP

```text
configure terminal
 feature nxapi
 nxapi use-vrf management
 feature scp-server
 ip domain-name example.com
 ntp server 192.0.2.123 use-vrf management
end
copy running-config startup-config
```

NX-API od 9.2(1) poslouchá na HTTPS 443 (HTTP 80 je vypnuté). Čas musí sedět - certifikát mimo dobu platnosti zařízení odmítne.

### 2. Účet s nejmenšími právy

Vestavěná role `network-admin` umí vše, co acme potřebuje. Vlastní role (*nejisté*: přesnou syntaxi `rule` ověřte v bezpečnostním průvodci NX-OS):

```text
configure terminal
 role name acme-pki
  rule 1 permit command configure terminal
  rule 2 permit command crypto *
  rule 3 permit command nxapi certificate *
  rule 4 permit command copy *
  rule 5 permit command delete bootflash:*
  rule 6 permit command show *
 username acme password 0 <silne-heslo> role acme-pki
end
copy running-config startup-config
```

JSON-RPC NX-API potřebuje právo na `configure terminal`. acme se do NX-API (HTTP basic) i do SCP přihlašuje stejným uživatelem a heslem.

## Vyplnění v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | adresa správy Nexusu, např. `n9k01.example.com`, a `443` |
| Uživatel / Heslo | `acme` a jeho heslo |
| SSH port (SCP) | `22` |
| Klíč serveru (rozšířené) | řádek known_hosts switche; prázdné s *Věřit prvnímu viděnému klíči serveru* vezme první |
| Ověřovat certifikát zařízení | zapnuto, jakmile NX-API servíruje certifikát vaší CA (u soukromé CA vyplňte *Certifikát CA*); vypnuto jen dokud má vlastní self-signed |
| HTTPS NX-API (nasazení) | zapnuto |
| Uložit konfiguraci (copy running-config startup-config) (nasazení) | zapnuto |
| Kolik předchozích verzí ponechat (rozšířené) | `1` |

## Ověření

Na switchi:

```text
show crypto ca trustpoints
show crypto ca certificates acme-www.example.com-20261112-a1b2c3d4
show nxapi
```

Ze stroje acme:

```sh
openssl s_client -connect n9k01.example.com:443 -servername n9k01.example.com </dev/null | openssl x509 -noout -subject -issuer -dates
curl -s -u acme -H 'Content-Type: application/json-rpc' -X POST https://n9k01.example.com/ins \
  -d '[{"jsonrpc":"2.0","method":"cli","params":{"cmd":"show version","version":1},"id":1}]'
```

## Časté potíže

| Co acme hlásí | Význam | Řešení |
|---|---|---|
| `scp to ...` | SCP odmítnuto | `feature scp-server`; role to musí povolit |
| `NX-OS said "% Invalid ..."` | příkaz odmítnut (práva, syntaxe) | role z kroku 2, nebo `network-admin` |
| *runs NX-OS 10.2(2)...* | příliš staré pro `nxapi certificate trustpoint` | aktualizujte, nebo certifikát vložte ručně |
| *NX-API restarted before it answered* | očekávané: NX-API se s novým certifikátem restartuje | test servírovaného certifikátu řekne, zda ho převzalo |
| `401` | špatný uživatel nebo heslo, nebo vypnuté NX-API | `show nxapi`, účet |

*Nejisté*: tvar odpovědi dávky JSON-RPC a pole `nxos_ver_str` z `show version` jsou obvyklé tvary NX-API; odstranění staršího trustpointu (`delete certificate force`, `delete ca-certificate`) je obvyklý postup NX-OS - úklid při selhání jen varuje.

Zdroje: Cisco Nexus 9000 NX-OS Security Configuration Guide 10.6(x) - Configuring PKI; NX-OS Programmability Guide 10.6(x) - NX-API CLI.
