# FortiGate (FortiOS 6.0 - 6.4) - nastavení pro acme

acme s FortiGate mluví přes **FortiOS REST API** s **API tokenem** (`Authorization: Bearer <token>`, jen HTTPS). Certifikát naimportuje pod jménem s datem (`acme-<jméno>-<datum>-<sériové číslo>`, nejvýš 35 znaků) přes `POST /api/v2/monitor/vpn-certificate/local/import` (PKCS#12 s jednorázovým heslem, nebo certifikát + klíč v PEM), mezilehlé certifikáty naimportuje jako CA, nastaví je službám, které zaškrtnete, a starší certifikáty acme nad počet *ponechat* smaže.

## Pro který FortiOS je tento návod

Verze modulu **„FortiOS 6.0 - 6.4“** (`6.0`): FortiOS **6.0.x, 6.2.x a 6.4.x**. Na jiné verzi FortiOS acme nasazení odmítne (dřív, než cokoli změní) a řekne, kterou verzi cíle zvolit.

| Verze modulu | FortiOS | `server-cert` inspekčního profilu | `ssl-certificate` VIP |
|---|---|---|---|
| jakákoli verze (zjistí ji) | 6.0 - 8.0 | podle verze | podle verze |
| FortiOS 6.0 - 6.4 | 6.0.x - 6.4.x | jméno | jméno |
| FortiOS 7.0 - 7.4.1 | 7.0.0 - 7.4.1 | seznam `{name}` | jméno |
| FortiOS 7.4.2 - 8.0 | 7.4.2 - 8.0 | seznam `{name}` | seznam `{name}` |

Vše ostatní, co acme používá - import certifikátu, `system global admin-server-cert`, `vpn ssl settings servercert`, mazání `vpn.certificate/local` - je v 6.0 - 8.0 stejné (Ansible kolekce Fortinetu 2.6.0, která u každého atributu uvádí verze FortiOS, a schémata z FortiOS 7.4.8). Nevíte, jaký FortiOS na krabici běží? `get system status` v CLI, nebo *Najít nastavení z účtu* v acme ukáže verzi i verzi modulu pro ni.

## Co acme na FortiGate mění

| Volba v acme | Nastavení FortiOS | Hodnota |
|---|---|---|
| (vždy) | `config vpn certificate local` | nový lokální certifikát `acme-...`; starší `acme-...` téhož certifikátu nad *ponechat* smazány (používaný zůstane) |
| Importovat mezilehlé certifikáty jako certifikáty CA (pokročilé, zapnuto) | `config vpn certificate ca` | mezilehlé CA, globálně; už existující se přeskočí |
| Certifikát administrace (GUI) | `config system global` / `set admin-server-cert` | nový certifikát (globální - certifikát musí být importován *globálně*) |
| Certifikát SSL VPN | `config vpn ssl settings` / `set servercert` | nový certifikát, ve VDOM |
| Inspekční profily SSL/SSH | `config firewall ssl-ssh-profile` / `set server-cert` | jedno jméno (`server-cert` je v 6.x jediný certifikát) - certifikát profilu se nahradí |
| Virtuální IP | `config firewall vip` / `set ssl-certificate` | jedno jméno |

acme nevytváří profily, VIP ani samotnou SSL VPN a nepřepíná inspekční profil na `server-cert-mode replace` - to nastavte jednou sami.

## Nahradit existující certifikát na místě (jeho použití zůstanou)

Když je certifikát na FortiGate už navázaný na politiky, VIP, pravidla ZTNA, ověřování uživatelů nebo cokoli jiného a chcete ho jen vyměnit, zvolte v nasazení **Certifikát na FortiGate: Nahradit existující certifikát na místě** a pak **Certifikát na FortiGate**:

- **Najít na zařízení** vypíše lokální certifikáty FortiGate přes REST s tokenem: jméno, CN, platnost, vydavatele, global/vdom, kolik objektů ho používá a začátek jeho SHA-256. FortiOS 7.6 je vypisuje bez PEM, proto acme tyto údaje bere z `GET /api/v2/monitor/system/available-certificates` (jinak přečte každý zvlášť). Ten se jmény certifikátu v acme je označen ★ a vybrán. Tovární certifikáty Fortinetu (`Fortinet_*`, zdroj *factory*) jsou vynechány - ty se nenahrazují.
- **Zadat ručně…** funguje vždy, např. když token nesmí certifikáty vypsat; řádek pod seznamem řekne, proč výpis selhal. Na velikosti písmen ve jménu záleží.

**Způsob nahrazení: REST API** (výchozí) nepotřebuje nic než token API - jeho profil správce potřebuje pro tuto výměnu jen **VPN (`vpngrp`) čtení i zápis** (víc jen pro to, co níže zaškrtnete nebo vypíšete). Žádné SSH. Každé nasazení:

```
1  GET  /api/v2/cmdb/vpn.certificate/local/<jméno>?with_meta=1     certifikát (není / tovární: konec)
2  GET  /api/v2/monitor/system/available-certificates?scope=…&with_ca=1   otisky všech certifikátů
3  POST /api/v2/monitor/vpn-certificate/ca/import                  každý chybějící mezilehlý, PŘED výměnou
4  DELETE /api/v2/cmdb/vpn.certificate/local/<kopie>               jen vlastní nepoužitá kopie nového certifikátu
5  PUT  /api/v2/cmdb/vpn.certificate/local/<jméno>                 nový certifikát (koncový) a jeho klíč,
                                                                   zašifrovaný jednorázovým heslem
6  GET  /api/v2/cmdb/vpn.certificate/local/<jméno>?with_meta=1     jeho otisk musí být ten nový
```

Běžná obnova jsou kroky 1, 2, 5 a 6 - jediný zápis. Když FortiOS PUT odmítne, nic nezmění a acme řekne proč: *duplicated* (stejný certifikát pod jiným jménem), *Invalid private key, password may be required* (klíč nebo jeho heslo), *not a valid/matched certificate* (klíč jiného certifikátu). Služba, která certifikát používá (administrační GUI, VIP…), začne nový posílat sama během několika sekund.

**Způsob nahrazení: SSH** je druhá cesta (CLI FortiOS, jako v acme 1.0.129). Vyplňte v cíli **Uživatel SSH (nahrazení přes SSH)** a jeho klíč nebo **Heslo SSH** - správce, který smí měnit certifikáty VPN (`vpngrp` čtení i zápis; certifikát v rozsahu *global* potřebuje `scope global`, např. *super_admin*). *Zkusit spojení* na kartě klíče spustí `get system status`. Pole SSH jsou nepovinná a používá je jen tato cesta; bez nich nasazení nastavené na SSH selže dřív, než se cokoli změní. Přes SSH acme spustí:

```
get system status                                (verze, VDOM)
[config global | config vdom / edit <vdom>]      jen se zapnutými VDOM: podle rozsahu certifikátu
config vpn certificate local
  edit "<jméno>"
    set password "<jednorázové heslo>"           klíč jde zašifrovaný tímto heslem
    set private-key "<PEM>"
    set certificate "<certifikát, PEM>"
  abort                                          nejdřív: FortiOS řádky zkontroluje, nic se neuloží
```

a když FortiOS přijal každý řádek, tytéž řádky zakončené `next` / `end` (uloží se); potom certifikát přečte zpět.

Obě cesty:

- **Uloží se jen koncový certifikát**: FortiOS si ponechá samotný certifikát a zbytek řetězce zahodí; řetězec posílá ze svých certifikátů CA. Proto acme mezilehlé certifikáty importuje jako certifikáty CA (přes REST API *před* výměnou, aby se celý řetězec posílal od první sekundy).
- **Duplikáty**: FortiOS nikdy nedrží tentýž lokální certifikát pod dvěma jmény („This local certificate is duplicated“) - např. stejný certifikát, který dříve importovalo nasazení ve výchozím režimu (to byla chyba acme 1.0.128). acme nový certifikát nejdřív hledá podle otisku: už je pod zvoleným jménem - není co dělat („už na místě“); kopie, kterou acme vytvořilo pro tento certifikát (`acme-<jméno>-…`) - nejdřív se smaže a řekne se to; kopii, která se používá, FortiOS smazat odmítne („currently being used“, `-23`) - nasazení se pak zastaví a cíl zůstane nedotčen: přepojte použití kopie na zvolené jméno a nasaďte znovu; kopie, kterou acme nevytvořilo - nasazení se zastaví dřív, než se cokoli změní, a kopii jmenuje. Zvolený certifikát se nikdy nemaže a tento režim certifikát pod novým jménem nikdy neimportuje.
- **Jméno zůstane**, takže vše, co je na něj navázané, ho dál používá a nic se nepřepojuje. Administrační GUI, SSL VPN, profily a VIP se nastavují jen tehdy, když je zaškrtnete nebo vypíšete - a to na totéž jméno. Typ klíče se může změnit (RSA → ECDSA): použití certifikátu zůstanou.
- Jméno, které na FortiGate není, selže dřív, než se cokoli změní; *Co se stane* ukáže každý krok (u REST API: čtení, certifikáty CA k importu, kopie ke smazání, výměnu a kontrolu).
- Když FortiOS odmítne, nasazení selže s jeho chybovými řádky (nikdy s PEM nebo klíčem) a starý certifikát zůstane, jak byl. Úklid starších certifikátů `acme-...` nahrazený certifikát nikdy nevezme.
- **Jméno nejde upravit - to je v pořádku**: FortiOS lokální certifikát nikdy přejmenovat nedovolí; *Upravit* v jeho GUI ukáže u každého importovaného certifikátu jen *Komentáře*. Nahrazení na místě je právě způsob, jak si certifikát jméno ponechá.
- Stejné ve všech verzích modulu (FortiOS 6.0 - 8.0). Změřeno na FortiOS 7.6.8; na 7.4 a starších se čeká totéž API (na zařízení zatím neověřeno).

## Nastavení FortiGate

Profil a API uživatele musí založit *super_admin* (API admina smí vytvořit či změnit jen super admin).

### 1. Profil administrátora s nejmenšími právy, která acme potřebuje

| Co acme dělá | Skupina oprávnění (accprofile) | Potřeba |
|---|---|---|
| Čte verzi (`monitor/system/status`) | jakákoli | vždy |
| Import / mazání certifikátů, import CA, `servercert` SSL VPN | `vpngrp` read-write | vždy (reference REST API 6.0.4 uvádí u importu certifikátů skupinu `vpngrp`) |
| Certifikát administrace (`system global`) | `sysgrp` custom, `cfg` read-write | když je zaškrtnuta *administrace* |
| Virtuální IP (`firewall vip`) | `fwgrp` read-write | když jsou uvedeny VIP |
| Inspekční profily SSL/SSH (`firewall ssl-ssh-profile`) | `utmgrp` read-write (Security Profiles) | když jsou uvedeny profily |

```text
config system accprofile
    edit "acme-cert"
        set comments "acme: certificates, admin GUI, SSL VPN, inspection profiles, VIPs"
        set scope global
        set secfabgrp none
        set ftviewgrp none
        set authgrp none
        set sysgrp custom
        set netgrp none
        set loggrp none
        set fwgrp read-write
        set vpngrp read-write
        set utmgrp read-write
        set wifi none
        config sysgrp-permission
            set admin none
            set upd none
            set cfg read-write
            set mnt none
        end
    next
end
```

- `set scope global` dovolí API uživateli import do **globálního** rozsahu (výchozí v acme, nutné pro administraci): podle reference je globální rozsah jen pro globální administrátory. Bez VDOM řádek nevadí; importujete-li jen do VDOM (*Importovat do: VDOM*) a administraci nenastavujete, stačí `scope vdom`.
- Co nepoužíváte, vynechte: bez VIP `set fwgrp none`; bez inspekčních profilů `set utmgrp none`; bez administrace `set sysgrp none` (*nejisté*: na některých verzích se úložiště certifikátů může kontrolovat i proti `sysgrp cfg` - pokud import s `vpngrp` read-write vrátí 403, vraťte `cfg` read-write).

### 2. REST API admin, jeho důvěryhodné adresy a token

Do důvěryhodných adres (trusted hosts) dejte adresy serverů acme - každého uzlu clusteru: aspoň jedna je povinná a požadavek odjinud je odmítnut.

```text
config system api-user
    edit "acme"
        set comments "acme certificate manager"
        set accprofile "acme-cert"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.0.2.10 255.255.255.255
            next
        end
    next
end
```

- `192.0.2.10` je příklad - použijte adresu acme (`ipv6-trusthost` pro IPv6, další `edit 2` pro druhý uzel).
- `set vdom "root"`: VDOM, ve kterém API uživatel pracuje; s VDOM uveďte VDOM se SSL VPN, profily a VIP.
- `peer-auth` nechte vypnuté (acme klientský certifikát neposílá) a `cors-allow-origin` prázdné.

Vygenerujte token - ukáže se **jen jednou**:

```text
execute api-user generate-key acme
```

V GUI totéž: *System → Administrators → Create New → REST API Admin* (profil `acme-cert`, *Trusted Hosts*, token se ukáže po *OK*). Nový klíč nahradí starý.

### 3. VDOM

- Bez VDOM: pole *VDOM* v acme nechte prázdné (nebo `root`).
- S VDOM: acme posílá `?vdom=<VDOM>` (VDOM cíle, nebo nasazení). SSL VPN, inspekční profily a VIP jsou v každé VDOM zvlášť; certifikát administrace je globální.
- *Importovat do: globálně* (výchozí) zpřístupní certifikát všem VDOM i administraci; potřebuje profil se `scope global`. *VDOM* jej naimportuje jen tam.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Verze modulu | **FortiOS 6.0 - 6.4** |
| Adresa / HTTPS port | adresa správy FortiGate a jeho HTTPS port administrace (`admin-sport`, výchozí 443) |
| API token | klíč z `execute api-user generate-key` |
| VDOM | `root`, vaše VDOM, nebo prázdné bez VDOM |
| Ověřovat certifikát zařízení | zapnuto; vypnuto jen dokud má FortiGate vlastní `Fortinet_GUI_Server` |
| Certifikát administrace / SSL VPN (nasazení) | zaškrtněte, co má certifikát používat |
| Inspekční profily SSL/SSH, Virtuální IP (nasazení) | jedno jméno na řádek, např. `inbound-replace`, `vip-www` |
| Uživatel SSH (nahrazení přes SSH), jeho klíč nebo heslo SSH | jen když *Způsob nahrazení* je SSH: správce s `vpngrp` čtení i zápis (rozsah global: `scope global`); jinak prázdné - nahrazení přes REST API stačí token |
| Kolik předchozích verzí ponechat (pokročilé) | kolik starších certifikátů acme ponechat (používaný se nikdy nesmaže) |

Administrace přejde na nový certifikát hned: se zapnutým *Ověřovat certifikát zařízení* se další požadavky acme ověřují proti němu (certifikát veřejné CA projde; u soukromé CA nastavte *CA certifikát*). Skupiny, které profil neuvádí, mají výchozí `none`.

## Kontrola

V CLI:

```text
show system global | grep admin-server-cert
show vpn ssl settings | grep servercert
show firewall ssl-ssh-profile <profile> | grep server-cert
    set server-cert "acme-www.example.com-20261112-a1b2c3"
show firewall vip <vip> | grep ssl-certificate
# the certificate itself (the command may differ between versions):
get vpn certificate local details acme-www.example.com-20261112-a1b2c3
```

Token ze stroje acme:

```sh
curl -sS -H "Authorization: Bearer $TOKEN" "https://fw.example.local/api/v2/monitor/system/status"
```

Ladění REST API na FortiGate (ukáže každý požadavek a proč byl odmítnut):

```text
diagnose debug application httpsd -1
diagnose debug enable
# ... spusťte nasazení v acme ...
diagnose debug disable
diagnose debug reset
```

## Časté chyby

| Odpověď | Význam | Řešení |
|---|---|---|
| `401` | neplatný token, nebo požadavek mimo důvěryhodné adresy | zkontrolujte token (vygenerujte nový), přidejte adresu acme do `trusthost`; za NAT vidí FortiGate adresu NAT |
| `403` | profilu chybí oprávnění | doplňte skupinu z kroku 1 (certifikáty: `vpngrp`; administrace: `sysgrp cfg`; VIP: `fwgrp`; profily: `utmgrp`); globální import potřebuje `scope global` |
| `404` | takový profil / VIP / VDOM není | zkontrolujte jména (záleží na velikosti písmen) a VDOM |
| `424` (Failed Dependency) | neplatná hodnota: např. jméno certifikátu, který v této VDOM není, nebo špatný tvar `server-cert` / `ssl-certificate` | importujte *globálně* (nebo do správné VDOM); zvolte verzi modulu pro FortiOS, který na krabici běží |
| `429` | omezení počtu požadavků po mnoha špatných tokenech | počkejte, opravte token |
| `500` s `"error": <záporné číslo>` | FortiOS změnu odmítl (`-328` při importu CA: ta už tam je - ověřeno, acme to jen jednou poznamená) | přečtěte detail v úloze acme a ladění `httpsd` |
| *FortiOS refused to replace … in place* | FortiOS nepřijal nový certifikát či klíč lokálního certifikátu (důvod a jeho chybové řádky jsou uvedeny); nic se nezměnilo, starý zůstal | *duplicated*: jiný lokální certifikát je tentýž - viz Duplikáty výše; *Invalid private key*: klíč nebo heslo; *not a valid/matched*: klíč jiného certifikátu |
| *replace in place over SSH ("How to replace": SSH) and the target has no SSH sign-in* | způsob SSH potřebuje v cíli uživatele SSH a klíč nebo heslo | vyplňte je (správce s `vpngrp` čtení i zápis), nebo zvolte REST API |
| *… an earlier import of acme that is in use - FortiOS refused to delete it (-23 …)* | kopie nového certifikátu se používá, FortiOS ji nesmaže | přepojte její použití na zvolené jméno a nasaďte znovu |
| *the FortiGate has this very certificate already as …* | shodný lokální certifikát pod jiným jménem, používaný nebo ne od acme - FortiOS duplikát odmítne | přepojte jeho použití na zvolené jméno, smažte ho, nasaďte znovu |
| *there is no local certificate …* | to jméno na FortiGate (v té VDOM) není | **Najít na zařízení**, nebo jméno přesně (velikost písmen) |
| *the module version ... is for FortiOS ...* | na krabici běží jiný FortiOS, než pro který je tato verze cíle | zvolte verzi uvedenou ve zprávě (nebo *jakoukoli verzi*) |

*Nejisté*: zda je po změně přes REST potřeba uložení, když je `cfg-save` nastaveno na `manual` (ve výchozím stavu se ukládá); přesná záporná čísla chyb FortiOS se mezi verzemi liší.

Zdroje: Ansible kolekce Fortinetu `fortinet.fortios` 2.6.0 (rozsahy verzí atributů 6.0.0 - 8.0.0), schémata CMDB FortiOS 7.4.8, reference FortiOS 6.0.4 REST API (token, důvěryhodné adresy, skupiny oprávnění, HTTP kódy) a monitor API FortiOS 7.6.
