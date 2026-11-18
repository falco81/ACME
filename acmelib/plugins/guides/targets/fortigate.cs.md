# FortiGate (jakákoli verze - zjistí ji) - nastavení pro acme

acme s FortiGate mluví přes **FortiOS REST API** s **API tokenem** (`Authorization: Bearer <token>`, jen HTTPS). Certifikát naimportuje pod jménem s datem (`acme-<jméno>-<datum>-<sériové číslo>`, nejvýš 35 znaků) přes `POST /api/v2/monitor/vpn-certificate/local/import` (PKCS#12 s jednorázovým heslem, nebo certifikát + klíč v PEM), mezilehlé certifikáty naimportuje jako CA, nastaví je službám, které zaškrtnete, a starší certifikáty acme nad počet *ponechat* smaže.

## Pro který FortiOS je tento návod

Verze modulu **„jakákoli verze (zjistí ji)“** (`''`): FortiOS **6.0 až 8.0** - acme si verzi přečte z `monitor/system/status` a tvar polí zvolí sám; když verzi nepřečte nebo je tvar odmítnut, zkusí ten druhý.

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
| Inspekční profily SSL/SSH | `config firewall ssl-ssh-profile` / `set server-cert` | podle verze: jméno do 6.4, seznam certifikátů od 7.0 |
| Virtuální IP | `config firewall vip` / `set ssl-certificate` | podle verze: jméno do 7.4.1, seznam certifikátů od 7.4.2 |

**SSL VPN na FortiOS 7.6.3 a novějším**: tunelový režim SSL VPN zmizel (jeho nastavení jako `tunnel-ip-pools` a `dtls-tunnel` v datech API končí verzí 7.6.2) a webový režim se jmenuje *Agentless VPN*; `vpn ssl settings servercert` zůstává a ten acme nastavuje. Na FortiOS 7.6 některé menší modely SSL VPN vůbec nemají (z release notes Fortinetu, *není* v dokumentech API - ověřte u svého); tam *Certifikát SSL VPN* nechte vypnutý.

acme nevytváří profily, VIP ani samotnou SSL VPN a nepřepíná inspekční profil na `server-cert-mode replace` - to nastavte jednou sami.

## Nahradit existující certifikát na místě (jeho použití zůstanou)

Když je certifikát na FortiGate už navázaný na politiky, VIP, pravidla ZTNA, ověřování uživatelů nebo cokoli jiného a chcete ho jen vyměnit, zvolte v nasazení **Certifikát na FortiGate: Nahradit existující certifikát na místě** a pak **Certifikát na FortiGate**:

- **Najít na zařízení** vypíše lokální certifikáty FortiGate (`GET /api/v2/cmdb/vpn.certificate/local?with_meta=1`, přes REST s tokenem): jméno, CN, platnost, vydavatele, global/vdom a kolik objektů ho používá. Ten se jmény certifikátu v acme je označen ★ a vybrán. Tovární certifikáty Fortinetu (`Fortinet_*`, zdroj *factory*) jsou vynechány - ty se nenahrazují.
- **Zadat ručně…** funguje vždy, např. když token nesmí certifikáty vypsat; řádek pod seznamem řekne, proč výpis selhal. Na velikosti písmen ve jménu záleží.

**Nahrazení na místě jde přes SSH.** Vyplňte v cíli **Uživatel SSH (nahrazení na místě)** a jeho klíč nebo **Heslo SSH** - správce, který smí měnit certifikáty VPN (`vpngrp` čtení i zápis; certifikát v rozsahu *global* potřebuje `scope global`, např. *super_admin*). *Zkusit spojení* na kartě klíče spustí `get system status`. Bez přihlášení SSH nasazení v tomto režimu selže dřív, než se cokoli změní; výchozí režim (pokaždé nový certifikát) SSH nikdy nepoužívá.

*Proč ne REST API*: FortiOS změnu `certificate` lokálního certifikátu přes REST převádí na řádky CLI a PEM na více řádcích je rozbije - FortiOS 7.4.13 odpoví `500`, chyba `-651`, „value parse error before '-----BEGIN CERTIFICATE-----'“ a nezmění nic. CLI ho přijme.

Každé nasazení pak přes SSH:

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

a když FortiOS přijal každý řádek, tytéž řádky zakončené `next` / `end` (uloží se). Když FortiOS zašifrovaný klíč odmítne, zkusí se nešifrovaný klíč PEM. Jakákoli chyba v odpovědi FortiOS („Command fail“, „duplicated“, „not a valid“…) to zastaví a nic se neuloží; potom acme certifikát přečte zpět a jeho otisk musí být ten nový. Mezilehlé certifikáty se importují jako certifikáty CA jako obvykle. **Jméno zůstane**, takže vše, co je na něj navázané, ho dál používá a nic se nepřepojuje. Administrační GUI, SSL VPN, profily a VIP se nastavují jen tehdy, když je zaškrtnete nebo vypíšete - a to na totéž jméno. Typ klíče se může změnit (RSA → ECDSA): použití certifikátu zůstanou.

- **Duplikáty**: FortiOS odmítne lokální certifikát shodný s jiným („This local certificate is duplicated“) - např. stejný certifikát, který dříve importovalo nasazení ve výchozím režimu. acme nový certifikát nejdřív porovná se všemi lokálními certifikáty: už je pod zvoleným jménem - není co dělat („už na místě“); nepoužitá kopie, kterou vytvořilo acme (`acme-…`, nic ji nepoužívá) - nejdřív se smaže a řekne se to; kopie, která se používá, nebo kterou nevytvořilo acme - nasazení se zastaví dřív, než se cokoli změní, a kopii jmenuje: přepojte její použití na zvolené jméno, kopii smažte a nasaďte znovu.
- Jméno, které na FortiGate není, selže dřív, než se cokoli změní; *Co se stane* ukáže přihlášení SSH, který certifikát se nahradí, duplikáty a řádky CLI (bez klíče).
- Když FortiOS odmítne, nasazení selže s jeho chybovými řádky (nikdy s PEM nebo klíčem) a starý certifikát zůstane, jak byl; nikdy se nemaže. Úklid starších certifikátů `acme-...` nahrazený certifikát nikdy nevezme.
- **Jméno nejde upravit - to je v pořádku**: FortiOS lokální certifikát nikdy přejmenovat nedovolí; *Upravit* v jeho GUI ukáže u každého importovaného certifikátu jen *Komentáře*. Nahrazení na místě je právě způsob, jak si certifikát jméno ponechá.
- Stejné ve všech verzích modulu (FortiOS 6.0 - 8.0).

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
- Užší práva k firewallu (FortiOS 7.0.1 a novější mají ve `fwgrp-permission` položku `others`). *Nejisté*: dokumenty neříkají, do které části VIP patří (*Address* nebo *Other*), proto obě:

```text
config system accprofile
    edit "acme-cert"
        set fwgrp custom
        config fwgrp-permission
            set policy none
            set address read-write
            set service none
            set schedule none
            set others read-write
        end
    next
end
```

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
| Verze modulu | **jakákoli verze (zjistí ji)** |
| Adresa / HTTPS port | adresa správy FortiGate a jeho HTTPS port administrace (`admin-sport`, výchozí 443) |
| API token | klíč z `execute api-user generate-key` |
| VDOM | `root`, vaše VDOM, nebo prázdné bez VDOM |
| Ověřovat certifikát zařízení | zapnuto; vypnuto jen dokud má FortiGate vlastní `Fortinet_GUI_Server` |
| Certifikát administrace / SSL VPN (nasazení) | zaškrtněte, co má certifikát používat |
| Inspekční profily SSL/SSH, Virtuální IP (nasazení) | jedno jméno na řádek, např. `inbound-replace`, `vip-www` |
| Uživatel SSH (nahrazení na místě), jeho klíč nebo heslo SSH | jen pro *Nahradit existující certifikát na místě*: správce s `vpngrp` čtení i zápis (rozsah global: `scope global`); jinak prázdné |
| Kolik předchozích verzí ponechat (pokročilé) | kolik starších certifikátů acme ponechat (používaný se nikdy nesmaže) |

Administrace přejde na nový certifikát hned: se zapnutým *Ověřovat certifikát zařízení* se další požadavky acme ověřují proti němu (certifikát veřejné CA projde; u soukromé CA nastavte *CA certifikát*). Skupiny, které profil neuvádí, mají výchozí `none`.

## Kontrola

V CLI:

```text
show system global | grep admin-server-cert
show vpn ssl settings | grep servercert
show firewall ssl-ssh-profile <profile> | grep server-cert
# 6.x: set server-cert "acme-www.example.com-20261112-a1b2c3"
# 7.0+: set server-cert "Fortinet_SSL_ECDSA256" "acme-www.example.com-20261112-a1b2c3"
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
| `500` s `"error": <záporné číslo>` | FortiOS změnu odmítl (`-328` při importu CA: ta už tam je - acme to jen jednou poznamená) | přečtěte detail v úloze acme a ladění `httpsd` |
| *FortiOS refused to replace … in place* | CLI FortiOS nepřijalo nový certifikát či klíč lokálního certifikátu (jeho chybové řádky jsou uvedeny); nic se neuložilo, starý zůstal | řádky v úloze acme; *duplicated*: jiný lokální certifikát je tentýž - viz Duplikáty výše; jinak výchozí režim (nový certifikát) |
| *replace in place goes over SSH and the target has no SSH sign-in* | režim potřebuje v cíli uživatele SSH a klíč nebo heslo | vyplňte je (správce s `vpngrp` čtení i zápis) |
| *the FortiGate has this very certificate already as …* | shodný lokální certifikát pod jiným jménem, používaný nebo ne od acme - FortiOS duplikát odmítne | přepojte jeho použití na zvolené jméno, smažte ho, nasaďte znovu |
| *there is no local certificate …* | to jméno na FortiGate (v té VDOM) není | **Najít na zařízení**, nebo jméno přesně (velikost písmen) |
| *the module version ... is for FortiOS ...* | na krabici běží jiný FortiOS, než pro který je tato verze cíle | zvolte verzi uvedenou ve zprávě (nebo *jakoukoli verzi*) |
| SSL VPN odmítnuta na 7.6 | model nemá SSL VPN / Agentless VPN | *Certifikát SSL VPN* nechte vypnutý |

*Nejisté*: zda je po změně přes REST potřeba uložení, když je `cfg-save` nastaveno na `manual` (ve výchozím stavu se ukládá); přesná záporná čísla chyb FortiOS se mezi verzemi liší.

Zdroje: Ansible kolekce Fortinetu `fortinet.fortios` 2.6.0 (rozsahy verzí atributů 6.0.0 - 8.0.0), schémata CMDB FortiOS 7.4.8, reference FortiOS 6.0.4 REST API (token, důvěryhodné adresy, skupiny oprávnění, HTTP kódy) a monitor API FortiOS 7.6.
