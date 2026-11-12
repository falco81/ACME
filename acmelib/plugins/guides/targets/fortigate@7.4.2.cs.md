# FortiGate (FortiOS 7.4.2 - 8.0) - nastavení pro acme

acme s FortiGate mluví přes **FortiOS REST API** s **API tokenem** (`Authorization: Bearer <token>`, jen HTTPS). Certifikát naimportuje pod jménem s datem (`acme-<jméno>-<datum>-<sériové číslo>`, nejvýš 35 znaků) přes `POST /api/v2/monitor/vpn-certificate/local/import` (PKCS#12 s jednorázovým heslem, nebo certifikát + klíč v PEM), mezilehlé certifikáty naimportuje jako CA, nastaví je službám, které zaškrtnete, a starší certifikáty acme nad počet *ponechat* smaže.

## Pro který FortiOS je tento návod

Verze modulu **„FortiOS 7.4.2 - 8.0“** (`7.4.2`): FortiOS **7.4.2 a novější 7.4.x, 7.6.x a 8.0**. Na starší verzi acme nasazení odmítne (dřív, než cokoli změní) a řekne, kterou verzi cíle zvolit; na FortiOS novějším než 8.0 pokračuje s varováním (s jeho API nebylo ověřeno).

| Verze modulu | FortiOS | `server-cert` inspekčního profilu | `ssl-certificate` VIP |
|---|---|---|---|
| libovolná verze (zjistí ji) | 6.0 - 8.0 | podle verze | podle verze |
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
| Inspekční profily SSL/SSH | `config firewall ssl-ssh-profile` / `set server-cert` | seznam certifikátů - acme ponechá ostatní a nahradí jen svůj |
| Virtuální IP | `config firewall vip` / `set ssl-certificate` | seznam certifikátů (od 7.4.2 může VIP mít RSA i ECDSA) - acme ponechá ostatní |

**SSL VPN na FortiOS 7.6.3 a novějším**: tunelový režim SSL VPN zmizel (jeho nastavení jako `tunnel-ip-pools` a `dtls-tunnel` v datech API končí verzí 7.6.2) a webový režim se jmenuje *Agentless VPN*; `vpn ssl settings servercert` zůstává a ten acme nastavuje. Na FortiOS 7.6 některé menší modely SSL VPN vůbec nemají (z release notes Fortinetu, *není* v dokumentech API - ověřte u svého); tam *Certifikát SSL VPN* nechte vypnutý.

acme nevytváří profily, VIP ani samotnou SSL VPN a nepřepíná inspekční profil na `server-cert-mode replace` - to nastavte jednou sami.

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
| Verze modulu | **FortiOS 7.4.2 - 8.0** |
| Adresa / HTTPS port | adresa správy FortiGate a jeho HTTPS port administrace (`admin-sport`, výchozí 443) |
| API token | klíč z `execute api-user generate-key` |
| VDOM | `root`, vaše VDOM, nebo prázdné bez VDOM |
| Ověřovat certifikát zařízení | zapnuto; vypnuto jen dokud má FortiGate vlastní `Fortinet_GUI_Server` |
| Certifikát administrace / SSL VPN (nasazení) | zaškrtněte, co má certifikát používat |
| Inspekční profily SSL/SSH, Virtuální IP (nasazení) | jedno jméno na řádek, např. `inbound-replace`, `vip-www` |
| Kolik předchozích verzí ponechat (pokročilé) | kolik starších certifikátů acme ponechat (používaný se nikdy nesmaže) |

Administrace přejde na nový certifikát hned: se zapnutým *Ověřovat certifikát zařízení* se další požadavky acme ověřují proti němu (certifikát veřejné CA projde; u soukromé CA nastavte *CA certifikát*). Skupiny, které profil neuvádí, mají výchozí `none`.

## Kontrola

V CLI:

```text
show system global | grep admin-server-cert
show vpn ssl settings | grep servercert
show firewall ssl-ssh-profile <profile> | grep server-cert
    set server-cert "Fortinet_SSL_ECDSA256" "acme-www.example.com-20261112-a1b2c3"
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
| `500` s `"error": <záporné číslo>` | FortiOS změnu odmítl (např. CA už existuje při importu - to acme ignoruje) | přečtěte detail v úloze acme a ladění `httpsd` |
| *the module version ... is for FortiOS ...* | na krabici běží jiný FortiOS, než pro který je tato verze cíle | zvolte verzi uvedenou ve zprávě (nebo *libovolnou verzi*) |
| SSL VPN odmítnuta na 7.6 | model nemá SSL VPN / Agentless VPN | *Certifikát SSL VPN* nechte vypnutý |

*Nejisté*: zda je po změně přes REST potřeba uložení, když je `cfg-save` nastaveno na `manual` (ve výchozím stavu se ukládá); přesná záporná čísla chyb FortiOS se mezi verzemi liší.

Zdroje: Ansible kolekce Fortinetu `fortinet.fortios` 2.6.0 (rozsahy verzí atributů 6.0.0 - 8.0.0), schémata CMDB FortiOS 7.4.8, reference FortiOS 6.0.4 REST API (token, důvěryhodné adresy, skupiny oprávnění, HTTP kódy) a monitor API FortiOS 7.6.
