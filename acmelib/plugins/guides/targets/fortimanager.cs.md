# FortiManager / FortiAnalyzer - nastavení pro acme

acme mluví s **JSON-RPC API** (`POST /jsonrpc`, HTTPS) FortiManageru nebo FortiAnalyzeru s **API tokenem** (`Authorization: Bearer <token>`). Certifikát přidá jako **lokální certifikát** systému pod jménem s datem (`acme-<jméno>-<datum>-<sériové číslo>`, nejvýš 35 znaků) - klíč zašifrovaný jednorázovým heslem, jak ho bere CLI -, mezilehlé certifikáty přidá jako certifikáty CA, nastaví ho jako **HTTPS certifikát GUI a API** a starší certifikáty acme nad počet *ponechat* smaže:

```text
add    /cli/global/system/certificate/local   {"name", "comment", "password", "private-key", "certificate"}
add    /cli/global/system/certificate/ca      {"name", "ca"}
set    /cli/global/system/admin/setting       {"admin_server_cert": "<jméno>"}
delete /cli/global/system/certificate/local/<starší jméno acme>
```

Totéž v CLI:

```text
config system certificate local
    edit "acme-fmg.example.com-20261112-a1b2c3"
        set password <heslo>
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY----- ... -----END ENCRYPTED PRIVATE KEY-----"
        set certificate "-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----"
    next
end
config system admin setting
    set admin_server_cert "acme-fmg.example.com-20261112-a1b2c3"
end
```

Jde o vlastní certifikát zařízení - ne o certifikáty FortiGate, které spravuje (na ty nasměrujte acme přímo u každé FortiGate), ani o certifikát FGFM mezi FortiGate a FortiManagerem.

## Pro které verze

FortiManager a FortiAnalyzer **7.2.2 - 7.6** (API tokeny existují od 7.2.2; od **7.4.7 / 7.6.2** se token přijímá jen v hlavičce - acme ho tam posílá vždy). GUI nastavení přesunulo ze *System Settings > Admin > Admin Settings* (7.2) do *System Settings > Settings → HTTPS & Web Service Certificate* (7.4 a novější); API je stejné.

## 1. API uživatel a jeho token

```text
config system admin user
    edit "acme"
        set trusthost1 192.0.2.10 255.255.255.255
        set profileid "Super_User"
        set user_type api
        set rpc-permit read-write
    next
end
execute api-user generate-key acme
```

- `192.0.2.10` je příklad: adresa acme (`trusthost2` … pro druhý uzel).
- `rpc-permit read-write` je pro JSON-RPC **povinné**.
- KB používá profil `Super_User`; menší profil, který smí zapisovat systémové certifikáty a nastavení administrace, Fortinet nedokumentuje - zkuste profil s *System Settings* pro čtení i zápis a vraťte se k `Super_User`, pokud acme dostane `-11` (bez oprávnění).
- Token se zobrazí jednou; nové `execute api-user generate-key acme` vytvoří nový (starý přestane platit).

## 2. HTTPS

Port HTTPS GUI je `https_port` v `config system admin setting` (výchozí 443). Na rozhraní, na které acme dosáhne, povolte HTTPS (`config system interface` → `set allowaccess https ...`).

## Vyplňte v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / Port HTTPS | FortiManager / FortiAnalyzer, `443` |
| API token | klíč z `execute api-user generate-key` |
| Ověřovat certifikát zařízení | zapnuto; vypnuto jen dokud má zařízení vlastní `server.crt` |
| HTTPS certifikát GUI a API (nasazení) | zapnuto (`admin_server_cert`); vypnuto, pokud se má certifikát jen přidat |
| Přidat mezilehlé certifikáty jako certifikáty CA (nasazení, pokročilé) | zapnuto |
| Kolik předchozích verzí ponechat (nasazení, pokročilé) | kolik starších certifikátů acme ponechat; ten, který používá GUI, se nikdy nesmaže |

GUI i API přejdou na nový certifikát hned: se zapnutým *Ověřovat certifikát zařízení* se další požadavky acme ověřují proti němu (u privátní CA vyplňte *Certifikát CA*).

## Ověřte to

```sh
openssl s_client -connect fmg.example.local:443 -servername fmg.example.local -showcerts </dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
curl -s -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"id":1,"method":"get","params":[{"url":"/cli/global/system/admin/setting"}]}' \
  "https://fmg.example.local/jsonrpc"
```

V CLI:

```text
get system certificate local
show system admin setting
```

## Časté problémy

| Odpověď (stavový kód) | Význam | Řešení |
|---|---|---|
| HTTP `401` | špatný token, nebo požadavek přišel mimo důvěryhodné adresy | nový token; adresa acme v `trusthost1` |
| `-11` No permission | profil nebo `rpc-permit` nedovoluje zápis | `set rpc-permit read-write`; profil (`Super_User`) |
| `-6` Invalid url | zařízení cestu nezná (starý firmware) | 7.2.2 nebo novější |
| `-2` / *already exist* při add | certifikát tohoto jména už existuje | acme se nejdřív dívá; s *vynutit* nasazujte až po jeho smazání |
| prohlížeč stále ukazuje `server.crt` | *HTTPS certifikát GUI a API* je vypnutý | zapněte ho |
| starší certifikát zůstal | stále se používá (jiné nastavení) | acme to oznámí a ponechá ho |

*Neověřeno* (z návodu výrobce): tělo JSON-RPC volání `add` (neoficiální návod; pole odpovídají oficiálnímu CLI a Ansible), pole `ca` certifikátu CA (Ansible), nejmenší profil administrátora a zda se restartuje webový server a odhlásí relace.
