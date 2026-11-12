# FortiWeb - nastavení pro acme

acme nasazuje certifikáty na Fortinet FortiWeb přes jeho REST API v2.0. Každé nasazení importuje certifikát a klíč jako **lokální certifikát** pod jménem s datem (`acme-…`), vloží mezilehlé certifikáty do **skupiny intermediate CA** (nahrané acme jako `acme-chain-…`, nebo vaše skupina, nebo žádná), nasměruje na obojí zadané **server policy** a smaže starší lokální certifikáty acme, které už žádná policy nepoužívá.

FortiWeb nemá vlastní API tokeny: acme se přihlašuje jménem a heslem administrátora, které posílá s každým požadavkem (`Authorization: base64({"username", "password", "vdom"})`).

## Co potřebujete

- FortiWeb s REST API v2.0 (FortiWeb 6.x / 7.x).
- Přístup HTTPS z acme na správcové rozhraní FortiWebu (výchozí port 443), s povoleným administrativním přístupem HTTPS na tom rozhraní.
- Administrátorský účet pro acme.
- Aspoň jednu HTTPS **server policy**, která má certifikát používat.

## Nastavení FortiWebu

1. Vytvořte pro acme admin profil: **System → Admin → Admin Profiles → Create New**, např. `acme`, s **read-write** na oblasti, které acme mění - systémové certifikáty (lokální certifikáty, intermediate CA a jejich skupiny) a server policy - a jinde jen čtení nebo nic. Názvy oblastí se mezi verzemi liší; ověřte je ve své.
2. Vytvořte administrátora: **System → Admin → Administrators → Create New**:
   - **Administrator**: `acme`, typ lokální uživatel, silné heslo;
   - **Trusted Host**: jen adresa acme serveru;
   - **Access Profile**: `acme`;
   - jsou-li zapnuté administrativní domény (ADOM/VDOM), přidělte doménu, ve které policy jsou.
3. Poznamenejte si jména server policy (**Policy → Server Policy**), pro které certifikát je.
4. Rozhodněte, jak naložit s mezilehlými certifikáty:
   - *uploaded by acme* (výchozí): acme jednou nahraje řetězec CA a vytvoří skupinu `acme-chain-…`;
   - *a group of mine*: nejdřív ji vytvořte v **System → Certificates → Intermediate CA Group**;
   - *none*: policy si ponechá svou skupinu mezilehlých certifikátů.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | jméno nebo IP správcového rozhraní FortiWebu |
| HTTPS port | 443 (nebo administrátorský port HTTPS) |
| User | administrátor z kroku 2 |
| Password | jeho heslo |
| VDOM | administrativní doména; prázdné na FortiWebu bez administrativních domén |
| Check the device's certificate | zapnuto; vypnout jen dokud má FortiWeb self-signed certifikát |
| CA certificate (pokročilé) | CA vlastního certifikátu FortiWebu, když není veřejná |
| Server policy (nasazení) | HTTPS server policy (vyberte ze seznamu nebo napište) |
| More server policies | další jména policy, jedno na řádek |
| Intermediates | uploaded by acme as a group / a group of mine / none |
| Intermediate CA group | jméno vaší skupiny, když je *Intermediates* „a group of mine“ |
| Previous versions to keep | kolik starších lokálních certifikátů acme zůstane |
| Check what is served | `adresa-vip:443`, jedna na řádek |

## Ověření

- **Test** v acme se přihlásí a přečte stav systému; akce **List the server policies** ukáže každou policy a certifikát, který používá, bez jakékoli změny.
- Ve FortiWebu ukazuje **System → Certificates → Local** nový certifikát `acme-…` a policy (**Policy → Server Policy**) ho uvádí.
- Z příkazové řádky:

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com -showcerts </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 nebo `FortiWeb said error …` při Testu | špatný uživatel/heslo, trusted host nezahrnuje acme, nebo špatný VDOM |
| `FortiWeb has no server policy "…"` | jméno se musí přesně shodovat, v zadaném VDOM |
| `Intermediates "a group of mine" needs the group's name` | vyplňte *Intermediate CA group* |
| Import odmítnut | admin profil nemá read-write na certifikáty, nebo vaše verze nepodporuje typ klíče |
| Nahrání mezilehlého certifikátu selže | vytvořte skupinu sami a zvolte *a group of mine* |
| `the older … stays: a server policy still uses it` | starý certifikát ještě uvádí jiná policy; přepněte ji na nový nebo ji uveďte v *More server policies* |
