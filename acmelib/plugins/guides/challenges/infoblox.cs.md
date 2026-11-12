# Infoblox NIOS - nastavení pro acme

acme prokazuje jména metodou DNS-01 v autoritativní zóně gridu Infoblox NIOS. Komunikuje s REST API Grid Masteru (WAPI) přes HTTP basic autentizaci: vypíše autoritativní zóny DNS view (`zone_auth`), pro každou hodnotu přidá jeden `record:txt` na `_acme-challenge.JMÉNO` (s komentářem `acme DNS-01`) a potom smaže právě tento záznam. Jiných TXT hodnot na stejném jménu se nedotkne.

Pro gridy NIOS s WAPI `2.10` nebo novějším (acme nic novějšího nepoužívá).

## Co potřebujete

- Grid NIOS, ve kterém je zóna jako **autoritativní zóna** v DNS view a obsluhují ji členové gridu, kterých se ptá internet.
- HTTPS (TCP 443) z acme na Grid Master (nebo jeho VIP).
- Certifikát CA (PEM), která podepsala certifikát Grid Masteru, pokud jde o vlastní CA organizace.

## Nastavení Infobloxu

1. Zjistěte verzi WAPI gridu: Grid Manager → **Help → About**, nebo v prohlížeči `https://GRID-MASTER/wapi/v1.0/?_schema`.
2. Vytvořte pro acme skupinu administrátorů: **Administration → Administrators → Groups → Add**.
   - **Ne**dělejte z ní skupinu superuserů.
   - V **Allowed Interfaces** zaškrtněte jen **API** (acme nepotřebuje GUI).
3. Dejte skupině oprávnění: **Administration → Administrators → Permissions → Add** (pro skupinu):
   - **Read/Write** na zóny, které smí acme měnit, nebo - úžeji - **Read/Write na TXT záznamy** v těchto zónách a **Read-Only** na zóny samotné (acme musí vypsat `zone_auth` daného view).
   - **Read-Only** na DNS view, pokud chcete, aby acme ve formuláři nabízel views.
4. Vytvořte pro acme vlastního uživatele: **Administration → Administrators → Admins → Add**, člen této skupiny, lokální autentizace, dlouhé náhodné heslo.
5. Exportujte CA, která podepsala HTTPS certifikát Grid Masteru (PEM), pokud to není veřejná CA.

Rychlá kontrola z libovolného shellu, který na Grid Master dosáhne:

```sh
curl --cacert gm-ca.pem -u acme:'HESLO' \
  'https://gm.example.local/wapi/v2.10/zone_auth?view=default&_return_fields=fqdn'
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Grid Master | `https://gm.example.local` - Grid Master nebo jeho VIP, bez `/wapi` |
| WAPI version | verze, kterou grid mluví, např. `2.10` (pokročilé) |
| User name | uživatel pro acme |
| Password | jeho heslo |
| DNS view | `default`, pokud grid nepoužívá jiná views |
| Zone | prázdné (nejdelší autoritativní zóna view, do které jméno patří), nebo zóna |
| TTL (s) | výchozí 60 (pokročilé) |
| Check the Grid Master's certificate | nechte zapnuté |
| CA of the Grid Master's certificate | CA z kroku 5 (PEM); prázdné, pokud jí systém už věří |

## Ověření

- V acme stiskněte u validace **Test**: přihlásí se a vypíše zóny daného view; žádný záznam nemění.
- V gridu po objednávce: **Data Management → DNS → Zones →** zóna → TXT záznamy `_acme-challenge` s komentářem `acme DNS-01` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401 Unauthorized` | Špatné heslo, nebo skupina nemá rozhraní **API**. |
| `403` / „permission denied“ při POST | Skupina má na zónu nebo její TXT záznamy jen čtení. |
| Selhání ověření certifikátu | Vložte vydávající CA do *CA of the Grid Master's certificate* - kontrolu **ne**vypínejte. |
| „no zone“ pro jméno | Zóna je v jiném DNS view nebo není autoritativní (forward/stub) - nastavte *DNS view*. |
| Záznam existuje, ale CA ho nevidí | Člen gridu obsluhující zónu nerestartoval DNS službu: zkontrolujte nastavení gridu pro restart služeb. |
| Chyba neznámé verze WAPI | Nastavte *WAPI version* podle toho, co grid hlásí. |
