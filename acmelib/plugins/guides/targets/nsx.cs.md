# VMware NSX load balancer - nastavení pro acme

acme nasazuje certifikáty na load balancer NSX (NSX-T Data Center / VMware NSX) přes **NSX Policy API** (`https://<nsx-manager>/policy/api/v1`, HTTP basic autentizace). Certifikát v NSX nelze přepsat, takže každé obnovení **importuje nový certifikát** pod id s datem (`PUT /infra/certificates/<id>`: certifikát + řetězec, soukromý klíč, štítky). Pak se každý zadaný virtuální server přečte celý a zapíše zpět s **client SSL bindingem** ukazujícím na nový certifikát - jako výchozí certifikát, jako SNI certifikát (starší certifikát acme se nahradí, ostatní zůstanou), nebo obojí. Starší certifikáty acme, na které žádný virtuální server neodkazuje, se mažou. Policy API nepotřebuje zvláštní krok publikování.

## Co potřebujete

- NSX-T 3.x nebo VMware NSX 4.x (psáno podle specifikace Policy API 9.1), s load balancerem konfigurovaným přes Policy API / Policy UI (ne staré Manager API).
- Přístup HTTPS z acme na NSX Manager (nebo VIP clusteru), port 443.
- Uživatele NSX, který smí importovat/mazat certifikáty a měnit virtuální servery load balanceru.
- Virtuální servery, které už mají **client SSL profile binding** (podávají HTTPS).

## Nastavení NSX

1. Vytvořte uživatele pro acme:
   - lokální uživatel: **System → User Management → Local Users** (NSX 3.1+ / 4.x) - přidejte `acme` se silným heslem; nebo
   - uživatel z LDAP / adresáře, kterého přidáte v **System → User Management → User Role Assignment**.
2. Přidělte mu roli: **System → User Management → User Role Assignment → Add → Role Assignment for …**. Použijte nejužší roli, která umí spravovat **load balancing** a **certifikáty** - např. **LB Admin**, pokud ve vaší verzi smí importovat certifikáty; jinak vlastní roli (NSX 3.2+: **Roles → Add Role**) s plným přístupem k *Networking → Load Balancing* a *System → Certificates*. Ověřte to tlačítkem **Test** v acme, akcí **List the virtual servers** a prvním nasazením. *Enterprise Admin* pro acme nepoužívejte.
3. Ověřte, že je pro tohoto uživatele povolena HTTP basic autentizace přes API (u lokálních a LDAP uživatelů standardně je).
4. Poznamenejte si **id** virtuálních serverů (**Networking → Load Balancing → Virtual Servers**; id je v detailu objektu, nebo použijte akci v acme).

Ověření ze serveru acme:

```sh
curl -s -u acme:'…' https://nsx-manager.example.local/policy/api/v1/infra/lb-virtual-servers | head -40
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | NSX Manager nebo VIP jeho clusteru |
| HTTPS port | 443 |
| User / Password | uživatel z kroku 1 (výchozí `admin` - lépe vyhrazený) |
| Check the device's certificate | zapnuto; vypnout jen dokud má Manager self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu NSX Manageru, když není veřejná |
| Virtual server (nasazení) | id virtuálního serveru LB (vyberte ze seznamu nebo napište) |
| More virtual servers | další id, jedno na řádek |
| As | výchozí certifikát virtuálního serveru / SNI certifikát / obojí |
| Previous versions to keep | kolik starších certifikátů acme zůstane v NSX |
| Check what is served | `vip.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí; akce **List the virtual servers** ukáže každý virtuální server a certifikáty jeho client SSL bindingu, bez jakékoli změny.
- V NSX: **System → Certificates** ukazuje nový certifikát `acme-…`; **SSL Configuration → Client SSL** virtuálního serveru ho uvádí.

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 / 403 | špatný uživatel/heslo, nebo role nesmí importovat certifikáty či měnit virtuální servery |
| `NSX has no virtual server "…"` | použijte **id** virtuálního serveru, ne jen jeho zobrazované jméno (viz akci se seznamem) |
| `the virtual server … has no client SSL binding` | nejdřív na virtuálním serveru zapněte Client SSL |
| 412 / chyba revize u virtuálního serveru | současně ho změnil někdo jiný; nasaďte znovu |
| Import odmítnut | klíč nesedí, nebo je řetězec neúplný - viz zprávu |
| `the older … stays: a virtual server still uses it` | používá ho ještě jiný virtuální server; uveďte i ten |
