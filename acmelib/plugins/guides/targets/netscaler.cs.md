# NetScaler / Citrix ADC - nastavení pro acme

acme nasazuje certifikáty na NetScaler (Citrix ADC) přes **NITRO REST API**:

1. přihlásí se (`login`, session cookie `NITRO_AUTH_TOKEN`);
2. nahraje `acme-<jméno>-<datum>-<sériové číslo>.crt` a `.key` do `/nsconfig/ssl` (`systemfile`);
3. **aktualizuje certkey na místě** (výchozí jméno `acme-<jméno certifikátu>`, zachovává se mezi obnoveními, `update … -noDomainCheck`), takže jeho vazby zůstanou - nebo ho poprvé přidá;
4. přidá každý mezilehlý certifikát jako certkey `acme-ca-<id>` a propojí certifikát nahoru po řetězci (link);
5. naváže certkey na zadané SSL virtuální servery (volitelně jako SNI certifikát);
6. uloží konfiguraci (`save ns config`), smaže starší soubory acme nad rámec *keep* a odhlásí se.

HA pár si soubory i konfiguraci synchronizuje sám.

## Co potřebujete

- NetScaler / Citrix ADC 12.1 nebo novější (EC klíče potřebují 12.1+; RSA funguje na všech verzích).
- Přístup HTTPS z acme na NSIP (nebo SNIP se správcovským přístupem), port 443.
- Systémového uživatele s command policy, která povoluje výše uvedené příkazy - nebo vestavěnou policy `superuser`.

## Nastavení NetScaleru

V CLI NetScaleru (SSH na NSIP jako `nsroot`):

```text
add system cmdPolicy acme_certs ALLOW "(^show\s+ns\s+version)|(^(show|add|rm)\s+system\s+file)|(^(show|add|update|link|unlink)\s+ssl\s+certKey)|(^(show|bind)\s+ssl\s+vserver)|(^save\s+ns\s+config)"
add system user acme -timeout 900
bind system user acme acme_certs 100
save ns config
```

`add system user acme` se zeptá na heslo. Policy ověřte prvním nasazením - když je některý krok odmítnut, úloha uvede volání NITRO; rozšiřte regulární výraz jen pro ten příkaz. **Pro acme nepoužívejte `nsroot`.**

V GUI je totéž v **System → User Administration → Command Policies** (přidat `acme_certs`) a **System → User Administration → Users** (přidat `acme`, navázat policy).

Volitelně omezte správcovský přístup na server acme (např. ACL na NSIP nebo `set ns ip <NSIP> -mgmtAccess ENABLED -restrictAccess ENABLED`, podle vašeho nastavení).

Poznamenejte si jména SSL virtuálních serverů (**Traffic Management → Load Balancing / Content Switching → Virtual Servers**, protokol SSL).

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | NSIP (nebo správcovský SNIP) |
| HTTPS port | 443 |
| User / Password | `acme` a jeho heslo |
| Check the device's certificate | zapnuto; vypnout jen dokud má správcovské rozhraní výchozí self-signed certifikát |
| CA certificate (pokročilé) | CA správcovského certifikátu NetScaleru, když není veřejná |
| Certkey name (nasazení) | certkey zachovávaný mezi obnoveními, např. `www`; prázdné: `acme-<jméno certifikátu>` |
| SSL virtual servers (nasazení) | jeden na řádek, např. `vs_www_ssl`; `vs_portal sni` ho naváže jako SNI certifikát |
| Key as (pokročilé) | tradiční RSA (výchozí, funguje všude; EC klíče jdou jako PKCS#8), nebo PKCS#8 |
| Previous versions to keep | kolik starších souborů acme zůstane v `/nsconfig/ssl` |
| Check what is served | `vip.example.com:443`, jeden na řádek |

Chcete-li převzít existující certkey (se všemi jeho vazbami), zadejte jeho jméno do *Certkey name* - acme ho aktualizuje na místě.

## Ověření

- **Test** v acme se přihlásí a přečte `nsversion`.
- Na NetScaleru:

```text
show ssl certKey www
show ssl vserver vs_www_ssl
shell ls -l /nsconfig/ssl | grep acme-
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the NetScaler gave no session on signing in` / 401 | špatný uživatel/heslo, nebo uživatel má jen externí autentizaci |
| `…: Not authorized to execute this command` | command policy tento příkaz nepovoluje; rozšiřte ji o něj |
| `there is no SSL virtual server …` | jméno se musí přesně shodovat (i velikost písmen) |
| Update odmítnut kvůli klíči | zkuste *Key as* PKCS#8 (nebo na starých verzích tradiční RSA) |
| Klientům chybí mezilehlý certifikát | link selhal - zkontrolujte *Linked to* v `show ssl certKey <jméno>` |
| Po restartu se konfigurace ztratí | `save ns config` byl odmítnut - povolte ho v policy |
