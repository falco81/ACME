# Hetzner Cloud Load Balancer - nastavení pro acme

acme nahraje certifikát do projektu Hetzner Cloud (typ `uploaded`, pod jménem s datem, štítek `managed-by=acme`) přes Hetzner Cloud API (`https://api.hetzner.cloud/v1`) a pak ho dá na **HTTPS služby** zadaných load balancerů místo staršího certifikátu acme. Služba může mít více certifikátů (vybíraných podle SNI) - standardně se nahrazuje jen ten starší od acme a ostatní zůstávají. Starší certifikáty acme, které už žádný load balancer nepoužívá, se mažou.

## Co potřebujete

- Projekt Hetzner Cloud s aspoň jedním load balancerem, který má **HTTPS službu** (protokol `https`, TLS ukončené na load balanceru).
- **API token projektu s Read & Write** (tokeny patří k jednomu projektu).
- Přístup HTTPS z acme na `api.hetzner.cloud` port 443 (přímo nebo přes proxy acme).

## Nastavení Hetzner Cloud

1. V Hetzner Console otevřete projekt, pak **Security → API tokens → Generate API token**:
   - **Description**: `acme`
   - **Permissions**: **Read & Write** (nahrávání a mazání certifikátů a změny služeb potřebují zápis).
2. Token zkopírujte - zobrazí se jen jednou. **Kdo má tento token, může v projektu změnit cokoli**; pokud to jde, použijte projekt, ve kterém je jen to, co token potřebuje.
3. Ověřte, že každý load balancer má HTTPS službu (**Load Balancers → (LB) → Services**, protokol HTTPS, listen port např. 443). Při ručním vytváření musíte vybrat nějaký certifikát; acme ho při prvním běhu nahradí.

Totéž můžete ověřit pomocí CLI `hcloud`:

```sh
export HCLOUD_TOKEN=…
hcloud load-balancer list
hcloud load-balancer describe lb-www
hcloud certificate list
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| API token | token projektu (Read & Write) |
| Through the proxy (pokročilé) | zapnuto, když acme dosáhne na internet jen přes Nastavení → Proxy |
| Timeout (s) (pokročilé) | 30 stačí |
| Load balancers (nasazení) | jméno nebo ID každého load balanceru, jedno na řádek (ukáže je akce **List the load balancers**) |
| Listen ports (nasazení) | HTTPS služby podle listen portu, např. `443`, jeden na řádek; prázdné: všechny HTTPS služby |
| Replace every certificate of the service | vypnuto: nahradí se jen starší certifikát acme; zapnuto: služba bude mít jen tento certifikát |
| Previous versions to keep | kolik starších certifikátů acme zůstane před smazáním |
| Check what is served | `www.example.com:443` (směřující na load balancer), jeden na řádek |

## Ověření

- **Test** v acme se přihlásí a spočítá load balancery projektu.
- Akce **List the load balancers** ukáže každý load balancer, jeho HTTPS služby a jejich certifikáty, bez jakékoli změny.
- Po nasazení ukáže `hcloud load-balancer describe lb-www` na službě nový certifikát `acme-…`, a také:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 `unauthorized` | špatný token, nebo token jiného projektu |
| 403 `forbidden` | token je jen pro čtení - vytvořte token s Read & Write |
| `there is no load balancer "…" in this project` | ověřte jméno/ID akcí *List the load balancers*; projekt tokenu musí být projekt load balanceru |
| `the load balancer … has no HTTPS service` | přidejte HTTPS službu, nebo opravte *Listen ports* |
| `… has not finished in 120 s` / `… failed` | akce load balanceru je pomalá nebo odmítnutá; podívejte se do **Load Balancers → (LB) → Activity** v konzoli |
| `the older … stays: a load balancer still uses it` | používá ho ještě jiný load balancer/služba; uveďte i ten, nebo ho tam odeberte |
