# Fastly - nastavení pro acme

acme dává vlastní certifikát (certifikát dodaný zákazníkem, ne vydaný Fastly) do Fastly TLS přes Fastly API (`https://api.fastly.com`). Při každém nasazení nahraje nový soukromý klíč pod jménem s datem a pak **na místě nahradí** certifikát, který tam dal minule, takže jeho aktivace (které domény obsluhuje a na které TLS konfiguraci) zůstanou. Úplně poprvé není co nahradit: acme přidá nový certifikát a **vy ho jednou aktivujete** ve Fastly. Starší klíče acme, které už žádný certifikát nepoužívá, se mažou.

## Co potřebujete

- Účet Fastly se správou TLS pro vlastní certifikáty (Fastly TLS s certifikáty dodanými zákazníkem).
- Uživatele Fastly, který smí spravovat TLS (role, která může spravovat TLS účtu, např. superuser nebo engineer - ověřte role ve svém účtu).
- Přístup HTTPS z acme na `api.fastly.com` port 443 (přímo nebo přes proxy z Nastavení → Proxy v acme).

## Nastavení Fastly

1. Přihlaste se do ovládacího panelu Fastly jako uživatel, za kterého bude acme jednat (nejlépe vyhrazený uživatel).
2. Otevřete **Account → API tokens** (Personal API tokens) a vytvořte nový token:
   - **Name**: např. `acme`
   - **Scope**: `global` - správa TLS ho potřebuje (rozsahy pouze pro čtení a purge nestačí).
   - **Service access**: všechny služby (TLS certifikáty jsou objekty celého účtu).
   - Platnost: podle vaší politiky; nezapomeňte token obnovit, než vyprší.
3. Token zkopírujte - zobrazí se jen jednou.
4. Poprvé: spusťte v acme nasazení (viz níže), pak ve Fastly jděte do **Secure → TLS management**, najděte certifikát přidaný acme (jméno `acme-…`) a **aktivujte** ho pro jeho domény na požadované TLS konfiguraci. Každé další obnovení nahradí tentýž certifikát a aktivace zachová.

Token můžete ověřit z příkazové řádky:

```sh
curl -s -H "Fastly-Key: $FASTLY_TOKEN" \
     -H "Accept: application/vnd.api+json" \
     "https://api.fastly.com/tls/certificates?page%5Bsize%5D=100"
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| API token | token z kroku 2 |
| Through the proxy | zapnuto, když acme dosáhne na internet jen přes proxy z Nastavení → Proxy (výchozí zapnuto) |
| Timeout (s) | časový limit API, 30 stačí |
| Fastly certificate ID (nasazení, pokročilé) | prázdné: acme najde svůj certifikát podle jména, nebo přidá nový; nebo ID existujícího TLS certifikátu ve Fastly, který se má nahradit (např. dříve nahraný ručně) |
| Previous versions to keep | kolik starších klíčů acme zůstane ve Fastly, než se smažou |
| Check what is served | `host:443` domény na Fastly, jeden na řádek - acme ověří, že se podává nový certifikát |
| SNI name for the check | prázdné: první jméno certifikátu |

## Ověření

- V acme stiskněte u cíle **Test**: přihlásí se a vypíše TLS certifikáty (`signed in to Fastly; N TLS certificates`).
- Po nasazení ukazuje certifikát ve Fastly v **Secure → TLS management** nové datum platnosti, a také:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 / 403 při přihlášení | token je špatný, vypršel nebo nemá rozsah `global`; nebo uživatel nesmí spravovat TLS |
| `added the certificate … - activate it once` | při prvním běhu očekávané: aktivujte ho v Secure → TLS management |
| `there is no TLS certificate <id> at Fastly` | *Fastly certificate ID* je špatně; nechte ho prázdné nebo zkopírujte ID ze stránky TLS management |
| Nahrání klíče je odmítnuto | Fastly odmítá nepodporované typy klíčů; ověřte typ klíče certifikátu v acme |
| Stále se podává starý certifikát | nový certifikát byl přidán, ale nikdy aktivován, nebo je doména aktivována na jiném certifikátu |
| `the older key … stays` | klíč ještě používá nějaký certifikát; smaže se při některém dalším běhu |
