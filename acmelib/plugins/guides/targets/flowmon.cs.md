# Flowmon - nastavení pro acme

acme vkládá certifikát a jeho klíč do Progress Flowmon přes Flowmon REST API (psáno podle Flowmon OS 13.1). Může ho dát na jedno nebo obě ze dvou míst:

- **pár certifikátů** (certificate pair) v **opakovaně použitelném TLS nastavení** (Configuration center → Reusable settings → TLS: čím sondy dešifrují TLS sledovaných serverů) - pár se nahradí, když existuje, jinak se přidá; samotné nastavení se vytvoří (s vydávající CA jako jeho CA souborem), když žádné takového jména není;
- **naslouchající porty kolektoru přes TLS** (porty, které přijímají toky přes TLS) - každý dostane certifikát, jeho klíč a vydávající CA.

**Poznámka:** API nemá volání pro certifikát vlastního webového rozhraní Flowmonu - ten se nastavuje ručně v Configuration center (nebo přes SSH cílem `ssh` v acme).

## Co potřebujete

- Flowmon OS 13.1 nebo novější verzi se stejným REST API.
- Přístup HTTPS z acme na správcové rozhraní zařízení Flowmon, port 443.
- Uživatele Flowmonu, který se smí přihlásit do REST API a měnit Configuration center (opakovaně použitelná nastavení a naslouchající porty).
- Pro nové TLS nastavení: certifikát musí přijít i s řetězcem (acme použije vydávající CA jako CA soubor nastavení).

## Nastavení Flowmonu

1. Přihlaste se do webového rozhraní Flowmonu jako administrátor.
2. Vytvořte pro acme vyhrazeného uživatele (např. `acme`) ve správě uživatelů v Configuration center, s rolí, která smí měnit nastavení Configuration center (reusable settings, naslouchající porty kolektoru). Ve své verzi ověřte, která role to dává - acme nic jiného nedělá, ale API potřebuje k těmto objektům zápis.
3. Chcete-li certifikát v opakovaně použitelném TLS nastavení, rozhodněte jeho jméno (**Configuration center → Reusable settings → TLS**). Existující nastavení se použije, jak je; chybějící vytvoří acme.
4. Chcete-li naslouchající porty přes TLS, poznamenejte si přesná **jména** naslouchajících portů kolektoru (např. `IPFIX-TLS`) - acme je hledá podle jména a nevytváří je.
5. Ověřte z acme serveru, že přihlášení do API funguje:

```sh
curl -s -X POST https://flowmon.example.local/resources/oauth/token \
     -d grant_type=password -d client_id=invea-tech \
     --data-urlencode username=acme --data-urlencode password='…'
```

Odpověď musí obsahovat `access_token`.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | jméno nebo IP adresa zařízení Flowmon |
| HTTPS port | 443 |
| User | uživatel Flowmonu (výchozí `admin`; lépe vyhrazený) |
| Password | jeho heslo |
| OAuth client (pokročilé) | `invea-tech`, pokud Flowmon neuvádí jiný `client_id` |
| Form of the uploads (pokročilé) | ponechte `entity[name], entity[tlsCaFile]`; měňte jen když Flowmon odmítne nahrání |
| Check the device's certificate | zapnuto; vypnout jen dokud má Flowmon svůj self-signed certifikát |
| CA certificate (pokročilé) | CA vlastního certifikátu Flowmonu, když není veřejná |
| Reusable TLS setting (nasazení) | jeho jméno, např. `Web servers`; prázdné: žádné |
| Certificate pair (nasazení) | jméno páru v tom nastavení; prázdné: jméno certifikátu |
| Listening ports over TLS (nasazení) | jména naslouchajících portů kolektoru, jedno na řádek; prázdné: žádné |
| Check what is served | `host:port` k ověření TLS handshakem po nasazení, jeden na řádek |

Vyplněno musí být aspoň jedno z *Reusable TLS setting* a *Listening ports over TLS*.

## Ověření

- V acme stiskněte **Test**: přihlásí se, přečte verzi a spočítá TLS nastavení a naslouchající porty přes TLS (`signed in to Flowmon 13.x at …`).
- Po nasazení otevřete ve Flowmonu **Configuration center → Reusable settings → TLS → <nastavení>** a zkontrolujte platnost páru, a naslouchající porty v nastavení kolektoru.
- Z příkazové řádky, s tokenem z přihlášení výše:

```sh
curl -s -H "Authorization: bearer $TOKEN" https://flowmon.example.local/rest/fcc/reusable-settings-tls
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `Flowmon did not sign in …` | špatný uživatel nebo heslo, uživatel nesmí používat API, nebo je potřeba jiný *OAuth client* |
| `say where the certificate goes …` | v nasazení vyplňte TLS nastavení nebo naslouchající porty |
| `the TLS setting … is not there … no chain` | nastavení se vytváří s CA z řetězce; vytvořte ho ručně nebo zajistěte, že certifikát má řetězec |
| `there is no listening port …` | jména portů se musí přesně shodovat se jmény v nastavení kolektoru |
| Nahrání odmítnuto (400/403) | 403 může znamenat neplatný certifikát nebo klíč; jinak zkuste jiné *Form of the uploads* |
| Chyba TLS při spojení se zařízením | Flowmon má ještě self-signed certifikát: zadejte jeho CA do *CA certificate*, nebo dočasně vypněte *Check the device's certificate* |
