# Azure Blob Storage (HTTP-01) - nastavení pro acme

acme prokazuje jména přes HTTP-01 tak, že soubor s tokenem `.well-known/acme-challenge/TOKEN` nahraje do kontejneru Azure Storage, který obsluhuje dané jméno - **statický web** (kontejner `$web`) nebo kontejner za Azure Front Door / CDN - a poté ho smaže. CA si pak stáhne `http://JMÉNO/.well-known/acme-challenge/TOKEN`. **Ne pro wildcardy** (ty potřebují DNS-01).

## Co potřebujete

- Účet úložiště, jehož kontejner blobů obsluhuje web daného jména (zapnutý statický web, nebo CDN / Front Door s originem v kontejneru).
- Jméno směřující (CNAME / A) na tento web nebo CDN a odpovídající do internetu na **portu 80**.
- Odchozí HTTPS z acme na `ACCOUNT.blob.core.windows.net` (port 443).

## Nastavení Azure Storage

1. Pro statický web: účet úložiště → **Data management → Static website → Enabled**; tím vznikne kontejner `$web`. Přidejte vlastní doménu (přes Front Door / CDN nebo *Networking → Custom domain* účtu úložiště).
2. Vytvořte přístupový údaj, menší oprávnění nejdřív:
   - **SAS token** (doporučeno): kontejner `$web` → **Shared access tokens** → oprávnění **Read, Write, Create, Delete**, datum vypršení (nezapomeňte obnovit), povolená IP = veřejná adresa acme, protokol jen HTTPS → **Generate SAS token and URL** → zkopírujte **token** (část za `?`). Funguje i SAS účtu: služba *Blob*, typ prostředku *Object*, stejná oprávnění.
   - Nebo **klíč účtu**: účet úložiště → **Security + networking → Access keys** → key1 nebo key2 (plný přístup k účtu - pokud možno se mu vyhněte).
3. Za Azure Front Door nebo CDN: zajistěte, aby `/.well-known/acme-challenge/*` procházelo přes **HTTP** (žádné nefunkční vynucené přesměrování na HTTPS a **žádné cachování** této cesty).
4. Je-li zapnutý firewall účtu úložiště (*Networking → Selected networks*), přidejte veřejnou adresu acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Storage account | Název účtu, např. `mysite` |
| Container | `$web` pro statický web, nebo název kontejneru |
| Signs in with | `a SAS token` nebo `the account key (Shared Key)` |
| SAS token | Token (část za `?`) |
| Account key | key1 nebo key2 (base64) |
| Folder in the container | Kde v kontejneru je kořen webu; prázdné = jeho kořen |
| Blob endpoint | (pokročilé) Prázdné = `https://ACCOUNT.blob.core.windows.net`; jiný cloud Azure: jeho vlastní |
| Check before the CA is asked | `http://NAME/` (výchozí), adresa níže, nebo bez kontroly |
| Address the folder is served at | (pokročilé) např. vlastní adresa statického webu `https://mysite.z6.web.core.windows.net/` |

## Kontrola

- **Test** v acme nahraje zkušební soubor, přečte ho zpět a smaže.
- Z libovolného stroje v internetu, během běhu (nebo se souborem, který tam vložíte):

  ```sh
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403 AuthorizationPermissionMismatch` | SAS nemá Write/Create/Delete, nebo vypršel. |
| `403 AuthorizationFailure` | Firewall úložiště blokuje adresu acme. |
| Zkušební soubor funguje, ale CA dostane 404 | Špatně nastavená *Folder in the container*, nebo jméno nevede na tento kontejner / CDN. |
| CA dostane starou odpověď | CDN cachuje `/.well-known/acme-challenge/*` - vyřaďte tuto cestu z cache. |
