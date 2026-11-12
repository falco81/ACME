# cPanel - nastavení pro acme

acme prokazuje jména přes DNS-01 v DNS účtu cPanel: přes **UAPI** cPanelu (port 2083) přečte zónu (`DNS::parse_zone`), přidá záznam TXT `_acme-challenge.JMÉNO` pomocí `DNS::mass_edit_zone` (s aktuálním sériovým číslem SOA zóny) a při úklidu odebere jen řádky TXT s jeho hodnotou. Přihlašuje se jako uživatel cPanelu s **API tokenem**. Pro verze cPanel & WHM, které mají API tokeny a funkci UAPI `DNS::mass_edit_zone` (současná vydání).

## Co potřebujete

- Účet cPanel, jehož domény používají DNS serveru (zónu obsluhuje tento server cPanel/WHM nebo jeho DNS cluster).
- Jméno uživatele cPanelu a přístup do cPanelu pro vytvoření API tokenu.
- Odchozí HTTPS z acme na server cPanel na **port 2083** (nebo zadaný port).

## Nastavení cPanelu

1. Přihlaste se do cPanelu jako účet, kterému domény patří.
2. **Security → Manage API Tokens → Create**.
3. Pojmenujte ho např. `acme`, případně nastavte **datum vypršení** (nezapomeňte ho obnovit) a nechte ho **neomezený jen na čtení** - acme musí zónu upravovat. Zkopírujte token (zobrazí se jen jednou).
4. Pokud server používá cPHulk nebo firewall (CSF, Imunify360), který omezuje port 2083, povolte veřejnou adresu acme.
5. Poskytovatel hostingu musí účtu povolit úpravy zóny DNS (funkce *Zone Editor* zapnutá v balíčku účtu).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| cPanel address | Server, jak na něj účet přistupuje: `cpanel.example.com`, `host:port` nebo `https://…`; bez portu 2083 |
| User name | Jméno účtu cPanel |
| API token | Token |
| Zone | Načtěte seznam a vyberte, nebo napište; prázdné = nejdelší z domén účtu, ve které jméno leží (jinak podle SOA) |
| TTL (s) | (pokročilé) Výchozí `300` |
| Check the server's certificate | (pokročilé) nechte zapnuté; vypněte jen má-li server certifikát podepsaný sám sebou |

## Kontrola

- **Test** v acme se přihlásí a vypíše domény - nebo při vyplněné *Zone* zónu přečte a uvede její sériové číslo a záznamy TXT. Nic nemění.
- Pomocí curl:

  ```sh
  curl -s -H "Authorization: cpanel alice:$TOKEN" \
    'https://cpanel.example.com:2083/execute/DomainInfo/list_domains'
  ```

- V cPanelu: **Domains → Zone Editor → Manage** ukazuje během běhu záznam TXT `_acme-challenge`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` / `Access denied` | Špatný uživatel nebo token, nebo token vypršel. |
| Spojení odmítnuto / vypršel čas | Port 2083 blokuje firewall serveru, nebo hosting používá jinou adresu - zeptejte se poskytovatele. |
| Chyba TLS | Certifikát serveru neodpovídá použitému jménu - použijte jméno z certifikátu, nebo vypněte *Check the server's certificate*. |
| Zónu nelze přečíst | Účet nesmí upravovat DNS (Zone Editor vypnutý), nebo je doména subdoménou uvnitř zóny nadřazené domény - vyberte nadřazenou zónu. |
| Změny opakovaně odmítnuty | Zónu současně upravuje někdo jiný (sériové číslo se posouvá); zkuste znovu. |
