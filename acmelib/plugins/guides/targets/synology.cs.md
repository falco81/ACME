# Synology DSM - nastavení pro acme

acme se přihlásí k webovému API DSM (`SYNO.API.Auth`, relace `Certificate`) a naimportuje
certifikát, klíč a mezilehlé certifikáty přes `SYNO.Core.Certificate` `import`. Pokaždé
**nahradí certifikát se stejným popisem**, takže služby, kterým jste ho přiřadili (DSM,
Synology Drive, WebDAV, reverzní proxy...), ho dál používají. Umí ho nastavit jako výchozí;
certifikát, který už výchozí je, výchozím zůstane.

Pro DSM 6.2 a DSM 7.x. Volání pro přihlášení Synology dokumentuje; volání pro certifikáty
jsou neoficiální (jak je používá acme.sh) a na současném DSM fungují.

## Co potřebujete

- Síťový přístup z acme na DSM přes HTTPS: **TCP 5001** (nebo váš port HTTPS DSM).
- Uživatele DSM ve skupině **administrators** **bez dvoufázového ověření** (acme ho
  nepodporuje).

## Nastavení DSM

1. Vytvořte samostatného uživatele: **Control Panel → User & Group → User → Create**, např.
   `acme`, se silným heslem.
2. Přidejte ho do skupiny **administrators** (DSM dovolí import certifikátu jen správcům).
   Ve stejném průvodci mu můžete zakázat přístup ke sdíleným složkám a aplikacím, které
   nepotřebuje.
3. Ověřte, že pro něj **není** vynucené dvoufázové ověření (**Control Panel → Security →
   Account → 2-Factor Authentication**: nevynucovat pro tohoto uživatele / skupinu).
4. Používáte-li **Control Panel → Security → Firewall** nebo *Auto Block*, povolte / dejte
   na seznam povolených IP adresu serveru acme pro port HTTPS DSM.
5. Volitelně při prvním běhu: nechte *Make it the default certificate* vypnuté, jednou
   nasaďte a pak v **Control Panel → Security → Certificate → Settings** přiřaďte nový
   certifikát (`acme <jméno>`) požadovaným službám. Další obnovení ho nahradí na místě.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP NAS, např. `nas.example.local` |
| HTTPS port | `5001` |
| User / Password | Uživatel `acme` |
| Check the device's certificate | Zapnuto; vypnout jen dokud má DSM self-signed certifikát |
| CA certificate (pokročilé) | CA současného certifikátu DSM, pokud není veřejná |
| Description on the NAS (nasazení) | Popis certifikátu, který acme pokaždé nahradí; prázdné: `acme <jméno>` |
| Make it the default certificate (nasazení) | Zapnout, má-li být výchozím v DSM |
| Check what is served | např. `nas.example.local:5001` |

**Po prvním nasazení popis neměňte**, jinak acme naimportuje nový certifikát místo
nahrazení toho přiřazeného.

## Ověření

- Na cíli stiskněte **Try**: acme se přihlásí, vypíše certifikáty a odpoví
  `signed in to ..., N certificates`.
- V DSM: **Control Panel → Security → Certificate** ukazuje `acme <jméno>` s novým datem
  platnosti.

## Časté problémy

| Problém | Řešení |
|---|---|
| `DSM said error 400` při přihlášení | Špatný uživatel nebo heslo. |
| `DSM said error 403` / `406` | Uživatel má dvoufázové ověření - pro `acme` ho vypněte. |
| `DSM said error 402` / chyba oprávnění | Uživatel není ve skupině *administrators*. |
| Přihlášení po chybách zablokováno | *Auto Block* zablokoval IP acme - odblokujte ji a povolte. |
| Služby mají starý certifikát | Jsou přiřazené k jinému certifikátu - jednou přiřaďte `acme <jméno>` v *Settings*. |
