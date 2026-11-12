# AVM FRITZ!Box - nastavení pro acme

acme nahrává certifikát vlastních webových stránek FRITZ!Boxu - který box používá také pro MyFRITZ!/vzdálený přístup a VPN - stejně, jako to dělá stránka boxu: přihlásí se přes `login_sid.lua` (PBKDF2 challenge FRITZ!OS 7.24 a novějšího, nebo starou MD5), pošle klíč a celý řetězec na `/cgi-bin/firmwarecfg` a odhlásí se. Když box certifikát už podává, nic se nenahrává.

## Co potřebujete

- FRITZ!Box s FRITZ!OS 7.x (doporučeno 7.24 a novější; starší FRITZ!OS bere **jen RSA klíče** - tam vystavte certifikát s RSA klíčem).
- Přístup HTTPS z acme na box: obvykle z domácí sítě na `fritz.box` (nebo jeho LAN IP) port 443. Z internetu jen když je zapnutý vzdálený přístup přes HTTPS (pak jeho port, např. port MyFRITZ!).
- Uživatele FRITZ!Boxu pro acme.

## Nastavení FRITZ!Boxu

1. Přihlaste se do uživatelského rozhraní FRITZ!Boxu (`https://fritz.box`) jako administrátor.
2. Jděte do **System → FRITZ!Box Users → Add User**:
   - **User name**: `acme`, silné **heslo**;
   - práva: zaškrtněte jen **FRITZ!Box settings** (práva NAS, Smart Home, VPN ani jiná nejsou potřeba);
   - přístup z internetu není potřeba, když je acme v domácí síti.
3. Vypněte dodatečné potvrzování změn nastavení pro tohoto uživatele: v **System → FRITZ!Box Users → Login to the Home Network** musí být volba dodatečně potvrzovat provedení určitých nastavení a funkcí (stiskem tlačítka nebo kódem z telefonu) **vypnutá** - acme nemůže na boxu stisknout tlačítko. **Tím se snižuje ochrana změn nastavení; heslo uživatele `acme` mějte silné.** (Přesné znění se mezi verzemi FRITZ!OS liší.)
4. Uložte nastavení (box může chtít tuto změnu jednou potvrdit stiskem tlačítka).

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | `fritz.box` nebo LAN IP boxu |
| HTTPS port | 443 (nebo HTTPS port vzdáleného přístupu, když acme na box jde z internetu) |
| User | `acme` |
| Password | jeho heslo |
| Check the device's certificate | při prvním běhu vypnuto, dokud má box self-signed certifikát (nebo zadejte jeho CA); potom zapnuto |
| CA certificate (pokročilé) | CA současného certifikátu boxu, když není veřejná |
| Check what is served | `fritz.box:443` (nebo vaše jméno MyFRITZ! a port), jeden na řádek |

## Ověření

- **Test** v acme se přihlásí do boxu (špatné heslo ohlásí, i s dobou blokování, když box přihlášení blokuje).
- Po nasazení otevřete `https://fritz.box` v prohlížeči a podívejte se na certifikát, nebo:

```sh
openssl s_client -connect fritz.box:443 -servername fritz.box </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -enddate
```

- Na boxu ukazuje **Internet → Permit Access → FRITZ!Box Services** certifikát používaný pro vzdálený přístup (v novějších FRITZ!OS).

## Časté problémy

| Problém | Řešení |
|---|---|
| `the FRITZ!Box gave no challenge` | adresa není FRITZ!Box, nebo je v cestě proxy |
| `does not let acme in: wrong user or password (it blocks sign-ins for N s)` | opravte uživatele/heslo; počkejte na konec blokování - každý neúspěšný pokus ho prodlužuje |
| `the FRITZ!Box did not take the certificate` | starší FRITZ!OS potřebuje RSA klíč; nebo je dodatečné potvrzování změn nastavení stále zapnuté |
| Nahrání zdánlivě projde, zůstává starý certifikát | je zapnuté potvrzování tlačítkem - vypněte ho pro uživatele (krok 3) |
| Chyba TLS při dalším běhu | *Check the device's certificate* zapněte zpět až ve chvíli, kdy box podává nový certifikát, jehož jméno odpovídá *Address* |
