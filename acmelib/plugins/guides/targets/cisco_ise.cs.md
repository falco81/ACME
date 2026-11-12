# Cisco ISE - nastavení pro acme

acme používá **OpenAPI ISE** (basic autentizace). Naimportuje mezilehlé certifikáty jako
**trusted certificates** (`/api/v1/certs/trusted-certificate/import`) a pak certifikát
jako **system certificate** jednoho uzlu pod přátelským jménem s datem
(`/api/v1/certs/system-certificate/import`) pro zadané role - Admin, EAP, RADIUS DTLS,
pxGrid, SAML, Portal, ISE messaging. Soukromý klíč putuje šifrovaný jednorázovým heslem.
Starší systémové certifikáty acme na uzlu nad počet *ponechat* smaže.

**Role Admin restartuje aplikační server daného uzlu (několik minut výpadku jeho webových
stránek a služeb).**

Pro ISE 3.1 a novější.

## Co potřebujete

- HTTPS (TCP 443) z acme na **každý uzel**, který certifikát dostane: import jde na uzel,
  kterému je požadavek poslán, proto **jeden cíl na uzel** a jeho *Address* je ten uzel.
- Administrátora s rolí **ERS Admin** (nebo Super Admin).
- **Nový soukromý klíč při každé obnově**: ISE neumí naimportovat dva certifikáty se
  stejným klíčem (nahradí ten stávající) - neobnovujte tento certifikát se starým klíčem.

## Nastavení Cisco ISE

1. Zapněte API: **Administration → System → Settings → API Settings → API Service
   Settings**: zapněte **Open API** (a ERS pro primární/sekundární uzly, jak je nabízeno).
   Uložte.
2. Vytvořte správce: **Administration → System → Admin Access → Administrators → Admin
   Users → Add**, např. `acme`, silné heslo, skupina správců **ERS Admin**.
3. Poznamenejte si hostname každého uzlu, jak ho ISE uvádí: **Administration → System →
   Deployment**.
4. Naplánujte role: EAP a RADIUS DTLS přejdou na nový certifikát; zahrnete-li `admin`,
   naplánujte nasazení do servisního okna.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address / HTTPS port | Adresa **tohoto uzlu**, např. `ise01.example.local` / `443` |
| User | Správce s ERS Admin (výchozí `acme`) |
| Password | Jeho heslo |
| Node hostname | Hostname uzlu, jak ho ISE uvádí, např. `ise01` |
| Check the device's certificate / CA certificate | CA jeho admin certifikátu, pokud není veřejná |
| Use it for (nasazení) | Jedna na řádek: `admin`, `eap`, `radius`, `pxgrid`, `saml`, `portal`, `ims` (výchozí `eap` a `portal`) |
| Portal group tag (nasazení, pokročilé) | Výchozí `Default Portal Certificate Group` |
| Import the intermediates as trusted (nasazení, pokročilé) | Zapnuto |
| Previous versions to keep (pokročilé) | Výchozí 1 |
| Check what is served | např. portál `guest.example.com:8443` |

## Ověření

- **Try**: `signed in to ...; node ise01 has N system certificates`.
- V ISE: **Administration → System → Certificates → System Certificates** ukazuje
  přátelské jméno `acme-...` a jeho role na uzlu.

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 | Chybný uživatel/heslo, nebo správce není v ERS Admin |
| 404 / API neodpovídá | Open API je vypnuté - zapněte ho v API Settings |
| Naimportováno na špatný uzel | *Address* musí být přímo ten uzel, *Node hostname* jeho jméno |
| Import odmítnut: stejný soukromý klíč | Obnovte s novým klíčem |
| Uzel několik minut nedostupný | Role Admin restartuje jeho služby - očekávané |
| Klienti EAP si stěžují | Klienti musí důvěřovat novému řetězci - ověřte důvěryhodné CA suplikantu |
