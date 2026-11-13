# Fujitsu PRIMEQUEST 3000 MMB - bez automatického nasazení

**Management Board (MMB) serverů PRIMEQUEST 3000** přijme HTTPS certifikát (Web-UI, výchozí port
432) **jen přes své Web-UI** a jen k CSR, kterou vytvořilo samo:
**[Network Configuration] → [SSL] → [Create CSR] → [Export Key/CSR] → [Import Certificate]**.
Nemá REST/Redfish API pro certifikáty, jeho CLI jen zapíná HTTPS (`set https`, `set
https_port`) a klíč vytvořený jinde naimportovat neumí - proto pro něj acme **nemá cíl**.
(Tool Reference (MMB) CA92344-1657-22, 02/2026.)

**PRIMEQUEST 4000 MMB nemá**: jeho správa je iRMC S6 - použijte cíl **Fujitsu iRMC (PRIMERGY,
PRIMEQUEST 4000)**. Stejný cíl zvládne i iRMC S5 jednotlivých partition PRIMEQUEST 3000.

## Co bylo ověřeno (2026-11)

acme vytvoří cíl pro zařízení, které si klíč dělá samo, kdykoli *některé* jeho rozhraní umí
vytvořit CSR a převzít podepsaný certifikát (viz cíle s „klíč vytváří zařízení“). MMB žádné
takové nemá: Tool Reference neuvádí v CLI žádný příkaz pro certifikáty (kapitola 3: jen
`set https`, `set https_port`, `show https`, `show https_port`), MMB nemá REST ani Redfish
(RESTful API iRMC S5, CA92344-1673, patří partitionům, ne MMB), nemá objekt SNMP pro
certifikáty a nepodporuje Ansible, PowerShell, ACME ani SCEP. Menu [SSL] je jen pro
*Administrator* a jen ve Web-UI.

## Ruční postup (jen Administrator)

1. Web-UI MMB jako *Administrator*: **[Network Configuration] → [SSL] → [Create CSR]** - délka
   klíče 2048, Common Name = FQDN MMB (žádná IP, žádný wildcard; nejvýše 56 znaků). Vytvořením CSR
   přestane platit dosavadní klíč: HTTPS certifikát nefunguje až do importu - udělejte to v jednom
   okně, mezitím používejte HTTP (8081).
2. **[Export Key/CSR] → [Export CSR]** (a **[Export Key]** - bezpečně uložte).
3. Nechte CSR podepsat; CSR z MMB **nemá SAN** - vaše CA musí doplnit `DNS:<FQDN>`. V acme ji
   můžete podepsat vlastní autoritou: *Certifikáty → Nový* s vloženou CSR.
4. **[Import Certificate]**, potom **[Network Protocols]**: HTTPS *Enable*, port 432 nebo 443,
   HTTP *Disable*.

## Obnova s pomocí acme

Certifikát vytvořený v acme z vložené CSR si tu CSR pamatuje a **při každé obnově se vydá
znovu pro ni** (stejný klíč). MMB si klíč drží až do dalšího *Create CSR* - proto:

- K obnově na MMB **nevytvářejte** novou CSR: acme certifikát obnoví samo (vlastní autoritou
  nebo jiným zdrojem, který podepisuje CSR) a vy ho jen stáhnete z certifikátu (*Stáhnout →
  certifikát, PEM*) a naimportujete přes **[Import Certificate]**.
- Nový klíč dělejte, jen když ho chcete: **[Create CSR]** na MMB, potom *Poslat nový CSR*
  u certifikátu v acme - vydá se hned znovu - a ihned ho naimportujte (HTTPS nefunguje od
  nové CSR do importu).
- Dejte certifikátu **upozornění** před vypršením (Nastavení → Upozornění a reporty) a test TLS na MMB,
  ať se ruční import nezapomene: test ukáže, že MMB po obnově servíruje ještě starý
  certifikát.

```text
# set https_port 443
# set https enable
# show https
```

## Ověření

```sh
openssl s_client -connect mmb.example.local:432 -servername mmb.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Hlídat vypršení acme přesto umí: přidejte k certifikátu test TLS na `mmb.example.local:432`.
