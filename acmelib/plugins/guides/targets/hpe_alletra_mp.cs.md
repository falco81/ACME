# HPE Alletra 9000 / Alletra Storage MP B10000 - klíč vytváří pole - nastavení pro acme

CLI pole si samo vytváří klíč a CSR svého certifikátu **unified-server** (jediný certifikát
pro WSAPI, připojení UI / SSMC a CIM) a importuje certifikát podepsaný k němu - klíč
vytvořený jinde naimportovat nejde. Proto **klíč vytváří pole**: při každém vydání a obnově se
acme přihlásí přes SSH, spustí `createcert unified-server -csr ...` přesně pro jména
certifikátu, nechá CSR podepsat zdrojem certifikátu a hned certifikát naimportuje
(`importcert unified-server`), mezilehlé certifikáty napřed. Samotný CSR na poli nic nemění;
import na chvíli restartuje služby správy (WSAPI, UI) - I/O hostitelů se nedotkne.

Verze: HPE Alletra 9000 (OS 9.x) a Alletra Storage MP B10000 (OS 10.x) - CLI převzaté
z Primera a 3PAR. Klíče: RSA 2048, 3072 nebo 4096.

**acme to na poli nezkoušelo** - CLI reference HPE nebyla při přípravě čitelná. Na svém poli
před první obnovou ověřte, že `help createcert` uvádí `-csr -keysize -C -ST -L -O -OU -CN
-SAN` a `help importcert` bere jako soubor `stdin`; jiná odpověď zastaví úlohu slovy CLI
a nic se nezmění.

## Co je potřeba

- Z acme na management adresu pole: **TCP 22** (SSH).
- Uživatel CLI s rolí **super** v doméně **all** (certifikáty jsou pro celý systém).
- Zdroj, který podepisuje CSR vytvořený jinde - ACME CA (validace DNS-01), vlastní autorita
  acme, komerční CA. Ne *Self-signed*, CMP ani SCEP.

## Nastavení pole

1. Uživatel pro acme (jako administrátor, v CLI):

   ```text
   cli% createuser -c '<heslo>' svc-cert all super
   cli% setsshkey -user svc-cert
   ```

   `setsshkey` se zeptá na veřejný klíč (vložte ten, který acme ukáže u *SSH klíč*); nebo se
   přihlašujte heslem.
2. Prohlédněte si současný certifikát a nápovědu CLI:

   ```text
   cli% showcert -service unified-server
   cli% help createcert
   cli% help importcert
   ```

3. Jména: management FQDN pole a jeho management IP - všechna jdou do CSR
   (`-SAN DNS:...,IP:...`).

## Vyplnění v acme

Cíl (**Cíle → Přidat → HPE Alletra 9000 / Alletra Storage MP B10000 - klíč vytváří pole**):

| Pole v acme | Co vyplnit |
|---|---|
| Adresa | Management FQDN nebo IP pole, např. `alletra01.example.local` |
| SSH port | `22` |
| Uživatel | `svc-cert` |
| Přihlásit se přes / SSH klíč / Heslo | Klíč nastavený přes `setsshkey`, nebo heslo |
| Země (C), Kraj (ST), Město (L), Organizace (O), Útvar (OU) | Subjekt CSR; přednost má vlastní subjekt certifikátu (jeho profil) |
| Port HTTPS pro WSAPI / UI | `443` - kam se dívá test acme |

Potom certifikát: **Přidat certifikát → Klíč → Klíč vytváří zařízení → vyberte tento cíl**.
Jeho jména: FQDN a management IP pole. Typ klíče: `rsa-2048`, `rsa-3072` nebo `rsa-4096`.
acme samo vytvoří nasazení na pole (volba *Nejdřív naimportovat mezilehlé certifikáty*,
ve výchozím stavu zapnutá); spustí se hned po každém vydání.

```sh
acme --cert-add alletra01 --names alletra01.example.local,10.0.0.60 --key-type rsa-2048 --issuer "Own CA" --csr-from alletra01
acme --renew alletra01
```

## Ověření

- **Test** u cíle se přihlásí a spustí `showversion` a `showcert -service unified-server` -
  nic nemění.
- **Obnovit teď** u certifikátu: úloha ukáže příkaz `createcert`, vydání a potom oba příkazy
  `importcert`.

  ```sh
  openssl s_client -connect alletra01.example.local:443 -servername alletra01.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
  ```

  Po změně ověřte v DSCC (a ve VASA provideru vCenteru, je-li registrovaný), že je pole stále
  připojené - klient, který si pamatuje starý certifikát, musí přijmout nový.

## Časté problémy

| Problém | Řešení |
|---|---|
| SSH odmítnuto / `Permission denied` | Uživatel, klíč nebo heslo; uživatel musí smět SSH. |
| `CLI pole odpovědělo ... invalid option` | CLI tohoto OS bere jiné volby - viz `help createcert` / `help importcert`, a dejte nám vědět. |
| `nelze předat CLI pole` | Odstraňte ze subjektu u cíle `"`, `[ ]`, `{ }`, `$` nebo `\`. |
| `nevypsalo žádný CSR` | Uživatel nemá *super* v *all*, nebo CLI vypsalo CSR jinam - podívejte se do detailu úlohy. |
| Import odmítnut | Na poli mezitím vznikl jiný CSR (ručně) - **Obnovit teď** vytvoří nový. |
| Nasazení pozdržena | Pole si nechá starý certifikát; další vydání si vyžádá nový klíč a CSR. |
