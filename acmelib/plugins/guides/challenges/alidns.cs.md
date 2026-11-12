# Alibaba Cloud DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 v Alibaba Cloud DNS (Aliyun DNS): přes RPC API Alidns (verze 2015-01-09) přidá záznam TXT `_acme-challenge.JMÉNO` (`AddDomainRecord`) a poté smaže jen svůj vlastní záznam (`DeleteDomainRecord`). Přihlašuje se AccessKey uživatele RAM.

## Co potřebujete

- Doménu přidanou do Alibaba Cloud DNS (jakákoli edice; **bezplatná edice nepřijme TTL pod 600**).
- Přístup do konzole RAM pro vytvoření uživatele a AccessKey.
- Odchozí HTTPS z acme na `alidns.aliyuncs.com` (nebo endpoint vašeho regionu, např. `alidns.ap-southeast-1.aliyuncs.com`), port 443.

## Nastavení Alibaba Cloud

1. Konzole RAM → **Identities → Users → Create User**: uživatel pro acme, jen s **OpenAPI access** (programový přístup), bez přihlášení do konzole.
2. Uložte **AccessKey ID** a **AccessKey secret** zobrazené po vytvoření - secret se zobrazí jen jednou.
3. Přidělte uživateli politiku. Nejjednodušší je systémová politika `AliyunDNSFullAccess`; minimální je vlastní politika povolující jen čtyři akce, které acme volá:

   ```text
   {
     "Version": "1",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["alidns:DescribeDomains", "alidns:DescribeDomainRecords",
                  "alidns:AddDomainRecord", "alidns:DeleteDomainRecord"],
       "Resource": "*"
     }]
   }
   ```

4. Volitelně do politiky přidejte podmínku `acs:SourceIp` s veřejnou adresou acme.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| AccessKey ID | AccessKey ID uživatele RAM |
| AccessKey secret | Jeho secret |
| Domain | Doména, např. `example.com`; prázdné = nejdelší doména účtu, ve které jméno leží |
| TTL (s) | (pokročilé) Výchozí `600`; nižší jen v placené edici |
| API address | (pokročilé) Výchozí `https://alidns.aliyuncs.com`; případně endpoint regionu |

## Kontrola

- **Test** v acme se přihlásí a vypíše domény (`DescribeDomains`). Nic nemění.
- S Alibaba Cloud CLI nastaveným na stejný klíč:

  ```sh
  aliyun alidns DescribeDomainRecords --DomainName example.com --TypeKeyWord TXT
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `SignatureDoesNotMatch` | Špatný secret (zkopírovaný s mezerou?) nebo nesedí čas stroje s acme. |
| `Forbidden.RAM` / `NoPermission` | Uživateli chybí některá ze čtyř akcí `alidns:`. |
| Chyba TTL (`DomainRecordTTLInvalid` apod.) | Bezplatná edice: nastavte *TTL (s)* na 600 nebo více. |
| Doména se nenajde | Není v Alibaba Cloud DNS tohoto účtu, nebo vyplňte přesně *Domain*. |
