# Tencent Cloud DNSPod - nastavení pro acme

acme prokazuje jména metodou DNS-01 v doméně u **Tencent Cloud DNSPod**, přes API 3.0 (verze `2021-03-23`, `https://dnspod.tencentcloudapi.com/`), každý požadavek podepsaný TC3-HMAC-SHA256 pomocí SecretId a SecretKey z CAM. Volá `DescribeDomainList`, `DescribeRecordList`, `CreateRecord` (jeden TXT záznam pro každou hodnotu, na výchozí lince `默认`) a `DeleteRecord` podle id záznamu. Ostatní hodnoty na jménu zůstanou.

## Co potřebujete

- Doménu v DNSPod (Tencent Cloud) se jmennými servery DNSPod.
- HTTPS (TCP 443) z acme na `dnspod.tencentcloudapi.com`.
- **Správné hodiny** acme (podpisy jsou odmítnuty, jdou-li o víc než pár minut špatně).

## Nastavení Tencent Cloud

1. Přihlaste se do konzole Tencent Cloud.
2. **CAM → Policies → Create Custom Policy → Create by Policy Syntax**, název `acme-dnspod-dns01`:

   ```json
   {
     "version": "2.0",
     "statement": [{
       "effect": "allow",
       "action": ["dnspod:DescribeDomainList", "dnspod:DescribeRecordList",
                  "dnspod:CreateRecord", "dnspod:DeleteRecord"],
       "resource": ["*"]
     }]
   }
   ```

   (Funguje i přednastavená policy `QcloudDNSPodFullAccess`, ta ale dovoluje mnohem víc.)
3. **CAM → Users → Create User → Custom** → uživatel `acme`, přístup jen **Programming access** (bez přihlášení do konzole), připojte výše uvedenou policy.
4. Zkopírujte **SecretId** a **SecretKey** uživatele (klíč se zobrazí jednou; později u uživatele → **API Keys**).

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| SecretId | SecretId |
| SecretKey | SecretKey |
| Domain | prázdné (nejdelší doména účtu, do které jméno patří), nebo doména |
| TTL (s) | 600 (méně bezplatný tarif nepřijme; pokročilé) |
| API host | `dnspod.tencentcloudapi.com` (pokročilé) |

## Ověření

- V acme stiskněte **Test**: vypíše domény; nic nemění.
- Po objednávce: konzole → **DNSPod → My Domains →** doména: TXT záznam `_acme-challenge` se objeví a zase zmizí.

## Časté problémy

| Problém | Řešení |
|---|---|
| `AuthFailure.SignatureFailure` | Špatný SecretKey. |
| `AuthFailure.SignatureExpire` | Hodiny acme jdou špatně - zkontrolujte NTP. |
| `UnauthorizedOperation` | Uživateli CAM chybí některá ze čtyř akcí. |
| `InvalidParameter` u TTL | U bezplatného tarifu nechte *TTL (s)* na 600 nebo víc. |
| Doména nenalezena | Doména je v jiném účtu Tencent Cloud, nebo v DNSPod Čína (dnspod.cn) s vlastním účtem. |
