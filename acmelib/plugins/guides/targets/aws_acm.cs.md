# AWS Certificate Manager (ACM) - nastavení pro acme

acme naimportuje certifikát do **ACM** (`CertificateManager.ImportCertificate`, podepsáno
Signature Version 4) a při každé obnově ho **znovu naimportuje do stejného ARN**. Listenery
ALB/NLB, distribuce CloudFront a vlastní domény API Gateway, které tento ARN používají,
převezmou nový certifikát samy - acme nic jiného nemění. ARN je ten, který zadáte, nebo ten,
který acme získalo při prvním importu (uchovaný pro region a certifikát).

Pro ACM v kterémkoli komerčním regionu AWS. **CloudFront bere certifikáty jen z
`us-east-1`.**

## Co potřebujete

- Účet AWS a **region** load balancerů / API Gateway (nebo `us-east-1` pro CloudFront).
- Odchozí HTTPS z acme na `acm.<region>.amazonaws.com` (TCP 443), přímo nebo přes proxy ze
  Settings → Proxy.
- Uživatele IAM s přístupovým klíčem (nebo dočasné přihlašovací údaje STS).
- Při opakovaném importu musí **typ a velikost klíče zůstat stejné** jako u certifikátu v
  ARN (ACM změnu odmítne).

## Nastavení AWS

1. Vytvořte politiku IAM s přesně těmito akcemi:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "acm:ImportCertificate",
         "acm:DescribeCertificate",
         "acm:ListCertificates",
         "acm:AddTagsToCertificate"
       ],
       "Resource": "*"
     }]
   }
   ```

   `Resource` pro `ImportCertificate`/`DescribeCertificate` můžete zúžit na ARN
   certifikátů, až budou existovat; `ListCertificates` potřebuje `*`.
2. Vytvořte uživatele IAM (bez přístupu do konzole), připojte politiku a vytvořte
   **přístupový klíč** (IAM → Users → uživatel → Security credentials → Create access
   key). S AWS CLI:

   ```sh
   aws iam create-policy --policy-name acme-acm-import --policy-document file://acme-acm.json
   aws iam create-user --user-name acme-acm
   aws iam attach-user-policy --user-name acme-acm --policy-arn arn:aws:iam::123456789012:policy/acme-acm-import
   aws iam create-access-key --user-name acme-acm
   ```

3. Volitelně: je-li certifikát už v ACM (dříve naimportovaný), zkopírujte jeho ARN.
4. Po prvním importu certifikát jednou vyberte na listenerech / distribucích / vlastních
   doménách; opakované importy tato přiřazení zachovají.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Access key ID | `AKIA...` uživatele IAM |
| Secret access key | Jeho tajný klíč |
| Session token (pokročilé) | Jen pro dočasné údaje STS |
| Region | Region load balancerů, např. `eu-central-1`; `us-east-1` pro CloudFront |
| Through the proxy (pokročilé) | Výchozí zapnuto: ven přes Settings → Proxy |
| Certificate ARN (nasazení) | Importovat do tohoto ARN; prázdné: jednou jako nový, pak se ten ARN uchová |
| Tags (nasazení, pokročilé) | `klic=hodnota`, jeden na řádek, např. `Owner=it` - jen při prvním importu |
| Check what is served | např. `www.example.com:443` |

## Ověření

- **Try**: `signed in to ACM in <region>, N certificates`.
- V AWS:

  ```sh
  aws acm describe-certificate --region eu-central-1 --certificate-arn <arn> --query 'Certificate.[Serial,NotAfter,InUseBy]'
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AccessDenied` / `UnrecognizedClientException` | Chybné klíče, nebo v politice chybí akce |
| `SignatureDoesNotMatch` | Chybný tajný klíč, nebo nejdou hodiny serveru acme - ověřte NTP |
| Odmítnuto, protože typ klíče se liší od ARN | Zachovejte typ klíče, nebo importujte jako nový certifikát (prázdný / jiný ARN) a přesměrujte na něj listenery |
| CloudFront certifikát nevidí | Musí být v `us-east-1` |
| Po obnově chybí tagy | ACM bere tagy jen při prvním importu |
| `acm.<region>.amazonaws.com` nedostupné | Povolte odchozí HTTPS nebo nastavte proxy |
