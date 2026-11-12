# Amazon Route 53 - nastavení pro acme

acme prokazuje jména metodou DNS-01 v **hostované zóně Route 53**, přes Route 53 API (podepisuje AWS Signature Version 4 sám). Zónu najde podle jména (`ListHostedZonesByName`, veřejnou přednostně), není-li zadáno ID, načte TXT RRset na `_acme-challenge.JMÉNO` (`ListResourceRecordSets`), zapíše ho zpět s přidanou (`ChangeResourceRecordSets` UPSERT) nebo odebranou naší hodnotou (UPSERT, nebo DELETE s přesně načtenými hodnotami) a čeká, dokud není změna `INSYNC` (`GetChange`). Ostatní hodnoty v RRsetu zůstanou.

## Co potřebujete

- Veřejnou hostovanou zónu v Route 53, delegovanou od registrátora.
- HTTPS (TCP 443) z acme na `route53.amazonaws.com` (nebo endpoint pro Čínu / GovCloud).
- Účet AWS, kde smíte vytvořit uživatele IAM a policy.

## Nastavení AWS

1. **IAM → Policies → Create policy → JSON** - `Z0123456789ABC` nahraďte ID svých hostovaných zón:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": ["route53:ListHostedZones", "route53:ListHostedZonesByName", "route53:GetChange"],
         "Resource": "*"
       },
       {
         "Effect": "Allow",
         "Action": ["route53:GetHostedZone", "route53:ListResourceRecordSets"],
         "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABC"
       },
       {
         "Effect": "Allow",
         "Action": "route53:ChangeResourceRecordSets",
         "Resource": "arn:aws:route53:::hostedzone/Z0123456789ABC",
         "Condition": {
           "ForAllValues:StringEquals": {"route53:ChangeResourceRecordSetsRecordTypes": ["TXT"]},
           "ForAllValues:StringLike": {"route53:ChangeResourceRecordSetsNormalizedRecordNames": ["_acme-challenge.*"]}
         }
       }
     ]
   }
   ```

   Obě podmínky omezují acme na TXT záznamy na jménech `_acme-challenge`. `ListHostedZones` a `GetHostedZone` používá jen *Test* a seznam zón ve formuláři acme.
2. Pojmenujte ji `acme-route53-dns01`.
3. **IAM → Users → Create user** `acme` (bez přístupu do konzole) → *Attach policies directly* → výše uvedená policy.
4. Uživatel → **Security credentials → Create access key** → *Application running outside AWS* → zkopírujte **Access key ID** a **Secret access key**.

Nebo s AWS CLI:

```sh
aws iam create-user --user-name acme
aws iam put-user-policy --user-name acme --policy-name acme-route53-dns01 --policy-document file://policy.json
aws iam create-access-key --user-name acme
```

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Access key ID | `AKIA…` |
| Secret access key | tajný klíč |
| Session token | jen pro dočasné přihlašovací údaje (STS) (pokročilé) |
| Hosted zone ID | `Z0123456789ABC`, nebo prázdné (dohledá se podle jména) |
| TTL (s) | 60 (pokročilé) |
| Partition | `AWS`; Čína nebo GovCloud jen tam (pokročilé) |
| Wait for INSYNC | zapnuto (pokročilé) |

## Ověření

- V acme stiskněte **Test**: s ID zóny načte tuto zónu; jinak vypíše hostované zóny, které klíč vidí. Nic nemění.
- S AWS CLI:

```sh
aws route53 list-resource-record-sets --hosted-zone-id Z0123456789ABC \
  --query "ResourceRecordSets[?Type=='TXT']"
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AccessDenied` u ChangeResourceRecordSets | Špatné ID zóny v policy, nebo jméno neodpovídá `_acme-challenge.*` (CNAME vede jinam). |
| `AccessDenied` u ListHostedZones při *Testu* | Přidejte `route53:ListHostedZones`, nebo vyplňte *Hosted zone ID*. |
| `SignatureDoesNotMatch` | Špatný tajný klíč, nebo hodiny acme jdou o víc než 5 minut špatně. |
| Zvolena privátní zóna | Privátní a veřejná zóna mají stejné jméno - nastavte *Hosted zone ID* na veřejnou. |
