# AWS Private CA - nastavení pro acme

Zdroj **AWS Private CA** nechá vydávat certifikáty privátní CA služby AWS Private Certificate Authority (ACM PCA) z žádosti, kterou vytvořilo acme: `IssueCertificate` (CSR, podpisový algoritmus CA, platnost ve dnech, ARN šablony, je-li nastavena), pak `GetCertificate`, dokud není hotový - certifikát, který se ještě vytváří (`RequestInProgressException`), se vyžádá znovu, v případě potřeby při dalším pokusu. `RevokeCertificate` odvolává podle sériového čísla. Požadavky se podepisují AWS Signature Version 4 pomocí **přístupového klíče IAM**. **Soukromý klíč nikdy neopustí acme.** AWS účtuje každý vydaný certifikát - to je dohoda vlastníka CA s AWS; tady se nic nekupuje.

## Co potřebujete

- **ACTIVE** privátní CA v AWS Private CA a její ARN (`arn:aws:acm-pca:<region>:<account>:certificate-authority/<id>`).
- Uživatele IAM (nebo dočasné klíče role) pro acme s minimální politikou níže.
- Přístup HTTPS **z acme** na `acm-pca.<region>.amazonaws.com:443` (nebo VPC / FIPS endpoint), přímo nebo přes Nastavení → Proxy.

## Nastavení AWS

1. **IAM → Policies → Create policy** (JSON), omezená na CA:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": ["acm-pca:IssueCertificate", "acm-pca:GetCertificate",
                  "acm-pca:DescribeCertificateAuthority", "acm-pca:RevokeCertificate"],
       "Resource": "arn:aws:acm-pca:eu-central-1:123456789012:certificate-authority/…"
     }]
   }
   ```

   Volitelně: `acm-pca:ListCertificateAuthorities` (Resource `*`) umožní *Find the settings from the account* nabídnout ARN CA.
2. **IAM → Users → Create user** `acme-pca` (bez přístupu do konzole), připojte politiku, pak **Security credentials → Create access key** (*Application running outside AWS*). Zkopírujte ID klíče a tajný klíč.
3. Nebo z CLI:

   ```sh
   aws iam create-user --user-name acme-pca
   aws iam put-user-policy --user-name acme-pca --policy-name acme-pca --policy-document file://acme-pca.json
   aws iam create-access-key --user-name acme-pca
   ```

4. Zkopírujte ARN CA: **AWS Private CA → Private certificate authorities → CA → ARN**.

## Vyplnění v acme

Zdroje → **Přidat** → **AWS Private CA**.

| Pole v acme | Co do něj zadat |
|---|---|
| CA ARN | ARN z kroku 4; region se vezme z něj |
| Access key ID / Secret access key | z kroku 2 |
| Session token (pokročilé) | jen pro dočasné přihlašovací údaje |
| Validity (days) | `90` (výchozí); vlastní dny certifikátu mají přednost; nejvýš vlastní platnost CA |
| Template (pokročilé) | prázdné: `EndEntityCertificate/V1`; např. `arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1`. Šablony APIPassthrough nemají smysl (acme neposílá ApiPassthrough) |
| Signing algorithm (pokročilé) | *As the CA signs* |
| API endpoint (pokročilé) | prázdné: endpoint regionu; jinak VPC nebo FIPS endpoint |
| Wait for the certificate (s) (pokročilé) | `60` |

## Ověření

- Zdroje → zdroj → **Test** (Try it): `DescribeCertificateAuthority` - stav a subjekt CA.
- Se stejnými klíči:

```sh
aws acm-pca describe-certificate-authority --certificate-authority-arn <CA ARN> \
  --query 'CertificateAuthority.Status'
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `AccessDeniedException` | politice chybí některá akce výše, nebo její Resource je jiná CA |
| `InvalidSignatureException` / `UnrecognizedClientException` | špatný tajný klíč nebo ID klíče, nebo jdou hodiny acme špatně |
| `InvalidStateException` | CA není ACTIVE (čeká na certifikát, vypnutá, vypršelá) |
| `ValidationException` u platnosti | delší než zbývající platnost samotné CA |
| `MalformedCSRException` | šablona neodpovídá žádosti (např. šablona CSRPassthrough s nečekanými rozšířeními) |
| Certifikát není hotový | `RequestInProgressException`: acme se zeptá znovu; zvyšte *Wait for the certificate* |
