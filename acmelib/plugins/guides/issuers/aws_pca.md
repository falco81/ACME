# AWS Private CA - setup for acme

The **AWS Private CA** source has certificates issued by a private CA of AWS Private Certificate Authority (ACM PCA) from the request acme made: `IssueCertificate` (the CSR, the CA's signing algorithm, the validity in days, a template ARN where set), then `GetCertificate` until it is ready - a certificate still being made (`RequestInProgressException`) is asked for again, at the next try if need be. `RevokeCertificate` revokes by serial. Requests are signed with AWS Signature Version 4 using an **IAM access key**. **The private key never leaves acme.** AWS charges per certificate issued - that is the CA owner's agreement with AWS; there is no order to buy here.

## What you need

- An **ACTIVE** private CA in AWS Private CA and its ARN (`arn:aws:acm-pca:<region>:<account>:certificate-authority/<id>`).
- An IAM user (or a role's temporary keys) for acme with the minimal policy below.
- HTTPS access **from acme** to `acm-pca.<region>.amazonaws.com:443` (or a VPC / FIPS endpoint), directly or through Settings → Proxy.

## Set up AWS

1. **IAM → Policies → Create policy** (JSON), restricted to the CA:

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

   Optional: `acm-pca:ListCertificateAuthorities` (Resource `*`) lets *Find the settings from the account* offer the CA ARN.
2. **IAM → Users → Create user** `acme-pca` (no console access), attach the policy, then **Security credentials → Create access key** (*Application running outside AWS*). Copy the access key ID and secret.
3. Or with the CLI:

   ```sh
   aws iam create-user --user-name acme-pca
   aws iam put-user-policy --user-name acme-pca --policy-name acme-pca --policy-document file://acme-pca.json
   aws iam create-access-key --user-name acme-pca
   ```

4. Copy the CA ARN: **AWS Private CA → Private certificate authorities → the CA → ARN**.

## Fill in acme

Sources → **Add** → **AWS Private CA**.

| acme field | What to put there |
|---|---|
| CA ARN | the ARN from step 4; the region is taken from it |
| Access key ID / Secret access key | from step 2 |
| Session token (advanced) | only for temporary credentials |
| Validity (days) | `90` (default); a certificate's own days win; at most the CA's own validity |
| Template (advanced) | empty: `EndEntityCertificate/V1`; e.g. `arn:aws:acm-pca:::template/EndEntityServerAuthCertificate/V1`. APIPassthrough templates are not useful (acme sends no ApiPassthrough) |
| Signing algorithm (advanced) | *As the CA signs* |
| API endpoint (advanced) | empty: the region's; a VPC or FIPS endpoint otherwise |
| Wait for the certificate (s) (advanced) | `60` |

## Check it

- Sources → the source → **Test** (Try it): `DescribeCertificateAuthority` - the CA's status and subject.
- With the same keys:

```sh
aws acm-pca describe-certificate-authority --certificate-authority-arn <CA ARN> \
  --query 'CertificateAuthority.Status'
```

## Common problems

| Problem | Fix |
|---|---|
| `AccessDeniedException` | the policy lacks an action above, or its Resource is another CA |
| `InvalidSignatureException` / `UnrecognizedClientException` | wrong secret or key id, or acme's clock is off |
| `InvalidStateException` | the CA is not ACTIVE (pending certificate, disabled, expired) |
| `ValidationException` on validity | longer than the CA's own remaining validity |
| `MalformedCSRException` | the template does not fit the request (e.g. a CSRPassthrough template with unexpected extensions) |
| Certificate not ready | `RequestInProgressException`: acme asks again; raise *Wait for the certificate* |
