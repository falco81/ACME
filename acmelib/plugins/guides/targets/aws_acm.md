# AWS Certificate Manager (ACM) - setup for acme

acme imports the certificate into **ACM** (`CertificateManager.ImportCertificate`, signed
with Signature Version 4) and on every renewal **re-imports it into the same ARN**. The
ALB/NLB listeners, CloudFront distributions and API Gateway custom domains that use that
ARN take the new certificate by themselves - acme touches nothing else. The ARN is the one
you give, or the one acme got on the first import (kept per region and certificate).

For ACM in any commercial AWS region. **CloudFront takes certificates only from
`us-east-1`.**

## What you need

- An AWS account and the **region** of the load balancers / API Gateway (or `us-east-1`
  for CloudFront).
- Outbound HTTPS from acme to `acm.<region>.amazonaws.com` (TCP 443), directly or through
  the proxy of Settings → Proxy.
- An IAM user with an access key (or temporary STS credentials).
- On re-imports the **key type and size must stay the same** as the certificate in the
  ARN (ACM refuses a change).

## Set up AWS

1. Create an IAM policy with exactly these actions:

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

   You may narrow `Resource` for `ImportCertificate`/`DescribeCertificate` to the
   certificate ARNs once they exist; `ListCertificates` needs `*`.
2. Create an IAM user (no console access), attach the policy, and create an **access
   key** (IAM → Users → the user → Security credentials → Create access key).
   With the AWS CLI:

   ```sh
   aws iam create-policy --policy-name acme-acm-import --policy-document file://acme-acm.json
   aws iam create-user --user-name acme-acm
   aws iam attach-user-policy --user-name acme-acm --policy-arn arn:aws:iam::123456789012:policy/acme-acm-import
   aws iam create-access-key --user-name acme-acm
   ```

3. Optional: if the certificate is already in ACM (imported before), copy its ARN.
4. After the first import, select the certificate on the listeners / distributions /
   custom domains once; re-imports keep these associations.

## Fill in acme

| acme field | What to put there |
|---|---|
| Access key ID | `AKIA...` of the IAM user |
| Secret access key | Its secret |
| Session token (advanced) | Only for temporary STS credentials |
| Region | The region of the load balancers, e.g. `eu-central-1`; `us-east-1` for CloudFront |
| Through the proxy (advanced) | On by default: out through Settings → Proxy |
| Certificate ARN (deploy) | Re-import into this ARN; empty: imported once as new, then that ARN is kept |
| Tags (deploy, advanced) | `key=value`, one a line, e.g. `Owner=it` - set on the first import only |
| Check what is served | e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in to ACM in <region>, N certificates`.
- In AWS:

  ```sh
  aws acm describe-certificate --region eu-central-1 --certificate-arn <arn> --query 'Certificate.[Serial,NotAfter,InUseBy]'
  ```

## Common problems

| Problem | Fix |
|---|---|
| `AccessDenied` / `UnrecognizedClientException` | Wrong keys, or a missing action in the policy |
| `SignatureDoesNotMatch` | Wrong secret, or the acme server's clock is off - check NTP |
| Refused because the key type differs from the ARN's | Keep the key type, or import as a new certificate (empty ARN / another ARN) and point the listeners at it |
| CloudFront does not see the certificate | It must be in `us-east-1` |
| Tags missing after a renewal | ACM takes tags only on the first import |
| Cannot reach `acm.<region>.amazonaws.com` | Allow outbound HTTPS or set up the proxy |
