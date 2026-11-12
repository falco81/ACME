# Amazon Route 53 - setup for acme

acme proves names by DNS-01 in a **Route 53 hosted zone**, through the Route 53 API (signed with AWS Signature Version 4 by acme itself). It finds the hosted zone by name (`ListHostedZonesByName`, a public zone first) unless the ID is given, reads the TXT RRset at `_acme-challenge.NAME` (`ListResourceRecordSets`), writes it back with our value added (`ChangeResourceRecordSets` UPSERT) or removed (UPSERT, or DELETE with exactly the values read), and waits until the change is `INSYNC` (`GetChange`). Other values in the RRset stay.

## What you need

- A public hosted zone in Route 53, delegated from the registrar.
- HTTPS (TCP 443) from acme to `route53.amazonaws.com` (or the China / GovCloud endpoint).
- An AWS account where you may create an IAM user and a policy.

## Set up AWS

1. **IAM → Policies → Create policy → JSON** - replace `Z0123456789ABC` with your hosted zone ID(s):

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

   The two conditions limit acme to TXT records at `_acme-challenge` names. `ListHostedZones` and `GetHostedZone` are used only by *Test* and the zone list in acme's form.
2. Name it `acme-route53-dns01`.
3. **IAM → Users → Create user** `acme` (no console access) → *Attach policies directly* → the policy above.
4. The user → **Security credentials → Create access key** → *Application running outside AWS* → copy the **Access key ID** and **Secret access key**.

Or with the AWS CLI:

```sh
aws iam create-user --user-name acme
aws iam put-user-policy --user-name acme --policy-name acme-route53-dns01 --policy-document file://policy.json
aws iam create-access-key --user-name acme
```

## Fill in acme

| acme field | What to put there |
|---|---|
| Access key ID | `AKIA…` |
| Secret access key | the secret |
| Session token | only for temporary (STS) credentials (advanced) |
| Hosted zone ID | `Z0123456789ABC`, or empty (found by the name) |
| TTL (s) | 60 (advanced) |
| Partition | `AWS`; China or GovCloud only there (advanced) |
| Wait for INSYNC | on (advanced) |

## Check it

- In acme press **Test**: with a hosted zone ID it reads that zone; otherwise it lists the hosted zones the key sees. Nothing is changed.
- With the AWS CLI:

```sh
aws route53 list-resource-record-sets --hosted-zone-id Z0123456789ABC \
  --query "ResourceRecordSets[?Type=='TXT']"
```

## Common problems

| Problem | Fix |
|---|---|
| `AccessDenied` on ChangeResourceRecordSets | Zone ID in the policy wrong, or the name does not match `_acme-challenge.*` (a CNAME leads elsewhere). |
| `AccessDenied` on ListHostedZones in *Test* | Add `route53:ListHostedZones`, or set *Hosted zone ID*. |
| `SignatureDoesNotMatch` | Secret wrong, or acme's clock is off by more than 5 minutes. |
| Private zone chosen | A private and a public zone have the same name - set *Hosted zone ID* to the public one. |
