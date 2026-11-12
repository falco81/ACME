# Tencent Cloud DNSPod - setup for acme

acme proves names by DNS-01 in a domain at **Tencent Cloud DNSPod**, through API 3.0 (version `2021-03-23`, `https://dnspod.tencentcloudapi.com/`), each request signed TC3-HMAC-SHA256 with a CAM SecretId and SecretKey. It calls `DescribeDomainList`, `DescribeRecordList`, `CreateRecord` (one TXT record per value, on the default line `默认`) and `DeleteRecord` by the record's id. Other values at the name stay.

## What you need

- The domain in DNSPod (Tencent Cloud), with DNSPod's name servers.
- HTTPS (TCP 443) from acme to `dnspod.tencentcloudapi.com`.
- acme's **clock right** (signatures are refused when it is off by more than a few minutes).

## Set up Tencent Cloud

1. Sign in to the Tencent Cloud console.
2. **CAM → Policies → Create Custom Policy → Create by Policy Syntax**, named `acme-dnspod-dns01`:

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

   (The preset policy `QcloudDNSPodFullAccess` also works but allows far more.)
3. **CAM → Users → Create User → Custom** → user `acme`, access **Programming access** only (no console login), attach the policy above.
4. Copy the user's **SecretId** and **SecretKey** (the key is shown once; later under the user → **API Keys**).

## Fill in acme

| acme field | What to put there |
|---|---|
| SecretId | the SecretId |
| SecretKey | the SecretKey |
| Domain | empty (the longest domain of the account the name is in), or the domain |
| TTL (s) | 600 (the free plan takes nothing lower; advanced) |
| API host | `dnspod.tencentcloudapi.com` (advanced) |

## Check it

- In acme press **Test**: it lists the domains; nothing is changed.
- After an order: console → **DNSPod → My Domains →** the domain: the `_acme-challenge` TXT record appears and is removed again.

## Common problems

| Problem | Fix |
|---|---|
| `AuthFailure.SignatureFailure` | SecretKey wrong. |
| `AuthFailure.SignatureExpire` | acme's clock is off - check NTP. |
| `UnauthorizedOperation` | The CAM user lacks one of the four actions. |
| `InvalidParameter` on TTL | Keep *TTL (s)* at 600 or more on the free plan. |
| Domain not found | The domain is in another Tencent Cloud account, or in DNSPod China (dnspod.cn) with its own account. |
