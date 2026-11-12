# Alibaba Cloud DNS - setup for acme

acme proves names by DNS-01 at Alibaba Cloud DNS (Aliyun DNS): through the Alidns RPC API (version 2015-01-09) it adds a TXT record `_acme-challenge.NAME` (`AddDomainRecord`) and deletes only its own record afterwards (`DeleteDomainRecord`). It signs in with a RAM user's AccessKey.

## What you need

- The domain added to Alibaba Cloud DNS (any edition; **the free edition takes no TTL under 600**).
- Access to the RAM console to create a user and an AccessKey.
- Outbound HTTPS from acme to `alidns.aliyuncs.com` (or your region's endpoint, e.g. `alidns.ap-southeast-1.aliyuncs.com`), port 443.

## Set up Alibaba Cloud

1. RAM console → **Identities → Users → Create User**: a user for acme, with **OpenAPI access** (programmatic access) only, no console logon.
2. Save the **AccessKey ID** and **AccessKey secret** shown after creation - the secret is shown only once.
3. Give the user a policy. The simplest is the system policy `AliyunDNSFullAccess`; the minimal one is a custom policy allowing only the four actions acme calls:

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

4. Optional: add a condition `acs:SourceIp` with acme's public address to the policy.

## Fill in acme

| acme field | What to put there |
|---|---|
| AccessKey ID | The RAM user's AccessKey ID |
| AccessKey secret | Its secret |
| Domain | The domain, e.g. `example.com`; empty = the longest domain of the account the name is in |
| TTL (s) | (advanced) Default `600`; lower only on a paid edition |
| API address | (advanced) Default `https://alidns.aliyuncs.com`; a region's endpoint if needed |

## Check it

- **Test** in acme signs in and lists the domains (`DescribeDomains`). It changes nothing.
- With the Alibaba Cloud CLI configured with the same key:

  ```sh
  aliyun alidns DescribeDomainRecords --DomainName example.com --TypeKeyWord TXT
  ```

## Common problems

| Problem | Fix |
|---|---|
| `SignatureDoesNotMatch` | The secret is wrong (copied with a space?) or the acme machine's clock is off. |
| `Forbidden.RAM` / `NoPermission` | The user lacks one of the four `alidns:` actions. |
| TTL error (`DomainRecordTTLInvalid` or similar) | The free edition: set *TTL (s)* to 600 or more. |
| The domain is not found | It is not in this account's Alibaba Cloud DNS, or set *Domain* exactly. |
