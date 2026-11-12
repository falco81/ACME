# S3 bucket (HTTP-01) - setup for acme

acme proves names by HTTP-01 by uploading the token file `.well-known/acme-challenge/TOKEN` to an **S3 or S3-compatible bucket** that serves the name - a static website or a CDN (CloudFront etc.) in front of the bucket - and deletes it afterwards (requests signed with AWS Signature V4). Works with Amazon S3 and S3-compatible services: MinIO, Ceph, Wasabi, Cloudflare R2, Backblaze B2, Hetzner, Exoscale SOS, OVH and others. **Not for wildcards** (they need DNS-01).

## What you need

- A bucket whose content is served at `http://NAME/` (S3 static website hosting, or a CDN with the bucket as origin).
- The name pointing at that website or CDN, answering on **port 80** to the internet.
- Outbound HTTPS from acme to the S3 endpoint (port 443).

## Set up the bucket

1. Create an IAM user (or the S3 service's access key) for acme, allowed only the token folder:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {"Effect": "Allow",
        "Action": ["s3:PutObject", "s3:GetObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::www-example-com/.well-known/acme-challenge/*"},
       {"Effect": "Allow", "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::www-example-com"}
     ]
   }
   ```

   (`s3:ListBucket` only lets acme's guide check that it sees the bucket; add the folder prefix if the site is in a folder).
2. Create an **access key** for the user and copy the key ID and secret.
3. Make the files readable by the CA: a bucket policy allowing public `s3:GetObject` on `.well-known/acme-challenge/*` (or set *ACL of the file* to `public-read` where ACLs are enabled), or let the CDN read the bucket through its origin access.
4. With a CDN in front: pass `/.well-known/acme-challenge/*` through to the bucket over **HTTP** without caching (or with a very short cache).
5. For other services, create the key in their console (e.g. R2 → *Manage R2 API tokens* with Object Read & Write on the bucket; Backblaze → *App Keys* limited to the bucket).

## Fill in acme

| acme field | What to put there |
|---|---|
| Bucket | The bucket name |
| Region | The bucket's region, e.g. `eu-central-1` (`auto` for Cloudflare R2) |
| Access key ID | The key ID |
| Secret access key | The secret |
| Session token | (advanced) Only for temporary STS credentials |
| Folder in the bucket | Where the site's root is in the bucket; empty = the bucket's root |
| Endpoint | (advanced) Empty = Amazon S3; another service: its S3 address, e.g. `https://s3.eu-central-003.backblazeb2.com` |
| Path style (endpoint/bucket/key) | (advanced) On for MinIO, Ceph and most self-hosted services |
| ACL of the file | (advanced) `none` (the bucket policy decides) or `public-read` |
| Check before the CA is asked | `http://NAME/` (default), the address below, or no check |
| Address the folder is served at | (advanced) e.g. `http://my-bucket.s3-website.eu-central-1.amazonaws.com/` |

## Check it

- **Test** in acme uploads a probe file, reads it back and deletes it.
- With the AWS CLI and curl:

  ```sh
  aws s3 ls s3://www-example-com/.well-known/acme-challenge/
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Common problems

| Problem | Fix |
|---|---|
| `403 AccessDenied` on upload | The policy does not cover `FOLDER.well-known/acme-challenge/*`, or the key belongs to another account. |
| `SignatureDoesNotMatch` | Wrong secret or *Region*; for S3-compatible services check *Endpoint* and *Path style*. |
| Test works but the CA gets 403/404 | The file is not public (bucket policy / ACL), *Folder* is wrong, or the name points elsewhere. |
| The CA gets an old answer | The CDN caches the challenge path - exclude it. |
