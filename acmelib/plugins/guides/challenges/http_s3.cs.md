# S3 bucket (HTTP-01) - nastavení pro acme

acme prokazuje jména přes HTTP-01 tak, že soubor s tokenem `.well-known/acme-challenge/TOKEN` nahraje do **bucketu S3 nebo S3-kompatibilního úložiště**, který obsluhuje dané jméno - statický web nebo CDN (CloudFront apod.) před bucketem - a poté ho smaže (požadavky podepsané AWS Signature V4). Funguje s Amazon S3 i S3-kompatibilními službami: MinIO, Ceph, Wasabi, Cloudflare R2, Backblaze B2, Hetzner, Exoscale SOS, OVH a dalšími. **Ne pro wildcardy** (ty potřebují DNS-01).

## Co potřebujete

- Bucket, jehož obsah se servíruje na `http://JMÉNO/` (S3 static website hosting, nebo CDN s bucketem jako originem).
- Jméno směřující na tento web nebo CDN a odpovídající do internetu na **portu 80**.
- Odchozí HTTPS z acme na endpoint S3 (port 443).

## Nastavení bucketu

1. Vytvořte pro acme uživatele IAM (nebo přístupový klíč služby S3) s přístupem jen do složky s tokeny:

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

   (`s3:ListBucket` jen umožní průvodci acme ověřit, že bucket vidí; je-li web ve složce, přidejte prefix složky).
2. Vytvořte uživateli **přístupový klíč** a zkopírujte ID klíče a secret.
3. Zpřístupněte soubory pro CA: bucket policy povolující veřejné `s3:GetObject` na `.well-known/acme-challenge/*` (nebo nastavte *ACL of the file* na `public-read`, jsou-li ACL zapnuté), nebo nechte CDN číst bucket přes svůj přístup k originu.
4. S CDN před bucketem: propouštějte `/.well-known/acme-challenge/*` do bucketu přes **HTTP** bez cachování (nebo s velmi krátkou cache).
5. U jiných služeb vytvořte klíč v jejich konzoli (např. R2 → *Manage R2 API tokens* s Object Read & Write na bucket; Backblaze → *App Keys* omezené na bucket).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Bucket | Název bucketu |
| Region | Region bucketu, např. `eu-central-1` (`auto` pro Cloudflare R2) |
| Access key ID | ID klíče |
| Secret access key | Secret |
| Session token | (pokročilé) Jen pro dočasné údaje STS |
| Folder in the bucket | Kde v bucketu je kořen webu; prázdné = kořen bucketu |
| Endpoint | (pokročilé) Prázdné = Amazon S3; jiná služba: její adresa S3, např. `https://s3.eu-central-003.backblazeb2.com` |
| Path style (endpoint/bucket/key) | (pokročilé) Zapnout pro MinIO, Ceph a většinu služeb na vlastním serveru |
| ACL of the file | (pokročilé) `none` (rozhoduje bucket policy) nebo `public-read` |
| Check before the CA is asked | `http://NAME/` (výchozí), adresa níže, nebo bez kontroly |
| Address the folder is served at | (pokročilé) např. `http://my-bucket.s3-website.eu-central-1.amazonaws.com/` |

## Kontrola

- **Test** v acme nahraje zkušební soubor, přečte ho zpět a smaže.
- Pomocí AWS CLI a curl:

  ```sh
  aws s3 ls s3://www-example-com/.well-known/acme-challenge/
  curl -i http://www.example.com/.well-known/acme-challenge/test
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `403 AccessDenied` při nahrání | Politika nepokrývá `FOLDER.well-known/acme-challenge/*`, nebo klíč patří jinému účtu. |
| `SignatureDoesNotMatch` | Špatný secret nebo *Region*; u S3-kompatibilních služeb zkontrolujte *Endpoint* a *Path style*. |
| Test funguje, ale CA dostane 403/404 | Soubor není veřejný (bucket policy / ACL), špatná *Folder*, nebo jméno vede jinam. |
| CA dostane starou odpověď | CDN cachuje cestu pro ověření - vyřaďte ji. |
