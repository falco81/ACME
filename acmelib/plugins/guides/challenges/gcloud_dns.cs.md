# Google Cloud DNS - nastavení pro acme

acme prokazuje jména přes DNS-01 ve **veřejné** spravované zóně Google Cloud DNS: přihlásí se jako servisní účet (klíč JSON, JWT podepsané RS256 pomocí openssl), přečte sadu záznamů TXT `_acme-challenge.JMÉNO` a odešle jednu atomickou změnu, která sadu nahradí sadou s přidanou (nebo při úklidu odebranou) hodnotou. Změní-li sadu mezitím někdo jiný, změna selže a jeho hodnota se neztratí. Soukromé zóny se nepoužívají.

## Co potřebujete

- Veřejnou spravovanou zónu v Cloud DNS, s doménou delegovanou na její jmenné servery Google.
- Projekt Google Cloud, kde smíte vytvořit servisní účet a přidělovat role.
- Odchozí HTTPS z acme na `oauth2.googleapis.com` a `dns.googleapis.com` (port 443).
- `openssl` na stroji s acme (podepisuje žádost o token).

## Nastavení Google Cloud

1. **IAM & Admin → Service accounts → Create service account**: např. `acme-dns01`.
2. Přidělte mu na projektu roli **DNS Administrator** (`roles/dns.admin`). Pro nejmenší přístup místo ní vytvořte vlastní roli s: `dns.managedZones.list`, `dns.resourceRecordSets.list`, `dns.changes.create`, `dns.changes.get`, `dns.resourceRecordSets.create`, `dns.resourceRecordSets.update`, `dns.resourceRecordSets.delete`.
3. Servisní účet → **Keys → Add key → Create new key → JSON**. Stažený soubor dobře uschovejte - je to přihlašovací údaj.
4. V gcloud:

   ```sh
   gcloud iam service-accounts create acme-dns01 --project my-project
   gcloud projects add-iam-policy-binding my-project \
     --member serviceAccount:acme-dns01@my-project.iam.gserviceaccount.com --role roles/dns.admin
   gcloud iam service-accounts keys create acme-dns01.json \
     --iam-account acme-dns01@my-project.iam.gserviceaccount.com
   ```

   (Blokuje-li vaše organizace vytváření klíčů politikou, musí to admin pro tento účet povolit.)

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Service account key (JSON) | Celý soubor s klíčem JSON, vložený |
| Project ID | Projekt zóny; prázdné = projekt servisního účtu |
| Managed zone | **Název** zóny v Cloud DNS (např. `example-com`), ne doména; prázdné = najde se podle domény |
| TTL (s) | (pokročilé) Výchozí `60` |

## Kontrola

- **Test** v acme se přihlásí a vypíše spravované zóny projektu. Nic nemění.
- V gcloud:

  ```sh
  gcloud dns managed-zones list --project my-project
  gcloud dns record-sets list --zone example-com --name _acme-challenge.example.com. --type TXT
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `invalid_grant` / chyby JWT | Klíč byl smazán, nebo nesedí čas stroje s acme. |
| `403 Forbidden` | Servisní účet nemá roli na tomto projektu, nebo *Project ID* ukazuje jinam. |
| Zóna se nenajde | Zóna je soukromá nebo v jiném projektu - vyplňte *Project ID* / *Managed zone*. |
| Změna občas selže | Jiný nástroj mezitím změnil stejnou sadu záznamů; další pokus ji přečte znovu. |
