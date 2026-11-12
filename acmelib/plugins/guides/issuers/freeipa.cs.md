# FreeIPA / Red Hat IdM - nastavení pro acme

Zdroj **FreeIPA / Red Hat IdM** nechá vydávat certifikáty CA (Dogtag) systému FreeIPA / Red Hat Identity Management pro **servisní principal**: acme se přihlásí (`/ipa/session/login_password`), pak zavolá JSON-RPC `cert_request` pro `SERVICE/<první jméno>@REALM` s CSR, které vytvořilo, a certifikačním profilem (výchozí `caIPAserviceCert`); chybějící službu nejdřív přidá. **Soukromý klíč nikdy neopustí acme.** Odvolání je `cert_revoke`; seznam profilů pochází z `certprofile_find`; *Import from a source* používá `cert_find`. IPA vydává pro principaly: **žádné wildcardy**. FreeIPA 4.x, RHEL IdM 8/9/10.

## Co potřebujete

- IPA server dosažitelný **z acme** přes HTTPS (`443`).
- Uživatele pro acme s právem žádat o certifikáty pro služby (a přidávat služby, má-li je acme přidávat).
- První jméno každého certifikátu jako **host** v IPA (`ipa host-add`); další jména certifikátu musí být jména, která IPA dané službě dovolí (hosty, které spravuje host služby).
- Certifikát CA IPA (`/etc/ipa/ca.crt`).

## Nastavení IPA

Na IPA serveru (nebo klientovi s právy admina) nejdřív `kinit admin`.

1. Uživatel a role s potřebnými privilegii:

   ```sh
   ipa user-add svc-acme --first=acme --last=service --password
   ipa role-add "acme certificates"
   ipa role-add-privilege "acme certificates" --privileges="Certificate Administrators"
   ipa role-add-privilege "acme certificates" --privileges="Service Administrators"   # jen pro přidávání služeb
   ipa role-add-member "acme certificates" --users=svc-acme
   ```

   Pak se jednou přihlaste jako `svc-acme` (`kinit svc-acme`) a nahraďte počáteční heslo - IPA vynutí změnu při prvním přihlášení a s vypršelým heslem přihlášení acme selže. Nastavte politiku hesel, která ho nenechá vypršet příliš brzy.
2. Hosty pro jména:

   ```sh
   ipa host-add web1.example.local --force          # první jméno certifikátu
   ipa host-add www.example.local --force           # další jméno
   ipa host-add-managedby www.example.local --hosts=web1.example.local
   ```

   (Je-li další jméno odmítnuto, podívejte se do dokumentace IPA k SAN v certifikátech služeb.)
3. CA ACL: výchozí `hosts_services_caIPAserviceCert` dovoluje všem hostům a službám používat `caIPAserviceCert`. Pro jiný profil nebo sub-CA:

   ```sh
   ipa caacl-add acme-tls --servicecat=all
   ipa caacl-add-profile acme-tls --certprofiles=caIPAserviceCert
   ipa caacl-add-ca acme-tls --cas=ipa
   ```

4. Zkopírujte `/etc/ipa/ca.crt` z IPA serveru.

## Vyplnění v acme

Zdroje → **Přidat** → **FreeIPA / Red Hat IdM**.

| Pole v acme | Co do něj zadat |
|---|---|
| IPA server | `https://ipa.example.local` |
| User / Password | `svc-acme` a jeho (změněné) heslo |
| Realm | `EXAMPLE.LOCAL` |
| Service | `HTTP` (výchozí) - principal je `HTTP/<první jméno>@EXAMPLE.LOCAL` |
| Add the service when missing | zapnuto (vyžaduje *Service Administrators*); vypnuto, pokud služby zakládáte ručně |
| Profile | `caIPAserviceCert` (výchozí) - *Load the list* načte profily IPA; vlastní profil certifikátu má přednost |
| CA (pokročilé) | `ipa` (hlavní CA) nebo jméno sub-CA |
| IPA's CA certificate | obsah `/etc/ipa/ca.crt` |
| Check the server's TLS certificate (pokročilé) | zapnuto |

## Ověření

- Zdroje → zdroj → **Test** (Try it).
- V IPA po vydání:

```sh
ipa service-show HTTP/web1.example.local@EXAMPLE.LOCAL
ipa cert-find --services=HTTP/web1.example.local
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Přihlášení `401` / heslo vypršelo | změňte heslo přes `kinit svc-acme`; zkontrolujte politiku hesel |
| `Insufficient access` u `cert_request` | roli chybí *Certificate Administrators* (žádost o certifikát) |
| `service not found` | zapněte *Add the service when missing* (s *Service Administrators*), nebo `ipa service-add HTTP/web1.example.local` |
| `host not found` | přidejte hosta: `ipa host-add <jméno> --force` |
| SAN odmítnut (`... does not match`, `not allowed`) | další jméno není host spravovaný prvním hostem |
| `Principal ... not permitted to use CA ... with profile ...` | CA ACL musí dané službě povolit profil i CA |
| Wildcard odmítnut | IPA wildcardy nevydává - použijte jiný zdroj |
