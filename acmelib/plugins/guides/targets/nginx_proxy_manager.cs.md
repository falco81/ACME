# Nginx Proxy Manager - nastavení pro acme

acme komunikuje s API Nginx Proxy Manageru (NPM) (`http://<npm>:81/api`). Přidá certifikát jako **vlastní certifikát** (provider „other“) pod jménem s datem, nahraje certifikát, klíč a mezilehlé certifikáty a nasměruje na něj zadané proxy hosty, redirection hosty a 404 hosty - a standardně i každého hosta, který používal starší certifikát acme. NPM pak zapíše konfiguraci nginx těchto hostů a nginx reloaduje. Starší certifikáty acme, které už žádný host nepoužívá, se mažou; certifikátů Let's Encrypt, které NPM vytvořil sám, se acme nikdy nedotkne.

## Co potřebujete

- Nginx Proxy Manager 2.x s administrací (výchozí port 81) dosažitelnou z acme.
- Uživatele NPM **bez dvoufaktorového přihlášení**, který smí spravovat certifikáty a hosty, které acme mění.

## Nastavení Nginx Proxy Manageru

1. Přihlaste se do administrace NPM jako administrátor.
2. **Users → Add User**:
   - **Full Name** `acme`, **Email** např. `acme@example.com` (slouží k přihlášení), ne administrátor;
   - nastavte silné heslo (**⋮ → Change Password**).
3. **⋮ → Permissions** tohoto uživatele:
   - **Item Visibility**: *All Items* (acme musí vidět hosty a certifikáty, které mění, i ty vytvořené jinými);
   - **Certificates**: *Manage*;
   - **Proxy Hosts**: *Manage*; **Redirection Hosts** / **404 Hosts**: *Manage* jen když je má acme měnit, jinak *View*;
   - **Streams**, **Access Lists**: *Hidden*.
4. Pro tohoto uživatele **nezapínejte** dvoufaktorové přihlášení (acme druhý faktor zadat nemůže).
5. Port 81 nevystavujte do internetu; povolte ho jen správcům a serveru acme. **Bez HTTPS před portem 81 jde heslo po síti nešifrovaně** - je-li acme v jiné síti, dejte administraci za proxy hosta NPM s certifikátem a použijte jeho adresu `https://`.

Vyzkoušejte přihlášení ze serveru acme:

```sh
curl -s http://npm.example.local:81/api/tokens -H 'Content-Type: application/json' \
     -d '{"identity":"acme@example.com","secret":"…"}'
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | adresa administrace NPM se schématem a portem, např. `http://npm.example.local:81` |
| E-mail | e-mail uživatele NPM |
| Password | jeho heslo |
| Check the device's certificate | u adresy `https://`: zapnuto, pokud není self-signed |
| CA certificate (pokročilé) | CA certifikátu té adresy, když není veřejná |
| Proxy hosts (nasazení) | jeden na řádek: doménové jméno, které proxy host obsluhuje, nebo jeho ID |
| Redirection hosts / 404 hosts (pokročilé) | jeden na řádek: doménové jméno nebo ID |
| Also the hosts that use the older one | zapnuto: každý host se starším certifikátem acme přejde na nový |
| Previous versions to keep | kolik starších certifikátů acme zůstane (smažou se, jen když je žádný host nepoužívá) |
| Check what is served | `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí a čte z NPM.
- V NPM: **SSL Certificates** ukazuje nový vlastní certifikát (`acme-…`) s jeho platností; **Hosts → Proxy Hosts** ukazuje hosta, který ho používá.
- Z příkazové řádky:

```sh
openssl s_client -connect www.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `this NPM user signs in with a second factor …` | dejte acme vlastního uživatele bez 2FA |
| `Nginx Proxy Manager gave no token on signing in` / 401 | špatný e-mail nebo heslo |
| 403 při nahrávání nebo změně hosta | uživatel nemá *Manage* na Certificates nebo na ten typ hostů, nebo má viditelnost jen *Created Items* |
| `there is no proxy host "…" in Nginx Proxy Manager` | použijte doménu, kterou host obsluhuje, přesně jak je uvedena, nebo jeho ID |
| Host po změně hlásí chybu | NPM nedokázal reloadovat nginx - podívejte se na stav hosta a logy NPM (`docker logs <npm>`) |
| `the older … stays: N hosts still use it` | některé hosty se nepřesunuly; uveďte je, nebo nechte *Also the hosts that use the older one* zapnuté |
