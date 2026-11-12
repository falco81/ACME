# Kemp / Progress LoadMaster - nastavení pro acme

acme nasazuje certifikáty na Kemp / Progress LoadMaster přes jeho **RESTful API** v podobě JSON (APIv2, `POST https://<lm>/accessv2`). Každé obnovení přidá certifikát (celý řetězec + klíč) pod jménem s datem (`addcert`), jednou přidá mezilehlé certifikáty (`addintermediate`), nasměruje zadané virtuální služby na nový certifikát (`modvs … CertFile=`, přičemž ostatní certifikáty virtuální služby ponechá a vymění jen starší certifikát acme) a smaže starší certifikáty acme (`delcert`). Změny platí ihned; zvláštní uložení neexistuje. acme dodržuje limit LoadMasteru 30 volání API za 3 sekundy.

## Co potřebujete

- LoadMaster **7.2.50 nebo novější** (kvůli JSON API `accessv2`).
- Přístup HTTPS z acme na správcové rozhraní LoadMasteru (WUI, výchozí port 443).
- Zapnuté API rozhraní a buď **API klíč**, nebo uživatele s právy **Certificate Creation** a **Virtual Services**.

## Nastavení LoadMasteru

1. Přihlaste se do webového rozhraní LoadMasteru (WUI) jako `bal` nebo jiný plný administrátor.
2. Zapněte API: **System Configuration → Remote Access → Enable API Interface** (zaškrtnout).
3. Vytvořte pro acme uživatele: **System Configuration → System Administration → User Management**, přidejte uživatele `acme` se silným heslem a jen s oprávněními **Certificate Creation** a **Virtual Services** (pokud je vaše verze uvádí zvlášť, přidejte i práva pro mezilehlé certifikáty).
4. V acme použijte buď jméno a heslo tohoto uživatele, nebo pro něj vytvořte **API klíč** (**Certificates & Security → API keys**, nebo sekce API klíče u uživatele, podle verze) a zkopírujte ho.
5. Pokud omezujete WUI podle adres (**System Configuration → Remote Access → Allowed WUI networks** apod.), přidejte server acme.
6. Poznamenejte si každou virtuální službu jako `adresa:port` (např. `192.0.2.10:443`) z **Virtual Services → View/Modify Services**; musí mít zapnutou SSL akceleraci (**SSL Properties → Enabled**).

Vyzkoušejte API ze serveru acme:

```sh
curl -s https://lm.example.local/accessv2 -H 'Content-Type: application/json' \
     -d '{"cmd":"listcert","apikey":"…"}'
```

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | správcová adresa LoadMasteru |
| HTTPS port | 443 (port WUI) |
| Sign in with | API klíč, nebo uživatel a heslo |
| API key | klíč z kroku 4 |
| User / Password | uživatel z kroku 3 (výchozí je `bal` - lépe vyhrazený uživatel) |
| Check the device's certificate | zapnuto; vypnout jen dokud má LoadMaster self-signed certifikát |
| CA certificate (pokročilé) | CA vlastního certifikátu LoadMasteru, když není veřejná |
| Virtual services (nasazení) | `adresa:port[:tcp\|udp]` každé virtuální služby, jedna na řádek |
| Add the intermediates (pokročilé) | zapnuto: řetězec se přidá jako mezilehlé certifikáty |
| Previous versions to keep | kolik starších certifikátů acme zůstane před smazáním |
| Check what is served | `192.0.2.10:443` nebo `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme se přihlásí a vypíše certifikáty.
- Ve WUI: **Certificates & Security → SSL Certificates** ukazuje nový certifikát `acme-…` a virtuální služby, které ho používají; **Intermediate Certs** ukazuje řetězec.
- Z příkazové řádky:

```sh
openssl s_client -connect 192.0.2.10:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the LoadMaster did not answer with JSON (is it 7.2.50 or later, the API on?)` | zapněte API rozhraní; starší LoadMastery aktualizujte |
| `the LoadMaster said … - Unauthorized` / chyby oprávnění | špatný klíč/heslo, nebo uživatel nemá Certificate Creation / Virtual Services |
| `"…" is not address:port[:tcp]` | virtuální službu zapište jako `192.0.2.10:443` |
| Virtuální služba nenalezena | adresa a port musí přesně odpovídat virtuální službě; musí mít zapnuté SSL |
| `… lists certificates acme cannot name …` | seznam virtuální služby nešel přečíst; acme nastaví jen svůj certifikát - ostatní přidejte zpět ručně |
| `the old … stays (still used?)` | některá virtuální služba ho ještě používá; LoadMaster ho odmítne smazat |
| Spojení padá | příliš mnoho volání API z více nástrojů najednou (limit 30 za 3 s pro všechny uživatele API) |
