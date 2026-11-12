# FortiADC - nastavení pro acme

acme nasazuje certifikáty na Fortinet FortiADC přes jeho REST API. Každé nasazení nahraje certifikát a klíč jako **lokální certifikát** pod jménem s datem (`acme-…`), přidá ho do **skupiny lokálních certifikátů** místo staršího člena od acme, volitelně nasměruje **client SSL profily** na tuto skupinu a **virtuální servery** na profil, smaže starší certifikáty acme, které už žádná skupina nedrží, a odhlásí se.

Volání pro nahrání potřebuje **FortiADC 7.4.0 nebo novější**.

## Co potřebujete

- FortiADC 7.4.0 nebo novější, s REST API dosažitelným z acme přes HTTPS (správcové rozhraní, výchozí port 443; na rozhraní povolený administrativní přístup HTTPS).
- Administrátora, za kterého se acme přihlásí: uživatele s heslem, nebo **REST API admina** s API klíčem.
- **Skupinu lokálních certifikátů**, kterou předkládá váš client SSL profil (pokud žádnou nemáte, jednou ji ve FortiADC vytvořte).
- Volitelně: **skupinu intermediate CA** s mezilehlými certifikáty vaší CA - acme mezilehlé certifikáty nenahrává, jen uvede jméno skupiny.

## Nastavení FortiADC

1. Vytvořte pro acme přístupový profil: **System → Administrator → Access Profile → Create New**, např. `acme`, s **read-write** na části, které acme mění - systémové certifikáty (lokální certifikáty, skupiny certifikátů) a Server Load Balance (client SSL profily, virtuální servery) - a nic víc. Přesné názvy oprávnění se mezi verzemi liší; ověřte je ve své.
2. Vytvořte administrátora:
   - uživatel a heslo: **System → Administrator → Create New**, uživatel `acme`, přístupový profil `acme`, trusted hosts omezené na adresu acme serveru;
   - nebo API klíč: **System → Administrator → Create New → REST API Admin**, přístupový profil `acme`, trusted hosts jako výše; klíč si zkopírujte.
3. Jsou-li zapnuté VDOM, přidělte administrátorovi VDOM, kde certifikáty jsou, a poznamenejte si jeho jméno.
4. Pokud neexistuje, vytvořte skupinu lokálních certifikátů: **System → Certificate → Local Certificate Group** (v některých verzích pod **System → Certificate → Local**) - pojmenujte ji např. `acme-www`. acme do ní vloží svého člena.
5. Volitelně: vytvořte skupinu intermediate CA s mezilehlým certifikátem vaší CA (**System → Certificate → Intermediate CA Group**).
6. Nasměrujte svůj client SSL profil na skupinu (**Server Load Balance → Application Resources → Client SSL Profile**) - nebo to nechte na acme tím, že profil uvedete v nasazení.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | jméno nebo IP správcového rozhraní FortiADC |
| HTTPS port | 443 (nebo nastavený administrátorský port HTTPS) |
| Sign in with | uživatel a heslo, nebo klíč REST API admina |
| User / Password | administrátor z kroku 2 |
| API key | klíč REST API admina |
| VDOM | jméno VDOM; prázdné na FortiADC bez VDOM |
| Check the device's certificate | zapnuto; vypnout jen dokud má FortiADC self-signed certifikát |
| CA certificate (pokročilé) | CA vlastního certifikátu FortiADC, když není veřejná |
| Local certificate group (nasazení) | skupina z kroku 4 (tlačítko: List the certificate groups) |
| Intermediate CA group (nasazení) | skupina z kroku 5; prázdné: žádná |
| Client SSL profiles to point at the group | jména profilů, jedno na řádek; prázdné: profily zůstanou, jak jsou |
| Virtual servers to point at the profile | jména virtuálních serverů, jedno na řádek: dostanou první profil výše |
| Previous versions to keep | kolik starších certifikátů acme zůstane před smazáním |
| Check what is served | `adresa-vip:443`, jedna na řádek |

## Ověření

- **Test** v acme se přihlásí a čte z FortiADC; akce **List the certificate groups** vypíše skupiny a jejich členy, aniž by cokoli měnila.
- Po nasazení ukazuje ve FortiADC **System → Certificate → Local** nový certifikát `acme-…` a skupina ho má jako člena.
- Z příkazové řádky:

```sh
openssl s_client -connect vip.example.com:443 -servername www.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -enddate
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `FortiADC gave no token on signing in` / 401 | špatný uživatel nebo heslo, nebo trusted hosts neobsahují adresu acme |
| `FortiADC said error -N` | požadavek byl odmítnut - často chybí read-write práva v přístupovém profilu nebo je špatně VDOM |
| Nahrání selže na starším FortiADC | API pro nahrání potřebuje 7.4.0 nebo novější - aktualizujte |
| `no local certificate group is set` | vyberte skupinu v nasazení |
| `FortiADC has no client SSL profile "…"` / virtuální server | jména se musí přesně shodovat (i velikost písmen), ve správném VDOM |
| `virtual servers are given but no client SSL profile …` | když uvádíte virtuální servery, uveďte aspoň jeden client SSL profil |
| `the older … stays: a group still holds it` | starý certifikát ještě používá jiná skupina; odeberte ho tam |
| Klientům chybí mezilehlý certifikát | nastavte *Intermediate CA group* na skupinu s mezilehlým certifikátem vaší CA |
