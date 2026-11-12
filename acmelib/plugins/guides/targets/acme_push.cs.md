# Naše aplikace (acme push) - nastavení pro acme

acme nasadí certifikát do jiné aplikace stejné rodiny - **otp, isemon, zigmon nebo jiné
acme** - přes její vlastní **Settings → Certificates and TLS → Certificates from acme**.
Komunikuje přes HTTPS se správcovskými stránkami aplikace; každý požadavek je podepsán
klíčem Ed25519 acme a soukromý klíč putuje zapečetěný pro aplikaci (X25519 + HKDF-SHA256 +
AES-256-GCM). Certifikát se uloží do zadaných *slotů*: stránky jednotlivých uzlů, VIP
adresy, server před aplikací, broker.

Pro verze aplikací, které mají *Certificates from acme* (protokol acme push 1).

## Co potřebujete

- Správa aplikace dostupná z acme přes **HTTPS** (obvykle TCP 443), např.
  `https://otp.example.com/admin/` nebo `https://isemon.example.com/`.
- **Adresa acme povolená pro přístup ke správě**: vlastní seznam povolených adres
  správcovských stránek aplikace (řádky nginx `allow`) platí i pro acme.
- Správce aplikace, který funkci zapne a vytvoří párovací kód.

## Nastavení aplikace

1. Přihlaste se do správy aplikace.
2. Otevřete **Settings → Certificates and TLS → Certificates from acme** a zapněte
   **Take certificates from acme**.
3. Ověřte, že IP adresa acme patří mezi adresy povolené pro správcovské stránky
   (nastavení přístupu aplikace).
4. Klikněte na **Pair with an acme**. Zobrazí se jednorázový kód typu
   `ABCD-EFGH-JKMN-PQRS` - platí **15 minut a jen jednou**. Zkopírujte ho.
   - Alternativa: vložte tam **klíč acme** (*Or paste acme's key*). **Try** v acme ho
     vypíše, dokud nejsou spárované; vypadá jako `acme-push-ed25519 BASE64... komentář`.
     Tento způsob vyžaduje v acme zapnuté *Check the application's certificate*.
5. Volitelně povolte **Take certificates of other names**, jen pokud opravdu chcete
   nasazovat certifikát bez jmen slotu.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address of its administration | Jak ji otevíráte v prohlížeči: `https://JMENO/admin/` pro otp a acme, `https://JMENO/` pro isemon a zigmon |
| Pairing code | Kód z kroku 4; potřeba jen pro první **Try** (spárování) |
| Check the application's certificate | Zapnuto; vypnout jen dokud má self-signed certifikát (párovací kód i tak prokáže, kdo odpovídá) |
| CA certificate (pokročilé) | CA aktuálního certifikátu aplikace, pokud není veřejná |
| Timeout (s) (pokročilé) | Výchozí 30 |
| Slots (nasazení) | `auto` (každý slot, jehož jména certifikát obsahuje), `nodes`, `vip`, `this`, nebo id slotů z **Discover**, např. `node:otp1`, `vip`, `front`, `broker` - jeden na řádek |
| The certificate must hold the slot's names (nasazení, pokročilé) | Zapnuto; vypnutí se uplatní jen tam, kde to aplikace povoluje |

Příklad z příkazové řádky:

```sh
acme --target-add otp --kind acme_push --set url=https://otp.example.com/admin/ --set pair_code=ABCD-EFGH-JKMN-PQRS
acme --deploy-add otp.example.com otp --set slots=auto
```

## Ověření

- **Try** pozdraví aplikaci (hello), spáruje (je-li zadán kód) a přečte inventář - nic
  nemění. Odpoví např. `otp 1.2 answers, paired (code); slots: ...`.
- **Discover** vypíše sloty aplikace, jména, která musí každý obsahovat, a co v nich je;
  umí pro ně vytvořit certifikáty a nasazení.
- V aplikaci ukazuje *Certificates from acme* položku *Paired with* a sloty.
- K adrese aplikace připojte HTTPS test, který po nasazení ověří, co se servíruje.

## Časté problémy

| Problém | Řešení |
|---|---|
| `... does not speak acme push (HTTP 404)` | Chybná adresa: použijte URL správy (`/admin/` pro otp a acme) |
| `... takes no certificates from acme` | V aplikaci zapněte *Take certificates from acme* |
| Nedostupné / HTTP 403 | Adresa acme není povolena pro správcovské stránky |
| `not paired yet` | Vytvořte párovací kód a vložte ho do *Pairing code*, nebo tam vložte klíč acme |
| `the first pairing without a pairing code needs "Check the application's certificate" on` | Použijte párovací kód, nebo kontrolu zapněte |
| `... is not the one paired (its keys changed ...)` | Aplikace byla nastavena znovu: vytvořte nový kód a znovu **Try** |
| Kód odmítnut | Vypršel (15 minut), byl použit, nebo byl 5× zadán špatně - vytvořte nový |
| Certifikátu chybí jména slotu | Přidejte jména do certifikátu, nebo v aplikaci povolte jiná jména |
