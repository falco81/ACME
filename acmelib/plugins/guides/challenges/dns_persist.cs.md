# dns-persist-01 (záznam DNS nastavený jednou) - nastavení pro acme

S **dns-persist-01** (draft-ietf-acme-dns-persist) se doména prokazuje **jedním záznamem TXT, který zůstává**: `_validation-persist.JMÉNO` jmenuje CA a účet ACME, který smí vydávat. Při objednávce se v DNS nic nemění a acme v té chvíli nepotřebuje přístup k DNS. Let's Encrypt to oznámil v únoru 2026; Google Trust Services (issuer domain `pki.goog`) to nabízí od září 2026. Dokud to CA nenabízí, prokazuje jména **záložní validace** (fallback) a acme samo přepne, jakmile to CA nabídne. Jen se zdrojem ACME (modul `acme`); ne pro IP adresy.

## Co potřebujete

- Zdroj ACME (Let's Encrypt, jeho staging nebo jinou CA, která dns-persist-01 nabízí). Záznam uvádí jeho **account URI** - acme ho ukáže a účet vytvoří, pokud ještě není.
- Přístup k DNS každé domény, kam jednou vložíte záznam TXT - ručně, nebo přes jinou validaci DNS, kterou acme už má (Cloudflare, Route 53, Active24, SSH DNS, RFC 2136 …).
- **Záložní validaci** (libovolnou jinou validaci DNS-01 nebo HTTP-01) po dobu, kdy CA dns-persist-01 nenabízí.

## Nastavení vašeho DNS

1. V acme otevřete stránku validace (Certificates → Validation → tato validace): ukazuje **přesný záznam** pro každý zdroj ACME s tlačítky pro kopírování. **Make the record** vytvoří u CA účet ACME, pokud ho zdroj ještě nemá. Z příkazové řádky: `acme --validation-show NAME`.
2. Vložte záznam jednou do DNS domény:

   ```text
   _validation-persist.example.com.  3600  IN  TXT  "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1234567; policy=wildcard"
   ```

   - `letsencrypt.org` - issuer domain name CA.
   - `accounturi=` - URL účtu ACME (povinné).
   - `policy=wildcard` - pokrývá i `*.example.com` (a podle draftu i jména pod doménou).
   - `persistUntil=` - volitelný unixový čas, po kterém CA záznam nebere.
3. **Let's Encrypt dnes hledá záznam jen u samotného jména**: `www.example.com` potřebuje vlastní `_validation-persist.www.example.com`. Zapněte *A record at each name (Let's Encrypt today)* a acme ukáže (nebo zapíše) jeden pro každé jméno.
4. Produkce a staging Let's Encrypt mají **různé URL účtů**: každý zdroj potřebuje svůj záznam. U jména může stát více záznamů TXT; ostatní záznamy TXT tam zůstanou.
5. Nebo ho nechte zapsat acme: v *Write the record through* zvolte validaci DNS, pak **Write the records to DNS** (nebo nechte zapnuté *Write it by itself when missing*). acme nahrazuje nebo odebírá jen záznamy, které samo zapsalo.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Names with the record | Kde záznam stojí; prázdné = jména certifikátů (nebo jejich registrované domény) |
| Cover subdomains and wildcards (policy=wildcard) | Zapnuto (výchozí) pro wildcardy a jména pod doménou |
| A record at each name (Let's Encrypt today) | Zapnout pro Let's Encrypt, jak dnes funguje |
| Valid until (persistUntil) | Volitelné datum nebo unixový čas |
| Fallback validation | Validace, která prokazuje jména, dokud CA dns-persist-01 nenabízí |
| Write the record through | Prázdné = ručně; nebo validace DNS, přes kterou acme záznam zapíše |
| Write it by itself when missing | Zapnuto (výchozí): chybějící záznam se zapíše při objednávce |
| Sources the record is for, The CA's issuer domain name, Resolvers | (pokročilé) prázdné = všechny zdroje ACME, `letsencrypt.org`, Settings → DNS |

## Kontrola

- **Test** (a **Check the records** na stránce validace) vyhledá záznam u každého jména a domén nad ním a řekne přesně, co je špatně: chybí, jiná CA, nečitelný, jiné account URI, chybí `policy=wildcard`, `persistUntil` vypršel nebo vyprší do 30 dnů. Také řekne, zda CA dns-persist-01 už nabízí.
- Ručně:

  ```sh
  dig +short TXT _validation-persist.example.com
  dig +short TXT _validation-persist.www.example.com
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `the CA does not offer dns-persist-01 yet - used FALLBACK` | Očekávané, dokud to CA nespustí; nic neměňte. |
| NXDOMAIN pro `_validation-persist.www.example.com` | Let's Encrypt chce záznam u každého jména - zapněte *A record at each name*. |
| Jiné account URI | Účet ACME se změnil (nebo staging vs. produkce) - aktualizujte záznam (nebo *Write the records to DNS*). |
| Wildcard odmítnut | Přidejte `policy=wildcard`. |
| `there is no ACME source` | Nejprve přidejte zdroj ACME - záznam uvádí jeho účet. |
