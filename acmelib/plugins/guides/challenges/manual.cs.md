# DNS ručně - nastavení pro acme

S touto validací acme ve vašem DNS nic nemění. Při každé objednávce - **i při obnovách** - ukáže přesný TXT záznam, který je třeba vložit (`_acme-challenge.JMÉNO. 60 IN TXT "<hodnota>"`, případně CNAME, kde je potřeba), a pak čeká, dokud ho neodpovídají všechny jmenné servery zóny, nebo dokud někdo neřekne **It is in DNS**. Potom vám připomene, že záznam lze zase odstranit.

Funguje s jakýmkoli poskytovatelem DNS, ale při každé objednávce musí někdo zasáhnout (každých 60-90 dní na certifikát, u krátkodobých certifikátů častěji). Pro obnovy, které nikdo nehlídá, zvolte jinou validaci.

## Co potřebujete

- Možnost upravit DNS zónu každého jména v certifikátu (webový panel poskytovatele, soubor zóny, ...).
- Někoho k dispozici po dobu objednávky (acme čeká tak dlouho, jak dovolí čekací doba ACME vydavatele).
- Aby se acme mohl ptát jmenných serverů zóny na UDP/TCP 53 (jinak použije resolvery a řekne to).

## Nastavení DNS

1. Předem nic nesnižujte - záznam je pokaždé nový. Ověřte, že v panelu poskytovatele lze přidat **TXT** záznam na jméno začínající `_acme-challenge`.
2. Když acme záznam ukáže (v DNS průvodci certifikátu a v logu úlohy), vložte ho přesně:

   ```text
   _acme-challenge.www.example.com.  60  IN  TXT  "gfj9Xq...Rg85nM"
   ```

   - Mnoho panelů chce jen návěští relativní k zóně: `_acme-challenge.www`.
   - Hodnoty, které na jméně už jsou, nechte - `example.com` a `*.example.com` potřebují dvě hodnoty na stejném jménu.
3. Počkejte, až acme řekne, že ho mají všechny jmenné servery, nebo v acme stiskněte **It is in DNS**.
4. Po vydání certifikátu záznam odstraňte (acme připomene, je-li zapnuto *Say to take it away afterwards*).

**Lepší:** vložte jednou CNAME - `_acme-challenge.www.example.com CNAME` do zóny, kam acme umí zapisovat (vlastní DNS server acme, acme-dns nebo poskytovatel s API, např. deSEC) - a přejděte na tu validaci; pak už se nic nedělá ručně.

## Vyplnění v acme

| Pole v acme | Co zadat |
|---|---|
| Say to take it away afterwards | zapnuto: acme po objednávce připomene smazání záznamu |
| Wait until it is seen by | vlastní jmenné servery zóny (výchozí); *nothing* = platí jen vaše **It is in DNS** (pokročilé) |
| Wait at least (seconds) | další prodleva pro poskytovatele, který publikuje pomalu (pokročilé) |

## Ověření

- **Test** nemá co zkoušet: záznam se vkládá ručně při každé objednávce.
- Během čekající objednávky ukazuje DNS průvodce certifikátu přesný záznam a zda ho mají všechny jmenné servery.

```sh
dig +short TXT _acme-challenge.www.example.com @ns1.your-provider.example
```

## Časté problémy

| Problém | Řešení |
|---|---|
| Objednávka vypršela | Záznam přišel pozdě - prodlužte čekací dobu ACME vydavatele, nebo použijte validaci s API. |
| „not on every name server yet“ | Sekundární jmenný server ještě nepřevzal zónu; počkejte, nebo zkontrolujte sériové číslo zóny / NOTIFY. |
| CA vidí špatnou hodnotu | Stará hodnota byla nahrazena místo přidání nové, nebo bylo jméno zadáno s dvakrát připojenou zónou (`..example.com.example.com`). |
| Obnova tiše selhala | Záznam nikdo nevložil - přejděte na automatickou validaci (viz *Lepší* výše). |
