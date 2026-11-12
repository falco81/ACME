# Tento server acme - nastavení pro acme

acme udělá ze spravovaného certifikátu certifikát **vlastních stránek** - každého uzlu,
VIP adresy, nebo obojího - stejně, jako by ho převzalo nahrání v **Settings →
Certificates and TLS**. Každý uzel ho během několika sekund vloží do nginx; certifikát
VIP adresy servíruje ten uzel, který adresu právě drží. Obnova ho nasadí znovu sama, takže
se stránky obnoví na všech uzlech. Vlastní ACME enginu (**Settings → Automatic
certificates**) pak tyto stránky nechá být. Nastavení TLS stránek (protokoly, šifry, DH,
HSTS) zůstává beze změny.

Pro tento server acme, samostatný uzel i cluster.

## Co potřebujete

- Certifikát v acme, který obsahuje **jména, pod kterými jsou stránky dostupné**: jméno
  každého uzlu a v clusteru s VIP adresou i jméno VIP (SAN certifikát pro všechna, nebo
  jeden certifikát na stránky).
- Jeho soukromý klíč uložený v acme (certifikát bez klíče nasadit nelze).
- V clusteru: jména uzlů a VIP adresu podle **Settings → High availability**.

## Nastavení stránek acme

Není se kam přihlašovat - cíl nemá žádná nastavení.

1. Zjistěte jména: **Settings → High availability** ukazuje jméno každého uzlu a jméno
   VIP adresy.
2. V **Certificates** vytvořte (nebo vyberte) certifikát, jehož jména tato jména
   obsahují, a nechte ho vydat.
3. V **Targets** přidejte cíl **This acme server (its pages)** a k němu nasazení
   certifikátu.
4. Počítejte s tím, že ručně nahraný certifikát ani automatické ACME stránek se pro
   stránky, kam acme nasazuje, už nepoužije.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Which pages (nasazení) | `auto` - všechny uzly a VIP adresa v clusteru, který ji má; `nodes` - vlastní stránky všech uzlů; `this` - uzel, který nasazuje; `vip` - jen VIP adresa; `list` - ty, které jsou vyjmenované níže |
| Nodes (or vip) (nasazení) | Při `list`: jeden na řádek, jméno uzlu, jak ho zná cluster, nebo `vip` |
| The certificate must hold the names (nasazení, pokročilé) | Zapnuto: odmítne certifikát, mezi jehož jmény není jméno uzlu nebo VIP (prohlížeč by ho tam odmítl) |

Příklad z příkazové řádky:

```sh
acme --target-add pages --kind appliance
acme --deploy-add acme-pages pages --set where=auto
```

## Ověření

- **Try** na cíli řekne, který uzel to je, jaké jsou uzly a VIP adresa a jaký certifikát
  mají jednotlivé stránky teď (`acme1: www.example.com, put in`).
- Po nasazení otevřete stránky každého uzlu a VIP adresu v prohlížeči, nebo:

  ```sh
  openssl s_client -connect acme1.example.com:443 -servername acme1.example.com </dev/null | openssl x509 -noout -subject -enddate
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| `there is no VIP address here` | Zvoleno `vip`, ale v Settings → High availability není nastavena VIP adresa |
| `not a node of this cluster (nor vip)` | Jméno v *Nodes* není jméno uzlu, jak ho zná cluster - použijte jména, která ukáže Try |
| Certifikát odmítnut kvůli chybějícím jménům | Přidejte do certifikátu jména uzlů / VIP, nebo vypněte *The certificate must hold the names* (nedoporučeno) |
| Druhý uzel ukazuje starý certifikát | Počkejte pár sekund; ověřte, že uzel běží a databáze clusteru se replikuje |
| Duální certifikát | Dvojče se stane druhým certifikátem stránek na všech uzlech / VIP; ověřují se oba |
