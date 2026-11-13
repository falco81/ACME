# VMware Aria Automation / Orchestrator (vracli) - nastavení pro acme

acme nastaví **ingress certifikát** Aria Automation nebo Automation Orchestratoru 8.18 (UI a API na 443) pomocí `vracli` přes **SSH jako root**:

1. `vracli certificate ingress --list` - je-li tam už tento certifikát, nic nedělá;
2. zapíše `/root/acme-ingress-<náhodné>.pem` (0600): **soukromý klíč RSA, certifikát, mezilehlé, kořen** - každý blok na vlastních řádcích (KB 325876, KB 423843);
3. `vracli certificate ingress --validate stdin --parse < soubor` - odmítnutí ho zastaví dřív, než se cokoli změní;
4. `vracli certificate ingress --set <soubor>`;
5. **`/opt/scripts/deploy.sh`** - znovu nasadí všechny služby na všech uzlech: **produkt je desítky minut nedostupný**;
6. soubor smaže, ať se stalo cokoli.

V clusteru stačí jeden uzel: `deploy.sh` to použije na všechny.

## Pro které verze je tento návod

Aria Automation a Automation Orchestrator (i samostatný) **8.18.x**. Spravuje je **Aria Suite Lifecycle**? Dejte přednost cíli `aria_lifecycle`: jeho *Replace Certificate* zajistí, že nový certifikát přijmou i ostatní produkty. **VCF Automation 9.x** spravuje VCF Operations (fleet management), který bere jen vlastní CSR - na to tento cíl není.

## Nastavení appliance

1. SSH jako **root** je na appliance standardně zapnuté. Veřejný klíč z acme (karta klíče v acme) vložte do `/root/.ssh/authorized_keys`, nebo použijte heslo roota.
2. Jednou to vyzkoušejte ručně:

   ```sh
   ssh root@vra01.example.local 'vracli certificate ingress --list | openssl x509 -noout -subject -dates'
   ```

3. Nasazení plánujte do **servisního okna**: `deploy.sh` zastaví a spustí všechny služby. Předem udělejte snapshot.
4. Za load balancerem, který ukončuje TLS, vyměňte certifikát i na něm (Suite Lifecycle to nedělá).

## Certifikát

- Klíč **RSA** (jiný acme odmítne dřív, než se připojí).
- SAN: **FQDN a IP všech uzlů a FQDN load balanceru**; **žádný wildcard** (KB 325876; bez uzlů precheck selže, KB 420444).
- Kořen na konci PEM: vyplňte *Kořenový certifikát CA*, když jím řetězec nekončí.

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa | uzel, např. `vra01.example.local` |
| SSH port / Uživatel | `22`, `root` |
| Přihlásit se přes / SSH klíč / Heslo | klíč (vytvořený v acme) nebo heslo roota |
| Kořenový certifikát CA (nasazení) | kořenový PEM (pro Let's Encrypt ISRG Root X1) |
| Spustit /opt/scripts/deploy.sh (nasazení) | zapnuto; vypnuto: spustíte ho sami později - certifikát se použije až po něm |
| Čekat na deploy.sh (minut) (nasazení, pokročilé) | `90` |
| Zkontrolovat, co se servíruje | `vra.example.local:443` (load balancer) a uzly |

## Kontrola

*Vyzkoušet* se přihlásí a řekne, zda je ingress certifikát nastavený. Po nasazení:

```sh
vracli certificate ingress --list | openssl x509 -noout -subject -dates
openssl s_client -connect vra.example.local:443 </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

## Časté potíže

| Potíž | Řešení |
|---|---|
| `vracli does not take the certificate` | Přečtěte si v úloze, co vracli hlásí: špatný SAN, neúplný řetězec (vyplňte kořen). |
| vyžaduje `--sha256` (KB 423843) | Bloky PEM nejsou na vlastních řádcích - acme je tak zapisuje; nahlaste to. |
| `deploy.sh` selže nebo trvá dlouho | Konec jeho výstupu je v úloze acme; celý ho uvidíte, když ho na uzlu spustíte ručně. Samostatný Orchestrator 8.18.1 s vlastním certifikátem: KB 384243. |
| Ostatní produkty přestaly důvěřovat | Použijte cíl `aria_lifecycle` (Retrust), nebo důvěru v každém produktu upravte ručně. |
