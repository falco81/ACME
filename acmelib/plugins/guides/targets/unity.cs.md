# Dell Unity (service shell) - nastavení pro acme

acme nainstaluje certifikát jako **certifikát správy Unisphere** na Dell Unity, Unity XT nebo
UnityVSA (GUI, REST API a uemcli na portu 443). Unity pro tento certifikát **nemá volání REST
ani příkaz uemcli**: postup Dellu (KB 000021122) vede přes **service shell**, a přesně to dělá
acme přes SSH jako uživatel `service`:

```text
put  /home/service/user/acmecert.crt     certifikát (+ mezilehlé), jen PEM
put  /home/service/user/acmecert.pk      klíč RSA, PEM, nešifrovaný, práva 0600
run  svc_custom_cert acmecert            "Successfully installed custom certificate files."
run  rm -f /home/service/user/acmecert.crt /home/service/user/acmecert.pk    (vždy)
```

`svc_custom_cert` **restartuje webový server Unisphere**: GUI, REST API a uemcli jsou na
chvíli nedostupné a jejich relace se odhlásí. Blokové ani souborové I/O to neovlivní.

## Pro které Unity OE

**Unity OE 5.x** (5.3, 5.4, 5.5.x; doporučeno 5.5.1 nebo novější) - ve všech stejný příkaz,
proto jeden modul. Verzi OE v service shellu přečíst nelze, takže:

- **OE 5.5.0** odmítne soubor s certifikáty CA (`Unable to validate the specified
  certificate`, KB 000317557) a může selhat s `Could not determine private key strength`
  (KB 000308965): tam vypněte **Přiložit mezilehlé certifikáty**, nebo raději aktualizujte na
  5.5.1+.
- Zdokumentované jsou jen klíče **RSA** (příklad od Dellu: RSA 2048) - klíč ECDSA acme odmítne.

## Účet

Umí to jen účet **service** (heslo se nastavuje při úvodní konfiguraci a liší se od hesla
admina Unisphere). Role Unisphere nestačí.

Zapněte SSH pro účet service - Unisphere: **Settings → Service → Service Tasks → Enable SSH** -
nebo přes uemcli (syntaxi ověřte na svém OE):

```sh
uemcli -d unity.example.local -u admin -p '<heslo-admina>' /service/ssh set -enabled yes
```

SSH na **adresu správy** vede na primární SP, kde soubory musí být. Ověřte to ze serveru acme:

```sh
ssh service@unity.example.local 'id -un; ls -d /home/service/user'
```

Heslo účtu service je silné tajemství: dejte acme vlastní cíl a pokud nasazujete jen občas,
SSH zase vypněte (acme se pak nepřipojí, dokud ho nezapnete).

## Vyplňte v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa | adresa správy Unity (`unity.example.local`) |
| SSH port | `22` |
| Uživatel | `service` |
| Přihlásit se přes / Heslo | *heslo*, heslo účtu service |
| Klíč serveru (rozšířené) | SSH klíč Unity, nebo nechte zapnuté *Věřit prvnímu viděnému klíči serveru* |
| Port HTTPS Unisphere (rozšířené) | `443` - kde acme kontroluje, co se servíruje |
| Přiložit mezilehlé certifikáty (nasazení) | zapnuto; **na OE 5.5.0 vypnuto** |
| Název souboru (nasazení, rozšířené) | `acmecert` - základ jmen souborů `.crt` / `.pk` |

## Ověření

```sh
openssl s_client -connect unity.example.local:443 -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
uemcli -d unity.example.local -u admin -p '<heslo-admina>' /sys/cert show
```

Kolik certifikátů je v souboru (OE 5.5.0):

```sh
openssl crl2pkcs7 -nocrl -certfile unitycert.crt | openssl pkcs7 -print_certs -noout | grep -E "Issuer:|Subject:"
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `/home/service/user is not there` | Přihlásili jste se jako jiný uživatel - použijte `service`. |
| `ERROR: File <acmecert.pk> does not exist` | Relace skončila na sekundárním SP: použijte adresu správy. |
| `ERROR: Certificate ... is invalid` | Není to PEM - acme zapisuje vždy PEM; zkontrolujte, že klíč je RSA. |
| `Unable to validate the specified certificate (0x1000100)` | OE 5.5.0: vypněte *Přiložit mezilehlé certifikáty*, nebo aktualizujte na 5.5.1+. |
| Unisphere Central hlásí chyby ověření | Odeberte Unity z Unisphere Central a přidejte ho znovu. |
| uemcli znovu žádá přijetí certifikátu | Po změně je to očekávané: přijměte a uložte ho (nebo `uemcli -certImport`). |
