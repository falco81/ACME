# Plesk - nastavení pro acme

acme přes **XML API** Plesku (`POST https://<host>:8443/enterprise/control/agent.php`)
nainstaluje certifikát, jeho klíč a řetězec CA do **úložiště certifikátů** - předplatného,
nebo serveru (*Tools & Settings*) - pod jménem s datem `acme-<jméno>-<datum>-<sériové číslo>`.

**acme certifikát webu nepřiřadí**: XML API Plesku na to nemá zdokumentované volání. Po
každém obnovení vyberte nový certifikát pro web v Plesku (nebo příkazem, viz níže); úloha
vás na to upozorní. Starší certifikáty acme se odstraňují jen tehdy, když nastavíte
*Previous versions to keep* (výchozí `-1`, ponechat vše), protože Plesk neprozradí, zda je
některý ještě přiřazen.

Pro Plesk Obsidian na Linuxu i Windows.

## Co potřebujete

- Síťový přístup z acme na panel Plesk: **TCP 8443**.
- Přihlášení správce nebo prodejce (reseller), nebo **tajný klíč** XML API.
- Předplatné (jeho hlavní doménu), do jehož úložiště certifikát patří, nebo úložiště serveru.

## Nastavení Plesku

1. Povolte acme přístup na port 8443 (Plesk Firewall: **Tools & Settings → Firewall**, nebo
   váš síťový firewall); omezte ho na IP adresu serveru acme.
2. Zvolte způsob přihlášení acme:
   - **Tajný klíč** (doporučeno - neukládá se heslo, klíč je vázán na IP acme). Na serveru
     Plesk:

     ```sh
     plesk bin secret_key --create -ip-address <IP-acme> -description "acme"
     ```

     Příkaz vypíše klíč. Klíče vypíše `plesk bin secret_key --list`.
   - **Login a heslo**: účet `admin` nebo **prodejce**, kterému předplatné patří. Operace
     s certifikátem proběhne jeho jménem.
3. Je-li zapnuté *Tools & Settings → Restrict Administrative Access*, přidejte IP adresu
   serveru acme.
4. Poznamenejte si doménu předplatného (*Websites & Domains*).

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Server Plesk, např. `plesk.example.com` |
| HTTPS port | `8443` |
| Sign in with | *a secret key* nebo *login and password* |
| Secret key | Klíč z kroku 2 |
| Login / Password | `admin` nebo prodejce a jeho heslo |
| Check the device's certificate | Zapnuto; vypnout jen dokud má panel self-signed certifikát |
| CA certificate (pokročilé) | CA certifikátu panelu, pokud není veřejná |
| Repository (nasazení) | *the subscription's* nebo *the server's (Tools & Settings)* |
| Subscription (nasazení) | Doména předplatného, např. `example.com` |
| Previous versions to keep (pokročilé) | `-1` (výchozí, ponechat vše); číslo nastavte jen, když víte, že starší už nejsou přiřazené |
| Check what is served | např. `www.example.com:443` |

## Po každém obnovení: přiřazení

V Plesku: **Websites & Domains → <doména> → SSL/TLS Certificates** → vyberte pro doménu
nový certifikát `acme-...` (nebo *Hosting Settings → Certificate*). Nebo na serveru:

```sh
plesk bin subscription -u example.com -certificate-name acme-example.com-20261112-1a2b3c4d
```

## Ověření

- Na cíli stiskněte **Try**: acme vypíše úložiště serveru a odpoví
  `signed in to Plesk ...; N certificates in the server's repository`.
- Po nasazení je certifikát ve zvoleném úložišti; úloha končí
  `installed ... - assign it to the website in Plesk`.

## Časté problémy

| Problém | Řešení |
|---|---|
| `Plesk said ... authentication failed` | Špatný login/heslo, nebo tajný klíč byl vytvořen pro jinou IP. |
| `no subscription is set` | Vyplňte *Subscription*, nebo zvolte úložiště serveru. |
| `Plesk said ... domain does not exist` | Jméno předplatného není jeho hlavní doména. |
| Spojení odmítnuto / timeout | Port 8443 je blokovaný, nebo *Restrict Administrative Access* acme nepouští. |
| Web ukazuje starý certifikát | Očekávané: přiřaďte nový (viz výše). |
| `the older ... stays` | Plesk ho odmítl odstranit (zřejmě je ještě přiřazen); odstraňte ho ručně. |
