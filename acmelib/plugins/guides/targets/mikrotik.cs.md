# MikroTik RouterOS - nastavení pro acme

acme nahraje certifikát (celý řetězec) a jeho klíč na router jako soubory přes **SSH** (SCP/SFTP), naimportuje je (`/certificate import`), výsledek pojmenuje `acme-<jméno>-<datum>-<sériové číslo>`, nahrané soubory smaže a certifikát přiřadí vybraným službám - `www-ssl`, `api-ssl`, `reverse-proxy` (RouterOS 7.22+), SSTP serveru a OpenVPN serveru. Starší certifikáty acme, které žádná služba nepoužívá, se odstraní. Dva způsoby komunikace s routerem:

- **REST API (RouterOS 7) + SSH pro soubory** - výchozí;
- **jen SSH (RouterOS 6)** - totéž příkazy CLI.

## Co potřebujete

- RouterOS 7 (REST) nebo RouterOS 6 (jen SSH).
- Z acme: SSH (port 22) na router, a pro REST také HTTPS (`www-ssl`, port 443).
- Uživatele RouterOS ve skupině s politikami `read`, `write`, `api`, `rest-api`, `ssh`, `ftp` (`ftp` umožňuje zápis souborů přes SCP/SFTP; `rest-api` existuje jen v RouterOS 7).

## Nastavení RouterOS

1. Vytvořte skupinu a uživatele pro acme, povoleného jen ze serveru acme (zde `192.0.2.10`):

```text
/user group add name=acme policy=read,write,api,rest-api,ssh,ftp
/user add name=acme group=acme password="a-strong-password" address=192.0.2.10/32
```

   (Na RouterOS 6 vynechte `rest-api`.)

2. Volitelné, ale doporučené: přihlašování přes SSH klíčem. Nahrajte veřejný klíč vytvořený v acme (např. jako `acme.pub` přes Winbox **Files**) a pak:

```text
/user ssh-keys import public-key-file=acme.pub user=acme
```

3. Ověřte, že je SSH zapnuté a dosažitelné z acme:

```text
/ip service set ssh disabled=no address=192.0.2.10/32,10.0.0.0/8
```

4. Pro REST (RouterOS 7): `www-ssl` musí být zapnuté. Nový router nemá certifikát - pro první běh vytvořte self-signed:

```text
/certificate add name=selfsigned common-name=router.example.local key-usage=digital-signature,key-encipherment,tls-server
/certificate sign selfsigned
/ip service set www-ssl certificate=selfsigned disabled=no
```

   Pokud `www-ssl` omezujete adresou, přidejte do jeho `address` server acme. **Nešifrovanou službu `www` (HTTP) nechte vypnutou** - heslo se posílá v každém požadavku REST.

5. Pro SSTP / OpenVPN: servery musí existovat (`/interface sstp-server server`, `/interface ovpn-server server`); acme mění jen jejich certifikát.

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| Address | adresa routeru |
| Speak through | REST API (RouterOS 7) + SSH for the files, nebo SSH only (RouterOS 6) |
| User | `acme` |
| Password | jeho heslo (pro REST a pro SSH, když není zadán klíč) |
| HTTPS port | 443 (port `www-ssl`) |
| SSH port | 22 |
| The SSH key | klíč vytvořený v acme (veřejná část importovaná v kroku 2); prázdné: použije se heslo |
| SSH host key / Trust the first host key seen (pokročilé) | host key routeru, nebo důvěřovat prvnímu viděnému |
| Check the device's certificate | při prvním běhu vypnuto, dokud je `www-ssl` self-signed (nebo ho vložte jako *CA certificate*); potom zapnuto |
| Use it for (nasazení) | jedno na řádek: `www-ssl`, `api-ssl`, `reverse-proxy`, `sstp`, `ovpn` |
| Previous versions to keep | kolik starších certifikátů acme zůstane na routeru |
| Check what is served | `router.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme přečte `/system/resource` (REST) nebo `/system resource print` (SSH) a ukáže verzi RouterOS. Tlačítko *Try* u SSH klíče spustí `/system identity print`.
- Na routeru:

```text
/certificate print detail where name~"acme-"
/ip service print detail where name~"ssl"
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 při Testu (REST) | špatné heslo, skupina nemá `rest-api`/`read`, nebo `address` uživatele nezahrnuje acme |
| Přihlášení přes SSH odmítnuto | služba `ssh` vypnutá nebo omezená adresou, skupina nemá `ssh`, nebo klíč není uživateli importován |
| Nahrání souboru selže | skupina nemá `ftp` (potřeba pro zápis přes SCP/SFTP) |
| Chyba TLS při prvním běhu REST | `www-ssl` je self-signed: jednou vypněte *Check the device's certificate* nebo zadejte jeho certifikát jako CA |
| `the router took the certificate without its key` | nahrání klíče selhalo nebo nesedí; zkontrolujte soubory a volné místo na routeru |
| `not a service acme can bind on RouterOS` | používejte jen `www-ssl`, `api-ssl`, `reverse-proxy`, `sstp`, `ovpn` |
| `the old … is still used: kept` | používá ho jiná služba (např. IPsec, hotspot); přepněte ji ručně |
