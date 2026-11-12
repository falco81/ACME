# Dell PowerScale OneFS - nastavení pro acme

acme nahraje certifikát na **cluster PowerScale (Isilon)** jako serverový certifikát HTTPS a
nastaví ho jako **výchozí certifikát HTTPS** pro WebUI a Platform API
(`https://<cluster>:8080`). Používá jen REST API OneFS na portu 8080 se základní (basic)
autentizací:

1. přečte verzi OneFS (`GET /platform/1/cluster/config`);
2. zapíše certifikát (s mezilehlými) a klíč jako soubory do `/ifs/local` přes RESTful Access
   to Namespace (RAN, `PUT /namespace/ifs/local/<jméno>.crt|.key`, práva 0600) - OneFS
   importuje certifikáty **jen ze souborů na /ifs**;
3. naimportuje je (`POST /platform/4/certificate/server` s `certificate_path` a
   `certificate_key_path`) pod jménem s datem `acme-<jméno>-<datum>-<sériové číslo>`;
4. **oba soubory hned smaže** (i když import selže) - klíč na /ifs nezůstane;
5. nastaví ho jako výchozí (`PUT /platform/7/certificate/settings`
   `{"default_https_certificate": "<id>"}`);
6. smaže starší certifikáty od acme nad počet *ponechat* (nikdy ten, který je výchozí).

## Pro které OneFS

**OneFS 8.2 - 9.12** (ověřeno podle dokumentace 9.5 - 9.12, PAPI `v9_12_0`): všechny verze
používají stejná volání, proto jeden modul. OneFS 8.0/8.1 nastavovaly výchozí certifikát jinak
(`isi certificate server modify --default`) - ty acme odmítne dřív, než cokoli změní. Novější
OneFS pokračuje s varováním. Datové protokoly (SMB, NFS, S3) výměna neovlivní.

## Účet (nejmenší oprávnění)

| Oprávnění | Proč |
|---|---|
| `ISI_PRIV_LOGIN_PAPI` (čtení) | přihlášení do Platform API |
| `ISI_PRIV_CERTIFICATE` (zápis) | import, nastavení výchozího, mazání certifikátů |
| `ISI_PRIV_NS_IFS_ACCESS` (čtení) + zápis do `/ifs/local` | zápis a smazání obou souborů přes RAN |

Na libovolném uzlu, v zóně System (OneFS 9.x; 8.x používá `--add-priv`):

```sh
isi auth users create acme --enabled=true --set-password --zone=System
isi auth roles create AcmeCert --description "acme: TLS certificates" --zone=System
isi auth roles modify AcmeCert --add-priv-read=ISI_PRIV_LOGIN_PAPI --add-priv-write=ISI_PRIV_CERTIFICATE --add-priv-read=ISI_PRIV_NS_IFS_ACCESS --add-user=acme --zone=System
isi auth roles view AcmeCert
```

Názvy oprávnění si nejdřív ověřte na svém OneFS (nejsou ve všech příručkách):

```sh
isi auth privileges | grep -Ei 'cert|papi|ifs_access'
```

Složka pro soubory (smí do ní jen acme a root):

```sh
mkdir -p /ifs/local
chown acme /ifs/local
chmod 700 /ifs/local
```

Pokud chcete, má vše vestavěná role **SystemAdmin**.

## Co zapnout

- WebUI / Platform API na **TCP 8080** z acme (`isi http settings view`; HTTPS je zapnuté
  ve výchozím stavu).
- Basic autentizaci pro Platform API (ve výchozím stavu zapnutá).
- Jména v certifikátu musí obsahovat **všechna jména SmartConnect**, která klienti používají:
  OneFS vybírá certifikát podle požadovaného jména.
- Klíč RSA (příklad od Dellu: RSA 2048); ECDSA není zdokumentováno.

## Vyplňte v acme

| Pole v acme | Co do něj patří |
|---|---|
| Adresa / Port HTTPS | jméno SmartConnect clusteru nebo adresa uzlu, `8080` |
| Uživatel / Heslo | účet `acme` |
| Ověřovat certifikát zařízení | při prvním nasazení přes self-signed certifikát vypnuto (nebo vyplňte *Certifikát CA*), potom zapnuto |
| Nastavit jako výchozí certifikát HTTPS (nasazení) | zapnuto (vypnuto jen naimportuje) |
| Složka na /ifs pro import (nasazení, rozšířené) | `/ifs/local` |
| Kolik předchozích verzí ponechat (nasazení, rozšířené) | kolik starších certifikátů od acme ponechat |
| Zkontrolovat, co se servíruje | prázdné: acme ověří adresu a port cíle |

## Ověření

```sh
isi certificate server list -v
isi certificate settings view
openssl s_client -connect cluster.example.local:8080 -servername cluster.example.local -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

Přes API:

```sh
curl -s -u acme:'<heslo>' https://cluster.example.local:8080/platform/7/certificate/settings
```

## Časté problémy

| Problém | Řešení |
|---|---|
| `401` při přihlášení | Špatné heslo, nebo účet nemá `ISI_PRIV_LOGIN_PAPI`. |
| `403` u `PUT /namespace/...` | Chybí `ISI_PRIV_NS_IFS_ACCESS` nebo právo zápisu do složky. |
| `403` u `/platform/4/certificate/server` | Chybí `ISI_PRIV_CERTIFICATE` (zápis). |
| Import odmítnut, klíč nesedí | Klíč a certifikát se liší - nasaďte znovu (acme posílá vždy odpovídající pár). |
| `runs OneFS 8.1` | Aktualizujte na 8.2 nebo novější, nebo nastavte výchozí certifikát ručně. |
| Stále je servírován starý certifikát | Příručka OneFS 9.5 po změně restartuje službu WebUI - udělejte to v servisním okně: `isi services -a isi_webui disable` a `isi services -a isi_webui enable` (syntaxi ověřte na svém OneFS). |
| Prohlížeč hlásí nesoulad jména | Přidejte do certifikátu jména SmartConnect. |
