# Fujitsu ETERNUS LT (LT140, LT260) - bez automatického nasazení

**Remote Panel (RMI)** páskových knihoven přijme „Custom Certificate“ **jen přes své webové
GUI**: „The functions related to certificates can only be used in the remote panel.“ Klíč
vytváří knihovna (průvodce CSR, 30 minut od CSR po podepsaný certifikát), import klíče vytvořeného
jinde neexistuje, stejně jako CLI, REST nebo SNMP (SSH je jen pro servis). acme pro ni **nemá
cíl**. (LT260 User's Guide -Panel Operation- P3AM-8802-14ENZ0, LT140 P3AG-3732-08ENZ0.)

## Co bylo ověřeno (2026-11)

acme vytvoří cíl pro zařízení, které si klíč dělá samo, kdykoli *některé* jeho rozhraní umí
vytvořit CSR a převzít podepsaný certifikát. Knihovny žádné nemají: obě uživatelské příručky
říkají „The functions related to certificates can only be used in the remote panel“;
knihovny nemají pro zákazníky REST API ani CLI („SSH is used for maintenance work. It cannot
be used by the customer.“), jejich SNMP MIB nemá objekty pro certifikáty a nepodporují
Ansible, PowerShell, ACME ani SCEP. Průvodce Remote Panelu je relace prohlížeče (nejvýše 30
minut) - ne rozhraní, které by acme smělo ovládat.

## Ruční postup

1. Přihlaste se do Remote Panelu jako *administrator* (nebo *security* pro přepínání SSL); je-li
   zapnuté „Restricted Remote Management Interface (RMI) Login“, nejdřív ho vypněte na operátorském
   panelu.
2. **[Configuration > Web Management] → [Session Timeout]**: 30 min.
3. **[Create Custom Certificate] → [Start Certificate Wizard]**: vyplňte 7 polí → **[Generate
   CSR]**, CSR zkopírujte, nechte podepsat (v acme: vlastní autorita, *Certifikáty → Nový*
   s vloženou CSR), vložte PEM do **Signed Certificate** → **[Finish]**.
4. **[Certificate Settings] → Use Custom Certificate → [Submit]**; **[Secure Communications]**: SSL
   zapnuto.
5. **[Backup Custom Certificate]** - po výměně řídicí desky ho **[Restore Custom Certificate]**
   vrátí.

## Obnova s pomocí acme

CSR z průvodce platí jen jeho 30 minut, takže každá obnova je nový klíč: spusťte průvodce
znovu (krok 3) a v acme u certifikátu zvolte **Poslat nový CSR** - s vlastní autoritou acme
se vydá hned, s rezervou v rámci 30 minut - a vložte ho. Zbytek ohlídá acme: **upozornění**
před vypršením certifikátu (Nastavení → Upozornění a reporty) a test TLS knihovny na portu 443, který
ukáže, zda se po *[Finish]* servíruje nový certifikát.

## Ověření

```sh
openssl s_client -connect lt260.example.local:443 -servername lt260.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Přidejte k certifikátu v acme test TLS knihovny, ať se hlídá jeho vypršení. Páskových operací
(FC/SAS) se změna nedotkne.
