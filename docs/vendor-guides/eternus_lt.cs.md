# Fujitsu ETERNUS LT (LT140, LT260) - bez automatického nasazení

**Remote Panel (RMI)** páskových knihoven přijme „Custom Certificate“ **jen přes své webové
GUI**: „The functions related to certificates can only be used in the remote panel.“ Klíč
vytváří knihovna (průvodce CSR, 30 minut od CSR po podepsaný certifikát), import klíče vytvořeného
jinde neexistuje, stejně jako CLI, REST nebo SNMP (SSH je jen pro servis). acme pro ni **nemá
cíl**. (LT260 User's Guide -Panel Operation- P3AM-8802-14ENZ0, LT140 P3AG-3732-08ENZ0.)

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

## Ověření

```sh
openssl s_client -connect lt260.example.local:443 -servername lt260.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Přidejte k certifikátu v acme test TLS knihovny, ať se hlídá jeho vypršení. Páskových operací
(FC/SAS) se změna nedotkne.
