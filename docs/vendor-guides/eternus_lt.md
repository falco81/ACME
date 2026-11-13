# Fujitsu ETERNUS LT (LT140, LT260) - no automated deployment

The tape libraries' **Remote Panel (RMI)** takes a "Custom Certificate" **only through its web
GUI**: "The functions related to certificates can only be used in the remote panel." The key is
made by the library (a CSR wizard, 30 minutes from CSR to the signed certificate), there is no
import of a key made elsewhere, no CLI, REST or SNMP for it (SSH is for service only). acme has
**no target** for it. (LT260 User's Guide -Panel Operation- P3AM-8802-14ENZ0, LT140
P3AG-3732-08ENZ0.)

## Doing it by hand

1. Sign in to the Remote Panel as *administrator* (or *security* for switching SSL); turn off
   "Restricted Remote Management Interface (RMI) Login" on the operator panel first, if it is on.
2. **[Configuration > Web Management] → [Session Timeout]**: 30 min.
3. **[Create Custom Certificate] → [Start Certificate Wizard]**: fill in the 7 fields → **[Generate
   CSR]**, copy the CSR, have it signed (in acme: an own authority, *Certificates → New* with the
   CSR sent in), paste the PEM into **Signed Certificate** → **[Finish]**.
4. **[Certificate Settings] → Use Custom Certificate → [Submit]**; **[Secure Communications]**: SSL
   on.
5. **[Backup Custom Certificate]** - after a controller board change **[Restore Custom
   Certificate]** puts it back.

## Check it

```sh
openssl s_client -connect lt260.example.local:443 -servername lt260.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates
```

Add a TLS test of the library to the certificate in acme so its expiry is watched. Tape
operations (FC/SAS) are not affected by the change.
