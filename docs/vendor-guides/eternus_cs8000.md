# Fujitsu ETERNUS CS8000 - no automated deployment

ETERNUS CS8000 (V8.x, V9) serves its **Web GUI** over HTTPS from the VLP (and from the SVLP after a
failover). How its certificate is replaced - a "certificate management" section of the Web GUI,
file locations, a restart - is **not confirmed by any official document available** (the V9 User
Guide needs a support login; the white paper and data sheet do not describe it). Its CLI over SSH
is scriptable, but no certificate command is documented. acme therefore has **no target** for it.

## What to do

1. Look up "certificate management" in the ETERNUS CS8000 V9 User Guide (Web GUI chapter), or ask
   Fujitsu / Fsas service (role *Service*).
2. If the Web GUI takes a certificate with its key: make it in acme (RSA 3072, names of the VLP
   **and** the SVLP / the virtual address), download it as PEM key + full chain, import it there.
3. Use an account with the role *ETERNUS CS8000 Administrator* (or *Operating System
   Administrator*, as the guide says).

## Check it - both nodes

```sh
openssl s_client -connect cs8000-vlp.example.local:443 -servername cs8000.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates -ext subjectAltName
openssl s_client -connect cs8000-svlp.example.local:443 -servername cs8000.example.local </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

Add a TLS test of both addresses to the certificate in acme so its expiry is watched.
