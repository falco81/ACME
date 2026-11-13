# Webová konzole Cockpit (Linux, SSH) - nastavení pro acme

Cockpit nemá pro svůj certifikát API ani stránku: použije **poslední soubor podle jména** v `/etc/cockpit/ws-certs.d/` – `.crt` / `.cert` s certifikátem a řetězcem a vedle něj `.key` se stejným jménem (nešifrovaný). acme přes SSH:

1. nahraje oba soubory do složky pro nahrávání (`/tmp`) a nainstaluje je, každý **jedním příkazem přes sudo**:
   `install -m 0644 -o root -g root … /etc/cockpit/ws-certs.d/90-acme-<jméno>-<datum>-<sériové číslo>.crt` a `.key` s právy `0600`;
2. spustí `cockpit-certificate-ensure --check` (`/usr/libexec/…` na RHEL / Fedoře, `/usr/lib/cockpit/…` na Debianu / Ubuntu): kdyby Cockpit vzal jiný soubor, nové soubory zase odstraní a nasazení selže – dál se servíruje starý certifikát;
3. na požádání přidá certifikáty CA do **systémového úložiště důvěryhodných CA** (níže);
4. `systemctl restart cockpit.service` (otevřené relace Cockpitu se odhlásí; systémových služeb se to netýká) – bez restartu vezme cockpit-tls nový soubor, až příště naběhne (po 90 s nečinnosti se ukončí);
5. smaže starší soubory acme nad počet *Kolik předchozích verzí ponechat*.

Pokaždé nový soubor (nic se nepřepisuje), takže selhání nikdy nenechá Cockpit bez funkčního certifikátu.

## Pro které verze

Cockpit s `/etc/cockpit/ws-certs.d` a samostatným `.key` (Cockpit Guide, Cockpit 371; webová konzole RHEL 8, 9, 10, Fedora, Debian 13, Ubuntu 24.04, SLES / openSUSE). Jeden modul.

## Co potřebujete

- Nainstalovaný a zapnutý Cockpit: `dnf install cockpit` nebo `apt install cockpit`, `systemctl enable --now cockpit.socket`; ve firewallu otevřený port **9090** (`firewall-cmd --add-service=cockpit --permanent; firewall-cmd --reload`).
- Certifikát s FQDN (a IP), pod kterým uživatelé Cockpit otevírají. Platí systémová kryptografická politika (RHEL DEFAULT: RSA aspoň 2048).
- Účet pro acme se **sudo přesně na tyto příkazy** – žádný shell přes sudo:

```sh
useradd -r -m -s /bin/bash svc-cert
cat > /etc/sudoers.d/svc-cert <<'EOF'
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/bin/install -m 0600 -o root -g root /tmp/acme-* /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/bin/rm -f /etc/cockpit/ws-certs.d/90-acme-*, \
                              /usr/libexec/cockpit-certificate-ensure --check, \
                              /usr/bin/systemctl restart cockpit.service
EOF
visudo -cf /etc/sudoers.d/svc-cert
```

Na Debianu / Ubuntu je kontrola `/usr/lib/cockpit/cockpit-certificate-ensure --check`. Se zapnutým *Přidat její certifikáty CA do systémového úložiště důvěry* přidejte i řádky úložiště:

```text
# RHEL, Fedora
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/pki/ca-trust/source/anchors/acme-ca-*, /usr/bin/update-ca-trust extract
# Debian, Ubuntu
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /usr/local/share/ca-certificates/acme-ca-*, /usr/sbin/update-ca-certificates
# SLES, openSUSE
svc-cert ALL=(root) NOPASSWD: /usr/bin/install -m 0644 -o root -g root /tmp/acme-* /etc/pki/trust/anchors/acme-ca-*, /usr/sbin/update-ca-certificates
```

Řádky sudoers jsou návrh (žádný zdroj ho neuvádí); ověřte `sudo -l -U svc-cert`. Funguje i přihlášení jako `root` (bez *Použít sudo*). RHEL 8 se SELinuxem: acme zapisuje přes `install` jako root, změna `semanage` není potřeba (ta je pro certmonger, který do složky zapisuje sám).

## Vyplnění v acme

| Pole v acme | Co tam patří |
|---|---|
| Adresa / SSH port / Uživatel | server, `22`, `svc-cert` |
| Přihlásit se přes / SSH klíč | klíč vytvořený v acme |
| Použít sudo | zapnuto (vypnuto při přihlášení jako root); *Heslo pro sudo* prázdné při `NOPASSWD` |
| Port Cockpitu | `9090` (to acme kontroluje) |
| Složka pro nahrávání (pokročilé) | `/tmp` – uvádějí ji řádky sudoers |
| Předpona jména souboru (nasazení, pokročilé) | `90` – vyšší než `10-ipa.cert` a ostatní soubory tam |
| Restartovat cockpit.service (nasazení) | zapnuto |
| Přidat její certifikáty CA do systémového úložiště důvěry (nasazení) | zapnout u certifikátu vlastní CA, které má server sám důvěřovat |

## Ověření

```sh
openssl s_client -connect server01.example.com:9090 -servername server01.example.com -showcerts </dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
sudo /usr/libexec/cockpit-certificate-ensure --check
ls -l /etc/cockpit/ws-certs.d/
trust list --filter=ca-anchors | grep -i -A2 "Example CA"
```

## Časté problémy

| Co vidíte | Proč | Co dělat |
|---|---|---|
| *Cockpit would not use the new certificate (it takes 99-….crt)* | vyhrává soubor řazený později | zvyšte *Předpona jména souboru* (např. `99`) nebo ten soubor odstraňte |
| `sudo: a password is required` | řádek sudoers neodpovídá příkazu | porovnejte s příkazem v úloze; předpona a složka pro nahrávání musí sedět |
| stále se ukazuje starý certifikát | *Restartovat cockpit.service* je vypnuté | počkejte, až se cockpit-tls restartuje (90 s nečinnosti), nebo ho zapněte |
| `update-ca-certificates` soubor ignoruje | Debian chce `.crt`, jeden certifikát na soubor | acme zapisuje `acme-ca-<id>.crt`, každý zvlášť |
| RHEL 7 / 8: složka pro nedůvěru | tam `blacklist`, od RHEL 9 `blocklist` | acme jen přidává důvěryhodné kotvy |

Zdroje: Cockpit Guide *SSL/TLS Usage*, `cockpit-tls(8)`, `update-ca-trust(8)` (Fedora ca-certificates), `update-ca-certificates(8)` (Debian trixie), Linux System Roles `certificate`.
