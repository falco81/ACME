# VMware ESXi host - nastavení pro acme

acme se k hostiteli ESXi přihlásí přes **SSH**, zapíše certifikát hostitele do
`/etc/vmware/ssl/rui.crt` (celý řetězec) a `/etc/vmware/ssl/rui.key` a pak restartuje
`hostd` a `vpxa` (nebo všechny služby), aby ho viděl Host Client i vCenter. Selže-li
restart, vrátí staré soubory a služby restartuje znovu. Obsahují-li oba soubory už
přesně tento certifikát, nic se nemění.

Pro ESXi 6.7, 7.0 a 8.0. **ESXi před verzí 8.0 bere jen RSA klíče** - zvolte pro
certifikát typ klíče RSA.

## Co potřebujete

- SSH z acme na hostitele (TCP 22), na hostiteli zapnuté SSH.
- Účet **root** (nebo jiného správce, který smí zapisovat do `/etc/vmware/ssl` a
  restartovat služby).
- **Je-li hostitel spravován z vCenter** ve výchozím režimu VMCA, vCenter certifikát
  hostitele obnovuje a přepíše ten od acme: nejdřív nastavte ve vCenter
  `vpxd.certmgmt.mode` na `custom` (nebo `thumbprint`).
- Certifikát, jehož jména obsahují jméno hostitele, pod kterým ho vCenter a prohlížeče
  oslovují.

## Nastavení hostitele ESXi

1. Zapněte SSH: **Host Client → Host → Actions → Services → Enable Secure Shell (SSH)** a
   nastavte jeho politiku na *Start and stop with host* (**Manage → Services → TSM-SSH**),
   aby přežilo restart. Nebo ve vCenter: *host → Configure → System → Services → SSH*.
2. Přidejte veřejný klíč acme pro roota (přihlášení klíčem nehrozí zablokováním hesla):

   ```sh
   cat >> /etc/ssh/keys-root/authorized_keys <<'EOF'
   ssh-ed25519 AAAA... acme
   EOF
   ```

3. Jen pokud hostitele spravuje vCenter: **vCenter → Configure → Settings → Advanced
   Settings → Edit**, `vpxd.certmgmt.mode` = `custom`, pak restartujte službu vCenter
   (vpxd), jak popisuje Broadcom.
4. Je-li na hostiteli zapnutý lockdown mode, přidejte roota (nebo uživatele acme) do
   *Exception Users*, jinak bude přihlášení přes SSH odmítnuto.

## Vyplnění v acme

| Pole v acme | Co vyplnit |
|---|---|
| Address | Jméno nebo IP hostitele, např. `esxi01.example.local` |
| SSH port / User | `22` / `root` |
| Sign in with / The SSH key / Password | Klíč vytvořený v acme (doporučeno) nebo heslo roota |
| Host key / Trust the first host key seen (pokročilé) | SSH klíč hostitele, nebo důvěřovat prvnímu |
| Timeout (s) (pokročilé) | Výchozí 30 |
| Restart (nasazení) | `hostd and vpxa` (výchozí), `every service (services.sh restart)` nebo `nothing (done by hand)` |
| Leave a file alone when it is the same / Keep a copy of a file replaced | Práce se soubory `rui.crt` / `rui.key` |
| Check what is served | Výchozí: hostitel na portu 443 |

## Ověření

- **Try** spustí `vmware -v`: `signed in as root: VMware ESXi 8.0.x build-...`.
- Na hostiteli:

  ```sh
  openssl x509 -in /etc/vmware/ssl/rui.crt -noout -subject -enddate
  /etc/init.d/hostd status
  ```

## Časté problémy

| Problém | Řešení |
|---|---|
| Spojení na 22 odmítnuto | SSH na hostiteli není zapnuté (nebo se při restartu zastavilo) |
| Permission denied | Chybný klíč/heslo; lockdown mode bez výjimky pro uživatele |
| `"/etc/init.d/hostd restart ..." failed, the previous certificate is back` | Často klíč, který hostitel nebere (EC na ESXi před 8.0) - použijte RSA |
| vCenter ukazuje hostitele odpojeného | Po novém certifikátu může vCenter chtít jeho potvrzení - hostitele znovu připojte |
| vCenter certifikát znovu nahradil | `vpxd.certmgmt.mode` je stále `vmca` - nastavte `custom` |
| Host Client ukazuje starý certifikát | Počkejte minutu na hostd a obnovte stránku |
