acme-agent for Windows
======================

A server that takes its certificates from acme without acme holding any of its
credentials: no password, no remote desktop, no WinRM. acme proposes, signed; this
server decides by its own policy (C:\ProgramData\acme-agent\etc\policy, the
Administrators' - acme can never change it). The policy allows nothing until you
say so.

The whole story - the design, the threat model, the protocol, the policy - is in
acme's documentation: docs/target-agent.md ("Install on Windows").


Install by hand
---------------

Double-click acme-agent-X.Y.Z-windows-x64.msi: Welcome, Join (paste a join code,
or leave it empty), Install, Finish. Before you run it, compare its SHA-256 with
the one acme shows (PowerShell: Get-FileHash .\acme-agent-X.Y.Z-windows-x64.msi).

The join code is either
  * a target's join code (ACAG1...) - made on the target's card in acme
    (an hour, once), or
  * a company enrollment code (ACAE1...) - one code for many servers: each server
    that installs with it appears in acme as its own target, waiting for an
    administrator's confirmation.
Left empty, join later from an elevated prompt:  acme-agent join CODE

The join itself is finished by the service in the background (no network is needed
while installing); acme-agent status says how it goes. Confirm the fingerprint in
acme only when it is the one acme-agent fingerprint prints here.


Install silently (a company)
----------------------------

  msiexec /i acme-agent-X.Y.Z-windows-x64.msi /qn JOINCODE=ACAE1...
  msiexec /i acme-agent-X.Y.Z-windows-x64.msi /qn /l*v C:\Windows\Temp\acme-agent.log

  * Group Policy (GPO) software installation: Computer Configuration > Policies >
    Software Settings > Software installation > New > Package (from a share every
    computer can read), "Assigned". A GPO cannot pass JOINCODE on the command
    line: install without it and join with a startup script, or make a transform
    (.mst) that sets JOINCODE to the enrollment code.
  * Intune (Win32 app, .intunewin made from the MSI):
      install:   msiexec /i acme-agent-X.Y.Z-windows-x64.msi /qn JOINCODE=ACAE1...
      uninstall: msiexec /x {ProductCode} /qn
      detection: MSI product code (the version's own), install behaviour System.
  * Configuration Manager (SCCM / MECM): an application with a Windows Installer
    deployment type, the install line above, run as System, detection by the MSI
    product code.

A newer MSI replaces an older one in place (the policy and the agent's identity in
C:\ProgramData\acme-agent stay). An older one is never installed over a newer one.

The enrollment code is a secret for as long as it is valid: whoever has it can ask
to join (an administrator still confirms each server in acme, unless the code was
made to confirm by itself). The installer keeps it out of its logs.


Uninstall
---------

  Settings > Apps > Installed apps > acme-agent > Uninstall, or
  msiexec /x {ProductCode} /qn                 the policy and identity stay
  msiexec /x {ProductCode} /qn PURGE=1         ...taken away too

The product code of each version is in the MSI (Property table, ProductCode); acme's
Settings > Target agents shows it with the package.


The CLI (an elevated prompt - "Run as administrator" - is the analogue of sudo)
-------------------------------------------------------------------------------

  acme-agent status                      what is here
  acme-agent fingerprint                 the fingerprint to confirm in acme
  acme-agent join CODE                   join acme (ACAG1... or ACAE1...)
  acme-agent policy show                 what acme may do here
  acme-agent allow file C:\certs
  acme-agent allow service W3SVC restart
  acme-agent allow store                 Cert:\LocalMachine\My
  acme-agent allow iis "Default Web Site"
  acme-agent allow rdp
  acme-agent allow test -- C:\Windows\System32\inetsrv\appcmd.exe list site
  acme-agent allow script C:\scripts\after-cert.ps1
  acme-agent allow from 192.0.2.10
  acme-agent allow self-update
  acme-agent deny ...                    the same words: that entry taken away
  acme-agent forget                      leave acme (the policy stays)

Where things are:
  C:\Program Files\acme-agent\        the program, its own Python (runtime\) and
                                      OpenSSL (openssl\); MANIFEST and MANIFEST.sig
                                      list every file, signed by acme's release key
  C:\ProgramData\acme-agent\etc\      policy, agent.json
  Services:                           acme-agent-root (LocalSystem), acme-agent
                                      (NT SERVICE\acme-agent, no privileges)
  Log:                                Windows Application log, source acme-agent
