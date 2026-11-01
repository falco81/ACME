# Certificates by SCEP

The `scep` issuer gets certificates from any CA that speaks SCEP (RFC 8894):
Microsoft NDES, EJBCA, Smallstep step-ca, Cisco IOS, FortiAuthenticator,
Palo Alto, Jamf, OpenXPKI and others.

## What it does

1. `GetCACaps` - what the server can do (POST, AES, SHA-256, …).
2. `GetCACert` (with the *CA identifier* as `message`) - the CA certificate alone,
   or a PKCS#7 with the RA certificates too (NDES). The request is encrypted to
   the RA certificate meant for encryption (keyEncipherment), else to the CA.
   With a *CA fingerprint* set, the CA certificate must be that one.
3. `PKIOperation` with a **PKCSReq**: acme's CSR with the *challenge password*
   added (and signed again with the key), encrypted (EnvelopedData,
   AES-256-CBC - or 3DES where the server has no AES - the key RSA-encrypted to
   the RA/CA), wrapped in a SignedData signed by a short-lived self-signed
   certificate of the request's own key, with the SCEP attributes messageType,
   transactionID (the SHA-256 of the public key), senderNonce, and contentType,
   messageDigest, signingTime. POSTed where the server says *POSTPKIOperation*,
   else sent by GET, base64.
4. The **CertRep** is checked (its transaction and our nonce, its digest, its
   signature by the CA/RA with `openssl cms -verify`) and its pkiStatus read:
   * SUCCESS: the envelope opened with `openssl cms -decrypt` with the request's
     key, the certificate taken from the PKCS#7 inside (the chain from GetCACert);
   * PENDING: asked again by **CertPoll** (GetCertInitial) every *Ask again
     every* seconds for *Wait for approval*; then the job ends with *the CA holds
     the request* and later tries poll again under the same transaction;
   * FAILURE: its failInfo said in words (badAlg, badMessageCheck, badRequest,
     badTime, badCertId).

## The settings

| Field | |
|---|---|
| SCEP address | NDES: `https://ndes.example.local/certsrv/mscep/mscep.dll`; EJBCA: `…/ejbca/publicweb/apply/scep/<alias>/pkiclient.exe`; step-ca: `https://ca.example.local/scep/<provisioner>` |
| Challenge password | NDES: from `/certsrv/mscep_admin` (one-time by default - see below); EJBCA: the end entity's enrolment code; step-ca: the provisioner's `challenge` |
| CA fingerprint | SHA-256 (or SHA-1/MD5) of the CA certificate. **Set it**: SCEP often runs over plain HTTP, and the fingerprint is what stops someone in between |
| CA identifier | where one server hosts several CAs (EJBCA: the CA name) |
| Encryption / Digest | *As the CA says* picks AES-256-CBC and SHA-256 when it says AES / SHA-256 (or SCEPStandard), else 3DES and SHA-1 |

## Keys

SCEP answers are encrypted to the request's key, so the certificate's key type
must be **RSA** (2048 or more). An EC key is refused with words saying so.

## NDES notes

* The challenge password from `mscep_admin` is one-time and expires (60 minutes
  by default): an automatic renewal needs a fixed password -
  `HKLM\Software\Microsoft\Cryptography\MSCEP\UseSinglePassword` = 1 and the
  password set there, or `EnforcePassword` = 0 on a closed network.
* The template NDES issues from is set in the registry
  (`HKLM\Software\Microsoft\Cryptography\MSCEP`: `EncryptionTemplate`,
  `GeneralPurposeTemplate`, `SignatureTemplate`).
* NDES sends two RA certificates (signing and encryption); acme picks the one
  for encryption by its key usage.

## When it fails

| The job says | Do |
|---|---|
| the CA refused the request: … badRequest | a wrong, used or expired challenge password; names the CA does not allow |
| … badMessageCheck | the server could not check the signature or decrypt (the RA certificate changed?) |
| … badAlg | choose 3DES / SHA-1 under More (old servers) |
| … badTime | this machine's clock |
| the CA certificate … is not the one of the fingerprint | someone in between, or the CA was renewed: compare and set the new fingerprint |
| SCEP needs an RSA key | the certificate's key type to RSA |
