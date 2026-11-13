# -*- coding: utf-8 -*-
"""
What happens (runplan.py): the answers a source's and a validation's recording gets (1.0.98) -
what a CA's or a DNS provider's API answers when all goes as it goes on a running account:
the zone of the name is there, a record put in is listed back, an order is issued, the
certificate it sends is for the request's key. Made up, as every answer of the recording is;
each rule is plansandbox.Answers' (method, url regex, status, headers, body, times, sent, b64).

Placeholders, besides those of plansandbox.Answers ({SESSION}, {TAIL}, {SENT:key},
{SEEN:regex}): {ZONE} (the registrable domain of the name validated), {NAME}, {FQDN}
(_acme-challenge.NAME), {TXT} (the value put in); {CERT} / {CHAIN} (PEM of the certificate
issued for the request's key and of its intermediate), {CERT_B64} / {CHAIN_B64} (their DER in
base64), {P7_B64} / {CA_P7_B64} (PKCS#7 of both / of the intermediate, DER in base64),
{CERT_SERIAL}; {CFG:key} a setting of the module.

    answers(family, kind, version='') -> [rule]       family 'issuer' or 'challenge'
"""
from __future__ import annotations

import xmlrpc.client

RID = '‹record id›'
ZID = '‹zone id›'



def xmlrpc_answer(value):
    """An XML-RPC methodResponse holding value (Loopia, Gandi's old API...)."""
    return xmlrpc.client.dumps((value,), methodresponse=True)


def php_soap(command, value):
    """A PHP-SOAP answer to `command` holding value (a dict a map of key/value items, a list
    an array of items) - Subreg's."""
    from xml.sax.saxutils import escape

    def put(v):
        if isinstance(v, dict):
            return ''.join('<item><key>%s</key><value>%s</value></item>' % (escape(str(k)), put(x))
                           for k, x in v.items())
        if isinstance(v, list):
            return ''.join('<item>%s</item>' % put(x) for x in v)
        return escape(str(v))
    return ('<?xml version="1.0" encoding="UTF-8"?><SOAP-ENV:Envelope xmlns:SOAP-ENV='
            '"http://schemas.xmlsoap.org/soap/envelope/" xmlns:ns1="http://soap.subreg.cz/soap">'
            '<SOAP-ENV:Body><ns1:%sResponse><response>%s</response></ns1:%sResponse>'
            '</SOAP-ENV:Body></SOAP-ENV:Envelope>' % (command, put(value), command))


R53 = ('<?xml version="1.0" encoding="UTF-8"?>\n<%s xmlns="https://route53.amazonaws.com/doc/'
       '2013-04-01/">%s</%s>')

# an HTTP-01 file put in place: the name's own web server answers it (what a validation's
# ready() asks before the CA is told)
HTTP01 = [{'method': 'GET', 'url': r'^http://[^/]+/\.well-known/acme-challenge/[^/]+$',
           'headers': {'Content-Type': 'text/plain'}, 'body': '{KEYAUTH}'}]


SOURCES = {
    # -- commercial CAs: an order bought before, reissued inside it at each renewal; the
    #    domain's validation run out, so the CA asks for its DCV record again (put in place by
    #    the certificate's validation), checked, issued, downloaded ---------------------------
    'zerossl': [
        {'method': 'POST', 'url': r'/certificates(\?|$)', 'body': {
            'id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'type': '1', 'common_name': '{NAME}',
            'status': 'draft', 'validation': {'email_validation': {'{NAME}': [
                'admin@{ZONE}', 'webmaster@{ZONE}']}, 'other_methods': {'{NAME}': {
                    'file_validation_url_http': 'http://{NAME}/.well-known/pki-validation/'
                                                '0F2E4C6A8B1D3F5E7A9C0B2D4F6E8A1C.txt',
                    'file_validation_content': ['b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0',
                                                'comodoca.com', '‹unique value›'],
                    'cname_validation_p1': '_0F2E4C6A8B1D3F5E7A9C0B2D4F6E8A1C.{NAME}',
                    'cname_validation_p2': 'b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0.'
                                           '9a8b7c6d5e4f3a2b1c0d.zerossl.com'}}}}},
        {'method': 'POST', 'url': r'/challenges(\?|$)', 'body': {
            'id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'status': 'pending_validation'}},
        {'method': 'GET', 'url': r'/certificates/[0-9a-f]+(\?|$)', 'times': 1, 'body': {
            'id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'status': 'pending_validation'}},
        {'method': 'GET', 'url': r'/certificates/[0-9a-f]+(\?|$)', 'body': {
            'id': 'a1b2c3d4e5f60718293a4b5c6d7e8f90', 'status': 'issued',
            'expires': '2027-01-01 00:00:00'}},
        {'method': 'GET', 'url': r'/download/json', 'body': {'certificate.crt': '{CERT}',
                                                            'ca_bundle.crt': '{CHAIN}'}}],
    # Sectigo Certificate Manager: the domain's validation run out (CNAME DCV again), the
    # certificate renewed by its ID (renewById), collected once issued
    'sectigo_scm': [
        {'method': 'POST', 'url': r'/openid-connect/token$', 'body': {
            'access_token': '{SESSION}', 'expires_in': 300, 'token_type': 'Bearer'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/status$', 'times': 1, 'body': {
            'status': 'EXPIRED', 'orderStatus': 'NOT_INITIATED', 'expirationDate': '2026-01-01'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/status$', 'body': {
            'status': 'VALIDATED', 'orderStatus': 'NOT_INITIATED', 'expirationDate': '2027-01-01'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/start/domain/cname$', 'body': {
            'host': '_8f2e4c6a8b1d3f5e7a9c0b2d4f6e8a1c.{SENT:domain}.',
            'point': '1c3e5a7b9d0f2e4c6a8b1d3f5e7a9c0b.4d6f8a0c2e.sectigo.com.'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/start/domain/http$', 'body': {
            'url': 'http://{SENT:domain}/.well-known/pki-validation/8F2E4C6A8B1D3F5E7A9C.txt',
            'firstLine': '1c3e5a7b9d0f2e4c6a8b1d3f5e7a9c0b', 'secondLine': 'sectigo.com'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/submit/domain/txt$', 'body': {
            'host': '_dnsauth.{SENT:domain}.', 'point': '1c3e5a7b9d0f2e4c6a8b1d3f5e7a9c0b'}},
        {'method': 'POST', 'url': r'/api/dcv/v2/validation/submit/domain/', 'body': {
            'status': 'SUBMITTED', 'orderStatus': 'SUBMITTED'}},
        {'method': 'GET', 'url': r'/api/ssl/v2/\d+$', 'body': {
            'sslId': '{CFG:ssl_id}', 'status': 'Issued', 'commonName': '{NAME}',
            'subjectAlternativeNames': [], 'expires': '2027-01-01'}},
        {'method': 'POST', 'url': r'/api/ssl/v2/renewById/\d+$', 'body': {'sslId': 445566}},
        {'method': 'POST', 'url': r'/api/ssl/v2/replace/\d+$', 'body': ''},
        {'method': 'POST', 'url': r'/api/ssl/v2/enroll$', 'body': {'sslId': 445566,
                                                                   'renewId': '‹id›'}},
        {'method': 'GET', 'url': r'/api/ssl/v2/collect/\d+', 'headers': {
            'Content-Type': 'application/x-pem-file'}, 'body': '{CERT}{CHAIN}'}],
    # The SSL Store: an order bought before, reissued inside it; the CNAME DCV of the reissue
    'sslstore': [
        {'url': r'/order/info$', 'times': 1, 'body': {
            'AuthResponse': {'isError': False}, 'TheSSLStoreOrderID': '{CFG:order_id}',
            'CommonName': '{NAME}', 'DNSNames': '', 'OrderStatus': {'MajorStatus': 'Active'},
            'CertificateEndDateInUTC': '2027-01-01T00:00:00', 'OrderExpiryDateInUTC':
            '2028-01-01T00:00:00'}},
        {'url': r'/order/reissue$', 'body': {
            'AuthResponse': {'isError': False}, 'TheSSLStoreOrderID': '{CFG:order_id}',
            'OrderStatus': {'MajorStatus': 'Pending', 'DomainAuthVettingStatus': [
                {'domain': '{NAME}', 'dcvMethod': 'CNAME',
                 'DNSName': '_8F2E4C6A8B1D3F5E7A9C0B2D4F6E8A1C.{NAME}',
                 'DNSEntry': '1c3e5a7b9d0f2e4c6a8b1d3f5e7a9c0b.4d6f8a0c2e.sectigo.com'}]}}},
        {'url': r'/order/info$', 'body': {
            'AuthResponse': {'isError': False}, 'TheSSLStoreOrderID': '{CFG:order_id}',
            'CommonName': '{NAME}', 'OrderStatus': {'MajorStatus': 'Active'},
            'CertificateEndDateInUTC': '2027-02-11T00:00:00'}},
        {'url': r'/order/certificate/download$', 'body': {
            'AuthResponse': {'isError': False}, 'Certificates': [
                {'FileName': '{NAME}.crt', 'FileContent': '{CERT}'},
                {'FileName': 'Intermediate.crt', 'FileContent': '{CHAIN}'}]}}],
    'digicert': [
        {'method': 'GET', 'url': r'/order/certificate/\d+$', 'body': {
            'id': '{CFG:order_id}', 'status': 'issued', 'order_valid_till': '2028-01-01',
            'product': {'name_id': '{CFG:product}'},
            'certificate': {'id': 987654321, 'common_name': '{NAME}', 'dns_names': ['{NAME}'],
                            'valid_till': '2027-01-01'}}},
        {'method': 'POST', 'url': r'/order/certificate/\d+/reissue$', 'status': 201, 'body': {
            'id': '{CFG:order_id}', 'requests': [{'id': 7654321, 'status': 'pending'}]}},
        {'method': 'PUT', 'url': r'/dcv-random-value$', 'body': {
            'dcv_random_value': 'f3e9a1b2c4d5e6f708192a3b4c5d6e7f'}},
        {'method': 'GET', 'url': r'/domain\?include_validation', 'body': {'domains': [
            {'id': 1, 'name': '{ZONE}', 'is_active': True, 'validations': [
                {'type': 'ov', 'status': 'expired', 'validated_until': '2026-01-01'}],
             'dcv_expiration': {'ov': '2026-01-01'}}]}},
        {'method': 'PUT', 'url': r'/check-dcv$', 'body': {'order_status': 'issued',
                                                         'dcv_status': 'complete'}},
        {'method': 'GET', 'url': r'/download/format/pem_all$', 'headers': {
            'Content-Type': 'application/x-pem-file'}, 'body': '{CERT}{CHAIN}'}],
    # -- CAs of one's own: the request signed at once, the certificate in the answer --------
    'vault_pki': [
        {'method': 'POST', 'url': r'/v1/auth/[^/]+/login$', 'body': {'auth': {
            'client_token': '{SESSION}', 'lease_duration': 3600, 'renewable': True}}},
        {'method': 'POST', 'url': r'/sign/[^/]+$', 'body': {
            'request_id': '‹request›', 'lease_duration': 0, 'data': {
                'certificate': '{CERT}', 'issuing_ca': '{CHAIN}', 'ca_chain': ['{CHAIN}'],
                'serial_number': '{CERT_SERIAL}', 'expiration': 1798761600},
            'warnings': None}}],
    'ejbca': [
        {'method': 'POST', 'url': r'/v1/certificate/pkcs10enroll$', 'status': 201, 'body': {
            'certificate': '{CERT_B64}', 'serial_number': '{CERT_SERIAL}',
            'response_format': 'DER', 'certificate_chain': ['{CHAIN_B64}']}}],
    'est': [
        {'method': 'POST', 'url': r'/simple(re)?enroll$', 'headers': {
            'Content-Type': 'application/pkcs7-mime; smime-type=certs-only',
            'Content-Transfer-Encoding': 'base64'}, 'body': '{P7_B64}'},
        {'method': 'GET', 'url': r'/cacerts$', 'headers': {
            'Content-Type': 'application/pkcs7-mime', 'Content-Transfer-Encoding': 'base64'},
         'body': '{CA_P7_B64}'}],
    'freeipa': [
        {'method': 'POST', 'url': r'/ipa/session/login_password$', 'headers': {
            'Set-Cookie': 'ipa_session=MagBearerToken=PLANSESSION0token; path=/ipa; '
                          'httponly; secure;'}, 'body': ''},
        {'method': 'POST', 'url': r'/ipa/session/json$', 'body': {
            'result': {'result': {'certificate': '{CERT_B64}', 'certificate_chain': [
                '{CERT_B64}', '{CHAIN_B64}'], 'request_id': '42', 'serial_number': 4242,
                'subject': 'CN={NAME},O=EXAMPLE.COM'}, 'value': '', 'summary': None},
            'error': None, 'id': 0, 'principal': 'admin@EXAMPLE.COM', 'version': '4.12.2'}}],
    'step_ca': [
        {'method': 'GET', 'url': r'/1\.0/provisioners', 'body': {'provisioners': [
            {'type': 'JWK', 'name': '{CFG:provisioner}', 'key': {
                'kty': 'EC', 'crv': 'P-256', 'use': 'sig', 'kid': '‹key id›'}}],
            'nextCursor': ''}},
        {'method': 'POST', 'url': r'/1\.0/sign$', 'status': 201, 'body': {
            'crt': '{CERT}', 'ca': '{CHAIN}', 'certChain': ['{CERT}', '{CHAIN}']}}],
    'aws_pca': [
        {'sent': r'^\{"CertificateAuthorityArn": "[^"]*"\}$', 'body': {
            'CertificateAuthority': {'Arn': '{CFG:ca_arn}', 'Status': 'ACTIVE',
                                     'Type': 'SUBORDINATE', 'CertificateAuthorityConfiguration': {
                                         'KeyAlgorithm': 'EC_prime256v1',
                                         'SigningAlgorithm': 'SHA256WITHECDSA',
                                         'Subject': {'CommonName': 'Private Issuing CA'}}}}},
        {'sent': r'"Csr"', 'body': {'CertificateArn': '{CFG:ca_arn}/certificate/'
                                                      '‹certificate id›'}},
        {'sent': r'"CertificateArn"', 'times': 1, 'status': 400, 'body': {
            '__type': 'RequestInProgressException',
            'message': 'The request to issue the certificate is still in progress.'}},
        {'sent': r'"CertificateArn"', 'body': {'Certificate': '{CERT}',
                                               'CertificateChain': '{CHAIN}'}}],
    'google_cas': [
        {'method': 'POST', 'url': r'oauth2\.googleapis\.com/token$', 'body': {
            'access_token': '{SESSION}', 'expires_in': 3599, 'token_type': 'Bearer'}},
        {'method': 'POST', 'url': r'/certificates\?certificateId=', 'body': {
            'name': 'projects/{CFG:project}/locations/{CFG:location}/caPools/{CFG:pool}/'
                    'certificates/‹certificate id›',
            'pemCertificate': '{CERT}', 'pemCertificateChain': ['{CHAIN}'],
            'lifetime': '7776000s', 'issuerCertificateAuthority': 'projects/{CFG:project}/'
                                                                  'locations/{CFG:location}/'
                                                                  'caPools/{CFG:pool}/'
                                                                  'certificateAuthorities/ca-1'}}],
    'keyfactor_command': [
        {'method': 'POST', 'url': r'/Enrollment/CSR$', 'body': {'CertificateInformation': {
            'SerialNumber': '{CERT_SERIAL}', 'IssuerDN': 'CN=Plan Intermediate CA',
            'KeyfactorID': 4711, 'KeyfactorRequestId': 815, 'RequestDisposition': 'ISSUED',
            'DispositionMessage': 'The private key was successfully retained.',
            'Certificates': ['{CERT}', '{CHAIN}']}, 'Metadata': {}}}],
    'globalsign_atlas': [
        {'method': 'POST', 'url': r'/login$', 'body': {'access_token': '{SESSION}'}},
        {'method': 'POST', 'url': r'/certificates$', 'status': 201, 'headers': {
            'Location': 'https://emea.api.hvca.globalsign.com:8443/v2/certificates/'
                        '0123456789ABCDEF0123456789ABCDEF'}, 'body': ''},
        {'method': 'GET', 'url': r'/certificates/[0-9A-Fa-f]+$', 'times': 1, 'status': 202,
         'body': {'status': 'PENDING'}},
        {'method': 'GET', 'url': r'/certificates/[0-9A-Fa-f]+$', 'body': {
            'status': 'ISSUED', 'certificate': '{CERT}'}},
        {'method': 'GET', 'url': r'/trustchain$', 'body': ['{CHAIN}']}],
    'venafi_cloud': [
        {'method': 'GET', 'url': r'/applications/name/', 'body': {
            'id': '‹application id›', 'name': '{CFG:application}',
            'certificateIssuingTemplateAliasIdMap': {'{CFG:template}': '‹template id›'}}},
        {'method': 'POST', 'url': r'/certificaterequests$', 'status': 201, 'body': {
            'certificateRequests': [{'id': '3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'status': 'REQUESTED'}]}},
        {'method': 'GET', 'url': r'/certificaterequests/', 'times': 1, 'body': {
            'id': '3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'status': 'PENDING'}},
        {'method': 'GET', 'url': r'/certificaterequests/', 'body': {
            'id': '3f2504e0-4f89-11d3-9a0c-0305e82c3301', 'status': 'ISSUED',
            'certificateIds': ['6ba7b810-9dad-11d1-80b4-00c04fd430c8']}},
        {'method': 'GET', 'url': r'/contents\?', 'headers': {'Content-Type': 'text/plain'},
         'body': '{CERT}{CHAIN}'}],
    'venafi_tpp': [
        {'method': 'POST', 'url': r'/vedauth/authorize/oauth$', 'body': {
            'access_token': '{SESSION}', 'refresh_token': '{SESSION}', 'expires': 1893456000,
            'token_type': 'Bearer', 'scope': 'certificate:manage,revoke'}},
        {'method': 'POST', 'url': r'/vedsdk/certificates/request$', 'body': {
            'CertificateDN': '{CFG:zone}\\\\{NAME}', 'Guid': '{‹guid›}'}},
        {'method': 'POST', 'url': r'/vedsdk/certificates/renew$', 'body': {'Success': True}},
        {'method': 'POST', 'url': r'/vedsdk/certificates/retrieve$', 'times': 1, 'status': 202,
         'body': {'Stage': 500, 'Status': 'Post CSR'}},
        {'method': 'POST', 'url': r'/vedsdk/certificates/retrieve$', 'body': {
            'CertificateData': '{P7_B64}', 'Filename': '{NAME}.p7b', 'Format': 'Base64'}}],
    # Web Enrollment behind IIS Windows authentication: the first request refused (401,
    # NTLM offered), the NEGOTIATE answered with a CHALLENGE (a real one's shape: domain
    # EXAMPLE, a time), the AUTHENTICATE let in - on the one connection the module keeps
    'ms_adcs': [
        {'method': 'POST', 'url': r'/certfnsh\.asp$', 'times': 1, 'status': 401, 'headers': {
            'WWW-Authenticate': 'Negotiate, NTLM', 'Content-Type': 'text/html'},
         'body': '<html><body>401 - Unauthorized</body></html>'},
        {'method': 'POST', 'url': r'/certfnsh\.asp$', 'times': 1, 'status': 401, 'headers': {
            'WWW-Authenticate': 'NTLM TlRMTVNTUAACAAAADgAOADgAAAAVgoniASNFZ4mrze8AAAAAAAAAAJIAkgBGAAAACgBjRQAAAA9FAFgAQQBNAFAATABFAAIADgBFAFgAQQBNAFAATABFAAEACABDAEEAMAAxAAQAGgBlAHgAYQBtAHAAbABlAC4AbABvAGMAYQBsAAMAJABjAGEAMAAxAC4AZQB4AGEAbQBwAGwAZQAuAGwAbwBjAGEAbAAFABoAZQB4AGEAbQBwAGwAZQAuAGwAbwBjAGEAbAAHAAgAAADnP0oQ3AEAAAAA', 'Content-Type': 'text/html'}, 'body': ''},
        {'method': 'POST', 'url': r'/certfnsh\.asp$', 'headers': {'Content-Type': 'text/html'},
         'body': '<html><body><P ID=locInfo>The certificate you requested was issued to you.'
                 '</P><A Href="certnew.cer?ReqID=4711&amp;Enc=b64">Base 64 encoded</A>'
                 '</body></html>'},
        {'method': 'GET', 'url': r'/certnew\.cer\?ReqID=\d+&Enc=b64$', 'headers': {
            'Content-Type': 'application/pkix-cert'}, 'body': '{CERT}'},
        {'method': 'GET', 'url': r'/certnew\.p7b\?ReqID=\d+&Enc=b64$', 'headers': {
            'Content-Type': 'application/x-pkcs7-certificates'},
         'body': '-----BEGIN PKCS7-----\n{P7_B64}\n-----END PKCS7-----\n'}],
    # a SCEP server (RFC 8894): its capabilities, its CA certificate (DER), and a CertRep made
    # for the request sent - enveloped to the requester, signed by the CA (plansandbox.scep_reply)
    'scep': [
        {'method': 'GET', 'url': r'operation=GetCACaps', 'headers': {'Content-Type': 'text/plain'},
         'body': 'POSTPKIOperation\nSHA-256\nSHA-512\nAES\nSCEPStandard\nRenewal\n'},
        {'method': 'GET', 'url': r'operation=GetCACert', 'b64': True, 'headers': {
            'Content-Type': 'application/x-x509-ca-cert'}, 'body': '{CHAIN_B64}'},
        {'method': 'POST', 'url': r'operation=PKIOperation', 'scep': True, 'headers': {
            'Content-Type': 'application/x-pki-message'}, 'body': ''}],
    'cloudflare_origin_ca': [
        {'method': 'POST', 'url': r'/client/v4/certificates$', 'body': {
            'success': True, 'errors': [], 'messages': [], 'result': {
                'id': '‹certificate id›', 'certificate': '{CERT}',
                'hostnames': ['{NAME}'], 'request_type': 'origin-ecc',
                'requested_validity': 5475, 'expires_on': '2041-01-01 00:00:00 +0000 UTC'}}},
        {'method': 'GET', 'url': r'developers\.cloudflare\.com/ssl/static/', 'headers': {
            'Content-Type': 'application/x-pem-file'}, 'body': '{CHAIN}'}],
}

CHALLENGES = {
    # -- DNS providers: the zone of the name is on the account, the TXT record not there yet
    #    when it is put in, there (with its id) when it is taken away --------------------------
    'active24': [
        {'method': 'GET', 'url': r'/v1/user/self/service$', 'body': [
            {'id': 1001, 'name': '{ZONE}', 'serviceName': 'domain'}]},
        {'method': 'GET', 'url': r'/v2/service/\d+/dns/record\?', 'times': 1,
         'body': {'data': []}},
        {'method': 'GET', 'url': r'/v2/service/\d+/dns/record\?', 'body': {'data': [
            {'id': 2002, 'type': 'TXT', 'name': '{SEEN:filters%5Bname%5D=([^&]*)}',
             'content': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/v2/service/\d+/dns/record$', 'body': {'id': 2002}}],
    'akamai_edgedns': [
        {'method': 'GET', 'url': r'/config-dns/v2/zones\?', 'body': {'zones': [
            {'zone': '{ZONE}', 'type': 'PRIMARY'}]}},
        {'method': 'GET', 'url': r'/types/TXT$', 'times': 1, 'status': 404, 'body': {
            'title': 'Not Found', 'status': 404}},
        {'method': 'GET', 'url': r'/types/TXT$', 'body': {
            'name': '{FQDN}', 'type': 'TXT', 'ttl': 60, 'rdata': ['"{TXT}"']}},
        {'method': 'POST', 'url': r'/types/TXT$', 'status': 201, 'body': {
            'name': '{FQDN}', 'type': 'TXT', 'ttl': 60, 'rdata': ['"{TXT}"']}}],
    'alidns': [
        {'url': r'Action=DescribeDomains', 'body': {'RequestId': 'req-1', 'TotalCount': 1,
         'Domains': {'Domain': [{'DomainName': '{ZONE}', 'DomainId': 'dom-1'}]}}},
        {'url': r'Action=DescribeDomainRecords', 'times': 1, 'body': {
            'RequestId': 'req-2', 'TotalCount': 0, 'DomainRecords': {'Record': []}}},
        {'url': r'Action=DescribeDomainRecords', 'body': {
            'RequestId': 'req-3', 'TotalCount': 1, 'DomainRecords': {'Record': [
                {'RecordId': '3003', 'RR': '{SEEN:RRKeyWord=([^&]*)}', 'Type': 'TXT',
                 'Value': '{TXT}'}]}}},
        {'url': r'Action=AddDomainRecord', 'body': {'RequestId': 'req-4', 'RecordId': '3003'}},
        {'url': r'Action=DeleteDomainRecord', 'body': {'RequestId': 'req-5',
                                                        'RecordId': '3003'}}],
    'azure_dns': [
        {'method': 'POST', 'url': r'/oauth2/v2\.0/token$', 'body': {
            'token_type': 'Bearer', 'expires_in': 3599, 'access_token': '{SESSION}'}},
        {'method': 'GET', 'url': r'/providers/Microsoft\.Network/dnsZones\?', 'body': {'value': [
            {'id': '/subscriptions/{CFG:subscription_id}/resourceGroups/dns/providers/'
                   'Microsoft.Network/dnszones/{ZONE}', 'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/TXT/', 'times': 1, 'status': 404, 'body': {
            'error': {'code': 'NotFound', 'message': 'The resource record was not found.'}}},
        {'method': 'GET', 'url': r'/TXT/', 'body': {
            'etag': '‹etag›', 'properties': {'TTL': 60, 'TXTRecords': [
                {'value': ['{TXT}']}]}}},
        {'method': 'PUT', 'url': r'/TXT/', 'status': 201, 'body': {'etag': '‹etag›'}}],
    'bunny': [
        {'method': 'GET', 'url': r'/dnszone\?page=', 'body': {
            'Items': [{'Id': 4004, 'Domain': '{ZONE}'}], 'HasMoreItems': False}},
        {'method': 'GET', 'url': r'/dnszone/\d+$', 'times': 1, 'body': {
            'Id': 4004, 'Domain': '{ZONE}', 'Records': []}},
        {'method': 'GET', 'url': r'/dnszone/\d+$', 'body': {
            'Id': 4004, 'Domain': '{ZONE}', 'Records': [
                {'Id': 5005, 'Type': 3, 'Name': '{SEEN:"Name": "([^"]*)"}', 'Value': '{TXT}'}]}},
        {'method': 'PUT', 'url': r'/records$', 'status': 201, 'body': {'Id': 5005, 'Type': 3}}],
    'cloudflare': [
        {'method': 'GET', 'url': r'/zones\?name={ZONE}$', 'body': {
            'success': True, 'result': [{'id': ZID, 'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/zones\?name=', 'body': {'success': True, 'result': []}},
        {'method': 'GET', 'url': r'/dns_records\?', 'times': 1, 'body': {
            'success': True, 'result': []}},
        {'method': 'GET', 'url': r'/dns_records\?', 'body': {'success': True, 'result': [
            {'id': RID, 'type': 'TXT', 'name': '{FQDN}', 'content': '"{TXT}"'}]}},
        {'method': 'POST', 'url': r'/dns_records$', 'body': {'success': True, 'result': {
            'id': RID, 'type': 'TXT', 'name': '{FQDN}', 'content': '"{TXT}"'}}},
        {'method': 'DELETE', 'body': {'success': True, 'result': {'id': RID}}}],
    'cloudns': [
        {'url': r'/list-zones\.json$', 'body': [{'name': '{ZONE}', 'type': 'master',
                                                 'zone': 'domain', 'status': '1'}]},
        {'url': r'/records\.json$', 'times': 1, 'body': []},
        {'url': r'/records\.json$', 'body': {'6006': {
            'id': '6006', 'type': 'TXT', 'host': '{SEEN:host=([^&]*)}', 'record': '{TXT}',
            'ttl': '60'}}},
        {'url': r'/add-record\.json$', 'body': {'status': 'Success', 'statusDescription':
                                                'The record was added successfully.',
                                                'data': {'id': 6006}}},
        {'url': r'/delete-record\.json$', 'body': {'status': 'Success', 'statusDescription':
                                                   'The record was deleted successfully.'}}],
    'constellix': [
        {'method': 'GET', 'url': r'/v1/domains$', 'body': [{'id': 7007, 'name': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/records/txt$', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/records/txt$', 'body': [
            {'id': 8008, 'name': '{SEEN:"name": "([^"]*)"}', 'ttl': 60, 'roundRobin': [
                {'value': '"{TXT}"', 'disableFlag': False}]}]},
        {'method': 'POST', 'url': r'/records/txt$', 'body': [{'id': 8008, 'name': 'x'}]}],
    'czechia': [
        {'method': 'GET', 'url': r'/DNS/[^/]+$', 'times': 1, 'body': {'txtRecords': []}},
        {'method': 'GET', 'url': r'/DNS/[^/]+$', 'body': {'txtRecords': [
            {'hostName': '{SEEN:"hostName": "([^"]*)"}', 'text': '{TXT}', 'ttl': 3600}]}},
        {'method': 'POST', 'url': r'/TXT$', 'body': {'isError': False}},
        {'method': 'DELETE', 'url': r'/TXT$', 'body': {'isError': False}}],
    'desec': [
        {'method': 'GET', 'url': r'/domains/$', 'body': [{'name': '{ZONE}', 'minimum_ttl': 3600}]},
        {'method': 'GET', 'url': r'/domains/[^/]+/$', 'body': {'name': '{ZONE}',
                                                              'minimum_ttl': 3600}},
        {'method': 'GET', 'url': r'/rrsets/[^/]+/TXT/$', 'times': 1, 'status': 404, 'body': {
            'detail': 'Not found.'}},
        {'method': 'GET', 'url': r'/rrsets/[^/]+/TXT/$', 'body': {
            'subname': '{SEEN:/rrsets/([^/]+)/TXT/}', 'type': 'TXT', 'ttl': 3600,
            'records': ['"{TXT}"']}},
        {'method': 'PATCH', 'url': r'/rrsets/$', 'body': [{'type': 'TXT', 'ttl': 3600}]}],
    'digitalocean': [
        {'method': 'GET', 'url': r'/domains/{ZONE}$', 'body': {'domain': {'name': '{ZONE}',
                                                                         'ttl': 1800}}},
        {'method': 'GET', 'url': r'/domains/[^/?]+$', 'status': 404, 'body': {
            'id': 'not_found', 'message': 'The resource you requested could not be found.'}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': {'domain_record': {
            'id': 9009, 'type': 'TXT', 'name': '_acme-challenge', 'data': '{TXT}'}}}],
    'directadmin': [
        {'method': 'GET', 'url': r'/CMD_API_SHOW_DOMAINS', 'body': 'list[]={ZONE}'},
        {'method': 'GET', 'url': r'/CMD_API_DNS_CONTROL\?', 'times': 1,
         'body': 'A=www=192.0.2.10\nTXT=@=%22v%3Dspf1%20mx%20-all%22\n'},
        {'method': 'GET', 'url': r'/CMD_API_DNS_CONTROL\?', 'times': 2,
         'body': 'A=www=192.0.2.10\nTXT=@=%22v%3Dspf1%20mx%20-all%22&'
                 '{SEEN:name=([^&]+)&value=}=%22{TXT}%22\n'},
        {'method': 'GET', 'url': r'/CMD_API_DNS_CONTROL\?',
         'body': 'A=www=192.0.2.10\nTXT=@=%22v%3Dspf1%20mx%20-all%22\n'},
        {'method': 'POST', 'url': r'/CMD_API_DNS_CONTROL$', 'body': 'error=0&text=Records '
                                                                    'Updated&details='}],
    'dnsimple': [
        {'method': 'GET', 'url': r'/whoami$', 'body': {'data': {'user': None, 'account': {
            'id': 1010, 'email': 'dns@{ZONE}'}}}},
        {'method': 'GET', 'url': r'/zones\?per_page', 'body': {'data': [{'id': 1, 'name': '{ZONE}'}],
                                                             'pagination': {'total_pages': 1}}},
        {'method': 'GET', 'url': r'/records\?type=TXT', 'times': 1, 'body': {'data': []}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': {'data': {
            'id': 1111, 'type': 'TXT', 'content': '{TXT}'}}}],
    'dnsmadeeasy': [
        {'method': 'GET', 'url': r'/dns/managed/$', 'body': {'data': [{'id': 1212,
                                                                      'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/records\?', 'times': 1, 'body': {'data': []}},
        {'method': 'GET', 'url': r'/records\?', 'body': {'data': [
            {'id': 1313, 'type': 'TXT', 'name': '{SEEN:recordName=([^&]*)}',
             'value': '"{TXT}"'}]}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': {'id': 1313,
                                                                      'type': 'TXT'}}],
    'domeneshop': [
        {'method': 'GET', 'url': r'/domains$', 'body': [{'id': 1414, 'domain': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/dns\?', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/dns\?', 'body': [
            {'id': 1515, 'host': '{SEEN:host=([^&]*)}', 'type': 'TXT', 'data': '{TXT}'}]},
        {'method': 'POST', 'url': r'/dns$', 'status': 201, 'body': {'id': 1515}}],
    'dreamhost': [
        {'url': r'cmd=dns-list_records', 'times': 2, 'body': {'result': 'success', 'data': [
            {'zone': '{ZONE}', 'record': '{ZONE}', 'type': 'A', 'value': '192.0.2.10'}]}},
        {'url': r'cmd=dns-list_records', 'body': {'result': 'success', 'data': [
            {'zone': '{ZONE}', 'record': '{ZONE}', 'type': 'A', 'value': '192.0.2.10'},
            {'zone': '{ZONE}', 'record': '{FQDN}', 'type': 'TXT', 'value': '{TXT}'}]}},
        {'url': r'cmd=dns-(add|remove)_record', 'body': {'result': 'success',
                                                          'data': 'record_added'}}],
    'duckdns': [
        {'url': r'duckdns\.org/update\?', 'body': 'OK\n{TXT}\n\nUPDATED'}],
    'dynu': [
        {'method': 'GET', 'url': r'/dns$', 'body': {'domains': [{'id': 1616, 'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/record$', 'times': 1, 'body': {'dnsRecords': []}},
        {'method': 'GET', 'url': r'/record$', 'body': {'dnsRecords': [
            {'id': 1717, 'recordType': 'TXT', 'hostname': '{FQDN}', 'textData': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/record$', 'body': {'statusCode': 200, 'id': 1717}}],
    'easydns': [
        {'method': 'GET', 'url': r'/zones/records/all/', 'times': 1, 'body': {'data': [
            {'id': '1818', 'host': '@', 'type': 'A', 'rdata': '192.0.2.10'}]}},
        {'method': 'GET', 'url': r'/zones/records/all/', 'body': {'data': [
            {'id': '1818', 'host': '@', 'type': 'A', 'rdata': '192.0.2.10'},
            {'id': '1919', 'host': '{SEEN:"host": "([^"]*)"}', 'type': 'TXT',
             'rdata': '{TXT}'}]}},
        {'method': 'PUT', 'url': r'/zones/records/add/', 'status': 201, 'body': {
            'data': {'id': '1919'}}}],
    'efficientip': [
        {'method': 'GET', 'url': r'/dns/zone/list', 'body': [
            {'zone_id': '20', 'zone_name': '{ZONE}', 'zone_is_reverse': '0',
             'server_name': '{CFG:server}'}]},
        {'method': 'GET', 'url': r'/dns/rr/list', 'times': 1, 'status': 204, 'body': ''},
        {'method': 'GET', 'url': r'/dns/rr/list', 'body': [
            {'rr_id': '2121', 'rr_full_name': '{FQDN}', 'rr_type': 'TXT',
             'rr_value1': '{TXT}'}]},
        {'method': 'POST', 'url': r'/dns/rr/add', 'status': 201, 'body': [{'ret_oid': '2121',
                                                                          'rr_id': '2121'}]},
        {'method': 'DELETE', 'url': r'/dns/rr/delete', 'body': [{'ret_oid': '2121'}]}],
    'exoscale': [
        {'method': 'GET', 'url': r'/dns-domain$', 'body': {'dns-domains': [
            {'id': '‹domain id›', 'unicode-name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/record$', 'times': 1, 'body': {'dns-domain-records': []}},
        {'method': 'GET', 'url': r'/record$', 'body': {'dns-domain-records': [
            {'id': RID, 'type': 'TXT', 'name': '{SEEN:"name": "([^"]*)"}',
             'content': '"{TXT}"'}]}},
        {'method': 'POST', 'url': r'/record$', 'body': {'id': '‹operation›',
                                                        'state': 'success'}}],
    'forpsi': [
        {'method': 'GET', 'url': r'/domains\?skip', 'body': {'domains': [{'name': '{ZONE}'}],
                                                            'next_page': None}},
        {'method': 'GET', 'url': r'/records\?skip', 'times': 1, 'body': {'dnsrecords': [
            {'id': 2222, 'name': '@', 'type': 'A', 'data': '192.0.2.10'}]}},
        {'method': 'GET', 'url': r'/records\?skip', 'body': {'dnsrecords': [
            {'id': 2222, 'name': '@', 'type': 'A', 'data': '192.0.2.10'},
            {'id': 2323, 'name': '{SEEN:"name": "([^"]*)"}', 'type': 'TXT', 'data': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': {'id': 2323}}],
    'froxlor': [
        {'sent': r'"Domains\.listing"', 'body': {'data': {'count': 1, 'list': [
            {'id': 1, 'domain': '{ZONE}', 'parentdomainid': '0', 'isbinddomain': '1'}]}}},
        {'sent': r'"DomainZones\.listing"', 'times': 1, 'body': {'data': {'count': 1, 'list': [
            {'id': 2424, 'record': '@', 'type': 'A', 'content': '192.0.2.10'}]}}},
        {'sent': r'"DomainZones\.listing"', 'body': {'data': {'count': 2, 'list': [
            {'id': 2424, 'record': '@', 'type': 'A', 'content': '192.0.2.10'},
            {'id': 2525, 'record': '{SEEN:"record": "([^"]*)"}', 'type': 'TXT',
             'content': '"{TXT}"'}]}}},
        {'sent': r'"DomainZones\.(add|delete)"', 'body': {'data': {}}}],
    'gandi': [
        {'method': 'GET', 'url': r'/domains$', 'body': [{'fqdn': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/records/[^/]+/TXT$', 'times': 1, 'status': 404, 'body': {
            'code': 404, 'message': 'Not Found', 'object': 'HTTPNotFound', 'cause': 'Not Found'}},
        {'method': 'GET', 'url': r'/records/[^/]+/TXT$', 'body': {
            'rrset_name': '{SEEN:/records/([^/]+)/TXT}', 'rrset_type': 'TXT', 'rrset_ttl': 300,
            'rrset_values': ['"{TXT}"']}},
        {'method': 'POST', 'url': r'/TXT$', 'status': 201, 'body': {
            'message': 'DNS Record Created'}},
        {'method': 'PATCH', 'url': r'/TXT$', 'status': 201, 'body': {
            'message': 'DNS Record Created'}}],
    'gcore': [
        {'method': 'GET', 'url': r'/v2/zones\?', 'body': {'zones': [{'id': 2626,
                                                                     'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/TXT$', 'times': 1, 'status': 404, 'body': {
            'error': 'record is not found'}},
        {'method': 'GET', 'url': r'/TXT$', 'body': {'name': '{FQDN}', 'type': 'TXT', 'ttl': 60,
                                                   'resource_records': [
                                                       {'content': ['{TXT}'], 'enabled': True}]}},
        {'method': 'POST', 'url': r'/TXT$', 'body': {}}],
    'glesys': [
        {'url': r'/domain/list$', 'body': {'response': {'status': {'code': 200}, 'domains': [
            {'domainname': '{ZONE}'}]}}},
        {'url': r'/domain/listrecords$', 'times': 1, 'body': {'response': {
            'status': {'code': 200}, 'records': [
                {'recordid': 2727, 'host': '@', 'type': 'A', 'data': '192.0.2.10'}]}}},
        {'url': r'/domain/listrecords$', 'body': {'response': {
            'status': {'code': 200}, 'records': [
                {'recordid': 2727, 'host': '@', 'type': 'A', 'data': '192.0.2.10'},
                {'recordid': 2828, 'host': '{SEEN:"host": "([^"]*)"}', 'type': 'TXT',
                 'data': '{TXT}'}]}}},
        {'url': r'/domain/addrecord$', 'body': {'response': {
            'status': {'code': 200}, 'record': {'recordid': 2828}}}},
        {'url': r'/domain/deleterecord$', 'body': {'response': {'status': {'code': 200}}}}],
    'godaddy': [
        {'method': 'GET', 'url': r'/domain-names\?', 'body': {'items': [
            {'domain': '{ZONE}', 'status': 'ACTIVE'}], 'links': []}},
        {'method': 'GET', 'url': r'/domains\?statuses', 'body': [{'domain': '{ZONE}',
                                                                  'status': 'ACTIVE'}]},
        {'method': 'GET', 'url': r'/dns-records\?', 'times': 1, 'body': {'items': [],
                                                                        'links': []}},
        {'method': 'GET', 'url': r'/dns-records\?', 'body': {'items': [
            {'recordId': '‹record id›', 'type': 'TXT',
             'name': '{SEEN:[?&]name=([^&]*)}', 'data': '{TXT}'}], 'links': []}},
        {'method': 'POST', 'url': r'/dns-records$', 'status': 201, 'body': {
            'recordId': '‹record id›'}},
        {'method': 'GET', 'url': r'/records/TXT/', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/records/TXT/', 'body': [{'data': '{TXT}', 'ttl': 600}]}],
    'he_net': [
        {'method': 'POST', 'url': r'dyn\.dns\.he\.net/nic/update', 'body': 'good 127.0.0.1'}],
    'hestiacp': [
        {'sent': r'cmd=v-list-dns-domains', 'body': {'{ZONE}': {'IP': '192.0.2.10',
                                                               'SOA': 'ns1.{ZONE}'}}},
        {'sent': r'cmd=v-list-dns-records', 'times': 1, 'body': {'1': {
            'ID': '1', 'RECORD': '@', 'TYPE': 'A', 'VALUE': '192.0.2.10'}}},
        {'sent': r'cmd=v-list-dns-records', 'body': {'1': {
            'ID': '1', 'RECORD': '@', 'TYPE': 'A', 'VALUE': '192.0.2.10'}, '2': {
            'ID': '2', 'RECORD': '{SEEN:arg3=([^&]*)&arg4=TXT}', 'TYPE': 'TXT',
            'VALUE': '"{TXT}"'}}},
        {'sent': r'cmd=v-(add|delete)-dns-record', 'body': '0'}],
    'hetzner': [
        {'method': 'GET', 'url': r'/zones\?name={ZONE}$', 'body': {'zones': [
            {'id': 2929, 'name': '{ZONE}', 'mode': 'primary'}]}},
        {'method': 'GET', 'url': r'/zones\?name=', 'body': {'zones': []}},
        {'method': 'GET', 'url': r'/rrsets/[^/]+/TXT$', 'times': 1, 'status': 404, 'body': {
            'error': {'code': 'not_found', 'message': 'rrset not found'}}},
        {'method': 'GET', 'url': r'/rrsets/[^/]+/TXT$', 'body': {'rrset': {
            'name': '{SEEN:/rrsets/([^/]+)/TXT}', 'type': 'TXT', 'ttl': 60, 'records': [
                {'value': '"{TXT}"'}]}}},
        {'method': 'POST', 'url': r'/actions/(add|remove)_records$', 'status': 201, 'body': {
            'action': {'id': 3030, 'command': 'add_rrset_records', 'status': 'running'}}},
        {'method': 'GET', 'url': r'/zones/actions/\d+$', 'body': {'action': {
            'id': 3030, 'status': 'success'}}}],
    'hostingde': [
        {'sent': r'"value": "\*"', 'url': r'/zoneConfigsFind$', 'body': {
            'status': 'success', 'response': {'data': [{'id': ZID, 'name': '{ZONE}'}]}}},
        {'url': r'/zoneConfigsFind$', 'body': {'status': 'success', 'response': {'data': [
            {'id': ZID, 'name': '{ZONE}', 'type': 'NATIVE'}]}}},
        {'url': r'/recordsFind$', 'times': 1, 'body': {'status': 'success',
                                                       'response': {'data': []}}},
        {'url': r'/recordsFind$', 'body': {'status': 'success', 'response': {'data': [
            {'name': '{FQDN}', 'type': 'TXT', 'content': '"{TXT}"'}]}}},
        {'url': r'/zoneUpdate$', 'body': {'status': 'success', 'response': {}}}],
    'hostinger': [
        {'method': 'GET', 'url': r'/api/domains/v1/portfolio$', 'body': [
            {'id': 3131, 'domain': '{ZONE}', 'type': 'domain', 'status': 'active'}]},
        {'method': 'GET', 'url': r'/api/dns/v1/zones/[^/]+$', 'times': 1, 'body': [
            {'name': '@', 'type': 'A', 'ttl': 300, 'records': [{'content': '192.0.2.10'}]}]},
        {'method': 'GET', 'url': r'/api/dns/v1/zones/[^/]+$', 'body': [
            {'name': '@', 'type': 'A', 'ttl': 300, 'records': [{'content': '192.0.2.10'}]},
            {'name': '{SEEN:"name": "([^"]*)", "type": "TXT"}', 'type': 'TXT', 'ttl': 60,
             'records': [{'content': '{TXT}'}]}]},
        {'method': 'PUT', 'url': r'/api/dns/v1/zones/', 'body': {'message': 'Request accepted'}},
        {'method': 'DELETE', 'url': r'/api/dns/v1/zones/', 'body': {
            'message': 'Request accepted'}}],
    'huawei_dns': [
        {'method': 'GET', 'url': r'/v2/zones\?', 'body': {'zones': [
            {'id': '‹zone id›', 'name': '{ZONE}.', 'zone_type': 'public'}],
            'links': {}}},
        {'method': 'GET', 'url': r'/recordsets\?', 'times': 1, 'body': {'recordsets': []}},
        {'method': 'GET', 'url': r'/recordsets\?', 'body': {'recordsets': [
            {'id': '‹recordset id›', 'name': '{FQDN}.', 'type': 'TXT', 'ttl': 300,
             'records': ['"{TXT}"']}]}},
        {'method': 'POST', 'url': r'/recordsets$', 'status': 202, 'body': {
            'id': '‹recordset id›', 'status': 'PENDING_CREATE'}},
        {'method': 'DELETE', 'url': r'/recordsets/', 'status': 202, 'body': {
            'id': '‹recordset id›', 'status': 'PENDING_DELETE'}}],
    'infoblox': [
        {'method': 'GET', 'url': r'/zone_auth\?', 'body': [
            {'_ref': 'zone_auth/‹ref›:{ZONE}/default', 'fqdn': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/record:txt\?', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/record:txt\?', 'body': [
            {'_ref': 'record:txt/‹ref›:{FQDN}/default', 'name': '{FQDN}',
             'text': '{TXT}'}]},
        {'method': 'POST', 'url': r'/record:txt$', 'status': 201,
         'body': '"record:txt/‹ref›:{FQDN}/default"'}],
    'infomaniak': [
        {'method': 'GET', 'url': r'/2/zones/{ZONE}/exists$', 'body': {'result': 'success',
                                                                    'data': True}},
        {'method': 'GET', 'url': r'/exists$', 'body': {'result': 'success', 'data': False}},
        {'method': 'GET', 'url': r'/records\?', 'times': 1, 'body': {'result': 'success',
                                                                    'data': []}},
        {'method': 'GET', 'url': r'/records\?', 'body': {'result': 'success', 'data': [
            {'id': 3232, 'source': '{SEEN:"source": "([^"]*)"}', 'type': 'TXT',
             'target': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/records$', 'body': {'result': 'success', 'data': {
            'id': 3232}}},
        {'method': 'DELETE', 'url': r'/records/', 'body': {'result': 'success', 'data': True}}],
    'inwx': [
        {'sent': r'"account\.login"', 'headers': {
            'Set-Cookie': 'domrobot=PLANSESSION0token; path=/; secure; HttpOnly'},
         'body': {'code': 1000, 'msg': 'Command completed successfully', 'resData': {
             'tfa': '0'}}},
        {'sent': r'"nameserver\.list"', 'body': {'code': 1000, 'resData': {
            'count': 1, 'domains': [{'roId': 1, 'domain': '{ZONE}', 'type': 'MASTER'}]}}},
        {'sent': r'"nameserver\.info"', 'body': {'code': 1000, 'resData': {
            'domain': '{ZONE}', 'record': []}}},
        {'sent': r'"nameserver\.createRecord"', 'body': {'code': 1000, 'resData': {
            'id': 3333}}},
        {'sent': r'"nameserver\.deleteRecord"', 'body': {'code': 1000,
                                                         'msg': 'Command completed successfully'}}],
    'ionos': [
        {'method': 'GET', 'url': r'/zones$', 'body': [{'id': ZID, 'name': '{ZONE}',
                                                      'type': 'NATIVE'}]},
        {'method': 'GET', 'url': r'/zones/[^/?]+\?recordName', 'times': 1, 'body': {
            'id': ZID, 'name': '{ZONE}', 'records': []}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': [
            {'id': RID, 'name': '{FQDN}', 'type': 'TXT', 'content': '"{TXT}"'}]}],
    'ispconfig': [
        {'url': r'\?login$', 'body': {'code': 'ok', 'message': '', 'response': '{SESSION}'}},
        {'url': r'\?logout$', 'body': {'code': 'ok', 'message': '', 'response': True}},
        {'url': r'\?dns_zone_get$', 'sent': r'"primary_id": -1', 'body': {
            'code': 'ok', 'message': '', 'response': [{'id': '34', 'origin': '{ZONE}.'}]}},
        {'url': r'\?dns_zone_get$', 'body': {'code': 'ok', 'message': '', 'response': [
            {'id': '34', 'origin': '{ZONE}.', 'server_id': '1'}]}},
        {'url': r'\?dns_rr_get_all_by_zone$', 'times': 1, 'body': {
            'code': 'ok', 'message': '', 'response': [
                {'id': '3434', 'name': '{ZONE}.', 'type': 'A', 'data': '192.0.2.10'}]}},
        {'url': r'\?dns_rr_get_all_by_zone$', 'body': {'code': 'ok', 'message': '', 'response': [
            {'id': '3434', 'name': '{ZONE}.', 'type': 'A', 'data': '192.0.2.10'},
            {'id': '3535', 'name': '{FQDN}.', 'type': 'TXT', 'data': '{TXT}'}]}},
        {'url': r'\?dns_txt_add$', 'body': {'code': 'ok', 'message': '', 'response': '3535'}},
        {'url': r'\?dns_txt_delete$', 'body': {'code': 'ok', 'message': '', 'response': 1}}],
    'joker': [
        {'url': r'/request/login$', 'body': 'Auth-Sid: {SESSION}\nUID: ‹user id›\n'
                                           'Status-Code: 0\nStatus-Text: Command completed '
                                           'successfully\n\n{ZONE}\n'},
        {'url': r'/request/dns-zone-list$', 'body': 'Status-Code: 0\n\n{ZONE} 2027-01-01\n'},
        {'url': r'/request/dns-zone-get$', 'times': 1, 'body':
            'Status-Code: 0\n\n@ A 0 192.0.2.10 86400\nwww A 0 192.0.2.10 86400\n'},
        {'url': r'/request/dns-zone-get$', 'times': 2, 'body':
            'Status-Code: 0\n\n@ A 0 192.0.2.10 86400\nwww A 0 192.0.2.10 86400\n'
            '{SEEN:zone=[^&]*%0A([^+%]+)\\+TXT\\+0} TXT 0 "{TXT}" 300\n'},
        {'url': r'/request/dns-zone-get$', 'body':
            'Status-Code: 0\n\n@ A 0 192.0.2.10 86400\nwww A 0 192.0.2.10 86400\n'},
        {'url': r'/request/dns-zone-put$', 'body': 'Status-Code: 0\nStatus-Text: Command '
                                                   'completed successfully\n\n'}],
    'linode': [
        {'method': 'GET', 'url': r'/domains\?', 'body': {'data': [
            {'id': 3636, 'domain': '{ZONE}', 'type': 'master'}], 'page': 1, 'pages': 1}},
        {'method': 'GET', 'url': r'/records\?', 'times': 1, 'body': {'data': [], 'pages': 1}},
        {'method': 'POST', 'url': r'/records$', 'body': {'id': 3737, 'type': 'TXT',
                                                         'target': '{TXT}'}}],
    'loopia': [
        {'sent': r'<methodName>getDomains<', 'body': xmlrpc_answer([
            {'domain': '{ZONE}', 'paid': 1, 'registered': 1, 'renewal_status': 'NORMAL'}])},
        {'sent': r'<methodName>getZoneRecords<', 'times': 1, 'body': xmlrpc_answer([])},
        {'sent': r'<methodName>getZoneRecords<', 'times': 1, 'body': xmlrpc_answer([
            {'type': 'TXT', 'ttl': 300, 'priority': 0, 'rdata': '{TXT}', 'record_id': 3838}])},
        {'sent': r'<methodName>getZoneRecords<', 'body': xmlrpc_answer([])},
        {'sent': r'<methodName>(addSubdomain|addZoneRecord|removeZoneRecord|removeSubdomain)<',
         'body': xmlrpc_answer('OK')}],
    'mailinabox': [
        {'method': 'GET', 'url': r'/admin/dns/zones$', 'body': ['{ZONE}']},
        {'method': 'GET', 'url': r'/admin/dns/custom/[^/]+/TXT$', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/admin/dns/custom/[^/]+/TXT$', 'body': [
            {'qname': '{FQDN}', 'rtype': 'TXT', 'value': '{TXT}'}]},
        {'method': 'POST', 'url': r'/admin/dns/custom/', 'body': 'updated DNS: {ZONE}'},
        {'method': 'DELETE', 'url': r'/admin/dns/custom/', 'body': 'updated DNS: {ZONE}'}],
    'mythic_beasts': [
        {'method': 'POST', 'url': r'auth\.mythic-beasts\.com/login', 'body': {
            'access_token': '{SESSION}', 'token_type': 'bearer', 'expires_in': 300}},
        {'method': 'GET', 'url': r'/zones$', 'body': {'zones': ['{ZONE}']}},
        {'method': 'GET', 'url': r'/TXT$', 'times': 1, 'body': {'records': []}},
        {'method': 'GET', 'url': r'/TXT$', 'body': {'records': [
            {'host': '{SEEN:/records/([^/]+)/TXT}', 'type': 'TXT', 'ttl': 60,
             'data': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/TXT$', 'body': {'records_added': 1,
                                                     'message': '1 records added'}},
        {'method': 'DELETE', 'url': r'/TXT\?', 'body': {'records_removed': 1,
                                                        'message': '1 records removed'}}],
    'namecheap': [
        {'url': r'Command=namecheap\.domains\.getList', 'body': '<?xml version="1.0" encoding="utf-8"?>\n<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><Warnings /><RequestedCommand>namecheap.domains.getList</RequestedCommand><CommandResponse Type="namecheap.domains.getList"><DomainGetListResult><Domain ID="1" Name="{ZONE}" IsExpired="false" /></DomainGetListResult><Paging><TotalItems>1</TotalItems><CurrentPage>1</CurrentPage><PageSize>100</PageSize></Paging></CommandResponse><Server>PHX01APIEXT01</Server><ExecutionTime>0.1</ExecutionTime></ApiResponse>'},
        {'method': 'GET', 'url': r'Command=namecheap\.domains\.dns\.getHosts', 'times': 1,
         'body': '<?xml version="1.0" encoding="utf-8"?>\n<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><Warnings /><RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="{ZONE}" EmailType="MX" IsUsingOurDNS="true"><host HostId="1" Name="@" Type="A" Address="192.0.2.10" MXPref="10" TTL="1800" /><host HostId="2" Name="@" Type="MX" Address="mail.{ZONE}." MXPref="10" TTL="1800" /></DomainDNSGetHostsResult></CommandResponse><Server>PHX01APIEXT01</Server><ExecutionTime>0.1</ExecutionTime></ApiResponse>'},
        {'method': 'GET', 'url': r'Command=namecheap\.domains\.dns\.getHosts', 'body': '<?xml version="1.0" encoding="utf-8"?>\n<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><Warnings /><RequestedCommand>namecheap.domains.dns.getHosts</RequestedCommand><CommandResponse Type="namecheap.domains.dns.getHosts"><DomainDNSGetHostsResult Domain="{ZONE}" EmailType="MX" IsUsingOurDNS="true"><host HostId="1" Name="@" Type="A" Address="192.0.2.10" MXPref="10" TTL="1800" /><host HostId="2" Name="@" Type="MX" Address="mail.{ZONE}." MXPref="10" TTL="1800" /><host HostId="3" Name="{SEEN:HostName3=([^&]*)}" Type="TXT" Address="{TXT}" MXPref="10" TTL="60" /></DomainDNSGetHostsResult></CommandResponse><Server>PHX01APIEXT01</Server><ExecutionTime>0.1</ExecutionTime></ApiResponse>'},
        {'method': 'POST', 'body': '<?xml version="1.0" encoding="utf-8"?>\n<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response"><Errors /><Warnings /><RequestedCommand>namecheap.domains.dns.setHosts</RequestedCommand><CommandResponse Type="namecheap.domains.dns.setHosts"><DomainDNSSetHostsResult Domain="{ZONE}" IsSuccess="true" /></CommandResponse><Server>PHX01APIEXT01</Server><ExecutionTime>0.1</ExecutionTime></ApiResponse>'}],
    'namecom': [
        {'method': 'GET', 'url': r'/domains\?page', 'body': {'domains': [
            {'domainName': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/records\?page', 'times': 1, 'body': {'records': [
            {'id': 3939, 'host': '', 'fqdn': '{ZONE}.', 'type': 'A', 'answer': '192.0.2.10'}]}},
        {'method': 'GET', 'url': r'/records\?page', 'body': {'records': [
            {'id': 3939, 'host': '', 'fqdn': '{ZONE}.', 'type': 'A', 'answer': '192.0.2.10'},
            {'id': 4040, 'host': '{SEEN:"host": "([^"]*)"}', 'fqdn': '{FQDN}.', 'type': 'TXT',
             'answer': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/records$', 'body': {'id': 4040, 'type': 'TXT'}}],
    'namesilo': [
        {'url': r'/listDomains\?', 'body': {'request': {'operation': 'listDomains'}, 'reply': {
            'code': 300, 'detail': 'success', 'domains': {'domain': [{'domain': '{ZONE}'}]}}}},
        {'url': r'/dnsListRecords\?', 'times': 1, 'body': {'reply': {
            'code': 300, 'detail': 'success', 'resource_record': [
                {'record_id': '4141', 'type': 'A', 'host': '{ZONE}', 'value': '192.0.2.10'}]}}},
        {'url': r'/dnsListRecords\?', 'body': {'reply': {
            'code': 300, 'detail': 'success', 'resource_record': [
                {'record_id': '4141', 'type': 'A', 'host': '{ZONE}', 'value': '192.0.2.10'},
                {'record_id': '4242', 'type': 'TXT', 'host': '{FQDN}', 'value': '{TXT}'}]}}},
        {'url': r'/dnsAddRecord\?', 'body': {'reply': {'code': 300, 'detail': 'success',
                                                       'record_id': '4242'}}},
        {'url': r'/dnsDeleteRecord\?', 'body': {'reply': {'code': 300, 'detail': 'success'}}}],
    'netcup': [
        {'sent': r'"action": "login"', 'body': {'status': 'success', 'statuscode': 2000,
                                                'responsedata': {'apisessionid': '{SESSION}'}}},
        {'sent': r'"action": "infoDnsZone".*"domainname": "{ZONE}"', 'body': {
            'status': 'success', 'statuscode': 2000, 'responsedata': {
                'name': '{ZONE}', 'ttl': '86400', 'dnssecstatus': False}}},
        {'sent': r'"action": "infoDnsZone"', 'body': {
            'status': 'error', 'statuscode': 5029, 'shortmessage': 'Can not get DNS zone.',
            'longmessage': 'The DNS zone does not exist.'}},
        {'sent': r'"action": "infoDnsRecords"', 'times': 1, 'body': {
            'status': 'success', 'statuscode': 2000, 'responsedata': {'dnsrecords': [
                {'id': '4343', 'hostname': '@', 'type': 'A', 'destination': '192.0.2.10'}]}}},
        {'sent': r'"action": "infoDnsRecords"', 'body': {
            'status': 'success', 'statuscode': 2000, 'responsedata': {'dnsrecords': [
                {'id': '4343', 'hostname': '@', 'type': 'A', 'destination': '192.0.2.10'},
                {'id': '4444', 'hostname': '{SEEN:"hostname": "(_acme-challenge[^"]*)"}',
                 'type': 'TXT', 'destination': '{TXT}'}]}}},
        {'sent': r'"action": "updateDnsRecords"', 'body': {
            'status': 'success', 'statuscode': 2000, 'responsedata': {'dnsrecords': []}}}],
    'netim': [
        {'method': 'POST', 'url': r'/session/$', 'body': {'access_token': '{SESSION}'}},
        {'method': 'DELETE', 'url': r'/session/$', 'body': {}},
        {'method': 'GET', 'url': r'/domains/\*$', 'body': [{'domain': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/zone/$', 'times': 1, 'body': [
            {'hostname': '@', 'type': 'A', 'value': '192.0.2.10'}]},
        {'method': 'GET', 'url': r'/zone/$', 'body': [
            {'hostname': '@', 'type': 'A', 'value': '192.0.2.10'},
            {'hostname': '{FQDN}', 'type': 'TXT', 'value': '{TXT}'}]},
        {'method': 'POST', 'url': r'/zone/$', 'body': {'ID_OPE': 4545, 'STATUS': 'Pending'}},
        {'method': 'DELETE', 'url': r'/zone/$', 'body': {'ID_OPE': 4646, 'STATUS': 'Pending'}},
        {'method': 'GET', 'url': r'/operation/\d+$', 'body': {'ID_OPE': 4545, 'STATUS': 'Done'}}],
    'netlify': [
        {'method': 'GET', 'url': r'/dns_zones$', 'body': [{'id': '‹zone id›',
                                                          'name': '{ZONE}'}]},
        {'method': 'GET', 'url': r'/dns_records$', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/dns_records$', 'body': [
            {'id': RID, 'hostname': '{FQDN}', 'type': 'TXT', 'value': '{TXT}'}]},
        {'method': 'POST', 'url': r'/dns_records$', 'status': 201, 'body': {
            'id': RID, 'hostname': '{FQDN}', 'type': 'TXT', 'value': '{TXT}'}}],
    'njalla': [
        {'sent': r'"method": "list-domains"', 'body': {'result': {'domains': [
            {'name': '{ZONE}', 'status': 'active'}]}}},
        {'sent': r'"method": "list-records"', 'times': 1, 'body': {'result': {'records': []}}},
        {'sent': r'"method": "list-records"', 'body': {'result': {'records': [
            {'id': 4747, 'name': '{SEEN:"name": "(_acme-challenge[^"]*)"}', 'type': 'TXT',
             'content': '{TXT}'}]}}},
        {'sent': r'"method": "add-record"', 'body': {'result': {'id': 4747, 'type': 'TXT'}}},
        {'sent': r'"method": "remove-record"', 'body': {'result': {}}}],
    'ns1': [
        {'method': 'GET', 'url': r'/zones$', 'body': [{'zone': '{ZONE}', 'id': ZID}]},
        {'method': 'GET', 'url': r'/TXT$', 'times': 1, 'status': 404, 'body': {
            'message': 'record not found'}},
        {'method': 'GET', 'url': r'/TXT$', 'body': {'domain': '{FQDN}', 'type': 'TXT', 'ttl': 60,
                                                   'answers': [{'answer': ['{TXT}']}]}},
        {'method': 'PUT', 'url': r'/TXT$', 'body': {'domain': '{FQDN}', 'type': 'TXT'}}],
    'oci_dns': [
        {'method': 'GET', 'url': r'/zones\?compartmentId', 'body': [
            {'id': 'ocid1.dns-zone.oc1..‹zone›', 'name': '{ZONE}',
             'zoneType': 'PRIMARY'}]},
        {'method': 'GET', 'url': r'\?rtype=TXT$', 'times': 1, 'body': {'items': []}},
        {'method': 'GET', 'url': r'\?rtype=TXT$', 'body': {'items': [
            {'domain': '{FQDN}', 'rtype': 'TXT', 'rdata': '"{TXT}"', 'ttl': 30,
             'recordHash': '‹hash›'}]}},
        {'method': 'PATCH', 'url': r'/TXT$', 'body': {'items': []}}],
    'openprovider': [
        {'method': 'POST', 'url': r'/v1beta/auth/login$', 'body': {'code': 0, 'desc': '',
                                                                   'data': {'token': '{SESSION}',
                                                                            'reseller_id': 1}}},
        {'method': 'GET', 'url': r'/v1beta/dns/zones\?', 'body': {'code': 0, 'data': {
            'results': [{'id': 4848, 'name': '{ZONE}', 'is_deleted': False}], 'total': 1}}},
        {'method': 'GET', 'url': r'/records\?', 'times': 1, 'body': {'code': 0, 'data': {
            'results': [], 'total': 0}}},
        {'method': 'GET', 'url': r'/records\?', 'body': {'code': 0, 'data': {'results': [
            {'name': '{FQDN}', 'type': 'TXT', 'value': '"{TXT}"', 'ttl': 60}], 'total': 1}}},
        {'method': 'PUT', 'url': r'/v1beta/dns/zones/', 'body': {'code': 0, 'data': {
            'success': True}}}],
    'ovh': [
        {'method': 'GET', 'url': r'/auth/time$', 'body': 1767225600},
        {'method': 'GET', 'url': r'/domain/zone$', 'body': ['{ZONE}']},
        {'method': 'POST', 'url': r'/record$', 'body': {'id': 4949, 'fieldType': 'TXT',
                                                        'target': '"{TXT}"', 'zone': '{ZONE}'}},
        {'method': 'POST', 'url': r'/refresh$', 'body': None}],
    'porkbun': [
        {'url': r'/domain/listAll$', 'body': {'status': 'SUCCESS', 'domains': [
            {'domain': '{ZONE}', 'status': 'ACTIVE'}]}},
        {'url': r'/dns/retrieveByNameType/', 'times': 1, 'body': {'status': 'SUCCESS',
                                                                  'records': []}},
        {'url': r'/dns/retrieveByNameType/', 'body': {'status': 'SUCCESS', 'records': [
            {'id': '5050', 'name': '{FQDN}', 'type': 'TXT', 'content': '{TXT}'}]}},
        {'url': r'/dns/create/', 'body': {'status': 'SUCCESS', 'id': 5050}},
        {'url': r'/dns/delete/', 'body': {'status': 'SUCCESS'}}],
    'plesk': [
        {'sent': r'<site>\s*<get>', 'body': '<?xml version="1.0" encoding="UTF-8"?>\n<packet version="1.6.9.1"><site><get><result><status>ok</status><filter-id>{ZONE}</filter-id><id>1</id><data><gen_info><name>{ZONE}</name><ascii-name>{ZONE}</ascii-name></gen_info></data></result></get></site></packet>'},
        {'sent': r'<get_rec>', 'times': 1, 'body': '<?xml version="1.0" encoding="UTF-8"?>\n<packet version="1.6.9.1"><dns><get_rec><result><status>ok</status><id>11</id><data><site-id>1</site-id><type>A</type><host>{ZONE}.</host><value>192.0.2.10</value></data></result></get_rec></dns></packet>'},
        {'sent': r'<get_rec>', 'body': '<?xml version="1.0" encoding="UTF-8"?>\n<packet version="1.6.9.1"><dns><get_rec><result><status>ok</status><id>11</id><data><site-id>1</site-id><type>A</type><host>{ZONE}.</host><value>192.0.2.10</value></data></result><result><status>ok</status><id>12</id><data><site-id>1</site-id><type>TXT</type><host>{FQDN}.</host><value>{TXT}</value></data></result></get_rec></dns></packet>'},
        {'sent': r'<add_rec>', 'body': '<?xml version="1.0" encoding="UTF-8"?>\n<packet version="1.6.9.1"><dns><add_rec><result><status>ok</status><id>12</id></result></add_rec></dns></packet>'},
        {'sent': r'<del_rec>', 'body': '<?xml version="1.0" encoding="UTF-8"?>\n<packet version="1.6.9.1"><dns><del_rec><result><status>ok</status><id>12</id></result></del_rec></dns></packet>'}],
    'powerdns': [
        {'method': 'GET', 'url': r'/servers/[^/]+/zones$', 'body': [
            {'id': '{ZONE}.', 'name': '{ZONE}.', 'kind': 'Native'}]},
        {'method': 'GET', 'url': r'/servers/[^/]+$', 'body': {
            'type': 'Server', 'id': 'localhost', 'daemon_type': 'authoritative',
            'version': '4.9.4'}},
        {'method': 'GET', 'url': r'/zones/[^?]+\?rrsets=true', 'times': 1, 'body': {
            'id': '{ZONE}.', 'name': '{ZONE}.', 'rrsets': []}},
        {'method': 'GET', 'url': r'/zones/[^?]+\?rrsets=true', 'body': {
            'id': '{ZONE}.', 'name': '{ZONE}.', 'rrsets': [
                {'name': '{FQDN}.', 'type': 'TXT', 'ttl': 60, 'records': [
                    {'content': '"{TXT}"', 'disabled': False}]}]}},
        {'method': 'PATCH', 'url': r'/zones/', 'status': 204, 'body': ''}],
    'rackspace': [
        {'method': 'POST', 'url': r'/v2\.0/tokens$', 'body': {'access': {
            'token': {'id': '{SESSION}', 'expires': '2030-01-01T00:00:00.000Z'},
            'serviceCatalog': [{'name': 'cloudDNS', 'type': 'rax:dns', 'endpoints': [
                {'publicURL': 'https://dns.api.rackspacecloud.com/v1.0/‹account›'}]}]}}},
        {'method': 'GET', 'url': r'/domains\?limit', 'body': {'domains': [
            {'id': 5151, 'name': '{ZONE}'}], 'totalEntries': 1}},
        {'method': 'GET', 'url': r'/records\?', 'times': 1, 'body': {'records': []}},
        {'method': 'GET', 'url': r'/records\?', 'body': {'records': [
            {'id': 'TXT-5252', 'name': '{FQDN}', 'type': 'TXT', 'data': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/records$', 'status': 202, 'body': {
            'status': 'RUNNING', 'jobId': '‹job›',
            'callbackUrl': 'https://dns.api.rackspacecloud.com/v1.0/‹account›/status/'
                           '‹job›'}},
        {'method': 'DELETE', 'url': r'/records/', 'status': 202, 'body': {
            'status': 'RUNNING', 'jobId': '‹job›',
            'callbackUrl': 'https://dns.api.rackspacecloud.com/v1.0/‹account›/status/'
                           '‹job›'}},
        {'method': 'GET', 'url': r'/status/', 'body': {'status': 'COMPLETED', 'response': {
            'records': [{'id': 'TXT-5252', 'name': '{FQDN}', 'type': 'TXT'}]}}}],
    'gcloud_dns': [
        {'method': 'POST', 'url': r'oauth2\.googleapis\.com/token$', 'body': {
            'access_token': '{SESSION}', 'expires_in': 3599, 'token_type': 'Bearer'}},
        {'method': 'GET', 'url': r'/managedZones$', 'body': {'managedZones': [
            {'name': 'zone-1', 'dnsName': '{ZONE}.', 'visibility': 'public'}]}},
        {'method': 'GET', 'url': r'/rrsets\?', 'times': 1, 'body': {'rrsets': []}},
        {'method': 'GET', 'url': r'/rrsets\?', 'body': {'rrsets': [
            {'name': '{FQDN}.', 'type': 'TXT', 'ttl': 60, 'rrdatas': ['"{TXT}"']}]}},
        {'method': 'POST', 'url': r'/changes$', 'body': {'kind': 'dns#change', 'id': '5',
                                                         'status': 'done'}}],
    'route53': [
        {'method': 'GET', 'url': r'/hostedzonesbyname\?dnsname={ZONE}&', 'body': R53 % (
            'ListHostedZonesByNameResponse', '<HostedZones><HostedZone><Id>/hostedzone/'
            'Z0123456789ABCDEFGHIJ</Id><Name>{ZONE}.</Name><CallerReference>acme</CallerReference>'
            '<Config><PrivateZone>false</PrivateZone></Config><ResourceRecordSetCount>8'
            '</ResourceRecordSetCount></HostedZone></HostedZones><IsTruncated>false</IsTruncated>'
            '<MaxItems>10</MaxItems>', 'ListHostedZonesByNameResponse')},
        {'method': 'GET', 'url': r'/hostedzonesbyname\?', 'body': R53 % (
            'ListHostedZonesByNameResponse', '<HostedZones/><IsTruncated>false</IsTruncated>'
            '<MaxItems>10</MaxItems>', 'ListHostedZonesByNameResponse')},
        {'method': 'GET', 'url': r'/rrset\?name=', 'times': 1, 'body': R53 % (
            'ListResourceRecordSetsResponse', '<ResourceRecordSets/><IsTruncated>false'
            '</IsTruncated><MaxItems>1</MaxItems>', 'ListResourceRecordSetsResponse')},
        {'method': 'GET', 'url': r'/rrset\?name=', 'body': R53 % (
            'ListResourceRecordSetsResponse', '<ResourceRecordSets><ResourceRecordSet><Name>'
            '{FQDN}.</Name><Type>TXT</Type><TTL>60</TTL><ResourceRecords><ResourceRecord><Value>'
            '"{TXT}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet>'
            '</ResourceRecordSets><IsTruncated>false</IsTruncated><MaxItems>1</MaxItems>',
            'ListResourceRecordSetsResponse')},
        {'method': 'POST', 'url': r'/rrset$', 'body': R53 % (
            'ChangeResourceRecordSetsResponse', '<ChangeInfo><Id>/change/C0123456789ABCDEFGH'
            '</Id><Status>PENDING</Status><SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt>'
            '</ChangeInfo>', 'ChangeResourceRecordSetsResponse')},
        {'method': 'GET', 'url': r'/change/', 'body': R53 % (
            'GetChangeResponse', '<ChangeInfo><Id>/change/C0123456789ABCDEFGH</Id><Status>INSYNC'
            '</Status><SubmittedAt>2026-01-01T00:00:00.000Z</SubmittedAt></ChangeInfo>',
            'GetChangeResponse')}],
    'scaleway': [
        {'method': 'GET', 'url': r'/dns-zones\?page=', 'body': {'dns_zones': [
            {'domain': '{ZONE}', 'subdomain': '', 'status': 'active'}], 'total_count': 1}},
        {'method': 'GET', 'url': r'/records\?name=', 'times': 1, 'body': {'records': [],
                                                                        'total_count': 0}},
        {'method': 'GET', 'url': r'/records\?name=', 'body': {'records': [
            {'id': RID, 'name': '{SEEN:records[?]name=([^&]*)}', 'type': 'TXT',
             'data': '"{TXT}"', 'ttl': 60}], 'total_count': 1}},
        {'method': 'PATCH', 'url': r'/records$', 'body': {'records': []}}],
    'simply': [
        {'method': 'GET', 'url': r'/my/products/$', 'body': {'products': [
            {'object': 'S123456', 'domain': {'name': '{ZONE}', 'name_idn': '{ZONE}'}}]}},
        {'method': 'GET', 'url': r'/dns/records/$', 'times': 1, 'body': {'records': [
            {'record_id': 5353, 'name': '@', 'type': 'A', 'data': '192.0.2.10'}]}},
        {'method': 'GET', 'url': r'/dns/records/$', 'body': {'records': [
            {'record_id': 5353, 'name': '@', 'type': 'A', 'data': '192.0.2.10'},
            {'record_id': 5454, 'name': '{SEEN:"name": "([^"]*)"}', 'type': 'TXT',
             'data': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/dns/records/$', 'body': {'record': {'id': 5454},
                                                              'status': 200}}],
    'subreg': [
        {'sent': r'<ns1:Login>', 'body': php_soap('Login', {'status': 'ok', 'data': {
            'ssid': '{SESSION}'}})},
        {'sent': r'<ns1:Domains_List>', 'body': php_soap('Domains_List', {
            'status': 'ok', 'data': {'count': '1', 'domains': [
                {'name': '{ZONE}', 'expire': '2027-01-01', 'autorenew': '1'}]}})},
        {'sent': r'<ns1:Get_DNS_Zone>', 'times': 1, 'body': php_soap('Get_DNS_Zone', {
            'status': 'ok', 'data': {'domain': '{ZONE}', 'records': [
                {'id': '5555', 'name': '', 'type': 'A', 'content': '192.0.2.10'}]}})},
        {'sent': r'<ns1:Get_DNS_Zone>', 'body': php_soap('Get_DNS_Zone', {
            'status': 'ok', 'data': {'domain': '{ZONE}', 'records': [
                {'id': '5555', 'name': '', 'type': 'A', 'content': '192.0.2.10'},
                {'id': '5656', 'name': '{SEEN:<name>(_acme-challenge[^<]*)</name>}',
                 'type': 'TXT', 'content': '{TXT}'}]}})},
        {'sent': r'<ns1:Add_DNS_Record>', 'body': php_soap('Add_DNS_Record', {
            'status': 'ok', 'data': {'record_id': '5656'}})},
        {'sent': r'<ns1:Delete_DNS_Record>', 'body': php_soap('Delete_DNS_Record', {
            'status': 'ok', 'data': {}})}],
    'technitium': [
        {'url': r'/api/zones/list$', 'body': {'status': 'ok', 'response': {'zones': [
            {'name': '{ZONE}', 'type': 'Primary', 'disabled': False}]}}},
        {'url': r'/api/zones/records/get$', 'times': 1, 'body': {'status': 'ok', 'response': {
            'zone': {'name': '{ZONE}', 'type': 'Primary'}, 'records': []}}},
        {'url': r'/api/zones/records/get$', 'body': {'status': 'ok', 'response': {
            'zone': {'name': '{ZONE}', 'type': 'Primary'}, 'records': [
                {'name': '{FQDN}', 'type': 'TXT', 'ttl': 60, 'rData': {'text': '{TXT}'}}]}}},
        {'url': r'/api/zones/records/(add|delete)$', 'body': {'status': 'ok', 'response': {}}}],
    'tencentcloud': [
        {'sent': r'"Offset"', 'body': {'Response': {
            'DomainCountInfo': {'AllTotal': 1}, 'DomainList': [
                {'DomainId': 5757, 'Name': '{ZONE}', 'Status': 'ENABLE'}],
            'RequestId': '‹request›'}}},
        {'sent': r'"Subdomain"', 'times': 1, 'body': {'Response': {
            'Error': {'Code': 'ResourceNotFound.NoDataOfRecord',
                      'Message': 'The record list is empty.'},
            'RequestId': '‹request›'}}},
        {'sent': r'"Subdomain"', 'body': {'Response': {'RecordList': [
            {'RecordId': 5858, 'Name': '{SEEN:"SubDomain": "([^"]*)"}', 'Type': 'TXT',
             'Value': '{TXT}'}], 'RequestId': '‹request›'}}},
        {'sent': r'"SubDomain"', 'body': {'Response': {'RecordId': 5858,
                                                       'RequestId': '‹request›'}}},
        {'sent': r'"RecordId"', 'body': {'Response': {'RequestId': '‹request›'}}}],
    'transip': [
        {'method': 'POST', 'url': r'/v6/auth$', 'status': 201, 'body': {'token': '{SESSION}'}},
        {'method': 'GET', 'url': r'/v6/domains$', 'body': {'domains': [
            {'name': '{ZONE}', 'authCode': None, 'isTransferLocked': False}]}},
        {'method': 'GET', 'url': r'/dns$', 'times': 1, 'body': {'dnsEntries': [
            {'name': '@', 'expire': 86400, 'type': 'A', 'content': '192.0.2.10'}]}},
        {'method': 'GET', 'url': r'/dns$', 'body': {'dnsEntries': [
            {'name': '@', 'expire': 86400, 'type': 'A', 'content': '192.0.2.10'},
            {'name': '{SEEN:"name": "(_acme-challenge[^"]*)"}', 'expire': 60, 'type': 'TXT',
             'content': '{TXT}'}]}},
        {'method': 'POST', 'url': r'/dns$', 'status': 201, 'body': ''},
        {'method': 'DELETE', 'url': r'/dns$', 'status': 204, 'body': ''}],
    'ultradns': [
        {'method': 'POST', 'url': r'/v1/authorization/token$', 'body': {
            'tokenType': 'Bearer', 'accessToken': '{SESSION}', 'expiresIn': '3600'}},
        {'method': 'GET', 'url': r'/v3/zones\?', 'body': {'zones': [
            {'properties': {'name': '{ZONE}.', 'type': 'PRIMARY'}}], 'cursorInfo': {}}},
        {'method': 'GET', 'url': r'/rrsets/TXT/', 'times': 1, 'status': 404, 'body': [
            {'errorCode': 70002, 'errorMessage': 'Data not found.'}]},
        {'method': 'GET', 'url': r'/rrsets/TXT/', 'body': {'rrSets': [
            {'ownerName': '{FQDN}.', 'rrtype': 'TXT (16)', 'ttl': 60, 'rdata': ['{TXT}']}]}},
        {'method': 'POST', 'url': r'/rrsets/TXT/', 'status': 201, 'body': {
            'message': 'Successful'}}],
    'vercel': [
        {'method': 'GET', 'url': r'/v5/domains', 'body': {'domains': [
            {'name': '{ZONE}', 'serviceType': 'zeit.world'}], 'pagination': {'next': None}}},
        {'method': 'GET', 'url': r'/records', 'times': 1, 'body': {'records': [],
                                                                  'pagination': {}}},
        {'method': 'GET', 'url': r'/records', 'body': {'records': [
            {'id': 'rec_‹id›', 'name': '{SEEN:"name": "(_acme-challenge[^"]*)"}',
             'type': 'TXT', 'value': '{TXT}'}], 'pagination': {}}},
        {'method': 'POST', 'url': r'/records', 'body': {'uid': 'rec_‹id›'}}],
    'virtualmin': [
        {'sent': r'program=list-domains', 'body': '{ZONE}\nExit status: 0\n'},
        {'sent': r'program=get-dns', 'times': 1, 'body':
            '{ZONE}. TXT "v=spf1 a mx -all"\nExit status: 0\n'},
        {'sent': r'program=get-dns', 'times': 2, 'body':
            '{ZONE}. TXT "v=spf1 a mx -all"\n{FQDN}. TXT "{TXT}"\nExit status: 0\n'},
        {'sent': r'program=get-dns', 'body': '{ZONE}. TXT "v=spf1 a mx -all"\nExit status: 0\n'},
        {'sent': r'program=modify-dns', 'body': 'Updating DNS records ..\n.. done\n\n'
                                                'Exit status: 0\n'}],
    'vultr': [
        {'method': 'GET', 'url': r'/domains\?per_page', 'body': {'domains': [
            {'domain': '{ZONE}', 'dns_sec': 'disabled'}], 'meta': {'total': 1, 'links': {
                'next': '', 'prev': ''}}}},
        {'method': 'GET', 'url': r'/records\?per_page', 'times': 1, 'body': {
            'records': [], 'meta': {'total': 0, 'links': {'next': ''}}}},
        {'method': 'POST', 'url': r'/records$', 'status': 201, 'body': {'record': {
            'id': '‹record id›', 'type': 'TXT', 'data': '"{TXT}"'}}}],
    'webglobe': [
        {'method': 'POST', 'url': r'/auth/login$', 'body': {'success': True, 'data': {
            'token': '{SESSION}', 'expires_in': 3600}}},
        {'method': 'GET', 'url': r'/domains\?per_page', 'body': {'success': True, 'data': [
            {'domain': '{ZONE}', 'domain_id': 1001}]}},
        {'method': 'GET', 'url': r'/\d+/dns$', 'times': 1, 'body': {'success': True, 'data': {
            'records': [{'id': 6060, 'name': '@', 'type': 'A', 'data': '192.0.2.10'}],
            'soa': {'primary': 'ns1.{ZONE}'}}}},
        {'method': 'GET', 'url': r'/\d+/dns$', 'body': {'success': True, 'data': {
            'records': [{'id': 6060, 'name': '@', 'type': 'A', 'data': '192.0.2.10'},
                        {'id': 6161, 'name': '{FQDN}', 'type': 'TXT', 'data': '{TXT}'}],
            'soa': {'primary': 'ns1.{ZONE}'}}}},
        {'method': 'POST', 'url': r'/\d+/dns$', 'body': {'success': True, 'new_id': 6161}},
        {'method': 'DELETE', 'url': r'/\d+/dns/\d+$', 'body': {'success': True}}],
    'websupport': [
        {'method': 'GET', 'url': r'/v1/user/self/zone$', 'body': {'items': [
            {'id': 6262, 'name': '{ZONE}'}]}},
        {'method': 'GET', 'url': r'/record$', 'times': 1, 'body': {'items': [
            {'id': 6363, 'type': 'A', 'name': '@', 'content': '192.0.2.10'}]}},
        {'method': 'POST', 'url': r'/record$', 'body': {'status': 'success', 'item': {
            'id': 6464, 'type': 'TXT', 'content': '{TXT}'}}}],
    'wedos': [
        {'sent': r'dns-domains-list', 'body': {'response': {'code': 1000, 'result': 'OK',
                                                           'data': {'domain': [
                                                               {'name': '{ZONE}',
                                                                'type': 'primary',
                                                                'status': 'active'}],
                                                               'total': 1}}}},
        {'sent': r'dns-rows-list', 'times': 1, 'body': {'response': {
            'code': 1000, 'result': 'OK', 'data': {'row': []}}}},
        {'sent': r'dns-rows-list', 'body': {'response': {'code': 1000, 'result': 'OK', 'data': {
            'row': [{'ID': '6565', 'name': '{SEEN:%22name%22%3A[+]%22(_acme-challenge[^%]*)%22}',
                     'ttl': '300', 'rdtype': 'TXT', 'rdata': '{TXT}'}]}}}},
        {'sent': r'dns-(row-add|row-delete|domain-commit)', 'body': {'response': {
            'code': 1000, 'result': 'OK', 'data': {}}}}],
    'cpanel': [
        {'url': r'/execute/DomainInfo/list_domains', 'body': {'result': {
            'status': 1, 'errors': None, 'data': {'main_domain': '{ZONE}', 'addon_domains': [],
                                                  'parked_domains': [], 'sub_domains': []}}}},
        {'url': r'/execute/DNS/parse_zone\?zone={ZONE}$', 'times': 2, 'body': {'result': {
            'status': 1, 'errors': None, 'data': [
                {'type': 'record', 'line_index': 3, 'record_type': 'SOA', 'dname_b64': '{ZONE_B64}',
                 'data_b64': ['bnMxLmV4YW1wbGUuY29tLg==', 'aG9zdG1hc3Rlci5leGFtcGxlLmNvbS4=',
                              'MjAyNjAxMDEwMQ==', 'ODY0MDA=', 'NzIwMA==', 'MzYwMDAwMA==',
                              'ODY0MDA=']}]}}},
        {'url': r'/execute/DNS/parse_zone\?zone={ZONE}$', 'times': 1, 'body': {'result': {
            'status': 1, 'errors': None, 'data': [
                {'type': 'record', 'line_index': 3, 'record_type': 'SOA', 'dname_b64': '{ZONE_B64}',
                 'data_b64': ['bnMxLmV4YW1wbGUuY29tLg==', 'aG9zdG1hc3Rlci5leGFtcGxlLmNvbS4=',
                              'MjAyNjAxMDEwMg==', 'ODY0MDA=', 'NzIwMA==', 'MzYwMDAwMA==',
                              'ODY0MDA=']},
                {'type': 'record', 'line_index': 21, 'record_type': 'TXT', 'ttl': 60,
                 'dname_b64': '{FQDN_B64}', 'data_b64': ['{TXT_B64}']}]}}},
        {'url': r'/execute/DNS/parse_zone\?', 'body': {'result': {
            'status': 0, 'errors': ['The zone does not exist.'], 'data': None}}},
        {'url': r'/execute/DNS/mass_edit_zone', 'body': {'result': {
            'status': 1, 'errors': None, 'data': {'new_serial': '2026010103'}}}}],
    'http_ssh': HTTP01,
    'http_ftp': HTTP01,
    'http_s3': HTTP01 + [{'method': 'PUT', 'headers': {'ETag': '"\u2039etag\u203a"'},
                          'body': ''}, {'method': 'DELETE', 'status': 204, 'body': ''}],
    'http_azure_blob': HTTP01 + [{'method': 'PUT', 'status': 201, 'body': ''},
                                 {'method': 'DELETE', 'status': 202, 'body': ''}],
    # the folders are there already: MKCOL is refused (405), the file is made (201)
    'http_webdav': HTTP01 + [{'method': 'MKCOL', 'status': 405, 'body': ''},
                             {'method': 'PUT', 'status': 201, 'body': ''},
                             {'method': 'DELETE', 'status': 204, 'body': ''}],
    'acme_dns': [
        {'method': 'POST', 'url': r'/update$', 'body': {'txt': '{TXT}'}}],
}


# What the commands of a validation over SSH print (plansandbox.Answers.ssh rules): nsupdate,
# the DnsServer cmdlets, mkdir / rm print nothing when they do it - the shell says exit 0.
SSH_CHALLENGES = {
    'ssh_dns': [{'command': r'nsupdate( |$)', 'stdout': ''},
                {'command': r'(?i)powershell', 'stdout': ''}],
    'windows_dns': [{'command': r'(?i)powershell', 'stdout': ''}],
    'http_ssh': [{'command': r'^(sudo -n )?(mkdir -p|rm -f) ', 'stdout': ''}],
}


def ssh_answers(family, kind, version=''):
    table = SSH_CHALLENGES if family == 'challenge' else {}
    return [dict(r) for r in (table.get('%s@%s' % (kind, version), []) if version else []) +
            table.get(kind, [])]


# Settings a source checks the CA it reaches against (a pinned fingerprint): in the recording
# they are those of the stand-in CA that answers, in the shape the user wrote them
PINNED = {'scep': ['ca_fingerprint']}


# a record taken away: done, nothing to say (204) - after the module's own rules
GONE = [{'method': 'DELETE', 'status': 204, 'body': ''}]


def answers(family, kind, version=''):
    table = SOURCES if family == 'issuer' else CHALLENGES if family == 'challenge' else {}
    own = (table.get('%s@%s' % (kind, version), []) if version else []) + table.get(kind, [])
    if family == 'challenge' and own:
        own = own + GONE
    return [dict(r) for r in own]
