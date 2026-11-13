# -*- coding: utf-8 -*-
"""
What happens: the run plan of a certificate (1.0.20) - everything a renewal
of it would do, step by step, worked out without doing any of it.

    plan(store, cert, deploys, full=False) -> {cert, head, phases, made}

Phases, in the order a renewal goes:

    key         the key (new, kept, or the CSR sent in) and the request
    source      where it comes from: the ACME protocol in order (written here),
                an own authority (written here), any other source as its module's
                own issue() was recorded
    validation  per name, the module's present() / ready() / cleanup() recorded
    deploy      per deployment, the target's deploy() recorded (what is served: the tests)
    after       who is told, when it comes again, what only the first time does

How a module is recorded (plansandbox.py): its own code is run in a process of
its own that can reach nothing - no socket, no program but openssl, no file
outside its temporary folder, no sleep - against a Context that answers every
call (an HTTP 200 with {}, an SSH command that printed nothing) and writes
each down. It never sees a secret: each secret setting is handed as a
stand-in, masked again on the way out; the certificate is a stand-in of the
same names and key type made there for the run. The answers it had to make
up are marked: what the device answers decides there.

A step: {kind, words, detail?, branch?, note?, invented?, secret?}
    kind     call | connect | file | command | dns | wait | check | key | sign |
             mail | delete | save | info | stop | read
    detail   {method, url, headers, body} | {command, input} |
             {path, mode, owner, size, format, body?} | {record} | {text} |
             {files: [...]} | {pairs: [[label, value]]}
"""
from __future__ import annotations

import base64
import difflib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

from acmelib import engine as E
from acmelib.plugins import base
from acmelib.certs import store as S

RUN_S = 8                       # each module's recording at most
ALL_S = 75                      # the whole recording at most
NAMES_MOST = 8                  # names whose validation is recorded one by one
DOTS = '••••'
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# What the sandbox puts where the CA's answer goes (plansandbox.TOKEN, TXT, KEYAUTH).
SHOWN = (('PLAN-TOKEN-from-the-CA-0000000000.PLANthumbprintOfTheAccountKey00000000000000',
          '‹key authorization: token.thumbprint›'),
         ('PLANTXTvalueComputedFromTheToken0000000000a',
          '‹value computed at the time from the token›'),
         ('PLAN-TOKEN-from-the-CA-0000000000', '‹token from the CA›'),
         ('PLANSESSION0token', '‹session›'))

# Second runs: what a device answers once the certificate is there already.
LATER = {
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/[^/?]+$',
         'body': {'errorcode': 0, 'sslcertkey': [{'certkey': '{TAIL}', 'cert': 'earlier.crt',
                                                  'linkcertkeyname': ''}]}},
        {'method': 'GET', 'url': r'/nitro/v1/config/systemfile\?',
         'body': {'errorcode': 0, 'systemfile': []}},
    ],
}
# (a header takes no placeholder: the session in one is written as plansandbox.SESSION is)
# a Redfish sign-in: the session's token and address are headers of its answer
_REDFISH_SESSION = {
    'method': 'POST', 'url': r'/SessionService/Sessions/?$', 'status': 201, 'body': {},
    'headers': {'Content-Type': 'application/json', 'X-Auth-Token': 'PLANSESSION0token',
                'Location': '/redfish/v1/SessionService/Sessions/\u2039session\u203a/'}}
# a sign-in to vCenter's Automation API (/api/session): the session is a JSON string
_VSPHERE_SESSION = {'method': 'POST', 'url': r'/api/session$', 'status': 201,
                    'body': '"PLANSESSION0token"'}
# What a module needs answered to go on at all (a sign-in's token where it looks for it, a
# zone or domain found) - made up, as every answer of the recording is.
ANSWERS = {
    'f5': [{'method': 'POST', 'url': r'/authn/login', 'body': {'token': {'token': '{SESSION}'}}}],
    'webglobe': [{'method': 'GET', 'url': r'/domains/[^/?]+$',
                  'body': {'success': True, 'data': {'domain': '{TAIL}', 'domain_id': '1001'}}},
                 {'method': 'GET', 'url': r'/\d+/dns$', 'body': {'success': True, 'data': {
                     'records': [], 'soa': {}}}},
                 {'method': 'POST', 'url': r'/\d+/dns$', 'body': {'success': True, 'data': {
                     'id': '\u2039record id\u203a'}}}],
    'cloudflare': [{'method': 'GET', 'url': r'/zones\?name=', 'body': {
        'success': True, 'result': [{'id': '\u2039zone id\u203a', 'name': '{TAIL}'}]}},
        {'method': 'POST', 'url': r'/dns_records$', 'body': {'success': True, 'result': {
            'id': '\u2039record id\u203a'}}},
        {'body': {'success': True, 'result': []}}],
    'synology': [{'url': r'auth', 'body': {'success': True, 'data': {
        'sid': '{SESSION}', 'synotoken': '{SESSION}'}}},
        {'body': {'success': True, 'data': {}}}],
    'cloudflare_ssl': [{'method': 'GET', 'url': r'/zones\?name=', 'body': {
        'success': True, 'result': [{'id': '\u2039zone id\u203a', 'name': 'zone'}]}},
        {'body': {'success': True, 'result': []}}],
    'aws_acm': [{'method': 'POST', 'body': {
        'CertificateArn': 'arn:aws:acm:\u2039region\u203a:\u2039account\u203a:certificate/'
                          '\u2039new\u203a'}}],
    # Suite Lifecycle: the Locker without the certificate before the import, with it (the
    # alias the import sent) after; Replace Certificate a request that completes
    'aria_lifecycle': [
        {'method': 'GET', 'url': r'/lcm/locker/api/v2/certificates$', 'times': 1, 'body': []},
        {'method': 'GET', 'url': r'/lcm/locker/api/v2/certificates$', 'body': [
            {'alias': '{SENT:alias}', 'vmid': '\u2039certificate vmid\u203a'}]},
        {'method': 'PUT', 'url': r'/products/[^/]+/certificates/[^/]+$', 'body': {
            'requestId': '\u2039request\u203a'}},
        {'method': 'GET', 'url': r'/lcm/request/api/v2/requests/', 'body': {
            'state': 'COMPLETED'}}],
    # Catalyst Center: the token is "Token" of the sign-in; the import is a task, done
    'cisco_catalyst_center': [
        {'method': 'POST', 'url': r'/auth/token$', 'body': {'Token': '{SESSION}'}},
        {'method': 'POST', 'url': r'/dna/intent/api/v1/certificate', 'status': 202, 'body': {
            'response': {'taskId': '\u2039task\u203a'}, 'version': '1.0'}},
        {'method': 'GET', 'url': r'/dna/intent/api/v1/task/', 'body': {'response': {
            'isError': False, 'progress': 'done', 'endTime': 1}}}],
    # the FMC: the token and the domain are headers of the sign-in; the devices to enrol on
    # and the decryption policies are those named
    'cisco_fmc': [
        {'method': 'POST', 'url': r'/generatetoken$', 'status': 204, 'body': '',
         'headers': {'X-auth-access-token': 'PLANSESSION0token',
                     'DOMAIN_UUID': '\u2039domain\u203a'}},
        {'method': 'POST', 'url': r'/object/(certenrollments|internalcertificates)$',
         'status': 201, 'body': {'id': '\u2039new object\u203a'}},
        {'method': 'GET', 'url': r'/devices/devicerecords\?', 'body': {'items': [
            {'id': '\u2039device\u203a', 'name': '{EACH:OPT:enroll_devices}'}]}},
        {'method': 'GET', 'url': r'/policy/decryptionpolicies\?', 'body': {'items': [
            {'id': '\u2039policy\u203a', 'name': '{EACH:OPT:decryption_policy}'},
            {'id': '\u2039policy\u203a', 'name': '{EACH:OPT:decryption_policies}'}]}}],
    # the IMC answers every call of its XML API at /nuova: a session cookie, no error
    'cisco_imc': [{'method': 'POST', 'url': r'/nuova$', 'headers': {'Content-Type': 'text/xml'},
                   'body': '<aaaLogin response="yes" outCookie="PLANSESSION0token" '
                           'outRefreshPeriod="600" errorCode="0"/>'}],
    # ClearPass: the server named is one of the cluster's
    'aruba_clearpass': [
        {'method': 'POST', 'url': r'/api/oauth$', 'body': {
            'access_token': '{SESSION}', 'token_type': 'Bearer', 'expires_in': 28800}},
        {'method': 'GET', 'url': r'/api/cluster/server$', 'body': {'_embedded': {'items': [
            {'server_uuid': '\u2039server uuid\u203a', 'name': '{CFG:server}'}]}}}],
    # ESXi through vCenter's VI JSON API: its session manager, the session a header of the
    # sign-in, the host's certificate manager; the Automation API's session
    'esxi': [
        {'method': 'GET', 'url': r'/ServiceInstance/ServiceInstance/content$', 'body': {
            'sessionManager': {'type': 'SessionManager', 'value': 'SessionManager'}}},
        {'method': 'POST', 'url': r'/SessionManager/[^/]+/Login$', 'body': {},
         'headers': {'Content-Type': 'application/json',
                     'vmware-api-session-id': 'PLANSESSION0token'}},
        {'method': 'GET', 'url': r'/HostSystem/[^/]+/configManager$', 'body': {
            'certificateManager': {'type': 'HostCertificateManager',
                                   'value': '\u2039certificate manager\u203a'}}},
        _VSPHERE_SESSION],
    # vCenter, the Supervisor: the Automation API's session (as above)
    'vcenter': [_VSPHERE_SESSION],
    'vsphere_supervisor': [_VSPHERE_SESSION],
    # FortiManager: every JSON-RPC call is at /jsonrpc - its first, "is it there?", answered
    # -3 (Object does not exist), the others status 0 (OK)
    'fortimanager': [
        {'method': 'POST', 'url': r'/jsonrpc$', 'times': 1, 'body': {
            'id': 1, 'result': [{'status': {'code': -3, 'message': 'Object does not exist'}}]}},
        {'method': 'POST', 'url': r'/jsonrpc$', 'body': {
            'id': 1, 'result': [{'status': {'code': 0, 'message': 'OK'}, 'data': {}}]}}],
    # NimbleOS: the token and its id in "data" of the sign-in
    'hpe_nimble': [{'method': 'POST', 'url': r'/v1/tokens$', 'status': 201, 'body': {
        'data': {'session_token': '{SESSION}', 'id': '\u2039token id\u203a'}}}],
    # OneView: its API version (that of OneView 9.00), the sessionID, the CA not in the trust
    # store yet, the tasks of the calls completed
    'hpe_oneview': [
        {'method': 'GET', 'url': r'/rest/version$', 'body': {
            'currentVersion': 6600, 'minimumVersion': 120}},
        {'method': 'POST', 'url': r'/rest/login-sessions$', 'body': {'sessionID': '{SESSION}'}},
        {'method': 'GET', 'url': r'/rest/certificates/ca/', 'status': 404, 'body': {
            'errorCode': 'RESOURCE_NOT_FOUND'}},
        {'method': 'POST', 'url': r'/rest/certificates/ca$', 'status': 202, 'body': {
            'uri': '/rest/tasks/\u2039task\u203a'}},
        {'method': 'PUT', 'url': r'/rest/certificates/https/pkcs12', 'status': 202, 'body': {
            'uri': '/rest/tasks/\u2039task\u203a'}},
        {'method': 'GET', 'url': r'/rest/tasks/', 'body': {'taskState': 'Completed'}}],
    # NIOS: uploadinit gives the token and the address the file goes to
    'infoblox': [{'method': 'POST', 'url': r'/fileop\?_function=uploadinit$', 'body': {
        'token': '\u2039upload token\u203a',
        'url': 'https://\u2039grid master\u203a/http_direct_file_io/req_id-UPLOAD-'
               '\u2039id\u203a/acme.pem'}}],
    # the iRMC answers SCCI (POST /config) in XML: status 0, no error
    'irmc': [{'method': 'POST', 'url': r'/config$', 'headers': {'Content-Type': 'text/xml'},
              'body': '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><Status>'
                      '<Value>0</Value><Severity>Information</Severity><Message>No Error'
                      '</Message></Status>'}],
    # ONTAP: the SVM named is there; the certificate asked for by its name is not there
    # before the install, then listed (by the name the install sent)
    'netapp_ontap': [
        {'method': 'GET', 'url': r'/api/svm/svms\?', 'body': {'records': [
            {'uuid': '\u2039svm uuid\u203a', 'name': '{OPT:svm}'}], 'num_records': 1}},
        {'method': 'GET', 'url': r'/api/security/certificates\?.*&name=', 'times': 1,
         'body': {'records': [], 'num_records': 0}},
        {'method': 'GET', 'url': r'/api/security/certificates\?', 'body': {'records': [
            {'uuid': '\u2039certificate uuid\u203a', 'name': '{SENT:name}', 'type': 'server'}],
            'num_records': 1}}],
    # NSX: the id of the certificate imported, its validation OK
    'nsx_manager': [
        {'method': 'POST', 'url': r'/certificates\?action=import$', 'status': 201, 'body': {
            'results': [{'id': '\u2039certificate id\u203a'}], 'result_count': 1}},
        {'method': 'GET', 'url': r'\?action=validate', 'body': {'status': 'OK'}}],
    # Prism Central: the cluster named is one of its clusters, its certificate read with an
    # ETag, the replacement a task that succeeds
    'nutanix': [
        {'method': 'GET', 'url': r'/config/clusters$', 'body': {'data': [
            {'extId': '\u2039cluster id\u203a', 'name': '{CFG:cluster}'}]}},
        {'method': 'GET', 'url': r'/ssl-certificate$', 'body': {'data': {}},
         'headers': {'Content-Type': 'application/json', 'ETag': '\u2039etag\u203a'}},
        {'method': 'PUT', 'url': r'/ssl-certificate$', 'status': 202, 'body': {
            'data': {'extId': '\u2039task\u203a'}}},
        {'method': 'GET', 'url': r'/config/tasks/', 'body': {'data': {'status': 'SUCCEEDED'}}}],
    # OneFS: the id of the certificate imported
    'powerscale': [{'method': 'POST', 'url': r'/platform/\d+/certificate/server$',
                    'status': 201, 'body': {'id': '\u2039certificate id\u203a'}}],
    # PowerStore: the session is the DELL-EMC-TOKEN header and the cookie of the sign-in; the
    # id of the certificate imported
    'powerstore': [
        {'method': 'GET', 'url': r'/api/rest/login_session$',
         'body': [{'id': '\u2039session\u203a'}],
         'headers': {'Content-Type': 'application/json', 'DELL-EMC-TOKEN': 'PLANSESSION0token',
                     'Set-Cookie': 'auth_cookie=PLANSESSION0token; Path=/; Secure; HttpOnly'}},
        {'method': 'POST', 'url': r'/api/rest/x509_certificate$', 'status': 201, 'body': {
            'id': '\u2039certificate id\u203a'}}],
    # Purity: the REST API versions it speaks (the newest 2.x is used), the session the
    # x-auth-token header of the sign-in, the certificate to replace there
    'pure_flasharray': [
        {'method': 'GET', 'url': r'/api/api_version$', 'body': {
            'version': ['1.19', '2.\u2039n\u203a']}},
        {'method': 'POST', 'url': r'/login$', 'body': {'items': [{}]},
         'headers': {'Content-Type': 'application/json', 'x-auth-token': 'PLANSESSION0token'}},
        {'method': 'GET', 'url': r'/certificates\?names=', 'body': {'items': [
            {'name': '{OPT:cert_name}', 'certificate': ''}]}}],
    # Redfish (and the BMCs signed in to by it): the session's token and address are headers
    # of the sign-in, so it is signed out of
    'redfish': [_REDFISH_SESSION],
    'supermicro_bmc': [_REDFISH_SESSION],
    'huawei_ibmc': [_REDFISH_SESSION],
    # an iLO's one manager says it is an iLO (its firmware not said: the recording goes on)
    'redfish@ilo': [
        {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
            {'@odata.id': '/redfish/v1/Managers/1/'}]}},
        {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
            'Model': 'iLO 6', 'Manufacturer': 'HPE'}}],
    # an iDRAC's manager is iDRAC.Embedded.1 (its firmware not said: the recording goes on)
    'redfish@6.00.02': [
        {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
            {'@odata.id': '/redfish/v1/Managers/iDRAC.Embedded.1'}]}},
        {'method': 'GET', 'url': r'/Managers/iDRAC\.Embedded\.1$', 'body': {
            'Manufacturer': 'Dell Inc.'}}],
    # SDDC Manager: the token is accessToken of the sign-in
    'sddc_manager': [{'method': 'POST', 'url': r'/v1/tokens$', 'body': {
        'accessToken': '{SESSION}', 'refreshToken': {'id': '\u2039refresh token\u203a'}}}],
    # Unisphere says its REST API version (that of Unisphere 10.0, the oldest acme takes)
    'unisphere_powermax': [{'method': 'GET', 'url': r'/univmax/restapi/version$', 'body': {
        'version': 'V10.0.0.0', 'api_version': '100', 'supported_api_versions': ['100']}}],
    # Cloud Director: the token is a header of the sign-in; the library gives the id of the
    # item imported; its cells (those named, else one), the endpoints' change a task that
    # succeeds
    'vcd': [
        {'method': 'POST', 'url': r'/sessions/provider$', 'body': {},
         'headers': {'Content-Type': 'application/json',
                     'X-VMWARE-VCLOUD-ACCESS-TOKEN': 'PLANSESSION0token'}},
        {'method': 'POST', 'url': r'/ssl/certificateLibrary$', 'status': 201, 'body': {
            'id': 'urn:vcloud:certificateLibraryItem:\u2039new\u203a'}},
        {'method': 'GET', 'url': r'/cells\?', 'body': {'values': [
            {'id': 'urn:vcloud:cell:\u2039cell\u203a', 'name': '\u2039cell\u203a'},
            {'id': 'urn:vcloud:cell:\u2039cell\u203a', 'name': '{EACH:OPT:cells}'}],
            'pageCount': 1}},
        {'method': 'PUT', 'url': r'/cells/[^/]+(/accessEndpoints)?$', 'status': 202, 'body': '',
         'headers': {'Location': '/api/task/\u2039task\u203a'}},
        {'method': 'GET', 'url': r'/api/task/', 'body': {'status': 'success'}}],
    # Site Recovery / vSphere Replication: session_id of the sign-in
    'vmware_dr': [{'method': 'POST', 'url': r'/session$', 'body': {'session_id': '{SESSION}'}}],
}
# a FlashBlade answers as a FlashArray
ANSWERS['pure_flashblade'] = ANSWERS['pure_flasharray']
# What an SSH command prints where a module reads it (plansandbox.Answers.ssh): {command (a
# regex), input? (a regex of what is typed in), stdout, stderr?, exit?, times?} - else nothing
SSH_ANSWERS = {
    # IOS XE: the trustpoint imported holds its certificate; write memory says [OK]
    'cisco_iosxe': [
        {'command': r'^show crypto pki certificates ',
         'stdout': 'Certificate\n  Status: Available\n'},
        {'command': r'^write memory', 'stdout': 'Building configuration...\n[OK]\n'}],
    # Unity: svc_custom_cert says it installed the files
    'unity': [{'command': r'^svc_custom_cert ',
               'stdout': 'Successfully installed custom certificate files.\n'}],
}
# a Catalyst 9800 is an IOS XE
SSH_ANSWERS['cisco_wlc9800'] = SSH_ANSWERS['cisco_iosxe']
# Lenovo XCC: the device makes the key - its CertificateService, the HTTPS collection, the CSR
# it answers GenerateCSR with ({CSR}: the sandbox's own for the names, plansandbox.Answers)
ANSWERS['lenovo_xcc'] = [
    _REDFISH_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/?$', 'body': {
        'RedfishVersion': '1.22.0', 'CertificateService': {
            '@odata.id': '/redfish/v1/CertificateService'},
        'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}}}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {
        'Members': [{'@odata.id': '/redfish/v1/Managers/1'}]}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
        'Manufacturer': 'Lenovo', 'Model': 'XClarity Controller',
        'NetworkProtocol': {'@odata.id': '/redfish/v1/Managers/1/NetworkProtocol'}}},
    {'method': 'GET', 'url': r'/redfish/v1/CertificateService/?$', 'body': {'Actions': {
        '#CertificateService.GenerateCSR': {
            'target': '/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR'},
        '#CertificateService.ReplaceCertificate': {
            'target': '/redfish/v1/CertificateService/Actions/'
                      'CertificateService.ReplaceCertificate'}}}},
    {'method': 'GET', 'url': r'/HTTPS/Certificates/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1'}]}},
    {'method': 'POST', 'url': r'GenerateCSR$', 'body': {'CSRString': '{CSR}'}},
]
# HPE Synergy Composer / OneView, key made by the device: the API version, the session
# (sessionID), the CSR of the appliance (base64Data) and of an enclosure's bay
ANSWERS['hpe_synergy'] = [
    {'method': 'GET', 'url': r'/rest/version$', 'body': {'currentVersion': 9200}},
    {'method': 'POST', 'url': r'/rest/login-sessions$', 'body': {'sessionID': '{SESSION}'}},
    {'method': 'POST', 'url': r'/https/certificaterequest(\?bayNumber=\d+)?$', 'body': {
        'type': 'CertificateSigningRequestV2', 'base64Data': '{CSR}'}},
    {'method': 'GET', 'url': r'/rest/enclosures\?filter=', 'body': {'members': [
        {'name': '{OPT:enclosure}', 'uri': '/rest/enclosures/‹enclosure›'}]}},
]
# HPE iLO with its own key: the manager is an iLO 6 in Production; its HttpsCert has no CSR
# before GenerateCSR and the new one ({CSR}) after it
ANSWERS['hpe_ilo_devkey'] = [
    _REDFISH_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1/'}]}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
        'Model': 'iLO 6', 'FirmwareVersion': 'iLO 6 v1.62', 'Manufacturer': 'HPE'}},
    {'method': 'GET', 'url': r'/SecurityService/?$', 'body': {
        'SecurityState': 'Production', 'Links': {'HttpsCert': {
            '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/'}}}},
    {'method': 'GET', 'url': r'/HttpsCert/?$', 'times': 1, 'body': {
        'CertificateSigningRequest': ''}},
    {'method': 'GET', 'url': r'/HttpsCert/?$', 'body': {'CertificateSigningRequest': '{CSR}'}},
]
# Dell OpenManage Enterprise, key made by the device: the session (X-Auth-Token, Id), the
# version (4.6: the chain uploaded), the CSR in CertificateData
ANSWERS['dell_ome'] = [
    {'method': 'POST', 'url': r'/api/SessionService/Sessions$', 'status': 201,
     'body': {'Id': '‹session›'},
     'headers': {'Content-Type': 'application/json', 'X-Auth-Token': 'PLANSESSION0token'}},
    {'method': 'GET', 'url': r'/api/ApplicationService/Info$', 'body': {'Version': '4.6.0'}},
    {'method': 'POST', 'url': r'ApplicationService\.GenerateCSR$', 'body': {
        'CertificateData': '{CSR}'}},
]
# its version for OME 3.0 - 3.9 says such a version (the certificate uploaded alone)
ANSWERS['dell_ome@3.0'] = [
    {'method': 'GET', 'url': r'/api/ApplicationService/Info$', 'body': {'Version': '3.9.0'}},
]
# Lenovo XClarity Administrator, key made by the device: the CSR made (its path) and
# downloaded, the upload taken (FQXHMSE0134I)
ANSWERS['lenovo_lxca'] = [
    {'method': 'POST', 'url': r'/certificateSigningRequest$', 'body': {
        'response': [{'path': '1'}], 'result': 'success'}},
    {'method': 'GET', 'url': r'/certificateSigningRequest\?', 'body': {'csr': '{CSR}'}},
    {'method': 'POST', 'url': r'/serverCertificate/tmp$', 'body': {
        'result': 'success', 'messages': [{'id': 'FQXHMSE0134I'}]}},
]
# VCF component through SDDC Manager, key made by the device: the token, the domain named,
# the tasks done, the CSR made ({CSR}), the validation succeeded
ANSWERS['vcf_component'] = [
    {'method': 'POST', 'url': r'/v1/tokens$', 'body': {
        'accessToken': '{SESSION}', 'refreshToken': {'id': '‹refresh token›'}}},
    {'method': 'GET', 'url': r'/v1/domains$', 'body': {'elements': [
        {'id': '‹domain›', 'name': '{CFG:domain}'}]}},
    {'method': 'PUT', 'url': r'/v1/domains/[^/]+/csrs$', 'status': 202, 'body': {
        'id': '‹task›', 'status': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/v1/domains/[^/]+/csrs$', 'body': {'elements': [
        {'csrEncodedContent': '{CSR}'}]}},
    {'method': 'PUT', 'url': r'/resource-certificates/validations$', 'status': 201, 'body': {
        'validationId': '‹validation›'}},
    {'method': 'GET', 'url': r'/resource-certificates/validations/', 'body': {
        'executionStatus': 'COMPLETED', 'resultStatus': 'SUCCEEDED'}},
    {'method': 'PUT', 'url': r'/v1/domains/[^/]+/resource-certificates$', 'status': 202,
     'body': {'id': '‹task›', 'status': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/v1/tasks/', 'body': {'status': 'SUCCESSFUL'}},
    {'method': 'GET', 'url': r'/v1/sddc-managers$', 'body': {'elements': [
        {'version': '5.2.1.0'}]}},
]
# its version 9.1 - VCF Operations: the token, the version 9.1, the component's certificate
# (the FQDN asked), the workflows completed, the CSR made ({CSR})
ANSWERS['vcf_component@9.1'] = [
    {'method': 'POST', 'url': r'/auth/token/acquire$', 'body': {'token': '{SESSION}'}},
    {'method': 'GET', 'url': r'/suite-api/api/versions/current$', 'body': {
        'releaseName': 'VCF Operations 9.1', 'major': 9, 'minor': 1}},
    {'method': 'POST', 'url': r'/certificates/query', 'body': {'vcfCertificateModels': [
        {'certificateResourceKey': '‹certificate›',
         'applianceFqdn': '{SENT:applianceFqdn}', 'category': 'TLS_CERT'}]}},
    {'method': 'POST', 'url': r'/certificate-management/csrs$', 'body': {
        'requestId': '‹request›', 'state': 'INPROGRESS'}},
    {'method': 'GET', 'url': r'/certificate-management/csrs\?', 'body': {
        'certificateSignatureInfo': [{'csr': '{CSR}'}]}},
    {'method': 'PUT', 'url': r'/certificate-management/certificates/', 'status': 202,
     'body': {'requestId': '‹request›'}},
    {'method': 'GET', 'url': r'/workflows/requests/', 'body': {'state': 'COMPLETED'}},
]
# CUCM's CLI (one session a step, the lines on its input): the version, an empty trust
# store, the imports and restarts as Cisco's TechNote 200753 shows them; set csr gen /
# show csr own print the sandbox's CSR (what an unanswered command prints)
SSH_ANSWERS['cucm'] = [
    {'command': r'^$', 'input': r'^show version active', 'stdout':
        'Active Master Version: 15.0.1.13900-234\n'},
    {'command': r'^$', 'input': r'^show cert list (trust|own)\nexit', 'stdout': ''},
    {'command': r'^$', 'input': r'^set cert import trust', 'stdout':
        'Paste the Certificate and Hit Enter\nImport of trust certificate is successful\n'},
    {'command': r'^$', 'input': r'^set cert import own', 'stdout':
        'Paste the Certificate and Hit Enter\nSuccessfully imported certificate for tomcat.\n'},
    {'command': r'^$', 'input': r'^utils service restart', 'stdout':
        'Service Manager is running\nCommanded Restart\n'},
]
FIRST = {
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/', 'status': 404,
         'body': {'errorcode': 1540, 'message': 'Certificate does not exist'}},
    ],
}


# {CFG:key} / {OPT:key} in an answer's body: that setting (or deployment option) of the
# module as the user gave it - the name a module looks for in a list it reads (a server, an
# SVM, a cluster), so the list it is answered with holds it whatever the name is; an item of
# a list in the body with {EACH:CFG:key} / {EACH:OPT:key} in it: one such item for each line
# of that setting (none for an empty one)
_SETTING_RE = re.compile(r'\{(EACH:)?(CFG|OPT):([A-Za-z0-9_]+)\}')


def _setting_lines(v):
    if isinstance(v, (list, tuple)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str('' if v is None else v).splitlines() if x.strip()]


def _filled(v, cfg, opts):
    def one(src, key):
        got = _setting_lines((cfg if src == 'CFG' else opts).get(key))
        return got[0] if got else ''
    if isinstance(v, dict):
        return {k: _filled(x, cfg, opts) for k, x in v.items()}
    if isinstance(v, list):
        out = []
        for x in v:
            m = re.search(r'\{EACH:(CFG|OPT):([A-Za-z0-9_]+)\}', json.dumps(x))
            if not m:
                out.append(_filled(x, cfg, opts))
                continue
            for line in _setting_lines((cfg if m.group(1) == 'CFG' else opts).get(m.group(2))):
                out.append(_filled(json.loads(json.dumps(x).replace(
                    m.group(0), json.dumps(line)[1:-1])), cfg, opts))
        return out
    if isinstance(v, str):
        return _SETTING_RE.sub(lambda m: one(m.group(2), m.group(3)), v)
    return v


def answers_of(kind, cfg=None, opts=None, first=True, later=False, version=''):
    """The answers a module's recording gets: FIRST (or LATER) and ANSWERS of its kind - those
    of its version ("kind@version") before those of the kind -, the settings put in where an
    answer names them."""
    rules = (LATER.get(kind, []) if later else FIRST.get(kind, []) if first else []) + \
        (ANSWERS.get('%s@%s' % (kind, version), []) if version else []) + ANSWERS.get(kind, [])
    cfg, opts = dict(cfg or {}), dict(opts or {})
    return [dict(r, body=_filled(r['body'], cfg, opts)) if 'body' in r else dict(r)
            for r in rules]


def ssh_answers_of(kind, cfg=None, opts=None, version=''):
    """What the SSH commands of a module's recording print: SSH_ANSWERS of its version and
    kind, the settings put in where an answer names them."""
    rules = (SSH_ANSWERS.get('%s@%s' % (kind, version), []) if version else []) + \
        SSH_ANSWERS.get(kind, [])
    cfg, opts = dict(cfg or {}), dict(opts or {})
    return [dict(r, stdout=_filled(r['stdout'], cfg, opts)) if 'stdout' in r else dict(r)
            for r in rules]


# ---------------------------------------------------------------------------
# The modules and their secrets
# ---------------------------------------------------------------------------
def _stand_in(n):
    return base64.b64encode(('plansecret%02d' % n).encode()).decode()


class Secrets(object):
    """Every secret of the modules taking part: the real ones (masked out at the
    end) and the stand-ins the recording gets instead."""
    def __init__(self):
        self.real = set()
        self.n = 0

    def stand_ins(self, fields, cfg):
        """cfg with every secret field a stand-in -> (cfg, {stand-in: label})."""
        out, marks = dict(cfg or {}), {}
        for f in fields or []:
            k = f.get('key')
            if not (f.get('type') == 'secret' or f.get('secret')):
                continue
            v = out.get(k)
            if v in (None, ''):
                continue
            self.keep(v)
            self.n += 1
            si = _stand_in(self.n)
            out[k] = si
            marks[si] = str(f.get('label') or k)
        for k, v in list(out.items()):
            if isinstance(v, str) and (v.startswith('sealed:') or '-----BEGIN' in v and
                                       'PRIVATE' in v):
                self.keep(v)
                self.n += 1
                si = _stand_in(self.n)
                out[k] = si
                marks[si] = k
        return out, marks

    def keep(self, v):
        if isinstance(v, (bytes, bytearray)):
            v = v.decode('utf-8', 'replace')
        v = str(v)
        if len(v) >= 4:
            self.real.add(v)
            for line in v.splitlines():
                if len(line.strip()) >= 12:
                    self.real.add(line.strip())


def _cls(family, kind, row=None):
    return S.row_class(family, row, kind) if row else S.plugin_class(family, kind)


def _ver(cls):
    """The version of a module (1.0.95: its setup guide is of that version)."""
    return str(getattr(cls, 'module_version', '') or '') if cls is not None else ''


def _fields_of(cls, attr='fields'):
    return list(getattr(cls, attr, None) or []) if cls else []


def facts_of(cls, cfg, secrets_set=(), attr='fields'):
    """[[label, value]] of a module's settings as they are: secrets said, never shown."""
    out = []
    seen = set()
    for f in _fields_of(cls, attr):
        k = f.get('key')
        seen.add(k)
        v = (cfg or {}).get(k)
        if f.get('type') == 'secret' or f.get('secret') or k in secrets_set:
            if v not in (None, ''):
                out.append([f.get('label') or k, DOTS + ' (set, not shown)', 'words'])
            continue
        if v in (None, '', []):
            continue
        if f.get('type') == 'bool':
            out.append([f.get('label') or k, 'yes' if v is True or str(v).lower() in (
                '1', 'true', 'yes', 'on') else 'no', 'words'])
            continue
        elif f.get('type') == 'pem':
            out.append([f.get('label') or k, '(a certificate is set)', 'words'])
            continue
        elif f.get('type') == 'select':
            for o in f.get('options') or []:
                if isinstance(o, (list, tuple)) and len(o) >= 2 and str(o[0]) == str(v):
                    v = '%s (%s)' % (o[1], o[0]) if str(o[1]) != str(o[0]) else o[1]
                    break
        elif isinstance(v, list):
            v = '\n'.join(str(x) for x in v)
        # header lines with a secret in them (1.0.52): "Authorization: Bearer ..." of a webhook
        # or an HTTPS test was shown to read-only accounts
        v = '\n'.join(_header_masked(x) for x in str(v).split('\n'))
        out.append([f.get('label') or k, str(v)[:2000]])
    return out


def _header_masked(line):
    name, sep, _val = str(line).partition(':')
    if sep and re.match(r'^\s*(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|'
                        r'api-key|x-api-token|[a-z-]*(token|secret|key|password)[a-z-]*)\s*$',
                        name, re.I):
        return '%s: %s' % (name.strip(), DOTS)
    return line


# ---------------------------------------------------------------------------
# The recording
# ---------------------------------------------------------------------------
def record(job, timeout=ALL_S):
    """The sandbox run: plansandbox.main() in a process of its own -> {id: result}."""
    folder = tempfile.mkdtemp(prefix='acme-plan-')
    try:
        env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8', 'TMPDIR': folder,
               'HOME': folder}
        for k in ('ACME_PLAN_TRACE',):
            if os.environ.get(k):
                env[k] = os.environ[k]
        job = dict(job, root=ROOT, folder=folder,
                   plugin_dirs=[d for d in base.REGISTRY.dirs[1:] if os.path.isdir(d)])
        code = ('import sys; sys.path.insert(0, %r); '
                'from acmelib.certs import plansandbox as m; m.main()' % ROOT)
        try:
            got = subprocess.run([sys.executable, '-I', '-c', code],
                                 input=json.dumps(job, default=str).encode('utf-8'),
                                 capture_output=True, timeout=timeout, env=env, cwd=folder,
                                 start_new_session=True)
        except subprocess.TimeoutExpired:
            return {}, 'the recording took more than %d s' % timeout
        if got.returncode != 0:
            tail = got.stderr.decode('utf-8', 'replace').strip().splitlines()[-1:]
            return {}, 'the recording failed: %s' % (' '.join(tail)[:300] or got.returncode)
        try:
            return json.loads(got.stdout.decode('utf-8')).get('runs') or {}, ''
        except ValueError:
            return {}, 'the recording said nothing that can be read'
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def _host(url):
    try:
        return urllib.parse.urlsplit(url).netloc or url
    except ValueError:
        return url


def _sig(ev):
    """What one recorded event is, for comparing two runs."""
    k = ev.get('kind')
    if k == 'http':
        u = re.sub(r'[0-9a-f]{8,}|\d{8}', '#', ev.get('url') or '')
        b = ev.get('body')
        keys = ''
        if isinstance(b, dict):
            keys = ','.join(sorted(b))
            inner = next(iter(b.values())) if len(b) == 1 else None
            if isinstance(inner, dict):
                keys += ':' + ','.join(sorted(inner))
        return 'http %s %s %s' % (ev.get('method'), u, keys)
    if k == 'ssh-run':
        return 'run ' + re.sub(r'[0-9a-f]{8,}', '#', ev.get('command') or '')[:200]
    return '%s %s' % (k, re.sub(r'[0-9a-f]{8,}|\d{8}', '#', str(ev.get('path') or '')))


LOGIN = re.compile(r'(/login|/logon|/signin|/sign-in|/auth\b|/authn|/token\b|/oauth|session)',
                   re.I)
LOGOUT = re.compile(r'(logout|logoff|signout)', re.I)


def _is_ip(h):
    import ipaddress
    try:
        ipaddress.ip_address(str(h).strip('[]'))
        return True
    except ValueError:
        return False


def _conn_of(url, ev, proxy_on=False):
    """How an HTTP request is connected, in facts (1.0.37): [[what, value, tone]] - the
    address and port, TLS, the name sent as SNI, how the device's certificate is
    checked, a client certificate, the proxy, the time limit."""
    u = urllib.parse.urlsplit(str(url))
    tls = u.scheme == 'https'
    host = u.hostname or ''
    port = u.port or (443 if tls else 80)
    out = [['Address', host, ''], ['Port', str(port), '']]
    if tls:
        out.append(['TLS', 'yes', 'ok'])
        out.append(['SNI', host if not _is_ip(host) else 'none (an address: no name is sent)',
                    '' if not _is_ip(host) else 'dim'])
        if not ev.get('verify', True):
            out.append(['Device certificate', 'not checked', 'warn'])
        elif ev.get('ca'):
            out.append(['Device certificate', 'checked against the CA set in it', 'ok'])
        else:
            out.append(['Device certificate', 'checked against this machine\'s CAs', 'ok'])
        out.append(['Client certificate', 'yes' if ev.get('client_cert') else 'none',
                    'info' if ev.get('client_cert') else 'dim'])
    else:
        out.append(['TLS', 'no - plain HTTP', 'warn'])
    if ev.get('proxy_own'):
        out.append(['Proxy', 'one of its own (https_proxy of its environment)', 'info'])
    else:
        out.append(['Proxy', 'Settings → Proxy' if (ev.get('proxy') and proxy_on) else 'none - straight',
                    'info' if (ev.get('proxy') and proxy_on) else 'dim'])
    if ev.get('timeout'):
        out.append(['Time limit', '%s s' % ev['timeout'], 'dim'])
    return out


def _ssh_shown(ev):
    """The ssh command acme runs to a target (1.0.37), its options as SshSession makes
    them (runtime.ssh_options) - its own temporary files said, no secret in it."""
    try:
        from acmelib.certs import runtime as _rt
        key = bool(ev.get('key')) or ev.get('auth') == 'key'
        pw = bool(ev.get('password')) or ev.get('auth') == 'password'
        auths = (['publickey'] if key else []) + (['password', 'keyboard-interactive'] if pw else [])
        opts = _rt.ssh_options(ev.get('host') or '?', int(ev.get('timeout') or 15),
                               '‹the host key kept, in a file of its own›',
                               '‹a socket of its own›', '‹the key, in a file of its own (0600)›'
                               if key else None)
        opts += _rt.ssh_auth_options(auths or ['publickey'], pw or bool(ev.get('key_pass')))
        lines = ['ssh']
        k = 0
        while k < len(opts):
            if opts[k] in ('-o', '-i', '-F') and k + 1 < len(opts):
                lines.append('  %s %s' % (opts[k], opts[k + 1]))
                k += 2
            else:
                lines.append('  ' + opts[k])
                k += 1
        lines.append('  -p %s %s@%s' % (ev.get('port') or 22, ev.get('user') or '?', ev.get('host') or '?'))
        if pw or ev.get('key_pass'):
            lines.append('# the password%s handed to ssh through SSH_ASKPASS - never on its command line'
                         % (' of the key' if ev.get('key_pass') and not pw else ''))
        return ' \\\n'.join(lines[:1] + [x for x in lines[1:] if not x.startswith('#')]) + \
            ''.join('\n' + x for x in lines if x.startswith('#'))
    except Exception:                                   # noqa: BLE001
        return None


def _cmd(argv):
    return ' '.join(shlex.quote(str(a)) for a in argv)


def steps_of(events, sandbox_err=None, later=None, invented_note=True, proxy_on=False):
    """The recorded events as steps of the plan, in order."""
    out = []
    branch_of = {}
    if later is not None:
        a = [_sig(e) for e in events]
        b = [_sig(e) for e in later]
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        extra = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag in ('replace', 'delete'):
                for i in range(i1, i2):
                    branch_of[i] = 'first'
            if tag in ('replace', 'insert'):
                extra.append((i2, later[j1:j2]))
        merged = []
        ins = {}
        for at, evs in extra:
            ins.setdefault(at, []).extend(evs)
        for i, ev in enumerate(events):
            for e2 in ins.get(i, []):
                merged.append((e2, 'later'))
            merged.append((ev, branch_of.get(i)))
        for e2 in ins.get(len(events), []):
            merged.append((e2, 'later'))
    else:
        merged = [(e, None) for e in events]
    sub = None
    i = 0
    while i < len(merged):
        ev, br = merged[i]
        k = ev.get('kind')
        st = None
        if k == 'phase':
            sub = ev.get('what')
            if sub == 'verify':
                out.append({'kind': 'head', 'words': 'After it is put in place'})
            elif sub == 'ready':
                out.append({'kind': 'head', 'words': 'Until it can be seen'})
            elif sub == 'cleanup':
                out.append({'kind': 'head', 'words': 'After the CA has looked: taken away again'})
            i += 1
            continue
        if k == 'http':
            url, m = ev.get('url') or '', ev.get('method') or 'GET'
            host = _host(url)
            path = urllib.parse.urlsplit(url).path
            if m == 'POST' and LOGIN.search(path) and not LOGOUT.search(path):
                words, kind = 'Signs in to {0}', 'connect'
            elif LOGOUT.search(path):
                words, kind = 'Signs out of {0}', 'connect'
            elif m == 'GET':
                words, kind = 'Reads from {0}', 'read'
            elif m == 'DELETE':
                words, kind = 'Deletes on {0}', 'delete'
            elif m in ('PUT', 'PATCH'):
                words, kind = 'Changes on {0}', 'call'
            else:
                words, kind = 'Sends a request to {0}', 'call'
            if re.search(r'save|commit|write_mem|saveconfig', url, re.I):
                kind = 'save'
            st = {'kind': kind, 'words': words.replace('{0}', host),
                  'detail': {'method': m, 'url': url, 'headers': ev.get('headers') or {},
                             'body': ev.get('body')}}
            st['detail']['conn'] = _conn_of(url, ev, proxy_on)
            # the request as it goes on the wire (1.0.37): every header, the ones acme
            # and Python add too, and the body as sent - secrets left out by scrub()
            try:
                from acmelib.certs import runtime as _rt
                st['detail']['wire'] = _rt.wire_request(m, url, ev.get('headers') or {},
                                                        ev.get('body'), own=bool(ev.get('own')))
                if ev.get('own'):
                    st['note'] = ((st.get('note') + '; ') if st.get('note') else '') + \
                        'a connection the module makes itself (http.client), not through acme'
                # recorded with stand-ins (the certificate, the secrets): the real length differs
                for h in st['detail']['wire']['headers']:
                    if h[0] == 'Content-Length':
                        h[1] = '≈ %s' % h[1]
            except Exception:                           # noqa: BLE001
                pass
            notes = []
            if not ev.get('verify', True):
                notes.append('the device\'s TLS certificate is not checked')
            if ev.get('client_cert'):
                notes.append('signed in with a client certificate')
            if ev.get('proxy') and proxy_on:
                notes.append('through the proxy of Settings → Proxy')
            if notes:
                st['note'] = '; '.join(notes)
            if m == 'GET' and invented_note and later is None:
                st['invented'] = True
        elif k == 'ftp-open':
            st = {'kind': 'connect', 'words': 'Connects over {0} to {1}:{2}'.replace(
                '{0}', 'FTPS (AUTH TLS)' if ev.get('tls') else 'FTP').replace(
                '{1}', ev.get('host') or '?').replace('{2}', str(ev.get('port') or 21)),
                'detail': {'conn': [['Address', ev.get('host') or '', ''],
                                    ['Port', str(ev.get('port') or 21), ''],
                                    ['TLS', 'yes - AUTH TLS, then PROT P' if ev.get('tls')
                                     else 'no - plain FTP: the password goes in the clear',
                                     'ok' if ev.get('tls') else 'warn'],
                                    ['Server certificate', ('checked against this machine\'s CAs'
                                                            if ev.get('verify') else 'not checked')
                                     if ev.get('tls') else '-', 'ok' if ev.get('verify') else 'warn'],
                                    ['Data', 'passive mode', 'dim']]}}
            if not ev.get('tls'):
                st['note'] = 'plain FTP: the password goes in the clear'
            cmds = []
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') == 'ftp-cmd':
                cmds.append(merged[j][0].get('cmd'))
                j += 1
            if cmds:
                st['detail']['text'] = '\n'.join('→ ' + str(c) for c in cmds)
                i = j - 1
        elif k == 'ftp-cmd':
            cmds = [ev.get('cmd')]
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') == 'ftp-cmd':
                cmds.append(merged[j][0].get('cmd'))
                j += 1
            i = j - 1
            st = {'kind': 'call', 'words': 'Speaks FTP to {0}'.replace('{0}', ev.get('host') or ''),
                  'detail': {'text': '\n'.join('→ ' + str(c) for c in cmds)}}
        elif k == 'ftp-put':
            st = {'kind': 'file', 'words': 'Uploads over FTP to {0}'.replace('{0}', ev.get('host') or ''),
                  'detail': {'text': '→ %s   (%d bytes, binary)' % (ev.get('cmd'), ev.get('bytes') or 0)}}
        elif k == 'socket':
            hp = '%s:%s' % (ev.get('host'), ev.get('port'))
            if ev.get('hex'):
                hx = ev['hex']
                try:
                    from acmelib.certs import dissect as _dx
                    pk = _dx.dissect(bytes.fromhex(hx), port=ev.get('port'))
                except Exception:                       # noqa: BLE001
                    pk = None
                st = {'kind': 'call', 'words': 'Sends {0} bytes over UDP to {1}'.replace(
                    '{0}', str(ev.get('bytes') or len(hx) // 2)).replace('{1}', hp),
                    'detail': {'packets': [pk]} if pk else {'text': ' '.join(
                        hx[n:n + 2] for n in range(0, len(hx), 2))},
                    'note': 'a connection the module makes itself, not through acme' + (
                        ' - %s' % pk['summary'] if pk and pk.get('fields') else '')}
            else:
                st = {'kind': 'stop', 'words': 'Opens a connection of its own to {0} ({1})'.replace(
                    '{0}', hp).replace('{1}', (ev.get('how') or 'tcp').upper()),
                    'note': 'the module speaks to it itself, not through acme: where to can be '
                            'told from here, what it sends there cannot'}
        elif k == 'ssh-open':
            st = {'kind': 'connect', 'words': 'Connects over SSH to {0}'.replace(
                '{0}', '%s@%s:%s' % (ev.get('user'), ev.get('host'), ev.get('port'))),
                'detail': {'pairs': [
                    ['Host', '%s port %s' % (ev.get('host'), ev.get('port'))],
                    ['User', ev.get('user') or ''],
                    ['Signs in with', {'key': 'an SSH key (not shown)',
                                       'password': 'a password (not shown)'}.get(
                                           ev.get('auth'), 'nothing set'), 'words'],
                    ['Host key', ', '.join(ev.get('hostkey') or [])] if ev.get('hostkey') else
                    ['Host key', 'none pinned: the first one seen is trusted and kept'
                     if ev.get('trust_first') else 'none pinned: refused until it is', 'words']] +
                    ([['Through', 'the connector %s - signed in to first, this server reached from '
                       'it (ssh -W)' % ev['via'], 'words']] if ev.get('via') else []),
                    'command': _ssh_shown(ev)}}
        elif k == 'ssh-run':
            cmd = ev.get('command') or ''
            kind = 'delete' if re.match(r"^(sudo -[nS] (-p '' )?sh -c ')?rm ", cmd) else 'command'
            st = {'kind': kind, 'words': 'Runs a command on {0}'.replace('{0}', ev.get('host') or ''),
                  'detail': {'command': cmd}}
            if ev.get('script'):
                st['detail']['script'] = ev['script']
            if ev.get('input'):
                inp = ev['input']
                st['detail']['input'] = '%s (%s, %d B)' % (
                    DOTS if inp.get('secret') else 'input', inp.get('format') or 'text',
                    inp.get('size') or 0)
            if 'sudo -S' in cmd:
                st['note'] = 'through sudo - its password goes on the command\'s input, not shown'
            elif 'sudo -n' in cmd:
                st['note'] = 'through sudo (it must not ask for a password)'
            if sub == 'ready':
                st['invented'] = True
        elif k == 'ssh-put':
            st = {'kind': 'file', 'words': 'Uploads a file to {0}'.replace('{0}',
                                                                           ev.get('host') or ''),
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'owner': ev.get('owner'), 'size': ev.get('size'),
                             'format': ev.get('format'), 'via': ev.get('via')}}
            if ev.get('body') is not None:
                st['detail']['body'] = ev['body']
            if ev.get('secret'):
                st['secret'] = True
        elif k == 'ssh-get':
            st = {'kind': 'read', 'words': 'Reads a file from {0}'.replace('{0}',
                                                                           ev.get('host') or ''),
                  'detail': {'path': ev.get('path')}, 'invented': True}
        elif k == 'file':
            st = {'kind': 'file', 'words': 'Writes a file on this machine',
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'size': ev.get('size'), 'format': ev.get('format')}}
            if ev.get('body') is not None:
                st['detail']['body'] = ev['body']
            if ev.get('secret'):
                st['secret'] = True
        elif k == 'mkdir':
            if any(o.get('kind') == 'file' and (o.get('detail') or {}).get('path') == ev.get(
                    'path') for o in out) or any(
                    (o.get('detail') or {}).get('mkdir') == ev.get('path') for o in out):
                i += 1
                continue
            st = {'kind': 'file', 'words': 'Makes the folder where it is not there yet',
                  'detail': {'path': ev.get('path'), 'mkdir': ev.get('path')}}
        elif k in ('chmod', 'chown'):
            st = {'kind': 'file', 'words': 'Sets who may read it',
                  'detail': {'path': ev.get('path'), 'mode': ev.get('mode'),
                             'owner': ev.get('owner')}}
        elif k == 'delete':
            st = {'kind': 'delete', 'words': 'Deletes on this machine',
                  'detail': {'path': ev.get('path')}}
        elif k == 'move':
            st = {'kind': 'file', 'words': 'Moves a file on this machine',
                  'detail': {'path': ev.get('path'), 'text': '%s → %s' % (ev.get('from'),
                                                                          ev.get('path'))}}
        elif k == 'command':
            st = {'kind': 'command', 'words': 'Runs on this machine',
                  'detail': {'command': _cmd(ev.get('argv') or [])}}
            if ev.get('env'):
                st['note'] = 'with the variables %s' % ', '.join(ev['env'])
            st['detail']['conn'] = [['As', 'the acme account', ''],
                                    ['In', ev.get('cwd') or 'a folder of its own, made for it', '' if ev.get('cwd') else 'dim'],
                                    ['Its variables', ', '.join(ev.get('env') or []) or 'none of acme\'s', 'dim'],
                                    ['A shell', 'none - the program and its words as they are', 'dim']]
        elif k == 'dns-ask':
            servers = [ev.get('server')]
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') == 'dns-ask' and \
                    merged[j][0].get('name') == ev.get('name') and \
                    merged[j][0].get('qtype') == ev.get('qtype'):
                if merged[j][0].get('server') not in servers:
                    servers.append(merged[j][0].get('server'))
                j += 1
            i = j - 1
            port = ev.get('port') or 53
            st = {'kind': 'dns', 'words': 'Asks DNS for the {0} record of {1}'.replace(
                '{0}', ev.get('qtype') or '?').replace('{1}', ev.get('name') or '?'),
                'detail': {'command': '\n'.join('dig %s@%s %s %s' % (
                    '-p %s ' % port if int(port) != 53 else '', s, ev.get('name'),
                    ev.get('qtype')) for s in servers)},
                'invented': True}
            st['detail']['conn'] = [['Servers', ', '.join(str(x) for x in servers), ''],
                                    ['Port', str(port), ''], ['Asks', '%s %s' % (ev.get('qtype'), ev.get('name')), ''],
                                    ['Over', 'UDP, TCP when the answer is cut', 'dim']]
        elif k == 'dns-update':
            lines = ['server %s' % ev.get('server'), 'zone %s' % ev.get('zone')]
            for r in ev.get('records') or []:
                if r.get('delete'):
                    lines.append('update delete %s %s%s' % (r['name'], r['type'], (
                        ' "%s"' % r['value']) if r.get('value') else ''))
                else:
                    lines.append('update add %s %s %s "%s"' % (r['name'], r.get('ttl') or 60,
                                                               r['type'], r.get('value') or ''))
            lines.append('send')
            st = {'kind': 'dns', 'words': 'Sends a DNS UPDATE to {0}'.replace(
                '{0}', ev.get('server') or ''), 'detail': {'command': '\n'.join(lines)}}
            srv, _, prt = str(ev.get('server') or '').rpartition(':')
            st['detail']['conn'] = [['Server', srv or ev.get('server') or '', ''], ['Port', prt or '53', ''],
                                    ['Over', 'UDP, TCP when the answer is cut', 'dim'],
                                    ['Signed', ('TSIG %s' % (ev.get('tsig_name') or '')).strip()
                                     if ev.get('tsig') else 'not signed', 'ok' if ev.get('tsig') else 'warn']]
            if ev.get('tsig'):
                st['note'] = 'signed with its TSIG key (not shown)'
        elif k == 'own-dns':
            st = {'kind': 'dns', 'words': 'Puts the record into acme\'s own DNS server',
                  'detail': {'record': {'name': ev.get('name'), 'type': ev.get('type'),
                                        'value': ev.get('value'), 'ttl': ev.get('ttl')}}}
        elif k == 'own-dns-drop':
            st = {'kind': 'delete', 'words': 'Takes the record out of acme\'s own DNS server',
                  'detail': {'record': {'name': ev.get('name'), 'type': ev.get('type')}}}
        elif k == 'own-http':
            st = {'kind': 'file', 'words': 'Answers the file on this server\'s port 80',
                  'detail': {'path': '/.well-known/acme-challenge/%s' % ev.get('token')}}
        elif k == 'own-http-drop':
            st = {'kind': 'delete', 'words': 'Stops answering the file on port 80',
                  'detail': {'path': '/.well-known/acme-challenge/%s' % ev.get('token')}}
        elif k == 'own-file':
            st = {'kind': 'file', 'words': 'Answers the file on this server\'s port 80',
                  'detail': {'path': 'http://%s%s' % (ev.get('host'), ev.get('path'))}}
        elif k == 'wait':
            secs = float(ev.get('seconds') or 0)
            times = int(ev.get('times') or 1)
            if secs < 0.5:
                i += 1
                continue
            st = {'kind': 'wait', 'words': ('Waits {0} s' if times <= 1 else
                                            'Waits up to {0} s, asking again every {1} s').replace(
                '{0}', '%g' % round(secs)).replace('{1}', '%g' % round(secs / times, 1))}
        elif k == 'check':
            hp = '%s:%s' % (ev.get('host'), ev.get('port'))
            tries = 1
            j = i + 1
            while j < len(merged) and merged[j][0].get('kind') in ('check', 'wait', 'say'):
                e2 = merged[j][0]
                if e2.get('kind') == 'check':
                    if '%s:%s' % (e2.get('host'), e2.get('port')) != hp or \
                            (e2.get('only') or '') != (ev.get('only') or ''):
                        break
                    tries += 1
                j += 1
            while i < j - 1 and merged[j - 1][0].get('kind') != 'check':
                j -= 1
            i = j - 1
            fam = {'ec': 'ECDSA', 'ed': 'ECDSA', 'rsa': 'RSA'}.get(ev.get('only') or '')
            st = {'kind': 'check', 'words': ('Checks with a TLS handshake that {0} serves the new '
                                             '{1} certificate' if fam else
                                             'Checks with a TLS handshake that {0} serves the new '
                                             'certificate').replace('{0}', hp).replace('{1}', fam or ''),
                  'detail': {'command': 'openssl s_client -connect %s%s%s </dev/null | openssl '
                             'x509 -noout -fingerprint -sha256' % (
                                 hp, ' -servername %s' % ev['sni'] if ev.get('sni') else '',
                                 ' -cipher a%s' % ('ECDSA' if ev.get('only') in ('ec', 'ed')
                                                   else 'RSA') if ev.get('only') else '')}}
            if tries > 1:
                st['note'] = 'tried up to %d times, a few seconds apart, until it is so' % tries
            hh, _, pp = hp.rpartition(':')
            st['detail']['conn'] = [['Address', hh, ''], ['Port', pp, ''],
                                    ['SNI', ev.get('sni') or 'none', '' if ev.get('sni') else 'dim'],
                                    ['Key asked for', fam or 'whichever the server picks', ''],
                                    ['TLS at most', 'TLS 1.2 (to ask for the key type)' if fam else
                                     'as the server and this machine agree', 'dim'],
                                    ['Compared by', 'the SHA-256 fingerprint of the certificate sent', 'dim']]
        elif k == 'pages':
            st = {'kind': 'save', 'words': 'Puts it into acme\'s own pages ({0})'.replace(
                '{0}', ev.get('where') or '')}
        elif k == 'preview':
            files = ev.get('files') or []
            if files:
                st = {'kind': 'file', 'words': 'The files it writes',
                      'detail': {'files': files}}
                out.append(st)
            sc = ev.get('script')
            if sc:
                d = {'pairs': [['Script', sc.get('path')] if sc.get('path') else
                               ['Script', 'written in the deployment (%s)' % (
                                   sc.get('interp') or 'sh'), 'words'],
                               ['Arguments', sc.get('args') or '–'],
                               ['Variables', ', '.join(ev.get('env') or []) or '–']]}
                if sc.get('body'):
                    d['script'] = sc['body']
                out.append({'kind': 'command', 'words': 'The script after the files',
                            'detail': d})
            i += 1
            continue
        if st is not None:
            if br == 'first':
                st['branch'] = 'Only the first time - when it is not there yet'
            elif br == 'later':
                st['branch'] = 'Only at later renewals - when it is there already'
            if sub == 'ready' and st.get('kind') in ('read', 'dns'):
                st['invented'] = True
            out.append(st)
        i += 1
    if sandbox_err:
        out.append({'kind': 'stop', 'words': 'From here on, what it does depends on what it is '
                    'answered', 'note': sandbox_err})
    return out


# ---------------------------------------------------------------------------
# The phases
# ---------------------------------------------------------------------------
def _names(cert):
    v = cert.get('names')
    if isinstance(v, str):
        v = S.jload(v, [])
    return [str(x) for x in (v or [])]


def key_phase(cert, profile, irow, icls):
    steps = []
    given = str(cert.get('csr_given') or '').strip()
    kts = [cert.get('key_type') or 'ec-256'] + ([cert['key_type_alt']] if cert.get(
        'key_type_alt') and not given else [])
    names = _names(cert)
    sans = S.sans_of(names, profile) if names else []
    if cert.get('csr_from') and not given:
        # the key made by a target's device (devicekey.py): its run is recorded in plan()
        steps.append({'kind': 'key', 'words': 'The key and the request (CSR) are made by the '
                      'device of {0} - a new key at every issue; acme holds none'.replace(
                          '{0}', str(cert['csr_from'])),
                      'detail': {'pairs': [['Names', ', '.join(names)],
                                           ['Key type', cert.get('key_type') or 'ec-256'],
                                           ['Subject', ', '.join('%s=%s' % kv for kv in (
                                               profile.get('subject') or {}).items()) or
                                            'CN=%s' % (names[0] if names else '?')]]},
                      'note': 'the CSR is checked: every name in it and no other; the '
                              'certificate issued must be for its key'})
    elif given:
        steps.append({'kind': 'key', 'words': 'The CSR that was sent in is used - its key '
                      'stays with whoever made it, acme does not hold it',
                      'detail': {'pairs': [['Names', ', '.join(names)],
                                           ['Subject', ', '.join('%s=%s' % kv for kv in (
                                               profile.get('subject') or {}).items()) or '–']]}})
    else:
        for i, kt in enumerate(kts):
            sealed = cert.get('alt_key_sealed' if i else 'key_sealed')
            if cert.get('reuse_key') and sealed and cert.get('state') != 'revoked':
                words = 'The {0} key it has is kept (sealed in acme\'s database)'
            else:
                words = 'A new {0} key is made here, on this machine'
            st = {'kind': 'key', 'words': words.replace('{0}', kt),
                  'detail': {'command': 'openssl genpkey %s' % (
                      '-algorithm RSA -pkeyopt rsa_keygen_bits:%s' % kt[4:] if kt.startswith(
                          'rsa') else '-algorithm EC -pkeyopt ec_paramgen_curve:P-%s' % kt[3:]
                      if kt.startswith('ec') else '-algorithm ED25519')}}
            if i:
                st['branch'] = 'The twin of a dual certificate: the same names, another key'
            if cert.get('reuse_key') and not sealed:
                st['note'] = 'it keeps this key at the renewals after'
            steps.append(st)
        subj = dict(profile.get('subject') or {})
        pairs = [['Subject', ', '.join('%s=%s' % kv for kv in subj.items()) or
                  'CN=%s' % (names[0] if names else '?')],
                 ['subjectAltName', ', '.join(sans)]]
        if profile.get('eku'):
            pairs.append(['Extended key usage', ', '.join(profile['eku'])])
        if profile.get('must_staple'):
            pairs.append(['OCSP must-staple', 'yes', 'words'])
        if profile.get('days'):
            pairs.append(['Validity asked for', '%s days' % profile['days'], 'words'])
        if profile.get('acme_profile'):
            pairs.append(['ACME profile', profile['acme_profile']])
        steps.append({'kind': 'sign', 'words': 'The request (CSR) is made and signed with that '
                      'key', 'detail': {'pairs': pairs}})
    if icls is not None and getattr(icls, 'makes_key', False):
        steps.append({'kind': 'info', 'words': 'This source makes the key itself and sends it '
                      'with the certificate'})
    return {'key': 'key', 'title': 'Key and request', 'steps': steps}


def acme_steps(store, irow, icls, cfg, cert, names, challenges):
    """The ACME protocol as it goes (RFC 8555), written here - it needs a CA to record."""
    from acmelib.plugins.issuers import _acme_client as ac
    d = str(cfg.get('directory') or 'letsencrypt')
    url = str(cfg.get('directory_url') or '').strip() if d == 'custom' else \
        ac.DIRECTORIES.get(d, '?')
    base_ = url.rsplit('/', 1)[0] if url.endswith('/directory') else url.rstrip('/')
    le = d in ('letsencrypt', 'letsencrypt-staging')

    def ep(name, le_path):
        return base_ + '/acme/' + le_path if le else '‹%s from the directory›' % name
    acct = None
    try:
        from acmelib.certs import runtime
        inst = icls(cfg, runtime.RunContext(store, None, scope='issuer:%s' % irow['name']))
        acct = inst.ctx.kv_get(inst.account_slot(url))
        if isinstance(acct, (str, bytes)):
            acct = json.loads(acct)
    except Exception:                                   # noqa: BLE001
        acct = None
    contacts = cfg.get('contacts') or []
    if isinstance(contacts, str):
        contacts = [x for x in re.split(r'[\s,;]+', contacts) if x]
    jws = {'alg': 'ES256' if str(cfg.get('account_key') or 'ec-256').startswith('ec')
           else 'RS256', 'nonce': '‹from newNonce›'}
    steps = [{'kind': 'read', 'words': 'Reads the CA\'s directory',
              'detail': {'method': 'GET', 'url': url, 'headers': {}, 'body': None}},
             {'kind': 'read', 'words': 'Asks for a nonce (each signed request uses one)',
              'detail': {'method': 'HEAD', 'url': ep('newNonce', 'new-nonce'), 'headers': {},
                         'body': None}}]
    if isinstance(acct, dict) and acct.get('url'):
        steps.append({'kind': 'connect', 'words': 'Uses its ACME account (made before, its key '
                      'sealed in acme\'s database)',
                      'detail': {'pairs': [['Account', acct.get('url')],
                                           ['Contacts', ', '.join(acct.get('contacts') or [])
                                            or '–']]}})
    else:
        body = {'protected': dict(jws, jwk='‹the account\'s public key›',
                                  url=ep('newAccount', 'new-acct')),
                'payload': {'termsOfServiceAgreed': True,
                            'contact': ['mailto:%s' % c for c in contacts]}}
        if cfg.get('eab_kid'):
            body['payload']['externalAccountBinding'] = {
                'protected': {'alg': 'HS256', 'kid': cfg.get('eab_kid'),
                              'url': ep('newAccount', 'new-acct')},
                'payload': '‹the account\'s public key›',
                'signature': DOTS + ' (HMAC with the EAB key)'}
        steps.append({'kind': 'connect', 'words': 'Makes an ACME account at the CA (the first '
                      'time only; its key is made here and kept sealed)',
                      'branch': 'Only the first time - when it is not there yet',
                      'detail': {'method': 'POST', 'url': ep('newAccount', 'new-acct'),
                                 'headers': {'Content-Type': 'application/jose+json'},
                                 'body': body}})
    kid = (acct or {}).get('url') or '‹the account URL›'
    order = {'identifiers': [{'type': 'ip' if re.match(r'^[\d.:]+$', n) else 'dns',
                              'value': n} for n in names]}
    prof = (S.jload(cert.get('profile'), {}) or {}).get('acme_profile') if isinstance(
        cert.get('profile'), str) else (cert.get('profile') or {}).get('acme_profile')
    prof = prof or cfg.get('profile')
    if prof:
        order['profile'] = prof
    if cert.get('cert_pem'):
        order['replaces'] = '‹ARI id of the certificate now (if the CA has ARI)›'
    steps.append({'kind': 'call', 'words': 'Orders the certificate for its names',
                  'detail': {'method': 'POST', 'url': ep('newOrder', 'new-order'),
                             'headers': {'Content-Type': 'application/jose+json'},
                             'body': {'protected': dict(jws, kid=kid,
                                                        url=ep('newOrder', 'new-order')),
                                      'payload': order}}})
    auth_steps = []
    for n in names:
        mod = challenges.get(n) or {}
        kinds = list(mod.get('types') or [])
        pick = 'dns-01' if n.startswith('*.') else next(
            (t for t in kinds if t in ('dns-01', 'http-01', 'dns-persist-01')), 'dns-01')
        auth_steps.append({'kind': 'read', 'words': 'Reads the authorization of {0}'.replace(
            '{0}', n), 'detail': {'method': 'POST', 'url': '‹authorization URL of the '
                                  'order›', 'headers': {}, 'body': {
                                      'protected': dict(jws, kid=kid), 'payload': ''}},
            'note': 'POST-as-GET (an empty payload); if the CA still holds the name as proved, '
                    'nothing below is done for it'})
        auth_steps.append({'kind': 'info', 'words': 'Chooses the {0} challenge, put in place by '
                           '{1}'.replace('{0}', pick).replace('{1}', mod.get('name') or '?'),
                           'note': 'the validation phase below says how'})
    steps += auth_steps
    steps.append({'kind': 'wait', 'words': 'Waits until every proof can be seen (at most {0} s)'
                  .replace('{0}', '%g' % float(cfg.get('wait_ready') or 300))})
    steps.append({'kind': 'call', 'words': 'Tells the CA to check each name',
                  'detail': {'method': 'POST', 'url': '‹challenge URL›', 'headers': {},
                             'body': {'protected': dict(jws, kid=kid), 'payload': {}}}})
    steps.append({'kind': 'wait', 'words': 'Asks again every {0} s until each name is valid (at '
                  'most {1} s)'.replace('{0}', '%g' % float(cfg.get('poll_every') or 5))
                  .replace('{1}', '%g' % float(cfg.get('wait_valid') or 180))})
    steps.append({'kind': 'sign', 'words': 'Finalizes the order with the request (CSR)',
                  'detail': {'method': 'POST', 'url': '‹finalize URL of the order›',
                             'headers': {}, 'body': {'protected': dict(jws, kid=kid),
                                                     'payload': {'csr': '‹the CSR, '
                                                                 'DER, base64url›'}}}})
    steps.append({'kind': 'read', 'words': 'Downloads the certificate and its chain',
                  'detail': {'method': 'POST', 'url': '‹certificate URL of the order›',
                             'headers': {'Accept': 'application/pem-certificate-chain'},
                             'body': {'protected': dict(jws, kid=kid), 'payload': ''}},
                  'note': ('the chain that ends at "%s" is taken where the CA offers several '
                           '(Link: rel="alternate")' % cfg['preferred_chain'])
                  if cfg.get('preferred_chain') else 'the chain the CA sends first'})
    steps.append({'kind': 'read', 'words': 'Afterwards, every 6 hours: asks the CA when to renew '
                  '(ARI, RFC 9773)', 'detail': {'method': 'GET', 'url': '‹renewalInfo from '
                                                'the directory›/‹ARI id›',
                                                'headers': {}, 'body': None}})
    for s in steps:
        if s.get('detail', {}).get('body') and isinstance(s['detail']['body'], dict) and \
                'protected' in s['detail']['body']:
            s['detail']['note_jws'] = True
            s.setdefault('note', 'shown as it is signed (JWS): protected header and payload; '
                                 'the signature is made with the account key')
    pairs = [['CA', ac.DIRECTORY_WORDS.get(d) or d], ['Directory', url],
             ['Account', (acct or {}).get('url')] if (acct or {}).get('url') else
             ['Account', 'made at the first order', 'words'],
             ['Contacts', ', '.join(contacts) or '–']]
    if cfg.get('eab_kid'):
        pairs.append(['EAB key id', cfg['eab_kid']])
    return steps, pairs


def internal_ca_steps(store, cfg, cert, names, profile):
    from acmelib.certs import ca as CA
    pairs, steps = [], []
    try:
        got = CA.ca_get(store, int(cfg['ca']) if str(cfg.get('ca') or '').isdigit()
                        else cfg.get('ca'))
    except Exception as e:                              # noqa: BLE001
        return [{'kind': 'stop', 'words': 'The authority cannot be read', 'note': str(e)}], []
    info = got.get('info') or {}
    pairs += [['Authority', got.get('name')], ['Its subject', info.get('subject') or
                                               got.get('subject_dn') or '?'],
              ['Valid until', time.strftime('%Y-%m-%d', time.gmtime(float(
                  got.get('not_after') or 0)))]]
    days = profile.get('days') or cfg.get('days') or 397
    eku = profile.get('eku') or cfg.get('eku') or ['serverAuth', 'clientAuth']
    if isinstance(eku, str):
        eku = [x for x in re.split(r'[\s,]+', eku) if x]
    ext = [['Validity', '%s days (never past the end of the authority)' % days, 'words'],
           ['Extended key usage', ', '.join(eku)],
           ['subjectAltName', ', '.join(names)]]
    try:
        from acmelib.certs import publish
        v = publish.view(store, got['id'])
        if v.get('crl_url'):
            ext.append(['CRL distribution point', v['crl_url']])
        if v.get('aia_url'):
            ext.append(['Authority information (AIA)', v['aia_url']])
    except Exception:                                   # noqa: BLE001
        pass
    if got.get('ocsp_url'):
        ext.append(['OCSP', got['ocsp_url']])
    steps.append({'kind': 'sign', 'words': 'The authority {0} signs it here, at once - no '
                  'network, no validation'.replace('{0}', got.get('name') or '?'),
                  'detail': {'pairs': ext}})
    steps.append({'kind': 'save', 'words': 'What it signed is written into the authority\'s '
                  'list (for its revocation list)'})
    return steps, pairs


def _hostish(cfg):
    for k in ('host', 'url', 'base', 'api', 'server', 'endpoint', 'address'):
        v = (cfg or {}).get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ''


def persist_steps(store, crow, cfg, names, irow):
    """dns-persist-01 (challenges/dns_persist.py): nothing is put in place at an order;
    the record set once is looked up and - with "Write the record through" and "Write it
    by itself when missing" - written through that validation first."""
    from acmelib.plugins.challenges import dns_persist as DP
    from acmelib.plugins.challenges import _dns as D
    wild = str(cfg.get('wildcard', True)).strip().lower() not in ('0', 'false', 'no', 'off')
    doms = []
    own = [D.norm(x).lstrip('*.') for x in re.split(r'[\s,]+', str(cfg.get('domains') or ''))
           if x.strip()]
    for n in names:
        b = D.norm(n)
        b = b[2:] if b.startswith('*.') else b
        if re.match(r'^[\d.:]+\Z', b):
            continue
        hits = [d for d in own if b == d or b.endswith('.' + d)]
        d = (max(hits, key=len) if hits else D.registrable(b)) if wild else b
        if d not in doms:
            doms.append(d)
    writer = str(cfg.get('writer') or '').strip()
    auto = str(cfg.get('write_missing', True)).strip().lower() not in ('0', 'false', 'no',
                                                                       'off', '')
    acct = '‹the URL of the ACME account›'
    preset = str(S.plugin_config('issuer', irow).get('directory') or '') if irow else ''
    idn = D.norm(cfg.get('issuer_domain') or '') or (DP.ISSUER_DOMAINS.get(preset) or [''])[0] \
        or '‹the CA\'s issuer domain name›'
    value = '%s; accounturi=%s%s' % (idn, acct, '; policy=wildcard' if wild else '')
    steps = [{'kind': 'info', 'words': 'Nothing is put in place at an order: the CA reads the '
              'record set once (if it offers dns-persist-01 in the authorization)'}]
    wrow = S.plugin_row(store, 'challenge', writer) if writer else None
    for d in doms:
        rec = {'name': DP.PREFIX + d, 'type': 'TXT', 'value': value, 'ttl': None}
        steps.append({'kind': 'read', 'words': 'Looks the record up at {0}'.replace(
            '{0}', DP.PREFIX + d), 'detail': {'record': rec}})
        if writer and auto:
            steps.append({'kind': 'dns', 'words': 'Writes it through {0} ({1}) when it is '
                          'missing or not right'.replace('{0}', writer).replace(
                              '{1}', (wrow or {}).get('kind') or '?'),
                          'branch': 'Only when the record is missing or not right',
                          'detail': {'record': rec},
                          'note': 'only a value acme wrote itself is replaced; other TXT '
                                  'records at the name stay'})
        elif writer:
            steps.append({'kind': 'info', 'words': 'Not written at an order: "Write the records '
                          'to DNS" at the validation writes it through {0}'.replace('{0}',
                                                                                    writer)})
        else:
            steps.append({'kind': 'info', 'words': 'Set by hand, once - acme writes nothing'})
    fb = str(cfg.get('fallback') or '').strip()
    steps.append({'kind': 'info', 'words': ('Until the CA offers dns-persist-01: {0} proves the '
                                            'names').replace('{0}', fb) if fb else
                  'No fallback validation: until the CA offers dns-persist-01 nothing can be '
                  'issued'})
    return steps


def plan(store, cert, deploys, full=False):
    """The plan of `cert` (a row of certs, or a draft of one) with `deploys` (rows
    of cert_deploys, or [{target, options}])."""
    t0 = time.time()
    secrets_ = Secrets()
    names = _names(cert)
    profile = cert.get('profile')
    profile = S.jload(profile, {}) if isinstance(profile, str) else dict(profile or {})
    irow = S.plugin_row(store, 'issuer', cert.get('issuer')) if cert.get('issuer') else None
    icls = _cls('issuer', irow.get('kind'), irow) if irow else None
    icfg = S.plugin_config('issuer', irow) if irow else {}
    icfg = S.config_over(icls, icfg, S.cert_over({'profile': profile}, 'issuer'))
    runs = []
    rid = [0]

    def run(**kw):
        rid[0] += 1
        kw['id'] = 'r%d' % rid[0]
        kw.setdefault('seconds', RUN_S)
        runs.append(kw)
        return kw['id']

    # the validations, per name
    needs = bool(icls and icls.needs_challenge_for(icfg))
    chal = {}
    groups = {}
    if needs:
        for n in names:
            which = S.challenge_for(cert, n)
            chal[n] = which
            groups.setdefault(which, []).append(n)
    vinfo = {}
    for which, ns in groups.items():
        crow = S.plugin_row(store, 'challenge', which) if which else None
        ccls = _cls('challenge', crow.get('kind'), crow) if crow else None
        if not crow or not ccls:
            vinfo[which] = {'row': crow, 'cls': ccls, 'runs': []}
            continue
        ccfg = S.config_over(ccls, S.plugin_config('challenge', crow),
                             S.cert_over({'profile': profile}, 'challenge', crow['name']))
        scfg, marks = secrets_.stand_ins(_fields_of(ccls), ccfg)
        vinfo[which] = {'row': crow, 'cls': ccls, 'cfg': ccfg, 'runs': []}
        if crow.get('kind') == 'dns_persist':
            continue                    # nothing put in place per order: persist_steps()
        for n in ns[:NAMES_MOST]:
            vinfo[which]['runs'].append((n, run(family='challenge', kind=crow['kind'],
                                                name=crow['name'], op='challenge', names=[n],
                                                config=scfg, marks=marks,
                                                answers=answers_of(crow['kind'], scfg,
                                                                   first=False))))
    # the source, where it is not written here
    iid = None
    if irow and icls and irow.get('kind') not in ('acme', 'internal_ca', 'selfsigned'):
        scfg, marks = secrets_.stand_ins(_fields_of(icls), icfg)
        iid = run(family='issuer', kind=irow['kind'], name=irow['name'], op='issue',
                  config=scfg, marks=marks, answers=answers_of(irow['kind'], scfg, first=False))
    elif icfg:
        secrets_.stand_ins(_fields_of(icls), icfg)
    # the device that makes the key (certs.csr_from): its device_csr() recorded
    devrun = None
    if cert.get('csr_from'):
        drow = S.plugin_row(store, 'target', cert.get('csr_from'))
        dcls = _cls('target', drow.get('kind'), drow) if drow else None
        if drow and dcls is not None and getattr(dcls, 'device_key', False):
            dep0 = [d for d in deploys or [] if d.get('target') == drow['name']]
            dopts = {}
            if dep0:
                dopts = dep0[0].get('_options')
                if dopts is None:
                    dopts = S.deploy_options(store, dep0[0]) if dep0[0].get('id') else \
                        dict(dep0[0].get('options') or {})
            dcfg, dmarks = secrets_.stand_ins(_fields_of(dcls), S.plugin_config('target', drow))
            dsopts, dm2 = secrets_.stand_ins(_fields_of(dcls, 'deploy_fields'), dopts)
            dmarks.update(dm2)
            subj = dict(profile.get('subject') or {})
            subj.setdefault('CN', cert.get('cn') or (names[0] if names else ''))
            devrun = (drow, dcls, run(
                family='target', kind=drow['kind'], name=drow['name'], op='device_csr',
                config=dcfg, options=dsopts, marks=dmarks, subject=subj,
                sans=S.sans_of(names, profile),
                answers=answers_of(drow['kind'], dcfg, dsopts, version=_ver(dcls)),
                ssh_answers=ssh_answers_of(drow['kind'], dcfg, dsopts, version=_ver(dcls))))
        else:
            devrun = (drow, dcls, None)
    # the deployments
    dinfo = []
    for dep in deploys or []:
        trow = S.plugin_row(store, 'target', dep.get('target'))
        tcls = _cls('target', trow.get('kind'), trow) if trow else None
        item = {'dep': dep, 'row': trow, 'cls': tcls}
        dinfo.append(item)
        if not trow or not tcls:
            continue
        tcfg = S.plugin_config('target', trow)
        opts = dep.get('_options')
        if opts is None:
            opts = S.deploy_options(store, dep) if dep.get('id') else dict(dep.get('options')
                                                                         or {})
        scfg, marks = secrets_.stand_ins(_fields_of(tcls), tcfg)
        sopts, m2 = secrets_.stand_ins(_fields_of(tcls, 'deploy_fields') + [
            {'key': 'pfx_password', 'type': 'secret', 'label': 'password of the files'}], opts)
        marks.update(m2)
        item.update(cfg=tcfg, opts=opts)
        kw = dict(family='target', kind=trow['kind'], name=trow['name'], op='deploy',
                  config=scfg, options=sopts, marks=marks, deploy_id=dep.get('id'))
        kw['answers'] = answers_of(trow['kind'], scfg, sopts, version=_ver(tcls))
        kw['ssh_answers'] = ssh_answers_of(trow['kind'], scfg, sopts, version=_ver(tcls))
        if trow['kind'] in LATER:
            kw['later_answers'] = answers_of(trow['kind'], scfg, sopts, later=True,
                                             version=_ver(tcls))
        item['run'] = run(**kw)
    # the recording
    resolvers = {}
    try:
        from acmelib.certs import dnssets
        for p in ('validation', 'public', 'targets'):
            r = dnssets.resolver(p, store, None)
            resolvers[p] = [str(x) for x in r] or ['the system\'s resolvers']
    except Exception:                                   # noqa: BLE001
        pass
    chain = S.chain_list(cert.get('chain_pem')) if cert.get('chain_pem') else []
    job = {'settings': S.settings_view(), 'resolvers': resolvers, 'node': E.node_name(),
           'cert': {'name': cert.get('name') or (names[0] if names else 'certificate'),
                    'names': names, 'key_type': cert.get('key_type') or 'ec-256',
                    'key_type_alt': cert.get('key_type_alt') or '',
                    'serial': cert.get('serial'), 'not_before': cert.get('not_before'),
                    'not_after': cert.get('not_after'), 'version': cert.get('version'),
                    'chain': chain, 'id': cert.get('id'),
                    'ref': cert.get('issuer_ref') or None,
                    'csr_from': cert.get('csr_from') or ''},
           'runs': runs}
    got, rec_err = record(job) if runs else ({}, '')
    try:
        proxy_on = bool(E.proxy_full('acme'))
    except Exception:                                   # noqa: BLE001
        proxy_on = False

    def result(i):
        return got.get(i) or {'events': [], 'error': rec_err or 'not recorded'}

    phases = []
    # 1. key
    kp = key_phase(cert, profile, irow, icls)
    if devrun is not None:
        drow, dcls, did = devrun
        if did is None:
            kp['steps'].append({'kind': 'stop', 'words': 'There is no such target, or its module '
                                'makes no keys: the issue is refused'})
        else:
            r = result(did)
            dsteps = steps_of(r['events'], r.get('error'), proxy_on=proxy_on)
            if not r['events']:
                dsteps = [{'kind': 'stop', 'words': 'The detailed steps could not be worked out',
                           'note': r.get('error') or ''}]
            kp['steps'] += dsteps
            kp['module'] = {'name': drow['name'], 'kind': drow['kind'],
                            'title': dcls.title or dcls.kind, 'family': 'target',
                            'version': _ver(dcls)}
            if not drow.get('enabled', 1):
                kp['steps'].append({'kind': 'stop', 'words': 'The target is switched off: the '
                                    'issue is refused until it is on again'})
    phases.append(kp)
    # 2. the source
    src = {'key': 'source', 'title': 'The source', 'steps': []}
    if not irow:
        src['steps'].append({'kind': 'info', 'words': 'It has no source acme asks: it is '
                             'imported, or answered by an outside CA - nothing is ordered'})
    elif not icls:
        src['steps'].append({'kind': 'stop', 'words': 'The module of this source is missing'})
    elif irow['kind'] == 'acme':
        st, pairs = acme_steps(store, irow, icls, icfg, cert, names,
                               {n: {'name': chal.get(n), 'types': list(getattr(
                                   (vinfo.get(chal.get(n)) or {}).get('cls'), 'types', ())
                                   or ())} for n in names})
        src['steps'], src['facts'] = st, pairs
    elif irow['kind'] == 'internal_ca':
        st, pairs = internal_ca_steps(store, icfg, cert, names, profile)
        src['steps'], src['facts'] = st, pairs
    elif irow['kind'] == 'selfsigned':
        src['steps'] = [{'kind': 'sign', 'words': 'It signs itself with its own key, here - '
                         'nothing is asked of anybody'}]
        src['facts'] = facts_of(icls, icfg)
    else:
        r = result(iid)
        src['facts'] = facts_of(icls, icfg)
        src['steps'] = steps_of(r['events'], r.get('error'), proxy_on=proxy_on)
        if not r['events']:
            src['steps'] = [{'kind': 'info', 'words': (icls.description or icls.title)},
                            {'kind': 'stop', 'words': 'The detailed steps could not be worked '
                             'out', 'note': r.get('error') or ''}]
    if irow:
        src['module'] = {'name': irow['name'], 'kind': irow['kind'],
                         'title': (icls.title if icls else irow['kind']),
                         'family': 'issuer', 'version': _ver(icls)}
    phases.append(src)
    # 3. validation
    val = {'key': 'validation', 'title': 'Validation, per name', 'groups': []}
    if not needs:
        val['steps'] = [{'kind': 'info', 'words': 'This source needs no validation: the names '
                         'are not proved to anybody'}]
    for which, ns in groups.items():
        vi = vinfo.get(which) or {}
        g = {'title': which or 'none', 'names': ns}
        if not vi.get('row'):
            g['steps'] = [{'kind': 'stop', 'words': 'There is no validation for these names'}]
            val['groups'].append(g)
            continue
        cls = vi['cls']
        g['module'] = {'name': vi['row']['name'], 'kind': vi['row']['kind'],
                       'title': cls.title or cls.kind, 'family': 'challenge', 'version': _ver(cls)}
        g['facts'] = facts_of(cls, vi['cfg'])
        if vi['row'].get('kind') == 'dns_persist':
            g['steps'] = persist_steps(store, vi['row'], vi['cfg'], ns, irow)
            val['groups'].append(g)
            continue
        g['per_name'] = []
        for n, i in vi['runs']:
            r = result(i)
            steps = steps_of(r['events'], r.get('error'), proxy_on=proxy_on)
            if not r['events']:
                steps = [{'kind': 'info', 'words': cls.description or cls.title},
                         {'kind': 'stop', 'words': 'The detailed steps could not be worked '
                          'out', 'note': r.get('error') or ''}]
            g['per_name'].append({'name': n, 'steps': steps})
        if len(ns) > NAMES_MOST:
            g['more'] = len(ns) - NAMES_MOST
        val['groups'].append(g)
    phases.append(val)
    # 4. deployments
    dp = {'key': 'deploy', 'title': 'Deployments', 'groups': []}
    stop_all = []
    if cert.get('enabled') == 0:
        stop_all.append({'kind': 'stop', 'words': 'The certificate is switched off: nothing is '
                         'deployed, whoever asks'})
    elif cert.get('id') and S.current_revoked(store, cert):
        stop_all.append({'kind': 'stop', 'words': 'The certificate it holds now is revoked: '
                         'nothing is deployed until a new one is issued'})
    hold = S.deploy_hold(store, cert['id']) if cert.get('id') else None
    if hold and not stop_all:
        stop_all.append({'kind': 'wait', 'words': 'Its deployments are held: a new certificate '
                         'is issued and kept here, and put on the targets only with Deploy now',
                         'note': 'not by itself either - not at a renewal'})
    if stop_all:
        dp['steps'] = stop_all
    if not dinfo:
        dp['steps'] = stop_all + [{'kind': 'info', 'words': 'It is deployed nowhere: it is only '
                                   'kept here'}]
    for item in dinfo:
        dep, trow, cls = item['dep'], item['row'], item['cls']
        g = {'title': dep.get('target') or '?', 'enabled': bool(dep.get('enabled', 1)) and
             str(dep.get('enabled')) not in ('0', 'False')}
        if not trow or not cls:
            g['steps'] = [{'kind': 'stop', 'words': 'There is no such target (or its module '
                           'is missing)'}]
            dp['groups'].append(g)
            continue
        g['module'] = {'name': trow['name'], 'kind': trow['kind'], 'title': cls.title or cls.kind,
                       'family': 'target', 'version': _ver(cls)}
        g['host'] = _hostish(item['cfg'])
        g['facts'] = facts_of(cls, item['cfg'])
        g['options'] = facts_of(cls, item['opts'], attr='deploy_fields')
        if not trow.get('enabled', 1):
            g['off'] = True
        r = result(item['run'])
        steps = steps_of(r['events'], r.get('error'), later=r.get('later'), proxy_on=proxy_on)
        if not [s for s in steps if s['kind'] not in ('head', 'stop')]:
            steps = [{'kind': 'info', 'words': cls.description or cls.title},
                     {'kind': 'stop', 'words': 'The detailed steps could not be worked out',
                      'note': r.get('error') or ''}]
        pre = []
        if g.get('off'):
            pre.append({'kind': 'stop', 'words': 'The target is switched off: nothing is put '
                        'there until it is on again (not counted as failed)'})
        if not g['enabled']:
            pre.append({'kind': 'stop', 'words': 'This deployment is switched off: it is passed '
                        'over (Deploy now on it still runs it)'})
        if cert.get('key_type_alt'):
            if getattr(cls, 'dual', False):
                pre.append({'kind': 'info', 'words': 'Dual: both certificates go there ({0} and '
                            '{1})'.replace('{0}', cert.get('key_type') or 'ec-256').replace(
                                '{1}', cert['key_type_alt'])})
            else:
                want = str((item['opts'] or {}).get('variant') or 'auto').strip().lower()
                pre.append({'kind': 'info', 'words': 'Dual: the target holds one certificate - '
                            '{0} goes there'.replace('{0}', 'the RSA one' if want == 'auto' else
                                                     want), 'note': 'its option "variant": %s' %
                            want})
        if str((item['opts'] or {}).get('pfx_password_mode') or '') == 'generate' and \
                not (item['opts'] or {}).get('pfx_password'):
            pre.append({'kind': 'key', 'words': 'A password for the PKCS#12 / keystore files is '
                        'made and kept sealed with the deployment', 'first': True,
                        'note': 'a full administrator sees it'})
        post = []
        if cert.get('id') and dep.get('target'):
            # what says what is served there (1.0.93): the tests attached, or that none does
            try:
                from acmelib.certs import deployer as _dep
                words = _dep._tested_words(store, cert, dep['target'])
                post.append({'kind': 'check' if 'checked by' in words else 'info',
                             'words': words[:1].upper() + words[1:]})
            except Exception:                           # noqa: BLE001
                pass
        g['steps'] = pre + steps + post
        dp['groups'].append(g)
    phases.append(dp)
    # 5. the tests of what the servers serve (1.0.32)
    tp = checks_phase(store, cert, names)
    phases.append(tp)
    # 6. after
    phases.append(after_phase(store, cert, irow, dinfo))
    out = {'cert': {'id': cert.get('id'), 'name': cert.get('name'), 'names': names,
                    'key_type': cert.get('key_type') or 'ec-256',
                    'key_type_alt': cert.get('key_type_alt') or '',
                    'state': cert.get('state') or 'new', 'issued': bool(cert.get('cert_pem')),
                    'not_after': cert.get('not_after'), 'draft': not cert.get('id')},
           'head': {'source': src.get('module'),
                    'validations': [g.get('module') for g in val['groups'] if g.get('module')],
                    'deploys': len(dinfo), 'tests': len(tp.get('groups') or [])},
           'phases': phases, 'made': time.time(), 'took_ms': int((time.time() - t0) * 1000),
           'recording': rec_err or ''}
    return scrub(out, secrets_.real)


SECRET_HEADERS = re.compile(r'^(authorization|proxy-authorization|cookie|x-api-key|x-auth-token|'
                            r'api-key|x-api-token)$', re.I)


def _test_steps(cls, cfg, names, via=None):
    """What one test does, from its settings - a test only reads, so nothing needs to be
    recorded: the connection, what it says first, TLS, HTTP, the comparison - each as
    it goes on the wire (1.0.37): what is sent before TLS, the ClientHello's settings,
    the HTTP request whole (a header that signs in left out)."""
    full = {f['key']: f.get('default') for f in cls.fields or [] if f.get('key')}
    full.update({k: v for k, v in (cfg or {}).items() if v not in (None, '')})
    cfg = full
    first = next((n for n in names or [] if not str(n).startswith('*.')), '')
    host = str(cfg.get('host') or '').strip() or first or '?'
    port = int(cfg.get('port') or cls.default_port or 0)
    sni = str(cfg.get('sni') or '').strip() or first or host
    steps = []
    fam = {'4': 'IPv4 only', '6': 'IPv6 only'}.get(str(cfg.get('family') or ''), 'whichever the name gives')
    pairs = [['Address', host], ['Port', str(port)], ['Address family', fam, 'words'],
             ['From the address', str(cfg.get('source') or '') or 'as the system chooses',
              'words' if not cfg.get('source') else None],
             ['Time limit', '%s s' % (cfg.get('timeout') or 15)]]
    if via:
        steps.append({'kind': 'connect', 'words': 'From {0}, a connection to {1}:{2} (ssh -W)'
                      .replace('{0}', via).replace('{1}', host).replace('{2}', str(port)),
                      'detail': {'pairs': pairs}, 'debug': True})
    else:
        steps.append({'kind': 'connect', 'words': 'Connects to {0}:{1}'.replace(
            '{0}', host).replace('{1}', str(port)), 'note': 'the address set in the test' if
            cfg.get('host') else 'the certificate\'s first name: "Connect to" is empty',
            'detail': {'pairs': pairs}, 'debug': True})
    try:
        mod = cls(cfg, None)
    except Exception:                                   # noqa: BLE001
        mod = None
    talk = []
    try:
        talk = mod.talk(host, sni) if mod is not None and hasattr(mod, 'talk') else []
    except Exception:                                   # noqa: BLE001
        talk = []
    if talk or getattr(cls, 'starttls', False):
        text = []
        for t in talk:
            if t.get('send') is not None:
                text.append('→ ' + str(t['send']))
            elif t.get('send_hex'):
                hx = str(t['send_hex'])
                text.append('→ %s (%d bytes)' % (t.get('what') or 'bytes', len(hx) // 2))
                text.append('  ' + ' '.join(hx[i:i + 2] for i in range(0, len(hx), 2)))
            elif t.get('wait'):
                text.append('← waits for ' + str(t['wait']))
        packets = []
        for t in talk:
            if t.get('send_hex'):
                try:
                    from acmelib.certs import dissect as _dx
                    pk = _dx.dissect(bytes.fromhex(str(t['send_hex'])), proto=cls.kind)
                    pk['title'] = t.get('what') or pk['summary']
                    packets.append(pk)
                except Exception:                       # noqa: BLE001
                    pass
        st = {'kind': 'call', 'words': 'Speaks {0} first, then asks for TLS'.replace(
            '{0}', cls.protocol or cls.kind), 'note': cls.description or '',
            'detail': ({'text': '\n'.join(text), 'packets': packets} if text else None),
            'debug': True}
        if not text:
            # a module of your own that does not say it (1.0.37): said, not left blank
            st['note'] = ('this module does not say what it sends before TLS - a talk() of '
                          'its own would (docs/writing-a-module.md)')
            st['kind'] = 'stop'
        steps.append(st)
    want_key = str(cfg.get('key_want') or '').lower()
    tmax = str(cfg.get('tls_max') or '')
    ciphers = str(cfg.get('ciphers') or '')
    if want_key in ('rsa', 'ecdsa', 'both'):
        tmax = tmax if tmax in ('TLSv1', 'TLSv1_1', 'TLSv1_2') else 'TLSv1_2'
    TLSW = {'TLSv1': 'TLS 1.0', 'TLSv1_1': 'TLS 1.1', 'TLSv1_2': 'TLS 1.2', 'TLSv1_3': 'TLS 1.3'}
    tmax = TLSW.get(tmax, tmax)
    cfg = dict(cfg, tls_min=TLSW.get(str(cfg.get('tls_min') or ''), cfg.get('tls_min')))
    kw = {'rsa': 'RSA', 'ecdsa': 'ECDSA', 'both': 'both: once RSA, once ECDSA - two connections'}.get(
        want_key, 'whichever the server picks')
    tls_pairs = [
        ['Name sent (SNI)', '(none)' if sni == '-' else sni],
        ['TLS at least', str(cfg.get('tls_min') or '') or 'as the server and this machine agree',
         None if cfg.get('tls_min') else 'words'],
        ['TLS at most', tmax or 'as the server and this machine agree', None if tmax else 'words'],
        ['Ciphers', ciphers or ({'rsa': 'aRSA (RSA ones only)', 'ecdsa': 'aECDSA (ECDSA ones only)',
                                 'both': 'aRSA, then aECDSA'}.get(want_key) or
                                'what this machine offers'),
         None if ciphers else 'words'],
        ['ALPN', str(cfg.get('alpn') or '') or 'none offered', None if cfg.get('alpn') else 'words'],
        ['Key asked for', kw, 'words'],
        ['The chain', 'checked against this machine\'s CAs, and read whole without that when it '
         'is not trusted here', 'words']]
    tls_bits = [x for x in (
        ('at least ' + str(cfg['tls_min'])) if cfg.get('tls_min') else '',
        ('at most ' + tmax) if tmax else '', ('ciphers ' + ciphers) if ciphers else '',
        ('ALPN ' + str(cfg['alpn'])) if cfg.get('alpn') else '',
        {'rsa': 'the RSA certificate asked for', 'ecdsa': 'the ECDSA certificate asked for',
         'both': 'twice: once asking for RSA, once for ECDSA'}.get(want_key, '')) if x]
    steps.append({'kind': 'read', 'words': 'TLS handshake, the name {0} sent as SNI'.replace(
        '{0}', '(none)' if sni == '-' else sni), 'detail': {'pairs': tls_pairs}, 'debug': True,
        'note': ', '.join(tls_bits) or 'TLS as the server and this machine agree; the chain read whole'})
    if str(cfg.get('http', '')).lower() in ('1', 'true', 'yes', 'on') and hasattr(mod, 'http_lines'):
        try:
            lines, method, path, hosth = mod.http_lines(sni if sni not in ('', '-') else host, port)
        except Exception as e:                          # noqa: BLE001
            lines, method, path, hosth = None, str(cfg.get('method') or 'HEAD'), str(
                cfg.get('path') or '/'), str(cfg.get('host_header') or sni)
            steps.append({'kind': 'stop', 'words': str(e)})
        if lines:
            hdrs = []
            for ln in lines[1:]:
                k, _, v = ln.partition(':')
                v = v.strip()
                if SECRET_HEADERS.match(k.strip()):
                    v = DOTS
                hdrs.append([k.strip(), v, k.strip().lower() in ('user-agent', 'accept', 'connection')
                             and not any(str(h).lower().startswith(k.strip().lower() + ':')
                                         for h in (cfg.get('headers') or []))])
            steps.append({'kind': 'call', 'words': 'Asks {0} {1} with Host: {2}'.replace(
                '{0}', method).replace('{1}', path).replace('{2}', hosth),
                'note': 'the status expected: %s%s' % (cfg.get('expect_status') or 'any', (
                    '; the answer holds "%s"' % cfg['body_contains']) if cfg.get('body_contains')
                    else ''),
                'debug': True,
                'detail': {'method': method, 'url': 'https://%s%s%s' % (
                    host, '' if port == 443 else ':%d' % port, path),
                    'headers': {h[0]: h[1] for h in hdrs},
                    'wire': {'line': lines[0], 'headers': hdrs, 'body': None}}})
    want = {'current': 'the version deployed now (or its twin)', 'main': 'the main one only',
            'alt': 'the twin only', 'any': 'any version of it'}.get(
        str(cfg.get('expect') or 'current'), 'the version deployed now')
    trusted = str(cfg.get('require_trusted', '')).lower() in ('1', 'true', 'on', 'yes')
    days = int(E.CONFIG.get('certs_checks_warn_days') or 0)
    judge = [['Counts as right', want, 'words'],
             ['Compared by', 'the SHA-256 fingerprint of the certificate sent', 'words'],
             ['Name it must hold', str(cfg.get('check_name') or '') or (sni if sni != '-' else host)],
             ['Trusted here', 'must be - else it fails' if trusted else 'said, not a fault', 'words'],
             ['Ends within', ('%d days: a warning' % days) if days else 'not looked at', 'words'],
             ['The chain', 'an intermediate missing is a warning', 'words']]
    if str(cfg.get('http', '')).lower() in ('1', 'true', 'yes', 'on'):
        judge.append(['HTTP status', str(cfg.get('expect_status') or '') or 'any answer',
                      None if cfg.get('expect_status') else 'words'])
        if cfg.get('body_contains'):
            judge.append(['The answer holds', str(cfg['body_contains'])])
    steps.append({'kind': 'check', 'words': 'The certificate served compared with this one: '
                  '{0}'.replace('{0}', want), 'detail': {'pairs': judge}, 'debug': True,
                  'note': 'its fingerprint, the name %s among its names, the chain sent with it, '
                  'how long it runs%s' % (cfg.get('check_name') or sni, '; it must be trusted here'
                                          if trusted else '')})
    return steps


def checks_phase(store, cert, names):
    """The tests attached to the certificate: one group each (a connector: the tests it
    carries, from its server), as the deployments are."""
    ph = {'key': 'checks', 'title': 'Tests', 'groups': []}
    rows = store.db.rows('SELECT * FROM cert_checks WHERE cert_id = ? ORDER BY position, id',
                         (cert['id'],)) if cert.get('id') else []
    if not rows:
        ph['steps'] = [{'kind': 'info', 'words': 'No test is attached: what the servers serve '
                        'is not looked at (the certificate → Tests → Attach a test)'}]
        return ph
    after = bool(E.CONFIG.get('certs_checks_after_deploy', 1))
    auto = bool(E.CONFIG.get('certs_checks_auto'))
    for r in rows:
        trow = S.plugin_row(store, 'check', r['test'])
        cls = S.row_class('check', trow) if trow else None
        g = {'title': r['test'], 'enabled': bool(r.get('enabled', 1)) and
             str(r.get('enabled')) not in ('0', 'False')}
        if not trow or not cls:
            g['steps'] = [{'kind': 'stop', 'words': 'There is no such test (or its module is '
                           'missing)'}]
            ph['groups'].append(g)
            continue
        cfg = S.plugin_config('check', trow)
        g['module'] = {'name': trow['name'], 'kind': trow['kind'],
                       'title': cls.title or cls.kind, 'family': 'check', 'version': _ver(cls)}
        g['facts'] = facts_of(cls, cfg)
        if not trow.get('enabled', 1):
            g['off'] = True
        steps = []
        if getattr(cls, 'composite', False):
            g['host'] = '%s@%s:%s' % (cfg.get('user') or 'root', cfg.get('host') or '?',
                                      cfg.get('port') or 22)
            steps.append({'kind': 'connect', 'words': 'Signs in over SSH to {0}'.replace(
                '{0}', g['host']), 'note': 'with its key or password, as a Linux / Unix (SSH) '
                'target does - nothing is installed there'})
            for mname in cfg.get('tests') or []:
                mrow = S.plugin_row(store, 'check', mname)
                mcls = S.row_class('check', mrow) if mrow else None
                steps.append({'kind': 'head', 'words': mname})
                if not mcls:
                    steps.append({'kind': 'stop', 'words': 'There is no test %s' % mname})
                    continue
                steps += _test_steps(mcls, S.plugin_config('check', mrow), names,
                                     via=str(cfg.get('host') or '?'))
        else:
            mcfg = cfg
            first = next((n for n in names or [] if not str(n).startswith('*.')), '')
            g['host'] = '%s:%s' % (cfg.get('host') or first or '?',
                                   cfg.get('port') or cls.default_port)
            steps += _test_steps(cls, mcfg, names)
        # how it runs for this certificate (1.0.65/66), switched off here or as a test (1.0.85)
        from acmelib.certs import checks as CK
        tied = CK.after_list(r.get('after_target'))
        if not g['enabled']:
            steps.append({'kind': 'stop', 'words': 'Switched off for this certificate: it does '
                          'not run, neither after a deployment nor by itself'})
        elif not trow.get('enabled', 1):
            steps.append({'kind': 'stop', 'words': 'The test is switched off (Tests): it does not '
                          'run for any certificate'})
        if CK.AFTER_NONE in tied or not after:
            steps.append({'kind': 'wait', 'words': 'No deployment runs it: only its schedule '
                          'and Run it now'})
        else:
            try:
                waits = CK._tries_for(store, r, None)
            except Exception:                           # noqa: BLE001
                waits = CK.AFTER_DEPLOY_TRIES
            made = CK.auto_made(store, r['test'])
            if made:
                steps.append({'kind': 'info', 'words': 'Made by acme from a deployment: what the '
                              'target serves', 'note': 'its module checked it itself until 1.0.92; '
                              'taken off, it is not attached again'})
            if tied:
                steps.append({'kind': 'wait', 'words': 'Runs only after a deployment on {0}'.replace(
                    '{0}', ', '.join(tied)), 'note': (
                    'a wrong certificate served there fails that deployment - tried again later, '
                    'an event and a notice; not reached from here (a proxy, another network): '
                    'a warning, the deployment stands') if made else (
                    'when it fails there, that deployment fails - tried again later, an event '
                    'and a notice as a failed deployment')})
            else:
                steps.append({'kind': 'wait', 'words': 'Runs after every deployment, on any of '
                              'its targets', 'note': 'when it fails, the deployments of this run '
                              'fail - tried again later'})
            steps.append({'kind': 'wait', 'words': 'Asked {0} times while the services restart'
                          .replace('{0}', str(len(waits))), 'note': 'after %s s%s' % (
                              ', '.join(str(x) for x in waits),
                              ' - its target restarts for long' if tuple(waits) !=
                              tuple(CK.AFTER_DEPLOY_TRIES) else '')})
        steps.append({'kind': 'wait', 'words': ('By itself every {0} min'.replace(
            '{0}', str(E.CONFIG.get('certs_checks_every_min'))) if auto else
            'Not by itself: the regular runs are off (Settings → Certificates)'),
            'note': 'a test that starts failing is an event, a notice (Settings → Renewal and '
            'notices) and among the alerts (mail, SNMP trap, Prometheus)' if
            E.CONFIG.get('certs_checks_alert', 1) else 'no notice is sent when it fails'})
        if r.get('last_at'):
            steps.append({'kind': 'info', 'words': 'Last time: {0}'.replace(
                '{0}', str(r.get('last_said') or r.get('last_state') or '?'))})
        g['steps'] = steps
        ph['groups'].append(g)
    return ph


def after_phase(store, cert, irow, dinfo):
    steps = []
    try:
        from acmelib.certs import notices
        to = notices.recipients(store, cert) if cert.get('id') else \
            [x for x in re.split(r'[\s,;]+', str(E.CONFIG.get('certs_notify_mail') or '')) if x]
        ok = notices.ok_wanted()
    except Exception:                                   # noqa: BLE001
        to, ok = [], False
    if to:
        steps.append({'kind': 'mail', 'words': 'When something fails, a mail goes to {0}'.replace(
            '{0}', ', '.join(to)), 'note': 'and when it went well too' if ok else
            'nothing is sent when it goes well (Settings → Renewal and notices)'})
    else:
        steps.append({'kind': 'mail', 'words': 'Nobody is mailed: no address is set for '
                      'notices (Settings → Renewal and notices)'})
    steps.append({'kind': 'save', 'words': 'Every step is written into the job\'s log, and an '
                  'event (syslog, SIEM) says what was done'})
    tels = [x for x in re.split(r'[\s,;]+', str(E.CONFIG.get('certs_notify_sms') or '')) if x]
    if tels:
        steps.append({'kind': 'mail', 'words': 'And by SMS to {0}'.replace('{0}', ', '.join(tels))})
    C = E.CONFIG
    if C.get('alerts') and C.get('alerts_to'):
        steps.append({'kind': 'mail', 'words': 'A failed deployment or a failing test is among '
                      'the alerts: mailed to {0}'.replace('{0}', str(C.get('alerts_to'))),
                      'note': 'after %s min, again every %s h while it lasts (Settings → Alerts)'
                      % (C.get('alerts_delay_min', 5), C.get('alerts_repeat_h', 24))})
    if C.get('snmp_traps') and C.get('snmp_trap_to'):
        steps.append({'kind': 'call', 'words': 'An SNMP trap goes to {0}'.replace(
            '{0}', str(C.get('snmp_trap_to'))), 'note': 'when it fails, and when it is right again'})
    if C.get('metrics'):
        steps.append({'kind': 'info', 'words': 'Prometheus reads its state at /metrics'})
    if C.get('isemon'):
        steps.append({'kind': 'call', 'words': 'Every line of the job goes to isemon too',
                      'note': 'nothing secret: no password, key or token'})
    days = int(cert.get('renew_days') or E.CONFIG.get('certs_renew_days') or 30)
    auto = cert.get('auto_renew') not in (0, '0', False, None) or not cert.get('id')
    if not auto:
        steps.append({'kind': 'info', 'words': 'It is renewed only when somebody asks - '
                      'nothing repeats by itself'})
    elif cert.get('not_after'):
        at = float(cert['not_after']) - days * 86400
        ari = S.jload(cert.get('ari'), {}) if isinstance(cert.get('ari'), str) else {}
        if ari and ari.get('at'):
            at = min(at, float(ari['at']))
        steps.append({'kind': 'wait', 'words': 'Next renewal: {0}'.replace(
            '{0}', time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(max(at, time.time())))),
            'note': '%d days before the end, or sooner in the window its CA suggests (ARI)'
            % days})
    else:
        steps.append({'kind': 'wait', 'words': 'Issued at the next look (within minutes), or '
                      'at once with Issue now'})
    if auto:
        steps.append({'kind': 'info', 'words': 'At each renewal all of the above repeats - the '
                      'steps marked "only the first time" are not done again'})
        steps.append({'kind': 'info', 'words': 'A deployment that fails is tried again by '
                      'itself: after 5 minutes, then twice as long each time, at most every '
                      '{0} h'.replace('{0}', str(max(1, int(E.CONFIG.get('certs_retry_max_h')
                                                              or 6))))})
    return {'key': 'after', 'title': 'After', 'steps': steps}


PRIV_RE = re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----')


def scrub(out, real):
    """The plan as it leaves: every real secret, every private key and every
    stand-in left out once more; the CA's placeholders in words."""
    text = json.dumps(out, ensure_ascii=False, default=str)
    for a, b in SHOWN:
        text = text.replace(a, b)
    for v in sorted(real, key=len, reverse=True):
        for form in {v, json.dumps(v, ensure_ascii=False)[1:-1]}:
            if len(form) >= 6 and form in text:
                text = text.replace(form, DOTS)
            elif form and ('"%s"' % form) in text:
                text = text.replace('"%s"' % form, '"%s"' % DOTS)
    text = re.sub(r'cGxhbnNlY3JldD[A-Za-z0-9+/=]{2,6}', DOTS, text)
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                  DOTS + ' (private key)', text)
    return json.loads(text)
