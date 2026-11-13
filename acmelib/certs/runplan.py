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
    'hpe_oneview': [],          # the CA in the trust store already (ANSWERS)
    # Kubernetes: the TLS secret there, the earlier certificate in it
    'kubernetes': [
        {'method': 'GET', 'url': r'/api/v1/namespaces/[^/]+/secrets/[^/?]+$', 'body': {
            'kind': 'Secret', 'apiVersion': 'v1', 'type': 'kubernetes.io/tls',
            'metadata': {'name': '{TAIL}', 'resourceVersion': '81723',
                         'labels': {'app.kubernetes.io/managed-by': 'acme'}},
            'data': {'tls.crt': '{EARLIER_B64}', 'tls.key': '‹its key, base64›'}}}],
    # NetScaler: its certkey there, on the files of the earlier certificate, linked to the
    # intermediate (once that was read); the vserver bound to it already
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/[^/?]+$',
         'body': {'errorcode': 0, 'message': 'Done', 'sslcertkey': [
             {'certkey': '{TAIL}', 'cert': '/nsconfig/ssl/{EARLIER}.crt',
              'key': '/nsconfig/ssl/{EARLIER}.key', 'status': 'Valid',
              'linkcertkeyname': '{SEEN:sslcertkey/(acme-ca-[0-9a-f]+)}'}]}},
        {'method': 'GET', 'url': r'/nitro/v1/config/sslvserver_sslcertkey_binding/',
         'body': {'errorcode': 0, 'message': 'Done', 'sslvserver_sslcertkey_binding': [
             {'vservername': '{TAIL}',
              'certkeyname': '{SEEN:"certkey": "((?!acme-ca-)[^"]+)"}'}]}},
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
# The certificates a device holds before a renewal (plansandbox.Answers.earlier): {CURRENT}
# the name the new one gets; {EARLIER}, {EARLIER2}, {EARLIER3} ... {EARLIERn} the names of
# certificates of the same names 1, 2, 3 ... n renewals older (3 months each, another serial)
# - list three earlier ones to a module keeping 2 and its cleanup deletes the oldest. Each
# takes :maxlen[:serial length[:replacement char]] ({EARLIER3:35:6}). What the device serves
# over TLS before the new one was sent is such an earlier certificate ({EARLIER_PEM}), after
# it the new one (plansandbox served_der, 1.0.98).
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
    # Cloudflare's custom certificates: the zone found by its name, a custom certificate of
    # the certificate's names there (sni_custom, active) - replaced in place (PATCH), the
    # answer the new id (sni_custom: "a new resource id being returned")
    'cloudflare_ssl': [{'method': 'GET', 'url': r'/zones\?name=', 'body': {
        'success': True, 'errors': [], 'result': [
            {'id': '\u2039zone id\u203a', 'name': '{CFG:zone}', 'status': 'active'}]}},
        {'method': 'GET', 'url': r'/custom_certificates\?', 'body': {
            'success': True, 'errors': [], 'result': [
                {'id': '\u2039custom certificate id\u203a', 'hosts': '{CERTNAMES}',
                 'type': 'sni_custom', 'status': 'active', 'bundle_method': 'force',
                 'expires_on': '2026-12-01T00:00:00Z', 'priority': 0}],
            'result_info': {'page': 1, 'per_page': 50, 'count': 1, 'total_count': 1,
                            'total_pages': 1}}},
        {'method': 'PATCH', 'url': r'/custom_certificates/', 'body': {
            'success': True, 'errors': [], 'result': {
                'id': '\u2039new custom certificate id\u203a', 'hosts': '{CERTNAMES}',
                'status': 'pending'}}},
        {'method': 'POST', 'url': r'/custom_certificates$', 'body': {
            'success': True, 'errors': [], 'result': {
                'id': '\u2039new custom certificate id\u203a', 'status': 'pending'}}},
        {'body': {'success': True, 'errors': [], 'result': []}}],
    # ACM (JSON 1.1, the action a header): the ARN imported before (asked for, or kept) holds
    # the earlier certificate, used by a load balancer - re-imported into it (1.0.98); a first
    # import (no ARN) gets a new one
    'aws_acm': [
        {'method': 'POST', 'sent': r'^\{"CertificateArn": "[^"]*"\}$', 'body': {
            'Certificate': {
                'CertificateArn': '{SENT:CertificateArn}', 'DomainName': '{CERTNAME}',
                'Serial': '5a:0e:1d:2c:3b:4a:59:68:77', 'Type': 'IMPORTED', 'Status': 'ISSUED',
                'InUseBy': ['arn:aws:elasticloadbalancing:\u2039region\u203a:\u2039account'
                            '\u203a:loadbalancer/app/\u2039load balancer\u203a/\u2039id\u203a']}}},
        {'method': 'POST', 'sent': r'"CertificateArn": "arn:', 'body': {
            'CertificateArn': '{SENT:CertificateArn}'}},
        {'method': 'POST', 'body': {
            'CertificateArn': 'arn:aws:acm:\u2039region\u203a:\u2039account\u203a:certificate/'
                              '\u2039new\u203a'}}],
    # Suite Lifecycle: the Locker with two earlier certificates of acme before the import, with
    # the new one (the alias the import sent) too after; the pre-validation passes; Replace
    # Certificate a request that completes; the oldest deleted (1.0.98: the renewal's path)
    'aria_lifecycle': [
        {'method': 'GET', 'url': r'/lcm/locker/api/v2/certificates$', 'times': 1, 'body': [
            {'alias': '{EARLIER}', 'vmid': '\u2039earlier vmid\u203a'},
            {'alias': '{EARLIER2}', 'vmid': '\u2039oldest vmid\u203a'}]},
        {'method': 'GET', 'url': r'/lcm/locker/api/v2/certificates$', 'body': [
            {'alias': '{SENT:alias}', 'vmid': '\u2039certificate vmid\u203a'},
            {'alias': '{EARLIER}', 'vmid': '\u2039earlier vmid\u203a'},
            {'alias': '{EARLIER2}', 'vmid': '\u2039oldest vmid\u203a'}]},
        {'method': 'POST', 'url': r'/lcm/locker/api/v2/certificates/import$', 'body': {
            'alias': '{SENT:alias}', 'vmid': '\u2039certificate vmid\u203a'}},
        {'method': 'POST', 'url': r'/certificates/[^/]+/pre-validate$', 'body': {}},
        {'method': 'PUT', 'url': r'/products/[^/]+/certificates/[^/]+$', 'body': {
            'requestId': '\u2039request\u203a'}},
        {'method': 'GET', 'url': r'/lcm/request/api/v2/requests/', 'body': {
            'state': 'COMPLETED'}},
        {'method': 'DELETE', 'url': r'/lcm/locker/api/v2/certificates/', 'body': {}}],
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
            {'id': '\u2039policy\u203a', 'name': '{EACH:OPT:decryption_policies}'}]}},
        # (1.0.98: a renewal) the Internal Certificates: two earlier ones of acme; a Decrypt -
        # Known Key rule of each policy uses the newer earlier one - switched, deployed to the
        # device with changes, the oldest (no rule uses it) deleted; FMC 7.7: the Cert
        # Enrollment object asked for is there (PKCS12), enrolled on the devices asked already
        {'method': 'GET', 'url': r'/object/internalcertificates\?', 'body': {'items': [
            {'id': '\u2039earlier object\u203a', 'name': '{EARLIER}',
             'type': 'InternalCertificate'},
            {'id': '\u2039oldest object\u203a', 'name': '{EARLIER2}',
             'type': 'InternalCertificate'}], 'paging': {'offset': 0, 'limit': 1000, 'count': 2,
                                                         'pages': 1}}},
        {'method': 'GET', 'url': r'/decryptionpolicyrules\?expanded=true', 'body': {'items': [{
            'id': '\u2039rule\u203a', 'name': 'decrypt-www', 'type': 'DecryptionPolicyRule',
            'action': 'DECRYPT_KNOWN_KEY', 'enabled': True, 'internalCertificates': {'objects': [
                {'id': '\u2039earlier object\u203a', 'name': '{EARLIER}',
                 'type': 'InternalCertificate'}]}}], 'paging': {'count': 1, 'pages': 1}}},
        {'method': 'PUT', 'url': r'/decryptionpolicyrules/[^/?]+$', 'body': {
            'id': '\u2039rule\u203a', 'name': 'decrypt-www', 'type': 'DecryptionPolicyRule'}},
        {'method': 'GET', 'url': r'/deployment/deployabledevices\?', 'body': {'items': [{
            'type': 'DeployableDevice', 'name': 'ftd-1', 'canBeDeployed': True,
            'device': {'id': '\u2039device\u203a', 'name': 'ftd-1', 'type': 'Device'}}]}},
        {'method': 'POST', 'url': r'/deployment/deploymentrequests$', 'status': 202, 'body': {
            'type': 'DeploymentRequest', 'metadata': {'task': {
                'id': '\u2039task\u203a', 'taskType': 'DEVICE_DEPLOYMENT'}}}},
        {'method': 'DELETE', 'url': r'/object/internalcertificates/', 'body': {
            'id': '{TAIL}', 'type': 'InternalCertificate'}},
        {'method': 'GET', 'url': r'/object/certenrollments\?', 'body': {'items': [
            {'id': '\u2039enrollment\u203a', 'name': '{EACH:OPT:enrollment}',
             'type': 'CertEnrollment', 'enrollmentType': 'PKCS12'}],
            'paging': {'count': 1, 'pages': 1}}},
        {'method': 'PUT', 'url': r'/object/certenrollments/', 'body': {
            'id': '\u2039enrollment\u203a', 'name': '{SENT:name}', 'type': 'CertEnrollment',
            'enrollmentType': 'PKCS12'}},
        {'method': 'GET', 'url': r'/devices/certificates\?filter=', 'body': {'items': [{
            'type': 'DeviceCertificate', 'status': 'Available', 'certificate': {
                'id': '\u2039enrollment\u203a', 'type': 'CertEnrollment'}}]}},
        {'method': 'POST', 'url': r'/devices/operational/managecertificates$', 'status': 202,
         'body': {'type': 'ManageCertificate', 'metadata': {'task': {
             'id': '\u2039task\u203a'}}}}],
    # FMC 7.7: its version
    'cisco_fmc@7.7': [{'method': 'GET', 'url': r'/info/serverversion$', 'body': {'items': [{
        'serverVersion': '7.7.0 (build 91)', 'type': 'ServerVersion'}]}}],
    # the IMC answers every call of its XML API at /nuova (1.0.98: each as its method): the
    # sign-in a session cookie; a configConfMo the object it changed (the dn sent); the sign-out
    'cisco_imc': [
        {'method': 'POST', 'url': r'/nuova$', 'sent': r'^<aaaLogin ',
         'headers': {'Content-Type': 'text/xml'},
         'body': '<aaaLogin response="yes" outCookie="PLANSESSION0token" '
                 'outRefreshPeriod="600" outPriv="admin" outSessionId="15" '
                 'outVersion="4.3(2.240009)" errorCode="0"/>'},
        {'method': 'POST', 'url': r'/nuova$', 'sent': r'^<configConfMo ',
         'headers': {'Content-Type': 'text/xml'},
         'body': '<configConfMo dn="{SEEN:<configConfMo [^>]*dn="([^"]+)"}" '
                 'cookie="PLANSESSION0token" response="yes"><outConfig><{SEEN:<inConfig><(\\w+)} '
                 'dn="{SEEN:<configConfMo [^>]*dn="([^"]+)"}" status="modified"/></outConfig>'
                 '</configConfMo>'},
        {'method': 'POST', 'url': r'/nuova$', 'sent': r'^<aaaLogout ',
         'headers': {'Content-Type': 'text/xml'},
         'body': '<aaaLogout cookie="" response="yes" outStatus="success"> </aaaLogout>'},
        {'method': 'POST', 'url': r'/nuova$', 'headers': {'Content-Type': 'text/xml'},
         'body': '<aaaLogin response="yes" outCookie="PLANSESSION0token" '
                 'outRefreshPeriod="600" errorCode="0"/>'}],
    # ClearPass: the server named is one of the cluster's; at a renewal the chain's CA is in
    # the trust list already (refused, said - 1.0.98); each service's certificate replaced
    # (its answer: the new one's subject and expiry)
    'aruba_clearpass': [
        {'method': 'POST', 'url': r'/api/oauth$', 'body': {
            'access_token': '{SESSION}', 'token_type': 'Bearer', 'expires_in': 28800}},
        {'method': 'GET', 'url': r'/api/cluster/server$', 'body': {'_embedded': {'items': [
            {'server_uuid': '\u2039server uuid\u203a', 'name': '{CFG:server}'}]}}},
        {'method': 'POST', 'url': r'/api/cert-trust-list$', 'status': 422, 'headers': {
            'Content-Type': 'application/problem+json'}, 'body': {
            'type': 'http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html',
            'title': 'Unprocessable Entity', 'status': 422,
            'detail': 'Certificate already exists in the trust list'}},
        {'method': 'PUT', 'url': r'/api/server-cert/name/[^/]+/[^/]+$', 'body': {
            'service_name': '{TAIL}', 'subject': 'CN={CERTNAME}', 'validity': 'Valid',
            'expiry_date': '\u2039its expiry\u203a', 'issued_by': 'CN={CACN}'}}],
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
    # FortiManager: every JSON-RPC call is at /jsonrpc - its first, "is it there?", answered
    # -3 (Object does not exist), the others status 0 (OK)
    # (1.0.98: by the call in the body) the new certificate not there yet (-3); the
    # intermediate there already (-2, a renewal); the local certificates: three earlier acme
    # ones, the new one, the factory one (beyond the 2 kept: the oldest deleted); the admin
    # setting on the new one
    'fortimanager': [
        {'method': 'POST', 'url': r'/jsonrpc$',
         'sent': r'"method": "get", "params": \[\{"url": "/cli/global/system/certificate/'
                 r'local/', 'body': {'id': 1, 'result': [{'status': {
                     'code': -3, 'message': 'Object does not exist'},
                     'url': '/cli/global/system/certificate/local/\u2039name\u203a'}]}},
        {'method': 'POST', 'url': r'/jsonrpc$',
         'sent': r'"method": "add", "params": \[\{"url": "/cli/global/system/certificate/ca"',
         'body': {'id': 1, 'result': [{'status': {
             'code': -2, 'message': 'Object already exists'},
             'url': '/cli/global/system/certificate/ca'}]}},
        {'method': 'POST', 'url': r'/jsonrpc$',
         'sent': r'"method": "get", "params": \[\{"url": "/cli/global/system/certificate/'
                 r'local"', 'body': {'id': 1, 'result': [{'status': {'code': 0, 'message': 'OK'},
                                                          'url': '/cli/global/system/certificate/local',
                                                          'data': [
            {'name': 'Fortinet_Local'}, {'name': 'Fortinet_Local2'},
            {'name': '{EARLIER3:35:6}'}, {'name': '{EARLIER2:35:6}'},
            {'name': '{EARLIER:35:6}'}, {'name': '{CURRENT:35:6}'}]}]}},
        {'method': 'POST', 'url': r'/jsonrpc$',
         'sent': r'"method": "get", "params": \[\{"url": "/cli/global/system/admin/setting"',
         'body': {'id': 1, 'result': [{'status': {'code': 0, 'message': 'OK'},
                                       'url': '/cli/global/system/admin/setting',
                                       'data': {'admin_server_cert': '{EARLIER:35:6}',
                                                'https_port': 443}}]}},
        {'method': 'POST', 'url': r'/jsonrpc$', 'body': {
            'id': 1, 'result': [{'status': {'code': 0, 'message': 'OK'}, 'data': {}}]}}],
    # NimbleOS: the token and its id in "data" of the sign-in
    'hpe_nimble': [{'method': 'POST', 'url': r'/v1/tokens$', 'status': 201, 'body': {
        'data': {'session_token': '{SESSION}', 'id': '2a0e1d2c3b4a596870000000000000000000015',
                 'app_name': 'acme', 'username': '{CFG:user}'}}},
        # the import replaces the certificate of that name (force), "use" puts it to use
        {'method': 'POST', 'url': r'/v1/certificates/actions/import$', 'body': {
            'data': {'id': '2b0e1d2c3b4a596870000000000000000000003', 'name': '{SENT:data.name}',
                     'usage': 'https,apis', 'is_custom': True}}},
        {'method': 'POST', 'url': r'/v1/certificates/actions/use$', 'body': {'data': {}}},
        {'method': 'DELETE', 'url': r'/v1/tokens/', 'body': {'data': {}}}],
    # OneView: its API version (that of OneView 9.00), the sessionID, the CA not in the trust
    # store yet, the tasks of the calls completed
    'hpe_oneview': [
        {'method': 'GET', 'url': r'/rest/version$', 'body': {
            'currentVersion': 6600, 'minimumVersion': 120}},
        {'method': 'POST', 'url': r'/rest/login-sessions$', 'body': {'sessionID': '{SESSION}'}},
        # the CA in the trust store already (a renewal - FIRST: not yet, added)
        {'method': 'GET', 'url': r'/rest/certificates/ca/', 'body': {
            'type': 'CertificateAuthorityInfo', 'certificateDetails': {
                'type': 'CertificateDetailV2', 'aliasName': '{TAIL}',
                'commonName': '\u2039the intermediate\u203a'},
            'uri': '/rest/certificates/ca/{TAIL}'}},
        {'method': 'POST', 'url': r'/rest/certificates/ca$', 'status': 202, 'body': {
            'uri': '/rest/tasks/\u2039task\u203a'}},
        {'method': 'PUT', 'url': r'/rest/certificates/https/pkcs12', 'status': 202, 'body': {
            'uri': '/rest/tasks/\u2039task\u203a'}},
        {'method': 'GET', 'url': r'/rest/tasks/', 'body': {'taskState': 'Completed'}},
        {'method': 'DELETE', 'url': r'/rest/login-sessions$', 'status': 204, 'body': ''}],
    # Redfish (and the BMCs signed in to by it): the session's token and address are headers
    # of the sign-in, so it is signed out of
    # (supermicro_bmc, sddc_manager, unisphere_powermax, vcd, vmware_dr, vcenter,
    # vsphere_supervisor, synology: in the section of targets redfish@ilo .. zimbra below)
}
# What an SSH command prints where a module reads it (plansandbox.Answers.ssh): {command (a
# regex), input? (a regex of what is typed in), stdout, stderr?, exit?, times?} - else nothing.
# stdout may say {SESSION}, {SEEN:regex} (the first group of it in what was sent before) and
# {SERIAL} (1.0.96: the serial of the last certificate sent over SSH)
SSH_ANSWERS = {
    # IOS XE: the trustpoint imported holds its certificate; write memory says [OK]
    # (1.0.98: a renewal) a Catalyst 9300 on IOS XE 17.12.4 (17.9.5 for the version 17.3): the
    # running configuration holds its self-signed trustpoint and two earlier acme ones, the
    # HTTPS server on the newer; after the binding it uses the new one, after the clean-up the
    # oldest is gone; the import succeeds, the PKCS#12 is deleted, the configuration lines go
    # through (IOS asks before it removes a trustpoint: the "yes" lines)
    'cisco_iosxe': [
        {'command': r'^show version', 'stdout':
            'Cisco IOS XE Software, Version 17.12.04\nCisco IOS Software [Dublin], Catalyst L3 '
            'Switch Software (CAT9K_IOSXE), Version 17.12.4, RELEASE SOFTWARE (fc5)\n'
            'cisco C9300-48P (X86) processor with 1331521K/6147K bytes of memory.\n'},
        {'command': r'^show running-config \| include \^crypto pki trustpoint', 'times': 1,
         'stdout': 'crypto pki trustpoint TP-self-signed-3045923487\n'
                   'crypto pki trustpoint {EARLIER2:60}\ncrypto pki trustpoint {EARLIER:60}\n'
                   'ip http secure-trustpoint {EARLIER:60}\n'},
        {'command': r'^show running-config \| include \^crypto pki trustpoint', 'times': 1,
         'stdout': 'crypto pki trustpoint TP-self-signed-3045923487\n'
                   'crypto pki trustpoint {EARLIER2:60}\ncrypto pki trustpoint {EARLIER:60}\n'
                   'crypto pki trustpoint {CURRENT:60}\nip http secure-trustpoint {CURRENT:60}\n'},
        {'command': r'^show running-config \| include \^crypto pki trustpoint',
         'stdout': 'crypto pki trustpoint TP-self-signed-3045923487\n'
                   'crypto pki trustpoint {EARLIER:60}\ncrypto pki trustpoint {CURRENT:60}\n'
                   'ip http secure-trustpoint {CURRENT:60}\n'},
        {'command': r'^$', 'input': r'crypto pki import ', 'stdout':
            'Enter configuration commands, one per line.  End with CNTL/Z.\n'
            'CRYPTO_PKI: Imported PKCS12 file successfully.\n'},
        {'command': r'^show crypto pki certificates ', 'stdout':
            'Certificate\n  Status: Available\n  Certificate Serial Number (hex): ‹serial'
            '›\n  Certificate Usage: General Purpose\n  Associated Trustpoints: {CURRENT:60}'
            '\nCA Certificate\n  Status: Available\n  Associated Trustpoints: {CURRENT:60}\n'},
        {'command': r'^delete /force ', 'stdout': ''},
        {'command': r'^write memory', 'stdout': 'Building configuration...\n[OK]\n'},
        {'command': r'^$', 'input': r'\nip http secure-trustpoint ', 'stdout':
            'Enter configuration commands, one per line.  End with CNTL/Z.\n'},
        {'command': r'^$', 'input': r'\nno crypto pki trustpoint ', 'stdout':
            'Enter configuration commands, one per line.  End with CNTL/Z.\n'
            '% Removing an enrolled certificate may destroy existing connection.\n'
            'Are you sure you want to do this? [yes/no]: yes\n'
            '% Be sure to ask the CA administrator to revoke your certificates.\n'}],
    'cisco_iosxe@17.3': [
        {'command': r'^show version', 'stdout':
            'Cisco IOS XE Software, Version 17.09.05\nCisco IOS Software [Cupertino], Catalyst '
            'L3 Switch Software (CAT9K_IOSXE), Version 17.9.5, RELEASE SOFTWARE (fc4)\n'
            'cisco C9300-48P (X86) processor with 1331521K/6147K bytes of memory.\n'}],
}
# a Catalyst 9800 is an IOS XE: show version says 17.12.4 (17.9.5, 17.15.3 for those versions);
# the running configuration holds two earlier acme trustpoints (the older with a CA's of its
# chain), the HTTPS server uses the newer - after the import and the binding it uses the new
# one, after the clean-up the oldest is gone; the import says it succeeded, the trustpoint
# holds the certificate, the webauth map named, write memory [OK]
_WLC_NEW = '{SEEN:crypto pki import (\\S+) pkcs12}'
SSH_ANSWERS['cisco_wlc9800'] = [
    {'command': r'^show version', 'stdout':
        'Cisco IOS XE Software, Version 17.12.04\nCisco IOS Software [Dublin], C9800 Software '
        '(C9800_IOSXE-K9), Version 17.12.4, RELEASE SOFTWARE (fc3)\n'
        'cisco C9800-40-K9 (KATAR) processor with 16004362K/6147K bytes of memory.\n'},
    {'command': r'^show running-config \| include \^crypto pki trustpoint', 'times': 1,
     'stdout': 'crypto pki trustpoint TP-self-signed-1972538263\n'
               'crypto pki trustpoint {EARLIER2:60}\ncrypto pki trustpoint {EARLIER2:60}-rrr1\n'
               'crypto pki trustpoint {EARLIER:60}\nip http secure-trustpoint {EARLIER:60}\n'},
    {'command': r'^show running-config \| include \^crypto pki trustpoint', 'times': 1,
     'stdout': 'crypto pki trustpoint TP-self-signed-1972538263\n'
               'crypto pki trustpoint {EARLIER2:60}\ncrypto pki trustpoint {EARLIER2:60}-rrr1\n'
               'crypto pki trustpoint {EARLIER:60}\ncrypto pki trustpoint ' + _WLC_NEW + '\n'
               'ip http secure-trustpoint ' + _WLC_NEW + '\n'},
    {'command': r'^show running-config \| include \^crypto pki trustpoint',
     'stdout': 'crypto pki trustpoint TP-self-signed-1972538263\n'
               'crypto pki trustpoint {EARLIER:60}\ncrypto pki trustpoint ' + _WLC_NEW + '\n'
               'ip http secure-trustpoint ' + _WLC_NEW + '\n'},
    {'command': r'^show running-config \| section parameter-map type webauth', 'stdout':
        'parameter-map type webauth global\n type webauth\n virtual-ip ipv4 192.0.2.1\n'
        ' virtual-ip ipv6 1::1\n trustpoint ' + _WLC_NEW + '\n'},
    {'command': r'^$', 'input': r'crypto pki import ', 'stdout':
        'WLC(config)#crypto pki import ‹trustpoint› pkcs12 ‹file› password ‹password›\n'
        'CRYPTO_PKI: Imported PKCS12 file successfully.\nWLC(config)#end\n'},
    {'command': r'^show crypto pki certificates ', 'stdout':
        'Certificate\n  Status: Available\n  Certificate Serial Number (hex): ‹serial›\n'
        '  Certificate Usage: General Purpose\n  Associated Trustpoints: ' + _WLC_NEW + '\n'
        'CA Certificate\n  Status: Available\n  Associated Trustpoints: ' + _WLC_NEW + '\n'},
    {'command': r'^write memory', 'stdout': 'Building configuration...\n[OK]\n'},
    # the PKCS#12 deleted from bootflash:; a binding, a trustpoint removed: configuration mode
    # takes the lines (IOS asks before it removes a trustpoint: the "yes" lines)
    {'command': r'^delete /force ', 'stdout': ''},
    {'command': r'^$', 'input': r'\n(ip http secure-trustpoint|parameter-map type webauth) ',
     'stdout': 'Enter configuration commands, one per line.  End with CNTL/Z.\n'},
    {'command': r'^$', 'input': r'\nno crypto pki trustpoint ', 'stdout':
        'Enter configuration commands, one per line.  End with CNTL/Z.\n'
        '% Removing an enrolled certificate may destroy existing connection.\n'
        'Are you sure you want to do this? [yes/no]: yes\n'
        '% Be sure to ask the CA administrator to revoke your certificates.\n'}]
SSH_ANSWERS['cisco_wlc9800@17.3'] = [
    {'command': r'^show version', 'stdout':
        'Cisco IOS XE Software, Version 17.09.05\nCisco IOS Software [Cupertino], C9800 '
        'Software (C9800_IOSXE-K9), Version 17.9.5, RELEASE SOFTWARE (fc2)\n'}]
SSH_ANSWERS['cisco_wlc9800@17.12'] = [
    {'command': r'^show version', 'stdout':
        'Cisco IOS XE Software, Version 17.15.03\nCisco IOS Software [IOSXE], C9800 Software '
        '(C9800_IOSXE-K9), Version 17.15.3, RELEASE SOFTWARE (fc1)\n'}]
# ArubaOS 8 (1.0.98: a renewal): show version an AOS 8.10; `show crypto-local pki ServerCert`
# (name, original file, references, expired) lists the earlier acme certificate the WebUI uses
# and an older one before the import, the new one too after it (its name as the import command
# gave it), and after switch-cert the new one in use - the oldest is removed (keep 1); the
# chain's CAs are not there yet; copy, import, profile, delete go through; write memory saves
_AOS8_CERTS = ('Certificates\n------------\nName                             Original Filename'
               '  Reference Count  Expired\n----                             -----------------'
               '  ---------------  -------\n')
SSH_ANSWERS['aruba_aos8'] = [
    {'input': r'(?m)^show version$', 'stdout':
        'Aruba Operating System Software.\nArubaOS (MODEL: Aruba7210), Version 8.10.0.7\n'
        'Website: http://www.arubanetworks.com\nCopyright (c) 2002-2023, Hewlett Packard '
        'Enterprise Development LP.\n'},
    {'input': r'(?m)^show crypto-local pki ServerCert$', 'times': 1, 'stdout': _AOS8_CERTS +
        '{EARLIER:31}   acme-4a596877.pfx  1                No\n'
        '{EARLIER2:31}   acme-4a596876.pfx  0                No\n'},
    {'input': r'(?m)^show crypto-local pki ServerCert$', 'times': 1, 'stdout': _AOS8_CERTS +
        '{SEEN:crypto pki-import pfx ServerCert (\\S+)}   {SEEN:copy \\S+: .* flash: '
        '(acme-[0-9a-f]+\\.pfx)}  0                No\n'
        '{EARLIER:31}   acme-4a596877.pfx  1                No\n'
        '{EARLIER2:31}   acme-4a596876.pfx  0                No\n'},
    {'input': r'(?m)^show crypto-local pki ServerCert$', 'stdout': _AOS8_CERTS +
        '{SEEN:crypto pki-import pfx ServerCert (\\S+)}   {SEEN:copy \\S+: .* flash: '
        '(acme-[0-9a-f]+\\.pfx)}  1                No\n'
        '{EARLIER:31}   acme-4a596877.pfx  0                No\n'
        '{EARLIER2:31}   acme-4a596876.pfx  0                No\n'},
    {'input': r'(?m)^show crypto-local pki (IntermediateCA|TrustedCA)$', 'stdout': _AOS8_CERTS +
        'acme-ca-{CAID}                   acme-ca-{CAID}.pem  1                No\n'},
    {'input': r'(?m)^copy (tftp|scp): ', 'stdout': ''},
    {'input': r'(?m)^crypto pki-import (pfx|pem) ', 'stdout': ''},
    {'input': r'(?m)^web-server profile$', 'stdout': ''},
    {'input': r'(?m)^write memory$', 'stdout': 'Saving Configuration...\n\nConfiguration Saved.\n'},
    {'input': r'(?m)^delete filename ', 'stdout': ''},
    {'command': r'^rm -f -- ', 'stdout': ''}]
# Cockpit: ws-certs.d holds its own self-signed one and two earlier acme certificates;
# cockpit-certificate-ensure is in /usr/libexec and would use the new one
SSH_ANSWERS['cockpit'] = [
    {'command': r'ls -1 /etc/cockpit/ws-certs\.d$', 'stdout':
        '0-self-signed.cert\n0-self-signed.key\n90-{EARLIER2}.crt\n90-{EARLIER2}.key\n'
        '90-{EARLIER}.crt\n90-{EARLIER}.key\n'},
    {'command': r'^test -x /usr/libexec/cockpit-certificate-ensure', 'stdout':
        '/usr/libexec/cockpit-certificate-ensure\n'},
    {'command': r'cockpit-certificate-ensure --check$', 'stdout':
        'Would use certificate /etc/cockpit/ws-certs.d/90-{CURRENT}.crt\n'},
    {'command': r'test -d /etc/pki/ca-trust/source/anchors', 'stdout':
        '/etc/pki/ca-trust/source/anchors\n'},
    # install, rm, the trust store's update, the restart: nothing printed
    {'command': r'(^|\' )(install -m 06[04][04] |rm -f |systemctl restart cockpit\.service$|'
                r'/usr/bin/update-ca-trust extract$|/usr/sbin/update-ca-certificates$)',
     'stdout': ''}]
# cPanel (UAPI): the websites with SSL - one of the certificate's first name (its names, an
# earlier certificate installed), the domains named; install_ssl updates it (cert_id); SSL
# storage lists what is there. WHM API 1: the same through fetch_ssl_vhosts / installssl
_CPANEL_HOST = {'servername': '{CERTNAME}', 'domains': '{CERTNAMES}',
                'certificate_text': '', 'certificate': {
                    'subject.commonName': '{CERTNAME}', 'not_after': 1779000000,
                    'modulus': '\u2039modulus\u203a', 'issuer.organizationName': "Let's Encrypt"}}
ANSWERS['cpanel_ssl'] = [
    {'method': 'GET', 'url': r'/execute/SSL/installed_hosts$', 'body': {'result': {
        'status': 1, 'errors': None, 'messages': None, 'data': [
            _CPANEL_HOST,
            dict(_CPANEL_HOST, servername='{OPT:domain}', domains=['{OPT:domain}']),
            dict(_CPANEL_HOST, servername='{EACH:OPT:domains}', domains=['{EACH:OPT:domains}'])
        ]}}},
    {'method': 'POST', 'url': r'/execute/SSL/install_ssl$', 'body': {'result': {
        'status': 1, 'errors': None, 'messages': None, 'data': {
            'cert_id': '{SENT:domain}_\u2039id\u203a', 'action': 'update', 'domain': '{SENT:domain}',
            'message': 'The SSL certificate is now installed onto the domain \u201c{SENT:domain}'
                       '\u201d using the IP address \u201c192.0.2.10\u201d.',
            'warning_domains': []}}}},
    {'method': 'GET', 'url': r'/execute/SSL/list_certs$', 'body': {'result': {
        'status': 1, 'errors': None, 'data': []}}},
    {'method': 'GET', 'url': r'/execute/SSL/delete_cert\?', 'body': {'result': {
        'status': 1, 'errors': None, 'data': []}}},
    {'method': 'GET', 'url': r'/json-api/fetch_ssl_vhosts\?', 'body': {
        'metadata': {'result': 1, 'reason': 'OK', 'version': 1, 'command': 'fetch_ssl_vhosts'},
        'data': {'vhosts': [
            {'servername': '{CERTNAME}', 'domains': '{CERTNAMES}', 'crt': {
                'subject.commonName': '{CERTNAME}', 'not_after': 1779000000,
                'modulus': '\u2039modulus\u203a'}},
            {'servername': '{OPT:domain}', 'domains': ['{OPT:domain}'], 'crt': {
                'not_after': 1779000000}},
            {'servername': '{EACH:OPT:domains}', 'domains': ['{EACH:OPT:domains}'], 'crt': {
                'not_after': 1779000000}}]}}},
    {'method': 'POST', 'url': r'/json-api/installssl$', 'body': {
        'metadata': {'result': 1, 'reason': 'OK', 'version': 1, 'command': 'installssl'},
        'data': {'status': 1, 'statusmsg': 'The SSL certificate is now installed onto the '
                 'domain \u201c{SENT:domain}\u201d using the IP address \u201c192.0.2.10\u201d.',
                 'message': 'The SSL certificate is now installed onto the domain \u201c'
                 '{SENT:domain}\u201d using the IP address \u201c192.0.2.10\u201d.'}}},
]
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
        {'name': '{OPT:enclosure}', 'uri': '/rest/enclosures/0000000000A66101'}]}},
]
# (its HttpsCert: the certificate it serves now - the earlier one -, its two actions)
_ILO_HTTPS_CERT = {
    '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/', 'Id': 'HttpsCert',
    'X509CertificateInformation': {
        'Issuer': "/C=US/O=Let's Encrypt/CN=R11", 'Subject': '/CN={CERTNAME}',
        'SerialNumber': '5a:0e:1d:2c:3b:4a:59:68:77', 'ValidNotBefore': '2026-08-14T10:00:00Z',
        'ValidNotAfter': '2026-11-12T10:00:00Z'},
    'Actions': {
        '#HpeHttpsCert.GenerateCSR': {
            'target': '/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/'
                      'HpeHttpsCert.GenerateCSR'},
        '#HpeHttpsCert.ImportCertificate': {
            'target': '/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/'
                      'HpeHttpsCert.ImportCertificate'}}}
# HPE iLO with its own key: the manager is an iLO 6 in Production; its HttpsCert has no CSR
# before GenerateCSR and the new one ({CSR}) after it
ANSWERS['hpe_ilo_devkey'] = [
    {'method': 'GET', 'url': r'/redfish/v1/?$', 'body': {
        'RedfishVersion': '1.13.0', 'Product': 'ProLiant DL380 Gen11', 'Vendor': 'HPE',
        'Managers': {'@odata.id': '/redfish/v1/Managers/'},
        'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions/'}}}},
    {'method': 'DELETE', 'url': r'/SessionService/Sessions/', 'body': {}},
    _REDFISH_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1/'}]}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
        'Model': 'iLO 6', 'FirmwareVersion': 'iLO 6 v1.62', 'Manufacturer': 'HPE'}},
    {'method': 'GET', 'url': r'/SecurityService/?$', 'body': {
        'SecurityState': 'Production', 'Links': {'HttpsCert': {
            '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/'}}}},
    {'method': 'GET', 'url': r'/HttpsCert/?$', 'times': 1, 'body': dict(
        _ILO_HTTPS_CERT, CertificateSigningRequest='')},
    {'method': 'GET', 'url': r'/HttpsCert/?$', 'body': dict(
        _ILO_HTTPS_CERT, CertificateSigningRequest='{CSR}')},
    {'method': 'POST', 'url': r'/HpeHttpsCert\.GenerateCSR$', 'body': {'error': {
        'code': 'iLO.0.10.ExtendedInfo', '@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.27.GeneratingCertificate'}]}}},
    {'method': 'POST', 'url': r'/HpeHttpsCert\.ImportCertificate$', 'body': {'error': {
        'code': 'iLO.0.10.ExtendedInfo', '@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.27.ImportCertSuccessfuliLOResetinProgress'}]}}},
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
    # the upload taken (200, nothing said); the session deleted
    {'method': 'POST', 'url': r'ApplicationService\.Upload(CertChain|Certificate)$',
     'body': ''},
    {'method': 'DELETE', 'url': r'/api/SessionService/Sessions\(', 'status': 204, 'body': ''},
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
# CUCM's CLI (one session a step, the lines on its input): the version, an empty trust
# store, the imports and restarts as Cisco's TechNote 200753 shows them; set csr gen /
# show csr own print the sandbox's CSR (what an unanswered command prints); show cert own
# prints the serial of the certificate just pasted ({SERIAL}, 1.0.96 - no warning that CUCM
# shows another)
SSH_ANSWERS['cucm'] = [
    {'command': r'^$', 'input': r'^show version active', 'stdout':
        'Active Master Version: 15.0.1.13900-234\n'},
    {'command': r'^$', 'input': r'^show cert list (trust|own)\nexit', 'stdout': ''},
    {'command': r'^$', 'input': r'^set cert import trust', 'stdout':
        'Paste the Certificate and Hit Enter\nImport of trust certificate is successful\n'
        'tomcat-trust/Cisco_Root_CA_2048.pem: Trust Certificate\n'
        'tomcat-trust/{CACN_}.pem: Trust Certificate\ntomcat-trust/{CACN2_}.pem: Trust '
        'Certificate\n'},
    # set csr gen: a new key and CSR made; show csr own prints it (the sandbox's {CSR})
    {'command': r'^$', 'input': r'^set csr gen ', 'stdout':
        'Successfully Generated CSR for tomcat\n{CSR}\n'},
    {'command': r'^$', 'input': r'^set cert import own', 'stdout':
        'Paste the Certificate and Hit Enter\nSuccessfully imported certificate for tomcat.\n'
        '[\n  Version: V3\n  SerialNumber: [ {SERIAL} ]\n]\n'},
    {'command': r'^$', 'input': r'^utils service restart', 'stdout':
        'Service Manager is running\nCommanded Restart\n'},
]
# ---- targets a10 .. cisco_nxos (1.0.98): what each device answers on a renewal - the
# certificate acme put there before ({EARLIER}, {EARLIER2}: two older ones of its names) is
# there, so the module takes its real path: replaced, rebound, the older ones deleted ----
# acme push: an application acme is paired with already (it keeps the pin of it) answers
# hello with the id and key of that pin - the plan's own, the same in both; install puts the
# certificate into the slots asked for. Not paired yet: no pin, the pairing (or inventory)
# shown before.
PUSH_PIN = {'app_id': '4f0c2d0e8b7a4a6c9d3e1f2a3b4c5d6e',
            'enc_key': 'B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=', 'how': 'pairing code',
            'app': 'otp'}


def push_pin_of(store, cls, cfg):
    """The plan's pin for an acme push target paired already (acme keeps one for its
    address), else None."""
    try:
        return dict(PUSH_PIN) if E.push_pin(store, cls(dict(cfg or {}), None).base_url()) \
            else None
    except Exception:                                   # noqa: BLE001
        return None


def pages_of(store):
    """acme's own pages (targets/appliance.py) as they are: the nodes, the VIP address and
    what each holds now - so its run says where it goes and what it replaces."""
    try:
        from acmelib.certs import runtime
        ctx = runtime.RunContext.__new__(runtime.RunContext)
        ctx.store = store
        where = ctx.pages_where()
        have = {}
        for one in list(where.get('nodes') or []) + (['vip'] if (where.get('vip') or {})
                                                     .get('on') else []):
            try:
                have[one] = ctx.pages_get(one)
            except Exception:                           # noqa: BLE001
                have[one] = None
        return {'where': where, 'have': have}
    except Exception:                                   # noqa: BLE001
        return None


def kept_of(store, trow, cls, cfg, opts, cert):
    """What a target kept between its deployments that decides the way its run takes, as
    it is ({key: value} for the sandbox's kv) - ACM's ARN of the certificate imported
    before (aws_acm: a renewal re-imports into it); None for the others."""
    if trow.get('kind') != 'aws_acm':
        return None
    try:
        from acmelib.certs import runtime
        from acmelib.plugins.targets import aws_acm as A
        ctx = runtime.RunContext.__new__(runtime.RunContext)
        ctx.store, ctx.scope = store, 'target:%s' % trow['name']

        class B(object):
            name = cert.get('name') or ''
            names = _names(cert)
            key_type = cert.get('key_type') or ''
        mod = cls(dict(cfg or {}), ctx)
        out = {}
        for k in (mod.kv_arn(B, opts or {}) + ':' + A.acm_key_type(B),
                  mod.kv_arn(B, opts or {})):
            v = ctx.kv_get(k)
            if v:
                out[k] = v
        return out or None
    except Exception:                                   # noqa: BLE001
        return None


ANSWERS['acme_push'] = [
    {'method': 'GET', 'url': r'[?&]api=acme-push-hello$', 'body': {
        'ok': True, 'protocol': [1], 'app': 'otp', 'version': '1.0.210', 'on': True,
        'app_id': PUSH_PIN['app_id'], 'enc_key': PUSH_PIN['enc_key'],
        'enc_alg': 'X25519-HKDF-SHA256-A256GCM', 'node': 'otp1', 'cluster': True,
        'nodes': ['otp1', 'otp2'], 'slots': ['node:otp1', 'node:otp2', 'vip'], 'paired': 1,
        'pairing': False}},
    {'method': 'POST', 'url': r'[?&]api=acme-push-pair$', 'body': {
        'ok': True, 'app': 'otp', 'app_id': PUSH_PIN['app_id'], 'key_id': 'acme-plan',
        'enc_key': PUSH_PIN['enc_key'], 'confirm': '{PUSH_CONFIRM}'}},
    {'method': 'POST', 'url': r'[?&]api=acme-push-inventory$', 'body': {
        'ok': True, 'app': 'otp', 'version': '1.0.210', 'cluster': True, 'slots': []}},
    {'method': 'POST', 'url': r'[?&]api=acme-push-install$', 'body': {
        'ok': True, 'installed': [{'slot': 'node:otp1', 'node': 'otp1',
                                   'names': ['\u2039the slot\'s names\u203a'],
                                   'state': 'installed'}],
        'said': 'put in for node:otp1 - each node puts it into nginx within seconds'}},
]
# A10 ACOS (aXAPI v3): the signature; the SSL files and keys there - two earlier ones of acme
# and, once imported, the new one; the template holds the earlier one beside the new one;
# every change answered {"response": {"status": "OK"}}
_A10_OK = {'response': {'status': 'OK'}}
ANSWERS['a10'] = [
    {'method': 'POST', 'url': r'/axapi/v3/auth$', 'body': {'authresponse': {
        'signature': '{SESSION}', 'description': 'the signature should be set in '
                                                  'Authorization header for following request.'}}},
    {'method': 'POST', 'url': r'/axapi/v3/active-partition/', 'body': _A10_OK},
    {'method': 'GET', 'url': r'/axapi/v3/file/ssl-(cert|key)/oper$', 'body': {
        'ssl-cert': {'oper': {'file-list': [
            {'file': '{SENT:certificate.cert}', 'type': 'certificate'},
            {'file': '{EARLIER}', 'type': 'certificate'},
            {'file': '{EARLIER2}', 'type': 'certificate'},
            {'file': 'acme-ca-{CAID}', 'type': 'certificate'}]}},
        'ssl-key': {'oper': {'file-list': [
            {'file': '{SENT:certificate.key}'}, {'file': '{EARLIER}'}, {'file': '{EARLIER2}'}]}}}},
    {'method': 'POST', 'url': r'/axapi/v3/file/ssl-(cert|key)$', 'body': _A10_OK},
    {'method': 'POST', 'url': r'/axapi/v3/slb/template/client-ssl/[^/]+/certificate$',
     'body': _A10_OK},
    {'method': 'GET', 'url': r'/axapi/v3/slb/template/client-ssl/[^/]+$', 'body': {
        'client-ssl': {'name': '{TAIL}', 'certificate-list': [
            {'cert': '{EARLIER}', 'key': '{EARLIER}'},
            {'cert': '{SENT:certificate.cert}', 'key': '{SENT:certificate.key}',
             'chain-cert': '{SENT:certificate.chain-cert}'}]}}},
    {'method': 'DELETE', 'url': r'/axapi/v3/slb/template/client-ssl/[^/]+/certificate/',
     'body': _A10_OK},
    {'method': 'POST', 'url': r'/axapi/v3/write/memory$', 'body': _A10_OK},
    {'method': 'POST', 'url': r'/axapi/v3/pki/delete$', 'body': _A10_OK},
    {'method': 'POST', 'url': r'/axapi/v3/logoff$', 'body': _A10_OK},
]
# Aria Automation (vracli over SSH): the ingress certificate there now is an earlier one of
# its names; validate, set, deploy.sh and rm go through (exit 0)
SSH_ANSWERS['aria_automation'] = [
    {'command': r'vracli certificate ingress --list', 'stdout': '{EARLIER_PEM}'},
    {'command': r'vracli certificate ingress --validate ', 'stdout': ''},
    {'command': r'vracli certificate ingress --set ', 'stdout': ''},
    {'command': r'/opt/scripts/deploy\.sh', 'stdout': ''},
    {'command': r"rm -f /root/acme-ingress-", 'stdout': ''},
]
# AOS-CX (REST): the session a cookie of the sign-in (and its CSRF token); the switch holds its
# own local-cert and two earlier acme certificates, the WebUI's (https-server) the newer one;
# the CAs not trusted yet; after the PATCH it uses the new one, as configured; the oldest no
# application uses is deleted (keep 1)
ANSWERS['aruba_aoscx'] = [
    {'method': 'POST', 'url': r'/rest/[^/]+/login\?', 'body': '',
     'headers': {'Set-Cookie': 'id=PLANSESSION0token; Path=/; HttpOnly; Secure',
                 'x-csrf-token': 'PLANSESSION0token'}},
    {'method': 'POST', 'url': r'/rest/[^/]+/logout$', 'body': ''},
    {'method': 'GET', 'url': r'/rest/[^/]+/certificates$', 'body': {
        'local-cert': '/rest/v10.13/certificates/local-cert',
        '{EARLIER:32:6}': '/rest/v10.13/certificates/{EARLIER:32:6}',
        '{EARLIER2:32:6}': '/rest/v10.13/certificates/{EARLIER2:32:6}'}},
    {'method': 'GET', 'url': r'/rest/[^/]+/system/pki_ta_profiles$', 'body': {
        'corp-root-ca': '/rest/v10.13/system/pki_ta_profiles/corp-root-ca',
        'acme-ca-{CAID}': '/rest/v10.13/system/pki_ta_profiles/acme-ca-{CAID}'}},
    {'method': 'POST', 'url': r'/rest/[^/]+/system/pki_ta_profiles$', 'status': 201, 'body': ''},
    {'method': 'PUT', 'url': r'/rest/[^/]+/certificates/[^/?]+$', 'body': ''},
    {'method': 'GET', 'url': r'/system\?attributes=certificate_association$', 'times': 1,
     'body': {'certificate_association': {'https-server': '{EARLIER:32:6}'}}},
    {'method': 'GET', 'url': r'/system\?attributes=certificate_association$', 'body': {
        'certificate_association': {'https-server': '{CURRENT:32:6}'}}},
    {'method': 'GET', 'url': r'/system\?attributes=certificate_association_status$', 'body': {
        'certificate_association_status': {'https-server': {
            'status': 'up', 'status_reason': 'as_configured'}}}},
    {'method': 'PATCH', 'url': r'/rest/[^/]+/system$', 'status': 204, 'body': ''},
    {'method': 'PUT', 'url': r'/fullconfigs/startup-config\?from=', 'body': ''},
    {'method': 'DELETE', 'url': r'/rest/[^/]+/certificates/', 'status': 204, 'body': ''},
]
# Aruba Central: the token refresh gives a token and a new refresh token; the name asked for is
# in the store (a server certificate) - replaced under that name (FIRST: not there, uploaded)
ANSWERS['aruba_central'] = [
    {'method': 'POST', 'url': r'/oauth2/token\?', 'body': {
        'access_token': '{SESSION}', 'refresh_token': '{SESSION}', 'token_type': 'bearer',
        'expires_in': 7200}},
    {'method': 'GET', 'url': r'/configuration/v1/certificates\?', 'body': {'items': [
        {'cert_name': '{OPT:cert_name}', 'cert_type': 'SERVER_CERT', 'cert_format': 'PEM',
         'expire_date': 'Feb 11 12:00:00 2027 GMT', 'cert_md5_checksum':
             '‹checksum›'}], 'total': 1}},
    {'method': 'POST', 'url': r'/configuration/v1/certificates$', 'body': {
        'cert_name': '{SENT:cert_name}', 'cert_type': 'SERVER_CERT'}},
    {'method': 'PUT', 'url': r'/configuration/v1/non_msp/certificate$', 'body': {
        'cert_name': '{SENT:cert_name}', 'cert_type': 'SERVER_CERT'}},
]
# ClearPass's staging web server: the staged PKCS#12 removed
SSH_ANSWERS['aruba_clearpass'] = [{'command': r"^rm -f .*acme-[0-9a-f]+\.p12", 'stdout': ''}]
# Avi Controller: the session and CSRF cookies of the sign-in (22.1: avi-sessionid, its
# version); the new certificate is not there yet, the chain's CA is (by the name asked); the
# certificates listed: the new one, two earlier ones of acme, the Controller's own; each
# virtual service asked uses the earlier one - replaced, the oldest deleted (keep 1)
_AVI_REF = 'https://‹controller›/api/sslkeyandcertificate/'
ANSWERS['avi'] = [
    {'method': 'POST', 'url': r'/login$', 'headers': {
        'Content-Type': 'application/json',
        'Set-Cookie': 'csrftoken=PLANSESSION0token; Path=/; Secure, avi-sessionid='
                      'PLANSESSION0token; HttpOnly; Path=/; Secure'},
     'body': {'session_cookie_name': 'avi-sessionid', 'version': {
         'Version': '22.1.6', 'build': 9191, 'Product': 'controller'},
         'user': {'username': '{CFG:user}'}}},
    {'method': 'POST', 'url': r'/logout$', 'body': ''},
    {'method': 'GET', 'url': r'/api/sslkeyandcertificate\?name=acme-ca-', 'body': {
        'count': 1, 'results': [{
            'name': '{SEEN:sslkeyandcertificate\\?name=(acme-ca-[0-9a-f]+)}',
            'uuid': 'sslkeyandcertificate-‹ca›', 'type': 'SSL_CERTIFICATE_TYPE_CA'}]}},
    {'method': 'GET', 'url': r'/api/sslkeyandcertificate\?name=', 'body': {
        'count': 0, 'results': []}},
    {'method': 'POST', 'url': r'/api/sslkeyandcertificate$', 'status': 201, 'body': {
        'uuid': 'sslkeyandcertificate-‹new›', 'name': '{SENT:name}',
        'type': '{SENT:type}', 'url': _AVI_REF + 'sslkeyandcertificate-‹new›'}},
    {'method': 'GET', 'url': r'/api/sslkeyandcertificate\?page_size=', 'body': {
        'count': 4, 'results': [
            {'name': '{SENT:name}', 'uuid': 'sslkeyandcertificate-‹new›'},
            {'name': '{EARLIER}', 'uuid': 'sslkeyandcertificate-‹earlier›'},
            {'name': '{EARLIER2}', 'uuid': 'sslkeyandcertificate-‹oldest›'},
            {'name': 'System-Default-Cert', 'uuid': 'sslkeyandcertificate-‹default›'}]}},
    {'method': 'GET', 'url': r'/api/virtualservice\?name=', 'body': {'count': 1, 'results': [
        {'name': '{EACH:OPT:virtual_services}', 'uuid': 'virtualservice-‹uuid›',
         'ssl_key_and_certificate_refs': [_AVI_REF + 'sslkeyandcertificate-‹earlier›']}]}},
    {'method': 'PATCH', 'url': r'/api/virtualservice/', 'body': {
        'uuid': 'virtualservice-‹uuid›'}},
    {'method': 'GET', 'url': r'/api/systemconfiguration$', 'body': {'portal_configuration': {
        'enable_https': True, 'redirect_to_https': True, 'sslkeyandcertificate_refs': [
            _AVI_REF + 'sslkeyandcertificate-‹earlier›']}}},
    {'method': 'PATCH', 'url': r'/api/systemconfiguration$', 'body': {}},
    {'method': 'DELETE', 'url': r'/api/sslkeyandcertificate/', 'status': 204, 'body': ''},
]
# Microsoft Entra: an app registration's client-credentials token
_ENTRA = {'method': 'POST', 'url': r'/oauth2/v2\.0/token$', 'body': {
    'token_type': 'Bearer', 'expires_in': 3599, 'ext_expires_in': 3599,
    'access_token': '{SESSION}'}}
# Azure Application Gateway: a running gateway (Succeeded, with a managed identity) holding two
# earlier acme certificates (uploaded) and the Key Vault one (its secret as set), its HTTPS
# listeners asked for on the newer earlier one; the PUT starts an update (Updating), the next
# read says Succeeded; the oldest certificate, used by no listener, taken out (keep 1)
_AGW = '/subscriptions/{CFG:subscription_id}/resourceGroups/{CFG:resource_group}/providers/' \
       'Microsoft.Network/applicationGateways/{OPT:gateway}'


def _agw(state):
    return {'name': '{OPT:gateway}', 'id': _AGW, 'location': 'westeurope',
            'etag': 'W/"‹etag›"', 'tags': {'acme-certificate': '5a0e1d2c3b4a5968'},
            'identity': {'type': 'UserAssigned', 'userAssignedIdentities': {
                '/subscriptions/{CFG:subscription_id}/resourceGroups/{CFG:resource_group}/'
                'providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-agw': {}}},
            'properties': {
                'provisioningState': state, 'operationalState': 'Running',
                'sslCertificates': [
                    {'name': '{EARLIER:80}', 'id': _AGW + '/sslCertificates/{EARLIER:80}',
                     'properties': {'publicCertData': '‹PKCS#7, base64›'}},
                    {'name': '{EARLIER2:80}', 'id': _AGW + '/sslCertificates/{EARLIER2:80}',
                     'properties': {'publicCertData': '‹PKCS#7, base64›'}},
                    {'name': 'acme-{LABEL:70}', 'id': _AGW + '/sslCertificates/acme-{LABEL:70}',
                     'properties': {'keyVaultSecretId': '{OPT:key_vault_secret_id}'}},
                    {'name': '{EACH:OPT:cert_name}', 'id': _AGW + '/sslCertificates/'
                     '{EACH:OPT:cert_name}', 'properties': {
                         'publicCertData': '\u2039PKCS#7, base64\u203a'}}],
                'httpListeners': [
                    {'name': '{EACH:OPT:listener}', 'properties': {
                        'protocol': 'Https', 'hostName': '{CERTNAME}', 'sslCertificate': {
                            'id': _AGW + '/sslCertificates/{EARLIER:80}'}}},
                    {'name': '{EACH:OPT:listeners}', 'properties': {
                        'protocol': 'Https', 'hostName': '{CERTNAME}', 'sslCertificate': {
                            'id': _AGW + '/sslCertificates/{EARLIER:80}'}}},
                    {'name': 'http-www', 'properties': {'protocol': 'Http'}}]}}


ANSWERS['azure_appgw'] = [
    _ENTRA,
    {'method': 'GET', 'url': r'/applicationGateways/[^/?]+\?', 'times': 1,
     'body': _agw('Succeeded')},
    {'method': 'PUT', 'url': r'/applicationGateways/[^/?]+\?', 'body': _agw('Updating')},
    {'method': 'GET', 'url': r'/applicationGateways/[^/?]+\?', 'times': 1,
     'body': _agw('Updating')},
    {'method': 'GET', 'url': r'/applicationGateways/[^/?]+\?', 'body': _agw('Succeeded')},
    {'method': 'PATCH', 'url': r'/applicationGateways/[^/?]+\?', 'body': _agw('Succeeded')},
]
# Azure App Service: the new certificate is not there yet (404), the web app runs on its plan;
# its custom hostnames (those asked, the certificate's first name) are bound SNI SSL to the
# earlier certificate; the list holds two earlier ones - the oldest deleted (keep 1)
_ASP = '/subscriptions/{CFG:subscription_id}/resourceGroups/{CFG:resource_group}/providers/' \
       'Microsoft.Web'
_ASP_BIND = {'properties': {'sslState': 'SniEnabled', 'thumbprint':
                            '5A0E1D2C3B4A59687706F5E4D3C2B1A098877665', 'hostNameType': 'Verified',
                            'customHostNameDnsRecordType': 'CName'}}
ANSWERS['azure_appservice'] = [
    _ENTRA,
    {'method': 'GET', 'url': r'/Microsoft\.Web/certificates/[^/?]+\?', 'status': 404, 'body': {
        'error': {'code': 'ResourceNotFound', 'message': "The Resource 'Microsoft.Web/"
                  "certificates/{TAIL}' under resource group '{CFG:resource_group}' was not "
                  "found."}}},
    {'method': 'GET', 'url': r'/Microsoft\.Web/sites/[^/?]+\?', 'body': {
        'name': '{OPT:site}', 'location': 'West Europe', 'id': _ASP + '/sites/{OPT:site}',
        'properties': {'state': 'Running', 'serverFarmId': _ASP + '/serverfarms/asp-www',
                       'hostNames': ['{CERTNAME}', '{OPT:site}.azurewebsites.net']}}},
    {'method': 'PUT', 'url': r'/Microsoft\.Web/certificates/[^/?]+\?', 'body': {
        'name': '{TAIL}', 'location': 'West Europe', 'properties': {
            'thumbprint': '{FP1}', 'subjectName': '{CERTNAME}', 'hostNames': ['{CERTNAMES}']}}},
    {'method': 'GET', 'url': r'/hostNameBindings\?', 'body': {'value': [
        dict(_ASP_BIND, name='{OPT:site}/{CERTNAME}'),
        dict(_ASP_BIND, name='{OPT:site}/{EACH:OPT:hostnames}'),
        {'name': '{OPT:site}/{OPT:site}.azurewebsites.net', 'properties': {
            'sslState': 'Disabled', 'hostNameType': 'Verified'}}]}},
    {'method': 'PUT', 'url': r'/hostNameBindings/[^/?]+\?', 'body': {
        'properties': {'sslState': 'SniEnabled', 'thumbprint': '{SENT:properties.thumbprint}'}}},
    {'method': 'GET', 'url': r'/Microsoft\.Web/certificates\?', 'body': {'value': [
        {'name': '{CURRENT}'}, {'name': '{EARLIER}'}, {'name': '{EARLIER2}'}]}},
    {'method': 'DELETE', 'url': r'/Microsoft\.Web/certificates/', 'body': ''},
]
# Azure Key Vault: the certificate's current version is an earlier one (another thumbprint) -
# a new version imported (FIRST: none of that name yet, 404)
_AKV_CERT = {'attributes': {'enabled': True, 'nbf': 1786000000, 'exp': 1793776000,
                            'recoveryLevel': 'Recoverable+Purgeable'},
             'policy': {'key_props': {'exportable': True, 'kty': 'RSA', 'reuse_key': False},
                        'secret_props': {'contentType': 'application/x-pem-file'}},
             'tags': {'managed-by': 'acme'}}
ANSWERS['azure_keyvault'] = [
    _ENTRA,
    {'method': 'GET', 'url': r'/certificates/[^/?]+\?api-version=', 'body': dict(
        _AKV_CERT, id='https://‹vault›/certificates/{TAIL}/‹earlier version›',
        x5t='Wg4dLDtKWWh3BvXk08KxoJiHdmU')},
    {'method': 'POST', 'url': r'/certificates/[^/?]+/import\?', 'body': dict(
        _AKV_CERT, id='https://‹vault›/certificates/{SEEN:/certificates/([^/?]+)/import}/'
                      '‹new version›', x5t='‹its thumbprint›')},
]
# Barracuda CGF: the store entry holds the earlier certificate before the import, the new one
# (its fingerprint) after it
ANSWERS['barracuda_cgf'] = [
    {'method': 'GET', 'url': r'/store/certificates/[^/?]+$', 'times': 1, 'body': {
        'name': '{TAIL}', 'comment': 'acme 5a0e1d2c3b4a5968', 'subCertificates': [{
            'subject': 'CN={CERTNAME}', 'issuer': 'CN={CACN}', 'fingerprint':
                '5a0e1d2c3b4a59687706f5e4d3c2b1a0988776655443322110ffeeddccbbaa99'}]}},
    {'method': 'GET', 'url': r'/store/certificates/[^/?]+$', 'body': {
        'name': '{TAIL}', 'comment': '{SENT:comment}', 'subCertificates': [{
            'subject': 'CN={CERTNAME}', 'issuer': 'CN={CACN}', 'fingerprint': '{FP}'}]}},
    {'method': 'GET', 'url': r'/store/certificates(\?expand=true)?$', 'body': {
        'certificates': ['{OPT:entry}']}},
    {'method': 'POST', 'url': r'/store/certificates$', 'status': 201, 'body': ''},
    {'method': 'PUT', 'url': r'/store/certificates/[^/?]+$', 'status': 204, 'body': ''},
]
# Barracuda WAF: the token of the sign-in; the new certificate is not there yet (404); each
# service's SSL security uses the earlier acme certificate; the list holds two earlier ones -
# the oldest, used by no service, deleted (keep 1)
_BWAF_OK = {'id': '{TAIL}', 'token': '{SESSION}', 'msg': 'Configuration updated'}
_BWAF_SSL = {'status': 'On', 'certificate': '{EARLIER}', 'ecdsa-certificate': '',
             'enable-sni': 'No', 'sni-certificate': [], 'sni-ecdsa-certificate': [],
             'domain': [], 'enable-tls-1-2': 'Yes', 'enable-tls-1-3': 'Yes'}
ANSWERS['barracuda_waf'] = [
    {'method': 'POST', 'url': r'/restapi/v[\d.]+/login$', 'status': 201, 'body': {
        'token': '{SESSION}'}},
    {'method': 'DELETE', 'url': r'/restapi/v[\d.]+/logout$', 'body': {'msg': 'Logged out'}},
    {'method': 'GET', 'url': r'/restapi/v[\d.]+/certificates(/signed-certificate)?$', 'body': {
        'data': {'{CURRENT}': {'name': '{CURRENT}'}, '{EARLIER}': {'name': '{EARLIER}'},
                 '{EARLIER2}': {'name': '{EARLIER2}'}}}},
    {'method': 'GET', 'url': r'/certificates(/signed-certificate)?/[^/?]+$', 'status': 404,
     'body': {'msg': 'Certificate {TAIL} does not exist', 'id': '{TAIL}'}},
    {'method': 'POST', 'url': r'/restapi/v[\d.]+/certificates', 'status': 201,
     'body': _BWAF_OK},
    {'method': 'GET', 'url': r'/services/[^/]+/ssl-security$', 'body': {'data': {
        '{SEEN:services/([^/\\s]+)/ssl-security}': {'SSL Security': _BWAF_SSL}}}},
    {'method': 'PUT', 'url': r'/services/[^/]+/ssl-security$', 'body': _BWAF_OK},
    {'method': 'GET', 'url': r'/restapi/v[\d.]+/services$', 'body': {'data': [
        {'name': '{EACH:OPT:service}', 'status': 'On'},
        {'name': '{EACH:OPT:services}', 'status': 'On'}]}},
    {'method': 'DELETE', 'url': r'/certificates(/signed-certificate)?/', 'body': _BWAF_OK},
]
# bunny.net: the pull zone (by its name or ID) with its system hostname and the custom ones -
# the certificate's first name and those asked - each with a certificate already; the new one
# takes its place (204)
_BUNNY_HOST = {'Id': 4207001, 'HasCertificate': True, 'IsSystemHostname': False,
               'ForceSSL': True, 'Certificate': '‹the one there›'}
_BUNNY_ZONE = {'Id': 1234567, 'Name': '{OPT:pull_zone}', 'OriginUrl': 'https://origin.{CERTNAME}',
               'Enabled': True, 'Hostnames': [
                   {'Id': 4207000, 'Value': '{OPT:pull_zone}.b-cdn.net', 'IsSystemHostname': True,
                    'HasCertificate': True, 'ForceSSL': False},
                   dict(_BUNNY_HOST, Value='{CERTNAME}'),
                   dict(_BUNNY_HOST, Value='{EACH:OPT:hostnames}')]}
ANSWERS['bunny'] = [
    {'method': 'GET', 'url': r'api\.bunny\.net/pullzone/\d+$', 'body': _BUNNY_ZONE},
    {'method': 'GET', 'url': r'api\.bunny\.net/pullzone\?search=', 'body': {
        'Items': [_BUNNY_ZONE], 'CurrentPage': 1, 'TotalItems': 1, 'HasMoreItems': False}},
    {'method': 'POST', 'url': r'/pullzone/\d+/addCertificate$', 'status': 204, 'body': ''},
]
# Two files written over SSH (targets/_files.py): sha256sum says the ones there (another
# certificate), the placing script says each existed and was placed (so its copy is kept and
# the older copies pruned), the temporary files removed
_FILES2_SSH = [
    {'command': r'sha256sum \S+ \S+ 2>/dev/null', 'stdout':
        '5a0e1d2c3b4a59687706f5e4d3c2b1a0988776655443322110ffeeddccbbaa99  '
        '{SEEN:sha256sum (\\S+) \\S+ 2>/dev/null}\n'
        '0b1c2d3e4f5a69788706f5e4d3c2b1a0988776655443322110ffeeddccbbaa11  '
        '{SEEN:sha256sum \\S+ (\\S+) 2>/dev/null}\n'},
    {'command': r'echo "PLACED \d+"', 'stdout': 'EXISTED 0\nPLACED 0\nEXISTED 1\nPLACED 1\n'},
    {'command': r'ls -1t -- ', 'stdout': ''},
    {'command': r'^rm -f /tmp/\.acme-', 'stdout': ''},
]
# Caddy: its admin API (curl on the machine) lists the certificates loaded through it - the
# earlier one of this certificate (its tag) and another - and takes the new list (200);
# files: as _FILES2_SSH, caddy reload says nothing
SSH_ANSWERS['caddy'] = [
    {'command': r'curl .* -X GET .*/config/apps/tls/certificates', 'stdout':
        '{"load_pem": [{"certificate": "‹the earlier certificate, PEM›", "key": '
        '"‹its key›", "tags": ["acme-{LABEL}"]}, {"certificate": "‹another '
        'certificate, PEM›", "key": "‹its key›", "tags": ["intranet"]}]}\n200'},
    {'command': r'curl .* -X (PATCH|POST) ', 'stdout': '\n200'},
    {'command': r'^rm -f /tmp/\.acme-caddy-', 'stdout': ''},
    {'command': r'caddy reload', 'stdout': ''},
] + _FILES2_SSH
# Check Point Management API (every command a POST of its own): the session; the dated new
# object is not there yet (a fixed one is - replaced in place); the server certificates are the
# new one and two earlier ones of acme - the oldest, used nowhere, deleted (keep 1); publish and
# install are tasks that succeed
_CP_TASK = {'task-id': '01234567-89ab-cdef-0123-456789abcdef'}
ANSWERS['checkpoint'] = [
    {'method': 'POST', 'url': r'/web_api/(v[\d.]+/)?login$', 'body': {
        'sid': '{SESSION}', 'uid': '‹session uid›', 'session-timeout': 600,
        'api-server-version': '1.9.1', 'url': 'https://{CFG:host}:443/web_api'}},
    {'method': 'POST', 'url': r'/web_api/(v[\d.]+/)?logout$', 'body': {'message': 'OK'}},
    {'method': 'POST', 'url': r'/show-server-certificate$', 'sent': r'"name": "acme-',
     'status': 404, 'body': {'code': 'generic_err_object_not_found',
                             'message': 'Requested object [{SENT:name}] not found'}},
    {'method': 'POST', 'url': r'/show-server-certificate$', 'body': {
        'uid': '‹object uid›', 'name': '{SENT:name}', 'type': 'server-certificate',
        'server-certificate': {'subject': 'CN={CERTNAME}', 'valid-to': {
            'iso-8601': '‹its end›'}}}},
    {'method': 'POST', 'url': r'/(add|set)-server-certificate$', 'body': {
        'uid': '‹object uid›', 'name': '{SENT:name}', 'type': 'server-certificate'}},
    {'method': 'POST', 'url': r'/set-https-rule$', 'body': {
        'uid': '‹rule uid›', 'type': 'https-rule', 'certificate': '{SENT:certificate}'}},
    {'method': 'POST', 'url': r'/set-simple-(gateway|cluster)$', 'body': {
        'uid': '‹gateway uid›', 'name': '{SENT:name}'}},
    {'method': 'POST', 'url': r'/show-server-certificates$', 'body': {
        'objects': [{'name': '{CURRENT}', 'type': 'server-certificate'},
                    {'name': '{EARLIER}', 'type': 'server-certificate'},
                    {'name': '{EARLIER2}', 'type': 'server-certificate'}],
        'from': 1, 'to': 3, 'total': 3}},
    {'method': 'POST', 'url': r'/where-used$', 'body': {
        'used-directly': {'total': 0, 'objects': []},
        'used-indirectly': {'total': 0, 'objects': []}}},
    {'method': 'POST', 'url': r'/delete-server-certificate$', 'body': {'message': 'OK'}},
    {'method': 'POST', 'url': r'/(publish|install-policy)$', 'body': _CP_TASK},
    {'method': 'POST', 'url': r'/show-task$', 'body': {'tasks': [dict(
        _CP_TASK, status='succeeded', **{'progress-percentage': 100})]}},
]
# Cisco ASA (HTTP interface, text answers): the trustpoints - two earlier ones of acme and the
# Smart Call Home one; ssl trust-point names the earlier one on the interface, then the new one
# (as the switch sent it); the PKCS#12 import completes; write memory says [OK]
_ASA_TEXT = {'Content-Type': 'text/plain'}
ANSWERS['cisco_asa'] = [
    {'method': 'GET', 'url': r'/admin/exec/show\+running-config\+crypto\+ca\+trustpoint$',
     'headers': _ASA_TEXT, 'body':
        'crypto ca trustpoint {EARLIER:128}\n keypair {EARLIER:128}\n crl configure\n'
        'crypto ca trustpoint {EARLIER2:128}\n keypair {EARLIER2:128}\n crl configure\n'
        'crypto ca trustpoint _SmartCallHome_ServerCA\n no validation-usage\n crl configure\n'},
    {'method': 'GET', 'url': r'/admin/exec/show\+running-config\+ssl\+trust-point$',
     'times': 1, 'headers': _ASA_TEXT, 'body': 'ssl trust-point {EARLIER:128} '
                                               '{OPT:trust_points}\n'},
    {'method': 'GET', 'url': r'/admin/exec/show\+running-config\+ssl\+trust-point$',
     'headers': _ASA_TEXT, 'body': 'ssl trust-point {SEEN:(?:^|\\n)ssl trust-point (\\S+ [^\\n]*)}\n'},
    {'method': 'POST', 'url': r'/admin/config$', 'sent': r'crypto ca import \S+ pkcs12',
     'headers': _ASA_TEXT, 'body': 'Enter the base 64 encoded pkcs12.\nEnd with the word "quit" '
                                   'on a line by itself:\nINFO: Import PKCS12 operation '
                                   'completed successfully.\n'},
    {'method': 'POST', 'url': r'/admin/config$', 'sent': r'no crypto ca trustpoint',
     'headers': _ASA_TEXT, 'body': 'WARNING: Removing an enrolled trustpoint will destroy all\n'
                                   'certificates received from the related\n'
                                   'Certificate Authority.\n'},
    {'method': 'POST', 'url': r'/admin/config$', 'headers': _ASA_TEXT, 'body': ''},
    {'method': 'GET', 'url': r'/admin/exec/write\+memory$', 'headers': _ASA_TEXT, 'body':
        'Building configuration...\nCryptochecksum: 5a0e1d2c 3b4a5968 7706f5e4 d3c2b1a0\n\n'
        '21834 bytes copied in 0.230 secs\n[OK]\n'},
]
# FTD Device Manager: the token; the Internal Certificates - the device's default and two
# earlier ones of acme; the chain's CA is an External CA Certificate already; the web interface
# (and the RA VPN) use the newer earlier one - switched, deployed (QUEUED, then DEPLOYED), the
# oldest (used by nothing) deleted (keep 1) and that deployed too
_FDM_EARLIER = {'id': '‹earlier object›', 'name': '{EARLIER:128}',
                'type': 'internalcertificate', 'version': '‹version›'}
ANSWERS['cisco_ftd_fdm'] = [
    {'method': 'POST', 'url': r'/fdm/token$', 'body': {
        'access_token': '{SESSION}', 'expires_in': 1800, 'token_type': 'Bearer',
        'refresh_token': '{SESSION}', 'refresh_expires_in': 2400}},
    {'method': 'GET', 'url': r'/object/internalcertificates\?', 'body': {'items': [
        {'id': '‹default object›', 'name': 'DefaultInternalCertificate',
         'type': 'internalcertificate'},
        _FDM_EARLIER,
        {'id': '‹oldest object›', 'name': '{EARLIER2:128}',
         'type': 'internalcertificate', 'version': '‹version›'}],
        'paging': {'prev': [], 'next': [], 'limit': 10, 'offset': 0, 'count': 3, 'pages': 0}}},
    {'method': 'POST', 'url': r'/object/internalcertificates$', 'body': {
        'id': '‹new object›', 'name': '{SENT:name}', 'type': 'internalcertificate',
        'version': '‹version›', 'certType': 'UPLOAD'}},
    {'method': 'GET', 'url': r'/object/externalcacertificates\?', 'body': {'items': [
        {'id': '‹ca object›', 'name': 'acme-ca-{CAID}', 'type': 'externalcacertificate',
         'version': '‹version›'}],
        'paging': {'limit': 10, 'offset': 0, 'count': 1, 'pages': 0}}},
    {'method': 'POST', 'url': r'/object/externalcacertificates$', 'body': {
        'id': '‹ca object›', 'name': '{SENT:name}', 'type': 'externalcacertificate'}},
    {'method': 'GET', 'url': r'/devicesettings/default/webuicertificates$', 'body': {'items': [{
        'id': '‹web ui setting›', 'type': 'webuicertificate',
        'version': '‹version›', 'certificate': _FDM_EARLIER, 'trustChain': []}]}},
    {'method': 'PUT', 'url': r'/devicesettings/default/webuicertificates/', 'body': {
        'id': '‹web ui setting›', 'type': 'webuicertificate'}},
    {'method': 'GET', 'url': r'/ravpns\?', 'body': {'items': [{
        'id': '‹ra vpn›', 'name': 'RAVPN', 'type': 'ravpn',
        'version': '‹version›', 'vpnGatewaySettings': {
            'serverCertificate': _FDM_EARLIER, 'type': 'vpngatewaysettings'}}],
        'paging': {'limit': 10, 'offset': 0, 'count': 1, 'pages': 0}}},
    {'method': 'PUT', 'url': r'/ravpns/', 'body': {'id': '‹ra vpn›', 'type': 'ravpn'}},
    {'method': 'POST', 'url': r'/operational/deploy$', 'body': {
        'id': '‹deployment›', 'type': 'deploymentstatus', 'state': 'QUEUED',
        'statusMessage': 'Deployment queued'}},
    {'method': 'GET', 'url': r'/operational/deploy/', 'body': {
        'id': '‹deployment›', 'type': 'deploymentstatus', 'state': 'DEPLOYED',
        'statusMessage': 'Deployed successfully'}},
    {'method': 'DELETE', 'url': r'/object/internalcertificates/', 'status': 204, 'body': ''},
]
# Cisco ISE (OpenAPI): the node's system certificates - its self-signed one, two earlier ones of
# acme (the newer for EAP and the portal); the chain's CA is trusted already (refused, said);
# the import takes the roles over; the oldest (in use nowhere) deleted (keep 1)
ANSWERS['cisco_ise'] = [
    {'method': 'GET', 'url': r'/api/v1/certs/system-certificate/[^/?]+\?size=', 'body': {
        'response': [
            {'id': '‹self-signed id›', 'friendlyName':
                'Default self-signed server certificate', 'usedBy': 'Admin, pxGrid',
             'issuedTo': '{CFG:node}', 'expirationDate': '‹its end›'},
            {'id': '‹earlier id›', 'friendlyName': '{EARLIER:60}',
             'usedBy': 'EAP Authentication, Portal', 'issuedTo': '{CERTNAME}',
             'expirationDate': '‹its end›', 'portalsUsingTheTag':
                 'Default Portal Certificate Group'},
            {'id': '‹oldest id›', 'friendlyName': '{EARLIER2:60}',
             'usedBy': 'Not in use', 'issuedTo': '{CERTNAME}',
             'expirationDate': '‹its end›'}], 'version': '1.0.0'}},
    {'method': 'POST', 'url': r'/api/v1/certs/trusted-certificate/import$', 'status': 400,
     'body': {'message': 'Trust certificate already exists in the Trusted Certificates store',
              'version': '1.0.0'}},
    {'method': 'POST', 'url': r'/api/v1/certs/system-certificate/import$', 'body': {
        'response': {'id': '‹new id›', 'message': 'Successfully imported the system '
                                                            'certificate', 'status': 'SUCCESS'},
        'version': '1.0.0'}},
    {'method': 'DELETE', 'url': r'/api/v1/certs/system-certificate/', 'body': {
        'response': {'message': 'Successfully deleted System Certificate'},
        'version': '1.0.0'}},
]
# Cisco NX-OS (NX-API JSON-RPC at /ins, one batch a call): NX-OS 10.4(3)F; the trustpoints - two
# earlier ones of acme; the import, delete, save, the switch of NX-API go through (each command
# answered null); NX-API answers again after its restart; show nxapi names the new trustpoint -
# the oldest is removed (keep 1)
_NX_OK = [{'jsonrpc': '2.0', 'result': None, 'id': 1}]
ANSWERS['cisco_nxos'] = [
    {'method': 'POST', 'url': r'/ins$', 'sent': r'"cmd": "show version"', 'body': [{
        'jsonrpc': '2.0', 'id': 1, 'result': {'body': {
            'nxos_ver_str': '10.4(3)F', 'host_name': 'n9k-1',
            'chassis_id': 'Nexus9000 C93180YC-FX Chassis', 'bios_ver_str': '05.47'}}}]},
    {'method': 'POST', 'url': r'/ins$', 'sent': r'"cmd": "show running-config \| include',
     'body': [{'jsonrpc': '2.0', 'id': 1, 'result': {'msg':
               'crypto ca trustpoint {EARLIER2:60}\ncrypto ca trustpoint {EARLIER:60}\n'}}]},
    {'method': 'POST', 'url': r'/ins$', 'sent': r'"cmd": "show nxapi"', 'body': [{
        'jsonrpc': '2.0', 'id': 1, 'result': {'msg':
            'nxapi enabled\nNXAPI timeout 10\nHTTPS Listen on port 443\nCertificate '
            'Information:\n    Trustpoint: {SEEN:nxapi certificate trustpoint ([^"\\s]+)}\n'
            '    Issuer:   CN={CACN}\n    Expires:  \u2039its end\u203a\n'}}]},
    {'method': 'POST', 'url': r'/ins$', 'body': _NX_OK},
]
# ---- end of targets a10 .. cisco_nxos ----
# ---- targets cisco_wlc9800 .. hpe_oneview ----
# CUCM: the CA certificates of the chain in <unit>-trust already at a renewal (the first time
# they are not: imported)
SSH_FIRST = {}
SSH_LATER = {}
SSH_LATER['cucm'] = [
    {'command': r'^$', 'input': r'^show cert list trust\nexit', 'stdout':
        'tomcat-trust/Cisco_Root_CA_2048.pem: Trust Certificate\n'
        'tomcat-trust/{CACN_}.pem: Trust Certificate\ntomcat-trust/{CACN2_}.pem: Trust '
        'Certificate\nCallManager-trust/{CACN_}.pem: Trust Certificate\n'
        'CallManager-trust/{CACN2_}.pem: Trust Certificate\n'
        'Successfully listed the trust certificates.\n'}]
# DigitalOcean: the certificate of this name not there yet, then uploaded (its id); the load
# balancers named (by name: listed; by ID: read) with an HTTPS rule on the earlier
# certificate, an HTTP one, a passthrough one; the account's certificates: the two earlier
# ones and the new one (the oldest deleted)
_DO_LB = {'id': '\u2039load balancer id\u203a', 'name': '{EACH:OPT:load_balancers}',
          'ip': '192.0.2.1', 'status': 'active', 'region': {'slug': 'fra1', 'name': 'Frankfurt 1'},
          'size_unit': 1, 'algorithm': 'round_robin', 'droplet_ids': [3164444, 3164445],
          'redirect_http_to_https': True, 'vpc_uuid': '\u2039vpc\u203a',
          'health_check': {'protocol': 'http', 'port': 80, 'path': '/'},
          'forwarding_rules': [
              {'entry_protocol': 'https', 'entry_port': 443, 'target_protocol': 'http',
               'target_port': 80, 'certificate_id': '\u2039earlier certificate id\u203a',
               'tls_passthrough': False},
              {'entry_protocol': 'http', 'entry_port': 80, 'target_protocol': 'http',
               'target_port': 80, 'certificate_id': '', 'tls_passthrough': False}]}
ANSWERS['digitalocean_lb'] = [
    {'method': 'GET', 'url': r'/v2/certificates\?name=', 'body': {
        'certificates': [], 'links': {}, 'meta': {'total': 0}}},
    {'method': 'POST', 'url': r'/v2/certificates$', 'status': 201, 'body': {'certificate': {
        'id': '\u2039new certificate id\u203a', 'name': '{SENT:name}', 'type': 'custom',
        'state': 'verified', 'dns_names': '{CERTNAMES}', 'sha1_fingerprint': '{FP1}'}}},
    {'method': 'GET', 'url': r'/v2/load_balancers\?', 'body': {
        'load_balancers': [_DO_LB], 'links': {}, 'meta': {'total': 1}}},
    {'method': 'GET', 'url': r'/v2/load_balancers/[^/?]+$', 'body': {
        'load_balancer': dict(_DO_LB, id='{TAIL}', name='lb-www')}},
    {'method': 'PUT', 'url': r'/v2/load_balancers/[^/?]+$', 'body': {
        'load_balancer': dict(_DO_LB, name='lb-www')}},
    {'method': 'GET', 'url': r'/v2/certificates\?page=', 'body': {'certificates': [
        {'id': '\u2039older certificate id\u203a', 'name': '{EARLIER2}', 'type': 'custom',
         'state': 'verified'},
        {'id': '\u2039earlier certificate id\u203a', 'name': '{EARLIER}', 'type': 'custom',
         'state': 'verified'},
        {'id': '\u2039new certificate id\u203a', 'name': '{CURRENT}', 'type': 'custom',
         'state': 'verified'}], 'links': {}, 'meta': {'total': 3}}},
    {'method': 'DELETE', 'url': r'/v2/certificates/', 'status': 204, 'body': ''}]
# DirectAdmin (the new API): the domain's certificates - its own and the one acme replaces,
# for the certificate's names; the files of a slot are the earlier certificate; the PUT
# (dry run, then for real) takes it. The legacy CMD_API_SSL says error=0
ANSWERS['directadmin_ssl'] = [
    {'method': 'GET', 'url': r'/domain-tls/domains/[^/]+/certs$', 'body': {
        'certIds': ['\u2039webmail slot\u203a', '\u2039certificate slot\u203a'],
        'missingDNSNames': [], 'certs': [
            {'id': '\u2039webmail slot\u203a', 'autorenewEnabled': True, 'error': '',
             'certificate': {'dnsNames': ['webmail.{OPT:da_domain}'],
                             'notAfter': '2026-12-20T10:00:00Z'}},
            {'id': '\u2039certificate slot\u203a', 'autorenewEnabled': False, 'error': '',
             'certificate': {'dnsNames': '{CERTNAMES}', 'notAfter': '2026-12-01T10:00:00Z'}}]}},
    {'method': 'GET', 'url': r'/domain-tls/domains/[^/]+/certs/[^/]+/files$', 'body': {
        'cert': '\u2039the earlier certificate, PEM\u203a', 'chain': [], 'error': ''}},
    {'method': 'PUT', 'url': r'/domain-tls/domains/[^/]+/certs/[^/]+/files\?', 'body': {
        'cert': '\u2039the certificate sent, PEM\u203a', 'error': ''}},
    {'method': 'GET', 'url': r'/CMD_API_SSL\?domain=', 'headers': {
        'Content-Type': 'text/plain'}, 'body': 'certificate=%E2%80%B9the+earlier+certificate'
        '%E2%80%BA&key=&cacert=&active=yes'},
    {'method': 'POST', 'url': r'/CMD_API_SSL$', 'headers': {'Content-Type': 'text/plain'},
     'body': 'error=0&text=Certificate+and+Key+Saved.&details='}]
# Docker Swarm: the secrets of two earlier certificates there (and one of the application),
# then the new ones too; each service named mounts the earlier pair as tls.crt / tls.key
# (root, 0444 / 0400); the update converges; the oldest pair removed
_SWARM_LS = 'db_password\n{EARLIER2:58}.crt\n{EARLIER2:58}.key\n{EARLIER:58}.crt\n{EARLIER:58}.key\n'
SSH_ANSWERS['docker_swarm'] = [
    {'command': r'secret ls --format', 'times': 1, 'stdout': _SWARM_LS},
    {'command': r'secret ls --format', 'stdout': _SWARM_LS + '{CURRENT:58}.crt\n{CURRENT:58}.key\n'},
    {'command': r'service inspect ', 'stdout':
        '[{"File":{"Name":"tls.crt","UID":"0","GID":"0","Mode":292},"SecretID":'
        '"\u2039secret id\u203a","SecretName":"{EARLIER:58}.crt"},{"File":{"Name":"tls.key",'
        '"UID":"0","GID":"0","Mode":256},"SecretID":"\u2039secret id\u203a","SecretName":'
        '"{EARLIER:58}.key"},{"File":{"Name":"db_password","UID":"0","GID":"0","Mode":292},'
        '"SecretID":"\u2039secret id\u203a","SecretName":"db_password"}]\n'},
    {'command': r'secret create ', 'stdout': '\u2039secret id\u203a\n'},
    {'command': r'service update ', 'stdout': '\u2039service\u203a\n'},
    {'command': r'secret rm ', 'stdout': '{SEEN:secret rm (\\S+)}\n'},
    {'command': r'^rm -f /tmp/\.acme-secret-', 'stdout': ''}]
# ESXi over SSH: rui.crt and rui.key there (an earlier certificate: other SHA-256s), both
# replaced (EXISTED, PLACED), hostd and vpxa restarted, the state saved to the boot bank
SSH_ANSWERS['esxi'] = [
    {'command': r'sha256sum /etc/vmware/ssl/rui\.crt', 'stdout':
        '3f1d0c5e8a2b4c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f  '
        '/etc/vmware/ssl/rui.crt\n'
        '9a8b7c6d5e4f30211203f4e5d6c7b8a9f0e1d2c3b4a5968778695a4b3c2d1e0f  '
        '/etc/vmware/ssl/rui.key\n'},
    {'command': r'echo "PLACED 0"', 'stdout': 'EXISTED 0\nPLACED 0\nEXISTED 1\nPLACED 1\n'},
    {'command': r'/etc/init.d/hostd restart', 'stdout':
        'hostd stopped.\nhostd started.\nvpxa stopped.\nvpxa started.\n'},
    {'command': r'services\.sh restart', 'stdout': 'Running services restart\n'},
    {'command': r'/sbin/auto-backup\.sh', 'stdout':
        'Saving current state in /bootbank\nClock updated.\n'},
    # the uploads taken away, the older dated copies pruned: nothing printed
    {'command': r'^rm -f /tmp/\.acme-', 'stdout': ''},
    {'command': r'ls -1t -- .*\.bak ', 'stdout': ''}]
# ESXi 8.0 U3 - 9.1 through vCenter: the service content says vCenter 8.0.3; the host is
# ESXi 8.0.3 of its name; the chain added to the trusted roots (its id)
ANSWERS['esxi@8.0.3'] = [
    {'method': 'GET', 'url': r'/ServiceInstance/ServiceInstance/content$', 'body': {
        'sessionManager': {'type': 'SessionManager', 'value': 'SessionManager'},
        'about': {'name': 'VMware vCenter Server', 'version': '8.0.3', 'build': '24322831',
                  'apiVersion': '8.0.3.0', 'productLineId': 'vpx'}}},
    {'method': 'GET', 'url': r'/HostSystem/[^/]+/summary$', 'body': {
        'config': {'name': '{CFG:esx_name}', 'product': {
            'name': 'VMware ESXi', 'fullName': 'VMware ESXi 8.0.3 build-24280767',
            'version': '8.0.3', 'build': '24280767'}},
        'runtime': {'connectionState': 'connected', 'inMaintenanceMode': False}}},
    {'method': 'POST', 'url': r'/certificate-management/vcenter/trusted-root-chains$',
     'status': 201, 'body': '"\u2039chain id\u203a"'},
    # the methods that return nothing (204), the sessions ended
    {'method': 'POST', 'url': r'/HostCertificateManager/[^/]+/(ProvisionServerPrivateKey|'
                              r'InstallServerCertificate|NotifyAffectedServices)$',
     'status': 204, 'body': ''},
    {'method': 'POST', 'url': r'/SessionManager/[^/]+/Logout$', 'status': 204, 'body': ''},
    {'method': 'DELETE', 'url': r'/api/session$', 'status': 204, 'body': ''}]
# BIG-IP: the new key and certificate not there yet (404), the chain there already (the same
# intermediate as at the earlier renewal); the uploads and installs taken; the profile's
# cert-key-chain on the earlier certificate; the partition's certificates: three earlier
# ones, the new one, the chain, the default (beyond the 2 kept: the oldest deleted)
_F5_ITEM = {'kind': 'tm:sys:file:ssl-cert:ssl-certstate', 'partition': '{OPT:partition}'}
ANSWERS['f5'][1:1] = [
    {'method': 'GET', 'url': r'/mgmt/tm/sys/crypto/cert/~[^/?]*~acme-chain-', 'body': dict(
        _F5_ITEM, name='{TAIL}', fullPath='{TAIL}', certificateKeyCurveName='none',
        issuer='CN=\u2039the root\u203a')},
    {'method': 'GET', 'url': r'/mgmt/tm/sys/crypto/(cert|key)/~[^/?]+$', 'status': 404, 'body': {
        'code': 404, 'message': '01020036:3: The requested Certificate File (\u2039name\u203a) '
        'was not found.', 'errorStack': [], 'apiError': 3}},
    {'method': 'POST', 'url': r'/mgmt/shared/file-transfer/uploads/', 'body': {
        'remainingByteCount': 0, 'usedChunks': {'0': 1}, 'totalByteCount': 1,
        'localFilePath': '/var/config/rest/downloads/{TAIL}', 'temporaryFilePath':
        '/var/config/rest/downloads/tmp/{TAIL}', 'generation': 0}},
    {'method': 'POST', 'url': r'/mgmt/tm/sys/crypto/(cert|key)$', 'body': {
        'kind': 'tm:sys:crypto:cert:certstate', 'command': 'install', 'name': '{SENT:name}',
        'from-local-file': '{SENT:from-local-file}'}},
    {'method': 'POST', 'url': r'/mgmt/tm/util/unix-rm$', 'body': {
        'kind': 'tm:util:unix-rm:runstate', 'command': 'run',
        'utilCmdArgs': '{SENT:utilCmdArgs}'}},
    {'method': 'GET', 'url': r'/mgmt/tm/ltm/profile/client-ssl/', 'body': {
        'kind': 'tm:ltm:profile:client-ssl:client-sslstate', 'name': '{TAIL}',
        'defaultsFrom': '/Common/clientssl', 'certKeyChain': [
            {'name': 'default', 'cert': '/Common/{EARLIER}', 'key': '/Common/{EARLIER}',
             'chain': '/Common/acme-chain-\u2039id\u203a'}]}},
    {'method': 'PATCH', 'url': r'/mgmt/tm/ltm/profile/client-ssl/', 'body': {
        'kind': 'tm:ltm:profile:client-ssl:client-sslstate', 'name': '{TAIL}'}},
    {'method': 'GET', 'url': r'/mgmt/tm/sys/crypto/cert\?\$filter=partition', 'body': {
        'kind': 'tm:sys:crypto:cert:certcollectionstate', 'items': [
            dict(_F5_ITEM, name='default.crt'), dict(_F5_ITEM, name='{EARLIER3}'),
            dict(_F5_ITEM, name='{EARLIER2}'), dict(_F5_ITEM, name='{EARLIER}'),
            dict(_F5_ITEM, name='{CURRENT}'),
            dict(_F5_ITEM, name='acme-chain-\u2039id\u203a')]}},
    {'method': 'POST', 'url': r'/mgmt/tm/sys/config$', 'body': {
        'kind': 'tm:sys:config:savestate', 'command': 'save'}},
    {'method': 'POST', 'url': r'/mgmt/tm/cm$', 'body': {
        'kind': 'tm:cm:runstate', 'command': 'run', 'utilCmdArgs': '{SENT:utilCmdArgs}'}},
    {'method': 'DELETE', 'url': r'/mgmt/tm/sys/crypto/(cert|key)/', 'body': ''},
    {'method': 'DELETE', 'url': r'/mgmt/shared/authz/tokens/', 'body': {
        'token': '\u2039session\u203a', 'name': '\u2039session\u203a',
        'kind': 'shared:authz:tokens:authtokenitemstate'}}]
# Fastly: the TLS certificates - the earlier one acme put there (its activations kept), the
# one named by its ID, another; the private keys of the two earlier ones (not this one's);
# the key uploaded, the certificate replaced in place; unused keys: the two earlier ones (the
# older deleted)
_FASTLY_CERT = {'type': 'tls_certificate', 'attributes': {
    'issued_to': '{CERTNAME}', 'issuer': "Let's Encrypt", 'replace': False,
    'not_after': '2026-12-01T10:00:00.000Z'}}
_FASTLY_KEY = {'type': 'tls_private_key', 'attributes': {'key_type': 'RSA', 'key_length': 2048,
                                                         'replace': False}}
ANSWERS['fastly'] = [
    {'method': 'GET', 'url': r'/tls/certificates\?', 'body': {'data': [
        {'id': '\u2039certificate id\u203a', 'type': 'tls_certificate', 'attributes': dict(
            _FASTLY_CERT['attributes'], name='{EARLIER}')},
        {'id': '{OPT:certificate_id}', 'type': 'tls_certificate', 'attributes': dict(
            _FASTLY_CERT['attributes'], name='www (uploaded by hand)')},
        {'id': '\u2039other certificate id\u203a', 'type': 'tls_certificate', 'attributes': dict(
            _FASTLY_CERT['attributes'], name='api.example.org', issued_to='api.example.org')}],
        'meta': {'per_page': 100, 'current_page': 1, 'record_count': 3, 'total_pages': 1}}},
    {'method': 'GET', 'url': r'/tls/private_keys\?filter', 'body': {'data': [
        dict(_FASTLY_KEY, id='\u2039older key id\u203a', attributes=dict(
            _FASTLY_KEY['attributes'], name='{EARLIER2}')),
        dict(_FASTLY_KEY, id='\u2039earlier key id\u203a', attributes=dict(
            _FASTLY_KEY['attributes'], name='{EARLIER}'))],
        'meta': {'per_page': 100, 'current_page': 1, 'record_count': 2, 'total_pages': 1}}},
    {'method': 'GET', 'url': r'/tls/private_keys\?', 'body': {'data': [
        dict(_FASTLY_KEY, id='\u2039older key id\u203a', attributes=dict(
            _FASTLY_KEY['attributes'], name='{EARLIER2}')),
        dict(_FASTLY_KEY, id='\u2039earlier key id\u203a', attributes=dict(
            _FASTLY_KEY['attributes'], name='{EARLIER}'))],
        'meta': {'per_page': 100, 'current_page': 1, 'record_count': 2, 'total_pages': 1}}},
    {'method': 'POST', 'url': r'/tls/private_keys$', 'status': 201, 'body': {'data': dict(
        _FASTLY_KEY, id='\u2039new key id\u203a', attributes=dict(
            _FASTLY_KEY['attributes'], name='{SENT:data.attributes.name}'))}},
    {'method': 'PATCH', 'url': r'/tls/certificates/', 'body': {'data': dict(
        _FASTLY_CERT, id='{SENT:data.id}', attributes=dict(
            _FASTLY_CERT['attributes'], name='{SENT:data.attributes.name}'))}},
    {'method': 'POST', 'url': r'/tls/certificates$', 'status': 201, 'body': {'data': dict(
        _FASTLY_CERT, id='\u2039new certificate id\u203a')}},
    {'method': 'DELETE', 'url': r'/tls/private_keys/', 'status': 204, 'body': ''}]
# Flowmon: the token; the reusable TLS setting named is there with the pair of this
# certificate (by the name given, else its label) - replaced; the listening ports named take
# flows over TLS already (with the earlier certificate)
ANSWERS['flowmon'] = [
    {'method': 'POST', 'url': r'/resources/oauth/token$', 'body': {
        'access_token': '{SESSION}', 'token_type': 'bearer', 'expires_in': 7199,
        'scope': 'all'}},
    {'method': 'GET', 'url': r'/rest/fcc/reusable-settings-tls$', 'body': [
        {'id': '\u2039setting id\u203a', 'name': '{OPT:tls_setting}', 'description': '',
         'usageCount': 1}]},
    {'method': 'GET', 'url': r'/rest/fcc/reusable-settings-tls/[^/]+/pairs$', 'body': [
        {'id': '\u2039pair id\u203a', 'name': '{OPT:pair}', 'usageCount': 2,
         'description': 'acme', 'parsedCertificate': {'validTo': '2026-12-01T10:00:00Z'}},
        {'id': '\u2039pair id\u203a', 'name': '{LABEL:100}', 'usageCount': 2,
         'description': 'acme', 'parsedCertificate': {'validTo': '2026-12-01T10:00:00Z'}}]},
    {'method': 'PUT', 'url': r'/pairs$', 'body': {'id': '\u2039pair id\u203a'}},
    {'method': 'POST', 'url': r'/pairs$', 'status': 201, 'body': {'id': '\u2039pair id\u203a'}},
    {'method': 'POST', 'url': r'/rest/fcc/reusable-settings-tls$', 'status': 201, 'body': {
        'id': '\u2039setting id\u203a', 'name': '{OPT:tls_setting}'}},
    {'method': 'GET', 'url': r'/rest/fcc/listening-ports$', 'body': [
        {'id': '\u2039port id\u203a', 'name': '{EACH:OPT:listening_ports}', 'secure': True,
         'tcpCollector': {'name': 'p6343', 'localPort': 6343}, 'stats': {'flows': 1520311},
         'certificates': {'keyExtension': 'pem', 'crtExtension': 'pem',
                          'cacrtExtension': 'pem'}}]},
    {'method': 'PUT', 'url': r'/rest/fcc/listening-ports$', 'body': {
        'id': '\u2039port id\u203a', 'secure': True}}]
# FortiADC: the token; the local certificates: the factory one and two earlier acme ones (the
# new one too after the upload); the groups: the one named and another; the group holds the
# earlier certificate as its default member (the new one after the change); the client SSL
# profiles named present the group already, the virtual servers the first profile
_FADC_LOCAL = [{'mkey': 'Factory', 'type': 'CertKey', 'status': 'normal'},
               {'mkey': '{EARLIER2}', 'type': 'CertKey', 'status': 'normal'},
               {'mkey': '{EARLIER}', 'type': 'CertKey', 'status': 'normal'}]
ANSWERS['fortiadc'] = [
    {'method': 'POST', 'url': r'/api/user/login', 'body': {'token': '{SESSION}'},
     'headers': {'Content-Type': 'application/json',
                 'Set-Cookie': 'last_login=PLANSESSION0token; Path=/; Secure; HttpOnly'}},
    {'method': 'GET', 'url': r'/api/system_certificate_local(\?|$)', 'times': 1, 'body': {
        'payload': _FADC_LOCAL}},
    {'method': 'GET', 'url': r'/api/system_certificate_local(\?|$)', 'body': {
        'payload': _FADC_LOCAL + [{'mkey': '{CURRENT}', 'type': 'CertKey', 'status': 'normal'}]}},
    {'method': 'GET', 'url': r'/api/system_certificate_local_cert_group(\?|$)', 'body': {
        'payload': [{'mkey': '{OPT:cert_group}'}, {'mkey': 'LOCAL_CERT_GROUP'}]}},
    {'method': 'GET', 'url': r'_child_group_member\?pkey=', 'times': 1, 'body': {'payload': [
        {'mkey': '1', 'local_cert': '{EARLIER}', 'default': 'enable',
         'OCSP_stapling': 'disable', 'intermediate_cag': '{OPT:intermediate_cag}'}]}},
    {'method': 'GET', 'url': r'_child_group_member\?pkey=', 'body': {'payload': [
        {'mkey': '2', 'local_cert': '{CURRENT}', 'default': 'enable',
         'OCSP_stapling': 'disable', 'intermediate_cag': '{OPT:intermediate_cag}'}]}},
    {'method': 'GET', 'url': r'/api/load_balance_client_ssl_profile\?mkey=', 'body': {
        'payload': [{'mkey': '{TAIL}', 'local_certificate_group': '{OPT:cert_group}',
                     'ssl_ciphers': 'ECDHE-RSA-AES256-GCM-SHA384', 'ssl_session_cache_flag':
                     'enable'}]}},
    {'method': 'GET', 'url': r'/api/load_balance_virtual_server\?mkey=', 'body': {
        'payload': [{'mkey': '\u2039virtual server\u203a', 'status': 'enable',
                     'client_ssl_profile': '{OPT:client_ssl_profiles}', 'port': '443'}]}},
    {'body': {'payload': 0}}]
# FortiGate: its status says FortiOS 7.4.5 (6.4.15, 7.2.10 for those versions); the new
# certificate not there yet (404); the inspection profiles named present the earlier
# certificate and one of their own, the VIPs the earlier one (a name before 7.4.2, a list
# after); the certificates: three earlier ones, the new one, the factory one (beyond the 2
# kept: the oldest deleted)
_FGT_STATUS = {'http_method': 'GET', 'status': 'success', 'serial': 'FGT60F\u2039serial\u203a',
               'version': 'v7.4.5', 'build': 2702, 'vdom': 'root', 'results': {
                   'model_name': 'FortiGate', 'model_number': '60F', 'hostname': 'fw01'}}
ANSWERS['fortigate'] = [
    {'method': 'GET', 'url': r'/api/v2/monitor/system/status', 'body': _FGT_STATUS},
    {'method': 'GET', 'url': r'/api/v2/cmdb/vpn\.certificate/local/[^/?]+', 'status': 404,
     'body': {'http_method': 'GET', 'status': 'error', 'http_status': 404, 'vdom': 'root'}},
    {'method': 'POST', 'url': r'/vpn-certificate/(local|ca)/import', 'body': {
        'http_method': 'POST', 'status': 'success', 'http_status': 200,
        'results': {'mkey': '{SENT:certname}'}}},
    {'method': 'GET', 'url': r'/api/v2/cmdb/firewall/ssl-ssh-profile/', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': '{TAIL}', 'server-cert-mode': 're-sign', 'server-cert': [
                {'name': '{EARLIER:35:6}'}, {'name': 'Fortinet_SSL'}]}]}},
    {'method': 'GET', 'url': r'/api/v2/cmdb/firewall/vip/', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': '{TAIL}', 'type': 'server-load-balance', 'server-type': 'https',
             'ssl-certificate': [{'name': '{EARLIER:35:6}'}]}]}},
    {'method': 'GET', 'url': r'/api/v2/cmdb/vpn\.certificate/local\?', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': 'Fortinet_Factory'}, {'name': 'Fortinet_SSL'},
            {'name': '{EARLIER3:35:6}'}, {'name': '{EARLIER2:35:6}'},
            {'name': '{EARLIER:35:6}'}, {'name': '{CURRENT:35:6}'}]}},
    {'body': {'http_method': 'PUT', 'status': 'success', 'http_status': 200}}]
ANSWERS['fortigate@6.0'] = [
    {'method': 'GET', 'url': r'/api/v2/monitor/system/status', 'body': dict(
        _FGT_STATUS, version='v6.4.15', build=2095)},
    {'method': 'GET', 'url': r'/api/v2/cmdb/firewall/ssl-ssh-profile/', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': '{TAIL}', 'server-cert-mode': 'replace', 'server-cert': '{EARLIER:35:6}'}]}},
    {'method': 'GET', 'url': r'/api/v2/cmdb/firewall/vip/', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': '{TAIL}', 'ssl-certificate': '{EARLIER:35:6}'}]}}]
ANSWERS['fortigate@7.0'] = [
    {'method': 'GET', 'url': r'/api/v2/monitor/system/status', 'body': dict(
        _FGT_STATUS, version='v7.2.10', build=1706)},
    {'method': 'GET', 'url': r'/api/v2/cmdb/firewall/vip/', 'body': {
        'http_method': 'GET', 'status': 'success', 'results': [
            {'name': '{TAIL}', 'ssl-certificate': '{EARLIER:35:6}'}]}}]
# FortiWeb: the new local certificate not there yet (-3); the intermediate CA group of the
# chain there already (a renewal); each server policy named on the earlier certificate (and
# that group); the local certificates: the defaults, two earlier ones, the new one (beyond
# the 1 kept: the oldest deleted)
_FWB_GROUP = '{SEEN:certificate\\.intermediate-certificate-group\\?mkey=([A-Za-z0-9_.-]+)}'
_FWB_POL = {'name': '{TAIL}', 'deployment-mode': 'server-pool', 'ssl': 'enable',
            'certificate': '{EARLIER}', 'intermediate-certificate-group': _FWB_GROUP,
            'vserver': 'vs-www', 'service': 'HTTPS'}
ANSWERS['fortiweb'] = [
    {'method': 'GET', 'url': r'/cmdb/system/certificate\.local\?mkey=', 'status': 500,
     'body': {'results': {'errcode': -3, 'message': 'Entry not found.'}}},
    {'method': 'GET', 'url': r'/cmdb/system/certificate\.local$', 'body': {'results': [
        {'name': 'defaultcert', 'status': 'ok'}, {'name': '{EARLIER2}', 'status': 'ok'},
        {'name': '{EARLIER}', 'status': 'ok'}, {'name': '{CURRENT}', 'status': 'ok'}]}},
    {'method': 'POST', 'url': r'/system/certificate\.local\.json_cert$', 'body': {
        'results': {'name': '{SENT:name}'}}},
    {'method': 'GET', 'url': r'/certificate\.intermediate-certificate-group\?mkey=', 'body': {
        'results': [{'name': _FWB_GROUP, 'q_ref': 1}]}},
    {'method': 'GET', 'url': r'/cmdb/server-policy/policy\?mkey=', 'body': {'results': [
        dict(_FWB_POL, name='{SEEN:server-policy/policy\\?mkey=([^&\\s]+)}')]}},
    {'method': 'GET', 'url': r'/cmdb/server-policy/policy$', 'body': {'results': [
        dict(_FWB_POL, name='{OPT:policy}', certificate='{CURRENT}'),
        dict(_FWB_POL, name='{EACH:OPT:policies}', certificate='{CURRENT}')]}},
    {'body': {'results': {}}}]
# FRITZ!Box: login_sid.lua gives a PBKDF2 challenge, then the session (a SID, hex); the
# upload page says the certificate was imported; the sign-out ends the session
ANSWERS['fritzbox'] = [
    {'method': 'GET', 'url': r'/login_sid\.lua\?version=2$', 'headers': {
        'Content-Type': 'text/xml'}, 'body':
        '<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID>'
        '<Challenge>2$60000$5a1711f0e0c2b1a3$6000$9b8f3c1d2e4a5b6c</Challenge><BlockTime>0'
        '</BlockTime><Rights></Rights><Users><User last="1">{CFG:user}</User></Users>'
        '</SessionInfo>'},
    {'method': 'POST', 'url': r'/login_sid\.lua\?version=2$', 'headers': {
        'Content-Type': 'text/xml'}, 'body':
        '<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>5e1d0c0ffee5a1ab</SID>'
        '<Challenge>2$60000$5a1711f0e0c2b1a3$6000$9b8f3c1d2e4a5b6c</Challenge><BlockTime>0'
        '</BlockTime><Rights><Name>Dial</Name><Access>2</Access><Name>App</Name><Access>2'
        '</Access><Name>HomeAuto</Name><Access>2</Access><Name>BoxAdmin</Name><Access>2'
        '</Access><Name>Phone</Name><Access>2</Access><Name>NAS</Name><Access>2</Access>'
        '</Rights></SessionInfo>'},
    {'method': 'POST', 'url': r'/cgi-bin/firmwarecfg$', 'headers': {
        'Content-Type': 'text/html; charset=utf-8'}, 'body':
        '<html><body><p>Das SSL-Zertifikat wurde erfolgreich importiert.</p></body></html>'},
    {'method': 'GET', 'url': r'/login_sid\.lua\?logout=1', 'headers': {
        'Content-Type': 'text/xml'}, 'body':
        '<?xml version="1.0" encoding="utf-8"?><SessionInfo><SID>0000000000000000</SID>'
        '<Challenge>2$60000$5a1711f0e0c2b1a3$6000$9b8f3c1d2e4a5b6c</Challenge><BlockTime>0'
        '</BlockTime><Rights></Rights></SessionInfo>'}]
# froxlor: each domain has a certificate (the earlier one) - updated in place
ANSWERS['froxlor'] = [
    {'method': 'POST', 'url': r'/api\.php$', 'sent': r'"command": "Certificates\.get"',
     'body': {'data': {'id': 7, 'domainid': 12, 'domain': '{SENT:params.domainname}',
                       'ssl_cert_file': '\u2039the earlier certificate, PEM\u203a',
                       'ssl_key_file': '', 'ssl_ca_file': '',
                       'ssl_cert_chainfile': '\u2039its chain, PEM\u203a',
                       'validfromdate': '2026-08-14 10:00:00',
                       'validtodate': '2026-11-12 10:00:00', 'letsencrypt': 0}}},
    {'method': 'POST', 'url': r'/api\.php$', 'sent': r'"command": "Certificates\.(update|add)"',
     'body': {'data': {'id': 7, 'domainid': 12, 'domain': '{SENT:params.domainname}'}}}]
# ISM-VA: ismadm asks before it sets the certificate and before the restart (answered y)
SSH_ANSWERS['fujitsu_ism'] = [
    {'command': r'^ismadm sslcert set ', 'stdout':
        'The SSL server certificate will be set. Do you want to continue? [y/n]: y\n'
        'The SSL server certificate has been set. Restart ISM-VA to apply it.\n'},
    {'command': r'^ismadm power restart', 'stdout':
        'ISM-VA will be restarted. Do you want to continue? [y/n]: y\n'}]
# ETERNUS DX / AF: import ssl-certificate prints nothing when it took the files
SSH_ANSWERS['eternus_dx'] = [
    {'command': r'^import ssl-certificate ', 'stdout': ''},
    {'command': r'^set smi-s ', 'stdout': ''}]
# Certificate Manager: the token; the certificate of this ID there (the earlier one, the same
# names) - updated in place (PATCH), the operation done when read again
ANSWERS['gcp_certmanager'] = [
    {'method': 'POST', 'url': r'oauth2\.googleapis\.com/token$', 'body': {
        'access_token': '{SESSION}', 'expires_in': 3599, 'token_type': 'Bearer'}},
    {'method': 'GET', 'url': r'/locations/[^/]+/certificates/[^/?]+$', 'body': {
        'name': 'projects/\u2039project\u203a/locations/global/certificates/{TAIL}',
        'description': 'kept by acme', 'labels': {'managed-by': 'acme'},
        'createTime': '2026-02-14T10:00:00Z', 'updateTime': '2026-08-14T10:00:00Z',
        'pemCertificate': '\u2039the earlier certificate, PEM\u203a',
        'sanDnsnames': '{CERTNAMES}', 'expireTime': '2026-11-12T10:00:00Z', 'scope': 'DEFAULT',
        'selfManaged': {}}},
    {'method': 'PATCH', 'url': r'/certificates/[^/?]+\?updateMask=', 'body': {
        'name': 'projects/\u2039project\u203a/locations/global/operations/operation-'
                '\u2039id\u203a', 'metadata': {
            '@type': 'type.googleapis.com/google.cloud.certificatemanager.v1.OperationMetadata',
            'verb': 'update'}, 'done': False}},
    {'method': 'POST', 'url': r'/certificates\?certificateId=', 'body': {
        'name': 'projects/\u2039project\u203a/locations/global/operations/operation-'
                '\u2039id\u203a', 'done': False}},
    {'method': 'GET', 'url': r'/operations/operation-', 'body': {
        'name': 'projects/\u2039project\u203a/locations/global/operations/operation-'
                '\u2039id\u203a', 'done': True, 'response': {
            '@type': 'type.googleapis.com/google.cloud.certificatemanager.v1.Certificate'}}}]
# HAProxy: the PEM there (an earlier certificate: another SHA-256), replaced; the Runtime API
# lists it among its certificates - set ssl cert makes a transaction, commit says Success!
SSH_ANSWERS['haproxy'] = [
    {'command': r'sha256sum ', 'stdout':
        '7c2b0e9d4f1a3b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5  {OPT:cert_path}\n'},
    {'command': r'echo "PLACED 0"', 'stdout': 'EXISTED 0\nPLACED 0\n'},
    {'command': r"'show ssl cert'", 'stdout':
        '# filename\n/etc/haproxy/certs/default.pem\n{OPT:cert_path}\n'},
    {'command': r"'show ssl cert /", 'stdout':
        'Filename: {OPT:cert_path}\nStatus: Used\nSerial: 03A1B2C3D4E5F60718293A4B5C6D7E8F9012\n'
        'notBefore: Aug 14 10:00:00 2026 GMT\nnotAfter: Nov 12 10:00:00 2026 GMT\n'},
    {'command': r'set ssl cert ', 'stdout':
        'Transaction created for certificate {OPT:cert_path}!\n'},
    {'command': r"'commit ssl cert ", 'stdout':
        'Committing {OPT:cert_path}\nSuccess!\n'},
    {'command': r"'new ssl cert ", 'stdout': 'New empty certificate store \'{OPT:cert_path}\'!\n'},
    {'command': r'^rm -f /tmp/\.acme-', 'stdout': ''},
    {'command': r'ls -1t -- .*\.bak ', 'stdout': ''},
    {'command': r"'add ssl crt-list ", 'stdout':
        'Inserting certificate \'{OPT:cert_path}\' in crt-list \'{OPT:crt_list}\'.\nSuccess!\n'}]
# HestiaCP: each web domain has SSL on with a certificate of its own (not Hestia's Let's
# Encrypt) - the earlier one; a private folder made for the files; the certificate changed
_HESTIA_DOM = '{SEEN:v-list-web-domain(?:-ssl)? [^ ]+ ([^ \']+) json}'
SSH_ANSWERS['hestiacp'] = [
    {'command': r'/v-list-web-domain ', 'stdout':
        '{\n    "' + _HESTIA_DOM + '": {\n        "IP": "192.0.2.10",\n        "ALIAS": "",\n'
        '        "TPL": "default",\n        "SSL": "yes",\n        "SSL_FORCE": "yes",\n'
        '        "SSL_HOME": "same",\n        "LETSENCRYPT": "no",\n        "SUSPENDED": "no"\n'
        '    }\n}\n'},
    {'command': r'/v-list-web-domain-ssl ', 'stdout':
        '{\n    "' + _HESTIA_DOM + '": {\n        "CRT": "\u2039the earlier certificate\u203a",\n'
        '        "KEY": "",\n        "CA": "",\n        "SUBJECT": "' + _HESTIA_DOM + '",\n'
        '        "NOT_AFTER": "Nov 12 10:00:00 2026 GMT"\n    }\n}\n'},
    {'command': r'mktemp -d$', 'stdout': '/tmp/tmp.Xa8k2LmQ0p\n'},
    {'command': r'/v-(change|add)-web-domain-ssl(cert)? ', 'stdout': ''},
    {'command': r'^rm -rf /tmp/tmp\.', 'stdout': ''}]
# Hetzner Cloud: the certificate of this name not there yet, then uploaded (its id); each
# load balancer named has an HTTPS service on the earlier certificate (and an HTTP one); the
# update an action that is running, then done; the project's certificates: the two earlier
# ones (the older used by nothing - deleted), the new one
_HZ_PAGE = {'pagination': {'page': 1, 'per_page': 50, 'previous_page': None,
                           'next_page': None, 'last_page': 1, 'total_entries': 1}}
_HZ_LB = {'id': 4711, 'name': '{EACH:OPT:load_balancers}', 'location': {'name': 'fsn1'},
          'load_balancer_type': {'name': 'lb11'}, 'services': [
              {'protocol': 'https', 'listen_port': 443, 'destination_port': 80,
               'proxyprotocol': False, 'http': {'certificates': [102],
                                                'redirect_http': True, 'sticky_sessions': False}},
              {'protocol': 'http', 'listen_port': 80, 'destination_port': 80,
               'proxyprotocol': False, 'http': {'certificates': []}}]}
_HZ_CERT = {'type': 'uploaded', 'labels': {'managed-by': 'acme'},
            'domain_names': '{CERTNAMES}', 'status': None}
ANSWERS['hetzner_lb'] = [
    {'method': 'GET', 'url': r'/v1/certificates\?name=', 'body': {
        'certificates': [], 'meta': _HZ_PAGE}},
    {'method': 'POST', 'url': r'/v1/certificates$', 'status': 201, 'body': {'certificate': dict(
        _HZ_CERT, id=897, name='{SENT:name}', used_by=[])}},
    {'method': 'GET', 'url': r'/v1/certificates\?page=', 'body': {'certificates': [
        dict(_HZ_CERT, id=101, name='{EARLIER2}', used_by=[]),
        dict(_HZ_CERT, id=102, name='{EARLIER}', used_by=[{'id': 4711, 'type': 'load_balancer'}]),
        dict(_HZ_CERT, id=897, name='{CURRENT}', used_by=[{'id': 4711, 'type': 'load_balancer'}])],
        'meta': _HZ_PAGE}},
    {'method': 'GET', 'url': r'/v1/load_balancers\?name=', 'body': {
        'load_balancers': [_HZ_LB], 'meta': _HZ_PAGE}},
    {'method': 'GET', 'url': r'/v1/load_balancers/\d+$', 'body': {
        'load_balancer': dict(_HZ_LB, id='{TAIL}', name='lb-www')}},
    {'method': 'POST', 'url': r'/actions/update_service$', 'status': 201, 'body': {'action': {
        'id': 13, 'command': 'update_service', 'status': 'running', 'progress': 0,
        'resources': [{'id': 4711, 'type': 'load_balancer'}], 'error': None}}},
    {'method': 'GET', 'url': r'/v1/load_balancers/actions/\d+$', 'body': {'action': {
        'id': 13, 'command': 'update_service', 'status': 'success', 'progress': 100,
        'error': None}}},
    {'method': 'DELETE', 'url': r'/v1/certificates/\d+$', 'status': 204, 'body': ''}]
# Horizon Connection Server (PowerShell over SSH): the import says what it did - imported,
# the intermediates in LocalMachine\CA, the friendly name taken off the earlier certificate
# and put on the new one; the service restarted
SSH_ANSWERS['horizon_cs'] = [
    {'command': r'^powershell', 'script': r'Import-PfxCertificate', 'stdout':
        'STEP ok imported into LocalMachine\\My with an exportable key\n'
        'STEP info the intermediates are in LocalMachine\\CA\n'
        'STEP info {SEEN:\\$_\\.FriendlyName -eq \'([^\']+)\'} taken off '
        '5A0E1D2C3B4A5968776A0E1D2C3B4A5968776A0E\n'
        'STEP ok the friendly name {SEEN:\\$_\\.FriendlyName -eq \'([^\']+)\'} is on '
        '{SEEN:\\$thumb = \'([0-9A-Fa-f]+)\'}\n'},
    {'command': r'^powershell', 'script': r'Restart-Service', 'stdout':
        'STEP ok restarted VMware Horizon Connection Server\n'},
    {'command': r'^powershell', 'script': r"if \(\$c -and \$c\.FriendlyName", 'stdout': 'NO\n'},
    # the files put for the import taken away: nothing printed
    {'command': r'^powershell', 'script': r'^(\$\w+ = [^\n]*\n)*try \{\nRemove-Item ', 'stdout': ''}]
# Alletra MP / Primera: createcert -csr prints the new CSR (the sandbox's {CSR}); importcert
# takes the CA certificates and the certificate (the services restart)
SSH_ANSWERS['hpe_alletra_mp'] = [
    {'command': r'^createcert unified-server -csr ', 'stdout': '{CSR}\n'},
    {'command': r'^importcert unified-server -f -ca stdin', 'stdout':
        'Importing CA certificate(s) for service unified-server\n'},
    {'command': r'^importcert unified-server -f stdin', 'stdout':
        'Importing certificate for service unified-server\nThe affected services will be '
        'restarted\n'}]
# ---- end of targets cisco_wlc9800 .. hpe_oneview ----
# ---- targets hpe_synergy .. redfish_idrac ----
# ISPConfig's Remote API (JSON): the session; the website asked for (by its domain) has SSL on
# with another certificate - the update writes this one; signed out
ANSWERS['ispconfig'] = [
    {'method': 'POST', 'url': r'/remote/json\.php\?login$', 'body': {
        'code': 'ok', 'message': '', 'response': '{SESSION}'}},
    {'method': 'POST', 'url': r'/remote/json\.php\?sites_web_domain_get$', 'body': {
        'code': 'ok', 'message': '', 'response': [{
            'domain_id': '12', 'domain': '{SENT:primary_id.domain}', 'type': 'vhost',
            'active': 'y', 'ssl': 'y', 'ssl_letsencrypt': 'n',
            'ssl_cert': '‹the certificate it has now›'}]}},
    {'method': 'POST', 'url': r'/remote/json\.php\?sites_web_domain_update$', 'body': {
        'code': 'ok', 'message': '', 'response': 1}},
    {'method': 'POST', 'url': r'/remote/json\.php\?logout$', 'body': {
        'code': 'ok', 'message': '', 'response': True}}]
# Kemp LoadMaster (every call POST /accessv2, its command in the body): acme's two earlier
# certificates listed, the virtual services on the earlier one, the intermediate there
# already (422), the oldest deleted
ANSWERS['kemp'] = [
    {'method': 'POST', 'url': r'/accessv2$', 'sent': r'"cmd": "listcert"', 'times': 1, 'body': {
        'code': 200, 'status': 'ok', 'cert': [
            {'name': '{EARLIER:60}', 'type': 'RSA', 'modulus': '‹modulus›'},
            {'name': '{EARLIER2:60}', 'type': 'RSA', 'modulus': '‹modulus›'}]}},
    {'method': 'POST', 'url': r'/accessv2$', 'sent': r'"cmd": "listcert"', 'body': {
        'code': 200, 'status': 'ok', 'cert': [
            {'name': '{EARLIER:60}'}, {'name': '{EARLIER2:60}'}, {'name': '{CURRENT:60}'}]}},
    {'method': 'POST', 'url': r'/accessv2$', 'sent': r'"cmd": "addintermediate"', 'status': 422,
     'body': {'code': 422, 'status': 'fail', 'message': 'Certificate already exists'}},
    {'method': 'POST', 'url': r'/accessv2$', 'sent': r'"cmd": "showvs"', 'body': {
        'code': 200, 'status': 'ok', 'Status': 'Up', 'Protocol': 'tcp', 'SSLAcceleration': 'Y',
        'CertFile': '{EARLIER:60}'}},
    {'method': 'POST', 'url': r'/accessv2$', 'body': {
        'code': 200, 'message': 'Command completed ok', 'status': 'ok'}}]
# Kong: no certificate with this one's fingerprint tag yet; added (its id); the SNIs pointed;
# acme's certificates of this name - the new one and two earlier ones no SNI uses any more
ANSWERS['kong'] = [
    {'method': 'GET', 'url': r'/certificates\?tags=acme-fp-', 'body': {'data': [], 'next': None}},
    {'method': 'POST', 'url': r'/certificates$', 'status': 201, 'body': {
        'id': '3f1e0c52-7d4b-4c1e-9a6f-0b8e2d71c4a9', 'created_at': 1763000000, 'snis': []}},
    {'method': 'PUT', 'url': r'/snis/[^/]+$', 'body': {
        'id': '‹sni id›', 'name': '{TAIL}', 'certificate': {'id': '3f1e0c52-7d4b-4c1e-9a6f-0b8e2d71c4a9'}}},
    {'method': 'GET', 'url': r'/certificates\?tags=acme-', 'body': {'data': [
        {'id': '3f1e0c52-7d4b-4c1e-9a6f-0b8e2d71c4a9', 'tags': ['acme', 'acme-at-29991231-00000000'],
         'snis': ['{CERTNAME}']},
        {'id': '9b2d5e10-3c7a-4f8e-b1d2-6a4c8e0f2b17', 'tags': ['acme', 'acme-at-20260815-5a0e1d27'],
         'snis': []},
        {'id': 'c47a19e3-5b2f-4d6c-8e0a-1f3b5d7e9a24', 'tags': ['acme', 'acme-at-20260515-5a0e1d26'],
         'snis': []}], 'next': None}},
    {'method': 'DELETE', 'url': r'/certificates/', 'status': 204, 'body': ''}]
# RouterOS 7 REST: acme's earlier certificates (none with this one's fingerprint) before the
# import, this one (with its key) after it; the uploaded files found and deleted; www-ssl and
# api-ssl on the earlier one; no SSTP / OpenVPN server on any; the oldest removed
ANSWERS['mikrotik'] = [
    {'method': 'GET', 'url': r'/rest/certificate$', 'times': 1, 'body': [
        {'.id': '*A', 'name': '{EARLIER}', 'fingerprint': '‹its SHA-256›',
         'private-key': 'true', 'trusted': 'true'},
        {'.id': '*9', 'name': '{EARLIER2}', 'fingerprint': '‹its SHA-256›',
         'private-key': 'true', 'trusted': 'true'}]},
    {'method': 'GET', 'url': r'/rest/certificate$', 'body': [
        {'.id': '*A', 'name': '{EARLIER}', 'fingerprint': '‹its SHA-256›',
         'private-key': 'true'},
        {'.id': '*9', 'name': '{EARLIER2}', 'fingerprint': '‹its SHA-256›',
         'private-key': 'true'},
        {'.id': '*B', 'name': '{CURRENT}', 'fingerprint': '{FP}', 'private-key': 'true',
         'trusted': 'true'}]},
    {'method': 'POST', 'url': r'/rest/certificate/import$', 'body': [
        {'certificates-imported': '1', 'private-keys-imported': '0', 'files-imported': '1',
         'decryption-failures': '0', 'keys-with-no-certificate': '0'}]},
    {'method': 'GET', 'url': r'/rest/file\?name=', 'body': [
        {'.id': '*1F', 'name': '{SEEN:name=([^&\\s]+)}', 'type': '.crt file'}]},
    {'method': 'DELETE', 'url': r'/rest/(file|certificate)/', 'status': 204, 'body': ''},
    {'method': 'GET', 'url': r'/rest/ip/service$', 'times': 1, 'body': [
        {'.id': '*6', 'name': 'www-ssl', 'port': '443', 'certificate': '{EARLIER}'},
        {'.id': '*7', 'name': 'api-ssl', 'port': '8729', 'certificate': '{EARLIER}'},
        {'.id': '*1', 'name': 'ssh', 'port': '22'}]},
    {'method': 'GET', 'url': r'/rest/ip/service$', 'body': [
        {'.id': '*6', 'name': 'www-ssl', 'port': '443', 'certificate': '{CURRENT}'},
        {'.id': '*7', 'name': 'api-ssl', 'port': '8729', 'certificate': '{CURRENT}'},
        {'.id': '*1', 'name': 'ssh', 'port': '22'}]},
    {'method': 'PATCH', 'url': r'/rest/ip/service/', 'body': {'certificate': '{CURRENT}'}},
    {'method': 'GET', 'url': r'/rest/interface/(sstp|ovpn)-server/server$', 'body': {
        'certificate': 'none', 'enabled': 'false'}}]
# Nginx Proxy Manager: the token; acme's two earlier custom certificates (the proxy host of
# the name on the newer); the new one added (its id), its files uploaded; the proxy hosts;
# then the earlier ones used by no host - the oldest deleted
ANSWERS['nginx_proxy_manager'] = [
    {'method': 'POST', 'url': r'/api/tokens$', 'body': {
        'token': '{SESSION}', 'expires': '‹in a day›'}},
    {'method': 'GET', 'url': r'/api/nginx/certificates\?expand=', 'times': 1, 'body': [
        {'id': 7, 'provider': 'other', 'nice_name': '{EARLIER}',
         'proxy_hosts': [{'id': 3, 'domain_names': ['{CERTNAME}']}],
         'redirection_hosts': [], 'dead_hosts': []},
        {'id': 4, 'provider': 'other', 'nice_name': '{EARLIER2}', 'proxy_hosts': [],
         'redirection_hosts': [], 'dead_hosts': []}]},
    {'method': 'GET', 'url': r'/api/nginx/certificates\?expand=', 'body': [
        {'id': 12, 'provider': 'other', 'nice_name': '{CURRENT}',
         'proxy_hosts': [{'id': 3, 'domain_names': ['{CERTNAME}']}],
         'redirection_hosts': [], 'dead_hosts': []},
        {'id': 7, 'provider': 'other', 'nice_name': '{EARLIER}', 'proxy_hosts': [],
         'redirection_hosts': [], 'dead_hosts': []},
        {'id': 4, 'provider': 'other', 'nice_name': '{EARLIER2}', 'proxy_hosts': [],
         'redirection_hosts': [], 'dead_hosts': []}]},
    {'method': 'POST', 'url': r'/api/nginx/certificates$', 'status': 201, 'body': {
        'id': 12, 'provider': 'other', 'nice_name': '{SENT:nice_name}'}},
    {'method': 'POST', 'url': r'/api/nginx/certificates/\d+/upload$', 'body': {
        'certificate': '‹the certificate›', 'certificate_key': '‹the key›'}},
    {'method': 'GET', 'url': r'/api/nginx/proxy-hosts$', 'body': [
        {'id': 3, 'domain_names': ['{CERTNAME}'], 'certificate_id': 7},
        {'id': 3, 'domain_names': ['{EACH:OPT:proxy_hosts}'], 'certificate_id': 7}]},
    {'method': 'GET', 'url': r'/api/nginx/redirection-hosts$', 'body': [
        {'id': 5, 'domain_names': ['{EACH:OPT:redirection_hosts}'], 'certificate_id': 7}]},
    {'method': 'GET', 'url': r'/api/nginx/dead-hosts$', 'body': [
        {'id': 6, 'domain_names': ['{EACH:OPT:dead_hosts}'], 'certificate_id': 7}]},
    {'method': 'PUT', 'url': r'/api/nginx/[a-z-]+-hosts/\d+$', 'body': {
        'id': '{TAIL}', 'certificate_id': 12}},
    {'method': 'DELETE', 'url': r'/api/nginx/certificates/\d+$', 'body': 'true'}]
# NSX Policy API: this certificate's id not there yet (404); imported; the virtual server
# with a client SSL binding on the earlier one; acme's certificates, the oldest used by none
ANSWERS['nsx'] = [
    {'method': 'GET', 'url': r'/infra/certificates/[^/?]+$', 'status': 404, 'body': {
        'httpStatus': 'NOT_FOUND', 'error_code': 500090, 'module_name': 'Policy',
        'error_message': 'The path=[/infra/certificates/{TAIL}] is invalid'}},
    {'method': 'PUT', 'url': r'/infra/certificates/[^/?]+$', 'body': {
        'id': '{TAIL}', 'resource_type': 'TlsCertificate', 'display_name': '{TAIL}'}},
    {'method': 'GET', 'url': r'/infra/lb-virtual-servers/[^/?]+$', 'body': {
        'id': '{TAIL}', 'display_name': '{TAIL}', 'resource_type': 'LBVirtualServer',
        'ip_address': '192.0.2.10', 'ports': ['443'], '_revision': 3,
        'lb_service_path': '/infra/lb-services/lb-1',
        'client_ssl_profile_binding': {
            'ssl_profile_path': '/infra/lb-client-ssl-profiles/default-balanced-client-ssl-profile',
            'default_certificate_path': '/infra/certificates/{EARLIER}',
            'sni_certificate_paths': []}}},
    {'method': 'PUT', 'url': r'/infra/lb-virtual-servers/[^/?]+$', 'body': {
        'id': '{TAIL}', '_revision': 4}},
    {'method': 'GET', 'url': r'/infra/certificates(\?|$)', 'body': {'results': [
        {'id': '{CURRENT}'}, {'id': '{EARLIER}'}, {'id': '{EARLIER2}'}], 'result_count': 3}},
    {'method': 'GET', 'url': r'/infra/lb-virtual-servers(\?|$)', 'body': {'results': [
        {'id': 'vs-www-443', 'client_ssl_profile_binding': {
            'default_certificate_path': '/infra/certificates/{CURRENT}',
            'sni_certificate_paths': []}}], 'result_count': 1}},
    {'method': 'DELETE', 'url': r'/infra/certificates/', 'body': ''}]
# the UAG: a token at sign-in; each certificate replaced (PUT answers the settings)
ANSWERS['omnissa_uag'] = [
    {'method': 'POST', 'url': r'/rest/v1/jwt/login$', 'body': {
        'accessToken': '{SESSION}', 'refreshToken': '{SESSION}',
        'accessTokenExpiryTime': '‹in an hour›'}},
    {'method': 'PUT', 'url': r'/rest/v1/config/certs/ssl/(end_user|admin)$', 'body': {
        'certChainPem': '‹the chain›'}}]
# PAN-OS XML API (POST /api/, what is asked in the form body): the key at keygen; this
# certificate not there yet, the intermediate there already; imported; profiles set; acme's
# certificates there; the commit a job - running, then finished OK
ANSWERS['paloalto'] = [
    {'method': 'POST', 'url': r'/api/$', 'sent': r'type=keygen', 'body':
        '<response status="success"><result><key>PLANSESSION0token</key></result></response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent':
        r'action=get&xpath=[^&]*certificate%2Fentry%5B%40name%3D%27acme-ca-', 'body':
        '<response status="success" code="19"><result total-count="1" count="1">'
        '<entry name="{SEEN:%27(acme-ca-[0-9a-f]+)%27}"><common-name>‹intermediate›'
        '</common-name></entry></result></response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent': r'action=get&xpath=[^&]*certificate%2Fentry',
     'body': '<response status="success" code="7"><result/></response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent': r'action=get&xpath=[^&]*%2Fcertificate$',
     'body': '<response status="success" code="19"><result total-count="1" count="1">'
             '<certificate><entry name="{EARLIER}"/><entry name="{EARLIER2}"/>'
             '<entry name="{CURRENT}"/></certificate></result></response>'},
    {'method': 'POST', 'url': r'/api/\?.*type=import', 'body':
        '<response status="success"><msg><line>Successfully imported {SEEN:certificate-name='
        '([^&]+)} into candidate configuration</line></msg></response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent': r'type=commit', 'body':
        '<response status="success" code="19"><result><msg><line>Commit job enqueued with '
        'jobid 1234</line></msg><job>1234</job></result></response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent': r'type=op', 'times': 1, 'body':
        '<response status="success"><result><job><id>1234</id><type>Commit</type>'
        '<status>ACT</status><result>PEND</result><progress>55</progress></job></result>'
        '</response>'},
    {'method': 'POST', 'url': r'/api/$', 'sent': r'type=op', 'body':
        '<response status="success"><result><job><id>1234</id><type>Commit</type>'
        '<status>FIN</status><result>OK</result><progress>100</progress><details><line>'
        'Configuration committed successfully</line></details></job></result></response>'},
    {'method': 'POST', 'url': r'/api/$', 'body':
        '<response status="success" code="20"><msg>command succeeded</msg></response>'}]
# Plesk XML API (POST agent.php, the operation in the packet): the repository holds acme's two
# earlier certificates; the install and a removal OK
ANSWERS['plesk'] = [
    {'method': 'POST', 'url': r'/enterprise/control/agent\.php$', 'sent': r'<get-pool>', 'body':
        '<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><certificate>'
        '<get-pool><result><status>ok</status><certificates>'
        '<certificate><name>{EARLIER}</name></certificate>'
        '<certificate><name>{EARLIER2}</name></certificate>'
        '</certificates></result></get-pool></certificate></packet>'},
    {'method': 'POST', 'url': r'/enterprise/control/agent\.php$', 'sent': r'<(install|remove)>',
     'body': '<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1"><certificate>'
             '<{SEEN:<(install|remove)>}><result><status>ok</status></result>'
             '</{SEEN:<(install|remove)>}></certificate></packet>'}]
# NGINX Unit's control API through curl over SSH (the answer, then its status on the last
# line): acme's earlier bundle and an older one, the listener (the default one, and the first
# named) on the earlier one
SSH_ANSWERS['nginx_unit'] = [
    {'command': r"-X GET .*http://localhost/certificates'?$", 'stdout':
        '{"{EARLIER}": {"key": "RSA (2048 bits)", "chain": []}, '
        '"{EARLIER2}": {"key": "RSA (2048 bits)", "chain": []}}\n200'},
    {'command': r"-X GET .*http://localhost/config/listeners'?$", 'stdout':
        '{"*:443": {"pass": "routes", "tls": {"certificate": "{EARLIER}"}}, '
        '"{OPT:listeners}": {"pass": "routes", "tls": {"certificate": "{EARLIER}"}}}\n200'},
    {'command': r"-X PUT .*http://localhost/certificates/", 'stdout':
        '{"success": "Certificate chain uploaded."}\n200'},
    {'command': r"-X PUT .*http://localhost/config/listeners/", 'stdout':
        '{"success": "Reconfiguration done."}\n200'},
    {'command': r"-X DELETE .*http://localhost/certificates/", 'stdout':
        '{"success": "Certificate deleted."}\n200'}]
# pfSense: the PHP script imported the certificate, pointed the web GUI at it, finished
SSH_ANSWERS['pfsense'] = [
    {'command': r'php$', 'input': r'certs\.inc', 'stdout':
        'IMPORTED 6553f0a1b2c3d\nGUI\nDONE\n'},
    {'command': r'^/etc/rc\.restart_webgui', 'stdout': '>>> Restarting nginx webConfigurator... done.\n'}]
# Junos REST: the PKI's local certificates - acme's two earlier ones (Junos ids, plan_name)
# and the system's; every RPC posted answered OK, the commit with commit-success
ANSWERS['juniper_srx'] = [
    {'method': 'GET', 'url': r'/rpc/get-pki-local-certificate$', 'headers': {
        'Content-Type': 'application/xml'}, 'body':
        '<x509-pki-certificate-info-list xmlns="http://xml.juniper.net/junos/23.4R1/junos-pki">'
        '<x509-certificate-info><identifier>{EARLIER}</identifier></x509-certificate-info>'
        '<x509-certificate-info><identifier>{EARLIER2}</identifier></x509-certificate-info>'
        '<x509-certificate-info><identifier>system-generated</identifier>'
        '</x509-certificate-info></x509-pki-certificate-info-list>'},
    {'method': 'POST', 'url': r'/rpc\?stop-on-error=1$', 'sent': r'<commit-configuration>',
     'headers': {'Content-Type': 'application/xml'}, 'body':
        '<rpc-reply><ok/></rpc-reply><rpc-reply><load-configuration-results><ok/>'
        '</load-configuration-results></rpc-reply><rpc-reply><commit-results><routing-engine>'
        '<name>node0</name><commit-success/></routing-engine></commit-results></rpc-reply>'
        '<rpc-reply><ok/></rpc-reply>'},
    {'method': 'POST', 'url': r'/rpc\?stop-on-error=1$', 'headers': {
        'Content-Type': 'application/xml'}, 'body': '<rpc-reply><ok/></rpc-reply>'}]
# Kubernetes: the TLS secret made (the first time, FIRST) or patched (at a renewal it is there
# with the earlier certificate, LATER); a deployment restarted
ANSWERS['kubernetes'] = [
    {'method': 'POST', 'url': r'/api/v1/namespaces/[^/]+/secrets$', 'status': 201, 'body': {
        'kind': 'Secret', 'apiVersion': 'v1', 'type': 'kubernetes.io/tls',
        'metadata': {'name': '{SENT:metadata.name}', 'resourceVersion': '81723'}}},
    {'method': 'PATCH', 'url': r'/api/v1/namespaces/[^/]+/secrets/[^/?]+$', 'body': {
        'kind': 'Secret', 'apiVersion': 'v1', 'type': 'kubernetes.io/tls',
        'metadata': {'name': '{TAIL}', 'resourceVersion': '81802'}}},
    {'method': 'PATCH', 'url': r'/apis/apps/v1/namespaces/[^/]+/deployments/', 'body': {
        'kind': 'Deployment', 'apiVersion': 'apps/v1', 'metadata': {
            'name': '{TAIL}', 'generation': 8}}}]
# Proxmox VE: the cluster's nodes; each serves an earlier custom certificate (pveproxy-ssl.pem)
# - uploaded anew, pveproxy restarted
ANSWERS['proxmox'] = [
    {'method': 'GET', 'url': r'/api2/json/nodes$', 'body': {'data': [
        {'node': 'pve1', 'status': 'online'}, {'node': 'pve2', 'status': 'online'}]}},
    {'method': 'GET', 'url': r'/api2/json/nodes/[^/]+/certificates/info$', 'body': {'data': [
        {'filename': 'pve-root-ca.pem', 'subject': '/CN=Proxmox Virtual Environment/OU=‹id›'},
        {'filename': 'pve-ssl.pem', 'fingerprint': '‹its own›'},
        {'filename': 'pveproxy-ssl.pem', 'subject': '/CN={CERTNAME}',
         'fingerprint': '5A:0E:1D:2C:3B:4A:59:68:77:86:95:A4:B3:C2:D1:E0:F0:01:12:23:34:45:56:'
                        '67:78:89:9A:AB:BC:CD:DE:EF', 'notafter': 1763000000}]}},
    {'method': 'POST', 'url': r'/api2/json/nodes/[^/]+/certificates/custom$', 'body': {'data': {
        'filename': 'pveproxy-ssl.pem', 'fingerprint': '{FP}'}}}]
# Proxmox Backup Server: its proxy.pem an earlier certificate; the upload taken
ANSWERS['proxmox_backup'] = [
    {'method': 'GET', 'url': r'/api2/json/nodes/[^/]+/certificates/info$', 'body': {'data': [
        {'filename': 'proxy.pem', 'subject': 'CN = {CERTNAME}',
         'fingerprint': '5a:0e:1d:2c:3b:4a:59:68:77:86:95:a4:b3:c2:d1:e0:f0:01:12:23:34:45:56:'
                        '67:78:89:9a:ab:bc:cd:de:ef', 'notafter': 1763000000}]}},
    {'method': 'POST', 'url': r'/api2/json/nodes/[^/]+/certificates/custom$', 'body': {
        'data': None}}]
# OPNsense: acme's two earlier certificates in the trust store, the intermediate there already;
# imported; then the three - the oldest deleted (keep 2: none - keep 1: the oldest)
ANSWERS['opnsense'] = [
    {'method': 'GET', 'url': r'/api/trust/cert/search\?', 'times': 1, 'body': {'rows': [
        {'uuid': '6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5', 'descr': '{EARLIER}'},
        {'uuid': '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d', 'descr': '{EARLIER2}'}],
        'rowCount': 2, 'total': 2, 'current': 1}},
    {'method': 'GET', 'url': r'/api/trust/cert/search\?', 'body': {'rows': [
        {'uuid': '9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a', 'descr': '{CURRENT}'},
        {'uuid': '6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5', 'descr': '{EARLIER}'},
        {'uuid': '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d', 'descr': '{EARLIER2}'}],
        'rowCount': 3, 'total': 3, 'current': 1}},
    {'method': 'GET', 'url': r'/api/trust/ca/search\?', 'body': {'rows': [
        {'uuid': '2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e',
         'descr': '{SEEN:searchPhrase=(acme-ca-[0-9a-f]+)}'}], 'rowCount': 1, 'total': 1}},
    {'method': 'POST', 'url': r'/api/trust/(cert|ca)/(add|set/[^/]+)$', 'body': {
        'result': 'saved', 'uuid': '9e8d7c6b-5a49-4382-9170-6f5e4d3c2b1a'}},
    {'method': 'POST', 'url': r'/api/trust/cert/del/', 'body': {'result': 'deleted'}}]
# its web GUI over SSH: the PHP script switched it (CHANGED), the web GUI restarted
SSH_ANSWERS['opnsense'] = [
    {'command': r'php$', 'stdout': 'CHANGED 6553f0a1b2c3d\n'},
    {'command': r'^configctl webgui restart', 'stdout': 'OK\n'}]
# QNAP: stunnel.pem holds an earlier certificate (not this one); stunnel restarts
SSH_ANSWERS['qnap'] = [
    {'command': r"sed -n .*/etc/stunnel/stunnel\.pem", 'stdout':
        '-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIUWm5vdHRoaXNjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQsF\n'
        '-----END CERTIFICATE-----\n'},
    {'command': r'stunnel\.sh restart', 'stdout':
        'Shutting down stunnel:  OK\nStarting stunnel:  OK\n'},
    {'command': r'Qthttpd\.sh restart', 'stdout':
        'Shutting down Qthttpd services: OK\nStarting Qthttpd services: OK\n'}]
# NIOS: uploadinit gives the token and the address the file goes to; the upload and
# uploadcertificate answered as WAPI does (an empty object)
ANSWERS['infoblox'] = [
    {'method': 'POST', 'url': r'/fileop\?_function=uploadinit$', 'body': {
        'token': 'eJydkE1PwzAMhv+Kz3NIm7Z0Ozf9RZDXXa',
        'url': 'https://gm.example.local/http_direct_file_io/req_id-UPLOAD-0217164802912345/'
               'import_file'}},
    {'method': 'POST', 'url': r'/http_direct_file_io/', 'body': ''},
    {'method': 'POST', 'url': r'/fileop\?_function=uploadcertificate$', 'body': {}}]
# the iRMC answers SCCI (POST /config) in XML: status 0, no error; its reset taken
ANSWERS['irmc'] = [
    {'method': 'POST', 'url': r'/config$', 'headers': {'Content-Type': 'text/xml'},
     'body': '<?xml version="1.0" encoding="UTF-8" standalone="yes" ?><Status>'
             '<Value>0</Value><Severity>Information</Severity><Message>No Error'
             '</Message></Status>'},
    {'method': 'POST', 'url': r'/rest/v1/Oem/iRMC/Reset$', 'status': 204, 'body': ''},
    {'method': 'POST', 'url': r'/Managers/iRMC/Actions/Manager\.Reset$', 'status': 204,
     'body': ''}]
# ONTAP: the cluster's version; the SVM named; this certificate not there before the install,
# then listed by the name the install sent; the web services bound (a job, running, then
# done); the SVM's certificates - acme's two earlier ones and this one
_ONTAP_CERTS = {'records': [
    {'uuid': '1c8e4b3a-9f2d-11ee-8c90-0242ac120002', 'name': '{CURRENT}', 'type': 'server'},
    {'uuid': '7d2a0f14-1b6e-11ef-9a3c-005056bb4e21', 'name': '{EARLIER}', 'type': 'server'},
    {'uuid': '3f5b9c70-5e8a-11ee-b1d4-005056bb4e21', 'name': '{EARLIER2}', 'type': 'server'}],
    'num_records': 3}
ANSWERS['netapp_ontap'] = [
    {'method': 'GET', 'url': r'/api/cluster\?fields=version', 'body': {
        'name': 'cluster1', 'version': {
            'full': 'NetApp Release 9.14.1P3: Fri Mar 08 12:39:01 UTC 2024',
            'generation': 9, 'major': 14, 'minor': 1}}},
    {'method': 'GET', 'url': r'/api/svm/svms\?', 'body': {'records': [
        {'uuid': '02c9e252-41be-11e9-81d5-00a0986138f7', 'name': '{OPT:svm}'}],
        'num_records': 1}},
    {'method': 'GET', 'url': r'/api/security/certificates\?.*&name=', 'times': 1,
     'body': {'records': [], 'num_records': 0}},
    {'method': 'GET', 'url': r'/api/security/certificates\?.*&name=', 'body': {'records': [
        {'uuid': '1c8e4b3a-9f2d-11ee-8c90-0242ac120002', 'name': '{SENT:name}',
         'type': 'server'}], 'num_records': 1}},
    {'method': 'GET', 'url': r'/api/security/certificates\?', 'body': _ONTAP_CERTS},
    {'method': 'POST', 'url': r'/api/security/certificates\?', 'status': 201, 'body': {
        'num_records': 1, 'records': [{'uuid': '1c8e4b3a-9f2d-11ee-8c90-0242ac120002',
                                       'name': '{SENT:name}'}]}},
    {'method': 'PATCH', 'url': r'/api/(cluster|svm/svms/[^/?]+)(/web)?$', 'status': 202,
     'body': {'job': {'uuid': 'b3f4a2c1-77d0-11ef-8e2a-00a098d39e12'}}},
    {'method': 'GET', 'url': r'/api/cluster/jobs/', 'times': 1, 'body': {
        'state': 'running', 'message': 'Restarting the web services'}},
    {'method': 'GET', 'url': r'/api/cluster/jobs/', 'body': {'state': 'success',
                                                             'message': 'success'}},
    {'method': 'DELETE', 'url': r'/api/security/certificates/', 'body': {}}]
# its 9.6 - 9.9 version: a cluster of ONTAP 9.8
ANSWERS['netapp_ontap@9.6'] = [
    {'method': 'GET', 'url': r'/api/cluster\?fields=version', 'body': {
        'name': 'cluster1', 'version': {'full': 'NetApp Release 9.8P12: Thu Aug 04 2022',
                                        'generation': 9, 'major': 8, 'minor': 0}}}]
# NSX Manager: acme's earlier certificate applied (used_by) and an older one; imported (its
# id), validated; applied to the node and the VIP; then the earlier ones no longer used, the
# oldest deleted
ANSWERS['nsx_manager'] = [
    {'method': 'GET', 'url': r'/trust-management/certificates$', 'times': 1, 'body': {
        'results': [
            {'id': '8f2c1d6a-3b4e-4f5a-9c7d-1e2f3a4b5c6d', 'display_name': '{EARLIER}',
             'used_by': [{'node_id': 'a1b2c3d4-0000-0000-0000-000000000001',
                          'service_types': ['API', 'MGMT_CLUSTER']}]},
            {'id': '2e4f6a8c-0b1d-4e3f-8a5c-7d9e1f3a5b7c', 'display_name': '{EARLIER2}',
             'used_by': []}], 'result_count': 2}},
    {'method': 'GET', 'url': r'/trust-management/certificates$', 'body': {'results': [
        {'id': '5b7d9f1a-2c4e-4a6b-8d0f-3e5a7c9e1b3d', 'display_name': '{CURRENT}',
         'used_by': [{'node_id': 'a1b2c3d4-0000-0000-0000-000000000001',
                      'service_types': ['API', 'MGMT_CLUSTER']}]},
        {'id': '8f2c1d6a-3b4e-4f5a-9c7d-1e2f3a4b5c6d', 'display_name': '{EARLIER}',
         'used_by': []},
        {'id': '2e4f6a8c-0b1d-4e3f-8a5c-7d9e1f3a5b7c', 'display_name': '{EARLIER2}',
         'used_by': []}], 'result_count': 3}},
    {'method': 'POST', 'url': r'/certificates\?action=import$', 'status': 201, 'body': {
        'results': [{'id': '5b7d9f1a-2c4e-4a6b-8d0f-3e5a7c9e1b3d',
                     'display_name': '{SENT:display_name}'}], 'result_count': 1}},
    {'method': 'GET', 'url': r'\?action=validate', 'body': {'status': 'OK'}},
    {'method': 'POST', 'url': r'\?action=apply_certificate', 'body': ''},
    {'method': 'DELETE', 'url': r'/trust-management/certificates/', 'body': ''}]
# Prism Central: the cluster named is one of its clusters, its certificate read with an
# ETag, the replacement a task - running, then succeeded
ANSWERS['nutanix'] = [
    {'method': 'GET', 'url': r'/config/clusters$', 'body': {'data': [
        {'extId': '00061de0-6c4e-25a1-0000-00000000aa11', 'name': '{CFG:cluster}'}]}},
    {'method': 'GET', 'url': r'/ssl-certificate$', 'body': {'data': {
        'privateKeyAlgorithm': 'RSA_2048', 'publicCertificate': '‹the certificate it has›'}},
     'headers': {'Content-Type': 'application/json', 'ETag': 'YXBwbGljYXRpb24vanNvbg==:0'}},
    {'method': 'PUT', 'url': r'/ssl-certificate$', 'status': 202, 'body': {
        'data': {'extId': 'ZXJnb24=:7b1f3c5e-9a2d-4e6f-8b0c-1d3e5f7a9b2c'}}},
    {'method': 'GET', 'url': r'/config/tasks/', 'times': 1, 'body': {'data': {
        'status': 'RUNNING', 'progressPercentage': 40}}},
    {'method': 'GET', 'url': r'/config/tasks/', 'body': {'data': {'status': 'SUCCEEDED',
                                                                  'progressPercentage': 100}}}]
# OneFS 9.10: acme's two earlier certificates, the earlier one the default HTTPS one; the
# files written to /ifs and taken away, imported (its id), made the default; the oldest deleted
ANSWERS['powerscale'] = [
    {'method': 'GET', 'url': r'/platform/1/cluster/config$', 'body': {
        'name': 'isilon-cl1', 'onefs_version': {'release': '9.10.0.0',
                                                'build': 'B_9_10_0_0_001(RELEASE)'}}},
    {'method': 'GET', 'url': r'/platform/4/certificate/server$', 'times': 1, 'body': {
        'certificates': [
            {'id': 'a4c7e19b2f5d8306', 'name': '{EARLIER}', 'status': 'valid'},
            {'id': '6e2b9f0d4a1c7385', 'name': '{EARLIER2}', 'status': 'valid'}], 'total': 2}},
    {'method': 'GET', 'url': r'/platform/4/certificate/server$', 'body': {'certificates': [
        {'id': 'd81f3a5c7e9b0246', 'name': '{CURRENT}', 'status': 'valid'},
        {'id': 'a4c7e19b2f5d8306', 'name': '{EARLIER}', 'status': 'valid'},
        {'id': '6e2b9f0d4a1c7385', 'name': '{EARLIER2}', 'status': 'valid'}], 'total': 3}},
    {'method': 'GET', 'url': r'/platform/7/certificate/settings$', 'body': {'settings': {
        'default_https_certificate': 'a4c7e19b2f5d8306'}}},
    {'method': 'PUT', 'url': r'/platform/7/certificate/settings$', 'status': 204, 'body': ''},
    {'method': 'POST', 'url': r'/platform/\d+/certificate/server$', 'status': 201,
     'body': {'id': 'd81f3a5c7e9b0246'}},
    {'method': 'PUT', 'url': r'/namespace/', 'body': ''},
    {'method': 'DELETE', 'url': r'/namespace/', 'status': 204, 'body': ''},
    {'method': 'DELETE', 'url': r'/platform/4/certificate/server/', 'status': 204, 'body': ''}]
# PowerStore: the session is the DELL-EMC-TOKEN header and the cookie of the sign-in; the
# cluster runs PowerStoreOS 4.1; the certificate imported (its id) is the current one
ANSWERS['powerstore'] = [
    {'method': 'GET', 'url': r'/api/rest/login_session$',
     'body': [{'id': '‹session›'}],
     'headers': {'Content-Type': 'application/json', 'DELL-EMC-TOKEN': 'PLANSESSION0token',
                 'Set-Cookie': 'auth_cookie=PLANSESSION0token; Path=/; Secure; HttpOnly'}},
    {'method': 'GET', 'url': r'/api/rest/software_installed\?', 'body': [
        {'release_version': '4.1.0.0', 'is_cluster': True}]},
    {'method': 'POST', 'url': r'/api/rest/x509_certificate$', 'status': 201, 'body': {
        'id': 'e3a7c1d9-5b2f-4e8a-9c6d-0f1b3d5e7a9c'}},
    {'method': 'GET', 'url': r'/api/rest/x509_certificate/[^/?]+\?', 'body': {
        'id': '{SEEN:x509_certificate/([^/?]+)\\?}', 'is_current': True, 'is_valid': True}},
    {'method': 'POST', 'url': r'/api/rest/logout$', 'status': 204, 'body': ''}]
# Purity: the REST API versions it speaks (the newest 2.x is used), the session the
# x-auth-token header of the sign-in, the certificate named holds an earlier one; replaced
ANSWERS['pure_flasharray'] = [
    {'method': 'GET', 'url': r'/api/api_version$', 'body': {
        'version': ['1.19', '2.0', '2.36']}},
    {'method': 'POST', 'url': r'/login$', 'body': {'items': [{'username': 'pureuser'}]},
     'headers': {'Content-Type': 'application/json', 'x-auth-token': 'PLANSESSION0token'}},
    {'method': 'GET', 'url': r'/certificates\?names=', 'body': {'items': [
        {'name': '{SEEN:names=([^&\\s]+)}', 'certificate': '{EARLIER_PEM}',
         'common_name': '{CERTNAME}', 'status': 'imported'}]}},
    {'method': 'PATCH', 'url': r'/certificates\?names=', 'body': {'items': [
        {'name': '{SEEN:names=([^&\\s]+)}', 'status': 'imported'}]}},
    {'method': 'POST', 'url': r'/logout$', 'body': {}}]
# Redfish: the service root, the session (its token and address headers of the sign-in), the
# first manager and its HTTPS certificate, the CertificateService's ReplaceCertificate; the
# replacement and a reset taken, the session ended
ANSWERS['redfish'] = [
    _REDFISH_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/?$', 'body': {
        'RedfishVersion': '1.17.0',
        'CertificateService': {'@odata.id': '/redfish/v1/CertificateService'},
        'Managers': {'@odata.id': '/redfish/v1/Managers'},
        'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}}}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1'}], 'Members@odata.count': 1}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
        'Id': '1', 'Manufacturer': '‹vendor›', 'Model': 'BMC', 'FirmwareVersion': '1.00',
        'NetworkProtocol': {'@odata.id': '/redfish/v1/Managers/1/NetworkProtocol'}}},
    {'method': 'GET', 'url': r'/NetworkProtocol/HTTPS/Certificates/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1'}],
        'Members@odata.count': 1}},
    {'method': 'GET', 'url': r'/redfish/v1/CertificateService/?$', 'body': {'Actions': {
        '#CertificateService.GenerateCSR': {
            'target': '/redfish/v1/CertificateService/Actions/CertificateService.GenerateCSR'},
        '#CertificateService.ReplaceCertificate': {
            'target': '/redfish/v1/CertificateService/Actions/'
                      'CertificateService.ReplaceCertificate'}}}},
    {'method': 'POST', 'url': r'CertificateService\.ReplaceCertificate$', 'body': {
        '@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1',
        'CertificateType': 'PEM'}},
    {'method': 'POST', 'url': r'/Actions/Manager\.Reset$', 'status': 204, 'body': ''},
    {'method': 'DELETE', 'url': r'/SessionService/Sessions/', 'status': 204, 'body': ''}]
# (redfish@ilo - redfish_ilo.py: in the section of targets redfish@ilo .. zimbra below)
# an iDRAC9 (firmware 7.10.30.00): its manager iDRAC.Embedded.1, Dell's card service with
# UploadSSLKey and ImportSSLCertificate
ANSWERS['redfish@6.00.02'] = [
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/iDRAC.Embedded.1'}]}},
    {'method': 'GET', 'url': r'/Managers/iDRAC\.Embedded\.1$', 'body': {
        'Manufacturer': 'Dell Inc.', 'Model': '16G Monolithic',
        'FirmwareVersion': '7.10.30.00'}},
    {'method': 'GET', 'url': r'/DelliDRACCardService$', 'body': {'Actions': {
        '#DelliDRACCardService.UploadSSLKey': {
            'target': '/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/'
                      'Actions/DelliDRACCardService.UploadSSLKey'},
        '#DelliDRACCardService.ImportSSLCertificate': {
            'target': '/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DelliDRACCardService/'
                      'Actions/DelliDRACCardService.ImportSSLCertificate'}}}},
    {'method': 'POST', 'url': r'DelliDRACCardService\.(UploadSSLKey|ImportSSLCertificate)$',
     'body': {'@Message.ExtendedInfo': [{'MessageId': 'IDRAC.2.9.LC067',
                                         'Message': 'The SSL certificate is successfully '
                                                    'imported.'}]}}]
# the Huawei / xFusion iBMC: Redfish's root and session; the upload to /tmp/web taken (202),
# the import said, the reset taken
ANSWERS['huawei_ibmc'] = [
    _REDFISH_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/?$', 'body': {
        'RedfishVersion': '1.0.2', 'Vendor': 'Huawei',
        'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}}}},
    {'method': 'POST', 'url': r'/UpdateService/FirmwareInventory$', 'status': 202, 'body': {
        'Id': '1', 'TaskState': 'Completed'}},
    {'method': 'POST', 'url': r'HttpsCert\.ImportCustomCertificate$', 'body': {
        '@Message.ExtendedInfo': [{'MessageId': 'iBMC.1.0.CertImportOK',
                                   'Message': 'The certificate has been imported.'}]}},
    {'method': 'POST', 'url': r'/Actions/Manager\.Reset$', 'body': {
        '@Message.ExtendedInfo': [{'MessageId': 'Base.1.0.Success'}]}},
    {'method': 'DELETE', 'url': r'/SessionService/Sessions/', 'body': {}}]
# the device-key controllers' sessions end, their imports are taken
ANSWERS['lenovo_xcc'] += [
    {'method': 'POST', 'url': r'CertificateService\.ReplaceCertificate$', 'body': {
        '@odata.id': '/redfish/v1/Managers/1/NetworkProtocol/HTTPS/Certificates/1'}},
    {'method': 'DELETE', 'url': r'/SessionService/Sessions/', 'status': 204, 'body': ''}]
# LXCA: the root and the intermediate in its trust store already at a renewal (409)
ANSWERS['lenovo_lxca'] += [
    {'method': 'POST', 'url': r'/trustedCertificates$', 'status': 409, 'body': {
        'result': 'failed', 'messages': [{'id': 'FQXHMSE0222J',
                                          'text': 'The certificate already exists.'}]}}]
# Synergy: the intermediate in the trust store already; the import a task, completed
ANSWERS['hpe_synergy'] += [
    {'method': 'GET', 'url': r'/rest/certificates/ca/[^/?]+$', 'body': {
        'type': 'CertificateAuthorityInfo', 'certificateDetails': {
            'aliasName': '{TAIL}', 'commonName': '{CACN}'}}},
    {'method': 'PUT', 'url': r'/https/certificaterequest(\?bayNumber=\d+)?$', 'status': 202,
     'body': {'uri': '/rest/tasks/4D4B9A0C-2E1F-4A3B-9C8D-7E6F5A4B3C2D'}},
    {'method': 'GET', 'url': r'/rest/tasks/', 'body': {'taskState': 'Completed',
                                                       'percentComplete': 100}},
    {'method': 'DELETE', 'url': r'/rest/login-sessions$', 'status': 204, 'body': ''}]
# NetScaler (NITRO): signed in; every call "Done"; the vserver's bindings (the first time the
# appliance's own certificate, at a renewal acme's certkey - FIRST / LATER); the files in
# /nsconfig/ssl: acme's earlier pairs and this one
ANSWERS['netscaler'] = [
    {'method': 'POST', 'url': r'/nitro/v1/config/login$', 'status': 201, 'body': {
        'errorcode': 0, 'message': 'Done', 'severity': 'NONE', 'sessionid': '{SESSION}'}},
    {'method': 'GET', 'url': r'/nitro/v1/config/systemfile\?', 'body': {
        'errorcode': 0, 'message': 'Done', 'systemfile': [
            {'filename': 'ns-server.cert'}, {'filename': 'ns-server.key'},
            {'filename': '{EARLIER}.crt'}, {'filename': '{EARLIER}.key'},
            {'filename': '{EARLIER2}.crt'}, {'filename': '{EARLIER2}.key'},
            {'filename': '{CURRENT}.crt'}, {'filename': '{CURRENT}.key'}]}},
    {'method': 'DELETE', 'url': r'/nitro/v1/config/systemfile/', 'body': {
        'errorcode': 0, 'message': 'Done', 'severity': 'NONE'}},
    {'method': 'POST', 'url': r'/nitro/v1/config/', 'status': 201, 'body': {
        'errorcode': 0, 'message': 'Done', 'severity': 'NONE'}},
    {'method': 'PUT', 'url': r'/nitro/v1/config/', 'body': {
        'errorcode': 0, 'message': 'Done', 'severity': 'NONE'}}]
SSH_ANSWERS['nginx_unit'] += [{'command': r'^rm -f /tmp/\.acme-unit-', 'stdout': ''}]
SSH_ANSWERS['qnap'] += [{'command': r'stunnel\.pem\.acme-prev && ', 'stdout': ''},
                        {'command': r'^sh -c .rm -f /tmp/acme-', 'stdout': ''}]
# a FlashBlade answers as a FlashArray
ANSWERS['pure_flashblade'] = ANSWERS['pure_flasharray']
# RouterOS 6 over SSH (the mode "SSH only"): acme's two earlier certificates by name before
# the import, this one too after it; the imports said; the services on this one after the
# binding, the VPN servers on none
SSH_ANSWERS['mikrotik'] = [
    {'command': r'^:foreach c in=\[/certificate find where name~', 'times': 1,
     'stdout': '{EARLIER}\n{EARLIER2}\n'},
    {'command': r'^:foreach c in=\[/certificate find where name~"[^"]*-"\] do=\{:put',
     'stdout': '{EARLIER}\n{EARLIER2}\n{CURRENT}\n'},
    {'command': r'^/certificate import ', 'stdout':
        '     certificates-imported: 1\n     private-keys-imported: 0\n            '
        'files-imported: 1\n       decryption-failures: 0\n  keys-with-no-certificate: 0\n'},
    {'command': r'^:foreach i in=\[/ip service find\]', 'stdout':
        'USED none\nUSED none\nUSED none\nUSED none\nUSED none\nUSED {CURRENT}\n'
        'USED {CURRENT}\n'},
    {'command': r'^:do \{:put \("USED "', 'stdout': 'USED none\n'},
    {'command': r'^(:foreach c in=|/file remove |/ip service set |/certificate remove |'
                r'/interface (sstp|ovpn)-server server set )', 'stdout': ''}]
# ---- end of targets hpe_synergy .. redfish_idrac ----
# ---- targets redfish@ilo .. zimbra (1.0.98): what each device answers on a renewal - the
# certificate of the renewal before there, replaced, the older acme ones cleaned up ----
_SOPHOS_OK = '<Login><status>Authentication Successful</status></Login>'
ANSWERS['sophos'] = [
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Get><Certificate>',
     'times': 1, 'headers': {'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<Certificate transactionid=""><Name>ApplianceCertificate</Name></Certificate>'
        '<Certificate transactionid=""><Name>{EARLIER2:50:6}</Name></Certificate>'
        '<Certificate transactionid=""><Name>{EARLIER:50:6}</Name></Certificate></Response>'},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Get><Certificate>',
     'headers': {'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<Certificate transactionid=""><Name>ApplianceCertificate</Name></Certificate>'
        '<Certificate transactionid=""><Name>{EARLIER2:50:6}</Name></Certificate>'
        '<Certificate transactionid=""><Name>{EARLIER:50:6}</Name></Certificate>'
        '<Certificate transactionid=""><Name>{CURRENT:50:6}</Name></Certificate></Response>'},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Get><FirewallRule>',
     'headers': {'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<FirewallRule transactionid=""><Name>{SEEN:criteria="=">([^<]*)<}</Name><PolicyType>HTTPBased'
        '</PolicyType><HTTPBasedPolicy><HTTPSCertificate>{EARLIER:50:6}</HTTPSCertificate>'
        '</HTTPBasedPolicy></FirewallRule></Response>'},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Remove>',
     'headers': {'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<Certificate transactionid=""><Status code="200">Configuration applied '
        'successfully.</Status></Certificate></Response>'},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<FirewallRule',
     'headers': {'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<FirewallRule transactionid=""><Status code="200">Configuration applied '
        'successfully.</Status></FirewallRule></Response>'},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'headers': {
        'Content-Type': 'application/xml'}, 'body':
        '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
        + _SOPHOS_OK + '<Certificate transactionid=""><Status code="200">Configuration applied '
        'successfully.</Status></Certificate></Response>'},
]
# DSM: the sign-in (sid, synotoken), the certificates - the one acme put there before under
# its description, the default one - the import (its id), the sign-out
ANSWERS['synology'] = [
    {'method': 'POST', 'url': r'/webapi/entry\.cgi', 'sent': r'api=SYNO\.API\.Auth&.*method=login',
     'body': {'data': {'did': '‹device id›', 'is_portal_port': False,
                       'sid': '{SESSION}', 'synotoken': '{SESSION}'}, 'success': True}},
    {'method': 'POST', 'url': r'/webapi/entry\.cgi', 'sent': r'api=SYNO\.Core\.Certificate\.CRT&.*method=list',
     'body': {'data': {'certificates': [
         {'desc': '{EACH:OPT:desc}', 'id': 'Xq3vTb', 'is_default': True,
          'is_broken': False, 'renewable': False, 'user_deletable': True,
          'subject': {'common_name': '{CERTNAME}'}, 'valid_till': 'Feb 11 08:00:00 2027 GMT',
          'services': [{'display_name': 'DSM Desktop Service', 'service': 'default',
                        'subscriber': 'system', 'owner': 'root', 'isPkg': False}]},
         {'desc': 'acme {LABEL}', 'id': 'Kd81Wm', 'is_default': True,
          'is_broken': False, 'renewable': False, 'user_deletable': True,
          'subject': {'common_name': '{CERTNAME}'}, 'valid_till': 'Feb 11 08:00:00 2027 GMT',
          'services': [{'display_name': 'DSM Desktop Service', 'service': 'default',
                        'subscriber': 'system', 'owner': 'root', 'isPkg': False}]},
         {'desc': '', 'id': 'Rm2kqP', 'is_default': False, 'is_broken': False,
          'renewable': False, 'user_deletable': False,
          'subject': {'common_name': 'synology'}, 'valid_till': 'Mar  3 10:15:00 2045 GMT',
          'services': []}]}, 'success': True}},
    {'method': 'POST', 'url': r'/webapi/entry\.cgi\?api=SYNO\.Core\.Certificate&.*method=import',
     'body': {'data': {'id': 'Kd81Wm', 'restart_http': True}, 'success': True}},
    {'method': 'POST', 'url': r'/webapi/entry\.cgi', 'sent': r'method=logout',
     'body': {'success': True}},
]
# TrueNAS (midclt over SSH): its certificates - the default, two acme put there before -, the
# web interface on the newer of those; the import's job done; listed with the new one after it
_TRUENAS_CERTS = ('{"id": 1, "type": 8, "name": "truenas_default", "cert_type": "CERTIFICATE", '
       '"common": "localhost", "issuer": "external", "until": "Wed Sep 10 08:12:30 2031"}, '
       '{"id": 4, "type": 8, "name": "{EARLIER2:63:8:_}", "cert_type": "CERTIFICATE", '
       '"common": "{CERTNAME}", "issuer": "external", "until": "Fri Feb 13 09:00:00 2026"}, '
       '{"id": 6, "type": 8, "name": "{EARLIER:63:8:_}", "cert_type": "CERTIFICATE", '
       '"common": "{CERTNAME}", "issuer": "external", "until": "Thu May 14 09:00:00 2026"}')
SSH_ANSWERS['truenas'] = [
    {'command': r'midclt call certificate\.query', 'times': 1, 'stdout': '[' + _TRUENAS_CERTS + ']\n'},
    {'command': r'midclt call certificate\.query', 'stdout':
        '[' + _TRUENAS_CERTS + ', {"id": 9, "type": 8, "name": "{CURRENT:63:8:_}", "cert_type": '
        '"CERTIFICATE", "common": "{CERTNAME}", "issuer": "external", '
        '"until": "Thu Feb 11 09:00:00 2027"}]\n'},
    {'command': r'midclt call system\.general\.config', 'stdout':
        '{"id": 1, "ui_address": ["0.0.0.0"], "ui_port": 80, "ui_httpsport": 443, '
        '"ui_httpsredirect": true, "ui_certificate": {"id": 6, "name": "{EARLIER:63:8:_}", '
        '"cert_type": "CERTIFICATE"}, "timezone": "Europe/Prague"}\n'},
    {'command': r'certificate\.create', 'stdout':
        '{"id": 9, "type": 8, "name": "{CURRENT:63:8:_}", "cert_type": "CERTIFICATE"}\n'},
    {'command': r'midclt call system\.general\.update', 'stdout':
        '{"id": 1, "ui_certificate": {"id": 9, "name": "{CURRENT:63:8:_}"}}\n'},
    {'command': r'midclt call system\.general\.ui_restart', 'stdout': 'null\n'},
    {'command': r'midclt call ftp\.update', 'stdout': '{"id": 1, "ssltls_certificate": 9}\n'},
    {'command': r'midclt call -j certificate\.delete', 'stdout':
        'Status: Deleting certificate\nTotal Progress: [########################################] '
        '100.00%\ntrue\n'},
]
# UniFi OS: the session the TOKEN cookie of the sign-in, its CSRF token a header; the
# certificates added there - two acme added before, the newer active -, the new one's id
_UNIFI_OLD = [
    {'id': '6650c1a2e4b0a1f3c2d1e0a1', 'name': '{EARLIER2}', 'active': False,
     'fingerprint': '5A:0E:1D:2C:3B:4A:59:68:76:00:11:22:33:44:55:66:77:88:99:A6',
     'subject': {'CN': '{CERTNAME}'}, 'validTo': '2026-02-12T09:00:00Z'},
    {'id': '66f1d0b3e4b0a1f3c2d1e0b2', 'name': '{EARLIER}', 'active': True,
     'fingerprint': '5A:0E:1D:2C:3B:4A:59:68:77:00:11:22:33:44:55:66:77:88:99:A7',
     'subject': {'CN': '{CERTNAME}'}, 'validTo': '2026-05-14T09:00:00Z'}]
ANSWERS['unifi_os'] = [
    {'method': 'POST', 'url': r'/api/auth/login$', 'body': {
        'unique_id': '‹user id›', 'username': '{CFG:user}', 'isOwner': False,
        'deviceToken': ''},
     'headers': {'Content-Type': 'application/json',
                 'Set-Cookie': 'TOKEN=PLANSESSION0token; path=/; samesite=strict; secure; httponly',
                 'X-CSRF-Token': '‹csrf token›'}},
    {'method': 'GET', 'url': r'/api/userCertificates$', 'times': 1, 'body': _UNIFI_OLD},
    {'method': 'POST', 'url': r'/api/userCertificates$', 'body': {
        'id': '67a2b9c4e4b0a1f3c2d1e0c3', 'name': '{SENT:name}', 'active': False}},
    {'method': 'GET', 'url': r'/api/userCertificates$', 'body': _UNIFI_OLD + [
        {'id': '67a2b9c4e4b0a1f3c2d1e0c3', 'name': '{CURRENT}', 'active': True,
         'fingerprint': '{FP1}', 'subject': {'CN': '{CERTNAME}'},
         'validTo': '2027-02-11T09:00:00Z'}]},
    {'method': 'PUT', 'url': r'/api/userCertificates/[^/]+/status$', 'body': {'active': True}},
    {'method': 'DELETE', 'url': r'/api/userCertificates/[^/]+$', 'body': {}},
]
# the certificate a device holds from the renewal before (another key, its own fingerprint)
_OLD_PEM = ('-----BEGIN CERTIFICATE-----\n'
            'MIIBiTCCAS+gAwIBAgIUY9Lv9vUV7BKizx5JYHEl/xbIWGAwCgYIKoZIzj0EAwIw\n'
            'GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMB4XDTI2MTExMzE2MDg1NVoXDTI3\n'
            'MDIxMTE2MDg1NVowGjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMFkwEwYHKoZI\n'
            'zj0CAQYIKoZIzj0DAQcDQgAESvI9qZBOGt9o3fYmLZeWpMKzjeSJjRDa+4+QC+d3\n'
            'QLTNowramYbjy2/IYb38w43OPgafMVqHx8vrjcjYodnPGKNTMFEwHQYDVR0OBBYE\n'
            'FLqmJxjaZTDTvtYLpGCvHLa5XhfVMB8GA1UdIwQYMBaAFLqmJxjaZTDTvtYLpGCv\n'
            'HLa5XhfVMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgSmUGNsO9\n'
            'BgIhAjDaF0Y9W3aY/cOf+q2VbmrFYgwLYQwCIQDtfQXvrmpVZSMCol2b7AQKm8uE\n'
            '6cRzLREnWYEIUb9xqg==\n'
            '-----END CERTIFICATE-----\n')
# Virtualmin (remote.cgi, text): the virtual server holds the certificate of the renewal
# before; install-cert installs and restarts what uses it
ANSWERS['virtualmin'] = [
    {'method': 'POST', 'url': r'/virtual-server/remote\.cgi$', 'sent': r'program=list-certs',
     'headers': {'Content-Type': 'text/plain'}, 'body': _OLD_PEM + '\nExit status: 0\n'},
    {'method': 'POST', 'url': r'/virtual-server/remote\.cgi$', 'sent': r'program=enable-feature',
     'headers': {'Content-Type': 'text/plain'}, 'body':
        'Enabling features for virtual server ..\n.. done\n\nExit status: 0\n'},
    {'method': 'POST', 'url': r'/virtual-server/remote\.cgi$', 'sent': r'program=install-cert',
     'headers': {'Content-Type': 'text/plain'}, 'body':
        'Installing new SSL files ..\n.. done\n\nRe-loading Apache webserver ..\n.. done\n'
        '\nExit status: 0\n'},
    {'method': 'POST', 'url': r'/virtual-server/remote\.cgi$', 'sent': r'program=list-domains',
     'headers': {'Content-Type': 'text/plain'}, 'body':
        '{OPT:domain}\nshop.example.com\n\nExit status: 0\n'},
]
# a webhook: the receiver takes it (what it answers is the receiver's own - 200 here)
ANSWERS['webhook'] = [{'method': 'POST', 'body': {'ok': True}}]
# Files over SSH (_files: hashes, place_lines): each file there holds the certificate of the
# renewal before (sha256sum prints another SHA-256 for every path asked), each is put in place
# - the old one there was copied aside (EXISTED i), the new one moved over (PLACED i), as the
# script's echo lines print it
_SSH_SHA = {'command': r'sha256sum ', 'seen_lines': True, 'stdout': ''.join(
    '5a0e1d2c3b4a5968%02d7e1f0c9b8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c  '
    '{SEEN:sha256sum (?:[^\\s\']+ ){%d}(/[^\\s\';]*)}\n' % (i, i) for i in range(12))}
_SSH_PLACED = {'command': r'echo "PLACED \d+"', 'seen_lines': True, 'stdout': ''.join(
    '{SEEN:echo "(EXISTED %d)"}\n{SEEN:echo "(PLACED %d)"}\n' % (i, i) for i in range(12))}
SSH_ANSWERS['ssh'] = [_SSH_SHA, _SSH_PLACED]
# what the services' own tests print (to stderr, exit 0), and the commands that print nothing
_SSH_SERVICES = [
    {'command': r'nginx -t', 'stderr': 'nginx: the configuration file /etc/nginx/nginx.conf syntax '
     'is ok\nnginx: configuration file /etc/nginx/nginx.conf test is successful\n'},
    {'command': r'apachectl -t|apache2ctl -t|httpd -t', 'stderr': 'Syntax OK\n'},
    {'command': r'haproxy -c', 'stdout': 'Configuration file is valid\n'},
    {'command': r'^(sh -c \'|sudo -[nS] (-p \'\' )?sh -c \')?(systemctl (reload|restart)|postfix '
     r'(check|reload)|doveconf -n|exim -bV|docker restart|rm -f|ls -1t|mv -f|chmod|chown)',
     'stdout': ''},
]
SSH_ANSWERS['ssh'] += _SSH_SERVICES
# strongSwan: the files there hold the renewal before's; swanctl --load-creds says what it
# loaded (ipsec rereadall nothing)
SSH_ANSWERS['strongswan'] = [_SSH_SHA, _SSH_PLACED, {
    'command': r'swanctl --load-creds', 'stdout':
        "loaded certificate from '{SEEN:mv -f \\S+ (/\\S+/x509/[^\\s/]+\\.crt)}'\n"
        "loaded certificate from '{SEEN:mv -f \\S+ (/\\S+/x509ca/[^\\s/]+\\.crt)}'\n"
        "loaded ecdsa key from '{SEEN:mv -f \\S+ (/\\S+/private/[^\\s/]+\\.key)}'\n"
        "no authorities found, 0 unloaded\nno pools found, 0 unloaded\n"},
    {'command': r'ipsec rereadall', 'stdout': ''}] + _SSH_SERVICES
# Traefik: the dynamic configuration there (another SHA-256), no files of the new name yet;
# the certificates' folder holds two acme wrote before and the new one
SSH_ANSWERS['traefik'] = [
    {'command': r'sha256sum ', 'seen_lines': True, 'stdout': ''.join(
        '5a0e1d2c3b4a5968%02d7e1f0c9b8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c  '
        '{SEEN:sha256sum (?:[^\\s\']+ ){%d}(/[^\\s\';]*\\.yml)}\n' % (i, i) for i in range(4))},
    {'command': r'echo "PLACED \d+"', 'times': 1, 'seen_lines': True, 'stdout': ''.join(
        '{SEEN:echo "(PLACED %d)"}\n' % i for i in range(4))},
    _SSH_PLACED,
    {'command': r'ls -1 ', 'stdout': '{EARLIER2}.crt\n{EARLIER2}.key\n{EARLIER}.crt\n'
                                     '{EARLIER}.key\n{CURRENT}.crt\n{CURRENT}.key\n'}] + _SSH_SERVICES
# Zimbra: commercial.key / .crt there (the renewal before's), the work files not; zmcertmgr
# says the key, certificate and chain match, deploys, zmcontrol restarts every service
SSH_ANSWERS['zimbra'] = [
    {'command': r'sha256sum ', 'seen_lines': True, 'stdout': ''.join(
        '5a0e1d2c3b4a5968%02d7e1f0c9b8a7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c  '
        '{SEEN:sha256sum (?:[^\\s\']+ ){%d}(/[^\\s\';]*/commercial/[^\\s\';]*)}\n' % (i, i)
        for i in range(4))},
    {'command': r'echo "PLACED \d+"', 'times': 1, 'seen_lines': True, 'stdout': ''.join(
        '{SEEN:echo "(PLACED %d)"}\n' % i for i in range(4))},
    _SSH_PLACED,
    {'command': r'zmcertmgr verifycrt', 'stdout':
        "** Verifying '/opt/zimbra/ssl/acme/cert.pem' against "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.key'\n"
        "Certificate '/opt/zimbra/ssl/acme/cert.pem' and private key "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.key' match.\n"
        "** Verifying '/opt/zimbra/ssl/acme/cert.pem' against '/opt/zimbra/ssl/acme/chain.pem'\n"
        "Valid certificate chain: /opt/zimbra/ssl/acme/cert.pem: OK\n"},
    {'command': r'zmcertmgr deploycrt', 'stdout':
        "** Verifying '/opt/zimbra/ssl/acme/cert.pem' against "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.key'\n"
        "Certificate '/opt/zimbra/ssl/acme/cert.pem' and private key "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.key' match.\n"
        "** Verifying '/opt/zimbra/ssl/acme/cert.pem' against '/opt/zimbra/ssl/acme/chain.pem'\n"
        "Valid certificate chain: /opt/zimbra/ssl/acme/cert.pem: OK\n"
        "** Copying '/opt/zimbra/ssl/acme/cert.pem' to "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.crt'\n"
        "** Copying '/opt/zimbra/ssl/acme/chain.pem' to "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial_ca.crt'\n"
        "** Appending ca chain '/opt/zimbra/ssl/acme/chain.pem' to "
        "'/opt/zimbra/ssl/zimbra/commercial/commercial.crt'\n"
        "** Importing cert '/opt/zimbra/ssl/zimbra/commercial/commercial_ca.crt' as "
        "'zcs-user-commercial_ca' into cacerts '/opt/zimbra/common/lib/jvm/java/lib/security/"
        "cacerts'\n** NOTE: restart mailboxd to use the imported certificate.\n"
        "** Saving config key 'zimbraSSLCertificate' via zmprov modifyServer {CERTNAME}...ok\n"
        "** Saving config key 'zimbraSSLPrivateKey' via zmprov modifyServer {CERTNAME}...ok\n"
        "** Installing imapd certificate '/opt/zimbra/conf/imapd.crt' and key "
        "'/opt/zimbra/conf/imapd.key'\n** Installing MTA certificate '/opt/zimbra/conf/smtpd.crt'"
        " and key '/opt/zimbra/conf/smtpd.key'\n** Installing proxy certificate "
        "'/opt/zimbra/conf/nginx.crt' and key '/opt/zimbra/conf/nginx.key'\n"
        "** Installing ldap certificate '/opt/zimbra/conf/slapd.crt' and key "
        "'/opt/zimbra/conf/slapd.key'\n"},
    {'command': r'zmcontrol restart', 'stdout':
        'Host {CERTNAME}\n\tStopping zmconfigd...Done.\n\tStopping zimlet webapp...Done.\n'
        '\tStopping proxy...Done.\n\tStopping mta...Done.\n\tStopping mailbox...Done.\n'
        '\tStopping ldap...Done.\nHost {CERTNAME}\n\tStarting ldap...Done.\n'
        '\tStarting mailbox...Done.\n\tStarting mta...Done.\n\tStarting proxy...Done.\n'
        '\tStarting zmconfigd...Done.\n'},
    {'command': r'zmproxyctl restart', 'stdout': 'Stopping proxy...done.\nStarting proxy...done.\n'
     'Stopping mailboxd...done.\nStarting mailboxd...done.\nRewrote: /opt/zimbra/conf/'
     'postfix_header_checks\nStopping saslauthd...done.\nStarting saslauthd...done.\n'
     '/postfix-script: refreshing the Postfix mail system\n'}] + _SSH_SERVICES


def _nth(before, group, after, i):
    """A regex finding the i-th (0: the first) "before GROUP after" of a script: its group."""
    one = before + group.replace('(', '(?:', 1) + after
    return '(?s)(?:%s.*?){%d}%s%s%s' % (one, i, before, group, after)


# Windows over OpenSSH (PowerShell, decoded): the new certificate not in the machine store yet;
# the import script says what it did - IMPORTED, each IIS binding, RDP, Exchange, the old one
# beyond "keep" removed (two acme put there before, the older goes); the files there hold
# the renewal before's (SHA), each was there (HAD); a role's script and the clean-up say their
# steps (STEP) as their Say does
_OLD_THUMB = '5A0E1D2C3B4A59687600112233445566778899A6'
_WIN = [
    {'command': r'powershell', 'script': r"Test-Path 'Cert:\\LocalMachine\\My\\[0-9A-Fa-f]+'\) \{ "
     r"'YES' \}", 'stdout': 'NO\n'},
    {'command': r'powershell', 'script': r'Write-Output "IMPORTED \$thumb"', 'seen_lines': True,
     'stdout': "IMPORTED {SEEN:\\$thumb = '([0-9A-Fa-f]{40})'}\n" + ''.join(
         'IIS {SEEN:%s}\n' % _nth(r"Write-Output \('IIS ' \+ '", r"([^']*)", r"'\)", i)
         for i in range(8)) +
        "{SEEN:Write-Output '(RDP)'}\n{SEEN:Write-Output '(EXCHANGE)'}\n"
        "{SEEN:\\('(REMOVED) ' \\+}" + ' ' + _OLD_THUMB + '\n'},
    {'command': r'powershell', 'script': r"Write-Output \('SHA ' \+", 'seen_lines': True,
     'stdout': ''.join(
         'SHA 5A0E1D2C3B4A5968%02d7E1F0C9B8A7D6E5F4A3B2C1D0E9F8A7B6C5D4E3F2A1B0C {SEEN:%s}\n'
         % (i, _nth(r"\$p = '", r"([^']+)", r"'; if \(Test-Path", i)) for i in range(12))},
    {'command': r'powershell', 'script': r"Write-Output \('HAD ' \+", 'seen_lines': True,
     'stdout': ''.join('HAD {SEEN:%s}\n' % _nth(r"Write-Output \('HAD ' \+ '", r"([^']+)",
                                                r"'\)", i) for i in range(12))},
    {'command': r'powershell', 'script': r"Grant-KeyRead \$cert '", 'seen_lines': True,
     'stdout': ''.join('STEP ok read on the key for {SEEN:%s}\n' % _nth(
         r"Grant-KeyRead \$cert '", r"([^']+)", r"'", i) for i in range(6))},
    {'command': r'powershell', 'script': r"Say info \('removed the old ' \+", 'stdout':
        'STEP info removed the old ' + _OLD_THUMB + '\n'},
    {'command': r'powershell', 'script': r'(?s)^(?:\$ErrorActionPreference[^\n]*\n'
     r'\$ProgressPreference[^\n]*\ntry \{\n)?(?:Remove-Item -LiteralPath [^\n]*(?:\n|; )?|'
     r'Get-ChildItem -LiteralPath [^\n]*Remove-Item[^\n]*\n?)+(?:\} catch[^\n]*\n?)?$',
     'stdout': ''},
]
SSH_ANSWERS['windows_ssh'] = list(_WIN)
# Windows products (windows_products): the import as windows_ssh's; each product's script says
# its steps - the renewal: the product used the certificate of the renewal before, moves to
# this one; the old ones beyond "keep" removed by the clean-up (_WIN)
_WIN_IMPORT = [
    {'command': r'powershell', 'script': r'Write-Output "IMPORTED \$thumb"', 'stdout':
        "IMPORTED {SEEN:\\$thumb = '([0-9A-Fa-f]{40})'}\n"}] + _WIN
SSH_ANSWERS['windows_wsus'] = [
    {'command': r'powershell', 'script': r"Need-Service 'WsusService'", 'seen_lines': True,
     'stdout': "STEP ok WSUS: {SEEN:\\$site = '([^']+)'} *:{SEEN:\\$port = (\\d+)}: uses it\n" +
        ''.join("STEP ok WSUS: {SEEN:%s} already requires SSL\n" % _nth(
            r"foreach \(\$v in @\((?:'[^']*', ){%d}" % i, r"'([^']+)'", '', 0) for i in range(5)) +
        "STEP ok WSUS: wsusutil configuressl {SEEN:@\\('configuressl', '([^']+)'\\)} - "
        "Successfully configured SSL.\n"}] + _WIN_IMPORT
SSH_ANSWERS['windows_hyperv_replica'] = [
    {'command': r'powershell', 'script': r"Need-Module 'Hyper-V'", 'seen_lines': True,
     'stdout': "STEP ok {SEEN:Say ok '(Hyper-V Replica server uses it)'}\n"
               "STEP ok {SEEN:Say ok \\('(Hyper-V Replica: )' \\+ \\$to}hvr02.example.com:443 "
               "takes it\n"
               "STEP ok {SEEN:Say ok \\('(Hyper-V Replica: VM )' \\+ \\$r}SQL01 uses it\n"
               "STEP ok {SEEN:Say ok \\('(Hyper-V Replica: VM )' \\+ \\$r}WEB01 uses it\n"}
] + _WIN_IMPORT
SSH_ANSWERS['windows_ssrs'] = [
    {'command': r'powershell', 'script': r'MSReportServer_ConfigurationSetting', 'stdout':
        'STEP ok Reporting Services: ReportServerWebService 0.0.0.0:443 uses it\n'
        'STEP ok Reporting Services: ReportServerWebApp 0.0.0.0:443 uses it\n'}] + _WIN_IMPORT
SSH_ANSWERS['windows_scom'] = [
    {'command': r'powershell', 'script': r"Need-Service 'HealthService'", 'seen_lines': True,
     'stdout': 'STEP ok Operations Manager uses it ({CERTNAME})\n'
               "STEP ok restarted {SEEN:Restart-Role '(HealthService)'}\n"
               "STEP warn {SEEN:Say warn '(Operations Manager takes it when the HealthService "
               "restarts)'}\n"}] + _WIN_IMPORT
SSH_ANSWERS['windows_oos'] = [
    {'command': r'powershell', 'script': r"Need-Module 'OfficeWebApps'", 'seen_lines': True,
     'stdout': "STEP ok Office Online Server uses it ({CURRENT})\n"
               "STEP warn {SEEN:Say warn '(Office Online Server: this server restarts in a "
               "minute)'}\n"
               "STEP warn {SEEN:Say warn '(Office Online Server takes it after the servers of "
               "the farm restart)'}\n"}] + _WIN_IMPORT
# Vault (KV v2): AppRole's token; the secret holds the certificate of the renewal before
# (version 3), the write makes version 4
ANSWERS['vault'] = [
    {'method': 'POST', 'url': r'/v1/auth/[^/]+/login$', 'body': {
        'request_id': '‹request›', 'auth': {
            'client_token': '{SESSION}', 'accessor': '‹accessor›',
            'policies': ['default', 'acme'], 'lease_duration': 3600, 'renewable': True}}},
    {'method': 'GET', 'url': r'/v1/[^?]+/data/', 'body': {
        'request_id': '‹request›', 'lease_id': '', 'renewable': False,
        'lease_duration': 0, 'data': {'data': {
            'certificate': _OLD_PEM, 'chain': '', 'fullchain': _OLD_PEM,
            'fingerprint': '5a0e1d2c3b4a59687700112233445566778899a7b6c5d4e3f2a1b0c9d8e7f6a5',
            'serial': '5A0E1D2C3B4A59687', 'names': '{CERTNAME}',
            'not_before': 1771146000, 'not_after': 1778922000, 'private_key': '‹key›'},
            'metadata': {'created_time': '2026-05-15T09:00:12.345678Z', 'custom_metadata': None,
                         'deletion_time': '', 'destroyed': False, 'version': 3}}}},
    {'method': 'POST', 'url': r'/v1/[^?]+/data/', 'body': {
        'request_id': '‹request›', 'data': {
            'created_time': '2026-11-13T09:00:12.345678Z', 'custom_metadata': None,
            'deletion_time': '', 'destroyed': False, 'version': 4}}},
    {'method': 'GET', 'url': r'/v1/auth/token/lookup-self$', 'body': {'data': {
        'display_name': 'approle', 'policies': ['default', 'acme']}}},
]
# Webglobe (the target; the validation's rules follow in ANSWERS['webglobe']): the JWT of the
# sign-in, the domains of the login with the one set, Webglobe's check of the certificate, the
# own certificate stored (its id), the redirect set
_WEBGLOBE_TARGET = [
    {'method': 'POST', 'url': r'/auth/login$', 'body': {'success': True, 'data': {
        'token': '{SESSION}', 'token_type': 'bearer', 'expires_in': 3600}}},
    {'method': 'GET', 'url': r'/domains\?per_page=', 'body': {'success': True, 'data': {
        '1001': {'domain': '{CFG:domain}', 'domain_id': 1001},
        '1002': {'domain': 'example.org', 'domain_id': 1002}}}},
    {'method': 'POST', 'url': r'/\d+/ssl/validate$', 'body': {'success': True, 'data': {
        'domain': '{CERTNAME}', 'valid_from': '2026-11-13', 'valid_to': '2027-02-11',
        'serial_number': '‹serial›', 'subject': {'CN': '{CERTNAME}'},
        'issuer': {'CN': '‹issuer›'}, 'purposes': [], 'extensions': {}}}},
    {'method': 'POST', 'url': r'/\d+/ssl/own-certificate$', 'body': {'success': True,
                                                                      'id': 4711}},
    {'method': 'POST', 'url': r'/\d+/ssl/httpsRedirect$', 'body': {'success': True}},
]
# SDDC Manager: its token; the trust store holds the VMCA root and another CA, not this
# certificate's issuers (a renewal from an intermediate the CA rotated to): both are added
ANSWERS['sddc_manager'] = [
    {'method': 'POST', 'url': r'/v1/tokens$', 'body': {
        'accessToken': '{SESSION}', 'refreshToken': {'id': '‹refresh token›'}}},
    {'method': 'GET', 'url': r'/v1/sddc-manager/trusted-certificates$', 'body': {'elements': [
        {'certificate': _OLD_PEM, 'certificateUsageType': 'TRUSTED_FOR_OUTBOUND',
         'issuedBy': 'CN=CA, DC=vsphere, DC=local', 'issuedTo': 'CN=CA, DC=vsphere, DC=local',
         'keySize': '2048', 'notAfter': '2034-03-01T10:00:00.000Z', 'numberOfDaysToExpire': 2665,
         'serialNumber': '‹serial›', 'thumbprint': '‹thumbprint›'}]}},
    {'method': 'POST', 'url': r'/v1/sddc-manager/trusted-certificates$', 'body': {}},
]
# a Redfish service root (the sign-in's address in it)
_REDFISH_ROOT = {'method': 'GET', 'url': r'/redfish/v1/?$', 'body': {
    '@odata.id': '/redfish/v1/', 'RedfishVersion': '1.15.1', 'Name': 'Root Service',
    'SessionService': {'@odata.id': '/redfish/v1/SessionService'},
    'Managers': {'@odata.id': '/redfish/v1/Managers'},
    'Links': {'Sessions': {'@odata.id': '/redfish/v1/SessionService/Sessions'}}}}
_REDFISH_SIGNOUT = {'method': 'DELETE', 'url': r'/SessionService/Sessions/', 'status': 204,
                    'body': ''}
_RF_SESSION = {
    'method': 'POST', 'url': r'/SessionService/Sessions/?$', 'status': 201, 'body': {
        '@odata.id': '/redfish/v1/SessionService/Sessions/‹session›',
        'Id': '‹session›', 'UserName': '{CFG:user}'},
    'headers': {'Content-Type': 'application/json', 'X-Auth-Token': 'PLANSESSION0token',
                'Location': '/redfish/v1/SessionService/Sessions/‹session›/'}}
# Supermicro: the upload taken (Redfish's success message), its one manager reset
ANSWERS['supermicro_bmc'] = [
    _REDFISH_ROOT, _RF_SESSION,
    {'method': 'POST', 'url': r'/SmcSSLCert\.Upload$', 'body': {
        'Success': {'code': 'Base.v1_10_3.Success', 'Message': 'Successfully Completed Request',
                    '@Message.ExtendedInfo': [{'MessageId': 'Base.1.10.Success',
                                               'Message': 'Successfully Completed Request',
                                               'Severity': 'OK', 'Resolution': 'None'}]}}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {
        'Members': [{'@odata.id': '/redfish/v1/Managers/1'}], 'Members@odata.count': 1}},
    {'method': 'POST', 'url': r'/Actions/Manager\.Reset$', 'status': 204, 'body': ''},
    _REDFISH_SIGNOUT,
]
# an iLO 6 (firmware 1.62, in Production): its HTTPS certificate is the renewal before's (RSA);
# the import taken, the iLO resets
ANSWERS['redfish@ilo'] = [
    _REDFISH_ROOT, _RF_SESSION,
    {'method': 'GET', 'url': r'/redfish/v1/Managers/?$', 'body': {'Members': [
        {'@odata.id': '/redfish/v1/Managers/1/'}], 'Members@odata.count': 1}},
    {'method': 'GET', 'url': r'/redfish/v1/Managers/1/?$', 'body': {
        '@odata.id': '/redfish/v1/Managers/1/', 'Id': '1', 'Model': 'iLO 6',
        'FirmwareVersion': 'iLO 6 v1.62', 'ManagerType': 'BMC',
        'Oem': {'Hpe': {'Firmware': {'Current': {'VersionString': 'iLO 6 v1.62'}}}}}},
    {'method': 'GET', 'url': r'/SecurityService/?$', 'body': {
        'SecurityState': 'Production', 'Links': {'HttpsCert': {
            '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/'}}}},
    {'method': 'GET', 'url': r'/HttpsCert/?$', 'body': {
        '@odata.id': '/redfish/v1/Managers/1/SecurityService/HttpsCert/', 'Id': 'HttpsCert',
        'KeyType': 'RSA', 'CertificateSigningRequest': '',
        'X509CertificateInformation': {
            'Issuer': '/C=US/O=Let\'s Encrypt/CN=R11', 'SerialNumber': '5a0e1d2c3b4a59687',
            'Subject': '/CN={CERTNAME}', 'ValidNotAfter': 'May 16 09:00:00 2026 GMT',
            'ValidNotBefore': 'Feb 15 09:00:00 2026 GMT'},
        'Actions': {'#HpeHttpsCert.ImportCertificate': {
            'target': '/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/'
                      'HpeHttpsCert.ImportCertificate/'},
            '#HpeHttpsCert.GenerateCSR': {
            'target': '/redfish/v1/Managers/1/SecurityService/HttpsCert/Actions/'
                      'HpeHttpsCert.GenerateCSR/'}}}},
    {'method': 'PATCH', 'url': r'/HttpsCert/?$', 'body': {'error': {
        'code': 'iLO.0.10.ExtendedInfo', '@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.15.Success'}]}}},
    {'method': 'POST', 'url': r'HpeHttpsCert\.ImportCertificate/?$', 'body': {'error': {
        'code': 'iLO.0.10.ExtendedInfo', 'message': 'See @Message.ExtendedInfo for more '
        'information.', '@Message.ExtendedInfo': [
            {'MessageId': 'iLO.2.15.ImportCertSuccessfuliLOResetinProgress'}]}}},
    _REDFISH_SIGNOUT,
]
# Unisphere for PowerMax 10.1 (REST API 101); each node's import taken (an empty JSON answer)
ANSWERS['unisphere_powermax'] = [
    {'method': 'GET', 'url': r'/univmax/restapi/version$', 'body': {
        'version': 'V10.1.0.2', 'api_version': '101', 'supported_api_versions': ['101', '100']}},
    {'method': 'POST', 'url': r'/solutions_enabler/custom_certificate/import$', 'body': {}},
    {'method': 'GET', 'url': r'/serviceability/symmetrix/[^/]+/application/unisphere$', 'body': {
        'node_name': 'Semgmt0', 'status': 'Online'}},
]
# Unity: svc_custom_cert says it installed the files; the files taken away after
SSH_ANSWERS['unity'] = [
    {'command': r'^svc_custom_cert ', 'stdout':
        'Successfully installed custom certificate files.\n'},
    {'command': r'^rm -f ', 'stdout': ''}]
# Cloud Director: the token a header of the sign-in; the new alias not in the library yet;
# the cells (those named, else two), each endpoint on the item of the renewal before; the
# import's id; the endpoints' change a task running, then done; the library holding the two
# acme put there before and the new one - the older beyond "keep" used by nothing, deleted
_VCD_ITEM = 'urn:vcloud:certificateLibraryItem:'
ANSWERS['vcd'] = [
    {'method': 'POST', 'url': r'/sessions/provider$', 'body': {
        'id': 'urn:vcloud:session:‹session›', 'site': {'name': 'vcd'},
        'user': {'name': '{CFG:user}'}, 'roles': ['System Administrator']},
     'headers': {'Content-Type': 'application/json;version=39.0',
                 'X-VMWARE-VCLOUD-ACCESS-TOKEN': 'PLANSESSION0token',
                 'X-VMWARE-VCLOUD-TOKEN-TYPE': 'Bearer'}},
    {'method': 'GET', 'url': r'/ssl/certificateLibrary\?filter=', 'body': {
        'resultTotal': 0, 'pageCount': 0, 'page': 1, 'pageSize': 128, 'values': []}},
    {'method': 'GET', 'url': r'/cells\?', 'body': {'resultTotal': 2, 'pageCount': 1, 'page': 1,
                                                   'pageSize': 128, 'values': [
        {'id': 'urn:vcloud:cell:3f1c0a52-cell-0001', 'name': '{EACH:OPT:cells}',
         'primaryIp': '10.0.10.11', 'status': 'ACTIVE'},
        {'id': 'urn:vcloud:cell:3f1c0a52-cell-0001', 'name': 'vcd-cell1', 'primaryIp': '10.0.10.11',
         'status': 'ACTIVE'},
        {'id': 'urn:vcloud:cell:3f1c0a52-cell-0002', 'name': 'vcd-cell2', 'primaryIp': '10.0.10.12',
         'status': 'ACTIVE'}]}},
    {'method': 'POST', 'url': r'/ssl/certificateLibrary$', 'status': 201, 'body': {
        'id': _VCD_ITEM + '9b2e0c41-new', 'alias': '{SENT:alias}',
        'description': '{SENT:description}', 'certificate': '‹certificate›'}},
    {'method': 'GET', 'url': r'/cells/[^/]+/accessEndpoints$', 'body': {
        'apiSslCertRef': {'id': _VCD_ITEM + '5a0e1d2c-earlier', 'name': '{EARLIER}'},
        'consoleProxySslCertRef': {'id': _VCD_ITEM + '5a0e1d2c-earlier', 'name': '{EARLIER}'},
        'publicUrl': 'https://{CERTNAME}', 'consoleProxyPublicUrl': 'https://{CERTNAME}:8443'}},
    {'method': 'PUT', 'url': r'/cells/[^/]+(/accessEndpoints)?$', 'status': 202, 'body': '',
     'headers': {'Location': '/api/task/\u2039task\u203a'}},
    {'method': 'GET', 'url': r'/cells/[^/?]+$', 'body': {
        'id': 'urn:vcloud:cell:3f1c0a52-cell-0001', 'name': 'vcd-cell1', 'status': 'ACTIVE'}},
    {'method': 'GET', 'url': r'/api/task/', 'times': 1, 'body': {
        'status': 'running', 'operation': 'Updating cell endpoints'}},
    {'method': 'GET', 'url': r'/api/task/', 'body': {'status': 'success'}},
    {'method': 'GET', 'url': r'/ssl/certificateLibrary\?page=', 'body': {
        'resultTotal': 3, 'pageCount': 1, 'page': 1, 'pageSize': 128, 'values': [
            {'id': _VCD_ITEM + '1c7d9e30-earlier2', 'alias': '{EARLIER2}'},
            {'id': _VCD_ITEM + '5a0e1d2c-earlier', 'alias': '{EARLIER}'},
            {'id': _VCD_ITEM + '9b2e0c41-new', 'alias': '{CURRENT}'}]}},
    {'method': 'GET', 'url': r'/consumers\?', 'body': {
        'resultTotal': 0, 'pageCount': 0, 'page': 1, 'pageSize': 25, 'values': []}},
    {'method': 'DELETE', 'url': r'/ssl/certificateLibrary/', 'status': 204, 'body': ''},
]
# vCenter: the session (a JSON string); the machine SSL certificate there the renewal
# before's; the chain added to the trusted roots (its id); the replacement taken (204); signed
# out (204). Its version (VI JSON API) 8.0.3
_VS_SESSION = {'method': 'POST', 'url': r'/api/session$', 'status': 201,
                    'body': '"PLANSESSION0token"'}
_VSPHERE_SIGNOUT = {'method': 'DELETE', 'url': r'/api/session$', 'status': 204, 'body': ''}
_VC_ABOUT = {'method': 'GET', 'url': r'/sdk/vim25/[^/]+/ServiceInstance/ServiceInstance/content$',
             'body': {'_typeName': 'ServiceContent', 'about': {
                 '_typeName': 'AboutInfo', 'name': 'VMware vCenter Server',
                 'fullName': 'VMware vCenter Server 8.0.3 build 24322831', 'vendor': 'VMware, Inc.',
                 'version': '8.0.3', 'build': '24322831', 'apiVersion': '8.0.3.0',
                 'productLineId': 'vpx', 'apiType': 'VirtualCenter'}}}
_VC_TLS = {'method': 'GET', 'url': r'/certificate-management/vcenter/tls$', 'body': {
    'subject_dn': 'CN={CERTNAME}', 'issuer_dn': "CN=R11, O=Let's Encrypt, C=US",
    'serial_number': '5a0e1d2c3b4a59687', 'thumbprint':
        '5A:0E:1D:2C:3B:4A:59:68:77:00:11:22:33:44:55:66:77:88:99:A7',
    'valid_from': '2026-05-15T09:00:00.000Z', 'valid_to': '2026-08-13T09:00:00.000Z',
    'version': 3, 'is_CA': False, 'key_usage': ['digitalSignature', 'keyEncipherment'],
    'extended_key_usage': ['serverAuth'], 'subject_alternative_name': ['{CERTNAME}']}}
ANSWERS['vcenter'] = [
    _VS_SESSION, _VC_ABOUT, _VC_TLS,
    {'method': 'POST', 'url': r'/certificate-management/vcenter/trusted-root-chains$',
     'status': 201, 'body': '"‹chain id›"'},
    {'method': 'PUT', 'url': r'/certificate-management/vcenter/tls$', 'status': 204, 'body': ''},
    _VSPHERE_SIGNOUT]


def _vc_about(ver, build):
    return {'method': 'GET', 'url': r'/sdk/vim25/[^/]+/ServiceInstance/ServiceInstance/content$',
            'body': {'_typeName': 'ServiceContent', 'about': {
                '_typeName': 'AboutInfo', 'name': 'VMware vCenter Server',
                'fullName': 'VMware vCenter Server %s build %s' % (ver, build),
                'vendor': 'Broadcom', 'version': ver, 'build': build, 'apiVersion': ver + '.0',
                'productLineId': 'vpx', 'apiType': 'VirtualCenter'}}}


# the Supervisor: vCenter 9.1 (9.0 for the version of 9.0); the endpoint holds the
# certificate of the renewal before; the replacement taken (204)
_SUP_OLD = {'tls_endpoint_certificate': _OLD_PEM, 'endpoint': 'KUBERNETES_API_SERVER'}
ANSWERS['vsphere_supervisor'] = [
    _VS_SESSION, _vc_about('9.1.0', '24957300'),
    {'method': 'GET', 'url': r'/namespace-management/supervisors/[^/]+/certificates$',
     'body': [_SUP_OLD, {'tls_endpoint_certificate': '', 'endpoint': 'DEFAULT_NSX_INGRESS'}]},
    {'method': 'GET', 'url': r'/namespace-management/clusters/[^/]+$', 'body': {
        'config_status': 'RUNNING', 'kubernetes_status': 'READY',
        'api_server_management_endpoint': '10.0.40.2', 'tls_endpoint_certificate': _OLD_PEM}},
    {'method': 'PATCH', 'url': r'/namespace-management/', 'status': 204, 'body': ''},
    _VSPHERE_SIGNOUT]
ANSWERS['vsphere_supervisor@9.0'] = [_vc_about('9.0.0', '24755230')]
# Live Site Recovery / vSphere Replication: session_id of the sign-in; the appliance holds the
# certificate of the renewal before; the CA certificates and the PKCS#12 taken (204)
ANSWERS['vmware_dr'] = [
    {'method': 'POST', 'url': r'/session$', 'body': {'session_id': '{SESSION}'}},
    {'method': 'GET', 'url': r'/appliance/certificates/server$', 'body': {
        'certificate': _OLD_PEM, 'subject_dn': 'CN={CERTNAME}',
        'issuer_dn': "CN=R11, O=Let's Encrypt, C=US", 'not_before': '2026-05-15T09:00:00Z',
        'not_after': '2026-08-13T09:00:00Z',
        'thumbprint': '5A:0E:1D:2C:3B:4A:59:68:77:00:11:22:33:44:55:66:77:88:99:A7'}},
    {'method': 'POST', 'url': r'/appliance/certificates/ca$', 'status': 204, 'body': ''},
    {'method': 'POST', 'url': r'/appliance/certificates/server$', 'status': 204, 'body': ''},
]
# VCF component through SDDC Manager, key made by the device: the token, the domain named,
# each task running once and then done, the CSR made ({CSR}), the validation in progress once
# and then succeeded
ANSWERS['vcf_component'] = [
    {'method': 'POST', 'url': r'/v1/tokens$', 'body': {
        'accessToken': '{SESSION}', 'refreshToken': {'id': '‹refresh token›'}}},
    {'method': 'GET', 'url': r'/v1/domains$', 'body': {'elements': [
        {'id': '‹domain›', 'name': '{CFG:domain}', 'type': 'MANAGEMENT',
         'status': 'ACTIVE'}]}},
    {'method': 'PUT', 'url': r'/v1/domains/[^/]+/csrs$', 'status': 202, 'body': {
        'id': '‹task›', 'name': 'Generate CSR(s)', 'status': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/v1/domains/[^/]+/csrs$', 'body': {'elements': [
        {'csrEncodedContent': '{CSR}', 'resource': {
            'fqdn': '{SEEN:"resources": \\[."fqdn": "([^"]+)"}',
            'type': '{SEEN:"resources": \\[.[^\\]]*?"type": "([^"]+)"}'}}]}},
    {'method': 'PUT', 'url': r'/resource-certificates/validations$', 'status': 201, 'body': {
        'validationId': '‹validation›', 'executionStatus': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/resource-certificates/validations/', 'times': 1, 'body': {
        'validationId': '‹validation›', 'executionStatus': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/resource-certificates/validations/', 'body': {
        'validationId': '‹validation›', 'executionStatus': 'COMPLETED',
        'resultStatus': 'SUCCEEDED', 'validations': [
            {'resourceFqdn': '{CERTNAME}', 'resultStatus': 'SUCCEEDED'}]}},
    {'method': 'PUT', 'url': r'/v1/domains/[^/]+/resource-certificates$', 'status': 202,
     'body': {'id': '‹task›', 'name': 'Replace certificate(s)',
              'status': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/v1/tasks/', 'times': 1, 'body': {
        'id': '‹task›', 'status': 'IN_PROGRESS'}},
    {'method': 'GET', 'url': r'/v1/tasks/', 'body': {
        'id': '‹task›', 'status': 'SUCCESSFUL'}},
    {'method': 'GET', 'url': r'/v1/sddc-managers$', 'body': {'elements': [
        {'version': '5.2.1.0-24307856', 'fqdn': '{CFG:host}'}]}},
]
# its version 9.1 - VCF Operations: the token, the version 9.1, the component's certificate
# (the FQDN asked), each workflow in progress once and then completed, the CSR made ({CSR}),
# the token released
ANSWERS['vcf_component@9.1'] = [
    {'method': 'POST', 'url': r'/auth/token/acquire$', 'body': {
        'token': '{SESSION}', 'validity': 1763049600000, 'expiresAt': 'Thu Nov 13 16:00:00 UTC '
        '2026', 'roles': []}},
    {'method': 'POST', 'url': r'/auth/token/release$', 'status': 200, 'body': ''},
    {'method': 'GET', 'url': r'/suite-api/api/versions/current$', 'body': {
        'releaseName': 'VCF Operations 9.1', 'major': 9, 'minor': 1, 'minorMinor': 0}},
    {'method': 'POST', 'url': r'/certificates/query', 'body': {'vcfCertificateModels': [
        {'certificateResourceKey': '‹certificate›',
         'applianceFqdn': '{SENT:applianceFqdn}', 'category': 'TLS_CERT',
         'issuedTo': '{SENT:applianceFqdn}', 'expiryDate': '2026-12-01'}]}},
    {'method': 'POST', 'url': r'/certificate-management/csrs$', 'body': {
        'requestId': '‹request›', 'state': 'INPROGRESS'}},
    {'method': 'GET', 'url': r'/certificate-management/csrs\?', 'body': {
        'certificateSignatureInfo': [{'csr': '{CSR}'}]}},
    {'method': 'PUT', 'url': r'/certificate-management/certificates/', 'status': 202,
     'body': {'requestId': '‹request›', 'state': 'INPROGRESS'}},
    {'method': 'GET', 'url': r'/workflows/requests/', 'times': 1, 'body': {
        'requestId': '‹request›', 'state': 'INPROGRESS'}},
    {'method': 'GET', 'url': r'/workflows/requests/', 'body': {
        'requestId': '‹request›', 'state': 'COMPLETED'}},
]
# Veeam (PowerShell over SSH, _veeam): an administrator; the version and the certificate there
# (the renewal before's); the import (not in the store yet - the chain trusted already), the
# certificate set, the older acme one beyond "keep" removed, the services restarted - as the
# scripts' STEP lines print it
_OLD_THUMB2 = '5A0E1D2C3B4A59687700112233445566778899A7'
_VEEAM = [
    {'command': r'powershell', 'script': r'Write-Output \("WHO \$env:USERNAME', 'stdout':
        'WHO {CFG:user}|True\n'},
    {'command': r'powershell', 'script': r'-match \(\'\^\' \+ \[regex\]::Escape', 'seen_lines': True,
     'stdout': "{SEEN:Write-Output '(STEP ok imported the certificate into "
               "LocalMachine\\\\My)'}\n"
               "{SEEN:Write-Output '(STEP ok the backup server certificate is set)'}\n"
               "SET {SEEN:\\$thumb = '([0-9A-Fa-f]{40})'}\n"
               "{SEEN:Write-Output '(STEP ok the REST API \\(0\\.0\\.0\\.0:9419\\) uses it)'}"
               "\n{SEEN:Write-Output '(STEP ok Cloud Connect uses the new certificate)'}\n"
               "STEP info removed the old " + _OLD_THUMB + '\n' + ''.join(
                   "STEP ok restarted {SEEN:%s}\n" % _nth(r"Write-Output \('STEP ok restarted ' "
                                                         r"\+ '", r"([^']+)", r"'\)", i)
                   for i in range(4))},
] + _WIN
SSH_ANSWERS['veeam_vbr'] = [
    {'command': r'powershell', 'script': r'Get-Command Add-VBRBackupServerCertificate', 'stdout':
        'FORCE True\nBUILD 13.0.1.180\nCURRENT ' + _OLD_THUMB2 + '\n'}] + _VEEAM
SSH_ANSWERS['veeam_vbr@12.3'] = [
    {'command': r'powershell', 'script': r'Get-Command Add-VBRBackupServerCertificate', 'stdout':
        'FORCE False\nBUILD 12.3.1.1139\nCURRENT ' + _OLD_THUMB2 + '\n'}]
SSH_ANSWERS['veeam_cloud_connect'] = [
    {'command': r'powershell', 'script': r'Get-VBRCloudGatewayCertificate -ErrorAction Stop',
     'stdout': 'CURRENT ' + _OLD_THUMB2 + '\n'}] + _VEEAM
SSH_ANSWERS['veeam_vb365'] = [
    {'command': r'powershell', 'script': r'Import-Module Veeam\.Archiver\.PowerShell',
     'seen_lines': True, 'stdout': ''.join(
         '{SEEN:%s}\n' % _nth(r"Write-Output '", r"(STEP ok [^']+)", r"'", i) for i in range(6))},
] + _VEEAM
SSH_ANSWERS['truenas'] += _SSH_SERVICES
ANSWERS['webglobe'] = _WEBGLOBE_TARGET + ANSWERS.get('webglobe', [])
# ---- end of targets redfish@ilo .. zimbra ----
FIRST = {
    # OneView: the CA of the chain not in its trust store yet the first time (added)
    'hpe_oneview': [
        {'method': 'GET', 'url': r'/rest/certificates/ca/', 'status': 404, 'body': {
            'errorCode': 'RESOURCE_NOT_FOUND', 'message': 'The requested resource could '
            'not be found.'}}],
    # Kubernetes, the first time: no secret of the name yet
    'kubernetes': [
        {'method': 'GET', 'url': r'/api/v1/namespaces/[^/]+/secrets/[^/?]+$', 'status': 404,
         'body': {'kind': 'Status', 'apiVersion': 'v1', 'status': 'Failure',
                  'message': 'secrets "{TAIL}" not found', 'reason': 'NotFound', 'code': 404}}],
    # NetScaler, the first time: no certkey of the name, the vserver on the appliance's own
    'netscaler': [
        {'method': 'GET', 'url': r'/nitro/v1/config/sslcertkey/', 'status': 404,
         'body': {'errorcode': 1540, 'message': 'Certificate does not exist'}},
        {'method': 'GET', 'url': r'/nitro/v1/config/sslvserver_sslcertkey_binding/',
         'body': {'errorcode': 0, 'message': 'Done', 'sslvserver_sslcertkey_binding': [
             {'vservername': '{TAIL}', 'certkeyname': 'ns-server-certificate'}]}},
    ],
}
# ---- targets a10 .. cisco_nxos: the first deployment (FIRST: nothing there yet) and the
# renewals (LATER: [] - the ANSWERS above, the certificate there) ----
# Aruba Central: the name is not in the store the first time (uploaded), then replaced
FIRST['aruba_central'] = [{'method': 'GET', 'url': r'/configuration/v1/certificates\?',
                           'body': {'items': [], 'total': 0}}]
LATER['aruba_central'] = []
# Azure Key Vault: no certificate of the name the first time, a new version of it then
FIRST['azure_keyvault'] = [{'method': 'GET', 'url': r'/certificates/[^/?]+\?api-version=',
                            'status': 404, 'body': {'error': {
                                'code': 'CertificateNotFound', 'message':
                                    'A certificate with (name/id) {TAIL} was not found in this '
                                    'key vault.'}}}]
LATER['azure_keyvault'] = []
# Cisco FMC: the first time no earlier Internal Certificate (no rule switched: said), no Cert
# Enrollment object (made) and nothing enrolled on the devices (ENROLL)
FIRST['cisco_fmc'] = [
    {'method': 'GET', 'url': r'/object/(internalcertificates|certenrollments)\?', 'body': {
        'items': [], 'paging': {'offset': 0, 'limit': 1000, 'count': 0, 'pages': 0}}},
    {'method': 'GET', 'url': r'/devices/certificates\?filter=', 'body': {'items': []}}]
LATER['cisco_fmc'] = []
# ---- end of targets a10 .. cisco_nxos (FIRST / LATER) ----
# ---- targets redfish@ilo .. zimbra: the first deployment (FIRST: nothing of acme there yet)
# and the renewals (LATER: [] - the ANSWERS above, the certificate of the renewal before) ----
_SOPHOS_FIRST_LIST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<Response APIVersion="2000.1" IPS_CAT_VER="1">'
    '<Login><status>Authentication Successful</status></Login><Certificate transactionid="">'
    '<Name>ApplianceCertificate</Name></Certificate></Response>')
# Sophos: only the appliance's own certificate the first time (the rule on it)
FIRST['sophos'] = [
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Get><Certificate>',
     'times': 1, 'headers': {'Content-Type': 'application/xml'}, 'body': _SOPHOS_FIRST_LIST},
    {'method': 'POST', 'url': r'/webconsole/APIController$', 'sent': r'<Get><Certificate>',
     'headers': {'Content-Type': 'application/xml'}, 'body': _SOPHOS_FIRST_LIST.replace(
         '</Response>', '<Certificate transactionid=""><Name>{CURRENT:50:6}</Name>'
                        '</Certificate></Response>')}]
LATER['sophos'] = []
# UniFi OS: no certificate added the first time
FIRST['unifi_os'] = [{'method': 'GET', 'url': r'/api/userCertificates$', 'times': 1,
                      'body': []}]
LATER['unifi_os'] = []
# DSM: no certificate of the description the first time - imported as a new one
FIRST['synology'] = [
    {'method': 'POST', 'url': r'/webapi/entry\.cgi', 'sent': r'api=SYNO\.Core\.Certificate\.CRT&',
     'body': {'data': {'certificates': [
         {'desc': '', 'id': 'Rm2kqP', 'is_default': True, 'is_broken': False,
          'subject': {'common_name': 'synology'}, 'services': []}]}, 'success': True}}]
LATER['synology'] = []
# Vault: no secret at the path the first time
FIRST['vault'] = [{'method': 'GET', 'url': r'/v1/[^?]+/data/', 'status': 404,
                   'body': {'errors': []}}]
LATER['vault'] = []
# Cloud Director: no acme item in the library the first time - nothing to delete
FIRST['vcd'] = [{'method': 'GET', 'url': r'/ssl/certificateLibrary\?page=', 'body': {
    'resultTotal': 1, 'pageCount': 1, 'page': 1, 'pageSize': 128, 'values': [
        {'id': 'urn:vcloud:certificateLibraryItem:9b2e0c41-new', 'alias': '{CURRENT}'}]}}]
LATER['vcd'] = []
# TrueNAS: only its own certificate the first time, the web interface on it
SSH_FIRST['truenas'] = [
    {'command': r'midclt call certificate\.query', 'times': 1, 'stdout':
        '[{"id": 1, "type": 8, "name": "truenas_default", "cert_type": "CERTIFICATE"}]\n'},
    {'command': r'midclt call certificate\.query', 'stdout':
        '[{"id": 1, "type": 8, "name": "truenas_default", "cert_type": "CERTIFICATE"}, '
        '{"id": 9, "type": 8, "name": "{CURRENT:63:8:_}", "cert_type": "CERTIFICATE"}]\n'},
    {'command': r'midclt call system\.general\.config', 'stdout':
        '{"id": 1, "ui_certificate": {"id": 1, "name": "truenas_default"}}\n'}]
SSH_LATER['truenas'] = []
# files over SSH: none there the first time (sha256sum prints nothing, nothing EXISTED)
for _k in ('ssh', 'strongswan', 'traefik', 'zimbra'):
    SSH_FIRST[_k] = [{'command': r'sha256sum ', 'stdout': ''},
                     {'command': r'echo "PLACED \d+"', 'seen_lines': True, 'stdout': ''.join(
                         '{SEEN:echo "(PLACED %d)"}\n' % i for i in range(12))}]
    SSH_LATER[_k] = []
# ---- end of targets redfish@ilo .. zimbra (FIRST / LATER) ----


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
        return {(_filled(k, cfg, opts) if isinstance(k, str) else k): _filled(x, cfg, opts)
                for k, x in v.items()}
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


def answers_of(kind, cfg=None, opts=None, first=True, later=False, version='', family=None):
    """The answers a module's recording gets: FIRST (or LATER) and ANSWERS of its kind - those
    of its version ("kind@version") before those of the kind -, the settings put in where an
    answer names them. A source's or a validation's (family 'issuer' / 'challenge', 1.0.98):
    those of plansources.py first - a kind there is of that family only (a target of the same
    kind - Plesk, bunny.net - answers otherwise)."""
    own = []
    if family in ('issuer', 'challenge'):
        from acmelib.certs import plansources
        own = plansources.answers(family, kind, version)
    rules = own + (LATER.get(kind, []) if later else FIRST.get(kind, []) if first else []) + \
        (ANSWERS.get('%s@%s' % (kind, version), []) if version else []) + (
            ANSWERS.get(kind, []) if not (own and family) else [])
    cfg, opts = dict(cfg or {}), dict(opts or {})
    return [dict(r, body=_filled(r['body'], cfg, opts)) if 'body' in r else dict(r)
            for r in rules]


def ssh_answers_of(kind, cfg=None, opts=None, version='', first=True, later=False,
                   family=None):
    """What the SSH commands of a module's recording print: SSH_FIRST (or SSH_LATER, 1.0.98)
    and SSH_ANSWERS of its version and kind, the settings put in where an answer names them;
    a validation's (family 'challenge'): those of plansources.py only."""
    if family in ('issuer', 'challenge'):
        from acmelib.certs import plansources
        rules = plansources.ssh_answers(family, kind, version)
    else:
        rules = (SSH_LATER.get(kind, []) if later else SSH_FIRST.get(kind, []) if first
                 else []) + (SSH_ANSWERS.get('%s@%s' % (kind, version), []) if version
                             else []) + SSH_ANSWERS.get(kind, [])
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
            shaped = self.shaped(v, str(f.get('label') or k), marks)
            if shaped is not None:
                out[k] = shaped
                continue
            self.n += 1
            si = _stand_in(self.n)
            out[k] = si
            marks[si] = str(f.get('label') or k)
        for k, v in list(out.items()):
            if isinstance(v, str) and (v.startswith('sealed:') or '-----BEGIN' in v and
                                       'PRIVATE' in v):
                self.keep(v)
                shaped = self.shaped(v, k, marks) if not v.startswith('sealed:') else None
                if shaped is not None:
                    out[k] = shaped
                    continue
                self.n += 1
                si = _stand_in(self.n)
                out[k] = si
                marks[si] = k
        return out, marks

    def shaped(self, v, label, marks):
        """A stand-in of the secret's own shape (1.0.98), or None: a module that signs with a
        private key (a service account's JSON, a JWK, a PEM key: Google, OCI, TransIP, step-ca)
        gets a throwaway key of the same kind, made here for the run - the real one is never
        handed; a JSON of several secrets (acme-dns accounts) the same JSON, each secret in it a
        stand-in."""
        from acmelib.certs import pki

        def key_like(pem):
            kt = 'ec-256'
            try:
                kt = pki.key_info(pem)['key_type']
            except Exception:                           # noqa: BLE001
                kt = 'rsa-2048' if 'RSA' in pem else 'ec-256'
            return pki.make_key(kt if str(kt).startswith(('rsa', 'ec', 'ed')) else 'ec-256')

        def ec_jwk(jwk):
            # a throwaway P-256 key as a private JWK, the other members (kid, use) kept
            out = pki.openssl(['ec', '-text', '-noout'], pki.make_key('ec-256'))
            out = out.decode() if isinstance(out, bytes) else out
            hx = {}
            for part in ('priv', 'pub'):
                m = re.search(part + r':\s*\n((?:\s+[0-9a-f:]+\n)+)', out)
                hx[part] = bytes.fromhex(re.sub(r'[^0-9a-f]', '', m.group(1)))
            d = hx['priv'].rjust(32, b'\0')[-32:]
            pub = hx['pub'][1:]

            def b64u(b):
                return base64.urlsafe_b64encode(b).decode().rstrip('=')
            return dict(jwk, kty='EC', crv='P-256', x=b64u(pub[:32]), y=b64u(pub[32:]),
                        d=b64u(d))

        def walk(x, path):
            if isinstance(x, dict):
                if x.get('kty') and x.get('d'):
                    if x.get('kty') == 'EC':
                        return ec_jwk(x)
                    return key_like('RSA')
                return {a: walk(b, path + [str(a)]) for a, b in x.items()}
            if isinstance(x, list):
                return [walk(b, path) for b in x]
            if isinstance(x, str) and '-----BEGIN' in x and 'PRIVATE KEY' in x:
                return key_like(x)
            if isinstance(x, str) and x and path and (re.search(
                    r'(pass|secret|private|apikey|credential)', path[-1], re.I) or re.search(
                    r'(^|_)(key|token)$', path[-1], re.I)):
                self.keep(x)
                self.n += 1
                si = _stand_in(self.n)
                marks[si] = '%s: %s' % (label, path[-1])
                return si
            return x
        try:
            if isinstance(v, str) and v.strip()[:1] in ('{', '['):
                got = json.loads(v)
                if isinstance(got, (dict, list)):
                    w = walk(got, [])
                    return w if isinstance(w, str) else json.dumps(w)
            if isinstance(v, str) and '-----BEGIN' in v and 'PRIVATE KEY' in v:
                return key_like(v)
        except Exception:                               # noqa: BLE001
            return None
        return None

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


def _answer_ver(cls):
    """The version whose canned answers a module's recording gets (1.0.98): its own - or, for
    a version of your own made from a shipped one (Download a start: the same class, a new
    number), the shipped version it was made from, whose API it speaks; an override, the one
    it replaces."""
    v = _ver(cls)
    if cls is None or getattr(cls, '_origin', 'builtin') == 'builtin':
        return v
    rep = getattr(cls, '_replaced', None)
    if rep is not None:
        return _ver(rep)
    try:
        fam = next((f for f, b in base.FAMILIES.items() if issubclass(cls, b)), None)
        for sv, sc in (base.REGISTRY.versions.get(fam, {}).get(cls.kind) or {}).items():
            if getattr(sc, '_origin', 'builtin') == 'builtin' and sc.__name__ == cls.__name__:
                return sv
            if getattr(sc, '_replaced', None) is not None and sc._replaced.__name__ == cls.__name__:
                return _ver(sc._replaced)
    except Exception:                               # noqa: BLE001
        pass
    return v


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
            if ev.get('body_facts'):
                st['detail']['body_facts'] = ev['body_facts']
            st['detail']['conn'] = _conn_of(url, ev, proxy_on)
            # the request as it goes on the wire (1.0.37): every header, the ones acme
            # and Python add too, and the body as sent - secrets left out by scrub().
            # The sandbox works it out from what the module sent (1.0.98), before masking
            # - a form stays a form, a multipart body its parts; else here from the event.
            try:
                if isinstance(ev.get('wire'), dict):
                    w = ev['wire']
                    st['detail']['wire'] = {'line': w.get('line'), 'body': w.get('body'),
                                            'headers': [list(h) for h in w.get('headers') or []]}
                else:
                    from acmelib.certs import runtime as _rt
                    st['detail']['wire'] = _rt.wire_request(m, url, ev.get('headers') or {},
                                                            ev.get('body'),
                                                            own=bool(ev.get('own')))
                # recorded with stand-ins (the certificate, the secrets): the real length differs
                for h in st['detail']['wire']['headers']:
                    if h[0] == 'Content-Length':
                        h[1] = '≈ %s' % h[1]
            except Exception:                           # noqa: BLE001
                pass
            # what the stand-in device answered (debug details); a call no prepared answer
            # matched is marked - its answer is a generic stand-in, not the device's
            if isinstance(ev.get('answered'), dict):
                st['detail']['answer'] = dict(ev['answered'])
            elif ev.get('answer') is not None:
                st['detail']['answer'] = {'status': ev.get('answer')}
            if ev.get('fallback') and 'answer' in st['detail']:
                st['detail']['answer']['fallback'] = ev['fallback']
            notes = []
            if ev.get('own'):
                notes.append('a connection the module makes itself (http.client), not through acme')
            if ev.get('kept'):
                notes.append('on one connection kept open for the whole sign-in (Windows '
                             'authentication signs in a connection, not a request); no proxy')
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
            # what it uploads (1.0.98): its format, size and sha256 - a key marked
            path = re.sub(r'^\s*(STOR|APPE|STOU)\s+', '', str(ev.get('cmd') or ''), flags=re.I)
            if ev.get('format'):
                st['detail'] = {'path': path, 'format': ev.get('format'), 'size': ev.get('bytes'),
                                'sha256': ev.get('sha256'), 'text': '→ %s' % ev.get('cmd')}
            if ev.get('secret'):
                st['secret'] = True
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
                # what goes on its input, readable (debug details; secrets out)
                if inp.get('body') is not None:
                    st['detail']['input_body'] = inp['body']
                if inp.get('sha256'):
                    st['detail']['input_sha256'] = inp['sha256']
            # what the stand-in device printed (debug details), a stand-in answer marked
            if isinstance(ev.get('answer'), dict):
                st['detail']['answer'] = dict(ev['answer'])
                if ev.get('fallback'):
                    st['detail']['answer']['fallback'] = ev['fallback']
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
            if ev.get('sha256'):
                st['detail']['sha256'] = ev['sha256']
            if ev.get('command'):
                st['detail']['put_command'] = ev['command']
            if ev.get('secret'):
                st['secret'] = True
        elif k == 'ssh-get':
            st = {'kind': 'read', 'words': 'Reads a file from {0}'.replace('{0}',
                                                                           ev.get('host') or ''),
                  'detail': {'path': ev.get('path')}, 'invented': True}
            if ev.get('command'):
                st['detail']['put_command'] = ev['command']
            if isinstance(ev.get('answer'), dict):
                st['detail']['answer'] = dict(ev['answer'], fallback=ev.get('fallback'))
        elif k == 'bypass':
            # a call around acme's connection layer (1.0.98): a bug in the module - shown as
            # an error, so no call it makes is ever missing from here unseen
            st = {'kind': 'stop', 'error': True,
                  'words': 'The module went around acme\'s connection layer: {0}'.replace(
                      '{0}', {'http.client': 'HTTP of its own (http.client / urllib)',
                              'socket': 'a connection of its own', 'udp': 'UDP of its own',
                              'dns': 'a DNS lookup of its own',
                              'program': 'a program run by itself'}.get(
                                  ev.get('how'), str(ev.get('how') or ''))),
                  'detail': {'text': ev.get('what') or ''},
                  'note': 'refused here and not recorded as acme would make it - the module '
                          'must make this call through acme (ctx)'}
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
            # what the stand-in device served (1.0.98): the earlier certificate before the new
            # one was sent, the new one after
            served = merged[i][0].get('served') or ev.get('served')    # the last one asked
            if served:
                st['served'] = served
            hh, _, pp = hp.rpartition(':')
            st['detail']['conn'] = ([['Here', 'the stand-in served an earlier certificate'
                                      if served == 'earlier' else
                                      'the stand-in served the new certificate', 'dim']]
                                    if served else []) + [['Address', hh, ''], ['Port', pp, ''],
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
    # the order itself asked for until it is ready, and after the finalize until it is valid
    # (1.0.98: acme.py polls the order URL both times - POST-as-GET)
    steps.append({'kind': 'wait', 'words': 'Asks for the order until it is ready (every {0} s, '
                  'at most {1} s)'.replace('{0}', '%g' % float(cfg.get('poll_every') or 5))
                  .replace('{1}', '%g' % float(cfg.get('wait_valid') or 180)),
                  'detail': {'method': 'POST', 'url': '‹order URL›', 'headers': {},
                             'body': {'protected': dict(jws, kid=kid), 'payload': ''}}})
    steps.append({'kind': 'sign', 'words': 'Finalizes the order with the request (CSR)',
                  'detail': {'method': 'POST', 'url': '‹finalize URL of the order›',
                             'headers': {}, 'body': {'protected': dict(jws, kid=kid),
                                                     'payload': {'csr': '‹the CSR, '
                                                                 'DER, base64url›'}}}})
    steps.append({'kind': 'wait', 'words': 'Asks for the order again while the CA makes the '
                  'certificate (processing) until it is valid (at most {0} s)'.replace(
                      '{0}', '%g' % float(cfg.get('wait_order') or 300)),
                  'detail': {'method': 'POST', 'url': '‹order URL›', 'headers': {},
                             'body': {'protected': dict(jws, kid=kid), 'payload': ''}},
                  'note': 'not stopped from here on: a certificate the CA made is never left '
                          'behind'})
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
    # a commercial CA's domain validation (DCV, issuers/_dcv.py): the records of its own shape
    # are put in place by the validations within its issue() - recorded there (1.0.98)
    dcv_src = bool(needs and irow and irow.get('kind') != 'acme' and getattr(icls, 'dcv', None))
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
        vinfo[which] = {'row': crow, 'cls': ccls, 'cfg': ccfg, 'runs': [], 'scfg': scfg,
                        'marks': marks}
        if crow.get('kind') == 'dns_persist':
            continue                    # nothing put in place per order: persist_steps()
        if dcv_src:
            continue                    # the CA's own records: put in place in the source's run
        for n in ns[:NAMES_MOST]:
            vinfo[which]['runs'].append((n, run(family='challenge', kind=crow['kind'],
                                                name=crow['name'], op='challenge', names=[n],
                                                config=scfg, marks=marks,
                                                answers=answers_of(crow['kind'], scfg,
                                                                   first=False,
                                                                   family='challenge'),
                                                ssh_answers=ssh_answers_of(
                                                    crow['kind'], scfg, family='challenge'))))
    # the source, where it is not written here
    iid = None
    if irow and icls and irow.get('kind') not in ('acme', 'internal_ca', 'selfsigned'):
        scfg, marks = secrets_.stand_ins(_fields_of(icls), icfg)
        dcv = {}
        for n, which in (chal.items() if dcv_src else ()):
            vi = vinfo.get(which) or {}
            if vi.get('row') and vi.get('cls') and 'scfg' in vi:
                dcv[n] = {'kind': vi['row']['kind'], 'name': which, 'config': vi['scfg'],
                          'answers': answers_of(vi['row']['kind'], vi['scfg'], first=False,
                                                family='challenge'),
                          'ssh_answers': ssh_answers_of(vi['row']['kind'], vi['scfg'],
                                                        family='challenge')}
                marks = dict(marks, **vi['marks'])
        # a renewal hands the certificate it renews (CertRequest.previous)
        iid = run(family='issuer', kind=irow['kind'], name=irow['name'], op='issue',
                  config=scfg, marks=marks, answers=answers_of(irow['kind'], scfg, first=False,
                                                               family='issuer'),
                  challenges=dcv, previous=bool(cert.get('cert_pem')),
                  pinned=__import__('acmelib.certs.plansources', fromlist=['PINNED']).PINNED.get(
                      irow['kind'], []))
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
                answers=answers_of(drow['kind'], dcfg, dsopts, version=_answer_ver(dcls)),
                ssh_answers=ssh_answers_of(drow['kind'], dcfg, dsopts, version=_answer_ver(dcls))))
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
        kw['answers'] = answers_of(trow['kind'], scfg, sopts, version=_answer_ver(tcls))
        kw['ssh_answers'] = ssh_answers_of(trow['kind'], scfg, sopts, version=_answer_ver(tcls))
        if trow['kind'] == 'acme_push':
            kw['push_pin'] = push_pin_of(store, tcls, tcfg)
        kept = kept_of(store, trow, tcls, tcfg, opts, cert)
        if kept:
            kw['kv'] = kept
        if trow['kind'] in LATER or trow['kind'] in SSH_LATER:
            kw['later_answers'] = answers_of(trow['kind'], scfg, sopts, later=True,
                                             version=_answer_ver(tcls))
            kw['later_ssh_answers'] = ssh_answers_of(trow['kind'], scfg, sopts, later=True,
                                                     version=_answer_ver(tcls))
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
    if any(r.get('kind') == 'appliance' for r in runs):
        job['pages'] = pages_of(store)
    if any(r.get('kind') == 'dns_builtin' or 'dns_builtin' in [
            c.get('kind') for c in (r.get('challenges') or {}).values()] for r in runs):
        # acme's own DNS server (1.0.98): its zone and addresses, as ctx.dns_server_info()
        # gives them to the validation (plansandbox.PlanContext) - none secret
        try:
            from acmelib.certs import dnsserver
            job['settings']['_dns_server'] = dnsserver.server_info(store)
        except Exception:                               # noqa: BLE001
            pass
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
        if dcv_src:
            g['steps'] = [{'kind': 'info', 'words': 'It puts in place the records (or files) '
                           '{0} asks for - of the CA\'s own shape, with the values the order '
                           'gives - within the source\'s run: The source shows each call, the '
                           'wait until they can be seen and their taking away'.replace(
                               '{0}', (icls.title if icls else '') or irow['kind'])}]
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
                    'not_after': cert.get('not_after'), 'draft': not cert.get('id'),
                    # the device that makes its key (certs.csr_from): the page says so
                    'csr_from': cert.get('csr_from') or ''},
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


# The target modules there were in 1.0.92 - the last version whose modules checked what is
# served themselves after a deployment ("verify"); a test made from a deployment on a module
# added later never was the module's own check.
KINDS_BY_1092 = frozenset((
    'a10', 'acme_push', 'appliance', 'avi', 'aws_acm', 'azure_appgw', 'azure_appservice',
    'azure_keyvault', 'barracuda_waf', 'bunny', 'caddy', 'checkpoint', 'cisco_asa', 'cisco_fmc',
    'cisco_ftd_fdm', 'cisco_ise', 'cloudflare_ssl', 'cpanel_ssl', 'digitalocean_lb',
    'directadmin_ssl', 'docker_swarm', 'esxi', 'f5', 'fastly', 'flowmon', 'fortiadc',
    'fortigate', 'fortiweb', 'fritzbox', 'froxlor', 'gcp_certmanager', 'haproxy', 'hestiacp',
    'hetzner_lb', 'ispconfig', 'juniper_srx', 'kemp', 'kong', 'kubernetes', 'local', 'mikrotik',
    'netscaler', 'nginx_proxy_manager', 'nginx_unit', 'nsx', 'nutanix', 'omnissa_uag',
    'opnsense', 'paloalto', 'pfsense', 'plesk', 'proxmox', 'proxmox_backup', 'redfish',
    'simple', 'sophos', 'ssh', 'ssh_connector', 'strongswan', 'synology', 'traefik', 'truenas',
    'unifi_os', 'vault', 'vcenter', 'virtualmin', 'webglobe', 'webhook', 'windows_ssh',
    'zimbra'))


def waits_words(waits):
    """The waits of the tests after a deployment, in words: "after 3, 10, 20 s", and a long
    run of the same wait said once (1.0.96: "after 3, 30, 30, 30..." - 31 times "30")."""
    waits = [int(x) if float(x) == int(x) else x for x in waits or []]
    if len(waits) > 2 and len(set(waits[1:])) == 1:
        return 'after {0} s, then {1} more times, {2} s apart'.replace(
            '{0}', str(waits[0])).replace('{1}', str(len(waits) - 1)).replace('{2}', str(waits[1]))
    return 'after %s s' % ', '.join(str(x) for x in waits)


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
                # "until 1.0.92 its module checked it" - only of a module there was then (1.0.96:
                # said of a module new in 1.0.96 too)
                at = CK.auto_target(store, r['test'])
                arow = S.plugin_row(store, 'target', at) if at else None
                steps.append({'kind': 'info', 'words': 'Made by acme from a deployment: what the '
                              'target serves', 'note': 'its module checked it itself until 1.0.92; '
                              'taken off, it is not attached again' if arow and
                              arow.get('kind') in KINDS_BY_1092 else
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
                          .replace('{0}', str(len(waits))), 'note': waits_words(waits) + (
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
    elif cert.get('state') == 'held' or (not cert.get('id') and cert.get('hold')):
        # "Add only" (1.0.26): never issued by itself (1.0.96: said it would be, at the next look)
        steps.append({'kind': 'wait', 'words': 'Not issued by itself: it was only added - it '
                      'waits until Issue now is pressed in its window'})
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
    # a signed token (JWT / compact JWS: a service account's assertion, a provisioner's
    # token): its header and payload as they are, the signature said (1.0.98)
    text = re.sub(r'\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]{16,}',
                  r'\1.' + DOTS + ' (signature)', text)
    text = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
                  DOTS + ' (private key)', text)
    return json.loads(text)
