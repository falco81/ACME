# -*- coding: utf-8 -*-
"""
pfSense over SSH: a PHP script run with pfSense's own functions imports the
certificate into the certificate manager, points the web GUI at it and
deletes older acme ones.

Checked against api-docs/pfsense/notes.md: pfSense CE has no official REST API
(the pfSense-pkg-RESTAPI package is not Netgate's), so SSH and pfSense's own
PHP functions stay. The documents' GUI steps: a certificate is edited in place
("The Certificate Data, which may need to be replaced if the certificate was
renewed") - Force on a name there already now does that, its refid kept,
instead of removing it and importing it anew; "To remove a certificate, first
it must be removed from active use" - older ones are kept when pfSense's
cert_in_use() says something still uses them (OpenVPN, IPsec, the captive
portal, packages), not only the web GUI. Less certain: cert_import() and
cert_in_use() are pfSense's code, not documented functions.
"""
from __future__ import annotations

import base64

from acmelib.plugins.targets._common import (
    Base, SshMixin, PluginError, field, as_bool, object_name, name_prefix, ssh_fields,
    verify_fields, keep_field, text)

PHP = r'''<?php
require_once("config.inc");
require_once("certs.inc");
global $config;
$descr  = base64_decode('%(descr)s');
$prefix = base64_decode('%(prefix)s');
$crt    = base64_decode('%(crt)s');
$key    = base64_decode('%(key)s');
$gui    = %(gui)s;
$keep   = %(keep)d;
$force  = %(force)s;
$get = function ($p, $d) { global $config;
    if (function_exists('config_get_path')) { return config_get_path($p, $d); }
    $v = $config; foreach (explode('/', $p) as $k) { if (!is_array($v) || !isset($v[$k])) { return $d; } $v = $v[$k]; }
    return $v; };
$set = function ($p, $v) { global $config;
    if (function_exists('config_set_path')) { config_set_path($p, $v); return; }
    $r = &$config; foreach (explode('/', $p) as $k) { if (!isset($r[$k]) || !is_array($r[$k])) { $r[$k] = array(); } $r = &$r[$k]; }
    $r = $v; };
$certs = $get('cert', array());
if (!is_array($certs)) { $certs = array(); }
$ref = null;
$changed = false;
foreach ($certs as $i => $c) {
    if (($c['descr'] ?? '') === $descr && $ref === null) {
        $ref = $c['refid'];
        if ($force) {
            /* edited in place, as System > Certificates > Edit does: its refid (and every
               service pointing at it) stays */
            cert_import($certs[$i], $crt, $key); $changed = true;
            echo "REPLACED $ref\n";
            if ($get('system/webgui/ssl-certref', '') === $ref) { echo "GUIUSES\n"; }
        }
    }
}
if ($ref === null) {
    $new = array('refid' => uniqid(), 'descr' => $descr);
    cert_import($new, $crt, $key);
    $certs[] = $new; $ref = $new['refid']; $changed = true;
    echo "IMPORTED $ref\n";
}
if ($gui && $get('system/webgui/ssl-certref', '') !== $ref) {
    $set('system/webgui/ssl-certref', $ref); $changed = true; echo "GUI\n";
}
$guiref = $gui ? $ref : $get('system/webgui/ssl-certref', '');
if ($keep >= 0) {
    $mine = array();
    foreach ($certs as $i => $c) {
        $d = $c['descr'] ?? '';
        if ($c['refid'] !== $ref && strpos($d, $prefix) === 0 && preg_match('/^\d{8}-[0-9a-f]+$/', substr($d, strlen($prefix)))) { $mine[$d] = $i; }
    }
    krsort($mine);
    foreach (array_slice($mine, $keep, null, true) as $d => $i) {
        if ($certs[$i]['refid'] === $guiref) { echo "INUSE $d\n"; continue; }
        /* "To remove a certificate, first it must be removed from active use" - OpenVPN,
           IPsec, the captive portal, packages: pfSense's own check, where it has one */
        if (function_exists('cert_in_use') && cert_in_use($certs[$i]['refid'])) { echo "INUSE $d\n"; continue; }
        unset($certs[$i]); $changed = true; echo "REMOVED $d\n";
    }
}
if ($changed) { $set('cert', array_values($certs)); write_config('acme: certificate ' . $descr); }
echo "DONE\n";
'''


class PfSenseTarget(SshMixin, Base):
    kind = 'pfsense'
    discovery = False       # nothing to find: a server over SSH
    title = 'pfSense'
    vendor = 'Netgate'
    description = ('Imports the certificate into the pfSense certificate manager over SSH '
                   '(its own PHP functions), makes the web GUI use it and deletes older ones.')
    doc = 'targets.md'
    fields = ssh_fields(sudo=False, user_default='admin', howto='pfsense') + [
        field('php', 'PHP', 'text', default='/usr/local/bin/php', advanced=True),
        field('timeout', 'Timeout (s)', 'number', default=60, advanced=True),
    ]
    deploy_fields = [
        field('webgui', 'Web GUI certificate', 'bool', default=True),
        keep_field(2),
    ] + verify_fields()

    def php(self, s, script):
        rc, out, err = s.run(self.c('php') or '/usr/local/bin/php', input=script, timeout=180,
                             check=False)
        out = text(out)
        if rc != 0 or 'DONE' not in out:
            raise PluginError('the PHP script on pfSense failed: %s'
                              % (out.strip() or text(err).strip())[-300:], detail=out + text(err))
        return out

    def test(self):
        with self.ssh() as s:
            out = self.php(s, '<?php require_once("config.inc"); echo trim(@file_get_contents('
                              '"/etc/version")) . "\\nDONE\\n";')
        return 'signed in to %s, pfSense %s' % (self.c('host'), out.split('\n')[0].strip())

    def deploy(self, bundle, options):
        options = options or {}
        name = object_name(bundle, options)
        e = lambda b: base64.b64encode(b if isinstance(b, bytes) else b.encode()).decode()  # noqa
        gui = as_bool(self.opt(options, 'webgui', True), True)
        script = PHP % {
            'descr': e(name), 'prefix': e(name_prefix(bundle, options)),
            'crt': e(bundle.as_format('fullchain-pem')), 'key': e(bundle.as_format('key-pem')),
            'gui': 'true' if gui else 'false', 'keep': self.keep(options),
            'force': 'true' if as_bool(options.get('force')) else 'false'}
        with self.ssh() as s:
            out = self.php(s, script)
            did = []
            for line in out.splitlines():
                if line.startswith('IMPORTED'):
                    did.append('imported %s' % name)
                    self.ctx.step('imported %s' % name, 'ok')
                elif line.startswith('REPLACED'):
                    did.append('replaced %s in place' % name)
                    self.ctx.step('replaced %s in place' % name, 'ok')
                elif line in ('GUI', 'GUIUSES'):
                    did.append('web GUI')
                elif line.startswith('REMOVED '):
                    self.ctx.step('deleted the old %s' % line[8:])
                elif line.startswith('INUSE '):
                    self.ctx.step('the old %s is still used: kept' % line[6:], 'warn')
            if 'web GUI' in did:
                s.run('/etc/rc.restart_webgui', timeout=120, check=False)
                self.ctx.step('the web GUI uses %s and was restarted' % name, 'ok')
        self.remember(bundle, options)
        return ', '.join(did) or self.same(bundle, 'as %s' % name)
