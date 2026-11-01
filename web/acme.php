<?php
/* acme.php - the answer to an ACME CA's HTTP-01 challenge (1.0.169), and to a
   commercial CA's file-based domain validation (DigiCert http-token, Sectigo
   FILE): nginx sends http://NAME/.well-known/acme-challenge/TOKEN and
   http://NAME/.well-known/pki-validation/FILE here, on port 80; the answer is
   kept in acme's database, so whichever node the CA reaches - the one with the
   web address, in a cluster - gives it. Nothing else is said, so anybody may ask. */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';
header('Cache-Control: no-store');
$uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$uri = (string) preg_replace('#\?.*$#', '', $uri);

function acme_not_found(): void
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "not found\n";
    exit;
}

if (preg_match('#^/\.well-known/acme-challenge/([A-Za-z0-9_-]{8,256})$#', $uri, $m)) {
    $got = acme_get('/api/acme/challenge?token=' . $m[1], 10.0);
    if (!is_array($got) || !isset($got['auth']) || !is_string($got['auth'])) {
        acme_not_found();
    }
    header('Content-Type: application/octet-stream');
    echo $got['auth'];
    exit;
}
if (preg_match('#^/\.well-known/pki-validation/([A-Za-z0-9_.-]{1,128})$#', $uri, $m)
        && strpos($m[1], '..') === false) {
    $host = strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
    $host = (string) preg_replace('#:\d+$#', '', $host);
    if (!preg_match('#^[a-z0-9_.-]{1,253}$#', $host)) {
        acme_not_found();
    }
    $got = acme_get('/api/acme/file?host=' . rawurlencode($host) . '&path='
        . rawurlencode('/.well-known/pki-validation/' . $m[1]), 10.0);
    if (!is_array($got) || !isset($got['content']) || !is_string($got['content'])) {
        acme_not_found();
    }
    header('Content-Type: text/plain; charset=utf-8');
    echo $got['content'];
    exit;
}
acme_not_found();
