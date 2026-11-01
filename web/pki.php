<?php
/* pki.php - the CRLs and certificates of acme's own authorities, for
   everybody, over plain HTTP (docs/own-ca.md, "Publishing on acme").
   nginx sends /pki/ here on port 80 (never redirected to HTTPS: a CRL fetcher
   seldom follows one) and on 443:

     /pki/                   a page listing what is published
     /pki/<slug>.crl         the newest CRL, DER     application/pkix-crl
     /pki/<slug>.crl.pem     the same, PEM
     /pki/<slug>.crt         the authority's certificate, DER   application/pkix-cert
     /pki/<slug>.pem         the same, PEM

   Everything comes from acme's database through the daemon's public,
   read-only routes (GET /api/pki/...), which give only what is published - so
   every node and the VIP address answer alike. Nothing else is said. */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';

function pki_say(int $code, string $words): void
{
    http_response_code($code);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo $words, "\n";
    exit;
}

if (!in_array((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'), ['GET', 'HEAD'], true)) {
    header('Allow: GET, HEAD');
    pki_say(405, 'only GET');
}
$uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
$path = (string) parse_url($uri, PHP_URL_PATH);

if ($path === '/pki' || $path === '/pki/' || $path === '/pki/index.html') {
    [$status, $body] = acme_call('/api/pki/index', 'GET', null, 10.0);
    $got = $status === 200 ? json_decode($body, true) : null;
    if (!is_array($got)) {
        pki_say($status === 429 ? 429 : 503, $status === 429 ? 'too many requests' : 'not available just now');
    }
    $rows = is_array($got['published'] ?? null) ? $got['published'] : [];
    $h = static fn ($v): string => htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    $when = static fn ($ts): string => is_numeric($ts) ? gmdate('Y-m-d H:i', (int) $ts) . ' UTC' : '–';
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: max-age=300');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'");
    header('X-Content-Type-Options: nosniff');
    echo "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">",
         "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
         "<title>Certificate authorities</title><style>",
         "body{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem;color:#1f2933;background:#fff}",
         "h1{font-size:1.4rem}table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #e4e7eb;vertical-align:top}",
         "code{font-size:.85rem;word-break:break-all}.muted{color:#616e7c;font-size:.85rem}",
         "@media (prefers-color-scheme:dark){body{background:#12161b;color:#e4e7eb}th,td{border-color:#323f4b}a{color:#7cc4fa}.muted{color:#9aa5b1}}",
         "</style></head><body><h1>Certificate authorities</h1>";
    if (!$rows) {
        echo '<p class="muted">Nothing is published here.</p>';
    } else {
        echo '<table><thead><tr><th>Authority</th><th>CRL</th><th>Certificate</th><th>Next CRL by</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            if (!is_array($r)) {
                continue;
            }
            echo '<tr><td><b>', $h($r['name'] ?? ''), '</b><div class="muted">', $h($r['subject'] ?? ''), '</div></td>',
                 '<td><a href="', $h($r['crl'] ?? ''), '">DER</a> · <a href="', $h($r['crl_pem'] ?? ''), '">PEM</a></td>',
                 '<td><a href="', $h($r['cert'] ?? ''), '">DER</a> · <a href="', $h($r['cert_pem'] ?? ''), '">PEM</a>',
                 '<div class="muted"><code>SHA-256 ', $h($r['fingerprint'] ?? ''), '</code></div></td>',
                 '<td>', $h($when($r['next_update'] ?? null)), '</td></tr>';
        }
        echo '</tbody></table>';
    }
    echo "</body></html>\n";
    exit;
}

if (!preg_match('#^/pki/([a-z0-9][a-z0-9._-]{0,79}?)\.(crl\.pem|crl|crt|cer|pem)$#', $path, $m)) {
    pki_say(404, 'not found');
}
[$slug, $ext] = [$m[1], $m[2]];
$what = str_starts_with($ext, 'crl') ? 'crl' : 'cert';
$fmt = ($ext === 'crl.pem' || $ext === 'pem') ? 'pem' : 'der';
[$status, $body] = acme_call('/api/pki/' . $what . '?ca=' . rawurlencode($slug) . '&format=' . $fmt,
                             'GET', null, 15.0);
$got = $status === 200 ? json_decode($body, true) : null;
if (!is_array($got) || !is_string($got['data_b64'] ?? null)) {
    pki_say($status === 429 ? 429 : ($status === 0 || $status >= 500 ? 503 : 404),
            $status === 429 ? 'too many requests' : ($status === 0 || $status >= 500 ? 'not available just now' : 'not found'));
}
$data = base64_decode($got['data_b64'], true);
if ($data === false) {
    pki_say(503, 'not available just now');
}
$mime = (string) ($got['mime'] ?? 'application/octet-stream');
if (!preg_match('#^application/[a-z0-9.+-]{1,60}$#', $mime)) {
    $mime = 'application/octet-stream';
}
$file = preg_replace('/[^A-Za-z0-9._-]/', '_', (string) ($got['filename'] ?? ($slug . '.' . $ext)));
header('Content-Type: ' . $mime);
header('Content-Length: ' . strlen($data));
header('Content-Disposition: inline; filename="' . $file . '"');
header('X-Content-Type-Options: nosniff');
/* A CRL changes after a revocation: a few minutes in a cache at most. */
header('Cache-Control: ' . ($what === 'crl' ? 'max-age=300' : 'max-age=3600'));
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
    echo $data;
}
