<?php
/* metrics.php - Prometheus' scrape of this node (1.0.173): GET /metrics with
   Authorization: Bearer TOKEN. The daemon checks the token and where it comes
   from; nothing is said without both. */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';
header('Cache-Control: no-store');
$auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
$token = preg_match('/^Bearer ([A-Za-z0-9_.~+\/=-]{24,200})$/', trim($auth), $m) ? $m[1] : '';
if ($token === '') {
    http_response_code(401);
    header('WWW-Authenticate: Bearer realm="acme metrics"');
    header('Content-Type: text/plain; charset=utf-8');
    echo "a token is needed: Authorization: Bearer ...\n";
    exit;
}
[$status, $body] = acme_call('/api/metrics', 'GET', null, 10.0, ['X-Acme-Metrics: ' . $token]);
$got = json_decode($body, true);
if ($status !== 200 || !is_array($got) || !isset($got['text']) || !is_string($got['text'])) {
    http_response_code($status === 0 ? 503 : ($status ?: 503));
    header('Content-Type: text/plain; charset=utf-8');
    echo ($status === 0 ? 'the daemon is not answering' : (string) ($got['error'] ?? 'no')) . "\n";
    exit;
}
header('Content-Type: text/plain; version=0.0.4; charset=utf-8');
echo $got['text'];
