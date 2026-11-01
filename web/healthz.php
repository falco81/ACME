<?php
/* healthz.php - what a load balancer asks: is this node able to answer?
   200 and "ok" when the daemon answers and its database opens; 503 and why
   otherwise. Nothing else is said, so it may be asked by anybody. (1.0.13) */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';
header('Content-Type: text/plain; charset=utf-8');
header('Cache-Control: no-store');
if (acme_token() === null) {
    // Said as it is (1.0.36): the daemon may well be up; it is the pages
    // that cannot reach it.
    http_response_code(503);
    echo "down: the pages cannot read the daemon's API token\n";
    exit;
}
// What is asked (1.0.47): web (the default - the pages: nginx, PHP, the
// daemon, the database) or all (that, and replication running - for
// monitoring, not for a balancer: one node cannot fix the other's). Anything
// else is web.
$check = (string) ($_GET['check'] ?? 'web');
if (!in_array($check, ['web', 'all'], true)) {
    $check = 'web';
}
$got = acme_get('/api/health' . ($check === 'all' ? '?check=all' : ''), 3.0);
if (!is_array($got) || empty($got['ok'])) {
    http_response_code(503);
    echo "down: the daemon is not answering\n";
    exit;
}
if (isset($got['database']['ok']) && !$got['database']['ok']) {
    http_response_code(503);
    echo "down: the database does not open\n";
    exit;
}
if (!empty($got['maintenance'])) {
    // Taken out by hand or for an upgrade (1.0.37): the balancer sends
    // nobody here until it is back.
    http_response_code(503);
    echo 'maintenance ' . preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($got['node'] ?? '')) . "\n";
    exit;
}
$node = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($got['node'] ?? ''));
if ($check === 'all' && isset($got['replication']) && empty($got['replication']['ok'])) {
    http_response_code(503);
    echo 'degraded: replication ' . (!empty($got['replication']['lost']) ? 'lost' : 'not running')
        . " on $node\n";
    exit;
}
echo "ok $node\n";
