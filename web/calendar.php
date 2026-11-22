<?php
/* calendar.php - the expiry calendar a calendar program subscribes to (1.0.140,
   docs/expiry-calendar.md): GET /calendar.ics?t=SECRET, the secret of one person's link.
   The daemon checks the secret and answers with what that account may see now - nothing
   without it. Nothing is kept here and nothing is logged (nginx: access_log off). */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$token = (string) ($_GET['t'] ?? '');
if (!preg_match('/^[A-Za-z0-9_-]{30,100}$/', $token)) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo "no such calendar\n";
    exit;
}
[$status, $body] = acme_call('/api/calendar/feed', 'GET', null, 15.0, ['X-Acme-Calfeed: ' . $token]);
$got = json_decode($body, true);
if ($status !== 200 || !is_array($got) || !isset($got['text']) || !is_string($got['text'])) {
    http_response_code($status === 0 ? 503 : ($status === 404 ? 404 : ($status ?: 503)));
    header('Content-Type: text/plain; charset=utf-8');
    echo ($status === 0 ? 'the daemon is not answering' : 'no such calendar') . "\n";
    exit;
}
header('Content-Type: text/calendar; charset=utf-8');
header('Content-Disposition: inline; filename="acme-certificates.ics"');
echo $got['text'];
