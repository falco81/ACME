<?php
/* agent.php - the agents' port (1.0.116, docs/target-agent.md): an active acme-agent asks
   here for its jobs. nginx sends only its requests here, from the server of the agents'
   port alone (acme_agents.conf, written only while Settings → Target agents → active mode is
   on), with the client certificate it checked against acme's agent authority:

     /agent/v1/join          the join (its one-time code proves it - no certificate yet)
     /agent/v1/join/status   the join's state, the certificate once confirmed
     /agent/v1/poll          the jobs and their results (only with a certificate that passed)
     /agent/v1/enroll        a server joining with a company enrollment code (1.0.120: the
                             code proves it - no certificate yet; acme makes its target)

   The daemon decides everything (POST /api/agent-wire/OP): whether the certificate is one of
   an agent it knows, of a target switched on - this only relays. */
declare(strict_types=1);
require_once __DIR__ . '/acme-api.php';

function agent_say(int $code, array $out): void
{
    http_response_code($code);
    header('Content-Type: application/json');
    header('Cache-Control: no-store');
    echo json_encode($out), "\n";
    exit;
}

if ((string) ($_SERVER['ACME_AGENT_PORT'] ?? '') !== '1') {
    agent_say(404, ['ok' => false, 'said' => 'not here']);
}
$op = (string) ($_SERVER['ACME_AGENT_OP'] ?? '');
if (!in_array($op, ['join', 'status', 'poll', 'enroll'], true)) {
    agent_say(404, ['ok' => false, 'said' => 'not here']);
}
if ((string) ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    agent_say(405, ['ok' => false, 'said' => 'only POST']);
}
$most = 4 * 1024 * 1024;
$raw = (string) file_get_contents('php://input', false, null, 0, $most + 1);
if (strlen($raw) > $most) {
    agent_say(413, ['ok' => false, 'said' => 'too big']);
}
$body = json_decode($raw === '' ? '{}' : $raw, true);
if (!is_array($body)) {
    agent_say(400, ['ok' => false, 'said' => 'not JSON']);
}
$cert = rawurldecode((string) ($_SERVER['ACME_AGENT_CERT'] ?? ''));
if (strlen($cert) > 16384) {
    agent_say(400, ['ok' => false, 'said' => 'not a certificate']);
}
$verify = (string) ($_SERVER['ACME_AGENT_VERIFY'] ?? '');
[$status, $reply] = acme_call('/api/agent-wire/' . $op, 'POST', [
    'body' => (object) $body, 'cert' => $cert,
    'verify' => preg_replace('/[^A-Za-z:]/', '', $verify),
    'ip' => preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? '')),
], 85.0);
if ($status === 0) {
    agent_say(503, ['ok' => false, 'said' => 'acme does not answer just now']);
}
http_response_code($status);
header('Content-Type: application/json');
header('Cache-Control: no-store');
echo $reply;
