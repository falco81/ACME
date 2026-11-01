<?php
/**
 * admin/index.php — the administration pages of acme.
 *
 * isemon's dashboard, for certificates kept, renewed and put in place by
 * themselves: the same header, the same tabs, the same settings down a rail at
 * the left edge, the same popups. It collects
 * nothing itself and decides nothing: every word comes from the acme daemon
 * over its API on localhost, and the daemon decides whether whoever is signed
 * in may have it.
 */
declare(strict_types=1);

define('ACME_COOKIE', 'acme_session');
define('ACME_COOKIE_PATH', '/admin/');
require_once dirname(__DIR__) . '/acme-page.php';
require_once dirname(__DIR__) . '/acme-api.php';
require_once dirname(__DIR__) . '/acme-art.php';
/* The certificate manager's tabs and panes (acme_certs_*), when they are there. */
if (is_file(__DIR__ . '/certs-ui.php')) {
    require_once __DIR__ . '/certs-ui.php';
}

/* nginx's question before it takes a big body (1.0.98, auth_request): is a
   full administrator signed in? Nothing else is answered here. */
if (($_SERVER['ACME_AUTH_ONLY'] ?? '') === '1') {
    $who = acme_whoami();
    /* One who must change the password first is not let send 4 GB to be refused (1.0.208). */
    http_response_code(is_array($who) && ($who['role'] ?? '') === 'fulladmin'
                       && empty($who['must_change']) ? 204 : 403);
    exit;
}

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    /* acme push (docs/acme-push-protocol.md): an acme putting its certificates on
       these pages - Settings → Certificates and TLS → Certificates from acme. No
       sign-in: the daemon checks acme's signature over the body as it came, so the
       body (as base64) and the X-Acme-Push-* headers go to it untouched, in its JSON. */
    if (preg_match('/^acme-push-(hello|pair|inventory|install)$/', $what, $push)) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $op = $push[1];
        if (($op === 'hello') === $post) {
            http_response_code(405);
            echo json_encode(['ok' => false, 'code' => 'bad_request',
                              'error' => $op === 'hello' ? 'hello is a GET' : 'a POST, signed']);
            exit;
        }
        $payload = null;
        if ($post) {
            $raw = (string) file_get_contents('php://input', false, null, 0, 1048577);
            if (strlen($raw) > 1048576) {
                http_response_code(413);
                echo json_encode(['ok' => false, 'code' => 'too_big', 'error' => 'that is more than a certificate']);
                exit;
            }
            $signed = [];
            foreach (['Version', 'Key', 'Time', 'Nonce', 'Signature'] as $h) {
                $signed[$h] = substr((string) ($_SERVER['HTTP_X_ACME_PUSH_' . strtoupper($h)] ?? ''), 0, 300);
            }
            $payload = ['body' => base64_encode($raw), 'headers' => $signed];
        }
        [$status, $body] = acme_call('/api/acme-push/' . $op, $post ? 'POST' : 'GET', $payload, 60.0);
        http_response_code($status ?: 503);
        echo $status ? $body : json_encode(['ok' => false, 'code' => 'down',
                                            'error' => 'the daemon is not answering']);
        exit;
    }
    if ($what === 'lang' && !$post) {
        acme_serve_lang();
    }
    if ($what === 'software' && !$post) {
        /* What every node runs on (1.0.99) - and of the pages, what this
           PHP itself is: php-fpm's, not the command line's. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        [$status, $body] = acme_call('/api/software', 'GET', null, 20.0);
        $data = json_decode((string) $body, true);
        if ($status !== 200 || !is_array($data)) {
            http_response_code($status ?: 503);
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
            exit;
        }
        $ext = [];
        foreach (get_loaded_extensions() as $e) {
            $v = phpversion($e);
            $ext[$e] = ($v === false || $v === PHP_VERSION) ? '' : (string) $v;
        }
        ksort($ext, SORT_NATURAL | SORT_FLAG_CASE);
        $data['pages'] = [
            'php' => PHP_VERSION, 'sapi' => PHP_SAPI, 'extensions' => $ext,
            'opcache' => function_exists('opcache_get_status') && is_array(@opcache_get_status(false))
                && !empty(@opcache_get_status(false)['opcache_enabled']),
            'server' => (string) ($_SERVER['SERVER_SOFTWARE'] ?? ''),
            'os' => PHP_OS_FAMILY,
        ];
        echo json_encode($data);
        exit;
    }
    if ($what === 'logo' && !$post) {
        acme_serve_logo();
    }
    if ($post) {
        acme_guard_post();
    }
    if ($what === 'login' && $post) {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $sent = sent_body();
        [$status, $body] = acme_call('/api/auth/login', 'POST', [
            'name'     => (string) ($sent['name'] ?? ''),
            'password' => (string) ($sent['password'] ?? ''),
        ], 30.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is acme.service running?']);
            exit;
        }
        $data = json_decode($body, true);
        if ($status === 200 && is_array($data) && !empty($data['token'])) {
            acme_set_session((string) $data['token']);
            unset($data['token']);
            echo json_encode($data);
            exit;
        }
        http_response_code($status === 200 ? 400 : $status);
        echo json_encode(is_array($data) ? $data : ['ok' => false, 'error' => 'sign-in failed']);
        exit;
    }
    if ($what === 'mfa' && $post) {
        /* The second step given (1.0.149): the daemon ends the sign-in the
           password opened and hands a new one - its cookie set here, the
           token never shown to the page. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        [$status, $body] = acme_call('/api/auth/mfa', 'POST', sent_json(), 90.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is acme.service running?']);
            exit;
        }
        $data = json_decode($body, true);
        if (is_array($data) && !empty($data['token'])) {
            if ($status === 200) {
                acme_set_session((string) $data['token']);
            }
            unset($data['token']);
            $body = json_encode($data);
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'upgrade-package' && $post) {
        /* A new version of acme (1.0.37): the .tar.gz itself is the body, as a
           database being put back is. A full administrator only, asked before
           a byte is read; the daemon checks its signature, and root checks it
           again before putting it in. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $who = acme_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin' || !empty($who['must_change'])) {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => is_array($who)
                ? 'only a full administrator may send a new version'
                : 'not signed in']);
            exit;
        }
        [$tmp, $why] = acme_take_body(64 * 1024 * 1024);
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        try {
            [$status, $body] = acme_send_file('/api/upgrade/package', $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is acme.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'db-restore' && $post) {
        /* A database somebody is putting back: the file itself is the body,
           written down a lump at a time as it arrives and going on to the
           daemon from there - never held in memory, never a multipart form. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        /* Who is sending it is asked first, before a byte of the body is read:
           the daemon would refuse it at the end anyway, but up to four
           gigabytes would have been written to disk by then on anybody's
           say-so. Only a full administrator may put a database back. */
        $who = acme_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin' || !empty($who['must_change'])) {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => is_array($who)
                ? 'only a full administrator may put a database back'
                : 'not signed in']);
            exit;
        }
        [$tmp, $why] = acme_take_body(4 * 1024 * 1024 * 1024);
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        $ask = '/api/db/restore' . (isset($_GET['check']) ? '?check=1' : '');
        try {
            [$status, $body] = acme_send_file($ask, $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' =>
                'the daemon is not answering — is acme.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'rbackup-upload' && $post) {
        /* A backup file being put back (1.0.109): as a database above - the
           file the body, written down as it comes, only a full administrator. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        $who = acme_whoami();
        if (!is_array($who) || ($who['role'] ?? '') !== 'fulladmin' || !empty($who['must_change'])) {
            http_response_code(401);
            echo json_encode(['ok' => false, 'error' => 'only a full administrator may put a backup back']);
            exit;
        }
        [$tmp, $why] = acme_take_body(4 * 1024 * 1024 * 1024);   // as nginx and the pool take (1.0.139)
        if ($tmp === null) {
            http_response_code(400);
            echo json_encode(['ok' => false, 'error' => $why]);
            exit;
        }
        try {
            [$status, $body] = acme_send_file('/api/rbackup/upload', $tmp);
        } finally {
            @unlink($tmp);
        }
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' => 'the daemon is not answering — is acme.service running?']);
            exit;
        }
        http_response_code($status);
        echo $body;
        exit;
    }
    if ($what === 'rbackup-download' && !$post) {
        /* A backup made now - or one fetched from a destination - a lump at a
           time to the browser. Only an id and a file name are passed on. */
        $id = preg_replace('/[^a-f0-9]/', '', (string) ($_GET['id'] ?? ''));
        $name = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($_GET['name'] ?? ''));
        $bits = [];
        if ($id !== '' && $name !== '') { $bits[] = 'id=' . $id; $bits[] = 'name=' . rawurlencode($name); }
        [$status, $body] = acme_pipe('/api/rbackup/download' . ($bits ? '?' . implode('&', $bits) : ''), $name, 1800.0);
        if ($status === 401) {
            header('Location: /admin/');
            exit;
        }
        if ($status !== 200) {
            http_response_code($status ?: 503);
            header('Content-Type: application/json');
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
        }
        exit;
    }
    if ($what === 'db-download' && !$post) {
        /* A copy or a dump as a file to save, from the daemon to the browser a
           lump at a time. Only a name and which folder are passed on - never a
           path: the daemon holds both folders. */
        $name = preg_replace('/[^A-Za-z0-9._-]/', '', (string) ($_GET['name'] ?? ''));
        $kind = ($_GET['kind'] ?? '') === 'dump' ? 'dump' : '';
        $ticket = preg_replace('/[^a-f0-9]/', '', (string) ($_GET['ticket'] ?? ''));
        $bits = [];
        if ($ticket !== '') { $bits[] = 'ticket=' . $ticket; }
        if ($name !== '') { $bits[] = 'name=' . rawurlencode($name); }
        if ($kind !== '') { $bits[] = 'kind=dump'; }
        $ask = '/api/db/download' . ($bits ? '?' . implode('&', $bits) : '');
        [$status, $body] = acme_pipe($ask, $name);
        if ($status === 401) {
            // Signed out meanwhile: back to the sign-in, not a page of JSON (1.0.36).
            header('Location: /admin/');
            exit;
        }
        if ($status !== 200) {
            http_response_code($status ?: 503);
            header('Content-Type: application/json');
            echo $body ?: json_encode(['ok' => false, 'error' => 'the daemon is not answering']);
        }
        exit;
    }
    if ($what === 'logout' && $post) {
        acme_call('/api/auth/logout', 'POST', [], 10.0);
        acme_clear_session();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }
    /* Reads apart from writes, so a GET can never reach a road that changes
       something, whatever is typed in the address bar. */
    $reads = [
        'status' => '/api/status',
        'directories' => '/api/directories', 'settings' => '/api/settings',
        'users' => '/api/users', 'sessions' => '/api/sessions', 'events' => '/api/events',
        'suggest' => '/api/suggest', 'mail' => '/api/mail',
        'log' => '/api/log', 'db' => '/api/db', 'whoami' => '/api/auth/whoami',
        'export' => '/api/export', 'my-settings' => '/api/auth/settings', 'ha' => '/api/ha',
        'upgrade' => '/api/upgrade', 'web' => '/api/web',
        'firewall' => '/api/firewall', 'ha-history' => '/api/ha/history',
        'art' => '/api/portal/art', 'mailq' => '/api/mailq', 'texts' => '/api/texts', 'mailq-one' => '/api/mailq/one', 'software' => '/api/software',
        'rbackup' => '/api/rbackup', 'lockouts' => '/api/lockouts', 'net' => '/api/net', 'power' => '/api/power', 'ntp' => '/api/ntp',
        'console-login' => '/api/console-login',
        'mfa' => '/api/auth/mfa',
        'sshkeys' => '/api/sshkeys', 'osup' => '/api/osup', 'alerts' => '/api/alerts', 'sshd' => '/api/sshd', 'hisec' => '/api/hisec', 'acme' => '/api/acme', 'siem' => '/api/siem', 'isemon' => '/api/isemon', 'proxy' => '/api/proxy', 'logs' => '/api/logs',
        'dbtls' => '/api/dbtls', 'metrics' => '/api/metrics', 'snmp' => '/api/snmp',
        'acme-push' => '/api/acme-push',
        'split' => '/api/split',
    ];
    $writes = [
        'directories' => '/api/directories',
        'settings' => '/api/settings', 'isemon' => '/api/isemon', 'users' => '/api/users',
        'sessions' => '/api/sessions', 'db' => '/api/db', 'import' => '/api/import',
        'password' => '/api/auth/password', 'prefs' => '/api/auth/prefs',
        'columns' => '/api/auth/columns', 'my-settings' => '/api/auth/settings',
        'ha' => '/api/ha', 'mail' => '/api/mail', 'upgrade' => '/api/upgrade', 'web' => '/api/web', 'firewall' => '/api/firewall',
        'art' => '/api/portal/art', 'mailq' => '/api/mailq', 'texts' => '/api/texts',
        'rbackup' => '/api/rbackup', 'lockouts' => '/api/lockouts', 'trial' => '/api/trial', 'net' => '/api/net', 'power' => '/api/power', 'ntp' => '/api/ntp',
        'console-login' => '/api/console-login',
        'mfa' => '/api/auth/mfa',
        'sshkeys' => '/api/sshkeys', 'osup' => '/api/osup', 'alerts' => '/api/alerts', 'sshd' => '/api/sshd', 'hisec' => '/api/hisec', 'acme' => '/api/acme', 'siem' => '/api/siem', 'proxy' => '/api/proxy', 'logs' => '/api/logs',
        'dbtls' => '/api/dbtls', 'metrics' => '/api/metrics', 'snmp' => '/api/snmp',
        'acme-push' => '/api/acme-push',
        'split' => '/api/split',
    ];
    /* The certificate manager's API (docs/architecture.md), relayed under its
       own name - certs, certs-one (or certs/one), cas-create, targets-test...
       The daemon's routes are each one method, so a GET still never reaches a
       write, and the daemon decides whether whoever is signed in may. */
    if (preg_match('#^(certs|cas|plugins|sources|validations|targets|deploys|dns|dnssets|sshkey|teams|tags)(?:[/-]([a-z_]{1,40}))?$#', $what, $road)) {
        $path = '/api/' . $road[1] . (isset($road[2]) && $road[2] !== '' ? '/' . $road[2] : '');
        if ($post) {
            acme_relay($path, 'POST', sent_json(), 120.0);
            exit;
        }
        $query = $_GET;
        unset($query['api']);
        acme_relay($path . ($query ? '?' . http_build_query($query) : ''), 'GET', null, 60.0);
        exit;
    }
    if ($post) {
        if (!isset($writes[$what])) {
            http_response_code(404);
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
            exit;
        }
        acme_relay($writes[$what], 'POST', sent_json(), 90.0);
        exit;
    }
    if (!isset($reads[$what])) {
        http_response_code(404);
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
        exit;
    }
    $query = $_GET;
    unset($query['api']);
    acme_relay($reads[$what] . ($query ? '?' . http_build_query($query) : ''), 'GET', null, 60.0);
    exit;
}

/* ---- the page ------------------------------------------------------------ */
$me      = acme_whoami();
/* Signed in with the password, the second step still to give (1.0.125): the
   sign-in page, asking for it - nothing of the pages yet. */
$mfa     = (is_array($me) && !empty($me['mfa'])) ? (string) $me['mfa'] : '';
if ($mfa !== '') { $me = null; }
$health  = acme_get('/api/health', 5.0);
$alive   = is_array($health);
$token_there = file_exists(ACME_TOKEN);
$token_ok    = acme_token() !== null;
$web_user    = function_exists('posix_getpwuid') && function_exists('posix_geteuid')
    ? (posix_getpwuid(posix_geteuid())['name'] ?? '?') : '?';
/* What the sign-in page says when something is wrong is for the operator at
   the console: which account the pages run as, where the token is, whether
   any account exists yet. From anywhere but this machine the page says only
   that the daemon is not answering - and the lines that would have named the
   rest never get a chance to. */
if (!$me && !acme_local()) {
    $token_there = false;
    if (!$token_ok || empty($health['database']['ok']) || empty($health['users'])) {
        $alive = false;
    }
    /* Reduced to what the markup tests, all of it saying "fine": anything
       that is not fine has already turned this into "not answering" above.
       (1.0.19: only the language was kept, and the page then read the
       missing database as one that will not open.) */
    $health = ['lang' => (string) ($health['lang'] ?? 'cs'), 'database' => ['ok' => true],
               'users' => 1];
}
$initial = $me ? (acme_get('/api/status', 8.0) ?: null) : null;
/* The sign-in's picture, when it is to be shown here too (1.0.71). */
$art_info = $me ? null : acme_get('/api/portal/info', 3.0);
$art_here = $me ? '' : acme_art_for(is_array($art_info) ? ($art_info['admin_art'] ?? null) : null, 'admin', 'acme');
$host    = (string) ($_SERVER['HTTP_HOST'] ?? php_uname('n'));
$site    = (string) ($initial['site'] ?? '');
$title   = $site !== '' ? $site . ' · ACME' : 'acme';
$lang    = acme_lang_pick($me, (string) ($health['lang'] ?? 'cs'));
$load    = $lang !== 'en' && acme_lang_pack($lang) !== null;
if ($me && ($_COOKIE['acme_lang'] ?? '') !== $lang) {
    setcookie('acme_lang', $lang, ['expires' => time() + 365 * 86400, 'path' => '/',
              'secure' => acme_https(), 'httponly' => false, 'samesite' => 'Strict']);
}
?>
<!doctype html>
<html lang="<?= h($lang) ?>" class="app-shell-root<?= $load ? ' i18n-wait' : '' ?>">
<head>
<?php acme_head($title, $lang, $load, $nonce, '/'); ?>
<?php if ($me && is_file(dirname(__DIR__) . '/assets/certs.css')): ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/certs.css?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/certs.css')) ?>">
<?php endif; ?>
<?php if ($me && is_file(dirname(__DIR__) . '/assets/dnssets.css')): ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/dnssets.css?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/dnssets.css')) ?>">
<?php endif; ?>
<?php if ($me && is_file(dirname(__DIR__) . '/assets/teams.css')): ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/teams.css?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/teams.css')) ?>">
<?php endif; ?>
<?php if ($me && is_file(dirname(__DIR__) . '/assets/sshkey.css')): ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/sshkey.css?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/sshkey.css')) ?>">
<?php endif; ?>
</head>
<body class="app-shell fold-words<?= $me ? ' framed' : '' ?>">
<div class="wrap">

<?php if (!$me): ?>
<div class="signin">
  <div class="signbox">
    <?= $art_here ?>
    <div class="card">
    <h1 data-no-i18n><?= h($title) ?></h1>
    <p class="lede">Certificates kept, renewed and put in place by themselves, on <span data-no-i18n><?= h($host) ?></span>. Sign in to go on.</p>
    <?php if (!$token_ok && $token_there): ?>
      <div class="offline">
        The daemon is running, but this page may not read what it wrote.<br><br>
        <span class="mono"><?= h(ACME_TOKEN) ?></span> exists and is not readable by
        <span class="mono"><?= h($web_user) ?></span>, which is what this page runs as.
        On the server:<br>
        <span class="mono">usermod -a -G acme-web <?= h($web_user) ?></span><br>
        <span class="mono">systemctl restart php-fpm nginx</span>
      </div>
    <?php elseif (!$alive): ?>
      <div class="offline">The daemon is not answering. Nobody can sign in until
        <span class="mono">acme.service</span> is running:<br>
        <span class="mono">systemctl status acme</span> ·
        <span class="mono">journalctl -u acme -n 50</span></div>
    <?php elseif (empty($health['database']['ok'])): ?>
      <div class="offline">The daemon is running, but its database will not open. On the
        server: <span class="mono">acme --check</span> · <span class="mono">journalctl -u acme -n 50</span></div>
    <?php elseif (empty($health['users'])): ?>
      <div class="offline">There is no account on this machine yet. Make one on the server:<br>
        <span class="mono">acme --add-user yourname --role fulladmin</span></div>
    <?php endif; ?>
    <div id="mfa-box" data-stage="<?= h($mfa) ?>" hidden></div>
    <form id="signin-form" autocomplete="on"<?= $mfa !== '' ? ' hidden' : '' ?>>
      <input type="text" id="in-name" name="username" placeholder="name" autocomplete="username"
             autocapitalize="none" spellcheck="false" required>
      <input type="password" id="in-pass" name="password" placeholder="password"
             autocomplete="current-password" required>
      <button class="btn primary cmd" type="submit" id="in-go"><svg
        viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
        stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
        ><path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="M14 12h7"/><path
        d="M18 9l3 3-3 3"/></svg><span>Sign in</span></button>
      <div class="said" id="in-said"></div>
    </form>
    <div style="margin-top:14px;display:flex;justify-content:space-between;align-items:center">
      <span class="muted small">acme <?= h(ACME_VERSION) ?></span>
      <span class="langpick" id="langpick"></span>
    </div>
    </div>
  </div>
</div>
</div>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/core.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>">
(function () {
  var form = $('signin-form'), said = $('in-said'), go = $('in-go');
  /* The language, chosen before signing in - as on the portal (1.0.15). */
  var host = $('langpick');
  if (host && window.ACME_LANGS && window.ACME_LANGS.length > 1) {
    window.ACME_LANGS.forEach(function (l) {
      var b = el('button', l.code === window.ACME_LANG ? 'on' : '', l.code.toUpperCase());
      b.type = 'button';
      b.setAttribute('data-no-i18n', '');
      b.title = l.name;
      b.onclick = function () {
        document.cookie = 'acme_lang=' + encodeURIComponent(l.code) + '; path=/; max-age=31536000; '
          + 'samesite=strict' + (location.protocol === 'https:' ? '; secure' : '');
        location.reload();
      };
      host.appendChild(b);
    });
  }
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    said.className = 'said';
    said.textContent = '';
    go.disabled = true;
    var words = go.querySelector('span');
    words.textContent = 'Signing in…';
    api('login', {name: $('in-name').value, password: $('in-pass').value}).then(function (d) {
      if (d && d.mfa) { form.hidden = true; mfaStep(); return; }
      said.className = 'said good';
      said.textContent = 'Welcome back.';
      location.reload();
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
      go.disabled = false;
      words.textContent = 'Sign in';
      $('in-pass').value = '';
      $('in-pass').focus();
    });
  });
  if ($('mfa-box').dataset.stage) mfaStep(); else $('in-name').focus();
}());
</script>
</body>
</html>
<?php exit; endif; ?>

<header>
  <h1 data-no-i18n><?= h($site ?: 'acme') ?> <span class="host"><?= h($host) ?></span></h1>
  <span id="state-pill" class="pill unknown"><span class="dot"></span><span>…</span></span>
  <div class="spacer"></div>
  <div class="btnrow">
    <button type="button" class="btn small mebtn" id="me-btn" data-icon="person"
            title="The account you are signed in as: what it may do, its password, the language of these pages, the columns of the tables and your settings in a file."><span class="me-name" data-no-i18n><?= h($me['name']) ?></span></button>
    <button class="btn small" id="signout" data-icon="out">Sign out</button>
  </div>
  <div class="updated" id="updated" title="Click to pause or resume the live updates">
    <b>live</b><br><span id="updated-at">…</span></div>
</header>

<div id="offline" class="offline" hidden></div>
<div id="phpsafety" class="offline" hidden></div>
<div id="problems" class="offline warnish" hidden></div>
<div id="trials" class="trials" hidden></div>

<div class="tabs" role="tablist">
  <button role="tab" aria-selected="true" data-tab="overview" data-icon="chart"
          title="The shape of things: the certificates, what runs out soonest, the nodes, the database.">Overview</button>
<?php if (function_exists('acme_certs_tab_buttons')) { acme_certs_tab_buttons(); } ?>
  <button role="tab" aria-selected="false" data-tab="events" data-icon="history"
          title="Every certificate issued, renewed or put in place, every change of a setting, every sign-in - and the daemon’s own log.">Events</button>
  <button role="tab" aria-selected="false" data-tab="settings" data-icon="gear"
          title="The certificate manager, mail and SMS, the portal, the accounts, the network, high availability, the database, monitoring and updates.">Settings</button>
</div>

<!-- ===================== Overview ===================== -->
<section class="panel" id="tab-overview">
  <!-- As in otp: the product's own tiles first (here the certificates, drawn by
       certs.js in front of isemon), then the server's, then what certs.js draws. -->
  <div class="grid top" id="ov-row1">
    <div class="card metric warn" id="card-isemon"><div class="label">isemon</div>
      <div class="value" id="m-isemon">–</div><div class="sub" id="m-isemon-sub">&nbsp;</div></div>
  </div>
  <div class="grid top" style="margin-top:14px">
    <div class="card metric ok" id="card-server"><div class="label">This server</div>
      <div class="value" id="m-server">–</div><div class="sub" id="m-server-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-cluster"><div class="label">High availability</div>
      <div class="value" id="m-cluster">–</div><div class="sub" id="m-cluster-sub">&nbsp;</div></div>
    <div class="card metric info" id="card-db"><div class="label">The database</div>
      <div class="value" id="m-db">–</div><div class="sub" id="m-db-sub">&nbsp;</div></div>
    <div class="card metric ok" id="card-maint"><div class="label">Maintenance and upgrades</div>
      <div class="value" id="m-maint">–</div><div class="sub" id="m-maint-sub">&nbsp;</div></div>
  </div>
  <div id="ov-certs" style="margin-top:14px"></div>
</section>
<?php if (function_exists('acme_certs_tab_panels')) { acme_certs_tab_panels(); } ?>

<!-- ===================== Events ===================== -->
<section class="panel" id="tab-events" hidden>
  <div class="card full" data-hold>
    <h2>What this daemon has done</h2>
    <p class="note">Every certificate issued, renewed, put in place or taken away, every change
      of a setting, every sign-in. Kept in the database, so it survives a restart.</p>
    <div class="btnrow filters">
      <input type="search" id="ev-q" placeholder="anything in an event…" style="flex:1;min-width:200px">
      <select id="ev-kind"><option value="">everything</option></select>
      <span id="ev-time" title="How far back the events go."></span>
    </div>
    <div id="ev-table" class="scroll rowsonly"></div>
    <div class="pager" id="ev-pager"></div>
  </div>
  <div class="card full fulladmin-only aside">
    <h2>The daemon's own log</h2>
    <p class="note">The tail of <span class="mono">/var/log/acme/acme.log</span>. Switch on
      <i>debug</i> in Settings → About to have it say every step of every request.</p>
    <div class="btnrow"><button class="btn cmd" id="log-read" data-icon="log">Read it</button>
      <select id="log-lines"><option>200</option><option selected>600</option><option>2000</option></select></div>
    <pre class="lines" id="log-out" style="margin-top:12px" hidden></pre>
  </div>
</section>

<!-- ===================== Settings ===================== -->
<section class="panel" id="tab-settings" hidden>
<div class="ctl-layout">
  <nav class="ctl-nav" id="ctl-nav" aria-label="Settings sections">
    <div class="ctl-navtop">
      <button type="button" class="ctl-pin" id="ctl-pin" aria-pressed="false" aria-label="Keep this menu open"></button>
      <div class="ctl-find-wrap">
        <input type="search" id="ctl-find" placeholder="Find a setting…" autocomplete="off" aria-label="Find a setting">
        <div class="ctl-found" id="ctl-found" hidden></div>
      </div>
    </div>
<?php if (function_exists('acme_certs_settings_nav')) { acme_certs_settings_nav(); } ?>
    <div class="ctl-group">Messages and the portal</div>
    <button type="button" data-pane="codes" data-icon="phone" title="The SMS gateway, and the codes sent by e-mail or SMS for the administrators' second step and the notifications: how long they last, how many.">Codes by e-mail and SMS</button>
    <button type="button" data-pane="texts" data-icon="edit" title="Every word people get from this server - the mails and the SMS - in Czech and in English, edited as they will look.">Message texts</button>
    <button type="button" data-pane="portal" data-icon="people" title="The certificate portal: who may sign in to it, what they see, the picture on its sign-in.">The enrolment pages</button>
    <div class="ctl-group">Mail</div>
    <button type="button" data-pane="mail" data-icon="mail" title="How the mails of this server - alerts, reports, codes, notices of certificates - reach people: a mail server, or straight to theirs.">Mail</button>
    <button type="button" data-pane="mailq" data-icon="list" title="Every mail sent - an alert, a report, a code to sign in with - and what became of it: sent, waiting for another try (greylisting, a server away), failed. Sent again or taken away by hand.">Outgoing mail <span class="nav-badge" id="mq-badge" hidden></span></button>
    <div class="ctl-group">Access</div>
    <button type="button" data-pane="people" data-icon="person" title="Who may open these pages, what each of them may do, and who is signed in right now.">Accounts</button>
    <button type="button" class="fulladmin-only" data-pane="hisec" data-icon="shield" title="Every way of doing something less safely switched off - and what stands against it now.">High security</button>
    <button type="button" data-pane="web" data-icon="lock" title="The certificates of the nodes and of the cluster's VIP address, and how TLS is spoken.">Certificates and TLS</button>
    <button type="button" class="fulladmin-only" data-pane="acme" data-icon="lock" title="The certificates ordered from Let's Encrypt (or another ACME CA) and renewed by themselves.">Automatic certificates</button>
    <button type="button" data-pane="fw" data-icon="wall" title="Who may reach the portal, the administration and the health check; and the machine's firewall (iptables, IPv4 and IPv6) - what acme's functions need opens by itself.">Firewall and access</button>
    <button type="button" class="fulladmin-only" data-pane="sshd" data-icon="shield" title="How the SSH server lets people in - root, passwords, the port - and the notice shown before and after signing in.">SSH server and notices</button>
    <button type="button" class="fulladmin-only" data-pane="sshkeys" data-icon="key" title="The keys that may sign in to each node as root over SSH: made here, added or taken away.">SSH keys of root</button>
    <div class="ctl-group">Server</div>
    <button type="button" class="fulladmin-only" data-pane="network" data-icon="net" title="Each node's address, gateway, DNS servers, host name and IPv6 - put in by the node itself, a cluster kept whole.">Network</button>
    <button type="button" class="fulladmin-only" data-pane="proxy" data-icon="globe" title="An HTTP proxy, for what you switch on: the new versions, the system updates, ACME, the SMS gateway.">Proxy</button>
    <button type="button" data-pane="dnssets" data-icon="globe" title="Named sets of DNS servers - the system's, public resolvers, your own - and which of them each function of acme asks: the validation checks, the public view, the CAs and APIs, the targets, the appliance's own ACME, mail.">DNS</button>
    <button type="button" class="fulladmin-only" data-pane="time" data-icon="clock" title="The clock of each node: chrony, its time servers, how far off it is - certificates' dates and the codes of the second step are worked out from it.">Time</button>
    <button type="button" data-pane="ha" data-icon="ethernet" title="Two servers, both answering: the nodes, and the wizard that makes the second one.">High availability</button>
    <button type="button" class="fulladmin-only" data-pane="power" data-icon="power" title="Restart or switch off this node, the other, or both - the VIP address moved out of the way first.">Restart and power off</button>
    <button type="button" class="fulladmin-only" data-pane="logs" data-icon="chart" title="Each node's disks, and how much the system journal and acme's own logs may take.">Disks and logs</button>
    <div class="ctl-group">Data</div>
    <button type="button" data-pane="db" data-icon="db" title="Which database everything lives in, how big it is, copies of it, and how long things are kept.">The database</button>
    <button type="button" data-pane="backup" data-icon="archive" title="Backups of everything to another machine - FTP, FTPS, SFTP, SCP, SMB or a folder - locked with a password, on a schedule, and putting one back.">Backups</button>
    <button type="button" data-pane="carry" data-icon="download" title="Everything that makes this installation what it is, as one file to carry to another machine.">Export and import</button>
    <div class="ctl-group">Monitoring and updates</div>
    <button type="button" class="fulladmin-only" data-pane="alerts" data-icon="bell" title="A mail when something is wrong, and a report of the week by mail.">Alerts and reports</button>
    <button type="button" class="fulladmin-only" data-pane="monitor" data-icon="pulse" title="Prometheus asks each node for its metrics.">Monitoring</button>
    <button type="button" data-pane="isemon" data-icon="pulse" title="Sending the events of this server to isemon, in the shape isemon already reads.">isemon</button>
    <button type="button" class="fulladmin-only" data-pane="siem" data-icon="log" title="Every event and every sign-in to a syslog server or a SIEM - UDP, TCP or TLS; JSON, CEF or RFC 5424.">Syslog and SIEM</button>
    <button type="button" class="fulladmin-only" data-pane="osup" data-icon="download" title="The operating system's packages updated, one node at a time, the VIP address moved out of the way first; a restart offered when one is needed.">System updates</button>
    <button type="button" class="fulladmin-only" data-pane="upgrade" data-icon="up" title="A new version, put in from here; nodes in and out of service.">Upgrades and maintenance</button>
    <button type="button" data-pane="about" data-icon="info" title="Version, what is running, the language, the debug log.">About</button>
  </nav>

  <div class="ctl-main">
  <div class="card full" id="readonly-note" hidden>
    <h2>You may look, but not change</h2>
    <p class="note" style="margin:0">This account may not change the settings. A full administrator can change that under <i>Accounts</i>.</p>
  </div>

<?php if (function_exists('acme_certs_settings_panes')) { acme_certs_settings_panes(); } ?>

  <div class="ctl-pane" id="pane-portal" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The enrolment pages</h2>
      <p class="ctl-lede">The certificate portal: <span class="mono" id="portal-url">/</span>
        on this server, where people sign in with their directory password - who may, what they
        see there, and the picture above its sign-in.</p></div>
    <template id="art-gallery"><?php foreach (ACME_ARTS as $a): ?><div data-art="<?= h($a) ?>" data-words="<?= h(ACME_ART_WORDS[$a]) ?>"><?= acme_art_svg($a) ?></div><?php endforeach; ?></template>
    <div class="card full" id="art-card">
      <h2>The picture on the sign-in</h2>
      <div class="seg" id="art-slot" style="margin:4px 0 10px">
        <button type="button" data-slot="portal">The enrolment pages</button>
        <button type="button" data-slot="admin">The administration</button>
      </div>
      <p class="note" id="art-note-portal">Shown above the sign-in of the portal.</p>
      <p class="note" id="art-note-admin" hidden>Shown above the sign-in of these administration pages.</p>
      <p class="note small muted">Pick one of these, or a picture of your own (a logo: PNG, JPEG,
        GIF, WebP or SVG, at most 512 KB) - each sign-in its own. It is kept in the database: both
        nodes of a cluster show the same one, and it is in every backup and in the exported
        configuration. A picture of your own stays kept when you pick another one.</p>
      <div class="art-grid" id="art-grid"></div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd small fulladmin-only" id="art-upload" data-icon="upload">Upload a picture of your own</button>
        <button class="btn cmd small fulladmin-only" id="art-reset" data-icon="undo">Back to the default</button>
        <button class="btn cmd small fulladmin-only" id="art-forget" data-icon="trash" hidden>Take my own picture away</button>
      </div>
      <input type="file" id="art-file" accept="image/png,image/jpeg,image/gif,image/webp,image/svg+xml,.svg" hidden>
      <p class="note small" id="art-said"></p>
    </div>
    <div class="card full"><div id="sect-portal"></div></div>
  </div>

  <div class="ctl-pane" id="pane-alerts" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Alerts and reports</h2>
      <p class="ctl-lede">A mail when something is wrong - a node or the replication, a backup, a certificate,
        a disk, the clock, the directory, the SMS gateway - and again when it is over; and a report of the
        week (or the day, or the month) with the sign-ins, who was refused and why, and everything else.
        One node of a cluster looks at both and sends them. Both are off until switched on below.</p></div>
    <div id="al-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-alerts"></div></div>
    <div id="al-log"></div>
  </div>
  <div class="ctl-pane" id="pane-hisec" hidden>
    <div class="ctl-head"><h2 class="ctl-title">High security</h2>
      <p class="ctl-lede">Every way of doing something less safely switched off, on every node: plain LDAP,
        unencrypted mail, syslog and backups, certificates not checked, weak TLS, SSH with passwords, the
        administration open to everybody, exports not locked. It is switched on only once nothing below stands
        against it; while it is on, all of that is refused wherever it is changed and greyed out on the pages.</p></div>
    <div id="hs-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-hisec"></div></div>
  </div>
  <div class="ctl-pane" id="pane-acme" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Automatic certificates</h2>
      <p class="ctl-lede">The certificate of the VIP address - and, where asked, each node's own - ordered from Let's
        Encrypt or another ACME CA and renewed by itself well before it runs out. The CA checks the name by asking
        it on port 80 (HTTP-01), or by a record in DNS (DNS-01) for servers it cannot see from the internet. In a
        cluster the answer is kept in the database, so whichever node has the VIP address gives it.</p></div>
    <div id="ac-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-acme"></div></div>
  </div>
  <div class="ctl-pane" id="pane-siem" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Syslog and SIEM</h2>
      <p class="ctl-lede">Every event and every sign-in - who, from where, let in or refused and why - to a
        syslog server or a SIEM (Graylog, Splunk, Elastic, Wazuh, QRadar, Sentinel), as RFC 5424 syslog over
        UDP, TCP or TLS. Each node sends its own, as it happens, from a thread of its own: a sign-in never
        waits for it. Off until switched on.</p></div>
    <div id="si-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-siem"></div></div>
  </div>
  <div class="ctl-pane" id="pane-monitor" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Monitoring</h2>
      <p class="ctl-lede">Prometheus asks each node for its metrics at <code>https://NODE/metrics</code>:
        the certificates and the jobs, the database, the cluster and its replication, the mail,
        isemon and syslog, the alerts open now. And SNMPv3: each node answers it itself, and sends traps when
        something is wrong.</p></div>
    <div class="card full"><h2>Settings</h2><div id="sect-monitor"></div></div>
    <div id="snmp-host"></div>
    <div id="mon-host"></div>
  </div>
  <div class="ctl-pane" id="pane-proxy" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Proxy</h2>
      <p class="ctl-lede">Where the servers may reach the web only through an HTTP proxy - on every node. Off
        by default, and switched on it is used only for what is switched on below: the new versions of acme, the
        system updates, ACME and its DNS APIs, the SMS gateway; all of them off, nowhere. Mail, Active
        Directory, the database, syslog, isemon, the backups, the other node and the VIP address's check never go
        through it.</p></div>
    <div class="card full"><h2>Settings</h2><div id="sect-proxy"></div></div>
    <div id="px-host"></div>
  </div>
  <div class="ctl-pane" id="pane-dnssets" hidden>
    <div class="ctl-head"><h2 class="ctl-title">DNS</h2>
      <p class="ctl-lede">Which DNS servers acme asks, for each thing it looks up: named sets of servers - the
        system's own (/etc/resolv.conf), public resolvers, the resolvers of your company - and, for each function,
        the set it asks. Not acme's own DNS server (Settings → DNS server), which answers others.</p></div>
    <div id="dnss-host"></div>
  </div>
  <div class="ctl-pane" id="pane-logs" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Disks and logs</h2>
      <p class="ctl-lede">How full each node's disks are, and how much the system journal and acme's own logs
        may take - put in on every node by the node itself, again whenever it is changed here.</p></div>
    <div id="lg-host"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-logs"></div></div>
  </div>
  <div class="ctl-pane" id="pane-isemon" hidden>
    <div class="ctl-head"><h2 class="ctl-title">isemon</h2>
      <p class="ctl-lede">The events of this server - certificates issued, renewed, put in place
        or failing, sign-ins to these pages - go to isemon as syslog lines, so isemon watches this
        server with what it already has.</p></div>
    <div id="isemon-state"></div>
    <div class="card full fulladmin-only" id="isemon-tls-card" hidden>
      <h2>Encrypted sending (TLS)</h2>
      <p class="note">The lines to isemon over TLS on 6514/tcp, isemon's certificate checked - from
        every node. Where isemon has no certificate, acme's own authority makes one for it, given
        away once in a locked file with the rsyslog configuration that takes it; with mutual TLS
        each node shows isemon a certificate of its own, so isemon takes lines from acme's nodes
        only.</p>
      <div id="isemon-tls"></div>
    </div>
    <div class="card full"><h2>Settings</h2><div id="sect-isemon"></div></div>
    <div class="card full" id="isemon-guide"></div>
  </div>

  <div class="ctl-pane" id="pane-people" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Accounts</h2>
      <p class="ctl-lede">Who may open these pages. <b>full admin</b> may change everything;
        <b>cert admin</b> may look at everything and add, import, renew, deploy and export
        certificates (never a private key); <b>read only</b> may look and change nothing.</p></div>
    <div class="card full">
      <h2>Accounts <span class="right"><button class="btn cmd small primary admin-only" id="us-add" data-icon="add">Make an account</button></span></h2>
      <div id="us-table"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Signed in now</h2><div id="se-table"></div></div>
    <div class="card full fulladmin-only" id="lo-card"><h2>Locked out <span class="right" id="lo-tools"></span></h2>
      <p class="note">Addresses and names with wrong attempts still counted, and codes sent to a person for
        the second step - at the limit they are locked out until the time runs out. Clear one, or all of them,
        and they may try again at once.</p>
      <div id="lo-table"></div></div>
    <div class="card full" id="cols-card">
      <h2>Columns of the tables <span class="right" id="cols-count"></span></h2>
      <p class="note">Every table on these pages can be laid out the way you read it. Press
        your name at the top right and switch on <b>Edit the columns</b>; then drag the edge of
        a column's heading to make it wider or narrower, and drag the heading itself to move
        the column. The right button on a heading hides a column, brings a hidden one back or
        adds an empty one for room. Twice on an edge puts that table's widths back. Each change
        is kept with your account the moment you let go, not in this browser, and comes back
        wherever you sign in; nobody else's tables change. The switch is for this sign-in
        only: signing out, the sign-in running out or the service restarting turn it off
        again, and the columns stay as you left them.</p>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd" id="cols-edit-go" data-icon="edit"
                title="The same switch as under your name: on for this sign-in only.">Edit the columns</button>
        <button class="btn cmd" id="cols-reset" data-icon="undo"
                title="Every table back as it comes: the widths and the order of the columns you set, on every page. Nobody else's are touched.">Put my columns back as they come</button>
        <button class="btn cmd" id="cols-export" data-icon="download"
                title="How you have set these pages up for yourself, saved as a JSON file.">Export my settings</button>
        <button class="btn cmd" id="cols-import" data-icon="upload"
                title="Read a file saved by Export my settings - here or on another machine running acme.">Import settings…</button>
      </div>
    </div>
    <div class="card full" id="ad-card">
      <h2>The directories administrators sign in against <span class="right"><button class="btn cmd small primary admin-only" id="ad-add" data-icon="add">Add a directory</button></span></h2>
      <p class="note">The Active Directory servers an administrator's name and password are checked
        against, and the groups below are looked up in - chosen in <i>Sign administrators in
        against the directory</i>. Read only: nothing is ever written to a directory, and the
        reading account needs no right beyond reading.</p>
      <div id="ad-table"></div>
    </div>
    <div class="card full" id="ca-card" hidden>
      <h2>The certificate authority <span class="right muted small" id="ca-when"></span></h2>
      <p class="note">Needed only when the directory is reached over TLS (LDAPS or StartTLS) and the domain controllers' certificates were signed by your own authority. Several can be kept for one directory - a chain for each domain or authority its controllers come from: paste one (or a whole chain), or read it from the .crt / .pem / .cer file, and press Save the changes below. Each is listed and can be taken out by itself.</p>
      <div id="ca-pick"></div>
      <div id="ca-state"></div>
      <textarea id="ca-pem" rows="6" class="mono admin-only" style="width:100%;margin-top:10px"
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"></textarea>
      <div class="btnrow admin-only" style="margin-top:10px">
        <button class="btn cmd primary" id="ca-save" data-icon="save"
                title="Read the certificate and keep it. It is checked for being a certificate at all before it is stored, and what it is gets shown above.">Add it</button>
        <button class="btn cmd" id="ca-file" data-icon="upload"
                title="Pick a .crt or .pem file instead of pasting it.">Read a file…</button>
        <button class="btn cmd danger" id="ca-drop" data-icon="trash"
                title="Take every certificate kept for this directory away. The domain controllers' certificates then have to be signed by one this machine already trusts.">Take them all away</button>
        <input type="file" id="ca-input" accept=".pem,.crt,.cer,.txt" hidden>
      </div>
    </div>
    <div class="card full"><div id="sect-people"></div></div>
    <div class="card full">
      <h2>The groups, and what each one may do</h2>
      <p class="note">Choose the directory in Sign administrators in against the directory above, then press Find the groups and pick them out of the directory rather than typing a distinguished name by hand — that is how a role ends up pointing at a group that does not exist, and nobody finds out until the first person cannot sign in.</p>
      <div class="btnrow admin-only" style="align-items:center">
        <input type="search" id="ag-like" style="min-width:340px;max-width:420px" placeholder="part of a group's name (empty: all)"
               autocomplete="off">
        <button class="btn cmd primary" id="ag-find" data-icon="search"
                title="Ask the directory what groups there are. Nothing is changed; it only reads.">Find the groups</button>
        <button class="btn cmd" id="ag-try" data-icon="person"
                title="Try one person's sign-in from here, so you find out it works before you sign out.">Try a sign-in…</button>
      </div>
      <div id="ag-groups" style="margin-top:14px"></div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-db" hidden>
    <div class="ctl-head"><h2 class="ctl-title">The database</h2>
      <p class="ctl-lede">One database holds everything: the certificates and their keys, the
        authorities, the targets, the jobs, the events, the settings and the accounts. It is a file
        on this machine unless you say otherwise. The private keys and the secrets are sealed with
        a key kept beside it, in the state folder - and every copy and every dump is kept with that
        key beside it.</p></div>
    <div class="card full"><div id="sect-db"></div></div>

    <div class="card full" id="db-tls-card" hidden>
      <h2>Encryption to the database server</h2>
      <p class="note">This daemon’s own connection to its database - on every node, moved over
        on the live database without stopping anything: tried apart first, then switched, and
        put back at once if the first statement on the new one does not go.</p>
      <div id="db-tls"></div>
    </div>

    <div class="card full" id="db-dump-card">
      <h2>The dumps it keeps <span class="right" id="db-dump-now"></span></h2>
      <p class="note">Every night at the time above, the database in use is dumped
        <b>by its own engine's own program</b> — <code>pg_dump</code> on PostgreSQL,
        <code>mariadb-dump</code> on MariaDB, and on the file SQLite's own backup, which is
        the file. It is a fraction of the size of the database, and it is the format the
        server's own tools read, so it can be put back by somebody who has never heard of
        this program.</p>
      <p class="note">A dump goes back into <b>the engine it came off</b>. What goes back
        into any of the three is a copy, which the card below makes — that is what carries an
        installation from the file to a server and back.</p>
      <div id="db-dump-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="db-dump-make" data-icon="save"
                title="Dump the database now, with the engine's own program, rather than waiting for tonight. It is kept with the others and counts as one of them.">Make one now</button>
        <button class="btn cmd" id="db-dump-get" data-icon="down"
                title="Dump the database now and save it to the machine you are sitting at. Nothing is kept here.">Download one</button>
      </div>
      <div id="db-dumps" style="margin-top:18px"></div>
      <div class="admin-only" id="db-dump-upload" style="margin-top:18px">
        <h4>Put a dump back</h4>
        <p class="note">A dump from somewhere else — one downloaded from here, or a file
          copied off the dumps folder. It replaces everything: every certificate, every job,
          every setting and every account. Nothing happens until it has been read, checked and
          shown to you.</p>
        <div class="drop" id="dump-drop">
          <input type="file" id="dump-file" accept=".pgc,.gz,.sql,.db,application/octet-stream" hidden>
          <span id="dump-drop-says">Drop a dump here, or press to choose one</span>
        </div>
        <div id="dump-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="dump-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full" id="db-engine-card">
      <h2>Which one it is <span class="right" id="db-engine-now"></span></h2>
      <p class="note">Where everything is kept: a file on this machine (SQLite), or a MariaDB or
        a PostgreSQL server. Its address is the one setting kept in the config file rather
        than in the database - a database cannot hold the address of itself.</p>
      <p class="note">Moving to another one is a wizard: it asks where to and how to reach it,
        checks it, says what will happen, and then does all of it - a copy made first, every
        row copied, counted and its sealed secrets opened there, the config file switched and
        the service started again on it. The database it came from is left exactly as it was:
        it is the way back.</p>
      <div id="db-engine-says"></div>
      <div id="db-move-guard"></div>
      <div id="db-move-last"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd primary" id="db-move-open" data-icon="db"
                title="Step by step: where to, how to reach it, the checks, what will happen - then everything is carried across and acme starts again on it. Nothing is changed until the last step.">Move to another database…</button>
      </div>
    </div>

    <div class="card full">
      <h2>The disk it is on</h2>
      <p class="note">How much room there is where this database's files live, how fast it is
        growing, and how long one will hold the other. Measured, not guessed: the size is
        noted once a day and what is shown is the slope of the last fortnight. On a database
        server the database is not on this machine at all — what is here then is the copies
        and the dumps, and the line below says so.</p>
      <div id="db-disk"></div>
    </div>

    <div class="card full" id="db-tune-card">
      <h2>The database server’s own settings</h2>
      <p class="note">A database server is installed with settings for a machine of any size,
        which is to say for a small one: PostgreSQL keeps 128 MB of the database in memory, and
        MariaDB likewise, on a machine of 32 GB. This reads what the machine the server runs on
        has — its memory, its processors, its disk — works the settings out for it, shows them
        beside what is there now, and puts them in when you say so.</p>
      <p class="note">Changing them takes an account that may: this program’s own where it has
        that right, otherwise an administrator on that server, asked for in the popup, used for
        that one request and stored nowhere — not in the settings, not in the database, not in
        any log.</p>
      <div id="db-tune-says"></div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd primary" id="db-tune" data-icon="gear"
                title="Read what the machine the database server runs on has, work its settings out for it and show them beside what is there now. Nothing is changed until you say so.">Tune it for this machine…</button>
        <button class="btn cmd" id="db-tune-restart" data-icon="power" hidden
                title="Restart PostgreSQL for the settings that take effect only at its start.">Restart the server…</button>
        <button class="btn cmd" id="db-tune-undo" data-icon="undo" hidden
                title="Put every setting this page changed back to what it was before.">Put back as it was…</button>
      </div>
    </div>

    <div class="card full">
      <h2>What is in it <span class="right" id="db-size"></span></h2>
      <p class="note">A copy is consistent even while the daemon is writing to it, and it is
        written as a portable file whatever this is running on — so a copy made on MariaDB or
        PostgreSQL goes back into either of those, or into the file on this machine.</p>
      <p class="btnhelp">These are <b>every row in each table</b>, which is not the number on
        the tabs above: those count what the page they belong to is showing.</p>
      <div id="db-counts"></div>
      <div class="going wide" id="db-going" hidden>
        <div class="bar"><span id="db-going-fill"></span></div>
        <div class="says" id="db-going-says"></div>
      </div>
      <div class="btnrow" style="margin-top:12px">
        <button class="btn cmd admin-only" id="db-backup" data-icon="save"
                title="Copy the database as it is into the backups folder on this machine, now, rather than waiting for tonight.">Make a copy now</button>
        <button class="btn cmd admin-only" id="db-download" data-icon="down"
                title="Make a copy now and save it to the machine you are sitting at, with the key that opens the sealed keys inside it. Nothing is kept here.">Download it</button>
        <button class="btn cmd admin-only" id="db-check" data-icon="check"
                title="Ask the database to read itself through and say whether anything in it is broken - SQLite's integrity check, MariaDB's CHECK TABLE, and on PostgreSQL every table read through. It only reads; on a large one it takes a while.">Check it</button>
        <button class="btn cmd admin-only" id="db-tidy" data-icon="broom"
                title="Throws away exactly what the &quot;keep for&quot; numbers above already say is too old — the jobs and the events, each by its own number of days. It happens by itself every hour; this is the same thing, now. Lowering one of those numbers deletes nothing by itself: this is what does it.">Apply what is kept, now</button>
        <button class="btn cmd danger admin-only" id="db-prune" data-icon="forget"
                title="Forgets the records of what happened older than an age you choose here, whatever the &quot;keep for&quot; numbers say. Only records: the certificates, the accounts and the settings are not touched.">Forget records older than…</button>
        <button class="btn cmd admin-only" id="db-optimize" data-icon="db"
                title="Gives the space back to the DISK. Deleting rows frees room inside the database and the engine reuses it; nothing hands it back to the operating system until the whole thing is rebuilt. All three do that the same way — SQLite's VACUUM, MariaDB's OPTIMIZE TABLE, PostgreSQL's VACUUM FULL — and all three hold the table shut while they do it and need room for a second copy of the biggest one. Worth doing after throwing a lot away, and not otherwise.">Give the disk back</button>
      </div>
      <div id="db-backups" style="margin-top:18px"></div>
      <div class="admin-only" id="db-upload" style="margin-top:18px">
        <h4>Put a copy back</h4>
        <p class="note">A database from somewhere else — one downloaded from here, or a file
          copied off the backups folder. It replaces everything: every certificate, every job,
          every setting and every account. Nothing happens until it has been read, checked
          and shown to you.</p>
        <div class="drop" id="db-drop">
          <input type="file" id="db-file" accept=".gz,.db,.sqlite,.sqlite3,application/octet-stream" hidden>
          <span id="db-drop-says">Drop a database file here, or press to choose one</span>
        </div>
        <div id="db-upload-what" hidden></div>
        <div class="btnrow" style="margin-top:10px">
          <button class="btn cmd danger" id="db-restore" data-icon="undo" disabled>Restore from this file</button>
        </div>
      </div>
    </div>

    <div class="card full">
      <h2>Erase the collected data <span class="right" id="erase-size"></span></h2>
      <p class="note">What is recorded of what happened can be thrown away without anybody
        losing anything they need: no certificate is lost and nothing stops working. Choose
        what goes; nothing is erased that you have not ticked.</p>
      <p class="note"><b>The certificates, the authorities, the targets, the accounts, the
        directories and every setting are never touched by this.</b> They are not options you could tick by
        mistake: they are not in the list at all.</p>
      <div id="erase-list" class="erase-list"></div>
      <div class="btnrow admin-only" style="margin-top:14px;align-items:center">
        <button class="btn cmd danger" id="erase-go" data-icon="forget"
                title="Erase everything ticked above. It cannot be undone — but a copy of the database is made just before it, and it can be restored.">Erase what is ticked…</button>
        <label class="check small" id="erase-tidy-wrap">
          <input type="checkbox" id="erase-tidy" checked
                 title="Rebuild the database afterwards so the space actually goes back to the disk. None of the three give room back by themselves when rows are deleted — it is reused inside instead.">
          <span>rebuild it afterwards, to give the disk back</span>
        </label>
      </div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-codes" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Codes by e-mail and SMS</h2>
      <p class="ctl-lede">The codes an administrator gets as the second step of signing in to
        these pages (Accounts), and the notifications and alerts sent as SMS. E-mail goes the way
        set under Mail; SMS through a gateway or a modem set up here.</p></div>
    <div class="card full"><div id="sect-codes"></div></div>
    <div class="card full">
      <h2>Try an SMS <span class="right muted small" id="sms-said"></span></h2>
      <p class="note">Sends a short message with a code that opens nothing, the way a sign-in code
        would go, and shows what the gateway answered. Save the changes first.</p>
      <div class="btnrow admin-only filters">
        <input type="tel" id="sms-to" placeholder="+420 603 123 456" style="flex:1;min-width:240px">
        <button class="btn cmd" id="sms-try" data-icon="phone">Send a test SMS</button>
      </div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-mail" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Mail</h2>
      <p class="ctl-lede">The alerts, the reports, the codes of the second step and the notices
        about certificates. The mail leaves through your mail server (SMTP), or straight to the
        server of the recipient's domain with no relay at all.</p></div>
    <div class="card full"><div id="sect-mail"></div></div>
    <div class="card full">
      <h2>Try it <span class="right muted small" id="mail-said"></span></h2>
      <p class="note">Sends a short message - or a sample of a sign-in code - the way this server's
        mail goes, and shows every step: the server reached, TLS, signing in, the message handed
        over and what the server said. Save the changes first.</p>
      <div class="btnrow admin-only filters">
        <input type="email" id="mail-to" placeholder="somebody@example.cz" style="flex:1;min-width:240px">
        <select id="mail-test-kind"><option value="short">a short message</option><option value="code">a sample sign-in code (e-mail codes)</option></select>
        <select id="mail-test-lang"><option value="cs">Čeština</option><option value="en">English</option></select>
        <select id="mail-test-via" title="With mail sent straight to the recipient's server: this once, every step shown here - or through the outgoing mail, as codes go: tried now, and tried again by itself while the other side does not take it yet (greylisting)." hidden><option value="queue">through the outgoing mail</option><option value="straight">straight, this once (to see every step)</option></select>
        <button class="btn cmd primary" id="mail-test" data-icon="mail">Send a test</button>
      </div>
      <div id="mail-steps"></div>
    </div>
    <div class="card full">
      <h2>The certificate authority <span class="right muted small" id="mca-when"></span></h2>
      <p class="note">Needed only when the mail server's certificate was signed by an authority of your own that this machine does not already trust. Paste one (or a whole chain), or read it from the .crt / .pem / .cer file, and press Save the changes below. Each is listed and can be taken out by itself.</p>
      <div id="mca-state"></div>
      <textarea id="mca-pem" rows="5" class="mono admin-only" style="width:100%;margin-top:10px"
                placeholder="-----BEGIN CERTIFICATE-----&#10;MIID...&#10;-----END CERTIFICATE-----"></textarea>
      <div class="btnrow admin-only" style="margin-top:10px">
        <button class="btn cmd primary" id="mca-save" data-icon="save">Add it</button>
        <button class="btn cmd" id="mca-file" data-icon="upload">Read a file…</button>
        <button class="btn cmd danger" id="mca-drop" data-icon="trash">Take them all away</button>
        <input type="file" id="mca-input" accept=".pem,.crt,.cer,.txt" hidden>
      </div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-network" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Network</h2>
      <p class="ctl-lede">Each node's address, gateway, DNS servers, host name and - switched on - IPv6.
        A change is put in by the node itself: in a cluster the other node is told the new address
        first, the VIP address moves away, the network is set and the node restarts; back up, it
        checks its address, replication and the link between the databases, and comes back into service.</p></div>
    <div id="net-host"></div>
    <div class="card full fulladmin-only"><h2>Taken back unless kept</h2><div id="sect-network"></div></div>
  </div>
  <div class="ctl-pane" id="pane-time" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Time</h2>
      <p class="ctl-lede">A certificate's dates, a renewal's time and the codes of the second step
        are worked out from the clock: a node whose clock is off asks for certificates at the wrong
        time and refuses codes that are right. Each node keeps its clock with chrony; here
        is how far off each one is, which servers it follows, and the time servers set for the whole cluster.</p></div>
    <div id="ntp-host"></div>
  </div>
  <div class="ctl-pane" id="pane-power" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Restart and power off</h2>
      <p class="ctl-lede">This node, the other or both, restarted or switched off from here. In a cluster the
        VIP address moves to the other node first; restarted one after the other, the service never stops.
        The page follows each node down and up again.</p></div>
    <div id="pw-host"></div>
    <div class="card full fulladmin-only"><h2>On a schedule</h2><div id="sect-power"></div></div>
  </div>
  <div class="ctl-pane" id="pane-osup" hidden>
    <div class="ctl-head"><h2 class="ctl-title">System updates</h2>
      <p class="ctl-lede">The operating system's packages, updated by dnf (or apt) on each node. In a cluster one
        node at a time: each is out of service while it is updated - the VIP address moves to the other,
        which answers meanwhile - and back in service before the next one starts. A restart an update
        needs is offered when it is done, or made by itself, one node after the other.</p></div>
    <div id="ou-host"></div>
    <div class="card full fulladmin-only"><h2>On a schedule</h2><div id="sect-osup"></div></div>
  </div>
  <div class="ctl-pane" id="pane-sshd" hidden>
    <div class="ctl-head"><h2 class="ctl-title">SSH server and notices</h2>
      <p class="ctl-lede">How each node's SSH server lets people in - root with a key or a password, the port,
        who may sign in - and the notice shown before signing in over SSH, at the console and after signing in.
        Put in by each node's root helper as a file of acme's own beside the system's, checked by sshd before it
        is used, and on trial: unless it is kept in time, each node puts back what it had by itself.</p></div>
    <div id="sd-host"></div>
  </div>
  <div class="ctl-pane" id="pane-sshkeys" hidden>
    <div class="ctl-head"><h2 class="ctl-title">SSH keys of root</h2>
      <p class="ctl-lede">The keys that may sign in to each node as root over SSH - the lines of
        /root/.ssh/authorized_keys, read from every node. A key made here is shown once, to be kept by you, and
        kept nowhere on the server; one of your own is put on by its public half - on every node or on one.
        Every change is written into Events.</p></div>
    <div id="sk-host"></div>
  </div>
  <div class="ctl-pane" id="pane-backup" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Backups</h2>
      <p class="ctl-lede">A backup is everything: the whole database (the certificates and their
        keys, the authorities, the targets, the jobs, the accounts, every setting, the VIP address,
        the firewall, the texts, the logs), the key that opens the sealed keys and this machine's config.json - with RESTORE.md, the
        exact steps to bring it all back on a machine installed from nothing, one server or a
        cluster. Locked with the password below; sent to every destination switched on - a
        folder, FTP, FTPS, SFTP, SCP or a Windows/Samba share. Each node of a cluster sends its own.</p></div>
    <div id="rb-top"></div>
    <div class="card full" id="rb-tried-card" hidden><h2>Backups tried <span class="right" id="rb-tried-tools"></span></h2><div id="rb-tried"></div></div>
    <div class="card full"><h2>When, how many, and the password</h2><div id="sect-backup"></div></div>
    <div class="card full"><h2>Where they go <span class="right" id="rb-add-host"></span></h2>
      <div id="rb-targets"></div></div>
    <div class="card full"><h2>What was sent <span class="right" id="rb-runs-tools"></span></h2><div id="rb-runs"></div></div>
  </div>
  <div class="ctl-pane" id="pane-texts" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Message texts</h2>
      <p class="ctl-lede">What people get from this server - the mails and the SMS, in Czech and English. Click into a text to write; the blue parts are filled in when it is sent.</p></div>
    <div id="tx-root"></div>
  </div>

  <div class="ctl-pane" id="pane-mailq" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Outgoing mail</h2>
      <p class="ctl-lede">Every mail this server sends - an alert, a report, a code to sign in with,
        a notice about a certificate - goes through here. What the receiving side does not take at
        once (greylisting's "try again later", a server away, a full mailbox) waits and is tried
        again by itself; what it refuses for good is shown as failed. Both nodes of a cluster see
        the same list: a mail is sent by the node it was made on, or by the other when that one
        is gone. What a mail held is never kept once it went.</p></div>
    <div class="card full held mq-held">
      <div class="mq-chips" id="mq-chips"></div>
      <div class="btnrow filters" style="margin-top:12px">
        <input type="search" id="mq-q" placeholder="an address, a name, what the server said… (to:*@example.cz, state:waiting, kind:code…)" style="flex:1;min-width:260px">
        <select id="mq-state">
          <option value="">every state</option>
          <option value="open">waiting or failed</option>
          <option value="waiting">waiting for another try</option>
          <option value="sending">being sent</option>
          <option value="sent">sent</option>
          <option value="failed">failed</option>
          <option value="expired">given up</option>
        </select>
        <button class="btn cmd certadmin-only" id="mq-retry-all" data-icon="refresh">Send every waiting one now</button>
        <button class="btn cmd certadmin-only" id="mq-drop-sent" data-icon="trash">Clear the sent ones</button>
        <button class="btn cmd danger certadmin-only" id="mq-drop-failed" data-icon="trash">Clear the failed ones</button>
      </div>
      <div id="mq-said" class="muted small" style="margin:8px 0 0"></div>
      <div id="mq-table" class="scroll rowsonly" style="margin-top:10px"></div>
      <div id="mq-pager" class="pager"></div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-ha" hidden>
    <div class="ctl-head"><h2 class="ctl-title">High availability
        <button type="button" class="btn cmd small ha-hist-btn" id="ha-history" data-icon="history"
                title="What happened to the cluster: the VIP address moving, a node stopping and coming back, replication stopping, errors - and what was done by hand.">History</button></h2>
      <p class="ctl-lede" id="ha-lede-shared">Two servers, both answering - active/active. Both open the same
        PostgreSQL and keep nothing that matters anywhere else, so a load balancer may send any
        request to either, round robin and without stickiness: a sign-in, a certificate added on
        one and renewed by the other. Every change made on one is on the
        other within five seconds.</p>
      <p class="ctl-lede" id="ha-lede-replicated" hidden>Two servers, both answering (active/active). Each has its own PostgreSQL and the two replicate to each other both ways, so a load balancer may send any request to either one, round robin and with no stickiness - a sign-in, a certificate added on one and renewed by the other. Either node goes on alone while the other is away and catches up when it is back.</p></div>
    <div class="card full">
      <h2>The nodes <span class="right" id="ha-said"></span></h2>
      <p class="note">Each node writes into the database every fifteen seconds that it is
        there. One not heard from for three of those is shown as gone; one taken away for good
        can be taken off the list.</p>
      <div id="ha-nodes"></div>
    </div>
    <div class="card full" id="ha-own-card" hidden>
      <h2>Each node's own settings</h2>
      <p class="note">Everything else in Settings is the cluster's and goes to every node. These
        belong to one machine: the port the pages ask
        the daemon on, the name it greets mail servers with and the name isemon files it under,
        its own copies of the database (whether, when, how many - each node keeps them on its own
        disk), and the debug switches. Each node shows the value in effect on it: its own,
        marked, or the cluster's, dimmed.</p>
      <p class="note">The machine itself - its addresses, IPv6, gateway, DNS and host name - is
        set per node in Settings → Network. Its clock is in Settings → Time.</p>
      <div id="ha-own"></div>
    </div>
    <div class="card full" id="ha-rep-card" hidden>
      <h2>Replication <span class="right" id="ha-rep-said"></span></h2>
      <p class="note">Each node has its own PostgreSQL and goes on alone when the other is away.
        What one writes goes to the other within a moment; what a node misses while it is away
        waits for it on the other (up to 16 GB of it) and comes over by itself when it is back.
        A node that was away longer than that, or was reinstalled, is rebuilt from the other.</p>
      <div id="ha-rep"></div>
      <div class="going wide" id="ha-going" hidden>
        <div class="bar"><span id="ha-going-fill"></span></div>
        <div class="says" id="ha-going-says"></div>
      </div>
      <div class="btnrow admin-only" style="margin-top:12px">
        <button class="btn cmd" id="ha-pause" data-icon="power"
                title="Both directions stop for now. What is written meanwhile waits on each node for the other, up to 16 GB, and goes over when it is resumed.">Pause it…</button>
        <button class="btn cmd primary" id="ha-resume" data-icon="play"
                title="Both directions go on from where they stopped.">Resume it</button>
        <button class="btn cmd" id="ha-errors" data-icon="flag"
                title="What the errors were, from PostgreSQL's own log - and clearing them once dealt with.">The errors…</button>
        <button class="btn cmd" id="ha-refresh" data-icon="refresh"
                title="Read the list of tables the other node publishes again - after an upgrade that added one.">Read the tables again</button>
        <button class="btn cmd danger" id="ha-resync" data-icon="db"
                title="Rebuild THIS node from the other: its tables emptied and every row copied over, both directions made afresh. A copy of what is here is made first.">Rebuild this node from the other…</button>
        <button class="btn cmd danger" id="ha-stop" data-icon="cancel"
                title="Replication off for good: each node goes on alone with what it has, and they drift apart.">Switch it off…</button>
      </div>
    </div>
    <div class="card full" id="ha-addr-card" hidden>
      <h2>The addresses of the two nodes <span class="right" id="ha-addr-said"></span></h2>
      <p class="note">Replication reaches the other node by its address, kept in three places on
        each node: config.json, its subscription and the line of pg_hba.conf that lets the other
        in. When an address changes, tell it here - on the node whose address did <b>not</b>
        change: it puts its side right and tells the other node, which does its part by itself.
        Names of the nodes are changed under Each node's own settings; the whole guide is
        docs/renaming-and-readdressing.md.</p>
      <div id="ha-addr"></div>
    </div>
    <div class="card full" id="ha-vip-card">
      <h2>The VIP address</h2>
      <p class="note">An address for the pages that is on one node at a time - active and
        standby - held by keepalived. It leaves a node by itself when the node goes into
        maintenance, is upgraded or rebuilt, or when its pages stop answering their own
        /healthz (nginx, PHP, the daemon, the database); and when
        the node is gone altogether. It comes back to the node it is meant to be on once
        that is well again. With it off, a load balancer of your own works as before
        (docs/load-balancers.md).</p>
      <div id="web-vip"></div>
    </div>
    <div class="card full" id="ha-split-card" hidden>
      <h2>When the nodes lose each other <span class="right" id="ha-split-state"></span></h2>
      <p class="note">Two nodes that cannot reach each other each take the other for gone and go on alone
        (split brain): a certificate may then be renewed on both halves, the wrong tries are counted on each half
        apart, and what is changed on each half goes its own way. Without a third machine it cannot be
        ruled out - but which node goes on, and what holds meanwhile, is chosen here. Each node watches
        the other’s database every two seconds.</p>
      <div id="ha-split"></div>
    </div>
    <div class="card full"><div id="sect-ha"></div></div>
    <div class="card full" id="ha-make">
      <h2>Making it two, step by step</h2>
      <div id="ha-checks"></div>
      <div class="btnrow" id="ha-make-open" hidden><button class="btn cmd" id="ha-make-btn" data-icon="eye">Show how it was made</button></div>
      <div id="ha-make-body">
      <p class="note">Two ways. <b>One shared PostgreSQL</b> (both nodes open the same database) is done on the pages alone: <b>Make the bundle…</b> here asks for the second node's address, lets it through this node's firewall and into PostgreSQL here at once, and saves the bundle; <b>Join a cluster…</b> on the second node's pages takes it. <b>Replicated</b> (a PostgreSQL on each node) is done on the command line, as root, because it installs and restarts PostgreSQL there. The pages show the result and look after it afterwards. In the examples the first node is <code>acme1</code> at <code>192.0.2.11</code> and the second <code>acme2</code> at <code>192.0.2.12</code>; put your own names and addresses in.</p>
      <ol class="ha-steps">
        <li><p><b>On this node, the first one.</b> Its database has to be PostgreSQL 16 or later on this machine (<i>Settings → The database</i> moves it there if it is not yet). Then:</p>
          <pre class="ha-cmd" data-no-i18n>acme --ha-setup --ha-peer 192.0.2.12 --node-name acme1</pre>
          <p>It switches PostgreSQL to logical replication and restarts it (after asking), lets the second node in (pg_hba.conf, the firewall), publishes every table, numbers this node's rows odd - the second's will be even - and writes the bundle to <code>/root/acme-join-acme1.json</code>, printing its passphrase once. Write the passphrase down.</p>
          <p>For one PostgreSQL both nodes open instead (a server of its own, or a cluster's address) add <code>--ha-shared</code>, and <code>--ha-db-host ADDRESS</code> when the server is elsewhere.</p></li>
        <li><p><b>The bundle</b> carries what the second node needs and nothing else: the database's account and password, and the key that opens the sealed keys - locked with the passphrase. Carry the file over on its own (scp, a USB stick) and tell the passphrase some other way. A fresh one, for a node to be rebuilt later:</p>
          <pre class="ha-cmd" data-no-i18n>acme --ha-bundle /root/acme-join-acme1.json</pre>
          <div class="btnrow admin-only">
            <button class="btn cmd primary" id="ha-bundle" data-icon="key">Make the bundle…</button>
          </div></li>
        <li><p><b>On the second node</b>, as root: install the same version of acme, fetch the bundle and join:</p>
          <pre class="ha-cmd" data-no-i18n>./install.sh --with-db postgres --yes
scp root@192.0.2.11:/root/acme-join-acme1.json /root/
acme --ha-join /root/acme-join-acme1.json --node-name acme2</pre>
          <p>It installs PostgreSQL there if it is missing, prepares it the same way, copies every row from this node and sets both directions up. From then on sign in to either node with the same accounts. A node joining one shared PostgreSQL can instead use <b>Join a cluster…</b> on its own pages.</p>
          <div class="btnrow admin-only">
            <button class="btn cmd" id="ha-join" data-icon="net">Join a cluster…</button>
          </div></li>
        <li><p><b>On both nodes</b>, give the load balancer's address, so that the allow lists, the sign-in pause and every log see the real client and not the balancer:</p>
          <pre class="ha-cmd" data-no-i18n>acme --trusted-proxy 192.0.2.10/32</pre></li>
        <li><p><b>Check it</b> on either node - both nodes and both directions of the replication should be listed as running:</p>
          <pre class="ha-cmd" data-no-i18n>acme --ha-status</pre>
          <p>The same is on this page, above. Then set the load balancer up: see below.</p></li>
      </ol>
      </div>
    </div>
    <div class="card full">
      <h2>Looking after it from the command line</h2>
      <p class="note">Each of these has its button above; the command does the same thing from a shell on the node, as root, and works when the pages do not.</p>
      <!-- Folded away until asked for (1.0.75), as the balancers' guides. -->
      <details class="lb-guide ha-cli-fold" id="ha-cli-fold">
        <summary><b>The commands</b><span class="tag dim">replication · the VIP address (VRRP) · maintenance</span></summary>
        <div class="ha-cli-in">
      <table class="plain ha-cli">
        <thead><tr><th>Command</th><th>What it does</th></tr></thead>
        <tbody>
          <tr><td data-no-i18n>acme --ha-status</td>
            <td>The nodes, when each was last heard from, and both directions of the replication: running or not, how much is waiting to go over, any error.</td></tr>
          <tr><td data-no-i18n>acme --ha-pause<br>acme --ha-pause in<br>acme --ha-pause out</td>
            <td>Stop sending for now - both directions, or only what comes in or goes out. Both nodes keep answering from their own database. What is written meanwhile waits (up to 16 GB) and goes over after resuming.</td></tr>
          <tr><td data-no-i18n>acme --ha-resume<br>acme --ha-resume in<br>acme --ha-resume out</td>
            <td>Carry on from where it stopped.</td></tr>
          <tr><td data-no-i18n>acme --ha-resync</td>
            <td>Rebuild <b>this</b> node from the other: a copy of this node's database is made, its tables are emptied, every row is copied over and both directions are set up afresh. For a node that was away longer than what is kept for it (the status says <i>lost - rebuild the other node</i>), or one whose database is in doubt. Always run it on the node that was away, never on the one that kept working.</td></tr>
          <tr><td data-no-i18n>acme --ha-bundle FILE<br>acme --ha-join FILE --node-name NAME</td>
            <td>A node reinstalled from scratch: a new bundle on the live node, then install acme on the new machine and join with it, exactly as the second node did the first time. It takes the same place as the node it replaces.</td></tr>
          <tr><td data-no-i18n>acme --ha-stop</td>
            <td>Replication off for good: both subscriptions and their slots are removed, each node goes on alone with what it has, and from then on they drift apart. Putting them together again is a rebuild of one from the other (<code>--ha-resync</code>).</td></tr>
          <tr><td data-no-i18n>./install.sh</td>
            <td>An upgrade: run it on one node, then on the other. Both nodes have to run the same version - the list of nodes above shows a mismatch. Replication goes on through it.</td></tr>
          <tr><td data-no-i18n>acme --ha-stop<br>…<br>acme --ha-resync</td>
            <td>Putting a dump back is refused while replication runs. Switch it off, restore the dump on one node, then rebuild the <b>other</b> node from it with <code>--ha-resync</code> run there.</td></tr>
          <tr><td data-no-i18n>acme --trusted-proxy CIDR</td>
            <td>The load balancer's address, on both nodes: nginx then takes the client's own address from X-Forwarded-For sent by that one address.</td></tr>
          <tr class="ha-cli-group"><td colspan="2">The VIP address (VRRP)</td></tr>
          <tr><td data-no-i18n>acme --web-status</td>
            <td>Where the VIP address is now and how each node sees it (VRRP: master or backup), its settings, and the certificates of the nodes and of the address. <code>--json</code> for a script.</td></tr>
          <tr><td data-no-i18n>acme --vip-set 192.0.2.10/24 --vip-fqdn NAME<br>&nbsp;&nbsp;[--vip-vrid N] [--vip-iface NODE=IFACE]</td>
            <td>The address itself: with its prefix, its host name, the VRRP id (1-255, default 51; another id for every cluster on the same network) and on each node the interface it goes on (default: the one with the node's own address). Run on one node; the other takes it within a few seconds.</td></tr>
          <tr><td data-no-i18n>acme --vip on<br>acme --vip off</td>
            <td>The VIP address on or off: root writes keepalived's configuration and starts it, or stops it and takes the address away - on both nodes.</td></tr>
          <tr><td data-no-i18n>acme --vip-move NODE</td>
            <td>Move the address to that node now, by hand - it goes once the node is healthy (its pages answer, not in maintenance).</td></tr>
          <tr><td data-no-i18n>acme --vip-return NODE<br>acme --vip-return stay</td>
            <td>Where it goes after a failure is over: always back to that node, or <i>stay</i> - it stays where it is until that node fails or it is moved by hand.</td></tr>
          <tr><td data-no-i18n>acme --maintenance on|off|status [--node NAME]</td>
            <td>A node out of service and back: its /healthz says 503 - and the VIP address leaves it for the other node by itself.</td></tr>
          <tr><td data-no-i18n>acme --web-retry</td>
            <td>This node asks root again for what failed (keepalived's configuration, a certificate for nginx, the firewall).</td></tr>
          <tr><td data-no-i18n>systemctl status keepalived<br>journalctl -u keepalived -n 50<br>ip -br addr</td>
            <td>On the node itself, when the address does not come or does not move: whether keepalived runs, what it said (each change between MASTER and BACKUP is a line), and on which interface the address is. VRRP is IP protocol 112 between the two nodes - the firewall lets it in from the other node by itself.</td></tr>
        </tbody>
      </table>
        </div>
      </details>
      <p class="note">A short outage - a reboot, a network cut, hours or days - needs nothing: the live node keeps what the other misses, and the node catches up by itself when it is back. A code used on one node is known to the other a moment later; a code tried on both nodes in that same moment, or on both halves of a split network, can be accepted twice - so a 30-second code may, rarely, pass twice. Change settings on one node at a time.</p>
    </div>
    <div class="card full">
      <h2>The load balancer</h2>
      <div id="ha-lb"></div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-carry" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Export and import</h2>
      <p class="ctl-lede">The whole configuration as one file: the settings (each node's own
        too), the directories, the accounts of these pages, the certificates of the pages and the
        VIP address, the VIP address, who may reach which page, the firewall and the mail server's
        authorities. The certificates kept and their keys are not in it: they move with a copy of
        the database and its key. On the command line: acme --export-config FILE
        [--with-secrets] and acme --import-config FILE --yes.</p></div>
    <div class="card full">
      <div class="btnrow">
        <button class="btn cmd admin-only" id="ex-plain" data-icon="download">Export</button>
        <button class="btn cmd danger admin-only" id="ex-whole" data-icon="key">Export with the secrets</button>
        <button class="btn cmd admin-only" id="ex-load" data-icon="upload">Import a file…</button>
        <input type="file" id="ex-file" accept=".json" hidden>
      </div>
    </div>
  </div>

  <div class="ctl-pane" id="pane-web" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Certificates and TLS</h2>
      <p class="ctl-lede">How the pages and the administration speak HTTPS: on each node,
        and on the cluster's VIP address (Settings → High availability) - the certificate
        with its chain, the protocols, the ciphers.</p></div>
    <div class="card full">
      <h2>Certificates</h2>
      <p class="note">One for each node's own name and one for the VIP address's. A
        certificate is sent as PEM files (the certificate, its key, the chain, the root - in
        any order, or all in one file) or as a PFX / PKCS#12 file, with its password or
        without; or the request is made here and only what the authority sends back is
        uploaded. Root puts it in nginx and asks nginx before reloading it.</p>
      <div id="web-certs" class="cert-grid"></div>
    </div>
    <div class="card full" id="web-push-card">
      <h2>Certificates from acme <span class="right" id="web-push-state"></span></h2>
      <p class="note">acme, the certificate manager, can give this server its certificate and renew it
        by itself (acme push). Paired once with a code shown here, acme signs every request with its key and
        sends the certificate's private key sealed for this server alone; the certificate is kept exactly where
        an upload above keeps it, and the Automatic certificates leave it alone from then on. Off until switched
        on; acme's address must be among those that may reach these pages.</p>
      <div id="web-push"></div>
    </div>

  </div>
  <div class="ctl-pane" id="pane-fw" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Firewall and access</h2>
      <p class="ctl-lede">Who may reach which pages, and the machine's own firewall: what acme's
        functions need is let in by itself (the DNS server for DNS-01 switched on, the cluster
        made, the web address turned on), and you add whatever else you want - for IPv4 and IPv6. Inside
        the cluster everything is always let in.</p></div>
    <div class="card full">
      <h2>Who may reach the pages</h2>
      <p class="note">The portal, the administration and the health check share
        ports 80 and 443, so who sees which is said by nginx, page by page; the firewall
        below opens the ports only to these networks. The other node and the VIP address
        are always let in, and so is the machine itself.</p>
      <div id="fw-access"></div>
    </div>
    <div class="card full">
      <div class="fw-top"><div><h2>The firewall (iptables / ip6tables)</h2>
        <p class="note" id="fw-lede"></p></div>
        <div id="fw-master"></div></div>
      <div id="fw-nodes" class="fw-nodes"></div>
      <div id="fw-body"></div>
    </div>
    <div class="card full fulladmin-only"><h2>Taken back unless kept</h2><div id="sect-fw"></div></div>
  </div>
  <div class="ctl-pane" id="pane-upgrade" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Upgrades and maintenance</h2>
      <p class="ctl-lede">A new version put in from here: send the package, and the nodes are
        upgraded one at a time - each taken out of service first, so the load balancer and the
        VIP address go to the other, and brought back only once it answers again. The command
        line (install.sh --upgrade) works as it always has.</p></div>
    <div class="card full">
      <h2>The nodes</h2>
      <p class="note">A node in maintenance renews and deploys nothing and its /healthz says
        503, so the load balancer leaves it alone; these pages go on working. With a single
        server, maintenance means no certificate is renewed or put in place until it is back.</p>
      <div id="up-nodes"></div>
    </div>
    <div class="card full admin-only" id="up-web-card">
      <h2>From the web</h2>
      <p class="note">Where new versions are published - the address below - is looked at once a
        day. A newer acme found there is offered here, and put in with one click: fetched, its
        signature checked like a package sent by hand, then the nodes upgraded one at a time.
        Nothing is put in by itself.</p>
      <div id="up-web"></div>
      <div id="sect-upgrade"></div>
    </div>
    <div class="card full admin-only">
      <h2>A new version</h2>
      <p class="note">The .tar.gz of a new acme, as it was released. It is checked before
        anything else: it must be signed by a release key this server trusts, every file in
        it must be the one signed, and it must not be older than what runs here. Root checks
        it all again before it is put in.</p>
      <div class="drop" id="up-drop">
        <input type="file" id="up-file" accept=".gz,.tgz,application/gzip,application/octet-stream" hidden>
        <span id="up-drop-says">Drop the acme-X.Y.Z.tar.gz here, or press to choose it</span>
      </div>
      <div id="up-pkg"></div>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd primary" id="up-start" data-icon="play" disabled>Upgrade</button>
        <button class="btn cmd" id="up-forget" data-icon="trash" hidden>Forget the package</button>
      </div>
      <div id="up-ready"></div>
    </div>
    <div class="card full admin-only" id="up-down-card" hidden>
      <h2>Going back to an older version</h2>
      <p class="note">Only to a version that is safe: one that reads what the newer versions
        wrote into the database the same, and has every security fix that matters - each version
        says how far back it may go, and the highest of what ran on this database and was
        installed on this machine counts. The database is not put back nor changed: its tables
        stay as they are and the older version runs on them, so it does not matter how big it
        is. The package is checked like an upgrade's, and against this database's tables, before
        anything is put in; then the nodes go back one at a time, as in an upgrade.</p>
      <div id="up-down"></div>
    </div>
    <div class="card full" id="up-plan-card" hidden>
      <h2>The upgrade</h2>
      <div id="up-plan"></div>
      <p class="note small" id="up-retry" style="min-height:1.4em;margin:6px 0 0"></p>
      <div class="btnrow" style="margin-top:10px">
        <button class="btn cmd danger admin-only" id="up-cancel" data-icon="cancel" hidden>Stop it</button>
      </div>
    </div>
    <div class="card full">
      <h2>What root said last <span class="mono small muted" id="up-log-node" data-no-i18n></span></h2>
      <p class="note"><span>The output of install.sh, the last time this node was upgraded from these pages.</span>
        <span class="mono" data-no-i18n>/var/lib/acme/upgrade/last.log</span></p>
      <!-- Folded until asked for (1.0.196): a long log pushed the rest down. -->
      <details class="fold" id="up-log-fold">
        <summary>the output</summary>
        <div class="seg" id="up-log-nodes" hidden style="margin:10px 0"></div>
        <pre class="lines" id="up-log">–</pre>
      </details>
    </div>
    <div class="card full">
      <h2>On the command line</h2>
      <p class="note">The same, by hand, on each node in turn, as root:</p>
      <pre class="lines">acme --maintenance on --why "upgrade"     # out of service
tar xzf acme-X.Y.Z.tar.gz && cd acme-X.Y.Z
./install.sh --upgrade                     # takes it out and back by itself as well
acme --maintenance off                      # back in service (if it was put out by hand)
acme --upgrade-status                       # an upgrade started on these pages</pre>
    </div>
  </div>

  <div class="ctl-pane" id="pane-about" hidden>
    <div class="ctl-head"><h2 class="ctl-title">About</h2></div>
    <div class="card full"><div id="about-state"></div></div>
    <div class="card full"><div id="sect-about"></div></div>
  </div>

  <div class="card full" id="rest-card" hidden><div id="sect-rest"></div></div>

  <div class="save-bar admin-only" id="save-bar">
    <button class="btn cmd primary" id="set-save" data-icon="save"
            title="Save the changed settings into the database. They take effect the moment they are saved - nothing restarts.">Save the changes</button>
    <button class="btn cmd" id="set-reset" data-icon="undo"
            title="Throw away the changes on this page and read the settings back from the daemon as they are.">Put them back</button>
    <span class="muted small" id="set-said"></span>
  </div>
  </div>
</div>
</section>

</div><!-- /wrap -->

<div class="modal" id="modal" hidden>
  <div class="box" id="modal-box">
    <div class="head"><h3 id="modal-title">…</h3>
      <button class="xbtn" id="modal-x" data-icon="close" aria-label="Close"></button></div>
    <div class="body" id="modal-body"></div>
    <div class="foot" id="modal-foot"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script nonce="<?= h($nonce) ?>">
var ME = <?= json_encode($me, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;
var STATUS = <?= $initial ? json_encode($initial, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
var PHP_SAFETY = <?= ($me['role'] ?? '') === 'fulladmin' ? json_encode(acme_php_safety(), JSON_HEX_TAG | JSON_HEX_AMP) : 'null' ?>;
</script>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/core.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/cols.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/cols.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/admin.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/admin.js')) ?>"></script>
<?php if (is_file(dirname(__DIR__) . '/assets/certs.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/certs.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/certs.js')) ?>"></script>
<?php endif; ?>
<?php if (is_file(dirname(__DIR__) . '/assets/dnssets.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/dnssets.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/dnssets.js')) ?>"></script>
<?php endif; ?>
<?php if (is_file(dirname(__DIR__) . '/assets/teams.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/teams.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/teams.js')) ?>"></script>
<?php endif; ?>
<?php if (is_file(dirname(__DIR__) . '/assets/sshkey.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/sshkey.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/sshkey.js')) ?>"></script>
<?php endif; ?>
<?php if (is_file(dirname(__DIR__) . '/assets/deployfiles.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/deployfiles.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/deployfiles.js')) ?>"></script>
<?php endif; ?>
<?php if (is_file(dirname(__DIR__) . '/assets/cas.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/cas.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(dirname(__DIR__) . '/assets/cas.js')) ?>"></script>
<?php endif; ?>
</body>
</html>
