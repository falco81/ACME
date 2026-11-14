<?php
/**
 * index.php — the certificate portal of acme (certificates kept, renewed and
 * put in place by themselves).
 *
 * Signed in with their directory name and password, somebody sees what the
 * portal offers them - drawn by portal.js and what is plugged into it
 * (assets/certs-portal.js, when it is there). Nothing is decided here: every
 * answer comes from the acme daemon, and this page holds nothing but a cookie
 * the browser cannot read.
 */
declare(strict_types=1);

define('ACME_COOKIE', 'acme_portal');
define('ACME_COOKIE_PATH', '/');
require_once __DIR__ . '/acme-page.php';
require_once __DIR__ . '/acme-api.php';
require_once __DIR__ . '/acme-art.php';

/* ---- signed in by the load balancer or WAF in front (otp 1.0.239) ----------
   Off unless switched on in the administration: then /api/portal/info names the header the
   balancer puts the name it signed in into. The name, the key it sends with it, and the
   address of the machine the request really came from (nginx's $realip_remote_addr, as
   ACME_PEER - never the client's address from X-Forwarded-For) go to the daemon, which decides. */
define('ACME_SSO_HOLD', 'acme_sso_off');

function acme_sso_hold(bool $on): void
{
    setcookie(ACME_SSO_HOLD, $on ? '1' : '', [
        'expires'  => $on ? 0 : time() - 3600,
        'path'     => ACME_COOKIE_PATH,
        'secure'   => acme_https(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    if ($on) {
        $_COOKIE[ACME_SSO_HOLD] = '1';
    } else {
        unset($_COOKIE[ACME_SSO_HOLD]);
    }
}

/** Signed in by the balancer, when it sent who: '' when nothing was to be done or it went
    well, the words of the refusal otherwise. */
function acme_sso_sign_in(array $info): string
{
    $sso = $info['sso'] ?? null;
    if (!is_array($sso) || empty($info['on']) || !empty($_COOKIE[ACME_SSO_HOLD])) {
        return '';
    }
    $head = (string) ($sso['header'] ?? '');
    if (!preg_match('/^[A-Za-z][A-Za-z0-9-]{0,63}$/', $head)) {
        return '';
    }
    $who = (string) ($_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $head))] ?? '');
    if ($who === '') {
        return '';
    }
    $extra = [];
    $peer = preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['ACME_PEER'] ?? ''));
    if ($peer !== '') {
        $extra[] = 'X-Acme-Peer: ' . substr($peer, 0, 64);
    }
    [$status, $body] = acme_call('/api/portal/sso', 'POST', [
        'name' => substr($who, 0, 300),
        'key'  => substr((string) ($_SERVER['HTTP_X_ACME_SSO_KEY'] ?? ''), 0, 300),
        'lang' => preg_replace('/[^a-z]/', '', (string) ($_COOKIE['acme_lang'] ?? '')),
    ], 60.0, $extra);
    if ($status === 0) {
        return 'the server is not answering - try again in a while';
    }
    $data = json_decode($body, true);
    if ($status === 200 && is_array($data)) {
        if (!empty($data['token'])) {
            acme_set_session((string) $data['token']);
            $_COOKIE[ACME_COOKIE] = (string) $data['token'];
        }
        return '';
    }
    if ($status === 401 || $status === 403) {
        // Not this person's any more: whoever was signed in here before is not shown.
        acme_clear_session();
        unset($_COOKIE[ACME_COOKIE]);
    }
    return is_array($data) && !empty($data['error']) ? (string) $data['error']
        : 'the sign-in through the load balancer was not taken here';
}

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
    // the reads from another page refused, as the admin pages' (1.0.52)
    if (!$post) {
        $gf = (string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
        if ($gf !== '' && $gf !== 'same-origin' && $gf !== 'none') {
            http_response_code(403);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['ok' => false, 'error' => 'that request did not come from this page']);
            exit;
        }
    }
    if ($what === 'lang' && !$post) {
        acme_serve_lang();
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
        [$status, $body] = acme_call('/api/portal/login', 'POST', [
            'name'     => (string) ($sent['name'] ?? ''),
            'password' => (string) ($sent['password'] ?? ''),
            'lang'     => (string) ($sent['lang'] ?? ''),
        ], 30.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' => 'the server is not answering - try again in a while']);
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
    if ($what === 'kerberos-login' && $post) {
        /* Signing in with Windows (Kerberos, 1.0.99): the portal's own switch - 404 while off,
           401 Negotiate without a ticket, 403 for every refusal. */
        acme_kerberos_relay('/api/portal/kerberos');
        exit;
    }
    if ($what === 'mfa' && $post) {
        /* The second step of an account of acme's own (portal_local), as the
           administration's: given, the daemon hands a new sign-in - its cookie
           set here, the token never shown to the page. */
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        [$status, $body] = acme_call('/api/portal/mfa', 'POST', sent_json(), 90.0);
        if ($status === 0) {
            http_response_code(503);
            echo json_encode(['ok' => false, 'error' => 'the server is not answering - try again in a while']);
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
    if ($what === 'logout' && $post) {
        $sent = sent_body();
        acme_call('/api/portal/logout', 'POST', [], 10.0);
        acme_clear_session();
        header('Content-Type: application/json; charset=utf-8');
        /* Signed in by the balancer (otp 1.0.239): its own sign-out next, or - with none set - no
           sign-in by it again until asked, or Sign out would sign the person straight back in. */
        $go = '';
        if (!empty($sent['sso'])) {
            $inf = acme_get('/api/portal/info', 5.0);
            $go = is_array($inf) && is_array($inf['sso'] ?? null) ? (string) ($inf['sso']['logout'] ?? '') : '';
            if ($go === '') {
                acme_sso_hold(true);
            }
        }
        echo json_encode(['ok' => true, 'go' => $go]);
        exit;
    }
    $reads = ['me' => '/api/portal/me', 'info' => '/api/portal/info', 'certs' => '/api/portal/certs',
              'mfa' => '/api/portal/mfa'];
    $writes = ['cert-download' => '/api/portal/cert_download', 'cert-request' => '/api/portal/cert_request',
               'password' => '/api/portal/password', 'cert-renew' => '/api/portal/cert_renew',
               'cert-auto' => '/api/portal/cert_auto', 'cert-revoke' => '/api/portal/cert_revoke',
               'cert-approve' => '/api/portal/cert_approve', 'csr-decode' => '/api/portal/csr_decode',
               'cert-csr' => '/api/portal/cert_csr',
               // The one-time code at every sign-in (1.0.40, as otp 1.0.228).
               'gate' => '/api/portal/gate', 'gate_again' => '/api/portal/gate/again'];
    if ($post && isset($writes[$what])) {
        acme_relay($writes[$what], 'POST', sent_json(), 120.0);
        exit;
    }
    if (!$post && $what === 'cert-job') {
        /* One job of one of their certificates - the daemon checks it is theirs. */
        acme_relay('/api/portal/cert_job?' . http_build_query(['id' => (int) ($_GET['id'] ?? 0)]), 'GET', null, 30.0);
        exit;
    }
    if (!$post && isset($reads[$what])) {
        acme_relay($reads[$what], 'GET', null, 30.0);
        exit;
    }
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['ok' => false, 'error' => 'unknown endpoint']);
    exit;
}

/* ---- the page ------------------------------------------------------------ */
$info  = acme_get('/api/portal/info', 5.0);
$alive = is_array($info);
// Sign in through the balancer again, after Sign out held it (otp 1.0.239).
$sso_from = (string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '');
// only from this page (1.0.52): a link of another site undid a Sign out
if (isset($_GET['sso']) && in_array($sso_from, ['', 'same-origin', 'same-site', 'none'], true)) {
    acme_sso_hold(false);
    header('Location: /', true, 303);
    exit;
}
$sso_said = $alive ? acme_sso_sign_in($info) : '';
$me    = null;
$mfa   = '';
if ($alive && acme_session() !== '') {
    $got = acme_get('/api/portal/me', 8.0);
    $me = is_array($got) ? ($got['me'] ?? null) : null;
    /* The password given, its second step not yet (an account of acme's own). */
    $mfa = (is_array($got) && !$me && !empty($got['mfa'])) ? (string) $got['mfa'] : '';
}
// Signed in, the one-time code not typed yet (as otp 1.0.228): the sign-in page, asking for it.
$gate = (is_array($me) && !empty($me['gate'])) ? $me['gate'] : null;
if ($gate !== null) {
    $me = null;
}
$lang = acme_lang_pick(null, (string) ($info['lang'] ?? 'cs'));
$load = $lang !== 'en' && acme_lang_pack($lang) !== null;
$title = (string) ($info['title'] ?? '');
/* Signing in with Windows (1.0.99): the button, tried by itself, or no password at all. */
$krb = ($alive && is_array($info['kerberos'] ?? null)) ? $info['kerberos'] : [];
$krb_on = !empty($krb['on']);
$krb_only = $krb_on && !empty($krb['only']);
// No title of the site's own: a heading of the page's own, in the page's language.
$title_ours = $title === '';
if ($title_ours) {
    $title = 'Certificates';
}
?>
<!doctype html>
<html lang="<?= h($lang) ?>" class="app-shell-root<?= $load ? ' i18n-wait' : '' ?>">
<head>
<?php acme_head($title, $lang, $load, $nonce, '/'); ?>
<?php if ($me && is_file(__DIR__ . '/assets/certs-portal.js')):
    /* The certificate manager's own pieces (names, days left, states), as the administration has them. */
    foreach (['certs.css', 'certs-portal.css'] as $css):
        if (is_file(__DIR__ . '/assets/' . $css)): ?>
<link rel="stylesheet" nonce="<?= h($nonce) ?>" href="/assets/<?= h($css) ?>?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/' . $css)) ?>">
<?php endif; endforeach; endif; ?>
</head>
<body class="app-shell">
<div class="wrap portal">
<?php if (!$me): ?>
<div class="signin">
  <div class="signbox">
    <!-- What this is, in one picture - the one picked in the administration (1.0.71). -->
    <?= acme_art_for(is_array($info) ? ($info['art'] ?? null) : null, 'portal', $title) ?>
    <div class="card">
      <h1<?= $title_ours ? '' : ' data-no-i18n' ?>><?= h($title) ?></h1>
      <?php if ($krb_only): ?>
      <p class="lede">Sign in with Windows to see your certificates.</p>
      <?php else: ?>
      <p class="lede">Sign in with your name and password to see your certificates.</p>
      <?php endif; ?>
      <?php if (!$alive): ?>
        <div class="offline">The server is not answering just now. Try again in a while, or tell
          the administrator.</div>
      <?php elseif (empty($info['on'])): ?>
        <div class="offline">The portal is switched off. Ask the administrator.</div>
      <?php endif; ?>
      <?php if ($sso_said !== ''): ?>
        <div class="offline" id="sso-said"><?= h($sso_said) ?></div>
      <?php endif; ?>
      <?php if ($alive && is_array($info['sso'] ?? null) && !empty($_COOKIE[ACME_SSO_HOLD])): ?>
        <p class="note small" id="sso-again">You signed out. <a href="/?sso=1">Sign in through the company sign-in again</a>, or with your name and password below.</p>
      <?php endif; ?>
      <div id="mfa-box" data-stage="<?= h($mfa) ?>" hidden></div>
      <?php if ($krb_only): ?>
      <!-- Only Windows (1.0.99): no name and no password on the page at all. -->
      <form id="signin-form" hidden></form>
      <?php else: ?>
      <form id="signin-form" autocomplete="on"<?= $mfa !== '' ? ' hidden' : '' ?>>
        <input type="text" id="in-name" name="username" placeholder="name" aria-label="Name" autocomplete="username"
               autocapitalize="none" spellcheck="false" required>
        <input type="password" id="in-pass" name="password" placeholder="password" aria-label="Password"
               autocomplete="current-password" required>
        <?php if (!empty($info['hint'])): ?>
          <p class="muted small" style="margin:-4px 0 10px">Your name is written as <b class="mono" data-no-i18n><?= h($info['hint']) ?></b></p>
        <?php endif; ?>
        <button class="btn primary cmd" type="submit" id="in-go"><svg
          viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor"
          stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"
          ><path d="M10 4H6a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h4"/><path d="M14 12h7"/><path
          d="M18 9l3 3-3 3"/></svg><span>Sign in</span></button>
        <div class="said" id="in-said"></div>
      </form>
      <?php endif; ?>
      <?php if ($krb_on && $mfa === '' && $gate === null): ?>
      <div class="krb-box" id="krb-box" data-part="portal" data-auto="<?= !empty($krb['auto']) ? '1' : '0' ?>" data-only="<?= $krb_only ? '1' : '0' ?>">
        <?php if (!$krb_only): ?><div class="krb-or"><span>or</span></div><?php endif; ?>
        <button class="btn cmd<?= $krb_only ? ' primary' : '' ?>" type="button" id="krb-go"><svg
          viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.7"
          stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="4" width="7" height="7" rx="0.6"/><rect
          x="13" y="4" width="7" height="7" rx="0.6"/><rect x="4" y="13" width="7" height="7" rx="0.6"/><rect
          x="13" y="13" width="7" height="7" rx="0.6"/></svg><span>Sign in with Windows</span></button>
        <div class="said" id="krb-said"></div>
      </div>
      <?php endif; ?>
      <div style="margin-top:14px;display:flex;justify-content:space-between;align-items:center">
        <span class="muted small">acme <?= h(ACME_VERSION) ?> · <a class="muted" href="/admin/">Administration</a></span>
        <span class="langpick" id="langpick"></span>
      </div>
    </div>
    <?php if (!empty($info['help'])): ?>
    <div class="card help" id="help-card"><div id="help-text" data-help="<?= h($info['help']) ?>"></div></div>
    <?php endif; ?>
  </div>
</div>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/core.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/portal.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/portal.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>">var PORTAL_GATE = <?= json_encode($gate, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;</script>
<script nonce="<?= h($nonce) ?>">portalDoor();</script>
<?php else: ?>
<header>
  <h1<?= $title_ours ? '' : ' data-no-i18n' ?>><?= h($title) ?></h1>
  <div class="spacer"></div>
  <div class="btnrow">
    <span class="langpick" id="langpick"></span>
    <button type="button" class="btn small mebtn" id="mebtn" data-no-i18n><?= h(($me['display'] ?? '') ?: ($me['name'] ?? '')) ?></button>
    <button class="btn small" id="signout" data-icon="out">Sign out</button>
  </div>
</header>
<div id="portal"></div>
<div class="modal" id="modal" hidden>
  <div class="box" id="modal-box">
    <div class="head"><h3 id="modal-title">…</h3>
      <button class="xbtn" id="modal-x" data-icon="close" aria-label="Close"></button></div>
    <div class="body" id="modal-body"></div>
    <div class="foot" id="modal-foot"></div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script nonce="<?= h($nonce) ?>">var PORTAL_ME = <?= json_encode($me, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP) ?>;</script>
<script nonce="<?= h($nonce) ?>" src="/assets/core.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/core.js')) ?>"></script>
<script nonce="<?= h($nonce) ?>" src="/assets/portal.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/portal.js')) ?>"></script>
<?php if (is_file(__DIR__ . '/assets/certs-portal.js')): ?>
<script nonce="<?= h($nonce) ?>" src="/assets/certs-portal.js?v=<?= h(ACME_VERSION . '-' . (int) @filemtime(__DIR__ . '/assets/certs-portal.js')) ?>"></script>
<?php endif; ?>
<script nonce="<?= h($nonce) ?>">portalApp(PORTAL_ME);</script>
<?php endif; ?>
</div>
</body>
</html>
