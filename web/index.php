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

if (isset($_GET['api'])) {
    $what = (string) $_GET['api'];
    $post = $_SERVER['REQUEST_METHOD'] === 'POST';
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
        acme_call('/api/portal/logout', 'POST', [], 10.0);
        acme_clear_session();
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => true]);
        exit;
    }
    $reads = ['me' => '/api/portal/me', 'info' => '/api/portal/info', 'certs' => '/api/portal/certs',
              'mfa' => '/api/portal/mfa'];
    $writes = ['cert-download' => '/api/portal/cert_download', 'cert-request' => '/api/portal/cert_request'];
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
$me    = null;
$mfa   = '';
if ($alive && acme_session() !== '') {
    $got = acme_get('/api/portal/me', 8.0);
    $me = is_array($got) ? ($got['me'] ?? null) : null;
    /* The password given, its second step not yet (an account of acme's own). */
    $mfa = (is_array($got) && !$me && !empty($got['mfa'])) ? (string) $got['mfa'] : '';
}
$lang = acme_lang_pick(null, (string) ($info['lang'] ?? 'cs'));
$load = $lang !== 'en' && acme_lang_pack($lang) !== null;
$title = (string) ($info['title'] ?? '');
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
      <p class="lede">Sign in with your name and password to see your certificates.</p>
      <?php if (!$alive): ?>
        <div class="offline">The server is not answering just now. Try again in a while, or tell
          the administrator.</div>
      <?php elseif (empty($info['on'])): ?>
        <div class="offline">The portal is switched off. Ask the administrator.</div>
      <?php endif; ?>
      <div id="mfa-box" data-stage="<?= h($mfa) ?>" hidden></div>
      <form id="signin-form" autocomplete="on"<?= $mfa !== '' ? ' hidden' : '' ?>>
        <input type="text" id="in-name" name="username" placeholder="name" autocomplete="username"
               autocapitalize="none" spellcheck="false" required>
        <input type="password" id="in-pass" name="password" placeholder="password"
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
<script nonce="<?= h($nonce) ?>">portalDoor();</script>
<?php else: ?>
<header>
  <h1<?= $title_ours ? '' : ' data-no-i18n' ?>><?= h($title) ?></h1>
  <div class="spacer"></div>
  <div class="btnrow">
    <span class="langpick" id="langpick"></span>
    <button type="button" class="btn small mebtn" id="mebtn" data-no-i18n><?= h($me['display'] ?: $me['name']) ?></button>
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
