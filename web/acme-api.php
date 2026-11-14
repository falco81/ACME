<?php
/**
 * acme-api.php — the pages' side of the daemon API.
 *
 * Taken from isemon, where it has been the whole of the web side for a long
 * time. Neither page holds anything or decides anything: the daemon does all
 * the work and answers on http://127.0.0.1:<port>; this file is the thin
 * client that talks to it, for the administration pages (admin/index.php) and
 * for the enrolment pages (index.php) alike.
 *
 * Two things travel with every request that changes something: the API token
 * the daemon dropped in a file readable only by root and the web server's
 * group, and the session of whoever is signed in. The browser holds the
 * session in a cookie it cannot read itself (HttpOnly), and never sees the
 * token at all — so a page that somebody manages to run JavaScript in still
 * cannot lift anything worth having out of it.
 */
declare(strict_types=1);

// Included by index.php and admin/index.php, never a page of its own. The nginx
// vhost shipped with this refuses it by name, but a site's own vhost may not,
// and a file that answers when asked is a file somebody will one day put a
// side effect in. Asked for directly, it answers as though it were not there.
if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

const ACME_HOST    = '127.0.0.1';
/* api_port in the settings, as the daemon wrote it down when it started
   (1.0.59); 9861 where it has not. */
define('ACME_PORT', (static function (): int {
    $p = (int) trim((string) @file_get_contents('/run/acme/api-port'));
    return ($p >= 1024 && $p <= 65535) ? $p : 9861;
})());
const ACME_TOKEN   = '/run/acme/api-token';

/* Two kinds of sign-in, never the same cookie: an administrator's, and a person
   enrolling their own token, who can reach nothing but that. Which one this
   page uses is said by the page before it includes this file. */
if (!defined('ACME_COOKIE')) {
    define('ACME_COOKIE', 'acme_session');
}
if (!defined('ACME_COOKIE_PATH')) {
    define('ACME_COOKIE_PATH', '/');
}

/** Whether this page was reached over TLS - directly, or through a proxy in
 *  front that terminates it and says so. */
function acme_https(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }
    return strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}

/** Whether this request comes from the machine itself - the operator at the
 *  console, who may be told where things are and what the pages run as. */
function acme_local(): bool
{
    return in_array((string) ($_SERVER['REMOTE_ADDR'] ?? ''), ['127.0.0.1', '::1'], true);
}

/** Read the API token the daemon wrote for us, or null if we can't. */
function acme_token(): ?string
{
    if (!is_readable(ACME_TOKEN)) {
        return null;
    }
    $token = trim((string) @file_get_contents(ACME_TOKEN));
    return $token !== '' ? $token : null;
}

/** The name of a session's cookie (1.0.101): __Host-acme_session / __Host-acme_portal over
 *  https - Secure, Path=/, no Domain, so neither a sibling name (Domain=.example.local) nor a
 *  page over http can plant one beside it (cookie tossing: the browser sent the planted one
 *  first, and PHP took it). Over plain http (a test server) the name as it was - __Host- needs
 *  Secure. */
function acme_cookie_name(string $base = ACME_COOKIE): string
{
    return acme_https() ? '__Host-' . $base : $base;
}

/** The path of the session's cookie: / over https (__Host- asks it - the administration's
 *  cookie is no longer of /admin/ alone, its name keeps it apart), the page's own over http. */
function acme_cookie_path(): string
{
    return acme_https() ? '/' : ACME_COOKIE_PATH;
}

/** How many cookies of that name the browser sent (PHP's $_COOKIE keeps the first only). */
function acme_cookie_count(string $name): int
{
    $n = 0;
    foreach (explode(';', (string) ($_SERVER['HTTP_COOKIE'] ?? '')) as $part) {
        $eq = strpos($part, '=');
        if ($eq !== false && trim(substr($part, 0, $eq)) === $name) {
            $n++;
        }
    }
    return $n;
}

/** A session's token from its cookie (base name 'acme_session' or 'acme_portal') - '' when
 *  there is none, it is not one, or two of the same name came (1.0.101: one of them planted;
 *  which is whose cannot be told - signed out). */
function acme_cookie_session(string $base): string
{
    $name = acme_cookie_name($base);
    if (acme_cookie_count($name) > 1) {
        return '';
    }
    $got = (string) ($_COOKIE[$name] ?? '');
    // \z, not $ (1.0.52): $ let a newline at the end through - it ended the request's headers
    return preg_match('/^[A-Za-z0-9_-]{16,128}\z/', $got) === 1 ? $got : '';
}

/** The session of whoever is signed in, from the cookie - or the one this request has just
 *  set or ended. */
function acme_session(): string
{
    if (array_key_exists('acme_session_now', $GLOBALS)) {
        return (string) $GLOBALS['acme_session_now'];
    }
    return acme_cookie_session(ACME_COOKIE);
}

/** Start one. Same-site and HttpOnly, and Secure whenever the page is on TLS. */
function acme_set_session(string $token): void
{
    setcookie(acme_cookie_name(), $token, [
        'expires'  => 0,                 /* until the browser is closed */
        'path'     => acme_cookie_path(),
        'secure'   => acme_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    $GLOBALS['acme_session_now'] = $token;
    acme_clear_old_cookie();
}

function acme_clear_session(): void
{
    setcookie(acme_cookie_name(), '', [
        'expires'  => time() - 3600,
        'path'     => acme_cookie_path(),
        'secure'   => acme_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    $GLOBALS['acme_session_now'] = '';
    acme_clear_old_cookie();
}

/** The cookie of before 1.0.101 (its plain name, the page's path), taken away over https:
 *  never read there any more. */
function acme_clear_old_cookie(): void
{
    if (acme_https() && isset($_COOKIE[ACME_COOKIE])) {
        setcookie(ACME_COOKIE, '', [
            'expires'  => time() - 3600,
            'path'     => ACME_COOKIE_PATH,
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
    }
}

/**
 * Call the daemon. Returns [status, body-string]; status 0 means unreachable.
 * $payload, when given, is sent as a JSON body and turns this into a POST.
 */
function acme_call(string $path, string $method = 'GET', array|object|null $payload = null,
                     float $timeout = 30.0, array $extra = []): array
{
    $headers = ['Accept: application/json'];
    /* Headers of a caller's own (1.0.173): the scraper's token for /metrics,
       one line each, nothing that could start another header. */
    foreach ($extra as $line) {
        $line = (string) $line;
        if (preg_match('/^X-Acme-[A-Za-z-]{1,40}: [\x21-\x7e]{1,300}\z/', $line)) {
            $headers[] = $line;
        }
    }
    $headers[] = 'X-Acme-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));
    // The name the pages were reached by, for the link in a token's mail
    // (1.0.33) - built by the daemon from this, never taken from the page.
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');
    if (preg_match('/^([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?\z/', $host)) {
        $headers[] = 'X-Acme-Host: ' . $host;
    }
    $session = acme_session();
    if ($session !== '') {
        $headers[] = 'X-Acme-Session: ' . $session;
    }
    // The language of the page (1.0.127): a code mailed from it is written in it.
    $lang = preg_replace('/[^a-z]/', '', (string) ($_COOKIE['acme_lang'] ?? ''));
    if (strlen($lang) === 2) {
        $headers[] = 'X-Acme-Lang: ' . $lang;
    }
    $token = acme_token();
    if ($token === null) {
        return [0, ''];
    }
    $headers[] = 'X-Acme-Token: ' . $token;

    $body = null;
    if ($payload !== null) {
        $body = json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($body === false) {
            /* A number JSON cannot hold (1e400 is INF to PHP) - the request's
               fault, said so, not a 500 with an empty body (1.0.103). */
            return [400, json_encode(['ok' => false, 'error' => 'a number in the request is too big']) ?: ''];
        }
        $headers[] = 'Content-Type: application/json';
        $headers[] = 'Content-Length: ' . strlen($body);
    } elseif ($method !== 'GET') {
        $headers[] = 'Content-Length: 0';
    }

    /* A socket, spoken to by hand, rather than file_get_contents('http://…').
       That one needs allow_url_fopen, which a hardened php.ini switches off —
       and when it is off every call here fails silently and the dashboard
       says "the daemon is not answering" about a daemon that is running
       perfectly. A socket to localhost needs no ini setting at all.

       The daemon always sends a Content-Length and never chunks, so reading
       the body is reading that many bytes. */
    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client(
        'tcp://' . ACME_HOST . ':' . ACME_PORT, $errno, $errstr, $timeout,
        STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);

    $request = $method . ' ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . ACME_HOST . ':' . ACME_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if ($body !== null) {
        $request .= $body;
    }
    if (@fwrite($sock, $request) === false) {
        @fclose($sock);
        return [0, ''];
    }

    $raw = '';
    while (!feof($sock)) {
        $chunk = @fread($sock, 65536);
        if ($chunk === false || $chunk === '') {
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                @fclose($sock);
                return [0, ''];
            }
            break;
        }
        $raw .= $chunk;
    }
    @fclose($sock);

    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return [0, ''];
    }
    $head = substr($raw, 0, $split);
    $reply = substr($raw, $split + 4);
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', $head, $m)) {
        $status = (int) $m[1];
    }
    return [$status, $reply];
}

/** Call the daemon and return the decoded reply, or null. */
function acme_get(string $path, float $timeout = 30.0): ?array
{
    [$status, $body] = acme_call($path, 'GET', null, $timeout);
    if ($status !== 200) {
        return null;
    }
    $data = json_decode($body, true);
    return is_array($data) ? $data : null;
}

/** Pass a daemon reply straight through to the browser. $extra: headers of the
    caller's own, as acme_call takes them. */
function acme_relay(string $path, string $method = 'GET', array|object|null $payload = null,
                      float $timeout = 30.0, array $extra = []): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');

    if (acme_token() === null) {
        http_response_code(503);
        /* Where the token lives is for whoever is on the machine; from
           anywhere else it is a daemon that is not answering. */
        echo json_encode(['ok' => false, 'error' => acme_local()
            ? 'the API token is unreadable — is acme.service running, and is '
              . ACME_TOKEN . ' readable by the web server?'
            : 'the daemon is not answering — is acme.service running?']);
        return;
    }
    [$status, $body] = acme_call($path, $method, $payload, $timeout, $extra);
    if ($status === 0) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' =>
            'the daemon is not answering — is acme.service running?']);
        return;
    }
    /* A 401 is no longer taken as the end of the session here (1.0.73): while
       the web address moves between the nodes, or a node restarts during an
       upgrade, one answer may say so for a moment, and throwing the cookie
       away signed the person out in the middle of watching the upgrade. The
       page asks again (whoami) and goes to the sign-in only when the session
       is really gone; signing out takes the cookie away. */
    http_response_code($status);
    echo acme_squeeze($body);
}

/**
 * Signing in with Windows - Kerberos (1.0.99, as otp 1.0.274): the relay between the
 * browser and the daemon, for the administration and the portal alike. POST of these pages
 * only (acme_guard_post before it).
 *
 * - No "Authorization" yet: the daemon is asked first whether that part signs in with
 *   Windows at all - off, 404 and nothing more; on, 401 with "WWW-Authenticate: Negotiate",
 *   and a browser that may send a ticket to this name sends it at once (the same request
 *   again, with the header).
 * - With it: the header as it came (its length capped) to the daemon, which decides
 *   everything - NTLM, the ticket, the realm, the person. The session goes into the HttpOnly
 *   cookie, never to the page.
 * - Refused: 403, NEVER 401 again - a second 401 makes the browser try again, fall back to
 *   NTLM, or open a password window of its own.
 * The ticket is never written anywhere here.
 *
 * $session: false for "Try my browser's ticket" (nobody is signed in by it).
 */
function acme_kerberos_relay(string $path, array $more = [], bool $session = true): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $auth = (string) ($_SERVER['HTTP_AUTHORIZATION'] ?? ($_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
    $payload = $more;
    /* 65000: the daemon's cap (KRB_HEADER_MAX) - AD's MaxTokenSize in base64, one line of
       nginx's 64 kB header buffers. */
    if (strlen($auth) > 65000) {
        $payload['too_big'] = true;           /* said so, never cut and sent on */
    } elseif ($auth !== '') {
        $payload['header'] = $auth;
    }
    [$status, $body] = acme_call($path, 'POST', (object) $payload, 30.0);
    if ($status === 0) {
        http_response_code(503);
        echo json_encode(['ok' => false, 'error' => 'the server is not answering - try again in a while']);
        return;
    }
    $data = json_decode($body, true);
    if (!is_array($data)) {
        $data = ['ok' => false, 'error' => 'refused'];
    }
    if ($status === 401 && $auth === '') {
        http_response_code(401);
        header('WWW-Authenticate: Negotiate');
        echo json_encode(['ok' => false, 'code' => 'no_ticket',
                          'error' => 'the browser sent no Kerberos ticket - is this computer in the domain, and this name among the browser\'s intranet sites?']);
        return;
    }
    if ($status === 200 && $session && !empty($data['token'])) {
        acme_set_session((string) $data['token']);
        unset($data['token']);
        echo json_encode($data);
        return;
    }
    unset($data['token']);
    /* NTLM, a password typed into the browser's own dialog, another mechanism (1.0.100): no
       Kerberos ticket at all, as a computer outside the domain sends - said as no_ticket, so
       the page tells it from a refusal of a real ticket (the words stay the generic ones). */
    if ($status === 401 && preg_match('/: no Kerberos ticket\z/', (string) ($data['error'] ?? '')) === 1) {
        $data['code'] = 'no_ticket';
    }
    http_response_code($status === 401 ? 403 : $status);
    echo json_encode($data);
}

/**
 * Signing in with a certificate - a smart card, a YubiKey (1.0.100, as otp 1.0.275). Two halves:
 *
 * 1. On 443, POST ?api=cert-nonce (acme_guard_post before it: this page's own JSON, same
 *    origin): a nonce, five minutes, bound by a MAC to the part and to a random value of its
 *    own in an HttpOnly SameSite=Strict __Host- cookie of this browser (the daemon's API token
 *    the MAC's key, which only this pool and the daemon read), used once in the whole cluster
 *    (the daemon keeps it), and the address of the certificate's own port with it. The page goes
 *    there as a top-level navigation: the browser shows its certificate chooser, the card's PIN.
 * 2. On the certificate's port (ACME_CERT_PORT set by nginx - a parameter of nginx's, never a
 *    header of the browser's): the nonce of the address checked against the cookie (login CSRF:
 *    a link of somebody else's signs nobody in), the certificate nginx handed on sent to the
 *    daemon, which decides everything; the session cookie set (cookies are not kept apart by
 *    port: the one set here is the one of 443) and back to 443 - signed in, or ?certsaid=<kind>.
 *    Nothing else is ever served there.
 */
const ACME_CERT_KINDS = ['certificate not accepted' => 'certificate', 'revoked' => 'revoked',
                         'run out' => 'expired', 'not allowed' => 'allowed',
                         'not available just now' => 'unavailable'];

function acme_cert_host(): string
{
    $host = preg_replace('/:\d{1,5}\z/', '', (string) ($_SERVER['HTTP_HOST'] ?? ''));
    return preg_match('/^([A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?|\[[0-9A-Fa-f:.]{2,45}\])\z/', $host) === 1
        ? $host : '';
}

function acme_cert_mac(string $for, string $rand, string $at, string $bind): string
{
    return substr(hash_hmac('sha256', 'acme-cert-nonce|' . $for . '|' . $rand . '|' . $at . '|' . $bind,
                            (string) acme_token()), 0, 32);
}

/** The cookie that binds a nonce to this browser (security review F7): __Host- - set by this
    host alone over https, path /, no Domain (a sibling name or a page over http cannot plant
    one); a random value of its own, never the nonce. One for each part. */
function acme_cert_cookie(string $part): string
{
    return '__Host-acme_certn_' . $part;
}

/** The nonce (POST ?api=cert-nonce on 443), and where the browser goes with it. $info: what the
    daemon says of the part ({on, port}); $try: 'admin' or 'portal' for Try my certificate. */
function acme_cert_nonce(string $part, array $info, string $try = ''): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    $port = (int) ($info['port'] ?? 0);
    if (empty($info['on']) || $port < 1024 || $port > 65535 || $port === 443) {
        http_response_code(404);
        echo json_encode(['ok' => false, 'error' => 'signing in with a certificate is switched off here']);
        return;
    }
    $host = acme_cert_host();
    if ($host === '' || acme_token() === null) {
        http_response_code($host === '' ? 400 : 503);
        echo json_encode(['ok' => false, 'error' => $host === '' ? 'the name this page was opened by cannot be used'
                                                    : 'the server is not answering - try again in a while']);
        return;
    }
    $rand = bin2hex(random_bytes(16));
    $bind = bin2hex(random_bytes(16));
    $at = (string) time();
    $for = $try !== '' ? 'try-' . $try : $part;
    $n = $rand . '.' . $at . '.' . acme_cert_mac($for, $rand, $at, $bind);
    setcookie(acme_cert_cookie($part), $bind, [
        'expires' => time() + 300, 'path' => '/', 'secure' => true,
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    echo json_encode(['ok' => true, 'url' => 'https://' . $host . ':' . $port
        . ($part === 'admin' ? '/admin/' : '/') . '?api=' . ($try !== '' ? 'cert-try' : 'cert-login')
        . '&n=' . $n . ($try !== '' ? '&part=' . $try : '')]);
}

/** Back to 443: signed in, or why not (a kind of ACME_CERT_KINDS, never words of anybody's). */
function acme_cert_back(string $part, string $said = '', string $more = ''): void
{
    $host = acme_cert_host();
    if ($host === '') {
        $host = 'localhost';
    }
    $q = $said !== '' ? '?certsaid=' . rawurlencode($said) : $more;
    header('Location: https://' . $host . ($part === 'admin' ? '/admin/' : '/') . $q, true, 303);
    header('Cache-Control: no-store');
    exit;
}

/** The certificate's port: the whole of what this page does there. */
function acme_cert_port(string $part): void
{
    header('Cache-Control: no-store');
    header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    $said_part = (string) ($_SERVER['ACME_CERT_PART'] ?? '');
    $fail = (string) ($_SERVER['ACME_CERT_FAIL'] ?? '') === '1';
    $what = (string) ($_GET['api'] ?? '');
    if ($said_part !== $part || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
            || (!$fail && !in_array($what, ['cert-login', 'cert-try'], true))
            || ($what === 'cert-try' && $part !== 'admin')) {
        http_response_code(404);
        exit;
    }
    $cookie = acme_cert_cookie($part);
    $c = (string) ($_COOKIE[$cookie] ?? '');
    setcookie($cookie, '', ['expires' => time() - 3600, 'path' => '/', 'secure' => true,
                            'httponly' => true, 'samesite' => 'Strict']);
    $n = (string) ($_GET['n'] ?? '');
    $try = $what === 'cert-try' ? (string) ($_GET['part'] ?? '') : '';
    if ($what === 'cert-try' && !in_array($try, ['admin', 'portal'], true)) {
        acme_cert_back($part, 'certificate');
    }
    $ok = false;
    if (preg_match('/^([0-9a-f]{32})\.([0-9]{10})\.([0-9a-f]{32})\z/', $n, $m) === 1
            && preg_match('/^[0-9a-f]{32}\z/', $c) === 1 && acme_token() !== null) {
        $age = time() - (int) $m[2];
        $ok = $age >= 0 && $age <= 300
            && hash_equals(acme_cert_mac($try !== '' ? 'try-' . $try : $part, $m[1], $m[2], $c), $m[3]);
    }
    if (!$ok) {
        acme_cert_back($part, 'nonce');
    }
    $raw = (string) ($_SERVER['ACME_CERT_PEM'] ?? '');
    /* Once in the whole cluster: the daemon keeps the nonce's random part (review F7). */
    $payload = ['once' => $m[1]];
    if ($fail) {
        $payload['failed'] = substr(preg_replace('/[^\x20-\x7e]/', '', (string) ($_SERVER['ACME_CERT_VERIFY'] ?? '')), 0, 200) ?: 'FAILED';
    } elseif (strlen($raw) > 65536) {
        $payload['cert'] = str_repeat('x', 16385);       /* said so by the daemon, never cut */
    } else {
        $payload['cert'] = rawurldecode($raw);
    }
    if ($try !== '') {
        [$status, $body] = acme_call('/api/certlogin/try', 'POST', $payload + ['part' => $try], 60.0);
        $d = json_decode((string) $body, true);
        if ($status === 200 && is_array($d) && preg_match('/^[0-9a-f]{24}\z/', (string) ($d['id'] ?? '')) === 1) {
            acme_cert_back('admin', '', '?certtried=' . $d['id'] . '#settings/' . ($try === 'admin' ? 'people' : 'portal'));
        }
        acme_cert_back('admin', $status === 401 ? 'signin' : 'unavailable');
    }
    [$status, $body] = acme_call($part === 'admin' ? '/api/auth/cert' : '/api/portal/cert', 'POST', $payload, 60.0);
    $d = json_decode((string) $body, true);
    if ($status === 200 && is_array($d) && !empty($d['token'])) {
        acme_set_session((string) $d['token']);
        acme_cert_back($part);
    }
    $words = is_array($d) ? (string) ($d['error'] ?? '') : '';
    $kind = ACME_CERT_KINDS[preg_replace('/^.*: /', '', $words)] ?? '';
    if ($kind === '') {
        $kind = $status === 429 ? 'wait' : ($status === 404 ? 'off' : 'unavailable');
    }
    acme_cert_back($part, $kind);
}

/**
 * A large answer, compressed for a browser that says it takes gzip.
 *
 * A page of failed attempts with every field in it is a few hundred kilobytes
 * and shrinks to a tenth of that.
 */
function acme_squeeze(string $body): string
{
    $accepts = (string) ($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '');
    if (strlen($body) < 2048 || !function_exists('gzencode') || headers_sent()
        || stripos($accepts, 'gzip') === false || ini_get('zlib.output_compression')) {
        return $body;
    }
    $packed = gzencode($body, 4);
    if ($packed === false) {
        return $body;
    }
    header('Content-Encoding: gzip');
    header('Vary: Accept-Encoding');
    header('Content-Length: ' . strlen($packed));
    return $packed;
}

/** Whoever is signed in, as the daemon sees them, or null. */
function acme_whoami(): ?array
{
    $got = acme_get('/api/auth/whoami', 5.0);
    $who = is_array($got) ? ($got['who'] ?? null) : null;
    if (is_array($who)) {
        $prefs = $who['prefs'] ?? null;
        $who['prefs'] = (is_array($prefs) && $prefs) ? $prefs : new stdClass();
        /* An empty layout is an object, not a list, to the page. */
        $cols = $who['cols'] ?? null;
        $who['cols'] = (is_array($cols) && $cols) ? $cols : new stdClass();
    }
    return $who;
}

/* ==========================================================================
   Files, in both directions
   --------------------------------------------------------------------------
   A copy of the database is not an answer to be held in memory and echoed:
   it is eighty megabytes on a good day and it would be held twice over -
   once as the reply, once as the string being printed. Both of these read a
   lump at a time and pass it straight on, so the memory used is the size of
   the lump however big the file is.
   ========================================================================== */

/** Ask the daemon for a file and hand it straight to the browser.

    Returns the HTTP status. On anything but 200 nothing has been printed and
    the JSON the daemon sent back is returned instead, so the caller can say
    what went wrong. */
function acme_pipe(string $path, string $filename, float $timeout = 600.0): array
{
    $token = acme_token();
    if ($token === null) {
        return [0, ''];
    }
    $headers = ['Accept: application/octet-stream', 'X-Acme-Token: ' . $token];
    $session = acme_session();
    if ($session !== '') {
        $headers[] = 'X-Acme-Session: ' . $session;
    }
    $headers[] = 'X-Acme-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client('tcp://' . ACME_HOST . ':' . ACME_PORT,
                                  $errno, $errstr, 20.0, STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);
    $request = 'GET ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . ACME_HOST . ':' . ACME_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if (@fwrite($sock, $request) === false) {
        @fclose($sock);
        return [0, ''];
    }

    /* The head, a line at a time, so that the body is never pulled into a
       string with it. */
    $head = '';
    while (($line = @fgets($sock, 8192)) !== false) {
        $head .= $line;
        if ($line === "\r\n" || $line === "\n") {
            break;
        }
    }
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', $head, $m)) {
        $status = (int) $m[1];
    }
    if ($status !== 200) {
        $body = '';
        while (!feof($sock)) {
            $lump = @fread($sock, 65536);
            if ($lump === false || $lump === '') {
                break;
            }
            $body .= $lump;
            if (strlen($body) > 1 << 20) {
                break;
            }
        }
        @fclose($sock);
        return [$status, $body];
    }

    $length = null;
    if (preg_match('/^Content-Length:\s*(\d+)/mi', $head, $m)) {
        $length = (int) $m[1];
    }
    $sent = (string) $filename;
    if ($sent === '' && preg_match('/filename="([^"]+)"/i', $head, $m)) {
        $sent = $m[1];
    }
    $sent = preg_replace('/[^A-Za-z0-9@._-]/', '', $sent) ?: 'acme.json.gz';

    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $sent . '"');
    header('Cache-Control: no-store');
    if ($length !== null) {
        header('Content-Length: ' . $length);
    }
    $left = $length ?? PHP_INT_MAX;
    while ($left > 0 && !feof($sock)) {
        $lump = @fread($sock, 262144);
        if ($lump === false || $lump === '') {
            break;
        }
        echo $lump;
        flush();
        $left -= strlen($lump);
    }
    @fclose($sock);
    return [200, ''];
}


/** Send a file on disk to the daemon as the body of a POST, a lump at a
    time, and return what it says. */
function acme_send_file(string $path, string $file, float $timeout = 900.0): array
{
    $token = acme_token();
    if ($token === null) {
        return [0, ''];
    }
    $size = @filesize($file);
    if ($size === false) {
        return [0, ''];
    }
    $in = @fopen($file, 'rb');
    if ($in === false) {
        return [0, ''];
    }
    $headers = ['Accept: application/json',
                'Content-Type: application/octet-stream',
                'Content-Length: ' . $size,
                'X-Acme-Token: ' . $token];
    $session = acme_session();
    if ($session !== '') {
        $headers[] = 'X-Acme-Session: ' . $session;
    }
    $headers[] = 'X-Acme-Client: '
        . preg_replace('/[^0-9a-fA-F:.]/', '', (string) ($_SERVER['REMOTE_ADDR'] ?? ''));

    $errno = 0;
    $errstr = '';
    $sock = @stream_socket_client('tcp://' . ACME_HOST . ':' . ACME_PORT,
                                  $errno, $errstr, 20.0, STREAM_CLIENT_CONNECT);
    if ($sock === false) {
        fclose($in);
        return [0, ''];
    }
    stream_set_timeout($sock, (int) $timeout);
    $head = 'POST ' . $path . " HTTP/1.1\r\n"
        . 'Host: ' . ACME_HOST . ':' . ACME_PORT . "\r\n"
        . "Connection: close\r\n"
        . implode("\r\n", $headers) . "\r\n\r\n";
    if (@fwrite($sock, $head) === false) {
        fclose($in);
        @fclose($sock);
        return [0, ''];
    }
    while (!feof($in)) {
        $lump = fread($in, 262144);
        if ($lump === false || $lump === '') {
            break;
        }
        if (@fwrite($sock, $lump) === false) {
            // The daemon stopped taking it (1.10.198): it says why before it
            // closes - not admin, too big, no room - and that answer is read
            // below rather than reported as a daemon that is not answering.
            break;
        }
    }
    fclose($in);

    $raw = '';
    while (!feof($sock)) {
        $lump = @fread($sock, 65536);
        if ($lump === false || $lump === '') {
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                @fclose($sock);
                return [0, ''];
            }
            break;
        }
        $raw .= $lump;
    }
    @fclose($sock);
    $split = strpos($raw, "\r\n\r\n");
    if ($split === false) {
        return [0, ''];
    }
    $status = 0;
    if (preg_match('#^HTTP/\S+\s+(\d+)#', substr($raw, 0, $split), $m)) {
        $status = (int) $m[1];
    }
    return [$status, substr($raw, $split + 4)];
}

/**
 * The body of a request, written to a temporary file as it arrives (1.10.218):
 * a database being put back, sent as the file itself rather than as a form.
 * Returns [path, ''] or [null, why]. At most $most bytes; never held whole in
 * memory. Read from php://input, which is there whether or not PHP takes
 * request bodies apart itself - and on this page it does not
 * (`enable_post_data_reading = Off` in .user.ini, against php2shell).
 */
function acme_take_body(int $most): array
{
    $told = (int) ($_SERVER['CONTENT_LENGTH'] ?? -1);
    if ($told === 0) {
        return [null, 'no file arrived'];
    }
    if ($told > $most) {
        return [null, 'that file is bigger than this page takes ('
            . round($told / 1048576) . ' MB sent, at most '
            . round($most / 1048576) . ' MB)'];
    }
    $tmp = @tempnam(acme_spool_dir(), 'acme-restore-');
    if ($tmp === false) {
        return [null, 'this web server could not write the file down while it arrived'];
    }
    @chmod($tmp, 0600);
    /* Whatever goes wrong from here, the file goes: the page may be a
       gigabyte in when the connection drops, and nothing else will tidy up. */
    $fail = function (string $why) use ($tmp): array {
        @unlink($tmp);
        return [null, $why];
    };
    $in = @fopen('php://input', 'rb');
    $out = @fopen($tmp, 'wb');
    if ($in === false || $out === false) {
        if ($in !== false) { fclose($in); }
        if ($out !== false) { fclose($out); }
        return $fail('this web server could not write the file down while it arrived');
    }
    $got = 0;
    $broken = false;
    try {
        while (!feof($in)) {
            $lump = fread($in, 1048576);
            if ($lump === false) {
                $broken = true;
                break;
            }
            if ($lump === '') {
                continue;
            }
            $got += strlen($lump);
            if ($got > $most) {
                $broken = true;
                break;
            }
            if (fwrite($out, $lump) !== strlen($lump)) {
                return $fail('this web server could not write the file down while it arrived');
            }
        }
    } catch (\Throwable $e) {
        return $fail('this web server could not write the file down while it arrived');
    } finally {
        fclose($in);
        fclose($out);
    }
    if ($got === 0) {
        return $fail('no file arrived');
    }
    if ($broken || ($told > 0 && $got !== $told)) {
        return $fail($got > $most ? 'that file is bigger than this page takes'
                                  : 'the file did not arrive whole');
    }
    return [$tmp, ''];
}

/** Where a file arriving is written down: a folder of this pool's own under
    the temporary folder (0700, so nothing else on the machine reads a
    database on its way through), or upload_tmp_dir when the pool names one,
    or the temporary folder itself when neither can be had. */
function acme_spool_dir(): string
{
    $named = (string) ini_get('upload_tmp_dir');
    if ($named !== '' && is_dir($named) && is_writable($named)) {
        return $named;
    }
    $base = sys_get_temp_dir();
    $own = $base . '/acme-restore';
    if (!is_dir($own) && !is_link($own)) {
        @mkdir($own, 0700);
    }
    /* Ours, and not a link somebody left there with our name on it. */
    if (is_dir($own) && !is_link($own) && is_writable($own)
            && function_exists('posix_geteuid') && @fileowner($own) === posix_geteuid()) {
        return $own;
    }
    return $base;
}

/**
 * Whether the PHP running this page is safe from php2shell (CVE-2026-109618,
 * CVE-2026-109619), as far as it can tell from inside: its version against
 * the fixed releases of 21 October 2026, and whether this page's own guard -
 * request bodies never taken apart by PHP, no upload progress - is in force.
 * A distribution that backported the fix keeps its old version number, so a
 * version below the fixed ones is "may be affected", not "is".
 */
function acme_php_safety(): array
{
    $fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
    $branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
    if (isset($fixed[$branch])) {
        $patched = version_compare(PHP_VERSION, $fixed[$branch], '>=');
        $needs = $fixed[$branch];
    } else {
        /* Newer than the branches fixed that day is fixed; older is end of
           life, with no fix from PHP itself. */
        $patched = version_compare($branch, '8.5', '>');
        $needs = $patched ? '' : '8.2.35';
    }
    $reading = (string) ini_get('enable_post_data_reading');
    $progress = (string) ini_get('session.upload_progress.enabled');
    $off = function (string $v): bool {
        return in_array(strtolower($v), ['0', '', 'off', 'false', 'no'], true);
    };
    return [
        'version'  => PHP_VERSION,
        'sapi'     => PHP_SAPI,
        'patched'  => $patched,
        'needs'    => $needs,
        'guarded'  => $off($reading) && $off($progress),
        'post_reading' => !$off($reading),
        'upload_progress' => !$off($progress),
    ];
}
