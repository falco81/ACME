<?php
/**
 * acme-art.php — the pictures of the sign-in (1.0.71; each page its own since 1.0.72).
 *
 * Drawn in the page's own colours, so they follow the light and the dark
 * look and need nothing fetched. Which one a page shows is picked in the
 * administration (Settings → The enrolment pages) and kept in the database:
 * the same on both nodes of a cluster. 'custom' is a picture of the site's
 * own, served by ?api=logo; 'none' is no picture at all.
 */
declare(strict_types=1);

const ACME_ARTS = ['phone', 'radius', 'authapp', 'totp', 'acmecode', 'twostep', 'vpn', 'timeline', 'recovery',
                  'clock', 'key', 'qr', 'lock', 'none', 'custom'];

/** What each page shows until something else is picked. */
const ACME_ART_DEFAULT = ['portal' => 'phone', 'admin' => 'radius'];

/** The words under each picture in the administration's choice. */
const ACME_ART_WORDS = [
    'phone' => 'The phone, the check and the way in (as acme came)',
    'radius' => 'RADIUS, the code and Active Directory (as the administration came)',
    'authapp' => 'The authenticator app with its codes',
    'totp' => 'How a code is made: the key and the time (TOTP)',
    'acmecode' => 'The six digits, good for 30 seconds',
    'twostep' => 'The name, the password and the code',
    'vpn' => 'The VPN asking for the code',
    'timeline' => 'The codes in time, a step either side',
    'recovery' => 'Recovery codes when the phone is gone',
    'clock' => 'A new code every 30 seconds',
    'key'   => 'Two keys for one door',
    'qr'    => 'Scan once, a code for every sign-in',
    'lock'  => 'A padlock and the six digits',
    'none'  => 'No picture',
    'custom'=> 'A picture of your own',
];

function acme_art_svg(string $name): string
{
    $glow = '<defs><radialGradient id="sa-glow" cx="50%" cy="42%" r="62%">'
          . '<stop offset="0" stop-color="var(--info)" stop-opacity=".30"/>'
          . '<stop offset="1" stop-color="var(--info)" stop-opacity=".04"/>'
          . '</radialGradient></defs>'
          . '<rect class="plate" x=".75" y=".75" width="418.5" height="186.5" rx="14"/>';
    $shield = '<path class="halo" d="M210 40 l52 18 v38c0 30-21 50-52 60c-31-10-52-30-52-60V58z" fill="var(--info)" opacity=".35"/>'
            . '<path class="shield" d="M210 44 l48 17 v35c0 28-19 46-48 55c-29-9-48-27-48-55V61z"/>';
    switch ($name) {
    case 'phone':
        return '<svg class="signart art-phone" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A code from the phone is the second key</title>' . $glow
            . '<text class="lbl" x="70" y="32" text-anchor="middle">THE PHONE</text>'
            . '<rect x="44" y="44" width="52" height="96" rx="9" fill="none" stroke="var(--tx-mut)" stroke-width="2"/>'
            . '<rect x="51" y="58" width="38" height="64" rx="3" fill="var(--panel2)"/>'
            . '<circle cx="70" cy="131" r="3" fill="var(--tx-mut)"/>'
            . '<text x="70" y="94" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">482 913</text>'
            . '<rect x="55" y="101" width="30" height="3" rx="1.5" fill="var(--info)" opacity=".7"/>'
            . '<path class="flow" d="M112 92 H158"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="210" y="32" text-anchor="middle">CHECKED</text>' . $shield
            . '<rect x="191" y="92" width="38" height="28" rx="5" fill="none" stroke="var(--ok)" stroke-width="3"/>'
            . '<path d="M198 92 v-7a12 12 0 0 1 24 0 v7" fill="none" stroke="var(--ok)" stroke-width="3"/>'
            . '<text class="lbl" x="350" y="32" text-anchor="middle">THE VPN</text>'
            . '<path class="through" d="M264 100 h66 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<rect class="brick" x="336" y="70" width="44" height="60" rx="6"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">PASSWORD · CODE · IN</text>'
            . '</svg>';
    case 'radius':
        return '<svg class="signart art-radius" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title"><title id="sa-title">What this program does</title><rect class="plate" x=".75" y=".75" width="418.5" height="186.5" rx="14"/><g><rect class="logline" x="26" y="42" width="76" height="6" rx="3"/><rect class="logline good" x="26" y="56" width="58" height="6" rx="3"/><rect class="logline" x="26" y="70" width="88" height="6" rx="3"/><rect class="logline bad" x="26" y="84" width="44" height="6" rx="3"/><rect class="logline" x="26" y="98" width="70" height="6" rx="3"/><rect class="logline good" x="26" y="112" width="52" height="6" rx="3"/><rect class="logline" x="26" y="126" width="64" height="6" rx="3"/><rect class="logline good" x="26" y="140" width="38" height="6" rx="3"/></g><text class="lbl" x="26" y="32">RADIUS</text><path class="halo" d="M210 40 l52 18 v38c0 30-21 50-52 60c-31-10-52-30-52-60V58z" fill="var(--info)" opacity=".35"/><path class="shield" d="M210 44 l48 17 v35c0 28-19 46-48 55c-29-9-48-27-48-55V61z"/><rect x="190" y="94" width="40" height="22" rx="5" fill="none" stroke="var(--ok)" stroke-width="3"/><path d="M197 105h3M208 105h4M219 105h4" stroke="var(--ok)" stroke-width="3" stroke-linecap="round"/><text class="lbl" x="210" y="32" text-anchor="middle">THE CODE</text><path class="flow" d="M118 100 H158"/><circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/><g><rect class="brick" x="306" y="46" width="42" height="18" rx="3"/><rect class="brick" x="352" y="46" width="42" height="18" rx="3"/><rect class="brick" x="306" y="68" width="30" height="18" rx="3"/><rect class="brick" x="340" y="68" width="54" height="18" rx="3"/><rect class="brick" x="306" y="90" width="54" height="18" rx="3"/><rect class="brick" x="364" y="90" width="30" height="18" rx="3"/><rect class="brick" x="306" y="112" width="20" height="18" rx="3"/><rect class="brick" x="360" y="112" width="34" height="18" rx="3"/></g><text class="lbl" x="394" y="32" text-anchor="end">ACTIVE DIRECTORY</text><path class="through" d="M264 100 h36 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/><text class="lbl" x="210" y="172" text-anchor="middle">ASKED · CHECKED · LET IN</text></svg>';
    case 'authapp':
        // An authenticator app: three accounts, each with its code and its ring.
        $rows = '';
        foreach ([['VPN · novak@example.cz', '482 913'], ['acme · admin', '730 155'], ['mail · novak', '061 448']] as $i => $r) {
            $y = 56 + $i * 36;
            $rows .= sprintf('<text x="128" y="%d" font-size="8.5" fill="var(--tx-mut)" font-family="var(--face)">%s</text>', $y + 8, $r[0])
                . sprintf('<text x="128" y="%d" font-size="17" font-weight="700" fill="%s" font-family="ui-monospace,Menlo,monospace" letter-spacing="1">%s</text>', $y + 27, $i ? 'var(--tx)' : 'var(--ok)', $r[1])
                . sprintf('<circle cx="290" cy="%d" r="8" fill="none" stroke="var(--line)" stroke-width="3"/>', $y + 19)
                . sprintf('<circle class="ring" cx="290" cy="%d" r="8" fill="none" stroke="var(--info)" stroke-width="3" pathLength="100" stroke-dasharray="100" transform="rotate(-90 290 %d)" style="animation-delay:-%ds"/>', $y + 19, $y + 19, 4 + $i * 9)
                . ($i < 2 ? sprintf('<path d="M122 %d H302" stroke="var(--line)"/>', $y + 34) : '');
        }
        return '<svg class="signart art-authapp" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">An authenticator app with a code for each account</title>' . $glow
            . '<rect x="110" y="20" width="200" height="150" rx="14" fill="var(--panel2)" stroke="var(--line)"/>'
            . '<text class="lbl" x="128" y="40">THE AUTHENTICATOR APP</text>'
            . $rows
            . '<text class="lbl" x="58" y="58" text-anchor="middle">THE KEY</text>'
            . '<circle cx="48" cy="92" r="11" fill="none" stroke="var(--tx-mut)" stroke-width="4"/>'
            . '<path d="M59 92 H86 M78 92 v9 M85 92 v6" stroke="var(--tx-mut)" stroke-width="4" stroke-linecap="round" fill="none"/>'
            . '<text class="lbl" x="58" y="128" text-anchor="middle">STAYS IN IT</text>'
            . '<path class="through" d="M318 92 h28 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<circle cx="374" cy="92" r="18" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M365 92 l6 6 12-13" fill="none" stroke="var(--ok)" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="374" y="128" text-anchor="middle">SIGNED IN</text>'
            . '</svg>';
    case 'totp':
        // How a code is made: the key and the time, through HMAC, to six digits.
        return '<svg class="signart art-totp" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A code is made of the key and the time</title>' . $glow
            . '<text class="lbl" x="66" y="52" text-anchor="middle">THE KEY</text>'
            . '<rect class="brick" x="20" y="62" width="92" height="50" rx="8"/>'
            . '<text x="66" y="92" text-anchor="middle" font-size="11" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">JBSW Y3DP</text>'
            . '<text x="126" y="94" text-anchor="middle" font-size="20" font-weight="700" fill="var(--tx-mut)">+</text>'
            . '<text class="lbl" x="182" y="52" text-anchor="middle">THE TIME</text>'
            . '<rect class="brick" x="140" y="62" width="84" height="50" rx="8"/>'
            . '<circle cx="162" cy="87" r="11" fill="none" stroke="var(--tx-mut)" stroke-width="2.5"/>'
            . '<path d="M162 87 V80 M162 87 L167 90" stroke="var(--tx-mut)" stroke-width="2.5" stroke-linecap="round"/>'
            . '<text x="200" y="91" text-anchor="middle" font-size="11" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">÷ 30 s</text>'
            . '<path class="flow" d="M228 87 H250"/>'
            . '<rect x="252" y="62" width="64" height="50" rx="8" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<text x="284" y="86" text-anchor="middle" font-size="12" font-weight="700" fill="var(--tx)" font-family="var(--face)">HMAC</text>'
            . '<text class="lbl" x="284" y="101" text-anchor="middle">SHA-1</text>'
            . '<path class="through" d="M320 87 h14 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="372" y="52" text-anchor="middle">THE CODE</text>'
            . '<rect class="brick" x="340" y="62" width="64" height="50" rx="8"/>'
            . '<text x="372" y="92" text-anchor="middle" font-size="13" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">482913</text>'
            . '<text class="lbl" x="210" y="148" text-anchor="middle">THE PHONE AND THE SERVER WORK OUT THE SAME CODE</text>'
            . '<text class="lbl" x="210" y="166" text-anchor="middle">TOTP · RFC 6238</text>'
            . '</svg>';
    case 'acmecode':
        // The six digits, large, and the time they are good for running down.
        $boxes = '';
        foreach (['4', '8', '2', '9', '1', '3'] as $i => $d) {
            $x = 50 + $i * 52 + ($i >= 3 ? 8 : 0);
            $boxes .= sprintf('<rect class="brick" x="%d" y="48" width="44" height="60" rx="8"/>'
                . '<text x="%d" y="90" text-anchor="middle" font-size="30" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x, $x + 22, $d);
        }
        return '<svg class="signart art-acmecode" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A one-time password, good for 30 seconds</title>' . $glow
            . '<text class="lbl" x="210" y="34" text-anchor="middle">YOUR ONE-TIME PASSWORD</text>'
            . $boxes
            . '<rect x="50" y="126" width="320" height="6" rx="3" fill="var(--line)"/>'
            . '<rect class="drain" x="50" y="126" width="320" height="6" rx="3" fill="var(--info)"/>'
            . '<text class="lbl" x="210" y="160" text-anchor="middle">GOOD FOR 30 SECONDS · ONCE</text>'
            . '</svg>';
    case 'twostep':
        // A sign-in with three boxes: the name, the password, the code.
        $f = function (int $y, string $text, bool $code): string {
            return sprintf('<rect x="48" y="%d" width="148" height="26" rx="6" fill="var(--bg)" stroke="%s" stroke-width="%s"/>', $y, $code ? 'var(--info)' : 'var(--line)', $code ? '1.8' : '1')
                . sprintf('<text x="58" y="%d" font-size="11" font-weight="%s" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>', $y + 17, $code ? '700' : '400', $code ? 'var(--ok)' : 'var(--tx-mut)', $text);
        };
        return '<svg class="signart art-twostep" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The name, the password and the code from the phone</title>' . $glow
            . '<rect x="30" y="22" width="196" height="144" rx="12" fill="var(--panel2)" stroke="var(--line)"/>'
            . '<text class="lbl" x="48" y="42">SIGN IN</text>'
            . $f(52, 'novak@example.cz', false) . $f(88, '••••••••', false) . $f(124, '482 913', true)
            . '<rect class="caret" x="112" y="129" width="1.6" height="16" fill="var(--info)"/>'
            . '<text class="lbl" x="210" y="69" text-anchor="middle">1</text><text class="lbl" x="210" y="105" text-anchor="middle">2</text><text class="lbl" x="210" y="141" text-anchor="middle">3</text>'
            . '<path class="through" d="M240 94 h44 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<path d="M320 82 v-16a20 20 0 0 1 38 -8" fill="none" stroke="var(--ok)" stroke-width="6" stroke-linecap="round"/>'
            . '<rect x="306" y="80" width="68" height="52" rx="9" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="340" cy="101" r="6" fill="var(--ok)"/><rect x="337.5" y="103" width="5" height="13" rx="2" fill="var(--ok)"/>'
            . '<text class="lbl" x="340" y="158" text-anchor="middle">NAME · PASSWORD · CODE</text>'
            . '</svg>';
    case 'vpn':
        // The VPN client asking for the code, the phone beside it.
        $f = function (int $y, string $k, string $text, bool $code): string {
            return sprintf('<text class="lbl" x="152" y="%d">%s</text>', $y - 4, $k)
                . sprintf('<rect x="152" y="%d" width="200" height="22" rx="5" fill="var(--bg)" stroke="%s" stroke-width="%s"/>', $y, $code ? 'var(--info)' : 'var(--line)', $code ? '1.8' : '1')
                . sprintf('<text x="160" y="%d" font-size="10.5" font-weight="%s" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>', $y + 15, $code ? '700' : '400', $code ? 'var(--ok)' : 'var(--tx-mut)', $text);
        };
        return '<svg class="signart art-vpn" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The VPN asks for the code from the phone</title>' . $glow
            . '<rect x="134" y="18" width="236" height="154" rx="10" fill="var(--panel2)" stroke="var(--line)"/>'
            . '<path d="M134 42 H370" stroke="var(--line)"/>'
            . '<circle cx="148" cy="30" r="3.5" fill="var(--line)"/><circle cx="159" cy="30" r="3.5" fill="var(--line)"/><circle cx="170" cy="30" r="3.5" fill="var(--line)"/>'
            . '<text class="lbl" x="252" y="34" text-anchor="middle">VPN</text>'
            . $f(62, 'NAME', 'novak@example.cz', false) . $f(102, 'PASSWORD', '••••••••', false) . $f(142, 'CODE', '482 913', true)
            . '<rect class="caret" x="206" y="146" width="1.6" height="14" fill="var(--info)"/>'
            . '<rect x="34" y="56" width="50" height="92" rx="9" fill="none" stroke="var(--tx-mut)" stroke-width="2"/>'
            . '<rect x="40" y="68" width="38" height="64" rx="3" fill="var(--panel2)"/>'
            . '<text x="59" y="104" text-anchor="middle" font-size="9" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">482 913</text>'
            . '<circle cx="59" cy="140" r="2.6" fill="var(--tx-mut)"/>'
            . '<path class="flow" d="M90 152 H146"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="59" y="44" text-anchor="middle">THE PHONE</text>'
            . '</svg>';
    case 'timeline':
        // The codes one after another, 30 s each; the server takes a step either side.
        $seg = '';
        foreach ([['104 551', 'old'], ['739 020', 'near'], ['482 913', 'now'], ['650 287', 'near']] as $i => $c) {
            $x = 26 + $i * 94;
            $stroke = $c[1] === 'now' ? 'var(--info)' : ($c[1] === 'near' ? 'var(--ok)' : 'var(--line)');
            $seg .= sprintf('<rect x="%d" y="70" width="86" height="34" rx="7" fill="%s" stroke="%s" stroke-width="%s"%s/>', $x,
                    $c[1] === 'now' ? 'url(#sa-glow)' : 'var(--panel2)', $stroke, $c[1] === 'old' ? '1' : '1.6', $c[1] === 'near' ? ' stroke-dasharray="4 3"' : '')
                . sprintf('<text x="%d" y="92" text-anchor="middle" font-size="13" font-weight="700" fill="%s" font-family="ui-monospace,Menlo,monospace">%s</text>', $x + 43,
                    $c[1] === 'old' ? 'var(--tx-mut)' : ($c[1] === 'now' ? 'var(--ok)' : 'var(--tx)'), $c[0]);
        }
        return '<svg class="signart art-timeline" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A new code every 30 seconds; the server takes one step either side</title>' . $glow
            . '<text class="lbl" x="210" y="40" text-anchor="middle">ONE CODE EVERY 30 SECONDS</text>'
            . $seg
            . '<path d="M26 118 H394" stroke="var(--line)" stroke-width="1.5"/>'
            . '<text class="lbl" x="163" y="134" text-anchor="middle">−30 S</text>'
            . '<text class="lbl" x="257" y="134" text-anchor="middle">NOW</text>'
            . '<text class="lbl" x="351" y="134" text-anchor="middle">+30 S</text>'
            . '<rect class="nowline" x="214" y="62" width="2" height="60" rx="1" fill="var(--info)"/>'
            . '<text class="lbl" x="210" y="166" text-anchor="middle">THE SERVER TAKES ONE STEP EITHER SIDE</text>'
            . '</svg>';
    case 'recovery':
        // The recovery codes: each works once, for when the phone is gone.
        $codes = '';
        foreach (['8301 2297', '5512 9043', '0476 3318', '9920 1157', '3364 8021'] as $i => $c) {
            $y = 66 + $i * 20;
            $used = $i < 2;
            $codes .= sprintf('<text x="210" y="%d" text-anchor="middle" font-size="13" font-weight="700" fill="%s" font-family="ui-monospace,Menlo,monospace"%s>%s</text>', $y,
                    $used ? 'var(--tx-mut)' : 'var(--tx)', $used ? ' opacity=".5"' : '', $c)
                . ($used ? sprintf('<path d="M166 %d H254" stroke="var(--crit)" stroke-width="1.6" opacity=".8"/>', $y - 4) : '');
        }
        return '<svg class="signart art-recovery" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Recovery codes, each works once, for when the phone is gone</title>' . $glow
            . '<text class="lbl" x="62" y="40" text-anchor="middle">NO PHONE?</text>'
            . '<rect x="38" y="52" width="48" height="88" rx="9" fill="none" stroke="var(--tx-mut)" stroke-width="2" opacity=".6"/>'
            . '<path d="M50 80 l24 30 M74 80 l-24 30" stroke="var(--crit)" stroke-width="3" stroke-linecap="round"/>'
            . '<rect x="122" y="22" width="176" height="150" rx="8" fill="var(--panel2)" stroke="var(--line)"/>'
            . '<text class="lbl" x="210" y="42" text-anchor="middle">RECOVERY CODES</text>'
            . $codes
            . '<text class="lbl" x="210" y="164" text-anchor="middle">EACH WORKS ONCE</text>'
            . '<path class="through" d="M306 96 h26 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<circle cx="364" cy="96" r="20" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M354 96 l7 7 13-14" fill="none" stroke="var(--ok)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="364" y="136" text-anchor="middle">STILL IN</text>'
            . '</svg>';
    case 'clock':
        // A ring that runs down in 30 s, and the code it stands for.
        return '<svg class="signart art-clock" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A new code every 30 seconds</title>' . $glow
            . '<text class="lbl" x="210" y="30" text-anchor="middle">A NEW CODE EVERY 30 SECONDS</text>'
            . '<circle cx="110" cy="100" r="46" fill="url(#sa-glow)" stroke="var(--line)" stroke-width="8"/>'
            . '<circle class="ring" cx="110" cy="100" r="46" fill="none" stroke="var(--info)" stroke-width="8" stroke-linecap="round" pathLength="100" stroke-dasharray="100" transform="rotate(-90 110 100)"/>'
            . '<path d="M110 100 V72 M110 100 L128 110" stroke="var(--tx-mut)" stroke-width="3" stroke-linecap="round" fill="none"/>'
            . '<circle cx="110" cy="100" r="4" fill="var(--tx-mut)"/>'
            . '<text x="110" y="166" text-anchor="middle" class="lbl">30 S</text>'
            . (function (): string {
                $o = '';
                foreach (['7', '3', '1', '2', '0', '8'] as $i => $d) {
                    $x = 176 + $i * 36 + ($i >= 3 ? 10 : 0);
                    $o .= sprintf('<rect class="brick" x="%d" y="74" width="30" height="44" rx="6"/>'
                        . '<text class="digit" x="%d" y="104" text-anchor="middle">%s</text>', $x, $x + 15, $d);
                }
                return $o;
            })()
            . '<text class="lbl" x="283" y="146" text-anchor="middle">TYPED AFTER THE PASSWORD</text>'
            . '</svg>';
    case 'key':
        return '<svg class="signart art-key" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The password and the code together open the door</title>' . $glow
            . '<text class="lbl" x="78" y="32" text-anchor="middle">THE PASSWORD</text>'
            . '<circle cx="50" cy="94" r="20" fill="none" stroke="var(--tx-mut)" stroke-width="5"/>'
            . '<circle cx="50" cy="94" r="6" fill="var(--panel2)" stroke="var(--tx-mut)" stroke-width="2"/>'
            . '<path d="M70 94 H122 M106 94 v14 M116 94 v10" stroke="var(--tx-mut)" stroke-width="5" stroke-linecap="round" fill="none"/>'
            . '<text class="lbl" x="78" y="146" text-anchor="middle">WHAT YOU KNOW</text>'
            . '<text x="146" y="102" text-anchor="middle" font-size="22" font-weight="700" fill="var(--tx-mut)">+</text>'
            . '<text class="lbl" x="214" y="32" text-anchor="middle">THE CODE</text>'
            . '<rect x="172" y="70" width="84" height="48" rx="8" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<text x="214" y="101" text-anchor="middle" font-size="16" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">905 116</text>'
            . '<text class="lbl" x="214" y="146" text-anchor="middle">WHAT YOU HAVE</text>'
            . '<path class="through" d="M266 94 h40 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="350" y="32" text-anchor="middle">THE WAY IN</text>'
            . '<rect class="brick" x="320" y="48" width="60" height="96" rx="6"/>'
            . '<path class="door" d="M326 54 h48 v84 h-48z" fill="var(--panel)" stroke="var(--ok)" stroke-width="1.6"/>'
            . '<circle cx="364" cy="98" r="3.5" fill="var(--ok)"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">TWO KEYS FOR ONE DOOR</text>'
            . '</svg>';
    case 'qr':
        $q = '';
        // A made-up QR code: the three corners and a scatter that reads as one.
        $bits = [
            '0011010', '1010011', '0101101', '1100100', '0011011', '1001110', '0110001',
        ];
        foreach ($bits as $y => $row) {
            for ($x = 0; $x < 7; $x++) {
                if ($row[$x] === '1') {
                    $q .= sprintf('<rect x="%d" y="%d" width="7" height="7" fill="var(--tx-mut)"/>', 66 + $x * 8, 74 + $y * 8);
                }
            }
        }
        $eye = function (int $x, int $y): string {
            return sprintf('<rect x="%d" y="%d" width="22" height="22" rx="3" fill="none" stroke="var(--tx-mut)" stroke-width="4"/>'
                . '<rect x="%d" y="%d" width="8" height="8" rx="1" fill="var(--tx-mut)"/>', $x + 2, $y + 2, $x + 9, $y + 9);
        };
        return '<svg class="signart art-qr" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Scan the QR code once; the phone makes a code for every sign-in</title>' . $glow
            . '<text class="lbl" x="92" y="32" text-anchor="middle">SCAN IT ONCE</text>'
            . '<rect x="36" y="42" width="112" height="112" rx="10" fill="var(--panel2)" stroke="var(--line)"/>'
            . $eye(42, 48) . $eye(118, 48) . $eye(42, 124)
            . $q
            . '<rect class="scan" x="40" y="46" width="104" height="3" rx="1.5" fill="var(--info)"/>'
            . '<path class="flow" d="M160 98 H222"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="268" y="32" text-anchor="middle">THE APP</text>'
            . '<rect x="242" y="44" width="52" height="104" rx="9" fill="none" stroke="var(--tx-mut)" stroke-width="2"/>'
            . '<rect x="249" y="58" width="38" height="72" rx="3" fill="var(--panel2)"/>'
            . '<circle cx="268" cy="139" r="3" fill="var(--tx-mut)"/>'
            . '<text x="268" y="98" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">318 457</text>'
            . '<rect x="253" y="105" width="30" height="3" rx="1.5" fill="var(--info)" opacity=".7"/>'
            . '<path class="through" d="M306 98 h30 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<circle cx="364" cy="98" r="20" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M354 98 l7 7 13-14" fill="none" stroke="var(--ok)" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="210" y="174" text-anchor="middle">A CODE FOR EVERY SIGN-IN</text>'
            . '</svg>';
    case 'lock':
        $boxes = '';
        $digits = ['4', '0', '7', '2', '6', '9'];
        foreach ($digits as $i => $d) {
            $x = 96 + $i * 40 + ($i >= 3 ? 12 : 0);
            $boxes .= sprintf('<rect class="brick" x="%d" y="122" width="32" height="38" rx="6"/>'
                . '<text class="digit d%d" x="%d" y="148" text-anchor="middle">%s</text>', $x, $i, $x + 16, $d);
        }
        return '<svg class="signart art-lock" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Six digits from the phone open the lock</title>' . $glow
            . '<path class="halo" d="M210 22 a44 44 0 1 1 -0.1 0z" fill="var(--info)" opacity=".25"/>'
            . '<path d="M188 66 v-14a22 22 0 0 1 44 0 v14" fill="none" stroke="var(--ok)" stroke-width="6" stroke-linecap="round"/>'
            . '<rect x="176" y="64" width="68" height="46" rx="9" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="210" cy="83" r="6" fill="var(--ok)"/><rect x="207.5" y="85" width="5" height="12" rx="2" fill="var(--ok)"/>'
            . '<text class="lbl" x="40" y="32">SIGN IN</text>'
            . '<text class="lbl" x="380" y="32" text-anchor="end">WITH A CODE</text>'
            . $boxes
            . '</svg>';
    }
    return '';
}

/**
 * The picture for a sign-in page (1.0.72: each page its own): $art as
 * /api/portal/info gives it - 'art' for the enrolment pages, 'admin_art'
 * for the administration - and $slot which of the two.
 */
function acme_art_for(?array $art, string $slot, string $title): string
{
    $slot = $slot === 'admin' ? 'admin' : 'portal';
    $art = is_array($art) ? $art : [];
    $name = in_array($art['art'] ?? '', ACME_ARTS, true) ? $art['art'] : ACME_ART_DEFAULT[$slot];
    if ($name === 'none') {
        return '';
    }
    if ($name === 'custom') {
        $sha = preg_replace('/[^0-9a-f]/', '', (string) ($art['sha'] ?? ''));
        if ($sha === '') {
            return acme_art_svg(ACME_ART_DEFAULT[$slot]);
        }
        return '<div class="signlogo"><img src="' . ($slot === 'admin' ? '/admin/' : '/')
            . '?api=logo&amp;slot=' . $slot . '&amp;v=' . $sha . '" alt="' . h($title) . '" data-no-i18n></div>';
    }
    return acme_art_svg($name);
}

/** ?api=logo: the site's own picture, as a picture, run as nothing. */
function acme_serve_logo(): void
{
    $slot = ($_GET['slot'] ?? '') === 'admin' ? 'admin' : 'portal';
    [$status, $body] = acme_call('/api/portal/logo?slot=' . $slot, 'GET', null, 10.0);
    $data = $status === 200 ? json_decode((string) $body, true) : null;
    $logo = is_array($data) ? ($data['logo'] ?? null) : null;
    $kinds = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml'];
    if (!is_array($logo) || !in_array($logo['type'] ?? '', $kinds, true)) {
        http_response_code(404);
        header('Cache-Control: no-store');
        exit;
    }
    $raw = base64_decode((string) ($logo['b64'] ?? ''), true);
    if ($raw === false) {
        http_response_code(404);
        exit;
    }
    $etag = '"' . preg_replace('/[^0-9a-f]/', '', (string) ($logo['sha'] ?? '')) . '"';
    header_remove('Pragma');
    header_remove('Expires');
    header('Content-Type: ' . $logo['type']);
    header('X-Content-Type-Options: nosniff');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; sandbox");
    header('Content-Disposition: inline; filename="logo"');
    header('ETag: ' . $etag);
    // The address carries which picture (?v=), so it may be kept a while.
    header('Cache-Control: public, max-age=' . (isset($_GET['v']) ? '86400' : '60'));
    if (trim((string) ($_SERVER['HTTP_IF_NONE_MATCH'] ?? '')) === $etag) {
        http_response_code(304);
        exit;
    }
    header('Content-Length: ' . strlen($raw));
    echo $raw;
    exit;
}
