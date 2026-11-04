<?php
/**
 * acme-art.php — the pictures of the sign-in (1.0.71; each page its own since 1.0.72).
 *
 * Drawn in the page's own colours, so they follow the light and the dark
 * look and need nothing fetched. Which one a page shows is picked in the
 * administration (Settings → The portal) and kept in the database:
 * the same on both nodes of a cluster. 'custom' is a picture of the site's
 * own, served by ?api=logo; 'none' is no picture at all.
 */
declare(strict_types=1);

const ACME_ARTS = ['cert', 'chain', 'renew', 'deploy', 'order', 'dns', 'keys', 'watch', 'revoke',
                   'cycle', 'ask', 'get', 'mine', 'code', 'team', 'overview', 'cluster', 'sources',
                   'jobs', 'alerts', 'none', 'custom'];

/** The pictures of one sign-in only (1.0.41): the people who ask for certificates see
 *  their own side of it, the administrators theirs. Any other picture is for both. */
const ACME_ART_ONLY = ['ask' => 'portal', 'get' => 'portal', 'mine' => 'portal', 'code' => 'portal',
                       'team' => 'portal', 'overview' => 'admin', 'cluster' => 'admin',
                       'sources' => 'admin', 'jobs' => 'admin', 'alerts' => 'admin'];

/** What each page shows until something else is picked. */
const ACME_ART_DEFAULT = ['portal' => 'cert', 'admin' => 'deploy'];

/** The words under each picture in the administration's choice. */
const ACME_ART_WORDS = [
    'cert'   => 'A certificate, kept and renewed by itself (as the portal came)',
    'chain'  => 'The chain of trust: the root, the intermediate, your name',
    'renew'  => 'Renewed well before it runs out',
    'deploy' => 'One certificate, put in place everywhere (as the administration came)',
    'order'  => 'An ACME order, step by step: ordered, proved, issued',
    'dns'    => 'The name proved in the DNS, no port opened',
    'keys'   => 'The key, the request, the signature: the key never leaves',
    'watch'  => 'What the servers serve, looked at again and again',
    'revoke' => 'Revoked and replaced: a new key, put in place',
    'cycle'  => 'The next one long before the last runs out: never a gap',
    'ask'      => 'Asked for on the pages, approved, issued to you',
    'get'      => 'Your certificate, downloaded as your server takes it',
    'mine'     => 'Your certificates, and how long each one has',
    'code'     => 'Your password, then a code by mail or SMS',
    'team'     => 'Your team\'s certificates, seen by the whole team',
    'overview' => 'Everything at a glance, all of it well',
    'cluster'  => 'Two nodes, one address, one database',
    'sources'  => 'Every authority, into one place',
    'jobs'     => 'The jobs, by themselves and on time',
    'alerts'   => 'Every change written down, every failure told',
    'none'   => 'No picture',
    'custom' => 'A picture of your own',
];

function acme_art_svg(string $name): string
{
    $glow = '<defs><radialGradient id="sa-glow" cx="50%" cy="42%" r="62%">'
          . '<stop offset="0" stop-color="var(--info)" stop-opacity=".30"/>'
          . '<stop offset="1" stop-color="var(--info)" stop-opacity=".04"/>'
          . '</radialGradient></defs>'
          . '<rect class="plate" x=".75" y=".75" width="418.5" height="186.5" rx="14"/>';
    $dots = '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>';
    $shield = '<path class="halo" d="M210 40 l52 18 v38c0 30-21 50-52 60c-31-10-52-30-52-60V58z" fill="var(--info)" opacity=".35"/>'
            . '<path class="shield" d="M210 44 l48 17 v35c0 28-19 46-48 55c-29-9-48-27-48-55V61z"/>';
    switch ($name) {
    case 'cert':
        // A certificate with its seal, and the arrow that renews it.
        return '<svg class="signart art-cert" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">A certificate, kept and renewed by itself</title>' . $glow
            . '<text class="lbl" x="130" y="30" text-anchor="middle">THE CERTIFICATE</text>'
            . '<rect class="brick" x="60" y="40" width="140" height="112" rx="8"/>'
            . '<rect class="logline" x="76" y="56" width="92" height="6" rx="3"/>'
            . '<rect class="logline good" x="76" y="72" width="70" height="6" rx="3"/>'
            . '<rect class="logline" x="76" y="88" width="104" height="6" rx="3"/>'
            . '<rect class="logline" x="76" y="104" width="58" height="6" rx="3"/>'
            . '<path class="halo" d="M172 112 a20 20 0 1 1 -0.1 0z" fill="var(--info)" opacity=".3"/>'
            . '<circle cx="172" cy="132" r="15" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2.2"/>'
            . '<path d="M165 132 l5 5 9-10" fill="none" stroke="var(--ok)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="310" y="30" text-anchor="middle">RENEWED BY ITSELF</text>'
            . '<path class="through" d="M352 96 a42 42 0 1 1 -12 -30" stroke-width="5" stroke-linecap="round"/>'
            . '<path d="M330 54 l12 12 -16 4" fill="none" stroke="var(--ok)" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text x="310" y="102" text-anchor="middle" font-size="15" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">90 d</text>'
            . '<text class="lbl" x="210" y="174" text-anchor="middle">KEPT · RENEWED · PUT IN PLACE</text>'
            . '</svg>';
    case 'chain':
        // The chain of trust, from the root to the name.
        $box = function (int $x, string $top, string $name, string $tone): string {
            return sprintf('<rect class="brick" x="%d" y="62" width="104" height="62" rx="8" stroke="var(--%s)" stroke-width="1.6"/>', $x, $tone)
                . sprintf('<text class="lbl" x="%d" y="52" text-anchor="middle">%s</text>', $x + 52, $top)
                . sprintf('<text x="%d" y="98" text-anchor="middle" font-size="11" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x + 52, $tone, $name);
        };
        return '<svg class="signart art-chain" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The chain of trust: the root, the intermediate, your name</title>' . $glow
            . $box(18, 'THE ROOT', 'Root CA', 'info')
            . '<path class="through" d="M126 93 h22 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . $box(158, 'INTERMEDIATE', 'Issuing CA', 'info')
            . '<path class="through" d="M266 93 h22 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . $box(298, 'YOUR NAME', 'www.example.cz', 'ok')
            . '<text class="lbl" x="210" y="160" text-anchor="middle">EACH ONE SIGNED BY THE ONE BEFORE</text>'
            . '</svg>';
    case 'renew':
        // The life of a certificate: in use, renewed in time, never run out.
        return '<svg class="signart art-renew" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Renewed well before it runs out</title>' . $glow
            . '<text class="lbl" x="40" y="58">ISSUED</text>'
            . '<text class="lbl" x="380" y="58" text-anchor="end">IT WOULD RUN OUT</text>'
            . '<rect x="40" y="70" width="230" height="14" rx="7" fill="var(--ok)" opacity=".8"/>'
            . '<rect x="270" y="70" width="80" height="14" fill="var(--warn)" opacity=".8"/>'
            . '<rect x="350" y="70" width="30" height="14" rx="7" fill="var(--crit)" opacity=".85"/>'
            . '<path d="M290 64 v26" stroke="var(--info)" stroke-width="2.4"/>'
            . '<path class="halo" d="M290 98 a12 12 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="290" cy="110" r="10" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="2"/>'
            . '<path d="M285 110 l4 4 7-8" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="290" y="140" text-anchor="middle">RENEWED HERE</text>'
            . '<path class="flow" d="M118 100 H180"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="150" y="122" text-anchor="middle">IN USE</text>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">NOTHING RUNS OUT UNSEEN</text>'
            . '</svg>';
    case 'deploy':
        // One certificate, put in place on every machine that serves it.
        $target = function (int $y, string $name): string {
            return sprintf('<rect class="brick" x="300" y="%d" width="96" height="30" rx="6"/>', $y)
                . sprintf('<text x="348" y="%d" text-anchor="middle" font-size="10.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">%s</text>', $y + 19, $name)
                . sprintf('<path class="through" d="M232 100 C262 100 266 %d 294 %d m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>', $y + 15, $y + 15);
        };
        return '<svg class="signart art-deploy" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">One certificate, put in place everywhere</title>' . $glow
            . '<text class="lbl" x="66" y="32" text-anchor="middle">THE CERTIFICATE</text>'
            . '<rect class="brick" x="30" y="58" width="72" height="84" rx="7"/>'
            . '<rect class="logline" x="42" y="72" width="48" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="42" y="84" width="36" height="5" rx="2.5"/>'
            . '<rect class="logline" x="42" y="96" width="44" height="5" rx="2.5"/>'
            . '<circle cx="80" cy="124" r="9" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path class="flow" d="M118 100 H180"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="206" y="32" text-anchor="middle">ACME</text>'
            . '<circle cx="206" cy="100" r="22" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<path d="M196 100 l7 7 13-14" fill="none" stroke="var(--ok)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="348" y="32" text-anchor="middle">THE TARGETS</text>'
            . $target(44, 'linux') . $target(85, 'F5') . $target(126, 'FortiGate')
            . '<text class="lbl" x="210" y="176" text-anchor="middle">RENEWED · PUT IN PLACE · CHECKED</text>'
            . '</svg>';
    case 'order':
        // An ACME order, step by step: ordered, the challenge, proved, issued.
        $step = function (int $x, string $top, string $under, string $inner, bool $last): string {
            return sprintf('<text class="lbl" x="%d" y="56" text-anchor="middle">%s</text>', $x, $top)
                . ($last ? sprintf('<path class="halo" d="M%d 72 a24 24 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>', $x) : '')
                . sprintf('<circle cx="%d" cy="96" r="20" fill="%s" stroke="var(--%s)" stroke-width="1.8"/>', $x,
                          $last ? 'url(#sa-glow)' : 'var(--panel2)', $last ? 'ok' : 'info')
                . $inner
                . sprintf('<text data-no-i18n x="%d" y="136" text-anchor="middle" font-size="10" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x, $last ? 'ok' : 'info', $under);
        };
        $num = function (int $x, string $n): string {
            return sprintf('<text x="%d" y="101" text-anchor="middle" font-size="14" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x, $n);
        };
        return '<svg class="signart art-order" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">An ACME order, step by step: ordered, proved, issued</title>' . $glow
            . '<path class="flow" d="M82 96 H338"/>'
            . '<path class="through" d="M82 96 H138 M182 96 H238" stroke-linecap="round"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . $step(60, 'ORDERED', 'new-order', $num(60, '1'), false)
            . $step(160, 'THE CHALLENGE', 'dns-01', $num(160, '2'), false)
            . $step(260, 'PROVED', 'valid', '<path d="M251 96 l6 6 11-12" fill="none" stroke="var(--ok)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>', false)
            . $step(360, 'ISSUED', 'cert.pem', '<rect x="351" y="86" width="18" height="20" rx="2.5" fill="none" stroke="var(--ok)" stroke-width="1.8"/><path d="M355 92 h10 M355 97 h7" stroke="var(--ok)" stroke-width="1.6" stroke-linecap="round"/>', true)
            . '<text class="lbl" x="210" y="172" text-anchor="middle">ORDERED · PROVED · ISSUED - BY ITSELF</text>'
            . '</svg>';
    case 'dns':
        // The name proved in the DNS: the record put in, the authority looks it up.
        return '<svg class="signart art-dns" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The name proved in the DNS, no port opened</title>' . $glow
            . '<text class="lbl" x="122" y="40" text-anchor="middle">THE ZONE</text>'
            . '<rect class="brick" x="24" y="50" width="196" height="92" rx="8"/>'
            . '<rect class="logline" x="40" y="64" width="120" height="5" rx="2.5"/>'
            . '<text data-no-i18n x="40" y="90" font-size="10.5" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">_acme-challenge</text>'
            . '<text data-no-i18n x="40" y="108" font-size="10.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">TXT "gT9q…4kQ"</text>'
            . '<rect class="caret" x="146" y="99" width="6" height="11" fill="var(--ok)" opacity=".8"/>'
            . '<rect class="logline" x="40" y="122" width="88" height="5" rx="2.5"/>'
            . '<path class="flow" d="M232 96 H296"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<text class="lbl" x="264" y="84" text-anchor="middle">LOOKED UP</text>'
            . '<text class="lbl" x="340" y="40" text-anchor="middle">THE AUTHORITY</text>'
            . '<path class="halo" d="M340 66 a30 30 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="340" cy="96" r="26" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="335" cy="91" r="9" fill="none" stroke="var(--info)" stroke-width="2.2"/>'
            . '<path d="M341.5 97.5 l8 8" stroke="var(--info)" stroke-width="2.6" stroke-linecap="round"/>'
            . '<circle cx="360" cy="118" r="9" fill="var(--panel2)" stroke="var(--ok)" stroke-width="1.8"/>'
            . '<path d="M356 118 l3 3 5-6" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">THE NAME PROVED · NO PORT OPENED</text>'
            . '</svg>';
    case 'keys':
        // The key made here, the request out of it, the signature back: the key stays.
        $arrow = function (int $x): string {
            return sprintf('<path class="through" d="M%d 96 h20 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>', $x);
        };
        return '<svg class="signart art-keys" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The key, the request, the signature: the key never leaves</title>' . $glow
            . '<text class="lbl" x="62" y="50" text-anchor="middle">THE KEY</text>'
            . '<rect class="brick" x="26" y="62" width="72" height="68" rx="8"/>'
            . '<circle cx="46" cy="96" r="10" fill="none" stroke="var(--warn)" stroke-width="2.4"/>'
            . '<path d="M56 96 h28 M78 96 v7 M71 96 v5" stroke="var(--warn)" stroke-width="2.4" stroke-linecap="round"/>'
            . $arrow(106)
            . '<text class="lbl" x="166" y="50" text-anchor="middle">THE REQUEST</text>'
            . '<rect class="brick" x="136" y="62" width="60" height="68" rx="7"/>'
            . '<text x="166" y="84" text-anchor="middle" font-size="11" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">CSR</text>'
            . '<rect class="logline" x="148" y="94" width="36" height="5" rx="2.5"/>'
            . '<rect class="logline" x="148" y="104" width="28" height="5" rx="2.5"/>'
            . '<rect class="logline" x="148" y="114" width="32" height="5" rx="2.5"/>'
            . $arrow(204)
            . '<text class="lbl" x="258" y="50" text-anchor="middle">SIGNED</text>'
            . '<path class="halo" d="M258 72 a24 24 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="258" cy="96" r="20" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<path d="M249 96 l6 6 11-12" fill="none" stroke="var(--ok)" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>'
            . $arrow(286)
            . '<text class="lbl" x="354" y="50" text-anchor="middle">THE CERTIFICATE</text>'
            . '<rect class="brick" x="316" y="62" width="76" height="68" rx="7"/>'
            . '<rect class="logline" x="328" y="74" width="44" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="328" y="86" width="32" height="5" rx="2.5"/>'
            . '<rect class="logline" x="328" y="98" width="40" height="5" rx="2.5"/>'
            . '<circle cx="374" cy="115" r="8" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<text x="62" y="148" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--warn)" font-family="ui-monospace,Menlo,monospace">stays here</text>'
            . '<text class="lbl" x="210" y="174" text-anchor="middle">THE PRIVATE KEY NEVER LEAVES THE SERVER</text>'
            . '</svg>';
    case 'watch':
        // What the servers serve, asked over TLS and looked at: the name, the chain, the days.
        $row = function (int $y, string $words, string $tone): string {
            return sprintf('<circle cx="272" cy="%.1f" r="5.5" fill="none" stroke="var(--%s)" stroke-width="1.6"/>', $y - 3.5, $tone)
                . sprintf('<path d="M269.5 %.1f l2 2 3.5-4" fill="none" stroke="var(--%s)" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>', $y - 3.5, $tone)
                . sprintf('<text x="284" y="%d" font-size="10.5" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $y, $tone, $words);
        };
        return '<svg class="signart art-watch" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">What the servers serve, looked at again and again</title>' . $glow
            . '<text class="lbl" x="84" y="40" text-anchor="middle">THE SERVER :443</text>'
            . '<rect class="brick" x="30" y="50" width="108" height="92" rx="8"/>'
            . '<rect class="logline" x="44" y="64" width="80" height="5" rx="2.5"/>'
            . '<rect class="logline" x="44" y="76" width="60" height="5" rx="2.5"/>'
            . '<rect x="72" y="106" width="24" height="20" rx="3.5" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="1.8"/>'
            . '<path d="M77 106 v-6 a7 7 0 0 1 14 0 v6" fill="none" stroke="var(--ok)" stroke-width="1.8"/>'
            . '<path class="flow" d="M146 84 H240"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<path class="through" d="M240 110 H152 m7-6 l-7 6 7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="193" y="74" text-anchor="middle">ASKED OVER TLS</text>'
            . '<text class="lbl" x="196" y="130" text-anchor="middle">WHAT IT SERVES</text>'
            . '<text class="lbl" x="324" y="40" text-anchor="middle">THE CHECK</text>'
            . '<rect class="brick" x="254" y="50" width="140" height="92" rx="8"/>'
            . $row(78, 'the name', 'ok') . $row(100, 'the chain', 'ok') . $row(122, '63 d left', 'ok')
            . '<text class="lbl" x="210" y="172" text-anchor="middle">SERVED · LOOKED AT · TOLD WHEN WRONG</text>'
            . '</svg>';
    case 'revoke':
        // A key gone astray: the certificate revoked, a new one with a new key put in its place.
        return '<svg class="signart art-revoke" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Revoked and replaced: a new key, put in place</title>' . $glow
            . '<text class="lbl" x="96" y="40" text-anchor="middle">THE OLD ONE</text>'
            . '<rect class="brick" x="44" y="50" width="104" height="88" rx="8" opacity=".75"/>'
            . '<rect class="logline" x="58" y="64" width="64" height="5" rx="2.5"/>'
            . '<rect class="logline bad" x="58" y="76" width="48" height="5" rx="2.5"/>'
            . '<rect class="logline" x="58" y="88" width="70" height="5" rx="2.5"/>'
            . '<circle cx="124" cy="116" r="11" fill="var(--panel2)" stroke="var(--crit)" stroke-width="2"/>'
            . '<path d="M119.5 111.5 l9 9 m0 -9 l-9 9" stroke="var(--crit)" stroke-width="2.2" stroke-linecap="round"/>'
            . '<text x="96" y="156" text-anchor="middle" font-size="10" font-weight="700" fill="var(--crit)" font-family="ui-monospace,Menlo,monospace">revoked</text>'
            . '<path class="flow" d="M162 94 H252"/>'
            . '<circle class="spark dot" r="2.6" cx="0" cy="0"/><circle class="spark dot dot2" r="2.6" cx="0" cy="0"/><circle class="spark dot dot3" r="2.6" cx="0" cy="0"/>'
            . '<path class="through" d="M246 88 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="207" y="82" text-anchor="middle">A NEW KEY</text>'
            . '<text class="lbl" x="318" y="40" text-anchor="middle">THE NEW ONE</text>'
            . '<rect class="brick" x="266" y="50" width="104" height="88" rx="8" stroke="var(--ok)" stroke-width="1.6"/>'
            . '<rect class="logline" x="280" y="64" width="64" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="280" y="76" width="48" height="5" rx="2.5"/>'
            . '<rect class="logline" x="280" y="88" width="70" height="5" rx="2.5"/>'
            . '<path class="halo" d="M346 102 a14 14 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="346" cy="116" r="11" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M341 116 l4 4 7-8" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text x="318" y="156" text-anchor="middle" font-size="10" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">in place</text>'
            . '<text class="lbl" x="210" y="178" text-anchor="middle">REVOKED · REPLACED · PUT IN PLACE</text>'
            . '</svg>';
    case 'cycle':
        // One after another: each new one there long before the last runs out.
        $life = function (int $x, int $y, string $name): string {
            return sprintf('<rect x="%d" y="%d" width="124" height="12" rx="6" fill="var(--ok)" opacity=".8"/>', $x, $y)
                . sprintf('<rect x="%d" y="%d" width="30" height="12" rx="6" fill="var(--warn)" opacity=".7"/>', $x + 120, $y)
                . sprintf('<rect x="%d" y="%d" width="8" height="12" fill="var(--ok)" opacity=".8"/>', $x + 116, $y)
                . sprintf('<text class="lbl" x="%d" y="%d">%s</text>', $x + 10, $y - 6, $name);
        };
        $renew = function (int $x, int $y): string {
            return sprintf('<path d="M%d %d v18" stroke="var(--info)" stroke-width="1.6" stroke-dasharray="2 3"/>', $x, $y + 12)
                . sprintf('<circle cx="%d" cy="%d" r="3.5" fill="var(--info)"/>', $x, $y + 6);
        };
        return '<svg class="signart art-cycle" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The next one long before the last runs out: never a gap</title>' . $glow
            . $life(30, 58, 'NO. 1') . $life(135, 88, 'NO. 2') . $life(240, 118, 'NO. 3')
            . $renew(135, 58) . $renew(240, 88)
            . '<text class="lbl" x="390" y="34" text-anchor="end">THE NEXT ONE BEFORE THE LAST RUNS OUT</text>'
            . '<path class="flow" d="M30 150 H390"/>'
            . '<text class="lbl" x="210" y="176" text-anchor="middle">ALWAYS A GOOD ONE · NEVER A GAP</text>'
            . '</svg>';
    /* ---- the enrolment pages' own (1.0.41): what the people who ask for certificates see ---- */
    case 'ask':
        // Asked for on the pages, approved by the team, issued to you.
        return '<svg class="signart art-ask" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Asked for on the pages, approved, issued to you</title>' . $glow
            . '<text class="lbl" x="92" y="36" text-anchor="middle">YOUR REQUEST</text>'
            . '<rect class="brick" x="24" y="46" width="136" height="98" rx="8"/>'
            . '<rect x="36" y="58" width="112" height="20" rx="4" fill="none" stroke="var(--info)" stroke-width="1.2"/>'
            . '<text data-no-i18n x="44" y="72" font-size="10" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">www.example.cz</text>'
            . '<rect x="36" y="84" width="112" height="20" rx="4" fill="none" stroke="var(--line)" stroke-width="1.2"/>'
            . '<text data-no-i18n x="44" y="98" font-size="10" font-weight="700" fill="var(--tx-mut)" font-family="ui-monospace,Menlo,monospace">+ api.example.cz</text>'
            . '<rect x="36" y="114" width="70" height="20" rx="5" fill="var(--info)" opacity=".9"/>'
            . '<text x="71" y="128" text-anchor="middle" font-size="10" font-weight="700" fill="#fff">Ask for it</text>'
            . '<path class="flow" d="M168 94 H222"/>' . $dots
            . '<text class="lbl" x="262" y="36" text-anchor="middle">APPROVED</text>'
            . '<path class="halo" d="M262 70 a24 24 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="262" cy="94" r="22" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="262" cy="87" r="6" fill="none" stroke="var(--info)" stroke-width="2"/>'
            . '<path d="M251 106 a11 9 0 0 1 22 0" fill="none" stroke="var(--info)" stroke-width="2" stroke-linecap="round"/>'
            . '<circle cx="279" cy="112" r="8" fill="var(--panel2)" stroke="var(--ok)" stroke-width="1.8"/>'
            . '<path d="M275.5 112 l2.5 2.5 4.5-5" fill="none" stroke="var(--ok)" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<path class="through" d="M294 94 h20 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="360" y="36" text-anchor="middle">YOURS</text>'
            . '<rect class="brick" x="322" y="50" width="76" height="88" rx="7" stroke="var(--ok)" stroke-width="1.4"/>'
            . '<rect class="logline" x="334" y="64" width="44" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="334" y="76" width="32" height="5" rx="2.5"/>'
            . '<rect class="logline" x="334" y="88" width="40" height="5" rx="2.5"/>'
            . '<circle cx="378" cy="118" r="9" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M374 118 l3 3 5-6" fill="none" stroke="var(--ok)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">ASKED · APPROVED · ISSUED TO YOU</text>'
            . '</svg>';
    case 'get':
        // Your certificate, downloaded in the form your server takes.
        $form = function (int $c, string $file, string $tone): string {
            return sprintf('<path class="through" d="M142 96 C192 96 202 %d 246 %d m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>', $c, $c)
                . sprintf('<rect class="brick" x="254" y="%d" width="142" height="28" rx="6"/>', $c - 14)
                . sprintf('<path d="M270 %d v9 m-4 -4 l4 4 4-4 M265 %d h10" fill="none" stroke="var(--%s)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>', $c - 7, $c + 7, $tone)
                . sprintf('<text data-no-i18n x="286" y="%d" font-size="10.5" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $c + 4, $tone, $file);
        };
        return '<svg class="signart art-get" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Your certificate, downloaded as your server takes it</title>' . $glow
            . '<text class="lbl" x="88" y="34" text-anchor="middle">YOUR CERTIFICATE</text>'
            . '<rect class="brick" x="44" y="46" width="90" height="98" rx="8"/>'
            . '<rect class="logline" x="58" y="60" width="54" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="58" y="72" width="40" height="5" rx="2.5"/>'
            . '<rect class="logline" x="58" y="84" width="50" height="5" rx="2.5"/>'
            . '<path class="halo" d="M112 110 a14 14 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="112" cy="124" r="11" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M107 124 l4 4 7-8" fill="none" stroke="var(--ok)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="325" y="34" text-anchor="middle">AS YOU NEED IT</text>'
            . $form(58, 'cert.pem', 'ok') . $form(98, 'cert.pfx', 'info') . $form(138, 'chain.pem', 'ok')
            . '<text class="lbl" x="210" y="172" text-anchor="middle">PEM · PFX · THE CHAIN - DOWNLOADED BY YOU</text>'
            . '</svg>';
    case 'mine':
        // Your certificates, and how long each one has.
        $row = function (int $y, string $name, float $part, string $tone, string $days, bool $plain): string {
            return sprintf('<rect class="brick" x="24" y="%d" width="270" height="30" rx="6"/>', $y)
                . sprintf('<text data-no-i18n x="36" y="%d" font-size="10" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">%s</text>', $y + 19, $name)
                . sprintf('<rect x="150" y="%d" width="76" height="6" rx="3" fill="var(--line)"/>', $y + 12)
                . sprintf('<rect x="150" y="%d" width="%.1f" height="6" rx="3" fill="var(--%s)" opacity=".85"/>', $y + 12, 76 * $part, $tone)
                . sprintf('<text%s x="284" y="%d" text-anchor="end" font-size="10" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $plain ? ' data-no-i18n' : '', $y + 19, $tone, $days);
        };
        return '<svg class="signart art-mine" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Your certificates, and how long each one has</title>' . $glow
            . '<text class="lbl" x="24" y="34">YOUR CERTIFICATES</text>'
            . $row(44, 'www.example.cz', .72, 'ok', '63 d', true)
            . $row(82, 'api.example.cz', .24, 'warn', '21 d', true)
            . $row(120, 'vpn.example.cz', 1, 'info', 'renewed', false)
            . '<text class="lbl" x="352" y="60" text-anchor="middle">TOLD IN TIME</text>'
            . '<path class="flow" d="M298 97 H316"/>'
            . '<rect x="320" y="76" width="64" height="42" rx="6" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<path d="M322 79 L352 100 L382 79" fill="none" stroke="var(--info)" stroke-width="1.8" stroke-linejoin="round"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">THE DAYS OF EACH · A MAIL BEFORE IT RUNS OUT</text>'
            . '</svg>';
    case 'code':
        // The directory password, then a code by mail or SMS: at every sign-in.
        return '<svg class="signart art-code" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Your password, then a code by mail or SMS</title>' . $glow
            . '<text class="lbl" x="78" y="38" text-anchor="middle">YOUR PASSWORD</text>'
            . '<rect class="brick" x="22" y="48" width="112" height="94" rx="8"/>'
            . '<rect x="34" y="60" width="88" height="22" rx="4" fill="none" stroke="var(--line)" stroke-width="1.2"/>'
            . '<text data-no-i18n x="42" y="75" font-size="10" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">jan.novak</text>'
            . '<rect x="34" y="90" width="88" height="22" rx="4" fill="none" stroke="var(--info)" stroke-width="1.2"/>'
            . '<text data-no-i18n x="42" y="106" font-size="12" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">••••••••</text>'
            . '<rect class="logline" x="34" y="122" width="52" height="5" rx="2.5"/>'
            . '<path class="flow" d="M140 94 H196"/>' . $dots
            . '<text class="lbl" x="231" y="38" text-anchor="middle">A CODE TO YOU</text>'
            . '<rect class="brick" x="207" y="48" width="48" height="94" rx="9" stroke="var(--info)" stroke-width="1.6"/>'
            . '<rect x="221" y="54" width="20" height="3" rx="1.5" fill="var(--line)"/>'
            . '<rect x="212" y="80" width="38" height="26" rx="4" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1"/>'
            . '<text data-no-i18n x="231" y="97" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">482913</text>'
            . '<rect x="221" y="132" width="20" height="3" rx="1.5" fill="var(--line)"/>'
            . '<path class="through" d="M266 94 h22 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="344" y="38" text-anchor="middle">SIGNED IN</text>'
            . '<path class="halo" d="M344 66 a28 28 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="344" cy="94" r="25" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<path d="M333 94 l8 8 14-15" fill="none" stroke="var(--ok)" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">A CODE AT EVERY SIGN-IN · BY MAIL OR SMS</text>'
            . '</svg>';
    case 'team':
        // The team's certificates: whoever is in it sees and asks for them.
        $person = function (int $y, string $who): string {
            return sprintf('<path d="M72 %d C110 %d 118 96 150 96" fill="none" stroke="var(--line)" stroke-width="1.6"/>', $y, $y)
                . sprintf('<circle cx="58" cy="%d" r="14" fill="var(--panel2)" stroke="var(--info)" stroke-width="1.6"/>', $y)
                . sprintf('<text data-no-i18n x="58" y="%.1f" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--info)">%s</text>', $y + 3.5, $who);
        };
        return '<svg class="signart art-team" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Your team\'s certificates, seen by the whole team</title>' . $glow
            . '<text class="lbl" x="58" y="30" text-anchor="middle">YOUR TEAM</text>'
            . $person(56, 'JN') . $person(96, 'PK') . $person(136, 'MS')
            . '<path class="halo" d="M170 74 a22 22 0 1 1 -0.1 0z" fill="var(--info)" opacity=".35"/>'
            . '<circle cx="170" cy="96" r="20" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="164" cy="91" r="4.5" fill="none" stroke="var(--info)" stroke-width="1.8"/>'
            . '<circle cx="177" cy="91" r="4.5" fill="none" stroke="var(--info)" stroke-width="1.8"/>'
            . '<path d="M156 105 a8 6.5 0 0 1 16 0 M169 105 a8 6.5 0 0 1 16 0" fill="none" stroke="var(--info)" stroke-width="1.8" stroke-linecap="round"/>'
            . '<path class="flow" d="M192 96 H246"/>' . $dots
            . '<text class="lbl" x="326" y="30" text-anchor="middle">ITS CERTIFICATES</text>'
            . '<rect class="brick" x="262" y="42" width="100" height="76" rx="7" opacity=".55"/>'
            . '<rect class="brick" x="276" y="54" width="100" height="76" rx="7" opacity=".8"/>'
            . '<rect class="brick" x="290" y="66" width="100" height="76" rx="7" stroke="var(--ok)" stroke-width="1.4"/>'
            . '<rect class="logline" x="302" y="80" width="56" height="5" rx="2.5"/>'
            . '<rect class="logline good" x="302" y="92" width="40" height="5" rx="2.5"/>'
            . '<rect class="logline" x="302" y="104" width="50" height="5" rx="2.5"/>'
            . '<circle cx="370" cy="124" r="9" fill="url(#sa-glow)" stroke="var(--ok)" stroke-width="2"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">SEEN AND ASKED FOR BY THE WHOLE TEAM</text>'
            . '</svg>';
    /* ---- the administration's own (1.0.41): what the people who run acme see ---- */
    case 'overview':
        // Everything at a glance: the certificates, the sources, the targets, the tests.
        $tile = function (int $x, string $top, string $n, string $line): string {
            return sprintf('<text class="lbl" x="%d" y="40" text-anchor="middle">%s</text>', $x + 41, $top)
                . sprintf('<rect class="brick" x="%d" y="50" width="82" height="96" rx="8"/>', $x)
                . sprintf('<circle cx="%d" cy="64" r="3.5" fill="var(--ok)"/>', $x + 70)
                . sprintf('<text data-no-i18n x="%d" y="100" text-anchor="middle" font-size="24" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x + 41, $n)
                . sprintf('<path d="%s" fill="none" stroke="var(--ok)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" transform="translate(%d 0)"/>', $line, $x);
        };
        return '<svg class="signart art-overview" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Everything at a glance, all of it well</title>' . $glow
            . $tile(24, 'CERTIFICATES', '41', 'M12 130 L26 124 L38 127 L52 118 L70 120')
            . $tile(120, 'SOURCES', '3', 'M12 124 L28 124 L42 122 L56 124 L70 123')
            . $tile(216, 'TARGETS', '12', 'M12 128 L24 126 L38 121 L54 122 L70 116')
            . $tile(312, 'TESTS', '12', 'M12 122 L26 125 L40 121 L56 123 L70 120')
            . '<path class="halo" d="M94 57 a7 7 0 1 1 -0.1 0z" fill="var(--ok)" opacity=".3"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">EVERYTHING AT A GLANCE · ALL OF IT WELL</text>'
            . '</svg>';
    case 'cluster':
        // Two nodes, one address in front of them, one database between them.
        $node = function (int $x, string $name, string $state, string $tone): string {
            return sprintf('<rect class="brick" x="%d" y="82" width="110" height="60" rx="8" stroke="var(--%s)" stroke-width="1.4"/>', $x, $tone)
                . sprintf('<rect class="logline" x="%d" y="94" width="30" height="4" rx="2"/>', $x + 12)
                . sprintf('<text data-no-i18n x="%d" y="117" text-anchor="middle" font-size="12" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $x + 55, $tone, $name)
                . sprintf('<text x="%d" y="133" text-anchor="middle" font-size="9.5" font-weight="700" fill="var(--tx-mut)">%s</text>', $x + 55, $state);
        };
        return '<svg class="signart art-cluster" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Two nodes, one address, one database</title>' . $glow
            . '<text class="lbl" x="210" y="24" text-anchor="middle">ONE ADDRESS</text>'
            . '<rect x="158" y="32" width="104" height="24" rx="12" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<text data-no-i18n x="210" y="48" text-anchor="middle" font-size="10.5" font-weight="700" fill="var(--info)" font-family="ui-monospace,Menlo,monospace">192.0.2.10</text>'
            . '<path class="through" d="M176 56 C150 60 90 62 85 82" stroke-linecap="round"/>'
            . '<path d="M244 56 C270 60 330 62 335 82" fill="none" stroke="var(--line)" stroke-width="1.6" stroke-dasharray="3 4"/>'
            . '<path class="flow" d="M142 112 H278"/>' . $dots
            . $node(30, 'acme1', 'in service', 'ok') . $node(280, 'acme2', 'ready', 'info')
            . '<path d="M184 96 v30 a26 8 0 0 0 52 0 v-30" fill="var(--panel2)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<ellipse cx="210" cy="96" rx="26" ry="8" fill="var(--panel2)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<path d="M184 110 a26 8 0 0 0 52 0" fill="none" stroke="var(--info)" stroke-width="1.2" opacity=".6"/>'
            . '<text class="lbl" x="210" y="152" text-anchor="middle">THE DATABASE</text>'
            . '<text class="lbl" x="210" y="176" text-anchor="middle">TWO NODES · ONE ADDRESS · NOTHING LOST</text>'
            . '</svg>';
    case 'sources':
        // Every authority it gets certificates from, into one place.
        $src = function (int $c, string $name, string $tone, bool $plain): string {
            return sprintf('<rect class="brick" x="24" y="%d" width="124" height="30" rx="6"/>', $c - 15)
                . sprintf('<circle cx="40" cy="%d" r="4" fill="var(--%s)"/>', $c, $tone)
                . sprintf('<text%s x="52" y="%d" font-size="10.5" font-weight="700" fill="var(--%s)" font-family="ui-monospace,Menlo,monospace">%s</text>', $plain ? ' data-no-i18n' : '', $c + 4, $tone, $name)
                . ($c === 99 ? '' : sprintf('<path class="through" d="M152 %d C196 %d 206 99 248 99" stroke-linecap="round"/>', $c, $c));
        };
        return '<svg class="signart art-sources" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Every authority, into one place</title>' . $glow
            . '<text class="lbl" x="86" y="32" text-anchor="middle">THE AUTHORITIES</text>'
            . $src(59, 'ACME CA', 'info', true) . $src(99, 'internal CA', 'ok', false) . $src(139, 'a reseller', 'warn', false)
            . '<path class="flow" d="M152 99 H248"/>' . $dots
            . '<path class="through" d="M248 99 h16 m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>'
            . '<text class="lbl" x="334" y="32" text-anchor="middle">ONE PLACE</text>'
            . '<path d="M290 56 v80 a44 11 0 0 0 88 0 v-80" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<ellipse cx="334" cy="56" rx="44" ry="11" fill="var(--panel2)" stroke="var(--info)" stroke-width="1.6"/>'
            . '<path d="M290 82 a44 11 0 0 0 88 0 M290 108 a44 11 0 0 0 88 0" fill="none" stroke="var(--info)" stroke-width="1.1" opacity=".55"/>'
            . '<text data-no-i18n x="334" y="128" text-anchor="middle" font-size="18" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">41</text>'
            . '<text class="lbl" x="210" y="176" text-anchor="middle">EVERY AUTHORITY · ONE STORE · ONE WAY</text>'
            . '</svg>';
    case 'jobs':
        // The jobs: queued, done, tried again - by themselves, on time.
        $job = function (int $y, string $icon, string $name, string $state, string $tone): string {
            return sprintf('<rect class="brick" x="24" y="%d" width="290" height="28" rx="6"/>', $y)
                . $icon
                . sprintf('<text data-no-i18n x="58" y="%d" font-size="10" font-weight="700" fill="var(--tx)" font-family="ui-monospace,Menlo,monospace">%s</text>', $y + 18, $name)
                . sprintf('<text class="lbl" x="302" y="%d" text-anchor="end" style="fill:var(--%s)">%s</text>', $y + 17, $tone, $state);
        };
        return '<svg class="signart art-jobs" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">The jobs, by themselves and on time</title>' . $glow
            . '<text class="lbl" x="24" y="32">THE JOBS</text>'
            . $job(42, '<circle cx="40" cy="56" r="7" fill="none" stroke="var(--ok)" stroke-width="1.8"/><path d="M36.5 56 l2.5 2.5 4.5-5" fill="none" stroke="var(--ok)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>', 'www.example.cz', 'RENEWED', 'ok')
            . $job(80, '<circle cx="40" cy="94" r="7" fill="none" stroke="var(--info)" stroke-width="1.8" stroke-dasharray="11 4"/>', 'F5', 'BEING PUT IN', 'info')
            . '<path class="flow" d="M82 94 H200"/>' . $dots
            . $job(118, '<circle cx="40" cy="132" r="7" fill="none" stroke="var(--warn)" stroke-width="1.8"/><path d="M40 128 v4 l3 2" fill="none" stroke="var(--warn)" stroke-width="1.6" stroke-linecap="round"/>', 'api.example.cz', 'AGAIN IN 10 MIN', 'warn')
            . '<text class="lbl" x="362" y="32" text-anchor="middle">ON TIME</text>'
            . '<path class="halo" d="M362 62 a32 32 0 1 1 -0.1 0z" fill="var(--info)" opacity=".3"/>'
            . '<circle cx="362" cy="94" r="28" fill="url(#sa-glow)" stroke="var(--info)" stroke-width="1.8"/>'
            . '<path d="M362 72 v4 M362 112 v4 M340 94 h4 M380 94 h4" stroke="var(--info)" stroke-width="1.6" stroke-linecap="round"/>'
            . '<path d="M362 94 v-14 M362 94 l10 6" stroke="var(--ok)" stroke-width="2.4" stroke-linecap="round"/>'
            . '<text class="lbl" x="210" y="172" text-anchor="middle">QUEUED · DONE · TRIED AGAIN - NOBODY WAITS</text>'
            . '</svg>';
    case 'alerts':
        // Every change written down; every failure told at once, the way you want it.
        $line = function (int $y, string $tone, int $w): string {
            return sprintf('<circle cx="40" cy="%d" r="3.5" fill="var(--%s)"/>', $y, $tone)
                . sprintf('<rect class="logline%s" x="50" y="%.1f" width="%d" height="5" rx="2.5"/>', $tone === 'crit' ? ' bad' : '', $y - 2.5, $w);
        };
        $to = function (int $c, string $name): string {
            return sprintf('<path class="through" d="M262 92 C282 92 284 %d 300 %d m-7-6 l7 6 -7 6" stroke-linecap="round" stroke-linejoin="round"/>', $c, $c)
                . sprintf('<rect class="brick" x="306" y="%d" width="92" height="26" rx="6"/>', $c - 13)
                . sprintf('<text data-no-i18n x="352" y="%d" text-anchor="middle" font-size="10.5" font-weight="700" fill="var(--ok)" font-family="ui-monospace,Menlo,monospace">%s</text>', $c + 4, $name);
        };
        return '<svg class="signart art-alerts" viewBox="0 0 420 188" role="img" aria-labelledby="sa-title">'
            . '<title id="sa-title">Every change written down, every failure told</title>' . $glow
            . '<text class="lbl" x="99" y="32" text-anchor="middle">THE EVENTS</text>'
            . '<rect class="brick" x="24" y="44" width="150" height="100" rx="8"/>'
            . $line(60, 'ok', 96) . $line(76, 'ok', 72) . $line(92, 'crit', 88) . $line(108, 'ok', 80) . $line(124, 'warn', 60)
            . '<path class="flow" d="M182 92 H214"/>' . $dots
            . '<path class="halo" d="M240 70 a22 22 0 1 1 -0.1 0z" fill="var(--warn)" opacity=".3"/>'
            . '<circle cx="240" cy="92" r="20" fill="url(#sa-glow)" stroke="var(--warn)" stroke-width="1.8"/>'
            . '<path d="M232 99 h16 l-2.5-3.5 v-5 a5.5 5.5 0 0 0 -11 0 v5z M238 101.5 a2.2 2.2 0 0 0 4 0" fill="none" stroke="var(--warn)" stroke-width="1.7" stroke-linejoin="round"/>'
            . '<text class="lbl" x="352" y="28" text-anchor="middle">TOLD AT ONCE</text>'
            . $to(52, 'e-mail') . $to(92, 'SMS') . $to(132, 'syslog/SIEM')
            . '<text class="lbl" x="210" y="172" text-anchor="middle">EVERY CHANGE WRITTEN · EVERY FAILURE TOLD</text>'
            . '</svg>';
    }
    return '';
}

/**
 * The picture for a sign-in page (1.0.72: each page its own): $art as
 * /api/portal/info gives it - 'art' for the portal, 'admin_art'
 * for the administration - and $slot which of the two.
 */
function acme_art_for(?array $art, string $slot, string $title): string
{
    $slot = $slot === 'admin' ? 'admin' : 'portal';
    $art = is_array($art) ? $art : [];
    $name = in_array($art['art'] ?? '', ACME_ARTS, true) ? $art['art'] : ACME_ART_DEFAULT[$slot];
    if (isset(ACME_ART_ONLY[$name]) && ACME_ART_ONLY[$name] !== $slot) {
        $name = ACME_ART_DEFAULT[$slot];   // never saved so; shown as the page's own all the same
    }
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
