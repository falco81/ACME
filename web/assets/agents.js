/* agents.js - target agents (1.0.116, docs/target-agent.md): the pane Settings → Target agents,
   the agent's card on a target "Server with acme-agent", its join wizard, and what a deployment
   needs of the agent's policy (drawn into the files designer's preview). Phases 3 and 4: the
   keys made there, the tests and connections through the agent, a newer agent offered (and
   sent, where its policy allows), a deployment its policy blocked.

   Drawn with the page's own pieces (core.js) and the classes of the database agent's card and
   wizard (acme.css: dbs-*, dbw-*); what is its own is in agents.css. certs.js hands it how to
   ask the daemon: ACME_AGENTS.init({capi, over, openTarget}). */
(function () {
'use strict';

var H = {capi: null, over: null, openTarget: null, newCert: null};
var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
var FULL = ROLE === 'fulladmin';
var MANAGE = FULL || ROLE === 'certadmin';
var PANE = {ticket: 0, timer: null};
/* the agents being updated now (id: 1) - a second click, or Update all meanwhile, sent the
   package to the same agent again */
var UPDATING = {};
/* how each tile's update goes (id: {cls, words, at}) - the pane drawn again meanwhile (its
   4 s settling, an update ending) drew the tiles without it (1.0.119) */
var MARKS = {};
var MARK_KEEP = 300000;

function ask(path, body, wait) {
  if (!H.capi) return Promise.reject(new Error('the page is not ready'));
  return H.capi(path, body, wait);
}
function arr(v) { return Array.isArray(v) ? v : []; }
/** The policy builder (policybuilder.js, 1.0.118) of a target's agent. */
function builder(row, opts) {
  if (window.ACME_POLICY_BUILDER) window.ACME_POLICY_BUILDER.open(row, opts || {});
  else toast('the policy builder is not on this page', 'bad');
}
function designButton(row, opts, cls) {
  var b = cmdButton('Design its policy…', 'shield', cls || 'small');
  b.onclick = function () { builder(row, opts); };
  return b;
}
/** Another program than the one this acme ships - only of the same version (an older one
    has the newer agent offered, which says it). */
function otherProgram(a, shipped, also) {
  /* also (1.0.122): every hash of the program acme ships - on Linux without its Windows files too
     (a 1.0.119 agent updated itself with acme_agent.py only). */
  if (also && also.indexOf && also.indexOf(a.code_hash) >= 0) return false;
  return !!(a.code_hash && shipped && a.code_hash !== shipped && !(a.update && a.update.newer)
    && (!a.update || !a.update.offered || String(a.version || '') === String(a.update.offered)));
}
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function mono(text, cls) { return noI18n(el('span', 'mono' + (cls ? ' ' + cls : ''), text)); }
function icon(key, size) {
  var s = noI18n(el('span', 'ag-ic'));
  s.innerHTML = iconMarkup(key, size || 18);
  return s;
}
function grouped(fp) {
  var f = String(fp || '').toUpperCase(), out = [];
  for (var i = 0; i < f.length; i += 4) out.push(f.slice(i, i + 4));
  return out;
}
function bytes(n) {
  n = Number(n || 0);
  if (n >= 1048576) return (n / 1048576).toFixed(1) + ' MB';
  if (n >= 1024) return Math.round(n / 1024) + ' kB';
  return n + ' B';
}
function when(ts) {
  if (!ts) return '–';
  try { return stamp(ts); } catch (e) { return String(ts); }
}
function daysLeft(ts) { return ts ? (Number(ts) * 1000 - Date.now()) / 86400000 : null; }

/** A command to copy: the line itself (selectable whole) and its Copy button. */
function cmdBox(text, cls) {
  var box = el('div', 'dbs-cmd ag-cmd' + (cls ? ' ' + cls : ''));
  box.appendChild(noI18n(el('pre', 'mono', text)));
  var cp = cmdButton('Copy', 'copy', 'small');
  cp.onclick = function () { copyText(text, cp, 'on the clipboard'); };
  box.appendChild(cp);
  return box;
}
/** The fingerprint as it is compared by eye: sixteen groups of four, large. */
function fpBig(fp, cls) {
  var box = noI18n(el('div', 'ag-fp' + (cls ? ' ' + cls : '')));
  grouped(fp).forEach(function (g, i) {
    var s = el('span', 'ag-fp-g', g);
    if (i % 4 === 3) s.classList.add('brk');
    box.appendChild(s);
  });
  return box;
}

/* ---- the state of one agent, in words and colour --------------------------------------- */
var STATE = {
  answers: ['answers', 'ok'], quiet: ['not heard from', 'warn'], refused: ['refused', 'bad'],
  joining: ['joining', 'info'], 'new': ['not joined', 'dim'], off: ['switched off', 'dim']
};
function statePill(a) {
  var m = STATE[a.state] || [a.state || '–', 'dim'];
  var p = el('span', 'dbs-state ag-state ' + m[1]);
  p.appendChild(el('span', 'dot ' + (m[1] === 'ok' ? 'ok' : m[1] === 'bad' ? 'crit' : m[1] === 'warn' ? 'warn' : 'off')));
  p.appendChild(el('span', '', m[0]));
  if (a.last_seen && (a.state === 'answers' || a.state === 'quiet')) {
    p.appendChild(noI18n(el('span', 'dbs-ago', ' · ')));
    p.appendChild(el('span', 'dbs-ago', ago(a.last_seen)));
  }
  if (a.last_error && a.state !== 'answers') explain(p, String(a.last_error));
  return p;
}
function modeBadge(mode) {
  var b = el('span', 'ag-mode ' + (mode === 'active' ? 'active' : 'passive'));
  b.appendChild(icon(mode === 'active' ? 'out' : 'in', 13));
  b.appendChild(el('span', '', mode === 'active' ? 'active' : 'passive'));
  explain(b, mode === 'active' ? 'The agent connects to acme: nothing listens on its server.'
    : 'acme connects to the agent: it listens and lets in only acme’s certificate.');
  return b;
}
function certEnd(ts) {
  if (!ts) return el('span', 'muted', '–');
  var d = daysLeft(ts);
  var s = el('span', 'ag-end' + (d < 3 ? ' bad' : (d < 14 ? ' warn' : '')));
  s.appendChild(document.createTextNode(when(ts)));
  return s;
}
function chips(ps, small) {
  var box = el('div', 'ag-chips' + (small ? ' small' : ''));
  if (!ps) { box.appendChild(el('span', 'ag-chip unk', 'policy not known yet')); return box; }
  [['files', 'folder', 'folders', 'lock'], ['units', 'unit', 'units', 'refresh'],
   ['tests', 'test', 'tests', 'check'], ['scripts', 'script', 'scripts', 'terminal']].forEach(function (x) {
    var n = Number(ps[x[0]] || 0);
    var c = el('span', 'ag-chip' + (n ? '' : ' none'));
    c.appendChild(icon(x[3], 13));
    c.appendChild(el('span', '', n + ' ' + (n === 1 ? x[1] : x[2])));
    box.appendChild(c);
  });
  /* phase 3: what is reached through it - shown only where its policy allows any */
  [['probes', 'test from here', 'tests from here', 'pulse'], ['connects', 'connection', 'connections', 'plug']].forEach(function (x) {
    var n = Number(ps[x[0]] || 0);
    if (!n) return;
    var c = el('span', 'ag-chip more');
    c.appendChild(icon(x[3], 13));
    c.appendChild(el('span', '', n + ' ' + (n === 1 ? x[1] : x[2])));
    box.appendChild(c);
  });
  if (ps.self_update) {
    var u = el('span', 'ag-chip more');
    u.appendChild(icon('refresh', 13));
    u.appendChild(el('span', '', 'updates from acme'));
    box.appendChild(u);
  }
  if (Number(ps.problems || 0)) {
    var p = el('span', 'ag-chip bad');
    p.appendChild(icon('flag', 13));
    p.appendChild(el('span', '', 'lines not read'));
    box.appendChild(p);
  }
  return box;
}
function kv(k, v, wide) {
  var c = el('div', 'dbs-kv' + (wide ? ' wide' : ''));
  c.appendChild(el('span', 'k', k));
  var vv = el('span', 'v');
  if (v && v.nodeType) vv.appendChild(v); else vv.appendChild(document.createTextNode(v === undefined || v === null || v === '' ? '–' : String(v)));
  c.appendChild(vv);
  return c;
}

/* ==========================================================================
   Settings → Target agents
   ========================================================================== */
function pane(live) {
  var hero = $('ag-hero'), pkg = $('ag-pkg'), list = $('ag-list'), ca = $('ag-ca');
  var wait = $('ag-wait'), enr = $('ag-enroll');
  if (!hero) return;
  var ticket = ++PANE.ticket;
  function fill(d, how) {
    liveFill(hero, function (box) { drawHero(box, d); }, how);
    /* 1.0.120: the agents asking to join, the company enrollment codes */
    if (wait) liveFill(wait, function (box) { drawWaiting(box, d); }, how);
    if (enr) liveFill(enr, function (box) { drawEnroll(box, d); }, how);
    liveFill(pkg, function (box) { drawPackage(box, d); }, how);
    liveFill(ca, function (box) { drawAuthority(box, d); }, how);
    liveFill(list, function (box) { drawList(box, d); }, how);
    explainWhatWasDrawn(hero.parentNode);
  }
  /* opened again: what was seen last drawn at once, then what the daemon says now in its
     place - the pane does not jump while it is asked (the first time the hero's place is kept
     by agents.css) */
  if (PANE.last && !hero.firstChild) fill(PANE.last, false);
  else if (!hero.firstChild) hero.classList.toggle('on', activeSaid());
  ask('agents').then(function (d) {
    if (ticket !== PANE.ticket) return;
    var again = !!PANE.last && !!hero.firstChild;
    PANE.last = d;
    fill(d, live || again);
    settleMore(d);
  }).catch(function (e) {
    if (ticket !== PANE.ticket) return;
    /* 1.0.119: said where it is seen - the hero alone said it, the boxes below went on
       empty (the first time) or showing what was seen last as if it were now */
    var words = 'The target agents could not be asked: ' + String((e && e.message) || e);
    if (PANE.last && hero.firstChild) {
      var was = hero.querySelector('.ag-ask-err');
      if (was) was.remove();
      var p = el('p', 'ct-bad ag-ask-err', words);
      hero.insertBefore(p, hero.firstChild);
      return;
    }
    [hero, pkg, ca, list, wait, enr].forEach(function (b) { if (b) clear(b); });
    hero.appendChild(el('p', 'ct-bad ag-ask-err', words));
  });
}
/* After active mode or the port is saved (1.0.117): the pane is asked again every 4 s while
   what it shows is not yet what was saved - the setting itself, then each node's nginx taking
   the port or letting it go (the root helper, within a minute) - for 2 minutes at most, and
   only while the pane is on the screen. */
function settle() {
  PANE.settleUntil = Date.now() + 120000;
  pane(true);
}
function settleMore(d) {
  clearTimeout(PANE.settleT);
  if (!PANE.settleUntil || Date.now() > PANE.settleUntil) return;
  var hero = $('ag-hero');
  if (!hero || !hero.offsetParent || document.hidden) { PANE.settleUntil = 0; return; }
  var on = !!d.active, port = d.nginx ? Number(d.nginx.port || 0) : 0;
  var done = on === activeSaid() && (on ? port > 0 && port === Number(d.port || port) : port === 0);
  if (done) { PANE.settleUntil = 0; return; }
  PANE.settleT = setTimeout(function () { pane(true); }, 4000);
}
/** Active mode as the settings on the page say it (admin.js SETTINGS) - the hero's place
    kept the height it will have (its addresses' line) while the pane is asked. */
function activeSaid() {
  try {
    var s = (window.SETTINGS && window.SETTINGS.settings || []).filter(function (x) { return x.key === 'certs_agents_active'; })[0];
    return !!(s && Number(s.value));
  } catch (e) { return false; }
}
function drawHero(box, d) {
  var on = !!d.active, listening = d.nginx && Number(d.nginx.port || 0) > 0;
  var h = el('div', 'dbs-hero ag-hero ' + (on ? (listening ? 'good' : 'warn') : ''));
  var ic = noI18n(el('span', 'dbs-hero-ic'));
  ic.innerHTML = iconMarkup('terminal', 24);
  h.appendChild(ic);
  var w = el('div', 'dbs-hero-w');
  w.appendChild(el('b', '', 'acme proposes, the server decides'));
  w.appendChild(el('div', 'small', 'A server with acme-agent gives acme none of its credentials: the agent does only what its own policy allows - the folders, owners and modes, the units it may reload, the tests and scripts by their hash.'));
  var modes = el('div', 'ag-hero-modes');
  var a = el('div', 'ag-hero-mode');
  a.appendChild(modeBadge('passive'));
  a.appendChild(el('span', 'small', 'always possible: acme connects out, nothing listens here'));
  modes.appendChild(a);
  var b = el('div', 'ag-hero-mode');
  b.appendChild(modeBadge('active'));
  if (!on) b.appendChild(el('span', 'small', 'off - no port, no server of nginx, no firewall rule'));
  else {
    b.appendChild(el('span', 'small', 'agents connect to every node on port'));
    b.appendChild(mono(String(d.port), 'ag-port'));
  }
  modes.appendChild(b);
  w.appendChild(modes);
  h.appendChild(w);
  var st = el('span', 'dbs-state ' + (on ? (listening ? 'ok' : 'warn') : ''));
  st.appendChild(el('span', 'dot ' + (on ? (listening ? 'ok' : 'warn') : 'off')));
  st.appendChild(el('span', '', on ? (listening ? 'active mode on' : 'active mode on - nginx not yet') : 'active mode off'));
  if (on && !listening) explain(st, 'Switched on: each node gives nginx the agents’ port within a minute (its root helper). If it stays so, Settings → Web shows what nginx said.');
  h.appendChild(st);
  box.appendChild(h);
  if (on && arr(d.endpoints).length) {
    var e = el('div', 'ag-eps');
    e.appendChild(el('span', 'dbw-k', 'An active agent is given'));
    arr(d.endpoints).forEach(function (x) { e.appendChild(mono(x, 'ag-ep')); });
    box.appendChild(e);
  }
}
function drawPackage(box, d) {
  var h = el('h2', '');
  h.appendChild(document.createTextNode('The agent to install'));
  box.appendChild(h);
  /* 1.0.120: the Linux package and the Windows installer, a tab each */
  box.appendChild(osTabs('pkg', function (host, os) {
    if (os === 'windows') drawWindowsPackage(host, d); else drawLinuxPackage(host, d);
  }));
}
function drawLinuxPackage(box, d) {
  var p = d.package;
  if (!p) {
    box.appendChild(el('p', 'ct-bad', 'The package could not be made: ' + String(d.package_error || '?')));
    return;
  }
  var tile = el('div', 'ag-pkg');
  var ic = noI18n(el('span', 'ag-pkg-ic'));
  ic.innerHTML = iconMarkup('download', 26);
  tile.appendChild(ic);
  var w = el('div', 'ag-pkg-w');
  var top = el('div', 'ag-pkg-top');
  top.appendChild(data('b', 'ag-pkg-name', p.name));
  var sig = el('span', 'ag-badge ' + (p.signed ? 'ok' : 'warn'));
  sig.appendChild(icon(p.signed ? 'shield' : 'flag', 13));
  sig.appendChild(el('span', '', p.signed ? 'signed by acme’s release key' : 'not signed - made from this source tree'));
  explain(sig, p.signed ? 'install.sh checks every file against MANIFEST and MANIFEST against its signature before it installs anything.'
    : 'A release carries the package signed. This one was made here from the program acme ships; compare its SHA-256 on the server.');
  top.appendChild(sig);
  w.appendChild(top);
  var meta = el('div', 'ag-pkg-meta');
  meta.appendChild(el('span', '', 'version'));
  meta.appendChild(mono(String(p.version)));
  meta.appendChild(noI18n(el('span', 'muted', '·')));
  meta.appendChild(mono(bytes(p.size)));
  meta.appendChild(noI18n(el('span', 'muted', '·')));
  meta.appendChild(el('span', '', 'RHEL 8–10, Debian, Ubuntu · Python 3.7+'));
  w.appendChild(meta);
  var sha = el('div', 'ag-sha');
  sha.appendChild(el('span', 'dbw-k', 'SHA-256'));
  var sv = mono(String(p.sha256), 'ag-sha-v');
  copyOnClick(sv, String(p.sha256), 'on the clipboard');
  sha.appendChild(sv);
  w.appendChild(sha);
  tile.appendChild(w);
  /* the package is given to a certificate administrator (GET agents/package) - the button
     was there for every role, and said "forbidden" (1.0.119) */
  if (MANAGE) {
    var dl = cmdButton('Download', 'download', 'primary');
    dl.onclick = function () { download(dl); };
    tile.appendChild(dl);
  }
  box.appendChild(tile);
  box.appendChild(el('h4', 'dbw-h', 'On the server, as root'));
  var ol = el('ol', 'dbs-steps ag-steps');
  var words = ['Check it is the same file (the SHA-256 above):', 'Unpack it:',
    'Install - the package is checked, nothing is allowed yet:', 'Join with the code made on the target’s card:'];
  arr(d.commands).forEach(function (c, i) {
    var li = el('li', '');
    li.appendChild(el('span', '', words[i] || ''));
    li.appendChild(cmdBox(c));
    /* CODE is the join code (ACAG1.…) of one target - not the fingerprint of the authority
       below, which went in for it once (1.0.117) */
    if (i === 3) li.appendChild(el('p', 'note small muted', 'CODE starts with ACAG1. and is made for one target: Targets → Add a target → Server with acme-agent, then Join the agent… on its card. It is not the fingerprint of acme’s agent authority below.'));
    ol.appendChild(li);
  });
  box.appendChild(ol);
}
function download(button) {
  busy(button, true);
  ask('agents/package').then(function (d) {
    var raw = atob(d.data_b64), u8 = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i);
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([u8], {type: d.mime || 'application/gzip'}));
    a.download = d.filename || 'acme-agent.tar.gz';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
  }).catch(oops).then(function () { busy(button, false); });
}
function drawAuthority(box, d) {
  box.appendChild(el('h2', '', 'acme’s agent authority'));
  box.appendChild(el('p', 'note', 'It signs each agent’s certificate (30 days, renewed over the channel) and acme’s own; every agent pins its fingerprint at the join. Its key is sealed in the database - in every backup, on every node.'));
  if (!d.ca) {
    box.appendChild(el('p', 'muted', 'Made with the first join code.'));
    return;
  }
  var row = el('div', 'ag-ca');
  row.appendChild(fpBig(d.ca.fp, 'small'));
  var cp = cmdButton('Copy', 'copy', 'small');
  cp.onclick = function () { copyText(String(d.ca.fp), cp, 'on the clipboard'); };
  row.appendChild(cp);
  box.appendChild(row);
  var k = el('div', 'dbs-kvs ag-ca-kvs');
  k.appendChild(kv('Valid until', when(d.ca.end)));
  k.appendChild(kv('Made', when(d.ca.at)));
  box.appendChild(k);
}
function drawList(box, d) {
  var rows = arr(d.rows);
  var h = el('h2', '');
  h.appendChild(document.createTextNode('Targets with an agent'));
  var n = noI18n(el('span', 'count', String(rows.length)));
  h.appendChild(n);
  if (FULL && rows.some(function (a) { return a.update && a.update.newer; })) {
    h.className = 'ag-list-h';
    var ua = cmdButton('Update all agents…', 'up', 'small');
    ua.onclick = updateAll;
    h.appendChild(ua);
  }
  box.appendChild(h);
  if (!rows.length) {
    var e = el('div', 'ag-empty');
    e.appendChild(icon('terminal', 28));
    e.appendChild(el('b', '', 'No target with an agent yet'));
    e.appendChild(el('p', 'note', 'Targets → Add a target → Server with acme-agent; then its card makes the join code.'));
    box.appendChild(e);
    return;
  }
  var g = el('div', 'dbs-grid ag-grid');
  rows.forEach(function (a) { g.appendChild(tile(a, d)); });
  box.appendChild(g);
  var sv = serversTable(rows);    /* 1.0.120: every server at a glance */
  if (sv) box.appendChild(sv);
}
function tile(a, d) {
  var t = el('div', 'dbs-tile ag-tile ' + (a.state === 'refused' ? 'bad' : ''));
  var top = el('div', 'dbs-tile-top');
  var dot = el('span', 'dot ' + ({answers: 'ok', quiet: 'warn', refused: 'crit'}[a.state] || 'off'));
  top.appendChild(dot);
  var name = el('button', 'ag-name');
  name.type = 'button';
  name.appendChild(data('span', 'dbs-tile-n', a.name));
  name.onclick = function () { if (H.openTarget) H.openTarget(a.name); };
  top.appendChild(name);
  top.appendChild(modeBadge(a.mode));
  if (a.platform === 'windows') top.appendChild(platformBadge('windows', true));
  var sp = el('span', 'ag-tile-st');
  sp.appendChild(statePill(a));
  top.appendChild(sp);
  t.appendChild(top);
  var k = el('div', 'dbs-kvs');
  k.appendChild(kv('Server', a.agent_host || a.host ? mono(String(a.agent_host || a.host)) : '–'));
  k.appendChild(kv('Agent', a.version ? mono(a.version) : '–'));
  k.appendChild(kv('Last heard', a.last_seen ? ago(a.last_seen) : 'never'));
  k.appendChild(kv('Its certificate ends', certEnd(a.cert_end)));
  t.appendChild(k);
  var sl = sysLine(a);           /* 1.0.120: its server in a line */
  if (sl) t.appendChild(sl);
  t.appendChild(chips(a.policy_summary, true));
  var flags = el('div', 'ag-flags');
  if (a.blocked) {
    var bf = el('span', 'ag-flag bad');
    bf.appendChild(icon('flag', 13));
    bf.appendChild(el('span', '', 'its policy blocks a deployment'));
    explain(bf, String(a.blocked.what || ''));
    flags.appendChild(bf);
  }
  if (a.update && a.update.newer) {
    var nf = el('span', 'ag-flag info');
    nf.appendChild(icon('up', 13));
    nf.appendChild(el('span', '', 'newer agent offered'));
    nf.appendChild(mono(String(a.update.offered || ''), 'ag-flag-v'));
    flags.appendChild(nf);
  }
  if (arr(a.keys_of).length) {
    var kf = el('span', 'ag-flag ok');
    kf.appendChild(icon('key', 13));
    kf.appendChild(el('span', '', arr(a.keys_of).length === 1 ? 'makes 1 key' : 'makes ' + arr(a.keys_of).length + ' keys'));
    explain(kf, arr(a.keys_of).join(', '));
    flags.appendChild(kf);
  }
  if (flags.firstChild) t.appendChild(flags);
  if (a.design) {
    var df = el('span', 'ag-flag ' + (a.design.state === 'matches' ? 'ok' : (a.design.state === 'differs' ? 'warn' : 'info')));
    df.appendChild(icon('shield', 13));
    df.appendChild(el('span', '', a.design.state === 'matches' ? 'matches its design' : (a.design.state === 'differs' ? 'differs from its design' : 'a design is saved')));
    if (a.design.title) explain(df, String(a.design.title));
    if (!flags.parentNode) t.appendChild(flags);
    flags.appendChild(df);
  }
  /* the actions in a row of their own at the foot of the tile - the button sat right under the
     chips, a tile's foot at another height than its neighbour's */
  t.appendChild(el('div', 'ag-tile-sp'));
  var acts = el('div', 'btnrow ag-tile-acts');
  acts.appendChild(designButton({id: a.id, name: a.name}, {done: function () { pane(true); }}, 'small'));
  if (FULL && a.update && a.update.newer && a.update.allowed && a.update.signed) {
    var ub = cmdButton('Update', 'up', 'small');
    ub.disabled = !!UPDATING[a.id];
    ub.onclick = function () { ub.disabled = true; updateMany([{id: a.id, name: a.name, offered: a.update.offered, ok: true}]); };
    acts.appendChild(ub);
  }
  var prog = el('span', 'ag-tile-upd');
  prog.hidden = true;
  prog.setAttribute('data-upd', String(a.id));
  var mk = MARKS[a.id];
  if (mk && (UPDATING[a.id] || Date.now() - mk.at < MARK_KEEP)) {
    prog.hidden = false;
    prog.className = 'ag-tile-upd ' + mk.cls;
    prog.textContent = mk.words;
  }
  acts.appendChild(prog);
  t.appendChild(acts);
  if (otherProgram(a, d && d.shipped_code, d && d.shipped_codes)) {
    t.appendChild(el('div', 'note warn small ag-older', 'Another program than the one this acme ships - install the package of this version.'));
  }
  return t;
}

/* ==========================================================================
   1.0.120: the company enrollment code, the agents waiting for confirmation, Windows
   ========================================================================== */
/** A Windows or a Linux server, as a badge. */
function platformBadge(platform, small) {
  var win = platform === 'windows';
  var b = el('span', 'ag-os ' + (win ? 'win' : 'linux') + (small ? ' small' : ''));
  b.appendChild(icon(win ? 'windows' : 'terminal', small ? 12 : 13));
  b.appendChild(noI18n(el('span', '', win ? 'Windows' : 'Linux')));
  return b;
}
function windowsPackage(d) {
  var p = (d && d.package) || {};
  var w = p.windows || (d && d.windows) || null;
  return w && w.name ? w : null;
}
function msiName(d) {
  var w = windowsPackage(d);
  if (w) return String(w.name);
  var v = ((d && d.package) || {}).version || 'X.Y.Z';
  return 'acme-agent-' + v + '-windows-x64.msi';
}
/** The lines that install the agent on Windows (`code`: the join or the enrollment code). */
function windowsLines(d, code, withHash) {
  var name = msiName(d), c = code || 'CODE';
  var ol = el('ol', 'dbs-steps ag-steps ag-winsteps');
  var add = function (words, line, note) {
    var li = el('li', '');
    li.appendChild(el('span', '', words));
    if (line) li.appendChild(cmdBox(line, 'ag-wincmd'));
    if (note) li.appendChild(el('p', 'note small muted', note));
    ol.appendChild(li);
  };
  if (withHash) add('Check it is the same file (PowerShell):', 'Get-FileHash ' + name + ' -Algorithm SHA256');
  add('By hand: run the MSI - Next, Next, Install. At its Join step paste the code (or leave it empty and join later).', '',
    'The installer joins in the background: no network is needed while it installs, and acme-agent status says how it goes.');
  add('Silently, for many servers (Group Policy, Intune, SCCM):', 'msiexec /i ' + name + ' /qn JOINCODE=' + c,
    'Group Policy: a computer startup script with that line. Intune or SCCM: a Win32 app (or an application) whose install command is that line - every server then waits for confirmation here.');
  add('Or from the command line, in an elevated prompt (Run as administrator):', 'acme-agent join ' + c);
  return ol;
}
function linuxLines(code) {
  var ol = el('ol', 'dbs-steps ag-steps');
  var c = code || 'CODE';
  [['In the unpacked package, install and join at once:', 'sudo ./install.sh --join ' + c],
   ['Or, with the agent installed already:', 'sudo acme-agent join ' + c]].forEach(function (x) {
    var li = el('li', '');
    li.appendChild(el('span', '', x[0]));
    li.appendChild(cmdBox(x[1]));
    ol.appendChild(li);
  });
  return ol;
}
/** Linux | Windows: a choice of two, kept while the page is open. */
var OS_TAB = {pkg: 'linux', code: 'linux'};
function osTabs(which, draw) {
  var box = el('div', 'ag-ostabs');
  var seg = el('div', 'seg ag-osseg');
  seg.setAttribute('role', 'tablist');
  var body = el('div', 'ag-ostab-b');
  var show = function () {
    Array.prototype.forEach.call(seg.children, function (b) {
      var on = b.getAttribute('data-os') === OS_TAB[which];
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    clear(body);
    draw(body, OS_TAB[which]);
  };
  [['linux', 'terminal', 'Linux'], ['windows', 'windows', 'Windows']].forEach(function (x) {
    var b = el('button', '');
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('data-os', x[0]);
    b.appendChild(icon(x[1], 14));
    b.appendChild(noI18n(el('span', '', x[2])));
    b.onclick = function () { OS_TAB[which] = x[0]; show(); };
    seg.appendChild(b);
  });
  box.appendChild(seg);
  box.appendChild(body);
  show();
  return box;
}
function downloadMsi(button) {
  busy(button, true);
  ask('agents/package?platform=windows').then(function (d) {
    var raw = atob(d.data_b64), u8 = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) u8[i] = raw.charCodeAt(i);
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([u8], {type: d.mime || 'application/x-msi'}));
    a.download = d.filename || d.name || 'acme-agent-windows-x64.msi';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
  }).catch(oops).then(function () { busy(button, false); });
}
/** The Windows package's tile - or what says it comes with a release. */
function drawWindowsPackage(box, d) {
  var w = windowsPackage(d);
  if (!w) {
    var none = el('div', 'ag-pkg ag-pkg-none');
    var ic0 = noI18n(el('span', 'ag-pkg-ic'));
    ic0.innerHTML = iconMarkup('windows', 26);
    none.appendChild(ic0);
    var w0 = el('div', 'ag-pkg-w');
    w0.appendChild(el('b', '', 'The Windows installer comes with a release'));
    w0.appendChild(el('p', 'note small', 'A signed release carries ' + msiName(d) + ' beside the Linux package. This acme runs from a source tree, which has none - the lines below are what it will be.'));
    var why = ((d && d.package) || {}).windows_why || (d && d.windows_why);
    if (why) w0.appendChild(data('p', 'note small muted', String(why)));
    none.appendChild(w0);
    box.appendChild(none);
  } else {
    var tile = el('div', 'ag-pkg ag-pkg-win');
    var ic = noI18n(el('span', 'ag-pkg-ic'));
    ic.innerHTML = iconMarkup('windows', 26);
    tile.appendChild(ic);
    var ww = el('div', 'ag-pkg-w');
    var top = el('div', 'ag-pkg-top');
    top.appendChild(data('b', 'ag-pkg-name', w.name));
    var sig = el('span', 'ag-badge ' + (w.signed ? 'ok' : 'warn'));
    sig.appendChild(icon(w.signed ? 'shield' : 'flag', 13));
    sig.appendChild(el('span', '', w.signed ? 'signed by acme’s release key' : 'not signed'));
    top.appendChild(sig);
    ww.appendChild(top);
    var meta = el('div', 'ag-pkg-meta');
    meta.appendChild(el('span', '', 'version'));
    meta.appendChild(mono(String(w.version || '')));
    meta.appendChild(noI18n(el('span', 'muted', '·')));
    meta.appendChild(mono(bytes(w.size)));
    meta.appendChild(noI18n(el('span', 'muted', '·')));
    meta.appendChild(el('span', '', 'Windows Server 2016 and newer · x64'));
    ww.appendChild(meta);
    var sha = el('div', 'ag-sha');
    sha.appendChild(el('span', 'dbw-k', 'SHA-256'));
    var sv = mono(String(w.sha256 || ''), 'ag-sha-v');
    copyOnClick(sv, String(w.sha256 || ''), 'on the clipboard');
    sha.appendChild(sv);
    ww.appendChild(sha);
    tile.appendChild(ww);
    if (MANAGE) {
      var dl = cmdButton('Download MSI', 'download', 'primary');
      dl.onclick = function () { downloadMsi(dl); };
      tile.appendChild(dl);
    }
    box.appendChild(tile);
  }
  box.appendChild(el('h4', 'dbw-h', 'On the server, as an administrator'));
  box.appendChild(windowsLines(d, '', !!w));
  box.appendChild(el('p', 'note small muted', 'CODE is a join code made on one target’s card (ACAG1.…), or an enrollment code for many servers (ACAE1.…, below). The Windows agent takes the same commands as the Linux one: acme-agent allow, deny, policy, status, fingerprint, forget.'));
}

/** Settings → Target agents → Waiting for confirmation: every agent asking to join. */
var PICKED = {};
function drawWaiting(box, d) {
  var rows = arr(d.waiting);
  if (!rows.length) return;
  var ids = {};
  rows.forEach(function (r) { ids[r.id] = r.fp; });
  Object.keys(PICKED).forEach(function (k) { if (ids[k] !== PICKED[k]) delete PICKED[k]; });
  var h = el('h2', 'ag-list-h ag-wait-h');
  h.appendChild(document.createTextNode('Waiting for confirmation'));
  h.appendChild(noI18n(el('span', 'count warn', String(rows.length))));
  var sel = null;
  if (FULL) {
    sel = cmdButton('Confirm selected…', 'check', 'small primary');
    sel.onclick = function () { confirmMany(rows.filter(function (r) { return PICKED[r.id]; }), ''); };
    h.appendChild(sel);
  }
  box.appendChild(h);
  box.appendChild(el('p', 'note', 'Each agent below asks to join. Compare its fingerprint with the one the server printed (acme-agent join, or acme-agent fingerprint there) - confirm only when every group is the same. Until then acme sends it nothing.'));
  var count = function () {
    if (!sel) return;
    var n = rows.filter(function (r) { return PICKED[r.id]; }).length;
    sel.disabled = !n;
    var s = sel.querySelector('span:last-child') || sel;
    s.textContent = n ? tr('Confirm selected ({0})…').replace('{0}', n) : tr('Confirm selected…');
  };
  /* by the enrollment code they came with; the targets' own join codes last */
  var groups = [], byKey = {};
  rows.forEach(function (r) {
    var k = r.enroll ? 'e:' + r.enroll.id : 'own';
    if (!byKey[k]) { byKey[k] = {key: k, enroll: r.enroll, rows: []}; groups.push(byKey[k]); }
    byKey[k].rows.push(r);
  });
  groups.sort(function (a, b) { return (a.key === 'own') - (b.key === 'own'); });
  groups.forEach(function (g) {
    var gb = el('div', 'ag-wgroup');
    var gh = el('div', 'ag-wgroup-h');
    if (FULL) {
      var all = document.createElement('input');
      all.type = 'checkbox';
      all.className = 'ag-wpick-all';
      all.setAttribute('aria-label', tr('Select all of them'));
      all.checked = g.rows.every(function (r) { return PICKED[r.id]; });
      all.onchange = function () {
        g.rows.forEach(function (r) { if (all.checked) PICKED[r.id] = r.fp; else delete PICKED[r.id]; });
        Array.prototype.forEach.call(gb.querySelectorAll('.ag-wpick'), function (c) { c.checked = all.checked; });
        count();
      };
      gh.appendChild(all);
    }
    gh.appendChild(icon(g.enroll ? 'people' : 'key', 15));
    if (g.enroll) gh.appendChild(el('span', 'ag-wgroup-k', 'Joined with the code'));
    var tc = el('span', 'ag-wgroup-tc');
    if (g.enroll) tc.appendChild(data('b', 'ag-wgroup-t', g.enroll.title || g.enroll.id));
    else tc.appendChild(el('b', 'ag-wgroup-t', 'Each with its target’s own join code'));
    tc.appendChild(noI18n(el('span', 'count', String(g.rows.length))));
    gh.appendChild(tc);
    if (FULL && g.enroll && g.rows.length > 1) {
      var ab = cmdButton('Confirm all of this code…', 'check', 'small');
      ab.onclick = function () { confirmMany(g.rows, g.enroll.title || g.enroll.id); };
      gh.appendChild(ab);
    }
    gb.appendChild(gh);
    g.rows.forEach(function (r) { gb.appendChild(waitRow(r, count)); });
    box.appendChild(gb);
  });
  count();
}
function waitRow(r, count) {
  var row = el('div', 'ag-wrow' + (FULL ? '' : ' ro'));
  if (FULL) {
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'ag-wpick';
    cb.setAttribute('aria-label', r.name);
    cb.checked = !!PICKED[r.id];
    cb.onchange = function () { if (cb.checked) PICKED[r.id] = r.fp; else delete PICKED[r.id]; count(); };
    row.appendChild(cb);
  }
  var who = el('div', 'ag-wwho');
  var top = el('div', 'ag-wtop');
  var name = el('button', 'ag-name');
  name.type = 'button';
  name.appendChild(data('span', 'dbs-tile-n', r.name));
  name.onclick = function () { if (H.openTarget) H.openTarget(r.name); };
  top.appendChild(name);
  top.appendChild(platformBadge(r.platform, true));
  top.appendChild(modeBadge(r.mode));
  who.appendChild(top);
  var meta = el('div', 'ag-wmeta');
  if (r.fqdn || r.host) meta.appendChild(mono(String(r.fqdn || r.host), 'ag-host'));
  if (r.ip) { var ip = el('span', 'ag-wip'); ip.appendChild(el('span', 'muted', 'from')); ip.appendChild(mono(' ' + r.ip)); meta.appendChild(ip); }
  if (r.os) meta.appendChild(data('span', 'ag-wos', String(r.os)));
  if (r.at) meta.appendChild(el('span', 'muted', ago(r.at)));
  who.appendChild(meta);
  row.appendChild(who);
  row.appendChild(fpBig(r.fp, 'small ag-wfp'));
  if (FULL) {
    var ok = cmdButton('Confirm…', 'check', 'small');
    ok.onclick = function () { confirmOne(r); };
    row.appendChild(ok);
  }
  return row;
}
function confirmOne(r) {
  modal(tr('Confirm the agent of {0}').replace('{0}', r.name), function (body) {
    var h = el('div', 'ag-confirm-h');
    h.appendChild(platformBadge(r.platform));
    if (r.fqdn || r.host) h.appendChild(mono(String(r.fqdn || r.host), 'ag-host'));
    if (r.ip) h.appendChild(mono(String(r.ip), 'ag-host'));
    if (r.os) h.appendChild(data('span', 'muted small', String(r.os)));
    body.appendChild(h);
    body.appendChild(el('p', 'note', 'Compare this fingerprint with the one the server printed. Confirm only when every group is the same.'));
    body.appendChild(fpBig(r.fp));
  }, [{words: 'Close', close: true}, {words: 'It is the same - confirm', cls: 'primary', icon: 'check', close: true, go: function () {
    ask('agents/confirm', {id: r.id, fp: r.fp}, 90).then(function (x) {
      if (x && x.said) toast(String(x.said), 'bad'); else toast('the agent is confirmed', 'good');
      delete PICKED[r.id];
      pane(true);
    }).catch(oops);
  }}], 'medium');
}
/** Several confirmed at once - asked first, each fingerprint listed. */
function confirmMany(list, codeTitle) {
  if (!list.length) return;
  modal(codeTitle ? tr('Confirm all of {0}').replace('{0}', codeTitle) : tr('Confirm {0} agents').replace('{0}', list.length), function (body) {
    body.appendChild(el('p', 'note', 'Each of these servers gets its certificate and acme sends it jobs from now on. Compare each fingerprint with the one its server printed first - confirm only servers you know.'));
    var l = el('div', 'ag-many');
    list.forEach(function (r) {
      var one = el('div', 'ag-many-one');
      var t = el('div', 'ag-wtop');
      t.appendChild(data('b', '', r.name));
      t.appendChild(platformBadge(r.platform, true));
      if (r.fqdn || r.host) t.appendChild(mono(String(r.fqdn || r.host), 'ag-host'));
      if (r.ip) t.appendChild(mono(String(r.ip), 'muted small'));
      one.appendChild(t);
      one.appendChild(fpBig(r.fp, 'small'));
      l.appendChild(one);
    });
    body.appendChild(l);
  }, [{words: 'Close', close: true}, {words: list.length === 1 ? tr('Confirm 1 agent') : tr('Confirm {0} agents').replace('{0}', list.length), cls: 'primary', icon: 'check', close: true, go: function () {
    ask('agents/confirm-many', {items: list.map(function (r) { return {id: r.id, fp: r.fp}; })}, 300).then(function (x) {
      var bad = arr(x && x.rows).filter(function (y) { return !y.ok; });
      list.forEach(function (r) { delete PICKED[r.id]; });
      if (bad.length) toast(bad.map(function (y) { return (y.name || y.id) + ': ' + y.said; }).join('; '), 'bad');
      else toast(tr('{0} confirmed').replace('{0}', (x && x.confirmed) || list.length), 'good');
      pane(true);
    }).catch(oops);
  }}], 'medium');
}

/** Settings → Target agents → Enrollment codes. */
var ESTATE = {active: ['active', 'ok'], expired: ['ran out', 'dim'], used: ['used up', 'dim'], revoked: ['revoked', 'bad']};
function drawEnroll(box, d) {
  var codes = arr(d.enroll);
  var h = el('h2', 'ag-list-h');
  h.appendChild(document.createTextNode('Enrollment codes'));
  h.appendChild(noI18n(el('span', 'count', String(codes.length))));
  if (FULL) {
    var mk = cmdButton('Make an enrollment code…', 'add', 'small primary');
    mk.disabled = !d.active;
    if (!d.active) mk.title = tr('Switch on active mode above first');
    mk.onclick = function () { enrollDialog(d); };
    h.appendChild(mk);
  }
  box.appendChild(h);
  var lead = el('div', 'ag-enroll-lead');
  lead.appendChild(icon('people', 22));
  var lw = el('div', '');
  lw.appendChild(el('b', '', 'One code for many servers'));
  lw.appendChild(el('p', 'note small', 'Use it to install the agent on as many servers as you like - by hand, or with Group Policy, Intune, SCCM or Ansible. Each server appears here as a target of its own, waiting for your confirmation; confirm them one by one or many at once.'));
  lead.appendChild(lw);
  box.appendChild(lead);
  if (!d.active) box.appendChild(el('p', 'note warn small', 'An enrolling agent always asks acme on the agents’ port: switch on “Agents may connect to acme” above first.'));
  if (!codes.length) {
    var e = el('div', 'ag-empty');
    e.appendChild(icon('people', 28));
    e.appendChild(el('b', '', 'No enrollment code yet'));
    box.appendChild(e);
    return;
  }
  var list = el('div', 'ag-codes');
  codes.forEach(function (c) { list.appendChild(codeRow(c)); });
  box.appendChild(list);
}
function codeRow(c) {
  var st = ESTATE[c.state] || [c.state, 'dim'];
  var r = el('div', 'ag-erow ' + st[1]);
  var top = el('div', 'ag-etop');
  top.appendChild(data('b', 'ag-etitle', c.title || c.id));
  var sb = el('span', 'ag-badge ' + st[1]);
  sb.appendChild(el('span', '', st[0]));
  top.appendChild(sb);
  top.appendChild(modeBadge(c.mode));
  if (c.auto) {
    var au = el('span', 'ag-badge bad');
    au.appendChild(icon('flag', 12));
    au.appendChild(el('span', '', 'confirmed automatically'));
    explain(au, 'Each server that joins with it is confirmed at once - nobody compares its fingerprint.');
    top.appendChild(au);
  }
  r.appendChild(top);
  var k = el('div', 'dbs-kvs ag-ekvs');
  var used = el('div', 'ag-uses');
  var bar = el('span', 'ag-uses-bar');
  var fill = el('span', '');
  fill.style.width = Math.min(100, Math.round(100 * Number(c.uses || 0) / Math.max(1, Number(c.most || 1)))) + '%';
  bar.appendChild(fill);
  used.appendChild(bar);
  used.appendChild(document.createTextNode(tr('{0} of {1}').replace('{0}', c.uses || 0).replace('{1}', c.most || 1)));
  k.appendChild(kv('Servers', used));
  k.appendChild(kv(c.state === 'active' ? 'Valid until' : 'Was valid until', when(c.until)));
  var by = el('span', '');
  by.appendChild(data('span', '', String(c.by || '–')));
  by.appendChild(noI18n(el('span', 'muted', ' · ')));
  by.appendChild(el('span', 'muted', when(c.at)));
  k.appendChild(kv('Who made it', by));
  if (c.mode === 'passive' && c.port) k.appendChild(kv('Their port', mono(String(c.port))));
  if (c.state === 'revoked' && c.revoked_by) k.appendChild(kv('Revoked by', data('span', '', String(c.revoked_by))));
  r.appendChild(k);
  if (arr(c.targets).length) {
    var ts = el('div', 'ag-etargets');
    arr(c.targets).slice(0, 24).forEach(function (n) {
      var b = el('button', 'ag-etarget');
      b.type = 'button';
      b.appendChild(noI18n(document.createTextNode(n)));
      b.onclick = function () { if (H.openTarget) H.openTarget(n); };
      ts.appendChild(b);
    });
    if (arr(c.targets).length > 24) ts.appendChild(noI18n(el('span', 'muted small', '+' + (arr(c.targets).length - 24))));
    r.appendChild(ts);
  }
  if (FULL && c.state === 'active') {
    var acts = el('div', 'btnrow ag-eacts');
    var rv = cmdButton('Revoke…', 'ban', 'small danger');
    rv.onclick = function () {
      confirmThen(tr('Revoke the enrollment code'), esc(tr('No other server joins with “{0}”. The servers that joined with it stay; those waiting still wait for confirmation.').replace('{0}', c.title || c.id)), 'Revoke it', function () {
        return ask('agents/enroll/revoke', {id: c.id}).then(function () { toast('the enrollment code is revoked', 'good'); pane(true); }).catch(oops);
      });
    };
    acts.appendChild(rv);
    r.appendChild(acts);
  }
  return r;
}
function numBox(value, min, max) {
  var i = el('input', 'ag-num');
  i.type = 'number';
  i.min = String(min);
  i.max = String(max);
  i.step = '1';
  i.value = String(value);
  return i;
}
/** Make an enrollment code: its title, mode, port, days, servers, and confirming
    automatically (off; red while on) - then the code, shown once, with the lines. */
function enrollDialog(d) {
  var F = {title: '', mode: 'passive', port: 8446, days: 7, most: 10, auto: false};
  var made = null;
  var paint = function () {
    if (made) return shown();
    modal('Make an enrollment code', function (body) {
      body.appendChild(el('p', 'note', 'One code for many servers: each server that joins with it becomes a target of its own (its host name) and waits here for its fingerprint to be confirmed.'));
      var g = el('div', 'ag-eform');
      var t = textBox(F.title, tr('e.g. Branch offices 2026'));
      t.maxLength = 80;
      t.oninput = function () { F.title = t.value; };
      g.appendChild(formField('Its title', t, 'What you call it - the targets it makes and Events say it.'));
      var seg = el('div', 'seg ag-eseg');
      var port = numBox(F.port, 1, 65535);
      var portF = formField('Their port', port, 'Where each agent listens for acme (passive).');
      [['passive', 'Passive - acme connects to them'], ['active', 'Active - they connect to acme']].forEach(function (o) {
        var b = el('button', F.mode === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () {
          F.mode = o[0];
          Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); });
          portF.hidden = F.mode !== 'passive';
        };
        seg.appendChild(b);
      });
      g.appendChild(formField('Mode', seg, 'Passive: each agent listens (open its port to acme only). Active: nothing listens on the servers, they ask acme on the agents’ port.'));
      port.oninput = function () { F.port = port.value; };
      portF.hidden = F.mode !== 'passive';
      g.appendChild(portF);
      var days = numBox(F.days, 1, 365);
      days.oninput = function () { F.days = days.value; };
      g.appendChild(formField('Valid for (days)', days, '1 to 365. Servers that joined stay joined after it ends.'));
      var most = numBox(F.most, 1, 10000);
      most.oninput = function () { F.most = most.value; };
      g.appendChild(formField('At most (servers)', most, 'How many servers may join with it - the same server again does not count twice.'));
      var sw = switchBox(F.auto);
      sw.classList.add('ag-sw-red');
      var warn = el('div', 'ag-auto-warn');
      warn.appendChild(icon('flag', 16));
      warn.appendChild(el('span', '', 'Anybody who has this code joins a server to acme without anyone comparing its fingerprint - and gets the certificates deployed to it. Only for a code that never leaves your deployment tooling, for a short time.'));
      warn.hidden = !F.auto;
      sw._input.onchange = function () { F.auto = !!sw._get(); warn.hidden = !F.auto; };
      g.appendChild(formField('Confirm automatically', sw, 'Off (the default): a person confirms each server here.'));
      g.appendChild(warn);
      body.appendChild(g);
    }, [{words: 'Close', close: true}, {words: 'Make the code', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      ask('agents/enroll', {title: F.title, mode: F.mode, port: Number(F.port || 8446), days: Number(F.days || 7), most: Number(F.most || 10), auto: !!F.auto}).then(function (x) {
        made = x;
        pane(true);
        paint();
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  };
  var shown = function () {
    modal('The enrollment code', function (body) {
      var hd = el('div', 'ag-made');
      hd.appendChild(icon('check', 22));
      var hw = el('div', '');
      hw.appendChild(data('b', '', made.title));
      var sub = el('div', 'ag-made-sub');
      sub.appendChild(modeBadge(made.mode));
      sub.appendChild(el('span', '', tr('valid until {0}').replace('{0}', when(made.until))));
      sub.appendChild(noI18n(el('span', 'muted', '·')));
      sub.appendChild(el('span', '', tr('at most {0} servers').replace('{0}', made.most)));
      if (made.auto) { var a = el('span', 'ag-badge bad'); a.appendChild(el('span', '', 'confirmed automatically')); sub.appendChild(a); }
      hw.appendChild(sub);
      hd.appendChild(hw);
      body.appendChild(hd);
      var code = el('div', 'ag-code');
      code.appendChild(noI18n(el('pre', 'mono', made.code)));
      var cp = cmdButton('Copy', 'copy', 'small');
      cp.onclick = function () { copyText(made.code, cp, 'on the clipboard'); };
      code.appendChild(cp);
      body.appendChild(code);
      var once = el('div', 'ag-code-left');
      once.appendChild(icon('eyeoff', 14));
      once.appendChild(el('span', '', 'Shown this once - copy it now. Keep it as a password: whoever has it can ask to join servers.'));
      body.appendChild(once);
      body.appendChild(el('h4', 'dbw-h', 'On each server'));
      body.appendChild(osTabs('code', function (host, os) {
        if (os === 'windows') host.appendChild(windowsLines(PANE.last || {}, made.code, false));
        else host.appendChild(linuxLines(made.code));
      }));
    }, [{words: 'Close', close: true}], 'medium');
  };
  paint();
}

/* ==========================================================================
   The agent's card on a target (its form, and its detail)
   ========================================================================== */
function card(row, opts) {
  opts = opts || {};
  var box = el('div', 'ag-card');
  var ticket = {n: 0, timer: null};
  function load(look, button) {
    if (look) ticket.fresh = true;
    var n = ++ticket.n;
    if (button) busy(button, true);
    var p = look ? ask('agents/look', {id: row.id}, 60).then(function (x) { return x.agent; })
      : ask('agents/one?id=' + encodeURIComponent(row.id));
    return p.then(function (a) {
      if (n !== ticket.n || !box.isConnected && n > 1) return;
      draw(a);
      if (a.said) toast(String(a.said), 'bad');
    }).catch(function (e) {
      clear(box);
      box.appendChild(el('p', 'ct-bad', String((e && e.message) || e)));
    }).then(function () { if (button) busy(button, false); });
  }
  function draw(a) {
    clear(box);
    var head = el('div', 'ag-card-head');
    head.appendChild(icon('terminal', 20));
    head.appendChild(el('b', '', 'acme-agent'));
    head.appendChild(modeBadge(a.mode));
    if (a.platform === 'windows' || row.kind === 'agent_windows') head.appendChild(platformBadge('windows', true));
    var sp = el('span', 'ag-card-st');
    sp.appendChild(statePill(a));
    head.appendChild(sp);
    box.appendChild(head);
    if (a.pending && !a.pending.confirmed) box.appendChild(confirmBox(row, a, function () { load(true); }));
    if (!a.joined && !a.pending) {
      var j = el('div', 'ag-join-cta');
      j.appendChild(el('p', 'note', a.code_until
        ? 'A join code is waiting to be used on the server (until ' + when(a.code_until) + ').'
        : 'No agent has joined yet: install it on the server and join it with a one-time code.'));
      box.appendChild(j);
    }
    var k = el('div', 'dbs-kvs ag-kvs');
    k.appendChild(kv('Server', a.agent_host || a.host ? mono(String(a.agent_host || a.host)) : '–'));
    k.appendChild(kv('Agent', a.version ? mono(a.version) : '–'));
    k.appendChild(kv('Last heard', a.last_seen ? ago(a.last_seen) : 'never'));
    k.appendChild(kv('Its certificate ends', certEnd(a.cert_end)));
    if (a.os && !sysOf(a)) k.appendChild(kv('System', data('span', '', a.os)));
    if (a.agent_id) k.appendChild(kv('Agent id', mono(a.agent_id)));
    if (a.via) k.appendChild(kv('Reached through', mono(a.via)));
    if (a.key_fp) {
      var kf = mono(grouped(a.key_fp).slice(0, 4).join(' ') + ' …', 'ag-kfp');
      explain(kf, grouped(a.key_fp).join(' '));
      k.appendChild(kv('Its key', kf));
    }
    box.appendChild(k);
    /* 1.0.120: what the agent tells about its server */
    if (a.joined) box.appendChild(sysPanel(row, a, function (b) { load(true, b); }));
    /* 1.0.125: what the server runs that takes certificates (only where its policy allows it) */
    if (a.joined) box.appendChild(discoverBox(row, a, {reopen: opts.reopen, done: function () { load(false); }}));
    if (otherProgram(a, a.shipped_code, a.shipped_codes)) {
      box.appendChild(el('div', 'note warn small', 'The agent runs another program than the one this acme ships - install the package of this version (Settings → Target agents).'));
    }
    if (a.last_error && a.state !== 'answers') {
      var le = el('div', 'note bad small ag-err');
      le.appendChild(data('span', '', String(a.last_error)));
      box.appendChild(le);
    }
    if (a.blocked) box.appendChild(blockedBox(a));
    if (a.update && a.update.newer) box.appendChild(updateBox(row, a, function () { load(false); }));
    if (a.joined) box.appendChild(keysBox(row, a));
    if (a.joined) box.appendChild(policyView(a.policy, a.policy_at));
    if (a.design) box.appendChild(designBox(row, a, function () { load(false); }));
    var bar = el('div', 'btnrow ag-acts');
    if (FULL) {
      var jb = cmdButton(a.joined ? 'Join again…' : 'Join the agent…', a.joined ? 'refresh' : 'add', a.joined ? 'small' : 'primary small');
      jb.onclick = function () { wizard(row, a, function () { load(false); }); };
      bar.appendChild(jb);
    }
    if (MANAGE && (a.joined || a.mode === 'passive' && a.code_until)) {
      var lb = cmdButton(a.joined ? 'Ask it now' : 'Look for it now', 'play', 'small');
      lb.onclick = function () { load(true, lb); };
      bar.appendChild(lb);
    }
    if (FULL && a.joined) {
      var rb = cmdButton('Renew its certificate', 'key', 'small');
      rb.onclick = function () {
        busy(rb, true);
        ask('agents/renew', {id: row.id}, 300).then(function () { toast('its certificate is renewed', 'good'); load(false); })
          .catch(oops).then(function () { busy(rb, false); });
      };
      bar.appendChild(rb);
      var fb = cmdButton('Forget…', 'forget', 'small danger');
      fb.onclick = function () {
        var back = function () { if (opts.reopen) opts.reopen(); };
        confirmThen('Forget the agent', 'The agent of this target is no longer let in: its certificate is refused at once and its key, policy and state are gone from acme. On the server, <code>acme-agent forget</code> takes its side away. To use it again: join it again.', 'Forget it', function () {
          return ask('agents/forget', {id: row.id}).then(function () { toast('forgotten', 'good'); back(); }).catch(oops);
        });
      };
      bar.appendChild(fb);
    }
    if (a.joined || a.design) bar.appendChild(designButton(row, {done: function () { load(false); }, back: opts.reopen}));
    if (bar.childNodes.length) box.appendChild(bar);
    explainWhatWasDrawn(box);
    /* 1.0.118: the policy said more than a minute ago is asked again by itself - the card never
       shows an old one ("Nothing is allowed yet" while the server allowed self-update) */
    if (!ticket.fresh && MANAGE && a.joined && a.state === 'answers' && (!a.policy_at || Date.now() / 1000 - Number(a.policy_at) > 60)) {
      ticket.fresh = true;
      var n = ++ticket.n;
      ask('agents/look', {id: row.id}, 60).then(function (x) {
        if (n === ticket.n && box.isConnected && x && x.agent && !x.agent.said) draw(x.agent);
      }).catch(function () { });
    }
  }
  box.appendChild(el('p', 'muted', 'Asking…'));
  load(false);
  return box;
}
/** A newer agent offered (phase 4): sent from here where its policy allows it, else the way
    to install it - and the line that would let acme do it. */
function updateBox(row, a, done) {
  var u = a.update || {};
  var box = el('div', 'ag-upd' + (u.allowed ? ' can' : ''));
  var ic = noI18n(el('span', 'ag-upd-ic'));
  ic.innerHTML = iconMarkup('up', 20);
  box.appendChild(ic);
  var w = el('div', 'ag-upd-w');
  var h = el('div', 'ag-upd-h');
  h.appendChild(el('b', '', 'A newer agent is offered'));
  var vv = el('span', 'ag-vers');
  vv.appendChild(mono(String(a.version || '?'), 'ag-ver old'));
  vv.appendChild(noI18n(el('span', 'ag-ver-arrow', '→')));
  vv.appendChild(mono(String(u.offered || '?'), 'ag-ver new'));
  h.appendChild(vv);
  w.appendChild(h);
  if (u.allowed) {
    w.appendChild(el('p', 'note small', u.signed
      ? 'Its policy lets acme update it: the package signed by acme’s release key is sent; the agent checks the signature with the key it was installed with and that the version is newer, then starts again.'
      : 'Its policy lets acme update it, but this acme has no signed package (a source tree): install a release package on the server.'));
    w.appendChild(el('p', 'note small muted', 'The package comes from this acme itself - the signed agent it ships - never from the internet.'));
    if (FULL && u.signed) {
      var b = cmdButton('Update the agent now', 'up', 'primary');
      var prog = el('div', 'ag-upd-prog');
      prog.hidden = true;
      b.onclick = function () {
        confirmThen('Update the agent of ' + row.name, 'acme sends the agent ' + esc(String(u.offered || '')) + ' it ships, signed by its release key. The agent checks the signature with the key it was installed with and that it is newer, puts it in place and starts again - a few seconds without it.', 'Update it now', function () {
          busy(b, true);
          prog.hidden = false;
          clear(prog);
          prog.appendChild(el('span', 'ag-spin'));
          prog.appendChild(el('span', '', 'Sending the package and waiting for the agent…'));
          ask('agents/update', {id: row.id}, 240).then(function (x) {
            toast(String((x && x.said) || 'updated'), 'good');
            clear(prog);
            prog.appendChild(el('span', 'ag-spin'));
            prog.appendChild(el('span', '', 'Updated - waiting for it to answer again…'));
            return waitVersion(row, String(u.offered || ''));
          }).then(function () { done(); }).catch(function (e) { prog.hidden = true; oops(e); }).then(function () { busy(b, false); });
        }, false);
      };
      var br = el('div', 'btnrow');
      br.appendChild(b);
      w.appendChild(br);
      w.appendChild(prog);
    }
  } else {
    w.appendChild(el('p', 'note small', 'Its policy does not let acme update it: install the package on the server (Settings → Target agents), or allow acme to send it - only a package signed by the release key, only a newer version:'));
    /* hunt R1: a Windows server has no sudo - the line in an elevated prompt there */
    w.appendChild(cmdBox(selfUpdateLine(a.platform === 'windows' || row.kind === 'agent_windows'), 'small'));
  }
  if (u.last && u.last.ok === false) w.appendChild(data('div', 'note bad small', String(u.last.said || '')));
  box.appendChild(w);
  return box;
}
function selfUpdateLine(win) { return (win ? '' : 'sudo ') + 'acme-agent allow self-update'; }
function esc(t) { return String(t).replace(/[&<>"]/g, function (c) { return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]; }); }
/** After an update: the agent asked until it says the version sent (a minute at most). */
function waitVersion(row, want) {
  var end = Date.now() + 60000;
  return new Promise(function (resolve) {
    var once = function () {
      ask('agents/look', {id: row.id}, 30).then(function (x) {
        if ((x && x.agent && x.agent.version) === want || Date.now() > end) resolve(x); else setTimeout(once, 2500);
      }).catch(function () { if (Date.now() > end) resolve(null); else setTimeout(once, 2500); });
    };
    setTimeout(once, 2000);
  });
}
/** Several agents updated one by one (Settings → Target agents: Update all agents, or a
    tile's Update), each tile saying how it goes. */
function updateMany(list) {
  var mark = function (id, cls, words) {
    MARKS[id] = {cls: cls, words: words, at: Date.now()};
    var p = document.querySelector('[data-upd="' + id + '"]');
    if (!p) return;
    p.hidden = false;
    p.className = 'ag-tile-upd ' + cls;
    p.textContent = words;
  };
  var todo = list.filter(function (x) { return x.ok && !UPDATING[x.id]; });
  todo.forEach(function (x) { UPDATING[x.id] = 1; });
  var step = function (i) {
    if (i >= todo.length) { pane(true); return; }
    var x = todo[i];
    mark(x.id, 'run', tr('updating…'));
    ask('agents/update', {id: x.id}, 240).then(function () {
      mark(x.id, 'run', tr('waiting for it to answer…'));
      return waitVersion(x, String(x.offered || ''));
    }).then(function (got) {
      var v = got && got.agent && got.agent.version;
      mark(x.id, v === x.offered ? 'ok' : 'bad', v === x.offered ? tr('updated to') + ' ' + v : tr('sent - it has not answered with the new version yet'));
    }).catch(function (e) { mark(x.id, 'bad', String((e && e.message) || e)); }).then(function () { delete UPDATING[x.id]; step(i + 1); });
  };
  step(0);
}
function tr(w) { return typeof i18nText === 'function' ? (i18nText(w) || w) : w; }
function updateAll() {
  ask('agents/updates').then(function (d) {
    var rows = arr(d.rows), can = rows.filter(function (x) { return x.ok; });
    var go = function () {
      modal('Update all agents', function (body) {
        body.appendChild(el('p', 'note', 'Each agent below runs an older version than the one this acme ships. acme sends its own signed package - never one from the internet - to those whose policy allows it, one by one; each checks the signature and starts again.'));
        var l = el('div', 'ag-upd-all');
        if (!rows.length) l.appendChild(el('p', 'muted', 'Every agent runs the version this acme ships.'));
        rows.forEach(function (x) {
          var r = el('div', 'ag-upd-one' + (x.ok ? '' : ' no'));
          r.appendChild(el('span', 'dot ' + (x.ok ? 'ok' : 'off')));
          r.appendChild(data('b', '', x.name));
          var vv = el('span', 'ag-vers');
          vv.appendChild(mono(String(x.version || '?'), 'ag-ver old'));
          vv.appendChild(noI18n(el('span', 'ag-ver-arrow', '→')));
          vv.appendChild(mono(String(x.offered || '?'), 'ag-ver new'));
          r.appendChild(vv);
          r.appendChild(el('span', 'tag ' + (x.ok ? 'ok' : 'dim'), x.ok ? 'will be updated' : 'not updated'));
          if (!x.ok) r.appendChild(el('span', 'why', String(x.why || '')));
          /* what lets acme do it, to copy for the server */
          if (!x.ok && /allow self-update/.test(String(x.why || ''))) r.appendChild(cmdBox(selfUpdateLine(x.platform === 'windows'), 'small ag-upd-line'));
          l.appendChild(r);
        });
        body.appendChild(l);
      /* the button that starts it is always there (it was missing when no agent could be
         updated now - a popup with Close only): offered but not pressed when none can be, the
         reasons said by each agent above and in its title */
      }, [{words: 'Close', close: true}, {words: can.length > 1 ? 'Update ' + can.length + ' agents' : (can.length ? 'Update 1 agent' : 'Update all agents'),
        cls: 'primary', icon: 'up', close: true, disabled: !can.length,
        title: can.length ? '' : rows.map(function (x) { return String(x.why || ''); }).filter(function (w, i, a) { return w && a.indexOf(w) === i; }).join('; ') || 'Every agent runs the version this acme ships.',
        go: function () { updateMany(can); }}], 'medium');
    };
    go();
  }).catch(oops);
}
/** The policy designed in acme for this agent (1.0.118) - documentation only: the title, the
    note, who saved it, and whether the server's policy (as the agent last said it) is it. */
function designBox(row, a, reload) {
  var D = a.design || {};
  var box = el('div', 'ag-design');
  var fill = function (D) {
    clear(box);
    var c = D.compare || {state: D.state || 'unknown', added: [], removed: []};
    box.className = 'ag-design ' + (c.state || 'unknown');
    var h = el('div', 'ag-design-h');
    h.appendChild(icon('shield', 16));
    h.appendChild(el('b', '', 'Its saved design'));
    if (D.title) h.appendChild(data('span', 'ag-design-t', D.title));
    var st = el('span', 'ag-badge ' + (c.state === 'matches' ? 'ok' : (c.state === 'differs' ? 'warn' : 'dim')));
    st.appendChild(el('span', '', c.state === 'matches' ? 'the server’s policy matches the saved design'
      : (c.state === 'differs' ? 'the server’s policy differs from it' : 'not asked yet')));
    h.appendChild(st);
    box.appendChild(h);
    var m = el('div', 'ag-design-meta');
    m.appendChild(noI18n(el('span', '', 'v' + (D.n || '?') + ' · ')));
    m.appendChild(el('span', '', 'saved'));
    m.appendChild(document.createTextNode(' ' + when(D.at) + ' · '));
    m.appendChild(data('span', '', String(D.by || '')));
    box.appendChild(m);
    if (D.note) box.appendChild(data('p', 'ag-design-note', D.note));
    if (c.state === 'differs' && arr(c.added).length + arr(c.removed).length) {
      var pre = noI18n(el('pre', 'ag-design-diff mono'));
      arr(c.added).forEach(function (x) { var s = el('span', 'pb-d add'); s.textContent = '+ ' + x + '\n'; pre.appendChild(s); });
      arr(c.removed).forEach(function (x) { var s = el('span', 'pb-d del'); s.textContent = '- ' + x + '\n'; pre.appendChild(s); });
      box.appendChild(el('span', 'small muted', '+ only in the design (to apply on the server) · - only on the server'));
      box.appendChild(pre);
    }
    var bar = el('div', 'btnrow');
    var ob = cmdButton('Open in the builder', 'edit', 'small');
    ob.onclick = function () { builder(row, {from: 'design', done: reload}); };
    bar.appendChild(ob);
    var cb = cmdButton('Copy policy', 'copy', 'small');
    cb.onclick = function () { copyText(String(D.text || ''), cb, 'on the clipboard'); };
    bar.appendChild(cb);
    var db = cmdButton('Download', 'download', 'small');
    db.onclick = function () {
      var x = document.createElement('a');
      x.href = URL.createObjectURL(new Blob([String(D.text || '')], {type: 'text/plain'}));
      x.download = 'policy';
      document.body.appendChild(x);
      x.click();
      setTimeout(function () { URL.revokeObjectURL(x.href); x.remove(); }, 2000);
    };
    bar.appendChild(db);
    if (FULL) {
      var del = cmdButton('Delete design…', 'trash', 'small danger');
      del.onclick = function () {
        confirmThen('Delete the saved design', 'The design kept in acme for this agent - every version of it - is deleted. The policy on the server does not change: acme never sent it.', 'Delete it', function () {
          return ask('agents/design/forget', {id: row.id}).then(function () { toast('the design is deleted', 'good'); if (reload) reload(); }).catch(oops);
        });
      };
      bar.appendChild(del);
    }
    box.appendChild(bar);
    var hist = arr(D.history);
    if (hist.length > 1) {
      var det = el('details', 'ag-design-hist');
      det.appendChild(el('summary', '', 'Earlier versions'));
      hist.slice(1).forEach(function (v) {
        var r = el('div', 'ag-design-v');
        r.appendChild(noI18n(el('b', '', 'v' + v.n)));
        if (v.title) r.appendChild(data('span', '', v.title));
        r.appendChild(el('span', 'muted small', when(v.at)));
        r.appendChild(data('span', 'muted small', String(v.by || '')));
        var o = cmdButton('Open', 'edit', 'small');
        o.onclick = function () { builder(row, {state: v.state, text: v.text, done: reload}); };
        r.appendChild(o);
        det.appendChild(r);
      });
      box.appendChild(det);
    }
  };
  if (D.text !== undefined) fill(D);
  else {
    fill(D);
    ask('agents/design?id=' + encodeURIComponent(row.id)).then(function (x) { if (x && x.design) fill(x.design); }).catch(function () { });
  }
  return box;
}
/** The last deployment its policy refused (an alert until one goes through). */
function blockedBox(a) {
  var b = a.blocked || {};
  var box = el('div', 'ag-blocked');
  var h = el('div', 'ag-blocked-h');
  h.appendChild(icon('flag', 16));
  h.appendChild(el('b', '', 'Its policy blocked the last deployment'));
  if (b.at) { h.appendChild(noI18n(el('span', 'muted small', ' · '))); h.appendChild(el('span', 'muted small', ago(b.at))); }
  box.appendChild(h);
  if (b.what) box.appendChild(mono(String(b.what), 'ag-blocked-what'));
  var lines = arr(b.allow).filter(Boolean).map(function (x) { return 'sudo ' + x; });
  if (lines.length) {
    box.appendChild(el('span', 'dbw-k', 'Allow it on the server, as root'));
    box.appendChild(cmdBox(lines.join('\n'), 'small'));
  }
  return box;
}
/** The keys its agent makes (phase 3): the certificates, and a new one made so. */
function keysBox(row, a) {
  var box = el('div', 'ag-keys');
  var h = el('div', 'ag-keys-h');
  h.appendChild(icon('key', 16));
  h.appendChild(el('b', '', 'Keys made on this server'));
  box.appendChild(h);
  var certs = arr(a.keys_of);
  if (certs.length) {
    var list = el('div', 'ag-keys-l');
    certs.forEach(function (n) { list.appendChild(data('span', 'ag-keycert', n)); });
    box.appendChild(list);
    box.appendChild(el('p', 'note small', 'Their keys are made by the agent (its root side) and written straight into the folders its policy allows - they never leave the server; acme holds none.'));
  } else {
    box.appendChild(el('p', 'note small', 'A certificate used only on this server can have its key made here: the agent makes it at every issue (or keeps it), acme gets only the CSR and never holds the key.'));
  }
  if (MANAGE && H.newCert) {
    var mk = cmdButton('Make a certificate with its key made here', 'add', 'small');
    mk.onclick = function () { H.newCert(row, a.host); };
    var br = el('div', 'btnrow');
    br.appendChild(mk);
    box.appendChild(br);
  }
  return box;
}
/** "Is it the same?" - the agent waiting to be confirmed: its fingerprint, large. */
function confirmBox(row, a, done) {
  var box = el('div', 'ag-confirm');
  var h = el('div', 'ag-confirm-h');
  h.appendChild(icon('key', 18));
  h.appendChild(el('b', '', 'An agent asks to join'));
  if (a.pending.host) h.appendChild(mono(String(a.pending.host), 'ag-host'));
  if (a.pending.ip) h.appendChild(mono(String(a.pending.ip), 'ag-host'));
  if (a.pending.os) h.appendChild(data('span', 'muted small', String(a.pending.os)));
  box.appendChild(h);
  /* 1.0.120: it came with a company enrollment code */
  if (a.pending.enroll) {
    var en = el('div', 'ag-confirm-en');
    en.appendChild(icon('people', 14));
    en.appendChild(el('span', '', 'It joined with the enrollment code'));
    en.appendChild(data('b', '', String(a.pending.enroll.title || a.pending.enroll.id)));
    box.appendChild(en);
  }
  box.appendChild(el('p', 'note', 'Compare this fingerprint with the one acme-agent join printed on the server. Confirm only when every group is the same.'));
  box.appendChild(fpBig(a.pending.fp));
  if (FULL) {
    var row2 = el('div', 'btnrow');
    var ok = cmdButton('It is the same - confirm', 'check', 'primary');
    ok.onclick = function () {
      busy(ok, true);
      ask('agents/confirm', {id: row.id, fp: a.pending.fp}, 90).then(function (x) {
        if (x && x.said) toast(String(x.said), 'bad'); else toast('the agent is confirmed', 'good');
        done(x);
      }).catch(oops).then(function () { busy(ok, false); });
    };
    row2.appendChild(ok);
    box.appendChild(row2);
  } else {
    box.appendChild(el('p', 'muted small', 'A full administrator confirms it.'));
  }
  return box;
}
/** The policy as the agent last said it: each folder, unit, test and script. */
function policyView(pol, at) {
  var box = el('div', 'ag-pol');
  var h = el('div', 'ag-pol-h');
  h.appendChild(icon('shield', 16));
  h.appendChild(el('b', '', 'What its policy allows'));
  if (at) { h.appendChild(noI18n(el('span', 'muted small', ' · '))); h.appendChild(el('span', 'muted small', ago(at))); }
  box.appendChild(h);
  if (!pol) { box.appendChild(el('p', 'muted small', 'Not said yet - Ask it now.')); return box; }
  var any = false;
  function group(title, items, draw) {
    if (!items.length) return;
    any = true;
    var g = el('div', 'ag-pol-g');
    g.appendChild(el('span', 'dbw-k', title));
    items.forEach(function (x) { g.appendChild(draw(x)); });
    box.appendChild(g);
  }
  group('Folders', arr(pol.files), function (f) {
    var r = el('div', 'ag-pol-i');
    r.appendChild(mono(f.dir));
    var m = el('span', 'ag-pol-m');
    m.appendChild(mono(f.owner + ':' + f.group));
    m.appendChild(mono(('000' + Number(f.mode || 0).toString(8)).slice(-4)));
    r.appendChild(m);
    return r;
  });
  group('Units', Object.keys(pol.units || {}), function (u) {
    var r = el('div', 'ag-pol-i');
    r.appendChild(mono(u));
    var m = el('span', 'ag-pol-m');
    arr(pol.units[u]).forEach(function (v) { m.appendChild(data('span', 'ag-verb', v)); });
    r.appendChild(m);
    return r;
  });
  group('Tests and commands', arr(pol.tests), function (t) {
    var r = el('div', 'ag-pol-i');
    r.appendChild(mono(arr(t).join(' ')));
    return r;
  });
  group('Scripts', arr(pol.scripts).concat(arr(pol.script_hashes).map(function (x) { return {hash: x}; })), function (s) {
    var r = el('div', 'ag-pol-i');
    if (s.hash) {
      r.appendChild(el('span', 'small', 'written in acme'));
      r.appendChild(mono(String(s.hash).slice(0, 16) + '…'));
    } else {
      r.appendChild(mono(s.path));
      r.appendChild(mono(String(s.sha256).slice(0, 12) + '…', 'muted'));
    }
    return r;
  });
  group('Only from', arr(pol.from), function (f) { var r = el('div', 'ag-pol-i'); r.appendChild(mono(f)); return r; });
  /* phase 3 and 4: tests run from it, connections for acme, updates from acme */
  group('Tests from here', (pol.probe_local ? [{local: true}] : []).concat(arr(pol.probe).map(function (x) { return {to: x}; })), function (x) {
    var r = el('div', 'ag-pol-i');
    if (x.local) {
      r.appendChild(el('span', '', 'anything on this server'));
      r.appendChild(mono('127.0.0.1 · ::1 · localhost', 'muted'));
    } else r.appendChild(mono(x.to));
    return r;
  });
  group('Connections for acme', arr(pol.connect), function (x) {
    var r = el('div', 'ag-pol-i');
    r.appendChild(mono(x));
    var m = el('span', 'ag-pol-m');
    m.appendChild(el('span', 'small', 'a connector of SSH targets'));
    r.appendChild(m);
    return r;
  });
  group('Updates from acme', pol.self_update ? [1] : [], function () {
    var r = el('div', 'ag-pol-i');
    r.appendChild(el('span', '', 'allowed - a package signed by the release key, a newer version only'));
    return r;
  });
  if (!any) box.appendChild(el('p', 'ag-pol-none', 'Nothing is allowed yet: acme can do nothing on this server. Allow what its deployments need there (acme-agent allow …) - each deployment says what it needs.'));
  arr(pol.problems).forEach(function (p) { box.appendChild(data('div', 'note warn small', String(p))); });
  return box;
}

/* ==========================================================================
   The join wizard: install, the code, the fingerprint
   ========================================================================== */
function wizard(row, a0, after) {
  var W = {step: a0 && a0.pending && !a0.pending.confirmed ? 2 : 0, code: null, a: a0, err: '', busy: false, d: null};
  var STEPS = ['Install the agent', 'The join code', 'Confirm the fingerprint'];
  var timer = null, gen = 0, asked = 0;
  ask('agents/one?id=' + encodeURIComponent(row.id)).then(function (d) { W.d = d; W.a = d; paint(); }).catch(oops);
  function stop() { clearTimeout(timer); timer = null; }
  function rail() {
    var r = el('ol', 'dbw-rail dbs-rail ag-rail');
    STEPS.forEach(function (t, i) {
      var li = el('li', i < W.step ? 'done' : (i === W.step ? 'on' : ''));
      var b = el('button', '');
      b.type = 'button';
      b.disabled = i > W.step || W.busy;
      b.appendChild(noI18n(el('span', 'n', i < W.step ? '✓' : String(i + 1))));
      b.appendChild(el('span', '', t));
      b.onclick = function () { if (i < W.step) { W.step = i; paint(); } };
      li.appendChild(b);
      r.appendChild(li);
    });
    return r;
  }
  function paint() {
    stop();
    var me = ++gen;
    var buttons = [];
    if (W.step > 0) buttons.push({words: 'Back', icon: 'prev', left: true, go: function () { W.step -= 1; paint(); }});
    buttons.push({words: 'Close', close: true});
    if (W.step === 0) buttons.push({words: 'Make the join code', cls: 'primary', icon: 'next', go: function (b) { makeCode(b); }});
    if (W.step === 1) buttons.push({words: 'It is joining', cls: 'primary', icon: 'next', go: function () { W.step = 2; paint(); }});
    var open = function () {
      modal('Join the agent of ' + row.name, function (body) {
        body.appendChild(rail());
        var host = el('div', 'dbs-wiz ag-wiz');
        host.id = 'ag-wiz-' + W.step;
        body.appendChild(host);
        [one, two, three][W.step](host, me);
      }, buttons, 'large');
      explainWhatWasDrawn($('modal-body'));
    };
    if (W.opened) open(); else { W.opened = true; if (H.over) H.over(open, after); else open(); }
  }
  function makeCode(b) {
    busy(b, true);
    ask('agents/code', {id: row.id}).then(function (c) {
      W.code = c; W.a = c.agent; W.step = 1; paint();
    }).catch(oops).then(function () { busy(b, false); });
  }
  /* 1.0.120: a Windows server's agent (agent_windows) - the MSI, its Join step, the same CLI */
  function isWin() {
    var a = W.d || W.a || {};
    return a.kind === 'agent_windows' || a.platform === 'windows' || row.kind === 'agent_windows';
  }
  function oneWin(host) {
    var lead = el('div', 'ha-lead');
    lead.appendChild(noI18n(el('span', 'ha-lead-ico'))).innerHTML = iconMarkup('windows', 22);
    var lw = el('div', '');
    lw.appendChild(el('b', '', 'acme-agent on the Windows server does the work - acme holds none of its credentials'));
    lw.appendChild(el('p', 'note', 'Two services: the network side as a virtual account without privileges; the root side (LocalSystem) never on the network, doing only what its policy allows. Every job from acme is signed; the private keys arrive sealed to the agent.'));
    lead.appendChild(lw);
    host.appendChild(lead);
    var d = W.d || {};
    var w = windowsPackage(d);
    if (w) {
      var t = el('div', 'ag-pkg ag-pkg-small ag-pkg-win');
      var ic = noI18n(el('span', 'ag-pkg-ic'));
      ic.innerHTML = iconMarkup('windows', 22);
      t.appendChild(ic);
      var ww = el('div', 'ag-pkg-w');
      ww.appendChild(data('b', 'ag-pkg-name', w.name));
      var sha = el('div', 'ag-sha');
      sha.appendChild(el('span', 'dbw-k', 'SHA-256'));
      var sv = mono(String(w.sha256 || ''), 'ag-sha-v');
      copyOnClick(sv, String(w.sha256 || ''), 'on the clipboard');
      sha.appendChild(sv);
      ww.appendChild(sha);
      t.appendChild(ww);
      var dl = cmdButton('Download MSI', 'download', 'small');
      dl.onclick = function () { downloadMsi(dl); };
      t.appendChild(dl);
      host.appendChild(t);
    } else {
      host.appendChild(el('p', 'note warn small', 'The Windows installer comes with a release (' + msiName(d) + ') - this acme runs from a source tree, which has none.'));
    }
    host.appendChild(el('h4', 'dbw-h', 'On the server, as an administrator'));
    host.appendChild(windowsLines(d, '', !!w));
    var m = el('div', 'note info small ag-mode-note');
    m.appendChild(modeBadge((W.a || {}).mode));
    m.appendChild(el('span', '', (W.a || {}).mode === 'active'
      ? 'The agent connects to acme on the agents’ port: nothing needs to be open on the server.'
      : 'acme connects to the agent on port 8446: the installer opens it in Windows Firewall at the join (only to the addresses of acme-agent allow from, when there are any).'));
    host.appendChild(m);
  }
  function one(host) {
    if (isWin()) return oneWin(host);
    var lead = el('div', 'ha-lead');
    lead.appendChild(noI18n(el('span', 'ha-lead-ico'))).innerHTML = iconMarkup('terminal', 22);
    var lw = el('div', '');
    lw.appendChild(el('b', '', 'acme-agent on the server does the work - acme holds none of its credentials'));
    lw.appendChild(el('p', 'note', 'Two processes: the network side as the account acme-agent, without privileges; the root side never on the network, doing only what /etc/acme-agent/policy allows. Every job from acme is signed; the private keys arrive sealed to the agent.'));
    lead.appendChild(lw);
    host.appendChild(lead);
    var d = W.d || {};
    var p = d.package || {};
    if (p.name) {
      var t = el('div', 'ag-pkg ag-pkg-small');
      var ic = noI18n(el('span', 'ag-pkg-ic'));
      ic.innerHTML = iconMarkup('download', 22);
      t.appendChild(ic);
      var w = el('div', 'ag-pkg-w');
      w.appendChild(data('b', 'ag-pkg-name', p.name));
      var sha = el('div', 'ag-sha');
      sha.appendChild(el('span', 'dbw-k', 'SHA-256'));
      var sv = mono(String(p.sha256), 'ag-sha-v');
      copyOnClick(sv, String(p.sha256), 'on the clipboard');
      sha.appendChild(sv);
      w.appendChild(sha);
      t.appendChild(w);
      var dl = cmdButton('Download', 'download', 'small');
      dl.onclick = function () { download(dl); };
      t.appendChild(dl);
      host.appendChild(t);
    }
    host.appendChild(el('h4', 'dbw-h', 'On the server, as root'));
    var ol = el('ol', 'dbs-steps ag-steps');
    var words = ['Check it is the same file:', 'Unpack it:', 'Install - nothing is allowed yet:'];
    arr(d.commands).slice(0, 3).forEach(function (c, i) {
      var li = el('li', '');
      li.appendChild(el('span', '', words[i]));
      li.appendChild(cmdBox(c));
      ol.appendChild(li);
    });
    host.appendChild(ol);
    var m = el('div', 'note info small ag-mode-note');
    m.appendChild(modeBadge((W.a || {}).mode));
    m.appendChild(el('span', '', (W.a || {}).mode === 'active'
      ? 'The agent connects to acme on the agents’ port: nothing needs to be open on the server.'
      : 'acme connects to the agent on port 8446: let acme in there (and only acme - acme-agent allow from ADDRESS).'));
    host.appendChild(m);
  }
  function two(host) {
    var c = W.code;
    if (!c) { host.appendChild(el('p', 'muted', 'Make the code first.')); return; }
    host.appendChild(el('h4', 'dbw-h', 'The one-time join code'));
    var code = el('div', 'ag-code');
    code.appendChild(noI18n(el('pre', 'mono', c.code)));
    var cp = cmdButton('Copy', 'copy', 'small');
    cp.onclick = function () { copyText(c.code, cp, 'on the clipboard'); };
    code.appendChild(cp);
    host.appendChild(code);
    var left = el('div', 'ag-code-left');
    left.appendChild(icon('clock', 14));
    left.appendChild(el('span', '', 'valid once, until'));
    left.appendChild(document.createTextNode(' ' + when(c.until)));
    host.appendChild(left);
    if (isWin()) {
      host.appendChild(el('h4', 'dbw-h', 'On the server, in an elevated prompt (Run as administrator)'));
      host.appendChild(cmdBox('acme-agent join ' + c.code));
      host.appendChild(el('p', 'note small', 'Or paste it at the MSI’s Join step - or silently: msiexec /i ' + msiName(W.d || {}) + ' /qn JOINCODE=CODE. The agent makes its own key there (it never leaves the server) and shows its fingerprint - acme shows it next, to compare.'));
    } else {
      host.appendChild(el('h4', 'dbw-h', 'On the server, as root'));
      host.appendChild(cmdBox('sudo acme-agent join ' + c.code));
      host.appendChild(el('p', 'note small', 'Or at the install: sudo ./install.sh --join CODE. The agent makes its own key there (it never leaves the server) and prints its fingerprint - acme shows it next, to compare.'));
    }
    var pins = el('div', 'dbs-kvs ag-pins');
    pins.appendChild(kv('The authority it pins', mono(grouped(c.ca_fp).slice(0, 4).join(' ') + ' …')));
    if (c.mode === 'active') pins.appendChild(kv('It connects to', mono(arr(c.endpoints).join('  '))));
    else pins.appendChild(kv('acme connects to', mono((W.a && W.a.host || '?') + ':' + (c.port || 8446))));
    host.appendChild(pins);
  }
  function three(host, me) {
    var a = W.a || {};
    var steps = el('div', 'ag-wait');
    host.appendChild(steps);
    function drawWait() {
      clear(steps);
      a = W.a || {};
      /* joined: its certificate taken (an active agent takes it at its next question - until
         then the confirmed join is still pending: "handing the agent its certificate") */
      if (a.joined && !a.pending && !a.code_until) {
        var ok = el('div', 'ag-done');
        ok.appendChild(icon('check', 26));
        var w = el('div', '');
        w.appendChild(el('b', '', 'The agent has joined'));
        w.appendChild(el('p', 'note', 'It has its certificate from acme’s agent authority. Allow on the server what its deployments need - each deployment says it, with the lines to copy.'));
        ok.appendChild(w);
        steps.appendChild(ok);
        if (a.joined) steps.appendChild(policyView(a.policy, a.policy_at));
        return true;
      }
      if (a.pending && !a.pending.confirmed) {
        steps.appendChild(confirmBox(row, a, function () { tick(true); }));
        return false;
      }
      if (a.pending && a.pending.confirmed) {
        var w2 = el('div', 'ag-waiting');
        w2.appendChild(el('span', 'ag-spin'));
        w2.appendChild(el('span', '', 'Confirmed - handing the agent its certificate…'));
        steps.appendChild(w2);
        return false;
      }
      var w3 = el('div', 'ag-waiting');
      w3.appendChild(el('span', 'ag-spin'));
      w3.appendChild(el('span', '', a.mode === 'active' ? 'Waiting for the agent to ask acme…' : 'Waiting for the agent - acme looks for it on the server…'));
      steps.appendChild(w3);
      if (a.last_error) steps.appendChild(data('div', 'note warn small', String(a.last_error)));
      return false;
    }
    function tick(now) {
      if (me !== gen || !host.isConnected) return;
      /* one round of asking at a time: "It is the same - confirm" asked at once while the
         round before was waiting - two of them went on side by side to the end */
      clearTimeout(timer);
      var mine = ++asked;
      /* a passive agent is reached by acme (look) - joining again too, where the agent joined
         before is still the target's until the new one is confirmed */
      var p = a.mode === 'passive'
        ? ask('agents/look', {id: row.id}, 60).then(function (x) { return x.agent; })
        : ask('agents/one?id=' + encodeURIComponent(row.id));
      p.then(function (x) {
        if (me !== gen || !host.isConnected || mine !== asked) return;
        W.a = x;
        if (!drawWait()) timer = setTimeout(tick, 2500);
        else if (after) after();
      }).catch(function () { if (me === gen && host.isConnected && mine === asked) timer = setTimeout(tick, 4000); });
      return now;
    }
    if (!drawWait()) timer = setTimeout(tick, 600);
  }
}

/* ==========================================================================
   A deployment on an agent: what it needs of the policy (the preview's d.agent)
   ========================================================================== */
function needs(d) {
  var box = el('div', 'ag-needs');
  var items = arr(d && d.items);
  /* a Windows server's agent (1.0.120): its lines are typed in an elevated prompt - no sudo */
  var sudo = d && d.platform === 'windows' ? '' : 'sudo ';
  var bad = items.filter(function (i) { return i.ok === false; });
  var unk = items.filter(function (i) { return i.ok === null || i.ok === undefined; });
  var h = el('div', 'ag-needs-h');
  h.appendChild(icon('shield', 16));
  h.appendChild(el('b', '', 'The agent’s policy'));
  var err = !!(d && d.error);
  /* nothing judged yet (no file in the form) is not "allows all of it"; what the agent cannot
     do at all (a line of a shell, a key it makes in a keystore) is not either */
  var pill = el('span', 'ag-badge ' + (err || bad.length ? 'bad' : (unk.length ? 'warn' : (items.length ? 'ok' : 'dim'))));
  pill.appendChild(el('span', '', err ? 'the agent cannot do it this way' : (bad.length ? 'needs more on the server'
    : (unk.length ? 'not known yet' : (items.length ? 'allows all of it' : 'nothing to judge yet')))));
  h.appendChild(pill);
  box.appendChild(h);
  if (d && d.error) box.appendChild(data('p', 'note warn small', String(d.error)));
  if (d && d.agent_key) {
    var kc = el('div', 'ag-needs-key');
    kc.appendChild(icon('key', 15));
    kc.appendChild(el('span', '', 'The key is made on the server: the agent makes it and puts it into the files below - acme never holds it.'));
    box.appendChild(kc);
  }
  if (unk.length && !bad.length) box.appendChild(el('p', 'note small', 'The agent has not said its policy yet (it has not joined, or was not asked): the lines below allow what this deployment does.'));
  items.forEach(function (i) {
    var r = el('div', 'ag-need ' + (i.ok === true ? 'ok' : (i.ok === false ? 'bad' : 'unk')));
    var mk = noI18n(el('span', 'ag-need-mk', i.ok === true ? '✓' : (i.ok === false ? '✕' : '?')));
    r.appendChild(mk);
    var w = el('div', 'ag-need-w');
    var line = el('div', 'ag-need-l');
    if (i.label) line.appendChild(el('span', 'ag-need-k', String(i.label)));
    line.appendChild(mono(String(i.what || '')));
    w.appendChild(line);
    /* never allowed there, whatever the policy says (a protected place): why, and no line */
    if (i.ok === false && i.why) w.appendChild(data('div', 'note bad small ag-need-why', String(i.why)));
    if (i.ok !== true && i.allow) w.appendChild(cmdBox(sudo + String(i.allow).split('\n').join('\n' + sudo), 'small'));
    r.appendChild(w);
    box.appendChild(r);
  });
  var lines = items.filter(function (i) { return i.ok !== true && i.allow; }).map(function (i) { return sudo + String(i.allow).split('\n').join('\n' + sudo); });
  var br = el('div', 'btnrow ag-needs-all');
  if (lines.length > 1) {
    var all = cmdButton('Copy all the lines', 'copy', 'small');
    all.onclick = function () { copyText(lines.join('\n'), all, 'on the clipboard'); };
    br.appendChild(all);
  }
  /* 1.0.118: the whole policy, clicked together - what every deployment there needs offered */
  if (d && d.target && (d.target.id || d.target.name)) br.appendChild(designButton({id: d.target.id || d.target.name, name: d.target.name}, {}, 'small'));
  if (br.firstChild) box.appendChild(br);
  return box;
}

/* ==========================================================================
   1.0.120: what the agent tells about its server - "The server" on the agent's card, a line on
   each tile of Settings → Target agents and the Servers overview there. Its words, never a
   secret (agents.py cleans them: agent_system.py); a.system = {state: ok|old|unknown, at,
   facts, skew, skew_level, uptime, warnings}.
   ========================================================================== */
var SYS = {filter: 'all', sort: 'name', dir: 1};
function sysOf(a) { return a && a.system && a.system.state === 'ok' && a.system.facts ? a.system : null; }
function sysWin(a, f) { return (f && f.platform === 'windows') || (a && a.platform === 'windows'); }
function sizeWords(n) {
  n = Number(n || 0);
  var units = ['B', 'kB', 'MB', 'GB', 'TB', 'PB'], i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  var said = i === 0 ? n.toFixed(0) : (n >= 100 ? n.toFixed(0) : n.toFixed(1));
  if (typeof numDecimal === 'function' && numDecimal() === ',') said = said.replace('.', ',');
  return said + ' ' + units[i];
}
function pctWords(p) {
  var t = (Math.round(p * 10) / 10).toFixed(p >= 10 ? 0 : 1);
  if (typeof numDecimal === 'function' && numDecimal() === ',') t = t.replace('.', ',');
  return t + ' %';
}
function upWords(s) { return typeof span === 'function' ? span(s) : Math.round(s / 3600) + ' h'; }
function usedLevel(p) { return p > 95 ? 'bad' : (p > 85 ? 'warn' : 'ok'); }
function skewWords(s) {
  var a = Math.abs(Number(s)), t = a < 10 ? a.toFixed(1) : String(Math.round(a));
  if (typeof numDecimal === 'function' && numDecimal() === ',') t = t.replace('.', ',');
  return (s > 0 ? '+' : (s < 0 ? '−' : '±')) + t + ' s';
}
/** The Linux distribution or Windows, by its colour (the theme's own). */
function distroCls(f) {
  var id = String((f && f.os_id) || '').toLowerCase();
  if (f && f.platform === 'windows') return 'd-win';
  if (/ubuntu/.test(id)) return 'd-ubuntu';
  if (/debian|rhel|redhat|centos|oracle|ol$/.test(id)) return 'd-red';
  if (/rocky|alma|fedora|suse|sles|opensuse|amzn|mint/.test(id)) return 'd-green';
  return 'd-other';
}
/** A pill of the server's: ok (green), warn (amber), bad (red), dim (grey), info. */
function sysPill(cls, ic, words, more) {
  var p = el('span', 'ag-sys-pill ' + cls);
  if (ic) p.appendChild(icon(ic, 12));
  p.appendChild(el('span', '', words));
  if (more !== undefined && more !== null && more !== '') p.appendChild(data('b', 'ag-sys-pill-v', String(more)));
  return p;
}
function skewPill(sv) {
  if (!sv || sv.skew === null || sv.skew === undefined) return sysPill('dim', 'clock', 'clock not known');
  var lv = sv.skew_level === 'bad' ? 'bad' : (sv.skew_level === 'warn' ? 'warn' : 'ok');
  var p = sysPill(lv, 'clock', lv === 'ok' ? 'clock in time' : (lv === 'warn' ? 'clock off' : 'clock far off'), skewWords(sv.skew));
  explain(p, lv === 'ok' ? 'The server’s clock against acme’s: in time.'
    : 'The server’s clock against acme’s. The agent refuses every job more than 300 s off - set its time right (NTP).');
  return p;
}
/** A bar of what is used: green, amber above 85 %, red above 95 %. */
function useBar(pct, label) {
  var lv = usedLevel(pct);
  var b = el('div', 'ag-sys-bar ' + lv);
  b.setAttribute('role', 'meter');
  b.setAttribute('aria-valuemin', '0');
  b.setAttribute('aria-valuemax', '100');
  b.setAttribute('aria-valuenow', String(Math.round(pct)));
  if (label) b.setAttribute('aria-label', tr(label));
  var f = el('span', 'ag-sys-fill');
  f.style.width = Math.max(1.5, Math.min(100, pct)) + '%';
  b.appendChild(f);
  return b;
}
function sysTile(ic, title, cls) {
  var t = el('div', 'ag-sys-t' + (cls ? ' ' + cls : ''));
  var h = el('div', 'ag-sys-k');
  h.appendChild(icon(ic, 14));
  h.appendChild(el('span', '', title));
  t.appendChild(h);
  return t;
}
function osName(f) {
  var n = String(f.os || (f.platform === 'windows' ? 'Windows' : 'Linux'));
  return n;
}
function osVersion(f) {
  if (f.platform === 'windows') return [f.os_version, f.build].filter(Boolean).join(' · ');
  var v = String(f.os_version || '');
  return v && String(f.os || '').indexOf(v) < 0 ? v : '';
}
/** The agent's card: "The server". */
function sysPanel(row, a, ask) {
  var box = el('div', 'ag-sys');
  var sv = a.system || {state: 'unknown'};
  var f = sysOf(a) ? sv.facts : null;
  var head = el('div', 'ag-sys-h');
  head.appendChild(icon(sysWin(a, f) ? 'windows' : 'terminal', 16));
  head.appendChild(el('b', '', 'The server'));
  if (sv.at) {
    var said = el('span', 'ag-sys-ago');
    said.appendChild(el('span', '', 'said ' + ago(sv.at)));
    explain(said, 'When the agent last told about its server: a passive agent with every answer (every 5 minutes), an active one when something changes and every half hour.');
    head.appendChild(said);
  }
  if (MANAGE && a.joined && ask) {
    var b = cmdButton('Ask it now', 'refresh', 'small ag-sys-ask');
    b.onclick = function () { ask(b); };
    head.appendChild(b);
  }
  box.appendChild(head);
  if (!f) {
    var e = el('div', 'ag-sys-none' + (sv.state === 'old' ? ' old' : ''));
    e.appendChild(icon(sv.state === 'old' ? 'up' : 'info', 18));
    var w = el('div', '');
    w.appendChild(el('b', '', sv.state === 'old' ? 'The agent is too old to tell (update it)' : 'Not said yet'));
    w.appendChild(el('p', 'note small', sv.state === 'old'
      ? 'A newer agent tells acme its server’s system, addresses, memory, disks, uptime and clock.'
      : 'Ask it now: the agent tells its server’s system, addresses, memory, disks, uptime and clock.'));
    e.appendChild(w);
    box.appendChild(e);
    if (sv.skew !== null && sv.skew !== undefined) box.appendChild(skewPill(sv));
    return box;
  }
  /* the system, large */
  var hero = el('div', 'ag-sys-hero');
  var mark = el('div', 'ag-sys-mark ' + distroCls(f));
  mark.appendChild(icon(sysWin(a, f) ? 'windows' : 'terminal', 26));
  hero.appendChild(mark);
  var who = el('div', 'ag-sys-who');
  who.appendChild(data('div', 'ag-sys-osn', osName(f)));
  var sub = el('div', 'ag-sys-sub');
  var ver = osVersion(f);
  if (ver) sub.appendChild(mono(ver, 'ag-sys-ver'));
  if (f.platform !== 'windows' && f.kernel) {
    var kc = mono(f.kernel, 'ag-sys-tag');
    explain(kc, 'The kernel it runs');
    sub.appendChild(kc);
  }
  if (f.edition) sub.appendChild(data('span', 'ag-sys-tag', f.edition));
  if (f.install && f.install !== 'Server' && f.install !== 'Client') sub.appendChild(data('span', 'ag-sys-tag', f.install));
  if (f.arch) sub.appendChild(mono(f.arch, 'ag-sys-tag'));
  if (f.machine) sub.appendChild(data('span', 'ag-sys-tag dim', f.machine));
  who.appendChild(sub);
  hero.appendChild(who);
  var pills = el('div', 'ag-sys-pills');
  pills.appendChild(skewPill(sv));
  if (f.reboot === true) {
    var rp = sysPill('warn', 'power', 'restart pending');
    if (f.reboot_why) explain(rp, String(f.reboot_why));
    pills.appendChild(rp);
  } else if (f.reboot === false) pills.appendChild(sysPill('ok', 'power', 'no restart pending'));
  if (f.selinux) pills.appendChild(sysPill(f.selinux === 'enforcing' ? 'ok' : (f.selinux === 'permissive' ? 'warn' : 'dim'), 'shield', 'SELinux', f.selinux));
  if (f.apparmor === true) pills.appendChild(sysPill('ok', 'shield', 'AppArmor'));
  hero.appendChild(pills);
  box.appendChild(hero);
  /* the tiles */
  var grid = el('div', 'ag-sys-grid');
  var host = sysTile('globe', 'Host');
  host.appendChild(data('div', 'ag-sys-big mono', f.hostname || '–'));
  if (f.fqdn && f.fqdn !== f.hostname) host.appendChild(mono(f.fqdn, 'ag-sys-fqdn'));
  var dom = el('div', 'ag-sys-line2');
  if (f.ad_domain) { dom.appendChild(el('span', 'ag-sys-l', 'AD domain')); dom.appendChild(data('b', '', f.ad_domain)); }
  else if (f.workgroup) { dom.appendChild(el('span', 'ag-sys-l', 'workgroup')); dom.appendChild(data('b', '', f.workgroup)); }
  else if (f.domain) { dom.appendChild(el('span', 'ag-sys-l', 'domain')); dom.appendChild(data('b', '', f.domain)); }
  if (dom.firstChild) host.appendChild(dom);
  if (arr(f.addrs).length) {
    var ips = el('div', 'ag-sys-ips');
    arr(f.addrs).forEach(function (x) {
      var c = noI18n(el('span', 'ag-sys-ip'));
      if (x['if']) c.appendChild(el('span', 'ag-sys-if', x['if']));
      c.appendChild(el('span', 'mono', x.ip));
      ips.appendChild(c);
    });
    host.appendChild(ips);
  }
  grid.appendChild(host);
  if (f.cpu || f.cores) {
    var cpu = sysTile('pulse', 'Processor');
    if (f.cpu) cpu.appendChild(data('div', 'ag-sys-cpu', f.cpu));
    var cl = el('div', 'ag-sys-line2');
    if (f.cores) cl.appendChild(el('span', 'ag-sys-l', f.cores === 1 ? '1 core' : f.cores + ' cores'));
    if (arr(f.load).length === 3) {
      var ld = el('span', 'ag-sys-l', 'load');
      cl.appendChild(ld);
      cl.appendChild(mono(arr(f.load).map(function (x) { return Number(x).toFixed(2); }).join(' · '), 'ag-sys-load'));
      explain(ld, 'The load average of the last 1, 5 and 15 minutes');
    }
    cpu.appendChild(cl);
    grid.appendChild(cpu);
  }
  if (f.mem_total) {
    var mem = sysTile('chart', 'Memory');
    var used = f.mem_avail !== undefined ? Math.max(0, f.mem_total - f.mem_avail) : null;
    var mtop = el('div', 'ag-sys-num');
    mtop.appendChild(data('b', '', sizeWords(f.mem_total)));
    if (used !== null) mtop.appendChild(data('span', 'ag-sys-pct ' + usedLevel(100 * used / f.mem_total), pctWords(100 * used / f.mem_total)));
    mem.appendChild(mtop);
    if (used !== null) {
      mem.appendChild(useBar(100 * used / f.mem_total, 'Memory'));
      var ml = el('div', 'ag-sys-line2 small');
      ml.appendChild(data('span', '', sizeWords(used)));
      ml.appendChild(el('span', 'ag-sys-l', 'used'));
      ml.appendChild(data('span', '', sizeWords(f.mem_avail)));
      ml.appendChild(el('span', 'ag-sys-l', 'available'));
      mem.appendChild(ml);
    }
    grid.appendChild(mem);
  }
  if (arr(f.disks).length) {
    var dk = sysTile('db', arr(f.disks).length === 1 ? 'Disk' : 'Disks', 'wide');
    arr(f.disks).forEach(function (d) {
      var p = d.used_pct !== undefined && d.used_pct !== null ? Number(d.used_pct) : 100 * (d.size - d.free) / d.size;
      var one = el('div', 'ag-sys-disk');
      var top = el('div', 'ag-sys-disk-h');
      top.appendChild(mono(d.path, 'ag-sys-mp'));
      if (d.fs) top.appendChild(mono(d.fs, 'ag-sys-fs'));
      top.appendChild(data('span', 'ag-sys-pct ' + usedLevel(p), pctWords(p)));
      one.appendChild(top);
      one.appendChild(useBar(p, 'Disk'));
      var dl = el('div', 'ag-sys-line2 small');
      dl.appendChild(data('span', '', sizeWords(d.free)));
      dl.appendChild(el('span', 'ag-sys-l', 'free of'));
      dl.appendChild(data('span', '', sizeWords(d.size)));
      one.appendChild(dl);
      dk.appendChild(one);
    });
    grid.appendChild(dk);
  }
  var up = sysTile('history', 'Uptime');
  up.appendChild(el('div', 'ag-sys-big', sv.uptime !== null && sv.uptime !== undefined ? upWords(sv.uptime) : '–'));
  if (f.boot) {
    var bl = el('div', 'ag-sys-line2');
    bl.appendChild(el('span', 'ag-sys-l', 'started'));
    bl.appendChild(data('span', '', when(f.boot)));
    up.appendChild(bl);
  }
  /* the time in the same tile: the zone, its offset, the clock against acme's */
  var tm = up;
  var th = el('div', 'ag-sys-k ag-sys-k2');
  th.appendChild(icon('clock', 14));
  th.appendChild(el('span', '', 'Time'));
  tm.appendChild(th);
  tm.appendChild(data('div', 'ag-sys-tz', f.tz || '–'));
  if (f.tz_offset !== undefined && f.tz_offset !== null) {
    var o = Number(f.tz_offset), hh = Math.floor(Math.abs(o) / 60), mm = Math.abs(o) % 60;
    tm.appendChild(mono('UTC' + (o < 0 ? '−' : '+') + (hh < 10 ? '0' : '') + hh + ':' + (mm < 10 ? '0' : '') + mm, 'ag-sys-off'));
  }
  var sk = el('div', 'ag-sys-skew');
  sk.appendChild(skewPill(sv));
  tm.appendChild(sk);
  grid.appendChild(up);
  box.appendChild(grid);
  /* the services (Linux) or the roles (Windows) a certificate is used by */
  var svcs = arr(f.services);
  var sw = el('div', 'ag-sys-svcs');
  var sh = el('div', 'ag-sys-k');
  sh.appendChild(icon('gear', 14));
  sh.appendChild(el('span', '', f.platform === 'windows' ? 'Roles' : 'Services'));
  sw.appendChild(sh);
  var chipsBox = el('div', 'ag-sys-chips');
  if (!svcs.length) chipsBox.appendChild(el('span', 'ag-sys-svc none', f.platform === 'windows' ? 'none of the roles acme knows' : 'none of the services acme knows'));
  svcs.slice().sort(function (x, y) { return (x.state === 'active' ? 0 : 1) - (y.state === 'active' ? 0 : 1); }).forEach(function (s) {
    var c = el('span', 'ag-sys-svc ' + (s.state === 'active' ? 'on' : 'off'));
    c.appendChild(el('span', 'dot ' + (s.state === 'active' ? 'ok' : 'off')));
    c.appendChild(data('span', '', s.name));
    if (s.detail) c.appendChild(data('span', 'ag-sys-det', s.detail));
    explain(c, s.state === 'active' ? 'running' : 'installed, not running');
    chipsBox.appendChild(c);
  });
  sw.appendChild(chipsBox);
  box.appendChild(sw);
  /* the agent's runtime */
  var rt = el('div', 'ag-sys-rt');
  if (f.python) { rt.appendChild(el('span', 'ag-sys-l', 'Python')); rt.appendChild(mono(f.python)); }
  if (f.openssl) { rt.appendChild(el('span', 'ag-sys-l', 'OpenSSL')); rt.appendChild(mono(String(f.openssl).replace(/^OpenSSL\s+/, ''))); }
  if (f.openssl_cli && String(f.openssl_cli).split(' (')[0] !== String(f.openssl)) {
    rt.appendChild(el('span', 'ag-sys-l', 'openssl command'));
    rt.appendChild(mono(String(f.openssl_cli).split(' (')[0].replace(/^OpenSSL\s+/, '')));
  }
  if (f.init) { rt.appendChild(el('span', 'ag-sys-l', 'init')); rt.appendChild(mono(f.init)); }
  if (rt.firstChild) box.appendChild(rt);
  return box;
}
/** A tile of Settings → Target agents: the system in a line, and what is worth a look. */
function sysLine(a) {
  var sv = a.system;
  if (!a.joined || !sv) return null;
  var line = el('div', 'ag-sys-tl');
  var f = sysOf(a) ? sv.facts : null;
  if (!f) {
    if (sv.state === 'old') line.appendChild(sysPill('dim', 'up', 'the agent is too old to tell'));
    else return null;
    return line;
  }
  var os = el('span', 'ag-sys-tos ' + distroCls(f));
  os.appendChild(icon(sysWin(a, f) ? 'windows' : 'terminal', 13));
  os.appendChild(data('span', 'ag-sys-tosn', osName(f) + (osVersion(f) && f.platform !== 'windows' ? ' ' + osVersion(f) : '')));
  if (f.platform === 'windows' && f.os_version) os.appendChild(mono(f.os_version, 'ag-sys-tosv'));
  line.appendChild(os);
  if (sv.uptime !== null && sv.uptime !== undefined) {
    var u = el('span', 'ag-sys-tup');
    u.appendChild(icon('history', 12));
    u.appendChild(el('span', '', 'up ' + upWords(sv.uptime)));
    line.appendChild(u);
  }
  if (sv.skew_level === 'warn' || sv.skew_level === 'bad') line.appendChild(skewPill(sv));
  var full = arr(f.disks).filter(function (d) { return Number(d.used_pct) > 85; });
  if (full.length) {
    var worst = full.reduce(function (m, d) { return Number(d.used_pct) > Number(m.used_pct) ? d : m; });
    var dp = sysPill(usedLevel(Number(worst.used_pct)), 'db', 'disk full', pctWords(Number(worst.used_pct)));
    explain(dp, full.map(function (d) { return d.path + ' ' + pctWords(Number(d.used_pct)); }).join(', '));
    line.appendChild(dp);
  }
  if (f.reboot) line.appendChild(sysPill('warn', 'power', 'restart pending'));
  return line;
}
/** Settings → Target agents: every server at a glance - sorted by a click on a heading,
    filtered by its platform. */
function serversTable(rows) {
  var have = rows.filter(function (a) { return sysOf(a); });
  if (!have.length) return null;
  var box = el('div', 'ag-srv');
  var h = el('div', 'ag-srv-h');
  h.appendChild(icon('db', 18));
  h.appendChild(el('h3', '', 'Servers'));
  h.appendChild(noI18n(el('span', 'count', String(have.length))));
  var seg = el('div', 'seg ag-srv-seg');
  [['all', 'All'], ['linux', 'Linux'], ['windows', 'Windows']].forEach(function (x) {
    var b = el('button', SYS.filter === x[0] ? 'on' : '', x[1]);
    b.type = 'button';
    b.setAttribute('data-f', x[0]);
    b.onclick = function () { SYS.filter = x[0]; fill(); };
    seg.appendChild(b);
  });
  h.appendChild(seg);
  box.appendChild(h);
  var COLS = [
    ['name', 'Target', function (a) { return String(a.name).toLowerCase(); }],
    ['os', 'System', function (a) { return osName(sysOf(a).facts).toLowerCase(); }],
    ['ver', 'Version', function (a) { var f = sysOf(a).facts; return f.platform === 'windows' ? String(f.build || '') : String(f.os_version || f.kernel || ''); }],
    ['up', 'Uptime', function (a) { return Number(sysOf(a).uptime || 0); }],
    ['mem', 'Memory', function (a) { var f = sysOf(a).facts; return f.mem_total && f.mem_avail !== undefined ? 1 - f.mem_avail / f.mem_total : -1; }],
    ['disk', 'Disk', function (a) { return arr(sysOf(a).facts.disks).reduce(function (m, d) { return Math.max(m, Number(d.used_pct || 0)); }, -1); }],
    ['skew', 'Clock', function (a) { var s = sysOf(a).skew; return s === null || s === undefined ? -1 : Math.abs(s); }],
    ['agent', 'Agent', function (a) { return String(a.version || ''); }]];
  var wrap = el('div', 'ag-srv-wrap');
  var table = el('table', 'ag-srv-t');
  var thead = el('thead', ''), tbody = el('tbody', '');
  table.appendChild(thead);
  table.appendChild(tbody);
  wrap.appendChild(table);
  box.appendChild(wrap);
  function fill() {
    Array.prototype.forEach.call(seg.children, function (b) { b.classList.toggle('on', b.getAttribute('data-f') === SYS.filter); });
    clear(thead);
    var tr0 = el('tr', '');
    COLS.forEach(function (c) {
      var th = el('th', 'c-' + c[0]);
      var b = el('button', 'ag-srv-sort' + (SYS.sort === c[0] ? ' on' : ''));
      b.type = 'button';
      b.appendChild(el('span', '', c[1]));
      b.appendChild(noI18n(el('span', 'ag-srv-arr', SYS.sort === c[0] ? (SYS.dir > 0 ? '▲' : '▼') : '')));
      b.onclick = function () { if (SYS.sort === c[0]) SYS.dir = -SYS.dir; else { SYS.sort = c[0]; SYS.dir = c[0] === 'name' || c[0] === 'os' || c[0] === 'ver' || c[0] === 'agent' ? 1 : -1; } fill(); };
      th.setAttribute('aria-sort', SYS.sort === c[0] ? (SYS.dir > 0 ? 'ascending' : 'descending') : 'none');
      th.appendChild(b);
      tr0.appendChild(th);
    });
    thead.appendChild(tr0);
    clear(tbody);
    var key = (COLS.filter(function (c) { return c[0] === SYS.sort; })[0] || COLS[0])[2];
    var list = have.filter(function (a) { return SYS.filter === 'all' || (sysWin(a, sysOf(a).facts) ? 'windows' : 'linux') === SYS.filter; });
    list.sort(function (x, y) { var p = key(x), q = key(y); return (p < q ? -1 : p > q ? 1 : 0) * SYS.dir || String(x.name).localeCompare(String(y.name)); });
    if (!list.length) {
      var e = el('tr', 'ag-srv-empty');
      var td = el('td', '', 'No server of this kind');
      td.colSpan = COLS.length;
      e.appendChild(td);
      tbody.appendChild(e);
    }
    list.forEach(function (a) { tbody.appendChild(serverRow(a)); });
  }
  fill();
  return box;
}
function cell(cls, label, child) {
  var td = el('td', 'c-' + cls);
  td.setAttribute('data-l', tr(label));
  if (child) td.appendChild(child);
  return td;
}
function serverRow(a) {
  var sv = sysOf(a), f = sv.facts;
  var r = el('tr', '');
  var nb = el('button', 'ag-srv-name');
  nb.type = 'button';
  nb.appendChild(data('span', '', a.name));
  nb.onclick = function () { if (H.openTarget) H.openTarget(a.name); };
  var nc = el('span', 'ag-srv-nc');
  nc.appendChild(el('span', 'dot ' + ({answers: 'ok', quiet: 'warn', refused: 'crit'}[a.state] || 'off')));
  nc.appendChild(nb);
  if (f.hostname) nc.appendChild(mono(f.fqdn || f.hostname, 'ag-srv-host'));
  r.appendChild(cell('name', 'Target', nc));
  var os = el('span', 'ag-sys-tos ' + distroCls(f));
  os.appendChild(icon(sysWin(a, f) ? 'windows' : 'terminal', 13));
  os.appendChild(data('span', 'ag-sys-tosn', osName(f)));
  r.appendChild(cell('os', 'System', os));
  r.appendChild(cell('ver', 'Version', mono(f.platform === 'windows' ? [f.os_version, f.build].filter(Boolean).join(' · ') || '–' : (f.os_version || '') + (f.kernel ? (f.os_version ? ' · ' : '') + f.kernel : '') || '–', 'ag-srv-v')));
  var upc = el('span', 'ag-srv-up');
  upc.appendChild(el('span', '', sv.uptime !== null && sv.uptime !== undefined ? upWords(sv.uptime) : '–'));
  if (f.reboot) { var rp = sysPill('warn', 'power', 'restart'); if (f.reboot_why) explain(rp, String(f.reboot_why)); upc.appendChild(rp); }
  r.appendChild(cell('up', 'Uptime', upc));
  var mc = el('span', 'ag-srv-mini');
  if (f.mem_total && f.mem_avail !== undefined) {
    var mp = 100 * (f.mem_total - f.mem_avail) / f.mem_total;
    mc.appendChild(useBar(mp, 'Memory'));
    mc.appendChild(data('span', 'ag-srv-mv', sizeWords(f.mem_total)));
  } else mc.appendChild(el('span', 'muted', '–'));
  r.appendChild(cell('mem', 'Memory', mc));
  var dc = el('span', 'ag-srv-mini');
  var worst = arr(f.disks).reduce(function (m, d) { return !m || Number(d.used_pct) > Number(m.used_pct) ? d : m; }, null);
  if (worst) {
    dc.appendChild(useBar(Number(worst.used_pct), 'Disk'));
    dc.appendChild(data('span', 'ag-srv-mv ' + usedLevel(Number(worst.used_pct)), pctWords(Number(worst.used_pct))));
    explain(dc, arr(f.disks).map(function (d) { return d.path + ': ' + pctWords(Number(d.used_pct)) + ' (' + sizeWords(d.free) + ' / ' + sizeWords(d.size) + ')'; }).join('\n'));
  } else dc.appendChild(el('span', 'muted', '–'));
  r.appendChild(cell('disk', 'Disk', dc));
  r.appendChild(cell('skew', 'Clock', skewPill(sv)));
  r.appendChild(cell('agent', 'Agent', a.version ? mono(a.version, 'ag-srv-av') : el('span', 'muted', '–')));
  return r;
}

/* ---- discovery (1.0.125, docs/target-agent.md "Discovery"): what the server runs that takes
   certificates, read by its agent where its policy says `allow discover` - each service found
   with the certificate it serves now; a deployment prefilled from it, the policy lines it
   needs, a test of what it serves; the certificates there that acme does not manage. ---- */
var DISC_IC = '<circle cx="11" cy="11" r="6.5"/><path d="M16 16l4.5 4.5"/><path d="M8.2 11h5.6M11 8.2v5.6"/>';
var DISC_TONE = {nginx: 'g', apache: 'r', haproxy: 'b', postfix: 'v', dovecot: 'v', exim: 'v', tomcat: 'o', proxmox: 'o', pbs: 'o',
  openldap: 'b', grafana: 'o', cockpit: 'b', webmin: 'b', vsftpd: 'g', mariadb: 'b', files: 'm', iis: 'b', rdp: 'v', store: 'm',
  sql: 'r', exchange: 'b', adfs: 'v', wap: 'v', winrm: 'g', ldaps: 'o', sstp: 'g', ftp: 'g', ccs: 'b', rdgw: 'v', rds: 'v',
  sharepoint: 'g', wac: 'b', lync: 'b'};
var DISC_ABBR = {nginx: 'NG', apache: 'AP', haproxy: 'HA', postfix: 'PF', dovecot: 'DC', exim: 'EX', tomcat: 'TC', proxmox: 'PV',
  pbs: 'PB', openldap: 'LD', grafana: 'GF', cockpit: 'CP', webmin: 'WM', vsftpd: 'FT', mariadb: 'DB', files: '/', iis: 'IIS',
  rdp: 'RDP', store: 'MY', sql: 'SQL', exchange: 'EXC', adfs: 'ADFS', wap: 'WAP', winrm: 'WRM', ldaps: 'LDS', sstp: 'VPN',
  ftp: 'FTP', ccs: 'CCS', rdgw: 'GW', rds: 'RDS', sharepoint: 'SP', wac: 'WAC', lync: 'SfB'};
var DISC_ROLE = {cert: 'certificate', key: 'key', chain: 'chain', combined: 'key + chain', keystore: 'keystore'};
var DISC = {};          /* target id -> {view, at, busy} - kept while the page is open */
function discIcon(size) {
  var s = noI18n(el('span', 'ag-ic'));
  s.innerHTML = '<svg viewBox="0 0 24 24" width="' + (size || 16) + '" height="' + (size || 16) + '" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + DISC_IC + '</svg>';
  return s;
}
function discAllowed(a) { return arr(a && a.policy && a.policy.discover); }
function discWin(a) { return (a && a.platform === 'windows') || false; }
function discAllowLine(a, kinds) {
  return (discWin(a) ? '' : 'sudo ') + 'acme-agent allow discover' + (kinds && kinds.length ? ' ' + kinds.join(',') : '');
}
/** How long a certificate has: a pill (green, amber within 14 days, red when it ran out). */
function daysPill(c) {
  if (!c || c.days === undefined || c.days === null) return null;
  var d = Number(c.days), lv = d < 0 ? 'bad' : (d <= 14 ? 'warn' : 'ok');
  var p = el('span', 'ag-sys-pill ag-dc-days ' + lv);
  p.appendChild(noI18n(el('span', 'dot')));
  p.appendChild(el('span', '', d < 0 ? 'ran out' : (d === 1 ? '1 day left' : d + ' days left')));
  if (c.not_after) explain(p, tr('until') + ' ' + new Date(Number(c.not_after) * 1000).toLocaleDateString());
  return p;
}
function certLine(c, cls) {
  var line = el('div', 'ag-dc-cert' + (cls ? ' ' + cls : ''));
  if (!c) { line.appendChild(el('span', 'muted small', 'no certificate read there')); return line; }
  if (c.missing) {
    line.appendChild(el('span', 'ag-sys-pill bad', 'its certificate is not in the machine store'));
    line.appendChild(mono(String(c.thumbprint || '').slice(0, 16) + '…', 'small muted'));
    return line;
  }
  var w = el('div', 'ag-dc-cw');
  var top = el('div', 'ag-dc-ct');
  top.appendChild(icon('lock', 13));
  top.appendChild(mono(c.cn || c.subject || c.thumbprint, 'ag-dc-cn'));
  var dp = daysPill(c);
  if (dp) top.appendChild(dp);
  if (c.managed) {
    var m = el('span', 'ag-badge ok ag-dc-acme');
    m.appendChild(el('span', '', 'acme'));
    m.appendChild(data('b', '', c.managed.name));
    explain(m, c.managed.current ? 'This is the certificate acme holds now.' : 'An older version of this certificate of acme.');
    top.appendChild(m);
  } else if (c.acme) {
    top.appendChild(el('span', 'ag-badge ok ag-dc-acme', 'imported by acme'));
  } else {
    top.appendChild(el('span', 'ag-badge dim ag-dc-acme', 'not managed by acme'));
  }
  w.appendChild(top);
  var sub = el('div', 'ag-dc-cs');
  if (c.issuer) { sub.appendChild(el('span', 'ag-sys-l', 'issuer')); sub.appendChild(data('span', 'ag-dc-iss', c.issuer)); }
  if (arr(c.sans).length) {
    var more = arr(c.sans).filter(function (n) { return n !== c.cn; });
    if (more.length) { sub.appendChild(el('span', 'ag-sys-l', 'names')); sub.appendChild(data('span', 'ag-dc-iss', more.slice(0, 6).join(', ') + (more.length > 6 ? ' …' : ''))); }
  }
  w.appendChild(sub);
  if (c.thumbprint) {
    var t = mono(c.thumbprint.replace(/(.{4})/g, '$1 ').trim(), 'ag-dc-thumb');
    explain(t, 'SHA-1 thumbprint' + (c.serial ? ' · serial ' + c.serial : ''));
    w.appendChild(t);
  }
  line.appendChild(w);
  return line;
}
function discBadge(kind) {
  var b = noI18n(el('span', 'ag-dc-ic t-' + (DISC_TONE[kind] || 'm'), DISC_ABBR[kind] || String(kind).slice(0, 2).toUpperCase()));
  return b;
}
/** One service found: its names, its files, what it serves now - and what acme offers. */
function discCard(row, a, f, v, opts) {
  var c = el('div', 'ag-dc');
  var h = el('div', 'ag-dc-h');
  h.appendChild(discBadge(f.kind));
  var hw = el('div', 'ag-dc-hw');
  var ht = el('div', 'ag-dc-ht');
  ht.appendChild(noI18n(el('b', '', f.title || f.kind_title || f.kind)));
  if (f.unit) ht.appendChild(mono(f.unit, 'ag-dc-unit'));
  if (f.state && f.state !== 'Started') ht.appendChild(el('span', 'ag-badge warn', 'stopped'));
  hw.appendChild(ht);
  var where = f.site || f.config || f.detail || '';
  if (where && where !== f.kind) hw.appendChild(mono(where, 'ag-dc-where'));
  h.appendChild(hw);
  c.appendChild(h);
  var names = arr(f.names);
  if (names.length || arr(f.listen).length) {
    var ch = el('div', 'ag-dc-chips');
    names.slice(0, 8).forEach(function (n) { ch.appendChild(mono(n, 'ag-dc-name')); });
    if (names.length > 8) ch.appendChild(data('span', 'ag-dc-name more', '+' + (names.length - 8)));
    arr(f.listen).slice(0, 3).forEach(function (l) { ch.appendChild(mono(l, 'ag-dc-port')); });
    c.appendChild(ch);
  }
  if (arr(f.files).length) {
    var fl = el('div', 'ag-dc-files');
    arr(f.files).forEach(function (x) {
      var r = el('div', 'ag-dc-file' + (x.there ? '' : ' gone'));
      r.appendChild(el('span', 'ag-dc-role', DISC_ROLE[x.role] || x.role));
      r.appendChild(mono(x.path, 'ag-dc-path'));
      if (x.there) r.appendChild(mono((x.mode || '') + ' ' + (x.owner ? x.owner + ':' + (x.group || x.owner) : ''), 'ag-dc-meta'));
      else r.appendChild(el('span', 'ag-dc-meta warn', x.dynamic ? 'set at run time' : 'not there yet'));
      fl.appendChild(r);
    });
    c.appendChild(fl);
  }
  if (arr(f.bindings).length) {
    var bl = el('div', 'ag-dc-chips');
    arr(f.bindings).forEach(function (b) {
      var x = el('span', 'ag-dc-bind');
      x.appendChild(icon('globe', 12));
      x.appendChild(mono((b.host || (b.ip && b.ip !== '*' ? b.ip : '*')) + ':' + b.port));
      if (b.sni) x.appendChild(el('span', 'ag-dc-sni', 'SNI'));
      bl.appendChild(x);
    });
    c.appendChild(bl);
  }
  if (arr(f.instances).length || arr(f.listeners).length) {
    var il = el('div', 'ag-dc-chips');
    arr(f.instances).forEach(function (i) { var x = el('span', 'ag-dc-bind'); x.appendChild(icon('db', 12)); x.appendChild(mono(i.name)); il.appendChild(x); });
    arr(f.listeners).forEach(function (i) { var x = el('span', 'ag-dc-bind'); x.appendChild(icon('plug', 12)); x.appendChild(mono((i.host || '*') + ':' + (i.port || '5986'))); il.appendChild(x); });
    c.appendChild(il);
  }
  c.appendChild(certLine(f.cert));
  if (f.note) c.appendChild(data('p', 'note small ag-dc-note', f.note));
  var acts = el('div', 'ag-dc-acts');
  if (MANAGE) {
    var has = f.prefill && Object.keys(f.prefill).length;
    var mk = cmdButton('Make a deployment', 'add', 'small primary ag-dc-deploy');
    mk.disabled = !has || !H.newDeploy;
    if (!has) explain(mk, 'Nothing here acme could write to: no file of its was read.');
    mk.onclick = function () {
      var cert = f.cert && f.cert.managed && f.cert.managed.current ? f.cert.managed.id : null;
      H.newDeploy(row, {options: f.prefill, cert_id: cert, back: opts.reopen});
    };
    acts.appendChild(mk);
  }
  if (arr(f.items).length) {
    var pb = cmdButton('Add to the policy', 'shield', 'small ag-dc-policy');
    pb.onclick = function () { builder(row, {from: 'server', add: f.items, back: opts.reopen, done: opts.done}); };
    acts.appendChild(pb);
  }
  if (MANAGE && f.watch && H.newTest && !(f.cert && f.cert.managed)) {
    var wb = cmdButton('Watch it', 'eye', 'small ag-dc-watch');
    explain(wb, 'A test of what ' + (f.watch.host || 'the server') + ':' + f.watch.port + ' serves - its form filled in, saved by you.');
    wb.onclick = function () { watch(row, f.watch, opts); };
    acts.appendChild(wb);
  }
  if (acts.childNodes.length) c.appendChild(acts);
  return c;
}
function watch(row, w, opts) {
  H.newTest(w.kind, {config: {host: w.host, port: w.port, sni: w.sni || ''}, name: ('watch-' + (w.sni || w.host || row.name) + '-' + w.port).replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 60),
    note: tr('What the server serves - found by the discovery on') + ' ' + row.name}, opts.reopen);
}
/** The certificates found that acme does not manage: watched (a test), imported. */
function discUnmanaged(row, a, v, opts) {
  var list = arr(v.certs).filter(function (c) { return !c.managed && !c.acme; });
  var box = el('div', 'ag-du');
  var h = el('div', 'ag-du-h');
  h.appendChild(icon('flag', 14));
  h.appendChild(el('b', '', 'Certificates found that acme does not manage'));
  h.appendChild(noI18n(el('span', 'count', String(list.length))));
  box.appendChild(h);
  if (!list.length) { box.appendChild(el('p', 'muted small', 'Every certificate found is one of acme’s.')); return box; }
  list.slice(0, 40).forEach(function (c) {
    var r = el('div', 'ag-du-r');
    var d = Number(c.days);
    r.appendChild(noI18n(el('span', 'dot ' + (c.days === undefined ? 'dim' : (d < 0 ? 'bad' : (d <= 14 ? 'warn' : 'ok'))))));
    var w = el('div', 'ag-du-w');
    var t = el('div', 'ag-du-t');
    t.appendChild(mono(c.cn || c.subject || c.thumbprint, 'ag-du-cn'));
    var dp = daysPill(c);
    if (dp) t.appendChild(dp);
    w.appendChild(t);
    var s = el('div', 'ag-dc-cs');
    if (c.issuer) { s.appendChild(el('span', 'ag-sys-l', 'issuer')); s.appendChild(data('span', 'ag-dc-iss', c.issuer)); }
    w.appendChild(s);
    if (arr(c.where).length) w.appendChild(mono(arr(c.where).slice(0, 3).join(' · '), 'ag-du-where'));
    r.appendChild(w);
    var acts = el('div', 'ag-du-acts');
    if (MANAGE && c.watch && H.newTest) {
      var wb = cmdButton('Watch it', 'eye', 'small');
      wb.onclick = function () { watch(row, c.watch, opts); };
      acts.appendChild(wb);
    }
    if (MANAGE && H.importCert) {
      var ib = cmdButton('Import…', 'upload', 'small');
      var file = arr(c.where).map(function (x) { return String(x).split(' ').slice(1).join(' '); }).filter(function (x) { return x.charAt(0) === '/'; })[0];
      explain(ib, file ? tr('Its file on the server:') + ' ' + file + ' - ' + tr('copy it here; acme then renews it (a source of yours) or watches it.')
        : tr('Export it from the machine store (certlm.msc, with its key if acme is to deploy it) and drop the file here.'));
      ib.onclick = function () {
        H.importCert(opts.reopen);
        toast(file ? tr('Its file on the server:') + ' ' + file : tr('Export it from the machine store (certlm.msc) and drop the file here.'), 'info');
      };
      acts.appendChild(ib);
    }
    if (acts.childNodes.length) r.appendChild(acts);
    box.appendChild(r);
  });
  if (list.length > 40) box.appendChild(el('p', 'muted small', '…and ' + (list.length - 40) + ' more'));
  return box;
}
/** The card's "Found on this server" - only where the policy allows discovery; else the line
    that allows it. */
function discoverBox(row, a, opts) {
  opts = opts || {};
  var box = el('div', 'ag-disc');
  var head = el('div', 'ag-sys-h ag-disc-h');
  var hi = discIcon(16);
  head.appendChild(hi);
  head.appendChild(el('b', '', 'Found on this server'));
  var said = el('span', 'ag-sys-ago');
  head.appendChild(said);
  box.appendChild(head);
  var body = el('div', 'ag-disc-b');
  box.appendChild(body);
  var kinds = discAllowed(a);
  if (!a.policy) {
    body.appendChild(el('p', 'muted small', 'Its policy is not known yet - Ask it now.'));
    return box;
  }
  if (!kinds.length) {
    var off = el('div', 'ag-sys-none ag-disc-off');
    off.appendChild(discIcon(18));
    var w = el('div', 'ag-disc-offw');
    w.appendChild(el('b', '', 'Discovery is off on this server'));
    w.appendChild(el('p', 'note small', discWin(a)
      ? 'acme can list what this server runs that takes certificates - the IIS sites and their bindings, the Remote Desktop listener, the roles, the machine store - read-only, never a key. Its policy allows it with this line (an elevated prompt):'
      : 'acme can list what this server runs that takes certificates - nginx, Apache, HAProxy, Postfix, Dovecot, Tomcat, Proxmox… with their files and the certificate each serves - read-only, never a key. Its policy allows it with this line (as root):'));
    w.appendChild(cmdBox(discAllowLine(a, []), 'small ag-disc-line'));
    var pb = cmdButton('Allow it in the policy designer…', 'shield', 'small');
    pb.onclick = function () { builder(row, {from: 'server', add: [{kind: 'discover', kinds: ['*']}], back: opts.reopen, done: opts.done}); };
    var br = el('div', 'btnrow');
    br.appendChild(pb);
    w.appendChild(br);
    off.appendChild(w);
    body.appendChild(off);
    return box;
  }
  var allowedPill = el('span', 'ag-sys-pill ok ag-disc-kinds');
  allowedPill.appendChild(noI18n(el('span', 'dot')));
  allowedPill.appendChild(el('span', '', kinds[0] === '*' ? 'every kind allowed' : 'allowed: ' + kinds.join(', ')));
  explain(allowedPill, 'The policy on the server: ' + discAllowLine(a, kinds[0] === '*' ? [] : kinds).replace(/^sudo /, ''));
  head.appendChild(allowedPill);
  var look = null;
  var st = DISC[row.id] || (DISC[row.id] = {});
  var paint = function () {
    clear(body);
    clear(said);
    var v = st.view;
    if (look) look.disabled = !!st.busy;
    if (st.busy && !v) { body.appendChild(el('p', 'muted small ag-disc-busy', 'Looking at the server…')); return; }
    if (st.error) {
      var e = el('div', 'pb-msg bad ag-disc-err');
      e.appendChild(data('span', '', st.error));
      body.appendChild(e);
    }
    if (!v) {
      if (!st.error) body.appendChild(el('p', 'muted small', 'Not looked yet: Look now asks the agent what its server runs (read-only).'));
      return;
    }
    if (v.refused) {
      var r = el('div', 'ag-sys-none old ag-disc-off');
      r.appendChild(discIcon(18));
      var rw = el('div', '');
      rw.appendChild(el('b', '', 'The agent refused the discovery'));
      rw.appendChild(data('p', 'note small', v.said || ''));
      if (v.allow) rw.appendChild(cmdBox((discWin(a) ? '' : 'sudo ') + v.allow, 'small ag-disc-line'));
      r.appendChild(rw);
      body.appendChild(r);
      return;
    }
    if (v.at) {
      said.appendChild(el('span', '', 'looked ' + ago(v.at)));
      if (v.by) said.appendChild(data('span', '', ' · ' + v.by));
    }
    var found = arr(v.found), certs = arr(v.certs);
    var sum = el('div', 'ag-disc-sum');
    var s1 = el('span', 'ag-chip');
    s1.appendChild(icon('gear', 13));
    s1.appendChild(el('span', '', found.length === 1 ? '1 service' : found.length + ' services'));
    sum.appendChild(s1);
    var s2 = el('span', 'ag-chip');
    s2.appendChild(icon('lock', 13));
    s2.appendChild(el('span', '', certs.length === 1 ? '1 certificate' : certs.length + ' certificates'));
    sum.appendChild(s2);
    var um = Number(v.unmanaged || 0);
    var s3 = el('span', 'ag-chip' + (um ? ' warnc' : ''));
    s3.appendChild(icon('flag', 13));
    s3.appendChild(el('span', '', um + ' not managed by acme'));
    sum.appendChild(s3);
    var soon = certs.filter(function (c) { return c.days !== undefined && Number(c.days) <= 14; }).length;
    if (soon) {
      var s4 = el('span', 'ag-chip bad');
      s4.appendChild(icon('clock', 13));
      s4.appendChild(el('span', '', soon + ' end within 14 days'));
      sum.appendChild(s4);
    }
    body.appendChild(sum);
    if (!found.length) body.appendChild(el('p', 'muted small', 'Nothing of the kinds allowed was found on this server.'));
    var grid = el('div', 'ag-dc-grid');
    found.forEach(function (f) { grid.appendChild(discCard(row, a, f, v, opts)); });
    if (found.length) body.appendChild(grid);
    if (certs.length) body.appendChild(discUnmanaged(row, a, v, opts));
    arr(v.skipped).forEach(function (s) { body.appendChild(data('p', 'note warn small', s.kind + ': ' + s.why)); });
    if (v.truncated) body.appendChild(el('p', 'note warn small', 'Only part of it is shown: the server has more than an answer holds.'));
    explainWhatWasDrawn(body);
  };
  var run = function (live, button) {
    st.busy = true;
    st.error = '';
    paint();
    if (button) busy(button, true);
    return ask('agents/discover?target=' + encodeURIComponent(row.id || row.name) + (live ? '' : '&cached=1'), null, live ? 240 : 30).then(function (x) {
      st.busy = false;
      if (x && x.discovery) st.view = x.discovery;
      else if (live) st.view = null;
      paint();
    }).catch(function (e) {
      st.busy = false;
      st.error = String((e && e.message) || e);
      paint();
    }).then(function () { if (button) busy(button, false); });
  };
  if (MANAGE) {
    look = cmdButton('Look now', 'refresh', 'small ag-sys-ask ag-disc-look');
    explain(look, 'The agent reads what its server runs: configurations and the certificates there - nothing is changed, no key is read.');
    look.onclick = function () { run(true, look); };
    head.appendChild(look);
  }
  paint();
  if (MANAGE && !st.view && !st.busy && !st.asked) { st.asked = true; run(false); }
  return box;
}

function init(h) { Object.keys(h || {}).forEach(function (k) { H[k] = h[k]; }); }
/* certs.js is loaded before this file on the page: what it hands is waiting there */
if (window.ACME_AGENTS_HANDS) init(window.ACME_AGENTS_HANDS);
window.ACME_AGENTS = {
  init: init, hands: function () { return H; }, designBox: designBox,
  pane: pane, settle: settle, card: card, wizard: wizard, needs: needs, policyView: policyView,
  statePill: statePill, chips: chips, updateBox: updateBox, blockedBox: blockedBox, keysBox: keysBox,
  sysPanel: sysPanel, sysLine: sysLine, serversTable: serversTable, discoverBox: discoverBox
};
}());
