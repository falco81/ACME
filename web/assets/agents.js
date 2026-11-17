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
function otherProgram(a, shipped) {
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
  if (!hero) return;
  var ticket = ++PANE.ticket;
  function fill(d, how) {
    liveFill(hero, function (box) { drawHero(box, d); }, how);
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
    clear(hero);
    hero.appendChild(el('p', 'ct-bad', 'The target agents could not be asked: ' + String((e && e.message) || e)));
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
  var p = d.package;
  var h = el('h2', '');
  h.appendChild(document.createTextNode('The agent to install'));
  box.appendChild(h);
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
  var dl = cmdButton('Download', 'download', 'primary');
  dl.onclick = function () { download(dl); };
  tile.appendChild(dl);
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
  acts.appendChild(prog);
  t.appendChild(acts);
  if (otherProgram(a, d && d.shipped_code)) {
    t.appendChild(el('div', 'note warn small ag-older', 'Another program than the one this acme ships - install the package of this version.'));
  }
  return t;
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
    if (a.os) k.appendChild(kv('System', data('span', '', a.os)));
    if (a.agent_id) k.appendChild(kv('Agent id', mono(a.agent_id)));
    if (a.via) k.appendChild(kv('Reached through', mono(a.via)));
    if (a.key_fp) {
      var kf = mono(grouped(a.key_fp).slice(0, 4).join(' ') + ' …', 'ag-kfp');
      explain(kf, grouped(a.key_fp).join(' '));
      k.appendChild(kv('Its key', kf));
    }
    box.appendChild(k);
    if (otherProgram(a, a.shipped_code)) {
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
    w.appendChild(cmdBox('sudo acme-agent allow self-update', 'small'));
  }
  if (u.last && u.last.ok === false) w.appendChild(data('div', 'note bad small', String(u.last.said || '')));
  box.appendChild(w);
  return box;
}
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
          l.appendChild(r);
        });
        body.appendChild(l);
      }, [{words: 'Close', close: true}].concat(can.length ? [{words: can.length === 1 ? 'Update 1 agent' : 'Update ' + can.length + ' agents', cls: 'primary', icon: 'up', close: true, go: function () { updateMany(can); }}] : []), 'medium');
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
  box.appendChild(h);
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
  function one(host) {
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
    host.appendChild(el('h4', 'dbw-h', 'On the server, as root'));
    host.appendChild(cmdBox('sudo acme-agent join ' + c.code));
    host.appendChild(el('p', 'note small', 'Or at the install: sudo ./install.sh --join CODE. The agent makes its own key there (it never leaves the server) and prints its fingerprint - acme shows it next, to compare.'));
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
    if (i.ok !== true && i.allow) w.appendChild(cmdBox('sudo ' + String(i.allow).split('\n').join('\nsudo '), 'small'));
    r.appendChild(w);
    box.appendChild(r);
  });
  var lines = items.filter(function (i) { return i.ok !== true && i.allow; }).map(function (i) { return 'sudo ' + String(i.allow).split('\n').join('\nsudo '); });
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

function init(h) { Object.keys(h || {}).forEach(function (k) { H[k] = h[k]; }); }
/* certs.js is loaded before this file on the page: what it hands is waiting there */
if (window.ACME_AGENTS_HANDS) init(window.ACME_AGENTS_HANDS);
window.ACME_AGENTS = {
  init: init, hands: function () { return H; }, designBox: designBox,
  pane: pane, settle: settle, card: card, wizard: wizard, needs: needs, policyView: policyView,
  statePill: statePill, chips: chips, updateBox: updateBox, blockedBox: blockedBox, keysBox: keysBox
};
}());
