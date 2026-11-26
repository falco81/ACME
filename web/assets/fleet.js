/* fleet.js - Settings → Agent fleet (1.0.138, docs/agent-fleet.md): every target agent at once.

   A hero (the fleet's health as a ring, what needs a look, the versions as a chart), then five
   views: Groups (cards: health ring, members, the template and its drift, the versions, actions on
   all of them), Agents (each one, chosen for actions on many: ask now, update, compare with the
   template, a template, a group), Templates (built-in and the administrators' own policy
   templates - opened in the policy builder), Updates (the versions and an update in rings: the
   canary ring first, the rest after a wait when it is healthy) and Not managed (the certificates
   discovery found on the servers that acme does not manage, by risk - each taken over with a
   preview of what happens).

   Drawn with the page's own pieces (core.js: el, modal, cmdButton, explain, toast, liveFill) and
   the API of fleet.py (GET /api/fleet ...), asked through certs.js (window.ACME_CERTS.api). */
(function () {
'use strict';

var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
var FULL = ROLE === 'fulladmin';
var MANAGE = FULL || ROLE === 'certadmin';
var V = {d: null, tab: 'groups', sel: {}, q: '', ticket: 0, um: null, timer: null, plan: null};
var TABS = [['groups', 'Groups', 'people'], ['agents', 'Agents', 'terminal'], ['templates', 'Templates', 'shield'],
  ['updates', 'Updates', 'up'], ['unmanaged', 'Not managed', 'search']];
try { var t0 = localStorage.getItem('acme.fleet.tab'); if (t0 && TABS.some(function (t) { return t[0] === t0; })) V.tab = t0; } catch (e) { /* none kept */ }

function ask(path, body, wait) {
  var c = window.ACME_CERTS && window.ACME_CERTS.api;
  if (typeof c !== 'function') return Promise.reject(new Error('the page is not ready'));
  return c(path, body, wait);
}
function arr(v) { return Array.isArray(v) ? v : []; }
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function tr(w) { return typeof i18nText === 'function' ? (i18nText(w) || w) : w; }
function icon(key, size, cls) {
  var s = noI18n(el('span', 'fl-ic' + (cls ? ' ' + cls : '')));
  s.innerHTML = iconMarkup(key, size || 16);
  return s;
}
function initials(name) {
  var w = String(name || '?').replace(/[^A-Za-z0-9 .\-_]/g, '').split(/[\s.\-_]+/).filter(Boolean);
  return ((w[0] || '?')[0] + (w.length > 1 ? w[1][0] : (w[0] || '')[1] || '')).toUpperCase();
}
function hue(name) {
  var h = 0;
  String(name || '').split('').forEach(function (c) { h = (h * 31 + c.charCodeAt(0)) % 360; });
  return h;
}
function avatar(name, cls) {
  var a = data('span', 'fl-av' + (cls ? ' ' + cls : ''), initials(name));
  a.style.setProperty('--h', String(hue(name)));
  a.title = String(name || '');
  return a;
}
function agentsOf(ids) {
  var by = {};
  arr(V.d && V.d.agents).forEach(function (a) { by[a.id] = a; });
  return arr(ids).map(function (i) { return by[i]; }).filter(Boolean);
}
function agentById(id) { return agentsOf([id])[0]; }
function groupById(id) { return arr(V.d && V.d.groups).filter(function (g) { return g.id === id; })[0]; }
function tplByRef(ref) { return arr(V.d && V.d.templates).filter(function (t) { return t.ref === ref; })[0]; }
function kindWords(k) { return k === 'windows' ? 'Windows' : (k === 'kubernetes' ? 'Kubernetes' : 'Linux'); }
function kindIcon(k) { return k === 'windows' ? 'windows' : (k === 'kubernetes' ? 'gear' : 'terminal'); }
function healthWords(h) {
  return {ok: 'healthy', warn: 'to look at', bad: 'in trouble', idle: 'not joined yet'}[h] || h;
}
var STATE_WORDS = {answers: ['answers', 'ok'], quiet: ['not heard from', 'bad'], refused: ['refused', 'bad'],
  joining: ['joining', 'warn'], 'new': ['not joined', 'dim'], off: ['switched off', 'dim']};
function statePill(a) {
  if (window.ACME_AGENTS && window.ACME_AGENTS.statePill) return window.ACME_AGENTS.statePill(a);
  var m = STATE_WORDS[a.state] || [a.state || '–', 'dim'];
  return el('span', 'tag ' + m[1], m[0]);
}
function riskWords(r) {
  return {expired: 'expired', critical: 'ends this week', high: 'ends within 30 days', medium: 'ends within 60 days',
    'self-signed': 'self-signed', low: 'fine for now', unknown: 'no end known'}[r] || r;
}
function riskTone(r) {
  return {expired: 'bad', critical: 'bad', high: 'warn', medium: 'warn', 'self-signed': 'violet', low: 'ok', unknown: 'dim'}[r] || 'dim';
}
/** A number and its word as one text (the page's language makes them agree: "{0} agents"). */
function cnt(n, one, many) { return n + ' ' + (Number(n) === 1 ? one : many); }

/* ---- the rings and the chart ---------------------------------------------------------------- */
var SVGNS = 'http://www.w3.org/2000/svg';
function svg(kind, attrs) {
  var n = document.createElementNS(SVGNS, kind);
  Object.keys(attrs || {}).forEach(function (k) { n.setAttribute(k, attrs[k]); });
  return n;
}
/** The health as a ring: ok, warn, bad, idle - each its arc, the number of agents inside. */
function ring(h, size, label) {
  h = h || {};
  var total = (h.ok || 0) + (h.warn || 0) + (h.bad || 0) + (h.idle || 0);
  var box = el('div', 'fl-ring' + (size < 80 ? ' small' : ''));
  box.style.width = box.style.height = size + 'px';
  var r = 15.915, s = svg('svg', {viewBox: '0 0 36 36', 'aria-hidden': 'true', focusable: 'false'});
  s.appendChild(svg('circle', {cx: 18, cy: 18, r: r, 'class': 'fl-ring-bg'}));
  var at = 0;
  ['ok', 'warn', 'bad', 'idle'].forEach(function (k) {
    var n = h[k] || 0;
    if (!n || !total) return;
    var p = n / total * 100, gap = total > 1 && p < 100 ? 1.2 : 0;
    s.appendChild(svg('circle', {cx: 18, cy: 18, r: r, 'class': 'fl-ring-a ' + k,
      'stroke-dasharray': Math.max(p - gap, 0.6) + ' ' + (100 - Math.max(p - gap, 0.6)), 'stroke-dashoffset': String(25 - at)}));
    at += p;
  });
  box.appendChild(s);
  var mid = el('div', 'fl-ring-mid');
  mid.appendChild(data('b', '', String(total)));
  if (label) mid.appendChild(el('span', '', label));
  box.appendChild(mid);
  box.setAttribute('role', 'img');
  box.setAttribute('aria-label', [['ok', 'healthy'], ['warn', 'to look at'], ['bad', 'in trouble'], ['idle', 'not joined yet']]
    .map(function (x) { return (h[x[0]] || 0) + ' ' + tr(x[1]); }).join(', '));
  return box;
}
function legend(h) {
  var l = el('div', 'fl-legend');
  ['ok', 'warn', 'bad', 'idle'].forEach(function (k) {
    var i = el('span', 'fl-leg ' + k + ((h || {})[k] ? '' : ' zero'));
    i.appendChild(noI18n(el('span', 'fl-dot ' + k)));
    i.appendChild(data('b', '', String((h || {})[k] || 0)));
    i.appendChild(el('span', '', healthWords(k)));
    l.appendChild(i);
  });
  return l;
}
/** The versions as bars: the one acme offers green, older ones amber. */
function versionChart(versions, offered, compact) {
  var c = el('div', 'fl-vchart' + (compact ? ' compact' : ''));
  var most = Math.max.apply(null, [1].concat(arr(versions).map(function (v) { return v.count; })));
  var total = arr(versions).reduce(function (n, v) { return n + v.count; }, 0);
  if (!arr(versions).length) { c.appendChild(el('p', 'muted small', 'No agent has said its version yet.')); return c; }
  /* the whole as one stacked bar */
  var stack = el('div', 'fl-vstack');
  arr(versions).forEach(function (v) {
    var seg = noI18n(el('span', 'fl-vseg ' + (v.current ? 'cur' : 'old')));
    seg.style.flexGrow = String(v.count);
    seg.title = v.version + ': ' + v.count;
    stack.appendChild(seg);
  });
  c.appendChild(stack);
  arr(versions).slice(0, compact ? 4 : 50).forEach(function (v) {
    var row = el('div', 'fl-vrow');
    var lab = el('span', 'fl-vlab');
    lab.appendChild(data('span', 'mono', v.version));
    if (v.current) lab.appendChild(el('span', 'tag ok', v.version === offered ? 'offered' : 'newest'));
    row.appendChild(lab);
    var bar = el('span', 'fl-vbar');
    var fill = noI18n(el('span', 'fl-vfill ' + (v.current ? 'cur' : 'old')));
    fill.style.width = Math.max(4, Math.round(v.count / most * 100)) + '%';
    bar.appendChild(fill);
    row.appendChild(bar);
    row.appendChild(data('span', 'fl-vn', v.count + (total ? ' · ' + Math.round(v.count / total * 100) + ' %' : '')));
    c.appendChild(row);
  });
  if (compact && versions.length > 4) c.appendChild(el('span', 'muted small', 'more under Updates'));
  return c;
}

/* ---- the pane ---------------------------------------------------------------------------------- */
/* The fleet is the whole of the agents: an account kept to some teams is refused it (api_fleet's
   _whole) - asked anyway, its pane was a red failure and a 403 in the console. Said calmly
   instead, nothing asked (hunt v2). */
function scopedOut() {
  var t = window.ACME_TEAMS;
  if (!t || typeof t.load !== 'function') return Promise.resolve(false);
  return t.load().then(function (d) { return !!(d && d.scoped && d.scoped.view); }, function () { return false; });
}
function scopedNote(root) {
  clear(root);
  var e = el('div', 'fl-empty');
  e.id = 'fl-scoped';
  e.appendChild(icon('people', 30));
  e.appendChild(el('b', '', 'The fleet is for whoever sees every certificate'));
  e.appendChild(el('p', 'muted', 'This account sees the certificates of its teams only - the agents of its targets are under Settings → Target agents.'));
  root.appendChild(e);
}
function pane(live) {
  var root = $('fl-root');
  if (!root) return;
  var ticket = ++V.ticket;
  if (!V.d && !root.firstChild) root.appendChild(el('div', 'fl-asking', 'Asking for the fleet…'));
  scopedOut().then(function (no) {
    if (ticket !== V.ticket) return;
    if (no) { clearTimeout(V.timer); scopedNote(root); return; }
    paneAsk(root, ticket, live);
  });
}
function paneAsk(root, ticket, live) {
  ask('fleet').then(function (d) {
    if (ticket !== V.ticket) return;
    V.d = d;
    liveFill(root, draw, !!live);
    explainWhatWasDrawn(root);
    if (V.tab === 'unmanaged' && V.um === null) loadUnmanaged();
  }).catch(function (e) {
    if (ticket !== V.ticket) return;
    clear(root);
    root.appendChild(el('p', 'ct-bad', tr('The fleet could not be asked') + ': ' + String((e && e.message) || e)));
  });
  /* again every 30 s while it is shown (a rollout, an agent coming back) */
  clearTimeout(V.timer);
  V.timer = setTimeout(function () {
    var r = $('fl-root');
    if (r && r.offsetParent && !document.hidden && !($('modal') && !$('modal').hidden)) pane(true);
  }, 30000);
}
function again() { pane(true); }
function draw(box) {
  var d = V.d;
  box.appendChild(hero(d));
  var tabs = el('div', 'fl-tabs');
  tabs.setAttribute('role', 'tablist');
  TABS.forEach(function (t) {
    var b = el('button', 'fl-tab' + (V.tab === t[0] ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', V.tab === t[0] ? 'true' : 'false');
    b.appendChild(icon(t[2], 15));
    b.appendChild(el('span', '', t[1]));
    var n = t[0] === 'groups' ? arr(d.groups).length : t[0] === 'agents' ? arr(d.agents).length
      : t[0] === 'templates' ? arr(d.templates).length : t[0] === 'unmanaged' ? (d.unmanaged || 0) : 0;
    if (n) b.appendChild(data('span', 'fl-tab-n' + (t[0] === 'unmanaged' ? ' warn' : ''), String(n)));
    b.onclick = function () {
      V.tab = t[0];
      try { localStorage.setItem('acme.fleet.tab', V.tab); } catch (e) { /* not kept */ }
      if (V.tab === 'unmanaged' && V.um === null) loadUnmanaged();
      liveFill($('fl-root'), draw, false);
      explainWhatWasDrawn($('fl-root'));
      var nb = $('fl-root').querySelector('.fl-tab.on');
      if (nb) nb.focus();
    };
    b.onkeydown = function (ev) {
      if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
      var bs = Array.prototype.slice.call(tabs.children), i = bs.indexOf(b);
      var nx = bs[(i + (ev.key === 'ArrowRight' ? 1 : bs.length - 1)) % bs.length];
      if (nx) { nx.click(); ev.preventDefault(); }
    };
    tabs.appendChild(b);
  });
  box.appendChild(tabs);
  var body = el('div', 'fl-view');
  box.appendChild(body);
  if (!arr(d.agents).length && V.tab !== 'templates' && V.tab !== 'unmanaged') {
    var e = el('div', 'fl-empty');
    e.appendChild(icon('terminal', 30));
    e.appendChild(el('b', '', 'No target agent yet'));
    e.appendChild(el('p', 'muted', 'A target “Server with acme-agent” joins the fleet once it has an agent - see Settings → Target agents.'));
    body.appendChild(e);
    return;
  }
  ({groups: drawGroups, agents: drawAgents, templates: drawTemplates, updates: drawUpdates, unmanaged: drawUnmanaged}[V.tab] || drawGroups)(body, d);
}

function hero(d) {
  var h = el('div', 'fl-hero');
  var left = el('div', 'fl-hero-ring');
  left.appendChild(ring(d.health, 128, 'agents'));
  left.appendChild(legend(d.health));
  h.appendChild(left);
  var mid = el('div', 'fl-hero-mid');
  var t = el('div', 'fl-hero-t');
  t.appendChild(el('b', '', 'The fleet at a glance'));
  mid.appendChild(t);
  var drifted = arr(d.agents).filter(function (a) { return a.drift && a.drift.state === 'differs'; }).length;
  var newer = arr(d.agents).filter(function (a) { return a.newer; }).length;
  var following = arr(d.agents).filter(function (a) { return a.template; }).length;
  var kinds = {};
  arr(d.agents).forEach(function (a) { kinds[a.kind] = (kinds[a.kind] || 0) + 1; });
  var tiles = el('div', 'fl-tiles');
  [['people', arr(d.groups).length, 'groups', '', 'groups'],
    ['shield', following + ' / ' + arr(d.agents).length, 'follow a template', '', 'agents'],
    ['flag', drifted, 'drifted from it', drifted ? 'warn' : '', 'agents'],
    ['up', newer, 'a newer agent offered', newer ? 'info' : '', 'updates'],
    ['search', d.unmanaged || 0, 'certificates not managed', d.unmanaged ? 'warn' : '', 'unmanaged']].forEach(function (x) {
    var b = el('button', 'fl-tile ' + x[3]);
    b.type = 'button';
    b.appendChild(icon(x[0], 16));
    b.appendChild(data('b', '', String(x[1])));
    b.appendChild(el('span', '', x[2]));
    b.onclick = function () {
      V.tab = x[4];
      try { localStorage.setItem('acme.fleet.tab', V.tab); } catch (e) { /* not kept */ }
      if (V.tab === 'unmanaged' && V.um === null) loadUnmanaged();
      liveFill($('fl-root'), draw, false);
    };
    tiles.appendChild(b);
  });
  mid.appendChild(tiles);
  var ks = el('div', 'fl-kinds');
  Object.keys(kinds).sort().forEach(function (k) {
    var c = el('span', 'fl-kind ' + k);
    c.appendChild(icon(kindIcon(k), 13));
    c.appendChild(el('span', '', kindWords(k)));
    c.appendChild(data('b', '', String(kinds[k])));
    ks.appendChild(c);
  });
  mid.appendChild(ks);
  h.appendChild(mid);
  var right = el('div', 'fl-hero-v');
  var vh = el('div', 'fl-hero-vh');
  vh.appendChild(el('b', '', 'Versions'));
  var off = el('span', 'muted small');
  off.appendChild(el('span', '', 'acme offers'));
  off.appendChild(noI18n(document.createTextNode(' ')));
  off.appendChild(data('span', 'mono', String(d.offered || '?')));
  vh.appendChild(off);
  right.appendChild(vh);
  right.appendChild(versionChart(d.versions, d.offered, true));
  if (d.rollout && ['canary', 'waiting', 'rest', 'held'].indexOf(d.rollout.phase) >= 0) {
    var ro = el('button', 'fl-ro-mini ' + (d.rollout.phase === 'held' ? 'warn' : 'info'));
    ro.type = 'button';
    ro.appendChild(icon('up', 13));
    ro.appendChild(el('span', '', d.rollout.phase === 'held' ? 'The rollout is held' : 'An update rollout is under way'));
    ro.onclick = function () { V.tab = 'updates'; liveFill($('fl-root'), draw, false); };
    right.appendChild(ro);
  }
  h.appendChild(right);
  return h;
}

/* ---- groups ----------------------------------------------------------------------------------- */
function drawGroups(body, d) {
  var top = el('div', 'fl-bar');
  top.appendChild(el('span', 'muted small', 'A group takes actions on all its agents at once and can name the template its agents follow. The canary group is updated first.'));
  top.appendChild(el('span', 'spacer'));
  if (FULL) {
    var nb = cmdButton('New group', 'add', 'primary small');
    nb.onclick = function () { groupEdit(null); };
    top.appendChild(nb);
  }
  body.appendChild(top);
  var grid = el('div', 'fl-groups');
  arr(d.groups).forEach(function (g) { grid.appendChild(groupCard(g)); });
  /* the agents in no group */
  var inGroup = {};
  arr(d.groups).forEach(function (g) { arr(g.members).forEach(function (x) { inGroup[x] = 1; }); });
  var loose = arr(d.agents).filter(function (a) { return !inGroup[a.id]; });
  if (loose.length) {
    var h = {ok: 0, warn: 0, bad: 0, idle: 0};
    loose.forEach(function (a) { h[a.health] = (h[a.health] || 0) + 1; });
    grid.appendChild(groupCard({id: '', name: tr('In no group'), color: 'slate', note: '', members: loose.map(function (a) { return a.id; }),
      health: h, template: '', template_title: '', drifted: 0, versions: [], newer: loose.filter(function (a) { return a.newer; }).length, loose: true}));
  }
  if (!grid.children.length) {
    var e = el('div', 'fl-empty');
    e.appendChild(icon('people', 30));
    e.appendChild(el('b', '', 'No group yet'));
    e.appendChild(el('p', 'muted', 'Put the agents of one kind together - web servers, mail, the canary ring - and act on all of them at once.'));
    grid.appendChild(e);
  }
  body.appendChild(grid);
}
function groupCard(g) {
  var c = el('div', 'fl-group c-' + (g.color || 'blue') + (g.loose ? ' loose' : ''));
  var head = el('div', 'fl-group-h');
  head.appendChild(ring(g.health, 64));
  var w = el('div', 'fl-group-w');
  var nm = el('div', 'fl-group-n');
  nm.appendChild(g.loose ? el('b', '', g.name) : data('b', '', g.name));
  if (g.canary) {
    var cb = el('span', 'tag violet fl-canary', 'canary');
    explain(cb, 'The canary ring: an update rollout updates these agents first, waits, and goes on with the rest only when they are healthy.');
    nm.appendChild(cb);
  }
  w.appendChild(nm);
  if (g.note) w.appendChild(data('span', 'fl-group-note', g.note));
  w.appendChild(el('span', 'fl-group-c', cnt(arr(g.members).length, 'agent', 'agents')));
  head.appendChild(w);
  if (FULL && !g.loose) {
    var eb = iconButton('edit', tr('Edit the group'));
    eb.classList.add('fl-edit');
    eb.setAttribute('aria-label', tr('Edit the group') + ' ' + g.name);
    eb.onclick = function () { groupEdit(g); };
    head.appendChild(eb);
  }
  c.appendChild(head);
  /* members as avatars */
  var mem = agentsOf(g.members);
  var av = el('div', 'fl-avs');
  mem.slice(0, 7).forEach(function (a) {
    var x = avatar(a.name, 'h-' + a.health);
    x.tabIndex = 0;
    x.setAttribute('role', 'button');
    x.setAttribute('aria-label', a.name);
    explain(x, a.name + ' - ' + tr(healthWords(a.health)) + (a.version ? ' · acme-agent ' + a.version : ''));
    x.onclick = x.onkeydown = function (ev) { if (ev.type === 'keydown' && ev.key !== 'Enter') return; openAgent(a); };
    av.appendChild(x);
  });
  if (mem.length > 7) av.appendChild(data('span', 'fl-av more', '+' + (mem.length - 7)));
  if (!mem.length) av.appendChild(el('span', 'muted small', 'No member yet.'));
  c.appendChild(av);
  /* the template and its drift, the versions */
  var facts = el('div', 'fl-group-f');
  var tf = el('div', 'fl-fact');
  tf.appendChild(icon('shield', 14));
  if (g.template) {
    var tt = tplByRef(g.template);
    tf.appendChild(tt && tt.builtin ? el('span', '', g.template_title) : data('span', '', g.template_title || '?'));
    tf.appendChild(el('span', 'tag ' + (g.drifted ? 'warn' : 'ok'), g.drifted ? cnt(g.drifted, 'drifted', 'drifted') : 'all match'));
  } else tf.appendChild(el('span', 'muted', g.loose ? 'each its own template' : 'no template'));
  facts.appendChild(tf);
  var vf = el('div', 'fl-fact');
  vf.appendChild(icon('up', 14));
  if (arr(g.versions).length) arr(g.versions).slice(0, 3).forEach(function (v) { vf.appendChild(data('span', 'fl-chip mono', v.version + ' ×' + v.count)); });
  else vf.appendChild(el('span', 'muted', 'no version said'));
  if (g.newer) vf.appendChild(el('span', 'tag info', cnt(g.newer, 'to update', 'to update')));
  facts.appendChild(vf);
  c.appendChild(facts);
  /* actions on all of it */
  var acts = el('div', 'fl-group-a');
  var ids = arr(g.members);
  if (MANAGE && ids.length) {
    var a1 = cmdButton('Ask now', 'refresh', 'small');
    a1.onclick = function () { act('ask', ids, a1); };
    acts.appendChild(a1);
  }
  if (FULL && g.newer) {
    var a2 = cmdButton('Update', 'up', 'small');
    a2.onclick = function () { updateAsk(ids, a2); };
    acts.appendChild(a2);
  }
  if (ids.length) {
    var a3 = cmdButton('Compare', 'eye', 'small');
    explain(a3, 'Each agent’s policy against the template it should follow: the lines missing on the server and those it has besides.');
    a3.onclick = function () { driftView(ids, g.loose ? '' : g.name); };
    acts.appendChild(a3);
  }
  if (FULL && g.loose && ids.length) {
    var a5 = cmdButton('Template…', 'shield', 'small');
    a5.onclick = function () { assignDialog(ids); };
    acts.appendChild(a5);
  }
  c.appendChild(acts);
  return c;
}
function openAgent(a) {
  var h = window.ACME_AGENTS && window.ACME_AGENTS.hands && window.ACME_AGENTS.hands();
  if (h && h.openTarget) h.openTarget(a.name);
}

/* ---- one group, made or changed ------------------------------------------------------------- */
function groupEdit(g) {
  var d = V.d || {};
  var F = {name: g ? g.name : '', color: g ? g.color || 'blue' : 'blue', note: g ? g.note || '' : '', template: g ? g.template || '' : '',
    canary: g ? !!g.canary : false, members: g ? arr(g.members).slice() : []};
  modal(g ? 'Group ' + g.name : 'New group', function (body) {
    var f = el('div', 'fl-form');
    var nl = el('label', 'fl-field');
    nl.appendChild(el('span', 'fl-k', 'Name'));
    var ni = el('input', '');
    ni.type = 'text';
    ni.value = F.name;
    ni.maxLength = 80;
    ni.placeholder = 'Web servers';
    ni.oninput = function () { F.name = ni.value; };
    nl.appendChild(ni);
    f.appendChild(nl);
    var cl = el('div', 'fl-field');
    cl.appendChild(el('span', 'fl-k', 'Colour'));
    var sw = el('div', 'fl-swatches');
    sw.setAttribute('role', 'radiogroup');
    arr(d.colors).forEach(function (c) {
      var b = el('button', 'fl-sw c-' + c + (F.color === c ? ' on' : ''));
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', F.color === c ? 'true' : 'false');
      b.setAttribute('aria-label', c);
      b.onclick = function () {
        F.color = c;
        Array.prototype.forEach.call(sw.children, function (x) { x.classList.remove('on'); x.setAttribute('aria-checked', 'false'); });
        b.classList.add('on');
        b.setAttribute('aria-checked', 'true');
      };
      sw.appendChild(b);
    });
    cl.appendChild(sw);
    f.appendChild(cl);
    var tl = el('label', 'fl-field');
    tl.appendChild(el('span', 'fl-k', 'Its agents follow the template'));
    tl.appendChild(tplSelect(F.template, '', function (v) { F.template = v; }));
    f.appendChild(tl);
    var ol = el('label', 'fl-field');
    ol.appendChild(el('span', 'fl-k', 'Note'));
    var oi = el('textarea', '');
    oi.rows = 2;
    oi.value = F.note;
    oi.placeholder = 'What these servers are';
    oi.oninput = function () { F.note = oi.value; };
    ol.appendChild(oi);
    f.appendChild(ol);
    var cy = el('label', 'fl-check');
    var cyi = el('input', '');
    cyi.type = 'checkbox';
    cyi.checked = F.canary;
    cyi.onchange = function () { F.canary = cyi.checked; };
    cy.appendChild(cyi);
    cy.appendChild(el('span', '', 'The canary ring: updated first in an update rollout'));
    f.appendChild(cy);
    body.appendChild(f);
    /* the members, chosen */
    var mh = el('div', 'fl-mem-h');
    mh.appendChild(el('b', '', 'Members'));
    var q = el('input', 'fl-find ct-kind-find');
    q.type = 'search';
    q.placeholder = 'a name, a host, a version…';
    mh.appendChild(q);
    body.appendChild(mh);
    var list = el('div', 'fl-mem');
    body.appendChild(list);
    var paint = function () {
      clear(list);
      var s = q.value.trim().toLowerCase();
      arr(d.agents).forEach(function (a) {
        if (s && (a.name + ' ' + a.host + ' ' + a.version + ' ' + a.kind).toLowerCase().indexOf(s) < 0) return;
        var r = el('label', 'fl-mem-r');
        var cb = el('input', '');
        cb.type = 'checkbox';
        cb.checked = F.members.indexOf(a.id) >= 0;
        cb.onchange = function () {
          var i = F.members.indexOf(a.id);
          if (cb.checked && i < 0) F.members.push(a.id);
          if (!cb.checked && i >= 0) F.members.splice(i, 1);
        };
        r.appendChild(cb);
        r.appendChild(avatar(a.name, 'h-' + a.health + ' small'));
        var w = el('span', 'fl-mem-w');
        w.appendChild(data('b', '', a.name));
        w.appendChild(data('span', 'muted small', [kindWords(a.kind), a.host, a.version].filter(Boolean).join(' · ')));
        r.appendChild(w);
        list.appendChild(r);
      });
      if (!list.children.length) list.appendChild(el('p', 'muted small', 'No agent of that name.'));
    };
    q.oninput = paint;
    paint();
    setTimeout(function () { try { ni.focus(); } catch (e) { /* no focus */ } }, 30);
  }, [
    g ? {words: 'Delete group', icon: 'trash', go: function () {
      ask('fleet/group_delete', {id: g.id}).then(function () { toast(tr('the group is deleted'), 'good'); closeModal(); again(); }).catch(oops);
    }} : null,
    {words: 'Cancel', close: true},
    {words: g ? 'Save' : 'Make the group', cls: 'primary', icon: 'save', go: function (b) {
      if (!String(F.name).trim()) { toast(tr('a group needs a name'), 'bad'); return; }
      busy(b, true);
      ask('fleet/group_save', {id: g ? g.id : '', name: F.name, color: F.color, note: F.note, template: F.template, canary: F.canary,
        members: F.members}).then(function () {
        toast(tr('the group is saved'), 'good');
        closeModal();
        again();
      }).catch(oops).then(function () { busy(b, false); });
    }}
  ], 'fl-box');
}
function tplSelect(value, platform, change) {
  var s = el('select', '');
  var o0 = el('option', '', '- none -');
  o0.value = '';
  s.appendChild(o0);
  [['linux', 'Linux'], ['windows', 'Windows']].forEach(function (p) {
    if (platform && platform !== p[0]) return;
    var og = el('optgroup', '');
    og.label = p[1];
    arr(V.d && V.d.templates).filter(function (t) { return t.platform === p[0]; }).forEach(function (t) {
      var o = el('option', '', t.title + (t.builtin ? '' : ' ★'));
      if (!t.builtin) noI18n(o);
      o.value = t.ref;
      if (t.ref === value) o.selected = true;
      og.appendChild(o);
    });
    if (og.children.length) s.appendChild(og);
  });
  s.onchange = function () { change(s.value); };
  return s;
}

/* ---- agents ---------------------------------------------------------------------------------- */
function selected() { return Object.keys(V.sel).filter(function (k) { return V.sel[k]; }).map(Number).filter(function (i) { return agentById(i); }); }
function drawAgents(body, d) {
  var top = el('div', 'fl-bar');
  var q = el('input', 'fl-find ct-kind-find');
  q.type = 'search';
  q.placeholder = 'a name, a host, a group, a version…';
  q.value = V.q;
  q.setAttribute('aria-label', 'Find an agent');
  top.appendChild(q);
  var seg = el('div', 'fl-seg');
  V.health = V.health || '';
  [['', 'all'], ['bad', 'in trouble'], ['warn', 'to look at'], ['drift', 'drifted'], ['newer', 'to update']].forEach(function (x) {
    var b = el('button', 'fl-seg-b' + (V.health === x[0] ? ' on' : ''), x[1]);
    b.type = 'button';
    b.setAttribute('aria-pressed', V.health === x[0] ? 'true' : 'false');
    b.onclick = function () { V.health = x[0]; liveFill($('fl-root'), draw, false); };
    seg.appendChild(b);
  });
  top.appendChild(seg);
  body.appendChild(top);
  var list = el('div', 'fl-agents');
  list.setAttribute('role', 'list');
  body.appendChild(list);
  var bar = el('div', 'fl-bulk');
  body.appendChild(bar);
  var gname = {};
  arr(d.groups).forEach(function (g) { gname[g.id] = g; });
  var paint = function () {
    clear(list);
    var s = q.value.trim().toLowerCase();
    var rows = arr(d.agents).filter(function (a) {
      if (V.health === 'bad' && a.health !== 'bad') return false;
      if (V.health === 'warn' && a.health !== 'warn') return false;
      if (V.health === 'drift' && !(a.drift && a.drift.state === 'differs')) return false;
      if (V.health === 'newer' && !a.newer) return false;
      if (!s) return true;
      var g = arr(a.groups).map(function (x) { return (gname[x] || {}).name || ''; }).join(' ');
      return (a.name + ' ' + a.host + ' ' + a.version + ' ' + a.kind + ' ' + g + ' ' + (a.template ? a.template.title : '')).toLowerCase().indexOf(s) >= 0;
    });
    var all = el('label', 'fl-arow fl-ahead');
    var ac = el('input', '');
    ac.type = 'checkbox';
    ac.setAttribute('aria-label', 'Choose every agent shown');
    ac.checked = rows.length > 0 && rows.every(function (a) { return V.sel[a.id]; });
    ac.onchange = function () { rows.forEach(function (a) { V.sel[a.id] = ac.checked; }); paint(); };
    all.appendChild(ac);
    all.appendChild(el('span', 'fl-a-name', 'Agent'));
    all.appendChild(el('span', 'fl-a-st', 'State'));
    all.appendChild(el('span', 'fl-a-ver', 'Version'));
    all.appendChild(el('span', 'fl-a-grp', 'Groups'));
    all.appendChild(el('span', 'fl-a-tpl', 'Template'));
    list.appendChild(all);
    rows.forEach(function (a) { list.appendChild(agentRow(a, gname, function () {
      ac.checked = rows.length > 0 && rows.every(function (x) { return V.sel[x.id]; });
      paintBulk();
    })); });
    if (!rows.length) list.appendChild(el('p', 'muted small fl-none', 'No agent fits.'));
    paintBulk();
  };
  var paintBulk = function () {
    clear(bar);
    var ids = selected();
    bar.classList.toggle('on', ids.length > 0);
    if (!ids.length) return;
    bar.appendChild(data('b', 'fl-bulk-n', String(ids.length)));
    bar.appendChild(el('span', 'fl-bulk-w', 'chosen'));
    if (MANAGE) { var b1 = cmdButton('Ask now', 'refresh', 'small'); b1.onclick = function () { act('ask', ids, b1); }; bar.appendChild(b1); }
    if (FULL) { var b2 = cmdButton('Update', 'up', 'small'); b2.onclick = function () { updateAsk(ids, b2); }; bar.appendChild(b2); }
    var b3 = cmdButton('Compare with the template', 'eye', 'small fl-cmp');
    b3.onclick = function () { driftView(ids, ''); };
    bar.appendChild(b3);
    if (FULL) {
      var b4 = cmdButton('Template…', 'shield', 'small');
      b4.onclick = function () { assignDialog(ids); };
      bar.appendChild(b4);
      if (arr(d.groups).length) {
        var b5 = cmdButton('Add to a group…', 'people', 'small');
        b5.onclick = function () { addToGroup(ids); };
        bar.appendChild(b5);
      }
    }
    var x = cmdButton('', 'close', 'small fl-bulk-x');
    x.setAttribute('aria-label', 'Choose none');
    x.title = 'Choose none';
    x.onclick = function () { V.sel = {}; paint(); };
    bar.appendChild(x);
  };
  V.paintAgents = paint;
  q.oninput = function () { V.q = q.value; paint(); };
  paint();
}
function agentRow(a, gname, repaint) {
  var r = el('div', 'fl-arow h-' + a.health + (V.sel[a.id] ? ' sel' : ''));
  r.setAttribute('role', 'listitem');
  var cb = el('input', '');
  cb.type = 'checkbox';
  cb.checked = !!V.sel[a.id];
  cb.setAttribute('aria-label', tr('Choose') + ' ' + a.name);
  cb.onchange = function () { V.sel[a.id] = cb.checked; r.classList.toggle('sel', cb.checked); repaint(); };
  r.appendChild(cb);
  var n = el('div', 'fl-a-name');
  n.appendChild(avatar(a.name, 'h-' + a.health + ' small'));
  var nw = el('div', 'fl-a-nw');
  var nb = data('button', 'fl-link', a.name);
  nb.type = 'button';
  nb.onclick = function () { openAgent(a); };
  nw.appendChild(nb);
  var sub = el('span', 'fl-a-sub');
  sub.appendChild(icon(kindIcon(a.kind), 12));
  sub.appendChild(el('span', '', kindWords(a.kind)));
  if (a.host) { sub.appendChild(noI18n(document.createTextNode(' · '))); sub.appendChild(data('span', 'mono', a.host)); }
  nw.appendChild(sub);
  n.appendChild(nw);
  r.appendChild(n);
  var st = el('div', 'fl-a-st');
  st.appendChild(statePill(a));
  if (arr(a.why).length && a.health === 'warn') {
    var w = el('span', 'fl-why ' + a.health, a.why[0]);
    if (a.why.length > 1) explain(w, a.why.map(tr).join('\n'));
    st.appendChild(w);
  }
  r.appendChild(st);
  var v = el('div', 'fl-a-ver');
  v.appendChild(data('span', 'mono', a.version || '–'));
  if (a.newer) {
    var up = el('span', 'tag info', 'newer offered');
    explain(up, a.self_update ? 'Its policy lets acme update it (allow self-update).' : 'Its policy has no allow self-update: it is updated by hand on the server.');
    v.appendChild(up);
  }
  r.appendChild(v);
  var g = el('div', 'fl-a-grp');
  arr(a.groups).forEach(function (x) {
    var gg = gname[x];
    if (gg) g.appendChild(data('span', 'fl-gchip c-' + (gg.color || 'blue'), gg.name));
  });
  if (!g.children.length) g.appendChild(el('span', 'muted small', '–'));
  r.appendChild(g);
  var t = el('div', 'fl-a-tpl');
  if (a.template) {
    var tt = tplByRef(a.template.ref);
    t.appendChild(tt && tt.builtin ? el('span', 'fl-tname', a.template.title) : data('span', 'fl-tname', a.template.title));
    var ds = (a.drift || {}).state;
    var pill = el('button', 'tag fl-dpill ' + (ds === 'matches' ? 'ok' : ds === 'differs' ? 'warn' : 'dim'),
      ds === 'matches' ? 'matches' : ds === 'differs' ? 'drifted' : ds === 'other' ? 'other platform' : 'not asked yet');
    pill.type = 'button';
    pill.onclick = function () { driftView([a.id], ''); };
    if (ds === 'differs') explain(pill, tr('missing on the server') + ': ' + a.drift.missing + ' · ' + tr('besides it') + ': ' + a.drift.extra);
    t.appendChild(pill);
  } else t.appendChild(el('span', 'muted small', 'none'));
  r.appendChild(t);
  return r;
}

/* ---- actions ---------------------------------------------------------------------------------- */
function act(action, ids, button) {
  if (button) busy(button, true);
  ask('fleet/act', {action: action, ids: ids}, 60).then(function (x) {
    toast(action === 'ask' ? tr('the agents are asked now') : tr('the agents are being updated'), 'good');
    if (x && x.job_id) follow(x.job_id);
  }).catch(oops).then(function () { if (button) busy(button, false); });
}
/** A job of the fleet followed: its steps shown (jobPeek), the pane asked again when it ends. */
function follow(jid) {
  if (window.ACME_CERTS && window.ACME_CERTS.jobPeek) window.ACME_CERTS.jobPeek(jid);
  var n = 0;
  var look = function () {
    ask('certs/job?id=' + encodeURIComponent(jid)).then(function (x) {
      if (x && x.job && x.job.live && n++ < 200) setTimeout(look, 2500);
      else pane(true);
    }).catch(function () { pane(true); });
  };
  setTimeout(look, 1500);
}
function updateAsk(ids, button) {
  var ags = agentsOf(ids).filter(function (a) { return a.newer; });
  if (!ags.length) { toast(tr('every one of them runs the newest agent'), 'good'); return; }
  modalSure(tr('Update the agents') + ' (' + ags.length + ')? ' + tr('Only those whose policy allows it are updated; each checks the package’s signature itself.'), function () {
    act('update', ags.map(function (a) { return a.id; }), button);
  }, 'Update');
}
function assignDialog(ids) {
  var ags = agentsOf(ids);
  var plats = {};
  ags.forEach(function (a) { plats[a.platform] = 1; });
  var only = Object.keys(plats).length === 1 ? Object.keys(plats)[0] : '';
  var F = {ref: ''};
  modal('The template of ' + cnt(ags.length, 'agent', 'agents'), function (body) {
    body.appendChild(el('p', 'small muted', 'Each of these agents should follow this template - before the template of its groups. It is documentation, as a design is: acme never sends a policy; the drift says where a server differs.'));
    var l = el('label', 'fl-field');
    l.appendChild(el('span', 'fl-k', 'Template'));
    l.appendChild(tplSelect('', only, function (v) { F.ref = v; }));
    body.appendChild(l);
    var av = el('div', 'fl-avs');
    ags.slice(0, 20).forEach(function (a) { av.appendChild(avatar(a.name, 'h-' + a.health + ' small')); });
    body.appendChild(av);
  }, [{words: 'Cancel', close: true}, {words: 'Set it', cls: 'primary', icon: 'save', go: function (b) {
    busy(b, true);
    ask('fleet/assign', {ids: ids, template: F.ref}).then(function () {
      toast(F.ref ? tr('the template is set') : tr('the template is taken away'), 'good');
      closeModal();
      again();
    }).catch(oops).then(function () { busy(b, false); });
  }}], true);
}
function addToGroup(ids) {
  var F = {g: arr(V.d.groups)[0] ? V.d.groups[0].id : ''};
  modal('Add to a group', function (body) {
    var l = el('label', 'fl-field');
    l.appendChild(el('span', 'fl-k', 'Group'));
    var s = el('select', '');
    noI18n(s);
    arr(V.d.groups).forEach(function (g) { var o = el('option', '', g.name); o.value = g.id; s.appendChild(o); });
    s.onchange = function () { F.g = s.value; };
    l.appendChild(s);
    body.appendChild(l);
  }, [{words: 'Cancel', close: true}, {words: 'Add', cls: 'primary', icon: 'add', go: function (b) {
    var g = groupById(F.g);
    if (!g) return;
    busy(b, true);
    var mem = arr(g.members).slice();
    ids.forEach(function (i) { if (mem.indexOf(i) < 0) mem.push(i); });
    ask('fleet/group_save', {id: g.id, members: mem}).then(function () {
      toast(tr('added to the group'), 'good');
      closeModal();
      again();
    }).catch(oops).then(function () { busy(b, false); });
  }}], true);
}

/* ---- the drift: each agent's policy against its template --------------------------------------- */
function driftView(ids, title) {
  modal(title ? 'Compared with the template: ' + title : 'Compared with the template', function (body) {
    var w = el('div', 'fl-drift');
    w.appendChild(el('div', 'fl-asking', 'Comparing…'));
    body.appendChild(w);
    ask('fleet/drift?ids=' + ids.join(',')).then(function (x) {
      clear(w);
      var rows = arr(x && x.rows);
      var none = rows.filter(function (r) { return !r.drift; });
      rows.filter(function (r) { return r.drift; }).forEach(function (r) { w.appendChild(driftCard(r)); });
      if (none.length) {
        var n = el('div', 'fl-drift-none');
        n.appendChild(el('span', 'muted small', 'Follow no template'));
        none.forEach(function (r) { n.appendChild(data('span', 'fl-chip', r.name)); });
        w.appendChild(n);
      }
      explainWhatWasDrawn(w);
    }).catch(function (e) { clear(w); w.appendChild(el('p', 'ct-bad', String((e && e.message) || e))); });
  }, [{words: 'Close', close: true}], 'fl-box');
}
function driftCard(r) {
  var d = r.drift, a = agentById(r.id) || {name: r.name, platform: 'linux'};
  var c = el('div', 'fl-dcard ' + d.state);
  var h = el('div', 'fl-dcard-h');
  h.appendChild(avatar(r.name, 'small h-' + (d.state === 'matches' ? 'ok' : d.state === 'differs' ? 'warn' : 'idle')));
  var w = el('div', 'fl-dcard-w');
  w.appendChild(data('b', '', r.name));
  var sub = el('span', 'muted small');
  sub.appendChild(el('span', '', d.template.via === 'group' ? 'follows, through its group, the template' : 'follows the template'));
  sub.appendChild(noI18n(document.createTextNode(' ')));
  var tt = tplByRef(d.template.ref);
  sub.appendChild(tt && tt.builtin ? el('b', '', d.template.title) : data('b', '', d.template.title));
  if (d.template.group) { sub.appendChild(noI18n(document.createTextNode(' · '))); sub.appendChild(data('span', '', d.template.group)); }
  w.appendChild(sub);
  h.appendChild(w);
  h.appendChild(el('span', 'tag ' + (d.state === 'matches' ? 'ok' : d.state === 'differs' ? 'warn' : 'dim'),
    d.state === 'matches' ? 'matches' : d.state === 'differs' ? 'drifted' : d.state === 'other' ? 'other platform' : 'not asked yet'));
  c.appendChild(h);
  if (d.state === 'unknown') c.appendChild(el('p', 'muted small', 'The agent has not said its policy yet - Ask now.'));
  if (d.state === 'other') c.appendChild(el('p', 'muted small', 'The template is for another platform than the agent runs on.'));
  if (d.state !== 'differs') return c;
  var diff = el('div', 'fl-diff');
  arr(d.missing).forEach(function (l) { var x = el('div', 'fl-diff-l add'); x.appendChild(data('span', 'fl-diff-mk', '+')); x.appendChild(data('code', '', l)); diff.appendChild(x); });
  arr(d.extra).forEach(function (l) { var x = el('div', 'fl-diff-l del'); x.appendChild(data('span', 'fl-diff-mk', '−')); x.appendChild(data('code', '', l)); diff.appendChild(x); });
  c.appendChild(diff);
  var leg = el('div', 'fl-diff-leg');
  leg.appendChild(el('span', 'add', 'missing on the server'));
  leg.appendChild(el('span', 'del', 'on the server besides the template'));
  c.appendChild(leg);
  /* to make it match: the template written on the server (root) */
  var tb = el('div', 'fl-dcard-a');
  var cp = cmdButton('Copy the lines to make it match', 'copy', 'small');
  cp.onclick = function () {
    ask('fleet/template?ref=' + encodeURIComponent(d.template.ref)).then(function (x) {
      var text = String((x && x.template && x.template.text) || '');
      var win = a.platform === 'windows';
      copyText(win ? text : 'sudo acme-agent policy apply - <<\'EOF\'\n' + text + (text.slice(-1) === '\n' ? '' : '\n') + 'EOF\n', cp, 'on the clipboard');
    }).catch(oops);
  };
  explain(cp, a.platform === 'windows' ? 'The template’s policy file - save it on the server and apply it in an elevated prompt: acme-agent policy apply FILE.'
    : 'One block to paste into a root shell on the server: acme-agent policy apply checks it and writes it in place of the policy there.');
  tb.appendChild(cp);
  c.appendChild(tb);
  return c;
}

/* ---- templates ------------------------------------------------------------------------------- */
/* 1.0.147: the lines shown and copied as they are in the policy file, or as the commands that
   write them on the server (acme-agent allow ..., no sudo) - one choice for every card, kept */
try { V.tplAs = localStorage.getItem('acme.fleet.tplAs') === 'commands' ? 'commands' : 'policy'; } catch (e) { V.tplAs = 'policy'; }
function asCmds(lines, platform) {
  var C = window.ACME_POLICY_CORE;
  return C && C.asCommands ? C.asCommands(lines, platform === 'windows', false) : arr(lines).map(function (l) { return 'acme-agent ' + l; });
}
function drawTemplates(body, d) {
  var top = el('div', 'fl-bar fl-tpl-top');
  top.appendChild(el('span', 'muted small', 'A template is a whole policy for one kind of server. New template… opens the policy builder and keeps what is clicked together there as your own. acme never sends a policy: root writes it on the server.'));
  var tools = el('div', 'fl-tpl-tools');
  var seg = el('div', 'seg fl-tpl-as');
  seg.setAttribute('role', 'group');
  seg.setAttribute('aria-label', tr('Show the lines as'));
  [['policy', 'Policy lines'], ['commands', 'acme-agent commands']].forEach(function (o) {
    var b = el('button', V.tplAs === o[0] ? 'on' : '', o[1]);
    b.type = 'button';
    b.setAttribute('aria-pressed', V.tplAs === o[0] ? 'true' : 'false');
    b.onclick = function () {
      if (V.tplAs === o[0]) return;
      V.tplAs = o[0];
      try { localStorage.setItem('acme.fleet.tplAs', V.tplAs); } catch (e) { /* not kept */ }
      clear(body);
      drawTemplates(body, d);
    };
    seg.appendChild(b);
  });
  explain(seg, 'Policy lines are the policy file as it is. acme-agent commands are the same entries as commands for a root shell on the server (an elevated prompt on Windows) - each adds to what is allowed there. Copy copies what is shown.');
  tools.appendChild(seg);
  if (FULL) {
    var nb = cmdButton('New template…', 'add', 'small primary');
    nb.onclick = function () { tplBuild(null); };
    tools.appendChild(nb);
  }
  top.appendChild(tools);
  body.appendChild(top);
  [['linux', 'Linux'], ['windows', 'Windows']].forEach(function (p) {
    var ts = arr(d.templates).filter(function (t) { return t.platform === p[0]; });
    if (!ts.length) return;
    var h = el('h3', 'fl-h3');
    h.appendChild(icon(p[0] === 'windows' ? 'windows' : 'terminal', 15));
    h.appendChild(el('span', '', p[1]));
    body.appendChild(h);
    var g = el('div', 'fl-tpls');
    ts.forEach(function (t) { g.appendChild(tplCard(t)); });
    body.appendChild(g);
  });
}
function tplCard(t) {
  var c = el('div', 'fl-tpl' + (t.builtin ? '' : ' own'));
  var h = el('div', 'fl-tpl-h');
  h.appendChild(data('span', 'fl-tpl-ic', String(t.title).replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase()));
  var w = el('div', 'fl-tpl-w');
  w.appendChild(t.builtin ? el('b', '', t.title) : data('b', '', t.title));
  var sub = el('span', 'muted small');
  sub.appendChild(el('span', '', t.builtin ? 'built-in' : 'yours'));
  if (!t.builtin && t.n) sub.appendChild(data('span', '', ' · v' + t.n));
  if (!t.builtin && t.by) sub.appendChild(data('span', '', ' · ' + t.by));
  w.appendChild(sub);
  h.appendChild(w);
  if (t.used) h.appendChild(el('span', 'tag info', cnt(t.used, 'agent', 'agents')));
  c.appendChild(h);
  if (t.note) c.appendChild(t.builtin ? el('p', 'fl-tpl-note', t.note) : data('p', 'fl-tpl-note', t.note));
  var cmds = V.tplAs === 'commands';
  var shown = cmds ? asCmds(t.lines, t.platform) : arr(t.lines);
  var pre = el('div', 'fl-tpl-lines k-code' + (cmds ? ' cmds' : ''));
  /* every line, coloured as the shell reads it and wrapped under itself between words - nothing
     cut off (1.0.148) */
  var C = window.ACME_POLICY_CORE;
  shown.forEach(function (l) {
    var x = noI18n(el('code', ''));
    if (C && C.paintWords && !/^\s*#/.test(l)) C.paintWords(x, l); else x.textContent = l;
    pre.appendChild(x);
  });
  c.appendChild(pre);
  var a = el('div', 'fl-tpl-a');
  var cp = cmdButton('Copy', 'copy', 'small');
  if (cmds) explain(cp, 'Copies the lines as acme-agent commands, one entry a command.');
  cp.onclick = function () {
    ask('fleet/template?ref=' + encodeURIComponent(t.ref)).then(function (x) {
      var text = String(x.template.text || '');
      copyText(cmds ? asCmds(text.split('\n'), t.platform).join('\n') + '\n' : text, cp, 'on the clipboard');
    }).catch(oops);
  };
  a.appendChild(cp);
  var ob = cmdButton('Open in the builder…', 'shield', 'small');
  ob.onclick = function () { openInBuilder(t); };
  a.appendChild(ob);
  if (FULL && !t.builtin) {
    var eb = cmdButton('Edit…', 'edit', 'small');
    eb.onclick = function () { tplBuild(t); };
    a.appendChild(eb);
  }
  if (FULL && !t.builtin) {
    var del = cmdButton('Delete', 'trash', 'small');
    del.onclick = function () {
      modalSure(tr('Delete the template') + ' ' + t.title + '? ' + tr('The agents and groups that follow it then follow none.'), function () {
        ask('fleet/template_delete', {ref: t.ref}).then(function () { toast(tr('the template is deleted'), 'good'); again(); }).catch(oops);
      }, 'Delete');
    };
    a.appendChild(del);
  }
  c.appendChild(a);
  return c;
}
/** A template of your own made or changed in the policy builder (1.0.148): the builder with no
    agent - its sections, its checks, its output - saved as a fleet template (template_save). */
function tplBuild(t) {
  if (!window.ACME_POLICY_BUILDER) { toast(tr('the policy builder is not on this page'), 'bad'); return; }
  var go = function (T) {
    window.ACME_POLICY_BUILDER.open({id: 0, name: ''}, {template: T, over: false, fleetDone: function () { again(); }});
  };
  if (!t) { go({platform: 'linux'}); return; }
  ask('fleet/template?ref=' + encodeURIComponent(t.ref)).then(function (x) {
    var T = x.template || {};
    go({ref: t.ref, platform: T.platform || t.platform, title: T.title || t.title, note: T.note || '', state: T.state || null, text: T.text || ''});
  }).catch(oops);
}
/** The builder needs an agent of the template's platform (its checks are the agent's own). */
function openInBuilder(t) {
  var ags = arr(V.d && V.d.agents).filter(function (a) { return a.platform === t.platform && a.joined; });
  if (!ags.length) ags = arr(V.d && V.d.agents).filter(function (a) { return a.platform === t.platform; });
  if (!ags.length) { toast(tr('the builder needs an agent of that platform'), 'bad'); return; }
  var go = function (a) {
    ask('fleet/template?ref=' + encodeURIComponent(t.ref)).then(function (x) {
      if (!window.ACME_POLICY_BUILDER) { toast(tr('the policy builder is not on this page'), 'bad'); return; }
      window.ACME_POLICY_BUILDER.open({id: a.id, name: a.name}, {fleetTemplate: x.template, over: false, fleetDone: function () { again(); }});
    }).catch(oops);
  };
  if (ags.length === 1) { go(ags[0]); return; }
  var F = {a: ags[0]};
  modal('Open in the builder', function (body) {
    body.appendChild(el('p', 'small muted', 'The builder checks the policy as the agent of a server checks it: choose the agent it is designed with (its policy is compared, nothing is sent).'));
    var l = el('label', 'fl-field');
    l.appendChild(el('span', 'fl-k', 'Agent'));
    var s = el('select', '');
    noI18n(s);
    ags.forEach(function (a, i) { var o = el('option', '', a.name); o.value = String(i); s.appendChild(o); });
    s.onchange = function () { F.a = ags[Number(s.value)]; };
    l.appendChild(s);
    body.appendChild(l);
  }, [{words: 'Cancel', close: true}, {words: 'Open', cls: 'primary', icon: 'shield', go: function () { closeModal(); go(F.a); }}], true);
}

/* ---- updates: the versions and the rings ------------------------------------------------------ */
function drawUpdates(body, d) {
  var grid = el('div', 'fl-upd');
  var vc = el('div', 'fl-card');
  var vh = el('div', 'fl-card-h');
  vh.appendChild(icon('chart', 16));
  vh.appendChild(el('b', '', 'Versions of the agents'));
  vc.appendChild(vh);
  vc.appendChild(versionChart(d.versions, d.offered, false));
  if (!d.signed) vc.appendChild(el('p', 'fl-note warn', 'This acme has no signed package of the agent (a source tree): agents are updated by hand, or by a release of acme.'));
  grid.appendChild(vc);
  var rc = el('div', 'fl-card');
  var rh = el('div', 'fl-card-h');
  rh.appendChild(icon('up', 16));
  rh.appendChild(el('b', '', 'An update in rings'));
  rc.appendChild(rh);
  if (d.rollout) drawRollout(rc, d.rollout); else drawRolloutForm(rc, d);
  grid.appendChild(rc);
  body.appendChild(grid);
}
function drawRollout(c, r) {
  var steps = [['canary', 'Canary ring'], ['waiting', 'Wait'], ['rest', 'The rest'], ['done', 'Done']];
  var order = {canary: 0, waiting: 1, held: 1, rest: 2, done: 3, stopped: -1};
  var at = order[r.phase] !== undefined ? order[r.phase] : 0;
  var st = el('ol', 'fl-steps');
  steps.forEach(function (s, i) {
    var li = el('li', 'fl-step' + (r.phase === 'stopped' ? '' : i < at || r.phase === 'done' ? ' done' : i === at ? ' now' + (r.phase === 'held' ? ' held' : '') : ''));
    li.appendChild(data('span', 'fl-step-n', i < at || r.phase === 'done' ? '✓' : String(i + 1)));
    li.appendChild(el('span', '', s[1]));
    st.appendChild(li);
  });
  c.appendChild(st);
  var say = el('p', 'fl-note ' + (r.phase === 'held' ? 'warn' : r.phase === 'stopped' ? 'bad' : 'info'));
  var words = {canary: 'The canary ring is being updated.', waiting: 'The canary ring is updated: the rest follows after the wait, when it is healthy.',
    held: 'Held: the canary ring is not healthy.', rest: 'The rest of the agents is being updated.', done: 'The rollout is done.', stopped: 'The rollout was stopped.'}[r.phase] || r.phase;
  say.appendChild(el('span', '', words));
  if (r.phase === 'waiting' && r.next_at) { say.appendChild(noI18n(document.createTextNode(' '))); say.appendChild(el('span', '', tr('The rest at') + ' ' + stamp(r.next_at))); }
  if (r.phase === 'held' && r.held) { say.appendChild(noI18n(document.createTextNode(' '))); say.appendChild(data('span', '', r.held)); }
  c.appendChild(say);
  var meta = el('div', 'fl-ro-meta');
  meta.appendChild(el('span', '', 'Update to'));
  meta.appendChild(data('b', 'mono', ' ' + r.version + ' '));
  meta.appendChild(el('span', 'muted', tr('started') + ' ' + ago(r.at)));
  meta.appendChild(data('span', 'muted', ' · ' + r.by));
  c.appendChild(meta);
  var res = r.results || {};
  [['canary', 'Canary ring'], ['rest', 'The rest']].forEach(function (k) {
    if (!arr(r[k[0]]).length) return;
    c.appendChild(el('h4', 'fl-h4', k[1]));
    var l = el('div', 'fl-ro-list');
    arr(r[k[0]]).forEach(function (x) {
      var o = res[String(x.id)];
      var p = el('span', 'fl-ro-a ' + (o ? (o.ok ? 'ok' : 'bad') : 'wait'));
      p.appendChild(avatar(x.name, 'small'));
      p.appendChild(data('span', '', x.name));
      p.appendChild(data('span', 'fl-ro-mk', o ? (o.ok ? '✓' : '✕') : '…'));
      if (o && o.said) explain(p, o.said);
      l.appendChild(p);
    });
    c.appendChild(l);
  });
  if (arr(r.skipped).length) {
    c.appendChild(el('h4', 'fl-h4', 'Not updated'));
    var sk = el('div', 'fl-ro-skip');
    arr(r.skipped).forEach(function (x) { var p = el('div', ''); p.appendChild(data('b', '', x.name)); p.appendChild(data('span', 'muted small', ' - ' + x.why)); sk.appendChild(p); });
    c.appendChild(sk);
  }
  if (FULL) {
    var a = el('div', 'fl-ro-a-bar');
    if (r.phase === 'waiting' || r.phase === 'held') {
      var go = cmdButton(r.phase === 'held' ? 'Go on anyway' : 'Go on now', 'next', 'small primary');
      go.onclick = function () { roStep('continue', go); };
      a.appendChild(go);
    }
    if (['canary', 'waiting', 'held', 'rest'].indexOf(r.phase) >= 0) {
      var sp = cmdButton('Stop', 'cancel', 'small');
      sp.onclick = function () { modalSure('Stop the rollout? The agents updated stay updated; no other is updated.', function () { roStep('stop', sp); }, 'Stop'); };
      a.appendChild(sp);
    }
    if (r.phase === 'done' || r.phase === 'stopped') {
      var fg = cmdButton('Start another', 'refresh', 'small');
      fg.onclick = function () { roStep('forget', fg); };
      a.appendChild(fg);
    }
    c.appendChild(a);
  }
}
function roStep(what, b) {
  busy(b, true);
  ask('fleet/rollout_step', {'do': what}).then(function () { again(); }).catch(oops).then(function () { busy(b, false); });
}
function drawRolloutForm(c, d) {
  c.appendChild(el('p', 'small muted', 'The canary ring is updated first; the rest follows after the wait - and only when every canary agent answers with the new version. Only agents whose policy says allow self-update are updated, each checking the signature itself.'));
  var F = V.roForm = V.roForm || {canary: (arr(d.groups).filter(function (g) { return g.canary; })[0] || {}).id || '', wait: 60, healthy: true};
  var f = el('div', 'fl-form');
  var l1 = el('label', 'fl-field');
  l1.appendChild(el('span', 'fl-k', 'Canary ring'));
  var s = el('select', '');
  var o0 = el('option', '', '5 % of the agents (at least one)');
  o0.value = '';
  s.appendChild(o0);
  arr(d.groups).forEach(function (g) { var o = data('option', '', g.name + (g.canary ? ' ★' : '')); o.value = g.id; if (g.id === F.canary) o.selected = true; s.appendChild(o); });
  s.onchange = function () { F.canary = s.value; plan(); };
  l1.appendChild(s);
  f.appendChild(l1);
  var l2 = el('label', 'fl-field');
  l2.appendChild(el('span', 'fl-k', 'Then wait (minutes)'));
  var wi = el('input', '');
  wi.type = 'number';
  wi.min = '0';
  wi.max = '10080';
  wi.value = String(F.wait);
  wi.oninput = function () { F.wait = Number(wi.value || 0); };
  l2.appendChild(wi);
  f.appendChild(l2);
  var hc = el('label', 'fl-check');
  var hi = el('input', '');
  hi.type = 'checkbox';
  hi.checked = F.healthy;
  hi.onchange = function () { F.healthy = hi.checked; };
  hc.appendChild(hi);
  hc.appendChild(el('span', '', 'Go on only when the canary ring is healthy'));
  f.appendChild(hc);
  c.appendChild(f);
  var pv = el('div', 'fl-plan');
  c.appendChild(pv);
  var plan = function () {
    clear(pv);
    pv.appendChild(el('span', 'muted small', 'Asking who would be updated…'));
    ask('fleet/rollout_plan?canary=' + encodeURIComponent(F.canary || '')).then(function (p) {
      V.plan = p;
      clear(pv);
      [['canary', 'Canary ring', 'violet'], ['rest', 'Then the rest', 'info']].forEach(function (k) {
        var row = el('div', 'fl-plan-r');
        row.appendChild(el('span', 'tag ' + k[2], k[1]));
        if (!arr(p[k[0]]).length) row.appendChild(el('span', 'muted small', 'nobody'));
        arr(p[k[0]]).slice(0, 12).forEach(function (x) { row.appendChild(data('span', 'fl-chip', x.name)); });
        if (arr(p[k[0]]).length > 12) row.appendChild(data('span', 'fl-chip', '+' + (p[k[0]].length - 12)));
        pv.appendChild(row);
      });
      if (arr(p.skipped).length) {
        var sk = el('details', 'fl-plan-skip');
        var su = el('summary', '');
        su.appendChild(el('span', '', 'Not updated'));
        su.appendChild(data('span', '', ' (' + p.skipped.length + ')'));
        sk.appendChild(su);
        arr(p.skipped).forEach(function (x) { var r = el('div', 'small'); r.appendChild(data('b', '', x.name)); r.appendChild(data('span', 'muted', ' - ' + x.why)); sk.appendChild(r); });
        pv.appendChild(sk);
      }
    }).catch(function (e) { clear(pv); pv.appendChild(el('p', 'ct-bad small', String((e && e.message) || e))); });
  };
  plan();
  if (FULL) {
    var a = el('div', 'fl-ro-a-bar');
    var go = cmdButton('Start the rollout', 'up', 'primary small');
    go.onclick = function () {
      var p = V.plan || {};
      if (!arr(p.canary).length && !arr(p.rest).length) { toast(tr('no agent can be updated now'), 'bad'); return; }
      modalSure('Start the rollout? ' + arr(p.canary).length + ' now, ' + arr(p.rest).length + ' after the wait.', function () {
        busy(go, true);
        ask('fleet/rollout', {canary: F.canary, wait: F.wait, healthy: F.healthy}, 60).then(function () {
          toast(tr('the rollout is started'), 'good');
          again();
        }).catch(oops).then(function () { busy(go, false); });
      }, 'Start');
    };
    a.appendChild(go);
    c.appendChild(a);
  } else c.appendChild(el('p', 'muted small', 'A full administrator starts a rollout.'));
}

/* ---- not managed: what discovery found, by risk, and its take-over -------------------------- */
function loadUnmanaged() {
  V.um = 'asking';
  ask('fleet/unmanaged').then(function (x) {
    V.um = arr(x && x.rows);
    if (V.tab === 'unmanaged' && $('fl-root')) { liveFill($('fl-root'), draw, false); explainWhatWasDrawn($('fl-root')); }
  }).catch(function (e) { V.um = {error: String((e && e.message) || e)}; if ($('fl-root')) liveFill($('fl-root'), draw, false); });
}
function drawUnmanaged(body) {
  var top = el('div', 'fl-bar');
  top.appendChild(el('span', 'muted small', 'What the last discovery on each server found that acme does not manage, the most urgent first. Take over makes the certificate in acme with the same names and a deployment to the same place through the agent - with a preview first.'));
  top.appendChild(el('span', 'spacer'));
  var rb = cmdButton('Again', 'refresh', 'small');
  rb.onclick = function () { V.um = null; loadUnmanaged(); };
  top.appendChild(rb);
  body.appendChild(top);
  if (V.um === null || V.um === 'asking') { body.appendChild(el('div', 'fl-asking', 'Asking…')); return; }
  if (V.um && V.um.error) { body.appendChild(el('p', 'ct-bad', V.um.error)); return; }
  if (!V.um.length) {
    var e = el('div', 'fl-empty');
    e.appendChild(icon('check', 30));
    e.appendChild(el('b', '', 'Nothing found that acme does not manage'));
    e.appendChild(el('p', 'muted', 'Discovery runs on a server whose policy says allow discover - from the agent’s card, Found on this server.'));
    body.appendChild(e);
    return;
  }
  var counts = {};
  V.um.forEach(function (r) { counts[r.risk] = (counts[r.risk] || 0) + 1; });
  var sum = el('div', 'fl-risks');
  ['expired', 'critical', 'high', 'medium', 'self-signed', 'low', 'unknown'].forEach(function (k) {
    if (!counts[k]) return;
    var p = el('span', 'fl-risk ' + riskTone(k));
    p.appendChild(data('b', '', String(counts[k])));
    p.appendChild(el('span', '', riskWords(k)));
    sum.appendChild(p);
  });
  body.appendChild(sum);
  var list = el('div', 'fl-um');
  V.um.forEach(function (r) { list.appendChild(umRow(r)); });
  body.appendChild(list);
}
function umRow(r) {
  var c = el('div', 'fl-um-r ' + riskTone(r.risk));
  var rk = el('div', 'fl-um-risk');
  rk.appendChild(el('span', 'tag ' + riskTone(r.risk), riskWords(r.risk)));
  rk.appendChild(el('span', 'fl-um-days', r.days === null || r.days === undefined ? '–' : (r.days < 0 ? cnt(-r.days, 'day ago', 'days ago') : cnt(r.days, 'day left', 'days left'))));
  c.appendChild(rk);
  var w = el('div', 'fl-um-w');
  var n = el('div', 'fl-um-n');
  n.appendChild(data('b', '', r.names[0] || r.cn || r.subject || r.thumbprint));
  if (r.names.length > 1) n.appendChild(data('span', 'fl-chip', '+' + (r.names.length - 1)));
  w.appendChild(n);
  var where = el('div', 'fl-um-where');
  where.appendChild(icon('terminal', 12));
  where.appendChild(data('span', '', r.target));
  if (r.kind_title) { where.appendChild(noI18n(document.createTextNode(' · '))); where.appendChild(data('span', '', r.kind_title)); }
  if (r.where) { where.appendChild(noI18n(document.createTextNode(' · '))); where.appendChild(data('span', 'mono', r.where)); }
  w.appendChild(where);
  if (r.issuer) w.appendChild(data('div', 'fl-um-iss muted small', r.issuer));
  c.appendChild(w);
  var a = el('div', 'fl-um-a');
  if (r.can_take && MANAGE) {
    var tb = cmdButton('Take over…', 'import', 'small primary');
    tb.onclick = function () { takeover(r); };
    a.appendChild(tb);
  } else if (r.taken) {
    /* taken over and not deployed yet (hunt w9): Take over… again made a second certificate,
       deployed to the same files */
    var tk = el('span', 'small fl-um-taken');
    tk.appendChild(el('span', '', 'taken over'));
    tk.appendChild(noI18n(document.createTextNode(' ')));
    tk.appendChild(data('b', '', r.taken));
    explain(tk, 'acme manages it now: the certificate is deployed to the same files there at its next deployment - then it is no longer listed here.');
    a.appendChild(tk);
  } else if (!r.can_take) {
    var why = el('span', 'muted small', r.service ? 'make its deployment by hand' : 'a file of no service');
    explain(why, 'acme takes over a certificate a service found uses: it knows where to put the new one. This one is not one it can place by itself - Import… or a deployment by hand, from the agent’s card.');
    a.appendChild(why);
  }
  var h = window.ACME_AGENTS && window.ACME_AGENTS.hands && window.ACME_AGENTS.hands();
  if (r.watch && h && h.newTest && MANAGE) {
    var wb = cmdButton('Watch it', 'eye', 'small');
    wb.onclick = function () {
      h.newTest(r.watch.kind, {config: {host: r.watch.host, port: r.watch.port, sni: r.watch.sni}, name: (r.watch.sni || r.target) + ' ' + r.watch.port}, function () { });
    };
    a.appendChild(wb);
  }
  c.appendChild(a);
  return c;
}
function takeover(r) {
  var F = {target: r.target_id, service: r.service, name: '', issuer: '', names: r.names.slice(), auto_renew: true, issue_now: false};
  var P = {p: null};
  modal('Take over ' + (r.names[0] || r.cn), function (body) {
    var w = el('div', 'fl-to');
    body.appendChild(w);
    var paint = function () {
      clear(w);
      var p = P.p;
      if (!p) { w.appendChild(el('div', 'fl-asking', 'Working out what happens…')); return; }
      if (p.error) { w.appendChild(el('p', 'ct-bad', p.error)); return; }
      var grid = el('div', 'fl-to-g');
      /* left: what is made */
      var L = el('div', 'fl-to-l');
      var found = el('div', 'fl-to-found ' + riskTone(p.found.risk));
      found.appendChild(el('span', 'tag ' + riskTone(p.found.risk), riskWords(p.found.risk)));
      var fw = el('div', '');
      fw.appendChild(el('span', 'fl-k', 'Found on the server'));
      var fl = el('div', 'small');
      fl.appendChild(data('b', '', p.target));
      fl.appendChild(data('span', 'muted', ' · ' + p.where));
      fw.appendChild(fl);
      if (p.found.issuer) fw.appendChild(data('div', 'muted small', p.found.issuer));
      found.appendChild(fw);
      L.appendChild(found);
      var f = el('div', 'fl-form');
      var nl = el('label', 'fl-field');
      nl.appendChild(el('span', 'fl-k', 'The certificate in acme'));
      var ni = el('input', '');
      ni.type = 'text';
      ni.value = F.name || p.cert.name;
      ni.oninput = function () { F.name = ni.value; };
      nl.appendChild(ni);
      f.appendChild(nl);
      var nml = el('label', 'fl-field');
      nml.appendChild(el('span', 'fl-k', 'Its names (one a line)'));
      var nt = el('textarea', 'mono');
      nt.rows = Math.min(6, Math.max(2, p.cert.names.length));
      nt.value = p.cert.names.join('\n');
      nt.onchange = function () { F.names = nt.value.split(/\s+/).filter(Boolean); refreshPreview(); };
      nml.appendChild(nt);
      f.appendChild(nml);
      var sl = el('label', 'fl-field');
      sl.appendChild(el('span', 'fl-k', 'Issued from'));
      var ss = el('select', '');
      noI18n(ss);
      if (!arr(p.sources).length) { var oo = el('option', '', '-'); oo.value = ''; ss.appendChild(oo); }
      arr(p.sources).forEach(function (s) { var o = el('option', '', s); o.value = s; if (s === (F.issuer || p.cert.issuer)) o.selected = true; ss.appendChild(o); });
      /* hunt w9: the preview asked again - "What happens" said the source chosen first, and
         whether the source issues for these names */
      ss.onchange = function () { F.issuer = ss.value; refreshPreview(); };
      sl.appendChild(ss);
      f.appendChild(sl);
      var ar = el('label', 'fl-check');
      var ari = el('input', '');
      ari.type = 'checkbox';
      ari.checked = F.auto_renew;
      ari.onchange = function () { F.auto_renew = ari.checked; };
      ar.appendChild(ari);
      ar.appendChild(el('span', '', 'Renewed by itself'));
      f.appendChild(ar);
      var nw = el('label', 'fl-check' + (p.allowed ? '' : ' off'));
      var nwi = el('input', '');
      nwi.type = 'checkbox';
      nwi.disabled = !p.allowed;
      nwi.checked = p.allowed && F.issue_now;
      nwi.onchange = function () { F.issue_now = nwi.checked; };
      nw.appendChild(nwi);
      nw.appendChild(el('span', '', p.allowed ? 'Issue and deploy it now' : 'Issue and deploy it now - once the policy allows it'));
      f.appendChild(nw);
      L.appendChild(f);
      grid.appendChild(L);
      /* right: what happens, and the lines of the policy */
      var Rr = el('div', 'fl-to-r');
      Rr.appendChild(el('span', 'fl-k', 'What happens'));
      var ol = el('ol', 'fl-to-steps');
      arr(p.steps).forEach(function (s) {
        var li = el('li', 'fl-to-s ' + s[0]);
        li.appendChild(icon({cert: 'lock', deploy: 'out', file: 'save', cmd: 'terminal', ok: 'check', wait: 'flag', bad: 'ban'}[s[0]] || 'info', 13));
        li.appendChild(s[0] === 'file' || s[0] === 'cmd' ? data('code', '', s[1]) : el('span', '', s[1]));
        ol.appendChild(li);
      });
      Rr.appendChild(ol);
      /* the source does not issue for these names: said, and Take over not offered (it was,
         and the daemon refused it) */
      if (p.refused) Rr.appendChild(data('p', 'fl-note bad fl-to-refused', p.refused));
      var tb = $('modal-foot') && $('modal-foot').querySelector('.btn.primary');
      if (tb) tb.disabled = !!p.refused;
      Rr.appendChild(el('span', 'fl-k', 'What the agent’s policy needs'));
      var its = el('div', 'fl-to-items');
      if (!p.policy_known) its.appendChild(el('p', 'muted small', 'The agent has not said its policy yet - Ask now on its card.'));
      arr(p.items).forEach(function (it) {
        var row = el('div', 'fl-to-it ' + (it.ok ? 'ok' : it.ok === false ? 'bad' : 'dim'));
        row.appendChild(data('span', 'fl-to-mk', it.ok ? '✓' : it.ok === false ? '✕' : '?'));
        row.appendChild(data('code', '', it.allow));
        its.appendChild(row);
      });
      Rr.appendChild(its);
      if (p.block) {
        var cb = el('div', 'fl-cmd');
        cb.appendChild(data('pre', 'mono', p.block));
        var cp = cmdButton('Copy', 'copy', 'small');
        cp.onclick = function () { copyText(p.block, cp, 'on the clipboard'); };
        cb.appendChild(cp);
        Rr.appendChild(cb);
        Rr.appendChild(el('p', 'small muted', 'Run these on the server (as root), then Ask now on the agent’s card: the take-over can issue at once.'));
      } else if (p.allowed) Rr.appendChild(el('p', 'fl-note ok', 'The agent’s policy allows all of it.'));
      grid.appendChild(Rr);
      w.appendChild(grid);
    };
    var refreshPreview = function () {
      ask('fleet/takeover_preview', {target: F.target, service: F.service, names: F.names, issuer: F.issuer || undefined}).then(function (x) {
        P.p = x.preview;
        if (!F.issuer) F.issuer = P.p.cert.issuer;
        paint();
        explainWhatWasDrawn(w);
      }).catch(function (e) { P.p = {error: String((e && e.message) || e)}; paint(); });
    };
    paint();
    refreshPreview();
  }, [{words: 'Cancel', close: true}, {words: 'Take over', cls: 'primary', icon: 'import', noConfirm: true, go: function (b) {
    if (!P.p || P.p.error || P.p.refused) return;
    busy(b, true);
    ask('fleet/takeover', {target: F.target, service: F.service, names: F.names, name: F.name || P.p.cert.name, issuer: F.issuer || P.p.cert.issuer,
      auto_renew: F.auto_renew, issue_now: !!(F.issue_now && P.p.allowed), confirm: true}, 90).then(function (x) {
      toast(tr('taken over') + ': ' + x.name, 'good');
      closeModal();
      V.um = null;
      loadUnmanaged();
      again();
      if (x.job_id) follow(x.job_id);
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'fl-box wide');
}

window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
window.ACME_EXTRA_PANES.fleet = function () { pane(false); };
window.ACME_FLEET = {pane: pane, ring: ring, versionChart: versionChart};
}());
