/* portal-teams.js - the team workspace of the certificate portal (1.0.125, docs/teams.md,
   docs/certificate-portal.md "Teams"): somebody who is a member of a team (or of a team above
   it) works there on the portal - the certificates of their teams, the requests waiting for
   them, the team's devices and agents, deployments, members, the teams below and their limits,
   what happened.

   certs-portal.js asks GET teams first: in a team, it hands the page over here
   (ACME_PORTAL_WS.start); in none, "Your certificates" stays as it always was. The list of
   certificates, their dialog, the download and asking for one are certs-portal.js's own
   (ACME_PORTAL_CERTS), here only told which team. The module forms of devices and deployments
   are certs.js's fieldForm, the agent's server panel and policy builder agents.js's and
   policybuilder.js's, "What happens" runplan.js's - loaded when first needed.

   Every button is drawn only where the person's capabilities on that team (GET teams `caps`)
   allow it; the daemon checks every route again. Drawn with core.js's pieces; what is its own
   is in portal-teams.css (pw-*). */
(function () {
'use strict';

var WS = {d: null, me: null, team: '*', view: 'home', below: true, host: null, main: null,
          nav: null, inbox: null, timer: null, seq: 0, devQ: '', certQ: {q: '', state: ''}};

/* ---- icons of its own --------------------------------------------------------------------- */
var OWN_ICONS = {
  cert: '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M7.5 8h9M7.5 11h5"/>'
    + '<circle cx="16" cy="16.5" r="2.6"/><path d="M14.4 18.6l-.9 3 2.5-1.1 2.5 1.1-.9-3"/>',
  home: '<path d="M4 11l8-6.5 8 6.5"/><path d="M6 9.5V19a1 1 0 0 0 1 1h3.5v-5.5h3V20H17a1 1 0 0 0 1-1V9.5"/>',
  inbox: '<path d="M4 13.5l2.4-7.2A1.5 1.5 0 0 1 7.8 5.3h8.4a1.5 1.5 0 0 1 1.4 1l2.4 7.2"/><path d="M4 13.5V18a1.5 1.5 0 0 0 1.5 1.5h13A1.5 1.5 0 0 0 20 18v-4.5h-4.5l-1.2 2h-4.6l-1.2-2z"/>',
  server: '<rect x="4" y="4" width="16" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="16" height="6.5" rx="1.5"/><path d="M7.5 7.25h.01M7.5 16.75h.01M11 7.25h5M11 16.75h5"/>',
  agent: '<rect x="4" y="4" width="16" height="6.5" rx="1.5"/><path d="M7.5 7.25h.01M11 7.25h5"/><path d="M12 13.5l5 1.8v2.4c0 1.8-2.1 3.1-5 3.8-2.9-.7-5-2-5-3.8v-2.4z"/>',
  deploy: '<path d="M12 3.5l7.5 4.2v8.6L12 20.5l-7.5-4.2V7.7z"/><path d="M12 12l7.5-4.3M12 12L4.5 7.7M12 12v8.5"/>',
  tree: '<rect x="9" y="3.5" width="6" height="4.5" rx="1"/><rect x="3" y="16" width="6" height="4.5" rx="1"/><rect x="15" y="16" width="6" height="4.5" rx="1"/><path d="M12 8v4M6 16v-2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2"/>',
  unit: '<path d="M4 20.5V6.5l7-3v17"/><path d="M11 9.5h7a2 2 0 0 1 2 2v9"/><path d="M3 20.5h18M7 9h1M7 12.5h1M7 16h1M14.5 13h2M14.5 16.5h2"/>',
  chev: '<path d="M7 9.5l5 5 5-5"/>',
  sliders: '<path d="M4 7h10M18 7h2M4 17h4M12 17h8"/><circle cx="16" cy="7" r="2"/><circle cx="10" cy="17" r="2"/>',
  sparkle: '<path d="M12 3.5l1.7 4.6 4.8 1.9-4.8 1.9L12 16.5l-1.7-4.6L5.5 10l4.8-1.9z"/><path d="M18.5 15.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1.2 1.2"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1.2-1.2"/>',
  calendar: '<rect x="3.5" y="5" width="17" height="15" rx="2"/><path d="M3.5 9.5h17M8 3v4M16 3v4"/>'
};
Object.keys(OWN_ICONS).forEach(function (k) { if (typeof ICONS === 'object' && !ICONS[k]) ICONS[k] = OWN_ICONS[k]; });

/* ---- small things ------------------------------------------------------------------------- */
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function arr(v) { return Array.isArray(v) ? v : []; }
function tr(w) { try { return (typeof i18nText === 'function' && i18nText(w)) || w; } catch (e) { return w; } }
function low(s) { return String(s || '').toLowerCase(); }
function ic(key, size, cls) {
  var s = noI18n(el('span', 'pw-ic' + (cls ? ' ' + cls : '')));
  s.innerHTML = iconMarkup(key, size || 18);
  return s;
}
function when(ts) { return ts ? stamp(ts) : '–'; }
function agoW(ts) { try { return ago(ts); } catch (e) { return when(ts); } }
function chip(words, tone, iconKey, isData) {
  var c = el('span', 'pw-chip' + (tone ? ' ' + tone : ''));
  if (iconKey) c.appendChild(ic(iconKey, 13));
  c.appendChild((isData ? data : el)('span', '', words));
  return c;
}
function dot(tone) { return el('span', 'pw-dot ' + (tone || 'dim')); }
function initials(who) {
  var w = String(who || '?').replace(/^(local|group|portal):/i, '').replace(/@.*$/, '').replace(/^CN=([^,]*).*$/i, '$1');
  var parts = w.split(/[\s._-]+/).filter(Boolean);
  return ((parts[0] || '?').charAt(0) + (parts[1] ? parts[1].charAt(0) : (parts[0] || '').charAt(1) || '')).toUpperCase();
}
function hue(s) {
  var h = 0;
  String(s || '').split('').forEach(function (c) { h = (h * 31 + c.charCodeAt(0)) % 360; });
  return h;
}
function avatar(who, group) {
  var a = noI18n(el('span', 'pw-av' + (group ? ' group' : '')));
  if (group) a.innerHTML = iconMarkup('people', 16);
  else a.textContent = initials(who);
  a.style.setProperty('--h', hue(who));
  a.setAttribute('aria-hidden', 'true');
  return a;
}
/** "3 certificates" - the number and its word, agreeing in the page's language. */
var SINGULAR = {certificates: 'certificate', members: 'member', teams: 'team', days: 'day', 'days left': 'day left',
  'limits of its own': 'limit of its own', 'requests wait for you': 'request waits for you',
  'agents wait to be confirmed': 'agent waits to be confirmed', 'certificates deployed': 'certificate deployed'};
function nW(n, words) {
  /* English says one in the singular; a translation's pattern ("{0} certificates") says it its own way */
  var on = typeof I18N === 'object' && I18N && I18N.on;
  if (!on && Number(n) === 1 && SINGULAR[words]) return '1 ' + SINGULAR[words];
  /* the whole of it, as the language's pattern ("{0} certificates") says it, number and all */
  return n + ' ' + words;
}
function whoWords(who) { return String(who || '').replace(/^(local|portal):/i, ''); }
function emptyState(iconKey, title, words, action) {
  var b = el('div', 'pw-empty');
  b.appendChild(ic(iconKey, 28, 'pw-empty-ic'));
  b.appendChild(el('h3', '', title));
  if (words) b.appendChild(el('p', '', words));
  if (action) b.appendChild(action);
  return b;
}
function skeleton(n, cls) {
  var w = el('div', 'pw-skels ' + (cls || ''));
  w.setAttribute('aria-busy', 'true');
  for (var i = 0; i < (n || 3); i++) {
    var r = el('div', 'pw-skel-row');
    r.appendChild(el('div', 'pw-skel pw-skel-c'));
    var t = el('div', 'pw-skel-t');
    t.appendChild(el('div', 'pw-skel pw-skel-l'));
    t.appendChild(el('div', 'pw-skel pw-skel-s'));
    r.appendChild(t);
    w.appendChild(r);
  }
  return w;
}
function failed(host, e) {
  clear(host);
  host.appendChild(emptyState('info', 'This could not be shown', String((e && e.message) || e)));
}
/** A card with a heading (icon, words) and something on the right. */
function card(title, iconKey, cls) {
  var c = el('section', 'card pw-card' + (cls ? ' ' + cls : ''));
  if (title) {
    var h = el('h2', 'pw-card-h');
    if (iconKey) h.appendChild(ic(iconKey, 17, 'pw-card-ic'));
    h.appendChild(el('span', 'pw-card-t', title));
    c.appendChild(h);
    c._head = h;
  }
  return c;
}
function cardRight(c, node) {
  var r = c._head.querySelector('.pw-card-r');
  if (!r) { r = el('span', 'pw-card-r'); c._head.appendChild(r); }
  r.appendChild(node);
  return node;
}
/** The heading of a page of the workspace: its icon, title, a sentence, its buttons. */
function pageHead(iconKey, title, words, buttons) {
  var h = el('div', 'pw-ph');
  h.appendChild(ic(iconKey, 22, 'pw-ph-ic'));
  var w = el('div', 'pw-ph-w');
  var t = el('h2', 'pw-ph-t', title);
  w.appendChild(t);
  if (words) w.appendChild(el('p', 'pw-ph-s', words));
  h.appendChild(w);
  if (buttons && buttons.length) {
    var r = el('div', 'pw-ph-b');
    buttons.forEach(function (b) { if (b) r.appendChild(b); });
    h.appendChild(r);
  }
  h._title = t;
  return h;
}
function searchBox(value, placeholder, go) {
  var w = el('label', 'pw-search');
  w.appendChild(ic('search', 16));
  var i = el('input');
  i.type = 'search';
  i.value = value || '';
  i.placeholder = placeholder;
  i.setAttribute('aria-label', placeholder);
  i.autocomplete = 'off';
  i.spellcheck = false;
  var later = debounce(function () { go(i.value.trim()); }, 280);
  i.addEventListener('input', later);
  i.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go(i.value.trim()); } });
  w.appendChild(i);
  w._input = i;
  return w;
}
/** A row of filter pills, one on. */
function pills(list, on, pick) {
  var box = el('div', 'pw-pills');
  box.setAttribute('role', 'tablist');
  list.forEach(function (p) {
    var b = el('button', 'pw-pill' + (p[0] === on ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', p[0] === on ? 'true' : 'false');
    if (p[2]) b.appendChild(dot(p[2]));
    b.appendChild(el('span', '', p[1]));
    b.onclick = function () {
      Array.prototype.forEach.call(box.children, function (x) { x.classList.toggle('on', x === b); x.setAttribute('aria-selected', x === b ? 'true' : 'false'); });
      pick(p[0]);
    };
    box.appendChild(b);
  });
  return box;
}
function switchLine(words, on, change) {
  var w = el('span', 'pw-switch');
  var sw = switchBox(on);
  sw._input.onchange = function () { change(!!sw._get()); };
  sw._input.setAttribute('aria-label', words);
  w.appendChild(sw);
  var t = el('span', '', words);
  t.onclick = function () { sw._input.click(); };
  w.appendChild(t);
  return w;
}
function ok(words) { toast(words, 'good'); }

/* ---- lazy pieces of the administration ------------------------------------------------------ */
var LOADED = {};
function version() {
  var s = document.querySelector('script[src*="portal-teams.js"]');
  var m = s && /\?v=([^&]+)/.exec(s.getAttribute('src'));
  return m ? '?v=' + m[1] : '';
}
function loadOne(f) {
  if (LOADED[f]) return LOADED[f];
  LOADED[f] = new Promise(function (resolve, reject) {
    var css = /\.css$/.test(f);
    var n = document.createElement(css ? 'link' : 'script');
    if (css) { n.rel = 'stylesheet'; n.href = '/assets/' + f + version(); } else { n.src = '/assets/' + f + version(); }
    n.onload = function () { resolve(f); };
    n.onerror = function () { delete LOADED[f]; reject(new Error(tr('a part of the page could not be loaded - try again'))); };
    document.head.appendChild(n);
  });
  return LOADED[f];
}
function need(files) {
  var go = Promise.resolve();
  files.forEach(function (f) { go = go.then(function () { return loadOne(f); }); });
  return go;
}
/* certs.js's forms of the modules (fieldForm) - nothing of the administration drawn */
function needForms() {
  window.ACME_CERTS_EMBED = true;
  return need(['sshkey.css', 'sshkey.js', 'pushslots.js', 'catalog.js', 'certs.js']).then(function () {
    if (!window.ACME_CERTS || !window.ACME_CERTS.fieldForm) throw new Error(tr('a part of the page could not be loaded - try again'));
    return window.ACME_CERTS;
  });
}
/* agents.js and the policy builder, asking the portal's routes instead of the administration's */
function needAgents() {
  return needForms().then(function () {
    return need(['agents.css', 'policybuilder.css', 'agents.js', 'policybuilder.js']);
  }).then(function () {
    if (window.ACME_AGENTS) window.ACME_AGENTS.init({capi: agentAsk, over: function (open, back) {
      if ($('modal') && !$('modal').hidden) modalOver(open, back); else open();
    }, openTarget: null, newCert: null, newTest: null, importCert: null,
    /* "Make a deployment" of a service the discovery found: the portal's own dialog, filled in */
    newDeploy: function (row, o) {
      o = o || {};
      var t = row.owner || (deviceById(row.id) || {}).owner;
      modalOver(function () { deployDialog(null, {team: t, target: row.name, options: o.options || {}, cert_id: o.cert_id || null}); },
                function () { deviceOpen(row); });
    }});
    return window.ACME_AGENTS;
  });
}
/** The administration's agent routes as the portal has them. */
function agentAsk(path, body, wait) {
  var q = '', at = path.indexOf('?');
  if (at >= 0) { q = path.slice(at + 1); path = path.slice(0, at); }
  var id = (/(?:^|&)id=([^&]*)/.exec(q) || [])[1];
  if (path === 'agents/builder') return api('agent-builder&id=' + id, undefined, wait);
  if (path === 'agents/design') return api('agent-design', body, wait);
  if (path === 'agents/update') return api('agent-update', body, wait);
  if (path === 'agents/discover') {
    var tg = (/(?:^|&)target=([^&]*)/.exec(q) || [])[1] || '';
    return api('agent-discover&id=' + tg + (/(?:^|&)cached=1/.test(q) ? '&cached=1' : ''), undefined, wait);
  }
  if (path === 'agents/look' || path === 'agents/one') return api('agent&id=' + encodeURIComponent((body && body.id) || decodeURIComponent(id || '')), undefined, wait);
  return Promise.reject(new Error(tr('not on the portal - an administrator does that')));
}

/* =============================================================================================
   The teams: who holds what where
   ============================================================================================= */
function teams() { return arr(WS.d && WS.d.teams); }
function teamOf(name) {
  var n = low(name);
  return teams().filter(function (t) { return low(t.name) === n; })[0] || null;
}
function capsOf(name) {
  if (name === '*' || !name) {
    var all = {};
    teams().forEach(function (t) { arr(t.caps).forEach(function (c) { all[c] = 1; }); });
    return Object.keys(all);
  }
  var t = teamOf(name);
  return t ? arr(t.caps) : [];
}
function can(cap, name) { return capsOf(name === undefined ? WS.team : name).indexOf(cap) >= 0; }
function canApprove(name) {
  var c = capsOf(name === undefined ? WS.team : name);
  return c.indexOf('cert.approve') >= 0;
}
function below(name) {
  var out = [], n = low(name), on = false, depth = 0;
  teams().forEach(function (t) {
    if (low(t.name) === n) { on = true; depth = t.depth; return; }
    if (on && t.depth > depth) out.push(t);
    else if (on) on = false;
  });
  return out;
}
/** The teams a view covers: the one chosen (and those below it), or every one. */
function scope() {
  if (WS.team === '*') return teams();
  var t = teamOf(WS.team);
  if (!t) return [];
  return [t].concat(WS.below ? below(t.name) : []);
}
/** The top-most of their teams where they hold `cap` - asked with below=1, nothing twice. */
function topsWith(cap) {
  var list = WS.team === '*' ? teams() : [teamOf(WS.team)].filter(Boolean);
  var got = [], inside = {};
  list.forEach(function (t) {
    if (arr(t.caps).indexOf(cap) < 0) return;
    var p = low(t.parent), covered = false;
    while (p) {
      if (inside[p]) { covered = true; break; }
      var pt = teamOf(p);
      p = pt ? low(pt.parent) : '';
    }
    if (!covered) got.push(t);
    inside[low(t.name)] = 1;
  });
  return got;
}
function sum(key) {
  return scope().reduce(function (a, t) { return a + Number((t.counts || {})[key] || 0); }, 0);
}
function kindIcon(t) { return t && t.kind === 'unit' ? 'unit' : 'people'; }
function teamLabel() {
  if (WS.team === '*') return tr('All my teams');
  return WS.team;
}
function teamChip(name, cls) {
  var t = teamOf(name);
  var c = el('span', 'pw-team' + (cls ? ' ' + cls : ''));
  c.appendChild(ic(kindIcon(t), 13));
  c.appendChild(data('span', '', name));
  return c;
}
/** Every team they may do `cap` on, by name (a select's choices). */
function teamsWith(cap) { return teams().filter(function (t) { return arr(t.caps).indexOf(cap) >= 0; }).map(function (t) { return t.name; }); }

/* =============================================================================================
   The shell: the team switcher, the views on the left (on a phone, tabs on top)
   ============================================================================================= */
var VIEWS = [
  {id: 'home', icon: 'home', words: 'Overview', may: function () { return true; }},
  {id: 'certs', icon: 'cert', words: 'Certificates', may: function () { return can('cert.view'); }},
  {id: 'inbox', icon: 'inbox', words: 'Requests', may: function () { return can('cert.view') || can('cert.request') || canApprove(); }},
  {id: 'devices', icon: 'server', words: 'Devices', may: function () { return can('target.view'); }},
  {id: 'deploys', icon: 'deploy', words: 'Deployments', may: function () { return can('deploy.view'); }},
  {id: 'members', icon: 'people', words: 'Members', may: function () { return can('team.members'); }},
  {id: 'teams', icon: 'tree', words: 'Sub-teams & limits', may: function () { return can('team.create') || can('team.policy'); }},
  {id: 'activity', icon: 'pulse', words: 'Activity', may: function () { return can('team.activity'); }}
];

function start(host, me, d) {
  WS.d = d;
  WS.me = me;
  WS.host = host;
  var hello = $('pt-hello');
  if (hello) hello.remove();
  document.body.classList.add('pw-on');
  try {
    var kept = JSON.parse(localStorage.getItem('acme-pw') || '{}');
    if (kept.team && (kept.team === '*' || teamOf(kept.team))) WS.team = kept.team;
    if (kept.below === false) WS.below = false;
  } catch (e) { }
  if (WS.team === '*' && teams().length === 1) WS.team = teams()[0].name;
  readHash();
  var shell = el('div', 'pw');
  shell.id = 'pw';
  var nav = el('nav', 'pw-nav');
  nav.id = 'pw-nav';
  nav.setAttribute('aria-label', tr('The team workspace'));
  var main = el('div', 'pw-main');
  main.id = 'pw-main';
  shell.appendChild(nav);
  shell.appendChild(main);
  host.appendChild(shell);
  WS.nav = nav;
  WS.main = main;
  drawSwitcher();
  go(WS.view, true);
  loadInbox();
  window.addEventListener('hashchange', function () {
    if (WS.writing) return;
    var was = WS.team + '|' + WS.view;
    readHash();
    if (was !== WS.team + '|' + WS.view) { drawSwitcher(); go(WS.view, true); }
  });
  clearInterval(WS.timer);
  WS.timer = setInterval(tick, 60000);
}
/* #view or #view/Team - kept in the address so a reload (or a link) opens the same */
function readHash() {
  var h = decodeURIComponent(String(location.hash || '').replace(/^#/, ''));
  if (!h) return;
  var at = h.indexOf('/'), v = at < 0 ? h : h.slice(0, at), t = at < 0 ? '' : h.slice(at + 1);
  if (VIEWS.some(function (x) { return x.id === v; })) WS.view = v;
  if (t === '*' || (t && teamOf(t))) WS.team = t === '*' ? '*' : teamOf(t).name;
}
function writeHash() {
  WS.writing = true;
  try { history.replaceState(null, '', '#' + WS.view + '/' + encodeURIComponent(WS.team)); } catch (e) { }
  setTimeout(function () { WS.writing = false; }, 0);
  try { localStorage.setItem('acme-pw', JSON.stringify({team: WS.team, below: WS.below})); } catch (e) { }
}
function drawNav() {
  var nav = WS.nav;
  clear(nav);
  VIEWS.forEach(function (v) {
    if (!v.may()) return;
    var b = el('button', 'pw-navi' + (v.id === WS.view ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('data-view', v.id);
    if (v.id === WS.view) b.setAttribute('aria-current', 'page');
    b.appendChild(ic(v.icon, 18));
    b.appendChild(el('span', 'pw-navw', v.words));
    if (v.id === 'inbox' && WS.inbox && WS.inbox.count) {
      var n = noI18n(el('span', 'pw-badge', String(WS.inbox.count)));
      n.title = tr('Waiting for you');
      b.appendChild(n);
    }
    if (v.id === 'devices' && sum('agents_waiting') > 0) b.appendChild(noI18n(el('span', 'pw-badge warn', String(sum('agents_waiting')))));
    b.onclick = function () { go(v.id); };
    nav.appendChild(b);
  });
  nav.onkeydown = function (e) {
    if (['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight'].indexOf(e.key) < 0) return;
    var items = Array.prototype.slice.call(nav.querySelectorAll('.pw-navi'));
    var i = items.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    var n = items[(i + (e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : items.length - 1)) % items.length];
    n.focus();
  };
}
function go(view, first) {
  var v = VIEWS.filter(function (x) { return x.id === view; })[0];
  if (!v || !v.may()) view = 'home';
  WS.view = view;
  WS.seq += 1;
  if (window.ACME_PORTAL_CERTS) window.ACME_PORTAL_CERTS.stop();
  writeHash();
  drawNav();
  var main = WS.main;
  clear(main);
  main.className = 'pw-main pw-v-' + view;
  try {
    ({home: viewHome, certs: viewCerts, inbox: viewInbox, devices: viewDevices, deploys: viewDeploys,
      members: viewMembers, teams: viewTeams, activity: viewActivity})[view](main);
  } catch (e) {
    if (window.console) console.error(e);
    failed(main, e);
  }
  if (!first) {
    var on = WS.nav.querySelector('.pw-navi.on');
    if (on && on.scrollIntoView && window.innerWidth <= 820) { try { on.scrollIntoView({block: 'nearest', inline: 'center'}); } catch (e) { } }
    try { window.scrollTo({top: 0}); } catch (e) { }
  }
  explainWhatWasDrawn(main);
}
function pickTeam(name) {
  WS.team = name;
  drawSwitcher();
  go(WS.view);
}
/** Live: the counts (and what waits for them) again every minute, while nothing is being done. */
function tick() {
  if (document.hidden || ($('modal') && !$('modal').hidden)) return;
  refresh(false);
}
function refresh(redraw) {
  return Promise.all([api('teams'), loadInbox(true)]).then(function (got) {
    if (got[0] && got[0].teams) WS.d = got[0];
    drawNav();
    drawSwitcher();
    if (redraw || WS.view === 'home') go(WS.view, true);
  }).catch(function () { });
}
function loadInbox(quiet) {
  return api('inbox').then(function (d) {
    WS.inbox = d;
    if (!quiet) drawNav();
    return d;
  }).catch(function () { WS.inbox = WS.inbox || {count: 0}; });
}

/* ---- the team switcher in the header ------------------------------------------------------ */
function drawSwitcher() {
  var host = $('pt-switch-host');
  if (!host) return;
  clear(host);
  var many = teams().length > 1;
  var b = el('button', 'pw-switch-b');
  b.type = 'button';
  b.id = 'pw-switch';
  b.setAttribute('aria-haspopup', 'listbox');
  b.setAttribute('aria-expanded', 'false');
  var t = teamOf(WS.team);
  b.appendChild(ic(WS.team === '*' ? 'tree' : kindIcon(t), 16, 'pw-switch-ic'));
  var w = el('span', 'pw-switch-w');
  w.appendChild(el('span', 'pw-switch-k', WS.team === '*' ? 'Your workspace' : (t && t.kind === 'unit' ? 'Unit' : 'Team')));
  w.appendChild((WS.team === '*' ? el : data)('b', 'pw-switch-n', teamLabel()));
  b.appendChild(w);
  if (many) b.appendChild(ic('chev', 15, 'pw-switch-chev'));
  else b.disabled = true;
  host.appendChild(b);
  if (!many) return;
  var panel = null;
  var close = function () {
    if (!panel) return;
    panel.remove();
    panel = null;
    b.setAttribute('aria-expanded', 'false');
    document.removeEventListener('mousedown', outside, true);
  };
  var outside = function (e) { if (panel && !panel.contains(e.target) && !b.contains(e.target)) close(); };
  b.onclick = function () {
    if (panel) { close(); return; }
    panel = el('div', 'pw-switch-p');
    panel.setAttribute('role', 'dialog');
    var s = searchBox('', tr('Find a team'), function () { paint(); });
    panel.appendChild(s);
    var list = el('div', 'pw-switch-l');
    list.setAttribute('role', 'listbox');
    panel.appendChild(list);
    var base = teams().length ? teams()[0].depth : 0;
    var paint = function () {
      clear(list);
      var q = low(s._input.value.trim());
      var items = [{name: '*', label: tr('All my teams'), depth: 0, all: true}].concat(teams().map(function (x) {
        return {name: x.name, label: x.name, depth: Math.max(0, x.depth - base), t: x};
      }));
      items.filter(function (x) { return !q || x.all || low(x.label).indexOf(q) >= 0 || low(x.t && x.t.description).indexOf(q) >= 0; }).forEach(function (x) {
        var o = el('button', 'pw-switch-o' + (x.name === WS.team ? ' on' : '') + (x.all ? ' all' : ''));
        o.type = 'button';
        o.setAttribute('role', 'option');
        o.setAttribute('aria-selected', x.name === WS.team ? 'true' : 'false');
        o.style.setProperty('--d', q ? 0 : x.depth);
        o.appendChild(ic(x.all ? 'tree' : kindIcon(x.t), 15));
        var ow = el('span', 'pw-switch-ow');
        ow.appendChild((x.all ? el : data)('b', '', x.label));
        if (x.t && x.t.description) ow.appendChild(data('span', '', x.t.description));
        o.appendChild(ow);
        var waits = x.all ? (WS.inbox && WS.inbox.count) || 0 : Number(((x.t || {}).counts || {}).waiting_for_me || 0);
        if (waits) o.appendChild(noI18n(el('span', 'pw-badge', String(waits))));
        else if (x.t && x.t.counts && x.t.counts.certs !== undefined) o.appendChild(noI18n(el('span', 'pw-switch-n2', String(x.t.counts.certs))));
        o.onclick = function () { close(); pickTeam(x.name); b.focus(); };
        list.appendChild(o);
      });
      if (!list.children.length) list.appendChild(el('p', 'pw-switch-none', 'No team of yours is called so.'));
    };
    paint();
    panel.onkeydown = function (e) {
      var opts = Array.prototype.slice.call(list.querySelectorAll('.pw-switch-o'));
      var i = opts.indexOf(document.activeElement);
      if (e.key === 'Escape') { e.preventDefault(); close(); b.focus(); return; }
      if (e.key === 'ArrowDown') { e.preventDefault(); (opts[i + 1] || opts[0]).focus(); }
      if (e.key === 'ArrowUp') { e.preventDefault(); (i <= 0 ? s._input : opts[i - 1]).focus(); }
      if (e.key === 'Enter' && document.activeElement === s._input && opts.length) { e.preventDefault(); opts[opts.length > 1 ? 1 : 0].click(); }
    };
    host.appendChild(panel);
    b.setAttribute('aria-expanded', 'true');
    document.addEventListener('mousedown', outside, true);
    setTimeout(function () { s._input.focus(); }, 0);
    explainWhatWasDrawn(panel);
  };
}

/* =============================================================================================
   HOME - the tiles, what needs attention, what to do
   ============================================================================================= */
function greeting() {
  var h = new Date().getHours();
  return h < 5 ? 'Good evening' : (h < 12 ? 'Good morning' : (h < 18 ? 'Good afternoon' : 'Good evening'));
}
var CAP_SHORT = {'cert.request': 'ask for certificates', 'cert.renew': 'renew', 'cert.revoke': 'revoke',
  'cert.delete': 'delete', 'cert.key': 'download keys', 'cert.approve': 'approve requests',
  'deploy.run': 'deploy', 'deploy.manage': 'set up deployments', 'target.manage': 'manage devices',
  'target.test': 'test devices', 'team.members': 'manage members', 'team.policy': 'set limits',
  'team.create': 'create sub-teams', 'team.activity': 'see the activity'};
function viewHome(main) {
  var t = teamOf(WS.team), all = WS.team === '*';
  var hero = el('section', 'pw-hero');
  var hl = el('div', 'pw-hero-l');
  hl.appendChild(ic(all ? 'tree' : kindIcon(t), 30, 'pw-hero-ic'));
  var hw = el('div', 'pw-hero-w');
  var hi = el('div', 'pw-hero-hi');
  hi.appendChild(el('span', '', greeting()));
  hi.appendChild(document.createTextNode(', '));
  hi.appendChild(data('span', '', String((WS.me && (WS.me.display || WS.me.name)) || '').split(/\s+/)[0]));
  hw.appendChild(hi);
  var name = el('h2', 'pw-hero-t');
  name.appendChild((all ? el : data)('span', '', teamLabel()));
  if (t) name.appendChild(chip(t.kind === 'unit' ? 'unit' : 'team', 'info'));
  hw.appendChild(name);
  if (t && t.description) hw.appendChild(data('p', 'pw-hero-d', t.description));
  else if (all) hw.appendChild(el('p', 'pw-hero-d', teams().length === 1 ? 'Your team, in one place.' : teams().length + ' teams in one place - pick one at the top to work in it alone.'));
  if (t) {
    var path = el('div', 'pw-crumbs');
    var chain = [], p = t.parent;
    while (p) { chain.unshift(p); var pt = teamOf(p); p = pt ? pt.parent : null; }
    chain.forEach(function (x) { path.appendChild(data('span', '', x)); path.appendChild(ic('next', 12)); });
    if (chain.length) { path.appendChild(data('b', '', t.name)); hw.appendChild(path); }
  }
  var mine = el('div', 'pw-hero-caps');
  var held = capsOf(WS.team).filter(function (c) { return CAP_SHORT[c]; });
  held.slice(0, held.length > 7 ? 6 : 7).forEach(function (c) { mine.appendChild(chip(CAP_SHORT[c], 'dim', 'check')); });
  if (held.length > 7) {
    var more = chip('+' + (held.length - 6), 'info');
    noI18n(more);
    explain(more, held.slice(6).map(function (c) { return tr(CAP_SHORT[c]); }).join(', '));
    mine.appendChild(more);
  }
  if (!mine.children.length) mine.appendChild(chip('see what is here', 'dim', 'eye'));
  hw.appendChild(mine);
  hl.appendChild(hw);
  hero.appendChild(hl);
  var quick = el('div', 'pw-quick');
  if (can('cert.request')) {
    var ab = cmdButton('Ask for a certificate', 'add', 'primary');
    ab.id = 'pw-ask';
    ab.onclick = askCert;
    quick.appendChild(ab);
  }
  if (can('target.manage')) {
    var db = cmdButton('Add a device', 'server', '');
    db.onclick = function () { deviceDialog(null); };
    quick.appendChild(db);
    if (agentsOk()) {
      var eb = cmdButton('Enrol servers', 'agent', '');
      eb.onclick = function () { enrolDialog(); };
      quick.appendChild(eb);
    }
  }
  if (quick.children.length) hero.appendChild(quick);
  main.appendChild(hero);
  /* the tiles */
  var tiles = el('div', 'pw-tiles');
  var certs = sum('certs'), exp = sum('expiring'), fail = sum('failing');
  var waits = (WS.inbox && WS.inbox.count) || 0;
  if (can('cert.view')) {
    tiles.appendChild(tile('cert', 'info', certs, 'Certificates', all || !WS.below ? 'owned by your teams' : 'with the teams below', function () { WS.certQ = {q: '', state: ''}; go('certs'); }, [certs - exp - fail, exp, fail]));
    tiles.appendChild(tile('clock', exp ? 'warn' : 'ok', exp, 'Expiring soon', 'within 30 days', function () { WS.certQ = {q: '', state: 'expiring'}; go('certs'); }, null, certs ? exp / certs : 0));
    tiles.appendChild(tile('pulse', fail ? 'crit' : 'ok', fail, 'Failing', fail ? 'the last renewal failed' : 'nothing failed', function () { WS.certQ = {q: '', state: 'failing'}; go('certs'); }, null, certs ? fail / certs : 0));
  }
  if (can('target.view')) {
    tiles.appendChild(tile('server', 'violet', sum('devices'), 'Devices', 'servers and appliances', function () { go('devices'); }));
    var aw = sum('agents_waiting');
    tiles.appendChild(tile('agent', aw ? 'warn' : 'dim', aw, 'Agents waiting', aw ? 'to be confirmed' : 'none waits', function () { go('devices'); }));
  }
  tiles.appendChild(tile('inbox', waits ? 'load' : 'dim', waits, 'Waiting for you', waits ? 'to approve or decline' : 'nothing to approve', function () { go('inbox'); }));
  main.appendChild(tiles);
  /* what needs attention, and the team's limits */
  var cols = el('div', 'pw-cols');
  var att = card('Needs attention', 'bell', 'pw-attn');
  var list = el('div', 'pw-attn-l');
  list.appendChild(skeleton(3));
  att.appendChild(list);
  cols.appendChild(att);
  var side = el('div', 'pw-side');
  if (t) side.appendChild(limitsCard(t));
  else side.appendChild(teamsCard());
  cols.appendChild(side);
  main.appendChild(cols);
  attention(list, WS.seq);
}
/** A tile: an icon, a big number, its words - and a thin bar under it (a share, or the
    certificates split into valid / expiring / failing). */
function tile(iconKey, tone, n, words, sub, click, split, share) {
  var b = el('button', 'pw-tile ' + tone);
  b.type = 'button';
  var top = el('div', 'pw-tile-top');
  top.appendChild(ic(iconKey, 18, 'pw-tile-ic'));
  top.appendChild(el('span', 'pw-tile-w', words));
  b.appendChild(top);
  b.appendChild(noI18n(el('div', 'pw-tile-n', num(n))));
  b.appendChild(el('div', 'pw-tile-s', sub));
  var bar = el('div', 'pw-spark');
  if (split) {
    var tot = split.reduce(function (a, x) { return a + Math.max(0, x); }, 0) || 1;
    ['ok', 'warn', 'crit'].forEach(function (c, i) {
      var s = el('span', c);
      s.style.width = (100 * Math.max(0, split[i]) / tot).toFixed(1) + '%';
      bar.appendChild(s);
    });
  } else {
    var s1 = el('span', tone);
    s1.style.width = (share === undefined ? (n ? 100 : 0) : Math.max(n ? 6 : 0, Math.min(100, 100 * share))).toFixed(1) + '%';
    bar.appendChild(s1);
  }
  b.appendChild(bar);
  b.onclick = click;
  return b;
}
function attention(list, seq) {
  var items = [];
  var asks = [];
  var add = function (o) { items.push(o); };
  if (WS.inbox && WS.inbox.count) {
    add({tone: 'load', icon: 'inbox', title: nW(WS.inbox.count, 'requests wait for you'), words: 'Approve or decline them - the people who asked are told.', go: function () { go('inbox'); }, order: 0});
  }
  if (can('cert.view')) {
    var q = WS.team === '*' ? '' : '&team=' + encodeURIComponent(WS.team) + (WS.below ? '&below=1' : '');
    asks.push(api('certs' + q + '&state=failing&per=4').then(function (d) {
      arr(d.rows).forEach(function (c) {
        add({tone: 'crit', icon: 'pulse', title: c.cn || c.name, isData: true, words: c.why || tr('its last renewal failed'), team: c.owner, go: function () { openCert(c); }, order: 1});
      });
    }).catch(function () { }));
    asks.push(api('certs' + q + '&state=expiring&per=4').then(function (d) {
      arr(d.rows).forEach(function (c) {
        var left = c.days_left !== undefined && c.days_left !== null ? c.days_left : null;
        add({tone: 'warn', icon: 'clock', title: c.cn || c.name, isData: true, words: left === null ? tr('runs out soon') : (left <= 0 ? tr('ends today') : nW(left, 'days left')) + (c.auto_renew ? ' · ' + tr('renewed by itself') : ' · ' + tr('not renewed by itself')), team: c.owner, go: function () { openCert(c); }, order: 2});
      });
    }).catch(function () { }));
  }
  if (can('target.view') && sum('agents_waiting')) {
    add({tone: 'warn', icon: 'agent', title: nW(sum('agents_waiting'), 'agents wait to be confirmed'), words: 'Compare each fingerprint with the one its server printed, then confirm it.', go: function () { go('devices'); }, order: 3});
  }
  if (WS.inbox) {
    arr(WS.inbox.asked_actions).filter(function (a) { return a.action === 'key' && a.state === 'approved'; }).forEach(function (a) {
      add({tone: 'ok', icon: 'key', title: a.what, isData: true, words: tr('approved - take the key now'), go: function () { keyAfterApproval(a); }, order: 0});
    });
  }
  Promise.all(asks).then(function () {
    if (seq !== WS.seq || !list.isConnected) return;
    clear(list);
    items.sort(function (a, b) { return a.order - b.order; });
    if (!items.length) {
      list.appendChild(emptyState('check', 'All is well', 'Nothing fails, nothing runs out within 30 days and nothing waits for you.'));
      return;
    }
    items.slice(0, 9).forEach(function (o) {
      var r = el('button', 'pw-attn-i ' + o.tone);
      r.type = 'button';
      r.appendChild(ic(o.icon, 17, 'pw-attn-ic'));
      var w = el('span', 'pw-attn-w');
      w.appendChild((o.isData ? data : el)('b', '', o.title));
      w.appendChild(el('span', '', o.words));
      r.appendChild(w);
      if (o.team) r.appendChild(teamChip(o.team, 'small'));
      r.appendChild(ic('next', 15, 'pw-attn-go'));
      r.onclick = o.go;
      list.appendChild(r);
    });
    explainWhatWasDrawn(list);
  });
}
function openCert(c) {
  if (window.ACME_PORTAL_CERTS) window.ACME_PORTAL_CERTS.openRow(c);
}
function askCert() {
  if (!window.ACME_PORTAL_CERTS) return;
  window.ACME_PORTAL_CERTS.askStart(certCtx(null));
}
/** Every team, as cards (All my teams). */
function teamsCard() {
  var c = card('Your teams', 'tree', 'pw-teamlist');
  var base = teams().length ? teams()[0].depth : 0;
  teams().slice(0, 12).forEach(function (t) {
    var r = el('button', 'pw-tli');
    r.type = 'button';
    r.style.setProperty('--d', Math.max(0, t.depth - base));
    r.appendChild(ic(kindIcon(t), 16));
    var w = el('span', 'pw-tli-w');
    w.appendChild(data('b', '', t.name));
    if (t.description) w.appendChild(data('span', '', t.description));
    r.appendChild(w);
    var n = (t.counts || {});
    if (n.waiting_for_me) r.appendChild(noI18n(el('span', 'pw-badge', String(n.waiting_for_me))));
    if (n.certs !== undefined) r.appendChild(chip(nW(n.certs, 'certificates'), 'dim', 'cert'));
    r.onclick = function () { pickTeam(t.name); };
    c.appendChild(r);
  });
  if (teams().length > 12) c.appendChild(el('p', 'note small', 'More in the switcher at the top.'));
  return c;
}

/* ---- the limits of a team, in words ---------------------------------------------------------- */
var MODE_WORDS = {none: 'nothing waits - the team does it all itself', outside: 'waits only outside the pre-approved envelope',
  profile: 'as each request profile says', always: 'every request waits for an approval'};
var APPROVER_WORDS = {team: 'the team’s lead', parent: 'the team above', team_or_parent: 'the team’s lead or the team above',
  both: 'the team’s lead, then the team above'};
var ACTION_WORDS_P = {revoke: 'revoking', 'delete': 'deleting', key: 'downloading a key', device: 'deleting a device'};
function policyRows(pol) {
  pol = pol || {};
  var rows = [];
  var list = function (v, mono) {
    var w = el('span', 'pw-chips');
    arr(v).forEach(function (x) { w.appendChild(chip(String(x), 'info', null, true)); });
    if (!arr(v).length) w.appendChild(chip('none', 'crit'));
    return w;
  };
  if (pol.profiles) rows.push(['profiles', 'Request profiles', list(pol.profiles)]);
  if (pol.free_form === false) rows.push(['free_form', 'Without a profile', chip('not allowed', 'crit', 'ban')]);
  if (pol.suffixes) rows.push(['suffixes', 'Names under', list(pol.suffixes)]);
  if (pol.max_days) rows.push(['max_days', 'Longest validity', chip(pol.max_days + ' days at most', 'info')]);
  if (pol.max_certs) rows.push(['max_certs', 'Most certificates', chip(String(pol.max_certs), 'info', null, true)]);
  if (pol.issuers) rows.push(['issuers', 'Sources', list(pol.issuers)]);
  if (pol.validations) rows.push(['validations', 'Validation', list(pol.validations)]);
  if (pol.target_kinds) rows.push(['target_kinds', 'Device modules', list(pol.target_kinds)]);
  if (pol.key_download === false) rows.push(['key_download', 'Private keys', chip('never downloaded', 'crit', 'ban')]);
  if (pol.agents === false) rows.push(['agents', 'Agents', chip('not allowed', 'crit', 'ban')]);
  if (pol.approval) {
    var a = typeof pol.approval === 'string' ? {mode: pol.approval} : pol.approval;
    var w = el('span', 'pw-chips');
    w.appendChild(chip(MODE_WORDS[a.mode] || a.mode, a.mode === 'none' ? 'ok' : 'warn'));
    if (a.mode !== 'none' && a.mode !== 'profile' && a.approvers) w.appendChild(chip(APPROVER_WORDS[a.approvers] || a.approvers, 'dim', 'people'));
    if (Number(a.count) > 1) w.appendChild(chip('four eyes - two approvers', 'violet', 'eye'));
    rows.push(['approval', 'Approval', w]);
  }
  if (arr(pol.approve_actions).length) {
    var aw = el('span', 'pw-chips');
    pol.approve_actions.forEach(function (x) { aw.appendChild(chip(ACTION_WORDS_P[x] || x, 'warn')); });
    rows.push(['approve_actions', 'Also approved first', aw]);
  }
  return rows;
}
function limitsCard(t) {
  var c = card('Limits in force', 'shield', 'pw-limits');
  var rows = policyRows(t.policy);
  if (!rows.length) {
    c.appendChild(emptyState('sparkle', 'No limits', 'The team asks for what the request profiles and the portal allow.'));
    return c;
  }
  var from = (t.policy || {}).from || {};
  rows.forEach(function (r) {
    var line = el('div', 'pw-lim');
    line.appendChild(el('span', 'pw-lim-k', r[1]));
    var v = el('div', 'pw-lim-v');
    v.appendChild(r[2]);
    if (from[r[0]] && low(from[r[0]]) !== low(t.name)) {
      var f = el('span', 'pw-from');
      f.appendChild(el('span', '', 'from'));
      f.appendChild(document.createTextNode(' '));
      f.appendChild(data('b', '', from[r[0]]));
      v.appendChild(f);
    }
    line.appendChild(v);
    c.appendChild(line);
  });
  return c;
}
/** "Your team may ask only..." - above the forms that ask for a certificate. */
/** The team a certificate is asked for: the one chosen - or, in All my teams, the first where
    they may ask. */
function askTeam() {
  var mine = teamsWith('cert.request');
  return WS.team !== '*' && mine.indexOf(WS.team) >= 0 ? WS.team : (mine[0] || '');
}
function limitsNote() {
  var t = teamOf(askTeam());
  if (!t) return null;
  var pol = t.policy || {}, parts = [];
  if (pol.profiles) parts.push('only from the profiles ' + arr(pol.profiles).join(', '));
  if (pol.suffixes) parts.push('only names under ' + arr(pol.suffixes).join(', '));
  if (pol.max_days) parts.push('valid ' + pol.max_days + ' days at most');
  if (pol.free_form === false) parts.push('never without a profile');
  var a = pol.approval && (typeof pol.approval === 'string' ? {mode: pol.approval} : pol.approval);
  if (!parts.length && !(a && a.mode)) return null;
  var box = el('div', 'pw-note');
  box.appendChild(ic('shield', 17));
  var w = el('div', '');
  var h = el('b', '');
  h.appendChild(el('span', '', 'The limits of'));
  h.appendChild(document.createTextNode(' '));
  h.appendChild(data('span', '', t.name));
  w.appendChild(h);
  if (parts.length) {
    var pl = el('span', 'pw-note-parts');
    pl.appendChild(el('span', '', 'Your team may ask:'));
    parts.forEach(function (x) { pl.appendChild(el('span', 'pw-note-part', x)); });
    w.appendChild(pl);
  }
  if (a && a.mode) w.appendChild(el('span', 'pw-note-s', MODE_WORDS[a.mode] || ''));
  box.appendChild(w);
  return box;
}

/* =============================================================================================
   CERTIFICATES - certs-portal.js's list, one page at a time, searched on the server
   ============================================================================================= */
function viewCerts(main) {
  var askB = null;
  if (can('cert.request')) {
    askB = cmdButton('Ask for a certificate', 'add', 'primary');
    askB.id = 'pw-ask-c';
    askB.onclick = askCert;
  }
  var head = pageHead('cert', 'Certificates', WS.team === '*' ? 'Every certificate of your teams. Click one for everything about it.'
    : 'The certificates of the team. Each is renewed by itself before it runs out - click one for everything about it.', [askB]);
  main.appendChild(head);
  var bar = el('div', 'pw-bar');
  bar.appendChild(searchBox(WS.certQ.q, tr('Search names, owners, serials'), function (q) {
    WS.certQ.q = q;
    window.ACME_PORTAL_CERTS.ask({q: q, page: 0});
  }));
  bar.appendChild(pills([['', 'All'], ['ok', 'Valid', 'ok'], ['expiring', 'Expiring', 'warn'], ['failing', 'Failing', 'crit'],
                         ['waiting', 'Waiting', 'violet'], ['mine', 'Asked by me', 'info']], WS.certQ.state, function (st) {
    WS.certQ.state = st;
    window.ACME_PORTAL_CERTS.ask({state: st, page: 0});
  }));
  var t = teamOf(WS.team);
  if (t && below(t.name).length) {
    bar.appendChild(switchLine(tr('with the teams below'), WS.below, function (on) {
      WS.below = on;
      writeHash();
      window.ACME_PORTAL_CERTS.ask({below: on ? 1 : '', page: 0});
    }));
  }
  main.appendChild(bar);
  var c = el('div', 'card cp-card pw-certs');
  c.id = 'cp-card';
  var said = el('div', 'cp-said muted small');
  said.id = 'cp-said';
  c.appendChild(said);
  var list = el('div', 'cp-list');
  list.id = 'cp-list';
  list.appendChild(skeleton(6, 'pw-skels-table'));
  c.appendChild(list);
  main.appendChild(c);
  if (!window.ACME_PORTAL_CERTS) return;
  window.ACME_PORTAL_CERTS.mount(list, {team: WS.team === '*' ? '' : WS.team, below: WS.team !== '*' && WS.below ? 1 : '',
                                        q: WS.certQ.q, state: WS.certQ.state, page: 0, per: 50}, certCtx(said)).catch(function () { });
}
function certCtx(said) {
  return {
    team: function () { return askTeam(); },
    policy: function () { var t = teamOf(askTeam()); return t ? t.policy : null; },
    askTeams: function () { return teamsWith('cert.request'); },
    limitsNote: limitsNote,
    mayAsk: can('cert.request'),
    certMore: certMore,
    changed: function () { refresh(false); },
    drawn: function (d) {
      if (!said || !said.isConnected) return;
      clear(said);
      said.appendChild(noI18n(el('b', '', num(d.total || 0))));
      said.appendChild(document.createTextNode(' '));
      said.appendChild(el('span', '', d.total === 1 ? 'certificate' : 'certificates'));
      if (d.q || d.state) { said.appendChild(document.createTextNode(' · ')); said.appendChild(el('span', '', 'filtered')); }
    }
  };
}
/** In a certificate's dialog: where it is deployed, and how its request went. */
function certMore(body, c) {
  var t = c.owner && teamOf(c.owner);
  if (!t) return;
  var box = el('div', 'pw-cm');
  body.appendChild(box);
  if (arr(t.caps).indexOf('deploy.view') >= 0) {
    var dh = el('h4', 'pw-cm-h');
    dh.appendChild(ic('deploy', 15));
    dh.appendChild(el('span', '', 'Deployed to'));
    box.appendChild(dh);
    var dl = el('div', 'pw-cm-deps');
    dl.appendChild(skeleton(1));
    box.appendChild(dl);
    api('deploys&team=' + encodeURIComponent(t.name)).then(function (d) {
      clear(dl);
      var mine = arr(d.rows).filter(function (r) { return r.cert_id === c.id; });
      if (!mine.length) { dl.appendChild(el('p', 'muted small', 'Nowhere yet - the team’s deployments put it on its devices.')); return; }
      mine.forEach(function (r) { dl.appendChild(deployLine(r, false)); });
    }).catch(function () { clear(dl); });
  }
  api('timeline&id=' + c.id).then(function (d) {
    if (!arr(d.timeline).length) return;
    var th = el('h4', 'pw-cm-h');
    th.appendChild(ic('history', 15));
    th.appendChild(el('span', '', 'How it was asked for'));
    box.appendChild(th);
    box.appendChild(timelineBox(d));
    explainWhatWasDrawn(box);
  }).catch(function () { });
}

/* =============================================================================================
   REQUESTS - waiting for you, what you asked, the approval timeline
   ============================================================================================= */
var LEVEL_WORDS = {team: 'the team’s lead', parent: 'the team above', team_or_parent: 'the team’s lead or the team above'};
function viewInbox(main) {
  main.appendChild(pageHead('inbox', 'Requests', 'What waits for your approval, and how the requests you made are going.'));
  var wait = card('Waiting for you', 'bell', 'pw-inbox');
  var wl = el('div', 'pw-reqs');
  wl.appendChild(skeleton(2));
  wait.appendChild(wl);
  main.appendChild(wait);
  var mine = card('Your requests', 'person', 'pw-mine');
  var ml = el('div', 'pw-reqs');
  ml.appendChild(skeleton(2));
  mine.appendChild(ml);
  main.appendChild(mine);
  var seq = WS.seq;
  loadInbox().then(function (d) {
    if (seq !== WS.seq) return;
    d = d || {};
    clear(wl);
    var n = arr(d.requests).length + arr(d.actions).length;
    if (n) cardRight(wait, noI18n(el('span', 'pw-badge big', String(n))));
    if (!n) wl.appendChild(emptyState('check', 'Nothing waits for you', 'When someone of your teams asks for something you approve, it is here - and you are told by mail.'));
    arr(d.requests).forEach(function (r) { wl.appendChild(requestCard(r, true)); });
    arr(d.actions).forEach(function (a) { wl.appendChild(actionCard(a, true)); });
    clear(ml);
    var m = arr(d.asked).length + arr(d.asked_actions).length;
    if (!m) ml.appendChild(emptyState('inbox', 'You have not asked for anything waiting', 'What you ask for that waits for an approval is followed here, step by step.'));
    arr(d.asked).forEach(function (r) { ml.appendChild(requestCard(r, false)); });
    arr(d.asked_actions).forEach(function (a) { ml.appendChild(actionCard(a, false)); });
    explainWhatWasDrawn(main);
  });
}
function levelsChips(needed) {
  var w = el('span', 'pw-chips');
  arr(needed).forEach(function (l) { w.appendChild(chip(LEVEL_WORDS[l] || l, 'warn', 'clock')); });
  return w;
}
function requestCard(r, mayAct) {
  var c = el('article', 'pw-req');
  var top = el('div', 'pw-req-top');
  top.appendChild(ic('cert', 20, 'pw-req-ic'));
  var w = el('div', 'pw-req-w');
  var t = el('div', 'pw-req-t');
  t.appendChild(data('b', '', r.name));
  if (r.owner) t.appendChild(teamChip(r.owner, 'small'));
  if (r.profile) t.appendChild(chip(r.profile, 'dim', null, true));
  w.appendChild(t);
  var meta = el('div', 'pw-req-m');
  if (r.asked_by) {
    meta.appendChild(avatar(r.asked_by));
    meta.appendChild(data('span', '', whoWords(r.asked_by)));
    meta.appendChild(el('span', 'muted', 'asked'));
  }
  if (r.at) meta.appendChild(el('span', 'muted', agoW(r.at)));
  w.appendChild(meta);
  var others = arr(r.names).filter(function (n) { return n !== r.name; });
  if (others.length && window.ACME_PORTAL_CERTS) w.appendChild(window.ACME_PORTAL_CERTS.namesChips(arr(r.names), 4));
  top.appendChild(w);
  c.appendChild(top);
  var foot = el('div', 'pw-req-f');
  if (arr(r.needed).length) {
    var nw = el('span', 'pw-req-need');
    nw.appendChild(el('span', 'muted small', 'waits for'));
    nw.appendChild(levelsChips(r.needed));
    foot.appendChild(nw);
  }
  var btns = el('div', 'pw-req-b');
  var tl = cmdButton('Timeline', 'history', 'small');
  tl.onclick = function () { timelineDialog(r.id, r.name); };
  btns.appendChild(tl);
  if (mayAct) {
    var no = cmdButton('Decline', 'ban', 'small');
    no.onclick = function () { declineReq(r); };
    btns.appendChild(no);
    var yes = cmdButton('Approve', 'check', 'small primary');
    yes.classList.add('pw-approve');
    yes.onclick = function () {
      busy(yes, true);
      api('cert-approve', {id: r.id, ok: 1}).then(function (d) {
        ok(d.message || (d.job_id ? tr('approved - it is being issued') : tr('approved')));
        WS.lastApproval = d;
        refresh(true);
      }).catch(oops).then(function () { busy(yes, false); });
    };
    btns.appendChild(yes);
  }
  foot.appendChild(btns);
  c.appendChild(foot);
  return c;
}
function declineReq(r) {
  var why = null;
  modal(tr('Decline') + ' ' + r.name, function (body) {
    body.appendChild(el('p', 'note', 'The person who asked is told why, by mail.'));
    why = el('textarea');
    why.rows = 3;
    body.appendChild(formField('Why', why, ''));
  }, [{words: 'No, leave it', close: true}, {words: 'Decline it', cls: 'danger', icon: 'ban', once: true, go: function (b) {
    if (!String(why.value || '').trim()) { why.focus(); toast(tr('say why it is declined'), 'bad'); return; }
    busy(b, true);
    api('cert-approve', {id: r.id, ok: 0, why: why.value}).then(function () {
      closeModal();
      ok(tr('declined - the person who asked is told'));
      refresh(true);
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'narrow');
}
function actionCard(a, mayAct) {
  var c = el('article', 'pw-req action');
  var top = el('div', 'pw-req-top');
  top.appendChild(ic(a.action === 'key' ? 'key' : (a.action === 'device' ? 'server' : (a.action === 'revoke' ? 'ban' : 'trash')), 20, 'pw-req-ic'));
  var w = el('div', 'pw-req-w');
  var t = el('div', 'pw-req-t');
  t.appendChild(el('span', 'pw-req-act', ACTION_TITLE[a.action] || a.action));
  t.appendChild(data('b', '', a.what));
  if (a.team) t.appendChild(teamChip(a.team, 'small'));
  w.appendChild(t);
  var meta = el('div', 'pw-req-m');
  if (a.by) { meta.appendChild(avatar(a.by)); meta.appendChild(data('span', '', whoWords(a.by))); }
  if (a.at) meta.appendChild(el('span', 'muted', agoW(a.at)));
  if (a.words) meta.appendChild(data('span', 'muted', a.words));
  w.appendChild(meta);
  top.appendChild(w);
  var st = {waiting: ['waiting', 'warn'], approved: ['approved', 'ok'], declined: ['declined', 'crit'], done: ['done', 'ok']}[a.state] || [a.state, 'dim'];
  top.appendChild(chip(st[0], st[1]));
  c.appendChild(top);
  var foot = el('div', 'pw-req-f');
  var btns = el('div', 'pw-req-b');
  if (mayAct) {
    var no = cmdButton('Decline', 'ban', 'small');
    no.onclick = function () { actionDecide(a, false); };
    btns.appendChild(no);
    var yes = cmdButton('Approve', 'check', 'small primary');
    yes.onclick = function () { actionDecide(a, true, yes); };
    btns.appendChild(yes);
  } else if (a.action === 'key' && a.state === 'approved') {
    var k = cmdButton('Take the key now', 'key', 'small primary');
    k.onclick = function () { keyAfterApproval(a); };
    btns.appendChild(k);
  }
  if (btns.children.length) { foot.appendChild(btns); c.appendChild(foot); }
  return c;
}
var ACTION_TITLE = {revoke: 'Revoke', 'delete': 'Delete', key: 'The key of', device: 'Delete the device'};
function actionDecide(a, yes, b) {
  var send = function (why, btn) {
    busy(btn, true);
    return api('action-approve', {id: a.id, ok: yes ? 1 : 0, why: why || ''}).then(function (d) {
      closeModal();
      ok(d.message || (yes ? tr('approved') : tr('declined')));
      refresh(true);
    }).catch(oops).then(function () { busy(btn, false); });
  };
  if (yes) { send('', b); return; }
  var why = null;
  modal(tr('Decline'), function (body) {
    body.appendChild(el('p', 'note', 'The person who asked is told why, by mail.'));
    why = el('textarea');
    why.rows = 3;
    body.appendChild(formField('Why', why, ''));
  }, [{words: 'No, leave it', close: true}, {words: 'Decline it', cls: 'danger', icon: 'ban', once: true, go: function (btn) {
    if (!String(why.value || '').trim()) { why.focus(); return; }
    send(why.value, btn);
  }}], 'narrow');
}
/** An approved key download: the PFX made now, once, with a password chosen here. */
function keyAfterApproval(a) {
  var pw1 = null, pw2 = null;
  modal(tr('The key of') + ' ' + a.what, function (body) {
    body.appendChild(el('p', 'note', 'Its download was approved. The certificate, its chain and its private key in one PFX file, locked with a password you choose - taken once.'));
    pw1 = el('input'); pw1.type = 'password'; pw1.placeholder = 'a password for the file'; pw1.autocomplete = 'new-password';
    pw2 = el('input'); pw2.type = 'password'; pw2.placeholder = 'the same again'; pw2.autocomplete = 'new-password';
    body.appendChild(formField('Password', pw1, 'At least 8 characters.'));
    body.appendChild(formField('Again', pw2, ''));
  }, [{words: 'Close', close: true}, {words: 'Download', cls: 'primary', icon: 'download', go: function (b) {
    if ((pw1.value || '').length < 8) { toast(tr('the password is at least 8 characters'), 'bad'); return; }
    if (pw1.value !== pw2.value) { toast(tr('the two passwords are not the same'), 'bad'); return; }
    busy(b, true);
    api('cert-download', {id: a.ref, format: 'pfx', password: pw1.value, action: a.id}).then(function (d) {
      if (window.ACME_PORTAL_CERTS) window.ACME_PORTAL_CERTS.saveB64(d);
      closeModal();
      ok(tr('downloaded:') + ' ' + (d.filename || ''));
      loadInbox();
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'narrow');
}
function timelineDialog(id, name) {
  modal(tr('Timeline') + ' · ' + name, function (body) { body.appendChild(skeleton(3)); }, [{words: 'Close', close: true}], 'medium');
  var ticket = modalTicket();
  api('timeline&id=' + id).then(function (d) {
    if (!modalStill(ticket)) return;
    var body = $('modal-body');
    clear(body);
    if (d.rule) body.appendChild(ruleBox(d.rule));
    body.appendChild(timelineBox(d));
    explainWhatWasDrawn(body);
  }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
}
function ruleBox(r) {
  var b = el('div', 'pw-rule');
  b.appendChild(ic('shield', 18, 'pw-rule-ic'));
  var w = el('div', 'pw-rule-w');
  var h = el('b', '');
  h.appendChild(el('span', '', 'The rule of'));
  h.appendChild(document.createTextNode(' '));
  h.appendChild(data('span', '', r.team || ''));
  w.appendChild(h);
  var cs = el('div', 'pw-chips');
  cs.appendChild(chip(MODE_WORDS[r.mode] || r.mode, 'warn'));
  if (r.approvers) cs.appendChild(chip(APPROVER_WORDS[r.approvers] || r.approvers, 'dim', 'people'));
  if (Number(r.count) > 1) cs.appendChild(chip('four eyes - two approvers', 'violet', 'eye'));
  if (!r.self) cs.appendChild(chip('never the one who asked', 'dim', 'ban'));
  w.appendChild(cs);
  b.appendChild(w);
  return b;
}
var TL = {asked: ['add', 'info', 'asked for it'], approved: ['check', 'ok', 'approved'], declined: ['ban', 'crit', 'declined'],
          'let through': ['next', 'ok', 'let it through'], issued: ['cert', 'ok', 'issued']};
/** The vertical timeline: each step a dot on the line - and what still waits, dashed. */
function timelineBox(d) {
  var box = el('ol', 'pw-tl');
  arr(d.timeline).forEach(function (e) {
    var k = TL[e.what] || ['info', 'dim', e.what];
    var li = el('li', 'pw-tl-i ' + k[1]);
    var m = el('span', 'pw-tl-m');
    m.appendChild(ic(k[0], 14));
    li.appendChild(m);
    var w = el('div', 'pw-tl-w');
    var t = el('div', 'pw-tl-t');
    if (e.by) { t.appendChild(avatar(e.by)); t.appendChild(data('b', '', whoWords(e.by))); }
    t.appendChild(el('span', '', k[2]));
    arr(e.levels).forEach(function (l) { t.appendChild(chip(LEVEL_WORDS[l] || l, 'dim')); });
    if (e.profile) t.appendChild(chip(e.profile, 'dim', null, true));
    if (e.version) t.appendChild(chip('version ' + e.version, 'dim'));
    w.appendChild(t);
    w.appendChild(noI18n(el('div', 'pw-tl-when', when(e.at))));
    if (e.why) w.appendChild(data('div', 'pw-tl-why', '“' + e.why + '”'));
    li.appendChild(w);
    box.appendChild(li);
  });
  (d.state && d.state !== 'pending-approval' ? [] : arr(d.needed)).forEach(function (l) {
    var li = el('li', 'pw-tl-i wait');
    var m = el('span', 'pw-tl-m');
    m.appendChild(ic('clock', 14));
    li.appendChild(m);
    var w = el('div', 'pw-tl-w');
    var t = el('div', 'pw-tl-t');
    t.appendChild(el('span', '', 'waits for'));
    t.appendChild(el('b', '', LEVEL_WORDS[l] || l));
    w.appendChild(t);
    li.appendChild(w);
    box.appendChild(li);
  });
  if (!box.children.length) box.appendChild(el('li', 'muted', 'Nothing recorded yet.'));
  return box;
}

/* =============================================================================================
   DEVICES (and their agents)
   ============================================================================================= */
var KIND_ICON = {ssh: 'terminal', local: 'terminal', windows_ssh: 'windows', winrm: 'windows', iis: 'windows',
  agent: 'agent', agent_windows: 'agent', webhook: 'plug', fake: 'server'};
function kindIconOf(kind) {
  if (KIND_ICON[kind]) return KIND_ICON[kind];
  if (/win/.test(kind)) return 'windows';
  if (/f5|citrix|netscaler|forti|palo|cisco|juniper|checkpoint|mikrotik|ubiquiti|sophos|kemp|haproxy|nginx/.test(kind)) return 'net';
  if (/k8s|kube|vault|azure|aws|gcp|cloud/.test(kind)) return 'db';
  return 'router';
}
function isAgent(r) { return r.kind === 'agent' || r.kind === 'agent_windows'; }
function agentsOk() {
  var t = teamOf(WS.team);
  var list = t ? [t] : teams();
  return list.some(function (x) {
    if (arr(x.caps).indexOf('target.manage') < 0) return false;
    var p = x.policy || {};
    if (p.agents === false) return false;
    return !p.target_kinds || arr(p.target_kinds).some(function (k) { return k === 'agent' || k === 'agent_windows'; });
  });
}
/** Rows of several teams asked at once (each with below=1), nothing twice. */
function askTops(cap, route, extra) {
  var tops = topsWith(cap);
  return Promise.all(tops.map(function (t) {
    return api(route + '&team=' + encodeURIComponent(t.name) + (WS.team === '*' || WS.below ? '&below=1' : '') + (extra || ''));
  })).then(function (all) {
    var seen = {}, rows = [], more = {};
    all.forEach(function (d) {
      Object.keys(d || {}).forEach(function (k) { if (k !== 'rows') more[k] = more[k] || d[k]; });
      arr(d.rows).forEach(function (r) { var k = r.id; if (!seen[k]) { seen[k] = 1; rows.push(r); } });
      arr(d.codes).forEach(function (c) { more.allCodes = (more.allCodes || []).concat([c]); });
    });
    more.rows = rows;
    return more;
  });
}
function viewDevices(main) {
  var bs = [];
  if (can('target.manage')) {
    var add = cmdButton('Add a device', 'add', 'primary');
    add.id = 'pw-add-device';
    add.onclick = function () { deviceDialog(null); };
    bs.push(add);
    if (agentsOk()) {
      var en = cmdButton('Enrol servers', 'agent', '');
      en.id = 'pw-enrol';
      en.onclick = function () { enrolDialog(); };
      bs.push(en);
    }
  }
  main.appendChild(pageHead('server', 'Devices', 'The servers and appliances the team’s certificates are deployed to - with their own settings, tested from here.', bs));
  var bar = el('div', 'pw-bar');
  bar.appendChild(searchBox(WS.devQ, tr('Search devices'), function (q) { WS.devQ = q; paint(); }));
  main.appendChild(bar);
  var waitHost = el('div', 'pw-waithost');
  main.appendChild(waitHost);
  var grid = el('div', 'pw-devs');
  grid.appendChild(skeleton(3, 'pw-skels-grid'));
  main.appendChild(grid);
  var seq = WS.seq, rows = [];
  var paint = function () {
    clear(grid);
    var q = low(WS.devQ);
    var shown = rows.filter(function (r) {
      return !q || low([r.name, r.kind, r.title, r.owner, r.note, (r.config || {}).host].join(' ')).indexOf(q) >= 0;
    });
    if (!rows.length) {
      var b = null;
      if (can('target.manage')) { b = cmdButton('Add a device', 'add', 'primary'); b.onclick = function () { deviceDialog(null); }; }
      grid.appendChild(emptyState('server', 'No device yet', 'A device is a server or an appliance a certificate is put on - add one with the settings its module asks for.', b));
      return;
    }
    if (!shown.length) { grid.appendChild(emptyState('search', 'Nothing matches', 'No device here matches what you are looking for.')); return; }
    shown.forEach(function (r) { grid.appendChild(deviceCard(r)); });
    explainWhatWasDrawn(grid);
  };
  askTops('target.view', 'devices').then(function (d) {
    if (seq !== WS.seq) return;
    rows = d.rows.sort(function (a, b) { return low(a.name) < low(b.name) ? -1 : 1; });
    rows.forEach(function (r) { DEVICES_SEEN[r.id] = r; });
    paint();
  }).catch(function (e) { if (seq === WS.seq) failed(grid, e); });
  askTops('target.view', 'agents-waiting').then(function (d) {
    if (seq !== WS.seq || !d.rows.length) return;
    waitHost.appendChild(waitingCard(d));
    explainWhatWasDrawn(waitHost);
  }).catch(function () { });
}
function deviceCard(r) {
  var c = el('button', 'pw-dev' + (r.enabled ? '' : ' off'));
  c.type = 'button';
  var top = el('div', 'pw-dev-top');
  top.appendChild(ic(kindIconOf(r.kind), 22, 'pw-dev-ic k-' + (isAgent(r) ? 'agent' : 'x')));
  var w = el('div', 'pw-dev-w');
  w.appendChild(data('b', 'pw-dev-n', r.name));
  w.appendChild(data('span', 'pw-dev-k', r.title || r.kind));
  top.appendChild(w);
  var st = deviceState(r);
  top.appendChild(st);
  c.appendChild(top);
  var host = (r.config || {}).host || (r.agent && (r.agent.host || '')) || (r.config || {}).address || '';
  var meta = el('div', 'pw-dev-m');
  if (host) { var h = el('span', 'pw-dev-host'); h.appendChild(ic('globe', 13)); h.appendChild(data('span', 'mono', host)); meta.appendChild(h); }
  meta.appendChild(teamChip(r.owner, 'small'));
  c.appendChild(meta);
  var foot = el('div', 'pw-dev-f');
  var used = el('span', 'pw-dev-u');
  used.appendChild(ic('cert', 13));
  used.appendChild(el('span', '', r.used_by ? nW(r.used_by, 'certificates deployed') : tr('no certificate here yet')));
  foot.appendChild(used);
  if (r.last_ok || r.last_error) {
    var l = el('span', 'pw-dev-l ' + (r.last_error ? 'bad' : 'good'));
    l.appendChild(el('span', '', r.last_error ? 'last failed' : 'last went well'));
    l.appendChild(document.createTextNode(' · '));
    l.appendChild(el('span', '', agoW(r.last_error ? (r.last_error.at || r.last_error) : r.last_ok)));
    foot.appendChild(l);
  }
  c.appendChild(foot);
  c.onclick = function () { deviceOpen(r); };
  return c;
}
var AGENT_STATE = {answers: ['answers', 'ok'], quiet: ['not heard from', 'warn'], refused: ['refused', 'crit'],
  joining: ['joining', 'info'], 'new': ['not joined', 'dim'], off: ['switched off', 'dim']};
function deviceState(r) {
  if (!r.enabled) return chip('switched off', 'dim');
  if (isAgent(r) && r.agent) {
    var a = AGENT_STATE[r.agent.state] || [r.agent.state, 'dim'];
    var c = el('span', 'pw-state ' + a[1]);
    c.appendChild(dot(a[1]));
    c.appendChild(el('span', '', r.agent.waiting ? 'waits to be confirmed' : a[0]));
    return c;
  }
  var bad = !!r.last_error;
  var s = el('span', 'pw-state ' + (bad ? 'crit' : (r.last_ok ? 'ok' : 'dim')));
  s.appendChild(dot(bad ? 'crit' : (r.last_ok ? 'ok' : 'dim')));
  s.appendChild(el('span', '', bad ? 'failing' : (r.last_ok ? 'works' : 'not used yet')));
  return s;
}
function teamCaps(name) { var t = teamOf(name); return t ? arr(t.caps) : []; }
/** One device: what it is, its settings (secrets only set / not set), where it serves, its
    agent - and Test, Edit, Delete where the team gives them. */
function deviceOpen(r0) {
  modal(r0.name, function (body) { body.appendChild(skeleton(3)); }, [{words: 'Close', close: true}], 'large');
  var ticket = modalTicket();
  Promise.all([api('device&id=' + r0.id), api('kinds&team=' + encodeURIComponent(r0.owner || '')).catch(function () { return {}; })]).then(function (both) {
    if (!modalStill(ticket)) return;
    var d = both[0];
    var r = d.device || r0, may = r.may || d.may || {};
    /* the module's own words for its fields */
    var labels = {};
    arr(both[1].kinds).forEach(function (k) {
      if (k.kind !== r.kind) return;
      arr(k.fields).forEach(function (f) { if (f && f.key) labels[f.key] = f.label || f.key; });
    });
    var caps = teamCaps(r.owner);
    var buttons = [{words: 'Close', close: true}];
    if (may.manage || caps.indexOf('target.manage') >= 0) {
      buttons.push({words: 'Delete', icon: 'trash', go: function (b) {
        busy(b, true);
        api('device-delete', {id: r.id}).then(function (x) {
          if (x && x.waits) { toast(x.message || tr('it waits for an approval first'), 'good'); return; }
          closeModal();
          ok(x.message || tr('deleted'));
          refresh(true);
        }).catch(oops).then(function () { busy(b, false); });
      }});
      buttons.push({words: 'Edit', icon: 'edit', go: function () { modalOver(function () { deviceDialog(r); }, function () { deviceOpen(r); }); }});
    }
    if (may.test || caps.indexOf('target.test') >= 0) {
      buttons.push({words: 'Test it', icon: 'play', cls: 'primary', noConfirm: true, go: function (b) { testDevice(r, b); }});
    }
    modal(r.name, function (body) {
      var head = el('div', 'pw-dh');
      head.appendChild(ic(kindIconOf(r.kind), 26, 'pw-dh-ic'));
      var w = el('div', 'pw-dh-w');
      var t = el('div', 'pw-dh-t');
      t.appendChild(data('b', '', r.name));
      t.appendChild(deviceState(r));
      w.appendChild(t);
      var s = el('div', 'pw-dh-s');
      s.appendChild(data('span', '', r.title || r.kind));
      s.appendChild(teamChip(r.owner, 'small'));
      w.appendChild(s);
      head.appendChild(w);
      body.appendChild(head);
      var tb = el('div', 'pw-testbox');
      tb.id = 'pw-testbox';
      body.appendChild(tb);
      var pairs = [];
      Object.keys(r.config || {}).forEach(function (k) {
        var v = r.config[k];
        if ((r.secrets || {})[k] !== undefined) return;
        if (v === '' || v === null || v === undefined || typeof v === 'object') return;
        pairs.push([labels[k] || k, data('span', 'mono small', String(v))]);
      });
      Object.keys(r.secrets || {}).forEach(function (k) {
        pairs.push([labels[k] || k, chip(r.secrets[k] ? 'set' : 'not set', r.secrets[k] ? 'ok' : 'dim', 'lock')]);
      });
      if (r.note) pairs.push(['Note', data('span', '', r.note)]);
      pairs.push(['Added', when(r.created)]);
      var h4 = el('h4', 'pw-cm-h');
      h4.appendChild(ic('gear', 15));
      h4.appendChild(el('span', '', 'Its settings'));
      body.appendChild(h4);
      body.appendChild(kvTable(pairs.map(function (p) { return [p[0], p[1]]; })));
      var dh = el('h4', 'pw-cm-h');
      dh.appendChild(ic('deploy', 15));
      dh.appendChild(el('span', '', 'Certificates deployed here'));
      body.appendChild(dh);
      if (!arr(r.deploys).length) body.appendChild(el('p', 'muted small', 'None yet.'));
      arr(r.deploys).forEach(function (x) {
        var l = el('div', 'pw-depmini');
        l.appendChild(ic('cert', 14));
        l.appendChild(data('b', '', x.cert_name || ('#' + x.cert_id)));
        l.appendChild(depState(x.state));
        body.appendChild(l);
      });
      if (isAgent(r)) {
        var ah = el('div', 'pw-agenthost');
        body.appendChild(ah);
        agentPart(ah, r, d.device && d.device.agent, may.manage || caps.indexOf('target.manage') >= 0);
      }
    }, buttons, 'large');
  }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
}
function testDevice(r, b) {
  var box = $('pw-testbox');
  busy(b, true);
  if (box) { clear(box); box.className = 'pw-testbox run'; box.appendChild(el('span', 'pw-spin')); box.appendChild(el('span', '', 'Testing - acme connects to it now…')); }
  api('device-test', {id: r.id}, 120).then(function (x) {
    showTest(box, x);
  }).catch(function (e) { showTest(box, {ok: false, said: String(e.message || e)}); }).then(function () { busy(b, false); });
}
function showTest(box, x) {
  if (!box) { toast(x.said || (x.ok ? 'it answers' : 'it failed'), x.ok ? 'good' : 'bad'); return; }
  clear(box);
  box.className = 'pw-testbox ' + (x.ok ? 'good' : 'bad');
  var h = el('div', 'pw-test-h');
  h.appendChild(ic(x.ok ? 'check' : 'cancel', 20));
  var w = el('div', '');
  w.appendChild(el('b', '', x.ok ? 'The test went well' : 'The test failed'));
  w.appendChild(data('div', 'pw-test-s', String(x.said || '')));
  h.appendChild(w);
  box.appendChild(h);
  if (arr(x.steps).length && window.ACME_PORTAL_CERTS) box.appendChild(window.ACME_PORTAL_CERTS.jobLog(x.steps));
}
/** Add or change a device: the module first (those the team's limits allow), then its own
    fields as the administration draws them - secrets "set - leave empty to keep it". */
function deviceDialog(row) {
  var mayTeams = teamsWith('target.manage');
  var team = row ? row.owner : (mayTeams.indexOf(WS.team) >= 0 ? WS.team : mayTeams[0]);
  if (!team) { toast(tr('no team of yours lets you add devices'), 'bad'); return; }
  modal(row ? tr('Change') + ' ' + row.name : tr('Add a device'), function (body) { body.appendChild(skeleton(3)); }, [{words: 'Close', close: true}], 'large');
  var ticket = modalTicket();
  Promise.all([api('kinds&team=' + encodeURIComponent(team)), needForms()]).then(function (got) {
    if (!modalStill(ticket)) return;
    var k = got[0];
    var kinds = arr(k.kinds);
    if (row) {
      var mine = kinds.filter(function (x) { return x.kind === row.kind; })[0];
      if (!mine) throw new Error(tr('its module is not one the team may use any more'));
      deviceForm(row, mine, team, kinds, k);
      return;
    }
    if (kinds.length === 1) { deviceForm(null, kinds[0], team, kinds, k); return; }
    modal(tr('Add a device'), function (body) {
      if (mayTeams.length > 1) {
        var ts = selectBox(mayTeams.map(function (x) { return [x, x]; }), team);
        noI18n(ts);
        ts.onchange = function () { closeModal(); WS.team = WS.team; deviceDialogFor(ts.value); };
        body.appendChild(formField('For the team', ts, 'The device belongs to it: its members see it and deploy to it.'));
      }
      if (k.limit) {
        var n = el('div', 'pw-note');
        n.appendChild(ic('shield', 17));
        var nw = el('div', '');
        nw.appendChild(el('b', '', 'The modules the team may use'));
        var lw = el('span', '');
        lw.appendChild(data('span', '', arr(k.limit).join(', ')));
        if (k.from) { lw.appendChild(document.createTextNode(' · ')); lw.appendChild(el('span', '', 'set by')); lw.appendChild(document.createTextNode(' ')); lw.appendChild(data('b', '', k.from)); }
        nw.appendChild(lw);
        n.appendChild(nw);
        body.appendChild(n);
      }
      body.appendChild(el('p', 'note', 'What kind of device is it? Pick its module - then fill in what that module needs.'));
      var grid = el('div', 'pw-kinds');
      kinds.forEach(function (x) {
        var b = el('button', 'pw-kind');
        b.type = 'button';
        b.appendChild(ic(kindIconOf(x.kind), 22, 'pw-kind-ic'));
        var w = el('span', 'pw-kind-w');
        w.appendChild(el('b', '', x.title || x.kind));
        if (x.vendor) w.appendChild(el('span', 'pw-kind-v', x.vendor));
        if (x.description) w.appendChild(el('span', 'pw-kind-d', x.description));
        b.appendChild(w);
        b.onclick = function () { deviceForm(null, x, team, kinds, k); };
        grid.appendChild(b);
      });
      if (!kinds.length) grid.appendChild(emptyState('ban', 'No module allowed', 'The team’s limits allow no device module - ask its manager.'));
      body.appendChild(grid);
    }, [{words: 'Close', close: true}], 'large');
  }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
}
function deviceDialogFor(team) {
  var keep = WS.team;
  WS.team = team;
  try { deviceDialog(null); } finally { WS.team = keep; }
}
function deviceForm(row, kind, team, kinds, k) {
  var form = null, name = null, note = null, on = null, said = null;
  modal(row ? tr('Change') + ' ' + row.name : (kind.title || kind.kind), function (body) {
    var head = el('div', 'pw-dh');
    head.appendChild(ic(kindIconOf(kind.kind), 24, 'pw-dh-ic'));
    var w = el('div', 'pw-dh-w');
    var t = el('div', 'pw-dh-t');
    t.appendChild(el('b', '', kind.title || kind.kind));
    w.appendChild(t);
    var s = el('div', 'pw-dh-s');
    s.appendChild(el('span', '', 'for the team'));
    s.appendChild(teamChip(team, 'small'));
    w.appendChild(s);
    head.appendChild(w);
    body.appendChild(head);
    var g = el('div', 'formgrid');
    name = textBox(row ? row.name : '', kind.default_name ? '' : 'web1', 'mono');
    name.id = 'pw-dev-name';
    noI18n(name);
    if (row) name.disabled = true;
    g.appendChild(formField('Name', name, row ? 'Its name stays.' : 'How it is called here - unique.'));
    on = switchBox(row ? !!row.enabled : true);
    g.appendChild(formField('Switched on', on, 'Off: nothing is deployed to it.'));
    body.appendChild(g);
    form = window.ACME_CERTS.fieldForm(kind.fields || [], row ? row.config : {}, row ? row.secrets : {}, {});
    var fh = el('h4', 'pw-cm-h');
    fh.appendChild(ic('gear', 15));
    fh.appendChild(el('span', '', 'Its settings'));
    body.appendChild(fh);
    body.appendChild(form.node);
    note = el('textarea');
    note.rows = 2;
    note.value = row ? row.note || '' : '';
    note.placeholder = 'what it is, where it stands';
    var nf = formField('A note', note, '');
    nf.classList.add('wide');
    body.appendChild(nf);
    said = el('div', 'said');
    body.appendChild(said);
  }, [{words: row ? 'Close' : 'Back', icon: row ? null : 'prev', close: !!row, go: row ? null : function () { deviceDialog(null); }},
      {words: row ? 'Save' : 'Add it', cls: 'primary', icon: row ? 'save' : 'add', go: function (b) {
    said.className = 'said';
    said.textContent = '';
    var bad = form.check();
    if (!row && !name.value.trim()) { said.className = 'said bad'; said.textContent = tr('Give it a name.'); name.focus(); return; }
    if (bad) { said.className = 'said bad'; said.textContent = bad; return; }
    busy(b, true);
    var body = {team: team, kind: kind.kind, enabled: on._get() ? 1 : 0, note: note.value, config: form.read()};
    if (row) body.id = row.id; else body.name = name.value.trim();
    api('device-save', body).then(function (x) {
      closeModal();
      ok(x.message || tr('saved'));
      refresh(WS.view === 'devices');
      var dev = x.device || {id: x.id, name: body.name, kind: kind.kind, owner: team};
      if (!row) setTimeout(function () { deviceOpen(dev); }, 50);
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
    }).then(function () { busy(b, false); });
  }}], 'large');
}

/* ---- agents: waiting ones, join and enrollment codes, the server panel ------------------- */
function fpBig(fp) {
  var box = noI18n(el('div', 'ag-fp small'));
  var f = String(fp || '').toUpperCase();
  for (var i = 0; i < f.length; i += 4) {
    var s = el('span', 'ag-fp-g', f.slice(i, i + 4));
    if ((i / 4) % 4 === 3) s.classList.add('brk');
    box.appendChild(s);
  }
  return box;
}
function waitingCard(d) {
  var c = card('Waiting for confirmation', 'agent', 'pw-waiting');
  cardRight(c, noI18n(el('span', 'pw-badge warn big', String(d.rows.length))));
  c.appendChild(el('p', 'note', 'Each agent below asks to join. Compare its fingerprint with the one the server printed (acme-agent join, or acme-agent fingerprint there) - confirm only when every group is the same. Until then acme sends it nothing.'));
  d.rows.forEach(function (r) {
    var row = el('div', 'pw-wrow');
    var w = el('div', 'pw-wrow-w');
    var t = el('div', 'pw-wrow-t');
    t.appendChild(ic(r.platform === 'windows' ? 'windows' : 'terminal', 15));
    t.appendChild(data('b', '', r.name));
    if (r.owner) t.appendChild(teamChip(r.owner, 'small'));
    if (r.enroll) { var e = chip(r.enroll.title || r.enroll.id, 'violet', 'people', true); explain(e, tr('Joined with the code')); t.appendChild(e); }
    w.appendChild(t);
    var m = el('div', 'pw-wrow-m');
    if (r.fqdn || r.host) m.appendChild(data('span', 'mono', String(r.fqdn || r.host)));
    if (r.ip) m.appendChild(data('span', 'mono muted', String(r.ip)));
    if (r.os) m.appendChild(data('span', 'muted', String(r.os)));
    if (r.at) m.appendChild(el('span', 'muted', agoW(r.at)));
    w.appendChild(m);
    w.appendChild(fpBig(r.fp));
    row.appendChild(w);
    if (can('target.manage', r.owner) || teamCaps(r.owner).indexOf('target.manage') >= 0) {
      var bs = el('div', 'pw-wrow-b');
      var no = cmdButton('Refuse', 'ban', 'small');
      no.onclick = function () {
        confirmThen(tr('Refuse the agent of {0}').replace('{0}', r.name), tr('The server asking to join is refused; the device made for it is taken away.'), 'Refuse it', function () {
          api('agent-refuse', {id: r.id}).then(function (x) { ok(x.message || tr('refused')); refresh(true); }).catch(oops);
        });
      };
      var yes = cmdButton('Confirm…', 'check', 'small primary');
      yes.onclick = function () {
        modal(tr('Confirm the agent of {0}').replace('{0}', r.name), function (body) {
          body.appendChild(el('p', 'note', 'Compare this fingerprint with the one the server printed. Confirm only when every group is the same.'));
          var f = fpBig(r.fp);
          f.classList.remove('small');
          body.appendChild(f);
        }, [{words: 'Close', close: true}, {words: 'It is the same - confirm', cls: 'primary', icon: 'check', close: true, go: function () {
          api('agent-confirm', {id: r.id, fp: r.fp}, 90).then(function (x) {
            if (x && x.said) toast(String(x.said), 'bad'); else ok(tr('the agent is confirmed'));
            refresh(true);
          }).catch(oops);
        }}], 'medium');
      };
      bs.appendChild(no);
      bs.appendChild(yes);
      row.appendChild(bs);
    }
    c.appendChild(row);
  });
  return c;
}
function cmdBox(text) {
  var box = el('div', 'dbs-cmd ag-cmd');
  box.appendChild(noI18n(el('pre', 'mono', text)));
  var cp = cmdButton('Copy', 'copy', 'small');
  cp.onclick = function () { copyText(text, cp, 'on the clipboard'); };
  box.appendChild(cp);
  return box;
}
function linuxLines(code) {
  var ol = el('ol', 'dbs-steps ag-steps');
  [['In the unpacked package, install and join at once:', 'sudo ./install.sh --join ' + code],
   ['Or, with the agent installed already:', 'sudo acme-agent join ' + code]].forEach(function (x) {
    var li = el('li', '');
    li.appendChild(el('span', '', x[0]));
    li.appendChild(cmdBox(x[1]));
    ol.appendChild(li);
  });
  return ol;
}
function windowsLines(code, version) {
  var name = 'acme-agent-' + (version || 'X.Y.Z') + '-windows-x64.msi';
  var ol = el('ol', 'dbs-steps ag-steps ag-winsteps');
  var add = function (words, line, note) {
    var li = el('li', '');
    li.appendChild(el('span', '', words));
    if (line) li.appendChild(cmdBox(line));
    if (note) li.appendChild(el('p', 'note small muted', note));
    ol.appendChild(li);
  };
  add('By hand: run the MSI - Next, Next, Install. At its Join step paste the code (or leave it empty and join later).', '',
    'The installer joins in the background: no network is needed while it installs, and acme-agent status says how it goes.');
  add('Silently, for many servers (Group Policy, Intune, SCCM):', 'msiexec /i ' + name + ' /qn JOINCODE=' + code,
    'Group Policy: a computer startup script with that line. Intune or SCCM: a Win32 app (or an application) whose install command is that line - every server then waits for confirmation here.');
  add('Or from the command line, in an elevated prompt (Run as administrator):', 'acme-agent join ' + code);
  return ol;
}
var OS_ON = 'linux';
function osTabs(code, version) {
  var box = el('div', 'ag-ostabs pw-ostabs');
  var seg = el('div', 'seg ag-osseg');
  seg.setAttribute('role', 'tablist');
  var body = el('div', 'ag-ostab-b');
  var show = function () {
    Array.prototype.forEach.call(seg.children, function (b) {
      var on = b.getAttribute('data-os') === OS_ON;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    clear(body);
    body.appendChild(OS_ON === 'windows' ? windowsLines(code, version) : linuxLines(code));
    explainWhatWasDrawn(body);
  };
  [['linux', 'terminal', 'Linux'], ['windows', 'windows', 'Windows']].forEach(function (x) {
    var b = el('button', '');
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('data-os', x[0]);
    b.appendChild(ic(x[1], 14));
    b.appendChild(el('span', '', x[2]));
    b.onclick = function () { OS_ON = x[0]; show(); };
    seg.appendChild(b);
  });
  box.appendChild(seg);
  box.appendChild(body);
  show();
  return box;
}
function codeShown(title, made, words) {
  modal(title, function (body) {
    var hd = el('div', 'ag-made');
    hd.appendChild(ic('check', 22));
    var hw = el('div', '');
    hw.appendChild(data('b', '', made.title || made.name || ''));
    var sub = el('div', 'ag-made-sub');
    if (made.until) sub.appendChild(el('span', '', tr('valid until {0}').replace('{0}', when(made.until))));
    if (made.most) { sub.appendChild(noI18n(el('span', 'muted', '·'))); sub.appendChild(el('span', '', tr('at most {0} servers').replace('{0}', made.most))); }
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
    once.appendChild(ic('eyeoff', 14));
    once.appendChild(el('span', '', words || 'Shown this once - copy it now. Keep it as a password: whoever has it can ask to join servers.'));
    body.appendChild(once);
    body.appendChild(el('h4', 'dbw-h', 'On each server'));
    body.appendChild(osTabs(made.code, made.version));
  }, [{words: 'Close', close: true}], 'medium');
}
var ESTATE = {active: ['active', 'ok'], expired: ['ran out', 'dim'], used: ['used up', 'dim'], revoked: ['revoked', 'crit']};
/** Enrol servers: the team's enrollment codes, and a new one - its servers become the team's
    devices, waiting for a member to confirm them. */
function enrolDialog() {
  var mayTeams = teamsWith('target.manage');
  var team = mayTeams.indexOf(WS.team) >= 0 ? WS.team : mayTeams[0];
  modal(tr('Enrol servers'), function (body) { body.appendChild(skeleton(2)); }, [{words: 'Close', close: true}], 'medium');
  var ticket = modalTicket();
  api('agents-waiting&team=' + encodeURIComponent(team)).then(function (d) {
    if (!modalStill(ticket)) return;
    var F = {title: '', mode: 'active', days: 7, most: 10, auto: false};
    var tsel = null;
    modal(tr('Enrol servers'), function (body) {
      var lead = el('div', 'pw-enrol-lead');
      lead.appendChild(ic('agent', 26, 'pw-enrol-ic'));
      var lw = el('div', '');
      lw.appendChild(el('b', '', 'One code for many servers'));
      lw.appendChild(el('p', 'note small', 'Install the agent on as many servers as you like - by hand, or with Group Policy, Intune, SCCM or Ansible. Each server appears among the team’s devices, waiting for confirmation by a member who manages its devices.'));
      lead.appendChild(lw);
      body.appendChild(lead);
      if (!d.active) body.appendChild(el('p', 'note warn small', 'An enrolling agent asks acme on the agents’ port, which is switched off now - the administrators switch it on.'));
      var codes = arr(d.codes);
      if (codes.length) {
        var h = el('h4', 'pw-cm-h');
        h.appendChild(ic('key', 15));
        h.appendChild(el('span', '', 'The team’s codes'));
        body.appendChild(h);
        codes.forEach(function (c) {
          var r = el('div', 'pw-code');
          var st = ESTATE[c.state] || [c.state, 'dim'];
          r.appendChild(dot(st[1]));
          var w = el('div', 'pw-code-w');
          w.appendChild(data('b', '', c.title || c.id));
          var m = el('span', 'muted small');
          m.appendChild(el('span', '', st[0]));
          m.appendChild(document.createTextNode(' · ' + (c.uses || 0) + ' / ' + (c.most || '∞') + ' · '));
          m.appendChild(el('span', '', tr('valid until {0}').replace('{0}', when(c.until))));
          w.appendChild(m);
          r.appendChild(w);
          if (c.state === 'active') {
            var rv = cmdButton('Revoke', 'ban', 'small');
            rv.onclick = function () {
              busy(rv, true);
              api('enroll-revoke', {id: c.id}).then(function () { ok(tr('the enrollment code is revoked')); closeModal(); enrolDialog(); }).catch(oops).then(function () { busy(rv, false); });
            };
            r.appendChild(rv);
          }
          body.appendChild(r);
        });
      }
      var h2 = el('h4', 'pw-cm-h');
      h2.appendChild(ic('add', 15));
      h2.appendChild(el('span', '', 'A new enrollment code'));
      body.appendChild(h2);
      var g = el('div', 'formgrid');
      if (mayTeams.length > 1) {
        tsel = selectBox(mayTeams.map(function (x) { return [x, x]; }), team);
        noI18n(tsel);
        g.appendChild(formField('For the team', tsel, 'Servers joining with it become devices of this team.'));
      }
      var title = textBox('', 'Web servers in Prague', '');
      title.oninput = function () { F.title = title.value; };
      g.appendChild(formField('Name', title, 'What these servers are - shown with each of them.'));
      var mode = selectBox([['active', 'the agent connects to acme (nothing open on the server)'], ['passive', 'acme connects to the agent (it listens, 8446)']], 'active');
      mode.onchange = function () { F.mode = mode.value; };
      g.appendChild(formField('Who connects', mode, ''));
      var days = textBox('7', '7', '');
      days.type = 'number';
      days.oninput = function () { F.days = days.value; };
      g.appendChild(formField('Valid for (days)', days, ''));
      var most = textBox('10', '10', '');
      most.type = 'number';
      most.oninput = function () { F.most = most.value; };
      g.appendChild(formField('At most (servers)', most, ''));
      if (d.auto_ok) {
        var au = switchBox(false);
        au._input.onchange = function () { F.auto = !!au._get(); };
        g.appendChild(formField('Confirmed automatically', au, 'Allowed by the administrators for this team: servers joining with it are confirmed without a look at their fingerprint.'));
      }
      body.appendChild(g);
    }, [{words: 'Close', close: true}, {words: 'Make the code', cls: 'primary', icon: 'key', go: function (b) {
      busy(b, true);
      api('enroll-code', {team: tsel ? tsel.value : team, title: F.title || tr('Servers of {0}').replace('{0}', team), mode: F.mode,
                          days: Number(F.days || 7), most: Number(F.most || 10), auto: F.auto ? 1 : 0}).then(function (x) {
        codeShown(tr('The enrollment code'), x);
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
}
/** The agent of a device: its state, the server panel (agents.js), its join code, its policy
    (the builder), a newer agent. */
function agentPart(host, r, a, manage) {
  host.appendChild(skeleton(1));
  Promise.all([needAgents(), a ? Promise.resolve({agent: a}) : api('agent&id=' + r.id)]).then(function (got) {
    var AG = got[0], info = (got[1] && got[1].agent) || {};
    clear(host);
    var h = el('h4', 'pw-cm-h');
    h.appendChild(ic('agent', 15));
    h.appendChild(el('span', '', 'Its agent'));
    if (AG.statePill) { try { h.appendChild(AG.statePill(info)); } catch (e) { } }
    host.appendChild(h);
    if (!info.joined) {
      var j = el('div', 'pw-note');
      j.appendChild(ic('key', 17));
      var jw = el('div', '');
      jw.appendChild(el('b', '', 'Not joined yet'));
      jw.appendChild(el('span', '', 'Install the agent on the server and join it with a one-time code made here.'));
      j.appendChild(jw);
      host.appendChild(j);
    }
    if (AG.sysPanel && info.joined) { try { host.appendChild(AG.sysPanel(r, info, null)); } catch (e) { if (window.console) console.error(e); } }
    var bar = el('div', 'btnrow pw-agent-b');
    if (manage) {
      var jc = cmdButton(info.joined ? 'A new join code' : 'Make a join code', 'key', info.joined ? 'small' : 'small primary');
      jc.onclick = function () {
        busy(jc, true);
        api('agent-code', {id: r.id}).then(function (x) {
          x.title = r.name;
          modalOver(function () { codeShown(tr('The join code'), x, tr('Shown this once - copy it now. It joins this one server, once.')); }, function () { deviceOpen(r); });
        }).catch(oops).then(function () { busy(jc, false); });
      };
      bar.appendChild(jc);
    }
    /* what the server runs that takes certificates (agent_discover, agents.js's card) */
    if (AG.discoverBox && info.joined) {
      try { host.appendChild(AG.discoverBox(r, info, {manage: !!manage, read: true, reopen: function () { deviceOpen(r); }, done: function () { }})); }
      catch (e) { if (window.console) console.error(e); }
    }
    if (info.joined && window.ACME_POLICY_BUILDER) {
      var pb = cmdButton('Design its policy…', 'shield', 'small');
      pb.onclick = function () { window.ACME_POLICY_BUILDER.open({id: r.id, name: r.name}, {maySave: manage, done: function () { }}); };
      bar.appendChild(pb);
    }
    if (manage && info.update && info.update.newer) {
      var up = cmdButton('Update the agent now', 'up', 'small');
      up.onclick = function () {
        busy(up, true);
        api('agent-update', {id: r.id}, 240).then(function (x) { ok(String((x && x.said) || tr('updated'))); }).catch(oops).then(function () { busy(up, false); });
      };
      bar.appendChild(up);
    }
    if (bar.children.length) host.appendChild(bar);
    explainWhatWasDrawn(host);
  }).catch(function (e) { failed(host, e); });
}

/* =============================================================================================
   DEPLOYMENTS
   ============================================================================================= */
var DSTATE = {ok: ['deployed', 'ok'], failed: ['failed', 'crit'], pending: ['waiting', 'warn'], running: ['running', 'info'],
  outdated: ['an older version', 'warn'], off: ['switched off', 'dim'], 'new': ['not deployed yet', 'dim']};
function depState(st) {
  var s = DSTATE[st] || [st || 'not deployed yet', 'dim'];
  var c = el('span', 'pw-state ' + s[1]);
  c.appendChild(dot(s[1]));
  c.appendChild(el('span', '', s[0]));
  return c;
}
function viewDeploys(main) {
  var bs = [];
  if (can('deploy.manage')) {
    var add = cmdButton('Add a deployment', 'add', 'primary');
    add.id = 'pw-add-deploy';
    add.onclick = function () { deployDialog(null); };
    bs.push(add);
  }
  main.appendChild(pageHead('deploy', 'Deployments', 'Which certificate goes to which device - put there by itself after every renewal.', bs));
  var list = el('div', 'card pw-deps');
  list.appendChild(skeleton(3));
  main.appendChild(list);
  var seq = WS.seq;
  askTops('deploy.view', 'deploys').then(function (d) {
    if (seq !== WS.seq) return;
    clear(list);
    if (!d.rows.length) {
      var b = null;
      if (can('deploy.manage')) { b = cmdButton('Add a deployment', 'add', 'primary'); b.onclick = function () { deployDialog(null); }; }
      list.appendChild(emptyState('deploy', 'Nothing is deployed yet', 'A deployment puts a certificate of the team on a device of the team - again after every renewal.', b));
      return;
    }
    d.rows.sort(function (a, b) { return low(a.cert_name) < low(b.cert_name) ? -1 : (low(a.cert_name) > low(b.cert_name) ? 1 : (low(a.target) < low(b.target) ? -1 : 1)); });
    d.rows.forEach(function (r) { list.appendChild(deployLine(r, true)); });
    explainWhatWasDrawn(list);
  }).catch(function (e) { if (seq === WS.seq) failed(list, e); });
}
function deployLine(r, tools) {
  var row = el('div', 'pw-dep' + (r.enabled === 0 ? ' off' : ''));
  var a = el('div', 'pw-dep-a');
  a.appendChild(ic('cert', 16, 'pw-dep-ic'));
  a.appendChild(data('b', '', r.cert_name || ('#' + r.cert_id)));
  row.appendChild(a);
  row.appendChild(ic('next', 15, 'pw-dep-arrow'));
  var b = el('div', 'pw-dep-b');
  b.appendChild(ic(kindIconOf(r.target_kind), 16, 'pw-dep-ic'));
  b.appendChild(data('b', '', r.target));
  row.appendChild(b);
  var st = el('div', 'pw-dep-s');
  st.appendChild(depState(r.enabled === 0 ? 'off' : (r.outdated && r.state === 'ok' ? 'outdated' : r.state)));
  if (r.last_error) { var e = el('span', 'pw-dep-err'); e.appendChild(data('span', '', String(r.last_error.said || r.last_error).slice(0, 140))); st.appendChild(e); }
  else if (r.last_ok) st.appendChild(el('span', 'muted small', agoW(r.last_ok)));
  row.appendChild(st);
  if (tools) {
    var caps = teamCaps(r.team || r.owner || ((teamOf(WS.team) || {}).name)) ;
    if (!caps.length) caps = capsOf(WS.team);
    var t = el('div', 'pw-dep-t');
    var plan = iconButton('search', tr('What happens'));
    plan.onclick = function () { dryRun(r); };
    t.appendChild(plan);
    if (caps.indexOf('deploy.run') >= 0) {
      var run = iconButton('play', tr('Deploy now'));
      run.classList.add('pw-run');
      run.onclick = function () {
        busy(run, true);
        api('deploy-run', {id: r.id}).then(function (x) {
          ok(tr('deploying - it runs now'));
          if (x.job_id) followDeploy(x.job_id, r);
        }).catch(oops).then(function () { busy(run, false); });
      };
      t.appendChild(run);
    }
    if (caps.indexOf('deploy.manage') >= 0) {
      var ed = iconButton('edit', tr('Change it'));
      ed.onclick = function () { deployDialog(r); };
      t.appendChild(ed);
      var del = iconButton('trash', tr('Delete it'));
      del.onclick = function () {
        confirmThen(tr('Delete the deployment'), tr('The certificate is no longer put on this device. What is on the device now stays there.'), 'Delete it', function () {
          api('deploy-delete', {id: r.id}).then(function (x) { ok(x.message || tr('deleted')); go('deploys'); }).catch(oops);
        });
      };
      t.appendChild(del);
    }
    row.appendChild(t);
  }
  return row;
}
function followDeploy(jobId, r) {
  modal(tr('Deploying') + ' · ' + (r.cert_name || ''), function (body) { body.appendChild(skeleton(2)); }, [{words: 'Close', close: true}], 'medium');
  var ticket = modalTicket();
  var step = function () {
    api('cert-job&id=' + jobId).then(function (d) {
      if (!modalStill(ticket)) return;
      var j = d.job || {};
      var body = $('modal-body');
      clear(body);
      var h = el('div', 'pw-testbox ' + (j.live ? 'run' : (j.ok ? 'good' : 'bad')));
      var hh = el('div', 'pw-test-h');
      hh.appendChild(j.live ? el('span', 'pw-spin') : ic(j.ok ? 'check' : 'cancel', 20));
      var w = el('div', '');
      w.appendChild(el('b', '', j.live ? 'Deploying…' : (j.ok ? 'Deployed' : 'It failed')));
      if (j.said) w.appendChild(data('div', 'pw-test-s', String(j.said)));
      hh.appendChild(w);
      h.appendChild(hh);
      if (window.ACME_PORTAL_CERTS) h.appendChild(window.ACME_PORTAL_CERTS.jobLog(arr(j.steps)));
      body.appendChild(h);
      if (j.live) setTimeout(step, 1200); else if (WS.view === 'deploys') go('deploys');
    }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
  };
  step();
}
function dryRun(r) {
  need(['runplan.css', 'runplan.js']).then(function () {
    window.ACME_RUNPLAN.open({name: (r.cert_name || '') + ' → ' + (r.target || ''), ask: function () {
      return api('deploy-dry-run', {id: r.id}, 180);
    }});
  }).catch(oops);
}
/** A deployment added or changed: a certificate of the team, a device of the team, the
    module's own deployment options. */
var DEVICES_SEEN = {};
function deviceById(id) { return DEVICES_SEEN[id] || null; }
function deployDialog(row, pre) {
  pre = pre || null;
  var team = row ? (row.team || WS.team) : (pre && pre.team && teamsWith('deploy.manage').indexOf(pre.team) >= 0 ? pre.team
    : (teamsWith('deploy.manage').indexOf(WS.team) >= 0 ? WS.team : teamsWith('deploy.manage')[0]));
  if (!team || team === '*') team = teamsWith('deploy.manage')[0];
  if (!team) { toast(tr('no team of yours lets you set up deployments'), 'bad'); return; }
  modal(row ? tr('Change the deployment') : tr('Add a deployment'), function (body) { body.appendChild(skeleton(3)); }, [{words: 'Close', close: true}], 'large');
  var ticket = modalTicket();
  Promise.all([api('devices&team=' + encodeURIComponent(team) + '&below=1'), api('kinds&team=' + encodeURIComponent(team)), needForms()]).then(function (got) {
    if (!modalStill(ticket)) return;
    var devices = arr(got[0].rows), kinds = arr(got[1].kinds);
    var pick = {cert: row ? {id: row.cert_id, name: row.cert_name} : null, dev: row ? devices.filter(function (x) { return x.name === row.target; })[0] || {name: row.target, kind: row.target_kind} : null};
    if (pre) {
      pick.dev = devices.filter(function (x) { return x.name === pre.target; })[0] || null;
      if (pre.cert_id) pick.cert = {id: pre.cert_id, name: '#' + pre.cert_id};
      row = null;
    }
    var preOpts = pre ? pre.options || {} : null;
    var optHost = null, form = null, on = null, note = null, said = null, certBox = null, devSel = null;
    var drawOpts = function () {
      clear(optHost);
      form = null;
      if (!pick.dev) { optHost.appendChild(el('p', 'muted small', 'Pick the device first - its module says what it needs.')); return; }
      var k = kinds.filter(function (x) { return x.kind === pick.dev.kind; })[0];
      if (!k) { optHost.appendChild(el('p', 'note warn small', 'The team may not deploy to a device of this module.')); return; }
      form = window.ACME_CERTS.fieldForm(k.deploy_fields || [], row ? row.options : (preOpts || {}), row ? row.secrets : {}, {kept: row ? row.options : null});
      optHost.appendChild(form.node);
    };
    modal(row ? tr('Change the deployment') : tr('Add a deployment'), function (body) {
      var flow = el('div', 'pw-flow');
      /* the certificate: searched among the team's */
      var cs = el('div', 'pw-flow-s');
      cs.appendChild(el('span', 'pw-flow-k', 'The certificate'));
      certBox = el('div', 'pw-pick');
      cs.appendChild(certBox);
      flow.appendChild(cs);
      flow.appendChild(ic('next', 18, 'pw-flow-arrow'));
      var ds = el('div', 'pw-flow-s');
      ds.appendChild(el('span', 'pw-flow-k', 'The device'));
      devSel = selectBox([['', '–']].concat(devices.map(function (x) { return [x.name, x.name + ' · ' + (x.title || x.kind)]; })), pick.dev ? pick.dev.name : '');
      devSel.id = 'pw-dep-dev';
      noI18n(devSel);
      devSel.onchange = function () { pick.dev = devices.filter(function (x) { return x.name === devSel.value; })[0] || null; drawOpts(); };
      if (row) devSel.disabled = true;
      ds.appendChild(devSel);
      if (!devices.length) ds.appendChild(el('p', 'note warn small', 'The team has no device yet - add one first.'));
      flow.appendChild(ds);
      body.appendChild(flow);
      var drawCert = function () {
        clear(certBox);
        if (pick.cert) {
          var c = el('div', 'pw-pick-on');
          c.appendChild(ic('cert', 16));
          c.appendChild(data('b', '', pick.cert.name));
          if (!row) {
            var x = iconButton('close', tr('Another one'));
            x.onclick = function () { pick.cert = null; drawCert(); };
            c.appendChild(x);
          }
          certBox.appendChild(c);
          return;
        }
        var res = el('div', 'pw-pick-l');
        var s = searchBox('', tr('Search the team’s certificates'), function (q) { find(q); });
        s._input.id = 'pw-dep-cert';
        certBox.appendChild(s);
        certBox.appendChild(res);
        var find = function (q) {
          api('certs&team=' + encodeURIComponent(team) + '&below=1&per=8&q=' + encodeURIComponent(q || '')).then(function (d) {
            clear(res);
            arr(d.rows).forEach(function (c) {
              var o = el('button', 'pw-pick-o');
              o.type = 'button';
              o.appendChild(ic('cert', 14));
              o.appendChild(data('span', '', c.name));
              if (c.owner) o.appendChild(teamChip(c.owner, 'small'));
              o.onclick = function () { pick.cert = {id: c.id, name: c.name}; drawCert(); };
              res.appendChild(o);
            });
            if (!res.children.length) res.appendChild(el('p', 'muted small', 'Nothing matches.'));
          }).catch(oops);
        };
        find('');
      };
      drawCert();
      /* prefilled from a discovery: the certificate it serves now, by its name */
      if (pick.cert && /^#/.test(pick.cert.name)) {
        api('certs&team=' + encodeURIComponent(team) + '&below=1&per=200').then(function (d) {
          var c = arr(d.rows).filter(function (x) { return x.id === pick.cert.id; })[0];
          if (c) { pick.cert.name = c.name; drawCert(); }
        }).catch(function () { });
      }
      if (pre) {
        var pn = el('div', 'pw-note');
        pn.appendChild(ic('search', 17));
        var pw = el('div', '');
        pw.appendChild(el('b', '', 'Filled in from what was found on the server'));
        pw.appendChild(el('span', '', 'Look at it before you add it - the files, the service, its reload.'));
        pn.appendChild(pw);
        body.insertBefore(pn, body.firstChild);
      }
      var oh = el('h4', 'pw-cm-h');
      oh.appendChild(ic('gear', 15));
      oh.appendChild(el('span', '', 'How it is put there'));
      body.appendChild(oh);
      optHost = el('div', 'pw-opts');
      body.appendChild(optHost);
      drawOpts();
      var g = el('div', 'formgrid');
      on = switchBox(row ? row.enabled !== 0 : true);
      g.appendChild(formField('Switched on', on, 'Off: it is kept, but nothing is deployed.'));
      note = textBox(row ? row.note || '' : '', '', '');
      g.appendChild(formField('A note', note, ''));
      body.appendChild(g);
      said = el('div', 'said');
      body.appendChild(said);
    }, [{words: 'Close', close: true}, {words: row ? 'Save' : 'Add it', cls: 'primary', icon: row ? 'save' : 'add', go: function (b) {
      said.className = 'said bad';
      if (!pick.cert) { said.textContent = tr('Pick the certificate.'); return; }
      if (!pick.dev) { said.textContent = tr('Pick the device.'); return; }
      var bad = form ? form.check() : '';
      if (bad) { said.textContent = bad; return; }
      said.textContent = '';
      busy(b, true);
      var body = {cert_id: pick.cert.id, target: pick.dev.name, options: form ? form.read() : {}, enabled: on._get() ? 1 : 0, note: note.value};
      if (row) body.id = row.id;
      api('deploy-save', body).then(function (x) {
        closeModal();
        ok(x.message || tr('saved'));
        if (WS.view === 'deploys') go('deploys');
      }).catch(function (e) { said.className = 'said bad'; said.textContent = String(e.message || e); }).then(function () { busy(b, false); });
    }}], 'large');
  }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
}

/* =============================================================================================
   MEMBERS
   ============================================================================================= */
/** A view of one team only: in "All my teams", the teams where it can be done, as cards. */
function needOneTeam(main, cap, iconKey, title, words) {
  if (WS.team !== '*' && can(cap)) return teamOf(WS.team);
  main.appendChild(pageHead(iconKey, title, words));
  var c = card('Choose a team', 'tree', 'pw-choose');
  var grid = el('div', 'pw-choose-g');
  teams().filter(function (t) { return arr(t.caps).indexOf(cap) >= 0; }).forEach(function (t) {
    var b = el('button', 'pw-choose-o');
    b.type = 'button';
    b.appendChild(ic(kindIcon(t), 20));
    var w = el('span', '');
    w.appendChild(data('b', '', t.name));
    if (t.description) w.appendChild(data('span', '', t.description));
    b.appendChild(w);
    b.onclick = function () { pickTeam(t.name); };
    grid.appendChild(b);
  });
  c.appendChild(grid);
  main.appendChild(c);
  return null;
}
var KIND_WORDS = {local: 'an account of acme’s own', user: 'a person of the directory', group: 'a directory group'};
function viewMembers(main) {
  var t = needOneTeam(main, 'team.members', 'people', 'Members', 'Who is in a team, and what each may do there.');
  if (!t) return;
  var add = cmdButton('Add a member', 'add', 'primary');
  add.id = 'pw-add-member';
  main.appendChild(pageHead('people', 'Members', 'Who is in the team and what each may do - members of the teams above work here too.', [add]));
  var c = card('', null, 'pw-members');
  c.appendChild(skeleton(3));
  main.appendChild(c);
  var seq = WS.seq;
  api('members&team=' + encodeURIComponent(t.name)).then(function (d) {
    if (seq !== WS.seq) return;
    add.onclick = function () { memberDialog(t, d, null); };
    clear(c);
    var ms = arr(d.members);
    if (!ms.length) c.appendChild(emptyState('people', 'No member of its own', 'Add people or directory groups - each with the roles that say what they may do.'));
    ms.forEach(function (m) { c.appendChild(memberRow(t, d, m, true)); });
    if (arr(d.above).length) {
      var h = el('h3', 'pw-sub-h');
      h.appendChild(ic('up', 15));
      h.appendChild(el('span', '', 'Through the teams above'));
      c.appendChild(h);
      c.appendChild(el('p', 'note small', 'Members of the teams above hold what they hold there here too - changed in those teams.'));
      d.above.forEach(function (m) { c.appendChild(memberRow(t, d, m, false)); });
    }
    explainWhatWasDrawn(c);
  }).catch(function (e) { if (seq === WS.seq) failed(c, e); });
}
function memberRow(t, d, m, own) {
  var r = el('div', 'pw-mem' + (m.expired ? ' expired' : '') + (own ? '' : ' above'));
  r.appendChild(avatar(m.who, m.kind === 'group'));
  var w = el('div', 'pw-mem-w');
  var top = el('div', 'pw-mem-t');
  top.appendChild(data('b', '', whoWords(m.who).replace(/^group:/i, '')));
  if (m.me) top.appendChild(chip('you', 'info'));
  if (!own && m.team) top.appendChild(teamChip(m.team, 'small'));
  w.appendChild(top);
  var sub = el('div', 'pw-mem-s');
  sub.appendChild(el('span', 'muted', KIND_WORDS[m.kind] || m.kind || ''));
  if (m.until) {
    var u = chip((m.expired ? tr('ended') : tr('until')) + ' ' + dayWords(new Date(m.until * 1000)), m.expired ? 'crit' : 'warn', 'calendar');
    sub.appendChild(u);
  }
  if (m.note) sub.appendChild(data('span', 'muted', m.note));
  w.appendChild(sub);
  r.appendChild(w);
  var roles = el('div', 'pw-mem-r');
  arr(m.roles).forEach(function (x) { roles.appendChild(chip(x, 'violet', null, true)); });
  arr(m.rights).forEach(function (x) { roles.appendChild(chip(x, 'dim', null, true)); });
  r.appendChild(roles);
  if (own) {
    var tools = el('div', 'pw-mem-b');
    var ed = iconButton('edit', tr('Change'));
    ed.disabled = !m.may_change;
    if (!m.may_change) ed.title = tr('they hold more than you do here - not yours to change');
    ed.onclick = function () { memberDialog(t, d, m); };
    tools.appendChild(ed);
    var rm = iconButton('trash', tr('Take them off'));
    rm.disabled = !m.may_change;
    rm.onclick = function () {
      confirmThen(tr('Take a member off'), tr('{0} is no longer a member of {1}.').replace('{0}', htmlText(whoWords(m.who))).replace('{1}', htmlText(t.name)), 'Take it off', function () {
        api('member-delete', {team: t.name, who: m.who}).then(function (x) { ok(x.message || tr('done')); go('members'); }).catch(oops);
      });
    };
    tools.appendChild(rm);
    r.appendChild(tools);
  }
  return r;
}
function memberDialog(t, d, m) {
  var who = null, picked = {}, until = null, note = null, said = null, results = null;
  arr(m && m.roles).forEach(function (x) { picked[x] = 1; });
  arr(m && m.rights).forEach(function (x) { picked['right:' + x] = 1; });
  modal(m ? tr('Change a member') : tr('Add a member'), function (body) {
    var top = el('div', 'pw-mfind');
    who = textBox(m ? m.who : '', 'jan.novak, jnovak@corp.example, group:PKI-Web, local:jan', 'mono');
    who.id = 'pw-mem-who';
    noI18n(who);
    if (m) who.disabled = true;
    top.appendChild(formField('Who', who, 'A person (name, UPN or e-mail), a directory group (group:NAME) or an account of acme’s own (local:NAME). Type to search the directory.'));
    results = el('div', 'pw-mfind-r');
    top.appendChild(results);
    body.appendChild(top);
    if (!m) {
      var look = debounce(function () {
        var q = who.value.trim();
        clear(results);
        if (q.length < 2 || /^(local|group):/i.test(q)) return;
        Promise.all([api('dir-search&kind=user&q=' + encodeURIComponent(q)), api('dir-search&kind=group&q=' + encodeURIComponent(q))]).then(function (got) {
          clear(results);
          arr(got[0].rows).concat(arr(got[1].rows)).slice(0, 12).forEach(function (x) {
            var o = el('button', 'pw-mfind-o');
            o.type = 'button';
            var g = /^group:/i.test(x.who);
            o.appendChild(avatar(x.who, g));
            var w = el('span', '');
            w.appendChild(data('b', '', x.display || x.cn || x.who));
            w.appendChild(data('span', 'mono', x.who));
            o.appendChild(w);
            if (x.disabled) o.appendChild(chip('switched off', 'crit'));
            o.onclick = function () { who.value = x.who; clear(results); };
            results.appendChild(o);
          });
        }).catch(function () { clear(results); });
      }, 300);
      who.addEventListener('input', look);
    }
    var rh = el('h4', 'pw-cm-h');
    rh.appendChild(ic('shield', 15));
    rh.appendChild(el('span', '', 'Roles'));
    body.appendChild(rh);
    var grid = el('div', 'pw-roles');
    arr(d.roles).forEach(function (x) {
      var lab = el('label', 'pw-role' + (x.givable ? '' : ' no'));
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = !!picked[x.name];
      cb.disabled = !x.givable;
      cb.onchange = function () { if (cb.checked) picked[x.name] = 1; else delete picked[x.name]; };
      lab.appendChild(cb);
      var w = el('span', 'pw-role-w');
      w.appendChild((x.builtin ? el : data)('b', '', x.name));
      if (x.description) w.appendChild((x.builtin ? el : data)('span', '', x.description));
      if (!x.givable) w.appendChild(el('span', 'pw-role-no', 'more than you hold here - not yours to give'));
      lab.appendChild(w);
      grid.appendChild(lab);
    });
    body.appendChild(grid);
    var g = el('div', 'formgrid');
    until = el('input');
    until.type = 'date';
    until.id = 'pw-mem-until';
    if (m && m.until) { var dd = new Date(m.until * 1000); until.value = dd.getFullYear() + '-' + pad2(dd.getMonth() + 1) + '-' + pad2(dd.getDate()); }
    g.appendChild(formField('Until', until, 'Leave it empty for good - or the last day of a temporary membership.'));
    note = textBox(m ? m.note || '' : '', 'why they are here', '');
    g.appendChild(formField('A note', note, ''));
    body.appendChild(g);
    said = el('div', 'said');
    body.appendChild(said);
  }, [{words: 'Close', close: true}, {words: m ? 'Save' : 'Add them', cls: 'primary', icon: m ? 'save' : 'add', go: function (b) {
    var roles = Object.keys(picked).filter(function (k) { return k.indexOf('right:') !== 0; });
    var rights = Object.keys(picked).filter(function (k) { return k.indexOf('right:') === 0; }).map(function (k) { return k.slice(6); });
    said.className = 'said bad';
    if (!who.value.trim()) { said.textContent = tr('Who? Type a name or pick one.'); who.focus(); return; }
    if (!roles.length && !rights.length) { said.textContent = tr('Give them a role at least.'); return; }
    said.textContent = '';
    busy(b, true);
    api('member-save', {team: t.name, who: who.value.trim(), roles: roles, rights: rights, until: until.value || null,
                        note: note.value, old_who: m ? m.who : undefined}).then(function (x) {
      closeModal();
      ok(x.message || tr('saved'));
      go('members');
    }).catch(function (e) { said.className = 'said bad'; said.textContent = String(e.message || e); }).then(function () { busy(b, false); });
  }}], 'medium');
}

/* =============================================================================================
   SUB-TEAMS & LIMITS
   ============================================================================================= */
function viewTeams(main) {
  var t = WS.team !== '*' && (can('team.create') || can('team.policy')) ? teamOf(WS.team) : null;
  if (!t) { needOneTeam(main, can('team.create', '*') ? 'team.create' : 'team.policy', 'tree', 'Sub-teams & limits', 'The teams below one of yours, and the limits they work within.'); return; }
  var add = null;
  if (can('team.create')) {
    add = cmdButton('A sub-team', 'add', 'primary');
    add.id = 'pw-add-team';
    add.onclick = function () { teamDialog(t, null); };
  }
  main.appendChild(pageHead('tree', 'Sub-teams & limits', 'The teams below this one: made and named here, each within the limits set here - never wider than this team’s own.', [add]));
  var cols = el('div', 'pw-cols');
  var tree = card('The teams below', 'tree', 'pw-tree');
  var kids = below(t.name);
  var root = el('div', 'pw-node root');
  root.appendChild(ic(kindIcon(t), 18));
  root.appendChild(data('b', '', t.name));
  root.appendChild(chip('this team', 'info'));
  tree.appendChild(root);
  if (!kids.length) tree.appendChild(emptyState('tree', 'No team below this one', 'Make a sub-team for a part of the work - a site, a service, a group of servers - with its own members and limits.'));
  kids.forEach(function (k) {
    var n = el('div', 'pw-node');
    n.style.setProperty('--d', Math.max(1, k.depth - t.depth));
    n.appendChild(ic(kindIcon(k), 17));
    var w = el('div', 'pw-node-w');
    var top = el('div', 'pw-node-t');
    top.appendChild(data('b', '', k.name));
    var cnt = k.counts || {};
    if (cnt.certs !== undefined) top.appendChild(chip(nW(cnt.certs, 'certificates'), 'dim', 'cert'));
    if (k.members !== undefined) top.appendChild(chip(nW(k.members, 'members'), 'dim', 'people'));
    var own = Object.keys(k.own_policy || {}).length;
    if (own) top.appendChild(chip(nW(own, 'limits of its own'), 'warn', 'shield'));
    w.appendChild(top);
    if (k.description) w.appendChild(data('span', 'pw-node-d', k.description));
    n.appendChild(w);
    var b = el('div', 'pw-node-b');
    var parentCaps = teamCaps(k.parent);
    if (parentCaps.indexOf('team.policy') >= 0) {
      var lim = cmdButton('Limits', 'sliders', 'small');
      lim.onclick = function () { limitsDialog(k); };
      b.appendChild(lim);
    }
    if (parentCaps.indexOf('team.create') >= 0) {
      var ed = iconButton('edit', tr('Rename, describe'));
      ed.onclick = function () { teamDialog(teamOf(k.parent), k); };
      b.appendChild(ed);
      var del = iconButton('trash', tr('Delete the team'));
      del.onclick = function () { deleteTeam(k); };
      b.appendChild(del);
    }
    var open = iconButton('next', tr('Open the team'));
    open.onclick = function () { pickTeam(k.name); };
    b.appendChild(open);
    n.appendChild(b);
    tree.appendChild(n);
  });
  cols.appendChild(tree);
  var side = el('div', 'pw-side');
  side.appendChild(limitsCard(t));
  cols.appendChild(side);
  main.appendChild(cols);
}
function teamDialog(parent, k) {
  var name = null, desc = null, kind = null, said = null, lim = null;
  modal(k ? tr('Change') + ' ' + k.name : tr('A new sub-team of {0}').replace('{0}', parent.name), function (body) {
    var g = el('div', 'formgrid');
    name = textBox(k ? k.name : '', 'WebOps', '');
    name.id = 'pw-team-name';
    noI18n(name);
    g.appendChild(formField('Name', name, 'Unique among all teams.'));
    kind = selectBox([['team', 'a team'], ['unit', 'a unit (a region, a site)']], k ? k.kind : 'team');
    g.appendChild(formField('It is', kind, ''));
    desc = textBox(k ? k.description || '' : '', 'what it looks after', '');
    var df = formField('Description', desc, '');
    df.classList.add('wide');
    g.appendChild(df);
    body.appendChild(g);
    if (!k && teamCaps(parent.name).indexOf('team.policy') >= 0) {
      var h = el('h4', 'pw-cm-h');
      h.appendChild(ic('sliders', 15));
      h.appendChild(el('span', '', 'Its limits'));
      body.appendChild(h);
      lim = limitsEditor(parent, {});
      body.appendChild(lim.node);
    }
    said = el('div', 'said');
    body.appendChild(said);
  }, [{words: 'Close', close: true}, {words: k ? 'Save' : 'Make the team', cls: 'primary', icon: k ? 'save' : 'add', go: function (b) {
    said.className = 'said bad';
    if (!name.value.trim()) { said.textContent = tr('Give it a name.'); name.focus(); return; }
    var out = k ? {old_name: k.name, name: name.value.trim(), description: desc.value, kind: kind.value}
      : {name: name.value.trim(), parent: parent.name, description: desc.value, kind: kind.value};
    if (lim) { var p = lim.read(); if (p.bad) { said.textContent = p.bad; return; } if (Object.keys(p.policy).length) out.policy = p.policy; }
    said.textContent = '';
    busy(b, true);
    api('team-save', out).then(function (x) {
      closeModal();
      ok(x.message || tr('saved'));
      refresh(true);
    }).catch(function (e) { said.className = 'said bad'; said.textContent = String(e.message || e); }).then(function () { busy(b, false); });
  }}], 'large');
}
function deleteTeam(k) {
  confirmThen(tr('Delete the team {0}').replace('{0}', k.name),
    htmlText(tr('Its certificates and devices go to the team above ({0}), and so do the teams below it. Its members lose what it gave them.').replace('{0}', k.parent || '')),
    'Delete it', function () {
      api('team-delete', {name: k.name}).then(function (x) { ok(x.message || tr('deleted')); refresh(true); }).catch(oops);
    });
}
function limitsDialog(k) {
  var parent = teamOf(k.parent);
  var ed = null, said = null;
  modal(tr('The limits of {0}').replace('{0}', k.name), function (body) {
    body.appendChild(el('p', 'note', 'Each limit narrows what the team above allows - never wider. Unset, the limit of the teams above holds (said beside it).'));
    ed = limitsEditor(parent, k.own_policy || {});
    body.appendChild(ed.node);
    said = el('div', 'said');
    body.appendChild(said);
  }, [{words: 'Close', close: true}, {words: 'Save the limits', cls: 'primary', icon: 'save', go: function (b) {
    var p = ed.read();
    said.className = 'said bad';
    if (p.bad) { said.textContent = p.bad; return; }
    said.textContent = '';
    busy(b, true);
    api('team-save', {old_name: k.name, policy: p.policy}).then(function (x) {
      closeModal();
      ok(x.message || tr('saved'));
      refresh(true);
    }).catch(function (e) { said.className = 'said bad'; said.textContent = String(e.message || e); }).then(function () { busy(b, false); });
  }}], 'large');
}
/** Chips typed in (Enter or a comma adds one), each taken off by its x. */
function chipsInput(values, placeholder, suggest) {
  var box = el('div', 'pw-chipin');
  var list = arr(values).slice();
  var input = el('input');
  input.type = 'text';
  input.placeholder = placeholder || '';
  input.spellcheck = false;
  noI18n(input);
  if (suggest && suggest.length) {
    var dl = el('datalist');
    dl.id = 'pw-dl-' + Math.random().toString(36).slice(2);
    suggest.forEach(function (s) { var o = el('option'); o.value = s; dl.appendChild(o); });
    box.appendChild(dl);
    input.setAttribute('list', dl.id);
  }
  var paint = function () {
    Array.prototype.slice.call(box.querySelectorAll('.pw-chipin-c')).forEach(function (n) { n.remove(); });
    list.forEach(function (v, i) {
      var c = el('span', 'pw-chipin-c');
      c.appendChild(data('span', '', v));
      var x = el('button', '');
      x.type = 'button';
      x.setAttribute('aria-label', tr('Take it off'));
      x.innerHTML = iconMarkup('close', 12);
      x.onclick = function () { list.splice(i, 1); paint(); };
      c.appendChild(x);
      box.insertBefore(c, input);
    });
  };
  var take = function () {
    String(input.value || '').split(/[\s,;]+/).map(function (s) { return s.trim(); }).filter(Boolean).forEach(function (s) { if (list.indexOf(s) < 0) list.push(s); });
    input.value = '';
    paint();
  };
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); take(); }
    if (e.key === 'Backspace' && !input.value && list.length) { list.pop(); paint(); }
  });
  input.addEventListener('change', take);
  input.addEventListener('blur', take);
  box.appendChild(input);
  box.onclick = function (e) { if (e.target === box) input.focus(); };
  paint();
  box._get = function () { take(); return list.slice(); };
  box._input = input;
  return box;
}
/** The limits editor: each limit "as above" or set here, with what holds above beside it. */
function limitsEditor(parent, own) {
  var eff = (parent && parent.policy) || {}, from = eff.from || {};
  var node = el('div', 'pw-led');
  var items = [];
  var above = function (key, words) {
    var h = el('span', 'pw-above');
    if (eff[key] === undefined || eff[key] === null) { h.appendChild(el('span', '', 'no limit above')); return h; }
    h.appendChild(el('span', '', 'above:'));
    h.appendChild(document.createTextNode(' '));
    h.appendChild(data('b', '', words !== undefined ? words : (Array.isArray(eff[key]) ? eff[key].join(', ') : String(eff[key]))));
    if (from[key]) {
      h.appendChild(document.createTextNode(' · '));
      h.appendChild(el('span', '', 'from'));
      h.appendChild(document.createTextNode(' '));
      h.appendChild(data('b', '', from[key]));
    }
    return h;
  };
  var row = function (key, label, input, set, read, aboveWords) {
    var r = el('div', 'pw-led-r' + (set ? ' on' : ''));
    var sw = switchBox(!!set);
    sw.classList.add('pw-led-sw');
    sw.setAttribute('aria-label', label);
    var l = el('div', 'pw-led-l');
    l.appendChild(el('b', '', label));
    l.appendChild(above(key, aboveWords));
    var head = el('div', 'pw-led-h');
    head.appendChild(sw);
    head.appendChild(l);
    r.appendChild(head);
    var v = el('div', 'pw-led-v');
    v.appendChild(input);
    r.appendChild(v);
    sw._input.onchange = function () { r.classList.toggle('on', !!sw._get()); };
    node.appendChild(r);
    items.push({key: key, on: function () { return !!sw._get(); }, read: read});
  };
  var listRow = function (key, label, ph, suggest) {
    var ci = chipsInput(own[key] || eff[key] || [], ph, suggest);
    row(key, label, ci, own[key] !== undefined, function () { return ci._get(); });
  };
  var numRow = function (key, label, unit) {
    var i = el('input');
    i.type = 'number';
    i.min = 1;
    i.value = own[key] || eff[key] || '';
    i.id = 'pw-led-' + key;
    var w = el('span', 'pw-led-num');
    w.appendChild(i);
    if (unit) w.appendChild(el('span', 'muted', unit));
    row(key, label, w, own[key] !== undefined, function () { return i.value === '' ? null : Number(i.value); },
        eff[key] && unit ? nW(eff[key], unit) : undefined);
  };
  var boolRow = function (key, label, yes, no) {
    var s = selectBox([['1', yes], ['0', no]], own[key] === false ? '0' : '1');
    row(key, label, s, own[key] !== undefined, function () { return s.value === '1'; }, eff[key] === undefined ? undefined : tr(eff[key] ? yes : no));
  };
  var profs = (window.ACME_PORTAL_CERTS && window.ACME_PORTAL_CERTS.data() && arr(window.ACME_PORTAL_CERTS.data().profiles).map(function (p) { return p.name; })) || [];
  listRow('profiles', 'Request profiles', 'a profile’s name', profs.concat(arr(eff.profiles)));
  boolRow('free_form', 'Without a profile', 'may ask', 'never');
  listRow('suffixes', 'Names under', 'example.com', arr(eff.suffixes));
  numRow('max_days', 'Longest validity', 'days');
  numRow('max_certs', 'Most certificates', '');
  listRow('target_kinds', 'Device modules', 'ssh, agent, f5…', arr(eff.target_kinds));
  boolRow('key_download', 'Private keys', 'may be downloaded', 'never downloaded');
  boolRow('agents', 'Agents', 'allowed', 'not allowed');
  /* approval */
  var a0 = own.approval ? (typeof own.approval === 'string' ? {mode: own.approval} : own.approval) : {};
  var ae = eff.approval ? (typeof eff.approval === 'string' ? {mode: eff.approval} : eff.approval) : null;
  var ap = el('div', 'pw-led-ap');
  var mode = selectBox([['none', MODE_WORDS.none], ['outside', MODE_WORDS.outside], ['profile', MODE_WORDS.profile], ['always', MODE_WORDS.always]], a0.mode || 'profile');
  var who = selectBox([['team', APPROVER_WORDS.team], ['parent', APPROVER_WORDS.parent], ['team_or_parent', APPROVER_WORDS.team_or_parent], ['both', APPROVER_WORDS.both]], a0.approvers || 'team');
  var cnt = selectBox([['1', 'one approver'], ['2', 'four eyes - two approvers']], String(a0.count || 1));
  ap.appendChild(formField('Requests', mode, ''));
  ap.appendChild(formField('Approved by', who, ''));
  ap.appendChild(formField('How many', cnt, ''));
  row('approval', 'Approval', ap, own.approval !== undefined, function () {
    return {mode: mode.value, approvers: who.value, count: Number(cnt.value)};
  }, ae ? tr(MODE_WORDS[ae.mode] || ae.mode) : undefined);
  var acts = el('div', 'pw-led-acts');
  var picks = {};
  arr(own.approve_actions).forEach(function (x) { picks[x] = 1; });
  ['revoke', 'delete', 'key', 'device'].forEach(function (x) {
    var lab = el('label', 'pw-check');
    var cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = !!picks[x];
    cb.onchange = function () { if (cb.checked) picks[x] = 1; else delete picks[x]; };
    lab.appendChild(cb);
    lab.appendChild(el('span', '', ACTION_WORDS_P[x]));
    acts.appendChild(lab);
  });
  row('approve_actions', 'Also approved first', acts, own.approve_actions !== undefined, function () { return Object.keys(picks); },
      arr(eff.approve_actions).length ? arr(eff.approve_actions).map(function (x) { return tr(ACTION_WORDS_P[x] || x); }).join(', ') : undefined);
  return {node: node, read: function () {
    var p = {}, bad = '';
    items.forEach(function (it) {
      if (!it.on()) return;
      var v = it.read();
      if ((it.key === 'max_days' || it.key === 'max_certs') && (v === null || !(v > 0))) { bad = tr('a number of days or certificates is 1 at least'); return; }
      p[it.key] = v;
    });
    /* keys of its own the editor does not show (agents_auto_confirm, issuers, validations) stay */
    ['issuers', 'validations', 'agents_auto_confirm'].forEach(function (k) { if (own[k] !== undefined) p[k] = own[k]; });
    return {policy: p, bad: bad};
  }};
}

/* =============================================================================================
   ACTIVITY
   ============================================================================================= */
function viewActivity(main) {
  var t = needOneTeam(main, 'team.activity', 'pulse', 'Activity', 'What happened in a team - its certificates, devices and members.');
  if (!t) return;
  main.appendChild(pageHead('pulse', 'Activity', 'What happened to the team’s certificates, devices and members - newest first.'));
  var c = card('', null, 'pw-activity');
  main.appendChild(c);
  var page = 0;
  var load = function () {
    clear(c);
    c.appendChild(skeleton(5));
    var seq = WS.seq;
    api('activity&team=' + encodeURIComponent(t.name) + '&page=' + page + '&per=30' + (WS.below && below(t.name).length ? '&below=1' : '')).then(function (d) {
      if (seq !== WS.seq) return;
      clear(c);
      if (!arr(d.rows).length) { c.appendChild(emptyState('pulse', 'Nothing happened yet', 'What the team’s people and acme do with its certificates and devices is written here.')); return; }
      var ol = el('ol', 'pw-acts');
      arr(d.rows).forEach(function (r) {
        var li = el('li', 'pw-act ' + ({bad: 'crit', warn: 'warn', ok: 'ok'}[r.level] || 'info'));
        li.appendChild(el('span', 'pw-act-m'));
        var w = el('div', 'pw-act-w');
        w.appendChild(el('div', 'pw-act-t', r.words));
        var m = el('div', 'pw-act-s');
        if (r.who) { m.appendChild(avatar(r.who)); m.appendChild(data('span', '', whoWords(r.who))); }
        m.appendChild(noI18n(el('span', 'muted', when(r.ts))));
        w.appendChild(m);
        li.appendChild(w);
        ol.appendChild(li);
      });
      c.appendChild(ol);
      if ((d.pages || 1) > 1) {
        var bar = el('div', 'cp-pager');
        var back = iconButton('prev', tr('Newer'));
        back.disabled = page <= 0;
        back.onclick = function () { page -= 1; load(); };
        var next = iconButton('next', tr('Older'));
        next.disabled = page >= d.pages - 1;
        next.onclick = function () { page += 1; load(); };
        bar.appendChild(back);
        bar.appendChild(noI18n(el('span', 'cp-pager-n', (page + 1) + ' / ' + d.pages)));
        bar.appendChild(next);
        c.appendChild(bar);
      }
      explainWhatWasDrawn(c);
    }).catch(function (e) { if (seq === WS.seq) failed(c, e); });
  };
  load();
}

window.ACME_PORTAL_WS = {start: start, go: go, pick: pickTeam, state: WS};
})();
