/* palette.js - Ctrl+K (⌘K on a Mac): one box to find anything in the administration and go
   there or do it (1.0.138, docs/context-menu.md "The command palette"): the certificates,
   targets, agents, sources, validations, tests, teams and request profiles; every tab and every
   pane of Settings; the page's own buttons (Add a certificate, Import...); and, typed as a verb
   first, an action on an object - "renew web", "test fw1", "deploy mail". The last ones chosen
   come first. Keyboard only, if you like: ↑ ↓, Enter, Esc. Nothing is asked of the daemon
   until it is opened.
   1.0.140: what is typed is also asked of the server (GET /api/search - api_search.py): every
   certificate by its names, SANs or serial, the deployments, agents, authorities, accounts (a
   full administrator's) and the events of the last 30 days - each kept by the server to what
   this account may see - grouped with the page's own; Enter opens the object's own card or page.
   The search box in the header opens the same. */
(function () {
'use strict';
if (window.ACME_PALETTE) return;
var P = window.ACME_PALETTE = {open: open, close: close};
var MAC = /Mac|iPhone|iPad/.test(navigator.platform || '');
var RECENT_KEY = 'acme.palette.recent';
var CACHE = {at: 0, items: null, asking: null};
var ST = null;      /* {veil, box, input, list, rows, at, items} */

function me() { return (typeof ME === 'object' && ME) || null; }
function role() { var m = me(); return (m && m.role) || 'readonly'; }
function full() { return role() === 'fulladmin'; }
function manage() { var r = role(); return r === 'fulladmin' || r === 'certadmin' || r === 'tokenadmin'; }
function tr(s) { try { var t = typeof i18nText === 'function' ? i18nText(String(s)) : null; return t || String(s); } catch (e) { return String(s); } }
function arr(v) { return Array.isArray(v) ? v : []; }
function H() { return (window.ACME_CERTS && window.ACME_CERTS.ctx) || null; }
function capi(path) { return window.ACME_CERTS && window.ACME_CERTS.api ? window.ACME_CERTS.api(path) : api(path); }
function fold(s) {
  s = String(s || '').toLowerCase();
  try { s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (e) { }
  return s;
}

/* ---- what can be found -------------------------------------------------------------- */
var KIND = {
  cert: ['Certificate', 'lock', 'ok'], target: ['Target', 'net', 'info'], agent: ['Agent', 'terminal', 'violet'],
  source: ['Source', 'download', 'info'], validation: ['Validation', 'check', 'info'], test: ['Test', 'pulse', 'info'],
  team: ['Team', 'people', 'violet'], profile: ['Request profile', 'list', 'warn'], pane: ['Settings', 'gear', 'dim'],
  tab: ['Page', 'chart', 'dim'], action: ['Action', 'play', 'ok'],
  /* found by the server (1.0.140) */
  deploy: ['Deployment', 'upload', 'info'], ca: ['Authority', 'shield', 'violet'], account: ['Account', 'person', 'dim'],
  event: ['Event', 'history', 'dim']
};
function shown(n) { return !!(n && (n.offsetParent !== null || n.closest('.panel, #ctl-nav'))) && !n.hidden && !(n.classList.contains('fulladmin-only') && !full()); }
function staticItems() {
  var out = [];
  Array.prototype.forEach.call(document.querySelectorAll('.tabs [role="tab"][data-tab]'), function (b) {
    if (b.hidden || b.style.display === 'none') return;
    var name = b.getAttribute('data-tab');
    var words = '';
    Array.prototype.forEach.call(b.childNodes, function (c) { if (c.nodeType === 3) words += c.textContent; else if (c.tagName === 'SPAN' && !c.classList.contains('count')) words += c.textContent; });
    words = words.trim() || b.textContent.trim();
    out.push({kind: 'tab', key: 'tab:' + name, label: words, sub: '', icon: b.getAttribute('data-icon') || '', go: function () { showTab(name); }});
  });
  var group = '';
  Array.prototype.forEach.call(document.querySelectorAll('#ctl-nav > *'), function (n) {
    if (n.classList.contains('ctl-group')) { group = n.textContent.trim(); return; }
    if (n.tagName !== 'BUTTON' || !n.dataset.pane || n.hidden) return;
    if (n.classList.contains('fulladmin-only') && !full()) return;
    var name = n.dataset.pane;
    var words = '';
    Array.prototype.forEach.call(n.childNodes, function (c) { if (c.nodeType === 3) words += c.textContent; });
    words = words.trim() || n.textContent.trim();
    out.push({kind: 'pane', key: 'pane:' + name, label: words, sub: group, icon: n.getAttribute('data-icon') || '', about: n.getAttribute('title') || n.getAttribute('aria-label') || '',
              go: function () { showTab('settings'); setTimeout(function () { if (typeof showPane === 'function') showPane(name); }, 30); }});
  });
  /* the page's own buttons: the ones that make something */
  var ACTS = [['ct-add', 'certs'], ['ct-import', 'certs'], ['ct-onlineimport', 'certs'], ['ct-self', 'certs'], ['ct-csr', 'certs'],
              ['ct-tests', 'certs'], ['ct-view', 'certs'], ['src-add', 'sources'], ['val-add', 'validation'], ['tg-add', 'targets'],
              ['ts-add', 'tests'], ['ca-root', 'cas'], ['ca-inter', 'cas'], ['ca-import', 'cas'], ['ca-sign', 'cas'], ['log-read', 'events']];
  if (window.acmeTrash && typeof window.acmeTrash.open === 'function' && document.querySelector('#ctl-nav [data-pane]')) {
    out.push({kind: 'action', key: 'act:trash', label: 'Open the trash', sub: '', icon: 'trash', go: function () { window.acmeTrash.open(); }});
  }
  /* 1.0.140: the expiry calendar, a request profile from a template */
  if (window.ACME_CAL && typeof window.ACME_CAL.open === 'function' && document.getElementById('tab-certs')) {
    out.push({kind: 'action', key: 'act:calendar', label: 'The expiry calendar', sub: '', icon: 'cal', about: 'when certificates run out',
              go: function () { window.ACME_CAL.open(); }});
  }
  if (full() && window.ACME_RP_TPL && document.querySelector('#ctl-nav [data-pane="reqprofiles"]')) {
    out.push({kind: 'action', key: 'act:rptemplate', label: 'A request profile from a template', sub: '', icon: 'add',
              go: function () { goPane('reqprofiles', function () { if (!document.getElementById('rp-tpl')) return false; window.ACME_RP_TPL.open(); return true; }); }});
  }
  ACTS.forEach(function (a) {
    var b = document.getElementById(a[0]);
    if (!b || b.hidden || b.disabled) return;
    if ((b.classList.contains('ct-fulladmin') || b.classList.contains('fulladmin-only')) && !full()) return;
    if (b.classList.contains('ct-manage') && !manage()) return;
    var words = b.textContent.trim();
    if (!words) return;
    out.push({kind: 'action', key: 'act:' + a[0], label: words, sub: '', icon: b.getAttribute('data-icon') || '', go: function () { showTab(a[1]); setTimeout(function () { b.click(); }, 40); }});
  });
  return out;
}
/* The daemon's serial (its last event, admin.js's tick): it moved - something was made, renamed or
   deleted, here, in another tab or by somebody else - the objects are asked anew. They were kept a
   minute whatever happened: a certificate deleted was still offered (its card a 404) and one
   renamed was found only by its old name. */
function serialNow() { try { return typeof SERIAL !== 'undefined' ? String(SERIAL) : ''; } catch (e) { return ''; } }
function objectItems() {
  if (CACHE.items && Date.now() - CACHE.at < 60000 && CACHE.serial === serialNow()) return Promise.resolve(CACHE.items);
  if (CACHE.asking) return CACHE.asking;
  var serial = serialNow();
  var safe = function (p) { return p.catch(function () { return null; }); };
  var have = !!window.ACME_CERTS;
  CACHE.asking = Promise.all([
    have ? safe(capi('certs?per=1000')) : Promise.resolve(null),
    have ? safe(capi('targets')) : Promise.resolve(null),
    have ? safe(capi('sources')) : Promise.resolve(null),
    have ? safe(capi('validations')) : Promise.resolve(null),
    have ? safe(capi('tests')) : Promise.resolve(null),
    safe(api('teams')), safe(api('reqprofiles'))
  ]).then(function (g) {
    var out = [];
    var rows = function (d, k) { return arr(d && (d[k] || d.rows)); };
    rows(g[0], 'certs').forEach(function (c) {
      out.push({kind: 'cert', key: 'cert:' + c.id, label: c.name, sub: (c.names || []).slice(0, 3).join(', '), obj: c, data: true,
                words: (c.names || []).join(' ') + ' ' + (c.serial || '') + ' ' + (c.owner || ''),
                go: function () { window.ACME_CERTS.certPeek(c.id); }});
    });
    var mod = function (d, kind, key) {
      rows(d, kind === 'source' ? 'sources' : kind === 'validation' ? 'validations' : kind === 'test' ? 'tests' : 'targets').forEach(function (r) {
        var agent = kind === 'target' && /^agent/.test(r.kind || '');
        var cfg = r.config || {};
        out.push({kind: agent ? 'agent' : kind, key: kind + ':' + r.id, label: r.name, sub: (r.title || r.kind || '') + (cfg.host ? ' · ' + cfg.host : ''), obj: r, data: true, family: key,
                  words: (r.kind || '') + ' ' + (cfg.host || cfg.hostname || cfg.url || '') + ' ' + (r.tags || []).join(' '),
                  go: function () { var h = H(); if (!h) return; if (key === 'targets') h.targetPeek(r); else h.modEdit(key, r); }});
      });
    };
    mod(g[1], 'target', 'targets');
    mod(g[2], 'source', 'sources');
    mod(g[3], 'validation', 'validation');
    mod(g[4], 'test', 'tests');
    arr(g[5] && g[5].teams).forEach(function (t) {
      out.push({kind: 'team', key: 'team:' + t.name, label: t.name, sub: t.description || '', data: true, obj: t,
                go: function () { goPane('teams', function () {
                  var r = document.querySelector('#tmx-tree .tmx-row[data-name="' + String(t.name).replace(/["\\]/g, '\\$&') + '"]');
                  if (r) { r.click(); return true; }
                  return false;
                }); }});
    });
    arr(g[6] && g[6].profiles).forEach(function (p) {
      out.push({kind: 'profile', key: 'profile:' + p.name, label: p.name, sub: p.description || p.issuer || '', data: true, obj: p,
                go: function () { goPane('reqprofiles', function () {
                  var r = document.querySelector('#rp-host .rp-row[data-name="' + String(p.name).replace(/["\\]/g, '\\$&') + '"]');
                  if (!r) return false;
                  var ed = r.querySelector('.rp-edit');
                  if (ed) ed.click(); else r.scrollIntoView({block: 'center'});
                  return true;
                }); }});
    });
    CACHE.items = out;
    CACHE.at = Date.now();
    CACHE.serial = serial;
    CACHE.asking = null;
    return out;
  });
  return CACHE.asking;
}
function openTeam(name) {
  goPane('teams', function () {
    var r = document.querySelector('#tmx-tree .tmx-row[data-name="' + String(name).replace(/["\\]/g, '\\$&') + '"]');
    if (r) { r.click(); return true; }
    return false;
  });
}
function openProfile(name) {
  goPane('reqprofiles', function () {
    var r = document.querySelector('#rp-host .rp-row[data-name="' + String(name).replace(/["\\]/g, '\\$&') + '"]');
    if (!r) return false;
    var ed = r.querySelector('.rp-edit');
    if (ed) ed.click(); else r.scrollIntoView({block: 'center'});
    return true;
  });
}
function goPane(name, then) {
  showTab('settings');
  setTimeout(function () {
    if (typeof showPane === 'function') showPane(name);
    var n = 0;
    var tick = function () { if (then() || ++n > 40) return; setTimeout(tick, 100); };
    setTimeout(tick, 120);
  }, 30);
}

/* ---- what the server finds (1.0.140): GET /api/search, kept there to what this account sees ---- */
var REMOTE = {timer: null, ticket: 0};
function rowIn(list, id) {
  return capi(list).then(function (d) { return arr(d && d.rows).filter(function (x) { return String(x.id) === String(id); })[0] || null; });
}
function remoteGo(kind, r) {
  var h = H();
  if (kind === 'cert') { if (window.ACME_CERTS) window.ACME_CERTS.certPeek(r.id); return; }
  if (kind === 'deploy') { if (window.ACME_CERTS) window.ACME_CERTS.certPeek(r.cert_id); return; }
  if (kind === 'ca') { if (window.ACME_CERTS && window.ACME_CERTS.caPeek) window.ACME_CERTS.caPeek(r.id); return; }
  if (kind === 'team') { openTeam(r.name); return; }
  if (kind === 'profile') { openProfile(r.name); return; }
  if (kind === 'target' || kind === 'agent' || kind === 'source' || kind === 'validation' || kind === 'test') {
    var list = {target: 'targets', agent: 'targets', source: 'sources', validation: 'validations', test: 'tests'}[kind];
    var key = {target: 'targets', agent: 'targets', source: 'sources', validation: 'validation', test: 'tests'}[kind];
    rowIn(list, r.id).then(function (row) {
      if (!row || !h) return;
      if (key === 'targets') h.targetPeek(row); else h.modEdit(key, row);
    }).catch(oops);
    return;
  }
  if (kind === 'account') {
    goPane('people', function () {
      var host = document.getElementById('us-table');
      if (!host || !host.querySelector('tr')) return false;
      var hit = Array.prototype.filter.call(host.querySelectorAll('tr'), function (tr0) {
        return Array.prototype.some.call(tr0.querySelectorAll('td'), function (td) { return td.textContent.trim() === r.name; });
      })[0];
      if (hit) {
        hit.scrollIntoView({block: 'center'});
        hit.classList.add('cxp-flash');
        setTimeout(function () { hit.classList.remove('cxp-flash'); }, 2200);
      }
      return true;
    });
    return;
  }
  if (kind === 'event') {
    showTab('events');
    setTimeout(function () {
      var q = document.getElementById('ev-q');
      if (!q) return;
      q.value = String(r.name || '').slice(0, 80);
      try { q.dispatchEvent(new Event('input', {bubbles: true})); } catch (e) { }
    }, 80);
  }
}
function pat(s, a) { return tr(s).replace('{0}', a); }
function remoteItems(groups) {
  var out = [];
  Object.keys(groups || {}).forEach(function (kind) {
    if (!KIND[kind]) return;
    arr(groups[kind]).forEach(function (r) {
      var key = kind === 'team' || kind === 'profile' || kind === 'account' ? kind + ':' + r.name
        : (kind === 'agent' ? 'target' : kind) + ':' + r.id;
      var sub = r.sub || '';
      if (kind === 'cert' && r.days_left !== null && r.days_left !== undefined) {
        sub = (r.days_left < 0 ? pat('ran out {0} days ago', -r.days_left) : pat('{0} days left', r.days_left)) + (sub ? ' · ' + sub : '');
      }
      if (kind === 'event' && r.at && typeof stamp === 'function') sub = stamp(r.at) + (sub ? ' · ' + sub : '');
      out.push({kind: kind, key: key, label: r.name, sub: sub, data: true, remote: true,
                words: [r.sub || '', r.serial || '', r.owner || '', r.issuer || ''].join(' '),
                go: function () { remoteGo(kind, r); }});
    });
  });
  return out;
}
/* asked as one types (after a breath), never for a verb or a letter alone */
function remoteAsk() {
  if (!ST) return;
  clearTimeout(REMOTE.timer);
  var q = ST.input.value.trim();
  if (q.length < 2 || q.length > 100 || verbOf(q)) { ST.remote = null; ST.remoteBusy = false; return; }
  if (ST.remote && ST.remote.q === q) return;
  ST.remoteBusy = true;
  REMOTE.timer = setTimeout(function () {
    var my = ++REMOTE.ticket;
    var asked = window.ACME_CERTS && window.ACME_CERTS.api ? window.ACME_CERTS.api('search?q=' + encodeURIComponent(q))
      : api('search&q=' + encodeURIComponent(q));
    asked.then(function (d) {
      if (!ST || my !== REMOTE.ticket) return;
      ST.remote = {q: q, items: remoteItems(d && d.groups)};
      ST.remoteBusy = false;
      draw();
    }).catch(function () {
      if (!ST || my !== REMOTE.ticket) return;
      ST.remote = {q: q, items: []};
      ST.remoteBusy = false;
      draw();
    });
  }, 160);
}

/* ---- verbs: "renew web" - an action on the objects found ---------------------------------- */
var TYPE_OF ={cert: 'cert', target: 'target', agent: 'target', source: 'source', validation: 'validation', test: 'test', team: 'team', profile: 'reqprofile'};
var VERBS = [
  {words: ['renew', 'obnov', 'obnovit'], label: 'Renew', icon: 'refresh', kinds: ['cert'], may: function (o) { return manage() && !!o.issuer; },
   go: function (it) { var h = H(); if (h) h.certRenew(it.obj, null); }},
  {words: ['deploy', 'nasad', 'nasadit'], label: 'Deploy', icon: 'upload', kinds: ['cert'], may: function (o) { return manage() && Number(o.deploys) > 0; },
   go: function (it) { var h = H(); if (h) h.certDeploy(it.obj, null); }},
  {words: ['test', 'otestuj', 'otestovat'], label: 'Test', icon: 'play', kinds: ['target', 'agent', 'source', 'validation', 'test'], may: function () { return manage(); },
   go: function (it) { var h = H(); if (h) h.modTest(it.family, it.obj, null); }},
  {words: ['edit', 'uprav', 'upravit'], label: 'Edit', icon: 'edit', kinds: ['cert', 'target', 'agent', 'source', 'validation', 'test'], may: function (o, it) { return it.kind === 'cert' ? manage() : full(); },
   go: function (it) {
     var h = H();
     if (!h) return;
     if (it.kind === 'cert') capi('certs/one?id=' + it.obj.id).then(function (d) { h.certWizard(d.cert); }).catch(oops);
     else h.modEdit(it.family, it.obj);
   }},
  {words: ['clone', 'klonuj', 'klonovat', 'duplicate', 'duplikuj'], label: 'Clone', icon: 'copy', kinds: ['cert', 'target', 'agent', 'source', 'validation', 'test', 'team', 'profile'],
   may: function (o, it) { return it.kind === 'cert' ? manage() : full(); },
   go: function (it) {
     var t = window.ACME_CTX && window.ACME_CTX.types[{cert: 'cert', target: 'target', agent: 'target', source: 'source', validation: 'validation', test: 'test', team: 'team', profile: 'reqprofile'}[it.kind]];
     if (t && t.clone) Promise.resolve(t.clone(it.obj, {})).catch(oops);
   }},
  {words: ['history', 'historie', 'changes', 'zmeny'], label: 'History', icon: 'history', kinds: ['cert', 'target', 'agent', 'source', 'validation', 'test', 'team', 'profile'],
   may: function (o, it) { return !!(window.ACME_CTX && window.ACME_CTX.historyRef(TYPE_OF[it.kind], o)); },
   go: function (it) { var r = window.ACME_CTX.historyRef(TYPE_OF[it.kind], it.obj); if (r) window.acmeHistory.open(r.kind, r.id); }},
  {words: ['open', 'otevri', 'otevrit', 'show', 'ukaz'], label: 'Open', icon: 'eye', kinds: null, may: function () { return true; }, go: function (it) { it.go(); }}
];
function verbOf(q) {
  var m = /^(\S+)\s+(.*)$/.exec(q);
  if (!m) return null;
  var w = fold(m[1]);
  for (var i = 0; i < VERBS.length; i++) if (VERBS[i].words.indexOf(w) >= 0) return {verb: VERBS[i], rest: m[2]};
  return null;
}

/* ---- fuzzy: whole words first, then the start of a word, then letters in order inside one word
   (never across words: "ma" is not the m of "example" and the a of "alt") ------------------- */
function score(q, text) {
  if (!q) return 1;
  text = fold(text);
  var at = text.indexOf(q);
  if (at === 0) return 1000 - Math.min(200, text.length);
  if (at > 0) return (/[\s._\-/@:]/.test(text.charAt(at - 1)) ? 800 : 500) - Math.min(100, at);
  if (q.length < 2) return 0;
  var best = 0;
  text.split(/[\s,;\u0001]+/).forEach(function (tok) {
    if (!tok || tok.charAt(0) !== q.charAt(0)) return;
    var s = 0, ti = 1, run = 0;
    for (var i = 1; i < q.length; i++) {
      var f = tok.indexOf(q.charAt(i), ti);
      if (f < 0) return;
      run = f === ti ? run + 1 : 0;
      s += 10 + run * 8 + (/[._\-/@]/.test(tok.charAt(f - 1)) ? 10 : 0) - Math.min(6, f - ti);
      ti = f + 1;
    }
    best = Math.max(best, 150 + s - Math.min(60, tok.length));
  });
  return best;
}
function rank(items, q) {
  var words = fold(q).trim();
  if (!words) return items.slice();
  var parts = words.split(/\s+/);
  var got = [];
  items.forEach(function (it) {
    var main = it.data ? it.label : it.label + ' \u0001 ' + tr(it.label);
    var hay = [it.sub, it.data ? '' : tr(it.sub || ''), it.words || '', tr(KIND[it.kind][0]), it.about ? tr(it.about) : ''].join(' \u0001 ');
    var total = 0;
    for (var i = 0; i < parts.length; i++) {
      var s = Math.max(score(parts[i], main) * 1.5, score(parts[i], hay) * 0.8);
      if (!s) return;
      total += s;
    }
    got.push({it: it, s: total + (it.kind === 'action' ? 40 : 0) + (it.kind === 'pane' || it.kind === 'tab' ? 20 : 0)});
  });
  got.sort(function (a, b) { return b.s - a.s; });
  return got.map(function (x) { return x.it; });
}

/* ---- recent ---------------------------------------------------------------------------- */
function recentRead() { try { var v = JSON.parse(localStorage.getItem(RECENT_KEY) || '[]'); return Array.isArray(v) ? v.filter(function (x) { return x && typeof x.key === 'string'; }) : []; } catch (e) { return []; } }
function recentAdd(it) {
  try {
    var list = recentRead().filter(function (x) { return x.key !== it.key; });
    list.unshift({key: it.key});
    localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 8)));
  } catch (e) { }
}

/* ---- the panel ---------------------------------------------------------------------------- */
function iconTile(kind, size) {
  var k = KIND[kind] || KIND.action;
  var s = el('span', 'cxp-ic ' + k[2]);
  s.innerHTML = iconMarkup(k[1], size || 16);
  return s;
}
function open(initial) {
  if (ST) { ST.input.focus(); return; }
  if (typeof showTab !== 'function') return;
  var veil = el('div', 'cxp-veil');
  var box = el('div', 'cxp');
  box.setAttribute('role', 'dialog');
  box.setAttribute('aria-modal', 'true');
  box.setAttribute('aria-label', tr('Find and do anything'));
  var top = el('div', 'cxp-top');
  var si = el('span', 'cxp-search');
  si.innerHTML = iconMarkup('search', 18);
  top.appendChild(si);
  var input = el('input', 'cxp-in');
  input.type = 'text';
  input.setAttribute('role', 'combobox');
  input.setAttribute('aria-expanded', 'true');
  input.setAttribute('aria-controls', 'cxp-list');
  input.setAttribute('aria-autocomplete', 'list');
  input.setAttribute('aria-label', tr('Find and do anything'));
  input.placeholder = 'A certificate, a target, a setting - or “renew web”…';
  input.autocomplete = 'off';
  input.spellcheck = false;
  top.appendChild(input);
  var esc = noI18n(el('kbd', 'cxp-esc', 'Esc'));
  top.appendChild(esc);
  box.appendChild(top);
  var list = el('div', 'cxp-list');
  list.id = 'cxp-list';
  list.setAttribute('role', 'listbox');
  box.appendChild(list);
  var foot = el('div', 'cxp-foot');
  var hint = function (k, words) {
    var s = el('span', 'cxp-hint');
    k.forEach(function (x) { s.appendChild(noI18n(el('kbd', '', x))); });
    s.appendChild(el('span', '', words));
    foot.appendChild(s);
  };
  hint(['↑', '↓'], 'to move');
  hint(['Enter'], 'to open or do');
  hint(['Esc'], 'to close');
  var tip = el('span', 'cxp-tip', 'Type a verb first: renew, deploy, test, edit, clone, history');
  foot.appendChild(tip);
  box.appendChild(foot);
  veil.appendChild(box);
  document.body.appendChild(veil);
  ST = {veil: veil, box: box, input: input, list: list, at: 0, rows: [], items: [], back: document.activeElement, objs: null};
  veil.addEventListener('mousedown', function (e) { if (e.target === veil) close(); });
  input.addEventListener('input', function () { remoteAsk(); draw(); });
  input.addEventListener('keydown', function (e) {
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); move(e.key === 'ArrowDown' ? 1 : -1); }
    else if (e.key === 'PageDown' || e.key === 'PageUp') { e.preventDefault(); move(e.key === 'PageDown' ? 6 : -6); }
    else if (e.key === 'Enter') { e.preventDefault(); run(ST.at); }
    else if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'Tab') { e.preventDefault(); move(e.shiftKey ? -1 : 1); }
  });
  if (initial) input.value = initial;
  if (initial) remoteAsk();
  draw();
  setTimeout(function () { input.focus(); }, 0);
  objectItems().then(function (objs) { if (!ST) return; ST.objs = objs; draw(); });
}
function close() {
  if (!ST) return;
  var back = ST.back;
  ST.veil.remove();
  ST = null;
  if (back && back.isConnected && back.focus) { try { back.focus({preventScroll: true}); } catch (e) { } }
}
function move(d) {
  if (!ST || !ST.rows.length) return;
  ST.at = Math.max(0, Math.min(ST.rows.length - 1, ST.at + d));
  mark();
}
function mark() {
  ST.rows.forEach(function (r, i) { r.classList.toggle('on', i === ST.at); r.setAttribute('aria-selected', i === ST.at ? 'true' : 'false'); });
  var on = ST.rows[ST.at];
  if (on) { ST.input.setAttribute('aria-activedescendant', on.id); on.scrollIntoView({block: 'nearest'}); }
}
function run(i) {
  var it = ST && ST.items[i];
  if (!it) return;
  close();
  recentAdd(it.base || it);
  try { (it.act || it.go)(it.base || it); } catch (e) { oops(e); }
}
function draw() {
  if (!ST) return;
  var q = ST.input.value;
  var all = staticItems().concat(ST.objs || []);
  var byKey = {};
  all.forEach(function (it) { byKey[it.key] = it; });
  var groups = [];
  var v = verbOf(q.trim());
  if (!q.trim()) {
    var rec = recentRead().map(function (x) { return byKey[x.key]; }).filter(Boolean);
    if (rec.length) groups.push(['Recent', rec]);
    groups.push(['Go to', all.filter(function (x) { return x.kind === 'tab'; })]);
    groups.push(['Actions', all.filter(function (x) { return x.kind === 'action'; })]);
  } else if (v) {
    var cand = all.filter(function (x) { return !v.verb.kinds || v.verb.kinds.indexOf(x.kind) >= 0; });
    var found = rank(cand, v.rest).slice(0, 30).filter(function (x) { return x.obj || !v.verb.kinds; });
    groups.push([v.verb.label, found.map(function (x) {
      var ok = v.verb.may(x.obj || {}, x);
      return {kind: x.kind, key: x.key, label: x.label, sub: x.sub, data: x.data, verb: v.verb, off: !ok, base: x, act: v.verb.go};
    })]);
  } else {
    /* the server's finds (1.0.140) beside the page's own - an object once, the page's first */
    var far = (ST.remote && ST.remote.q === q.trim()) ? ST.remote.items.filter(function (x) { return !byKey[x.key]; }) : [];
    var ranked = rank(all.concat(far), q).slice(0, 60);
    var seen = {};
    ranked.forEach(function (x) { seen[x.key] = 1; });
    /* what the server found by what the page does not hold (a SAN, a serial, an event's words) */
    far.forEach(function (x) { if (!seen[x.key]) { ranked.push(x); seen[x.key] = 1; } });
    var order = ['action', 'cert', 'deploy', 'target', 'agent', 'team', 'profile', 'pane', 'tab', 'source', 'ca', 'validation', 'test',
                 'account', 'event'];
    var best = ranked.slice(0, 3);
    if (best.length) groups.push(['Best match', best]);
    order.forEach(function (k) {
      var g = ranked.slice(3).filter(function (x) { return x.kind === k; }).slice(0, 6);
      if (g.length) groups.push([({action: 'Actions', cert: 'Certificates', target: 'Targets', agent: 'Agents', team: 'Teams', profile: 'Request profiles',
                                   pane: 'Settings', tab: 'Pages', source: 'Sources', validation: 'Validations', test: 'Tests',
                                   deploy: 'Deployments', ca: 'Authorities', account: 'Accounts', event: 'Events'})[k], g]);
    });
  }
  clear(ST.list);
  ST.rows = [];
  ST.items = [];
  var n = 0;
  groups.forEach(function (g) {
    if (!g[1].length) return;
    var h = el('div', 'cxp-g', g[0]);
    h.setAttribute('role', 'presentation');
    ST.list.appendChild(h);
    g[1].forEach(function (it) {
      var r = el('div', 'cxp-row' + (it.off ? ' off' : ''));
      r.setAttribute('role', 'option');
      r.id = 'cxp-o' + n;
      if (it.off) r.setAttribute('aria-disabled', 'true');
      r.appendChild(iconTile(it.verb ? 'action' : it.kind));
      if (it.verb) r.querySelector('.cxp-ic').innerHTML = iconMarkup(it.verb.icon, 16);
      else if (it.icon && typeof ICONS === 'object' && ICONS[it.icon]) r.querySelector('.cxp-ic').innerHTML = iconMarkup(it.icon, 16);
      var w = el('div', 'cxp-w');
      var t = el('div', 'cxp-t');
      if (it.verb) {
        t.appendChild(el('span', 'cxp-verb', it.verb.label));
        t.appendChild(document.createTextNode(' '));
      }
      t.appendChild(it.data ? noI18n(el('span', '', it.label)) : el('span', '', it.label));
      w.appendChild(t);
      var sub = el('div', 'cxp-s');
      sub.appendChild(el('span', 'cxp-k', KIND[it.kind] ? KIND[it.kind][0] : ''));
      if (it.sub) { sub.appendChild(noI18n(el('span', 'cxp-dot', ' · '))); sub.appendChild(it.data || it.kind === 'cert' ? noI18n(el('span', '', it.sub)) : el('span', '', it.sub)); }
      if (it.off) { sub.appendChild(noI18n(el('span', 'cxp-dot', ' · '))); sub.appendChild(el('span', 'cxp-no', 'not possible here')); }
      w.appendChild(sub);
      r.appendChild(w);
      var go = noI18n(el('kbd', 'cxp-go', '↵'));
      r.appendChild(go);
      var i = n;
      r.addEventListener('mousemove', function () { if (ST && ST.at !== i) { ST.at = i; mark(); } });
      r.addEventListener('click', function () { if (!it.off) run(i); });
      ST.list.appendChild(r);
      ST.rows.push(r);
      ST.items.push(it.off ? null : it);
      n++;
    });
  });
  if (!n) {
    var e = el('div', 'cxp-none');
    e.appendChild(iconTile('action', 20));
    var still = !ST.objs || ST.remoteBusy;
    e.appendChild(el('b', '', still ? 'Looking…' : 'Nothing found'));
    if (!still) e.appendChild(el('span', 'muted small', 'Try fewer letters, or a verb first: renew, deploy, test, edit, clone, history.'));
    ST.list.appendChild(e);
  } else if (ST.remoteBusy) {
    /* the server is still being asked (1.0.140): said under what is found already */
    var wb = el('div', 'cxp-busy');
    wb.setAttribute('role', 'presentation');
    wb.appendChild(el('span', 'cxp-spin'));
    wb.appendChild(el('span', '', 'Searching every certificate, deployment and event…'));
    ST.list.appendChild(wb);
  }
  ST.at = Math.min(ST.at, Math.max(0, n - 1));
  if (q !== ST.lastQ) { ST.at = 0; ST.lastQ = q; }
  while (ST.at < n - 1 && !ST.items[ST.at]) ST.at++;
  mark();
}

document.addEventListener('keydown', function (e) {
  if (!(e.ctrlKey || e.metaKey) || e.altKey || e.shiftKey || String(e.key).toLowerCase() !== 'k') return;
  if (typeof showTab !== 'function' || !document.querySelector('.tabs')) return;
  var t = e.target;
  if (t && t.closest && t.closest('[contenteditable="true"], .gd-editor')) return;
  e.preventDefault();
  if (ST) close(); else open();
});
/* the button in the header, where the page has one (none needed: the keys always work) */
P.hint = (MAC ? '⌘' : 'Ctrl') + '+K';
P.refresh = function () { CACHE.items = null; };
/* A search box in the header (1.0.140) for those who reach for the mouse: it opens the palette
   (what is typed into it goes with it). Only on the administration's own page. */
function headerBox() {
  var head = document.querySelector('body > .wrap > header');
  if (!head || head.querySelector('.hsearch') || !document.querySelector('.tabs [role="tab"]')) return;
  var b = el('button', 'hsearch');
  b.type = 'button';
  b.id = 'hsearch';
  b.setAttribute('aria-label', tr('Find anything') + ' (' + P.hint + ')');
  b.setAttribute('aria-haspopup', 'dialog');
  b.title = pat('Certificates by name, SAN or serial, targets, agents, teams, settings, events - and actions. Also {0}.', P.hint);
  var i = el('span', 'hsearch-ic');
  i.innerHTML = iconMarkup('search', 16);
  b.appendChild(i);
  b.appendChild(el('span', 'hsearch-w', 'Find anything…'));
  var k = noI18n(el('kbd', 'hsearch-k', P.hint.replace('+', ' ')));
  b.appendChild(k);
  b.onclick = function () { open(); };
  var row = head.querySelector('.btnrow');
  head.insertBefore(b, row || null);
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', headerBox); else headerBox();
}());
