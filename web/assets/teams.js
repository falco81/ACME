/* teams.js - Settings → Owners and teams (docs/teams.md): the owners of
   certificates as an organisation (1.0.125) - a tree of units, teams and persons,
   their members with roles, their limits, devices, certificates and activity; the
   roles' capability matrix, the access check, teams from directory groups - and the
   tags, from GET /api/teams, changed through acmelib/certs/api_teams.py. The
   pane's markup is a host in admin/certs-ui.php (<div id="teams-host">), the two
   settings of who sees what are drawn by admin.js into <div id="sect-teams">.

   It also gives the rest of the page what picks from the catalogs instead of
   free text (window.ACME_TEAMS):
     ownerPicker(value)   a select of the owners this account may give (+ nobody);
                          an owner not defined is kept, marked, with "Make it an owner"
     tagPicker(list)      chips of the tags chosen, and a select to add one
     tagChip(name)        one tag in its colour; not in the catalog: marked
     fillFilters()        the owner and tag selects above the list of certificates
   Both pickers answer .value (the owner; the tags with spaces between) and _get().
   Every popup is the page's own (modal, confirmThen) - never one of the browser's.
   A full administrator changes; anybody signed in sees. */
'use strict';
(function () {
  var TM = {d: null, asking: null, users: null};
  var RIGHT_WORDS = {view: 'see', request: 'ask for new', manage: 'manage', approve: 'approve'};
  var RIGHT_SAYS = {
    view: 'Sees the team\'s certificates - in the list, on the portal - and downloads them there.',
    request: 'Asks for new certificates owned by the team (the portal, or the wizard). Sees them too.',
    manage: 'Edits, renews, deploys, exports and revokes the team\'s certificates; makes new ones for it.',
    approve: 'Approves or declines what is asked for on the portal for the team.'
  };
  var KIND_WORDS = {local: 'account of acme', user: 'directory user', group: 'directory group'};

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function call(what, body) { return api(what, body); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function cell(cls, child) {
    var td = el('td', cls || '');
    if (child instanceof Node) td.appendChild(child);
    else if (child !== undefined && child !== null) td.textContent = String(child);
    return td;
  }
  function low(s) { return String(s || '').trim().toLowerCase(); }

  function load(force) {
    if (TM.d && !force) return Promise.resolve(TM.d);
    if (TM.asking && !force) return TM.asking;
    TM.asking = call('teams').then(function (d) { TM.d = d || {}; TM.asking = null; return TM.d; },
      function (e) { TM.asking = null; throw e; });
    return TM.asking;
  }
  function teamOf(name) {
    return ((TM.d || {}).teams || []).filter(function (t) { return low(t.name) === low(name); })[0] || null;
  }
  function tagOf(name) {
    return ((TM.d || {}).tags || []).filter(function (t) { return low(t.name) === low(name); })[0] || null;
  }
  /* Whatever else on the page shows an owner or a tag drawn again after a change. */
  function changed() {
    return load(true).then(function () {
      fillFilters();
      var ct = window.ACME_CERTS;   /* certs.js's CT (window.CT is never set) */
      if (ct && typeof ct.refresh === 'function') { try { ct.refresh(); } catch (e) { } }
    });
  }

  /* ---- one tag, one owner --------------------------------------------------- */
  /* A tag's colour as its class: the first six acme.css's own, the others teams.css's. */
  var OWN_COLOURS = ['dim', 'info', 'ok', 'warn', 'crit', 'violet'];
  var COLOUR_WORDS = {dim: 'grey', info: 'blue', ok: 'green', warn: 'yellow', crit: 'red', violet: 'violet',
                      teal: 'teal', cyan: 'cyan', indigo: 'indigo', pink: 'pink', rose: 'rose', orange: 'orange',
                      amber: 'amber', lime: 'lime', brown: 'brown', slate: 'slate'};
  function colourClass(c) {
    c = String(c || 'dim');
    return OWN_COLOURS.indexOf(c) >= 0 ? c : 'tc-' + c.replace(/[^a-z]/g, '');
  }
  /* The colour picked from the tags themselves: a button showing the tag in its
     colour, and a panel of the tag in every colour under it. .value as a select. */
  function colourPicker(colours, now, nameOf) {
    var wrap = el('div', 'tm-cpick');
    var btn = el('button', 'tm-cpick-btn');
    btn.type = 'button';
    /* The panel floats over the page (as the search boxes' lists, core.js):
       inside the popup it was cut by the popup's own edge. */
    var panel = el('div', 'tm-cpick-panel qs-float');
    panel.hidden = true;
    wrap.appendChild(btn);
    var place = function () {
      var r = btn.getBoundingClientRect();
      var w = Math.min(520, window.innerWidth - 16);
      panel.style.width = w + 'px';
      panel.style.left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8)) + 'px';
      var below = window.innerHeight - r.bottom - 12;
      panel.style.maxHeight = Math.max(160, Math.max(below, r.top - 12)) + 'px';
      if (below < 220 && r.top > below) { panel.style.top = ''; panel.style.bottom = (window.innerHeight - r.top + 6) + 'px'; }
      else { panel.style.bottom = ''; panel.style.top = (r.bottom + 6) + 'px'; }
    };
    var shut = function () { panel.hidden = true; if (panel.parentNode) panel.parentNode.removeChild(panel); };
    var open = function () {
      document.body.appendChild(panel);
      panel.hidden = false;
      place();
    };
    wrap.value = colours.indexOf(now) >= 0 ? now : 'dim';
    var chip = function (c) {
      return data('span', 'tag ' + colourClass(c), nameOf() || 'tag');
    };
    var paint = function () {
      clear(btn);
      btn.appendChild(chip(wrap.value));
      btn.appendChild(el('span', 'tm-cpick-w', COLOUR_WORDS[wrap.value] || wrap.value));
      btn.appendChild(el('span', 'tm-cpick-caret', '▾'));
      clear(panel);
      colours.forEach(function (c) {
        var o = el('button', 'tm-cpick-opt' + (c === wrap.value ? ' on' : ''));
        o.type = 'button';
        o.appendChild(chip(c));
        o.appendChild(el('span', 'tm-cpick-w', COLOUR_WORDS[c] || c));
        o.onclick = function () {
          wrap.value = c;
          shut();
          paint();
          wrap.dispatchEvent(new Event('change', {bubbles: true}));
          btn.focus();
        };
        panel.appendChild(o);
      });
    };
    btn.onclick = function () {
      if (!panel.hidden) { shut(); return; }
      open();
      var on = panel.querySelector('.on') || panel.firstChild;
      if (on) on.focus();
    };
    var keys = function (e) {
      if (e.key === 'Escape' && !panel.hidden) { e.stopPropagation(); e.preventDefault(); shut(); btn.focus(); }
      if (!panel.hidden && /^Arrow/.test(e.key)) {
        var opts = Array.prototype.slice.call(panel.querySelectorAll('.tm-cpick-opt'));
        var at = opts.indexOf(document.activeElement);
        var cols = Math.max(1, Math.round(panel.clientWidth / ((opts[0] && opts[0].offsetWidth) || 1)));
        var step = {ArrowRight: 1, ArrowLeft: -1, ArrowDown: cols, ArrowUp: -cols}[e.key];
        var to = opts[Math.max(0, Math.min(opts.length - 1, (at < 0 ? 0 : at) + step))];
        if (to) { e.preventDefault(); to.focus(); }
      }
    };
    wrap.addEventListener('keydown', keys);
    panel.addEventListener('keydown', keys);
    document.addEventListener('mousedown', function (e) { if (!wrap.contains(e.target) && !panel.contains(e.target)) shut(); });
    window.addEventListener('resize', function () { if (!panel.hidden) place(); });
    document.addEventListener('scroll', function () { if (!panel.hidden) place(); }, true);
    wrap._repaint = paint;
    paint();
    return wrap;
  }
  function tagChip(name) {
    var t = tagOf(name);
    var c = data('span', 'tag ' + (t ? colourClass(t.colour) : 'dim tm-undef') + ' ct-tagchip', name);
    if (t && t.description) c.title = t.description;
    if (!t && TM.d) c.title = tr('not defined - Settings → Owners and teams');
    return c;
  }
  function ownerChip(name) {
    var t = teamOf(name);
    var c = data('span', 'tag ' + (t ? 'info' : 'dim tm-undef') + ' tm-owner', name);
    if (!t && TM.d) c.title = tr('not defined - Settings → Owners and teams');
    else if (t && t.contact_mail) c.title = t.contact_mail;
    return c;
  }

  /* ---- the owner picker ----------------------------------------------------- */
  function ownerPicker(value) {
    var wrap = el('div', 'tm-pick');
    var sel = el('select', 'tm-owner-sel');
    noI18n(sel);
    wrap.appendChild(sel);
    var undef = el('div', 'tm-undef-line');
    wrap.appendChild(undef);
    var cur = String(value || '').trim();
    var fill = function () {
      var d = TM.d || {};
      var keep = sel.options.length ? sel.value : cur;
      clear(sel);
      var add = function (v, words, cls) {
        var o = el('option', cls || '', words);
        o.value = v;
        sel.appendChild(o);
        return o;
      };
      if (d.unowned_ok !== false || !cur) {
        var none = add('', tr('nobody'));
        if (d.unowned_ok === false) { none.disabled = true; none.textContent = tr('choose an owner'); }
      }
      var may = d.choosable || [];
      (d.teams || []).forEach(function (t) {
        if (may.indexOf(t.name) < 0 && low(t.name) !== low(cur)) return;
        add(t.name, t.name + (t.kind === 'person' ? ' · ' + tr('person') : ''));
      });
      if (cur && !teamOf(cur)) add(cur, cur + ' - ' + tr('not defined'), 'tm-undef');
      sel.value = keep;
      if (sel.value !== keep) sel.value = cur;
      /* an owner written in other letters than its team ("web" of the team Web, as the API
         and the command line take it): that team chosen - the box showed "nobody", and the
         owner was dropped when only the note was saved (hunt Rt4) */
      if (sel.value !== keep && sel.value !== cur) {
        var same = teamOf(keep) || teamOf(cur);
        if (same) sel.value = same.name;
      }
      paintUndef();
    };
    var paintUndef = function () {
      clear(undef);
      var v = sel.value;
      if (!v || teamOf(v) || !TM.d) return;
      undef.appendChild(el('span', 'muted small', 'Not defined - typed as text before. '));
      if (full()) {
        var mk = cmdButton('Make it an owner', 'add', 'small');
        mk.classList.add('tm-adopt-owner');
        mk.onclick = function () {
          busy(mk, true);
          call('teams/adopt', {owner: v}).then(function (r) {
            toast(r.message || 'made', 'good');
            cur = r.team || v;
            return changed();
          }).then(fill).catch(oops).then(function () { busy(mk, false); });
        };
        undef.appendChild(mk);
      }
    };
    sel.addEventListener('change', paintUndef);
    Object.defineProperty(wrap, 'value', {get: function () { return sel.value; },
                                          set: function (v) { cur = String(v || ''); fill(); }});
    wrap._get = function () { return sel.value; };
    wrap._select = sel;
    fill();
    load().then(fill).catch(function () { });
    return wrap;
  }

  /* ---- the tag picker ------------------------------------------------------- */
  function tagPicker(list) {
    var chosen = (Array.isArray(list) ? list : String(list || '').split(/[\s,;]+/))
      .map(function (x) { return String(x).trim(); }).filter(Boolean);
    var wrap = el('div', 'tm-pick tm-tags');
    var chips = el('div', 'chips tm-chips');
    var sel = el('select', 'tm-tag-add');
    noI18n(sel);
    wrap.appendChild(chips);
    wrap.appendChild(sel);
    var draw = function () {
      clear(chips);
      if (!chosen.length) chips.appendChild(el('span', 'muted small', tr('No tag.')));
      chosen.forEach(function (n) {
        var c = el('span', 'tm-chip');
        c.appendChild(tagChip(n));
        if (!tagOf(n) && TM.d && full()) {
          var def = iconButton('add', 'Define this tag');
          def.classList.add('tm-define');
          def.onclick = function () {
            call('teams/adopt', {tag: n}).then(function (r) { toast(r.message || 'made', 'good'); return changed(); })
              .then(draw).catch(oops);
          };
          c.appendChild(def);
        }
        var x = iconButton('close', 'Take it off');
        x.onclick = function () { chosen = chosen.filter(function (v) { return v !== n; }); draw(); };
        c.appendChild(x);
        chips.appendChild(c);
      });
      clear(sel);
      var first = el('option', '', tr('add a tag…'));
      first.value = '';
      sel.appendChild(first);
      ((TM.d || {}).tags || []).forEach(function (t) {
        if (chosen.some(function (v) { return low(v) === low(t.name); })) return;
        var o = el('option', '', t.name + (t.description ? ' - ' + t.description : ''));
        o.value = t.name;
        sel.appendChild(o);
      });
      sel.disabled = sel.options.length < 2;
      if (sel.disabled) first.textContent = TM.d && !((TM.d.tags || []).length)
        ? tr('no tags defined - Settings → Owners and teams') : tr('every tag is on');
    };
    sel.onchange = function () {
      if (sel.value) chosen.push(sel.value);
      draw();
    };
    Object.defineProperty(wrap, 'value', {get: function () { return chosen.join(' '); }});
    wrap._get = function () { return chosen.slice(); };
    draw();
    load().then(draw).catch(function () { });
    return wrap;
  }

  /* ---- the filters above the list of certificates --------------------------- */
  function fillFilters() {
    var o = $('ct-owner'), t = $('ct-tag');
    if (!o && !t) return;
    load().then(function (d) {
      [[o, d.teams || [], 'every owner'], [t, d.tags || [], 'every tag']].forEach(function (x) {
        var sel = x[0];
        if (!sel) return;
        var keep = sel.value;
        clear(sel);
        var any = el('option', '', x[2]);
        any.value = '';
        sel.appendChild(any);
        x[1].forEach(function (r) {
          var op = data('option', '', r.name);
          op.value = r.name;
          sel.appendChild(op);
        });
        sel.value = keep;
        sel.hidden = !x[1].length && !keep;
      });
    }).catch(function () { });
  }

  /* ==== the pane: an organisation (1.0.125, docs/teams.md "Enterprise teams") ==========
     Four views over GET /api/teams: the organisation (the tree of teams on the left, the
     team's page on the right), the roles (a matrix of capabilities), the access check and
     the tags. Everything is drawn from what the daemon says; a full administrator changes,
     a certificate administrator also checks access and previews teams from directory
     groups, a reader sees all of it without a single control that changes something. */
  var UI = {view: 'org', team: null, tab: 'overview', open: {}, q: '', below: false,
            targets: null, cats: null, counts: {}, drawer: false, opened: false};
  var VIEWS = [['org', 'Organisation', 'tm_tree'], ['roles', 'Roles', 'tm_grid'],
               ['access', 'Access check', 'tm_check'], ['tags', 'Tags', 'tm_tag'],
               /* governance (1.0.138) */
               ['whomay', 'Who may', 'tmg_who'], ['health', 'Health', 'tmg_heart'],
               ['gov', 'Requests', 'tmg_inbox'], ['templates', 'Templates', 'tmg_tpl']];
  var TABS = [['overview', 'Overview', 'chart'], ['members', 'Members', 'people'],
              ['limits', 'Limits', 'shield'], ['devices', 'Devices', 'router'],
              ['certs', 'Certificates', 'lock'], ['activity', 'Activity', 'history'],
              ['gov', 'Governance', 'tmg_gov']];
  var KIND_ICON = {unit: 'tm_unit', team: 'people', person: 'person'};
  var KIND_NAME = {unit: 'unit', team: 'team', person: 'person'};
  var WHO_ICON = {user: 'person', group: 'people', local: 'key'};
  var ROW_H = 38;

  /* A few marks of the pane's own, beside the page's (core.js ICONS). */
  if (typeof ICONS === 'object') {
    ICONS.tm_unit = '<path d="M4 21V6.5L12 3l8 3.5V21"/><path d="M9 21v-4h6v4"/><path d="M8 9h.01M12 9h.01M16 9h.01M8 13h.01M12 13h.01M16 13h.01"/>';
    ICONS.tm_tree = '<rect x="9" y="3" width="6" height="5" rx="1.2"/><rect x="3" y="16" width="6" height="5" rx="1.2"/><rect x="15" y="16" width="6" height="5" rx="1.2"/><path d="M12 8v4M6 16v-2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2"/>';
    ICONS.tm_grid = '<rect x="3" y="3" width="18" height="18" rx="2.5"/><path d="M3 9h18M9 3v18"/><path d="M12.5 14.5l1.5 1.5 3-3"/>';
    ICONS.tm_check = '<circle cx="10" cy="8" r="3.5"/><path d="M3.5 20c0-3.5 2.9-5.5 6.5-5.5 1.2 0 2.3.2 3.2.6"/><path d="M15 18l2 2 4-4.5"/>';
    ICONS.tm_tag = '<path d="M3 12V4a1 1 0 0 1 1-1h8l9 9-9 9z"/><circle cx="7.5" cy="7.5" r="1.5"/>';
    ICONS.tm_move = '<path d="M5 12h14"/><path d="M15 8l4 4-4 4"/><path d="M5 5v14"/>';
    ICONS.tm_dir = '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="11" r="2.5"/><path d="M5.5 17c.6-1.8 2-2.7 3.5-2.7s2.9.9 3.5 2.7"/><path d="M15 9.5h3.5M15 13h3.5"/>';
    ICONS.tm_plus = '<path d="M12 5v14M5 12h14"/>';
    ICONS.tm_expand = '<path d="M7 9l5-5 5 5"/><path d="M7 15l5 5 5-5"/>';
    ICONS.tm_collapse = '<path d="M7 4l5 5 5-5"/><path d="M7 20l5-5 5 5"/>';
    ICONS.tm_menu = '<path d="M4 7h16M4 12h16M4 17h10"/>';
    ICONS.tm_copy = ICONS.copy;
  }
  function ic(key, size, cls) {
    var s = el('span', 'tmx-ic' + (cls ? ' ' + cls : ''));
    s.innerHTML = iconMarkup(key, size || 16);
    return s;
  }
  function role() { return (typeof ME === 'object' && ME && ME.role) || 'readonly'; }
  function writes() { return full() && !!(TM.d && TM.d.can_change !== false); }
  function checks() { return role() === 'fulladmin' || role() === 'certadmin'; }
  function dirs() { return (typeof SETTINGS === 'object' && SETTINGS && SETTINGS.directories) || []; }
  function fold(s) {
    s = String(s || '').toLowerCase();
    try { s = s.normalize('NFD').replace(/[\u0300-\u036f]/g, ''); } catch (e) { }
    return s;
  }
  function keep() {
    try { localStorage.setItem('acme.teams.ui', JSON.stringify({view: UI.view, team: UI.team, tab: UI.tab, open: UI.open})); } catch (e) { }
  }
  function kept() {
    try {
      var k = JSON.parse(localStorage.getItem('acme.teams.ui') || '{}') || {};
      if (k.view) UI.view = k.view;
      if (k.team) UI.team = k.team;
      if (k.tab) UI.tab = k.tab;
      if (k.open && typeof k.open === 'object') UI.open = k.open;
    } catch (e) { }
  }
  function enc(v) { return encodeURIComponent(String(v === undefined || v === null ? '' : v)); }
  /* the words that change with the number, in the page's language */
  function nw(n, words) { return el('span', '', num(n) + ' ' + words); }
  function daysTo(ts) { return Math.ceil((Number(ts) - Date.now() / 1000) / 86400); }
  function dateOf(ts) {
    if (!ts) return '';
    var d = new Date(Number(ts) * 1000);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  }
  function initials(who) {
    var w = String(who || '').replace(/^(local|group):/i, '').replace(/^cn=/i, '').split(/,/)[0];
    w = w.replace(/@.*$/, '');
    var parts = w.split(/[\s._-]+/).filter(Boolean);
    if (parts.length > 1) return (parts[0][0] + parts[1][0]).toUpperCase();
    return (w.slice(0, 2) || '?').toUpperCase();
  }
  function hue(s) {
    var h = 0;
    s = String(s || '');
    for (var i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) >>> 0;
    return h % 6;
  }
  function avatar(who, kind) {
    var a = el('span', 'tmx-av tmx-av-' + hue(who) + (kind === 'group' ? ' grp' : ''));
    if (kind === 'group') a.innerHTML = iconMarkup('people', 15);
    else a.appendChild(data('span', '', initials(who)));
    return a;
  }
  function kindBadge(kind, size) {
    var k = KIND_ICON[kind] ? kind : 'team';
    return ic(KIND_ICON[k], size || 15, 'tmx-kind k-' + k);
  }
  function chip(words, cls, icon) {
    var c = el('span', 'tmx-chip' + (cls ? ' ' + cls : ''));
    if (icon) c.appendChild(ic(icon, 13));
    if (words instanceof Node) c.appendChild(words); else c.appendChild(el('span', '', words));
    return c;
  }
  function dataChip(words, cls, icon) { return chip(data('span', '', words), cls, icon); }
  function empty(icon, title, words, button) {
    var b = el('div', 'tmx-empty');
    b.appendChild(ic(icon, 30));
    b.appendChild(el('b', '', title));
    if (words) b.appendChild(el('span', '', words));
    if (button) b.appendChild(button);
    return b;
  }
  function asking() { return el('div', 'tmx-asking', 'Asking…'); }
  function fade(n) { n.classList.add('tmx-fade'); return n; }

  /* ---- the organisation, as a tree --------------------------------------------- */
  function tree() {
    var d = TM.d || {}, nodes = {}, tops = [];
    (d.teams || []).forEach(function (t) {
      nodes[low(t.name)] = {name: t.name, key: low(t.name), kind: t.kind || 'team', parent: t.parent || null,
                            desc: t.description || '', t: t, kids: [], certs: Number(t.used || 0),
                            members: (t.members || []).length, devices: 0};
    });
    var own = {};
    (UI.targets || []).forEach(function (r) { if (r.owner) own[low(r.owner)] = (own[low(r.owner)] || 0) + 1; });
    Object.keys(nodes).forEach(function (k) {
      var n = nodes[k];
      n.devices = own[k] || 0;
      var p = n.parent && nodes[low(n.parent)];
      if (p && p !== n) p.kids.push(n); else { n.parent = null; tops.push(n); }
    });
    var byName = function (a, b) { return a.name.localeCompare(b.name, undefined, {sensitivity: 'base', numeric: true}); };
    var order = [];
    var walk = function (n, depth, seen) {
      if (seen[n.key]) return;
      seen[n.key] = 1;
      n.depth = depth;
      order.push(n);
      n.kids.sort(byName);
      n.all = n.certs;
      n.below = 0;
      n.kids.forEach(function (c) { walk(c, depth + 1, seen); n.all += c.all; n.below += 1 + c.below; });
    };
    tops.sort(byName);
    var seen = {};
    tops.forEach(function (n) { walk(n, 0, seen); });
    return {nodes: nodes, tops: tops, order: order};
  }
  function chainOf(T, name) {
    var out = [], n = T.nodes[low(name)], guard = 0;
    while (n && guard++ < 200) { out.unshift(n); n = n.parent ? T.nodes[low(n.parent)] : null; }
    return out;
  }
  function below(T, name) {
    var out = {}, n = T.nodes[low(name)];
    var go = function (x) { x.kids.forEach(function (c) { out[c.key] = 1; go(c); }); };
    if (n) go(n);
    return out;
  }

  /* ---- the pane ------------------------------------------------------------------- */
  function drawPane() {
    var host = $('teams-host');
    if (!host) return;
    if (!UI.opened) { kept(); UI.opened = true; }
    if (!host.firstChild) host.appendChild(asking());
    Promise.all([load(true), targetsLoad()]).then(function (x) {
      var d = x[0];
      clear(host);
      var box = el('div', 'tmx');
      box.id = 'tmx';
      host.appendChild(box);
      if (!checks() && (UI.view === 'access' || UI.view === 'whomay')) UI.view = 'org';
      box.appendChild(viewBar(d));
      var body = el('div', 'tmx-view');
      body.id = 'tmx-view';
      box.appendChild(body);
      drawView();
      fillFilters();
    }).catch(function (e) { clear(host); oops(e); });
  }
  function targetsLoad() {
    return api('targets').then(function (d) { UI.targets = (d && d.rows) || []; return UI.targets; })
      .catch(function () { UI.targets = UI.targets || []; return UI.targets; });
  }
  function refresh(name) {
    if (name !== undefined) UI.team = name;
    UI.counts = {};
    return changed().then(drawPane);
  }
  function viewBar(d) {
    var bar = el('div', 'tmx-bar');
    var seg = el('div', 'tmx-views');
    seg.setAttribute('role', 'tablist');
    VIEWS.forEach(function (v) {
      if ((v[0] === 'access' || v[0] === 'whomay') && !checks()) return;
      if (v[0] === 'templates' && !fullAdmin()) return;     /* members may be in them (1.0.138) */
      var b = el('button', 'tmx-vbtn' + (UI.view === v[0] ? ' on' : ''));
      b.type = 'button';
      b.dataset.view = v[0];
      b.setAttribute('role', 'tab');
      b.appendChild(ic(v[2], 16));
      b.appendChild(el('span', '', v[1]));
      var n = v[0] === 'org' ? (d.teams || []).length : v[0] === 'roles' ? (d.roles || []).length
        : v[0] === 'tags' ? (d.tags || []).length : null;
      if (n !== null) b.appendChild(data('span', 'tmx-n', num(n)));
      b.onclick = function () {
        UI.view = v[0];
        keep();
        seg.querySelectorAll('.tmx-vbtn').forEach(function (x) { x.classList.toggle('on', x === b); });
        drawView();
      };
      seg.appendChild(b);
    });
    bar.appendChild(seg);
    var right = el('div', 'tmx-bar-r');
    if (checks() && dirs().length) {
      var fg = cmdButton('From directory groups', 'tm_dir', 'small');
      fg.id = 'tmx-fromgroups';
      fg.onclick = fromGroups;
      right.appendChild(fg);
    }
    bar.appendChild(right);
    return bar;
  }
  function drawView() {
    var body = $('tmx-view');
    if (!body) return;
    clear(body);
    var d = TM.d || {};
    if (UI.view === 'roles') body.appendChild(fade(rolesView(d)));
    else if (UI.view === 'access') body.appendChild(fade(accessView()));
    else if (UI.view === 'whomay') body.appendChild(fade(whomayView()));
    else if (UI.view === 'health') body.appendChild(fade(healthView()));
    else if (UI.view === 'gov') body.appendChild(fade(govView()));
    else if (UI.view === 'templates') body.appendChild(fade(templatesView()));
    else if (UI.view === 'tags') {
      var tg = fade(el('div', 'tmx-tags'));
      tg.appendChild(tagsCard(d));
      var lg = d.legacy || {};
      if ((lg.owners || []).length || (lg.tags || []).length) tg.appendChild(legacyCard(lg));
      body.appendChild(tg);
    } else body.appendChild(orgView(d));
    if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(body); } catch (e) { } }
  }

  /* ---- the organisation view ------------------------------------------------------ */
  function orgView(d) {
    var T = tree();
    UI.T = T;
    var wrap = el('div', 'tmx-org' + (UI.drawer ? ' drawer-open' : ''));
    wrap.id = 'tmx-org';
    var warn = portalWarning(d);
    if (warn) wrap.appendChild(warn);
    if (!T.order.length) {
      var add = writes() ? cmdButton('Add the first team', 'add', 'primary') : null;
      if (add) { add.id = 'tmx-first'; add.onclick = function () { editTeam(null, {kind: 'team'}); }; }
      wrap.appendChild(empty('tm_tree', 'No team yet', 'Teams own certificates and devices; their members - accounts of acme, users and groups of the directory - see and do with them what their roles give. Arrange them in a tree: regions and sites as units, teams below them.', add));
      return wrap;
    }
    if (!UI.team || !T.nodes[low(UI.team)]) UI.team = T.order[0].name;
    /* the first time: the top two levels unfolded */
    if (!UI.folded) { UI.folded = true; if (!Object.keys(UI.open).length) T.order.forEach(function (n) { if (n.depth < 2 && n.kids.length) UI.open[n.key] = true; }); }
    chainOf(T, UI.team).slice(0, -1).forEach(function (n) { UI.open[n.key] = true; });
    /* the phone's way to the tree: the team chosen, and a drawer */
    var sw = el('button', 'tmx-switch');
    sw.type = 'button';
    sw.id = 'tmx-switch';
    var cur = T.nodes[low(UI.team)];
    sw.appendChild(kindBadge(cur.kind, 18));
    var sws = el('span', 'tmx-switch-w');
    sws.appendChild(data('b', '', cur.name));
    sws.appendChild(data('span', 'tmx-switch-p', chainOf(T, cur.name).slice(0, -1).map(function (n) { return n.name; }).join(' › ')));
    sw.appendChild(sws);
    sw.appendChild(ic('tm_menu', 18, 'tmx-switch-c'));
    sw.onclick = function () { drawer(true); };
    wrap.appendChild(sw);
    var grid = el('div', 'tmx-grid');
    grid.appendChild(treeCard(T));
    var page = el('div', 'tmx-page');
    page.id = 'tmx-page';
    grid.appendChild(page);
    wrap.appendChild(grid);
    var shade = el('div', 'tmx-shade');
    shade.onclick = function () { drawer(false); };
    wrap.appendChild(shade);
    teamPage(page, T, T.nodes[low(UI.team)]);
    return wrap;
  }
  function drawer(on) {
    UI.drawer = !!on;
    var o = $('tmx-org');
    if (o) o.classList.toggle('drawer-open', UI.drawer);
    if (on) { var q = $('tmx-q'); if (q) setTimeout(function () { q.focus(); }, 50); }
  }
  function portalWarning(d) {
    if (d.portal && (!d.portal.on || !d.portal.certs)) {
      var off = el('div', 'tmx-note warn tm-portal-off');
      off.appendChild(ic('info', 18));
      off.appendChild(el('span', '', !d.portal.on
        ? 'The enrolment pages are switched off: the members see nothing there.'
        : 'Certificates on the portal is off: the members sign in on the enrolment pages and see nothing there - no certificate of their teams, no asking for one.'));
      var go = cmdButton('Open the setting', 'gear', 'small');
      go.onclick = function () { location.hash = '#settings/portal'; };
      off.appendChild(go);
      return off;
    }
    return null;
  }

  /* the tree card: search, fold, the rows (only those shown are drawn - 2000 teams stay quick) */
  function treeCard(T) {
    var card = el('div', 'tmx-tree');
    card.id = 'tmx-tree';
    var head = el('div', 'tmx-tree-h');
    var title = el('div', 'tmx-tree-t');
    title.appendChild(ic('tm_tree', 16));
    title.appendChild(el('b', '', 'Organisation'));
    var units = T.order.filter(function (n) { return n.kind === 'unit'; }).length;
    var counts = el('span', 'tmx-tree-n');
    counts.appendChild(nw(T.order.length - units, T.order.length - units === 1 ? 'team' : 'teams'));
    if (units) { counts.appendChild(document.createTextNode(' · ')); counts.appendChild(nw(units, units === 1 ? 'unit' : 'units')); }
    title.appendChild(counts);
    var x = iconButton('close', 'Close');
    x.classList.add('tmx-drawer-x');
    x.onclick = function () { drawer(false); };
    title.appendChild(x);
    head.appendChild(title);
    var find = el('div', 'tmx-find');
    find.appendChild(ic('search', 15));
    var q = el('input', 'tmx-q');
    q.type = 'search';
    q.id = 'tmx-q';
    q.placeholder = tr('Find a team…');
    q.setAttribute('aria-label', q.placeholder);   /* a box kept as typed: named in the page's language (1.0.143) */
    q.autocomplete = 'off';
    q.value = UI.q;
    noI18n(q);
    find.appendChild(q);
    head.appendChild(find);
    var tools = el('div', 'tmx-tree-tools');
    var ex = iconButton('tm_expand', 'Unfold everything');
    ex.id = 'tmx-expand';
    ex.onclick = function () { T.order.forEach(function (n) { if (n.kids.length) UI.open[n.key] = true; }); keep(); paint(); };
    var co = iconButton('tm_collapse', 'Fold everything');
    co.id = 'tmx-collapse';
    co.onclick = function () { UI.open = {}; chainOf(T, UI.team).slice(0, -1).forEach(function (n) { UI.open[n.key] = true; }); keep(); paint(); };
    tools.appendChild(ex);
    tools.appendChild(co);
    if (writes()) {
      var at = T.nodes[low(UI.team)];
      var addT = cmdButton('New team', 'tm_plus', 'small');
      addT.id = 'tmx-add-team';
      explain(addT, at ? 'A new team under {0}'.replace('{0}', at.name) : 'A new team');
      addT.onclick = function () { editTeam(null, {kind: 'team', parent: UI.team || ''}); };
      var addU = cmdButton('New unit', 'tm_plus', 'small');
      addU.id = 'tmx-add-unit';
      explain(addU, at ? 'A new unit (a region, a site) under {0}'.replace('{0}', at.name) : 'A new unit');
      addU.onclick = function () { editTeam(null, {kind: 'unit', parent: UI.team || ''}); };
      tools.appendChild(el('span', 'tmx-sp'));
      tools.appendChild(addU);
      tools.appendChild(addT);
    }
    head.appendChild(tools);
    card.appendChild(head);
    var scroll = el('div', 'tmx-tree-s');
    scroll.id = 'tmx-tree-s';
    scroll.setAttribute('role', 'tree');
    var inner = el('div', 'tmx-tree-in');
    scroll.appendChild(inner);
    card.appendChild(scroll);
    var none = el('div', 'tmx-tree-none muted small', 'No team matches.');
    card.appendChild(none);
    var rows = [], hits = {};
    var compute = function () {
      rows = [];
      hits = {};
      var w = fold(UI.q).trim();
      if (w) {
        var keepK = {};
        T.order.forEach(function (n) {
          if (fold(n.name).indexOf(w) >= 0 || fold(n.desc).indexOf(w) >= 0) {
            hits[n.key] = 1;
            chainOf(T, n.name).forEach(function (a) { keepK[a.key] = 1; });
          }
        });
        rows = T.order.filter(function (n) { return keepK[n.key]; });
      } else {
        var add = function (n) {
          rows.push(n);
          if (UI.open[n.key]) n.kids.forEach(add);
        };
        T.tops.forEach(add);
      }
      none.hidden = rows.length > 0;
    };
    var virtual = function () { return rows.length > 120; };
    var draw = function () {
      clear(inner);
      var from = 0, to = rows.length;
      if (virtual()) {
        inner.style.height = (rows.length * ROW_H) + 'px';
        var top = scroll.scrollTop, h = scroll.clientHeight || 600;
        from = Math.max(0, Math.floor(top / ROW_H) - 10);
        to = Math.min(rows.length, Math.ceil((top + h) / ROW_H) + 10);
      } else inner.style.height = '';
      for (var i = from; i < to; i++) {
        var r = treeRow(T, rows[i], hits, !!UI.q);
        if (virtual()) { r.style.position = 'absolute'; r.style.top = (i * ROW_H) + 'px'; r.style.left = '0'; r.style.right = '0'; }
        inner.appendChild(r);
      }
      inner.classList.toggle('virtual', virtual());
    };
    var paint = function () { compute(); draw(); };
    card._paint = paint;
    var ticking = false;
    scroll.addEventListener('scroll', function () {
      if (!virtual() || ticking) return;
      ticking = true;
      requestAnimationFrame(function () { ticking = false; draw(); });
    });
    q.addEventListener('input', debounce(function () { UI.q = q.value; paint(); }, 120));
    q.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') {
        var first = Object.keys(hits)[0];
        if (first) choose(T.nodes[first].name);
      }
      if (e.key === 'Escape' && q.value) { e.stopPropagation(); q.value = ''; UI.q = ''; paint(); }
    });
    paint();
    /* the chosen one in sight */
    setTimeout(function () {
      var on = inner.querySelector('.tmx-row.on');
      if (on && on.offsetTop > scroll.clientHeight - ROW_H) scroll.scrollTop = on.offsetTop - scroll.clientHeight / 3;
    }, 0);
    return card;
  }
  function mark(text, w) {
    var box = data('span', 'tmx-row-n', '');
    var f = fold(text), at = w ? f.indexOf(w) : -1;
    if (at < 0) { box.textContent = text; return box; }
    box.appendChild(document.createTextNode(text.slice(0, at)));
    box.appendChild(el('mark', '', text.slice(at, at + w.length)));
    box.appendChild(document.createTextNode(text.slice(at + w.length)));
    return box;
  }
  function treeRow(T, n, hits, searching) {
    var r = el('div', 'tmx-row' + (low(UI.team) === n.key ? ' on' : '') + (hits[n.key] ? ' hit' : '')
               + (searching && !hits[n.key] ? ' ctx' : ''));
    r.dataset.name = n.name;
    r.setAttribute('role', 'treeitem');
    r.tabIndex = 0;
    r.style.paddingLeft = (8 + n.depth * 18) + 'px';
    for (var g = 0; g < n.depth; g++) {
      var guide = el('span', 'tmx-guide');
      guide.style.left = (17 + g * 18) + 'px';
      r.appendChild(guide);
    }
    var tw = el('button', 'tmx-tw' + (n.kids.length ? '' : ' leaf') + (UI.open[n.key] || searching ? ' open' : ''));
    tw.type = 'button';
    tw.tabIndex = -1;
    tw.innerHTML = iconMarkup('next', 13);
    if (n.kids.length && !searching) {
      tw.setAttribute('aria-label', tr(UI.open[n.key] ? 'Fold' : 'Unfold'));
      tw.onclick = function (e) {
        e.stopPropagation();
        UI.open[n.key] = !UI.open[n.key];
        keep();
        var c = $('tmx-tree');
        if (c && c._paint) c._paint();
      };
    }
    r.appendChild(tw);
    r.appendChild(kindBadge(n.kind, 14));
    var w = el('span', 'tmx-row-w');
    w.appendChild(mark(n.name, searching ? fold(UI.q).trim() : ''));
    if (n.desc) { var rd = data('span', 'tmx-row-d', n.desc); rd.title = n.desc; w.appendChild(rd); }
    r.appendChild(w);
    var b = el('span', 'tmx-row-b');
    if (n.all) {
      var c1 = el('span', 'tmx-mini');
      c1.appendChild(ic('lock', 11));
      c1.appendChild(data('span', '', num(n.all)));
      explain(c1, n.all === n.certs ? '{0} certificate(s)'.replace('{0}', num(n.certs))
        : '{0} certificate(s) - {1} with the teams below'.replace('{0}', num(n.certs)).replace('{1}', num(n.all)));
      b.appendChild(c1);
    }
    if (n.members) {
      var c2 = el('span', 'tmx-mini');
      c2.appendChild(ic('people', 11));
      c2.appendChild(data('span', '', num(n.members)));
      explain(c2, '{0} member(s)'.replace('{0}', num(n.members)));
      b.appendChild(c2);
    }
    if (n.devices) {
      var c3 = el('span', 'tmx-mini');
      c3.appendChild(ic('router', 11));
      c3.appendChild(data('span', '', num(n.devices)));
      explain(c3, '{0} device(s)'.replace('{0}', num(n.devices)));
      b.appendChild(c3);
    }
    r.appendChild(b);
    r.onclick = function () { choose(n.name); };
    r.onkeydown = function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); choose(n.name); }
      if (e.key === 'ArrowRight' && n.kids.length && !UI.open[n.key]) { UI.open[n.key] = true; keep(); $('tmx-tree')._paint(); focusRow(n.name); }
      if (e.key === 'ArrowLeft' && UI.open[n.key]) { UI.open[n.key] = false; keep(); $('tmx-tree')._paint(); focusRow(n.name); }
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        var to = e.key === 'ArrowDown' ? r.nextElementSibling : r.previousElementSibling;
        if (to && to.classList.contains('tmx-row')) to.focus();
      }
    };
    return r;
  }
  function focusRow(name) {
    var r = document.querySelector('#tmx-tree .tmx-row[data-name="' + String(name).replace(/["\\]/g, '\\$&') + '"]');
    if (r) r.focus();
  }
  function choose(name) {
    UI.team = name;
    keep();
    drawer(false);
    document.querySelectorAll('#tmx-tree .tmx-row').forEach(function (r) { r.classList.toggle('on', r.dataset.name === name); });
    var T = UI.T, page = $('tmx-page');
    if (!T || !page) { drawView(); return; }
    var sw = $('tmx-switch');
    if (sw) {
      var n = T.nodes[low(name)];
      sw.replaceChild(kindBadge(n.kind, 18), sw.firstChild);
      sw.querySelector('b').textContent = n.name;
      sw.querySelector('.tmx-switch-p').textContent = chainOf(T, n.name).slice(0, -1).map(function (x) { return x.name; }).join(' › ');
    }
    ['tmx-add-team', 'tmx-add-unit'].forEach(function (id, i) {
      var b = $(id);
      /* the words of the button itself (they were swapped), and what a screen reader says
         of it again - explain() keeps an aria-label it finds */
      if (b) { b.removeAttribute('aria-label'); explain(b, (i ? 'A new unit (a region, a site) under {0}' : 'A new team under {0}').replace('{0}', name)); }
    });
    teamPage(page, T, T.nodes[low(name)]);
  }

  /* ---- the team's page ---------------------------------------------------------- */
  function teamPage(page, T, n) {
    clear(page);
    if (!n) return;
    var t = n.t;
    var card = fade(el('div', 'tmx-team'));
    card.dataset.team = n.name;
    var hero = el('div', 'tmx-hero k-' + (KIND_ICON[n.kind] ? n.kind : 'team'));
    var crumbs = el('nav', 'tmx-crumbs');
    crumbs.setAttribute('aria-label', tr('Where it stands'));
    var chain = chainOf(T, n.name);
    chain.forEach(function (a, i) {
      if (i) crumbs.appendChild(ic('next', 12, 'tmx-crumb-s'));
      var c = data(i === chain.length - 1 ? 'span' : 'button', 'tmx-crumb' + (i === chain.length - 1 ? ' here' : ''), a.name);
      if (i < chain.length - 1) { c.type = 'button'; c.onclick = function () { choose(a.name); }; }
      crumbs.appendChild(c);
    });
    hero.appendChild(crumbs);
    var top = el('div', 'tmx-hero-top');
    var big = el('div', 'tmx-hero-ic');
    big.innerHTML = iconMarkup(KIND_ICON[n.kind] || 'people', 26);
    top.appendChild(big);
    var tw = el('div', 'tmx-hero-w');
    var h = el('h2', 'tmx-hero-n');
    h.appendChild(data('span', '', n.name));
    h.appendChild(el('span', 'tag ' + (n.kind === 'unit' ? 'violet' : n.kind === 'person' ? 'ok' : 'info'), KIND_NAME[n.kind] || 'team'));
    tw.appendChild(h);
    if (n.desc) tw.appendChild(data('p', 'tmx-hero-d', n.desc));
    var meta = el('div', 'tmx-hero-m');
    if (t.contact_mail) {
      String(t.contact_mail).split(/\s*,\s*/).filter(Boolean).forEach(function (m) {
        var a = data('a', 'tmx-mail', '');
        a.href = 'mailto:' + m;
        a.appendChild(ic('mail', 13));
        a.appendChild(document.createTextNode(m));
        meta.appendChild(a);
      });
    }
    if (t.contact_phone) meta.appendChild(dataChip(t.contact_phone, 'dim', 'phone'));
    if (n.kids.length) {
      var kc = chip(n.kids.length === 1 ? '1 team below' : num(n.kids.length) + ' teams below', 'dim', 'tm_tree');
      meta.appendChild(kc);
    }
    if (meta.firstChild) tw.appendChild(meta);
    top.appendChild(tw);
    if (writes()) {
      var acts = el('div', 'tmx-hero-a');
      var ed = cmdButton('Edit', 'edit', 'small');
      ed.id = 'tmx-edit';
      ed.onclick = function () { editTeam(t); };
      var mv = cmdButton('Move to…', 'tm_move', 'small');
      mv.id = 'tmx-move';
      mv.onclick = function () { moveTeam(n); };
      var del = iconButton('trash', 'Delete this team');
      del.id = 'tmx-del';
      del.onclick = function () { deleteTeam(t, n); };
      acts.appendChild(ed);
      acts.appendChild(mv);
      acts.appendChild(del);
      top.appendChild(acts);
    }
    hero.appendChild(top);
    card.appendChild(hero);
    var tabs = el('div', 'tmx-tabs');
    tabs.setAttribute('role', 'tablist');
    var own = Object.keys(t.policy || {}).length;
    var devs = (UI.targets || []).filter(function (r) { return low(r.owner) === n.key; }).length;
    /* a tab another file adds (window.ACME_TEAM_TABS: {name, title, icon, draw}, 1.0.140) */
    TABS.concat((window.ACME_TEAM_TABS || []).map(function (x) { return [x.name, x.title, x.icon]; })).forEach(function (x) {
      var b = el('button', 'tmx-tab' + (UI.tab === x[0] ? ' on' : ''));
      b.type = 'button';
      b.dataset.tab = x[0];
      b.setAttribute('role', 'tab');
      b.appendChild(ic(x[2], 15));
      b.appendChild(el('span', '', x[1]));
      var cnt = {members: (t.members || []).length, limits: own, devices: devs, certs: n.certs}[x[0]];
      if (cnt) b.appendChild(data('span', 'tmx-n', num(cnt)));
      b.onclick = function () {
        UI.tab = x[0];
        keep();
        tabs.querySelectorAll('.tmx-tab').forEach(function (o) { o.classList.toggle('on', o === b); });
        b.scrollIntoView({block: 'nearest', inline: 'nearest'});
        drawTab(body, T, n);
      };
      tabs.appendChild(b);
    });
    card.appendChild(tabs);
    var body = el('div', 'tmx-body');
    body.id = 'tmx-body';
    card.appendChild(body);
    page.appendChild(card);
    drawTab(body, T, n);
  }
  function drawTab(body, T, n) {
    clear(body);
    var inner = fade(el('div', 'tmx-tabbody'));
    body.appendChild(inner);
    var f = {overview: overview, members: membersTab, limits: limitsTab, devices: devicesTab,
             certs: certsTab, activity: activityTab, gov: govTab}[UI.tab] ||
      (window.ACME_TEAM_TABS || []).filter(function (x) { return x.name === UI.tab; }).map(function (x) { return x.draw; })[0] || overview;
    f(inner, T, n);
    if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(inner); } catch (e) { } }
  }

  /* -- Overview -- */
  function teamCounts(name) {
    var k = low(name);
    if (UI.counts[k]) return UI.counts[k];
    /* GET /api/teams says them of every team at once (1.0.125) - the lists asked only of a
       daemon that does not */
    var t = teamOf(name);
    if (t && t.counts) {
      UI.counts[k] = Promise.resolve({certs: Number(t.counts.certs || 0), expiring: Number(t.counts.expiring || 0),
                                      failing: Number(t.counts.failing || 0), waiting: Number(t.counts.waiting || 0),
                                      agents_waiting: Number(t.counts.agents_waiting || 0)});
      return UI.counts[k];
    }
    var ask = function (state) {
      return api('certs&owner=' + enc(name) + '&per=1' + (state ? '&state=' + state : ''))
        .then(function (d) { return Number(d.total || 0); }).catch(function () { return null; });
    };
    UI.counts[k] = Promise.all([ask(''), ask('expiring'), ask('failed'), ask('pending-approval')])
      .then(function (x) { return {certs: x[0], expiring: x[1], failing: x[2], waiting: x[3]}; });
    return UI.counts[k];
  }
  function tile(key, icon, label, value, sub, tone, go) {
    var b = el(go ? 'button' : 'div', 'tmx-tile' + (tone ? ' ' + tone : ''));
    if (go) { b.type = 'button'; b.onclick = go; }
    b.dataset.tile = key;
    /* the label alone on its line (wrapped at spaces only, never inside a word), the mark
       beside the number */
    var top = el('div', 'tmx-tile-h', label);
    b.appendChild(top);
    var vr = el('div', 'tmx-tile-vr');
    vr.appendChild(ic(icon, 16));
    vr.appendChild(data('div', 'tmx-tile-v', value === null || value === undefined ? '–' : num(value)));
    b.appendChild(vr);
    b.title = top.textContent;
    if (sub) b.appendChild(sub instanceof Node ? sub : el('div', 'tmx-tile-s', sub));
    return b;
  }
  function goTab(tab) {
    return function () {
      UI.tab = tab;
      keep();
      var b = document.querySelector('#tmx .tmx-tab[data-tab="' + tab + '"]');
      if (b) b.click();
    };
  }
  function overview(box, T, n) {
    var t = n.t;
    var tiles = el('div', 'tmx-tiles');
    box.appendChild(tiles);
    var devs = (UI.targets || []).filter(function (r) { return low(r.owner) === n.key; });
    var agents = devs.filter(function (r) { return r.kind === 'agent' || r.kind === 'agent_windows'; });
    var mem = t.members || [];
    var ending = mem.filter(function (m) { return m.until && !m.expired && daysTo(m.until) <= 30; }).length;
    var paint = function (c) {
      clear(tiles);
      var allSub = n.all !== n.certs ? el('div', 'tmx-tile-s', '{0} with the teams below'.replace('{0}', num(n.all))) : el('div', 'tmx-tile-s', 'owned by this team');
      tiles.appendChild(tile('certs', 'lock', 'Certificates', c ? c.certs : null, allSub, 'info', goTab('certs')));
      tiles.appendChild(tile('expiring', 'clock', 'Running out', c ? c.expiring : null, 'within the notice days', c && c.expiring ? 'warn' : '', goTab('certs')));
      tiles.appendChild(tile('failing', 'pulse', 'Failing', c ? c.failing : null, 'the last renewal failed', c && c.failing ? 'crit' : '', goTab('certs')));
      tiles.appendChild(tile('waiting', 'bell', 'Waiting requests', c ? c.waiting : null, 'for an approval', c && c.waiting ? 'violet' : '', goTab('certs')));
      tiles.appendChild(tile('devices', 'router', 'Devices', devs.length, 'targets owned by the team', '', goTab('devices')));
      tiles.appendChild(tile('agents', 'terminal', 'Agents', agents.length, c && c.agents_waiting ? el('div', 'tmx-tile-s warn', '{0} waiting to be confirmed'.replace('{0}', num(c.agents_waiting))) : 'servers with acme-agent', c && c.agents_waiting ? 'warn' : '', goTab('devices')));
      tiles.appendChild(tile('members', 'people', 'Members', mem.length, ending ? el('div', 'tmx-tile-s warn', '{0} ending within 30 days'.replace('{0}', num(ending))) : 'people and groups', '', goTab('members')));
    };
    paint(null);
    teamCounts(n.name).then(function (c) { if (tiles.isConnected) paint(c); });
    healthStrip(box, n);
    var cols = el('div', 'tmx-cols');
    /* the limits in force */
    var lim = el('section', 'tmx-sec');
    var lh = el('h3', 'tmx-sec-h');
    lh.appendChild(ic('shield', 16));
    lh.appendChild(el('span', '', 'Limits in force'));
    var more = el('button', 'tmx-link', 'Open');
    more.type = 'button';
    more.onclick = goTab('limits');
    lh.appendChild(more);
    lim.appendChild(lh);
    var eff = t.effective || {};
    var keys = POLICY_ROWS.filter(function (p) { return eff[p.k] !== undefined; });
    if (!keys.length) lim.appendChild(el('p', 'muted small tmx-none', 'Nothing limits this team: it may do what its members\' roles give.'));
    keys.forEach(function (p) {
      var line = el('div', 'tmx-effline');
      line.appendChild(el('span', 'tmx-effk', p.label));
      line.appendChild(valueView(p, eff[p.k]));
      line.appendChild(fromBadge(eff.from && eff.from[p.k], n.name));
      lim.appendChild(line);
    });
    cols.appendChild(lim);
    /* below it, and the people */
    var side = el('section', 'tmx-sec');
    var sh = el('h3', 'tmx-sec-h');
    sh.appendChild(ic('tm_tree', 16));
    sh.appendChild(el('span', '', 'Teams below'));
    side.appendChild(sh);
    if (!n.kids.length) side.appendChild(el('p', 'muted small tmx-none', 'No team below this one.'));
    var kids = el('div', 'tmx-kids');
    n.kids.forEach(function (c) {
      var k = el('button', 'tmx-kid');
      k.type = 'button';
      k.appendChild(kindBadge(c.kind, 14));
      k.appendChild(data('span', 'tmx-kid-n', c.name));
      if (c.all) k.appendChild(data('span', 'tmx-mini', num(c.all)));
      k.onclick = function () { choose(c.name); };
      kids.appendChild(k);
    });
    side.appendChild(kids);
    if (mem.length) {
      var ph = el('h3', 'tmx-sec-h tmx-sec-h2');
      ph.appendChild(ic('people', 16));
      ph.appendChild(el('span', '', 'Members'));
      side.appendChild(ph);
      var stack = el('div', 'tmx-stack');
      mem.slice(0, 12).forEach(function (m) {
        var a = avatar(m.who, m.kind || kindOf(m.who));
        explain(a, m.who);
        stack.appendChild(a);
      });
      if (mem.length > 12) stack.appendChild(data('span', 'tmx-av more', '+' + (mem.length - 12)));
      stack.onclick = goTab('members');
      side.appendChild(stack);
    }
    cols.appendChild(side);
    box.appendChild(cols);
    if (t.note) {
      var nt = el('div', 'tmx-note');
      nt.appendChild(ic('info', 16));
      nt.appendChild((t.note === 'made from what certificates said' ? el : data)('span', '', t.note));
      box.appendChild(nt);
    }
  }

  /* -- Members -- */
  function roleOf(name) {
    return ((TM.d || {}).roles || []).filter(function (r) { return low(r.name) === low(name); })[0] || null;
  }
  function roleChip(name) {
    var r = roleOf(name);
    var c = r && r.builtin ? chip(name, 'role') : dataChip(name, 'role custom' + (r ? '' : ' gone'));
    if (r) explain(c, (r.description ? known(r.description) + ' - ' : '') + tr(r.caps.length + ' capabilities'));
    else explain(c, 'This role is not in the catalog any more.');
    return c;
  }
  function untilChip(m) {
    if (!m.until) return null;
    var d = daysTo(m.until);
    if (m.expired || d < 0) return chip('ended {0}'.replace('{0}', dateOf(m.until)), 'crit', 'clock');
    var c = chip(d <= 1 ? 'ends today' : 'expires in {0} days'.replace('{0}', num(d)), d <= 14 ? 'warn' : 'dim', 'clock');
    explain(c, 'until {0}'.replace('{0}', dateOf(m.until)));
    return c;
  }
  function memberRow(t, m, i, inherited) {
    var kind = m.kind || kindOf(m.who);
    var r = el('div', 'tmx-mrow' + (m.expired ? ' expired' : '') + (inherited ? ' inh' : ''));
    r.dataset.who = m.who;
    r.appendChild(avatar(m.who, kind));
    var w = el('div', 'tmx-mw');
    var top = el('div', 'tmx-mtop');
    top.appendChild(data('b', 'tmx-mwho', shortWho(m.who)));
    top.lastChild.title = m.who;
    var kc = chip(KIND_WORDS[kind] || kind, 'dim k', WHO_ICON[kind] || 'person');
    top.appendChild(kc);
    if (inherited) {
      var ib = el('button', 'tmx-from', '');
      ib.type = 'button';
      ib.appendChild(el('span', '', 'from'));
      ib.appendChild(data('b', '', inherited));
      ib.onclick = function () { choose(inherited); };
      top.appendChild(ib);
    }
    w.appendChild(top);
    var roles = el('div', 'tmx-mroles');
    (m.roles || []).forEach(function (x) { roles.appendChild(roleChip(x)); });
    if ((m.rights || []).length) roles.appendChild(el('span', 'tmx-oldr', 'old rights'));
    (m.rights || []).forEach(function (x) {
      var c = chip(RIGHT_WORDS[x] || x, 'legacy');
      explain(c, RIGHT_SAYS[x] || x);
      roles.appendChild(c);
    });
    if (!roles.firstChild) roles.appendChild(el('span', 'muted small', 'no role - sees nothing'));
    var u = untilChip(m);
    if (u) roles.appendChild(u);
    w.appendChild(roles);
    if (m.note) w.appendChild(data('div', 'tmx-mnote', m.note));
    r.appendChild(w);
    if (!inherited && writes()) {
      var tools = el('div', 'tmx-mtools');
      var ed = iconButton('edit', 'Change this member');
      ed.classList.add('tmx-medit');
      ed.onclick = function () { memberDialog(t, m); };
      var x = iconButton('trash', 'Take this member out');
      x.classList.add('tmx-mdel');
      x.onclick = function () {
        confirmThen('Take the member out', htmlText('{0} is taken out of {1}.'.replace('{0}', m.who).replace('{1}', t.name)), 'Take it out', function () {
          var list = (t.members || []).filter(function (o) { return o !== m; });
          saveTeam(t, {members: list}).catch(oops);
        });
      };
      tools.appendChild(ed);
      tools.appendChild(x);
      r.appendChild(tools);
    }
    /* view as this member (1.0.138): a full administrator, a person (not a group) */
    if (fullAdmin() && kind !== 'group') {
      var va = iconButton('eye', 'View as this member');
      va.classList.add('tmg-mview');
      va.onclick = function () { viewAsChoose(m.who); };
      var vt = r.querySelector('.tmx-mtools');
      if (!vt) { vt = el('div', 'tmx-mtools'); r.appendChild(vt); }
      vt.insertBefore(va, vt.firstChild);
    }
    return r;
  }
  function membersTab(box, T, n) {
    var t = n.t;
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'Who belongs to the team and what each may do - by roles (sets of capabilities) or the old rights. What they may do here they may do in every team below too. A membership may end by itself.'));
    if (writes()) {
      var add = cmdButton('Add a member', 'add', 'small primary');
      add.id = 'tmx-addm';
      add.onclick = function () { memberDialog(t, null); };
      head.appendChild(add);
    }
    box.appendChild(head);
    var list = el('div', 'tmx-mlist');
    list.id = 'tmx-mlist';
    (t.members || []).forEach(function (m, i) { list.appendChild(memberRow(t, m, i, null)); });
    if (!(t.members || []).length) {
      list.appendChild(empty('people', 'No member of its own', 'Only administrators and the members of the teams above it see its certificates.'));
    }
    box.appendChild(list);
    var up = chainOf(T, n.name).slice(0, -1).reverse();
    var inh = [];
    up.forEach(function (a) { (a.t.members || []).forEach(function (m) { inh.push([a, m]); }); });
    if (inh.length) {
      var h = el('h3', 'tmx-sub');
      h.appendChild(ic('tm_tree', 15));
      h.appendChild(el('span', '', 'From the teams above'));
      h.appendChild(data('span', 'tmx-n', num(inh.length)));
      box.appendChild(h);
      var l2 = el('div', 'tmx-mlist inh');
      inh.forEach(function (x, i) { l2.appendChild(memberRow(x[0].t, x[1], i, x[0].name)); });
      box.appendChild(l2);
    }
  }
  function cleanMember(m) {
    var o = {who: m.who};
    if ((m.rights || []).length) o.rights = m.rights.slice();
    if ((m.roles || []).length) o.roles = m.roles.slice();
    if (m.until) o.until = m.until;
    if (m.note) o.note = m.note;
    if (!o.rights && !o.roles) o.rights = [];
    return o;
  }
  /* a team saved as it is, with what changed */
  function saveTeam(t, ch) {
    var b = {old_name: t.name, name: t.name, kind: t.kind || 'team', parent: t.parent || '',
             description: t.description || '', contact_mail: t.contact_mail || '',
             contact_phone: t.contact_phone || '', note: t.note || '',
             members: (t.members || []).map(cleanMember)};
    Object.keys(ch || {}).forEach(function (k) { b[k] = ch[k]; });
    if (ch && ch.members) b.members = ch.members.map(cleanMember);
    /* the team as it was read: saved by someone else since, refused - not written over (hunt w6) */
    if (t.updated) b.was_updated = t.updated;
    return call('teams/save', b).then(function (r) {
      toast(r.message || 'saved', 'good');
      return refresh(b.name);
    }, function (e) {
      if (e && e.status === 409) refresh(t.name);
      throw e;
    });
  }

  /* the member's popup: the directory searched, the roles as chips, an end */
  function memberDialog(t, m) {
    var isNew = !m;
    var st = {who: m ? m.who : '', kind: m ? (m.kind || kindOf(m.who)) : '', roles: m ? (m.roles || []).slice() : [],
              rights: m ? (m.rights || []).slice() : [], until: m ? m.until || null : null, note: m ? m.note || '' : ''};
    modal(isNew ? 'A new member of {0}'.replace('{0}', t.name) : 'A member', function (body) {
      body.classList.add('tmx-dlg');
      var whoBox = el('div', 'tmx-whobox');
      body.appendChild(sectionHead('person', 'Who'));
      body.appendChild(whoBox);
      var chosen = el('div', 'tmx-chosen');
      var paintChosen = function () {
        clear(chosen);
        chosen.hidden = !st.who;
        if (!st.who) return;
        chosen.appendChild(avatar(st.who, st.kind));
        var w = el('div', 'tmx-chosen-w');
        w.appendChild(data('b', '', st.display || shortWho(st.who)));
        w.appendChild(data('span', 'mono small', st.who));
        chosen.appendChild(w);
        var info = el('div', 'tmx-chosen-i');
        chosen.appendChild(info);
        if (st.kind === 'group' && dirs().length) {
          info.appendChild(el('span', 'muted small', 'Asking…'));
          api('dir/group&name=' + enc(st.who)).then(function (g) {
            clear(info);
            info.appendChild(chip((g.count === 1 ? '1 person' : '{0} people'.replace('{0}', num(g.count || 0))) + (g.capped ? '+' : ''), 'info', 'people'));
            var names = el('div', 'tmx-gnames');
            (g.first || []).slice(0, 8).forEach(function (u) { names.appendChild(dataChip(u.display || u.sam || u.upn, 'dim')); });
            if ((g.count || 0) > 8) names.appendChild(data('span', 'muted small', '…'));
            info.appendChild(names);
          }).catch(function () { clear(info); info.appendChild(el('span', 'muted small', 'not found in the directory - kept as typed')); });
        }
        if (isNew) {
          var x = iconButton('close', 'Choose somebody else');
          x.onclick = function () { st.who = ''; paintChosen(); };
          chosen.appendChild(x);
        }
      };
      if (isNew) {
        var how = segmented(dirs().length ? [['dir', 'Directory', 'tm_dir'], ['local', 'Account of acme', 'key'], ['typed', 'Typed', 'edit']]
          : [['local', 'Account of acme', 'key'], ['typed', 'Typed', 'edit']], dirs().length ? 'dir' : 'local');
        how.id = 'tmx-m-how';
        whoBox.appendChild(how);
        var pane = el('div', 'tmx-whopane');
        whoBox.appendChild(pane);
        var drawHow = function () {
          clear(pane);
          if (how.value === 'dir') pane.appendChild(dirPicker(function (row, kind) {
            st.who = row.who;
            st.kind = kind;
            st.display = row.display || row.cn || '';
            paintChosen();
          }));
          else if (how.value === 'local') {
            var acc = el('select', 'tmx-m-acc');
            noI18n(acc);
            pane.appendChild(acc);
            accounts().then(function (names) {
              acc.appendChild(el('option', '', tr('choose an account…'))).value = '';
              names.forEach(function (nm) { var o = data('option', '', nm); o.value = nm; acc.appendChild(o); });
            });
            acc.onchange = function () { st.who = acc.value ? 'local:' + acc.value : ''; st.kind = 'local'; st.display = acc.value; paintChosen(); };
          } else {
            var tx = textBox('', tr('sAMAccountName, UPN, mail, group:NAME or a DN'), 'mono');
            tx.id = 'tmx-m-typed';
            noI18n(tx);
            pane.appendChild(tx);
            tx.oninput = function () { st.who = tx.value.trim(); st.kind = kindOf(st.who); st.display = ''; paintChosen(); };
          }
        };
        how.addEventListener('change', drawHow);
        drawHow();
      }
      whoBox.appendChild(chosen);
      paintChosen();
      /* roles */
      body.appendChild(sectionHead('shield', 'Roles'));
      var rbox = el('div', 'tmx-rolepick');
      rbox.id = 'tmx-m-roles';
      body.appendChild(rbox);
      var capsBox = el('div', 'tmx-capsum');
      body.appendChild(capsBox);
      var paintCaps = function () {
        clear(capsBox);
        var caps = {};
        st.roles.forEach(function (r) { var o = roleOf(r); if (o) o.caps.forEach(function (c) { caps[c] = 1; }); });
        st.rights.forEach(function (r) { (RIGHT_CAPS[r] || []).forEach(function (c) { caps[c] = 1; }); });
        var n = Object.keys(caps).length;
        if (!n) { capsBox.appendChild(el('span', 'muted small', 'Choose at least one role: without one the member sees nothing.')); return; }
        capsBox.appendChild(el('span', 'muted small', 'Gives {0} capabilities:'.replace('{0}', num(n))));
        capGroups().forEach(function (g) {
          g.caps.forEach(function (c) { if (caps[c.id]) { var x = data('span', 'tmx-cap g-' + g.cls, c.id); explain(x, c.words); capsBox.appendChild(x); } });
        });
      };
      ((TM.d || {}).roles || []).forEach(function (r) {
        var b = el('button', 'tmx-rchip' + (r.builtin ? '' : ' custom') + (st.roles.some(function (x) { return low(x) === low(r.name); }) ? ' on' : ''));
        b.type = 'button';
        b.dataset.role = r.name;
        b.appendChild(ic('check', 13, 'tmx-rchk'));
        b.appendChild((r.builtin ? el : data)('span', '', r.name));
        explain(b, (r.description ? known(r.description) + ' ' : '') + '(' + tr(r.caps.length + ' capabilities') + ')');
        b.onclick = function () {
          var on = st.roles.some(function (x) { return low(x) === low(r.name); });
          st.roles = on ? st.roles.filter(function (x) { return low(x) !== low(r.name); }) : st.roles.concat([r.name]);
          b.classList.toggle('on', !on);
          paintCaps();
        };
        rbox.appendChild(b);
      });
      paintCaps();
      if (st.rights.length) {
        body.appendChild(sectionHead('history', 'Old rights'));
        body.appendChild(el('p', 'note', 'Given before roles came; they still give exactly what they gave. Take them off once the roles say the same.'));
        var rr = el('div', 'tmx-rolepick');
        ['view', 'request', 'manage', 'approve'].forEach(function (x) {
          var b = el('button', 'tmx-rchip legacy' + (st.rights.indexOf(x) >= 0 ? ' on' : ''));
          b.type = 'button';
          b.appendChild(ic('check', 13, 'tmx-rchk'));
          b.appendChild(el('span', '', RIGHT_WORDS[x]));
          explain(b, RIGHT_SAYS[x]);
          b.onclick = function () {
            var on = st.rights.indexOf(x) >= 0;
            st.rights = on ? st.rights.filter(function (y) { return y !== x; }) : st.rights.concat([x]);
            b.classList.toggle('on', !on);
            paintCaps();
          };
          rr.appendChild(b);
        });
        body.appendChild(rr);
      }
      /* until, a note */
      body.appendChild(sectionHead('clock', 'Until'));
      var ub = el('div', 'tmx-until');
      var date = el('input', 'tmx-date');
      date.type = 'date';
      date.id = 'tmx-m-until';
      date.value = st.until ? dateOf(st.until) : '';
      var quick = el('div', 'tmx-quick');
      [['', 'No end'], [30, '30 days'], [90, '90 days'], [365, 'a year']].forEach(function (q) {
        var b = el('button', 'tmx-qbtn', q[1]);
        b.type = 'button';
        b.onclick = function () {
          date.value = q[0] ? dateOf(Date.now() / 1000 + q[0] * 86400) : '';
          date.dispatchEvent(new Event('change'));
        };
        quick.appendChild(b);
      });
      var said = el('span', 'tmx-until-s muted small');
      var paintUntil = function () {
        clear(said);
        if (!date.value) { said.textContent = 'The membership does not end.'; return; }
        var ts = Date.parse(date.value + 'T23:59:59') / 1000;
        var dd = daysTo(ts);
        said.appendChild(el('span', '', dd < 0 ? 'That day is over: the membership gives nothing.' : 'It ends by itself in {0} days.'.replace('{0}', num(dd))));
      };
      date.addEventListener('change', paintUntil);
      ub.appendChild(date);
      ub.appendChild(quick);
      ub.appendChild(said);
      paintUntil();
      body.appendChild(ub);
      var note = textBox(st.note, tr('why, who asked, a ticket…'), '');
      note.id = 'tmx-m-note';
      noI18n(note);
      body.appendChild(formField('Note', note));
      memberDialog._read = function () {
        st.until = date.value || null;
        st.note = note.value.trim();
        return st;
      };
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add the member' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var s = memberDialog._read();
          if (!s.who) { toast('who? - choose somebody', 'bad'); return; }
          if (!s.roles.length && !s.rights.length) { toast('choose at least one role', 'bad'); return; }
          var list = (t.members || []).slice();
          var one = {who: s.who, roles: s.roles, rights: s.rights, until: s.until || null, note: s.note};
          if (isNew) {
            if (list.some(function (x) { return low(x.who) === low(s.who); })) { toast('already a member', 'bad'); return; }
            list.push(one);
          } else list = list.map(function (x) { return x === m ? one : x; });
          busy(b, true);
          saveTeam(t, {members: list}).then(function () { closeModal(); UI.tab = 'members'; keep(); })
            .catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function sectionHead(icon, words) {
    var h = el('div', 'tmx-dh');
    h.appendChild(ic(icon, 15));
    h.appendChild(el('span', '', words));
    return h;
  }
  /* the directory searched as it is typed in: people or groups */
  function dirPicker(pick, opts) {
    opts = opts || {};
    var wrap = el('div', 'tmx-dir');
    var row = el('div', 'tmx-dir-row');
    var f = el('div', 'tmx-find big');
    f.appendChild(ic('search', 16));
    var q = el('input', 'tmx-dir-q');
    q.type = 'search';
    q.id = opts.id || 'tmx-dir-q';
    q.placeholder = tr('Type a name, a login, a mail or a group…');
    q.autocomplete = 'off';
    noI18n(q);
    f.appendChild(q);
    row.appendChild(f);
    var kind = segmented(opts.users === false ? [['group', 'Groups', 'people']]
      : opts.groups === false ? [['user', 'People', 'person']]
        : [['user', 'People', 'person'], ['group', 'Groups', 'people']], opts.kind || 'user');
    kind.classList.add('small');
    row.appendChild(kind);
    wrap.appendChild(row);
    var list = el('div', 'tmx-dir-list');
    list.setAttribute('role', 'listbox');
    wrap.appendChild(list);
    var said = el('div', 'tmx-dir-said muted small', 'At least two letters.');
    wrap.appendChild(said);
    var gen = 0;
    var go = debounce(function () {
      var w = q.value.trim(), mine = ++gen;
      clear(list);
      if (w.length < 2) { said.textContent = 'At least two letters.'; return; }
      said.textContent = 'Asking the directory…';
      list.classList.add('busy');
      api('dir/search&q=' + enc(w) + '&kind=' + kind.value + '&limit=20').then(function (d) {
        if (mine !== gen) return;
        list.classList.remove('busy');
        var rows = d.rows || [];
        said.textContent = rows.length ? (d.more ? 'More are there - type more of the name.' : '') : 'Nobody found.';
        rows.forEach(function (r) {
          var it = el('button', 'tmx-dir-it');
          it.type = 'button';
          it.setAttribute('role', 'option');
          it.appendChild(avatar(r.who, kind.value === 'group' ? 'group' : 'user'));
          var w2 = el('span', 'tmx-dir-w');
          w2.appendChild(data('b', '', r.display || r.cn || r.sam || r.who));
          w2.appendChild(data('span', 'muted small', kind.value === 'group' ? (r.description || r.dn || '') : [r.upn || r.sam, r.mail].filter(Boolean).join(' · ')));
          it.appendChild(w2);
          if (r.disabled) it.appendChild(chip('disabled', 'crit'));
          it.onclick = function () {
            list.querySelectorAll('.on').forEach(function (x) { x.classList.remove('on'); });
            it.classList.add('on');
            pick(r, kind.value === 'group' ? 'group' : 'user');
          };
          list.appendChild(it);
        });
      }).catch(function (e) {
        if (mine !== gen) return;
        list.classList.remove('busy');
        said.textContent = String((e && e.message) || e);
      });
    }, 300);
    q.addEventListener('input', go);
    kind.addEventListener('change', go);
    setTimeout(function () { q.focus(); }, 60);
    return wrap;
  }
  /* a row of buttons standing for one choice; .value as a select, 'change' when changed */
  function segmented(pairs, value, disabled) {
    var s = el('div', 'tmx-seg');
    s.setAttribute('role', 'radiogroup');
    s.value = value;
    pairs.forEach(function (p) {
      var b = el('button', 'tmx-segb' + (String(p[0]) === String(value) ? ' on' : ''));
      b.type = 'button';
      b.dataset.v = p[0];
      if (p[2]) b.appendChild(ic(p[2], 14));
      b.appendChild(el('span', '', p[1]));
      if (disabled) b.disabled = true;
      b.onclick = function () {
        if (s.value === p[0]) return;
        s.value = p[0];
        s.querySelectorAll('.tmx-segb').forEach(function (x) { x.classList.toggle('on', x === b); });
        s.dispatchEvent(new Event('change'));
      };
      s.appendChild(b);
    });
    return s;
  }

  /* -- Limits -- */
  var POLICY_ROWS = [
    {k: 'profiles', g: 'req', type: 'list', cat: 'profiles', label: 'Request profiles', says: 'What its members may ask for on the portal. With no limit: whatever the profiles themselves allow.'},
    {k: 'free_form', g: 'req', type: 'bool', label: 'Ask without a profile', says: 'The portal\'s free form - names and source chosen by the person.'},
    {k: 'issuers', g: 'req', type: 'list', cat: 'issuers', label: 'Sources', says: 'Where its certificates may come from.'},
    {k: 'validations', g: 'req', type: 'list', cat: 'validations', label: 'Validations', says: 'How the names of its certificates may be proved.'},
    {k: 'pairs', g: 'req', type: 'pairs', label: 'Sources with their validations', says: 'A certificate from a source here is proved only by the validations picked for it. A source not here only where Sources lists it.'},
    {k: 'suffixes', g: 'req', type: 'list', cat: 'free', label: 'Domains', says: 'Every name of its certificates must be under one of these.'},
    {k: 'wildcards', g: 'req', type: 'bool', label: 'Wildcard names', says: 'Names like *.example.com in its certificates.'},
    {k: 'max_days', g: 'req', type: 'int', label: 'Longest validity', unit: 'days', says: 'The most days a certificate of the team may be valid.'},
    {k: 'max_certs', g: 'req', type: 'int', label: 'Most certificates', unit: 'certificates', says: 'How many certificates the team - with the teams below it - may own.'},
    {k: 'key_download', g: 'dev', type: 'bool', label: 'Download the private key', says: 'Files with the private key (PFX, PEM with the key) may be downloaded.'},
    {k: 'target_kinds', g: 'dev', type: 'list', cat: 'kinds', label: 'Target modules', says: 'Which kinds of devices its members may create and use.'},
    {k: 'test_kinds', g: 'dev', type: 'list', cat: 'test_kinds', label: 'Test modules', says: 'Which kinds of tests its members may create and run.'},
    {k: 'agents', g: 'dev', type: 'bool', label: 'Target agents', says: 'Servers with acme-agent may be the team\'s devices.'},
    {k: 'agents_auto_confirm', g: 'dev', type: 'bool', label: 'Agents confirmed by themselves', says: 'Agents enrolling with the team\'s code become its devices without waiting for a confirmation.'},
    {k: 'approval', g: 'appr', type: 'approval', label: 'Approval of requests', says: 'Whether what its members ask for waits, and who approves it.'},
    {k: 'approve_actions', g: 'appr', type: 'list', cat: 'actions', label: 'Other actions approved', says: 'These wait for an approval too.'}
  ];
  var POLICY_GROUPS = [['req', 'Requests', 'lock'], ['dev', 'Keys, devices and agents', 'router'], ['appr', 'Approvals', 'check']];
  var MODE_WORDS = {none: 'Never waits', profile: 'As the profile says', always: 'Always waits', outside: 'Waits outside the envelope'};
  var MODE_SAYS = {none: 'Members ask for what the team\'s limits allow and get it at once - the team does it all itself.',
                   profile: 'The request profile decides, as before.',
                   always: 'Every request waits for an approval.',
                   outside: 'Inside the pre-approved envelope at once; anything outside it waits.'};
  var APPROVER_WORDS = {team: 'the team\'s own approvers', parent: 'the approvers of the team above',
                        team_or_parent: 'either of them', both: 'both - the team first, then the team above'};
  var ACTION_WORDS = {revoke: 'revoking', 'delete': 'deleting', key: 'downloading a key', device: 'devices'};
  var KEY_TYPES = ['ec-256', 'ec-384', 'rsa-2048', 'rsa-3072', 'rsa-4096', 'ed25519'];
  function catalogs() {
    if (UI.cats) return Promise.resolve(UI.cats);
    var rows = function (what, key) {
      return api(what).then(function (d) { return (d && (d.rows || d[key])) || []; }).catch(function () { return []; });
    };
    return Promise.all([rows('reqprofiles', 'profiles'), rows('sources'), rows('validations'),
                        api('plugins').catch(function () { return {}; })]).then(function (x) {
      var kinds = ((x[3] && (x[3].target || x[3].targets)) || []).map(function (p) { return [p.kind, p.title || p.kind]; });
      var tkinds = ((x[3] && (x[3].check || x[3].checks)) || []).map(function (p) { return [p.kind, p.title || p.kind]; });
      UI.cats = {profiles: x[0].map(function (r) { return [r.name, r.name]; }),
                 issuers: x[1].map(function (r) { return [r.name, r.name + (r.kind ? ' · ' + r.kind : '')]; }),
                 validations: x[2].map(function (r) { return [r.name, r.name + (r.kind ? ' · ' + r.kind : '')]; }),
                 kinds: kinds, test_kinds: tkinds, actions: ((TM.d || {}).approve_actions || Object.keys(ACTION_WORDS)).map(function (a) { return [a, ACTION_WORDS[a] || a]; }),
                 key_types: KEY_TYPES.map(function (k) { return [k, k]; })};
      return UI.cats;
    });
  }
  function catWord(cat, v) {
    var c = UI.cats && UI.cats[cat];
    var one = c && c.filter(function (x) { return x[0] === v; })[0];
    return one ? one[1] : v;
  }
  function valueView(p, v) {
    var box = el('span', 'tmx-val');
    if (p.type === 'bool') {
      box.appendChild(chip(v ? (p.k === 'agents_auto_confirm' ? 'yes' : 'allowed') : (p.k === 'agents_auto_confirm' ? 'no' : 'forbidden'), v ? 'ok' : 'crit', v ? 'check' : 'ban'));
    } else if (p.type === 'int') {
      box.appendChild(chip(el('span', '', ('at most {0} ' + p.unit).replace('{0}', num(v))), 'info'));
    } else if (p.type === 'list') {
      if (!v.length) box.appendChild(chip('none at all', 'crit', 'ban'));
      v.forEach(function (x) {
        if (p.cat === 'actions') box.appendChild(chip(ACTION_WORDS[x] || x, 'info'));
        else box.appendChild(dataChip(p.cat === 'kinds' || p.cat === 'test_kinds' ? catWord(p.cat, x) : x, 'info'));
      });
    } else if (p.type === 'pairs') {
      var ks = Object.keys(v || {});
      if (!ks.length) box.appendChild(chip('none at all', 'crit', 'ban'));
      ks.forEach(function (k) { box.appendChild(pairChip(k, v[k])); });
    } else if (p.type === 'approval') {
      var a = typeof v === 'string' ? {mode: v} : (v || {});
      box.appendChild(chip(MODE_WORDS[a.mode] || a.mode, a.mode === 'none' ? 'ok' : a.mode === 'always' ? 'warn' : 'info', 'check'));
      if (a.approvers) box.appendChild(chip(APPROVER_WORDS[a.approvers] || a.approvers, 'dim', 'people'));
      if (Number(a.count) === 2) box.appendChild(chip('four eyes', 'violet', 'eye'));
      if (a.self) box.appendChild(chip('may approve their own', 'dim'));
      if (a.outside && a.outside.wildcards === false) box.appendChild(chip('a wildcard waits', 'warn'));
    }
    return box;
  }
  /* one source with its validations: "acme-le → dns-web, http-web" (null: any validation) */
  function pairChip(src, vals) {
    var c = el('span', 'chip info tmx-pair');
    c.appendChild(data('b', '', src));
    c.appendChild(document.createTextNode(' → '));
    if (vals === null || vals === undefined) c.appendChild(el('span', '', 'any validation'));
    else if (!vals.length) c.appendChild(el('span', '', 'no validation'));
    else c.appendChild(data('span', '', vals.join(', ')));
    return c;
  }
  /* pairs: no limit, or these sources each with the validations picked for it (catalogs) */
  function pairsEditor(value, changedTo, noLimit) {
    var box = el('div', 'tmx-list tmx-pairs');
    box.id = 'tmx-pairs';
    var map = value && typeof value === 'object' ? JSON.parse(JSON.stringify(value)) : null;
    var s = segmented([['', noLimit || 'No limit'], ['on', 'Only these']], map ? 'on' : '');
    s.classList.add('small');
    box.appendChild(s);
    var list = el('div', 'tmx-pairl');
    box.appendChild(list);
    var srcs = (UI.cats && UI.cats.issuers) || [], vals = (UI.cats && UI.cats.validations) || [];
    var put = function () { changedTo(map ? JSON.parse(JSON.stringify(map)) : null); };
    var paint = function () {
      clear(list);
      list.hidden = !map;
      if (!map) return;
      Object.keys(map).forEach(function (src) {
        var row = el('div', 'tmx-pairr');
        var h = el('div', 'tmx-pairh');
        var sc = dataChip(catWord('issuers', src), 'info', 'cert');
        if (!srcs.some(function (x) { return x[0] === src; })) sc.classList.add('gone');
        h.appendChild(sc);
        h.appendChild(el('span', 'muted small', 'proved by'));
        var x = el('button', 'tmx-chip-x');
        x.type = 'button';
        x.innerHTML = iconMarkup('close', 11);
        x.setAttribute('aria-label', tr('Take it off'));
        x.onclick = function () { delete map[src]; paint(); put(); };
        h.appendChild(x);
        row.appendChild(h);
        row.appendChild(listEditor({k: 'pairs', cat: 'validations'}, map[src] || [], function (v) {
          map[src] = v || [];
          put();
        }, {always: true}));
        list.appendChild(row);
      });
      var left = srcs.filter(function (x) { return map[x[0]] === undefined; });
      if (left.length) {
        var sel = el('select', 'tmx-addsel');
        sel.id = 'tmx-pairs-add';
        var o0 = el('option', '', 'add a source…');
        o0.value = '';
        sel.appendChild(o0);
        left.forEach(function (x) { var o = data('option', '', x[1]); o.value = x[0]; sel.appendChild(o); });
        sel.onchange = function () { if (sel.value) { map[sel.value] = []; paint(); put(); } };
        list.appendChild(sel);
      } else if (!srcs.length) list.appendChild(el('span', 'muted small', 'nothing in the catalog'));
      if (!Object.keys(map).length) list.insertBefore(chip('none at all', 'crit', 'ban'), list.firstChild);
      if (!vals.length) list.appendChild(el('span', 'muted small', 'no validation in the catalog'));
    };
    s.addEventListener('change', function () {
      map = s.value === 'on' ? (map || {}) : null;
      paint();
      put();
    });
    paint();
    return box;
  }
  function fromBadge(from, here) {
    if (!from) return el('span');
    if (low(from) === low(here)) return chip('set here', 'here', 'pin');
    var b = el('button', 'tmx-from');
    b.type = 'button';
    b.appendChild(ic('tm_tree', 12));
    b.appendChild(el('span', '', 'inherited from'));
    b.appendChild(data('b', '', from));
    b.onclick = function (e) { e.stopPropagation(); choose(from); };
    return b;
  }
  function limitsTab(box, T, n) {
    var t = n.t;
    var own = JSON.parse(JSON.stringify(t.policy || {}));
    var eff = t.effective || {};
    var editing = writes() && (Object.keys(own).length > 0 || UI.limitsOpen === n.key);
    if (!Object.keys(own).length) {
      var hero = el('div', 'tmx-nolim');
      hero.id = 'tmx-nolim';
      hero.appendChild(ic('shield', 30));
      var w = el('div', 'tmx-nolim-w');
      w.appendChild(el('b', '', 'No limits of its own'));
      var effKeys = Object.keys(eff).filter(function (k) { return k !== 'from'; });
      w.appendChild(el('span', '', effKeys.length ? 'What is in force here comes from the teams above it - shown beside each limit below.'
        : 'Nothing above it limits it either: its members may do what their roles give.'));
      hero.appendChild(w);
      if (writes() && !editing) {
        var set = cmdButton('Set limits', 'edit', 'small primary');
        set.id = 'tmx-setlim';
        set.onclick = function () { UI.limitsOpen = n.key; drawTab($('tmx-body'), T, n); };
        hero.appendChild(set);
      }
      box.appendChild(hero);
    }
    var form = el('div', 'tmx-pol' + (editing ? ' edit' : ''));
    form.id = 'tmx-pol';
    box.appendChild(form);
    var bar = null, dirty = false;
    var touch = function () {
      dirty = true;
      if (bar) bar.classList.add('dirty');
    };
    catalogs().then(function () {
      POLICY_GROUPS.forEach(function (g) {
        var sec = el('section', 'tmx-polg');
        var h = el('h3', 'tmx-sec-h');
        h.appendChild(ic(g[2], 16));
        h.appendChild(el('span', '', g[1]));
        sec.appendChild(h);
        POLICY_ROWS.filter(function (p) { return p.g === g[0]; }).forEach(function (p) {
          sec.appendChild(policyRow(p, own, eff, n.name, editing, touch));
        });
        form.appendChild(sec);
      });
      if (editing) {
        bar = el('div', 'tmx-savebar');
        bar.appendChild(el('span', 'tmx-savebar-w', 'A team below may only narrow what is in force here - never widen it.'));
        var clr = cmdButton('No limits of its own', 'broom', 'small');
        clr.id = 'tmx-polclear';
        clr.onclick = function () {
          confirmThen('No limits of its own', htmlText('Every limit set on {0} is taken off; what the teams above it say stays in force.'.replace('{0}', t.name)), 'Take them off', function () {
            saveTeam(t, {policy: {}}).catch(oops);
          });
        };
        if (!Object.keys(t.policy || {}).length) clr.hidden = true;
        var sv = cmdButton('Save the limits', 'save', 'small primary');
        sv.id = 'tmx-polsave';
        sv.onclick = function () {
          busy(sv, true);
          UI.limitsOpen = null;
          saveTeam(t, {policy: cleanPolicy(own)}).then(function () { UI.tab = 'limits'; })
            .catch(oops).then(function () { busy(sv, false); });
        };
        bar.appendChild(clr);
        bar.appendChild(sv);
        box.appendChild(bar);
      }
      if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(form); } catch (e) { } }
    });
    return dirty;
  }
  function cleanPolicy(p) {
    var out = {};
    Object.keys(p).forEach(function (k) {
      var v = p[k];
      if (v === undefined || v === null || v === '') return;
      if (k === 'approval') {
        if (!v || !v.mode) return;
        var a = {mode: v.mode};
        ['approvers', 'count', 'self'].forEach(function (x) { if (v[x] !== undefined && v[x] !== null && v[x] !== '') a[x] = v[x]; });
        if (v.mode === 'outside' && v.outside) {
          var o = {};
          Object.keys(v.outside).forEach(function (x) { var y = v.outside[x]; if (y !== undefined && y !== null && y !== '') o[x] = y; });
          if (Object.keys(o).length) a.outside = o;
        }
        out.approval = a;
        return;
      }
      out[k] = v;
    });
    return out;
  }
  function policyRow(p, own, eff, here, editing, mark) {
    var row = el('div', 'tmx-prow' + (own[p.k] !== undefined ? ' own' : ''));
    row.dataset.key = p.k;
    var l = el('div', 'tmx-prow-l');
    l.appendChild(el('b', '', p.label));
    l.appendChild(el('span', 'tmx-prow-s', p.says));
    var effLine = el('div', 'tmx-prow-e');
    if (eff[p.k] !== undefined) {
      effLine.appendChild(el('span', 'tmx-prow-ek', 'in force'));
      effLine.appendChild(valueView(p, eff[p.k]));
      effLine.appendChild(fromBadge(eff.from && eff.from[p.k], here));
    } else {
      effLine.appendChild(chip('no limit', 'dim'));
    }
    l.appendChild(effLine);
    row.appendChild(l);
    var c = el('div', 'tmx-prow-c');
    row.appendChild(c);
    if (!editing) {
      if (own[p.k] !== undefined) { c.appendChild(el('span', 'tmx-prow-ek', 'its own')); c.appendChild(valueView(p, own[p.k])); }
      else c.appendChild(el('span', 'muted small', 'nothing of its own'));
      return row;
    }
    var touched = function () { row.classList.toggle('own', own[p.k] !== undefined); mark(); };
    var above = eff[p.k] !== undefined && eff.from && eff.from[p.k] && low(eff.from[p.k]) !== low(here);
    var noLimit = above ? 'As above' : 'No limit';
    if (p.type === 'bool') {
      var cur = own[p.k] === undefined ? '' : (own[p.k] ? 'yes' : 'no');
      var s = segmented([['', noLimit], ['yes', p.k === 'agents_auto_confirm' ? 'Yes' : 'Allowed', 'check'],
                         ['no', p.k === 'agents_auto_confirm' ? 'No' : 'Forbidden', 'ban']], cur);
      s.classList.add('small');
      s.addEventListener('change', function () {
        if (!s.value) delete own[p.k]; else own[p.k] = s.value === 'yes';
        touched();
      });
      c.appendChild(s);
    } else if (p.type === 'int') {
      var s2 = segmented([['', noLimit], ['on', 'At most']], own[p.k] === undefined ? '' : 'on');
      s2.classList.add('small');
      var nb = el('input', 'tmx-num');
      nb.type = 'number';
      nb.min = '1';
      nb.value = own[p.k] === undefined ? '' : own[p.k];
      nb.setAttribute('aria-label', tr(p.label));
      var unit = el('span', 'muted small', p.unit);
      var sh = function () { nb.hidden = unit.hidden = s2.value !== 'on'; };
      s2.addEventListener('change', function () {
        if (s2.value === 'on') { if (!nb.value) nb.value = eff[p.k] || (p.k === 'max_days' ? 90 : 100); own[p.k] = Number(nb.value); nb.focus(); }
        else delete own[p.k];
        sh();
        touched();
      });
      nb.addEventListener('input', function () { if (s2.value === 'on') { own[p.k] = Number(nb.value) || undefined; touched(); } });
      var line = el('div', 'tmx-intline');
      line.appendChild(s2);
      line.appendChild(nb);
      line.appendChild(unit);
      sh();
      c.appendChild(line);
    } else if (p.type === 'list') {
      c.appendChild(listEditor(p, own[p.k], function (v) {
        if (v === null) delete own[p.k]; else own[p.k] = v;
        touched();
      }, {anyWords: noLimit}));
    } else if (p.type === 'approval') {
      c.appendChild(approvalEditor(own, touched, noLimit));
    } else if (p.type === 'pairs') {
      c.appendChild(pairsEditor(own[p.k], function (v) {
        if (v === null) delete own[p.k]; else own[p.k] = v;
        touched();
      }, noLimit));
    }
    return row;
  }
  /* a list limit: no limit, or only these (chips from a catalog, or typed) */
  function listEditor(p, value, changedTo, opts) {
    opts = opts || {};
    var box = el('div', 'tmx-list');
    var list = Array.isArray(value) ? value.slice() : null;
    var s = segmented([['', opts.anyWords || 'No limit'], ['on', opts.onWords || 'Only these']], list ? 'on' : '');
    s.classList.add('small');
    if (opts.always) { list = list || []; s.value = 'on'; s.hidden = true; }    /* a list always (a pair's validations) */
    box.appendChild(s);
    var chips = el('div', 'tmx-lchips');
    box.appendChild(chips);
    var cat = (UI.cats && UI.cats[p.cat]) || null;
    var paint = function () {
      clear(chips);
      chips.hidden = !list;
      if (!list) return;
      list.forEach(function (v) {
        var c = p.cat === 'actions' ? chip(ACTION_WORDS[v] || v, 'info') : dataChip(cat ? catWord(p.cat, v) : v, 'info');
        if (cat && !cat.some(function (x) { return x[0] === v; })) c.classList.add('gone');
        var x = el('button', 'tmx-chip-x');
        x.type = 'button';
        x.innerHTML = iconMarkup('close', 11);
        x.setAttribute('aria-label', tr('Take it off'));
        x.onclick = function () { list = list.filter(function (y) { return y !== v; }); paint(); changedTo(list); };
        c.appendChild(x);
        chips.appendChild(c);
      });
      if (cat) {
        var left = cat.filter(function (x) { return list.indexOf(x[0]) < 0; });
        if (left.length) {
          var sel = el('select', 'tmx-addsel');
          var o0 = el('option', '', 'add…');
          o0.value = '';
          sel.appendChild(o0);
          left.forEach(function (x) { var o = (p.cat === 'actions' ? el : data)('option', '', x[1]); o.value = x[0]; sel.appendChild(o); });
          sel.onchange = function () { if (sel.value) { list.push(sel.value); paint(); changedTo(list); } };
          chips.appendChild(sel);
        } else if (!list.length) chips.appendChild(el('span', 'muted small', 'nothing in the catalog'));
        if (!list.length) chips.insertBefore(chip('none at all', 'crit', 'ban'), chips.firstChild);
      } else {
        var tx = textBox('', p.k === 'suffixes' || p.cat === 'free' ? 'example.com' : '', 'mono tmx-addtx');
        noI18n(tx);
        tx.onkeydown = function (e) {
          if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
            e.preventDefault();
            var v = tx.value.trim().replace(/^\*?\./, '');
            if (v && list.indexOf(v) < 0) { list.push(v); paint(); changedTo(list); }
            else tx.value = '';
          }
        };
        tx.onblur = function () { var v = tx.value.trim().replace(/^\*?\./, ''); if (v && list.indexOf(v) < 0) { list.push(v); paint(); changedTo(list); } };
        chips.appendChild(tx);
        var hint = el('span', 'muted small', 'Enter adds it');
        chips.appendChild(hint);
      }
    };
    s.addEventListener('change', function () {
      list = s.value === 'on' ? (list || []) : null;
      paint();
      changedTo(list);
      var f = chips.querySelector('select, input');
      if (f && list) f.focus();
    });
    paint();
    return box;
  }
  function approvalEditor(own, touched, noLimit) {
    var a = own.approval ? JSON.parse(JSON.stringify(typeof own.approval === 'string' ? {mode: own.approval} : own.approval)) : null;
    var box = el('div', 'tmx-appr');
    var mode = segmented([['', noLimit || 'No limit'], ['none', 'Never'], ['profile', 'Profile'], ['always', 'Always'], ['outside', 'Outside envelope']], a ? a.mode : '');
    mode.classList.add('small', 'wrap');
    mode.id = 'tmx-appr-mode';
    box.appendChild(mode);
    var says = el('div', 'tmx-appr-s muted small');
    box.appendChild(says);
    var more = el('div', 'tmx-appr-more');
    box.appendChild(more);
    var put = function () {
      if (!a) delete own.approval; else own.approval = a;
      touched();
    };
    var paint = function () {
      clear(more);
      says.textContent = a ? (MODE_SAYS[a.mode] || '') : 'As the teams above say (or the request profile).';
      if (!a || a.mode === 'none' || a.mode === 'profile') return;
      var who = selectBox(((TM.d || {}).approvers || ['team', 'parent', 'team_or_parent', 'both']).map(function (x) { return [x, APPROVER_WORDS[x] || x]; }), a.approvers || 'team');
      who.id = 'tmx-appr-who';
      who.onchange = function () { a.approvers = who.value; put(); };
      more.appendChild(formField('Who approves', who));
      var cnt = segmented([['1', 'One approval'], ['2', 'Two (four eyes)', 'eye']], String(a.count || 1));
      cnt.classList.add('small');
      cnt.addEventListener('change', function () { a.count = Number(cnt.value); put(); });
      more.appendChild(formField('How many', cnt));
      var self = switchBox(!!a.self);
      self._input.addEventListener('change', function () { a.self = self._input.checked; put(); });
      more.appendChild(formField('Their own request', self, 'On: whoever asked may approve it too.'));
      if (a.mode === 'outside') {
        a.outside = a.outside || {};
        var env = el('div', 'tmx-env');
        var eh = el('div', 'tmx-env-h');
        eh.appendChild(ic('shield', 14));
        eh.appendChild(el('b', '', 'The pre-approved envelope'));
        eh.appendChild(el('span', 'muted small', 'what stays inside it goes through at once'));
        env.appendChild(eh);
        [{k: 'profiles', cat: 'profiles', label: 'Request profiles'}, {k: 'suffixes', cat: 'free', label: 'Domains'},
         {k: 'key_types', cat: 'key_types', label: 'Key types'}].forEach(function (p) {
          env.appendChild(formField(p.label, listEditor(p, a.outside[p.k], function (v) {
            if (v === null) delete a.outside[p.k]; else a.outside[p.k] = v;
            put();
          }, {anyWords: 'Any', onWords: 'Only these'})));
        });
        var md = el('input', 'tmx-num');
        md.type = 'number';
        md.min = '1';
        md.value = a.outside.max_days || '';
        md.placeholder = tr('any');
        md.oninput = function () { if (md.value) a.outside.max_days = Number(md.value); else delete a.outside.max_days; put(); };
        env.appendChild(formField('Longest validity (days)', md));
        var wc = segmented([['', 'Any'], ['no', 'A wildcard waits', 'ban']], a.outside.wildcards === false ? 'no' : '');
        wc.classList.add('small');
        wc.id = 'tmx-env-wild';
        wc.addEventListener('change', function () { if (wc.value === 'no') a.outside.wildcards = false; else delete a.outside.wildcards; put(); });
        env.appendChild(formField('Wildcard names', wc));
        more.appendChild(env);
      }
    };
    mode.addEventListener('change', function () {
      if (!mode.value) a = null;
      else { a = a || {}; a.mode = mode.value; }
      put();
      paint();
    });
    paint();
    return box;
  }

  /* -- Devices -- */
  function devicesTab(box, T, n) {
    var mine = (UI.targets || []).filter(function (r) { return low(r.owner) === n.key; });
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'Targets owned by the team: its members with the device capabilities see, test and change them, and deploy the team\'s certificates to them.'));
    if (writes()) {
      var add = cmdButton('Assign devices', 'add', 'small primary');
      add.id = 'tmx-assign';
      add.onclick = function () { assignDevices(n); };
      head.appendChild(add);
    }
    box.appendChild(head);
    if (UI.targets && UI.targets.length && UI.targets[0].owner === undefined) {
      box.appendChild(el('p', 'note warn', 'This daemon does not say whose a target is yet.'));
    }
    if (!mine.length) {
      box.appendChild(empty('router', 'No device of the team', 'Assign targets to it - servers, load balancers, agents - and its members take care of them.'));
      return;
    }
    var list = el('div', 'tmx-dlist');
    mine.forEach(function (r) { list.appendChild(deviceRow(r, n)); });
    box.appendChild(list);
  }
  function deviceRow(r, n) {
    var agent = r.kind === 'agent' || r.kind === 'agent_windows';
    var row = el('div', 'tmx-drow');
    row.dataset.name = r.name;
    var i = el('span', 'tmx-dic' + (agent ? ' agent' : ''));
    i.innerHTML = iconMarkup(agent ? 'terminal' : 'router', 18);
    row.appendChild(i);
    var w = el('div', 'tmx-dw');
    var top = el('div', 'tmx-dtop');
    var nm = data('button', 'tmx-dname', r.name);
    nm.type = 'button';
    nm.onclick = function () { if (typeof targetPeek === 'function') targetPeek(r); };
    top.appendChild(nm);
    top.appendChild(dataChip(r.title || r.kind, 'dim'));
    w.appendChild(top);
    var st = el('div', 'tmx-dst');
    var dot = el('span', 'dot ' + (!r.enabled ? 'off' : r.last_error ? 'bad' : r.last_ok ? 'ok' : ''));
    st.appendChild(dot);
    if (!r.enabled) st.appendChild(el('span', 'muted', 'switched off'));
    else if (r.last_error) st.appendChild(data('span', 'bad tmx-derr', r.last_error));
    else if (r.last_ok) st.appendChild(el('span', 'muted', 'fine {0}'.replace('{0}', ago(r.last_ok))));
    else st.appendChild(el('span', 'muted', 'not tried yet'));
    w.appendChild(st);
    row.appendChild(w);
    if (writes() && n) {
      var x = iconButton('close', 'Take it from the team');
      x.classList.add('tmx-dfree');
      x.onclick = function () {
        call('targets/save', {id: r.id, owner: ''}).then(function () {
          toast('{0} is acme\'s own again'.replace('{0}', r.name), 'good');
          return targetsLoad();
        }).then(function () { drawView(); }).catch(oops);
      };
      row.appendChild(x);
    }
    return row;
  }
  function assignDevices(n) {
    var picked = {};
    modal('Devices for {0}'.replace('{0}', n.name), function (body) {
      body.classList.add('tmx-dlg');
      body.appendChild(el('p', 'note', 'Pick the targets that become the team\'s. A target of another team moves to this one.'));
      var f = el('div', 'tmx-find big');
      f.appendChild(ic('search', 16));
      var q = el('input', '');
      q.type = 'search';
      q.placeholder = tr('Find a target…');
      noI18n(q);
      f.appendChild(q);
      body.appendChild(f);
      var list = el('div', 'tmx-picklist');
      list.id = 'tmx-assign-list';
      body.appendChild(list);
      var paint = function () {
        clear(list);
        var w = fold(q.value).trim();
        var rows = (UI.targets || []).filter(function (r) {
          return low(r.owner) !== n.key && (!w || fold(r.name + ' ' + (r.title || r.kind)).indexOf(w) >= 0);
        });
        if (!rows.length) list.appendChild(el('p', 'muted small', 'No other target.'));
        rows.forEach(function (r) {
          var it = el('label', 'tmx-pick-it');
          var cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.checked = !!picked[r.id];
          cb.onchange = function () { if (cb.checked) picked[r.id] = r; else delete picked[r.id]; };
          it.appendChild(cb);
          it.appendChild(ic(r.kind === 'agent' || r.kind === 'agent_windows' ? 'terminal' : 'router', 16));
          it.appendChild(data('b', '', r.name));
          it.appendChild(dataChip(r.title || r.kind, 'dim'));
          if (r.owner) { var oc = dataChip(r.owner, 'violet', 'people'); it.appendChild(oc); }
          list.appendChild(it);
        });
      };
      q.oninput = paint;
      paint();
    }, [{words: 'Close', close: true},
        {words: 'Assign them', cls: 'primary', icon: 'check', go: function (b) {
          var ids = Object.keys(picked);
          if (!ids.length) { toast('pick a target', 'bad'); return; }
          busy(b, true);
          ids.reduce(function (p, id) { return p.then(function () { return call('targets/save', {id: Number(id), owner: n.name}); }); }, Promise.resolve())
            .then(function () { toast('{0} device(s) assigned'.replace('{0}', num(ids.length)), 'good'); closeModal(); return targetsLoad(); })
            .then(function () { UI.tab = 'devices'; drawView(); })
            .catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  /* -- Certificates -- */
  function certsTab(box, T, n) {
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'The certificates the team owns itself. Those of the teams below are on their own pages.'));
    var go = cmdButton('Open in Certificates', 'next', 'small');
    go.onclick = function () {
      if (typeof showTab === 'function') showTab('certs');
      setTimeout(function () {
        var o = $('ct-owner');
        if (o) {
          if (!o.querySelector('option[value="' + n.name.replace(/["\\]/g, '\\$&') + '"]')) { var op = data('option', '', n.name); op.value = n.name; o.appendChild(op); }
          o.hidden = false;
          o.value = n.name;
          o.dispatchEvent(new Event('change'));
        }
      }, 50);
    };
    head.appendChild(go);
    box.appendChild(head);
    var list = el('div', 'tmx-clist');
    list.appendChild(asking());
    box.appendChild(list);
    api('certs&owner=' + enc(n.name) + '&per=200').then(function (d) {
      clear(list);
      var rows = d.rows || d.certs || [];
      if (!rows.length) { list.appendChild(empty('lock', 'No certificate of its own', 'Certificates are given to the team where they are made or changed - or asked for by its members on the portal.')); return; }
      rows.forEach(function (c) { list.appendChild(certRow(c)); });
      if ((d.total || 0) > rows.length) list.appendChild(el('p', 'muted small', '{0} of {1} shown'.replace('{0}', num(rows.length)).replace('{1}', num(d.total))));
      if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(list); } catch (e) { } }
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'bad', String(e.message || e))); });
  }
  var CERT_STATE_WORDS = {'new': 'not issued yet', ok: 'valid', due: 'due', renewing: 'renewing', failed: 'failed',
                          expired: 'has expired', pending: 'waiting for a CA', revoked: 'revoked',
                          disabled: 'switched off', declined: 'declined', deleting: 'being revoked, then deleted',
                          'revoke-failed': 'revocation failed', held: 'added, not issued'};
  function certRow(c) {
    var st = c.state || 'new';
    var tone = st === 'ok' ? (c.days_left !== null && c.days_left !== undefined && c.days_left < 15 ? 'warn' : 'ok')
      : st === 'failed' || st === 'expired' || st === 'revoked' ? 'bad' : st === 'pending-approval' ? 'violet' : 'dim';
    var row = el('button', 'tmx-crow t-' + tone);
    row.type = 'button';
    row.dataset.id = c.id;
    row.appendChild(el('span', 'dot ' + (tone === 'bad' ? 'bad' : tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : 'off')));
    var w = el('span', 'tmx-cw');
    w.appendChild(data('b', '', c.name));
    var names = c.names || [];
    if (names.length) w.appendChild(data('span', 'mono muted small', names.slice(0, 2).join(', ') + (names.length > 2 ? ' +' + (names.length - 2) : '')));
    row.appendChild(w);
    var right = el('span', 'tmx-cr');
    if (c.not_after) {
      var dl = daysTo(c.not_after);
      right.appendChild(el('span', 'tmx-cdays ' + (dl < 0 ? 'bad' : dl < 15 ? 'warn' : ''), dl < 0 ? 'ran out' : '{0} days left'.replace('{0}', num(dl))));
    }
    /* the state in words, as the list of certificates says it (certs.js STATE): the bare
       "ok" stayed English on the Czech page */
    var stw = st === 'pending-approval' ? 'waiting' : CERT_STATE_WORDS[st] || st;
    var stc = el('span', 'tag ' + (tone === 'bad' ? 'crit' : tone === 'ok' ? 'ok' : tone === 'warn' ? 'warn' : tone === 'violet' ? 'violet' : 'dim'), stw);
    if (c.state_words) explain(stc, c.state_words);
    right.appendChild(stc);
    row.appendChild(right);
    row.onclick = function () { if (typeof certPeek === 'function') certPeek(c.id); };
    return row;
  }

  /* -- Activity -- */
  function activityTab(box, T, n) {
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'What happened to the team, its members, limits, certificates and devices.'));
    var bl = switchBox(UI.below);
    bl.id = 'tmx-below';
    var lab = el('label', 'tmx-belowl');
    lab.appendChild(bl);
    lab.appendChild(el('span', '', 'with the teams below'));
    if (n.kids.length) head.appendChild(lab);
    box.appendChild(head);
    var tl = el('div', 'tmx-tl');
    tl.id = 'tmx-tl';
    box.appendChild(tl);
    var more = cmdButton('Older', 'down', 'small');
    more.hidden = true;
    box.appendChild(more);
    var offset = 0;
    /* a scoped account sees only the names of the teams it is not in (GET /api/teams: their
       tree rows left out) - their activity is refused, so it is not asked */
    var d = TM.d || {};
    if (d.scoped && d.scoped.view && Array.isArray(d.tree)
        && !d.tree.some(function (x) { return low(x.name) === n.key; })) {
      lab.hidden = true;
      tl.appendChild(empty('history', 'Not yours to see', 'What happened in a team is shown to its members and to administrators who see every certificate.'));
      return;
    }
    var get = function () {
      busy(more, true);
      api('teams/activity&team=' + enc(n.name) + '&limit=40&offset=' + offset + (UI.below ? '&below=1' : '')).then(function (d) {
        if (!offset) clear(tl);
        var rows = d.rows || [];
        if (!rows.length && !offset) tl.appendChild(empty('history', 'Nothing yet', 'Changes of the team and what happens to its certificates and devices are listed here.'));
        var lastDay = tl._day || '';
        rows.forEach(function (r) {
          var day = dateOf(r.ts);
          if (day !== lastDay) { tl.appendChild(data('div', 'tmx-tl-day', day)); lastDay = day; }
          var it = el('div', 'tmx-tl-it lv-' + (r.level || 'info'));
          var dot = el('span', 'tmx-tl-dot');
          var wd = String(r.words || '');
          dot.innerHTML = iconMarkup(/^certificate|certificate /i.test(wd) ? 'lock' : /^target|device|agent/i.test(wd) ? 'router'
            : /member|role/i.test(wd) ? 'person' : /owner|team|limit/i.test(wd) ? 'people' : 'info', 12);
          it.appendChild(dot);
          var w = el('div', 'tmx-tl-w');
          w.appendChild(data('div', 'tmx-tl-t', known(r.words)));
          var meta = el('div', 'tmx-tl-m');
          meta.appendChild(data('span', '', clockWords(new Date(r.ts * 1000))));
          if (r.who) { meta.appendChild(ic('person', 11)); meta.appendChild(data('span', '', r.who)); }
          w.appendChild(meta);
          it.appendChild(w);
          tl.appendChild(it);
        });
        tl._day = lastDay;
        offset += rows.length;
        more.hidden = offset >= (d.total || 0);
      }).catch(function (e) { clear(tl); tl.appendChild(el('p', 'bad', String(e.message || e))); })
        .then(function () { busy(more, false); });
    };
    bl._input.addEventListener('change', function () { UI.below = bl._input.checked; offset = 0; tl._day = ''; get(); });
    more.onclick = get;
    get();
  }

  /* ---- a team: made, changed, moved, deleted -------------------------------------- */
  function editTeam(t, preset) {
    var isNew = !t;
    preset = preset || {};
    t = t || {name: '', kind: preset.kind || 'team', members: [], contact_mail: '', contact_phone: '', note: '',
              parent: preset.parent || '', description: ''};
    var f = {};
    modal(isNew ? (t.kind === 'unit' ? 'A new unit' : 'A new team') : 'The team {0}'.replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var g = el('div', 'formgrid');
      f.name = textBox(t.name, tr('Web team'), '');
      f.name.id = 'tm-f-name';
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'Letters, digits, spaces and . _ @ + - (as every name in acme). Renamed, its certificates, devices and the teams below follow.'));
      f.kind = segmented([['unit', 'a unit', KIND_ICON.unit], ['team', 'a team', KIND_ICON.team], ['person', 'a person', KIND_ICON.person]], t.kind || 'team');
      f.kind.id = 'tm-f-kind';
      g.appendChild(formField('It is', f.kind, 'A unit is a region or a site - it groups teams; a team and a person own certificates. All three may have members and limits.'));
      f.parent = teamSelect(t.parent || '', t.name);
      f.parent.id = 'tm-f-parent';
      g.appendChild(formField('Under', f.parent));
      f.desc = textBox(t.description || '', tr('what the team takes care of'), '');
      f.desc.id = 'tm-f-desc';
      noI18n(f.desc);
      var df = formField('Description', f.desc);
      df.classList.add('wide');
      g.appendChild(df);
      f.mail = textBox(t.contact_mail || '', 'web-team@example.com', 'mono');
      f.mail.id = 'tm-f-mail';
      noI18n(f.mail);
      g.appendChild(formField('Mail', f.mail, 'Told when one of its certificates fails or runs out. Comma between them.'));
      f.phone = textBox(t.contact_phone || '', '+420 …', '');
      noI18n(f.phone);
      g.appendChild(formField('Phone', f.phone, 'Only shown - who to call.'));
      f.note = textBox(t.note || '', '', '');
      noI18n(f.note);
      var nf = formField('Note', f.note);
      nf.classList.add('wide');
      g.appendChild(nf);
      body.appendChild(g);
      setTimeout(function () { f.name.focus(); }, 60);
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = {name: f.name.value.trim(), kind: f.kind.value, parent: f.parent.value || '',
                      description: f.desc.value.trim(), contact_mail: f.mail.value.trim(),
                      contact_phone: f.phone.value.trim(), note: f.note.value.trim(),
                      members: (t.members || []).map(cleanMember)};
          if (!isNew) body.old_name = t.name;
          if (!isNew && t.updated) body.was_updated = t.updated;
          busy(b, true);
          call('teams/save', body).then(function (r) {
            toast(r.message || 'saved', 'good');
            closeModal();
            if (body.parent) UI.open[low(body.parent)] = true;
            if (isNew) UI.tab = 'overview';
            return refresh(body.name);
          }).catch(function (e) {
            if (e && e.status === 409 && !isNew) { closeModal(); refresh(t.name); }
            oops(e);
          }).then(function () { busy(b, false); });
        }}], 'medium');
  }
  /* a select of the teams, indented as the tree (never the team itself or one below it) */
  function teamSelect(value, self) {
    var T = UI.T || tree();
    var no = self ? below(T, self) : {};
    if (self) no[low(self)] = 1;
    var pairs = [['', tr('the top - under no team')]];
    T.order.forEach(function (n) {
      if (no[n.key]) return;
      pairs.push([n.name, '\u00a0\u00a0'.repeat(n.depth) + (n.kind === 'unit' ? '▸ ' : '') + n.name]);
    });
    var s = selectBox(pairs, value || '');
    noI18n(s);
    return s;
  }
  /* Move to…: a searchable list of where it may go */
  function moveTeam(n) {
    var T = UI.T;
    var no = below(T, n.name);
    no[n.key] = 1;
    var to = {v: null};
    modal('Move {0}'.replace('{0}', n.name), function (body) {
      body.classList.add('tmx-dlg');
      body.appendChild(el('p', 'note', 'Where it stands decides what it inherits: the members of the teams above see and do with it what they may there, and their limits narrow its own. The teams below it move with it.'));
      body.appendChild(teamPicker(T, n.parent || '', no, function (v) { to.v = v; }, 'tmx-move-list'));
    }, [{words: 'Close', close: true},
        {words: 'Move it here', cls: 'primary', icon: 'tm_move', go: function (b) {
          if (to.v === null) { toast('choose where', 'bad'); return; }
          busy(b, true);
          if (to.v) UI.open[low(to.v)] = true;
          saveTeam(n.t, {parent: to.v || ''}).then(function () { closeModal(); }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function teamPicker(T, current, no, onPick, id) {
    var wrap = el('div', 'tmx-tpick');
    var f = el('div', 'tmx-find big');
    f.appendChild(ic('search', 16));
    var q = el('input', '');
    q.type = 'search';
    q.placeholder = tr('Find a team…');
    noI18n(q);
    f.appendChild(q);
    wrap.appendChild(f);
    var list = el('div', 'tmx-picklist');
    if (id) list.id = id;
    wrap.appendChild(list);
    var chosen = null;
    var paint = function () {
      clear(list);
      var w = fold(q.value).trim();
      var item = function (name, label, depth, kind, isCur) {
        var it = el('button', 'tmx-tp-it' + (chosen === name ? ' on' : '') + (isCur ? ' cur' : ''));
        it.type = 'button';
        it.dataset.name = name;
        it.style.paddingLeft = (10 + depth * 16) + 'px';
        it.appendChild(kind ? kindBadge(kind, 14) : ic('tm_tree', 14, 'tmx-kind k-top'));
        it.appendChild(name ? data('span', '', label) : el('span', '', label));
        if (isCur) it.appendChild(chip('now', 'dim'));
        it.onclick = function () {
          chosen = name;
          list.querySelectorAll('.on').forEach(function (x) { x.classList.remove('on'); });
          it.classList.add('on');
          onPick(name);
        };
        list.appendChild(it);
      };
      if (!w) item('', 'The top - under no team', 0, null, !current);
      T.order.forEach(function (n) {
        if (no[n.key]) return;
        if (w && fold(n.name).indexOf(w) < 0) return;
        item(n.name, n.name, w ? 0 : n.depth, n.kind, low(current) === n.key);
      });
    };
    q.oninput = paint;
    paint();
    setTimeout(function () { q.focus(); }, 60);
    return wrap;
  }
  function deleteTeam(t, n) {
    var kids = n ? n.kids.length : 0;
    if (!t.used && !kids) {
      confirmThen('Delete the team', htmlText('The team {0} is deleted. It owns no certificate and has no team below it.'.replace('{0}', t.name)), 'Delete it', function () {
        call('teams/delete', {name: t.name}).then(function (r) { toast(r.message || 'deleted', 'good'); return refresh(t.parent || null); }).catch(oops);
      });
      return;
    }
    var to = null, rp = null;
    modal('Delete the team {0}'.replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      if (t.used) {
        body.appendChild(el('p', 'note warn', 'It owns {0} certificate(s). They are given to the owner chosen here first - nothing else changes on them.'.replace('{0}', num(t.used))));
        var pairs = [['', 'nobody']].concat(((TM.d || {}).teams || []).filter(function (x) { return x.name !== t.name; })
          .map(function (x) { return [x.name, x.name]; }));
        to = selectBox(pairs, t.parent || '');
        to.id = 'tm-reassign';
        noI18n(to);
        body.appendChild(formField('Their new owner', to));
      }
      if (kids) {
        body.appendChild(el('p', 'note warn', '{0} team(s) stand under it. They move to the place chosen here.'.replace('{0}', num(kids))));
        rp = teamSelect(t.parent || '', t.name);
        rp.id = 'tm-reparent';
        body.appendChild(formField('The teams below it go under', rp));
      }
    }, [{words: 'Close', close: true},
        {words: 'Delete it', cls: 'danger', icon: 'trash', go: function (b) {
          var body = {name: t.name};
          if (to) body.reassign = to.value;
          if (rp) body.reparent = rp.value;
          busy(b, true);
          call('teams/delete', body).then(function (r) {
            toast(r.message || 'deleted', 'good');
            closeModal();
            return refresh(t.parent || null);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  /* ---- the roles: a matrix of capabilities ---------------------------------------------- */
  var GROUP_CLS = {'Certificates': 'cert', 'Deployments': 'deploy', 'Devices': 'target', 'The team': 'team'};
  var RIGHT_CAPS = {
    view: ['cert.view', 'deploy.view', 'target.view', 'team.view'],
    request: ['cert.view', 'deploy.view', 'target.view', 'team.view', 'cert.request'],
    manage: ['cert.view', 'deploy.view', 'target.view', 'team.view', 'cert.request', 'cert.renew', 'cert.auto', 'cert.edit', 'cert.revoke', 'cert.delete', 'cert.key', 'deploy.run', 'deploy.manage'],
    approve: ['cert.view', 'deploy.view', 'target.view', 'team.view', 'cert.approve']
  };
  function capGroups() {
    var out = [], at = {};
    ((TM.d || {}).caps || []).forEach(function (c) {
      var g = c.group || 'Certificates';
      if (!at[g]) { at[g] = {name: g, cls: GROUP_CLS[g] || 'cert', caps: []}; out.push(at[g]); }
      at[g].caps.push(c);
    });
    return out;
  }
  function rolesView(d) {
    var wrap = el('div', 'tmx-roles');
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'A role is a set of capabilities a member is given on a team (and every team below it). The built-in roles stay as they are - copy one to make a role of your own. The old rights view / request / manage / approve still work and give what they gave.'));
    if (writes()) {
      var add = cmdButton('A new role', 'add', 'small primary');
      add.id = 'tmx-role-add';
      add.onclick = function () { editRole(null); };
      head.appendChild(add);
    }
    wrap.appendChild(head);
    /* the roles of your own first - they are the ones changed here */
    var roles = (d.roles || []).filter(function (r) { return !r.builtin; }).concat((d.roles || []).filter(function (r) { return r.builtin; }));
    var groups = capGroups();
    var scroller = el('div', 'tmx-mx-s');
    var t = el('table', 'tmx-mx');
    t.id = 'tmx-matrix';
    var thead = el('thead');
    var hr = el('tr');
    hr.appendChild(el('th', 'tmx-mx-c0', 'Capability'));
    roles.forEach(function (r) {
      var th = el('th', 'tmx-mx-r' + (r.builtin ? ' builtin' : ' custom'));
      th.dataset.role = r.name;
      var box = el('div', 'tmx-mx-rh');
      box.appendChild(ic(r.builtin ? 'lock' : 'edit', 12, 'tmx-mx-ri'));
      box.appendChild((r.builtin ? el : data)('span', 'tmx-mx-rn', r.name));
      th.appendChild(box);
      var sub = el('div', 'tmx-mx-rs');
      sub.appendChild(data('span', 'tmx-n', num(r.caps.length)));
      if (r.used) { var u = el('span', 'tmx-mx-used', ''); u.appendChild(ic('people', 11)); u.appendChild(data('span', '', num(r.used))); explain(u, 'given to {0} member(s)'.replace('{0}', num(r.used))); sub.appendChild(u); }
      th.appendChild(sub);
      if (r.description || r.builtin) explain(th, (r.description ? known(r.description) : '') + (r.builtin ? (r.description ? ' - ' : '') + tr('built in: copy it to change it') : ''));
      if (writes()) {
        var tools = el('div', 'tmx-mx-tools');
        if (r.builtin) {
          var cp = iconButton('copy', 'Copy it to a role of your own');
          cp.classList.add('tmx-role-copy');
          cp.onclick = function () { editRole(null, r); };
          tools.appendChild(cp);
        } else {
          var ed = iconButton('edit', 'Change this role');
          ed.classList.add('tmx-role-edit');
          ed.onclick = function () { editRole(r); };
          var dl = iconButton('trash', 'Delete this role');
          dl.classList.add('tmx-role-del');
          dl.onclick = function () { deleteRole(r); };
          tools.appendChild(ed);
          tools.appendChild(dl);
        }
        th.appendChild(tools);
      }
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    t.appendChild(thead);
    var tb = el('tbody');
    groups.forEach(function (g) {
      var gr = el('tr', 'tmx-mx-g g-' + g.cls);
      var gc = el('th', '', '');
      gc.colSpan = roles.length + 1;
      gc.appendChild(el('span', 'tmx-mx-gn', g.name));
      gr.appendChild(gc);
      tb.appendChild(gr);
      g.caps.forEach(function (c) {
        var row = el('tr', 'tmx-mx-row');
        row.dataset.cap = c.id;
        var c0 = el('th', 'tmx-mx-c0');
        c0.appendChild(el('span', 'tmx-mx-cw', c.words));
        c0.appendChild(data('span', 'tmx-mx-cid g-' + g.cls, c.id));
        row.appendChild(c0);
        roles.forEach(function (r) {
          var has = r.caps.indexOf(c.id) >= 0;
          var td = el('td', 'tmx-mx-x');
          var canEdit = !r.builtin && writes();
          var mk = el(canEdit ? 'button' : 'span', 'tmx-tick' + (has ? ' on' : '') + ' g-' + g.cls + (canEdit ? ' edit' : ''));
          if (canEdit) {
            mk.type = 'button';
            mk.dataset.role = r.name;
            mk.dataset.cap = c.id;
            mk.setAttribute('aria-pressed', has ? 'true' : 'false');
            mk.setAttribute('aria-label', r.name + ': ' + c.id);
            mk.onclick = function () { toggleCap(r, c.id, mk); };
          }
          mk.innerHTML = has ? iconMarkup('check', 13) : '';
          td.appendChild(mk);
          row.appendChild(td);
        });
        tb.appendChild(row);
      });
    });
    t.appendChild(tb);
    scroller.appendChild(t);
    wrap.appendChild(scroller);
    matrixHead(scroller, t, thead);
    return wrap;
  }
  /* The matrix has no height of its own (1.0.128): it flows with the pane - one scrollbar, the
     pane's - and its headings stick to the top of the pane (position:sticky, teams.css). Wider
     than the pane, its box scrolls sideways (.wide); a box that scrolls sideways is where
     sticky stops, so then the headings are moved down here as the pane scrolls. */
  function matrixHead(box, t, thead) {
    var q = 0;
    var pane = function () {
      for (var n = box.parentElement; n && n !== document.body; n = n.parentElement) {
        if (/auto|scroll/.test(getComputedStyle(n).overflowY) && n.scrollHeight > n.clientHeight + 1) return n;
      }
      return null;
    };
    var fit = function () {
      q = 0;
      if (!box.isConnected) { stop(); return; }
      var wide = t.offsetWidth > box.clientWidth + 1;
      box.classList.toggle('wide', wide);
      var dy = 0;
      if (wide) {
        var p = pane(), r = t.getBoundingClientRect();
        dy = Math.max(0, Math.min((p ? p.getBoundingClientRect().top : 0) - r.top, r.height - thead.offsetHeight));
      }
      thead.style.transform = dy ? 'translateY(' + Math.round(dy) + 'px)' : '';
    };
    var tick = function () { if (!q) q = requestAnimationFrame(fit); };
    var ro = window.ResizeObserver ? new ResizeObserver(tick) : null;
    var stop = function () {
      document.removeEventListener('scroll', tick, true);
      window.removeEventListener('resize', tick);
      if (ro) ro.disconnect();
    };
    document.addEventListener('scroll', tick, true);
    window.addEventListener('resize', tick);
    if (ro) ro.observe(box);
    setTimeout(tick, 0);
  }
  var CAP_SAVE = {};
  function toggleCap(r, cap, mk) {
    var on = r.caps.indexOf(cap) >= 0;
    if (on && r.caps.length === 1) { toast('a role gives at least one capability', 'bad'); return; }
    r.caps = on ? r.caps.filter(function (x) { return x !== cap; }) : r.caps.concat([cap]);
    mk.classList.toggle('on', !on);
    mk.setAttribute('aria-pressed', on ? 'false' : 'true');
    mk.innerHTML = on ? '' : iconMarkup('check', 13);
    mk.classList.add('pop');
    setTimeout(function () { mk.classList.remove('pop'); }, 260);
    var th = document.querySelector('#tmx-matrix th[data-role="' + r.name.replace(/["\\]/g, '\\$&') + '"] .tmx-n');
    if (th) th.textContent = num(r.caps.length);
    clearTimeout(CAP_SAVE[r.name]);
    CAP_SAVE[r.name] = setTimeout(function () {
      call('roles/save', {name: r.name, old_name: r.name, description: r.description || '', caps: r.caps}).then(function (x) {
        toast(x.message || 'saved', 'good');
        return load(true);
      }).catch(function (e) { oops(e); refresh(); });
    }, 450);
  }
  function editRole(r, from) {
    var isNew = !r;
    var caps = (r || from || {caps: ['cert.view', 'deploy.view', 'target.view', 'team.view']}).caps.slice();
    var f = {};
    modal(isNew ? (from ? 'A copy of {0}'.replace('{0}', from.name) : 'A new role') : 'The role {0}'.replace('{0}', r.name), function (body) {
      body.classList.add('tmx-dlg');
      var g = el('div', 'formgrid');
      f.name = textBox(r ? r.name : (from ? from.name + ' ' + tr('(own)') : ''), tr('Night shift'), '');
      f.name.id = 'tmx-r-name';
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'Not a name of a built-in role or of an old right. Renamed, it is renamed on every member.'));
      f.desc = textBox(r ? r.description || '' : (from ? from.description || '' : ''), tr('what it is for'), '');
      f.desc.id = 'tmx-r-desc';
      noI18n(f.desc);
      g.appendChild(formField('What it is for', f.desc));
      body.appendChild(g);
      body.appendChild(sectionHead('tm_grid', 'Capabilities'));
      var box = el('div', 'tmx-capedit');
      box.id = 'tmx-r-caps';
      capGroups().forEach(function (gr) {
        var col = el('div', 'tmx-capcol g-' + gr.cls);
        col.appendChild(el('b', 'tmx-capcol-h', gr.name));
        gr.caps.forEach(function (c) {
          var lab = el('label', 'tmx-capt');
          var cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.value = c.id;
          cb.checked = caps.indexOf(c.id) >= 0;
          cb.onchange = function () { caps = cb.checked ? caps.concat([c.id]) : caps.filter(function (x) { return x !== c.id; }); };
          lab.appendChild(cb);
          var w = el('span', 'tmx-capt-w');
          w.appendChild(el('span', '', c.words));
          w.appendChild(data('span', 'mono tmx-capt-id', c.id));
          lab.appendChild(w);
          col.appendChild(lab);
        });
        box.appendChild(col);
      });
      body.appendChild(box);
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = {name: f.name.value.trim(), description: f.desc.value.trim(), caps: caps};
          if (!isNew) body.old_name = r.name;
          busy(b, true);
          call('roles/save', body).then(function (x) {
            toast(x.message || 'saved', 'good');
            closeModal();
            return refresh();
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'large');
  }
  function deleteRole(r) {
    var words = r.used ? 'The role {0} is deleted and taken off {1} member(s).'.replace('{0}', r.name).replace('{1}', num(r.used))
      : 'The role {0} is deleted. No member has it.'.replace('{0}', r.name);
    confirmThen('Delete the role', htmlText(words), 'Delete it', function () {
      call('roles/delete', {name: r.name, strip: !!r.used}).then(function (x) { toast(x.message || 'deleted', 'good'); return refresh(); }).catch(oops);
    });
  }

  /* ---- the access check: a person, their teams, and why --------------------------------- */
  function accessView() {
    var wrap = el('div', 'tmx-access');
    var card = el('div', 'tmx-ac-ask');
    var h = el('div', 'tmx-ac-h');
    h.appendChild(ic('tm_check', 22));
    var hw = el('div', '');
    hw.appendChild(el('b', '', 'Who may do what'));
    hw.appendChild(el('span', 'muted small', 'A person\'s teams, what they may do in each and why - through which membership, role and group, inherited from where - as the directory says now.'));
    h.appendChild(hw);
    card.appendChild(h);
    var row = el('div', 'tmx-ac-row');
    var f = el('div', 'tmx-find big');
    f.appendChild(ic('person', 16));
    var q = el('input', '');
    q.type = 'search';
    q.id = 'tmx-ac-q';
    q.placeholder = tr('local:NAME, a login or a UPN');
    q.autocomplete = 'off';
    q.value = UI.acWho || '';
    noI18n(q);
    f.appendChild(q);
    row.appendChild(f);
    var go = cmdButton('Check', 'search', 'primary');
    go.id = 'tmx-ac-go';
    row.appendChild(go);
    card.appendChild(row);
    /* a person picked from the directory by the button beside the box (1.0.128) */
    if (typeof dirPickButton === 'function') {
      dirPickButton(q, {kinds: ['user'], format: 'login', quiet: true, id: 'tmx-ac-pick', after: f,
                  picked: function () { setTimeout(function () { check(); }, 0); }});
    }
    var sugg = el('div', 'tmx-dir-list tmx-ac-sugg');
    card.appendChild(sugg);
    wrap.appendChild(card);
    var out = el('div', 'tmx-ac-out');
    out.id = 'tmx-ac-out';
    wrap.appendChild(out);
    var gen = 0;
    var suggest = debounce(function () {
      var w = q.value.trim(), mine = ++gen;
      clear(sugg);
      if (w.length < 2 || /^local:/i.test(w) || !dirs().length || w === UI.acWho) return;
      api('dir/search&q=' + enc(w) + '&kind=user&limit=6').then(function (d) {
        if (mine !== gen) return;
        (d.rows || []).forEach(function (r) {
          var it = el('button', 'tmx-dir-it');
          it.type = 'button';
          it.appendChild(avatar(r.who, 'user'));
          var w2 = el('span', 'tmx-dir-w');
          w2.appendChild(data('b', '', r.display || r.sam || r.who));
          w2.appendChild(data('span', 'muted small', r.upn || r.sam || ''));
          it.appendChild(w2);
          it.onclick = function () { q.value = r.upn || r.sam || r.who; clear(sugg); check(); };
          sugg.appendChild(it);
        });
      }).catch(function () { });
    }, 300);
    var check = function () {
      var w = q.value.trim();
      if (!w) { toast('whom?', 'bad'); return; }
      UI.acWho = w;
      gen++;
      clear(sugg);
      clear(out);
      out.appendChild(asking());
      busy(go, true);
      api('teams/access&who=' + enc(w)).then(function (d) {
        clear(out);
        out.appendChild(fade(accessResult(d)));
        if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(out); } catch (e) { } }
      }).catch(function (e) { clear(out); out.appendChild(el('p', 'bad', String(e.message || e))); })
        .then(function () { busy(go, false); });
    };
    q.addEventListener('input', suggest);
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); check(); } });
    go.onclick = check;
    if (UI.acWho) setTimeout(check, 0);
    return wrap;
  }
  function accessResult(d) {
    var box = el('div', 'tmx-ac-res');
    var who = d.who || {};
    var p = el('div', 'tmx-ac-who');
    p.appendChild(avatar(who.name || who.said || '?', 'user'));
    var w = el('div', 'tmx-ac-ww');
    w.appendChild(data('b', '', who.display || who.name || who.said || ''));
    var sub = [who.upn, who.sam, who.mail].filter(Boolean).filter(function (x, i, a) { return a.indexOf(x) === i; });
    if (sub.length) w.appendChild(data('span', 'mono small muted', sub.join(' · ')));
    if (who.dn) w.appendChild(data('span', 'mono small tmx-ac-dn', who.dn));
    p.appendChild(w);
    var tags = el('div', 'tmx-ac-tags');
    tags.appendChild(chip({local: 'account of acme', user: 'directory user', unknown: 'not found in the directory'}[who.kind] || who.kind || '', who.kind === 'unknown' ? 'warn' : 'info', WHO_ICON[who.kind] || 'person'));
    if (who.disabled) tags.appendChild(chip('disabled', 'crit'));
    if (who.directory) tags.appendChild(dataChip(who.directory, 'dim', 'tm_dir'));
    p.appendChild(tags);
    box.appendChild(p);
    if (who.kind === 'unknown' && who.said) box.appendChild(data('p', 'note warn', known(who.said)));
    if ((d.groups || []).length) {
      var gs = el('div', 'tmx-ac-groups');
      gs.appendChild(el('span', 'tmx-prow-ek', '{0} groups'.replace('{0}', num(d.groups_count || d.groups.length))));
      d.groups.slice(0, 40).forEach(function (g) { gs.appendChild(dataChip(g, 'dim', 'people')); });
      if (d.groups.length > 40) gs.appendChild(data('span', 'muted small', '+' + (d.groups.length - 40)));
      box.appendChild(gs);
    }
    var teams = d.teams || [];
    if (!teams.length) {
      box.appendChild(empty('tm_check', 'In no team', 'Nothing of acme\'s is shown to this person: no membership of any team matches them or a group they are in.'));
      return box;
    }
    var grid = el('div', 'tmx-ac-grid');
    teams.forEach(function (t) { grid.appendChild(accessCard(t)); });
    box.appendChild(grid);
    return box;
  }
  function accessCard(t) {
    var c = el('div', 'tmx-ac-card' + (!(t.caps || []).length ? ' none' : ''));
    c.dataset.team = t.team;
    var h = el('div', 'tmx-ac-ch');
    h.appendChild(kindBadge(t.kind, 16));
    var tn = data('button', 'tmx-ac-tn', t.team);
    tn.type = 'button';
    tn.onclick = function () { UI.view = 'org'; UI.team = t.team; keep(); drawPane(); };
    h.appendChild(tn);
    if (t.parent) { var pp = el('span', 'muted small'); pp.appendChild(el('span', '', 'under')); pp.appendChild(document.createTextNode(' ')); pp.appendChild(data('span', '', t.parent)); h.appendChild(pp); }
    h.appendChild(data('span', 'tmx-n', num((t.caps || []).length)));
    c.appendChild(h);
    var caps = el('div', 'tmx-ac-caps');
    if (!(t.caps || []).length) caps.appendChild(chip('nothing - the membership ended', 'crit', 'clock'));
    capGroups().forEach(function (g) {
      g.caps.forEach(function (x) {
        if ((t.caps || []).indexOf(x.id) < 0) return;
        var k = data('span', 'tmx-cap g-' + g.cls, x.id);
        explain(k, x.words);
        caps.appendChild(k);
      });
    });
    c.appendChild(caps);
    var why = el('div', 'tmx-why');
    why.appendChild(el('div', 'tmx-why-h', 'Why'));
    (t.via || []).forEach(function (v) {
      var line = el('div', 'tmx-why-l' + (v.expired ? ' expired' : ''));
      var step = function (node, cls) { var s = el('span', 'tmx-why-s ' + (cls || '')); s.appendChild(node); return s; };
      var arrow = function () { return ic('next', 12, 'tmx-why-a'); };
      var m = el('span', '');
      m.appendChild(ic(WHO_ICON[v.kind] || 'person', 12));
      m.appendChild(data('span', 'mono', shortWho(v.who)));
      line.appendChild(step(m, 'who'));
      if (v.group) { line.appendChild(arrow()); var gg = el('span', ''); gg.appendChild(el('span', '', 'through')); gg.appendChild(document.createTextNode(' ')); gg.appendChild(data('b', '', v.group)); line.appendChild(step(gg, 'grp')); }
      line.appendChild(arrow());
      var rr = el('span', 'tmx-why-r');
      (v.roles || []).forEach(function (x) { rr.appendChild(roleChip(x)); });
      (v.rights || []).forEach(function (x) { rr.appendChild(chip(RIGHT_WORDS[x] || x, 'legacy')); });
      line.appendChild(rr);
      if (v.inherited) {
        line.appendChild(arrow());
        var ih = el('button', 'tmx-from');
        ih.type = 'button';
        ih.appendChild(ic('tm_tree', 12));
        ih.appendChild(el('span', '', 'inherited from'));
        ih.appendChild(data('b', '', v.team));
        ih.onclick = function () { UI.view = 'org'; UI.team = v.team; keep(); drawPane(); };
        line.appendChild(ih);
      } else line.appendChild(chip('on this team', 'here'));
      if (v.until) line.appendChild(untilChip(v));
      why.appendChild(line);
    });
    c.appendChild(why);
    var pol = t.policy || {};
    var pk = POLICY_ROWS.filter(function (p) { return pol[p.k] !== undefined; });
    if (pk.length) {
      var lim = el('div', 'tmx-ac-lim');
      lim.appendChild(el('div', 'tmx-why-h', 'Limits in force'));
      pk.forEach(function (p) {
        var l = el('div', 'tmx-effline');
        l.appendChild(el('span', 'tmx-effk', p.label));
        l.appendChild(valueView(p, pol[p.k]));
        if (pol.from && pol.from[p.k]) l.appendChild(fromBadge(pol.from[p.k], t.team));
        lim.appendChild(l);
      });
      c.appendChild(lim);
    }
    return c;
  }

  /* ---- teams from directory groups: a wizard with a preview --------------------------- */
  function fromGroups() {
    var st = {filter: 'CN=PKI-*', role: 'Requester', parent: UI.team || '', kind: 'team', preview: null};
    var f = {picked: []};
    modal('Teams from directory groups', function (body) {
      body.classList.add('tmx-dlg', 'tmx-wiz');
      var steps = el('div', 'tmx-steps');
      [['1', 'Which groups'], ['2', 'Preview'], ['3', 'Made']].forEach(function (s, i) {
        var x = el('div', 'tmx-step' + (i === 0 ? ' on' : ''));
        x.dataset.step = s[0];
        x.appendChild(data('span', 'tmx-step-n', s[0]));
        x.appendChild(el('span', '', s[1]));
        steps.appendChild(x);
      });
      body.appendChild(steps);
      body.appendChild(el('p', 'note', 'Every group of the directory matching the filter becomes a team whose member is that group, with the role chosen. A team that is there already is left as it is. Nothing is made until the preview is confirmed.'));
      var g = el('div', 'formgrid');
      f.filter = textBox(st.filter, 'CN=PKI-*', 'mono');
      f.filter.id = 'tmx-fg-filter';
      noI18n(f.filter);
      var gItem = formField('Groups', f.filter, 'A name with * where anything may stand: CN=PKI-*, *-certs.');
      g.appendChild(gItem);
      /* ...and groups picked from the directory beside the filter (1.0.128): each a team as well;
         with the filter left empty, only those */
      var pickedBox = el('div', 'tmx-fg-picked');
      pickedBox.id = 'tmx-fg-picked';
      var paintPicked = function () {
        clear(pickedBox);
        if (!f.picked.length) {
          pickedBox.appendChild(el('span', 'muted small', 'Or pick groups from the directory with the search button beside the filter.'));
          return;
        }
        pickedBox.appendChild(el('span', 'muted small', 'Picked from the directory - besides what the filter finds (leave it empty for these alone):'));
        var chips = el('div', 'tmx-fg-chips');
        f.picked.forEach(function (p) {
          var c = el('span', 'chip tmx-fg-chip');
          c.dataset.dn = p.dn;
          var w = data('span', 'mono', p.cn);
          explain(w, p.dn);
          c.appendChild(w);
          var x = iconButton('close', 'Take it out');
          x.onclick = function () {
            f.picked = f.picked.filter(function (y) { return y !== p; });
            fromGroups._ok = false;
            paintPicked();
          };
          c.appendChild(x);
          chips.appendChild(c);
        });
        pickedBox.appendChild(chips);
      };
      var pickedAt = function (r) {
        var dn = low(r.dn || r.who);
        return f.picked.filter(function (p) { return low(p.dn) === dn; })[0] || null;
      };
      if (typeof dirPickButton === 'function') {
        dirPickButton(f.filter, {kinds: ['group'], id: 'tmx-fg-pick', title: 'Pick groups from the directory',
          format: function (r) { return r.dn || r.who; },
          has: function (r) { return !!pickedAt(r); },
          toggle: function (r) {
            var was = pickedAt(r);
            if (was) f.picked = f.picked.filter(function (p) { return p !== was; });
            else f.picked.push({dn: r.dn || r.who, cn: r.cn || r.who});
            fromGroups._ok = false;
            paintPicked();
          }});
        gItem.appendChild(pickedBox);
        paintPicked();
      }
      f.role = selectBox(((TM.d || {}).roles || []).map(function (r) { return [r.name, r.name]; }), st.role);
      f.role.id = 'tmx-fg-role';
      g.appendChild(formField('The group\'s role', f.role));
      f.parent = teamSelect(st.parent, null);
      f.parent.id = 'tmx-fg-parent';
      g.appendChild(formField('Under', f.parent));
      f.kind = segmented([['team', 'Teams', KIND_ICON.team], ['unit', 'Units', KIND_ICON.unit]], 'team');
      g.appendChild(formField('They are', f.kind));
      /* the filter, the role, where and what changed after the preview: what the preview
         showed is no longer what would be made - previewed again first */
      var stale = function () { fromGroups._ok = false; };
      g.addEventListener('input', stale);
      g.addEventListener('change', stale);
      f.kind.addEventListener('change', stale);     /* its 'change' does not bubble */
      body.appendChild(g);
      var prev = el('div', 'tmx-fg-prev');
      prev.id = 'tmx-fg-prev';
      body.appendChild(prev);
      fromGroups._prev = prev;
      fromGroups._steps = steps;
    }, [{words: 'Close', close: true},
        {words: 'Preview', icon: 'eye', go: function (b) { fgRun(f, true, b); }},
        writes() ? {words: 'Make the teams', cls: 'primary', icon: 'add', go: function (b) {
          if (!fromGroups._ok) { toast('see the preview first', 'bad'); return; }
          fgRun(f, false, b);
        }} : null].filter(Boolean), 'large');
    fromGroups._ok = false;
  }
  function fgStep(n) {
    var s = fromGroups._steps;
    if (!s) return;
    s.querySelectorAll('.tmx-step').forEach(function (x) { x.classList.toggle('on', Number(x.dataset.step) <= n); });
  }
  function fgRun(f, dry, b) {
    var prev = fromGroups._prev;
    var body = {filter: f.filter.value.trim(), role: f.role.value, parent: f.parent.value || '', kind: f.kind.value, dry_run: dry};
    /* the groups picked from the directory go with the filter - and only when there are some,
       so what is sent with none is what it always was */
    if ((f.picked || []).length) body.groups = f.picked.map(function (p) { return p.dn; });
    if (!body.filter && !body.groups) { toast('which groups?', 'bad'); return; }
    busy(b, true);
    clear(prev);
    prev.appendChild(asking());
    call('teams/from_groups', body).then(function (d) {
      clear(prev);
      var gs = d.groups || [];
      fromGroups._ok = dry && gs.some(function (x) { return !x.exists; });
      fgStep(dry ? 2 : 3);
      var head = el('div', 'tmx-fg-h');
      var fresh = gs.filter(function (x) { return !x.exists; }).length;
      head.appendChild(chip('{0} group(s) found'.replace('{0}', num(gs.length)), 'info', 'people'));
      head.appendChild(chip((dry ? '{0} team(s) to make' : '{0} team(s) made').replace('{0}', num(dry ? fresh : (d.made || []).length)), 'ok', 'add'));
      if (gs.length - fresh) head.appendChild(chip('{0} there already'.replace('{0}', num(gs.length - fresh)), 'dim'));
      if (d.capped) head.appendChild(chip('only the first 500', 'warn'));
      prev.appendChild(head);
      if (!gs.length) { prev.appendChild(el('p', 'muted', 'No group matches the filter.')); return; }
      prev.appendChild(listTable(['Group', 'Team', 'Already in', ''], gs, function (x) {
        var r = el('tr', 'tmx-fg-row' + (x.exists ? ' exists' : ''));
        r.dataset.cn = x.cn;
        var c1 = el('td', '');
        c1.appendChild(data('b', '', x.cn));
        if (x.description) c1.appendChild(data('div', 'muted small', x.description));
        r.appendChild(c1);
        var c2 = el('td', '');
        var tw = el('span', 'tmx-fg-team');
        tw.appendChild(kindBadge(body.kind, 13));
        tw.appendChild(data('span', '', x.team));
        c2.appendChild(tw);
        r.appendChild(c2);
        var c3 = el('td', 'small');
        (x.member_of || []).forEach(function (m) { c3.appendChild(dataChip(m, 'dim')); });
        r.appendChild(c3);
        var c4 = el('td', '');
        c4.appendChild(x.exists ? chip('there already', 'dim') : chip(dry ? 'new' : (x.made ? 'made' : 'not made'), x.made || dry ? 'ok' : 'crit', x.made ? 'check' : 'add'));
        r.appendChild(c4);
        return r;
      }, 'plain tmx-fg-table'));
      if (!dry) {
        if (body.parent) UI.open[low(body.parent)] = true;
        changed().then(drawPane);
      }
    }).catch(function (e) { clear(prev); prev.appendChild(el('p', 'bad', String(e.message || e))); })
      .then(function () { busy(b, false); });
  }


  /* ---- the tags ---------------------------------------------------------------- */
  function shortWho(who) {
    var m = /^\s*(?:group:)?cn=((?:\\.|[^,])+)/i.exec(who);
    return m ? 'group:' + m[1].replace(/\\(.)/g, '$1') : who;
  }


  function tagsCard(d) {
    var card = el('div', 'card full tm');
    var h = el('h2', '', 'Tags');
    var right = el('span', 'right btnrow');
    if (full()) {
      var add = cmdButton('Add a tag', 'add', 'small primary');
      add.id = 'tm-tag-add';
      add.onclick = function () { editTag(null); };
      right.appendChild(add);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'The words certificates and targets are found and grouped by, each with its colour and what it means - picked from this list, never typed. Renamed here, a tag is renamed on everything that carries it.'));
    /* none yet: said as the pane's other empty places say it, not an empty table's one line
       (the button that adds the first one above it) */
    if (!(d.tags || []).length) {
      card.appendChild(empty('tm_tag', 'No tag yet', 'Tags group certificates and targets across teams - prod, pci, legacy… - each with its colour and what it means.'));
      return card;
    }
    card.appendChild(listTable(['Tag', 'What it means', {words: 'Certificates', cls: 'num'}, {words: 'Targets', cls: 'num'}, ''],
      d.tags || [], function (t) {
        var tr_ = el('tr', 'tm-tagrow');
        tr_.dataset.name = t.name;
        tr_.appendChild(cell('', tagChip(t.name)));
        tr_.appendChild(cell('small', t.description ? data('span', '', t.description) : el('span', 'muted', '–')));
        tr_.appendChild(cell('num', num(t.certs || 0)));
        tr_.appendChild(cell('num', num(t.targets || 0)));
        var tools = el('td', 'rowtools');
        if (full()) {
          var ed = iconButton('edit', 'Edit this tag');
          ed.onclick = function () { editTag(t); };
          tools.appendChild(ed);
          var del = iconButton('trash', 'Delete this tag');
          del.onclick = function () { deleteTag(t); };
          tools.appendChild(del);
        }
        tr_.appendChild(tools);
        return tr_;
      }, 'plain tm-tagtable|No tag yet'));
    return card;
  }

  function legacyCard(lg) {
    var card = el('div', 'card full tm tm-legacy');
    var h = el('h2', '', 'Not defined yet');
    var right = el('span', 'right btnrow');
    if (full()) {
      var all = cmdButton('Make teams and tags from what certificates say now', 'add', 'small primary');
      all.id = 'tm-adopt-all';
      all.onclick = function () {
        confirmThen('Make teams and tags', htmlText(tr('Every owner below becomes a team whose one member is what the certificate said (so the portal shows it to the same people as before), every tag a tag of the list. Nothing is taken away.')),
          'Make them', function () {
            call('teams/adopt', {}).then(function (r) { toast(r.message || 'made', 'good'); return changed(); })
              .then(drawPane).catch(oops);
          }, false);
      };
      right.appendChild(all);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'What certificates say that is in neither list - typed as text before. It stays as it is until it is made an owner or a tag here.'));
    var rows = (lg.owners || []).map(function (o) { return {what: 'owner', name: o.owner, certs: o.certs, targets: 0}; })
      .concat((lg.tags || []).map(function (t) { return {what: 'tag', name: t.tag, certs: t.certs, targets: t.targets}; }));
    card.appendChild(listTable(['What', 'Said', {words: 'Certificates', cls: 'num'}, {words: 'Targets', cls: 'num'}, ''], rows, function (r) {
      var tr_ = el('tr', 'tm-legacy-row');
      tr_.appendChild(cell('', el('span', 'tag dim', r.what === 'owner' ? 'owner' : 'tag')));
      tr_.appendChild(cell('mono small', data('span', '', r.name)));
      tr_.appendChild(cell('num', num(r.certs)));
      tr_.appendChild(cell('num', num(r.targets)));
      var tools = el('td', 'rowtools');
      if (full()) {
        var mk = cmdButton(r.what === 'owner' ? 'Make it an owner' : 'Make it a tag', 'add', 'small');
        mk.onclick = function () {
          var b = r.what === 'owner' ? {owner: r.name} : {tag: r.name};
          /* once (1.0.119: pressed twice, the second said "there is an owner ... already") */
          if (mk.disabled) return;
          busy(mk, true);
          call('teams/adopt', b).then(function (x) { toast(x.message || 'made', 'good'); return changed(); })
            .then(drawPane).catch(function (e) { busy(mk, false); oops(e); });
        };
        tools.appendChild(mk);
      }
      tr_.appendChild(tools);
      return tr_;
    }, 'plain'));
    return card;
  }


  function accounts() {
    if (TM.users) return Promise.resolve(TM.users);
    return api('users').then(function (d) {
      TM.users = (d.users || []).filter(function (u) { return u.source !== 'directory'; })
        .map(function (u) { return u.name; });
      return TM.users;
    }).catch(function () { return []; });
  }


  function kindOf(who) {
    var w = low(who);
    if (w.indexOf('local:') === 0) return 'local';
    if (w.indexOf('group:') === 0 || w.indexOf('cn=') === 0 || (w.indexOf('=') > 0 && w.indexOf(',') > 0)) return 'group';
    return 'user';
  }


  /* ---- a tag: its dialog --------------------------------------------------------- */
  function editTag(t) {
    var isNew = !t;
    t = t || {name: '', colour: 'dim', description: ''};
    var f = {};
    var colours = (TM.d && TM.d.colours) || Object.keys(COLOUR_WORDS);
    modal(isNew ? 'A new tag' : 'The tag ' + t.name, function (body) {
      var g = el('div', 'formgrid');
      f.name = textBox(t.name, 'prod', 'mono');
      f.name.id = 'tm-t-name';
      noI18n(f.name);
      g.appendChild(formField('Tag', f.name, 'One word: letters, digits and . _ : + -. Renamed, it is renamed on every certificate and target.'));
      f.colour = colourPicker(colours, t.colour || 'dim', function () { return f.name.value.trim(); });
      f.colour.id = 'tm-t-colour';
      var paint = function () { f.colour._repaint(); };
      f.name.oninput = paint;
      var cf = formField('Colour', f.colour);
      g.appendChild(cf);
      f.desc = textBox(t.description || '', tr('what it means'), '');
      noI18n(f.desc);
      var df = formField('What it means', f.desc);
      df.classList.add('wide');
      g.appendChild(df);
      body.appendChild(g);
      paint();
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = {name: f.name.value.trim(), colour: f.colour.value, description: f.desc.value.trim()};
          if (!isNew) body.old_name = t.name;
          busy(b, true);
          call('tags/save', body).then(function (r) {
            toast(r.message || 'saved', 'good');
            closeModal();
            return changed().then(drawPane);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function deleteTag(t) {
    var n = (t.certs || 0) + (t.targets || 0);
    var words = n ? tr('The tag {0} is deleted and taken off {1} certificate(s) and {2} target(s).')
      .replace('{0}', t.name).replace('{1}', num(t.certs || 0)).replace('{2}', num(t.targets || 0))
      : tr('The tag {0} is deleted. Nothing carries it.').replace('{0}', t.name);
    confirmThen('Delete the tag', htmlText(words), 'Delete it', function () {
      call('tags/delete', {name: t.name, strip: n > 0}).then(function (r) { toast(r.message || 'deleted', 'good'); return changed(); })
        .then(drawPane).catch(oops);
    });
  }



  /* ==== Governance (1.0.138, docs/teams.md "Governance") ===================================
     Who may do what and why (a matrix, each cell saying why), view as, temporary roles, access
     reviews, separation of duties, templates and CSV import, the team's channels and the
     escalation chain, the teams' health. Everything from /api/teams/* (api_teamgov.py); a full
     administrator changes, the others see. */
  var CAP_SHORT = function (id) { return String(id).split('.')[1] || id; };
  var GOV = {who: null, mode: 'person', team: '', cap: 'cert.key', target: '', cert: '', health: null,
             hsort: 'worst', hq: '', hshow: 60, rshow: 200};
  function govIcons() {
    if (typeof ICONS !== 'object' || ICONS.tmg_who) return;
    ICONS.tmg_who = '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 3-5.8 6.5-5.8"/><rect x="13" y="12" width="8.5" height="8.5" rx="1.6"/><path d="M15.3 16.3l1.5 1.5 2.6-2.8"/>';
    ICONS.tmg_heart = '<path d="M12 20s-7.5-4.6-7.5-10.1A4.3 4.3 0 0 1 12 7.3a4.3 4.3 0 0 1 7.5 2.6C19.5 15.4 12 20 12 20z"/><path d="M7.5 12.5h2.6l1.4-2.4 2 4.3 1.3-1.9h1.7"/>';
    ICONS.tmg_inbox = '<path d="M3 13l3-8h12l3 8v6H3z"/><path d="M3 13h5l1.5 2.5h5L16 13h5"/>';
    ICONS.tmg_tpl = '<rect x="3" y="3" width="13" height="13" rx="2.2"/><path d="M8 21h11a2 2 0 0 0 2-2V8"/><path d="M7 7.5h5M7 11h3"/>';
    ICONS.tmg_gov = '<path d="M12 3l8 3.4v5.3c0 4.6-3.3 8.1-8 9.3-4.7-1.2-8-4.7-8-9.3V6.4z"/><path d="M8.6 12.2l2.3 2.3 4.5-4.8"/>';
    ICONS.tmg_up = '<path d="M12 19V5"/><path d="M6 11l6-6 6 6"/>';
    ICONS.tmg_pair = '<circle cx="7" cy="12" r="4"/><circle cx="17" cy="12" r="4"/><path d="M4 20L20 4"/>';
    ICONS.tmg_chain = '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>';
  }
  govIcons();
  function fullAdmin() { return role() === 'fulladmin'; }
  function teamNames() { return ((UI.T || tree()).order || []).map(function (n) { return n.name; }); }
  function teamPick(value, id, none) {
    var T = UI.T || tree();
    var pairs = none ? [['', none]] : [];
    T.order.forEach(function (n) { pairs.push([n.name, '  '.repeat(Math.min(n.depth, 8)) + n.name]); });
    var s = selectBox(pairs, value || (pairs[0] ? pairs[0][0] : ''));
    if (id) s.id = id;
    noI18n(s);
    return s;
  }
  function whenText(ts) { return ts ? stamp(ts) : '–'; }
  function leftWords(ts) {
    var s = Number(ts) - Date.now() / 1000;
    if (s <= 0) return tr('ended');
    if (s < 3600) return 'ends in {0} min'.replace('{0}', num(Math.max(1, Math.round(s / 60))));
    if (s < 86400 * 2) return 'ends in {0} h'.replace('{0}', num(Math.round(s / 3600)));
    return 'ends in {0} days'.replace('{0}', num(Math.round(s / 86400)));
  }
  var STATE_TONE = {waiting: 'violet', granted: 'ok', declined: 'crit', cancelled: 'dim', ended: 'dim', expired: 'dim',
                    open: 'info', overdue: 'warn', done: 'ok', closed: 'dim', kept: 'ok', removed: 'crit', pending: 'warn'};
  var STATE_WORDS = {waiting: 'waiting', granted: 'granted', declined: 'declined', cancelled: 'taken back',
                     ended: 'ended early', expired: 'ended', open: 'open', overdue: 'overdue', done: 'done',
                     closed: 'closed', kept: 'confirmed', removed: 'taken out', pending: 'to confirm'};
  function stateChip(st) { return chip(STATE_WORDS[st] || st, STATE_TONE[st] || 'dim'); }
  function govCard(icon, title, sub, tone) {
    var c = el('section', 'tmx-sec tmg-card' + (tone ? ' ' + tone : ''));
    var h = el('h3', 'tmx-sec-h');
    h.appendChild(ic(icon, 16));
    h.appendChild(el('span', '', title));
    c.appendChild(h);
    if (sub) c.appendChild(el('p', 'muted small tmg-sub', sub));
    c._head = h;
    return c;
  }
  function headButton(card, b) {
    var r = card._head.querySelector('.tmg-hb');
    if (!r) { r = el('span', 'tmg-hb'); card._head.appendChild(r); }
    r.appendChild(b);
    return b;
  }
  function personLine(who, kind, sub) {
    var r = el('div', 'tmg-person');
    r.appendChild(avatar(who, kind || kindOf(who)));
    var w = el('div', 'tmg-person-w');
    w.appendChild(data('b', '', shortWho(who)));
    if (sub) w.appendChild(sub instanceof Node ? sub : el('span', 'muted small', sub));
    r.appendChild(w);
    return r;
  }

  /* ---- the banner while viewing as somebody (every page of the administration) -------------- */
  function viewAsBanner(va) {
    var old = $('tmg-viewas');
    if (old) old.parentNode.removeChild(old);
    if (!va) { document.body.classList.remove('tmg-viewing'); return; }
    var b = el('div', 'tmg-viewas');
    b.id = 'tmg-viewas';
    b.setAttribute('role', 'status');
    b.appendChild(ic('eye', 18));
    var w = el('span', 'tmg-viewas-w');
    w.appendChild(el('span', '', 'You see the pages as'));
    w.appendChild(document.createTextNode(' '));
    w.appendChild(data('b', '', va.display || va.name || va.who || '?'));
    if (va.role) { w.appendChild(document.createTextNode(' ')); w.appendChild(chip({fulladmin: 'full administrator', certadmin: 'certificate administrator', readonly: 'read-only account'}[va.role] || va.role, 'dim')); }
    w.appendChild(document.createTextNode(' '));
    w.appendChild(el('span', 'tmg-viewas-ro', '- read-only: nothing is changed'));
    b.appendChild(w);
    var stop = cmdButton('Stop viewing as', 'close', 'small');
    stop.id = 'tmg-viewas-stop';
    stop.onclick = function () {
      busy(stop, true);
      api('teams/view_as_stop', {}).then(function () { location.reload(); })
        .catch(function (e) { busy(stop, false); oops(e); });
    };
    b.appendChild(stop);
    document.body.insertBefore(b, document.body.firstChild);
    document.body.classList.add('tmg-viewing');
  }
  function viewAsCheck() {
    var va = (typeof ME === 'object' && ME) ? ME.view_as : null;
    if (va) { viewAsBanner(va); return; }
    api('teams/view_as').then(function (d) { if (d && d.active) viewAsBanner(d.view_as); }).catch(function () { });
  }
  function viewAs(who, portal) {
    if (!who) return;
    if (portal) {
      api('teams/view_as_portal', {who: who}).then(function (d) {
        var w = window.open(d.url, '_blank', 'noopener');
        if (!w) location.href = d.url;
        toast(tr('The portal opens as {0} - read-only').replace('{0}', d.who), 'good');
      }).catch(oops);
      return;
    }
    confirmThen('View as {0}'.replace('{0}', shortWho(who)),
      htmlText(tr('The administration is shown as {0} sees it - their role, their teams. Nothing can be changed meanwhile; it is written in the events. Stop it with the button at the top.').replace('{0}', who)),
      'View as', function () {
        api('teams/view_as', {who: who}).then(function () { location.reload(); }).catch(oops);
      });
  }
  function viewAsChoose(who) {
    modal(tr('View as {0}').replace('{0}', shortWho(who)), function (body) {
      body.classList.add('tmx-dlg');
      body.appendChild(el('p', 'note', 'See what this member sees - read-only: nothing can be changed meanwhile, and it is written in the events (and the team\'s activity).'));
      var opts = el('div', 'tmg-vachoose');
      [['admin', 'The administration', 'gear', 'Their role and teams, here - if they sign in to the administration.'],
       ['portal', 'The portal', 'globe', 'In a new tab, as they sign in there - for two hours at most.']].forEach(function (o) {
        var b = el('button', 'tmg-vaopt');
        b.type = 'button';
        b.id = 'tmg-va-' + o[0];
        b.appendChild(ic(o[2], 22));
        var w = el('span', 'tmg-vaopt-w');
        w.appendChild(el('b', '', o[1]));
        w.appendChild(el('span', 'muted small', o[3]));
        b.appendChild(w);
        b.onclick = function () {
          closeModal(true);
          if (o[0] === 'portal') viewAs(who, true);
          else api('teams/view_as', {who: who}).then(function () { location.reload(); }).catch(oops);
        };
        opts.appendChild(b);
      });
      body.appendChild(opts);
    }, [{words: 'Close', close: true}], true);
  }
  function viewAsButtons(who, box) {
    if (!fullAdmin() || !who || /^group:/i.test(who) || kindOf(who) === 'group') return;
    var a = cmdButton('View as', 'eye', 'small');
    a.classList.add('tmg-va-admin');
    explain(a, 'Open the administration as this person sees it - read-only.');
    a.onclick = function () { viewAs(who, false); };
    var p = cmdButton('Open the portal as', 'globe', 'small');
    p.classList.add('tmg-va-portal');
    explain(p, 'Open the portal in a new tab as this person sees it - read-only, for two hours at most.');
    p.onclick = function () { viewAs(who, true); };
    box.appendChild(a);
    box.appendChild(p);
  }

  /* ---- Who may do what and why --------------------------------------------------------------- */
  function whomayView() {
    var wrap = el('div', 'tmg-whomay');
    var card = el('div', 'tmx-ac-ask');
    var h = el('div', 'tmx-ac-h');
    h.appendChild(ic('tmg_who', 22));
    var hw = el('div', '');
    hw.appendChild(el('b', '', 'Who may do what - and why'));
    hw.appendChild(el('span', 'muted small', 'Every capability across the tree of teams and the roles, each with the reason: which role or right, on which team, inherited from where, ending when. The same answer the server enforces.'));
    h.appendChild(hw);
    card.appendChild(h);
    var seg = segmented([['person', 'A person', 'person'], ['team', 'A team', 'people'], ['cap', 'Who may…', 'search']], GOV.mode);
    seg.id = 'tmg-wm-mode';
    seg.classList.add('tmg-mode');
    card.appendChild(seg);
    var form = el('div', 'tmg-wm-form');
    card.appendChild(form);
    wrap.appendChild(card);
    var out = el('div', 'tmg-wm-out');
    out.id = 'tmg-wm-out';
    wrap.appendChild(out);
    var run = function (what, after) {
      clear(out);
      out.appendChild(asking());
      api(what).then(function (d) {
        clear(out);
        out.appendChild(fade(after(d)));
        if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(out); } catch (e) { } }
      }).catch(function (e) { clear(out); out.appendChild(data('p', 'bad', String(e.message || e))); });
    };
    var paint = function () {
      clear(form);
      clear(out);
      var row = el('div', 'tmx-ac-row');
      form.appendChild(row);
      if (GOV.mode === 'person') {
        var f = el('div', 'tmx-find big');
        f.appendChild(ic('person', 16));
        var q = el('input', '');
        q.type = 'search';
        q.id = 'tmg-wm-who';
        q.placeholder = tr('local:NAME, a login or a UPN');
        q.value = GOV.who || '';
        noI18n(q);
        f.appendChild(q);
        row.appendChild(f);
        var go = cmdButton('Show', 'search', 'primary');
        go.id = 'tmg-wm-go';
        row.appendChild(go);
        if (typeof dirPickButton === 'function') {
          dirPickButton(q, {kinds: ['user'], format: 'login', quiet: true, after: f,
                            picked: function () { setTimeout(function () { go.click(); }, 0); }});
        }
        var check = function () {
          var w = q.value.trim();
          if (!w) { toast('whom?', 'bad'); return; }
          GOV.who = w;
          run('teams/whomay&who=' + enc(w), personResult);
        };
        q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); check(); } });
        go.onclick = check;
        if (GOV.who) setTimeout(check, 0);
      } else if (GOV.mode === 'team') {
        var s = teamPick(GOV.team || UI.team, 'tmg-wm-team');
        row.appendChild(formField('Team', s));
        var go2 = cmdButton('Show', 'search', 'primary');
        go2.id = 'tmg-wm-go';
        row.appendChild(go2);
        go2.onclick = function () {
          GOV.team = s.value;
          if (!s.value) return;
          run('teams/whomay&team=' + enc(s.value), teamResult);
        };
        if (s.value) setTimeout(function () { go2.click(); }, 0);
      } else {
        var caps = [];
        capGroups().forEach(function (g) { g.caps.forEach(function (c) { caps.push([c.id, c.id + ' - ' + c.words]); }); });
        var cs = selectBox(caps, GOV.cap);
        cs.id = 'tmg-wm-cap';
        row.appendChild(formField('May', cs));
        var on = segmented([['team', 'on a team'], ['cert', 'on a certificate']], GOV.target || 'team');
        on.classList.add('small');
        row.appendChild(on);
        var holder = el('div', 'tmg-wm-target');
        row.appendChild(holder);
        var ts = teamPick(GOV.team || UI.team, 'tmg-wm-cteam');
        var cert = textBox(GOV.cert, tr('a certificate\'s name or number'));
        cert.id = 'tmg-wm-cert';
        noI18n(cert);
        var paintTarget = function () {
          clear(holder);
          holder.appendChild(on.value === 'cert' ? formField('Certificate', cert) : formField('Team', ts));
        };
        on.addEventListener('change', function () { GOV.target = on.value; paintTarget(); });
        paintTarget();
        var go3 = cmdButton('Who?', 'search', 'primary');
        go3.id = 'tmg-wm-go';
        row.appendChild(go3);
        go3.onclick = function () {
          GOV.cap = cs.value;
          GOV.team = ts.value;
          GOV.cert = cert.value.trim();
          var q2 = 'teams/whocan&cap=' + enc(cs.value) + (on.value === 'cert' ? '&cert=' + enc(GOV.cert) : '&team=' + enc(ts.value));
          run(q2, whoCanResult);
        };
        cert.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go3.click(); } });
      }
    };
    seg.addEventListener('change', function () { GOV.mode = seg.value; paint(); });
    paint();
    return wrap;
  }
  function legend() {
    var l = el('div', 'tmg-legend');
    [['d', 'on the team itself'], ['i', 'inherited from a team above'], ['j', 'a temporary role'], ['l', 'held, but its limits narrow it']].forEach(function (x) {
      var it = el('span', 'tmg-leg');
      it.appendChild(el('span', 'tmg-dot ' + x[0]));
      it.appendChild(el('span', '', x[1]));
      l.appendChild(it);
    });
    return l;
  }
  /* rows x capabilities; rows: {label node, caps, cells: {cap: [via idx]}, via, limits} */
  function capMatrix(rows, onCell, rowHead) {
    var groups = capGroups();
    var box = el('div', 'tmx-mx-s tmg-mx-s wide');
    var t = el('table', 'tmx-mx tmg-mx');
    var thead = el('thead');
    var g1 = el('tr', 'tmg-mx-gh');
    var c0 = el('th', 'tmx-mx-c0', rowHead || '');
    c0.rowSpan = 2;
    g1.appendChild(c0);
    groups.forEach(function (g) {
      var th = el('th', 'tmg-mx-g g-' + g.cls, g.name);
      th.colSpan = g.caps.length;
      g1.appendChild(th);
    });
    thead.appendChild(g1);
    var g2 = el('tr');
    groups.forEach(function (g) {
      g.caps.forEach(function (c, i) {
        var th = el('th', 'tmg-mx-cap g-' + g.cls + (i === 0 ? ' first' : ''));
        th.appendChild(data('span', '', CAP_SHORT(c.id)));
        explain(th, c.id + ' - ' + known(c.words));
        th.dataset.cap = c.id;
        g2.appendChild(th);
      });
    });
    thead.appendChild(g2);
    t.appendChild(thead);
    var tb = el('tbody');
    var shown = 0;
    var addRows = function (upto) {
      rows.slice(shown, upto).forEach(function (r, ri) {
        var tr_ = el('tr', 'tmg-mx-row' + (r.cls ? ' ' + r.cls : ''));
        var h = el('th', 'tmx-mx-c0');
        h.appendChild(r.label);
        tr_.appendChild(h);
        groups.forEach(function (g) {
          g.caps.forEach(function (c, i) {
            var td = el('td', 'tmg-mx-x' + (i === 0 ? ' first' : ''));
            var held = (r.caps || []).indexOf(c.id) >= 0;
            if (held) {
              var idx = (r.cells || {})[c.id] || [];
              var vias = idx.map(function (k) { return (r.via || [])[k]; }).filter(Boolean);
              var kind = !vias.length ? 'a' : vias.some(function (v) { return v.jit; }) ? 'j'
                : vias.some(function (v) { return !v.inherited; }) ? 'd' : 'i';
              var lim = (r.limits || {})[c.id];
              var b = el('button', 'tmg-cell');
              b.type = 'button';
              b.dataset.cap = c.id;
              b.appendChild(el('span', 'tmg-dot ' + kind + (lim ? ' l' : '')));
              b.setAttribute('aria-label', r.name + ': ' + c.id);
              var words = !vias.length ? tr(r.why || '') : vias.map(function (v) {
                return (v.roles || []).concat(v.rights || []).join(', ') + ' - ' + (v.inherited ? tr('inherited from') + ' ' + v.team : tr('in the team') + ' ' + v.team);
              }).join(' · ');
              if (lim) words += ' · ' + lim;
              explain(b, c.id + ': ' + words);
              b.onclick = function () {
                tb.querySelectorAll('.tmg-cell.on').forEach(function (x) { x.classList.remove('on'); });
                b.classList.add('on');
                onCell(r, c, vias, lim);
              };
              td.appendChild(b);
            }
            tr_.appendChild(td);
          });
        });
        tb.appendChild(tr_);
      });
      shown = Math.min(upto, rows.length);
    };
    addRows(GOV.rshow);
    t.appendChild(tb);
    box.appendChild(t);
    var wrap = el('div', 'tmg-mx-wrap');
    wrap.appendChild(box);
    if (rows.length > shown) {
      var more = cmdButton('Show more', 'down', 'small');
      more.classList.add('tmg-more');
      more.onclick = function () { addRows(shown + 200); if (shown >= rows.length) more.remove(); };
      wrap.appendChild(more);
    }
    return wrap;
  }
  function whyPanel() {
    var p = el('div', 'tmg-why');
    p.id = 'tmg-why';
    p.setAttribute('aria-live', 'polite');
    p.appendChild(el('span', 'muted small', 'Choose a dot in the matrix: why it is there.'));
    p.show = function (title, vias, lim, extra) {
      clear(p);
      var h = el('div', 'tmg-why-h');
      h.appendChild(ic('info', 15));
      h.appendChild(title);
      p.appendChild(h);
      if (extra) p.appendChild(extra);
      vias.forEach(function (v) {
        var line = el('div', 'tmx-why-l');
        var who = el('span', 'tmx-why-s who');
        who.appendChild(ic(WHO_ICON[v.kind] || 'person', 12));
        who.appendChild(data('span', 'mono', shortWho(v.who)));
        line.appendChild(who);
        if (v.group) { line.appendChild(ic('next', 12, 'tmx-why-a')); var gg = el('span', 'tmx-why-s grp'); gg.appendChild(el('span', '', 'through')); gg.appendChild(document.createTextNode(' ')); gg.appendChild(data('b', '', v.group)); line.appendChild(gg); }
        line.appendChild(ic('next', 12, 'tmx-why-a'));
        var rr = el('span', 'tmx-why-r');
        (v.roles || []).forEach(function (x) { rr.appendChild(roleChip(x)); });
        (v.rights || []).forEach(function (x) { rr.appendChild(chip(RIGHT_WORDS[x] || x, 'legacy')); });
        line.appendChild(rr);
        line.appendChild(ic('next', 12, 'tmx-why-a'));
        if (v.inherited) {
          var ih = el('span', 'tmx-from');
          ih.appendChild(ic('tm_tree', 12));
          ih.appendChild(el('span', '', 'inherited from'));
          ih.appendChild(data('b', '', v.team));
          line.appendChild(ih);
        } else {
          var on = el('span', 'tmx-chip here');
          on.appendChild(el('span', '', 'in the team'));
          on.appendChild(document.createTextNode(' '));
          on.appendChild(data('b', '', v.team));
          line.appendChild(on);
        }
        if (v.jit) line.appendChild(chip('temporary', 'warn', 'clock'));
        if (v.until) line.appendChild(untilChip(v));
        if (v.reason) line.appendChild(data('span', 'muted small tmg-reason', '“' + v.reason + '”'));
        p.appendChild(line);
      });
      if (lim) { var n = el('div', 'tmx-note warn tmg-lim'); n.appendChild(ic('shield', 15)); n.appendChild(el('span', '', lim)); p.appendChild(n); }
      p.scrollIntoView({block: 'nearest', behavior: 'smooth'});
    };
    return p;
  }
  function personResult(d) {
    var box = el('div', 'tmg-res');
    var who = d.who || {};
    var head = el('div', 'tmx-ac-who');
    head.appendChild(avatar(who.name || '?', 'user'));
    var w = el('div', 'tmx-ac-ww');
    w.appendChild(data('b', '', who.display || who.name || ''));
    var sub = [who.upn, who.sam, who.mail].filter(Boolean).filter(function (x, i, a) { return a.indexOf(x) === i; });
    if (sub.length) w.appendChild(data('span', 'mono small muted', sub.join(' · ')));
    head.appendChild(w);
    var tags = el('div', 'tmx-ac-tags');
    if (d.account) tags.appendChild(chip({fulladmin: 'full administrator', certadmin: 'certificate administrator', tokenadmin: 'certificate administrator', readonly: 'read-only account', portal: 'portal only'}[d.account.role] || d.account.role, d.account.role === 'fulladmin' ? 'crit' : 'info', 'key'));
    tags.appendChild(chip('{0} teams'.replace('{0}', num((d.teams || []).length)), 'dim', 'people'));
    if (d.groups_count) tags.appendChild(chip('{0} groups'.replace('{0}', num(d.groups_count)), 'dim', 'people'));
    head.appendChild(tags);
    var acts = el('div', 'tmg-va');
    var meName = low((typeof ME === 'object' && ME && ME.name) || '');
    if (low(String(who.name || '').replace(/^local:/i, '')) !== meName) viewAsButtons(who.kind === 'local' ? who.name : (who.upn || who.sam || who.name), acts);
    if (acts.firstChild) head.appendChild(acts);
    box.appendChild(head);
    if (d.account && (d.account.role === 'fulladmin' || ((d.account.role === 'certadmin' || d.account.role === 'tokenadmin') && (d.settings || {}).certadmin_all))) {
      var n = el('div', 'tmx-note');
      n.appendChild(ic('info', 16));
      n.appendChild(el('span', '', d.account.role === 'fulladmin' ? 'A full administrator: every capability on every certificate, whatever the teams say. The matrix shows only what the teams give.' : 'A certificate administrator with "Certificate administrators manage every certificate" on: every certificate, whatever the teams say. The matrix shows only what the teams give.'));
      box.appendChild(n);
    }
    var teams = d.teams || [];
    if (!teams.length) { box.appendChild(empty('tmg_who', 'In no team', 'No membership of any team matches this person or a group they are in.')); return box; }
    box.appendChild(legend());
    var why = whyPanel();
    var rows = teams.map(function (t) {
      var lab = el('span', 'tmg-rl');
      lab.style.paddingLeft = Math.min(t.depth || 0, 6) * 10 + 'px';
      lab.appendChild(kindBadge(t.kind, 14));
      lab.appendChild(data('span', 'tmg-rl-n', t.team));
      if (!(t.caps || []).length) lab.appendChild(chip('ended', 'crit'));
      return {name: t.team, label: lab, caps: t.caps, cells: t.cells, via: t.via, limits: t.limits,
              cls: (t.caps || []).length ? '' : 'none'};
    });
    box.appendChild(capMatrix(rows, function (r, c, vias, lim) {
      var title = el('span', '');
      title.appendChild(data('b', '', c.id));
      title.appendChild(document.createTextNode(' '));
      title.appendChild(el('span', '', 'in the team'));
      title.appendChild(document.createTextNode(' '));
      title.appendChild(data('b', '', r.name));
      why.show(title, vias, lim);
    }, tr('Team')));
    box.appendChild(why);
    return box;
  }
  function teamResult(d) {
    var box = el('div', 'tmg-res');
    var head = el('div', 'tmg-res-h');
    head.appendChild(kindBadge(d.kind, 18));
    head.appendChild(data('b', '', d.team));
    if ((d.chain || []).length > 1) head.appendChild(data('span', 'muted small', d.chain.slice(0, -1).join(' › ')));
    head.appendChild(chip('{0} people and groups'.replace('{0}', num((d.people || []).length)), 'dim', 'people'));
    box.appendChild(head);
    if (!(d.people || []).length) { box.appendChild(empty('people', 'Nobody', 'No member of this team or of a team above it.')); return box; }
    box.appendChild(legend());
    var why = whyPanel();
    var rows = (d.people || []).map(function (p) {
      var lab = el('span', 'tmg-rl');
      lab.appendChild(avatar(p.who, p.kind));
      lab.appendChild(data('span', 'tmg-rl-n', shortWho(p.who)));
      if (p.admin) lab.appendChild(chip(p.admin === 'fulladmin' ? 'full administrator' : p.admin === 'certadmin' ? 'certificate administrator' : 'read-only', 'dim'));
      return {name: p.who, label: lab, caps: p.caps, cells: p.cells, via: p.via, limits: d.limits, admin: p.admin, why: p.why,
              cls: p.admin ? 'adm' : ''};
    });
    box.appendChild(capMatrix(rows, function (r, c, vias, lim) {
      var title = el('span', '');
      title.appendChild(data('b', '', shortWho(r.name)));
      title.appendChild(document.createTextNode(' - '));
      title.appendChild(data('b', '', c.id));
      var extra = r.admin ? el('p', 'muted small', r.why) : null;
      if (extra) extra.textContent = tr(r.why);
      why.show(title, vias, lim, extra);
    }, tr('Who')));
    box.appendChild(why);
    return box;
  }
  function whoCanResult(d) {
    var box = el('div', 'tmg-res');
    var head = el('div', 'tmg-res-h');
    head.appendChild(ic('search', 18));
    var t = el('span', 'tmg-q');
    t.appendChild(el('span', '', 'Who may'));
    t.appendChild(document.createTextNode(' '));
    t.appendChild(data('b', 'mono', d.cap));
    t.appendChild(document.createTextNode(' '));
    t.appendChild(el('span', '', d.cert ? 'on the certificate' : 'in the team'));
    t.appendChild(document.createTextNode(' '));
    t.appendChild(data('b', '', d.cert ? d.cert : (d.team || '?')));
    if (d.cert && d.team) { t.appendChild(document.createTextNode(' (')); t.appendChild(data('span', '', d.team)); t.appendChild(document.createTextNode(')')); }
    head.appendChild(t);
    head.appendChild(chip(num((d.people || []).length), 'info', 'people'));
    box.appendChild(head);
    if (d.words) box.appendChild(el('p', 'muted small', d.words));
    if (d.admins_only) box.appendChild(data('p', 'note warn', tr('It has no team: only those who see every certificate may.')));
    if (d.limit) { var n = el('div', 'tmx-note warn'); n.appendChild(ic('shield', 16)); n.appendChild(el('span', '', d.limit)); box.appendChild(n); }
    var list = el('div', 'tmx-mlist tmg-wc');
    list.id = 'tmg-wc-list';
    (d.people || []).forEach(function (p) {
      var r = el('div', 'tmx-mrow tmg-wc-row' + (p.admin ? ' adm' : ''));
      r.dataset.who = p.who;
      r.appendChild(avatar(p.who, p.kind));
      var w = el('div', 'tmx-mw');
      var top = el('div', 'tmx-mtop');
      top.appendChild(data('b', 'tmx-mwho', shortWho(p.who)));
      top.appendChild(chip(KIND_WORDS[p.kind] || p.kind, 'dim k', WHO_ICON[p.kind] || 'person'));
      w.appendChild(top);
      if (p.admin) w.appendChild(el('div', 'muted small', p.why));
      (p.why_here || []).forEach(function (v) {
        var line = el('div', 'tmx-mroles');
        (v.roles || []).forEach(function (x) { line.appendChild(roleChip(x)); });
        (v.rights || []).forEach(function (x) { line.appendChild(chip(RIGHT_WORDS[x] || x, 'legacy')); });
        if (v.inherited) { var ih = el('span', 'tmx-from'); ih.appendChild(el('span', '', 'from')); ih.appendChild(data('b', '', v.team)); line.appendChild(ih); }
        else line.appendChild(chip('on this team', 'here'));
        if (v.jit) line.appendChild(chip('temporary', 'warn', 'clock'));
        if (v.until) line.appendChild(untilChip(v));
        w.appendChild(line);
      });
      r.appendChild(w);
      if (p.kind === 'group' && dirs().length) {
        var g = iconButton('people', 'Who is in the group');
        g.onclick = function () {
          busy(g, true);
          api('dir/group&name=' + enc(p.who)).then(function (x) {
            var names = el('div', 'tmx-gnames');
            names.appendChild(chip((x.count === 1 ? '1 person' : '{0} people'.replace('{0}', num(x.count || 0))) + (x.capped ? '+' : ''), 'info', 'people'));
            (x.first || []).slice(0, 12).forEach(function (u) { names.appendChild(dataChip(u.display || u.sam || u.upn, 'dim')); });
            w.appendChild(names);
            g.remove();
          }).catch(oops).then(function () { busy(g, false); });
        };
        r.appendChild(g);
      }
      list.appendChild(r);
    });
    if (!(d.people || []).length) list.appendChild(empty('ban', 'Nobody', 'Nobody may do that there - not even through a team above it.'));
    box.appendChild(list);
    return box;
  }

  /* ---- Health ------------------------------------------------------------------------------ */
  var HEALTH_KEYS = [['expiring', 'Running out', 'clock', 'warn'], ['expired', 'Expired', 'ban', 'crit'],
                     ['failed_renewals', 'Failed renewals', 'pulse', 'crit'], ['failed_deploys', 'Failed deployments', 'router', 'crit'],
                     ['outside', 'Outside the limits', 'shield', 'warn'], ['weak', 'Weak keys', 'key', 'warn']];
  var GRADE_WORDS = {good: 'good', fair: 'fair', poor: 'poor'};
  function ring(score, size, grade) {
    size = size || 64;
    var r = (size - 8) / 2, c = 2 * Math.PI * r, v = Math.max(0, Math.min(100, Number(score) || 0));
    var wrap = el('div', 'tmg-ring g-' + (grade || 'good'));
    wrap.style.width = size + 'px';
    wrap.style.height = size + 'px';
    wrap.innerHTML = '<svg viewBox="0 0 ' + size + ' ' + size + '" aria-hidden="true"><circle class="bg" cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r +
      '"/><circle class="fg" cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" stroke-dasharray="' + (c * v / 100).toFixed(1) + ' ' + c.toFixed(1) +
      '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"/></svg>';
    wrap.appendChild(data('b', 'tmg-ring-v', String(Math.round(v))));
    wrap.setAttribute('role', 'img');
    wrap.setAttribute('aria-label', tr('health') + ' ' + Math.round(v) + ' / 100');
    return wrap;
  }
  function quotaBar(q) {
    var b = el('div', 'tmg-quota');
    var pct = q.max ? Math.min(100, Math.round(100 * q.used / q.max)) : 0;
    var top = el('div', 'tmg-quota-t');
    top.appendChild(el('span', '', 'Quota'));
    top.appendChild(data('b', '', num(q.used) + ' / ' + num(q.max)));
    b.appendChild(top);
    var bar = el('div', 'tmg-quota-b' + (pct >= 100 ? ' crit' : pct >= 80 ? ' warn' : ''));
    var fill = el('span', '');
    fill.style.width = pct + '%';
    bar.appendChild(fill);
    b.appendChild(bar);
    explain(b, 'max_certs: {0} certificates at most (the limit of {1})'.replace('{0}', num(q.max)).replace('{1}', q.from || ''));
    return b;
  }
  function healthCard(h, onOpen) {
    var m = h.below || {};
    var c = el('button', 'tmg-hcard g-' + h.grade);
    c.type = 'button';
    c.dataset.team = h.team;
    var top = el('div', 'tmg-hcard-t');
    top.appendChild(ring(h.score, 52, h.grade));
    var w = el('div', 'tmg-hcard-w');
    var n = el('div', 'tmg-hcard-n');
    n.appendChild(kindBadge(h.kind, 14));
    n.appendChild(data('b', '', h.team));
    w.appendChild(n);
    var s = el('div', 'tmg-hcard-s');
    s.appendChild(chip(GRADE_WORDS[h.grade] || h.grade, h.grade === 'good' ? 'ok' : h.grade === 'fair' ? 'warn' : 'crit'));
    s.appendChild(el('span', 'muted small', m.certs === 1 ? '1 certificate' : '{0} certificates'.replace('{0}', num(m.certs || 0))));
    w.appendChild(s);
    top.appendChild(w);
    c.appendChild(top);
    var pills = el('div', 'tmg-hpills');
    HEALTH_KEYS.forEach(function (k) {
      var v = Number(m[k[0]] || 0);
      if (!v) return;
      var p = el('span', 'tmg-hpill ' + k[3]);
      p.dataset.k = k[0];
      p.appendChild(ic(k[2], 12));
      p.appendChild(data('b', '', num(v)));
      p.appendChild(el('span', '', k[1]));
      pills.appendChild(p);
    });
    if (!pills.firstChild) {
      var okp = el('span', 'tmg-hpill ok');
      okp.appendChild(ic('check', 12));
      okp.appendChild(el('span', '', m.certs ? 'all well' : 'no certificate yet'));
      pills.appendChild(okp);
    }
    c.appendChild(pills);
    if (m.quota && m.quota.max) c.appendChild(quotaBar(m.quota));
    c.onclick = function () { onOpen(h); };
    return c;
  }
  function healthDetail(name) {
    modal(tr('Health of {0}').replace('{0}', name), function (body) {
      body.classList.add('tmx-dlg', 'tmg-hdlg');
      body.appendChild(asking());
      api('teams/health&team=' + enc(name)).then(function (d) {
        clear(body);
        var h = (d.teams || []).filter(function (x) { return low(x.team) === low(name); })[0];
        if (!h) { body.appendChild(el('p', 'muted', 'Nothing to say.')); return; }
        var top = el('div', 'tmg-hd-top');
        top.appendChild(ring(h.score, 84, h.grade));
        var w = el('div', 'tmg-hd-w');
        w.appendChild(data('b', 'tmg-hd-n', h.team));
        w.appendChild(el('span', 'muted small', 'with the teams below it'));
        var own = h.own || {};
        w.appendChild(el('span', 'muted small', '{0} of its own'.replace('{0}', num(own.certs || 0))));
        top.appendChild(w);
        body.appendChild(top);
        if ((h.below || {}).quota && h.below.quota.max) body.appendChild(quotaBar(h.below.quota));
        var any = false;
        HEALTH_KEYS.forEach(function (k) {
          var lst = (h.list || {})[k[0]] || [];
          if (!lst.length) return;
          any = true;
          body.appendChild(sectionHead(k[2], k[1]));
          var l = el('div', 'tmg-hlist');
          lst.forEach(function (x) {
            var it = el('div', 'tmg-hlist-it');
            it.appendChild(data('b', 'mono', x.name));
            if (x.why) it.appendChild(data('span', 'muted small', x.why));
            l.appendChild(it);
          });
          body.appendChild(l);
        });
        if (!any) body.appendChild(empty('check', 'All well', 'Nothing of its own runs out soon, failed, stands outside its limits or has a weak key.'));
      }).catch(function (e) { clear(body); body.appendChild(data('p', 'bad', String(e.message || e))); });
    }, [{words: 'Close', close: true}], 'medium');
  }
  function healthView() {
    var wrap = el('div', 'tmg-health');
    wrap.appendChild(asking());
    api('teams/health').then(function (d) {
      clear(wrap);
      GOV.health = d;
      var rows = d.teams || [];
      var hero = el('div', 'tmg-hhero');
      var sc = d.score === null || d.score === undefined ? 100 : d.score;
      var grade = sc >= 90 ? 'good' : sc >= 70 ? 'fair' : 'poor';
      hero.appendChild(ring(sc, 96, grade));
      var hw = el('div', 'tmg-hhero-w');
      hw.appendChild(el('b', '', 'The health of the teams'));
      hw.appendChild(el('span', 'muted small', 'Certificates running out within {0} days, failed renewals and deployments, certificates outside their team\'s limits, weak keys and the quota - one score of 100 for each team and its teams below; for the leadership, all of them together.'.replace('{0}', num(d.days || 14))));
      var tot = {};
      rows.filter(function (r) { return !r.parent; }).forEach(function (r) { HEALTH_KEYS.forEach(function (k) { tot[k[0]] = (tot[k[0]] || 0) + Number((r.below || {})[k[0]] || 0); }); });
      var pills = el('div', 'tmg-hpills big');
      HEALTH_KEYS.forEach(function (k) {
        var v = tot[k[0]] || 0;
        var p = el('span', 'tmg-hpill' + (v ? ' ' + k[3] : ' zero'));
        p.appendChild(ic(k[2], 13));
        p.appendChild(data('b', '', num(v)));
        p.appendChild(el('span', '', k[1]));
        pills.appendChild(p);
      });
      hw.appendChild(pills);
      hero.appendChild(hw);
      wrap.appendChild(hero);
      var bar = el('div', 'tmg-hbar');
      var f = el('div', 'tmx-find');
      f.appendChild(ic('search', 15));
      var q = el('input', '');
      q.type = 'search';
      q.id = 'tmg-h-q';
      q.placeholder = tr('Find a team…');
      q.value = GOV.hq;
      noI18n(q);
      f.appendChild(q);
      bar.appendChild(f);
      var sort = segmented([['worst', 'Worst first', 'down'], ['tree', 'As the tree', 'tm_tree']], GOV.hsort);
      sort.classList.add('small');
      bar.appendChild(sort);
      wrap.appendChild(bar);
      var grid = el('div', 'tmg-hgrid');
      grid.id = 'tmg-hgrid';
      wrap.appendChild(grid);
      var paint = function () {
        clear(grid);
        var w = fold(q.value).trim();
        var list = rows.filter(function (r) { return !w || fold(r.team).indexOf(w) >= 0; });
        if (GOV.hsort === 'worst') list = list.slice().sort(function (a, b) { return a.score - b.score || (b.below.certs - a.below.certs); });
        list.slice(0, GOV.hshow).forEach(function (h) { grid.appendChild(healthCard(h, function (x) { healthDetail(x.team); })); });
        if (!list.length) grid.appendChild(empty('search', 'No team', 'No team is called like that.'));
        if (list.length > GOV.hshow) {
          var more = cmdButton('Show more', 'down', 'small');
          more.classList.add('tmg-more');
          more.onclick = function () { GOV.hshow += 120; paint(); };
          grid.appendChild(more);
        }
      };
      q.oninput = debounce(function () { GOV.hq = q.value; paint(); }, 150);
      sort.addEventListener('change', function () { GOV.hsort = sort.value; paint(); });
      paint();
    }).catch(function (e) { clear(wrap); wrap.appendChild(data('p', 'bad', String(e.message || e))); });
    return wrap;
  }
  /* the strip on a team's Overview */
  function healthStrip(box, n) {
    var s = el('div', 'tmg-hstrip');
    box.appendChild(s);
    var paint = function (d) {
      var h = (d.teams || []).filter(function (x) { return low(x.team) === n.key; })[0];
      if (!h) { s.remove(); return; }
      clear(s);
      s.appendChild(ring(h.score, 48, h.grade));
      var w = el('div', 'tmg-hstrip-w');
      var t = el('div', '');
      t.appendChild(el('b', '', 'Health'));
      t.appendChild(document.createTextNode(' '));
      t.appendChild(chip(GRADE_WORDS[h.grade], h.grade === 'good' ? 'ok' : h.grade === 'fair' ? 'warn' : 'crit'));
      w.appendChild(t);
      var pills = el('div', 'tmg-hpills');
      HEALTH_KEYS.forEach(function (k) {
        var v = Number((h.below || {})[k[0]] || 0);
        if (!v) return;
        var p = el('span', 'tmg-hpill ' + k[3]);
        p.appendChild(ic(k[2], 12));
        p.appendChild(data('b', '', num(v)));
        p.appendChild(el('span', '', k[1]));
        pills.appendChild(p);
      });
      if (!pills.firstChild) pills.appendChild(el('span', 'muted small', 'nothing runs out, fails or stands outside its limits'));
      w.appendChild(pills);
      s.appendChild(w);
      if ((h.below || {}).quota && h.below.quota.max) s.appendChild(quotaBar(h.below.quota));
      var open = el('button', 'tmx-link', 'Details');
      open.type = 'button';
      open.onclick = function () { healthDetail(n.name); };
      s.appendChild(open);
    };
    if (GOV.health && GOV.health.at > Date.now() - 60000) paint(GOV.health);
    else api('teams/health').then(function (d) { d.at = Date.now(); GOV.health = d; if (s.isConnected) paint(d); }).catch(function () { s.remove(); });
  }

  /* ---- Temporary roles (just-in-time) and reviews: the inbox -------------------------------- */
  function elevRow(r, mode, after) {
    var row = el('div', 'tmg-erow');
    row.dataset.id = r.id;
    var head = el('div', 'tmg-erow-h');
    head.appendChild(avatar(r.who || r.asked_by, kindOf(r.who || '')));
    var hw = el('div', 'tmg-erow-w');
    var top = el('div', 'tmg-erow-t');
    top.appendChild(data('b', 'tmx-mwho', shortWho(r.asked_by || r.who)));
    top.appendChild(stateChip(r.state));
    hw.appendChild(top);
    var line = el('div', 'tmg-erow-l');
    line.appendChild(el('span', 'muted small', 'asks for'));
    line.appendChild(roleChip(r.role));
    line.appendChild(el('span', 'muted small', 'in the team'));
    line.appendChild(dataChip(r.team, 'dim', 'people'));
    line.appendChild(chip('{0} h'.replace('{0}', num(Math.round(r.hours || 0))), 'dim', 'clock'));
    hw.appendChild(line);
    head.appendChild(hw);
    row.appendChild(head);
    if (r.reason) row.appendChild(data('div', 'tmx-mnote tmg-erow-r', '“' + r.reason + '”'));
    var meta = el('div', 'tmg-emeta muted small');
    meta.appendChild(el('span', '', 'asked {0}'.replace('{0}', whenText(r.asked))));
    if (r.decided_by) { meta.appendChild(document.createTextNode(' · ')); meta.appendChild(el('span', '', r.state === 'declined' ? 'declined by' : 'approved by')); meta.appendChild(document.createTextNode(' ')); meta.appendChild(data('span', '', shortWho(r.decided_by))); }
    if (r.decided_why) { meta.appendChild(document.createTextNode(' · ')); meta.appendChild(data('span', '', '“' + r.decided_why + '”')); }
    if (r.state === 'granted' && r.until) { meta.appendChild(document.createTextNode(' · ')); meta.appendChild(el('span', 'tmg-left', leftWords(r.until))); }
    row.appendChild(meta);
    var tools = el('div', 'tmg-etools');
    if (mode === 'decide') {
      var ok = cmdButton('Approve', 'check', 'small primary');
      ok.classList.add('tmg-e-ok');
      ok.onclick = function () { decideElev(r, true, after); };
      var no = cmdButton('Decline', 'close', 'small');
      no.classList.add('tmg-e-no');
      no.onclick = function () { decideElev(r, false, after); };
      tools.appendChild(ok);
      tools.appendChild(no);
    } else if ((r.state === 'waiting' || r.state === 'granted') && mode !== 'view') {
      var end = cmdButton(r.state === 'waiting' ? 'Take back' : 'End now', 'close', 'small');
      end.classList.add('tmg-e-end');
      end.onclick = function () {
        busy(end, true);
        api('teams/elevate_end', {id: r.id}).then(function (x) { toast(x.message || 'ended', 'good'); after(); }).catch(oops).then(function () { busy(end, false); });
      };
      tools.appendChild(end);
    }
    if (tools.firstChild) row.appendChild(tools);
    return row;
  }
  function decideElev(r, ok, after) {
    modal(ok ? tr('Approve {0} for {1}').replace('{0}', r.role).replace('{1}', shortWho(r.asked_by)) : tr('Decline the request'), function (body) {
      body.classList.add('tmx-dlg');
      body.appendChild(elevRow(r, 'view', function () { }));
      var why = textBox('', ok ? tr('optional') : tr('why - the person who asked reads it'));
      why.id = 'tmg-e-why';
      noI18n(why);
      body.appendChild(formField(ok ? 'A word for the record' : 'Why', why));
      if (ok) body.appendChild(el('p', 'note', 'The role is given now and ends by itself after the hours asked. Separation of duties is checked: a role that would clash with another of theirs is refused.'));
      decideElev._why = why;
    }, [{words: 'Close', close: true},
        {words: ok ? 'Approve' : 'Decline', cls: ok ? 'primary' : 'danger', icon: ok ? 'check' : 'close', go: function (b) {
          var w = decideElev._why.value.trim();
          if (!ok && !w) { toast('say why it is declined', 'bad'); return; }
          busy(b, true);
          api('teams/elevate_decide', {id: r.id, ok: ok, why: w}).then(function (x) {
            toast(x.message || 'done', 'good');
            closeModal(true);
            after();
          }).catch(oops).then(function () { busy(b, false); });
        }}], true);
  }
  function askElevation(may, team, after) {
    var st = {team: team || (may[0] || {}).team || '', role: '', hours: 4};
    modal('Ask for a temporary role', function (body) {
      body.classList.add('tmx-dlg', 'tmg-ask');
      body.appendChild(el('p', 'note', 'A role on a team for a few hours - for a change window, a night shift, an incident. A manager of the team approves it (never you); it ends by itself.'));
      var ts = selectBox(may.map(function (m) { return [m.team, m.team]; }), st.team);
      ts.id = 'tmg-ask-team';
      noI18n(ts);
      body.appendChild(formField('Team', ts));
      var rolesBox = el('div', 'tmx-rolepick');
      rolesBox.id = 'tmg-ask-roles';
      var maxSaid = el('span', 'muted small');
      var hours = el('input', '');
      hours.type = 'number';
      hours.min = '1';
      hours.id = 'tmg-ask-hours';
      hours.value = st.hours;
      var paintRoles = function () {
        clear(rolesBox);
        var m = may.filter(function (x) { return x.team === ts.value; })[0] || {roles: [], max_hours: 8};
        hours.max = String(m.max_hours || 8);
        if (Number(hours.value) > m.max_hours) hours.value = m.max_hours;
        maxSaid.textContent = tr('{0} hours at most').replace('{0}', num(m.max_hours || 8));
        if (m.roles.indexOf(st.role) < 0) st.role = m.roles[0] || '';
        m.roles.forEach(function (r) {
          var b = el('button', 'tmx-rchip' + (st.role === r ? ' on' : ''));
          b.type = 'button';
          b.setAttribute('aria-pressed', st.role === r ? 'true' : 'false');
          var k = el('span', 'tmx-rchk');
          k.innerHTML = iconMarkup('check', 11);
          b.appendChild(k);
          b.appendChild(data('span', '', r));
          var ro = roleOf(r);
          if (ro) explain(b, (ro.description ? known(ro.description) + ' - ' : '') + ro.caps.join(', '));
          b.onclick = function () { st.role = r; paintRoles(); };
          rolesBox.appendChild(b);
        });
      };
      ts.addEventListener('change', paintRoles);
      body.appendChild(formField('Role', rolesBox));
      var hw = el('div', 'tmg-hours');
      hw.appendChild(hours);
      [1, 2, 4, 8].forEach(function (n) {
        var q = el('button', 'tmx-qbtn', '{0} h'.replace('{0}', n));
        q.type = 'button';
        q.onclick = function () { hours.value = Math.min(n, Number(hours.max || 8)); };
        hw.appendChild(q);
      });
      hw.appendChild(maxSaid);
      body.appendChild(formField('For how many hours', hw));
      var why = textBox('', tr('what for - a change window, a ticket…'));
      why.id = 'tmg-ask-why';
      noI18n(why);
      body.appendChild(formField('Why', why));
      paintRoles();
      askElevation._read = function () { return {team: ts.value, role: st.role, hours: Number(hours.value), reason: why.value.trim()}; };
    }, [{words: 'Close', close: true},
        {words: 'Ask', cls: 'primary', icon: 'bell', go: function (b) {
          var r = askElevation._read();
          if (!r.role) { toast('choose a role', 'bad'); return; }
          if (r.reason.length < 3) { toast('say why you need it', 'bad'); return; }
          busy(b, true);
          api('teams/elevate', r).then(function (x) { toast(x.message || 'asked', 'good'); closeModal(true); after(); })
            .catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function reviewDialog(rv, after) {
    modal(tr('Access review of {0}').replace('{0}', rv.team), function (body) {
      body.classList.add('tmx-dlg', 'tmg-rdlg');
      var head = el('div', 'tmg-rhead');
      var done = (rv.items || []).length - rv.pending;
      var bar = el('div', 'tmg-prog');
      var fill = el('span', '');
      fill.style.width = ((rv.items || []).length ? Math.round(100 * done / rv.items.length) : 100) + '%';
      bar.appendChild(fill);
      head.appendChild(bar);
      head.appendChild(el('span', 'muted small', '{0} of {1} answered'.replace('{0}', num(done)).replace('{1}', num((rv.items || []).length))));
      head.appendChild(el('span', 'muted small', 'by {0}'.replace('{0}', whenText(rv.due))));
      if (rv.late || rv.state === 'overdue') head.appendChild(chip('overdue', 'warn', 'clock'));
      body.appendChild(head);
      body.appendChild(el('p', 'note', 'Confirm each member and their roles, or take them out of the team. You do not confirm your own membership. What is not answered by the deadline is reported, or expires - as the team\'s review says.'));
      var list = el('div', 'tmx-mlist');
      list.id = 'tmg-rv-list';
      (rv.items || []).forEach(function (it) {
        var r = el('div', 'tmx-mrow tmg-rv-row' + (it.state !== 'pending' ? ' answered' : ''));
        r.dataset.who = it.who;
        r.appendChild(avatar(it.who, kindOf(it.who)));
        var w = el('div', 'tmx-mw');
        var top = el('div', 'tmx-mtop');
        top.appendChild(data('b', 'tmx-mwho', shortWho(it.who)));
        top.appendChild(stateChip(it.state));
        w.appendChild(top);
        var roles = el('div', 'tmx-mroles');
        (it.roles || []).forEach(function (x) { roles.appendChild(roleChip(x)); });
        (it.rights || []).forEach(function (x) { roles.appendChild(chip(RIGHT_WORDS[x] || x, 'legacy')); });
        if (it.until) roles.appendChild(untilChip(it));
        w.appendChild(roles);
        if (it.by) w.appendChild(data('div', 'muted small', it.by + ' · ' + whenText(it.at) + (it.note ? ' · “' + it.note + '”' : '')));
        r.appendChild(w);
        if (it.state === 'pending' && (rv.state === 'open' || rv.state === 'overdue')) {
          var tools = el('div', 'tmx-mtools tmg-etools');
          var keepB = cmdButton('Confirm', 'check', 'small primary');
          keepB.classList.add('tmg-rv-keep');
          var outB = cmdButton('Take out', 'trash', 'small');
          outB.classList.add('tmg-rv-out');
          var answer = function (keep, b) {
            busy(b, true);
            api('teams/review_answer', {id: rv.id, who: it.who, keep: keep}).then(function (x) {
              toast(x.message || 'saved', 'good');
              closeModal(true);
              after(x.review);
            }).catch(oops).then(function () { busy(b, false); });
          };
          keepB.onclick = function () { answer(true, keepB); };
          outB.onclick = function () {
            confirmThen('Take the member out', htmlText(tr('{0} is taken out of the team {1} now.').replace('{0}', it.who).replace('{1}', rv.team)), 'Take it out', function () { answer(false, outB); });
          };
          tools.appendChild(keepB);
          tools.appendChild(outB);
          r.appendChild(tools);
        }
        list.appendChild(r);
      });
      body.appendChild(list);
    }, [{words: 'Close', close: true}], 'medium');
  }
  function govView() {
    var wrap = el('div', 'tmg-inbox');
    var paint = function () {
      clear(wrap);
      wrap.appendChild(asking());
      Promise.all([api('teams/elevations'), api('teams/reviews').catch(function () { return {open: []}; })]).then(function (x) {
        clear(wrap);
        var d = x[0] || {}, rv = x[1] || {};
        var cols = el('div', 'tmg-icols');
        var c1 = govCard('clock', 'Temporary roles', 'A member asks for a role on a team for a few hours; a manager of the team approves it - never the one who asked - and it ends by itself.');
        c1.id = 'tmg-elev';
        if ((d.may_ask || []).length) {
          var ask = headButton(c1, cmdButton('Ask for a role', 'add', 'small primary'));
          ask.id = 'tmg-ask';
          ask.onclick = function () { askElevation(d.may_ask, UI.team, paint); };
        }
        var todo = d.to_decide || [];
        c1.appendChild(sectionHead('tmg_inbox', 'Waiting for you ({0})'.replace('{0}', num(todo.length))));
        var l1 = el('div', 'tmx-mlist');
        l1.id = 'tmg-todo';
        todo.forEach(function (r) { l1.appendChild(elevRow(r, 'decide', paint)); });
        if (!todo.length) l1.appendChild(el('p', 'muted small tmx-none', 'Nothing waits for you.'));
        c1.appendChild(l1);
        var mine = d.mine || [];
        if (mine.length) {
          c1.appendChild(sectionHead('person', 'Asked by you'));
          var l2 = el('div', 'tmx-mlist');
          l2.id = 'tmg-mine';
          mine.slice(0, 50).forEach(function (r) { l2.appendChild(elevRow(r, 'mine', paint)); });
          c1.appendChild(l2);
        }
        cols.appendChild(c1);
        var c2 = govCard('tmg_gov', 'Access reviews', 'The reviews open now in the teams you see: confirm each member and their roles, or take them out.');
        c2.id = 'tmg-reviews';
        var open = rv.open || [];
        var l3 = el('div', 'tmg-rvlist');
        open.forEach(function (r) {
          var it = el('button', 'tmg-rvcard' + (r.late || r.state === 'overdue' ? ' late' : ''));
          it.type = 'button';
          it.dataset.team = r.team;
          var t = el('div', 'tmg-rvcard-t');
          t.appendChild(ic('people', 15));
          t.appendChild(data('b', '', r.team));
          t.appendChild(stateChip(r.late && r.state === 'open' ? 'overdue' : r.state));
          it.appendChild(t);
          var bar = el('div', 'tmg-prog');
          var fill = el('span', '');
          var tot = (r.items || []).length;
          fill.style.width = (tot ? Math.round(100 * (tot - r.pending) / tot) : 100) + '%';
          bar.appendChild(fill);
          it.appendChild(bar);
          it.appendChild(el('span', 'muted small', '{0} to confirm, by {1}'.replace('{0}', num(r.pending)).replace('{1}', dateOf(r.due))));
          it.onclick = function () { reviewDialog(r, paint); };
          l3.appendChild(it);
        });
        if (!open.length) l3.appendChild(el('p', 'muted small tmx-none', 'No review is open.'));
        c2.appendChild(l3);
        cols.appendChild(c2);
        wrap.appendChild(cols);
        if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(wrap); } catch (e) { } }
      }).catch(function (e) { clear(wrap); wrap.appendChild(data('p', 'bad', String(e.message || e))); });
    };
    paint();
    return wrap;
  }

  /* ---- Templates and CSV import ------------------------------------------------------------ */
  function templatesView() {
    var wrap = el('div', 'tmg-tpl');
    var head = el('div', 'tmx-tabh');
    head.appendChild(el('p', 'note', 'A template is a team ready to be made again: its kind, members (with {team} for the team\'s name), limits, request profiles, channels and governance - never a secret. Make a team from one, or a whole structure from a CSV file.'));
    if (fullAdmin()) {
      var save = cmdButton('Save a team as a template', 'tmg_tpl', 'small');
      save.id = 'tmg-tpl-from';
      save.onclick = function () { templateFromTeam(paint); };
      var imp = cmdButton('Import from CSV', 'upload', 'small primary');
      imp.id = 'tmg-csv';
      imp.onclick = function () { importCsv(); };
      head.appendChild(save);
      head.appendChild(imp);
    }
    wrap.appendChild(head);
    var list = el('div', 'tmg-tgrid');
    list.id = 'tmg-tgrid';
    wrap.appendChild(list);
    var paint = function () {
      clear(list);
      list.appendChild(asking());
      api('teams/templates').then(function (d) {
        clear(list);
        (d.templates || []).forEach(function (t) { list.appendChild(templateCard(t, paint)); });
        if (!(d.templates || []).length) list.appendChild(empty('tmg_tpl', 'No template yet', 'Save a team as a template - its roles, limits, profiles and notifications - and make new teams from it in one step.'));
      }).catch(function (e) { clear(list); list.appendChild(data('p', 'bad', String(e.message || e))); });
    };
    paint();
    return wrap;
  }
  function templateCard(t, after) {
    var c = el('div', 'tmg-tcard');
    c.dataset.name = t.name;
    var cfg = t.config || {};
    var top = el('div', 'tmg-tcard-t');
    top.appendChild(kindBadge(cfg.kind || 'team', 18));
    var w = el('div', 'tmg-tcard-w');
    w.appendChild(data('b', '', t.name));
    if (t.description || cfg.description) w.appendChild(data('span', 'muted small', t.description || cfg.description));
    top.appendChild(w);
    c.appendChild(top);
    var chips = el('div', 'tmx-mroles');
    if ((cfg.members || []).length) chips.appendChild(chip('{0} members'.replace('{0}', num(cfg.members.length)), 'info', 'people'));
    var pk = Object.keys(cfg.policy || {});
    if (pk.length) chips.appendChild(chip('{0} limits'.replace('{0}', num(pk.length)), 'violet', 'shield'));
    if ((cfg.policy || {}).profiles) chips.appendChild(chip('{0} request profiles'.replace('{0}', num(cfg.policy.profiles.length)), 'dim', 'list'));
    Object.keys(cfg.extras || {}).forEach(function (k) {
      chips.appendChild(chip({review: 'access reviews', jit: 'temporary roles', sod: 'separation of duties', notify: 'notifications'}[k] || k, 'ok', 'tmg_gov'));
    });
    if (!chips.firstChild) chips.appendChild(el('span', 'muted small', 'an empty team'));
    c.appendChild(chips);
    var acts = el('div', 'tmg-tcard-a');
    if (fullAdmin()) {
      var mk = cmdButton('Make a team', 'add', 'small primary');
      mk.classList.add('tmg-tpl-make');
      mk.onclick = function () { teamFromTemplate(t); };
      var ed = iconButton('edit', 'Change this template');
      ed.onclick = function () { editTemplate(t, after); };
      var del = iconButton('trash', 'Delete this template');
      del.onclick = function () {
        confirmThen('Delete the template', htmlText(tr('The template {0} is deleted. The teams made from it stay as they are.').replace('{0}', t.name)), 'Delete it', function () {
          api('teams/template_delete', {name: t.name}).then(function (x) { toast(x.message || 'deleted', 'good'); after(); }).catch(oops);
        });
      };
      acts.appendChild(mk);
      acts.appendChild(ed);
      acts.appendChild(del);
    }
    c.appendChild(acts);
    return c;
  }
  function templateFromTeam(after) {
    modal('Save a team as a template', function (body) {
      body.classList.add('tmx-dlg');
      var ts = teamPick(UI.team, 'tmg-tf-team');
      body.appendChild(formField('Team', ts));
      var name = textBox('', tr('Web team'));
      name.id = 'tmg-tf-name';
      noI18n(name);
      body.appendChild(formField('Name of the template', name));
      var desc = textBox('', '');
      desc.id = 'tmg-tf-desc';
      noI18n(desc);
      body.appendChild(formField('Description', desc));
      var mem = switchBox(false);
      mem.id = 'tmg-tf-members';
      body.appendChild(formField('With its members', mem, 'Its members are copied as they are (a webhook\'s address never is).'));
      templateFromTeam._read = function () { return {from_team: ts.value, name: name.value.trim(), description: desc.value.trim(), members: !!(mem._input || mem.querySelector('input')).checked}; };
    }, [{words: 'Close', close: true},
        {words: 'Save the template', cls: 'primary', icon: 'save', go: function (b) {
          var r = templateFromTeam._read();
          if (!r.name) { toast('name it', 'bad'); return; }
          busy(b, true);
          api('teams/template_save', r).then(function (x) { toast(x.message || 'saved', 'good'); closeModal(true); after(); }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function editTemplate(t, after) {
    modal(tr('The template {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var name = textBox(t.name, '');
      name.id = 'tmg-te-name';
      noI18n(name);
      body.appendChild(formField('Name', name));
      var desc = textBox(t.description || '', '');
      noI18n(desc);
      body.appendChild(formField('Description', desc));
      var cfg = el('textarea', 'mono tmg-json');
      cfg.id = 'tmg-te-cfg';
      cfg.rows = 14;
      cfg.spellcheck = false;
      cfg.value = JSON.stringify(t.config || {}, null, 2);
      noI18n(cfg);
      body.appendChild(formField('What it holds', cfg, 'kind, description, members ({team} is the team\'s name), policy (the limits), contact_mail, extras: review, jit, sod, notify.'));
      editTemplate._read = function () { return {old_name: t.name, name: name.value.trim(), description: desc.value.trim(), config: JSON.parse(cfg.value || '{}')}; };
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
          var r;
          try { r = editTemplate._read(); } catch (e) { toast(tr('that is not JSON') + ': ' + e.message, 'bad'); return; }
          busy(b, true);
          api('teams/template_save', r).then(function (x) { toast(x.message || 'saved', 'good'); closeModal(true); after(); }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function teamFromTemplate(t) {
    modal(tr('A team from {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var name = textBox('', tr('the new team\'s name'));
      name.id = 'tmg-ft-name';
      noI18n(name);
      body.appendChild(formField('Name', name));
      var p = teamPick(UI.team, 'tmg-ft-parent', tr('the top - under no team'));
      body.appendChild(formField('Under', p));
      teamFromTemplate._read = function () { return {template: t.name, name: name.value.trim(), parent: p.value}; };
    }, [{words: 'Close', close: true},
        {words: 'Make the team', cls: 'primary', icon: 'add', go: function (b) {
          var r = teamFromTemplate._read();
          if (!r.name) { toast('name it', 'bad'); return; }
          busy(b, true);
          api('teams/from_template', r).then(function (x) { toast(x.message || 'made', 'good'); closeModal(true); UI.view = 'org'; keep(); refresh(x.team.name); })
            .catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function importCsv() {
    var st = {text: '', preview: null};
    modal('Teams from a CSV file', function (body) {
      body.classList.add('tmx-dlg', 'tmg-csvdlg');
      var cols = el('p', 'note');
      cols.appendChild(el('span', '', 'One team a line; the first line names the columns:'));
      cols.appendChild(document.createTextNode(' '));
      cols.appendChild(data('code', '', 'name,parent,kind,template,description,contact_mail,members'));
      cols.appendChild(document.createTextNode(' '));
      cols.appendChild(el('span', '', '- only the name is needed. Members as on the command line: local:jan=Requester+Deployer; group:Web=view. A parent may come later in the file. Nothing is made until the preview has no error.'));
      body.appendChild(cols);
      var drop = el('label', 'tmg-drop');
      drop.appendChild(ic('upload', 22));
      drop.appendChild(el('span', '', 'Drop a .csv file here, or choose one'));
      var file = el('input', '');
      file.type = 'file';
      file.accept = '.csv,text/csv,text/plain';
      file.id = 'tmg-csv-file';
      drop.appendChild(file);
      body.appendChild(drop);
      var ta = el('textarea', 'mono tmg-json');
      ta.id = 'tmg-csv-text';
      ta.rows = 8;
      ta.spellcheck = false;
      ta.placeholder = 'name,parent,kind\nEurope,,unit\nPrague,Europe,unit\nWeb,Prague,team';
      noI18n(ta);
      body.appendChild(formField('Or paste it', ta));
      var prev = el('div', 'tmg-csvprev');
      prev.id = 'tmg-csv-prev';
      body.appendChild(prev);
      var load_ = function (f) {
        if (!f) return;
        var rd = new FileReader();
        rd.onload = function () { ta.value = String(rd.result || ''); ta.dispatchEvent(new Event('input')); };
        rd.readAsText(f);
      };
      file.onchange = function () { load_(file.files[0]); };
      drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
      drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); load_(e.dataTransfer.files[0]); });
      importCsv._ta = ta;
      importCsv._prev = prev;
    }, [{words: 'Close', close: true},
        {words: 'Preview', icon: 'eye', go: function (b) { csvRun(true, b); }},
        {words: 'Make the teams', cls: 'primary', icon: 'add', go: function (b) { csvRun(false, b); }}], 'wide');
  }
  function csvRun(dry, b) {
    var text = importCsv._ta.value;
    if (!text.trim()) { toast('paste or drop a file first', 'bad'); return; }
    busy(b, true);
    api('teams/import_csv', {csv: text, dry_run: dry}).then(function (d) {
      var prev = importCsv._prev;
      clear(prev);
      var sum = el('div', 'tmx-mroles');
      sum.appendChild(chip('{0} new'.replace('{0}', num(d.new)), 'ok', 'add'));
      if (d.exists) sum.appendChild(chip('{0} there already - left as they are'.replace('{0}', num(d.exists)), 'dim'));
      if (d.errors) sum.appendChild(chip('{0} wrong'.replace('{0}', num(d.errors)), 'crit', 'ban'));
      if ((d.made || []).length) sum.appendChild(chip('{0} made'.replace('{0}', num(d.made.length)), 'ok', 'check'));
      prev.appendChild(sum);
      var tbl = el('table', 'tmg-ctable');
      var hr = el('tr');
      ['Line', 'Team', 'Under', 'Kind', 'Template', 'Members', ''].forEach(function (h) { hr.appendChild(el('th', '', h)); });
      var th = el('thead');
      th.appendChild(hr);
      tbl.appendChild(th);
      var tb = el('tbody');
      (d.rows || []).forEach(function (r) {
        var tr_ = el('tr', 's-' + r.state);
        tr_.appendChild(data('td', 'mono', String(r.line)));
        tr_.appendChild(data('td', '', r.name));
        tr_.appendChild(data('td', '', r.parent || '–'));
        tr_.appendChild(data('td', '', r.kind || 'team'));
        tr_.appendChild(data('td', '', r.template || ''));
        tr_.appendChild(data('td', 'small', (r.members || []).join(', ')));
        var st = el('td', '');
        st.appendChild(r.state === 'error' ? chip(r.error || 'wrong', 'crit') : chip(r.state === 'new' ? 'new' : 'there already', r.state === 'new' ? 'ok' : 'dim'));
        tr_.appendChild(st);
        tb.appendChild(tr_);
      });
      tbl.appendChild(tb);
      var sc = el('div', 'tmg-ctable-s');
      sc.appendChild(tbl);
      prev.appendChild(sc);
      if (!dry && (d.made || []).length) { toast(d.message || 'made', 'good'); changed().then(function () { }); }
      else if (!dry && d.errors) toast('nothing made - correct the lines marked', 'bad');
    }).catch(oops).then(function () { busy(b, false); });
  }

  /* ---- A team's Governance tab ------------------------------------------------------------- */
  function govTab(box, T, n) {
    var t = n.t;
    var g = t.gov || {};
    box.appendChild(el('p', 'note', 'What keeps the team\'s access in order: access reviews, temporary roles, separation of duties, and who is told what. Each is off until it is set; a team above sets them for the teams below where noted.'));
    var grid = el('div', 'tmg-ggrid');
    box.appendChild(grid);
    /* access reviews */
    var rc = govCard('tmg_gov', 'Access reviews', null);
    rc.id = 'tmg-g-review';
    var rule = g.review;
    if (rule) {
      var line = el('div', 'tmx-mroles');
      line.appendChild(chip(tr('every {0} days').replace('{0}', num(rule.every_days)), 'info', 'refresh'));
      line.appendChild(chip(tr('{0} days to answer').replace('{0}', num(rule.answer_days)), 'dim', 'clock'));
      line.appendChild(chip(rule.action === 'expire' ? 'not confirmed: expires' : 'not confirmed: reported', rule.action === 'expire' ? 'crit' : 'warn'));
      rc.appendChild(line);
    } else rc.appendChild(el('p', 'muted small tmx-none', 'Off - the members are never asked to be confirmed.'));
    var rhist = el('div', 'tmg-rhist');
    rc.appendChild(rhist);
    if (fullAdmin()) {
      var re = headButton(rc, iconButton('edit', 'Set the access reviews'));
      re.id = 'tmg-g-review-edit';
      re.onclick = function () { editReview(t); };
    }
    api('teams/reviews&team=' + enc(t.name)).then(function (d) {
      var list = d.reviews || [];
      var cur = list.filter(function (r) { return r.state === 'open' || r.state === 'overdue'; })[0];
      if (cur) {
        var open = el('button', 'tmg-rvcard' + (cur.late || cur.state === 'overdue' ? ' late' : ''));
        open.type = 'button';
        open.id = 'tmg-g-review-open';
        var tt = el('div', 'tmg-rvcard-t');
        tt.appendChild(el('b', '', 'The review open now'));
        tt.appendChild(stateChip(cur.late && cur.state === 'open' ? 'overdue' : cur.state));
        open.appendChild(tt);
        var bar = el('div', 'tmg-prog');
        var fill = el('span', '');
        var tot = (cur.items || []).length;
        fill.style.width = (tot ? Math.round(100 * (tot - cur.pending) / tot) : 100) + '%';
        bar.appendChild(fill);
        open.appendChild(bar);
        open.appendChild(el('span', 'muted small', '{0} to confirm, by {1}'.replace('{0}', num(cur.pending)).replace('{1}', dateOf(cur.due))));
        open.onclick = function () { reviewDialog(cur, function () { refresh(t.name); }); };
        rhist.appendChild(open);
      } else if (d.may_answer) {
        var st = cmdButton('Start a review now', 'play', 'small');
        st.id = 'tmg-g-review-start';
        st.onclick = function () {
          busy(st, true);
          api('teams/review_open', {team: t.name}).then(function (x) { toast(x.message || 'open', 'good'); refresh(t.name); }).catch(oops).then(function () { busy(st, false); });
        };
        rhist.appendChild(st);
      }
      var past = list.filter(function (r) { return r !== cur; });
      if (past.length) {
        rhist.appendChild(sectionHead('history', 'History'));
        var tb = el('div', 'tmg-hrows');
        past.slice(0, 8).forEach(function (r) {
          var row = el('div', 'tmg-hrow');
          row.appendChild(data('span', 'mono small', dateOf(r.started)));
          row.appendChild(stateChip(r.state));
          var kept = (r.items || []).filter(function (i) { return i.state === 'kept'; }).length;
          var out = (r.items || []).filter(function (i) { return i.state === 'removed' || i.state === 'expired'; }).length;
          row.appendChild(el('span', 'muted small', '{0} confirmed, {1} taken out'.replace('{0}', num(kept)).replace('{1}', num(out))));
          tb.appendChild(row);
        });
        rhist.appendChild(tb);
        var dl = cmdButton('Download the report (CSV)', 'download', 'small');
        dl.id = 'tmg-g-review-csv';
        dl.onclick = function () { reviewCsv(t.name, list); };
        rhist.appendChild(dl);
      }
    }).catch(function () { });
    grid.appendChild(rc);
    /* temporary roles */
    var jc = govCard('clock', 'Temporary roles', null);
    jc.id = 'tmg-g-jit';
    var jl = el('div', 'tmg-jit');
    jc.appendChild(jl);
    if (fullAdmin()) {
      var je = headButton(jc, iconButton('edit', 'Set the temporary roles'));
      je.id = 'tmg-g-jit-edit';
      je.onclick = function () { editJit(t); };
    }
    api('teams/elevations&team=' + enc(t.name)).then(function (d) {
      if (d.rule) {
        var line = el('div', 'tmx-mroles');
        d.rule.roles.forEach(function (r) { line.appendChild(roleChip(r)); });
        line.appendChild(chip(tr('{0} h at most').replace('{0}', num(d.rule.max_hours)), 'dim', 'clock'));
        if (d.rule_from && low(d.rule_from) !== low(t.name)) { var f = el('span', 'tmx-from'); f.appendChild(el('span', '', 'from')); f.appendChild(data('b', '', d.rule_from)); line.appendChild(f); }
        jl.appendChild(line);
      } else jl.appendChild(el('p', 'muted small tmx-none', 'Off - nobody asks for a role here for a while.'));
      var act = (d.rows || []).filter(function (r) { return r.state === 'granted' || r.state === 'waiting'; });
      act.forEach(function (r) { jl.appendChild(elevRow(r, r.state === 'waiting' && (d.to_decide || []).some(function (x) { return x.id === r.id; }) ? 'decide' : 'mine', function () { refresh(t.name); })); });
      var mayHere = (d.may_ask || []).filter(function (m) { return low(m.team) === low(t.name); });
      if (mayHere.length) {
        var ab = cmdButton('Ask for a role', 'add', 'small');
        ab.id = 'tmg-g-jit-ask';
        ab.onclick = function () { askElevation(mayHere, t.name, function () { refresh(t.name); }); };
        jl.appendChild(ab);
      }
      var past = (d.rows || []).filter(function (r) { return act.indexOf(r) < 0; }).slice(0, 5);
      if (past.length) {
        jl.appendChild(sectionHead('history', 'Lately'));
        past.forEach(function (r) {
          var row = el('div', 'tmg-hrow');
          row.appendChild(data('span', 'mono small', dateOf(r.asked)));
          row.appendChild(data('span', 'small', shortWho(r.asked_by)));
          row.appendChild(roleChip(r.role));
          row.appendChild(stateChip(r.state));
          jl.appendChild(row);
        });
      }
    }).catch(function () { });
    grid.appendChild(jc);
    /* separation of duties */
    var sc = govCard('tmg_pair', 'Separation of duties', null);
    sc.id = 'tmg-g-sod';
    var sod = g.sod || {};
    var sl = el('div', 'tmg-sod');
    var self = el('div', 'tmg-sodl');
    self.appendChild(chip(sod.no_self_approval ? 'on' : 'as the approval rule says', sod.no_self_approval ? 'ok' : 'dim', sod.no_self_approval ? 'check' : null));
    self.appendChild(el('span', 'small', 'The one who asks never approves their own request'));
    sl.appendChild(self);
    (sod.exclusive || []).forEach(function (p) {
      var pr = el('div', 'tmg-pair');
      pr.appendChild(pairSide(p[0]));
      pr.appendChild(ic('tmg_pair', 14, 'tmg-pair-x'));
      pr.appendChild(pairSide(p[1]));
      pr.appendChild(el('span', 'muted small', 'never the same person'));
      sl.appendChild(pr);
    });
    var up = chainOf(T, n.name).slice(0, -1);
    up.forEach(function (a) {
      var s2 = (a.t.gov || {}).sod || {};
      (s2.exclusive || []).forEach(function (p) {
        var pr = el('div', 'tmg-pair inh');
        pr.appendChild(pairSide(p[0]));
        pr.appendChild(ic('tmg_pair', 14, 'tmg-pair-x'));
        pr.appendChild(pairSide(p[1]));
        var f = el('span', 'tmx-from'); f.appendChild(el('span', '', 'from')); f.appendChild(data('b', '', a.name));
        pr.appendChild(f);
        sl.appendChild(pr);
      });
      if (s2.no_self_approval && !sod.no_self_approval) { var x = el('div', 'tmg-sodl'); x.appendChild(chip('on', 'ok', 'check')); x.appendChild(el('span', 'small', 'never their own request')); var f2 = el('span', 'tmx-from'); f2.appendChild(el('span', '', 'from')); f2.appendChild(data('b', '', a.name)); x.appendChild(f2); sl.appendChild(x); }
    });
    if (!(sod.exclusive || []).length && !sod.no_self_approval && !sl.querySelector('.inh')) sl.appendChild(el('p', 'muted small tmx-none', 'No pair of roles is kept apart.'));
    sc.appendChild(sl);
    if (fullAdmin()) {
      var se = headButton(sc, iconButton('edit', 'Set the separation of duties'));
      se.id = 'tmg-g-sod-edit';
      se.onclick = function () { editSod(t); };
    }
    grid.appendChild(sc);
    /* notifications */
    var nc = govCard('bell', 'Notifications and escalation', null);
    nc.id = 'tmg-g-notify';
    var nt = g.notify, ntFrom = null, ntHooks = g.hooks || {};
    if (!nt) {
      chainOf(T, n.name).slice(0, -1).reverse().some(function (a) {
        var an = (a.t.gov || {}).notify;
        if (an) { nt = an; ntFrom = a.name; ntHooks = (a.t.gov || {}).hooks || {}; }
        return !!an;
      });
    }
    if (nt) {
      if (ntFrom) {
        var nf = el('div', 'tmx-mroles');
        var fr = el('span', 'tmx-from'); fr.appendChild(el('span', '', 'from')); fr.appendChild(data('b', '', ntFrom));
        nf.appendChild(fr);
        nc.appendChild(nf);
      }
      var chain = el('div', 'tmg-chain');
      var stepN = function (icon, when, who, tone) {
        var s = el('div', 'tmg-step ' + (tone || ''));
        s.appendChild(ic(icon, 16));
        var w = el('div', 'tmg-step-w');
        w.appendChild(el('span', 'tmg-step-when', when));
        w.appendChild(who instanceof Node ? who : el('b', '', who));
        s.appendChild(w);
        return s;
      };
      var mails = function (v, fallback) {
        var x = el('span', 'tmg-mails');
        var lst = String(v || '').split(/\s*,\s*/).filter(Boolean);
        if (!lst.length) { x.appendChild(el('span', 'muted small', fallback)); return x; }
        lst.forEach(function (m) { x.appendChild(dataChip(m, 'dim', 'mail')); });
        return x;
      };
      if (nt.expiry_days) chain.appendChild(stepN('clock', tr('{0} days before the end').replace('{0}', num(nt.expiry_days)), mails(nt.mail || t.contact_mail, tr('the team (no address)')), 'info'));
      if (nt.manager_days) chain.appendChild(stepN('tmg_up', tr('{0} days before the end').replace('{0}', num(nt.manager_days)), mails(nt.manager_mail, tr('the manager (no address)')), 'warn'));
      if (nt.deploy_failed) chain.appendChild(stepN('router', tr('a failed deployment'), mails(nt.deploy_failed === 'oncall' ? nt.oncall_mail : nt.deploy_failed === 'manager' ? nt.manager_mail : (nt.mail || t.contact_mail), tr('nobody (no address)')), 'crit'));
      nc.appendChild(chain);
      var hk = el('div', 'tmx-mroles tmg-hooks');
      hk.appendChild(chip(ntHooks.teams ? 'Teams webhook set' : 'no Teams webhook', ntHooks.teams ? 'ok' : 'dim', 'tmg_chain'));
      hk.appendChild(chip(ntHooks.slack ? 'Slack webhook set' : 'no Slack webhook', ntHooks.slack ? 'ok' : 'dim', 'tmg_chain'));
      nc.appendChild(hk);
    } else nc.appendChild(el('p', 'muted small tmx-none', 'Off - as before: the team\'s contact addresses are told of failures and certificates running out (Settings → Notifications). Set channels to escalate.'));
    if (fullAdmin()) {
      var ne = headButton(nc, iconButton('edit', 'Set the channels and the escalation'));
      ne.id = 'tmg-g-notify-edit';
      ne.onclick = function () { editNotify(t); };
      if (nt && !ntFrom) {
        var tryB = headButton(nc, iconButton('play', 'Try every channel now'));
        tryB.id = 'tmg-g-notify-try';
        tryB.onclick = function () {
          busy(tryB, true);
          api('teams/notify_test', {team: t.name}).then(function (d) {
            var said = Object.keys(d.channels || {}).map(function (k) { return k + ': ' + ((d.channels[k] || {}).result || '?'); }).join(' · ');
            toast(said || 'nothing to try', said.indexOf('sent') >= 0 ? 'good' : 'bad');
          }).catch(oops).then(function () { busy(tryB, false); });
        };
      }
    }
    grid.appendChild(nc);
    /* who may */
    if (checks()) {
      var wm = el('div', 'tmx-note');
      wm.appendChild(ic('tmg_who', 16));
      wm.appendChild(el('span', '', 'Who may do what in this team - and why: every member, those of the teams above, temporary roles and the administrators.'));
      var go = cmdButton('Show', 'tmg_who', 'small');
      go.id = 'tmg-g-whomay';
      go.onclick = function () { GOV.mode = 'team'; GOV.team = t.name; UI.view = 'whomay'; keep(); drawPane(); };
      wm.appendChild(go);
      box.appendChild(wm);
    }
  }
  function pairSide(x) {
    if (/^[a-z]+\.[a-z]+$/.test(x)) { var c = data('span', 'tmx-cap', x); return c; }
    return roleOf(x) ? roleChip(x) : dataChip(x, 'legacy');
  }
  function reviewCsv(team, list) {
    /* a cell a spreadsheet would run as a formula starts with a quote (hunt w8: a member's
       answer note "=HYPERLINK(...)" went into the file as it was) - as every other CSV of acme */
    var q = function (v) { v = String(v === undefined || v === null ? '' : v); if (/^[=+\-@\t\r]/.test(v) && v !== '-' && !/^-?\d+(\.\d+)?$/.test(v)) v = "'" + v; return /[",\n\r;]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
    var lines = [['team', 'review', 'started', 'started_by', 'due', 'state', 'member', 'roles', 'answer', 'by', 'at', 'note'].join(',')];
    list.forEach(function (r) {
      (r.items || []).forEach(function (i) {
        lines.push([team, r.id, stamp(r.started), r.started_by, stamp(r.due), r.state, i.who, (i.roles || []).concat(i.rights || []).join(' '),
                    i.state, i.by || '', i.at ? stamp(i.at) : '', i.note || ''].map(q).join(','));
      });
    });
    var blob = new Blob(['﻿' + lines.join('\r\n') + '\r\n'], {type: 'text/csv;charset=utf-8'});
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'access-reviews-' + team.replace(/[^A-Za-z0-9._-]+/g, '_') + '.csv';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function govSave(t, key, value, b) {
    var body = {team: t.name};
    body[key] = value;
    busy(b, true);
    return api('teams/governance', body).then(function (x) {
      toast(x.message || 'saved', 'good');
      closeModal(true);
      if ((x.clash || []).length) {
        modal('Separation of duties: memberships that clash now', function (bd) {
          bd.classList.add('tmx-dlg');
          bd.appendChild(el('p', 'note', 'The rule holds for every membership added or changed from now on. These hold both roles of a pair already - change them by hand:'));
          x.clash.forEach(function (c) {
            var r = el('div', 'tmg-pair');
            r.appendChild(dataChip(c.team, 'dim', 'people'));
            r.appendChild(data('b', 'mono', shortWho(c.who)));
            r.appendChild(pairSide(c.pair[0]));
            r.appendChild(ic('tmg_pair', 14, 'tmg-pair-x'));
            r.appendChild(pairSide(c.pair[1]));
            bd.appendChild(r);
          });
        }, [{words: 'Close', close: true}], 'medium');
      }
      UI.tab = 'gov';
      keep();
      return refresh(t.name);
    }).catch(oops).then(function () { busy(b, false); });
  }
  function numBox(v, id, min, max) {
    var i = el('input', '');
    i.type = 'number';
    i.id = id;
    if (min !== undefined) i.min = String(min);
    if (max !== undefined) i.max = String(max);
    i.value = v === undefined || v === null ? '' : String(v);
    return i;
  }
  function switchOn(sw) { var i = sw._input || sw.querySelector('input'); return !!(i && i.checked); }
  function editReview(t) {
    var r = (t.gov || {}).review || {};
    modal(tr('Access reviews of {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var on = switchBox(!!(t.gov || {}).review);
      on.id = 'tmg-rv-on';
      body.appendChild(formField('Review the members regularly', on, 'The managers of the team (team.members) confirm each member and their roles; they never confirm their own membership.'));
      var every = numBox(r.every_days || 90, 'tmg-rv-every', 7, 3650);
      body.appendChild(formField('Every … days', every));
      var ans = numBox(r.answer_days || 14, 'tmg-rv-answer', 1, 365);
      body.appendChild(formField('Days to answer', ans));
      var act = segmented([['report', 'Report them', 'flag'], ['expire', 'Their membership expires', 'clock']], r.action || 'report');
      act.id = 'tmg-rv-action';
      body.appendChild(formField('Members not confirmed in time', act));
      editReview._read = function () { return switchOn(on) ? {every_days: Number(every.value), answer_days: Number(ans.value), action: act.value} : null; };
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) { govSave(t, 'review', editReview._read(), b); }}], 'medium');
  }
  function editJit(t) {
    var r = (t.gov || {}).jit || {};
    var chosen = (r.roles || []).slice();
    modal(tr('Temporary roles on {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var on = switchBox(!!(t.gov || {}).jit);
      on.id = 'tmg-jit-on';
      body.appendChild(formField('Members may ask for a role for a while', on, 'Set here, it holds for the teams below too, unless one of them sets its own.'));
      var pick = el('div', 'tmx-rolepick');
      pick.id = 'tmg-jit-roles';
      var paint = function () {
        clear(pick);
        ((TM.d || {}).roles || []).forEach(function (ro) {
          var isOn = chosen.indexOf(ro.name) >= 0;
          var b = el('button', 'tmx-rchip' + (isOn ? ' on' : '') + (ro.builtin ? '' : ' custom'));
          b.type = 'button';
          b.setAttribute('aria-pressed', isOn ? 'true' : 'false');
          var k = el('span', 'tmx-rchk');
          k.innerHTML = iconMarkup('check', 11);
          b.appendChild(k);
          b.appendChild((ro.builtin ? el : data)('span', '', ro.name));
          b.onclick = function () { if (isOn) chosen = chosen.filter(function (x) { return x !== ro.name; }); else chosen.push(ro.name); paint(); };
          pick.appendChild(b);
        });
      };
      paint();
      body.appendChild(formField('The roles that may be asked for', pick));
      var mh = numBox(r.max_hours || 8, 'tmg-jit-max', 1, 720);
      body.appendChild(formField('For how many hours at most', mh));
      editJit._read = function () { return switchOn(on) ? {roles: chosen, max_hours: Number(mh.value)} : null; };
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
          var v = editJit._read();
          if (v && !v.roles.length) { toast('choose at least one role', 'bad'); return; }
          govSave(t, 'jit', v, b);
        }}], 'medium');
  }
  function editSod(t) {
    var r = (t.gov || {}).sod || {};
    var pairs = (r.exclusive || []).map(function (p) { return [p[0], p[1]]; });
    modal(tr('Separation of duties in {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg');
      var self = switchBox(!!r.no_self_approval);
      self.id = 'tmg-sod-self';
      body.appendChild(formField('The one who asks never approves their own request', self, 'Wherever requests are approved - certificates, actions waiting for an approval, temporary roles - whatever the approval rule\'s "self" says.'));
      body.appendChild(sectionHead('tmg_pair', 'Never the same person on the team'));
      var list = el('div', 'tmg-pairs');
      list.id = 'tmg-sod-pairs';
      body.appendChild(list);
      var opts = [];
      ((TM.d || {}).roles || []).forEach(function (ro) { opts.push([ro.name, ro.name]); });
      capGroups().forEach(function (g) { g.caps.forEach(function (c) { opts.push([c.id, c.id]); }); });
      var paint = function () {
        clear(list);
        pairs.forEach(function (p, i) {
          var row = el('div', 'tmg-pair edit');
          var a = selectBox(opts, p[0]);
          var b = selectBox(opts, p[1]);
          noI18n(a); noI18n(b);
          a.onchange = function () { p[0] = a.value; };
          b.onchange = function () { p[1] = b.value; };
          row.appendChild(a);
          row.appendChild(ic('tmg_pair', 14, 'tmg-pair-x'));
          row.appendChild(b);
          var x = iconButton('trash', 'Take this pair away');
          x.onclick = function () { pairs.splice(i, 1); paint(); };
          row.appendChild(x);
          list.appendChild(row);
        });
        if (!pairs.length) list.appendChild(el('p', 'muted small tmx-none', 'No pair yet.'));
      };
      paint();
      var add = cmdButton('Add a pair', 'add', 'small');
      add.id = 'tmg-sod-add';
      add.onclick = function () { pairs.push(['Approver', 'Certificate manager']); paint(); };
      body.appendChild(add);
      body.appendChild(el('p', 'muted small', 'Checked when members are saved (a membership holding both is refused), when a temporary role is given, and when somebody approves (an approver holding both is refused). A rule here holds for the teams below too.'));
      editSod._read = function () { return (switchOn(self) || pairs.length) ? {no_self_approval: switchOn(self), exclusive: pairs} : null; };
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) { govSave(t, 'sod', editSod._read(), b); }}], 'medium');
  }
  function editNotify(t) {
    var r = (t.gov || {}).notify || {};
    var hooks = (t.gov || {}).hooks || {};
    modal(tr('Notifications of {0}').replace('{0}', t.name), function (body) {
      body.classList.add('tmx-dlg', 'tmg-ndlg');
      var on = switchBox(!!(t.gov || {}).notify);
      on.id = 'tmg-n-on';
      body.appendChild(formField('Channels and escalation of its own', on, 'Set here, they hold for the teams below too, unless one of them sets its own.'));
      body.appendChild(sectionHead('mail', 'Who'));
      var mail = textBox(r.mail || '', t.contact_mail || 'team@example.com');
      mail.id = 'tmg-n-mail';
      noI18n(mail);
      body.appendChild(formField('The team', mail, 'Empty: the team\'s contact addresses.'));
      var mgr = textBox(r.manager_mail || '', 'lead@example.com');
      mgr.id = 'tmg-n-mgr';
      noI18n(mgr);
      body.appendChild(formField('The manager', mgr));
      var onc = textBox(r.oncall_mail || '', 'oncall@example.com');
      onc.id = 'tmg-n-oncall';
      noI18n(onc);
      body.appendChild(formField('On-call', onc));
      body.appendChild(sectionHead('tmg_chain', 'Webhooks'));
      var hk = function (k, label, ph) {
        var i = el('input', '');
        i.type = 'password';
        i.autocomplete = 'new-password';
        i.id = 'tmg-n-' + k;
        i.placeholder = hooks[k] ? tr('set - type a new address to change it') : ph;
        noI18n(i);
        var wrap = el('div', 'tmg-hookrow');
        wrap.appendChild(i);
        var clr = null;
        if (hooks[k]) {
          clr = el('label', 'tmg-hookclr');
          var cb = document.createElement('input');
          cb.type = 'checkbox';
          cb.id = 'tmg-n-' + k + '-clear';
          clr.appendChild(cb);
          clr.appendChild(el('span', '', 'take it away'));
          wrap.appendChild(clr);
        }
        body.appendChild(formField(label, wrap, 'Kept sealed - never shown again, not even to you.'));
        return function () {
          if (clr && clr.querySelector('input').checked) return '';
          return i.value.trim() || null;
        };
      };
      var teamsHook = hk('teams', 'Microsoft Teams', 'https://….webhook.office.com/…');
      var slackHook = hk('slack', 'Slack', 'https://hooks.slack.com/services/…');
      body.appendChild(sectionHead('tmg_up', 'Escalation'));
      var ed = numBox(r.expiry_days === undefined ? 14 : r.expiry_days, 'tmg-n-exp', 0, 365);
      body.appendChild(formField('Tell the team … days before a certificate ends', ed));
      var md = numBox(r.manager_days === undefined ? 3 : r.manager_days, 'tmg-n-mdays', 0, 365);
      body.appendChild(formField('Tell the manager … days before', md));
      var dep = segmented([['oncall', 'On-call'], ['manager', 'The manager'], ['team', 'The team'], ['', 'Nobody']], r.deploy_failed === undefined ? 'oncall' : r.deploy_failed);
      dep.id = 'tmg-n-dep';
      dep.classList.add('wrap');
      body.appendChild(formField('A failed deployment goes to', dep));
      var ev = switchBox(r.elevations !== false);
      ev.id = 'tmg-n-elev';
      body.appendChild(formField('Temporary roles: asked, given, ended', ev));
      var rv = switchBox(r.reviews !== false);
      rv.id = 'tmg-n-rev';
      body.appendChild(formField('Access reviews: opened, overdue', rv));
      editNotify._read = function () {
        return {notify: switchOn(on) ? {mail: mail.value.trim(), manager_mail: mgr.value.trim(), oncall_mail: onc.value.trim(),
                                         expiry_days: Number(ed.value), manager_days: Number(md.value), deploy_failed: dep.value,
                                         elevations: switchOn(ev), reviews: switchOn(rv)} : null,
                hooks: {teams: teamsHook(), slack: slackHook()}};
      };
    }, [{words: 'Close', close: true},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
          var v = editNotify._read();
          var hk = {team: t.name};
          if (v.hooks.teams !== null) hk.teams = v.hooks.teams;
          if (v.hooks.slack !== null) hk.slack = v.hooks.slack;
          busy(b, true);
          var first = (hk.teams !== undefined || hk.slack !== undefined) ? api('teams/hooks', hk) : Promise.resolve();
          first.then(function () { busy(b, false); return govSave(t, 'notify', v.notify, b); }).catch(function (e) { busy(b, false); oops(e); });
        }}], 'medium');
  }

  function tr(s) {
    try { var got = typeof i18nText === 'function' ? i18nText(s) : null; return got || s; } catch (e) { return s; }
  }

  window.ACME_TEAMS = {load: load, ownerPicker: ownerPicker, tagPicker: tagPicker, tagChip: tagChip,
                       ownerChip: ownerChip, fillFilters: fillFilters, teamOf: teamOf, tagOf: tagOf};
  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.teams = function () { drawPane(); };
  /* A page that opened on this pane drew it before this file came. */
  if (typeof PANE === 'string' && PANE === 'teams') drawPane();
  load().then(fillFilters).catch(function () { });
  /* viewing as somebody (1.0.138): the banner on every page of the administration */
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', viewAsCheck);
  else viewAsCheck();
})();
