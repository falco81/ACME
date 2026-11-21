/* savedviews.js - saved views of the tables (1.0.138, X3; docs/history-and-trash.md).

   By the filters of every list that has them (a .btnrow.filters of a tab or a pane of Settings:
   the certificates, the targets, the jobs, the events...) a small menu "Views": the filters, the
   sort and the columns as they are now kept under a name - for oneself, shared with a team (who
   may see the team, team.view) or, by a full administrator, for everybody - picked again from that
   menu, and one of them opened by itself with the page (the star).

   Kept by the daemon (GET /api/views, POST /api/views/save, /delete, /default), so they follow
   the person to every browser. A list is known by the id of its first filter (ct-q, tg-q, jb-kind...).
   The columns are cols.js's layout of that list's table (COLS): put in place while a view is
   chosen, the person's own layout back when it is left - never saved over it, and never while
   "Edit the columns" is on (then a view changes the filters only). cols.js tells this file when a
   table is laid out (window.ACME_COLS_HOOK), so a view's columns are there from its first drawing. */
'use strict';
(function () {
  if (typeof ME !== 'object' || !ME) return;
  var SV = {d: null, asking: null, rows: {}, cur: {}, cols: {}, backup: {}, menu: null};

  function T(w) { try { return (typeof i18nText === 'function' && i18nText(w)) || w; } catch (e) { return w; } }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function ic(key, size, cls) {
    var s = el('span', 'tmx-ic' + (cls ? ' ' + cls : ''));
    s.innerHTML = iconMarkup(key, size || 16);
    s.setAttribute('aria-hidden', 'true');
    return s;
  }
  function chip(words, cls, icon) {
    var c = el('span', 'tmx-chip' + (cls ? ' ' + cls : ''));
    if (icon) c.appendChild(ic(icon, 12));
    if (words instanceof Node) c.appendChild(words); else c.appendChild(el('span', '', words));
    return c;
  }
  function clone(o) { return o === undefined ? undefined : JSON.parse(JSON.stringify(o)); }
  function full() { return ME.role === 'fulladmin'; }

  /* ---- the lists that have filters ---- */
  function controls(row) {
    return Array.prototype.filter.call(row.querySelectorAll('input[id], select[id]'), function (c) {
      if (c.closest('.sv-wrap')) return false;
      if (c.tagName === 'SELECT') return true;
      return /^(search|text|checkbox)$/.test(c.type || 'text');
    });
  }
  function keyOf(row) {
    if (row._svKey !== undefined) return row._svKey;
    var c = controls(row)[0];
    row._svKey = c && /^[A-Za-z][A-Za-z0-9_-]{0,60}$/.test(c.id) ? c.id : '';
    return row._svKey;
  }
  function cardOf(row) { return row.closest('.card') || row.parentNode; }
  function tableOf(row) {
    var card = cardOf(row);
    var t = card ? card.querySelector('table') : null;
    return t && !t.closest('.modal') ? t : null;
  }
  function rowOfTable(table) {
    var card = table.closest('.card');
    var row = card ? card.querySelector('.btnrow.filters') : null;
    return row && SV.rows[keyOf(row)] === row ? row : null;
  }
  function original(c) {
    if (c.tagName === 'SELECT') {
      var o = Array.prototype.filter.call(c.options, function (x) { return x.defaultSelected; })[0] || c.options[0];
      return o ? o.value : '';
    }
    if (c.type === 'checkbox') return !!c.defaultChecked;
    return c.defaultValue || '';
  }
  function valueOf(c) { return c.type === 'checkbox' ? !!c.checked : c.value; }
  function shown(row) { return !!(row.offsetParent || row.getClientRects().length); }
  function setValue(c, want, fire) {
    if (c.type === 'checkbox') {
      if (!!c.checked === !!want) return false;
      c.checked = !!want;
      if (fire) c.dispatchEvent(new Event('change', {bubbles: true}));
      return true;
    }
    want = want === undefined || want === null ? '' : String(want);
    if (c.value === want) return false;
    if (c.tagName === 'SELECT' && !Array.prototype.some.call(c.options, function (o) { return o.value === want; })) {
      /* its options come later (a source, an owner, a tag): set when they are there */
      waitOption(c, want, fire);
      return false;
    }
    c.value = want;
    if (fire) c.dispatchEvent(new Event(c.tagName === 'SELECT' ? 'change' : 'input', {bubbles: true}));
    return true;
  }
  function waitOption(c, want, fire) {
    if (c._svWait) c._svWait.disconnect();
    if (!window.MutationObserver) return;
    var ob = new MutationObserver(function () {
      if (Array.prototype.some.call(c.options, function (o) { return o.value === want; })) {
        ob.disconnect();
        c._svWait = null;
        c.value = want;
        if (fire || shown(c)) c.dispatchEvent(new Event('change', {bubbles: true}));
      }
    });
    ob.observe(c, {childList: true});
    c._svWait = ob;
    setTimeout(function () { ob.disconnect(); }, 20000);
  }

  /* ---- what a list looks like now, and putting a view in place ---- */
  function stateOf(row) {
    var st = {filters: {}};
    controls(row).forEach(function (c) { st.filters[c.id] = valueOf(c); });
    var t = tableOf(row);
    if (t && t._colsKey && typeof COLS === 'object' && COLS[t._colsKey]) {
      var c = clone(COLS[t._colsKey]);
      delete c.t;
      if (Object.keys(c).length) st.cols = c;
      st.key = t._colsKey;
    }
    if (t && t.tHead) {
      var th = t.tHead.querySelector('th[aria-sort="ascending"], th[aria-sort="descending"]');
      if (th && th.dataset.ck) st.sort = {col: th.dataset.ck, dir: th.getAttribute('aria-sort') === 'ascending' ? 'asc' : 'desc'};
    }
    return st;
  }
  function editing() { return typeof COLS_EDIT !== 'undefined' && !!COLS_EDIT; }
  function putCols(key, table, cols) {
    if (typeof COLS !== 'object' || !table || !table._colsKey) return;
    var ck = table._colsKey;
    if (!(ck in SV.backup)) SV.backup[ck] = COLS[ck] ? clone(COLS[ck]) : null;
    if (cols) COLS[ck] = clone(cols);
    else if (SV.backup[ck]) COLS[ck] = clone(SV.backup[ck]);
    else delete COLS[ck];
    if (!cols) delete SV.backup[ck];
    try { if (typeof colsApply === 'function') colsApply(table); } catch (e) { }
  }
  function sortTo(table, srt) {
    if (!table || !table.tHead || !srt) return;
    var th = Array.prototype.filter.call(table.tHead.querySelectorAll('th'), function (x) { return x.dataset.ck === srt.col; })[0];
    if (!th || !th.hasAttribute('aria-sort')) return;
    var want = srt.dir === 'asc' ? 'ascending' : 'descending';
    for (var i = 0; i < 2 && th.getAttribute('aria-sort') !== want; i++) th.click();
  }
  function apply(row, view, quiet) {
    var key = keyOf(row);
    var st = view ? (view.state || {}) : {};
    var f = st.filters || {};
    var fire = shown(row);
    controls(row).forEach(function (c) {
      setValue(c, Object.prototype.hasOwnProperty.call(f, c.id) ? f[c.id] : original(c), fire);
    });
    SV.cur[key] = view ? view.id : null;
    var table = tableOf(row);
    if (!editing()) {
      SV.cols[key] = view && st.cols ? st.cols : null;
      if (table) putCols(key, table, SV.cols[key]);
    } else if (view && st.cols && !quiet) {
      toast('The columns stay as they are while editing the columns is switched on - the filters were set', 'bad');
    }
    if (view && st.sort && table) sortTo(table, st.sort);
    drawButton(row);
  }
  /* cols.js: a table laid out - the view's columns there before it is painted */
  window.ACME_COLS_HOOK = function (table, ck) {
    if (editing() || typeof COLS !== 'object') return;
    var row = rowOfTable(table);
    if (!row) return;
    var cols = SV.cols[keyOf(row)];
    if (!cols) return;
    if (!(ck in SV.backup)) SV.backup[ck] = COLS[ck] ? clone(COLS[ck]) : null;
    var want = JSON.stringify(cols), have = COLS[ck] ? JSON.stringify((function (x) { x = clone(x); delete x.t; return x; }(COLS[ck]))) : '';
    if (want !== have) COLS[ck] = clone(cols);
  };

  /* ---- the daemon ---- */
  function load(force) {
    if (SV.d && !force) return Promise.resolve(SV.d);
    if (SV.asking && !force) return SV.asking;
    SV.asking = api('views').then(function (d) { SV.d = d || {views: []}; SV.asking = null; return SV.d; },
      function (e) { SV.asking = null; throw e; });
    return SV.asking;
  }
  function viewsOf(key) { return ((SV.d || {}).views || []).filter(function (v) { return v.table === key; }); }
  function viewById(id) { return ((SV.d || {}).views || []).filter(function (v) { return v.id === id; })[0] || null; }
  function defaultOf(key) { return ((SV.d || {}).defaults || {})[key] || null; }

  /* ---- the button and its menu ---- */
  function drawButton(row) {
    var w = row._svWrap;
    if (!w) return;
    var key = keyOf(row);
    var cur = SV.cur[key] ? viewById(SV.cur[key]) : null;
    var b = w.firstChild;
    clear(b);
    b.appendChild(ic(cur ? 'star' : 'list', 14));
    b.appendChild(cur ? data('span', 'sv-name', cur.name) : el('span', 'sv-name', 'Views'));
    b.appendChild(el('span', 'sv-caret', '▾'));
    b.classList.toggle('on', !!cur);
    b.setAttribute('aria-label', cur ? T('Saved views') + ': ' + cur.name : T('Saved views'));
  }
  function wire(row) {
    if (row._svWrap || row.closest('.modal')) return;
    var key = keyOf(row);
    if (!key) return;
    SV.rows[key] = row;
    var w = el('span', 'sv-wrap');
    var b = el('button', 'sv-btn');
    b.type = 'button';
    b.setAttribute('aria-haspopup', 'menu');
    b.setAttribute('aria-expanded', 'false');
    explain(b, 'Saved views: the filters, the sort and the columns of this list under a name - yours, a team\'s or everybody\'s. The star opens one by itself.');
    b.onclick = function (e) { e.stopPropagation(); if (SV.menu && SV.menu._row === row) closeMenu(); else openMenu(row); };
    w.appendChild(b);
    row._svWrap = w;
    var spacer = row.querySelector(':scope > .spacer');
    if (spacer) row.insertBefore(w, spacer); else row.appendChild(w);
    drawButton(row);
  }
  function closeMenu(focus) {
    var m = SV.menu;
    if (!m) return;
    SV.menu = null;
    if (m._row && m._row._svWrap) m._row._svWrap.firstChild.setAttribute('aria-expanded', 'false');
    m.remove();
    if (focus && m._row && m._row._svWrap) m._row._svWrap.firstChild.focus();
  }
  function place(menu, b) {
    var r = b.getBoundingClientRect();
    var w = Math.min(340, window.innerWidth - 16);
    menu.style.left = Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8)) + 'px';
    var below = window.innerHeight - r.bottom - 12, above = r.top - 12;
    if (below < 260 && above > below) {
      menu.style.top = '';
      menu.style.bottom = (window.innerHeight - r.top + 6) + 'px';
      menu.style.maxHeight = Math.max(160, Math.min(480, above - 6)) + 'px';
    } else {
      menu.style.bottom = '';
      menu.style.top = Math.max(8, r.bottom + 6) + 'px';
      menu.style.maxHeight = Math.max(160, Math.min(480, below - 6)) + 'px';
    }
  }
  function openMenu(row) {
    closeMenu();
    var key = keyOf(row);
    var b = row._svWrap.firstChild;
    var menu = el('div', 'sv-menu');
    menu.setAttribute('role', 'menu');
    menu.setAttribute('aria-label', T('Saved views'));
    menu._row = row;
    SV.menu = menu;
    b.setAttribute('aria-expanded', 'true');
    menu.appendChild(el('div', 'sv-none', 'Asking…'));
    document.body.appendChild(menu);
    place(menu, b);
    load().then(function () { if (SV.menu === menu) fillMenu(menu, row, key); })
      .catch(function (e) { clear(menu); menu.appendChild(el('div', 'sv-none', (e && e.message) || String(e))); });
  }
  function item(menu, row, v, dflt) {
    var key = keyOf(row);
    var it = el('div', 'sv-item' + (SV.cur[key] === v.id ? ' cur' : ''));
    var pick = el('button', 'sv-pick');
    pick.type = 'button';
    pick.setAttribute('role', 'menuitemradio');
    pick.setAttribute('aria-checked', SV.cur[key] === v.id ? 'true' : 'false');
    pick.appendChild(ic(SV.cur[key] === v.id ? 'check' : (v.scope === 'team' ? 'people' : v.scope === 'global' ? 'globe' : 'person'), 14));
    pick.appendChild(data('span', 'sv-n', v.name));
    if (v.scope === 'team') pick.appendChild(chip(data('span', '', v.team), 'info'));
    pick.onclick = function () { closeMenu(true); apply(row, v); };
    it.appendChild(pick);
    var star = el('button', 'sv-star' + (dflt === v.id ? ' on' : ''));
    star.type = 'button';
    star.innerHTML = iconMarkup('star', 15);
    star.setAttribute('aria-pressed', dflt === v.id ? 'true' : 'false');
    star.setAttribute('aria-label', T(dflt === v.id ? 'Opens by itself - press to stop that' : 'Open it by itself with the page'));
    star.onclick = function (e) {
      e.stopPropagation();
      var on = dflt !== v.id;
      api('views/default', {table: key, id: on ? v.id : null}).then(function (r) {
        SV.d.defaults = SV.d.defaults || {};
        if (on) SV.d.defaults[key] = v.id; else delete SV.d.defaults[key];
        toast(r.message || 'Done', 'good');
        if (SV.menu) fillMenu(SV.menu, row, key);
      }).catch(function (x) { toast(x.message, 'bad'); });
    };
    it.appendChild(star);
    menu.appendChild(it);
  }
  function action(menu, icon, words, go, cls, name) {
    var a = el('button', 'sv-act' + (cls ? ' ' + cls : ''));
    a.type = 'button';
    a.setAttribute('role', 'menuitem');
    a.appendChild(ic(icon, 15));
    a.appendChild(el('span', '', words));
    if (name) { a.appendChild(document.createTextNode(' ')); a.appendChild(data('span', 'sv-n', '“' + name + '”')); }
    a.onclick = function () { closeMenu(true); go(); };
    menu.appendChild(a);
  }
  function fillMenu(menu, row, key) {
    clear(menu);
    var list = viewsOf(key), dflt = defaultOf(key);
    var groups = [['user', 'Mine'], ['team', 'Shared with a team'], ['global', 'For everybody']];
    var any = false;
    groups.forEach(function (g) {
      var vs = list.filter(function (v) { return v.scope === g[0]; });
      if (!vs.length) return;
      any = true;
      menu.appendChild(el('div', 'sv-group', g[1]));
      vs.forEach(function (v) { item(menu, row, v, dflt); });
    });
    if (!any) menu.appendChild(el('div', 'sv-none', 'No view of this list yet. Set the filters and the columns as you want them, then save them as a view.'));
    menu.appendChild(el('div', 'sv-sep'));
    var cur = SV.cur[key] ? viewById(SV.cur[key]) : null;
    action(menu, 'add', 'Save this view…', function () { saveDialog(row, null); });
    if (cur && cur.mine) {
      action(menu, 'save', 'Update', function () {
        api('views/save', {id: cur.id, table: key, name: cur.name, scope: cur.scope, team: cur.team, view: stateOf(row)})
          .then(function (r) { toast(r.message || 'Saved', 'good'); return load(true); })
          .then(function () { drawButton(row); })
          .catch(function (e) { toast(e.message, 'bad'); });
      }, '', cur.name);
      action(menu, 'edit', 'Rename or share…', function () { saveDialog(row, cur); });
      action(menu, 'trash', 'Delete', function () {
        confirmThen('Delete the view', T('The view is deleted - the list stays as it is now.'), 'Delete it', function () {
          api('views/delete', {id: cur.id}).then(function (r) {
            toast(r.message || 'Deleted', 'good');
            SV.cur[key] = null;
            return load(true);
          }).then(function () { drawButton(row); }).catch(function (e) { toast(e.message, 'bad'); });
        });
      }, 'danger', cur.name);
    }
    if (cur) action(menu, 'undo', 'Back to the list as it comes', function () { apply(row, null); });
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(menu);
    var first = menu.querySelector('button');
    if (first) first.focus();
  }
  document.addEventListener('click', function (e) {
    if (SV.menu && !SV.menu.contains(e.target)) closeMenu();
  });
  document.addEventListener('keydown', function (e) {
    if (!SV.menu) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeMenu(true); return; }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      var all = Array.prototype.slice.call(SV.menu.querySelectorAll('button'));
      var at = all.indexOf(document.activeElement);
      var next = all[(at + (e.key === 'ArrowDown' ? 1 : all.length - 1)) % all.length];
      if (next) { e.preventDefault(); next.focus(); }
    }
  }, true);
  window.addEventListener('resize', function () { closeMenu(); });
  window.addEventListener('scroll', function (e) { if (SV.menu && !SV.menu.contains(e.target)) closeMenu(); }, true);

  /* ---- Save this view ---- */
  function saveDialog(row, cur) {
    var key = keyOf(row);
    var st = stateOf(row);
    var pick = {scope: cur ? cur.scope : 'user'};
    load().then(function (d) {
      var name = null, teamSel = null, dflt = null;
      modal(cur ? 'Rename or share the view' : 'Save this view', function (body) {
        var form = el('div', 'formgrid sv-form');
        name = textBox(cur ? cur.name : '', T('e.g. Mine, running out soon'), '');
        noI18n(name);
        name.maxLength = 80;
        form.appendChild(formField('Name', name));
        var scopes = el('div', 'sv-scopes');
        scopes.setAttribute('role', 'radiogroup');
        scopes.setAttribute('aria-label', T('Who sees it'));
        var teams = d.teams || [];
        [['user', 'Only me', 'Yours - nobody else sees it.', 'person', true],
         ['team', 'A team', 'Everybody who may see the team.', 'people', teams.length > 0],
         ['global', 'Everybody', 'Every account of acme - a full administrator\'s.', 'globe', !!d.can_global]].forEach(function (o) {
          var b = el('button', 'sv-scope' + (pick.scope === o[0] ? ' on' : ''));
          b.type = 'button';
          b.setAttribute('role', 'radio');
          b.setAttribute('aria-checked', pick.scope === o[0] ? 'true' : 'false');
          if (!o[4]) b.disabled = true;
          b.appendChild(ic(o[3], 18));
          var w = el('span', '');
          w.appendChild(el('b', '', o[1]));
          w.appendChild(el('span', 'hs-none', o[2]));
          b.appendChild(w);
          b.onclick = function () {
            pick.scope = o[0];
            Array.prototype.forEach.call(scopes.children, function (x) { x.classList.remove('on'); x.setAttribute('aria-checked', 'false'); });
            b.classList.add('on');
            b.setAttribute('aria-checked', 'true');
            teamField.hidden = pick.scope !== 'team';
          };
          scopes.appendChild(b);
        });
        form.appendChild(formField('Who sees it', scopes));
        teamSel = el('select', '');
        teams.forEach(function (t) { var o = el('option', '', t); o.value = t; noI18n(o); teamSel.appendChild(o); });
        if (cur && cur.team) teamSel.value = cur.team;
        var teamField = formField('The team', teamSel);
        teamField.hidden = pick.scope !== 'team';
        form.appendChild(teamField);
        dflt = switchBox(cur ? defaultOf(key) === cur.id : false);
        form.appendChild(formField('Open it by itself', dflt, 'With the page, this list shows this view (for you).'));
        var what = el('div', 'sv-what');
        var nf = Object.keys(st.filters || {}).filter(function (k) {
          var c = document.getElementById(k);
          return c && valueOf(c) !== original(c);
        }).length;
        what.appendChild(chip(nf + ' filter(s) set', nf ? 'info' : 'dim', 'funnel'));
        if (st.cols) what.appendChild(chip('its columns', 'info', 'list'));
        if (st.sort) what.appendChild(chip('its sort', 'info', 'down'));
        form.appendChild(formField('What it keeps', what));
        body.appendChild(form);
      }, [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        var sent = {table: key, name: name.value.trim(), scope: pick.scope, view: cur ? clone(cur.state) : st,
                    'default': dflt._get()};
        if (!cur) sent.view = st;
        if (cur) sent.id = cur.id;
        if (pick.scope === 'team') sent.team = teamSel.value;
        if (!sent.name) { toast(T('Give the view a name'), 'bad'); name.focus(); return; }
        busy(b, true);
        api('views/save', sent).then(function (r) {
          closeModal();
          toast(r.message || 'Saved', 'good');
          SV.cur[key] = r.view.id;
          return load(true);
        }).then(function () {
          if (cur && !dflt._get() && defaultOf(key) === cur.id) return api('views/default', {table: key, id: null}).then(function () { return load(true); });
        }).then(function () { drawButton(row); })
          .catch(function (e) { busy(b, false); toast(e.message, 'bad'); });
      }}], 'narrow');
    }).catch(function (e) { toast(e.message, 'bad'); });
  }

  /* ---- at the start: every list wired, the views that open by themselves put in place ---- */
  function scan() {
    Array.prototype.forEach.call(document.querySelectorAll('section.panel .btnrow.filters, .ctl-pane .btnrow.filters'), wire);
  }
  function start() {
    scan();
    load().then(function () {
      Object.keys(SV.rows).forEach(function (key) {
        var id = defaultOf(key);
        var v = id ? viewById(id) : null;
        if (v) apply(SV.rows[key], v, true);
      });
    }).catch(function () { /* no views: the lists as they come */ });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(start, 0); });
  else setTimeout(start, 0);
  window.acmeViews = {scan: scan, apply: function (key, id) {
    var row = SV.rows[key];
    if (row) apply(row, id ? viewById(id) : null);
  }};
}());
