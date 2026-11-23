/* calendar.js - the expiry calendar (1.0.140, docs/expiry-calendar.md): when certificates run out
   and when acme plans to renew them, as a month and as a year's heatmap (a square a day, its
   colour how soon, its strength how many) - a day or a week clicked lists its certificates,
   each opening the certificate's own card.
   - the administration: Certificates → List | Calendar (the switch above the filters), with
     the filters team, source, target and "only mine", a file for a calendar program and a
     link to subscribe to (GET /api/calendar, /api/calendar/ics, POST /api/calendar/feed_link);
   - the portal: "Calendar" beside "Your certificates" - theirs (GET /api/portal/calendar).
   Only what the server answers is shown: it keeps to what the person may see. The keyboard:
   the arrows move between days (Page Up / Page Down a month), Enter lists a day, Esc closes. */
(function () {
'use strict';
if (window.ACME_CAL) return;
var CAL = window.ACME_CAL = {};
var VIEW_KEY = 'acme.cal.view', MODE_KEY = 'acme.cal.mode';
var DAY = 86400000;

if (typeof ICONS === 'object' && !ICONS.cal) {
  ICONS.cal = '<rect x="3.5" y="5" width="17" height="15.5" rx="2.6"/><path d="M3.5 10h17M8 3v4M16 3v4"/>'
    + '<path d="M8 14h.01M12 14h.01M16 14h.01M8 17.2h.01M12 17.2h.01"/>';
}
if (typeof ICONS === 'object' && !ICONS.cal_grid) {
  ICONS.cal_grid = '<rect x="3" y="4" width="4.2" height="4.2" rx="1"/><rect x="9.9" y="4" width="4.2" height="4.2" rx="1"/>'
    + '<rect x="16.8" y="4" width="4.2" height="4.2" rx="1"/><rect x="3" y="10.9" width="4.2" height="4.2" rx="1"/>'
    + '<rect x="9.9" y="10.9" width="4.2" height="4.2" rx="1"/><rect x="16.8" y="10.9" width="4.2" height="4.2" rx="1"/>'
    + '<rect x="3" y="17.8" width="4.2" height="4.2" rx="1"/><rect x="9.9" y="17.8" width="4.2" height="4.2" rx="1"/>';
}

function tr(s) { try { var t = typeof i18nText === 'function' ? i18nText(String(s)) : null; return t || String(s); } catch (e) { return String(s); } }
function pat(s, a, b) { return tr(s).replace('{0}', a).replace('{1}', b === undefined ? '' : b); }
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function lang() { try { return (typeof I18N === 'object' && I18N.on && I18N.code) || 'en'; } catch (e) { return 'en'; } }
/* the browser's time zone: the .ics file's days are those the page draws (hunt w4) */
function tzName() { try { return (Intl.DateTimeFormat().resolvedOptions().timeZone) || ''; } catch (e) { return ''; } }
function loc() { var l = lang(); return l === 'en' ? 'en-GB' : l; }
function ic(key, size) { var s = el('span', 'cal-ic'); s.innerHTML = iconMarkup(key, size || 16); return s; }
function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { } return null; }
function pad(n) { return (n < 10 ? '0' : '') + n; }
function keyOf(d) { return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()); }
function dayOf(k) { var p = String(k).split('-'); return new Date(+p[0], +p[1] - 1, +p[2]); }
function addDays(d, n) { var x = new Date(d.getFullYear(), d.getMonth(), d.getDate() + n); return x; }
function monday(d) { var w = (d.getDay() + 6) % 7; return addDays(d, -w); }
function today() { var n = new Date(); return new Date(n.getFullYear(), n.getMonth(), n.getDate()); }
function fmt(d, o) { try { return new Intl.DateTimeFormat(loc(), o).format(d); } catch (e) { return keyOf(d); } }
function longDay(d) { return fmt(d, {weekday: 'long', day: 'numeric', month: 'long', year: 'numeric'}); }
function shortDay(d) { return fmt(d, {day: 'numeric', month: 'short'}); }
function monthTitle(d) { return fmt(d, {month: 'long', year: 'numeric'}); }
function diffDays(d) { return Math.round((d - today()) / DAY); }
/* how soon a day is: its colour */
function tone(d) {
  var n = diffDays(d);
  if (n < 8) return 'crit';
  if (n <= 30) return 'warn';
  if (n <= 60) return 'info';
  return 'ok';
}
function level(n) { return n <= 0 ? 0 : n === 1 ? 1 : n === 2 ? 2 : n <= 4 ? 3 : 4; }

/* ---- one calendar: a host, how it asks, how a certificate opens ----------------------- */
function Cal(host, o) {
  this.host = host;
  this.o = o;
  this.view = o.view || store(VIEW_KEY) || 'month';
  if (this.view !== 'month' && this.view !== 'year') this.view = 'month';
  var t = today();
  this.month = new Date(t.getFullYear(), t.getMonth(), 1);
  this.f = {team: '', issuer: '', target: '', mine: false};
  this.cache = [];
  this.pick = null;           /* {kind: 'day'|'week', key} */
  this.focus = keyOf(t);
  this.options = null;
  this.feed = null;
  this.draw();
}
Cal.prototype.window = function () {
  if (this.view === 'year') {
    var a = monday(today());
    return [a, addDays(a, 53 * 7 - 1)];
  }
  var first = this.month, start = monday(first);
  return [start, addDays(start, 41)];
};
Cal.prototype.ensure = function () {
  var self = this, w = this.window(), from = keyOf(w[0]), to = keyOf(w[1]);
  var got = this.cache.filter(function (c) { return c.from <= from && c.to >= to; })[0];
  if (got) return Promise.resolve(got);
  /* the year and the months near it asked at once: moving month by month asks nothing more */
  var a = w[0], b = w[1];
  if (this.view === 'month') {
    var y0 = monday(today()), y1 = addDays(y0, 53 * 7 - 1);
    if (a >= addDays(y0, -45) && b <= y1) { a = addDays(y0, -45); b = y1; }
  }
  var key = keyOf(a) + '|' + keyOf(b);
  if (this.asking && this.asking.key === key) return this.asking.p;
  var p = this.o.load(keyOf(a), keyOf(b), this.f).then(function (d) {
    var one = {from: keyOf(a), to: keyOf(b), certs: (d && d.certs) || [], capped: !!(d && d.capped), rows: (d && d.rows) || []};
    if (d && d.options) self.options = d.options;
    if (d && d.feed) self.feed = d.feed;
    self.cache.push(one);
    if (self.cache.length > 6) self.cache.shift();
    self.asking = null;
    return one;
  }, function (e) { self.asking = null; throw e; });
  this.asking = {key: key, p: p};
  return p;
};
/* {day key: {ends: [entries], renews: [entries]}} in the browser's own days */
Cal.prototype.bins = function (set) {
  var out = {};
  (set.certs || []).forEach(function (e) {
    [['ends', e.not_after], ['renews', e.renew_at]].forEach(function (x) {
      if (!x[1]) return;
      var d = new Date(x[1] * 1000);
      var k = keyOf(new Date(d.getFullYear(), d.getMonth(), d.getDate()));
      var b = out[k] || (out[k] = {ends: [], renews: []});
      b[x[0]].push(e);
    });
  });
  return out;
};
Cal.prototype.refilter = function () { this.cache = []; this.pick = null; this.draw(); };

Cal.prototype.draw = function () {
  var self = this;
  clear(this.host);
  var root = el('div', 'cal' + (this.o.compact ? ' compact' : ''));
  root.setAttribute('data-view', this.view);
  this.host.appendChild(root);
  root.appendChild(this.bar());
  var tiles = el('div', 'cal-tiles');
  root.appendChild(tiles);
  var main = el('div', 'cal-main');
  var board = el('div', 'cal-board');
  board.appendChild(el('div', 'cal-asking', 'Asking…'));
  main.appendChild(board);
  var side = el('aside', 'cal-side');
  side.setAttribute('aria-live', 'polite');
  main.appendChild(side);
  root.appendChild(main);
  this.ensure().then(function (set) {
    if (!root.isConnected) return;
    if (self.o.filters && self.options && !self._filled) { self._filled = true; self.fillFilters(); }
    var bins = self.bins(set);
    self.drawTiles(tiles, bins);
    clear(board);
    if (set.capped) {
      var n = el('div', 'cal-capped');
      n.appendChild(ic('info', 15));
      n.appendChild(el('span', '', 'Only the first 5000 certificates of this window are shown - narrow it with the filters.'));
      board.appendChild(n);
    }
    board.appendChild(self.view === 'year' ? self.year(bins) : self.monthGrid(bins));
    board.appendChild(self.legend());
    self.drawSide(side, bins, set);
  }).catch(function (e) {
    if (!root.isConnected) return;
    clear(board);
    var w = el('div', 'cal-empty bad');
    w.appendChild(ic('info', 22));
    w.appendChild(data('span', '', (e && e.message) || String(e)));
    board.appendChild(w);
  });
};

/* ---- the bar: the views, where we are, the filters, the file and the subscription --------- */
Cal.prototype.bar = function () {
  var self = this;
  var bar = el('div', 'cal-bar');
  var seg = el('div', 'cal-seg');
  seg.setAttribute('role', 'tablist');
  seg.setAttribute('aria-label', 'The calendar shows');
  [['month', 'Month', 'cal'], ['year', 'Year', 'cal_grid']].forEach(function (v) {
    var b = el('button', 'cal-segb' + (self.view === v[0] ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('role', 'tab');
    b.setAttribute('aria-selected', self.view === v[0] ? 'true' : 'false');
    b.appendChild(ic(v[2], 15));
    b.appendChild(el('span', '', v[1]));
    b.onclick = function () {
      if (self.view === v[0]) return;
      self.view = v[0];
      store(VIEW_KEY, v[0]);
      self.pick = null;
      self.draw();
    };
    seg.appendChild(b);
  });
  bar.appendChild(seg);
  if (this.view === 'month') {
    var nav = el('div', 'cal-nav');
    var prev = iconButton('prev', 'The month before');
    prev.setAttribute('aria-label', tr('The month before'));
    prev.onclick = function () { self.shift(-1); };
    var next = iconButton('next', 'The month after');
    next.setAttribute('aria-label', tr('The month after'));
    next.onclick = function () { self.shift(1); };
    var now = el('button', 'btn small cal-today', 'Today');
    now.type = 'button';
    now.onclick = function () { var t = today(); self.month = new Date(t.getFullYear(), t.getMonth(), 1); self.focus = keyOf(t); self.pick = null; self.draw(); };
    var title = data('h3', 'cal-title', monthTitle(this.month));
    title.setAttribute('aria-live', 'polite');
    nav.appendChild(prev);
    nav.appendChild(title);
    nav.appendChild(next);
    nav.appendChild(now);
    bar.appendChild(nav);
  } else {
    var a = monday(today());
    bar.appendChild(data('h3', 'cal-title', shortDay(a) + ' – ' + fmt(addDays(a, 53 * 7 - 1), {day: 'numeric', month: 'short', year: 'numeric'})));
  }
  var right = el('div', 'cal-acts');
  if (this.o.ics) {
    var dl = cmdButton('Download .ics', 'download', 'small');
    dl.title = tr('The certificates of this calendar as a file for Outlook, Google Calendar or Thunderbird.');
    dl.onclick = function () { self.download(dl); };
    right.appendChild(dl);
  }
  if (this.o.subscribe) {
    var sub = cmdButton('Subscribe…', 'bell', 'small');
    sub.title = tr('A private link your calendar program asks by itself, so the dates stay current.');
    sub.onclick = function () { self.subscribe(); };
    right.appendChild(sub);
  }
  bar.appendChild(right);
  if (this.o.filters) {
    var fl = el('div', 'cal-filters');
    fl.setAttribute('role', 'group');
    fl.setAttribute('aria-label', tr('Only the certificates of'));
    this.fl = {};
    [['team', 'every team', 'people'], ['issuer', 'every source', 'download'], ['target', 'every target', 'net']].forEach(function (x) {
      var w = el('label', 'cal-fsel');
      w.appendChild(ic(x[2], 14));
      var s = el('select', '');
      s.setAttribute('aria-label', tr({team: 'Team', issuer: 'Source', target: 'Target'}[x[0]]));
      var o0 = el('option', '', x[1]);
      o0.value = '';
      s.appendChild(o0);
      if (self.f[x[0]]) { var oc = data('option', '', self.f[x[0]]); oc.value = self.f[x[0]]; s.appendChild(oc); s.value = self.f[x[0]]; }
      s.onchange = function () { self.f[x[0]] = s.value; self.refilter(); };
      w.appendChild(s);
      fl.appendChild(w);
      self.fl[x[0]] = s;
    });
    var mine = el('button', 'cal-chip' + (this.f.mine ? ' on' : ''));
    mine.type = 'button';
    mine.setAttribute('aria-pressed', this.f.mine ? 'true' : 'false');
    mine.appendChild(ic('person', 14));
    mine.appendChild(el('span', '', 'Only mine'));
    mine.title = tr('Only the certificates you own or added yourself.');
    mine.onclick = function () { self.f.mine = !self.f.mine; self.refilter(); };
    fl.appendChild(mine);
    bar.appendChild(fl);
    this._filled = false;
  }
  return bar;
};
Cal.prototype.fillFilters = function () {
  var self = this, o = this.options || {};
  ['team', 'issuer', 'target'].forEach(function (k) {
    var s = self.fl && self.fl[k];
    if (!s) return;
    var have = {};
    Array.prototype.forEach.call(s.options, function (x) { have[x.value] = 1; });
    (o[{team: 'teams', issuer: 'issuers', target: 'targets'}[k]] || []).forEach(function (v) {
      if (have[v]) return;
      var x = data('option', '', v);
      x.value = v;
      s.appendChild(x);
    });
    s.value = self.f[k] || '';
    s.parentNode.hidden = s.options.length < 2;
  });
};
Cal.prototype.shift = function (n) {
  this.month = new Date(this.month.getFullYear(), this.month.getMonth() + n, 1);
  var f = dayOf(this.focus);
  var dim = new Date(this.month.getFullYear(), this.month.getMonth() + 1, 0).getDate();
  this.focus = keyOf(new Date(this.month.getFullYear(), this.month.getMonth(), Math.min(f.getDate(), dim)));
  this.pick = null;
  this.draw();
};

/* ---- the tiles: what runs out soon ------------------------------------------------------- */
Cal.prototype.drawTiles = function (host, bins) {
  var self = this;
  clear(host);
  var t = today(), n7 = 0, n30 = 0, n60 = 0, ren = 0, gone = 0;
  Object.keys(bins).forEach(function (k) {
    var d = diffDays(dayOf(k)), e = bins[k].ends.length;
    if (d < 0) gone += e;
    else if (d < 8) n7 += e;
    if (d >= 0 && d <= 30) n30 += e;
    if (d >= 0 && d <= 60) n60 += e;
    if (d >= 0 && d <= 30) ren += bins[k].renews.length;
  });
  var tile = function (cls, n, words, icon, go) {
    var b = el('button', 'cal-tile ' + cls + (n ? '' : ' zero'));
    b.type = 'button';
    var i = ic(icon, 17);
    b.appendChild(i);
    b.appendChild(data('b', '', num(n)));
    b.appendChild(el('span', '', words));
    b.onclick = go;
    host.appendChild(b);
  };
  var goRange = function (from, to, title) {
    return function () { self.select({kind: 'range', from: keyOf(from), to: keyOf(to), title: title}); };
  };
  tile('crit', n7, 'run out within 7 days', 'clock', goRange(t, addDays(t, 7), 'Within 7 days'));
  tile('warn', n30, 'run out within 30 days', 'cal', goRange(t, addDays(t, 30), 'Within 30 days'));
  tile('info', n60, 'run out within 60 days', 'cal', goRange(t, addDays(t, 60), 'Within 60 days'));
  tile('ok', ren, 'renewals planned in 30 days', 'refresh', function () { self.select({kind: 'range', from: keyOf(t), to: keyOf(addDays(t, 30)), title: 'Renewals planned in 30 days', renews: true}); });
  if (gone) tile('gone', gone, 'have run out', 'info', goRange(addDays(t, -400), addDays(t, -1), 'Have run out'));
};

/* ---- a month ------------------------------------------------------------------------------- */
Cal.prototype.monthGrid = function (bins) {
  var self = this;
  var wrap = el('div', 'cal-month');
  var grid = el('div', 'cal-grid');
  grid.setAttribute('role', 'grid');
  grid.setAttribute('aria-label', monthTitle(this.month));
  var head = el('div', 'cal-wd');
  head.setAttribute('role', 'row');
  var m0 = monday(today());
  for (var i = 0; i < 7; i++) {
    var wd = data('div', 'cal-wdn', fmt(addDays(m0, i), {weekday: 'short'}));
    wd.setAttribute('role', 'columnheader');
    head.appendChild(wd);
  }
  grid.appendChild(head);
  var start = monday(this.month), t = keyOf(today()), row = null;
  for (var c = 0; c < 42; c++) {
    if (c % 7 === 0) { row = el('div', 'cal-row'); row.setAttribute('role', 'row'); grid.appendChild(row); }
    var d = addDays(start, c), k = keyOf(d), b = bins[k] || {ends: [], renews: []};
    var out = d.getMonth() !== this.month.getMonth();
    var cell = el('button', 'cal-day' + (out ? ' out' : '') + (k === t ? ' today' : '') + (b.ends.length ? ' has ' + tone(d) : '')
                  + (self.pick && self.pick.kind === 'day' && self.pick.key === k ? ' on' : ''));
    cell.type = 'button';
    cell.setAttribute('role', 'gridcell');
    cell.dataset.day = k;
    cell.tabIndex = k === this.focus ? 0 : -1;
    var lab = longDay(d) + (b.ends.length ? ' · ' + pat('{0} run out', b.ends.length) : '') + (b.renews.length ? ' · ' + pat('{0} renewed by acme', b.renews.length) : '');
    cell.setAttribute('aria-label', lab);
    noI18n(cell);
    cell.appendChild(data('span', 'cal-dn', String(d.getDate())));
    var marks = el('span', 'cal-marks');
    if (b.ends.length) {
      var e = data('span', 'cal-n ' + tone(d), String(b.ends.length));
      marks.appendChild(e);
    }
    if (b.renews.length) {
      var r = el('span', 'cal-r');
      r.innerHTML = iconMarkup('refresh', 11);
      r.appendChild(data('span', '', String(b.renews.length)));
      marks.appendChild(r);
    }
    cell.appendChild(marks);
    /* the first names, where there is room */
    if (b.ends.length) {
      var names = el('span', 'cal-names');
      b.ends.slice(0, 2).forEach(function (x) { names.appendChild(data('span', 'cal-nm', x.name)); });
      if (b.ends.length > 2) names.appendChild(data('span', 'cal-more', '+' + (b.ends.length - 2)));
      cell.appendChild(names);
    }
    (function (key) {
      cell.onclick = function () { self.focus = key; self.select({kind: 'day', key: key}); };
    }(k));
    row.appendChild(cell);
  }
  grid.addEventListener('keydown', function (ev) { self.keys(ev, grid); });
  wrap.appendChild(grid);
  return wrap;
};
Cal.prototype.keys = function (ev, grid) {
  var steps = {ArrowLeft: -1, ArrowRight: 1, ArrowUp: -7, ArrowDown: 7};
  if (this.view === 'year') steps = {ArrowLeft: -7, ArrowRight: 7, ArrowUp: -1, ArrowDown: 1};
  var k = ev.key, cur = dayOf(this.focus), next = null;
  if (steps[k] !== undefined) next = addDays(cur, steps[k]);
  else if (k === 'Home') next = this.view === 'year' ? addDays(cur, -((cur.getDay() + 6) % 7)) : addDays(cur, -((cur.getDay() + 6) % 7));
  else if (k === 'End') next = addDays(cur, 6 - ((cur.getDay() + 6) % 7));
  else if (k === 'PageUp' || k === 'PageDown') {
    if (this.view === 'month') { ev.preventDefault(); this.shift(k === 'PageUp' ? -1 : 1); this.refocus(); return; }
    next = addDays(cur, k === 'PageUp' ? -28 : 28);
  } else return;
  ev.preventDefault();
  var w = this.window();
  if (this.view === 'month' && (next < w[0] || next > w[1] || next.getMonth() !== this.month.getMonth())) {
    this.focus = keyOf(next);
    this.month = new Date(next.getFullYear(), next.getMonth(), 1);
    this.pick = null;
    this.draw();
    this.refocus();
    return;
  }
  if (next < w[0] || next > w[1]) return;
  this.focus = keyOf(next);
  var cells = grid.querySelectorAll('[data-day]');
  var self = this;
  Array.prototype.forEach.call(cells, function (c) { c.tabIndex = c.dataset.day === self.focus ? 0 : -1; if (c.dataset.day === self.focus) c.focus(); });
};
Cal.prototype.refocus = function () {
  var self = this, n = 0;
  var tick = function () {
    var c = self.host.querySelector('[data-day="' + self.focus + '"]');
    if (c) { c.focus(); return; }
    if (++n < 30) setTimeout(tick, 60);
  };
  tick();
};
Cal.prototype.select = function (p) {
  this.pick = p || null;
  var self = this;
  Array.prototype.forEach.call(this.host.querySelectorAll('[data-day], [data-week]'), function (c) {
    c.classList.toggle('on', !!p && ((p.kind === 'day' && c.dataset.day === p.key) || (p.kind === 'week' && c.dataset.week === p.key)));
    if (c.dataset.day) c.tabIndex = c.dataset.day === self.focus ? 0 : -1;
  });
  this.redrawSide(true);
};

/* ---- a year: a square a day, a column a week ------------------------------------------------ */
Cal.prototype.year = function (bins) {
  var self = this;
  var wrap = el('div', 'cal-year');
  var scroll = el('div', 'cal-hm-scroll');
  var hm = el('div', 'cal-hm');
  hm.setAttribute('role', 'grid');
  hm.setAttribute('aria-label', tr('A year of certificates running out'));
  var a = monday(today()), t = keyOf(today());
  /* the weekdays down the left */
  var lefts = el('div', 'cal-hm-wd');
  lefts.setAttribute('aria-hidden', 'true');
  lefts.appendChild(el('span', 'cal-hm-mh', ''));
  for (var i = 0; i < 7; i++) lefts.appendChild(data('span', '', i % 2 === 0 ? fmt(addDays(a, i), {weekday: 'short'}) : ''));
  lefts.appendChild(el('span', 'cal-hm-wk', ''));
  hm.appendChild(lefts);
  var lastMonth = -1;
  for (var w = 0; w < 53; w++) {
    var col = el('div', 'cal-hm-col');
    col.setAttribute('role', 'row');
    var mon = addDays(a, w * 7);
    var mh = data('span', 'cal-hm-mh', '');
    /* the month's name over its first week */
    for (var j = 0; j < 7; j++) {
      var dj = addDays(mon, j);
      if (dj.getDate() === 1 || (w === 0 && j === 0)) {
        if (dj.getMonth() !== lastMonth) { mh.textContent = fmt(dj, {month: 'short'}); lastMonth = dj.getMonth(); }
        break;
      }
    }
    col.appendChild(mh);
    var wk = 0;
    for (var dd = 0; dd < 7; dd++) {
      var d = addDays(mon, dd), k = keyOf(d), b = bins[k] || {ends: [], renews: []};
      wk += b.ends.length;
      var sq = el('button', 'cal-sq l' + level(b.ends.length) + ' ' + tone(d) + (k === t ? ' today' : '') + (b.renews.length && !b.ends.length ? ' ren' : '')
                  + (self.pick && self.pick.kind === 'day' && self.pick.key === k ? ' on' : ''));
      sq.type = 'button';
      sq.setAttribute('role', 'gridcell');
      sq.dataset.day = k;
      sq.tabIndex = k === this.focus ? 0 : -1;
      var lab = longDay(d) + ': ' + (b.ends.length ? pat('{0} run out', b.ends.length) : tr('nothing runs out')) + (b.renews.length ? ' · ' + pat('{0} renewed by acme', b.renews.length) : '');
      sq.setAttribute('aria-label', lab);
      sq.title = lab;
      noI18n(sq);
      (function (key) { sq.onclick = function () { self.focus = key; self.select({kind: 'day', key: key}); }; }(k));
      col.appendChild(sq);
    }
    /* the week's count under it: a click lists the week */
    var wb = el('button', 'cal-wk l' + level(Math.ceil(wk / 2)) + (wk ? ' has' : '') + (self.pick && self.pick.kind === 'week' && self.pick.key === keyOf(mon) ? ' on' : ''));
    wb.type = 'button';
    wb.dataset.week = keyOf(mon);
    wb.tabIndex = -1;
    var wl = pat('The week of {0}: {1} run out', shortDay(mon), wk);
    wb.setAttribute('aria-label', wl);
    wb.title = wl;
    noI18n(wb);
    wb.appendChild(data('span', '', wk ? String(wk) : ''));
    (function (key) { wb.onclick = function () { self.select({kind: 'week', key: key}); }; }(keyOf(mon)));
    col.appendChild(wb);
    hm.appendChild(col);
  }
  hm.addEventListener('keydown', function (ev) { self.keys(ev, hm); });
  scroll.appendChild(hm);
  wrap.appendChild(scroll);
  /* this month in view on a phone: the squares scroll within their own box */
  setTimeout(function () { try { var on = hm.querySelector('.today'); if (on && scroll.scrollWidth > scroll.clientWidth) scroll.scrollLeft = Math.max(0, on.offsetLeft - 40); } catch (e) { } }, 0);
  return wrap;
};
Cal.prototype.legend = function () {
  var lg = el('div', 'cal-legend');
  var a = el('span', 'cal-lg');
  a.appendChild(el('span', 'cal-lgw', 'few'));
  for (var i = 0; i <= 4; i++) a.appendChild(el('span', 'cal-sq mini warn l' + i));
  a.appendChild(el('span', 'cal-lgw', 'many'));
  lg.appendChild(a);
  [['crit', 'within 7 days or run out'], ['warn', 'within 30 days'], ['info', 'within 60 days'], ['ok', 'later']].forEach(function (x) {
    var s = el('span', 'cal-lg');
    s.appendChild(el('span', 'cal-dot ' + x[0]));
    s.appendChild(el('span', '', x[1]));
    lg.appendChild(s);
  });
  var r = el('span', 'cal-lg');
  var ri = el('span', 'cal-r');
  ri.innerHTML = iconMarkup('refresh', 11);
  r.appendChild(ri);
  r.appendChild(el('span', '', 'a renewal acme plans'));
  lg.appendChild(r);
  return lg;
};

/* ---- the list of a day, a week or a range ------------------------------------------------------ */
Cal.prototype.redrawSide = function (scroll) {
  var self = this, side = this.host.querySelector('.cal-side');
  if (!side) return;
  this.ensure().then(function (set) {
    self.drawSide(side, self.bins(set), set);
    if (scroll && window.matchMedia && window.matchMedia('(max-width: 900px)').matches) {
      try { side.scrollIntoView({block: 'nearest', behavior: 'smooth'}); } catch (e) { }
    }
  });
};
Cal.prototype.drawSide = function (side, bins, set) {
  var self = this;
  clear(side);
  var p = this.pick;
  var head = el('div', 'cal-sh');
  var ends = [], renews = [], title;
  if (!p) {
    /* nothing chosen: the next ones to run out */
    var t = keyOf(today());
    var all = (set.certs || []).filter(function (e) { return e.not_after && keyOf(new Date(e.not_after * 1000)) >= t; })
      .sort(function (a, b) { return a.not_after - b.not_after; });
    ends = all.slice(0, 8);
    title = el('span', '', 'Next to run out');
  } else if (p.kind === 'day') {
    var b = bins[p.key] || {ends: [], renews: []};
    ends = b.ends;
    renews = b.renews;
    title = data('span', '', longDay(dayOf(p.key)));
  } else {
    var from = p.kind === 'week' ? p.key : p.from, to = p.kind === 'week' ? keyOf(addDays(dayOf(p.key), 6)) : p.to;
    Object.keys(bins).sort().forEach(function (k) {
      if (k < from || k > to) return;
      if (!p.renews) ends = ends.concat(bins[k].ends);
      renews = renews.concat(bins[k].renews);
    });
    if (p.kind === 'week') title = data('span', '', pat('The week of {0}', shortDay(dayOf(p.key))));
    else title = el('span', '', p.title);
    if (!p.renews && p.kind === 'range') renews = [];
  }
  head.appendChild(ic(p ? 'cal' : 'clock', 17));
  head.appendChild(title);
  if (p) {
    var x = iconButton('close', 'Back to the next ones');
    x.setAttribute('aria-label', tr('Back to the next ones'));
    x.onclick = function () { self.select(null); };
    head.appendChild(x);
  }
  side.appendChild(head);
  var section = function (words, list, kind) {
    if (!list.length) return;
    var h = el('div', 'cal-sg');
    h.appendChild(el('span', '', words));
    h.appendChild(data('span', 'cal-sgn', String(list.length)));
    side.appendChild(h);
    var ul = el('div', 'cal-list');
    ul.setAttribute('role', 'list');
    list.slice(0, 200).forEach(function (e) { ul.appendChild(self.row(e, kind)); });
    side.appendChild(ul);
    if (list.length > 200) side.appendChild(el('p', 'muted small', 'Only the first 200 are listed.'));
  };
  section(p ? 'Run out' : 'The certificates that run out first', ends, 'end');
  section('Renewed by acme', renews, 'renew');
  if (!ends.length && !renews.length) {
    var em = el('div', 'cal-empty');
    em.appendChild(ic('check', 22));
    em.appendChild(el('b', '', p ? 'Nothing runs out then' : 'Nothing runs out in this calendar'));
    em.appendChild(el('span', 'muted small', p ? 'Choose another day or week.' : 'Every certificate here is valid for longer than the calendar shows.'));
    side.appendChild(em);
  }
};
Cal.prototype.row = function (e, kind) {
  var self = this;
  var r = el('button', 'cal-item ' + (kind === 'renew' ? 'ren' : e.urgency || 'ok'));
  r.type = 'button';
  r.setAttribute('role', 'listitem');
  var tile = el('span', 'cal-itic');
  tile.innerHTML = iconMarkup(kind === 'renew' ? 'refresh' : 'lock', 16);
  r.appendChild(tile);
  var w = el('span', 'cal-itw');
  var t = el('span', 'cal-itt');
  t.appendChild(data('b', '', e.name));
  w.appendChild(t);
  var s = el('span', 'cal-its');
  var names = (e.names || []).slice(0, 2).join(', ') + (e.n_names > 2 ? ' +' + (e.n_names - 2) : '');
  if (names && names !== e.name) s.appendChild(data('span', 'mono', names));
  if (e.owner) { var o = data('span', 'cal-own', e.owner); s.appendChild(o); }
  w.appendChild(s);
  r.appendChild(w);
  var when = el('span', 'cal-when');
  if (kind === 'renew') {
    when.appendChild(data('b', '', shortDay(new Date(e.renew_at * 1000))));
    when.appendChild(el('span', '', 'renewed by acme'));
  } else {
    var dl = e.not_after ? Math.round((new Date(e.not_after * 1000) - new Date()) / DAY) : null;
    when.appendChild(data('b', '', shortDay(new Date(e.not_after * 1000))));
    when.appendChild(el('span', '', dl === null ? '' : dl < 0 ? pat('{0} days ago', -dl) : dl === 0 ? tr('today') : pat('in {0} days', dl)));
  }
  r.appendChild(when);
  r.setAttribute('aria-label', e.name + ' · ' + (kind === 'renew' ? tr('renewed by acme') : tr('runs out')) + ' ' + shortDay(new Date((kind === 'renew' ? e.renew_at : e.not_after) * 1000)));
  noI18n(r);
  r.onclick = function () { self.o.open(e); };
  return r;
};

/* ---- the file and the subscription ----------------------------------------------------------- */
Cal.prototype.download = function (b) {
  var self = this;
  busy(b, true);
  this.o.ics(this.f).then(function (d) {
    busy(b, false);
    var blob = new Blob([d.text], {type: 'text/calendar;charset=utf-8'});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = d.filename || 'acme-certificates.ics';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
    toast(pat('{0} certificate(s) in the file', d.count || 0), 'good');
  }).catch(function (e) { busy(b, false); oops(e); });
  return self;
};
Cal.prototype.subscribe = function () {
  var self = this;
  var feed = this.feed || {};
  var made = null;
  var draw = function () {
    modal('Subscribe to the calendar', function (body) {
      body.classList.add('cal-subdlg');
      var hero = el('div', 'cal-subhero');
      hero.appendChild(ic('cal', 26));
      var hw = el('div', '');
      hw.appendChild(el('b', '', 'Your certificates in your own calendar'));
      hw.appendChild(el('p', 'muted small', 'Outlook, Google Calendar, Apple Calendar or Thunderbird asks this link by itself every few hours: each certificate on the day it runs out, a reminder a week before, and the renewals acme plans. It shows what your account may see - never more - and stops working when your account may no longer sign in.'));
      hero.appendChild(hw);
      body.appendChild(hero);
      if (made) {
        var url = location.origin + made.path;
        var box = el('div', 'cal-link');
        var inp = noI18n(el('input', 'mono'));
        inp.type = 'text';
        inp.readOnly = true;
        inp.value = url;
        inp.setAttribute('aria-label', tr('The link to subscribe to'));
        inp.onfocus = function () { inp.select(); };
        box.appendChild(inp);
        var cp = cmdButton('Copy', 'copy', 'small primary');
        cp.onclick = function () { copyText(url, cp, 'Copied'); };
        box.appendChild(cp);
        body.appendChild(box);
        var n = el('div', 'cal-note warn');
        n.appendChild(ic('shield', 16));
        n.appendChild(el('span', '', 'Keep the link to yourself: whoever has it sees the names and dates of your certificates. It is shown only now - a new link replaces it.'));
        body.appendChild(n);
      } else if (feed.on) {
        var st = el('div', 'cal-note');
        st.appendChild(ic('check', 16));
        st.appendChild(data('span', '', pat('You have a link, made {0}.', stamp(feed.made)) + (feed.used ? ' ' + pat('Last asked {0}.', stamp(feed.used)) : '')));
        body.appendChild(st);
      } else {
        var st2 = el('div', 'cal-note');
        st2.appendChild(ic('info', 16));
        st2.appendChild(el('span', '', 'You have no link yet.'));
        body.appendChild(st2);
      }
    }, (function () {
      var bs = [{words: 'Close', close: true}];
      if (feed.on || made) bs.push({words: 'Take it back', icon: 'ban', cls: 'danger', go: function () {
        api('calendar/feed_link', {action: 'revoke'}).then(function () {
          toast('The link no longer works', 'good');
          feed = self.feed = {on: false, may: true};
          made = null;
          draw();
        }).catch(oops);
      }});
      if (feed.may !== false) bs.push({words: feed.on || made ? 'Make a new link' : 'Make a link', icon: 'add', cls: 'primary', go: function (b) {
        busy(b, true);
        api('calendar/feed_link', {action: 'new', lang: lang(), tz: tzName()}).then(function (d) {
          made = d;
          feed = self.feed = {on: true, made: Date.now() / 1000, may: true};
          draw();
        }).catch(function (e) { busy(b, false); oops(e); });
      }});
      return bs;
    }()));
  };
  draw();
};

/* ---- the administration: Certificates → List | Calendar ---------------------------------------- */
function capi(path) { return window.ACME_CERTS && ACME_CERTS.api ? ACME_CERTS.api(path) : api(path); }
function qs(o) {
  var out = [];
  Object.keys(o).forEach(function (k) { if (o[k] !== '' && o[k] !== false && o[k] !== null && o[k] !== undefined) out.push(k + '=' + encodeURIComponent(o[k] === true ? '1' : o[k])); });
  return out.length ? '?' + out.join('&') : '';
}
var ADMIN = null;
function adminCard() {
  var tab = document.getElementById('tab-certs');
  return tab ? tab.querySelector('.card') : null;
}
function mountAdmin() {
  var card = adminCard();
  if (!card || card.querySelector('.cal-switch')) return;
  var filters = card.querySelector('.ct-filters');
  var sw = el('div', 'cal-switch');
  sw.setAttribute('role', 'tablist');
  sw.setAttribute('aria-label', tr('Certificates as'));
  var host = el('div', 'cal-host');
  host.id = 'cal-host';
  host.hidden = true;
  var btns = {};
  [['list', 'List', 'list'], ['cal', 'Calendar', 'cal']].forEach(function (v) {
    var b = el('button', 'cal-segb');
    b.type = 'button';
    b.id = 'cal-view-' + v[0];
    b.setAttribute('role', 'tab');
    b.appendChild(ic(v[2], 15));
    b.appendChild(el('span', '', v[1]));
    b.onclick = function () { CAL.show(v[0] === 'cal'); };
    btns[v[0]] = b;
    sw.appendChild(b);
  });
  if (filters) filters.parentNode.insertBefore(sw, filters); else card.appendChild(sw);
  var pager = card.querySelector('#ct-pager');
  if (pager && pager.parentNode) pager.parentNode.insertBefore(host, pager.nextSibling); else card.appendChild(host);
  ADMIN = {card: card, host: host, btns: btns, cal: null};
  CAL.show(store(MODE_KEY) === 'cal', true);
}
CAL.show = function (on, quiet) {
  if (!ADMIN) mountAdmin();
  if (!ADMIN) return;
  ADMIN.card.classList.toggle('cal-on', !!on);
  ADMIN.host.hidden = !on;
  ['list', 'cal'].forEach(function (k) {
    var b = ADMIN.btns[k], sel = (k === 'cal') === !!on;
    b.classList.toggle('on', sel);
    b.setAttribute('aria-selected', sel ? 'true' : 'false');
  });
  if (!quiet) store(MODE_KEY, on ? 'cal' : 'list');
  if (on) {
    if (!ADMIN.cal) {
      ADMIN.cal = new Cal(ADMIN.host, {
        filters: true, subscribe: true,
        load: function (from, to, f) { return capi('calendar' + qs({from: from, to: to, team: f.team, issuer: f.issuer, target: f.target, mine: f.mine})); },
        ics: function (f) { return capi('calendar/ics' + qs({team: f.team, issuer: f.issuer, target: f.target, mine: f.mine, lang: lang(), tz: tzName()})); },
        open: function (e) { if (window.ACME_CERTS && ACME_CERTS.certPeek) ACME_CERTS.certPeek(e.id); }
      });
    } else if (Date.now() - (ADMIN.at || 0) > 60000) {
      ADMIN.cal.cache = [];
      ADMIN.cal.draw();
    }
    ADMIN.at = Date.now();
  }
};
/* opened from elsewhere (Ctrl+K): the Certificates tab, as a calendar */
CAL.open = function () {
  if (typeof showTab === 'function') showTab('certs');
  setTimeout(function () { CAL.show(true); var c = document.getElementById('cal-host'); if (c) { try { c.scrollIntoView({block: 'start'}); } catch (e) { } } }, 60);
};

/* ---- the portal: "Calendar" beside Your certificates ------------------------------------------------ */
CAL.portalButtonEl = function (cls) {
  var b = cmdButton('Calendar', 'cal', (cls || '') + ' cal-pbtn');
  b.title = tr('When your certificates run out, as a calendar.');
  b.onclick = function () { CAL.portal(); };
  return b;
};
CAL.portalButton = function (where) {
  if (!where || where.querySelector('.cal-pbtn')) return;
  where.insertBefore(CAL.portalButtonEl('small'), where.firstChild);
};
CAL.portal = function () {
  var rows = {};
  modal('When your certificates run out', function (body) {
    body.classList.add('cal-dlg');
    var host = el('div', 'cal-host');
    body.appendChild(host);
    new Cal(host, {
      compact: true,
      load: function () {
        return api('calendar').then(function (d) { (d.rows || []).forEach(function (r) { rows[r.id] = r; }); return d; });
      },
      ics: function () { return api('calendar-ics&lang=' + encodeURIComponent(lang()) + '&tz=' + encodeURIComponent(tzName())); },
      open: function (e) {
        var r = rows[e.id];
        if (r && window.ACME_PORTAL_CERTS && ACME_PORTAL_CERTS.openRow) ACME_PORTAL_CERTS.openRow(r);
      }
    });
  }, [{words: 'Close', close: true}], 'large');
};

CAL.Cal = Cal;
if (document.getElementById('tab-certs')) {
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountAdmin);
  else mountAdmin();
}
}());
