/* ctxmenu.js - the right button over the whole application (1.0.138): a menu of what can be
   done with the thing under the pointer - a row of any table, a team in the tree, an agent's
   tile - and with several rows picked at once; the acme clipboard (an object as JSON, never a
   secret, carried between tabs); "Copy as a CLI command" and "as an API call".

   Who decides what (docs/context-menu.md):
   - Normal mode: the right button on a row opens this menu. While "Edit the columns" is on
     (cols.js, COLS_EDIT), a table keeps the column menu it has always had - nothing here runs
     inside a table then.
   - Shift + the right button is always the browser's own menu; so is the right button in a box
     to type in (input, textarea, select, anything contenteditable), on a link, and over text
     somebody has selected.
   - The keyboard: the Menu key or Shift+F10 on a focused row; on a phone, a long press.
   - What a row is, and what can be done with it, is registered per kind of object
     (ctxmenu-registry.js: ACME_CTX.type and ACME_CTX.scope); a table nobody registered still
     gets the menu every row has: copy the cell, copy the row (text, CSV, JSON), filter by the
     value or leave it out, and the row's own buttons.
   - Every action runs the code the page runs for it (the row's own button pressed, or the
     function of the page that button calls): the same checks, the same questions.

   Nothing here changes anything until it is used: no request is made, nothing is drawn. */
(function () {
'use strict';
if (window.ACME_CTX && window.ACME_CTX._ready) return;
var CX = window.ACME_CTX = window.ACME_CTX || {};
CX._ready = true;

var TYPES = {};          /* name -> {label, icon, ...} - see CX.type */
var SCOPES = [];         /* where rows of a kind are: {sel, row, type, read, ...} */
var MAC = /Mac|iPhone|iPad/.test(navigator.platform || '');
var MOD = MAC ? '⌘' : 'Ctrl';

function me() {
  if (typeof ME === 'object' && ME) return ME;
  if (typeof PORTAL_ME === 'object' && PORTAL_ME) return PORTAL_ME;
  return null;
}
function role() { var m = me(); return (m && m.role) || 'readonly'; }
function isFull() { return role() === 'fulladmin'; }
function isManage() { var r = role(); return r === 'fulladmin' || r === 'certadmin' || r === 'tokenadmin'; }
function portal() { return !/\/admin\//.test(location.pathname); }
function tr(s) {
  try { var t = typeof i18nText === 'function' ? i18nText(String(s)) : null; return t || String(s); } catch (e) { return String(s); }
}
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function arr(v) { return Array.isArray(v) ? v : (v === undefined || v === null || v === '' ? [] : [v]); }
function icon(key, size) {
  var s = el('span', 'cxm-ic');
  s.innerHTML = iconMarkup(key, size || 15);
  return s;
}
/** What a cell says, as it is shown: the words of its pieces with a space between them (a
    cell of chips said "a.example.testb.example.test"), never its buttons. */
function textOf(node) {
  if (!node) return '';
  var out = [];
  var walk = function (n) {
    if (n.nodeType === 3) { out.push(n.nodeValue); return; }
    if (n.nodeType !== 1) return;
    if (n.matches && n.matches('button, .rowtools, .col-grip, .t-sort, script, style, svg, input, select, [aria-hidden="true"]')) return;
    if (n.tagName === 'BR') { out.push(' '); return; }
    out.push(' ');
    Array.prototype.forEach.call(n.childNodes, walk);
    out.push(' ');
  };
  walk(node);
  return out.join('').replace(/\s+/g, ' ').trim();
}

/* ==========================================================================
   Registration
   ========================================================================== */
/** A kind of object. def: {label, plural, icon, key(o), name(o), idents(o) -> [[label, value]],
    load(o) -> Promise of the whole object, open(o, ctx), actions(o, ctx) -> items,
    bulk(list, ctx) -> items, clone(o, ctx), paste: {TYPE: fn(clip, objs, ctx)},
    pasteNew(clip, ctx), copyData(o) -> Promise of what goes on the acme clipboard,
    cli(o) -> Promise of text, curl(o) -> Promise of {method, path, body}, events(o) -> words,
    jobs(o) -> {cert_id}, add(ctx) - "Add a new one" in an empty area}. */
CX.type = function (name, def) { def.name = name; TYPES[name] = def; return def; };
CX.types = TYPES;
/** Where rows of a kind are drawn. def: {sel: the container (a CSS selector), row: the row
    within it ('tbody > tr' by default), type, read(rowEl) -> the object (or {name}/{id}),
    filter(info) -> {box, term} | null (a search box of the page), area: true - its empty
    space offers "Paste as new" and "Add"}. */
CX.scope = function (def) { def.row = def.row || 'tbody > tr'; SCOPES.push(def); return def; };
CX.scopes = SCOPES;

/* ==========================================================================
   The menu itself
   ========================================================================== */
var OPEN = null;        /* {root, stack: [menus], opener, row, at} */
var KB_AT = 0;          /* a menu opened from the keyboard: the browser's own event after it is swallowed */
var TOUCH_AT = 0;

function close(back) {
  if (!OPEN) return;
  var o = OPEN;
  OPEN = null;
  o.stack.forEach(function (m) { if (m.node.parentNode) m.node.parentNode.removeChild(m.node); });
  if (o.veil && o.veil.parentNode) o.veil.parentNode.removeChild(o.veil);
  if (back !== false) {
    var to = o.row && o.row.isConnected && o.row.tabIndex >= 0 ? o.row : o.opener;
    if (to && to.isConnected && typeof to.focus === 'function') { try { to.focus({preventScroll: true}); } catch (e) { to.focus(); } }
  }
}
CX.close = close;
CX.isOpen = function () { return !!OPEN; };

/** An item: {label, icon, hint (a key), go(), sub (items or a function giving them), off
    (the reason it cannot be done - shown under it), danger, data (words that are a name: not
    translated), note (a small line under it), cls}. '-' a separator, {head: words} a heading. */
function itemNode(it, menu, depth) {
  if (it === '-') { var s = el('div', 'cxm-sep'); s.setAttribute('role', 'separator'); return s; }
  if (it.head !== undefined) {
    var h = el('div', 'cxm-h');
    h.appendChild(el('span', '', it.head));
    if (it.count !== undefined) h.appendChild(data('span', 'cxm-h-n', String(it.count)));
    return h;
  }
  var b = el('div', 'cxm-i' + (it.danger ? ' danger' : '') + (it.off ? ' off' : '') + (it.cls ? ' ' + it.cls : ''));
  b.setAttribute('role', 'menuitem');
  b.tabIndex = -1;
  if (it.off) b.setAttribute('aria-disabled', 'true');
  var ic = it.svg ? (function () { var x = el('span', 'cxm-ic'); x.innerHTML = it.svg; return x; }()) : icon(it.icon || 'next', 15);
  if (!it.icon && !it.svg) ic.classList.add('blank');
  b.appendChild(ic);
  var w = el('span', 'cxm-w');
  var l = el('span', 'cxm-l');
  if (Array.isArray(it.label)) {
    it.label.forEach(function (p) {
      if (p && p.data !== undefined) l.appendChild(data('span', 'cxm-d', p.data));
      else l.appendChild(el('span', '', p));
    });
  } else l.appendChild(el('span', '', it.label));
  w.appendChild(l);
  if (it.off && typeof it.off === 'string') {
    var why = el('span', 'cxm-why', it.off);
    why.id = 'cxm-why-' + (++itemNode.n);
    b.setAttribute('aria-describedby', why.id);
    w.appendChild(why);
  } else if (it.note) {
    w.appendChild(it.noteData ? data('span', 'cxm-note', it.note) : el('span', 'cxm-note', it.note));
  }
  b.appendChild(w);
  if (it.sub) {
    b.setAttribute('aria-haspopup', 'menu');
    b.setAttribute('aria-expanded', 'false');
    var ch = icon('next', 13);
    ch.className = 'cxm-more';
    b.appendChild(ch);
  } else if (it.hint) {
    var k = noI18n(el('span', 'cxm-k'));
    String(it.hint).split('+').forEach(function (part, i) {
      if (i) k.appendChild(document.createTextNode(''));
      k.appendChild(el('kbd', '', part === 'Mod' ? MOD : part));
    });
    b.appendChild(k);
  }
  b._it = it;
  b.addEventListener('click', function (e) {
    e.preventDefault();
    e.stopPropagation();
    activate(b, menu, depth, true);
  });
  b.addEventListener('mouseenter', function () {
    if (!OPEN) return;
    focusItem(menu, b);
    clearTimeout(menu.subTimer);
    /* on a phone a sub-menu takes the menu's place: opened by a tap, never by the pointer passing */
    if (it.sub && !it.off && !narrow()) menu.subTimer = setTimeout(function () { openSub(b, menu, depth); }, 160);
    else menu.subTimer = setTimeout(function () { closeDeeper(depth); }, 220);
  });
  return b;
}
itemNode.n = 0;

function activate(b, menu, depth, byPointer) {
  var it = b._it;
  if (!it || it.off) return;
  if (it.sub) { openSub(b, menu, depth, !byPointer); return; }
  close(!it.keepFocus);
  if (typeof it.go === 'function') {
    try {
      var got = it.go();
      if (got && typeof got.then === 'function') got.catch(function (e) { if (e && e.quiet) return; if (typeof oops === 'function') oops(e); });
    } catch (e) { if (typeof oops === 'function') oops(e); else throw e; }
  }
}
function items(menu) { return Array.prototype.filter.call(menu.node.querySelectorAll('.cxm-i'), function (n) { return n.offsetParent !== null; }); }
function focusItem(menu, b) {
  items(menu).forEach(function (n) { n.classList.toggle('on', n === b); });
  if (b) { b.focus({preventScroll: true}); b.scrollIntoView({block: 'nearest'}); menu.at = b; }
}
function closeDeeper(depth) {
  if (!OPEN) return;
  while (OPEN.stack.length > depth + 1) {
    var m = OPEN.stack.pop();
    if (m.node.parentNode) m.node.parentNode.removeChild(m.node);
    if (m.from) { m.from.setAttribute('aria-expanded', 'false'); m.from.classList.remove('open'); }
  }
  var top = OPEN.stack[OPEN.stack.length - 1];
  if (top && top.drill) top.node.hidden = false;
}
function narrow() { return window.innerWidth < 560; }
function openSub(b, menu, depth, focusFirst) {
  if (!OPEN) return;
  if (OPEN.stack[depth + 1] && OPEN.stack[depth + 1].from === b) { if (focusFirst) focusItem(OPEN.stack[depth + 1], items(OPEN.stack[depth + 1])[0]); return; }
  closeDeeper(depth);
  var it = b._it;
  var list = typeof it.sub === 'function' ? it.sub() : it.sub;
  var build = function (got) {
    if (!OPEN || OPEN.stack[depth] !== menu) return;
    var sub = makeMenu(got || [], depth + 1, it.label);
    sub.from = b;
    b.setAttribute('aria-expanded', 'true');
    b.classList.add('open');
    OPEN.stack.push(sub);
    if (narrow()) {
      /* a phone: the sub-menu in the place of its menu, with the way back on top */
      sub.drill = true;
      var r = menu.node.getBoundingClientRect();
      menu.node.hidden = true;
      document.body.appendChild(sub.node);
      place(sub.node, r.left, r.top, null);
    } else {
      document.body.appendChild(sub.node);
      var rb = b.getBoundingClientRect(), rm = menu.node.getBoundingClientRect();
      place(sub.node, rm.right - 4, rb.top - 6, rm.left + 4);
    }
    if (focusFirst || narrow()) focusItem(sub, items(sub)[0]);
  };
  if (list && typeof list.then === 'function') {
    b.classList.add('busy');
    list.then(function (got) { b.classList.remove('busy'); build(got); }, function (e) { b.classList.remove('busy'); build([{label: 'It could not be asked', icon: 'info', off: String((e && e.message) || e)}]); });
  } else build(list);
}
function makeMenu(list, depth, title) {
  var node = el('div', 'cxm' + (depth ? ' cxm-sub' : ''));
  node.setAttribute('role', 'menu');
  node.tabIndex = -1;
  var menu = {node: node, depth: depth};
  if (depth && narrow()) {
    var back = el('div', 'cxm-i cxm-back');
    back.setAttribute('role', 'menuitem');
    back.tabIndex = -1;
    back.appendChild(icon('prev', 15));
    var bl = el('span', 'cxm-w');
    if (Array.isArray(title)) title.forEach(function (p) { bl.appendChild(p && p.data !== undefined ? data('span', '', p.data) : el('span', '', p)); });
    else bl.appendChild(el('span', '', title || 'Back'));
    back.appendChild(bl);
    back._it = {go: function () {}, back: true};
    back.addEventListener('click', function (e) { e.stopPropagation(); goBack(depth); });
    node.appendChild(back);
  }
  var lastSep = true;
  (list || []).forEach(function (it, i) {
    if (!it) return;
    if (it === '-') { if (lastSep) return; lastSep = true; } else lastSep = false;
    if (it === '-' && !(list || []).slice(i + 1).some(function (x) { return x && x !== '-'; })) return;
    if (it.card) { node.appendChild(it.card); lastSep = false; return; }
    node.appendChild(itemNode(it, menu, depth));
  });
  if (!node.querySelector('.cxm-i:not(.cxm-back)')) node.appendChild(el('div', 'cxm-empty', 'Nothing can be done here'));
  node.addEventListener('keydown', function (e) { keys(e, menu); });
  node.addEventListener('contextmenu', function (e) { e.preventDefault(); });
  return menu;
}
function goBack(depth) {
  if (!OPEN) return;
  var parent = OPEN.stack[depth - 1];
  var from = OPEN.stack[depth] && OPEN.stack[depth].from;
  closeDeeper(depth - 1);
  if (parent) { parent.node.hidden = false; focusItem(parent, from || items(parent)[0]); }
}
function place(node, x, y, flipX) {
  node.style.left = '0px';
  node.style.top = '0px';
  var r = node.getBoundingClientRect();
  var W = window.innerWidth, H = window.innerHeight;
  var left = x;
  if (left + r.width > W - 8) left = flipX !== null && flipX !== undefined ? flipX - r.width : W - r.width - 8;
  left = Math.max(8, Math.min(left, W - r.width - 8));
  var top = Math.max(8, Math.min(y, H - r.height - 8));
  node.style.left = Math.round(left) + 'px';
  node.style.top = Math.round(top) + 'px';
}
function keys(e, menu) {
  var list = items(menu);
  var at = list.indexOf(document.activeElement);
  var k = e.key;
  if (k === 'ArrowDown' || k === 'ArrowUp') {
    e.preventDefault();
    var n = list.length;
    if (!n) return;
    var i = at < 0 ? (k === 'ArrowDown' ? 0 : n - 1) : (at + (k === 'ArrowDown' ? 1 : -1) + n) % n;
    focusItem(menu, list[i]);
  } else if (k === 'Home' || k === 'End') {
    e.preventDefault();
    focusItem(menu, list[k === 'Home' ? 0 : list.length - 1]);
  } else if (k === 'Enter' || k === ' ') {
    e.preventDefault();
    if (at >= 0) {
      if (list[at]._it && list[at]._it.back) goBack(menu.depth);
      else activate(list[at], menu, menu.depth, false);
    }
  } else if (k === 'ArrowRight') {
    if (at >= 0 && list[at]._it && list[at]._it.sub) { e.preventDefault(); openSub(list[at], menu, menu.depth, true); }
  } else if (k === 'ArrowLeft') {
    if (menu.depth > 0) { e.preventDefault(); goBack(menu.depth); }
  } else if (k === 'Escape') {
    e.preventDefault();
    e.stopPropagation();
    if (menu.depth > 0) goBack(menu.depth); else close();
  } else if (k === 'Tab') {
    e.preventDefault();
    close();
  } else if (k.length === 1 && /\S/.test(k) && !e.ctrlKey && !e.metaKey && !e.altKey) {
    /* the first letter of an item, as every menu does */
    var low = k.toLowerCase();
    for (var j = 1; j <= list.length; j++) {
      var c = list[(Math.max(at, 0) + j) % list.length];
      var t = (c.querySelector('.cxm-l') || c).textContent.trim().toLowerCase();
      if (t.charAt(0) === low) { focusItem(menu, c); break; }
    }
  }
}
/** The menu at x, y. head: a card on top (what the menu is about). */
function openMenu(list, x, y, opts) {
  close(false);
  opts = opts || {};
  var menu = makeMenu(list, 0);
  if (opts.head) menu.node.insertBefore(opts.head, menu.node.firstChild);
  if (opts.label) menu.node.setAttribute('aria-label', opts.label);
  var veil = null;
  if (opts.touch && narrow()) {
    /* a phone: the menu as a sheet from the bottom, the page dimmed behind it */
    veil = el('div', 'cxm-veil');
    veil.addEventListener('click', function () { close(); });
    document.body.appendChild(veil);
    menu.node.classList.add('cxm-sheet');
  }
  document.body.appendChild(menu.node);
  OPEN = {root: menu, stack: [menu], opener: opts.opener || document.activeElement, row: opts.row || null, veil: veil, at: Date.now()};
  if (!menu.node.classList.contains('cxm-sheet')) place(menu.node, x, y, null);
  var first = items(menu)[0];
  if (first) focusItem(menu, first); else menu.node.focus();
}
CX.openMenu = openMenu;

document.addEventListener('mousedown', function (e) {
  if (!OPEN) return;
  if (OPEN.stack.some(function (m) { return m.node.contains(e.target); })) return;
  close(false);
}, true);
document.addEventListener('scroll', function (e) {
  if (!OPEN || Date.now() - OPEN.at < 400) return;     /* the page settling as the menu came */
  if (OPEN.stack.some(function (m) { return m.node.contains(e.target); })) return;
  close(false);
}, true);
window.addEventListener('resize', function () { if (OPEN && !narrow()) close(false); });
window.addEventListener('blur', function () { close(false); });

/* ==========================================================================
   What the pointer is on
   ========================================================================== */
function typing(t) {
  return !!(t && t.closest && t.closest('input, textarea, select, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"]'));
}
function onLink(t) {
  var a = t && t.closest && t.closest('a[href]');
  return !!(a && !/^(#|javascript:)/i.test(a.getAttribute('href') || ''));
}
function textSelectedAt(t) {
  try {
    var s = window.getSelection();
    if (!s || s.isCollapsed || !String(s).trim()) return false;
    for (var i = 0; i < s.rangeCount; i++) if (s.getRangeAt(i).intersectsNode(t)) return true;
  } catch (e) { }
  return false;
}
function editingColumns() { return typeof COLS_EDIT !== 'undefined' && !!COLS_EDIT; }
/** The registered scope a row is in, and the row: {scope, row}. */
function scopeOf(t) {
  for (var i = SCOPES.length - 1; i >= 0; i--) {
    var s = SCOPES[i];
    var row = t.closest(s.row);
    if (!row) continue;
    var box = row.closest(s.sel);
    if (!box) continue;
    /* the row of this scope, not of a table inside one of its rows */
    var outer = row.parentNode && row.parentNode.closest ? row.parentNode.closest(s.row) : null;
    if (outer && box.contains(outer)) row = outer;
    return {scope: s, row: row, box: box};
  }
  return null;
}
function genericRow(t) {
  var row = t.closest('tr');
  if (!row) return null;
  var table = row.closest('table');
  if (!table || !row.parentNode || row.parentNode.tagName !== 'TBODY') return null;
  if (row.classList.contains('empty-row') || row.querySelector('td[colspan]') && row.cells.length === 1) return null;
  return row;
}
/** Everything the menu needs about where it was opened: the row, its object, the cell. */
function where(t) {
  var got = scopeOf(t);
  var row = got ? got.row : genericRow(t);
  if (!row) return null;
  var w = {row: row, scope: got && got.scope, box: got && got.box, table: row.closest('table'), target: t};
  var cell = t.closest('td, th');
  if (cell && cell.parentNode === row) w.cell = cell;
  else if (row.tagName === 'TR') w.cell = null;
  if (w.table && w.cell && w.table.tHead && w.table.tHead.rows.length === 1) {
    var head = w.table.tHead.rows[0];
    if (head.cells.length === row.cells.length) w.th = head.cells[w.cell.cellIndex];
  }
  w.type = w.scope ? TYPES[w.scope.type] : null;
  try { w.obj = w.scope && w.scope.read ? w.scope.read(row, w) : (row._rec || null); } catch (e) { w.obj = null; }
  if (w.type && !w.obj) w.type = null;
  if (!w.type && row._rec) w.obj = row._rec;
  return w;
}
CX.where = where;
/** An empty part of a registered list (its card, its heading): {scope, box}. */
function areaOf(t) {
  for (var i = SCOPES.length - 1; i >= 0; i--) {
    var s = SCOPES[i];
    if (!s.area) continue;
    var sel = s.area === true ? s.sel : s.area;
    var box = t.closest(sel);
    if (box) return {scope: s, box: box};
  }
  return null;
}

/* ==========================================================================
   The right button, the keyboard, a long press
   ========================================================================== */
document.addEventListener('contextmenu', function (e) {
  if (Date.now() - KB_AT < 600) { e.preventDefault(); return; }
  if (e.defaultPrevented || e.shiftKey) return;              /* Shift: the browser's own, always */
  var t = e.target;
  if (!t || !t.closest || t.closest('.cxm, .cxp')) return;
  if (typing(t) || onLink(t) || textSelectedAt(t)) return;
  var inTable = !!t.closest('table');
  if (editingColumns() && inTable) return;                     /* the column menu stays (cols.js) */
  var touch = Date.now() - TOUCH_AT < 900;
  var w = where(t);
  if (w) {
    e.preventDefault();
    if (touch) TOUCH.fired = true;
    rowMenu(w, e.clientX, e.clientY, {touch: touch});
    return;
  }
  var a = areaOf(t);
  if (a && !t.closest('button, .btn, .tabs')) {
    e.preventDefault();
    areaMenu(a, e.clientX, e.clientY, {touch: touch});
  }
});
document.addEventListener('keydown', function (e) {
  var menuKey = e.key === 'ContextMenu' || (e.key === 'F10' && e.shiftKey);
  if (!menuKey) return;
  var t = document.activeElement || document.body;
  if (typing(t)) return;
  if (OPEN) { e.preventDefault(); return; }
  if (editingColumns() && t.closest && t.closest('table')) return;
  var w = t.closest ? where(t) : null;
  var anchor = w ? w.row : null;
  if (!w) {
    var a = t.closest ? areaOf(t) : null;
    if (!a) return;
    e.preventDefault();
    KB_AT = Date.now();
    var ra = (t === document.body ? a.box : t).getBoundingClientRect();
    areaMenu(a, ra.left + 12, ra.top + Math.min(ra.height, 40), {opener: t});
    return;
  }
  e.preventDefault();
  KB_AT = Date.now();
  var r = anchor.getBoundingClientRect();
  var cell = w.cell ? w.cell.getBoundingClientRect() : r;
  rowMenu(w, Math.max(r.left + 16, cell.left + 8), Math.min(r.bottom - 4, window.innerHeight - 20), {opener: t});
});
/* A long press on a phone or a tablet (iOS sends no contextmenu): the menu as a sheet. */
var TOUCH = {timer: null, x: 0, y: 0, fired: false, t: null};
document.addEventListener('pointerdown', function (e) {
  if (e.pointerType !== 'touch') return;
  TOUCH_AT = Date.now();
  TOUCH.fired = false;
  clearTimeout(TOUCH.timer);
  var t = e.target;
  if (!t || !t.closest || typing(t) || onLink(t) || t.closest('.cxm, .cxp, button, .btn, .sw')) return;
  if (editingColumns() && t.closest('table')) return;
  TOUCH.x = e.clientX; TOUCH.y = e.clientY; TOUCH.t = t;
  TOUCH.timer = setTimeout(function () {
    if (TOUCH.fired) return;
    var w = where(t);
    if (!w) return;
    TOUCH.fired = true;
    rowMenu(w, TOUCH.x, TOUCH.y, {touch: true});
  }, 560);
}, true);
['pointerup', 'pointercancel'].forEach(function (ev) {
  document.addEventListener(ev, function () { clearTimeout(TOUCH.timer); }, true);
});
document.addEventListener('pointermove', function (e) {
  if (e.pointerType === 'touch' && (Math.abs(e.clientX - TOUCH.x) > 10 || Math.abs(e.clientY - TOUCH.y) > 10)) clearTimeout(TOUCH.timer);
}, true);
/* the tap that ended a long press is not also a tap on the row */
document.addEventListener('click', function (e) {
  if (TOUCH.fired && Date.now() - TOUCH_AT < 1500) { TOUCH.fired = false; e.preventDefault(); e.stopPropagation(); }
}, true);

/* ==========================================================================
   Picking several rows (M3): Ctrl/Cmd+click, Shift+click
   ========================================================================== */
var SEL = {box: null, scope: null, keys: {}, anchor: null};
function rowKey(w) {
  if (w.type && w.obj) return w.type.name + ':' + String(w.type.key(w.obj));
  return null;
}
function selRows() {
  if (!SEL.box || !SEL.box.isConnected) return [];
  var out = [];
  var rows = SEL.scope ? SEL.box.querySelectorAll(SEL.scope.row) : SEL.box.querySelectorAll('tbody > tr');
  Array.prototype.forEach.call(rows, function (r) {
    if (r.classList.contains('cxm-sel') || (r.cells && r.cells[0] && r.cells[0].querySelector('input[type=checkbox]:checked'))) out.push(r);
  });
  return out;
}
CX.selected = selRows;
function selClear() {
  Array.prototype.forEach.call(document.querySelectorAll('.cxm-sel'), function (r) { r.classList.remove('cxm-sel'); r.removeAttribute('aria-selected'); });
  SEL = {box: null, scope: null, keys: {}, anchor: null};
  dock();
}
CX.clearSelection = selClear;
function selSet(w, on) {
  var box = w.box || w.table;
  if (SEL.box && SEL.box !== box) selClear();
  SEL.box = box;
  SEL.scope = w.scope || null;
  var k = rowKey(w);
  w.row.classList.toggle('cxm-sel', on);
  if (on) w.row.setAttribute('aria-selected', 'true'); else w.row.removeAttribute('aria-selected');
  if (k) { if (on) SEL.keys[k] = 1; else delete SEL.keys[k]; }
  SEL.anchor = w.row;
  if (!selRows().length) selClear(); else dock();
}
function selToggle(w) { selSet(w, !w.row.classList.contains('cxm-sel')); }
function selRange(w) {
  var box = w.box || w.table;
  if (!SEL.anchor || SEL.box !== box || !SEL.anchor.isConnected) { selToggle(w); return; }
  var rows = Array.prototype.slice.call(SEL.scope ? box.querySelectorAll(SEL.scope.row) : box.querySelectorAll('tbody > tr'))
    .filter(function (r) { return r.offsetParent !== null; });
  var a = rows.indexOf(SEL.anchor), b = rows.indexOf(w.row);
  if (a < 0 || b < 0) { selToggle(w); return; }
  var anchor = SEL.anchor;
  rows.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(function (r) {
    var rw = where(r.cells && r.cells[0] ? r.cells[0] : r);
    if (rw) selSet(rw, true);
  });
  SEL.anchor = anchor;
}
CX.selectAll = function (w) {
  var box = w.box || w.table;
  var rows = SEL.scope || w.scope ? box.querySelectorAll((w.scope || SEL.scope).row) : box.querySelectorAll('tbody > tr');
  Array.prototype.forEach.call(rows, function (r) {
    if (r.offsetParent === null) return;
    var rw = where(r.cells && r.cells[0] ? r.cells[0] : r);
    if (rw) selSet(rw, true);
  });
};
document.addEventListener('click', function (e) {
  var mod = e.ctrlKey || e.metaKey;
  if ((!mod && !e.shiftKey) || e.button !== 0) return;
  var t = e.target;
  if (!t || !t.closest || typing(t) || onLink(t) || t.closest('button, a, label, select, .sw, .cxm, .cxp, thead')) return;
  if (editingColumns() && t.closest('table')) return;
  var w = where(t);
  if (!w || (!w.type && !(w.row.classList.contains('tappable') || w.row.tabIndex >= 0))) return;
  e.preventDefault();
  e.stopPropagation();
  try { window.getSelection().removeAllRanges(); } catch (x) { }
  if (e.shiftKey && !mod) selRange(w); else selToggle(w);
}, true);
document.addEventListener('mousedown', function (e) {
  /* Shift+click picks rows: the browser does not select text across them as well */
  if (!e.shiftKey || e.button !== 0 || !SEL.box || !e.target.closest) return;
  if (typing(e.target)) return;
  var w = genericRow(e.target) || (scopeOf(e.target) || {}).row;
  if (w && SEL.box.contains(w)) e.preventDefault();
});
document.addEventListener('keydown', function (e) {
  if (e.key !== 'Escape' || OPEN) return;
  if (typeof $ === 'function' && $('modal') && !$('modal').hidden) return;
  if (document.querySelector('.cxp-veil')) return;
  if (SEL.box) { selClear(); }
});

/* The rows a refresh drew again are picked (and filtered) as before. */
var AGAIN = 0;
var watch = new MutationObserver(function () {
  if (AGAIN || (!SEL.box && !FILTERS.length)) return;
  AGAIN = requestAnimationFrame(function () { AGAIN = 0; reapply(); });
});
watch.observe(document.documentElement, {childList: true, subtree: true});
function reapply() {
  if (SEL.box && !SEL.box.isConnected) {
    /* the list was drawn anew: the same place, the same rows */
    var keys = SEL.keys, sc = SEL.scope;
    var box = sc ? document.querySelector(sc.sel) : null;
    if (box && Object.keys(keys).length) {
      SEL.box = box;
      Array.prototype.forEach.call(box.querySelectorAll(sc.row), function (r) {
        var rw = where(r.cells && r.cells[0] ? r.cells[0] : r);
        var k = rw && rowKey(rw);
        if (k && keys[k]) { r.classList.add('cxm-sel'); r.setAttribute('aria-selected', 'true'); }
      });
      if (!selRows().length) selClear(); else dock();
    } else selClear();
  } else if (SEL.box && SEL.scope) {
    Array.prototype.forEach.call(SEL.box.querySelectorAll(SEL.scope.row + ':not(.cxm-sel)'), function (r) {
      var rw = where(r.cells && r.cells[0] ? r.cells[0] : r);
      var k = rw && rowKey(rw);
      if (k && SEL.keys[k]) { r.classList.add('cxm-sel'); r.setAttribute('aria-selected', 'true'); }
    });
  }
  if (FILTERS.length || document.querySelector('table.cxm-filtered')) filterApply(); else dock();
}

/* ==========================================================================
   Filters of a table without a search box of its own (by the value of a column)
   ========================================================================== */
var FILTERS = [];     /* {key, col, value, out} */
function tableKey(table) {
  var around = table.id ? table : (table.parentNode && table.parentNode.closest ? table.parentNode.closest('[id]') : null);
  var heads = table.tHead && table.tHead.rows[0] ? Array.prototype.map.call(table.tHead.rows[0].cells, function (c) { return c.dataset.ck || textOf(c); }).join('|') : '';
  return (around ? around.id : 'page') + '|' + heads;
}
function colIndex(table, col) {
  if (!table.tHead || !table.tHead.rows[0]) return -1;
  var cells = table.tHead.rows[0].cells;
  for (var i = 0; i < cells.length; i++) if ((cells[i].dataset.ck || textOf(cells[i])) === col) return i;
  return -1;
}
function filterApply() {
  var tables = document.querySelectorAll('table');
  Array.prototype.forEach.call(tables, function (table) {
    var key = null;
    var mine = FILTERS.filter(function (f) { if (key === null) key = tableKey(table); return f.key === key; });
    var had = table.classList.contains('cxm-filtered');
    if (!mine.length && !had) return;
    table.classList.toggle('cxm-filtered', !!mine.length);
    Array.prototype.forEach.call(table.tBodies, function (tb) {
      Array.prototype.forEach.call(tb.rows, function (r) {
        var hide = mine.some(function (f) {
          var i = colIndex(table, f.col);
          if (i < 0 || !r.cells[i]) return false;
          var v = textOf(r.cells[i]).toLowerCase();
          var same = v === f.value.toLowerCase();
          return f.out ? same : !same;
        });
        r.classList.toggle('cxm-hide', hide);
      });
    });
  });
  dock();
}
function filterAdd(w, out) {
  var value = textOf(w.cell);
  var col = w.th ? (w.th.dataset.ck || textOf(w.th)) : '';
  FILTERS.push({key: tableKey(w.table), col: col, colShown: w.th ? textOf(w.th) : '', value: value, out: out});
  filterApply();
}
CX.filters = FILTERS;

/* ==========================================================================
   The acme clipboard (M2): the object as JSON, never a secret, between the tabs too
   ========================================================================== */
var CLIP_KEY = 'acme.ctx.clip';
var CLIP = null;
function clipRead() {
  try {
    var v = JSON.parse(localStorage.getItem(CLIP_KEY) || 'null');
    if (v && typeof v === 'object' && v.v === 1 && typeof v.type === 'string' && Array.isArray(v.items)) return v;
  } catch (e) { }
  return CLIP;
}
function clipWrite(c) {
  CLIP = c;
  try {
    if (c) localStorage.setItem(CLIP_KEY, JSON.stringify(c)); else localStorage.removeItem(CLIP_KEY);
  } catch (e) { /* private window, storage full: kept for this tab */ }
  dock();
}
window.addEventListener('storage', function (e) { if (e.key === CLIP_KEY) { CLIP = null; dock(); } });
/** The secrets taken out of anything that goes on the clipboard, a command or an API call. */
var SECRET_KEY = /(pass(word|phrase|wd)?|secret|token|private|priv_?key|api_?key|apikey|hmac|psk|credential|bind_pw|community|auth_?key|client_key|sas|service_account|key_pem|pin)$/i;
function isSecretValue(v) { return typeof v === 'string' && v.charAt(0) === '•'; }
function scrub(o, secretKeys) {
  var drop = {};
  arr(secretKeys).forEach(function (k) { drop[k] = 1; });
  var walk = function (v, depth) {
    if (depth > 8) return null;
    if (Array.isArray(v)) return v.map(function (x) { return walk(x, depth + 1); });
    if (v && typeof v === 'object') {
      var out = {};
      Object.keys(v).forEach(function (k) {
        if (drop[k] || SECRET_KEY.test(k) || isSecretValue(v[k])) return;
        if (/^(secret_set|secrets_set|secrets|caps|_rec|cert_pem|key_pem|chain_pem|csr_pem|pem)$/.test(k)) return;
        out[k] = walk(v[k], depth + 1);
      });
      return out;
    }
    if (isSecretValue(v)) return '';
    return v;
  };
  return walk(o, 0);
}
CX.scrub = scrub;
CX.secretKeyRe = SECRET_KEY;
CX.clip = function () { return clipRead(); };
CX.clipSet = function (type, list, label) {
  var c = {v: 1, type: type, at: Date.now(), origin: location.host, label: label || '', items: list};
  clipWrite(c);
  var t = TYPES[type];
  toast(list.length > 1 ? '{0} objects on the acme clipboard'.replace('{0}', list.length) : 'On the acme clipboard', 'good');
};
CX.clipClear = function () { clipWrite(null); };
/** A name nobody has: "Copy of web", "Copy of web 2"... (names are data: ASCII as acme's names are). */
CX.copyName = function (name, taken) {
  var low = {};
  arr(taken).forEach(function (n) { low[String(n).toLowerCase()] = 1; });
  var cs = (window.ACME_LANG || document.documentElement.lang) === 'cs';
  var base = (cs ? 'Kopie ' : 'Copy of ') + String(name || '').replace(/^(Copy of|Kopie) /, '');
  base = base.slice(0, 110);
  var n = 1, got = base;
  while (low[got.toLowerCase()]) { n += 1; got = base + ' ' + n; }
  return got;
};

/* ==========================================================================
   Copying
   ========================================================================== */
function heads(table) {
  if (!table || !table.tHead || !table.tHead.rows[0]) return [];
  return Array.prototype.map.call(table.tHead.rows[0].cells, function (c) { return textOf(c); });
}
function cellsOf(row) {
  return Array.prototype.map.call(row.cells || [], function (c) { return textOf(c); });
}
function csvLine(list) {
  return list.map(function (v) {
    v = String(v === undefined || v === null ? '' : v);
    /* a cell a spreadsheet would run as a formula starts with a quote */
    if (/^[=+\-@\t\r]/.test(v)) v = "'" + v;
    return /[",;\n\r]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
  }).join(',');
}
function rowsAs(rows, table, how) {
  var h = heads(table);
  var keep = h.map(function (x, i) { return x !== '' || rows.some(function (r) { return r.cells && r.cells[i] && textOf(r.cells[i]); }); });
  var pick = function (list) { return list.filter(function (x, i) { return keep[i] && (h[i] !== '' || x !== ''); }); };
  if (how === 'csv') {
    var out = [csvLine(pick(h))];
    rows.forEach(function (r) { out.push(csvLine(pick(cellsOf(r)))); });
    return out.join('\r\n') + '\r\n';
  }
  if (how === 'json') {
    var list = rows.map(function (r) {
      var w = where(r.cells && r.cells[0] ? r.cells[0] : r);
      if (w && w.obj && typeof w.obj === 'object') return scrub(w.obj, w.type && w.type.secrets ? w.type.secrets(w.obj) : []);
      var o = {};
      cellsOf(r).forEach(function (v, i) { if (h[i] || v) o[h[i] || '#' + (i + 1)] = v; });
      return o;
    });
    return JSON.stringify(list.length === 1 ? list[0] : list, null, 2);
  }
  return rows.map(function (r) {
    if (!r.cells) return textOf(r);
    var c = cellsOf(r);
    return h.length ? c.map(function (v, i) { return v && h[i] ? h[i] + ': ' + v : v; }).filter(Boolean).join('\n') : c.filter(Boolean).join('\t');
  }).join('\n\n');
}
CX.rowsAs = rowsAs;
function copy(text, words) { copyText(text, null, words || 'copied'); }
CX.copy = copy;

/* ==========================================================================
   The menu of a row
   ========================================================================== */
function headCard(w, n) {
  var card = el('div', 'cxm-head');
  var t = w.type;
  var ic = el('span', 'cxm-head-ic');
  ic.innerHTML = iconMarkup(n > 1 ? 'list' : (t && t.icon) || 'list', 16);
  card.appendChild(ic);
  var txt = el('div', 'cxm-head-w');
  if (n > 1) {
    txt.appendChild(el('b', '', '{0} selected'.replace('{0}', n)));
    txt.appendChild(el('span', 'cxm-head-t', t ? t.plural || t.label : 'rows'));
  } else {
    var name = t && w.obj ? String(t.nameOf(w.obj) || '') : (w.row.cells ? textOf(w.row.cells[0] || w.row) : textOf(w.row));
    txt.appendChild(data('b', '', (name || '').slice(0, 80) || '–'));
    txt.appendChild(el('span', 'cxm-head-t', t ? t.label : 'Row'));
  }
  card.appendChild(txt);
  return {card: card};
}
/** What a registered action needs: the object, the row, the cell, and helpers. */
function ctxFor(w) {
  return {row: w.row, cell: w.cell, th: w.th, table: w.table, box: w.box, scope: w.scope, type: w.type,
          where: w, full: isFull(), manage: isManage(), portal: portal()};
}
/** The row's own buttons, as items: pressed exactly as the button is. */
function rowButtons(row, skip) {
  var out = [];
  var tools = row.querySelectorAll('td.rowtools button, td.right button, .rowtools button, .osu-act button, .rpx-tools button, .ag-tile-acts button');
  Array.prototype.forEach.call(tools, function (b) {
    if (b.disabled || b.hidden || b.offsetParent === null) return;
    var label = (b.getAttribute('aria-label') || b.title || textOf(b) || '').trim();
    if (!label) return;
    if (skip && skip(label, b)) return;
    var svg = b.querySelector('svg');
    out.push({label: label, svg: svg ? svg.outerHTML.replace(/width="\d+"/, 'width="15"').replace(/height="\d+"/, 'height="15"') : null,
              danger: /trash|close|power|off|remove|delete/.test(b.className) || !b.classList.contains('go') && /^(Delete|Take|Revoke|Remove)/.test(label),
              go: function () { b.click(); }});
  });
  return out;
}
CX.rowButtons = rowButtons;
function filterItems(w) {
  if (!w.cell || !w.table) return [];
  var value = textOf(w.cell);
  if (!value || value === '–' || value.length > 200) return [];
  var via = w.scope && w.scope.filter ? w.scope.filter(w) : null;
  var short = value.length > 40 ? value.slice(0, 39) + '…' : value;
  if (via && via.box) {
    var put = function (neg) {
      var box = via.box;
      var now = String(box.value || '').trim();
      var term = (neg ? '-' : '') + via.term;
      box.value = (now ? now + ' ' : '') + term;
      box.dispatchEvent(new Event('input', {bubbles: true}));
      box.dispatchEvent(new Event('change', {bubbles: true}));
      if (via.after) via.after();
      toast((neg ? 'Left out of the list: {0}' : 'Only: {0}').replace('{0}', via.term), 'good');
    };
    var said = via.shown ? (via.shown.length > 40 ? via.shown.slice(0, 39) + '…' : via.shown) : short;
    return [{label: ['Filter by ', {data: '“' + said + '”'}], icon: 'funnel', note: via.term, noteData: true, go: function () { put(false); }},
            {label: ['Leave out ', {data: '“' + said + '”'}], icon: 'ban', note: '-' + via.term, noteData: true, go: function () { put(true); }}];
  }
  var paged = w.table.closest('.lt-paged') || (w.scope && w.scope.paged);
  var off = paged ? 'The list is paged - use its search box' : (!w.th ? 'This table has no headings to filter by' : '');
  return [{label: ['Filter by ', {data: '“' + short + '”'}], icon: 'funnel', off: off, go: function () { filterAdd(w, false); }},
          {label: ['Leave out ', {data: '“' + short + '”'}], icon: 'ban', off: off, go: function () { filterAdd(w, true); }}];
}
/** "Copy “the cell”" on its own, and one Copy ▸ with the row (text, CSV, JSON), the object's
    identifiers and the command and API call that make it. */
function copyItems(w, list) {
  var out = [];
  if (w.cell && list.length === 1) {
    var v = textOf(w.cell);
    if (v && v !== '–') out.push({label: ['Copy ', {data: '“' + (v.length > 34 ? v.slice(0, 33) + '…' : v) + '”'}], icon: 'copy',
                                  note: w.th ? textOf(w.th) : '', go: function () { copy(v, 'copied'); }});
  }
  var rows = list;
  var sub = [{head: list.length > 1 ? 'The rows' : 'The row'},
    {label: 'As text', icon: 'list', hint: list.length === 1 ? 'Mod+C' : '', go: function () { copy(rowsAs(rows, w.table, 'text')); }},
    {label: 'As CSV', icon: 'download', go: function () { copy(rowsAs(rows, w.table, 'csv'), 'copied as CSV'); }},
    {label: 'As JSON', icon: 'db', note: w.type ? 'without any secret' : '', go: function () { copy(rowsAs(rows, w.table, 'json'), 'copied as JSON'); }}];
  if (list.length === 1) {
    var ids = identItems(w);
    if (ids.length) sub = sub.concat(['-', {head: 'Its identifiers'}]).concat(ids);
    var as = asItems(w);
    if (as.length) sub = sub.concat(['-', {head: 'To make it again'}]).concat(as);
  }
  out.push({label: 'Copy', icon: 'list', sub: sub});
  return out;
}
function identItems(w) {
  var t = w.type;
  if (!t || !t.idents) return [];
  var got = [];
  try { got = (t.idents(w.obj, ctxFor(w)) || []).filter(function (x) { return x && x[1] !== undefined && x[1] !== null && String(x[1]) !== ''; }); } catch (e) { got = []; }
  if (!got.length) return [];
  var mk = function (x) { return {label: x[0], icon: x[2] || 'copy', note: String(x[1]).slice(0, 60), noteData: true, go: function () { copy(String(x[1])); }}; };
  return got.map(mk);
}
function asItems(w) {
  var t = w.type;
  if (!t || (!t.cli && !t.curl)) return [];
  var sub = [];
  var c = ctxFor(w);
  if (t.cli) sub.push({label: 'As a CLI command', icon: 'terminal', note: 'acme …', noteData: true, go: function () {
    return Promise.resolve(t.cli(w.obj, c)).then(function (text) { copy(text, 'the command is on the clipboard'); });
  }});
  if (t.curl) sub.push({label: 'As an API call (curl)', icon: 'globe', note: 'curl …', noteData: true, go: function () {
    return Promise.resolve(t.curl(w.obj, c)).then(function (call) { copy(CX.curlText(call), 'the API call is on the clipboard'); });
  }});
  return sub;
}
function clipItems(w, list) {
  var t = w.type;
  var out = [];
  var c = ctxFor(w);
  if (t && list.length === 1 && t.copyData) {
    out.push({label: 'Copy to the acme clipboard', icon: 'archive', hint: 'Mod+Shift+C', go: function () { return CX.copyObjects(t, [w.obj], c); }});
  } else if (t && list.length > 1 && t.copyData) {
    out.push({label: 'Copy them to the acme clipboard', icon: 'archive', go: function () { return CX.copyObjects(t, list.map(function (r) { return where(r.cells ? r.cells[0] : r).obj; }), c); }});
  }
  var clip = clipRead();
  if (clip && t) {
    var paste = t.paste && t.paste[clip.type];
    var objs = list.map(function (r) { var x = where(r.cells && r.cells[0] ? r.cells[0] : r); return x && x.obj; }).filter(Boolean);
    var src = TYPES[clip.type];
    var what = (clip.items.length > 1 ? clip.items.length + ' ' : '') + tr((src && (clip.items.length > 1 ? src.plural : src.label)) || clip.type).toLowerCase();
    /* (said in the page's language here: a note of data, not translated again) */
    if (paste) {
      var off = typeof paste.off === 'function' ? paste.off(clip, objs, c) : '';
      out.push({label: [(paste.words || 'Paste') + ' ', {data: clipName(clip)}], icon: 'import', hint: 'Mod+Shift+V', note: what, noteData: true,
                off: off, go: function () { return paste.go(clip, objs, c); }});
    }
    if (clip.type === t.name && t.pasteNew && list.length === 1) {
      out.push({label: ['Paste as new: ', {data: clipName(clip)}], icon: 'add', note: what, noteData: true, off: t.mayAdd && !t.mayAdd(c) ? (t.addRefused || 'Only a full administrator may do that') : '',
                go: function () { return t.pasteNew(clip, c); }});
    }
  }
  if (t && t.clone && list.length === 1) {
    var why = t.mayClone ? t.mayClone(w.obj, c) : '';
    out.push({label: 'Clone…', icon: 'copy', note: t.cloneNote || 'a new one with the same settings, saved only when you save it', off: why || '',
              go: function () { return t.clone(w.obj, c); }});
  }
  return out;
}
function clipName(clip) {
  var it = clip.items || [];
  if (it.length === 1) return String(it[0].name || '').slice(0, 40);
  return it.slice(0, 2).map(function (x) { return x.name; }).join(', ') + (it.length > 2 ? ' …' : '');
}
CX.clipName = clipName;
/** The title of the popup open now: its words translated, the name in it as it is. */
CX.nameTitle = function (words, name) {
  var t = document.getElementById('modal-title');
  if (!t) return;
  clear(t);
  t.appendChild(el('span', '', words));
  t.appendChild(document.createTextNode(' '));
  t.appendChild(data('span', '', name));
};
CX.copyObjects = function (t, objs, c) {
  return Promise.all(objs.map(function (o) { return Promise.resolve(t.copyData(o, c)); })).then(function (list) {
    CX.clipSet(t.name, list.map(function (d, i) {
      return {name: String(t.nameOf(objs[i]) || ''), id: t.key(objs[i]), data: scrub(d, t.secrets ? t.secrets(d) : [])};
    }));
  });
};
function goItems(w) {
  var t = w.type;
  if (!t) return [];
  var out = [];
  if (t.events && !portal() && document.getElementById('ev-q')) {
    out.push({label: 'Show in Events', icon: 'history', go: function () { CX.showEvents(t.events(w.obj)); }});
  }
  if (t.jobs && !portal() && document.getElementById('jb-cert')) {
    var j = t.jobs(w.obj);
    if (j) out.push({label: 'Show in Jobs', icon: 'list', go: function () { CX.showJobs(j); }});
  }
  return out;
}
CX.showEvents = function (words) {
  if (typeof showTab === 'function') showTab('events');
  setTimeout(function () {
    var q = document.getElementById('ev-q');
    if (!q) return;
    q.value = String(words || '');
    q.dispatchEvent(new Event('input', {bubbles: true}));
    q.dispatchEvent(new Event('change', {bubbles: true}));
  }, 60);
};
CX.showJobs = function (f) {
  if (typeof showTab === 'function') showTab('jobs');
  setTimeout(function () {
    var c = document.getElementById('jb-cert');
    if (!c) return;
    if (f.cert_id && !c.querySelector('option[value="' + String(f.cert_id).replace(/"/g, '') + '"]')) {
      var o = el('option', '', f.name || ('#' + f.cert_id));
      o.value = String(f.cert_id);
      noI18n(o);
      c.appendChild(o);
    }
    c.value = String(f.cert_id || '');
    c.dispatchEvent(new Event('change', {bubbles: true}));
  }, 60);
};
function rowMenu(w, x, y, opts) {
  opts = opts || {};
  var sel = selRows();
  var inSel = sel.length > 1 && sel.indexOf(w.row) >= 0;
  var list = inSel ? sel : [w.row];
  var t = w.type;
  var c = ctxFor(w);
  var menu = [];
  if (!inSel) {
    /* open: what the row does when pressed, or what its kind says */
    var openIt = t && t.open ? function () { return t.open(w.obj, c); } : (w.row.classList.contains('tappable') || typeof w.row.onclick === 'function' ? function () { w.row.click(); } : null);
    if (openIt) menu.push({label: 'Open', icon: 'eye', hint: 'Enter', go: openIt});
  }
  var acts = [];
  if (inSel) {
    if (t && t.bulk) { try { acts = t.bulk(list.map(function (r) { return where(r.cells && r.cells[0] ? r.cells[0] : r).obj; }).filter(Boolean), c) || []; } catch (e) { acts = []; } }
  } else {
    var own = [];
    if (t && t.actions) { try { own = t.actions(w.obj, c) || []; } catch (e) { own = []; } }
    var labels = {};
    own.forEach(function (a) { if (a && a.label && typeof a.label === 'string') labels[a.label.toLowerCase()] = 1; });
    var buttons = t && t.actions && !t.rowButtons ? [] : rowButtons(w.row, function (label) {
      var l = String(label).toLowerCase();
      return labels[l] || (t && t.skipButtons && t.skipButtons.test(label));
    });
    acts = own.concat(buttons);
  }
  /* somebody who may only look is not shown what they may not do; an administrator is - greyed,
     with why (their teams, or a full administrator's) */
  if (!isManage()) acts = acts.filter(function (a) { return a && !a.off; });
  var safe = acts.filter(function (a) { return a && !a.danger; });
  var danger = acts.filter(function (a) { return a && a.danger; });
  if (safe.length) { menu.push('-'); menu = menu.concat(safe); }
  menu.push('-');
  menu = menu.concat(copyItems(w, list));
  var clip = clipItems(w, list);
  if (clip.length) { menu.push('-'); menu = menu.concat(clip); }
  if (!inSel) {
    var f = filterItems(w);
    if (f.length) { menu.push('-'); menu = menu.concat(f); }
    var g = goItems(w);
    if (g.length) { menu.push('-'); menu = menu.concat(g); }
  }
  menu.push('-');
  if (inSel) menu.push({label: 'Clear the selection', icon: 'close', hint: 'Esc', go: function () { selClear(); }});
  else if (t || w.row.classList.contains('tappable')) {
    var picked = w.row.classList.contains('cxm-sel');
    menu.push({label: 'Select', icon: 'check', sub: [
      {label: picked ? 'Take this row out' : 'This row', icon: 'check', note: MOD + '+click', noteData: true, go: function () { selToggle(w); }},
      {label: 'Every row of the list', icon: 'list', note: 'Shift+click: from one to another', go: function () { CX.selectAll(w); }}]});
  }
  if (danger.length) { menu.push('-'); menu = menu.concat(danger); }
  openMenu(menu, x, y, {head: headCard(w, list.length).card, row: w.row, opener: opts.opener, touch: opts.touch,
                        label: t ? tr(t.label) : tr('Row')});
}
CX.rowMenu = rowMenu;
function areaMenu(a, x, y, opts) {
  var s = a.scope, t = TYPES[s.type];
  var c = {box: a.box, scope: s, type: t, full: isFull(), manage: isManage(), portal: portal()};
  var menu = [];
  var card = el('div', 'cxm-head');
  var ic = el('span', 'cxm-head-ic');
  ic.innerHTML = iconMarkup((t && t.icon) || 'list', 16);
  card.appendChild(ic);
  var tw = el('div', 'cxm-head-w');
  tw.appendChild(el('b', '', (t && t.plural) || 'List'));
  tw.appendChild(el('span', 'cxm-head-t', 'The list'));
  card.appendChild(tw);
  if (t && t.add) menu.push({label: t.addWords || 'Add a new one…', icon: 'add', off: t.mayAdd && !t.mayAdd(c) ? (t.addRefused || 'Only a full administrator may do that') : '', go: function () { return t.add(c); }});
  var clip = clipRead();
  if (t && t.pasteNew) {
    var same = clip && clip.type === t.name;
    menu.push({label: same ? ['Paste as new: ', {data: clipName(clip)}] : 'Paste as new', icon: 'import', hint: 'Mod+Shift+V',
               off: !same ? (clip ? 'The acme clipboard holds another kind of object' : 'The acme clipboard is empty - copy one first')
                    : (t.mayAdd && !t.mayAdd(c) ? (t.addRefused || 'Only a full administrator may do that') : ''),
               go: function () { return t.pasteNew(clip, c); }});
  }
  var table = a.box.querySelector('table');
  if (table && table.tBodies[0] && table.tBodies[0].rows.length) {
    menu.push('-');
    var rows = Array.prototype.filter.call(table.tBodies[0].rows, function (r) { return r.offsetParent !== null && !r.classList.contains('empty-row'); });
    menu.push({label: 'Copy the whole list', icon: 'list', sub: [
      {label: 'As text', icon: 'list', go: function () { copy(rowsAs(rows, table, 'text')); }},
      {label: 'As CSV', icon: 'download', go: function () { copy(rowsAs(rows, table, 'csv'), 'copied as CSV'); }},
      {label: 'As JSON', icon: 'db', go: function () { copy(rowsAs(rows, table, 'json'), 'copied as JSON'); }}]});
  }
  if (clip) { menu.push('-'); menu.push({label: 'Empty the acme clipboard', icon: 'broom', go: function () { CX.clipClear(); }}); }
  openMenu(menu, x, y, {head: card, opener: opts && opts.opener, touch: opts && opts.touch, label: tr((t && t.plural) || 'List')});
}
CX.areaMenu = areaMenu;

/* The keys of the menu's items, where a row has the focus: Ctrl+C the row as text,
   Ctrl+Shift+C onto the acme clipboard, Ctrl+Shift+V paste. */
document.addEventListener('keydown', function (e) {
  if (!(e.ctrlKey || e.metaKey) || e.altKey) return;
  var k = String(e.key || '').toLowerCase();
  if (k !== 'c' && k !== 'v') return;
  var t = document.activeElement;
  if (!t || typing(t) || OPEN) return;
  if (k === 'c' && !e.shiftKey) {
    var s = window.getSelection && window.getSelection();
    if (s && !s.isCollapsed && String(s).trim()) return;          /* text selected: the browser's copy */
  }
  var w = t.closest && (t.matches('tr, .tmx-row, .rp-row, .ag-tile') ? where(t.cells && t.cells[0] ? t.cells[0] : t) : null);
  if (!w && !(k === 'v' && e.shiftKey)) return;
  if (k === 'c' && !e.shiftKey) { e.preventDefault(); copy(rowsAs([w.row], w.table, 'text')); return; }
  if (k === 'c' && e.shiftKey && w.type && w.type.copyData) { e.preventDefault(); CX.copyObjects(w.type, [w.obj], ctxFor(w)).catch(oops); return; }
  if (k === 'v' && e.shiftKey) {
    var clip = clipRead();
    if (!clip) return;
    if (w && w.type && w.type.paste && w.type.paste[clip.type]) {
      e.preventDefault();
      var p = w.type.paste[clip.type];
      if (p.off && p.off(clip, [w.obj], ctxFor(w))) { toast(p.off(clip, [w.obj], ctxFor(w)), 'warn'); return; }
      Promise.resolve(p.go(clip, [w.obj], ctxFor(w))).catch(oops);
      return;
    }
    var a = (w && w.row) ? areaOf(w.row) : (t.closest ? areaOf(t) : null);
    var ty = a && TYPES[a.scope.type];
    if (ty && ty.pasteNew && clip.type === ty.name) {
      e.preventDefault();
      Promise.resolve(ty.pasteNew(clip, {box: a.box, scope: a.scope, type: ty, full: isFull(), manage: isManage()})).catch(oops);
    }
  }
});

/* ==========================================================================
   Several at once (M3): what will happen, then one result for all of them
   ========================================================================== */
/** plan: {title, verb, icon, danger, items: [{name, will, skip}], run(item) -> Promise of
    {ok, said, job_id}, intro, extra(body), done()} - asked first, run one after another, one
    summary at the end. */
CX.bulk = function (plan) {
  var doing = plan.items.filter(function (x) { return !x.skip; });
  var skipped = plan.items.filter(function (x) { return x.skip; });
  var state = {body: null};
  modal(plan.title, function (body) {
    state.body = body;
    body.classList.add('cxb');
    if (plan.intro) body.appendChild(el('p', 'note', plan.intro));
    var sum = el('div', 'cxb-sum');
    var pill = function (n, words, cls, ic) {
      var p = el('span', 'cxb-pill ' + cls);
      p.appendChild(icon(ic, 13));
      p.appendChild(el('span', '', words.replace('{0}', n)));
      return p;
    };
    sum.appendChild(pill(doing.length, '{0} will be done', 'go', plan.icon || 'play'));
    if (skipped.length) sum.appendChild(pill(skipped.length, '{0} left as they are', 'skip', 'ban'));
    body.appendChild(sum);
    if (plan.extra) plan.extra(body);
    var list = el('div', 'cxb-list');
    list.setAttribute('role', 'list');
    plan.items.forEach(function (x) {
      var r = el('div', 'cxb-row' + (x.skip ? ' skip' : ''));
      r.setAttribute('role', 'listitem');
      var st = el('span', 'cxb-st');
      st.innerHTML = iconMarkup(x.skip ? 'ban' : (plan.icon || 'play'), 14);
      r.appendChild(st);
      var w = el('div', 'cxb-w');
      w.appendChild(data('b', '', x.name));
      w.appendChild(el('span', 'cxb-will', x.skip || x.will || plan.verb));
      r.appendChild(w);
      x._row = r;
      list.appendChild(r);
    });
    body.appendChild(list);
  }, [{words: 'Cancel', close: true},
      {words: plan.button || plan.title.replace(/\?$/, ''), cls: plan.danger ? 'danger' : 'primary', icon: plan.icon || 'play', once: true, go: function (b) {
        if (!doing.length) { closeModal(); return; }
        if (plan.check) { var bad = plan.check(); if (bad) { toast(bad, 'bad'); return; } }
        busy(b, true);
        if (state.body) {
          Array.prototype.forEach.call(state.body.querySelectorAll('input, select, textarea'), function (x) { x.disabled = true; });
          var sm = state.body.querySelector('.cxb-sum');
          if (sm) sm.remove();
        }
        var ok = 0, bad = 0, jobs = [];
        var bar = el('div', 'cxb-bar');
        var fill = el('span', '');
        bar.appendChild(fill);
        if (state.body) state.body.insertBefore(bar, state.body.querySelector('.cxb-list'));
        var step = function (i) {
          if (i >= doing.length) return Promise.resolve();
          var x = doing[i];
          x._row.classList.add('running');
          return Promise.resolve().then(function () { return plan.run(x); }).then(function (got) {
            var good = !got || got.ok !== false;
            if (good) ok += 1; else bad += 1;
            if (got && got.job_id) jobs.push(got.job_id);
            mark(x, good, got && (got.said || got.message));
          }, function (e) {
            bad += 1;
            mark(x, false, String((e && e.message) || e));
          }).then(function () {
            fill.style.width = Math.round(100 * (i + 1) / doing.length) + '%';
            return step(i + 1);
          });
        };
        var mark = function (x, good, said) {
          x._row.classList.remove('running');
          x._row.classList.add(good ? 'ok' : 'bad');
          x._row.querySelector('.cxb-st').innerHTML = iconMarkup(good ? 'check' : 'close', 14);
          var will = x._row.querySelector('.cxb-will');
          will.textContent = said ? String(said) : (good ? tr('done') : tr('failed'));
          if (said) noI18n(will);
          if (x._job) x._job = null;
        };
        step(0).then(function () {
          busy(b, false);
          b.hidden = true;
          var res = el('div', 'cxb-result ' + (bad ? (ok ? 'mixed' : 'bad') : 'ok'));
          res.setAttribute('role', 'status');
          res.appendChild(icon(bad ? 'info' : 'check', 18));
          var words = el('div', '');
          words.appendChild(el('b', '', bad ? '{0} done, {1} failed'.replace('{0}', ok).replace('{1}', bad) : 'All {0} done'.replace('{0}', ok)));
          if (jobs.length) words.appendChild(el('span', 'muted small', '{0} job(s) started - their steps are in Jobs'.replace('{0}', jobs.length)));
          res.appendChild(words);
          if (jobs.length && document.getElementById('jb-table')) {
            var jb = cmdButton('Open Jobs', 'list', 'small');
            jb.onclick = function () { closeModal(); if (typeof showTab === 'function') showTab('jobs'); };
            res.appendChild(jb);
          }
          if (state.body) state.body.insertBefore(res, state.body.firstChild);
          var foot = document.getElementById('modal-foot');
          var cancel = foot && foot.querySelector('button');
          if (cancel) { var sp = cancel.querySelector('span'); if (sp) sp.textContent = 'Close'; else cancel.textContent = 'Close'; }
          if (plan.done) plan.done({ok: ok, bad: bad, jobs: jobs});
        });
      }}], 'medium');
};

/* ==========================================================================
   A command and an API call (M4)
   ========================================================================== */
var FILL = '<fill in>';
CX.FILL = FILL;
/** A word for the shell: as it is when it is safe, else in single quotes. */
function sh(v) {
  v = String(v === undefined || v === null ? '' : v);
  if (v === FILL) return "'" + FILL + "'";
  if (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(v)) return v;
  if (/\n/.test(v)) return "$'" + v.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n') + "'";
  return "'" + v.replace(/'/g, "'\\''") + "'";
}
CX.sh = sh;
/** acme ARGS... as lines a terminal takes (one option a line, a backslash at the end). */
CX.cliText = function (parts, notes) {
  var lines = [], line = 'acme';
  parts.forEach(function (p) {
    if (Array.isArray(p)) {
      var bit = p.map(function (x, i) { return i === 0 ? x : sh(x); }).join(' ');
      lines.push(line);
      line = '  ' + bit;
    }
  });
  lines.push(line);
  var text = lines.join(' \\\n');
  if (notes && notes.length) text += '\n' + notes.map(function (n) { return '# ' + n; }).join('\n');
  return text + '\n';
};
CX.setValue = function (v) {
  if (Array.isArray(v)) return v.map(function (x) { return String(x); }).join(v.some(function (x) { return /,/.test(String(x)); }) ? '\n' : ',');
  if (v === true) return 'yes';
  if (v === false) return 'no';
  if (v && typeof v === 'object') return JSON.stringify(v);
  return String(v === null || v === undefined ? '' : v);
};
/** curl of an API route of the administration (?api=...), its body as JSON on stdin. */
CX.curlText = function (call) {
  var base = location.origin + (portal() ? '/' : '/admin/');
  var cookie = (location.protocol === 'https:' ? '__Host-' : '') + 'acme_session';
  var url = base + '?api=' + call.path;
  var lines = ['curl -sS ' + (call.method === 'GET' ? '' : '-X POST ') + sh(url)];
  lines.push("  -b '" + cookie + "=" + FILL + "'");
  if (call.method !== 'GET') {
    lines.push("  -H 'Content-Type: application/json'");
    lines.push("  --data-binary @- <<'JSON'");
  }
  var text = lines.join(' \\\n');
  if (call.method !== 'GET') text += '\n' + JSON.stringify(call.body || {}, null, 2) + '\nJSON';
  var notes = ['the cookie: the session of a signed-in administrator (the browser\'s ' + cookie + ')'];
  if (call.notes) notes = notes.concat(call.notes);
  return text + '\n' + notes.map(function (n) { return '# ' + n; }).join('\n') + '\n';
};

/* ==========================================================================
   The dock: what is picked, what is filtered, what is on the acme clipboard
   ========================================================================== */
var DOCK = null, DOCK_SAID = '';
function dock() {
  if (!document.body) return;
  var sel = selRows();
  var shownFilters = FILTERS.filter(function (f) {
    return Array.prototype.some.call(document.querySelectorAll('table.cxm-filtered'), function (t) { return t.offsetParent !== null && tableKey(t) === f.key; });
  });
  var clip = clipRead();
  if (!sel.length && !shownFilters.length && !clip) { if (DOCK) { DOCK.remove(); DOCK = null; } DOCK_SAID = ''; return; }
  /* drawn again only when what it says changed: the page's clock ticks every second */
  var said = [sel.length, shownFilters.map(function (f) { return f.key + f.col + f.value + f.out; }).join('|'),
              clip ? clip.at + clip.type + clip.items.length : '', window.innerWidth < 560].join('#');
  if (DOCK && DOCK.isConnected && said === DOCK_SAID) return;
  DOCK_SAID = said;
  if (!DOCK || !DOCK.isConnected) {
    DOCK = el('div', 'cxm-dock');
    DOCK.setAttribute('role', 'region');
    DOCK.setAttribute('aria-label', tr('Selection and the acme clipboard'));
    document.body.appendChild(DOCK);
  }
  clear(DOCK);
  if (sel.length) {
    var s = el('div', 'cxm-dk sel');
    s.appendChild(icon('check', 14));
    s.appendChild(el('b', '', '{0} selected'.replace('{0}', sel.length)));
    var acts = el('button', 'cxm-dk-b');
    acts.type = 'button';
    acts.appendChild(el('span', '', 'Actions'));
    acts.appendChild(icon('down', 12));
    acts.onclick = function () {
      var r = sel[0];
      var w = where(r.cells && r.cells[0] ? r.cells[0] : r);
      if (!w) return;
      var rr = acts.getBoundingClientRect();
      rowMenu(w, rr.left, rr.top - 8, {opener: acts});
      /* above the dock: the menu sits on it */
      if (OPEN) { var n = OPEN.root.node, h = n.getBoundingClientRect().height; n.style.top = Math.max(8, rr.top - h - 8) + 'px'; }
    };
    s.appendChild(acts);
    var x = el('button', 'cxm-dk-x');
    x.type = 'button';
    x.setAttribute('aria-label', tr('Clear the selection'));
    x.innerHTML = iconMarkup('close', 13);
    x.onclick = selClear;
    s.appendChild(x);
    DOCK.appendChild(s);
  }
  shownFilters.forEach(function (f) {
    var c = el('div', 'cxm-dk filt');
    c.appendChild(icon(f.out ? 'ban' : 'funnel', 13));
    if (f.colShown) c.appendChild(data('span', 'cxm-dk-col', f.colShown));
    c.appendChild(el('span', 'cxm-dk-op', f.out ? '≠' : '='));
    c.appendChild(data('b', '', f.value.length > 30 ? f.value.slice(0, 29) + '…' : f.value));
    var x2 = el('button', 'cxm-dk-x');
    x2.type = 'button';
    x2.setAttribute('aria-label', tr('Take this filter away'));
    x2.innerHTML = iconMarkup('close', 13);
    x2.onclick = function () { FILTERS.splice(FILTERS.indexOf(f), 1); filterApply(); };
    c.appendChild(x2);
    DOCK.appendChild(c);
  });
  if (clip) {
    var t = TYPES[clip.type];
    var k = el('div', 'cxm-dk clip');
    k.appendChild(icon((t && t.icon) || 'archive', 13));
    var kw = el('span', 'cxm-dk-cw');
    kw.appendChild(el('span', 'cxm-dk-k', clip.items.length > 1 ? '{0} on the clipboard'.replace('{0}', clip.items.length) : (t ? t.label : clip.type)));
    kw.appendChild(data('b', '', clipName(clip)));
    k.appendChild(kw);
    explain(k, tr('On the acme clipboard (this browser, every tab of it, without any secret). Paste it with the right button on a row or on the empty part of a list, or Ctrl+Shift+V.'));
    var x3 = el('button', 'cxm-dk-x');
    x3.type = 'button';
    x3.setAttribute('aria-label', tr('Empty the acme clipboard'));
    x3.innerHTML = iconMarkup('close', 13);
    x3.onclick = function () { CX.clipClear(); };
    k.appendChild(x3);
    DOCK.appendChild(k);
  }
}
CX.dock = dock;
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', dock); else setTimeout(dock, 0);
/* a tab changed: the filters of tables not shown leave the dock */
document.addEventListener('click', function (e) { if (e.target && e.target.closest && e.target.closest('.tabs, #ctl-nav')) setTimeout(dock, 50); });
}());
