/* catalog.js - a field of the type `catalog` (acmelib/plugins/base.py): a choice
   from a list the module fetches live - a CA's products (SSLS.cz), its server
   types. certs.js draws the module's form and hands a field of this type here
   (window.ACME_FIELD_TYPES.catalog).

   "Load the list" asks the daemon (POST /api/<sources|validations|targets>/
   catalog, acmelib/certs/api_catalog.py) with the form as it is - saved or
   not; a secret left as its dots is the one kept - and the module asks its
   server, read-only: nothing is ordered or changed. The list fills the
   select; what was chosen before stays chosen (said when the list no longer
   has it). A choice can fill other fields of the form in (`sets` of the
   answer: a product's validation level, its authority), as if typed - the
   form shows and hides its parts by them. A saved module loads its list by
   itself when its form opens. */
'use strict';
(function () {
  var PATHS = {issuer: 'sources', challenge: 'validations', target: 'targets'};

  /* Words in the page's language for where they go into data (an option of the
     list, marked as data): i18n.js's own, English where there is none. */
  function catTr(words) {
    try { var got = typeof i18nText === 'function' ? i18nText(words) : null; return got || words; }
    catch (e) { return words; }
  }

  /* A field of the form given a value from here: as if typed (show_if repaints). */
  function catSet(form, key, v) {
    var item = form && form.querySelector('[data-fkey="' + key + '"]');
    if (!item) return false;
    var box = item.querySelector('input[type="checkbox"]');
    if (box) {
      box.checked = v === true || v === 1 || v === '1' || v === 'true';
    } else {
      box = item.querySelector('select') || item.querySelector('textarea') || item.querySelector('input');
      if (!box) return false;
      if (box.tagName === 'SELECT' && v !== '' && v !== null && v !== undefined &&
          !Array.prototype.some.call(box.options, function (o) { return o.value === String(v); })) {
        var o = el('option', '', String(v));
        o.value = String(v);
        box.appendChild(o);
      }
      box.value = v === undefined || v === null ? '' : String(v);
    }
    box.dispatchEvent(new Event('input', {bubbles: true}));
    box.dispatchEvent(new Event('change', {bubbles: true}));
    return true;
  }

  function catalogField(f, v, ctx) {
    ctx = ctx || {};
    var opts = ctx.opts || {};
    var now = v === undefined || v === null ? '' : String(v);
    var wrap = el('div', 'ct-catalog');
    var line = el('div', 'ct-catalog-line');
    line.style.display = 'flex';
    line.style.gap = '8px';
    line.style.alignItems = 'center';
    line.style.flexWrap = 'wrap';
    var sel = el('select', 'ct-catalog-select');
    sel.style.flex = '1 1 16em';
    sel.style.minWidth = '0';
    noI18n(sel);                      /* the names of products: data */
    var load = cmdButton('Load the list', 'refresh', 'small');
    var said = el('div', 'muted small ct-catalog-said');
    /* Always settable by hand too (a value the list does not show, or no list to
       load): "Type it yourself…" opens a box of its own. */
    var OWN = '\u0001own';
    var own = el('input', 'mono ct-catalog-own');
    own.type = 'text';
    own.placeholder = f.placeholder || '';
    own.style.flex = '1 1 12em';
    own.style.minWidth = '0';
    own.hidden = true;
    noI18n(own);
    line.appendChild(sel);
    line.appendChild(own);
    line.appendChild(load);
    wrap.appendChild(line);
    wrap.appendChild(said);
    var sets = {};

    function fill(pairs) {
      var keep = sel.value || now;
      while (sel.firstChild) sel.removeChild(sel.firstChild);
      var add = function (val, words) {
        var o = document.createElement('option');
        o.value = val;
        o.textContent = words;
        sel.appendChild(o);
      };
      if (keep === OWN) keep = own.value.trim();
      if (!pairs) {
        add('', catTr(keep ? 'chosen before - Load the list to see the others' : 'not loaded yet - Load the list'));
        if (keep) add(keep, keep);
      } else {
        add('', '–');
        pairs.forEach(function (p) { add(p[0], p[1] + (p[1].indexOf(p[0]) < 0 ? ' · ' + p[0] : '')); });
        if (keep && !pairs.some(function (p) { return p[0] === keep; })) {
          add(keep, keep + ' - ' + catTr('not in the list'));
        }
      }
      add(OWN, catTr('Type it yourself…'));
      sel.value = keep;
      ownShown();
    }
    function ownShown() {
      own.hidden = sel.value !== OWN;
      if (!own.hidden && !own.value) own.focus();
    }
    fill(null);

    function family() { return PATHS[opts.family] || 'sources'; }
    function current() {
      try { return ctx.current ? ctx.current() : {}; } catch (e) { return {}; }
    }
    function ask() {
      var row = opts.row || null, plug = opts.plug || {};
      var body = {kind: plug.kind || (row && row.kind) || '', field: f.key, config: current()};
      if (row && row.id) { body.id = row.id; body.name = row.name; }
      busy(load, true);
      said.className = 'muted small ct-catalog-said';
      said.textContent = catTr('asking…');
      return api(family() + '-catalog', body, 90).then(function (d) {
        sets = d.sets || {};
        fill(arr(d.options));
        said.textContent = String(d.said || '');
      }).catch(function (e) {
        said.className = 'bad small ct-catalog-said';
        said.textContent = String((e && e.message) || e);
      }).then(function () { busy(load, false); });
    }
    load.onclick = ask;
    sel.addEventListener('change', function () {
      ownShown();
      var want = sets[sel.value];
      if (!want || !ctx.form) return;
      Object.keys(want).forEach(function (k) { catSet(ctx.form, k, want[k]); });
    });
    /* A saved module: its list loaded by itself (its secrets are kept there). */
    if (opts.row && opts.row.id && (f.autoload !== false)) setTimeout(ask, 0);
    /* Given from outside (discovery, 1.0.29): the value chosen - the list it came
       with put in, when there is one - or typed in "Type it yourself…". */
    function put(v, extra) {
      v = v === undefined || v === null ? '' : String(v);
      extra = extra || {};
      if (Array.isArray(extra.options) && extra.options.length) {
        sets = extra.sets || sets;
        fill(extra.options.filter(function (p) { return p[0] !== ''; }));
      }
      if (v === '' || Array.prototype.some.call(sel.options, function (o) { return o.value === v; })) {
        sel.value = v;
      } else {
        sel.value = OWN;
        own.value = v;
      }
      ownShown();
    }
    return {input: wrap, box: sel, set: put,
            get: function () { return sel.value === OWN ? own.value.trim() : sel.value; }};
  }

  function arr(x) { return Array.isArray(x) ? x : []; }

  window.ACME_FIELD_TYPES = window.ACME_FIELD_TYPES || {};
  window.ACME_FIELD_TYPES.catalog = catalogField;
})();
