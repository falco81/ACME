/* discover.js - "Find the settings from the account" (1.0.29): a module's form
   filled in from what its account says. certs.js puts the button over the form
   of a source, a validation or a target whose module offers it (GET
   /api/plugins: discover = {keys}) and hands it here (window.ACME_DISCOVER).

   A popup over the form asks only what signing in takes (the module's keys:
   its secrets, its address, its user - the values of the form shown, a kept
   secret as its dots); "Find out" asks the daemon (POST /api/<sources|
   validations|targets>/discover, acmelib/certs/api_discover.py), which has
   the module ask its server - read-only: nothing is ordered, changed or
   saved. What it found is shown beside what the form says now: a value
   where the form has none is ticked, one the form has otherwise is not
   (discovery never overwrites what was set without being asked), a choice
   is a list. "Fill in the ticked ones" puts them into the form, with what
   was typed in the popup; Save keeps it. Every field stays settable by hand. */
'use strict';
(function () {
  var PATHS = {issuer: 'sources', challenge: 'validations', target: 'targets'};

  function arr(x) { return Array.isArray(x) ? x : []; }
  function obj(x) { return x && typeof x === 'object' && !Array.isArray(x) ? x : {}; }
  function blank(v) { return v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length); }
  function text(v) {
    if (Array.isArray(v)) return v.map(String).join(', ');
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    return blank(v) ? '' : String(v);
  }
  function same(a, b) {
    if (typeof a === 'boolean' || typeof b === 'boolean') return truthy(a) === truthy(b);
    var s = function (v) { return Array.isArray(v) ? v.map(String).join('\n') : (blank(v) ? '' : String(v)); };
    return s(a).trim() === s(b).trim();
  }

  /* `o`: {form (fieldForm of the module), row (saved, or null), p (the module),
     family, secrets, nameNow()} -> the bar to put over the form. */
  /* certs.js's own helpers, handed in (it keeps them to itself) */
  var H = {};
  function fieldForm() { return H.fieldForm.apply(null, arguments); }
  function over() { return H.over.apply(null, arguments); }
  function capi() { return H.capi.apply(null, arguments); }
  function failedBox() { return H.failedBox.apply(null, arguments); }
  function factsRow() { return H.factsRow.apply(null, arguments); }
  function td() { return H.td.apply(null, arguments); }
  function data() { return H.data.apply(null, arguments); }
  function saidLine() { return H.saidLine.apply(null, arguments); }
  function jobPeek() { return H.jobPeek.apply(null, arguments); }
  function truthy(v) { return H.truthy ? H.truthy(v) : (v === true || v === 1 || v === '1' || v === 'true'); }

  function discoverBar(o) {
    H = o.h || H;
    var p = o.p || {};
    var keys = arr(obj(p.discover).keys);
    var bar = el('div', 'btnrow ct-discover');
    var go = cmdButton('Find the settings from the account', 'search', 'small');
    bar.appendChild(go);
    bar.appendChild(el('span', 'muted small', 'Only the sign-in is needed - the rest is read from the account and offered. Everything can still be set by hand.'));
    go.onclick = function () { over(function () { popupOf(o, keys); }); };
    return bar;
  }

  function popupOf(o, keys) {
    var p = o.p || {}, form = o.form;
    var fieldsOf = {};
    arr(p.fields).forEach(function (f) { fieldsOf[f.key] = f; });
    var asked = keys.map(function (k) { return fieldsOf[k]; }).filter(Boolean);
    var now = {};
    asked.forEach(function (f) { var v = form.get(f.key); if (v !== undefined) now[f.key] = v; });
    var sub = null, out = null, said = null;
    modal('Find the settings from the account', function (body) {
      body.appendChild(el('p', 'note', 'Give only what signing in to the account takes. acme asks its API and only reads - nothing is ordered, changed or saved - then offers what it found: what you tick is filled into the form, and Save keeps it. A value the form has already is never replaced unless you tick it.'));
      body.appendChild(el('h4', 'ct-formh', 'Sign-in'));
      sub = fieldForm(asked, now, o.secrets || {}, {family: p.family || o.family, row: o.row, plug: p, none: false});
      body.appendChild(sub.node);
      said = saidLine('', '');
      body.appendChild(said);
      out = el('div', 'ct-discover-out');
      body.appendChild(out);
    }, [
      {words: 'Close', close: true},
      {words: 'Find out', cls: 'primary', icon: 'search', go: function (b) { ask(b); }}
    ], 'medium');

    function cfgNow() {
      var c = {};
      /* the form as it is (what the module needs besides the sign-in - its own
         choices), the popup's values over it */
      try { c = form.read() || {}; } catch (e) { c = {}; }
      var s = sub.read();
      Object.keys(s).forEach(function (k) { c[k] = s[k]; });
      return c;
    }
    function ask(b) {
      var bad = sub.check();
      if (bad) { toast(bad, 'bad'); return; }
      busy(b, true);
      said.className = 'said';
      said.textContent = 'Asking the account…';
      clear(out);
      var body = {kind: p.kind, config: cfgNow(), name: o.nameNow ? o.nameNow() : ''};
      if (o.row && o.row.id) body.id = o.row.id;
      capi(PATHS[o.family] + '/discover', body, 180).then(function (d) {
        draw(d || {});
      }).catch(function (e) {
        said.className = 'said bad';
        said.textContent = '';
        out.appendChild(failedBox(e, 'the settings from the account'));
        out.appendChild(el('p', 'muted small', 'Every field of the form can still be set by hand.'));
      }).then(function () { busy(b, false); });
    }

    function draw(d) {
      var f = obj(d.found);
      clear(out);
      var worked = d.worked !== undefined ? !!d.worked : !!d.ok;
      said.className = 'said ' + (worked ? 'good' : 'bad');
      said.textContent = '';
      said.appendChild(el('span', '', String(d.said || '')));
      if (d.job_id) {
        var st = el('button', 'btn small ct-steps-btn', 'every step');
        st.type = 'button';
        st.onclick = function () { over(function () { jobPeek(d.job_id); }); };
        said.appendChild(st);
      }
      if (!worked) {
        out.appendChild(el('p', 'muted small', 'Every field of the form can still be set by hand.'));
        return;
      }
      if (arr(f.facts).length) {
        out.appendChild(factsRow(arr(f.facts).map(function (x) { return [x[0], data('span', 'mono', x[1])]; })));
      }
      if (arr(f.notes).length) {
        var ul = el('ul', 'ct-discover-notes');
        arr(f.notes).forEach(function (w) { ul.appendChild(data('li', 'warn small', w)); });
        out.appendChild(ul);
      }
      var rows = [], already = 0;
      Object.keys(obj(f.sets)).forEach(function (k) {
        if (!fieldsOf[k]) return;
        var v = f.sets[k];
        if (same(form.get(k), v)) { already += 1; return; }
        rows.push({key: k, value: v});
      });
      Object.keys(obj(f.choices)).forEach(function (k) {
        if (!fieldsOf[k]) return;
        var c = f.choices[k];
        rows.push({key: k, choice: c});
      });
      /* in the form's order */
      var order = arr(p.fields).map(function (x) { return x.key; });
      rows.sort(function (a, b) { return order.indexOf(a.key) - order.indexOf(b.key); });
      if (!rows.length) {
        out.appendChild(el('p', 'muted', already ? 'The form already says everything that was found.' : 'The account told nothing to fill in - set the fields by hand.'));
        return;
      }
      var t = el('table', 'plain tight ct-discover-table');
      var hr = el('tr');
      ['', 'Field', 'Now in the form', 'From the account'].forEach(function (w) { hr.appendChild(el('th', '', w)); });
      t.appendChild(hr);
      rows.forEach(function (r) {
        var tr = el('tr');
        var c = document.createElement('input');
        c.type = 'checkbox';
        var cur = form.get(r.key);
        var fd = fieldsOf[r.key];
        var empty = blank(cur) || (fd['default'] !== undefined && same(cur, fd['default']));
        var cb = el('td');
        cb.appendChild(c);
        tr.appendChild(cb);
        tr.appendChild(td('', el('span', '', fd.label || r.key)));
        var nowCell = td('', blank(cur) ? el('span', 'muted', '–') : data('span', 'mono', text(cur)));
        tr.appendChild(nowCell);
        if (r.choice) {
          var sel = el('select', 'ct-discover-pick');
          noI18n(sel);
          var opts = arr(r.choice.options);
          var hasBlank = opts.some(function (x) { return x[0] === ''; });
          if (!hasBlank) {
            var o0 = document.createElement('option');
            o0.value = '\u0001';
            o0.textContent = tr_('– choose –');
            sel.appendChild(o0);
          }
          opts.forEach(function (x) {
            var op = document.createElement('option');
            op.value = x[0];
            op.textContent = x[0] === '' ? tr_(x[1]) : (x[1] + (x[1].indexOf(x[0]) < 0 ? ' · ' + x[0] : ''));
            sel.appendChild(op);
          });
          var pick = String(r.choice.pick || '');
          var known = opts.some(function (x) { return x[0] === pick; });
          sel.value = known ? pick : (hasBlank ? '' : '\u0001');
          r.get = function () { return sel.value; };
          c.checked = sel.value !== '\u0001' && !same(cur, sel.value) && (empty || blank(cur));
          if (same(cur, sel.value) && sel.value !== '\u0001') c.checked = false;
          sel.onchange = function () { c.checked = sel.value !== '\u0001' && !same(form.get(r.key), sel.value); };
          var cell = el('td');
          cell.appendChild(sel);
          cell.appendChild(el('div', 'muted small', opts.length + ' ' + tr_('in the account')));
          tr.appendChild(cell);
        } else {
          r.get = function () { return r.value; };
          c.checked = empty;
          tr.appendChild(td('', data('span', 'mono', text(r.value))));
          if (!empty) tr.classList.add('ct-discover-other');
        }
        r.box = c;
        t.appendChild(tr);
      });
      var tw = el('div', 'tablewrap');    /* scrolls on a phone (1.0.88), not the dialog */
      tw.style.overflowX = 'auto';
      tw.appendChild(t);
      out.appendChild(tw);
      if (rows.some(function (r) { return !r.box.checked && !r.choice; })) {
        out.appendChild(el('p', 'muted small', 'Unticked: the form has another value there - tick it to replace it.'));
      }
      var btns = el('div', 'btnrow');
      var put = cmdButton('Fill in the ticked ones', 'check', 'primary');
      put.onclick = function () { apply(rows); };
      btns.appendChild(put);
      out.appendChild(btns);
    }

    function apply(rows) {
      var did = [];
      /* what was typed in the popup goes into the form too (a secret typed there) */
      var s = sub.read();
      Object.keys(s).forEach(function (k) {
        var v = s[k];
        var f = fieldsOf[k] || {};
        if ((f.type === 'secret' || f.secret) && (blank(v) || String(v).charAt(0) === '•')) return;
        if (!same(form.get(k), v)) { form.set(k, v); did.push(k); }
      });
      rows.forEach(function (r) {
        if (!r.box.checked) return;
        var v = r.get();
        if (v === '\u0001') return;
        if (r.choice) {
          form.set(r.key, v, {options: r.choice.options, sets: r.choice.sets});
          var more = obj(obj(r.choice.sets)[v]);
          Object.keys(more).forEach(function (k) { if (fieldsOf[k] && form.set(k, more[k])) did.push(k); });
        } else form.set(r.key, v);
        did.push(r.key);
      });
      closeModal();
      if (!did.length) { toast('Nothing filled in', ''); return; }
      var uniq = did.filter(function (k, i) { return did.indexOf(k) === i; });
      toast(tr_('Filled in') + ': ' + uniq.map(function (k) { return tr_((fieldsOf[k] || {}).label || k); }).join(', ') + '. ' + tr_('Save to keep it.'), 'good');
    }
  }

  function tr_(w) {
    try { var got = typeof i18nText === 'function' ? i18nText(w) : null; return got || w; } catch (e) { return w; }
  }

  window.ACME_DISCOVER = discoverBar;
})();
