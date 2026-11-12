/* pushslots.js - the slots of an application of ours (acme push: otp, isemon, zigmon, acme)
   picked, not typed (1.0.90). The field "Slots" of the target acme_push says picker:
   'push_slots' (acmelib/plugins/targets/acme_push.py); certs.js's fieldForm hands it here
   (window.ACME_FIELD_TYPES.push_slots) instead of the box of lines.

   "Find the slots" asks the application what it has (POST /api/targets/push_discover - the
   same as the target's Discover: signed, read-only) and lists each slot with its names, what
   it has now and who looks after it; ticked ones are what the deployment puts the certificate
   into. Beside them the words the application knows by itself: auto (each slot whose names
   the certificate holds), nodes, vip, this. A slot ticked before and not there any more stays
   ticked and said; one the application does not answer for can be added by its id. The value
   is the same list of lines as before - the command line and the console type it. */
'use strict';
(function () {
  var WORDS = [
    ['auto', 'Automatically', 'each slot whose names the certificate holds'],
    ['nodes', 'Every node', 'the certificate of each node of the application'],
    ['vip', 'The VIP address', 'the address of the application\'s cluster'],
    ['this', 'This one', 'the node that answers at the address of the target']];
  var MANAGED = {'acme-push': 'from acme', manual: 'put in by hand', 'own-acme': 'its own ACME',
                 none: 'nothing yet'};

  function tr(w) {
    try { var got = typeof i18nText === 'function' ? i18nText(w) : null; return got || w; }
    catch (e) { return w; }
  }
  function arr(x) { return Array.isArray(x) ? x : []; }
  function day(ts) {
    if (!ts) return '';
    try { return typeof stamp === 'function' ? stamp(ts).split(' ')[0] : new Date(ts * 1000).toISOString().slice(0, 10); }
    catch (e) { return ''; }
  }

  function pushSlotsField(f, v, ctx) {
    ctx = ctx || {};
    var opts = ctx.opts || {};
    var row = opts.row || {};
    var picks = arr(Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/\n/) : []))
      .map(function (x) { return String(x).trim(); }).filter(Boolean);
    if (!picks.length && v === undefined) picks = ['auto'];
    var slots = null;           /* what the application said; null: not asked yet */
    var wrap = el('div', 'ps-wrap');
    var head = el('div', 'ps-head');
    var find = cmdButton('Find the slots', 'refresh', 'small');
    var said = el('span', 'muted small ps-said', row.name ? '' : 'Save the target first - then its slots can be asked for.');
    head.appendChild(find);
    head.appendChild(said);
    var list = el('div', 'ps-list');
    var own = el('div', 'ps-own');
    var ownBox = el('input', 'mono');
    ownBox.type = 'text';
    ownBox.placeholder = 'node:otp1';
    if (typeof noI18n === 'function') noI18n(ownBox);
    var ownAdd = cmdButton('Add', 'add', 'small');
    own.appendChild(el('span', 'muted small', 'Another slot by its id:'));
    own.appendChild(ownBox);
    own.appendChild(ownAdd);
    wrap.appendChild(head);
    wrap.appendChild(list);
    wrap.appendChild(own);

    function ticked(id) { return picks.indexOf(id) >= 0; }
    function tick(id, on) {
      var i = picks.indexOf(id);
      if (on && i < 0) picks.push(id);
      if (!on && i >= 0) picks.splice(i, 1);
      draw();
    }
    function line(id, title, sub, extra, off) {
      var r = el('label', 'ps-row' + (ticked(id) ? ' on' : '') + (off ? ' off' : ''));
      var box = el('input');
      box.type = 'checkbox';
      box.checked = ticked(id);
      box.onchange = function () { tick(id, box.checked); };
      r.appendChild(box);
      var txt = el('span', 'ps-txt');
      var t = el('span', 'ps-title');
      t.appendChild(el('b', '', title));
      var code = el('code', 'ps-id', id);
      if (typeof noI18n === 'function') noI18n(code);
      t.appendChild(code);
      txt.appendChild(t);
      if (sub) txt.appendChild(sub);
      r.appendChild(txt);
      if (extra) r.appendChild(extra);
      return r;
    }
    function draw() {
      clear(list);
      list.appendChild(el('div', 'ps-group', 'By what they are'));
      WORDS.forEach(function (w) {
        list.appendChild(line(w[0], w[1], el('span', 'muted small', w[2])));
      });
      list.appendChild(el('div', 'ps-group', 'The slots of the application'));
      if (slots === null) {
        list.appendChild(el('p', 'muted small ps-none', row.name ? 'Not asked yet - Find the slots asks the application.' : 'Not asked yet.'));
      } else if (!slots.length) {
        list.appendChild(el('p', 'muted small ps-none', 'The application has no slots to give.'));
      }
      arr(slots).forEach(function (s) {
        var sub = el('span', 'ps-sub');
        var names = el('span', 'ps-names', arr(s.names).join(', ') || tr('no name'));
        if (typeof noI18n === 'function') noI18n(names);
        sub.appendChild(names);
        var cur = s.current || {};
        var state = el('span', 'muted small');
        if (cur.not_after) {
          state.textContent = tr('has one until') + ' ' + day(cur.not_after) + ' · ' + tr(MANAGED[s.managed_by] || String(s.managed_by || ''));
        } else state.textContent = tr('nothing yet');
        sub.appendChild(state);
        var extra = null;
        var off = false;
        if (String(s.managed_by || '').indexOf('follows:') === 0) {
          extra = el('span', 'tag dim', tr('follows') + ' ' + s.managed_by.slice(8));
          off = true;
        } else if (s.installable === false) {
          extra = el('span', 'tag warn', s.why_not || 'cannot be put in');
          off = true;
        } else if (arr(s.covered_by).length) {
          extra = el('span', 'tag ok', tr('acme gives it') + ': ' + arr(s.covered_by).map(function (c) { return c.cert; }).join(', '));
        }
        list.appendChild(line(String(s.id), s.title || s.kind || String(s.id), sub, extra, off));
      });
      /* ticked before, not among them (or not asked yet): kept, and said */
      picks.filter(function (p) {
        return !WORDS.some(function (w) { return w[0] === p; }) &&
          !arr(slots).some(function (s) { return String(s.id) === p; });
      }).forEach(function (p) {
        list.appendChild(line(p, p, el('span', 'muted small', slots === null ? tr('chosen before') : tr('not there any more'))));
      });
      if (!picks.length) list.appendChild(el('p', 'bad small ps-none', 'Nothing chosen - choose at least one (Automatically: each slot whose names it holds).'));
    }
    function ask() {
      if (!row.name) return;
      busy(find, true);
      said.className = 'muted small ps-said';
      said.textContent = tr('asking the application…');
      ctx.capi('targets/push_discover', {name: row.name}, 120).then(function (d) {
        slots = arr(d.slots);
        said.textContent = (d.app || '') + (d.version ? ' ' + d.version : '') + ' · ' + tr(slots.length + ' slot(s)');
        draw();
      }).catch(function (e) {
        said.className = 'bad small ps-said';
        said.textContent = String((e && e.message) || e);
      }).then(function () { busy(find, false); });
    }
    find.onclick = ask;
    find.disabled = !row.name;
    ownAdd.onclick = function () {
      var id = ownBox.value.trim();
      if (!id) return;
      if (!/^[A-Za-z0-9_.:@-]{1,120}$/.test(id)) { toast('a slot\'s id is letters, digits and : . _ - @', 'bad'); return; }
      ownBox.value = '';
      tick(id, true);
    };
    ownBox.addEventListener('keydown', function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); ownAdd.onclick(); } });
    draw();
    /* a saved, paired target: asked by itself when the form opens */
    if (row.name) setTimeout(ask, 0);
    return {input: wrap, get: function () { return picks.slice(); },
            set: function (val) {
              picks = arr(Array.isArray(val) ? val : String(val || '').split(/\n/))
                .map(function (x) { return String(x).trim(); }).filter(Boolean);
              draw();
            }};
  }

  window.ACME_FIELD_TYPES = window.ACME_FIELD_TYPES || {};
  window.ACME_FIELD_TYPES.push_slots = pushSlotsField;
})();
