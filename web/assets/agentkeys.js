/* agentkeys.js - 1.0.140 (docs/target-agent.md "What the agent deploys", "Where keys are made"):

   * A1: the guard of an agent's policy (allow issuer, allow names, require key local) as a pill
     on the agent's tile and card - "Guards what it deploys: 2 issuers, 3 names, own key";
   * B7: Settings → Target agents, the card "Where keys are made": for each target with an agent,
     how many of the certificates deployed there have the key made on the server and how many
     acme's, which of acme's could switch (deployed there alone), `require key local` beside it;
     "Switch to a key made on the server…" for one or many - a dialog that says what happens
     (at the next renewal, or now).

   Drawn with the page's own pieces (core.js: el, cmdButton, modal, explain, toast) and the
   agents' classes (agents.css); what is its own is in agentkeys.css. Asks the daemon the way
   agents.js does (ACME_AGENTS.hands().capi). Nothing here changes anything until it is used. */
(function (root) {
'use strict';

var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
var MANAGE = ROLE === 'fulladmin' || ROLE === 'certadmin';

function arr(v) { return Array.isArray(v) ? v : []; }
function tr(w) { return typeof i18nText === 'function' ? (i18nText(w) || w) : w; }
function hands() { return (root.ACME_AGENTS && root.ACME_AGENTS.hands && root.ACME_AGENTS.hands()) || {}; }
function ask(path, body, wait) {
  var h = hands();
  if (!h.capi) return Promise.reject(new Error('the page is not ready'));
  return h.capi(path, body, wait);
}
var OWN = {cert: '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M7.5 8h9M7.5 11h4"/><circle cx="16" cy="15.5" r="2.5"/><path d="M14.8 17.6l-.8 3 2-1 2 1-.8-3"/>'};
function icon(key, size) {
  var s = noI18n(el('span', 'ag-ic'));
  s.innerHTML = OWN[key] ? '<svg viewBox="0 0 24 24" width="' + (size || 16) + '" height="' + (size || 16) + '" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + OWN[key] + '</svg>'
    : iconMarkup(key, size || 16);
  return s;
}
function mono(text, cls) { return noI18n(el('span', 'mono' + (cls ? ' ' + cls : ''), text)); }
function sep(t) { return noI18n(el('span', 'ak-sep', t)); }
function grouped(fp) { return String(fp || '').toUpperCase().replace(/(.{4})(?=.)/g, '$1 '); }
function day(ts) {
  if (!ts) return '–';
  var d = new Date(Number(ts) * 1000);
  return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
}
function many(n, one, more) { return n === 1 ? one : more.replace('{0}', n); }

/* ---- A1: the guard as a pill ------------------------------------------------------------------ */
function guardOf(a) {
  var p = (a && a.policy) || {};
  var g = {issuers: arr(p.issuers), names: arr(p.names), key_local: !!p.key_local};
  return g.issuers.length || g.names.length || g.key_local ? g : null;
}
/** Its parts, each a text of its own (each translated by itself). */
function guardParts(g, box) {
  var parts = [];
  if (g.issuers.length) parts.push([many(g.issuers.length, '1 issuer', '{0} issuers'), g.issuers.map(function (f) { return grouped(f.slice(0, 16)) + ' …'; }).join('\n')]);
  if (g.names.length) parts.push([many(g.names.length, '1 name', '{0} names'), g.names.slice(0, 30).join('\n') + (g.names.length > 30 ? '\n…' : '')]);
  if (g.key_local) parts.push(['own key', tr('only a key the agent made on the server (require key local)')]);
  parts.forEach(function (p, i) {
    if (i) box.appendChild(sep(', '));
    var s = el('span', 'ak-part', p[0]);
    explain(s, p[1]);
    box.appendChild(s);
  });
}
/** The tile's flag (Settings → Target agents). */
function flag(a, flags) {
  var g = guardOf(a);
  if (!g || !flags) return null;
  var f = el('span', 'ag-flag ok ak-flag');
  f.appendChild(icon('shield', 13));
  var w = el('span', 'ak-w');
  w.appendChild(el('span', '', 'guards what it deploys'));
  w.appendChild(sep(': '));
  guardParts(g, w);
  f.appendChild(w);
  flags.appendChild(f);
  return f;
}
/** The card's pill (the target's card) - or null when its policy has none of the lines. */
function pill(a) {
  var g = guardOf(a);
  if (!g) return null;
  var row = el('div', 'ak-guard');
  var p = el('span', 'ak-pill');
  p.appendChild(icon('shield', 14));
  var w = el('span', 'ak-w');
  w.appendChild(el('b', '', 'Guards what it deploys'));
  w.appendChild(sep(': '));
  guardParts(g, w);
  p.appendChild(w);
  row.appendChild(p);
  explain(p, tr('The agent checks every certificate itself before it writes anything - its issuer, its names, its key. A deployment it would refuse is not sent: acme says why.'));
  return row;
}

/* ---- B7: where keys are made -------------------------------------------------------------- */
var PICK = {};          /* certificate id -> true: picked to switch (kept while the page is open) */
function keyPill(c) {
  if (c.key === 'agent') return el('span', 'ak-k agent', 'made on the server');
  if (c.key === 'elsewhere') {
    var e = el('span', 'ak-k other', 'made by another device');
    explain(e, String(c.key_by || ''));
    return e;
  }
  return el('span', 'ak-k acme', 'acme’s key');
}
function stateOf(c, t) {
  if (c.key !== 'acme') return null;
  if (c.pending) return el('span', 'ak-s pending', 'switches at its next renewal');
  if (c.switchable && c.refused) return el('span', 'ak-s bad', 'refused by its policy - could switch');
  if (c.switchable) return el('span', 'ak-s could', 'could switch');
  var w = el('span', 'ak-s why', c.refused ? 'refused by its policy' : 'stays with acme');
  if (c.why) explain(w, String(c.why));
  return w;
}
function bar(n) {
  var tot = (n.agent || 0) + (n.acme || 0);
  var b = el('div', 'ak-bar');
  b.setAttribute('role', 'img');
  b.setAttribute('aria-label', tr('the key made on the server') + ': ' + (n.agent || 0) + ', ' + tr('acme’s key') + ': ' + (n.acme || 0));
  if (!tot) { b.classList.add('empty'); return b; }
  var a = el('span', 'ak-bar-a');
  a.style.width = (100 * (n.agent || 0) / tot) + '%';
  var s = el('span', 'ak-bar-s');
  s.style.width = (100 * (n.switchable || 0) / tot) + '%';
  var c = el('span', 'ak-bar-c');
  c.style.width = (100 * Math.max(0, (n.acme || 0) - (n.switchable || 0)) / tot) + '%';
  b.appendChild(a);
  b.appendChild(s);
  b.appendChild(c);
  return b;
}
function statTile(cls, ic, n, words) {
  var t = el('div', 'ak-stat ' + cls + (n ? '' : ' zero'));
  t.appendChild(icon(ic, 15));
  t.appendChild(noI18n(el('b', '', String(n || 0))));
  t.appendChild(el('span', '', words));
  return t;
}
function card(opts) {
  opts = opts || {};
  var box = el('section', 'ak-card');
  box.setAttribute('aria-label', tr('Where keys are made'));
  var h = el('div', 'ag-srv-h ak-h');
  h.appendChild(icon('key', 18));
  var hw = el('div', 'ak-h-w');
  hw.appendChild(el('h3', '', 'Where keys are made'));
  hw.appendChild(el('p', 'muted small', 'For each server with an agent: the certificates whose key the agent makes there - it never leaves the server - and those with acme’s key. A certificate deployed to one server alone can switch.'));
  h.appendChild(hw);
  box.appendChild(h);
  var body = el('div', 'ak-b');
  body.appendChild(el('p', 'muted small', 'Asking…'));
  box.appendChild(body);
  var last = null;
  function load() {
    return ask('agents/keyplace').then(function (x) { last = x || {}; draw(last); })
      .catch(function (e) { clear(body); body.appendChild(el('p', 'ct-bad', String((e && e.message) || e))); });
  }
  function picked() {
    var out = [];
    arr(last && last.targets).forEach(function (t) {
      arr(t.certs).forEach(function (c) { if (PICK[c.id] && c.switchable && !c.pending && c.may !== false) out.push({id: c.id, name: c.name, target: t.name}); });
    });
    return out;
  }
  function draw(x) {
    clear(body);
    var tg = arr(x.targets).filter(function (t) { return arr(t.certs).length; });
    var tot = x.totals || {};
    var stats = el('div', 'ak-stats');
    stats.appendChild(statTile('agent', 'key', tot.agent, 'the key made on the server'));
    stats.appendChild(statTile('acme', 'lock', tot.acme, 'acme’s key'));
    stats.appendChild(statTile('could', 'refresh', tot.switchable, 'could switch'));
    if (tot.pending) stats.appendChild(statTile('pending', 'clock', tot.pending, 'at the next renewal'));
    if (tot.refused) stats.appendChild(statTile('bad', 'ban', tot.refused, 'refused by require key local'));
    body.appendChild(stats);
    if (!tg.length) {
      body.appendChild(el('p', 'pb-empty ak-empty', 'No certificate is deployed to a server with an agent yet.'));
      return;
    }
    var list = el('div', 'ak-list');
    tg.forEach(function (t) { list.appendChild(targetBlock(t)); });
    body.appendChild(list);
    if (MANAGE) {
      var foot = el('div', 'btnrow ak-foot');
      var n = picked().length;
      var hint = el('span', 'muted small ak-foot-h', n ? many(n, '1 certificate picked', '{0} certificates picked') : 'Pick the certificates that could switch.');
      var go = cmdButton('Switch to a key made on the server…', 'key', 'primary small');
      go.disabled = !n;
      go.onclick = function () { switchDialog({items: picked(), done: function () { PICK = {}; load(); if (opts.reload) opts.reload(); }}); };
      foot.appendChild(hint);
      foot.appendChild(go);
      body.appendChild(foot);
    }
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(body);
  }
  function targetBlock(t) {
    var n = t.counts || {};
    var b = el('div', 'ak-t' + (t.key_local ? ' strict' : ''));
    var top = el('div', 'ak-t-top');
    var nm = el('button', 'ak-t-n');
    nm.type = 'button';
    nm.appendChild(noI18n(el('b', '', t.name)));
    nm.onclick = function () { var h = hands(); if (h.openTarget) h.openTarget(t.name); };
    top.appendChild(nm);
    if (t.platform === 'windows') top.appendChild(el('span', 'ak-tag', 'Windows'));
    if (t.key_local) {
      var kl = el('span', 'ak-tag strict');
      kl.appendChild(icon('shield', 12));
      kl.appendChild(mono('require key local'));
      explain(kl, tr('Its policy takes only a key the agent made: a certificate with acme’s key is refused there.'));
      top.appendChild(kl);
    }
    var cnt = el('span', 'ak-t-c');
    cnt.appendChild(el('span', 'ak-c agent', many(n.agent || 0, '1 made on the server', '{0} made on the server')));
    if (n.acme) cnt.appendChild(el('span', 'ak-c acme', many(n.acme, '1 with acme’s key', '{0} with acme’s key')));
    top.appendChild(cnt);
    b.appendChild(top);
    b.appendChild(bar(n));
    var rows = el('div', 'ak-rows');
    var could = arr(t.certs).filter(function (c) { return c.switchable && !c.pending && c.may !== false; });
    arr(t.certs).forEach(function (c) {
      var r = el('div', 'ak-r ' + c.key + (c.switchable ? ' could' : '') + (c.refused ? ' refused' : '') + (c.pending ? ' pending' : ''));
      var pickable = MANAGE && c.switchable && !c.pending && c.may !== false;
      var cb = el('input', 'ak-cb');
      cb.type = 'checkbox';
      cb.disabled = !pickable;
      cb.checked = !!(pickable && PICK[c.id]);
      cb.setAttribute('aria-label', tr('Pick') + ' ' + c.name);
      if (!MANAGE || c.key !== 'acme') cb.hidden = true;
      cb.onchange = function () { if (cb.checked) PICK[c.id] = true; else delete PICK[c.id]; draw(last); };
      r.appendChild(cb);
      var nm2 = noI18n(el('span', 'ak-r-n', c.name));
      r.appendChild(nm2);
      r.appendChild(keyPill(c));
      var s = stateOf(c, t);
      if (s) r.appendChild(s);
      var end = el('span', 'ak-r-d muted small');
      end.appendChild(el('span', '', 'until'));
      end.appendChild(sep(' '));
      end.appendChild(mono(day(c.not_after)));
      r.appendChild(end);
      if (MANAGE && c.pending && c.may !== false) {
        var un = cmdButton('Take back', 'undo', 'small ak-undo');
        un.onclick = function () {
          busy(un, true);
          ask('agents/keyplace/cancel', {ids: [c.id]}).then(function () { toast(tr('taken back'), 'good'); load(); })
            .catch(oops).then(function () { busy(un, false); });
        };
        r.appendChild(un);
      }
      rows.appendChild(r);
    });
    b.appendChild(rows);
    if (MANAGE && could.length > 1) {
      var all = cmdButton(could.every(function (c) { return PICK[c.id]; }) ? 'Pick none of them' : 'Pick all that could switch', 'check', 'small ak-all');
      all.onclick = function () {
        var every = could.every(function (c) { return PICK[c.id]; });
        could.forEach(function (c) { if (every) delete PICK[c.id]; else PICK[c.id] = true; });
        draw(last);
      };
      var br = el('div', 'btnrow');
      br.appendChild(all);
      b.appendChild(br);
    }
    if (n.hidden) b.appendChild(el('p', 'muted small', many(n.hidden, '1 certificate you may not see', '{0} certificates you may not see')));
    return b;
  }
  load();
  box.reload = load;
  return box;
}

/* ---- the dialog: Switch to a key made on the server ------------------------------------------- */
function switchDialog(o) {
  o = o || {};
  var items = arr(o.items);
  if (!items.length && arr(o.ids).length) items = arr(o.ids).map(function (id) { return {id: id, name: String(id), target: o.target || ''}; });
  if (!items.length) return;
  var when = 'next';
  modal(items.length === 1 ? 'Switch to a key made on the server' : 'Switch ' + items.length + ' certificates to a key made on the server', function (body) {
    var w = el('div', 'ak-dlg');
    var hero = el('div', 'ak-flow');
    var a = el('div', 'ak-flow-n acme');
    a.appendChild(icon('lock', 18));
    a.appendChild(el('b', '', 'acme'));
    a.appendChild(el('span', 'small', 'makes the key today'));
    hero.appendChild(a);
    var arrw = noI18n(el('span', 'ak-flow-ar', '→'));
    hero.appendChild(arrw);
    var s = el('div', 'ak-flow-n srv');
    s.appendChild(icon('key', 18));
    s.appendChild(el('b', '', 'the server'));
    s.appendChild(el('span', 'small', 'its agent makes the key - it never leaves it'));
    hero.appendChild(s);
    w.appendChild(hero);
    var steps = el('ol', 'ak-steps');
    [['key', 'The agent on the server makes a new key and sends acme only its CSR. acme never holds that key.'],
      ['cert', 'The certificate is issued for that key - at its next renewal, or now.'],
      ['shield', 'Its deployment puts the key into the files there: the agent builds the key file, a combined PEM or a PFX itself.'],
      ['undo', 'Until then nothing changes: the certificate deployed now stays, with acme’s key.']].forEach(function (x) {
      var li = el('li', '');
      li.appendChild(icon(x[0], 15));
      li.appendChild(el('span', '', x[1]));
      steps.appendChild(li);
    });
    w.appendChild(steps);
    var ch = el('div', 'ak-when');
    ch.setAttribute('role', 'radiogroup');
    ch.setAttribute('aria-label', tr('When'));
    [['next', 'At its next renewal', 'A day before it is due, acme switches it; the renewal then makes the key on the server. Nothing happens before.'],
      ['now', 'Now - and renew it now', 'Switched and renewed at once: the new certificate, with a key made on the server, is deployed in a few minutes.']].forEach(function (x) {
      var b = el('button', 'ak-when-b' + (when === x[0] ? ' on' : ''));
      b.type = 'button';
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', when === x[0] ? 'true' : 'false');
      var mk = noI18n(el('span', 'ak-when-mk'));
      b.appendChild(mk);
      var tw = el('span', 'ak-when-w');
      tw.appendChild(el('b', '', x[1]));
      tw.appendChild(el('span', 'small', x[2]));
      b.appendChild(tw);
      b.onclick = function () {
        when = x[0];
        Array.prototype.forEach.call(ch.children, function (c) { c.classList.remove('on'); c.setAttribute('aria-checked', 'false'); });
        b.classList.add('on');
        b.setAttribute('aria-checked', 'true');
      };
      b.onkeydown = function (e) {
        if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
          e.preventDefault();
          var other = b.nextSibling || b.previousSibling;
          if (other) { other.click(); other.focus(); }
        }
      };
      ch.appendChild(b);
    });
    w.appendChild(ch);
    var lh = el('div', 'ak-items-h');
    lh.appendChild(el('span', 'pb-k', items.length === 1 ? 'The certificate' : 'The certificates'));
    w.appendChild(lh);
    var list = el('div', 'ak-items');
    items.forEach(function (it) {
      var c = el('span', 'ak-item');
      c.appendChild(icon('cert', 13));
      c.appendChild(noI18n(el('b', '', it.name)));
      if (it.target) {
        c.appendChild(sep(' → '));
        c.appendChild(noI18n(el('span', 'ak-item-t', it.target)));
      }
      list.appendChild(c);
    });
    w.appendChild(list);
    w.appendChild(el('p', 'note small', 'Each certificate is checked as its form checks “Key made by the device”: deployed to that server alone, a source that signs a CSR, no twin. Those that cannot are said, and stay as they are.'));
    body.appendChild(w);
  }, [{words: 'Close', close: true},
    {words: 'Switch', cls: 'primary', icon: 'key', noConfirm: true, go: function (button) {
      busy(button, true);
      ask('agents/keyplace/switch', {ids: items.map(function (x) { return x.id; }), when: when}, 120).then(function (r) {
        var done = arr(r && r.done), bad = arr(r && r.refused);
        if (done.length) toast(when === 'now' ? tr('switched - renewing now: {0}').replace('{0}', done.map(function (x) { return x.name; }).join(', '))
          : tr('switches at its next renewal: {0}').replace('{0}', done.map(function (x) { return x.name; }).join(', ')), 'good');
        if (bad.length) toast(bad.map(function (x) { return x.name + ': ' + tr(x.why); }).join('\n'), 'bad');
        closeModal();
        if (o.done) o.done(r);
      }).catch(oops).then(function () { busy(button, false); });
    }}], 'ak-box');
}

root.ACME_AGENTKEYS = {flag: flag, pill: pill, card: card, switchDialog: switchDialog, guardOf: guardOf};
}(typeof window !== 'undefined' ? window : this));
