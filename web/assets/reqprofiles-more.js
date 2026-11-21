/* reqprofiles-more.js - Settings → Request profiles, 1.0.138 (docs/request-profiles.md), beside
   reqprofiles.js, which calls it through window.ACME_RP_MORE:
   - P1 the versions of a profile: a timeline, a diff of any two side by side, restore one
     (as a new version) - GET reqprofiles/versions, reqprofiles/diff, POST reqprofiles/restore;
   - P3 the compliance check: the CA/Browser Forum's schedule of the validity of public TLS
     certificates, the keys and algorithms and the company's own rules, on any date -
     GET reqprofiles/compliance, POST reqprofiles/rules;
   - P4 a dry run: what a profile would issue for these names or this CSR - POST reqprofiles/dryrun;
   - P5 a profile that ends: its successor, and which certificates move at their renewal -
     GET reqprofiles/impact, POST reqprofiles/ends.
   Drawn with teams.css's pieces (.tmx-*) and its own .rpm-* (reqprofiles.css). A full
   administrator changes; everybody signed in reads. */
'use strict';
(function () {
  var M = {d: null};
  var KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072',
                   'rsa-4096': 'RSA 4096', ed25519: 'Ed25519'};
  var EKU_WORDS = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
                   emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing'};
  var FIELD_WORDS = {O: 'Organisation', OU: 'Unit', L: 'City', ST: 'Region', C: 'Country', emailAddress: 'E-mail'};
  /* the fields of a version, as the diff names them */
  var LABELS = {name: 'Name', description: 'What it is for', enabled: 'Offered', base: 'Based on',
                inherit: 'Inherited from the base', issuer: 'Source', challenge: 'Names proved by',
                suffixes: 'Under these domains', wildcards: 'Wildcards', max_names: 'Names in one certificate',
                make_key: 'acme makes the key', csr: 'The person may send a CSR', key_types: 'Key types allowed',
                key_default: 'Offered first', auto_renew: 'Renew by itself', renew_days: 'Days before the end',
                days: 'Valid for (days)', eku: 'Used for', approval: 'Approved first', owner: 'Whose it is',
                owner_team: 'The team', tags: 'Tags', teams: 'Who may use it', pfx: 'PFX with the key',
                ends: 'Ends - its successor', source: 'Source'};
  var OWNER_WORDS = {person: 'the person who asks', team: 'a team they pick', fixed: 'this team'};
  var MODE_WORDS = {off: 'not used', fixed: 'fixed', person: 'filled by the person'};
  var CHANGE_WORDS = {key_type: 'Key type', issuer: 'Source', challenge: 'Names proved by', key_type_alt: 'Twin',
                      subject: 'Subject', eku: 'Used for', days: 'Valid for (days)', renew_days: 'Days before the end',
                      tags: 'Tags'};

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function low(s) { return String(s || '').trim().toLowerCase(); }
  function tr(s) {
    try { var got = typeof i18nText === 'function' ? i18nText(s) : null; return got || s; } catch (e) { return s; }
  }
  function ic(key, size, cls) {
    var s = el('span', 'tmx-ic' + (cls ? ' ' + cls : ''));
    s.innerHTML = iconMarkup(key, size || 16);
    return s;
  }
  function chip(words, cls, icon) {
    var c = el('span', 'tmx-chip' + (cls ? ' ' + cls : ''));
    if (icon) c.appendChild(ic(icon, 13));
    if (words instanceof Node) c.appendChild(words); else c.appendChild(el('span', '', words));
    return c;
  }
  function dataChip(words, cls, icon) { return chip(data('span', '', words), cls, icon); }
  /* words with a name in them: "{0}" replaced by the name as data, the rest translated */
  function said(pattern, value, cls) {
    var parts = tr(pattern).split('{0}');
    var s = el('span', cls || '');
    noI18n(s);
    s.appendChild(document.createTextNode(parts[0] || ''));
    s.appendChild(data('b', '', String(value)));
    if (parts.length > 1) s.appendChild(document.createTextNode(parts[1]));
    return s;
  }
  function initials(who) {
    var w = String(who || '').replace(/^(local|portal|profile):/i, '').replace(/@.*$/, '');
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
  function avatar(who) {
    var a = el('span', 'tmx-av rpm-av tmx-av-' + hue(who));
    a.appendChild(data('span', '', initials(who)));
    a.setAttribute('aria-hidden', 'true');
    return a;
  }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function dateOf(ts) {
    if (!ts) return '';
    var d = new Date(Number(ts) * 1000);
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  }
  function today() {
    var d = new Date();
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate());
  }
  function q(s) { return encodeURIComponent(String(s || '')); }
  function redraw() {
    if (window.ACME_EXTRA_PANES && ACME_EXTRA_PANES.reqprofiles) ACME_EXTRA_PANES.reqprofiles();
  }
  function profiles() { return ((M.d || {}).profiles) || []; }
  function profileOf(name) { return profiles().filter(function (x) { return low(x.name) === low(name); })[0] || null; }
  function labelOf(k) {
    if (k.indexOf('subject.') === 0) return el('span', '', FIELD_WORDS[k.slice(8)] || k.slice(8));
    return el('span', '', LABELS[k] || k);
  }
  /* a value of a version, drawn: lists as chips, yes / no, an inherited field as such */
  function valueOf(k, v, cls) {
    var box = el('div', 'rpm-val' + (cls ? ' ' + cls : ''));
    if (v && typeof v === 'object' && !Array.isArray(v) && v.inherited !== undefined) {
      box.appendChild(said('inherited from {0}', v.inherited || '?', 'rpm-inhv'));
      return box;
    }
    if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length)) {
      box.appendChild(el('span', 'muted', k === 'teams' ? 'anybody who may sign in' : 'none'));
      return box;
    }
    if (typeof v === 'boolean') {
      box.appendChild(chip(v ? 'yes' : 'no', v ? 'ok' : 'dim', v ? 'check' : 'ban'));
      return box;
    }
    if (k === 'inherit' && Array.isArray(v)) {
      v.forEach(function (g) { box.appendChild(chip(labelOf(g.indexOf('subject.') === 0 ? g : (g === 'source' ? 'issuer' : g)), 'dim')); });
      return box;
    }
    if (Array.isArray(v)) {
      v.forEach(function (x) {
        var w = k === 'key_types' ? KEY_WORDS[x] || x : k === 'eku' ? EKU_WORDS[x] || x : x;
        box.appendChild(k === 'eku' ? chip(w, 'dim') : dataChip(w, 'dim' + (k === 'suffixes' ? ' mono' : '')));
      });
      return box;
    }
    if (k === 'owner') { box.appendChild(el('span', '', OWNER_WORDS[v] || v)); return box; }
    if (k === 'key_default') { box.appendChild(data('span', '', KEY_WORDS[v] || v)); return box; }
    if (k.indexOf('subject.') === 0) {
      var m = /^(\w+)(?::\s?(.*))?$/.exec(String(v)) || [0, v, ''];
      box.appendChild(chip(MODE_WORDS[m[1]] || m[1], m[1] === 'off' ? 'dim' : 'info'));
      if (m[2]) box.appendChild(data('span', 'rpm-sv', m[2]));
      return box;
    }
    box.appendChild(data('span', typeof v === 'number' ? 'rpm-num' : '', String(v)));
    return box;
  }
  function apiGet(what) { return api(what); }

  /* ---- hooks of reqprofiles.js ------------------------------------------------- */
  function bar(right, d) {
    M.d = d;
    var b = cmdButton('Compliance', 'shield', 'small');
    b.id = 'rpm-comply';
    explain(b, 'Each profile and the certificates asked for from it against the CA/Browser Forum\'s schedule of public TLS validity, the keys and algorithms, and the company\'s own rules - on any date.');
    b.onclick = function () { compliance(); };
    right.appendChild(b);
  }
  function chips(nm, p) {
    if (p.base) nm.appendChild(said('based on {0}', p.base, 'tmx-chip info rpm-basechip'));
    if (p.ends) {
      var e = said('ends → {0}', p.ends.successor || '?', 'tmx-chip warn rpm-endchip');
      nm.appendChild(e);
    }
    if ((p.children || []).length) nm.appendChild(chip(num(p.children.length) + ' based on it', 'violet', 'people'));
  }
  function actions(p, small) {
    var out = [];
    var h = el('button', 'rpm-act rpm-hist');
    h.type = 'button';
    h.appendChild(ic('history', 14));
    h.appendChild(el('span', '', 'History'));
    h.appendChild(data('span', 'rpm-v', 'v' + (p.version || 1)));
    h.setAttribute('aria-label', tr('History') + ' - ' + tr('version {0}').replace('{0}', p.version || 1));
    h.onclick = function (e) { e.stopPropagation(); history(p); };
    out.push(h);
    var t = el('button', 'rpm-act rpm-try');
    t.type = 'button';
    t.appendChild(ic('play', 14));
    t.appendChild(el('span', '', 'Dry run'));
    t.onclick = function (e) { e.stopPropagation(); dryRun(p); };
    out.push(t);
    if (full() || p.ends) {
      var x = el('button', 'rpm-act rpm-end' + (p.ends ? ' on' : ''));
      x.type = 'button';
      x.appendChild(ic('flag', 14));
      x.appendChild(el('span', '', p.ends ? 'Ends' : 'End it…'));
      x.onclick = function (e) { e.stopPropagation(); ending(p); };
      out.push(x);
    }
    return out;
  }
  function foot(f, p) {
    f.classList.add('rpm-foot');
    var g = el('div', 'rpm-acts');
    actions(p).forEach(function (b) { g.appendChild(b); });
    f.appendChild(g);
  }
  function rowActs(cell, p) {
    var g = el('div', 'rpm-acts rpm-racts');
    actions(p).forEach(function (b) { g.appendChild(b); });
    cell.appendChild(g);
  }

  /* ---- P1: the versions ----------------------------------------------------------- */
  function history(p) {
    apiGet('reqprofiles/versions&name=' + q(p.name)).then(function (d) {
      modal('History of the request profile', function (body) {
        body.classList.add('tmx-dlg', 'rpm-dlg');
        var head = el('div', 'rpm-head');
        head.appendChild(ic('history', 20, 'rpm-hic'));
        var hw = el('div', 'rpm-head-w');
        hw.appendChild(data('b', 'rpm-head-n', d.profile));
        hw.appendChild(said('version {0} now', d.current, 'muted small'));
        head.appendChild(hw);
        body.appendChild(head);
        var vs = d.versions || [];
        /* compare any two */
        if (vs.length > 1) {
          var cmp = el('div', 'rpm-cmp');
          var pairs = vs.map(function (v) { return [String(v.version), tr('version {0}').replace('{0}', v.version)]; });
          var a = selectBox(pairs, String(vs[1].version));
          var b = selectBox(pairs, String(vs[0].version));
          a.id = 'rpm-cmp-a';
          b.id = 'rpm-cmp-b';
          noI18n(a);
          noI18n(b);
          a.setAttribute('aria-label', tr('Compare'));
          b.setAttribute('aria-label', tr('with'));
          cmp.appendChild(el('span', 'rpm-cmp-l', 'Compare'));
          cmp.appendChild(a);
          cmp.appendChild(el('span', 'rpm-cmp-l', 'with'));
          cmp.appendChild(b);
          var go = cmdButton('Show the differences', 'eye', 'small primary');
          go.id = 'rpm-cmp-go';
          go.onclick = function () { showDiff(d.profile, a.value, b.value); };
          cmp.appendChild(go);
          body.appendChild(cmp);
        }
        var tl = el('ol', 'rpm-tl');
        tl.setAttribute('aria-label', tr('Versions'));
        vs.forEach(function (v, i) {
          var it = el('li', 'rpm-tl-it' + (i === 0 ? ' now' : ''));
          it.dataset.version = v.version;
          var dot = el('div', 'rpm-tl-dot');
          dot.appendChild(data('span', '', 'v' + v.version));
          it.appendChild(dot);
          var w = el('div', 'rpm-tl-w');
          var top = el('div', 'rpm-tl-top');
          top.appendChild(avatar(v.by));
          var who = el('div', 'rpm-tl-who');
          who.appendChild(data('b', '', String(v.by || '?').replace(/^local:/, '')));
          var when = data('span', 'muted small', v.at ? stamp(v.at) : '');
          who.appendChild(when);
          top.appendChild(who);
          if (i === 0) top.appendChild(chip('now', 'ok', 'check'));
          if (v.certs) top.appendChild(chip(num(v.certs) + ' certificate(s)', 'dim', 'lock'));
          w.appendChild(top);
          if (v.why) w.appendChild(el('div', 'rpm-tl-why', whyWords(v.why)));
          if ((v.changes || []).length) {
            var ch = el('div', 'rpm-tl-ch');
            ch.appendChild(el('span', 'rpm-tl-chl', 'Changed'));
            v.changes.forEach(function (k) { ch.appendChild(chip(labelOf(k), 'info')); });
            w.appendChild(ch);
          }
          var acts = el('div', 'rpm-tl-acts');
          var next = vs[i + 1];
          if (next) {
            var dd = cmdButton('What changed', 'eye', 'small');
            dd.classList.add('rpm-what');
            dd.onclick = function () { showDiff(d.profile, String(next.version), String(v.version)); };
            acts.appendChild(dd);
          }
          if (i > 0) {
            var vn = cmdButton('Compare with now', 'list', 'small');
            vn.onclick = function () { showDiff(d.profile, String(v.version), 'now'); };
            acts.appendChild(vn);
          }
          if (i > 0 && full() && !v.unsaved) {
            var rs = cmdButton('Restore it', 'undo', 'small');
            rs.classList.add('rpm-restore');
            rs.onclick = function () { restore(d.profile, v.version); };
            acts.appendChild(rs);
          }
          if (acts.children.length) w.appendChild(acts);
          it.appendChild(w);
          tl.appendChild(it);
        });
        body.appendChild(tl);
        if (vs.length === 1 && vs[0].unsaved) body.appendChild(el('p', 'note', 'Not changed since versions are kept: its next change is version 2.'));
      }, [{words: 'Close', close: true}], 'large');
    }).catch(oops);
  }
  /* why a version was made, in the words the daemon wrote them (patterns translate the names) */
  function whyWords(w) {
    var m = /^restored from version (\d+)$/.exec(w);
    if (m) return tr('restored from version {0}').replace('{0}', m[1]);
    return w;
  }
  function showDiff(name, a, b) {
    apiGet('reqprofiles/diff&name=' + q(name) + '&a=' + q(a) + '&b=' + q(b)).then(function (d) {
      var back = function () { history(profileOf(name) || {name: name}); };
      modalOver(function () {
        modal('The differences', function (body) {
          body.classList.add('tmx-dlg', 'rpm-dlg');
          var head = el('div', 'rpm-dhead');
          var va = el('span', 'rpm-vb a');
          va.appendChild(data('span', '', a === 'now' ? tr('now') : 'v' + a));
          var vb = el('span', 'rpm-vb b');
          vb.appendChild(data('span', '', b === 'now' ? tr('now') : 'v' + b));
          head.appendChild(data('b', 'rpm-head-n', d.profile));
          head.appendChild(va);
          head.appendChild(ic('next', 16, 'rpm-arrow'));
          head.appendChild(vb);
          var n = (d.changes || []).length;
          head.appendChild(chip(n ? num(n) + ' change(s)' : 'the same', n ? 'info' : 'ok'));
          body.appendChild(head);
          var grid = el('div', 'rpm-diff');
          grid.setAttribute('role', 'table');
          var hr = el('div', 'rpm-dr rpm-dh');
          hr.setAttribute('role', 'row');
          ['Field', a === 'now' ? 'now' : 'version ' + a, b === 'now' ? 'now' : 'version ' + b].forEach(function (w, i) {
            var c = el('div', 'rpm-dc' + (i ? ' v' : ''), w);
            c.setAttribute('role', 'columnheader');
            hr.appendChild(c);
          });
          grid.appendChild(hr);
          var same = [];
          var byKey = {};
          (d.changes || []).forEach(function (c) { byKey[c.key] = c; });
          (d.rows || []).forEach(function (r) {
            var line = el('div', 'rpm-dr' + (r.same ? ' same' : ' diff'));
            line.setAttribute('role', 'row');
            line.dataset.key = r.key;
            var k = el('div', 'rpm-dc k');
            k.setAttribute('role', 'rowheader');
            k.appendChild(labelOf(r.key));
            line.appendChild(k);
            var c = byKey[r.key];
            var ca = el('div', 'rpm-dc v a');
            ca.setAttribute('role', 'cell');
            ca.dataset.side = tr('before');
            var cb = el('div', 'rpm-dc v b');
            cb.setAttribute('role', 'cell');
            cb.dataset.side = tr('after');
            if (c && c.added) {
              /* a list: what went struck out on the left, what came in green on the right */
              ca.appendChild(listDiff(r.key, r.a, c.removed, 'gone'));
              cb.appendChild(listDiff(r.key, r.b, c.added, 'new'));
            } else {
              ca.appendChild(valueOf(r.key, r.a, r.same ? '' : 'old'));
              cb.appendChild(valueOf(r.key, r.b, r.same ? '' : 'new'));
            }
            line.appendChild(ca);
            line.appendChild(cb);
            if (r.same) { line.hidden = true; same.push(line); }
            grid.appendChild(line);
          });
          body.appendChild(grid);
          if (same.length) {
            var t = el('button', 'btn cmd small rpm-same');
            t.type = 'button';
            var tw = data('span', '', '');
            t.appendChild(ic('unfold', 14));
            t.appendChild(tw);
            var open = false;
            var paint = function () {
              tw.textContent = tr(open ? 'Hide the {0} fields that are the same' : 'Show the {0} fields that are the same').replace('{0}', same.length);
              t.setAttribute('aria-expanded', open ? 'true' : 'false');
            };
            paint();
            t.onclick = function () { open = !open; same.forEach(function (x) { x.hidden = !open; }); paint(); };
            body.appendChild(t);
          }
        }, [{words: 'Close', close: true}], 'large');
      }, back);
    }).catch(oops);
  }
  function listDiff(k, all, marked, how) {
    var box = el('div', 'rpm-val');
    if (all && typeof all === 'object' && !Array.isArray(all)) return valueOf(k, all);
    (all || []).forEach(function (x) {
      var w = k === 'key_types' ? KEY_WORDS[x] || x : k === 'eku' ? EKU_WORDS[x] || x : x;
      var hit = (marked || []).indexOf(x) >= 0;
      var c = k === 'eku' ? chip(w, hit ? how : 'dim') : dataChip(w, (hit ? how : 'dim') + (k === 'suffixes' ? ' mono' : ''));
      if (hit) c.classList.add('rpm-' + how);
      box.appendChild(c);
    });
    if (!(all || []).length) box.appendChild(el('span', 'muted', k === 'teams' ? 'anybody who may sign in' : 'none'));
    return box;
  }
  function restore(name, n) {
    modalOver(function () {
      modal('Restore a version', function (body) {
        var p = el('p', '');
        p.appendChild(said('The request profile will be as version {0} said - saved as a new version, so nothing is lost. Its name, and whether it ends, stay as they are now.', n));
        body.appendChild(p);
      }, [{words: 'No, leave it', close: true},
          {words: 'Restore it', cls: 'primary', icon: 'undo', go: function (b) {
            busy(b, true);
            api('reqprofiles/restore', {name: name, version: n}).then(function () {
              toast('The version is restored', 'good');
              closeModal();
              closeModal();
              redraw();
            }).catch(function (e) { busy(b, false); oops(e); });
          }}], true);
    }, function () { history(profileOf(name) || {name: name}); });
  }

  /* ---- P4: a dry run ---------------------------------------------------------------- */
  function dryRun(p) {
    var f = {};
    modal('Dry run', function (body) {
      body.classList.add('tmx-dlg', 'rpm-dlg');
      var head = el('div', 'rpm-head');
      head.appendChild(ic('play', 20, 'rpm-hic'));
      var hw = el('div', 'rpm-head-w');
      hw.appendChild(data('b', 'rpm-head-n', p.name));
      hw.appendChild(el('span', 'muted small', 'What it would issue - nothing is issued, asked of a CA or kept.'));
      head.appendChild(hw);
      body.appendChild(head);
      var form = el('div', 'rpm-form');
      var useCsr = !!p.csr && !p.make_key;
      if (p.csr && p.make_key) {
        f.how = el('div', 'tmx-seg small');
        f.how.setAttribute('role', 'radiogroup');
        f.how.setAttribute('aria-label', tr('How'));
        [['names', 'Names', 'globe'], ['csr', 'A CSR', 'key']].forEach(function (x) {
          var b = el('button', 'tmx-segb' + (x[0] === 'names' ? ' on' : ''));
          b.type = 'button';
          b.dataset.v = x[0];
          b.setAttribute('role', 'radio');
          b.setAttribute('aria-checked', x[0] === 'names' ? 'true' : 'false');
          b.appendChild(ic(x[2], 14));
          b.appendChild(el('span', '', x[1]));
          b.onclick = function () {
            f.how.querySelectorAll('.tmx-segb').forEach(function (o) { o.classList.toggle('on', o === b); o.setAttribute('aria-checked', o === b ? 'true' : 'false'); });
            useCsr = x[0] === 'csr';
            paint();
          };
          f.how.appendChild(b);
        });
        form.appendChild(field('How', f.how));
      }
      f.names = textBox('', 'www.' + ((p.suffixes || [])[0] || 'example.com'), 'mono');
      f.names.id = 'rpm-dr-names';
      noI18n(f.names);
      f.namesRow = field('Names', f.names, tr('At most {0}, under: ').replace('{0}', p.max_names || 1) + (p.suffixes || []).join(', '));
      form.appendChild(f.namesRow);
      f.csr = el('textarea', 'mono rpm-csr');
      f.csr.rows = 5;
      f.csr.id = 'rpm-dr-csr';
      f.csr.placeholder = '-----BEGIN CERTIFICATE REQUEST-----';
      noI18n(f.csr);
      f.csrRow = field('The CSR', f.csr);
      form.appendChild(f.csrRow);
      f.kt = selectBox((p.key_types || []).map(function (k) { return [k, KEY_WORDS[k] || k]; }), p.key_default);
      f.kt.id = 'rpm-dr-kt';
      noI18n(f.kt);
      f.ktRow = field('Key type', f.kt);
      form.appendChild(f.ktRow);
      f.subj = {};
      Object.keys(p.subject || {}).forEach(function (k) {
        var s = p.subject[k];
        if (!s || s.mode !== 'person') return;
        var t = textBox(s.value || '', '', '');
        t.id = 'rpm-dr-s-' + k;
        noI18n(t);
        f.subj[k] = t;
        form.appendChild(field(FIELD_WORDS[k] || k, t));
      });
      if (p.owner === 'team') {
        var teams = (p.teams || []).length ? p.teams : (((M.d || {}).options || {}).teams || []);
        f.team = selectBox([['', tr('choose a team')]].concat(teams.map(function (t) { return [t, t]; })), teams[0] || '');
        f.team.id = 'rpm-dr-team';
        noI18n(f.team);
        form.appendChild(field('The team', f.team));
      }
      body.appendChild(form);
      var res = el('div', 'rpm-res');
      res.id = 'rpm-dr-res';
      res.setAttribute('aria-live', 'polite');
      body.appendChild(res);
      f.res = res;
      var paint = function () {
        f.namesRow.hidden = useCsr;
        f.ktRow.hidden = useCsr;
        f.csrRow.hidden = !useCsr;
        Object.keys(f.subj).forEach(function (k) { f.subj[k].closest('.rpm-field').hidden = useCsr; });
      };
      f.useCsr = function () { return useCsr; };
      paint();
      f.names.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); run(); } });
    }, [{words: 'Close', close: true},
        {words: 'Try it', cls: 'primary', icon: 'play', go: function (b) { run(b); }}], 'large');
    function field(label, ctl, hint) {
      var r = el('div', 'rpm-field');
      var l = el('label', 'rpm-fl', label);
      if (ctl.id) l.htmlFor = ctl.id;
      else { l.id = 'rpm-l-' + Math.random().toString(36).slice(2); ctl.setAttribute('aria-labelledby', l.id); }
      r.appendChild(l);
      r.appendChild(ctl);
      if (hint) { var h = el('div', 'muted small rpm-fh'); h.appendChild(document.createTextNode(hint)); noI18n(h); r.appendChild(h); }
      return r;
    }
    function run(b) {
      var body = {profile: p.name};
      if (f.useCsr()) body.csr = f.csr.value;
      else {
        body.names = f.names.value.split(/[\s,;]+/).filter(Boolean);
        body.key_type = f.kt.value;
        body.subject = {};
        Object.keys(f.subj).forEach(function (k) { body.subject[k] = f.subj[k].value; });
      }
      if (f.team) body.team = f.team.value;
      if (b) busy(b, true);
      api('reqprofiles/dryrun', body).then(function (d) { drawResult(f.res, d); })
        .catch(function (e) { clear(f.res); var n = el('div', 'tmx-note warn'); n.appendChild(ic('info', 16)); n.appendChild(el('span', '', String(e.message || e))); f.res.appendChild(n); })
        .then(function () { if (b) busy(b, false); });
    }
  }
  function kv(list, label, icon, value) {
    var r = el('div', 'rpm-kv');
    var k = el('div', 'rpm-kv-k');
    k.appendChild(ic(icon, 13));
    k.appendChild(el('span', '', label));
    r.appendChild(k);
    var v = el('div', 'rpm-kv-v');
    (Array.isArray(value) ? value : [value]).forEach(function (x) { if (x) v.appendChild(x instanceof Node ? x : el('span', '', x)); });
    r.appendChild(v);
    list.appendChild(r);
  }
  function drawResult(host, d) {
    clear(host);
    var verdict = el('div', 'rpm-verdict ' + (d.fits ? 'ok' : 'bad'));
    verdict.appendChild(ic(d.fits ? 'check' : 'ban', 20));
    var vw = el('div', '');
    vw.appendChild(el('b', '', d.fits ? 'It would be issued' : 'It would be refused'));
    if (d.fits) vw.appendChild(el('span', '', d.approval.waits ? 'after an approval' : 'at once'));
    verdict.appendChild(vw);
    host.appendChild(verdict);
    if (!d.fits) {
      var ul = el('ul', 'rpm-why');
      (d.refused || []).forEach(function (w) { ul.appendChild(el('li', '', w)); });
      host.appendChild(ul);
    }
    /* the certificate, as it would be */
    var c = el('div', 'rpm-cert');
    var ch = el('div', 'rpm-cert-h');
    ch.appendChild(ic('lock', 22, 'rpm-cert-ic'));
    var cw = el('div', '');
    cw.appendChild(data('b', 'rpm-cert-cn', d.cn || '–'));
    var from = el('div', 'muted small');
    from.appendChild(said('from {0}', d.profile + ' v' + d.version));
    cw.appendChild(from);
    ch.appendChild(cw);
    c.appendChild(ch);
    var list = el('div', 'rpm-kvs');
    var dn = el('div', 'rpm-dn');
    (d.subject || []).forEach(function (x) {
      var line = el('div', 'rpm-dn-l');
      line.appendChild(data('span', 'rpm-dn-k', x[0]));
      line.appendChild(data('span', 'rpm-dn-v', x[1]));
      dn.appendChild(line);
    });
    kv(list, 'Subject', 'person', dn);
    kv(list, 'Names', 'globe', (d.sans || []).map(function (n) { return dataChip(n, 'info mono'); }));
    kv(list, 'Key', 'key', [dataChip(KEY_WORDS[d.key.type] || d.key.type || '–', 'dim'),
      chip(d.key.by === 'csr' ? 'from the CSR - acme never has it' : 'made and kept by acme', d.key.by === 'csr' ? 'violet' : 'dim')]);
    kv(list, 'Used for', 'check', (d.eku || []).length ? d.eku.map(function (e) { return chip(EKU_WORDS[e] || e, 'dim'); })
      .concat(d.eku_by === 'the CA' ? [el('span', 'muted small', 'as the CA puts it in')] : [])
      : [el('span', 'muted', 'as the source puts it in')]);
    var val = [];
    if (d.validity.days) {
      val.push(chip(num(d.validity.days) + ' days', 'info', 'clock'));
      if (d.validity.until) val.push(said('until about {0}', dateOf(d.validity.until), 'muted small'));
    } else val.push(el('span', 'muted', 'what the CA gives'));
    if (d.validity.limit) val.push(said('a public certificate: at most {0} days now', d.validity.limit, 'muted small'));
    kv(list, 'Valid for', 'clock', val);
    var src = [dataChip(d.issuer || '–', 'info', 'in')];
    if (d.public) src.push(chip('public', 'info', 'globe'));
    if (d.challenge) src.push(dataChip(d.challenge, 'violet', 'shield'));
    kv(list, 'Source', 'in', src);
    var ap = [chip(d.approval.waits ? 'waits for approval' : 'issued at once', d.approval.waits ? 'warn' : 'ok', d.approval.waits ? 'clock' : 'check')];
    if (d.approval.approver) { var aw = el('div', 'rpm-apw'); aw.appendChild(el('span', '', d.approval.approver)); ap.push(aw); }
    (d.approval.why || []).forEach(function (w) { if (w !== d.approval.approver) { var x = el('div', 'muted small'); x.appendChild(el('span', '', w)); ap.push(x); } });
    kv(list, 'Approval', 'check', ap);
    kv(list, 'Whose it is', 'people', d.owner.name ? [dataChip(d.owner.name, 'info', d.owner.mode === 'person' ? 'person' : 'people')]
      : [el('span', '', OWNER_WORDS[d.owner.mode] || d.owner.mode)]);
    kv(list, 'Tags', 'pin', (d.tags || []).map(function (t) { return dataChip(t, 'dim'); }));
    kv(list, 'Renewal', 'refresh', [chip(d.renew.auto ? 'renews by itself' : 'not by itself', d.renew.auto ? 'ok' : 'dim'),
      d.renew.days ? chip(num(d.renew.days) + ' days before the end', 'dim') : null]);
    if (d.pfx) kv(list, 'PFX with the key', 'download', [chip('may be downloaded', 'warn')]);
    c.appendChild(list);
    host.appendChild(c);
    var fs = (d.findings || []).filter(function (x) { return x.level !== 'info'; });
    if (fs.length) host.appendChild(findingList(fs));
  }

  /* ---- P5: a profile that ends ---------------------------------------------------- */
  function ending(p) {
    var others = profiles().filter(function (x) { return low(x.name) !== low(p.name) && !x.ends; });
    var f = {};
    modal(p.ends ? 'The request profile ends' : 'End the request profile', function (body) {
      body.classList.add('tmx-dlg', 'rpm-dlg');
      var head = el('div', 'rpm-head');
      head.appendChild(ic('flag', 20, 'rpm-hic warn'));
      var hw = el('div', 'rpm-head-w');
      hw.appendChild(data('b', 'rpm-head-n', p.name));
      hw.appendChild(el('span', 'muted small', 'Ended, the portal no longer offers it; each certificate asked for from it takes its successor\'s settings at its next renewal. It can be taken back.'));
      head.appendChild(hw);
      body.appendChild(head);
      if (p.ends) {
        var n = el('div', 'tmx-note warn rpm-endsnote');
        n.appendChild(ic('flag', 16));
        var w = el('span', '');
        w.appendChild(said('It ends: its successor is {0}', p.ends.successor));
        if (p.ends.since) { w.appendChild(document.createTextNode(' · ')); w.appendChild(data('span', '', stamp(p.ends.since))); }
        if (p.ends.by) { w.appendChild(document.createTextNode(' · ')); w.appendChild(data('span', '', p.ends.by)); }
        n.appendChild(w);
        body.appendChild(n);
        if (p.ends.note) body.appendChild(data('p', 'note', p.ends.note));
      } else if (full()) {
        f.succ = selectBox([['', tr('choose its successor')]].concat(others.map(function (x) { return [x.name, x.name]; })), '');
        f.succ.id = 'rpm-succ';
        noI18n(f.succ);
        var r1 = el('div', 'rpm-field');
        var l1 = el('label', 'rpm-fl', 'Its successor');
        l1.htmlFor = f.succ.id;
        r1.appendChild(l1);
        r1.appendChild(f.succ);
        body.appendChild(r1);
        f.note = el('textarea', 'rpm-note');
        f.note.rows = 2;
        f.note.id = 'rpm-endnote';
        f.note.placeholder = tr('Why - shown to the administrators');
        noI18n(f.note);
        var r2 = el('div', 'rpm-field');
        var l2 = el('label', 'rpm-fl', 'A note');
        l2.htmlFor = f.note.id;
        r2.appendChild(l2);
        r2.appendChild(f.note);
        body.appendChild(r2);
        f.succ.onchange = function () { impact(p.name, f.succ.value); };
      }
      var h = el('h3', 'tmx-sec-h rpm-sh');
      h.appendChild(ic('lock', 16));
      h.appendChild(el('span', '', 'The certificates it moves'));
      body.appendChild(h);
      f.imp = el('div', 'rpm-imp');
      f.imp.id = 'rpm-imp';
      f.imp.setAttribute('aria-live', 'polite');
      body.appendChild(f.imp);
      var impact = function (name, succ) {
        clear(f.imp);
        if (!succ && !p.ends) { f.imp.appendChild(el('p', 'muted', 'Choose its successor to see what moves.')); return; }
        f.imp.appendChild(el('p', 'muted', 'Asking…'));
        apiGet('reqprofiles/impact&name=' + q(name) + (succ ? '&successor=' + q(succ) : '')).then(function (d) { drawImpact(f.imp, d); }).catch(oops);
      };
      impact(p.name, p.ends ? '' : '');
    }, p.ends ? [{words: 'Close', close: true}].concat(full() ? [{words: 'Offer it again', cls: 'primary', icon: 'undo', go: function (b) {
        busy(b, true);
        api('reqprofiles/ends', {name: p.name, undo: true}).then(function () { toast('The request profile is offered again', 'good'); closeModal(); redraw(); })
          .catch(function (e) { busy(b, false); oops(e); });
      }}] : []) : [{words: 'Close', close: true},
        {words: 'End it', cls: 'primary', icon: 'flag', go: function (b) {
          if (!f.succ || !f.succ.value) { toast('choose its successor among the request profiles', 'bad'); if (f.succ) f.succ.focus(); return; }
          busy(b, true);
          api('reqprofiles/ends', {name: p.name, successor: f.succ.value, note: f.note.value}).then(function () {
            toast('The request profile ends', 'good');
            closeModal();
            redraw();
          }).catch(function (e) { busy(b, false); oops(e); });
        }}], 'large');
  }
  function drawImpact(host, d) {
    clear(host);
    var tiles = el('div', 'rpm-tiles');
    tiles.appendChild(tile('Certificates', d.certs.length, 'lock', ''));
    if (d.successor) {
      tiles.appendChild(tile('Move at their renewal', d.moves, 'next', 'ok'));
      tiles.appendChild(tile('Cannot move', d.stays, 'ban', d.stays ? 'crit' : ''));
    }
    host.appendChild(tiles);
    if (!d.certs.length) { host.appendChild(el('p', 'muted', 'No certificate was asked for from it - nothing moves.')); return; }
    var list = el('ul', 'rpm-ilist');
    d.certs.forEach(function (c) {
      var li = el('li', 'rpm-ii' + (c.moves === false ? ' stays' : c.moves ? ' moves' : ''));
      var top = el('div', 'rpm-ii-t');
      top.appendChild(ic(c.moves === false ? 'ban' : c.moves ? 'check' : 'lock', 15, 'rpm-ii-ic'));
      top.appendChild(data('b', '', c.name));
      top.appendChild(dataChip('v' + c.version, 'dim'));
      if (c.renews) top.appendChild(said('renewed about {0}', dateOf(c.renews), 'muted small rpm-ii-when'));
      li.appendChild(top);
      var nm = el('div', 'rpm-ii-n');
      (c.names || []).slice(0, 4).forEach(function (n) { nm.appendChild(dataChip(n, 'dim mono')); });
      if ((c.names || []).length > 4) nm.appendChild(data('span', 'muted small', '+' + (c.names.length - 4)));
      li.appendChild(nm);
      if (c.moves === false) { var why = el('div', 'rpm-ii-why'); why.appendChild(el('span', '', c.why)); why.appendChild(el('span', 'muted', ' - it is renewed as it is')); li.appendChild(why); }
      if (c.moves && (c.changes || []).length) {
        var chs = el('div', 'rpm-ii-ch');
        c.changes.forEach(function (x) {
          var t = el('span', 'rpm-chg');
          t.appendChild(el('span', 'rpm-chg-k', CHANGE_WORDS[x.field] || x.field));
          t.appendChild(data('span', 'rpm-chg-a', short(x.field, x.from)));
          t.appendChild(ic('next', 11));
          t.appendChild(data('span', 'rpm-chg-b', short(x.field, x.to)));
          chs.appendChild(t);
        });
        li.appendChild(chs);
      } else if (c.moves) li.appendChild(el('div', 'muted small', 'nothing else changes'));
      list.appendChild(li);
    });
    host.appendChild(list);
  }
  function short(k, v) {
    if (v === null || v === undefined || v === '') return '–';
    if (k === 'key_type' || k === 'key_type_alt') return KEY_WORDS[v] || v;
    if (Array.isArray(v)) return v.join(', ') || '–';
    if (typeof v === 'object') return Object.keys(v).map(function (x) { return x + '=' + v[x]; }).join(', ');
    return String(v);
  }
  function tile(label, n, icon, cls) {
    var t = el('div', 'rpm-tile' + (cls ? ' ' + cls : ''));
    var h = el('div', 'rpm-tile-h', label);
    t.appendChild(h);
    var v = el('div', 'rpm-tile-vr');
    v.appendChild(ic(icon, 18));
    v.appendChild(data('span', 'rpm-tile-v', num(n)));
    t.appendChild(v);
    return t;
  }

  /* ---- P3: the compliance check ----------------------------------------------------- */
  var LEVEL = {bad: ['crit', 'ban'], warn: ['warn', 'info'], info: ['dim', 'info']};
  var STATUS = {ok: ['complies', 'ok', 'check'], bad: ['does not comply', 'crit', 'ban'], ends: ['stops complying', 'warn', 'clock']};
  function findingList(fs) {
    var ul = el('ul', 'rpm-finds');
    fs.forEach(function (x) {
      var li = el('li', 'rpm-find lv-' + x.level);
      li.appendChild(ic(LEVEL[x.level] ? LEVEL[x.level][1] : 'info', 14));
      var w = el('span', 'rpm-find-w');
      w.appendChild(el('span', '', x.said));
      li.appendChild(w);
      if (x.from) li.appendChild(said('from {0}', x.from, 'tmx-chip warn rpm-from'));
      ul.appendChild(li);
    });
    return ul;
  }
  function compliance(at) {
    apiGet('reqprofiles/compliance' + (at ? '&at=' + q(at) : '')).then(function (d) {
      var reopen = function () { compliance(at); };
      modal('Compliance of the request profiles', function (body) {
        body.classList.add('tmx-dlg', 'rpm-dlg', 'rpm-comply');
        var head = el('div', 'rpm-chead');
        var hl = el('div', 'rpm-head');
        hl.appendChild(ic('shield', 20, 'rpm-hic'));
        var hw = el('div', 'rpm-head-w');
        hw.appendChild(el('b', 'rpm-head-n', 'Which profiles and certificates stop complying - and when'));
        hw.appendChild(el('span', 'muted small', 'A publicly trusted TLS certificate is valid for at most the days the CA/Browser Forum\'s schedule says (ballot SC-081); a private CA - an authority of acme\'s own, AD CS - is not bound by it. The keys, SHA-1 and the company\'s rules apply to every source.'));
        hl.appendChild(hw);
        head.appendChild(hl);
        var pick = el('div', 'rpm-at');
        var lab = el('label', 'rpm-fl', 'On the date');
        var inp = el('input', 'rpm-date');
        inp.type = 'date';
        inp.id = 'rpm-at';
        inp.min = d.today;
        inp.value = d.at;
        lab.htmlFor = inp.id;
        pick.appendChild(lab);
        pick.appendChild(inp);
        inp.addEventListener('change', function () { if (inp.value) compliance(inp.value); });
        head.appendChild(pick);
        body.appendChild(head);
        /* the schedule: each step with what does not comply from then on */
        var steps = el('ol', 'rpm-steps');
        steps.setAttribute('aria-label', tr('The CA/Browser Forum\'s schedule'));
        (d.steps || []).forEach(function (s) {
          var li = el('li', 'rpm-step' + (s.now ? ' now' : '') + (s.from === d.at || (s.now && d.at === d.today) ? ' sel' : '') + (s.profiles || s.certs ? ' hit' : ''));
          var b = el('button', 'rpm-step-b');
          b.type = 'button';
          b.appendChild(el('span', 'rpm-step-d', s.now ? 'today' : ''));
          if (!s.now) b.lastChild.appendChild(data('span', '', s.from));
          var dd = el('span', 'rpm-step-n');
          dd.appendChild(data('b', '', num(s.days)));
          dd.appendChild(el('span', '', ' days at most'));
          b.appendChild(dd);
          var bad = el('span', 'rpm-step-c');
          bad.appendChild(s.profiles || s.certs ? chip(num(s.profiles) + ' / ' + num(s.certs) + ' not complying', 'warn')
            : chip('all comply', 'ok', 'check'));
          b.appendChild(bad);
          b.setAttribute('aria-label', (s.now ? tr('today') : s.from) + ': ' + s.days);
          b.onclick = function () { compliance(s.now ? '' : s.from); };
          li.appendChild(b);
          steps.appendChild(li);
        });
        body.appendChild(steps);
        var tiles = el('div', 'rpm-tiles');
        tiles.appendChild(tile('Profiles comply', d.count.ok, 'check', 'ok'));
        tiles.appendChild(tile('Stop complying by the date', d.count.ends, 'clock', d.count.ends ? 'warn' : ''));
        tiles.appendChild(tile('Do not comply now', d.count.bad, 'ban', d.count.bad ? 'crit' : ''));
        tiles.appendChild(tile('Certificates not complying', d.cert_count.bad + d.cert_count.ends, 'lock', d.cert_count.bad + d.cert_count.ends ? 'warn' : ''));
        body.appendChild(tiles);
        /* the profiles */
        var h = el('h3', 'tmx-sec-h rpm-sh');
        h.appendChild(ic('list', 16));
        h.appendChild(el('span', '', 'Profiles'));
        body.appendChild(h);
        var list = el('div', 'rpm-clist');
        var order = {bad: 0, ends: 1, ok: 2};
        (d.profiles || []).slice().sort(function (a, b) { return order[a.status] - order[b.status]; }).forEach(function (p) {
          list.appendChild(compItem(p, d, (d.certs || []).filter(function (c) { return c.profile === p.name; })));
        });
        if (!(d.profiles || []).length) list.appendChild(el('p', 'muted', 'No request profile yet.'));
        body.appendChild(list);
        body.appendChild(rulesBox(d.rules, reopen));
      }, [{words: 'Close', close: true}], 'large');
    }).catch(oops);
  }
  function compItem(p, d, certs) {
    var s = STATUS[p.status] || STATUS.ok;
    var card = el('details', 'rpm-ci st-' + p.status);
    if (p.status !== 'ok') card.open = true;
    var sm = el('summary', 'rpm-ci-s');
    sm.appendChild(ic(s[2], 16, 'rpm-ci-ic'));
    sm.appendChild(data('b', 'rpm-ci-n', p.name));
    sm.appendChild(chip(p.public ? 'public' : 'private CA', p.public ? 'info' : 'dim', p.public ? 'globe' : 'lock'));
    if (p.days) sm.appendChild(chip(num(p.days) + ' days', 'dim', 'clock'));
    var st = chip(s[0], s[1]);
    st.classList.add('rpm-ci-st');
    sm.appendChild(st);
    card.appendChild(sm);
    var fs = p.findings || [];
    if (fs.length) card.appendChild(findingList(fs));
    else card.appendChild(el('p', 'muted small rpm-ci-ok', p.public ? 'Within the schedule and the rules.' : 'A private CA: the CA/Browser Forum\'s schedule does not apply; within the rules.'));
    if (certs.length) {
      var cl = el('div', 'rpm-cc');
      cl.appendChild(el('div', 'rpm-pg-h', 'Certificates asked for from it'));
      certs.forEach(function (c) {
        var cs = STATUS[c.status] || STATUS.ok;
        var row = el('div', 'rpm-cc-r st-' + c.status);
        var t = el('div', 'rpm-cc-t');
        t.appendChild(ic(cs[2], 14));
        t.appendChild(data('span', 'rpm-cc-n', c.name));
        t.appendChild(dataChip('v' + c.version, 'dim'));
        if (c.not_after) t.appendChild(said('until {0}', dateOf(c.not_after), 'muted small'));
        t.appendChild(chip(cs[0], cs[1]));
        row.appendChild(t);
        if ((c.findings || []).length) row.appendChild(findingList(c.findings));
        cl.appendChild(row);
      });
      card.appendChild(cl);
    }
    return card;
  }
  function rulesBox(r, reopen) {
    var box = el('details', 'rpm-rules');
    var sm = el('summary', 'rpm-rules-s');
    sm.appendChild(ic('gear', 16));
    sm.appendChild(el('span', '', 'The company\'s own rules'));
    var on = [r.max_days, r.min_rsa > 2048, (r.forbid_keys || []).length, r.wildcards_approval, r.no_pfx, r.max_names].filter(Boolean).length;
    sm.appendChild(chip(on ? num(on) + ' set' : 'none set', on ? 'info' : 'dim'));
    box.appendChild(sm);
    var f = {};
    var grid = el('div', 'rpm-rgrid');
    var line = function (label, ctl, hint) {
      var r0 = el('div', 'tmx-prow rpx-row');
      var l = el('div', 'tmx-prow-l');
      var lab = el('label', 'rpx-lab', label);
      if (ctl._input) { if (!ctl._input.id) ctl._input.id = 'rpm-r-' + Math.random().toString(36).slice(2); lab.htmlFor = ctl._input.id; }
      else if (ctl.id) lab.htmlFor = ctl.id;
      l.appendChild(lab);
      if (hint) { var s = saysBlock(hint); s.classList.add('tmx-prow-s'); l.appendChild(s); }
      r0.appendChild(l);
      var c = el('div', 'tmx-prow-c');
      c.appendChild(ctl);
      r0.appendChild(c);
      grid.appendChild(r0);
    };
    var nb = function (v, id, min, max) {
      var i = el('input', 'tmx-num rpx-num');
      i.type = 'number'; i.min = min; i.max = max; i.id = id;
      i.value = v || '';
      return i;
    };
    f.max = nb(r.max_days, 'rpm-r-max', 1, 36500);
    line('Longest validity (days)', f.max, 'Of any certificate of a profile, a private CA\'s too. Empty: no rule.');
    f.rsa = selectBox([['2048', 'RSA 2048'], ['3072', 'RSA 3072'], ['4096', 'RSA 4096']], String(r.min_rsa || 2048));
    f.rsa.id = 'rpm-r-rsa';
    noI18n(f.rsa);
    line('Shortest RSA key', f.rsa, 'RSA below 2048 bits and SHA-1 are never allowed.');
    f.keys = {};
    var kp = el('div', 'rpx-pills');
    kp.setAttribute('role', 'group');
    kp.id = 'rpm-r-keys';
    Object.keys(KEY_WORDS).forEach(function (k) {
      var lab = el('label', 'rpx-pill');
      var cb = el('input');
      cb.type = 'checkbox';
      cb.checked = (r.forbid_keys || []).indexOf(k) >= 0;
      lab.appendChild(cb);
      lab.appendChild(data('span', '', KEY_WORDS[k]));
      f.keys[k] = cb;
      kp.appendChild(lab);
    });
    var lk = el('div', 'tmx-prow rpx-row');
    var lkl = el('div', 'tmx-prow-l');
    var lkb = el('label', 'rpx-lab', 'Key types forbidden');
    lkb.id = 'rpm-r-keys-l';
    kp.setAttribute('aria-labelledby', lkb.id);
    lkl.appendChild(lkb);
    lk.appendChild(lkl);
    var lkc = el('div', 'tmx-prow-c');
    lkc.appendChild(kp);
    lk.appendChild(lkc);
    grid.appendChild(lk);
    f.wild = switchBox(r.wildcards_approval);
    line('Wildcards wait for approval', f.wild, 'A profile that gives wildcards is approved first.');
    f.pfx = switchBox(r.no_pfx);
    line('No PFX with the key', f.pfx, 'No profile lets the person download the private key.');
    f.names = nb(r.max_names, 'rpm-r-names', 1, 50);
    line('Names in one certificate', f.names, 'At most. Empty: no rule.');
    box.appendChild(grid);
    if (full()) {
      var save = cmdButton('Save the rules', 'save', 'primary small');
      save.id = 'rpm-r-save';
      save.onclick = function () {
        busy(save, true);
        api('reqprofiles/rules', {max_days: f.max.value ? Number(f.max.value) : null, min_rsa: Number(f.rsa.value),
                                  forbid_keys: Object.keys(f.keys).filter(function (k) { return f.keys[k].checked; }),
                                  wildcards_approval: f.wild._get(), no_pfx: f.pfx._get(),
                                  max_names: f.names.value ? Number(f.names.value) : null})
          .then(function () { toast('The rules are saved', 'good'); reopen(); })
          .catch(function (e) { busy(save, false); oops(e); });
      };
      var fr = el('div', 'rpm-rfoot');
      fr.appendChild(save);
      box.appendChild(fr);
    } else {
      grid.setAttribute('inert', '');
    }
    return box;
  }

  window.ACME_RP_MORE = {bar: bar, chips: chips, foot: foot, rowActs: rowActs,
                         history: history, dryRun: dryRun, ending: ending, compliance: compliance};
})();
