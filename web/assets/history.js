/* history.js - Settings → Trash and history, and the History of any object (1.0.138, X1, X2;
   docs/history-and-trash.md, acmelib/certs/history.py).

   - The pane (Settings → Trash and history, <div id="hs-host"> in admin/certs-ui.php): what was
     deleted, kept for the days set above it, filtered by kind, by who and by when, each
     restored after a preview of what comes back (its secrets sealed as they were, a name
     taken since - another one offered, what it needs - brought back with it); and the latest
     changes of everything, each opening that object's History.
   - The History of one object (a popup): every change - who, when, from where - field by field,
     a secret only as "changed"; "Restore this version" shows what would change and saves it
     through the object's own route (checked as any save).
   - A History button in the head of a certificate's window and of a source's, validation's,
     target's or test's form.

   For the other scripts (the right-click menu, the Ctrl+K palette):
     window.acmeHistory.open(type, id)   type: cert, target, source, validation, test, deploy,
                                         check, profile, team, role, tag, dnsset, dnsrecord;
                                         id: its number, or {name: '...'}
     window.acmeHistory.types            those types
     window.acmeTrash.open([type])       Settings → Trash and history, the trash (of one kind)
   Every popup is the page's own (modal); nothing is the browser's. */
'use strict';
(function () {
  var HS = {view: 'trash', tr: null, feed: null, asking: 0,
            f: {type: '', who: '', when: '', q: ''}, cf: {type: '', who: '', when: '', q: ''}};
  var TYPE_ICON = {cert: 'lock', target: 'router', source: 'download', validation: 'shield',
                   test: 'pulse', deploy: 'out', check: 'check', profile: 'list', team: 'people',
                   role: 'key', tag: 'flag', dnsset: 'globe', dnsuse: 'globe', dnsrecord: 'net'};
  var TYPE_WORDS = {cert: 'certificate', target: 'target', source: 'source', validation: 'validation',
                    test: 'test', deploy: 'deployment', check: 'test of a certificate',
                    profile: 'request profile', team: 'owner', role: 'role', tag: 'tag',
                    dnsset: 'DNS set', dnsuse: 'use of a DNS set', dnsrecord: 'DNS record'};
  var TYPE_PLURAL = {cert: 'certificates', target: 'targets', source: 'sources', validation: 'validations',
                     test: 'tests', deploy: 'deployments', check: 'tests of certificates',
                     profile: 'request profiles', team: 'owners', role: 'roles', tag: 'tags',
                     dnsset: 'DNS sets', dnsrecord: 'DNS records'};
  var ACTION_WORDS = {create: 'created', change: 'changed', 'delete': 'deleted', restore: 'restored'};
  var FIELD_WORDS = {name: 'Name', note: 'Note', enabled: 'Switched on', kind: 'Module', config: 'Settings',
                     options: 'Options', members: 'Members', policy: 'Limits', caps: 'Capabilities',
                     names: 'Names', tags: 'Tags', owner: 'Owner', target: 'Target', cert_id: 'Certificate',
                     issuer: 'Source', challenge: 'Validation', challenge_map: 'Validation per name',
                     key_type: 'Key type', key_type_alt: 'Second key type', auto_renew: 'Renewed by itself',
                     renew_days: 'Renewed days before the end', reuse_key: 'Keeps its key',
                     profile: 'Subject and extensions', contact_mail: 'Contact mail',
                     contact_phone: 'Contact phone', parent: 'Under', description: 'Description',
                     colour: 'Colour', servers: 'Servers', protocol: 'Protocol', tls_name: 'TLS name',
                     timeout_s: 'Timeout (s)', position: 'Order', test: 'Test', after_target: 'Runs after',
                     rtype: 'Type', value: 'Value', ttl: 'TTL', csr_from: 'Key made by', set_name: 'DNS set',
                     purpose: 'Function', state: 'State', version: 'Version', source: 'Comes from',
                     csr_given: 'CSR given', cn: 'Common name', not_after: 'Expires'};
  var FLAG_FIELDS = {enabled: 1, auto_renew: 1, reuse_key: 1};
  var WHEN = [['', 'any time'], ['1', 'today'], ['7', 'the last 7 days'], ['30', 'the last 30 days']];

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
    if (icon) c.appendChild(ic(icon, 13));
    if (words instanceof Node) c.appendChild(words); else c.appendChild(el('span', '', words));
    return c;
  }
  function role() { return (typeof ME === 'object' && ME && ME.role) || 'readonly'; }
  function isFull() { return role() === 'fulladmin'; }
  function mayTrash() { return role() === 'fulladmin' || role() === 'certadmin'; }
  function initials(who) {
    var w = String(who || '').replace(/^(local|group):/i, '').replace(/@.*$/, '');
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
  function avatar(who, small) {
    var a = el('span', 'tmx-av tmx-av-' + hue(who) + (small ? ' hs-av-s' : ''));
    a.appendChild(data('span', '', initials(who)));
    a.setAttribute('aria-hidden', 'true');
    return a;
  }
  function typeTile(type, big) {
    var t = el('span', 'hs-tile t-' + (type || 'x') + (big ? ' big' : ''));
    t.appendChild(ic(TYPE_ICON[type] || 'list', big ? 22 : 18));
    return t;
  }
  var ACTION_TONE = {create: 'ok', change: 'info', 'delete': 'crit', restore: 'violet'};
  function actionChip(a) { return chip(ACTION_WORDS[a] || a, 'hs-actc ' + (ACTION_TONE[a] || 'dim')); }
  function when(ts) {
    var s = el('span', 'hs-when');
    s.appendChild(el('span', '', ago(ts)));
    explain(s, stamp(ts));
    return s;
  }
  function blank(icon, title, words) {
    var e = el('div', 'tmx-empty hs-empty');
    e.appendChild(ic(icon, 30));
    e.appendChild(el('b', '', title));
    if (words) e.appendChild(el('span', '', words));
    return e;
  }
  function asking(host) {
    clear(host);
    host.appendChild(el('div', 'tmx-asking', 'Asking…'));
  }
  function failed(host, e) {
    clear(host);
    var n = el('div', 'tmx-note warn');
    n.appendChild(ic('info', 16));
    n.appendChild(el('span', '', (e && e.message) || String(e)));
    host.appendChild(n);
  }
  function qs(o) {
    var out = [];
    Object.keys(o).forEach(function (k) {
      if (o[k] !== '' && o[k] !== null && o[k] !== undefined) out.push(encodeURIComponent(k) + '=' + encodeURIComponent(o[k]));
    });
    return out.length ? '&' + out.join('&') : '';
  }
  function sinceOf(days) {
    if (!days) return '';
    var d = new Date();
    if (days === '1') { d.setHours(0, 0, 0, 0); return String(Math.floor(d.getTime() / 1000)); }
    return String(Math.floor(Date.now() / 1000) - Number(days) * 86400);
  }
  function selectOf(pairs, value, label) {
    var s = el('select', 'hs-sel');
    pairs.forEach(function (p) {
      var o = el('option', '', p[1]);
      o.value = p[0];
      if (p[2]) noI18n(o);
      s.appendChild(o);
    });
    s.value = value || '';
    if (label) s.setAttribute('aria-label', T(label));
    return s;
  }
  function findBox(value, placeholder, go) {
    var f = el('div', 'tmx-find hs-find');
    f.appendChild(ic('search', 15));
    var q = el('input', '');
    q.type = 'search';
    q.placeholder = T(placeholder);
    q.setAttribute('aria-label', T(placeholder));
    q.autocomplete = 'off';
    q.value = value || '';
    noI18n(q);
    q.addEventListener('input', debounce(function () { go(q.value); }, 200));
    f.appendChild(q);
    return f;
  }

  /* ---- a value, and two of them side by side -------------------------------------- */
  function isScalar(v) { return v === null || v === undefined || typeof v !== 'object'; }
  function plain(v) {
    if (v === null || v === undefined || v === '') return '';
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }
  function memberWords(m) {
    if (!m || typeof m !== 'object') return plain(m);
    var bits = [String(m.who || '?')];
    var r = (m.roles || []).concat(m.rights || []);
    if (r.length) bits.push('(' + r.join(', ') + ')');
    if (m.until) bits.push('until ' + m.until);
    return bits.join(' ');
  }
  function valueNode(field, v, mark) {
    if (v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length) ||
        (v && typeof v === 'object' && !Array.isArray(v) && !Object.keys(v).length)) {
      return el('span', 'hs-none', 'not set');
    }
    if (FLAG_FIELDS[field] && (v === 0 || v === 1 || v === true || v === false || v === '0' || v === '1')) {
      return el('span', 'hs-flag ' + (Number(v) ? 'on' : 'off'), Number(v) ? 'yes' : 'no');
    }
    if (typeof v === 'boolean') return el('span', 'hs-flag ' + (v ? 'on' : 'off'), v ? 'yes' : 'no');
    if (Array.isArray(v)) {
      var box = el('span', 'hs-chips');
      v.slice(0, 60).forEach(function (x) {
        var words = field === 'members' ? memberWords(x) : plain(x);
        var c = data('span', 'hs-vchip' + (mark && mark[words] ? ' ' + mark[words] : ''), words);
        box.appendChild(c);
      });
      if (v.length > 60) box.appendChild(el('span', 'hs-none', '+' + (v.length - 60)));
      return box;
    }
    if (typeof v === 'object') {
      var kv = el('span', 'hs-kv');
      Object.keys(v).slice(0, 40).forEach(function (k) {
        var line = el('span', 'hs-kvl');
        line.appendChild(data('span', 'hs-k', k));
        line.appendChild(data('span', 'hs-v', plain(v[k])));
        kv.appendChild(line);
      });
      return kv;
    }
    var s = String(v);
    if (field === 'cert_id') return data('span', 'mono', '#' + s);
    return data('span', 'hs-text' + (s.length > 60 || /\n/.test(s) ? ' long' : ''), s);
  }
  /* What differs in two lists: the ones gone marked in the first, the new ones in the second. */
  function listMarks(field, a, b) {
    var key = function (x) { return field === 'members' ? memberWords(x) : plain(x); };
    var ak = {}, bk = {};
    (a || []).forEach(function (x) { ak[key(x)] = 1; });
    (b || []).forEach(function (x) { bk[key(x)] = 1; });
    var ma = {}, mb = {};
    Object.keys(ak).forEach(function (k) { if (!bk[k]) ma[k] = 'gone'; });
    Object.keys(bk).forEach(function (k) { if (!ak[k]) mb[k] = 'came'; });
    return [ma, mb];
  }
  /* Two texts of several lines: the lines gone and the lines come. */
  function linesDiff(a, b) {
    var la = String(a || '').split('\n'), lb = String(b || '').split('\n');
    var box = el('div', 'hs-lines');
    var inB = {}, inA = {};
    lb.forEach(function (l) { inB[l] = 1; });
    la.forEach(function (l) { inA[l] = 1; });
    la.forEach(function (l) {
      if (!inB[l]) { var r = data('div', 'hs-line gone', l || ' '); r.setAttribute('data-sign', '−'); box.appendChild(r); }
    });
    lb.forEach(function (l) {
      var r = data('div', 'hs-line ' + (inA[l] ? 'same' : 'came'), l || ' ');
      r.setAttribute('data-sign', inA[l] ? ' ' : '+');
      box.appendChild(r);
    });
    return box;
  }
  function fieldLabel(c) {
    var lab = el('div', 'hs-field');
    if (c.sub) {
      lab.appendChild(el('span', 'hs-group', FIELD_WORDS[c.field] || c.field));
      lab.appendChild(el('span', 'hs-label', c.label || c.sub));
    } else {
      lab.appendChild(el('span', 'hs-label', FIELD_WORDS[c.field] || c.label || c.field));
    }
    return lab;
  }
  function diffRows(changes) {
    var box = el('div', 'hs-diff');
    box.setAttribute('role', 'table');
    changes.forEach(function (c) {
      var row = el('div', 'hs-row');
      row.setAttribute('role', 'row');
      row.appendChild(fieldLabel(c));
      if (c.secret) {
        var s = el('div', 'hs-secret');
        s.appendChild(chip(c.set_after ? (c.set_before ? 'changed' : 'set') : 'taken away', 'violet', 'lock'));
        s.appendChild(el('span', 'hs-none', 'a secret is never shown - only that it changed'));
        row.appendChild(s);
        box.appendChild(row);
        return;
      }
      var a = c.before, b = c.after;
      var bothText = typeof a === 'string' && typeof b === 'string' && (/\n/.test(a) || /\n/.test(b));
      if (bothText) {
        var w = el('div', 'hs-both');
        w.appendChild(linesDiff(a, b));
        row.appendChild(w);
        box.appendChild(row);
        return;
      }
      var marks = Array.isArray(a) || Array.isArray(b) ? listMarks(c.field, a || [], b || []) : [null, null];
      var isList = Array.isArray(a) || Array.isArray(b);
      var was = el('div', 'hs-was' + (isList ? ' list' : ''));
      was.setAttribute('aria-label', T('before'));
      was.appendChild(valueNode(c.sub || c.field, a, marks[0]));
      var arrow = ic('next', 14, 'hs-arrow');
      var now = el('div', 'hs-now' + (isList ? ' list' : ''));
      now.setAttribute('aria-label', T('after'));
      now.appendChild(valueNode(c.sub || c.field, b, marks[1]));
      row.appendChild(was);
      row.appendChild(arrow);
      row.appendChild(now);
      box.appendChild(row);
    });
    return box;
  }

  /* ==== The History of one object ================================================== */
  function openHistory(type, ref) {
    var args = {type: type};
    if (ref && typeof ref === 'object') { if (ref.id) args.id = ref.id; else args.name = ref.name; }
    else args.id = ref;
    var go = function () {
      modal('History', function (body) {
        asking(body);
      }, [{words: 'Close', close: true}], 'medium');
      var ticket = modalTicket();
      api('history' + qs(args)).then(function (d) {
        if (!modalStill(ticket)) return;
        drawHistory($('modal-body'), d, args);
      }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
    };
    if ($('modal') && !$('modal').hidden) modalOver(go); else go();
  }
  function drawHistory(outer, d, args) {
    clear(outer);
    var body = el('div', 'hs-modal');
    outer.appendChild(body);
    var o = d.object || {};
    var head = el('div', 'hs-head');
    head.appendChild(typeTile(o.type, true));
    var hw = el('div', 'hs-head-w');
    hw.appendChild(data('b', 'hs-head-n', o.name || ('#' + o.id)));
    var sub = el('div', 'hs-head-s');
    sub.appendChild(chip(TYPE_WORDS[o.type] || o.type, 'dim'));
    if (!o.exists) {
      sub.appendChild(chip(o.trash_id ? 'deleted - in the trash' : 'deleted', 'crit', 'trash'));
    }
    var n = (d.entries || []).length;
    sub.appendChild(el('span', 'hs-none', n + ' change(s)'));
    hw.appendChild(sub);
    head.appendChild(hw);
    if (!o.exists && o.trash_id && mayTrash()) {
      var tb = el('button', 'btn cmd small', 'Open the trash');
      setButtonIcon(tb, 'trash', 'Open the trash');
      tb.onclick = function () { closeModal(); openTrash(); };
      head.appendChild(tb);
    }
    body.appendChild(head);
    if (!n) {
      body.appendChild(blank('history', 'No change written down yet',
        Number(d.keep_days) ? 'Every change of it from now on is written here - who, when, from where and what changed. Kept ' + d.keep_days + ' days.'
          : 'The history is switched off (Settings → Trash and history).'));
      return;
    }
    var tl = el('ol', 'hs-tl');
    tl.setAttribute('aria-label', T('Latest changes'));
    (d.entries || []).forEach(function (e, i) { tl.appendChild(entryNode(e, i, args)); });
    body.appendChild(tl);
    body.appendChild(el('p', 'hs-foot', 'Kept ' + d.keep_days + ' days. A secret is never shown here - only that it changed.'));
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(body);
  }
  function entryNode(e, i, args) {
    var li = el('li', 'hs-ent a-' + (e.action || 'change'));
    var dot = el('span', 'hs-dot');
    dot.appendChild(ic({create: 'add', change: 'edit', 'delete': 'trash', restore: 'undo'}[e.action] || 'edit', 12));
    li.appendChild(dot);
    var card = el('div', 'hs-card');
    var top = el('div', 'hs-top');
    top.appendChild(avatar(e.who, true));
    var w = el('div', 'hs-top-w');
    var line = el('div', 'hs-line1');
    line.appendChild(data('b', '', e.who || '?'));
    line.appendChild(actionChip(e.action));
    w.appendChild(line);
    var meta = el('div', 'hs-meta');
    meta.appendChild(when(e.ts));
    meta.appendChild(el('span', 'hs-sep', '·'));
    meta.appendChild(data('span', '', stamp(e.ts)));
    if (e.ip) {
      meta.appendChild(el('span', 'hs-sep', '·'));
      var ipw = el('span', '', 'from ');
      ipw.appendChild(data('span', 'mono', e.ip));
      meta.appendChild(ipw);
    }
    w.appendChild(meta);
    top.appendChild(w);
    if (i === 0) top.appendChild(chip('now', 'ok'));
    card.appendChild(top);
    if (e.note) card.appendChild(el('div', 'hs-note', e.note));
    var ch = e.changes || [];
    if (ch.length) card.appendChild(diffRows(ch));
    else if ((e.made || []).length) {
      var det = el('details', 'hs-made');
      var sm = el('summary', '');
      sm.appendChild(el('span', '', e.action === 'restore' ? 'What it came back with' : 'What it was made with'));
      sm.appendChild(el('span', 'tmx-n', String(e.made.length)));
      det.appendChild(sm);
      var made = diffRows(e.made.filter(function (c) { return c.secret || (c.after !== null && c.after !== '' && c.after !== undefined); }));
      made.classList.add('made');
      det.appendChild(made);
      card.appendChild(det);
    }
    if (e.can_restore && i > 0) {
      var act = el('div', 'hs-acts');
      var b = el('button', 'btn cmd small', 'Restore this version');
      setButtonIcon(b, 'undo', 'Restore this version');
      var panel = el('div', 'hs-restore');
      panel.hidden = true;
      b.onclick = function () {
        if (!panel.hidden) { panel.hidden = true; b.setAttribute('aria-expanded', 'false'); return; }
        b.setAttribute('aria-expanded', 'true');
        panel.hidden = false;
        asking(panel);
        api('history/preview', {entry: e.id}).then(function (p) { drawRestore(panel, e, p, args); })
          .catch(function (x) { failed(panel, x); });
      };
      b.setAttribute('aria-expanded', 'false');
      act.appendChild(b);
      card.appendChild(act);
      card.appendChild(panel);
    }
    li.appendChild(card);
    return li;
  }
  function drawRestore(panel, e, p, args) {
    clear(panel);
    var h = el('div', 'hs-rh');
    h.appendChild(ic('undo', 16));
    h.appendChild(el('b', '', 'What restoring this version changes'));
    panel.appendChild(h);
    var ch = p.changes || [];
    if (!ch.length) {
      panel.appendChild(el('p', 'hs-none', 'Nothing - it is as that version already.'));
      return;
    }
    panel.appendChild(diffRows(ch));
    var sec = null;
    if ((p.secrets || []).length) {
      var row = el('label', 'hs-check');
      sec = el('input', '');
      sec.type = 'checkbox';
      row.appendChild(sec);
      var sw = el('span', '');
      sw.appendChild(el('b', '', 'Also put back the secrets of that version'));
      sw.appendChild(el('span', 'hs-none', 'Off: the secrets it has now stay - only the other settings go back.'));
      row.appendChild(sw);
      panel.appendChild(row);
    }
    panel.appendChild(el('p', 'hs-none', 'It is saved as any change is - checked, and written down here as a new version.'));
    var foot = el('div', 'hs-rfoot');
    var no = el('button', 'btn cmd small', 'Cancel');
    setButtonIcon(no, 'close', 'Cancel');
    no.onclick = function () { panel.hidden = true; };
    var yes = el('button', 'btn cmd small primary', 'Restore');
    setButtonIcon(yes, 'undo', 'Restore');
    yes.onclick = function () {
      busy(yes, true);
      api('history/restore', {entry: e.id, secrets: !!(sec && sec.checked)}).then(function (r) {
        toast('The version was restored' + ((r.lost || []).length ? ' - ' + r.lost.join(', ') + ': enter again' : ''), 'good');
        api('history' + qs(args)).then(function (d) { drawHistory($('modal-body'), d, args); });
        refreshOthers();
      }).catch(function (x) { busy(yes, false); toast((x && x.message) || String(x), 'bad'); });
    };
    foot.appendChild(no);
    foot.appendChild(yes);
    panel.appendChild(foot);
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(panel);
    try { panel.scrollIntoView({block: 'nearest'}); } catch (x) { }
  }
  /* What else on the page shows what was just changed. */
  function refreshOthers() {
    try { if (window.ACME_TEAMS && ACME_TEAMS.load) ACME_TEAMS.load(true); } catch (e) { }
    try { if (window.ACME_CERTS && typeof ACME_CERTS.refresh === 'function') ACME_CERTS.refresh(); } catch (e) { }
    try { if (typeof forgetAll === 'function') forgetAll(); } catch (e) { }
  }

  /* ==== Settings → Trash and history ================================================ */
  function drawPane() {
    var host = $('hs-host');
    if (!host) return;
    if (!mayTrash()) HS.view = 'changes';
    clear(host);
    var wrap = el('div', 'hs tmx');
    var bar = el('div', 'tmx-bar');
    var views = el('div', 'tmx-views');
    views.setAttribute('role', 'tablist');
    views.setAttribute('aria-label', T('Trash and history'));
    [['trash', 'Trash', 'trash'], ['changes', 'Latest changes', 'history']].forEach(function (v) {
      var b = el('button', 'tmx-vbtn' + (HS.view === v[0] ? ' on' : ''));
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', HS.view === v[0] ? 'true' : 'false');
      b.appendChild(ic(v[2], 15));
      b.appendChild(el('span', '', v[1]));
      if (v[0] === 'trash') {
        var n = el('span', 'tmx-n hs-count', HS.tr ? String((HS.tr.total || 0)) : '…');
        noI18n(n);
        b.appendChild(n);
        if (!mayTrash()) { b.disabled = true; explain(b, 'Only a full or a certificate administrator sees the trash.'); }
      }
      b.onclick = function () { if (b.disabled) return; HS.view = v[0]; drawPane(); };
      views.appendChild(b);
    });
    bar.appendChild(views);
    wrap.appendChild(bar);
    var body = el('div', 'hs-body');
    wrap.appendChild(body);
    host.appendChild(wrap);
    if (HS.view === 'trash') loadTrash(body); else loadFeed(body);
  }

  /* ---- the trash ---- */
  function loadTrash(body) {
    asking(body);
    var f = HS.f;
    api('trash' + qs({type: f.type, who: f.who, since: sinceOf(f.when), q: f.q})).then(function (d) {
      HS.tr = d;
      var cnt = document.querySelector('#hs-host .hs-count');
      if (cnt) cnt.textContent = String(d.total || 0);
      drawTrash(body, d);
    }).catch(function (e) { failed(body, e); });
  }
  function drawTrash(body, d) {
    clear(body);
    if (!Number(d.days)) {
      var off = el('div', 'tmx-note warn');
      off.appendChild(ic('info', 16));
      off.appendChild(el('span', '', 'The trash is switched off: what is deleted is gone at once. Set how many days it is kept above.'));
      body.appendChild(off);
    }
    var bar = el('div', 'hs-filters');
    bar.appendChild(findBox(HS.f.q, 'Find in the trash…', function (v) { HS.f.q = v; loadTrash(body); }));
    var tp = [['', 'every kind']];
    Object.keys(d.types || {}).sort().forEach(function (k) { tp.push([k, (TYPE_PLURAL[k] || k) + ' (' + d.types[k] + ')']); });
    var ts = selectOf(tp, HS.f.type, 'Only of this kind');
    ts.onchange = function () { HS.f.type = ts.value; loadTrash(body); };
    bar.appendChild(ts);
    var wp = [['', 'by anybody']].concat((d.people || []).map(function (p) { return [p, p, true]; }));
    var ws = selectOf(wp, HS.f.who, 'Deleted by');
    ws.onchange = function () { HS.f.who = ws.value; loadTrash(body); };
    bar.appendChild(ws);
    var ds = selectOf(WHEN, HS.f.when, 'Deleted when');
    ds.onchange = function () { HS.f.when = ds.value; loadTrash(body); };
    bar.appendChild(ds);
    if (d.can_purge && (d.items || []).length) {
      var sp = el('span', 'hs-sp');
      bar.appendChild(sp);
      var all = el('button', 'btn cmd small hs-empty-btn', 'Empty the trash');
      setButtonIcon(all, 'broom', 'Empty the trash');
      all.onclick = function () {
        confirmThen('Empty the trash', T('Everything in the trash is deleted for good - it can never be restored.'), 'Delete them', function () {
          api('trash/purge', {all: true}).then(function (r) { toast(r.message || 'Done', 'good'); loadTrash(body); })
            .catch(function (e) { toast(e.message, 'bad'); });
        });
      };
      bar.appendChild(all);
    }
    body.appendChild(bar);
    var items = d.items || [];
    if (!items.length) {
      var filtered = HS.f.type || HS.f.who || HS.f.when || HS.f.q;
      body.appendChild(filtered ? blank('funnel', 'Nothing deleted matches', 'Another kind, another person or a longer time shows more.')
        : blank('trash', 'The trash is empty', Number(d.days) ? 'What is deleted - a target, a deployment, a test, a source, a validation, a request profile, an owner, a role, a tag, a DNS set, a certificate - waits here ' + d.days + ' days and can be restored.'
          : 'Nothing is kept while the trash is off.'));
      return;
    }
    var list = el('ul', 'hs-list');
    list.setAttribute('aria-label', T('Trash'));
    items.forEach(function (it) { list.appendChild(trashItem(it, body)); });
    body.appendChild(list);
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(body);
  }
  function daysLeft(ts) { return Math.max(0, Math.ceil((Number(ts) - Date.now() / 1000) / 86400)); }
  function trashItem(it, body) {
    var li = el('li', 'hs-item');
    li.appendChild(typeTile(it.type));
    var m = el('div', 'hs-main');
    var t = el('div', 'hs-title');
    t.appendChild(data('b', 'hs-name', it.name || '?'));
    t.appendChild(chip(TYPE_WORDS[it.type] || it.type, 'dim'));
    if (it.owner) t.appendChild(chip(data('span', '', it.owner), 'info', 'people'));
    m.appendChild(t);
    if (it.detail) m.appendChild(data('div', 'hs-detail', it.detail));
    var sub = el('div', 'hs-sub');
    sub.appendChild(avatar(it.who, true));
    var by = el('span', '', 'deleted by ');
    by.appendChild(data('b', '', it.who || '?'));
    sub.appendChild(by);
    sub.appendChild(el('span', 'hs-sep', '·'));
    sub.appendChild(when(it.ts));
    if (it.ip) {
      sub.appendChild(el('span', 'hs-sep', '·'));
      var ip = el('span', '', 'from ');
      ip.appendChild(data('span', 'mono', it.ip));
      sub.appendChild(ip);
    }
    m.appendChild(sub);
    if ((it.children || []).length) {
      var w = el('div', 'hs-with');
      w.appendChild(el('span', 'hs-none', 'with'));
      it.children.forEach(function (c) { w.appendChild(chip(data('span', '', c.name), 'dim', TYPE_ICON[c.type] || 'list')); });
      m.appendChild(w);
    }
    li.appendChild(m);
    var side = el('div', 'hs-side');
    var left = daysLeft(it.expires);
    var lp = el('span', 'hs-left' + (left <= 3 ? ' soon' : ''), left === 1 ? '1 day left' : left + ' days left');
    explain(lp, T('Deleted for good on') + ' ' + stamp(it.expires));
    side.appendChild(lp);
    var hb = el('button', 'btn iconbtn small');
    hb.innerHTML = iconMarkup('history', 15);
    hb.setAttribute('aria-label', T('History'));
    explain(hb, 'Its history: every change before it was deleted.');
    hb.onclick = function () { openHistory(it.type, it.oid); };
    side.appendChild(hb);
    if (it.can_purge) {
      var del = el('button', 'btn iconbtn small hs-del');
      del.innerHTML = iconMarkup('trash', 15);
      del.setAttribute('aria-label', T('Delete for good'));
      explain(del, 'Deleted for good - it can never be restored.');
      del.onclick = function () {
        confirmThen('Delete for good', T('It is deleted for good and can never be restored.'), 'Delete it', function () {
          api('trash/purge', {ids: [it.id]}).then(function () { toast('Deleted for good', 'good'); loadTrash(body); })
            .catch(function (e) { toast(e.message, 'bad'); });
        });
      };
      side.appendChild(del);
    }
    var rb = el('button', 'btn cmd small primary', 'Restore…');
    setButtonIcon(rb, 'undo', 'Restore…');
    if (!it.can_restore) { rb.disabled = true; explain(rb, 'Only a full administrator brings this back.'); }
    rb.onclick = function () { restoreDialog(it, body); };
    side.appendChild(rb);
    li.appendChild(side);
    return li;
  }
  function restoreDialog(it, listBody) {
    var st = {needs: false};
    modal('Restore from the trash', function (body) { asking(body); }, [{words: 'Close', close: true}], 'medium');
    var ticket = modalTicket();
    api('trash/preview', {id: it.id}).then(function (p) {
      if (!modalStill(ticket)) return;
      var nameBox = null;
      var can = (p.item || {}).can_restore;
      var buttons = [{words: 'Close', close: true}];
      if (can) buttons.push({words: 'Restore', cls: 'primary', icon: 'undo', noConfirm: true, go: function (b) {
        var sent = {id: it.id, with_needs: st.needs};
        if (nameBox) sent.name = nameBox.value.trim();
        busy(b, true);
        api('trash/restore', sent).then(function (r) {
          closeModal();
          var left = r.left || [];
          toast((r.message || 'Restored') + (left.length ? ' - ' + T('left in the trash') + ': ' + left.join('; ') : ''), left.length ? 'bad' : 'good');
          refreshOthers();
          if (listBody && listBody.isConnected) loadTrash(listBody);
        }).catch(function (e) { busy(b, false); toast((e && e.message) || String(e), 'bad'); });
      }});
      modal('Restore from the trash', function (outer) {
        var body = el('div', 'hs-modal');
        outer.appendChild(body);
        var head = el('div', 'hs-head');
        head.appendChild(typeTile(it.type, true));
        var hw = el('div', 'hs-head-w');
        hw.appendChild(data('b', 'hs-head-n', it.name));
        var sub = el('div', 'hs-head-s');
        sub.appendChild(chip(TYPE_WORDS[it.type] || it.type, 'dim'));
        var by = el('span', 'hs-none', 'deleted by ');
        by.appendChild(data('b', '', it.who));
        sub.appendChild(by);
        sub.appendChild(when(it.ts));
        hw.appendChild(sub);
        head.appendChild(hw);
        body.appendChild(head);
        if (p.conflict) {
          var c = el('div', 'tmx-note warn hs-conflict');
          c.appendChild(ic('info', 16));
          var cw = el('span', '');
          cw.appendChild(el('span', '', 'Its name is taken since:'));
          cw.appendChild(document.createTextNode(' '));
          cw.appendChild(data('b', '', p.conflict.name));
          cw.appendChild(document.createTextNode(' '));
          cw.appendChild(el('span', '', 'is another one now. It comes back under the name below.'));
          c.appendChild(cw);
          body.appendChild(c);
          nameBox = textBox(p.conflict.suggestion, '', '');
          noI18n(nameBox);
          var fg = el('div', 'formgrid hs-one');
          fg.appendChild(formField('Restore it as', nameBox, 'The name it has here after it is restored.'));
          body.appendChild(fg);
        }
        var needs = p.needs || [];
        if (needs.length) {
          var nn = el('div', 'tmx-note warn');
          nn.appendChild(ic('info', 16));
          var nw = el('div', 'hs-needs');
          nw.appendChild(el('b', '', 'It needs what is not here'));
          needs.forEach(function (x) { nw.appendChild(el('div', '', x.words)); });
          nn.appendChild(nw);
          body.appendChild(nn);
          if (needs.every(function (x) { return x.trash_id; })) {
            var row = el('label', 'hs-check');
            var cb = el('input', '');
            cb.type = 'checkbox';
            cb.checked = true;
            st.needs = true;
            cb.onchange = function () { st.needs = cb.checked; };
            row.appendChild(cb);
            var cw2 = el('span', '');
            cw2.appendChild(el('b', '', 'Restore what it needs too'));
            cw2.appendChild(el('span', 'hs-none', 'It is in the trash as well - it comes back first.'));
            row.appendChild(cw2);
            body.appendChild(row);
          }
        }
        (p.notes || []).forEach(function (n) {
          var x = el('div', 'tmx-note');
          x.appendChild(ic('info', 16));
          x.appendChild(el('span', '', n));
          body.appendChild(x);
        });
        var sect = el('div', 'hs-sect');
        sect.appendChild(el('h4', '', 'What comes back'));
        var grid = el('div', 'hs-fields');
        var FIRST = ['name', 'kind', 'names', 'issuer', 'challenge', 'cert_id', 'target', 'test', 'owner', 'enabled'];
        var rank = function (f) { var i = FIRST.indexOf(f.field); return i < 0 ? 99 : i; };
        (p.fields || []).slice().sort(function (x, y) { return rank(x) - rank(y); }).forEach(function (f) {
          var r = el('div', 'hs-frow');
          r.appendChild(el('span', 'hs-label', FIELD_WORDS[f.field] || f.field));
          var v = el('div', 'hs-fval');
          v.appendChild(valueNode(f.field, f.value));
          r.appendChild(v);
          grid.appendChild(r);
        });
        sect.appendChild(grid);
        if ((p.secrets || []).length) {
          var s = el('div', 'hs-sealed');
          s.appendChild(chip('sealed', 'violet', 'lock'));
          var sw = el('span', '');
          sw.appendChild(el('span', '', 'Its secrets come back as they were, never shown:'));
          sw.appendChild(document.createTextNode(' '));
          sw.appendChild(data('span', 'mono', p.secrets.join(', ')));
          s.appendChild(sw);
          sect.appendChild(s);
        }
        body.appendChild(sect);
        if ((p.children || []).length) {
          var ks = el('div', 'hs-sect');
          ks.appendChild(el('h4', '', 'Comes back with it'));
          var kl = el('ul', 'hs-kids');
          p.children.forEach(function (k) {
            var li = el('li', '');
            li.appendChild(ic(TYPE_ICON[k.type] || 'list', 15));
            li.appendChild(data('span', 'hs-kid-n', k.name));
            li.appendChild(chip(TYPE_WORDS[k.type] || k.type, 'dim'));
            (k.needs || []).forEach(function (w) { li.appendChild(chip(w, 'warn')); });
            kl.appendChild(li);
          });
          ks.appendChild(kl);
          body.appendChild(ks);
        }
        if (!can) body.appendChild(el('p', 'hs-none', 'Only a full administrator brings this back.'));
      }, buttons, 'medium');
    }).catch(function (e) { if (modalStill(ticket)) failed($('modal-body'), e); });
  }

  /* ---- the latest changes of everything ---- */
  function loadFeed(body) {
    asking(body);
    var f = HS.cf;
    api('history' + qs({feed: 1, type: f.type, who: f.who, since: sinceOf(f.when), q: f.q, limit: 150})).then(function (d) {
      HS.feed = d;
      drawFeed(body, d);
    }).catch(function (e) { failed(body, e); });
  }
  function drawFeed(body, d) {
    clear(body);
    if (!Number(d.keep_days)) {
      var off = el('div', 'tmx-note warn');
      off.appendChild(ic('info', 16));
      off.appendChild(el('span', '', 'The history is switched off: no change is written down. Set how many days it is kept above.'));
      body.appendChild(off);
    }
    var bar = el('div', 'hs-filters');
    bar.appendChild(findBox(HS.cf.q, 'Find a name…', function (v) { HS.cf.q = v; loadFeed(body); }));
    var tp = [['', 'every kind']];
    Object.keys(TYPE_PLURAL).forEach(function (k) { tp.push([k, TYPE_PLURAL[k]]); });
    var ts = selectOf(tp, HS.cf.type, 'Only of this kind');
    ts.onchange = function () { HS.cf.type = ts.value; loadFeed(body); };
    bar.appendChild(ts);
    var wp = [['', 'by anybody']].concat((d.people || []).map(function (p) { return [p, p, true]; }));
    var ws = selectOf(wp, HS.cf.who, 'Changed by');
    ws.onchange = function () { HS.cf.who = ws.value; loadFeed(body); };
    bar.appendChild(ws);
    var ds = selectOf(WHEN, HS.cf.when, 'Changed when');
    ds.onchange = function () { HS.cf.when = ds.value; loadFeed(body); };
    bar.appendChild(ds);
    body.appendChild(bar);
    var list = d.entries || [];
    if (!list.length) {
      body.appendChild(blank('history', 'No change written down', 'Every change of a target, a deployment, a test, a source, a validation, a request profile, an owner, a role, a tag, a DNS set or a certificate shows here.'));
      return;
    }
    var ul = el('ul', 'hs-feed');
    ul.setAttribute('aria-label', T('Latest changes'));
    list.forEach(function (e) {
      var li = el('li', '');
      var b = el('button', 'hs-ev a-' + (e.action || 'change'));
      b.type = 'button';
      b.appendChild(avatar(e.who, true));
      var w = el('span', 'hs-ev-w');
      var l1 = el('span', 'hs-ev-1');
      l1.appendChild(data('b', '', e.who || '?'));
      l1.appendChild(actionChip(e.action));
      l1.appendChild(el('span', 'hs-none', TYPE_WORDS[e.type] || e.type));
      l1.appendChild(data('b', 'hs-ev-n', e.name || ''));
      w.appendChild(l1);
      if ((e.fields || []).length) {
        var fl = el('span', 'hs-ev-f');
        e.fields.slice(0, 6).forEach(function (fk) { fl.appendChild(el('span', 'hs-fchip', FIELD_WORDS[fk] || fk)); });
        if (e.fields.length > 6) fl.appendChild(el('span', 'hs-none', '+' + (e.fields.length - 6)));
        w.appendChild(fl);
      }
      if (e.note) w.appendChild(el('span', 'hs-ev-note', e.note));
      b.appendChild(w);
      var tm = el('span', 'hs-ev-t');
      tm.appendChild(el('span', '', ago(e.ts)));
      b.appendChild(tm);
      b.setAttribute('aria-label', T('History') + ': ' + (e.name || ''));
      b.onclick = function () { openHistory(e.type, e.oid); };
      li.appendChild(b);
      ul.appendChild(li);
    });
    body.appendChild(ul);
    if (d.total > list.length) body.appendChild(el('p', 'hs-foot', 'The latest ' + list.length + ' of ' + d.total + ' - a filter shows the others.'));
    if (typeof explainWhatWasDrawn === 'function') explainWhatWasDrawn(body);
  }

  function openTrash(type) {
    HS.view = mayTrash() ? 'trash' : 'changes';
    if (type) HS.f.type = String(type);
    var go = function () {
      if (typeof showTab === 'function') showTab('settings');
      if (typeof showPane === 'function') showPane('trash');
    };
    if ($('modal') && !$('modal').hidden) closeModal();
    go();
  }

  /* ==== A History button in the head of an object's window ======================== */
  var FORM_TYPE = {source: 'source', validation: 'validation', target: 'target', test: 'test'};
  function modalObject() {
    var m = $('modal');
    if (!m || m.hidden) return null;
    if (m.dataset.cert && /^\d+$/.test(m.dataset.cert)) return {type: 'cert', ref: Number(m.dataset.cert)};
    var t = $('modal-title');
    var words = t ? (typeof srcText === 'function' ? srcText(t) : t.textContent) : '';
    var hit = /^The (source|validation|target|test) (.+)$/.exec(String(words || '').trim());
    if (hit) return {type: FORM_TYPE[hit[1]], ref: {name: hit[2]}};
    return null;
  }
  function headButton() {
    var head = $('modal-x') ? $('modal-x').parentNode : null;
    if (!head) return;
    var old = head.querySelector('.hs-hbtn');
    var o = modalObject();
    var key = o ? o.type + ':' + JSON.stringify(o.ref) : '';
    if (old && old.dataset.key === key) return;
    if (old) old.remove();
    if (!o) return;
    var b = el('button', 'btn iconbtn small hs-hbtn');
    b.type = 'button';
    b.dataset.key = key;
    b.innerHTML = iconMarkup('history', 16);
    b.setAttribute('aria-label', T('History'));
    explain(b, 'History: every change of it - who, when, what - and restore a version.');
    b.onclick = function () { openHistory(o.type, o.ref); };
    head.insertBefore(b, $('modal-x'));
  }
  var soon = null;
  function headSoon() {
    if (soon) return;
    soon = setTimeout(function () { soon = null; try { headButton(); } catch (e) { } }, 30);
  }
  /* Watched: each popup (data-cert, shown or hidden) and its title - a popup stacked over another
     is a new one, appended to the page. */
  function watch(m) {
    if (!m || m._hsWatched || !window.MutationObserver) return;
    m._hsWatched = true;
    new MutationObserver(headSoon).observe(m, {attributes: true, attributeFilter: ['data-cert', 'hidden']});
    var t = m.querySelector('h3');
    if (t) new MutationObserver(headSoon).observe(t, {childList: true, characterData: true, subtree: true});
  }
  function watchAll() { Array.prototype.forEach.call(document.querySelectorAll('.modal'), watch); }
  if (window.MutationObserver) {
    new MutationObserver(function (recs) {
      for (var i = 0; i < recs.length; i++) {
        for (var j = 0; j < recs[i].addedNodes.length; j++) {
          var n = recs[i].addedNodes[j];
          if (n.nodeType === 1 && n.classList && n.classList.contains('modal')) { watch(n); headSoon(); }
        }
      }
    }).observe(document.body, {childList: true});
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchAll); else watchAll();
  }

  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.trash = function () { drawPane(); };
  window.acmeHistory = {open: openHistory, types: Object.keys(TYPE_ICON).filter(function (t) { return t !== 'dnsuse'; })};
  window.acmeTrash = {open: openTrash};
}());
