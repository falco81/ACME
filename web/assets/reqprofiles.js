/* reqprofiles.js - Settings → Request profiles (docs/request-profiles.md): what
   people may ask for on the portal with everything but the names set beforehand,
   from GET /api/reqprofiles, changed through acmelib/certs/api_reqprofiles.py.
   The pane's markup is a host in admin/certs-ui.php (<div id="rp-host">); a
   profile is edited in its own dialog with its own Save, as an owner of
   Owners and teams is. Everything is picked from the catalogs - sources,
   validations, key types, owners and teams, tags - never typed, but the
   domains. A full administrator changes; anybody signed in sees.
   Drawn as Owners and teams is (1.0.128): the view switcher, the search, cards,
   chips and segmented choices of teams.css (.tmx-*), and an editor of sections
   with icons, a side navigation and what the portal will show. */
'use strict';
(function () {
  var RP = {d: null, limits: {}};
  var UI = {view: 'cards', q: ''};
  var KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072',
                   'rsa-4096': 'RSA 4096', ed25519: 'Ed25519'};
  var EKU_WORDS = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
                   emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing'};
  var MODE_WORDS = [['off', 'not used'], ['fixed', 'fixed by the profile'], ['person', 'filled by the person']];
  var FIELD_WORDS = {O: 'Organisation', OU: 'Unit', L: 'City', ST: 'Region', C: 'Country', emailAddress: 'E-mail'};
  var VIEWS = [['cards', 'Cards', 'rp_cards'], ['table', 'Table', 'list']];
  var SECTIONS = [['general', 'General', 'info'], ['source', 'Where it comes from', 'in'], ['names', 'Names', 'globe'],
                  ['key', 'The key', 'key'], ['subject', 'The subject', 'person'], ['renewal', 'Use and renewal', 'refresh'],
                  ['approval', 'Approval and owner', 'check'], ['who', 'Who may use it', 'people']];

  if (typeof ICONS === 'object' && !ICONS.rp_link) {
    /* a chain link: a field taken from the base profile (1.0.138) */
    ICONS.rp_link = '<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1.3 1.3"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1.3-1.3"/>';
  }
  if (typeof ICONS === 'object' && !ICONS.rp_cards) {
    ICONS.rp_cards = '<rect x="3" y="3" width="7.5" height="7.5" rx="1.8"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.8"/>'
      + '<rect x="3" y="13.5" width="7.5" height="7.5" rx="1.8"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.8"/>';
  }

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function low(s) { return String(s || '').trim().toLowerCase(); }
  function fold(s) {
    s = String(s || '').toLowerCase();
    try { s = s.normalize('NFD').replace(/[̀-ͯ]/g, ''); } catch (e) { }
    return s;
  }
  function cell(cls, child) {
    var td = el('td', cls || '');
    if (child instanceof Node) td.appendChild(child);
    else if (child !== undefined && child !== null) td.textContent = String(child);
    return td;
  }
  function numBox(value, placeholder, min, max) {
    var i = el('input', 'tmx-num rpx-num');
    i.type = 'number';
    i.min = min;
    i.max = max;
    i.value = value === undefined || value === null ? '' : String(value);
    if (placeholder) i.placeholder = placeholder;
    return i;
  }
  /* teams.js's own small pieces (its ic, chip, empty, segmented), copied: the same markup and
     classes of teams.css, kept apart so neither file waits for the other */
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
  function empty(icon, title, words, button) {
    var b = el('div', 'tmx-empty');
    b.appendChild(ic(icon, 30));
    b.appendChild(el('b', '', title));
    if (words) b.appendChild(el('span', '', words));
    if (button) b.appendChild(button);
    return b;
  }
  /* a row of buttons standing for one choice; .value as a select, 'change' (bubbling) when changed */
  function segmented(pairs, value, label) {
    var s = el('div', 'tmx-seg small wrap');
    s.setAttribute('role', 'radiogroup');
    if (label) s.setAttribute('aria-label', tr(label));
    s.value = value;
    var paint = function () {
      s.querySelectorAll('.tmx-segb').forEach(function (x) {
        var on = x.dataset.v === String(s.value);
        x.classList.toggle('on', on);
        x.setAttribute('aria-checked', on ? 'true' : 'false');
      });
    };
    pairs.forEach(function (p) {
      var b = el('button', 'tmx-segb');
      b.type = 'button';
      b.dataset.v = p[0];
      b.setAttribute('role', 'radio');
      if (p[2]) b.appendChild(ic(p[2], 14));
      b.appendChild(p[3] ? data('span', '', p[1]) : el('span', '', p[1]));
      b.onclick = function () {
        if (String(s.value) === String(p[0])) return;
        s.value = p[0];
        paint();
        s.dispatchEvent(new Event('change', {bubbles: true}));
      };
      s.appendChild(b);
    });
    paint();
    s._paint = paint;
    return s;
  }
  function load() {
    return api('reqprofiles').then(function (d) { RP.d = d || {}; return RP.d; });
  }
  /* which teams' limits name each profile (their policy's "profiles") - from what Owners and
     teams has asked already; nothing more is asked for it */
  function loadLimits() {
    if (!window.ACME_TEAMS || typeof ACME_TEAMS.load !== 'function') return Promise.resolve({});
    return ACME_TEAMS.load().then(function (d) {
      var by = {};
      ((d && d.teams) || []).forEach(function (t) {
        var ps = t.policy && t.policy.profiles;
        if (!Array.isArray(ps)) return;
        ps.forEach(function (n) { (by[low(n)] = by[low(n)] || []).push(t.name); });
      });
      RP.limits = by;
      return by;
    }).catch(function () { return {}; });
  }
  function issuerOf(name) {
    return (((RP.d || {}).options || {}).issuers || []).filter(function (i) { return i.name === name; })[0] || null;
  }
  function keep() {
    try { localStorage.setItem('acme.reqprofiles.ui', JSON.stringify({view: UI.view})); } catch (e) { }
  }
  function kept() {
    try {
      var k = JSON.parse(localStorage.getItem('acme.reqprofiles.ui') || '{}') || {};
      if (k.view === 'cards' || k.view === 'table') UI.view = k.view;
    } catch (e) { }
  }

  /* ---- the pane --------------------------------------------------------------- */
  function drawPane() {
    var host = $('rp-host');
    if (!host) return;
    if (!UI.opened) { kept(); UI.opened = true; }
    Promise.all([load(), loadLimits()]).then(function (x) {
      var d = x[0];
      clear(host);
      var box = el('div', 'rpx');
      box.id = 'rpx';
      box.appendChild(bar(d));
      box.appendChild(el('p', 'note rpx-lede', 'Each is a kind of certificate people may ask for on the enrolment pages: they pick one, give its names (or send their CSR) and what it leaves to them; everything else is as it says. Who may use one is said by its teams - none: everybody who may sign in there. Asked for, a certificate is issued at once or waits for approval - by the certificate administrators here, and on the portal by the members with the right approve of the team that owns it.'));
      if (d.portal && (!d.portal.on || !d.portal.certs)) {
        var off = el('div', 'tmx-note warn rpx-portal-off');
        off.appendChild(ic('info', 18));
        off.appendChild(el('span', '', !d.portal.on ? 'The enrolment pages are switched off: nobody sees these profiles.'
          : 'Certificates on the portal is off: nobody sees these profiles there.'));
        var go = cmdButton('Open the setting', 'gear', 'small');
        /* to the setting itself, not to the top of the pane - a long way above it (hunt w8) */
        go.onclick = function () { location.hash = '#settings/portal'; toSetting(d.portal.on ? 'portal_cert' : 'portal'); };
        off.appendChild(go);
        box.appendChild(off);
      }
      var body = el('div', 'rpx-view');
      body.id = 'rpx-view';
      box.appendChild(body);
      host.appendChild(box);
      drawView();
    }).catch(function (e) { clear(host); oops(e); });
  }

  function bar(d) {
    var b = el('div', 'tmx-bar rpx-bar');
    var seg = el('div', 'tmx-views');
    seg.setAttribute('role', 'tablist');
    seg.setAttribute('aria-label', tr('Request profiles'));
    VIEWS.forEach(function (v) {
      var x = el('button', 'tmx-vbtn' + (UI.view === v[0] ? ' on' : ''));
      x.type = 'button';
      x.dataset.view = v[0];
      x.setAttribute('role', 'tab');
      x.setAttribute('aria-selected', UI.view === v[0] ? 'true' : 'false');
      x.appendChild(ic(v[2], 16));
      x.appendChild(el('span', '', v[1]));
      if (v[0] === 'cards') x.appendChild(data('span', 'tmx-n', num((d.profiles || []).length)));
      x.onclick = function () {
        UI.view = v[0];
        keep();
        seg.querySelectorAll('.tmx-vbtn').forEach(function (o) {
          o.classList.toggle('on', o === x);
          o.setAttribute('aria-selected', o === x ? 'true' : 'false');
        });
        drawView();
      };
      seg.appendChild(x);
    });
    b.appendChild(seg);
    var find = el('div', 'tmx-find rpx-find');
    find.appendChild(ic('search', 15));
    var q = el('input', 'rpx-q');
    q.type = 'search';
    q.id = 'rpx-q';
    q.placeholder = tr('Find a profile…');
    q.setAttribute('aria-label', tr('Find a profile…'));
    q.autocomplete = 'off';
    q.value = UI.q;
    noI18n(q);
    q.addEventListener('input', debounce(function () { UI.q = q.value; drawView(); }, 120));
    find.appendChild(q);
    b.appendChild(find);
    var right = el('div', 'tmx-bar-r');
    /* 1.0.138: the compliance check (reqprofiles-more.js) */
    if (window.ACME_RP_MORE) ACME_RP_MORE.bar(right, d);
    if (full()) {
      /* 1.0.140: a new profile from a template (rptemplates.js) */
      if (window.ACME_RP_TPL) ACME_RP_TPL.bar(right, d);
      var add = cmdButton('Add a profile', 'add', 'small primary');
      add.id = 'rp-add';
      add.onclick = function () { editProfile(null); };
      right.appendChild(add);
    }
    b.appendChild(right);
    return b;
  }

  function matches(p, q) {
    if (!q) return true;
    /* the domains as the card and the table show them too: *.example.com with wildcards */
    var sufs = (p.suffixes || []).map(function (s) { return p.wildcards ? '*.' + s : s; });
    var hay = [p.name, p.description, p.issuer, p.challenge, p.owner_team, p.base, p.ends && p.ends.successor].concat(sufs, p.teams || [], p.tags || [],
      (p.key_types || []).map(function (k) { return KEY_WORDS[k] || k; }), RP.limits[low(p.name)] || []);
    hay = fold(hay.join(' \u0001 '));
    return fold(q).split(/\s+/).filter(Boolean).every(function (w) { return hay.indexOf(w) >= 0; });
  }

  function drawView() {
    var body = $('rpx-view');
    if (!body) return;
    clear(body);
    var d = RP.d || {};
    var all = d.profiles || [];
    if (!all.length) {
      var first = full() ? cmdButton('Add the first profile', 'add', 'primary') : null;
      if (first) { first.id = 'rpx-first'; first.onclick = function () { editProfile(null); }; }
      body.appendChild(empty('rp_cards', 'No request profile yet', 'The portal asks with its free form (The enrolment pages), if that is set. A profile sets everything beforehand - the source, the names allowed, the key, the subject and approval: people give only the names.', first));
      return;
    }
    var shown = all.filter(function (p) { return matches(p, UI.q); });
    if (!shown.length) {
      body.appendChild(empty('search', 'Nothing found', 'No profile has these words in its name, description, source, domains or teams.'));
      return;
    }
    if (UI.view === 'table') body.appendChild(tableView(shown));
    else {
      var grid = el('div', 'rpx-grid');
      shown.forEach(function (p) { grid.appendChild(profileCard(p)); });
      body.appendChild(grid);
    }
    if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(body); } catch (e) { } }
  }

  function tools(p) {
    var t = el('div', 'rpx-tools');
    if (!full()) return t;
    var ed = iconButton('edit', 'Edit this profile');
    ed.classList.add('rp-edit');
    ed.onclick = function () { editProfile(p); };
    t.appendChild(ed);
    var dup = iconButton('copy', 'Duplicate this profile');
    dup.classList.add('rp-dup');
    dup.onclick = function () { duplicate(p); };
    t.appendChild(dup);
    var del = iconButton('trash', 'Delete this profile');
    del.classList.add('rp-del');
    del.onclick = function () { deleteProfile(p); };
    t.appendChild(del);
    return t;
  }
  function teamChip(t) {
    return window.ACME_TEAMS && ACME_TEAMS.teamOf && ACME_TEAMS.teamOf(t) ? dataChip(t, 'info', 'people') : dataChip(t, 'dim', 'people');
  }
  function fact(label, icon, kids) {
    var r = el('div', 'rpx-fact');
    var k = el('div', 'rpx-fact-k');
    k.appendChild(ic(icon, 13));
    k.appendChild(el('span', '', label));
    r.appendChild(k);
    var v = el('div', 'rpx-fact-v');
    kids.forEach(function (x) { if (x) v.appendChild(x); });
    r.appendChild(v);
    return r;
  }

  function profileCard(p) {
    var card = el('article', 'rpx-card rp-row' + (p.enabled ? '' : ' off') + ((p.problems || []).length ? ' bad' : ''));
    card.dataset.name = p.name;
    var head = el('div', 'rpx-card-h');
    var big = el('div', 'rpx-card-ic ' + (!p.enabled ? 'dim' : p.approval ? 'warn' : 'ok'));
    big.innerHTML = iconMarkup('lock', 20);
    head.appendChild(big);
    var w = el('div', 'rpx-card-w');
    var nm = el('div', 'rpx-card-n');
    nm.appendChild(data('b', 'rpx-name', p.name));
    /* one that ends is not offered (1.0.138): its "ends" chip says so instead */
    if (!(p.ends && p.enabled)) nm.appendChild(p.enabled ? chip('offered', 'ok', 'check') : chip('switched off', 'dim rp-off', 'ban'));
    if (window.ACME_RP_MORE) ACME_RP_MORE.chips(nm, p);
    w.appendChild(nm);
    if (p.description) w.appendChild(data('p', 'rpx-card-d rp-desc', p.description));
    head.appendChild(w);
    head.appendChild(tools(p));
    card.appendChild(head);
    (p.problems || []).forEach(function (x) {
      var n = el('div', 'tmx-note warn rpx-prob');
      n.appendChild(ic('info', 15));
      n.appendChild(el('span', '', x));
      card.appendChild(n);
    });
    var facts = el('div', 'rpx-facts');
    facts.appendChild(fact('Gives', 'in', [dataChip(p.issuer, 'info', 'in'), p.challenge ? dataChip(p.challenge, 'violet', 'shield') : null]));
    var names = [];
    (p.suffixes || []).forEach(function (s) { names.push(dataChip((p.wildcards ? '*.' : '') + s, 'dim mono rpx-dom')); });
    names.push(chip(p.wildcards ? 'wildcards too' : 'no wildcards', p.wildcards ? 'violet' : 'dim'));
    facts.appendChild(fact('Names', 'globe', names));
    var how = [];
    if (p.make_key) how.push(chip('key made by acme', 'dim', 'key'));
    if (p.csr) how.push(chip('CSR', 'violet'));
    (p.key_types || []).forEach(function (k) { how.push(dataChip(KEY_WORDS[k] || k, k === p.key_default ? 'info' : 'dim')); });
    facts.appendChild(fact('The key', 'key', how));
    facts.appendChild(fact('Approval', 'check', [chip(p.approval ? 'approved first' : 'issued at once', p.approval ? 'warn' : 'ok', p.approval ? 'clock' : 'check')]));
    var who = [];
    if (!(p.teams || []).length) who.push(chip('anybody who may sign in', 'dim', 'globe'));
    (p.teams || []).forEach(function (t) { who.push(teamChip(t)); });
    facts.appendChild(fact('Who may use it', 'people', who));
    var lim = RP.limits[low(p.name)] || [];
    if (lim.length) facts.appendChild(fact('In the limits of', 'shield', lim.map(function (t) { return dataChip(t, 'dim', 'people'); })));
    card.appendChild(facts);
    var foot = el('div', 'rpx-card-f');
    foot.appendChild(chip(num(p.used || 0) + ' certificate(s)', 'dim', 'lock'));
    if (window.ACME_RP_MORE) ACME_RP_MORE.foot(foot, p);
    card.appendChild(foot);
    if (full()) {
      card.classList.add('tappable');
      card.onclick = function (e) { if (!(e.target.closest && e.target.closest('button, a, input, select'))) editProfile(p); };
    }
    return card;
  }

  /* the dense view: the table it was before 1.0.128 */
  function tableView(rows) {
    return listTable(['Profile', 'Gives', 'How', 'Who may use it', {words: 'Certificates', cls: 'num'}, ''],
      rows, function (p) {
        var row = el('tr', 'rp-row');
        row.dataset.name = p.name;
        var nm = cell('', '');
        nm.appendChild(data('b', '', p.name));
        if (!p.enabled) nm.appendChild(el('span', 'tag dim rp-off', 'switched off'));
        if (window.ACME_RP_MORE) ACME_RP_MORE.chips(nm, p);
        if (p.description) nm.appendChild(data('div', 'muted small rp-desc', p.description));
        (p.problems || []).forEach(function (w) { nm.appendChild(el('div', 'small ct-bad', w)); });
        /* its history, a dry run, ending (1.0.138) */
        if (window.ACME_RP_MORE) ACME_RP_MORE.rowActs(nm, p);
        row.appendChild(nm);
        var gives = cell('small', '');
        var src = el('div', '');
        src.appendChild(data('span', 'tag info', p.issuer));
        if (p.challenge) { src.appendChild(document.createTextNode(' ')); src.appendChild(data('span', 'tag dim', p.challenge)); }
        gives.appendChild(src);
        var sx = el('div', 'rp-sufs');
        (p.suffixes || []).forEach(function (s) { sx.appendChild(data('span', 'ct-name dns', (p.wildcards ? '*.' : '') + s)); });
        gives.appendChild(sx);
        row.appendChild(gives);
        var how = cell('small', '');
        var hw = el('div', 'rp-how');
        if (p.make_key) hw.appendChild(el('span', 'tag dim', 'key made by acme'));
        if (p.csr) hw.appendChild(el('span', 'tag violet', 'CSR'));
        hw.appendChild(el('span', 'tag ' + (p.approval ? 'warn' : 'ok'), p.approval ? 'approved first' : 'issued at once'));
        how.appendChild(hw);
        how.appendChild(data('div', 'muted', (p.key_types || []).map(function (k) { return KEY_WORDS[k] || k; }).join(', ')));
        row.appendChild(how);
        var who = cell('small', '');
        if (!(p.teams || []).length) who.appendChild(el('span', 'muted', 'anybody who may sign in'));
        (p.teams || []).forEach(function (t) {
          who.appendChild(window.ACME_TEAMS ? ACME_TEAMS.ownerChip(t) : data('span', 'tag info', t));
          who.appendChild(document.createTextNode(' '));
        });
        row.appendChild(who);
        row.appendChild(cell('num', num(p.used || 0)));
        var td = el('td', 'rowtools');
        td.appendChild(tools(p));
        row.appendChild(td);
        if (full()) {
          row.classList.add('tappable');
          row.onclick = function (e) { if (!(e.target.closest && e.target.closest('button'))) editProfile(p); };
        }
        return row;
      }, 'plain rp-table|No request profile yet - the portal asks with its free form (The enrolment pages), if that is set');
  }

  /* A copy: the editor of a new profile filled in with this one, under a name not taken yet. */
  function duplicate(p) {
    var c = JSON.parse(JSON.stringify(p));
    var taken = {};
    ((RP.d || {}).profiles || []).forEach(function (x) { taken[low(x.name)] = 1; });
    /* "Web 2" copied again: "Web 3", when "Web" is there too */
    var n = 2, base = String(p.name || ''), m = /^(.+?)\s+\d+$/.exec(base);
    if (m && taken[low(m[1])]) base = m[1];
    while (taken[low(base + ' ' + n)]) n++;
    c.name = base + ' ' + n;
    delete c.used;
    delete c.problems;
    delete c.children;
    delete c.version;
    delete c.ends;
    editProfile(null, c);
  }

  /* ---- one profile: its dialog -------------------------------------------------- */
  var ROW_N = 0;
  /* a labelled row as the team's limits are (.tmx-prow): the label and what it means on the
     left, the box on the right - the label names its box */
  function row(label, control, says, cls) {
    var r = el('div', 'tmx-prow rpx-row' + (cls ? ' ' + cls : ''));
    var l = el('div', 'tmx-prow-l');
    var lab = el('label', 'rpx-lab', label);
    var target = control && control._input ? control._input : control && control._labelFor ? control._labelFor : control;
    if (target && target.nodeType === 1 && /^(INPUT|SELECT|TEXTAREA)$/.test(target.tagName)) {
      if (!target.id) target.id = 'rpx-f-' + (++ROW_N);
      lab.htmlFor = target.id;
    } else if (control && control.setAttribute) {
      lab.id = 'rpx-l-' + (++ROW_N);
      control.setAttribute('aria-labelledby', lab.id);
      lab.onclick = function () { var f = control.querySelector('button, input, select'); if (f) f.focus(); };
    }
    l.appendChild(lab);
    if (says) {
      var s = saysBlock(says);
      s.classList.add('tmx-prow-s');
      l.appendChild(s);
      r._says = s;
    }
    r.appendChild(l);
    var c = el('div', 'tmx-prow-c');
    c.appendChild(control);
    r.appendChild(c);
    return r;
  }
  function section(key, title, icon, note) {
    var s = el('section', 'rpx-sec');
    s.id = 'rpx-s-' + key;
    s.dataset.sec = key;
    var h = el('h3', 'tmx-sec-h rpx-sec-h');
    h.appendChild(ic(icon, 16));
    h.appendChild(el('span', '', title));
    s.appendChild(h);
    if (note) s.appendChild(el('p', 'note rpx-sec-n', note));
    return s;
  }
  /* a box ticked inside a pill */
  function pill(words, on, mono) {
    var lab = el('label', 'rpx-pill');
    var cb = el('input');
    cb.type = 'checkbox';
    cb.checked = !!on;
    lab.appendChild(cb);
    lab.appendChild(words instanceof Node ? words : el('span', '', words));
    if (mono) lab.appendChild(data('span', 'mono rpx-pill-m', mono));
    lab._input = cb;
    return lab;
  }
  /* the domains: chips, typed in (Enter, a comma, a space or a semicolon adds one, as the lines
     of the box before), with the domains of the other profiles and the teams' limits offered */
  function domainEditor(list, suggest, onChange) {
    var chosen = [];
    var box = el('div', 'tmx-list rpx-doms');
    var chips = el('div', 'tmx-lchips');
    box.appendChild(chips);
    var tx = textBox('', 'example.com', 'mono tmx-addtx rpx-addtx');
    tx.id = 'rp-f-suffixes';
    noI18n(tx);
    var dl = el('datalist');
    dl.id = 'rpx-doms-dl';
    noI18n(dl);
    suggest.forEach(function (s) { var o = el('option'); o.value = s; dl.appendChild(o); });
    tx.setAttribute('list', dl.id);
    var hint = el('span', 'muted small', 'Enter adds it');
    var add = function (text) {
      String(text || '').split(/[\s,;]+/).filter(Boolean).forEach(function (v) { if (chosen.indexOf(v) < 0) chosen.push(v); });
    };
    var paint = function () {
      clear(chips);
      chosen.forEach(function (v) {
        var c = dataChip(v, 'info mono rpx-dom');
        var x = el('button', 'tmx-chip-x');
        x.type = 'button';
        x.innerHTML = iconMarkup('close', 11);
        x.setAttribute('aria-label', tr('Take it off') + ': ' + v);
        x.onclick = function () { chosen = chosen.filter(function (y) { return y !== v; }); paint(); onChange(); tx.focus(); };
        c.appendChild(x);
        chips.appendChild(c);
      });
      chips.appendChild(tx);
      chips.appendChild(dl);
      chips.appendChild(hint);
    };
    var take = function () {
      if (!tx.value.trim()) return;
      add(tx.value);
      tx.value = '';
      paint();
      onChange();
      tx.focus();
    };
    tx.onkeydown = function (e) {
      if (e.key === 'Enter' || e.key === ',' || e.key === ' ' || e.key === ';') { e.preventDefault(); take(); }
      else if (e.key === 'Backspace' && !tx.value && chosen.length) { chosen.pop(); paint(); onChange(); tx.focus(); }
    };
    tx.addEventListener('paste', function () { setTimeout(function () { if (/[\s,;]/.test(tx.value)) take(); }, 0); });
    tx.addEventListener('change', function () { if (tx.value.trim() && suggest.indexOf(tx.value.trim()) >= 0) take(); });
    tx.onblur = function () {
      if (!tx.value.trim()) return;
      add(tx.value);
      tx.value = '';
      paint();
      onChange();
    };
    add((list || []).join(' '));
    paint();
    box._labelFor = tx;
    /* what is saved: the chips and whatever is still typed in the box */
    box._get = function () {
      var out = chosen.slice();
      String(tx.value || '').split(/[\s,;]+/).filter(Boolean).forEach(function (v) { if (out.indexOf(v) < 0) out.push(v); });
      return out;
    };
    return box;
  }
  /* a list picked from a catalog: chips, and "add…" with what is left (teams.js's listEditor) */
  function catalogPicker(list, catalog, noneWords, id, onChange) {
    var chosen = (list || []).filter(function (v) { return catalog.indexOf(v) >= 0; });
    var box = el('div', 'tmx-list rpx-cat');
    var chips = el('div', 'tmx-lchips');
    box.appendChild(chips);
    var sel = el('select', 'tmx-addsel');
    sel.id = id;
    noI18n(sel);
    var paint = function () {
      clear(chips);
      if (!chosen.length) chips.appendChild(chip(noneWords, 'dim', 'globe'));
      chosen.forEach(function (v) {
        var c = dataChip(v, 'info', 'people');
        c.dataset.v = v;
        var x = el('button', 'tmx-chip-x');
        x.type = 'button';
        x.innerHTML = iconMarkup('close', 11);
        x.setAttribute('aria-label', tr('Take it off') + ': ' + v);
        x.onclick = function () { chosen = chosen.filter(function (y) { return y !== v; }); paint(); onChange(); sel.focus(); };
        c.appendChild(x);
        chips.appendChild(c);
      });
      clear(sel);
      var left = catalog.filter(function (x) { return chosen.indexOf(x) < 0; });
      var o0 = el('option', '', tr('add…'));
      o0.value = '';
      sel.appendChild(o0);
      left.forEach(function (x) { var o = data('option', '', x); o.value = x; sel.appendChild(o); });
      sel.hidden = !left.length;
      chips.appendChild(sel);
    };
    sel.onchange = function () { if (sel.value) { chosen.push(sel.value); paint(); onChange(); sel.focus(); } };
    paint();
    box._labelFor = sel;
    box._get = function () { return catalog.filter(function (x) { return chosen.indexOf(x) >= 0; }); };
    return box;
  }

  /* ---- a base profile (1.0.138, docs/request-profiles.md "A base profile") ------------
     The groups of fields a profile may take from its base - reqprofiles.py's INHERIT_GROUPS. */
  var INHERIT = [['source', ['issuer', 'challenge']], ['suffixes', ['suffixes']], ['wildcards', ['wildcards']],
                 ['max_names', ['max_names']], ['make_key', ['make_key']], ['csr', ['csr']],
                 ['key_types', ['key_types', 'key_default']], ['auto_renew', ['auto_renew']],
                 ['renew_days', ['renew_days']], ['days', ['days']], ['eku', ['eku']], ['approval', ['approval']],
                 ['owner', ['owner', 'owner_team']], ['tags', ['tags']], ['teams', ['teams']], ['pfx', ['pfx']]];
  var SUBJ_KEYS = ['O', 'OU', 'L', 'ST', 'C', 'emailAddress'];
  /* chosen as a base the first time: everything inherited but the domains and the teams */
  function inheritAll() {
    return INHERIT.map(function (g) { return g[0]; }).concat(SUBJ_KEYS.map(function (k) { return 'subject.' + k; }))
      .filter(function (g) { return g !== 'suffixes' && g !== 'teams'; });
  }
  function profileOf(name) {
    return (((RP.d || {}).profiles) || []).filter(function (x) { return low(x.name) === low(name); })[0] || null;
  }
  /* the profiles based on this one, theirs too - never a base of it */
  function descendants(name) {
    var all = ((RP.d || {}).profiles) || [], out = [], want = [low(name)];
    while (want.length) {
      var got = all.filter(function (x) { return x.base && want.indexOf(low(x.base)) >= 0 && out.indexOf(x.name) < 0; })
        .map(function (x) { return x.name; });
      out = out.concat(got);
      want = got.map(low);
    }
    return out;
  }
  function copyOf(v) { return v === undefined ? v : JSON.parse(JSON.stringify(v)); }
  /* what the editor shows: the inherited groups as the base has them */
  function withBase(p, b, inh) {
    var out = copyOf(p);
    out.subject = copyOf(p.subject || {});
    inh.forEach(function (g) {
      if (g.indexOf('subject.') === 0) {
        var k = g.slice(8);
        out.subject[k] = copyOf((b.subject || {})[k] || {mode: 'off', value: ''});
        return;
      }
      (INHERIT.filter(function (x) { return x[0] === g; })[0] || [0, []])[1].forEach(function (k) { out[k] = copyOf(b[k]); });
    });
    return out;
  }
  function inhToggle(g, on, baseName, go) {
    var b = el('button', 'rpx-inh-t' + (on ? ' on' : ''));
    b.type = 'button';
    b.dataset.group = g;
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
    b.appendChild(ic(on ? 'rp_link' : 'edit', 12));
    b.appendChild(el('span', '', on ? 'inherited' : 'overridden'));
    var says = on ? tr('Inherited from {0} - press to override it here') : tr('Its own value here - press to inherit it from {0}');
    b.title = says.replace('{0}', baseName);
    b.setAttribute('aria-label', b.title);
    b.onclick = go;
    return b;
  }

  function editProfile(p, copy, again) {
    var orig = p;
    var isNew = !p;
    var o = (RP.d || {}).options || {};
    var iss = o.issuers || [];
    p = again ? again.values : p || copy || {name: '', description: '', enabled: true, issuer: (iss.filter(function (i) { return i.enabled; })[0] || iss[0] || {}).name || '',
              challenge: '', suffixes: [], wildcards: false, max_names: 5, make_key: true, csr: false,
              key_types: ['ec-256', 'rsa-2048'], key_default: 'ec-256', subject: {}, auto_renew: true,
              renew_days: null, days: null, eku: ['serverAuth'], approval: false, owner: 'person',
              owner_team: '', tags: [], teams: [], pfx: false};
    var st = again ? {base: again.base || '', inherit: (again.inherit || []).slice()}
      : {base: p.base || '', inherit: (p.inherit || []).slice()};
    var baseP = st.base ? profileOf(st.base) : null;
    if (baseP) p = withBase(p, baseP, st.inherit);
    var G = {};
    var reg = function (g, x) { (G[g] = G[g] || []).push(x); return x; };
    var f = {};
    var collect = function () { return {}; };
    var rerender = function (base, inherit, focus) {
      var vals = collect();
      var mb = $('modal-body');
      editProfile(orig, copy, {base: base, inherit: inherit, values: vals, scroll: mb ? mb.scrollTop : 0, focus: focus});
    };
    var shown = function () {};
    var preview = function () {};
    modal(isNew ? 'A new request profile' : 'Edit the request profile', function (body) {
      body.classList.add('tmx-dlg', 'rpx-dlg');
      var ed = el('div', 'rpx-ed');
      ed.id = 'rpx-ed';
      var nav = el('nav', 'rpx-nav');
      nav.setAttribute('aria-label', tr('Sections'));
      var main = el('div', 'rpx-main');
      var aside = el('aside', 'rpx-aside');
      ed.appendChild(nav);
      ed.appendChild(main);
      ed.appendChild(aside);
      body.appendChild(ed);
      var secs = {};
      SECTIONS.forEach(function (s) {
        var b = el('button', 'rpx-nb');
        b.type = 'button';
        b.dataset.sec = s[0];
        b.setAttribute('aria-label', tr(s[1]));
        b.appendChild(ic(s[2], 15));
        b.appendChild(el('span', '', s[1]));
        b.onclick = function () {
          var to = secs[s[0]];
          if (!to) return;
          var still = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;
          to.scrollIntoView({block: 'start', behavior: still ? 'auto' : 'smooth'});
          mark(s[0]);
          var first = to.querySelector('input:not([type=hidden]), select, textarea, button.tmx-segb');
          if (first) setTimeout(function () { try { first.focus({preventScroll: true}); } catch (e) { } }, still ? 0 : 350);
        };
        nav.appendChild(b);
      });
      var mark = function (k) {
        nav.querySelectorAll('.rpx-nb').forEach(function (b) {
          var on = b.dataset.sec === k;
          b.classList.toggle('on', on);
          if (on) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current');
        });
      };
      mark('general');
      /* the section in view marked as the popup's body scrolls (one handler, kept on the body) */
      if (!body._rpxScroll) {
        body._rpxScroll = true;
        body.addEventListener('scroll', function () {
          var e = $('rpx-ed');
          if (!e || !e._mark) return;
          var top = body.getBoundingClientRect().top + 90, at = null;
          e.querySelectorAll('.rpx-sec').forEach(function (s) { if (s.getBoundingClientRect().top <= top) at = s.dataset.sec; });
          if (body.scrollTop + body.clientHeight >= body.scrollHeight - 4) {
            var all = e.querySelectorAll('.rpx-sec');
            if (all.length) at = all[all.length - 1].dataset.sec;
          }
          e._mark(at || 'general');
        }, {passive: true});
      }
      ed._mark = mark;
      var add = function (s) { secs[s.dataset.sec] = s; main.appendChild(s); return s; };

      /* -- what it is -- */
      var sg = add(section('general', 'General', 'info'));
      f.name = textBox(p.name, 'Web servers', '');
      f.name.id = 'rp-f-name';
      noI18n(f.name);
      f.name.setAttribute('data-i18n-hint', '1');   /* its hint is words (1.0.88) */
      sg.appendChild(row('Name', f.name, 'What people pick on the portal. Letters, digits, spaces and . _ @ + -.'));
      f.enabled = switchBox(p.enabled);
      sg.appendChild(row('Offered', f.enabled, 'Off: kept, not shown on the portal.'));
      /* its base (1.0.138): none, or another profile - never itself nor one based on it */
      var nob = orig ? [low(orig.name)].concat(descendants(orig.name).map(low)) : [];
      var bases = (((RP.d || {}).profiles) || []).filter(function (x) { return nob.indexOf(low(x.name)) < 0; });
      if (bases.length || st.base) {
        f.base = selectBox([['', tr('none - it stands alone')]].concat(bases.map(function (x) { return [x.name, x.name]; })), st.base);
        f.base.id = 'rp-f-base';
        noI18n(f.base);
        f.base.onchange = function () {
          var nb = f.base.value;
          rerender(nb, nb ? (st.base ? st.inherit : inheritAll()) : [], '#base');
        };
        sg.appendChild(row('Based on', f.base, 'Another profile it takes its settings from: each field marked inherited follows it, and a change of it applies here too. Override a field to set it here.'));
        if (baseP) {
          var bn = el('div', 'tmx-note info rpx-basenote');
          bn.appendChild(ic('rp_link', 16));
          var bw = el('span', '');
          bw.appendChild(el('span', '', 'Inherited from the base'));
          bw.appendChild(document.createTextNode(': '));
          bw.appendChild(data('b', '', baseP.name));
          bw.appendChild(document.createTextNode(' · '));
          bw.appendChild(el('span', '', num(st.inherit.length) + ' field(s)'));
          bn.appendChild(bw);
          sg.appendChild(bn);
        }
      }
      f.desc = el('textarea', 'rp-f-desc');
      f.desc.rows = 2;
      f.desc.value = p.description || '';
      f.desc.placeholder = 'A TLS certificate for a web server of the company, issued at once.';
      noI18n(f.desc);
      f.desc.setAttribute('data-i18n-hint', '1');   /* its hint is words (1.0.88) */
      sg.appendChild(row('What it is for', f.desc, 'Shown to people on the portal beside its name.', 'rpx-wide'));

      /* -- where from, how proved -- */
      var ss = add(section('source', 'Where it comes from', 'in'));
      f.issuer = selectBox(iss.map(function (i) { return [i.name, i.name + ' · ' + tr(i.title) + (i.enabled ? '' : ' (' + tr('switched off') + ')')]; }), p.issuer);
      f.issuer.id = 'rp-f-issuer';
      noI18n(f.issuer);
      /* its source deleted (1.0.119): the box showed none - or the first - without a word; kept
         as it is, said, until another is chosen */
      f.gone = !isNew && p.issuer && !issuerOf(p.issuer) ? p.issuer : '';
      if (f.gone) {
        var og = data('option', '', p.issuer + ' · ' + tr('deleted'));
        og.value = p.issuer;
        f.issuer.insertBefore(og, f.issuer.firstChild);
        f.issuer.value = p.issuer;
      }
      ss.appendChild(reg('source', row('Source', f.issuer, 'Certificates → Sources.')));
      f.srcChips = el('div', 'rpx-srcchips');
      ss.appendChild(f.srcChips);
      f.goneSaid = el('p', 'note ct-bad rp-gone', tr('The source {0} of this profile is deleted: choose another.').replace('{0}', f.gone));
      noI18n(f.goneSaid);
      f.goneSaid.hidden = !f.gone;
      ss.appendChild(f.goneSaid);
      f.challenge = selectBox([['', tr('choose one')]].concat((o.challenges || []).map(function (c) { return [c.name, c.name]; })), p.challenge);
      f.challenge.id = 'rp-f-challenge';
      noI18n(f.challenge);
      f.challengeField = reg('source', row('Names proved by', f.challenge, 'Certificates → Validation: how its names are proved to the CA.'));
      ss.appendChild(f.challengeField);

      /* -- the names -- */
      var sn = add(section('names', 'Names', 'globe'));
      var doms = {};
      ((RP.d || {}).profiles || []).forEach(function (x) { (x.suffixes || []).forEach(function (s) { doms[s] = 1; }); });
      /* ...and the domains of the teams' limits, when Owners and teams has them */
      if (window.ACME_TEAMS && ACME_TEAMS.teamOf) {
        (o.teams || []).forEach(function (t) {
          var tt = ACME_TEAMS.teamOf(t);
          ((tt && tt.policy && tt.policy.suffixes) || []).forEach(function (s) { doms[s] = 1; });
        });
      }
      f.suffixes = domainEditor(p.suffixes || [], Object.keys(doms).sort(), function () { preview(); });
      sn.appendChild(reg('suffixes', row('Under these domains', f.suffixes, 'A name is the domain itself or under it. Enter, a comma or a space adds the one typed.', 'rpx-wide')));
      f.wild = switchBox(p.wildcards);
      sn.appendChild(reg('wildcards', row('Wildcards', f.wild, 'A name like *.example.com - only where the source gives them, proved by DNS.')));
      f.most = numBox(p.max_names || 1, '5', 1, 50);
      sn.appendChild(reg('max_names', row('Names in one certificate', f.most, 'At most.')));

      /* -- the key -- */
      var sk = add(section('key', 'The key', 'key'));
      f.make = switchBox(p.make_key);
      sk.appendChild(reg('make_key', row('acme makes the key', f.make, 'The key is made here and kept, sealed; the person downloads the certificate (and, if allowed below, a PFX with the key).')));
      f.csr = switchBox(p.csr);
      f.csrField = reg('csr', row('The person may send a CSR', f.csr, 'Made where the key is to stay. It is decoded and checked against this profile first; renewals use the same CSR.'));
      sk.appendChild(f.csrField);
      f.kts = {};
      var kw = el('div', 'rpx-pills rp-kts');
      (o.key_types || Object.keys(KEY_WORDS)).forEach(function (k) {
        var lab = pill(data('span', '', KEY_WORDS[k] || k), (p.key_types || []).indexOf(k) >= 0);
        lab._input.onchange = function () { fillDefault(); };
        lab._input.dataset.kt = k;
        f.kts[k] = lab._input;
        kw.appendChild(lab);
      });
      kw.setAttribute('role', 'group');
      sk.appendChild(reg('key_types', row('Key types allowed', kw, 'Of a key made here, and of a CSR sent in. Greyed: the source does not sign it.')));
      f.kdefHost = el('div', 'rpx-kdef');
      f.kdef = {value: p.key_default};
      sk.appendChild(reg('key_types', row('Offered first', f.kdefHost)));
      var fillDefault = function () {
        var keep2 = f.kdef.value || p.key_default;
        var ok = Object.keys(f.kts).filter(function (k) { return f.kts[k].checked && !f.kts[k].disabled; });
        var v = ok.indexOf(keep2) >= 0 ? keep2 : (ok[0] || '');
        clear(f.kdefHost);
        if (!ok.length) {
          f.kdef = {value: ''};
          f.kdefHost.appendChild(chip('none at all', 'crit', 'ban'));
        } else {
          f.kdef = segmented(ok.map(function (k) { return [k, KEY_WORDS[k] || k, null, true]; }), v, 'Offered first');
          f.kdef.id = 'rp-f-kdef';
          f.kdefHost.appendChild(f.kdef);
        }
        preview();
      };

      /* -- the subject -- */
      var sj = add(section('subject', 'The subject', 'person', 'Beside the names (the common name is the first of them). Fixed: put in as said here, whatever a CSR says. Filled by the person: what they type - or what their CSR says - with the value here as the default.'));
      f.subject = {};
      var sbox = el('div', 'rp-subj rpx-subj');
      (o.subject_fields || []).forEach(function (pair) {
        var k = pair[0], have = (p.subject || {})[k] || {mode: 'off', value: ''};
        var line = el('div', 'rp-subj-row rpx-subj-row');
        line.dataset.field = k;
        var lab = el('div', 'rp-subj-k rpx-subj-k');
        var lw = el('span', 'rpx-subj-w', FIELD_WORDS[k] || pair[1]);
        lw.id = 'rpx-subj-l-' + k;
        lab.appendChild(lw);
        lab.appendChild(data('span', 'mono muted small', ' ' + k));
        line.appendChild(lab);
        var mode = segmented(MODE_WORDS,
          MODE_WORDS.some(function (m) { return m[0] === have.mode; }) ? have.mode : 'off');
        mode.classList.add('rp-subj-mode');
        mode.dataset.field = k;
        mode.setAttribute('aria-labelledby', lw.id);
        var val = textBox(have.value || '', '', 'rp-subj-v rpx-subj-v');
        val.setAttribute('aria-labelledby', lw.id);
        noI18n(val);
        var paint = function () {
          val.hidden = mode.value === 'off';
          val.placeholder = mode.value === 'fixed' ? tr('its value') : tr('a default (may be empty)');
          line.classList.toggle('on', mode.value !== 'off');
        };
        mode.addEventListener('change', paint);
        paint();
        line.appendChild(mode);
        line.appendChild(val);
        f.subject[k] = {mode: mode, value: val};
        reg('subject.' + k, line);
        sbox.appendChild(line);
      });
      sj.appendChild(sbox);

      /* -- what it is for, renewal -- */
      var sr = add(section('renewal', 'Use and renewal', 'refresh'));
      f.auto = switchBox(p.auto_renew);
      sr.appendChild(reg('auto_renew', row('Renew by itself', f.auto, 'Off: only when somebody presses Renew now.')));
      f.rdays = numBox(p.renew_days, '30', 1, 3650);
      sr.appendChild(reg('renew_days', row('Days before the end', f.rdays, 'Empty: as Renewal and notices says.')));
      f.days = numBox(p.days, '', 1, 36500);
      f.daysField = reg('days', row('Valid for (days)', f.days, 'Empty: what the source gives. A public certificate is valid for at most 200 days from 15 March 2026, 100 from 15 March 2027 and 47 from 15 March 2029 (CA/Browser Forum).'));
      sr.appendChild(f.daysField);
      f.eku = {};
      var ek = el('div', 'rpx-pills ct-ekus rp-ekus');
      ek.setAttribute('role', 'group');
      (o.ekus || Object.keys(EKU_WORDS)).forEach(function (e) {
        var lab = pill(EKU_WORDS[e] || e, (p.eku || []).indexOf(e) >= 0, e);
        f.eku[e] = lab._input;
        ek.appendChild(lab);
      });
      sr.appendChild(reg('eku', row('Used for', ek, 'A public CA puts in what it puts in; an authority of your own what is asked.', 'rpx-wide')));

      /* -- approval, owner, tags -- */
      var sa = add(section('approval', 'Approval and owner', 'check'));
      f.approval = segmented([['0', 'issued at once', 'check'], ['1', 'waits for approval', 'clock']], p.approval ? '1' : '0', 'When asked for');
      f.approval.id = 'rp-f-approval';
      sa.appendChild(reg('approval', row('When asked for', f.approval, 'Approved by the certificate administrators (Certificates → waiting for approval), and on the portal by the members with the right approve of the team that owns it.')));
      f.owner = segmented([['person', 'the person who asks', 'person'], ['team', 'a team they pick (where they may ask)', 'people'], ['fixed', 'this team', 'pin']],
        ['person', 'team', 'fixed'].indexOf(p.owner) >= 0 ? p.owner : 'person', 'Whose it is');
      f.owner.id = 'rp-f-owner';
      sa.appendChild(reg('owner', row('Whose it is', f.owner, 'Owners and teams: the members of its team see it on the portal and are told when it fails.')));
      f.oteam = selectBox([['', tr('choose a team')]].concat((o.teams || []).map(function (t) { return [t, t]; })), p.owner_team || '');
      f.oteam.id = 'rp-f-oteam';
      noI18n(f.oteam);
      f.oteamField = reg('owner', row('The team', f.oteam));
      sa.appendChild(f.oteamField);
      f.pfx = switchBox(p.pfx);
      f.pfxField = reg('pfx', row('PFX with the key', f.pfx, 'The person may download the certificate with its private key, locked with a password they choose. Only for a key acme made.'));
      sa.appendChild(f.pfxField);
      f.tags = window.ACME_TEAMS ? ACME_TEAMS.tagPicker(p.tags || []) : null;
      if (f.tags) {
        var tsel = f.tags.querySelector('select');
        if (tsel) f.tags._labelFor = tsel;
        sa.appendChild(reg('tags', row('Tags', f.tags, 'Put on every certificate asked for from it, beside "portal".')));
      }

      /* -- who may use it -- */
      var sw = add(section('who', 'Who may use it', 'people', 'The members of these teams with the right to ask for new ones (Owners and teams). None chosen: everybody who may sign in to the enrolment pages.'));
      if (!(o.teams || []).length) {
        sw.appendChild(el('span', 'muted small', 'No owner or team yet - Settings → Owners and teams.'));
        f.teams = {_get: function () { return []; }};
      } else {
        f.teams = catalogPicker(p.teams || [], o.teams || [], 'anybody who may sign in', 'rp-f-teams', function () { preview(); });
        sw.appendChild(reg('teams', row('Teams', f.teams, null, 'rpx-wide')));
      }
      f.said = el('div', 'said');
      main.appendChild(f.said);

      /* -- what the portal will show -- */
      var prev = el('div', 'rpx-prev');
      prev.id = 'rpx-prev';
      var ph = el('div', 'rpx-prev-h');
      ph.appendChild(ic('eye', 15));
      ph.appendChild(el('span', '', 'On the portal'));
      prev.appendChild(ph);
      var pbody = el('div', 'rpx-prev-b');
      prev.appendChild(pbody);
      aside.appendChild(prev);
      preview = function () {
        clear(pbody);
        var name = f.name.value.trim();
        var card = el('div', 'rpx-pc');
        var top = el('div', 'rpx-pc-t');
        top.appendChild(name ? data('b', '', name) : el('b', 'muted', 'Name'));
        var waits = f.approval.value === '1';
        top.appendChild(chip(waits ? 'approved first' : 'issued at once', waits ? 'warn' : 'ok'));
        card.appendChild(top);
        var desc = f.desc.value.trim();
        if (desc) card.appendChild(data('div', 'rpx-pc-d', desc));
        var cs = el('div', 'rpx-pc-c');
        if (f.issuer.value) cs.appendChild(dataChip(f.issuer.value, 'info'));
        var sx = f.suffixes._get();
        sx.slice(0, 3).forEach(function (s) { cs.appendChild(dataChip((f.wild._get() ? '*.' : '') + s, 'dim mono')); });
        if (sx.length > 3) cs.appendChild(data('span', 'muted small', '+' + (sx.length - 3)));
        var make = !!f.make._get();
        if (make) cs.appendChild(chip('key made for you', 'dim'));
        if (f.csr._get()) cs.appendChild(chip('your CSR', 'violet'));
        if (!f.daysField.hidden && f.days.value) cs.appendChild(chip(num(Number(f.days.value)) + ' days', 'dim'));
        Object.keys(f.eku).forEach(function (e) { if (f.eku[e].checked) cs.appendChild(chip(EKU_WORDS[e] || e, 'dim')); });
        if (make && f.pfx._get()) cs.appendChild(chip('PFX with the key', 'dim'));
        card.appendChild(cs);
        pbody.appendChild(card);
        /* what they give */
        var give = el('div', 'rpx-pg');
        give.appendChild(el('div', 'rpx-pg-h', 'They give'));
        var gl = el('ul', 'rpx-pg-l');
        var li = function (icon, words) { var x = el('li'); x.appendChild(ic(icon, 13)); x.appendChild(words instanceof Node ? words : el('span', '', words)); gl.appendChild(x); };
        li('globe', 'at most ' + num(Number(f.most.value || 1)) + ' name(s)');
        var mine = Object.keys(f.subject).filter(function (k) { return f.subject[k].mode.value === 'person'; });
        mine.forEach(function (k) { li('person', el('span', '', FIELD_WORDS[k] || k)); });
        if (f.kdef.value) {
          var kk = el('span', '');
          kk.appendChild(el('span', '', 'Offered first'));
          kk.appendChild(document.createTextNode(': '));
          kk.appendChild(data('span', '', KEY_WORDS[f.kdef.value] || f.kdef.value));
          li('key', kk);
        }
        give.appendChild(gl);
        pbody.appendChild(give);
        var fixed = Object.keys(f.subject).filter(function (k) { return f.subject[k].mode.value === 'fixed'; });
        var fx = el('div', 'rpx-pg');
        fx.appendChild(el('div', 'rpx-pg-h', 'In the subject'));
        var fc = el('div', 'rpx-pc-c');
        if (!fixed.length) fc.appendChild(el('span', 'muted small', 'nothing beside the names'));
        fixed.forEach(function (k) {
          var t = el('span', '');
          t.appendChild(el('span', '', FIELD_WORDS[k] || k));
          t.appendChild(document.createTextNode(': '));
          t.appendChild(data('span', '', f.subject[k].value.value.trim()));
          fc.appendChild(chip(t, 'dim'));
        });
        fx.appendChild(fc);
        pbody.appendChild(fx);
        var wh = el('div', 'rpx-pg');
        wh.appendChild(el('div', 'rpx-pg-h', 'Who may use it'));
        var wc = el('div', 'rpx-pc-c');
        var tl = f.teams._get();
        if (!tl.length) wc.appendChild(chip('anybody who may sign in', 'dim', 'globe'));
        tl.forEach(function (t) { wc.appendChild(dataChip(t, 'info', 'people')); });
        wh.appendChild(wc);
        pbody.appendChild(wh);
        if (!f.enabled._get()) {
          var off = el('div', 'tmx-note warn rpx-prev-off');
          off.appendChild(ic('ban', 15));
          off.appendChild(el('span', '', 'Off: kept, not shown on the portal.'));
          pbody.appendChild(off);
        }
      };
      var later = null;
      var soon = function () { if (later) return; later = setTimeout(function () { later = null; preview(); }, 60); };
      main.addEventListener('input', soon);
      main.addEventListener('change', soon);
      main.addEventListener('click', soon);

      /* What the source takes, said as it is chosen. */
      shown = function () {
        f.goneSaid.hidden = !f.gone || f.issuer.value !== f.gone;
        /* the source deleted: what it took is not known - the boxes left as they were */
        if (f.gone && f.issuer.value === f.gone) {
          f.oteamField.hidden = f.owner.value !== 'fixed';
          f.pfxField.hidden = !f.make._get();
          clear(f.srcChips);
          preview();
          return;
        }
        var i = issuerOf(f.issuer.value) || {};
        clear(f.srcChips);
        if (i.name) {
          if (i.public) f.srcChips.appendChild(chip('public', 'info', 'globe'));
          f.srcChips.appendChild(chip(i.csr ? 'CSR' : 'key made by acme', i.csr ? 'violet' : 'dim', 'key'));
          if (i.wildcards !== false) f.srcChips.appendChild(chip('wildcards too', 'dim'));
          if (!i.enabled) f.srcChips.appendChild(chip('switched off', 'crit', 'ban'));
        }
        f.challengeField.hidden = !i.needs_validation;
        f.wild._input.disabled = i.wildcards === false;
        if (i.wildcards === false) f.wild._input.checked = false;
        f.csr._input.disabled = !i.csr;
        if (!i.csr) f.csr._input.checked = false;
        var says = f.csrField._says;
        if (says) says.textContent = i.csr ? tr('Made where the key is to stay. It is decoded and checked against this profile first; renewals use the same CSR.')
          : tr('This source signs only a key acme makes and holds.');
        Object.keys(f.kts).forEach(function (k) {
          var ok = (i.key_types || []).indexOf(k) >= 0;
          f.kts[k].disabled = !ok;
          if (!ok) f.kts[k].checked = false;
          f.kts[k].parentNode.classList.toggle('rp-grey', !ok);
        });
        f.daysField.hidden = !i.choose_days;
        f.oteamField.hidden = f.owner.value !== 'fixed';
        f.pfxField.hidden = !f.make._get();
        fillDefault();
      };
      f.issuer.addEventListener('change', shown);
      f.owner.addEventListener('change', shown);
      f.make._input.addEventListener('change', shown);
      shown();
      fillDefault();
      /* inherited or overridden, field by field (1.0.138): an inherited one shows its base's
         value and cannot be changed here - its toggle overrides it */
      if (baseP) Object.keys(G).forEach(function (g) {
        var on = st.inherit.indexOf(g) >= 0;
        G[g].forEach(function (r, i) {
          r.classList.add('rpx-hasinh');
          r.classList.toggle('rpx-inh', on);
          var parts = r.classList.contains('rpx-subj-row') ? Array.prototype.slice.call(r.children, 1)
            : [r.querySelector('.tmx-prow-c')];
          parts.forEach(function (x) { if (x && on) { x.setAttribute('inert', ''); x.classList.add('rpx-locked'); } });
          if (i) return;
          var where = r.classList.contains('rpx-subj-row') ? r.querySelector('.rpx-subj-k') : r.querySelector('.tmx-prow-l');
          if (!where) return;
          where.appendChild(inhToggle(g, on, baseP.name, function () {
            var inh = st.inherit.filter(function (x) { return x !== g; });
            if (!on) inh.push(g);
            rerender(st.base, inh, g);
          }));
        });
      });
      collect = function () {
        var subject = {};
        Object.keys(f.subject).forEach(function (k) {
          subject[k] = {mode: f.subject[k].mode.value, value: f.subject[k].value.value.trim()};
        });
        return {name: f.name.value.trim(), description: f.desc.value.trim(), enabled: f.enabled._get(),
                issuer: f.issuer.value, challenge: f.challengeField.hidden ? '' : f.challenge.value,
                suffixes: f.suffixes._get(), wildcards: f.wild._get(),
                max_names: Number(f.most.value || 1), make_key: f.make._get(), csr: f.csr._get(),
                key_types: Object.keys(f.kts).filter(function (k) { return f.kts[k].checked; }),
                key_default: f.kdef.value, subject: subject, auto_renew: f.auto._get(),
                renew_days: f.rdays.value ? Number(f.rdays.value) : null,
                days: !f.daysField.hidden && f.days.value ? Number(f.days.value) : null,
                eku: Object.keys(f.eku).filter(function (k) { return f.eku[k].checked; }),
                approval: f.approval.value === '1', owner: f.owner.value, owner_team: f.oteam.value,
                tags: f.tags ? f.tags._get() : [], pfx: f.make._get() ? f.pfx._get() : 0,
                teams: f.teams._get(), base: st.base, inherit: st.base ? st.inherit.slice() : []};
      };
      if (again) {
        try { MODAL_TYPED = MODAL_GEN; } catch (e) { }   /* what was typed is still to be saved */
        /* after the popup's own focus (modal() sets it a moment after this is drawn) */
        setTimeout(function () { setTimeout(function () {
          var mb = $('modal-body');
          if (mb) mb.scrollTop = again.scroll || 0;
          var t = again.focus === '#base' ? $('rp-f-base')
            : body.querySelector('.rpx-inh-t[data-group="' + again.focus + '"]');
          if (t) { try { t.focus({preventScroll: true}); } catch (e) { } }
        }, 0); }, 0);
      }
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var out = collect();
          if (!isNew) out.old_name = orig.name;
          /* the profile as it was read: saved by someone else since, refused - not written over (hunt w6) */
          if (!isNew && orig.updated) out.was_updated = orig.updated;
          f.said.className = 'said';
          f.said.textContent = '';
          busy(b, true);
          api('reqprofiles/save', out).then(function (r) {
            /* its name not run through the translation (1.0.88: "Client certificate" came out
               Czech in the toast) */
            toast('The request profile is saved', 'good');
            closeModal();
            drawPane();
          }).catch(function (e) {
            f.said.className = 'said bad';
            f.said.textContent = String(e.message || e);
            try { f.said.scrollIntoView({block: 'nearest'}); } catch (x) { }
          }).then(function () { busy(b, false); });
        }}], 'large');
  }

  function deleteProfile(p) {
    /* the base of others (1.0.138): they take what they inherit as their own first */
    if ((p.children || []).length) {
      modal('Delete the request profile', function (body) {
        var n = el('div', 'tmx-note warn rpx-delbase');
        n.appendChild(ic('rp_link', 18));
        var w = el('div', '');
        w.appendChild(el('p', '', 'It is the base of these profiles. Deleted, each of them takes what it inherits from it as its own and stands alone - nothing they give changes:'));
        var cs = el('div', 'rpx-pc-c');
        p.children.forEach(function (c) { cs.appendChild(dataChip(c, 'info', 'rp_link')); });
        w.appendChild(cs);
        n.appendChild(w);
        body.appendChild(n);
        body.appendChild(el('p', 'note', 'The certificates asked for from it stay as they are.'));
      }, [{words: 'No, leave it', close: true},
          {words: 'Delete it', cls: 'danger', icon: 'trash', close: true, once: true, go: function () {
            api('reqprofiles/delete', {name: p.name, detach: true}).then(function () { toast('The request profile is deleted', 'good'); drawPane(); }).catch(oops);
          }}], true);
      return;
    }
    confirmThen('Delete the request profile', htmlText(tr('The request profile {0} is deleted. The certificates asked for from it stay as they are.').replace('{0}', p.name)),
      'Delete it', function () {
        api('reqprofiles/delete', {name: p.name}).then(function (r) { toast('The request profile is deleted', 'good'); drawPane(); }).catch(oops);
      });
  }

  function tr(s) {
    try { var got = typeof i18nText === 'function' ? i18nText(s) : null; return got || s; } catch (e) { return s; }
  }

  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.reqprofiles = function () { drawPane(); };
  /* for a profile made from a template (rptemplates.js, 1.0.140): the pane drawn again, a
     profile's editor - of one saved, or of a new one filled in */
  window.ACME_RP = {redraw: drawPane, edit: function (p, copy) { editProfile(p || null, copy); },
                    data: function () { return RP.d; }};
  /* A page that opened on this pane drew it before this file came. */
  if (typeof PANE === 'string' && PANE === 'reqprofiles') drawPane();
})();
