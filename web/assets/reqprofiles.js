/* reqprofiles.js - Settings → Request profiles (docs/request-profiles.md): what
   people may ask for on the portal with everything but the names set beforehand,
   from GET /api/reqprofiles, changed through acmelib/certs/api_reqprofiles.py.
   The pane's markup is a host in admin/certs-ui.php (<div id="rp-host">); a
   profile is edited in its own dialog with its own Save, as an owner of
   Owners and teams is. Everything is picked from the catalogs - sources,
   validations, key types, owners and teams, tags - never typed, but the
   domains. A full administrator changes; anybody signed in sees. */
'use strict';
(function () {
  var RP = {d: null};
  var KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072',
                   'rsa-4096': 'RSA 4096', ed25519: 'Ed25519'};
  var EKU_WORDS = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
                   emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing'};
  var MODE_WORDS = [['off', 'not used'], ['fixed', 'fixed by the profile'], ['person', 'filled by the person']];
  var FIELD_WORDS = {O: 'Organisation', OU: 'Unit', L: 'City', ST: 'Region', C: 'Country', emailAddress: 'E-mail'};

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function cell(cls, child) {
    var td = el('td', cls || '');
    if (child instanceof Node) td.appendChild(child);
    else if (child !== undefined && child !== null) td.textContent = String(child);
    return td;
  }
  function numBox(value, placeholder, min, max) {
    var i = el('input');
    i.type = 'number';
    i.min = min;
    i.max = max;
    i.value = value === undefined || value === null ? '' : String(value);
    if (placeholder) i.placeholder = placeholder;
    return i;
  }
  function load() {
    return api('reqprofiles').then(function (d) { RP.d = d || {}; return RP.d; });
  }
  function issuerOf(name) {
    return (((RP.d || {}).options || {}).issuers || []).filter(function (i) { return i.name === name; })[0] || null;
  }

  /* ---- the pane --------------------------------------------------------------- */
  function drawPane() {
    var host = $('rp-host');
    if (!host) return;
    load().then(function (d) {
      clear(host);
      host.appendChild(listCard(d));
      explainWhatWasDrawn(host);
    }).catch(function (e) { clear(host); oops(e); });
  }

  function listCard(d) {
    var card = el('div', 'card full rp');
    var h = el('h2', '', 'Request profiles');
    var right = el('span', 'right btnrow');
    if (full()) {
      var add = cmdButton('Add a profile', 'add', 'small primary');
      add.id = 'rp-add';
      add.onclick = function () { editProfile(null); };
      right.appendChild(add);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Each is a kind of certificate people may ask for on the enrolment pages: they pick one, give its names (or send their CSR) and what it leaves to them; everything else is as it says. Who may use one is said by its teams - none: everybody who may sign in there. Asked for, a certificate is issued at once or waits for approval - by the certificate administrators here, and on the portal by the members with the right approve of the team that owns it.'));
    if (d.portal && (!d.portal.on || !d.portal.certs)) {
      var off = el('div', 'tm-portal-off');
      off.appendChild(el('span', '', !d.portal.on ? 'The enrolment pages are switched off: nobody sees these profiles.'
        : 'Certificates on the portal is off: nobody sees these profiles there.'));
      var go = cmdButton('Open the setting', 'gear', 'small');
      go.onclick = function () { location.hash = '#settings/portal'; };
      off.appendChild(go);
      card.appendChild(off);
    }
    card.appendChild(listTable(['Profile', 'Gives', 'How', 'Who may use it', {words: 'Certificates', cls: 'num'}, ''],
      d.profiles || [], function (p) {
        var row = el('tr', 'rp-row');
        row.dataset.name = p.name;
        var nm = cell('', '');
        nm.appendChild(data('b', '', p.name));
        if (!p.enabled) nm.appendChild(el('span', 'tag dim rp-off', 'switched off'));
        if (p.description) nm.appendChild(data('div', 'muted small rp-desc', p.description));
        (p.problems || []).forEach(function (w) { nm.appendChild(el('div', 'small ct-bad', w)); });
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
        var tools = el('td', 'rowtools');
        if (full()) {
          var ed = iconButton('edit', 'Edit this profile');
          ed.classList.add('rp-edit');
          ed.onclick = function () { editProfile(p); };
          tools.appendChild(ed);
          var del = iconButton('trash', 'Delete this profile');
          del.classList.add('rp-del');
          del.onclick = function () { deleteProfile(p); };
          tools.appendChild(del);
        }
        row.appendChild(tools);
        if (full()) {
          row.classList.add('tappable');
          row.onclick = function (e) { if (!(e.target.closest && e.target.closest('button'))) editProfile(p); };
        }
        return row;
      }, 'plain rp-table|No request profile yet - the portal asks with its free form (The enrolment pages), if that is set'));
    return card;
  }

  /* ---- one profile: its dialog -------------------------------------------------- */
  function editProfile(p) {
    var isNew = !p;
    var o = (RP.d || {}).options || {};
    var iss = o.issuers || [];
    p = p || {name: '', description: '', enabled: true, issuer: (iss.filter(function (i) { return i.enabled; })[0] || iss[0] || {}).name || '',
              challenge: '', suffixes: [], wildcards: false, max_names: 5, make_key: true, csr: false,
              key_types: ['ec-256', 'rsa-2048'], key_default: 'ec-256', subject: {}, auto_renew: true,
              renew_days: null, days: null, eku: ['serverAuth'], approval: false, owner: 'person',
              owner_team: '', tags: [], teams: [], pfx: false};
    var f = {};
    var shown = function () {};
    modal(isNew ? 'A new request profile' : 'Edit the request profile', function (body) {
      /* -- what it is -- */
      var g = el('div', 'formgrid');
      f.name = textBox(p.name, 'Web servers', '');
      f.name.id = 'rp-f-name';
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'What people pick on the portal. Letters, digits, spaces and . _ @ + -.'));
      f.enabled = switchBox(p.enabled);
      g.appendChild(formField('Offered', f.enabled, 'Off: kept, not shown on the portal.'));
      f.desc = el('textarea', 'rp-f-desc');
      f.desc.rows = 2;
      f.desc.value = p.description || '';
      f.desc.placeholder = 'A TLS certificate for a web server of the company, issued at once.';
      noI18n(f.desc);
      f.desc.setAttribute('data-i18n-hint', '1');   /* its hint is words (1.0.88) */
      var df = formField('What it is for', f.desc, 'Shown to people on the portal beside its name.');
      df.classList.add('wide');
      g.appendChild(df);
      body.appendChild(g);
      /* -- where from, how proved -- */
      body.appendChild(el('h3', 'peek-h', 'Where it comes from'));
      var g2 = el('div', 'formgrid');
      f.issuer = selectBox(iss.map(function (i) { return [i.name, i.name + ' · ' + tr(i.title) + (i.enabled ? '' : ' (' + tr('switched off') + ')')]; }), p.issuer);
      f.issuer.id = 'rp-f-issuer';
      noI18n(f.issuer);
      g2.appendChild(formField('Source', f.issuer, 'Certificates → Sources.'));
      f.challenge = selectBox([['', tr('choose one')]].concat((o.challenges || []).map(function (c) { return [c.name, c.name]; })), p.challenge);
      f.challenge.id = 'rp-f-challenge';
      noI18n(f.challenge);
      f.challengeField = formField('Names proved by', f.challenge, 'Certificates → Validation: how its names are proved to the CA.');
      g2.appendChild(f.challengeField);
      body.appendChild(g2);
      /* -- the names -- */
      body.appendChild(el('h3', 'peek-h', 'Names'));
      var g3 = el('div', 'formgrid');
      f.suffixes = el('textarea', 'mono rp-f-sufs');
      f.suffixes.rows = 2;
      f.suffixes.spellcheck = false;
      f.suffixes.value = (p.suffixes || []).join('\n');
      f.suffixes.placeholder = 'example.com\nintra.example.com';
      noI18n(f.suffixes);
      f.suffixes.id = 'rp-f-suffixes';
      g3.appendChild(formField('Under these domains', f.suffixes, 'One a line: a name is the domain itself or under it.'));
      f.wild = switchBox(p.wildcards);
      g3.appendChild(formField('Wildcards', f.wild, 'A name like *.example.com - only where the source gives them, proved by DNS.'));
      f.most = numBox(p.max_names || 1, '5', 1, 50);
      g3.appendChild(formField('Names in one certificate', f.most, 'At most.'));
      body.appendChild(g3);
      /* -- the key -- */
      body.appendChild(el('h3', 'peek-h', 'The key'));
      var g4 = el('div', 'formgrid');
      f.make = switchBox(p.make_key);
      g4.appendChild(formField('acme makes the key', f.make, 'The key is made here and kept, sealed; the person downloads the certificate (and, if allowed below, a PFX with the key).'));
      f.csr = switchBox(p.csr);
      f.csrField = formField('The person may send a CSR', f.csr, 'Made where the key is to stay. It is decoded and checked against this profile first; renewals use the same CSR.');
      g4.appendChild(f.csrField);
      body.appendChild(g4);
      f.kts = {};
      var kw = el('div', 'rp-kts');
      (o.key_types || Object.keys(KEY_WORDS)).forEach(function (k) {
        var lab = el('label', 'set-check');
        var cb = el('input');
        cb.type = 'checkbox';
        cb.checked = (p.key_types || []).indexOf(k) >= 0;
        cb.onchange = function () { fillDefault(); };
        f.kts[k] = cb;
        lab.appendChild(cb);
        lab.appendChild(el('span', '', KEY_WORDS[k] || k));
        kw.appendChild(lab);
      });
      body.appendChild(formField('Key types allowed', kw, 'Of a key made here, and of a CSR sent in. Greyed: the source does not sign it.'));
      f.kdef = selectBox([], p.key_default);
      noI18n(f.kdef);
      var fillDefault = function () {
        var keep = f.kdef.value || p.key_default;
        clear(f.kdef);
        Object.keys(f.kts).forEach(function (k) {
          if (!f.kts[k].checked || f.kts[k].disabled) return;
          var op = el('option', '', KEY_WORDS[k] || k);
          op.value = k;
          f.kdef.appendChild(op);
        });
        f.kdef.value = keep;
        if (f.kdef.value !== keep && f.kdef.options.length) f.kdef.value = f.kdef.options[0].value;
      };
      body.appendChild(formField('Offered first', f.kdef));
      /* -- the subject -- */
      body.appendChild(el('h3', 'peek-h', 'The subject'));
      body.appendChild(el('p', 'note', 'Beside the names (the common name is the first of them). Fixed: put in as said here, whatever a CSR says. Filled by the person: what they type - or what their CSR says - with the value here as the default.'));
      f.subject = {};
      var sg = el('div', 'rp-subj');
      (o.subject_fields || []).forEach(function (pair) {
        var k = pair[0], have = (p.subject || {})[k] || {mode: 'off', value: ''};
        var line = el('div', 'rp-subj-row');
        var lab = el('label', 'rp-subj-k');
        lab.appendChild(el('span', '', FIELD_WORDS[k] || pair[1]));
        lab.appendChild(data('span', 'mono muted small', ' ' + k));
        line.appendChild(lab);
        var mode = selectBox(MODE_WORDS, have.mode || 'off');
        mode.className = 'rp-subj-mode';
        mode.dataset.field = k;
        var val = textBox(have.value || '', '', 'rp-subj-v');
        noI18n(val);
        var paint = function () {
          val.hidden = mode.value === 'off';
          val.placeholder = mode.value === 'fixed' ? tr('its value') : tr('a default (may be empty)');
        };
        mode.onchange = paint;
        paint();
        line.appendChild(mode);
        line.appendChild(val);
        f.subject[k] = {mode: mode, value: val};
        sg.appendChild(line);
      });
      body.appendChild(sg);
      /* -- what it is for, renewal -- */
      body.appendChild(el('h3', 'peek-h', 'Use and renewal'));
      var g5 = el('div', 'formgrid');
      f.auto = switchBox(p.auto_renew);
      g5.appendChild(formField('Renew by itself', f.auto, 'Off: only when somebody presses Renew now.'));
      f.rdays = numBox(p.renew_days, '30', 1, 3650);
      g5.appendChild(formField('Days before the end', f.rdays, 'Empty: as Renewal and notices says.'));
      f.days = numBox(p.days, '', 1, 36500);
      f.daysField = formField('Valid for (days)', f.days, 'Empty: what the source gives. Browsers take at most 398 days for a public name.');
      g5.appendChild(f.daysField);
      body.appendChild(g5);
      f.eku = {};
      var ek = el('div', 'ct-ekus rp-ekus');
      (o.ekus || Object.keys(EKU_WORDS)).forEach(function (e) {
        var lab = el('label', 'set-check');
        var cb = el('input');
        cb.type = 'checkbox';
        cb.checked = (p.eku || []).indexOf(e) >= 0;
        f.eku[e] = cb;
        lab.appendChild(cb);
        lab.appendChild(el('span', '', EKU_WORDS[e] || e));
        lab.appendChild(data('span', 'mono muted small', ' ' + e));
        ek.appendChild(lab);
      });
      body.appendChild(formField('Used for', ek, 'A public CA puts in what it puts in; an authority of your own what is asked.'));
      /* -- approval, owner, tags -- */
      body.appendChild(el('h3', 'peek-h', 'Approval and owner'));
      var g6 = el('div', 'formgrid');
      f.approval = selectBox([['0', 'issued at once'], ['1', 'waits for approval']], p.approval ? '1' : '0');
      f.approval.id = 'rp-f-approval';
      g6.appendChild(formField('When asked for', f.approval, 'Approved by the certificate administrators (Certificates → waiting for approval), and on the portal by the members with the right approve of the team that owns it.'));
      f.owner = selectBox([['person', 'the person who asks'], ['team', 'a team they pick (where they may ask)'], ['fixed', 'this team']], p.owner || 'person');
      f.owner.id = 'rp-f-owner';
      g6.appendChild(formField('Whose it is', f.owner, 'Owners and teams: the members of its team see it on the portal and are told when it fails.'));
      f.oteam = selectBox([['', tr('choose a team')]].concat((o.teams || []).map(function (t) { return [t, t]; })), p.owner_team || '');
      f.oteam.id = 'rp-f-oteam';
      noI18n(f.oteam);
      f.oteamField = formField('The team', f.oteam);
      g6.appendChild(f.oteamField);
      f.pfx = switchBox(p.pfx);
      f.pfxField = formField('PFX with the key', f.pfx, 'The person may download the certificate with its private key, locked with a password they choose. Only for a key acme made.');
      g6.appendChild(f.pfxField);
      body.appendChild(g6);
      f.tags = window.ACME_TEAMS ? ACME_TEAMS.tagPicker(p.tags || []) : null;
      if (f.tags) body.appendChild(formField('Tags', f.tags, 'Put on every certificate asked for from it, beside "portal".'));
      /* -- who may use it -- */
      body.appendChild(el('h3', 'peek-h', 'Who may use it'));
      body.appendChild(el('p', 'note', 'The members of these teams with the right to ask for new ones (Owners and teams). None chosen: everybody who may sign in to the enrolment pages.'));
      f.teams = {};
      var tw = el('div', 'rp-teams');
      if (!(o.teams || []).length) tw.appendChild(el('span', 'muted small', 'No owner or team yet - Settings → Owners and teams.'));
      (o.teams || []).forEach(function (t) {
        var lab = el('label', 'set-check');
        var cb = el('input');
        cb.type = 'checkbox';
        cb.checked = (p.teams || []).indexOf(t) >= 0;
        f.teams[t] = cb;
        lab.appendChild(cb);
        lab.appendChild(data('span', '', t));
        tw.appendChild(lab);
      });
      body.appendChild(tw);
      f.said = el('div', 'said');
      body.appendChild(f.said);
      /* What the source takes, said as it is chosen. */
      shown = function () {
        var i = issuerOf(f.issuer.value) || {};
        f.challengeField.hidden = !i.needs_validation;
        f.wild._input.disabled = i.wildcards === false;
        if (i.wildcards === false) f.wild._input.checked = false;
        f.csr._input.disabled = !i.csr;
        if (!i.csr) f.csr._input.checked = false;
        var says = f.csrField.querySelector('.says');
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
      f.issuer.onchange = shown;
      f.owner.onchange = shown;
      f.make._input.addEventListener('change', shown);
      shown();
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var subject = {};
          Object.keys(f.subject).forEach(function (k) {
            subject[k] = {mode: f.subject[k].mode.value, value: f.subject[k].value.value.trim()};
          });
          var out = {name: f.name.value.trim(), description: f.desc.value.trim(), enabled: f.enabled._get(),
                     issuer: f.issuer.value, challenge: f.challengeField.hidden ? '' : f.challenge.value,
                     suffixes: f.suffixes.value.split(/[\s,;]+/).filter(Boolean), wildcards: f.wild._get(),
                     max_names: Number(f.most.value || 1), make_key: f.make._get(), csr: f.csr._get(),
                     key_types: Object.keys(f.kts).filter(function (k) { return f.kts[k].checked; }),
                     key_default: f.kdef.value, subject: subject, auto_renew: f.auto._get(),
                     renew_days: f.rdays.value ? Number(f.rdays.value) : null,
                     days: !f.daysField.hidden && f.days.value ? Number(f.days.value) : null,
                     eku: Object.keys(f.eku).filter(function (k) { return f.eku[k].checked; }),
                     approval: f.approval.value === '1', owner: f.owner.value, owner_team: f.oteam.value,
                     tags: f.tags ? f.tags._get() : [], pfx: f.make._get() ? f.pfx._get() : 0,
                     teams: Object.keys(f.teams).filter(function (t) { return f.teams[t].checked; })};
          if (!isNew) out.old_name = p.name;
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
          }).then(function () { busy(b, false); });
        }}], 'large');
  }

  function deleteProfile(p) {
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
  /* A page that opened on this pane drew it before this file came. */
  if (typeof PANE === 'string' && PANE === 'reqprofiles') drawPane();
})();
