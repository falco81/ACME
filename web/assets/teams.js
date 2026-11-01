/* teams.js - Settings → Owners and teams (docs/teams.md): the owners of
   certificates (teams and persons, their members and what each may do) and the
   tags, from GET /api/teams, changed through acmelib/certs/api_teams.py. The
   pane's markup is a host in admin/certs-ui.php (<div id="teams-host">), the two
   settings of who sees what are drawn by admin.js into <div id="sect-teams">.

   It also gives the rest of the page what picks from the catalogs instead of
   free text (window.ACME_TEAMS):
     ownerPicker(value)   a select of the owners this account may give (+ nobody);
                          an owner not defined is kept, marked, with "Make it an owner"
     tagPicker(list)      chips of the tags chosen, and a select to add one
     tagChip(name)        one tag in its colour; not in the catalog: marked
     fillFilters()        the owner and tag selects above the list of certificates
   Both pickers answer .value (the owner; the tags with spaces between) and _get().
   Every popup is the page's own (modal, confirmThen) - never one of the browser's.
   A full administrator changes; anybody signed in sees. */
'use strict';
(function () {
  var TM = {d: null, asking: null, users: null};
  var RIGHT_WORDS = {view: 'see', request: 'ask for new', manage: 'manage', approve: 'approve'};
  var RIGHT_SAYS = {
    view: 'Sees the team\'s certificates - in the list, on the portal - and downloads them there.',
    request: 'Asks for new certificates owned by the team (the portal, or the wizard). Sees them too.',
    manage: 'Edits, renews, deploys, exports and revokes the team\'s certificates; makes new ones for it.',
    approve: 'Approves or declines what is asked for on the portal for the team.'
  };
  var KIND_WORDS = {local: 'account of acme', user: 'directory user', group: 'directory group'};

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function call(what, body) { return api(what, body); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function cell(cls, child) {
    var td = el('td', cls || '');
    if (child instanceof Node) td.appendChild(child);
    else if (child !== undefined && child !== null) td.textContent = String(child);
    return td;
  }
  function low(s) { return String(s || '').trim().toLowerCase(); }

  function load(force) {
    if (TM.d && !force) return Promise.resolve(TM.d);
    if (TM.asking && !force) return TM.asking;
    TM.asking = call('teams').then(function (d) { TM.d = d || {}; TM.asking = null; return TM.d; },
      function (e) { TM.asking = null; throw e; });
    return TM.asking;
  }
  function teamOf(name) {
    return ((TM.d || {}).teams || []).filter(function (t) { return low(t.name) === low(name); })[0] || null;
  }
  function tagOf(name) {
    return ((TM.d || {}).tags || []).filter(function (t) { return low(t.name) === low(name); })[0] || null;
  }
  /* Whatever else on the page shows an owner or a tag drawn again after a change. */
  function changed() {
    return load(true).then(function () {
      fillFilters();
      if (window.CT && typeof CT.refresh === 'function') { try { CT.refresh(); } catch (e) { } }
    });
  }

  /* ---- one tag, one owner --------------------------------------------------- */
  function tagChip(name) {
    var t = tagOf(name);
    var c = data('span', 'tag ' + (t ? (t.colour || 'dim') : 'dim tm-undef') + ' ct-tagchip', name);
    if (t && t.description) c.title = t.description;
    if (!t && TM.d) c.title = tr('not defined - Settings → Owners and teams');
    return c;
  }
  function ownerChip(name) {
    var t = teamOf(name);
    var c = data('span', 'tag ' + (t ? 'info' : 'dim tm-undef') + ' tm-owner', name);
    if (!t && TM.d) c.title = tr('not defined - Settings → Owners and teams');
    else if (t && t.contact_mail) c.title = t.contact_mail;
    return c;
  }

  /* ---- the owner picker ----------------------------------------------------- */
  function ownerPicker(value) {
    var wrap = el('div', 'tm-pick');
    var sel = el('select', 'tm-owner-sel');
    noI18n(sel);
    wrap.appendChild(sel);
    var undef = el('div', 'tm-undef-line');
    wrap.appendChild(undef);
    var cur = String(value || '').trim();
    var fill = function () {
      var d = TM.d || {};
      var keep = sel.options.length ? sel.value : cur;
      clear(sel);
      var add = function (v, words, cls) {
        var o = el('option', cls || '', words);
        o.value = v;
        sel.appendChild(o);
        return o;
      };
      if (d.unowned_ok !== false || !cur) {
        var none = add('', tr('nobody'));
        if (d.unowned_ok === false) { none.disabled = true; none.textContent = tr('choose an owner'); }
      }
      var may = d.choosable || [];
      (d.teams || []).forEach(function (t) {
        if (may.indexOf(t.name) < 0 && low(t.name) !== low(cur)) return;
        add(t.name, t.name + (t.kind === 'person' ? ' · ' + tr('person') : ''));
      });
      if (cur && !teamOf(cur)) add(cur, cur + ' - ' + tr('not defined'), 'tm-undef');
      sel.value = keep;
      if (sel.value !== keep) sel.value = cur;
      paintUndef();
    };
    var paintUndef = function () {
      clear(undef);
      var v = sel.value;
      if (!v || teamOf(v) || !TM.d) return;
      undef.appendChild(el('span', 'muted small', 'Not defined - typed as text before. '));
      if (full()) {
        var mk = cmdButton('Make it an owner', 'add', 'small');
        mk.classList.add('tm-adopt-owner');
        mk.onclick = function () {
          busy(mk, true);
          call('teams/adopt', {owner: v}).then(function (r) {
            toast(r.message || 'made', 'good');
            cur = r.team || v;
            return changed();
          }).then(fill).catch(oops).then(function () { busy(mk, false); });
        };
        undef.appendChild(mk);
      }
    };
    sel.addEventListener('change', paintUndef);
    Object.defineProperty(wrap, 'value', {get: function () { return sel.value; },
                                          set: function (v) { cur = String(v || ''); fill(); }});
    wrap._get = function () { return sel.value; };
    wrap._select = sel;
    fill();
    load().then(fill).catch(function () { });
    return wrap;
  }

  /* ---- the tag picker ------------------------------------------------------- */
  function tagPicker(list) {
    var chosen = (Array.isArray(list) ? list : String(list || '').split(/[\s,;]+/))
      .map(function (x) { return String(x).trim(); }).filter(Boolean);
    var wrap = el('div', 'tm-pick tm-tags');
    var chips = el('div', 'chips tm-chips');
    var sel = el('select', 'tm-tag-add');
    noI18n(sel);
    wrap.appendChild(chips);
    wrap.appendChild(sel);
    var draw = function () {
      clear(chips);
      if (!chosen.length) chips.appendChild(el('span', 'muted small', 'No tag.'));
      chosen.forEach(function (n) {
        var c = el('span', 'tm-chip');
        c.appendChild(tagChip(n));
        if (!tagOf(n) && TM.d && full()) {
          var def = iconButton('add', 'Define this tag');
          def.classList.add('tm-define');
          def.onclick = function () {
            call('teams/adopt', {tag: n}).then(function (r) { toast(r.message || 'made', 'good'); return changed(); })
              .then(draw).catch(oops);
          };
          c.appendChild(def);
        }
        var x = iconButton('close', 'Take it off');
        x.onclick = function () { chosen = chosen.filter(function (v) { return v !== n; }); draw(); };
        c.appendChild(x);
        chips.appendChild(c);
      });
      clear(sel);
      var first = el('option', '', tr('add a tag…'));
      first.value = '';
      sel.appendChild(first);
      ((TM.d || {}).tags || []).forEach(function (t) {
        if (chosen.some(function (v) { return low(v) === low(t.name); })) return;
        var o = el('option', '', t.name + (t.description ? ' - ' + t.description : ''));
        o.value = t.name;
        sel.appendChild(o);
      });
      sel.disabled = sel.options.length < 2;
      if (sel.disabled) first.textContent = TM.d && !((TM.d.tags || []).length)
        ? tr('no tags defined - Settings → Owners and teams') : tr('every tag is on');
    };
    sel.onchange = function () {
      if (sel.value) chosen.push(sel.value);
      draw();
    };
    Object.defineProperty(wrap, 'value', {get: function () { return chosen.join(' '); }});
    wrap._get = function () { return chosen.slice(); };
    draw();
    load().then(draw).catch(function () { });
    return wrap;
  }

  /* ---- the filters above the list of certificates --------------------------- */
  function fillFilters() {
    var o = $('ct-owner'), t = $('ct-tag');
    if (!o && !t) return;
    load().then(function (d) {
      [[o, d.teams || [], 'every owner'], [t, d.tags || [], 'every tag']].forEach(function (x) {
        var sel = x[0];
        if (!sel) return;
        var keep = sel.value;
        clear(sel);
        var any = el('option', '', x[2]);
        any.value = '';
        sel.appendChild(any);
        x[1].forEach(function (r) {
          var op = data('option', '', r.name);
          op.value = r.name;
          sel.appendChild(op);
        });
        sel.value = keep;
        sel.hidden = !x[1].length && !keep;
      });
    }).catch(function () { });
  }

  /* ---- the pane --------------------------------------------------------------- */
  function drawPane() {
    var host = $('teams-host');
    if (!host) return;
    load(true).then(function (d) {
      clear(host);
      host.appendChild(teamsCard(d));
      host.appendChild(tagsCard(d));
      var lg = d.legacy || {};
      if ((lg.owners || []).length || (lg.tags || []).length) host.appendChild(legacyCard(lg));
      fillFilters();
    }).catch(function (e) { clear(host); oops(e); });
  }

  function membersCell(t) {
    var td = cell('small tm-members', '');
    if (!(t.members || []).length) td.appendChild(el('span', 'muted', 'no member - only administrators see it'));
    (t.members || []).forEach(function (m) {
      var line = el('div', 'tm-member');
      line.appendChild(el('span', 'tag dim tm-mkind', KIND_WORDS[m.kind] || m.kind));
      line.appendChild(data('span', 'mono', shortWho(m.who)));
      line.lastChild.title = m.who;
      (m.rights || []).forEach(function (r) { line.appendChild(el('span', 'tag info tm-right', RIGHT_WORDS[r] || r)); });
      td.appendChild(line);
    });
    return td;
  }
  function shortWho(who) {
    var m = /^\s*(?:group:)?cn=((?:\\.|[^,])+)/i.exec(who);
    return m ? 'group:' + m[1].replace(/\\(.)/g, '$1') : who;
  }

  function teamsCard(d) {
    var card = el('div', 'card full tm');
    var h = el('h2', '', 'Owners and teams');
    var right = el('span', 'right btnrow');
    if (full()) {
      var add = cmdButton('Add an owner', 'add', 'small primary');
      add.id = 'tm-add';
      add.onclick = function () { editTeam(null); };
      right.appendChild(add);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Who a certificate belongs to: a team or a person, picked from this list wherever a certificate is made or changed. Its members - accounts of acme, users and groups of the directory - see its certificates on the portal and, with the settings below off, in the administration; what each may do is said beside them. Its mail is told when one of its certificates fails or runs out.'));
    card.appendChild(listTable(['Name', 'Members and what they may', 'Told', {words: 'Certificates', cls: 'num'}, ''],
      d.teams || [], function (t) {
        var tr_ = el('tr', 'tm-team');
        tr_.dataset.name = t.name;
        var nm = cell('', '');
        nm.appendChild(data('b', '', t.name));
        nm.appendChild(el('span', 'tag dim tm-kind', t.kind === 'person' ? 'person' : 'team'));
        if (t.note) nm.appendChild(data('div', 'muted small', t.note));
        tr_.appendChild(nm);
        tr_.appendChild(membersCell(t));
        var told = cell('small', '');
        if (t.contact_mail) told.appendChild(data('div', 'mono', t.contact_mail));
        if (t.contact_phone) told.appendChild(data('div', 'muted', t.contact_phone));
        if (!t.contact_mail && !t.contact_phone) told.appendChild(el('span', 'muted', '–'));
        tr_.appendChild(told);
        tr_.appendChild(cell('num', num(t.used || 0)));
        var tools = el('td', 'rowtools');
        if (full()) {
          var ed = iconButton('edit', 'Edit this owner');
          ed.classList.add('tm-edit');
          ed.onclick = function () { editTeam(t); };
          tools.appendChild(ed);
          var del = iconButton('trash', 'Delete this owner');
          del.classList.add('tm-del');
          del.onclick = function () { deleteTeam(t); };
          tools.appendChild(del);
        }
        tr_.appendChild(tools);
        return tr_;
      }, 'plain tm-teams|No owner yet'));
    return card;
  }

  function tagsCard(d) {
    var card = el('div', 'card full tm');
    var h = el('h2', '', 'Tags');
    var right = el('span', 'right btnrow');
    if (full()) {
      var add = cmdButton('Add a tag', 'add', 'small primary');
      add.id = 'tm-tag-add';
      add.onclick = function () { editTag(null); };
      right.appendChild(add);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'The words certificates and targets are found and grouped by, each with its colour and what it means - picked from this list, never typed. Renamed here, a tag is renamed on everything that carries it.'));
    card.appendChild(listTable(['Tag', 'What it means', {words: 'Certificates', cls: 'num'}, {words: 'Targets', cls: 'num'}, ''],
      d.tags || [], function (t) {
        var tr_ = el('tr', 'tm-tagrow');
        tr_.dataset.name = t.name;
        tr_.appendChild(cell('', tagChip(t.name)));
        tr_.appendChild(cell('small', t.description ? data('span', '', t.description) : el('span', 'muted', '–')));
        tr_.appendChild(cell('num', num(t.certs || 0)));
        tr_.appendChild(cell('num', num(t.targets || 0)));
        var tools = el('td', 'rowtools');
        if (full()) {
          var ed = iconButton('edit', 'Edit this tag');
          ed.onclick = function () { editTag(t); };
          tools.appendChild(ed);
          var del = iconButton('trash', 'Delete this tag');
          del.onclick = function () { deleteTag(t); };
          tools.appendChild(del);
        }
        tr_.appendChild(tools);
        return tr_;
      }, 'plain tm-tagtable|No tag yet'));
    return card;
  }

  function legacyCard(lg) {
    var card = el('div', 'card full tm tm-legacy');
    var h = el('h2', '', 'Not defined yet');
    var right = el('span', 'right btnrow');
    if (full()) {
      var all = cmdButton('Make teams and tags from what certificates say now', 'add', 'small primary');
      all.id = 'tm-adopt-all';
      all.onclick = function () {
        confirmThen('Make teams and tags', htmlText(tr('Every owner below becomes a team whose one member is what the certificate said (so the portal shows it to the same people as before), every tag a tag of the list. Nothing is taken away.')),
          'Make them', function () {
            call('teams/adopt', {}).then(function (r) { toast(r.message || 'made', 'good'); return changed(); })
              .then(drawPane).catch(oops);
          }, false);
      };
      right.appendChild(all);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'What certificates say that is in neither list - typed as text before. It stays as it is until it is made an owner or a tag here.'));
    var rows = (lg.owners || []).map(function (o) { return {what: 'owner', name: o.owner, certs: o.certs, targets: 0}; })
      .concat((lg.tags || []).map(function (t) { return {what: 'tag', name: t.tag, certs: t.certs, targets: t.targets}; }));
    card.appendChild(listTable(['What', 'Said', {words: 'Certificates', cls: 'num'}, {words: 'Targets', cls: 'num'}, ''], rows, function (r) {
      var tr_ = el('tr', 'tm-legacy-row');
      tr_.appendChild(cell('', el('span', 'tag dim', r.what === 'owner' ? 'owner' : 'tag')));
      tr_.appendChild(cell('mono small', data('span', '', r.name)));
      tr_.appendChild(cell('num', num(r.certs)));
      tr_.appendChild(cell('num', num(r.targets)));
      var tools = el('td', 'rowtools');
      if (full()) {
        var mk = cmdButton(r.what === 'owner' ? 'Make it an owner' : 'Make it a tag', 'add', 'small');
        mk.onclick = function () {
          var b = r.what === 'owner' ? {owner: r.name} : {tag: r.name};
          call('teams/adopt', b).then(function (x) { toast(x.message || 'made', 'good'); return changed(); })
            .then(drawPane).catch(oops);
        };
        tools.appendChild(mk);
      }
      tr_.appendChild(tools);
      return tr_;
    }, 'plain'));
    return card;
  }

  /* ---- an owner: its dialog ----------------------------------------------------- */
  function accounts() {
    if (TM.users) return Promise.resolve(TM.users);
    return api('users').then(function (d) {
      TM.users = (d.users || []).filter(function (u) { return u.source !== 'directory'; })
        .map(function (u) { return u.name; });
      return TM.users;
    }).catch(function () { return []; });
  }

  function editTeam(t) {
    var isNew = !t;
    t = t || {name: '', kind: 'team', members: [], contact_mail: '', contact_phone: '', note: ''};
    var members = (t.members || []).map(function (m) { return {who: m.who, rights: (m.rights || []).slice(), kind: m.kind}; });
    var f = {};
    modal(isNew ? 'A new owner' : 'The owner ' + t.name, function (body) {
      var g = el('div', 'formgrid');
      f.name = textBox(t.name, 'Web team', '');
      f.name.id = 'tm-f-name';
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'Letters, digits, spaces and . _ @ + - (as every name in acme). Renamed, its certificates follow.'));
      f.kind = selectBox([['team', 'a team'], ['person', 'a person']], t.kind || 'team');
      f.kind.id = 'tm-f-kind';
      g.appendChild(formField('It is', f.kind));
      f.mail = textBox(t.contact_mail || '', 'web-team@example.com', 'mono');
      f.mail.id = 'tm-f-mail';
      noI18n(f.mail);
      g.appendChild(formField('Mail', f.mail, 'Told when one of its certificates fails or runs out, beside the addresses of Renewal and notices. Comma between them.'));
      f.phone = textBox(t.contact_phone || '', '+420 …', '');
      noI18n(f.phone);
      g.appendChild(formField('Phone', f.phone, 'Only shown - who to call.'));
      f.note = textBox(t.note || '', '', '');
      noI18n(f.note);
      var nf = formField('Note', f.note);
      nf.classList.add('wide');
      g.appendChild(nf);
      body.appendChild(g);
      body.appendChild(el('h3', 'peek-h', 'Members'));
      body.appendChild(el('p', 'note', 'Who belongs to it, and what each may do with its certificates. A full administrator always sees and does everything; certificate administrators and readers are kept to their teams only when the settings of this pane say so.'));
      var list = el('div', 'tm-mlist');
      list.id = 'tm-f-members';
      body.appendChild(list);
      var drawList = function () {
        clear(list);
        if (!members.length) { list.appendChild(el('p', 'muted small', 'No member yet: only administrators see its certificates.')); return; }
        var tbl = listTable(['Member', ''].concat(['view', 'request', 'manage', 'approve'].map(function (r) {
          return {words: RIGHT_WORDS[r], cls: 'center'};
        })).concat(['']), members, function (m) {
          var row = el('tr', 'tm-mrow');
          var who = cell('', data('span', 'mono', shortWho(m.who)));
          who.firstChild.title = m.who;
          row.appendChild(who);
          row.appendChild(cell('', el('span', 'tag dim', KIND_WORDS[m.kind || kindOf(m.who)] || '')));
          ['view', 'request', 'manage', 'approve'].forEach(function (r) {
            var td = cell('center', '');
            var box = document.createElement('input');
            box.type = 'checkbox';
            box.className = 'tm-r-' + r;
            box.checked = m.rights.indexOf(r) >= 0;
            box.title = tr(RIGHT_SAYS[r]);
            box.onchange = function () {
              m.rights = ['view', 'request', 'manage', 'approve'].filter(function (x) {
                return x === r ? box.checked : m.rights.indexOf(x) >= 0;
              });
            };
            td.appendChild(box);
            row.appendChild(td);
          });
          var tools = el('td', 'rowtools');
          var x = iconButton('close', 'Take this member out');
          x.onclick = function () { members = members.filter(function (o) { return o !== m; }); drawList(); };
          tools.appendChild(x);
          row.appendChild(tools);
          return row;
        }, 'plain tm-mtable');
        list.appendChild(tbl);
      };
      var put = function (who) {
        who = String(who || '').trim();
        if (!who) return;
        if (members.some(function (m) { return low(m.who) === low(who); })) { toast('already a member', 'bad'); return; }
        members.push({who: who, rights: ['view', 'request'], kind: kindOf(who)});
        drawList();
      };
      drawList();
      /* adding one: an account of acme's, a user of the directory, a group */
      var addRow = el('div', 'btnrow tm-addm');
      var how = selectBox([['local', 'An account of acme'], ['user', 'A user of the directory'], ['group', 'A group of the directory']], 'local');
      how.id = 'tm-f-how';
      var acc = el('select', 'tm-f-acc');
      noI18n(acc);
      var txt = textBox('', '', 'mono');
      txt.id = 'tm-f-who';
      noI18n(txt);
      var addGo = cmdButton('Add the member', 'add', 'small');
      addGo.id = 'tm-f-addm';
      var find = cmdButton('Find and pick the groups', 'search', 'small');
      find.id = 'tm-f-find';
      addRow.appendChild(how);
      addRow.appendChild(acc);
      addRow.appendChild(txt);
      addRow.appendChild(addGo);
      addRow.appendChild(find);
      body.appendChild(addRow);
      accounts().then(function (names) {
        clear(acc);
        names.forEach(function (n) { var o = data('option', '', n); o.value = n; acc.appendChild(o); });
      });
      if (typeof personSuggest === 'function') personSuggest(txt);
      var dirs = (typeof SETTINGS === 'object' && SETTINGS && SETTINGS.directories) || [];
      var shown = function () {
        acc.hidden = how.value !== 'local';
        txt.hidden = how.value === 'local';
        find.hidden = how.value !== 'group' || !dirs.length || typeof groupBrowser !== 'function';
        txt.placeholder = how.value === 'group' ? tr('group:NAME or the group\'s DN') : tr('sAMAccountName, UPN or mail');
      };
      how.onchange = shown;
      shown();
      addGo.onclick = function () {
        if (how.value === 'local') { if (acc.value) put('local:' + acc.value); return; }
        var v = txt.value.trim();
        if (!v) { toast(how.value === 'group' ? 'which group?' : 'which user?', 'bad'); return; }
        if (how.value === 'group' && !/^group:/i.test(v) && !/=/.test(v)) v = 'group:' + v;
        put(v);
        txt.value = '';
      };
      find.onclick = function () {
        modalOver(function () {
          modal('Groups of the directory', function (b2) {
            b2.appendChild(el('p', 'note', 'Find the groups and press Member beside each one that belongs to the owner. Nested groups count. Nothing is kept until the owner is saved.'));
            var dir = selectBox(dirs.map(function (x) { return [x, x]; }), dirs[0]);
            noI18n(dir);
            if (dirs.length > 1) b2.appendChild(formField('Look in the directory', dir));
            var has = function (g) {
              return members.filter(function (m) {
                var w = low(m.who).replace(/^group:/, '');
                return w === low(g.dn) || w === low(g.cn);
              });
            };
            b2.appendChild(groupBrowser({
              dir: function () { return dir.value; },
              buttons: [{words: 'Member', icon: 'check', on: function (g) { return has(g).length > 0; },
                         toggle: function (g) {
                           var hit = has(g);
                           if (hit.length) members = members.filter(function (m) { return hit.indexOf(m) < 0; });
                           else members.push({who: g.dn, rights: ['view', 'request'], kind: 'group'});
                         }}]
            }));
          }, [{words: 'Done', cls: 'primary', icon: 'check', close: true}], 'large');
        }, function () { drawList(); });
      };
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = {name: f.name.value.trim(), kind: f.kind.value, contact_mail: f.mail.value.trim(),
                      contact_phone: f.phone.value.trim(), note: f.note.value.trim(),
                      members: members.map(function (m) { return {who: m.who, rights: m.rights}; })};
          if (!isNew) body.old_name = t.name;
          busy(b, true);
          call('teams/save', body).then(function (r) {
            toast(r.message || 'saved', 'good');
            closeModal();
            return changed().then(drawPane);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'large');
  }
  function kindOf(who) {
    var w = low(who);
    if (w.indexOf('local:') === 0) return 'local';
    if (w.indexOf('group:') === 0 || w.indexOf('cn=') === 0 || (w.indexOf('=') > 0 && w.indexOf(',') > 0)) return 'group';
    return 'user';
  }

  function deleteTeam(t) {
    if (!t.used) {
      confirmThen('Delete the owner', htmlText(tr('The owner {0} is deleted. It owns no certificate.').replace('{0}', t.name)), 'Delete it', function () {
        call('teams/delete', {name: t.name}).then(function (r) { toast(r.message || 'deleted', 'good'); return changed(); })
          .then(drawPane).catch(oops);
      });
      return;
    }
    var to = null;
    modal('Delete the owner ' + t.name, function (body) {
      body.appendChild(el('p', 'note warn', tr('It owns {0} certificate(s). They are given to the owner chosen here first - nothing else changes on them.').replace('{0}', num(t.used))));
      var pairs = [['', tr('nobody')]].concat(((TM.d || {}).teams || []).filter(function (x) { return x.name !== t.name; })
        .map(function (x) { return [x.name, x.name]; }));
      to = selectBox(pairs, '');
      to.id = 'tm-reassign';
      noI18n(to);
      body.appendChild(formField('Their new owner', to));
    }, [{words: 'Close', close: true},
        {words: 'Delete it', cls: 'danger', icon: 'trash', go: function (b) {
          busy(b, true);
          call('teams/delete', {name: t.name, reassign: to.value}).then(function (r) {
            toast(r.message || 'deleted', 'good');
            closeModal();
            return changed().then(drawPane);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  /* ---- a tag: its dialog --------------------------------------------------------- */
  function editTag(t) {
    var isNew = !t;
    t = t || {name: '', colour: 'dim', description: ''};
    var f = {};
    var colours = (TM.d && TM.d.colours) || ['dim', 'info', 'ok', 'warn', 'crit', 'violet'];
    var cw = {dim: 'grey', info: 'blue', ok: 'green', warn: 'orange', crit: 'red', violet: 'violet'};
    modal(isNew ? 'A new tag' : 'The tag ' + t.name, function (body) {
      var g = el('div', 'formgrid');
      f.name = textBox(t.name, 'prod', 'mono');
      f.name.id = 'tm-t-name';
      noI18n(f.name);
      g.appendChild(formField('Tag', f.name, 'One word: letters, digits and . _ : + -. Renamed, it is renamed on every certificate and target.'));
      f.colour = selectBox(colours.map(function (c) { return [c, cw[c] || c]; }), t.colour || 'dim');
      f.colour.id = 'tm-t-colour';
      var prev = el('span', 'tm-prev');
      var paint = function () { clear(prev); prev.appendChild(data('span', 'tag ' + f.colour.value, f.name.value || 'tag')); };
      f.colour.onchange = paint;
      f.name.oninput = paint;
      var cf = formField('Colour', f.colour);
      cf.appendChild(prev);
      g.appendChild(cf);
      f.desc = textBox(t.description || '', 'what it means', '');
      noI18n(f.desc);
      var df = formField('What it means', f.desc);
      df.classList.add('wide');
      g.appendChild(df);
      body.appendChild(g);
      paint();
    }, [{words: 'Close', close: true},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = {name: f.name.value.trim(), colour: f.colour.value, description: f.desc.value.trim()};
          if (!isNew) body.old_name = t.name;
          busy(b, true);
          call('tags/save', body).then(function (r) {
            toast(r.message || 'saved', 'good');
            closeModal();
            return changed().then(drawPane);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function deleteTag(t) {
    var n = (t.certs || 0) + (t.targets || 0);
    var words = n ? tr('The tag {0} is deleted and taken off {1} certificate(s) and {2} target(s).')
      .replace('{0}', t.name).replace('{1}', num(t.certs || 0)).replace('{2}', num(t.targets || 0))
      : tr('The tag {0} is deleted. Nothing carries it.').replace('{0}', t.name);
    confirmThen('Delete the tag', htmlText(words), 'Delete it', function () {
      call('tags/delete', {name: t.name, strip: n > 0}).then(function (r) { toast(r.message || 'deleted', 'good'); return changed(); })
        .then(drawPane).catch(oops);
    });
  }

  function tr(s) { return typeof window.tr === 'function' ? window.tr(s) : s; }

  window.ACME_TEAMS = {load: load, ownerPicker: ownerPicker, tagPicker: tagPicker, tagChip: tagChip,
                       ownerChip: ownerChip, fillFilters: fillFilters, teamOf: teamOf, tagOf: tagOf};
  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.teams = function () { drawPane(); };
  /* A page that opened on this pane drew it before this file came. */
  if (typeof PANE === 'string' && PANE === 'teams') drawPane();
  load().then(fillFilters).catch(function () { });
})();
