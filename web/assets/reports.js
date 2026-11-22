/* reports.js - Settings → Reports and a team's Digest tab (1.0.140, docs/reports.md,
   docs/teams.md "The digest").

   The pane (<div id="rpt-host"> in admin/certs-ui.php): the reports defined as cards - kind,
   scope, formats, schedule, recipients, the last and the next run - with Preview (the report as
   a page), Run now (kept; mailed if wanted), the runs kept to download, Edit and Delete. Empty,
   it offers the five kinds to start from. A full administrator defines and runs them; a
   certificate administrator sees and downloads those of the teams they manage.

   The team's tab (window.ACME_TEAM_TABS, read by teams.js): whether the team gets a digest by
   mail, when and to whom, what goes in, the last one sent - Show the preview, Send a preview to
   me, and for a full administrator Set it and Send now.

   Everything is drawn from what the daemon says (/api/reports..., /api/teams/digest...). */
(function () {
  'use strict';

  var KIND_ICON = {inventory: 'list', expiry: 'clock', compliance: 'shield', agents: 'router', access: 'people'};
  var KIND_TONE = {inventory: 'info', expiry: 'warn', compliance: 'ok', agents: 'violet', access: 'info'};
  var DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  var R = {d: null, busy: false};

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function ic(key, size, cls) {
    var s = el('span', 'rpt-ic' + (cls ? ' ' + cls : ''));
    s.innerHTML = iconMarkup(key, size || 16);
    s.setAttribute('aria-hidden', 'true');
    return s;
  }
  function chip(words, tone, icon) {
    var c = el('span', 'tmx-chip ' + (tone || 'dim'));
    if (icon) c.appendChild(ic(icon, 12));
    c.appendChild(el('span', '', words));
    return c;
  }
  function dataChip(words, tone, icon) {
    var c = chip('', tone, icon);
    c.lastChild.textContent = words;
    noI18n(c.lastChild);
    return c;
  }
  function tr(s) {
    try { var got = typeof i18nText === 'function' ? i18nText(s) : null; return got || s; } catch (e) { return s; }
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function hour(h) { return pad(Number(h) || 0) + ':00'; }
  function when(ts) { return ts ? stamp(ts).slice(0, 16) : '–'; }
  function agoWords(ts) { return ts && Date.now() / 1000 - ts < 60 ? 'just now' : ago(ts); }
  function enc(v) { return encodeURIComponent(String(v === undefined || v === null ? '' : v)); }
  function schedWords(s) {
    s = s || {};
    if (s.every === 'weekly') return tr('Weekly on {0} at {1}').replace('{0}', tr(DAYS[Math.max(1, Math.min(7, Number(s.day) || 1)) - 1])).replace('{1}', hour(s.hour));
    if (s.every === 'monthly') return tr('Monthly on day {0} at {1}').replace('{0}', String(Number(s.day) || 1)).replace('{1}', hour(s.hour));
    return 'By hand only';
  }
  function numBox(v, min, max) {
    var i = el('input', 'rpt-num');
    i.type = 'number';
    i.min = String(min);
    i.max = String(max);
    i.value = String(v);
    return i;
  }
  function segmented(pairs, value) {
    var s = el('div', 'tmx-seg');
    s.setAttribute('role', 'radiogroup');
    s.value = value;
    pairs.forEach(function (p) {
      var b = el('button', 'tmx-segb' + (String(p[0]) === String(value) ? ' on' : ''));
      b.type = 'button';
      b.dataset.v = p[0];
      b.setAttribute('role', 'radio');
      b.setAttribute('aria-checked', String(p[0]) === String(value) ? 'true' : 'false');
      if (p[2]) b.appendChild(ic(p[2], 14));
      b.appendChild(el('span', '', p[1]));
      b.onclick = function () {
        s.value = p[0];
        s.querySelectorAll('.tmx-segb').forEach(function (x) {
          x.classList.toggle('on', x === b);
          x.setAttribute('aria-checked', x === b ? 'true' : 'false');
        });
        if (s.onchange) s.onchange();
      };
      s.appendChild(b);
    });
    return s;
  }
  function toggleChip(words, on, icon, isData) {
    var b = el('button', 'rpt-tog' + (on ? ' on' : ''));
    b.type = 'button';
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
    var k = el('span', 'rpt-tog-k');
    k.innerHTML = iconMarkup('check', 11);
    b.appendChild(k);
    if (icon) b.appendChild(ic(icon, 13));
    b.appendChild((isData ? data : el)('span', '', words));
    b._on = !!on;
    b.onclick = function () {
      b._on = !b._on;
      b.classList.toggle('on', b._on);
      b.setAttribute('aria-pressed', b._on ? 'true' : 'false');
      if (b.onflip) b.onflip(b._on);
    };
    return b;
  }
  function hourBox(v) {
    var pairs = [];
    for (var h = 0; h < 24; h++) pairs.push([String(h), hour(h)]);
    return selectBox(pairs, String(v === undefined || v === null ? 7 : v));
  }
  function dayBox(v, monthly) {
    var pairs = [];
    if (monthly) for (var d = 1; d <= 28; d++) pairs.push([String(d), String(d) + '.']);
    else DAYS.forEach(function (w, i) { pairs.push([String(i + 1), w]); });
    return selectBox(pairs, String(v || 1));
  }
  function mailOffNote(host) {
    var n = el('div', 'tmx-note warn rpt-mailoff');
    n.appendChild(ic('mail', 15));
    n.appendChild(el('span', '', 'Mail is switched off: nothing is mailed. Reports are still made and kept here.'));
    var go = cmdButton('Settings → Mail', 'gear', 'small');
    go.onclick = function () { location.hash = '#settings/mail'; };
    n.appendChild(go);
    host.appendChild(n);
  }
  function download(run, fmt, b) {
    if (b) busy(b, true);
    return api('reports/download&run=' + enc(run.id) + '&format=' + enc(fmt)).then(function (d) {
      var bin = atob(String(d.data_b64 || ''));
      var u8 = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
      var a = el('a');
      a.href = URL.createObjectURL(new Blob([u8], {type: d.mime || 'application/octet-stream'}));
      a.download = d.filename || ('report.' + fmt);
      a.hidden = true;
      document.body.appendChild(a);
      a.click();
      setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 800);
    }).catch(oops).then(function () { if (b) busy(b, false); });
  }
  function fileButtons(run, small) {
    var row = el('span', 'rpt-files');
    (run.files || []).forEach(function (f) {
      var b = cmdButton(String(f.format).toUpperCase(), 'download', small ? 'small' : '');
      b.classList.add('rpt-dl', 'rpt-dl-' + f.format);
      b.setAttribute('aria-label', tr('Download') + ' ' + f.filename);
      b.onclick = function () { download(run, f.format, b); };
      row.appendChild(b);
    });
    return row;
  }

  /* ==== the pane ========================================================================== */
  function drawPane() {
    var host = $('rpt-host');
    if (!host) return;
    if (!host.firstChild) host.appendChild(el('div', 'tmx-asking', 'Asking…'));
    api('reports').then(function (d) {
      R.d = d || {};
      clear(host);
      host.appendChild(paneBody(R.d));
      if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(host); } catch (e) { } }
    }).catch(function (e) {
      clear(host);
      var c = el('div', 'card full rpt-denied');
      c.appendChild(el('p', 'muted', e && e.message ? e.message : 'The reports could not be read.'));
      host.appendChild(c);
    });
  }
  function paneBody(d) {
    var box = el('div', 'rpt');
    var list = d.reports || [];
    if (!d.mail_on) mailOffNote(box);
    var bar = el('div', 'rpt-bar');
    var sum = el('div', 'rpt-bar-w');
    sum.appendChild(ic('chart', 18, 'rpt-bar-ic'));
    var t = el('div', '');
    t.appendChild(el('b', '', list.length === 1 ? '1 report' : num(list.length) + ' reports'));
    var nexts = list.map(function (r) { return r.next_at; }).filter(Boolean).sort();
    t.appendChild(el('span', 'muted small rpt-bar-s', nexts.length ? 'The next one is made ' + when(nexts[0]) : (list.length ? 'None is made by itself - each by hand' : 'Nothing is made until a report is defined')));
    sum.appendChild(t);
    bar.appendChild(sum);
    if (d.may_change) {
      var add = cmdButton('New report', 'add', 'primary');
      add.id = 'rpt-new';
      add.onclick = function () { editReport(null); };
      bar.appendChild(add);
    }
    box.appendChild(bar);
    if (!list.length) {
      box.appendChild(emptyState(d));
      return box;
    }
    var grid = el('div', 'rpt-grid');
    list.forEach(function (r) { grid.appendChild(reportCard(r, d)); });
    box.appendChild(grid);
    return box;
  }
  function emptyState(d) {
    var e = el('div', 'rpt-empty');
    var h = el('div', 'rpt-empty-h');
    h.appendChild(ic('chart', 30, 'rpt-empty-ic'));
    var w = el('div', '');
    w.appendChild(el('h3', '', d.may_change ? 'No report yet' : 'No report of your teams'));
    w.appendChild(el('p', 'muted', d.may_change ? 'Pick what the report says to start - you choose its teams, formats, schedule and recipients next. Nothing is made or mailed until you save it.'
      : 'A full administrator defines the reports. Those of the teams you manage show here, to preview and download.'));
    h.appendChild(w);
    e.appendChild(h);
    if (d.may_change) {
      var kinds = el('div', 'rpt-kinds');
      (d.kinds || []).forEach(function (k) {
        var b = el('button', 'rpt-kind k-' + (KIND_TONE[k.kind] || 'info'));
        b.type = 'button';
        b.dataset.kind = k.kind;
        b.appendChild(ic(KIND_ICON[k.kind] || 'chart', 20, 'rpt-kind-ic'));
        b.appendChild(el('b', '', k.words));
        b.appendChild(el('span', 'muted small', k.says));
        b.onclick = function () { editReport(null, k.kind); };
        kinds.appendChild(b);
      });
      e.appendChild(kinds);
    }
    return e;
  }
  function reportCard(r, d) {
    var c = el('article', 'rpt-card k-' + (KIND_TONE[r.kind] || 'info') + (r.enabled ? '' : ' paused'));
    c.dataset.report = r.name;
    var top = el('div', 'rpt-card-top');
    top.appendChild(ic(KIND_ICON[r.kind] || 'chart', 20, 'rpt-card-ic'));
    var tw = el('div', 'rpt-card-tw');
    tw.appendChild(data('h3', 'rpt-card-n', r.name));
    tw.appendChild(el('span', 'rpt-card-k', r.kind_words));
    top.appendChild(tw);
    if (d.may_change) {
      var acts = el('div', 'rpt-card-a');
      var ed = iconButton('edit', 'Change this report');
      ed.classList.add('rpt-edit');
      ed.onclick = function () { editReport(r); };
      var del = iconButton('trash', 'Delete this report and its runs');
      del.classList.add('rpt-del');
      del.onclick = function () { deleteReport(r); };
      acts.appendChild(ed);
      acts.appendChild(del);
      top.appendChild(acts);
    }
    c.appendChild(top);
    var chips = el('div', 'rpt-chips');
    if ((r.teams || []).length) r.teams.forEach(function (t) { chips.appendChild(dataChip(t, 'info', 'people')); });
    else chips.appendChild(chip('Every team', 'dim', 'people'));
    (r.formats || []).forEach(function (f) { chips.appendChild(chip(String(f).toUpperCase(), f === 'pdf' ? 'crit' : 'ok', 'download')); });
    chips.appendChild(chip(schedWords(r.schedule), r.schedule && r.schedule.every !== 'off' ? 'violet' : 'dim', 'clock'));
    if (!r.enabled) chips.appendChild(chip('Paused', 'warn'));
    if ((r.recipients || []).length) chips.appendChild(chip(r.recipients.length === 1 ? 'Mailed to 1 address' : 'Mailed to ' + r.recipients.length + ' addresses', 'dim', 'mail'));
    c.appendChild(chips);
    var facts = el('div', 'rpt-facts');
    var last = r.last;
    var lf = el('div', 'rpt-fact');
    lf.appendChild(el('span', 'rpt-fact-h', 'Last run'));
    if (last) {
      var lw = el('span', 'rpt-fact-v');
      lw.appendChild(el('span', '', agoWords(last.ts)));
      lw.appendChild(noI18n(el('span', 'muted', ' · ')));
      lw.appendChild(el('span', 'muted', last.rows === 1 ? '1 row' : num(last.rows) + ' rows'));
      lf.appendChild(lw);
      if (!last.ok) lf.appendChild(chip('Not mailed', 'crit'));
      else if ((last.sent_to || []).length) lf.appendChild(chip('Mailed', 'ok', 'mail'));
    } else lf.appendChild(el('span', 'rpt-fact-v muted', 'Never'));
    facts.appendChild(lf);
    var nf = el('div', 'rpt-fact');
    nf.appendChild(el('span', 'rpt-fact-h', 'Next run'));
    nf.appendChild(el('span', 'rpt-fact-v' + (r.next_at ? '' : ' muted'), r.next_at ? when(r.next_at) : 'By hand'));
    facts.appendChild(nf);
    c.appendChild(facts);
    var foot = el('div', 'rpt-card-f');
    var pv = cmdButton('Preview', 'eye', 'small');
    pv.classList.add('rpt-preview');
    pv.onclick = function () { previewReport({id: r.id}, r.name, pv, r.lang || null); };
    foot.appendChild(pv);
    if (d.may_change) {
      var run = cmdButton('Run now', 'play', 'small primary');
      run.classList.add('rpt-run');
      run.onclick = function () { runReport(r, d); };
      foot.appendChild(run);
    }
    var hist = cmdButton('Runs', 'history', 'small');
    hist.classList.add('rpt-runs');
    hist.onclick = function () { runsDialog(r); };
    foot.appendChild(hist);
    if (last && (last.files || []).length) {
      var sp = el('span', 'rpt-spacer');
      foot.appendChild(sp);
      foot.appendChild(fileButtons(last, true));
    }
    c.appendChild(foot);
    return c;
  }

  /* -- the report as a page ------------------------------------------------------------- */
  function paper(p) {
    var pp = el('div', 'rpt-paper');
    var band = el('div', 'rpt-paper-band');
    var k = el('div', 'rpt-paper-k');
    k.appendChild(el('span', '', p.kind_words));
    k.appendChild(document.createTextNode(' · '));
    k.appendChild(data('span', '', p.scope));
    band.appendChild(k);
    var tl = el('div', 'rpt-paper-tl');
    tl.appendChild(data('h3', 'rpt-paper-t', p.title));
    tl.appendChild(el('span', 'rpt-paper-d', when(p.made)));
    band.appendChild(tl);
    pp.appendChild(band);
    var tiles = el('div', 'rpt-ptiles');
    (p.tiles || []).forEach(function (t) {
      var x = el('div', 'rpt-ptile t-' + (t.tone || 'dim'));
      x.appendChild(data('b', 'rpt-ptile-v', String(t.value)));
      x.appendChild(data('span', 'rpt-ptile-l', t.label));
      tiles.appendChild(x);
    });
    pp.appendChild(tiles);
    if (p.note) pp.appendChild(data('p', 'rpt-paper-note', p.note));
    pp.appendChild(table(p.columns, p.rows, p.tones));
    if (p.total > (p.rows || []).length) pp.appendChild(el('p', 'rpt-paper-more', 'The first ' + num((p.rows || []).length) + ' rows of ' + num(p.total) + ' - the files have every one.'));
    (p.sections || []).forEach(function (s) {
      pp.appendChild(data('h4', 'rpt-paper-h', s.heading));
      pp.appendChild(table(s.columns, s.rows));
    });
    return pp;
  }
  function table(cols, rows, tones) {
    var sc = el('div', 'rpt-pscroll');
    sc.tabIndex = 0;
    sc.setAttribute('role', 'region');
    sc.setAttribute('aria-label', tr('The report\'s rows'));
    var t = noI18n(el('table', 'rpt-ptable'));
    var thead = el('thead');
    var hr = el('tr');
    (cols || []).forEach(function (c) { hr.appendChild(noI18n(el('th', c.num ? 'num' : '', c.head))); });
    thead.appendChild(hr);
    t.appendChild(thead);
    var tb = el('tbody');
    if (!(rows || []).length) {
      var er = el('tr');
      var td = el('td', 'rpt-none', tr('Nothing to report.'));
      td.colSpan = (cols || []).length || 1;
      er.appendChild(td);
      tb.appendChild(er);
    }
    (rows || []).forEach(function (r, i) {
      var tr_ = el('tr');
      r.forEach(function (v, j) {
        var tone = tones && tones[i] && tones[i][j];
        var td = el('td', ((cols[j] || {}).num ? 'num' : '') + (tone ? ' t-' + tone : ''));
        if (tone) td.appendChild(el('span', 'rpt-pill t-' + tone, String(v)));
        else td.textContent = String(v === null || v === undefined ? '' : v);
        tr_.appendChild(td);
      });
      tb.appendChild(tr_);
    });
    t.appendChild(tb);
    sc.appendChild(t);
    return sc;
  }
  function pageLang() { return (typeof I18N === 'object' && I18N && I18N.on && I18N.code === 'cs') ? 'cs' : 'en'; }
  function previewReport(body, title, b, lang, own) {
    /* in the report's own language - one without its own is shown in the page's */
    if (!lang && !own) lang = pageLang();
    if (b) busy(b, true);
    return api('reports/preview', lang ? Object.assign({lang: lang}, body) : body).then(function (x) {
      var p = x.preview;
      modal(tr('Preview: {0}').replace('{0}', title || p.title), function (bd) {
        bd.classList.add('rpt-dlg');
        var top = el('div', 'rpt-pv-top');
        top.appendChild(el('span', 'muted small', 'What the report says now - nothing is kept or mailed.'));
        var langs = segmented([['cs', 'Čeština'], ['en', 'English']], p.lang);
        langs.classList.add('small');
        langs.setAttribute('aria-label', tr('The report\'s language'));
        langs.onchange = function () { closeModal(true); previewReport(body, title, null, langs.value); };
        top.appendChild(langs);
        bd.appendChild(top);
        bd.appendChild(paper(p));
      }, [{words: 'Close', close: true}], 'al-report');
    }).catch(oops).then(function () { if (b) busy(b, false); });
  }

  /* -- run, runs, delete ---------------------------------------------------------------- */
  function runReport(r, d) {
    var may = d.mail_on && (r.recipients || []).length;
    modal(tr('Run {0} now').replace('{0}', r.name), function (bd) {
      bd.classList.add('rpt-dlg');
      bd.appendChild(el('p', 'note', 'The report is made now from what acme holds, kept with its other runs and ready to download.'));
      var sw = switchBox(false);
      sw.id = 'rpt-run-send';
      if (!may) sw._input.disabled = true;
      bd.appendChild(formField('Also mail it to its recipients', sw, !d.mail_on ? 'Mail is switched off (Settings → Mail).'
        : ((r.recipients || []).length ? (r.recipients || []).join(', ') : 'It has no recipients - add them in its settings.')));
      runReport._sw = sw;
    }, [{words: 'Close', close: true},
        {words: 'Run it', cls: 'primary', icon: 'play', go: function (b) {
          busy(b, true);
          api('reports/run', {id: r.id, send: !!(runReport._sw && runReport._sw._get())}).then(function (x) {
            closeModal(true);
            toast(x.message || 'made', x.run && x.run.ok ? 'good' : 'bad');
            drawPane();
            runsDialog(r, x.run);
          }).catch(oops).then(function () { busy(b, false); });
        }}], true);
  }
  function runsDialog(r, fresh) {
    api('reports/runs&id=' + enc(r.id)).then(function (x) {
      modal(tr('Runs of {0}').replace('{0}', r.name), function (bd) {
        bd.classList.add('rpt-dlg');
        var runs = x.runs || [];
        if (!runs.length) {
          bd.appendChild(el('p', 'muted', 'No run kept yet - Run now makes one, and so does its schedule.'));
          return;
        }
        bd.appendChild(el('p', 'muted small', 'The newest are kept - how many is in the report\'s settings.'));
        var list = el('div', 'rpt-runlist');
        runs.forEach(function (u) {
          var row = el('div', 'rpt-run' + (fresh && fresh.id === u.id ? ' fresh' : ''));
          var w = el('div', 'rpt-run-w');
          var t1 = el('div', 'rpt-run-t');
          t1.appendChild(el('b', '', when(u.ts)));
          t1.appendChild(el('span', 'muted small', u.rows === 1 ? '1 row' : num(u.rows) + ' rows'));
          if ((u.sent_to || []).length) t1.appendChild(chip('Mailed', 'ok', 'mail'));
          else if (!u.ok) t1.appendChild(chip('Not mailed', 'crit'));
          w.appendChild(t1);
          var by = el('div', 'muted small');
          by.appendChild(data('span', '', tr('Made by {0}').replace('{0}', u.by)));
          if ((u.sent_to || []).length) by.appendChild(data('span', '', ' · ' + tr('mailed to {0}').replace('{0}', u.sent_to.join(', '))));
          else if (!u.ok && u.said) { by.appendChild(noI18n(el('span', '', ' · '))); by.appendChild(el('span', '', u.said)); }
          w.appendChild(by);
          row.appendChild(w);
          row.appendChild(fileButtons(u, true));
          list.appendChild(row);
        });
        bd.appendChild(list);
      }, [{words: 'Close', close: true}], true);
    }).catch(oops);
  }
  function deleteReport(r) {
    confirmThen(tr('Delete {0}').replace('{0}', r.name),
      htmlText(tr('The report {0} and every run kept of it are deleted. Files already downloaded or mailed stay where they are.').replace('{0}', r.name)),
      'Delete it', function () {
        api('reports/delete', {id: r.id}).then(function (x) { toast(x.message || 'deleted', 'good'); drawPane(); }).catch(oops);
      });
  }

  /* -- define one -------------------------------------------------------------------------- */
  function teamNames() {
    var d = (window.ACME_TEAMS && ACME_TEAMS.load) ? ACME_TEAMS.load() : api('teams');
    return Promise.resolve(d).then(function (x) { return ((x || {}).teams || []).map(function (t) { return t.name; }); }).catch(function () { return []; });
  }
  function editReport(r, kind) {
    var d = R.d || {};
    r = r || {kind: kind || 'inventory', teams: [], formats: ['pdf', 'csv'], schedule: {every: 'off', day: 1, hour: 7},
              recipients: [], lang: '', keep: 12, options: {}, enabled: true};
    teamNames().then(function (names) {
      var f = {};
      modal(r.id ? tr('Change {0}').replace('{0}', r.name) : tr('New report'), function (bd) {
        bd.classList.add('rpt-dlg', 'rpt-form');
        var name = textBox(r.name || '', 'e.g. Monthly certificate inventory');
        name.id = 'rpt-f-name';
        name.maxLength = 80;
        bd.appendChild(formField('Name', name));
        f.name = name;
        /* the kind: cards */
        var kinds = el('div', 'rpt-kinds compact');
        kinds.setAttribute('role', 'radiogroup');
        kinds.setAttribute('aria-label', tr('What the report says'));
        var days = numBox((r.options || {}).days || 90, 1, 3650);
        days.id = 'rpt-f-days';
        var daysItem = formField('Days ahead', days, 'What ends within this many days is in it - those already ended too.');
        f.kind = r.kind;
        (d.kinds || []).forEach(function (k) {
          var b = el('button', 'rpt-kind k-' + (KIND_TONE[k.kind] || 'info') + (k.kind === f.kind ? ' on' : ''));
          b.type = 'button';
          b.dataset.kind = k.kind;
          b.setAttribute('role', 'radio');
          b.setAttribute('aria-checked', k.kind === f.kind ? 'true' : 'false');
          b.appendChild(ic(KIND_ICON[k.kind] || 'chart', 18, 'rpt-kind-ic'));
          b.appendChild(el('b', '', k.words));
          b.appendChild(el('span', 'muted small', k.says));
          b.onclick = function () {
            f.kind = k.kind;
            kinds.querySelectorAll('.rpt-kind').forEach(function (x) {
              x.classList.toggle('on', x === b);
              x.setAttribute('aria-checked', x === b ? 'true' : 'false');
            });
            daysItem.hidden = f.kind !== 'expiry';
          };
          kinds.appendChild(b);
        });
        bd.appendChild(formField('What the report says', kinds));
        daysItem.hidden = f.kind !== 'expiry';
        bd.appendChild(daysItem);
        /* the scope */
        var chosen = (r.teams || []).slice();
        var scope = segmented([['all', 'Every team', 'people'], ['some', 'Chosen teams', 'funnel']], chosen.length ? 'some' : 'all');
        scope.id = 'rpt-f-scope';
        var pick = el('div', 'rpt-togs');
        pick.id = 'rpt-f-teams';
        names.forEach(function (n) {
          var b = toggleChip(n, chosen.indexOf(n) >= 0, 'people', true);
          b.dataset.team = n;
          b.onflip = function (on) { if (on) chosen.push(n); else chosen = chosen.filter(function (x) { return x !== n; }); };
          pick.appendChild(b);
        });
        if (!names.length) pick.appendChild(el('span', 'muted small', 'No team is defined yet (Owners and teams).'));
        pick.hidden = scope.value !== 'some';
        scope.onchange = function () { pick.hidden = scope.value !== 'some'; };
        var sw = el('div', 'rpt-stack');
        sw.appendChild(scope);
        sw.appendChild(pick);
        bd.appendChild(formField('Teams', sw, 'Chosen teams take the teams below them too. Every team also takes the certificates and agents that have no team.'));
        f.scope = scope;
        f.teams = function () { return scope.value === 'some' ? chosen : []; };
        /* the formats */
        var fm = el('div', 'rpt-togs');
        fm.id = 'rpt-f-formats';
        var fPdf = toggleChip('PDF - for reading and printing', (r.formats || []).indexOf('pdf') >= 0, 'download');
        fPdf.dataset.format = 'pdf';
        var fCsv = toggleChip('CSV - for a spreadsheet', (r.formats || []).indexOf('csv') >= 0, 'download');
        fCsv.dataset.format = 'csv';
        fm.appendChild(fPdf);
        fm.appendChild(fCsv);
        bd.appendChild(formField('Formats', fm));
        f.formats = function () { return (fPdf._on ? ['pdf'] : []).concat(fCsv._on ? ['csv'] : []); };
        /* the schedule */
        var s = r.schedule || {};
        var every = segmented([['off', 'By hand', 'play'], ['weekly', 'Weekly', 'clock'], ['monthly', 'Monthly', 'clock']], s.every || 'off');
        every.id = 'rpt-f-every';
        var when_ = el('div', 'rpt-when');
        var day = dayBox(s.day, s.every === 'monthly');
        day.id = 'rpt-f-day';
        day.setAttribute('aria-label', tr('Day'));
        var hr = hourBox(s.hour);
        hr.id = 'rpt-f-hour';
        hr.setAttribute('aria-label', tr('Hour'));
        when_.appendChild(el('span', 'muted small', 'Day'));
        when_.appendChild(day);
        when_.appendChild(el('span', 'muted small', 'Time'));
        when_.appendChild(hr);
        var paint = function () {
          when_.hidden = every.value === 'off';
          var keep = day.value;
          var nd = dayBox(every.value === 'monthly' ? Math.min(28, Number(keep) || 1) : Math.min(7, Number(keep) || 1), every.value === 'monthly');
          nd.id = 'rpt-f-day';
          nd.setAttribute('aria-label', tr('Day'));
          when_.replaceChild(nd, day);
          day = nd;
        };
        every.onchange = paint;
        when_.hidden = every.value === 'off';
        var sch = el('div', 'rpt-stack');
        sch.appendChild(every);
        sch.appendChild(when_);
        bd.appendChild(formField('Made by itself', sch, 'On the node that leads the cluster, once a week or a month - and mailed to the recipients below.'));
        f.schedule = function () { return {every: every.value, day: Number(day.value), hour: Number(hr.value)}; };
        /* recipients, language, keep, paused */
        var to = el('textarea', 'rpt-to');
        to.id = 'rpt-f-to';
        to.rows = 2;
        to.value = (r.recipients || []).join(', ');
        to.placeholder = 'boss@example.com, audit@example.com';
        bd.appendChild(formField('Mailed to', to, d.mail_on ? 'Addresses, comma between them. Empty: kept here only.' : 'Mail is switched off - kept here only until it is switched on.'));
        f.to = to;
        var row = el('div', 'rpt-row3');
        var lang = selectBox([['', 'The mails\' language'], ['cs', 'Čeština'], ['en', 'English']], r.lang || '');
        lang.id = 'rpt-f-lang';
        row.appendChild(formField('Language', lang));
        var keep = numBox(r.keep || 12, 1, 100);
        keep.id = 'rpt-f-keep';
        row.appendChild(formField('Runs kept', keep));
        var on = switchBox(r.enabled !== false);
        on.id = 'rpt-f-on';
        row.appendChild(formField('Schedule active', on));
        bd.appendChild(row);
        f.lang = lang;
        f.keep = keep;
        f.on = on;
        f.days = days;
        f.id = r.id;
      }, [{words: 'Close', close: true},
          {words: 'Preview', icon: 'eye', go: function (b) { var dr = readForm(f); previewReport({draft: dr}, f.name.value || tr('New report'), b, dr.lang || null); }},
          {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
            busy(b, true);
            api('reports/save', readForm(f)).then(function (x) {
              toast(x.message || 'saved', 'good');
              closeModal(true);
              drawPane();
            }).catch(oops).then(function () { busy(b, false); });
          }}], 'medium');
    });
  }
  function readForm(f) {
    var out = {name: f.name.value.trim(), kind: f.kind, teams: f.teams(), formats: f.formats(),
               schedule: f.schedule(), recipients: f.to.value, lang: f.lang.value, keep: Number(f.keep.value) || 12,
               enabled: !!f.on._get(), options: f.kind === 'expiry' ? {days: Number(f.days.value) || 90} : {}};
    if (f.id) out.id = f.id;
    return out;
  }

  /* ==== a team's Digest tab ===================================================================== */
  var SECTIONS = [['clock', 'Certificates ending soon', 'and those that already ended'],
                  ['flag', 'Renewals and deployments that failed', 'since the last digest'],
                  ['bell', 'What waits', 'approvals, requests for a temporary role, access reviews'],
                  ['key', 'Temporary roles', 'granted, ending soon, ended'],
                  ['router', 'Agents that need a look', 'quiet, refused, waiting for confirmation']];
  function digestWords(g) {
    if (!g.on) return 'Off';
    return g.every === 'daily' ? tr('Every day at {0}').replace('{0}', hour(g.hour)) : tr('Every {0} at {1}').replace('{0}', tr(DAYS[(Number(g.day) || 1) - 1])).replace('{1}', hour(g.hour));
  }
  function digestTab(box, T, n) {
    var t = n.t || {name: n.name};
    var host = el('div', 'rpt-dg');
    box.appendChild(host);
    host.appendChild(el('div', 'tmx-asking', 'Asking…'));
    api('teams/digest&team=' + enc(t.name)).then(function (x) {
      clear(host);
      drawDigest(host, t, x);
      if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(host); } catch (e) { } }
    }).catch(function (e) { clear(host); host.appendChild(el('p', 'muted', e && e.message ? e.message : 'The digest could not be read.')); });
  }
  function drawDigest(host, t, x) {
    var g = x.digest || {};
    if (!x.mail_on) mailOffNote(host);
    var hero = el('section', 'rpt-dg-hero' + (g.on ? ' on' : ''));
    var hi = el('div', 'rpt-dg-hic');
    hi.innerHTML = iconMarkup('mail', 24);
    hero.appendChild(hi);
    var hw = el('div', 'rpt-dg-hw');
    var h3 = el('h3', 'rpt-dg-ht');
    h3.appendChild(el('span', '', g.every === 'daily' ? 'Daily digest' : 'Weekly digest'));
    h3.appendChild(chip(g.on ? 'On' : 'Off', g.on ? 'ok' : 'dim'));
    hw.appendChild(h3);
    hw.appendChild(el('p', 'rpt-dg-hs', g.on ? digestWords(g) : 'The team gets no digest. Switched on, it gets one mail a week (or a day) with what needs it.'));
    var meta = el('div', 'rpt-dg-meta');
    if (g.on && g.next_at) meta.appendChild(chip('Next: ' + when(g.next_at), 'violet', 'clock'));
    if (g.last && g.last.at) {
      var lc = g.last.skipped ? chip('Last: nothing to tell, not sent ' + agoWords(g.last.at), 'dim', 'history')
        : chip((g.last.ok ? 'Last sent ' : 'Last not sent ') + agoWords(g.last.at), g.last.ok ? 'ok' : 'crit', 'history');
      if (g.last.said) explain(lc, g.last.said);
      meta.appendChild(lc);
    }
    if (meta.firstChild) hw.appendChild(meta);
    hero.appendChild(hw);
    var acts = el('div', 'rpt-dg-acts');
    var pv = cmdButton('Show the preview', 'eye', 'small');
    pv.id = 'rpt-dg-preview';
    pv.onclick = function () { digestPreview(t, null, pv); };
    acts.appendChild(pv);
    var me = cmdButton('Send a preview to me', 'mail', 'small');
    me.id = 'rpt-dg-me';
    if (!x.mail_on) me.disabled = true;
    me.onclick = function () { sendMe(t, null, me); };
    acts.appendChild(me);
    if (x.may_change) {
      var set = cmdButton('Set it', 'edit', 'small primary');
      set.id = 'rpt-dg-set';
      set.onclick = function () { editDigest(t, x); };
      acts.appendChild(set);
      var now = cmdButton('Send now', 'play', 'small');
      now.id = 'rpt-dg-now';
      if (!x.mail_on) now.disabled = true;
      now.onclick = function () {
        confirmThen(tr('Send the digest of {0} now').replace('{0}', t.name), htmlText(tr('It goes to its recipients now, an empty one too. The next one by the schedule covers what comes after.')), 'Send it', function () {
          api('teams/digest_send', {team: t.name}).then(function (r) {
            toast(r.message || 'sent', r.result && r.result.ok ? 'good' : 'bad');
            refreshTab(host, t);
          }).catch(oops);
        }, false);
      };
      acts.appendChild(now);
    }
    hero.appendChild(acts);
    host.appendChild(hero);
    var grid = el('div', 'rpt-dg-grid');
    var what = el('section', 'tmx-sec rpt-dg-card');
    var wh = el('h3', 'tmx-sec-h');
    wh.appendChild(ic('list', 16));
    wh.appendChild(el('span', '', 'What goes in'));
    what.appendChild(wh);
    SECTIONS.forEach(function (s, i) {
      var r = el('div', 'rpt-dg-sec');
      r.appendChild(ic(s[0], 15, 'rpt-dg-sic'));
      var w = el('div', '');
      w.appendChild(el('b', '', i === 0 ? 'Certificates ending within ' + (g.days || 30) + ' days' : s[1]));
      w.appendChild(el('span', 'muted small', s[2]));
      r.appendChild(w);
      what.appendChild(r);
    });
    var scope = el('p', 'muted small rpt-dg-foot', g.below ? 'Of this team and every team below it.' : 'Of this team only.');
    what.appendChild(scope);
    if (g.skip_empty) what.appendChild(el('p', 'muted small rpt-dg-foot', 'When nothing needs the team, nothing is sent.'));
    grid.appendChild(what);
    var who = el('section', 'tmx-sec rpt-dg-card');
    var whh = el('h3', 'tmx-sec-h');
    whh.appendChild(ic('people', 16));
    whh.appendChild(el('span', '', 'Who gets it'));
    who.appendChild(whh);
    var any = false;
    if (g.contact) {
      var cr = el('div', 'rpt-dg-who');
      cr.appendChild(ic('mail', 15, 'rpt-dg-sic'));
      var cw = el('div', '');
      cw.appendChild(el('b', '', 'The team\'s address'));
      if (Array.isArray(g.contact_mail)) cw.appendChild(data('span', 'muted small', g.contact_mail.join(', ') || '–'));
      else cw.appendChild(el('span', 'muted small', g.contact_mail ? 'as the team says' : 'the team has no address - set it under Edit'));
      cr.appendChild(cw);
      who.appendChild(cr);
      any = true;
    }
    (g.members || []).forEach(function (m) {
      var r = el('div', 'rpt-dg-who');
      r.appendChild(ic(/^group:/i.test(m) ? 'people' : 'person', 15, 'rpt-dg-sic'));
      var w = el('div', '');
      w.appendChild(data('b', '', String(m).replace(/^local:/i, '')));
      var info = (x.members || []).filter(function (y) { return y.who === m; })[0];
      if (info) w.appendChild(el('span', 'muted small', info.mails ? (info.mails === 1 ? '1 address' : info.mails + ' addresses') : 'no address in acme'));
      r.appendChild(w);
      who.appendChild(r);
      any = true;
    });
    if (!any) who.appendChild(el('p', 'muted small', 'Nobody yet.'));
    who.appendChild(el('p', 'muted small rpt-dg-foot', g.lang ? (g.lang === 'cs' ? 'In Czech.' : 'In English.') : 'Each in their own language where acme knows it.'));
    grid.appendChild(who);
    host.appendChild(grid);
  }
  function refreshTab(host, t) {
    api('teams/digest&team=' + enc(t.name)).then(function (x) { clear(host); drawDigest(host, t, x); }).catch(oops);
  }
  function digestPreview(t, draft, b) {
    if (b) busy(b, true);
    var lang = (draft && draft.lang) || pageLang();
    return api('teams/digest_preview', {team: t.name, digest: draft || undefined, lang: lang}).then(function (x) {
      var p = x.preview;
      modal(tr('Digest of {0}: preview').replace('{0}', t.name), function (bd) {
        bd.classList.add('rpt-dlg');
        var top = el('div', 'rpt-pv-top');
        var subj = el('div', 'rpt-pv-subj');
        subj.appendChild(el('span', 'muted small', 'Subject'));
        subj.appendChild(data('b', '', p.subject));
        top.appendChild(subj);
        bd.appendChild(top);
        var facts = el('div', 'rpt-chips');
        facts.appendChild(chip(p.recipients.length === 1 ? 'To 1 recipient' : 'To ' + p.recipients.length + ' recipients', p.recipients.length ? 'info' : 'warn', 'mail'));
        if (p.would_skip) facts.appendChild(chip('Nothing needs the team: it would not be sent', 'dim'));
        if (!p.mail_on) facts.appendChild(chip('Mail is switched off', 'warn'));
        bd.appendChild(facts);
        var f = el('iframe', 'al-frame rpt-frame');
        f.setAttribute('sandbox', '');
        f.setAttribute('title', p.subject);
        f.srcdoc = p.html;
        bd.appendChild(f);
      }, [{words: 'Close', close: true},
          {words: 'Send a preview to me', icon: 'mail', go: function (bb) { sendMe(t, draft, bb); }}], 'al-report');
    }).catch(oops).then(function () { if (b) busy(b, false); });
  }
  function sendMe(t, draft, b) {
    if (b) busy(b, true);
    return api('teams/digest_send_me', {team: t.name, digest: draft || undefined}).then(function (x) {
      toast(x.message || 'sent', 'good');
    }).catch(oops).then(function () { if (b) busy(b, false); });
  }
  function editDigest(t, x) {
    var g = x.digest || {};
    var f = {};
    modal(tr('Digest of {0}').replace('{0}', t.name), function (bd) {
      bd.classList.add('rpt-dlg', 'rpt-form');
      var on = switchBox(!!g.on);
      on.id = 'rpt-dg-on';
      bd.appendChild(formField('Send the team a digest by mail', on, 'One mail with what needs the team: what ends soon, what failed, what waits, temporary roles, agents to look at.'));
      var every = segmented([['weekly', 'Weekly', 'clock'], ['daily', 'Every day', 'clock']], g.every || 'weekly');
      every.id = 'rpt-dg-every';
      var whenRow = el('div', 'rpt-when');
      var day = dayBox(g.day || 1, false);
      day.id = 'rpt-dg-day';
      day.setAttribute('aria-label', tr('Day'));
      var hr = hourBox(g.hour === undefined ? 7 : g.hour);
      hr.id = 'rpt-dg-hour';
      hr.setAttribute('aria-label', tr('Hour'));
      var dayWrap = el('span', 'rpt-when');
      dayWrap.appendChild(el('span', 'muted small', 'Day'));
      dayWrap.appendChild(day);
      whenRow.appendChild(dayWrap);
      whenRow.appendChild(el('span', 'muted small', 'Time'));
      whenRow.appendChild(hr);
      dayWrap.hidden = every.value === 'daily';
      every.onchange = function () { dayWrap.hidden = every.value === 'daily'; };
      var st = el('div', 'rpt-stack');
      st.appendChild(every);
      st.appendChild(whenRow);
      bd.appendChild(formField('When', st, 'The first one goes at the next moment chosen - never at once.'));
      var days = numBox(g.days || 30, 1, 365);
      days.id = 'rpt-dg-days';
      bd.appendChild(formField('Certificates ending within (days)', days));
      var contact = switchBox(g.contact !== false);
      contact.id = 'rpt-dg-contact';
      bd.appendChild(formField('To the team\'s address', contact, Array.isArray(g.contact_mail) && g.contact_mail.length ? g.contact_mail.join(', ') : 'The team has no address yet (Edit on the team\'s page).'));
      var chosen = (g.members || []).slice();
      var pick = el('div', 'rpt-togs');
      pick.id = 'rpt-dg-members';
      (x.members || []).forEach(function (m) {
        var b = toggleChip(String(m.who).replace(/^local:/i, ''), chosen.indexOf(m.who) >= 0, m.kind === 'group' ? 'people' : 'person', true);
        b.dataset.who = m.who;
        if (!m.mails) b.classList.add('nomail');
        if (!m.mails) explain(b, 'No address in acme for this member - it would get nothing.');
        b.onflip = function (v) { if (v) chosen.push(m.who); else chosen = chosen.filter(function (y) { return y !== m.who; }); };
        pick.appendChild(b);
      });
      if (!(x.members || []).length) pick.appendChild(el('span', 'muted small', 'The team has no members.'));
      bd.appendChild(formField('To members', pick, 'Each gets it at the address of their account, in their own language. A group: every member of it who signed in with an address.'));
      var row = el('div', 'rpt-row3');
      var skip = switchBox(g.skip_empty !== false);
      skip.id = 'rpt-dg-skip';
      row.appendChild(formField('Not sent when empty', skip));
      var below = switchBox(g.below !== false);
      below.id = 'rpt-dg-below';
      row.appendChild(formField('With the teams below', below));
      var lang = selectBox([['', 'Each recipient\'s own'], ['cs', 'Čeština'], ['en', 'English']], g.lang || '');
      lang.id = 'rpt-dg-lang';
      row.appendChild(formField('Language', lang));
      bd.appendChild(row);
      f.read = function () {
        return {on: !!on._get(), every: every.value, day: Number(day.value), hour: Number(hr.value), days: Number(days.value) || 30,
                contact: !!contact._get(), members: chosen, skip_empty: !!skip._get(), below: !!below._get(), lang: lang.value};
      };
    }, [{words: 'Close', close: true},
        {words: 'Show the preview', icon: 'eye', go: function (b) { digestPreview(t, f.read(), b); }},
        {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
          busy(b, true);
          api('teams/digest_save', {team: t.name, digest: f.read()}).then(function (r) {
            toast(r.message || 'saved', 'good');
            closeModal(true);
            var host = document.querySelector('.rpt-dg');
            if (host) refreshTab(host, t);
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }

  /* ==== plugged in ============================================================================ */
  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.reports = function () { drawPane(); };
  window.ACME_TEAM_TABS = window.ACME_TEAM_TABS || [];
  if (!window.ACME_TEAM_TABS.some(function (x) { return x.name === 'digest'; })) {
    window.ACME_TEAM_TABS.push({name: 'digest', title: 'Digest', icon: 'mail', draw: digestTab});
  }
  window.ACME_REPORTS = {draw: drawPane, preview: previewReport, digestTab: digestTab};
  /* a page that opened on this pane drew it before this file came */
  if (typeof PANE === 'string' && PANE === 'reports' && typeof TAB === 'string' && TAB === 'settings') drawPane();
})();
