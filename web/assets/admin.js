/* The time pickers (1.0.53), in place of the <select>s they replace. */
if ($('ev-time')) timePicker('ev-time', {start: {k: 'all'}, all: true});
/* admin.js - the administration pages of acme (certificates kept, renewed and
   put in place by themselves), drawn the way isemon draws its dashboard: the
   same header, tabs, rail, popups and panels (core.js), over the acme daemon's
   API. The page works nothing out for itself.

   ---- Extending the pages: what certs.js (or any later script) plugs into ----

   certs.js is loaded after this file (admin/index.php, when it is there), and
   the page starts only once every script has run (DOMContentLoaded), so what
   is registered below is known before the first tab is opened.

   window.ACME_EXTRA_TABS = [{name, draw, live}]
       A main tab of its own. Its button (<button role="tab" data-tab="NAME">)
       and its panel (<section class="panel" id="tab-NAME" hidden>) are printed
       by admin/certs-ui.php (acme_certs_tab_buttons, acme_certs_tab_panels);
       this only makes them work:
         name   the NAME above - also what #NAME in the address opens
         draw   function (ctx): called when the tab is shown, ctx = {live: false,
                status: STATUS}; and, with live: true, again on every live tick
                (every 5 s, unless paused, the window hidden, a popup open or the
                reader holding the panel - selecting, typing, pointing at help),
                ctx = {live: true, moved: <the daemon's serial changed>, status}
         live   true to be drawn again on the tick
       An entry named 'overview' adds no tab: its draw is called with the
       Overview's (shown and, live: true, on the tick) - to fill <div id="ov-certs">.

   window.ACME_EXTRA_PANES = {pane: draw}
       A pane of Settings: its rail button (<button data-pane="PANE">) and its
       <div class="ctl-pane" id="pane-PANE" hidden> are printed by certs-ui.php
       (acme_certs_settings_nav, acme_certs_settings_panes); draw(pane) is called
       each time the pane is opened. Settings of the daemon listed for that pane
       (GET /api/settings, panes[PANE]) are drawn into <div id="sect-PANE"> when
       it has one, and saved with the save bar like any other.

   What else there is to use, all globals: api(name[, body]) (relayed by
   admin/index.php: certs, certs/one, cas/create, targets/test, ... as named in
   docs/architecture.md), showTab(name), showPane(pane), modal, peek, listTable,
   el, clear, cmdButton, toast, oops, confirmThen, stepsList, nodeCell,
   qSuggest, searchButtons, ADMIN (a full administrator), CERTADMIN (a full or a
   cert administrator), ME, STATUS, TAB, PANE. */
'use strict';

ADMIN = !!(ME && ME.role === 'fulladmin');
var CERTADMIN = !!(ME && (ME.role === 'fulladmin' || ME.role === 'certadmin'));
var LIVE = true, SERIAL = STATUS ? STATUS.serial : '', PANE = '';
var SETTINGS = null, DIRTY = {}, DRAWN_NODE = '';
var PAGE = {events: 0};
window.ACME_EXTRA_TABS = window.ACME_EXTRA_TABS || [];
window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};

function roleWords(role) {
  return role === 'fulladmin' ? 'full admin' : (role === 'certadmin' ? 'cert admin' : 'read only');
}
function roleTone(role) {
  return role === 'fulladmin' ? 'violet' : (role === 'certadmin' ? 'warn' : 'dim');
}

/* ---- what this account may not even see ---------------------------------- */
(function roles() {
  document.querySelectorAll('.admin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  document.querySelectorAll('.fulladmin-only').forEach(function (n) { if (!ADMIN) n.hidden = true; });
  document.querySelectorAll('.certadmin-only').forEach(function (n) { if (!CERTADMIN) n.hidden = true; });
  if (!ADMIN) $('readonly-note').hidden = false;
  if (!ADMIN) $('save-bar').hidden = true;
}());
dressButtons(document);

/* ---- PHP and php2shell, said to an administrator (as on isemon) ---------- */
(function phpSafety() {
  var box = $('phpsafety'), s = PHP_SAFETY;
  if (!box || !s || s.patched) return;
  /* A distribution that backported the fix keeps the old number; the daemon
     reads the packages' changelog, and when it says the fix is in, so be it. */
  if (STATUS && STATUS.php && STATUS.php.fixed) return;
  box.hidden = false;
  box.classList.toggle('warnish', !!s.guarded);
  box.textContent = 'PHP ' + s.version + ' running this page may have php2shell '
    + '(CVE-2026-109618, CVE-2026-109619): remote code execution by anybody who can reach the '
    + 'web server. Update it - ' + (s.needs ? s.needs + ' or later, ' : '') + 'or the package '
    + 'your distribution fixed (dnf upgrade \'php*\') - and restart php-fpm; ./install.sh '
    + '--upgrade does it. A distribution that backported the fix keeps the old number: check '
    + 'rpm -q --changelog php-fpm | grep CVE-2026-109618.';
}());

/* ---- tabs ------------------------------------------------------------------ */
var TABS = ['overview', 'events', 'settings'];
/** Every tab there is: these, and the ones plugged in (ACME_EXTRA_TABS). */
function allTabs() {
  var all = TABS.slice();
  (window.ACME_EXTRA_TABS || []).forEach(function (t) {
    if (t && t.name && all.indexOf(t.name) < 0) all.push(t.name);
  });
  return all;
}
/** What is plugged in for one tab: its own, or more for the Overview. */
function extraTabs(name) {
  return (window.ACME_EXTRA_TABS || []).filter(function (t) { return t && t.name === name && typeof t.draw === 'function'; });
}
function extraDraw(name, ctx) {
  extraTabs(name).forEach(function (t) {
    if (ctx.live && !t.live) return;
    try { t.draw(ctx); } catch (e) { if (window.console) console.error(e); }
  });
}
window.optShowTab = function (name) {
  var all = allTabs();
  if (all.indexOf(name) < 0 || !$('tab-' + name)) name = 'overview';
  /* A tab this account may not use (its button is hidden) is not opened by
     the address either (1.0.15). */
  var btn = document.querySelector('.tabs button[data-tab="' + name + '"]');
  if (btn && btn.hidden) name = 'overview';
  TAB = name;
  document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
    b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false');
  });
  all.forEach(function (one) { if ($('tab-' + one)) $('tab-' + one).hidden = one !== name; });
  writeHash();
  holdTheTallOnes();
  onTab(name);
};
document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
  b.onclick = function () { showTab(b.getAttribute('data-tab')); };
});
function writeHash() {
  var want = '#' + TAB + (TAB === 'settings' && PANE ? '/' + PANE : '');
  if (location.hash !== want) try { history.replaceState(null, '', want); } catch (e) { }
}
function onTab(name, live) {
  explainWhatWasDrawn(document);
  if (name === 'overview') loadOverview();
  if (name === 'events') loadEvents();
  if (TABS.indexOf(name) < 0 || name === 'overview') extraDraw(name, {live: !!live, moved: true, status: STATUS});
  /* Coming back with changes not yet saved keeps them (1.0.15). */
  /* ...and the ones waiting in boxes of their own too (1.0.94): a pasted
     certificate vanished from its box while the bar still counted it. */
  if (name === 'settings') loadSettings(!Object.keys(DIRTY || {}).length && !Object.keys(PENDING || {}).length);
}

/* ---- the header and the live updates -------------------------------------- */
function paintHeader(s) {
  STATUS = s;
  /* The node that answered this page, on every tab (1.0.100) - it was
     written only while the overview was drawn. */
  var hs = document.querySelector('header .host');
  if (hs && s.node) {
    if (hs._base === undefined) hs._base = hs.textContent;
    hs.textContent = hs._base + ' · ' + s.node;
    hs.title = 'this page is answered by ' + s.node + ' · acme ' + (s.version || '');
  }
  mailqBadge(s.mailq);
  var pill = $('state-pill');
  var probs = (s.problems || []).length;
  var inMaint = !!(s.maintenance && s.maintenance.on);
  var kind = probs || inMaint ? 'warn' : 'ok';
  pill.className = 'pill ' + kind;
  pill.lastChild.textContent = inMaint ? 'in maintenance' : (probs ? 'running, with trouble' : 'running');
  pill.title = inMaint ? 'This node is in maintenance: it renews and puts in place nothing until it is back in service.'
    : (probs ? num(probs) + ' problem(s), listed under the header.' : 'The daemon answers and has nothing to complain about.');
  explainWhatWasDrawn(pill.parentNode);
  var pr = $('problems');
  clear(pr);
  (s.problems || []).forEach(function (p, i) {
    if (i) pr.appendChild(el('br'));
    pr.appendChild(document.createTextNode(p));
  });
  pr.hidden = !(s.problems && s.problems.length);
  drawTrials(s);
  $('updated-at').textContent = clockWords(new Date());
}

/* A change on trial (1.0.137): a node's new network, or the firewall - kept
   with a press, or it goes back by itself when its time runs out. On every
   page, with the time left counting down. */
var TRIALS = {list: [], skew: 0, timer: null};
function drawTrials(s) {
  TRIALS.list = (s && s.trials) || [];
  TRIALS.skew = s && s.now ? s.now - Date.now() / 1000 : 0;
  var host = $('trials');
  if (!host) return;
  if (!TRIALS.list.length) { host.hidden = true; clear(host); if (TRIALS.timer) { clearInterval(TRIALS.timer); TRIALS.timer = null; } return; }
  host.hidden = false;
  liveFill(host, function (host) {
    TRIALS.list.forEach(function (t) {
      var row = el('div', 'trial');
      var words = el('div', 'trial-words');
      words.appendChild(el('b', '', t.kind === 'net' ? 'The new network of ' + t.node + ' waits to be kept' : 'The change of the firewall and access waits to be kept'));
      var left = el('span', 'trial-left mono');
      left.dataset.until = t.until;
      words.appendChild(document.createTextNode(' - '));
      words.appendChild(left);
      words.appendChild(el('div', 'small', t.kind === 'net'
        ? 'Not kept, ' + t.node + ' goes back to its old network by itself and restarts. Keep it once you have checked that the node answers at its new address.'
        : 'Not kept, the rules and the access lists as they were before come back by itself. Keep it once you have checked that SSH and the pages still answer.'));
      row.appendChild(words);
      var tools = el('div', 'trial-tools');
      if (ADMIN) {
        var keep = cmdButton('Keep it', 'check', 'small primary');
        keep.onclick = function () { trialDo(t, 'keep', keep); };
        var back = cmdButton('Put the old back now', 'undo', 'small danger');
        back.onclick = function () {
          confirmThen('Put the old back now?', t.kind === 'net' ? htmlText(t.node) + ' goes back to its old network and restarts.'
            : 'The firewall and the access lists go back to what they were before the change.', 'Put it back', function () { trialDo(t, 'back', back); });
        };
        tools.appendChild(keep);
        tools.appendChild(back);
      }
      row.appendChild(tools);
      host.appendChild(row);
    });
  }, true);
  trialCount();
  if (!TRIALS.timer) TRIALS.timer = setInterval(trialCount, 1000);
}
function trialCount() {
  var now = Date.now() / 1000 + TRIALS.skew;
  document.querySelectorAll('#trials .trial-left').forEach(function (x) {
    var left = parseFloat(x.dataset.until) - now;
    x.textContent = left > 0 ? Math.floor(left / 60) + ':' + ('0' + Math.floor(left % 60)).slice(-2) + ' left' : 'going back now';
  });
}
function trialDo(t, action, button) {
  busy(button, true);
  api('trial', {kind: t.kind, node: t.node, action: action}).then(function (d) {
    toast(d.message, 'good');
    setTimeout(function () { api('status').then(paintHeader).catch(function () {}); }, 1500);
  }).catch(oops).then(function () { busy(button, false); });
}

var REDRAW_OWED = false;
function tick() {
  if (!LIVE || document.hidden) return;
  api('status').then(function (s) {
    $('offline').hidden = true;
    var moved = s.serial !== SERIAL || REDRAW_OWED;
    SERIAL = s.serial;
    paintHeader(s);
    /* Not drawn again under somebody reading it (1.0.57): a selection, the
       pointer over a help panel, a box being typed in, or a page further
       back, where every new request moved the rows under the reader. */
    var here = $('tab-' + TAB);
    var free = here && !document.querySelector('.modal:not([hidden])')
        && !userHolds(here) && !pointerBusy(here);
    if (moved && TAB === 'events' && free && !(PAGE.events > 0)) {
      REDRAW_OWED = false;
      onTab(TAB);
    } else if (moved && TAB === 'events') {
      /* Held back under the reader (1.0.94): owed, not forgotten - the
         serial taken meant the next tick saw nothing new. */
      REDRAW_OWED = true;
    }
    if (TAB === 'overview') paintCards();
    /* The tabs plugged in that asked to be live (ACME_EXTRA_TABS), and the
       Overview's own part of them: drawn again under the same rule. */
    if ((TAB === 'overview' || TABS.indexOf(TAB) < 0) && free) {
      extraDraw(TAB, {live: true, moved: moved, status: s});
    }
  }).catch(function (e) {
    var o = $('offline');
    o.hidden = false;
    o.textContent = 'The daemon is not answering: ' + (e.message || e);
  });
}
$('updated').onclick = function () {
  LIVE = !LIVE;
  $('updated').classList.toggle('paused', !LIVE);
  $('updated').querySelector('b').textContent = LIVE ? 'live' : 'paused';
  if (LIVE) tick();
};
$('signout').onclick = function () {
  api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); });
};

/* ---- the account signed in --------------------------------------------- */
function showMe() {
  modal('Your account', function (body) {
    /* Who, as isemon draws it: the initials, the name, the role and where
       the account comes from (1.0.19). */
    var head = el('div', 'me-head');
    var ava = noI18n(el('div', 'me-ava' + (ME.role === 'fulladmin' ? ' admin' : ''), meInitials(ME.name, ME.display)));
    ava.setAttribute('aria-hidden', 'true');
    head.appendChild(ava);
    var who = el('div', 'me-who');
    who.appendChild(noI18n(el('div', 'me-n mono', ME.name)));
    if (ME.display && ME.display !== ME.name) who.appendChild(noI18n(el('div', 'me-d', ME.display)));
    var tags = el('div', 'me-tags');
    tags.appendChild(el('span', 'tag ' + roleTone(ME.role), roleWords(ME.role)));
    tags.appendChild(el('span', 'tag info', ME.source === 'directory' ? 'from the directory' : 'local account'));
    who.appendChild(tags);
    head.appendChild(who);
    body.appendChild(head);
    var may = el('div', 'me-sec');
    may.appendChild(el('h3', '', 'What you may do'));
    may.appendChild(el('p', '', ME.role === 'fulladmin' ? 'Anything: certificates and their keys, the authorities, the targets, settings, accounts, the database.'
      : (ME.role === 'certadmin' ? 'Look at every page and look after the certificates: add, import, renew, put in place, export (never a private key). No setting and no account.'
         : 'Look at every page. Nothing can be changed from this account; how your own tables are laid out is yours to change.')));
    body.appendChild(may);
    if (ME.source === 'directory' && CERTADMIN) {     /* whois is a cert administrator's (1.0.146) */
      var dsec = el('div', 'me-sec');
      dsec.appendChild(el('h3', '', 'In the directory'));
      var dbody = el('div', 'muted', 'asking the directory…');
      dsec.appendChild(dbody);
      body.appendChild(dsec);
      api('directories', {action: 'whois', user: ME.name, kind: 'account'}).then(function (d) {
        clear(dbody);
        dbody.className = '';
        if (!d.entry) { dbody.appendChild(el('p', 'note', d.directory + ' has nobody by that name.')); return; }
        var kv = el('div', 'me-kv');
        var row = function (k, v) {
          if (!v) return;
          kv.appendChild(el('div', 'k', k));
          var c = el('div', 'v');
          if (v.nodeType) c.appendChild(v); else c.appendChild(noI18n(el('span', 'mono', v)));
          kv.appendChild(c);
        };
        row('User principal name', d.entry.upn);
        row('Mail', d.entry.mail);
        if (d.entry.dn) row('Where', placeSteps(d.entry.dn, ME.name));
        var gl = d.group_list || [];
        row('Groups (' + num(gl.length) + ')', personGroups(gl));
        dbody.appendChild(kv);
      }).catch(function (e) { dbody.textContent = String(e.message || e); });
    }
    var lsec = el('div', 'me-sec');
    lsec.appendChild(el('h3', '', 'Language'));
    body.appendChild(lsec);
    var lang = selectBox((window.ACME_LANGS || []).map(function (l) { return [l.code, l.name]; }),
                         window.ACME_LANG);
    noI18n(lang);
    lang.onchange = function () {
      api('prefs', {lang: lang.value}).then(function () { location.reload(); }).catch(oops);
    };
    lsec.appendChild(formField('The language of these pages', lang));

    /* The columns of the tables - exactly isemon's. */
    var cols = el('div', 'me-sec');
    cols.appendChild(el('h3', '', 'Columns of the tables'));
    var line = el('div', 'me-row');
    var say = el('div', 'me-say');
    say.innerHTML = '<b>Edit the columns</b><br>While this is on, the edge of any column’s '
      + 'heading can be dragged to size it and the heading itself to move it, and the right '
      + 'button on a heading hides a column, brings a hidden one back or adds an empty one '
      + 'for room; each change is kept the moment you let go. It is for this sign-in only: signing out, the sign-in '
      + 'running out or the service restarting turn it off again. Off, the tables are drawn '
      + 'as you left them and nothing can move them.';
    line.appendChild(say);
    var sw = el('label', 'sw');
    var box = el('input');
    box.type = 'checkbox';
    box.id = 'me-cols-edit';
    box.checked = COLS_EDIT;
    box.setAttribute('aria-label', 'Edit the columns');
    sw.appendChild(box);
    sw.appendChild(el('span', 'knob'));
    line.appendChild(sw);
    cols.appendChild(line);
    box.onchange = function () {
      var on = box.checked;
      box.disabled = true;
      colsSwitch(on).then(function (d) {
        box.checked = !!d.edit;
      }).catch(function (e) {
        box.checked = COLS_EDIT;
        oops(e);
      }).then(function () { box.disabled = false; });
    };
    var laid = Object.keys(COLS).length;
    cols.appendChild(el('p', '', laid ? 'You have laid out ' + num(laid) + ' table(s).'
      : 'Every table is as it comes.')).style.marginTop = '10px';
    var acts = el('div', 'me-acts');
    var back = cmdButton('Put my columns back as they come', 'undo', 'small');
    back.id = 'me-cols-reset';
    explain(back, 'Every table you have laid out goes back as it comes: the widths and the '
      + 'order of the columns, on every page. Nobody else’s change.');
    back.disabled = !laid;
    back.onclick = function () {
      back.disabled = true;
      colsReset().then(function () { showMe(); }).catch(function (e) {
        back.disabled = false;
        oops(e);
      });
    };
    acts.appendChild(back);
    cols.appendChild(acts);
    body.appendChild(cols);

    /* Your own settings, to a file and back. */
    var mine = el('div', 'me-sec');
    mine.appendChild(el('h3', '', 'Your settings in a file'));
    mine.appendChild(el('p', '', 'How you have set these pages up for yourself — the '
      + 'columns of the tables and the language — saved as a JSON file, and read back here '
      + 'or on another machine running acme. Never your password, your role or anything else '
      + 'about the account.'));
    var io = el('div', 'me-acts');
    var out = cmdButton('Export my settings', 'download', 'small');
    out.id = 'me-export';
    out.onclick = function () { meExport(out); };
    io.appendChild(out);
    var inn = cmdButton('Import settings…', 'upload', 'small');
    inn.id = 'me-import';
    inn.onclick = function () { mePick(); };
    io.appendChild(inn);
    mine.appendChild(io);
    body.appendChild(mine);

    if (ME.source !== 'directory') {
      var pwsec = el('div', 'me-sec');
      pwsec.appendChild(el('h3', '', 'A new password'));
      var old = maskBox('', '', '');
      var nw = maskBox('', '', '');
      var g = el('div', 'formgrid');
      g.appendChild(formField('The one you have now', old));
      g.appendChild(formField('The new one (8 characters at least)', nw));
      pwsec.appendChild(g);
      var go = cmdButton('Change the password', 'lock', 'primary');
      go.style.marginTop = '10px';
      go.onclick = function () {
        api('password', {old: old.value, 'new': nw.value}).then(function (d) {
          toast(d.message, 'good'); closeModal();
        }).catch(oops);
      };
      pwsec.appendChild(go);
      body.appendChild(pwsec);
    }
  }, null, 'medium');
}
$('me-btn').onclick = showMe;

/** "Edit the columns" on or off for this sign-in: the daemon holds it. */
function colsSwitch(on) {
  return api('columns', {edit: !!on}).then(function (d) {
    colsEditing(!!d.edit);
    colsCardSay();
    toast(d.edit ? 'Columns can be sized and moved now — each change is kept at once'
      : 'Columns are held as they are', 'good');
    return d;
  });
}

/** The file a person's own settings go into: one object with a mark of
    what it is, where and when it came from, and `settings` by section -
    `columns` and `prefs`; a version that does not know a section leaves it
    alone. As isemon's, with its own kind. */
var ME_FILE_KIND = 'acme-user-settings';

function meExport(button) {
  if (button) button.disabled = true;
  api('my-settings').then(function (d) {
    var file = {
      kind: ME_FILE_KIND,
      format: 1,
      from: location.host,
      version: d.version || '',
      user: d.name || (ME && ME.name) || '',
      exported: new Date().toISOString(),
      settings: d.settings || {}
    };
    var blob = new Blob([JSON.stringify(file, null, 2) + '\n'], {type: 'application/json'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'acme-settings-' + String(file.user || 'me').replace(/[^a-z0-9._-]/gi, '_')
      + '-' + file.exported.slice(0, 10) + '.json';
    document.body.appendChild(link);
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1500);
    var n = Object.keys((file.settings || {}).columns || {}).length;
    toast('your settings were saved to ' + link.download + ' (' + num(n)
      + ' table layout(s))', 'good');
  }).catch(oops).then(function () { if (button) button.disabled = false; });
}

function mePick() {
  var pick = el('input');
  pick.type = 'file';
  pick.accept = '.json,application/json';
  pick.hidden = true;
  pick.onchange = function () {
    var file = pick.files && pick.files[0];
    pick.remove();
    if (file) meImport(file);
  };
  document.body.appendChild(pick);
  pick.click();
}

function meImport(file) {
  if (file.size > 2 * 1024 * 1024) {
    toast('that file is far bigger than any settings file (' + bytes(file.size) + ')', 'bad');
    return;
  }
  var reader = new FileReader();
  reader.onerror = function () { toast('that file could not be read', 'bad'); };
  reader.onload = function () {
    var got;
    try { got = JSON.parse(String(reader.result || '')); } catch (e) {
      toast('that is not a settings file: it is not JSON', 'bad');
      return;
    }
    /* Our own file, or just its `settings` on their own. isemon's file is
       read as well: the columns are kept the same way in both. */
    var settings = got && (got.kind === ME_FILE_KIND || got.kind === 'opt-user-settings' || got.kind === 'isemon-user-settings')
      ? got.settings
      : (got && got.settings && typeof got.settings === 'object' ? got.settings : got);
    if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
      toast('that is not a settings file', 'bad');
      return;
    }
    var cols = settings.columns && typeof settings.columns === 'object'
      ? Object.keys(settings.columns).length : null;
    var other = Object.keys(settings).filter(function (k) {
      return k !== 'columns' && k !== 'prefs';
    });
    var at = got.exported ? Date.parse(String(got.exported)) : NaN;
    modal('Import settings', function (body) {
      body.appendChild(peekFacts([
        ['Whose', got.user ? noI18n(el('span', 'mono', String(got.user))) : '–'],
        ['From', got.from ? noI18n(el('span', 'mono', String(got.from))) : '–'],
        ['Saved', isFinite(at) ? stamp(at / 1000) : '–'],
        ['acme version', got.version ? noI18n(el('span', 'mono', String(got.version))) : '–']]));
      body.appendChild(el('p', 'note', 'This file holds:'));
      var list = el('ul', 'me-list');
      if (cols !== null) list.appendChild(el('li', '', 'the columns of ' + num(cols) + ' table(s)'));
      if (settings.prefs && typeof settings.prefs === 'object' && settings.prefs.lang) {
        list.appendChild(el('li', '', 'the language of the page'));
      }
      if (other.length) {
        list.appendChild(el('li', '', other.join(', ') + ' — not kept by this version, left alone'));
      }
      body.appendChild(list);
      body.appendChild(el('p', 'note', 'They replace yours. Your password and your account are not touched.'));
    }, [{words: 'No, leave it', close: true},
        {words: 'Import them', cls: 'primary', close: true, go: function () {
        api('my-settings', {settings: settings}).then(function (d) {
          if (settings.columns && typeof settings.columns === 'object') {
            /* What the daemon kept, not what the file said: it is the same
               less whatever a layout cannot hold. */
            return api('my-settings').then(function (now) {
              colsTake((now.settings || {}).columns || {});
              colsApplyAll();
              return d;
            });
          }
          return d;
        }).then(function (d) {
          toast('imported: the columns of ' + num((d.took || {}).columns || 0) + ' table(s)'
            + ((d.ignored || []).length ? '; left alone: ' + d.ignored.join(', ') : ''), 'good');
          var lang = settings.prefs && typeof settings.prefs === 'object'
            ? String(settings.prefs.lang || '') : '';
          if (lang && lang !== (window.ACME_LANG || 'en')
              && (window.ACME_LANGS || []).some(function (l) { return l.code === lang; })) {
            location.reload();
            return;
          }
          colsCardSay();
        }).catch(oops);
      }}], true);
  };
  reader.readAsText(file);
}

/** The card on the Accounts pane: how many tables are laid out, and the
    switch's words. */
function colsCardSay() {
  var laid = Object.keys(COLS).length;
  if ($('cols-count')) {
    $('cols-count').textContent = laid ? num(laid) + ' table(s) laid out by you'
      : 'every table as it comes';
  }
  var b = $('cols-edit-go');
  if (b) {
    setButtonIcon(b, COLS_EDIT ? 'check' : 'edit',
                  COLS_EDIT ? 'Stop editing the columns' : 'Edit the columns');
    b.classList.toggle('primary', COLS_EDIT);
  }
  if ($('cols-reset')) $('cols-reset').disabled = !laid;
}
$('cols-edit-go').onclick = function () { colsSwitch(!COLS_EDIT).catch(oops); };
$('cols-reset').onclick = function () {
  confirmThen('Put my columns back',
    'Every table you have laid out goes back as it comes: the widths and the order of the '
    + 'columns, on every page. Nobody else’s tables change.',
    'Put them back', function () { colsReset().then(function () { colsCardSay(); loadUsers(); }).catch(oops); });
};
$('cols-export').onclick = function () { meExport($('cols-export')); };
$('cols-import').onclick = function () { mePick(); };

/* ==========================================================================
   Overview
   ========================================================================== */
function paintCards() {
  var s = STATUS;
  if (!s) return;
  var i = s.isemon || {};
  var sent = Object.keys(i.sent || {}).reduce(function (a, k) { return a + i.sent[k]; }, 0);
  $('m-isemon').textContent = i.on ? (Object.keys(i.trouble || {}).length ? '!' : num(sent)) : 'off';
  $('m-isemon-sub').textContent = i.on ? ('as ' + i.host + ' to ' + ((i.targets || []).join(', ') || 'nowhere')
    + (i.last_sent ? ' · last ' + ago(i.last_sent) : '')) : 'not sent; Settings → isemon';
  $('card-isemon').className = 'card metric ' + (!i.on ? 'info' : (Object.keys(i.trouble || {}).length ? 'crit' : 'ok'))
    + ($('card-isemon').classList.contains('tappable') ? ' tappable' : '');
  paintCards2(s);
}

/* The second row (1.0.37): this server, the cluster, the database, maintenance. */
function upTime(sec) {
  sec = Math.max(0, Math.floor(sec || 0));
  var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return d ? d + ' d ' + h + ' h' : (h ? h + ' h ' + m + ' min' : m + ' min');
}
function paintCards2(s) {
  if (!$('card-server')) return;
  var probs = (s.problems || []).length;
  var maint = !!(s.maintenance && s.maintenance.on);
  $('m-server').textContent = maint ? 'maintenance' : (probs ? num(probs) + ' !' : 'OK');
  $('m-server-sub').textContent = s.node + ' · ' + s.version + ' · up ' + upTime(s.uptime);
  $('card-server').className = 'card metric ' + (maint || probs ? 'warn' : 'ok') + ($('card-server').classList.contains('tappable') ? ' tappable' : '');
  var nodes = s.nodes || [];
  var alive = nodes.filter(function (n) { return n.alive; }).length;
  var rep = s.replication || {};
  var cl = $('card-cluster');
  var tap = cl.classList.contains('tappable') ? ' tappable' : '';
  if (nodes.length <= 1 && !rep.mode) {
    $('m-cluster').textContent = 'one server';
    $('m-cluster-sub').textContent = 'no second node; Settings → High availability';
    cl.className = 'card metric info' + tap;
  } else {
    $('m-cluster').textContent = num(alive) + ' / ' + num(nodes.length);
    var bits = [alive === nodes.length ? 'every node answers' : num(nodes.length - alive) + ' gone'];
    if (rep.mode === 'replicated') bits.push(rep.healthy ? 'replication runs both ways' : (rep.lost ? 'replication lost' : 'replication stopped'));
    else if (rep.mode) bits.push('one shared database');
    var vers = {};
    nodes.forEach(function (n) { if (n.version) vers[n.version] = 1; });
    if (Object.keys(vers).length > 1) bits.push('versions differ');
    $('m-cluster-sub').textContent = bits.join(' · ');
    var bad = alive < nodes.length || (rep.mode === 'replicated' && !rep.healthy);
    cl.className = 'card metric ' + (bad ? 'crit' : (Object.keys(vers).length > 1 ? 'warn' : 'ok')) + tap;
  }
  var db = s.db || {};
  $('m-db').textContent = ({sqlite: 'SQLite', mariadb: 'MariaDB', postgres: 'PostgreSQL'})[db.engine] || db.engine || '–';
  $('m-db-sub').textContent = (db.size ? bytes(db.size) : '') + (db.last_backup ? ' · last copy ' + ago(db.last_backup) : ' · no copy yet')
    + (db.key_there === false ? ' · KEY MISSING' : '');
  $('card-db').className = 'card metric ' + (db.key_there === false ? 'crit' : (db.last_backup && Date.now() / 1000 - db.last_backup < 2 * 86400 ? 'ok' : 'warn'))
    + ($('card-db').classList.contains('tappable') ? ' tappable' : '');
  var mn = s.maint_nodes || [];
  var up = s.upgrade || {};
  var running = up.plan && up.plan.state === 'running';
  $('m-maint').textContent = running ? 'upgrading' : (mn.length ? num(mn.length) + ' out of service' : 'in service');
  $('m-maint-sub').textContent = running ? 'to ' + up.plan.version
    : (mn.length ? mn.join(', ') + ' in maintenance'
    : (up.package && verAbove(up.package, s.version) ? 'acme ' + up.package + ' is ready to be put in' : 'every node is in service'));
  $('card-maint').className = 'card metric ' + (running ? 'info' : (mn.length ? 'warn' : 'ok'))
    + ($('card-maint').classList.contains('tappable') ? ' tappable' : '');
}

/* The cards open what they count (1.0.37, as isemon's). */
function cardOpens(id, words, go) {
  var card = $(id);
  if (!card) return;
  card.classList.add('tappable');
  card.setAttribute('role', 'button');
  card.setAttribute('tabindex', '0');
  if (!card.querySelector('.goes')) {
    var arrow = el('span', 'goes');
    arrow.innerHTML = iconMarkup('next', 16);
    card.appendChild(arrow);
  }
  if (words) explain(card, words);
  card.onclick = function (e) {
    if (e && e.target && e.target.closest && e.target.closest('button,a,select,input')) return;
    go();
  };
  card.onkeydown = function (e) {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); }
  };
}
function peekIsemonCard() {
  var i = (STATUS || {}).isemon || {};
  peek('isemon', function () { return Promise.resolve(i); }, function (body) {
    var sent = Object.keys(i.sent || {});
    body.appendChild(peekFacts([['Sending', i.on ? 'on' : 'off'], ['As', i.host || '–'],
      ['Last line', i.last_sent ? ago(i.last_sent) : '–']]));
    if (!i.on) body.appendChild(el('p', 'note', 'Nothing is sent. Settings → isemon says where to.'));
    sent.forEach(function (k) { body.appendChild(el('p', 'small good', k + ': ' + num(i.sent[k]) + ' line(s) sent')); });
    Object.keys(i.trouble || {}).forEach(function (k) { body.appendChild(el('p', 'note bad', k + ': ' + i.trouble[k])); });
  }, {tab: 'settings', pane: 'isemon', words: 'Open Settings', icon: 'gear'});
}
function peekServerCard() {
  var s = STATUS || {};
  peek('This server: ' + s.node, function () { return Promise.resolve(s); }, function (body) {
    var m = s.maintenance || {};
    body.appendChild(peekFacts([['Version', s.version], ['Running for', upTime(s.uptime)],
      ['Started', stamp(s.started)], ['Host', s.host], ['State', m.on ? 'in maintenance' : 'in service']]));
    if (m.on) {
      var mp = el('p', 'note bad');
      mp.appendChild(el('b', '', 'In maintenance'));
      if (m.why) { mp.appendChild(document.createTextNode(' · ')); mp.appendChild(noI18n(el('span', '', m.why))); }
      if (m.by) { mp.appendChild(document.createTextNode(' · ')); mp.appendChild(noI18n(el('span', '', m.by))); }
      if (m.at) { mp.appendChild(document.createTextNode(' · ')); mp.appendChild(el('span', '', ago(m.at))); }
      body.appendChild(mp);
      body.appendChild(el('p', 'note', 'Nothing is renewed or put in place from here, and /healthz says 503.'));
    }
    body.appendChild(el('h4', '', 'Problems'));
    if (!(s.problems || []).length) body.appendChild(el('p', 'note good', 'None.'));
    (s.problems || []).forEach(function (p) { body.appendChild(el('p', 'note bad', p)); });
    var php = s.php || {};
    if (php.version) body.appendChild(el('p', 'note ' + (php.fixed === false ? 'bad' : ''), 'PHP ' + php.version + (php.fixed === false ? ' - may lack the php2shell fix' : '')));
  }, {tab: 'settings', pane: 'about', words: 'Open Settings', icon: 'gear'});
}
function peekClusterCard() {
  peek('High availability', function () { return api('ha'); }, function (body, d) {
    var rep = d.replication || {};
    var nodes = d.nodes || [];
    body.appendChild(peekFacts([['Nodes', num(nodes.length)], ['Answering', num(nodes.filter(function (n) { return n.alive; }).length)],
      ['Layout', rep.mode === 'replicated' ? 'each its own PostgreSQL' : (nodes.length > 1 ? 'one shared database' : 'one server')],
      ['This page from', d.node]]));
    body.appendChild(listTable(['Node', 'Version', 'Heard from', 'State'], nodes, function (n) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', n.name)));
      tr.appendChild(noI18n(el('td', 'mono', n.version || '?')));
      tr.appendChild(el('td', 'muted', ago(n.at)));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (n.alive ? (n.maintenance ? 'warn' : 'ok') : 'crit'), n.alive ? (n.maintenance ? 'in maintenance' : 'answering') : 'gone'));
      tr.appendChild(st);
      return tr;
    }, 'plain'));
    if (rep.mode === 'replicated') {
      body.appendChild(el('h4', '', 'The replication'));
      body.appendChild(el('p', 'note ' + (rep.healthy ? 'good' : 'bad'), rep.healthy ? 'Running both ways.' : (rep.lost ? 'Lost: rebuild the node that was away.' : 'Not running both ways.')));
      var rows = [];
      (rep.incoming || []).forEach(function (x) { rows.push(['coming in: ' + x.name, (x.enabled ? (x.running ? 'running' : 'not running') : 'paused') + (x.apply_errors ? ' · ' + x.apply_errors + ' error(s)' : '')]); });
      (rep.outgoing || []).forEach(function (x) { rows.push(['going out: ' + x.name, (x.active ? 'taken' : 'waiting') + ' · ' + bytes(x.behind || 0) + ' to go · ' + (x.wal_status || '')]); });
      body.appendChild(kvTable(rows));
      if (rep.trouble) body.appendChild(el('p', 'note bad', rep.trouble));
    } else if (nodes.length <= 1) {
      body.appendChild(el('p', 'note', 'One server. A second one answering beside it is set up in Settings → High availability.'));
    }
  }, {tab: 'settings', pane: 'ha', words: 'Open Settings', icon: 'gear'});
}
function peekDbCard() {
  peek('The database', function () { return api('db'); }, function (body, d) {
    body.appendChild(peekFacts([['Engine', d.words || d.engine], ['Where', d.where], ['Size', bytes(d.size || 0)],
      ['Version', d.version || '–'], ['The key', d.key_there ? 'there' : 'MISSING']]));
    /* What it holds (1.0.37): one row a table - what it is, its name, how
       many rows and how much room, with a bar for the room - biggest first,
       as on Settings → The database. */
    var tables = (d.tables || []).slice().sort(function (a, b) { return (b.bytes || 0) - (a.bytes || 0) || (b.rows || 0) - (a.rows || 0); });
    if (!tables.length) {
      var c = d.counts || {};
      tables = Object.keys(c).map(function (k) { return {table: k, rows: c[k], bytes: 0}; });
    }
    var most = Math.max.apply(null, tables.map(function (t) { return t.bytes || 0; }).concat([1]));
    body.appendChild(el('h3', 'peek-h', 'What it holds'));
    body.appendChild(listTable(['What', 'Table', {words: 'Rows', cls: 'num'}, {words: 'Room', cls: 'num'}, ''], tables, function (t) {
      var tr = el('tr');
      tr.appendChild(el('td', '', TABLE_SAID[t.table] || t.table));
      tr.appendChild(noI18n(el('td', 'mono small muted', t.table)));
      tr.appendChild(el('td', 'num', num(t.rows || 0)));
      tr.appendChild(el('td', 'num', t.bytes ? bytes(t.bytes) : '–'));
      var bc = el('td', 'barcell');
      var bar = el('div', 'bar good');
      var fill = el('span');
      fill.style.width = Math.max(2, Math.round(100 * (t.bytes || 0) / most)) + '%';
      bar.appendChild(fill);
      bc.appendChild(bar);
      tr.appendChild(bc);
      return tr;
    }, 'plain dbheld'));
    var b = d.backups || [];
    body.appendChild(el('h3', 'peek-h', 'Copies'));
    if (!b.length) {
      body.appendChild(el('p', 'note bad', 'No copy has been made yet.'));
    } else {
      body.appendChild(listTable(['Copy', {words: 'Size', cls: 'num'}, 'Made', 'Key beside it'], b.slice(0, 6), function (x) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono small', x.name)));
        tr.appendChild(el('td', 'num', bytes(x.size)));
        tr.appendChild(stampCell(x.at));
        var k = el('td');
        k.appendChild(el('span', 'tag ' + (x.key ? 'ok' : 'warn'), x.key ? 'yes' : 'no'));
        tr.appendChild(k);
        return tr;
      }, 'plain'));
      if (b.length > 6) body.appendChild(el('p', 'muted small', num(b.length - 6) + ' more in Settings → The database'));
    }
  }, {tab: 'settings', pane: 'db', words: 'Open Settings', icon: 'gear'});
}
function peekMaintCard() {
  peek('Maintenance and upgrades', function () { return ADMIN ? api('upgrade') : api('ha'); }, function (body, d) {
    var nodes = d.nodes || [];
    body.appendChild(listTable(['Node', 'Version', 'State', ''], nodes, function (n) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', n.name)));
      tr.appendChild(noI18n(el('td', 'mono', n.version || '?')));
      var m = n.maintenance && typeof n.maintenance === 'object' ? n.maintenance : {on: !!n.maintenance};
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (!n.alive ? 'crit' : (m.on ? 'warn' : 'ok')), !n.alive ? 'gone' : (m.on ? 'in maintenance' : 'in service')));
      if (m.on && m.why) st.appendChild(el('span', 'sub', m.why));
      tr.appendChild(st);
      var tools = el('td', 'rowtools');
      if (ADMIN && n.alive) {
        var b = cmdButton(m.on ? 'Back in service' : 'Maintenance', m.on ? 'play' : 'power', 'small');
        b.onclick = function () {
          UP.last = d;
          // Back in service asks nothing, so no window goes over this one
          // (1.0.61): the one left waiting stacked a second card on top.
          if (m.on) { maintenanceAsk(n, false, function () { peekMaintCard(); }); return; }
          modalOver(function () { maintenanceAsk(n, true, function () { peekMaintCard(); }); }, function () { peekMaintCard(); });
        };
        tools.appendChild(b);
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain'));
    var plan = d.plan;
    if (plan) {
      body.appendChild(el('h4', '', 'The last upgrade'));
      body.appendChild(el('p', 'note', 'To ' + plan.version + ' · ' + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state] + ' · ' + ago(plan.at)));
    }
    if (d.package) body.appendChild(el('p', 'note good', 'acme ' + d.package.version + ' is sent and checked.'));
  }, ADMIN ? {tab: 'settings', pane: 'upgrade', words: 'Open Upgrades', icon: 'up'} : null);
}
cardOpens('card-isemon', 'What is sent to isemon, and whether it arrives.', peekIsemonCard);
cardOpens('card-server', 'This server: its version, how long it has run, problems.', peekServerCard);
cardOpens('card-cluster', 'The nodes and the replication between them.', peekClusterCard);
cardOpens('card-db', 'The database: where, how big, what it holds, the copies.', peekDbCard);
cardOpens('card-maint', 'Which node is in service, and the upgrades.', peekMaintCard);

function loadOverview() {
  paintCards();
  explainWhatWasDrawn($('tab-overview'));
}

/** A section of a large popup: a card with a heading, a line saying what it
    is for, and whatever goes in it. */
function msect(title, lede, wide) {
  var box = el('section', 'msect' + (wide ? ' wide' : ''));
  box.appendChild(el('h4', '', title));
  if (lede) box.appendChild(el('p', 'msect-lede', lede));
  var body = el('div', 'msect-body');
  box.appendChild(body);
  box._body = body;
  return box;
}

/* ---- a person as the directory knows them (1.0.19, isemon's person card) ---- */
function meInitials(name, display) {
  var words = String(display || name || '?').replace(/[^\p{L}\p{N}\s._-]/gu, ' ')
    .split(/[\s._@-]+/).filter(Boolean);
  var two = words.length > 1 ? words[0][0] + words[words.length - 1][0] : String(words[0] || name || '?').slice(0, 2);
  return two.toUpperCase();
}
function dnParts(dn) {
  var out = [], cur = '', i, c;
  dn = String(dn || '');
  for (i = 0; i < dn.length; i++) {
    c = dn[i];
    if (c === '\\' && i + 1 < dn.length) { cur += dn[i + 1]; i++; continue; }
    if (c === ',') { out.push(cur); cur = ''; continue; }
    cur += c;
  }
  if (cur) out.push(cur);
  return out.map(function (one) {
    var at = one.indexOf('=');
    return at < 0 ? ['', one.trim()] : [one.slice(0, at).trim().toLowerCase(), one.slice(at + 1).trim()];
  });
}
function dnPlace(dn) {
  var parts = dnParts(dn), name = parts.length ? parts[0][1] : '', ous = [], dcs = [];
  parts.slice(1).forEach(function (p) { if (p[0] === 'dc') dcs.push(p[1]); else if (p[1]) ous.push(p[1]); });
  return {name: name, path: ous.reverse(), domain: dcs.join('.')};
}
/** Where somebody lives in the directory, as steps: the domain, each OU, them. */
function placeSteps(dn, own) {
  var place = dnPlace(dn);
  var steps = el('div', 'me-place');
  var step = function (words, cls) {
    if (steps.children.length) steps.appendChild(el('span', 'sep', '›'));
    steps.appendChild(noI18n(el('span', 'step' + (cls ? ' ' + cls : ''), words)));
  };
  if (place.domain) step(place.domain, 'dom');
  place.path.forEach(function (ou) { step(ou); });
  step(place.name || own, 'me');
  var wrap = el('div');
  wrap.appendChild(steps);
  wrap.appendChild(noI18n(el('div', 'me-dn mono', dn)));
  return wrap;
}
/** The groups: the ones that give something here as cards that say what,
    the rest as one wrapping line of names, past a few rows behind "and N more". */
function personGroups(list) {
  var cell = el('div');
  var key = list.filter(function (g) { return (g.gives || []).length; });
  var rest = list.filter(function (g) { return !(g.gives || []).length; });
  if (!list.length) { cell.appendChild(el('span', 'muted', 'in no group')); return cell; }
  if (key.length) {
    var cards = el('div', 'me-groups');
    key.forEach(function (g) {
      var role = (g.gives || []).filter(function (x) { return x.role; })[0];
      var card = el('div', 'me-group gives' + (role && role.role === 'readonly' ? ' ro' : ''));
      (g.gives || []).forEach(function (x) {
        if (x.role) card.appendChild(el('span', 'gwhy', 'makes an administrator: ' + roleWords(x.role)));
      });
      card.appendChild(noI18n(el('span', 'gn', g.name)));
      var where = dnPlace(g.dn);
      var bits = where.path.slice(); if (where.domain) bits.push(where.domain);
      if (bits.length) card.appendChild(noI18n(el('span', 'gp', bits.join(' › '))));
      card.title = g.dn || '';
      cards.appendChild(card);
    });
    cell.appendChild(cards);
  }
  if (rest.length) {
    var line = el('div', 'me-chips'), SHOW = 24;
    rest.forEach(function (g, i) {
      var chip = noI18n(el('span', 'me-chip', g.name));
      chip.title = g.dn || '';
      if (i >= SHOW) chip.hidden = true;
      line.appendChild(chip);
    });
    if (rest.length > SHOW) {
      var more = el('button', 'me-chip me-chip-more', 'and ' + num(rest.length - SHOW) + ' more');
      more.type = 'button';
      more.onclick = function () {
        Array.prototype.forEach.call(line.querySelectorAll('.me-chip[hidden]'), function (c) { c.hidden = false; });
        more.remove();
      };
      line.appendChild(more);
    }
    cell.appendChild(line);
  }
  return cell;
}
/** One person's card out of a whois answer: who, the state, where, what. */
function personCard(body, d, name) {
  var e = d.entry;
  var head = el('div', 'me-head');
  var ava = el('div', 'me-ava' + (d.role === 'fulladmin' ? ' admin' : ''), meInitials(e.sam || name, e.display));
  ava.setAttribute('aria-hidden', 'true');
  noI18n(ava);
  head.appendChild(ava);
  var who = el('div', 'me-who');
  who.appendChild(noI18n(el('div', 'me-n', e.display || e.sam || name)));
  who.appendChild(noI18n(el('div', 'me-d mono', e.upn || name)));
  var tags = el('div', 'me-tags');
  tags.appendChild(el('span', 'tag ' + (e.disabled ? 'crit' : 'ok'), e.disabled ? 'switched off in the directory' : 'active in the directory'));
  if (e.locked) tags.appendChild(el('span', 'tag crit', 'locked out'));
  if (e.expires) tags.appendChild(el('span', 'tag ' + (e.expires * 1000 < Date.now() ? 'crit' : 'warn'),
                                     (e.expires * 1000 < Date.now() ? 'expired ' : 'expires ') + stamp(e.expires)));
  if (d.role) tags.appendChild(el('span', 'tag ' + roleTone(d.role), roleWords(d.role)));
  who.appendChild(tags);
  head.appendChild(who);
  body.appendChild(head);
  var sec = el('div', 'me-sec');
  sec.appendChild(el('h3', '', 'In the directory'));
  var kv = el('div', 'me-kv');
  var row = function (k, v) {
    if (!v) return;
    kv.appendChild(el('div', 'k', k));
    var c = el('div', 'v');
    if (v.nodeType) c.appendChild(v); else c.appendChild(noI18n(el('span', 'mono', v)));
    kv.appendChild(c);
  };
  row('Account name', e.sam);
  row('User principal name', e.upn);
  row('Mail', e.mail);
  row('Department', e.department);
  row('Title', e.title);
  if (e.dn) row('Where', placeSteps(e.dn, e.sam || name));
  var asked = el('span', 'muted', d.directory + ' · ' + num(d.took_ms) + ' ms');
  noI18n(asked);
  row('Asked', asked);
  sec.appendChild(kv);
  body.appendChild(sec);
  var gs = el('div', 'me-sec');
  var list = (d.group_list || (d.groups || []).map(function (g) { return {name: g, dn: '', gives: []}; }));
  var h3 = el('h3', '', 'Groups, those inside groups as well');
  h3.appendChild(noI18n(el('span', 'me-count', ' (' + num(list.length) + ')')));
  gs.appendChild(h3);
  gs.appendChild(personGroups(list));
  body.appendChild(gs);
}

function whoisPeek(name, kind) {
  peek(name + ' in the directory', function () { return api('directories', {action: 'whois', user: name, kind: kind}); }, function (body, d) {
    if (!d.entry) { body.appendChild(el('p', 'note', d.directory + ' has nobody by that name.')); return; }
    personCard(body, d, name);
  });
  $('modal-box').className = 'box medium';
}

var MODAL_GO = null;

/* In a cluster, which node a line of a log was written on (1.0.45). */
function manyNodes() {
  return !!(STATUS && ((STATUS.nodes || []).length > 1 || (STATUS.replication || {}).mode));
}
function nodeCell(n) {
  var td = el('td', 'small');
  if (n) td.appendChild(noI18n(el('span', 'tag dim node-tag', n)));
  else td.appendChild(el('span', 'muted', '–'));
  return td;
}

function ensureOption(sel, value) {
  if (!Array.prototype.some.call(sel.options, function (o) { return o.value === value; })) {
    var o = el('option', '', value); o.value = value; sel.appendChild(o);
  }
}

function stepsList(steps) {
  var list = el('div', 'steps');
  (steps || []).forEach(function (s) {
    var row = el('div', 'step ' + (s.ok ? 'ok' : 'bad'));
    var mark = el('span', 'step-mark');
    mark.innerHTML = iconMarkup(s.ok ? 'check' : 'cancel', 15);
    row.appendChild(mark);
    var words = el('span', 'step-words');
    words.appendChild(el('b', '', s.what));
    if (s.said) words.appendChild(el('span', 'd', s.said));
    if (s.ms !== undefined) words.appendChild(el('span', 'd', s.ms + ' ms'));
    row.appendChild(words);
    list.appendChild(row);
  });
  return list;
}

/* ==========================================================================
   Events
   ========================================================================== */
function loadEvents() {
  var per = 100;
  apiLatest('events', 'events&q=' + encodeURIComponent($('ev-q').value) + '&kind=' + encodeURIComponent($('ev-kind').value)
      + tpQuery('ev-time') + '&limit=' + per + '&offset=' + PAGE.events * per).then(function (d) {
    QS.events.said(d.q_error || '');
    var sel = $('ev-kind');
    (d.kinds || []).forEach(function (k) { ensureOption(sel, k); });
    var host = $('ev-table');
    clear(host);
    var nd = manyNodes();
    host.appendChild(listTable(['When', 'Kind', 'Who', 'What'].concat(nd ? ['Node'] : []), d.rows, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.ts));
      var k = el('td'); k.appendChild(el('span', 'tag ' + (r.level === 'warn' || r.level === 'bad' ? 'warn' : 'dim'), r.kind));
      tr.appendChild(k);
      tr.appendChild(noI18n(el('td', '', r.who || '')));
      tr.appendChild(el('td', '', r.words));
      if (nd) tr.appendChild(nodeCell(r.node));
      return tr;
    }, '', {own: true}));
    pager('ev-pager', PAGE.events, per, d.total, function (p) { PAGE.events = p; loadEvents(); });
  }).catch(oops);
}
$('ev-q').addEventListener('input', debounce(function () { PAGE.events = 0; loadEvents(); }, 300));

$('ev-kind').onchange = function () { PAGE.events = 0; loadEvents(); };
if ($('ev-time')) $('ev-time').onchange = function () { PAGE.events = 0; loadEvents(); };
$('log-read').onclick = function () {
  api('log&lines=' + $('log-lines').value).then(function (d) {
    var out = $('log-out');
    out.hidden = false;
    out.textContent = d.lines.join('\n');
    out.scrollTop = out.scrollHeight;
  }).catch(oops);
};

/* ==========================================================================
   Settings: the rail, the panes, and the settings drawn from the daemon
   ========================================================================== */
var RAIL = {pinned: false, open: null, shut: null};
/** The pane shown when none is asked for: the first on the rail this account sees. */
function firstPane() {
  var b = Array.prototype.filter.call(document.querySelectorAll('#ctl-nav button[data-pane]'),
    function (x) { return !x.hidden && $('pane-' + x.dataset.pane); })[0];
  return b ? b.dataset.pane : 'about';
}
function showPane(name) {
  if (!name || !$('pane-' + name)) name = firstPane();
  PANE = name;
  document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
    b.classList.toggle('on', b.dataset.pane === name);
  });
  document.querySelectorAll('.ctl-pane').forEach(function (p) { p.hidden = p.id !== 'pane-' + name; });
  writeHash();
  if (name === 'people') { loadUsers(); loadDirs(); }
  if (name === 'db') { loadDb(); dbLinkNote(); }
  if (name === 'backup') loadRbackup();
  if (name === 'network') loadNet();
  if (name === 'power') loadPower();
  if (name === 'sshkeys') loadSshKeys(); else skPoll(false);
  if (name === 'alerts') loadAlerts();
  if (name === 'siem') loadSiem();
  if (name === 'acme') loadAcme(); else acPoll(false);
  if (name === 'hisec') loadHisec();
  if (name === 'proxy') drawProxy();
  if (name === 'monitor') { drawMonitor(); loadSnmp(); }
  if (name === 'logs') loadLogs();
  if (name === 'sshd') loadSshd(); else sdPoll(false);
  if (name === 'osup') loadOsup(); else ouPoll(false);
  if (name === 'time') loadNtp();
  if (name === 'ha') loadHa();
  if (name === 'mail') loadMail();
  if (name === 'mailq') loadMailq(); else mailqWatch(false);
  if (name === 'texts') loadTexts();
  if (name === 'isemon') loadIsemon();
  if (name === 'about') drawAbout();
  if (name === 'upgrade') loadUpgrade();
  if (name === 'web') loadWeb();
  if (name === 'fw') loadFw();
  if (name === 'portal') { $('portal-url').textContent = location.protocol + '//' + location.host + '/'; loadArt(); }
  /* A pane plugged in (ACME_EXTRA_PANES) draws itself. */
  var extra = (window.ACME_EXTRA_PANES || {})[name];
  if (typeof extra === 'function') { try { extra(name); } catch (e) { if (window.console) console.error(e); } }
  /* The save bar where there is a setting to save, and nowhere else - a page
     of clients or directories saves each one in its own window. */
  markDirtyCount();
}
document.querySelectorAll('#ctl-nav button[data-pane]').forEach(function (b) {
  b.onclick = function () { showPane(b.dataset.pane); };
});
function pinRail(on) {
  RAIL.pinned = !!on;
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  nav.classList.toggle('pinned', RAIL.pinned);
  document.querySelector('.ctl-layout').classList.toggle('nav-pinned', RAIL.pinned);
  pin.setAttribute('aria-pressed', RAIL.pinned ? 'true' : 'false');
  explain(pin, RAIL.pinned ? 'The menu is staying open. Press again to let it hide itself at the edge of the screen.'
    : 'The menu hides itself at the edge of the screen and slides out when you point at it. Press this to keep it open.');
  try { localStorage.setItem('acme-rail-pinned', RAIL.pinned ? '1' : '0'); } catch (e) { }
}
(function rail() {
  var nav = $('ctl-nav'), pin = $('ctl-pin');
  pin.innerHTML = iconMarkup('pin', 17);
  pin.onclick = function (e) { e.stopPropagation(); pinRail(!RAIL.pinned); };
  nav.addEventListener('mouseenter', function () {
    clearTimeout(RAIL.shut);
    RAIL.open = setTimeout(function () { nav.classList.add('open'); }, 60);
  });
  nav.addEventListener('mouseleave', function () {
    clearTimeout(RAIL.open);
    RAIL.shut = setTimeout(function () {
      if (document.activeElement && document.activeElement.id === 'ctl-find' && $('ctl-find').value) return;
      nav.classList.remove('open');
    }, 260);
  });
  var was = '0';
  try { was = localStorage.getItem('acme-rail-pinned') || '0'; } catch (e) { }
  pinRail(was === '1');
}());
$('ctl-find').addEventListener('input', function () {
  var want = $('ctl-find').value.trim().toLowerCase();
  var box = $('ctl-found');
  clear(box);
  if (!want || !SETTINGS) { box.hidden = true; return; }
  // In the page's language as well (1.0.61): a word seen on screen in Czech
  // found nothing.
  var tr = function (x) {
    try { return (typeof i18nText === 'function' && x) ? (i18nText(x) || '') : ''; } catch (e) { return ''; }
  };
  var hits = SETTINGS.settings.filter(function (s) {
    return (s.name + ' ' + s.key + ' ' + s.says + ' ' + tr(s.name) + ' ' + tr(s.says))
      .toLowerCase().indexOf(want) >= 0;
  }).slice(0, 12);
  if (!hits.length) box.appendChild(el('div', 'ctl-none', 'Nothing by that name'));
  hits.forEach(function (s) {
    var b = el('button', 'ctl-hit');
    b.type = 'button';
    b.appendChild(el('span', 'ctl-hit-t', s.name));
    var pane = Object.keys(SETTINGS.panes).filter(function (p) { return SETTINGS.panes[p].indexOf(s.key) >= 0; })[0];
    var where = document.querySelector('.ctl-nav [data-pane="' + (pane || 'about') + '"]');
    b.appendChild(el('span', 'ctl-hit-w', where ? where.textContent.trim() : (pane || '')));
    b.onclick = function () {
      showPane(pane || 'about');
      $('ctl-find').value = '';
      box.hidden = true;
      var item = document.querySelector('.set-item[data-key="' + s.key + '"]');
      if (item) {
        item.scrollIntoView({block: 'center'});
        item.classList.remove('found');
        void item.offsetWidth;
        item.classList.add('found');
        item.addEventListener('animationend', function () { item.classList.remove('found'); }, {once: true});
      }
    };
    box.appendChild(b);
  });
  box.hidden = !hits.length;
});

function loadSettings(redraw) {
  api('settings').then(function (d) {
    SETTINGS = d;
    /* Another node answers than the one that drew the boxes (1.0.110): the
       VIP address moved. Measured against that node, its own settings looked
       changed - acme1 took the name acme2 from a page acme2 had drawn. Drawn
       again from the node answering now; what was typed and not saved is put
       aside, said so. */
    if (DRAWN_NODE && d.node && d.node !== DRAWN_NODE) {
      var aside = Object.keys(DIRTY).length;
      toast('this page is answered by ' + d.node + ' now, not ' + DRAWN_NODE + ' (the VIP address moved): the settings are drawn again from ' + d.node
        + (aside ? '; ' + aside + ' change(s) not saved were put aside' : ''), 'warn');
      DIRTY = {};
      drawSettings(); markDirtyCount();
      var hh = (location.hash || '').split('/');
      showPane(PANE || hh[1] || '');
      return;
    }
    /* Typed while this was on its way (1.0.94): kept, not wiped by a redraw;
       the boxes are measured against what is saved now instead. */
    if (redraw !== false && !Object.keys(DIRTY).length) { drawSettings(); markDirtyCount(); }
    else {
      document.querySelectorAll('.set-item[data-key]').forEach(function (item) {
        var st = settingByKey(item.dataset.key);
        /* A secret just saved shows what is kept now (1.0.170): the box still
           held what was typed, never the dots of the saved one - it stayed
           "not saved" after every save. */
        if (st && st.secret && JUST_SAVED[st.key] && !(st.key in DIRTY) && $('set-' + st.key))
          $('set-' + st.key).value = st.value || '';
        if (st && $('set-' + st.key)) markDirty(item, st);
      });
    }
    JUST_SAVED = {};
    var h = (location.hash || '').split('/');
    showPane(PANE || h[1] || '');
  }).catch(oops);
}
var JUST_SAVED = {};
function settingByKey(key) {
  return ((SETTINGS && SETTINGS.settings) || []).filter(function (s) { return s.key === key; })[0];
}
function isBool(s) {
  return typeof s.default === 'boolean' || (s.min === 0 && s.max === 1 && typeof s.default === 'number');
}
var TALL = {portal_help: 1, portal_groups: 1, sms_body: 1, sms_headers: 1, isemon_targets: 1, admin_group_full: 1,
            admin_group_cert: 1, admin_group_token: 1, admin_group_readonly: 1};

/* A pane drawn in sections (1.0.88): what belongs together side by side,
   and what only one choice uses in a panel of its own that is there only
   while that choice is made - not a page of greyed-out boxes. */
var PANE_LAYOUT = {
  codes: [
    {title: 'The codes', icon: 'token', cols: 5, keys: ['code_digits', 'code_ttl_s', 'code_tries', 'code_send_max', 'code_send_window_min']},
    {title: 'What they say', icon: 'globe', keys: ['code_lang', 'code_mail_fmt'], wide: {code_lang: 2, code_mail_fmt: 2}},
    {title: 'SMS', icon: 'phone', keys: ['sms_mode', 'sms_prefix', 'sms_plain'], wide: {sms_mode: 2},
     master: 'sms_mode', subs: [
       {when: 'teltonika', title: 'The Teltonika gateway', icon: 'router',
        lede: 'TRB140, RUT… on the network: sent through its own API, the way zigmon sends its texts.',
        keys: ['sms_tel_host', 'sms_tel_api', 'sms_tel_modem', 'sms_tel_https', 'sms_tel_user', 'sms_tel_password', 'sms_tel_verify'],
        extra: smsTelExtra},
       {when: 'http', title: 'An HTTP gateway', icon: 'net',
        lede: 'An operator’s or a service’s HTTP API: where, how, with what key, and what it answers when a text went.',
        keys: ['sms_url', 'sms_method', 'sms_token', 'sms_ok_status', 'sms_body', 'sms_headers'], wide: {sms_url: 3, sms_token: 2, sms_ok_status: 2}},
       {when: 'spool', title: 'A modem on this machine', icon: 'terminal',
        lede: 'smstools3 or gammu-smsd: every text a file in their spool folder, sent by their own daemon.',
        keys: ['sms_spool_dir'], wide: {sms_spool_dir: 2}},
       {when: 'off', note: 'SMS is off: no code and no alert goes out as an SMS.'}]}
  ]
};
function layoutGrid(keys, wide, shown, cols) {
  var g = el('div', 'set-grid cols-' + (cols || 4));
  keys.forEach(function (key) {
    var s = settingByKey(key);
    if (!s) return;
    shown[key] = true;
    var it = settingItem(s);
    if (wide && wide[key] && !it.classList.contains('tall')) it.classList.add('span-' + wide[key]);
    g.appendChild(it);
  });
  return g;
}
function drawLaidOut(host, pane, shown) {
  var head = function (tag, sec) {
    var h = el(tag, 'set-sec-head');
    if (sec.icon) { var i = el('span', 'set-sec-icon'); i.innerHTML = iconMarkup(sec.icon, 15); h.appendChild(i); }
    h.appendChild(el('span', '', sec.title));
    return h;
  };
  PANE_LAYOUT[pane].forEach(function (sec) {
    var box = el('section', 'set-sec');
    box.appendChild(head('h3', sec));
    box.appendChild(layoutGrid(sec.keys, sec.wide, shown, sec.cols));
    (sec.subs || []).forEach(function (sub) {
      var p = el('div', 'set-sub');
      p.dataset.master = sec.master;
      p.dataset.when = sub.when;
      if (sub.note) {
        p.classList.add('set-sub-note');
        p.appendChild(el('div', 'says', sub.note));
      } else {
        p.appendChild(head('h4', sub));
        if (sub.lede) p.appendChild(el('div', 'says set-sub-lede', sub.lede));
        p.appendChild(layoutGrid(sub.keys, sub.wide, shown));
        if (sub.extra) p.appendChild(sub.extra());
      }
      box.appendChild(p);
    });
    host.appendChild(box);
  });
  /* Anything of the pane the layout does not name still shows, at the end. */
  var left = SETTINGS.panes[pane].filter(function (k) { return !shown[k] && settingByKey(k); });
  if (left.length) {
    var box = el('section', 'set-sec');
    box.appendChild(layoutGrid(left, null, shown));
    host.appendChild(box);
  }
}
function applySubs() {
  var val = function (key) {
    var m = $('set-' + key);
    return m ? String(m._get ? m._get() : m.value) : '';
  };
  document.querySelectorAll('.set-sub[data-master]').forEach(function (p) {
    p.hidden = val(p.dataset.master) !== p.dataset.when;
  });
  /* The gateway's certificates: there while its certificate is checked. */
  var ca = $('smsca');
  if (ca) {
    var on = function (k) { var v = val(k); return v === 'true' || v === '1'; };
    ca.hidden = !(on('sms_tel_verify') && on('sms_tel_https'));
    /* Said plainly when nothing checks who answers (1.0.101): the gateway's
       password and every code sent go to whoever is in between. */
    var warn = $('smsca-warn');
    if (!warn && ca.parentNode) {
      warn = el('div', 'note warn sms-warn');
      warn.id = 'smsca-warn';
      ca.parentNode.insertBefore(warn, ca);
    }
    if (warn) {
      var mode = val('sms_mode');
      var https = on('sms_tel_https'), verify = on('sms_tel_verify');
      warn.hidden = mode !== 'teltonika' || (https && verify);
      warn.textContent = !https
        ? 'Without HTTPS the gateway’s password and every code sent cross the network as they are: anybody on the way reads them.'
        : 'The gateway’s certificate is not checked: anybody between this server and the gateway can stand in for it and read its password and every code sent. Switch the check on and read its certificate from it below.';
    }
  }
}

/* Try the gateway (1.0.113): reached, signed in, its modems and what each
   says about the network - nothing is sent. With what is saved: changes not
   saved yet are asked to be saved first. */
function smsTelExtra() {
  var f = document.createDocumentFragment();
  var box = el('div', 'set-ca tel-test');
  var head = el('div', 'set-ca-head');
  var hi = el('span', 'set-sec-icon'); hi.innerHTML = iconMarkup('pulse', 15);
  head.appendChild(hi);
  head.appendChild(el('b', '', 'Is it talking to us?'));
  var go = cmdButton('Test the connection', 'play', 'small admin-only');
  go.classList.add('right');
  head.appendChild(go);
  box.appendChild(head);
  box.appendChild(el('div', 'says set-sub-lede', 'Signs in to the gateway with what is saved above and asks how its modems are - operator, signal, SIM. Nothing is sent; a test SMS goes from Try an SMS, below.'));
  var out = el('div', 'tel-out');
  box.appendChild(out);
  go.onclick = function () {
    var unsaved = Object.keys(DIRTY).filter(function (k) { return /^sms_/.test(k); });
    if (unsaved.length) { toast('save the changes first - the test uses what is saved', 'warn'); return; }
    busy(go, true);
    clear(out);
    out.appendChild(el('p', 'note', 'Asking the gateway…'));
    api('mail', {action: 'tel_test'}).then(function (d) {
      busy(go, false);
      clear(out);
      var steps = el('div', 'tel-steps');
      (d.steps || []).forEach(function (st) {
        var r = el('div', 'tel-step ' + (st.ok ? 'good' : 'bad'));
        r.appendChild(el('span', 'tel-mark', st.ok ? '✓' : '✗'));
        r.appendChild(el('b', '', st.what));
        if (st.secs) r.appendChild(noI18n(el('span', 'muted small', ' ' + String(st.secs).replace('.', numLang() === 'cs' ? ',' : '.') + ' s')));
        if (st.said) {
          r.appendChild(document.createTextNode(' – '));
          r.appendChild(el('span', 'small' + (st.ok ? ' muted' : ' bad'), st.said));
        }
        steps.appendChild(r);
      });
      out.appendChild(steps);
      (d.modems || []).forEach(function (m) {
        var card = el('div', 'tel-modem' + (m.sends ? ' sends' : ''));
        var t = el('div', 'tel-modem-head');
        t.appendChild(noI18n(el('b', 'mono', m.id || '?')));
        if (m.sends) t.appendChild(el('span', 'tag ok', 'sends the codes'));
        card.appendChild(t);
        var dl = el('dl', 'tel-facts');
        (m.fields || []).forEach(function (kv) {
          if (kv[0] === 'id') return;
          var one = el('div', 'tel-fact');
          one.appendChild(el('dt', '', kv[0]));
          one.appendChild(noI18n(el('dd', 'mono', kv[1])));
          dl.appendChild(one);
        });
        card.appendChild(dl);
        out.appendChild(card);
      });
      out.appendChild(el('p', 'note small ' + (d.ok ? (d.checked ? 'good' : 'warn') : 'bad'), d.ok
        ? 'The gateway answers' + (d.checked ? ', its certificate checked' : (d.https ? ' - its certificate NOT checked' : ' - over plain HTTP')) + ' (' + num(d.took_ms) + ' ms).'
        : 'The gateway cannot send codes like this - see the step marked ✗.'));
      out.appendChild(hideBar(function () { clear(out); }));
    }).catch(function (e) { busy(go, false); clear(out); oops(e); });
  };
  f.appendChild(box);
  f.appendChild(smsCaBlock());
  return f;
}

/* The certificates the Teltonika gateway is checked against (1.0.89): its
   own, read from it with a click, or the authority and chain that signed
   it - pasted or read from a file, added with Save the changes. */
function smsCaBlock() {
  var box = el('div', 'set-ca');
  box.id = 'smsca';
  var head = el('div', 'set-ca-head');
  var hi = el('span', 'set-sec-icon'); hi.innerHTML = iconMarkup('shield', 15);
  head.appendChild(hi);
  head.appendChild(el('b', '', 'The certificates it is checked against'));
  var when = el('span', 'muted small right', '');
  head.appendChild(when);
  box.appendChild(head);
  box.appendChild(el('div', 'says set-sub-lede', 'The gateway’s own certificate (a TRB makes one itself), or the root and the chain of the authority that signed it. With some here only these are trusted, and a gateway written as an address is not checked for a name. With none, the authorities this machine trusts - and the name.'));
  var state = el('div', 'set-ca-list');
  box.appendChild(state);
  var pem = el('textarea', 'mono admin-only');
  pem.rows = 4;
  pem.placeholder = '-----BEGIN CERTIFICATE-----';
  box.appendChild(pem);
  var row = el('div', 'set-ca-tools admin-only');
  var fetch = cmdButton('Read it from the gateway', 'download', '');
  var file = cmdButton('Read a file…', 'upload', '');
  var drop = cmdButton('Take them all away', 'trash', 'danger');
  var input = el('input'); input.type = 'file'; input.accept = '.pem,.crt,.cer,.txt'; input.hidden = true;
  [fetch, file, drop, input].forEach(function (b) { row.appendChild(b); });
  var seen = el('div', 'set-ca-seen');
  box.appendChild(row);
  box.appendChild(seen);
  var draw = function () {
    api('mail').then(function (d) {
      var list = d.sms_ca_list || [];
      when.textContent = list.length ? num(list.length) + ' certificate(s) kept' : 'none imported';
      drop.hidden = !list.length;
      clear(state);
      if (list.length) state.appendChild(certTable(list, function (c) {
        confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate')
          + '</b> is no longer trusted for the SMS gateway. The others stay.', 'Take it out', function () {
            api('mail', {action: 'sms_ca', mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
              toast(r.message, 'good'); draw();
            }).catch(oops);
          });
      }));
      explainWhatWasDrawn(box);
    }).catch(oops);
  };
  pem.addEventListener('input', function () {
    clear(seen);
    if (!pem.value.trim()) { delete PENDING.smsca; markDirtyCount(); return; }
    pendingSet('smsca', {save: function () {
      return api('mail', {action: 'sms_ca', mode: 'add', ca: pem.value.trim()}).then(function (r) {
        toast(r.message, 'good'); pem.value = ''; clear(seen); draw(); return true;
      });
    }, reset: function () { pem.value = ''; clear(seen); }});
  });
  fetch.onclick = function () {
    if (Object.keys(DIRTY || {}).some(function (k) { return /^sms_tel_(host|https)$/.test(k); })) {
      toast('save the gateway’s address first', 'bad'); return;
    }
    busy(fetch, true);
    api('mail', {action: 'sms_ca_fetch'}).then(function (r) {
      pem.value = r.pem || '';
      pem.dispatchEvent(new Event('input'));
      if ((r.certs || []).length) {
        seen.appendChild(el('div', 'says', 'What the gateway shows - check the fingerprint against the one on the gateway (System → Administration → Certificates) before Save the changes trusts it:'));
        seen.appendChild(certTable(r.certs));
        var top = r.certs[r.certs.length - 1];
        if (top && !top.self_signed) seen.appendChild(el('div', 'says', 'The gateway does not send the certificate of whom signed it: its own is then trusted as it is - only exactly this certificate passes.'));
        explainWhatWasDrawn(seen);
      }
    }).catch(oops).then(function () { busy(fetch, false); });
  };
  file.onclick = function () { input.click(); };
  input.onchange = function () { var f = input.files && input.files[0]; if (f) readCertFile(f, pem); input.value = ''; };
  drop.onclick = function () {
    confirmThen('Take every certificate of the SMS gateway away',
      'The gateway’s certificate will then have to be signed by an authority this machine already trusts, or the check has to be switched off.',
      'Take them all away', function () {
        api('mail', {action: 'sms_ca', mode: 'clear'}).then(function (r) { toast(r.message, 'good'); draw(); }).catch(oops);
      }, true);
  };
  draw();
  return box;
}

function drawSettings() {
  DRAWN_NODE = SETTINGS.node || '';
  var shown = {};
  Object.keys(SETTINGS.panes).forEach(function (pane) {
    var host = $('sect-' + pane);
    if (!host) return;
    clear(host);
    if (PANE_LAYOUT[pane]) { drawLaidOut(host, pane, shown); return; }
    var grid = el('div', 'set-grid');
    SETTINGS.panes[pane].forEach(function (key) {
      var s = settingByKey(key);
      if (!s) return;
      shown[key] = true;
      grid.appendChild(settingItem(s));
    });
    host.appendChild(grid);
  });
  var rest = SETTINGS.settings.filter(function (s) { return !shown[s.key]; });
  var host = $('sect-rest');
  clear(host);
  $('rest-card').hidden = !rest.length;
  if (rest.length) {
    var g = el('div', 'set-grid');
    rest.forEach(function (s) { g.appendChild(settingItem(s)); });
    host.appendChild(g);
  }
  applyOnlyWhen();
  if (typeof AC !== 'undefined' && AC.d) acmeNamesInSettings(AC.d);
  explainWhatWasDrawn($('tab-settings'));
  if (typeof PANE !== 'undefined' && PANE === 'db') dbLinkNote();   /* drawn again (1.0.107) */
  if (typeof PANE !== 'undefined' && PANE === 'backup' && typeof rbPassTools === 'function') rbPassTools();
}

/* Name, control, then the words, each in its own row of the grid, so every
   box on a row starts at the same height even where one name takes two
   lines (1.0.20). */
/* What a setting does, in three lines at most (1.0.156): a click opens the
   rest in place; the whole is on the name and its (i) as well. */
function saysClamped(words) {
  var box = saysBlock(words);
  box.classList.add('clamp');
  box.addEventListener('click', function () { box.classList.toggle('open'); });
  /* Marked once drawn, so only a text that is cut looks like one. */
  setTimeout(function () { if (box.scrollHeight > box.clientHeight + 2) box.classList.add('cut'); }, 0);
  return box;
}
function settingItem(s) {
  var item = settingItemBare(s);
  var tail = el('div', 'set-tail');
  Array.prototype.slice.call(item.children, 2).forEach(function (c) { tail.appendChild(c); });
  /* Right under the box (1.0.171), before what it says - words of different
     lengths put them at different heights along a row. */
  var others = nodeOthers(s);
  if (others) tail.insertBefore(others, tail.firstChild);
  item.appendChild(tail);
  return item;
}
/* A node's own setting, in a cluster (1.0.170): the other nodes' values under
   the box, each changed from here - the box is this node's, and the others'
   were only in Settings → High availability (the name of acme2's certificate
   could not be given on the page of the ACME certificates). */
function nodeOthers(s) {
  if (!s.node_key || !SETTINGS || !SETTINGS.cluster || s.secret) return null;
  var names = (SETTINGS.nodes || []).filter(function (n) { return n !== SETTINGS.node; });
  if (!names.length) return null;
  var box = el('div', 'node-others small' + (isBool(s) ? ' bool' : ''));
  names.forEach(function (n) {
    var has = s.per_node && Object.prototype.hasOwnProperty.call(s.per_node, n);
    var val = has ? s.per_node[n] : s.shared;
    var row = el('div', 'node-other');
    row.dataset.node = n;
    var redraw = function () { loadSettings(); };
    if (isBool(s)) {
      /* The node's switch first, right under the box's own (1.0.177): after
         the node's tag it stood off to the side of the one above. */
      var sw = switchBox(nodeValWords(s, val) === 'on');
      sw._input.disabled = !ADMIN;
      if (!has) sw.classList.add('inherited');
      sw._input.addEventListener('change', function () { nodeSave(s, n, !!sw._get(), redraw); });
      row.appendChild(sw);
      row.appendChild(noI18n(el('span', 'tag dim', n)));
    } else {
      row.appendChild(noI18n(el('span', 'tag dim', n)));
      row.appendChild(nodeValEl(s, val, 'mono small' + (has ? '' : ' muted')));
    }
    row.appendChild(el('span', 'muted', has ? 'its own' : 'the cluster’s'));
    if (ADMIN && !isBool(s)) {
      var eb = iconButton('edit', 'Change it for ' + n);
      eb.onclick = function () { nodeEdit(s, n, has ? val : null, redraw); };
      row.appendChild(eb);
    }
    if (ADMIN && has) {
      var back = iconButton('undo', 'Back to the cluster’s value');
      back.onclick = function () { nodeSave(s, n, s.shared, redraw); };
      row.appendChild(back);
    }
    box.appendChild(row);
  });
  return box;
}
function settingItemBare(s) {
  var item = el('div', 'set-item' + (isBool(s) ? ' set-bool' : ''));
  item.dataset.key = s.key;
  var label = el('label', '', s.name || s.key);
  label.setAttribute('for', 'set-' + s.key);
  var info = el('span', 'iinfo', 'i');
  info.setAttribute('role', 'button');
  info.tabIndex = 0;
  var asText = function (v) { return richText(Array.isArray(v) ? v.join(', ') : String(v)); };
  var where = s.source;
  var story = '<span class="k">on the command line this one is <b>acme --set ' + richText(s.key)
    + '=…</b> · running: ' + (s.secret ? (s.set ? 'set' : 'not set') : asText(s.value))
    + '<br><span class="' + (where === 'default' ? 'same' : 'diff') + '">' + richText(s.source_says || '')
    + (s.saved_by ? ' (by ' + richText(s.saved_by) + (s.saved_at ? ', ' + ago(s.saved_at) : '') + ')' : '')
    + '</span>'
    + (s.file_only ? '<br><span class="same">kept in ' + richText(SETTINGS.config_file)
       + ' - a database cannot hold its own address</span>' : '')
    + (where !== 'default' && !s.secret && String(s.value) !== String(s.default)
       ? '<br><span class="same">the built-in default is ' + asText(s.default) + '</span>' : '') + '</span>';
  var whole = s.says || 'No words have been written for this one yet.';
  if (s.node_key && SETTINGS.cluster) {
    story += '<br><span class="diff">' + richText('this node’s own - every node of the cluster has one of its own; the others’ are under the box, and all of them in Settings → High availability') + '</span>';
  }
  explain(info, whole, story);
  explain(label, whole, story);
  label.appendChild(info);
  /* A node's own setting, in a cluster (1.0.37): said beside its name. */
  if (s.node_key && SETTINGS.cluster) {
    /* The tags one block at the right, never broken over two lines: only the
       name wraps (1.0.172) - "acme1" went under the name on one box and stood
       beside it on the next. */
    var tags = el('span', 'node-tags');
    var nt = el('span', 'tag info', 'this node');
    nt.title = SETTINGS.node;
    tags.appendChild(nt);
    tags.appendChild(noI18n(el('span', 'tag dim', SETTINGS.node)));
    label.appendChild(tags);
  }
  if (label.firstChild && label.firstChild.nodeType === 3) {
    var txt = el('span', 'lbl-txt');
    txt.appendChild(label.firstChild);
    label.insertBefore(txt, label.firstChild);
  }
  item.appendChild(label);
  var input;
  if (isBool(s)) {
    input = switchBox(s.value === true || String(s.value) === '1');
    input._input.disabled = !ADMIN;
    input._input.addEventListener('change', function () { markDirty(item, s); });
    input.id = 'set-' + s.key;
    /* The name is a label for the checkbox itself, so a click on it flips
       the switch (1.0.15); the wrapper keeps the id the readers look up. */
    input._input.id = 'set-' + s.key + '-sw';
    label.setAttribute('for', input._input.id);
    item.appendChild(input);
    if (s.says) item.appendChild(saysClamped(s.short || s.says));   /* the whole on the (i) (1.0.156) */
    hsDress(item, s, input);
    if (s.key === 'high_security') hsSwitch(input, s);
    return item;
  }
  if (s.choices && s.choices.some(function (c) {
    return String((s.choice_words && s.choice_words[c]) || c).length > 30;
  })) item.classList.add('wide');
  if (s.choices) {
    input = selectBox(s.choices.map(function (c) { return [c, (s.choice_words && s.choice_words[c]) || c]; }), s.value);
  } else if (s.key === 'admin_directory' || s.key === 'portal_directory') {
    var dl = (SETTINGS.directories || []).slice();
    if (s.value && dl.indexOf(s.value) < 0) dl.push(s.value);
    input = selectBox([['', s.key === 'admin_directory' ? 'none - only the accounts made here'
                                                        : 'the administrators’ one']].concat(dl.map(function (d) { return [d, d]; })), s.value);
  } else if (typeof s.min === 'number') {
    input = el('input');
    input.type = 'number';
    input.min = s.min;
    input.max = s.max;
    input.value = s.value;
  } else if (TALL[s.key]) {
    item.classList.add('tall');
    input = el('textarea');
    input.value = s.value === null || s.value === undefined ? '' : String(s.value);
    input.rows = s.key === 'portal_help' ? 6 : 2;
  } else {
    input = s.secret ? maskBox(s.value, '', '') : textBox(s.value, '', '');
    if (s.secret) {
      input.placeholder = s.set ? 'set - leave as it is to keep it' : 'not set';
      input.addEventListener('focus', function () { if (input.value.indexOf('•') === 0) input.select(); });
    }
  }
  input.id = 'set-' + s.key;
  input.disabled = !ADMIN;
  input.addEventListener('input', function () { markDirty(item, s); });
  input.addEventListener('change', function () { markDirty(item, s); });
  item.appendChild(input);
  if (s.key === 'portal_groups' && ADMIN) {
    /* The groups found in the directory and picked, rather than typed - the
       same list as for the administrators' groups. */
    var pickRow = el('div', 'btnrow');
    pickRow.style.marginTop = '8px';
    var pickGo = cmdButton('Find and pick the groups', 'search', 'small');
    pickGo.id = 'portal-groups-find';
    pickGo.onclick = function () { portalGroupsPick(input, item, s); };
    pickRow.appendChild(pickGo);
    item.appendChild(pickRow);
  }
  if (s.says) item.appendChild(saysClamped(s.short || s.says));   /* the whole on the (i) (1.0.156) */
  hsDress(item, s, input);
  return item;
}

/* ---- High security (1.0.168) --------------------------------------------------
   While it is on, what it stands against is greyed out: a switch that may not
   go back, the choices that may not be chosen, a number's highest; the daemon
   refuses them anyway. Switched on only once nothing stands against it - what
   does is listed in a window, each with where it is set. */
function hsOn(rule) { return !!(STATUS && STATUS.high_security) && !(rule && (STATUS.hisec_waived || []).indexOf(rule) >= 0); }
function hsOptions(sel, bad, rule) {
  if (!hsOn(rule)) return;
  Array.prototype.forEach.call(sel.options, function (o) {
    if (bad.indexOf(o.value) >= 0) { o.disabled = true; o.title = 'not under high security'; }
  });
}
function hsDress(item, s, input) {
  var r = s.hisec;
  if (!r || !hsOn()) return;
  if (isBool(s)) {
    var on = s.value === true || String(s.value) === '1';
    if ((r.forbid || []).indexOf(on ? 0 : 1) >= 0) input._input.disabled = true;
  } else if (input && input.tagName === 'SELECT') {
    Array.prototype.forEach.call(input.options, function (o) {
      if ((r.forbid || []).indexOf(o.value) >= 0) { o.disabled = true; o.title = 'not under high security'; }
    });
  } else if (input && typeof r.most === 'number') {
    input.max = r.most;
  }
  var n = el('div', 'says hs-note', 'High security: ' + r.why + ' - not allowed.');
  (item.querySelector('.set-tail') || item).appendChild(n);
}
function hsSwitch(box, s) {
  box._input.addEventListener('change', function () {
    if (!box._input.checked || (s.value === true || String(s.value) === '1')) return;
    api('hisec').then(function (d) {
      if ((d.block || []).length) {
        box._input.checked = false;
        box._input.dispatchEvent(new Event('change'));
      }
      hsWindow(d, !(d.block || []).length);
    }).catch(oops);
  });
}
function hsWindow(d, may) {
  modal(may ? 'High security' : 'High security cannot be switched on yet', function (body) {
    var draw = function (v) {
      clear(body);
      var block = v.block || [];
      var ok = !block.length;
      body.appendChild(el('p', 'note' + (ok ? '' : ' warn'), ok
        ? 'Nothing stands against it now. Switch it on again and save: from then on every way of doing something less safely is refused - but the exceptions.'
        : num(block.length) + ' thing(s) stand against it. Set them as said, or make one an exception with its switch - then switch it on again.'));
      hsList(body, block, 'bad', 'Stands against it', draw);
      hsList(body, v.waived || [], 'waived', 'Exceptions - not enforced', draw);
    };
    draw(d);
  }, [{words: 'Close', close: true}], 'large');
}
/* One rule a row: what, what to set, where - and on the right the switch that
   makes it an exception: it then stops nothing and is not enforced. */
function hsList(host, rows, cls, title, redraw) {
  if (!rows.length) return;
  host.appendChild(el('h4', 'hs-h ' + (cls === 'waived' ? 'dim' : cls), title));
  var ul = el('div', 'hs-list');
  rows.forEach(function (x) {
    var it = el('div', 'hs-item ' + cls);
    it.appendChild(el('span', 'dot ' + (cls === 'bad' ? 'bad' : (cls === 'ok' ? 'ok' : (cls === 'warn' ? 'warn' : 'dim')))));
    var t = el('div', 'hs-t');
    t.appendChild(el('div', 'hs-what', x.title || x.what));
    if (x.details && x.details.length) t.appendChild(noI18n(el('div', 'small muted mono', x.details.join(', '))));
    var f = el('div', 'muted small');
    if (x.kind !== 'check') { f.appendChild(el('span', '', 'Set:')); f.appendChild(document.createTextNode(' ')); }
    f.appendChild(el('span', '', x.fix));
    if (x.pane) {
      var a = el('a', '', 'Open it →');
      a.href = '#settings/' + x.pane;
      a.onclick = function () { if ($('modal-box') && $('modal-box').contains(a)) closeModal(); };
      f.appendChild(document.createTextNode(' · '));
      f.appendChild(a);
    }
    t.appendChild(f);
    it.appendChild(t);
    if (x.rule && x.kind !== 'check' && ADMIN) {
      var sw = el('label', 'hs-ex');
      var box = switchBox(!!x.waived);
      sw.appendChild(el('span', 'small muted', 'Exception'));
      sw.appendChild(box);
      explain(sw, 'On: this rule is an exception - it does not stop high security and is not enforced while it is on. Every change is an event.');
      box._input.onchange = function () {
        var want = !!box._get();
        box._input.disabled = true;
        api('hisec', {action: 'waive', rule: x.rule, on: want}).then(function (v) {
          toast(want ? 'an exception now' : 'enforced again', 'good');
          if (STATUS) STATUS.hisec_waived = (v.waived || []).map(function (r) { return r.rule; });
          redraw(v);
          if ($('hs-host') && redraw !== drawHisec) drawHisec(v);
        }).catch(function (e) { box._input.disabled = false; box._input.checked = !want; oops(e); });
      };
      it.appendChild(sw);
    }
    ul.appendChild(it);
  });
  host.appendChild(ul);
}

/** The groups that may sign in to the portal, found in the directory: each one's button
    puts it into the box or takes it out, and the box is saved with the
    other settings as before. */
function portalGroupsPick(input, item, s) {
  var dirs = SETTINGS.directories || [];
  if (!dirs.length) { toast('there is no directory to look in: Settings → Accounts, The directories', 'bad'); return; }
  var names = function () {
    return input.value.split(/[;\n]+/).map(function (x) { return x.trim(); }).filter(Boolean);
  };
  var put = function (list) {
    input.value = list.join('\n');
    markDirty(item, s);
  };
  var has = function (g) {
    var cn = String(g.cn).toLowerCase(), dn = String(g.dn).toLowerCase();
    return names().filter(function (v) { v = v.toLowerCase(); return v === cn || v === dn; });
  };
  modal('Groups that may sign in to the portal', function (body) {
    body.appendChild(el('p', 'note', 'Find the groups in the directory and press May sign in beside each one that may: it goes into the box, and pressed again it comes out. Nested groups count - a member of a group inside one of these may sign in as well. Nothing is kept until Save the changes.'));
    var dir = selectBox(dirs.map(function (d) { return [d, d]; }), dirs[0]);
    noI18n(dir);
    /* The directory the portal signs people in against, as set - or the
       administrators' one. */
    var want = String(readValue(settingByKey('portal_directory') || {key: 'portal_directory'}) || '')
      || String(readValue(settingByKey('admin_directory') || {key: 'admin_directory'}) || '');
    if (want && dirs.indexOf(want) >= 0) dir.value = want;
    if (dirs.length > 1) body.appendChild(formField('Look in the directory', dir));
    var chosen = el('div', 'chips');
    chosen.style.margin = '6px 0 12px';
    var drawChosen = function () {
      clear(chosen);
      var list = names();
      if (!list.length) { chosen.appendChild(el('span', 'muted small', 'No group yet: nobody may sign in.')); return; }
      list.forEach(function (n) {
        var c = el('span', 'chip');
        /* A DN shown by its name, the whole of it on hover (1.0.101). */
        var m = /^\s*cn=((?:\\.|[^,])+)/i.exec(n);
        var shown = noI18n(el('span', 'mono', m ? m[1].replace(/\\(.)/g, '$1') : n));
        shown.title = n;
        c.appendChild(shown);
        var x = iconButton('close', 'Take it out');
        x.onclick = function () {
          put(names().filter(function (v) { return v !== n; }));
          drawChosen();
          if (gb._paint) gb._paint();
        };
        c.appendChild(x);
        chosen.appendChild(c);
      });
    };
    body.appendChild(el('h3', 'peek-h', 'Chosen'));
    body.appendChild(chosen);
    drawChosen();
    var gb = groupBrowser({
      dir: function () { return dir._get ? dir._get() : dir.value; },
      buttons: [{words: 'May sign in', icon: 'check',
                 on: function (g) { return has(g).length > 0; },
                 toggle: function (g) {
                   var hit = has(g);
                   if (hit.length) put(names().filter(function (v) { return hit.indexOf(v) < 0; }));
                   /* Its whole DN (1.0.101): the one group picked, never any
                      group of that name somewhere else in the directory. */
                   else put(names().concat([g.dn]));
                   drawChosen();
                 }}]
    });
    body.appendChild(gb);
  }, [{words: 'Done', cls: 'primary', icon: 'check', close: true}], 'large');
}

function readValue(s) {
  var input = $('set-' + s.key);
  if (!input) return undefined;
  if (input._get) return input._get();
  if (typeof s.min === 'number' && !s.choices) return String(input.value).trim() === '' ? '' : Number(input.value);
  return input.value;
}
function markDirty(item, s) {
  /* Against what is saved now (1.0.94), not what was when the box was
     drawn: after a save the old value made a change back look like none. */
  s = settingByKey(s.key) || s;
  var now = readValue(s);
  var was = isBool(s) ? ((s.value === true || String(s.value) === '1') ? '1' : '0')
    : (s.value === null || s.value === undefined ? '' : String(s.value));   /* null is empty (1.0.57) */
  var changed = was !== String(now);
  item.classList.toggle('changed', changed);
  /* The database's address is what the steps below it ask about, never
     saved by the save bar (1.0.37): saved, the next restart opened a
     database nothing had been carried into. */
  if (/^db_(engine|host|port|name|user|password)$/.test(s.key)) { delete DIRTY[s.key]; markDirtyCount(); applyOnlyWhen(); return; }
  if (changed) DIRTY[s.key] = now; else delete DIRTY[s.key];
  markDirtyCount();
  applyOnlyWhen();
}
/* Changes that are not settings (1.0.56) - the firewall, the VIP address,
   a certificate authority pasted in - wait for the same save bar:
   PENDING[key] = {save: function () -> Promise (false: not done), reset}. */
var PENDING = {};
function pendingSet(key, p) { p.pane = p.pane || PANE; PENDING[key] = p; markDirtyCount(); }
/* The one save bar, at the bottom (1.0.123): on every pane where something
   is saved - settings, the firewall, the VIP address, the time servers, the
   message texts, the pages' looks - and on no other. A pane that does
   something at once (Network, Restart and power off, Backups…) has its own
   buttons for it and no save bar. */
var SAVE_PANES = ['fw', 'ha', 'time', 'texts', 'portal', 'dnssets'];
function saveBarHere() {
  if (!ADMIN || TAB !== 'settings') return false;
  var pane = $('pane-' + PANE);
  if (!pane) return false;
  /* A setting of the daemon's own (data-key) - not a field that only looks
     like one, as on Network, where nothing is saved: it is done at once. */
  if (SAVE_PANES.indexOf(PANE) >= 0 || pane.querySelector('.set-item[data-key]')) return true;
  return Object.keys(PENDING).some(function (k) { return PENDING[k].pane === PANE; });
}
function markDirtyCount() {
  var n = Object.keys(DIRTY).length + Object.keys(PENDING).length;
  $('set-said').textContent = n ? n + ' change(s) not saved yet' : '';
  $('save-bar').classList.toggle('dirty', n > 0);
  /* Message texts, where only the editor scrolls (1.0.130): the bar is out of
     the way until something is changed, as it is below the end of any other
     page - and then at the bottom. */
  $('save-bar').style.display = saveBarHere() ? '' : 'none';
  saveBarPlace();
}
/* A question as a promise: true for the button, false for anything else. */
function askThen(title, words, buttonWords, danger) {
  return new Promise(function (done) {
    var said = false;
    var end = function (v) { if (!said) { said = true; done(v); } };
    confirmThen(title, words, buttonWords, function () { end(true); }, danger);
    var gen = MODAL_GEN;
    var watch = setInterval(function () {
      if (said) { clearInterval(watch); return; }
      if ($('modal').hidden || MODAL_GEN > gen + 1) { clearInterval(watch); setTimeout(function () { end(false); }, 50); }
    }, 300);
  });
}
function applyOnlyWhen() {
  applySubs();
  var rules = (SETTINGS && SETTINGS.only_when) || {};
  /* A setting is asleep when the one it depends on says so - and also when
     that one is asleep itself (1.0.165): On the day of a weekly restart was
     there to change with the restart switched off. The reason given is the
     first one up the line that is off. */
  var seen = {};
  function wake(key, depth) {
    if (seen[key]) return seen[key];
    var rule = rules[key];
    if (!rule || depth > 6) return (seen[key] = {live: true});
    var master = $('set-' + rule[0]);
    if (!master) return (seen[key] = {live: true});
    var up = wake(rule[0], depth + 1);
    if (!up.live) return (seen[key] = up);
    var now = master._get ? String(master._get()) : String(master.value);
    var want = rule[1];
    var live = want === '*' ? !!now.trim() : (want.slice(-4) === '-not' ? now !== want.slice(0, -4) : now === want);
    return (seen[key] = {live: live, by: rule[0], want: want, now: now});
  }
  Object.keys(rules).forEach(function (key) {
    var item = document.querySelector('.set-item[data-key="' + key + '"]');
    if (!item || !$('set-' + rules[key][0])) return;
    var w = wake(key, 0);
    var live = w.live, want = w.want, now = w.now;
    item.classList.toggle('asleep', !live);
    var says = item.querySelector('.asleep-why');
    // Written again on every pass (1.0.61): it went on naming the choice it
    // was first put in for.
    if (says) says.remove();
    if (!live) {
      var other = settingByKey(w.by) || {};
      (item.querySelector('.set-tail') || item).appendChild(el('div', 'says asleep-why', want === '*' ? 'Not in use until ' + other.name + ' is filled in.'
        : (isBool(other) ? 'Not in use while ' + other.name + ' is off.'
           : 'Not in use while ' + other.name + ' is “' + ((other.choice_words || {})[now] || now) + '”.')));
    }
  });
}
$('set-save').onclick = function () {
  var want = {};
  Object.keys(DIRTY).forEach(function (k) {
    var s = settingByKey(k);
    // A secret's dots are not a change (1.0.61): forgotten, not left on the
    // bar as "not saved" for ever.
    if (s && s.secret && String(DIRTY[k]).indexOf('•') === 0) { delete DIRTY[k]; return; }
    want[k] = DIRTY[k];
  });
  markDirtyCount();
  var keys = Object.keys(PENDING);
  if (!Object.keys(want).length && !keys.length) { toast('nothing has changed'); return; }
  busy($('set-save'), true);
  document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
  var chain = Promise.resolve(true);
  if (Object.keys(want).length) {
    chain = api('settings', {settings: want, drawn_by: DRAWN_NODE}).then(function (d) {
      toast(d.message, 'good');
      /* What was changed while the save was on its way stays changed
         (1.0.61): the redraw after it threw those away without a word. */
      var left = {};
      Object.keys(DIRTY).forEach(function (k) {
        if (!(k in want) || DIRTY[k] !== want[k]) left[k] = DIRTY[k];
      });
      /* What was saved is no longer a change (1.0.170): it stayed in DIRTY, so
         the page was never drawn again and a secret - shown as dots once
         saved - looked changed for ever. */
      Object.keys(want).forEach(function (k) { JUST_SAVED[k] = 1; });
      DIRTY = left;
      markDirtyCount();
      loadSettings(Object.keys(left).length ? false : undefined);
      if (paneLive('upgrade')) loadUpgrade();      /* the card to go back shown or not (1.0.144) */
      tick();
      return true;
    }).catch(function (e) {
      if (e.detail && e.detail.hisec) { hsWindow(e.detail.hisec, false); return false; }
      var said = String(e.message || e);
      /* The longest key the message starts with (1.0.57): portal before portal_help was taken. */
      var hit = SETTINGS.settings.filter(function (one) {
        return said.indexOf(one.key) === 0 && !/[A-Za-z0-9_]/.test(said.charAt(one.key.length));
      }).sort(function (a, b) { return b.key.length - a.key.length; })[0];
      if (hit) {
        var item = document.querySelector('.set-item[data-key="' + hit.key + '"]');
        if (item) { item.classList.add('refused'); item.scrollIntoView({block: 'center'}); }
        said = '“' + hit.name + '”' + said.slice(hit.key.length);
      }
      toast(said, 'bad');
      return false;
    });
  }
  /* Then the rest, one after the other; the first that fails stops it. */
  keys.forEach(function (k) {
    chain = chain.then(function (ok) {
      if (!ok || !PENDING[k]) return ok;
      return Promise.resolve(PENDING[k].save()).then(function (r) {
        if (r === false) return false;
        delete PENDING[k];
        return true;
      }).catch(function (e) { oops(e); return false; });
    });
  });
  chain.then(function () { markDirtyCount(); busy($('set-save'), false); });
};
$('set-reset').onclick = function () {
  var keys = Object.keys(PENDING);
  keys.forEach(function (k) { try { PENDING[k].reset(); } catch (e) { /* drawn again anyway */ } });
  PENDING = {};
  /* The changed values forgotten too (1.0.104): loadSettings draws nothing
     again while any is left, so Put them back did nothing at all. */
  DIRTY = {};
  document.querySelectorAll('.set-item.refused').forEach(function (n) { n.classList.remove('refused'); });
  markDirtyCount();
  loadSettings(); toast('put back as the daemon has them');
};
window.addEventListener('beforeunload', function (e) {
  if (Object.keys(DIRTY).length || Object.keys(PENDING).length) { e.preventDefault(); e.returnValue = ''; }
});

/* ---- the directories administrators sign in against (Settings → Accounts) -- */
function loadDirs() {
  api('directories').then(function (d) {
    var host = $('ad-table');
    clear(host);
    if (!d.directories.length) host.appendChild(el('p', 'note', 'No directory yet. Administrators sign in with the accounts of these pages only.'));
    var list = el('div', 'cardlist');
    d.directories.forEach(function (a) {
      var card = el('div', 'itemcard');
      var head = el('div', 'ic-head');
      var title = el('div', 'ic-title');
      title.appendChild(noI18n(el('b', '', a.name)));
      title.appendChild(el('span', 'tag ' + (a.tls === 'none' ? 'warn' : 'dim'),
        a.tls === 'none' ? 'plain LDAP, ' + a.port : (a.tls === 'ldaps' ? 'LDAPS, ' : 'StartTLS, ') + a.port));
      title.appendChild(el('span', 'tag ' + (a.tls === 'none' ? 'dim' : (a.verify ? 'ok' : 'warn')),
        a.tls === 'none' ? 'no certificate' : (a.verify ? (a.ca_says ? 'checked against ' + a.ca_says.subject : 'checked') : 'NOT checked')));
      if (a.weak && a.tls !== 'none') title.appendChild(el('span', 'tag warn', 'weak certificates taken'));
      if (!a.enabled) title.appendChild(el('span', 'tag dim', 'off'));
      head.appendChild(title);
      var tools = el('div', 'ic-tools');
      var chk = cmdButton('Check it', 'pulse', 'small');
      chk.onclick = function (ev) { ev.stopPropagation(); checkDir(a.name); };
      var who = cmdButton('Look a name up', 'search', 'small');
      who.onclick = function (ev) { ev.stopPropagation(); lookupDir(a.name); };
      if (CERTADMIN) { tools.appendChild(chk); tools.appendChild(who); }
      if (ADMIN) {
        var ed = iconButton('edit', 'Edit');
        ed.onclick = function (ev) { ev.stopPropagation(); editDir(a); };
        tools.appendChild(ed);
        var x = iconButton('trash', 'Take it away');
        x.onclick = function (ev) {
          ev.stopPropagation();
          confirmThen('Take the directory ' + a.name + ' away', 'Nothing is looked up in it any more: nobody signs in against it.', 'Take it away', function () {
            api('directories', {action: 'delete', id: a.id}).then(function (d2) { toast(d2.message, 'good'); loadDirs(); }).catch(oops);
          });
        };
        tools.appendChild(x);
      }
      head.appendChild(tools);
      card.appendChild(head);
      var facts = el('div', 'ic-facts');
      var fact = function (k, v, mono) {
        var f = el('div', 'ic-fact');
        f.appendChild(el('span', 'k', k));
        var vv = el('span', 'v' + (mono ? ' mono' : ''));
        if (typeof v === 'string') vv.textContent = v; else vv.appendChild(v);
        noI18n(vv);
        f.appendChild(vv);
        facts.appendChild(f);
      };
      var hosts = el('span', 'chips');
      String(a.hosts || '').split(/\s*,\s*/).filter(Boolean).forEach(function (h) { hosts.appendChild(el('span', 'chip mono', h)); });
      fact('Servers, in order', hosts);
      fact('Where to look (the base)', a.base || '–', true);
      fact('The account it reads with', a.bind_dn || 'nobody', true);
      fact('A short name is', a.user_attr || 'sAMAccountName', true);
      card.appendChild(facts);
      if (ADMIN) card.onclick = function () { editDir(a); };
      list.appendChild(card);
    });
    host.appendChild(list);
    DIRS = d.directories;
    drawCaPick();
    explainWhatWasDrawn(host);
  }).catch(oops);
}
if ($('ad-add')) $('ad-add').onclick = function () { editDir({tls: 'ldaps', port: 636, verify: 1, nested: 1, enabled: 1, timeout_s: 10, user_attr: 'sAMAccountName'}); };

function editDir(a) {
  modal(a.id ? 'The directory ' + a.name : 'A new directory', function (body) {
    var g = el('div', 'formgrid');
    var name = textBox(a.name, 'AD', '');
    var hosts = textBox(a.hosts, 'dc1.example.local, dc2.example.local', 'mono');
    var tls = selectBox([['ldaps', 'LDAPS (636)'], ['starttls', 'StartTLS (389)'], ['none', 'plain LDAP (389) - a test only']], a.tls);
    hsOptions(tls, ['none'], 'dir:tls');
    var port = textBox(a.port, '636', 'mono');
    tls.onchange = function () { port.value = tls.value === 'ldaps' ? '636' : '389'; };
    var verify = switchBox(a.verify);
    var weak = switchBox(!!a.weak);                  /* old, weak certificates (1.0.77) */
    if (hsOn('dir:verify') && (a.verify || a.verify === undefined)) verify._input.disabled = true;
    if (hsOn('dir:weak') && !a.weak) weak._input.disabled = true;
    var base = textBox(a.base, 'DC=example,DC=local', 'mono');
    var bind = textBox(a.bind_dn, 'acme@example.local', 'mono');
    var pw = secretBox(a.id ? a.bind_pw : '', a.id ? 'set - leave as it is to keep it' : '', 'mono');
    var attr = textBox(a.user_attr || 'sAMAccountName', '', 'mono');
    var to = textBox(a.timeout_s || 10, '', 'mono');
    var on = switchBox(a.enabled);
    var ca = el('textarea'); ca.rows = 4; ca.placeholder = '-----BEGIN CERTIFICATE-----'; ca.value = a.ca || '';
    var secs = el('div', 'msects');
    var s1 = msect('How it is reached', 'The domain controllers, in the order they are asked, and how.');
    var g1 = el('div', 'formgrid');
    g1.appendChild(formField('Name', name, 'What Accounts calls it, in Sign administrators in against the directory.'));
    g1.appendChild(formField('In use', on));
    s1._body.appendChild(g1);
    s1._body.appendChild(formField('Servers, in the order to ask them', hosts, 'Separated by commas. One that cannot be reached is passed over for the next.'));
    var g1b = el('div', 'formgrid');
    g1b.appendChild(formField('How it is reached', tls));
    g1b.appendChild(formField('Port', port));
    g1b.appendChild(formField('Check its certificate', verify, 'Off is for a test: a directory reached without checking its certificate is one anybody on the path can pretend to be.'));
    g1b.appendChild(formField('Take old, weak certificates', weak, 'For domain controllers whose certificate has a 1024-bit key or a SHA-1 signature, or that speak TLS 1.0 only: refused by default ("EE certificate key too weak"). The certificate is still checked against its authority and the server’s name; the encryption is as weak as the server’s. Better: give the servers new certificates.'));
    g1b.appendChild(formField('Wait for an answer (s)', to));
    s1._body.appendChild(g1b);
    secs.appendChild(s1);
    var s2 = msect('Reading it', 'The account it reads with - it needs nothing but to read - and where it looks.');
    s2._body.appendChild(formField('The account it reads with', bind, 'A user principal name (acme@example.local) or a whole DN. It needs nothing but to read.'));
    s2._body.appendChild(formField('Its password', pw));
    s2._body.appendChild(formField('Where to look (the base)', base));
    s2._body.appendChild(formField('A short name is', attr, 'The attribute a name without its @domain is looked up by.'));
    secs.appendChild(s2);
    body.appendChild(secs);
    if (!a.id) {
      var cf = formField('The certificate authority that signed its certificate (PEM)', ca,
        'Needed when the domain controllers’ certificates come from an authority of your own that this machine does not already trust.');
      body.appendChild(cf);
    } else {
      body.appendChild(el('p', 'note', a.ca_says
        ? 'The certificate authority: ' + (a.ca_says.subject || 'imported') + ', good until '
          + (a.ca_says.until || '–') + '. It is imported, read from a file or taken away under '
          + 'The certificate authority, below the list of directories.'
        : 'No certificate authority is imported for it. That is done under The certificate '
          + 'authority, below the list of directories.'));
    }
    MODAL_GO = function (b) {
      busy(b, true);
      api('directories', {action: 'save', directory: {id: a.id, name: name.value, hosts: hosts.value, tls: tls.value,
        port: Number(port.value), verify: verify._get(), weak: weak._get(), base: base.value, bind_dn: bind.value,
        bind_pw: pw.value === a.bind_pw ? undefined : pw.value, user_attr: attr.value, timeout_s: Number(to.value),
        enabled: on._get(), nested: 1, ca: a.id ? undefined : ca.value, note: a.note || ''}}).then(function (d) {
        toast(d.message, 'good'); closeModal(); loadDirs();
      }).catch(oops).then(function () { busy(b, false); });
    };
  }, [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) { MODAL_GO(b); }}], 'large');
}

/* Tried from every node (1.0.169): each reaches the domain controllers on its own. */
function checkDir(name) {
  modal('Checking ' + name, function (body) {
    var grid = nodeGrid();
    body.appendChild(grid);
    var cards = {};
    askNodes('directories', {action: 'check_all', name: name}, function (n, got) {
      var slot = cards[n];
      if (!slot) return;
      var c = got.check;
      var fresh = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, got.ok ? 'ok' : 'bad', got.ok ? 'reached' : 'not reached', got.ok ? 'ok' : 'crit');
      if (got.error || !c) {
        fresh.appendChild(el('p', 'note bad', got.error || 'no answer'));
      } else {
        fresh.appendChild(netFacts([['How', c.tls === 'none' ? 'plain LDAP' : c.tls], ['Certificate', c.tls === 'none' ? 'not used' : (c.verify ? 'checked' : 'NOT checked') + (c.weak ? ' · weak taken' : '')],
                                    ['Took', num(c.took_ms) + ' ms']]));
        (c.servers || []).forEach(function (sv) {
          fresh.appendChild(noI18n(el('h3', 'peek-h', sv.host + ':' + sv.port)));
          fresh.appendChild(stepsList(sv.steps));
        });
      }
      grid.replaceChild(fresh, slot);
      cards[n] = fresh;
    }).then(function (x) {
      (x.nodes || []).forEach(function (n) {
        var c = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, 'dim', 'being tried', 'info');
        c.appendChild(el('p', 'muted small', 'Connecting to the domain controllers from ' + n + '…'));
        grid.appendChild(c);
        cards[n] = c;
      });
    }).catch(function (e) { closeModal(); oops(e); });
  }, [{words: 'Close', close: true}], 'large');
}
/** A question in the page's own popup - never the browser's. `fields` are
    {label, type, placeholder, says}; `go(values, button)` gets what was typed. */
function askInModal(title, lede, fields, words, icon, go) {
  var boxes = [];
  modal(title, function (body) {
    if (lede) body.appendChild(el('p', 'note', lede));
    var g = el('div', 'formgrid');
    fields.forEach(function (f) {
      var input = f.type === 'password' ? maskBox('', '', '') : el('input');
      if (f.type !== 'password') input.type = f.type || 'text';
      input.placeholder = f.placeholder || '';
      input.autocomplete = 'off';
      if (f.value && f.type !== 'password') input.value = f.value;
      if (f.mono) input.className = 'mono';
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); $('modal-foot').querySelector('.btn.primary').click(); }
      });
      boxes.push(input);
      g.appendChild(formField(f.label, input, f.says));
      if (f.people) personSuggest(input, f.people);
    });
    body.appendChild(g);
    setTimeout(function () { if (boxes[0]) boxes[0].focus(); }, 60);
  }, [{words: 'Close', close: true}, {words: words, cls: 'primary', icon: icon, go: function (b) {
    go(boxes.map(function (x) { return x.value; }), b);
  }}], 'medium');
}

function lookupDir(name) {
  askInModal('Look a name up in ' + name, 'What the directory says about one person: who they are, whether the '
    + 'account is switched off or has run out, and every group they are in, those inside groups as well.',
    [{label: 'Who', placeholder: 'novak@example.cz or novak', mono: true, people: {directory: name},
      says: 'A whole name, or a short one - or part of a name, and pick one.'}], 'Look it up', 'search', function (v) {
      var who = v[0].trim();
      if (!who) { toast('type a name first', 'bad'); return; }
      lookupDirShow(name, who);
    });
}
function lookupDirShow(name, who) {
  peek(who + ' in ' + name, function () { return api('directories', {action: 'lookup', name: name, user: who}); }, function (body, d) {
    if (!d.entry) { body.appendChild(el('p', 'note', 'The directory has nobody by that name.')); return; }
    var e = d.entry;
    body.appendChild(peekFacts([['Who', e.display || e.sam], ['Switched off', e.disabled ? 'yes' : 'no'],
                                ['Expires', e.expires ? stamp(e.expires) : 'never'], ['Took', d.took_ms + ' ms']]));
    body.appendChild(kvTable([['DN', e.dn], ['userPrincipalName', e.upn], ['sAMAccountName', e.sam], ['Mail', e.mail],
                              ['Department', e.department]]));
    body.appendChild(el('h3', 'peek-h', 'Groups, those inside groups as well'));
    var box = el('div', 'namesrow');
    (d.groups || []).slice().sort().forEach(function (gname) { box.appendChild(noI18n(el('span', 'tag namepill', gname))); });
    body.appendChild(box);
  });
}

/* ---- every node as a card of its own (1.0.169) ----------------------------------
   The standard of the panes that show the nodes - Time, Network, Syslog, isemon,
   Disks and logs: one card a node, its state in the head, the facts as tiles,
   what can be done on that node below; the settings for all in a card after. */
function nodeGrid() { return el('div', 'pw-grid node-grid'); }
function nodeCard(n, dot, tag, tagCls) {
  var c = el('div', 'card ntp-node');
  var head = el('div', 'pw-head');
  head.appendChild(el('span', 'dot ' + dot));
  head.appendChild(noI18n(el('b', '', n.node || n.name)));
  if (n.me) head.appendChild(el('span', 'tag info', 'this page'));
  if (tag) head.appendChild(el('span', 'tag ' + (tagCls || 'dim'), tag));
  c.appendChild(head);
  return c;
}
function nodeBig(c, value, words) {
  var big = el('div', 'ntp-big');
  big.appendChild(noI18n(el('span', 'ntp-off', value)));
  if (words) big.appendChild(el('span', 'muted small', ' ' + words));
  c.appendChild(big);
}
function nodeFresh(n) { return n.at && Date.now() / 1000 - n.at < 300; }
/* A test only a node can make, asked of it (or of every node) and its answer
   followed: onEach(node, answer) as each comes, onDone() at the end. */
function askNodes(what, body, onEach, onDone) {
  return api(what, body).then(function (x) {
    var left = (x.nodes || []).slice(), began = Date.now();
    var timer = setInterval(function () {
      api(what, {action: 'result', id: x.id}).then(function (r) {
        left = left.filter(function (n) {
          var got = (r.nodes || {})[n];
          if (got) { onEach(n, got); return false; }
          return true;
        });
        if (!left.length || Date.now() - began > 60000) {
          clearInterval(timer);
          left.forEach(function (n) { onEach(n, {ok: false, error: 'did not answer in a minute - is it running?'}); });
          if (onDone) onDone();
        }
      }).catch(function () {
        /* Every answer failing (1.0.208): asked once a second for good, its
           button busy - the minute ends it as well. */
        if (Date.now() - began > 60000) {
          clearInterval(timer);
          left.forEach(function (n) { onEach(n, {ok: false, error: 'did not answer in a minute - is it running?'}); });
          if (onDone) onDone();
        }
      });
    }, 1000);
    return x;
  });
}

/* ---- isemon --------------------------------------------------------------- */
var IS = {d: null, said: {}};
function loadIsemon() {
  api('isemon').then(function (d) { IS.d = d; drawIsemon(); drawIsemonTls(); }).catch(oops);
  drawIsemonGuide();
}
function drawIsemon() {
  var real = $('isemon-state');
  if (!real || !IS.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var grid = nodeGrid();
    (IS.d.nodes || []).forEach(function (n) {
      var fresh = nodeFresh(n), trouble = Object.keys(n.trouble || {});
      var on = n.on && (n.targets || []).length;
      var c = nodeCard(n, !fresh ? 'bad' : (!on ? 'dim' : (trouble.length ? 'warn' : 'ok')),
        !fresh ? 'not heard from' : (!n.on ? 'off' : (!(n.targets || []).length ? 'nowhere to send' : (trouble.length ? 'trouble' : 'sending'))),
        !fresh ? 'crit' : (!on ? 'dim' : (trouble.length ? 'warn' : 'ok')));
      var total = 0;
      Object.keys(n.sent || {}).forEach(function (k) { total += n.sent[k]; });
      nodeBig(c, num(total), 'line(s) sent since it started');
      c.appendChild(netFacts([
        ['As the host', n.host || '', true], ['To', (n.targets || []).join(', ') || '', true],
        ['Last sent', n.last_sent ? ago(n.last_sent) : 'never'], ['Waiting', num(n.queued || 0)],
        ['Dropped, the queue full', num(n.dropped || 0)], ['Files here', n.files ? n.file_dir : 'no', !!n.files]
      ]));
      (n.targets || []).forEach(function (t) {
        var row = el('div', 'si-row');
        row.appendChild(el('span', 'dot ' + ((n.trouble || {})[t] ? 'bad' : ((n.sent || {})[t] ? 'ok' : 'dim'))));
        row.appendChild(noI18n(el('span', 'mono', t)));
        row.appendChild(el('span', 'muted small', num((n.sent || {})[t] || 0) + ' sent'));
        c.appendChild(row);
        if ((n.trouble || {})[t]) c.appendChild(noI18n(el('div', 'si-said small', n.trouble[t])));
      });
      var said = IS.said[n.node];
      if (said) c.appendChild(nodeSaid(said, said.ok ? 'The test line went to ' + (said.went || []).join(', ') : 'The test line did not go'));
      if (ADMIN) {
        var row2 = el('div', 'btnrow');
        var t = cmdButton('Send a test line', 'pulse', 'small');
        t.disabled = !IS.d.on || !fresh;
        explain(t, 'One line from ' + n.node + ' to every isemon receiver, now - isemon reads nothing from it; to see it arrive.');
        t.onclick = function () {
          busy(t, true);
          askNodes('isemon', {action: 'test', node: n.node}, function (node, got) {
            IS.said[node] = got;
            if (got.state) IS.d.nodes.forEach(function (x) { if (x.node === node) Object.assign(x, got.state, {at: Date.now() / 1000}); });
          }, function () { busy(t, false); drawIsemon(); }).catch(function (e) { busy(t, false); oops(e); });
        };
        row2.appendChild(t);
        /* A sign-in isemon shows (1.0.178), under a name given. */
        var ts = cmdButton('Send a test sign-in…', 'person', 'small');
        ts.disabled = t.disabled;
        explain(ts, 'A line from ' + n.node + ' to every isemon receiver that isemon shows as a sign-in of the name given - its message says it is a test.');
        ts.onclick = function () {
          var who, res;
          modal('A test sign-in for isemon', function (body) {
            body.appendChild(el('p', 'note', 'isemon shows it under this name as a sign-in from ' + n.node + ', a success or a failure as chosen; its message says it is a test from acme. Nothing is checked and nothing is written into this node\'s files.'));
            var g = el('div', 'formgrid');
            who = textBox('acme-test', 'acme-test', 'mono');
            g.appendChild(formField('As the user', who));
            /* Success or Failure (1.0.179): a switch, green or red - it said s / f. */
            res = switchBox(true);
            res.className += ' okbad';
            var said = el('span', 'sw-said ok', 'Success');
            res._input.onchange = function () {
              said.className = 'sw-said ' + (res._get() ? 'ok' : 'bad');
              said.textContent = res._get() ? 'Success' : 'Failure';
            };
            var line = el('div', 'sw-line');
            line.appendChild(res); line.appendChild(said);
            g.appendChild(formField('How it ends', line));
            body.appendChild(g);
            setTimeout(function () { who.focus(); }, 60);
          }, [{words: 'Close', close: true}, {words: 'Send it', cls: 'primary', icon: 'pulse', go: function (b) {
            busy(b, true);
            askNodes('isemon', {action: 'test', node: n.node, as_user: who.value.trim(), ok: !!res._get()}, function (node, got) {
              IS.said[node] = got;
              if (got.state) IS.d.nodes.forEach(function (x) { if (x.node === node) Object.assign(x, got.state, {at: Date.now() / 1000}); });
            }, function () { closeModal(); drawIsemon(); }).catch(function (e) { busy(b, false); oops(e); });
          }}], 'medium');
        };
        row2.appendChild(ts);
        c.appendChild(row2);
      }
      grid.appendChild(c);
    });
    host.appendChild(grid);
  });
}
/* What a test found, in a node's card. */
function nodeSaid(got, words) {
  var p = el('div', 'node-said ' + (got.ok ? 'ok' : 'bad'));
  p.appendChild(el('span', 'dot ' + (got.ok ? 'ok' : 'bad')));
  var t = el('div');
  t.appendChild(el('b', '', got.error ? 'It did not go' : words));
  if (got.error) t.appendChild(noI18n(el('div', 'small muted', got.error)));
  t.appendChild(el('div', 'small muted', ago(got.at)));
  p.appendChild(t);
  return p;
}
function drawIsemonGuide() {
  var host = $('isemon-guide');
  if (!host || host._drawn) return;
  host._drawn = true;
  host.appendChild(el('h2', '', 'On the isemon machine'));
  host.appendChild(el('p', 'note', 'isemon reads each node from the files its rsyslog writes under /var/log/remote/HOST/. Its rsyslog needs the rule for acme\'s program names - deploy/isemon/11-acme.conf in this package, copied to /etc/rsyslog.d/ there - and in isemon the folder of each node switched on.'));
}

/* ---- accounts ------------------------------------------------------------- */
function loadUsers() {
  colsCardSay();
  api('users').then(function (d) {
    var host = $('us-table');
    clear(host);
    host.appendChild(listTable(['Name', 'Role', 'Signs in', 'State', 'Second step', 'Last signed in', 'From', 'Columns', 'Note', ''], d.users, function (u) {
      var tr = el('tr');
      var n = el('td'); n.appendChild(noI18n(el('span', 'mono', u.name)));
      if (u.display) n.appendChild(noI18n(el('span', 'sub', u.display)));
      tr.appendChild(n);
      var r = el('td'); r.appendChild(el('span', 'tag ' + roleTone(u.role), roleWords(u.role))); tr.appendChild(r);
      tr.appendChild(el('td', 'muted', u.source === 'directory' ? 'against the directory' : 'a password here'));
      var st = el('td'); st.appendChild(el('span', 'tag ' + (u.disabled ? 'crit' : 'ok'), u.disabled ? 'off' : 'on')); tr.appendChild(st);
      /* The second step of signing in (1.0.125): how it is given, or not yet. */
      var mf = el('td', 'small');
      if (u.mfa) {
        mf.appendChild(el('span', 'tag ok', {app: 'an app', mail: 'e-mail', sms: 'SMS'}[u.mfa.kind] || u.mfa.kind));
        if (u.mfa.dest) mf.appendChild(noI18n(el('span', 'sub mono', u.mfa.dest)));
      } else {
        mf.appendChild(el('span', d.mfa_on ? 'muted' : 'muted', d.mfa_on ? 'set up at the next sign-in' : '–'));
      }
      tr.appendChild(mf);
      tr.appendChild(u.last_in ? stampCell(u.last_in) : el('td', 'muted', 'never'));
      tr.appendChild(noI18n(el('td', 'mono small', u.last_from || '')));
      tr.appendChild(el('td', 'muted small', u.cols_tables ? num(u.cols_tables) + ' table(s) laid out' : 'as they come'));
      tr.appendChild(noI18n(el('td', 'muted small', u.note || '')));
      var tools = el('td', 'rowtools');
      /* Every row has the same buttons in the same places (1.0.18): one
         that does not apply to this account is there, dimmed, and says why -
         an invisible gap looked like a mistake. */
      var info = iconButton('person', u.source === 'directory'
        ? 'In the directory: who it is, whether the account is switched off, its groups'
        : 'An account kept here, not in a directory');
      if (u.source === 'directory') info.onclick = function (ev) { ev.stopPropagation(); whoisPeek(u.name, 'account'); };
      else info.disabled = true;
      if (ADMIN) {
        /* The role first, the buttons as one group after it. */
        var role = selectBox(d.roles.map(function (x) { return [x.role, x.words]; }), u.role);
        role.onchange = function () { userDo({action: 'role', name: u.name, role: role.value}); };
        role.style.marginRight = '10px';
        tools.appendChild(role);
      }
      tools.appendChild(info);
      if (ADMIN) {
        if (u.source !== 'directory') {
          var pw = iconButton('lock', 'Set a new password');
          pw.onclick = function () {
            askInModal('A new password for ' + u.name, 'They choose their own at the next sign-in.',
              [{label: 'The new one (8 characters at least)', type: 'password'},
               {label: 'Again', type: 'password'}], 'Set it', 'lock', function (v) {
                if (v[0].length < 8) { toast('8 characters at least', 'bad'); return; }
                if (v[0] !== v[1]) { toast('the two are not the same', 'bad'); return; }
                closeModal();
                userDo({action: 'password', name: u.name, password: v[0], must_change: 1});
              });
          };
          tools.appendChild(pw);
        } else {
          var gap = iconButton('lock', 'The password is the directory’s: it is changed there');
          gap.disabled = true;
          tools.appendChild(gap);
        }
        var off = iconButton('power', u.disabled ? 'Let it sign in again' : 'Stop it signing in');
        off.onclick = function () { userDo({action: u.disabled ? 'enable' : 'disable', name: u.name}); };
        var x = iconButton('trash', 'Remove it');
        x.onclick = function () {
          confirmThen('Remove the account ' + u.name, 'It cannot sign in any more.', 'Remove it', function () {
            userDo({action: 'delete', name: u.name});
          });
        };
        tools.appendChild(off); tools.appendChild(x);
        /* Somebody's own layout of the tables, put back as it comes. */
        var cb = iconButton('undo', u.cols_tables
          ? u.name + ' has laid out ' + num(u.cols_tables) + ' table(s) by hand. Put every one of them back as it comes: the widths, the order and the hidden columns. Nothing else of theirs changes.'
          : u.name + ' has every table as it comes: nothing to put back.');
        cb.classList.add('cols-back');
        if (u.cols_tables) {
          cb.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('The columns of ' + u.name,
              'Every table ' + htmlText(u.name) + ' has laid out goes back as it comes. They see it '
              + 'the next time a page loads.',
              'Put them back', function () {
                colsReset(u.name).then(function () {
                  if (ME && u.name === ME.name) colsCardSay();
                  loadUsers();
                }).catch(oops);
              });
          };
        } else {
          cb.disabled = true;
        }
        tools.appendChild(cb);
        var mr = iconButton('shield', u.mfa
          ? 'Reset the second step: ' + u.name + ' sets it up again at the next sign-in. Their sign-ins are ended.'
          : u.name + ' has no second step set up: nothing to reset.');
        if (u.mfa) {
          mr.onclick = function (ev) {
            ev.stopPropagation();
            confirmThen('Reset the second step of ' + u.name + '?',
              htmlText('The way ' + u.name + ' gives the second step is taken away, and their sign-ins are ended. At the next sign-in they choose and set it up again - with the password alone, so do it only when you know it is them (a lost phone, a new one).'),
              'Reset it', function () {
                api('users', {action: 'mfa_reset', name: u.name}).then(function (r) { toast(r.message, 'good'); loadUsers(); }).catch(oops);
              }, true);
          };
        } else {
          mr.disabled = true;
        }
        tools.appendChild(mr);
      }
      tr.appendChild(tools);
      return tr;
    }));
    explainWhatWasDrawn(host);
  }).catch(oops);
  loadLockouts();
  if (ADMIN) api('sessions').then(function (d) {
    var host = $('se-table');
    clear(host);
    host.appendChild(listTable(['Who', 'Where', 'From', 'Since', 'Last asked', ''], d.sessions, function (s) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', s.name)));
      tr.appendChild(el('td', '', s.kind === 'admin' ? 'these pages' : 'the portal'));
      tr.appendChild(noI18n(el('td', 'mono small', s.ip)));
      tr.appendChild(stampCell(s.created));
      tr.appendChild(el('td', 'muted', ago(s.last)));
      var tools = el('td', 'rowtools');
      var x = cmdButton('End it', 'cancel', 'small');
      // Asked first (1.0.61): it may be your own.
      x.onclick = function () {
        confirmThen('End this sign-in', htmlText(String(s.name || '?')) + (s.ip ? ' from ' + htmlText(String(s.ip)) : '')
          + ' is signed out at once.', 'End it', function () {
          api('sessions', {id: s.id}).then(function () { loadUsers(); }).catch(oops);
        });
      };
      tools.appendChild(x);
      tr.appendChild(tools);
      return tr;
    }));
  }).catch(oops);
}
/* Locked out (1.0.112): who has wrong attempts counted, on which node, how
   long the lockout still runs - cleared one by one or all at once. Fetched
   again every 10 s while the card is on the screen; the time left counts
   down every second in between. */
var LO = {data: null, skew: 0, fetched: 0, timer: null};
/* Where the counts are shown (1.0.137): Accounts. */
var LO_VIEWS = [
  {table: 'lo-table', tools: 'lo-tools', card: 'lo-card', kinds: null}
];
function loadLockouts() {
  if (!ADMIN || !LO_VIEWS.some(function (v) { return $(v.table); })) return;
  api('lockouts').then(function (d) {
    LO.data = d;
    LO.skew = d.now - Date.now() / 1000;
    LO.fetched = Date.now();
    drawLockouts();
    if (!LO.timer) LO.timer = setInterval(loTick, 1000);
  }).catch(function (e) { if (LO.timer) { clearInterval(LO.timer); LO.timer = null; } oops(e); });
}
function loTick() {
  var seen = LO_VIEWS.some(function (v) { var c = $(v.card); return c && c.offsetParent; });
  if (!seen || document.hidden) { clearInterval(LO.timer); LO.timer = null; return; }
  if (Date.now() - LO.fetched > 10000) { LO.fetched = Date.now(); loadLockouts(); return; }
  drawLockouts();
}
function loNow() { return Date.now() / 1000 + LO.skew; }
function loClear(body, words) {
  api('lockouts', body).then(function (r) {
    toast((words || r.message) + ((r.told || []).length ? ' - ' + r.told.join(', ') + ' clears it within a few seconds' : ''), 'good');
    loadLockouts();
    /* The other node clears its part at its next turn (5 s). */
    if ((r.told || []).length) setTimeout(loadLockouts, 7000);
  }).catch(oops);
}
function drawLockouts() {
  LO_VIEWS.forEach(function (v) { if ($(v.table)) drawLockoutsIn(v); });
}
/* How far a count has got towards its limit (1.0.137): a bar that fills. */
function loBar(n, limit, locked) {
  var bar = el('div', 'lo-bar' + (locked ? ' full' : ''));
  var fill = el('i');
  fill.style.width = (limit ? Math.min(100, Math.round(100 * n / limit)) : 0) + '%';
  bar.appendChild(fill);
  return bar;
}
function drawLockoutsIn(v) {
  var d = LO.data;
  var host = $(v.table);
  if (!d || !host) return;
  var now = loNow();
  var rows = [];
  var find = v.find && $(v.find) ? $(v.find).value.trim().toLowerCase() : '';
  (d.nodes || []).forEach(function (n) {
    (n.rows || []).forEach(function (r) {
      if (r.forgets <= now) return;
      if (v.kinds && v.kinds.indexOf(r.kind) < 0) return;
      if (find && (String(r.who).toLowerCase().indexOf(find) < 0)
          && !(r.others || []).some(function (o) { return String(o).toLowerCase().indexOf(find) >= 0; })) return;
      var x = Object.assign({}, r);
      x.node = n.node; x.stale = !n.fresh;
      if (x.locked && x.until <= now) x.locked = false;
      rows.push(x);
    });
  });
  rows.sort(function (a, b) { return (b.locked - a.locked) || (b.last - a.last); });
  liveFill($(v.tools), function (tools) {
  var locked = rows.filter(function (r) { return r.locked; }).length;
  if (rows.length) {
    if (locked) { var lc = el('span', 'small bad', num(locked) + ' locked out'); lc.style.marginRight = '12px'; tools.appendChild(lc); }
    var all = cmdButton('Clear them all', 'broom', 'small');
    all.onclick = function () {
      confirmThen('Clear every lockout?', 'Every count of wrong attempts is forgotten' + (d.cluster ? ' on every node' : '')
        + ' - the locked out may try again at once. Events keeps a line saying who did it.', 'Clear them all', function () {
        loClear({action: 'clear_all'});
      }, false);
    };
    tools.appendChild(all);
  }
  }, true);
  liveFill(host, function (host) {
  if (!rows.length) {
    host.appendChild(el('p', 'note good', find ? 'Nothing counted for "' + find + '".'
      : 'Nobody is locked out, and no wrong attempt is being counted.'));
    return;
  }
  var heads = ['State', 'Who', 'Where', 'How many', 'Tried'].concat(d.cluster ? ['Node'] : []).concat(['Last', '']);
  host.appendChild(listTable(heads, rows, function (r) {
    var tr = el('tr', r.locked ? 'lo-locked' : '');
    var st = el('td');
    if (r.locked) {
      st.appendChild(el('span', 'tag crit', 'locked out'));
      st.appendChild(el('div', 'small', span(r.until - now) + ' left'));
      if (r.why) st.appendChild(el('div', 'small muted', r.why));
    } else {
      st.appendChild(el('span', 'tag load', 'counting'));
      st.appendChild(el('div', 'small muted', 'forgotten in ' + span(r.forgets - now)));
    }
    tr.appendChild(st);
    var who = el('td');
    who.appendChild(noI18n(el('div', 'mono', r.who)));
    who.appendChild(el('div', 'small muted', r.by === 'address' ? 'an address' : 'a name'));
    tr.appendChild(who);
    tr.appendChild(el('td', 'small', r.what));
    var w = el('td', 'num lo-count');
    var line = el('div');
    line.appendChild(noI18n(el('b', '', num(r.fails))));
    line.appendChild(document.createTextNode(' / ' + num(r.limit)));
    w.appendChild(line);
    w.appendChild(loBar(r.fails, r.limit, r.locked));
    tr.appendChild(w);
    var tried = el('td', 'small');
    if ((r.others || []).length) {
      tried.appendChild(el('div', 'muted', r.by === 'address' ? 'names:' : 'from:'));
      tried.appendChild(noI18n(el('div', 'mono', r.others.slice().reverse().join(', '))));
    } else tried.textContent = '–';
    tr.appendChild(tried);
    if (d.cluster) {
      /* Counted in the database (1.0.116): the same for every node. */
      var nd = r.node === '*' ? el('td', 'small muted', 'every node') : noI18n(el('td', 'mono small', r.node));
      if (r.stale) { nd.appendChild(document.createTextNode(' ')); nd.appendChild(el('span', 'tag warn', 'not heard from')); }
      tr.appendChild(nd);
    }
    tr.appendChild(el('td', 'muted small', ago(r.last - LO.skew)));
    var a = el('td', 'rowtools');
    var x = cmdButton('Clear', 'broom', 'small');
    explain(x, 'Its count of wrong attempts is forgotten: it may try again at once.');
    x.onclick = function () {
      loClear({action: 'clear', node: r.node, kind: r.kind, who: r.who}, 'cleared: ' + r.who);
    };
    a.appendChild(x);
    tr.appendChild(a);
    return tr;
  }, 'plain'));
  }, true);
}
function userDo(body) {
  /* Drawn again either way (1.0.44): a refused change stayed in its box. */
  api('users', body).then(function (d) { toast(d.message, 'good'); loadUsers(); })
    .catch(function (e) { oops(e); loadUsers(); });
}
$('us-add').onclick = function () {
  modal('A new account', function (body) {
    var g = el('div', 'formgrid');
    var name = textBox('', '', 'mono');
    var role = selectBox([['readonly', 'read only'], ['certadmin', 'cert admin'], ['fulladmin', 'full admin']], 'certadmin');
    var pw = secretBox('', '8 characters at least', 'mono');
    var note = textBox('', '', '');
    g.appendChild(formField('Name', name));
    g.appendChild(formField('Role', role));
    g.appendChild(formField('A first password', pw, 'They choose their own at the first sign-in.'));
    g.appendChild(formField('Note', note));
    body.appendChild(g);
    MODAL_GO = function (b) {
      if (b) busy(b, true);         // one account per press (1.0.61)
      api('users', {action: 'add', name: name.value, role: role.value, password: pw.value, note: note.value, must_change: 1})
        .then(function (d) { toast(d.message, 'good'); closeModal(); loadUsers(); }).catch(oops)
        .then(function () { if (b) busy(b, false); });
    };
  }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'add', go: function (b) { MODAL_GO(b); }}], true);
};

/* ---- the database --------------------------------------------------------- */
/* ==========================================================================
   The database - as isemon's Settings → The database (1.10.160 - 1.10.218)
   ========================================================================== */
var DBSTATE = null;
var ENGINE_SAID = {sqlite: 'the file on this machine', mariadb: 'MariaDB', postgres: 'PostgreSQL'};
var DUMP_SAID = {sqlite: 'a copy of the file', mariadb: 'a MariaDB dump',
                 postgres: 'a PostgreSQL dump', copy: 'a portable copy'};
var TABLE_SAID = {certs: 'certificates', cert_versions: 'certificates had before', cert_cas: 'own authorities',
                  cert_ca_issued: 'signed by own authorities', cert_issuers: 'sources', cert_challenges: 'validations',
                  cert_targets: 'targets', cert_deploys: 'deployments', cert_jobs: 'jobs', dns_records: 'DNS records',
                  events: 'events', accounts: 'accounts', sessions: 'sign-ins',
                  directories: 'directories', settings: 'settings', meta: 'notes of its own'};

function loadDb() {
  api('db').then(function (d) {
    DBSTATE = d;
    $('db-size').textContent = bytes(d.size) + ' · ' + d.where;
    drawEngine(d);
    drawDisk(d);
    drawCounts(d);
    keptTable($('db-backups'), d.copies || [], {
      kind: 'copy', head: 'Copies kept (' + d.keep + ' at most)',
      where: 'They are files on this machine, under ' + d.backup_dir + ', each with the key '
        + 'that opens the sealed keys beside it. Copy them off it if they are to survive the machine.'
    });
    keptTable($('db-dumps'), d.dumps || [], {
      kind: 'dump', head: 'Dumps kept (' + d.keep + ' at most)',
      where: 'They are files on this machine, under ' + d.dump_dir + ', each with the key '
        + 'that opens the sealed keys beside it. Copy them off it if they are to survive the machine.'
    });
    dumpCard(d);
    loadDbTls();                                        /* encryption to the server (1.0.170) */
    drawTune(d);
    drawErasable(d.erasable || {});
    if (d.job && d.job.running && ADMIN) dbWatch();     /* its progress is a full administrator's (1.0.146) */
    explainWhatWasDrawn($('pane-db'));
  }).catch(oops);
}

/* ---- which database everything is kept in -------------------------------- */
function engineWord(name) { return ENGINE_SAID[name] || name; }

function drawEngine(d) {
  $('db-engine-now').textContent = (ENGINE_SAID[d.engine] || d.engine) + ' · ' + d.where;
  var host = $('db-engine-says');
  clear(host);
  var c = d.counts || {};
  host.appendChild(peekFacts([
    ['In use now', d.version],
    ['Where', noI18n(el('span', 'mono', d.where))],
    ['Holding', num(c.certs || 0) + ' certificate(s), ' + num(c.cert_jobs || 0) + ' job(s)'],
    ['Room it takes', bytes(d.size || 0)]
  ]));
  dbMoveGuardDraw($('db-move-guard'), d.move_guard, true);
  if ($('db-move-open')) {
    $('db-move-open').disabled = !!d.move_guard;
    $('db-move-open').title = d.move_guard ? 'Not on a node of a cluster: see why above.'
      : 'Step by step: where to, how to reach it, the checks, what will happen - then everything is carried across and acme starts again on it. Nothing is changed until the last step.';
  }
  dbMoveLastDraw(d.move);
}

/* ==========================================================================
   Move to another database - the wizard (1.0.210)
   Where to → how to reach it → the checks → what happens → moving → done.
   The move is the daemon's one job; its state is kept beside the database, so
   this follows it through the restart and reads its end from the daemon that
   answers on the new database.
   ========================================================================== */
var DBW_ICON = {sqlite: 'archive', mariadb: 'db', postgres: 'db'};
var DBW_RUNNING = ['running', 'switching', 'restarting'];
var DBW_STEP_WORDS = {backup: 'A copy of everything here, first', schema: 'The tables made there',
  copy: 'Every row copied', verify: 'The rows counted there, every sealed secret opened',
  switch: 'config.json switched to it', restart: 'acme started again on it',
  reconnect: 'It answers on the new database'};

/* Why the wizard does not start on a node of a cluster, and how to get there. */
function dbMoveGuardDraw(host, g, compact) {
  if (!host) return;
  clear(host);
  if (!g) return;
  var box = el('div', 'dbw-guard');
  var head = el('div', 'dbw-guard-head');
  var ic = el('span', 'dbw-guard-ic');
  ic.innerHTML = iconMarkup('ethernet', 20);
  head.appendChild(ic);
  head.appendChild(el('b', '', g.stale ? 'This node is still set up as one of a cluster' : 'This node is one of a cluster'));
  box.appendChild(head);
  box.appendChild(el('p', 'note', g.why));
  var ol = el('ol', 'dbw-guard-how');
  (g.how || []).forEach(function (line) { ol.appendChild(el('li', '', line)); });
  box.appendChild(ol);
  if ((g.nodes || []).length) {
    var seen = el('p', 'note small muted');
    seen.appendChild(document.createTextNode('Nodes heard on this database: '));
    seen.appendChild(noI18n(el('span', 'mono', g.nodes.map(function (n) {
      return n.name + (n.alive ? ' (now)' : ' (' + Math.round(n.age / 60) + ' min ago)');
    }).join(', '))));
    box.appendChild(seen);
  }
  var row = el('div', 'btnrow');
  var go = cmdButton('Open High availability', 'ethernet', compact ? 'small' : '');
  go.onclick = function () { closeModal(); showTab('settings'); showPane('ha'); };
  row.appendChild(go);
  box.appendChild(row);
  host.appendChild(box);
}

/* The last move under the button: one going on (follow it), or how it ended. */
function dbMoveLastDraw(m) {
  var host = $('db-move-last');
  if (!host) return;
  clear(host);
  if (!m || !m.id) return;
  var running = DBW_RUNNING.indexOf(m.state) >= 0;
  var cls = running ? 'info' : (m.state === 'done' ? 'good' : 'bad');
  var box = el('div', 'dbw-last ' + cls);
  var words = el('div', 'dbw-last-w');
  var to = (m.to || {}).where || '';
  if (running) words.appendChild(el('b', '', 'A move to another database is going on'));
  else if (m.state === 'done') words.appendChild(el('b', '', 'The last move went through'));
  else if (m.state === 'cancelled') words.appendChild(el('b', '', 'The last move was cancelled'));
  else words.appendChild(el('b', '', 'The last move failed'));
  var line = el('div', 'small');
  line.appendChild(noI18n(el('span', 'mono', ((m.from || {}).where || '') + ' → ' + to)));
  if (m.ended) line.appendChild(noI18n(el('span', 'muted', ' · ' + stamp(m.ended))));
  words.appendChild(line);
  if (m.error) words.appendChild(el('div', 'small', m.error));
  box.appendChild(words);
  var b = cmdButton(running ? 'Follow it' : 'Show it', running ? 'eye' : 'info', 'small');
  b.onclick = function () { dbMoveWizard({follow: true}); };
  box.appendChild(b);
  if (!running) {
    var f = cmdButton('Hide this', 'close', 'small');
    f.onclick = function () { api('db', {action: 'wiz_forget'}).then(function () { clear(host); }).catch(oops); };
    box.appendChild(f);
  }
  host.appendChild(box);
}

function dbMoveWizard(opts) {
  opts = opts || {};
  api('db', {action: 'wiz_start'}).then(function (info) {
    var m = info.move;
    if (opts.follow && m && m.id) { dbMoveRun(info, null, m); return; }
    if (info.guard) {
      modal('Move to another database', function (body) {
        dbMoveGuardDraw(body, info.guard, false);
      }, [{words: 'Close', close: true}], 'medium');
      return;
    }
    if (m && DBW_RUNNING.indexOf(m.state) >= 0) { dbMoveRun(info, null, m); return; }
    dbMoveSteps(info, opts.preset || null);
  }).catch(oops);
}

function dbMoveSteps(info, preset) {
  var here = info.here || {};
  var hs = here.settings || {};
  var W = {step: 0, seen: {0: true}, check: null, checking: false, sure: false, made: '', sql: null};
  var p = preset || {};
  W.d = {engine: p.engine || '', host: p.host || '127.0.0.1', port: p.port || '', name: p.name || 'acme',
         user: p.user || 'acme', password: '', tls: p.tls || '', ca_pem: '', ca_name: p.tls_ca || '',
         path: p.path || '', overwrite: !!p.overwrite, admin_user: '', admin_password: ''};
  if (!W.d.path) W.d.path = here.engine === 'sqlite' && String(here.where) === info.sqlite_default
    ? info.state_dir + '/acme-moved.db' : info.sqlite_default;
  var STEPS = [
    {key: 'where', title: 'Where to', draw: drawWhere, check: function () { return W.d.engine ? '' : 'choose the database to move to'; }},
    {key: 'conn', title: 'Connection', draw: drawConn, check: checkConn},
    {key: 'check', title: 'Check', draw: drawCheck, check: function () {
      if (!W.check) return 'press Check first';
      return W.check.ready ? '' : 'not every check is passed yet: put right what is marked, and check again';
    }},
    {key: 'what', title: 'What happens', draw: drawWhat},
    {key: 'run', title: 'Moving'},
    {key: 'done', title: 'Done'}
  ];
  var read = null;
  function settings() {
    var d = W.d;
    if (d.engine === 'sqlite') return {db_engine: 'sqlite', db_path: d.path.trim()};
    var out = {db_engine: d.engine, db_host: d.host.trim(), db_port: Number(d.port) || info.engines[d.engine].port,
               db_name: d.name.trim(), db_user: d.user.trim(), db_password: d.password,
               db_tls: d.tls, db_tls_ca: d.tls && !d.ca_pem ? d.ca_name : ''};
    return out;
  }
  function body(extra) {
    return Object.assign({settings: settings(), ca_pem: W.d.tls ? W.d.ca_pem : '', overwrite: !!W.d.overwrite}, extra || {});
  }
  function go(to) {
    if (read) read();
    W.step = Math.max(0, Math.min(3, to));
    W.seen[W.step] = true;
    paint();
  }
  function paint() {
    var st = STEPS[W.step];
    read = null;
    var buttons = [];
    if (W.step > 0) buttons.push({words: 'Back', icon: 'prev', left: true, go: function () { go(W.step - 1); }});
    buttons.push({words: 'Close', close: true});
    if (st.key === 'what') {
      buttons.push({words: 'Move it now', cls: 'primary', icon: 'play', go: function (b) { start(b); }});
    } else {
      buttons.push({words: 'Next', cls: 'primary', icon: 'next', go: function () {
        if (read) read();
        var bad = st.check ? st.check() : '';
        if (bad) { toast(bad, 'bad'); return; }
        go(W.step + 1);
      }});
    }
    modal('Move to another database', function (b) {
      b.appendChild(dbMoveRail(STEPS, W.step, W.seen, function (i) {
        if (i > W.step) {
          if (read) read();
          for (var k = W.step; k < i; k++) {
            var bad = STEPS[k].check ? STEPS[k].check() : '';
            if (bad) { toast(bad, 'bad'); return; }
          }
        }
        go(i);
      }));
      var host = el('div', 'dbw-body');
      host.id = 'dbw-step-' + st.key;
      b.appendChild(host);
      st.draw(host);
    }, buttons, 'large');
    if (st.key === 'what') {
      var mv = Array.prototype.filter.call($('modal-foot').querySelectorAll('.btn.primary'), function (x) { return true; })[0];
      if (mv) { mv.id = 'dbw-go'; mv.disabled = !W.sure; }
    }
    explainWhatWasDrawn($('modal-body'));
  }

  /* -- 1. where from, where to -- */
  function drawWhere(host) {
    var from = el('div', 'dbw-here');
    var ic = el('span', 'dbw-tile-ic');
    ic.innerHTML = iconMarkup(DBW_ICON[here.engine] || 'db', 22);
    from.appendChild(ic);
    var w = el('div', 'dbw-here-w');
    w.appendChild(el('span', 'dbw-k', 'Here now'));
    w.appendChild(el('b', '', engineWord(here.engine)));
    w.appendChild(noI18n(el('span', 'mono small', here.where)));
    w.appendChild(el('span', 'small muted', here.version + ' · ' + bytes(here.size) + ' · ' + num(here.rows) + ' row(s)'));
    from.appendChild(w);
    host.appendChild(from);
    var fold = el('details', 'dbw-tables');
    fold.appendChild(el('summary', '', 'The rows of each table'));
    var grid = el('div', 'dbw-tgrid');
    (here.tables || []).forEach(function (t) {
      if (t.table === 'meta') return;
      var r = el('div', 'dbw-trow');
      r.appendChild(el('span', '', TABLE_SAID[t.table] || t.table));
      r.appendChild(noI18n(el('span', 'mono', num(t.rows))));
      grid.appendChild(r);
    });
    fold.appendChild(grid);
    host.appendChild(fold);
    host.appendChild(el('h4', 'dbw-h', 'Move it to'));
    var tiles = el('div', 'dbw-tiles');
    ['sqlite', 'mariadb', 'postgres'].forEach(function (e) {
      var t = el('button', 'dbw-tile' + (W.d.engine === e ? ' on' : ''));
      t.type = 'button';
      t.id = 'dbw-engine-' + e;
      var i2 = el('span', 'dbw-tile-ic');
      i2.innerHTML = iconMarkup(DBW_ICON[e], 22);
      t.appendChild(i2);
      var tw = el('span', 'dbw-tile-w');
      tw.appendChild(el('b', '', (info.engines[e] || {}).words || e));
      tw.appendChild(el('span', 'small', (info.engines[e] || {}).note || ''));
      var chips = el('span', 'dbw-chips');
      if (here.engine === e) chips.appendChild(el('span', 'tag info', e === 'sqlite' ? 'in use - another file' : 'in use - another server'));
      if (e === 'postgres') chips.appendChild(el('span', 'tag ok', 'high availability'));
      var dr = (info.drivers || {})[e];
      if (dr && !dr.ready) chips.appendChild(el('span', 'tag warn', 'driver missing'));
      else if (dr) chips.appendChild(el('span', 'tag dim', 'driver installed'));
      tw.appendChild(chips);
      t.appendChild(tw);
      t.onclick = function () {
        if (W.d.engine !== e) { W.check = null; W.d.overwrite = false; W.d.port = ''; }
        W.d.engine = e;
        Array.prototype.forEach.call(tiles.children, function (x) { x.classList.remove('on'); });
        t.classList.add('on');
        drawDriver();
      };
      t.ondblclick = function () { t.onclick(); go(1); };
      tiles.appendChild(t);
    });
    host.appendChild(tiles);
    var drv = el('div', 'dbw-driver');
    host.appendChild(drv);
    function drawDriver() {
      clear(drv);
      var dr = (info.drivers || {})[W.d.engine];
      if (!dr || dr.ready) return;
      var n = el('div', 'note warn');
      n.appendChild(el('b', '', 'The driver for it is not installed in acme’s Python. Install it, as root:'));
      n.appendChild(dbwCmd(dr.install));
      n.appendChild(el('div', 'small', 'You can go on meanwhile - the check in step 3 tries again.'));
      drv.appendChild(n);
    }
    drawDriver();
  }

  /* -- 2. how to reach it -- */
  function checkConn() {
    var d = W.d;
    if (d.engine === 'sqlite') return /^\/.+\.db$/.test(d.path.trim()) ? '' : 'the file is a full path ending in .db';
    if (!d.host.trim()) return 'the server is needed';
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(d.name.trim())) return 'the database name is letters, digits and _, starting with a letter';
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(d.user.trim())) return 'the account is letters, digits and _, starting with a letter';
    if (d.port && !(Number(d.port) > 0 && Number(d.port) < 65536)) return 'the port is a number up to 65535';
    if (!d.password) return 'its password is needed (or let the wizard make the account: it makes one)';
    if (d.tls === 'verify-full' && !d.ca_pem && !d.ca_name) return 'verify-full needs the authority that signed the server’s certificate';
    return '';
  }
  function drawConn(host) {
    var d = W.d;
    if (d.engine === 'sqlite') {
      host.appendChild(el('p', 'note', 'A file on this machine. acme makes it, and the folder it is in must be one acme may write to - the state folder is.'));
      var path = textBox(d.path, info.sqlite_default, 'mono');
      path.id = 'dbw-path';
      noI18n(path);
      host.appendChild(formField('The file', path, 'A full path ending in .db. If a file of acme is there already - one left by an earlier move - the check says so, and it is thrown away only if you say so.'));
      read = function () { d.path = path.value; };
      return;
    }
    var eng = info.engines[d.engine] || {};
    host.appendChild(el('p', 'note', 'How acme reaches ' + engineWord(d.engine) + '. These go into the config file at the end, and nowhere else.'));
    var g = el('div', 'formgrid');
    var hostBox = textBox(d.host, '127.0.0.1', 'mono'); hostBox.id = 'dbw-host'; noI18n(hostBox);
    hostBox.onchange = function () { if (read) read(); paint(); };
    var port = textBox(d.port, String(eng.port), 'mono'); port.id = 'dbw-port'; noI18n(port);
    var name = textBox(d.name, 'acme', 'mono'); name.id = 'dbw-name'; noI18n(name);
    var user = textBox(d.user, 'acme', 'mono'); user.id = 'dbw-user'; noI18n(user);
    var pw = maskBox(d.password, '', 'mono'); pw.id = 'dbw-password';
    g.appendChild(formField('Server', hostBox, '127.0.0.1 for a server on this machine.'));
    g.appendChild(formField('Port', port, 'Empty: ' + eng.port + ', the usual one.'));
    g.appendChild(formField('Database name', name));
    g.appendChild(formField('Account', user));
    g.appendChild(formField('The account’s password', pw, 'Typed, it shows dots only. Empty: the wizard makes one when it makes the account.'));
    var tls = selectBox([['', 'off'], ['require', 'require - always encrypted'], ['verify-full', 'verify-full - encrypted, the server’s certificate and name checked']], d.tls);
    tls.id = 'dbw-tls';
    g.appendChild(formField('Encryption (TLS)', tls, 'On another machine, require at least: the keys and passwords travel to it. The server needs TLS switched on.'));
    host.appendChild(g);
    var caRow = el('div', 'dbw-ca');
    host.appendChild(caRow);
    var caPick = el('input'); caPick.type = 'file'; caPick.accept = '.pem,.crt,.cer,.txt'; caPick.hidden = true; caPick.id = 'dbw-ca-file';
    host.appendChild(caPick);
    function drawCa() {
      clear(caRow);
      if (tls.value !== 'verify-full') return;
      var line = el('div', 'dbw-ca-line');
      line.appendChild(el('span', '', 'The authority that signed the server’s certificate (PEM):'));
      line.appendChild(noI18n(el('b', 'mono', d.ca_name || '-')));
      var b = cmdButton(d.ca_pem ? 'Another file…' : 'Choose the file…', 'upload', 'small');
      b.onclick = function () { caPick.click(); };
      line.appendChild(b);
      caRow.appendChild(line);
    }
    caPick.onchange = function () {
      var f = caPick.files && caPick.files[0];
      if (!f) return;
      var r = new FileReader();
      r.onload = function () {
        var t = String(r.result || '');
        if (t.indexOf('-----BEGIN CERTIFICATE-----') < 0) { toast('that is not a PEM certificate', 'bad'); return; }
        d.ca_pem = t; d.ca_name = f.name; W.check = null; drawCa();
      };
      r.readAsText(f);
      caPick.value = '';
    };
    tls.onchange = function () { d.tls = tls.value; drawCa(); };
    drawCa();
    read = function () {
      var before = JSON.stringify([d.host, d.port, d.name, d.user, d.password, d.tls]);
      d.host = hostBox.value; d.port = port.value; d.name = name.value; d.user = user.value;
      d.password = pw.value; d.tls = tls.value;
      if (JSON.stringify([d.host, d.port, d.name, d.user, d.password, d.tls]) !== before) W.check = null;
    };
    /* Making the database and the account. */
    var mk = el('div', 'dbw-make');
    mk.appendChild(el('h4', 'dbw-h', 'The database and the account'));
    var said = el('div', 'dbw-make-said');
    var local = ['', 'localhost', '127.0.0.1', '::1'].indexOf(hostBox.value.trim().toLowerCase()) >= 0;
    if (local) {
      mk.appendChild(el('p', 'note', 'The server is on this machine: acme can make the database and the account itself, as root - ' + (d.engine === 'postgres' ? 'as postgres, with no password typed anywhere' : 'as root over its socket, with no password typed anywhere') + '. A password is made for the account if none is typed above.'));
      var b = cmdButton('Make the database and the account for me', 'key', 'primary');
      b.id = 'dbw-make';
      b.onclick = function () {
        read();
        busy(b, true);
        api('db', body({action: 'wiz_make', how: 'local'}), 120).then(function (x) {
          if (x.password) { d.password = x.password; pw.value = x.password; W.made = x.password; }
          W.check = null;
          clear(said);
          (x.made || []).forEach(function (line) { said.appendChild(el('div', 'note good', '✓ ' + line)); });
          if (x.password) said.appendChild(el('div', 'note', 'A password was made for the account and is filled in above. It goes into the config file at the end - nothing has to be noted down.'));
        }).catch(function (e) { clear(said); said.appendChild(el('div', 'note bad', e.message || String(e))); })
          .then(function () { busy(b, false); });
      };
      mk.appendChild(el('div', 'btnrow')).appendChild(b);
      mk.appendChild(said);
    } else {
      mk.appendChild(el('p', 'note', 'On another machine: run this there as its administrator - or let an administrator account of that server do it from here.'));
      var sqlHost = el('div', 'dbw-sql');
      mk.appendChild(sqlHost);
      var show = cmdButton('Show the SQL to run there', 'terminal', '');
      show.id = 'dbw-sql';
      show.onclick = function () {
        read();
        api('db', body({action: 'wiz_sql'})).then(function (x) {
          if (x.password) { d.password = x.password; pw.value = x.password; }
          clear(sqlHost);
          sqlHost.appendChild(el('div', 'small muted', x.run));
          sqlHost.appendChild(dbwCmd(x.sql));
          if (x.also) sqlHost.appendChild(el('p', 'note small', x.also));
          if (x.password) sqlHost.appendChild(el('p', 'note small', 'A password was made for the account: it is in the SQL and filled in above.'));
        }).catch(oops);
      };
      mk.appendChild(el('div', 'btnrow')).appendChild(show);
      var adm = el('details', 'dbw-admin');
      adm.appendChild(el('summary', '', 'Or with an administrator account of that server'));
      var ag = el('div', 'formgrid');
      var au = textBox(d.admin_user, d.engine === 'postgres' ? 'postgres' : 'root', 'mono'); noI18n(au);
      var ap = maskBox('', '', 'mono');
      ag.appendChild(formField('Administrator', au, 'Used for this one connection, kept nowhere.'));
      ag.appendChild(formField('Its password', ap));
      adm.appendChild(ag);
      var ab = cmdButton('Make them with it', 'key', '');
      ab.onclick = function () {
        read();
        busy(ab, true);
        api('db', body({action: 'wiz_make', how: 'admin', admin_user: au.value.trim(), admin_password: ap.value}), 120).then(function (x) {
          if (x.password) { d.password = x.password; pw.value = x.password; }
          W.check = null;
          clear(said);
          (x.made || []).forEach(function (line) { said.appendChild(el('div', 'note good', '✓ ' + line)); });
        }).catch(function (e) { clear(said); said.appendChild(el('div', 'note bad', e.message || String(e))); })
          .then(function () { busy(ab, false); });
      };
      adm.appendChild(el('div', 'btnrow')).appendChild(ab);
      mk.appendChild(adm);
      mk.appendChild(said);
    }
    host.appendChild(mk);
  }

  /* -- 3. the checks -- */
  function runCheck(host) {
    W.checking = true;
    clear(host);
    host.appendChild(el('div', 'note muted', 'Checking…'));
    api('db', body({action: 'wiz_check'}), 90).then(function (x) {
      W.check = x;
      W.checking = false;
      if (x.target && !x.target.rows) W.d.overwrite = false;
      drawChecks(host);
    }).catch(function (e) {
      W.checking = false;
      W.check = null;
      clear(host);
      host.appendChild(el('div', 'note bad', e.message || String(e)));
    });
  }
  function drawCheck(host) {
    var head = el('div', 'dbw-check-head');
    var hw = el('span', 'dbw-check-to');
    hw.appendChild(el('b', '', engineWord(W.d.engine)));
    hw.appendChild(noI18n(el('span', 'mono', ' · ' + (W.d.engine === 'sqlite' ? W.d.path : W.d.user + '@' + W.d.host + ':' + (W.d.port || info.engines[W.d.engine].port) + '/' + W.d.name))));
    head.appendChild(hw);
    var again = cmdButton('Check again', 'refresh', 'small');
    again.id = 'dbw-recheck';
    head.appendChild(again);
    host.appendChild(head);
    var list = el('div', 'dbw-checks');
    host.appendChild(list);
    again.onclick = function () { runCheck(list); };
    if (W.check) drawChecks(list); else runCheck(list);
  }
  function drawChecks(host) {
    clear(host);
    var x = W.check;
    (x.checks || []).forEach(function (r) {
      var row = el('div', 'dbw-check ' + (r.ok === true ? 'ok' : (r.ok === 'warn' ? 'warn' : 'bad')));
      row.appendChild(noI18n(el('span', 'dbw-mark', r.ok === true ? '✔' : (r.ok === 'warn' ? '!' : '✘'))));
      var w = el('div', 'dbw-check-w');
      w.appendChild(el('b', '', r.what));
      if (r.said) w.appendChild(el('span', 'small', r.said));
      if (r.fix && r.ok !== true) {
        var f = el('div', 'dbw-fix');
        f.appendChild(el('b', '', 'What to do: '));
        f.appendChild(el('span', '', r.fix));
        w.appendChild(f);
      }
      row.appendChild(w);
      host.appendChild(row);
    });
    if (x.target && x.target.rows) {
      var box = el('div', 'dbw-over' + (W.d.overwrite ? ' on' : ''));
      box.appendChild(el('b', '', 'It holds acme already'));
      box.appendChild(el('p', 'note', 'A copy left there by an earlier move - the way back, say - can be thrown away and moved over. Everything of acme in it is deleted first; a copy of what is HERE is made in any case. If it is another installation’s database, stop and choose another one: two are never mixed.'));
      var sw = switchBox(W.d.overwrite);
      sw._input.id = 'dbw-overwrite';
      var lab = el('label', 'dbw-over-sw');
      lab.appendChild(sw);
      lab.appendChild(el('span', '', 'Throw away what of acme is in it, and move over it'));
      box.appendChild(lab);
      sw._input.onchange = function () { W.d.overwrite = !!sw._get(); W.sure = false; runCheck(host); };
      host.appendChild(box);
    }
    var sum = el('div', 'note ' + (x.ready ? 'good' : 'bad'), x.ready ? 'Every check is passed: Next says what will happen.' : 'Not ready yet: put right what is marked ✘, then Check again.');
    host.appendChild(sum);
  }

  /* -- 4. what happens -- */
  function drawWhat(host) {
    var x = W.check || {};
    var hereC = (x.here || {}).counts || {};
    var rows = 0;
    Object.keys(hereC).forEach(function (k) { rows += Number(hereC[k] || 0); });
    var est = Number(x.estimate_s || 15);
    host.appendChild(el('p', 'note', 'This is what will be done, in this order. Nothing has been changed yet.'));
    var t = kvTable([
      ['The database now', noI18n(el('span', 'mono', here.where))],
      ['The new database', noI18n(el('span', 'mono', (x.to || {}).where || ''))],
      ['Rows to copy', num(rows) + ' in ' + Object.keys(hereC).length + ' table(s)'],
      ['How long', est < 60 ? 'about ' + est + ' s' : 'about ' + Math.ceil(est / 60) + ' min'],
      ['Meanwhile', 'the pages answer; renewals and deployments wait until it is done; the service is away for a few seconds while it starts again']
    ]);
    t.classList.add('dbw-sum');
    host.appendChild(t);
    var ol = el('ol', 'dbw-plan');
    [['A copy of everything here is made first', 'kept in ' + (x.backup_dir || info.backup_dir) + ', with the key that opens its sealed secrets beside it'],
     ['The tables are made there', W.d.overwrite ? 'what of acme is in it now is thrown away first' : 'in the empty database'],
     ['Every row is copied', 'as one transaction: all of it or nothing'],
     ['It is checked there', 'every table counted against the copy, every sealed secret (keys, passwords) opened with the key'],
     ['The config file is switched to it', x.config_file || info.config_file],
     ['acme starts again on it', 'and this page waits for it, and asks it whether it answers'],
     ['The old database is left exactly as it was', 'it is the way back: the same wizard, the other way, moves back to it']].forEach(function (p) {
      var li = el('li', '');
      li.appendChild(el('b', '', p[0]));
      li.appendChild(noI18n(el('span', 'small muted', ' - ')));
      li.appendChild(el('span', 'small muted', p[1]));
      ol.appendChild(li);
    });
    host.appendChild(ol);
    if (W.d.overwrite) host.appendChild(el('div', 'note bad', 'What of acme is in ' + ((x.to || {}).where || 'it') + ' now is thrown away first.'));
    host.appendChild(el('p', 'note small', 'Cancel stops it at any step until the config file is switched; after that it goes through.'));
    var sw = switchBox(W.sure);
    sw._input.id = 'dbw-sure';
    var lab = el('label', 'dbw-over-sw');
    lab.appendChild(sw);
    lab.appendChild(el('span', '', 'I have read this: move everything now'));
    host.appendChild(lab);
    sw._input.onchange = function () {
      W.sure = !!sw._get();
      if ($('dbw-go')) $('dbw-go').disabled = !W.sure;
    };
  }
  function start(b) {
    if (!W.sure) { toast('say first that you have read it', 'bad'); return; }
    busy(b, true);
    api('db', body({action: 'wiz_go'}), 120).then(function (x) {
      dbMoveRun(info, W, x.move);
    }).catch(function (e) { busy(b, false); oops(e); });
  }
  paint();
}

/* The rail of the steps along the top. */
function dbMoveRail(steps, at, seen, pick) {
  var strip = el('ol', 'dbw-rail');
  steps.forEach(function (s, i) {
    var li = el('li', (i === at ? 'on' : '') + (i < at ? ' done' : ''));
    var b = el('button', '');
    b.type = 'button';
    b.appendChild(el('span', 'n', String(i + 1)));
    b.appendChild(el('span', 'w', s.title));
    b.disabled = !pick || i > 3 || !(seen[i] || i <= at);
    if (pick) b.onclick = function () { pick(i); };
    li.appendChild(b);
    strip.appendChild(li);
  });
  return strip;
}

/* A command or SQL in a box, with Copy. */
function dbwCmd(text) {
  var wrap = el('div', 'dbw-cmd');
  var pre = noI18n(el('pre', 'mono', text));
  wrap.appendChild(pre);
  var c = cmdButton('Copy', 'copy', 'small');
  c.onclick = function () { copyText(text, c); };
  wrap.appendChild(c);
  return wrap;
}

/* -- 5. moving, and 6. done: followed through the restart -- */
function dbMoveRun(info, W, m) {
  var RAIL = [{title: 'Where to'}, {title: 'Connection'}, {title: 'Check'}, {title: 'What happens'}, {title: 'Moving'}, {title: 'Done'}];
  var steps, tables, said, timer = null, ticket, away = 0, lastId = m && m.id;
  function frame(at) {
    modal('Move to another database', function (b) {
      b.appendChild(dbMoveRail(RAIL, at, {}, null));
      var host = el('div', 'dbw-body');
      host.id = at === 4 ? 'dbw-step-run' : 'dbw-step-done';
      b.appendChild(host);
      if (at === 4) {
        said = el('div', 'dbw-run-head');
        host.appendChild(said);
        steps = haLiveSteps(Object.keys(DBW_STEP_WORDS).map(function (k) { return {key: k, what: DBW_STEP_WORDS[k]}; }));
        steps.classList.add('dbw-live');
        host.appendChild(steps);
        tables = el('div', 'dbw-tprog');
        host.appendChild(tables);
      }
    }, [], 'large');
    ticket = modalTicket();
  }
  function foot(list) { haFoot(list); }
  function draw(mv) {
    if (!modalStill(ticket)) return;
    clear(said);
    said.appendChild(noI18n(el('span', 'mono', ((mv.from || {}).where || '') + ' → ' + ((mv.to || {}).where || ''))));
    (mv.steps || []).forEach(function (s) {
      var state = s.state === 'wait' ? 'wait' : s.state;
      steps.set(s.key, state, s.said, s.state === 'bad' ? mv.fix : '');
    });
    clear(tables);
    var copying = (mv.steps || []).filter(function (s) { return s.key === 'copy'; })[0] || {};
    if (copying.state && copying.state !== 'wait') {
      (mv.tables || []).forEach(function (t) {
        if (!t.whole && !t.done) return;
        var r = el('div', 'dbw-tp');
        r.appendChild(el('span', 'dbw-tp-n', TABLE_SAID[t.table] || t.table));
        var bar = el('span', 'dbw-tp-bar');
        var fill = el('span', '');
        var pct = t.whole ? Math.min(100, Math.round(100 * (t.there !== undefined ? t.there : t.done) / t.whole)) : 100;
        fill.style.width = pct + '%';
        bar.appendChild(fill);
        r.appendChild(bar);
        r.appendChild(noI18n(el('span', 'dbw-tp-c mono', num(t.there !== undefined ? t.there : t.done) + ' / ' + num(t.whole))));
        tables.appendChild(r);
      });
    }
    if (mv.state === 'running') {
      foot([{words: 'Close', icon: 'close', left: true, go: function () { stop(); closeModal(); }},
            {key: 'cancel', words: 'Cancel the move', icon: 'cancel', cls: 'danger', go: function (b) {
              busy(b, true);
              api('db', {action: 'wiz_cancel'}).then(function (x) { toast(x.message, 'good'); }).catch(function (e) { busy(b, false); oops(e); });
            }}]);
    } else if (DBW_RUNNING.indexOf(mv.state) >= 0) {
      foot([{words: 'Close', icon: 'close', left: true, go: function () { stop(); closeModal(); }}]);
    }
  }
  function stop() { if (timer) clearTimeout(timer); timer = null; }
  function poll() {
    stop();
    api('db', {action: 'wiz_state'}, 10).then(function (x) {
      away = 0;
      var mv = x.move;
      if (!mv || (lastId && mv.id !== lastId)) {
        if (!modalStill(ticket)) return;
        clear(said); said.appendChild(el('div', 'note bad', 'The move is no longer known here.'));
        foot([{words: 'Close', icon: 'close', go: closeModal}]);
        return;
      }
      if (mv.state === 'done') { stop(); done(mv, x); return; }
      draw(mv);
      if (mv.state === 'failed' || mv.state === 'cancelled') { stop(); ended(mv); return; }
      if (modalStill(ticket)) timer = setTimeout(poll, 1000);
    }).catch(function (e) {
      /* Away while it starts again on the new database: asked again. */
      away += 1;
      if (!modalStill(ticket)) return;
      var r = steps && steps.querySelector('.step.run .d');
      if (r) r.textContent = 'acme is starting again on the new database - waiting for it…';
      if (away > 180) {
        clear(said); said.appendChild(el('div', 'note bad', 'acme has not answered for three minutes: ' + (e.message || e) + '. Look at it on the server: systemctl status acme; journalctl -u acme'));
        foot([{words: 'Close', icon: 'close', go: closeModal}, {words: 'Ask again', icon: 'refresh', cls: 'primary', go: function () { away = 0; poll(); }}]);
        return;
      }
      timer = setTimeout(poll, 1000);
    });
  }
  function ended(mv) {
    var r = el('div', 'note ' + (mv.state === 'cancelled' ? 'warn' : 'bad'));
    r.id = 'dbw-ended';
    r.appendChild(el('b', '', mv.state === 'cancelled' ? 'The move was cancelled. ' : 'The move failed. '));
    r.appendChild(el('span', '', mv.error || ''));
    if (mv.fix) { r.appendChild(el('br')); r.appendChild(el('span', '', mv.fix)); }
    said.parentNode.appendChild(r);
    var list = [{words: 'Close', icon: 'close', left: true, go: function () { closeModal(); loadDb(); }}];
    if (W) list.push({words: 'Back to the checks', icon: 'prev', cls: 'primary', go: function () { W.check = null; dbMoveSteps(info, presetOf(W)); }});
    foot(list);
    loadDb();
  }
  function presetOf(w) {
    var d = w.d;
    return {engine: d.engine, host: d.host, port: d.port, name: d.name, user: d.user, tls: d.tls, tls_ca: d.ca_name, path: d.path};
  }
  function done(mv, x) {
    frame(5);
    var host = $('dbw-step-done');
    var res = mv.result || {};
    var ok = el('div', 'dbw-done');
    var ic = el('span', 'dbw-done-ic');
    ic.innerHTML = iconMarkup('check', 26);
    ok.appendChild(ic);
    var w = el('div', '');
    w.appendChild(el('b', '', 'acme now runs on ' + engineWord(x.engine)));
    w.appendChild(noI18n(el('div', 'mono small', x.where)));
    w.appendChild(el('div', 'small', (res.version || '') + ' · ' + num(res.rows || 0) + ' row(s) · ' + num(((res.sealed || {}).opened) || 0) + ' sealed secret(s) open'));
    ok.appendChild(w);
    host.appendChild(ok);
    var st = haLiveSteps(Object.keys(DBW_STEP_WORDS).map(function (k) { return {key: k, what: DBW_STEP_WORDS[k]}; }));
    st.classList.add('dbw-live');
    (mv.steps || []).forEach(function (s) { st.set(s.key, s.state, s.said); });
    var fold = el('details', 'dbw-steps-fold');
    fold.appendChild(el('summary', '', 'What was done'));
    fold.appendChild(st);
    host.appendChild(fold);
    host.appendChild(el('h4', 'dbw-h', 'What next'));
    var ol = el('ol', 'dbw-plan');
    ['Look around the pages: the certificates, the jobs, the settings - everything is where it was.',
     'The copy made first is kept: ' + (mv.backup || '') + '.',
     'The old database (' + ((mv.from || {}).where || '') + ') is left as it was - keep it until you are sure; then delete the file, or drop that database on its server.'].forEach(function (t) {
      ol.appendChild(el('li', '', t));
    });
    host.appendChild(ol);
    var back = el('div', 'dbw-back');
    back.appendChild(el('b', '', 'Going back'));
    back.appendChild(el('p', 'note', 'The old database is still there: moving back is the same wizard the other way. It holds what was there before this move, so it is thrown away and filled again with what is here now.'));
    host.appendChild(back);
    var from = mv.from || {};
    haFoot([{words: 'Close', icon: 'close', left: true, go: function () { closeModal(); loadDb(); }},
            {key: 'back', words: 'Move back…', icon: 'undo', go: function () {
              api('db', {action: 'wiz_start'}).then(function (inf) {
                dbMoveSteps(inf, {engine: from.engine, host: from.host, port: from.port, name: from.name, user: from.user,
                                  tls: from.tls, tls_ca: from.tls_ca, path: from.path, overwrite: true});
              }).catch(oops);
            }}]);
    loadDb();
  }
  frame(4);
  if (m) draw(m);
  poll();
}

/* ---- the job going on, and the bar that says how far ---------------------- */
var DB_WATCHING = null;
function dbBusyButtons(on) {
  ['db-backup', 'db-dump-make', 'db-optimize', 'db-check', 'db-prune', 'db-tidy',
   'db-restore', 'dump-restore', 'db-move-open', 'erase-go'].forEach(function (id) {
    var b = $(id);
    if (b) b.disabled = on || (id === 'erase-go' && !erasePicked().length)
      || ((id === 'db-restore' || id === 'dump-restore') && !b._held);
  });
}
/* A bar that has finished gets Hide this; one that starts again loses it. */
function goingCloser(box) {
  if (!box || box.querySelector('.hide-row')) return;
  box.appendChild(hideBar(function () { box.hidden = true; }));
}
function goingOpen(box) {
  if (!box) return;
  box.hidden = false;
  var r = box.querySelector('.hide-row');
  if (r) r.remove();
}
function dbWatch(done) {
  if (DB_WATCHING) return;
  DB_WATCHING = true;     /* taken at once (1.0.57): two watchers ran when asked twice in one round trip */
  var box = $('db-going');
  goingOpen(box);
  dbBusyButtons(true);
  var step = function () {
    api('db', {action: 'job'}).then(function (d) {
      var j = d.job || {};
      var pct = j.whole ? Math.min(100, Math.round(100 * j.done / j.whole)) : (j.running ? 5 : 100);
      $('db-going-fill').style.width = pct + '%';
      $('db-going-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '')
        + (j.whole ? ' (' + num(j.done) + ' of ' + num(j.whole) + ')' : '');
      /* Every second while the pane is open; every five once it is left, so
         the job's end is still told and the daemon is not asked for nothing. */
      if (j.running) { DB_WATCHING = setTimeout(step, TAB === 'settings' && PANE === 'db' ? 1000 : 5000); return; }
      DB_WATCHING = null;
      dbBusyButtons(false);
      goingCloser($('db-going'));
      if (j.error) { toast(j.what + ' failed: ' + j.error, 'bad'); $('db-going-says').textContent = j.error; return; }
      var r = j.result || {};
      if (r.rows !== undefined) {
        toast('everything is in ' + r.where + ': ' + num(r.rows) + ' row(s) — now Start using it', 'good');
        $('db-going-says').textContent = 'done: ' + num(r.rows) + ' row(s) in ' + r.where
          + ' · a copy made first: ' + r.copy;
      } else if (r.erased) {
        toast('erased; a copy was made first: ' + r.copy, 'good');
        $('db-going-says').textContent = 'done · a copy made first: ' + r.copy;
      } else if (r.before !== undefined) {
        toast('the disk is given back: ' + bytes(r.before) + ' → ' + bytes(r.after), 'good');
        $('db-going-says').textContent = 'done: ' + bytes(r.before) + ' → ' + bytes(r.after);
      }
      if (done) done(r);
      loadDb();
    }).catch(function (e) { DB_WATCHING = null; dbBusyButtons(false); oops(e); });
  };
  step();
}

/* ---- the disk under it ----------------------------------------------------- */
function drawDisk(d) {
  var host = $('db-disk');
  clear(host);
  var disk = d.disk || {};
  var grew = d.growth || {};
  var cache = d.cache;
  if (cache && cache.low) {
    var slow = el('p', 'note bad');
    slow.appendChild(el('b', '', cache.engine));
    slow.appendChild(document.createTextNode(' keeps '));
    slow.appendChild(el('b', '', bytes(cache.cache)));
    slow.appendChild(document.createTextNode(' of its own in memory ('));
    slow.appendChild(noI18n(el('span', 'mono', cache.setting)));
    slow.appendChild(document.createTextNode(') for a database of '));
    slow.appendChild(el('b', '', bytes(cache.size)));
    slow.appendChild(document.createTextNode('. Its indexes do not fit, so a busy minute waits for the disk. A quarter of the machine’s memory is the usual setting.'));
    host.appendChild(slow);
    if (ADMIN) {
      var go = cmdButton('Tune it for this machine…', 'gear', '');
      go.onclick = openTune;
      host.appendChild(go);
    }
  }
  if (!disk.total) {
    host.appendChild(el('p', 'note', 'The disk this is on could not be measured.'));
    return;
  }
  var share = Number(disk.share || 0);
  var line = el('div', 'disk-bar ' + (share >= 92 ? 'crit' : (share >= 80 ? 'warn' : 'ok')));
  var fill = el('span');
  fill.style.width = Math.max(1, Math.min(100, share)) + '%';
  line.appendChild(fill);
  host.appendChild(line);
  var says = el('p', 'note');
  says.appendChild(el('b', '', bytes(disk.free)));
  says.appendChild(document.createTextNode(' free of ' + bytes(disk.total) + ' on '));
  says.appendChild(noI18n(el('span', 'mono', disk.where || '')));
  says.appendChild(document.createTextNode(' — '));
  says.appendChild(el('span', '', share + '% of it is used'));
  if (grew.a_day) {
    says.appendChild(document.createTextNode(', and this database has been growing '));
    says.appendChild(el('b', '', bytes(grew.a_day)));
    says.appendChild(document.createTextNode(' a day over the last ' + grew.over_days + ' day(s).'));
  } else {
    says.appendChild(document.createTextNode('. How fast it is growing is not known yet: the size is noted once a day, and two are needed.'));
  }
  host.appendChild(says);
  host.appendChild(el('p', 'note', 'That disk holds ' + (disk.holds || '') + '.'));
  if (disk.days_left !== null && disk.days_left !== undefined) {
    host.appendChild(el('p', 'note ' + (disk.days_left < 45 ? 'bad' : ''), disk.days_left > 3650
      ? 'At that rate the disk has years left.'
      : 'At that rate the disk has about ' + num(disk.days_left) + ' day(s) left. Forgetting old records, under the keep-for numbers above, is what shortens it.'));
  }
  var parts = d.parts || [];
  if (parts.length) {
    var wrap = listTable([d.engine !== 'sqlite' ? 'Where' : 'File', 'What it is', {words: 'Size', cls: 'num'}],
      parts, function (one) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono', one.name)));
        tr.appendChild(el('td', 'muted', one.what));
        tr.appendChild(el('td', 'num', bytes(one.bytes)));
        return tr;
      });
    wrap.style.marginTop = '10px';
    host.appendChild(wrap);
  }
}

/* ---- what is in it ----------------------------------------------------------- */
function drawCounts(d) {
  var host = $('db-counts');
  clear(host);
  var rows = (d.tables || []).slice().sort(function (a, b) {
    return (b.bytes || 0) - (a.bytes || 0) || b.rows - a.rows;
  });
  var known = rows.some(function (t) { return t.bytes !== null && t.bytes !== undefined; });
  host.appendChild(listTable(['What', 'Table', {words: 'Rows', cls: 'num'}]
      .concat(known ? [{words: 'Size', cls: 'num'}] : []), rows, function (t) {
    var tr = el('tr');
    tr.appendChild(el('td', '', TABLE_SAID[t.table] || t.table));
    tr.appendChild(noI18n(el('td', 'mono muted small', t.table)));
    tr.appendChild(el('td', 'num', num(t.rows)));
    if (known) tr.appendChild(el('td', 'num', t.bytes === null || t.bytes === undefined ? '–' : bytes(t.bytes)));
    return tr;
  }));
  var key = el('p', 'note ' + (d.key_there ? '' : 'bad'));
  key.appendChild(document.createTextNode(d.key_there ? 'The key that opens the sealed keys: ' : 'The key that opens the sealed keys is MISSING: '));
  key.appendChild(noI18n(el('span', 'mono', d.key)));
  host.appendChild(key);
  if (d.free) {
    host.appendChild(el('p', 'btnhelp', d.engine === 'postgres'
      ? num(d.free) + ' row(s) deleted and not yet given back to the disk.'
      : bytes(d.free) + ' free inside it, which the engine uses again; Give the disk back hands it to the operating system.'));
  }
}

/* ---- the two lists of files kept beside it --------------------------------- */
function keptTable(into, rows, opts) {
  clear(into);
  if (!into || !rows || !rows.length) return;
  var dump = opts.kind === 'dump';
  into.appendChild(el('h4', '', opts.head));
  into.appendChild(listTable(['Name', dump ? 'What it is' : 'Taken off', {words: 'Size', cls: 'num'},
                              'Made', 'Key beside it', {words: '', cls: 'act'}], rows, function (b) {
    var line = el('tr');
    line.appendChild(noI18n(el('td', 'mono', b.name)));
    var came = (dump ? DUMP_SAID[b.kind] : ENGINE_SAID[b.from]) || '';
    var mine = !dump || b.mine !== false;
    var off = el('td', came ? (mine ? '' : 'muted') : 'muted', came || 'not said');
    if (!mine) explain(off, 'This dump was taken off a different engine from the one this '
      + 'installation is on now, so it cannot be put back here. Put that engine back on, or '
      + 'use a copy — a copy goes into any of the three.');
    else if (dump && b.kind === 'copy') explain(off, 'Made on a night when the program that '
      + 'dumps this engine was not on the machine, so a portable copy was made instead. It is '
      + 'a whole copy and goes back into any of the three.');
    line.appendChild(off);
    line.appendChild(el('td', 'num', bytes(b.bytes)));
    line.appendChild(stampCell(b.at));
    line.appendChild(el('td', b.key ? 'good' : 'bad', b.key ? 'yes' : 'no'));
    var act = el('td', 'rowtools');
    if (ADMIN) {
      var take = cmdButton('Download', 'down', 'small');
      explain(take, dump
        ? 'Save this dump to the machine you are sitting at - with the key that opens its sealed keys, '
          + 'locked with a passphrase you give, or without it.'
        : 'Save this copy to the machine you are sitting at - with the key that opens its sealed keys, '
          + 'locked with a passphrase you give, or without it.');
      take.onclick = function () { dbDownloadAsk({name: b.name, kind: dump ? 'dump' : '', key: b.key}); };
      act.appendChild(take);
      var back = cmdButton('Restore', 'undo', 'small danger');
      explain(back, 'Put <b>this</b> one back, without downloading it and uploading it again: '
        + 'everything in the live database is replaced by what is in this file. You are shown '
        + 'what is in it and asked first, and a copy of what is being replaced is made before '
        + 'anything changes.');
      back.disabled = !mine;
      if (mine) back.onclick = function () { restoreKept(b, opts.kind); };
      act.appendChild(back);
      var gone = cmdButton('Delete', 'trash', 'small danger');
      explain(gone, 'Delete this file, and the key beside it, from the server. The live database is not touched.');
      gone.onclick = function () {
        confirmThen(dump ? 'Delete this dump?' : 'Delete this copy?', 'The file ' + htmlText(b.name)
          + ' and the key beside it are deleted from this machine. The live database is '
          + 'not touched, and the others stay where they are.', 'Delete it', function () {
            api('db', {action: 'delete', name: b.name, kind: opts.kind}).then(function (x) {
              toast(x.message, 'good');
              loadDb();
            }).catch(oops);
          });
      };
      act.appendChild(gone);
    }
    line.appendChild(act);
    return line;
  }));
  into.appendChild(el('p', 'btnhelp', opts.where));
}

function dumpCard(d) {
  var says = $('db-dump-says');
  clear(says);
  var info = d.dump || {};
  $('db-dump-now').textContent = info.words || '';
  $('db-dump-make').disabled = false;
  $('db-dump-get').disabled = false;
  if (info.ready) {
    var line = el('p', 'note good');
    line.appendChild(document.createTextNode('Tonight’s will be '));
    line.appendChild(el('b', '', info.words || 'a dump'));
    if (info.suffix) {
      line.appendChild(document.createTextNode(', written as '));
      line.appendChild(noI18n(el('code', '', info.suffix)));
    }
    line.appendChild(document.createTextNode('.'));
    says.appendChild(line);
  } else {
    says.appendChild(el('p', 'note bad', info.why || 'A dump cannot be made on this machine.'));
    var fix = el('p', 'note');
    fix.appendChild(document.createTextNode('Until it is there, the nightly one is made as a portable copy instead — a whole copy, which goes back into any engine, but several times the size of a dump. To have dumps: '));
    fix.appendChild(noI18n(el('code', '', info.install || '')));
    says.appendChild(fix);
  }
}

/* ---- putting one back ------------------------------------------------------- */
function restoreKept(b, kind) {
  api('db', {action: 'restore_kept', name: b.name, kind: kind, check: true}).then(function (d) {
    askBeforeRestoring(d.says, b.name, function () {
      return api('db', {action: 'restore_kept', name: b.name, kind: kind});
    });
  }).catch(oops);
}

function askBeforeRestoring(says, what, go) {
  var n = (says && says.counts) || {};
  var kind = (says && says.kind) || '';
  modal('Put this database back?', function (body) {
    var facts = [['File', noI18n(el('span', 'mono', String(what)))],
                 ['What it is', DUMP_SAID[kind] || kind], ['Size', bytes(says.bytes || 0)],
                 ['Tables', num(says.tables || 0)], ['Accounts', num(n.accounts || 0)],
                 ['Full administrators', num(says.admins || 0)]];
    if (n.certs !== undefined) facts.push(['Certificates', num(n.certs)]);
    if (n.cert_targets !== undefined) facts.push(['Targets', num(n.cert_targets)]);
    if (n.cert_jobs !== undefined) facts.push(['Jobs', num(n.cert_jobs)]);
    if (says.version) facts.push(['Made by acme', says.version]);
    /* Where it was made (1.0.63): the machine's config.json came with it, to
       be read - it is never put back. */
    var m = says.machine || null;
    if (m) {
      var use = m.in_use || {};
      facts.push(['Made on', noI18n(el('span', 'mono', String(m.node || '?') + (m.host ? ' (' + m.host + ')' : '')))]);
      facts.push(['Its database', noI18n(el('span', 'mono', String(use.db_engine || '?')
        + (use.db_engine && use.db_engine !== 'sqlite' ? ' ' + (use.db_host || '') + ':' + (use.db_port || '') + '/' + (use.db_name || '') : '')))]);
      if (use.ha_mode) facts.push(['Its cluster', el('span', 'mono', use.ha_mode + ', slot ' + (use.ha_slot || '?') + ', the other node ' + (use.ha_peer || '?'))]);
    }
    body.appendChild(peekFacts(facts));
    if (m && m.config) {
      var det = el('details', 'note');
      det.appendChild(el('summary', '', 'Its ' + (m.config_file || 'config.json') + ' (only to read: it is not put back)'));
      det.appendChild(noI18n(el('pre', 'mono', JSON.stringify(m.config, null, 1))));
      body.appendChild(det);
    }
    if (kind === 'mariadb' || kind === 'postgres') {
      body.appendChild(el('p', 'note', 'How many records are in a dump is not read from it — that is what putting it back is for.'));
    }
    var warn = el('p', 'note bad');
    warn.textContent = 'Putting it back replaces everything in the live database with what is in that file. A copy of what is being replaced is made first and kept with the others, so this can be undone — but everything recorded since that file was made will only be in that copy.';
    body.appendChild(warn);
    body.appendChild(el('p', 'btnhelp', 'You will probably be signed out: who is signed in came with the file like everything else. The key that opens the sealed keys is taken from beside the file, or from inside a downloaded copy; where there is none, the key in use stays.'));
  }, [
    {words: 'No, leave it', close: true},
    {words: 'Restore it', cls: 'danger', icon: 'undo', close: true, go: function () {
      go().then(function (done) {
        if (done && done.job) { setTimeout(function () { rbRestoreWatch('Putting the database back'); }, 50); return; }
        toast('the database was restored; what it replaced is in ' + done.safety + ' — ' + done.key, 'good');
        setTimeout(function () { window.location.reload(); }, 2500);
      }).catch(oops);
    }}], true);
}

/* A big file goes to /admin/upload/ (1.0.98): there nginx asks whether a
   full administrator sends it before it takes a byte. Where that place is
   not set up (an nginx without auth_request) it answers 404, and the file
   goes the old way. */
var BIG_PATH = true;
function bigFetch(query, file) {
  var opts = {method: 'POST', body: file, credentials: 'same-origin',
              headers: {'X-Acme-Restore': '1', 'Content-Type': 'application/octet-stream'}};
  if (!BIG_PATH) return fetch(query, opts);
  return fetch('/admin/upload/' + query, opts).then(function (r) {
    if (r.status !== 404) return r;
    BIG_PATH = false;
    return fetch(query, opts);
  });
}
function dbSend(file, check) {
  return bigFetch('?api=db-restore' + (check ? '&check=1' : ''), file)
    .then(function (r) {
      return r.json().catch(function () {
        throw new Error('the server did not answer with anything readable (HTTP ' + r.status + ')');
      }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    });
}

/* ---- a copy or a dump with its key (1.0.123) ------------------------------
   Downloaded with the key that opens its sealed keys, locked with a passphrase -
   one file that is all of it - or without it; and the same file put back
   with the passphrase. */
function dbDownloadAsk(o) {
  var what = o.kind === 'dump' ? 'dump' : 'copy';
  modal(o.name ? 'Download ' + o.name : (what === 'dump' ? 'Download a dump made now' : 'Download a copy made now'), function (body) {
    var seg = el('div', 'seg');
    var withB = el('button', 'on', 'With the key'), noB = el('button', '', 'Without the key');
    withB.type = noB.type = 'button';
    seg.appendChild(withB); seg.appendChild(noB);
    body.appendChild(seg);
    var withBox = el('div');
    withBox.appendChild(el('p', 'note', what === 'dump'
      ? 'One file that is all of it: the dump and the key that opens its sealed keys, locked with the passphrase below. Put back here or on another machine (Put a dump back), the passphrase opens the key again. Lost, the key in the file is lost with it - it is not kept anywhere.'
      : 'One file that is all of it: the copy and the key that opens its sealed keys, locked with the passphrase below. Put back here or on another machine (Put a copy back), the passphrase opens the key again. Lost, the key in the file is lost with it - it is not kept anywhere.'));
    var p1 = secretBox('', '10 characters at least', 'mono');
    var p2 = secretBox('', 'the same again', 'mono');
    p1.id = 'dbk-p1'; p2.id = 'dbk-p2';
    var g = el('div', 'formgrid');
    g.appendChild(formField('Passphrase', p1));
    g.appendChild(formField('The passphrase again', p2));
    withBox.appendChild(g);
    body.appendChild(withBox);
    var noBox = el('div');
    noBox.hidden = true;
    noBox.appendChild(el('p', 'note warn', what === 'dump'
      ? 'The dump alone opens no sealed key on another machine: the key is the .key file beside it in /var/lib/acme/dumps (or /var/lib/acme/secrets.key). Keep the two together.'
      : 'The copy alone opens no sealed key on another machine: the key is the .key file beside it in /var/lib/acme/backups (or /var/lib/acme/secrets.key). Keep the two together.'));
    body.appendChild(noBox);
    body._with = true;
    withB.onclick = function () { body._with = true; withB.classList.add('on'); noB.classList.remove('on'); withBox.hidden = false; noBox.hidden = true; };
    noB.onclick = function () { body._with = false; noB.classList.add('on'); withB.classList.remove('on'); withBox.hidden = true; noBox.hidden = false; };
    MODAL_BODY_DBK = body;
  }, [
    {words: 'Cancel', close: true},
    {words: 'Download', cls: 'primary', icon: 'down', go: function (button) {
      var body = MODAL_BODY_DBK;
      if (!body._with) {
        closeModal();
        if (o.now) toast('it is being made; the download starts when it is ready', 'good');
        window.location.href = '?api=db-download' + (o.name ? '&name=' + encodeURIComponent(o.name) : '') + (o.kind === 'dump' ? '&kind=dump' : '');
        return;
      }
      var a = $('dbk-p1').value, b2 = $('dbk-p2').value;
      if (a.length < 10) { toast('a passphrase of 10 characters at least', 'bad'); return; }
      if (a !== b2) { toast('the two passphrases are not the same', 'bad'); return; }
      busy(button, true);
      if (o.now) toast('it is being made; the download starts when it is ready', 'good');
      api('db', {action: 'download_ticket', name: o.name || '', kind: o.kind || '', passphrase: a}).then(function (t) {
        closeModal();
        window.location.href = '?api=db-download&ticket=' + encodeURIComponent(t.ticket);
        toast(t.name + ' - keep the passphrase apart from the file', 'good');
      }).catch(oops).then(function () { busy(button, false); });
    }}]);
}
var MODAL_BODY_DBK = null;
function dbAskPassphrase(d, fileName) {
  modal('The key in ' + fileName, function (body) {
    body.appendChild(el('p', 'note', 'This file holds the database and the key that opens its sealed keys, locked with a passphrase. Give it, and both are put back.'));
    var p = secretBox('', '', 'mono');
    p.id = 'dbk-open';
    body.appendChild(formField('Passphrase', p));
    setTimeout(function () { p.focus(); }, 50);
  }, [
    {words: 'Cancel', close: true},
    {words: 'Open it', cls: 'primary', icon: 'key', go: function (button) {
      var pass = $('dbk-open').value;
      busy(button, true);
      api('db', {action: 'upload_restore', upload: d.upload, passphrase: pass, check: true}).then(function (x) {
        closeModal();
        setTimeout(function () {
          askBeforeRestoring(x.says, fileName + ' (with its key)', function () {
            return api('db', {action: 'upload_restore', upload: d.upload, passphrase: pass});
          });
        }, 30);
      }).catch(oops).then(function () { busy(button, false); });
    }}]);
}
function dropBox(ids, empty) {
  var box = $(ids.drop);
  if (!box) return;
  var go = $(ids.go);
  function picked(file) {
    go._held = file || null;
    var says = $(ids.what);
    clear(says);
    says.hidden = !go._held;
    go.disabled = !go._held;
    $(ids.says).textContent = go._held ? go._held.name + ' · ' + bytes(go._held.size) : empty;
    if (!go._held) return;
    says.appendChild(el('p', 'btnhelp', 'Nothing has happened yet. Press Restore from this file and it will be read first — if it is not one of ours, if it is a dump of a different engine, or if it has no administrator in it, it is refused and nothing here changes.'));
  }
  box.onclick = function () { $(ids.file).click(); };
  $(ids.file).onchange = function () { picked(this.files && this.files[0]); this.value = ''; };
  ['dragenter', 'dragover'].forEach(function (name) {
    box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (name) {
    box.addEventListener(name, function (e) {
      e.preventDefault();
      box.classList.remove('over');
      if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) picked(e.dataTransfer.files[0]);
    });
  });
  go.onclick = function () {
    var held = go._held;
    if (!held) return;
    busy(go, true);
    dbSend(held, true).then(function (d) {
      if (d.upload) { dbAskPassphrase(d, held.name); return; }
      askBeforeRestoring(d.says, held.name, function () { return dbSend(held, false); });
    }).catch(oops).then(function () { busy(go, false); });
  };
}

/* ---- the database server's own settings ---------------------------------- */
function drawTune(d) {
  var host = $('db-tune-says');
  clear(host);
  var t = d.tune || {};
  var file = d.engine === 'sqlite';
  $('db-tune').hidden = file;
  var last = t.last;
  $('db-tune-undo').hidden = file || !last || !!last.undone || last.engine !== d.engine;
  $('db-tune-restart').hidden = true;
  if (file) {
    host.appendChild(el('p', 'note', 'The file on this machine has no server to tune: this program sets it up itself.'));
    return;
  }
  if (last && last.engine === d.engine) {
    var p = el('p', 'note');
    if (last.undone) {
      p.appendChild(document.createTextNode('Put back as it was before'));
      p.appendChild(document.createTextNode(' ' + stamp(last.undone) + (last.undone_by ? ' · ' + last.undone_by : '') + '.'));
    } else {
      p.appendChild(document.createTextNode('Tuned for its machine'));
      p.appendChild(document.createTextNode(' ' + stamp(last.at) + (last.by ? ' · ' + last.by : '') + ':'));
      var set = last.set || {};
      Object.keys(set).sort().forEach(function (n, i) {
        p.appendChild(document.createTextNode(i ? ', ' : ' '));
        p.appendChild(noI18n(el('span', 'mono', n + ' = ' + set[n])));
      });
    }
    host.appendChild(p);
  } else {
    host.appendChild(el('p', 'note', 'Not tuned from this page yet.'));
  }
  if ((t.pending || []).length) {
    var w = el('p', 'note bad');
    w.appendChild(document.createTextNode('Waiting for the server’s next start:'));
    t.pending.forEach(function (n, i) {
      w.appendChild(document.createTextNode(i ? ', ' : ' '));
      w.appendChild(noI18n(el('span', 'mono', n)));
    });
    host.appendChild(w);
    if (t.restart && t.restart.may) {
      $('db-tune-restart').hidden = false;
    } else {
      if (t.restart && t.restart.why) host.appendChild(el('p', 'note', 'This program cannot restart it from here: ' + t.restart.why + '.'));
      host.appendChild(el('p', 'note', 'On the server, as root:'));
      host.appendChild(noI18n(el('pre', 'mono small', 'systemctl restart ' + ((t.restart && t.restart.unit) || 'postgresql'))));
      host.appendChild(el('p', 'btnhelp', 'Or let these pages do it: install.sh --upgrade puts in the rule that lets acme restart PostgreSQL on this machine, and nothing else (--no-db-restart takes it away).'));
    }
  }
  if ((t.lost || []).length) {
    var l = el('p', 'note bad');
    l.appendChild(document.createTextNode('MariaDB has been started again since, and these are back as they were:'));
    t.lost.forEach(function (n, i) {
      l.appendChild(document.createTextNode(i ? ', ' : ' '));
      l.appendChild(noI18n(el('span', 'mono', n)));
    });
    host.appendChild(l);
    host.appendChild(el('p', 'note', 'The file the popup gives keeps them over a restart.'));
  }
}

var TUNE = null;
function tuneAdminBoxes(body, engine) {
  var g = el('div', 'formgrid');
  var who = textBox(TUNE && TUNE.user || '', engine === 'postgres' ? 'postgres' : 'root', '');
  who.autocomplete = 'off';
  who.setAttribute('data-lpignore', 'true');
  var word = maskBox('', '', '');
  word.setAttribute('data-lpignore', 'true');
  word.value = TUNE && TUNE.pass || '';
  g.appendChild(formField('An administrator on that server', who, 'Only where acme’s own account may not change them. Used for this one request and stored nowhere: not in the settings, not in the database, not in any log.'));
  g.appendChild(formField('Its password', word));
  body.appendChild(g);
  return {who: who, word: word};
}
function tuneForget() {
  TUNE = null;
  Array.prototype.forEach.call(document.querySelectorAll('#modal-body input'), function (i) { i.value = ''; });
}
function tuneAsked() {
  var out = {machine: {}};
  if (!TUNE) return out;
  if (TUNE.boxes) { TUNE.user = TUNE.boxes.who.value.trim(); TUNE.pass = TUNE.boxes.word.value; }
  if (TUNE.hw) {
    TUNE.ram = TUNE.hw.ram.value.replace(',', '.').trim();
    TUNE.cpus = TUNE.hw.cpus.value.trim();
    TUNE.disk = TUNE.hw.disk.value;
  }
  if (TUNE.ram) out.machine.ram_gb = TUNE.ram;
  if (TUNE.cpus) out.machine.cpus = TUNE.cpus;
  if (TUNE.disk) out.machine.disk = TUNE.disk;
  out.admin_user = TUNE.user || '';
  out.admin_password = TUNE.pass || '';
  return out;
}
function openTune() {
  TUNE = {user: '', pass: '', ram: '', cpus: '', disk: '', plan: null};
  modal('Tuning the database server for its machine', function (body) {
    body.appendChild(el('p', 'note', 'Reading what the machine has and what the server is set to, and timing a few small writes…'));
  }, [{words: 'Close', close: true}], 'tune');
  MODAL_CLOSE = tuneForget;
  tuneLook();
}
function tuneLook(button) {
  var ask = tuneAsked();
  var ticket = modalTicket();
  if (button) busy(button, true);
  api('db', {action: 'tune_plan', machine: ask.machine}).then(function (d) {
    if (!modalStill(ticket)) return;
    TUNE.plan = d;
    tuneDraw(d);
  }).catch(function (e) {
    if (!modalStill(ticket)) return;
    if (button) busy(button, false);
    oops(e);
  });
}
function tuneValue(v) { return v === null || v === undefined || v === '' ? '–' : String(v); }
function tuneDraw(d, done) {
  var changes = (d.items || []).filter(function (it) { return it.change; });
  var buttons = [
    {words: 'Read again', icon: 'refresh', left: true, go: function (b) { tuneLook(b); }},
    {words: 'Close', close: true}
  ];
  if (changes.length) {
    buttons.splice(1, 0, {words: 'Put it in', cls: 'primary', icon: 'gear', admin: true,
                          go: function (b) { tuneApply(b); }});
  }
  /* What waits for the server's next start, started from here - as isemon
     does - where install.sh let this program restart it. */
  var waiting = (d.items || []).some(function (it) { return it.waiting || it.pending; });
  if (waiting && d.restart && d.restart.may) {
    buttons.splice(1, 0, {words: 'Restart the server…', cls: changes.length ? '' : 'primary',
                          icon: 'power', admin: true, go: function () { tuneRestartAsk(); }});
  }
  modal('Tuning ' + d.words + ' for its machine', function (body) {
    var f = d.facts || {};
    body.appendChild(peekFacts([
      ['Server', String(d.version || d.words).replace(/\s*\(.*\)\s*$/, '')],
      ['Where', d.where],
      ['Database', bytes(d.size)],
      f.ram ? ['Memory', bytes(f.ram)] : null,
      f.avail ? ['Free now', bytes(f.avail)] : null,
      f.cpus ? ['Processors', num(f.cpus)] : null,
      ['Disk', f.disk === 'hdd' ? 'a disk that spins' : 'SSD'],
      f.commit_ms !== null && f.commit_ms !== undefined
        ? ['A write made safe in', Number(f.commit_ms).toFixed(1).replace('.', numDecimal()) + ' ms'] : null,
      d.connections ? ['Connections allowed', num(d.connections)] : null
    ]));
    var from = {'this machine': 'Read from this machine, which the server runs on.',
                'typed': 'As typed below.'}[f.source || ''];
    if (from) body.appendChild(el('p', 'note', from));
    if (f.why && f.why !== 'chosen') body.appendChild(el('p', 'note', 'The disk: ' + f.why));
    if (d.need_facts) {
      body.appendChild(el('p', 'note bad', 'The server is on another machine and what it has could not be read from here. Type its memory and processors below and press Read again.'));
    }
    var row = el('div', 'tune-machine');
    var hw = {};
    [['ram', 'Memory, GB', f.ram ? String(Math.round(f.ram / 1073741824 * 10) / 10) : ''],
     ['cpus', 'Processors', f.cpus ? String(f.cpus) : '']].forEach(function (one) {
      var box = el('div', 'set-item');
      box.appendChild(el('label', '', one[1]));
      var input = el('input');
      input.type = 'text';
      input.inputMode = 'decimal';
      input.value = TUNE[one[0]] || one[2];
      box.appendChild(input);
      row.appendChild(box);
      hw[one[0]] = input;
    });
    var dbox = el('div', 'set-item');
    dbox.appendChild(el('label', '', 'Disk'));
    var sel = selectBox([['ssd', 'SSD'], ['hdd', 'a disk that spins']], TUNE.disk || f.disk || 'ssd');
    dbox.appendChild(sel);
    row.appendChild(dbox);
    hw.disk = sel;
    body.appendChild(row);
    TUNE.hw = hw;
    body.appendChild(el('p', 'btnhelp', 'Change any of these and press Read again: the settings are worked out afresh for what is typed.'));
    if (done) {
      if ((done.done || []).length || (done.later || []).length) {
        body.appendChild(el('p', 'note good', 'Put in: ' + ((done.done || []).join(', ') || 'nothing at once')
          + ((done.later || []).length ? ' · at the next start: ' + done.later.join(', ') : '')));
      }
      if ((done.failed || []).length) body.appendChild(el('p', 'note bad', 'Refused: ' + done.failed.join('; ')));
    }
    if ((d.items || []).length) {
      body.appendChild(el('h4', '', changes.length
        ? 'What would change' : 'Nothing to change: every setting is right for this machine'));
      var wrap = listTable(['Setting', 'Now', 'For this machine', 'Takes', 'Why'], d.items, function (it) {
        var tr = el('tr', it.change ? 'tune-change' : '');
        tr.appendChild(noI18n(el('td', 'mono', it.name)));
        tr.appendChild(noI18n(el('td', 'mono', tuneValue(it.now))));
        var want = el('td', 'mono ' + (it.change ? 'good' : 'muted'));
        want.appendChild(noI18n(el('span', '', tuneValue(it.want))));
        if (it.waiting) { want.appendChild(document.createTextNode(' ')); want.appendChild(el('span', 'tag warn', 'waiting for a start')); }
        tr.appendChild(want);
        tr.appendChild(el('td', it.restart ? 'warn' : 'muted', it.takes));
        tr.appendChild(el('td', 'muted small', it.why));
        return tr;
      }, 'plain tune-table');
      body.appendChild(wrap);
    }
    if (d.engine === 'postgres' && waiting && d.restart && !d.restart.may && d.restart.why) {
      body.appendChild(el('p', 'note bad', 'This program cannot restart it from here: ' + d.restart.why + '.'));
    }
    if (d.engine === 'postgres') {
      body.appendChild(el('p', 'btnhelp', d.restart && d.restart.may
        ? 'What takes effect only at the next start waits for it: Restart the server, under this popup, does that when you say so.'
        : 'What takes effect only at the next start waits for it: on the server, as root, systemctl restart ' + ((d.restart && d.restart.unit) || 'postgresql') + '.'));
    }
    if (d.engine === 'mariadb' && d.cnf) {
      body.appendChild(el('h4', '', 'To keep them over a restart'));
      body.appendChild(el('p', 'note', 'SET GLOBAL lasts until MariaDB is next started, and acme may not write in /etc. Put this in /etc/my.cnf.d/zz-acme-tuning.cnf on the server; the ones marked at the next start take effect only from there.'));
      body.appendChild(noI18n(el('pre', 'mono small', d.cnf)));
    }
    body.appendChild(el('h4', '', 'Who changes them'));
    TUNE.boxes = tuneAdminBoxes(body, d.engine);
  }, buttons, 'tune');
  MODAL_CLOSE = tuneForget;
}
function tuneApply(button) {
  var ask = tuneAsked();
  busy(button, true);
  api('db', {action: 'tune_apply', machine: ask.machine, admin_user: ask.admin_user,
             admin_password: ask.admin_password}).then(function (d) {
    TUNE.plan = d;
    tuneDraw(d, d);
    loadDb();
  }).catch(function (e) { busy(button, false); oops(e); });
}

/* ---- erasing what was collected ----------------------------------------- */
function drawErasable(d) {
  var host = $('erase-list');
  var was = {};
  Array.prototype.forEach.call(host.querySelectorAll('input[type=checkbox]'),
    function (b) { was[b.dataset.group] = b.checked; });
  clear(host);
  $('erase-size').textContent = bytes(d.bytes || 0) + ' in all';
  (d.groups || []).forEach(function (g) {
    var row = el('label', 'erase-one' + (g.rows ? '' : ' empty'));
    var box = document.createElement('input');
    box.type = 'checkbox';
    box.dataset.group = g.key;
    box.checked = !!was[g.key];
    box.disabled = !ADMIN || !g.rows;
    box.onchange = markErase;
    row.appendChild(box);
    var words = el('div', 'erase-words');
    var top = el('div', 'erase-top');
    top.appendChild(el('span', 'erase-name', g.name));
    top.appendChild(el('span', 'tag ' + (g.rows ? 'info' : 'dim'), g.rows ? num(g.rows) + ' row(s)' : 'already empty'));
    words.appendChild(top);
    words.appendChild(el('div', 'erase-says', g.says));
    row.appendChild(words);
    host.appendChild(row);
  });
  markErase();
}
function erasePicked() {
  return Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
    function (b) { return b.checked; }).map(function (b) { return b.dataset.group; });
}
function markErase() {
  var picked = erasePicked();
  var go = $('erase-go');
  go.disabled = !ADMIN || !picked.length || !!DB_WATCHING;
  setButtonIcon(go, 'forget', picked.length ? 'Erase ' + picked.length + ' of these…' : 'Erase what is ticked…');
}

if ($('db-engine-card')) {
  $('db-move-open').onclick = function () { dbMoveWizard(); };

  $('db-backup').onclick = function () {
    busy($('db-backup'), true);
    api('db', {action: 'backup'}).then(function (x) { toast(x.message, 'good'); loadDb(); })
      .catch(oops).then(function () { busy($('db-backup'), false); });
  };
  $('db-download').onclick = function () { dbDownloadAsk({kind: '', now: true, key: true}); };
  $('db-dump-make').onclick = function () {
    busy($('db-dump-make'), true);
    toast('dumping — this takes as long as the database is big');
    api('db', {action: 'dump'}).then(function (d) {
      toast('a dump was made: ' + d.name + ' (' + bytes(d.bytes) + ')', 'good');
      loadDb();
    }).catch(oops).then(function () { busy($('db-dump-make'), false); });
  };
  $('db-dump-get').onclick = function () { dbDownloadAsk({kind: 'dump', now: true, key: true}); };
  $('db-tidy').onclick = function () {
    busy($('db-tidy'), true);
    api('db', {action: 'tidy'}).then(function (x) { toast(x.message, 'good'); loadDb(); })
      .catch(oops).then(function () { busy($('db-tidy'), false); });
  };
  $('db-check').onclick = function () {
    busy($('db-check'), true);
    api('db', {action: 'check'}).then(function (d) {
      modal(d.ok ? 'Nothing in it is broken' : 'Something in it is broken', function (body) {
        var ul = el('ul', 'note');
        (d.said || []).forEach(function (one) { ul.appendChild(noI18n(el('li', 'mono small', one))); });
        body.appendChild(ul);
      }, [{words: 'Close', close: true}], true);
    }).catch(oops).then(function () { busy($('db-check'), false); });
  };
  $('db-optimize').onclick = function () {
    confirmThen('Give the disk back', 'Each table is rebuilt and held shut while it is. In a cluster this node '
      + 'renews nothing meanwhile and the other node does the work; alone, everything waits for it - do it '
      + 'when little is going on. It needs room for a second copy of the biggest table. Worth '
      + 'doing after throwing a lot away, and not otherwise.', 'Give it back',
      function () { api('db', {action: 'give_back'}).then(function () { dbWatch(); }).catch(oops); }, false);
  };
  $('db-prune').onclick = function () {
    var days, everything;
    modal('Forget records older than…', function (body) {
      body.appendChild(el('p', 'note', 'The records of what was done - the jobs and their steps - older than this are '
        + 'deleted now, whatever the keep-for numbers say. The certificates, the accounts, the settings and the events are not touched.'));
      days = el('input'); days.type = 'number'; days.min = 1; days.value = 90;
      body.appendChild(formField('Older than (days)', days));
      everything = switchBox(false);
      everything._input.addEventListener('change', function () { days.disabled = !!everything._get(); });
      body.appendChild(formField('Every line, whatever its age — the whole log emptied', everything));
    }, [{words: 'Close', close: true}, {words: 'Forget them', cls: 'danger', icon: 'forget', go: function (b) {
      busy(b, true);
      api('db', {action: 'prune', days: Number(days.value), everything: !!everything._get()}).then(function (d) {
        toast(d.message, 'good'); closeModal(); loadDb();
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  };
  $('db-tune').onclick = openTune;
  $('db-tune-restart').onclick = function () { tuneRestartAsk(); };
}
function tuneRestartAsk() {
  {
    var unit = ((DBSTATE && DBSTATE.tune && DBSTATE.tune.restart) || {}).unit || 'postgresql';
    modal('Restart ' + unit, function (body) {
      body.appendChild(el('p', 'note', 'PostgreSQL is stopped and started again so that the settings waiting for its next start take effect. It takes a few seconds; the daemon waits for it meanwhile, and what was asked in that moment is done as soon as it is back.'));
      body.appendChild(el('p', 'note', 'Not done when it might not come back: a shared_buffers larger than the memory free now, or huge pages.'));
    }, [{words: 'Not now', close: true}, {words: 'Restart it', cls: 'primary', icon: 'power', go: function (b) {
      busy(b, true);
      api('db', {action: 'tune_restart'}).then(function (d) {
        toast(d.message, 'good'); closeModal(); loadDb();
      }).catch(function (e) { busy(b, false); oops(e); });
    }}], true);
  }
}
if ($('db-tune-undo')) {
  $('db-tune-undo').onclick = function () {
    var user, pass;
    modal('Put back as it was', function (body) {
      body.appendChild(el('p', 'note', 'Every setting this page changed goes back to what it was before. Empty: acme’s own account, where it has that right.'));
      var g = el('div', 'formgrid');
      user = textBox('', DBSTATE && DBSTATE.engine === 'postgres' ? 'postgres' : 'root', '');
      pass = maskBox('', '', '');
      g.appendChild(formField('An administrator on that server', user));
      g.appendChild(formField('Its password', pass, 'Used for this one request; kept nowhere.'));
      body.appendChild(g);
    }, [{words: 'Close', close: true}, {words: 'Put it back', cls: 'primary', icon: 'undo', go: function (b) {
      busy(b, true);
      api('db', {action: 'tune_undo', admin_user: user.value.trim(), admin_password: pass.value}).then(function (d) {
        toast('put back: ' + (d.done || []).join(', '), 'good'); closeModal(); loadDb();
      }).catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
  };
  $('erase-go').onclick = function () {
    var picked = erasePicked();
    if (!picked.length) return;
    var names = Array.prototype.filter.call(document.querySelectorAll('#erase-list input[type=checkbox]'),
      function (b) { return b.checked; }).map(function (b) {
        return b.closest('.erase-one').querySelector('.erase-name').textContent;
      });
    modal(picked.length === 1 ? 'Erase this?' : 'Erase these ' + picked.length + '?', function (body) {
      body.appendChild(el('p', 'note', 'This erases, for good:'));
      var ul = el('ul', 'ask-list');
      names.forEach(function (n) { ul.appendChild(el('li', '', n)); });
      body.appendChild(ul);
      body.appendChild(el('p', 'note', 'The certificates, the accounts and every setting are not touched.'));
      body.appendChild(el('p', 'muted', 'A copy of the database is made first, so this can be undone by restoring it.'));
    }, [{words: 'No, leave it', close: true}, {words: 'Erase it', cls: 'danger', icon: 'forget', close: true, go: function () {
      api('db', {action: 'erase', groups: picked, tidy: $('erase-tidy').checked}).then(function () {
        dbWatch();
      }).catch(oops);
    }}], true);
  };
  dropBox({drop: 'db-drop', file: 'db-file', says: 'db-drop-says', what: 'db-upload-what', go: 'db-restore'},
          'Drop a database file here, or press to choose one');
  dropBox({drop: 'dump-drop', file: 'dump-file', says: 'dump-drop-says', what: 'dump-upload-what', go: 'dump-restore'},
          'Drop a dump here, or press to choose one');
}

/* ---- export and import ---------------------------------------------------- */
/* A certificate downloaded (1.0.191): its format chosen in a window - with its
   private key (PFX, PEM) only locked with a passphrase typed twice. */
var CERT_FORMATS = [
  ['pem', '.crt', 'The certificate', 'PEM - the certificate alone. nginx, Apache, most of Linux.', false],
  ['fullchain', '.pem', 'Certificate and chain', 'PEM - the certificate and the authorities that signed it, one file.', false],
  ['der', '.cer', 'Certificate, binary', 'DER - the certificate alone. Windows, Java, network devices.', false],
  ['p7b', '.p7b', 'Certificate and chain, PKCS#7', 'The certificate with its chain, no key. Windows and IIS import it.', false],
  ['pfx', '.pfx', 'With the private key, PKCS#12', 'The certificate, its chain and its private key in one file locked with a password. Windows, IIS, Exchange, Azure, browsers.', true],
  ['pemkey', '.pem', 'With the private key, PEM', 'The certificate, its chain and its private key locked with a passphrase (PKCS#8, AES-256).', true]
];
function certExport(target, prof) {
  var info = prof.info || {};
  var st = {kind: 'pfx', legacy: false};
  modal('Download the certificate of ' + webTargetWords(target), function (body) {
    if (info.subject) body.appendChild(el('p', 'muted small', info.subject + (info.not_after ? ' · until ' + stamp(info.not_after) : '')));
    var list = el('div', 'fmt-list');
    var keyBox = el('div', 'fmt-key');
    var draw = function () {
      list.querySelectorAll('.fmt').forEach(function (b) { b.classList.toggle('on', b.dataset.kind === st.kind); b.setAttribute('aria-checked', b.dataset.kind === st.kind ? 'true' : 'false'); });
      var f = CERT_FORMATS.filter(function (x) { return x[0] === st.kind; })[0];
      keyBox.hidden = !f[4];
      $('cx-legacy-row').hidden = st.kind !== 'pfx';
    };
    CERT_FORMATS.forEach(function (f) {
      var b = el('button', 'fmt' + (f[4] ? ' with-key' : ''));
      b.type = 'button';
      b.dataset.kind = f[0];
      b.setAttribute('role', 'radio');
      b.appendChild(el('span', 'fmt-ext', f[1]));
      var t = el('span', 'fmt-text');
      t.appendChild(el('b', '', f[2]));
      t.appendChild(el('span', 'fmt-says', f[3]));
      if (f[4]) t.appendChild(el('span', 'tag warn', 'private key'));
      b.appendChild(t);
      b.onclick = function () { st.kind = f[0]; draw(); };
      list.appendChild(b);
    });
    body.appendChild(list);
    keyBox.appendChild(el('p', 'note warn', 'The private key leaves this machine. Whoever holds the file and its password can be ' + webTargetWords(target) + '. The download, and by whom, goes into Events.'));
    var p1 = secretBox('', '10 characters at least', 'mono');
    var p2 = secretBox('', 'the same again', 'mono');
    p1.id = 'cx-p1'; p2.id = 'cx-p2';
    p1.autocomplete = p2.autocomplete = 'new-password';
    var g = el('div', 'formgrid');
    g.appendChild(formField('Password of the file', p1));
    g.appendChild(formField('The password again', p2));
    keyBox.appendChild(g);
    var lg = switchBox(false);
    lg._input.onchange = function () { st.legacy = !!lg._get(); };
    var row = formField('For older Windows', lg, 'Windows before 10 (1709) and Server 2016 open no AES-protected PFX: 3DES then, as they need.');
    row.id = 'cx-legacy-row';
    keyBox.appendChild(row);
    body.appendChild(keyBox);
    draw();
  }, [
    {words: 'Cancel', close: true},
    {words: 'Download', cls: 'primary', icon: 'download', go: function (button) {
      var f = CERT_FORMATS.filter(function (x) { return x[0] === st.kind; })[0];
      var req = {action: 'tls_export', target: target, kind: st.kind};
      if (f[4]) {
        var a = $('cx-p1').value, b2 = $('cx-p2').value;
        if (a.length < 10) { toast('a password of 10 characters at least', 'bad'); $('cx-p1').focus(); return; }
        if (a !== b2) { toast('the two passwords are not the same', 'bad'); $('cx-p2').focus(); return; }
        req.passphrase = a;
        req.legacy = st.legacy;
      }
      busy(button, true);
      api('web', req).then(function (x) {
        var raw = atob(x.file), bytes = new Uint8Array(raw.length);
        for (var i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
        var a2 = el('a');
        a2.href = URL.createObjectURL(new Blob([bytes], {type: x.type || 'application/octet-stream'}));
        a2.download = x.name;
        document.body.appendChild(a2);
        a2.click();
        setTimeout(function () { URL.revokeObjectURL(a2.href); a2.remove(); }, 500);
        closeModal();
        toast(x.name + (f[4] ? ' - keep its password apart from the file' : ''), 'good');
      }).catch(oops).then(function () { busy(button, false); });
    }}], 'medium');
}
function saveFile(name, text) {
  var a = el('a');
  a.href = URL.createObjectURL(new Blob([text], {type: 'application/json'}));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
$('ex-plain').onclick = function () {
  api('export').then(function (d) { saveFile('acme-config-' + Date.now() + '.json', JSON.stringify(d.config, null, 2)); }).catch(oops);
};
$('ex-whole').onclick = function () {
  confirmThen('Export with the secrets', 'The shared secrets of the clients, the passwords of the directories and of the mail server, the password hashes of the accounts and the private keys of the certificates go into the file - locked with a passphrase made now and shown once. The file opens only with it.',
    'Export them', function () {
      /* Locked with a passphrase (1.0.136), as the cluster's bundle is. */
      api('export&secrets=1').then(function (d) {
        saveFile('acme-config-complete-locked-' + Date.now() + '.json', JSON.stringify(d.bundle, null, 2));
        modal('The passphrase of the file', function (body) {
          body.appendChild(el('p', 'note', 'The file opens only with this passphrase - it is not shown again and not kept here. Write it down apart from the file.'));
          body.appendChild(el('p', '', '')).appendChild(copyOnClick(noI18n(el('span', 'keytext', d.passphrase)), d.passphrase, 'the passphrase was copied'));
        }, [{words: 'Close', close: true}], 'small');
      }).catch(oops);
    });
};
$('ex-load').onclick = function () { $('ex-file').click(); };
$('ex-file').onchange = function () {
  var f = this.files && this.files[0];
  this.value = '';
  if (!f) return;
  f.text().then(function (t) {
    var conf;
    /* Not the browser's own words for broken JSON (1.0.103). */
    try { conf = JSON.parse(t); } catch (e) { toast('the file is not JSON - is it the right file?', 'bad'); return; }
    if (!conf || typeof conf !== 'object' || Array.isArray(conf)) { toast('the file is not JSON - is it the right file?', 'bad'); return; }
    // A file of acme --export-config holds it under "config" (1.0.62).
    if (conf && conf.config && typeof conf.config === 'object') conf = conf.config;
    var locked = conf && conf.kind === 'acme-config-locked';
    var phrase = null;
    modal('Import ' + f.name, function (body) {
      if (locked) {
        body.appendChild(el('p', 'note', 'Exported with the secrets, it is locked: the passphrase shown when it was exported opens it.'));
        phrase = textBox('', 'the passphrase', 'mono');
        phrase.type = 'password';
        noI18n(phrase);
        body.appendChild(formField('Passphrase', phrase));
      }
      body.appendChild(el('p', 'note', 'Directories and accounts of the same name are replaced; the settings, the certificates, the VIP address, who may reach the pages, the firewall and the mail server\'s authorities in it are saved. Your own account is left as it is.'));
      body.appendChild(el('p', 'note', 'Add to what is here: anything not in the file stays. Exactly the file: directories and accounts not in it are taken away, and settings not in it go back to their defaults - as when a whole configuration is put back.'));
    }, [{words: 'Close', close: true},
        {words: 'Exactly the file', cls: 'danger', icon: 'upload', close: true, go: function () {
          api('import', {config: conf, replace: true, passphrase: phrase ? phrase.value : ''}).then(function (d) { toast(d.message, 'good'); loadSettings(); }).catch(oops);
        }},
        {words: 'Add to what is here', cls: 'primary', icon: 'upload', close: true, go: function () {
          api('import', {config: conf, passphrase: phrase ? phrase.value : ''}).then(function (d) { toast(d.message, 'good'); loadSettings(); }).catch(oops);
        }}], 'medium');
  }).catch(oops);
};

/* ---- about ---------------------------------------------------------------- */
function drawAbout() {
  var s = STATUS || {};
  var host = $('about-state');
  clear(host);
  host.appendChild(el('h2', '', 'acme ' + (s.version || '')));
  host.appendChild(el('p', 'note', 'Certificates kept, renewed and put in place by themselves: Let\'s Encrypt and any other ACME CA, authorities of its own, MS AD CS and SCEP; put onto Linux over SSH, F5, NetScaler, MikroTik, FortiGate and more.'));
  host.appendChild(peekFacts([['Running for', span(s.uptime || 0)], ['Directories', num(s.directories)],
                              ['Database', ({sqlite: 'SQLite', mariadb: 'MariaDB', postgres: 'PostgreSQL'})[(s.database || {}).engine] || (s.database || {}).engine]]));
  host.appendChild(el('p', 'muted small', 'The daemon (/usr/local/lib/acme/acme.py and acmelib), the standard library, and these PHP pages that ask it. On the server: acme --help.'));
  if (ADMIN) drawConsoleLogin(host);
  drawSoftware(host);
}

/* The acme console when root signs in at the console or over SSH (1.0.141):
   a switch a node; the node's own root helper writes it. */
function drawConsoleLogin(host) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'The console at login'));
  box.appendChild(el('p', 'note', 'On: root signing in at the machine\'s console or over SSH lands in the acme console (acme --console); q leaves it for the shell. Off: the ordinary shell, and acme --console opens it. Commands run over SSH, scp and sftp never get it. On the server: acme --console-at-login on|off.'));
  var list = el('div', '');
  box.appendChild(list);
  var tries = 0;
  function load() {
    api('console-login').then(function (d) {
      clear(list);
      var waiting = false;
      (d.nodes || []).forEach(function (n) {
        var row = el('div', 'kv-row');
        row.style.cssText = 'display:flex;align-items:center;gap:10px;margin:8px 0;flex-wrap:wrap';
        var sw = switchBox(!!n.on);
        sw._input.disabled = n.on === null || n.on === undefined || n.pending;
        var name = noI18n(el('b', '', n.name));
        row.appendChild(sw);
        row.appendChild(name);
        if (n.me) row.appendChild(el('span', 'tag info', 'this one'));
        /* The switch says on or off itself (1.0.148): words only when it cannot. */
        var said = n.pending ? 'being switched…' : (n.on === null || n.on === undefined) ? 'not said yet - the node says within a minute' : '';
        if (said) row.appendChild(el('span', 'muted small', said));
        if (n.error) row.appendChild(el('p', 'note bad', n.error));
        if (n.pending) waiting = true;
        /* The switch only says what it will be; the save bar at the bottom
           does it (1.0.147), as with every other setting. */
        var key = 'console-login:' + n.name;
        if (PENDING[key] && !sw._input.disabled) {      /* drawn again, still not saved */
          sw._input.checked = PENDING[key].on;
          row.classList.add('changed');
        }
        sw._input.onchange = function () {
          var on = sw._input.checked;
          row.classList.toggle('changed', on !== !!n.on);
          if (on === !!n.on) { delete PENDING[key]; markDirtyCount(); return; }
          pendingSet(key, {pane: 'about', on: on, save: function () {
            return api('console-login', {node: n.name, on: on}).then(function (r) {
              toast(r.message, 'good'); tries = 0; setTimeout(load, 2000);
              return true;
            });
          }, reset: function () { sw._input.checked = !!n.on; row.classList.remove('changed'); }});
        };
        list.appendChild(row);
      });
      if (waiting && tries++ < 30) setTimeout(load, 2000);
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'note bad', String((e && e.message) || e))); });
  }
  load();
}

/* What every node runs on (1.0.99): acme, Python and its modules, the
   libraries under them, the pages' PHP and its extensions, nginx and the
   rest beside it - a column a node, what differs between them marked. */
function drawSoftware(host) {
  var box = el('div', 'sw-box');
  host.appendChild(box);
  box.appendChild(el('h3', 'sw-h', 'What it runs on'));
  var wait = el('p', 'muted small', 'asking…');
  box.appendChild(wait);
  api('software').then(function (d) {
    box.removeChild(wait);
    var nodes = d.nodes || [];
    var pages = d.pages || {};
    var sw = function (n, f) { var x = n.software || {}; return f(x) || ''; };
    var prog = function (k) { return function (x) { return (x.programs || {})[k]; }; };
    var mod = function (k) { return function (x) { return (x.modules || {})[k] || ''; }; };
    var rows = [
      ['acme', function (x) { return x.acme; }],
      ['group:Python'],
      ['Python', function (x) { return x.python; }],
      ['where', function (x) { return x.python_path; }],
      ['psycopg2 (PostgreSQL)', mod('psycopg2')],
      ['PyMySQL (MariaDB)', mod('pymysql')],
      ['colorama', mod('colorama')],
      ['OpenSSL (Python’s)', function (x) { return x.openssl; }],
      ['SQLite (library)', function (x) { return x.sqlite; }],
      ['group:The database'],
      ['server', function (x) { return x.database; }],
      ['pg_dump', prog('pg_dump')],
      ['mariadb-dump', prog('mariadb-dump')],
      ['group:The pages'],
      ['nginx', prog('nginx')],
      ['php-fpm', prog('php-fpm')],
      ['PHP (command line)', function (x) { return x.php_cli; }],
      ['group:The system'],
      ['system', function (x) { return x.os; }],
      ['kernel', function (x) { return x.kernel + (x.arch ? ' · ' + x.arch : ''); }],
      ['systemd', prog('systemd')],
      ['OpenSSL (system)', prog('openssl')],
      ['keepalived', prog('keepalived')],
      ['iptables', prog('iptables')],
      ['firewalld', prog('firewalld')]
    ];
    var t = el('table', 'rows sw-table');
    var th = el('thead'), hr = el('tr');
    hr.appendChild(el('th', '', ''));
    nodes.forEach(function (n) {
      var c = el('th', '');
      c.appendChild(noI18n(el('span', '', n.name)));
      if (n.me) c.appendChild(el('span', 'tag info', 'this one'));
      else if (!n.alive) c.appendChild(el('span', 'tag warn', 'not heard from'));
      hr.appendChild(c);
    });
    th.appendChild(hr); t.appendChild(th);
    var tb = el('tbody');
    rows.forEach(function (r) {
      var tr = el('tr');
      if (r[0].indexOf('group:') === 0) {
        tr.className = 'sw-group';
        var g = el('td', '', r[0].slice(6));
        g.colSpan = nodes.length + 1;
        tr.appendChild(g);
        tb.appendChild(tr);
        return;
      }
      var vals = nodes.map(function (n) { return sw(n, r[1]); });
      if (!vals.some(function (v) { return v; })) return;     /* nowhere: not shown */
      var differs = nodes.length > 1 && vals.some(function (v) { return v !== vals[0]; });
      tr.appendChild(el('td', 'k', r[0]));
      vals.forEach(function (v) {
        var c = noI18n(el('td', 'mono small' + (differs ? ' warn' : ''), v || '–'));
        if (differs) c.title = 'not the same on every node';
        tr.appendChild(c);
      });
      tb.appendChild(tr);
    });
    t.appendChild(tb);
    box.appendChild(t);
    /* The pages: this PHP itself, as php-fpm runs it for the node that
       answered this page. */
    if (pages.php) {
      box.appendChild(el('h3', 'sw-h', 'The pages’ PHP (as php-fpm runs it here)'));
      box.appendChild(peekFacts([['PHP', pages.php], ['How', pages.sapi], ['OPcache', pages.opcache ? 'on' : 'off'],
                                 ['Web server', pages.server || '–']]));
      var ex = el('div', 'sw-ext');
      Object.keys(pages.extensions || {}).forEach(function (k) {
        var v = pages.extensions[k];
        ex.appendChild(noI18n(el('span', 'tag namepill', k + (v ? ' ' + v : ''))));
      });
      box.appendChild(el('div', 'muted small', 'Its extensions (' + num(Object.keys(pages.extensions || {}).length) + '):'));
      box.appendChild(ex);
    }
    explainWhatWasDrawn(box);
  }).catch(function (e) { wait.textContent = String(e.message || e); });
}

/* ---- a directory's groups, searched and picked (isemon's list) ----------- */
/** opts: {dir: () => directory name, buttons: [{words, icon, on(g), toggle(g)}]} -
    a box to type part of a name into, Find the groups, and the list with a
    button per role beside every group, lit where the group has it. */
function groupBrowser(opts) {
  var box = el('div', 'groupbrowser');
  var bar = el('div', 'btnrow');
  bar.style.alignItems = 'center';
  var like = el('input');
  like.type = 'search';
  like.placeholder = 'part of a group’s name (empty: all)';
  like.style.maxWidth = '420px';
  like.style.minWidth = '320px';
  var go = cmdButton('Find the groups', 'search', 'small');
  bar.appendChild(like);
  bar.appendChild(go);
  box.appendChild(bar);
  var list = el('div');
  list.style.marginTop = '10px';
  box.appendChild(list);
  var st = {groups: [], q: '', page: 0, per: 15};
  function paint() {
    Array.prototype.forEach.call(list.querySelectorAll('tr.dgroup'), function (tr) {
      var any = false;
      opts.buttons.forEach(function (b, i) {
        var on = !!b.on(tr._g);
        any = any || on;
        var btn = tr.querySelectorAll('.rowtools .btn')[i];
        if (btn) btn.classList.toggle('on', on);
      });
      tr.classList.toggle('is-read', any);
    });
  }
  function draw() {
    clear(list);
    if (!st.groups.length) { list.appendChild(el('p', 'note', 'The directory has no groups under that base matching that.')); return; }
    var low = st.q.toLowerCase();
    var rows = !low ? st.groups : st.groups.filter(function (g) {
      return (g.cn + ' ' + g.dn + ' ' + (g.description || '')).toLowerCase().indexOf(low) >= 0;
    });
    var fb = el('div', 'btnrow');
    fb.style.alignItems = 'center';
    var f = el('input');
    f.type = 'search';
    f.placeholder = 'narrow this list…';
    f.value = st.q;
    f.style.maxWidth = '420px';
    f.style.minWidth = '320px';
    f.oninput = function () {
      st.q = f.value; st.page = 0;
      var at = f.selectionStart;
      draw();
      var again = list.querySelector('input[type=search]');
      if (again) { again.focus(); try { again.setSelectionRange(at, at); } catch (e) { } }
    };
    fb.appendChild(f);
    fb.appendChild(el('span', 'muted small', num(rows.length) + ' of ' + num(st.groups.length)));
    list.appendChild(fb);
    var pages = Math.max(1, Math.ceil(rows.length / st.per));
    if (st.page >= pages) st.page = pages - 1;
    list.appendChild(listTable(['Group', 'What it is for', ''], rows.slice(st.page * st.per, st.page * st.per + st.per), function (g) {
      var tr = el('tr', 'dgroup');
      tr._g = g;
      var n = el('td');
      n.appendChild(noI18n(el('div', '', g.cn)));
      n.appendChild(noI18n(el('div', 'mono small muted', g.dn)));
      tr.appendChild(n);
      tr.appendChild(noI18n(el('td', 'muted small', g.description || '')));
      var t = el('td', 'rowtools');
      opts.buttons.forEach(function (b) {
        var btn = cmdButton(b.words, b.icon, 'small');
        btn.onclick = function (e) { e.stopPropagation(); b.toggle(g); paint(); };
        t.appendChild(btn);
      });
      tr.appendChild(t);
      return tr;
    }, 'rows'));
    if (pages > 1) {
      var nav = el('div', 'btnrow');
      nav.style.marginTop = '8px';
      var prev = cmdButton('Back', 'prev', 'small');
      prev.disabled = st.page === 0;
      prev.onclick = function () { st.page--; draw(); };
      var next = cmdButton('Next', 'next', 'small');
      next.disabled = st.page >= pages - 1;
      next.onclick = function () { st.page++; draw(); };
      nav.appendChild(prev);
      nav.appendChild(el('span', 'muted small', 'page ' + (st.page + 1) + ' of ' + pages));
      nav.appendChild(next);
      list.appendChild(nav);
    }
    paint();
    explainWhatWasDrawn(list);
  }
  function find() {
    var d = opts.dir();
    if (!d) { toast('choose the directory first', 'bad'); return; }
    busy(go, true);
    api('directories', {action: 'groups', name: d, like: like.value.trim()}).then(function (r) {
      st.groups = r.groups || []; st.q = ''; st.page = 0;
      draw();
      toast(num(st.groups.length) + ' group(s) found', 'good');
    }).catch(function (e) {
      /* The groups of the directory asked before must not stay to be added
         to a role of another one (1.0.36). */
      st.groups = []; st.q = ''; st.page = 0; draw(); oops(e);
    }).then(function () { busy(go, false); });
  }
  go.onclick = find;
  like.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); find(); } });
  box._paint = paint;
  return box;
}

/* ---- the certificate authority of a directory (as isemon) --------------- */
var DIRS = [];
function caDir() {
  var pick = $('ca-dir');
  var id = pick ? String(pick._get ? pick._get() : pick.value) : '';
  return DIRS.filter(function (x) { return String(x.id) === id; })[0] || DIRS[0];
}
function drawCaPick() {
  var host = $('ca-pick');
  if (!host) return;
  var was = $('ca-dir') ? String($('ca-dir')._get ? $('ca-dir')._get() : $('ca-dir').value) : '';
  clear(host);
  $('ca-card').hidden = !DIRS.length;
  if (!DIRS.length) return;
  var pick = selectBox(DIRS.map(function (x) { return [String(x.id), x.name]; }),
                       was && DIRS.some(function (x) { return String(x.id) === was; }) ? was : String(DIRS[0].id));
  pick.id = 'ca-dir';
  pick.addEventListener('change', drawCaState);
  if (DIRS.length > 1) host.appendChild(formField('For the directory', pick));
  else { pick.hidden = true; host.appendChild(pick); }
  drawCaState();
}
function drawCaState() {
  var d = caDir();
  var host = $('ca-state');
  if (!host || !d) return;
  clear(host);
  var list = d.ca_list || [];
  $('ca-when').textContent = list.length ? num(list.length) + ' certificate(s) kept' : 'none imported';
  $('ca-drop').hidden = !list.length;
  if (!list.length) {
    host.appendChild(el('p', 'note', 'Nothing is imported for ' + d.name + ', so the domain '
      + 'controllers’ certificates have to be signed by an authority this machine already '
      + 'trusts' + (d.tls === 'none' ? ' - and plain LDAP checks no certificate at all.' : '.')));
    return;
  }
  host.appendChild(el('p', 'note', 'Every certificate kept for ' + d.name + ' is trusted for its domain controllers - '
    + 'one chain for each domain or authority they come from. Each can be taken out by itself.'));
  host.appendChild(certTable(list, function (c) {
    confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate') + '</b> is no longer trusted for '
      + htmlText(d.name) + '. The others stay.', 'Take it out', function () {
        api('directories', {action: 'ca', id: d.id, mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
          toast(r.message, 'good'); loadDirs();
        }).catch(oops);
      });
  }));
}
/** Kept certificates as a table: who, signed by whom, from when to when, the
    whole fingerprint, and a button to take each out (1.0.20: shared by the
    directories and the mail server). */
function certTable(list, drop) {
  return listTable(['It is', 'Signed by', 'Good from', 'Good until', 'Fingerprint (SHA-256)', ''], list, function (c) {
    var tr = el('tr');
    tr.appendChild(noI18n(el('td', '', c.subject || '–')));
    var by = el('td');
    if (c.self_signed) by.appendChild(el('span', 'tag info', 'itself - a root'));
    else by.appendChild(noI18n(el('span', '', c.issuer || '–')));
    tr.appendChild(by);
    var when = function (t) { var ms = Date.parse(t || ''); return isNaN(ms) ? (t || '–') : dayWords(new Date(ms)); };
    tr.appendChild(el('td', 'muted small', when(c.from)));
    var left = c.until ? (Date.parse(c.until) - Date.now()) / 86400000 : null;
    var tone = left === null || isNaN(left) ? '' : (left < 0 ? 'bad' : (left < 60 ? 'warn' : 'good'));
    tr.appendChild(el('td', 'small ' + tone, when(c.until)));
    var fp = noI18n(el('td', 'mono small muted fp-full'));
    var hex = (c.fingerprint || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();
    var half = Math.ceil(hex.length / 4) * 2;
    [hex.slice(0, half), hex.slice(half)].forEach(function (part) {
      if (part) fp.appendChild(el('div', '', part.replace(/(..)(?=.)/g, '$1:')));
    });
    fp.title = hex.replace(/(..)(?=.)/g, '$1:');
    tr.appendChild(fp);
    var tools = el('td', 'rowtools');
    if (ADMIN && drop) {
      var x = iconButton('trash', 'Take this certificate out');
      x.onclick = function () { drop(c); };
      tools.appendChild(x);
    }
    tr.appendChild(tools);
    return tr;
  });
}
/** A certificate file read into a box: PEM as it is, a DER .cer written out as PEM. */
function readCertFile(file, box) {
  var reader = new FileReader();
  reader.onload = function () {
    var bytes = new Uint8Array(reader.result || new ArrayBuffer(0));
    var text = '';
    try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) { text = ''; }
    if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0 && bytes.length && bytes[0] === 0x30) {
      var bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      text = '-----BEGIN CERTIFICATE-----\n' + btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
        + '\n-----END CERTIFICATE-----';
    }
    var ok = text.indexOf('-----BEGIN CERTIFICATE-----') >= 0;
    box.value = ok ? text.trim() : '';
    box.dispatchEvent(new Event('input'));
    toast(ok ? 'read ' + file.name + ' - Save the changes adds it' : file.name + ' is not a certificate', ok ? 'good' : 'bad');
  };
  reader.readAsArrayBuffer(file);
}
/** The box to paste one into is always there: what is added joins the ones
    kept rather than replacing them (1.0.11). */
if ($('ca-save')) {
  var caSend = function (pem, done, dirId) {
    var d = dirId !== undefined ? DIRS.filter(function (x) { return String(x.id) === String(dirId); })[0] : caDir();
    if (!d) return Promise.resolve();
    return api('directories', {action: 'ca', id: d.id, ca: pem, mode: pem ? 'add' : 'clear'}).then(function (r) {
      toast(r.message, 'good');
      if (done) done();
      loadDirs();
    }).catch(oops);
  };
  $('ca-save').onclick = function () {
    var pem = $('ca-pem').value.trim();
    if (!pem) { toast('paste the certificate first, or read it from a file', 'bad'); return; }
    busy($('ca-save'), true);
    /* The button comes back when the daemon has answered, not on a timer:
       a slow import could be pressed twice (1.0.15). */
    caSend(pem, function () { $('ca-pem').value = ''; }).then(function () { busy($('ca-save'), false); });
  };
  /* Pasted or read, it waits for the save bar (1.0.56). */
  $('ca-save').hidden = true;
  $('ca-pem').addEventListener('input', function () {
    var pem = $('ca-pem').value.trim();
    if (!pem) { delete PENDING.ca; markDirtyCount(); return; }
    /* For the directory picked when it was pasted, whatever is picked when
       it is saved (1.0.57). */
    var forDir = (caDir() || {}).id;
    pendingSet('ca', {save: function () {
      var got = false;
      /* A directory gone since, or a refusal (1.0.94): said, and the paste
         dropped - not a false that stopped every later save for ever. */
      if (!DIRS.some(function (x) { return String(x.id) === String(forDir); })) {
        toast('the certificate was for a directory that is gone - it was dropped', 'bad');
        $('ca-pem').value = ''; delete PENDING.ca; markDirtyCount();
        return Promise.resolve(true);
      }
      return caSend($('ca-pem').value.trim(), function () { got = true; $('ca-pem').value = ''; }, forDir).then(function () {
        if (!got) { delete PENDING.ca; markDirtyCount(); }
        return true;
      });
    }, reset: function () { $('ca-pem').value = ''; }});
  });
  $('ca-file').onclick = function () { $('ca-input').click(); };
  $('ca-input').onchange = function () {
    var file = this.files && this.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      var bytes = new Uint8Array(reader.result || new ArrayBuffer(0));
      var text = '';
      try { text = new TextDecoder('utf-8').decode(bytes); } catch (e) { text = ''; }
      if (text.indexOf('-----BEGIN CERTIFICATE-----') < 0 && bytes.length && bytes[0] === 0x30) {
        /* A .cer in DER, as Windows exports it by default: the same bytes
           written out as PEM here, so nobody has to run openssl for it. */
        var bin = '';
        for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
        text = '-----BEGIN CERTIFICATE-----\n' + btoa(bin).replace(/(.{64})/g, '$1\n').replace(/\n$/, '')
          + '\n-----END CERTIFICATE-----';
      }
      var ok = text.indexOf('-----BEGIN CERTIFICATE-----') >= 0;
      $('ca-pem').value = ok ? text.trim() : '';
      $('ca-pem').dispatchEvent(new Event('input'));
      toast(ok ? 'read ' + file.name + ' - Save the changes adds it' : file.name + ' is not a certificate', ok ? 'good' : 'bad');
    };
    reader.readAsArrayBuffer(file);
    this.value = '';
  };
  $('ca-drop').onclick = function () {
    var d = caDir();
    if (!d) return;
    confirmThen('Take every certificate of ' + d.name + ' away',
      'The domain controllers’ certificates will then have to be signed by an authority this '
      + 'machine already trusts, or the check has to be switched off.',
      'Take them all away', function () { caSend(''); });
  };
}

/* ---- mail (1.0.20) ------------------------------------------------------- */
function loadMail() {
  setTimeout(mailViaShown, 0);
  return api('mail').then(function (d) {
    var list = d.ca_list || [];
    if (!$('mca-state')) return d;
    $('mca-when').textContent = list.length ? num(list.length) + ' certificate(s) kept' : 'none imported';
    $('mca-drop').hidden = !list.length;
    var host = $('mca-state');
    clear(host);
    if (list.length) {
      host.appendChild(certTable(list, function (c) {
        confirmThen('Take this certificate out', '<b>' + htmlText(c.subject || 'this certificate')
          + '</b> is no longer trusted for the mail server. The others stay.', 'Take it out', function () {
            api('mail', {action: 'ca', mode: 'drop', fingerprint: c.fingerprint}).then(function (r) {
              toast(r.message, 'good'); loadMail();
            }).catch(oops);
          });
      }));
    }
    $('mail-said').textContent = {off: 'switched off', smtp: 'through a mail server', direct: 'straight to the recipients'}[d.mode] || '';
    return d;
  }).catch(oops);
}
function mailSteps(host, d) {
  clear(host);
  if (d.queued === 'waiting') {
    /* Through the outgoing mail (1.0.103): not taken yet, tried again by itself. */
    var p = el('p', 'note warn', 'Waiting in the outgoing mail: ' + d.said + ' - it is tried again by itself.');
    host.appendChild(p);
    var go = cmdButton('Outgoing mail', 'list', 'small');
    go.onclick = function () { showPane('mailq'); };
    host.appendChild(go);
  } else {
    host.appendChild(el('p', 'note ' + (d.sent ? 'good' : 'bad'), (d.sent ? (d.queued ? 'Sent through the outgoing mail: ' : 'Sent: ') : 'Not sent: ') + d.said
      + (d.took_ms !== undefined ? ' · ' + num(d.took_ms) + ' ms' : '')));
  }
  if ((d.steps || []).length) host.appendChild(stepsList(d.steps));
  host.appendChild(hideBar(function () { clear(host); }));
}
/* The choice of how a test mail goes - there only while mail goes
   straight to the recipient's server (1.0.103). */
function mailViaShown() {
  var via = $('mail-test-via');
  if (!via) return;
  var mode = $('set-mail_mode');
  var v = mode ? String(mode._get ? mode._get() : mode.value) : String(((settingByKey('mail_mode') || {}).value) || '');
  via.hidden = v !== 'direct';
}
document.addEventListener('change', function (e) {
  if (e.target && e.target.id === 'set-mail_mode') mailViaShown();
}, true);
if ($('mail-test')) {
  $('mail-test').onclick = function () {
    var b = $('mail-test');
    /* Only a change to the mail settings stops the test (1.0.36), not one
       left on another page. */
    if (Object.keys(DIRTY || {}).some(function (k) { return /^(mail_|smtp_)/.test(k); })) {
      toast('save the mail settings first', 'bad'); return;
    }
    busy(b, true);
    var via = $('mail-test-via') && !$('mail-test-via').hidden ? $('mail-test-via').value : 'queue';
    api('mail', {action: 'test', to: $('mail-to').value.trim(), lang: $('mail-test-lang').value, kind: $('mail-test-kind') ? $('mail-test-kind').value : 'short', via: via}).then(function (d) {
      mailSteps($('mail-steps'), d);
    }).catch(oops).then(function () { busy(b, false); });
  };
  $('mca-save').onclick = function () {
    var pem = $('mca-pem').value.trim();
    if (!pem) { toast('paste the certificate first, or read it from a file', 'bad'); return; }
    busy($('mca-save'), true);
    api('mail', {action: 'ca', mode: 'add', ca: pem}).then(function (r) {
      toast(r.message, 'good'); $('mca-pem').value = ''; loadMail();
    }).catch(oops).then(function () { busy($('mca-save'), false); });
  };
  $('mca-save').hidden = true;
  $('mca-pem').addEventListener('input', function () {
    var pem = $('mca-pem').value.trim();
    if (!pem) { delete PENDING.mca; markDirtyCount(); return; }
    pendingSet('mca', {save: function () {
      return api('mail', {action: 'ca', mode: 'add', ca: $('mca-pem').value.trim()}).then(function (r) {
        toast(r.message, 'good'); $('mca-pem').value = ''; loadMail(); return true;
      });
    }, reset: function () { $('mca-pem').value = ''; }});
  });
  $('mca-file').onclick = function () { $('mca-input').click(); };
  $('mca-input').onchange = function () {
    var file = this.files && this.files[0];
    if (file) readCertFile(file, $('mca-pem'));
    this.value = '';
  };
  $('mca-drop').onclick = function () {
    confirmThen('Take every certificate of the mail server away',
      'The mail server’s certificate will then have to be signed by an authority this machine already trusts, or the check has to be switched off.',
      'Take them all away', function () {
        api('mail', {action: 'ca', mode: 'clear'}).then(function (r) { toast(r.message, 'good'); loadMail(); }).catch(oops);
      });
  };
}

/* ---- the administrators' groups, found rather than typed (as isemon) ---- */
var AG_ROLES = [['admin_group_full', 'Full admin', 'shield', 'is-admin'],
                ['admin_group_cert', 'Cert admin', 'key', 'is-cert'],
                ['admin_group_readonly', 'Read only', 'eye', 'is-read']];
var AG = {groups: [], q: '', page: 0, per: 25, capped: false};

/** The directory chosen in the editor right now - saved or not. */
function agDirectory() {
  var input = $('set-admin_directory');
  return input ? String(input._get ? input._get() : input.value || '') : '';
}
/** The box of a role's groups: the cert admins' under its older name
    (admin_group_token) as long as the daemon still calls it that. */
function agBox(key) {
  return $('set-' + key) || (key === 'admin_group_cert' ? $('set-admin_group_token') : null);
}
/** What a role's groups are set to right now, in the editor, lower-cased. */
function agWanted(key) {
  var input = agBox(key);
  var said = input ? (input._get ? input._get() : input.value) : '';
  return String(said || '').split(/[;\n]/).map(function (x) {
    return x.trim().toLowerCase();
  }).filter(Boolean);
}
/** Put a group into a role, or take it out, in the settings editor. Saved
    with the rest of the page - nothing happens until then. */
function agToggle(key, dn, name) {
  var input = agBox(key);
  if (!input) { toast('the settings are not drawn yet'); return; }
  var have = String(input.value || '').split(/[;\n]/).map(function (x) { return x.trim(); })
    .filter(Boolean);
  var same = function (one) {
    var low = one.toLowerCase();
    return low === String(dn).toLowerCase() || (name && low === String(name).toLowerCase());
  };
  var was = have.some(same);
  if (was) have = have.filter(function (one) { return !same(one); }); else have.push(dn);
  // In the separator the box already used (1.0.61): one per line stayed one
  // per line, so putting a group in and out again left nothing "changed".
  input.value = have.join(/\n/.test(String(input.value || '')) || input.tagName === 'TEXTAREA' && !/;/.test(String(input.value || '')) ? '\n' : '; ');
  input.dispatchEvent(new Event('input', {bubbles: true}));
  input.dispatchEvent(new Event('change', {bubbles: true}));
  toast(was ? 'taken out — save to keep it' : 'put in — save to keep it');
}
function agPaint() {
  var want = {};
  AG_ROLES.forEach(function (r) { want[r[0]] = agWanted(r[0]); });
  Array.prototype.forEach.call(document.querySelectorAll('#ag-groups tr.dgroup'), function (row) {
    var dn = String(row.dataset.dn || '').toLowerCase();
    var name = String(row.dataset.name || '').toLowerCase();
    AG_ROLES.forEach(function (r, i) {
      var on = want[r[0]].indexOf(dn) >= 0 || want[r[0]].indexOf(name) >= 0;
      row.classList.toggle(r[3], on);
      var b = row.querySelectorAll('.rowtools .btn')[i];
      if (b) b.classList.toggle('on', on);
    });
  });
}
function agDraw() {
  var host = $('ag-groups');
  clear(host);
  var all = AG.groups;
  if (!all.length) {
    host.appendChild(el('p', 'note', 'The directory has no groups under that base matching '
      + 'that - or the base is not where they live.'));
    return;
  }
  var low = AG.q.toLowerCase();
  var rows = !low ? all : all.filter(function (g) {
    return (g.cn + ' ' + g.dn + ' ' + (g.description || '')).toLowerCase().indexOf(low) >= 0;
  });
  var lead = el('p', 'note');
  lead.innerHTML = '<b>' + num(all.length) + '</b> group(s). Press a role beside one to put it '
    + 'in that role; press it again to take it out. More than one group may hold a role, and '
    + 'somebody in several gets the highest.'
    + (AG.capped ? ' This is as many as are fetched at once — there may be more: type part of '
       + 'a name above and press <i>Find the groups</i> again.' : '');
  host.appendChild(lead);
  var bar = el('div', 'filterbar btnrow');
  var find = el('input');
  find.type = 'search';
  find.placeholder = 'narrow this list…';
  find.value = AG.q;
  find.style.maxWidth = '320px';
  var found = el('span', 'muted small', num(rows.length) + ' shown');
  find.oninput = function () {
    AG.q = find.value;
    AG.page = 0;
    var at = find.selectionStart;
    agDraw();
    var again = $('ag-groups').querySelector('input[type=search]');
    if (again) { again.focus(); try { again.setSelectionRange(at, at); } catch (e) { } }
  };
  bar.appendChild(find);
  bar.appendChild(found);
  host.appendChild(bar);
  var pages = Math.max(1, Math.ceil(rows.length / AG.per));
  if (AG.page >= pages) AG.page = pages - 1;
  var page = rows.slice(AG.page * AG.per, AG.page * AG.per + AG.per);
  host.appendChild(listTable(['Group', 'What it is for', ''], page, function (g) {
    var tr = el('tr', 'dgroup');
    tr.dataset.dn = g.dn;
    tr.dataset.name = g.cn;
    var n = el('td');
    n.appendChild(noI18n(el('div', '', g.cn)));
    n.appendChild(noI18n(el('div', 'mono small muted', g.dn)));
    tr.appendChild(n);
    tr.appendChild(noI18n(el('td', 'muted small', g.description || '')));
    var pick = el('td', 'rowtools');
    if (ADMIN) {
      AG_ROLES.forEach(function (r) {
        var b = cmdButton(r[1], r[2], 'small');
        b.onclick = function (e) { e.stopPropagation(); agToggle(r[0], g.dn, g.cn); agPaint(); };
        explain(b, 'Put <b>' + wordsIn(g.cn) + '</b> in this role, or take it out of it. It is a '
          + 'change like any other on this page — nothing happens until you save.');
        pick.appendChild(b);
      });
    }
    tr.appendChild(pick);
    return tr;
  }, 'rows'));
  if (pages > 1) {
    var nav = el('div', 'btnrow');
    nav.style.marginTop = '10px';
    var prev = cmdButton('Back', 'prev', 'small');
    prev.disabled = AG.page === 0;
    prev.onclick = function () { AG.page--; agDraw(); };
    var next = cmdButton('Next', 'next', 'small');
    next.disabled = AG.page >= pages - 1;
    next.onclick = function () { AG.page++; agDraw(); };
    nav.appendChild(prev);
    nav.appendChild(el('span', 'muted small', 'page ' + (AG.page + 1) + ' of ' + pages));
    nav.appendChild(next);
    host.appendChild(nav);
  }
  agPaint();
  explainWhatWasDrawn(host);
}
if ($('ag-find')) {
  var agFind = function () {
    var dir = agDirectory();
    if (!dir) {
      toast('choose the directory first - "Sign administrators in against the directory" above', 'bad');
      var item = document.querySelector('.set-item[data-key="admin_directory"]');
      if (item) item.scrollIntoView({block: 'center'});
      return;
    }
    busy($('ag-find'), true);
    api('directories', {action: 'groups', name: dir, like: $('ag-like').value.trim()}).then(function (d) {
      AG.groups = d.groups || [];
      AG.capped = !!d.capped;
      AG.q = '';
      AG.page = 0;
      agDraw();
      toast(num(AG.groups.length) + ' group(s) found', 'good');
    }).catch(oops).then(function () { busy($('ag-find'), false); });
  };
  $('ag-find').onclick = agFind;
  $('ag-like').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); agFind(); } });
  /* A role typed or changed by hand shows in the list at once. */
  document.addEventListener('input', function (e) {
    if (e.target && /^set-admin_group_/.test(e.target.id || '')) agPaint();
  });
  $('ag-try').onclick = function () {
    var name, pass;
    modal('Try a sign-in', function (body) {
      body.appendChild(el('p', 'note', 'Nothing is signed in and no session is made. This asks '
        + 'the directory the same question a real sign-in asks, and shows the whole answer - '
        + 'including which groups came back and what role they earn. It uses the settings as '
        + 'they are saved.'));
      var one = el('div', 'set-item');
      one.appendChild(el('label', '', 'The name they would type'));
      name = el('input');
      name.type = 'text';
      name.placeholder = 'novak, novak@example.cz or EXAMPLE\\novak';
      one.appendChild(name);
      body.appendChild(one);
      var two = el('div', 'set-item');
      two.appendChild(el('label', '', 'Their password'));
      pass = maskBox('', '', '');
      two.appendChild(pass);
      body.appendChild(two);
      setTimeout(function () { name.focus(); }, 60);
    }, [{words: 'Try it', cls: 'primary', icon: 'person', go: function (b) {
      busy(b, true);
      api('directories', {action: 'try', user: name.value, password: pass.value}).then(function (d) {
        var said = d.tried || {};
        /* Under the boxes, not in their place (1.0.36): a typo could not be
           put right without closing the window. */
        var body = $('modal-body');
        var res = body.querySelector('.try-res');
        if (!res) { res = el('div', 'try-res'); res.style.marginTop = '12px'; body.appendChild(res); }
        clear(res);
        body = res;
        if (said.ok) {
          body.appendChild(kvTable([
            ['They are', said.display || said.name],
            ['Role here', said.role ? ({fulladmin: 'full admin', certadmin: 'cert admin',
                                         readonly: 'read only'}[said.role] || said.role)
                                    : 'none - they cannot sign in'],
            ['In the directory', said.dn || ''],
            ['Asked', said.directory]]));
          var g = el('p', 'note');
          g.appendChild(el('b', '', 'Groups the directory gave back:'));
          (said.groups || []).forEach(function (one) {
            g.appendChild(el('br'));
            g.appendChild(noI18n(el('span', 'mono small', one)));
          });
          body.appendChild(g);
        } else {
          body.appendChild(el('p', said.missing ? 'note' : 'note bad', said.said || 'it did not work'));
          if (said.missing) {
            body.appendChild(el('p', 'note', 'That is not a fault: a name the directory has '
              + 'never heard of is looked for in the local accounts instead.'));
          }
        }
      }).catch(oops).then(function () { busy(b, false); });
    }}, {words: 'Close', close: true}]);
  };
}

var QS = {
  mailq: qSuggest($('mq-q'), 'mailq'),
  events: qSuggest($('ev-q'), 'events')
};

/* ---- Search and Clear beside every search box (1.0.100) ---------------- */
/** go(): draw the list again; selects: filters put back to their first
    choice ("every …"); times: time pickers put back to the last 24 hours. */
function searchButtons(input, go, selects, times) {
  if (!input || input._sb) return;
  input._sb = true;
  var find = cmdButton('Search', 'search', 'sb-go');
  var clearB = cmdButton('Clear', 'close', 'sb-clear');
  find.type = clearB.type = 'button';
  find.title = 'Look for what is typed and chosen (Enter does the same)';
  clearB.title = 'Empty the search and put every filter here back';
  find.onclick = function () { go(); };
  clearB.onclick = function () {
    input.value = '';
    (selects || []).forEach(function (id) {
      var sel = typeof id === 'string' ? $(id) : id;
      if (sel && sel.options && sel.options.length) sel.value = sel.options[0].value;
    });
    (times || []).forEach(function (id) {
      var tp = $(id);
      if (tp && tp._set) { tp._quiet = true; tp._set({k: 'rel', s: 86400}); tp._quiet = false; }
    });
    if (input._qs) input._qs.said('');
    go();
  };
  var paint = function () {
    var busy = !!input.value.trim() || (selects || []).some(function (id) {
      var sel = typeof id === 'string' ? $(id) : id;
      return sel && sel.options && sel.options.length && sel.value !== sel.options[0].value;
    });
    clearB.classList.toggle('on', busy);
  };
  input.addEventListener('input', paint);
  (selects || []).forEach(function (id) { var sel = typeof id === 'string' ? $(id) : id; if (sel) sel.addEventListener('change', paint); });
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.defaultPrevented) go(); });
  /* Beside the box - beside the box with its suggestions, when it has them,
     not inside it under the box. */
  var at = input.parentNode && input.parentNode.classList.contains('qs-wrap') ? input.parentNode : input;
  var after = at.nextSibling;
  at.parentNode.insertBefore(find, after);
  at.parentNode.insertBefore(clearB, after);
  input._sbPaint = paint;
  paint();
}
searchButtons($('ev-q'), function () { PAGE.events = 0; loadEvents(); }, ['ev-kind'], ['ev-time']);
searchButtons($('mq-q'), function () { MQ.page = 0; loadMailq(); }, ['mq-state']);

/* ---- starting ------------------------------------------------------------ */
/* Started once every script has run (DOMContentLoaded) - certs.js comes after
   this file and plugs its tabs and panes in first (ACME_EXTRA_TABS, above). */
function start() {
  var h = (location.hash || '#overview').slice(1).split('/');
  if (h[1]) PANE = h[1];
  if (STATUS) paintHeader(STATUS);
  showTab(h[0] || 'overview');
  setInterval(tick, 5000);
  explainWhatWasDrawn(document);
  /* A link to #settings/people, or Back: the page follows the address. */
  window.addEventListener('hashchange', function () {
    var g = (location.hash || '#overview').slice(1).split('/');
    if (allTabs().indexOf(g[0]) < 0) return;
    if (g[0] === 'settings' && g[1] && g[1] !== PANE && typeof showPane === 'function'
        && TAB === 'settings') { showPane(g[1]); return; }
    if (g[1]) PANE = g[1];
    if (g[0] !== TAB) showTab(g[0]);
  });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
else setTimeout(start, 0);

/* ==========================================================================
   High availability (1.0.13)
   ========================================================================== */
var HA = null;
/* Each node's own settings (1.0.37): one row a setting, one column a node. */
/* Each node's own settings (1.0.67): grouped, each node's value as it is in
   effect - its own, marked, with a way back to the cluster's, or the
   cluster's, dimmed - switches flipped in place, and the cluster's own value
   changeable too. */
var NODE_GROUPS = [
  ['The ports', ['api_port']],
  ['What it calls itself', ['mail_helo', 'isemon_hostname', 'siem_hostname', 'acme_node_name']],
  ['Its copies of the database', ['backup_daily', 'backup_at', 'backup_keep']],
  ['Writing down more (debug)', ['debug', 'debug_ldap', 'debug_api', 'debug_codes']]];
var NODE_NAMES = {backup_daily: 'A copy of the database every day', backup_at: 'Made at',
                  backup_keep: 'Copies kept',
                  isemon_hostname: 'The name isemon files it under',
                  siem_hostname: 'The name the syslog servers file it under',
                  acme_node_name: 'The name of its own certificate (ACME)'};
var NODE_EMPTY = {isemon_hostname: 'the machine’s own name', mail_helo: 'the machine’s own name',
                  siem_hostname: 'the machine’s own name',
                  acme_node_name: 'the name of its certificate, else its full host name'};
function nodeValWords(s, v) {
  if (isBool(s)) return (v === true || v === 1 || v === '1' || v === 'true') ? 'on' : 'off';
  if (v === '' || v === null || v === undefined) return NODE_EMPTY[s.key] || '(empty)';
  return String(v);
}
/* One cell laid out the same in every row (1.0.67): the value on the left,
   its tag after it, the buttons at the right edge - so they stand one under
   the other down the column. */
function nodeCellTidy(td) {
  var wrap = el('div', 'nc'), val = el('span', 'nc-val'), tags = el('span', 'nc-tags'),
      acts = el('span', 'nc-acts');
  Array.prototype.slice.call(td.childNodes).forEach(function (c) {
    if (c.nodeType === 1 && c.tagName === 'BUTTON') acts.appendChild(c);
    else if (c.nodeType === 1 && c.classList.contains('tag')) tags.appendChild(c);
    else if (c.nodeType === 1) val.appendChild(c);
  });
  wrap.appendChild(val); wrap.appendChild(tags); wrap.appendChild(acts);
  td.appendChild(wrap);
  return td;
}
function nodeValEl(s, v, cls) {
  var words = nodeValWords(s, v);
  /* A value as it is; the words for an empty one in the page's language
     (not .mono: that is never translated). */
  if (v === '' || v === null || v === undefined)
    return el('span', String(cls).replace(/\bmono\b/, 'node-empty'), words);
  return noI18n(el('span', cls, words));
}
function nodeSave(s, node, value, then) {
  var want = {};
  want[s.key] = typeof s.default === 'number' ? Number(value)
    : (typeof s.default === 'boolean' ? (value === true || value === 'true' || value === '1' || value === 1) : value);
  return api('settings', {settings: want, node: node}).then(function (r) { toast(r.message, 'good'); then(); }).catch(oops);
}
function nodeEdit(s, node, current, then) {
  var box;
  var who = node === '*' ? 'the cluster (every node without its own)' : node + ' only';
  modal(s.name + ' · ' + (node === '*' ? 'the cluster' : node), function (body) {
    if (s.says) body.appendChild(saysBlock(s.says));
    box = textBox(current === null || current === undefined ? '' : String(current),
                  node === '*' ? String(s.default) : String(s.shared), 'mono');
    /* What empty means, once - "((empty))" said it twice (1.0.170). */
    var bare = function (v) { return nodeValWords(s, v).replace(/^\((.*)\)$/, '$1'); };
    body.appendChild(formField('For ' + who, box, node === '*' ? 'Empty: the built-in default (' + bare(s.default) + ').'
                                                     : 'Empty: the cluster’s value (' + bare(s.shared) + ').'));
  }, [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
    if (b && b.disabled) return;
    if (b) busy(b, true);
    var raw = box.value.trim();
    var val = raw === '' ? (node === '*' ? s.default : s.shared) : raw;
    nodeSave(s, node, val, function () { closeModal(); then(); }).then(function () { if (b) busy(b, false); });
  }}], true);
}
function drawNodeSettings(nodes, live) {
  var card = $('ha-own-card');
  if (!card) return;
  var names = (nodes || []).map(function (n) { return n.name; });
  card.hidden = names.length < 2 && !(SETTINGS && SETTINGS.cluster);
  if (card.hidden) return;
  apiLatest('nodeset', 'settings').then(function (d) {
    liveFill($('ha-own'), function (host) {
    var byKey = {};
    (d.settings || []).forEach(function (s) { if (s.node_key) byKey[s.key] = s; });
    var redraw = function () { drawNodeSettings(nodes); };
    var table = el('table', 'plain node-own');
    var head = el('tr');
    ['Setting', 'The cluster’s'].forEach(function (h) { head.appendChild(el('th', '', h)); });
    names.forEach(function (n) { head.appendChild(noI18n(el('th', 'mono', n))); });
    var thead = el('thead'); thead.appendChild(head); table.appendChild(thead);
    var tb = el('tbody');
    var groups = NODE_GROUPS.map(function (g) { return [g[0], g[1].filter(function (k) { return byKey[k]; })]; });
    var known = {}; NODE_GROUPS.forEach(function (g) { g[1].forEach(function (k) { known[k] = 1; }); });
    var rest = Object.keys(byKey).filter(function (k) { return !known[k]; });
    if (rest.length) groups.push(['Others', rest]);
    groups.forEach(function (g) {
      if (!g[1].length) return;
      var gr = el('tr', 'node-group');
      var gt = el('td', '', g[0]); gt.colSpan = 2 + names.length;
      gr.appendChild(gt); tb.appendChild(gr);
      g[1].forEach(function (k) {
        var s = byKey[k];
        var tr = el('tr');
        var nm = el('td', '');
        nm.appendChild(el('div', '', NODE_NAMES[s.key] || s.name || s.key));
        explain(nm, s.says ? String(s.says).replace(/<[^>]+>/g, '') : s.key);
        tr.appendChild(nm);
        /* The cluster's value. */
        var cc = el('td', 'node-cell');
        if (isBool(s)) {
          var sw0 = switchBox(nodeValWords(s, s.shared) === 'on');
          sw0._input.disabled = !ADMIN;
          sw0.title = 'The whole cluster';
          sw0._input.addEventListener('change', function () { nodeSave(s, '*', !!sw0._get(), redraw); });
          cc.appendChild(sw0);
        } else cc.appendChild(nodeValEl(s, s.shared, 'mono small'));
        if (ADMIN) {
          if (isBool(s)) {
            /* the switch is the control */
          } else {
            var eb = iconButton('edit', 'Change the cluster’s value');
            eb.onclick = function () { nodeEdit(s, '*', s.shared, redraw); };
            cc.appendChild(eb);
          }
        }
        tr.appendChild(nodeCellTidy(cc));
        names.forEach(function (n) {
          var has = s.per_node && Object.prototype.hasOwnProperty.call(s.per_node, n);
          /* What the node itself says is in effect (1.0.67), its config.json
             among it; the saved values where it has not said yet. */
          var nd = (nodes || []).filter(function (x) { return x.name === n; })[0] || {};
          var said = nd.own && Object.prototype.hasOwnProperty.call(nd.own, k);
          var fromFile = !has && said && (nd.own_file || []).indexOf(k) >= 0 &&
                         String(nd.own[k]) !== String(s.shared);
          var val = said ? nd.own[k] : (has ? s.per_node[n] : s.shared);
          var td = el('td', 'node-cell' + (has || fromFile ? ' own' : ''));
          var v;
          if (isBool(s)) {
            v = switchBox(nodeValWords(s, val) === 'on');
            v._input.disabled = !ADMIN;
            if (!has) v.classList.add('inherited');
            v._input.addEventListener('change', function () { nodeSave(s, n, !!v._get(), redraw); });
          } else v = nodeValEl(s, val, 'mono small' + (has || fromFile ? '' : ' muted'));
          td.appendChild(v);
          if (has) {
            td.appendChild(el('span', 'tag info', 'its own'));
          } else if (fromFile) {
            var ff = el('span', 'tag warn', 'config.json');
            explain(ff, 'Set in /etc/acme/config.json of ' + n + ' (no value of the cluster’s is saved for it). Changed here, it is saved as the node’s own and takes over.');
            td.appendChild(ff);
          } else {
            explain(v, 'The cluster’s value: ' + n + ' has none of its own.');
          }
          if (ADMIN) {
            if (isBool(s)) {
              /* the switch is the control: flipped, it is this node's own */
            } else {
              var b = iconButton('edit', 'Change it for ' + n);
              b.onclick = function () { nodeEdit(s, n, has ? val : null, redraw); };
              td.appendChild(b);
            }
            if (has) {
              var back = iconButton('undo', 'Back to the cluster’s value');
              back.onclick = function () { nodeSave(s, n, s.shared, redraw); };
              td.appendChild(back);
            }
          }
          tr.appendChild(nodeCellTidy(td));
        });
        tb.appendChild(tr);
      });
    });
    table.appendChild(tb);
    host.appendChild(table);
    host.appendChild(el('p', 'btnhelp', 'A value marked “its own” is that node’s alone; the others take the cluster’s. The API port takes effect when the node reads its settings again (within seconds).'));
    }, !!live);
  }).catch(oops);
}

function loadHa(live) {
  loadVip(live);
  api('ha').then(function (d) {
    drawNodeSettings(d.nodes, live);
    HA = d;
    var rep = !!(d.replication && d.replication.mode === 'replicated');
    if ($('ha-lede-shared')) { $('ha-lede-shared').hidden = rep; $('ha-lede-replicated').hidden = !rep; }
    var nodes = d.nodes || [];
    var alive = nodes.filter(function (n) { return n.alive; }).length;
    $('ha-said').textContent = num(alive) + ' of ' + num(nodes.length) + ' answering · this page from ' + d.node;
    liveFill($('ha-nodes'), function (host) {
    host.appendChild(listTable(['Node', 'Address', 'Version', 'Heard from', 'State', ''], nodes, function (n) {
      var tr = el('tr');
      var nm = el('td');
      nm.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'this page')); }
      tr.appendChild(nm);
      tr.appendChild(noI18n(el('td', 'mono small', n.address || '')));
      var v = el('td', n.version !== d.version ? 'warn' : '', n.version || '?');
      if (n.version !== d.version) explain(v, 'Not the version this node runs (' + d.version + '): both nodes should run the same one.');
      tr.appendChild(v);
      tr.appendChild(el('td', 'muted', ago(n.at)));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (n.alive ? 'ok' : 'crit'), n.alive ? 'answering' : 'gone'));
      tr.appendChild(st);
      var tools = el('td', 'rowtools');
      if (ADMIN && !n.me) {
        var x = iconButton('trash', 'Take it off the list');
        x.onclick = function () {
          confirmThen('Take ' + n.name + ' off the list', 'For a node taken away for good. If it is still running it writes itself back within fifteen seconds.', 'Take it off', function () {
            api('ha', {action: 'forget', name: n.name}).then(function (r) { toast(r.message, 'good'); loadHa(); }).catch(oops);
          });
        };
        tools.appendChild(x);
      }
      tr.appendChild(tools);
      return tr;
    }));
    }, !!live);
    liveFill($('ha-checks'), function (ch) {
    (d.checks || []).forEach(function (c) {
      var p = el('p', 'note ' + (c.ok ? 'good' : (c.warn ? 'warn' : 'bad')));
      p.appendChild(noI18n(el('b', '', c.ok ? '✓ ' : (c.warn ? '! ' : '✗ '))));
      p.appendChild(el('span', '', c.says));
      ch.appendChild(p);
    });
    /* Setting the pair up (1.0.210): who is let in for being joined, and
       PostgreSQL here as the node being joined finds it. */
    (d.pending || []).forEach(function (x) {
      var p = el('div', 'note info ha-pending');
      p.appendChild(haWords('Opened for the node being joined: ', x.address, ', until ', haWhen(x.until), ' (the firewall and PostgreSQL’s lists)'));
      if (ADMIN) {
        var f = cmdButton('Close it again', 'close', 'small');
        f.onclick = function () { api('ha', {action: 'prepare', step: 'forget', peer: x.address}).then(function () { loadHa(); }).catch(oops); };
        p.appendChild(f);
      }
      ch.appendChild(p);
    });
    if (d.pg_open && d.pg_open.only_local && d.engine === 'postgres') {
      var pg = el('div', 'note warn ha-pending');
      pg.appendChild(el('span', '', 'PostgreSQL on this machine listens only on localhost: a second node cannot reach it. Before it joins, PostgreSQL here has to listen on this node’s address and let it in.'));
      if (ADMIN) {
        var go = cmdButton('Prepare it…', 'net', 'small primary');
        go.onclick = function () { haBundlePopup(true); };
        pg.appendChild(go);
      }
      ch.appendChild(pg);
    } else if (d.pg_open && d.pg_open.last && d.pg_open.last.at) {
      var lst = d.pg_open.last;
      var lp = el('div', 'note ' + (lst.ok ? 'good' : 'warn'));
      lp.appendChild(haWords('PostgreSQL here was opened to ', lst.peer, ' ', ago(lst.at), lst.ok ? '' : ' - not all of it worked'));
      ch.appendChild(lp);
    }
    }, !!live);
    $('ha-bundle').disabled = d.engine !== 'postgres';
    /* Made two already (1.0.43): the steps folded away, a click away. */
    var made = !!d.mode;
    $('ha-make-open').hidden = !made;
    if (!made || !HA_MAKE_OPEN) $('ha-make-body').hidden = made;
    drawHaRep(d, !!live);
    drawHaLb(d);
    explainWhatWasDrawn($('pane-ha'));
  }).catch(oops);
}

/* The load balancer guides (1.0.52): one per kind, folded, filled in with
   this installation's own names, addresses and ports - and with what is
   typed in at the top - the real values marked where they stand. */
var LB_UI = (function () {
  var st = {};
  try { st = JSON.parse(localStorage.getItem('acme.lb') || '{}') || {}; } catch (e) { st = {}; }
  return st;
})();
function lbKeep() {
  try { localStorage.setItem('acme.lb', JSON.stringify(Object.assign({}, LB_UI, {secret: undefined, hc: undefined}))); } catch (e) { /* not kept */ }
}
function lbCode(tpl, v) {
  /* {key} in the text is a value: put in, and marked. */
  var pre = noI18n(el('pre', 'mono small lb-code'));
  tpl.split(/(\{[a-z0-9_]+\})/).forEach(function (part) {
    var m = /^\{([a-z0-9_]+)\}$/.exec(part);
    if (m && v[m[1]] !== undefined) pre.appendChild(el('span', 'lbv', String(v[m[1]])));
    else pre.appendChild(document.createTextNode(part));
  });
  return pre;
}
function lbBlock(tpl, v, title) {
  var box = el('div', 'lb-block');
  var head = el('div', 'lb-block-h' + (title ? '' : ' solo'));
  if (title) head.appendChild(el('span', 'arow-s', title));
  var cp = cmdButton('Copy', 'copy', 'small');
  var pre = lbCode(tpl, v);
  cp.onclick = function () { copyText(pre.textContent, cp); };
  head.appendChild(cp);
  box.appendChild(head);
  box.appendChild(pre);
  return box;
}
function lbServers(v, fmt) {
  return v.nodes.map(function (n, i) { return fmt(n, i); }).join('\n');
}
var LB_GUIDES = [
  ['haproxy', 'HAProxy', 'pages', function (v) {
    var out = [];
    if (v.tls === 'end') {
      out.push(['/etc/haproxy/haproxy.cfg - TLS ended on HAProxy',
        'frontend acme_https\n    bind {lb}:443 ssl crt /etc/haproxy/{name}.pem alpn h2,http/1.1\n    bind {lb}:80\n    mode http\n'
        + '    http-request redirect scheme https unless { ssl_fc }\n    option forwardfor\n    timeout client 900s\n    default_backend acme_nodes\n\n'
        + 'backend acme_nodes\n    mode http\n    balance roundrobin\n    timeout server 900s\n    option httpchk\n'
        + '    http-check send meth GET uri {hc} ver HTTP/1.1 hdr Host {name}\n    http-check expect status 200\n'
        + '    default-server inter 3s fall 2 rise 2 check ssl verify none\n'
        + lbServers(v, function (n, i) { return '    server {n' + i + '} {a' + i + '}:443'; })]);
    } else {
      out.push(['/etc/haproxy/haproxy.cfg - TLS passed through, the client\'s address in the PROXY protocol',
        'frontend acme_https\n    bind {lb}:443\n    mode tcp\n    timeout client 900s\n    default_backend acme_nodes\n\n'
        + 'backend acme_nodes\n    mode tcp\n    balance roundrobin\n    timeout server 900s\n    option httpchk\n'
        + '    http-check send meth GET uri {hc} ver HTTP/1.1 hdr Host {name}\n    http-check expect status 200\n'
        + '    default-server inter 3s fall 2 rise 2 check check-ssl verify none check-send-proxy send-proxy-v2\n'
        + lbServers(v, function (n, i) { return '    server {n' + i + '} {a' + i + '}:443'; })]);
    }
    return out;
  }],
  ['nginx', 'nginx', 'pages', function (v) {
    return [['/etc/nginx/conf.d/acme-lb.conf - open-source nginx checks passively; nginx Plus can ask /healthz (the commented lines)',
      'upstream acme_nodes {\n' + lbServers(v, function (n, i) { return '    server {a' + i + '}:443 max_fails=2 fail_timeout=10s;'; })
      + '\n    keepalive 16;\n}\nserver {\n    listen {lb}:80;\n    server_name {name};\n    return 301 https://$host$request_uri;\n}\n'
      + 'server {\n    listen {lb}:443 ssl;\n    http2 on;\n    server_name {name};\n'
      + '    ssl_certificate     /etc/nginx/certs/{name}.pem;\n    ssl_certificate_key /etc/nginx/certs/{name}.key;\n'
      + '    client_max_body_size 4g;\n    location / {\n        proxy_pass https://acme_nodes;\n        proxy_http_version 1.1;\n'
      + '        proxy_set_header Connection "";\n        proxy_set_header Host $host;\n'
      + '        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto https;\n'
      + '        proxy_read_timeout 900s;\n        proxy_next_upstream error timeout http_502 http_503 http_504;\n'
      + '        # nginx Plus: health_check uri={hc} interval=3 fails=2 passes=2 match=acme_ok;\n    }\n}\n'
      + '# nginx Plus: match acme_ok { status 200; body ~ "^ok "; }']];
  }],
  ['apache', 'Apache httpd', 'pages', function (v) {
    return [['/etc/httpd/conf.d/acme-lb.conf - mod_proxy_balancer with mod_proxy_hcheck asking /healthz',
      'ProxyHCExpr acme_ok {%{REQUEST_STATUS} == 200 && hc(\'body\') =~ /^ok /}\n\n<VirtualHost {lb}:443>\n    ServerName {name}\n'
      + '    SSLEngine on\n    SSLCertificateFile    /etc/pki/tls/certs/{name}.crt\n    SSLCertificateKeyFile /etc/pki/tls/private/{name}.key\n'
      + '    SSLProxyEngine on\n    SSLProxyVerify none\n    SSLProxyCheckPeerName off\n\n    <Proxy "balancer://acme">\n'
      + lbServers(v, function (n, i) { return '        BalancerMember https://{a' + i + '} hcmethod=GET hcuri={hc} hcexpr=acme_ok hcinterval=3 hcpasses=2 hcfails=2'; })
      + '\n        ProxySet lbmethod=byrequests\n    </Proxy>\n    ProxyPreserveHost On\n'
      + '    ProxyPass        "/" "balancer://acme/" timeout=900\n    ProxyPassReverse "/" "balancer://acme/"\n    LimitRequestBody 0\n</VirtualHost>']];
  }],
  ['f5', 'F5 BIG-IP', 'pages', function (v) {
    return [['tmsh - a monitor that reads /healthz, the pool, the virtual server (SSL offload, X-Forwarded-For)',
      'create ltm monitor https acme_healthz defaults-from https interval 3 timeout 10 send "GET {hc} HTTP/1.1\\r\\nHost: {name}\\r\\nConnection: close\\r\\n\\r\\n" recv "^ok " recv-disable "maintenance"\n'
      + 'create ltm pool acme_https monitor acme_healthz load-balancing-mode round-robin members add { '
      + v.nodes.map(function (n, i) { return '{a' + i + '}:443'; }).join(' ') + ' }\n'
      + 'create ltm profile http acme_http insert-xforwarded-for enabled\n'
      + 'create ltm virtual acme_vs destination {lb}:443 ip-protocol tcp pool acme_https profiles add { acme_http clientssl serverssl } source-address-translation { type automap }'],
      ['Put your certificate for {name} into the clientssl profile.', '']];
  }],
  ['netscaler', 'Citrix ADC / NetScaler', 'pages', function (v) {
    return [['NetScaler CLI',
      'add lb monitor acme_healthz HTTP-ECV -send "GET {hc}" -recv "ok " -secure YES -interval 3 -resptimeout 2 -downTime 5\n'
      + lbServers(v, function (n, i) { return 'add server {n' + i + '} {a' + i + '}'; }) + '\n'
      + 'add serviceGroup acme_https SSL -cip ENABLED X-Forwarded-For\n'
      + lbServers(v, function (n, i) { return 'bind serviceGroup acme_https {n' + i + '} 443'; }) + '\n'
      + 'bind serviceGroup acme_https -monitorName acme_healthz\n'
      + 'add lb vserver acme_vs SSL {lb} 443 -lbMethod ROUNDROBIN -persistenceType NONE\n'
      + 'bind lb vserver acme_vs acme_https\nbind ssl vserver acme_vs -certkeyName {name}']];
  }]
];

function drawHaLb(d) {
  var host = $('ha-lb');
  var open = {};
  host.querySelectorAll('details.lb-guide').forEach(function (x) { open[x.dataset.k] = x.open; });
  if (host.contains(document.activeElement) && liveControl(document.activeElement)) return;
  clear(host);
  var lb = d.lb || {};
  var nodes = (d.nodes || []).map(function (n) { return {name: n.name, address: n.address || ''}; });
  if (nodes.length < 2) nodes.push({name: 'acme2', address: '192.0.2.12'});
  var trusted = (lb.trusted || [])[0] || '';
  var v0 = {
    lb: LB_UI.lb || trusted.replace(/\/(32|128)$/, '') || '192.0.2.5',
    name: LB_UI.name || (lb.vip && lb.vip.fqdn) || lb.server_name || location.hostname,
    tls: LB_UI.tls || 'end', hc: LB_UI.hc || '/healthz'};
  host.appendChild(el('p', 'note', 'Both nodes answer everything, so any balancer spreads the pages round robin, without sticky sessions. Each node says GET /healthz: 200 "ok NODE" while it really works (the daemon, its database), 503 in maintenance or an upgrade - so the balancer takes it out by itself. Pick yours below: the configuration is filled in with this cluster\'s own names, addresses and ports, marked in colour, and follows what you type here.'));
  if (lb.vip && lb.vip.on) {
    host.appendChild(el('p', 'note warn', 'The built-in VIP address ' + lb.vip.address + ' is on: the pages need no balancer of yours. Use one or the other.'));
  }
  /* The values. */
  var form = el('div', 'lb-form');
  var field = function (words, key, ph, help) {
    var f = el('label', 'lb-f');
    f.appendChild(el('span', 'lb-f-k', words));
    var i = key === 'secret' ? maskBox('', '', 'mono') : textBox('', '', 'mono');
    i.value = v0[key]; i.placeholder = ph; i.spellcheck = false;
    i.oninput = function () { LB_UI[key] = i.value.trim(); lbKeep(); paint(); };
    f.appendChild(i);
    if (help) f.appendChild(el('span', 'arow-s', help));
    form.appendChild(f);
  };
  field('The balancer\'s address', 'lb', '192.0.2.5', 'its virtual address, the one people go to');
  field('The name people use', 'name', 'acme.example.cz', 'in its certificate');
  var segOf = function (words, key, opts) {
    var f = el('div', 'lb-f');
    f.appendChild(el('span', 'lb-f-k', words));
    var seg = el('div', 'seg');
    opts.forEach(function (o) {
      var b = el('button', '', o[1]); b.type = 'button';
      if (v0[key] === o[0]) b.classList.add('on');
      b.onclick = function () { v0[key] = LB_UI[key] = o[0]; lbKeep(); Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); paint(); };
      seg.appendChild(b);
    });
    f.appendChild(seg);
    form.appendChild(f);
  };
  segOf('TLS', 'tls', [['end', 'Ended on the balancer'], ['pass', 'Passed through (PROXY)']]);
  segOf('Health check', 'hc', [['/healthz', 'The pages'], ['/healthz?check=dns', '+ DNS server listening']]);
  host.appendChild(form);
  /* The nodes as they are. */
  var facts = el('div', 'lb-facts');
  nodes.forEach(function (n) {
    var c = el('span', 'cchip');
    c.appendChild(noI18n(el('b', '', n.name)));
    c.appendChild(noI18n(document.createTextNode(' ' + (n.address || '?'))));
    facts.appendChild(c);
  });
  host.appendChild(facts);
  var trust = el('div', 'lb-trust');
  host.appendChild(trust);
  var list = el('div', 'lb-list');
  host.appendChild(list);
  function values() {
    var v = {lb: LB_UI.lb || v0.lb, name: LB_UI.name || v0.name, hc: v0.hc, tls: v0.tls, nodes: nodes};
    nodes.forEach(function (n, i) { v['n' + i] = n.name; v['a' + i] = n.address || '192.0.2.1' + (i + 1); });
    return v;
  }
  function paint() {
    var v = values();
    /* The client's own address: are the nodes told the balancer's? */
    clear(trust);
    var ok = (lb.trusted || []).some(function (t) { return t.replace(/\/(32|128)$/, '') === v.lb; });
    if (v.tls === 'end') {
      trust.appendChild(el('div', 'note ' + (ok ? 'good' : 'warn'), ok
        ? 'The nodes already take the client\'s own address from X-Forwarded-For sent by ' + v.lb + '.'
        : 'Tell both nodes the balancer\'s address, so that the allow lists, the sign-in pause and every log see the client and not the balancer - as root on each node:'));
      if (!ok) trust.appendChild(lbBlock('acme --trusted-proxy {lb}/' + (v.lb.indexOf(':') >= 0 ? '128' : '32'), v, ''));
    } else {
      trust.appendChild(el('div', 'note', 'Passed through: in /etc/nginx/conf.d/acme.conf on both nodes, the PROXY protocol from the balancer only:'));
      trust.appendChild(lbBlock('listen 443 ssl proxy_protocol;        # in place of: listen 443 ssl;\nset_real_ip_from {lb};\nreal_ip_header proxy_protocol;\n\nnginx -t && systemctl reload nginx', v, ''));
    }
    clear(list);
    LB_GUIDES.concat([['check', 'Check it', 'after', function () {
      return [['From any machine: each node, then through the balancer; maintenance must take a node out',
        lbServers(v, function (n, i) { return 'curl -sk https://{a' + i + '}{hc}            # ok {n' + i + '}'; })
        + '\ncurl -sk https://{name}{hc}\n\n# on {n0}, as root:\nacme --maintenance on --why "balancer test"\n'
        + 'curl -sk https://{a0}/healthz             # 503 maintenance {n0} - the balancer sends everything to {n1}\nacme --maintenance off']];
    }]]).forEach(function (g) {
      var det = el('details', 'lb-guide');
      det.dataset.k = g[0];
      var sum = el('summary', '');
      sum.appendChild(el('b', '', g[1]));
      sum.appendChild(el('span', 'tag dim', g[2]));
      det.appendChild(sum);
      g[3](v).forEach(function (part) {
        if (part[1]) det.appendChild(lbBlock(part[1], v, part[0].replace(/\{name\}/g, v.name)));
        else det.appendChild(el('p', 'note', part[0].replace(/\{name\}/g, v.name)));
      });
      det.open = !!open[g[0]];
      det.ontoggle = function () { open[g[0]] = det.open; };
      list.appendChild(det);
    });
  }
  paint();
  host.appendChild(el('p', 'note', 'More, with the reasons: docs/load-balancers.md in the package.'));
}

/* ---- making the pair: the bundle on the first node, the join on the second (1.0.210) ----
   Each popup says what it will do, takes what it needs with the checks as it
   is typed, then shows every step live as the daemon does it - and the
   result, with the next step. */
var HA_PHRASE_ABC = 'abcdefghijkmnopqrstuvwxyz23456789';
function haIp(text) {
  var t = String(text || '').trim();
  if (/^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(t)) return true;
  return /^[0-9a-fA-F:]+$/.test(t) && t.indexOf(':') >= 0 && t.split('::').length <= 2;
}
/* Words with values in them: the words translated, the values kept as they are. */
function haWords() {
  var span = el('span', '');
  Array.prototype.forEach.call(arguments, function (p, i) {
    if (p === undefined || p === null || p === '') return;
    if (i % 2) span.appendChild(noI18n(el('b', 'mono', String(p))));
    else span.appendChild(document.createTextNode(String(p)));
  });
  return span;
}
function haWhen(ts) {
  if (!ts) return '';
  var d = new Date(ts * 1000);
  return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
}
/* A list of steps that fills in as they are done: waiting, running, done,
   failed or left out - each with what was said and, failed, what to do. */
function haLiveSteps(defs) {
  var list = el('div', 'steps ha-live');
  var rows = {};
  defs.forEach(function (d) {
    var row = el('div', 'step wait');
    var mark = el('span', 'step-mark');
    var words = el('span', 'step-words');
    words.appendChild(el('b', '', d.what));
    var said = el('span', 'd');
    words.appendChild(said);
    var more = el('div', 'ha-step-more');
    words.appendChild(more);
    row.appendChild(mark);
    row.appendChild(words);
    list.appendChild(row);
    rows[d.key] = {row: row, mark: mark, said: said, more: more};
  });
  list.set = function (key, state, text, fix, sub) {
    var r = rows[key];
    if (!r) return;
    r.row.className = 'step ' + state;
    r.mark.innerHTML = state === 'run' ? '<span class="ha-spin"></span>'
      : iconMarkup(state === 'ok' ? 'check' : (state === 'bad' ? 'cancel' : (state === 'warn' ? 'info' : 'next')), 15);
    r.said.textContent = text || (state === 'run' ? 'working on it…' : (state === 'skip' ? 'left out' : ''));
    clear(r.more);
    (sub || []).forEach(function (x) {
      var p = el('div', 'ha-sub ' + (x.ok ? 'ok' : 'bad'));
      p.appendChild(noI18n(el('span', 'ha-sub-mark', x.ok ? '✓' : '✗')));
      p.appendChild(el('span', '', x.said || ''));
      r.more.appendChild(p);
    });
    if (fix) {
      var f = el('div', 'note warn ha-fix');
      f.appendChild(el('b', '', 'What to do: '));
      f.appendChild(el('span', '', fix));
      r.more.appendChild(f);
    }
  };
  return list;
}
function haFoot(buttons) {
  var foot = $('modal-foot');
  clear(foot);
  var made = {};
  buttons.forEach(function (b) {
    var btn = cmdButton(b.words, b.icon || '', b.cls || '');
    if (b.left) btn.classList.add('left');
    btn.onclick = function () { b.go(btn); };
    foot.appendChild(btn);
    made[b.key || b.words] = btn;
  });
  return made;
}
function haPhraseBox() {
  /* The passphrase is a secret - it opens the key of every secret: dots only
     as it is typed. Taken in any case, with or without the dashes; shown in
     its five groups as they fill. */
  var wrap = el('div', 'ha-phrase');
  var box = maskBox('', '5 groups of 5 letters and digits', 'mono');
  box.id = 'ha-join-phrase';
  var meter = el('div', 'ha-phrase-meter');
  var groups = [];
  for (var i = 0; i < 5; i++) { var g = el('span', 'ha-pg'); meter.appendChild(g); groups.push(g); }
  var said = el('span', 'ha-phrase-said', '');
  meter.appendChild(said);
  wrap.appendChild(box);
  wrap.appendChild(meter);
  box._clean = function () {
    return String(box.value || '').toLowerCase().replace(/[\s-]+/g, '');
  };
  box._phrase = function () {
    var c = box._clean();
    return c.length === 25 ? c.match(/.{5}/g).join('-') : c;
  };
  box._ok = function () {
    var c = box._clean();
    return c.length === 25 && c.split('').every(function (ch) { return HA_PHRASE_ABC.indexOf(ch) >= 0; });
  };
  box.addEventListener('input', function () {
    var c = box._clean();
    var bad = c.split('').filter(function (ch) { return HA_PHRASE_ABC.indexOf(ch) < 0; });
    groups.forEach(function (g, n) {
      var part = c.slice(n * 5, n * 5 + 5);
      g.className = 'ha-pg' + (part.length === 5 ? ' full' : (part.length ? ' some' : ''));
    });
    wrap.classList.toggle('bad', !!bad.length || c.length > 25);
    clear(said);
    if (bad.length) said.appendChild(el('span', 'bad', 'it has letters a passphrase of acme never has (l, 0, 1 or others)'));
    else if (c.length > 25) said.appendChild(el('span', 'bad', 'too long: 25 letters and digits'));
    else if (c.length === 25) said.appendChild(el('span', 'good', 'complete'));
    else said.appendChild(haWords('', c.length, ' of 25'));
  });
  return wrap;
}

if ($('ha-bundle')) {
  $('ha-bundle').onclick = function () { haBundlePopup(false); };
  $('ha-join').onclick = haJoinPopup;
}

function haBundlePopup(prepareOnly) {
  var d = HA || {};
  var rep = !!(d.replication && d.replication.mode === 'replicated');
  var peer, host, peerSaid;
  var title = prepareOnly ? 'Prepare this node for the second one' : 'The bundle for the second node';
  modal(title, function (body) {
    var lead = el('div', 'ha-lead');
    lead.appendChild(noI18n(el('span', 'ha-lead-ico'))).innerHTML = iconMarkup('key', 22);
    var lw = el('div', '');
    lw.appendChild(el('b', '', prepareOnly ? 'Let the second node in, before it joins' : 'Everything the second node needs, locked'));
    lw.appendChild(el('p', 'note', prepareOnly
      ? 'This node lets the second one through its firewall at once, for 24 hours, and opens PostgreSQL here to it - what the join needs to reach this node.'
      : 'How to open the database, its password and the key that opens the sealed secrets - locked with a passphrase made here and shown once. Carry the file and the passphrase apart: the file over scp or a USB stick, the passphrase typed.'));
    lead.appendChild(lw);
    body.appendChild(lead);
    if (rep) {
      body.appendChild(kvTable([
        ['Mode', 'replicated - a PostgreSQL on each node'],
        ['The other node', noI18n(el('span', 'mono', d.peer || (d.replication || {}).peer || '?'))],
        ['This node', noI18n(el('span', 'mono', d.node + ' · ' + (d.address || '')))]]));
      body.appendChild(el('p', 'note', 'This node replicates already: the bundle makes the other node of the two - or makes it again, after it was lost or reinstalled. Join with it on that node, as root: acme --ha-join FILE.'));
      return;
    }
    peer = textBox((d.pending && d.pending[0] && d.pending[0].address) || '', '192.0.2.12', 'mono');
    peer.id = 'ha-b-peer';
    var pf = formField('The second node’s address', peer,
      'The node that will join. It is let through this node’s firewall at once, for 24 hours, and into PostgreSQL here (pg_hba.conf) - without it the join waits on both. Optional, but recommended.');
    peerSaid = el('div', 'ha-inline');
    pf.appendChild(peerSaid);
    body.appendChild(pf);
    peer.oninput = function () {
      clear(peerSaid);
      var v = peer.value.trim();
      if (!v) { peerSaid.appendChild(el('span', 'muted', 'none given: the firewall and PostgreSQL are left as they are')); return; }
      peerSaid.appendChild(haIp(v) ? el('span', 'good', '✓ an address') : el('span', 'bad', 'one address (IPv4 or IPv6), not a name or a range'));
    };
    peer.oninput();
    if (!prepareOnly) {
      host = textBox((d.db_host && ['localhost', '127.0.0.1', '::1', ''].indexOf(d.db_host) < 0) ? d.db_host : (d.address || ''), '192.0.2.11', 'mono');
      host.id = 'ha-b-host';
      body.appendChild(formField('PostgreSQL, as the second node reaches it', host, 'This machine’s address when PostgreSQL runs here; the server’s own address when it runs elsewhere.'));
    }
    var pg = d.pg_open;
    var facts = el('div', 'ha-facts');
    if (pg) {
      facts.appendChild(el('div', 'note ' + (pg.only_local ? 'warn' : 'good'), pg.only_local
        ? 'PostgreSQL runs on this machine and listens only on localhost: the second node cannot reach it yet. Given the second node’s address, it is opened to it here: listen_addresses, a line in pg_hba.conf (scram-sha-256), a restart of PostgreSQL - a few seconds.'
        : 'PostgreSQL runs on this machine and listens on the network; the second node’s line in pg_hba.conf is put in when its address is given.'));
    } else if (d.db_host) {
      facts.appendChild(haWords('PostgreSQL is not on this machine (', d.db_host, '): it has to let the second node in itself.'));
    }
    if (!d.fw_on) facts.appendChild(el('div', 'note muted small', 'acme does not manage this node’s firewall (Settings → Firewall): nothing to open there.'));
    (d.pending || []).forEach(function (x) {
      facts.appendChild(el('div', 'note info small')).appendChild(haWords('Let in already for being joined: ', x.address, ', until ', haWhen(x.until)));
    });
    body.appendChild(facts);
  }, [], 'medium');
  var btns = haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true},
    {key: 'go', words: prepareOnly ? 'Prepare it' : 'Make it', icon: prepareOnly ? 'net' : 'key', cls: 'primary', go: function (b) {
      var who = peer ? peer.value.trim() : '';
      if (who && !haIp(who)) { toast('the second node’s address: one address, IPv4 or IPv6', 'bad'); peer.focus(); return; }
      if (prepareOnly && !who) { toast('the second node’s address is needed', 'bad'); peer.focus(); return; }
      haBundleRun(who, host ? host.value.trim() : '', rep, prepareOnly);
    }}]);
  return btns;
}

function haBundleRun(peer, dbHost, rep, prepareOnly) {
  var d = HA || {};
  var body = $('modal-body');
  clear(body);
  var defs = [];
  if (!rep) {
    defs.push({key: 'pending', what: 'Letting the second node in'});
    defs.push({key: 'firewall', what: 'Opening this node’s firewall'});
    if (d.pg_open) defs.push({key: 'pg', what: 'Preparing PostgreSQL here'});
  }
  if (!prepareOnly) defs.push({key: 'bundle', what: 'Making the bundle'});
  var steps = haLiveSteps(defs);
  body.appendChild(steps);
  var result = el('div', 'ha-result');
  body.appendChild(result);
  haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true}]);
  var warned = [];
  var chain = Promise.resolve();
  function step(key, call) {
    chain = chain.then(function () {
      steps.set(key, 'run');
      return call().then(function (x) {
        var st = (x && x.steps) || [];
        var ok = st.every(function (s) { return s.ok; });
        var one = st.length === 1 ? st[0] : null;
        steps.set(key, ok ? (one && one.state === 'off' ? 'skip' : 'ok') : 'bad',
                  one ? one.said : (ok ? 'done' : 'not all of it worked'), one && one.fix, one ? null : st);
        if (!ok) warned.push(key);
      }, function (e) {
        steps.set(key, 'bad', e.message || String(e));
        warned.push(key);
      });
    });
  }
  if (!rep) {
    if (peer) {
      step('pending', function () { return api('ha', {action: 'prepare', step: 'pending', peer: peer}); });
      step('firewall', function () { return api('ha', {action: 'prepare', step: 'firewall', peer: peer}, 90); });
      if (d.pg_open) step('pg', function () { return api('ha', {action: 'prepare', step: 'pg', peer: peer}, 180); });
    } else {
      ['pending', 'firewall', 'pg'].forEach(function (k) { steps.set(k, 'skip', 'no address of the second node was given'); });
    }
  }
  if (prepareOnly) {
    chain.then(function () {
      result.appendChild(el('div', 'note ' + (warned.length ? 'warn' : 'good'), warned.length
        ? 'Not all of it worked - what failed says what to do. The join will fail on it until then.'
        : 'This node is ready for the second one: join it there now (Join a cluster… on its pages).'));
      loadHa();
    });
    return;
  }
  var made = null;
  chain = chain.then(function () {
    steps.set('bundle', 'run');
    return api('ha', {action: 'bundle', db_host: dbHost, peer: peer}).then(function (x) {
      made = x;
      steps.set('bundle', 'ok', 'locked with a passphrase made now');
    }, function (e) { steps.set('bundle', 'bad', e.message || String(e)); });
  });
  chain.then(function () {
    if (!made) return;
    var blob = new Blob([JSON.stringify(made.bundle, null, 1) + '\n'], {type: 'application/json'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = made.name;
    document.body.appendChild(link);
    link.click();
    setTimeout(function () { URL.revokeObjectURL(link.href); link.remove(); }, 1500);
    haBundleDone(result, made, peer, warned, blob.size);
    loadHa();
  });
}

function haBundleDone(host, made, peer, warned, size) {
  var file = el('div', 'ha-file ok');
  var ico = el('span', 'ha-file-ico'); ico.innerHTML = iconMarkup('download', 22); file.appendChild(ico);
  var fw = el('div', 'ha-file-w');
  fw.appendChild(noI18n(el('b', 'mono', made.name)));
  fw.appendChild(haWords('saved to your downloads · ', bytes(size)));
  file.appendChild(fw);
  host.appendChild(file);
  var pw = el('div', 'ha-pass');
  pw.appendChild(el('div', 'ha-pass-k', 'Its passphrase - shown only now. Write it down:'));
  var row = el('div', 'ha-pass-row');
  var code = noI18n(el('code', 'ha-pass-v', made.passphrase));
  row.appendChild(code);
  var cp = cmdButton('Copy', 'copy', 'small');
  cp.onclick = function () { copyText(made.passphrase, cp); };
  row.appendChild(cp);
  pw.appendChild(row);
  host.appendChild(pw);
  if (warned.length) host.appendChild(el('div', 'note warn', 'The bundle is made, but not every step before it worked (see above): the join fails until that is put right.'));
  var next = el('div', 'ha-next');
  next.appendChild(el('b', '', 'On the second node'));
  var ol = el('ol', '');
  if (made.mode === 'replicated') {
    ol.appendChild(el('li', '', 'Install the same version of acme there.'));
    var li = el('li', ''); li.appendChild(el('span', '', 'Copy the bundle over and join, as root:'));
    li.appendChild(noI18n(el('pre', 'mono small', 'acme --ha-join /root/' + made.name + ' --node-name acme2')));
    ol.appendChild(li);
  } else {
    ol.appendChild(el('li', '', 'Sign in to its pages: Settings → High availability → Join a cluster…'));
    ol.appendChild(el('li', '', 'Drop the bundle there and type the passphrase - or, as root:'));
    ol.appendChild(noI18n(el('pre', 'mono small', 'acme --ha-join /root/' + made.name + ' --node-name acme2')));
  }
  next.appendChild(ol);
  if (peer) next.appendChild(haWords('Only ', peer, ' is let in for it, for 24 hours - the database it will open: ', made.db_host, '.'));
  else next.appendChild(haWords('The database it will open: ', made.db_host, '.'));
  host.appendChild(next);
}

function haJoinPopup() {
  var d = HA || {};
  var st = {file: null, text: '', outer: null, opened: null, local: d.local || null};
  var phrase, name, sure, fileHost, openHost, sureHost, nameSaid, btns;
  modal('Join a cluster', function (body) {
    var lead = el('div', 'ha-lead');
    lead.appendChild(noI18n(el('span', 'ha-lead-ico'))).innerHTML = iconMarkup('net', 22);
    var lw = el('div', '');
    lw.appendChild(el('b', '', 'This node becomes the second node of a cluster'));
    lw.appendChild(el('p', 'note', 'It opens the cluster’s database and takes its key, and from then on answers the same as the first node, with the same accounts. Use the bundle made on the first node.'));
    lead.appendChild(lw);
    body.appendChild(lead);
    /* The bundle: a drop zone, then the file as a card with what it holds. */
    fileHost = el('div', 'ha-filehost');
    body.appendChild(fileHost);
    var inp = el('input'); inp.type = 'file'; inp.accept = '.json,application/json'; inp.hidden = true; inp.id = 'ha-join-file';
    body.appendChild(inp);
    inp.onchange = function () { take(inp.files && inp.files[0]); inp.value = ''; };
    fileHost._pick = function () { inp.click(); };
    drawFile();
    openHost = el('div', 'ha-openhost');
    body.appendChild(openHost);
    phrase = haPhraseBox();
    body.appendChild(formField('Its passphrase', phrase, 'Printed once when the bundle was made: five groups of five, dashes or not. Typed, it shows dots only.'));
    phrase.firstChild.addEventListener('input', function () { st.opened = null; drawOpened(); if (phrase.firstChild._ok() && st.text) tryOpen(); refresh(); });
    name = textBox(d.node || '', 'acme2', 'mono');
    name.id = 'ha-join-name';
    var nf = formField('This node’s name', name, 'How it is called among the nodes - in the list of nodes, in the logs, on the VIP address. Each node needs a name of its own, letters, digits, dots and dashes.');
    nameSaid = el('div', 'ha-inline');
    nf.appendChild(nameSaid);
    body.appendChild(nf);
    name.oninput = function () { drawName(); refresh(); };
    sureHost = el('div', 'ha-surehost');
    body.appendChild(sureHost);
    drawSure();
    drawName();
  }, [], 'medium');
  btns = haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true},
    {key: 'check', words: 'Check from here', icon: 'pulse', go: function () { run(false); }},
    {key: 'join', words: 'Join', icon: 'net', cls: 'primary', go: function () { run(true); }}]);
  refresh();

  function take(f) {
    st.file = f || null; st.text = ''; st.outer = null; st.opened = null; st.bad = '';
    if (!f) { drawFile(); refresh(); return; }
    if (f.size > 1 << 20) { st.bad = 'too big for a bundle'; drawFile(); refresh(); return; }
    var reader = new FileReader();
    reader.onload = function () {
      st.text = String(reader.result || '');
      try {
        var o = JSON.parse(st.text);
        if (!o || ['acme-ha-join', 'opt-ha-join'].indexOf(o.kind) < 0 || !o.locked) throw new Error('kind');
        st.outer = o;
      } catch (e) { st.bad = 'this is not a bundle made by acme (Make the bundle… on the first node, or acme --ha-bundle)'; }
      drawFile(); drawOpened(); refresh();
      if (st.outer && phrase.firstChild._ok()) tryOpen();
    };
    reader.readAsText(f);
  }
  function drawFile() {
    clear(fileHost);
    if (!st.file) {
      var drop = el('div', 'drop ha-drop');
      drop.id = 'ha-join-drop';
      var ico = el('span', 'ha-drop-ico'); ico.innerHTML = iconMarkup('upload', 26); drop.appendChild(ico);
      var w = el('div', 'ha-drop-w');
      w.appendChild(el('b', '', 'Drop the bundle here, or press to choose it'));
      w.appendChild(noI18n(el('span', 'mono small', 'acme-join-NODE-DATE.json')));
      drop.appendChild(w);
      drop.onclick = fileHost._pick;
      ['dragenter', 'dragover'].forEach(function (n) { drop.addEventListener(n, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
      drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
      drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); take(e.dataTransfer && e.dataTransfer.files[0]); });
      fileHost.appendChild(drop);
      return;
    }
    var card = el('div', 'ha-file' + (st.bad ? ' bad' : ''));
    var ico2 = el('span', 'ha-file-ico'); ico2.innerHTML = iconMarkup(st.bad ? 'cancel' : 'key', 22); card.appendChild(ico2);
    var w2 = el('div', 'ha-file-w');
    w2.appendChild(noI18n(el('b', 'mono', st.file.name)));
    var o = st.outer || {};
    w2.appendChild(o.made ? haWords('', bytes(st.file.size), ' · made ', haWhen(o.made), ' by ', o.from, ' · acme ', o.version) : haWords('', bytes(st.file.size)));
    card.appendChild(w2);
    var again = cmdButton('Another file', 'refresh', 'small');
    again.onclick = function () { take(null); };
    card.appendChild(again);
    fileHost.appendChild(card);
    if (st.bad) { fileHost.appendChild(el('div', 'note bad', st.bad)); return; }
    var a = o.about || null;
    if (a) {
      fileHost.appendChild(kvTable([
        ['Cluster', noI18n(el('b', '', a.cluster || '?'))],
        ['The first node', noI18n(el('span', 'mono', (a.node || '?') + ' · ' + (a.address || '?')))],
        ['Mode', a.mode === 'replicated' ? 'replicated - a PostgreSQL on each node' : 'shared - both nodes open one PostgreSQL'],
        ['The database it will open', noI18n(el('span', 'mono', a.mode === 'replicated' ? 'its own PostgreSQL, copied from ' + (a.node || '?') : a.db))],
        a.joining ? ['Made for', noI18n(el('span', 'mono', a.joining))] : null]));
    } else {
      fileHost.appendChild(el('div', 'note muted small', 'A bundle of an earlier version: what it holds is shown once the passphrase opens it.'));
    }
    if (o.version && d.version && o.version !== d.version) fileHost.appendChild(haWords('Made by acme ', o.version, ', this node runs ', d.version, ': both nodes should run the same version.'));
    if (a && a.mode === 'replicated') {
      var r = el('div', 'note warn');
      r.appendChild(el('span', '', 'A replicated cluster: this node gets a PostgreSQL of its own, which takes root on this machine (installing and setting it up). Copy the bundle here and run, as root:'));
      r.appendChild(noI18n(el('pre', 'mono small', 'acme --ha-join /root/' + st.file.name + ' --node-name ' + (name ? name.value || 'acme2' : 'acme2'))));
      fileHost.appendChild(r);
    }
  }
  function tryOpen() {
    var phr = phrase.firstChild._phrase();
    api('ha', {action: 'join_step', step: 'bundle', bundle: st.text, passphrase: phr}).then(function (x) {
      st.opened = x.bundle; st.local = x.local; st.phraseBad = '';
      drawOpened(); drawSure(); refresh();
    }).catch(function (e) { st.opened = null; st.phraseBad = e.message || String(e); drawOpened(); refresh(); });
  }
  function drawOpened() {
    clear(openHost);
    if (st.phraseBad) { openHost.appendChild(el('div', 'note bad', st.phraseBad)); return; }
    if (!st.opened) return;
    var v = st.opened;
    var p = el('div', 'note good ha-opened');
    p.appendChild(haWords('✓ The passphrase opens it: the cluster ', v.cluster, ' of ', v.node, ' (', v.address, '), the database ', v.db, ' as ', v.db_user, '.'));
    openHost.appendChild(p);
    if (!name.value || name.value === v.node) drawName();
  }
  function drawName() {
    clear(nameSaid);
    var v = name.value.trim();
    var first = (st.opened && st.opened.node) || ((st.outer || {}).about || {}).node || '';
    if (!v) nameSaid.appendChild(el('span', 'bad', 'a name is needed'));
    else if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(v)) nameSaid.appendChild(el('span', 'bad', 'letters, digits, dots, dashes and _ - 63 at most'));
    else if (first && v === first) nameSaid.appendChild(el('span', 'bad', 'that is the first node’s name: each node needs its own'));
    else nameSaid.appendChild(el('span', 'good', '✓'));
  }
  function nameOk() {
    var v = name.value.trim();
    var first = (st.opened && st.opened.node) || ((st.outer || {}).about || {}).node || '';
    return /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(v) && v !== first;
  }
  function drawSure() {
    clear(sureHost);
    sure = null;
    var l = st.local;
    if (!l || !l.held) return;
    var box = el('div', 'ha-sure');
    box.appendChild(el('b', '', 'This node has data of its own'));
    var what = el('p', 'note small ha-held');
    if (l.certs) what.appendChild(haWords('', l.certs, ' certificate(s)'));
    if (l.accounts > 1) what.appendChild(haWords('', l.accounts, ' accounts'));
    if (l.sealed) what.appendChild(el('span', '', 'sealed secrets (private keys, passwords)'));
    box.appendChild(what);
    box.appendChild(el('p', 'note', 'Joining does not delete them, but leaves them behind: this node then works only with the cluster’s database and key. They stay in its old database, and its key is kept as secrets.key.before-join - but nothing uses them any more. To keep a certificate, export it first.'));
    sure = switchBox(false);
    sure._input.id = 'ha-join-sure';
    var lab = el('label', 'ha-sure-sw');
    lab.appendChild(sure);
    lab.appendChild(el('span', '', 'Leave what this node has behind, and join'));
    box.appendChild(lab);
    sure._input.onchange = refresh;
    sureHost.appendChild(box);
  }
  function ready() {
    return !!(st.outer && !st.bad && phrase.firstChild._ok() && st.opened && st.opened.mode !== 'replicated');
  }
  function refresh() {
    if (!btns) return;
    var r = ready();
    btns.check.disabled = !r;
    btns.join.disabled = !r || !nameOk() || !!(sure && !sure._get());
  }
  function run(join) {
    var phr = phrase.firstChild._phrase();
    var body = $('modal-body');
    var keep = Array.prototype.slice.call(body.children);
    keep.forEach(function (c) { c.hidden = true; });
    var defs = [{key: 'bundle', what: 'Checking the bundle'}, {key: 'firewall', what: 'Opening the firewall to the first node'},
                {key: 'db', what: 'Reaching the database'}];
    if (join) defs.push({key: 'key', what: 'Taking the key'}, {key: 'restart', what: 'Starting again on the cluster’s database'});
    var head = el('div', 'ha-run-head');
    head.appendChild(haWords(join ? 'Joining the cluster ' : 'Checking from here: ', st.opened.cluster, join ? ' as ' : ', the first node ', join ? name.value.trim() : st.opened.address, ''));
    body.appendChild(head);
    var steps = haLiveSteps(defs);
    body.appendChild(steps);
    var result = el('div', 'ha-result');
    body.appendChild(result);
    var back = function () { head.remove(); steps.remove(); result.remove(); keep.forEach(function (c) { c.hidden = false; }); foot(); };
    var foot = function () {
      btns = haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true},
        {key: 'check', words: 'Check from here', icon: 'pulse', go: function () { run(false); }},
        {key: 'join', words: 'Join', icon: 'net', cls: 'primary', go: function () { run(true); }}]);
      refresh();
    };
    haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true}]);
    var failed = false;
    var one = function (key, call, wait) {
      return function () {
        if (failed) return null;
        steps.set(key, 'run');
        return api('ha', call, wait).then(function (x) {
          var s = (x.steps || [])[0] || {ok: true};
          steps.set(key, s.ok ? (s.state === 'off' ? 'skip' : 'ok') : (key === 'firewall' ? 'warn' : 'bad'), s.said, s.fix);
          if (!s.ok && key !== 'firewall') failed = true;
          return x;
        }, function (e) { steps.set(key, 'bad', e.message || String(e)); failed = true; });
      };
    };
    var base = {action: 'join_step', bundle: st.text, passphrase: phr};
    var chain = Promise.resolve()
      .then(one('bundle', Object.assign({step: 'bundle'}, base)))
      .then(one('firewall', Object.assign({step: 'firewall'}, base), 90))
      .then(one('db', Object.assign({step: 'db'}, base), 60));
    if (!join) {
      chain.then(function () {
        result.appendChild(el('div', 'note ' + (failed ? 'bad' : 'good'), failed
          ? 'Not reached from here - what failed says why and what to do. Nothing on this node was changed except its firewall.'
          : 'Everything the join needs answers from here. Nothing on this node was changed except its firewall: press Join to go on.'));
        haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true}, {words: 'Back', icon: 'prev', go: back}]);
      });
      return;
    }
    chain.then(function () {
      if (failed) return null;
      steps.set('key', 'run');
      return api('ha', {action: 'join', bundle: st.text, passphrase: phr, name: name.value.trim(),
                        even_if_data: !!(sure && sure._get())}, 120).then(function (x) {
        var k = (x.steps || []).filter(function (s) { return s.key === 'key'; })[0];
        steps.set('key', 'ok', (k && k.said) || 'the key is the cluster’s');
        steps.set('restart', 'run', 'acme starts again on ' + (x.where || 'the cluster’s database'));
        return haWaitBack().then(function (ok) {
          steps.set('restart', ok ? 'ok' : 'warn', ok ? 'it answers again, on the cluster’s database' : 'it has not answered yet - it may take a little longer');
          var r = el('div', 'ha-done');
          r.appendChild(el('b', '', 'This node is now one of the cluster'));
          r.appendChild(el('p', 'note', 'Sign in again - with the cluster’s accounts: the ones of this node were in its own database, which is no longer used. Both nodes are then in the list on this page.'));
          result.appendChild(r);
          haFoot([{words: 'Sign in again', icon: 'in', cls: 'primary', go: function () { location.reload(); }}]);
        });
      }, function (e) { steps.set('key', 'bad', e.message || String(e)); failed = true; });
    }).then(function () {
      if (failed) {
        result.appendChild(el('div', 'note bad', 'The join did not go on: nothing on this node was changed but its firewall. Put right what failed, then try again.'));
        haFoot([{words: 'Close', icon: 'close', go: closeModal, left: true}, {words: 'Back', icon: 'prev', go: back}]);
      }
    });
  }
}
/* After the join: the daemon goes away for a moment and comes back on the
   cluster's database - asked for its health until it answers again. */
function haWaitBack() {
  var t0 = Date.now(), seenDown = false;
  return new Promise(function (done) {
    var ask = function () {
      fetch('?api=health', {credentials: 'same-origin', cache: 'no-store'}).then(function (r) {
        return r.ok ? r.json() : null;
      }).catch(function () { return null; }).then(function (h) {
        if (!h || !h.database) seenDown = true;
        if (h && h.database && h.database.ok && (seenDown || Date.now() - t0 > 12000)) { done(true); return; }
        if (Date.now() - t0 > 120000) { done(false); return; }
        setTimeout(ask, 1500);
      });
    };
    setTimeout(ask, 2500);
  });
}

/* ---- the replication between the two PostgreSQLs (1.0.14) ---- */
function drawHaRep(d, live) {
  var r = d.replication || {};
  var card = $('ha-rep-card');
  card.hidden = r.mode !== 'replicated';
  if (r.mode !== 'replicated') return;
  $('ha-rep-said').textContent = r.healthy ? 'both directions running' : 'needs a look';
  $('ha-rep-said').className = 'right ' + (r.healthy ? 'good' : 'bad');
  var host = $('ha-rep');
  liveFill(host, function (host) {
  /* Said plainly when the link between the databases is not checked
     (1.0.101): whoever is between the nodes reads every row going over -
     sealed keys, hashed codes, the log - and can write rows of their own. */
  host.appendChild(haLinkBar(d));
  var rows = [];
  (r.incoming || []).forEach(function (x) {
    var base = (d.errbase || {})[x.name] || {};
    var all = (x.apply_errors || 0) + (x.sync_errors || 0);
    rows.push({dir: 'in', from: r.peer, to: d.node, state: !x.enabled ? 'paused' : (x.running ? 'running' : 'not running'),
               ok: x.enabled && x.running, when: x.last_msg, errors: Math.max(0, all - (base.apply || 0) - (base.sync || 0)),
               before: all});
  });
  if (!(r.incoming || []).length) rows.push({dir: 'in', from: r.peer, to: d.node, state: 'not set up', ok: false});
  (r.outgoing || []).forEach(function (x) {
    rows.push({dir: 'out', from: d.node, to: r.peer, state: x.wal_status === 'lost' ? 'lost - rebuild the other node'
               : (x.active ? 'taken' : 'waiting for the other node'), ok: x.active && x.wal_status !== 'lost',
               behind: x.behind, wal: x.wal_status});
  });
  if (!(r.outgoing || []).length) rows.push({dir: 'out', from: d.node, to: r.peer, state: 'not set up', ok: false});
  host.appendChild(listTable(['Direction', 'From', 'To', 'State', 'Last heard', {words: 'Waiting to go over', cls: 'num'}, 'Errors'], rows, function (x) {
    var tr = el('tr');
    tr.appendChild(el('td', '', x.dir === 'in' ? 'coming in' : 'going out'));
    tr.appendChild(noI18n(el('td', 'mono small', x.from || '')));
    tr.appendChild(noI18n(el('td', 'mono small', x.to || '')));
    var st = el('td'); st.appendChild(el('span', 'tag ' + (x.ok ? 'ok' : (x.state === 'paused' ? 'warn' : 'crit')), x.state)); tr.appendChild(st);
    tr.appendChild(el('td', 'muted', x.when ? ago(x.when) : '–'));
    tr.appendChild(el('td', 'num', x.behind !== undefined ? bytes(x.behind) : '–'));
    var ec = el('td');
    if (x.errors) {
      /* A click says what they were (1.0.52). */
      var eb = el('button', 'linkish bad', num(x.errors) + ' - what?');
      eb.type = 'button';
      eb.title = 'What PostgreSQL said, and clearing them';
      eb.onclick = haErrors;
      ec.appendChild(eb);
    } else {
      ec.appendChild(el('span', 'muted', x.dir === 'in' && x.before ? '– (cleared)' : '–'));
    }
    tr.appendChild(ec);
    return tr;
  }));
  if (r.lost) host.appendChild(el('p', 'note bad', 'The other node was away longer than what is kept for it: rebuild it from this one - on the other node, Rebuild this node from the other.'));
  if (r.trouble) host.appendChild(el('p', 'note bad', r.trouble));
  }, live);
  var paused = (r.incoming || []).some(function (x) { return !x.enabled; });
  $('ha-pause').disabled = paused;
  $('ha-resume').disabled = !paused && r.healthy;
  if (d.job && d.job.running) haWatch();
  drawHaAddr(d, live);
}
/* The addresses of the two nodes (1.0.106): seen, checked against what this
   machine has, and changed in place - this node put right, the other told. */
function drawHaAddr(d, live) {
  var a = d.readdress;
  var card = $('ha-addr-card');
  card.hidden = !a;
  if (!a) return;
  var host = $('ha-addr');
  liveFill(host, function (host) {
  $('ha-addr-said').textContent = a.mine_here ? '' : 'this node’s address is not on this machine';
  $('ha-addr-said').className = 'right ' + (a.mine_here ? '' : 'bad');
  var grid = el('div', 'formgrid');
  var mine = textBox(a.mine || a.detected || '', a.detected || '192.0.2.11', 'mono');
  var peer = textBox(a.peer || '', '192.0.2.12', 'mono');
  var f1 = formField('This node (' + d.node + ') is reached at', mine);
  f1.appendChild(el('div', 'small muted', 'This machine has: ' + ((a.addresses || []).join(', ') || '?')));
  grid.appendChild(f1);
  grid.appendChild(formField('The other node is at', peer));
  host.appendChild(grid);
  if (!a.mine_here && a.mine) {
    host.appendChild(el('p', 'note warn', 'config.json says this node is reached at ' + a.mine
      + ', which is not an address of this machine any more. If it moved, put its new address above and save here - or, better, on the other node as the other node’s address.'));
  }
  if (a.last && a.last.done && a.last.from !== d.node) {
    host.appendChild(el('p', 'note ' + (a.last.error ? 'bad' : 'muted small'),
      (a.last.error ? 'Told by ' + a.last.from + ', it could not be done: ' + a.last.error
        : 'Last told by ' + a.last.from + ' (' + ago(a.last.done) + '): ' + (a.last.said || ''))));
  }
  if (ME.role === 'fulladmin') {
    var row = el('div', 'btnrow');
    row.style.marginTop = '10px';
    var go = cmdButton('Change the addresses', 'save', 'primary');
    go.id = 'ha-addr-save';
    go.onclick = function () {
      confirmThen('Change the addresses of the cluster?',
        'This node: ' + htmlText(mine.value) + ' · the other node: ' + htmlText(peer.value)
        + '<br>This node’s pg_hba.conf, its subscription and its config.json are put right now, and the other node is told when it can be reached. Replication catches up by itself.',
        'Change them', function () {
          busy(go, true);
          api('ha', {action: 'readdress', mine: mine.value.trim(), peer: peer.value.trim()}).then(function (x) {
            busy(go, false);
            modal('The addresses of the cluster', function (body) {
              (x.done || []).forEach(function (t) { body.appendChild(el('p', 'note good', '✓ ' + t)); });
              (x.left || []).forEach(function (t) { body.appendChild(el('p', 'note warn', t)); });
              if (!(x.done || []).length && !(x.left || []).length) body.appendChild(el('p', 'note', x.message || ''));
            }, [{words: 'Close', close: true}], 'medium');
            loadHa();
          }).catch(function (e) { busy(go, false); oops(e); });
        }, false);
    };
    row.appendChild(go);
    host.appendChild(row);
  }
  }, live);
}
function haDo(act, words) {
  /* The node the page showed goes with it (1.0.94): behind a balancer the
     request may reach the other one, and "what comes in" is the other way
     round there. */
  return api('ha', {action: act, node: (HA && HA.node) || ''}).then(function (x) { toast(x.message || words, 'good'); loadHa(); }).catch(oops);
}
var HA_WATCHING = null;
var HA_MISSES = 0;
function haWatch() {
  if (HA_WATCHING) return;
  HA_WATCHING = true;
  goingOpen($('ha-going'));
  var step = function () {
    api('db', {action: 'job'}).then(function (d) {
      HA_MISSES = 0;
      var j = d.job || {};
      $('ha-going-fill').style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
      $('ha-going-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '');
      if (j.running) { HA_WATCHING = setTimeout(step, TAB === 'settings' && PANE === 'ha' ? 1000 : 5000); return; }
      HA_WATCHING = null;
      goingCloser($('ha-going'));
      if (j.error) { toast(j.error, 'bad'); return; }
      if (j.result && j.result.rows !== undefined) toast('rebuilt from the other node: ' + num(j.result.rows) + ' row(s)', 'good');
      loadHa();
    }).catch(function (e) {
      /* Not reachable for a moment - a restart, the VIP address moving
         (1.0.66): asked again, the job goes on regardless. */
      if (e && e.unreachable && ++HA_MISSES < 100) { HA_WATCHING = setTimeout(step, 3000); return; }
      HA_MISSES = 0; HA_WATCHING = null; oops(e);
    });
  };
  step();
}
var HA_MAKE_OPEN = false;
if ($('ha-make-btn')) {
  $('ha-make-btn').onclick = function () {
    HA_MAKE_OPEN = !HA_MAKE_OPEN;
    $('ha-make-body').hidden = !HA_MAKE_OPEN;
    setButtonIcon($('ha-make-btn'), HA_MAKE_OPEN ? 'close' : 'eye', HA_MAKE_OPEN ? 'Fold the steps away' : 'Show how it was made');
  };
}
if ($('ha-pause')) {
  $('ha-pause').onclick = function () {
    modal('Pause the replication', function (body) {
      body.appendChild(el('p', 'note', 'Both nodes go on answering, each with its own database; neither sends the other anything until it is resumed. What is written meanwhile waits on each node for the other - up to 16 GB of it - and goes over when it is resumed.'));
      body.appendChild(el('p', 'note', 'Or only one direction:'));
    }, [{words: 'Close', close: true},
        {words: 'Only what comes in', icon: 'power', close: true, go: function () { haDo('pause_in'); }},
        {words: 'Only what goes out', icon: 'power', close: true, go: function () { haDo('pause_out'); }},
        {words: 'Pause both', cls: 'primary', icon: 'power', close: true, go: function () { haDo('pause'); }}], 'medium');
  };
  $('ha-resume').onclick = function () { haDo('resume'); };
  $('ha-refresh').onclick = function () { haDo('refresh'); };
  $('ha-resync').onclick = function () {
    confirmThen('Rebuild this node from the other', 'Everything in <b>this</b> node’s database is replaced by what the other holds: its tables emptied and every row copied over, and both directions made afresh. A copy of what is here is made first. What was written here and never reached the other is only in that copy. You will be signed out.', 'Rebuild it', function () {
      // The node this page showed (1.0.59): behind a balancer the request
      // may land on the other one, which is refused rather than rebuilt.
      api('ha', {action: 'resync', node: (HA && HA.node) || ''}).then(function () { haWatch(); }).catch(oops);
    });
  };
  $('ha-stop').onclick = function () {
    confirmThen('Switch the replication off', 'Both subscriptions and their slots are taken away. Each node goes on alone with what it has, and from then on they drift apart. Putting them together again is a rebuild of one from the other.', 'Switch it off', function () { haDo('stop'); });
  };
}

/* The Test tab's password box, masked like every other (1.0.22). */
(function () {
  var old = $('rt-pass');
  if (!old || old.classList.contains('masked')) return;
  var box = maskBox('', '', 'mono');
  box.id = 'rt-pass';
  old.parentNode.replaceChild(box, old);
})();

/* Signed out after the idle time even with the page left open (1.0.33): the
   live refresh asks the daemon every few seconds, which kept the sign-in
   fresh for ever. What counts is a person using the page. */
(function () {
  var last = Date.now(), limit = 0;
  ['mousemove', 'keydown', 'click', 'scroll', 'touchstart', 'wheel'].forEach(function (e) {
    document.addEventListener(e, function () { last = Date.now(); }, {passive: true, capture: true});
  });
  api('whoami').then(function (d) { limit = (d.idle_min || 120) * 60000; }).catch(function () {});
  setInterval(function () {
    if (limit && Date.now() - last > limit) {
      limit = 0;
      api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); });
    }
  }, 30000);
})();

/* ---- upgrades and maintenance (1.0.37) ------------------------------------ */
var UP = {timer: null, held: null, misses: 0};
var UP_STATE = {waiting: ['waiting', 'dim'], none: ['waiting', 'dim'], draining: ['taken out of service', 'warn'],
                installing: ['being put in', 'info'], checking: ['checking', 'info'],
                done: ['done', 'ok'], failed: ['failed', 'crit']};
function upgradeSend(file) {
  return bigFetch('?api=upgrade-package', file)
    .then(function (r) {
      return r.json().catch(function () {
        throw new Error('the server did not answer with anything readable (HTTP ' + r.status + ')');
      }).then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    });
}
/* Is this settings pane the one in front, in a tab in front (1.0.57)? The
   timers asked for their pane every 5 s after leaving Settings, and in tabs
   in the background, for as long as the page stayed open. */
function paneLive(name) {
  return TAB === 'settings' && PANE === name && $('pane-' + name) && !$('pane-' + name).hidden;
}
function upgradeAgain(ms) {
  /* Never dropped while the pane is open (1.0.73): in a tab in the
     background it waits and goes on when the tab is shown again, where
     before it stopped for good and only F5 brought it back. */
  clearTimeout(UP.timer);
  UP.timer = setTimeout(function () {
    if (!paneLive('upgrade')) return;
    if (document.hidden) { UP.sleeping = true; return; }
    loadUpgrade(true);
  }, ms);
}
document.addEventListener('visibilitychange', function () {
  if (!document.hidden && UP.sleeping) { UP.sleeping = false; if (paneLive('upgrade')) loadUpgrade(); }
});
function maintenanceAsk(n, on, then) {
  var alone = (UP.last && (UP.last.nodes || []).filter(function (x) { return x.alive; }).length) <= 1;
  if (!on) {
    api('upgrade', {action: 'maintenance', node: n.name, on: false}).then(function (r) { toast(r.message, 'good'); then(r); }).catch(oops);
    return;
  }
  modal('Take ' + n.name + ' out of service', function (body) {
    var p = el('p', 'note');
    p.textContent = alone
      ? 'This is the only server: while it is in maintenance no certificate is renewed or put in place. Its pages go on working.'
      : 'It renews and puts in place nothing and its /healthz says 503: the load balancer and the VIP address go to the other node, which does the work. Its pages go on working.';
    if (alone) p.className = 'note bad';
    body.appendChild(p);
    var why = textBox('', 'why - for the events', '');
    why.id = 'maint-why';
    body.appendChild(formField('Why', why));
  }, [{words: 'No, leave it', close: true},
      {words: 'Take it out', cls: alone ? 'danger' : 'primary', icon: 'power', close: true, go: function () {
        api('upgrade', {action: 'maintenance', node: n.name, on: true, why: ($('maint-why') || {}).value || ''})
          .then(function (r) { toast(r.message, 'good'); then(r); }).catch(oops);
      }}], true);
}
/* Behind the VIP address the answers come from either node, and while one
   is restarting or the address moves, the other's copy of a step may be a
   moment behind (1.0.70): what was shown is never taken back by an older
   answer - each node's step only goes forward. */
function upSteady(d) {
  var p = d && d.plan;
  if (!p) return d;
  /* A plan older than the one shown, from a node whose copy is behind
     (1.0.73): not drawn - the one shown stays. */
  if (UP.keep && UP.keep.id !== p.id && Number(p.at || 0) < Number(UP.keep.at || 0) && UP.last && UP.last.plan) {
    d.plan = UP.last.plan;
    return d;
  }
  if (!UP.keep || UP.keep.id !== p.id) UP.keep = {id: p.id, at: p.at, steps: {}};
  (p.steps || []).forEach(function (st, i) {
    var k = UP.keep.steps[st.name];
    if (k && Number(k.at || 0) > Number(st.at || 0)) p.steps[i] = k;
    else UP.keep.steps[st.name] = st;
  });
  var states = (p.steps || []).map(function (x) { return x.state; });
  if (states.indexOf('failed') >= 0) p.state = 'failed';
  else if (states.length && states.every(function (x) { return x === 'done'; })) p.state = 'done';
  return d;
}
/* New versions on the web (1.0.123): what the address had when last asked,
   and one click to put the newest in. */
function drawUpWeb(d) {
  var w = d.web || {};
  var o = w.online || {};
  liveFill($('up-web'), function (host) {
    var p = el('p', 'note ' + (o.error ? 'bad' : (o.newer ? 'good' : '')));
    if (!o.at) p.textContent = w.check ? 'Not looked at yet - within minutes, or press Look now.' : 'Not looked at: looking every day is switched off below. Look now asks once.';
    else if (o.error) p.textContent = 'Looked ' + ago(o.at) + ': ' + o.error;
    else if (o.newer) p.textContent = 'acme ' + o.newest.version + ' is there - this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else if (o.newest) p.textContent = 'Nothing newer: the newest there is ' + o.newest.version + ' and this server runs ' + (o.here || d.version) + ' (looked ' + ago(o.at) + ')';
    else p.textContent = 'No acme package there (looked ' + ago(o.at) + ')';
    host.appendChild(p);
    /* One chain above (1.0.146): the line for several newer versions sat in
       the middle of it and every case below it said the wrong thing. */
    if (o.at && !o.error && o.newer && (o.newer_list || []).length > 1) {
      host.appendChild(el('p', 'note', num(o.newer_list.length) + ' versions there are newer than this one - choose which to go to; the newest is chosen.'));
    }
    if (o.url) host.appendChild(noI18n(el('p', 'mono small muted', o.url)));
    var row = el('div', 'btnrow');
    var look = cmdButton('Look now', 'refresh', '');
    look.onclick = function () {
      busy(look, true);
      api('upgrade', {action: 'online_look'}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
        .catch(oops).then(function () { busy(look, false); });
    };
    row.appendChild(look);
    var running = !!(d.plan && d.plan.state === 'running');
    if (o.newer && !running) {
      /* More than one newer there (1.0.142): which one, the newest chosen. */
      var list = (o.newer_list || []).filter(function (x) { return x && x.version; });
      var pick = list[0] && list[0].version === o.newest.version ? list[0] : o.newest;
      var choose = null;
      if (list.length > 1) {
        choose = selectBox(list.map(function (x, i) {
          return [x.version, x.version + (i === 0 ? ' (the newest)' : '')];
        }), pick.version);
        explain(choose, 'The versions there newer than the one this server runs. The newest is chosen; any of them can be put in instead.');
        row.appendChild(choose);
      }
      var up = cmdButton('Upgrade to ' + pick.version + ' now', 'play', 'primary');
      var chosen = function () {
        var v = choose ? choose.value : o.newest.version;
        return list.filter(function (x) { return x.version === v; })[0] || o.newest;
      };
      if (choose) {
        choose.onchange = function () {
          setButtonIcon(up, 'play', 'Upgrade to ' + chosen().version + ' now');
        };
      }
      up.onclick = function () {
        var many = (d.nodes || []).length > 1;
        var c = chosen();
        confirmThen('Upgrade to acme ' + c.version + '?', htmlText('It is fetched from ' + (c.url || o.url) + ', its signature checked, and '
          + (many ? 'the nodes are upgraded one at a time - each in maintenance while it is, so the service never stops.' : 'this server is upgraded: for a minute nothing is renewed or put in place.')), 'Upgrade', function () {
          busy(up, true);
          api('upgrade', {action: 'online_get', version: c.version, start: true}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
            .catch(oops).then(function () { busy(up, false); });
        }, false);
      };
      row.appendChild(up);
      var only = cmdButton('Only fetch it', 'down', '');
      explain(only, 'Fetched and checked, and left ready below - put in when Upgrade is pressed.');
      only.onclick = function () {
        busy(only, true);
        api('upgrade', {action: 'online_get', version: chosen().version}).then(function (x) { toast(x.message, 'good'); drawUpgrade(x); })
          .catch(oops).then(function () { busy(only, false); });
      };
      row.appendChild(only);
    }
    host.appendChild(row);
  });
}
/* Going back to an older version (1.0.143): asked for on purpose, in a card
   of its own - the versions at upgrade_url older than this one, each with what
   stands in its way; the database is checked against the one chosen. */
function upDownConfirm(version, go) {
  var d = UP.last || {};
  var many = (d.nodes || []).filter(function (n) { return n.alive; }).length > 1;
  confirmThen('Go back to acme ' + version + '?', htmlText('The version running now is replaced by the older ' + version + (many
    ? ' on every node, one at a time - each in maintenance while it is, so the service never stops.'
    : ' - for a minute nothing is renewed or put in place.') + ' The database stays as it is. What came in the newer versions is gone until you upgrade again.'),
    'Go back', go, true);
}
function upDownChangelog(version) {
  api('upgrade', {action: 'downgrade_changelog', version: version}).then(function (x) {
    var c = x.changelog || {};
    modal('What changed in ' + version, function (body) {
      if (c.from === 'package') body.appendChild(el('p', 'note small', 'Read from the package at the address - it is checked only when it is chosen.'));
      body.appendChild(c.entry ? noI18n(el('pre', 'lines', c.entry)) : el('p', 'note', 'The package says nothing about this version.'));
      if ((c.lost || []).length) {
        var det = el('details', 'fold');
        det.appendChild(el('summary', '', 'What going back gives up: ' + c.lost.length + ' newer version(s), up to ' + c.here));
        c.lost.forEach(function (one) { det.appendChild(noI18n(el('pre', 'lines', one.text))); });
        body.appendChild(det);
      }
    }, [{words: 'Close', close: true}], 'medium');
  }).catch(oops);
}
function drawUpDown(d) {
  var card = $('up-down-card');
  /* Offered only when switched on (1.0.144): Settings → Upgrades. */
  if (card) card.hidden = !(d && d.downgrade_on);
  var host = $('up-down');
  if (!host || host._made || !(d && d.downgrade_on)) return;
  host._made = true;
  var row = el('div', 'btnrow');
  var show = cmdButton('Show the versions to go back to', 'list', '');
  row.appendChild(show);
  host.appendChild(row);
  var list = el('div', '');
  host.appendChild(list);
  show.onclick = function () {
    busy(show, true);
    api('upgrade', {action: 'downgrade_list'}).then(function (x) {
      var g = x.downgrade || {};
      clear(list);
      var at = el('p', 'note small', 'At ' + (g.url || '?') + ' - this server runs ' + (g.here || '') + '; it may go back to ' + (g.lowest || g.floor || '?') + ' or newer.');
      at.style.marginTop = '10px';
      list.appendChild(at);
      var vs = g.versions || [];
      if (!vs.length) { list.appendChild(el('p', 'note', 'No version older than this one is there.')); return; }
      var running = !!((UP.last || {}).plan && UP.last.plan.state === 'running');
      var good = vs.filter(function (v) { return !(v.why || []).length; });
      var bad = vs.filter(function (v) { return (v.why || []).length; });
      /* One row a version, the buttons side by side (1.0.145): the reasons a
         version is refused are said once, folded below - not in every row. */
      var acts = function (v, ok) {
        var cell = el('div', '');
        cell.style.cssText = 'display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;margin-left:auto';
        var notes = cmdButton('What changed', 'list', 'small');
        notes.style.whiteSpace = 'nowrap';
        notes.onclick = function () { upDownChangelog(v.version); };
        cell.appendChild(notes);
        if (ok && !running) {
          var go = cmdButton('Go back to ' + v.version, 'undo', 'small danger');
          go.style.whiteSpace = 'nowrap';
          go.onclick = function () {
            upDownConfirm(v.version, function () {
              busy(go, true);
              api('upgrade', {action: 'downgrade_get', version: v.version, start: true}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); })
                .catch(oops).then(function () { busy(go, false); });
            });
          };
          cell.appendChild(go);
        }
        return cell;
      };
      /* Rows of their own, not a table (1.0.145): the version and its state on
         the left, the buttons on the right - on a narrow screen the buttons go
         below as a whole, never squeezed into a column. */
      var nowrap = function (node) {
        node.style.whiteSpace = 'nowrap';
        Array.prototype.forEach.call(node.querySelectorAll('span'), function (x) { x.style.whiteSpace = 'nowrap'; });
        return node;
      };
      var rows = function (items, ok) {
        var box = el('div', 'dg-rows');
        items.forEach(function (v) {
          var r = el('div', 'dg-row');
          r.style.cssText = 'display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:8px 16px;padding:8px 10px;border-bottom:1px solid var(--line)';
          var left = el('div', '');
          left.style.cssText = 'display:flex;align-items:center;gap:10px;min-width:9em';
          left.appendChild(noI18n(el('b', '', v.version)));
          var tag = nowrap(el('span', ok ? 'tag ok' : 'tag warn', ok ? 'yes' : (v.short || 'no')));
          if (!ok) explain(tag, (v.why || []).join('\n'));
          left.appendChild(tag);
          r.appendChild(left);
          var right = acts(v, ok);
          Array.prototype.forEach.call(right.children, nowrap);
          r.appendChild(right);
          box.appendChild(r);
        });
        return box;
      };
      if (good.length) list.appendChild(rows(good, true));
      else list.appendChild(el('p', 'note', 'No version at the address may be gone back to.'));
      if (bad.length) {
        var det = el('details', 'fold');
        det.style.marginTop = '12px';
        det.appendChild(el('summary', '', bad.length + ' older version(s) it may not go back to' + (g.lowest ? ' - below ' + g.lowest : '')));
        var reasons = [];
        bad.forEach(function (v) { (v.why || []).forEach(function (w) { if (reasons.indexOf(w) < 0) reasons.push(w); }); });
        var why = el('ul', 'note small');
        why.style.margin = '8px 0';
        reasons.forEach(function (w) { why.appendChild(el('li', 'bad', w)); });
        det.appendChild(why);
        det.appendChild(rows(bad, false));
        list.appendChild(det);
      }
    }).catch(function (e) { clear(list); list.appendChild(el('p', 'note bad', String((e && e.message) || e))); })
      .then(function () { busy(show, false); });
  };
}
function drawUpgrade(d) {
  d = upSteady(d);
  UP.last = d;
  /* The nodes. */
  liveFill($('up-nodes'), function (host) {
  /* By name, so the rows keep their places whichever node answered (1.0.70). */
  var nodesSorted = (d.nodes || []).slice().sort(function (a, b) { return String(a.name).localeCompare(String(b.name)); });
  host.appendChild(listTable(['Node', 'Version', 'Heard from', 'State', ''], nodesSorted, function (n) {
    var tr = el('tr');
    var nm = el('td');
    nm.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) { nm.appendChild(document.createTextNode(' ')); nm.appendChild(el('span', 'tag info', 'this page')); }
    tr.appendChild(nm);
    tr.appendChild(noI18n(el('td', 'mono', n.version || '?')));
    tr.appendChild(el('td', 'muted', n.at ? ago(n.at) : '–'));
    var st = el('td');
    var m = n.maintenance || {};
    if (!n.alive) st.appendChild(el('span', 'tag crit', 'gone'));
    else if (m.on) st.appendChild(el('span', 'tag warn', 'in maintenance'));
    else st.appendChild(el('span', 'tag ok', 'in service'));
    if (m.on && m.why) st.appendChild(el('span', 'sub', m.why + (m.by ? ' · ' + m.by : '') + (m.at ? ' · ' + ago(m.at) : '')));
    tr.appendChild(st);
    var tools = el('td', 'rowtools');
    if (ADMIN && n.alive) {
      var b = cmdButton(m.on ? 'Back in service' : 'Maintenance', m.on ? 'play' : 'power', 'small');
      b.onclick = function (ev) { ev.stopPropagation(); maintenanceAsk(n, !m.on, drawUpgrade); };
      tools.appendChild(b);
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain'));
  });
  drawUpWeb(d);
  /* The package. */
  var plan = d.plan;
  var running = !!(plan && plan.state === 'running');
  liveFill($('up-pkg'), function (pk) {
  if (d.package) {
    var p = d.package;
    var box = el('div', 'notice good');
    box.style.marginTop = '12px';
    if (p.downgrade) box.className = 'notice warn';
    box.appendChild(el('b', '', 'acme ' + p.version + (p.downgrade ? ' - older: ready to go back to' : '')));
    box.appendChild(el('div', 'small', 'signed by ' + (p.signed_by || '?') + ' · ' + bytes(p.bytes) + ' · sent by ' + (p.by || '?') + ' · ' + ago(p.at)));
    pk.appendChild(box);
    if (p.changelog) {
      var det = el('details', 'fold');
      det.appendChild(el('summary', '', 'What changed in ' + p.version));
      var pre = el('pre', 'lines', p.changelog);
      noI18n(pre);
      det.appendChild(pre);
      pk.appendChild(det);
    }
  }
  });
  $('up-forget').hidden = !d.package || running;
  $('up-start').disabled = !d.package || !d.ready || running;
  var many = (d.nodes || []).length > 1;
  var down = !!(d.package && d.package.downgrade);
  setButtonIcon($('up-start'), down ? 'undo' : 'play', down ? (many ? 'Go back on every node, one at a time' : 'Go back on this server')
    : (many ? 'Upgrade every node, one at a time' : 'Upgrade this server'));
  $('up-start').classList.toggle('danger', down);
  $('up-start').classList.toggle('primary', !down);
  drawUpDown(d);
  var rd = $('up-ready');
  clear(rd);
  if (d.package && !d.ready && !running) {
    (d.not_ready || []).forEach(function (w) { rd.appendChild(el('p', 'note bad', w)); });
  }
  if (!d.helper || !d.path_unit) {
    rd.appendChild(el('p', 'note bad', 'This server cannot put a version in by itself yet: acme-upgrade.path is not installed. Upgrade it once on the command line (install.sh --upgrade), which puts it in.'));
  }
  /* The plan. */
  $('up-plan-card').hidden = !plan;
  liveFill($('up-plan'), function (ph) {
  if (plan) {
    ph.appendChild(el('p', 'note', (plan.downgrade ? 'Going back to ' : 'To ') + plan.version + ' · started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · '
      + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state]));
    /* How far, as bars (1.0.67): the whole and each node. */
    var steps = plan.steps || [];
    var all = steps.length ? Math.round(steps.reduce(function (m, st) { return m + upPercent(st, plan); }, 0) / steps.length) : 0;
    ph.appendChild(upBar(all, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
                         num(all) + ' % · ' + steps.filter(function (x) { return x.state === 'done'; }).length + ' of ' + steps.length + ' node(s) done', true));
    var upTable = listTable(['Node', 'Step', 'How far', 'What happened', 'When'], steps, function (st) {
      var tr = el('tr');
      tr.appendChild(noI18n(el('td', 'mono', st.name)));
      var w = UP_STATE[st.state] || UP_STATE.waiting;
      var c = el('td');
      c.appendChild(el('span', 'tag ' + w[1], w[0]));
      tr.appendChild(c);
      var pc = upPercent(st, plan);
      var bt = el('td', 'up-how');
      bt.appendChild(upBar(pc, st.state === 'failed' ? 'bad' : (st.state === 'done' ? 'good' : ''),
                           st.state === 'installing' && st.part_words ? num(pc) + ' % · ' + st.part_words : num(pc) + ' %'));
      tr.appendChild(bt);
      var said = el('td', 'small', st.said || '');
      if ((st.tail || []).length) {
        var more = el('details', 'fold');
        more.appendChild(el('summary', '', 'what install.sh said'));
        more.appendChild(noI18n(el('pre', 'lines', st.tail.join('\n'))));
        /* Left open across the redraws every 3 s (1.0.69). */
        UP.tailOpen = UP.tailOpen || {};
        if (UP.tailOpen[st.name]) more.open = true;
        more.ontoggle = function () { UP.tailOpen[st.name] = more.open; };
        said.appendChild(more);
      }
      tr.appendChild(said);
      tr.appendChild(el('td', 'muted', st.at ? ago(st.at) : '–'));
      return tr;
    }, 'plain');
    /* Columns of a fixed width (1.0.69): they jumped about with every redraw
       as the bars and the words in them changed. */
    (upTable.querySelector('table') || upTable).classList.add('up-plan-table');
    ph.appendChild(upTable);
    if (plan.state === 'done' && d.version !== VERSION_LOADED) {
      var r = el('p', 'note good');
      r.appendChild(document.createTextNode('This page is still the one of ' + VERSION_LOADED + '. '));
      var a = el('a', 'fgo', 'Load it again');
      a.onclick = function () { location.reload(); };
      r.appendChild(a);
      ph.appendChild(r);
    }
    if (plan.state !== 'running') ph.appendChild(hideBar(function () {
      return api('upgrade', {action: 'hide'}).then(function (x) { drawUpgrade(x); });
    }));
  }
  });
  $('up-cancel').hidden = !running;
  /* Each node's own install.sh output (1.0.70), kept as it comes - the
     answering node changes behind the VIP address, and the one card showed
     one node's, then the other's. */
  UP.logs = UP.logs || {};
  if (d.node) UP.logs[d.node] = d.log || [];
  var known = Object.keys(UP.logs).sort();
  if (!UP.logNode || !UP.logs[UP.logNode]) UP.logNode = d.node;
  var lseg = $('up-log-nodes');
  if (lseg) {
    clear(lseg);
    lseg.hidden = known.length < 2;
    known.forEach(function (nm) {
      var b = noI18n(el('button', UP.logNode === nm ? 'on' : '', nm));
      b.type = 'button';
      b.onclick = function () { UP.logNode = nm; drawUpgrade(UP.last); };
      lseg.appendChild(b);
    });
  }
  if ($('up-log-node')) $('up-log-node').textContent = UP.logNode || '';
  var lg = $('up-log');
  var lines = UP.logs[UP.logNode] || [];
  lg.textContent = lines.length ? lines.join('\n') : '–';
  noI18n(lg);
  /* Asked again every 3 s while it runs and for two minutes after it ended,
     every 15 s otherwise - so a change made on the other node, or an answer
     from a node a moment behind, is never the last word (1.0.73). */
  if (running) UP.endedAt = 0;
  else if (UP.wasRunning && !UP.endedAt) UP.endedAt = Date.now() / 1000;
  UP.wasRunning = running || (UP.wasRunning && !UP.endedAt);
  upgradeAgain(upRunning() ? 3000 : 15000);
}
/* How far one node is (1.0.67), from its step and how long it has been in
   it: waiting 0, taken out of service up to 20, install.sh 20-82 by its
   sections, checking 85-95, done 100. */
function upPercent(st, plan) {
  var now = Date.now() / 1000, since = now - Number(st.at || now);
  switch (st.state) {
    case 'done': return 100;
    case 'failed': return 100;
    case 'draining':
      return Math.round(3 + 17 * Math.min(1, since / Math.max(1, Number(plan.drain_s || 20))));
    case 'installing':
      var asked = now - Number(st.asked || st.at || now);
      return Math.round(Math.min(82, 20 + 60 * Math.min(0.95, Number(st.part || 0) / 6) + Math.min(6, asked / 15)));
    case 'checking': return Math.round(85 + Math.min(10, since / 3));
    default: return 0;
  }
}
function upBar(pc, kind, words, wide) {
  var box = el('div', 'going up-bar' + (wide ? ' wide' : '') + (kind ? ' ' + kind : ''));
  var bar = el('div', 'bar');
  var fill = el('span', '');
  fill.style.width = Math.max(0, Math.min(100, pc)) + '%';
  bar.appendChild(fill);
  box.appendChild(bar);
  if (words) box.appendChild(wide ? el('div', 'says', words) : noI18n(el('div', 'says', words)));
  return box;
}
/* The version these pages came with: what the script was asked for as. */
var VERSION_LOADED = (function () {
  var sc = document.querySelector('script[src*="admin.js"]');
  var m = sc && /[?&]v=([0-9.]+)/.exec(sc.getAttribute('src') || '');
  return m ? m[1] : '';
}());
function loadUpgrade(live) {
  /* A short deadline while an upgrade runs (1.0.66): the node answering may
     be restarting, or the VIP address moving to the other one. */
  var running = upRunning();
  clearTimeout(UP.timer);
  var mine = UP.ask = (UP.ask || 0) + 1;
  api('upgrade', undefined, running ? 8 : 0).then(function (d) {
    if (mine !== UP.ask) return;          /* a newer question is on its way */
    UP.misses = 0;
    if ($('up-retry')) $('up-retry').textContent = '';
    if (!VERSION_LOADED) VERSION_LOADED = d.version;
    if (live) liveRun(function () { drawUpgrade(d); }); else drawUpgrade(d);
  }).catch(function (e) {
    if (mine !== UP.ask) return;
    /* The node that answers these pages may be the one being restarted, or
       the VIP address may be moving to the other node: asked again, always
       (1.0.73) - not only while the last answer said "running", and without
       a limit. Said once, in a line of its own that is always there. */
    UP.misses = (UP.misses || 0) + 1;
    if (running || e.unreachable || UP.misses <= 3) {
      if ($('up-retry')) $('up-retry').textContent = ('A node is restarting or the VIP address is moving to the other node - asking again…');
      upgradeAgain(Math.min(2000 * UP.misses, 6000));
      return;
    }
    oops(e);
    upgradeAgain(15000);
  });
}
/* Whether an upgrade is under way, as far as this page knows (1.0.73): the
   plan says so, or a step is not finished, or it ended a short while ago -
   behind the VIP address the next answer may come from the node whose copy
   is a moment behind. */
function upRunning() {
  var p = UP.last && UP.last.plan;
  if (!p) return false;
  if (p.state === 'running') return true;
  if ((p.steps || []).some(function (st) { return st.state !== 'done' && st.state !== 'failed' && st.state !== 'cancelled' && st.state !== 'skipped'; })
      && p.state !== 'cancelled' && p.state !== 'failed') return true;
  return Date.now() / 1000 - Number(UP.endedAt || 0) < 120;
}
if ($('up-drop')) {
  (function () {
    var box = $('up-drop');
    var sending = false;
    function send(file) {
      if (!file || sending) return;     /* chosen twice: sent once (1.0.94) */
      sending = true;
      $('up-drop-says').textContent = 'checking ' + file.name + ' (' + bytes(file.size) + ')…';
      upgradeSend(file).then(function (d) {
        sending = false;
        toast(d.message || 'checked', 'good');
        $('up-drop-says').textContent = 'Drop the acme-X.Y.Z.tar.gz here, or press to choose it';
        drawUpgrade(d);
      }).catch(function (e) {
        sending = false;
        $('up-drop-says').textContent = 'Drop the acme-X.Y.Z.tar.gz here, or press to choose it';
        modal('The package was not taken', function (body) {
          body.appendChild(el('p', 'note bad', String(e.message || e)));
        }, null, true);
      });
    }
    box.onclick = function () { $('up-file').click(); };
    $('up-file').onchange = function () { send(this.files && this.files[0]); this.value = ''; };
    ['dragenter', 'dragover'].forEach(function (name) {
      box.addEventListener(name, function (e) { e.preventDefault(); box.classList.add('over'); });
    });
    ['dragleave', 'drop'].forEach(function (name) {
      box.addEventListener(name, function (e) {
        e.preventDefault();
        box.classList.remove('over');
        if (name === 'drop' && e.dataTransfer && e.dataTransfer.files) send(e.dataTransfer.files[0]);
      });
    });
    $('up-start').onclick = function () {
      var d = UP.last || {};
      var p = d.package || {};
      var names = (d.nodes || []).filter(function (n) { return n.alive; }).map(function (n) { return n.name; });
      var many = names.length > 1;
      if (p.downgrade) { upDownConfirm(p.version, function () {
        api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      }); return; }
      confirmThen(many ? 'Upgrade every node to ' + p.version : 'Upgrade this server to ' + p.version,
        many ? 'One node at a time: it is taken out of service, upgraded, checked and brought back, and only then the next one. The load balancer and the VIP address use the other node meanwhile.'
             : 'This server is the only one: while it is put in and restarted - a minute or two - nothing is renewed or put in place, and these pages stop answering for a moment.',
        'Upgrade', function () {
          api('upgrade', {action: 'start'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
        }, !many);
    };
    $('up-forget').onclick = function () {
      confirmThen('Throw the package away', 'The uploaded package is deleted; upload it again to upgrade.', 'Throw it away', function () {
        api('upgrade', {action: 'forget'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      });
    };
    $('up-cancel').onclick = function () {
      confirmThen('Stop the upgrade', 'A node being put in right now is finished; the ones not begun stay as they are.', 'Stop it', function () {
        api('upgrade', {action: 'cancel'}).then(function (r) { toast(r.message, 'good'); drawUpgrade(r); }).catch(oops);
      });
    };
  }());
}

/* ==========================================================================
   Certificates and the VIP address (1.0.47)
   ========================================================================== */
var WEB = {last: null, timer: null};
function loadWeb() {
  apiLatest('web', 'web').then(drawWeb).catch(oops);
  loadPush();
  clearInterval(WEB.timer);
  WEB.timer = setInterval(function () {
    if (!paneLive('web')) { clearInterval(WEB.timer); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    apiLatest('web', 'web').then(function (d) { liveRun(function () { drawWeb(d); }); }).catch(function () {});
  }, 5000);
}
function daysLeft(ts) { return ts ? Math.floor((ts - Date.now() / 1000) / 86400) : null; }
function certTone(days) { return days === null ? 'dim' : (days < 0 ? 'crit' : (days < 21 ? 'warn' : 'ok')); }
function webTargetWords(t) { return t === 'vip' ? 'the VIP address' : t; }

function certCard(d, target) {
  var prof = d.tls[target];
  var node = (d.nodes || []).filter(function (n) { return n.name === target; })[0];
  var w = target === 'vip' ? null : ((node || {}).web || {});
  var info = (prof && prof.info) || (w && w.cert_now) || null;
  if (target === 'vip' && !info) {
    var holder = (d.nodes || []).filter(function (n) { return (n.web || {}).vip_cert_now; })[0];
    if (holder && prof) info = holder.web.vip_cert_now;
  }
  var card = el('section', 'cert-card');
  var head = el('header', 'cert-h');
  var title = el('div', 'cert-title');
  title.appendChild(el('span', 'cert-target', target === 'vip' ? 'The VIP address of the cluster' : 'Node'));
  title.appendChild(noI18n(el('b', '', target === 'vip' ? (d.vip.fqdn || d.vip.address || '–') : target)));
  if (target === 'vip') {
    /* Said plainly what this card is (1.0.50). */
    title.appendChild(el('span', 'cert-for', d.vip.address
      ? 'the certificate answered on the VIP ' + String(d.vip.address).split('/')[0] + ', whichever node holds it'
      : 'the certificate of the VIP - the address is set on Settings → High availability'));
  }
  if (node && node.me) title.appendChild(el('span', 'tag dim', 'this one'));
  if (target !== 'vip') {
    /* The same line under every name, so the cards stand level (1.0.51). */
    title.appendChild(el('span', 'cert-for', 'the certificate answered on ' + target + '\'s own name and address' +
      (node && node.address ? ' (' + node.address + ')' : '')));
  }
  head.appendChild(title);
  var days = info ? daysLeft(info.not_after) : null;
  var badge = el('span', 'tag ' + certTone(days), days === null ? 'no certificate' :
    (days < 0 ? 'ran out' : (days < 21 ? days + ' days left' : 'valid')));
  head.appendChild(badge);
  card.appendChild(head);
  if (info) {
    var b = el('div', 'cert-body');
    b.appendChild(noI18n(el('div', 'cert-cn', info.cn || info.subject || '')));
    var bar = el('div', 'cert-life');
    var span = info.not_after && info.not_before ? (info.not_after - info.not_before) : 1;
    var used = info.not_before ? Math.max(0, Math.min(1, (Date.now() / 1000 - info.not_before) / span)) : 0;
    var fill = el('span', 'cert-life-fill ' + certTone(days));
    fill.style.width = Math.round(used * 100) + '%';
    bar.appendChild(fill);
    b.appendChild(bar);
    var facts = [['Issued by', noI18n(el('span', '', info.self_signed ? 'itself (self-signed)' : (info.issuer || '').replace(/^CN=/, '')))],
                 ['Valid until', info.not_after ? stamp(info.not_after) : '–'],
                 ['Key', (info.key || '–') + (prof && prof.alt && prof.alt.info && prof.alt.info.key ? ' + ' + prof.alt.info.key + ' (a second certificate beside it)' : '')]];
    if (info.san && info.san.length) facts.push(['Names', noI18n(el('span', '', info.san.join(', ')))]);
    if (prof) {
      facts.push(['Chain', prof.chain_info ? (prof.chain_info.length + ' between it and the root') : '–']);
      facts.push(['Root', prof.root_info && prof.root_info.length ? noI18n(el('span', '', prof.root_info[0].cn || 'given')) : 'not given']);
      if (prof.verify) facts.push(['Checked', prof.verify === 'ok' ? el('span', 'good', 'the chain leads to the root') : el('span', 'bad', prof.verify)]);
    }
    var kv = el('dl', 'cert-kv');
    facts.forEach(function (f) {
      kv.appendChild(el('dt', '', f[0]));
      var dd = el('dd');
      if (f[1] && f[1].nodeType) dd.appendChild(f[1]); else dd.textContent = f[1];
      kv.appendChild(dd);
    });
    b.appendChild(kv);
    card.appendChild(b);
  } else {
    card.appendChild(el('p', 'note', target === 'vip'
      ? 'None of its own: the VIP address answers with the certificate of the node it is on.'
      : 'Not known yet.'));
  }
  /* How TLS is spoken, as chips. */
  var chips = el('div', 'cert-chips');
  var preset = (prof && prof.preset) || 'standard';
  chips.appendChild(el('span', 'cchip', {standard: 'TLS 1.2 + 1.3, ECDHE', intermediate: 'Mozilla intermediate', modern: 'TLS 1.3 only', custom: 'custom'}[preset] || preset));
  if (prof && prof.dh && prof.dh !== 'none') chips.appendChild(noI18n(el('span', 'cchip', 'DH ' + prof.dh)));
  if (prof && prof.hsts) chips.appendChild(el('span', 'cchip', 'HSTS ' + Math.round(prof.hsts / 86400) + ' days'));
  if (prof && prof.pending) chips.appendChild(el('span', 'cchip warn', 'a request waits for its certificate'));
  /* Automatic certificates beside it (1.0.170): who renews this one. */
  var ac = d.acme || {};
  if (ac.on) {
    var acare = (ac.care || {})[target];
    var ach = el('span', 'cchip' + (acare ? '' : ' dim'), acare ? 'renewed by ACME' : 'ACME leaves it alone');
    explain(ach, acare ? 'Settings → Automatic certificates renews it before it runs out. Uploading one here, or making one self-signed, takes it out of ACME’s care - it is kept as it is.'
      : 'Kept as it is: Automatic certificates does not replace it (Look after it there gives it to ACME).');
    ach.style.cursor = 'pointer';
    ach.onclick = function () { location.hash = '#settings/acme'; };
    chips.appendChild(ach);
    var ast = (ac.state || {})[target] || {};
    if (acare && ast.ok === false && ast.said) chips.appendChild(el('span', 'cchip warn', 'the last order failed'));
  }
  if (!prof && target !== 'vip') chips.appendChild(el('span', 'cchip dim', 'as install.sh made it'));
  card.appendChild(chips);
  /* Is it in place on the node? */
  if (target === 'vip' && prof && d.vip && d.vip.on) {
    /* The VIP address's certificate is put in on every node (1.0.51). */
    (d.nodes || []).forEach(function (n) {
      var nw = n.web || {};
      if (nw.progress) { card.appendChild(certProgress(nw.progress, n.name)); return; }
      var st2 = el('div', 'cert-state');
      st2.appendChild(el('span', 'dot ' + (nw.state === 'failed' ? 'crit' : (nw.current ? 'ok' : 'warn'))));
      st2.appendChild(el('span', '', nw.state === 'failed' ? n.name + ': ' + ((nw.said || []).slice(-1)[0] || 'failed')
        : (nw.current ? 'in place on ' + n.name : 'being put in on ' + n.name + '…')));
      card.appendChild(st2);
    });
  } else if (target === 'vip' && prof && d.vip && !d.vip.on) {
    card.appendChild(el('p', 'note small', 'Put in on the nodes once the VIP address is turned on (Settings → High availability).'));
  }
  if (target !== 'vip' && w && w.progress) {
    card.appendChild(certProgress(w.progress, target));
  } else if (prof && target !== 'vip' && w) {
    var st = el('div', 'cert-state');
    st.appendChild(el('span', 'dot ' + (w.state === 'failed' ? 'crit' : (w.current ? 'ok' : 'warn'))));
    st.appendChild(el('span', '', w.state === 'failed' ? 'root could not put it in: ' + ((w.said || []).slice(-1)[0] || '')
      : (w.current ? 'in place on ' + target : 'being put in on ' + target + '…')));
    card.appendChild(st);
  }
  if (d.may) {
    var tools = el('div', 'cert-tools');
    /* Put in by hand while ACME renews it (1.0.170): said first - it leaves
       ACME's care, or ACME would replace it at its next renewal. */
    var byHand = function (go) {
      if (!(d.acme && d.acme.on && (d.acme.care || {})[target])) { go(); return; }
      confirmThen('ACME renews this certificate', 'One put in here by hand takes ' + webTargetWords(target)
        + ' out of ACME’s care: it is kept as it is, not replaced at the next renewal. Settings → Automatic certificates → Look after it gives it back.', 'Go on',go, false);
    };
    var up = cmdButton('Upload', 'upload', 'small');
    up.onclick = function () { byHand(function () { certUpload(target, prof); }); };
    tools.appendChild(up);
    var req = cmdButton(prof && prof.pending ? 'The waiting request' : 'Request (CSR)', 'list', 'small');
    req.onclick = function () { certRequest(target, prof); };
    tools.appendChild(req);
    var ss = cmdButton('Self-signed', 'key', 'small');
    ss.onclick = function () { byHand(function () { certSelf(target, d); }); };
    tools.appendChild(ss);
    var pol = cmdButton('TLS settings', 'gear', 'small');
    pol.onclick = function () { certPolicy(target, prof, d); };
    /* Whoever gave the certificate - ACME too - its protocols, ciphers, DH
       and HSTS are set here and kept when it is renewed (1.0.172). */
    explain(pol, 'The protocols, the ciphers, the DH parameters and HSTS of ' + webTargetWords(target) + ' - kept as they are whichever way the certificate came, ACME and its renewals too.');
    tools.appendChild(pol);
    var bef = (d.acme && d.acme.before || {})[target];
    if (bef && !bef.ran_out) tools.appendChild(acmePutBackButton(target, bef, function () { loadWeb(); }));
    if (prof && prof.cert) {
      var dl = cmdButton('Download', 'download', 'small');
      dl.title = 'The certificate in the format chosen - PEM, DER, PKCS#7, or PFX with its private key';
      dl.onclick = function () { certExport(target, prof); };
      tools.appendChild(dl);
      var fg = cmdButton('Let go', 'forget', 'small danger-soft');
      fg.title = 'acme stops looking after it (nginx keeps what it has)';
      fg.onclick = function () {
        confirmThen('Stop looking after the TLS of ' + webTargetWords(target), 'nginx keeps the files it has now; acme no longer changes them.', 'Stop', function () {
          api('web', {action: 'tls_forget', target: target}).then(function (x) { toast(x.message, 'good'); loadWeb(); }).catch(oops);
        });
      };
      tools.appendChild(fg);
    }
    card.appendChild(tools);
  }
  return card;
}

/* What root is doing on a node, as a bar (1.0.50): the steps done, and in
   the long one - making DH parameters - the time gone against the time it
   usually takes (never shown as more than 95 % before it is done). */
function certProgress(p, target) {
  var box = el('div', 'cert-prog');
  var total = Number(p.total) || 6, step = Math.max(1, Number(p.step) || 1);
  var gone = Math.max(0, (Number(p.now) || 0) - (Number(p.at) || 0));
  var part = p.expect_s ? Math.min(0.95, gone / Number(p.expect_s)) : 0.5;
  var pct = Math.min(99, Math.round(((step - 1) + part) / total * 100));
  var head = el('div', 'cert-prog-h');
  head.appendChild(el('span', '', p.words || 'working'));
  head.appendChild(noI18n(el('b', '', pct + ' %')));
  box.appendChild(head);
  var bar = el('div', 'cert-prog-bar');
  var fill = el('span', '');
  fill.style.width = pct + '%';
  bar.appendChild(fill);
  box.appendChild(bar);
  var mm = function (sec) { sec = Math.round(sec); return Math.floor(sec / 60) + ':' + ('0' + (sec % 60)).slice(-2); };
  box.appendChild(el('div', 'cert-prog-s', p.expect_s
    ? 'on ' + target + ' - ' + mm(gone) + ' so far, usually about ' + Math.round(p.expect_s / 60 || 1) + ' min'
    : 'on ' + target + ' - step ' + step + ' of ' + total));
  return box;
}

/* Files read in the browser: PEM as text, a PFX as base64. */
function readCertFiles(files) {
  return Promise.all(Array.prototype.map.call(files, function (f) {
    return new Promise(function (ok, bad) {
      if (f.size > 200000) { bad(new Error(f.name + ' is far bigger than any certificate file')); return; }
      var r = new FileReader();
      r.onload = function () {
        var bytesArr = new Uint8Array(r.result);
        var head = String.fromCharCode.apply(null, bytesArr.slice(0, Math.min(bytesArr.length, 4096)));
        if (/-----BEGIN /.test(head) || /-----BEGIN /.test(new TextDecoder().decode(bytesArr))) {
          ok({name: f.name, pem: new TextDecoder().decode(bytesArr)});
        } else {
          var bin = '';
          for (var i = 0; i < bytesArr.length; i++) bin += String.fromCharCode(bytesArr[i]);
          ok({name: f.name, pfx: btoa(bin)});
        }
      };
      r.onerror = function () { bad(new Error(f.name + ' could not be read')); };
      r.readAsArrayBuffer(f);
    });
  }));
}

var CERT_PASTE_HINT = '-----BEGIN CERTIFICATE-----\n' +
  '1. the certificate of this name (the server\'s own)\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN CERTIFICATE-----\n' +
  '2. the intermediate certificate(s), if there are any - one block each\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN CERTIFICATE-----\n' +
  '3. the root certificate (optional)\n' +
  '-----END CERTIFICATE-----\n' +
  '-----BEGIN PRIVATE KEY-----\n' +
  '4. its private key (not needed when the request was made here)\n' +
  '-----END PRIVATE KEY-----\n\n' +
  'Any order is taken: they are sorted by themselves.';
function certUpload(target, prof) {
  var got = [];
  modal('A certificate for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'PEM files - the certificate, its key, the chain, the root, in any order or all in one - or one PFX / PKCS#12 file. ' +
      (prof && prof.pending ? 'A request waits here: the certificate the authority sent back is enough, its key is here.' : 'The key has to come with it.')));
    var drop = el('div', 'drop');
    var inp = el('input'); inp.type = 'file'; inp.multiple = true; inp.hidden = true;
    inp.accept = '.pem,.crt,.cer,.key,.pfx,.p12,.chain,.ca,.txt';
    var says = el('span', '', 'Drop the files here, or press to choose them');
    drop.appendChild(inp); drop.appendChild(says);
    var list = el('div', 'cert-files');
    function take(files) {
      readCertFiles(files).then(function (r) {
        got = got.concat(r);
        clear(list);
        got.forEach(function (x) { list.appendChild(noI18n(el('span', 'cchip', x.name + (x.pfx ? ' (PFX)' : ' (PEM)')))); });
        says.textContent = 'Read: ' + got.length + ' file(s). More can be added.';
      }).catch(oops);
    }
    drop.onclick = function () { inp.click(); };
    inp.onchange = function () { take(inp.files); inp.value = ''; };
    drop.addEventListener('dragover', function (e) { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', function () { drop.classList.remove('over'); });
    drop.addEventListener('drop', function (e) { e.preventDefault(); drop.classList.remove('over'); take(e.dataTransfer.files); });
    body.appendChild(drop);
    body.appendChild(list);
    var paste = el('textarea', 'mono cert-paste');
    paste.id = 'cu-paste';
    paste.rows = 16;
    /* The usual order shown in the box itself (1.0.50); any order is taken. */
    paste.placeholder = CERT_PASTE_HINT;
    paste.spellcheck = false;
    body.appendChild(formField('Or paste PEM here', paste));
    var pw = secretBox('', 'only for a PFX or a key with a passphrase', 'mono');
    pw.id = 'cu-pw';
    body.appendChild(formField('Password', pw, 'Used here to open it, and not kept.'));
    body.appendChild(el('div', 'said', '')).id = 'cu-said';
  }, [{words: 'Cancel', close: true},
      {words: 'Put it in', cls: 'primary', icon: 'save', go: function (b) {
        var pem = got.filter(function (x) { return x.pem; }).map(function (x) { return x.pem; }).join('\n') + '\n' + ($('cu-paste').value || '');
        var pfx = got.filter(function (x) { return x.pfx; });
        if (pfx.length > 1) { toast('one PFX / PKCS#12 file at a time', 'bad'); return; }
        if (!pfx.length && !/-----BEGIN /.test(pem)) { toast('choose the files first, or paste the PEM', 'bad'); return; }
        busy(b, true);
        api('web', {action: 'tls_upload', target: target, cert: pem, pfx: pfx.length ? pfx[0].pfx : '',
                    password: ($('cu-pw') || {}).value || ''}).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(function (e) { $('cu-said').className = 'said bad'; $('cu-said').textContent = e.message; }).then(function () { busy(b, false); });
      }}], 'medium');
}

function certNamesDefault(target, d) {
  if (target === 'vip') return d.vip.fqdn || '';
  var n = (d.nodes || []).filter(function (x) { return x.name === target; })[0];
  return n && /\./.test(n.host || '') ? n.host : '';
}
function certSubjectFields(body, target, d, withDays) {
  var g = el('div', 'formgrid');
  var cn = textBox(certNamesDefault(target, d), 'acme.example.cz', 'mono'); cn.id = 'cs-cn';
  var names = textBox('', 'acme1.example.cz, 192.0.2.11', 'mono'); names.id = 'cs-names';
  var kind = selectBox([['rsa2048', 'RSA 2048'], ['rsa3072', 'RSA 3072'], ['rsa4096', 'RSA 4096'], ['ec', 'EC P-256']], 'rsa2048'); kind.id = 'cs-kind';
  g.appendChild(formField('The name (CN)', cn, 'What people type in the browser.'));
  g.appendChild(formField('Other names', names, 'More names or addresses it is good for, by commas.'));
  g.appendChild(formField('The key', kind));
  var org = textBox('', 'Krajský úřad'); org.id = 'cs-org';
  g.appendChild(formField('Organisation', org));
  if (withDays) {
    var days = selectBox([['365', '1 year'], ['825', '27 months'], ['1825', '5 years'], ['3650', '10 years']], '825'); days.id = 'cs-days';
    g.appendChild(formField('Valid for', days));
  } else {
    var unit = textBox('', 'IT'); unit.id = 'cs-unit';
    var city = textBox('', 'Olomouc'); city.id = 'cs-city';
    var country = textBox('CZ', 'CZ'); country.id = 'cs-country'; country.maxLength = 2;
    g.appendChild(formField('Unit', unit));
    g.appendChild(formField('City', city));
    g.appendChild(formField('Country', country));
  }
  body.appendChild(g);
}
function certSubjectValues() {
  var v = function (id) { return ($(id) || {}).value || ''; };
  return {cn: v('cs-cn').trim(), names: v('cs-names'), kind: v('cs-kind'), org: v('cs-org'),
          unit: v('cs-unit'), city: v('cs-city'), country: v('cs-country'), days: v('cs-days')};
}

function certRequest(target, prof) {
  if (prof && prof.pending && prof.csr) { showCsr(target, prof.csr, prof); return; }
  modal('A certificate request for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'A new key is made here and stays here; the request (CSR) goes to your certificate authority. Upload what it sends back - the certificate alone is enough.'));
    certSubjectFields(body, target, WEB.last || {vip: {}}, false);
  }, [{words: 'Cancel', close: true},
      {words: 'Make the request', cls: 'primary', icon: 'list', go: function (b) {
        busy(b, true);
        api('web', Object.assign({action: 'tls_csr', target: target}, certSubjectValues())).then(function (x) {
          closeModal(); loadWeb(); showCsr(target, x.csr, x.tls);
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}
function showCsr(target, csr, prof) {
  modal('The request for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note', 'Give this to your certificate authority. The key waits here; once the certificate comes back, upload it.'));
    var pre = noI18n(el('pre', 'mono cert-csr', csr));
    copyOnClick(pre, csr, 'the request was copied');
    body.appendChild(pre);
  }, [{words: 'Drop the request', icon: 'trash', go: function () {
        modalOver(function () { confirmThen('Drop the request', 'Its waiting key goes too; a certificate made for it can then not be used.', 'Drop it', function () {
          api('web', {action: 'tls_csr_drop', target: target}).then(function (x) { toast(x.message, 'good'); loadWeb(); }).catch(oops);
        }, true); });
      }},
      {words: 'Download .csr', icon: 'download', go: function () { saveFile((target === 'vip' ? 'web-address' : target) + '.csr', csr); }},
      {spacer: true},
      {words: 'Upload the certificate…', cls: 'primary', icon: 'upload', go: function () { closeModal(); certUpload(target, {pending: true}); }},
      {words: 'Close', close: true}], 'medium');
}

function certSelf(target, d) {
  modal('A self-signed certificate for ' + webTargetWords(target), function (body) {
    body.appendChild(el('p', 'note warn', 'Browsers warn about a self-signed certificate until it is trusted by hand. Good for a test, or until the real one comes.'));
    certSubjectFields(body, target, d, true);
  }, [{words: 'Cancel', close: true},
      {words: 'Make it and put it in', cls: 'primary', icon: 'key', go: function (b) {
        busy(b, true);
        api('web', Object.assign({action: 'tls_selfsigned', target: target}, certSubjectValues())).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}

function certPolicy(target, prof, d) {
  prof = prof || {};
  var st = {preset: prof.preset || 'standard',
            protocols: (prof.protocols || ['TLSv1.2', 'TLSv1.3']).slice(),
            ciphers: prof.ciphers || (d.presets.standard || {}).ciphers || '',
            dh: prof.dh || 'none', prefer: !!prof.prefer, hsts: (prof.hsts === undefined || prof.hsts === null || prof.hsts === '') ? 63072000 : Number(prof.hsts)};
  var PRESETS = [
    ['standard', 'Standard', 'TLS 1.2 + 1.3', 'ECDHE with AES-GCM and ChaCha20. Every browser of the last ten years.', 'recommended'],
    ['intermediate', 'Mozilla intermediate', 'TLS 1.2 + 1.3', 'Adds the DHE ciphers, for old clients. Wants DH parameters.', ''],
    ['modern', 'Mozilla modern', 'TLS 1.3 only', 'The strongest; old systems and some scanners cannot connect.', ''],
    ['custom', 'Custom', 'chosen here', 'The protocols and an OpenSSL cipher list of your own.', '']];
  modal('How ' + webTargetWords(target) + ' speaks TLS', function (body) {
    /* The protocols and ciphers: one tile each. */
    body.appendChild(el('h4', 'tls-h', 'Protocols and ciphers'));
    var tiles = el('div', 'tls-tiles');
    var custom = el('div', 'tls-custom');
    var used = el('details', 'tls-used');
    function paint() {
      Array.prototype.forEach.call(tiles.children, function (t) { t.classList.toggle('on', t.dataset.k === st.preset); });
      custom.hidden = st.preset !== 'custom';
      used.hidden = st.preset === 'custom';
      var p = d.presets[st.preset];
      if (p) {
        clear(used);
        used.appendChild(el('summary', '', 'The ciphers it uses'));
        used.appendChild(noI18n(el('code', 'tls-cipherlist', p.ciphers ? p.ciphers.split(':').join('\n') : 'TLS 1.3 chooses its own: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256')));
      }
      dhRow.classList.toggle('dim', st.preset === 'modern' || (st.preset === 'standard' && st.dh === 'none'));
    }
    PRESETS.forEach(function (p) {
      var t = el('button', 'tls-tile');
      t.type = 'button';
      t.dataset.k = p[0];
      var top = el('div', 'tls-tile-top');
      top.appendChild(el('b', '', p[1]));
      if (p[4]) top.appendChild(el('span', 'tag ok', p[4]));
      t.appendChild(top);
      t.appendChild(el('div', 'tls-tile-prot', p[2]));
      t.appendChild(el('div', 'tls-tile-s', p[3]));
      t.onclick = function () { st.preset = p[0]; paint(); };
      if (hsOn('web:tls') && (p[0] === 'intermediate' || p[0] === 'custom')) { t.disabled = true; t.appendChild(el('div', 'small hs-note', 'not under high security')); }
      tiles.appendChild(t);
    });
    body.appendChild(tiles);
    /* Custom: the protocols as switches, the cipher list. */
    var prow = el('div', 'tls-prot');
    ['TLSv1.2', 'TLSv1.3'].forEach(function (v) {
      var b = el('button', 'tls-pill');
      b.type = 'button';
      b.textContent = v.replace('TLSv', 'TLS ');
      noI18n(b);
      var sync = function () { b.classList.toggle('on', st.protocols.indexOf(v) >= 0); };
      b.onclick = function () {
        var i = st.protocols.indexOf(v);
        if (i >= 0 && st.protocols.length > 1) st.protocols.splice(i, 1); else if (i < 0) st.protocols.push(v);
        sync();
      };
      sync();
      prow.appendChild(b);
    });
    custom.appendChild(el('div', 'tls-sub', 'Protocols'));
    custom.appendChild(prow);
    var ciphers = el('textarea', 'mono tls-ciphers');
    ciphers.rows = 4; ciphers.spellcheck = false; ciphers.value = st.ciphers;
    ciphers.oninput = function () { st.ciphers = ciphers.value; };
    custom.appendChild(el('div', 'tls-sub', 'Ciphers for TLS 1.2 (an OpenSSL list; TLS 1.3 chooses its own)'));
    custom.appendChild(ciphers);
    body.appendChild(custom);
    body.appendChild(used);
    /* The rest, row by row. */
    body.appendChild(el('h4', 'tls-h', 'More'));
    var rows = el('div', 'tls-rows');
    var dh = selectBox(Object.keys(d.dh).map(function (k) { return [k, d.dh[k]]; }), st.dh);
    dh.onchange = function () { st.dh = dh.value; paint(); };
    var dhRow = tlsRow('DH parameters', 'Only the DHE ciphers use them (Mozilla intermediate, or your own). An RFC 7919 group is ready at once; made here takes from seconds to minutes.', dh);
    rows.appendChild(dhRow);
    var prefer = switchBox(st.prefer);
    prefer._input.onchange = function () { st.prefer = !!prefer._get(); };
    rows.appendChild(tlsRow('The server chooses the cipher', 'Off is right for these lists: every cipher in them is strong, and the client knows best which is fast for it.', prefer));
    var seg = el('div', 'seg');
    [[0, 'off'], [15768000, '6 months'], [31536000, '1 year'], [63072000, '2 years']].forEach(function (o) {
      var b = el('button', '', o[1]);
      b.type = 'button';
      b.onclick = function () { st.hsts = o[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); };
      if (st.hsts === o[0]) b.classList.add('on');
      seg.appendChild(b);
    });
    if (!seg.querySelector('.on')) seg.children[0].classList.add('on');
    rows.appendChild(tlsRow('HSTS', 'A browser that saw it comes back only over HTTPS for that long. Turn it on once HTTPS is surely staying.', seg));
    body.appendChild(rows);
    paint();
  }, [{words: 'Cancel', close: true},
      {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
        busy(b, true);
        api('web', {action: 'tls_policy', target: target, preset: st.preset, protocols: st.protocols,
                    ciphers: String(st.ciphers || '').trim(), dh: st.dh, prefer: st.prefer ? 1 : 0,
                    hsts: st.hsts}).then(function (x) {
          toast(x.message, 'good'); closeModal(); loadWeb();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}
function tlsRow(words, says, control) {
  var row = el('div', 'arow');
  var t = el('div', 'arow-t');
  t.appendChild(el('div', 'arow-k', words));
  t.appendChild(el('div', 'arow-s', says));
  row.appendChild(t);
  var c = el('div', 'arow-c');
  c.appendChild(control);
  row.appendChild(c);
  return row;
}

function drawWeb(d) {
  WEB.last = d;
  var host = $('web-certs');
  liveFill(host, function (host) {
  Object.keys(d.tls).forEach(function (t) {
    if (t === 'vip' && !d.cluster) return;
    host.appendChild(certCard(d, t));
  });
  }, undefined, function () { explainWhatWasDrawn($('pane-web')); });
}

/* ---- Certificates from acme (acme push, docs/acme-push-protocol.md) -----------------
   An acme puts its certificates on these pages: paired once (a pairing code shown
   here, or acme's key pasted), it signs every request, and the key travels sealed
   to this server. */
var PUSH = {last: null};
function loadPush() {
  if (!$('web-push')) return;
  api('acme-push').then(function (v) { PUSH.last = v; drawPush(v); }).catch(function () {});
}
function pushDo(body, button) {
  if (button) busy(button, true);
  return api('acme-push', body).then(function (d) {
    toast(d.message || 'kept', 'good');
    if (d.view) { PUSH.last = d.view; drawPush(d.view); }
    return d;
  }).catch(oops).then(function (d) { if (button) busy(button, false); return d; });
}
function pushCode(code) {
  modal('The pairing code', function (body) {
    body.appendChild(el('p', 'note', 'Put it in acme: Targets → An application of ours (acme push) → Pairing code, with this address; then Try there. It is good for 15 minutes and once.'));
    var c = noI18n(el('div', 'mono push-code', code));
    c.style.fontSize = '1.6em';
    c.style.letterSpacing = '0.08em';
    c.style.margin = '12px 0';
    body.appendChild(c);
    var cp = el('button', 'btn small', 'Copy');
    cp.type = 'button';
    cp.onclick = function () { copyText(code, cp); };
    body.appendChild(cp);
  }, [{words: 'Close', close: true}], true);
}
function drawPush(v) {
  var host = $('web-push');
  if (!host) return;
  var may = !!(WEB.last && WEB.last.may);
  clear(host);
  var top = el('div', 'set-item');
  var sw = switchBox(v.on);
  sw._input.disabled = !may;
  sw._input.onchange = function () {
    var on = sw._input.checked;
    if (!on) {
      askThen('Take no certificates from acme', 'acme can no longer put certificates here; the ones it put stay as they are. The pairings are kept.', 'Switch it off').then(function (yes) {
        if (yes) pushDo({action: 'off'}); else sw._input.checked = true;
      });
      return;
    }
    pushDo({action: 'on'});
  };
  top.appendChild(sw);
  var tl = el('span', '', 'Take certificates from acme');
  tl.style.marginLeft = '8px';
  top.appendChild(tl);
  host.appendChild(top);
  if (v.on) {
    var keys = v.keys || [];
    host.appendChild(el('h3', '', 'Paired with'));
    if (!keys.length) host.appendChild(el('p', 'note warn', 'No acme yet: make a pairing code below, or paste acme’s key.'));
    keys.forEach(function (k) {
      var row = el('div', 'push-key');
      row.appendChild(noI18n(el('b', '', k.name || 'acme')));
      row.appendChild(noI18n(el('span', 'mono muted', ' ' + k.id + ' ')));
      row.appendChild(el('span', 'muted', k.by === 'pairing code' ? 'by a pairing code' : 'pasted'));
      if (k.at) row.appendChild(noI18n(el('span', 'muted', ' · ' + stamp(k.at))));
      if (may) {
        var f = el('button', 'btn small danger', 'Forget it');
        f.type = 'button';
        f.style.marginLeft = '8px';
        f.onclick = function () {
          askThen('Forget this acme', 'It can put nothing here from then on. The certificates it put stay.', 'Forget it').then(function (yes) {
            if (yes) pushDo({action: 'key_forget', id: k.id}, f);
          });
        };
        row.appendChild(f);
      }
      host.appendChild(row);
    });
    if (may) {
      var bar = el('div', 'btns');
      var pair = el('button', 'btn', v.pairing ? 'A new pairing code' : 'Pair with an acme');
      pair.type = 'button';
      pair.onclick = function () { pushDo({action: 'pair'}, pair).then(function (d) { if (d && d.code) pushCode(d.code); }); };
      bar.appendChild(pair);
      if (v.pairing) {
        bar.appendChild(el('span', 'tag warn', 'a pairing code waits'));
        var drop = el('button', 'btn small', 'Take it back');
        drop.type = 'button';
        drop.onclick = function () { pushDo({action: 'pair_drop'}, drop); };
        bar.appendChild(drop);
      }
      host.appendChild(bar);
      var paste = textBox('', 'acme-push-ed25519 AAAA…', 'mono');
      var take = el('button', 'btn small', 'Take this key');
      take.type = 'button';
      take.onclick = function () {
        if (!String(paste.value || '').trim()) { toast('Paste acme’s key first', 'bad'); return; }
        pushDo({action: 'key_add', key: paste.value}, take);
      };
      var line = el('div', 'push-paste');
      line.appendChild(paste);
      line.appendChild(take);
      host.appendChild(formField('Or paste acme’s key', line, 'acme’s Try on the target says it when it is not paired yet.'));
      var other = switchBox(v.other_names);
      other._input.onchange = function () { pushDo({action: 'other_names', on: other._input.checked}); };
      host.appendChild(formField('Take certificates of other names', other, 'Off: a certificate is taken only when it holds the name of the pages it goes to - a browser would refuse it there otherwise. On: acme may say not to check (its target’s option).'));
    }
    var slots = v.slots || [];
    if (slots.length) {
      host.appendChild(el('h3', '', 'What acme sees here'));
      host.appendChild(netFacts(slots.map(function (sl) {
        var words = (sl.names || []).join(', ') || '–';
        var by = {'acme-push': 'from acme', 'own-acme': 'Automatic certificates', 'manual': 'put in by hand', 'none': 'nothing yet'}[sl.managed_by] || sl.managed_by;
        var val = el('span');
        val.appendChild(noI18n(el('span', 'mono', words + ' · ')));
        val.appendChild(el('span', '', by));
        if (sl.current && sl.current.not_after) val.appendChild(noI18n(el('span', 'muted', ' · ' + stamp(sl.current.not_after))));
        return [sl.id, val];
      })));
    }
    if (v.last) {
      var lp = el('p', 'note');
      lp.appendChild(el('span', '', 'The last push'));
      lp.appendChild(noI18n(el('span', '', ': ' + stamp(v.last.at) + ' · ' + (v.last.by || '') + ' · ' + (v.last.slots || []).join(', '))));
      host.appendChild(lp);
    }
    host.appendChild(netFacts([['This server’s id', v.app_id, true], ['Its sealing key', v.enc_fp, true]]));
  }
  if (v.mine && v.mine.text) {
    host.appendChild(el('h3', '', 'This acme’s own key'));
    host.appendChild(el('p', 'note', 'For pasting into another application, when this acme puts certificates there (Targets → An application of ours). A pairing code there does the same without it.'));
    var mk = noI18n(el('code', 'mono push-mine', v.mine.text));
    mk.style.wordBreak = 'break-all';
    host.appendChild(mk);
    var cpy = el('button', 'btn small', 'Copy');
    cpy.type = 'button';
    cpy.style.marginLeft = '8px';
    cpy.onclick = function () { copyText(v.mine.text, cpy); };
    host.appendChild(cpy);
  }
}

/* The VIP address lives on the High availability pane (1.0.49), kept up to
   date there every five seconds while it is open. */
var VIP_TIMER = null;
function loadVip(live) {
  if (!$('web-vip')) return;
  apiLatest('vip', 'web').then(function (d) { WEB.last = d; if (live) liveRun(function () { drawVip(d); }); else drawVip(d); explainWhatWasDrawn($('ha-vip-card')); }).catch(oops);
  clearInterval(VIP_TIMER);
  VIP_TIMER = setInterval(function () {
    if (!paneLive('ha')) { clearInterval(VIP_TIMER); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    apiLatest('vip', 'web').then(function (d) { WEB.last = d; liveRun(function () { drawVip(d); }); explainWhatWasDrawn($('ha-vip-card')); }).catch(function () {});
  }, 5000);
}
var VIPD = null;
function vipFromServer(v, d) {
  var names = (d.nodes || []).map(function (n) { return n.name; });
  return {address: v.address || '', address6: v.address6 || '', fqdn: v.fqdn || '', vrid: String(v.vrid || 51),
          ifaces: Object.assign({}, v.ifaces || {}), mode: v.mode === 'stays' ? 'stays' : 'back',
          prefer: v.prefer || v.prefer_now || names[0] || '', on: !!v.on};
}
function vipDirty() {
  /* Changed in the moment after a save (1.0.206): there was no draft, and a TypeError. */
  if (!VIPD) { var w_ = WEB.last || {}; VIPD = vipFromServer(w_.vip || {}, w_); VIPD.base = vipFromServer(w_.vip || {}, w_); }
  VIPD.dirty = true;
  VIPD.ver = (VIPD.ver || 0) + 1;
  pendingSet('vip', {save: vipSave, reset: function () { VIPD = null; loadVip(); }});
}
function vipSave() {
  var dr = VIPD, d = WEB.last || {}, v = d.vip || {};
  if (!dr) return Promise.resolve(true);
  /* Against what the draft was made from (1.0.206), not the latest refresh: another
     administrator's change meanwhile was sent back the way it was. */
  var was = dr.base || vipFromServer(v, d);
  var steps = [];
  if (dr.address !== was.address || (dr.address6 || '') !== (was.address6 || '') || dr.fqdn !== was.fqdn || String(dr.vrid) !== String(was.vrid)
      || JSON.stringify(Object.keys(dr.ifaces).sort().map(function (k) { return [k, dr.ifaces[k]]; }))
         !== JSON.stringify(Object.keys(was.ifaces).sort().map(function (k) { return [k, was.ifaces[k]]; }))) {
    steps.push(function () { return api('web', {action: 'vip_save', address: dr.address, address6: dr.address6 || '', fqdn: dr.fqdn, vrid: Number(dr.vrid || 51), ifaces: dr.ifaces}); });
  }
  if (dr.mode !== was.mode || (dr.mode === 'back' && dr.prefer !== was.prefer)) {
    steps.push(function () { return api('web', {action: 'vip_mode', mode: dr.mode, prefer: dr.prefer}); });
  }
  var ask = Promise.resolve(true);
  if (dr.on !== was.on) {
    if (dr.on) steps.push(function () { return api('web', {action: 'vip_on'}); });
    else {
      ask = askThen('Turn the VIP address off', 'keepalived stops on both nodes and the address is on neither. The nodes keep answering on their own addresses, and a load balancer of your own works as before.', 'Turn it off');
      steps.push(function () { return api('web', {action: 'vip_off'}); });
    }
  }
  var ver = dr.ver;
  return ask.then(function (yes) {
    if (!yes) return false;
    var chain = Promise.resolve();
    var last = null;
    steps.forEach(function (f) { chain = chain.then(f).then(function (x) { last = x; }); });
    return chain.then(function () {
      toast((last && last.message) || 'saved', 'good');
      if (VIPD && VIPD.ver !== ver) return false;   // changed meanwhile: still to be saved
      VIPD = null;
      setTimeout(loadVip, 1500);
      return true;
    });
  });
}
function drawVip(d) {
  var host = $('web-vip');
  liveFill(host, function (host) {
  if (!d.cluster) {
    host.appendChild(el('p', 'note', 'The VIP address is for a cluster of two: make this node one of two first (High availability).'));
    return;
  }
  var v = d.vip || {};
  /* What is set waits for the save bar (1.0.56): a draft of it. */
  /* Taken again from the server on every draw until something is changed
     here (1.0.57): kept from the first answer, a later save sent stale
     values back - undoing a move, or turning the address off. */
  if (!VIPD || (!VIPD.dirty && !liveWorkedIn($('web-vip')))) {   /* (1.0.206) */
    VIPD = vipFromServer(v, d);
    VIPD.base = vipFromServer(v, d);
  }
  var dr = VIPD;
  /* The big line: where it is now. */
  var top = el('div', 'vip-top');
  var holder = (v.holder || [])[0];
  var big = el('div', 'vip-big ' + (!v.on ? 'off' : (holder ? 'ok' : 'crit')));
  big.appendChild(noI18n(el('div', 'vip-addr', v.address || '–')));
  big.appendChild(el('div', 'vip-where', !v.on ? 'off' : (holder ? 'on ' + holder : 'on no node')));
  if (v.fqdn) big.appendChild(noI18n(el('div', 'vip-fqdn', v.fqdn)));
  top.appendChild(big);
  /* Where it goes back to (1.0.52): a node chosen, or wherever it is. */
  var ret = el('div', 'vip-return');
  ret.appendChild(el('div', 'lb-f-k', 'When the node it left is well again'));
  var stays = dr.mode === 'stays';
  var rseg = el('div', 'seg');
  var names = (d.nodes || []).map(function (n) { return n.name; });
  var prefNow = stays ? '' : (dr.prefer || names[0] || '');
  names.forEach(function (nm) {
    var b = el('button', '', 'always back to ' + nm); b.type = 'button';
    if (!stays && prefNow === nm) b.classList.add('on');
    b.disabled = !d.may;
    b.onclick = function () { dr.mode = 'back'; dr.prefer = nm; vipDirty(); drawVip(d); };
    rseg.appendChild(b);
  });
  var sb = el('button', '', 'it stays where it is'); sb.type = 'button';
  if (stays) sb.classList.add('on');
  sb.disabled = !d.may;
  sb.onclick = function () { dr.mode = 'stays'; vipDirty(); drawVip(d); };
  rseg.appendChild(sb);
  ret.appendChild(rseg);
  ret.appendChild(el('div', 'arow-s', stays
    ? 'No preference: the node that holds it keeps it. It moves only when that node fails (maintenance, an upgrade, unhealthy, gone) or when moved by hand - and stays where it went.'
    : 'Preferred node: the address is on ' + (prefNow || '?') + ' whenever it is healthy, and goes back to it by itself (within a few seconds) after a failover. Moving it by hand makes the other node the preferred one.'));
  top.appendChild(ret);
  if ((v.holder || []).length > 1) top.appendChild(el('p', 'note bad', 'On both nodes at once: they do not hear each other (VRRP between them is blocked, or the network is split). See docs/tls-and-vip.md.'));
  host.appendChild(top);
  /* The nodes. */
  host.appendChild(listTable(['Node', 'Now', 'May hold it', 'Interface', 'Put in place', ''], d.nodes || [], function (n) {
    var w = n.web || {};
    var hl = w.health || {};
    var tr = el('tr');
    var nm = el('td');
    nm.appendChild(noI18n(el('b', '', n.name)));
    if (v.on && v.mode !== 'stays' && (v.prefer_now === n.name)) nm.appendChild(el('span', 'tag dim', 'preferred'));
    tr.appendChild(nm);
    var role = el('td');
    var r = w.vip_here ? 'holds it' : ({MASTER: 'holds it', BACKUP: 'standby', FAULT: 'not well'}[w.role] || (v.on ? '–' : 'off'));
    role.appendChild(el('span', 'tag ' + (w.vip_here ? 'ok' : (w.role === 'FAULT' ? 'crit' : 'dim')), r));
    tr.appendChild(role);
    var h = el('td', 'small');
    if (!v.on) h.appendChild(el('span', 'muted', '–'));
    else if (!n.alive) h.appendChild(el('span', 'bad', 'not answering'));
    else h.appendChild(el('span', hl.ok ? 'good' : 'bad', hl.ok ? 'yes' : 'no - ' + (hl.why || '?')));
    tr.appendChild(h);
    var ifc = el('td');
    var opts = [['', 'the one with ' + (n.address || 'its address')]].concat((w.ifaces || []).filter(function (x) { return x !== 'lo'; }).map(function (x) { return [x, x]; }));
    var sel = selectBox(opts, (dr.ifaces || {})[n.name] || '');
    sel.dataset.node = n.name;
    sel.className = 'vip-iface';
    sel.disabled = !d.may;
    sel.onchange = function () { if (sel.value) dr.ifaces[n.name] = sel.value; else delete dr.ifaces[n.name]; vipDirty(); };
    ifc.appendChild(sel);
    tr.appendChild(ifc);
    var rt = el('td', 'small');
    rt.appendChild(el('span', w.state === 'failed' ? 'bad' : 'muted', w.state ? (w.state === 'done' ? (w.current ? 'in place' : 'being put in…') : 'failed: ' + ((w.said || []).slice(-1)[0] || '')) : '–'));
    tr.appendChild(rt);
    var tools = el('td', 'rowtools');
    if (d.may && v.on && n.alive && !w.vip_here) {
      var mv = cmdButton('Move it here', 'next', 'small');
      mv.onclick = function () {
        var nn = htmlText(n.name);
        confirmThen('Move the VIP address to ' + n.name, 'Whoever is on the pages through it is answered by ' + nn + ' within a few seconds; sign-ins stay (they are in the database). ' + (v.mode === 'stays' ? 'It then stays on ' + nn + '.' : nn + ' becomes the preferred node: the address goes back to it after a failover.'), 'Move it', function () {
          api('web', {action: 'vip_move', to: n.name}).then(function (x) { toast(x.message, 'good'); setTimeout(loadVip, 4000); }).catch(oops);
        });
      };
      tools.appendChild(mv);
    }
    if (d.may && w.state === 'failed') {
      var again = iconButton('refresh', 'Try again');
      again.onclick = function () { api('web', {action: 'retry', node: n.name}).then(function (x) { toast(x.message, 'good'); }).catch(oops); };
      tools.appendChild(again);
    }
    tr.appendChild(tools);
    return tr;
  }));
  if (!d.may) return;
  /* The settings. */
  var g = el('div', 'formgrid');
  g.style.marginTop = '14px';
  var addr = textBox(dr.address, '192.0.2.10/24', 'mono'); addr.id = 'vip-addr';
  var fqdn = textBox(dr.fqdn, 'acme.example.cz', 'mono'); fqdn.id = 'vip-fqdn';
  var vrid = textBox(dr.vrid, '51', 'mono'); vrid.id = 'vip-vrid'; vrid.inputMode = 'numeric';
  addr.oninput = function () { dr.address = addr.value.trim(); vipDirty(); };
  fqdn.oninput = function () { dr.fqdn = fqdn.value.trim(); vipDirty(); };
  vrid.oninput = function () { dr.vrid = vrid.value.trim(); vipDirty(); };
  g.appendChild(formField('The address, with its prefix', addr, 'A third address in the nodes\' network - not either node\'s.'));
  g.appendChild(formField('Its name', fqdn, 'What people type. With a certificate of its own (Settings → Certificates and TLS), it is answered with that one.'));
  g.appendChild(formField('VRRP id', vrid, '1 to 255; one no other VRRP (keepalived, a router) on that network uses.'));
  /* Dual stack (1.0.119): an IPv6 address moved with it. */
  var addr6 = textBox(dr.address6 || '', '2001:db8::10/64', 'mono');
  addr6.oninput = function () { dr.address6 = addr6.value.trim(); vipDirty(); };
  g.appendChild(formField('…and its IPv6 address (optional)', addr6, 'With IPv6 on in Settings → Network: moved with the IPv4 one by the same VRRP; nginx answers on it too. Empty: IPv4 only.'));
  host.appendChild(g);
  /* On or off: a switch, kept with the rest until saved. */
  var onrow = el('label', 'fw-master vip-onoff');
  var sw = switchBox(dr.on);
  sw._input.disabled = !dr.address && !dr.on;
  sw._input.onchange = function () { dr.on = !!sw._get(); vipDirty(); drawVip(d); };
  onrow.appendChild(sw);
  onrow.appendChild(el('span', '', dr.on ? 'the VIP address is on' : 'the VIP address is off'));
  host.appendChild(onrow);
  host.appendChild(el('p', 'muted small', 'Each node needs keepalived (put in by itself from AlmaLinux\'s own repository), VRRP (IP protocol 112) let in from the other node, and the address in the same network as its own - docs/tls-and-vip.md says what to open in a firewall.'));
  });
}

/* ---- Firewall and access (1.0.52) ---------------------------------------------------
   Who may reach which pages (nginx, page by page) and the machine's firewall:
   acme's own chain ACME-IN, the rules of your own first, then what acme's
   functions need. Every node puts it in through its root helper. */
var FW = {last: null, timer: null, node: null, fam: '4', draft: null, dirty: false};
/* Changes wait for the save bar (1.0.54), as everywhere else in Settings:
   what is shown is the draft, the nodes' state comes live. */
function fwFromServer(d) {
  return JSON.parse(JSON.stringify({on: !!d.conf.on, off: d.conf.off || [], rules: d.conf.rules || [],
                                    access: d.access, access_changed: false}));
}
function fwDirty() {
  fwMarkBar();
  if (FW.last) drawFw(FW.last);
}
function fwPending() {
  pendingSet('fw', {save: fwSave, reset: function () { FW.dirty = false; FW.draft = null; loadFw(); }});
}
function fwMarkBar() {
  if (!FW.dirty) FW.dirty = true;
  FW.ver = (FW.ver || 0) + 1;
  fwPending();
}
function fwSave() {
  if (!FW.draft) return Promise.resolve(true);
  var dr = FW.draft, was = FW.last ? !!FW.last.conf.on : false, ver = FW.ver;
  var go = function () {
    var body = {action: 'save', on: dr.on, off: dr.off, rules: dr.rules};
    if (dr.access_changed) body.access = dr.access;
    return api('firewall', body).then(function (x) {
      toast(x.message, 'good');
      /* Changed while it was being saved: kept, still to be saved (1.0.57). */
      if (FW.ver !== ver) return false;
      FW.dirty = false; FW.draft = null;
      loadFw();
      return true;
    });
  };
  var ask = Promise.resolve(true);
  if (dr.on && !was) {
    ask = askThen('Let acme look after the firewall',
      'acme puts a chain of its own, ACME-IN, first in INPUT on every node, for IPv4 and IPv6, and keeps it in /etc/sysconfig/iptables and ip6tables. Your own rules stay as they are; ACME-IN only lets in - what it does not let in goes on to them. SSH stays open (a rule of acme\'s, which you can turn off).',
      'Turn it on', false);
  } else if (!dr.on && was) {
    ask = askThen('Take acme\'s rules away', 'The chain ACME-IN and its jump go, on every node; the rest of the firewall stays exactly as it is. ' +
      'Whatever only ACME-IN let in (the DNS server, the other node, the pages) is then up to your own rules.', 'Take them away');
  }
  return ask.then(function (yes) { return yes ? go() : false; });
}
function loadFw() {
  if (!CERTADMIN) {
    /* The map of the network is not for every reader (1.0.57); said here once,
       not refused every five seconds (1.0.146). */
    var lede = $('fw-lede');
    if (lede) lede.textContent = 'The firewall and who may reach the pages are shown to administrators only.';
    return;
  }
  apiLatest('fw', 'firewall').then(drawFw).catch(oops);     /* the newest only (1.0.61) */
  clearInterval(FW.timer);
  FW.timer = setInterval(function () {
    if (!paneLive('fw')) { clearInterval(FW.timer); return; }
    if (document.hidden) return;
    if ($('modal') && !$('modal').hidden) return;
    apiLatest('fw', 'firewall').then(function (d) { liveRun(function () { drawFw(d); }); }).catch(function () {});
  }, 5000);
}
function fwFam(f) {
  f = Number(f) || 0;
  return noI18n(el('span', 'fam fam' + (f || 'x'), f ? 'IPv' + f : 'IPv4 + IPv6'));
}
function fwWhat(r) {
  var proto = r.proto === 'any' ? 'everything' : (r.proto === 'icmp' && Number(r.family) === 6 ? 'ICMPv6' : r.proto.toUpperCase());
  return proto + (r.port ? ' ' + r.port : '');
}
function fwAction(a) {
  return el('span', 'fwact fwact-' + a, {accept: 'ACCEPT', drop: 'DROP', reject: 'REJECT'}[a] || a);
}
function fwRuleLine(r) {
  var line = el('div', 'fw-rl');
  line.appendChild(fwFam(r.family));
  line.appendChild(noI18n(el('code', 'fw-what', fwWhat(r))));
  line.appendChild(el('span', 'fw-from', r.source ? 'from ' : 'from anywhere'));
  if (r.source) line.lastChild.appendChild(noI18n(el('code', '', r.source)));
  return line;
}

function drawFw(d) {
  FW.last = d;
  if (!FW.draft || (!FW.dirty && !liveWorkedIn($('fw-master')) && !liveWorkedIn($('fw-access'))
                    && !liveWorkedIn($('fw-body')))) FW.draft = fwFromServer(d);   /* (1.0.206) */
  var dr = FW.draft;
  if (FW.dirty) fwPending();
  /* What is drawn is the draft; the auto rules follow what is turned off in it. */
  d = Object.assign({}, d, {conf: Object.assign({}, d.conf, {on: dr.on, off: dr.off, rules: dr.rules}), access: dr.access});
  d.nodes = d.nodes.map(function (n) {
    return Object.assign({}, n, {auto: (n.auto || []).map(function (a) {
      return Object.assign({}, a, {on: a.fixed || dr.off.indexOf(a.key) < 0});
    })});
  });
  if (!FW.node || !d.nodes.some(function (n) { return n.name === FW.node; })) {
    FW.node = (d.nodes.filter(function (n) { return n.me; })[0] || d.nodes[0] || {}).name;
  }
  drawFwAccess(d);
  /* The switch: acme looks after its rules, or leaves the firewall alone. */
  liveFill($('fw-master'), function (master) {
  var sw = switchBox(d.conf.on);
  sw.classList.add('big');
  sw._input.disabled = !d.may;
  sw._input.onchange = function () { FW.draft.on = !!sw._get(); fwDirty(); };
  var lab = el('label', 'fw-master');
  lab.appendChild(sw);
  lab.appendChild(el('span', '', d.conf.on ? 'acme looks after its rules' : 'acme leaves the firewall alone'));
  master.appendChild(lab);
  });
  $('fw-lede').textContent = d.conf.on
    ? 'In INPUT first: the chain ACME-IN - the other node of the cluster, your own rules in their order, then what acme\'s functions need. What it does not let in goes on to the rules that were there before.'
    : 'Off: nothing is changed in the firewall. Turned on, what acme\'s functions need is let in by itself, and the rules of your own with it.';
  /* The nodes, each with what its root says. */
  var nodes = $('fw-nodes');
  liveFill(nodes, function (nodes) {
  d.nodes.forEach(function (n) {
    var b = el('button', 'fw-node' + (n.name === FW.node ? ' on' : ''));
    b.type = 'button';
    var top = el('div', 'fw-node-top');
    top.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) top.appendChild(el('span', 'tag dim', 'this one'));
    b.appendChild(top);
    var be = (n.fw || {}).backend;
    var st = el('div', 'fw-node-s');
    var tone, words;
    if (!n.alive) { tone = 'crit'; words = 'not answering'; }
    else if (be === 'firewalld') { tone = 'warn'; words = 'firewalld - acme leaves it alone'; }
    else if (n.progress) { tone = 'warn'; words = 'putting it in…'; }
    else if (n.state === 'failed' && !n.current) { tone = 'crit'; words = 'failed - see below'; }
    else if (n.waiting || !n.current) { tone = 'warn'; words = 'waiting for root'; }
    else { tone = 'ok'; words = d.conf.on ? 'in place' : 'nothing of acme\'s'; }
    st.appendChild(el('span', 'dot ' + tone));
    st.appendChild(el('span', '', words));
    b.appendChild(st);
    if (n.address) b.appendChild(noI18n(el('div', 'fw-node-a', n.address)));
    b.onclick = function () { FW.node = n.name; drawFw(FW.last); };
    nodes.appendChild(b);
  });
  });
  nodes.hidden = d.nodes.length < 2;
  drawFwBody(d);
  explainWhatWasDrawn($('pane-fw'));
}

function drawFwAccess(d) {
  var host = $('fw-access');
  liveFill(host, function (host) {
  var st = {};
  var rows = el('div', 'fw-acc');
  var me = d.nodes.filter(function (n) { return n.name === FW.node; })[0] || d.nodes[0] || {};
  var inner = (d.inner || {})[me.name] || [];
  [['portal', 'The enrolment pages', 'https://…/ - the certificate portal', 'people'],
   ['admin', 'The administration', 'https://…/admin/ - these pages', 'gear'],
   ['health', 'The health check', '/healthz - for a load balancer or monitoring (Zabbix, Nagios…)', 'pulse']].forEach(function (p) {
    var acc = FW.draft.access;
    if (!acc[p[0]]) acc[p[0]] = {any: true, from: []};
    st[p[0]] = acc[p[0]];
    st[p[0]].any = !!st[p[0]].any;
    st[p[0]].from = (st[p[0]].from || []).slice();
    var row = el('div', 'fw-acc-row');
    var t = el('div', 'fw-acc-t');
    t.appendChild(el('b', '', p[1]));
    t.appendChild(el('div', 'arow-s', p[2]));
    row.appendChild(t);
    var c = el('div', 'fw-acc-c');
    var seg = el('div', 'seg');
    var box = el('textarea', 'mono fw-nets');
    box.rows = 2; box.spellcheck = false;
    box.placeholder = '10.0.0.0/8, 192.168.10.0/24, 2001:db8::/32';
    box.value = st[p[0]].from.join(', ');
    box.disabled = !d.may;
    /* Into the draft as it is now (1.0.206), not the one this box was drawn from:
       a refresh between made the save send the draft unchanged. */
    var now = function () {
      var a = FW.draft.access;
      if (!a[p[0]]) a[p[0]] = {any: !!st[p[0]].any, from: st[p[0]].from.slice()};
      return a[p[0]];
    };
    box.oninput = function () {
      st[p[0]].from = box.value.split(/[\s,;]+/).filter(Boolean);
      now().from = st[p[0]].from.slice();
      FW.draft.access_changed = true; FW.dirty = true; fwMarkBar();
    };
    [[true, 'Everybody'], [false, 'Only from']].forEach(function (o) {
      var b = el('button', '', o[1]);
      b.type = 'button';
      b.disabled = !d.may || (o[0] && p[0] === 'admin' && hsOn('fw:admin'));
      if (o[0] && p[0] === 'admin' && hsOn('fw:admin')) b.title = 'not under high security';
      b.onclick = function () {
        st[p[0]].any = o[0];
        now().any = o[0];
        Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); });
        box.hidden = o[0];
        FW.draft.access_changed = true; FW.dirty = true; fwMarkBar();
      };
      if (st[p[0]].any === o[0]) b.classList.add('on');
      seg.appendChild(b);
    });
    box.hidden = st[p[0]].any;
    c.appendChild(seg);
    c.appendChild(box);
    row.appendChild(c);
    rows.appendChild(row);
  });
  host.appendChild(rows);
  var foot = el('div', 'fw-acc-foot');
  var always = el('div', 'fw-always');
  always.appendChild(el('span', 'arow-s', 'Always let in:'));
  ['127.0.0.1', '::1'].concat(inner.filter(function (a) { return a !== '127.0.0.1' && a !== '::1'; })).forEach(function (a) { always.appendChild(noI18n(el('code', 'cchip', a))); });
  foot.appendChild(always);
  if (d.access.from_nginx && !FW.draft.access_changed) foot.appendChild(el('span', 'tag dim', 'as install.sh wrote it - not set here yet'));
  host.appendChild(foot);
  });
}

function drawFwBody(d) {
  var body = $('fw-body');
  liveFill(body, function (body) {
  var n = d.nodes.filter(function (x) { return x.name === FW.node; })[0] || {};
  var fw = n.fw || {};
  if (fw.backend === 'firewalld') {
    body.appendChild(el('p', 'note warn', 'firewalld looks after the firewall of ' + n.name + ': acme leaves it to it. ' +
      'To manage it here: dnf install iptables-services; systemctl disable --now firewalld; systemctl enable --now iptables ip6tables. ' +
      'What firewalld must let in is in docs/tls-and-vip.md.'));
  } else if (fw.backend === '' && n.state) {
    body.appendChild(el('p', 'note warn', 'There is no iptables on ' + n.name + '.'));
  }
  if (n.progress) body.appendChild(certProgress(n.progress, n.name));
  if (n.state === 'failed' && (n.said || []).length) {
    var bad = el('div', 'note bad');
    bad.appendChild(el('b', '', 'Root on ' + n.name + ' did not put it in: '));
    bad.appendChild(noI18n(el('span', '', n.said[n.said.length - 1])));
    if (d.may) {
      var again = cmdButton('Try again', 'refresh', 'small');
      again.onclick = function () { api('web', {action: 'retry', node: n.name}).then(function (x) { toast(x.message, 'good'); }).catch(oops); };
      bad.appendChild(again);
    }
    body.appendChild(bad);
  }
  /* How a packet goes: one line, so the order is plain. */
  var flow = el('div', 'fw-flow' + (d.conf.on ? '' : ' off'));
  [['INPUT', ''], ['ACME-IN: the other node', 'auto'], ['your rules', 'mine'], ['what acme needs', 'auto'], ['the rest of INPUT', 'rest']].forEach(function (s, i) {
    if (i) flow.appendChild(el('span', 'fw-arrow', '→'));
    flow.appendChild(el('span', 'fw-step ' + s[1], s[0]));
  });
  body.appendChild(flow);

  /* Your own rules. */
  var h1 = el('div', 'fw-h');
  h1.appendChild(el('h3', '', 'Rules of your own'));
  if (d.may) {
    var add = cmdButton('Add a rule', 'add', 'small primary');
    add.onclick = function () { fwRuleEdit(d, null); };
    h1.appendChild(add);
  }
  body.appendChild(h1);
  body.appendChild(el('p', 'note', 'Looked at in this order, right after the other node of the cluster (which nothing can shut out): a DROP or REJECT here wins over what acme lets in below. For all nodes, or for one.'));
  var mine = (d.conf.rules || []);
  body.appendChild(listTable(['', 'Action', 'IP', 'What', 'From', 'Node', 'Note', ''], mine, function (r, i) {
    var tr = el('tr', r.disabled ? 'dim' : '');
    tr.appendChild(el('td', 'num muted', String(i + 1)));
    var a = el('td'); a.appendChild(fwAction(r.action)); tr.appendChild(a);
    var f = el('td'); f.appendChild(fwFam(r.family)); tr.appendChild(f);
    tr.appendChild(noI18n(el('td', 'mono', fwWhat(r))));
    tr.appendChild(r.source ? noI18n(el('td', 'mono', r.source)) : el('td', 'muted', 'anywhere'));
    var sc = el('td'); sc.appendChild(r.scope === 'all' ? el('span', 'tag dim', 'all nodes') : noI18n(el('span', 'tag', r.scope))); tr.appendChild(sc);
    tr.appendChild(noI18n(el('td', 'muted', r.note || '')));
    var tools = el('td', 'acts');
    if (d.may) {
      var up = iconButton('up', 'Earlier'); up.disabled = i === 0;
      up.onclick = function () { fwMove(i, -1); };
      var dn = iconButton('down', 'Later'); dn.disabled = i === mine.length - 1;
      dn.onclick = function () { fwMove(i, 1); };
      var ed = iconButton('edit', 'Change it'); ed.onclick = function () { fwRuleEdit(d, r); };
      var rm = iconButton('trash', 'Take it away');
      rm.onclick = function () { FW.draft.rules.splice(i, 1); fwDirty(); };
      [up, dn, ed, rm].forEach(function (b) { tools.appendChild(b); });
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain fw-table|None yet - acme\'s own rules below are enough for what it does'));

  /* What acme lets in by itself, on this node. */
  var h2 = el('div', 'fw-h');
  h2.appendChild(el('h3', '', 'What acme lets in by itself'));
  h2.appendChild(noI18n(el('span', 'tag dim', n.name || '')));
  body.appendChild(h2);
  body.appendChild(el('p', 'note', 'Worked out from what is set up, and changed with it: the DNS server for DNS-01 switched on, the cluster made, the VIP address turned on. What keeps the cluster working cannot be turned off.'));
  var grid = el('div', 'fw-auto');
  (n.auto || []).forEach(function (item) {
    var card = el('div', 'fw-auto-card' + (item.on ? '' : ' off'));
    var top = el('div', 'fw-auto-top');
    var t = el('div', '');
    t.appendChild(el('b', '', item.title));
    t.appendChild(el('div', 'arow-s', item.why));
    top.appendChild(t);
    if (item.fixed) {
      top.appendChild(el('span', 'tag ok', 'always'));
    } else {
      var sw = switchBox(item.on);
      sw._input.disabled = !d.may;
      sw._input.onchange = function () {
        var off = FW.draft.off.filter(function (k) { return k !== item.key; });
        if (!sw._get()) off.push(item.key);
        FW.draft.off = off;
        fwDirty();
      };
      top.appendChild(sw);
    }
    card.appendChild(top);
    (item.pending || []).forEach(function (x) {
      /* Opened for the node being joined, before the cluster is made (1.0.210). */
      var pn = el('div', 'fw-pending');
      pn.appendChild(haWords('Opened for the node being joined: ', x.address, ', until ', haWhen(x.until)));
      card.appendChild(pn);
    });
    var list = el('div', 'fw-auto-rules');
    if (!item.rules.length) list.appendChild(el('span', 'muted', 'nothing'));
    item.rules.slice(0, 12).forEach(function (r) { list.appendChild(fwRuleLine(r)); });
    if (item.rules.length > 12) list.appendChild(el('span', 'muted', '… and ' + (item.rules.length - 12) + ' more'));
    card.appendChild(list);
    grid.appendChild(card);
  });
  body.appendChild(grid);

  /* Everything else: read only. */
  var other = el('details', 'fw-other');
  other.appendChild(el('summary', '', 'The whole firewall on ' + (n.name || 'this node') + ' (read only)'));
  var seg = el('div', 'seg');
  var pre = noI18n(el('pre', 'fw-pre'));
  /* All of it (1.0.67): every chain of the filter table as iptables-save
     shows it, ACME-IN's lines marked - root reads it after every change,
     and again when asked. Where it has not been read yet, INPUT alone. */
  var full = fw.full || null, now = fw.now || {};
  var paint = function () {
    var lines = full ? (full[FW.fam] || []) : (now[FW.fam] || []);
    clear(pre);
    if (!lines.length) pre.textContent = '(nothing - or not known yet)';
    lines.forEach(function (line, i) {
      var ours = /ACME-IN/.test(line);
      var sp = el('span', ours ? 'fw-line fw-ours' : 'fw-line', line);
      pre.appendChild(sp);
      if (i < lines.length - 1) pre.appendChild(document.createTextNode('\n'));
    });
    Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x.dataset.f === FW.fam); });
  };
  [['4', 'IPv4 (iptables)'], ['6', 'IPv6 (ip6tables)']].forEach(function (o) {
    var b = el('button', '', o[1]); b.type = 'button'; b.dataset.f = o[0];
    b.onclick = function () { FW.fam = o[0]; paint(); };
    seg.appendChild(b);
  });
  other.appendChild(seg);
  other.appendChild(pre);
  var foot = el('p', 'note');
  foot.appendChild(document.createTextNode(full
    ? 'The filter table as iptables-save shows it, read ' + (fw.full_at ? ago(fw.full_at) : '?') + '. The marked lines are acme\'s (the chain ACME-IN and the jump to it); the rest are yours, and acme never changes them. '
    : 'INPUT as iptables-save shows it, without ACME-IN. These lines are yours: acme never changes them. '));
  /* The other node's too (1.0.71): asked through the database, root there
     reads it and it comes back in a few seconds. */
  if (n.me || n.alive) {
    var again = el('a', 'fgo', 'Read it again');
    again.onclick = function () {
      again.textContent = 'reading…';
      api('firewall&fresh=' + encodeURIComponent(n.me ? '1' : n.name), undefined, 30).then(function (d) {
        FW.otherOpen = true; drawFw(d);
      }).catch(oops);
    };
    foot.appendChild(again);
  }
  other.appendChild(foot);
  paint();
  if (FW.otherOpen) other.open = true;
  other.ontoggle = function () { FW.otherOpen = other.open; };
  body.appendChild(other);
  });
}

function fwMove(i, dir) {
  var list = FW.draft.rules, j = i + dir;
  if (j < 0 || j >= list.length) return;
  var t = list[i]; list[i] = list[j]; list[j] = t;
  fwDirty();
}
function fwRuleEdit(d, r) {
  var st = Object.assign({family: 0, proto: 'tcp', port: '', source: '', action: 'accept', scope: 'all', note: '', disabled: false}, r || {});
  modal(r ? 'Change the rule' : 'A rule of your own', function (body) {
    var rows = el('div', 'tls-rows');
    var segOf = function (opts, key, after) {
      var seg = el('div', 'seg');
      opts.forEach(function (o) {
        var b = el('button', '', o[1]); b.type = 'button';
        b.onclick = function () { st[key] = o[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); if (after) after(); };
        if (String(st[key]) === String(o[0])) b.classList.add('on');
        seg.appendChild(b);
      });
      return seg;
    };
    rows.appendChild(tlsRow('Action', 'ACCEPT lets it in; DROP says nothing; REJECT answers that it is closed.',
      segOf([['accept', 'Accept'], ['drop', 'Drop'], ['reject', 'Reject']], 'action')));
    rows.appendChild(tlsRow('IP version', 'Taken from the address when one is given.',
      segOf([[0, 'Both'], [4, 'IPv4'], [6, 'IPv6']], 'family')));
    var port = textBox('', '', 'mono'); port.value = st.port; port.placeholder = '443 · 8000-8100 · 80,443';
    port.oninput = function () { st.port = port.value.trim(); };
    var portRow = tlsRow('Port', 'One, a range, or several by commas. Empty: every port.', port);
    var paintPort = function () { portRow.classList.toggle('dim', ['tcp', 'udp'].indexOf(st.proto) < 0); port.disabled = ['tcp', 'udp'].indexOf(st.proto) < 0; if (port.disabled) { port.value = ''; st.port = ''; } };
    rows.appendChild(tlsRow('Protocol', '', segOf([['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP'], ['vrrp', 'VRRP'], ['any', 'Any']], 'proto', paintPort)));
    rows.appendChild(portRow);
    var src = textBox('', '', 'mono'); src.value = st.source; src.placeholder = '192.0.2.0/24 · 2001:db8::/32 · empty = anywhere';
    src.oninput = function () { st.source = src.value.trim(); };
    rows.appendChild(tlsRow('From', 'An address or a network.', src));
    var scope = selectBox([['all', 'All nodes']].concat(d.nodes.map(function (n) { return [n.name, n.name + (n.me ? ' (this one)' : '')]; })), st.scope);
    scope.onchange = function () { st.scope = scope.value; };
    rows.appendChild(tlsRow('On', 'Every node, or only one.', scope));
    var note = textBox('', ''); note.value = st.note; note.placeholder = 'Zabbix agent'; note.maxLength = 80;
    note.oninput = function () { st.note = note.value; };
    rows.appendChild(tlsRow('Note', 'Shown here and as the comment of the rule in iptables.', note));
    var dis = switchBox(!st.disabled);
    dis._input.onchange = function () { st.disabled = !dis._get(); };
    rows.appendChild(tlsRow('In force', 'Off keeps it here without putting it in.', dis));
    body.appendChild(rows);
    paintPort();
  }, [{words: 'Cancel', close: true},
      {words: r ? 'Change it' : 'Add it', cls: 'primary', icon: 'check', go: function (b) {
        /* Checked by the daemon now, kept in the draft until Save (1.0.54). */
        busy(b, true);
        api('firewall', {action: 'rule_check', rule: st}).then(function (x) {
          var got = Object.assign({}, x.rule, {id: r ? r.id : 'n' + Date.now().toString(36)});
          var list = FW.draft.rules;
          var i = r ? list.findIndex(function (y) { return y.id === r.id; }) : -1;
          if (i >= 0) list[i] = got; else list.push(got);
          closeModal(); fwDirty();
        }).catch(oops).then(function () { busy(b, false); });
      }}], 'medium');
}

/* ---- Replication's errors and the cluster's history (1.0.52) ------------------------ */
function haErrors() {
  var host = el('div', 'ha-err');
  host.appendChild(el('p', 'muted', 'Asking PostgreSQL\'s log…'));
  modal('Replication errors on ' + ((HA && HA.node) || 'this node'), host, [
    {words: 'Close', close: true},
    {words: 'Clear them', icon: 'check', cls: 'danger', admin: true, go: function (b) {
      busy(b, true);
      api('ha', {action: 'errors_clear'}).then(function (x) { toast(x.message, 'good'); closeModal(); loadHa(); }).catch(oops).then(function () { busy(b, false); });
    }}], 'large');
  api('ha', {action: 'errors'}).then(function (d) { drawHaErrors(host, d); }).catch(function (e) { clear(host); host.appendChild(el('p', 'note bad', e.message || String(e))); });
}
function haErrorWhy(text) {
  /* What the commonest ones mean, in a sentence. */
  var t = String(text || '');
  if (/duplicate key value violates unique constraint/i.test(t)) return 'A row that came over already exists here - it was written on both nodes (or this node was rebuilt without its slot cleared). Replication retries it until it gives way; usually a rebuild of this node from the other, or the row taken away, ends it.';
  if (/could not connect to the publisher|connection to server .* failed|could not receive data from WAL stream|terminating logical replication worker due to/i.test(t)) return 'The other node or its PostgreSQL was not reached for a while (a restart, a network cut). Nothing to do when it went on by itself afterwards.';
  if (/replication slot .* does not exist/i.test(t)) return 'The other node\'s slot for this one is gone (it was rebuilt or reinstalled): rebuild this node from the other, or make replication again.';
  if (/replication slot .* is active for PID/i.test(t)) return 'An old connection still held the slot; it goes by itself within a minute.';
  if (/relation .* does not exist|logical replication target relation .* does not exist/i.test(t)) return 'A table the other node sends is not here - the nodes run different versions: upgrade this one, then Read the tables again.';
  if (/publication .* does not exist/i.test(t)) return 'The other node no longer publishes: make replication again from there.';
  if (/out of memory|could not extend file|No space left/i.test(t)) return 'The machine ran out of memory or disk.';
  if (/canceling statement due to statement timeout|lock timeout/i.test(t)) return 'A lock or a timeout - it is retried by itself.';
  return '';
}
function drawHaErrors(host, d) {
  clear(host);
  var subs = d.subs || [];
  var grid = el('div', 'ha-err-sum');
  subs.forEach(function (s) {
    var c = el('div', 'ha-err-card');
    c.appendChild(noI18n(el('b', 'mono', s.name)));
    var line = el('div', 'ha-err-n');
    line.appendChild(el('span', 'big ' + (s.apply_new + s.sync_new ? 'bad' : 'good'), num(s.apply_new + s.sync_new)));
    line.appendChild(el('span', 'muted', s.cleared ? 'since cleared ' + stamp(s.cleared) + (s.cleared_by ? ' by ' + s.cleared_by : '') : 'since PostgreSQL started counting'));
    c.appendChild(line);
    c.appendChild(el('div', 'arow-s', 'applying rows: ' + num(s.apply_new) + ' · first copy of a table: ' + num(s.sync_new) + ' · in all ' + num(s.apply + s.sync)));
    c.appendChild(el('span', 'tag ' + (s.running ? 'ok' : (s.enabled ? 'crit' : 'warn')), s.running ? 'running now' : (s.enabled ? 'not running now' : 'paused')));
    grid.appendChild(c);
  });
  host.appendChild(grid);
  host.appendChild(el('p', 'note', 'An error stops what comes in for a moment; PostgreSQL then tries the same again, every few seconds, until it goes through - so a count that went up and then stopped growing, with replication running now, was a passing thing (a restart, the other node away). One that keeps growing needs a look: what PostgreSQL said is below.'));
  var head = el('div', 'fw-h');
  head.appendChild(el('h3', '', 'What PostgreSQL said'));
  if (d.log_file) head.appendChild(noI18n(el('span', 'tag dim', d.log_file)));
  host.appendChild(head);
  if (!d.fresh) host.appendChild(el('p', 'note warn', 'Root did not answer in time (acme-web.path) - this is what it read last' + (d.log_at ? ', ' + ago(d.log_at) : '') + '.'));
  if (d.log_said) host.appendChild(el('p', 'note warn', d.log_said));
  var list = el('div', 'ha-err-log');
  var all = (d.log || []).slice().reverse();
  var seg = el('div', 'seg');
  [[true, 'Errors and warnings'], [false, 'Everything about replication']].forEach(function (o) {
    var b = el('button', '', o[1]); b.type = 'button';
    if (HA_ERR_ONLY === o[0]) b.classList.add('on');
    b.onclick = function () { HA_ERR_ONLY = o[0]; drawHaErrors(host, d); };
    seg.appendChild(b);
  });
  host.appendChild(seg);
  var rows = all.filter(function (e) { return !HA_ERR_ONLY || e.level !== 'LOG'; });
  if (!rows.length) list.appendChild(el('p', 'muted', !d.log_at ? 'Nothing read yet.' : (HA_ERR_ONLY ? 'No error or warning about replication in the log' : 'Nothing about replication in the log') + (subs[0] && subs[0].cleared ? ' since it was cleared' : '') + (HA_ERR_ONLY && all.length ? ' - ' + all.length + ' ordinary line(s) under Everything.' : '.')));
  rows.forEach(function (e) {
    var item = el('div', 'ha-err-item ' + String(e.level || '').toLowerCase());
    var top = el('div', 'ha-err-top');
    top.appendChild(el('span', 'tag ' + ({ERROR: 'crit', FATAL: 'crit', PANIC: 'crit', WARNING: 'warn'}[e.level] || 'dim'), e.level));
    top.appendChild(el('span', 'muted', e.ts ? stamp(e.ts) : ''));
    item.appendChild(top);
    item.appendChild(noI18n(el('div', 'mono ha-err-text', e.text)));
    (e.more || []).forEach(function (m) { item.appendChild(noI18n(el('div', 'mono ha-err-more', m))); });
    var why = haErrorWhy(e.text + ' ' + (e.more || []).join(' '));
    if (why) item.appendChild(el('div', 'ha-err-why', why));
    list.appendChild(item);
  });
  host.appendChild(list);
  host.appendChild(el('p', 'note', 'Clear them once dealt with: from then on only new ones are counted here and shown red on the page (PostgreSQL\'s own count goes on). On the command line: journalctl -u postgresql-16, or the files in the data folder\'s log/.'));
}

var HA_HIST_FILTER = 'all';
var HA_ERR_ONLY = true;
function haHistory() {
  var host = el('div', 'ha-hist');
  host.appendChild(el('p', 'muted', 'Reading…'));
  modal('What happened to the cluster', host, [
    {words: 'Clear the history', icon: 'forget', cls: 'danger', left: true, admin: true, go: function (b) {
      busy(b, true);
      api('ha', {action: 'history_clear'}).then(function (x) {
        toast(x.message, 'good');
        return apiLatest('ha-history', 'ha-history&limit=2000' + tpQuery('ha-hist-time')).then(function (d) { drawHaHistory(host, d); });
      }).catch(oops).then(function () { busy(b, false); });
    }},
    {words: 'Close', close: true}], 'large');
  /* With the window the picker remembers, from the first answer (1.0.57). */
  var q = '';
  try {
    var keep = JSON.parse(localStorage.getItem('acme.tp.ha-hist-time') || 'null');
    if (keep && keep.k && keep.k !== 'all') {
      var r = tpRange(keep);
      q = (r.from ? '&from=' + Math.floor(r.from) : '') + (r.to ? '&to=' + Math.ceil(r.to) : '');
    }
  } catch (e) { q = ''; }
  apiLatest('ha-history', 'ha-history&limit=2000' + q).then(function (d) { drawHaHistory(host, d); }).catch(oops);
}
function drawHaHistory(host, d) {
  clear(host);
  var rows = d.rows || [];
  var KINDS = [['all', 'Everything'], ['vip', 'The VIP address'], ['node', 'Nodes and health'], ['replication', 'Replication'], ['maintenance', 'Maintenance and upgrades']];
  var bar = el('div', 'ha-hist-bar');
  var tph = el('span'); tph.id = 'ha-hist-time';
  var seg = el('div', 'seg');
  var counts = el('div', 'ha-hist-counts');
  var bad = rows.filter(function (r) { return r.level === 'bad'; }).length;
  var moved = rows.filter(function (r) { return r.what === 'vip' && r.kind === 'ha' && /came to/.test(r.words); }).length;
  counts.appendChild(el('span', 'cchip', moved + ' × the VIP address moved'));
  counts.appendChild(el('span', 'cchip' + (bad ? ' warn' : ''), bad + ' × trouble'));
  var list = el('div', 'ha-hist-list');
  var paint = function () {
    clear(list);
    var shown = rows.filter(function (r) { return HA_HIST_FILTER === 'all' || r.what === HA_HIST_FILTER; });
    if (!shown.length) list.appendChild(el('p', 'muted', 'Nothing yet - it is written down from version 1.0.52 on, as it happens.'));
    var day = '';
    shown.forEach(function (r) {
      var dd = String(stamp(r.ts)).slice(0, 10);
      if (dd !== day) { day = dd; list.appendChild(noI18n(el('div', 'ha-hist-day', dd))); }
      var it = el('div', 'ha-hist-item ' + (r.level || 'info'));
      it.appendChild(el('span', 'ha-hist-dot'));
      var t = el('div', 'ha-hist-t');
      var top = el('div', 'ha-hist-top');
      top.appendChild(noI18n(el('span', 'mono muted', String(stamp(r.ts)).slice(11))));
      top.appendChild(el('span', 'tag dim', {vip: 'VIP address', node: 'node', replication: 'replication', maintenance: 'maintenance'}[r.what] || r.what));
      if (r.node) top.appendChild(noI18n(el('span', 'tag', r.node)));
      top.appendChild(el('span', 'muted', r.kind === 'ha' ? 'seen by itself' : 'done by ' + (r.who || 'hand')));
      t.appendChild(top);
      t.appendChild(noI18n(el('div', '', r.words)));
      it.appendChild(t);
      list.appendChild(it);
    });
  };
  KINDS.forEach(function (k) {
    var b = el('button', '', k[1]); b.type = 'button';
    if (k[0] === HA_HIST_FILTER) b.classList.add('on');
    b.onclick = function () { HA_HIST_FILTER = k[0]; Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); }); paint(); };
    seg.appendChild(b);
  });
  bar.appendChild(seg);
  bar.appendChild(tph);
  bar.appendChild(counts);
  host.appendChild(bar);
  var p = timePicker('ha-hist-time', {start: {k: 'all'}, all: true});
  p.onchange = function () { apiLatest('ha-history', 'ha-history' + tpQuery('ha-hist-time') + '&limit=2000').then(function (x) { drawHaHistory(host, x); }).catch(oops); };
  host.appendChild(list);
  paint();
}
if ($('ha-history')) $('ha-history').onclick = haHistory;
if ($('ha-errors')) $('ha-errors').onclick = haErrors;

/* ---- the pictures on the sign-ins (1.0.71; each its own since 1.0.72) ----
   A press only marks the change (1.0.73); it is made with Save the changes
   at the bottom, as every other setting, and Put them back drops it. */
var ART = {last: null, slot: 'portal', draft: {}};
function loadArt() {
  return api('art').then(function (d) {
    /* What waits for the save bar stays; the rest is drawn as saved. */
    Object.keys(ART.draft).forEach(function (k) { if (!PENDING['art-' + k]) delete ART.draft[k]; });
    drawArt(d);
  }).catch(oops);
}
function artDraft(slot) {
  var saved = (ART.last || {})[slot] || {};
  if (!ART.draft[slot]) ART.draft[slot] = {art: saved.art, data: '', name: '', bytes: 0, forget: false};
  return ART.draft[slot];
}
function artChanged(slot) {
  var dr = ART.draft[slot], saved = (ART.last || {})[slot] || {};
  return !!(dr && (dr.art !== saved.art || dr.data || dr.forget));
}
function artMark(slot) {
  var key = 'art-' + slot;
  if (artChanged(slot)) {
    pendingSet(key, {save: function () { return artSave(slot); },
                     reset: function () { delete ART.draft[slot]; if (ART.last) drawArt(ART.last); }});
  } else if (PENDING[key]) {
    delete PENDING[key];
    markDirtyCount();
  }
  drawArt(ART.last);
}
function artSave(slot) {
  var dr = ART.draft[slot];
  if (!dr || !artChanged(slot)) return Promise.resolve(true);
  return api('art', {slot: slot, action: 'save', art: dr.art, data: dr.data || undefined,
                     name: dr.name || undefined, forget: dr.forget || undefined}).then(function (d) {
    delete ART.draft[slot];
    drawArt(d);
    return true;
  });
}
function drawArt(all) {
  if (!all) return;
  ART.last = all;
  var slot = ART.slot, saved = all[slot] || {};
  var dr = ART.draft[slot] || {art: saved.art};
  var grid = $('art-grid'), tpl = $('art-gallery');
  if (!grid || !tpl) return;
  Array.prototype.forEach.call($('art-slot').children, function (b) {
    b.classList.toggle('on', b.dataset.slot === slot);
    b.classList.toggle('changed', artChanged(b.dataset.slot));
    b.onclick = function () { ART.slot = b.dataset.slot; drawArt(ART.last); };
  });
  $('art-note-portal').hidden = slot !== 'portal';
  $('art-note-admin').hidden = slot !== 'admin';
  /* A picture of your own as it will be after the save: a new one, the one
     kept, or none when it is to be taken away. */
  var own = dr.data ? {src: dr.data, name: dr.name, bytes: dr.bytes, fresh: true}
    : (saved.logo && !dr.forget ? {src: '/admin/?api=logo&slot=' + slot + '&v=' + encodeURIComponent(saved.logo.sha || ''),
                                  name: saved.logo.name, bytes: saved.logo.bytes, by: saved.logo.by, at: saved.logo.at} : null);
  clear(grid);
  Array.prototype.forEach.call(tpl.content.children, function (src) {
    var name = src.dataset.art;
    var picked = dr.art === name, isNow = saved.art === name;
    var tile = el('button', 'art-tile' + (picked ? ' on' : '') + (picked && !isNow ? ' unsaved' : ''));
    tile.type = 'button';
    var pic = el('div', 'art-pic');
    if (name === 'custom') {
      if (own) {
        var img = el('img');
        img.src = own.src;
        img.alt = '';
        pic.appendChild(img);
      } else {
        pic.appendChild(el('span', 'muted small', dr.forget ? 'taken away when saved' : 'nothing uploaded yet'));
        pic.classList.add('art-empty');
      }
    } else if (name === 'none') {
      pic.appendChild(el('span', 'muted small', 'only the sign-in'));
      pic.classList.add('art-empty');
    } else {
      pic.innerHTML = src.innerHTML;  /* our own drawing, from this page's markup */
      var t = pic.querySelector('title');
      if (t) t.removeAttribute('id');
      var sv = pic.querySelector('svg');
      if (sv) sv.removeAttribute('aria-labelledby');
    }
    tile.appendChild(pic);
    var cap = el('div', 'art-cap');
    cap.appendChild(el('span', '', src.dataset.words));
    if (picked && !isNow) cap.appendChild(el('span', 'tag warn', 'after saving'));
    else if (isNow) cap.appendChild(el('span', 'tag ok', 'shown'));
    else if (name === saved.default) cap.appendChild(el('span', 'tag', 'the default'));
    tile.appendChild(cap);
    if (name === 'custom' && own) {
      tile.appendChild(noI18n(el('div', 'art-meta mono small muted',
        (own.name || '') + ' · ' + bytes(own.bytes) + (own.fresh ? '' : ' · ' + (own.by || '?') + ', ' + ago(own.at)))));
    }
    tile.disabled = !ADMIN;
    tile.onclick = function () {
      if (name === 'custom' && !own) { $('art-file').click(); return; }
      artDraft(slot).art = name;
      artMark(slot);
    };
    grid.appendChild(tile);
  });
  $('art-forget').hidden = !own;
  $('art-reset').disabled = dr.art === saved.default;
  $('art-said').textContent = '';
}
if ($('art-upload')) {
  $('art-upload').onclick = function () { $('art-file').click(); };
  $('art-reset').onclick = function () {
    var slot = ART.slot;
    artDraft(slot).art = ((ART.last || {})[slot] || {}).default;
    artMark(slot);
  };
  $('art-forget').onclick = function () {
    var slot = ART.slot, dr = artDraft(slot);
    if (dr.data) { dr.data = ''; dr.name = ''; dr.bytes = 0; }
    else dr.forget = true;
    if (dr.art === 'custom' && !(((ART.last || {})[slot] || {}).logo && !dr.forget)) dr.art = ((ART.last || {})[slot] || {}).default;
    artMark(slot);
  };
  $('art-file').onchange = function () {
    var file = this.files && this.files[0];
    this.value = '';
    if (!file) return;
    if (file.size > 512 * 1024) { toast(file.name + ' is ' + bytes(file.size) + ' - at most 512 KB', 'bad'); return; }
    var slot = ART.slot;
    var reader = new FileReader();
    reader.onload = function () {
      var dr = artDraft(slot);
      dr.data = String(reader.result || ''); dr.name = file.name; dr.bytes = file.size;
      dr.forget = false; dr.art = 'custom';
      artMark(slot);
    };
    reader.readAsDataURL(file);
  };
}

/* ---- a test SMS (1.0.76) ---------------------------------------------------- */
if ($('sms-try')) {
  $('sms-try').onclick = function () {
    var b = $('sms-try');
    var stop = busyCount(b);
    $('sms-said').textContent = '';
    api('mail', {action: 'sms_test', to: $('sms-to').value.trim()}).then(function (d) {
      $('sms-said').textContent = (d.sent ? '✓ ' : '✗ ') + d.said + ' · ' + d.took_ms + ' ms';
      $('sms-said').style.color = d.sent ? 'var(--ok)' : 'var(--crit)';
      toast(d.sent ? 'sent to ' + d.to : 'not sent: ' + d.said, d.sent ? 'good' : 'bad');
    }).catch(oops).then(stop);
  };
}

/* ---- the outgoing mail (1.0.95) -------------------------------------------- */
var MQ = {page: 0, per: 50, timer: null};
var MQ_STATE_WORDS = {sending: ['being sent', 'info'], waiting: ['waiting', 'warn'], sent: ['sent', 'ok'],
                      failed: ['failed', 'crit'], expired: ['given up', 'dim']};
function mailqBadge(c) {
  var b = $('mq-badge');
  if (!b || !c) return;
  var n = (c.waiting || 0) + (c.failed || 0) + (c.sending || 0);
  b.hidden = !n;
  b.textContent = num(n);
  b.className = 'nav-badge' + (c.failed ? ' bad' : '');
  b.title = (c.waiting || 0) + ' waiting · ' + (c.failed || 0) + ' failed';
}
function mailqWatch(on) {
  clearInterval(MQ.timer);
  MQ.timer = null;
  /* Drawn again every 10 s while it is looked at - what waits moves by itself. */
  if (on) MQ.timer = setInterval(function () {
    if (PANE !== 'mailq' || TAB !== 'settings') { mailqWatch(false); return; }
    if (document.hidden) return;        /* skipped, not stopped (1.0.206): back on the tab it went on never */
    if (!document.querySelector('.modal:not([hidden])')) loadMailq(true);
  }, 10000);
}
function mailqStateTag(st) {
  var w = MQ_STATE_WORDS[st] || [st || '?', 'dim'];
  return el('span', 'tag ' + w[1], w[0]);
}
function loadMailq(quiet) {
  if (!$('mq-table')) return;
  if (!quiet) mailqWatch(true);
  apiLatest('mailq', 'mailq&q=' + encodeURIComponent($('mq-q').value) + '&state=' + $('mq-state').value
      + '&limit=' + MQ.per + '&offset=' + MQ.page * MQ.per).then(function (d) {
    QS.mailq.said(d.q_error || '');
    var c = d.counts || {};
    mailqBadge(c);
    var chips = $('mq-chips');
    clear(chips);
    [['waiting', 'waiting for another try'], ['sending', 'being sent'], ['failed', 'failed'],
     ['sent', 'sent'], ['expired', 'given up']].forEach(function (x) {
      var ch = el('button', 'mq-chip ' + (MQ_STATE_WORDS[x[0]] || ['', ''])[1] + ($('mq-state').value === x[0] ? ' on' : ''));
      ch.type = 'button';
      ch.appendChild(el('b', '', num(c[x[0]] || 0)));
      ch.appendChild(el('span', '', x[1]));
      ch.onclick = function () { $('mq-state').value = $('mq-state').value === x[0] ? '' : x[0]; MQ.page = 0; loadMailq(); };
      chips.appendChild(ch);
    });
    $('mq-said').textContent = (d.mode === 'off' ? 'Sending mail is switched off (Settings → Mail): nothing is sent or tried again. · ' : '')
      + 'A mail not taken is tried again for ' + d.retry_hours + ' h (a code to sign in with only while it is good); the list keeps what went or failed for ' + d.keep_days + ' days.';
    liveFill($('mq-table'), function (host) {
    var cluster = STATUS && STATUS.cluster;
    var heads = ['Made', 'To', 'What', 'State', {words: 'Tries', cls: 'num'}, 'Next try / went', 'What it said'];
    if (cluster) heads.push('Node');
    heads.push('');
    host.appendChild(listTable(heads, d.rows, function (r) {
      var tr = el('tr');
      tr.appendChild(stampCell(r.created));
      var to = el('td');
      to.appendChild(noI18n(el('span', 'mono', (r.to || []).join(', '))));
      if (r.name && (r.to || []).join() !== r.name) to.appendChild(noI18n(el('span', 'sub', r.name)));
      tr.appendChild(to);
      var what = el('td');
      what.appendChild(el('span', '', r.kind_words || r.kind));
      if (r.subject) what.appendChild(noI18n(el('span', 'sub', r.subject)));
      tr.appendChild(what);
      var st = el('td');
      st.appendChild(mailqStateTag(r.state));
      tr.appendChild(st);
      tr.appendChild(el('td', 'num', num(r.tries || 0)));
      if (r.state === 'sent') tr.appendChild(stampCell(r.sent_at));
      else if (r.state === 'waiting') {
        var nx = el('td', 'small');
        var left = (r.next_at || 0) - Date.now() / 1000;
        nx.textContent = left > 5 ? 'in ' + span(left) : 'now';
        nx.title = 'tried until ' + dayWords(new Date((r.expires || 0) * 1000)) + ' ' + clockWords(new Date((r.expires || 0) * 1000));
        tr.appendChild(nx);
      } else tr.appendChild(el('td', 'muted small', r.state === 'sending' ? 'now' : '–'));
      var said = el('td', 'muted small mq-said');
      said.textContent = r.said || '';
      said.title = r.said || '';
      noI18n(said);
      tr.appendChild(said);
      if (cluster) tr.appendChild(noI18n(el('td', 'muted small', r.node || '')));
      var tools = el('td', 'rowtools');
      if (CERTADMIN) {
        if (r.state === 'waiting' || r.state === 'failed') {
          var again = iconButton('refresh', 'Send it again now');
          again.onclick = function (e) { e.stopPropagation(); mailqDo('retry', [r.qid]); };
          tools.appendChild(again);
        }
        var x = iconButton('trash', 'Take it out of the outgoing mail');
        x.onclick = function (e) {
          e.stopPropagation();
          confirmThen('Take the mail out', 'The mail to <b>' + htmlText((r.to || []).join(', ')) + '</b> ('
            + htmlText(r.kind_words || '') + ') goes from the list' + (r.state === 'waiting' ? ' and is not tried again' : '') + '.',
            'Take it out', function () { mailqDo('drop', [r.qid]); }, true);
        };
        tools.appendChild(x);
      }
      tr.appendChild(tools);
      tr.onclick = function () { mailqPeek(r.qid); };
      tr.classList.add('tappable');
      return tr;
    }, 'rows', {own: true}));
    }, !!quiet);
    pager('mq-pager', MQ.page, MQ.per, d.total, function (p) { MQ.page = p; loadMailq(); });
    explainWhatWasDrawn($('pane-mailq'));
  }).catch(oops);
}
function mailqDo(act, ids) {
  return api('mailq', {action: act, ids: ids || []}).then(function (x) {
    toast(x.message, 'good');
    loadMailq(true);
    setTimeout(function () { if (PANE === 'mailq') loadMailq(true); }, 2500);
  }).catch(oops);
}
function mailqPeek(qid) {
  api('mailq-one&id=' + encodeURIComponent(qid)).then(function (r) {
    modal('A mail to ' + (r.to || []).join(', '), function (body) {
      var kv = el('div', 'me-kv');
      var row = function (k, v) { kv.appendChild(el('div', 'k', k)); var d = el('div', 'v'); if (typeof v === 'string') d.appendChild(noI18n(el('span', '', v))); else d.appendChild(v); kv.appendChild(d); };
      var at = function (ts) { var d = new Date((ts || 0) * 1000); return dayWords(d) + ' ' + clockWords(d); };
      row('State', mailqStateTag(r.state));
      row('What', el('span', '', r.kind_words || '')); if (r.subject) row('Subject', r.subject);
      row('Made', at(r.created) + (r.by ? ' · ' + r.by : ''));
      if (r.state === 'sent') row('Went', at(r.sent_at));
      if (r.state === 'waiting') row('Next try', at(r.next_at));
      row('Tried until', at(r.expires));
      if (r.node) row('Sent by the node', r.node);
      body.appendChild(kv);
      if ((r.history || []).length) {
        body.appendChild(el('h3', '', 'Tries'));
        body.appendChild(listTable(['When', 'Node', '', 'What it said'], r.history.slice().reverse(), function (h) {
          var tr = el('tr');
          tr.appendChild(stampCell(h.at));
          tr.appendChild(noI18n(el('td', 'muted small', h.node || '')));
          var t = el('td'); t.appendChild(el('span', 'tag ' + (h.ok ? 'ok' : 'warn'), h.ok ? 'taken' : 'not taken')); tr.appendChild(t);
          var w = noI18n(el('td', 'small', h.said || '')); tr.appendChild(w);
          return tr;
        }, 'rows'));
      }
      if ((r.steps || []).length) {
        body.appendChild(el('h3', '', 'The last try, step by step'));
        body.appendChild(stepsList(r.steps));
      }
      if (!r.has_body && (r.state === 'sent' || r.state === 'expired'))
        body.appendChild(el('p', 'note muted small', 'What the mail held is not kept once it went or was given up.'));
    }, [{words: 'Take it out', icon: 'trash', cls: 'danger', hidden: !CERTADMIN, go: function () { closeModal(); mailqDo('drop', [qid]); }},
        {spacer: true},
        {words: 'Send it again now', icon: 'refresh', cls: 'primary', hidden: !CERTADMIN || !r.has_body || !(r.state === 'waiting' || r.state === 'failed'),
         go: function () { closeModal(); mailqDo('retry', [qid]); }},
        {words: 'Close', close: true}].filter(function (b) { return !b.hidden; }), 'medium');
  }).catch(oops);
}
if ($('mq-q')) {
  var mqTimer = null;
  $('mq-q').addEventListener('input', function () { clearTimeout(mqTimer); mqTimer = setTimeout(function () { MQ.page = 0; loadMailq(); }, 300); });
  $('mq-state').onchange = function () { MQ.page = 0; loadMailq(); };
  $('mq-retry-all').onclick = function () { mailqDo('retry_all'); };
  $('mq-drop-sent').onclick = function () {
    confirmThen('Clear the sent mails', 'The mails that went leave the list (the events still say they went).', 'Clear them', function () { mailqDo('drop_sent'); });
  };
  $('mq-drop-failed').onclick = function () {
    confirmThen('Clear the failed mails', 'The mails refused for good, or given up, leave the list - they are not tried again.', 'Clear them', function () { mailqDo('drop_failed'); }, true);
  };
}

/* ==========================================================================
   The texts of the messages (1.0.103): every mail and SMS, in Czech and English, edited as they will look. A mail is shown as it
   arrives - its texts written into where they stand; what is filled in when
   it is sent stands in blue chips. Saved in the database: both nodes of a
   cluster send the same words.
   ========================================================================== */
var TX = {data: null, id: null, lang: 'cs', dirty: {}, eds: {}, active: null, range: null, frame: null};
var TX_KINDS = [['mail', 'E-mails', 'mail'], ['sms', 'SMS', 'phone']];
var TX_COLORS = ['#111827', '#1d4ed8', '#b91c1c', '#15803d', '#b45309', '#7c3aed', '#6b7280'];
function txT(s) {
  var got = typeof i18nText === 'function' ? i18nText(String(s)) : null;
  return got == null ? String(s) : got;      /* untranslated, or English: as it is */
}
function txMsg(id) { return ((TX.data || {}).messages || []).filter(function (m) { return m.id === (id || TX.id); })[0]; }
function txField(key) { var m = txMsg(); return m ? m.fields.filter(function (f) { return f.key === key; })[0] : null; }
function txDirtyCount() { return Object.keys(TX.dirty).length; }
function txValue(f) { return Object.prototype.hasOwnProperty.call(TX.dirty, f.key) ? TX.dirty[f.key] : f.value[TX.lang]; }

function loadTexts() {
  api('texts').then(function (d) {
    /* Only the mails and the SMS: what a VPN asked is gone with it. */
    d.messages = (d.messages || []).filter(function (m) { return m.kind === 'mail' || m.kind === 'sms'; });
    TX.data = d;
    if (!d.messages.length) { clear($('tx-root')); $('tx-root').appendChild(el('p', 'note', 'No message to change.')); return; }
    if (!txMsg(TX.id)) TX.id = d.messages[0].id;
    drawTexts();
  }).catch(oops);
}
/* Leaving what is not saved is asked first. */
function txLeave(go) {
  if (!txDirtyCount()) { go(); return; }
  confirmThen('Leave the changes unsaved?', 'What was written since the last save is thrown away.', 'Throw them away', function () {
    TX.dirty = {};
    go();
  }, true);
}

/* ---- a template and its picture in an editor ---------------------------- */
/* {code} as a chip, {{ and }} as braces; a plain text's lines as breaks. */
function txChipHtml(name, doc) {
  var label = (TX.data.placeholders || {})[name] || name;
  return '<span data-ph="' + name + '" contenteditable="false" title="{' + name + '}" style="display:inline-block;'
    + 'padding:0 6px;margin:0 1px;border-radius:5px;background:#dbeafe;color:#1e3a8a;border:1px solid #bfdbfe;'
    + 'font-size:.86em;line-height:1.5;font-weight:600;white-space:nowrap;vertical-align:baseline;cursor:default;'
    + 'user-select:all">' + htmlText(txT(label)) + '</span>';
}
function txToHtml(tpl, kind) {
  var s = String(tpl || '').replace(/\{\{/g, '').replace(/\}\}/g, '');
  if (kind !== 'rich') s = htmlText(s).replace(/\n/g, '<br>');
  s = s.replace(/\{([A-Za-z_]+)\}/g, function (_m, n) { return txChipHtml(n); });
  return s.replace(//g, '{').replace(//g, '}');
}
function txFromNode(node, kind) {
  var out = '';
  Array.prototype.forEach.call(node.childNodes, function (n) {
    if (n.nodeType === 3) {
      var t = n.nodeValue.replace(/​/g, '').replace(/\{/g, '{{').replace(/\}/g, '}}');
      out += kind === 'rich' ? htmlText(t).replace(/&#39;/g, "'").replace(/&quot;/g, '"') : t;
      return;
    }
    if (n.nodeType !== 1) return;
    var tag = n.tagName.toLowerCase();
    if (n.hasAttribute('data-ph')) { out += '{' + n.getAttribute('data-ph') + '}'; return; }
    if (tag === 'br') { out += kind === 'rich' ? '<br>' : (kind === 'line' ? ' ' : '\n'); return; }
    var inner = txFromNode(n, kind);
    if (tag === 'div' || tag === 'p') {
      out += (out && !/(<br>|\n)$/.test(out) ? (kind === 'rich' ? '<br>' : (kind === 'line' ? ' ' : '\n')) : '') + inner;
      return;
    }
    if (kind !== 'rich') { out += inner; return; }
    if (tag === 'b' || tag === 'strong') out += '<b>' + inner + '</b>';
    else if (tag === 'i' || tag === 'em') out += '<i>' + inner + '</i>';
    else if (tag === 'u') out += '<u>' + inner + '</u>';
    else if (tag === 'a' && n.getAttribute('href')) out += '<a href="' + htmlText(n.getAttribute('href')) + '">' + inner + '</a>';
    else if (tag === 'font' && n.getAttribute('color')) out += '<span style="color:' + n.getAttribute('color') + '">' + inner + '</span>';
    else if (tag === 'span' && n.getAttribute('style')) out += '<span style="' + htmlText(n.getAttribute('style')) + '">' + inner + '</span>';
    else out += inner;
  });
  return out;
}
function txSerialize(ed) {
  var v = txFromNode(ed, ed._f.kind);
  if (ed._f.kind === 'line') v = v.replace(/\s+/g, ' ').trim();
  return v;
}

/* One box of words: in the page, or in the picture of the mail. */
function txEditable(ed, f, doc) {
  ed._f = f;
  ed._doc = doc || document;
  ed.innerHTML = txToHtml(txValue(f), f.kind);
  ed.setAttribute('data-f', f.key);
  ed.setAttribute('spellcheck', 'true');
  ed.setAttribute('lang', TX.lang);
  var may = TX.data.may_change;
  ed.contentEditable = may ? 'true' : 'false';
  TX.eds[f.key] = ed;
  var mark = function () {
    var on = TX.active && TX.active.ed === ed;
    var changed = txValue(f) !== f.default[TX.lang];
    if (ed._inFrame) {
      ed.style.outline = on ? '2px solid #2563eb' : (ed._hover ? '1px dashed #60a5fa' : (changed ? '1px dashed #f59e0b' : '1px dashed transparent'));
      ed.style.outlineOffset = '3px';
      ed.style.borderRadius = '3px';
      ed.style.background = on ? 'rgba(37,99,235,.06)' : '';
    }
    ed.classList.toggle('tx-changed', changed);
    if (ed._mark2) ed._mark2(changed);
  };
  ed._markIt = mark;
  if (!may) { mark(); return ed; }
  ed.addEventListener('focus', function () { TX.active = {ed: ed, f: f, doc: ed._doc}; txToolsState(); Object.keys(TX.eds).forEach(function (k) { TX.eds[k]._markIt(); }); });
  ed.addEventListener('mouseenter', function () { ed._hover = true; mark(); });
  ed.addEventListener('mouseleave', function () { ed._hover = false; mark(); });
  ed.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (f.kind !== 'line') ed._doc.execCommand('insertLineBreak');
    }
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && /^[biu]$/i.test(e.key) && f.kind !== 'rich') e.preventDefault();
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); $('set-save').click(); }
  });
  ed.addEventListener('paste', function (e) {
    e.preventDefault();
    var t = (e.clipboardData || window.clipboardData).getData('text/plain') || '';
    if (f.kind === 'line') t = t.replace(/\s*\n\s*/g, ' ');
    ed._doc.execCommand('insertText', false, t);
  });
  ed.addEventListener('drop', function (e) { e.preventDefault(); });
  ed.addEventListener('input', function () {
    var v = txSerialize(ed);
    if (v === f.value[TX.lang]) delete TX.dirty[f.key]; else TX.dirty[f.key] = v;
    mark();
    txBarState();
    if (ed._onChange) ed._onChange(v);
    if (ed._inFrame) txFitFrame();
  });
  mark();
  return ed;
}
/* Put in where the cursor is, in the box last written in. */
function txInsertChip(name, ed) {
  ed = ed || (TX.active && TX.active.ed);
  if (!ed || !TX.data.may_change) return;
  if ((ed._f.placeholders || []).indexOf(name) < 0) { toast(txT('this text cannot have it'), 'bad'); return; }
  ed.focus();
  if (TX.range && TX.range.ed === ed) {
    var sel = ed._doc.getSelection();
    sel.removeAllRanges();
    sel.addRange(TX.range.r);
  }
  ed._doc.execCommand('insertHTML', false, txChipHtml(name) + '​');
  ed.dispatchEvent(new Event('input'));
}
function txKeepRange() {
  var a = TX.active;
  if (!a) return;
  var sel = a.doc.getSelection();
  if (sel && sel.rangeCount && a.ed.contains(sel.getRangeAt(0).commonAncestorContainer)) {
    TX.range = {ed: a.ed, r: sel.getRangeAt(0).cloneRange()};
  }
}
function txChipsFor(f, ed) {
  var row = el('div', 'tx-chips');
  if (!(f.placeholders || []).length || !TX.data.may_change) return row;
  row.appendChild(el('span', 'small muted', 'Put in:'));
  f.placeholders.forEach(function (p) {
    var b = el('button', 'tx-chip', (TX.data.placeholders || {})[p] || p);
    b.type = 'button';
    b.title = '{' + p + '}';
    b.addEventListener('mousedown', function (e) { e.preventDefault(); });
    b.onclick = function () { txInsertChip(p, ed); };
    row.appendChild(b);
  });
  return row;
}
function txResetField(f) {
  var ed = TX.eds[f.key];
  if (!ed) return;
  ed.innerHTML = txToHtml(f.default[TX.lang], f.kind);
  ed.dispatchEvent(new Event('input'));
}

/* ---- the whole pane ------------------------------------------------------ */
function drawTexts() {
  var host = $('tx-root');
  if (!host || !TX.data) return;
  saveBarHome();
  clear(host);
  TX.eds = {};
  TX.active = null;
  TX.range = null;
  /* One scroll, the page's (1.0.128): the list is short enough to stay in
     view beside the editor, which runs down the page - no scroll bars of
     their own. */
  var shell = el('div', 'tx-shell');
  txFitShell(shell);
  /* The messages, by whom they are for, then by how they go. */
  var list = el('div', 'tx-list card');
  var isAdmin = function (m) { return /^admin_/.test(m.id); };
  TX_KINDS.concat([['admin', 'The administration', 'shield']]).forEach(function (k) {
    var ms = TX.data.messages.filter(function (m) { return k[0] === 'admin' ? isAdmin(m) : (m.kind === k[0] && !isAdmin(m)); });
    if (!ms.length) return;
    var hd = el('div', 'tx-list-h');
    hd.innerHTML = iconMarkup(k[2], 14);
    hd.appendChild(el('span', '', k[1]));
    list.appendChild(hd);
    ms.forEach(function (m) {
      var b = el('button', 'tx-item' + (m.id === TX.id ? ' on' : ''));
      b.type = 'button';
      b.appendChild(el('span', 'tx-item-t', m.short || m.title));
      var st = el('span', 'tx-item-s');
      var ch = TX.data.langs.filter(function (l) { return (m.saved[l].changed || []).length; });
      ch.forEach(function (l) { st.appendChild(noI18n(el('span', 'tag warn', l.toUpperCase()))); });
      if (ch.length) b.title = 'Changed here - not as it comes';
      b.appendChild(st);
      b.onclick = function () { if (m.id !== TX.id) txLeave(function () { TX.id = m.id; drawTexts(); }); };
      list.appendChild(b);
    });
  });
  var ha = el('div', 'tx-ha small muted');
  ha.innerHTML = iconMarkup('db', 13);
  ha.appendChild(el('span', '', TX.data.ha ? 'Kept in the database: every node of the cluster sends the same words.' : 'Kept in the database: a second node, when there is one, sends the same words.'));
  list.appendChild(ha);
  shell.appendChild(list);
  var ed = el('div', 'tx-ed');
  shell.appendChild(ed);
  host.appendChild(shell);
  txDrawEditor(ed);
}

function txDrawEditor(host) {
  var m = txMsg();
  var head = el('div', 'tx-head card');
  var ttl = el('div', 'tx-title');
  ttl.appendChild(el('h3', '', m.title));
  ttl.appendChild(el('p', 'small muted', m.says));
  head.appendChild(ttl);
  var seg = el('div', 'seg tx-lang');
  TX.data.langs.forEach(function (l) {
    var b = el('button', l === TX.lang ? 'on' : '');
    b.type = 'button';
    b.appendChild(noI18n(el('span', '', {cs: 'Čeština', en: 'English'}[l] || l)));
    if ((m.saved[l].changed || []).length) b.appendChild(el('span', 'tx-dot'));
    b.onclick = function () { if (l !== TX.lang) txLeave(function () { TX.lang = l; drawTexts(); }); };
    seg.appendChild(b);
  });
  head.appendChild(seg);
  /* What is saved, and what can be done with it. */
  var bar = el('div', 'tx-bar');
  var said = el('span', 'tx-said small');
  said.id = 'tx-said';
  bar.appendChild(said);
  var spacer = el('span', 'tx-spacer');
  bar.appendChild(spacer);
  var may = TX.data.may_change;
  var prev = cmdButton('Preview', 'eye', '');
  prev.onclick = txPreview;
  bar.appendChild(prev);
  if (may) {
    var test = cmdButton('Send a sample…', 'mail', '');
    test.onclick = txTest;
    bar.appendChild(test);
  }
  if (may) {
    var back = cmdButton('Put back as it comes', 'undo', 'danger');
    back.id = 'tx-reset';
    back.onclick = txResetAll;
    bar.appendChild(back);
  }
  head.appendChild(bar);
  host.appendChild(head);
  if (!may) host.appendChild(el('p', 'note', 'Only a full administrator changes these words.'));
  if (m.kind === 'sms') txDrawSms(host, m);
  else txDrawMail(host, m);
  txBarState();
}

function txBarState() {
  var m = txMsg();
  if (!m) return;
  var n = txDirtyCount();
  var s = $('tx-said');
  if (s) {
    clear(s);
    var sv = m.saved[TX.lang];
    if (n) { s.className = 'tx-said small warn'; s.textContent = num(n) + ' text(s) changed, not saved yet'; }
    else if ((sv.changed || []).length && sv.at) {
      s.className = 'tx-said small';
      s.textContent = 'Saved ' + dayWords(new Date(sv.at * 1000)) + ' ' + clockWords(new Date(sv.at * 1000)) + (sv.by ? ' by ' + sv.by : '')
        + ' · ' + num(sv.changed.length) + ' text(s) not as they come';
    } else { s.className = 'tx-said small muted'; s.textContent = 'As it comes with acme'; }
  }
  /* Saved with the bar at the bottom (1.0.123), as everything else. */
  if (n && TX.data.may_change) {
    if (!PENDING.texts) pendingSet('texts', {pane: 'texts', save: txSave, reset: function () { TX.dirty = {}; drawTexts(); }});
  } else if (PENDING.texts) { delete PENDING.texts; markDirtyCount(); }
  if ($('tx-reset')) $('tx-reset').disabled = !(m.saved[TX.lang].changed || []).length && !n;
}

/* ---- a mail: drawn as it arrives, written into where it stands ----------- */
function txDrawMail(host, m) {
  var may = TX.data.may_change;
  var subj = m.fields.filter(function (f) { return f.where === 'subject'; })[0];
  /* The window of a mail program, with the toolbar over it. */
  var win = el('div', 'tx-mailwin card');
  var meta = el('div', 'tx-meta');
  var r1 = el('div', 'tx-meta-row');
  r1.appendChild(el('span', 'tx-meta-k', 'From'));
  r1.appendChild(noI18n(el('span', 'tx-meta-v mono small', TX.data.sender || '')));
  meta.appendChild(r1);
  var r2 = el('div', 'tx-meta-row');
  r2.appendChild(el('span', 'tx-meta-k', 'Subject'));
  var se = el('div', 'tx-line tx-subject');
  txEditable(se, subj);
  r2.appendChild(se);
  meta.appendChild(r2);
  var sc = txChipsFor(subj, se);
  sc.classList.add('tx-meta-chips');
  meta.appendChild(sc);
  win.appendChild(meta);
  if (may) win.appendChild(txToolbar());
  var stage = el('div', 'tx-stage');
  var frame = el('iframe', 'tx-frame');
  frame.setAttribute('title', m.title);
  TX.frame = frame;
  stage.appendChild(frame);
  var loading = el('p', 'note tx-loading', 'drawing the mail…');
  stage.appendChild(loading);
  win.appendChild(stage);
  host.appendChild(win);
  api('texts&render=' + encodeURIComponent(m.id) + '&lang=' + TX.lang + '&mark=1').then(function (d) {
    var page = String(d.html || '').replace(/<title>[\s\S]*?<\/title>/, '<title></title>')
      .replace(/⟦f:([a-z0-9_]+)⟧/g, function (_m, k) { return '<span data-slot="' + k + '"></span>'; });
    frame.onload = function () {
      loading.remove();
      var doc = frame.contentDocument;
      Array.prototype.forEach.call(doc.querySelectorAll('[data-slot]'), function (slot) {
        var f = txField(slot.getAttribute('data-slot'));
        if (!f) return;
        slot._inFrame = true;
        slot.style.minWidth = '24px';
        slot.style.display = 'inline-block';
        slot.style.cursor = may ? 'text' : 'default';
        slot.title = txT(f.label);
        txEditable(slot, f, doc);
      });
      doc.addEventListener('selectionchange', txKeepRange);
      doc.addEventListener('keyup', txKeepRange);
      doc.addEventListener('mouseup', txKeepRange);
      /* Links in the picture are not followed while it is written in. */
      doc.addEventListener('click', function (e) { var a = e.target.closest && e.target.closest('a'); if (a) e.preventDefault(); });
      txFitFrame();
      setTimeout(txFitFrame, 300);
    };
    frame.srcdoc = page;
  }).catch(function (e) { loading.textContent = e.message; });
  /* What is not in the picture: a greeting without a name, the text version. */
  var others = m.fields.filter(function (f) { return f.where === 'other'; });
  if (others.length) {
    var card = el('div', 'card tx-card');
    card.appendChild(el('h3', 'peek-h', 'When the name is not known'));
    card.appendChild(el('p', 'small muted', 'Used instead of the texts above when there is no name or account to put in.'));
    others.forEach(function (f) { card.appendChild(txFieldBox(f, 'tx-rich')); });
    host.appendChild(card);
  }
  var plain = m.fields.filter(function (f) { return f.where === 'plain'; });
  if (plain.length) {
    var pc = el('div', 'card tx-card');
    pc.appendChild(el('h3', 'peek-h', 'The plain text version'));
    pc.appendChild(el('p', 'small muted', 'What a mail program shows that does not show HTML.'));
    plain.forEach(function (f) { pc.appendChild(txFieldBox(f, 'tx-plain')); });
    host.appendChild(pc);
  }
}
/* One field in the page: its name, a box, what can be put in, its default. */
function txFieldBox(f, cls) {
  var wrap = el('div', 'tx-field');
  var top = el('div', 'tx-field-h');
  top.appendChild(el('b', '', f.label));
  var flag = el('span', 'tag warn small', 'changed');
  top.appendChild(flag);
  var sp = el('span', 'tx-spacer');
  top.appendChild(sp);
  var ed = el('div', 'tx-box ' + (cls || ''));
  if (TX.data.may_change) {
    var rb = cmdButton('As it comes', 'undo', 'small');
    rb.title = txT('Put this text back as it comes with acme');
    rb.onclick = function () { txResetField(f); };
    top.appendChild(rb);
  }
  wrap.appendChild(top);
  txEditable(ed, f);
  ed._mark2 = function (changed) { flag.hidden = !changed; if (rb) rb.disabled = !changed; };
  ed._markIt();
  wrap.appendChild(ed);
  wrap.appendChild(txChipsFor(f, ed));
  return wrap;
}
function txFitFrame() {
  var f = TX.frame;
  if (!f || !f.contentDocument || !f.contentDocument.documentElement) return;
  f.style.height = Math.max(200, f.contentDocument.documentElement.scrollHeight + 4) + 'px';
}
/* Bold, italic, a colour, a link - what mail programs show alike. */
function txToolbar() {
  var bar = el('div', 'tx-tools');
  bar.id = 'tx-tools';
  var cmd = function (icon, title, run, cls) {
    var b = el('button', 'tx-tool' + (cls ? ' ' + cls : ''));
    b.type = 'button';
    b.title = txT(title);
    b.setAttribute('aria-label', txT(title));
    if (/^</.test(icon)) b.innerHTML = icon; else b.appendChild(el('span', '', icon));
    b.addEventListener('mousedown', function (e) { e.preventDefault(); });
    b.onclick = function () {
      var a = TX.active;
      if (!a) { toast(txT('click into a text of the mail first'), 'bad'); return; }
      run(a);
      a.ed.dispatchEvent(new Event('input'));
    };
    bar.appendChild(b);
    return b;
  };
  var rich = function (a) { if (a.f.kind !== 'rich') { toast(txT('this text is one plain line'), 'bad'); return false; } return true; };
  cmd('<b>B</b>', 'Bold (Ctrl+B)', function (a) { if (rich(a)) a.doc.execCommand('bold'); }, 'rich-only');
  cmd('<i>I</i>', 'Italic (Ctrl+I)', function (a) { if (rich(a)) a.doc.execCommand('italic'); }, 'rich-only');
  cmd('<u>U</u>', 'Underline (Ctrl+U)', function (a) { if (rich(a)) a.doc.execCommand('underline'); }, 'rich-only');
  bar.appendChild(el('span', 'tx-sep'));
  var colors = el('span', 'tx-colors rich-only');
  TX_COLORS.forEach(function (c) {
    var b = el('button', 'tx-swatch');
    b.type = 'button';
    b.style.background = c;
    b.title = c;
    b.addEventListener('mousedown', function (e) { e.preventDefault(); });
    b.onclick = function () {
      var a = TX.active;
      if (!a || !rich(a)) return;
      a.doc.execCommand('styleWithCSS', false, true);
      a.doc.execCommand('foreColor', false, c);
      a.doc.execCommand('styleWithCSS', false, false);
      a.ed.dispatchEvent(new Event('input'));
    };
    colors.appendChild(b);
  });
  bar.appendChild(colors);
  bar.appendChild(el('span', 'tx-sep'));
  cmd(iconMarkup('globe', 15), 'A link', function (a) {
    if (!rich(a)) return;
    txKeepRange();
    var keep = TX.range;
    modalOver(function () {
      modal('A link', function (body) {
        var u = textBox('https://', 'https://…', 'mono');
        noI18n(u);
        body.appendChild(formField('Where it goes', u, 'https://…, http://… or mailto:…'));
        setTimeout(function () { u.focus(); u.select(); }, 50);
        u.addEventListener('keydown', function (e) { if (e.key === 'Enter') MODAL_GO(); });
        MODAL_GO = function () {
          var url = u.value.trim();
          if (!/^(https?:\/\/|mailto:)\S+$/i.test(url)) { toast(txT('a link starts with https://, http:// or mailto:'), 'bad'); return; }
          closeModal();
          a.ed.focus();
          if (keep) { var sel = a.doc.getSelection(); sel.removeAllRanges(); sel.addRange(keep.r); }
          if (a.doc.getSelection().isCollapsed) a.doc.execCommand('insertHTML', false, '<a href="' + htmlText(url) + '">' + htmlText(url) + '</a>');
          else a.doc.execCommand('createLink', false, url);
          a.ed.dispatchEvent(new Event('input'));
        };
      }, [{words: 'Close', close: true}, {words: 'Put it in', cls: 'primary', icon: 'check', go: function () { MODAL_GO(); }}], 'small');
    });
  }, 'rich-only');
  cmd(iconMarkup('close', 15), 'Take the link away', function (a) { if (rich(a)) a.doc.execCommand('unlink'); }, 'rich-only');
  cmd(iconMarkup('broom', 15), 'Take the formatting away', function (a) { if (rich(a)) { a.doc.execCommand('removeFormat'); a.doc.execCommand('unlink'); } }, 'rich-only');
  bar.appendChild(el('span', 'tx-sep'));
  cmd(iconMarkup('undo', 15), 'Undo (Ctrl+Z)', function (a) { a.doc.execCommand('undo'); });
  cmd(iconMarkup('refresh', 15), 'Redo (Ctrl+Y)', function (a) { a.doc.execCommand('redo'); });
  bar.appendChild(el('span', 'tx-sep'));
  /* What can be put into the text being written. */
  var ph = el('span', 'tx-tool-ph');
  ph.id = 'tx-tool-ph';
  bar.appendChild(ph);
  var sp = el('span', 'tx-spacer');
  bar.appendChild(sp);
  var which = el('span', 'tx-which small muted');
  which.id = 'tx-which';
  which.textContent = txT('Click into a text of the mail to write in it.');
  bar.appendChild(which);
  var fr = cmd(iconMarkup('undo', 15) + '<span>' + htmlText(txT('This text as it comes')) + '</span>', 'Put the text being written back as it comes with acme', function (a) { txResetField(a.f); }, 'tx-tool-wide');
  fr.id = 'tx-field-reset';
  return bar;
}
function txToolsState() {
  var a = TX.active;
  var bar = $('tx-tools');
  if (!bar || !a) return;
  var rich = a.f.kind === 'rich';
  Array.prototype.forEach.call(bar.querySelectorAll('.rich-only'), function (b) {
    if (b.tagName === 'BUTTON') b.disabled = !rich;
    else Array.prototype.forEach.call(b.querySelectorAll('button'), function (x) { x.disabled = !rich; });
  });
  var which = $('tx-which');
  if (which) which.textContent = txT(a.f.label) + (rich ? '' : ' · ' + txT('one plain line'));
  var ph = $('tx-tool-ph');
  clear(ph);
  (a.f.placeholders || []).forEach(function (p) {
    var b = el('button', 'tx-chip', (TX.data.placeholders || {})[p] || p);
    b.type = 'button';
    b.title = '{' + p + '}';
    b.addEventListener('mousedown', function (e) { e.preventDefault(); });
    b.onclick = function () { txInsertChip(p, a.ed); };
    ph.appendChild(b);
  });
  if (!(a.f.placeholders || []).length) ph.appendChild(el('span', 'small muted', 'nothing to put in here'));
  var fr = $('tx-field-reset');
  if (fr) fr.disabled = txValue(a.f) === a.f.default[TX.lang];
}

/* ---- an SMS: written, counted, shown on a phone -------------------------- */
function txFill(tpl, field) {
  var smp = (TX.data.samples || {})[TX.lang] || {};
  return String(tpl || '').replace(/\{\{/g, '').replace(/\}\}/g, '').replace(/\{([A-Za-z_]+)\}/g, function (_m, n) {
    if (n === 'dest' && field === 'ask_sms') return '+420 6•• ••• 456';
    return smp[n] !== undefined ? String(smp[n]) : '{' + n + '}';
  }).replace(//g, '{').replace(//g, '}');
}
var TX_GSM = '@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !"#¤%&\'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà';
var TX_GSM_EXT = '^{}\\[~]|€\f';
function txSmsCount(text) {
  var gsm = true, units = 0;
  for (var i = 0; i < text.length; i++) {
    var c = text.charAt(i);
    if (TX_GSM.indexOf(c) >= 0) units += 1;
    else if (TX_GSM_EXT.indexOf(c) >= 0) units += 2;
    else { gsm = false; break; }
  }
  if (!gsm) units = text.length;
  var one = gsm ? 160 : 70, part = gsm ? 153 : 67;
  return {gsm: gsm, chars: units, parts: units <= one ? 1 : Math.ceil(units / part), one: one};
}
function txPlainSms(t) {
  if (!TX.data.sms_plain || !t.normalize) return t;
  return t.normalize('NFKD').replace(/[̀-ͯ]/g, '');
}
function txDrawSms(host, m) {
  var f = m.fields[0];
  var grid = el('div', 'tx-sms');
  var left = el('div', 'card tx-card');
  left.appendChild(txFieldBox(f, 'tx-plain tx-smsbox'));
  var count = el('div', 'tx-count small');
  left.appendChild(count);
  if (TX.data.sms_plain) left.appendChild(el('p', 'small muted', 'Letters with accents go without them (Settings → Codes by e-mail and SMS → Without accents): the phone gets 160 characters a part instead of 70.'));
  grid.appendChild(left);
  var right = el('div', 'tx-phone');
  var screen = el('div', 'tx-phone-screen');
  var from = el('div', 'tx-phone-from small');
  from.textContent = TX.data.samples && TX.data.samples[TX.lang] ? TX.data.samples[TX.lang].site : '';
  noI18n(from);
  screen.appendChild(from);
  var bubble = noI18n(el('div', 'tx-bubble'));
  screen.appendChild(bubble);
  right.appendChild(screen);
  grid.appendChild(right);
  host.appendChild(grid);
  var draw = function () {
    var text = txPlainSms(txFill(txValue(f), f.key));
    bubble.textContent = text;
    var c = txSmsCount(text);
    clear(count);
    count.appendChild(el('span', c.parts > 1 ? 'tag warn' : 'tag ok', num(c.parts) + ' SMS'));
    count.appendChild(el('span', 'muted', num(c.chars) + ' / ' + num(c.parts > 1 ? c.parts * (c.gsm ? 153 : 67) : c.one) + ' · '
      + (c.gsm ? txT('GSM alphabet') : txT('Unicode - an accent or a sign outside GSM'))));
  };
  TX.eds[f.key]._onChange = draw;
  draw();
}

/* ---- saved, put back, looked at, sent ------------------------------------ */
function txSave() {
  var m = txMsg();
  if (!txDirtyCount() || !TX.data.may_change) return Promise.resolve(true);
  return api('texts', {action: 'save', id: m.id, lang: TX.lang, fields: TX.dirty, was_at: m.saved[TX.lang].at || null}).then(function (d) {
    TX.dirty = {};
    txPutState(d.state);
    toast(d.message, 'good');
    drawTexts();
    return true;
  }).catch(function (e) {
    if (e.status === 409) {
      modalOver(function () {
        confirmThen('Changed meanwhile', htmlText(e.message) + '<br><br>' + htmlText(txT('Load them again - what was written here is then lost - or copy it out first.')),
          'Load them again', function () { TX.dirty = {}; delete PENDING.texts; markDirtyCount(); loadTexts(); }, false);
      });
      return false;
    }
    throw e;
  });
}
function txPutState(st) {
  if (!st) return;
  TX.data.messages = TX.data.messages.map(function (x) { return x.id === st.id ? st : x; });
}
function txResetAll() {
  var m = txMsg();
  var lang = {cs: 'Czech', en: 'English'}[TX.lang] || TX.lang;
  confirmThen('Put “' + m.title + '” back as it comes', 'Every text of this message in <b>' + htmlText(txT(lang))
    + '</b> goes back to how it comes with acme - exactly as it was before it was changed. The other language stays as it is. Both nodes send it at once.',
    'Put back', function () {
      api('texts', {action: 'reset', id: m.id, lang: TX.lang}).then(function (d) {
        TX.dirty = {};
        txPutState(d.state);
        toast(d.message, 'good');
        drawTexts();
      }).catch(oops);
    }, true);
}
function txPreview() {
  var m = txMsg();
  api('texts', {action: 'preview', id: m.id, lang: TX.lang, fields: TX.dirty}).then(function (d) {
    modal('Preview: ' + m.title, function (body) {
      var bad = Object.keys(d.bad || {});
      if (bad.length) {
        var w = el('div', 'note warn');
        bad.forEach(function (k) { w.appendChild(el('div', '', d.bad[k])); });
        body.appendChild(w);
      }
      body.appendChild(el('p', 'small muted', 'With sample values, as it would go out now - what is not saved yet included.'));
      if (d.html) {
        var sub = el('div', 'tx-meta-row');
        sub.appendChild(el('span', 'tx-meta-k', 'Subject'));
        sub.appendChild(noI18n(el('b', '', d.subject || '')));
        body.appendChild(sub);
        var fr = el('iframe', 'tx-frame tx-frame-preview');
        fr.setAttribute('title', 'Preview');
        fr.onload = function () {
          try { fr.style.height = Math.max(200, fr.contentDocument.documentElement.scrollHeight + 4) + 'px'; } catch (e) { }
          try { fr.contentDocument.addEventListener('click', function (e) { if (e.target.closest && e.target.closest('a')) e.preventDefault(); }); } catch (e) { }
        };
        fr.srcdoc = d.html;
        body.appendChild(fr);
        if (d.text) {
          body.appendChild(el('h3', 'peek-h', 'The plain text version'));
          var pre = noI18n(el('pre', 'wrap mono small tx-pre'));
          pre.textContent = d.text;
          body.appendChild(pre);
        }
      } else if (d.sms !== undefined) {
        var bub = noI18n(el('div', 'tx-bubble'));
        bub.textContent = d.sms;
        body.appendChild(bub);
      }
    }, [{words: 'Close', close: true}], 'large');
  }).catch(oops);
}
function txTest() {
  var m = txMsg();
  var sms = m.kind === 'sms';
  modalOver(function () {
    modal('Send a sample', function (body) {
      body.appendChild(el('p', 'note', sms ? 'The SMS as it is written now - saved or not - with sample values, to one number.' : 'The mail as it is written now - saved or not - with sample values (a code, a name, a QR code that opens nothing), to one address.'));
      var to = textBox('', sms ? '+420 603 123 456' : 'jan.novak@example.cz', 'mono');
      noI18n(to);
      body.appendChild(formField(sms ? 'The number' : 'The address', to));
      setTimeout(function () { to.focus(); }, 50);
      to.addEventListener('keydown', function (e) { if (e.key === 'Enter') MODAL_GO(); });
      var out = el('div', 'said');
      body.appendChild(out);
      var going = false;
      MODAL_GO = function (button) {
        /* One at a time (1.0.206): Enter in the box sent another SMS at every press. */
        if (going) return;
        going = true;
        busy(button, true);
        api('texts', {action: 'test', id: m.id, lang: TX.lang, fields: TX.dirty, to: to.value.trim()}).then(function (d) {
          out.className = 'said good';
          out.textContent = d.message;
        }).catch(function (e) { out.className = 'said bad'; out.textContent = e.message; }).then(function () { busy(button, false); going = false; });
      };
    }, [{words: 'Close', close: true}, {words: 'Send', cls: 'primary', icon: sms ? 'phone' : 'mail', go: function (b) { MODAL_GO(b); }}], 'small');
  });
}

/* An account made with a password somebody else chose must set its own before
   anything (1.0.103): the form opens by itself instead of a page of dashes
   and "change your password first" errors. */
function mustChange() {
  if (!ME || !ME.must_change || ME.source === 'directory') return;
  modal('Choose your own password first', function (body) {
    body.appendChild(el('p', '', 'This account was given a password by somebody else. Before anything '
      + 'else, choose one only you know - every page waits for it.'));
    var old = maskBox('', '', '');
    var nw = maskBox('', '', '');
    var nw2 = maskBox('', '', '');
    var g = el('div', 'formgrid');
    g.appendChild(formField('The one you were given', old));
    g.appendChild(formField('The new one (8 characters at least)', nw));
    g.appendChild(formField('The new one again', nw2));
    body.appendChild(g);
    var go = cmdButton('Change the password', 'lock', 'primary');
    go.id = 'mc-go';
    var row = el('div', 'me-acts');
    row.style.marginTop = '14px';
    go.onclick = function () {
      if (nw.value !== nw2.value) { toast('the two new ones are not the same', 'bad'); return; }
      busy(go, true);
      api('password', {old: old.value, 'new': nw.value}).then(function (d) {
        toast(d.message, 'good');
        ME.must_change = false;
        setTimeout(function () { location.reload(); }, 600);
      }).catch(function (e) { busy(go, false); toast(String(e && e.message || e), 'bad'); });
    };
    row.appendChild(go);
    var out = cmdButton('Sign out', 'out', '');
    out.onclick = function () { api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); }); };
    row.appendChild(out);
    body.appendChild(row);
  }, null, 'medium');
}
setTimeout(mustChange, 300);

/* Is version a newer than b - 1.0.103 above 1.0.67.1 (1.0.103: a plain "not
   the same" offered an older package as one ready to be put in). */
function verAbove(a, b) {
  var x = String(a || '').split(/[.-]/), y = String(b || '').split(/[.-]/);
  for (var i = 0; i < Math.max(x.length, y.length); i++) {
    var p = parseInt(x[i] || '0', 10) || 0, q = parseInt(y[i] || '0', 10) || 0;
    if (p !== q) return p > q;
  }
  return false;
}

/* The link between the two databases (1.0.104): one bar that says how it is
   and mends it - both nodes, every step, nothing stopped. While it runs, each
   node's step; when done, how long its certificate lasts (renewed by itself). */
var HA_LINK_POLL = null;
var HA_LINK_STEPS = ['names', 'server', 'link', 'hba', 'done'];
var HA_LINK_OFF_STEPS = ['off_hba', 'off_link', 'off_server', 'off_done'];
function haLinkBar(d) {
  var lt = d.link_tls || {};
  var mode = lt.mode || d.db_tls || '';
  var checked = ['verify-full', 'verify-ca'].indexOf(mode) >= 0;
  var want = lt.want || null;
  var off = !!lt.off;
  var nodes = (lt.nodes || []).filter(function (n) { return !want || n['for'] === want.at || n.renew || n.step === 'done' || n.step === 'off_done'; });
  var failed = nodes.filter(function (n) { return n.step === 'failed'; });
  var running = !!lt.running;
  var soon = nodes.filter(function (n) { return n.cert_end && n.cert_end * 1000 - Date.now() < 45 * 86400000; });
  var box = el('div', 'hal ' + (running ? 'run' : (failed.length || !checked ? 'warn' : 'good')));
  var head = el('div', 'hal-head');
  var ic = el('span', 'hal-ic');
  ic.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    + ICONS[running ? 'refresh' : (checked && !failed.length ? 'lock' : 'shield')] + '</svg>';
  head.appendChild(ic);
  var words = el('div', 'hal-words');
  var title, sub;
  if (running && off) {
    title = 'Switching TLS between the databases off…';
    sub = 'The steps the other way round, so replication never stops: both databases let the other node in without TLS, both links go back, then the certificates leave both PostgreSQLs.';
  } else if (running) {
    title = 'Encrypting and checking the link between the databases…';
    sub = 'Both nodes, one step after the other; replication goes on all the time. This page follows it.';
  } else if (failed.length) {
    title = 'Encrypting the link stopped on ' + failed.map(function (n) { return n.name; }).join(', ');
    sub = 'Nothing is broken: what was not finished is used by nothing yet. Put what it says right and press Repair again.';
  } else if (checked) {
    title = 'The link between the two databases is encrypted and checked (' + mode + ')';
    sub = lt.own ? 'With the cluster’s own authority. Each node renews its certificate by itself 45 days before it ends; the authority is replaced two years before it ends.'
      : 'By Database → TLS, with the authority set there.';
  } else {
    title = mode ? 'The link between the two databases is encrypted, but whose certificate answers is not checked (' + mode + ')'
      : 'The link between the two databases is not encrypted';
    sub = 'Whoever is on the network between the nodes reads every row going over and can put rows of their own in. Repair gives both databases a certificate from the cluster’s own authority and moves replication over to verify-full - on both nodes, without stopping anything.';
  }
  words.appendChild(el('b', '', title));
  words.appendChild(el('div', 'small', sub));
  head.appendChild(words);
  /* Running for more than three minutes: it may start again from here
     (1.0.106) - a node that waits on the other is started over with it. */
  var long = running && want && Date.now() / 1000 - want.at > 180;
  if (ME.role === 'fulladmin' && (!running || long)) {
    var b = cmdButton(long ? (off ? 'Switch it off again' : 'Start the steps again') : (failed.length ? 'Repair again' : (checked ? (soon.length ? 'Renew now' : 'Renew the certificates') : 'Repair')),
                      checked && !failed.length ? 'refresh' : 'shield', checked && !failed.length && !soon.length ? 'small' : 'primary');
    b.id = 'ha-link-fix';
    explain(b, 'On both nodes: a certificate for each database from the cluster’s own authority, '
      + 'PostgreSQL given it (by the root helper, reloaded - not restarted), each node’s link to the other '
      + 'moved over to verify-full once that works, and then each database lets the other node in over TLS only. '
      + 'Also mends a link whose certificate has run out.');
    b.onclick = function () {
      confirmThen('Encrypt and check the link between the databases?',
        'Both nodes go through the steps by themselves; replication goes on meanwhile. A step that does not work stops there and leaves what is in use as it was.',
        'Start', function () {
          busy(b, true);
          api('ha', {action: 'tls_link'}).then(function (x) {
            toast(x.message, 'good');
            loadHa();
          }).catch(function (e) { busy(b, false); oops(e); });
        }, false);
    };
    head.appendChild(b);
    if (checked && lt.own && !running) {
      var offb = cmdButton('Switch TLS off…', 'cancel', 'small danger');
      offb.id = 'ha-link-off';
      offb.style.marginLeft = '6px';
      explain(offb, 'Back to how it was before: both databases let the other node in without TLS, '
        + 'both links go back to Database → TLS, and the cluster’s certificates leave both PostgreSQLs '
        + '(ssl as postgresql.conf says). Replication goes on meanwhile. Repair turns it on again.');
      offb.onclick = function () {
        confirmThen('Switch TLS between the databases off?',
          '<b>Whoever is on the network between the nodes will be able to read every row going over and put rows of their own in.</b><br>Both nodes go through the steps by themselves; replication goes on meanwhile. Repair turns it on again at any time.',
          'Switch it off', function () {
            busy(offb, true);
            api('ha', {action: 'tls_off'}).then(function (x) { toast(x.message, 'good'); loadHa(); })
              .catch(function (e) { busy(offb, false); oops(e); });
          });
      };
      head.appendChild(offb);
    }
  }
  box.appendChild(head);
  if (nodes.length && (running || failed.length || checked)) {
    var list = el('div', 'hal-nodes');
    nodes.forEach(function (n) {
      var row = el('div', 'hal-node');
      var nm = noI18n(el('b', 'hal-name', n.name));
      row.appendChild(nm);
      var steps = el('div', 'hal-steps');
      var order = (n.off || off) ? HA_LINK_OFF_STEPS : HA_LINK_STEPS;
      var labels = (n.off || off) ? [['off_hba', 'without TLS too'], ['off_link', 'link back'], ['off_server', 'certificate away'], ['off_done', 'done']]
        : [['server', 'certificate'], ['link', 'link verify-full'], ['hba', 'TLS only'], ['done', 'done']];
      var failedAt = n.step === 'failed' ? order.indexOf(n.failed_step || order[(n.off || off) ? 0 : 1]) : -1;
      var at = n.step === 'failed' ? failedAt : order.indexOf(n.step);
      labels.forEach(function (x) {
        var i = order.indexOf(x[0]);
        var cls = (n.step === 'failed' && i === Math.max((n.off || off) ? 0 : 1, at)) ? 'bad'
          : (at > i || n.step === 'done' || n.step === 'off_done' ? 'ok' : (at === i && n.step !== 'failed' ? 'now' : ''));
        steps.appendChild(el('span', 'hal-step ' + cls, x[1]));
      });
      row.appendChild(steps);
      var said = n.step === 'failed' ? (n.error || '') : (n.said || '');
      if (n.cert_end && n.step === 'done') said = 'its certificate ends ' + new Date(n.cert_end * 1000).toLocaleDateString(numLang()) + ' · in ' + num(Math.max(0, Math.round((n.cert_end * 1000 - Date.now()) / 86400000))) + ' days';
      row.appendChild(el('div', 'hal-said small ' + (n.step === 'failed' ? 'bad' : 'muted'), said));
      list.appendChild(row);
    });
    box.appendChild(list);
  }
  clearTimeout(HA_LINK_POLL);
  if (running) HA_LINK_POLL = setTimeout(function () { if (TAB === 'settings' && PANE === 'ha') loadHa(true); }, 3000);
  return box;
}

/* The Database page says how the link to the other node is protected
   (1.0.107): Database → TLS is about this daemon's own connection, and was
   empty after the link was encrypted - it looked as if nothing had happened. */
function dbLinkNote() {
  var old = document.getElementById('db-link-note');
  if (old) old.remove();
  api('ha').then(function (d) {
    var lt = d.link_tls;
    if (!lt || d.mode !== 'replicated') return;
    var item = document.querySelector('.set-item[data-key="db_tls"]');
    if (!item) return;
    /* Asked twice at once (the pane shown, the settings drawn): one note. */
    Array.prototype.forEach.call(document.querySelectorAll('#db-link-note'), function (n) { n.remove(); });
    var mode = lt.mode || '';
    var good = ['verify-full', 'verify-ca'].indexOf(mode) >= 0;
    var box = el('div', 'note small ' + (good ? 'good' : 'warn'));
    box.id = 'db-link-note';
    box.style.marginTop = '8px';
    box.appendChild(el('b', '', good ? 'The link to the other node: encrypted and checked (' + mode + ')'
      : (mode ? 'The link to the other node: ' + mode : 'The link to the other node: not encrypted')));
    box.appendChild(el('div', '', lt.own
      ? 'Its own setting, made by Settings → High availability (the cluster’s own authority). This field is only this daemon’s connection to its own PostgreSQL on 127.0.0.1 - leave it empty.'
      : 'As this field says. Settings → High availability → Repair encrypts and checks it without touching this field.'));
    var go = el('a', 'fgo', 'Settings → High availability');
    go.href = '#settings/ha';
    box.appendChild(go);
    var says = item.querySelector('.says');
    if (says) says.parentNode.insertBefore(box, says); else item.appendChild(box);
  }).catch(function () { /* nothing to add */ });
}

/* The heading and the list of messages stay where they are; only the editor
   scrolls (1.0.109, one scroll bar since 1.0.129): the shell is as tall as
   what is left of the pane above the save bar, so the page itself never
   scrolls. Narrow screens keep one column and the page's scroll. */
/* The save bar where the page scrolls (1.0.131): at the end of the pane - or,
   on Message texts, where only the editor scrolls, at the end of the editor.
   Either way it is below the last thing until something is changed, and
   then sticks to the bottom. Moved back home before the editor is drawn
   again, or it would go with it. */
var SAVE_BAR_HOME = null;
function saveBarHome() {
  var bar = $('save-bar');
  if (!bar) return;
  if (!SAVE_BAR_HOME) SAVE_BAR_HOME = {parent: bar.parentNode, next: bar.nextSibling};
  if (bar.parentNode !== SAVE_BAR_HOME.parent) {
    SAVE_BAR_HOME.parent.insertBefore(bar, SAVE_BAR_HOME.next && SAVE_BAR_HOME.next.parentNode === SAVE_BAR_HOME.parent ? SAVE_BAR_HOME.next : null);
    bar.classList.remove('in-editor');
  }
}
function saveBarPlace() {
  var bar = $('save-bar');
  if (!bar) return;
  var ed = PANE === 'texts' && TAB === 'settings' ? document.querySelector('.tx-shell.split > .tx-ed') : null;
  if (!ed) { saveBarHome(); return; }
  if (!SAVE_BAR_HOME) SAVE_BAR_HOME = {parent: bar.parentNode, next: bar.nextSibling};
  if (bar.parentNode !== ed || ed.lastChild !== bar) { ed.appendChild(bar); bar.classList.add('in-editor'); }
}
var TX_FIT = null;
function txFitShell(shell) {
  var fit = function () {
    if (!shell.isConnected) { window.removeEventListener('resize', fit); if (TX_FIT === fit) TX_FIT = null; return; }
    if (window.innerWidth < 900) { shell.style.height = ''; shell.classList.remove('split'); return; }
    var main = shell.closest('.ctl-main');
    if (!main) return;
    main.scrollTop = 0;
    var h = main.getBoundingClientRect().bottom - shell.getBoundingClientRect().top - 14;
    shell.style.height = Math.max(380, Math.floor(h)) + 'px';
    shell.classList.add('split');
    saveBarPlace();
  };
  TX_FIT = fit;
  setTimeout(fit, 0);
  window.addEventListener('resize', fit);
}

/* ==== Backups to another machine (1.0.109) ===================================
   Destinations (a folder, FTP, FTPS, SFTP, SCP, SMB) with their sign-in -
   passwords, ssh keys made here or brought, the server's host key or its
   certificate checked, a client certificate for FTPS - a backup sent now or on
   a schedule, the history, the backups at each destination, and putting one
   back. Only a full administrator sees any of it. */
var RB = null;
var RB_POLL = null;
var RB_KIND_ICON = {folder: 'db', ftp: 'upload', ftps: 'lock', sftp: 'terminal', scp: 'terminal', smb: 'net'};
var RB_KIND_SAYS = {
  folder: 'A folder on this machine - an NFS or other share mounted here.',
  ftp: 'Plain FTP: the password and the file go over unencrypted - only inside a network you trust (the file itself is locked).',
  ftps: 'FTP over TLS - explicit (port 21) or implicit (990); the server’s certificate checked, a client certificate if it wants one.',
  sftp: 'SSH file transfer: a key made here or your own, or a password; the server’s host key checked.',
  scp: 'scp over SSH, and ssh to list and take away old ones - needs a shell on the server.',
  smb: 'A Windows or Samba share: the account, its domain, SMB3 encryption.'
};
function rbWhen(ts) {
  if (!ts) return '';
  var n = Number(ts);
  return isNaN(n) ? String(ts) : 'until ' + new Date(n * 1000).toLocaleDateString(numLang());
}
function rbBytes(n) {
  n = Number(n || 0);
  if (n < 1024) return num(n) + ' B';
  var u = ['kB', 'MB', 'GB', 'TB'], i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n < 10 ? 1 : 0) + ' ' + u[i];
}
function rbWhere(t) {
  if (t.kind === 'folder') return t.path || '';
  if (t.kind === 'smb') return '\\\\' + t.host + (t.port && t.port !== 445 ? ':' + t.port : '') + '\\' + (t.share || '') + (t.path ? '\\' + String(t.path).replace(/\//g, '\\') : '');
  return (t.user ? t.user + '@' : '') + t.host + (t.port ? ':' + t.port : '') + '/' + String(t.path || '').replace(/^\//, '');
}
function loadRbackup() {
  var top = $('rb-top');
  if (!top) return;
  if (!ME || ME.role !== 'fulladmin') {
    clear(top);
    top.appendChild(el('p', 'note', 'Only a full administrator sees and changes the backups: they hold every private key.'));
    return;
  }
  api('rbackup').then(function (d) {
    RB = d;
    drawRbTop();
    drawRbTargets();
    drawRbRuns();
    rbPassTools();
    if (d.job && d.job.running) rbWatch();
  }).catch(oops);
}
function rbPassTools() {
  /* "Make one" beside the password of the backups: a long random one, shown
     once to be put into the password vault. */
  var item = document.querySelector('.set-item[data-key="rbackup_password"]');
  if (!item || item.querySelector('.rb-gen')) return;
  var b = cmdButton('Make a strong one', 'key', 'small rb-gen');
  b.style.alignSelf = 'flex-start';
  b.onclick = function () {
    var a = new Uint8Array(24);
    crypto.getRandomValues(a);
    var abc = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
    var pw = '';
    for (var i = 0; i < a.length; i++) { pw += abc.charAt(a[i] % abc.length); if (i % 6 === 5 && i < a.length - 1) pw += '-'; }
    var box = item.querySelector('input');
    if (box) {
      if (box._set) box._set(pw); else box.value = pw;
      box.dispatchEvent(new Event('input', {bubbles: true}));
      box.dispatchEvent(new Event('change', {bubbles: true}));
    }
    modal('The password of the backups', function (body) {
      body.appendChild(el('p', 'note', 'Put it into your password vault now - this is the only time it is shown whole. Without it no backup can be opened, by anybody. Then press Save the changes.'));
      var p = noI18n(el('div', 'rb-pass mono', pw));
      body.appendChild(p);
      var c = cmdButton('Copy', 'copy', 'small');
      c.onclick = function () { copyText(pw, c, 'Copied'); };
      body.appendChild(c);
    }, [{words: 'Close', close: true}], true);
  };
  var says = item.querySelector('.says');
  if (says) says.parentNode.insertBefore(b, says); else item.appendChild(b);
}
function drawRbTop() {
  var host = $('rb-top');
  clear(host);
  var d = RB;
  var card = el('div', 'card full rb-hero');
  var last = (d.runs || [])[0];
  var mine = (d.runs || []).filter(function (r) { return r.node === d.node; })[0];
  var on = (d.targets || []).filter(function (t) { return t.enabled; });
  var state = !on.length ? 'warn' : (!mine ? 'warn' : (mine.ok ? 'good' : 'bad'));
  card.classList.add(state);
  var head = el('div', 'rb-hero-head');
  var ic = el('span', 'rb-hero-ic');
  ic.innerHTML = iconMarkup(state === 'good' ? 'check' : (state === 'bad' ? 'flag' : 'info'), 22);
  head.appendChild(ic);
  var words = el('div', 'rb-hero-words');
  var title = !on.length ? 'No destination yet - backups go nowhere'
    : (!mine ? 'No backup of this node has been sent yet'
      : (mine.ok ? 'The last backup of ' + d.node + ' went to every destination'
        : 'The last backup of ' + d.node + ' did not reach every destination'));
  words.appendChild(el('b', '', title));
  var facts = el('div', 'rb-hero-facts');
  var fact = function (k, v, cls) {
    var f = el('span', 'rb-fact ' + (cls || ''));
    f.appendChild(el('span', 'k', k));
    f.appendChild(el('span', 'v', v));
    facts.appendChild(f);
  };
  if (mine) fact('Last', ago(mine.at) + ' · ' + rbBytes(mine.bytes));
  fact('Next', d.next ? new Date(d.next).toLocaleString(numLang(), {weekday: 'short', day: 'numeric', month: 'numeric', hour: '2-digit', minute: '2-digit'}) : 'by hand only', d.next ? '' : 'warn');
  fact('Locked', d.locked ? 'with the password (AES-256)' : 'NOT locked - set the password', d.locked ? 'good' : 'bad');
  fact('Destinations', num(on.length) + ' of ' + num((d.targets || []).length) + ' switched on');
  /* The last try (1.0.169): whether the newest backup can be put back. */
  var tried = (d.verified || []).filter(function (v) { return v.node === d.node; })[0];
  fact('Tried', tried ? (tried.ok ? 'can be put back' : 'NOT GOOD') + ' · ' + ago(tried.at) : 'never', tried ? (tried.ok ? 'good' : 'bad') : 'warn');
  words.appendChild(facts);
  if (mine && !mine.ok) {
    var bad = (mine.targets || []).filter(function (x) { return !x.ok; });
    var why = el('div', 'rb-hero-why small bad');
    why.textContent = mine.error || bad.map(function (x) { return x.name + ': ' + (x.error || 'failed'); }).join(' · ');
    words.appendChild(why);
  }
  head.appendChild(words);
  var acts = el('div', 'rb-hero-acts');
  var now = cmdButton('Back up now', 'upload', 'primary');
  now.id = 'rb-now';
  now.disabled = !on.length || (d.job && d.job.running);
  explain(now, 'A backup made now and sent to every destination switched on - the same as the scheduled one.');
  now.onclick = function () {
    busy(now, true);
    api('rbackup', {action: 'run'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
      .catch(function (e) { busy(now, false); oops(e); });
  };
  acts.appendChild(now);
  var tryb = cmdButton('Try the newest', 'check', '');
  tryb.disabled = !on.length || (d.job && d.job.running);
  explain(tryb, 'The newest backup of this node fetched back from the first destination, opened with the password, every file checked, the database read through and the sealed keys tried against the key in it - nothing is put back. And the newest nightly copy here read through.');
  tryb.onclick = function () {
    busy(tryb, true);
    api('rbackup', {action: 'verify'}).then(function (x) { toast(x.message, 'good'); RB.job = x.job; rbWatch(); })
      .catch(function (e) { busy(tryb, false); oops(e); });
  };
  acts.appendChild(tryb);
  var dl = cmdButton('Download one here', 'download', '');
  explain(dl, 'A backup made now, saved on the computer you are sitting at - locked with the password as the others.');
  dl.onclick = function () {
    if (!d.locked) {
      confirmThen('Download a backup that is not locked?', 'No password of the backups is set: the file will hold <b>every private key</b> readable. Set the password first unless you know where the file goes.', 'Download it', function () { window.location.href = '?api=rbackup-download'; }, false);
      return;
    }
    toast('the backup is being made - the download starts when it is ready', 'good');
    window.location.href = '?api=rbackup-download';
  };
  acts.appendChild(dl);
  var back = cmdButton('Put one back…', 'undo', '');
  back.onclick = rbPutBackFile;
  acts.appendChild(back);
  var guide = cmdButton('How to put it back', 'book', '');
  explain(guide, 'RESTORE.md - the exact steps to bring everything back from a backup, filled in with this installation, as every backup carries it. To read now, and to keep apart from the backups.');
  guide.onclick = rbGuide;
  acts.appendChild(guide);
  head.appendChild(acts);
  card.appendChild(head);
  var going = el('div', 'going wide');
  going.id = 'rb-going';
  going.hidden = !(d.job && d.job.running);
  going.innerHTML = '<div class="bar"><span id="rb-going-fill"></span></div><div class="says" id="rb-going-says"></div>';
  card.appendChild(going);
  if (!d.tools.openssl) card.appendChild(el('p', 'note bad', 'openssl is not on this machine: backups cannot be locked (dnf install openssl).'));
  host.appendChild(card);
  /* In a cluster each node backs itself up (1.0.169): every node's last
     backup and last try, side by side. */
  var names = Object.keys(d.last_by_node || {});
  (d.verified || []).forEach(function (v) { if (v.node && names.indexOf(v.node) < 0) names.push(v.node); });
  if (names.indexOf(d.node) < 0) names.push(d.node);
  if (names.length > 1) {
    var grid = nodeGrid();
    grid.classList.add('rb-nodes');
    names.sort().forEach(function (n) {
      var last = (d.last_by_node || {})[n];
      var tr = (d.verified || []).filter(function (v) { return v.node === n; })[0];
      var bad = (last && !last.ok) || (tr && !tr.ok);
      var c = nodeCard({node: n, me: n === d.node}, !last ? 'dim' : (bad ? 'bad' : 'ok'),
        !last ? 'no backup yet' : (last.ok ? 'went everywhere' : 'did not go everywhere'), !last ? 'dim' : (last.ok ? 'ok' : 'crit'));
      nodeBig(c, last ? ago(last.at) : '–', last ? 'the last backup' : '');
      c.appendChild(netFacts([['Size', last && last.bytes ? rbBytes(last.bytes) : ''], ['Certificates', last && last.certs != null ? num(last.certs) : ''],
        ['Tried', tr ? (tr.ok ? 'can be put back' : 'NOT GOOD') + ' · ' + ago(tr.at) : 'never']]));
      grid.appendChild(c);
    });
    host.appendChild(grid);
  }
  RB.verified = d.verified || [];
  drawRbTried();
}
/* The backups tried (1.0.169): each try, every check of it; the list can be
   emptied, or a try taken off - the backups themselves stay. */
function drawRbTried() {
  var card = $('rb-tried-card'), host = $('rb-tried'), tools = $('rb-tried-tools');
  if (!card) return;
  var rows = RB.verified || [];
  card.hidden = !rows.length;
  clear(host);
  clear(tools);
  if (!rows.length) return;
  var forget = function (q) {
    api('rbackup', Object.assign({action: 'verified_forget'}, q)).then(function (d) {
      toast(d.message, 'good'); RB.verified = d.verified || []; drawRbTried();
    }).catch(oops);
  };
  var wipe = cmdButton('Clear the list', 'trash', 'small');
  wipe.onclick = function () {
    confirmThen('Clear the list of backups tried?', 'Every try goes from this list (for both nodes). <b>The backups themselves stay where they are.</b> Events keeps a line saying who cleared it.', 'Clear the list', function () { forget({all: 1}); }, true);
  };
  tools.appendChild(wipe);
  var list = el('div', 'rb-tried');
  rows.slice(0, 8).forEach(function (v, i) {
    var it = el('details', 'rb-try ' + (v.ok ? 'good' : 'bad'));
    if (i === 0 && !v.ok) it.open = true;
    var sm = el('summary');
    sm.appendChild(el('span', 'dot ' + (v.ok ? 'ok' : 'bad')));
    sm.appendChild(el('b', '', v.ok ? 'Can be put back' : 'Not good'));
    sm.appendChild(noI18n(el('span', 'mono small', v.file || '?')));
    sm.appendChild(el('span', 'muted small', '·'));
    sm.appendChild(el('span', 'muted small', ago(v.at)));
    sm.appendChild(el('span', 'muted small', '·'));
    sm.appendChild(noI18n(el('span', 'muted small', (v.node || '') + ' → ' + (v.target_name || ''))));
    var x = el('button', 'xbtn rb-try-x');
    x.type = 'button';
    x.setAttribute('data-icon', 'close');
    x.title = 'Take it off the list';
    x.onclick = function (e) { e.preventDefault(); e.stopPropagation(); forget({at: v.at}); };
    sm.appendChild(x);
    it.appendChild(sm);
    var ul = el('div', 'rb-checks');
    (v.checks || []).forEach(function (k) {
      var row = el('div', 'rb-check');
      row.appendChild(el('span', 'dot ' + (k.ok ? 'ok' : 'bad')));
      row.appendChild(el('span', '', k.what));
      if (k.said) row.appendChild(noI18n(el('span', 'muted small', '- ' + k.said)));
      ul.appendChild(row);
    });
    it.appendChild(ul);
    list.appendChild(it);
  });
  host.appendChild(list);
  dressButtons(host);
}
/* RESTORE.md on the pages (1.0.110): read here, downloaded as the file. */
function rbGuide() {
  api('rbackup', {action: 'restore_md'}).then(function (d) {
    modal('How to put a backup back', function (body) {
      var lede = el('p', 'note');
      lede.innerHTML = 'The <code>RESTORE.md</code> every backup carries, as one made now would have it. Keep a copy apart from the backups - with the password of the backups in a vault.';
      body.appendChild(lede);
      var doc = noI18n(el('div', 'md-doc'));
      doc.appendChild(mdRender(d.md));
      body.appendChild(doc);
    }, [{words: 'Close', close: true},
        {words: 'Download RESTORE.md', cls: 'primary', icon: 'download', go: function () {
          var a = el('a');
          a.href = URL.createObjectURL(new Blob([d.md], {type: 'text/markdown;charset=utf-8'}));
          a.download = d.name || 'RESTORE.md';
          document.body.appendChild(a); a.click(); a.remove();
          setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
        }}], 'large');
  }).catch(oops);
}
/* Markdown as the guides are written: headings, paragraphs, lists, tables,
   fenced code (with a copy button), `code`, **bold**, *italic*. Built from
   elements - nothing in the text becomes HTML. */
function mdInline(text) {
  var frag = document.createDocumentFragment();
  var re = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*\s][^*]*\*)/g, last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) frag.appendChild(document.createTextNode(text.slice(last, m.index)));
    var t = m[0];
    if (t.charAt(0) === '`') frag.appendChild(el('code', '', t.slice(1, -1)));
    else if (t.slice(0, 2) === '**') frag.appendChild(el('b', '', t.slice(2, -2)));
    else frag.appendChild(el('i', '', t.slice(1, -1)));
    last = re.lastIndex;
  }
  if (last < text.length) frag.appendChild(document.createTextNode(text.slice(last)));
  return frag;
}
function mdRender(md) {
  var out = document.createDocumentFragment();
  var lines = String(md || '').split('\n'), i = 0;
  var para = [];
  var flush = function () {
    if (!para.length) return;
    var p = el('p');
    p.appendChild(mdInline(para.join(' ')));
    out.appendChild(p);
    para = [];
  };
  while (i < lines.length) {
    var ln = lines[i];
    if (/^```/.test(ln)) {
      flush();
      var code = [];
      i += 1;
      while (i < lines.length && !/^```/.test(lines[i])) { code.push(lines[i]); i += 1; }
      i += 1;
      var wrap = el('div', 'md-code');
      var pre = el('pre', '', code.join('\n'));
      wrap.appendChild(pre);
      var cp = iconButton('copy', 'Copy');
      (function (txt, b) {
        b.onclick = function () {
          (navigator.clipboard ? navigator.clipboard.writeText(txt) : Promise.reject()).then(function () { toast('copied', 'good'); }).catch(function () { toast('select it and copy it by hand'); });
        };
      })(code.join('\n'), cp);
      wrap.appendChild(cp);
      out.appendChild(wrap);
      continue;
    }
    var h = /^(#{1,4})\s+(.*)$/.exec(ln);
    if (h) { flush(); var hn = el('h' + Math.min(6, h[1].length + 2)); hn.appendChild(mdInline(h[2])); out.appendChild(hn); i += 1; continue; }
    if (/^\|/.test(ln)) {
      flush();
      var rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) { rows.push(lines[i]); i += 1; }
      var tbl = el('table', 'md-table');
      var tb = el('tbody');
      rows.forEach(function (r, n) {
        if (/^\|[\s|:-]+\|$/.test(r)) return;
        var cells = r.replace(/^\|/, '').replace(/\|$/, '').split('|');
        if (n === 0 && cells.every(function (c) { return !c.trim(); })) return;
        var tr = el('tr');
        cells.forEach(function (c) { var td = el(n === 0 && rows.length > 1 && /^\|[\s|:-]+\|$/.test(rows[1]) ? 'th' : 'td'); td.appendChild(mdInline(c.trim())); tr.appendChild(td); });
        tb.appendChild(tr);
      });
      tbl.appendChild(tb);
      out.appendChild(tbl);
      continue;
    }
    if (/^\s*[-*] /.test(ln)) {
      flush();
      var ul = el('ul');
      var li = null;
      while (i < lines.length && (/^\s*[-*] /.test(lines[i]) || (li && /^\s{2,}\S/.test(lines[i])))) {
        if (/^\s*[-*] /.test(lines[i])) { li = el('li'); li._t = lines[i].replace(/^\s*[-*] /, ''); ul.appendChild(li); }
        else li._t += ' ' + lines[i].trim();
        i += 1;
      }
      Array.prototype.forEach.call(ul.children, function (x) { x.appendChild(mdInline(x._t)); });
      out.appendChild(ul);
      continue;
    }
    if (/^---+\s*$/.test(ln)) { flush(); out.appendChild(el('hr')); i += 1; continue; }
    if (!ln.trim()) { flush(); i += 1; continue; }
    para.push(ln.trim());
    i += 1;
  }
  flush();
  return out;
}
function rbWatch() {
  if (RB_POLL) return;
  var step = function () {
    api('rbackup', {action: 'job'}).then(function (x) {
      var j = x.job || {};
      var g = $('rb-going');
      if (g) {
        g.hidden = !j.running;
        var f = $('rb-going-fill');
        if (f) f.style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
        var sy = $('rb-going-says');
        if (sy) sy.textContent = j.says || '';
      }
      if (j.running) { RB_POLL = setTimeout(step, TAB === 'settings' && PANE === 'backup' ? 1000 : 5000); return; }
      RB_POLL = null;
      if (j.error) toast('the backup: ' + j.error, 'bad');
      else if (j.result) toast(j.result.ok ? 'the backup went to every destination' : 'the backup did not reach every destination', j.result.ok ? 'good' : 'bad');
      if (TAB === 'settings' && PANE === 'backup') loadRbackup();
    }).catch(function () { RB_POLL = null; });
  };
  step();
}
function drawRbTargets() {
  var host = $('rb-targets');
  clear(host);
  var add = cmdButton('Add a destination', 'add', 'primary small');
  add.onclick = rbPickKind;
  var ah = $('rb-add-host');
  clear(ah);
  ah.appendChild(add);
  var ts = RB.targets || [];
  if (!ts.length) {
    var empty = el('div', 'rb-empty');
    empty.appendChild(el('p', '', 'No destination yet. A backup kept only on this machine is lost with it: add a place on another machine.'));
    host.appendChild(empty);
    return;
  }
  var grid = el('div', 'rb-grid');
  ts.forEach(function (t) {
    var c = el('div', 'rb-card' + (t.enabled ? '' : ' off'));
    var top = el('div', 'rb-card-top');
    var ic = el('span', 'rb-kind k-' + t.kind);
    ic.innerHTML = iconMarkup(RB_KIND_ICON[t.kind] || 'db', 18);
    top.appendChild(ic);
    var nm = el('div', 'rb-card-name');
    nm.appendChild(noI18n(el('b', '', t.name)));
    nm.appendChild(el('span', 'rb-kind-words', t.kind_words));
    top.appendChild(nm);
    var sw = switchBox(t.enabled);
    explain(sw, t.enabled ? 'Backups go here. Switch off to stop sending, keeping everything set.' : 'Switched off: nothing is sent here.');
    sw._input.onchange = function () {
      api('rbackup', {action: 'save', id: t.id, target: {kind: t.kind, enabled: sw._get(), name: t.name, host: t.host, port: t.port, path: t.path, user: t.user, share: t.share, domain: t.domain, smb_encrypt: t.smb_encrypt, implicit: t.implicit, tls_check: t.tls_check, passive: t.passive}})
        .then(function () { loadRbackup(); }).catch(function (e) { oops(e); loadRbackup(); });
    };
    top.appendChild(sw);
    c.appendChild(top);
    c.appendChild(noI18n(el('div', 'rb-where mono', rbWhere(t))));
    var chips = el('div', 'rb-chips');
    var chip = function (w, cls, tip) { var x = el('span', 'tag ' + (cls || 'dim'), w); if (tip) x.title = tip; chips.appendChild(x); };
    if (t.has_password) chip('password', 'dim');
    if (t.has_key) chip('ssh key', 'violet');
    if (t.ssh_cert) chip('ssh certificate', 'violet');
    if (t.kind === 'sftp' || t.kind === 'scp') chip(t.hostkey ? 'host key trusted' : 'host key not trusted yet', t.hostkey ? 'ok' : 'warn', (t.hostkey_fp || []).join('\n'));
    if (t.kind === 'ftps') chip({system: 'certificate: system authorities', ca: 'certificate: own authority', pin: 'certificate pinned', none: 'certificate NOT checked'}[t.tls_check] || '', t.tls_check === 'none' ? 'warn' : 'ok');
    if (t.has_client_key) chip('client certificate', 'violet');
    if (t.kind === 'smb' && t.smb_encrypt) chip('SMB3 encrypted', 'ok');
    if (t.kind === 'ftp') chip('not encrypted on the way', 'warn');
    c.appendChild(chips);
    var last = t.last;
    var ls = el('div', 'rb-last ' + (last ? (last.ok ? 'good' : 'bad') : 'muted'));
    ls.textContent = last ? (last.ok ? '✓ last sent ' + ago(last.at) + ' · ' + rbBytes(last.bytes) : '✗ ' + ago(last.at) + ': ' + (last.error || 'failed')) : 'nothing sent here yet';
    c.appendChild(ls);
    var acts = el('div', 'rb-acts');
    var tr = cmdButton('Try it', 'play', 'small');
    tr.onclick = function () { rbTry(t, null, tr); };
    acts.appendChild(tr);
    var ed = cmdButton('Edit', 'edit', 'small');
    ed.onclick = function () { rbEdit(t); };
    acts.appendChild(ed);
    var ls2 = cmdButton('Backups there', 'list', 'small');
    ls2.onclick = function () { rbListThere(t); };
    acts.appendChild(ls2);
    var del = iconButton('trash', 'Take this destination away');
    del.onclick = function () {
      confirmThen('Take the destination ' + t.name + ' away?', 'Nothing is deleted on the server; backups simply stop going there, and its keys and certificates set here are forgotten.', 'Take it away', function () {
        api('rbackup', {action: 'delete', id: t.id}).then(function (x) { toast(x.message, 'good'); loadRbackup(); }).catch(oops);
      });
    };
    acts.appendChild(del);
    c.appendChild(acts);
    grid.appendChild(c);
  });
  host.appendChild(grid);
}
function drawRbRuns() {
  var host = $('rb-runs');
  clear(host);
  var runs = RB.runs || [];
  /* The list can be emptied, or a line taken off (1.0.110) - the backups
     themselves stay where they went. */
  var tools = $('rb-runs-tools');
  if (tools) {
    clear(tools);
    if (runs.length) {
      var wipe = cmdButton('Clear the list', 'trash', 'small');
      wipe.onclick = function () {
        confirmThen('Clear the list of backups sent?', 'Every line goes from this list (for both nodes). <b>The backups themselves stay where they went</b> - delete them under <i>Backups there</i> on a destination. Events keeps a line saying who cleared it.', 'Clear the list', function () {
          api('rbackup', {action: 'runs_forget', all: 1}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
        }, true);
      };
      tools.appendChild(wipe);
    }
  }
  if (!runs.length) { host.appendChild(el('p', 'note', 'No backup sent yet.')); return; }
  host.appendChild(listTable(['When', 'Node', 'File', 'Size', 'Where it went', 'Who', ''], runs, function (r) {
    var tr = el('tr');
    tr.appendChild(el('td', 'muted', new Date(r.at * 1000).toLocaleString(numLang())));
    tr.appendChild(noI18n(el('td', '', r.node || '')));
    var f = el('td', 'mono small');
    f.appendChild(noI18n(el('span', '', r.file || '–')));
    if (r.file && !r.encrypted) { f.appendChild(document.createTextNode(' ')); f.appendChild(el('span', 'tag bad', 'not locked')); }
    tr.appendChild(f);
    tr.appendChild(el('td', 'num', r.bytes ? rbBytes(r.bytes) : '–'));
    var w = el('td');
    if (r.error) w.appendChild(el('span', 'small bad', r.error));
    (r.targets || []).forEach(function (x) {
      var s = el('span', 'tag namepill ' + (x.ok ? 'ok' : 'crit'), (x.ok ? '✓ ' : '✗ ') + x.name);
      s.title = x.ok ? (x.secs + ' s' + ((x.taken_away || []).length ? ' · taken away: ' + x.taken_away.join(', ') : '')) : (x.error || '');
      noI18n(s);
      w.appendChild(s);
      w.appendChild(document.createTextNode(' '));
    });
    tr.appendChild(w);
    tr.appendChild(noI18n(el('td', 'muted small', r.by || '')));
    var a = el('td', 'rowtools');
    var del = iconButton('trash', 'Take it off the list');
    del.onclick = function () {
      api('rbackup', {action: 'runs_forget', at: r.at, file: r.file || ''}).then(function (d) { toast(d.message, 'good'); RB.runs = d.runs || []; drawRbRuns(); }).catch(oops);
    };
    a.appendChild(del);
    tr.appendChild(a);
    return tr;
  }, 'plain'));
}
function rbPickKind() {
  modal('Where should the backups go?', function (body) {
    var g = el('div', 'rb-kinds');
    (RB.kinds || []).forEach(function (k) {
      var b = el('button', 'rb-kind-tile');
      b.type = 'button';
      var ic = el('span', 'rb-kind k-' + k.kind);
      ic.innerHTML = iconMarkup(RB_KIND_ICON[k.kind] || 'db', 20);
      b.appendChild(ic);
      b.appendChild(el('b', '', k.words));
      b.appendChild(el('span', 'small muted', RB_KIND_SAYS[k.kind] || ''));
      var need = {sftp: ['ssh', 'sftp'], scp: ['ssh', 'scp'], smb: ['smbclient']}[k.kind] || [];
      var missing = need.filter(function (x) { return !RB.tools[x]; });
      if (missing.length) {
        b.appendChild(el('span', 'small bad', 'missing here: ' + missing.join(', ') + (k.kind === 'smb' ? ' (dnf install samba-client)' : ' (dnf install openssh-clients)')));
      }
      b.onclick = function () { closeModal(); setTimeout(function () { rbEdit({kind: k.kind, enabled: 1, port: k.port}); }, 30); };
      if (hsOn('backup:ftp') && k.kind === 'ftp') { b.disabled = true; b.appendChild(el('span', 'small hs-note', 'not under high security')); }
      g.appendChild(b);
    });
    body.appendChild(g);
  }, [{words: 'Close', close: true}], 'medium');
}
/* The editor of one destination. A new one is saved before a key or a
   certificate is made for it - they are kept with it. */
function rbEdit(t) {
  t = t || {};
  var isNew = !t.id;
  var cur = {id: t.id};
  modal(isNew ? 'A new destination: ' + (t.kind_words || (RB.kinds.filter(function (k) { return k.kind === t.kind; })[0] || {}).words || t.kind) : t.name, function (body) {
    body.classList.add('rb-ed');
    var f = {};
    var sec = function (title, says) {
      var s = el('div', 'rb-sec');
      s.appendChild(el('h4', '', title));
      if (says) s.appendChild(el('p', 'small muted', says));
      var g = el('div', 'formgrid');
      s.appendChild(g);
      body.appendChild(s);
      return g;
    };
    var g0 = sec('What it is called', '');
    f.name = textBox(t.name || '', 'NAS in the server room');
    g0.appendChild(formField('Name', f.name));
    f.enabled = switchBox(t.enabled === undefined ? 1 : t.enabled);
    g0.appendChild(formField('Backups go here', f.enabled));
    var g1 = sec('Where', t.kind === 'folder' ? 'A whole path on this machine; the acme account must be able to write into it.' : '');
    if (t.kind === 'folder') {
      f.path = textBox(t.path || '', '/mnt/backup/acme', 'mono');
      var fp = formField('The folder', f.path);
      fp.classList.add('wide');
      g1.appendChild(fp);
    } else {
      f.host = textBox(t.host || '', 'backup.example.cz', 'mono');
      g1.appendChild(formField('The server', f.host));
      f.port = textBox(t.port || '', String({ftp: 21, ftps: t.implicit ? 990 : 21, sftp: 22, scp: 22, smb: 445}[t.kind] || ''), 'mono');
      g1.appendChild(formField('Port', f.port));
      if (t.kind === 'smb') {
        f.share = textBox(t.share || '', 'backup', 'mono');
        g1.appendChild(formField('The share', f.share));
        f.path = textBox(t.path || '', 'acme\\nightly', 'mono');
        g1.appendChild(formField('The folder in it', f.path, 'Made if it is not there.'));
      } else {
        f.path = textBox(t.path || '', t.kind === 'ftp' || t.kind === 'ftps' ? 'acme/backups' : '/home/backup/acme', 'mono');
        g1.appendChild(formField('The folder there', f.path, 'Made if it is not there. Without / at the start: under the account’s home.'));
      }
    }
    if (t.kind !== 'folder') {
      var g2 = sec('Signing in', t.kind === 'sftp' || t.kind === 'scp' ? 'A key (below) or a password - or both.' : '');
      f.user = textBox(t.user || '', t.kind === 'smb' ? 'backup' : 'acme-backup', 'mono');
      g2.appendChild(formField('Account', f.user));
      f.password = maskBox(t.password || '', t.has_password ? '' : '(none)', 'mono');
      g2.appendChild(formField('Password', f.password, t.has_password ? 'Kept, sealed. Type a new one to change it.' : ''));
      if (t.kind === 'smb') {
        f.domain = textBox(t.domain || '', 'CORP', 'mono');
        g2.appendChild(formField('Domain (workgroup)', f.domain));
        f.smb_encrypt = switchBox(t.smb_encrypt === undefined ? 1 : t.smb_encrypt);
        if (hsOn('backup:smb') && f.smb_encrypt._get()) f.smb_encrypt._input.disabled = true;
        g2.appendChild(formField('SMB3 encryption required', f.smb_encrypt, 'Everything on the wire encrypted; a server that cannot is refused.'));
      }
      if (t.kind === 'ftp' || t.kind === 'ftps') {
        f.passive = switchBox(t.passive === undefined ? 1 : t.passive);
        g2.appendChild(formField('Passive mode', f.passive, 'The usual one, through firewalls and NAT.'));
      }
    }
    if (t.kind === 'ftps') rbFtpsBlock(body, t, f, cur);
    if (t.kind === 'sftp' || t.kind === 'scp') rbSshBlock(body, t, f, cur);
    var out = el('div', 'rb-try-out');
    out.id = 'rb-try-out';
    body.appendChild(out);
    rbEdit.form = f;
  }, [
    {words: 'Close', close: true},
    {words: 'Try it', icon: 'play', go: function (b) { rbTry(cur.id ? rbTarget(cur.id) || t : t, rbFormData(t.kind), b, true); }},
    {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
      busy(b, true);
      rbSaveForm(t.kind, cur).then(function () { busy(b, false); toast('saved', 'good'); closeModal(); loadRbackup(); })
        .catch(function (e) { busy(b, false); oops(e); });
    }}], 'large');
}
function rbTarget(id) { return (RB.targets || []).filter(function (x) { return x.id === id; })[0]; }
function rbFormData(kind) {
  var f = rbEdit.form || {};
  var v = function (k) { return f[k] ? (f[k]._get ? f[k]._get() : f[k].value) : undefined; };
  var d = {kind: kind};
  ['name', 'enabled', 'host', 'port', 'path', 'user', 'password', 'share', 'domain', 'smb_encrypt', 'passive', 'implicit', 'tls_check', 'ca', 'pin', 'ssh_cert'].forEach(function (k) {
    var x = v(k);
    if (x !== undefined) d[k] = typeof x === 'string' ? x.trim() : x;
  });
  if (f.password) d.password = f.password.value;
  return d;
}
function rbSaveForm(kind, cur) {
  return api('rbackup', {action: 'save', id: cur.id || '', target: rbFormData(kind)}).then(function (x) {
    cur.id = x.target.id;
    var i = (RB.targets || []).map(function (t) { return t.id; }).indexOf(x.target.id);
    if (i >= 0) RB.targets[i] = x.target; else RB.targets.push(x.target);
    return x.target;
  });
}
function rbNeedSaved(kind, cur) {
  return cur.id ? Promise.resolve(rbTarget(cur.id)) : rbSaveForm(kind, cur);
}
function rbKeyBox(text) {
  var w = el('div', 'rb-keybox');
  var pre = noI18n(el('pre', 'mono', text));
  w.appendChild(pre);
  var c = cmdButton('Copy', 'copy', 'small');
  c.onclick = function () { copyText(text, c, 'Copied'); };
  w.appendChild(c);
  return w;
}
/* The key and the certificates, as isemon has them (1.0.109): one box each,
   a line saying what it is, the same row of buttons always there (Make,
   Use my own, Download, Forget - the last two greyed until there is one),
   Try it at the end of the row, and below it the half to copy - a click on
   it copies it. */
function rbConfirm(title, words, yes, go, danger) {
  /* Over the editor, which stays as it is underneath. */
  modalOver(function () { confirmThen(title, words, yes, go, danger); });
}
function rbCopyme(text, said) {
  var code = noI18n(el('code', 'copyme', text));
  explain(code, 'Click to copy.');
  code.onclick = function () { copyText(text, code, said || 'Copied'); };
  return code;
}
function rbPanel(note) {
  var box = el('div', 'subpanel rb-panel');
  var p = el('p', 'note');
  p.innerHTML = note;
  box.appendChild(p);
  var row = el('div', 'btnrow');
  box.appendChild(row);
  var below = el('div', 'rb-below');
  box.appendChild(below);
  return {box: box, row: row, below: below};
}
function rbTryButton(t, cur) {
  var b = cmdButton('Try reaching it', 'pulse', 'primary');
  explain(b, 'Sign in, write a small file, find it in the list and take it away again - with what is typed above, saved or not.');
  b.onclick = function () { rbTry(cur.id ? (rbTarget(cur.id) || t) : t, rbFormData(t.kind), b, true); };
  return b;
}
function rbSshBlock(body, t, f, cur) {
  var s = el('div', 'rb-sec');
  s.appendChild(el('h4', '', 'The SSH key'));
  var P = rbPanel('A key is better than a password: made here, it never leaves this machine except when you download it, and the server holds only its <b>public</b> half - in <code>~/.ssh/authorized_keys</code> of the account.');
  if (!RB.tools['ssh-keygen']) {
    var miss = el('p', 'note');
    miss.style.color = 'var(--warn)';
    miss.textContent = 'ssh-keygen is not on this machine, so a key cannot be made or read here: dnf install openssh-clients. A password still works.';
    P.box.insertBefore(miss, P.row);
  }
  var mk = cmdButton('Make a key', 'key', '');
  explain(mk, 'Make a fresh ed25519 pair here. The private half stays on this machine, sealed; the public half is shown below for you to put on the server. Any key already kept is replaced.');
  var own = cmdButton('Use my own', 'upload', '');
  explain(own, 'Use a private key you already have. Paste it whole, with its BEGIN and END lines; its public half is worked out here.');
  var dl = cmdButton('Download it', 'download', '');
  explain(dl, 'The private half as a file, for keeping somewhere safe. That it was downloaded, and by whom, is written into Events.');
  var fg = cmdButton('Forget it', 'forget', 'danger');
  explain(fg, 'Delete the private key from this machine. Unless the server takes a password instead, nothing here reaches it until a new key is made and put on it.');
  [mk, own, dl, fg].forEach(function (b) { P.row.appendChild(b); });
  P.row.appendChild(el('span', 'spacer'));
  P.row.appendChild(rbTryButton(t, cur));
  var state = {pub: t.pub, has: !!t.has_key};
  var paint = function () {
    clear(P.below);
    dl.disabled = !state.has;
    fg.disabled = !state.has;
    mk.disabled = own.disabled = !RB.tools['ssh-keygen'];
    if (!state.has || !state.pub) {
      P.below.appendChild(el('p', 'btnhelp', 'No key yet — make one, or let it sign in with a password.'));
      return;
    }
    P.below.appendChild(el('p', 'btnhelp', 'The public half. Click it to copy.'));
    P.below.appendChild(rbCopyme(state.pub, 'the public key is on the clipboard'));
    var u = (f.user && f.user.value) || 'the account';
    P.below.appendChild(el('p', 'btnhelp', 'On the server, as ' + u + ':'));
    P.below.appendChild(rbCopyme("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '" + state.pub + "' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"));
  };
  mk.onclick = function () {
    rbConfirm('Make a key for ' + ((f.name && f.name.value) || t.name || 'this destination'),
      'A fresh ed25519 pair is made here. The private half stays on this machine and the public half is shown for you to put on the server.' + (state.has ? '<br><br><b>The key kept now is replaced</b>, so until the new public half is on the server, backups cannot sign in there.' : ''),
      'Make one', function () {
        rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'keygen', id: cur.id}); })
          .then(function (x) { state.pub = x.pub; state.has = true; paint(); toast('a new key was made — put the public half on the server', 'good'); })
          .catch(oops);
      }, false);
  };
  own.onclick = function () {
    modalOver(function () {
      modal('Use my own key', function (body2) {
        var p = el('p', 'note');
        p.innerHTML = 'An OpenSSH private key, whole, including its <code>BEGIN</code> and <code>END</code> lines. It is kept in this machine’s database, sealed, and never shown back. Its public half is worked out here, so you do not have to hand that over as well.';
        body2.appendChild(p);
        var area = el('textarea', 'mono');
        area.rows = 11;
        area.id = 'rb-paste-area';
        area.spellcheck = false;
        area.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----';
        body2.appendChild(area);
        var pp = maskBox('', '', 'mono');
        pp.id = 'rb-paste-pp';
        body2.appendChild(formField('Its passphrase, if it has one', pp));
        setTimeout(function () { area.focus(); }, 60);
      }, [{words: 'Cancel', close: true},
          {words: 'Keep this key', cls: 'primary', close: true, go: function () {
            var key = $('rb-paste-area').value, pass = $('rb-paste-pp').value;
            rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'key_paste', id: cur.id, key: key, passphrase: pass}); })
              .then(function (x) { state.pub = x.pub; state.has = true; paint(); toast('the key was stored', 'good'); })
              .catch(oops);
          }}]);
    });
  };
  dl.onclick = function () {
    rbConfirm('Download the private key', 'The private half leaves this machine as a file. Anybody holding it can sign in to the server as <code>' + htmlText((f.user && f.user.value) || 'that account') + '</code>. That it was downloaded, and by whom, is written into Events.', 'Download it', function () {
      api('rbackup', {action: 'key_download', id: cur.id}).then(function (x) {
        var a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([x.pem], {type: 'application/octet-stream'}));
        a.download = x.file;
        document.body.appendChild(a); a.click(); a.remove();
      }).catch(oops);
    }, false);
  };
  fg.onclick = function () {
    rbConfirm('Forget the key', 'The private key is deleted from this machine. Unless the server takes a password instead, backups will not reach it until a new key is made and put on it.', 'Forget it', function () {
      api('rbackup', {action: 'key_forget', id: cur.id}).then(function () { state.has = false; state.pub = ''; paint(); toast('the key is gone'); }).catch(oops);
    });
  };
  paint();
  s.appendChild(P.box);
  f.ssh_cert = el('textarea', 'mono rb-area small');
  f.ssh_cert.value = t.ssh_cert || '';
  f.ssh_cert.placeholder = 'ssh-ed25519-cert-v01@openssh.com AAAA…';
  var cf = formField('SSH certificate of the key (only if the server wants one)', f.ssh_cert);
  cf.style.marginTop = '12px';
  s.appendChild(cf);
  body.appendChild(s);
  var h = el('div', 'rb-sec');
  h.appendChild(el('h4', '', 'The server’s host key'));
  var H = rbPanel('The key the server proves itself with. Trusted once, after comparing its fingerprint with the server’s own (<code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on it); a server answering with any other is refused - somebody in between, or the server reinstalled.');
  var hf = cmdButton('Forget it', 'forget', 'danger');
  H.row.appendChild(hf);
  H.row.appendChild(el('span', 'spacer'));
  H.row.appendChild(rbTryButton(t, cur));
  var paintHost = function (fps) {
    clear(H.below);
    hf.disabled = !(fps && fps.length);
    if (fps && fps.length) {
      H.below.appendChild(el('p', 'btnhelp ro', 'Trusted. Click to copy.'));
      fps.forEach(function (x) { H.below.appendChild(rbCopyme(x)); });
    } else {
      H.below.appendChild(el('p', 'btnhelp', 'Not trusted yet — Try reaching it shows the fingerprint to trust.'));
    }
  };
  hf.onclick = function () {
    rbConfirm('Forget the host key', 'Backups stop going there until it is trusted again.', 'Forget it', function () {
      api('rbackup', {action: 'hostkey_forget', id: cur.id}).then(function () { paintHost([]); }).catch(oops);
    });
  };
  paintHost(t.hostkey_fp);
  rbSshBlock.paintHost = paintHost;
  h.appendChild(H.box);
  body.appendChild(h);
}
function rbFtpsBlock(body, t, f, cur) {
  var s = el('div', 'rb-sec');
  s.appendChild(el('h4', '', 'TLS'));
  var g = el('div', 'formgrid');
  f.implicit = selectBox([['0', 'explicit - AUTH TLS on port 21'], ['1', 'implicit - TLS from the start, port 990']], t.implicit ? '1' : '0');
  f.implicit._get = function () { return f.implicit.value === '1' ? 1 : 0; };
  f.implicit.onchange = function () { if (f.port && (!f.port.value || f.port.value === '21' || f.port.value === '990')) f.port.value = f.implicit.value === '1' ? '990' : '21'; };
  g.appendChild(formField('TLS', f.implicit));
  f.tls_check = selectBox([['system', 'against the authorities this machine trusts'], ['ca', 'against an authority of my own'], ['pin', 'pinned: exactly this certificate'], ['none', 'not checked (not safe)']], t.tls_check || 'system');
  hsOptions(f.tls_check, ['none'], 'backup:ftps');
  g.appendChild(formField('The server’s certificate is checked', f.tls_check));
  s.appendChild(g);
  f.ca = el('textarea', 'mono rb-area small');
  f.ca.value = t.ca || '';
  f.ca.placeholder = '-----BEGIN CERTIFICATE-----';
  var caf = formField('The authority (PEM)', f.ca, t.ca_info ? 'Now: ' + (t.ca_info.subject || '') + ' · ' + rbWhen(t.ca_info.not_after) : 'The certificate of the authority that signed the server’s.');
  s.appendChild(caf);
  f.pin = textBox(t.pin || '', '64 hex digits - Try reaching it shows the server’s', 'mono');
  var pinf = formField('Pinned SHA-256 fingerprint', f.pin);
  s.appendChild(pinf);
  var show = function () { caf.hidden = f.tls_check.value !== 'ca'; pinf.hidden = f.tls_check.value !== 'pin'; };
  f.tls_check.onchange = show;
  show();
  rbFtpsBlock.pin = f.pin;
  rbFtpsBlock.check = f.tls_check;
  body.appendChild(s);
  var cc = el('div', 'rb-sec');
  cc.appendChild(el('h4', '', 'Client certificate'));
  var P = rbPanel('Only for a server that asks for one. Made here, its key never leaves this machine except when you download it; the server gets the <b>certificate</b> - give it to its administrator.');
  var mk = cmdButton('Make one', 'key', '');
  explain(mk, 'A key and a certificate for it, made here (EC P-256, five years). Any one kept is replaced.');
  var own = cmdButton('Use my own', 'upload', '');
  explain(own, 'A certificate and its key you have: PEM (both, in any order) or a PFX / PKCS#12 file with its password.');
  var dl = cmdButton('Download it', 'download', '');
  explain(dl, 'The certificate as a file (not its key), for the server’s administrator.');
  var fg = cmdButton('Forget it', 'forget', 'danger');
  [mk, own, dl, fg].forEach(function (b) { P.row.appendChild(b); });
  P.row.appendChild(el('span', 'spacer'));
  P.row.appendChild(rbTryButton(t, cur));
  var state = {cert: t.client_cert, info: t.client_cert_info};
  var paint = function () {
    clear(P.below);
    dl.disabled = fg.disabled = !state.cert;
    if (!state.cert) {
      P.below.appendChild(el('p', 'btnhelp', 'No client certificate — most servers want none.'));
      return;
    }
    if (state.info) P.below.appendChild(noI18n(el('p', 'btnhelp ro', (state.info.subject || '') + ' · ' + rbWhen(state.info.not_after))));
    P.below.appendChild(el('p', 'btnhelp', 'The certificate. Click it to copy.'));
    P.below.appendChild(rbCopyme(state.cert, 'the certificate is on the clipboard'));
  };
  mk.onclick = function () {
    rbConfirm('Make a client certificate', 'A key and a certificate for it are made here; the key stays on this machine.' + (state.cert ? '<br><br><b>The one kept now is replaced</b>: the server has to be given the new certificate.' : ''), 'Make one', function () {
      rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'cert_make', id: cur.id, cn: 'acme-backup-' + (RB.node || '')}); })
        .then(function (x) { state.cert = x.cert; state.info = x.info; paint(); toast('made — give the certificate to the server', 'good'); }).catch(oops);
    }, false);
  };
  own.onclick = function () {
    modalOver(function () {
      modal('Use my own client certificate', function (body2) {
        var p = el('p', 'note');
        p.innerHTML = 'The certificate and its private key, as PEM - pasted, in any order - or a <code>.pfx</code> / <code>.p12</code> file. The key is kept sealed and never shown back.';
        body2.appendChild(p);
        var area = el('textarea', 'mono');
        area.rows = 11;
        area.id = 'rb-cert-area';
        area.spellcheck = false;
        area.placeholder = '-----BEGIN CERTIFICATE-----\n…\n-----BEGIN PRIVATE KEY-----';
        body2.appendChild(area);
        var file = el('input');
        file.type = 'file';
        file.accept = '.pem,.crt,.key,.pfx,.p12';
        file.onchange = function () {
          var fl = file.files[0];
          if (!fl) return;
          if (/\.(pfx|p12)$/i.test(fl.name)) fl.arrayBuffer().then(function (buf) {
            var b = new Uint8Array(buf), s2 = '';
            for (var i = 0; i < b.length; i++) s2 += String.fromCharCode(b[i]);
            area.value = btoa(s2);
          });
          else fl.text().then(function (x) { area.value = (area.value ? area.value + '\n' : '') + x; });
        };
        body2.appendChild(formField('Or a file', file));
        var pw = maskBox('', '', 'mono');
        pw.id = 'rb-cert-pw';
        body2.appendChild(formField('The password of the key or of the PFX, if it has one', pw));
      }, [{words: 'Cancel', close: true},
          {words: 'Keep this certificate', cls: 'primary', close: true, go: function () {
            var text = $('rb-cert-area').value, pass = $('rb-cert-pw').value;
            rbNeedSaved(t.kind, cur).then(function () { return api('rbackup', {action: 'cert_given', id: cur.id, text: text, password: pass}); })
              .then(function (x) { state.cert = x.cert; state.info = x.info; paint(); toast('the certificate was stored', 'good'); }).catch(oops);
          }}]);
    });
  };
  dl.onclick = function () {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([state.cert], {type: 'application/x-pem-file'}));
    a.download = 'acme-backup-client.crt';
    document.body.appendChild(a); a.click(); a.remove();
  };
  fg.onclick = function () {
    rbConfirm('Forget the client certificate', 'Its key is deleted from this machine. A server that asks for one will refuse backups until another is made and given to it.', 'Forget it', function () {
      api('rbackup', {action: 'cert_forget', id: cur.id}).then(function () { state.cert = ''; state.info = null; paint(); }).catch(oops);
    });
  };
  paint();
  cc.appendChild(P.box);
  body.appendChild(cc);
}
function rbTry(t, data, button, inEditor) {
  if (button) busy(button, true);
  var ask = {action: 'try', id: t.id || ''};
  if (data) ask.target = data;
  api('rbackup', ask).then(function (x) {
    if (button) busy(button, false);
    var show = function (host) {
      clear(host);
      if (x.hostkey_needed) {
        host.appendChild(el('p', 'note warn', 'The server shows this host key. Compare it with the server’s own fingerprint before you trust it:'));
        (x.fingerprints || []).forEach(function (fp) { host.appendChild(noI18n(el('div', 'mono small', fp))); });
        var tb = cmdButton('Trust it', 'check', 'small primary');
        tb.onclick = function () {
          var save = (inEditor && rbEdit.form) ? rbSaveForm(t.kind, {id: t.id}) : Promise.resolve(t);
          save.then(function (saved) {
            return api('rbackup', {action: 'hostkey_trust', id: saved.id, hostkey: x.hostkey}).then(function (y) {
              toast('trusted', 'good');
              if (rbSshBlock.paintHost) rbSshBlock.paintHost(y.fingerprints);
              t.id = saved.id;
              rbTry(saved, inEditor ? rbFormData(t.kind) : null, button, inEditor);
            });
          }).catch(oops);
        };
        host.appendChild(tb);
        return;
      }
      var box = el('div', 'note ' + (x.ok ? 'good' : 'bad'));
      box.appendChild(el('b', '', x.ok ? 'It works (' + x.secs + ' s)' : 'It does not work'));
      var ul = el('ul', 'rb-steps');
      (x.steps || []).forEach(function (s) { ul.appendChild(el('li', '', '✓ ' + s)); });
      if (x.error) ul.appendChild(el('li', 'bad', '✗ ' + x.error));
      box.appendChild(ul);
      var sc = x.server_cert;
      if (sc && sc.fingerprint) {
        var p = el('div', 'small');
        p.appendChild(el('span', '', 'The server’s certificate: '));
        p.appendChild(noI18n(el('span', 'mono', ((sc.cert || {}).subject || '') + ' · SHA-256 ' + sc.fingerprint)));
        box.appendChild(p);
        if (inEditor && rbFtpsBlock.pin) {
          var pin = cmdButton('Pin this certificate', 'pin', 'small');
          pin.onclick = function () { rbFtpsBlock.check.value = 'pin'; rbFtpsBlock.check.onchange(); rbFtpsBlock.pin.value = sc.fingerprint; toast('pinned - Save to keep it', 'good'); };
          box.appendChild(pin);
        }
      }
      host.appendChild(box);
      if (inEditor) host.appendChild(hideBar(function () { clear(host); }));
    };
    var host = inEditor ? $('rb-try-out') : null;
    if (host) show(host);
    else modal('Trying ' + (t.name || ''), function (body) { var h = el('div'); body.appendChild(h); show(h); }, [{words: 'Close', close: true}], 'medium');
    if (!inEditor) loadRbackup();
  }).catch(function (e) { if (button) busy(button, false); oops(e); });
}
function rbListThere(t) {
  modal('Backups at ' + t.name, function (body) {
    var host = el('div');
    host.appendChild(el('p', 'center muted', 'Asking…'));
    body.appendChild(host);
    api('rbackup', {action: 'list', id: t.id}).then(function (x) {
      clear(host);
      var files = x.files || [];
      if (!files.length) { host.appendChild(el('p', 'note', 'No backup of acme there.')); return; }
      host.appendChild(listTable(['Made', 'Node', 'Size', '', ''], files, function (fl) {
        var tr = el('tr');
        var w = el('td');
        w.appendChild(el('div', '', new Date(fl.when * 1000).toLocaleString(numLang())));
        w.appendChild(noI18n(el('div', 'mono small muted', fl.name)));
        tr.appendChild(w);
        var n = el('td');
        n.appendChild(noI18n(el('span', '', fl.node)));
        if (fl.mine) { n.appendChild(document.createTextNode(' ')); n.appendChild(el('span', 'tag info', 'this node')); }
        tr.appendChild(n);
        var sz = el('td', 'num');
        sz.textContent = rbBytes(fl.bytes);
        if (!fl.encrypted) { sz.appendChild(document.createTextNode(' ')); sz.appendChild(el('span', 'tag bad', 'not locked')); }
        tr.appendChild(sz);
        var a = el('td', 'rowtools');
        var dl = iconButton('download', 'Download it');
        dl.onclick = function () { window.location.href = '?api=rbackup-download&id=' + encodeURIComponent(t.id) + '&name=' + encodeURIComponent(fl.name); };
        a.appendChild(dl);
        var pb = iconButton('undo', 'Put this back…');
        pb.onclick = function () { rbPutBackConfirm({id: t.id, name: fl.name, encrypted: fl.encrypted, when: fl.when, node: fl.node}); };
        a.appendChild(pb);
        var del = iconButton('trash', 'Delete it there');
        del.onclick = function () {
          confirmThen('Delete ' + fl.name + '?', 'It is deleted at ' + htmlText(t.name) + ', with its checksum and its RESTORE.md.', 'Delete it', function () {
            api('rbackup', {action: 'delete_file', id: t.id, name: fl.name}).then(function () { toast('deleted', 'good'); rbListThere(t); }).catch(oops);
          });
        };
        a.appendChild(del);
        tr.appendChild(a);
        return tr;
      }, 'plain'));
    }).catch(function (e) { clear(host); host.appendChild(el('p', 'note bad', String(e.message || e))); });
  }, [{words: 'Close', close: true}], 'large');
}
function rbPutBackConfirm(what) {
  modal('Put this backup back?', function (body) {
    var facts = [];
    if (what.when) facts.push(['Made', new Date(what.when * 1000).toLocaleString(numLang())]);
    if (what.node) facts.push(['On', what.node]);
    if (what.manifest) {
      var m = what.manifest;
      facts = [['Made', m.made_words], ['On', m.node + ' (' + (m.host || '') + ')'], ['acme', m.acme], ['Certificates', m.certs != null ? String(m.certs) : '–'], ['Database', m.engine_words || m.engine]];
    }
    if (facts.length) body.appendChild(peekFacts(facts));
    body.appendChild(el('p', 'note warn', 'Everything in the database is replaced with what the backup holds - certificates and their keys, accounts, settings, logs, and who is signed in: you sign in again afterwards, with an account the backup has. A copy of what is here now is made first (Settings → The database → Copies). In a cluster it goes over to the other node too.'));
    var pw = maskBox('', what.encrypted === false ? '(not locked)' : 'the password of the backups - empty: the one set here', 'mono');
    body.appendChild(formField('Its password', pw, 'Only when it was locked with another password than the one set here now.'));
    rbPutBackConfirm.pw = pw;
  }, [{words: 'No, leave it', close: true},
      {words: 'Put it back', cls: 'danger', icon: 'undo', close: true, go: function () {
        var ask = {action: 'restore', password: rbPutBackConfirm.pw.value};
        if (what.upload) ask.upload = what.upload; else { ask.id = what.id; ask.name = what.name; }
        api('rbackup', ask).then(function (x) {
          toast(x.message, 'good');
          rbRestoreWatch();
        }).catch(oops);
      }}], 'medium');
}
function rbRestoreWatch(title) {
  modal(title || 'Putting the backup back', function (body) {
    var bar = el('div', 'going wide');
    bar.innerHTML = '<div class="bar"><span id="rbr-fill"></span></div><div class="says" id="rbr-says"></div>';
    body.appendChild(bar);
  }, [{words: 'Close', close: true}], 'medium');
  var empty = 0;
  var step = function () {
    /* Not after its popup is closed, nor for ever on nothing (1.0.206). */
    if (!$('rbr-fill')) return;
    api('db', {action: 'job'}).then(function (d) {
      var j = d.job || {};
      if (!j.running && !j.what && !j.result && !j.error && ++empty > 60) {
        if ($('rbr-says')) $('rbr-says').textContent = 'No word of it for a minute - the service may have started again. Load the page again to see the database as it is.';
        return;
      }
      if ($('rbr-fill')) $('rbr-fill').style.width = (j.whole ? Math.round(100 * j.done / j.whole) : 5) + '%';
      if ($('rbr-says')) $('rbr-says').textContent = (j.what || '') + (j.says ? ' — ' + j.says : '');
      if (j.running) { setTimeout(step, 1000); return; }
      if (!j.what && !j.result && !j.error) { setTimeout(step, 1000); return; }
      if (j.error) { if ($('rbr-says')) $('rbr-says').textContent = j.error; toast('putting it back failed: ' + j.error, 'bad'); return; }
      var r = j.result || {};
      if ($('rbr-says')) {
        var said = $('rbr-says');
        clear(said);
        said.appendChild(el('div', '', 'Put back.'));
        (r.said || []).concat(r.key ? [r.key] : []).forEach(function (x) { said.appendChild(el('div', 'small', x)); });
        if (r.safety) said.appendChild(el('div', 'small muted', 'What was here is kept as ' + r.safety));
      }
      toast(title ? 'the database is back' : 'the backup is back', 'good');
      if (title) setTimeout(function () { location.reload(); }, 4000);
    }).catch(function (e) {
      /* Who was signed in is what the backup says now: the sign-in page. */
      if (/signed in|401/i.test(String(e && e.message || e))) {
        if ($('rbr-says')) $('rbr-says').textContent = 'Put back. Sign in again - with an account the backup has.';
        setTimeout(function () { location.reload(); }, 3500);
        return;
      }
      setTimeout(step, 2000);
    });
  };
  setTimeout(step, 500);
}
function rbPutBackFile() {
  var file = el('input');
  file.type = 'file';
  file.accept = '.enc,.gz';
  file.onchange = function () {
    var fl = file.files[0];
    if (!fl) return;
    toast('sending ' + fl.name + '…', 'good');
    bigFetch('?api=rbackup-upload', fl).then(function (r) {
      return r.json().then(function (d) {
        if (!r.ok || d.ok === false) throw new Error(d.error || ('the server said ' + r.status));
        return d;
      });
    }).then(function (d) {
      if (d.said) toast(d.said, 'bad');
      rbPutBackConfirm({upload: d.upload, encrypted: d.locked, manifest: d.manifest});
    }).catch(oops);
  };
  file.click();
}

/* A button busy with something slow, the seconds counted beside its words
   (1.0.109). Returns the function that ends it. */
function busyCount(button) {
  busy(button, true);
  var began = Date.now();
  var tag = el('span', 'busy-secs', '');
  button.appendChild(tag);
  var tick = setInterval(function () { tag.textContent = ' · ' + Math.round((Date.now() - began) / 1000) + ' s'; }, 500);
  return function () { clearInterval(tick); tag.remove(); busy(button, false); };
}

/* ---- Settings → Network (1.0.119) ---------------------------------------------
   Each node's network as it says it is, a form for the new one, and the change
   followed step by step - through whichever node answers the page. */
var NET = {d: null, node: '', poll: null, fails: 0, failSince: 0, watch: '', redirect: null};
function loadNet() {
  api('net').then(function (d) {
    NET.d = d; NET.fails = 0;
    if (!NET.node || !d.nodes.some(function (n) { return n.name === NET.node; })) NET.node = (d.nodes[0] || {}).name;
    drawNet();
    netPollFor();
  }).catch(oops);
}
function netJobActive(j) { return j && ['asked', 'running', 'rebooting'].indexOf(j.state) >= 0; }
function netPollFor() {
  var busy = NET.d && NET.d.nodes.some(function (n) { return netJobActive(n.job); });
  if ((busy || NET.watch) && !NET.poll) NET.poll = setInterval(netPoll, 2000);
  if (!busy && !NET.watch && NET.poll) { clearInterval(NET.poll); NET.poll = null; }
}
function netPoll() {
  if (TAB !== 'settings' || PANE !== 'network') { clearInterval(NET.poll); NET.poll = null; return; }
  api('net').then(function (d) {
    NET.d = d; NET.fails = 0; NET.failSince = 0;
    var n = d.nodes.filter(function (x) { return x.name === NET.watch; })[0];
    if (NET.watch && n && n.job && ['done', 'failed'].indexOf(n.job.state) >= 0) {
      toast(n.job.state === 'done' ? 'the network of ' + n.name + ' is changed' : 'the network of ' + n.name + ' was not changed', n.job.state === 'done' ? 'good' : 'bad');
      NET.watch = '';
    }
    drawNet(true);
    netPollFor();
  }).catch(function () {
    /* The page's own node restarting: it does not answer for a while. */
    NET.fails += 1;
    if (!NET.failSince) NET.failSince = Date.now();
    drawNetAway();
  });
}
function netNodeOf(name) { return ((NET.d && NET.d.nodes) || []).filter(function (n) { return n.name === name; })[0]; }
function drawNet(live) {
  var real = $('net-host');
  if (!real || !NET.d) return;
  liveFill(real, function (host) {
  var d = NET.d;
  if (d.cluster) {
    var seg = el('div', 'seg net-nodes');
    d.nodes.forEach(function (n) {
      var b = el('button', n.name === NET.node ? 'on' : '');
      b.type = 'button';
      b.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      b.appendChild(noI18n(el('span', '', ' ' + n.name)));
      if (n.me) b.appendChild(el('span', 'tag info', 'this page'));
      b.onclick = function () { NET.node = n.name; drawNet(); };
      seg.appendChild(b);
    });
    host.appendChild(seg);
  }
  var n = netNodeOf(NET.node);
  if (!n) return;
  if (n.job && n.job.state && (netJobActive(n.job) || NET.watch === n.name || Date.now() / 1000 - (n.job.moved || 0) < 900))
    host.appendChild(netProgressCard(n));
  host.appendChild(netNowCard(n));
  if (!netJobActive(n.job)) host.appendChild(netFormCard(n));
  }, live, function () { explainWhatWasDrawn(real); });
}
function netFacts(rows) {
  var dl = el('div', 'net-facts');
  rows.forEach(function (r) {
    if (r[1] === undefined) return;
    var one = el('div', 'net-fact');
    one.appendChild(el('span', 'k', r[0]));
    var v = el('span', 'v' + (r[2] ? ' mono' : ''));
    if (r[1] instanceof Node) v.appendChild(r[1]); else v.textContent = r[1] === '' || r[1] === null ? '–' : String(r[1]);
    if (r[2]) noI18n(v);
    one.appendChild(v);
    dl.appendChild(one);
  });
  return dl;
}
function netNowCard(n) {
  var card = el('div', 'card full');
  var h = el('h2', '', 'As it is now');
  var right = el('span', 'right');
  var re = cmdButton('Read it again', 'refresh', 'small');
  re.onclick = function () {
    busy(re, true);
    api('net', {action: 'read', node: n.name}).then(function (d) { NET.d = d; setTimeout(loadNet, n.me ? 0 : 6000); toast(n.me ? 'read' : n.name + ' says it again within a few seconds', 'good'); })
      .catch(oops).then(function () { busy(re, false); });
  };
  right.appendChild(re);
  h.appendChild(right);
  card.appendChild(h);
  var now = n.now || {};
  var data = now.data || {};
  if (!data.devices && !data.live) {
    card.appendChild(el('p', 'note', n.alive ? n.name + ' has not said what its network is yet - Read it again.' : n.name + ' is not answering.'));
    return card;
  }
  var conf = data.conf || {};
  var live = data.live || {};
  var v6 = (live.addrs6 || []).map(function (a) { return a.addr; });
  card.appendChild(netFacts([
    ['Host name', data.hostname || '', true],
    ['Connection', (data.con || '–') + (data.dev ? ' (' + data.dev + ')' : ''), true],
    ['IPv4 address', (conf.ipv4_addresses || []).join(', ') || (live.addrs4 || []).map(function (a) { return a.addr; }).join(', '), true],
    ['Gateway', conf.ipv4_gateway || live.gw4 || '', true],
    ['DNS servers', ((conf.ipv4_dns || []).concat(conf.ipv6_dns || [])).join(', ') || (live.dns || []).join(', '), true],
    ['Search domains', (conf.ipv4_search || []).join(', '), true],
    ['IPv6', conf.ipv6_method === 'disabled' || conf.ipv6_method === 'ignore' || !conf.ipv6_method ? 'off' : (conf.ipv6_method === 'manual' ? 'on, set by hand' : 'on, automatic')],
    ['IPv6 addresses', v6.join(', '), true],
    ['Read', now.at ? ago(now.at) : '']
  ]));
  if (!data.nm) card.appendChild(el('p', 'note warn', 'NetworkManager (nmcli) is not on ' + n.name + ': its network can only be set by hand there.'));
  return card;
}
function netFormCard(n) {
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'New settings for ' + n.name));
  var data = (n.now || {}).data || {};
  var conf = data.conf || {};
  var live = data.live || {};
  if (!data.nm) { card.appendChild(el('p', 'note', 'Nothing can be set from here without NetworkManager.')); return card; }
  var on6was = !(conf.ipv6_method === 'disabled' || conf.ipv6_method === 'ignore' || !conf.ipv6_method);
  var host = textBox(data.hostname || '', 'acme1.example.cz', 'mono');
  var a4Was = (conf.ipv4_addresses || [])[0] || ((live.addrs4 || [])[0] || {}).addr || '';
  var a4 = textBox(a4Was, '192.0.2.10/24', 'mono');
  var gw = textBox(conf.ipv4_gateway || live.gw4 || '', '192.0.2.1', 'mono');
  var dns = textBox((conf.ipv4_dns || live.dns || []).filter(function (x) { return x.indexOf(':') < 0; }).join(', '), '192.0.2.53, 192.0.2.54', 'mono');
  var search = textBox((conf.ipv4_search || []).join(', '), 'example.cz', 'mono');
  var s6 = switchBox(on6was);
  var mode6 = selectBox([['manual', 'set by hand'], ['auto', 'automatic (SLAAC / DHCPv6)']], conf.ipv6_method === 'auto' ? 'auto' : 'manual');
  var a6 = textBox((conf.ipv6_addresses || [])[0] || '', '2001:db8::10/64', 'mono');
  var gw6 = textBox(conf.ipv6_gateway || '', '2001:db8::1', 'mono');
  var dns6 = textBox((conf.ipv6_dns || []).join(', '), '2001:db8::53', 'mono');
  var cons = (data.devices || []).filter(function (x) { return x.con; });
  var con = selectBox(cons.map(function (x) { return [x.con, x.con + ' (' + x.dev + ')']; }), data.con);
  var g1 = el('div', 'formgrid');
  g1.appendChild(formField('Host name (FQDN)', host, 'The machine\'s whole name. The node keeps its name in acme (' + n.name + ') whatever the machine is called.'));
  if (cons.length > 1) g1.appendChild(formField('Connection', con));
  card.appendChild(g1);
  var s1 = msect('IPv4', '');
  var g2 = el('div', 'formgrid');
  g2.appendChild(formField('Address with its prefix', a4, 'e.g. 192.0.2.10/24 - /24 is the mask 255.255.255.0.'));
  g2.appendChild(formField('Gateway', gw));
  g2.appendChild(formField('DNS servers', dns, 'Separated by commas.'));
  g2.appendChild(formField('Search domains', search));
  s1._body.appendChild(g2);
  card.appendChild(s1);
  var s2 = msect('IPv6 (dual stack)', 'Switched on, the node takes IPv6 beside IPv4: nginx answers on both, the firewall is set for both. Replication between the databases stays on IPv4. The VIP address takes an IPv6 address of its own on High availability.');
  var r6 = el('div', 'formgrid');
  r6.appendChild(formField('IPv6', s6));
  var g6 = el('div', 'formgrid');
  g6.appendChild(formField('How', mode6));
  g6.appendChild(formField('Address with its prefix', a6, 'e.g. 2001:db8::10/64'));
  g6.appendChild(formField('Gateway', gw6));
  g6.appendChild(formField('DNS servers', dns6));
  s2._body.appendChild(r6);
  s2._body.appendChild(g6);
  card.appendChild(s2);
  var paint6 = function () {
    g6.hidden = !s6._get();
    var manual = mode6.value === 'manual';
    a6.closest('.set-item').hidden = !manual;
    gw6.closest('.set-item').hidden = !manual;
  };
  s6._input.addEventListener('change', paint6);
  mode6.addEventListener('change', paint6);
  /* Shown only when the new address is outside the VIP address's network
     (1.0.120): the node could not hold it there - on purpose only while a
     whole cluster moves to another network, one node at a time. */
  var elsewhere = null;
  var vnet = null;
  if (NET.d.cluster && NET.d.vip && NET.d.vip.on) {
    elsewhere = el('div', 'note warn net-elsewhere');
    var lab = el('label', 'check small');
    var cb = el('input'); cb.type = 'checkbox';
    lab.appendChild(cb);
    lab.appendChild(el('span', '', 'The VIP address (' + NET.d.vip.address + ') is meant to be in another network than the new address'));
    elsewhere.appendChild(el('div', 'small', 'The new address is not in the network of the VIP address: keepalived could not put the VIP address on this node. Tick it only while the whole cluster moves to another network - this node now, the other next, the VIP address last (High availability).'));
    elsewhere.appendChild(lab);
    elsewhere._get = function () { return cb.checked && !elsewhere.hidden; };
    elsewhere.hidden = true;
    card.appendChild(elsewhere);
    vnet = NET.d.vip.address;
    var paintVip = function () {
      elsewhere.hidden = !ipOutside(a4.value.trim(), vnet);
    };
    a4.addEventListener('input', paintVip);
    setTimeout(paintVip, 0);
  }
  var want = function () {
    return {con: con.value || data.con, hostname: host.value.trim(),
            ipv4: {addr: a4.value.trim(), gw: gw.value.trim(), dns: dns.value, search: search.value},
            ipv6: {on: !!s6._get(), mode: mode6.value, addr: a6.value.trim(), gw: gw6.value.trim(), dns: dns6.value},
            vip_elsewhere: elsewhere ? elsewhere._get() : false};
  };
  var planBox = el('div', 'net-plan');
  var row = el('div', 'btnrow');
  row.style.marginTop = '14px';
  var check = cmdButton('Check it', 'check', '');
  var go = cmdButton('Change it and restart ' + n.name, 'power', 'primary');
  check.onclick = function () {
    busy(check, true);
    api('net', {action: 'plan', node: n.name, want: want()}).then(function (d) {
      clear(planBox);
      planBox.appendChild(el('h4', '', 'What happens'));
      var ol = el('ol', 'net-steps');
      d.plan.forEach(function (p) { ol.appendChild(el('li', '', p)); });
      planBox.appendChild(ol);
    }).catch(function (e) { clear(planBox); planBox.appendChild(el('p', 'note bad', String(e.message || e))); })
      .then(function () { busy(check, false); });
  };
  go.onclick = function () {
    var w = want();
    api('net', {action: 'plan', node: n.name, want: w}).then(function (d) {
      var words = '<ol class="net-steps">' + d.plan.map(function (p) { return '<li>' + htmlText(p) + '</li>'; }).join('') + '</ol>'
        + (n.me && !NET.d.cluster ? '<p class="note">' + htmlText('The page loses its server for a minute or two; it follows it to its new address.') + '</p>' : '');
      confirmThen('Change the network of ' + n.name + ' and restart it?', words, 'Change it and restart', function () {
        api('net', {action: 'apply', node: n.name, want: w}).then(function (r) {
          toast(r.message, 'good');
          NET.watch = n.name;
          NET.target = {node: n.name, old: (a4Was || '').split('/')[0],   /* what the box was filled with (1.0.146) - its defaultValue was always '' */ ip: w.ipv4.addr.split('/')[0], host: w.hostname, oldHost: data.hostname || '', me: n.me};
          loadNet();
        }).catch(oops);
      });
    }).catch(oops);
  };
  row.appendChild(check);
  row.appendChild(go);
  card.appendChild(row);
  card.appendChild(planBox);
  setTimeout(paint6, 0);
  return card;
}
/* Is the address (with its prefix) outside the network of the VIP address?
   IPv4 only - the VIP address and the nodes speak VRRP over IPv4. */
function ipOutside(addr, vip) {
  var p = function (t) {
    var m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)(?:\/(\d+))?$/.exec(String(t || '').trim());
    if (!m) return null;
    return {n: ((+m[1] << 24) >>> 0) + (+m[2] << 16) + (+m[3] << 8) + (+m[4]), len: m[5] === undefined ? 32 : +m[5]};
  };
  var a = p(addr), v = p(vip);
  if (!a || !v) return false;
  var mask = v.len === 0 ? 0 : (0xffffffff << (32 - v.len)) >>> 0;
  return ((a.n & mask) >>> 0) !== ((v.n & mask) >>> 0);
}
function netProgressCard(n) {
  var j = n.job;
  var card = el('div', 'card full net-job ' + (j.state || ''));
  card.appendChild(el('h2', '', j.state === 'done' ? 'The network of ' + n.name + ' is changed'
    : (j.state === 'failed' ? 'The network of ' + n.name + ' was not changed' : 'Changing the network of ' + n.name)));
  var bar = el('div', 'going wide');
  bar.innerHTML = '<div class="bar"><span></span></div>';
  bar.querySelector('span').style.width = Math.max(3, Math.min(100, j.pct || 0)) + '%';
  card.appendChild(bar);
  if (j.state === 'rebooting') {
    var since = Math.max(0, NET.d.now - (j.down_at || j.moved || NET.d.now));
    var p = el('p', 'note', 'Restarting: ' + span(since) + ' so far - a restart takes a minute or two.');
    card.appendChild(p);
  }
  var ol = el('ol', 'net-steps done');
  (j.steps || []).forEach(function (s) {
    var li = el('li', s.ok ? 'good' : 'bad');
    li.appendChild(el('span', 'mark', s.ok ? '✓' : '✗'));
    li.appendChild(el('span', '', s.what));
    li.appendChild(el('span', 'muted small', ' ' + clockWords(new Date(s.at * 1000))));
    ol.appendChild(li);
  });
  card.appendChild(ol);
  if (j.state === 'done' || j.state === 'failed') {
    var row = el('div', 'actions');
    var hide = hideButton(function () {
      return api('net', {action: 'hide', node: n.name}).then(function (d) { NET.d = d; drawNet(); });
    });
    row.appendChild(hide);
    row.appendChild(el('span', 'muted small', j.state === 'done'
      ? 'Hidden by itself 6 hours after it was done.' : 'Hidden by itself after a day.'));
    card.appendChild(row);
  }
  return card;
}
/* "Hide this" on what is over and only says how it went (1.0.123): a
   change of network, a restart, an upgrade, a job on the database, a test
   mail. `go` hides it - a promise when the server is told. */
function hideButton(go) {
  var b = cmdButton('Hide this', 'close', 'small');
  b.classList.add('hide-this');
  b.onclick = function (e) {
    if (e) e.stopPropagation();
    busy(b, true);
    Promise.resolve(go()).catch(oops).then(function () { busy(b, false); });
  };
  return b;
}
function hideBar(go, words) {
  var row = el('div', 'actions hide-row');
  row.appendChild(hideButton(go));
  if (words) row.appendChild(el('span', 'muted small', words));
  return row;
}
function drawNetAway() {
  /* The page's node does not answer: it is the one restarting. Counted down,
     and taken to its new address when it changed. */
  var host = $('net-host');
  if (!host) return;
  var t = NET.target || {};
  var away = Math.round((Date.now() - NET.failSince) / 1000);
  var box = $('net-away');
  if (!box) {
    box = el('div', 'card full net-job');
    box.id = 'net-away';
    host.insertBefore(box, host.firstChild);
  }
  clear(box);
  box.appendChild(el('h2', '', 'This page\'s server is restarting'));
  var bar = el('div', 'going wide');
  bar.innerHTML = '<div class="bar"><span></span></div>';
  bar.querySelector('span').style.width = Math.min(100, Math.round(away / 150 * 100)) + '%';
  box.appendChild(bar);
  box.appendChild(el('p', 'note', 'Not answering for ' + span(away) + '. The page asks again every two seconds.'));
  var newHost = '';
  if (t.me && t.ip && t.old && t.ip !== t.old && location.hostname === t.old) newHost = t.ip;
  if (t.me && t.host && t.oldHost && t.host !== t.oldHost && location.hostname.toLowerCase() === t.oldHost.toLowerCase()) newHost = t.host;
  if (newHost) {
    var url = location.protocol + '//' + (newHost.indexOf(':') >= 0 ? '[' + newHost + ']' : newHost) + (location.port ? ':' + location.port : '') + '/admin/#settings/network';
    var p = el('p', 'note');
    p.appendChild(document.createTextNode('It comes back at its new address: '));
    var a = noI18n(el('a', 'mono', url)); a.href = url;
    p.appendChild(a);
    box.appendChild(p);
    if (away > 150 && !NET.redirect) { NET.redirect = setTimeout(function () { location.href = url; }, 500); }
  }
}

/* ---- Settings → Restart and power off (1.0.119) ------------------------------- */
var PW = {d: null, poll: null, failSince: 0, mine: false, reload: false};
function loadPower() {
  api('power').then(function (d) { PW.d = d; PW.failSince = 0; drawPower(); pwPollFor(); }).catch(oops);
}
function pwPollFor() {
  var live = PW.d && PW.d.plan && PW.d.plan.id && !pwAllDone(PW.d);
  if (live && !PW.poll) PW.poll = setInterval(pwPoll, 2000);
  if (!live && PW.poll) { clearInterval(PW.poll); PW.poll = null; }
}
function pwPoll() {
  if (TAB !== 'settings' || PANE !== 'power') { clearInterval(PW.poll); PW.poll = null; return; }
  api('power').then(function (d) {
    var wasAway = !!PW.failSince;
    PW.d = d; PW.failSince = 0;
    drawPower(true);
    if (pwAllDone(d)) {
      clearInterval(PW.poll); PW.poll = null;
      toast(d.plan.how === 'reboot' ? 'every node is up again' : 'switched off', 'good');
      if (wasAway || PW.reload) setTimeout(function () { location.reload(); }, 2500);
    }
  }).catch(function () { if (!PW.failSince) PW.failSince = Date.now(); drawPowerAway(); });
}
function pwStateOf(d, n) {
  var r = n.row || {};
  var plan = d.plan || {};
  if (!r.state) return {k: 'wait', w: plan.order === 'rolling' ? 'waits its turn' : 'asked'};
  if (r.state === 'failed') return {k: 'bad', w: 'failed: ' + (r.said || '')};
  if (r.state === 'back') return {k: 'ok', w: 'up again'};
  if (r.state === 'going') {
    if (plan.how === 'poweroff') return n.alive && (d.now - (r.down_at || 0)) < 20 ? {k: 'going', w: 'switching off'} : {k: 'ok', w: 'switched off'};
    if (n.alive && (n.started || 0) > (r.down_at || 0)) return {k: 'going', w: 'starting'};
    if (n.alive && d.now < (r.down_at || 0) + 15) return {k: 'going', w: 'going down'};
    return {k: 'going', w: 'restarting'};
  }
  return {k: 'wait', w: r.state};
}
function pwAllDone(d) {
  if (!d.plan || !d.plan.id) return true;
  return d.nodes.filter(function (n) { return (d.plan.targets || []).indexOf(n.name) >= 0; })
    .every(function (n) { var s = pwStateOf(d, n); return s.k === 'ok' || s.k === 'bad'; });
}
function drawPower(live) {
  var real = $('pw-host');
  if (!real || !PW.d) return;
  liveFill(real, function (host) {
  var d = PW.d;
  if (d.plan && d.plan.id) host.appendChild(pwProgress(d));
  var grid = el('div', 'pw-grid');
  d.nodes.forEach(function (n) {
    var c = el('div', 'card pw-node');
    var h = el('div', 'pw-head');
    h.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
    h.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) h.appendChild(el('span', 'tag info', 'this page'));
    c.appendChild(h);
    c.appendChild(netFacts([
      ['State', n.alive ? 'answering' : 'not answering'],
      ['Address', n.address || '', true],
      ['Running for', n.started ? span(d.now - n.started) : ''],
      ['Version', n.version || '', true]
    ]));
    var row = el('div', 'btnrow');
    var rb = cmdButton('Restart', 'refresh', '');
    var off = cmdButton('Power off', 'power', 'danger');
    rb.disabled = off.disabled = !!d.busy || !n.alive;
    rb.onclick = function () { pwAsk('reboot', [n.name], 'one', n); };
    off.onclick = function () { pwAsk('poweroff', [n.name], 'one', n); };
    row.appendChild(rb); row.appendChild(off);
    c.appendChild(row);
    grid.appendChild(c);
  });
  host.appendChild(grid);
  if (d.cluster) {
    var both = el('div', 'card full');
    both.appendChild(el('h2', '', 'Both nodes'));
    var all = d.nodes.map(function (n) { return n.name; });
    var row2 = el('div', 'btnrow');
    var r1 = cmdButton('Restart one after the other', 'refresh', 'primary');
    explain(r1, 'The other node first, then this one - each in maintenance while it restarts, so the VIP address and the service never stop.');
    var r2 = cmdButton('Restart both at once', 'refresh', '');
    var r3 = cmdButton('Power off both', 'power', 'danger');
    [r1, r2, r3].forEach(function (b) { b.disabled = !!d.busy; });
    r1.onclick = function () { pwAsk('reboot', all, 'rolling'); };
    r2.onclick = function () { pwAsk('reboot', all, 'together'); };
    r3.onclick = function () { pwAsk('poweroff', all, 'together'); };
    row2.appendChild(r1); row2.appendChild(r2); row2.appendChild(r3);
    both.appendChild(row2);
    host.appendChild(both);
  }
  }, live, function () { explainWhatWasDrawn(real); });
}
function pwAsk(how, targets, order, n) {
  var d = PW.d;
  var who = targets.join(', ');
  var words;
  if (how === 'poweroff') words = targets.length > 1 ? 'Both nodes are switched off. Nothing answers - the pages, the renewals - until somebody switches them on again at the machines.'
    : (d.cluster ? n.name + ' is switched off; the VIP address moves to the other node, which goes on answering alone. It has to be switched on again at the machine.' : 'The server is switched off. Nothing answers until somebody switches it on again at the machine.');
  else if (order === 'rolling') words = 'One after the other: each goes into maintenance, the VIP address moves to the other node, it restarts and comes back into service - then the next. The pages go on answering all the time.';
  else if (targets.length > 1) words = 'Both restart at the same moment: for a minute or two nothing answers - the pages, the VIP address.';
  else words = d.cluster ? n.name + ' goes into maintenance, the VIP address moves to the other node, and it restarts; back up, it comes back into service by itself.' : 'The server restarts: for a minute or two nothing answers.';
  confirmThen((how === 'reboot' ? 'Restart ' : 'Power off ') + who + '?', htmlText(words), how === 'reboot' ? 'Restart' : 'Power off', function () {
    api('power', {how: how, targets: targets, order: order}).then(function (r) {
      toast(r.message, 'good');
      PW.reload = targets.indexOf(((d.nodes.filter(function (x) { return x.me; })[0]) || {}).name) >= 0;
      loadPower();
    }).catch(oops);
  }, how === 'poweroff');
}
function pwProgress(d) {
  var plan = d.plan;
  var card = el('div', 'card full net-job');
  var done = pwAllDone(d);
  card.appendChild(el('h2', '', (plan.how === 'reboot' ? 'Restart' : 'Power-off') + (done ? ' - done' : ' under way')));
  var ol = el('ol', 'net-steps done');
  d.nodes.filter(function (n) { return (plan.targets || []).indexOf(n.name) >= 0; })
    .sort(function (a, b) { return plan.targets.indexOf(a.name) - plan.targets.indexOf(b.name); })
    .forEach(function (n) {
      var st = pwStateOf(d, n);
      var li = el('li', st.k === 'ok' ? 'good' : (st.k === 'bad' ? 'bad' : ''));
      li.appendChild(el('span', 'mark', st.k === 'ok' ? '✓' : (st.k === 'bad' ? '✗' : '…')));
      li.appendChild(noI18n(el('b', '', n.name + ' ')));
      li.appendChild(el('span', '', st.w));
      var r = n.row || {};
      if (st.k === 'going' && r.down_at) {
        var t = Math.max(0, d.now - r.down_at);
        var bar = el('div', 'going wide');
        bar.innerHTML = '<div class="bar"><span></span></div>';
        bar.querySelector('span').style.width = Math.min(100, Math.round(t / 120 * 100)) + '%';
        li.appendChild(el('span', 'muted small', ' ' + span(t)));
        li.appendChild(bar);
      }
      ol.appendChild(li);
    });
  card.appendChild(ol);
  if (done) card.appendChild(hideBar(function () {
    return api('power', {action: 'hide'}).then(function (x) { PW.d = x; drawPower(); });
  }, 'Hidden by itself half an hour after it began.'));
  return card;
}
function drawPowerAway() {
  var host = $('pw-host');
  if (!host) return;
  var box = $('pw-away');
  if (!box) { box = el('div', 'card full net-job'); box.id = 'pw-away'; host.insertBefore(box, host.firstChild); }
  clear(box);
  var away = Math.round((Date.now() - PW.failSince) / 1000);
  box.appendChild(el('h2', '', 'This page\'s server is restarting'));
  var bar = el('div', 'going wide');
  bar.innerHTML = '<div class="bar"><span></span></div>';
  bar.querySelector('span').style.width = Math.min(100, Math.round(away / 120 * 100)) + '%';
  box.appendChild(bar);
  box.appendChild(el('p', 'note', 'Not answering for ' + span(away) + ' - asked again every two seconds; the page comes back by itself.'));
}

/* ---- Settings → Time (1.0.120) -------------------------------------------------
   Each node's clock as chrony sees it, its sources, and the time servers for the
   whole cluster. */
var NTP = {d: null, poll: null, draft: null, node: ''};
function loadNtp() {
  api('ntp').then(function (d) {
    NTP.d = d;
    if (!NTP.node) NTP.node = (d.nodes[0] || {}).name;
    drawNtp();
    if (!NTP.poll) NTP.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'time') { clearInterval(NTP.poll); NTP.poll = null; return; }
      api('ntp').then(function (x) { NTP.d = x; drawNtp(true); }).catch(function () {});
    }, 10000);
  }).catch(oops);
}
function ntpMs(s) {
  if (s === undefined || s === null || isNaN(s)) return '–';
  var ms = s * 1000;
  var a = Math.abs(ms);
  return (ms >= 0 ? '+' : '−') + (a >= 1000 ? (a / 1000).toFixed(2) + ' s' : (a >= 10 ? a.toFixed(1) : a.toFixed(3)) + ' ms');
}
function ntpHealth(n) {
  var d = (n.now || {}).data || {};
  var t = d.tracking || {};
  if (!d.time) return {k: 'bad', w: n.alive ? 'not read yet' : 'not answering'};
  if (!d.chrony) return {k: d.ntpsynchronized === 'yes' ? 'ok' : 'bad', w: d.ntpsynchronized === 'yes' ? 'synchronised (not chrony)' : 'chrony is not installed'};
  if (t.leap === 'Not synchronised' || !t.stratum) return {k: 'bad', w: 'not synchronised'};
  var off = Math.abs(t.offset || 0);
  if (off > 1) return {k: 'bad', w: 'synchronised, but off'};
  if (off > 0.1) return {k: 'warn', w: 'synchronised'};
  return {k: 'ok', w: 'synchronised'};
}
function drawNtp(quiet) {
  var real = $('ntp-host');
  if (!real || !NTP.d) return;
  /* What the server has, until something is changed here. */
  /* ... and while somebody is in one of its boxes (1.0.206): the box kept, its
     handlers wrote to the draft of before, the save sent the new one unchanged. */
  if (!NTP.draft || (!PENDING.ntp && !liveWorkedIn(real))) NTP.draft = JSON.parse(JSON.stringify(NTP.d.conf));
  liveFill(real, function (host) {
  var d = NTP.d;
  var grid = el('div', 'pw-grid');
  d.nodes.forEach(function (n) {
    var nd = (n.now || {}).data || {};
    var t = nd.tracking || {};
    var h = ntpHealth(n);
    var c = el('div', 'card ntp-node');
    var head = el('div', 'pw-head');
    head.appendChild(el('span', 'dot ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'bad'))));
    head.appendChild(noI18n(el('b', '', n.name)));
    if (n.me) head.appendChild(el('span', 'tag info', 'this page'));
    head.appendChild(el('span', 'tag ' + (h.k === 'ok' ? 'ok' : (h.k === 'warn' ? 'warn' : 'crit')), h.w));
    c.appendChild(head);
    var big = el('div', 'ntp-big');
    big.appendChild(noI18n(el('span', 'ntp-off', ntpMs(t.offset))));
    big.appendChild(el('span', 'muted small', ' off the time servers'));
    c.appendChild(big);
    var clock = '';
    if (nd.time) {
      var dt = new Date((nd.time + (d.now - (n.now.at || d.now))) * 1000);
      clock = dt.toLocaleString(numLang());
    }
    c.appendChild(netFacts([
      ['Follows', t.ref || t.ref_id || '', true],
      ['Stratum', t.stratum !== undefined ? String(t.stratum) : '', true],
      ['Last correction', ntpMs(t.last_offset), true],
      ['Frequency', t.freq !== undefined ? t.freq.toFixed(3) + ' ppm' : '', true],
      ['Root delay / dispersion', t.root_delay !== undefined ? ntpMs(t.root_delay).replace('+', '') + ' / ' + ntpMs(t.root_disp).replace('+', '') : '', true],
      ['Leap status', t.leap || ''],
      ['Time zone', nd.timezone || '', true],
      ['Its time', clock],
      ['Read', n.now && n.now.at ? ago(n.now.at) : '']
    ]));
    var ap = n.applied || {};
    if (ap.at) {
      var st = el('p', 'small ' + (ap.ok ? 'muted' : 'bad'));
      st.textContent = (ap.ok ? 'Time servers set ' : 'Time servers NOT set ') + ago(ap.at) + (ap.said ? ': ' + ap.said : '');
      c.appendChild(st);
    }
    var row = el('div', 'btnrow');
    var re = cmdButton('Read it again', 'refresh', 'small');
    re.onclick = function () { api('ntp', {action: 'read', node: n.name}).then(function (r) { toast(r.message, 'good'); setTimeout(loadNtp, 4000); }).catch(oops); };
    var sy = cmdButton('Step it now', 'clock', 'small');
    explain(sy, 'The clock set to the time servers at once (chronyc makestep), not slewed slowly - for a clock that is far off.');
    sy.onclick = function () {
      confirmThen('Step the clock of ' + n.name + ' now?', htmlText('The clock jumps to the time servers\' time at once. Codes and logs written in that moment may look out of order.'), 'Step it', function () {
        api('ntp', {action: 'sync', node: n.name}).then(function (r) { toast(r.message, 'good'); setTimeout(loadNtp, 6000); }).catch(oops);
      }, false);
    };
    row.appendChild(re); row.appendChild(sy);
    c.appendChild(row);
    grid.appendChild(c);
  });
  host.appendChild(grid);
  if (d.cluster && d.nodes.length > 1) {
    var a = ((d.nodes[0].now || {}).data || {}).tracking || {};
    var b = ((d.nodes[1].now || {}).data || {}).tracking || {};
    if (a.offset !== undefined && b.offset !== undefined) {
      var diff = Math.abs(a.offset - b.offset);
      host.appendChild(el('p', 'note ' + (diff > 1 ? 'bad' : (diff > 0.1 ? 'warn' : 'good')), 'Between the two nodes: ' + ntpMs(diff).replace('+', '') + (diff > 1 ? ' - codes right on one node may be refused on the other' : '')));
    }
  }
  /* Sources, per node. */
  var sc = el('div', 'card full');
  var sh = el('h2', '', 'Where the time comes from');
  sc.appendChild(sh);
  if (d.cluster) {
    var seg = el('div', 'seg');
    d.nodes.forEach(function (n) {
      var bt = el('button', n.name === NTP.node ? 'on' : '', n.name);
      bt.type = 'button';
      noI18n(bt);
      bt.onclick = function () { NTP.node = n.name; drawNtp(false); };
      seg.appendChild(bt);
    });
    sc.appendChild(seg);
  }
  var sn = d.nodes.filter(function (x) { return x.name === NTP.node; })[0] || d.nodes[0];
  var srcs = (((sn || {}).now || {}).data || {}).sources || [];
  var STATES = {'*': ['ok', 'followed'], '+': ['ok', 'combined'], '-': ['', 'not combined'], '?': ['crit', 'unreachable'],
                'x': ['crit', 'false ticker'], '~': ['warn', 'too variable']};
  if (!srcs.length) sc.appendChild(el('p', 'note', 'No source - chrony has none, or is not installed.'));
  else sc.appendChild(listTable(['State', 'Source', 'Stratum', 'Asked every', 'Reached', 'Last heard', 'Offset'], srcs, function (s) {
    var tr = el('tr');
    var stt = STATES[s.state] || ['', s.state];
    var td = el('td');
    td.appendChild(el('span', 'tag ' + stt[0], stt[1]));
    if (s.mode === '=') td.appendChild(el('span', 'muted small', ' peer'));
    tr.appendChild(td);
    tr.appendChild(noI18n(el('td', 'mono', s.name)));
    tr.appendChild(el('td', 'num', String(s.stratum)));
    tr.appendChild(el('td', 'num', span(Math.pow(2, s.poll || 0))));
    var r = el('td');
    var bits = el('span', 'reach');
    for (var i = 7; i >= 0; i--) bits.appendChild(el('i', (s.reach >> i) & 1 ? 'on' : ''));
    bits.title = (s.reach || 0).toString(2).padStart(8, '0') + ' - the last 8 tries';
    r.appendChild(bits);
    tr.appendChild(r);
    tr.appendChild(el('td', 'muted', s.last_rx === null || s.last_rx === undefined ? '–' : span(s.last_rx) + ' ago'));
    tr.appendChild(noI18n(el('td', 'num mono', ntpMs(s.offset) + ' ± ' + ntpMs(s.error).replace('+', ''))));
    return tr;
  }, 'plain'));
  var own = (((sn || {}).now || {}).data || {}).own || [];
  if (own.length && !(((sn || {}).now || {}).data || {}).managed) {
    sc.appendChild(el('p', 'muted small', 'Its own /etc/chrony.conf: '));
    sc.appendChild(noI18n(el('pre', 'mono small', own.join('\n'))));
  }
  host.appendChild(sc);
  host.appendChild(ntpForm());
  }, !!quiet, function () { explainWhatWasDrawn(real); });
}
function ntpForm() {
  var d = NTP.d;
  var dr = NTP.draft;
  var card = el('div', 'card full');
  card.id = 'ntp-form';
  /* Anything changed here waits for the save bar at the bottom. */
  ['input', 'change'].forEach(function (ev) { card.addEventListener(ev, function () { ntpDirty(); }); });
  card.addEventListener('click', function (e) { if (e.target.closest && e.target.closest('button')) ntpDirty(); });
  card.appendChild(el('h2', '', 'The time servers'));
  var on = switchBox(dr.manage);
  var g0 = el('div', 'formgrid');
  g0.appendChild(formField('acme sets the time servers', on, 'Off: each machine keeps its own /etc/chrony.conf (AlmaLinux\'s pool, or what you set by hand) - shown and checked here, not changed. On: the servers below, the same on every node; the file\'s own server and pool lines are commented out, and put back when switched off again.'));
  card.appendChild(g0);
  var body = el('div');
  card.appendChild(body);
  var draw = function () {
    clear(body);
    body.hidden = !dr.manage;
    var list = el('div', 'ntp-servers');
    (dr.servers || []).forEach(function (s, i) {
      var row = el('div', 'ntp-srv');
      var hostIn = textBox(s.host, 'ntp.example.cz', 'mono');
      hostIn.oninput = function () { s.host = hostIn.value.trim(); };
      var kind = selectBox([['server', 'one server'], ['pool', 'a pool (several addresses)']], s.pool ? 'pool' : 'server');
      kind.onchange = function () { s.pool = kind.value === 'pool'; };
      row.appendChild(hostIn); row.appendChild(kind);
      [['iburst', 'iburst', 'Four quick questions at the start: synchronised in seconds, not minutes.'],
       ['prefer', 'preferred', 'Followed before the others when it is good.'],
       ['nts', 'NTS', 'Network Time Security: the server proves who it is (time.cloudflare.com, ptbtime1.ptb.de, nts.netnod.se…). Needs TCP 4460 out.']].forEach(function (o) {
        var l = el('label', 'check small');
        var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!s[o[0]];
        cb.onchange = function () { s[o[0]] = cb.checked; };
        l.appendChild(cb); l.appendChild(el('span', '', o[1]));
        explain(l, o[2]);
        row.appendChild(l);
      });
      var x = iconButton('trash', 'Take it away');
      x.onclick = function () { dr.servers.splice(i, 1); draw(); };
      row.appendChild(x);
      list.appendChild(row);
    });
    body.appendChild(list);
    var adds = el('div', 'btnrow');
    var add = cmdButton('Add a server', 'add', 'small');
    add.onclick = function () { dr.servers.push({host: '', pool: false, iburst: true, prefer: false, nts: false}); draw(); };
    adds.appendChild(add);
    [['cz.pool.ntp.org', true, false], ['pool.ntp.org', true, false], ['time.cloudflare.com', false, true], ['tik.cesnet.cz', false, false], ['tak.cesnet.cz', false, false]].forEach(function (p) {
      var b = cmdButton('+ ' + p[0], '', 'small');
      noI18n(b);
      b.onclick = function () {
        if (dr.servers.some(function (s) { return s.host === p[0]; })) return;
        dr.servers.push({host: p[0], pool: p[1], iburst: true, prefer: false, nts: p[2]}); draw();
      };
      adds.appendChild(b);
    });
    body.appendChild(adds);
    var g = el('div', 'formgrid');
    g.style.marginTop = '14px';
    if (d.cluster) {
      var peers = switchBox(dr.peers);
      peers._input.onchange = function () { dr.peers = !!peers._get(); };
      g.appendChild(formField('The nodes take each other too', peers, 'Each node is one more source for the other: if the servers above are out of reach, the two nodes at least keep one time - which is what codes need.'));
    }
    var stepS = textBox(String((dr.makestep || [1, 3])[0]), '1', 'mono');
    stepS.oninput = function () { dr.makestep = [stepS.value, (dr.makestep || [1, 3])[1]]; };
    var stepN = textBox(String((dr.makestep || [1, 3])[1]), '3', 'mono');
    stepN.oninput = function () { dr.makestep = [(dr.makestep || [1, 3])[0], stepN.value]; };
    g.appendChild(formField('Step when off by more than (s)', stepS, 'Further off than this, the clock jumps to the right time instead of being slowed or sped up gently.'));
    g.appendChild(formField('…in the first updates', stepN, 'How many updates after chronyd starts may step it: 3 is after a boot; -1 any time.'));
    var mins = textBox(String(dr.minsources || 1), '1', 'mono');
    mins.oninput = function () { dr.minsources = mins.value; };
    g.appendChild(formField('Sources that have to agree', mins, 'The clock is set only when at least this many sources agree. 1 with one server; 2 or 3 with several.'));
    var allow = textBox((dr.allow || []).join(', '), '192.0.2.0/24', 'mono');
    /* A list, as it came (1.0.146): kept as the typed text, the next drawing
       of the pane broke on .join and it stopped refreshing. */
    allow.oninput = function () { dr.allow = allow.value.split(/[\s,;]+/).filter(Boolean); };
    g.appendChild(formField('Serve the time to', allow, 'Networks that may ask these nodes for the time (UDP 123) - for the machines the certificates go to, say. Empty: nobody. The firewall opens it by itself.'));
    body.appendChild(g);
  };
  on._input.onchange = function () { dr.manage = !!on._get(); draw(); };
  draw();
  var zones = d.zones || [];
  var tz = selectBox([['', '- as each machine has it -']].concat(zones.map(function (z) { return [z, z]; })), dr.timezone || '');
  tz.onchange = function () { dr.timezone = tz.value; };
  var g2 = el('div', 'formgrid');
  g2.style.marginTop = '14px';
  g2.appendChild(formField('Time zone', tz, 'Of the machines: the logs and the times on these pages. Codes do not depend on it.'));
  card.appendChild(g2);
  card.appendChild(el('p', 'muted small', 'Saved with the bar at the bottom; each node then puts them in by itself within seconds.'));
  return card;
}
function ntpDirty() {
  pendingSet('ntp', {pane: 'time', save: ntpSave, reset: function () {
    NTP.draft = JSON.parse(JSON.stringify(NTP.d.conf)); drawNtp(false);
  }});
}
function ntpSave() {
  var dr = NTP.draft;
  if (!dr) return Promise.resolve(true);
  var c = {manage: dr.manage, servers: (dr.servers || []).filter(function (s) { return s.host; }), peers: dr.peers,
           allow: dr.allow, step_s: (dr.makestep || [1, 3])[0], step_n: (dr.makestep || [1, 3])[1],
           minsources: dr.minsources, timezone: dr.timezone};
  return api('ntp', {action: 'save', conf: c}).then(function (r) {
    /* What was saved kept as the draft until the server says it (1.0.206): with
       none, a change in those 5 s was marked and never sent. */
    toast(r.message, 'good'); NTP.draft = JSON.parse(JSON.stringify(Object.assign({}, NTP.d && NTP.d.conf, dr)));
    setTimeout(loadNtp, 5000); return true;
  });
}

/* ---- Settings → SSH keys of root (1.0.158) -------------------------------------
   Each node's /root/.ssh/authorized_keys as its root helper reads it; the keys
   put side by side, a column a node. Above them root's key kept here, drawn as
   isemon draws a router's (1.0.159), made here - one for every node, or one for
   a node of its own. The key is then in the list below, a key of one's own
   added there too (1.0.161). */
var SK = {d: null, poll: null, asked: 0, scope: 'all'};
function loadSshKeys() {
  api('sshkeys').then(function (d) {
    SK.d = d; drawSshKeys();
    /* Read afresh on every node when the pane is opened. */
    if (Date.now() - SK.asked > 20000) {
      SK.asked = Date.now();
      api('sshkeys', {action: 'refresh', nodes: skNodes(true)}).then(function () { skPoll(true); }).catch(function () {});
    }
    skPoll(skPending());
  }).catch(oops);
}
function skNodes(aliveOnly) {
  return ((SK.d && SK.d.nodes) || []).filter(function (n) { return !aliveOnly || n.alive; }).map(function (n) { return n.name; });
}
function skPending() { return ((SK.d && SK.d.nodes) || []).some(function (n) { return n.pending; }); }
function skPoll(on) {
  if (on && !SK.poll) {
    SK.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'sshkeys') { skPoll(false); return; }
      api('sshkeys').then(function (d) { SK.d = d; drawSshKeys(true); if (!skPending()) skPoll(false); }).catch(function () {});
    }, 2000);
  }
  if (!on && SK.poll) { clearInterval(SK.poll); SK.poll = null; }
}
function skKind(k) {
  var t = String(k.type || '?').toUpperCase();
  return t + (k.bits && t !== 'ED25519' ? ' ' + k.bits : '');
}
function drawSshKeys(live) {
  var real = $('sk-host');
  if (!real || !SK.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = SK.d, nodes = d.nodes || [];
    /* What sshd makes of root: keys are no use where it does not let root in. */
    nodes.forEach(function (n) {
      var sd = n.sshd || {};
      if (n.error) host.appendChild(el('p', 'note bad', n.name + ': ' + n.error));
      if (sd.there && sd.permit_root === 'no')
        host.appendChild(el('p', 'note warn', n.name + ': sshd does not let root sign in at all (PermitRootLogin no) - the keys below are not used there until it does.'));
      if (sd.there && sd.pubkey === 'no')
        host.appendChild(el('p', 'note warn', n.name + ': sshd takes no keys (PubkeyAuthentication no).'));
    });
    var kept = {};
    (d.kept || []).forEach(function (r) { if (r.fp) kept[r.fp] = r; });
    host.appendChild(skKeptCard(d));
    var card = el('div', 'card full');
    var h = el('h2', '', 'Keys that may sign in as root');
    var tools = el('span', 'right');
    var add = cmdButton('Add a key', 'upload', 'small');
    explain(add, 'A key you have already - its public line or .pub file, or the private key, of which only the public half is used - put onto the nodes you choose.');
    var again = iconButton('refresh', 'Read the keys again on every node');
    tools.appendChild(add); tools.appendChild(again);
    h.appendChild(tools);
    card.appendChild(h);
    add.onclick = skAdd;
    again.onclick = function () {
      api('sshkeys', {action: 'refresh', nodes: skNodes(true)}).then(function () { skPoll(true); toast('asked again'); }).catch(oops);
    };
    /* One row a key, by its fingerprint, a column a node. */
    var byFp = {}, order = [];
    nodes.forEach(function (n) {
      (n.keys || []).forEach(function (k) {
        var id = k.fp || ('?' + k.comment);
        if (!byFp[id]) { byFp[id] = {k: k, on: {}}; order.push(id); }
        byFp[id].on[n.name] = true;
      });
    });
    if (!order.length) {
      card.appendChild(el('p', 'note', nodes.some(function (n) { return n.at; })
        ? 'No key lets root in over SSH on ' + nodes.map(function (n) { return n.name; }).join(' or ') + '.'
        : 'Reading the keys of each node…'));
    } else {
      var heads = ['Key', 'Fingerprint', 'Comment'].concat(nodes.length > 1 ? nodes.map(function (n) { return n.name; }) : []).concat(['']);
      card.appendChild(listTable(heads, order, function (id) {
        var row = byFp[id], k = row.k;
        var tr = el('tr');
        var t = el('td');
        t.appendChild(el('span', 'tag ' + (String(k.type).toUpperCase() === 'ED25519' ? 'good' : 'info'), skKind(k)));
        if (k.options) t.appendChild(el('span', 'tag warn', 'with options'));
        if (kept[k.fp]) t.appendChild(el('span', 'tag info', 'made here'));
        tr.appendChild(t);
        tr.appendChild(noI18n(el('td', 'mono small', k.fp || '–')));
        tr.appendChild(noI18n(el('td', 'small', k.comment || '–')));
        if (nodes.length > 1) nodes.forEach(function (n) {
          var c = el('td');
          c.appendChild(el('span', 'tag ' + (row.on[n.name] ? 'good' : 'dim'), row.on[n.name] ? 'yes' : '–'));
          tr.appendChild(c);
        });
        var act = el('td', 'right sk-act');
        /* Each key exported by itself, as its .pub file (1.0.160). */
        var ex = iconButton('download', 'Export this key - its public half, as a .pub file');
        ex.disabled = !k.text;
        ex.onclick = function () { skExport(k); };
        act.appendChild(ex);
        var rm = iconButton('trash', 'Take this key away');
        rm.onclick = function () { skDrop(row); };
        act.appendChild(rm);
        tr.appendChild(act);
        return tr;
      }, 'plain'));
    }
    var pend = nodes.filter(function (n) { return n.pending; }).map(function (n) { return n.name; });
    if (pend.length) card.appendChild(el('p', 'muted small', 'Being written on ' + pend.join(', ') + '…'));
    host.appendChild(card);
    /* Each node's own facts. */
    var grid = el('div', 'pw-grid');
    nodes.forEach(function (n) {
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) hd.appendChild(el('span', 'tag info', 'this page'));
      c.appendChild(hd);
      var sd = n.sshd || {};
      c.appendChild(netFacts([
        ['Keys', String((n.keys || []).length)],
        ['Root may sign in', sd.there ? (sd.permit_root || '?') : 'sshd is not here'],
        ['With a password', sd.there ? (sd.password || '?') : ''],
        ['SSH port', sd.port || '', true],
        ['The file', n.file || '/root/.ssh/authorized_keys', true],
        ['Read', n.at ? ago(n.at) : 'not yet']
      ]));
      grid.appendChild(c);
    });
    host.appendChild(grid);
  }, live);
}
function skNodePicker(body) {
  var nodes = (SK.d && SK.d.nodes) || [];
  var box = el('div', 'sk-nodes');
  var boxes = [];
  if (nodes.length > 1) {
    box.appendChild(el('div', 'k small muted', 'Onto the nodes'));
    nodes.forEach(function (n) {
      var lab = el('label', 'chk');
      var c = el('input'); c.type = 'checkbox'; c.checked = n.alive; c.disabled = !n.alive; c.value = n.name;
      lab.appendChild(c); lab.appendChild(noI18n(el('span', '', ' ' + n.name + (n.alive ? '' : ' (not answering)'))));
      box.appendChild(lab);
      boxes.push(c);
    });
    body.appendChild(box);
  }
  return function () {
    if (!boxes.length) return [nodes.length ? nodes[0].name : ''];
    return boxes.filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
  };
}
function skScopeWords(sc) { return sc === 'all' ? 'every node' : sc; }
/* Root's key, made or given here: isemon's key panel - the same words, the
   buttons in a row, the public half below to copy. Unlike isemon's it is kept
   nowhere: acme never signs in as root, so a key made here is handed over
   once, and one given leaves only its public half. In a cluster, the same
   key on every node or a node's own. Taking a key away is in the list. */
function skKeptCard(d) {
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'A key for root'));
  var scopes = (d.kept || []);
  if (!scopes.some(function (r) { return r.scope === SK.scope; })) SK.scope = 'all';
  if (scopes.length > 1) {
    var segb = el('div', 'seg');
    scopes.forEach(function (r) {
      var b = el('button', r.scope === SK.scope ? 'on' : '', r.scope === 'all' ? 'The same key on every node' : 'Only on');
      if (r.scope !== 'all') b.appendChild(noI18n(el('b', '', ' ' + r.scope)));
      b.type = 'button';
      b.onclick = function () { SK.scope = r.scope; drawSshKeys(); };
      segb.appendChild(b);
    });
    var ff = formField('The key for', segb);
    ff.style.marginBottom = '12px';
    card.appendChild(ff);
  }
  var cur = scopes.filter(function (r) { return r.scope === SK.scope; })[0] || {scope: 'all', on: {}};
  var nodes = Object.keys(cur.on || {});
  var where = cur.scope === 'all' ? (nodes.length > 1 ? 'both nodes - the same key' : 'this server') : '<b>' + htmlText(cur.scope) + '</b> only';
  var P = rbPanel('Its <b>public</b> half goes into <code>/root/.ssh/authorized_keys</code> of ' + where + '. The <b>private</b> half is never kept here: it is shown to you once, to download or copy. The key is then in the list below - exported or taken away there; a key of your own is added there too.');
  if (!d.keygen) {
    var miss = el('p', 'note');
    miss.style.color = 'var(--warn)';
    miss.textContent = 'ssh-keygen is not on this machine, so a key cannot be made or read here: dnf install openssh-clients.';
    P.box.insertBefore(miss, P.row);
  }
  var mk = cmdButton('Make a key', 'key', '');
  explain(mk, 'Make a fresh pair here - Ed25519, or RSA 4096 where something old needs RSA. Its private half is shown to you once; its public half goes into root\'s authorized_keys of ' + (cur.scope === 'all' ? 'every node' : cur.scope) + '.');
  P.row.appendChild(mk);
  mk.disabled = !d.keygen;
  var words = cur.scope === 'all' ? 'every node' : cur.scope;
  mk.onclick = function () {
    var kind = 'ed25519';
    modal('Make a key for ' + words, function (body) {
      var p = el('p', 'note');
      p.innerHTML = 'A fresh pair is made here. Its <b>private</b> half is shown to you once, to download or copy, and kept nowhere; its <b>public</b> half goes into root\'s authorized_keys of ' + htmlText(nodes.join(', ')) + '. A key there before stays until it is taken away in the list below.';
      body.appendChild(p);
      var sg = el('div', 'seg');
      [['ed25519', 'Ed25519 (the strongest, and short)'], ['rsa4096', 'RSA 4096 (where something old needs RSA)']].forEach(function (o) {
        var b = el('button', o[0] === kind ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { kind = o[0]; Array.prototype.forEach.call(sg.children, function (x) { x.classList.remove('on'); }); b.classList.add('on'); };
        sg.appendChild(b);
      });
      body.appendChild(formField('The kind', sg));
    }, [{words: 'Cancel', close: true}, {words: 'Make one', cls: 'primary', icon: 'key', go: function (b) {
      busy(b, true);
      api('sshkeys', {action: 'rk_make', scope: cur.scope, kind: kind}).then(function (x) {
        skShowMade(x);
        return api('sshkeys');
      }).then(function (d2) { SK.d = d2; drawSshKeys(); skPoll(true); })
        .catch(function (e) { busy(b, false); oops(e); });
    }}], 'medium');
  };
  card.appendChild(P.box);
  return card;
}
function skShowMade(x) {
  modal('Keep the private key now', function (body) {
    var w = el('p', 'note warn');
    w.textContent = 'This is the only time it is shown. Whoever holds it signs in to ' + x.nodes.join(', ') + ' as root.';
    body.appendChild(w);
    var area = noI18n(el('textarea', 'mono'));
    area.rows = 9; area.readOnly = true; area.value = x.private; area.spellcheck = false;
    body.appendChild(area);
    var row = el('div', 'btnrow');
    var dl = cmdButton('Download the key', 'download', 'primary');
    dl.onclick = function () { skSave(x.private, x.file); };
    var cp = cmdButton('Copy it', 'copy', '');
    cp.onclick = function () { copyText(x.private, cp, 'the private key is on the clipboard'); };
    row.appendChild(dl); row.appendChild(cp);
    row.style.margin = '12px 0 16px';
    body.appendChild(row);
    body.appendChild(el('p', 'btnhelp', 'Its public half, put onto the nodes - click it to copy:'));
    body.appendChild(rbCopyme(x.pub, 'the public key is on the clipboard'));
    body.appendChild(noI18n(el('p', 'muted small mono', x.fp)));
    body.appendChild(el('p', 'btnhelp', 'Then, on your machine: ssh -i ' + x.file + ' root@…'));
  }, [{words: 'I have kept it', cls: 'primary', close: true}], 'medium');
}
function skKept(action, extra, b) {
  if (b) busy(b, true);
  var q = {action: action, scope: SK.scope};
  Object.keys(extra || {}).forEach(function (k) { q[k] = extra[k]; });
  api('sshkeys', q).then(function (x) {
    toast(x.message, 'good');
    return api('sshkeys');
  }).then(function (d) { SK.d = d; drawSshKeys(); skPoll(true); })
    .catch(function (e) { if (b) busy(b, false); oops(e); });
}
function skSave(text, file) {
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], {type: 'application/octet-stream'}));
  a.download = file;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
}
/* One key's public half as a .pub file, named by its comment. */
function skExport(k) {
  var name = String(k.comment || k.type || 'key').replace(/[^A-Za-z0-9@._-]+/g, '_').replace(/^[._]+/, '').slice(0, 60) || 'key';
  skSave(k.text + '\n', name + '.pub');
  toast('the key is exported as ' + name + '.pub', 'good');
}
function skAdd() {
  var area, pick, pp, ppf;
  modal('Add a key for root', function (body) {
    var p = el('p', 'note');
    p.innerHTML = 'One line of a <code>.pub</code> file: <code>ssh-ed25519 AAAA… you@laptop</code>. Ed25519, ECDSA or RSA of 3072 bits and more; options before the key are not taken here. A private key is taken too: its public half is worked out here and the private half is not kept.';
    body.appendChild(p);
    area = noI18n(el('textarea', 'mono'));
    area.rows = 4; area.spellcheck = false; area.placeholder = 'ssh-ed25519 AAAA… you@laptop';
    body.appendChild(area);
    var fr = el('div', 'btnrow');
    fr.style.margin = '8px 0 4px';
    var pickB = cmdButton('Read a file…', 'upload', 'small');
    var input = el('input'); input.type = 'file'; input.hidden = true;
    pickB.onclick = function () { input.click(); };
    input.onchange = function () {
      var f = input.files && input.files[0];
      if (!f) return;
      if (f.size > 65536) { toast('that file is far bigger than a key', 'warn'); return; }
      f.text().then(function (t) { t = t.trim(); area.value = t.indexOf('PRIVATE KEY') >= 0 ? t : t.split(/\r?\n/)[0]; skAddPp(); });
    };
    fr.appendChild(pickB); fr.appendChild(input);
    body.appendChild(fr);
    pp = maskBox('', '', 'mono');
    ppf = formField('Its passphrase, if the private key has one', pp);
    var skAddPp = function () { ppf.hidden = area.value.indexOf('PRIVATE KEY') < 0; };
    area.oninput = skAddPp;
    skAddPp();
    body.appendChild(ppf);
    pick = skNodePicker(body);
    setTimeout(function () { area.focus(); }, 60);
  }, [{words: 'Cancel', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', close: true, go: function () {
    var nodes = pick();
    api('sshkeys', {action: 'add', line: area.value.trim(), passphrase: pp.value, nodes: nodes}).then(function (x) { toast(x.message, 'good'); skPoll(true); }).catch(oops);
  }}], 'medium');
}
function skDrop(row) {
  var nodes = Object.keys(row.on);
  var last = ((SK.d && SK.d.nodes) || []).filter(function (n) { return row.on[n.name] && (n.keys || []).length <= 1; }).map(function (n) { return n.name; });
  confirmThen('Take the key away', 'Root no longer signs in with <code>' + htmlText(row.k.fp || '') + '</code>' + (row.k.comment ? ' (' + htmlText(row.k.comment) + ')' : '') + ' on ' + htmlText(nodes.join(', ')) + '.'
    + (last.length ? '<br><br><b>It is the last key root signs in with on ' + htmlText(last.join(', ')) + '.</b> Unless root may sign in with a password, nobody reaches it over SSH as root after this.' : ''),
    'Take it away', function () {
      api('sshkeys', {action: 'drop', fp: row.k.fp, nodes: nodes, last_ok: !!last.length}).then(function (x) { toast(x.message, 'good'); skPoll(true); }).catch(oops);
    }, true);
}

/* ---- Settings → System updates (1.0.158) ----------------------------------------
   What each node has waiting, the update one node at a time - out of service,
   dnf or apt, back in service - with its output as it comes, and the restart
   it needs offered at the end. */
var OU = {d: null, poll: null, node: '', hide: false, reboot: 'ask', asked: 0};
try { OU.hide = localStorage.getItem('acme-ou-hide') === '1'; } catch (e) { /* only a convenience */ }
var OU_STATE = {waiting: ['waits its turn', 'dim'], draining: ['out of service', 'warn'],
                updating: ['updating', 'info'], rebooting: ['restarting', 'warn'],
                done: ['done', 'good'], failed: ['failed', 'bad'], skipped: ['left out', 'dim']};
function loadOsup() {
  api('osup').then(function (d) { OU.d = d; drawOsup(); ouPoll(ouLive(d)); }).catch(oops);
}
function ouLive(d) {
  d = d || OU.d || {};
  /* Just asked: the node has not begun yet, followed until it says (1.0.159). */
  if (Date.now() - OU.asked < 30000) return true;
  return (d.plan && d.plan.state === 'running') || (d.nodes || []).some(function (n) { return (n.check || {}).state === 'running'; }) || !!(d.power && d.power.id);
}
function ouPoll(on) {
  if (on && !OU.poll) {
    OU.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'osup') { ouPoll(false); return; }
      api('osup').then(function (d) { OU.d = d; OU.away = 0; drawOsup(true); if (!ouLive(d)) ouPoll(false); })
        .catch(function () { OU.away = OU.away || Date.now(); drawOsup(true); });
    }, 2500);
  }
  if (!on && OU.poll) { clearInterval(OU.poll); OU.poll = null; }
}
/* Something asked of the nodes: followed from now on. */
function ouAsked() { OU.asked = Date.now(); ouPoll(true); }
/* A button clicked keeps the focus, and a live redraw leaves alone what has
   it - the window that was clicked in stayed as it was (1.0.159). */
function liveLetGo(host) {
  if (!host || host._letGo) return;
  host._letGo = true;
  host.addEventListener('click', function (e) {
    var b = e.target && e.target.closest ? e.target.closest('button') : null;
    if (b && host.contains(b)) setTimeout(function () { if (document.activeElement === b) b.blur(); }, 0);
  });
}
function ouPercent(r) {
  var st = (r || {}).state;
  if (st === 'done' || st === 'failed') return 100;
  if (st === 'draining') return Math.min(8, 3 + Math.round((Date.now() / 1000 - Number(r.drain_at || r.at || 0)) / 3));
  if (st === 'updating') return Math.max(8, Math.min(95, Number(r.pct || 0)));
  if (st === 'rebooting') return 96;
  return 0;
}
function drawOsup(live) {
  var real = $('ou-host');
  if (!real || !OU.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = OU.d, plan = d.plan || {}, nodes = d.nodes || [];
    var running = plan.state === 'running';
    if (OU.away) host.appendChild(el('p', 'note warn', 'This page\'s server is not answering for ' + span(Math.round((Date.now() - OU.away) / 1000)) + ' - restarting, or the VIP address moving; asked again every few seconds.'));
    /* A restart the update left to do. */
    var need = nodes.filter(function (n) { return n.reboot; });
    if (need.length && !(d.power && d.power.id)) {
      var rb = el('div', 'card full notice warn ou-reboot');
      rb.appendChild(el('h2', '', need.length > 1 ? 'The nodes need a restart' : need[0].name + ' needs a restart'));
      rb.appendChild(el('p', 'note', 'A new kernel or libraries are in that only a restart brings into use. ' + (d.cluster ? 'Restarted one after the other, each in maintenance while it is, the service never stops.' : 'For a minute or two nothing is renewed or put in place.')));
      var go = cmdButton(need.length > 1 ? 'Restart them, one at a time' : 'Restart ' + need[0].name, 'refresh', 'primary');
      go.onclick = function () {
        confirmThen('Restart after the update', 'Restarted now: ' + htmlText(need.map(function (n) { return n.name; }).join(', ')) + (need.length > 1 ? ', one after the other.' : '.'), 'Restart', function () {
          api('osup', {action: 'reboot', nodes: need.map(function (n) { return n.name; })}).then(function (x) { toast(x.message, 'good'); ouAsked(); }).catch(oops);
        }, false);
      };
      rb.appendChild(go);
      host.appendChild(rb);
    }
    if (d.power && d.power.id) host.appendChild(el('p', 'note', 'Restarting: ' + (d.power.targets || []).join(', ') + ' - followed on Restart and power off.'));
    /* What each node has waiting. */
    var grid = el('div', 'pw-grid');
    nodes.forEach(function (n) {
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) hd.appendChild(el('span', 'tag info', 'this page'));
      var ck = n.check || {};
      if (ck.state === 'running') hd.appendChild(el('span', 'tag info', 'looking…'));
      else if (ck.checked && ck.state === 'done') hd.appendChild(el('span', 'tag ' + (ck.count ? 'warn' : 'good'), ck.count ? num(ck.count) + ' waiting' : 'up to date'));
      /* The restart on a line of its own, always (1.0.193). */
      if (n.reboot || (ck.reboot_after && ck.count)) hd.appendChild(el('span', 'pw-break'));
      if (n.reboot) hd.appendChild(el('span', 'tag warn', 'restart needed'));
      else if (ck.reboot_after && ck.count) hd.appendChild(el('span', 'tag info', 'restart after the update'));
      c.appendChild(hd);
      c.appendChild(netFacts([
        ['Updates waiting', ck.checked ? num(ck.count || 0) : 'not looked yet'],
        ['Of them security', ck.security !== undefined && ck.security !== null ? num(ck.security) : ''],
        ['A restart', !ck.checked ? '' : (ck.reboot_now ? 'needed now, before any update'
          : (ck.reboot_after && ck.count ? 'needed after the update - ' + (ck.reboot_why || []).join(', ') : 'not needed by these updates'))],
        ['Looked', ck.checked ? ago(ck.checked) : ''],
        ['Updated by', ck.pm || '', true]
      ]));
      if (ck.error) c.appendChild(el('p', 'note bad', ck.error));
      if ((ck.packages || []).length) {
        var more = el('details', 'fold');
        more.appendChild(el('summary', '', 'what is waiting'));
        more.appendChild(noI18n(el('pre', 'lines', ck.packages.slice(0, 300).join('\n') + (ck.packages.length > 300 ? '\n…' : ''))));
        OU.pkOpen = OU.pkOpen || {};
        if (OU.pkOpen[n.name]) more.open = true;
        more.ontoggle = function () { OU.pkOpen[n.name] = more.open; };
        c.appendChild(more);
      }
      var row = el('div', 'btnrow');
      var look = cmdButton('Look for updates', 'search', '');
      look.disabled = !n.alive || ck.state === 'running' || running;
      look.onclick = function () { busy(look, true); api('osup', {action: 'check', nodes: [n.name]}).then(function (x) { toast(x.message); OU.node = n.name; ouAsked(); }).catch(function (e) { busy(look, false); oops(e); }); };
      row.appendChild(look);
      c.appendChild(row);
      grid.appendChild(c);
    });
    host.appendChild(grid);
    /* The update itself. */
    if (!running) {
      var uc = el('div', 'card full');
      uc.appendChild(el('h2', '', d.cluster ? 'Update the nodes' : 'Update this server'));
      uc.appendChild(el('p', 'note', d.cluster
        ? 'The other node first, then this one - each out of service while it is updated, the VIP address on the other, the work done there; back in service before the next one starts.'
        : 'dnf (or apt) updates every package. The pages go on answering meanwhile; a restart it needs is offered at the end.'));
      var segb = el('div', 'seg');
      [['ask', 'Ask me when a restart is needed'], ['auto', 'Restart by itself when needed' + (d.cluster ? ', one at a time' : '')]].forEach(function (o) {
        var b = el('button', OU.reboot === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.reboot = o[0]; drawOsup(); };
        segb.appendChild(b);
      });
      var after = nodes.filter(function (n) { var k = n.check || {}; return k.reboot_after && k.count; });
      if (after.length) {
        var an = el('p', 'note warn', (after.length === nodes.length && nodes.length > 1 ? 'Both nodes need' : after.map(function (n) { return n.name; }).join(', ') + (after.length > 1 ? ' need' : ' needs'))
          + ' a restart after this update: ' + after.map(function (n) { return (n.check.reboot_why || []).join(', '); }).filter(function (x, i, a) { return x && a.indexOf(x) === i; }).join('; ') + '.');
        uc.appendChild(an);
      }
      var seg2 = el('div', 'seg');
      [['all', 'Every update'], ['security', 'Only the security updates']].forEach(function (o) {
        var b = el('button', (OU.what || 'all') === o[0] ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () { OU.what = o[0]; drawOsup(); };
        seg2.appendChild(b);
      });
      uc.appendChild(formField('Which', seg2));
      uc.appendChild(formField('After the update', segb));
      var row2 = el('div', 'btnrow');
      var start = cmdButton(d.cluster ? 'Update them, one at a time' : 'Update it now', 'download', 'primary');
      start.disabled = !d.helper || nodes.some(function (n) { return !n.alive; }) || !!(d.power && d.power.id);
      start.onclick = function () {
        confirmThen(d.cluster ? 'Update the nodes' : 'Update this server', 'Every package of the system is updated' + (d.cluster ? ', on ' + htmlText(nodes.map(function (n) { return n.name; }).join(' and then ')) + ', each out of service while it is.' : '.')
          + (OU.reboot === 'auto' ? '<br><br>A node that needs it is <b>restarted by itself</b>.' : '<br><br>A restart it needs is offered when it is done.'),
          'Update', function () {
            api('osup', {action: 'start', reboot: OU.reboot, security: OU.what === 'security'}).then(function (x) { toast(x.message, 'good'); OU.node = ''; ouAsked(); loadOsup(); }).catch(oops);
          }, false);
      };
      var lookAll = cmdButton('Look on every node', 'search', '');
      lookAll.onclick = function () { busy(lookAll, true); api('osup', {action: 'check'}).then(function (x) { toast(x.message); ouAsked(); }).catch(function (e) { busy(lookAll, false); oops(e); }); };
      row2.appendChild(start); row2.appendChild(lookAll);
      uc.appendChild(row2);
      if (!d.helper) uc.appendChild(el('p', 'note bad', 'The root helper of this node is not installed (install.sh --upgrade puts it in).'));
      host.appendChild(uc);
    }
    /* How far it is. */
    if (plan.id) {
      var pc = el('div', 'card full');
      var ph = el('h2', '', 'The update');
      if (running) {
        var stop = cmdButton('Stop it', 'cancel', 'small danger');
        explain(stop, 'The nodes not begun stay as they are; a node being updated finishes.');
        stop.onclick = function () { confirmThen('Stop the update', 'The nodes not yet begun stay as they are; one being updated finishes.', 'Stop it', function () { api('osup', {action: 'cancel'}).then(function (x) { toast(x.message); loadOsup(); }).catch(oops); }, true); };
        var tl = el('span', 'right'); tl.appendChild(stop); ph.appendChild(tl);
      }
      pc.appendChild(ph);
      pc.appendChild(el('p', 'note', 'Started by ' + (plan.by || '?') + ' · ' + ago(plan.at) + ' · ' + ({running: 'going on', done: 'done', failed: 'failed', cancelled: 'stopped'})[plan.state || 'running']
        + (plan.reboot === 'auto' ? ' · restarted where needed' : '') + (plan.security ? ' · security updates only' : '')));
      var steps = (plan.order || []).map(function (nm) {
        var n = nodes.filter(function (x) { return x.name === nm; })[0] || {name: nm};
        return {name: nm, row: n.row || {}};
      });
      var all = steps.length ? Math.round(steps.reduce(function (m, s) { return m + ouPercent(s.row); }, 0) / steps.length) : 0;
      pc.appendChild(upBar(all, plan.state === 'failed' ? 'bad' : (plan.state === 'done' ? 'good' : ''),
        num(all) + ' % · ' + steps.filter(function (s) { return s.row.state === 'done'; }).length + ' of ' + steps.length + ' node(s) done', true));
      var t = listTable(['Node', 'Step', 'How far', 'What happened', 'When'], steps, function (s) {
        var tr = el('tr');
        tr.appendChild(noI18n(el('td', 'mono', s.name)));
        var w = OU_STATE[s.row.state] || OU_STATE.waiting;
        var c = el('td'); c.appendChild(el('span', 'tag ' + w[1], w[0])); tr.appendChild(c);
        var b2 = el('td', 'up-how');
        var p2 = ouPercent(s.row);
        b2.appendChild(upBar(p2, s.row.state === 'failed' ? 'bad' : (s.row.state === 'done' ? 'good' : ''), num(p2) + ' %' + (s.row.state === 'updating' && s.row.phase ? ' · ' + txT(s.row.phase) : '')));
        tr.appendChild(b2);
        tr.appendChild(el('td', 'small', s.row.said || ''));
        tr.appendChild(el('td', 'muted', s.row.at ? ago(s.row.at) : '–'));
        return tr;
      }, 'plain');
      (t.querySelector('table') || t).classList.add('up-plan-table');
      pc.appendChild(t);
      if (!running) pc.appendChild(hideBar(function () { return api('osup', {action: 'hide'}).then(function (x) { OU.d = x; drawOsup(); }); }));
      host.appendChild(pc);
    }
    /* What the package manager says, a node at a time. */
    var have = nodes.filter(function (n) { return ((n.row || {}).lines || []).length || ((n.check || {}).lines || []).length; });
    if (have.length) {
      if (!OU.node || !have.some(function (n) { return n.name === OU.node; })) {
        var busyOne = have.filter(function (n) { return (n.row || {}).state === 'updating' || (n.check || {}).state === 'running'; })[0];
        OU.node = (busyOne || have[0]).name;
      }
      var lc = el('div', 'card full');
      var lh = el('h2', '', 'What it says');
      var lt = el('span', 'right');
      var hb = cmdButton(OU.hide ? 'Show it' : 'Hide it', OU.hide ? 'unfold' : 'fold', 'small');
      hb.onclick = function () { OU.hide = !OU.hide; try { localStorage.setItem('acme-ou-hide', OU.hide ? '1' : '0'); } catch (e) { /* only a convenience */ } drawOsup(); };
      var cb = cmdButton('Clear the window', 'broom', 'small');
      explain(cb, 'Empty the window of every node - for every page, and after a reload too; what comes after is shown.');
      lt.appendChild(hb); lt.appendChild(cb);
      lh.appendChild(lt);
      lc.appendChild(lh);
      if (have.length > 1) {
        var sg = el('div', 'seg');
        sg.style.marginBottom = '10px';
        have.forEach(function (n) {
          var b3 = noI18n(el('button', OU.node === n.name ? 'on' : '', n.name));
          b3.type = 'button';
          b3.onclick = function () { OU.node = n.name; OU.picked = Date.now(); drawOsup(); };
          sg.appendChild(b3);
        });
        lc.appendChild(sg);
      }
      var one = have.filter(function (n) { return n.name === OU.node; })[0];
      var lines = (one.row || {}).lines && (one.row || {}).lines.length ? one.row.lines : ((one.check || {}).lines || []);
      var from = 0;
      cb.onclick = function () {
        busy(cb, true);
        api('osup', {action: 'clear'}).then(function (x) { OU.d = x; drawOsup(); toast('the window is empty'); })
          .catch(function (e) { busy(cb, false); oops(e); });
      };
      if (!OU.hide) {
        var pre = noI18n(el('pre', 'lines ou-log', lines.slice(from).join('\n') || '–'));
        lc.appendChild(pre);
        setTimeout(function () { pre.scrollTop = pre.scrollHeight; }, 0);
      } else {
        lc.appendChild(el('p', 'muted small', 'Hidden - ' + num(lines.length) + ' line(s).'));
      }
      host.appendChild(lc);
    }
  }, live);
}

/* ---- Settings → Alerts and reports (1.0.162) ------------------------------------
   What is wrong now as the alerts see it, each node's disks, the report to look
   at or send, and the mails that went. The settings are the pane's own card. */
var AL = {d: null};
var AL_LEVEL = {bad: ['bad', 'down'], warn: ['warn', 'warning']};
function loadAlerts() {
  api('alerts').then(function (d) { AL.d = d; drawAlerts(); }).catch(oops);
}
function alAct(action, extra, b) {
  if (b) busy(b, true);
  var q = {action: action};
  Object.keys(extra || {}).forEach(function (k) { q[k] = extra[k]; });
  return api('alerts', q).then(function (x) {
    if (b) busy(b, false);
    if (x.message) toast(x.message, 'good');
    if (x.problems) { AL.d = x; drawAlerts(); }
    return x;
  }).catch(function (e) { if (b) busy(b, false); oops(e); });
}
function drawAlerts() {
  var real = $('al-host');
  if (!real || !AL.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = AL.d, probs = d.problems || [];
    if (!d.mail) host.appendChild(el('p', 'note warn', 'Sending mail is off - Settings → Mail. Neither the alerts nor the report can go until it is on.'));
    /* What is wrong now. */
    var c = el('div', 'card full');
    var h = el('h2', '', 'What is wrong now');
    var tl = el('span', 'right');
    var look = cmdButton('Look again', 'refresh', 'small');
    look.onclick = function () { alAct('check', {}, look); };
    var test = cmdButton('Send a test alert', 'mail', 'small');
    explain(test, 'A mail to the addresses below, with what is wrong now - to see that the alerts arrive and how they look.');
    test.disabled = !d.mail || !(d.to || []).length;
    test.onclick = function () { alAct('test', {}, test); };
    tl.appendChild(look); tl.appendChild(test);
    h.appendChild(tl);
    c.appendChild(h);
    if (!probs.length) {
      var ok = el('div', 'al-ok');
      ok.appendChild(el('span', 'dot ok'));
      ok.appendChild(el('span', '', 'Nothing - every node, backup, certificate, disk and clock is as it should be.'));
      c.appendChild(ok);
    } else {
      var list = el('div', 'al-list');
      probs.forEach(function (p) {
        var it = el('div', 'al-item ' + (p.level === 'bad' ? 'bad' : 'warn'));
        var top = el('div', 'al-top');
        top.appendChild(el('span', 'tag ' + (p.level === 'bad' ? 'bad' : 'warn'), p.level === 'bad' ? 'down' : 'warning'));
        top.appendChild(el('b', '', p.title));
        if (p.node) top.appendChild(noI18n(el('span', 'tag dim', p.node)));
        if (p.sent) top.appendChild(el('span', 'tag info', 'mailed'));
        it.appendChild(top);
        it.appendChild(el('div', 'al-said', p.said));
        var foot = el('div', 'al-foot muted small');
        foot.appendChild(el('span', '', p.since ? 'since ' + ago(p.since) : 'just seen'));
        if (p.pane) {
          var go = el('a', '', 'Open it →');
          go.href = '#settings/' + p.pane;
          foot.appendChild(go);
        }
        it.appendChild(foot);
        list.appendChild(it);
      });
      c.appendChild(list);
    }
    c.appendChild(el('p', 'muted small', (d.lead ? 'This node sends the alerts' : 'The other node sends the alerts') + (d.checked ? ' · looked ' + ago(d.checked) : '') + ' · ' + ((d.to || []).length ? 'to ' + d.to.join(', ') : 'no address yet')));
    host.appendChild(c);
    /* Each node's disks. */
    var grid = el('div', 'pw-grid');
    Object.keys(d.health || {}).sort().forEach(function (n) {
      var hh = d.health[n] || {};
      var nc = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (hh.at && Date.now() / 1000 - hh.at < 300 ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', n)));
      hd.appendChild(el('span', 'tag dim', 'disks'));
      nc.appendChild(hd);
      (hh.disks || []).forEach(function (dk) {
        var row = el('div', 'al-disk');
        var lab = el('div', 'al-disk-l');
        lab.appendChild(noI18n(el('span', 'mono', dk.path)));
        lab.appendChild(el('span', 'muted small', bytes(dk.free) + ' free of ' + bytes(dk.total)));
        row.appendChild(lab);
        row.appendChild(upBar(dk.pct, dk.pct >= 95 ? 'bad' : (dk.pct >= 85 ? 'warn' : 'good'), num(dk.pct) + ' %'));
        nc.appendChild(row);
      });
      if (!(hh.disks || []).length) nc.appendChild(el('p', 'muted small', 'Not heard yet.'));
      grid.appendChild(nc);
    });
    host.appendChild(grid);
    /* The report. */
    var rc = el('div', 'card full');
    rc.appendChild(el('h2', '', 'The report'));
    var r = d.report || {};
    rc.appendChild(el('p', 'note', 'The last period ended: ' + alDay(r.since) + ' – ' + alDay(r.until - 1) + (r.sent ? ' · its report went' : '') + '. ' + ((d.report_to || []).length ? 'It goes to ' + d.report_to.join(', ') + '.' : 'No address to send it to yet.')));
    var row = el('div', 'btnrow');
    var pv = cmdButton('Look at it', 'eye', '');
    explain(pv, 'The report of the last period as the mail will look, here - nothing is sent.');
    pv.onclick = function () { alPreview('last'); };
    var pn = cmdButton('So far', 'eye', '');
    explain(pn, 'The period going on now, up to this moment.');
    pn.onclick = function () { alPreview('now'); };
    var sn = cmdButton('Send it now', 'mail', 'primary');
    sn.disabled = !d.mail || !(d.report_to || []).length;
    sn.onclick = function () { confirmThen('Send the report', 'The report of the last period goes now to ' + htmlText((d.report_to || []).join(', ')) + '.', 'Send it', function () { alAct('report', {period: 'last'}, sn); }, false); };
    row.appendChild(pv); row.appendChild(pn); row.appendChild(sn);
    rc.appendChild(row);
    host.appendChild(rc);
  });
  alLog();
}
function alDay(t) { return t ? new Date(t * 1000).toLocaleDateString() : '–'; }
function alPreview(period) {
  api('alerts', {action: 'preview', period: period}).then(function (x) {
    modal(x.subject, function (body) {
      var f = el('iframe', 'al-frame');
      f.setAttribute('sandbox', '');
      f.setAttribute('title', x.subject);
      f.srcdoc = x.html;
      body.appendChild(f);
    }, [{words: 'Close', close: true}], 'al-report');
  }).catch(oops);
}
function alLog() {
  var real = $('al-log');
  if (!real || !AL.d) return;
  liveFill(real, function (host) {
    var log = AL.d.log || [];
    if (!log.length) return;
    var c = el('div', 'card full');
    var h = el('h2', '', 'Mails sent');
    var tl = el('span', 'right');
    var fg = cmdButton('Forget the list', 'forget', 'small');
    fg.onclick = function () { alAct('forget', {}, fg); };
    tl.appendChild(fg); h.appendChild(tl);
    c.appendChild(h);
    var KIND = {alert: ['alert', 'warn'], report: ['report', 'info'], test: ['test', 'dim']};
    c.appendChild(listTable(['When', 'What', 'Subject', 'To', ''], log, function (e) {
      var tr = el('tr');
      tr.appendChild(el('td', 'muted', ago(e.at)));
      var k = KIND[e.kind] || ['mail', 'dim'];
      var t = el('td'); t.appendChild(el('span', 'tag ' + k[1], k[0])); tr.appendChild(t);
      tr.appendChild(noI18n(el('td', 'small', e.subject || '')));
      tr.appendChild(noI18n(el('td', 'small', (e.to || []).join(', '))));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (e.ok ? 'good' : (e.queued === 'waiting' ? 'warn' : 'bad')), e.ok ? 'sent' : (e.queued === 'waiting' ? 'waiting' : 'not sent')));
      if (!e.ok && e.said) explain(st, e.said);
      tr.appendChild(st);
      return tr;
    }, 'plain'));
    host.appendChild(c);
  });
}

/* ---- Settings → SSH server and notices (1.0.163) --------------------------------
   One wish for the cluster, each node putting it in by itself and saying what
   sshd makes of it; a change on trial until Keep it. Saved with the bar at
   the bottom, as the time servers are. */
var SD = {d: null, draft: null, poll: null};
var SD_STATE = {done: ['as wished', 'good'], trial: ['on trial', 'warn'], waiting: ['being put in', 'info'],
                failed: ['refused', 'bad'], back: ['went back', 'warn']};
function loadSshd() {
  api('sshd').then(function (d) {
    SD.d = d;
    if (!SD.draft) SD.draft = JSON.parse(JSON.stringify(d.conf));
    drawSshd();
    sdPoll(sdBusy(d));
  }).catch(oops);
}
function sdBusy(d) { return (d.nodes || []).some(function (n) { return n.state === 'waiting' || n.state === 'trial'; }); }
function sdPoll(on) {
  if (on && !SD.poll) {
    SD.poll = setInterval(function () {
      if (TAB !== 'settings' || PANE !== 'sshd') { sdPoll(false); return; }
      api('sshd').then(function (d) { SD.d = d; drawSshd(true); if (!sdBusy(d)) sdPoll(false); }).catch(function () {});
    }, 3000);
  }
  if (!on && SD.poll) { clearInterval(SD.poll); SD.poll = null; }
}
function sdDirty() {
  pendingSet('sshd', {pane: 'sshd', save: sdSave, reset: function () {
    SD.draft = JSON.parse(JSON.stringify(SD.d.conf)); drawSshd();
  }});
}
function sdSave() {
  var dr = SD.draft;
  return api('sshd', {action: 'save', conf: dr}).then(function (r) {
    toast(r.message, 'good'); SD.d = r; SD.draft = JSON.parse(JSON.stringify(r.conf)); drawSshd(); sdPoll(true); return true;
  });
}
function sdAct(action, b) {
  if (b) busy(b, true);
  api('sshd', {action: action}).then(function (r) { toast(r.message, 'good'); SD.d = r; drawSshd(); sdPoll(true); })
    .catch(function (e) { if (b) busy(b, false); oops(e); });
}
function drawSshd(live) {
  var real = $('sd-host');
  if (!real || !SD.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = SD.d, dr = SD.draft, nodes = d.nodes || [];
    if (!d.helper) host.appendChild(el('p', 'note bad', 'The root helper of this node is not installed (install.sh --upgrade puts it in).'));
    /* On trial: keep it, or put it back. */
    var trial = nodes.filter(function (n) { return n.state === 'trial'; });
    if (trial.length) {
      var tc = el('div', 'card full notice warn sd-trial');
      tc.appendChild(el('h2', '', 'On trial - keep it, or it goes back'));
      var until = Math.min.apply(null, trial.map(function (n) { return (n.now.trial || {}).until || 0; }));
      tc.appendChild(el('p', 'note', 'Open a new SSH session to ' + trial.map(function (n) { return n.name; }).join(' and ') + ' now, with the port and the way of signing in as set, and keep the one you have open. Works: Keep it. Unless kept, each node puts back what it had in ' + span(Math.max(0, Math.round(until - Date.now() / 1000))) + '.'));
      var row = el('div', 'btnrow');
      var kp = cmdButton('Keep it', 'check', 'primary');
      kp.onclick = function () { sdAct('keep', kp); };
      var bk = cmdButton('Put it back now', 'undo', '');
      bk.onclick = function () { confirmThen('Put the SSH server back', 'Each node on trial puts back what it had before the change.', 'Put it back', function () { sdAct('back', bk); }, false); };
      row.appendChild(kp); row.appendChild(bk);
      tc.appendChild(row);
      host.appendChild(tc);
    }
    /* Each node, as sshd has it. */
    var grid = el('div', 'pw-grid');
    nodes.forEach(function (n) {
      var c = el('div', 'card pw-node');
      var hd = el('div', 'pw-head');
      hd.appendChild(el('span', 'dot ' + (n.alive ? 'ok' : 'bad')));
      hd.appendChild(noI18n(el('b', '', n.name)));
      if (n.me) hd.appendChild(el('span', 'tag info', 'this page'));
      var w = SD_STATE[n.state] || SD_STATE.done;
      if (d.conf.hash) hd.appendChild(el('span', 'tag ' + w[1], w[0]));
      c.appendChild(hd);
      var v = (n.now || {}).values || {};
      c.appendChild(netFacts([
        ['Port', v.port || '', true],
        ['Root may sign in', v.permitrootlogin ? ({'without-password': 'with a key only', 'prohibit-password': 'with a key only', 'yes': 'yes', 'no': 'no'})[v.permitrootlogin] || v.permitrootlogin : (n.now.there === false ? 'sshd is not here' : '')],
        ['Passwords', v.passwordauthentication || ''],
        ['Tries a connection', v.maxauthtries || '', true],
        ['Who may sign in', v.allowusers || 'everybody'],
        ['Keys of root', String(n.keys)],
        ['SELinux', (n.now || {}).selinux || '–', true],
        ['Read', n.now.at ? ago(n.now.at) : 'not yet']
      ]));
      if (n.now.error) c.appendChild(el('p', 'note bad', n.now.error));
      if (n.now.dropins === false) c.appendChild(el('p', 'note warn', 'This sshd does not read sshd_config.d - acme cannot set it here.'));
      grid.appendChild(c);
    });
    host.appendChild(grid);
    /* The wish. */
    var fc = el('div', 'card full');
    fc.appendChild(el('h2', '', 'The SSH server'));
    var sw = switchBox(dr.manage);
    sw._input.onchange = function () { dr.manage = !!sw._get(); sdDirty(); drawSshd(); };
    fc.appendChild(formField('acme sets the SSH server', sw, 'Off: each node keeps sshd as the system has it, and acme\'s file is taken away.'));
    var g = el('div', 'formgrid sd-grid' + (dr.manage ? '' : ' off'));
    var seg = el('div', 'seg');
    [['prohibit-password', 'With a key only'], ['yes', 'With a key or a password'], ['no', 'Not at all']].forEach(function (o) {
      var b = el('button', dr.permit_root === o[0] ? 'on' : '', o[1]);
      if (hsOn('sshd:root') && o[0] === 'yes') { b.disabled = true; b.title = 'not under high security'; }
      b.type = 'button'; b.disabled = !dr.manage;
      b.onclick = function () { dr.permit_root = o[0]; sdDirty(); drawSshd(); };
      seg.appendChild(b);
    });
    g.appendChild(formField('Root signs in', seg));
    var pw = switchBox(dr.password);
    pw._input.disabled = !dr.manage || (hsOn('sshd:password') && !dr.password);
    pw._input.onchange = function () { dr.password = !!pw._get(); sdDirty(); drawSshd(); };
    g.appendChild(formField('Passwords', pw, 'Off: only keys sign in, for everybody.'));
    var port = textBox(String(dr.port || 22), '22', 'mono');
    port.disabled = !dr.manage;
    port.oninput = function () { dr.port = parseInt(port.value, 10) || 22; sdDirty(); };
    g.appendChild(formField('Port', port, 'Another than 22: the firewall lets it in by itself, the old one too while it is on trial.'));
    var tries = textBox(String(dr.tries || 4), '4', 'mono');
    tries.disabled = !dr.manage;
    tries.oninput = function () { dr.tries = parseInt(tries.value, 10) || 4; sdDirty(); };
    g.appendChild(formField('Tries a connection', tries, 'Wrong passwords or keys before sshd closes it (MaxAuthTries).'));
    var au = textBox((dr.allow_users || []).join(' '), 'root admin', 'mono');
    au.disabled = !dr.manage;
    au.oninput = function () { dr.allow_users = au.value.split(/[\s,]+/).filter(Boolean); sdDirty(); };
    g.appendChild(formField('Who may sign in', au, 'The accounts, separated by spaces (AllowUsers). Empty: everybody.'));
    var tm = textBox(String(dr.trial_min === undefined ? 5 : dr.trial_min), '5', 'mono');
    tm.disabled = !dr.manage;
    tm.oninput = function () { dr.trial_min = Math.max(0, parseInt(tm.value, 10) || 0); sdDirty(); };
    g.appendChild(formField('On trial for (min)', tm, 'Unless kept within this, each node puts back what it had. 0: no trial - not advised.'));
    fc.appendChild(g);
    var none = nodes.filter(function (n) { return !n.keys; }).map(function (n) { return n.name; });
    if (dr.manage && none.length && (dr.permit_root === 'prohibit-password' || !dr.password))
      fc.appendChild(el('p', 'note bad', 'Root has no key on ' + none.join(', ') + ' - add one on SSH keys of root first, or this is refused there.'));
    if (dr.manage && !dr.password && dr.permit_root === 'yes')
      fc.appendChild(el('p', 'note', 'Passwords off: root signs in with a key either way.'));
    host.appendChild(fc);
    /* The notice. */
    var nc = el('div', 'card full');
    nc.appendChild(el('h2', '', 'The notice'));
    var ta = noI18n(el('textarea', 'mono sd-notice'));
    ta.rows = 6; ta.value = dr.notice || ''; ta.placeholder = 'Authorised use only. Every connection is logged.';
    ta.oninput = function () { dr.notice = ta.value; sdDirty(); };
    nc.appendChild(formField('Its words', ta, 'Plain text, as many lines as needed - often what the security policy wants said.'));
    var wh = el('div', 'sd-where');
    [['notice_ssh', 'Before signing in over SSH', 'sshd\'s Banner - needs acme to set the SSH server'], ['notice_console', 'At the console', '/etc/issue'], ['notice_motd', 'After signing in', 'the message of the day']].forEach(function (o) {
      var lab = el('label', 'chk');
      var cb = el('input'); cb.type = 'checkbox'; cb.checked = !!dr[o[0]];
      cb.disabled = o[0] === 'notice_ssh' && !dr.manage;
      cb.onchange = function () { dr[o[0]] = cb.checked; sdDirty(); };
      lab.appendChild(cb); lab.appendChild(el('span', '', o[1]));
      lab.appendChild(el('span', 'muted small', o[2]));
      wh.appendChild(lab);
    });
    nc.appendChild(wh);
    nc.appendChild(el('p', 'muted small', 'Saved with the bar at the bottom; each node then puts it in by itself within seconds.'));
    host.appendChild(nc);
  }, live);
}

/* ---- Settings → Syslog and SIEM, Proxy, Disks and logs (1.0.166) ----------------
   Each node's own state; the settings are the pane's own card. */
var SI = {d: null, said: {}};
function loadSiem() {
  api('siem').then(function (d) { SI.d = d; drawSiem(); }).catch(oops);
}
function drawSiem() {
  var real = $('si-host');
  if (!real || !SI.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = SI.d;
    if (!d.on) host.appendChild(el('p', 'note', 'Sending is off - switch it on below and say where to.'));
    var grid = nodeGrid();
    (d.nodes || []).forEach(function (n) {
      var trouble = Object.keys(n.trouble || {});
      var fresh = nodeFresh(n), on = n.on && (n.targets || []).length;
      var c = nodeCard(n, !fresh ? 'bad' : (!on ? 'dim' : (trouble.length ? 'warn' : 'ok')),
        !fresh ? 'not heard from' : (!n.on ? 'off' : (!(n.targets || []).length ? 'nowhere to send' : (trouble.length ? 'trouble' : 'sending'))),
        !fresh ? 'crit' : (!on ? 'dim' : (trouble.length ? 'warn' : 'ok')));
      var total = 0;
      Object.keys(n.sent || {}).forEach(function (k) { total += n.sent[k]; });
      nodeBig(c, num(total), 'line(s) sent since it started');
      c.appendChild(netFacts([
        ['Written as', n.host || '', true], ['In the shape of', (n.format || '').toUpperCase(), true],
        ['Last sent', n.last_sent ? ago(n.last_sent) : 'never'], ['Waiting to go', num(n.queued || 0)],
        ['Dropped, the queue full', num(n.dropped || 0)], ['Read', n.at ? ago(n.at) : '']
      ]));
      (n.targets || []).forEach(function (t) {
        var row = el('div', 'si-row');
        row.appendChild(el('span', 'dot ' + ((n.trouble || {})[t] ? 'bad' : ((n.sent || {})[t] ? 'ok' : 'dim'))));
        row.appendChild(noI18n(el('span', 'mono', t)));
        row.appendChild(el('span', 'muted small', num((n.sent || {})[t] || 0) + ' sent'));
        c.appendChild(row);
        if ((n.trouble || {})[t]) c.appendChild(noI18n(el('div', 'si-said small', n.trouble[t])));
      });
      if (!(n.targets || []).length && fresh) c.appendChild(el('p', 'muted small', 'Nowhere to send to.'));
      var said = SI.said[n.node];
      if (said) {
        var bad = Object.keys(said.test || {}).filter(function (k) { return said.test[k] !== 'sent'; });
        c.appendChild(nodeSaid(said, said.ok ? 'The test line went to every server' : 'Not to ' + bad.join(', ')));
      }
      var row2 = el('div', 'btnrow');
      var look = cmdButton('Look again', 'refresh', 'small');
      look.onclick = function () { loadSiem(); };
      var test = cmdButton('Send a test line', 'play', 'small');
      explain(test, 'One line from ' + n.node + ' to every server, now - to see it arrive and how it reads.');
      test.disabled = !d.on || !fresh;
      test.onclick = function () {
        busy(test, true);
        askNodes('siem', {action: 'test', node: n.node}, function (node, got) {
          SI.said[node] = got;
          if (got.state) d.nodes.forEach(function (x) { if (x.node === node) Object.assign(x, got.state, {at: Date.now() / 1000}); });
        }, function () { busy(test, false); drawSiem(); }).catch(function (e) { busy(test, false); oops(e); });
      };
      row2.appendChild(look); row2.appendChild(test);
      c.appendChild(row2);
      grid.appendChild(c);
    });
    host.appendChild(grid);
  });
}

var PX = {poll: null};
function drawProxy() {
  var host = $('px-host');
  if (!host) return;
  clear(host);
  var c = el('div', 'card full');
  c.appendChild(el('h2', '', 'Try it'));
  c.appendChild(el('p', 'note', 'An address asked from this node the way acme asks the web: through the proxy as it is saved, or straight where none is set or the address is in the list. Each step is shown. Empty: where the new versions are looked for.'));
  var row = el('div', 'btnrow');
  var url = el('input');
  url.type = 'text';
  url.placeholder = 'https://github.com/';
  url.style.flex = '1';
  url.style.minWidth = '260px';
  var go = cmdButton('Try it', 'play', 'primary');
  var said = el('div', 'px-out');
  /* Tried on every node (1.0.169): each node's card fills in as it answers. */
  go.onclick = function () {
    busy(go, true);
    clear(said);
    if (PX.poll) { clearInterval(PX.poll); PX.poll = null; }
    api('proxy', {action: 'try', url: url.value.trim()}).then(function (x) {
      var nodes = x.nodes || [];
      var cards = {};
      var grid = nodeGrid();
      nodes.forEach(function (n) {
        var cd = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, 'dim', 'being tried', 'info');
        var body = el('div', 'px-out');
        body.appendChild(pxPath(null, n));
        cd.appendChild(body);
        grid.appendChild(cd);
        cards[n] = {body: body, done: false, card: cd};
      });
      said.appendChild(grid);
      var began = Date.now();
      var look = function () {
        api('proxy', {action: 'result', id: x.id}).then(function (r) {
          var left = 0;
          nodes.forEach(function (n) {
            var got = (r.nodes || {})[n];
            if (cards[n].done) return;
            if (!got) { left++; return; }
            cards[n].done = true;
            var hd = cards[n].card.querySelector('.pw-head');
            hd.querySelector('.dot').className = 'dot ' + (got.ok ? 'ok' : 'bad');
            var tg = hd.querySelector('.tag:last-child');
            hd.replaceChild(el('span', 'tag ' + (got.ok ? 'ok' : 'crit'), got.ok ? (got.mode === 'proxy' ? 'through the proxy' : 'straight') : 'not reached'), tg);
            clear(cards[n].body);
            if (got.error) { cards[n].body.appendChild(el('p', 'note bad', got.error)); return; }
            cards[n].body.appendChild(pxPath(got));
            cards[n].body.appendChild(pxSteps(got));
          });
          if (!left || Date.now() - began > 60000) {
            clearInterval(PX.poll); PX.poll = null; busy(go, false);
            nodes.forEach(function (n) {
              if (!cards[n].done) { clear(cards[n].body); cards[n].body.appendChild(el('p', 'note warn', 'This node did not answer in a minute - is it running?')); }
            });
          }
        }).catch(function () {
          /* Every answer failing: the minute ends it too (1.0.208). */
          if (Date.now() - began > 60000) {
            clearInterval(PX.poll); PX.poll = null; busy(go, false);
            nodes.forEach(function (n) {
              if (!cards[n].done) { clear(cards[n].body); cards[n].body.appendChild(el('p', 'note warn', 'This node did not answer in a minute - is it running?')); }
            });
          }
        });
      };
      PX.poll = setInterval(look, 1000);
      setTimeout(look, 300);
    }).catch(function (e) { busy(go, false); oops(e); });
  };
  url.addEventListener('keydown', function (e) { if (e.key === 'Enter') go.click(); });
  row.appendChild(url); row.appendChild(go);
  c.appendChild(row);
  c.appendChild(said);
  host.appendChild(c);
}
/* The way it went, drawn: this node, the proxy (when it went through one),
   the address - each link green, red, or still being tried. */
function pxPath(x, nodeName) {
  var box = el('div', 'px-path' + (x ? (x.ok ? ' ok' : ' bad') : ' going'));
  var steps = (x && x.steps) || [];
  var failAt = steps.filter(function (s) { return !s.ok; })[0];
  var stop = function (icon, title, sub, cls) {
    var n = el('div', 'px-stop ' + (cls || ''));
    var ic = el('span', 'px-ic');
    ic.innerHTML = iconMarkup(icon, 22);
    n.appendChild(ic);
    n.appendChild(noI18n(el('b', 'mono', title)));
    if (sub) n.appendChild(el('span', 'muted small', sub));
    return n;
  };
  var link = function (state, words) {
    var l = el('div', 'px-link ' + state);
    l.appendChild(el('span', 'px-wire'));
    if (words) l.appendChild(el('span', 'px-lw small', words));
    return l;
  };
  if (!x) {
    box.appendChild(stop('router', nodeName || (STATUS && STATUS.node) || 'acme', 'the node', 'me'));
    box.appendChild(link('going', 'trying…'));
    box.appendChild(stop('globe', '…', '', ''));
    return box;
  }
  var reached = function (re) { return steps.some(function (s) { return s.ok && re.test(s.what); }); };
  box.appendChild(stop('router', x.node, 'the node', 'me'));
  if (x.mode === 'proxy') {
    var toProxy = reached(/^connected to the proxy/) ? 'ok' : 'bad';
    box.appendChild(link(toProxy, toProxy === 'ok' ? 'connected' : 'not reached'));
    box.appendChild(stop('wall', x.proxy, x.proxy_auth ? 'the proxy · with a password' : 'the proxy', toProxy === 'ok' ? 'good' : 'bad'));
    var through = x.ok ? 'ok' : (toProxy === 'ok' ? 'bad' : 'off');
    box.appendChild(link(through, through === 'ok' ? 'through the proxy' : (through === 'bad' ? 'stopped here' : '')));
  } else {
    var st = x.ok ? 'ok' : 'bad';
    box.appendChild(link(st, 'straight'));
  }
  box.appendChild(stop(x.tls ? 'lock' : 'globe', x.host + ':' + x.port, x.tls ? x.tls.version + ' · ' + (x.tls.issuer || '') : '', x.ok ? 'good' : 'bad'));
  var top = el('div', 'px-verdict ' + (x.ok ? 'ok' : 'bad'));
  top.appendChild(el('span', 'dot ' + (x.ok ? 'ok' : 'bad')));
  var words = x.ok
    ? (x.mode === 'proxy' ? 'Reached through the proxy' : 'Reached straight') + ' - HTTP ' + x.status + ', ' + x.ms + ' ms'
    : 'Not reached: ' + ((failAt && failAt.said) || '?');
  top.appendChild(el('b', '', words));
  if (x.mode === 'direct' && x.why_direct) top.appendChild(el('span', 'muted small', 'straight because ' + x.why_direct));
  var wrap = el('div', 'px-result');
  wrap.appendChild(top);
  wrap.appendChild(box);
  return wrap;
}
function pxSteps(x) {
  var ul = el('div', 'px-steps');
  var plan = x.mode === 'proxy'
    ? ['the proxy looked up', 'connected to the proxy'].concat(/^https/.test(x.url) ? ['a tunnel through the proxy', 'TLS'] : []).concat(['asked for'])
    : ['looked up', 'connected to'].concat(/^https/.test(x.url) ? ['TLS'] : []).concat(['asked for']);
  var done = x.steps || [];
  done.forEach(function (s) {
    var r = el('div', 'px-step ' + (s.ok ? 'ok' : 'bad'));
    r.appendChild(el('span', 'px-n', s.ok ? '✓' : '✗'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', s.what));
    if (s.said) t.appendChild(noI18n(el('div', 'muted small mono', s.said)));
    r.appendChild(t);
    r.appendChild(el('span', 'px-ms small muted', s.ms + ' ms'));
    ul.appendChild(r);
  });
  for (var i = done.length; i < plan.length; i++) {
    var r = el('div', 'px-step off');
    r.appendChild(el('span', 'px-n', '○'));
    var t = el('div', 'px-st');
    t.appendChild(el('b', '', 'not tried - the step before stopped it'));
    r.appendChild(t);
    ul.appendChild(r);
  }
  return ul;
}

var LG = {d: null};
function loadLogs() {
  api('logs').then(function (d) { LG.d = d; drawLogs(); }).catch(oops);
}
function drawLogs() {
  var real = $('lg-host');
  if (!real || !LG.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = LG.d;
    var grid = nodeGrid();
    (d.nodes || []).forEach(function (n) {
      var state = !n.at ? ['dim', 'not asked yet', 'dim'] : (n.ok && n.current ? ['ok', 'as set', 'ok'] : (n.ok ? ['warn', 'being put in', 'warn'] : ['bad', 'failed', 'crit']));
      var c = nodeCard(n, state[0], state[1], state[2]);
      var lim = d.disk_pct || 85;
      var worst = (n.disks || []).reduce(function (m, dk) { return Math.max(m, dk.pct || 0); }, 0);
      nodeBig(c, num(worst) + ' %', 'the fullest disk');
      (n.disks || []).forEach(function (dk) {
        var row = el('div', 'al-disk');
        var lab = el('div', 'al-disk-l');
        lab.appendChild(noI18n(el('span', 'mono', dk.path)));
        lab.appendChild(el('span', 'muted small', bytes(dk.free) + ' free of ' + bytes(dk.total)));
        row.appendChild(lab);
        row.appendChild(upBar(dk.pct, dk.pct >= 95 ? 'bad' : (dk.pct >= lim ? 'warn' : 'good'), num(dk.pct) + ' %'));
        c.appendChild(row);
      });
      c.appendChild(netFacts([
        ['The system journal', n.journal_use == null ? '' : bytes(n.journal_use)],
        ['acme’s logs', n.logdir == null ? '' : bytes(n.logdir)],
        ['acme’s data', n.state == null ? '' : bytes(n.state)],
        ['Asked', n.at ? ago(n.at) : '']
      ]));
      if (n.said && !n.ok) c.appendChild(noI18n(el('div', 'si-said small', n.said)));
      var row2 = el('div', 'btnrow');
      var again = cmdButton('Put in and look again', 'refresh', 'small');
      explain(again, 'Every node puts the settings below in again and says how much its journal and logs take - the one this page is on at once, the other within a minute.');
      again.onclick = function () {
        busy(again, true);
        api('logs', {action: 'refresh'}).then(function (x) { busy(again, false); LG.d = x; drawLogs(); toast('Asked of every node', 'good'); })
          .catch(function (e) { busy(again, false); oops(e); });
      };
      row2.appendChild(again);
      c.appendChild(row2);
      grid.appendChild(c);
    });
    host.appendChild(grid);
  });
}

/* Settings → High security (1.0.168): what stands against it now, and what is advised. */
function loadHisec() {
  api('hisec').then(function (d) { drawHisec(d); }).catch(oops);
}
function drawHisec(d) {
  var host = $('hs-host');
  if (!host) return;
  clear(host);
  var c = el('div', 'card full');
  var h = el('h2', '', d.on ? 'High security is on' : 'High security is off');
  var tl = el('span', 'right');
  var look = cmdButton('Look again', 'refresh', 'small');
  look.onclick = function () { loadHisec(); };
  tl.appendChild(look);
  h.appendChild(tl);
  c.appendChild(h);
  var block = d.block || [], waived = d.waived || [], rules = d.rules || [];
  var top = el('div', 'al-ok');
  top.appendChild(el('span', 'dot ' + (block.length ? 'bad' : 'ok')));
  top.appendChild(el('span', '', block.length
    ? (d.on ? num(block.length) + ' thing(s) are not as high security wants them - set before it was on, or on a node: put them right.'
            : num(block.length) + ' thing(s) stand against switching it on.')
    : (d.on ? 'Everything is as high security wants it.' : 'Nothing stands against it - it can be switched on below.')));
  c.appendChild(top);
  if (waived.length) c.appendChild(el('p', 'muted small', num(waived.length) + ' exception(s): not enforced.'));
  hsList(c, block, 'bad', 'Stands against it', drawHisec);
  hsList(c, waived, 'waived', 'Exceptions - not enforced', drawHisec);
  var kept = rules.filter(function (r) { return !r.bad && !r.waived; });
  if (kept.length) {
    var det = el('details', 'hs-kept');
    det.appendChild(el('summary', '', 'Kept as high security wants it (' + num(kept.length) + ')'));
    hsList(det, kept, 'ok', '', drawHisec);
    c.appendChild(det);
  }
  host.appendChild(c);
  if ((d.warn || []).length) {
    var k = el('div', 'card full');
    k.appendChild(el('h2', '', 'The security check'));
    k.appendChild(el('p', 'note', 'What is not as it should be now - it does not stop high security.'));
    hsList(k, d.warn, 'warn', '', drawHisec);
    host.appendChild(k);
  }
}

/* ---- Settings → Automatic certificates (1.0.169) -------------------------------
   One card a certificate - the VIP address's, each node's - who orders it, what
   it has now, the last try; port 80 tried as the CA will try it. */
var AC = {d: null, probe: {}, poll: null};
function loadAcme() {
  api('acme').then(function (d) { AC.d = d; drawAcme(); acPoll(d.work && d.work.busy); }).catch(oops);
}
function acPoll(on) {
  if (on && !AC.poll) AC.poll = setInterval(function () {
    if (TAB !== 'settings' || PANE !== 'acme') { acPoll(false); return; }
    api('acme').then(function (d) { AC.d = d; drawAcme(); if (!(d.work && d.work.busy)) acPoll(false); }).catch(function () {});
  }, 2000);
  if (!on && AC.poll) { clearInterval(AC.poll); AC.poll = null; }
}
/* Which certificates to order now (1.0.200): each with a switch of its own, all on
   to begin with, and ordered one after another. */
function acmeOrderPick(all) {
  var boxes = [];
  modal('Order certificates now', function (body) {
    body.appendChild(el('p', 'note', 'The ones switched on are ordered from the CA now, one after another; ACME renews each from then on.'));
    var list = el('div', 'ac-pick');
    all.forEach(function (t) {
      var row = el('div', 'me-row ac-pick-row');
      var say = el('div', 'me-say');
      var top = el('div', '');
      top.appendChild(el('b', '', t.target === 'vip' ? 'the VIP address' : ''));
      if (t.target !== 'vip') top.appendChild(noI18n(el('b', '', t.target)));
      top.appendChild(noI18n(el('span', 'mono muted', '  ' + t.name)));
      say.appendChild(top);
      var left = t.not_after ? Math.floor((t.not_after - Date.now() / 1000) / 86400) : null;
      var st = t.state || {};
      say.appendChild(el('div', 'small muted', t.how === 'ACME'
        ? (st.ok === false ? 'from the CA - the last try failed' : 'from the CA') + (left !== null ? ' · ' + left + ' days left' : '')
        : (t.how ? 'put in on Certificates and TLS - the one from the CA takes its place' : 'none yet')));
      row.appendChild(say);
      var sw = el('label', 'sw');
      var box = el('input');
      box.type = 'checkbox';
      box.checked = true;
      box.setAttribute('aria-label', t.name);
      box._target = t.target;
      boxes.push(box);
      sw.appendChild(box);
      sw.appendChild(el('span', 'knob'));
      row.appendChild(sw);
      list.appendChild(row);
    });
    body.appendChild(list);
  }, [{words: 'No, leave it', close: true},
      {words: 'Order the ones switched on', cls: 'primary', go: function (button) {
        var targets = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b._target; });
        if (!targets.length) { toast('none is switched on', 'bad'); return; }
        busy(button, true);
        api('acme', {action: 'order_all', targets: targets}).then(function (x) {
          closeModal(); toast(x.message, 'good'); AC.d = x; drawAcme(); acPoll(true);
        }).catch(function (e) { busy(button, false); oops(e); });
      }}], true);
}
function drawAcme() {
  var real = $('ac-host');
  if (!real || !AC.d) return;
  liveLetGo(real);
  liveFill(real, function (host) {
    var d = AC.d;
    if (!d.on) host.appendChild(el('p', 'note', 'Off - switch it on below, say which certificates and the CA, and save.'));
    var each = (d.work && d.work.each) || {};
    if (d.work && d.work.busy && Object.keys(each).length > 1) {
      /* Side by side (1.0.203): how many, and each one's words on its own card. */
      var gs = el('div', 'going wide');
      gs.innerHTML = '<div class="bar"><span style="width:60%"></span></div>';
      var ws = el('div', 'says');
      ws.appendChild(el('span', '', Object.keys(each).length + ' certificates being ordered side by side'));
      if (d.work.of > 1) ws.appendChild(el('span', 'muted', ' (' + d.work.done + ' of ' + d.work.of + ' done)'));
      gs.appendChild(ws);
      host.appendChild(gs);
    } else if (d.work && d.work.busy) {
      var g = el('div', 'going wide');
      g.innerHTML = '<div class="bar"><span style="width:60%"></span></div>';
      /* Which certificate, and what is being waited for now (1.0.176). */
      var w = el('div', 'says');
      if (d.work.target) {
        w.appendChild(el('b', '', d.work.target === 'vip' ? 'the VIP address' : d.work.target));
        w.appendChild(document.createTextNode(': '));
      }
      w.appendChild(el('span', '', d.work.says || 'ordering…'));
      if (d.work.of > 1) w.appendChild(el('span', 'muted', ' (' + d.work.n + ' of ' + d.work.of + ')'));
      g.appendChild(w);
      host.appendChild(g);
    }
    /* Every certificate at once (1.0.200): one after another, as Order it now on
       each card - after the account changed, say, or a new CA. */
    var all = (d.targets || []).filter(function (t) { return t.wanted && t.name; });
    if (d.on && all.length > 1) {
      var ar = el('div', 'btnrow ac-all');
      var oa = cmdButton('Order certificates now…', 'download', 'small primary');
      oa.disabled = !!(d.work && d.work.busy);
      explain(oa, 'Several at once: choose which of them - ' + all.map(function (t) { return t.name; }).join(', ')
        + ' - and they are ordered from the CA one after another. ACME renews each from then on.');
      oa.onclick = function () { acmeOrderPick(all); };
      ar.appendChild(oa);
      host.appendChild(ar);
    }
    /* By hand (DNS-01): the record to put in, and the order waiting for it. */
    if (d.manual) {
      var mc = el('div', 'card full ac-manual');
      mc.appendChild(el('h2', '', 'Put this TXT record in DNS'));
      mc.appendChild(el('p', 'note warn', 'The order waits for it - up to an hour. Put it in, wait until DNS carries it, then say so. Take it away again once the certificate has come.'));
      mc.appendChild(netFacts([['Name', d.manual.rr, true], ['Type', 'TXT', true], ['Value', d.manual.txt, true], ['TTL', '60', true]]));
      var mr = el('div', 'btnrow');
      var cp = cmdButton('Copy the value', 'copy', 'small');
      cp.onclick = function () { copyText(d.manual.txt); };
      var dn = cmdButton('It is in DNS', 'check', 'small primary');
      dn.disabled = !!d.manual.done;
      dn.onclick = function () { api('acme', {action: 'manual_done'}).then(function (x) { AC.d = x; drawAcme(); acPoll(true); }).catch(oops); };
      var gv = cmdButton('Give the order up', 'close', 'small');
      gv.onclick = function () { api('acme', {action: 'manual_drop'}).then(function (x) { AC.d = x; drawAcme(); }).catch(oops); };
      mr.appendChild(cp); mr.appendChild(dn); mr.appendChild(gv);
      mc.appendChild(mr);
      host.appendChild(mc);
    }
    var grid = nodeGrid();
    (d.targets || []).forEach(function (t) {
      var st = t.state || {};
      var left = t.not_after ? Math.floor((t.not_after - Date.now() / 1000) / 86400) : null;
      var acme = t.how === 'ACME';
      var dot = !acme ? 'dim' : (st.ok === false ? 'warn' : (left !== null && left < 14 ? 'warn' : 'ok'));
      var c = nodeCard({node: t.target === 'vip' ? 'the VIP address' : t.target, me: t.target === d.node}, dot,
        acme ? (st.ok === false ? 'the last try failed' : 'from the CA') : (t.how ? 'not from the CA' : 'no certificate'),
        acme ? (st.ok === false ? 'warn' : 'ok') : 'dim');
      /* Who looks after it (1.0.170): ACME, or the certificate put in on
         Certificates and TLS is kept as it is. */
      var care = el('span', 'tag ' + (t.care && t.wanted ? 'info' : 'dim'),
        !t.wanted ? 'not asked for' : (t.care ? 'ACME renews it' : 'its own certificate is kept'));
      explain(care, !t.wanted ? 'For (Settings below) does not take this one in.'
        : (t.care ? 'Renewed by ACME before it runs out. A certificate put in by hand on Certificates and TLS takes it out of ACME’s care.'
          : 'The certificate put in on Certificates and TLS (uploaded, from a request, self-signed) stays: ACME does not replace it. Look after it, or Order it now, gives it to ACME.'));
      c.querySelector('.pw-head') ? c.querySelector('.pw-head').appendChild(care) : c.appendChild(care);
      nodeBig(c, left !== null ? num(left) : '–', left !== null ? 'days left' : '');
      c.appendChild(netFacts([
        ['For', t.name || '', true], ['Issued by', t.issuer || '', true], ['Keys', t.keys || '', true],
        ['Good until', t.not_after ? new Date(t.not_after * 1000).toLocaleDateString(numLang()) : ''],
        ['Last ordered', st.ordered_at ? ago(st.ordered_at) : 'never'],
        ['Ordered by', t.target === 'vip' ? 'the first node by name' : t.target]
      ]));
      /* Its own order under way (1.0.203), what it waits for now. */
      if (each[t.target]) {
        var gc = el('div', 'going ac-going');
        gc.innerHTML = '<div class="bar"><span style="width:60%"></span></div>';
        gc.appendChild(el('div', 'says small', each[t.target].says || 'ordering…'));
        c.appendChild(gc);
      }
      if (st.ok === false && st.said && !each[t.target]) c.appendChild(nodeSaid({ok: false, error: st.said, at: st.failed_at}, ''));
      /* What the last order did, step by step (1.0.175). */
      if ((st.steps || []).length) {
        var det = el('details', 'acme-steps-done');
        det.appendChild(el('summary', 'small muted', 'What the last order did'));
        var t0 = st.steps[0][0];
        st.steps.forEach(function (x) {
          /* The time in a column of its own, never broken; the step beside it,
             from the left (1.0.196 - the time took the room and broke in two). */
          var r = el('div', 'acme-step small');
          r.appendChild(noI18n(el('span', 'muted mono acme-step-t', '+' + Math.round(x[0] - t0) + ' s')));
          r.appendChild(el('span', 'acme-step-w', x[1]));
          det.appendChild(r);
        });
        c.appendChild(det);
      }
      var pr = AC.probe[t.target];
      if (pr) c.appendChild(nodeSaid({ok: pr.ok, at: pr.at, error: pr.ok ? '' : pr.said}, 'Port 80 answers as the CA will ask it'));
      var row = el('div', 'btnrow');
      var probe = cmdButton('Try port 80', 'play', 'small');
      probe.hidden = d.challenge === 'dns-01';
      explain(probe, t.name ? 'http://' + t.name + '/.well-known/acme-challenge/ asked from this node, as the CA will ask it - whether it reaches acme. A firewall in front of the servers may still stop the CA from outside.'
        : 'The name of this certificate is not known yet: give it in Settings below (This node’s DNS name, on that node) - or wait until that node says its own full name.');
      probe.disabled = !t.name;
      probe.onclick = function () {
        busy(probe, true);
        api('acme', {action: 'probe', target: t.target}).then(function (x) {
          busy(probe, false); x.at = Date.now() / 1000; AC.probe[t.target] = x; drawAcme();
        }).catch(function (e) { busy(probe, false); oops(e); });
      };
      var order = cmdButton('Order it now', 'download', 'small primary');
      order.disabled = !d.on || !t.name || (d.work && d.work.busy);
      explain(order, !d.on ? 'Switch it on below first.' : (!t.name ? 'Give its name first (Its name…).'
        : 'Ordered from the CA now - from this node for any of them: the CA’s question and the certificate are kept in the database, and ' + (t.target === 'vip' ? 'every node' : t.target) + ' puts it in. ACME renews it from then on.'));
      order.onclick = function () {
        var go = function () {
          busy(order, true);
          api('acme', {action: 'order', target: t.target}).then(function (x) { busy(order, false); toast(x.message, 'good'); AC.d = x; drawAcme(); acPoll(true); })
            .catch(function (e) { busy(order, false); oops(e); });
        };
        if (t.how && !acme) {
          confirmThen('Replace the certificate of ' + (t.target === 'vip' ? 'the VIP address' : t.target) + '?',
            'It has one put in on Certificates and TLS (' + htmlText(t.how) + (t.issuer ? ', ' + htmlText(t.issuer.replace(/^CN=/, '').split(',')[0]) : '') + '). The one from the CA takes its place once it comes, and ACME renews it from then on. Its TLS settings stay as they are.',
            'Order it', go, false);
        } else go();
      };
      var cb = cmdButton(t.care ? 'Leave it alone' : 'Look after it', t.care ? 'cancel' : 'refresh', 'small');
      cb.disabled = !t.wanted;
      explain(cb, t.care ? 'ACME stops renewing this one; the certificate it has stays.'
        : 'ACME renews this one from now on - at the next look (within the hour) if it is not from the CA yet.');
      cb.onclick = function () {
        busy(cb, true);
        api('acme', {action: 'care', target: t.target, on: !t.care}).then(function (x) { AC.d = x; drawAcme(); })
          .catch(function (e) { busy(cb, false); oops(e); });
      };
      /* Every certificate's name from here (1.0.170) - the other node's and
         the VIP address's too. */
      var nm = cmdButton('Its name…', 'edit', 'small');
      explain(nm, t.target === 'vip' ? 'The DNS name of the VIP address - the one people type. It is the VIP address’s own (Settings → High availability) and its certificate is for it.'
        : 'The DNS name the certificate of ' + t.target + ' is for. Empty: the full host name of ' + t.target + '.');
      nm.onclick = function () { acmeNameAsk(t); };
      row.appendChild(probe); row.appendChild(order); row.appendChild(cb); row.appendChild(nm);
      if (t.before && !t.before.ran_out) row.appendChild(acmePutBackButton(t.target, t.before, function (x) { AC.d = x; drawAcme(); }));
      c.appendChild(row);
      grid.appendChild(c);
    });
    host.appendChild(grid);
    if (d.on && d.dns_guide) host.appendChild(acmeDnsGuide(d));
    setTimeout(function () { acmeNamesInSettings(d); }, 0);
    if (d.account && d.account.kid) {
      var a = el('p', 'muted small', 'The account at the CA: ');
      a.appendChild(noI18n(el('span', 'mono', d.account.kid)));
      if (d.account.key) a.appendChild(noI18n(el('span', '', ' · ' + d.account.key)));
      host.appendChild(a);
    }
  });
}

/* The certificate from before ACME (1.0.172): kept when ACME replaced it,
   put back with its key as it was; ACME then leaves it alone. */
function acmePutBackButton(target, before, then) {
  var b = cmdButton('Back to the one before…', 'undo', 'small');
  var words = (before.issuer || '').replace(/^CN=/, '').split(',')[0];
  explain(b, 'The certificate it had before ACME replaced it' + (words ? ' - from ' + words : '') + (before.not_after ? ', good until ' + new Date(before.not_after * 1000).toLocaleDateString(numLang()) : '') + '. Put back as it was; ACME no longer renews this one. The TLS settings stay.');
  b.onclick = function () {
    confirmThen('Put the certificate from before ACME back?', 'The one from the CA is taken out and the one it had before - ' + htmlText(words || before.how || '') + ' - put back, on every node that serves it. ACME no longer renews this one (Look after it gives it back).', 'Put it back', function () {
      busy(b, true);
      api('acme', {action: 'put_back', target: target}).then(function (x) { toast(x.message, 'good'); then(x); })
        .catch(function (e) { busy(b, false); oops(e); });
    }, false);
  };
  return b;
}

/* The names of the certificates beside their box (1.0.170): what each node's
   certificate is for now when its box is empty, and the VIP address's name -
   it is the VIP address's own (High availability), changed from here too. */
function acmeNamesInSettings(d) {
  var item = document.querySelector('.set-item[data-key="acme_node_name"]');
  if (!item) return;
  var now = {};
  (d.targets || []).forEach(function (t) { now[t.target] = t.name || ''; });
  var input = $('set-acme_node_name');
  if (input && now[d.node]) input.placeholder = now[d.node];
  Array.prototype.forEach.call(item.querySelectorAll('.node-other[data-node]'), function (row) {
    /* An empty one says the name it stands for, in the place of "(empty)"
       (1.0.172): the words did not fit in a narrow box. */
    var n = row.dataset.node;
    var empty = row.querySelector('.node-empty');
    if (empty && now[n]) {
      var v = noI18n(el('span', 'mono small muted', now[n]));
      v.title = 'none of its own: the name of its certificate, else its full host name';
      row.replaceChild(v, empty);
      var note = row.querySelector('span.muted:not(.mono)');
      if (note) note.textContent = 'by itself';
    }
  });
  var vip = (d.targets || []).filter(function (t) { return t.target === 'vip'; })[0];
  var box = item.querySelector('.node-others');
  var vr = item.querySelector('.node-other.vip');
  if (vr) vr.remove();
  if (!vip) return;
  if (!box) {
    box = el('div', 'node-others small');
    (item.querySelector('.set-tail') || item).appendChild(box);
  }
  vr = el('div', 'node-other vip');
  vr.appendChild(el('span', 'tag dim', 'VIP'));
  vr.appendChild(vip.name ? noI18n(el('span', 'mono small', vip.name)) : el('span', 'node-empty small', '(empty)'));
  vr.appendChild(el('span', 'muted', 'High availability'));
  if (ADMIN) {
    var eb = iconButton('edit', 'Change the name of the VIP address');
    eb.onclick = function () { acmeNameAsk({target: 'vip', name: vip.name}); };
    vr.appendChild(eb);
  }
  box.appendChild(vr);
}
function acmeNameAsk(t) {
  askInModal(t.target === 'vip' ? 'The name of the VIP address' : 'The name of ' + t.target,
    'The full DNS name its certificate is for - it goes into the certificate as its name (CN) and in its alternative names (SAN). The CA gives it only for a name that points at it (HTTP-01) or whose TXT record can be put in (DNS-01).',
    [{label: 'DNS name', placeholder: t.target === 'vip' ? 'acme.example.cz' : t.target + '.example.cz', mono: true, value: t.name || '',
      says: t.target === 'vip' ? 'Empty: the VIP address has no name.' : 'Empty: its full host name, as ' + t.target + ' says it.'}],
    'Keep it', 'save', function (v, b) {
      busy(b, true);
      api('acme', {action: 'name', target: t.target, name: v[0].trim()}).then(function (x) {
        closeModal(); AC.d = x; drawAcme(); toast('kept', 'good');
        if (t.target !== 'vip') loadSettings();
      }).catch(function (e) { busy(b, false); oops(e); });
    });
}

/* In your DNS (1.0.170): what each certificate asked for needs there - by the
   way the CA checks it - the steps of the way chosen, and a check that looks
   each record up from this node. */
var AC_DNS = {at: 0, rows: null};
var ACME_DNS_STEPS = {
  'http-01': ['Each name points at the address that reaches port 80 of its node (or of the VIP address) - from the internet, or from your own CA.',
              'Port 80 is open to it - the firewall in front of the servers, and Firewall and access here.',
              'Try port 80 on each card, then Order it now.'],
  desec: ['Sign up at desec.io (free) and confirm the mail.',
          'Add a domain there: a free one - yourname.dedyn.io - or one of your own whose DNS is at deSEC.',
          'Token management: make a token. Give it below as The deSEC API token, with The domain at deSEC, and save.',
          'In the DNS of your own domain put the CNAME records below - once; they stay for every renewal.',
          'Check DNS here, then Order it now. Renewals go by themselves.'],
  cloudflare: ['A token at Cloudflare (My Profile → API Tokens) with Zone - DNS - Edit for the zone, given below.',
               'Where the DNS of your domain is not at Cloudflare: a zone that is, as The TXT records go into, and the CNAME records below in your DNS.',
               'Order it now. Renewals go by themselves.'],
  rfc2136: ['A TSIG key the DNS server lets update the _acme-challenge records (tsig-keygen), given below with the server and the zone.',
            'With The TXT records go into: the CNAME records below in your DNS, and the key allowed in that zone.',
            'Order it now. Renewals go by themselves.'],
  acmedns: ['Register at the acme-dns server (POST /register) - it gives a user, a key and a subdomain; give them below.',
            'In your DNS put the CNAME records below - once.',
            'Check DNS here, then Order it now. Renewals go by themselves.'],
  manual: ['At every order - renewals too - the TXT record is shown here: put it in your DNS, then say It is in DNS.',
           'Better: a CNAME once in your DNS to a zone acme can write to (deSEC is free) - then nothing is by hand any more.']
};
function acmeDnsGuide(d) {
  var g = d.dns_guide;
  var key = g.challenge === 'http-01' ? 'http-01' : g.dns;
  var card = el('div', 'card full acme-dns');
  var h = el('h2', '', 'In your DNS');
  card.appendChild(h);
  card.appendChild(el('p', 'note', g.challenge === 'http-01'
    ? 'HTTP-01: the CA asks port 80 of each name - so each name points at the node, or the VIP address, and port 80 is open to the CA.'
    : (g.dns === 'manual' ? 'DNS-01 by hand: the CA reads a TXT record you put in at every order.'
      : 'DNS-01: the CA reads a TXT record acme puts in. What has to be in your DNS for it - once - is below.')));
  var ol = el('ol', 'acme-steps');
  (ACME_DNS_STEPS[key] || []).forEach(function (w) { ol.appendChild(el('li', '', w)); });
  card.appendChild(ol);
  var checked = AC_DNS.rows && Date.now() / 1000 - AC_DNS.at < 600 ? AC_DNS.rows : null;
  var rows = (g.rows || []).map(function (r, i) {
    var c = checked && checked[i] && checked[i].record === r.record ? checked[i] : {};
    return Object.assign({}, r, {ok: c.ok, said: c.said});
  });
  /* Each column a share of the width of its own (1.0.198), as isemon draws it:
     what a cell says - not checked yet, there - never moves the others, after
     a reload or a check alike. Edit the columns sizes them as any table. */
  var t = listTable([{words: 'Certificate', cls: 'dw-c'}, {words: 'Record', cls: 'dw-r'}, {words: 'Type', cls: 'dw-t'},
                     {words: 'Points at / value', cls: 'dw-v'}, {words: 'In DNS now', cls: 'dw-s'}], rows, function (r) {
    var tr = el('tr');
    tr.appendChild(r.target === 'vip' ? el('td', '', 'the VIP address') : (r.type === 'NS' ? el('td', '', 'its zone at deSEC') : noI18n(el('td', '', r.target))));
    /* The text and its copy button in one cell (1.0.198), the button at the
       cell's right edge: the column as wide as its longest text, so the
       buttons stand one under the other right after it - laid out by the
       table itself, nothing measured after drawing, nothing jumping at each
       refresh. One cell per column, so Edit the columns takes this table
       too (two cells under one heading it leaves alone). */
    var pair = function (text, under) {
      var td = el('td', 'mono small dns-cell'), box = el('div', 'dns-val');
      var tx = noI18n(el('span', 'dns-t', text));
      tx.title = text;
      box.appendChild(tx);
      var b = iconButton('copy', 'Copy');
      b.onclick = function () { copyText(text, b); };
      box.appendChild(b);
      td.appendChild(box);
      if (under) td.appendChild(el('div', 'muted dns-under', under));
      tr.appendChild(td);
    };
    var lone = function (words) {
      var td = el('td', 'mono small');
      td.appendChild(el('span', 'muted', words || ''));
      tr.appendChild(td);
    };
    if (r.record) pair(r.record); else lone(r.why);
    tr.appendChild(noI18n(el('td', 'mono small', r.type || '')));
    if (r.type === 'CNAME' || r.type === 'NS' || (r.type === 'A' && r.value))
      pair(r.value, r.type === 'A' ? 'or the public address in front of it' : '');
    else lone(r.type === 'TXT' ? (r.value || r.why) : '');
    var st = el('td', 'small');
    if (r.check) {
      if (r.ok === undefined) st.appendChild(el('span', 'muted', 'not checked yet'));
      else {
        var tag = el('span', 'tag ' + (r.ok ? 'ok' : 'warn'), r.ok ? 'there' : 'not yet');
        st.appendChild(tag);
        if (r.said && !r.ok) st.appendChild(el('div', 'muted', r.said));
      }
    } else st.appendChild(el('span', 'muted', r.type === 'TXT' && !r.value ? 'acme puts it in' : '–'));
    tr.appendChild(st);
    return tr;
  });
  card.appendChild(t);
  var row = el('div', 'btnrow');
  var chk = cmdButton('Check DNS', 'search', 'small');
  explain(chk, 'Each record looked up from this node now, through its DNS servers - as the CA will look. A record just put in may take a while to show (its TTL).');
  chk.disabled = !(g.rows || []).some(function (r) { return r.check; });
  chk.onclick = function () {
    busy(chk, true);
    api('acme', {action: 'dns_check'}).then(function (x) {
      AC_DNS = {at: Date.now() / 1000, rows: x.rows, own: x.own_resolvers};
      busy(chk, false); drawAcme();
    }).catch(function (e) { busy(chk, false); oops(e); });
  };
  row.appendChild(chk);
  if (checked && AC_DNS.own === false) {
    card.appendChild(el('p', 'note warn small', 'Checked with this machine’s DNS servers - inside your network they may see what the internet does not. Set DNS servers for ACME (below) to public ones, 1.1.1.1, 9.9.9.9, to see what the CA sees.'));
  }
  if (checked) {
    var when = el('span', 'muted small');
    when.appendChild(el('span', '', 'checked'));
    when.appendChild(document.createTextNode(' '));
    when.appendChild(el('span', '', ago(AC_DNS.at)));
    row.appendChild(when);
  }
  card.appendChild(row);
  return card;
}

/* ==== Encryption to the database server (1.0.170) =============================
   The daemon's own connection to its database, as a wizard like the link
   between the databases: every node, in phases - the certificate of a
   PostgreSQL on the node itself first, then every node's connection - and
   back the other way round. Each node says how it went. */
var DBT = {d: null, run: null, said: {}};
function loadDbTls() {
  if (!ADMIN) return;
  /* Not answered: said on the card, not left out of the page (1.0.172). */
  api('dbtls').then(function (d) { DBT.d = d; DBT.err = ''; drawDbTls(); }).catch(function (e) {
    DBT.err = String((e && e.message) || e);
    var card = $('db-tls-card'), host = $('db-tls');
    if (!card || !host) return;
    card.hidden = false;
    host.innerHTML = '';
    host.appendChild(el('div', 'note bad', 'The encryption to the database server could not be read: ' + DBT.err));
  });
}
function dbtKindWords(k) {
  return {sqlite: 'a file on this machine', socket: 'over a Unix socket', local: 'PostgreSQL on this machine',
          replicated: 'its own PostgreSQL, replicated', remote: 'a database server over the network'}[k] || k;
}
function dbtPoll(of, id, nodes, onEach) {
  return new Promise(function (resolve) {
    var left = nodes.slice(), began = Date.now(), got = {};
    var timer = setInterval(function () {
      api('dbtls', {action: 'result', id: id, of: of}).then(function (r) {
        left = left.filter(function (n) {
          var x = (r.nodes || {})[n];
          if (x) { got[n] = x; if (onEach) onEach(n, x); return false; }
          return true;
        });
        if (r.view) DBT.d = r.view;
        if (!left.length || Date.now() - began > 150000) {
          clearInterval(timer);
          left.forEach(function (n) { got[n] = {ok: false, error: 'did not answer in two and a half minutes - is it running?'}; });
          resolve(got);
        }
      }).catch(function () {
        if (Date.now() - began > 150000) {             /* (1.0.208) */
          clearInterval(timer);
          left.forEach(function (n) { got[n] = {ok: false, error: 'did not answer in two and a half minutes - is it running?'}; });
          resolve(got);
        }
      });
    }, 1000);
  });
}
/* One phase on every node (or one): resolves with each node's answer. */
function dbtPhase(body) {
  return api('dbtls', body).then(function (x) {
    return dbtPoll(body.action === 'probe' ? 'probe' : 'apply', x.id, x.nodes || [], function (n, r) {
      DBT.said[n] = {phase: body.phase || 'probe', r: r};
      drawDbTls();
    });
  });
}
function dbtFailed(got) {
  return Object.keys(got).filter(function (n) { return got[n] && got[n].ok === false; });
}
/* The steps, one after the other; the first that fails on any node stops there. */
function dbtSteps(steps, done) {
  DBT.run = {steps: steps.map(function (s) { return s.label; }), at: 0};
  DBT.said = {};
  drawDbTls();
  var i = 0;
  var next = function () {
    if (i >= steps.length) { DBT.run = null; toast('done on every node', 'good'); loadDbTls(); if (done) done(true); return; }
    DBT.run.at = i;
    drawDbTls();
    dbtPhase(steps[i].body).then(function (got) {
      var bad = dbtFailed(got);
      if (bad.length) {
        DBT.run = null;
        toast('stopped on ' + bad.join(', ') + ' - what is in use there is as it was', 'bad');
        loadDbTls();
        if (done) done(false);
        return;
      }
      i++; next();
    }).catch(function (e) { DBT.run = null; oops(e); loadDbTls(); });
  };
  next();
}
function drawDbTls() {
  var card = $('db-tls-card'), host = $('db-tls');
  if (!card || !host || !DBT.d) return;
  var d = DBT.d;
  var kinds = {};
  (d.nodes || []).forEach(function (n) { kinds[n.kind || d.kind] = 1; });
  var net = (d.nodes || []).some(function (n) { return ['local', 'replicated', 'remote'].indexOf(n.kind || d.kind) >= 0; });
  card.hidden = d.kind === 'sqlite' && !net;
  if (card.hidden) return;
  host.innerHTML = '';
  var nodes = d.nodes || [];
  var on = nodes.filter(function (n) { return n.mode; });
  var checked = nodes.length && nodes.every(function (n) { return ['verify-ca', 'verify-full'].indexOf(n.mode) >= 0 && n.ssl; });
  var rescued = nodes.filter(function (n) { return n.rescued; });
  var running = !!DBT.run;
  var box = el('div', 'hal ' + (running ? 'run' : (checked && !rescued.length ? 'good' : 'warn')));
  var head = el('div', 'hal-head');
  var ic = el('span', 'hal-ic');
  ic.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">'
    + ICONS[running ? 'refresh' : (checked ? 'lock' : 'shield')] + '</svg>';
  head.appendChild(ic);
  var words = el('div', 'hal-words');
  var title, sub;
  if (running) {
    title = 'Moving every node’s connection over…';
    sub = 'Step ' + (DBT.run.at + 1) + ' of ' + DBT.run.steps.length + ': ' + DBT.run.steps[DBT.run.at] + '. The daemon goes on all the time; this page follows it.';
  } else if (d.kind === 'sqlite') {
    title = 'Nothing to encrypt here: the database is a file on this machine';
    sub = '';
  } else if (d.kind === 'socket' && !on.length) {
    title = 'Nothing goes over a network: the database is reached over a Unix socket';
    sub = '';
  } else if (rescued.length) {
    title = 'The connection of ' + rescued.map(function (n) { return n.name; }).join(', ') + ' was moved back to no TLS by itself';
    sub = 'It stopped working with TLS (' + (rescued[0].rescued.why || '') + ') - the database is on the same machine, so it went on without it and kept working. Put it right and encrypt it again.';
  } else if (checked) {
    title = 'Every node reaches its database encrypted and checked';
    /* Said outright (1.0.181): renewed while running, nothing stops. */
    sub = d.kind === 'local' || (d.kind === 'replicated' && !d.link_done) ? 'PostgreSQL here has a certificate from acme’s own authority, renewed by itself 45 days before it ends - and made again when the machine’s names change. Renewed while everything runs: PostgreSQL takes the new one with a reload, no restart - the connections go on, RADIUS does not notice.'
      : (d.kind === 'replicated' ? 'Each node checks its own PostgreSQL with acme’s own authority - its certificate the one the link between the databases has, renewed with it by itself 45 days before it ends (the authority two years before), as the replication’s: with a reload of PostgreSQL, no restart - nothing stops. Either is switched off without the other.'
        : 'The server’s certificate is checked with the authority given. That server’s certificate is renewed by its administrator - acme only checks it.');
  } else if (on.length) {
    title = 'Encrypted, but whose certificate answers is not checked on ' + on.filter(function (n) { return n.mode === 'require'; }).map(function (n) { return n.name; }).join(', ');
    sub = 'require encrypts but takes any certificate. verify-full also checks that it is the server’s.';
  } else {
    title = 'The connection to the database is not encrypted';
    sub = d.kind === 'remote' ? 'Whoever is on the network between this node and the database server reads every row going over - the private keys sealed, but who signs in, when and from where - and can change them.'
      : 'It does not leave the machine, so this matters less - but high security and the security check ask for it, and it is a few clicks.';
  }
  words.appendChild(el('b', '', title));
  if (sub) words.appendChild(el('div', 'small', sub));
  head.appendChild(words);
  var acts = el('div', 'btnrow');
  if (ME.role === 'fulladmin' && !running && d.kind !== 'sqlite') {
    {
      var b = cmdButton(checked ? 'Again…' : 'Encrypt…', checked ? 'refresh' : 'lock', checked ? 'small' : 'small primary');
      b.id = 'dbt-on';
      b.onclick = function () { dbtWizard(); };
      acts.appendChild(b);
      if ((d.servers || []).length && checked) {
        var rn = cmdButton('Renew the certificate', 'refresh', 'small');
        explain(rn, 'A new certificate for the PostgreSQL on ' + d.servers.join(', ') + ' now, not 45 days before the end. The connections go on.');
        rn.onclick = function () { dbtSteps([{label: 'a new certificate', body: {action: 'apply', phase: 'server', renew: true}}]); };
        acts.appendChild(rn);
      }
      if (on.length) {
        var off = cmdButton('Switch it off…', 'cancel', 'small danger');
        off.id = 'dbt-off';
        off.disabled = !!d.hisec;
        explain(off, d.hisec ? 'High security is on: the database is reached with TLS that checks its certificate (or make db:tls an exception there).'
          : 'Every node back to no TLS, then acme’s certificates out of the PostgreSQLs on the nodes (ssl as postgresql.conf says).');
        off.onclick = function () {
          confirmThen('Switch the encryption to the database off?',
            (d.kind === 'remote' ? '<b>Whoever is on the network between the nodes and the database server will read every row going over.</b><br>' : '')
            + 'Every node’s connection moves back to no TLS first, then acme’s certificates leave the PostgreSQLs on the nodes - not where the link between the databases uses them. Nothing stops meanwhile.',
            'Switch it off', function () {
              dbtSteps([{label: 'every connection back to no TLS', body: {action: 'apply', phase: 'connect', mode: ''}},
                        {label: 'acme’s certificates out of PostgreSQL', body: {action: 'apply', phase: 'server_off'}}]);
            });
        };
        acts.appendChild(off);
      }
    }
  }
  head.appendChild(acts);
  box.appendChild(head);
  var list = el('div', 'hal-nodes');
  nodes.forEach(function (n) {
    var row = el('div', 'hal-node');
    var nm = noI18n(el('b', 'hal-name', n.name));
    row.appendChild(nm);
    var steps = el('div', 'hal-steps');
    var kind = n.kind || d.kind;
    steps.appendChild(el('span', 'hal-step', dbtKindWords(kind)));
    if (kind === 'local' || kind === 'replicated') {
      var cs = el('span', 'hal-step ' + (n.server || n.server_by ? 'ok' : ''), n.server_by === 'link' ? 'the link’s certificate' : 'its certificate');
      steps.appendChild(cs);
    }
    steps.appendChild(el('span', 'hal-step ' + (n.mode ? (n.ssl ? 'ok' : 'bad') : ''), n.mode ? n.mode : 'no TLS'));
    if (n.ssl) steps.appendChild(noI18n(el('span', 'hal-step ok', (n.version || 'TLS') + (n.cipher ? ' · ' + n.cipher : ''))));
    row.appendChild(steps);
    var said = [];
    if (n.ca_said) said.push('checked with ' + n.ca_said);
    if (n.cert_end) said.push('its certificate ends ' + new Date(n.cert_end * 1000).toLocaleDateString(numLang()) + ' · in ' + num(Math.max(0, Math.round((n.cert_end * 1000 - Date.now()) / 86400000))) + ' days');
    if (!n.alive && !n.me) said.push('not heard from');
    var now = DBT.said[n.name];
    var bad = false;
    if (now && now.r) {
      var r = now.r;
      if (r.ok === false) { bad = true; said = [r.error || r.said || 'it did not go']; }
      else if (r.said) said.unshift(r.said);
      else if (r.ms !== undefined && now.phase === 'probe') said.unshift('it goes (' + r.ms + ' ms' + (r.version ? ', ' + r.version : '') + ')');
    }
    /* Each part its own, so each is said in the page's language. */
    var sd = el('div', 'hal-said small ' + (bad ? 'bad' : 'muted'));
    said.forEach(function (w, i) {
      if (i) sd.appendChild(document.createTextNode(' · '));
      sd.appendChild(el('span', '', w));
    });
    row.appendChild(sd);
    list.appendChild(row);
  });
  box.appendChild(list);
  host.appendChild(box);
}
/* What to switch to: for a server elsewhere its authority and the mode; for a
   PostgreSQL on the nodes nothing to choose - acme's (or the cluster's)
   authority and verify-full. Tried on every node before anything moves. */
function dbtWizard() {
  var d = DBT.d;
  var remote = (d.nodes || []).some(function (n) { return (n.kind || d.kind) === 'remote'; });
  var locals = (d.nodes || []).some(function (n) { return (n.kind || d.kind) === 'local' || ((n.kind || d.kind) === 'replicated' && !d.link_done); });
  var mode, src, pem, out;
  var on = (d.nodes || []).some(function (n) { return n.mode; });
  modal('Encrypt the connection to the database', function (body) {
    body.appendChild(el('p', 'note', 'Every node, one step after the other: ' + (locals ? 'the PostgreSQL on the node given a certificate from acme’s own authority (reloaded, not restarted), then ' : '')
      + 'each node’s connection tried apart with the new settings and moved over - put back at once on any node where the first statement does not go.'));
    if (remote) {
      var g = el('div', 'formgrid');
      var modes = [['verify-full', 'verify-full - encrypted, the certificate and its name checked']];
      modes.push(['verify-ca', 'verify-ca - encrypted, the certificate checked, not its name']);
      if (!d.hisec) modes.push(['require', 'require - encrypted, any certificate taken']);
      mode = selectBox(modes, 'verify-full');
      var far = (d.nodes || []).filter(function (n) { return (n.kind || d.kind) === 'remote' && n.host; }).map(function (n) { return n.host; });
      far = far.filter(function (h, i) { return far.indexOf(h) === i; });
      g.appendChild(formField('How', mode, 'verify-full needs a certificate that names the address the nodes reach the server by' + (far.length ? ' (' + far.join(', ') + ')' : '') + '.'));
      var srcs = [['given', 'its authority, given here (PEM)'], ['system', 'the system’s authorities (a public CA)']];
      if (d.own_ca) srcs.push(['acme', 'acme’s own authority (the server is a node’s PostgreSQL given one here)']);
      if (on && d.mode && d.mode !== 'require') srcs.push(['keep', 'the one in use now']);
      src = selectBox(srcs, d.own_ca && (d.servers || []).length ? 'acme' : 'given');
      var sf = formField('The server’s authority', src, 'Who signed the database server’s certificate.');
      g.appendChild(sf);
      body.appendChild(g);
      pem = el('textarea', 'mono');
      pem.rows = 6;
      pem.placeholder = '-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----';
      var pf = formField('The authority (PEM)', pem, 'The CA certificate of the database server - from its administrator, or the server’s root.crt / ca.pem. Nothing secret.');
      body.appendChild(pf);
      var sync = function () {
        var m = val(mode);
        sf.hidden = m === 'require';
        pf.hidden = m === 'require' || val(src) !== 'given';
      };
      [mode, src].forEach(function (x) { x.addEventListener('change', sync); });
      sync();
    }
    out = el('div', 'dbt-try');
    body.appendChild(out);
  }, [{words: 'Close', close: true},
      {words: 'Try it on every node', icon: 'play', go: function (b) { dbtTry(b); }},
      {words: 'Switch over', cls: 'primary', icon: 'lock', go: function (b) {
        var args = dbtArgs();
        var steps = [];
        /* Each node gives its own PostgreSQL a certificate where it has none
           of acme's yet - the link's is used where that is on. */
        if (locals || (d.nodes || []).some(function (n) { return (n.kind || d.kind) === 'replicated'; }) || (d.servers || []).length)
          steps.push({label: 'the certificates of the PostgreSQLs on the nodes', body: {action: 'apply', phase: 'server'}});
        steps.push({label: 'every node’s connection moved over', body: dbtObj({action: 'apply', phase: 'connect'}, args)});
        closeModal();
        dbtSteps(steps);
      }}], 'large');
  function val(x) { return x ? (x._get ? x._get() : x.value) : ''; }
  function dbtArgs() {
    if (!remote) return {mode: 'verify-full'};
    var m = val(mode);
    return {mode: m, ca_source: m === 'require' ? '' : val(src), ca_pem: m !== 'require' && val(src) === 'given' ? pem.value.trim() : ''};
  }
  function dbtObj(a, b) { Object.keys(b).forEach(function (k) { a[k] = b[k]; }); return a; }
  function dbtTry(b) {
    busy(b, true);
    out.innerHTML = '';
    var grid = nodeGrid();
    out.appendChild(grid);
    var cards = {};
    api('dbtls', dbtObj({action: 'probe'}, dbtArgs())).then(function (x) {
      (x.nodes || []).forEach(function (n) {
        var c = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, 'dim', 'being tried', 'info');
        c.appendChild(el('p', 'muted small', 'Connecting to the database from ' + n + ' with the new settings…'));
        grid.appendChild(c); cards[n] = c;
      });
      return dbtPoll('probe', x.id, x.nodes || [], function (n, r) {
        var old = cards[n];
        var good = r.ok !== false;
        var c = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, good ? 'ok' : 'crit', good ? (r.needs_server ? 'a certificate first' : 'it goes') : 'it does not go', good ? 'ok' : 'crit');
        c.appendChild(netFacts([['Its database', dbtKindWords(r.kind)], ['The server speaks TLS', r.server_tls ? 'yes' : 'no'],
                                ['Encrypted', r.ssl ? (r.version || 'yes') : (r.needs_server ? 'after its certificate' : 'no')],
                                ['Cipher', r.cipher || '–', true], ['Took', r.ms !== undefined ? r.ms + ' ms' : '–']]));
        if (!good || r.said) c.appendChild(nodeSaid({ok: good, error: good ? '' : (r.said || r.error), at: r.at || Date.now() / 1000}, good ? r.said : ''));
        if (old) grid.replaceChild(c, old); else grid.appendChild(c);
      });
    }).then(function () { busy(b, false); }).catch(function (e) { busy(b, false); oops(e); });
  }
}

/* ==== isemon over TLS (1.0.172) ================================================
   The state of the encrypted sending, and the wizard: where isemon is, whose
   certificate it has (one acme makes for it, its own CA's, a public CA's),
   mutual TLS, tried from every node, then switched over. */
function drawIsemonTls() {
  var card = $('isemon-tls-card'), host = $('isemon-tls');
  if (!card || !host || !IS.d || !IS.d.tls || !ADMIN) return;
  var t = IS.d.tls;
  card.hidden = false;
  host.innerHTML = '';
  var tls = (t.targets || []).filter(function (x) { return x.proto === 'tls'; });
  var plain = (t.targets || []).filter(function (x) { return x.proto !== 'tls'; });
  var good = tls.length && !plain.length && t.verify;
  var box = el('div', 'hal ' + (good ? 'good' : 'warn'));
  var head = el('div', 'hal-head');
  var ic = el('span', 'hal-ic');
  ic.innerHTML = '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' + ICONS[good ? 'lock' : 'shield'] + '</svg>';
  head.appendChild(ic);
  var words = el('div', 'hal-words');
  words.appendChild(el('b', '', !t.on ? 'Sending to isemon is off' : (good ? 'isemon is sent to over TLS, its certificate checked'
    : (tls.length ? (plain.length ? 'Part of it goes to isemon unencrypted' : 'Encrypted, but whoever answers is taken (its certificate not checked)')
      : 'isemon is sent plain syslog - whoever is on the network reads who signs in, when and from where'))));
  var sub = [];
  if (tls.length) {
    sub.push(t.ca_is_acme ? 'isemon’s certificate from acme’s own authority' : (t.ca === 'given' ? 'isemon’s certificate checked with the authority given' : 'isemon’s certificate checked with the system’s authorities'));
    if (t.mtls) sub.push('each node shows its own certificate (mutual TLS)');
  }
  if (sub.length) words.appendChild(el('div', 'small', sub.join(' · ')));
  head.appendChild(words);
  var acts = el('div', 'btnrow');
  var go = cmdButton(tls.length ? 'Change…' : 'Encrypt…', 'lock', tls.length ? 'small' : 'small primary');
  go.id = 'ise-tls-on';
  go.onclick = function () { isemonTlsWizard(); };
  acts.appendChild(go);
  if (tls.length) {
    var off = cmdButton('Switch TLS off…', 'cancel', 'small danger');
    off.disabled = !!t.hisec;
    explain(off, t.hisec ? 'High security is on: isemon is sent to over TLS only (or make isemon an exception there).' : 'Back to plain TCP on 514 - isemon’s rsyslog has to take that again.');
    off.onclick = function () {
      confirmThen('Send isemon plain syslog again?', '<b>Whoever is on the network between the nodes and isemon will read every line.</b><br>Every TLS target goes back to plain TCP on 514.', 'Switch it off', function () {
        api('isemon', {action: 'tls_off'}).then(function (x) { toast(x.message, 'good'); loadIsemon(); loadSettings(); }).catch(oops);
      });
    };
    acts.appendChild(off);
  }
  head.appendChild(acts);
  box.appendChild(head);
  var list = el('div', 'hal-nodes wide');
  (t.targets || []).forEach(function (x) {
    var row = el('div', 'hal-node');
    row.appendChild(noI18n(el('b', 'hal-name', x.host + ':' + x.port)));
    var steps = el('div', 'hal-steps');
    steps.appendChild(el('span', 'hal-step ' + (x.proto === 'tls' ? 'ok' : 'bad'), x.proto === 'tls' ? 'TLS' : (x.proto === 'tcp' ? 'TCP, unencrypted' : 'UDP, unencrypted')));
    if (x.proto === 'tls') steps.appendChild(el('span', 'hal-step ' + (t.verify ? 'ok' : 'bad'), t.verify ? 'its certificate checked' : 'its certificate not checked'));
    if (x.proto === 'tls' && t.mtls) steps.appendChild(el('span', 'hal-step ok', 'mutual TLS'));
    row.appendChild(steps);
    list.appendChild(row);
  });
  if (t.server && t.server.end) {
    var row = el('div', 'hal-node');
    row.appendChild(el('b', 'hal-name', 'isemon’s certificate'));
    var left = Math.round((t.server.end * 1000 - Date.now()) / 86400000);
    var sd = el('div', 'hal-said small ' + (left < 60 ? 'bad' : 'muted'));
    sd.appendChild(noI18n(el('span', 'mono', (t.server.names || []).join(', '))));
    sd.appendChild(document.createTextNode(' · '));
    sd.appendChild(el('span', '', 'ends ' + new Date(t.server.end * 1000).toLocaleDateString(numLang())));
    sd.appendChild(document.createTextNode(' · '));
    sd.appendChild(el('span', '', 'in ' + num(Math.max(0, left)) + ' days'));
    row.appendChild(sd);
    list.appendChild(row);
  }
  if (t.mtls) Object.keys(t.nodes || {}).forEach(function (n) {
    var c = t.nodes[n] || {};
    var row = el('div', 'hal-node');
    row.appendChild(noI18n(el('b', 'hal-name', n)));
    row.appendChild(el('div', 'hal-said small muted', c.client_end ? 'its own certificate ends ' + new Date(c.client_end * 1000).toLocaleDateString(numLang()) + ' - renewed by itself' : 'its own certificate is made at the next look (within 5 minutes)'));
    list.appendChild(row);
  });
  box.appendChild(list);
  host.appendChild(box);
}
function isemonTlsWizard(was) {
  var t = IS.d.tls || {};
  var cur = (t.targets || [])[0] || {};
  was = was || null;
  var hostI, portI, srcI, pemI, namesI, mtlsI, verI, out, pemF, namesF, bundleRow;
  modal('Encrypt the sending to isemon', function (body) {
    body.appendChild(el('p', 'note', 'Step by step: where isemon is and whose certificate it has; for one made here, the locked file for isemon with what to do there; then tried from every node; then switched over.'));
    var g = el('div', 'formgrid');
    if (was && was.saved) body.appendChild(el('p', 'note good', 'The file for isemon is saved. Put it in on the isemon machine as README.txt in it says, then Try it on every node and Switch over.'));
    hostI = textBox(was ? was.host : (cur.host || ''), 'isemon.example.cz', 'mono');
    g.appendChild(formField('isemon’s address', hostI, 'As the nodes reach it - the name or the address its certificate is for.'));
    portI = textBox(was ? String(was.port) : String(cur.proto === 'tls' ? cur.port : 6514), '6514', 'mono');
    g.appendChild(formField('Port', portI, '6514 is syslog over TLS.'));
    srcI = selectBox([['acme', 'acme makes isemon a certificate - a locked file for isemon'], ['given', 'isemon has one from its own CA (PEM)'], ['system', 'isemon has one from a public CA']],
      was ? was.src : (t.ca_is_acme || !t.tls ? 'acme' : (t.ca === 'given' ? 'given' : 'system')));
    g.appendChild(formField('isemon’s certificate', srcI, 'Who signed the certificate isemon’s rsyslog answers with.'));
    mtlsI = switchBox(was ? was.mtls : (t.tls ? t.mtls : true));
    g.appendChild(formField('isemon takes acme’s nodes only (mutual TLS)', mtlsI, 'Each node shows isemon a certificate of its own from acme’s authority, made and renewed by itself; isemon’s rsyslog lets in only those (PermittedPeer).'));
    verI = switchBox(was ? was.verify : (t.tls ? t.verify : true));
    verI._input.disabled = !!t.hisec;
    g.appendChild(formField('Check isemon’s certificate', verI, 'Off only to try it: encrypted, but whoever answers is taken.'));
    body.appendChild(g);
    pemI = el('textarea', 'mono'); pemI.rows = 5; pemI.placeholder = '-----BEGIN CERTIFICATE-----';
    if (was) pemI.value = was.pem || '';
    pemF = formField('isemon’s authority (PEM)', pemI, 'The CA certificate that signed isemon’s certificate. Nothing secret.');
    body.appendChild(pemF);
    namesI = textBox(was ? was.names : (cur.host || ''), 'isemon.example.cz, 10.1.2.3', 'mono');
    namesF = formField('Names in isemon’s certificate', namesI, 'Every name and address the nodes reach isemon by, separated by commas.');
    body.appendChild(namesF);
    bundleRow = el('div', 'btnrow');
    var mk = cmdButton('Make the file for isemon…', 'download', 'small');
    explain(mk, 'isemon’s certificate and its key from acme’s authority, acme’s authority, the rsyslog configuration and what to do - one ZIP locked with a passphrase you give now (the key is in it). acme does not keep the key. Open it with 7-Zip (7z x isemon-tls.zip).');
    mk.onclick = function () {
      /* What is filled in, to come back to (1.0.178): the passphrase's window
         takes the wizard's place, and the wizard closed with it. */
      var keep = {host: hostI.value, port: portI.value, src: srcI.value, mtls: !!mtlsI._get(), verify: !!verI._get(),
                  pem: pemI.value, names: namesI.value};
      askInModal('The file for isemon', 'A passphrase for the file: 12 characters at least. You need it to open the file on the isemon machine - acme does not keep it.',
        [{label: 'Passphrase', type: 'password'}, {label: 'Again', type: 'password'}], 'Make it', 'download', function (v, b) {
          if (v[0] !== v[1]) { toast('the two are not the same', 'bad'); return; }
          busy(b, true);
          api('isemon', {action: 'tls_bundle', host: hostI.value.trim(), port: Number(portI.value) || 6514, names: namesI.value, mtls: !!mtlsI._get(), passphrase: v[0]}).then(function (d) {
            var bin = atob(d.file), bytes = new Uint8Array(bin.length);
            for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            var a = el('a');
            a.href = URL.createObjectURL(new Blob([bytes], {type: 'application/zip'}));
            a.download = d.name;
            document.body.appendChild(a); a.click();
            setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
            closeModal();
            toast('the file for isemon is saved - put it in on the isemon machine (README.txt in it), then Try it on every node', 'good');
            keep.saved = true;
            isemonTlsWizard(keep);
          }).catch(function (e) { busy(b, false); oops(e); });
        });
    };
    bundleRow.appendChild(mk);
    body.appendChild(bundleRow);
    var sync = function () {
      var src = srcI.value;
      pemF.hidden = src !== 'given';
      namesF.hidden = bundleRow.hidden = src !== 'acme';
    };
    srcI.addEventListener('change', sync);
    sync();
    out = el('div', 'dbt-try');
    body.appendChild(out);
  }, [{words: 'Close', close: true},
      {words: 'Try it on every node', icon: 'play', go: function (b) { isemonTlsTry(b); }},
      {words: 'Switch over', cls: 'primary', icon: 'lock', go: function (b) {
        busy(b, true);
        api('isemon', isemonTlsArgs('tls_apply')).then(function (x) {
          closeModal(); toast(x.message, 'good'); loadIsemon(); loadSettings();
        }).catch(function (e) { busy(b, false); oops(e); });
      }}], 'large');
  function isemonTlsArgs(action) {
    return {action: action, host: hostI.value.trim(), port: Number(portI.value) || 6514, ca_source: srcI.value,
            ca_pem: srcI.value === 'given' ? pemI.value.trim() : '', mtls: !!mtlsI._get(), verify: !!verI._get()};
  }
  function isemonTlsTry(b) {
    busy(b, true);
    out.innerHTML = '';
    var grid = nodeGrid();
    out.appendChild(grid);
    var cards = {};
    api('isemon', isemonTlsArgs('tls_probe')).then(function (x) {
      (x.nodes || []).forEach(function (n) {
        var c = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, 'dim', 'being tried', 'info');
        c.appendChild(el('p', 'muted small', 'Connecting to isemon from ' + n + '…'));
        grid.appendChild(c); cards[n] = c;
      });
      var left = (x.nodes || []).slice(), began = Date.now();
      var timer = setInterval(function () {
        api('isemon', {action: 'tls_result', id: x.id}).then(function (r) {
          left = left.filter(function (n) {
            var g = (r.nodes || {})[n];
            if (!g) return true;
            var c = nodeCard({node: n, me: !!(STATUS && n === STATUS.node)}, g.ok ? 'ok' : 'crit', g.ok ? 'it goes' : 'it does not go', g.ok ? 'ok' : 'crit');
            var steps = el('div', 'pt-steps');
            (g.steps || []).forEach(function (s) {
              var row = el('div', 'si-row');
              row.appendChild(el('span', 'dot ' + (s.ok ? 'ok' : 'bad')));
              row.appendChild(el('span', '', s.what));
              if (s.said) row.appendChild(el('span', 'muted small', s.said));
              row.appendChild(noI18n(el('span', 'muted small', s.ms + ' ms')));
              steps.appendChild(row);
            });
            c.appendChild(steps);
            if (g.cert) c.appendChild(netFacts([['isemon’s certificate', g.cert.subject || '', true], ['Issued by', g.cert.issuer || '', true],
              ['Names', (g.cert.names || []).join(', '), true], ['Good until', g.cert.end ? new Date(g.cert.end * 1000).toLocaleDateString(numLang()) : '']]));
            if (g.error) c.appendChild(nodeSaid({ok: false, error: g.error, at: Date.now() / 1000}, ''));
            grid.replaceChild(c, cards[n]);
            return false;
          });
          if (!left.length || Date.now() - began > 60000) { clearInterval(timer); busy(b, false); }
        }).catch(function () {
          if (Date.now() - began > 60000) { clearInterval(timer); busy(b, false); }   /* (1.0.208) */
        });
      }, 1000);
    }).catch(function (e) { busy(b, false); oops(e); });
  }
}

/* ==== Monitoring: Prometheus (1.0.173) =========================================
   A token made here and shown once; what prometheus.yml says to ask every
   node; what this node answers now. */
/* ---- SNMPv3 (1.0.182): each node's agent, its engine ID, its own test ---------- */
var SN = {d: null, said: {}};
function loadSnmp() {
  api('snmp').then(function (d) { SN.d = d; drawSnmp(); }).catch(function () {});
}
function drawSnmp() {
  var host = $('snmp-host');
  if (!host || !SN.d) return;
  var d = SN.d;
  host.innerHTML = '';
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'SNMPv3'));
  card.appendChild(el('p', 'note', 'Each node answers by itself, at its own address, with an engine ID of its own - the monitoring asks every node, as with Prometheus. authPriv only: the user and its two passphrases above. acme\'s objects are under ' + d.base + ' (ACME-MIB, deploy/ACME-MIB.txt in the package).'));
  if (!d.on) card.appendChild(el('p', 'muted small', 'Off - switch it on above, with the user and its passphrases.'));
  else if (!d.ready) card.appendChild(el('p', 'note warn', 'On, but the user or a passphrase is not set: nothing is answered yet.'));
  var grid = nodeGrid();
  (d.nodes || []).forEach(function (n) {
    var a = n.snmp || {}, fresh = nodeFresh(n);
    var c = nodeCard(n, !fresh ? 'bad' : (a.listening ? 'ok' : (d.on ? 'bad' : 'dim')),
      !fresh ? 'not heard from' : (a.listening ? 'listening' : (d.on ? 'not listening' : 'off')),
      !fresh ? 'crit' : (a.listening ? 'ok' : (d.on ? 'crit' : 'dim')));
    c.appendChild(netFacts([
      ['Port', a.port ? a.port + '/udp' : '–', true],
      ['Engine ID', a.engine ? copyOnClick(noI18n(el('span', 'mono small', a.engine)), a.engine, 'the engine ID was copied') : '–'],
      ['Engine boots', a.boots ? String(a.boots) : '–', true],
      ['Asked / answered', num(a.asked || 0) + ' / ' + num(a.answered || 0)],
      ['Last asked from', a.last_from ? a.last_from + ' · ' + ago(a.last_at) : 'never'],
      ['Traps sent', num(a.traps || 0)],
      ['Read', n.at ? ago(n.at) : '']
    ]));
    if (a.error) c.appendChild(noI18n(el('p', 'note bad small', a.error)));
    if (a.trap_error) c.appendChild(noI18n(el('p', 'note warn small', 'Last trap: ' + a.trap_error)));
    var said = SN.said[n.node];
    if (said) c.appendChild(nodeSaid(said, said.sent ? 'The test trap went to ' + Object.keys(said.sent).join(', ') : 'It answered itself in ' + said.ms + ' ms: ' + ((said.said || {})['1.3.6.1.2.1.1.1.0'] || '')));
    if (ME.role === 'fulladmin') {
      var row = el('div', 'btnrow');
      var t = cmdButton('Ask it', 'play', 'small');
      explain(t, n.node + ' asks its own agent on 127.0.0.1 as the monitoring would: discovery, then a GET with the user and its passphrases (authPriv).');
      t.disabled = !d.on || !d.ready || !fresh;
      t.onclick = function () {
        busy(t, true);
        askNodes('snmp', {action: 'test', node: n.node}, function (node, got) { SN.said[node] = got; },
          function () { busy(t, false); drawSnmp(); }).catch(function (e) { busy(t, false); oops(e); });
      };
      var tr = cmdButton('Send a test trap', 'bell', 'small');
      explain(tr, 'A trap from ' + n.node + ' to every receiver set, now - with its engine ID, authPriv.');
      tr.disabled = !d.on || !d.ready || !fresh || !(d.trap_to || []).length;
      tr.onclick = function () {
        busy(tr, true);
        askNodes('snmp', {action: 'trap', node: n.node}, function (node, got) { SN.said[node] = got; },
          function () { busy(tr, false); drawSnmp(); }).catch(function (e) { busy(tr, false); oops(e); });
      };
      row.appendChild(t); row.appendChild(tr);
      c.appendChild(row);
    }
    grid.appendChild(c);
  });
  card.appendChild(grid);
  /* What to put into the monitoring - net-snmp's commands and the trap receiver. */
  var user = d.user || 'USER', auth = d.auth === 'SHA-1' ? 'SHA' : d.auth, priv = d.priv === 'AES-256' ? 'AES256' : 'AES';
  var lines = ['# asked (net-snmp; Zabbix: SNMPv3, authPriv, ' + d.auth + ', ' + d.priv + ', security name ' + user + ')'];
  (d.nodes || []).forEach(function (n) {
    lines.push('snmpwalk -v3 -l authPriv -u ' + user + ' -a ' + auth + ' -A \'…\' -x ' + priv + ' -X \'…\' ' + n.node + ':' + d.port + ' ' + d.base);
  });
  lines.push('', '# traps: snmptrapd.conf on the receiver, one line for each node\'s engine ID');
  (d.nodes || []).forEach(function (n) {
    var e = (n.snmp || {}).engine || 'ENGINE-ID-OF-' + n.node;
    lines.push('createUser -e 0x' + e + ' ' + user + ' ' + auth + ' \'…\' ' + priv + ' \'…\'');
  });
  lines.push('authUser log,execute ' + user + ' priv');
  card.appendChild(el('h3', 'peek-h', 'In the monitoring'));
  card.appendChild(noI18n(el('pre', 'wrap mono small', lines.join('\n'))));
  card.appendChild(el('p', 'muted small', 'The passphrases are not shown here - they are those set above (kept sealed). AES-256 is net-snmp\'s AES256 and Zabbix\'s AES256, not Cisco\'s AES256C.'));
  host.appendChild(card);
}
function drawMonitor() {
  var host = $('mon-host');
  if (!host || !ADMIN) return;
  host.innerHTML = '';
  var card = el('div', 'card full');
  card.appendChild(el('h2', '', 'Prometheus'));
  card.appendChild(el('p', 'note', 'Each node answers for itself - Prometheus asks every node, by its own address (not the VIP address, which is one node at a time). The token is the same for every node.'));
  var row = el('div', 'btnrow');
  var mk = cmdButton('Make a token…', 'key', 'small primary');
  explain(mk, 'A new token for Prometheus, shown once - the one before stops opening /metrics at once.');
  mk.onclick = function () {
    confirmThen('Make a new token for Prometheus?', 'The token used now stops opening /metrics at once - put the new one into Prometheus.', 'Make it', function () {
      api('metrics', {action: 'token'}).then(function (x) {
        modal('The token for Prometheus', function (body) {
          body.appendChild(el('p', 'note', 'Shown only now. Put it into a file Prometheus reads (bearer_token_file below), readable by it alone.'));
          var pre = noI18n(el('pre', 'wrap mono', x.token));
          body.appendChild(pre);
          var cp = cmdButton('Copy', 'copy', 'small');
          cp.onclick = function () { copyText(x.token, cp); };
          body.appendChild(cp);
        });
        loadSettings();
      }).catch(oops);
    }, false);
  };
  row.appendChild(mk);
  var pv = cmdButton('What this node answers now', 'list', 'small');
  pv.onclick = function () {
    busy(pv, true);
    api('metrics', {action: 'preview'}).then(function (x) {
      busy(pv, false);
      modal('/metrics of this node, now', function (body) {
        body.appendChild(noI18n(el('pre', 'mono small mon-pre', x.text)));
      }, null, 'large');
    }).catch(function (e) { busy(pv, false); oops(e); });
  };
  row.appendChild(pv);
  card.appendChild(row);
  card.appendChild(el('h3', 'peek-h', 'prometheus.yml'));
  var pre = noI18n(el('pre', 'wrap mono small', ''));
  card.appendChild(pre);
  var cpy = cmdButton('Copy', 'copy', 'small');
  card.appendChild(cpy);
  host.appendChild(card);
  api('ha').then(function (d) {
    var targets = (d.nodes || []).map(function (n) { return (n.address || n.name) + ':443'; });
    if (!targets.length) targets = [location.hostname + ':443'];
    var y = 'scrape_configs:\n  - job_name: acme\n    scheme: https\n    metrics_path: /metrics\n    bearer_token_file: /etc/prometheus/acme.token\n'
      + '    tls_config:\n      # the CA of the nodes\' certificates, if not a public one\n      # ca_file: /etc/prometheus/acme-ca.pem\n      insecure_skip_verify: false\n'
      + '    static_configs:\n      - targets: [' + targets.map(function (t) { return "'" + t + "'"; }).join(', ') + ']\n';
    pre.textContent = y;
    cpy.onclick = function () { copyText(y, cpy); };
  }).catch(function () {});
}
