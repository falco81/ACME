/* portal.js - the certificate portal: somebody signed in with their directory
   password. Drawn with isemon's pieces (core.js); every answer comes from the
   daemon.

   What it shows past the sign-in is plugged in: a later script (index.php
   loads assets/certs-portal.js when it is there) pushes parts into
   window.ACME_PORTAL_PARTS = [function (host, me) {...}], each drawn into
   the page, in order, after the card of who is signed in. The relay of
   index.php has for them api('certs'), api('cert-download', {...}) and
   api('cert-request', {...}) (/api/portal/certs, cert_download, cert_request). */
'use strict';

function drawLangPick() {
  var host = $('langpick');
  if (!host || !window.ACME_LANGS || window.ACME_LANGS.length < 2) return;
  clear(host);
  window.ACME_LANGS.forEach(function (l) {
    var b = el('button', l.code === window.ACME_LANG ? 'on' : '', l.code.toUpperCase());
    b.type = 'button';
    b.setAttribute('data-no-i18n', '');
    b.title = l.name;
    b.onclick = function () {
      document.cookie = 'acme_lang=' + encodeURIComponent(l.code) + '; path=/; max-age=31536000; '
        + 'samesite=strict' + (location.protocol === 'https:' ? '; secure' : '');
      location.reload();
    };
    host.appendChild(b);
  });
}

/** The help an administrator wrote, as paragraphs, text and nothing else. */
function drawHelp(host, text) {
  if (!host || !text) return;
  clear(host);
  String(text).split(/\n\s*\n/).forEach(function (para) {
    var p = el('p', '');
    para.split('\n').forEach(function (line, i) {
      if (i) p.appendChild(el('br'));
      p.appendChild(document.createTextNode(line));
    });
    host.appendChild(p);
  });
}

function portalDoor() {
  drawLangPick();
  var h = $('help-text');
  if (h) drawHelp(h, h.getAttribute('data-help'));
  var form = $('signin-form'), said = $('in-said'), go = $('in-go');
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    said.className = 'said';
    said.textContent = '';
    go.disabled = true;
    var words = go.querySelector('span');
    words.textContent = 'Signing in…';
    api('login', {name: $('in-name').value, password: $('in-pass').value}).then(function (d) {
      /* An account of acme's own with a second step: asked as the administration asks it (core.js). */
      if (d && d.mfa) { form.hidden = true; mfaStep(); return; }
      said.className = 'said good';
      said.textContent = 'Welcome.';
      location.reload();
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
      go.disabled = false;
      words.textContent = 'Sign in';
      $('in-pass').value = '';
      $('in-pass').focus();
    });
  });
  if ($('mfa-box') && $('mfa-box').dataset.stage) { form.hidden = true; mfaStep(); } else $('in-name').focus();
}

var ME = null;

window.ACME_PORTAL_PARTS = window.ACME_PORTAL_PARTS || [];

function portalApp(me) {
  ME = me;
  drawLangPick();
  dressButtons(document);
  $('signout').onclick = function () {
    api('logout', {}).then(function () { location.reload(); }, function () { location.reload(); });
  };
  if ($('mebtn')) $('mebtn').onclick = aboutMe;
  /* After every script has run, so the parts plugged in are there. */
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', drawPortal);
  else drawPortal();
}

/* "About you" (1.0.113): what the directory said about the person when they
   signed in - their name and account, how to reach them, the groups that
   let them in, when the account and the password end. Read only;
   wrong here, wrong in the directory - IT puts it right there. */
function aboutMe() {
  var a = (ME && ME.about) || {};
  modal(ME.display || ME.name, function (body) {
    var dl = el('dl', 'about-me');
    var row = function (label, value, mono, words) {
      if (value === null || value === undefined || value === '') return;
      dl.appendChild(el('dt', '', label));
      var dd = el('dd', mono ? 'mono' : '');
      if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
      if (!words) noI18n(dd);       /* what the directory holds stays as it is */
      dl.appendChild(dd);
    };
    var when = function (ts) {
      if (!ts) return '';
      var d = new Date(ts * 1000);
      return d.toLocaleDateString(numLang()) + ' ' + d.toLocaleTimeString(numLang(), {hour: '2-digit', minute: '2-digit'});
    };
    row('Full name', ME.display || '');
    if (ME.kind === 'local') row('Account', ROLE_WORDS_P[ME.role] || 'an account of acme’s own', false, true);
    row('Signed in as', a.login || ME.name, true);
    row('Account', a.sam || '', true);
    row('UPN', a.upn || '', true);
    row('E-mail', a.mail || '', true);
    row('Mobile', a.mobile || '', true);
    if (a.phone && a.phone !== a.mobile) row('Phone', a.phone, true);
    row('Department', a.department || '');
    row('Job title', a.title || '');
    if ((a.groups || []).length) {
      var g = el('span', 'about-groups');
      a.groups.forEach(function (x) { g.appendChild(el('span', 'tag namepill', x)); g.appendChild(document.createTextNode(' ')); });
      row('Groups that let you in', g);
    }
    row('The account ends', a.expires ? when(a.expires) : '');
    row('Password set', a.pw_set ? when(a.pw_set) : '');
    body.appendChild(dl);
    var p = el('p', 'note small');
    if (ME.kind === 'local') {
      p.textContent = ME.sees_all ? 'As a certificate administrator you see every certificate here, not only the ones you own.'
        : 'You see the certificates whose owner is your account here (its name, or local: and its name).';
      body.appendChild(p);
      return;
    }
    p.textContent = 'As the directory had it when you signed in. Something wrong here is wrong there too - your IT department puts it right.';
    body.appendChild(p);
  }, [{words: 'Close', close: true}], true);
}

var ROLE_WORDS_P = {readonly: 'an account of acme’s own - a reader',
  certadmin: 'an account of acme’s own - a certificate administrator',
  fulladmin: 'an account of acme’s own - a full administrator'};

function stateCard(kind, title, words) {
  var box = el('div', 'bigstate');
  var mark = el('div', 'mark ' + kind);
  mark.innerHTML = iconMarkup(kind === 'ok' ? 'check' : (kind === 'warn' ? 'clock' : 'lock'), 24);
  box.appendChild(mark);
  var w = el('div', 'words');
  w.appendChild(el('b', '', title));
  if (words) w.appendChild(el('span', '', words));
  box.appendChild(w);
  return box;
}

function drawPortal() {
  var host = $('portal');
  clear(host);
  var card = el('div', 'card');
  card.appendChild(stateCard('ok', 'You are signed in', (ME.display || ME.name)
    + ' · the certificates this portal offers you are below.'));
  host.appendChild(card);
  var parts = (window.ACME_PORTAL_PARTS || []).filter(function (f) { return typeof f === 'function'; });
  parts.forEach(function (f) {
    try { f(host, ME); } catch (e) { if (window.console) console.error(e); }
  });
  if (!parts.length) card.appendChild(el('p', 'note', 'Nothing is offered here yet.'));
  if (ME.help) {
    var help = el('div', 'card help');
    var inner = el('div');
    drawHelp(inner, ME.help);
    help.appendChild(inner);
    host.appendChild(help);
  }
  explainWhatWasDrawn(host);
}
