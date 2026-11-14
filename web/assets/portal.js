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
  var form = $('signin-form'), said = $('in-said') || $('krb-said'), go = $('in-go');
  if (go) form.addEventListener('submit', function (e) {
    e.preventDefault();
    said.className = 'said';
    said.textContent = '';
    /* Both asked for before anything is sent (1.0.48): empty, they were answered "wrong
       password". */
    var noName = !$('in-name').value.trim();
    if (noName || !$('in-pass').value) {
      said.className = 'said bad';
      said.textContent = noName ? 'type your name' : 'type your password';
      (noName ? $('in-name') : $('in-pass')).focus();
      return;
    }
    go.disabled = true;
    var words = go.querySelector('span');
    words.textContent = 'Signing in…';
    api('login', {name: $('in-name').value, password: $('in-pass').value, lang: window.ACME_LANG || ''}).then(function (d) {
      /* An account of acme's own with a second step: asked as the administration asks it (core.js). */
      if (d && d.mfa) { form.hidden = true; mfaStep(); return; }
      if (d && d.gate) { gateForm(d.gate); return; }
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
  if (window.PORTAL_GATE) { gateForm(window.PORTAL_GATE); return; }
  /* Signed in with a certificate (1.0.100): back here from its port - or why not. */
  var certNext = certDoor();
  /* Signed in with Windows (1.0.99): then the one-time code, as after a password. Both tried by
     themselves: Windows first, the certificate only when it did not sign in. */
  krbDoor(function (d) {
    if (d && d.gate) { var kb = $('krb-box'); if (kb) kb.hidden = true; gateForm(d.gate); return; }
    said.className = 'said good';
    said.textContent = 'Welcome.';
    location.reload();
  }, certNext);
  if ($('mfa-box') && $('mfa-box').dataset.stage) { form.hidden = true; mfaStep(); }
  else if ($('in-name')) $('in-name').focus();
  /* Sent back here because the sign-in ran out (1.0.48): said, not a page that just changed. */
  try {
    if (sessionStorage.getItem('acme-signed-out')) {
      sessionStorage.removeItem('acme-signed-out');
      said.className = 'said';
      said.textContent = 'your sign-in has run out - sign in again';
    }
  } catch (e) { }
}

/* The one-time code at every sign-in (1.0.40, as otp's before the first token, 1.0.228):
   somebody signed in with the directory password - or by the balancer in front - and a code
   went to the address or the number the directory has for them. Typed (or pasted from the
   message, "482 913" as it comes) here, the portal opens. */
function gateForm(g) {
  var form = $('signin-form');
  var box = form.parentNode;
  form.hidden = true;
  var first = box.querySelector('p.lede');
  if (first) first.hidden = true;
  var old = $('gate-box');
  if (old) old.parentNode.removeChild(old);
  var sms = g.kind === 'sms';
  var wrap = el('div', 'gate-box');
  wrap.id = 'gate-box';
  var mark = el('div', 'gate-mark');
  mark.innerHTML = iconMarkup(sms ? 'phone' : 'mail', 26);
  wrap.appendChild(mark);
  wrap.appendChild(el('h2', 'gate-title', 'Confirm it is you'));
  wrap.appendChild(el('p', 'gate-lede', sms
    ? 'To finish signing in, type the code we have just sent by SMS to'
    : 'To finish signing in, type the code we have just sent by e-mail to'));
  var where = el('div', 'gate-dest mono', g.dest || '');
  noI18n(where);
  wrap.appendChild(where);
  var f = el('form', 'gate-form');
  f.autocomplete = 'off';
  var code = textBox('', '000 000', 'codein gate-code');
  code.inputMode = 'numeric';
  code.autocomplete = 'one-time-code';
  code.maxLength = 32;
  code.setAttribute('aria-label', (typeof i18nText === 'function' && i18nText('The code')) || 'The code');
  noI18n(code);
  f.appendChild(code);
  var go = cmdButton('Confirm', 'check', 'primary');
  go.type = 'submit';
  go.className += ' gate-go';
  f.appendChild(go);
  var said = el('div', 'said gate-said');
  f.appendChild(said);
  wrap.appendChild(f);
  wrap.appendChild(el('p', 'gate-note', 'The code is good for ' + (g.minutes || 5) + ' min and only once. You can paste it as it came, with the space.'));
  var row = el('div', 'gate-actions');
  var again = cmdButton('Send it again', 'refresh', '');
  again.type = 'button';
  again.onclick = function () {
    busy(again, true);
    api('gate_again', {lang: window.ACME_LANG || ''}).then(function (d) {
      said.className = 'said gate-said good';
      said.textContent = 'A new code is on its way.';
      if (d && d.gate && d.gate.dest) where.textContent = d.gate.dest;
      code.value = '';
      code.focus();
    }).catch(function (e) {
      said.className = 'said gate-said bad';
      said.textContent = String(e.message || e);
    }).then(function () { busy(again, false); });
  };
  row.appendChild(again);
  var back = cmdButton('Back', 'undo', '');
  back.type = 'button';
  back.title = 'Sign in as somebody else';
  back.onclick = function () {
    portalSignOut(!!(g && g.sso));
  };
  row.appendChild(back);
  wrap.appendChild(row);
  box.insertBefore(wrap, form.nextSibling);
  dressButtons(wrap);
  if (g.live === false) {
    said.className = 'said gate-said bad';
    said.textContent = 'The code ran out - ask for a new one.';
  }
  var sending = false;
  function send() {
    if (sending) return;
    var typed = codeTyped(code.value);
    if (!/^[0-9]{4,10}$/.test(typed)) {
      said.className = 'said gate-said bad';
      said.textContent = 'Type the code from the message: its digits only.';
      code.select();
      return;
    }
    sending = true;
    busy(go, true);
    said.className = 'said gate-said';
    said.textContent = '';
    api('gate', {code: typed}).then(function () {
      said.className = 'said gate-said good';
      said.textContent = 'Welcome.';
      location.reload();
    }).catch(function (e) {
      sending = false;
      busy(go, false);
      said.className = 'said gate-said bad';
      said.textContent = String(e.message || e);
      code.select();
    });
  }
  f.addEventListener('submit', function (e) { e.preventDefault(); send(); });
  /* Pasted from the mail or the SMS ("482 913", a word or two around it): the digits taken,
     shown as they came in groups, and sent at once. */
  code.addEventListener('paste', function (e) {
    var t = (e.clipboardData || window.clipboardData);
    t = t ? t.getData('text') : '';
    var digits = codeTyped(t);
    if (!/^[0-9]{4,10}$/.test(digits)) {
      var m = String(t || '').match(/(?:\d[\s \-]?){4,10}/);
      digits = m ? codeTyped(m[0]) : '';
    }
    if (/^[0-9]{4,10}$/.test(digits)) {
      e.preventDefault();
      code.value = digits.length === 6 ? digits.slice(0, 3) + ' ' + digits.slice(3) : digits;
      send();
    }
  });
  code.focus();
}

var ME = null;

/* Signed out - and, signed in by the balancer (otp 1.0.239), on to its own sign-out when one is
   set: otherwise the next page would sign the person straight back in. */
function portalSignOut(sso) {
  krbSignedOut('portal');               /* never by itself again in this tab (1.0.99) */
  var done = function (d) {
    if (d && d.go) location.href = d.go;
    else location.reload();
  };
  api('logout', {sso: !!sso}).then(done, function () { location.reload(); });
}

window.ACME_PORTAL_PARTS = window.ACME_PORTAL_PARTS || [];

function portalApp(me) {
  ME = me;
  drawLangPick();
  dressButtons(document);
  $('signout').onclick = function () { portalSignOut(!!(ME && ME.sso)); };
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
        : 'You see the certificates whose owner is your account here (its name, or local: and its name), and those of the teams you are a member of.';
      body.appendChild(p);
      return;
    }
    p.textContent = 'As the directory had it when you signed in. Something wrong here is wrong there too - your IT department puts it right.';
    body.appendChild(p);
  }, (ME.kind === 'local' ? [{words: 'Change the password', icon: 'key', go: function () { closeModal(); changePassword(); }}] : [])
    .concat([{words: 'Close', close: true}]), true);
}

function changePassword() {
  modal('Change the password', function (body) {
    passwordForm(body, false, closeModal).focus();
  }, [{words: 'Close', close: true}], 'medium');
}

var ROLE_WORDS_P = {portal: 'an account of acme’s own - the enrolment pages only',
  readonly: 'an account of acme’s own - a reader',
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

/* A password to change first (1.0.14): an account of acme's own - one of the
   enrolment pages only has nowhere else to do it. In the page, not a dialog:
   until it is changed there is nothing else to show. */
function passwordForm(host, first, done) {
  /* The form every change of one's own password has (pwChangeForm, core.js): the three boxes,
     what the new one lacks said as it is typed, Enter in any of them (1.0.80). */
  var f = pwChangeForm(host, {oldLabel: first ? 'The password you were given' : 'The password you have now',
    icon: 'key', go: function (v) {
      return api('password', v).then(function () {
        toast('The password is changed.', 'good');
        done();
      });
    }});
  return f.old;
}

function drawPortal() {
  var host = $('portal');
  clear(host);
  if (ME.must_change) {
    var pc = el('div', 'card');
    pc.appendChild(stateCard('warn', 'Choose your own password first', 'The one you were given was for the first sign-in only.'));
    var first = passwordForm(pc, true, function () { location.reload(); });
    host.appendChild(pc);
    explainWhatWasDrawn(host);
    first.focus();
    return;
  }
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
