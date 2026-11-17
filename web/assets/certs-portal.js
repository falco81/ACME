/* certs-portal.js - the certificate portal's part of the portal (index.php):
   the certificates of the person signed in (theirs, or a directory group's
   they are in) with when each runs out, their download, and asking for a new
   one - issued at once or after an administrator's approval, its job
   followed live. Plugged into portal.js through window.ACME_PORTAL_PARTS;
   drawn with core.js's pieces and certs.css's ct- classes, as the
   administration's Certificates tab is. Every answer is the daemon's:
     api('certs')                       GET  /api/portal/certs
     api('cert-job&id=N')               GET  /api/portal/cert_job
     api('cert-download', {...})        POST /api/portal/cert_download
     api('cert-request', {...})         POST /api/portal/cert_request
     api('csr-decode', {...})           POST /api/portal/csr_decode
     api('cert-csr', {...})             POST /api/portal/cert_csr
   With request profiles (Settings → Request profiles, 1.0.18) "Ask for a
   certificate" first shows the profiles the person may use; a profile's form
   asks only what it leaves to them, and a CSR is decoded and checked before
   it is sent. */
(function () {
'use strict';

var CP = {d: null, host: null, timer: null, jobTimer: null, open: null,
          /* the team workspace (1.0.125, portal-teams.js): one page of a team's certificates,
             searched on the server - `q` what is asked (team, below, q, state, page, per) */
          paged: false, q: {}, ctx: null};

if (typeof ICONS === 'object' && !ICONS.cert) {
  ICONS.cert = '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M7.5 8h9M7.5 11h5"/>'
    + '<circle cx="16" cy="16.5" r="2.6"/><path d="M14.4 18.6l-.9 3 2.5-1.1 2.5 1.1-.9-3"/>';
}

/* ---- words, as the administration says them -------------------------------- */
var STATE = {
  'new': ['being issued', 'info'], ok: ['valid', 'ok'], due: ['due', 'warn'],
  renewing: ['being issued', 'info'], failed: ['failed', 'crit'], expired: ['has expired', 'crit'],
  pending: ['waiting for a CA', 'violet'], revoked: ['revoked', 'crit'], disabled: ['switched off', 'dim'],
  'pending-approval': ['waiting for approval', 'warn'], declined: ['declined', 'crit']
};
var FORMATS = {
  'fullchain-pem': ['Full chain', 'PEM', 'The certificate and the chain above it - what nginx, Apache and most servers want.'],
  'cert-pem': ['Certificate', 'PEM', 'The certificate alone, as text (.crt).'],
  'chain-pem': ['Chain', 'PEM', 'Only the authorities above it, nearest first.'],
  'cert-der': ['Certificate', 'DER', 'The certificate alone, binary (.cer) - what Windows opens with a double click.'],
  'p7b': ['Certificate and chain', 'P7B', 'PKCS#7: the certificate and its chain in one file, for Windows and Java.'],
  pfx: ['With its private key', 'PFX', 'PKCS#12: the certificate, the chain and the private key, locked with a password you choose.']
};
var KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072',
                 'rsa-4096': 'RSA 4096', ed25519: 'Ed25519'};

function arr(v) {
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null || v === '') return [];
  return String(v).split(/[\s,;]+/).filter(Boolean);
}
/* What is wrong with a form, said where it is seen (1.0.48): below "What this profile gives", on a
   phone it was under the fold, and pressing Ask seemed to do nothing. */
function sayBad(said, words) {
  said.className = 'said bad';
  said.textContent = words;
  try { said.scrollIntoView({block: 'nearest', behavior: 'smooth'}); } catch (e) { }
}
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function stateTag(st, c) {
  var s = STATE[st] || [st || '–', 'dim'];
  /* one not issued that nothing issues (not renewed by itself, its approval never recorded) is
     "not issued yet", as the administration says - not "being issued", pulsing for good */
  if (st === 'new' && c && !running(c)) s = ['not issued yet', 'dim'];
  var t = el('span', 'tag ' + s[1] + ' ct-state', s[0]);
  if (st === 'renewing' || (st === 'new' && s[1] !== 'dim')) t.classList.add('ct-pulse');
  return t;
}
function now() { return Date.now() / 1000; }
/* What the person may do with one certificate (1.0.125): its capabilities `caps` - or, from an
   older daemon, the old rights `may` (manage gave every one of them). */
var MANAGE_CAPS = ['cert.renew', 'cert.auto', 'cert.edit', 'cert.revoke', 'cert.delete', 'cert.key',
                   'deploy.run', 'deploy.manage'];
function has(c, cap) {
  if (Array.isArray(c.caps)) {
    if (cap === 'cert.approve') return c.caps.indexOf(cap) >= 0 || MANAGE_CAPS.every(function (x) { return c.caps.indexOf(x) >= 0; });
    return c.caps.indexOf(cap) >= 0;
  }
  var may = c.may || ['view'];
  if (may.indexOf('manage') >= 0) return true;
  if (cap === 'cert.approve') return may.indexOf('approve') >= 0;
  if (cap === 'cert.request') return may.indexOf('request') >= 0;
  return cap === 'cert.view';
}
function renewable(c) {
  return !!c.issuer && c.state !== 'pending-approval' && !c.stuck && c.state !== 'declined' && c.state !== 'revoked';
}
function daysLeftOf(ts) { return ts ? Math.floor((Number(ts) - now()) / 86400) : null; }
function daysTone(d) {
  if (d === null) return 'dim';
  if (d < 7) return 'crit';
  if (d < 21) return 'warn';
  return 'ok';
}
function daysWords(d) {
  if (d === null) return '–';
  if (d < 0) return 'expired ' + (-d === 1 ? 'a day ago' : (-d) + ' days ago');
  if (d === 0) return 'ends today';
  if (d === 1) return '1 day left';
  return d + ' days left';
}
function daysTag(ts) {
  var d = daysLeftOf(ts);
  return el('span', 'ct-days ' + daysTone(d), daysWords(d));
}
function dayOnly(ts) { return ts ? dayWords(new Date(ts * 1000)) : '–'; }
function isHost(n) {
  return n.length <= 253 && /^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i.test(n);
}
function splitNames(text) {
  var seen = {}, out = [];
  String(text || '').split(/[\s,;]+/).forEach(function (n) {
    n = n.trim().toLowerCase().replace(/\.$/, '');
    if (!n || seen[n]) return;
    seen[n] = 1;
    out.push(n);
  });
  return out;
}
function underSuffix(n, sufs) {
  var bare = n.indexOf('*.') === 0 ? n.slice(2) : n;
  return sufs.some(function (s) { return bare === s || bare.slice(-(s.length + 1)) === '.' + s; });
}
function namesChips(names, most, sufs) {
  var box = el('div', 'ct-names');
  names = arr(names);
  (most ? names.slice(0, most) : names).forEach(function (n) {
    var wild = n.indexOf('*.') === 0;
    var ok = isHost(wild ? n.slice(2) : n) && (!sufs || underSuffix(n, sufs));
    var c = el('span', 'ct-name ' + (!ok ? 'refused' : (wild ? 'wild' : 'dns')));
    c.appendChild(data('span', '', n));
    if (!ok && sufs) c.appendChild(el('i', '', isHost(wild ? n.slice(2) : n) ? 'not yours to ask' : 'not a name'));
    box.appendChild(c);
  });
  if (most && names.length > most) {
    var more = el('span', 'ct-name more', '+' + (names.length - most));
    explain(more, names.slice(most).join(', '));
    box.appendChild(more);
  }
  return box;
}
function lifeBar(nb, na) {
  var bar = el('div', 'ct-life');
  var fill = el('span');
  if (nb && na && na > nb) {
    fill.style.width = Math.max(0, Math.min(100, 100 * (now() - nb) / (na - nb))).toFixed(1) + '%';
    fill.className = daysTone(daysLeftOf(na));
  }
  bar.appendChild(fill);
  return bar;
}
function saveB64(d) {
  var bin = atob(d.data_b64 || ''), bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  var url = URL.createObjectURL(new Blob([bytes], {type: d.mime || 'application/octet-stream'}));
  var a = el('a');
  a.href = url;
  a.download = d.filename || 'certificate';
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
}
function running(c) {
  /* not issued yet is "being issued" only while something will issue it (1.0.119): one not
     renewed by itself, or whose approval was never recorded, was asked about every 3 s for
     good and said "being issued…" with nothing at work */
  return !!(c.job && c.job.live) || c.state === 'renewing'
    || (c.state === 'new' && !c.not_after && !!c.auto_renew && !c.stuck);
}

/* ---- the card ---------------------------------------------------------------- */
/* A person in a team (1.0.125): the team workspace (portal-teams.js) - in none, "Your
   certificates" as it always was. Which one is asked first (GET teams); a daemon that does not
   know it, or any refusal, is the old page. */
function part(host, me) {
  var wait = skeletonCard();
  host.appendChild(wait);
  api('teams').then(function (t) {
    wait.remove();
    if (t && t.in_teams && window.ACME_PORTAL_WS && !(me && me.must_change)) {
      window.ACME_PORTAL_WS.start(host, me, t);
      return;
    }
    oldPart(host, me);
  }).catch(function (e) {
    if (e && e.stopped) return;
    wait.remove();
    oldPart(host, me);
  });
}
/* A card of grey bars while the first answer comes. */
function skeletonCard() {
  var c = el('div', 'card cp-skel-card');
  c.setAttribute('aria-busy', 'true');
  var h = el('div', 'cp-skel cp-skel-h');
  c.appendChild(h);
  for (var i = 0; i < 4; i++) {
    var r = el('div', 'cp-skel-row');
    r.appendChild(el('div', 'cp-skel cp-skel-dot'));
    r.appendChild(el('div', 'cp-skel cp-skel-line'));
    r.appendChild(el('div', 'cp-skel cp-skel-short'));
    c.appendChild(r);
  }
  return c;
}
function oldPart(host, me) {
  var card = el('div', 'card cp-card');
  card.id = 'cp-card';
  var h = el('h2', 'cp-title');
  var hic = noI18n(el('span', 'cp-title-ic'));
  hic.innerHTML = iconMarkup('cert', 18);
  h.appendChild(hic);
  h.appendChild(el('span', '', 'Your certificates'));
  var right = el('span', 'right btnrow');
  var ask = cmdButton('Ask for a certificate', 'add', 'primary small');
  ask.id = 'cp-ask';
  ask.hidden = true;
  ask.onclick = function () { askStart(); };
  right.appendChild(ask);
  h.appendChild(right);
  card.appendChild(h);
  var lede = el('p', 'note cp-lede', me && me.sees_all ? 'Every certificate kept here - you are a certificate administrator (an account of acme’s own). Each is renewed by itself before it runs out. Click one for everything about it.' : 'The certificates that are yours, or a group’s you are in. Each is renewed by itself before it runs out - download it again after that. Click one for everything about it.');
  card.appendChild(lede);
  var said = el('div', 'cp-said muted small');
  said.id = 'cp-said';
  card.appendChild(said);
  var list = el('div', 'cp-list');
  list.id = 'cp-list';
  list.appendChild(el('p', 'muted', 'Asking…'));
  card.appendChild(list);
  host.appendChild(card);
  CP.host = list;
  load();
}

function query() {
  if (!CP.paged) return 'certs';
  var q = CP.q || {}, out = 'certs';
  ['team', 'below', 'q', 'state', 'page', 'per'].forEach(function (k) {
    if (q[k] !== undefined && q[k] !== null && q[k] !== '') out += '&' + k + '=' + encodeURIComponent(q[k]);
  });
  /* "All my teams": one page of every certificate they see */
  if (out === 'certs') out += '&page=0';
  return out;
}
function load() {
  clearTimeout(CP.timer);
  /* the workspace shows something else now: it is told something changed */
  if (!CP.host || !CP.host.isConnected) {
    if (CP.ctx && CP.ctx.changed) CP.ctx.changed();
    return Promise.resolve(null);
  }
  return apiLatest('cp-certs', query()).then(function (d) {
    CP.d = d;
    draw(d);
    var busyOnes = (d.rows || []).some(running);
    CP.timer = setTimeout(load, busyOnes ? 3000 : 60000);
    if (CP.onLoad) CP.onLoad(d);
    return d;
  }).catch(function (e) {
    if (e && e.stopped) return;
    if (e && e.status === 403) {
      /* Not offered (portal_cert off): said, not an empty page (1.0.15). */
      var card = $('cp-card');
      if (card) {
        clear(card);
        card.appendChild(stateCard('warn', 'Certificates are not offered here yet',
          'Your administrator switches them on (Settings → The enrolment pages → Certificates on the portal).'));
        explainWhatWasDrawn(card);
      }
      return;
    }
    clear(CP.host);
    CP.host.appendChild(el('p', 'ct-bad', String(e.message || e)));
    CP.timer = setTimeout(load, 30000);
  });
}

function draw(d) {
  var host = CP.host, rows = d.rows || [];
  var ask = $('cp-ask');
  if (CP.paged) { drawPaged(d); return; }
  var setUp = !!(d.suffixes || []).length && !!(d.issuers || []).length;
  var profs = (d.profiles || []).length > 0;
  /* A team gives them asking (request) but the pages are not set up for it:
     the button is there, dimmed, and says why (1.0.16) - not just missing. */
  ask.hidden = !setUp && !profs && !(d.teams || []).length;
  ask.disabled = (!setUp && !profs) || (profs ? d.may_ask === false : !d.may_request);
  /* what it said when it was off goes when it is on again (1.0.119): its tooltip and its name
     for a screen reader stayed "as many as one person may" on a button that asks again */
  ask._explainHtml = '';
  ask.removeAttribute('aria-label');
  delete ask.dataset.explains;
  if (!setUp && !profs && !ask.hidden) explain(ask, 'Asking for certificates here is not set up yet: your administrator says which names and sources may be asked for (Settings → The enrolment pages).');
  else if (ask.disabled && !ask.hidden) explain(ask, 'You have asked for as many certificates as one person may. Ask the administrator for more.');
  var said = $('cp-said');
  clear(said);
  if (!ask.hidden && profs) {
    said.appendChild(document.createTextNode(d.used + ' of ' + d.most + ' requests used'));
  } else if (!ask.hidden && setUp) {
    said.appendChild(document.createTextNode(d.used + ' of ' + d.most + ' requests used'));
    said.appendChild(document.createTextNode(' · '));
    said.appendChild(document.createTextNode(d.auto ? 'issued at once' : 'an administrator approves each one'));
  }
  clear(host);
  if (!rows.length) {
    host.appendChild(emptyState('cert', 'No certificate of yours yet', ask.hidden
      ? 'When an administrator gives you one (or a group you are in), it is here.'
      : 'Ask for one above: its names, where it comes from and its key.'));
  } else {
    host.appendChild(certTable(rows));
  }
  explainWhatWasDrawn(host.parentNode);
  if (CP.open && CP.open.refresh) CP.open.refresh();
}
/* Nothing to show: an icon, a heading and one helpful sentence. */
function emptyState(icon, title, words) {
  var b = el('div', 'ct-blank big cp-empty');
  var ic = el('div', 'ct-blank-ic');
  ic.innerHTML = iconMarkup(icon, 30);
  b.appendChild(ic);
  b.appendChild(el('h3', '', title));
  if (words) b.appendChild(el('p', 'muted', words));
  return b;
}
/* One page of a team's certificates (the workspace): the table, and where in them it is. */
function drawPaged(d) {
  var host = CP.host, rows = d.rows || [];
  clear(host);
  if (!rows.length) {
    var q = CP.q || {};
    host.appendChild(q.q || q.state
      ? emptyState('search', 'Nothing matches', 'No certificate here matches what you are looking for - try other words, or another filter.')
      : emptyState('cert', 'No certificate here yet', CP.ctx && CP.ctx.mayAsk
        ? 'Ask for one: it belongs to the team, and its members see it here too.'
        : 'When the team has one, it is here.'));
  } else {
    host.appendChild(certTable(rows));
    host.appendChild(pageBar(d));
  }
  if (CP.ctx && CP.ctx.drawn) CP.ctx.drawn(d);
  explainWhatWasDrawn(host);
  if (CP.open && CP.open.refresh) CP.open.refresh();
}
function pageBar(d) {
  var bar = el('div', 'cp-pager');
  var per = d.per || 50, page = d.page || 0, total = d.total || 0;
  var from = total ? page * per + 1 : 0, to = Math.min(total, (page + 1) * per);
  bar.appendChild(el('span', 'cp-pager-w', from + '–' + to + ' of ' + total));
  if ((d.pages || 1) > 1) {
    var go = function (n) { CP.q.page = n; load(); if (CP.host) CP.host.scrollIntoView({block: 'nearest'}); };
    var back = iconButton('prev', 'The page before');
    back.disabled = page <= 0;
    back.onclick = function () { go(page - 1); };
    var next = iconButton('next', 'The next page');
    next.disabled = page >= (d.pages || 1) - 1;
    next.onclick = function () { go(page + 1); };
    bar.appendChild(back);
    bar.appendChild(noI18n(el('span', 'cp-pager-n', (page + 1) + ' / ' + d.pages)));
    bar.appendChild(next);
  }
  return bar;
}
function certTable(rows) {
  {
    var t = el('table', 'rows cp-table');
    var hr = el('tr');
    ['State', 'Certificate', 'Source', 'Expires', ''].forEach(function (x) { hr.appendChild(el('th', '', x)); });
    var th = el('thead');
    th.appendChild(hr);
    t.appendChild(th);
    var tb = el('tbody');
    rows.forEach(function (c) { tb.appendChild(row(c)); });
    t.appendChild(tb);
    var sc = el('div', 'scroll rowsonly');
    sc.appendChild(t);
    return sc;
  }
}

function row(c) {
  var tr = el('tr', 'tappable');
  tr.tabIndex = 0;
  if (c.state === 'failed' || c.state === 'expired' || c.state === 'declined') tr.classList.add('ct-hot');
  var sc = el('td');
  sc.appendChild(stateTag(c.state, c));
  tr.appendChild(sc);
  var nc = el('td', 'ct-cname');
  nc.appendChild(data('b', '', c.cn || c.name));
  if (c.via && c.via !== 'me' && c.via !== '*') {
    var g = el('span', 'tag info cp-via', c.team ? 'team ' : 'group ');
    g.appendChild(data('span', '', c.via));
    explain(g, c.team ? 'Yours through your team (Settings → Owners and teams).' : 'Yours through the directory group ' + c.via + '.');
    nc.appendChild(document.createTextNode(' '));
    nc.appendChild(g);
  }
  /* out of the waiting state with its approval never recorded (1.0.107) */
  if (c.stuck) {
    var am = el('span', 'tag warn', 'approval missing');
    explain(am, 'It left the waiting for approval, but its approval was never recorded - nothing is issued for it until it is approved.');
    nc.appendChild(document.createTextNode(' '));
    nc.appendChild(am);
  }
  nc.appendChild(namesChips(c.names, 3));
  tr.appendChild(nc);
  tr.appendChild(data('td', 'muted', c.issuer || '–'));
  var ec = el('td', 'ct-exp');
  if (c.not_after) {
    ec.appendChild(el('span', 'day', dayOnly(c.not_after)));
    ec.appendChild(el('br'));
    ec.appendChild(c.state === 'revoked' ? el('span', 'ct-days crit', 'revoked') : daysTag(c.not_after));   /* 1.0.80: green days left on a revoked one */
  } else if (running(c)) {
    ec.appendChild(el('span', 'muted small', 'being issued…'));
  } else ec.appendChild(el('span', 'muted', '–'));
  tr.appendChild(ec);
  var tools = el('td', 'rowtools');
  if (c.not_after && c.state !== 'revoked') {
    var dl = iconButton('download', 'Download it');
    dl.onclick = function (e) { e.stopPropagation(); downloadDialog(c); };
    tools.appendChild(dl);
  }
  /* the workspace: Renew now beside it, where the team gives it */
  if (CP.paged && has(c, 'cert.renew') && renewable(c) && c.not_after && !running(c)) {
    var rn = iconButton('refresh', 'Renew it now');
    rn.classList.add('cp-renew');
    rn.onclick = function (e) { e.stopPropagation(); renewDialogP(c); };
    tools.appendChild(rn);
  }
  tr.appendChild(tools);
  tr.onclick = function (e) {
    if (e.target.closest && e.target.closest('button')) return;
    certDialog(c.id);
  };
  tr.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); certDialog(c.id); } };
  return tr;
}

/* ---- one certificate ---------------------------------------------------------- */
function rowById(id) { return ((CP.d && CP.d.rows) || []).filter(function (r) { return r.id === id; })[0]; }

function certDialog(id, fresh) {
  var c = rowById(id);
  if (!c) return;
  clearTimeout(CP.jobTimer);
  var logHost = null, jobId = c.job && c.job.id;
  var buttons = [{words: 'Close', close: true}];
  /* What the team that owns it gives (Settings → Owners and teams, 1.0.16). */
  var may = c.may || ['view'];
  var manage = may.indexOf('manage') >= 0, approve = has(c, 'cert.approve');
  var waiting = c.state === 'pending-approval';
  /* out of the waiting state, its approval never recorded (1.0.107): approved or declined as a
     waiting one - Decline off, the why said, for one with a certificate (revoked instead) */
  var stuck = !!c.stuck;
  if (approve && (waiting || stuck) && !c.asked_by_me) {
    var noNo = c.may_decline === false;
    buttons.push({words: 'Decline', icon: 'ban', disabled: noNo, title: noNo ? c.decline_why : '', go: function () { modalOver(function () { declineDialog(c); }, function () { certDialog(c.id); }); }});
    /* one it would refuse (names another owner holds: may_approve): offered off, the why said */
    var noOk = c.may_approve === false;
    buttons.push({words: 'Approve', cls: 'primary', icon: 'check', disabled: noOk, title: noOk ? c.approve_why : '', go: function (b) {
      busy(b, true);
      api('cert-approve', {id: c.id, ok: 1}).then(function (d) {
        toast(d && d.job_id ? 'approved - it is being issued' : 'approved', 'good');
        load();
      }).catch(oops).then(function () { busy(b, false); });
    }});
  }
  /* ...not where its CA cannot revoke it (revoke_no, as the administration's): offered on a
     self-signed one, its job failed "Self-signed cannot revoke a certificate" */
  if (has(c, 'cert.revoke') && c.not_after && (c.state !== 'revoked' || c.alt_state === 'revoke-failed') && !c.revoke_no) {
    buttons.push({words: 'Revoke', cls: 'danger', icon: 'ban', once: true, go: function () { modalOver(function () { revokeDialogP(c); }, function () { certDialog(c.id); }); }});
  }
  if (has(c, 'cert.renew') && renewable(c)) {
    buttons.push({words: 'Renew now', icon: 'refresh', go: function (b) {
      if (!c.not_after || c.state === 'failed') { renewGo(c, b); return; }
      modalOver(function () { renewDialogP(c); }, function () { certDialog(c.id); });
    }});
  }
  /* Issued for a CSR they sent: a new CSR is the way to a new key (1.0.18). */
  if (manage && c.from_csr && !waiting && c.state !== 'declined') {
    buttons.push({words: 'Send a new CSR', icon: 'upload', go: function () {
      modalOver(function () { newCsrDialog(c); }, function () { certDialog(c.id); });
    }});
  }
  /* deleted, not revoked (1.0.125, cert.delete) - asked twice, as everything that destroys */
  if (CP.paged && has(c, 'cert.delete') && !running(c)) {
    buttons.push({words: 'Delete', icon: 'trash', go: function (b) {
      busy(b, true);
      api('cert-delete', {id: c.id}).then(function (d) {
        if (d && d.waits) { toast(d.message || 'it waits for an approval first', 'good'); return; }
        closeModal();
        toast(d.message || 'deleted', 'good');
        load();
      }).catch(oops).then(function () { busy(b, false); });
    }});
  }
  if (c.not_after && c.state !== 'revoked') buttons.push({words: 'Download', cls: 'primary', icon: 'download', go: function () {
    modalOver(function () { downloadDialog(c); });
  }});
  modal(c.cn || c.name, function (body) {
    var head = el('div', 'ct-head');
    var ic = el('div', 'ct-head-ic ' + ((STATE[c.state] || [0, 'dim'])[1]));
    ic.innerHTML = iconMarkup('cert', 26);
    head.appendChild(ic);
    var hw = el('div', 'ct-head-w');
    var t = el('div', 'ct-head-t');
    t.appendChild(data('span', 'ct-head-name', c.cn || c.name));
    t.appendChild(stateTag(c.state, c));
    if (c.not_after) t.appendChild(c.state === 'revoked' ? el('span', 'ct-days crit', 'revoked') : daysTag(c.not_after));
    hw.appendChild(t);
    hw.appendChild(namesChips(c.names));
    head.appendChild(hw);
    body.appendChild(head);
    if (c.not_before && c.not_after) {
      var lw = el('div', 'ct-lifewrap');
      lw.appendChild(el('span', 'muted small', dayOnly(c.not_before)));
      lw.appendChild(lifeBar(c.not_before, c.not_after));
      lw.appendChild(el('span', 'muted small', dayOnly(c.not_after)));
      body.appendChild(lw);
    }
    /* "You asked for it" only to the one who did - an approver of the team sees it waiting */
    if (c.state === 'pending-approval') body.appendChild(c.asked_by_me
      ? stateNote('warn', 'Waiting for an administrator', 'You asked for it; an administrator approves it (or not). You are told by mail when they have.')
      : stateNote('warn', 'Waiting for approval', approve && c.may_approve !== false
        ? 'Someone asked for it; you may approve or decline it. They are told by mail.'
        : 'Someone asked for it; an approver of its team, or an administrator, approves it (or not).'));
    if (stuck) body.appendChild(c.asked_by_me
      ? stateNote('warn', 'Its approval was never recorded', 'You asked for it; it left the waiting for approval, but its approval was not recorded - an administrator approves it (or not).')
      : stateNote('warn', 'Its approval was never recorded', approve && c.may_decline === false
        ? 'It left the waiting for approval, but its approval was not recorded - approve it, or revoke it.'
        : approve ? 'It left the waiting for approval, but its approval was not recorded - nothing is issued for it until it is approved. Approve it, or decline it.'
        : 'It left the waiting for approval, but its approval was not recorded - an approver of its team, or an administrator, approves it (or not).'));
    if (stuck && approve && !c.asked_by_me && c.may_decline === false && c.decline_why)
      body.appendChild(stateNote('crit', 'You cannot decline it', c.decline_why));
    /* why its Approve is off - unless the note on the names of another owner below says it */
    if ((waiting || stuck) && approve && !c.asked_by_me && c.may_approve === false && c.approve_why
        && !(c.held_words && c.held_words.length))
      body.appendChild(stateNote('crit', 'You cannot approve it', c.approve_why));
    /* Names another owner's certificates hold (1.0.102): only that owner's approver approves it. */
    if ((waiting || stuck) && c.held_words && c.held_words.length) {
      var hn = stateNote('warn', 'Names of another owner', 'Its names are held by certificates of another owner - only someone who may approve (or manage) for that owner, or a full administrator, approves it:');
      var hl = el('ul', '');
      c.held_words.forEach(function (w) { hl.appendChild(el('li', '', w)); });
      hn.appendChild(hl);
      body.appendChild(hn);
    }
    if (c.state === 'declined') body.appendChild(stateNote('crit', 'Declined', c.why ? 'The administrator said: ' + c.why : 'An administrator declined it.'));
    if (c.state === 'failed') body.appendChild(stateNote('crit', 'It could not be issued', (c.why || '') + ' - it is tried again by itself; the administrators know.'));
    if (c.from_csr) body.appendChild(stateNote('info', 'Issued for the CSR you sent', 'Its private key is where you made the CSR - acme never had it, so there is no PFX with the key here. Every renewal uses the same CSR, so the same key; to change the key, send a new CSR.'));
    var kv = kvTable([
      ['Name', data('span', 'mono', c.name)],
      ['Source', data('span', '', c.issuer || '–')],
      ['Key', keyWords(c)],
      c.req_profile ? ['Request profile', data('span', '', c.req_profile)] : null,
      ['Valid from', c.not_before ? stamp(c.not_before) : '–'],
      ['Valid to', c.not_after ? stamp(c.not_after) : '–'],
      ['Serial', c.serial ? data('span', 'mono small', c.serial) : '–'],
      ['Issued by', c.issuer_dn ? data('span', 'mono small', c.issuer_dn) : '–'],
      ['Renews', has(c, 'cert.auto') && c.issuer && c.state !== 'revoked' && c.state !== 'declined' && !waiting ? autoSwitch(c)
        : (c.auto_renew ? 'by itself, before it runs out' : 'not by itself')],
      ['Owner', c.via === '*' ? (c.owner ? data('span', 'mono', c.owner) : 'nobody') : (c.via && c.via !== 'me' ? ownerWords(c) : 'you')],
      ['Asked for', c.created ? stamp(c.created) : '–'],
      ['You may', Array.isArray(c.caps) ? capTags(c.caps) : mayTags(may)]
    ]);
    body.appendChild(kv);
    /* the workspace adds what it knows: the certificate's deployments, its request's timeline */
    if (CP.ctx && CP.ctx.certMore) CP.ctx.certMore(body, c);
    if (jobId) {
      var jh = el('div', 'cp-jobhead');
      jh.appendChild(el('b', '', 'Its latest job'));
      jh.appendChild(el('span', 'muted small cp-jobsaid', ''));
      body.appendChild(jh);
      logHost = el('div', 'ct-loghost');
      logHost.appendChild(el('p', 'muted', 'Asking…'));
      body.appendChild(logHost);
    }
  }, buttons, 'large');
  var ticket = modalTicket();
  CP.open = {id: id, refresh: function () {
    var n = rowById(id);
    if (!modalStill(ticket) || !n) { CP.open = null; return; }
    /* A new state, or the first job: drawn again. */
    if (n.state !== c.state || (n.job && n.job.id) !== jobId || n.not_after !== c.not_after) certDialog(id);
  }};
  if (jobId) followJob(jobId, logHost, ticket);
}

var RIGHT_WORDS_P = {view: 'see them', request: 'ask for new ones', manage: 'manage them', approve: 'approve them'};   /* after "You may:" (1.0.80) */
function ownerWords(c) {
  var w = el('span', '');
  w.appendChild(data('span', '', c.owner));
  w.appendChild(document.createTextNode(' · '));
  w.appendChild(el('span', 'muted', c.team ? 'your team' : 'a group you are in'));
  return w;
}
var CAP_WORDS_P = {'cert.view': 'see it', 'cert.request': 'ask for new ones', 'cert.renew': 'renew it',
  'cert.auto': 'switch renewing', 'cert.edit': 'change it', 'cert.revoke': 'revoke it', 'cert.delete': 'delete it',
  'cert.key': 'download its key', 'cert.approve': 'approve requests', 'deploy.view': 'see its deployments',
  'deploy.run': 'deploy it', 'deploy.manage': 'set up its deployments'};
function capTags(caps) {
  var w = el('span', 'cp-may');
  caps.forEach(function (x) {
    if (!CAP_WORDS_P[x]) return;
    w.appendChild(el('span', 'tag info', CAP_WORDS_P[x]));
    w.appendChild(document.createTextNode(' '));
  });
  if (!w.childNodes.length) w.appendChild(el('span', 'muted', 'see it'));
  explain(w, 'What the team that owns it gives you - its team manager changes it on the portal (Members).');
  return w;
}
function mayTags(may) {
  var w = el('span', 'cp-may');
  ['view', 'request', 'manage', 'approve'].forEach(function (r) {
    if (may.indexOf(r) < 0) return;
    w.appendChild(el('span', 'tag info', RIGHT_WORDS_P[r]));
    w.appendChild(document.createTextNode(' '));
  });
  explain(w, 'What the team that owns it gives you (Settings → Owners and teams) - an administrator changes it there.');
  return w;
}
/* Renewed by itself or not - at once, as the switch in the administration's list. */
function autoSwitch(c) {
  var wrap = el('span', 'cp-auto');
  var sw = switchBox(c.auto_renew);
  var words = el('span', 'small', c.auto_renew ? 'by itself, before it runs out' : 'not by itself');
  sw._input.onchange = function () {
    var on = sw._get();
    sw._input.disabled = true;
    api('cert-auto', {id: c.id, auto_renew: on}).then(function (d) {
      c.auto_renew = on;
      words.textContent = on ? 'by itself, before it runs out' : 'not by itself';
      toast(d.said || 'changed', 'good');
      load();
    }).catch(function (e) { sw._input.checked = !on; oops(e); })
      .then(function () { sw._input.disabled = false; });
  };
  wrap.appendChild(sw);
  wrap.appendChild(words);
  return wrap;
}
var REVOKE_REASONS_P = [['unspecified', 'no reason given'], ['keyCompromise', 'the key got out'],
  ['superseded', 'replaced by another'], ['cessationOfOperation', 'no longer used'],
  ['affiliationChanged', 'the owner changed']];
function revokeDialogP(c) {
  var reason = null, also = null;
  modal('Revoke ' + (c.cn || c.name), function (body) {
    body.appendChild(el('p', 'note', 'The CA that issued it is told it must not be trusted any more - this cannot be taken back. Browsers and devices that check will refuse it; deploy a new one first if it is in use.'));
    reason = selectBox(REVOKE_REASONS_P, 'unspecified');
    body.appendChild(formField('Why', reason, 'Said to the CA. "The key got out" is the one that matters most.'));
    also = switchBox(false);
    /* Issued for their CSR: a new one needs a new CSR first (a new key) - not offered here. */
    if (!c.from_csr) body.appendChild(formField('Issue a new one at once', also, 'With a new key, deployed where this one is, and renewed by itself again.'));
    else body.appendChild(el('p', 'note small', 'Issued for the CSR you sent: for a new one, send a new CSR (a new key) afterwards.'));
  }, [{words: 'No, leave it', close: true}, {words: 'Revoke it', cls: 'danger', icon: 'ban', go: function (b) {
    busy(b, true);
    api('cert-revoke', {id: c.id, reason: reason.value, renew: also._get()}).then(function (d) {
      closeModal();
      if (d && d.waits) { toast(d.message || 'it waits for an approval first', 'good'); load(); return; }
      toast('it is being revoked - its job is shown here', 'good');
      load();
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'narrow');
}
function declineDialog(c) {
  var why = null;
  modal('Decline ' + (c.cn || c.name), function (body) {
    body.appendChild(el('p', 'note', 'The person who asked is told why, by mail.'));
    why = el('textarea');
    why.rows = 3;
    body.appendChild(formField('Why', why, ''));
  }, [{words: 'No, leave it', close: true}, {words: 'Decline it', cls: 'danger', icon: 'ban', go: function (b) {
    if (!String(why.value || '').trim()) { why.focus(); toast('say why it is declined'); return; }
    busy(b, true);
    api('cert-approve', {id: c.id, ok: 0, why: why.value}).then(function () {
      closeModal();
      toast('declined - the person who asked is told', 'good');
      load();
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'narrow');
}

function stateNote(kind, title, words) {
  var box = el('div', 'cp-note ' + kind);
  box.appendChild(el('b', '', title));
  box.appendChild(el('span', '', words));
  return box;
}

var LEVEL = {ok: 'ok', info: 'info', warn: 'warn', bad: 'bad', debug: 'debug'};
function jobLog(steps) {
  /* the words of each step translated as the admin pages' are (1.0.51) - only the time stays */
  var box = el('div', 'ct-log');
  if (!steps.length) { box.appendChild(el('div', 'muted', 'Waiting to begin…')); return box; }
  steps.forEach(function (s) {
    if (!Array.isArray(s)) s = [null, 'info', String(s)];
    var line = el('div', 'ct-log-l ' + (LEVEL[s[1]] || 'info'));
    line.appendChild(noI18n(el('b', '', s[0] ? clockWords(new Date(Number(s[0]) * 1000), true) : '')));
    line.appendChild(el('i', '', {ok: '✓', bad: '✗', warn: '!'}[s[1]] || '·'));
    line.appendChild(el('span', '', String(s[2] || '')));
    box.appendChild(line);
  });
  return box;
}
function followJob(jobId, host, ticket) {
  clearTimeout(CP.jobTimer);
  api('cert-job&id=' + encodeURIComponent(jobId)).then(function (d) {
    if (!modalStill(ticket)) return;
    var j = d.job || {};
    var saidNode = $('modal-body').querySelector('.cp-jobsaid');
    if (saidNode) {
      var st = j.live ? (j.state === 'queued' ? 'waiting to begin' : 'working…') : (j.ok ? 'done' : 'failed');
      saidNode.textContent = st + (j.took_ms ? ' · ' + Math.round(j.took_ms / 100) / 10 + ' s' : '');
      saidNode.className = 'small cp-jobsaid ' + (j.live ? 'muted ct-pulse' : (j.ok ? 'cp-good' : 'ct-bad'));
    }
    var log = jobLog(j.steps || []);
    clear(host);
    host.appendChild(log);
    log.scrollTop = log.scrollHeight;
    if (j.live) CP.jobTimer = setTimeout(function () { followJob(jobId, host, ticket); }, 1200);
    else if (j.finished) load();        /* its state, its dates, its download */
  }).catch(function (e) {
    if (!modalStill(ticket)) return;
    clear(host);
    host.appendChild(el('p', 'ct-bad', String(e.message || e)));
  });
}

/* ---- download ------------------------------------------------------------------ */
function downloadDialog(c) {
  var fmts = c.formats || (CP.d && CP.d.formats) || ['fullchain-pem', 'cert-pem', 'chain-pem'];
  var order = ['fullchain-pem', 'cert-pem', 'chain-pem', 'cert-der', 'p7b', 'pfx'];
  modal('Download', function (body) {
    body.appendChild(namesChips([c.cn || c.name]));
    body.appendChild(el('p', 'note', 'The certificate as your server or device wants it. Pick a format.'));
    var list = el('div', 'cp-formats');
    order.filter(function (f) { return fmts.indexOf(f) >= 0; }).forEach(function (f) {
      var w = FORMATS[f] || [f, '', ''];
      var item = el('div', 'cp-format');
      var words = el('div', 'cp-format-w');
      var t = el('b', '', w[0]);
      t.appendChild(document.createTextNode(' '));
      t.appendChild(data('span', 'tag dim', w[1]));
      words.appendChild(t);
      words.appendChild(el('span', 'muted small', w[2]));
      item.appendChild(words);
      var go = cmdButton('Download', 'download', f === 'fullchain-pem' ? 'primary small' : 'small');
      var pw1 = null, pw2 = null;
      if (f === 'pfx') {
        var pws = el('div', 'cp-pw');
        pw1 = el('input');
        pw1.type = 'password';
        pw1.placeholder = 'a password for the file';
        pw1.autocomplete = 'new-password';
        pw2 = el('input');
        pw2.type = 'password';
        pw2.placeholder = 'the same again';
        pw2.autocomplete = 'new-password';
        pws.appendChild(pw1);
        pws.appendChild(pw2);
        words.appendChild(pws);
      }
      go.onclick = function () {
        var body2 = {id: c.id, format: f};
        if (f === 'pfx') {
          if ((pw1.value || '').length < 8) { toast('the password is at least 8 characters', 'bad'); pw1.focus(); return; }
          if (pw1.value !== pw2.value) { toast('the two passwords are not the same', 'bad'); pw2.focus(); return; }
          body2.password = pw1.value;
        }
        busy(go, true);
        api('cert-download', body2).then(function (d) {
          if (d && d.waits) { toast(d.message || 'it waits for an approval first', 'good'); return; }
          saveB64(d);
          toast('downloaded: ' + (d.filename || ''), 'good');
          if (pw1) { pw1.value = ''; pw2.value = ''; }
        }).catch(oops).then(function () { busy(go, false); });
      };
      item.appendChild(go);
      list.appendChild(item);
    });
    body.appendChild(list);
    if (fmts.indexOf('pfx') < 0) body.appendChild(el('p', 'note small', c.from_csr ? 'Issued for the CSR you sent: its private key is where you made the CSR.' : 'The private key stays where it was made: the server that uses the certificate has it.'));
  }, [{words: 'Close', close: true}]);
}

/* ---- asking for one -------------------------------------------------------------- */
/* The team asked for (the workspace): its limits in force, said above the form. */
function teamPolicy() { return (CP.ctx && CP.ctx.policy && CP.ctx.policy()) || null; }
function limitsNote(body) {
  if (CP.ctx && CP.ctx.limitsNote) {
    var n = CP.ctx.limitsNote();
    if (n) body.appendChild(n);
  }
}
function askDialog() {
  var d = CP.d || {};
  var sufs = d.suffixes || [], iss = d.issuers || [];
  var pol = teamPolicy();
  if (pol && Array.isArray(pol.suffixes) && pol.suffixes.length) sufs = pol.suffixes;
  var namesBox, chips, issuerSel, keySel, noteBox, said, teamSel = null;
  var check = function () {
    var names = splitNames(namesBox.value);
    clear(chips);
    if (names.length) chips.appendChild(namesChips(names, 0, sufs));
    return names;
  };
  modal('Ask for a certificate', function (body) {
    limitsNote(body);
    var tp = teamPolicy(), ta = tp && tp.approval && (typeof tp.approval === 'string' ? tp.approval : tp.approval.mode);
    body.appendChild(el('p', 'note', ta === 'always' || ta === 'outside'
      ? 'An approver of the team approves it first (the team’s rule); you are told by mail when they have. Then it is issued, and renewed by itself before it runs out.'
      : d.auto
      ? 'It is issued as soon as you ask, and renewed by itself before it runs out.'
      : 'An administrator approves it first; you are told by mail when they have. Then it is issued, and renewed by itself before it runs out.'));
    namesBox = el('textarea', 'cp-names');
    namesBox.rows = 3;
    namesBox.spellcheck = false;
    namesBox.placeholder = 'www.' + (sufs[0] || 'example.com') + '\n' + 'app.' + (sufs[0] || 'example.com');
    namesBox.oninput = check;
    body.appendChild(formField('Its names', namesBox, ''));
    var hint = el('div', 'says small muted');
    hint.appendChild(el('span', '', 'One name a line - the first is the one it is called by.'));
    hint.appendChild(document.createTextNode(' '));
    hint.appendChild(el('span', '', 'Names under:'));
    hint.appendChild(document.createTextNode(' '));
    hint.appendChild(data('b', 'mono', sufs.join(', ')));
    body.lastChild.appendChild(hint);
    chips = el('div', 'cp-chips');
    body.lastChild.appendChild(chips);
    issuerSel = selectBox(iss.map(function (i) { return [i, i]; }), iss[0]);
    noI18n(issuerSel);
    if (iss.length > 1) body.appendChild(formField('Where it comes from', issuerSel, 'The certificate authority that issues it.'));
    keySel = selectBox((d.key_types || ['ec-256', 'rsa-2048']).map(function (k) { return [k, KEY_WORDS[k] || k]; }), 'ec-256');
    body.appendChild(formField('Its key', keySel, 'EC P-256 suits nearly everything; RSA 2048 for old devices that know nothing else.'));
    /* Owned by a team they may ask for (Settings → Owners and teams), or by them. */
    var askTeams = CP.ctx && CP.ctx.askTeams ? CP.ctx.askTeams() : null;
    if (askTeams && askTeams.length) {
      teamSel = selectBox(askTeams.map(function (t) { return [t, t]; }), askTeams.indexOf(CP.ctx.team()) >= 0 ? CP.ctx.team() : askTeams[0]);
      teamSel.id = 'cp-team';
      noI18n(teamSel);
      body.appendChild(formField('Whose it is', teamSel, 'The team it belongs to: its members see it here too.'));
    } else if ((d.teams || []).length) {
      teamSel = selectBox([['', 'me']].concat(d.teams.map(function (t) { return [t, t]; })), d.teams.length === 1 ? d.teams[0] : '');
      teamSel.id = 'cp-team';
      teamSel.options[0].textContent = 'me';
      Array.prototype.slice.call(teamSel.options, 1).forEach(function (o) { noI18n(o); });
      body.appendChild(formField('Whose it is', teamSel, 'The team it belongs to: its members see it here too.'));
    }
    noteBox = el('textarea');
    noteBox.rows = 2;
    noteBox.placeholder = 'what it is for (the administrator sees this)';
    body.appendChild(formField('A note', noteBox, ''));
    said = el('div', 'said');
    body.appendChild(said);
  }, [{words: 'Close', close: true}, {words: d.auto ? 'Ask and issue' : 'Ask for it', cls: 'primary', icon: 'add', go: function (b) {
    var names = check();
    said.className = 'said';
    said.textContent = '';
    if (!names.length) { sayBad(said, 'Which names? One a line.'); namesBox.focus(); return; }
    var bad = names.filter(function (n) { return !underSuffix(n, sufs); });
    if (bad.length) { sayBad(said, 'Only names under ' + sufs.join(', ') + ' may be asked for here.'); namesBox.focus(); return; }
    busy(b, true);
    api('cert-request', {names: names, issuer: issuerSel.value, key_type: keySel.value, note: noteBox.value,
                         team: teamSel ? teamSel.value : ''}).then(function (got) {
      toast(got.waits ? (CP.ctx ? 'asked for - it waits for approval' : 'asked for - it waits for an administrator') : 'asked for - it is being issued', 'good');
      closeModal();
      load().then(function () { if (got.id && !got.waits) certDialog(got.id); });
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
    }).then(function () { busy(b, false); });
  }}]);
  check();
}

/* ---- renewing, after it is said what that does ------------------------------------ */
function keyWords(c) {
  var w = el('span', '');
  w.appendChild(data('span', '', KEY_WORDS[c.key_type] || c.key_type || '–'));
  if (c.from_csr) {
    w.appendChild(document.createTextNode(' · '));
    w.appendChild(el('span', 'muted', 'from your CSR'));
  }
  return w;
}
function renewGo(c, b) {
  busy(b, true);
  return api('cert-renew', {id: c.id}).then(function () {
    toast('it is being renewed - its job is shown here', 'good');
    load();
  }).catch(oops).then(function () { busy(b, false); });
}
function renewDialogP(c) {
  modal('Renew ' + (c.cn || c.name) + ' now?', function (body) {
    body.appendChild(el('p', 'note', 'A new certificate is asked for at once, whether it is due or not - the one in use now stays valid until it runs out (it is not revoked).'));
    body.appendChild(kvTable([
      c.issuer ? ['From', data('span', '', c.issuer)] : null,
      ['Its key', c.from_csr ? 'the same key - the CSR you sent is used again' : 'a new key'],
      ['Then', 'download it again where it is used']
    ]));
  }, [{words: 'No, leave it', close: true}, {words: 'Renew now', cls: 'primary', icon: 'refresh', go: function (b) {
    busy(b, true);
    api('cert-renew', {id: c.id}).then(function () {
      closeModal();
      toast('it is being renewed - its job is shown here', 'good');
      load().then(function () { certDialog(c.id); });
    }).catch(oops).then(function () { busy(b, false); });
  }}], 'narrow');
}

/* ---- a CSR: pasted or a file, decoded by the server, shown before anything is asked --- */
var RDN_WORDS = {CN: 'Common name', O: 'Organisation', OU: 'Unit', L: 'City', ST: 'Region', C: 'Country',
                 emailAddress: 'E-mail', DC: 'Domain part', serialNumber: 'Serial number', street: 'Street',
                 postalCode: 'Postal code', title: 'Title', GN: 'Given name', SN: 'Surname', UID: 'User ID'};
var EKU_WORDS = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
                 emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing'};
function okMark(ok) {
  var i = el('span', 'cp-mark ' + (ok === true ? 'ok' : (ok === false ? 'bad' : 'note')));
  noI18n(i);
  i.textContent = ok === true ? '✓' : (ok === false ? '✗' : '!');
  return i;
}
/* The box for one: a text area and a file. read() -> Promise of {csr} or {csr_b64}. */
function csrInput(onChange) {
  var wrap = el('div', 'cp-csr-in');
  var box = el('textarea', 'cp-csr-text');
  box.rows = 6;
  box.spellcheck = false;
  box.placeholder = '-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----';
  noI18n(box);
  var file = el('input');
  file.type = 'file';
  file.accept = '.csr,.req,.pem,.der,.p10,.txt';
  file.hidden = true;
  var row = el('div', 'btnrow cp-csr-row');
  var pick = cmdButton('Choose a file', 'upload', 'small');
  var fname = el('span', 'muted small');
  noI18n(fname);
  pick.onclick = function () { file.click(); };
  var b64 = null;
  file.onchange = function () {
    var f = file.files && file.files[0];
    if (!f) return;
    if (f.size > 65536) { toast('a CSR is a few kilobytes - that file is too big', 'bad'); return; }
    var rd = new FileReader();
    rd.onload = function () {
      var bytes = new Uint8Array(rd.result), bin = '';
      for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
      if (/-----BEGIN/.test(bin)) { box.value = bin; b64 = null; } else { b64 = btoa(bin); box.value = ''; }
      fname.textContent = f.name;
      if (onChange) onChange();
    };
    rd.readAsArrayBuffer(f);
  };
  box.oninput = function () { b64 = null; fname.textContent = ''; if (onChange) onChange(); };
  row.appendChild(pick);
  row.appendChild(fname);
  wrap.appendChild(box);
  wrap.appendChild(row);
  wrap.appendChild(file);
  wrap._read = function () {
    if (b64) return {csr_b64: b64};
    return String(box.value || '').trim() ? {csr: box.value} : null;
  };
  return wrap;
}
function csrSection(title) {
  var sec = el('div', 'cp-csr-sec');
  sec.appendChild(el('div', 'cp-csr-h', title));
  return sec;
}
/* What the server said of it: its content, and each check against the profile. */
function csrCard(rv) {
  var c = rv.csr || {};
  var card = el('div', 'cp-csr-card ' + (rv.fits ? 'fits' : 'nofit'));
  var head = el('div', 'cp-csr-top');
  var ic = el('div', 'ct-head-ic ' + (rv.fits ? 'ok' : 'crit'));
  ic.innerHTML = iconMarkup('cert', 22);
  head.appendChild(ic);
  var hw = el('div', 'cp-csr-tw');
  hw.appendChild(data('b', 'cp-csr-cn', c.cn || (rv.names || [])[0] || '–'));
  hw.appendChild(el('span', 'tag ' + (rv.fits ? 'ok' : 'crit'), rv.fits ? 'fits the profile' : 'does not fit the profile'));
  head.appendChild(hw);
  card.appendChild(head);
  var grid = el('div', 'cp-csr-grid');
  /* The subject, each RDN as written */
  var sub = csrSection('Subject');
  var st = el('table', 'plain tight cp-rdn');
  var sb = el('tbody');
  (c.subject_list || []).forEach(function (p) {
    var tr_ = el('tr');
    var k = el('td', 'muted');
    k.appendChild(el('span', '', RDN_WORDS[p[0]] || p[0]));
    k.appendChild(data('span', 'mono cp-rdn-k', ' ' + p[0]));
    tr_.appendChild(k);
    tr_.appendChild(data('td', '', p[1]));
    sb.appendChild(tr_);
  });
  if (!(c.subject_list || []).length) { var e = el('tr'); e.appendChild(el('td', 'muted', 'an empty subject')); sb.appendChild(e); }
  st.appendChild(sb);
  sub.appendChild(st);
  grid.appendChild(sub);
  /* Its names */
  var nm = csrSection('Names (subjectAltName)');
  var chips = el('div', 'ct-names');
  var byName = {};
  (rv.checks || []).forEach(function (x) { if (x.what === 'name') byName[x.name] = x; });
  (c.san || []).forEach(function (p) {
    var v = p[1], chk = byName[String(v).toLowerCase()];
    var kind = p[0] === 'DNS' ? (String(v).indexOf('*.') === 0 ? 'wild' : 'dns') : (p[0] === 'IP' ? 'ip' : (p[0] === 'email' ? 'email' : 'uri'));
    var chip = el('span', 'ct-name ' + (chk && !chk.ok ? 'refused' : kind));
    if (chk) chip.appendChild(okMark(chk.ok));
    chip.appendChild(data('span', '', (p[0] === 'DNS' ? '' : p[0] + ':') + v));
    if (chk && !chk.ok) chip.appendChild(el('i', '', chk.said));
    chips.appendChild(chip);
  });
  if (!(c.san || []).length) {
    if ((rv.names || []).length) {
      rv.names.forEach(function (n) { var chip = el('span', 'ct-name dns'); chip.appendChild(data('span', '', n)); chips.appendChild(chip); });
      nm.appendChild(el('p', 'muted small', 'No subjectAltName: the common name is taken as its name.'));
    } else chips.appendChild(el('span', 'muted small', 'none'));
  }
  nm.appendChild(chips);
  grid.appendChild(nm);
  /* The key, the signature, what it is for */
  var kk = csrSection('Key and signature');
  kk.appendChild(kvTable([
    ['Key', data('span', '', (KEY_WORDS[c.key_type] || c.key_type || '?') + (c.key_bits ? ' · ' + c.key_bits + ' bit' : ''))],
    ['Signature', sigWords(c)],
    ['Key usage', (c.key_usage || []).length ? data('span', 'mono small', c.key_usage.join(', ')) : 'not said'],
    ['Used for', (c.eku || []).length ? ekuChips(c.eku) : 'not said'],
    ['OCSP must-staple', c.must_staple ? 'yes' : 'no'],
    c.challenge_password ? ['Challenge password', 'present (not used here)'] : null,
    ['Public key', data('span', 'mono small cp-sha', (c.sha256 || '').replace(/(.{2})(?!$)/g, '$1:').slice(0, 47) + '…')]
  ]));
  grid.appendChild(kk);
  card.appendChild(grid);
  /* The checks, one by one */
  var ch = csrSection('Against the profile');
  var list = el('div', 'cp-checks');
  var WHAT = {signature: 'Signature', name: 'DNS name', names: 'Names', count: 'How many names', other: 'Other names',
              refused: 'Refused', eku: 'Extended key usage',
              key: 'Key type', subject: 'Subject', fit: 'Source and validation', csr: 'CSR'};
  (rv.checks || []).forEach(function (x) {
    var line = el('div', 'cp-check ' + (x.ok === true ? 'ok' : (x.ok === false ? 'bad' : 'note')));
    line.appendChild(okMark(x.ok));
    var w = el('div', 'cp-check-w');
    var t = el('b', '', WHAT[x.what] || x.what);
    if (x.name) { t.appendChild(document.createTextNode(' ')); t.appendChild(data('span', 'mono', x.name)); }
    w.appendChild(t);
    w.appendChild(el('span', 'muted small', x.said || ''));
    line.appendChild(w);
    list.appendChild(line);
  });
  ch.appendChild(list);
  card.appendChild(ch);
  /* What the certificate will say beside what the CSR says */
  var cmp = csrSection('The subject: in the CSR and in the certificate');
  var HOW = {names: 'from the names', fixed: 'fixed by the profile', person: 'yours (the CSR, or the default)', off: 'not put in'};
  cmp.appendChild(listTable(['Field', 'In the CSR', 'In the certificate', 'Taken'], (rv.subject || []).filter(function (r) {
    return r.csr || r.cert;
  }), function (r) {
    var row = el('tr');
    var k = el('td', '');
    k.appendChild(el('span', '', RDN_WORDS[r.field] || r.field));
    row.appendChild(k);
    row.appendChild(r.csr ? data('td', '', r.csr) : el('td', 'muted', '–'));
    var cert = r.cert ? data('td', r.csr && r.csr !== r.cert ? 'cp-changed' : '', r.cert) : el('td', 'muted', '–');
    row.appendChild(cert);
    row.appendChild(el('td', 'muted small', HOW[r.how] || r.how));
    return row;
  }, 'plain tight cp-subj|The subject is empty'));
  if ((rv.eku || []).length) {
    var eu = el('p', 'muted small');
    eu.appendChild(el('span', '', 'The certificate is for:'));
    eu.appendChild(document.createTextNode(' '));
    eu.appendChild(ekuChips(rv.eku));
    cmp.appendChild(eu);
  }
  card.appendChild(cmp);
  return card;
}
function sigWords(c) {
  var w = el('span', 'cp-sig');
  w.appendChild(okMark(!!c.sig_ok));
  w.appendChild(el('span', c.sig_ok ? 'cp-good' : 'ct-bad', c.sig_ok ? 'valid' : 'not valid'));
  if (c.sig_alg) { w.appendChild(document.createTextNode(' · ')); w.appendChild(data('span', 'mono small', c.sig_alg)); }
  return w;
}
function ekuChips(list) {
  var w = el('span', 'cp-ekus');
  arr(list).forEach(function (e) {
    var t = el('span', 'tag info', EKU_WORDS[e] || e);
    if (!EKU_WORDS[e]) noI18n(t);
    w.appendChild(t);
    w.appendChild(document.createTextNode(' '));
  });
  return w;
}

/* A new CSR for one issued for a CSR (the right manage): a new key. */
function newCsrDialog(c) {
  var input = null, host = null, sent = null;
  modal('A new CSR for ' + (c.cn || c.name), function (body) {
    body.appendChild(el('p', 'note', 'A CSR made with a new key, for the same names - it is checked, kept and the certificate issued again at once. From then on, every renewal uses it.'));
    input = csrInput(function () { clear(host); });
    body.appendChild(formField('The CSR', input, 'Paste it (PEM), or choose its file (PEM or DER).'));
    host = el('div', 'cp-csr-host');
    body.appendChild(host);
    sent = el('div', 'said');
    body.appendChild(sent);
  }, [{words: 'No, leave it', close: true}, {words: 'Send it', cls: 'primary', icon: 'upload', go: function (b) {
    var got = input._read();
    if (!got) { toast('paste the CSR, or choose its file', 'bad'); return; }
    busy(b, true);
    api('cert-csr', Object.assign({id: c.id}, got)).then(function (d) {
      closeModal();
      toast(d.message || 'the new CSR was taken', 'good');
      load().then(function () { certDialog(c.id); });
    }).catch(function (e) { sent.className = 'said bad'; sent.textContent = String(e.message || e); })
      .then(function () { busy(b, false); });
  }}], 'large');
}

/* ---- asking: from a request profile, or the free form --------------------------------- */
function askProfiles() {
  var d = CP.d || {}, pol = teamPolicy();
  var profs = d.profiles || [];
  if (pol && Array.isArray(pol.profiles)) profs = profs.filter(function (p) { return pol.profiles.indexOf(p.name) >= 0; });
  return profs;
}
function askFree() {
  var d = CP.d || {}, pol = teamPolicy();
  if (pol && pol.free_form === false) return false;
  /* without profiles the free form was always the way (as before) */
  return (d.profiles || []).length ? !!d.free_form : true;
}
function askStart() {
  var profs = askProfiles(), free = askFree();
  if (!profs.length && !free) {
    toast('your team asks only from request profiles, and none of them is offered to you - ask its manager', 'bad');
    return;
  }
  if (!profs.length) { askDialog(); return; }
  if (profs.length === 1 && !free) { profileDialog(profs[0]); return; }
  pickerDialog();
}
function pickerDialog() {
  var d = CP.d || {};
  modal('Ask for a certificate', function (body) {
    limitsNote(body);
    body.appendChild(el('p', 'note', 'Pick what you need. Each kind says where the certificate comes from and what is in it - you give only its names and what is left to you.'));
    var list = el('div', 'cp-profiles');
    askProfiles().forEach(function (p) {
      var card = el('button', 'cp-prof');
      card.type = 'button';
      var t = el('div', 'cp-prof-t');
      t.appendChild(data('b', '', p.name));
      if (p.approval) t.appendChild(el('span', 'tag warn', 'approved first'));
      else t.appendChild(el('span', 'tag ok', 'issued at once'));
      card.appendChild(t);
      if (p.description) card.appendChild(data('div', 'cp-prof-d', p.description));
      card.appendChild(profileChips(p));
      card.onclick = function () { profileDialog(p, true); };
      list.appendChild(card);
    });
    if (askFree()) {
      var other = el('button', 'cp-prof cp-prof-free');
      other.type = 'button';
      var t2 = el('div', 'cp-prof-t');
      t2.appendChild(el('b', '', 'Something else'));
      other.appendChild(t2);
      other.appendChild(el('div', 'cp-prof-d', 'Its names, where it comes from and its key - chosen by you.'));
      other.onclick = function () { askDialog(); };
      list.appendChild(other);
    }
    body.appendChild(list);
  }, [{words: 'Close', close: true}], 'large');
}
/* What one gives, in a few chips. */
function profileChips(p) {
  var w = el('div', 'cp-prof-c');
  var add = function (cls, words, mono) { var t = (mono ? data : el)('span', 'tag ' + cls, words); w.appendChild(t); return t; };
  add('info', p.issuer, true);
  p.suffixes.slice(0, 3).forEach(function (sx) { add('dim', (p.wildcards ? '*.' : '') + sx, true); });
  if (p.make_key) add('dim', 'key made for you');
  if (p.csr) add('violet', 'your CSR');
  if (p.days) add('dim', p.days + ' days');
  arr(p.eku).forEach(function (e) { add('dim', EKU_WORDS[e] || e); });
  if (p.pfx && p.make_key) add('dim', 'PFX with the key');
  return w;
}
/* What the profile fixes, read-only. */
function profileFacts(p) {
  var subj = el('span', 'cp-fixed');
  (p.subject || []).filter(function (f) { return f.mode === 'fixed'; }).forEach(function (f) {
    var x = el('span', 'tag dim cp-fixed-f');
    x.appendChild(el('span', '', RDN_WORDS[f.field] || f.field));
    x.appendChild(document.createTextNode(': '));
    x.appendChild(data('span', '', f.value));
    subj.appendChild(x);
  });
  if (!subj.childNodes.length) subj.appendChild(el('span', 'muted', 'nothing beside the names'));
  var names = el('span', '');
  names.appendChild(data('span', 'mono', p.suffixes.join(', ')));
  names.appendChild(document.createTextNode(' · '));
  names.appendChild(el('span', 'muted', p.wildcards ? 'wildcards too' : 'no wildcards'));
  names.appendChild(document.createTextNode(' · '));
  names.appendChild(el('span', 'muted', 'at most ' + p.max_names + ' name(s)'));
  var owner = p.owner === 'fixed' ? data('span', '', p.owner_team) : el('span', '', p.owner === 'team' ? 'a team of yours, chosen below' : 'you');
  var renew = el('span', '', p.auto_renew ? (p.renew_days ? 'by itself, ' + p.renew_days + ' days before the end' : 'by itself, before it runs out') : 'not by itself');
  return kvTable([
    ['From', (function () {        /* the module's title translated, the name as it is (1.0.51) */
      var f = el('span', '');
      f.appendChild(data('span', '', p.issuer));
      if (p.issuer_title) { f.appendChild(document.createTextNode(' · ')); f.appendChild(el('span', '', p.issuer_title)); }
      return f;
    }())],
    p.challenge ? ['Names proved by', data('span', '', p.challenge)] : null,
    ['Names under', names],
    ['In the subject', subj],
    p.days ? ['Valid for', p.days + ' days'] : null,
    arr(p.eku).length ? ['Used for', ekuChips(p.eku)] : null,
    ['Renews', renew],
    ['Approval', p.approval ? 'an approver of its team, or an administrator, approves it first' : 'issued at once'],
    ['Owner', owner],
    (p.tags || []).length ? ['Tags', data('span', 'mono', p.tags.join(', '))] : null
  ]);
}
function profileDialog(p, fromPicker) {
  var d = CP.d || {};
  var how = p.make_key ? 'key' : 'csr';
  var f = {subject: {}}, said = null, keyHost = null, csrHost = null, review = null, reviewKey = '';
  var namesOk = function (names) {
    return names.filter(function (n) {
      var wild = n.indexOf('*.') === 0;
      return !isHost(wild ? n.slice(2) : n) || !underSuffix(n, p.suffixes) || (wild && !p.wildcards);
    });
  };
  var drawChips = function () {
    var names = splitNames(f.names.value);
    clear(f.chips);
    if (names.length) {
      var box = el('div', 'ct-names');
      names.forEach(function (n, i) {
        var wild = n.indexOf('*.') === 0;
        var why = !isHost(wild ? n.slice(2) : n) ? 'not a name' : (!underSuffix(n, p.suffixes) ? 'not yours to ask'
          : (wild && !p.wildcards ? 'no wildcards here' : (i >= p.max_names ? 'one too many' : '')));
        var c = el('span', 'ct-name ' + (why ? 'refused' : (wild ? 'wild' : 'dns')));
        c.appendChild(okMark(!why));
        c.appendChild(data('span', '', n));
        if (why) c.appendChild(el('i', '', why));
        box.appendChild(c);
      });
      f.chips.appendChild(box);
    }
    return names;
  };
  var decode = function (btn) {
    var got = f.csr._read();
    clear(review);
    reviewKey = '';
    if (!got) { review.appendChild(el('p', 'muted small', 'Paste the CSR, or choose its file, then Decode it.')); return Promise.resolve(null); }
    if (btn) busy(btn, true);
    review.appendChild(el('p', 'muted', 'Decoding…'));
    return api('csr-decode', Object.assign({profile: p.name}, got)).then(function (rv) {
      clear(review);
      review.appendChild(csrCard(rv));
      reviewKey = JSON.stringify(got);
      f.fits = rv.fits;
      explainWhatWasDrawn(review);
      return rv;
    }).catch(function (e) {
      clear(review);
      review.appendChild(el('p', 'ct-bad', String(e.message || e)));
      return null;
    }).then(function (rv) { if (btn) busy(btn, false); return rv; });
  };
  var showHow = function () {
    keyHost.hidden = how !== 'key';
    csrHost.hidden = how !== 'csr';
  };
  modal('Ask for a certificate', function (body) {
    limitsNote(body);
    var ph = el('div', 'cp-prof-head');
    ph.appendChild(data('b', 'cp-prof-name', p.name));
    ph.appendChild(el('span', 'tag ' + (p.approval ? 'warn' : 'ok'), p.approval ? 'approved first' : 'issued at once'));
    body.appendChild(ph);
    if (p.description) body.appendChild(data('p', 'note cp-prof-lede', p.description));
    var facts = el('details', 'cp-facts');
    facts.open = !fromPicker || window.innerWidth > 640;
    facts.appendChild(el('summary', '', 'What this profile gives'));
    facts.appendChild(profileFacts(p));
    body.appendChild(facts);
    if (p.make_key && p.csr) {
      var seg = el('div', 'seg cp-how');
      [['key', 'acme makes the key'], ['csr', 'Send a CSR']].forEach(function (o) {
        var b = el('button', o[0] === how ? 'on' : '', o[1]);
        b.type = 'button';
        b.onclick = function () {
          how = o[0];
          Array.prototype.forEach.call(seg.children, function (x) { x.classList.toggle('on', x === b); });
          showHow();
        };
        seg.appendChild(b);
      });
      body.appendChild(formField('How', seg, 'A key made here (and kept for you), or a CSR made where the key is to stay - your server, your device.'));
    }
    /* -- acme makes the key: the names, the key, the subject's own fields -- */
    keyHost = el('div', 'cp-how-key');
    f.names = el('textarea', 'cp-names');
    f.names.rows = Math.min(4, Math.max(2, p.max_names));
    f.names.spellcheck = false;
    /* a client's certificate (VPN, a device) is named after it, not after a web site (1.0.96) */
    var clientOnly = arr(p.eku).length && arr(p.eku).indexOf('serverAuth') < 0;
    f.names.placeholder = (clientOnly ? 'device1.' : 'www.') + (p.suffixes[0] || 'example.com') +
      (p.max_names > 1 ? '\n' + (clientOnly ? 'device2.' : 'app.') + (p.suffixes[0] || 'example.com') : '');
    f.names.oninput = drawChips;
    keyHost.appendChild(formField(p.max_names > 1 ? 'Its names' : 'Its name', f.names, ''));
    var hint = el('div', 'says small muted');
    hint.appendChild(el('span', '', p.max_names > 1 ? 'One name a line - the first is the one it is called by.' : 'The name it is called by (CN).'));
    hint.appendChild(document.createTextNode(' '));
    hint.appendChild(el('span', '', 'Names under:'));
    hint.appendChild(document.createTextNode(' '));
    hint.appendChild(data('b', 'mono', p.suffixes.join(', ')));
    keyHost.lastChild.appendChild(hint);
    f.chips = el('div', 'cp-chips');
    keyHost.lastChild.appendChild(f.chips);
    var g = el('div', 'formgrid');
    f.key = selectBox(p.key_types.map(function (k) { return [k, KEY_WORDS[k] || k]; }), p.key_default);
    /* the hint says what the profile picks (1.0.96: it praised EC P-256 over RSA 2048 picked) */
    if (p.key_types.length > 1) g.appendChild(formField('Its key', f.key, /^rsa/.test(String(p.key_default || ''))
      ? 'This request profile picks RSA - what the devices it is for take; EC P-256 suits nearly everything else.'
      : 'EC P-256 suits nearly everything; RSA 2048 for old devices that know nothing else.'));
    (p.subject || []).filter(function (x) { return x.mode === 'person'; }).forEach(function (x) {
      var b = textBox(x.value, x.field === 'C' ? 'CZ' : (x.field === 'emailAddress' ? 'it@example.cz' : ''), '');
      noI18n(b);
      f.subject[x.field] = b;
      g.appendChild(formField(RDN_WORDS[x.field] || x.field, b, x.value ? 'Filled in for you - change it if it is not right.' : ''));
    });
    if (g.childNodes.length) keyHost.appendChild(g);
    body.appendChild(keyHost);
    /* -- a CSR of theirs: pasted or a file, decoded and checked first -- */
    csrHost = el('div', 'cp-how-csr');
    f.csr = csrInput(function () { clear(review); reviewKey = ''; });
    csrHost.appendChild(formField('Your CSR', f.csr, 'Paste it (PEM), or choose its file (PEM or DER). It is decoded and checked against this profile before anything is asked.'));
    var dec = cmdButton('Decode it', 'search', 'small');
    dec.classList.add('cp-decode');
    dec.onclick = function () { decode(dec); };
    var dr = el('div', 'btnrow');
    dr.appendChild(dec);
    csrHost.appendChild(dr);
    review = el('div', 'cp-csr-host');
    csrHost.appendChild(review);
    csrHost.appendChild(el('p', 'note small', 'Renewed with the same CSR - so the same key. To change the key later, send a new CSR from the certificate.'));
    body.appendChild(csrHost);
    /* -- whose it is, a note -- */
    var g2 = el('div', 'formgrid');
    if (p.owner === 'team') {
      var here = CP.ctx && CP.ctx.team ? CP.ctx.team() : '';
      f.team = selectBox(p.owner_choices.map(function (t) { return [t, t]; }), p.owner_choices.length === 1 ? p.owner_choices[0]
        : (p.owner_choices.indexOf(here) >= 0 ? here : ''));
      noI18n(f.team);
      g2.appendChild(formField('Whose it is', f.team, 'The team it belongs to: its members see it here too.'));
    }
    f.note = el('textarea');
    f.note.rows = 2;
    f.note.placeholder = 'what it is for (the administrator sees this)';
    var nf = formField('A note', f.note, '');
    nf.classList.add('wide');
    g2.appendChild(nf);
    body.appendChild(g2);
    said = el('div', 'said');
    body.appendChild(said);
    showHow();
  }, [{words: fromPicker ? 'Back' : 'Cancel', icon: fromPicker ? 'prev' : null, go: fromPicker ? function () { pickerDialog(); } : null, close: !fromPicker},
      {words: p.approval ? 'Ask for it' : 'Ask and issue', cls: 'primary', icon: 'add', go: function (b) {
    said.className = 'said';
    said.textContent = '';
    var bodyOut = {profile: p.name, note: f.note.value, team: f.team ? f.team.value : ''};
    var go = function () {
      busy(b, true);
      api('cert-request', bodyOut).then(function (got) {
        toast(got.waits ? 'asked for - it waits for approval' : 'asked for - it is being issued', 'good');
        closeModal();
        load().then(function () { if (got.id) certDialog(got.id); });
      }).catch(function (e) {
        said.className = 'said bad';
        said.textContent = String(e.message || e);
      }).then(function () { busy(b, false); });
    };
    if (p.owner === 'team' && !bodyOut.team) { sayBad(said, 'Choose the team it belongs to.'); return; }
    if (how === 'csr') {
      var got = f.csr._read();
      if (!got) { sayBad(said, 'Paste the CSR, or choose its file.'); return; }
      Object.assign(bodyOut, got);
      /* Decoded and shown first - only then asked for. */
      if (reviewKey !== JSON.stringify(got)) {
        decode(null).then(function (rv) {
          if (rv && !rv.fits) { sayBad(said, 'The CSR does not fit this profile - see what is marked ✗ above.'); }
          else if (rv) { said.className = 'said'; said.textContent = 'Look at what the CSR says above, then ask again.'; }
        });
        return;
      }
      if (!f.fits) { sayBad(said, 'The CSR does not fit this profile - see what is marked ✗ above.'); return; }
      go();
      return;
    }
    var names = drawChips();
    if (!names.length) { sayBad(said, 'Which names? One a line.'); f.names.focus(); return; }
    if (namesOk(names).length) { sayBad(said, 'Only names under ' + p.suffixes.join(', ') + ' may be asked for here.'); f.names.focus(); return; }
    if (names.length > p.max_names) { sayBad(said, 'At most ' + p.max_names + ' name(s) in one certificate of this profile.'); return; }
    bodyOut.names = names;
    bodyOut.key_type = f.key.value;
    bodyOut.subject = {};
    Object.keys(f.subject).forEach(function (k) { bodyOut.subject[k] = f.subject[k].value.trim(); });
    go();
  }}], 'large');
  drawChips();
}
window.ACME_PORTAL_PARTS = window.ACME_PORTAL_PARTS || [];
window.ACME_PORTAL_PARTS.push(part);
/* For the team workspace (portal-teams.js): the same list, dialogs and asking, team-aware. */
window.ACME_PORTAL_CERTS = {
  /* the list of one team's certificates into `host` (a card with #cp-list in it) */
  mount: function (list, q, ctx) {
    CP.host = list;
    CP.paged = true;
    CP.q = q || {};
    CP.ctx = ctx || null;
    return load();
  },
  ask: function (q) { if (q) Object.keys(q).forEach(function (k) { CP.q[k] = q[k]; }); return load(); },
  stop: function () { clearTimeout(CP.timer); CP.host = null; },
  data: function () { return CP.d; },
  open: function (id) { if (rowById(id)) certDialog(id); },
  openRow: function (row) {
    if (!CP.d) CP.d = {rows: []};
    if (!rowById(row.id)) CP.d.rows.push(row);
    certDialog(row.id);
  },
  askStart: function (ctx) {
    if (ctx) CP.ctx = ctx;
    if (CP.d) { askStart(); return; }
    apiLatest('cp-certs', 'certs&per=1').then(function (d) { CP.d = d; askStart(); }).catch(oops);
  },
  download: downloadDialog, saveB64: saveB64, stateTag: stateTag, daysTag: daysTag, namesChips: namesChips,
  emptyState: emptyState, skeleton: skeletonCard, has: has, jobLog: jobLog, STATE: STATE, FORMATS: FORMATS
};
})();
