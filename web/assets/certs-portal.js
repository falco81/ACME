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
     api('cert-request', {...})         POST /api/portal/cert_request */
(function () {
'use strict';

var CP = {d: null, host: null, timer: null, jobTimer: null, open: null};

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
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function stateTag(st) {
  var s = STATE[st] || [st || '–', 'dim'];
  var t = el('span', 'tag ' + s[1] + ' ct-state', s[0]);
  if (st === 'renewing' || st === 'new') t.classList.add('ct-pulse');
  return t;
}
function now() { return Date.now() / 1000; }
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
  return !!(c.job && c.job.live) || c.state === 'renewing' || (c.state === 'new' && !c.not_after);
}

/* ---- the card ---------------------------------------------------------------- */
function part(host, me) {
  var card = el('div', 'card cp-card');
  card.id = 'cp-card';
  var h = el('h2', '', 'Your certificates');
  var right = el('span', 'right btnrow');
  var ask = cmdButton('Ask for a certificate', 'add', 'primary small');
  ask.id = 'cp-ask';
  ask.hidden = true;
  ask.onclick = function () { askDialog(); };
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

function load() {
  clearTimeout(CP.timer);
  return api('certs').then(function (d) {
    CP.d = d;
    draw(d);
    var busyOnes = (d.rows || []).some(running);
    CP.timer = setTimeout(load, busyOnes ? 3000 : 60000);
    return d;
  }).catch(function (e) {
    if (e && e.stopped) return;
    if (e && e.status === 403) {
      var card = $('cp-card');
      if (card) card.remove();
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
  ask.hidden = !(d.suffixes || []).length || !(d.issuers || []).length;
  ask.disabled = !d.may_request;
  if (!d.may_request && !ask.hidden) explain(ask, 'You have asked for as many certificates as one person may. Ask the administrator for more.');
  var said = $('cp-said');
  clear(said);
  if (!ask.hidden) {
    said.appendChild(document.createTextNode(d.used + ' of ' + d.most + ' requests used'));
    said.appendChild(document.createTextNode(' · '));
    said.appendChild(document.createTextNode(d.auto ? 'issued at once' : 'an administrator approves each one'));
  }
  clear(host);
  if (!rows.length) {
    var b = el('div', 'ct-blank big');
    var ic = el('div', 'ct-blank-ic');
    ic.innerHTML = iconMarkup('cert', 30);
    b.appendChild(ic);
    b.appendChild(el('h3', '', 'No certificate of yours yet'));
    b.appendChild(el('p', 'muted', ask.hidden
      ? 'When an administrator gives you one (or a group you are in), it is here.'
      : 'Ask for one above: its names, where it comes from and its key.'));
    host.appendChild(b);
  } else {
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
    host.appendChild(sc);
  }
  explainWhatWasDrawn(host.parentNode);
  if (CP.open && CP.open.refresh) CP.open.refresh();
}

function row(c) {
  var tr = el('tr', 'tappable');
  tr.tabIndex = 0;
  if (c.state === 'failed' || c.state === 'expired' || c.state === 'declined') tr.classList.add('ct-hot');
  var sc = el('td');
  sc.appendChild(stateTag(c.state));
  tr.appendChild(sc);
  var nc = el('td', 'ct-cname');
  nc.appendChild(data('b', '', c.cn || c.name));
  if (c.via && c.via !== 'me' && c.via !== '*') {
    var g = el('span', 'tag info cp-via', 'group ');
    g.appendChild(data('span', '', c.via));
    explain(g, 'Yours through the directory group ' + c.via + '.');
    nc.appendChild(document.createTextNode(' '));
    nc.appendChild(g);
  }
  nc.appendChild(namesChips(c.names, 3));
  tr.appendChild(nc);
  tr.appendChild(data('td', 'muted', c.issuer || '–'));
  var ec = el('td', 'ct-exp');
  if (c.not_after) {
    ec.appendChild(el('span', 'day', dayOnly(c.not_after)));
    ec.appendChild(el('br'));
    ec.appendChild(daysTag(c.not_after));
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
    t.appendChild(stateTag(c.state));
    if (c.not_after) t.appendChild(daysTag(c.not_after));
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
    if (c.state === 'pending-approval') body.appendChild(stateNote('warn', 'Waiting for an administrator', 'You asked for it; an administrator approves it (or not). You are told by mail when they have.'));
    if (c.state === 'declined') body.appendChild(stateNote('crit', 'Declined', c.why ? 'The administrator said: ' + c.why : 'An administrator declined it.'));
    if (c.state === 'failed') body.appendChild(stateNote('crit', 'It could not be issued', (c.why || '') + ' - it is tried again by itself; the administrators know.'));
    var kv = kvTable([
      ['Name', data('span', 'mono', c.name)],
      ['Source', data('span', '', c.issuer || '–')],
      ['Key', KEY_WORDS[c.key_type] || c.key_type || '–'],
      ['Valid from', c.not_before ? stamp(c.not_before) : '–'],
      ['Valid to', c.not_after ? stamp(c.not_after) : '–'],
      ['Serial', c.serial ? data('span', 'mono small', c.serial) : '–'],
      ['Issued by', c.issuer_dn ? data('span', 'mono small', c.issuer_dn) : '–'],
      ['Renews', c.auto_renew ? 'by itself, before it runs out' : 'not by itself'],
      ['Owner', c.via === '*' ? (c.owner ? data('span', 'mono', c.owner) : 'nobody') : (c.via && c.via !== 'me' ? data('span', '', c.owner + ' (a group of yours)') : 'you')],
      ['Asked for', c.created ? stamp(c.created) : '–']
    ]);
    body.appendChild(kv);
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

function stateNote(kind, title, words) {
  var box = el('div', 'cp-note ' + kind);
  box.appendChild(el('b', '', title));
  box.appendChild(el('span', '', words));
  return box;
}

var LEVEL = {ok: 'ok', info: 'info', warn: 'warn', bad: 'bad', debug: 'debug'};
function jobLog(steps) {
  var box = el('div', 'ct-log');
  noI18n(box);
  if (!steps.length) { box.appendChild(el('div', 'muted', 'Waiting to begin…')); return box; }
  steps.forEach(function (s) {
    if (!Array.isArray(s)) s = [null, 'info', String(s)];
    var line = el('div', 'ct-log-l ' + (LEVEL[s[1]] || 'info'));
    line.appendChild(el('b', '', s[0] ? clockWords(new Date(Number(s[0]) * 1000), true) : ''));
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
  var fmts = (CP.d && CP.d.formats) || ['fullchain-pem', 'cert-pem', 'chain-pem'];
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
          saveB64(d);
          toast('downloaded: ' + (d.filename || ''), 'good');
          if (pw1) { pw1.value = ''; pw2.value = ''; }
        }).catch(oops).then(function () { busy(go, false); });
      };
      item.appendChild(go);
      list.appendChild(item);
    });
    body.appendChild(list);
    if (fmts.indexOf('pfx') < 0) body.appendChild(el('p', 'note small', 'The private key stays where it was made: the server that uses the certificate has it.'));
  }, [{words: 'Close', close: true}]);
}

/* ---- asking for one -------------------------------------------------------------- */
function askDialog() {
  var d = CP.d || {};
  var sufs = d.suffixes || [], iss = d.issuers || [];
  var namesBox, chips, issuerSel, keySel, noteBox, said, teamSel = null;
  var check = function () {
    var names = splitNames(namesBox.value);
    clear(chips);
    if (names.length) chips.appendChild(namesChips(names, 0, sufs));
    return names;
  };
  modal('Ask for a certificate', function (body) {
    body.appendChild(el('p', 'note', d.auto
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
    if ((d.teams || []).length) {
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
  }, [{words: 'Cancel', close: true}, {words: d.auto ? 'Ask and issue' : 'Ask for it', cls: 'primary', icon: 'add', go: function (b) {
    var names = check();
    said.className = 'said';
    said.textContent = '';
    if (!names.length) { said.className = 'said bad'; said.textContent = 'Which names? One a line.'; namesBox.focus(); return; }
    var bad = names.filter(function (n) { return !underSuffix(n, sufs); });
    if (bad.length) { said.className = 'said bad'; said.textContent = 'Only names under ' + sufs.join(', ') + ' may be asked for here.'; namesBox.focus(); return; }
    busy(b, true);
    api('cert-request', {names: names, issuer: issuerSel.value, key_type: keySel.value, note: noteBox.value,
                         team: teamSel ? teamSel.value : ''}).then(function (got) {
      toast(got.waits ? 'asked for - it waits for an administrator' : 'asked for - it is being issued', 'good');
      closeModal();
      load().then(function () { if (got.id && !got.waits) certDialog(got.id); });
    }).catch(function (e) {
      said.className = 'said bad';
      said.textContent = String(e.message || e);
    }).then(function () { busy(b, false); });
  }}]);
  check();
}

window.ACME_PORTAL_PARTS = window.ACME_PORTAL_PARTS || [];
window.ACME_PORTAL_PARTS.push(part);
})();
