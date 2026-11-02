/* certs.js - the certificate manager in the administration pages: the
   Overview's tiles, and the tabs Certificates, Authorities, Sources,
   Validation, Targets and Jobs, with the settings panes Renewal and notices
   and DNS server. Drawn with the page's own pieces (core.js: modal, listTable,
   pager, formField, kvTable, explain...) the way admin.js draws its own, over
   the daemon's API. The forms of the modules (sources, validation, targets,
   deployments) are drawn from what each module says of itself (`fields`,
   `deploy_fields` of GET /api/plugins): a new module needs nothing here. */
(function () {
'use strict';

var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
var FULL = ROLE === 'fulladmin';
var MANAGE = FULL || ROLE === 'certadmin';
var CT = window.ACME_CERTS = window.ACME_CERTS || {};

/* ---- asking the daemon ----------------------------------------------------
   admin/index.php relays the certificate manager's roads under their own
   names (?api=certs/one is /api/certs/one). A page that names them otherwise
   says how in window.ACME_CERTS_API (a function of the path). */
function apiName(path) {
  if (typeof window.ACME_CERTS_API === 'function') return window.ACME_CERTS_API(path);
  if (window.ACME_CERTS_API_STYLE === 'dash') return path.replace(/\//g, '-');
  return path;
}
function capi(path, body, wait) {
  var q = '', at = path.indexOf('?');
  if (at >= 0) { q = path.slice(at + 1); path = path.slice(0, at); }
  var writes = body !== undefined && body !== null && !READS.test(path);
  return api(apiName(path) + (q ? '&' + q : ''), body, wait).then(function (d) {
    if (writes) afterWrite(path);
    return d;
  }, function (e) {
    looksMissing(e);
    throw e;
  });
}
/* ---- always current ------------------------------------------------------
   What this page keeps of the daemon's answers (the lists of Sources,
   Validation and Targets, the modules with the choices of their fields -
   the authorities, sources, validations, targets inside a select -, the
   authorities, the filters filled once) is forgotten after every request
   that changes something, so the next tab, popup or form asks again: a
   thing made in one tab is in every other at once, without F5. POSTs that
   only read (a file looked into, an export, a test, a check) keep them. */
var READS = /(^|\/)(parse|export|test|pki_check|check|csr|plan|run_plan|dry_run|compat|preview)$/;
var FRESH = {n: 0};
function forgetAll() {
  FRESH.n++;
  if (typeof LISTS === 'object' && LISTS) Object.keys(LISTS).forEach(function (k) { delete LISTS[k]; });
  PLUG = null;
  PLUG_ASK = null;
  CAS_FRESH = 0;
  JL.certsFilled = false;
  HTTP_INFO = {};
  var f = $('ct-issuer');
  if (f) f._filled = false;
  LAST = {};
}
var countsSoon = null;
function afterWrite(path) {
  forgetAll();
  /* The counts on the tabs (Certificates, Jobs) follow too. */
  clearTimeout(countsSoon);
  countsSoon = setTimeout(tabCounts, 400);
}
/** A part of the daemon that is not there (yet): its road is not known. */
function looksMissing(e) {
  if (e && (e.status === 404 || e.status === 501)
      && /unknown endpoint|^not found|no such (road|route|endpoint|path)|^HTTP 40[45]|not (there|available) yet/i.test(String(e.message || ''))) {
    e.missing = true;
  }
  return !!(e && e.missing);
}
function qs(o) {
  var bits = [];
  Object.keys(o || {}).forEach(function (k) {
    var v = o[k];
    if (v === undefined || v === null || v === '') return;
    bits.push(k + '=' + encodeURIComponent(String(v)));
  });
  return bits.length ? '?' + bits.join('&') : '';
}
/** The list in an answer, whatever it is called there. */
function rowsOf(d) {
  if (Array.isArray(d)) return d;
  if (!d || typeof d !== 'object') return [];
  for (var i = 1; i < arguments.length; i++) if (Array.isArray(d[arguments[i]])) return d[arguments[i]];
  if (Array.isArray(d.rows)) return d.rows;
  if (Array.isArray(d.items)) return d.items;
  if (Array.isArray(d.list)) return d.list;
  return [];
}
/** A list kept as JSON text, or as a list, or as words. */
function arr(v) {
  if (Array.isArray(v)) return v;
  if (v === undefined || v === null || v === '') return [];
  if (typeof v === 'string') {
    var t = v.trim();
    if (t.charAt(0) === '[') { try { var j = JSON.parse(t); if (Array.isArray(j)) return j; } catch (e) { } }
    return t.split(/[\s,;]+/).filter(Boolean);
  }
  return [v];
}
function obj(v) {
  if (v && typeof v === 'object' && !Array.isArray(v)) return v;
  if (typeof v === 'string' && v.trim().charAt(0) === '{') { try { return JSON.parse(v) || {}; } catch (e) { } }
  return {};
}
function first() {
  for (var i = 0; i < arguments.length; i++) {
    var v = arguments[i];
    if (v !== undefined && v !== null && v !== '') return v;
  }
  return undefined;
}
function said(d, fallback) {
  return (d && (d.message || d.said || d.result || d.words)) || fallback || 'done';
}
function wordsOf(e) { return String((e && e.message) || e || ''); }
/* ---- names that are safe ------------------------------------------------------
   The name of a source, a validation, a target, an authority, a certificate
   reaches shell commands, files and devices: letters, digits, spaces and
   . _ @ + - only, starting with a letter or a digit (store.NAME_RE). Every
   name this page suggests is made so (safeName - as store.safe_name does on
   the daemon), and every name box says at once what it would refuse. */
var NAME_OK = /^[A-Za-z0-9][A-Za-z0-9 ._@+-]{0,119}$/;
var LETTERS = {'\u00df': 'ss', '\u0141': 'L', '\u0142': 'l', '\u00d8': 'O', '\u00f8': 'o', '\u0110': 'D', '\u0111': 'd', '\u00c6': 'AE', '\u00e6': 'ae'};
function safeName(text, taken, fallback) {
  var t = String(text || '');
  try { t = t.normalize('NFKD').replace(/[\u0300-\u036f]/g, ''); } catch (e) { }
  t = t.replace(/[\u00df\u0141\u0142\u00d8\u00f8\u0110\u0111\u00c6\u00e6]/g, function (c) { return LETTERS[c]; });
  t = t.replace(/['\u2019\u2018\u02bc`"\u201c\u201d\u201e]/g, '');
  t = t.replace(/[()\[\]{}<>:,\/\\;|=*?!#$%^&~\s\u2013\u2014]+/g, ' ');
  t = t.replace(/[^A-Za-z0-9 ._@+-]+/g, '').replace(/ {2,}/g, ' ').replace(/^[ ._@+-]+|[ ._@+-]+$/g, '');
  t = t.slice(0, 120).replace(/[ ._@+-]+$/, '') || fallback || 'unnamed';
  if (!/^[A-Za-z0-9]/.test(t)) t = fallback || 'unnamed';
  var have = {};
  arr(taken).forEach(function (x) { have[String(x)] = true; });
  if (!have[t]) return t;
  for (var n = 2; ; n++) {
    var cand = t.slice(0, 120 - String(n).length - 1).replace(/\s+$/, '') + ' ' + n;
    if (!have[cand]) return cand;
  }
}
/** A certificate's name made from its first DNS name: a wildcard as "wildcard.". */
function certName(first, taken) { return safeName(String(first || '').replace(/^\*\./, 'wildcard.'), taken, 'certificate'); }
/** What is wrong with a name typed, or ''. */
function nameProblem(v, required, taken) {
  v = String(v || '').trim();
  if (!v) return required ? 'it needs a name' : '';
  if (!NAME_OK.test(v)) return 'letters, digits, spaces and . _ @ + - only (no quotes, no brackets), starting with a letter or a digit - e.g. ' + safeName(v);
  if (taken && arr(taken).indexOf(v) >= 0) return 'there is one called ' + v + ' already';
  return '';
}
/** A name box that says at once what it would refuse, under itself, and
    keeps the popup's main button off meanwhile. `taken`: names already there. */
function guardName(input, required, taken) {
  var said = el('div', 'ct-name-said small');
  var paint = function () {
    var bad = nameProblem(input.value, required, taken);
    said.textContent = bad;
    said.hidden = !bad;
    var item = input.closest ? input.closest('.set-item') : null;
    if (item) item.classList.toggle('refused', !!bad);
    input.setAttribute('aria-invalid', bad ? 'true' : 'false');
    var foot = $('modal-foot');
    if (foot) Array.prototype.forEach.call(foot.querySelectorAll('button.primary'), function (b) {
      b.disabled = !!bad;
      if (bad) b.title = bad; else b.removeAttribute('title');
    });
    return bad;
  };
  input.addEventListener('input', paint);
  input._nameCheck = paint;
  setTimeout(function () {
    if (input.parentNode) input.parentNode.appendChild(said);
    paint();
  }, 0);
  return paint;
}

/** Words in the page's language, for where they go into data (an option of a
    select marked as data): i18n.js's own, English where there is none. */
function tr(words) {
  try { var got = typeof i18nText === 'function' ? i18nText(words) : null; return got || words; }
  catch (e) { return words; }
}

/* ---- what is not there yet ------------------------------------------------- */
/** A calm box where a part of the daemon does not answer yet (404). */
function missingBox(what) {
  var box = el('div', 'ct-missing');
  var ic = el('div', 'ct-missing-ic');
  ic.innerHTML = iconMarkup('clock', 22);
  box.appendChild(ic);
  var w = el('div', 'ct-missing-w');
  w.appendChild(el('b', '', 'Not available yet'));
  w.appendChild(el('div', 'muted small', what
    ? 'This server does not answer for ' + what + ' yet - it comes with a later version of the daemon.'
    : 'This server does not answer for this yet - it comes with a later version of the daemon.'));
  box.appendChild(w);
  return box;
}
function failedBox(e, what) {
  if (looksMissing(e)) return missingBox(what);
  var p = el('p', 'ct-bad');
  p.textContent = wordsOf(e);
  return p;
}
function failInto(host, what) {
  return function (e) {
    if (e && e.stopped) return;
    if (!host) { oops(e); return; }
    clear(host);
    host.appendChild(failedBox(e, what));
  };
}
function fail(e) {
  if (looksMissing(e)) { toast('not available yet - the daemon does not do this yet', 'warn'); return; }
  oops(e);
}

/* ---- icons of its own ------------------------------------------------------ */
if (typeof ICONS === 'object') {
  ICONS.cert = '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M7.5 8h9M7.5 11h5"/>'
    + '<circle cx="16" cy="16.5" r="2.6"/><path d="M14.4 18.6l-.9 3 2.5-1.1 2.5 1.1-.9-3"/>';
  ICONS.ca = '<path d="M12 3l8.5 4.2V9h-17V7.2z"/><path d="M6 11.5v6M10 11.5v6M14 11.5v6M18 11.5v6"/><path d="M3 20.5h18"/>';
  ICONS.source = '<path d="M12 3.5v10"/><path d="M8 10l4 4 4-4"/><path d="M4 15.5V19a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3.5"/>';
  ICONS.proof = '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/><path d="M8.6 12.2l2.4 2.4 4.4-4.8"/>';
  ICONS.target = '<rect x="3" y="4" width="18" height="6.5" rx="1.6"/><rect x="3" y="13.5" width="18" height="6.5" rx="1.6"/>'
    + '<path d="M7 7.25h.01M7 16.75h.01M11 7.25h6M11 16.75h6"/>';
  ICONS.job = '<path d="M4 6h10M4 12h7M4 18h10"/><path d="M16.5 9.5l4.5 3-4.5 3z"/>';
  ICONS.deploy = '<path d="M12 20.5V9.5"/><path d="M8 13.5l4-4 4 4"/><path d="M4.5 9V5.5a2 2 0 0 1 2-2h11a2 2 0 0 1 2 2V9"/>';
  ICONS.tree = '<rect x="9" y="3" width="6" height="5" rx="1.2"/><rect x="3" y="16" width="6" height="5" rx="1.2"/>'
    + '<rect x="15" y="16" width="6" height="5" rx="1.2"/><path d="M12 8v4M6 16v-4h12v4"/>';
  ICONS.crown = '<path d="M4 18h16l1-10-5 4-4-7-4 7-5-4z"/><path d="M4 21h16"/>';
  ICONS.module = '<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>';
}

/* ---- words ----------------------------------------------------------------- */
var STATE = {
  'new': ['not issued yet', 'dim'], ok: ['valid', 'ok'], due: ['due', 'warn'],
  renewing: ['renewing', 'info'], failed: ['failed', 'crit'], expired: ['has expired', 'crit'],
  pending: ['waiting for a CA', 'violet'], revoked: ['revoked', 'crit'], disabled: ['switched off', 'dim'],
  /* asked for on the portal (acmelib/certs/portal.py) */
  'pending-approval': ['waiting for approval', 'warn'], declined: ['declined', 'crit']
};
/** A popup's title of words and a name: the name is data, the words are
    translated as they stand ("Revoke " + a name the pattern cannot tell
    from words, such as www.example.cz). */
function nameInTitle(words, name) {
  var t = $('modal-title');
  if (!t) return;
  clear(t);
  t.appendChild(document.createTextNode(words + ' '));
  t.appendChild(data('span', '', String(name)));
}
function asked(c) { return c.state === 'pending-approval' || c.state === 'declined'; }
function stateTag(st) {
  var s = STATE[st] || [st || '–', 'dim'];
  var t = el('span', 'tag ' + s[1] + ' ct-state', s[0]);
  if (st === 'renewing') t.classList.add('ct-pulse');
  return t;
}
var JOB_KIND = {issue: 'issue', renew: 'renewal', deploy: 'deployment', revoke: 'revocation',
                'import': 'import', test: 'test', csr: 'CSR', crl: 'CRL', verify: 'check', export: 'export',
                'dry-run': 'dry run'};
function jobState(j) {
  var st = j.state || (j.finished ? (j.ok ? 'ok' : 'failed') : 'running');
  if (st === 'done') st = j.ok ? 'ok' : 'failed';
  return st;
}
function jobRunning(j) { var s = jobState(j); return s === 'running' || s === 'queued' || s === 'waiting' || s === 'stopping'; }
function jobTag(j) {
  var st = jobState(j);
  var m = {running: ['running', 'info'], queued: ['waiting', 'dim'], waiting: ['waiting', 'dim'],
           stopping: ['stopping', 'warn'], ok: ['went well', 'ok'], failed: ['failed', 'crit'],
           stopped: ['stopped', 'dim'], warn: ['with warnings', 'warn']}[st] || [st, 'dim'];
  var t = el('span', 'tag ' + m[1], m[0]);
  if (st === 'running') t.classList.add('ct-pulse');
  return t;
}
var KEY_TYPES = [
  ['ec-256', 'EC P-256', 'Small and fast, understood by everything made in the last ten years. The usual choice.'],
  ['ec-384', 'EC P-384', 'A longer curve, where a policy asks for one.'],
  ['rsa-2048', 'RSA 2048', 'For old devices and appliances that speak no EC.'],
  ['rsa-3072', 'RSA 3072', 'RSA, longer: where 2048 is no longer allowed.'],
  ['rsa-4096', 'RSA 4096', 'The longest RSA; slower handshakes, bigger certificates.'],
  ['ed25519', 'Ed25519', 'Modern and small - but not for browsers or public CAs.']
];
function keyWords(k) {
  var one = KEY_TYPES.filter(function (x) { return x[0] === k; })[0];
  return one ? one[1] : (k || '–');
}
var EKUS = [['serverAuth', 'TLS server'], ['clientAuth', 'TLS client'], ['codeSigning', 'code signing'],
            ['emailProtection', 'e-mail (S/MIME)'], ['timeStamping', 'time stamping'], ['OCSPSigning', 'OCSP signing']];
var REVOKE_REASONS = [['unspecified', 'no reason given'], ['keyCompromise', 'the key got out'],
  ['superseded', 'replaced by another'], ['cessationOfOperation', 'no longer used'],
  ['affiliationChanged', 'the owner changed'], ['cACompromise', 'the CA was compromised']];

/* ---- time ------------------------------------------------------------------ */
function now() { return Date.now() / 1000; }
function daysLeftOf(ts) { return ts ? Math.floor((Number(ts) - now()) / 86400) : null; }
function daysTone(d, renewDays) {
  if (d === null) return 'dim';
  if (d < 0) return 'crit';
  if (d < 7) return 'crit';
  if (d < Math.max(14, renewDays || 0) || d < 21) return 'warn';
  return 'ok';
}
function daysWords(d) {
  if (d === null) return '–';
  if (d < 0) return 'expired ' + (-d === 1 ? 'a day ago' : (-d) + ' days ago');
  if (d === 0) return 'ends today';
  if (d === 1) return '1 day left';
  return d + ' days left';
}
function daysTag(ts, renewDays) {
  var d = daysLeftOf(ts);
  return el('span', 'ct-days ' + daysTone(d, renewDays), daysWords(d));
}
function dayOnly(ts) { return ts ? dayWords(new Date(ts * 1000)) : '–'; }
function tookWords(ms) {
  if (ms === undefined || ms === null || ms === '') return '–';
  ms = Number(ms);
  if (ms < 1000) return Math.round(ms) + ' ms';
  if (ms < 60000) return (Math.round(ms / 100) / 10) + ' s';
  return span(ms / 1000);
}
function cssVar(name, fallback) {
  try {
    var v = getComputedStyle(document.documentElement).getPropertyValue(name);
    return (v && v.trim()) || fallback;
  } catch (e) { return fallback; }
}

/* ---- little pieces --------------------------------------------------------- */
function mono(text, cls) { return noI18n(el('span', 'mono' + (cls ? ' ' + cls : ''), text)); }
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function namesChips(names, most) {
  var box = el('div', 'ct-names');
  names = arr(names);
  var shown = most ? names.slice(0, most) : names;
  shown.forEach(function (n) {
    var m = /^(email|uri):(.*)$/.exec(String(n || ''));
    var k = m ? m[1] : nameKind(n);
    var c = noI18n(el('span', 'ct-name ' + k, m ? m[2] : n));
    box.appendChild(c);
  });
  if (most && names.length > most) {
    var more = el('span', 'ct-name more', '+' + (names.length - most));
    explain(more, names.slice(most).join(', '));
    box.appendChild(more);
  }
  return box;
}
function nameKind(n) {
  n = String(n || '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(n) || (n.indexOf(':') >= 0 && /^[0-9a-f:.]+$/i.test(n))) return 'ip';
  if (/^\*\.[^*]+$/.test(n)) return isHost(n.slice(2)) ? 'wild' : 'bad';
  return isHost(n) ? 'dns' : 'bad';
}
function isHost(n) {
  return n.length <= 253 && /^([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)*[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(n);
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
function tagChips(tags) {
  var box = el('span', 'ct-tags');
  var TMS = window.ACME_TEAMS;
  arr(tags).forEach(function (t) { box.appendChild(TMS ? TMS.tagChip(t) : noI18n(el('span', 'tag dim ct-tagchip', t))); });
  return box;
}
/* The owner and the tags picked from Settings → Owners and teams (teams.js);
   without it, typed as before. Both answer .value. */
function ownerBox(v) { return window.ACME_TEAMS ? ACME_TEAMS.ownerPicker(v) : textBox(v || '', 'team or person', ''); }
function tagsBox(list) {
  if (window.ACME_TEAMS) return ACME_TEAMS.tagPicker(arr(list));
  var t = textBox(arr(list).join(' '), 'prod web', '');
  noI18n(t);
  return t;
}
function copyable(text, words) {
  var s = mono(text, 'ct-copy');
  copyOnClick(s, text, words || 'copied');
  return s;
}
function fpWords(fp) {
  fp = String(fp || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
  return fp ? fp.match(/.{1,2}/g).join(':') : '';
}
function lifeBar(nb, na) {
  var bar = el('div', 'ct-life');
  var fill = el('span');
  if (nb && na && na > nb) {
    var pc = Math.max(0, Math.min(100, 100 * (now() - nb) / (na - nb)));
    fill.style.width = pc.toFixed(1) + '%';
    var d = daysLeftOf(na);
    fill.className = daysTone(d);
  }
  bar.appendChild(fill);
  return bar;
}
function rowOpens(tr, go) {
  tr.classList.add('tappable');
  tr.tabIndex = 0;
  tr.onclick = function (e) {
    if (e && e.target && e.target.closest && e.target.closest('button, a, input, select, label')) return;
    go();
  };
  tr.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); go(); } };
  return tr;
}
function td(cls, content) {
  var c = el('td', cls || '');
  if (content === undefined || content === null) return c;
  if (content.nodeType) c.appendChild(content); else c.textContent = String(content);
  return c;
}
/** Who did it and how long ago, each in a piece of its own (the time is
    translated, the name is not). */
/** Who did something: a name is data, the daemon's own words are not. */
function byWho(who, cls) {
  return who === 'the renewer' ? el('span', cls || '', who) : data('span', cls || '', who);
}
function whoWhen(by, ts) {
  var c = el('td', 'muted small ct-whowhen');
  c.appendChild(byWho(by || '–'));
  if (ts) c.appendChild(el('span', '', ago(ts)));
  return c;
}
function emptyNote(words) { return el('p', 'muted ct-empty', words); }
function section(title, lede, wide) {
  var box = el('section', 'msect' + (wide ? ' wide' : ''));
  box.appendChild(el('h4', '', title));
  if (lede) box.appendChild(el('p', 'msect-lede', lede));
  var body = el('div', 'msect-body');
  box.appendChild(body);
  box._body = body;
  return box;
}
function factsRow(pairs) { return peekFacts(pairs); }
/** Two sections side by side take half each, one takes the row - not a
    third of it beside two empty thirds. */
function fitSections(root) {
  if (!root) return;
  Array.prototype.forEach.call(root.querySelectorAll('.msects'), function (g) {
    var narrow = Array.prototype.filter.call(g.children, function (x) { return !x.classList.contains('wide'); }).length;
    g.classList.toggle('ct-two', narrow === 2);
    g.classList.toggle('ct-one', narrow === 1);
  });
}

/* ---- files ----------------------------------------------------------------- */
function fileB64(file) {
  return new Promise(function (ok, bad) {
    var r = new FileReader();
    r.onload = function () {
      var s = String(r.result || '');
      var at = s.indexOf(',');
      ok(at >= 0 ? s.slice(at + 1) : s);
    };
    r.onerror = function () { bad(new Error('the file could not be read')); };
    r.readAsDataURL(file);
  });
}
function fileText(file) {
  return new Promise(function (ok, bad) {
    var r = new FileReader();
    r.onload = function () { ok(String(r.result || '')); };
    r.onerror = function () { bad(new Error('the file could not be read')); };
    r.readAsText(file);
  });
}
function textB64(text) {
  try { return btoa(unescape(encodeURIComponent(text))); } catch (e) { return btoa(text); }
}
/** {filename, mime, data_b64} from the daemon, saved by the browser. */
function download(d) {
  var bin = atob(String(d.data_b64 || d.data || ''));
  var u8 = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  saveBlob(new Blob([u8], {type: d.mime || 'application/octet-stream'}), d.filename || 'download.bin');
}
function saveBlob(blob, name) {
  var a = el('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 800);
}
function saveText(name, text, mime) { saveBlob(new Blob([text], {type: mime || 'text/plain'}), name); }

/** A box to drop files on (or press, to choose them). `got(files)`. */
function dropZone(words, got, accept, many) {
  var box = el('div', 'drop ct-drop');
  box.tabIndex = 0;
  box.setAttribute('role', 'button');
  var ic = el('span', 'ct-drop-ic');
  ic.innerHTML = iconMarkup('upload', 22);
  box.appendChild(ic);
  var w = el('span', '', words);
  box.appendChild(w);
  var input = el('input');
  input.type = 'file';
  input.hidden = true;
  if (accept) input.accept = accept;
  if (many) input.multiple = true;
  box.appendChild(input);
  var take = function (list) {
    var files = Array.prototype.slice.call(list || []);
    if (files.length) got(files);
  };
  box.onclick = function (e) { if (e.target !== input) input.click(); };
  box.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); } };
  input.onchange = function () { take(input.files); input.value = ''; };
  ['dragenter', 'dragover'].forEach(function (n) {
    box.addEventListener(n, function (e) { e.preventDefault(); box.classList.add('over'); });
  });
  ['dragleave', 'drop'].forEach(function (n) {
    box.addEventListener(n, function (e) {
      e.preventDefault();
      box.classList.remove('over');
      if (n === 'drop' && e.dataTransfer) take(e.dataTransfer.files);
    });
  });
  box._words = w;
  return box;
}
/** A textarea for PEM with a button that reads it from a file. */
function pemBox(value, placeholder, rows) {
  var wrap = el('div', 'ct-pem');
  var ta = el('textarea', 'mono');
  ta.rows = rows || 5;
  ta.spellcheck = false;
  ta.value = value || '';
  ta.placeholder = placeholder || '-----BEGIN CERTIFICATE-----';
  wrap.appendChild(ta);
  var b = cmdButton('Read from a file', 'upload', 'small');
  var input = el('input');
  input.type = 'file';
  input.hidden = true;
  b.onclick = function () { input.click(); };
  input.onchange = function () {
    var f = input.files && input.files[0];
    input.value = '';
    if (!f) return;
    fileText(f).then(function (t) {
      if (!/-----BEGIN/.test(t)) {
        /* Not PEM: carried as base64 so the daemon can say what it is. */
        return fileB64(f).then(function (b64) { ta.value = b64; ta.dispatchEvent(new Event('input', {bubbles: true})); });
      }
      ta.value = t.trim();
      ta.dispatchEvent(new Event('input', {bubbles: true}));
    }).catch(oops);
  };
  var row = el('div', 'btnrow ct-pem-tools');
  row.appendChild(b);
  row.appendChild(input);
  wrap.appendChild(row);
  wrap._input = ta;
  wrap._get = function () { return ta.value.trim(); };
  return wrap;
}
function numberBox(value, placeholder, min, max) {
  var i = el('input');
  i.type = 'number';
  if (min !== undefined) i.min = min;
  if (max !== undefined) i.max = max;
  i.value = value === undefined || value === null ? '' : String(value);
  if (placeholder) i.placeholder = placeholder;
  return i;
}
function areaBox(value, placeholder, rows, cls) {
  var ta = el('textarea', cls || '');
  ta.rows = rows || 3;
  ta.spellcheck = false;
  ta.value = value || '';
  if (placeholder) ta.placeholder = placeholder;
  return ta;
}
function wideField(label, input, says) {
  var f = formField(label, input, says);
  f.classList.add('wide');
  return f;
}
function saidLine(kind, words) {
  var s = el('div', 'said ' + (kind || ''));
  s.textContent = words || '';
  return s;
}

/* ---- popups that ask first ----------------------------------------------- */
/** Asks, then draws: `draw(d)` gives {build(body), buttons, title}. */
function popup(title, ask, draw, size, what) {
  modal(title, function (b) { b.appendChild(el('p', 'center muted', 'Asking…')); }, [{words: 'Close', close: true}], size);
  var ticket = modalTicket();
  return Promise.resolve().then(ask).then(function (d) {
    if (!modalStill(ticket)) return;
    var r = draw(d) || {};
    var build = r.build;
    modal(r.title || title, function (body) {
      try { if (build) build(body); }
      catch (e) {
        if (window.console) console.error(e);
        body.appendChild(el('p', 'ct-bad', 'This could not be drawn whole: ' + wordsOf(e)));
      }
    }, r.buttons, r.size || size);
    explainWhatWasDrawn($('modal-body'));
    fitSections($('modal-body'));
    /* A popup to read opens at its top: the page's popup puts the cursor in
       its first box, which here is a search far down. */
    setTimeout(function () {
      var a = document.activeElement, b = $('modal-body');
      if (a && a.type === 'search' && b && b.contains(a)) {
        a.blur();
        var go = $('modal-foot') && $('modal-foot').querySelector('.btn.primary:not(.danger)');
        if (go) { try { go.focus({preventScroll: true}); } catch (e) { } }
        b.scrollTop = 0;
      }
    }, 30);
    if (r.after) r.after();
  }).catch(function (e) {
    if (!modalStill(ticket)) return;
    var b = $('modal-body');
    clear(b);
    b.appendChild(failedBox(e, what));
  });
}
/** Over the popup open now, if there is one; `back` when it is on top again. */
function over(open, back) {
  if ($('modal') && !$('modal').hidden) modalOver(open, back); else open();
}
/** A job just started: said, and its log opened over what is open. */
function jobStarted(d, words, back) {
  toast(said(d, words || 'started'), 'good');
  var id = d && (d.job_id || d.job || d.id);
  if (d && (d.job_id || d.job)) over(function () { jobPeek(id); }, back);
  CT.refresh();
}

/* ==========================================================================
   The forms of the modules, drawn from what each says of itself
   --------------------------------------------------------------------------
   {key, label, type, required, default, placeholder, help, options,
    show_if: {other_key: [values]}, advanced}
   type: text | secret | number | bool | select | textarea | pem | list | hostport
   ========================================================================== */
function truthy(v) { return v === true || v === 1 || v === '1' || v === 'true' || v === 'on' || v === 'yes'; }
function optionPairs(f) {
  return (f.options || []).map(function (o) {
    if (Array.isArray(o)) return [String(o[0]), String(o.length > 1 ? o[1] : o[0])];
    if (o && typeof o === 'object') return [String(first(o.value, o.key, '')), String(first(o.label, o.words, o.value, ''))];
    return [String(o), String(o)];
  });
}
/** `values` the module's config, `secrets` which secrets are set. Returns
    {node, read(), check() -> words or '', focus()}. */
function fieldForm(fields, values, secrets, opts) {
  opts = opts || {};
  values = values || {};
  secrets = secrets || {};
  var node = el('div', 'ct-fform');
  var main = el('div', 'formgrid');
  var more = el('details', 'ct-more');
  var sum = el('summary', '', 'More');
  more.appendChild(sum);
  var moreGrid = el('div', 'formgrid');
  more.appendChild(moreGrid);
  var items = [];
  (fields || []).forEach(function (f) {
    if (!f || !f.key) return;
    var v = Object.prototype.hasOwnProperty.call(values, f.key) ? values[f.key] : f['default'];
    var type = f.type || 'text';
    var input, get, wide = false;
    /* A type drawn by a part of its own (window.ACME_FIELD_TYPES[type] -
       sshkey.js: the SSH key card): {input, get, item?}. */
    var own = window.ACME_FIELD_TYPES && typeof window.ACME_FIELD_TYPES[type] === 'function'
      ? window.ACME_FIELD_TYPES[type](f, v, {values: values, secrets: secrets, opts: opts, form: node,
                                             current: function () { return current(); }}) : null;
    if (own) {
      input = own.input;
      get = own.get;
      wide = true;
    } else if (type === 'bool') {
      input = switchBox(v === undefined ? false : truthy(v));
      get = function () { return !!input._get(); };
    } else if (type === 'select') {
      var pairs = optionPairs(f);
      if (!f.required && !pairs.some(function (p) { return p[0] === ''; }) && (v === undefined || v === '')) pairs.unshift(['', '–']);
      input = selectBox(pairs, v === undefined ? (pairs[0] ? pairs[0][0] : '') : v);
      get = function () { return input.value; };
    } else if (type === 'number') {
      input = numberBox(v, f.placeholder, f.min, f.max);
      get = function () { return input.value === '' ? null : Number(input.value); };
    } else if ((type === 'secret' && f.multiline) || (type === 'pem' && f.secret)) {
      /* A key or lines kept secret: typed or pasted unseen (dots), read from a
         file; the one kept shown as the daemon sends it - dots and its last
         two - and sent back as it is when untouched (it keeps the one kept). */
      input = secretPemBox(keptSecret(v), secrets[f.key] ? 'set - leave empty to keep it' : (f.placeholder || 'paste it here'));
      get = function () { return input._get(); };
      wide = true;
    } else if (type === 'secret') {
      var isSet = !!secrets[f.key];
      input = secretBox(keptSecret(v), tr(isSet ? 'set - leave empty to keep it' : (f.placeholder || 'not set')), 'mono');
      noI18n(input);   /* its hint in words all the same: tr() */
      get = function () { return input.value; };
    } else if (type === 'textarea' && f.ui === 'script' && window.ACME_DEPLOY_UI) {
      /* A script (the target's default one after the files): the code box. */
      input = window.ACME_DEPLOY_UI.codeBox(v || '', {readOnly: !FULL, min: 6});
      get = function () { return input._get(); };
      wide = true;
    } else if (type === 'textarea') {
      input = areaBox(v, f.placeholder, f.rows || 4);
      get = function () { return input.value; };
      wide = true;
    } else if (type === 'pem') {
      input = pemBox(v, f.placeholder, 5);
      get = function () { return input._get(); };
      wide = true;
    } else if (type === 'list') {
      input = areaBox(arr(Array.isArray(v) ? v : (typeof v === 'string' ? v.split(/\n/) : v)).join('\n'),
                      f.placeholder ? String(f.placeholder) : 'one a line', f.rows || 4, 'mono');
      get = function () { return input.value.split(/\n/).map(function (x) { return x.trim(); }).filter(Boolean); };
      wide = true;
    } else {
      input = textBox(v === undefined || v === null ? '' : v, f.placeholder || (type === 'hostport' ? 'host:port' : ''),
                      type === 'hostport' ? 'mono' : '');
      if (type === 'hostport') noI18n(input);
      get = function () { return input.value.trim(); };
    }
    var label = String(f.label || f.key);
    var item = own && own.item ? own.item : formField(label, input, f.help || '');
    item.dataset.fkey = f.key;
    if (f.required) item.classList.add('ct-req');
    if (!own && (type === 'secret' || f.secret)) {
      var lab = item.querySelector('label');
      if (lab) lab.appendChild(el('span', 'tag ' + (secrets[f.key] ? 'ok' : 'dim') + ' ct-secret-tag', secrets[f.key] ? 'set' : 'not set'));
    }
    if (wide || f.wide) item.classList.add('wide');
    if (f.placeholder && type !== 'secret' && type !== 'list') {
      var box = input._input || input;
      if (box && box.tagName === 'INPUT' && /^[\w.@:/-]+$/.test(String(f.placeholder))) noI18n(box);
    }
    (f.advanced ? moreGrid : main).appendChild(item);
    items.push({f: f, item: item, input: input, get: get});
  });
  node.appendChild(main);
  if (moreGrid.children.length) node.appendChild(more);
  if (!main.children.length && !moreGrid.children.length && opts.none !== false) {
    node.appendChild(el('p', 'muted small', opts.noneWords || 'Nothing to set: this module needs nothing more.'));
  }
  var current = function () {
    var o = {};
    items.forEach(function (it) { o[it.f.key] = it.get(); });
    return o;
  };
  /* A choice that fills others in (`fills`: {option: {key: value}}) - a
     preset of a service, say: chosen, the fields below take its values. */
  var put = function (it, v) {
    var box = it.input._input || it.input;
    if (it.f.type === 'bool') { box.checked = truthy(v); return; }
    if (it.f.type === 'pem' || it.input._input) { it.input._input.value = v || ''; return; }
    if (Array.isArray(v)) v = v.join('\n');
    box.value = v === undefined || v === null ? '' : String(v);
  };
  items.forEach(function (it) {
    if (!it.f.fills || it.f.type !== 'select') return;
    it.input.addEventListener('change', function () {
      var want = it.f.fills[it.input.value];
      if (!want) return;
      Object.keys(want).forEach(function (k) {
        var other = items.filter(function (x) { return x.f.key === k; })[0];
        if (other) put(other, want[k]);
      });
    });
  });
  var shown = function (it, cur) {
    var cond = it.f.show_if;
    if (!cond || typeof cond !== 'object') return true;
    return Object.keys(cond).every(function (k) {
      var want = Array.isArray(cond[k]) ? cond[k] : [cond[k]];
      var have = cur[k];
      return want.some(function (w) {
        if (typeof w === 'boolean' || typeof have === 'boolean') return truthy(w) === truthy(have);
        return String(w) === String(have === undefined || have === null ? '' : have);
      });
    });
  };
  var paint = function () {
    var cur = current();
    items.forEach(function (it) { it.item.hidden = !shown(it, cur); });
    if (more.parentNode) more.hidden = !items.some(function (it) { return it.f.advanced && !it.item.hidden; });
  };
  node.addEventListener('input', paint);
  node.addEventListener('change', paint);
  paint();
  /* Something required and set in "More" opens it. */
  if (items.some(function (it) { return it.f.advanced && it.f.required; })) more.open = true;
  return {
    node: node,
    /* A field given a value from outside (a helper of the form): as if typed. */
    set: function (key, v) {
      var it = items.filter(function (x) { return x.f.key === key; })[0];
      if (!it) return false;
      put(it, v);
      var box = it.input._input || it.input;
      box.dispatchEvent(new Event('input', {bubbles: true}));
      box.dispatchEvent(new Event('change', {bubbles: true}));
      if (it.f.advanced && more.parentNode) more.open = true;
      it.item.classList.add('ct-filled');
      return true;
    },
    /* A field's value now, shown or not (a helper of the form compares with it). */
    get: function (key) { return current()[key]; },
    read: function () {
      var cur = current(), o = {};
      items.forEach(function (it) {
        if (!shown(it, cur)) return;
        o[it.f.key] = cur[it.f.key];
      });
      return o;
    },
    check: function () {
      var cur = current(), bad = '';
      items.forEach(function (it) {
        it.item.classList.remove('refused');
        if (!it.f.required || !shown(it, cur)) return;
        var v = cur[it.f.key];
        var empty = v === '' || v === null || v === undefined || (Array.isArray(v) && !v.length);
        if ((it.f.type === 'secret' || it.f.secret) && secrets[it.f.key]) empty = false;
        if (it.f.type === 'bool') empty = false;
        if (empty) {
          it.item.classList.add('refused');
          if (it.f.advanced) more.open = true;
          if (!bad) {
            bad = (it.f.label || it.f.key) + ' is needed';
            var box = it.input._input || it.input;
            try { box.focus(); } catch (e) { }
          }
        }
      });
      return bad;
    }
  };
}
/** A kept secret as the daemon sends it: dots (and, to a full administrator,
    its last two characters) - never anything else into a secret's box. */
function keptSecret(v) {
  v = v === undefined || v === null ? '' : String(v);
  return v.charAt(0) === '\u2022' ? v : '';
}
/** A secret of several lines (a private key, JSON, KEY=VALUE lines): a box
    that shows dots only while it is typed or pasted - its lines kept - with
    "Read from a file" beside it. `_get()` its text, or the dots of the one
    kept when untouched. */
/** "set" / "not set" - with the kept one as dots and its last two when the daemon gave them. */
function secretShownTag(isSet, v) {
  var t = el('span', '');
  t.appendChild(el('span', 'tag ' + (isSet ? 'ok' : 'dim'), isSet ? 'set' : 'not set'));
  var k = keptSecret(v);
  if (isSet && k) { t.appendChild(document.createTextNode(' ')); t.appendChild(mono(k)); }
  return t;
}
function secretPemBox(value, placeholder) {
  var wrap = el('div', 'ct-pem ct-secretpem');
  var box = maskBox(value || '', placeholder || '', 'mono', true);
  noI18n(box);
  wrap.appendChild(box);
  var b = cmdButton('Read from a file', 'upload', 'small');
  var input = el('input');
  input.type = 'file';
  input.hidden = true;
  b.onclick = function () { input.click(); };
  input.onchange = function () {
    var f = input.files && input.files[0];
    input.value = '';
    if (!f) return;
    fileText(f).then(function (t) {
      box.value = String(t).trim();
      box.dispatchEvent(new Event('input', {bubbles: true}));
    }).catch(oops);
  };
  var row = el('div', 'btnrow ct-pem-tools');
  row.appendChild(b);
  row.appendChild(input);
  wrap.appendChild(row);
  wrap._input = box;
  wrap._get = function () { return box.value.trim(); };
  return wrap;
}
function secretsOf(row) {
  var s = row && (row.secret_set || row.secrets_set || row.secrets);
  if (Array.isArray(s)) { var o = {}; s.forEach(function (k) { o[k] = true; }); return o; }
  return s && typeof s === 'object' ? s : {};
}

/* ==========================================================================
   The modules there are (GET /api/plugins)
   ========================================================================== */
var PLUG = null, PLUG_ASK = null;
/** The modules, with the choices of their fields resolved by the daemon (the
    authorities, sources, validations, targets there are now). `again`: asked
    anew - a popup that offers choices asks so. What was asked before the
    last change (FRESH) is never given out as current. */
function plugins(again) {
  if (PLUG && !again && PLUG._gen === FRESH.n) return Promise.resolve(PLUG);
  if (!PLUG_ASK || again || PLUG_ASK._gen !== FRESH.n) {
    var gen = FRESH.n;
    var ask = capi('plugins').then(function (d) {
      d = d || {};
      var got = {issuer: rowsOf(d.issuer || d.issuers), challenge: rowsOf(d.challenge || d.challenges),
                 target: rowsOf(d.target || d.targets), broken: rowsOf(d.broken), _gen: gen};
      if (!PLUG || gen >= (PLUG._gen || 0)) PLUG = got;
      return got;
    }).catch(function (e) { if (PLUG_ASK === ask) PLUG_ASK = null; throw e; });
    ask._gen = gen;
    PLUG_ASK = ask;
  }
  return PLUG_ASK;
}
function plugOf(family, kind) {
  if (!PLUG) return null;
  return (PLUG[family] || []).filter(function (p) { return p.kind === kind; })[0] || null;
}
function plugTitle(family, kind) {
  var p = plugOf(family, kind);
  return p ? (p.title || p.kind) : (kind || '–');
}
/* What an issuer can do: said by the module where it says so, guessed from
   its kind where it does not. */
function issuerCan(kind) {
  var p = plugOf('issuer', kind) || {};
  var k = String(kind || '');
  var acmeLike = /acme|letsencrypt|zerossl|buypass/i.test(k);
  var own = /internal|own|ca$|selfsigned|self/i.test(k);
  var pick = function (key, guess) { return p[key] !== undefined ? !!p[key] : guess; };
  return {
    challenge: pick('needs_challenge', acmeLike),
    wildcards: pick('wildcards', true),
    ip: pick('ip_names', own),
    days: pick('choose_days', own),
    types: arr(p.challenge_types || (acmeLike ? ['dns-01', 'http-01'] : [])),
    makesKey: pick('makes_key', false)
  };
}
function challengeTypes(kind) {
  var p = plugOf('challenge', kind) || {};
  if (p.types) return arr(p.types);
  return /http/i.test(String(kind || '')) ? ['http-01'] : ['dns-01'];
}
function brokenBox(family) {
  var box = el('div');
  var list = (PLUG && PLUG.broken) || [];
  var folder = {issuer: 'issuers', challenge: 'challenges', target: 'targets'}[family];
  list = list.filter(function (b) {
    var file = Array.isArray(b) ? b[0] : (b.file || b.path || '');
    var fam = !Array.isArray(b) && b.family;
    if (fam) return fam === family;
    var f = String(file);
    var any = /\/(issuers|challenges|targets)\//.test(f);
    return !folder || !any || f.indexOf('/' + folder + '/') >= 0;
  });
  if (!list.length) return box;
  var card = el('div', 'ct-broken');
  var h = el('div', 'ct-broken-h');
  h.innerHTML = iconMarkup('flag', 17);
  h.appendChild(el('b', '', list.length === 1 ? 'A module that would not load' : list.length + ' modules that would not load'));
  card.appendChild(h);
  card.appendChild(el('p', 'small muted', 'These files are there but could not be read, so what they offer is missing below. Fix the file, then restart acme (or reload the modules).'));
  list.forEach(function (b) {
    var file = Array.isArray(b) ? b[0] : (b.file || b.path || '');
    var why = Array.isArray(b) ? b[1] : (b.error || b.words || b.why || '');
    var tb = Array.isArray(b) ? b[2] : (b.traceback || b.detail || '');
    var one = el('div', 'ct-broken-one');
    one.appendChild(mono(file));
    one.appendChild(data('div', 'ct-broken-why', why));
    if (tb) {
      var det = el('details', 'ct-more');
      det.appendChild(el('summary', '', 'What Python said'));
      det.appendChild(saidBox(tb));
      one.appendChild(det);
    }
    card.appendChild(one);
  });
  box.appendChild(card);
  return box;
}
/** Choose a module: cards grouped by vendor. `go(plugin)`. */
function kindPicker(family, go, filter) {
  var box = el('div', 'ct-kinds');
  var list = ((PLUG && PLUG[family]) || []).filter(function (p) { return !filter || filter(p); });
  if (!list.length) {
    box.appendChild(el('p', 'muted', 'No module of this family is installed.'));
    return box;
  }
  var find = null;
  if (list.length > 8) {
    find = el('input');
    find.type = 'search';
    find.placeholder = 'find a module…';
    find.className = 'ct-kind-find';
    box.appendChild(find);
  }
  var groups = {}, order = [];
  /* The ones most people want first. */
  var FIRST = ['acme', 'internal_ca', 'selfsigned', 'dns_builtin', 'http_local', 'http_ssh', 'ssh', 'local'];
  list = list.slice().sort(function (a, b) {
    var x = FIRST.indexOf(a.kind), y = FIRST.indexOf(b.kind);
    return (x < 0 ? 99 : x) - (y < 0 ? 99 : y);
  });
  list.forEach(function (p) {
    var v = p.vendor || 'Other';
    if (!groups[v]) { groups[v] = []; order.push(v); }
    groups[v].push(p);
  });
  /* Mostly one module a vendor: one grid, the vendor said on each card. */
  var flat = order.length > list.length / 2;
  if (flat) { groups = {'': list}; order = ['']; }
  var tiles = [];
  order.forEach(function (v) {
    var g = el('div', 'ct-kind-group');
    if (v) g.appendChild(data('div', 'ct-vendor', v));
    var grid = el('div', 'ct-kind-grid');
    groups[v].forEach(function (p) {
      var t = el('button', 'ct-kind-tile');
      t.type = 'button';
      var ic = el('span', 'ct-kind-ic v-' + String(p.vendor || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-'));
      ic.appendChild(document.createTextNode(String(p.title || p.kind).replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase() || '?'));
      noI18n(ic);
      t.appendChild(ic);
      var w = el('span', 'ct-kind-w');
      w.appendChild(el('span', 'ct-kind-t', p.title || p.kind));
      if (p.description) {
        var desc = el('span', 'ct-kind-d', p.description);
        w.appendChild(desc);
        if (String(p.description).length > 130) explain(t, p.description);
      }
      var foot = el('span', 'ct-kind-foot');
      if (flat && p.vendor) foot.appendChild(data('span', 'ct-kind-v', p.vendor));
      foot.appendChild(mono(p.kind, 'ct-kind-k'));
      w.appendChild(foot);
      t.appendChild(w);
      t.onclick = function () { go(p); };
      t._words = ((p.title || '') + ' ' + p.kind + ' ' + v + ' ' + (p.description || '')).toLowerCase();
      tiles.push({t: t, g: g});
      grid.appendChild(t);
    });
    g.appendChild(grid);
    box.appendChild(g);
  });
  if (find) {
    find.oninput = function () {
      var q = find.value.trim().toLowerCase();
      tiles.forEach(function (x) { x.t.hidden = q && x.t._words.indexOf(q) < 0; });
      Array.prototype.forEach.call(box.querySelectorAll('.ct-kind-group'), function (g) {
        g.hidden = !g.querySelector('.ct-kind-tile:not([hidden])');
      });
    };
  }
  return box;
}
function plugHead(p, family) {
  var h = el('div', 'ct-plughead');
  var ic = el('span', 'ct-kind-ic big v-' + String(p.vendor || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-'));
  ic.textContent = String(p.title || p.kind).replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase();
  noI18n(ic);
  h.appendChild(ic);
  var w = el('div', 'ct-plughead-w');
  var t = el('div', 'ct-plughead-t');
  t.appendChild(el('b', '', p.title || p.kind));
  if (p.vendor) t.appendChild(data('span', 'tag dim', p.vendor));
  t.appendChild(mono(p.kind, 'muted small'));
  w.appendChild(t);
  if (p.description) w.appendChild(el('div', 'muted small', p.description));
  if (p.doc) {
    var d = el('div', 'small muted');
    d.appendChild(document.createTextNode('More in '));
    d.appendChild(mono(p.doc));
    w.appendChild(d);
  }
  h.appendChild(w);
  return h;
}

/* ==========================================================================
   Sources, Validation, Targets - one way of drawing all three
   ========================================================================== */
var MODS = {
  sources: {tab: 'sources', family: 'issuer', list: 'sources', keys: ['sources', 'issuers'],
            host: 'src-list', broken: 'src-broken', said: 'src-said',
            newTitle: 'A new source', pickTitle: 'Add a source', one: 'The source',
            none: 'No source yet. Add one - Let’s Encrypt, an authority of acme’s own, self-signed - before the first certificate.',
            pick: 'Where should certificates come from? Each module asks for what it needs next.',
            what: 'the sources'},
  validation: {tab: 'validation', family: 'challenge', list: 'validations', keys: ['validations', 'challenges'],
               host: 'val-list', broken: 'val-broken', said: 'val-said',
               newTitle: 'A new way of validation', pickTitle: 'Add a way of validation', one: 'The validation',
               none: 'No way of validation yet. A certificate from an ACME CA needs one: acme’s own DNS server, your DNS provider, or HTTP-01.',
               pick: 'How should names be proved? DNS-01 for wildcards and names not reachable from the internet; HTTP-01 for a web server that is.',
               what: 'validation'},
  targets: {tab: 'targets', family: 'target', list: 'targets', keys: ['targets'],
            host: 'tg-list', broken: 'tg-broken', said: 'tg-said',
            newTitle: 'A new target', pickTitle: 'Add a target', one: 'The target',
            none: 'No target yet. Add the servers and devices certificates should go to.',
            pick: 'What kind of machine is it? The module knows how to put a certificate on it and make the service take it.',
            what: 'the targets'}
};
var LISTS = {};
function loadRows(key, again) {
  var m = MODS[key];
  if (LISTS[key] && !again && LISTS[key]._gen === FRESH.n) return Promise.resolve(LISTS[key]);
  var gen = FRESH.n;
  return capi(m.list).then(function (d) {
    var rows = rowsOf.apply(null, [d].concat(m.keys));
    rows.forEach(function (r) { r.config = obj(r.config); });
    rows._gen = gen;
    if (!LISTS[key] || gen >= (LISTS[key]._gen || 0)) LISTS[key] = rows;
    return rows;
  });
}
/** The default of a list (is_default), or null. */
function defaultOf(rows) { return arr(rows).filter(function (r) { return r.is_default; })[0] || null; }
function rowsSafe(key) { return loadRows(key).catch(function () { return []; }); }
function modSummary(m, r) {
  var p = plugOf(m.family, r.kind);
  var cfg = r.config || {};
  var bits = [];
  ((p && p.fields) || []).forEach(function (f) {
    if (bits.length >= 2 || f.advanced || f.type === 'secret' || f.type === 'pem' || f.type === 'bool') return;
    var v = cfg[f.key];
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return;
    if (f.type === 'select') {
      var pr = optionPairs(f).filter(function (x) { return x[0] === String(v); })[0];
      if (pr) v = pr[1];
    }
    bits.push([f.label || f.key, Array.isArray(v) ? v.join(', ') : String(v)]);
  });
  var box = el('div', 'ct-sum');
  bits.forEach(function (b) {
    var line = el('div', 'ct-sum-l');
    line.appendChild(el('span', 'muted', b[0] + ' '));
    line.appendChild(mono(b[1]));
    box.appendChild(line);
  });
  if (!bits.length) box.appendChild(el('span', 'muted', '–'));
  return box;
}
function modStateCell(r) {
  var c = el('td', 'ct-modstate');
  var on = r.enabled === undefined || truthy(r.enabled);
  c.appendChild(el('span', 'tag ' + (on ? 'ok' : 'dim'), on ? 'on' : 'off'));
  if (r.last_error) {
    var b = el('span', 'tag crit', 'failing');
    explain(b, String(r.last_error));
    c.appendChild(b);
  } else if (r.last_ok) {
    c.appendChild(el('span', 'muted small', 'last worked ' + ago(r.last_ok)));
  }
  return c;
}
function usedCount(r) {
  var n = first(r.used_by, r.used, r.certs, r.cert_count, r.deploys_count, r.deploy_count,
                Array.isArray(r.deploys) ? r.deploys.length : undefined);
  return n === undefined ? null : Number(n);
}
function drawModTab(key, live) {
  var m = MODS[key];
  var host = $(m.host);
  if (!host) return;
  if (!live && !host.children.length) host.appendChild(el('p', 'muted', 'Asking…'));
  /* Shown: the modules asked anew too (the choices of their fields). */
  var pl = plugins(!live).catch(function () { return null; });
  Promise.all([pl, loadRows(key, true)]).then(function (got) {
    var b = $(m.broken);
    if (b) { clear(b); b.appendChild(brokenBox(m.family)); }
    var rows = got[1];
    var q = key === 'targets' && $('tg-q') ? $('tg-q').value.trim().toLowerCase() : '';
    if (q) rows = rows.filter(function (r) {
      return (r.name + ' ' + r.kind + ' ' + plugTitle(m.family, r.kind) + ' ' + JSON.stringify(r.config || {}) + ' '
              + arr(r.tags).join(' ') + ' ' + (r.note || '')).toLowerCase().indexOf(q) >= 0;
    });
    var s = $(m.said);
    if (s) s.textContent = LISTS[key].length ? num(LISTS[key].length) + ' in all' : '';
    if (key === 'sources' && b) {
      var miss = LISTS[key].filter(function (r) {
        return r.kind === 'acme' && !arr(Array.isArray((r.config || {}).contacts) ? r.config.contacts : String((r.config || {}).contacts || '').split(/[\s,;]+/)).filter(Boolean).length;
      }).map(function (r) { return r.name; });
      contactAsk(b, miss);
    }
    liveFill(host, function (box) {
      if (!LISTS[key].length) {
        var e = el('div', 'ct-blank');
        e.appendChild(el('p', 'muted', m.none));
        box.appendChild(e);
        return;
      }
      var heads = ['Name', 'Kind', 'Settings', key === 'targets' ? 'Certificates' : 'Used by', 'State', ''];
      box.appendChild(listTable(heads, rows, function (r) {
        var tr = el('tr');
        var nc = el('td', 'ct-modname');
        nc.appendChild(data('b', '', r.name));
        if (r.is_default) nc.appendChild(el('span', 'tag ok small', 'default'));
        if (r.note) nc.appendChild(data('div', 'muted small', r.note));
        if (r.tags) nc.appendChild(tagChips(r.tags));
        tr.appendChild(nc);
        var kc = el('td');
        var p = plugOf(m.family, r.kind);
        var missingMod = r.module_missing || (PLUG && !p);
        kc.appendChild(el('div', '', p ? p.title : (r.title || r.kind)));
        kc.appendChild(data('div', missingMod ? 'small ct-badtext' : 'muted small', missingMod ? 'module missing: ' + r.kind : (p ? (p.vendor || r.kind) : r.kind)));
        tr.appendChild(kc);
        var sumCell = td('', modSummary(m, r));
        if (HTTP_HERE[r.kind]) sumCell.appendChild(httpRowLine(r));
        tr.appendChild(sumCell);
        var n = usedCount(r);
        tr.appendChild(td('num', n === null ? '–' : num(n)));
        tr.appendChild(modStateCell(r));
        var tools = el('td', 'rowtools');
        if (MANAGE) {
          var t = iconButton('play', 'Test it now, without changing anything');
          t.onclick = function (ev) { ev.stopPropagation(); modTest(key, r, t); };
          tools.appendChild(t);
        }
        /* What its module can do besides (Plugin.actions): one button each. */
        modActions(r, p).forEach(function (a) {
          if (a.changes !== false ? !FULL : !MANAGE) return;
          var ab = iconButton('gear', a.label || a.key);
          ab.onclick = function (ev) { ev.stopPropagation(); modAction(key, r, a, ab); };
          tools.appendChild(ab);
        });
        if (FULL) {
          tools.appendChild(defaultButton(key, r));
          var e = iconButton('edit', 'Edit');
          e.onclick = function (ev) { ev.stopPropagation(); modEdit(key, r); };
          tools.appendChild(e);
          var x = iconButton('trash', 'Take it away');
          x.onclick = function (ev) { ev.stopPropagation(); modDelete(key, r); };
          tools.appendChild(x);
        }
        tr.appendChild(tools);
        return rowOpens(tr, function () { if (key === 'targets') targetPeek(r); else modEdit(key, r); });
      }, 'plain ct-modtable|Nothing matches'));
    }, live);
    explainWhatWasDrawn(host);
  }).catch(function (e) {
    if (s) s.textContent = '';
    failInto(host, m.what)(e);
  });
  var s = $(m.said);
}
/** A test answers {ok, said, job_id, steps} - `ok: false` is its answer, not
    a fault of the request, so it is read whatever it says (api() would turn
    it into an error without the words). */
function askRaw(path, body, wait) {
  var opts = {credentials: 'same-origin', method: 'POST', headers: {'Content-Type': 'application/json'},
              body: JSON.stringify(body || {})};
  var timer = null;
  if (typeof AbortController === 'function') {
    var ac = new AbortController();
    opts.signal = ac.signal;
    timer = setTimeout(function () { ac.abort(); }, (wait || 120) * 1000);
  }
  return fetch('?api=' + apiName(path), opts).then(function (r) {
    clearTimeout(timer);
    return r.text().then(function (t) {
      var d = null;
      try { d = JSON.parse(t); } catch (e) { }
      if (!d) { var e1 = new Error(r.status === 404 ? 'not available yet' : 'HTTP ' + r.status); e1.status = r.status; e1.missing = r.status === 404; throw e1; }
      if (!r.ok) {
        var e2 = new Error(d.error || ('HTTP ' + r.status));
        e2.status = r.status;
        e2.missing = r.status === 404 && /no such endpoint|unknown endpoint/i.test(String(d.error || ''));
        throw e2;
      }
      if (!READS.test(path)) afterWrite(path);
      return d;
    });
  }, function () { clearTimeout(timer); throw new Error('the server could not be reached'); });
}
function modTest(key, r, button, form) {
  var m = MODS[key];
  busy(button, true);
  var body = {id: r && r.id, name: r && r.name};
  if (form) { body.kind = form.kind; body.config = form.config; body.name = form.name || body.name; if (!r) delete body.id; }
  return askRaw(m.list + '/test', body, 150).then(function (d) {
    var good = d.ok !== false && !d.error;
    var words = String(d.said || d.message || d.error || (good ? 'it works' : 'it does not work'));
    toast(words, good ? 'good' : 'bad');
    if (!good && d.job_id && !form) over(function () { jobPeek(d.job_id); });
    return {ok: good, words: words, job_id: d.job_id};
  }).catch(function (e) {
    if (e && e.missing) { fail(e); return {ok: false, words: 'not available yet'}; }
    toast(wordsOf(e), 'bad');
    return {ok: false, words: wordsOf(e)};
  }).then(function (x) { busy(button, false); if (!form) { delete LISTS[key]; drawModTab(key, true); } return x; });
}
function modActions(r, p) {
  return arr(r.actions && r.actions.length ? r.actions : (p && p.actions) || []);
}
/** One of a module's actions run on a saved row ({id, action}): its steps in a job. */
function modAction(key, r, a, button) {
  var m = MODS[key];
  if (r.kind === 'acme_push' && a.key === 'discover') { pushDiscover(r, button); return; }
  var go = function () {
    busy(button, true);
    askRaw(m.list + '/action', {id: r.id, name: r.name, action: a.key}, 600).then(function (d) {
      var good = d.ok !== false && !d.error;
      toast(String(d.said || d.message || d.error || (good ? 'done' : 'it did not work')).split('\n')[0], good ? 'good' : 'bad');
      /* An action that hands a file over (a config to put in place by hand): saved, no job shown. */
      if (good && d.file && d.file.name) { saveText(d.file.name, d.file.text || ''); return; }
      if (d.job_id) over(function () { jobPeek(d.job_id); });
    }).catch(fail).then(function () { busy(button, false); delete LISTS[key]; drawModTab(key, true); });
  };
  if (a.confirm) confirmThen(r.name + ': ' + (a.label || a.key), htmlText(a.confirm) + (a.help ? '<br><span class="muted small">' + htmlText(a.help) + '</span>' : ''), a.label || a.key, go);
  else go();
}
/** Discover (acme push): the application's slots, and - for a full administrator - the
    certificates and deployments made for those not covered yet. */
function pushDiscover(r, button) {
  busy(button, true);
  Promise.all([capi('targets/discover', {name: r.name}, 120), loadRows('sources'), loadRows('validation')]).then(function (got) {
    var d = got[0], srcs = got[1] || [], vals = got[2] || [];
    var picks = {};
    var plan, src, val;
    /* Known before the popup is drawn: its buttons are made with it. */
    var freeN = arr(d.slots).filter(function (sl) {
      return !(sl.covered_by && sl.covered_by.length) && sl.installable !== false
        && (sl.names || []).length && !/^follows:/.test(sl.managed_by || '');
    }).length;
    over(function () {
      modal('Discover', function (body) {
        body.appendChild(data('p', 'muted', r.name));
        var head = el('p', 'note');
        head.appendChild(data('b', '', (d.app || '?') + ' ' + (d.version || '')));
        if (d.cluster && d.cluster.on) { head.appendChild(data('span', '', ' \u00b7 ')); head.appendChild(el('span', '', 'a cluster')); }
        body.appendChild(head);
        var table = el('table', 'plain');
        var hr = el('tr');
        ['', 'Slot', 'Names', 'Has now', 'Kept by', 'From acme'].forEach(function (w) { hr.appendChild(el('th', '', w)); });
        table.appendChild(hr);
        arr(d.slots).forEach(function (sl) {
          var tr = el('tr');
          var free = !(sl.covered_by && sl.covered_by.length) && sl.installable !== false
            && (sl.names || []).length && !/^follows:/.test(sl.managed_by || '');
          var cb = el('td');
          if (free && FULL) {
            var c = document.createElement('input');
            c.type = 'checkbox';
            c.checked = true;
            picks[sl.id] = c;
            cb.appendChild(c);
          }
          tr.appendChild(cb);
          tr.appendChild(td('', data('b', 'mono', sl.id)));
          tr.appendChild(td('', data('span', 'mono', (sl.names || []).join(', ') || '–')));
          var cur = sl.current;
          tr.appendChild(td('', cur ? data('span', '', ((cur.names || []).join(', ') || '?') + ' · ' + (cur.not_after ? stamp(cur.not_after) : '?')) : el('span', 'muted', 'nothing')));
          var by = /^follows:/.test(sl.managed_by || '') ? el('span', '', 'follows another by itself')
            : el('span', '', {'acme-push': 'acme', 'own-acme': 'its own ACME', 'manual': 'put in by hand', 'none': 'nothing'}[sl.managed_by] || String(sl.managed_by || ''));
          tr.appendChild(td('', by));
          var cov = el('td');
          if (sl.covered_by && sl.covered_by.length) cov.appendChild(data('span', 'good', sl.covered_by.map(function (x) { return x.cert; }).join(', ')));
          else if (sl.installable === false) cov.appendChild(el('span', 'muted', 'cannot be put in'));
          else if (/^follows:/.test(sl.managed_by || '')) cov.appendChild(el('span', 'muted', 'needs nothing'));
          else cov.appendChild(el('span', 'warn', 'not covered'));
          tr.appendChild(cov);
          table.appendChild(tr);
        });
        table.style.marginBottom = '18px';
        body.appendChild(table);
        if (!FULL || !Object.keys(picks).length) {
          body.appendChild(el('p', 'note', Object.keys(picks).length ? 'A full administrator can make the certificates for those not covered.' : 'Every slot that needs a certificate has one from acme.'));
          return;
        }
        plan = selectBox([['each', 'A certificate for each slot'], ['together', 'One certificate for all of them (every node’s name and the VIP address’s)']], 'each');
        body.appendChild(formField('Certificates', plan));
        src = selectBox([['', 'the default source']].concat(srcs.map(function (x) { return [x.name, x.name]; })), '');
        body.appendChild(formField('From', src));
        val = selectBox([['', 'the default validation']].concat(vals.map(function (x) { return [x.name, x.name]; })), '');
        body.appendChild(formField('Validation', val, 'Each certificate is issued by itself and pushed to its slots; renewals the same.'));
      }, [{words: 'Close', close: true}].concat(FULL && freeN ? [{words: 'Make the certificates', cls: 'primary', icon: 'save', go: function (btn) {
        var ids = Object.keys(picks).filter(function (k) { return picks[k].checked; });
        if (!ids.length) { toast('Choose a slot first', 'bad'); return; }
        busy(btn, true);
        capi('targets/adopt', {name: r.name, slots: ids, plan: plan.value, issuer: src.value, challenge: val.value}, 180).then(function (x) {
          closeModal();
          toast(said(x, 'made'), 'good');
          arr(x.left).forEach(function (l) { toast(l.slot + ': ' + l.why, 'warn'); });
        }).catch(fail).then(function () { busy(btn, false); });
      }}] : []));
    });
  }).catch(fail).then(function () { busy(button, false); });
}
/** The ACME sources with no contact e-mail: asked for once, set on all of them. */
function contactAsk(host, names) {
  if (!host || !names || !names.length || !FULL) return;
  var box = el('div', 'note warn ct-contact');
  box.appendChild(el('span', '', 'These ACME sources have no contact e-mail - the CA mails about expiry and policy there; certificates are issued without one too:'));
  box.appendChild(data('b', '', ' ' + names.join(', ') + ' '));
  var b = el('button', 'btn small', 'Set the contact e-mail…');
  b.type = 'button';
  b.onclick = function () {
    var input;
    modal('The contact e-mail of the ACME sources', function (body) {
      body.appendChild(el('p', 'note', 'Set on every ACME source that has none: ' + names.join(', ') + '. The CA writes there before a certificate runs out unrenewed and when its rules change; nothing else is sent.'));
      input = textBox('', 'admin@example.com', 'mono');
      input.type = 'email';
      input.autocomplete = 'email';
      body.appendChild(formField('E-mail', input, 'One address, or several with a comma between them.'));
      setTimeout(function () { try { input.focus(); } catch (e) { } }, 0);
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); var ok = $('modal-foot') && $('modal-foot').querySelector('button.primary'); if (ok) ok.click(); }
      });
    }, [{words: 'Close', close: true}, {words: 'Set it', cls: 'primary', icon: 'save', go: function (btn) {
      var mail = String(input.value || '').trim();
      if (!/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+(\s*[,;]\s*[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+)*$/.test(mail)) {
        toast('That is not an e-mail address', 'bad');
        try { input.focus(); } catch (e) { }
        return;
      }
      busy(btn, true);
      capi('sources/contact', {email: mail}).then(function (d) {
        closeModal();
        toast(said(d, 'set'), 'good');
        box.remove();
        delete LISTS.sources;
        drawModTab('sources', true);
      }).catch(fail).then(function () { busy(btn, false); });
    }}], 'narrow');
  };
  box.appendChild(b);
  host.insertBefore(box, host.firstChild);
}
function modDelete(key, r, fromDialog) {
  var m = MODS[key];
  var n = usedCount(r);
  var done = function (d) {
    toast(said(d, 'taken away'), 'good');
    if (fromDialog) closeModal();
    delete LISTS[key];
    drawModTab(key);
  };
  if (r.kind === 'dns_persist') { persistDelete(key, r, n, done); return; }
  confirmThen(m.one + ' ' + r.name + ': take it away',
    (n ? htmlText('It is used by ' + num(n) + ' certificate(s) or deployment(s): change those first.') + ' ' : '')
    + 'Its settings and secrets go with it.', 'Take it away', function () {
      capi(m.list + '/delete', {id: r.id, name: r.name}).then(done).catch(fail);
    });
}
/* A dns-persist-01 validation taken away (1.0.21): "Also remove its records from
   DNS" - what acme wrote through another validation, in a job first; ticked when
   acme wrote any. Records set by hand always stay. */
function persistDelete(key, r, n, done) {
  var m = MODS[key];
  var w = Number(r.persist_written || 0);
  var also = null;
  modal(m.one + ' ' + r.name + ': take it away', function (body) {
    if (n) body.appendChild(el('p', 'note warn', 'It is used by ' + num(n) + ' certificate(s) or deployment(s): change those first.'));
    body.appendChild(el('p', 'note', 'Its settings and secrets go with it.'));
    also = switchBox(w > 0);
    if (!w) also._input.disabled = true;
    body.appendChild(formField('Also remove its records from DNS', also, w
      ? (w === 1 ? 'acme wrote 1 record for it: removed first, through the validation that wrote it. If that fails, nothing is deleted.' : 'acme wrote ' + w + ' records for it: removed first, through the validation that wrote them. If that fails, nothing is deleted.')
      : 'acme wrote no record for it. Records set by hand always stay.'));
  }, [{words: 'No, leave it', close: true}, {words: 'Take it away', cls: 'danger', icon: 'trash', once: true, go: function (b) {
    busy(b, true);
    var clean = !!(also && also._get());
    capi(m.list + '/delete', {id: r.id, name: r.name, cleanup: clean ? 1 : 0}, 300).then(function (d) {
      closeModal();
      done(d);
    }).catch(function (e) { busy(b, false); fail(e); });
  }}], 'narrow');
}
/* ---- HTTP-01 answered by acme itself: how it works here -------------------
   GET /api/validations/info: the URL the CA fetches, the nodes and the VIP
   address that answer it, port 80 in their firewall, and each name that uses
   it with where it points. */
var HTTP_HERE = {http_local: true};
var HTTP_PATH = '/.well-known/acme-challenge/';
var HTTP_INFO = {};
function httpInfo(r, again) {
  var k = String(r.id || r.name);
  var had = HTTP_INFO[k];
  if (had && !again && had.gen === FRESH.n && Date.now() - had.at < 60000) return had.ask;
  var ask = capi('validations/info' + qs({id: r.id, name: r.id ? '' : r.name}));
  HTTP_INFO[k] = {at: Date.now(), gen: FRESH.n, ask: ask};
  ask.catch(function () { delete HTTP_INFO[k]; });
  return ask;
}
function okMark(v) {
  return el('span', 'tag ' + (v === true ? 'ok' : (v === false ? 'crit' : 'dim')), v === true ? '✔' : (v === false ? '✘' : '?'));
}
/** A line under the row of the list: where the CA asks, and how many names point here. */
function httpRowLine(r) {
  var line = el('div', 'muted small ct-http-row');
  line.appendChild(mono('http://NAME' + HTTP_PATH + '…'));
  line.appendChild(el('span', '', ' · port 80'));
  var more = el('span', '');
  line.appendChild(more);
  httpInfo(r).then(function (d) {
    if (!d || !d.applies) return;
    var nodes = arr(d.nodes).length;
    more.appendChild(el('span', '', ' · '));
    more.appendChild(el('span', '', 'answered by ' + nodes + ' node(s)' + (d.vip && d.vip.on ? ' and the VIP address' : '')));
    var names = arr(d.names);
    if (names.length) {
      var good = names.filter(function (n) { return n.ours === true; }).length;
      more.appendChild(el('span', '', ' · '));
      more.appendChild(el('span', '', good + ' of ' + names.length + ' name(s) point at acme'));
      if (good < names.length) line.classList.add('ct-http-warn');
    }
  }).catch(function () { });
  return line;
}
/** The section of the popup: how it works here, and "Check a name". */
function httpHere(row) {
  var box = el('div', 'ct-http');
  box.appendChild(el('h4', 'ct-formh', 'How it works here'));
  var lead = el('p', 'note');
  lead.appendChild(el('span', '', 'The CA fetches '));
  lead.appendChild(mono('http://NAME' + HTTP_PATH + '<token>'));
  lead.appendChild(el('span', '', ' - port 80, plain HTTP, from the internet. The path and the port are fixed by the ACME standard (RFC 8555) and cannot be set; what can be set is above: whether acme fetches it itself first (Check before the CA is asked) and the address Test tries. Each name must point at acme - a node or the VIP address - or at a proxy that forwards ' + HTTP_PATH + ' to acme.'));
  box.appendChild(lead);
  var host = el('div');
  box.appendChild(host);
  if (!row || !row.id) {
    host.appendChild(el('p', 'muted small', 'Saved, it shows here which machines answer, port 80 in their firewall, and where each name that uses it points.'));
    return box;
  }
  host.appendChild(el('p', 'muted', 'Asking…'));
  var probeOut = el('div');
  var probe = function (name, button) {
    if (!name) { toast('which name?', 'bad'); return; }
    busy(button, true);
    clear(probeOut);
    probeOut.appendChild(el('p', 'muted', 'Fetching a probe token from ' + name + '…'));
    askRaw('validations/check', {id: row.id, host: name}, 60).then(function (d) {
      clear(probeOut);
      var good = d.ok !== false && !d.error;
      probeOut.appendChild(saidLine(good ? 'good' : 'bad', String(d.said || d.error || (good ? 'it answers' : 'it does not answer'))));
      probeOut.appendChild(jobLog(d.steps || []));
    }).catch(function (e) {
      clear(probeOut);
      probeOut.appendChild(saidLine('bad', wordsOf(e)));
    }).then(function () { busy(button, false); });
  };
  httpInfo(row, true).then(function (d) {
    clear(host);
    if (!d || !d.applies) return;
    var who = [];
    arr(d.nodes).forEach(function (n) {
      who.push([n.name + (n.me ? ' (this node)' : ''), function () {
        var w = el('span', '');
        w.appendChild(mono((n.dns && n.dns !== n.name ? n.dns + ' · ' : '') + (n.address || '–')));
        w.appendChild(el('span', 'tag ' + (n.alive ? 'ok' : 'crit') + ' small', n.alive ? 'answers' : 'not heard'));
        if (n.vip_here) w.appendChild(el('span', 'tag info small', 'holds the VIP address'));
        return w;
      }()]);
    });
    if (d.vip && d.vip.on) {
      var vw = el('span', '');
      vw.appendChild(mono((d.vip.fqdn ? d.vip.fqdn + ' · ' : '') + [d.vip.address, d.vip.address6].filter(Boolean).join(', ')));
      if (d.vip.holder) vw.appendChild(el('span', 'muted small', ' on ' + d.vip.holder));
      who.push(['The VIP address', vw]);
    }
    host.appendChild(el('h4', 'ct-formh', 'Answered by'));
    host.appendChild(kvTable(who));
    host.appendChild(el('h4', 'ct-formh', 'Port 80 in the firewall'));
    host.appendChild(listTable(['Node', 'Port 80', ''], arr(d.firewall), function (f) {
      var tr = el('tr');
      tr.appendChild(td('', data('span', '', f.node)));
      var st = el('td');
      st.appendChild(el('span', 'tag ' + (f.open === false ? 'crit' : (f.open ? 'ok' : 'dim')), f.open === false ? 'closed' : (f.open ? (f.from_anywhere ? 'open from anywhere' : 'open to some networks') : '?')));
      tr.appendChild(st);
      tr.appendChild(td('muted small', el('span', '', f.why || '')));
      return tr;
    }, 'plain'));
    host.appendChild(el('h4', 'ct-formh', 'Names proved by it'));
    var names = arr(d.names);
    if (!names.length) host.appendChild(emptyNote('No certificate uses it yet.'));
    else host.appendChild(listTable(['Name', 'Certificate', 'Resolves to', '', '', ''], names, function (n) {
      var tr = el('tr');
      tr.appendChild(td('', mono(n.name)));
      tr.appendChild(td('small', data('span', '', n.cert || '')));
      tr.appendChild(td('', mono(arr(n.addresses).join(', ') || '–')));
      tr.appendChild(td('', okMark(n.ours)));
      tr.appendChild(td('small', el('span', '', n.words || '')));
      var tools = el('td', 'rowtools');
      if (MANAGE && !n.wildcard) {
        var cb = iconButton('play', 'Check this name: a probe token fetched from it');
        cb.onclick = function () { probe(n.name, cb); };
        tools.appendChild(cb);
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain'));
    if (d.names_more) host.appendChild(el('p', 'muted small', 'and ' + d.names_more + ' more'));
    if (MANAGE) {
      host.appendChild(el('h4', 'ct-formh', 'Check a name'));
      var row2 = el('div', 'btnrow');
      var nb = textBox('', 'www.example.com', 'mono');
      noI18n(nb);
      nb.style.flex = '1';
      var go = cmdButton('Check it', 'play', 'small');
      go.onclick = function () { probe(nb.value.trim(), go); };
      nb.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
      row2.appendChild(nb);
      row2.appendChild(go);
      host.appendChild(row2);
      host.appendChild(el('p', 'muted small', 'acme puts a probe token in place and fetches http://NAME' + HTTP_PATH + '<token> itself, step by step. Fetched from this node: behind NAT a router may not loop back to its own public address (hairpin NAT) although the CA from outside is answered.'));
      host.appendChild(probeOut);
    }
  }).catch(function (e) { clear(host); host.appendChild(failedBox(e, 'how it works here')); });
  return box;
}

/** The section of a validation's popup: for each certificate that uses it,
    the records to create (the CNAMEs, the delegation) and their state. */
function setupHere(row) {
  var box = el('div', 'ct-http ct-rd-setup');
  box.appendChild(el('h4', 'ct-formh', 'What to set up'));
  box.appendChild(el('p', 'note', 'For each certificate that uses it: what its names need, where, and whether it is there now. Nothing is changed.'));
  var bar = el('div', 'btnrow');
  var again = cmdButton('Check again', 'refresh', 'small');
  bar.appendChild(again);
  box.appendChild(bar);
  var host = el('div');
  box.appendChild(host);
  var ticket = modalTicket();
  var load = function (force) {
    busy(again, true);
    clear(host);
    host.appendChild(el('p', 'muted', 'Asking…'));
    rdAsk('setup:' + row.id + ':' + (row.updated || ''), function () { return capi('validations/setup' + qs({id: row.id})); }, force).then(function (d) {
      if (!modalStill(ticket)) return;
      clear(host);
      var certs = arr(d.certs);
      if (!certs.length) { host.appendChild(emptyNote('No certificate uses it yet.')); return; }
      var cards = certs.map(function (c) {
        var card = el('div', 'ct-rd-group ' + (c.ok ? 'ok' : 'bad'));
        card._ok = !!c.ok;
        card._title = c.name;
        var head = el('div', 'ct-rd-head');
        head.appendChild(okMark(!!c.ok));
        head.appendChild(data('b', 'ct-rd-domain', c.name));
        head.appendChild(namesChips(arr(c.names), 8));
        card.appendChild(head);
        var steps = arr(c.steps).filter(function (st) { return (st.record && String(st.record.value || '').charAt(0) !== '(') || st.done === false; });
        var sb = el('div', 'ct-rd-steps ct-rd-body');
        if (!steps.length) sb.appendChild(el('p', 'muted small', 'Nothing to create for its names.'));
        rdSteps(sb, steps);
        card.appendChild(sb);
        return rdFold(card, head, sb);
      });
      rdList(host, cards, ['certificate', 'certificates']);
      if (d.more) host.appendChild(el('p', 'muted small', 'and ' + d.more + ' more'));
    }).catch(function (e) { if (modalStill(ticket)) { clear(host); host.appendChild(failedBox(e, 'what to set up')); } })
      .then(function () { busy(again, false); });
  };
  again.onclick = function () { load(true); };
  load(false);
  return box;
}

/** dns-persist-01 (challenges/dns_persist.py): the record each ACME source needs, set
    once - whether it is there now, and whether each CA offers dns-persist-01 yet. */
/* acme-dns: an account made at its server and put into the form (Save keeps it).
   No names: one account (username, password, subdomain, full domain); names: one
   account each, in "Accounts by name" - an account holds two TXT values only. */
function acmeDnsHere(form) {
  var box = el('div', 'ct-setup ct-acmedns');
  box.appendChild(el('h4', 'ct-formh', 'An account at the acme-dns server'));
  box.appendChild(el('p', 'note', 'Makes the account at the server above (POST /register) and fills it in here - nothing is saved until Save. With names, one account each (an acme-dns account keeps two TXT values only: a certificate of more names needs one a name); the CNAME of each is listed to copy.'));
  var names = el('textarea', 'mono');
  names.rows = 3;
  names.spellcheck = false;
  names.placeholder = 'www.example.com\nmail.example.com';
  noI18n(names);
  box.appendChild(formField('Names (empty: one account)', names));
  var out = el('div', 'ct-acmedns-out');
  var go = cmdButton('Register an account', 'add', '');
  go.onclick = function () {
    var cur = form.read();
    var url = String(cur.url || '').trim();
    if (!url) { toast('Set the acme-dns server first', 'bad'); return; }
    var list = String(names.value || '').split(/[\s,;]+/).filter(Boolean);
    busy(go, true);
    clear(out);
    capi('validations/acme_dns_register', {url: url, names: list, verify_tls: cur.verify_tls !== false}, 120).then(function (d) {
      if (d.account) {
        ['username', 'password', 'subdomain', 'fulldomain'].forEach(function (k) { form.set(k, d.account[k]); });
        out.appendChild(el('p', 'good', 'Filled in - save the validation to keep it. Put into your DNS, once per name:'));
        out.appendChild(data('code', 'mono', '_acme-challenge.NAME.  CNAME  ' + d.account.fulldomain + '.'));
      } else {
        form.set('accounts', JSON.stringify(d.accounts, null, 1));
        out.appendChild(el('p', 'good', 'Filled in "Accounts by name" - save the validation to keep them. Put into your DNS:'));
        arr(d.records).forEach(function (r) {
          var line = el('div', 'ct-acmedns-rec');
          line.appendChild(data('code', 'mono', r.name + '.  CNAME  ' + r.value));
          var c = iconButton('copy', 'Copy');
          c.onclick = function () { copyText(r.name + '. CNAME ' + r.value); };
          line.appendChild(c);
          out.appendChild(line);
        });
      }
    }).catch(fail).then(function () { busy(go, false); });
  };
  box.appendChild(go);
  box.appendChild(out);
  return box;
}
/* SSH DNS (challenges/ssh_dns.py): "Find out what runs there" - acme signs in and runs
   read-only commands only; what it found fills the form in (empty fields at once, the
   ones set otherwise only when asked), the zones listed to pick one. Every field stays
   editable: nothing is saved until Save. */
function sshDnsHere(form, row, p, nameNow) {
  var box = el('div', 'ct-setup ct-sshdns');
  box.appendChild(el('h4', 'ct-formh', 'What runs there'));
  box.appendChild(el('p', 'note', 'acme signs in over SSH and only reads: which DNS server runs there, its zones, their files and keys, whether sudo works. Nothing is written, reloaded or restarted. What it finds is filled in below - check it, then Save. If it finds nothing, every field can be set by hand.'));
  var go = cmdButton('Find out what runs there', 'search', '');
  var out = el('div', 'ct-sshdns-out');
  var fieldsOf = {};
  arr(p.fields).forEach(function (f) { fieldsOf[f.key] = f; });
  var same = function (a, b) {
    var s = function (v) { return Array.isArray(v) ? v.map(String).join('\n') : (v === undefined || v === null ? '' : String(v)); };
    if (typeof a === 'boolean' || typeof b === 'boolean') return truthy(a) === truthy(b);
    return s(a).trim() === s(b).trim();
  };
  var empty = function (k, v) {
    var f = fieldsOf[k] || {};
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) return true;
    return f['default'] !== undefined && same(v, f['default']);
  };
  /* "Filled in: Zone, Zones there. Save ..." - each label a text of its own (translated) */
  var labelsLine = function (cls, head, keys) {
    var line = el('p', cls);
    line.appendChild(el('span', '', head));
    line.appendChild(document.createTextNode(': '));
    keys.forEach(function (k, i) {
      if (i) line.appendChild(document.createTextNode(', '));
      line.appendChild(el('b', '', (fieldsOf[k] || {}).label || k));
    });
    line.appendChild(document.createTextNode('. '));
    line.appendChild(el('span', '', 'Save the validation to keep it.'));
    return line;
  };
  var shown = function (v) { return Array.isArray(v) ? v.join(', ') : (typeof v === 'boolean' ? (v ? 'yes' : 'no') : String(v)); };
  var fill = function (fields, host) {
    var now = [], ask = [];
    /* the way first: the fields of that way are the ones shown then */
    var keys = Object.keys(fields || {}).sort(function (a, b) { return (b === 'flavour') - (a === 'flavour'); });
    keys.forEach(function (k) {
      if (!fieldsOf[k]) return;
      var cur = form.get(k), v = fields[k];
      if (same(cur, v)) return;
      if (empty(k, cur)) now.push(k); else ask.push(k);
    });
    now.forEach(function (k) { form.set(k, fields[k]); });
    if (now.length) host.appendChild(labelsLine('good', 'Filled in', now));
    if (!ask.length) { if (!now.length) host.appendChild(el('p', 'muted small', 'The form already says what was found.')); return; }
    var pane = el('div', 'ct-sshdns-ask');
    pane.appendChild(el('p', 'warn', 'These are set otherwise than what was found - replace them?'));
    var list = el('table', 'plain tight');
    var hr = el('tr');
    ['', 'Field', 'Now', 'Found'].forEach(function (w) { hr.appendChild(el('th', '', w)); });
    list.appendChild(hr);
    var picks = {};
    ask.forEach(function (k) {
      var tr = el('tr');
      var c = document.createElement('input');
      c.type = 'checkbox';
      c.checked = true;
      picks[k] = c;
      var cb = el('td');
      cb.appendChild(c);
      tr.appendChild(cb);
      tr.appendChild(td('', el('span', '', fieldsOf[k].label || k)));
      tr.appendChild(td('', data('span', 'mono', shown(form.get(k)))));
      tr.appendChild(td('', data('span', 'mono', shown(fields[k]))));
      list.appendChild(tr);
    });
    pane.appendChild(list);
    var bar = el('div', 'btnrow');
    var yes = cmdButton('Replace the ticked ones', 'check', 'primary small');
    var no = cmdButton('Keep mine', 'cancel', 'small');
    yes.onclick = function () {
      var did = ask.filter(function (k) { return picks[k].checked; });
      did.forEach(function (k) { form.set(k, fields[k]); });
      clear(pane);
      pane.appendChild(did.length ? labelsLine('good', 'Replaced', did) : el('p', 'muted small', 'Nothing replaced.'));
    };
    no.onclick = function () { clear(pane); pane.appendChild(el('p', 'muted small', 'Kept as it was.')); };
    bar.appendChild(yes);
    bar.appendChild(no);
    pane.appendChild(bar);
    host.appendChild(pane);
  };
  var draw = function (d) {
    var f = d.found || {};
    clear(out);
    if (!f.ok) {
      var bad = el('div', 'ct-errbox');
      bad.appendChild(el('b', '', 'It could not be found out'));
      arr(f.problems).forEach(function (w) { bad.appendChild(el('p', 'said', w)); });
      bad.appendChild(el('p', 'muted small', 'Every field below can still be set by hand.'));
      out.appendChild(bad);
    } else {
      out.appendChild(factsRow([
        ['Server', f.server ? data('b', '', f.server + (f.version ? ' ' + f.version : '')) : el('span', 'muted', 'none found')],
        ['Suggested', f.flavour_suggested ? mono(f.flavour_suggested) : '–'],
        ['Signed in as', f.user ? mono(f.user + (f.root ? ' (root)' : '')) : '–'],
        ['sudo -n', f.root ? 'not needed' : (f.sudo_works ? (f.sudo ? 'works, needed' : 'works') : 'does not work')]
      ]));
      var zones = arr(f.zones);
      if (zones.length) {
        var t = el('div', 'ct-sshdns-zones');
        zones.forEach(function (z) {
          var row = el('div', 'ct-sshdns-zone' + (z.flavour ? '' : ' off'));
          var left = el('div', 'ct-sshdns-zname');
          left.appendChild(data('b', 'mono', z.name));
          if (z.dynamic || z.journal) { left.appendChild(document.createTextNode(' ')); left.appendChild(el('span', 'tag dim', 'dynamic')); }
          if (z.file) left.appendChild(data('div', 'mono small muted ct-sshdns-file', z.file));
          row.appendChild(left);
          var right = el('div', 'ct-sshdns-how');
          right.appendChild(el('div', z.flavour ? '' : 'muted', z.how_writable || z.flavour || 'not by acme'));
          if (z.flavour && z.flavour === f.flavour_suggested) {
            var use = cmdButton('Use only this one', 'check', 'small');
            use.onclick = function () { form.set('zone', z.name); toast('Zone: ' + z.name, 'good'); };
            right.appendChild(use);
          }
          row.appendChild(right);
          t.appendChild(row);
        });
        out.appendChild(t);
        out.appendChild(el('p', 'muted small', 'With Zone left empty each name goes in the longest of "Zones there" it is in.'));
      }
      var keys = arr(f.keys).filter(function (k) { return k.name; });
      if (keys.length) {
        var kp = el('p', 'small');
        kp.appendChild(el('span', 'muted', 'Keys: '));
        kp.appendChild(data('span', 'mono', keys.map(function (k) { return k.name + (k.file ? ' (' + k.file + ')' : ''); }).join(', ')));
        out.appendChild(kp);
      }
      if (arr(f.problems).length) {
        var pb = el('ul', 'ct-sshdns-problems');
        arr(f.problems).forEach(function (w) { pb.appendChild(el('li', 'warn small', w)); });
        out.appendChild(pb);
      }
      fill(f.fields || {}, out);
    }
    if (arr(f.commands).length) {
      var det = el('details', 'ct-more');
      det.appendChild(el('summary', '', 'What was run there (read-only)'));
      det.appendChild(saidBox(arr(f.commands).join('\n')));
      out.appendChild(det);
    }
    if (d.job_id) {
      var st = el('button', 'btn small ct-steps-btn', 'every step');
      st.type = 'button';
      st.onclick = function () { over(function () { jobPeek(d.job_id); }); };
      out.appendChild(st);
    }
  };
  go.onclick = function () {
    var cur = form.read();
    if (!String(cur.host || '').trim()) { toast('Set the DNS server first', 'bad'); return; }
    busy(go, true);
    clear(out);
    out.appendChild(el('p', 'muted', 'Asking…'));
    capi('validations/ssh_dns_discover', {id: row && row.id, name: nameNow ? nameNow() : '', kind: 'ssh_dns', config: cur}, 150)
      .then(draw).catch(function (e) { clear(out); out.appendChild(failedBox(e, 'what runs there')); })
      .then(function () { busy(go, false); });
  };
  box.appendChild(go);
  box.appendChild(out);
  return box;
}
function persistHere(row, p) {
  var box = el('div', 'ct-http ct-rd-setup ct-persist');
  box.appendChild(el('h4', 'ct-formh', 'The record to set once'));
  var cfg = obj(row.config);
  var via = String(cfg.writer || '').trim();
  box.appendChild(el('p', 'note', via
    ? 'One TXT record for each ACME account, at _validation-persist.DOMAIN - acme writes it through the validation chosen in “Write the record through” when you press “Write the records to DNS”, and takes away exactly what it wrote. Records set by hand are never touched.'
    : 'One TXT record for each ACME account, at _validation-persist.DOMAIN. Several may stand at the same name - Let’s Encrypt and its staging have different accounts. Nothing is changed in your DNS: set it by hand, or choose a validation in “Write the record through” and save.'));
  var bar = el('div', 'btnrow ct-persist-bar');
  var again = cmdButton('Check the records', 'refresh', 'small');
  var make = cmdButton('Make the record', 'key', 'small');
  var write = cmdButton('Write the records to DNS', 'upload', 'small');
  var away = cmdButton('Take the records away', 'trash', 'small');
  bar.appendChild(again);
  if (MANAGE) bar.appendChild(make);
  /* Writing in DNS changes something elsewhere: a full administrator's (action_role). */
  write.hidden = !(FULL && via);
  away.hidden = !(FULL && Number(row.persist_written || 0) > 0);
  bar.appendChild(write);
  bar.appendChild(away);
  var look = null;
  var lookAct = arr((p && p.actions) || []).filter(function (a) { return a.key === 'look'; })[0];
  if (MANAGE && lookAct) {
    look = cmdButton('Look now (staging)', 'play', 'small');
    look.hidden = true;
    bar.appendChild(look);
    look.onclick = function () { modAction('validation', row, lookAct, look); };
  }
  box.appendChild(bar);
  var said = saidLine('', '');
  said.hidden = true;
  box.appendChild(said);
  var host = el('div');
  box.appendChild(host);
  var ticket = modalTicket();
  var STATE = {present: ['there', 'ok'], missing: ['missing', 'crit'], different: ['another value', 'warn'], unknown: ['not known', 'dim']};
  var load = function (register, button) {
    ticket = modalTicket();
    busy(button, true);
    clear(host);
    host.appendChild(el('p', 'muted', register ? 'Making the accounts where there are none…' : 'Asking…'));
    capi('validations/persist', {id: row.id, register: !!register}, 150).then(function (d) {
      if (!modalStill(ticket)) return;
      clear(host);
      var got = obj(d.persist);
      var cas = arr(got.cas);
      if (look) look.hidden = !cas.some(function (c) { return c.staging; });
      away.hidden = !(FULL && arr(got.written).length);
      cas.forEach(function (c) {
        var line = el('div', 'ct-rd-step ' + (c.offered ? 'ok' : 'unk'));
        line.appendChild(okMark(c.offered ? true : null));
        var w = el('div', 'ct-rd-w');
        w.appendChild(el('b', '', c.words || ''));
        if (arr(c.sources).length) w.appendChild(data('div', 'muted small', arr(c.sources).join(', ')));
        line.appendChild(w);
        host.appendChild(line);
      });
      if (!arr(got.records).length) { host.appendChild(emptyNote('There is no ACME source: the record names an ACME account.')); return; }
      if (!arr(got.domains).length) host.appendChild(el('p', 'note warn', 'Set “Domains with the record” to see the exact record for each and check it.'));
      else if (got.derived) host.appendChild(el('p', 'muted small', 'The domains of the certificates that use it (“Domains with the record” is empty).'));
      arr(got.records).forEach(function (r) {
        var ok = r.ok === true ? true : (r.ok === false ? false : null);
        var one = el('div', 'ct-rd-step ' + (ok === true ? 'ok' : (ok === false ? (got.fallback ? 'warn' : 'bad') : 'unk')));
        one.appendChild(okMark(ok));
        var w = el('div', 'ct-rd-w');
        var top = el('div', 'ct-rd-what');
        top.appendChild(data('b', '', r.title || r.source));
        top.appendChild(data('span', 'muted small ct-rd-where', r.source + (r.domain ? ' · ' + r.domain : '')));
        if (r.state && STATE[r.state]) top.appendChild(el('span', 'tag small ct-persist-state ' + STATE[r.state][1], STATE[r.state][0]));
        w.appendChild(top);
        if (r.account) w.appendChild(data('div', 'mono small muted', r.account));
        if (r.error || r.said) w.appendChild(el('div', 'muted small ct-rd-said', r.error || r.said));
        if (r.written) {
          var wl = el('div', 'muted small');
          wl.appendChild(el('span', '', 'written by acme through '));
          wl.appendChild(data('b', '', r.via || '?'));
          w.appendChild(wl);
        }
        var rec = r.record;
        if (rec && rec.type && rec.value) w.appendChild(rdRecord(rec));
        one.appendChild(w);
        host.appendChild(one);
      });
      if (got.fallback) host.appendChild(el('p', 'muted small', 'Until the CA offers dns-persist-01 (or while the record is not right), the fallback validation proves the names.'));
      else host.appendChild(el('p', 'note warn', 'No fallback validation is chosen: until the CA offers dns-persist-01, no certificate can be issued with this validation.'));
    }).catch(function (e) { if (modalStill(ticket)) { clear(host); host.appendChild(failedBox(e, 'the record')); } })
      .then(function () { busy(button, false); });
  };
  /* Write / Take away: an action of the module, in a job (its steps and an event). */
  var act = function (key, button) {
    busy(button, true);
    said.hidden = false;
    said.className = 'said';
    said.textContent = key === 'write_records' ? 'Writing…' : 'Taking away…';
    askRaw('validations/action', {id: row.id, name: row.name, action: key}, 600).then(function (d) {
      var good = d.ok !== false && !d.error;
      clear(said);
      said.className = 'said ' + (good ? 'good' : 'bad');
      said.appendChild(data('span', '', String(d.said || d.message || d.error || (good ? 'done' : 'it did not work')).split('\n')[0]));
      if (d.job_id) {
        var st = el('button', 'btn small ct-steps-btn', 'every step');
        st.type = 'button';
        st.onclick = function () { over(function () { jobPeek(d.job_id); }); };
        said.appendChild(st);
      }
      delete LISTS.validation;
      load(false, again);
    }).catch(function (e) { said.className = 'said bad'; said.textContent = wordsOf(e); })
      .then(function () { busy(button, false); });
  };
  again.onclick = function () { load(false, again); };
  make.onclick = function () { load(true, make); };
  write.onclick = function () { act('write_records', write); };
  away.onclick = function () {
    over(function () {
      confirmThen(row.name + ': take the records away',
        htmlText('The dns-persist-01 records acme wrote are removed from DNS. Until they are written again, the names are proved by the fallback validation.')
        + '<br><span class="muted small">' + htmlText('Records set by hand stay.') + '</span>',
        'Take the records away', function () { act('remove_records', away); });
    });
  };
  load(false, again);
  return box;
}

/* ---- the default of a list ------------------------------------------------ */
var DEFAULT_WORDS = {
  sources: 'A new certificate comes from it when no source is said.',
  validation: 'A new certificate from an ACME CA is proved by it when nothing else is said.',
  targets: 'Offered first when a certificate is deployed - in the new certificate and in a new deployment.',
  cas: 'Offered first for a new source of the kind "own certificate authority" and for signing a CSR.'
};
/** {name} ('' for none) to POST /api/<list>/default; the authorities {id}. */
function setDefault(key, r, yes, button) {
  var path = key === 'cas' ? 'cas/default' : MODS[key].list + '/default';
  var body = key === 'cas' ? {id: yes ? r.id : ''} : {name: yes ? r.name : ''};
  if (button) busy(button, true);
  return capi(path, body).then(function (d) {
    toast(said(d, yes ? 'it is the default now' : 'there is no default now'), 'good');
    if (key === 'cas') loadCas(true); else drawModTab(key, true);
    return d;
  }).catch(fail).then(function (d) { if (button) busy(button, false); return d; });
}
/** The star in a row: "Make it the default" - or, on the default, "no default". */
function defaultButton(key, r) {
  var on = !!r.is_default;
  var b = iconButton('star', on ? 'The default - press to have no default' : 'Make it the default');
  b.classList.add('ct-star');
  if (on) b.classList.add('on');
  b.setAttribute('aria-pressed', on ? 'true' : 'false');
  b.onclick = function (ev) { ev.stopPropagation(); setDefault(key, r, !on, b); };
  return b;
}
/** The same in a popup: a button of the foot. */
function defaultFoot(key, r, back) {
  if (!FULL || !r || !(r.id || r.name)) return null;
  var on = !!r.is_default;
  return {words: on ? 'No default' : 'Make it the default', icon: 'star', go: function (b) {
    setDefault(key, r, !on, b).then(function (d) {
      if (!d) return;
      r.is_default = !on;
      if (back) back(); else closeModal();
    });
  }};
}
/** The tag and the words of a default in a popup. */
function defaultNote(key, r) {
  if (!r || !r.is_default) return null;
  var p = el('p', 'note ct-default-note');
  p.appendChild(el('span', 'tag ok small', 'default'));
  p.appendChild(el('span', '', ' ' + DEFAULT_WORDS[key]));
  return p;
}

function modEdit(key, row, p, fromPick) {
  var m = MODS[key];
  /* A form offers choices (an authority, a source, a validation): asked anew. */
  plugins(true).then(function () {
    if (!row && !p) { modPick(key); return; }
    p = p || plugOf(m.family, row.kind) || {kind: row.kind, title: row.kind, fields: [], missing: true};
    modForm(key, row, p, fromPick);
  }).catch(fail);
}
function modPick(key) {
  var m = MODS[key];
  modal(m.pickTitle, function (body) {
    body.appendChild(el('p', 'note', m.pick));
    body.appendChild(kindPicker(m.family, function (p) { modForm(key, null, p, true); }));
  }, [{words: 'Close', close: true}], 'large');
}
function modForm(key, row, p, fromPick) {
  var m = MODS[key];
  var cfg = (row && row.config) || {};
  var form = null, name = null, note = null, on = null, tags = null, testSaid = null;
  var title = row ? m.one + ' ' + row.name : m.newTitle + ' · ' + (p.title || p.kind);
  var gather = function () {
    return {id: row && row.id, name: name.value.trim(), kind: p.kind, config: form.read(),
            enabled: on._get(), note: note.value, tags: tags ? splitNames(tags.value) : undefined};
  };
  var buttons = [];
  if (fromPick) buttons.push({words: 'Back', icon: 'prev', left: true, go: function () { modPick(key); }});
  buttons.push({words: 'Close', close: true});
  if (MANAGE) buttons.push({words: 'Test', icon: 'play', go: function (b) {
    var g = gather();
    testSaid.className = 'said';
    testSaid.textContent = 'Trying…';
    modTest(key, row, b, g).then(function (x) {
      clear(testSaid);
      testSaid.className = 'said ' + (x.ok ? 'good' : 'bad');
      testSaid.appendChild(data('span', '', x.words));
      if (x.job_id) {
        var st = el('button', 'btn small ct-steps-btn', 'every step');
        st.type = 'button';
        st.onclick = function () { over(function () { jobPeek(x.job_id); }); };
        testSaid.appendChild(st);
      }
    });
  }});
  var df = row ? defaultFoot(key, row, function () { closeModal(); modEdit(key, row); }) : null;
  if (df) buttons.push(df);
  /* Asked in a popup over the dialog (1.0.21): it went at once, without a word. */
  if (row && FULL) buttons.push({words: 'Take it away', cls: 'danger', icon: 'trash', once: true, go: function () {
    over(function () { modDelete(key, row, true); });
  }});
  if (FULL) buttons.push({words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
    var g = gather();
    if (!g.name) { name.focus(); name.parentNode.classList.add('refused'); toast('it needs a name', 'bad'); return; }
    var bad = form.check();
    if (bad) { toast(bad, 'bad'); return; }
    busy(b, true);
    capi(m.list + '/save', g).then(function (d) {
      toast(said(d, 'saved'), 'good');
      delete LISTS[key];
      closeModal();
      drawModTab(key);
    }).catch(fail).then(function () { busy(b, false); });
  }});
  modal(title, function (body) {
    body.appendChild(plugHead(p, m.family));
    var dn = defaultNote(key, row);
    if (dn) body.appendChild(dn);
    if (p.missing) body.appendChild(el('p', 'ct-bad', 'The module of this kind is not installed (or would not load): its settings are shown as they are kept.'));
    var g = el('div', 'formgrid ct-basic');
    var others = arr(LISTS[key]).filter(function (x) { return !row || x.id !== row.id; }).map(function (x) { return x.name; });
    name = textBox(row ? row.name : safeName(p.default_name || p.title || p.kind, others), tr('a name of its own'), '');
    noI18n(name);
    if (FULL) guardName(name, true, others);
    g.appendChild(formField('Name', name, 'What it is called here, in the certificates and the jobs.'));
    on = switchBox(row ? (row.enabled === undefined || truthy(row.enabled)) : true);
    g.appendChild(formField('In use', on, 'Off: kept, but not used for anything.'));
    note = textBox(row ? row.note : '', '', '');
    var nf = formField('Note', note);
    if (key === 'targets') {
      tags = tagsBox(row ? arr(row.tags) : []);
      noI18n(tags);
      g.appendChild(formField('Tags', tags, 'Words to find and group targets by.'));
    } else nf.classList.add('wide');
    g.appendChild(nf);
    body.appendChild(g);
    body.appendChild(el('h4', 'ct-formh', 'Settings of the module'));
    form = fieldForm(p.fields || [], cfg, secretsOf(row), {noneWords: 'This module needs nothing set.', family: m.family, row: row, plug: p});
    body.appendChild(form.node);
    /* Where the files, the script and the roles of Windows are set: each certificate's
       deployment, not here (this is how acme reaches the machine). */
    if (key === 'targets' && p.files_ui) {
      var hint = el('div', 'muted small ct-deploy-hint');
      hint.appendChild(el('span', '', 'Files, their format, the script after them' + (p.kind === 'windows_ssh' ? ' and the roles of the server (IIS, RDS, AD FS, SQL…)' : '') + ': '));
      hint.appendChild(el('span', '', 'set for each certificate in its deployment - Certificates → the certificate → Deployments → "Deploy it on a target", or "Deploy a certificate here" in the detail of this target. Here only how acme reaches the machine, and the script it runs when a deployment says nothing.'));
      body.appendChild(hint);
    }
    testSaid = saidLine('', '');
    body.appendChild(testSaid);
    if (HTTP_HERE[p.kind]) body.appendChild(httpHere(row));
    if (row && row.id && MANAGE && p.kind === 'dns_persist') body.appendChild(persistHere(row, p));
    if (FULL && p.kind === 'acme_dns') body.appendChild(acmeDnsHere(form));
    if (MANAGE && p.kind === 'ssh_dns') body.appendChild(sshDnsHere(form, row, p, function () { return name.value.trim(); }));
    if (row && row.id && MANAGE && m.family === 'challenge') body.appendChild(setupHere(row));
    if (!FULL) Array.prototype.forEach.call(body.querySelectorAll('input, select, textarea'), function (x) { if (!x.closest('.ct-http')) x.disabled = true; });
  }, buttons, 'medium');
}

/* ---- a target and what is deployed on it --------------------------------- */
var DEPLOY_STATE = {ok: ['deployed', 'ok'], deployed: ['deployed', 'ok'], failed: ['failed', 'crit'],
  pending: ['waiting', 'dim'], 'new': ['not yet', 'dim'], running: ['deploying', 'info'],
  deploying: ['deploying', 'info'], changed: ['options changed', 'warn'],
  outdated: ['old version', 'warn'], disabled: ['off', 'dim'], unknown: ['–', 'dim']};
function deployTag(d, certVersion) {
  var st = d.state || (d.last_error ? 'failed' : (d.last_ok ? 'ok' : 'new'));
  if (d.enabled !== undefined && !truthy(d.enabled)) st = 'disabled';
  if ((st === 'ok' || st === 'deployed') && certVersion && d.deployed_version && Number(d.deployed_version) < Number(certVersion)) st = 'outdated';
  var m = DEPLOY_STATE[st] || [st, 'dim'];
  var t = el('span', 'tag ' + m[1], m[0]);
  if (st === 'failed' && d.last_error) explain(t, String(d.last_error));
  return t;
}
/* What is deployed on one target. The daemon lists deployments by
   certificate; where it does not answer GET /api/deploys?target=, they are
   gathered from the certificates that have any. */
function deploysOfTarget(r) {
  if (Array.isArray(r.deploys)) return Promise.resolve(r.deploys);
  return capi('deploys' + qs({target: r.name})).then(function (d) { return rowsOf(d, 'deploys'); })
    .catch(function (e) {
      if (!e || !e.missing) throw e;
      return capi('certs' + qs({per: 1000})).then(function (d) {
        var some = rowsOf(d, 'certs').filter(function (c) { return Number(c.deploys || 0) > 0; }).slice(0, 60);
        return Promise.all(some.map(function (c) {
          return capi('certs/one' + qs({id: c.id})).then(function (x) {
            return rowsOf(x.deploys).filter(function (dp) { return dp.target === r.name; }).map(function (dp) {
              dp.cert_name = dp.cert_name || c.name;
              dp.cert_version = (x.cert && x.cert.version) || c.version;
              return dp;
            });
          }).catch(function () { return []; });
        })).then(function (lists) { return [].concat.apply([], lists); });
      });
    });
}
function targetPeek(r) {
  var m = MODS.targets;
  var draw = function (got) {
    var p = plugOf('target', r.kind) || {kind: r.kind, title: r.kind, fields: [], deploy_fields: []};
    var deps = got.deps, depsErr = got.err;
    return {
      size: 'large',
      build: function (body) {
        body.appendChild(plugHead(p, 'target'));
        var dn = defaultNote('targets', r);
        if (dn) body.appendChild(dn);
        var cfg = r.config || {};
        var addr = first(cfg.host, cfg.address, cfg.hostport, cfg.url, cfg.server, '');
        body.appendChild(factsRow([
          ['Kind', p.title || r.kind],
          addr ? ['Address', mono(String(addr))] : null,
          ['State', (r.enabled === undefined || truthy(r.enabled)) ? 'in use' : 'off'],
          ['Last worked', r.last_ok ? ago(r.last_ok) : 'never'],
          ['Certificates', deps ? num(deps.length) : '–']
        ]));
        if (r.last_error) {
          var le = el('div', 'ct-errbox');
          le.appendChild(el('b', '', 'The last time it failed'));
          le.appendChild(saidBox(r.last_error));
          body.appendChild(le);
        }
        var grid = el('div', 'msects');
        var sec = section('Certificates deployed here', 'Each with the options it has on this target. Run deploys it again now.', true);
        if (depsErr) sec._body.appendChild(failedBox(depsErr, 'the deployments of a target'));
        else sec._body.appendChild(deployTable(deps || [], {target: r, back: function () { targetPeek(r); }}));
        if (MANAGE) {
          var add = cmdButton('Deploy a certificate here', 'add', 'primary small');
          add.onclick = function () { over(function () { deployEdit({target: r}); }, function () { targetPeek(r); }); };
          var row = el('div', 'btnrow'); row.appendChild(add);
          sec._body.appendChild(row);
        }
        grid.appendChild(sec);
        var st = section('Settings', 'How acme reaches it. Secrets are never shown - only whether they are set.');
        var pairs = [];
        var sset = secretsOf(r);
        (p.fields || []).forEach(function (f) {
          var v = cfg[f.key];
          if (f.type === 'secret' || f.secret) { pairs.push([f.label || f.key, secretShownTag(sset[f.key], v)]); return; }
          if (v === undefined || v === null || v === '') return;
          if (f.type === 'bool') v = truthy(v) ? 'yes' : 'no';
          else if (Array.isArray(v)) v = v.join('\n');
          else if (f.type === 'pem') v = String(v).slice(0, 64) + '…';
          pairs.push([f.label || f.key, f.type === 'bool' ? String(v) : mono(String(v))]);
        });
        if (!p.fields || !p.fields.length) Object.keys(cfg).forEach(function (k) {
          if (cfg[k] !== '' && cfg[k] !== null && typeof cfg[k] !== 'object') pairs.push([k, mono(String(cfg[k]))]);
        });
        st._body.appendChild(pairs.length ? kvTable(pairs) : emptyNote('Nothing set.'));
        grid.appendChild(st);
        var ab = section('About it');
        ab._body.appendChild(kvTable([
          ['Made', r.created ? stamp(r.created) + (r.created_by ? ' · ' + r.created_by : '') : '–'],
          ['Changed', r.updated ? stamp(r.updated) : '–'],
          ['Tags', arr(r.tags).length ? tagChips(r.tags) : '–'],
          ['Note', r.note || '–'],
          ['Module', mono(p.module || p.kind || '')]
        ]));
        grid.appendChild(ab);
        body.appendChild(grid);
      },
      buttons: [{words: 'Close', close: true},
        defaultFoot('targets', r, function () { closeModal(); targetPeek(r); }),
        MANAGE ? {words: 'Test', icon: 'play', go: function (b) { modTest('targets', r, b); }} : null,
        FULL ? {words: 'Edit', icon: 'edit', go: function () { modEdit('targets', r); }} : null
      ].filter(Boolean)
    };
  };
  popup(m.one + ' ' + r.name, function () {
    return Promise.all([plugins().catch(function () { return null; }),
      deploysOfTarget(r).then(function (d) { return {deps: d}; }, function (e) { return {err: e}; })])
      .then(function (x) { return x[1]; });
  }, draw, 'large');
}
/** The deployments of a certificate, or of a target. `o.cert` or `o.target`. */
function deployTable(rows, o) {
  var byCert = !!o.target;
  var heads = [byCert ? 'Certificate' : 'Target', 'State', 'Version', 'Last deployed', 'Options', ''];
  return listTable(heads, rows, function (d) {
    var tr = el('tr');
    var nc = el('td');
    if (byCert) {
      nc.appendChild(data('b', '', first(d.cert_name, d.cert, d.name, '#' + d.cert_id)));
    } else {
      nc.appendChild(data('b', '', d.target));
      var tg = (LISTS.targets || []).filter(function (t) { return t.name === d.target; })[0];
      if (tg) nc.appendChild(el('div', 'muted small', plugTitle('target', tg.kind)));
    }
    tr.appendChild(nc);
    tr.appendChild(td('', deployTag(d, (o.cert && o.cert.version) || d.cert_version)));
    tr.appendChild(td('num', d.deployed_version ? 'v' + d.deployed_version : '–'));
    tr.appendChild(d.last_ok ? stampCell(d.last_ok) : td('muted', d.last_try ? 'last tried ' + ago(d.last_try) : 'never'));
    var opt = obj(d.options);
    var keys = Object.keys(opt).filter(function (k) { return opt[k] !== '' && opt[k] !== null && typeof opt[k] !== 'object'; }).slice(0, 2);
    var oc = el('td', 'ct-sum');
    keys.forEach(function (k) {
      var l = el('div', 'ct-sum-l');
      l.appendChild(el('span', 'muted', k + ' '));
      l.appendChild(mono(String(opt[k])));
      oc.appendChild(l);
    });
    if (!keys.length) oc.textContent = '–';
    tr.appendChild(oc);
    var tools = el('td', 'rowtools');
    if (MANAGE) {
      var run = iconButton('deploy', 'Deploy it there again now');
      run.onclick = function (ev) {
        ev.stopPropagation();
        busy(run, true);
        capi('deploys/run', {id: d.id}).then(function (x) { jobStarted(x, 'deploying', o.back); })
          .catch(fail).then(function () { busy(run, false); });
      };
      tools.appendChild(run);
      var ed = iconButton('edit', 'The options of this deployment');
      ed.onclick = function (ev) { ev.stopPropagation(); over(function () { deployEdit({deploy: d, cert: o.cert, target: o.target}); }, o.back); };
      tools.appendChild(ed);
    }
    tr.appendChild(tools);
    if (d.last_error) {
      var why = el('div', 'ct-rowerr');
      why.textContent = String(d.last_error);
      nc.appendChild(why);
    }
    return MANAGE ? rowOpens(tr, function () { over(function () { deployEdit({deploy: d, cert: o.cert, target: o.target}); }, o.back); }) : tr;
  }, 'plain ct-deptable|Not deployed anywhere yet');
}
/** One certificate on one target: its options drawn from the target's
    module (`deploy_fields`). o: {deploy, cert ({id,name}), target (row or name)}. */
function deployEdit(o) {
  var d = o.deploy || {};
  var certId = first(d.cert_id, o.cert && o.cert.id);
  var tName = first(d.target, o.target && (o.target.name || o.target));
  modal('A deployment', function (b) { b.appendChild(el('p', 'center muted', 'Asking…')); }, [{words: 'Close', close: true}], 'medium');
  var ticket = modalTicket();
  Promise.all([plugins(true).catch(function () { return null; }), loadRows('targets', true).catch(function () { return []; }),
               certId ? Promise.resolve(null) : capi('certs' + qs({per: 1000})).then(function (x) { return rowsOf(x, 'certs'); }).catch(function () { return []; })])
  .then(function (got) {
    if (!modalStill(ticket)) return;
    var targets = got[1], certs = got[2];
    var tSel = null, cSel = null, formHost = el('div'), form = null, on = null;
    var target = function () {
      var n = tSel ? tSel.value : tName;
      return targets.filter(function (t) { return t.name === n; })[0] || (o.target && o.target.name ? o.target : {name: n, kind: ''});
    };
    var drawFields = function () {
      clear(formHost);
      var t = target();
      var p = plugOf('target', t.kind);
      if (!t.name) { formHost.appendChild(el('p', 'muted', 'Choose a target first.')); form = null; return; }
      if (!p) {
        formHost.appendChild(el('p', 'ct-bad', 'The module of this target (' + (t.kind || '?') + ') is not installed: its options cannot be drawn.'));
        form = null;
        return;
      }
      formHost.appendChild(el('h4', 'ct-formh', 'Options on ' + (p.title || p.kind)));
      /* A dual certificate (ECDSA + RSA): a target of one certificate is asked which
         of the two it gets; one that serves both is told it takes both. */
      var dual = deployDual();
      var opts = obj(d.options);
      var fields = arr(p.deploy_fields).filter(function (f) { return !f.dual_only || dual || opts[f.key]; });
      if (dual) formHost.appendChild(el('p', 'muted small', p.dual
        ? 'The certificate is dual (ECDSA and RSA): this target takes both, and gives each client the one it takes.'
        : 'The certificate is dual (ECDSA and RSA): this target holds one at a time - choose which below (RSA where unsure: every client can use it).'));
      /* A target that writes files (ssh, windows_ssh, local): the files designer,
         its live preview and the script after them (deployfiles.js). */
      if (p.files_ui && window.ACME_DEPLOY_UI) {
        var cid0 = cSel ? cSel.value : certId;
        form = window.ACME_DEPLOY_UI.form(p, fields, opts, secretsOf(d), {
          target: t.name, targetRow: t, deploy_id: d.id, cert_id: cid0 ? (isNaN(Number(cid0)) ? cid0 : Number(cid0)) : null,
          dual: dual, sudo: truthy((t.config || {}).sudo)});
        formHost.appendChild(form.node);
        $('modal-box').classList.remove('medium');
        $('modal-box').classList.add('large');
        if (testBtn) testBtn.hidden = !(p.files_ui.dry_run && MANAGE);
        return;
      }
      if (testBtn) testBtn.hidden = true;
      if ($('modal-box').classList.contains('large')) { $('modal-box').classList.remove('large'); $('modal-box').classList.add('medium'); }
      form = fieldForm(fields, opts, secretsOf(d), {noneWords: 'This target needs nothing more: the certificate goes where the module puts it.'});
      formHost.appendChild(form.node);
    };
    var deployDual = function () {
      if (o.cert && o.cert.key_type_alt) return true;
      if (d.cert_dual) return true;
      var cid = cSel ? cSel.value : '';
      return !!(cid && arr(certs).some(function (c) { return String(c.id) === String(cid) && c.key_type_alt; }));
    };
    var save = function (b, run) {
      var t = target();
      var cid = cSel ? cSel.value : certId;
      if (!cid) { toast('choose the certificate', 'bad'); return; }
      if (!t.name) { toast('choose the target', 'bad'); return; }
      if (form) { var bad = form.check(); if (bad) { toast(bad, 'bad'); return; } }
      busy(b, true);
      capi('deploys/save', {id: d.id, cert_id: isNaN(Number(cid)) ? cid : Number(cid), target: t.name,
                            options: form ? form.read() : {}, enabled: on._get()}).then(function (x) {
        var id = (x && (x.id || x.deploy_id)) || d.id;
        /* Saved: pressed again (the deployment run after it refused - not issued
           yet), it is this one saved again, not a second one made. (1.0.19) */
        d.id = id;
        if (!run) { toast(said(x, 'saved'), 'good'); closeModal(); CT.refresh(); return; }
        return capi('deploys/run', {id: id}).then(function (y) { closeModal(); jobStarted(y, 'deploying'); });
      }).catch(fail).then(function () { busy(b, false); });
    };
    var buttons = [{words: 'Close', close: true}];
    var testBtn = null;
    if (MANAGE) buttons.push({words: 'Test', icon: 'play', cls: 'df-testbtn', go: function (b) {
      if (form && form.test) form.test(b);
    }});
    if (d.id && MANAGE) buttons.push({words: 'Take it off', cls: 'danger', icon: 'trash', go: function () {
      capi('deploys/delete', {id: d.id}).then(function (x) { toast(said(x, 'taken off'), 'good'); closeModal(); CT.refresh(); }).catch(fail);
    }});
    if (MANAGE) {
      buttons.push({words: 'Save', icon: 'save', go: function (b) { save(b, false); }});
      buttons.push({words: 'Save and deploy now', cls: 'primary', icon: 'deploy', go: function (b) { save(b, true); }});
    }
    var certName = first(d.cert_name, o.cert && o.cert.name, certId ? '#' + certId : '');
    modal(d.id ? 'The deployment of ' + certName + ' on ' + tName : 'Deploy a certificate', function (body) {
      body.appendChild(el('p', 'note', 'Where the certificate goes on this target and in what shape. When it is renewed, it is put there again by itself - and the job checks what is served afterwards.'));
      var g = el('div', 'formgrid');
      if (certId) {
        g.appendChild(formField('Certificate', data('div', 'ct-fixed', certName)));
      } else {
        cSel = selectBox([['', tr('choose one…')]].concat(certs.map(function (c) { return [String(c.id), c.name + (c.cn && c.cn !== c.name ? ' (' + c.cn + ')' : '')]; })), '');
        noI18n(cSel);
        cSel.onchange = function () { drawFields(); };
        g.appendChild(formField('Certificate', cSel));
      }
      if (tName && (o.target || d.id)) {
        var tt = target();
        var fx = el('div', 'ct-fixed');
        fx.appendChild(data('span', '', tName));
        if (tt.kind) { var fxk = el('span', 'muted small', ' · '); fxk.appendChild(el('span', '', plugTitle('target', tt.kind))); fx.appendChild(fxk); }
        g.appendChild(formField('Target', fx));
      } else {
        /* The default target offered first (preselected). */
        var dtg = defaultOf(targets);
        tSel = selectBox([['', tr('choose one…')]].concat(targets.map(function (t) { return [t.name, t.name + ' · ' + plugTitle('target', t.kind) + (t.is_default ? ' · ' + tr('default') : '')]; })), tName || (dtg ? dtg.name : ''));
        noI18n(tSel);
        tSel.onchange = drawFields;
        g.appendChild(formField('Target', tSel, targets.length ? '' : 'No target yet - a full administrator adds them under Targets.'));
      }
      on = switchBox(d.id ? (d.enabled === undefined || truthy(d.enabled)) : true);
      g.appendChild(formField('In use', on, 'Off: kept, but the certificate is not put there.'));
      body.appendChild(g);
      body.appendChild(formHost);
      drawFields();
      if (d.last_error) {
        var le = el('div', 'ct-errbox');
        le.appendChild(el('b', '', 'The last time it failed'));
        le.appendChild(saidBox(d.last_error));
        body.appendChild(le);
      }
      if (!MANAGE) Array.prototype.forEach.call(body.querySelectorAll('input, select, textarea'), function (x) { x.disabled = true; });
    }, buttons, 'medium');
    testBtn = $('modal-foot').querySelector('.df-testbtn');
    var tp = target(), pl = plugOf('target', tp.kind);
    if (testBtn) testBtn.hidden = !(pl && pl.files_ui && pl.files_ui.dry_run);
    if (pl && pl.files_ui) { $('modal-box').classList.remove('medium'); $('modal-box').classList.add('large'); }
    explainWhatWasDrawn($('modal-body'));
  }).catch(function (e) { if (modalStill(ticket)) { var b = $('modal-body'); clear(b); b.appendChild(failedBox(e)); } });
}

/* ==========================================================================
   Certificates
   ========================================================================== */
var CL = {page: 0, total: 0, rows: [], drawn: 0};
function certFilters() {
  return {search: $('ct-q') ? $('ct-q').value.trim() : '', state: $('ct-state') ? $('ct-state').value : '',
          issuer: $('ct-issuer') ? $('ct-issuer').value : '', per: $('ct-per') ? Number($('ct-per').value || 50) : 50,
          owner: $('ct-owner') ? $('ct-owner').value : '', tag: $('ct-tag') ? $('ct-tag').value : ''};
}
function fillIssuerFilter() {
  var sel = $('ct-issuer');
  if (!sel || sel._filled) return;
  rowsSafe('sources').then(function (rows) {
    sel._filled = true;
    var keep = sel.value;
    /* Filled anew after a change (forgetAll): the first option ("any") stays. */
    while (sel.options.length > 1) sel.remove(1);
    rows.forEach(function (r) {
      var o = el('option', '', r.name);
      o.value = r.name;
      noI18n(o);
      sel.appendChild(o);
    });
    sel.value = keep;
  });
}
function loadCerts(live) {
  var host = $('ct-table');
  if (!host) return;
  fillIssuerFilter();
  var f = certFilters();
  if (!live && !host.children.length) host.appendChild(el('p', 'muted', 'Asking…'));
  if (window.ACME_TEAMS) ACME_TEAMS.fillFilters();
  apiLatest('ct-list', apiName('certs') + '&' + qs({search: f.search, state: f.state, issuer: f.issuer,
                                                    owner: f.owner, tag: f.tag,
                                                    page: CL.page + 1, per: f.per}).slice(1)).then(function (d) {
    var rows = rowsOf(d, 'certs');
    CL.rows = rows;
    CL.total = Number(first(d.total, rows.length));
    $('ct-said').textContent = num(CL.total) + ' certificate(s)';
    liveFill(host, function (box) {
      if (!CL.total && !f.search && !f.state && !f.issuer && !f.owner && !f.tag) { box.appendChild(certsBlank()); return; }
      box.appendChild(listTable(['State', 'Name', 'Names', 'Source', 'Expires', 'Renews',
                                 'Deployed', 'Last job', ''], rows, certRow, 'rows ct-certs|Nothing matches', {own: true}));
    }, live);
    pager('ct-pager', CL.page, f.per, CL.total, function (p) { CL.page = p; loadCerts(); });
    explainWhatWasDrawn(host);
    approvalsBadge();
  }).catch(function (e) {
    if (e && e.stopped) return;
    $('ct-said').textContent = '';
    clear($('ct-pager'));
    failInto(host, 'the certificates')(e);
  });
}
/** How many requests of the portal wait for an administrator: a badge that filters them. */
function approvalsBadge() {
  var b = $('ct-approvals');
  if (!b) return;
  capi('certs' + qs({state: 'pending-approval', per: 1})).then(function (d) {
    var n = Number(first(d.total, 0)) || 0;
    b.hidden = !n;
    setButtonIcon(b, 'clock', n + ' waiting for approval');
    b.style.color = 'var(--warn)';
    b.onclick = function () { openCerts({state: 'pending-approval'}); };
  }).catch(function () { b.hidden = true; });
}
function approveDialog(c, ok, back) {
  popup(ok ? 'Approve the request' : 'Decline the request', null, function () {
    var why = areaBox('', ok ? 'a word to the person (not needed)' : 'why - the person who asked is told', 3);
    var s = el('div', 'said');
    return {
      size: 'medium',
      build: function (body) {
        body.appendChild(namesChips(c.names));
        body.appendChild(el('p', 'note', ok
          ? 'It is issued now from ' + (c.issuer || '?') + ' and renewed by itself after; ' + (c.owner || 'the person') + ' is told by mail, if the directory has their mail.'
          : 'It is not issued. ' + (c.owner || 'The person') + ' sees it declined on the portal, with what you write, and is told by mail.'));
        body.appendChild(wideField(ok ? 'A word to them' : 'Why', why, ''));
        body.appendChild(s);
      },
      buttons: [{words: 'Cancel', close: true}, {words: ok ? 'Approve and issue' : 'Decline', cls: ok ? 'primary' : 'danger', once: true, icon: ok ? 'check' : 'ban', go: function (b) {
        busy(b, true);
        capi('certs/approve', {id: c.id, ok: ok, why: why.value}).then(function (d) {
          CT.refresh();
          toast(said(d, ok ? 'approved' : 'declined'), 'good');
          /* Its job in this popup's place: closed, the certificate is there again, drawn afresh. */
          if (ok && d.job_id) jobPeek(d.job_id); else closeModal();
        }).catch(function (e) { s.className = 'said bad'; s.textContent = wordsOf(e); }).then(function () { busy(b, false); });
      }}]
    };
  }, 'medium');
}
function certsBlank() {
  var b = el('div', 'ct-blank big');
  var ic = el('div', 'ct-blank-ic');
  ic.innerHTML = iconMarkup('cert', 34);
  b.appendChild(ic);
  b.appendChild(el('h3', '', 'No certificate yet'));
  b.appendChild(el('p', 'muted', 'Add one from a source - Let’s Encrypt, an authority of acme’s own, self-signed - or import one you already have. acme renews it before it runs out and deploys it where you say.'));
  if (MANAGE) {
    var row = el('div', 'btnrow');
    var a = cmdButton('Add a certificate', 'add', 'primary');
    a.onclick = function () { certWizard(); };
    var i = cmdButton('Import', 'upload', '');
    i.onclick = function () { importDialog(); };
    row.appendChild(a);
    row.appendChild(i);
    b.appendChild(row);
  }
  return b;
}
function certRow(c) {
  var tr = el('tr');
  if (c.state === 'failed' || c.state === 'expired') tr.classList.add('ct-hot');
  tr.appendChild(td('', stateTag(c.state)));
  var nc = el('td', 'ct-cname');
  nc.appendChild(data('b', '', c.name));
  if (arr(c.tags).length) nc.appendChild(tagChips(c.tags));
  tr.appendChild(nc);
  tr.appendChild(td('', namesChips(c.names || c.cn, 2)));
  var ic = el('td', 'muted');
  ic.appendChild(data('span', '', c.issuer || (c.source === 'import' ? 'imported' : (c.source === 'csr' ? 'outside CA' : '–'))));
  tr.appendChild(ic);
  var ec = el('td', 'ct-exp');
  if (c.not_after) {
    ec.appendChild(el('span', 'day', dayOnly(c.not_after)));
    ec.appendChild(el('br'));
    ec.appendChild(daysTag(c.not_after, c.renew_days));
  } else ec.appendChild(el('span', 'muted', '–'));
  tr.appendChild(ec);
  var ac = el('td');
  ac.appendChild(autoRenew(c, true));
  tr.appendChild(ac);
  tr.appendChild(deployCell(c));
  var jc = el('td', 'ct-lastjob');
  var lj = c.last_job || null;
  if (lj && typeof lj === 'object') {
    jc.appendChild(jobTag(lj));
    jc.appendChild(el('span', 'muted small ct-jk', JOB_KIND[lj.kind] || lj.kind || ''));
    jc.appendChild(el('span', 'muted small', ago(lj.ts)));
    jc.onclick = function (e) { e.stopPropagation(); jobPeek(lj.id); };
    jc.classList.add('ct-link');
  } else if (c.last_try || c.last_ok) {
    jc.appendChild(el('span', 'muted small', c.last_error ? 'renewal failed ' + ago(c.last_try) : 'last renewed ' + ago(c.last_ok || c.last_try)));
  } else jc.appendChild(el('span', 'muted', '–'));
  if (c.last_error && (c.state === 'failed')) explain(jc, String(c.last_error));
  tr.appendChild(jc);
  var tools = el('td', 'rowtools');
  if (MANAGE && c.state !== 'revoked' && c.state !== 'pending' && !asked(c)) {
    var r = iconButton('refresh', 'Renew it now');
    r.onclick = function (ev) { ev.stopPropagation(); certRenew(c, r); };
    tools.appendChild(r);
  }
  tr.appendChild(tools);
  return rowOpens(tr, function () { certPeek(c.id); });
}
/* Renewal by itself, switched on and off where it is shown (the list, the
   certificate) - nothing else changes: the certificate stays valid and deployed. */
function autoCan(c) {
  return MANAGE && !!c.issuer && c.state !== 'revoked' && c.state !== 'pending' && !asked(c);
}
function autoRenew(c, inList, after) {
  var auto = c.auto_renew === undefined || truthy(c.auto_renew);
  var box = el('span', inList ? 'ct-auto' : 'ct-auto ct-auto-wrap');
  var words = function (on) {
    return inList ? (on ? 'auto' : 'by hand')
      : (on ? 'by itself, ' + (c.renew_days || 30) + ' days before the end' : 'only when asked');
  };
  var tag = el('span', inList ? 'tag ' + (auto ? 'ok' : 'dim') : '', words(auto));
  if (!autoCan(c)) {
    box.appendChild(tag);
    if (inList) explain(tag, !c.issuer ? 'Imported or from an outside CA - renewed by importing a new one.'
      : (auto ? 'Renewed ' + (c.renew_days || 30) + ' days before it runs out (or when the CA suggests).' : 'Renewed only when asked.'));
    return box;
  }
  var sw = switchBox(auto);
  sw.classList.add('small');
  sw.onclick = function (e) { e.stopPropagation(); };
  var says = function (on) {
    sw.removeAttribute('aria-label');
    explain(sw, on ? 'Renewed by itself - switch off to stop it (it stays valid and deployed, nothing is revoked).'
      : 'Renewed only when asked - switch on to renew it by itself again.');
  };
  says(auto);
  sw._input.onchange = function () {
    var on = sw._input.checked;
    sw._input.disabled = true;
    capi('certs/auto', {id: c.id, auto_renew: on}).then(function (d) {
      c.auto_renew = on ? 1 : 0;
      tag.textContent = tr(words(on));
      if (inList) tag.className = 'tag ' + (on ? 'ok' : 'dim');
      says(on);
      toast(said(d, on ? 'renewed by itself' : 'not renewed by itself'), 'good');
      if (after) after(on);
    }).catch(function (err) { sw._input.checked = !on; fail(err); })
      .then(function () { sw._input.disabled = false; });
  };
  box.appendChild(sw);
  box.appendChild(tag);
  return box;
}
function deployCell(c) {
  var cell = el('td', 'ct-depcell');
  var n = Number(first(c.deploys, c.deploy_count, c.deploys_total, 0)) || 0;
  if (Array.isArray(c.deploys)) n = c.deploys.length;
  var bad = Number(first(c.deploys_failed, c.deploys_bad, 0)) || 0;
  if (!n) { cell.appendChild(el('span', 'muted', '–')); return cell; }
  var t = el('span', 'ct-depn ' + (bad ? 'crit' : 'ok'), num(n));
  explain(t, n === 1 ? 'Deployed on 1 target.' : 'Deployed on ' + n + ' targets.');
  cell.appendChild(t);
  if (bad) cell.appendChild(el('span', 'tag crit', num(bad) + ' failed'));
  return cell;
}
/* Delete (1.0.21): asked in a popup, and revoked at its CA first unless the box
   is cleared - a certificate deleted here stayed valid out there. Revoke alone
   stays its own button. */
function deleteDialog(c) {
  var also = null, reason = null;
  var no = c.revoke_no || '';
  modal('Delete ' + c.name, function (body) {
    body.appendChild(el('p', 'note', 'It is deleted from acme with its versions and deployments - this cannot be taken back. Nothing is removed from the targets: what is in place there stays.'));
    also = switchBox(!no);
    if (no) also._input.disabled = true;
    var f = formField('Revoke it first', also, no ? 'Not possible: ' + no + '.'
      : 'Its CA is told it must not be trusted any more, then it is deleted. If the revocation fails, nothing is deleted and you are told why.');
    body.appendChild(f);
    reason = selectBox(REVOKE_REASONS.filter(function (x) { return x[0] !== 'cACompromise'; }), 'cessationOfOperation');
    var rf = formField('Why', reason, 'Said to the CA.');
    body.appendChild(rf);
    var sync = function () { rf.hidden = !also._get(); };
    also._input.addEventListener('change', sync);
    sync();
    if (c.key_type_alt && !no) body.appendChild(el('p', 'note small muted', 'A dual certificate: both of its keys are revoked.'));
  }, [{words: 'No, leave it', close: true}, {words: 'Delete it', cls: 'danger', icon: 'trash', once: true, go: function (b) {
    busy(b, true);
    var rev = !!also._get();
    capi('certs/delete', {id: c.id, revoke: rev ? 1 : 0, reason: reason.value}).then(function (x) {
      closeModal();
      closeModal();
      if (rev && x && x.job_id) jobStarted(x, 'revoking, then deleting'); else { toast(said(x, 'deleted'), 'good'); CT.refresh(); }
    }).catch(function (e) { busy(b, false); fail(e); });
  }}], 'narrow');
  nameInTitle('Delete', c.name);
}
function certRenewGo(c, button, back) {
  busy(button, true);
  return capi('certs/renew', {id: c.id, force: true}).then(function (d) { jobStarted(d, 'renewing', back); })
    .catch(fail).then(function () { busy(button, false); });
}
/* A certificate that is there and valid is renewed only once it is said
   what that does (1.0.18): a new one from its source now, asked of the CA. A
   first issue, a revoked one or a failed job tried again go at once. */
function certRenew(c, button, back) {
  if (!c.not_after || c.state === 'revoked' || c.state === 'failed') return certRenewGo(c, button, back);
  over(function () {
    modal('Renew ' + (c.cn || c.name) + ' now?', function (body) {
      body.appendChild(el('p', 'note', 'A new certificate is asked for at once, whether it is due or not - the one in use now stays valid until it runs out (it is not revoked).'));
      var facts = [];
      if (c.issuer) facts.push(['From', data('span', '', c.issuer)]);
      facts.push(['Its key', c.from_csr ? 'the same key - the CSR sent in is used again' : (c.reuse_key ? 'the same key is kept' : 'a new key')]);
      if (c.key_type_alt) facts.push(['Dual', 'both certificates - ' + (c.key_type || '') + ' and ' + c.key_type_alt]);
      var n = Array.isArray(c.deploys) ? c.deploys.length : (Number(c.deploy_count || c.deploys_total || 0) || 0);
      facts.push(['Then', n ? 'put in place again on its targets' : 'nothing to deploy']);
      body.appendChild(kvTable(facts));
      /* Only for a source of a public CA (ACME and the commercial ones): an own
         authority or self-signed has no such limits. */
      var src = ((typeof LISTS === 'object' && LISTS && LISTS.sources) || []).filter(function (x) { return x.name === c.issuer; })[0];
      if (src && /acme|letsencrypt|zerossl|buypass|google|digicert|sectigo|sslmarket|globalsign|entrust/i.test(String(src.kind || ''))) {
        var lim = el('p', 'note small muted', 'A public CA counts every certificate it issues: renewing again and again can hit its limits.');
        lim.style.marginTop = '12px';
        body.appendChild(lim);
      }
    }, [{words: 'No, leave it', close: true}, {words: 'Renew now', cls: 'primary', icon: 'refresh', go: function (b) {
      busy(b, true);
      capi('certs/renew', {id: c.id, force: true}).then(function (d) { closeModal(); jobStarted(d, 'renewing'); })
        .catch(fail).then(function () { busy(b, false); });
    }}], 'narrow');
    nameInTitle('Renew', c.cn || c.name);
  }, back);
}
function certDeploy(c, button, back) {
  busy(button, true);
  capi('certs/deploy', {id: c.id}).then(function (d) { jobStarted(d, 'deploying', back); })
    .catch(fail).then(function () { busy(button, false); });
}

/* ---- everything about one ------------------------------------------------- */
function certPeek(id) {
  popup('A certificate', function () {
    return Promise.all([capi('certs/one' + qs({id: id})), rowsSafe('targets'), plugins().catch(function () { return null; })])
      .then(function (x) { return x[0]; });
  }, function (d) {
    var c = d.cert || d;
    c.names = arr(c.names);
    var versions = rowsOf(d.versions), deploys = rowsOf(d.deploys), jobs = rowsOf(d.jobs);
    var back = function () { certPeek(c.id); };
    var buttons = [];
    var waiting = c.state === 'pending' || c.csr_waiting;
    if (MANAGE) buttons.push({words: 'Delete', cls: 'danger', icon: 'trash', left: true, once: true, go: function () {
      over(function () { deleteDialog(c); }, back);
    }});
    buttons.push({words: 'Close', close: true});
    if (window.ACME_RUNPLAN) buttons.push({words: 'What happens', icon: 'list',
      says: 'Everything a renewal of it does, step by step: the key, every call to its source, how each name is proved, and on each target every call, file and command - worked out without doing any of it.',
      go: function () { ACME_RUNPLAN.open({id: c.id, name: c.name, back: back}); }});
    if (MANAGE && c.issuer && c.not_after && c.state !== 'revoked')
      buttons.push({words: 'Revoke', icon: 'ban', go: function () { over(function () { revokeDialog(c); }, back); }});
    if (MANAGE && c.issuer) buttons.push({words: c.not_after ? 'Change names, key, source…' : 'Edit', icon: 'edit',
      says: c.not_after ? 'The whole set-up, step by step. What is in the certificate itself (names, key, source, profile) takes a new certificate - you choose: now, or at its next renewal. Owner, tags, note and renewal are changed at once in Details above.' : '',
      go: function () { certWizard(c, d); }});
    if (MANAGE && (c.not_after || versions.length)) buttons.push({words: 'Export', icon: 'download', go: function () { over(function () { exportDialog(c, versions); }, back); }});
    if (MANAGE && waiting) buttons.push({words: 'Upload the answer', cls: 'primary', icon: 'upload', go: function () { over(function () { csrAnswer(c); }, back); }});
    if (MANAGE && !c.issuer && !waiting) buttons.push({words: 'Import a new one', icon: 'upload', go: function () { over(function () { importDialog(c); }, back); }});
    if (MANAGE && deploys.length && c.not_after && c.state !== 'revoked') buttons.push({words: 'Deploy now', icon: 'deploy', go: function (b) { certDeploy(c, b, back); }});
    if (MANAGE && c.issuer && c.state === 'revoked') buttons.push({words: 'Issue a new one', cls: 'primary', icon: 'refresh', go: function (b) { certRenew(c, b, back); }});
    if (MANAGE && c.issuer && c.state !== 'revoked' && !waiting && !asked(c)) buttons.push({words: c.not_after ? 'Renew now' : 'Issue now', cls: 'primary', icon: 'refresh', go: function (b) { certRenew(c, b, back); }});
    if (MANAGE && c.state === 'pending-approval') {
      buttons.push({words: 'Decline', icon: 'ban', go: function () { over(function () { approveDialog(c, false, back); }, back); }});
      buttons.push({words: 'Approve', cls: 'primary', icon: 'check', go: function () { over(function () { approveDialog(c, true, back); }, back); }});
    }
    return {
      title: c.name,
      size: 'large',
      build: function (body) { certBody(body, c, versions, deploys, jobs, back); },
      buttons: buttons
    };
  }, 'large', 'certificates');
}
/* What a certificate says of itself that is not in the certificate - its owner,
   tags, note, how it renews, its name here, on or off: shown, and with the
   pencil changed where it is shown and saved alone. Nothing is issued. */
function detailsSection(c, back) {
  var sec = section('Details', 'Changed here at once - none of this is in the certificate, nothing is issued again.');
  sec.classList.add('tm-details');
  var h = sec.querySelector('h4');
  var show = function () {
    clear(sec._body);
    sec._body.appendChild(kvTable([
      ['Owner', c.owner ? (window.ACME_TEAMS ? ACME_TEAMS.ownerChip(c.owner) : data('span', '', c.owner)) : 'nobody'],
      ['Tags', arr(c.tags).length ? tagChips(c.tags) : '–'],
      ['Note', c.note ? data('span', '', c.note) : '–'],
      ['Renews', autoCan(c) ? (truthy(c.auto_renew) ? 'by itself' : 'only when asked') : 'by importing a new one'],
      ['Days before the end', c.renew_days ? String(c.renew_days) : 'as Renewal and notices says'],
      ['Key on renewal', truthy(c.reuse_key) ? 'kept' : 'a new one each time'],
      ['Name in acme', data('span', 'mono', c.name)],
      ['In use', c.enabled === undefined || c.enabled === null || truthy(c.enabled) ? 'yes' : 'switched off']
    ]));
  };
  var edit = function () {
    clear(sec._body);
    var g = el('div', 'formgrid');
    var f = {owner: ownerBox(c.owner || ''), tags: tagsBox(arr(c.tags)), note: textBox(c.note || '', '', ''),
             auto: switchBox(c.auto_renew === undefined || truthy(c.auto_renew)),
             days: textBox(c.renew_days ? String(c.renew_days) : '', String(c.renew_days || 30), ''),
             reuse: switchBox(truthy(c.reuse_key)), name: textBox(c.name, '', ''),
             on: switchBox(c.enabled === undefined || c.enabled === null || truthy(c.enabled))};
    f.owner.id = 'ct-d-owner';
    f.note.id = 'ct-d-note';
    f.days.type = 'number';
    f.days.min = '1';
    f.days.max = '3650';
    noI18n(f.note);
    noI18n(f.name);
    g.appendChild(formField('Owner', f.owner));
    g.appendChild(formField('Tags', f.tags));
    var nf = formField('Note', f.note);
    nf.classList.add('wide');
    g.appendChild(nf);
    if (autoCan(c)) g.appendChild(formField('Renewed by itself', f.auto));
    g.appendChild(formField('Days before the end', f.days, 'Empty: as Settings → Renewal and notices says.'));
    g.appendChild(formField('Keep the key on renewal', f.reuse));
    g.appendChild(formField('Name in acme', f.name));
    g.appendChild(formField('In use', f.on, 'Off: kept, never renewed nor deployed.'));
    sec._body.appendChild(g);
    var foot = el('div', 'tm-dfoot');
    var no = cmdButton('Cancel', 'close', 'small');
    var go = cmdButton('Save the details', 'save', 'small primary');
    go.id = 'ct-d-save';
    no.onclick = show;
    go.onclick = function () {
      var b = {id: c.id};
      var put = function (k, v, was) { if (JSON.stringify(v) !== JSON.stringify(was)) b[k] = v; };
      put('owner', f.owner.value, c.owner || '');
      put('tags', f.tags._get ? f.tags._get() : splitNames(f.tags.value), arr(c.tags));
      put('note', f.note.value, c.note || '');
      if (autoCan(c)) put('auto_renew', !!f.auto._get(), c.auto_renew === undefined || truthy(c.auto_renew));
      put('renew_days', Number(f.days.value || 0) || null, c.renew_days || null);
      put('reuse_key', !!f.reuse._get(), truthy(c.reuse_key));
      put('name', f.name.value.trim(), c.name);
      put('enabled', !!f.on._get(), c.enabled === undefined || c.enabled === null || truthy(c.enabled));
      if (Object.keys(b).length < 2) { show(); return; }
      busy(go, true);
      capi('certs/save', b).then(function (d) {
        toast(said(d, 'saved'), 'good');
        CT.refresh();
        if (back) back();
      }).catch(fail).then(function () { busy(go, false); });
    };
    foot.appendChild(no);
    foot.appendChild(go);
    sec._body.appendChild(foot);
  };
  if (MANAGE) {
    var pen = cmdButton('Change', 'edit', 'small');
    explain(pen, 'Change the details - owner, tags, note, renewal - without a new certificate');
    pen.classList.add('ct-d-edit');
    pen.id = 'ct-d-edit';
    pen.onclick = edit;
    h.appendChild(pen);
  }
  show();
  return sec;
}
/* Saved with new names, key, source, validation or profile: renewed now, or
   left for its next renewal - asked in the page's own window. */
function renewAsk(id, name) {
  modal('Renew now with the new names, or at the next renewal?', function (body) {
    body.appendChild(data('p', '', name)).style.fontWeight = '600';
    body.appendChild(el('p', 'note', 'The changes are saved. The certificate in use stays as it is until it is renewed: now - a new certificate is issued and deployed where this one is - or by itself at its next renewal.'));
  }, [{words: 'At the next renewal', icon: 'clock', go: function () { closeModal(); certPeek(id); }},
      {words: 'Renew now', cls: 'primary', icon: 'refresh', go: function (b) {
        busy(b, true);
        capi('certs/renew', {id: id, force: true}).then(function (x) { closeModal(); jobStarted(x, 'renewing'); },
          function (e) { busy(b, false); fail(e); });
      }}], true);
}
function certBody(body, c, versions, deploys, jobs, back) {
  var head = el('div', 'ct-head');
  var ic = el('div', 'ct-head-ic ' + ((STATE[c.state] || [0, 'dim'])[1]));
  ic.innerHTML = iconMarkup('cert', 26);
  head.appendChild(ic);
  var hw = el('div', 'ct-head-w');
  var t = el('div', 'ct-head-t');
  t.appendChild(data('span', 'ct-head-name', c.cn || c.name));
  t.appendChild(stateTag(c.state));
  if (c.not_after) t.appendChild(daysTag(c.not_after, c.renew_days));
  hw.appendChild(t);
  hw.appendChild(namesChips(arr(c.names).concat(arr(obj(c.profile).san_other))));
  if (arr(c.tags).length || c.owner) {
    var tl = el('div', 'ct-head-tags');
    if (c.owner) tl.appendChild(explain(window.ACME_TEAMS ? ACME_TEAMS.ownerChip(c.owner) : data('span', 'tag info', c.owner), 'The owner: they see it on the enrolment pages - the person, the members of the group, or the account here (local:NAME). Certificate administrators signed in there see every certificate.'));
    tl.appendChild(tagChips(c.tags));
    hw.appendChild(tl);
  }
  head.appendChild(hw);
  body.appendChild(head);
  if (c.not_before && c.not_after) {
    var lw = el('div', 'ct-lifewrap');
    lw.appendChild(el('span', 'muted small', dayOnly(c.not_before)));
    lw.appendChild(lifeBar(c.not_before, c.not_after));
    lw.appendChild(el('span', 'muted small', dayOnly(c.not_after)));
    body.appendChild(lw);
  }
  if (c.last_error && (c.state === 'failed' || c.fails)) {
    var le = el('div', 'ct-errbox');
    var lh = el('div', 'ct-errbox-h');
    lh.appendChild(el('b', '', 'The last renewal failed'));
    if (c.fails) lh.appendChild(el('span', 'muted small', num(c.fails) + ' time(s) in a row'));
    if (c.next_try) lh.appendChild(el('span', 'muted small', 'tried again ' + stamp(c.next_try)));
    le.appendChild(lh);
    le.appendChild(saidBox(c.last_error));
    body.appendChild(le);
  }
  /* What its validation needs: at the top when the renewer did not ask the CA
     because of it (certs_precheck), else a section of its own below. */
  var proves = !!(c.issuer && (c.challenge || Object.keys(obj(c.challenge_map)).length));
  var blocked = /^the CA was not asked/.test(String(c.last_error || ''));
  var valSection = null;
  if (proves && MANAGE) {
    valSection = section('Validation', blocked
      ? 'The CA was not asked: what is missing is marked ✘, with the record to create. Once it is there, acme tries again by itself.'
      : 'What its names need for their validation, and where - checked now, nothing is changed.', true);
    valSection.classList.add('ct-rd-sect');
    var cview = readinessView({
      auto: blocked || c.state === 'new' || c.state === 'failed',
      ask: function (force) { return rdAsk('check:' + c.id + ':' + (c.updated || c.last_try || ''), function () { return capi('certs/check', {id: c.id}).then(function (d) { return d.plan || d; }); }, force); },
      dry: function () { return capi('certs/dry_run', {id: c.id}); }
    });
    valSection._body.appendChild(cview.node);
    if (blocked) body.appendChild(valSection);
  }
  var grid = el('div', 'msects');
  /* the certificate itself */
  var cs = section('The certificate');
  var info = obj(c.info);
  var sha256 = first(info.sha256, c.fingerprint);
  var sha1 = first(info.sha1, c.fingerprint_sha1);
  var uses = arr(info.eku);
  /* the common name apart, the subjectAltNames by their type */
  var sanRows = [];
  var byType = {DNS: [], IP: [], email: [], URI: []};
  if (arr(info.san).length) arr(info.san).forEach(function (x) { if (byType[x[0]]) byType[x[0]].push(x[1]); });
  else {
    arr(c.names).forEach(function (n) { byType[nameKind(n) === 'ip' ? 'IP' : 'DNS'].push(n); });
    arr(obj(c.profile).san_other).forEach(function (n) { var m = /^(email|uri):(.*)$/.exec(n); if (m) byType[m[1] === 'uri' ? 'URI' : 'email'].push(m[2]); });
  }
  [['DNS', 'DNS names'], ['IP', 'IP addresses'], ['email', 'E-mail addresses'], ['URI', 'URIs']].forEach(function (t) {
    if (byType[t[0]].length) sanRows.push([t[1], namesChips(byType[t[0]])]);
  });
  cs._body.appendChild(kvTable([
    ['Common name (CN)', data('span', 'mono', first(info.cn, obj(obj(c.profile).subject).CN, c.cn, arr(c.names)[0], '–'))]
  ].concat(sanRows).concat([
    ['Subject', data('span', 'mono small', first(info.subject_dn, c.subject_dn, 'CN=' + (c.cn || c.names[0] || '')))],
    ['Issued by', data('span', 'mono small', first(info.issuer_dn, c.issuer_dn, '–'))],
    ['Serial', first(info.serial, c.serial) ? copyable(first(info.serial, c.serial), 'the serial was copied') : '–'],
    ['SHA-256', sha256 ? copyable(fpWords(sha256), 'the fingerprint was copied') : '–'],
    sha1 ? ['SHA-1', copyable(fpWords(sha1), 'the fingerprint was copied')] : null,
    ['Key', keyWords(first(info.key_type, c.key_type)) + (info.key_bits ? ' · ' + info.key_bits + ' bits' : '')
      + (c.has_key === false ? ' · not kept here' : '')],
    ['Valid from', c.not_before ? stamp(c.not_before) : '–'],
    ['Valid to', c.not_after ? stamp(c.not_after) : '–'],
    ['Version', c.version ? 'v' + c.version : '–'],
    uses.length ? ['Used for', uses.join(', ')] : null,
    info.must_staple ? ['OCSP must-staple', 'yes'] : null,
    arr(info.ocsp).length ? ['OCSP', data('span', 'mono small', arr(info.ocsp).join(' '))] : null,
    arr(info.crl).length ? ['CRL', data('span', 'mono small', arr(info.crl).join(' '))] : null,
    info.sig_alg ? ['Signed with', data('span', 'mono small', info.sig_alg)] : null,
    info.error ? ['Read', data('span', 'ct-bad', info.error)] : null
  ])));
  grid.appendChild(cs);
  /* a dual certificate: its twin beside it */
  if (c.key_type_alt || arr(c.variants).length > 1) grid.appendChild(twinSection(c));
  /* how it is renewed */
  var rs = section('Where it comes from and how it renews');
  var prof = obj(c.profile);
  var cmap = obj(c.challenge_map);
  rs._body.appendChild(kvTable([
    ['Source', c.issuer || (c.source === 'import' ? 'imported - renewed by importing again' : (c.source === 'csr' ? 'an outside CA, by a CSR' : '–'))],
    ['Validation', c.challenge ? c.challenge + (Object.keys(cmap).length ? ' · ' + Object.keys(cmap).length + ' name(s) otherwise' : '') : '–'],
    ['Renews', autoRenew(c, false, function () { if (window.CT && CT.refresh) CT.refresh(); })],
    ['Key on renewal', truthy(c.reuse_key) ? 'kept' : 'a new one each time'],
    ['Last renewed', c.last_ok ? stamp(c.last_ok) : 'never'],
    ['Next look', c.next_try ? stamp(c.next_try) : '–'],
    prof.days ? ['Validity asked', prof.days + ' days'] : null,
    arr(prof.eku).length ? ['Used for', arr(prof.eku).join(', ')] : null,
    c.ari && obj(c.ari).start ? ['CA suggests', stamp(obj(c.ari).start) + ' – ' + stamp(obj(c.ari).end)] : null,
    ['Note', c.note || '–'],
    ['Made', c.created ? stamp(c.created) + (c.created_by ? ' · ' + c.created_by : '') : '–']
  ]));
  if (Object.keys(cmap).length) {
    var mt = kvTable(Object.keys(cmap).map(function (n) { return [n, cmap[n]]; }));
    mt.classList.add('ct-cmap');
    rs._body.appendChild(el('div', 'muted small', 'Names proved otherwise:'));
    rs._body.appendChild(mt);
  }
  grid.appendChild(rs);
  /* Details first: what is changed at once, without a new certificate. */
  grid.insertBefore(detailsSection(c, back), grid.firstChild);
  /* the chain */
  var chain = rowsOf(c.chain || c.chain_info || c.chain_certs);
  var chainPems = String(c.chain_pem || '').split('-----BEGIN CERTIFICATE-----').length - 1;
  if (chain.length || chainPems) {
    var ch = section('The chain', 'Above the certificate, nearest first.');
    var list = el('ol', 'ct-chain');
    var drawChain = function (items) {
      clear(list);
      items.forEach(function (one) {
        var li = el('li');
        if (typeof one === 'string') { li.appendChild(data('span', 'mono small', one)); list.appendChild(li); return; }
        li.appendChild(data('div', 'mono small', first(one.subject_dn, one.cn, '?')));
        var sub = el('div', 'muted small');
        sub.appendChild(document.createTextNode(tr('until {0}').replace('{0}', dayOnly(one.not_after))));
        if (one.self_signed) sub.appendChild(el('span', 'tag dim', 'root'));
        li.appendChild(sub);
        list.appendChild(li);
      });
    };
    if (chain.length) drawChain(chain);
    else {
      list.appendChild(el('li', 'muted small', chainPems === 1 ? '1 certificate' : chainPems + ' certificates'));
      if (MANAGE) capi('certs/parse', {data_b64: textB64(c.chain_pem), filename: 'chain.pem'}).then(function (x) {
        var got = rowsOf(x.certs);
        if (got.length) drawChain(got);
      }).catch(function () { });
    }
    ch._body.appendChild(list);
    grid.appendChild(ch);
  }
  if (valSection && !blocked) grid.appendChild(valSection);
  /* deployments */
  var ds = section('Deployments', 'Where it is put each time it is renewed.', true);
  ds._body.appendChild(deployTable(deploys, {cert: c, back: back}));
  if (MANAGE) {
    var add = cmdButton('Deploy it on a target', 'add', 'small');
    add.onclick = function () { over(function () { deployEdit({cert: c}); }, back); };
    var dr = el('div', 'btnrow');
    dr.appendChild(add);
    ds._body.appendChild(dr);
  }
  grid.appendChild(ds);
  /* versions */
  var vs = section('Versions', 'Every certificate it has had - renewals, imports. The newest is the one in use.', true);
  vs._body.appendChild(listTable(['Version', 'Serial', 'Valid', 'Why', 'By', ''], versions, function (v) {
    var tr = el('tr');
    var vc = td('num', 'v' + (v.version || '?'));
    if (Number(v.version) === Number(c.version) || (v.variant === 'alt' && Number(v.version) === Number(c.alt_version))) vc.appendChild(el('span', 'tag info ct-cur', 'in use'));
    if (v.variant === 'alt') vc.appendChild(el('span', 'tag dim', 'twin'));
    tr.appendChild(vc);
    tr.appendChild(td('', data('span', 'mono small', v.serial || '–')));
    tr.appendChild(td('small', dayOnly(v.not_before) + ' – ' + dayOnly(v.not_after)));
    var why = td('', v.why || '–');
    if (v.revoked) why.appendChild(el('span', 'tag crit', 'revoked'));
    tr.appendChild(why);
    tr.appendChild(whoWhen(v.by_who, v.created));
    var tools = el('td', 'rowtools');
    if (MANAGE) {
      var ex = iconButton('download', 'Export this version');
      ex.onclick = function () { over(function () { exportDialog(c, versions, v.version); }, back); };
      tools.appendChild(ex);
    }
    tr.appendChild(tools);
    return tr;
  }, 'plain ct-vertable|No version yet: it has not been issued'));
  grid.appendChild(vs);
  /* jobs */
  var js = section('Jobs', 'The latest work on it. Click one for every step.', true);
  js._body.appendChild(jobTable(jobs, {noCert: true}));
  grid.appendChild(js);
  body.appendChild(grid);
}

/* The twin of a dual certificate, side by side with the certificate itself. */
function twinSection(c) {
  var alt = arr(c.variants).filter(function (v) { return v.variant === 'alt'; })[0] || {};
  var sect = section('The twin (dual certificate)', 'The same names with another kind of key, issued and renewed with it - for the clients that cannot use the main one.');
  var ai = obj(alt.info);
  if (alt.state === 'failed' && alt.error) {
    var le = el('div', 'ct-errbox');
    var lh = el('div', 'ct-errbox-h');
    lh.appendChild(el('b', '', 'The twin failed'));
    if (alt.fails) lh.appendChild(el('span', 'muted small', num(alt.fails) + ' time(s) in a row'));
    if (alt.next_try) lh.appendChild(el('span', 'muted small', 'tried again ' + stamp(alt.next_try)));
    le.appendChild(lh);
    le.appendChild(saidBox(alt.error));
    sect._body.appendChild(le);
  }
  if (!alt.issued) {
    sect._body.appendChild(kvTable([
      ['Key', keyWords(c.key_type_alt)],
      ['State', c.dual_source === false ? 'its source gives no twin' : 'not issued yet - the next look issues it']
    ]));
    return sect;
  }
  if (alt.not_before && alt.not_after) {
    var lw = el('div', 'ct-lifewrap');
    lw.appendChild(el('span', 'muted small', dayOnly(alt.not_before)));
    lw.appendChild(lifeBar(alt.not_before, alt.not_after));
    lw.appendChild(el('span', 'muted small', dayOnly(alt.not_after)));
    sect._body.appendChild(lw);
  }
  sect._body.appendChild(kvTable([
    ['Key', keyWords(first(alt.key_type, c.key_type_alt)) + (ai.key_bits ? ' · ' + ai.key_bits + ' bits' : '')
      + (alt.has_key === false ? ' · not kept here' : '')],
    ['Issued by', data('span', 'mono small', first(alt.issuer_dn, '–'))],
    ['Serial', alt.serial ? copyable(alt.serial, 'the serial was copied') : '–'],
    ['SHA-256', alt.fingerprint ? copyable(fpWords(alt.fingerprint), 'the fingerprint was copied') : '–'],
    ai.sha1 ? ['SHA-1', copyable(fpWords(ai.sha1), 'the fingerprint was copied')] : null,
    ['Valid from', alt.not_before ? stamp(alt.not_before) : '–'],
    ['Valid to', alt.not_after ? stamp(alt.not_after) + (alt.days_left !== null && alt.days_left !== undefined ? ' · ' + alt.days_left + ' ' + tr('days') : '') : '–'],
    ['Version', alt.version ? 'v' + alt.version : '–'],
    obj(alt.ari).start ? ['CA suggests', stamp(obj(alt.ari).start) + ' – ' + stamp(obj(alt.ari).end)] : null,
    ai.sig_alg ? ['Signed with', data('span', 'mono small', ai.sig_alg)] : null
  ]));
  return sect;
}

/* ---- export ---------------------------------------------------------------- */
var FORMATS = [
  ['cert-pem', 'Certificate', 'PEM', 'The certificate alone, as text (.crt / .pem).', false, false],
  ['fullchain-pem', 'Full chain', 'PEM', 'The certificate and the chain above it - what nginx and most servers want.', false, false],
  ['chain-pem', 'Chain', 'PEM', 'Only the authorities above it, nearest first.', false, false],
  ['cert-der', 'Certificate', 'DER', 'Binary (.der / .cer), for Windows and Java tools.', false, false],
  ['p7b', 'PKCS#7', 'P7B', 'The certificate with its chain, without the key - for Windows and IIS.', false, false],
  ['key-pem', 'Private key', 'PEM', 'The key alone, PKCS#8.', true, false],
  ['key-rsa', 'Private key', 'PKCS#1', 'The key in the old RSA format, for software that wants BEGIN RSA PRIVATE KEY.', true, false],
  ['combined-pem', 'Key and full chain', 'PEM', 'Key, certificate and chain in one file - HAProxy, some appliances.', true, false],
  ['pfx', 'PFX / P12', 'PKCS#12', 'Key, certificate and chain in one file locked with a password (AES).', true, true],
  ['p12-legacy', 'P12, legacy', 'PKCS#12', 'The same with 3DES/RC2, for old devices and Windows Server 2016 and earlier.', true, true],
  ['jks', 'Java keystore', 'JKS', 'For Tomcat and other Java servers, locked with a password.', true, true]
];
function exportDialog(c, versions, version) {
  var pick = null, pass = null, alias = null, vSel = null, passItem = null, varSel = null;
  var twin = arr(c.variants).filter(function (v) { return v.variant === 'alt' && v.issued; })[0];
  modal('Export ' + c.name, function (body) {
    body.appendChild(el('p', 'note', FULL
      ? 'Choose the shape. A format with the private key is written down in the events, with who took it.'
      : 'Choose the shape. Formats with the private key are for a full administrator only.'));
    var grid = el('div', 'ct-fmts');
    FORMATS.forEach(function (f) {
      var lab = el('label', 'ct-fmt' + (f[4] && !FULL ? ' off' : ''));
      var r = el('input');
      r.type = 'radio';
      r.name = 'ct-fmt';
      r.value = f[0];
      if (f[4] && !FULL) r.disabled = true;
      lab.appendChild(r);
      var w = el('span', 'ct-fmt-w');
      var top = el('span', 'ct-fmt-t');
      top.appendChild(el('b', '', f[1]));
      top.appendChild(data('span', 'tag ' + (f[4] ? 'warn' : 'dim'), f[2]));
      if (f[4]) top.appendChild(el('span', 'ct-keymark', 'with the key'));
      w.appendChild(top);
      w.appendChild(el('span', 'muted small', f[3]));
      lab.appendChild(w);
      r.onchange = function () { pick = f; paint(); };
      grid.appendChild(lab);
    });
    body.appendChild(grid);
    var g = el('div', 'formgrid ct-expopts');
    pass = secretBox('', 'a password for the file', 'mono');
    passItem = formField('Password of the file', pass, 'Needed to open it again. Not kept here.');
    g.appendChild(passItem);
    alias = textBox(c.name, '', 'mono');
    noI18n(alias);
    var aliasItem = formField('Alias in the keystore', alias);
    aliasItem.dataset.only = 'jks';
    g.appendChild(aliasItem);
    if (versions && versions.length > 1) {
      vSel = selectBox(versions.map(function (v) {
        return [String(v.version), 'v' + v.version + ' · ' + dayOnly(v.not_before) + ' – ' + dayOnly(v.not_after)
                + (Number(v.version) === Number(c.version) ? ' (in use)' : '')];
      }), String(version || c.version || versions[0].version));
      g.appendChild(formField('Version', vSel));
    }
    if (twin && !version) {
      /* a dual certificate: which of its two */
      varSel = selectBox([['main', keyWords(c.key_type) + ' · ' + tr('the main one')],
                          ['alt', keyWords(twin.key_type || c.key_type_alt) + ' · ' + tr('the twin')]], 'main');
      g.appendChild(formField('Which certificate', varSel, 'It is dual: the same names with two kinds of key.'));
    }
    body.appendChild(g);
    var paint = function () {
      var needs = !!(pick && pick[5]);
      passItem.hidden = !needs;
      aliasItem.hidden = !(pick && pick[0] === 'jks');
      Array.prototype.forEach.call(grid.querySelectorAll('.ct-fmt'), function (l) {
        l.classList.toggle('on', !!(l.querySelector('input').checked));
      });
    };
    var firstOk = grid.querySelector('input:not([disabled])');
    if (firstOk) { firstOk.checked = true; pick = FORMATS[0]; }
    paint();
  }, [{words: 'Close', close: true}, {words: 'Download', cls: 'primary', icon: 'download', go: function (b) {
    if (!pick) { toast('choose a format', 'bad'); return; }
    if (pick[5] && !pass.value) { toast('a file with the key needs a password', 'bad'); pass.focus(); return; }
    busy(b, true);
    var vWant = vSel ? Number(vSel.value) : (version || undefined);
    var other = varSel && varSel.value === 'alt';
    if (other && vWant && Number(vWant) === Number(c.version)) vWant = undefined;     /* the twin in use */
    capi('certs/export', {id: c.id, format: pick[0], password: pick[5] ? pass.value : undefined,
                          alias: pick[0] === 'jks' ? alias.value : undefined,
                          variant: other ? 'alt' : 'main',
                          version: vWant}).then(function (d) {
      download(d);
      toast((d.filename || 'the file') + ' was downloaded', 'good');
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
  nameInTitle('Export', c.name);
}

/* ---- revoke ---------------------------------------------------------------- */
function revokeDialog(c) {
  var reason = null, also = null;
  modal('Revoke ' + c.name, function (body) {
    body.appendChild(el('p', 'note', 'The CA that issued it is told it must not be trusted any more - this cannot be taken back. Browsers and devices that check will refuse it; deploy a new one first if it is in use.'));
    if (c.key_type_alt) body.appendChild(el('p', 'note', 'A dual certificate: both of its keys are revoked - the ' + (c.key_type || '') + ' one and the ' + c.key_type_alt + ' one. Versions it had before are left as they are.'));
    else body.appendChild(el('p', 'note', 'The current version is revoked; versions it had before are left as they are.'));
    reason = selectBox(REVOKE_REASONS, 'unspecified');
    body.appendChild(formField('Why', reason, 'Said to the CA. "The key got out" is the one that matters most.'));
    also = switchBox(false);
    body.appendChild(formField('Issue a new one at once', also, 'With a new key, deployed where this one is, and renewed by itself again. Otherwise it is not renewed any more - only stopping renewal needs no revocation: the switch in the list does that.'));
  }, [{words: 'No, leave it', close: true}, {words: 'Revoke it', cls: 'danger', icon: 'ban', go: function (b) {
    busy(b, true);
    capi('certs/revoke', {id: c.id, reason: reason.value, renew: !!also._get()}).then(function (d) {
      closeModal();
      jobStarted(d, 'revoking');
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'narrow');
  nameInTitle('Revoke', c.name);
}

/* ==========================================================================
   Add a certificate: source → names → key → validation → renewal → profile
   → deployments → review. Editing one is the same steps, any in any order.
   ========================================================================== */
function sourceIcon(kind) {
  var k = String(kind || '');
  if (/acme|letsencrypt|zerossl/i.test(k)) return 'globe';
  if (/self/i.test(k)) return 'lock';
  if (/internal|own|ca/i.test(k)) return 'ca';
  if (/adcs|ms_|microsoft/i.test(k)) return 'key';
  if (/scep/i.test(k)) return 'router';
  return 'source';
}
/* ==========================================================================
   Before a certificate: what its validation needs, where (readiness)
   POST certs/plan {names, issuer, challenge, challenge_map}, certs/check {id},
   certs/dry_run -> {job_id}, GET certs/dry_run_result?job= (acmelib/certs/
   api_readiness.py). A step: {key, what, where, record, done, said, fix,
   blocking, name}. Its words are the daemon's, translated as they stand; the
   names and the records are data.
   ========================================================================== */
function rdRecordText(rec) {
  if (!rec || !rec.type) return '';
  var v = String(rec.value || '');
  if (rec.type === 'TXT' && v.charAt(0) !== '(') v = '"' + v + '"';
  return String(rec.name || '').replace(/\.$/, '') + '. ' + (rec.ttl ? rec.ttl + ' ' : '') + rec.type + ' ' + v;
}
function rdCopy(words, text) {
  var b = el('button', 'btn small ct-rd-copy', words);
  b.type = 'button';
  copyOnClick(b, text, 'copied');
  return b;
}
function rdRecord(rec) {
  var box = el('div', 'ct-rd-rec');
  var line = data('code', 'mono', rdRecordText(rec));
  box.appendChild(line);
  var tools = el('span', 'ct-rd-tools');
  tools.appendChild(rdCopy('Copy', rdRecordText(rec)));
  tools.appendChild(rdCopy('Name', String(rec.name || '').replace(/\.$/, '')));
  tools.appendChild(rdCopy('Value', String(rec.value || '')));
  box.appendChild(tools);
  return box;
}
function rdStep(st) {
  var row = el('div', 'ct-rd-step ' + (st.done === true ? 'ok' : (st.done === false ? (st.blocking ? 'bad' : 'warn') : 'unk')));
  row.appendChild(okMark(st.done === true ? true : (st.done === false ? false : null)));
  var w = el('div', 'ct-rd-w');
  var top = el('div', 'ct-rd-what');
  top.appendChild(el('b', '', st.what || ''));
  if (st.where) top.appendChild(el('span', 'muted small ct-rd-where', st.where));
  if (st.done === false && !st.blocking) top.appendChild(el('span', 'tag warn small', 'does not block'));
  w.appendChild(top);
  if (st.said) w.appendChild(el('div', 'muted small ct-rd-said', st.said));
  if (st.fix && st.done === false) w.appendChild(el('div', 'ct-rd-fix', st.fix));
  var rec = st.record;
  if (rec && rec.type && st.done !== true && String(rec.value || '').charAt(0) !== '(') w.appendChild(rdRecord(rec));
  else if (rec && rec.type && st.done === true) w.appendChild(data('div', 'mono small muted', rdRecordText(rec)));
  row.appendChild(w);
  return row;
}
function rdSteps(host, steps) {
  var by = {}, order = [];
  arr(steps).forEach(function (st) {
    var k = st.name || '';
    if (!by[k]) { by[k] = []; order.push(k); }
    by[k].push(st);
  });
  order.forEach(function (k) {
    if (order.length > 1 && k) host.appendChild(data('div', 'ct-rd-name mono', k));
    by[k].forEach(function (st) { host.appendChild(rdStep(st)); });
  });
}
function rdGroup(g, o) {
  var guide = obj(g.guide);
  var card = el('div', 'ct-rd-group ' + (guide.ok === true ? 'ok' : (guide.ok === false ? 'bad' : 'unk')));
  card._ok = guide.ok === true ? true : (guide.ok === false ? false : null);
  var head = el('div', 'ct-rd-head');
  head.appendChild(okMark(guide.ok === true ? true : (guide.ok === false ? false : null)));
  head.appendChild(data('b', 'ct-rd-domain', g.domain || '–'));
  head.appendChild(namesChips(arr(g.names), 8));
  var vt = el('span', 'ct-rd-val');
  if (g.validation) {
    vt.appendChild(el('span', 'muted small', 'proved by '));
    vt.appendChild(data('span', 'tag info', g.validation));
  } else vt.appendChild(el('span', 'tag crit', 'no validation'));
  head.appendChild(vt);
  card.appendChild(head);
  var fold = el('div', 'ct-rd-body');
  card.appendChild(fold);
  var sug = arr(g.suggested);
  if (sug.length) {
    var sbox = el('div', 'ct-rd-sugg');
    sbox.appendChild(el('span', 'muted small', guide.ok === false ? 'This would do:' : 'Could also be:'));
    sug.forEach(function (s) {
      var one = el('span', 'ct-rd-sone');
      if (s.validation && o.onUse) {
        var b = el('button', 'btn small' + (guide.ok === false ? ' primary' : ''), '');
        b.type = 'button';
        b.appendChild(el('span', '', 'Use '));
        b.appendChild(data('span', '', s.validation));
        b.onclick = function () { o.onUse(g, s.validation); };
        one.appendChild(b);
      } else one.appendChild(data('b', '', s.validation || plugTitle('challenge', s.kind)));
      one.appendChild(el('span', 'muted small', s.why || ''));
      sbox.appendChild(one);
    });
    fold.appendChild(sbox);
  }
  var body = el('div', 'ct-rd-steps');
  rdSteps(body, guide.steps);
  if (!arr(guide.steps).length) body.appendChild(el('p', 'muted small', 'Nothing to check for these names.'));
  fold.appendChild(body);
  return rdFold(card, head, fold);
}
/* A check asked by itself (a popup opened) is asked once for the same settings:
   opened again within RD_KEEP_MS, what was found is shown; "Check again" asks
   anew (and the daemon keeps its sign-ins and lists of zones for a little while
   too - acmelib/plugins/limits.py). */
var RD_KEEP_MS = 30000;
var RD_RECENT = {};
function rdAsk(key, ask, force) {
  var had = RD_RECENT[key];
  if (!force && had && Date.now() - had.at < RD_KEEP_MS) return had.got;
  var got = Promise.resolve().then(ask);
  RD_RECENT[key] = {at: Date.now(), got: got};
  got.catch(function () { if (RD_RECENT[key] && RD_RECENT[key].got === got) delete RD_RECENT[key]; });
  return got;
}
/* ---- readiness lists (1.0.21): compact where all is well -------------------
   One look says how it stands - "6 certificates · 4 ready · 2 need attention" -
   what needs attention comes first and open, what is ready is one row each
   (its name and a green tick; a click opens it), several of them folded into
   one row "4 ready". The validation's dialog (per certificate), the check and
   the dry run of a certificate and the wizard (per domain) all draw it so. */
function rdFold(card, head, body, open) {
  card.classList.add('ct-rd-fold');
  var chev = el('span', 'ct-rd-chev');
  chev.innerHTML = iconMarkup('unfold', 15);
  head.appendChild(chev);
  head.classList.add('ct-rd-toggle');
  head.setAttribute('role', 'button');
  head.tabIndex = 0;
  var set = function (on) {
    body.hidden = !on;
    card.classList.toggle('open', !!on);
    head.setAttribute('aria-expanded', on ? 'true' : 'false');
  };
  head.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('button, a, input, select, .ct-name.more')) return;
    set(body.hidden);
  });
  head.addEventListener('keydown', function (e) {
    if (e.target !== head || (e.key !== 'Enter' && e.key !== ' ')) return;
    e.preventDefault();
    set(body.hidden);
  });
  set(!!open);
  card._open = set;
  return card;
}
/** "6 certificates · 4 ready · 2 need attention", the counts coloured. noun: [one, many]. */
function rdCounts(cards, noun) {
  var n = cards.length;
  var ready = cards.filter(function (c) { return c._ok === true; }).length;
  var bad = cards.filter(function (c) { return c._ok === false; }).length;
  var unk = n - ready - bad;
  var line = el('div', 'ct-rd-counts');
  line.appendChild(el('b', '', n === 1 ? '1 ' + noun[0] : n + ' ' + noun[1]));
  var part = function (cls, words) {
    line.appendChild(el('span', 'ct-rd-dot', '·'));
    line.appendChild(el('span', 'ct-rd-n ' + cls, words));
  };
  if (ready) part('ok', ready + ' ready');
  if (bad) part('bad', bad === 1 ? '1 needs attention' : bad + ' need attention');
  if (unk) part('unk', unk === 1 ? '1 not known' : unk + ' not known');
  return line;
}
/** The cards of a readiness list put in `host`: the summary, what needs
    attention open and first, what is ready folded (several in a group). */
function rdList(host, cards, noun) {
  if (!cards.length) return;
  host.appendChild(rdCounts(cards, noun));
  var ready = cards.filter(function (c) { return c._ok === true; });
  var rest = cards.filter(function (c) { return c._ok !== true; });
  rest.sort(function (a, b) { return (a._ok === false ? 0 : 1) - (b._ok === false ? 0 : 1); });
  rest.forEach(function (c) { c._open(true); host.appendChild(c); });
  if (!ready.length) return;
  ready.forEach(function (c) { c._open(false); });
  if (ready.length < 4 || !rest.length) { ready.forEach(function (c) { host.appendChild(c); }); return; }
  var grp = el('div', 'ct-rd-group ok ct-rd-ready');
  var head = el('div', 'ct-rd-head');
  head.appendChild(okMark(true));
  head.appendChild(el('b', 'ct-rd-domain', ready.length + ' ready'));
  var who = data('span', 'muted small ct-rd-who', ready.map(function (c) { return c._title || ''; }).filter(Boolean).join(', '));
  head.appendChild(who);
  grp.appendChild(head);
  var body = el('div', 'ct-rd-body ct-rd-inner');
  ready.forEach(function (c) { body.appendChild(c); });
  grp.appendChild(body);
  host.appendChild(rdFold(grp, head, body));
}
/** The plan (or what a dry run found), a card a domain. */
function rdPlan(host, plan, o) {
  clear(host);
  plan = obj(plan);
  var head = obj(plan.head);
  if (arr(head.steps).length) {
    var hb = el('div', 'ct-rd-steps');
    rdSteps(hb, head.steps);
    host.appendChild(hb);
  }
  if (plan.issuer_needs_validation === false) host.appendChild(el('p', 'note', 'This source needs no validation: nothing has to be set up for the names.'));
  var cards = arr(plan.groups).map(function (g) { var c = rdGroup(g, o); c._title = g.domain || ''; return c; });
  if (plan.issuer_needs_validation === false) cards.forEach(function (c) { c._open(false); host.appendChild(c); });
  else rdList(host, cards, ['domain', 'domains']);
  if (plan.complete === false) host.appendChild(saidLine('', 'Not every check finished in time - a DNS server or an API answers slowly. Check again in a moment.'));
}
function rdSummary(plan) {
  var n = arr(obj(plan).blocking).length;
  if (!plan) return saidLine('', '');
  if (!n) return saidLine('good', 'Everything that can be checked from here is in place. A dry run tries it for real, with no CA asked.');
  return saidLine('bad', n === 1 ? '1 thing to set up first - see the ✘ below.' : n + ' things to set up first - see the ✘ below.');
}
/** The whole view: Check again, Dry run, the plan, the dry run's steps live.
    o: {ask() -> Promise(plan), dry() -> Promise({job_id}), onUse(group, validation),
        auto (check at once), onPlan(plan)} */
function readinessView(o) {
  var V = {plan: null, ticket: null};
  var node = el('div', 'ct-rd');
  var bar = el('div', 'btnrow ct-rd-bar');
  var again = cmdButton(o.auto === false ? 'Check' : 'Check again', 'refresh', 'small');
  var dry = cmdButton('Dry run', 'play', 'small');
  dry.title = 'A test record or file put in place, looked for from outside and taken away - no CA is asked';
  bar.appendChild(again);
  if (MANAGE && o.dry) bar.appendChild(dry);
  node.appendChild(bar);
  var sumHost = el('div');
  node.appendChild(sumHost);
  var dryHost = el('div', 'ct-rd-dry');
  node.appendChild(dryHost);
  var planHost = el('div', 'ct-rd-plan');
  node.appendChild(planHost);
  var check = function (force) {
    busy(again, true);
    clear(sumHost);
    sumHost.appendChild(saidLine('', 'Checking DNS, the addresses and the validations…'));
    var t = V.ticket = {};
    return o.ask(force !== false).then(function (plan) {
      if (V.ticket !== t) return plan;
      V.plan = plan;
      clear(sumHost);
      sumHost.appendChild(rdSummary(plan));
      rdPlan(planHost, plan, o);
      if (o.onPlan) o.onPlan(plan);
      return plan;
    }).catch(function (e) {
      if (V.ticket !== t) return;
      clear(sumHost);
      sumHost.appendChild(failedBox(e, 'the check of the validation'));
    }).then(function (x) { busy(again, false); return x; });
  };
  var runDry = function () {
    busy(dry, true);
    clear(dryHost);
    dryHost.appendChild(el('h4', 'ct-formh', 'Dry run'));
    var log = el('div', 'ct-loghost');
    dryHost.appendChild(log);
    log.appendChild(el('p', 'muted small', 'Starting…'));
    var t = V.ticket = {};
    var ticket = modalTicket();
    o.dry().then(function (d) {
      var id = d && d.job_id;
      var poll = function () {
        if (V.ticket !== t || !modalStill(ticket)) return;
        capi('certs/job' + qs({id: id})).then(function (x) {
          if (V.ticket !== t || !modalStill(ticket)) return;
          var j = x.job || x;
          clear(log);
          log.appendChild(jobLog(j.steps, j.ts));
          var box = log.querySelector('.ct-log');
          if (box) box.scrollTop = box.scrollHeight;
          if (jobRunning(j)) { setTimeout(poll, 1000); return; }
          busy(dry, false);
          if (j.said) log.appendChild(saidLine(jobState(j) === 'ok' ? 'good' : 'bad', String(j.said)));
          capi('certs/dry_run_result' + qs({job: id})).then(function (r) {
            if (V.ticket !== t || !r || !r.result) return;
            clear(sumHost);
            sumHost.appendChild(saidLine(r.result.ok ? 'good' : 'bad', r.result.ok
              ? 'The dry run worked: the CA will find what it looks for.'
              : 'The dry run found what is missing - see the ✘ below.'));
            rdPlan(planHost, r.result, o);
          }).catch(function () { });
        }).catch(function () { setTimeout(poll, 2000); });
      };
      poll();
    }).catch(function (e) { clear(log); log.appendChild(failedBox(e, 'the dry run')); busy(dry, false); });
  };
  again.onclick = function () { check(true); };
  dry.onclick = runDry;
  if (o.auto !== false) check(false);
  else planHost.appendChild(el('p', 'muted small', 'Check asks DNS, the addresses and the validations now - nothing is changed.'));
  V.node = node;
  V.check = check;
  return V;
}

/* ---- the subjectAltNames of a certificate, typed -----------------------------
   DNS names and IP addresses are its `names` (the ones proved); e-mail and URI
   ones are kept in profile.san_other as 'email:..' / 'uri:..'; the common name
   is profile.subject.CN (empty: the first name). What a source takes is said by
   POST /api/certs/compat (acmelib/certs/compat.py). */
var SAN_TYPES = [['dns', 'DNS name'], ['ip', 'IP address'], ['email', 'E-mail'], ['uri', 'URI']];
function sanDetect(v) {
  v = String(v || '').trim();
  var m = /^(dns|ip|email|uri):(.*)$/i.exec(v);
  if (m && !(m[1].toLowerCase() === 'uri' && m[2].slice(0, 2) === '//')) return {type: m[1].toLowerCase(), value: m[2].trim()};
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v) || /^(urn|tag|mailto|did|spiffe|ldap|sip):/i.test(v)) return {type: 'uri', value: v};
  if (v.indexOf('@') > 0) return {type: 'email', value: v};
  if (nameKind(v) === 'ip') return {type: 'ip', value: v};
  return {type: 'dns', value: v.toLowerCase().replace(/\.$/, '')};
}
/** Why a value is not a name of that type ('' when it is), as typed. */
function sanCheck(type, v) {
  v = String(v || '').trim();
  if (!v) return '';
  if (type === 'ip') return nameKind(v) === 'ip' ? '' : 'not an IP address';
  if (type === 'dns') {
    var k = nameKind(v.toLowerCase());
    if (k === 'ip') return 'an IP address - choose the type IP address';
    if (k === 'bad' && !/[^\x00-\x7f]/.test(v)) return 'not a DNS name';
    return '';
  }
  if (type === 'email') return /^[A-Za-z0-9!#$%&'*+\/=?^_`{|}~.-]+@[^@\s]+\.[^@\s]+$/.test(v) && !/\.\./.test(v) ? '' : 'not an e-mail address';
  if (type === 'uri') return (/^[a-z][a-z0-9+.-]*:\/\/[^\/?#\s]+/i.test(v) || /^[a-z][a-z0-9+.-]*:[^\s\/][^\s]*$/i.test(v)) && !/\s/.test(v) ? '' : 'not an absolute URI (scheme://host/...)';
  return 'an unknown type';
}
function sansOf(c, prof) {
  var out = arr(c.names).map(function (n) { return {type: nameKind(n) === 'ip' ? 'ip' : 'dns', value: n}; });
  arr(prof.san_other).forEach(function (x) { var d = sanDetect(x); out.push(d); });
  return out;
}

function certWizard(cert, detail) {
  var editing = !!(cert && cert.id);
  var W = {step: 0, seen: {0: true}, sources: [], vals: [], targets: [], deploys: {}};
  var c = cert || {};
  var prof = obj(c.profile);
  var subj = obj(prof.subject);
  W.d = {
    issuer: c.issuer || '', name: c.name || '', names: arr(c.names).join('\n'), key_type: c.key_type || 'ec-256',
    key_type_alt: c.key_type_alt || '',
    challenge: c.challenge || '', challenge_map: obj(c.challenge_map),
    auto_renew: c.id ? (c.auto_renew === undefined || truthy(c.auto_renew)) : true,
    renew_days: c.renew_days || 30, reuse_key: truthy(c.reuse_key),
    days: prof.days || '', eku: arr(prof.eku).length ? arr(prof.eku) : ['serverAuth'],
    must_staple: truthy(prof.must_staple), acme_profile: prof.acme_profile || '', template: prof.template || '',
    subject: {O: subj.O || '', OU: subj.OU || '', C: subj.C || '', ST: subj.ST || '', L: subj.L || '', emailAddress: subj.emailAddress || ''},
    tags: arr(c.tags).join(' '), note: c.note || '', owner: c.owner || '',
    sans: sansOf(c, prof), cn: subj.CN || '', cn_san: true
  };
  if (!W.d.sans.length) W.d.sans = [{type: 'dns', value: ''}];
  W.d.cn_san = !W.d.cn || arr(c.names).indexOf(String(W.d.cn).toLowerCase()) >= 0;
  var src = function () { return W.sources.filter(function (s) { return s.name === W.d.issuer; })[0] || null; };
  var can = function () {
    var s = src();
    var got = issuerCan(s ? s.kind : '');
    var info = W.compat && W.compat.source;
    if (info && info.name === W.d.issuer) {
      got.challenge = !!info.needs_validation;
      got.wildcards = !!info.wildcards;
      got.ip = !!info.ip_names;
      got.sanTypes = arr(info.san_types);
      got.cnFree = !!info.cn_free;
      got.public = !!info.public;
    }
    return got;
  };
  /* The names proved (DNS, IP): the common name first where it is also a SAN. */
  var names = function () {
    var out = [];
    var cnv = String(W.d.cn || '').trim().toLowerCase().replace(/\.$/, '');
    if (cnv && W.d.cn_san && nameKind(cnv) !== 'bad') out.push(cnv);
    W.d.sans.forEach(function (x) {
      if (x.type !== 'dns' && x.type !== 'ip') return;
      var v = String(x.value || '').trim().toLowerCase().replace(/\.$/, '');
      if (v && out.indexOf(v) < 0) out.push(v);
    });
    return out;
  };
  var sanOther = function () {
    var out = [];
    W.d.sans.forEach(function (x) {
      var v = String(x.value || '').trim();
      if ((x.type === 'email' || x.type === 'uri') && v && out.indexOf(x.type + ':' + v) < 0) out.push(x.type + ':' + v);
    });
    return out;
  };
  /* What fits, asked of acme (compat.py) for what is chosen now - once per question. */
  function compatBody() {
    return {names: names(), issuer: W.d.issuer, challenge: W.d.challenge, challenge_map: W.d.challenge_map,
            key_type: W.d.key_type, key_type_alt: W.d.key_type_alt,
            profile: {subject: W.d.cn ? {CN: String(W.d.cn).trim()} : {}, san_other: sanOther(), acme_profile: W.d.acme_profile}};
  }
  function compatFresh() { return W.compatKey === JSON.stringify(compatBody()); }
  function compatNow() {
    var key = JSON.stringify(compatBody());
    if (W.compatKey === key) return Promise.resolve(W.compat);
    if (W.compatAsk && W.compatAsk.key === key) return W.compatAsk.p;
    var p = capi('certs/compat', compatBody()).then(function (d) {
      W.compat = d; W.compatKey = key; return d;
    }, function () { W.compat = null; W.compatKey = key; return null; });
    W.compatAsk = {key: key, p: p};
    return p;
  }
  function compatProblems(step) {
    if (!W.compat || !compatFresh()) return [];
    return arr(W.compat.problems).filter(function (p) { return !step || p.step === step; });
  }
  /* A step that needs the answer: drawn again once it is there. */
  function compatThen(host, st) {
    if (compatFresh()) return true;
    host.appendChild(saidLine('', 'Checking what fits this source…'));
    var tick = modalTicket();
    compatNow().then(function () { if (modalStill(tick) && steps()[W.step] === st) paint(); });
    return false;
  }
  function problemBox(title, list) {
    var box = el('div', 'ct-errbox ct-compat');
    var hh = el('div', 'ct-errbox-h');
    hh.appendChild(el('b', '', title));
    box.appendChild(hh);
    list.forEach(function (p) {
      var line = el('div', 'ct-compat-p');
      line.appendChild(el('span', '', p.what));
      if (p.fix) line.appendChild(el('span', 'muted small ct-compat-fix', p.fix));
      box.appendChild(line);
    });
    return box;
  }
  var STEPS = [
    {key: 'source', title: 'Source', draw: drawSource, check: function () { return W.d.issuer ? '' : 'choose where it comes from'; }},
    {key: 'names', title: 'Names', draw: drawNames, check: checkNames},
    {key: 'key', title: 'Key', draw: drawKey},
    {key: 'validation', title: 'Validation', draw: drawValidation, show: function () { return can().challenge; },
     check: function () { return W.d.challenge || Object.keys(W.d.challenge_map).length === names().length ? '' : 'choose how the names are proved'; }},
    {key: 'renewal', title: 'Renewal', draw: drawRenewal},
    {key: 'profile', title: 'Profile', draw: drawProfile},
    {key: 'deploy', title: 'Deployments', draw: drawDeploy, show: function () { return !editing; }},
    {key: 'review', title: 'Review', draw: drawReview}
  ];
  var steps = function () { return STEPS.filter(function (s) { return !s.show || s.show(); }); };
  var read = null;          /* what the step on screen reads back into W.d */

  function go(to) {
    if (read) read();
    var list = steps();
    to = Math.max(0, Math.min(list.length - 1, to));
    W.step = to;
    W.seen[to] = true;
    paint();
  }
  function paint() {
    var list = steps();
    var st = list[W.step];
    read = null;
    var buttons = [];
    if (W.step > 0) buttons.push({words: 'Back', icon: 'prev', left: true, go: function () { go(W.step - 1); }});
    buttons.push({words: 'Close', close: true});
    if (editing && st.key !== 'review') buttons.push({words: 'Save', icon: 'save', go: function (b) { if (read) read(); finish(b, false); }});
    var unfit = st.key === 'review' ? compatProblems() : [];
    if (unfit.length) {
      var at = list.map(function (x) { return x.key; }).indexOf(unfit[0].step);
      if (at >= 0 && at !== W.step) buttons.push({words: 'Back to ' + tr(list[at].title), cls: 'primary', icon: 'prev', go: function () { go(at); }});
      buttons.push({words: editing ? 'Save' : 'Create', icon: 'save', cls: 'ct-blocked', go: function () { toast(tr('This does not fit yet - it cannot be created so') + ': ' + unfit[0].what, 'bad'); }});
    } else if (st.key === 'review' && !editing && planBlocks()) {
      if (window.ACME_RUNPLAN) buttons.push({words: 'What happens', icon: 'list', go: function () { planOpen(); }});
      var vstep = list.map(function (x) { return x.key; }).indexOf('validation');
      if (vstep >= 0) buttons.push({words: 'Back to the validation', icon: 'prev', go: function () { go(vstep); }});
      buttons.push({words: 'Create anyway (it will wait until this is in place)', cls: 'primary', icon: 'save', go: function (b) { finish(b, false); }});
    } else if (st.key === 'review') {
      if (window.ACME_RUNPLAN) buttons.push({words: 'What happens', icon: 'list',
        says: 'Everything it will do, step by step - the key, the source, how each name is proved, every call, file and command on its targets - from what is set here now; nothing is saved or contacted.',
        go: function () { planOpen(); }});
      if (!editing) buttons.push({words: 'Add only', icon: 'save', go: function (b) { finish(b, false); }});
      buttons.push({words: editing ? 'Save' : 'Add and issue now', cls: 'primary', icon: editing ? 'save' : 'play', go: function (b) { finish(b, !editing); }});
    } else {
      buttons.push({words: 'Next', cls: 'primary', icon: 'next', go: function () {
        if (read) read();
        var bad = st.check ? st.check() : '';
        if (bad) { toast(bad, 'bad'); return; }
        go(W.step + 1);
      }});
    }
    modal(editing ? 'Edit ' + c.name : 'Add a certificate', function (body) {
      var strip = el('ol', 'ct-wsteps');
      list.forEach(function (s, i) {
        var li = el('li', (i === W.step ? 'on' : '') + (i < W.step || W.seen[i] ? ' done' : ''));
        var b = el('button', '');
        b.type = 'button';
        b.appendChild(el('span', 'n', String(i + 1)));
        b.appendChild(el('span', 'w', s.title));
        /* Editing one already issued: which steps are in the certificate itself
           (a change waits for a new one) and which are acme's alone. */
        if (editing && c.not_after && ['source', 'names', 'key', 'profile'].indexOf(s.key) >= 0) {
          var mk = el('span', 'ct-wstep-cert');
          mk.innerHTML = iconMarkup('refresh', 12);
          b.appendChild(mk);
          explain(b, 'In the certificate itself: a change here takes a new certificate (now, or at its next renewal).');
        }
        b.disabled = !(editing || W.seen[i] || i <= W.step);
        b.onclick = function () {
          if (i > W.step && !editing) {
            if (read) read();
            var bad = st.check ? st.check() : '';
            if (bad) { toast(bad, 'bad'); return; }
          }
          go(i);
        };
        li.appendChild(b);
        strip.appendChild(li);
      });
      body.appendChild(strip);
      /* What is in the certificate itself changes with its next renewal - never by saving. */
      if (editing && c.not_after && ['source', 'names', 'key', 'profile'].indexOf(st.key) >= 0)
        body.appendChild(el('p', 'note tm-next-renewal', 'In the certificate itself: what is changed here goes into a new certificate - saving issues nothing; after Save you choose: renew now, or at its next renewal.'));
      else if (editing && c.not_after && st.key !== 'review')
        body.appendChild(el('p', 'note tm-acme-only', 'Only how acme works with it: a change here applies at once, the certificate stays as it is.'));
      var host = el('div', 'ct-wbody');
      body.appendChild(host);
      st.draw(host);
    }, buttons, 'large');
    if (editing) nameInTitle('Edit', c.name);
    explainWhatWasDrawn($('modal-body'));
  }

  /* -- 1. where it comes from -- */
  function drawSource(host) {
    host.appendChild(el('p', 'note', 'Where the certificate comes from. A source is set up once under Sources - an ACME account, an authority, a Windows CA.'));
    if (!W.sources.length) {
      var b = el('div', 'ct-blank');
      b.appendChild(el('p', 'muted', 'No source is set up yet.'));
      if (FULL) {
        var g = cmdButton('Add a source', 'add', 'primary');
        g.onclick = function () { closeModal(); showTab('sources'); setTimeout(function () { modEdit('sources'); }, 50); };
        b.appendChild(g);
      } else b.appendChild(el('p', 'muted small', 'A full administrator adds them under Sources.'));
      host.appendChild(b);
      return;
    }
    var grid = el('div', 'ct-srcs');
    W.sources.forEach(function (s) {
      var p = plugOf('issuer', s.kind);
      var on = s.enabled === undefined || truthy(s.enabled);
      var t = el('button', 'ct-src' + (W.d.issuer === s.name ? ' on' : '') + (on ? '' : ' off'));
      t.type = 'button';
      var ic = el('span', 'ct-src-ic');
      ic.innerHTML = iconMarkup(sourceIcon(s.kind), 22);
      t.appendChild(ic);
      var w = el('span', 'ct-src-w');
      w.appendChild(data('b', '', s.name));
      w.appendChild(el('span', 'muted small', p ? p.title : s.kind));
      var cn = issuerCan(s.kind);
      var chips = el('span', 'ct-src-chips');
      if (cn.challenge) chips.appendChild(el('span', 'tag info', 'proves names'));
      if (cn.wildcards) chips.appendChild(el('span', 'tag dim', 'wildcards'));
      if (cn.ip) chips.appendChild(el('span', 'tag dim', 'IP addresses'));
      if (cn.days) chips.appendChild(el('span', 'tag dim', 'validity chosen'));
      if (!on) chips.appendChild(el('span', 'tag warn', 'off'));
      if (s.is_default) chips.appendChild(el('span', 'tag ok', 'default'));
      w.appendChild(chips);
      t.appendChild(w);
      t.onclick = function () {
        var was = W.d.issuer;
        W.d.issuer = s.name;
        Array.prototype.forEach.call(grid.children, function (x) { x.classList.remove('on'); });
        t.classList.add('on');
        if (was !== s.name) sourceChanged(said);
      };
      t.ondblclick = function () { t.onclick(); go(W.step + 1); };
      grid.appendChild(t);
    });
    host.appendChild(grid);
    var said = el('div', 'ct-srcsaid');
    host.appendChild(said);
  }
  /* Another source: the names, the validation, the key type and the twin
     checked again - what no longer fits is said (the twin and a key type it
     does not sign are changed at once, and said). */
  function sourceChanged(box) {
    var tick = modalTicket();
    clear(box);
    if (!names().length) return;
    box.appendChild(saidLine('', 'Checking what fits this source…'));
    compatNow().then(function (d) {
      if (!modalStill(tick) || !d) { clear(box); return; }
      var changed = [];
      if (d.twin && !d.twin.ok && W.d.key_type_alt) {
        W.d.key_type_alt = '';
        changed.push({what: d.twin.why, fix: 'The twin is left out'});
      }
      var kt = arr(d.key_types).filter(function (k) { return k.key === W.d.key_type; })[0];
      if (kt && !kt.ok) {
        var first = arr(d.key_types).filter(function (k) { return k.ok; })[0];
        changed.push({what: kt.why, fix: first ? 'The key is now ' + keyWords(first.key) : 'Choose another source'});
        if (first) W.d.key_type = first.key;
      }
      return (changed.length ? compatNow() : Promise.resolve(d)).then(function (d2) {
        if (!modalStill(tick)) return;
        clear(box);
        var left = arr((d2 || d).problems);
        if (changed.length) box.appendChild(problemBox('Changed to fit this source', changed));
        if (left.length) box.appendChild(problemBox('With this source, this no longer fits', left));
        else if (!changed.length) box.appendChild(saidLine('good', 'Everything chosen so far fits this source.'));
      });
    });
  }
  /* -- 2. names -- */
  /* Why one SAN row is refused ('' when it is not): as typed, then what acme said
     of it for this source (compat: public names, e-mail or URI where not taken). */
  function rowWhy(x, i) {
    var v = String(x.value || '').trim();
    if (!v) return '';
    var cn = can();
    var bad = sanCheck(x.type, v);
    if (bad) return bad;
    var types = cn.sanTypes || ['dns', 'ip', 'email', 'uri'];
    if (types.indexOf(x.type) < 0) return 'this source puts no names of this type in its certificates';
    var low = x.type === 'dns' || x.type === 'ip' ? v.toLowerCase().replace(/\.$/, '') : x.type + ':' + v;
    var dup = W.d.sans.some(function (y, j) {
      if (j >= i || !String(y.value || '').trim()) return false;
      var w = String(y.value).trim();
      return (y.type === 'dns' || y.type === 'ip' ? w.toLowerCase().replace(/\.$/, '') : y.type + ':' + w) === low;
    });
    if (dup) return 'given twice';
    if (x.type === 'dns' && nameKind(low) === 'wild' && !cn.wildcards) return 'this source gives no wildcards';
    if (x.type === 'ip' && !cn.ip) return 'this source takes no IP addresses';
    if (W.compat && compatFresh()) {
      var said = x.type === 'dns' || x.type === 'ip' ? obj(W.compat.names)[low] : obj(W.compat.san_other)[low];
      if (said) return said;
    }
    return '';
  }
  function cnWhy() {
    var v = String(W.d.cn || '').trim();
    if (!v) return '';
    if (v.length > 64) return 'the common name is 64 characters at most';
    var cn = can();
    if (cn.cnFree === false && !W.d.cn_san) return 'this source needs the common name to be one of the names';
    if (W.compat && compatFresh() && W.compat.cn && W.compat.cn.why) return W.compat.cn.why;
    return '';
  }
  function checkNames() {
    var list = names();
    if (!list.length) return 'it needs at least one name';
    var bad = [];
    W.d.sans.forEach(function (x, i) { var w = rowWhy(x, i); if (w) bad.push(String(x.value).trim() + ': ' + tr(w)); });
    var cw = cnWhy();
    if (cw) bad.push(tr('Common name (CN)') + ': ' + tr(cw));
    if (bad.length) return tr('not possible here') + ': ' + bad.join('; ');
    return '';
  }
  function drawNames(host) {
    var cn = can();
    host.appendChild(el('p', 'note', 'Every name the certificate is for (its subjectAltNames), each of its type, and its common name. '
      + (cn.wildcards ? '*.example.com covers one level of names under it. ' : 'This source issues no wildcards. ')
      + (cn.ip ? 'IP addresses can be in it too.' : 'This source takes no IP addresses.')));
    var g = el('div', 'formgrid');
    /* the common name */
    var cnBox = textBox(W.d.cn, '', 'mono');
    noI18n(cnBox);
    var cnWrap = el('div', 'ct-cn');
    cnWrap.appendChild(cnBox);
    var cnSw = switchBox(W.d.cn_san);
    var cnSwL = el('label', 'ct-cn-san');
    cnSwL.appendChild(cnSw);
    cnSwL.appendChild(el('span', '', 'the CN is also a SAN'));
    cnWrap.appendChild(cnSwL);
    var cnSays = el('div', 'ct-rowwhy');
    cnWrap.appendChild(cnSays);
    var cf = formField('Common name (CN)', cnWrap, cn.cnFree === false
      ? 'A public CA puts in the common name only one of the names (CA/B Forum, 64 characters at most) - so the CN is also a SAN here. Empty: the first name.'
      : 'Empty: the first name. A source of your own may name it otherwise than every SAN (a device, a service) - switch "the CN is also a SAN" off for that.');
    cf.classList.add('wide');
    g.appendChild(cf);
    /* the SANs, a row each */
    var rows = el('div', 'ct-sans');
    var sf = formField('Names (subjectAltName)', rows);
    sf.classList.add('wide');
    g.appendChild(sf);
    var tools = el('div', 'ct-san-tools');
    var addB = cmdButton('Add a name', 'add', '');
    var pasteB = cmdButton('Paste many…', 'copy', '');
    tools.appendChild(addB);
    tools.appendChild(pasteB);
    rows.parentNode.appendChild(tools);
    var paste = el('div', 'ct-san-paste');
    paste.hidden = true;
    var pta = areaBox('', 'www.example.com\n192.0.2.10\nit@example.com\nhttps://example.com/id', 5, 'mono');
    noI18n(pta);
    paste.appendChild(pta);
    paste.appendChild(el('p', 'muted small', 'One a line: an address is an IP address, with @ an e-mail, with :// a URI, anything else a DNS name.'));
    var pasteGo = cmdButton('Add these', 'add', 'primary');
    paste.appendChild(pasteGo);
    rows.parentNode.appendChild(paste);
    var chips = el('div', 'ct-namecheck wide');
    g.appendChild(chips);
    var name = textBox(W.d.name, tr('the first name'), '');
    noI18n(name);
    var autoName = !W.d.name || W.d.name === certName(names()[0] || '');
    guardName(name, false);
    g.appendChild(formField('Name in acme', name, 'What it is called here. The first name, unless you say otherwise.'));
    var tags = tagsBox(splitNames(W.d.tags));
    g.appendChild(formField('Tags', tags, 'Picked from the tags of Settings → Owners and teams.'));
    var owner = ownerBox(W.d.owner);
    owner.id = 'ct-w-owner';
    g.appendChild(formField('Owner', owner, 'The team or person it belongs to (Settings → Owners and teams): its members see it on the portal, its mail is told when it fails or runs out.'));
    var note = textBox(W.d.note, '', '');
    g.appendChild(formField('Note', note));
    host.appendChild(g);
    var whys = [];
    var typePairs = function () {
      var types = can().sanTypes || ['dns', 'ip', 'email', 'uri'];
      return SAN_TYPES.map(function (t) {
        var off = types.indexOf(t[0]) < 0 || (t[0] === 'ip' && !can().ip);
        return [t[0], t[1] + (off ? ' - ' + tr('not by this source') : ''), off];
      });
    };
    var drawRows = function () {
      clear(rows);
      whys = [];
      W.d.sans.forEach(function (x, i) {
        var row = el('div', 'ct-san');
        var sel = selectBox(typePairs().map(function (t) { return [t[0], t[1]]; }), x.type);
        typePairs().forEach(function (t, j) { sel.options[j].disabled = t[2] && t[0] !== x.type; });
        sel.className = 'ct-san-type';
        var val = textBox(x.value, {dns: 'www.example.com', ip: '192.0.2.10', email: 'it@example.com', uri: 'https://example.com/id'}[x.type] || '', 'mono ct-san-val');
        noI18n(val);
        var rm = el('button', 'btn small ct-san-rm', '×');
        rm.type = 'button';
        rm.title = tr('Take this name out');
        var why = el('div', 'ct-rowwhy');
        whys.push(why);
        sel.onchange = function () { x.type = sel.value; val.placeholder = {dns: 'www.example.com', ip: '192.0.2.10', email: 'it@example.com', uri: 'https://example.com/id'}[x.type] || ''; changed(); };
        val.addEventListener('input', function () {
          var d = sanDetect(val.value);
          /* typed into a DNS row, an address or an e-mail takes its own type */
          if (x.type === 'dns' && d.type !== 'dns' && can().sanTypes && can().sanTypes.indexOf(d.type) >= 0) { x.type = d.type; sel.value = d.type; }
          x.value = val.value;
          changed();
        });
        rm.onclick = function () {
          W.d.sans.splice(i, 1);
          if (!W.d.sans.length) W.d.sans.push({type: 'dns', value: ''});
          drawRows();
          changed();
        };
        row.appendChild(sel);
        row.appendChild(val);
        row.appendChild(rm);
        row.appendChild(why);
        rows.appendChild(row);
      });
    };
    var paintWhys = function () {
      W.d.sans.forEach(function (x, i) {
        var w = rowWhy(x, i);
        var wild = x.type === 'dns' && nameKind(String(x.value || '').trim().toLowerCase()) === 'wild';
        if (!whys[i]) return;
        whys[i].textContent = w ? tr(w) : (wild ? tr('a wildcard covers one level of names under it: x.example.com, not a.b.example.com') : '');
        whys[i].className = 'ct-rowwhy' + (w ? ' bad' : (wild ? ' hint' : ''));
        if (whys[i].parentNode) whys[i].parentNode.classList.toggle('refused', !!w);
      });
      var cw = cnWhy();
      cnSays.textContent = cw ? tr(cw) : '';
      cnSays.className = 'ct-rowwhy' + (cw ? ' bad' : '');
      cnBox.placeholder = W.d.sans.filter(function (x) { return x.type === 'dns' && String(x.value || '').trim(); }).map(function (x) { return x.value.trim(); })[0] || 'www.example.com';
      /* the chips: the result as it goes into the certificate */
      clear(chips);
      var list = names();
      var cnv = String(W.d.cn || '').trim() || list[0] || '';
      if (cnv) {
        var cc = el('span', 'ct-name cn');
        cc.appendChild(el('i', '', 'CN'));
        cc.appendChild(data('span', '', cnv));
        chips.appendChild(cc);
      }
      list.concat(sanOther()).forEach(function (n) {
        var k = /^(email|uri):/.test(n) ? n.split(':')[0] : nameKind(n);
        var chip = el('span', 'ct-name ' + k);
        chip.appendChild(data('span', '', n.replace(/^(email|uri):/, '')));
        var w = {wild: 'wildcard', ip: 'IP address', email: 'e-mail', uri: 'URI'}[k];
        if (w) chip.appendChild(el('i', '', w));
        chips.appendChild(chip);
      });
      var all = list.length + sanOther().length;
      if (all) chips.appendChild(el('span', 'muted small', all === 1 ? '1 name' : all + ' names'));
      if (autoName) { name.value = list[0] ? certName(list[0]) : (cnv ? certName(cnv) : ''); if (name._nameCheck) name._nameCheck(); }
    };
    var soon = null;
    var tick = modalTicket();
    var changed = function () {
      paintWhys();
      clearTimeout(soon);
      soon = setTimeout(function () {
        if (!modalStill(tick)) return;
        compatNow().then(function () { if (modalStill(tick)) paintWhys(); });
      }, 450);
    };
    var forced = function () {
      var c2 = can();
      if (c2.cnFree === false) {
        W.d.cn_san = true;
        cnSw._input.checked = true;
        cnSw._input.disabled = true;
        explain(cnSwL, 'A public CA: the common name is one of the names (CA/B Forum).');
      } else cnSw._input.disabled = false;
    };
    cnBox.addEventListener('input', function () { W.d.cn = cnBox.value; changed(); });
    cnSw._input.onchange = function () { W.d.cn_san = cnSw._input.checked; changed(); };
    addB.onclick = function () { W.d.sans.push({type: 'dns', value: ''}); drawRows(); changed(); var all = rows.querySelectorAll('.ct-san-val'); if (all.length) all[all.length - 1].focus(); };
    pasteB.onclick = function () { paste.hidden = !paste.hidden; if (!paste.hidden) pta.focus(); };
    pasteGo.onclick = function () {
      var have = {};
      W.d.sans = W.d.sans.filter(function (x) { return String(x.value || '').trim(); });
      W.d.sans.forEach(function (x) { have[x.type + ':' + String(x.value).trim().toLowerCase()] = 1; });
      String(pta.value || '').split(/[\r\n,;]+/).forEach(function (line) {
        line = line.trim();
        if (!line) return;
        var d = sanDetect(line);
        var k = d.type + ':' + d.value.toLowerCase();
        if (have[k]) return;
        have[k] = 1;
        W.d.sans.push(d);
      });
      if (!W.d.sans.length) W.d.sans.push({type: 'dns', value: ''});
      pta.value = '';
      paste.hidden = true;
      drawRows();
      changed();
    };
    name.addEventListener('input', function () { autoName = false; });
    drawRows();
    forced();
    paintWhys();
    compatNow().then(function () { if (modalStill(tick)) { forced(); drawRows(); paintWhys(); } });
    read = function () {
      W.d.sans = W.d.sans.filter(function (x, i) { return String(x.value || '').trim() || (i === 0 && W.d.sans.length === 1); });
      W.d.names = names().join('\n');
      W.d.name = name.value.trim() || (names()[0] ? certName(names()[0]) : '');
      W.d.tags = tags.value; W.d.owner = owner.value; W.d.note = note.value;
    };
  }
  /* -- 3. key -- */
  function drawKey(host) {
    host.appendChild(el('p', 'note', 'The key is made here, on this server, and never leaves it unless a full administrator exports it.'));
    var grid = el('div', 'ct-keys');
    var tiles = {};
    KEY_TYPES.forEach(function (k) {
      var t = el('button', 'ct-keyt' + (W.d.key_type === k[0] ? ' on' : ''));
      t.type = 'button';
      t.dataset.key = k[0];
      t.appendChild(data('b', '', k[1]));
      if (k[0] === 'ec-256') t.appendChild(el('span', 'tag ok', 'recommended'));
      t.appendChild(el('span', 'muted small', k[2]));
      var why = el('span', 'ct-keywhy');
      t.appendChild(why);
      tiles[k[0]] = {node: t, why: why};
      t.onclick = function () {
        if (t.disabled) return;
        W.d.key_type = k[0];
        Array.prototype.forEach.call(grid.children, function (x) { x.classList.remove('on'); });
        t.classList.add('on');
      };
      grid.appendChild(t);
    });
    host.appendChild(grid);
    /* The key types the source does not sign: greyed, with the reason. */
    var ktick = modalTicket();
    compatNow().then(function (d) {
      if (!d || !modalStill(ktick)) return;
      arr(d.key_types).forEach(function (k) {
        var t = tiles[k.key];
        if (!t) return;
        t.node.disabled = !k.ok;
        t.node.classList.toggle('off', !k.ok);
        t.why.textContent = k.ok ? '' : k.why;
      });
    });
    if (can().makesKey) host.appendChild(el('p', 'muted small', 'This source makes the key itself; the type is what is asked of it.'));
    drawTwin(host, grid);
  }
  /* A dual certificate: a twin of the same names with the other kind of key -
     offered only where the source gives one (its "dual"). */
  function twinPairs() {
    var ec = /^ec/.test(W.d.key_type || 'ec-256');
    var out = [['', 'No - one certificate']];
    KEY_TYPES.forEach(function (k) {
      if (k[0] === 'ed25519' || /^ec/.test(k[0]) === ec) return;
      out.push([k[0], 'Yes - and one with ' + k[1]]);
    });
    return out;
  }
  function drawTwin(host, grid) {
    var s = src();
    var box = el('div', 'ct-twin');
    host.appendChild(box);
    var draw = function () {
      box.textContent = '';
      var tw = W.compat && W.compat.source && W.compat.source.name === W.d.issuer && W.compat.twin;
      if (!s || (tw ? !tw.ok : !s.dual)) {
        if (W.d.key_type_alt) W.d.key_type_alt = '';
        if (s) box.appendChild(el('p', 'muted small', 'This source gives one certificate of the names (a twin with another kind of key is not offered by it).'));
        return;
      }
      var pairs = twinPairs();
      if (!pairs.some(function (p) { return p[0] === W.d.key_type_alt; })) W.d.key_type_alt = '';
      var sel = selectBox(pairs, W.d.key_type_alt);
      sel.onchange = function () { W.d.key_type_alt = sel.value; };
      box.appendChild(formField('Also a twin', sel, 'A dual certificate: the same names twice, ECDSA and RSA, renewed together. Some clients cannot use ECDSA (old Windows and Java, some appliances, payment terminals) - the server gives each client the one it takes; a target that holds only one certificate gets the one its deployment says.'));
    };
    draw();
    grid.addEventListener('click', function () { setTimeout(draw, 0); });
  }
  /* -- 4. validation -- */
  function drawValidation(host) {
    var cn = can();
    host.appendChild(el('p', 'note', 'How the CA is shown these names are yours. One way for all of them, and another for any name that needs it - a wildcard can only be proved by DNS-01.'));
    if (!W.vals.length) {
      var b = el('div', 'ct-blank');
      b.appendChild(el('p', 'muted', 'No way of validation is set up yet.'));
      if (FULL) {
        var g = cmdButton('Add a way of validation', 'add', 'primary');
        g.onclick = function () { closeModal(); showTab('validation'); setTimeout(function () { modEdit('validation'); }, 50); };
        b.appendChild(g);
      }
      host.appendChild(b);
      return;
    }
    /* What fits: each validation, for this source and each name (compat) - the
       others greyed, with the reason (a wildcard: DNS ones; an IP address: HTTP ones;
       a commercial CA's DCV: only those that can put its record or file in place). */
    if (!compatThen(host, steps()[W.step])) return;
    var fit = {};
    arr(W.compat && W.compat.validations).forEach(function (v) { fit[v.name] = v; });
    var known = !!(W.compat && W.compat.validations && W.compat.validations.length);
    var list = names();
    var fitsName = function (v, n) { var f = fit[v]; return !known || !f ? '' : (obj(f.names)[n] || ''); };
    var fitsNone = function (v) {
      var f = fit[v];
      if (!known || !f) return '';
      if (!list.length) return f.ok ? '' : f.why;
      var bad = list.filter(function (n) { return obj(f.names)[n]; });
      return bad.length === list.length ? (obj(f.names)[bad[0]] || f.why) : '';
    };
    var label = function (v) {
      return v.name + ' · ' + plugTitle('challenge', v.kind) + ' (' + challengeTypes(v.kind).join(', ') + ')' + (v.is_default ? ' · ' + tr('default') : '');
    };
    var pairs = W.vals.map(function (v) { return [v.name, label(v)]; });
    var good = W.vals.filter(function (v) { return !fitsNone(v.name); });
    if ((!W.d.challenge || fitsNone(W.d.challenge)) && W.vals.length && !editing) {
      var dv = defaultOf(W.vals);
      W.d.challenge = (dv && !fitsNone(dv.name) ? dv : (good[0] || dv || W.vals[0])).name;
    }
    var mark = function (sel, perName) {
      Array.prototype.forEach.call(sel.options, function (o) {
        if (!o.value) return;
        var why = perName ? fitsName(o.value, perName) : fitsNone(o.value);
        var base = label(W.vals.filter(function (v) { return v.name === o.value; })[0] || {name: o.value});
        o.disabled = !!why && o.value !== sel.value;
        o.textContent = base + (why ? ' - ' + tr('does not fit') + ': ' + why : '');
        o.className = why ? 'ct-unfit' : '';
        o.title = why;
      });
    };
    var def = selectBox(pairs, W.d.challenge);
    noI18n(def);
    def.className = 'ct-valsel';
    mark(def, null);
    host.appendChild(formField('For every name', def, cn.types.length ? 'This source can use: ' + cn.types.join(', ') + '.' : ''));
    /* the ones that do not fit, said in words beside the choice */
    var unfit = W.vals.filter(function (v) { return fitsNone(v.name); });
    if (unfit.length) {
      var ub = el('div', 'ct-unfitlist');
      ub.appendChild(el('div', 'muted small', 'Not offered for this source and these names:'));
      unfit.forEach(function (v) {
        var line = el('div', 'ct-unfit-line');
        line.appendChild(data('b', '', v.name));
        line.appendChild(el('span', 'muted small', fitsNone(v.name)));
        ub.appendChild(line);
      });
      host.appendChild(ub);
    }
    var tb = el('div');
    host.appendChild(el('h4', 'ct-formh', 'Name by name'));
    host.appendChild(tb);
    var sels = {};
    var drawMap = function () {
      clear(tb);
      tb.appendChild(listTable(['Name', 'Proved by', ''], list, function (n) {
        var tr = el('tr');
        tr.appendChild(td('', data('span', 'mono', n)));
        var s = selectBox([['', (typeof i18nText === 'function' && i18nText('as for every name')) || 'as for every name']].concat(pairs), W.d.challenge_map[n] || '');   /* tr() is the row here */
        noI18n(s);
        s.className = 'ct-valsel';
        mark(s, n);
        sels[n] = s;
        var warn = el('span', 'ct-warnmark');
        var paintWarn = function () {
          var use = s.value || def.value;
          var why = fitsName(use, n);
          if (!known) {
            var v = W.vals.filter(function (x) { return x.name === use; })[0];
            var types = v ? challengeTypes(v.kind) : [];
            why = nameKind(n) === 'wild' && types.length && types.indexOf('dns-01') < 0 ? 'a wildcard needs DNS-01' : '';
          }
          warn.textContent = why;
          tr.classList.toggle('ct-hot', !!why);
          mark(s, n);
        };
        s.onchange = paintWarn;
        def.addEventListener('change', paintWarn);
        paintWarn();
        tr.appendChild(td('', s));
        tr.appendChild(td('', warn));
        return tr;
      }, 'plain ct-cmaptable'));
    };
    def.addEventListener('change', function () { mark(def, null); });
    drawMap();
    var curMap = function () {
      var m = {};
      Object.keys(sels).forEach(function (n) { if (sels[n].value) m[n] = sels[n].value; });
      return m;
    };
    read = function () {
      W.d.challenge = def.value;
      W.d.challenge_map = curMap();
    };
    /* What each domain needs, checked now; a suggestion taken writes the
       group's names into the map (or clears them when it is the one for all). */
    host.appendChild(el('h4', 'ct-formh', 'What each domain needs'));
    host.appendChild(el('p', 'muted small', 'The names grouped by their DNS zone, each with what its validation needs and where - checked now, nothing is changed. A record to create is shown exactly, with Copy.'));
    var view = readinessView({
      ask: function () { read(); return planNow(); },
      dry: function () { read(); return capi('certs/dry_run', planBody()); },
      onUse: function (g, v) {
        arr(g.names).forEach(function (n) {
          if (!sels[n]) return;
          sels[n].value = v === def.value ? '' : v;
          if (sels[n].onchange) sels[n].onchange();
        });
        read();
        view.check();
      }
    });
    host.appendChild(view.node);
    var soon = null;
    var later = function () { clearTimeout(soon); soon = setTimeout(function () { if (modalStill(tick)) view.check(); }, 700); };
    var tick = modalTicket();
    def.addEventListener('change', later);
    Object.keys(sels).forEach(function (n) { sels[n].addEventListener('change', later); });
  }
  /* The plan of what is in W.d now, asked once for the same question. */
  function planBody() {
    return {names: names(), issuer: W.d.issuer, challenge: W.d.challenge, challenge_map: W.d.challenge_map};
  }
  function planNow() {
    var key = JSON.stringify(planBody());
    if (W.plan && W.planKey === key) return Promise.resolve(W.plan);
    return capi('certs/plan', planBody()).then(function (d) {
      W.plan = d.plan || d;
      W.planKey = key;
      return W.plan;
    });
  }
  function planBlocks() {
    return !!(can().challenge && W.plan && W.planKey === JSON.stringify(planBody()) && arr(W.plan.blocking).length);
  }
  /* -- 5. renewal -- */
  function drawRenewal(host) {
    host.appendChild(el('p', 'note', 'acme looks every few minutes for certificates due. An ACME CA that suggests its own window (ARI) is listened to as well.'));
    var g = el('div', 'formgrid');
    var auto = switchBox(W.d.auto_renew);
    g.appendChild(formField('Renew by itself', auto, 'Off: only when Renew now is pressed.'));
    var days = numberBox(W.d.renew_days, '30', 1, 3650);
    g.appendChild(formField('Days before the end', days, 'Renewed this many days before it runs out. A third of its life is a good rule: 30 for 90 days.'));
    var reuse = switchBox(W.d.reuse_key);
    g.appendChild(formField('Keep the key', reuse, 'On: the same key in every renewal - for pinning, or a device that takes only the certificate. Off (better): a new key each time.'));
    host.appendChild(g);
    read = function () { W.d.auto_renew = !!auto._get(); W.d.renew_days = Number(days.value || 30); W.d.reuse_key = !!reuse._get(); };
  }
  /* -- 6. profile -- */
  function drawProfile(host) {
    var cn = can();
    var s = src();
    var kind = s ? String(s.kind) : '';
    host.appendChild(el('p', 'note', 'What is in the certificate beside its names. A public CA decides most of this itself; an authority of your own takes what is asked.'));
    var g = el('div', 'formgrid');
    var days = null, staple = null, prof = null, tmpl = null;
    if (cn.days) {
      days = numberBox(W.d.days, cn.challenge ? '' : '397', 1, 36500);
      g.appendChild(formField('Valid for (days)', days, 'Empty: what the source gives. Browsers take at most 398 days for a public name.'));
    }
    if (/acme/i.test(kind)) {
      prof = textBox(W.d.acme_profile, 'classic, tlsserver, shortlived', 'mono');
      noI18n(prof);
      g.appendChild(formField('ACME profile', prof, 'A profile the CA offers (Let’s Encrypt: classic, tlsserver, shortlived). Empty: its default.'));
      staple = switchBox(W.d.must_staple);
      g.appendChild(formField('OCSP must-staple', staple, 'Only where the server staples OCSP answers.'));
    }
    if (/adcs|ms_/i.test(kind)) {
      tmpl = textBox(W.d.template, 'WebServer', 'mono');
      noI18n(tmpl);
      g.appendChild(formField('Certificate template', tmpl, 'The template on the Windows CA. Empty: the source’s own.'));
    }
    host.appendChild(g);
    var ek = el('div', 'ct-ekus');
    var boxes = {};
    EKUS.forEach(function (e) {
      var lab = el('label', 'set-check');
      var cb = el('input');
      cb.type = 'checkbox';
      cb.checked = W.d.eku.indexOf(e[0]) >= 0;
      boxes[e[0]] = cb;
      lab.appendChild(cb);
      lab.appendChild(el('span', '', e[1]));
      lab.appendChild(data('span', 'mono muted small', ' ' + e[0]));
      ek.appendChild(lab);
    });
    var ef = formField('Used for', ek, cn.challenge ? 'A public CA puts in what it puts in; this is what is asked.' : '');
    host.appendChild(ef);
    host.appendChild(el('h4', 'ct-formh', 'Subject'));
    var sg = el('div', 'formgrid ct-subj');
    var sb = {};
    [['O', 'Organisation', 'Example s.r.o.'], ['OU', 'Unit', 'IT'], ['C', 'Country', 'CZ'], ['ST', 'Region', 'Praha'],
     ['L', 'City', 'Praha'], ['emailAddress', 'E-mail', 'it@example.cz']].forEach(function (f) {
      var b = textBox(W.d.subject[f[0]], f[2], '');
      noI18n(b);
      sb[f[0]] = b;
      sg.appendChild(formField(f[1], b));
    });
    host.appendChild(sg);
    if (cn.challenge) host.appendChild(el('p', 'muted small', 'A public ACME CA puts only the names in; the subject is for an authority of your own, AD CS or SCEP.'));
    read = function () {
      if (days) W.d.days = days.value;
      if (prof) W.d.acme_profile = prof.value.trim();
      if (staple) W.d.must_staple = !!staple._get();
      if (tmpl) W.d.template = tmpl.value.trim();
      W.d.eku = Object.keys(boxes).filter(function (k) { return boxes[k].checked; });
      Object.keys(sb).forEach(function (k) { W.d.subject[k] = sb[k].value.trim(); });
    };
  }
  /* -- 7. deployments -- */
  function drawDeploy(host) {
    host.appendChild(el('p', 'note', 'Where it goes once it is issued, and again after each renewal. More can be added later from the certificate or the target.'));
    if (!W.targets.length) {
      host.appendChild(el('p', 'muted', FULL ? 'No target yet - add them under Targets; this step can be skipped.' : 'No target yet - this step can be skipped.'));
      return;
    }
    var list = el('div', 'ct-deps');
    var forms = {};
    W.targets.forEach(function (t) {
      var p = plugOf('target', t.kind);
      var row = el('div', 'ct-dep' + (W.deploys[t.name] ? ' on' : ''));
      var top = el('label', 'ct-dep-top');
      var cb = el('input');
      cb.type = 'checkbox';
      cb.checked = !!W.deploys[t.name];
      top.appendChild(cb);
      var ic = el('span', 'ct-kind-ic v-' + String((p && p.vendor) || 'other').toLowerCase().replace(/[^a-z0-9]+/g, '-'));
      ic.textContent = String((p && p.title) || t.kind).replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase();
      noI18n(ic);
      top.appendChild(ic);
      var w = el('span', 'ct-dep-w');
      var wn = el('span', '');
      wn.appendChild(data('b', '', t.name));
      if (t.is_default) { wn.appendChild(document.createTextNode(' ')); wn.appendChild(el('span', 'tag ok small', 'default')); }
      w.appendChild(wn);
      w.appendChild(data('span', 'muted small', (p ? p.title : t.kind) + (t.config && (t.config.host || t.config.address) ? ' · ' + (t.config.host || t.config.address) : '')));
      top.appendChild(w);
      row.appendChild(top);
      var fh = el('div', 'ct-dep-form');
      row.appendChild(fh);
      var draw = function () {
        clear(fh);
        forms[t.name] = null;
        if (!cb.checked) return;
        if (!p) { fh.appendChild(el('p', 'ct-bad', 'Its module is not installed.')); return; }
        var dfs = arr(p.deploy_fields).filter(function (x) { return !x.dual_only || W.d.key_type_alt; });
        var f = p.files_ui && window.ACME_DEPLOY_UI
          ? window.ACME_DEPLOY_UI.form(p, dfs, W.deploys[t.name] || {}, {}, {target: t.name, targetRow: t, names: names(),
              key_type: W.d.key_type, key_type_alt: W.d.key_type_alt, dual: !!W.d.key_type_alt, sudo: truthy((t.config || {}).sudo)})
          : fieldForm(dfs, W.deploys[t.name] || {}, {}, {noneWords: 'Nothing to set for this target.'});
        forms[t.name] = f;
        fh.appendChild(f.node);
      };
      cb.onchange = function () {
        if (cb.checked && !W.deploys[t.name]) W.deploys[t.name] = {};
        if (!cb.checked) delete W.deploys[t.name];
        row.classList.toggle('on', cb.checked);
        draw();
      };
      draw();
      list.appendChild(row);
    });
    host.appendChild(list);
    read = function () {
      Object.keys(forms).forEach(function (k) { if (forms[k] && W.deploys[k]) W.deploys[k] = forms[k].read(); });
    };
    STEPS.filter(function (s) { return s.key === 'deploy'; })[0].check = function () {
      var bad = '';
      Object.keys(forms).forEach(function (k) { if (!bad && forms[k]) bad = forms[k].check(); });
      return bad;
    };
  }
  /* -- 8. review -- */
  function drawReview(host) {
    var s = src();
    var list = names();
    var pairs = [
      ['Source', s ? s.name + ' · ' + plugTitle('issuer', s.kind) : W.d.issuer],
      ['Name in acme', W.d.name || (list[0] ? certName(list[0]) : '–')],
      ['Common name (CN)', data('span', 'mono', String(W.d.cn || '').trim() || list[0] || '–')],
      ['Names', namesChips(list.concat(sanOther()))],
      ['Key', keyWords(W.d.key_type) + (W.d.key_type_alt ? ' + ' + keyWords(W.d.key_type_alt) + ' (' + tr('dual') + ')' : '')]
    ];
    if (can().challenge) pairs.push(['Validation', W.d.challenge + (Object.keys(W.d.challenge_map).length ? ' · ' + Object.keys(W.d.challenge_map).length + ' name(s) otherwise' : '')]);
    pairs.push(['Renews', W.d.auto_renew ? 'by itself, ' + W.d.renew_days + ' days before the end' : 'only when asked']);
    pairs.push(['Key on renewal', W.d.reuse_key ? 'kept' : 'a new one each time']);
    if (W.d.days) pairs.push(['Valid for', W.d.days + ' days']);
    pairs.push(['Used for', W.d.eku.join(', ') || '–']);
    var subj = Object.keys(W.d.subject).filter(function (k) { return W.d.subject[k]; }).map(function (k) { return k + '=' + W.d.subject[k]; });
    if (subj.length) pairs.push(['Subject', data('span', 'mono small', subj.join(', '))]);
    if (!editing) pairs.push(['Deployed on', Object.keys(W.deploys).length ? Object.keys(W.deploys).join(', ') : 'nowhere yet']);
    if (W.d.tags) pairs.push(['Tags', tagChips(splitNames(W.d.tags))]);
    host.appendChild(el('p', 'note', editing ? 'What it will be. Saved, it takes effect at its next renewal - press Renew now in it to have it at once.'
      : 'What it will be. "Add and issue now" asks the source at once, in a job you can watch; "Add only" waits for the next look.'));
    host.appendChild(kvTable(pairs));
    var bad = checkNames();
    if (bad) host.appendChild(el('p', 'ct-bad', bad));
    /* What does not fit (compat): said, and Create is blocked while it is so. */
    if (!compatThen(host, steps()[W.step])) return;
    var left = compatProblems();
    if (left.length) {
      host.appendChild(problemBox('This does not fit yet - it cannot be created so', left));
      bad = bad || left[0].what;
    }
    /* Before the first certificate: what the validation needs, checked at once.
       While something is missing the CA is not asked (certs_precheck). */
    if (can().challenge && !bad) {
      var rh = el('div', 'ct-rd-review');
      host.appendChild(rh);
      rh.appendChild(saidLine('', 'Checking what the validation needs…'));
      var had = planBlocks();
      var tick = modalTicket();
      planNow().then(function (plan) {
        if (!modalStill(tick) || steps()[W.step].key !== 'review') return;
        if (planBlocks() !== had) { paint(); return; }
        clear(rh);
        var block = arr(plan.blocking);
        if (!block.length) { rh.appendChild(saidLine('good', 'The validation looks ready: nothing that blocks was found.')); return; }
        var box = el('div', 'ct-errbox');
        var hh = el('div', 'ct-errbox-h');
        hh.appendChild(el('b', '', 'Not in place yet'));
        hh.appendChild(el('span', 'muted small', 'Created now, it waits: acme does not ask the CA until this is there, and tries again by itself.'));
        box.appendChild(hh);
        block.forEach(function (b) {
          box.appendChild(rdStep({what: b.what, said: b.said, fix: b.fix, record: b.record, done: false, blocking: true,
                                  where: b.domain || ''}));
        });
        rh.appendChild(box);
      }).catch(function (e) { if (modalStill(tick)) { clear(rh); rh.appendChild(failedBox(e, 'the check of the validation')); } });
    }
  }

  function body() {
    var d = W.d;
    var profile = {};
    if (d.days) profile.days = Number(d.days);
    if (d.eku.length) profile.eku = d.eku;
    if (d.must_staple) profile.must_staple = true;
    if (d.acme_profile) profile.acme_profile = d.acme_profile;
    if (d.template) profile.template = d.template;
    var subject = {};
    Object.keys(d.subject).forEach(function (k) { if (d.subject[k]) subject[k] = d.subject[k]; });
    if (String(d.cn || '').trim()) subject.CN = String(d.cn).trim();
    if (Object.keys(subject).length) profile.subject = subject;
    if (sanOther().length) profile.san_other = sanOther();
    var useChallenge = can().challenge;
    var tw = W.compat && W.compat.source && W.compat.source.name === d.issuer ? W.compat.twin.ok : (src() && src().dual);
    return {id: c.id, name: d.name || certName(names()[0] || String(d.cn || '').trim()), names: names(), key_type: d.key_type,
            key_type_alt: tw ? (d.key_type_alt || '') : '', issuer: d.issuer,
            challenge: useChallenge ? d.challenge : '', challenge_map: useChallenge ? d.challenge_map : {},
            auto_renew: !!d.auto_renew, renew_days: Number(d.renew_days || 30), reuse_key: !!d.reuse_key,
            profile: profile, tags: splitNames(d.tags), note: d.note, owner: d.owner};
  }
  /* What happens (runplan.js): the plan of what is set here now, over the wizard. */
  function planOpen() {
    if (read) read();
    var sent = body();
    sent.deploys = W.deploys;
    ACME_RUNPLAN.open({id: c.id || undefined, draft: sent, name: sent.name});
  }
  function finish(b, issue) {
    var bad = checkNames() || (!W.d.issuer ? 'choose where it comes from' : '') ||
      ((compatProblems()[0] || {}).what || '');
    if (bad) { toast(bad, 'bad'); return; }
    busy(b, true);
    var sent = body();
    /* What would make another certificate: changed on one already issued, the
       question after the save - now, or at the next renewal. */
    var inCert = function (x) {
      /* the validation is how the names are proved - not in the certificate */
      return JSON.stringify([arr(x.names).slice().sort(), x.key_type || '', x.key_type_alt || '', x.issuer || '',
                             obj(x.profile)]);
    };
    var reissue = editing && !issue && !!c.not_after && inCert(sent) !== inCert(c);
    capi('certs/save', sent).then(function (d) {
      var id = (d && d.id) || c.id;
      /* Saved: pressed again after a deployment was refused, it is this certificate
         and these deployments saved again - not a second of each. (1.0.19) */
      c.id = id;
      W.deployed = W.deployed || {};
      var jobs = Object.keys(W.deploys).map(function (t) {
        return function () {
          return capi('deploys/save', {id: W.deployed[t], cert_id: id, target: t, options: W.deploys[t], enabled: true})
            .then(function (x) { W.deployed[t] = (x && x.id) || W.deployed[t]; });
        };
      });
      var chain = jobs.reduce(function (p, fn) { return p.then(fn); }, Promise.resolve());
      return chain.then(function () {
        toast(said(d, editing ? 'saved' : 'added'), 'good');
        CT.refresh();
        /* Saved already: the popup closes whatever the issuing says - its error is
           said, and the certificate opened, as it is now. */
        if (issue) return capi('certs/renew', {id: id, force: true}).then(function (x) { closeModal(); jobStarted(x, 'issuing'); },
          function (e) { closeModal(); fail(e); certPeek(id); });
        if (reissue) { closeModal(); renewAsk(id, c.name); return; }
        if (editing) { closeModal(); certPeek(id); } else { closeModal(); certPeek(id); }
      });
    }).catch(fail).then(function () { busy(b, false); });
  }

  modal(editing ? 'Edit ' + c.name : 'Add a certificate', function (bd) { bd.appendChild(el('p', 'center muted', 'Asking…')); }, [{words: 'Close', close: true}], 'large');
  if (editing) nameInTitle('Edit', c.name);
  var ticket = modalTicket();
  /* Asked anew each time it opens: what was made a moment ago in another tab
     (or on the other node) is offered at once. */
  var fresh = function (key) { return loadRows(key, true).catch(function () { return []; }); };
  Promise.all([fresh('sources'), fresh('validation'), fresh('targets'), plugins(true).catch(function () { return null; })])
    .then(function (got) {
      if (!modalStill(ticket)) return;
      W.sources = got[0];
      W.vals = got[1];
      /* The default target first, offered (ticked) for a new certificate. */
      var dt = defaultOf(got[2]);
      W.targets = dt ? [dt].concat(got[2].filter(function (t) { return t !== dt; })) : got[2];
      if (dt && !editing && (dt.enabled === undefined || truthy(dt.enabled))) W.deploys[dt.name] = {};
      if (!W.d.issuer && W.sources.length === 1) W.d.issuer = W.sources[0].name;
      /* Let's Encrypt first: the default source and validation (is_default). */
      if (!W.d.issuer) W.d.issuer = (W.sources.filter(function (x) { return x.is_default; })[0] || {}).name || '';
      if (!W.d.challenge && !editing) W.d.challenge = (W.vals.filter(function (x) { return x.is_default; })[0] || {}).name || '';
      paint();
    });
}

/* ==========================================================================
   Import, self-signed, a CSR for an outside CA
   ========================================================================== */
var KEY_EXT = /\.(key)$/i;
function importDialog(into) {
  into = into && into.id ? into : null;
  var held = {main: null, key: null, mainB64: '', keyB64: '', parsed: null};
  var pass = null, keyPass = null, name = null, tags = null, note = null, found = null, drop = null, keyRow = null;
  var parse = function () {
    if (!held.main) return;
    clear(found);
    found.appendChild(el('p', 'muted', 'Reading ' + held.main.name + '…'));
    capi('certs/parse', {data_b64: held.mainB64, filename: held.main.name, password: pass.value || undefined}).then(function (d) {
      held.parsed = d;
      drawFound(d);
    }).catch(function (e) {
      clear(found);
      if (/password|passphrase|encrypted|mac verify/i.test(wordsOf(e))) {
        found.appendChild(askPass(wordsOf(e)));
        return;
      }
      found.appendChild(failedBox(e, 'reading certificate files'));
    });
  };
  var askPass = function (words) {
    var box = el('div', 'ct-askpass');
    var h = el('div', 'ct-askpass-h');
    h.innerHTML = iconMarkup('lock', 18);
    h.appendChild(el('b', '', 'It is locked with a password'));
    box.appendChild(h);
    if (words) box.appendChild(data('div', 'muted small', words));
    var row = el('div', 'btnrow');
    var mirror = secretBox(pass.value, 'the password of the file', 'mono');
    mirror.style.flex = '1';
    var go = cmdButton('Open it', 'lock', 'primary');
    go.onclick = function () { pass.value = mirror.value; parse(); };
    mirror.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go.click(); } });
    row.appendChild(mirror);
    row.appendChild(go);
    box.appendChild(row);
    setTimeout(function () { try { mirror.focus(); } catch (e) { } }, 0);
    return box;
  };
  var drawFound = function (d) {
    clear(found);
    var certs = rowsOf(d.certs || d.certificates || (d.cert ? [d.cert] : []));
    if (d.needs_password && !certs.length) { found.appendChild(askPass('')); return; }
    var hasKey = !!(d.has_key || d.key);
    var box = el('div', 'ct-found');
    var sum = el('div', 'ct-found-sum');
    sum.appendChild(data('span', 'tag info', String(d.format || (held.main.name.split('.').pop() || '')).toUpperCase()));
    sum.appendChild(el('span', '', certs.length === 1 ? '1 certificate' : certs.length + ' certificates'));
    sum.appendChild(el('span', 'tag ' + (hasKey ? 'ok' : 'dim'), hasKey ? 'with its key' : 'no key'));
    if (d.key_matches === true) sum.appendChild(el('span', 'tag ok', 'the key fits'));
    if (d.key_matches === false) sum.appendChild(el('span', 'tag crit', 'the key does not fit'));
    box.appendChild(sum);
    /* The certificate itself first, then the chain above it. */
    var leafAt = certs.map(function (x) { return !!x.leaf; }).indexOf(true);
    if (leafAt > 0) certs.unshift(certs.splice(leafAt, 1)[0]);
    certs.forEach(function (one, i) {
      var leaf = one.leaf || (leafAt < 0 && i === 0);
      var r = el('div', 'ct-found-one' + (leaf ? ' leaf' : ''));
      var t = el('div', 'ct-found-t');
      t.appendChild(data('b', '', first(one.cn, one.subject_dn, '?')));
      if (one.is_ca) t.appendChild(el('span', 'tag violet', one.self_signed ? 'root' : 'authority'));
      else if (leaf) t.appendChild(el('span', 'tag info', 'the certificate'));
      if (one.not_after) t.appendChild(daysTag(one.not_after));
      r.appendChild(t);
      if (one.error) r.appendChild(data('div', 'ct-bad small', one.error));
      if (arr(one.names).length && !one.is_ca) r.appendChild(namesChips(one.names, 6));
      var sub = el('div', 'muted small');
      sub.appendChild(document.createTextNode('issued by '));
      sub.appendChild(mono(first(one.issuer_dn, typeof one.issuer === 'string' ? one.issuer : '', '?')));
      if (one.not_before) sub.appendChild(document.createTextNode(' · ' + dayOnly(one.not_before) + ' – ' + dayOnly(one.not_after)));
      if (one.key_type) sub.appendChild(document.createTextNode(' · ' + keyWords(one.key_type) + (one.key_bits ? ' ' + one.key_bits : '')));
      r.appendChild(sub);
      box.appendChild(r);
    });
    rowsOf(d.notes || d.warnings).forEach(function (w) { box.appendChild(data('div', 'ct-warnline', String(w))); });
    found.appendChild(box);
    keyRow.hidden = hasKey;
    var lf = certs[0];
    if (!name.value && lf) name.value = lf.cn || arr(lf.names)[0] || '';
  };
  var take = function (files) {
    files.forEach(function (f) {
      var isKey = KEY_EXT.test(f.name);
      var p = fileB64(f).then(function (b64) {
        if (!isKey && /\.pem$/i.test(f.name)) {
          var text = '';
          try { text = atob(b64); } catch (e) { }
          if (/PRIVATE KEY/.test(text) && !/CERTIFICATE/.test(text)) isKey = true;
        }
        if (isKey && (held.main || files.length > 1)) { held.key = f; held.keyB64 = b64; }
        else { held.main = f; held.mainB64 = b64; }
      });
      p.then(function () {
        drop._words.textContent = (held.main ? held.main.name : '') + (held.key ? ' + ' + held.key.name : '');
        drop.classList.add('has');
        if (held.key) keyRow.querySelector('.ct-keyname').textContent = held.key.name + ' · ' + bytes(held.key.size);
        if (held.main && (!isKey || files.length === 1)) parse();
      }).catch(oops);
    });
  };
  modal(into ? 'A new certificate for ' + into.name : 'Import a certificate', function (body) {
    if (into) body.appendChild(el('p', 'note', 'It becomes the next version of ' + into.name + ' and is deployed where that one is. Without a key in the file, the key kept for it is used.'));
    body.appendChild(el('p', 'note', 'Any file a certificate comes in: PEM, CRT, CER, DER, P7B, PFX/P12, JKS - with its key in it, or the key in a file of its own (.key) dropped beside it. It is read first and shown; nothing is kept until you press Import.'));
    drop = dropZone('Drop the file here, or press to choose it', take, '.pem,.crt,.cer,.der,.p7b,.p7c,.pfx,.p12,.jks,.key,.txt', true);
    body.appendChild(drop);
    pass = secretBox('', 'only for a locked file', 'mono');
    found = el('div', 'ct-foundhost');
    body.appendChild(found);
    keyRow = el('div', 'ct-keyrow');
    keyRow.appendChild(el('b', 'small', 'The key, if it is in a file of its own'));
    var kd = dropZone('Drop the key here', function (fs) {
      held.key = fs[0];
      fileB64(fs[0]).then(function (b) { held.keyB64 = b; kd._words.textContent = fs[0].name; kd.classList.add('has'); });
    }, '.key,.pem,.txt', false);
    kd.classList.add('small');
    keyRow.appendChild(kd);
    keyRow.appendChild(el('span', 'ct-keyname muted small', ''));
    keyPass = secretBox('', 'the key’s password, if it has one', 'mono');
    keyRow.appendChild(formField('Password of the key', keyPass));
    body.appendChild(keyRow);
    var g = el('div', 'formgrid');
    name = textBox(into ? into.name : '', tr('from the certificate'), '');
    noI18n(name);
    if (!into) guardName(name, false);
    tags = tagsBox([]);
    var ownerI = ownerBox('');
    note = textBox('', '', '');
    if (!into) {
      g.appendChild(formField('Name in acme', name));
      g.appendChild(formField('Tags', tags));
      g.appendChild(formField('Owner', ownerI, 'Who it belongs to (Settings → Owners and teams).'));
    }
    g.appendChild(formField('Password of the file', pass, 'For a PFX/P12 or JKS. It is asked for if needed.'));
    if (!into) {
      var nf = formField('Note', note);
      nf.classList.add('wide');
      g.appendChild(nf);
    }
    body.appendChild(g);
  }, [{words: 'Close', close: true}, {words: 'Import', cls: 'primary', icon: 'upload', go: function (b) {
    if (!held.main) { toast('drop a file first', 'bad'); return; }
    busy(b, true);
    capi('certs/import', {id: into ? into.id : undefined, name: into ? undefined : (name.value.trim() || undefined), data_b64: held.mainB64, filename: held.main.name,
                          password: pass.value || undefined, key_b64: held.keyB64 || undefined, key_filename: held.key ? held.key.name : undefined,
                          key_password: keyPass.value || undefined, tags: splitNames(tags.value), note: note.value,
                          owner: into ? undefined : ownerI.value}).then(function (d) {
      toast(said(d, 'imported'), 'good');
      closeModal();
      CT.refresh();
      if (d && d.id && !into) certPeek(d.id);
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}

function selfSigned() {
  var f = {};
  modal('A self-signed certificate', function (b) { b.appendChild(el('p', 'center muted', 'Asking…')); }, [{words: 'Close', close: true}], 'medium');
  var ticket = modalTicket();
  Promise.all([rowsSafe('sources'), plugins().catch(function () { return null; })]).then(function (got) {
    if (!modalStill(ticket)) return;
    var mine = got[0].filter(function (s) { return /self/i.test(String(s.kind)); });
    modal('A self-signed certificate', function (body) {
      body.appendChild(el('p', 'note', 'Signed by its own key: encrypted, but trusted by nobody until its certificate is put in their trust store. For tests, internal tools and devices that only want something.'));
      var g = el('div', 'formgrid');
      f.names = areaBox('', 'device.example.local\n192.0.2.10', 3, 'mono');
      noI18n(f.names);
      var nf = formField('Names', f.names, 'One a line; IP addresses too. The first is its common name.');
      nf.classList.add('wide');
      g.appendChild(nf);
      f.name = textBox('', tr('the first name'), '');
      noI18n(f.name);
      g.appendChild(formField('Name in acme', f.name));
      guardName(f.name, false);
      f.key = selectBox(KEY_TYPES.map(function (k) { return [k[0], k[1]]; }), 'ec-256');
      g.appendChild(formField('Key', f.key));
      f.days = numberBox(825, '825', 1, 36500);
      g.appendChild(formField('Valid for (days)', f.days));
      f.auto = switchBox(true);
      g.appendChild(formField('Renew by itself', f.auto, '30 days before it runs out, as a new self-signed one.'));
      f.O = textBox('', 'Example s.r.o.', '');
      noI18n(f.O);
      g.appendChild(formField('Organisation', f.O));
      f.C = textBox('', 'CZ', '');
      noI18n(f.C);
      g.appendChild(formField('Country', f.C));
      f.owner = ownerBox('');
      g.appendChild(formField('Owner', f.owner, 'Who it belongs to (Settings → Owners and teams).'));
      f.tags = tagsBox([]);
      g.appendChild(formField('Tags', f.tags));
      if (mine.length > 1) {
        f.src = selectBox(mine.map(function (s) { return [s.name, s.name]; }), mine[0].name);
        noI18n(f.src);
        g.appendChild(formField('Source', f.src));
      }
      body.appendChild(g);
      if (!mine.length) body.appendChild(el('p', 'muted small', FULL ? 'There is no self-signed source yet: one is made with it.' : 'There is no self-signed source yet - a full administrator adds one under Sources.'));
    }, [{words: 'Close', close: true}, {words: 'Make it', cls: 'primary', icon: 'play', go: function (b) {
      var list = splitNames(f.names.value);
      if (!list.length) { toast('it needs at least one name', 'bad'); f.names.focus(); return; }
      var srcName = f.src ? f.src.value : (mine[0] && mine[0].name);
      busy(b, true);
      var ready = srcName ? Promise.resolve(srcName) : (FULL
        ? capi('sources/save', {name: 'Self-signed', kind: 'selfsigned', config: {}, enabled: true}).then(function () { delete LISTS.sources; return 'Self-signed'; })
        : Promise.reject(new Error('there is no self-signed source - a full administrator adds one under Sources')));
      ready.then(function (s) {
        var subject = {};
        if (f.O.value.trim()) subject.O = f.O.value.trim();
        if (f.C.value.trim()) subject.C = f.C.value.trim();
        return capi('certs/save', {name: f.name.value.trim() || certName(list[0]), names: list, key_type: f.key.value, issuer: s,
          challenge: '', challenge_map: {}, auto_renew: !!f.auto._get(), renew_days: 30, reuse_key: false,
          profile: {days: Number(f.days.value || 825), eku: ['serverAuth'], subject: subject},
          tags: splitNames(f.tags.value), note: '', owner: f.owner.value || ''});
      }).then(function (d) {
        CT.refresh();
        return capi('certs/renew', {id: d.id, force: true}).then(function (x) { closeModal(); jobStarted(x, 'issuing'); },
          function (e) { closeModal(); fail(e); certPeek(d.id); });
      }).catch(fail).then(function () { busy(b, false); });
    }}], 'medium');
    f.names.addEventListener('input', function () { f.name.placeholder = splitNames(f.names.value)[0] || tr('the first name'); });
  });
}

function csrDialog() {
  var f = {};
  modal('A CSR for an outside CA', function (body) {
    body.appendChild(el('p', 'note', 'For an authority acme does not speak to: the key is made here and kept here, you take the request (CSR) to the CA, and upload what it sends back - then acme deploys it like any other. It is renewed the same way, by hand.'));
    var g = el('div', 'formgrid');
    f.names = areaBox('', 'portal.example.com\nwww.portal.example.com', 3, 'mono');
    noI18n(f.names);
    var nf = formField('Names', f.names, 'One a line. The first is the common name.');
    nf.classList.add('wide');
    g.appendChild(nf);
    f.name = textBox('', tr('the first name'), '');
    noI18n(f.name);
    g.appendChild(formField('Name in acme', f.name));
    guardName(f.name, false);
    f.key = selectBox(KEY_TYPES.map(function (k) { return [k[0], k[1]]; }), 'rsa-2048');
    g.appendChild(formField('Key', f.key, 'Many commercial CAs still want RSA.'));
    [['O', 'Organisation', 'Example s.r.o.'], ['OU', 'Unit', 'IT'], ['C', 'Country', 'CZ'], ['ST', 'Region', 'Praha'],
     ['L', 'City', 'Praha'], ['emailAddress', 'E-mail', 'it@example.cz']].forEach(function (x) {
      f[x[0]] = textBox('', x[2], '');
      noI18n(f[x[0]]);
      g.appendChild(formField(x[1], f[x[0]]));
    });
    f.owner = ownerBox('');
    g.appendChild(formField('Owner', f.owner, 'Who it belongs to (Settings → Owners and teams).'));
    f.tags = tagsBox([]);
    g.appendChild(formField('Tags', f.tags));
    body.appendChild(g);
  }, [{words: 'Close', close: true}, {words: 'Make the CSR', cls: 'primary', icon: 'key', go: function (b) {
    var list = splitNames(f.names.value);
    if (!list.length) { toast('it needs at least one name', 'bad'); f.names.focus(); return; }
    var subject = {};
    ['O', 'OU', 'C', 'ST', 'L', 'emailAddress'].forEach(function (k) { if (f[k].value.trim()) subject[k] = f[k].value.trim(); });
    busy(b, true);
    capi('certs/save', {name: f.name.value.trim() || certName(list[0]), names: list, key_type: f.key.value, issuer: '', source: 'csr',
                        challenge: '', challenge_map: {}, auto_renew: false, renew_days: 30, reuse_key: false,
                        profile: {subject: subject}, tags: splitNames(f.tags.value), note: '',
                        owner: f.owner.value || ''}).then(function (d) {
      CT.refresh();
      return capi('certs/csr', {id: d.id}).then(function (x) { showCsr({id: d.id, name: f.name.value.trim() || certName(list[0])}, x.csr_pem || x.csr || ''); });
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}
function showCsr(c, pem) {
  modal('The CSR of ' + c.name, function (body) {
    body.appendChild(el('p', 'note', 'Give this to the CA. When it sends the certificate back, drop it below - now, or later from the certificate (it waits in the state "waiting for a CA").'));
    var ta = areaBox(pem, '', 10, 'mono ct-csr');
    ta.readOnly = true;
    noI18n(ta);
    body.appendChild(ta);
    var row = el('div', 'btnrow');
    var cp = cmdButton('Copy', 'copy', 'small');
    cp.onclick = function () { copyText(pem, cp, 'the CSR was copied'); };
    var dl = cmdButton('Download', 'download', 'small');
    dl.onclick = function () { saveText(String(c.name).replace(/[^A-Za-z0-9._-]+/g, '_') + '.csr', pem, 'application/pkcs10'); };
    row.appendChild(cp);
    row.appendChild(dl);
    body.appendChild(row);
    body.appendChild(el('h4', 'ct-formh', 'What the CA sent back'));
    body.appendChild(answerDrop(c));
  }, [{words: 'Close', close: true}], 'medium');
}
function answerDrop(c) {
  var box = el('div');
  var said0 = saidLine('', '');
  var dz = dropZone('Drop the certificate the CA sent (PEM, CRT, CER, DER, P7B)', function (files) {
    said0.className = 'said';
    said0.textContent = 'Reading ' + files[0].name + '…';
    fileB64(files[0]).then(function (b64) {
      return capi('certs/csr_answer', {id: c.id, data_b64: b64, filename: files[0].name});
    }).then(function (d) {
      said0.className = 'said good';
      said0.textContent = said(d, 'taken: the certificate is in use');
      toast(said(d, 'the certificate is in use'), 'good');
      CT.refresh();
      setTimeout(function () {
        closeModal();
        certPeek(c.id);
        if (d && d.job_id) setTimeout(function () { over(function () { jobPeek(d.job_id); }); }, 400);
      }, 700);
    }).catch(function (e) { said0.className = 'said bad'; said0.textContent = e.missing ? 'not available yet' : wordsOf(e); });
  }, '.pem,.crt,.cer,.der,.p7b,.p7c,.txt', false);
  box.appendChild(dz);
  box.appendChild(said0);
  return box;
}
function csrAnswer(c) {
  modal('The answer of the CA for ' + c.name, function (body) {
    body.appendChild(el('p', 'note', 'The certificate the outside CA issued for the CSR made here. It is checked against the key kept here before it is taken.'));
    body.appendChild(answerDrop(c));
    var again = cmdButton('Show the CSR again', 'key', 'small');
    again.onclick = function () {
      capi('certs/csr', {id: c.id}).then(function (x) { showCsr(c, x.csr_pem || x.csr || ''); }).catch(fail);
    };
    var row = el('div', 'btnrow');
    row.style.marginTop = '12px';
    row.appendChild(again);
    body.appendChild(row);
  }, [{words: 'Close', close: true}], 'medium');
}

/* ==========================================================================
   Authorities of acme's own
   ========================================================================== */
var CAS = [], CAS_FRESH = 0;
/** The authorities, asked anew unless they were asked since the last change
    (a picker of authorities opens with what there is now). */
function casNow(again) {
  if (!again && CAS_FRESH && CAS_FRESH === FRESH.n + 1) return Promise.resolve(CAS);
  var gen = FRESH.n;
  return capi('cas').then(function (d) {
    CAS = rowsOf(d, 'cas', 'authorities');
    if (gen === FRESH.n) CAS_FRESH = gen + 1;
    return CAS;
  });
}
function loadCas(live) {
  var host = $('ca-tree');
  if (!host) return;
  if (!live && !host.children.length) host.appendChild(el('p', 'muted', 'Asking…'));
  casNow(true).then(function () {
    pkiCard(CAS);
    $('ca-said').textContent = CAS.length ? num(CAS.length) + ' in all' : '';
    if ($('ca-inter')) $('ca-inter').disabled = !CAS.length;
    liveFill(host, function (box) {
      if (!CAS.length) {
        var b = el('div', 'ct-blank big');
        var ic = el('div', 'ct-blank-ic');
        ic.innerHTML = iconMarkup('ca', 34);
        b.appendChild(ic);
        b.appendChild(el('h3', '', 'No authority of acme’s own yet'));
        b.appendChild(el('p', 'muted', 'Make a root - and an intermediate under it to issue from - for certificates only your own machines need to trust: internal servers, devices, VPN clients. Or import the authority you already have.'));
        box.appendChild(b);
        return;
      }
      box.appendChild(caTree(CAS));
    }, live);
    explainWhatWasDrawn(host);
  }).catch(failInto(host, 'the authorities'));
}
function caTree(list) {
  var byParent = {}, ids = {};
  list.forEach(function (c) { ids[c.id] = c; });
  list.forEach(function (c) {
    var p = c.parent_id && ids[c.parent_id] ? c.parent_id : 0;
    (byParent[p] = byParent[p] || []).push(c);
  });
  var tree = el('ul', 'ct-tree');
  var add = function (ul, parent, depth) {
    (byParent[parent] || []).forEach(function (c) {
      var li = el('li');
      li.appendChild(caNode(c, depth, (byParent[c.id] || []).length));
      if (byParent[c.id]) {
        var sub = el('ul');
        add(sub, c.id, depth + 1);
        li.appendChild(sub);
      }
      ul.appendChild(li);
    });
  };
  add(tree, 0, 0);
  return tree;
}
function caNode(c, depth, kids) {
  var n = el('div', 'ct-node' + (c.disabled && truthy(c.disabled) ? ' off' : ''));
  n.tabIndex = 0;
  n.setAttribute('role', 'button');
  var ic = el('span', 'ct-node-ic ' + (depth ? 'inter' : 'root'));
  ic.innerHTML = iconMarkup(depth ? 'ca' : 'crown', 20);
  n.appendChild(ic);
  var w = el('div', 'ct-node-w');
  var t = el('div', 'ct-node-t');
  t.appendChild(data('b', '', c.name));
  t.appendChild(el('span', 'tag ' + (depth ? 'info' : 'violet'), depth ? 'intermediate' : 'root'));
  if (truthy(c.external)) t.appendChild(el('span', 'tag dim', 'imported'));
  if (c.has_key === false) {
    var nk = el('span', 'tag warn', 'no key');
    explain(nk, 'acme has only its certificate: it cannot sign with it.');
    t.appendChild(nk);
  }
  if (c.disabled && truthy(c.disabled)) t.appendChild(el('span', 'tag dim', 'off'));
  if (c.is_default) t.appendChild(el('span', 'tag ok', 'default'));
  if (c.published) {
    var pt = el('span', 'tag info', 'published on acme');
    explain(pt, 'Its CRL and certificate are served by acme itself at /pki/, over plain HTTP.');
    t.appendChild(pt);
  }
  w.appendChild(t);
  w.appendChild(data('div', 'mono small muted ct-node-dn', c.subject_dn || ''));
  n.appendChild(w);
  var f = el('div', 'ct-node-f');
  f.appendChild(ftag('Key', keyWords(c.key_type), 'k'));
  f.appendChild(ftag('Until', c.not_after ? dayOnly(c.not_after) : '–', 'u'));
  var d = daysLeftOf(c.not_after);
  var dt = el('span', 'ct-days ct-ft-d ' + (d === null ? 'dim' : (d < 0 ? 'crit' : (d < 90 ? 'warn' : 'ok'))), d === null ? '' : daysWords(d));
  f.appendChild(dt);
  var issued = first(c.issued, c.issued_count, c.signed);
  f.appendChild(ftag('Signed', issued === undefined ? '–' : num(Number(issued)), 's'));
  var ct = ftag('CRL', '–', 'c');
  if (c.crl_at) {
    var next = c.crl_next || (c.crl_at + (c.crl_days || 7) * 86400);
    var late = next < now();
    ct = ftag('CRL', late ? tr('out of date') : tr('until {0}').replace('{0}', dayOnly(next)), 'c');
    if (late) ct.classList.add('bad');
  }
  f.appendChild(ct);
  f.appendChild(ftag('Below', kids ? num(kids) : '–', 'b'));
  n.appendChild(f);
  if (FULL && !c.pending) {
    var star = defaultButton('cas', c);
    star.classList.add('ct-node-star');
    n.appendChild(star);
  }
  n.onclick = function () { caPeek(c.id); };
  n.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); caPeek(c.id); } };
  return n;
}
function ftag(k, v, cls) {
  var s = el('span', 'ct-ft' + (cls ? ' ct-ft-' + cls : ''));
  s.appendChild(el('i', '', k));
  s.appendChild(data('b', '', v));
  return s;
}
function caPeek(id) {
  popup('An authority', function () { return capi('cas/one' + qs({id: id})); }, function (d) {
    var c = d.ca || d.authority || d;
    var issued = rowsOf(d.issued || d.signed || c.issued_list);
    var back = function () { caPeek(c.id); };
    var buttons = [{words: 'Close', close: true}];
    if (MANAGE) buttons.push({words: 'New CRL', icon: 'refresh', go: function (b) {
      busy(b, true);
      capi('cas/crl', {id: c.id}).then(function (x) { toast(said(x, 'a new CRL was made'), 'good'); back(); }).catch(fail).then(function () { busy(b, false); });
    }});
    var dfc = defaultFoot('cas', c, back);
    if (dfc) buttons.push(dfc);
    if (FULL) {
      buttons.unshift({words: 'Delete', cls: 'danger', icon: 'trash', left: true, go: function () {
        capi('cas/delete', {id: c.id}).then(function (x) { toast(said(x, 'deleted'), 'good'); closeModal(); loadCas(); }).catch(fail);
      }});
      buttons.push({words: 'Create an intermediate', icon: 'add', go: function () { over(function () { caCreate(c); }, back); }});
      buttons.push({words: 'Sign a CSR', cls: 'primary', icon: 'key', go: function () { over(function () { signCsr(c); }, back); }});
    }
    caExtra('buttons', c, d, back, buttons);
    return {
      title: c.name, size: 'large',
      build: function (body) {
        var head = el('div', 'ct-head');
        var ic = el('div', 'ct-head-ic ' + (c.parent_id ? 'info' : 'violet'));
        ic.innerHTML = iconMarkup(c.parent_id ? 'ca' : 'crown', 26);
        head.appendChild(ic);
        var hw = el('div', 'ct-head-w');
        var t = el('div', 'ct-head-t');
        t.appendChild(data('span', 'ct-head-name', c.name));
        t.appendChild(el('span', 'tag ' + (c.parent_id ? 'info' : 'violet'), c.parent_id ? 'intermediate' : 'root'));
        if (c.not_after) t.appendChild(daysTag(c.not_after));
        if (c.has_key === false) t.appendChild(el('span', 'tag warn', 'no key - it cannot sign'));
        hw.appendChild(t);
        hw.appendChild(data('div', 'mono small muted', c.subject_dn || ''));
        head.appendChild(hw);
        body.appendChild(head);
        var dn = defaultNote('cas', c);
        if (dn) body.appendChild(dn);
        var parent = CAS.filter(function (x) { return x.id === c.parent_id; })[0];
        var grid = el('div', 'msects');
        var s1 = section('The authority');
        var nc = arr(c.name_constraints);
        s1._body.appendChild(kvTable([
          ['Signed by', parent ? parent.name : (c.parent_id ? '#' + c.parent_id : 'itself (a root)')],
          ['Key', keyWords(c.key_type)],
          ['Valid', dayOnly(c.not_before) + ' – ' + dayOnly(c.not_after)],
          ['SHA-256', c.fingerprint ? copyable(fpWords(c.fingerprint), 'the fingerprint was copied') : '–'],
          ['Path length', c.path_len === null || c.path_len === undefined || c.path_len === '' || Number(c.path_len) < 0 ? 'no limit' : String(c.path_len)],
          ['Name constraints', nc.length ? data('span', 'mono small', nc.join('\n')) : 'none'],
          ['Issues for', c.days_default ? c.days_default + ' days unless asked' : '–'],
          ['Next serial', c.serial_next ? String(c.serial_next) : '–'],
          ['Made', c.created ? stamp(c.created) + (c.created_by ? ' · ' + c.created_by : '') : '–']
        ]));
        grid.appendChild(s1);
        var s2 = section('Revocation and where it is published');
        var next = c.crl_at ? (c.crl_next || c.crl_at + (c.crl_days || 7) * 86400) : null;
        s2._body.appendChild(kvTable([
          ['CRL number', c.crl_number ? String(c.crl_number) : '–'],
          ['Made', c.crl_at ? stamp(c.crl_at) : 'not yet'],
          ['Valid until', next ? stamp(next) : '–'],
          ['Made anew every', (c.crl_days || 7) + ' days'],
          ['CRL address', c.crl_url ? mono(c.crl_url) : '–'],
          ['AIA address', c.aia_url ? mono(c.aia_url) : '–'],
          c.ocsp_url ? ['OCSP', mono(c.ocsp_url)] : null
        ]));
        var ex = el('div', 'btnrow');
        [['cert-pem', 'Certificate', 'cert'], ['cert-der', 'DER', 'cert-der'], ['chain-pem', 'Chain', 'chain'], ['crl', 'CRL', 'crl']].forEach(function (w) {
          var b = cmdButton(w[1], 'download', 'small');
          b.onclick = function () {
            busy(b, true);
            /* The CRL as it is made now (cas/crl makes it and hands it over). */
            var ask = w[0] === 'crl' && MANAGE ? capi('cas/crl', {id: c.id}) : capi('cas/export', {id: c.id, format: w[0], what: w[2]});
            ask.then(function (x) { download(x); if (w[0] === 'crl') loadCas(true); }).catch(fail).then(function () { busy(b, false); });
          };
          ex.appendChild(b);
        });
        s2._body.appendChild(ex);
        grid.appendChild(s2);
        if (d.pki && d.pki.urls) grid.appendChild(pkiSection(c, d.pki, back));
        var s3 = section('What it signed', 'Every certificate this authority issued; a revoked one is in its CRL.', true);
        var find = el('input');
        find.type = 'search';
        find.placeholder = 'a name, a serial…';
        var tableHost = el('div');
        var drawIssued = function () {
          var q = find.value.trim().toLowerCase();
          var rows = issued.filter(function (r) {
            return !q || (String(r.serial) + ' ' + (r.subject_dn || '') + ' ' + arr(r.names).join(' ')).toLowerCase().indexOf(q) >= 0;
          });
          clear(tableHost);
          tableHost.appendChild(listTable(['Serial', 'Subject', 'Names', 'Valid', 'State', 'By', ''], rows, function (r) {
            var tr = el('tr');
            tr.appendChild(td('', data('span', 'mono small', r.serial)));
            tr.appendChild(td('', data('span', 'mono small', r.subject_dn || '')));
            tr.appendChild(td('', namesChips(r.names, 3)));
            tr.appendChild(td('small', dayOnly(r.not_before) + ' – ' + dayOnly(r.not_after)));
            var st = el('td');
            if (r.revoked) {
              var rt = el('span', 'tag crit', 'revoked');
              explain(rt, stamp(r.revoked) + (r.reason ? ' · ' + r.reason : ''));
              st.appendChild(rt);
            } else if (r.not_after && r.not_after < now()) st.appendChild(el('span', 'tag dim', 'has expired'));
            else st.appendChild(el('span', 'tag ok', 'valid'));
            tr.appendChild(st);
            tr.appendChild(whoWhen(r.by_who, r.created));
            var tools = el('td', 'rowtools');
            if (FULL && !r.revoked) {
              var x = iconButton('ban', 'Revoke it: into the CRL');
              x.onclick = function (ev) { ev.stopPropagation(); over(function () { caRevoke(c, r); }, back); };
              tools.appendChild(x);
            }
            tr.appendChild(tools);
            return r.cert_id ? rowOpens(tr, function () { over(function () { certPeek(r.cert_id); }, back); }) : tr;
          }, 'plain ct-issued|Nothing signed yet'));
        };
        find.oninput = drawIssued;
        if (issued.length > 8) s3._body.appendChild(find);
        s3._body.appendChild(tableHost);
        drawIssued();
        grid.appendChild(s3);
        if (c.note) { var s4 = section('Note'); s4._body.appendChild(data('p', '', c.note)); grid.appendChild(s4); }
        caExtra('sections', c, d, back, grid);
        body.appendChild(grid);
      },
      buttons: buttons
    };
  }, 'large', 'the authorities');
}
/* ---- an authority's popup, parts drawn elsewhere --------------------------
   cas.js (Edit…, Renew its certificate…, its versions) adds itself to
   window.ACME_CA_PEEK: [{buttons: fn(c, d, back, list, kit), sections:
   fn(c, d, back, grid, kit)}] - kit is caKit(), the pieces of this file it
   draws with. A part that fails leaves the popup as it is. */
function caKit() {
  return {api: capi, full: FULL, manage: MANAGE, section: section, numberBox: numberBox,
    areaBox: areaBox, pemBox: pemBox, wideField: wideField, mono: mono, data: data, td: td,
    dayOnly: dayOnly, daysTag: daysTag, fpWords: fpWords, copyable: copyable, over: over,
    said: said, fail: fail, download: download, guardName: guardName, arr: arr, truthy: truthy,
    loadCas: loadCas, casNow: casNow, names: function () { return CAS.map(function (x) { return x.name; }); },
    caPeek: caPeek, ekus: EKUS};
}
function caExtra(what, c, d, back, host) {
  (window.ACME_CA_PEEK || []).forEach(function (x) {
    if (!x || typeof x[what] !== 'function') return;
    try { x[what](c, d, back, host, caKit()); } catch (e) { if (window.console) window.console.error(e); }
  });
}
/* ---- publishing on acme: the CRL and the certificate at /pki/ ------------- */
function goPkiSettings() {
  closeModal();
  showTab('settings');
  setTimeout(function () { if (typeof showPane === 'function') showPane('certs'); }, 60);
}
function urlLine(u) {
  var w = el('span', 'ct-url');
  w.appendChild(mono(u));
  var b = iconButton('copy', 'Copy the address');
  b.classList.add('small');
  b.onclick = function (ev) { ev.stopPropagation(); copyText(u, b, 'the address was copied'); };
  w.appendChild(b);
  return w;
}
function pkiSection(c, pki, back) {
  var sec = section('Published on acme', 'Its CRL and its certificate over plain HTTP, from every node and the VIP address alike (from the database) - for everybody, no sign-in, never sent to HTTPS.', true);
  var b = sec._body;
  var u = pki.urls || {};
  if (!pki.on) {
    var off = el('p', 'note warn');
    off.appendChild(el('span', '', 'Publishing is switched off for every authority (Settings → Renewal and notices: Publish CRLs on acme). '));
    if (FULL) {
      var go = el('button', 'btn small', 'Switch it on…');
      go.type = 'button';
      go.onclick = goPkiSettings;
      off.appendChild(go);
    }
    b.appendChild(off);
  }
  var state = el('span', '');
  state.appendChild(el('span', 'tag ' + (pki.published ? 'ok' : 'dim'), pki.published ? 'published' : 'not published'));
  if (FULL && pki.on) {
    var sw = switchBox(!!pki['switch']);
    sw.classList.add('ct-inline-switch');
    sw.addEventListener('change', function () {
      capi('cas/publish', {id: c.id, published: !!sw._get()}).then(function (x) {
        toast(said(x, 'saved'), 'good');
        back();
      }).catch(fail);
    });
    state.appendChild(sw);
  }
  var nu = pki.next_update;
  var late = nu && nu < now();
  b.appendChild(kvTable([
    ['Published', state],
    ['CRL (DER)', urlLine(u.crl)],
    ['CRL (PEM)', urlLine(u.crl_pem)],
    ['Certificate (DER)', urlLine(u.cert)],
    ['Certificate (PEM)', urlLine(u.cert_pem)],
    ['Every one published', urlLine(u.index)],
    ['Last CRL', pki.this_update ? stamp(pki.this_update) + (pki.number ? ' · #' + pki.number : '') : 'not yet'],
    ['Next update', nu ? (function () {
      var x = el('span', late ? 'ct-badtext' : '');
      x.appendChild(data('span', '', stamp(nu)));
      if (late) x.appendChild(el('span', 'tag crit small', 'it has run out'));
      return x;
    }()) : '–'],
    ['Made again by', pki.refresh_due ? (function () {
      var x = el('span', '');
      x.appendChild(data('span', '', stamp(pki.refresh_due)));
      x.appendChild(el('div', 'muted small', 'At half its life the node that leads makes it anew - and after every revocation.'));
      return x;
    }()) : '–'],
    ['In what it signs', pki.own_urls ? el('span', 'tag ok', 'acme’s own addresses') : (function () {
      var x = el('span', '');
      x.appendChild(el('span', 'tag warn', 'other addresses'));
      x.appendChild(mono(' ' + [pki.crl_url, pki.aia_url].filter(Boolean).join(' · ') || ' –'));
      return x;
    }())]
  ]));
  var row = el('div', 'btnrow');
  var out = el('div');
  if (MANAGE) {
    var ck = cmdButton('Check it', 'play', 'small');
    ck.onclick = function () {
      busy(ck, true);
      clear(out);
      out.appendChild(el('p', 'muted', 'Fetching it over HTTP…'));
      capi('cas/pki_check', {id: c.id}, 60).then(function (x) {
        clear(out);
        out.appendChild(saidLine(x.ok ? 'good' : 'bad', x.ok ? 'What is published is right.' : String(x.said || 'it is not right')));
        out.appendChild(jobLog(arr(x.steps).map(function (st) { return {level: st[0], words: st[1]}; })));
      }).catch(function (e) { clear(out); out.appendChild(saidLine('bad', wordsOf(e))); }).then(function () { busy(ck, false); });
    };
    row.appendChild(ck);
  }
  if (FULL && !pki.own_urls) {
    var use = cmdButton('Use acme’s own URLs', 'globe', 'small');
    use.onclick = function () {
      confirmThen('Use acme’s own URLs', htmlText('What ' + c.name + ' signs from now on carries the CRL address ' + u.crl + ' and the CA certificate address ' + u.cert + '. Certificates it issued before keep the addresses they have - they change at their next renewal.'), 'Use them', function () {
        capi('cas/pki_urls', {id: c.id}).then(function (x) { toast(said(x, 'saved'), 'good'); back(); }).catch(fail);
      });
    };
    row.appendChild(use);
  }
  b.appendChild(row);
  b.appendChild(out);
  return sec;
}
/** The card above the tree: whether acme publishes, and where. */
function pkiCard(list) {
  var box = $('ca-pki');
  if (!box) return;
  (function () {
    clear(box);
    var pubs = list.filter(function (c) { return c.published; });
    var line = el('p', 'note ct-pki-line');
    line.appendChild(el('b', '', 'Published on acme:'));
    line.appendChild(document.createTextNode(' '));
    if (pubs.length) {
      line.appendChild(el('span', '', pubs.length + ' authority(ies): their CRL and certificate at /pki/ on port 80 of every node and the VIP address.'));
    } else {
      line.appendChild(el('span', '', 'nothing yet - switched off, or no authority has a certificate.'));
    }
    var open = cmdButton('What is published', 'globe', 'small');
    open.onclick = function () { window.open('/pki/', '_blank', 'noopener'); };
    line.appendChild(open);
    if (FULL) {
      var st = cmdButton('Settings', 'gear', 'small');
      st.onclick = goPkiSettings;
      line.appendChild(st);
    }
    box.appendChild(line);
  }());
}
function caRevoke(ca, r) {
  var reason = null;
  modal('Revoke ' + r.serial, function (body) {
    body.appendChild(el('p', 'note', 'It goes into the CRL of ' + ca.name + ' at once, and a new CRL is made. This cannot be taken back.'));
    reason = selectBox(REVOKE_REASONS.filter(function (x) { return x[0] !== 'cACompromise'; }), 'unspecified');
    body.appendChild(formField('Why', reason));
  }, [{words: 'No, leave it', close: true}, {words: 'Revoke it', cls: 'danger', icon: 'ban', go: function (b) {
    busy(b, true);
    capi('cas/revoke', {id: ca.id, serial: r.serial, reason: reason.value}).then(function (x) {
      toast(said(x, 'revoked'), 'good');
      closeModal();
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'narrow');
  nameInTitle('Revoke', r.serial);
}
function subjectFields(g, f, cnNeeded) {
  [['CN', 'Common name', 'Example Root CA', true], ['O', 'Organisation', 'Example s.r.o.'], ['OU', 'Unit', 'IT'],
   ['C', 'Country', 'CZ'], ['ST', 'Region', 'Praha'], ['L', 'City', 'Praha']].forEach(function (x) {
    f[x[0]] = textBox('', x[2], '');
    noI18n(f[x[0]]);
    var item = formField(x[1], f[x[0]]);
    if (x[3] && cnNeeded) item.classList.add('ct-req');
    g.appendChild(item);
  });
}
/** An authority that can sign now (a certificate, a key, not off). */
function caSigns(c) { return c && !c.pending && c.has_key !== false && !(c.disabled && truthy(c.disabled)); }
function caPairs(list) {
  return list.map(function (c) { return [String(c.id), c.name + (c.is_default ? ' · ' + tr('default') : '')]; });
}
function caCreate(parent) {
  /* The authorities asked anew: one made a moment ago is offered as a parent. */
  casNow(true).catch(function () { return CAS; }).then(function () { caCreateForm(parent); });
}
function caCreateForm(parent) {
  var f = {};
  var isRoot = parent === null;
  var title = isRoot ? 'A new root authority' : 'A new intermediate authority';
  modal(title, function (body) {
    body.appendChild(el('p', 'note', isRoot
      ? 'A root signs itself and is what your machines trust. Keep it for signing intermediates and issue certificates from those: a root that is never used directly is one that never has to be replaced.'
      : 'An intermediate is signed by the authority above it and issues the certificates. Machines that trust the root trust it too.'));
    var g = el('div', 'formgrid');
    f.name = textBox('', isRoot ? 'Example Root CA' : 'Example Issuing CA', '');
    noI18n(f.name);
    var ni = formField('Name in acme', f.name);
    ni.classList.add('ct-req');
    g.appendChild(ni);
    guardName(f.name, true, CAS.map(function (c) { return c.name; }));
    if (!isRoot) {
      var signers = CAS.filter(caSigns);
      var dca = defaultOf(signers);
      f.parent = selectBox(caPairs(signers.length ? signers : CAS), parent ? String(parent.id) : (dca ? String(dca.id) : (CAS[0] ? String(CAS[0].id) : '')));
      noI18n(f.parent);
      g.appendChild(formField('Signed by', f.parent));
    }
    f.key = selectBox(KEY_TYPES.filter(function (k) { return k[0] !== 'ed25519'; }).map(function (k) { return [k[0], k[1]]; }), isRoot ? 'ec-384' : 'ec-256');
    g.appendChild(formField('Key', f.key));
    f.days = numberBox(isRoot ? 3650 : 1825, '', 1, 36500);
    g.appendChild(formField('Valid for (days)', f.days, isRoot ? '10 years is usual for a root.' : 'Shorter than the root above it.'));
    f.path = numberBox(isRoot ? '' : 0, 'no limit', 0, 9);
    g.appendChild(formField('Path length', f.path, 'How many authorities may still come under it. 0: it signs only certificates. Empty: no limit.'));
    body.appendChild(g);
    body.appendChild(el('h4', 'ct-formh', 'Subject'));
    var sg = el('div', 'formgrid');
    subjectFields(sg, f, true);
    body.appendChild(sg);
    body.appendChild(el('h4', 'ct-formh', 'Revocation and publishing'));
    var pg = el('div', 'formgrid');
    f.crlDays = numberBox(7, '7', 1, 365);
    pg.appendChild(formField('CRL made anew every (days)', f.crlDays));
    f.pub = switchBox(true);
    var pubField = formField('Publish on acme', f.pub, 'Its CRL and certificate served by acme itself at /pki/ (port 80, every node and the VIP address). The two addresses below are then acme’s own unless given - so every certificate it signs points here.');
    pubField.classList.add('wide');
    pg.appendChild(pubField);
    f.crlUrl = textBox('', 'http://pki.example.cz/root.crl', 'mono');
    noI18n(f.crlUrl);
    pg.appendChild(formField('CRL address', f.crlUrl, 'Written into what it signs, so a client can find the CRL. Empty: acme’s own when it is published on acme, else none.'));
    f.aia = textBox('', 'http://pki.example.cz/root.crt', 'mono');
    noI18n(f.aia);
    pg.appendChild(formField('AIA address', f.aia, 'Where its own certificate can be fetched. Empty: acme’s own when it is published on acme.'));
    f.nc = areaBox('', 'permitted DNS:.example.cz\npermitted IP:10.0.0.0/8\nexcluded DNS:.public.example.cz', 3, 'mono');
    noI18n(f.nc);
    var nf = formField('Name constraints', f.nc, 'One a line: names it may (permitted) or may not (excluded) sign for. Empty: any.');
    nf.classList.add('wide');
    pg.appendChild(nf);
    body.appendChild(pg);
    f.name.addEventListener('input', function () { if (!f.CN._touched) f.CN.value = f.name.value; });
    f.CN.addEventListener('input', function () { f.CN._touched = true; });
  }, [{words: 'Close', close: true}, {words: 'Create it', cls: 'primary', icon: 'add', go: function (b) {
    if (!f.name.value.trim()) { toast('it needs a name', 'bad'); f.name.focus(); return; }
    if (!f.CN.value.trim()) { toast('it needs a common name', 'bad'); f.CN.focus(); return; }
    var subject = {};
    ['CN', 'O', 'OU', 'C', 'ST', 'L'].forEach(function (k) { if (f[k].value.trim()) subject[k] = f[k].value.trim(); });
    busy(b, true);
    capi('cas/create', {name: f.name.value.trim(), subject: subject, key_type: f.key.value, days: Number(f.days.value || 3650),
      parent_id: f.parent ? Number(f.parent.value) : null, path_len: f.path.value === '' ? null : Number(f.path.value),
      crl_days: Number(f.crlDays.value || 7), crl_url: f.crlUrl.value.trim(), aia_url: f.aia.value.trim(),
      published: !!f.pub._get(),
      name_constraints: f.nc.value.split(/\n/).map(function (x) { return x.trim(); }).filter(Boolean)}, 120).then(function (d) {
      toast(said(d, 'created'), 'good');
      closeModal();
      loadCas();
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}
function caImport() {
  var f = {};
  modal('Import an authority', function (body) {
    body.appendChild(el('p', 'note', 'An authority you already have, to issue from here: its certificate and its private key (PEM), and the chain above it if it is an intermediate. The key is sealed in the database like every other.'));
    var g = el('div', 'formgrid');
    f.name = textBox('', 'Example Issuing CA', '');
    noI18n(f.name);
    g.appendChild(formField('Name in acme', f.name));
    guardName(f.name, false, CAS.map(function (c) { return c.name; }));
    f.pass = secretBox('', 'only if the key is locked', 'mono');
    g.appendChild(formField('Password of the key', f.pass));
    f.cert = pemBox('', '-----BEGIN CERTIFICATE-----', 5);
    g.appendChild(wideField('Its certificate', f.cert));
    f.key = pemBox('', '-----BEGIN PRIVATE KEY-----', 5);
    g.appendChild(wideField('Its private key', f.key));
    f.chain = pemBox('', 'the authorities above it, if any', 3);
    g.appendChild(wideField('Chain', f.chain, 'Empty for a root.'));
    body.appendChild(g);
  }, [{words: 'Close', close: true}, {words: 'Import', cls: 'primary', icon: 'upload', go: function (b) {
    if (!f.cert._get() || !f.key._get()) { toast('it needs the certificate and the key', 'bad'); return; }
    busy(b, true);
    capi('cas/import', {name: f.name.value.trim(), cert_pem: f.cert._get(), key_pem: f.key._get(),
                        key_password: f.pass.value || undefined, chain_pem: f.chain._get() || undefined}).then(function (d) {
      toast(said(d, 'imported'), 'good');
      closeModal();
      loadCas();
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}
function signCsr(ca) {
  /* Which authority signs is chosen here - the default one first. */
  casNow(true).catch(function () { return CAS; }).then(function () { signCsrForm(ca); });
}
function signCsrForm(ca) {
  var f = {};
  var signers = CAS.filter(caSigns);
  var pick = ca || defaultOf(signers) || signers[0] || null;
  if (!pick) { toast('No authority can sign yet: create one first', 'bad'); return; }
  var caOf = function () { return CAS.filter(function (x) { return String(x.id) === String(f.ca ? f.ca.value : pick.id); })[0] || pick; };
  modal('Sign a CSR', function (body) {
    body.appendChild(el('p', 'note', 'A request made elsewhere - by a device, another server, a person - signed by this authority. The certificate is shown at once; it is kept in what this authority signed, not as a certificate acme renews.'));
    var cg = el('div', 'formgrid');
    f.ca = selectBox(caPairs(signers.length ? signers : [pick]), String(pick.id));
    noI18n(f.ca);
    cg.appendChild(formField('Signed by', f.ca, 'The default authority comes first (the star on Authorities).'));
    body.appendChild(cg);
    f.csr = pemBox('', '-----BEGIN CERTIFICATE REQUEST-----', 8);
    body.appendChild(wideField('The CSR', f.csr));
    var g = el('div', 'formgrid');
    f.days = numberBox(pick.days_default || 397, '397', 1, 36500);
    f.ca.addEventListener('change', function () { var c = caOf(); if (c && c.days_default) f.days.value = c.days_default; });
    g.appendChild(formField('Valid for (days)', f.days));
    var ek = el('div', 'ct-ekus');
    f.eku = {};
    EKUS.forEach(function (e, i) {
      var lab = el('label', 'set-check');
      var cb = el('input');
      cb.type = 'checkbox';
      cb.checked = i === 0;
      f.eku[e[0]] = cb;
      lab.appendChild(cb);
      lab.appendChild(el('span', '', e[1]));
      ek.appendChild(lab);
    });
    g.appendChild(formField('Used for', ek));
    body.appendChild(g);
    f.out = el('div');
    body.appendChild(f.out);
  }, [{words: 'Close', close: true}, {words: 'Sign it', cls: 'primary', icon: 'key', go: function (b) {
    if (!f.csr._get()) { toast('paste the CSR', 'bad'); return; }
    busy(b, true);
    capi('cas/sign_csr', {id: caOf().id, csr_pem: f.csr._get(), days: Number(f.days.value || 397),
                          eku: Object.keys(f.eku).filter(function (k) { return f.eku[k].checked; })}).then(function (d) {
      var pem = d.cert_pem || d.certificate || '';
      var chain = d.chain_pem || '';
      clear(f.out);
      f.out.appendChild(el('h4', 'ct-formh', 'The certificate'));
      var ta = areaBox(pem + (chain ? '\n' + chain : ''), '', 8, 'mono ct-csr');
      ta.readOnly = true;
      noI18n(ta);
      f.out.appendChild(ta);
      var row = el('div', 'btnrow');
      var cp = cmdButton('Copy', 'copy', 'small');
      cp.onclick = function () { copyText(ta.value, cp, 'the certificate was copied'); };
      var dl = cmdButton('Download', 'download', 'small');
      dl.onclick = function () { saveText((d.serial || 'certificate') + '.crt', ta.value, 'application/x-pem-file'); };
      row.appendChild(cp);
      row.appendChild(dl);
      f.out.appendChild(row);
      toast(said(d, 'signed'), 'good');
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}

/* ==========================================================================
   Jobs
   ========================================================================== */
var JL = {page: 0, total: 0, rows: [], timer: null, certsFilled: false};
function jobTable(rows, o) {
  o = o || {};
  var heads = ['When', 'What'];
  if (!o.noCert) heads.push('Certificate');
  heads = heads.concat(['Target', 'State', {words: 'Took', cls: 'num'}, 'By', 'Said']);
  return listTable(heads, rows, function (j) {
    var tr = el('tr');
    if (jobState(j) === 'failed') tr.classList.add('ct-hot');
    tr.appendChild(stampCell(j.ts || j.started));
    tr.appendChild(td('', JOB_KIND[j.kind] || j.kind || '–'));
    if (!o.noCert) tr.appendChild(td('', data('span', '', first(j.cert_name, j.cert, j.cert_id ? '#' + j.cert_id : '–'))));
    tr.appendChild(td('muted', data('span', '', j.target || '–')));
    tr.appendChild(td('', jobTag(j)));
    tr.appendChild(td('num muted', jobRunning(j) ? span(now() - (j.ts || now())) : tookWords(j.took_ms)));
    var by = td('muted small', '');
    by.appendChild(byWho(j.by_who || 'acme'));
    if (j.node) by.appendChild(data('span', 'ct-node-name', ' · ' + j.node));
    tr.appendChild(by);
    var s = td('ct-jsaid small', '');
    s.appendChild(el('span', '', j.said || ''));
    tr.appendChild(s);
    return rowOpens(tr, function () { over(function () { jobPeek(j.id); }); });
  }, 'plain ct-jobs|No job yet');
}
function jobFilters() {
  var ok = $('jb-ok') ? $('jb-ok').value : '';
  return {kind: $('jb-kind') ? $('jb-kind').value : '', ok: ok === 'running' ? '' : ok,
          state: ok === 'running' ? 'running' : '', cert_id: $('jb-cert') ? $('jb-cert').value : '',
          per: $('jb-per') ? Number($('jb-per').value || 50) : 50};
}
function fillJobCerts() {
  var sel = $('jb-cert');
  if (!sel || JL.certsFilled) return;
  JL.certsFilled = true;
  capi('certs' + qs({per: 1000})).then(function (d) {
    var keep = sel.value;
    while (sel.options.length > 1) sel.remove(1);
    rowsOf(d, 'certs').forEach(function (c) {
      var o = el('option', '', c.name);
      o.value = String(c.id);
      noI18n(o);
      sel.appendChild(o);
    });
    sel.value = keep;
  }).catch(function () { JL.certsFilled = false; });
}
function loadJobs(live) {
  var host = $('jb-table');
  if (!host) return;
  fillJobCerts();
  var f = jobFilters();
  if (!live && !host.children.length) host.appendChild(el('p', 'muted', 'Asking…'));
  apiLatest('ct-jobs', apiName('certs/jobs') + '&' + qs({kind: f.kind, ok: f.ok, state: f.state, cert_id: f.cert_id,
                                                         page: JL.page + 1, per: f.per}).slice(1)).then(function (d) {
    var rows = rowsOf(d, 'jobs');
    if (f.state === 'running') rows = rows.filter(jobRunning);
    JL.rows = rows;
    JL.total = Number(first(d.total, rows.length));
    var running = rows.filter(jobRunning).length;
    $('jb-said').textContent = num(JL.total) + ' job(s)' + (running ? ' · ' + running + ' running' : '');
    tabCount('tabn-jobs', running, false);
    liveFill(host, function (box) { box.appendChild(jobTable(rows)); }, live);
    pager('jb-pager', JL.page, f.per, JL.total, function (p) { JL.page = p; loadJobs(); });
    explainWhatWasDrawn(host);
    clearTimeout(JL.timer);
    if (running && TAB === 'jobs') JL.timer = setTimeout(function () { if (TAB === 'jobs' && !document.hidden) liveRun(function () { loadJobs(true); }); }, 2500);
  }).catch(function (e) {
    if (e && e.stopped) return;
    $('jb-said').textContent = '';
    clear($('jb-pager'));
    failInto(host, 'the jobs')(e);
  });
}
var LEVEL = {ok: 'ok', good: 'ok', info: 'info', warn: 'warn', warning: 'warn', bad: 'bad', error: 'bad', fail: 'bad', debug: 'debug'};
function stepOf(s) {
  if (Array.isArray(s)) return {t: s[0], level: s[1], words: s[2], detail: s[3]};
  if (s && typeof s === 'object') return {t: first(s.t, s.ts, s.at, s.time), level: s.level || s.kind || 'info',
                                          words: first(s.words, s.text, s.msg, s.message, ''), detail: s.detail};
  return {t: null, level: 'info', words: String(s)};
}
function jobLog(steps, startedAt) {
  /* The words of each step are the daemon's, in English, and translated as
     every other text of the page is; what a machine answered (the detail)
     stays as it was said. */
  var box = el('div', 'ct-log');
  steps = Array.isArray(steps) ? steps : arr(steps);
  if (!steps.length) { box.appendChild(el('div', 'muted', 'No step yet.')); return box; }
  steps.forEach(function (raw) {
    var s = stepOf(raw);
    var line = el('div', 'ct-log-l ' + (LEVEL[s.level] || 'info'));
    var when = '';
    if (s.t) {
      var t = Number(s.t);
      when = t > 1e9 ? clockWords(new Date(t * 1000)) : ('+' + (t >= 100 ? Math.round(t) : (Math.round(t * 10) / 10)) + ' s');
    }
    line.appendChild(el('b', '', when));
    var mark = el('i', '', {ok: '✓', bad: '✗', warn: '!', info: '·', debug: '·'}[LEVEL[s.level] || 'info']);
    line.appendChild(mark);
    /* What a machine printed (a script's output, several lines): shown as it was said. */
    var sw = el('span', '', String(s.words));
    if (String(s.words).indexOf('\n') >= 0) { noI18n(sw); sw.classList.add('mono', 'ct-log-out'); }
    line.appendChild(sw);
    box.appendChild(line);
    if (s.detail) {
      var det = el('div', 'ct-log-d');
      det.textContent = String(s.detail);
      noI18n(det);
      box.appendChild(det);
    }
  });
  return box;
}
var JOB_POLL = null;
function jobPeek(id) {
  clearTimeout(JOB_POLL);
  var ticket = null, logHost = null, factsHost = null, drewDone = null;
  var draw = function (j) {
    var running = jobRunning(j);
    var buttons = [{words: 'Close', close: true}];
    if (j.cert_id) buttons.unshift({words: 'The certificate', icon: 'cert', left: true, go: function () { over(function () { certPeek(j.cert_id); }); }});
    if (running && MANAGE) buttons.push({words: 'Stop it', icon: 'cancel', go: function (b) {
      busy(b, true);
      capi('certs/job_stop', {id: j.id}).then(function (x) { toast(said(x, 'asked to stop'), 'good'); poll(true); }).catch(fail).then(function () { busy(b, false); });
    }});
    if (!running && MANAGE && j.cert_id && (j.kind === 'renew' || j.kind === 'issue') && jobState(j) === 'failed')
      buttons.push({words: 'Try again', cls: 'primary', icon: 'refresh', go: function (b) { certRenew({id: j.cert_id}, b); }});
    if (!running && MANAGE && j.deploy_id && j.kind === 'deploy' && jobState(j) === 'failed')
      buttons.push({words: 'Try again', cls: 'primary', icon: 'refresh', go: function (b) {
        busy(b, true);
        capi('deploys/run', {id: j.deploy_id}).then(function (x) { jobStarted(x, 'deploying'); }).catch(fail).then(function () { busy(b, false); });
      }});
    var title = (JOB_KIND[j.kind] || j.kind || 'Job') + ' #' + j.id;
    modal(title, function (body) {
      factsHost = el('div');
      body.appendChild(factsHost);
      paintFacts(j);
      logHost = el('div', 'ct-loghost');
      body.appendChild(logHost);
      logHost.appendChild(jobLog(j.steps, j.ts));
    }, buttons, 'medium');
    ticket = modalTicket();
    drewDone = !running;
    scrollLog(true);
  };
  var paintFacts = function (j) {
    clear(factsHost);
    var st = el('span');
    st.appendChild(jobTag(j));
    factsHost.appendChild(factsRow([
      ['What', JOB_KIND[j.kind] || j.kind || '–'],
      ['Certificate', data('span', '', first(j.cert_name, j.cert, j.cert_id ? '#' + j.cert_id : '–'))],
      j.target ? ['Target', data('span', '', j.target)] : null,
      ['State', st],
      ['Started', stamp(j.ts)],
      ['Took', jobRunning(j) ? span(now() - (j.ts || now())) + ' so far' : tookWords(j.took_ms)],
      ['By', (function () {
        var w = el('span', '');
        w.appendChild(byWho(j.by_who || 'acme'));
        if (j.node) w.appendChild(data('span', 'ct-node-name', ' · ' + j.node));
        return w;
      }())]
    ]));
    if (j.said && !jobRunning(j)) {
      var s = el('div', 'ct-jobsaid ' + (jobState(j) === 'ok' ? 'good' : (jobState(j) === 'failed' ? 'bad' : '')));
      s.textContent = String(j.said);
      factsHost.appendChild(s);
    }
  };
  var scrollLog = function (force) {
    var box = logHost && logHost.querySelector('.ct-log');
    if (!box) return;
    if (force || box._atEnd !== false) box.scrollTop = box.scrollHeight;
    box.onscroll = function () { box._atEnd = box.scrollTop + box.clientHeight >= box.scrollHeight - 12; };
  };
  var poll = function (soon) {
    clearTimeout(JOB_POLL);
    JOB_POLL = setTimeout(function () {
      if (!ticket || !modalStill(ticket)) return;
      capi('certs/job' + qs({id: id})).then(function (d) {
        if (!modalStill(ticket)) return;
        var j = d.job || d;
        if (!jobRunning(j) && !drewDone) { draw(j); CT.refresh(); return; }
        var old = logHost.querySelector('.ct-log');
        var atEnd = !old || old._atEnd !== false;
        var keep = old ? old.scrollTop : 0;
        clear(logHost);
        logHost.appendChild(jobLog(j.steps, j.ts));
        var nb = logHost.querySelector('.ct-log');
        if (atEnd) nb.scrollTop = nb.scrollHeight; else { nb.scrollTop = keep; nb._atEnd = false; }
        scrollLog(false);
        paintFacts(j);
        if (jobRunning(j)) poll();
      }).catch(function () { if (modalStill(ticket)) poll(); });
    }, soon ? 300 : 1500);
  };
  modal('A job', function (b) { b.appendChild(el('p', 'center muted', 'Asking…')); }, [{words: 'Close', close: true}], 'medium');
  var first0 = modalTicket();
  capi('certs/job' + qs({id: id})).then(function (d) {
    if (!modalStill(first0)) return;
    var j = d.job || d;
    draw(j);
    if (jobRunning(j)) poll();
  }).catch(function (e) {
    if (!modalStill(first0)) return;
    var b = $('modal-body');
    clear(b);
    b.appendChild(failedBox(e, 'the jobs'));
  });
}

/* ==========================================================================
   The Overview's part
   ========================================================================== */
var OV = {d: null};
function tabCount(id, n, hot) {
  var c = $(id);
  if (!c) return;
  c.textContent = n ? num(n) : '';
  c.classList.toggle('hot', !!hot);
}
function loadOverviewCerts(live) {
  var host = $('ov-certs');
  if (!host) return;
  capi('certs/overview').then(function (d) {
    OV.d = d;
    var counts = d.by_state || d.counts || {};
    var total = Number(first(d.total, Object.keys(counts).reduce(function (a, k) { return a + Number(counts[k] || 0); }, 0)));
    var bad = Number(counts.failed || 0) + Number(first(d.expired, counts.expired, 0));
    tabCount('tabn-certs', total, bad > 0);
    liveFill(host, function (box) { drawOverviewCerts(box, d, counts, total); }, live, function () {
      drawExpiryChart($('ov-ct-chart'), d);
    });
    explainWhatWasDrawn(host);
  }).catch(function (e) {
    if (e && e.missing) {
      liveFill(host, function (box) {
        var card = el('div', 'card full ct-ovcard');
        card.appendChild(el('h2', '', 'Certificates'));
        card.appendChild(missingBox('the certificates'));
        box.appendChild(card);
      }, live);
      return;
    }
    failInto(host, 'the certificates')(e);
  });
}
function drawOverviewCerts(box, d, counts, total) {
  var c = function (k) { return Number(counts[k] || 0); };
  var days = Number(first(d.notify_days, 14));
  var expired = Number(first(d.expired, c('expired')));
  var soon = Number(first(d.expiring, 0));
  var depBad = Number(first(d.deploys_failed, 0));
  var failing = c('failed') + depBad;
  var tiles = [
    ['Certificates', total, 'info', total ? num(c('ok')) + ' valid' + (c('due') + c('renewing') ? ' · ' + num(c('due') + c('renewing')) + ' being renewed' : '') : 'none yet', ''],
    ['Running out soon', soon, soon ? 'warn' : 'ok', 'within ' + days + ' days', 'expiring'],
    ['Failing', failing, failing ? 'crit' : 'ok', failing ? num(c('failed')) + ' renewal(s) · ' + num(depBad) + ' deployment(s)' : 'nothing failing', 'failed'],
    ['Expired', expired, expired ? 'crit' : 'ok', expired ? 'no longer valid' : 'none', 'expired']
  ];
  if (c('pending')) tiles.push(['Waiting for a CA', c('pending'), 'info', 'a CSR given out', 'pending']);
  /* As in otp: these are the first row of the overview, in front of isemon's
     tile (#ov-row1) - each opens what it counts, with the arrow and the words
     otp's tiles have. Without that row (an older page) they go on top here. */
  var row1 = $('ov-row1');
  var grid = row1 || el('div', 'grid top ct-ovtiles');
  if (row1) Array.prototype.slice.call(row1.querySelectorAll('.ct-ovtile')).forEach(function (n) { n.remove(); });
  var anchor = row1 ? $('card-isemon') : null;
  var says = {'': 'Every certificate acme keeps: how many are valid and how many are being renewed.',
              expiring: 'The certificates that end within ' + days + ' days.',
              failed: 'What failed: renewals, and deployments to the targets.',
              expired: 'The certificates that are no longer valid.',
              pending: 'Requests (CSRs) given out to a CA acme does not speak to, waiting for its certificate.'};
  tiles.forEach(function (t) {
    var card = el('div', 'card metric tappable ct-ovtile ' + t[2]);
    card.tabIndex = 0;
    card.setAttribute('role', 'button');
    card.appendChild(el('div', 'label', t[0]));
    card.appendChild(el('div', 'value', num(t[1])));
    card.appendChild(el('div', 'sub', t[3]));
    var arrow = el('span', 'goes');
    arrow.innerHTML = iconMarkup('next', 16);
    card.appendChild(arrow);
    if (says[t[4]] && typeof explain === 'function') explain(card, says[t[4]]);
    var open = function () {
      if (t[4] === 'failed' && !c('failed') && depBad) { openJobs({kind: 'deploy', ok: '0'}); return; }
      openCerts({state: t[4]});
    };
    card.onclick = open;
    card.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); open(); } };
    if (anchor) grid.insertBefore(card, anchor); else grid.appendChild(card);
  });
  if (!row1) box.appendChild(grid);
  var ch = el('div', 'card full ct-ovcard');
  var h = el('h2', '', 'When certificates run out');
  var right = el('span', 'right muted', 'the next ' + (rowsOf(d.weeks || d.expiry_by_week || d.by_week).length || 26) + ' weeks');
  h.appendChild(right);
  ch.appendChild(h);
  ch.appendChild(el('p', 'note', 'How many certificates end in each week ahead. Those that renew by themselves will be renewed before - a red bar of certificates renewed by hand is the one to look at.'));
  var chart = el('div', 'chart ct-chart');
  chart.id = 'ov-ct-chart';
  chart.appendChild(el('div', 'empty', '…'));
  chart.appendChild(el('div', 'tip'));
  ch.appendChild(chart);
  var lg = el('div', 'legend');
  [['crit', 'within 2 weeks'], ['warn', 'within 6 weeks'], ['info', 'later'], ['dim', 'renewed by hand']].forEach(function (x) {
    var s = el('span');
    var i = el('i', 'ct-lg ' + x[0]);
    s.appendChild(i);
    s.appendChild(document.createTextNode(x[1]));
    lg.appendChild(s);
  });
  ch.appendChild(lg);
  box.appendChild(ch);
  var halves = el('div', 'grid halves ct-ovhalves');
  /* what runs out soonest */
  var s1 = el('div', 'card ct-ovcard');
  s1.appendChild(el('h2', '', 'Running out soonest'));
  var soon = rowsOf(d.soonest || d.expiring || d.next);
  if (!soon.length) s1.appendChild(el('p', 'muted small', 'Nothing to run out.'));
  else {
    var l1 = el('div', 'ct-ovlist');
    soon.slice(0, 8).forEach(function (r) {
      var row = el('div', 'ct-ovrow tappable');
      row.tabIndex = 0;
      var w = el('div', 'ct-ovrow-w');
      w.appendChild(data('b', '', r.name));
      var sub = el('span', 'muted small ct-whowhen');
      sub.appendChild(data('span', '', r.issuer || ''));
      if (r.auto_renew !== undefined && !truthy(r.auto_renew)) sub.appendChild(el('span', '', 'by hand'));
      w.appendChild(sub);
      row.appendChild(w);
      var right1 = el('div', 'ct-ovrow-r');
      right1.appendChild(stateTag(r.state));
      right1.appendChild(daysTag(r.not_after, r.renew_days));
      row.appendChild(right1);
      row.onclick = function () { certPeek(r.id); };
      row.onkeydown = function (e) { if (e.key === 'Enter') certPeek(r.id); };
      l1.appendChild(row);
    });
    s1.appendChild(l1);
  }
  halves.appendChild(s1);
  /* what needs a look: the daemon's own alerts */
  var s2 = el('div', 'card ct-ovcard');
  var fails = rowsOf(d.alerts || d.failures);
  var h2 = el('h2', '', 'What needs a look');
  if (fails.length) h2.appendChild(el('span', 'right tag ' + (fails.some(function (a) { return a.level === 'bad'; }) ? 'crit' : 'warn'), num(fails.length)));
  s2.appendChild(h2);
  if (!fails.length) {
    var okb = el('div', 'ct-allgood');
    okb.innerHTML = iconMarkup('check', 20);
    okb.appendChild(el('span', '', 'Nothing is failing: every renewal and deployment went well.'));
    s2.appendChild(okb);
  } else {
    var l2 = el('div', 'ct-ovlist');
    fails.slice(0, 8).forEach(function (a) {
      var key = String(a.key || '');
      var m = /^cert-(\w+):(\d+)$/.exec(key);
      var row = el('div', 'ct-ovrow tappable ' + (a.level === 'bad' ? 'bad' : 'warn'));
      row.tabIndex = 0;
      var w = el('div', 'ct-ovrow-w');
      w.appendChild(data('span', 'ct-alert', String(a.words || a.said || key)));
      row.appendChild(w);
      var rr = el('div', 'ct-ovrow-r');
      var kind = m ? m[1] : '';
      rr.appendChild(el('span', 'tag ' + (a.level === 'bad' ? 'crit' : 'warn'),
        {failed: 'renewal', expired: 'has expired', expiring: 'by hand', deploy: 'deployment'}[kind] || (a.level === 'bad' ? 'failing' : 'warning')));
      row.appendChild(rr);
      var open = function () {
        if (m && kind !== 'deploy') certPeek(Number(m[2]));
        else openJobs({kind: 'deploy', ok: '0'});
      };
      row.onclick = open;
      row.onkeydown = function (e) { if (e.key === 'Enter') open(); };
      l2.appendChild(row);
    });
    s2.appendChild(l2);
  }
  halves.appendChild(s2);
  box.appendChild(halves);
  /* recent jobs */
  var s3 = el('div', 'card full ct-ovcard');
  var h3 = el('h2', '', 'Recent jobs');
  var all = el('span', 'right');
  var ab = cmdButton('All jobs', 'job', 'small');
  ab.onclick = function () { showTab('jobs'); };
  all.appendChild(ab);
  h3.appendChild(all);
  s3.appendChild(h3);
  s3.appendChild(jobTable(rowsOf(d.jobs || d.recent_jobs).slice(0, 8)));
  box.appendChild(s3);
}
function openJobs(f) {
  showTab('jobs');
  setTimeout(function () {
    if ($('jb-kind')) $('jb-kind').value = f.kind || '';
    if ($('jb-ok')) $('jb-ok').value = f.ok || '';
    JL.page = 0;
    loadJobs();
  }, 0);
}
function openCerts(f) {
  showTab('certs');
  setTimeout(function () {
    if ($('ct-state')) {
      if (f.state && !$('ct-state').querySelector('option[value="' + f.state + '"]')) {
        var o = el('option', '', f.state === 'expiring' ? 'running out soon' : f.state);
        o.value = f.state;
        $('ct-state').appendChild(o);
      }
      $('ct-state').value = f.state || '';
    }
    CL.page = 0;
    loadCerts();
  }, 0);
}
function drawExpiryChart(host, d) {
  if (!host) return;
  var tip = host.querySelector('.tip') || el('div', 'tip');
  clear(host);
  host.appendChild(tip);
  var weeks = rowsOf(d.weeks || d.expiry_by_week || d.by_week).map(function (w) {
    if (Array.isArray(w)) return {t: w[0], n: w[1] || 0};
    return {t: Number(first(w.t, w.week, w.start, w.from, 0)), n: Number(first(w.n, w.count, w.total, 0)),
            manual: Number(first(w.manual, w.by_hand, 0)), certs: rowsOf(w.certs || w.names)};
  });
  if (!weeks.length) { host.appendChild(el('div', 'empty', 'Nothing runs out in the weeks ahead')); return; }
  var W = host.clientWidth || 700, H = host.clientHeight || 230;
  var padL = 40, padR = 12, padT = 12, padB = 26;
  var h = Math.max(10, H - padT - padB);
  var top = Math.max(1, weeks.reduce(function (m, p) { return Math.max(m, p.n); }, 0));
  var unit = Math.max(1, Math.ceil(top / 4));
  var mag = Math.pow(10, Math.floor(Math.log(unit) / Math.LN10));
  unit = [1, 2, 5, 10].map(function (x) { return x * mag; }).filter(function (x) { return x >= unit; })[0] || unit;
  var ceil = unit * 4;
  padL = Math.max(40, 16 + 7 * String(num(ceil)).length);
  var w = Math.max(10, W - padL - padR);
  var NS = 'http://www.w3.org/2000/svg';
  var svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
  svg.setAttribute('preserveAspectRatio', 'none');
  var make = function (kind, attrs) {
    var n = document.createElementNS(NS, kind);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) n.setAttribute(k, attrs[k]);
    return n;
  };
  var line = cssVar('--line', '#262c37'), mut = cssVar('--tx-mut', '#5b6472');
  var col = {crit: cssVar('--crit', '#f85149'), warn: cssVar('--warn', '#d29922'), info: cssVar('--info', '#58a6ff'),
             dim: cssVar('--tx-mut', '#5b6472')};
  for (var g = 0; g <= 4; g++) {
    var y = padT + h - (h * g / 4);
    svg.appendChild(make('line', {x1: padL, x2: W - padR, y1: y, y2: y, stroke: line, 'stroke-width': 1}));
    var label = make('text', {x: padL - 8, y: y + 4, fill: mut, 'font-size': 11, 'text-anchor': 'end'});
    label.textContent = num(unit * g);
    svg.appendChild(label);
  }
  var step = w / weeks.length;
  var barW = Math.max(2, Math.min(28, step * 0.62));
  var t0 = now();
  weeks.forEach(function (p, i) {
    if (!p.n) return;
    var x = padL + step * i + (step - barW) / 2;
    var days = (p.t - t0) / 86400;
    var tone = days < 14 ? 'crit' : (days < 42 ? 'warn' : 'info');
    var auto = Math.max(0, p.n - (p.manual || 0));
    var bh = auto ? Math.max(2, h * (auto / ceil)) : 0;
    if (auto) svg.appendChild(make('rect', {x: x, y: padT + h - bh, width: barW, height: bh, fill: col[tone], rx: 2, opacity: 0.88}));
    if (p.manual) {
      var mh = Math.max(2, h * (p.manual / ceil));
      var base = padT + h - (auto ? bh + 1 : 0);
      svg.appendChild(make('rect', {x: x, y: base - mh, width: barW, height: mh,
                                    fill: tone === 'crit' ? col.crit : col.dim, rx: 2, opacity: 0.6}));
    }
  });
  var every = Math.max(1, Math.ceil(weeks.length / Math.max(3, Math.floor(w / 64))));
  weeks.forEach(function (p, i) {
    if (i % every) return;
    var dd = new Date(p.t * 1000);
    var t = make('text', {x: padL + step * i + step / 2, y: H - 8, fill: mut, 'font-size': 11, 'text-anchor': 'middle'});
    t.textContent = pad2(dd.getDate()) + '-' + pad2(dd.getMonth() + 1);
    svg.appendChild(t);
  });
  weeks.forEach(function (p, i) {
    var hit = make('rect', {x: padL + step * i, y: padT, width: step, height: h, fill: 'transparent'});
    hit.style.cursor = p.n ? 'pointer' : 'default';
    if (p.n) hit.addEventListener('click', function () {
      if (p.certs && p.certs.length && typeof p.certs[0] === 'object') weekPeek(p);
      else openCerts({});
    });
    hit.addEventListener('mousemove', function (e) {
      var box = host.getBoundingClientRect();
      var end = new Date((p.t + 6 * 86400) * 1000);
      tip.innerHTML = '';
      tip.appendChild(el('b', '', dayWords(new Date(p.t * 1000)) + ' – ' + dayWords(end)));
      tip.appendChild(el('br'));
      tip.appendChild(el('span', '', p.n ? (p.n === 1 ? '1 certificate ends' : p.n + ' certificates end') : 'nothing ends'));
      if (p.manual) { tip.appendChild(el('br')); tip.appendChild(el('span', 'ct-tipwarn', p.manual + ' renewed by hand')); }
      (p.certs || []).slice(0, 6).forEach(function (c) {
        tip.appendChild(el('br'));
        tip.appendChild(data('span', 'muted', typeof c === 'object' ? c.name : String(c)));
      });
      tip.style.display = 'block';
      var left = e.clientX - box.left + 12;
      if (left + tip.offsetWidth > box.width) left = e.clientX - box.left - tip.offsetWidth - 12;
      tip.style.left = Math.max(0, left) + 'px';
      tip.style.top = Math.max(0, e.clientY - box.top - 12) + 'px';
    });
    hit.addEventListener('mouseleave', function () { tip.style.display = 'none'; });
    svg.appendChild(hit);
  });
  host.appendChild(svg);
}
function weekPeek(p) {
  var end = new Date((p.t + 6 * 86400) * 1000);
  modal('Ending ' + dayWords(new Date(p.t * 1000)) + ' – ' + dayWords(end), function (body) {
    body.appendChild(listTable(['State', 'Name', 'Expires'], p.certs, function (c) {
      var tr = el('tr');
      tr.appendChild(td('', stateTag(c.state)));
      tr.appendChild(td('', data('b', '', c.name)));
      tr.appendChild(td('', daysTag(c.not_after, c.renew_days)));
      return rowOpens(tr, function () { over(function () { certPeek(c.id); }); });
    }, 'plain'));
  }, [{words: 'Close', close: true}], 'narrow');
}

/* ==========================================================================
   Settings: Renewal and notices, DNS server
   ========================================================================== */
var DNS = {d: null};
var RTYPES = ['TXT', 'A', 'AAAA', 'CNAME', 'NS', 'CAA', 'MX', 'SRV', 'PTR'];
function loadDns(live) {
  var st = $('dns-state'), host = $('dns-table');
  if (!st || !host) return;
  capi('dns').then(function (d) {
    DNS.d = d;
    liveFill(st, function (box) { drawDnsState(box, d); }, live);
    drawDnsRecords(live);
    explainWhatWasDrawn(st.parentNode);
  }).catch(function (e) {
    failInto(st, 'its own DNS server')(e);
    clear(host);
    $('dns-said').textContent = '';
  });
}
function drawDnsState(box, d) {
  var sv = obj(d.server), set = obj(d.settings);
  var listen = arr(first(sv.listening && arr(sv.listening).length ? sv.listening : null, sv.listen, set.dns_listen, d.listen));
  var enabled = set.dns_server === undefined ? (d.enabled === undefined || truthy(d.enabled)) : truthy(set.dns_server);
  var running = sv.running === undefined ? !!listen.length : !!sv.running;
  var good = sv.ok === undefined ? running : !!sv.ok;
  var h = el('h2', '', 'The server');
  var pill = el('span', 'pill ' + (!enabled ? 'unknown' : (good ? 'ok' : (running ? 'warn' : 'crit'))) + ' ct-dnspill');
  pill.appendChild(el('span', 'dot'));
  pill.appendChild(el('span', '', !enabled ? 'switched off' : (good ? 'answering' : (running ? 'answering, with trouble' : 'not listening'))));
  if (sv.said) explain(pill, String(sv.said));
  var right = el('span', 'right');
  right.appendChild(pill);
  h.appendChild(right);
  box.appendChild(h);
  var ns = arr(first(arr(sv.ns).length ? sv.ns : null, set.dns_ns_names, d.ns));
  var zone = first(d.zone, arr(sv.zones)[0], set.dns_zone, '');
  d.zone = zone;
  box.appendChild(factsRow([
    ['Zone', zone ? mono(String(zone)) : 'not set'],
    ['Name servers', ns.length ? mono(ns.join(', ')) : '–'],
    ['Listens on', listen.length ? mono(listen.join(', ') + (sv.port && String(listen.join('')).indexOf(':') < 0 ? ' · ' + sv.port : '')) : '–'],
    ['Records', num(rowsOf(d.records).length)],
    sv.queries !== undefined ? ['Answered', num(Number(sv.queries))] : null,
    sv.started ? ['Up since', ago(sv.started)] : null
  ]));
  rowsOf(sv.failed).forEach(function (f) {
    box.appendChild(data('div', 'ct-errbox', String(f.words || f.error || f.said || JSON.stringify(f))));
  });
  rowsOf(sv.problems).forEach(function (p) { box.appendChild(data('div', 'ct-warnline', String(p))); });
  if (sv.records_error) box.appendChild(data('div', 'ct-errbox', String(sv.records_error)));
  if (sv.last_error) box.appendChild(data('div', 'ct-warnline', String(sv.last_error) + (sv.last_error_at ? ' · ' + ago(sv.last_error_at) : '')));
  if (d.installed === false) box.appendChild(el('p', 'ct-bad', 'The DNS server is not installed with this version of acme.'));
  if (!enabled) box.appendChild(el('p', 'note', 'It is switched off: switch it on below, with the zone it answers for.'));
  d.ns = ns;
  d.ns_addresses = arr(set.dns_ns_addresses);
  if (d.error) box.appendChild(data('div', 'ct-errbox', String(d.error)));
  if (d.zone) {
    var g = el('div', 'ct-guide');
    g.appendChild(el('b', 'small', 'In your DNS'));
    g.appendChild(el('p', 'muted small', 'Delegate the zone to acme with an NS record (and an address for each name server, if it is inside the zone), then point the challenge name of every certificate name at it:'));
    var lines = arr(d.delegation);
    if (!lines.length) {
      var parent = String(d.zone).replace(/^[^.]+\./, '');
      ns.forEach(function (n) { lines.push(d.zone + '.  IN NS  ' + n + '.'); });
      arr(d.ns_addresses || d.glue).forEach(function (a, i) {
        var n = ns[i] || ns[0];
        if (n && /^[0-9.]+$/.test(a)) lines.push(n + '.  IN A  ' + a);
        else if (n && /:/.test(a)) lines.push(n + '.  IN AAAA  ' + a);
      });
      lines.push('_acme-challenge.www.example.com.  IN CNAME  www.example.com.' + d.zone + '.');
      if (parent && !ns.length) lines.push('; ' + parent);
    }
    var pre = el('pre', 'lines ct-dnslines');
    pre.textContent = lines.join('\n');
    noI18n(pre);
    g.appendChild(pre);
    var cp = cmdButton('Copy', 'copy', 'small');
    cp.onclick = function () { copyText(pre.textContent, cp, 'copied'); };
    g.appendChild(cp);
    box.appendChild(g);
  } else {
    box.appendChild(el('p', 'note', 'No zone is set yet: set it below, and the NS names this server is known by.'));
  }
}
function drawDnsRecords(live) {
  var host = $('dns-table');
  var all = rowsOf(DNS.d && (DNS.d.records || DNS.d.rows));
  var q = $('dns-q') ? $('dns-q').value.trim().toLowerCase() : '';
  var rows = all.filter(function (r) {
    return !q || (r.name + ' ' + r.rtype + ' ' + r.value + ' ' + (r.note || '') + ' ' + (r.owner || '')).toLowerCase().indexOf(q) >= 0;
  });
  $('dns-said').textContent = all.length ? num(all.length) + ' record(s)' : '';
  liveFill(host, function (box) {
    box.appendChild(listTable(['Name', 'Type', 'Value', {words: 'TTL', cls: 'num'}, 'Goes', 'Put there by', ''], rows, function (r) {
      var tr = el('tr');
      tr.appendChild(td('', mono(r.name)));
      tr.appendChild(td('', data('span', 'tag ' + (String(r.rtype).toUpperCase() === 'TXT' ? 'info' : 'dim'), r.rtype || r.type)));
      var v = td('ct-dnsval', mono(String(r.value || '')));
      tr.appendChild(v);
      tr.appendChild(td('num muted', r.ttl ? String(r.ttl) : '–'));
      var ex = r.expires ? (r.expires > now() ? 'in ' + span(r.expires - now()) : 'now') : 'kept';
      tr.appendChild(td('muted small', ex));
      var by = td('muted small', '');
      by.appendChild(data('span', '', String(r.owner || (r.expires ? 'a job' : 'by hand')).replace(/^admin:/, '')));
      if (r.note) by.appendChild(data('div', '', r.note));
      tr.appendChild(by);
      var tools = el('td', 'rowtools');
      if (FULL) {
        var x = iconButton('trash', 'Take it away');
        x.onclick = function () {
          confirmThen('Take the record away', htmlText(r.name + ' ' + (r.rtype || '') + ' ' + (r.value || '')) + ' is not answered any more.',
            'Take it away', function () {
              capi('dns/record_delete', {id: r.id}).then(function (d) { toast(said(d, 'taken away'), 'good'); loadDns(); }).catch(fail);
            });
        };
        tools.appendChild(x);
      }
      tr.appendChild(tools);
      return tr;
    }, 'plain ct-dnstable|No record yet'));
  }, live);
}
function dnsAdd() {
  var f = {};
  var zone = (DNS.d && DNS.d.zone) || '';
  modal('A record of your own', function (body) {
    body.appendChild(el('p', 'note', 'Answered by acme’s DNS server as long as it is here. The whole name, or @ for the zone itself' + (zone ? ' (' + zone + ')' : '') + '.'));
    var g = el('div', 'formgrid');
    f.name = textBox('', zone ? 'www.' + zone : 'www.acme.example.com', 'mono');
    noI18n(f.name);
    g.appendChild(formField('Name', f.name));
    f.type = selectBox(RTYPES.map(function (t) { return [t, t]; }), 'TXT');
    noI18n(f.type);
    g.appendChild(formField('Type', f.type));
    f.value = textBox('', '"v=spf1 -all" or 192.0.2.10', 'mono');
    noI18n(f.value);
    var vf = formField('Value', f.value);
    vf.classList.add('wide');
    g.appendChild(vf);
    f.ttl = numberBox(300, '300', 0, 86400);
    g.appendChild(formField('TTL (seconds)', f.ttl));
    f.note = textBox('', '', '');
    g.appendChild(formField('Note', f.note));
    body.appendChild(g);
  }, [{words: 'Close', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', go: function (b) {
    if (!f.name.value.trim() || !f.value.value.trim()) { toast('it needs a name and a value', 'bad'); return; }
    busy(b, true);
    capi('dns/record', {name: f.name.value.trim(), rtype: f.type.value, value: f.value.value.trim(),
                        ttl: Number(f.ttl.value || 300), note: f.note.value}).then(function (d) {
      toast(said(d, 'added'), 'good');
      closeModal();
      loadDns();
    }).catch(fail).then(function () { busy(b, false); });
  }}], 'medium');
}
function loadCertSettings() {
  /* The settings themselves are the engine's (sect-certs); here only a word
     on what they apply to, where the overview says it. */
  var box = $('cset-summary');
  if (!box) return;
  capi('certs/overview').then(function (d) {
    var counts = d.counts || d.by_state || {};
    var auto = first(d.auto_renew, d.auto, null);
    clear(box);
    box.appendChild(el('h2', '', 'What these apply to'));
    box.appendChild(factsRow([
      ['Certificates', num(Number(first(d.total, 0)))],
      auto !== null ? ['Renewed by themselves', num(Number(auto))] : null,
      ['Due now', num(Number(counts.due || 0))],
      ['Failing', num(Number(counts.failed || 0))]
    ]));
    box.hidden = false;
  }).catch(function () { box.hidden = true; });
}

/* ==========================================================================
   The tabs and the panes, put into the page
   ========================================================================== */
var MY_TABS = {
  certs: loadCerts, cas: loadCas, jobs: loadJobs,
  sources: function (live) { drawModTab('sources', live); },
  validation: function (live) { drawModTab('validation', live); },
  targets: function (live) { drawModTab('targets', live); }
};
var MY_PANES = {dnssrv: loadDns, certs: loadCertSettings};
var LAST = {};
/* How often a tab is asked again on the live tick, unless the daemon's serial
   moved (something happened): then at the next tick. */
var EVERY = {overview: 30000, certs: 30000, jobs: 10000, cas: 60000, sources: 60000, validation: 60000, targets: 60000};
function drawTab(name, live, moved) {
  var fn = name === 'overview' ? loadOverviewCerts : MY_TABS[name];
  if (!fn) return;
  var t = Date.now();
  var gap = live ? (moved ? 4500 : (EVERY[name] || 30000)) : 350;
  if (LAST[name] && t - LAST[name] < gap) return;
  if (live && name === 'certs' && CL.page > 0 && !moved) return;
  LAST[name] = t;
  try { fn(!!live); } catch (e) { oops(e); }
}
function drawPane(name, live) {
  var fn = MY_PANES[name];
  if (!fn) return;
  var key = 'pane:' + name, t = Date.now();
  if (LAST[key] && t - LAST[key] < (live ? 4000 : 350)) return;
  LAST[key] = t;
  try { fn(!!live); } catch (e) { oops(e); }
}
CT.refresh = function () {
  LAST = {};
  var tab = typeof TAB === 'string' ? TAB : '';
  if (tab === 'overview' || MY_TABS[tab]) liveRun(function () { drawTab(tab, true); });
  if (tab === 'settings' && typeof PANE === 'string' && MY_PANES[PANE]) drawPane(PANE, true);
};
CT.draw = drawTab;
CT.certPeek = certPeek;
CT.jobPeek = jobPeek;
CT.caPeek = caPeek;
CT.deployEdit = deployEdit;
CT.fieldForm = fieldForm;
CT.jobLog = jobLog;
CT.keptSecret = keptSecret;
CT.api = capi;

window.ACME_EXTRA_TABS = window.ACME_EXTRA_TABS || [];
Object.keys(MY_TABS).concat(['overview']).forEach(function (name) {
  if (window.ACME_EXTRA_TABS.some(function (t) { return t && t.name === name && t._certs; })) return;
  window.ACME_EXTRA_TABS.push({name: name, live: true, _certs: true, draw: function (ctx) {
    ctx = ctx || {};
    if (ctx.live) liveRun(function () { drawTab(name, true, !!ctx.moved); });
    else drawTab(name, false);
  }});
});
var PAGE_KNOWS = typeof allTabs === 'function';
window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
Object.keys(MY_PANES).forEach(function (p) {
  if (!window.ACME_EXTRA_PANES[p]) window.ACME_EXTRA_PANES[p] = function () { drawPane(p); };
});

/* A tab of ours shown even where the page does not know it yet. */
function tabHidden(name) {
  var b = document.querySelector('.tabs button[data-tab="' + name + '"]');
  return !b || b.hidden;
}
function showMine(name) {
  TAB = name;
  document.querySelectorAll('.tabs button[data-tab]').forEach(function (b) {
    b.setAttribute('aria-selected', b.getAttribute('data-tab') === name ? 'true' : 'false');
  });
  document.querySelectorAll('section.panel[id^="tab-"]').forEach(function (p) { p.hidden = p.id !== 'tab-' + name; });
  if (typeof writeHash === 'function') { try { writeHash(); } catch (e) { } }
  else { try { history.replaceState(null, '', '#' + name); } catch (e) { } }
  if (typeof holdTheTallOnes === 'function') holdTheTallOnes();
  explainWhatWasDrawn($('tab-' + name));
}
function afterTab() {
  var tab = typeof TAB === 'string' ? TAB : '';
  if (tab === 'overview' || MY_TABS[tab]) drawTab(tab);
}
/* An older page that does not know ACME_EXTRA_TABS: our tabs made to work
   all the same. */
var theirShow = window.optShowTab;
if (!PAGE_KNOWS) window.optShowTab = function (name) {
  if (typeof theirShow === 'function') theirShow.apply(this, arguments);
  if (MY_TABS[name] && TAB !== name && !tabHidden(name)) showMine(name);
  afterTab();
};
if (!PAGE_KNOWS && typeof window.showPane === 'function') {
  var theirPane = window.showPane;
  window.showPane = function (name) {
    var r = theirPane.apply(this, arguments);
    if (typeof PANE === 'string' && MY_PANES[PANE]) drawPane(PANE);
    return r;
  };
}

/* Live, while nobody is working in it - by the page's own tick where it has
   one (ACME_EXTRA_TABS live), else by this. */
if (!PAGE_KNOWS) setInterval(function () {
  if (document.hidden || (typeof LIVE !== 'undefined' && !LIVE)) return;
  if (document.querySelector('.modal:not([hidden])')) return;
  var tab = typeof TAB === 'string' ? TAB : '';
  var here = $('tab-' + tab);
  if (!here || (typeof userHolds === 'function' && userHolds(here)) || (typeof pointerBusy === 'function' && pointerBusy(here))) return;
  if (EVERY[tab] && (!LAST[tab] || Date.now() - LAST[tab] > EVERY[tab])) {
    if (tab === 'certs' && CL.page > 0) return;
    liveRun(function () { drawTab(tab, true); });
  }
  if (tab === 'settings' && typeof PANE === 'string' && PANE === 'dnssrv' && (!LAST['pane:dnssrv'] || Date.now() - LAST['pane:dnssrv'] > 20000)) {
    liveRun(function () { drawPane('dnssrv', true); });
  }
}, 4000);

/* ---- the buttons and filters of the markup ------------------------------- */
function on(id, ev, fn) { var n = $(id); if (n) n.addEventListener(ev, fn); }
on('ct-add', 'click', function () { certWizard(); });
on('ct-import', 'click', function () { importDialog(); });
on('ct-self', 'click', function () { selfSigned(); });
on('ct-csr', 'click', function () { csrDialog(); });
var certsAgain = debounce(function () { CL.page = 0; loadCerts(); }, 250);
on('ct-q', 'input', certsAgain);
['ct-state', 'ct-issuer', 'ct-per', 'ct-owner', 'ct-tag'].forEach(function (id) { on(id, 'change', function () { CL.page = 0; loadCerts(); }); });
['jb-kind', 'jb-ok', 'jb-cert', 'jb-per'].forEach(function (id) { on(id, 'change', function () { JL.page = 0; loadJobs(); }); });
on('ca-root', 'click', function () { caCreate(null); });
on('ca-inter', 'click', function () { caCreate(undefined); });
on('ca-import', 'click', function () { caImport(); });
on('ca-sign', 'click', function () { signCsr(null); });
on('src-add', 'click', function () { modEdit('sources'); });
on('val-add', 'click', function () { modEdit('validation'); });
on('tg-add', 'click', function () { modEdit('targets'); });
on('tg-q', 'input', debounce(function () { drawModTab('targets', true); }, 200));
on('dns-add', 'click', function () { dnsAdd(); });
on('dns-q', 'input', debounce(function () { drawDnsRecords(); }, 150));

/* ---- what this account may not do ----------------------------------------- */
document.querySelectorAll('.ct-manage').forEach(function (n) { if (!MANAGE) n.hidden = true; });
document.querySelectorAll('.ct-fulladmin').forEach(function (n) { if (!FULL) n.hidden = true; });

/* ---- icons of our own on the tabs (drawn before they existed) ------------ */
document.querySelectorAll('[data-cicon]').forEach(function (b) {
  if (!ICONS[b.dataset.cicon]) return;
  var keep = Array.prototype.slice.call(b.querySelectorAll('.count'));
  keep.forEach(function (k) { k.remove(); });
  var words = b.textContent.trim();
  setButtonIcon(b, b.dataset.cicon, words);
  keep.forEach(function (k) { b.appendChild(k); });
});

/* ---- the first draw ------------------------------------------------------- */
function start() {
  if (!PAGE_KNOWS) {
    var want = (location.hash || '').replace(/^#/, '').split('/')[0];
    if (MY_TABS[want] && TAB !== want) showTab(want);
    else afterTab();
    if (typeof TAB === 'string' && TAB === 'settings' && typeof PANE === 'string' && MY_PANES[PANE]) drawPane(PANE);
  }
  /* The count on the tab, on whatever tab the page opens. */
  setTimeout(function () { if (TAB !== 'overview') tabCounts(); }, 300);
}
/** The counts on the tabs Certificates and Jobs - at the start, and after
    every change (afterWrite); on the Overview its own drawing does it. */
function tabCounts() {
  if (TAB === 'overview') { drawTab('overview', true, true); return; }
  capi('certs/overview').then(function (d) {
    var counts = d.by_state || d.counts || {};
    var total = Number(first(d.total, Object.keys(counts).reduce(function (a, k) { return a + Number(counts[k] || 0); }, 0)));
    tabCount('tabn-certs', total, Number(counts.failed || 0) + Number(first(d.expired, counts.expired, 0)) > 0);
    tabCount('tabn-jobs', Number(d.running || 0), false);
  }).catch(function () { });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
else setTimeout(start, 0);

}());
