/* rptemplates.js - Settings → Request profiles → "From a template…" (1.0.140,
   docs/request-profiles.md "From a template"): the built-in templates as cards - a web server,
   a mail server, a VPN gateway, an internal service, a load balancer with a wildcard, code
   signing - each with what it sets, the sources that fit and what the compliance check says.
   One chosen asks a name, the domains and the source, shows the profile it will be (fitted to
   the source and the company's rules) and makes a NORMAL profile - then opened in its editor -
   or opens the editor filled in, nothing saved yet. A template never changes a profile there.
     GET  /api/reqprofiles/templates, POST /api/reqprofiles/template_preview,
     POST /api/reqprofiles/from_template (a full administrator) */
(function () {
'use strict';
if (window.ACME_RP_TPL) return;
var TPL = window.ACME_RP_TPL = {};
var KEY_WORDS = {'ec-256': 'EC P-256', 'ec-384': 'EC P-384', 'rsa-2048': 'RSA 2048', 'rsa-3072': 'RSA 3072',
                 'rsa-4096': 'RSA 4096', ed25519: 'Ed25519'};
var EKU_WORDS = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
                 emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing'};
var TONE = {web: 'info', mail: 'violet', vpn: 'ok', internal: 'warn', wildcard: 'crit', codesign: 'violet'};

if (typeof ICONS === 'object' && !ICONS.rpf_spark) {
  /* a template: a card with a star - something made from a ready start */
  ICONS.rpf_spark = '<rect x="3.5" y="5" width="12.5" height="15" rx="2.2"/><path d="M7 10h5.5M7 13.5h4"/>'
    + '<path d="M18.5 2.8l.9 2.1 2.1.9-2.1.9-.9 2.1-.9-2.1-2.1-.9 2.1-.9z"/>';
}

function tr(s) { try { var t = typeof i18nText === 'function' ? i18nText(String(s)) : null; return t || String(s); } catch (e) { return String(s); } }
function pat(s, a) { return tr(s).replace('{0}', a); }
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function ic(key, size) { var s = el('span', 'rpf-ic'); s.innerHTML = iconMarkup(key, size || 16); return s; }
function chip(words, cls, isData) { var c = (isData ? data : el)('span', 'rpf-chip' + (cls ? ' ' + cls : ''), words); return c; }

/* what a template (or the profile it makes) sets, as chips */
function setsChips(cfg, host, most) {
  var out = [];
  (cfg.eku || []).forEach(function (e) { out.push(chip(EKU_WORDS[e] || e, 'info')); });
  out.push(chip((cfg.key_types || []).map(function (k) { return KEY_WORDS[k] || k; }).join(' · '), 'key', true));
  var n = Number(cfg.max_names || 1);
  out.push(chip(n === 1 ? tr('one name') : pat('up to {0} names', n), ''));
  if (cfg.wildcards) out.push(chip('wildcards', 'warn'));
  if (cfg.make_key === false) out.push(chip('the key stays with the person', 'ok'));
  else if (cfg.csr) out.push(chip('key here or a CSR', ''));
  if (cfg.days) out.push(chip(pat('valid for {0} days', cfg.days), ''));
  out.push(chip(cfg.approval ? 'waits for approval' : 'issued at once', cfg.approval ? 'violet' : ''));
  if (cfg.pfx && cfg.make_key !== false) out.push(chip('PFX with the key', ''));
  out.slice(0, most || out.length).forEach(function (c) { host.appendChild(c); });
  if (most && out.length > most) host.appendChild(data('span', 'rpf-chip more', '+' + (out.length - most)));
}
function badge(t) {
  var b = el('span', 'rpf-badge');
  var st = t.status;
  var words = {ok: t.public ? 'Within the CA/B Forum’s limits' : 'Complies', warn: 'Complies, with warnings',
               bad: 'Does not comply', none: 'No source fits'}[st] || '';
  b.classList.add(st || 'none');
  b.appendChild(ic(st === 'ok' ? 'check' : st === 'none' ? 'ban' : 'info', 13));
  b.appendChild(el('span', '', words));
  return b;
}
function kindBadge(isPublic) {
  var b = el('span', 'rpf-kind ' + (isPublic ? 'pub' : 'own'));
  b.appendChild(ic(isPublic ? 'globe' : 'shield', 13));
  b.appendChild(el('span', '', isPublic ? 'Public CA' : 'Your own CA'));
  return b;
}

/* ---- the button in the pane's bar ------------------------------------------------------------- */
TPL.bar = function (right) {
  var b = cmdButton('From a template…', 'rpf_spark', 'small');
  b.id = 'rp-tpl';
  b.title = tr('A new profile from a ready start: a web server, a mail server, a VPN gateway, an internal service, a wildcard, code signing.');
  b.onclick = function () { TPL.open(); };
  right.appendChild(b);
};

/* ---- the picker -------------------------------------------------------------------------------- */
TPL.open = function () {
  modal('A new profile from a template', function (body) {
    body.classList.add('rpf-dlg');
    body.appendChild(el('div', 'rpf-asking', 'Asking…'));
  }, [{words: 'Close', close: true}], 'large');
  api('reqprofiles/templates').then(function (d) { TPL.d = d; pick(d); }).catch(oops);
};
function pick(d) {
  modal('A new profile from a template', function (body) {
    body.classList.add('rpf-dlg');
    var lede = el('div', 'rpf-lede');
    lede.appendChild(ic('rpf_spark', 22));
    var lw = el('div', '');
    lw.appendChild(el('b', '', 'Start from what most services need'));
    lw.appendChild(el('p', 'muted small', 'A template fills in a new request profile: the key types, what the certificate is used for, how many names, approval - fitted to the source you choose and to the company’s rules. It makes a normal profile you can change as any other; profiles already there stay as they are.'));
    lede.appendChild(lw);
    body.appendChild(lede);
    var grid = el('div', 'rpf-grid');
    grid.setAttribute('role', 'list');
    (d.templates || []).forEach(function (t) { grid.appendChild(card(t)); });
    body.appendChild(grid);
  }, [{words: 'Close', close: true}], 'large');
  var first = document.querySelector('.rpf-card:not([aria-disabled="true"])');
  if (first) setTimeout(function () { try { first.focus(); } catch (e) { } }, 30);
}
function card(t) {
  var off = !t.available;
  var c = el('button', 'rpf-card ' + (TONE[t.id] || 'info') + (off ? ' off' : ''));
  c.type = 'button';
  c.setAttribute('role', 'listitem');
  c.dataset.tpl = t.id;
  if (off) c.setAttribute('aria-disabled', 'true');
  var top = el('span', 'rpf-ctop');
  var tile = el('span', 'rpf-tile');
  tile.innerHTML = iconMarkup(t.icon || 'list', 22);
  top.appendChild(tile);
  var tw = el('span', 'rpf-ctw');
  tw.appendChild(el('b', 'rpf-ct', t.title));
  tw.appendChild(el('span', 'rpf-ca', t.about));
  top.appendChild(tw);
  c.appendChild(top);
  var chips = el('span', 'rpf-chips');
  setsChips(t.cfg || {}, chips, 5);
  c.appendChild(chips);
  var foot = el('span', 'rpf-cfoot');
  foot.appendChild(badge(t));
  if (t.available) {
    foot.appendChild(kindBadge(!!t.public));
    var src = el('span', 'rpf-src');
    src.appendChild(ic('download', 12));
    src.appendChild(data('span', '', t.source || ''));
    foot.appendChild(src);
  } else {
    foot.appendChild(el('span', 'rpf-why', t.needs_own_ca ? 'Needs an authority of acme’s own (Certificates → Sources)' : 'Add a source that can give it (Certificates → Sources)'));
  }
  c.appendChild(foot);
  c.onclick = function () { if (!off) form(t); };
  return c;
}

/* ---- one template: name, domains, source - and the profile it will be ------------------------- */
function form(t, kept) {
  var st = kept || {name: tr(t.name || t.title), suffixes: '', issuer: t.source || '', challenge: ''};
  var f = {}, prev = null, ticket = 0, last = null;
  var opts = (window.ACME_RP && ACME_RP.data && (ACME_RP.data() || {}).options) || {};
  var src = function () { return (t.sources || []).filter(function (s) { return s.name === f.issuer.value; })[0] || {}; };
  var values = function () {
    return {template: t.id, name: f.name.value.trim(), suffixes: f.suffixes.value.split(/[\s,;]+/).filter(Boolean),
            issuer: f.issuer.value, challenge: f.chal && !f.chalRow.hidden ? f.chal.value : ''};
  };
  var ask = debounce(function () {
    var my = ++ticket, v = values();
    var sufs = v.suffixes.length ? v.suffixes : ['example.com'];
    prev.classList.add('busy');
    api('reqprofiles/template_preview', {template: t.id, issuer: v.issuer, challenge: v.challenge, suffixes: sufs, name: v.name})
      .then(function (d) { if (my === ticket) { last = d; drawPreview(d); } })
      .catch(function (e) { if (my === ticket) { last = null; drawError(e); } });
  }, 200);
  var drawPreview = function (d) {
    prev.classList.remove('busy');
    clear(prev);
    var h = el('div', 'rpf-ph');
    h.appendChild(ic('eye', 15));
    h.appendChild(el('span', '', 'The profile it will be'));
    h.appendChild(badge({status: d.status, public: d.public}));
    prev.appendChild(h);
    var chips = el('div', 'rpf-chips');
    setsChips(d.body || {}, chips);
    prev.appendChild(chips);
    if (d.body && d.body.challenge) {
      var v = el('div', 'rpf-pl');
      v.appendChild(el('span', 'muted', 'Names proved by'));
      v.appendChild(data('b', '', d.body.challenge));
      prev.appendChild(v);
    }
    var finds = (d.findings || []).filter(function (x) { return x.level !== 'info'; });
    (d.notes || []).forEach(function (n) { finds.push({level: 'note', said: n}); });
    if (finds.length) {
      var ul = el('ul', 'rpf-finds');
      finds.forEach(function (x) {
        var li = el('li', x.level);
        li.appendChild(ic(x.level === 'bad' ? 'ban' : x.level === 'warn' ? 'info' : 'check', 14));
        li.appendChild(el('span', '', x.said + (x.from ? ' (' + pat('from {0}', x.from) + ')' : '')));
        ul.appendChild(li);
      });
      prev.appendChild(ul);
    } else {
      var ok = el('div', 'rpf-pl ok');
      ok.appendChild(ic('check', 14));
      ok.appendChild(el('span', '', d.public ? 'Within the CA/Browser Forum’s limits and the company’s rules.' : 'Within the company’s rules.'));
      prev.appendChild(ok);
    }
  };
  var drawError = function (e) {
    prev.classList.remove('busy');
    clear(prev);
    var w = el('div', 'rpf-pl bad');
    w.appendChild(ic('ban', 14));
    w.appendChild(data('span', '', (e && e.message) || String(e)));
    prev.appendChild(w);
  };
  modal('A new profile from a template', function (body) {
    body.classList.add('rpf-dlg');
    var back = el('button', 'rpf-back');
    back.type = 'button';
    back.appendChild(ic('prev', 14));
    back.appendChild(el('span', '', 'Every template'));
    back.onclick = function () { pick(TPL.d || {templates: []}); };
    body.appendChild(back);
    var hero = el('div', 'rpf-hero ' + (TONE[t.id] || 'info'));
    var tile = el('span', 'rpf-tile');
    tile.innerHTML = iconMarkup(t.icon || 'list', 26);
    hero.appendChild(tile);
    var hw = el('div', 'rpf-hw');
    hw.appendChild(el('b', '', t.title));
    hw.appendChild(el('p', 'muted small', t.about));
    hero.appendChild(hw);
    body.appendChild(hero);
    var cols = el('div', 'rpf-cols');
    var left = el('div', 'rpf-form');
    var row = function (label, box, says) {
      var r = el('label', 'rpf-row');
      r.appendChild(el('span', 'rpf-lab', label));
      r.appendChild(box);
      if (says) r.appendChild(el('span', 'rpf-says', says));
      left.appendChild(r);
      return r;
    };
    f.name = noI18n(el('input', ''));
    f.name.type = 'text';
    f.name.id = 'rpf-name';
    f.name.value = st.name;
    f.name.maxLength = 120;
    row('Name of the new profile', f.name, 'Shown to people on the portal. A name taken is refused - a template never changes a profile that is there.');
    f.suffixes = noI18n(el('input', 'mono'));
    f.suffixes.type = 'text';
    f.suffixes.id = 'rpf-suffixes';
    f.suffixes.placeholder = 'example.com, example.org';
    f.suffixes.value = st.suffixes;
    row('Under these domains', f.suffixes, 'A name asked for must be one of them or under it.');
    f.issuer = el('select', '');
    f.issuer.id = 'rpf-issuer';
    (t.sources || []).forEach(function (s) {
      var o = data('option', '', s.name + (s.fits ? '' : ' - ' + tr(s.why)));
      o.value = s.name;
      o.disabled = !s.fits;
      f.issuer.appendChild(o);
    });
    f.issuer.value = st.issuer || t.source || '';
    row('Source', f.issuer, 'Only the sources that can give what the template asks for.');
    f.chal = el('select', '');
    f.chal.id = 'rpf-chal';
    (opts.challenges || []).forEach(function (c) { var o = data('option', '', c.name); o.value = c.name; f.chal.appendChild(o); });
    f.chalRow = row('Names proved by', f.chal, 'How the source checks the names (Certificates → Validation).');
    if (st.challenge) f.chal.value = st.challenge;
    var paint = function () { f.chalRow.hidden = !src().needs_validation || !(opts.challenges || []).length; };
    paint();
    cols.appendChild(left);
    prev = el('div', 'rpf-prev');
    prev.setAttribute('aria-live', 'polite');
    cols.appendChild(prev);
    body.appendChild(cols);
    [f.name, f.suffixes].forEach(function (x) { x.addEventListener('input', ask); });
    f.issuer.addEventListener('change', function () { paint(); ask(); });
    f.chal.addEventListener('change', ask);
    ask();
  }, [{words: 'Close', close: true},
      {words: 'Open in the editor…', icon: 'edit', go: function () {
        var v = values();
        if (!last || !last.body) { toast('Choose a source that fits first', 'bad'); return; }
        var body = JSON.parse(JSON.stringify(last.body));
        body.name = v.name;
        body.suffixes = v.suffixes;
        if (window.ACME_RP && ACME_RP.edit) ACME_RP.edit(null, body);
      }},
      {words: 'Make the profile', icon: 'add', cls: 'primary', go: function (b) {
        var v = values();
        if (!v.name) { toast('Give the new profile a name', 'bad'); f.name.focus(); return; }
        if (!v.suffixes.length) { toast('Say under which domains names may be asked for', 'bad'); f.suffixes.focus(); return; }
        busy(b, true);
        api('reqprofiles/from_template', v).then(function (d) {
          busy(b, false);
          toast(pat('The request profile {0} is made - change anything in it', d.profile.name), 'good');
          if (window.ACME_RP) {
            ACME_RP.redraw();
            ACME_RP.edit(d.profile);
          } else closeModal();
        }).catch(function (e) { busy(b, false); oops(e); });
      }}], 'large');
}
}());
