/* certview.js - Show a certificate (1.0.23): any certificate, chain, request,
   CRL, key or keystore - dropped as a file or pasted - read by the daemon
   (POST /api/certs/inspect, acmelib/certs/certview.py) and shown in the page's
   largest popup. It changes nothing and keeps nothing; a private key is
   described, never sent back.

   On top the chain as a rail, leaf to root: each certificate a station, the
   link between two said (the signature checked), the root in the system's
   trust store or not, a missing issuer drawn as a gap. Below, the one picked
   in cards over the whole width - identity, validity, key, fingerprints,
   names, usages, extensions, the PEM folded.

   window.ACME_CERTVIEW:
     open({text?, data_b64?, filename?, title?, back?})  the popup (asks first
                                                         when nothing is given)
     inspect({text | data_b64, filename, password})     -> Promise of the answer
     render(host, answer, {pick?})                      the viewer, into host
     csrCard(csr)                                       a CSR's card (Sign a CSR)
   Drawn with core.js (modal, el, noI18n, iconMarkup, copyText, secretBox) and
   acme.css's colours; the data is never translated. */
'use strict';
(function () {
  var CV = window.ACME_CERTVIEW = window.ACME_CERTVIEW || {};

  ICONS.cvroot = '<path d="M12 3l2.5 5 5.5.8-4 3.9.9 5.5L12 15.6 7.1 18.2 8 12.7 4 8.8l5.5-.8z"/>';
  ICONS.cvlink = '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>';
  ICONS.cvgap = '<path d="M4 12h4M16 12h4"/><path d="M10 8l4 8"/>';
  ICONS.cvcsr = '<path d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20z"/><path d="M14 3.5V8h4"/><path d="M9 13.5l2 2 4-4"/>';
  ICONS.cvcrl = '<path d="M6 3.5h12V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20z"/><path d="M9 8h6M9 11.5h6"/><path d="M9.5 15l5 4M14.5 15l-5 4"/>';

  var RDN = {CN: 'Common name', O: 'Organization', OU: 'Organizational unit', C: 'Country',
    ST: 'State or province', L: 'Locality', street: 'Street', postalCode: 'Postal code',
    emailAddress: 'E-mail', serialNumber: 'Serial number of the subject', DC: 'Domain component',
    UID: 'User ID', GN: 'Given name', SN: 'Surname', title: 'Title', initials: 'Initials',
    businessCategory: 'Business category', organizationIdentifier: 'Organization identifier',
    jurisdictionC: 'Jurisdiction (country)', jurisdictionST: 'Jurisdiction (state)',
    jurisdictionL: 'Jurisdiction (locality)', description: 'Description', name: 'Name',
    pseudonym: 'Pseudonym', dnQualifier: 'DN qualifier', generationQualifier: 'Generation'};
  var KU = {digitalSignature: 'digital signature', nonRepudiation: 'non-repudiation',
    keyEncipherment: 'key encipherment', dataEncipherment: 'data encipherment',
    keyAgreement: 'key agreement', keyCertSign: 'signs certificates', cRLSign: 'signs CRLs',
    encipherOnly: 'encipher only', decipherOnly: 'decipher only'};
  var EKU = {serverAuth: 'TLS server', clientAuth: 'TLS client', codeSigning: 'code signing',
    emailProtection: 'e-mail (S/MIME)', timeStamping: 'time stamping', OCSPSigning: 'OCSP signing',
    anyExtendedKeyUsage: 'any purpose', msSmartcardLogin: 'smart card logon',
    ipsecIKE: 'IPsec IKE', ipsecEndSystem: 'IPsec end system', ipsecTunnel: 'IPsec tunnel',
    ipsecUser: 'IPsec user', msEFS: 'encrypting file system', msDocumentSigning: 'document signing',
    documentSigning: 'document signing', pkInitKDC: 'Kerberos KDC', sshClient: 'SSH client',
    sshServer: 'SSH server'};
  var EXT = {subjectAltName: 'Alternative names', issuerAltName: 'Alternative names of the issuer',
    keyUsage: 'Key usage', extendedKeyUsage: 'Extended key usage', basicConstraints: 'Basic constraints',
    nameConstraints: 'Name constraints', certificatePolicies: 'Certificate policies',
    crlDistributionPoints: 'CRL distribution points', freshestCRL: 'Delta CRLs',
    authorityInfoAccess: 'Authority information access', subjectInfoAccess: 'Subject information access',
    subjectKeyIdentifier: 'Subject key identifier', authorityKeyIdentifier: 'Authority key identifier',
    ct_precert_scts: 'Certificate Transparency (SCTs)', ct_precert_poison: 'Precertificate (CT poison)',
    tlsfeature: 'TLS feature (must-staple)', inhibitAnyPolicy: 'Inhibit any policy',
    policyConstraints: 'Policy constraints', policyMappings: 'Policy mappings',
    ocspNoCheck: 'OCSP no check', msCertificateTemplate: 'Certificate template (Microsoft)',
    msCertificateTemplateName: 'Certificate template name (Microsoft)', msCAVersion: 'CA version (Microsoft)',
    netscapeComment: 'Comment (Netscape)', netscapeCertType: 'Certificate type (Netscape)',
    qcStatements: 'Qualified certificate statements', privateKeyUsagePeriod: 'Private key usage period'};
  var ROLE = {leaf: ['end entity', 'info', 'cert'], intermediate: ['intermediate CA', 'violet', 'ca'],
    root: ['root CA', 'violet', 'cvroot'], 'self-signed': ['self-signed', 'warn', 'cert']};
  var FORMAT = {pem: 'PEM', der: 'DER', pkcs7: 'PKCS#7', pkcs12: 'PKCS#12', jks: 'JKS',
    jceks: 'JCEKS', zip: 'ZIP', csr: 'CSR (DER)', crl: 'CRL (DER)', pkcs8: 'PKCS#8',
    pkcs1: 'PKCS#1', sec1: 'SEC1', spki: 'public key (DER)', base64: 'base64'};

  /* ---- small pieces ------------------------------------------------------- */
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function icon(key, size, cls) {
    var s = el('span', cls || 'cv-ic');
    s.innerHTML = iconMarkup(key, size || 16);
    return s;
  }
  function tag(words, tone, cls) { return el('span', 'tag ' + (tone || 'dim') + (cls ? ' ' + cls : ''), words); }
  function dtag(text, tone) { return noI18n(tag(text, tone)); }
  function arr(v) { return Array.isArray(v) ? v : (v === undefined || v === null || v === '' ? [] : [v]); }
  function call(body) {
    var capi = window.ACME_CERTS && window.ACME_CERTS.api;
    return capi ? capi('certs/inspect', body, 120) : api('certs/inspect', body, 120);
  }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function when(ts) {
    if (!ts) return '–';
    var d = new Date(ts * 1000);
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
  }
  function utc(ts) { return ts ? new Date(ts * 1000).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : ''; }
  function nowS() { return Date.now() / 1000; }
  function daysLeft(ts) { return ts ? Math.floor((ts - nowS()) / 86400) : null; }
  function daysTone(d) { return d === null ? 'dim' : (d < 7 ? 'crit' : (d < 21 ? 'warn' : 'ok')); }
  function daysWords(d) {
    if (d === null) return '–';
    if (d < 0) return 'expired ' + (-d === 1 ? 'a day ago' : (-d) + ' days ago');
    if (d === 0) return 'ends today';
    if (d === 1) return '1 day left';
    return d + ' days left';
  }
  function daysTag(ts, from) {
    if (from && from > nowS()) return tag('not valid yet', 'warn');
    var d = daysLeft(ts);
    return el('span', 'tag ' + daysTone(d), daysWords(d));
  }
  function colons(hex) { return String(hex || '').replace(/(..)(?!$)/g, '$1:'); }
  function keyLine(k) {
    if (!k) return '–';
    /* "bits" in the page's language (1.0.79): the line is a value, not read by the translation */
    var bits = function (n) {
      var w = n + ' bits';
      try { w = (typeof i18nText === 'function' && i18nText(w)) || w; } catch (e) { }
      return w;
    };
    if (k.algo === 'EC') return 'EC ' + (k.curve || '') + (k.bits ? ' (' + bits(k.bits) + ')' : '');
    if (k.algo === 'RSA' || k.algo === 'RSA-PSS' || k.algo === 'DSA') return k.algo + ' ' + bits(k.bits);
    return k.algo || k.type || '?';
  }
  function copyBtn(text, words) {
    var b = el('button', 'btn small cv-copy');
    b.type = 'button';
    b.innerHTML = iconMarkup('copy', 13);
    b.title = 'Copy';
    b.setAttribute('aria-label', 'Copy');
    b.onclick = function (e) { e.stopPropagation(); copyText(text, b, words || 'copied'); };
    return b;
  }
  function saveFile(name, text, mime) {
    var a = document.createElement('a');
    var url = URL.createObjectURL(new Blob([text], {type: mime || 'application/x-pem-file'}));
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }
  function fileName(t) {
    var base = String(t.cn || t.issuer_cn || t.kind || 'certificate').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'certificate';
    return base + ({csr: '.csr', crl: '.crl'}[t.kind] || '.crt');
  }

  /* A card of the detail: a heading with its icon, then rows. */
  function card(title, ic, cls) {
    var c = el('section', 'cv-card' + (cls ? ' ' + cls : ''));
    var h = el('h4', 'cv-card-h');
    h.appendChild(icon(ic || 'info', 15));
    h.appendChild(el('span', '', title));
    c.appendChild(h);
    return c;
  }
  /* rows: [label, value (text = data, or a node), {copy, words}] */
  function rows(list) {
    var dl = el('dl', 'cv-rows');
    list.forEach(function (r) {
      if (!r) return;
      var dt = el('dt', '', r[0]);
      var dd = el('dd', '');
      var v = r[1];
      if (v === null || v === undefined || v === '') dd.appendChild(el('span', 'muted', '–'));
      else if (typeof v === 'object' && v.nodeType) dd.appendChild(v);
      else dd.appendChild(data('span', r[2] && r[2].mono ? 'mono cv-val' : 'cv-val', String(v)));
      if (r[2] && r[2].copy && v) dd.appendChild(copyBtn(typeof v === 'string' ? v : r[2].copy));
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    return dl;
  }
  function chips(list, cls) {
    var box = el('div', 'cv-chips');
    list.forEach(function (x) { box.appendChild(x.nodeType ? x : data('span', 'cv-chip ' + (cls || ''), String(x))); });
    return box;
  }
  function wordChip(words, code, cls) {
    var c = el('span', 'cv-chip ' + (cls || ''));
    c.appendChild(el('span', '', words));
    if (code && code !== words) c.appendChild(data('code', 'cv-chip-c', code));
    return c;
  }
  function nameChips(names) {
    return chips(names.map(function (n) {
      var k = String(n[0]);
      var c = el('span', 'cv-chip name k-' + k.toLowerCase());
      c.appendChild(data('i', 'cv-chip-k', k === 'DNS' ? (/^\*\./.test(n[1]) ? 'wildcard' : 'DNS') : k));
      c.appendChild(data('span', '', n[1]));
      if (k === 'DNS' && /^\*\./.test(n[1])) c.classList.add('wild');
      return c;
    }));
  }
  function linkList(urls) {
    var box = el('div', 'cv-urls');
    arr(urls).forEach(function (u) {
      var row = el('div', 'cv-url');
      if (/^https?:\/\//i.test(u)) {
        var a = data('a', 'mono', u);
        a.href = u;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        row.appendChild(a);
      } else row.appendChild(data('span', 'mono', u));
      box.appendChild(row);
    });
    return box;
  }
  function rdnTable(pairs) {
    var t = el('table', 'cv-rdn');
    var b = el('tbody');
    arr(pairs).forEach(function (p) {
      var tr = el('tr');
      var k = el('td', 'cv-rdn-k');
      k.appendChild(el('span', '', RDN[p[0]] || p[0]));
      if (RDN[p[0]]) k.appendChild(data('code', 'cv-rdn-s', p[0]));
      tr.appendChild(k);
      tr.appendChild(data('td', 'cv-rdn-v', p[1]));
      b.appendChild(tr);
    });
    t.appendChild(b);
    return t;
  }

  /* ---- the extensions ------------------------------------------------------ */
  function extValue(e) {
    var v = e.value;
    switch (e.kind) {
      case 'names': return nameChips(arr(v));
      case 'list':
        if (e.name === 'keyUsage') return chips(arr(v).map(function (x) { return wordChip(KU[x] || x, x); }));
        return chips(arr(v).map(function (x) { return x === 'status_request' ? wordChip('OCSP must-staple', x, 'warn') : data('span', 'cv-chip', x); }));
      case 'eku': return chips(arr(v).map(function (x) { return wordChip(EKU[x.name] || x.name, x.name === x.oid ? x.oid : x.name); }));
      case 'basic': {
        var b = el('div', 'cv-chips');
        b.appendChild(v && v.ca ? tag('a CA: may sign certificates', 'violet') : tag('not a CA', 'dim'));
        if (v && v.path_len !== null && v.path_len !== undefined) b.appendChild(el('span', 'cv-chip', 'path length ' + v.path_len));
        return b;
      }
      case 'constraints': {
        var box = el('div', 'cv-sub');
        ['permitted', 'excluded'].forEach(function (k) {
          if (!arr(v && v[k]).length) return;
          box.appendChild(el('div', 'small muted', k === 'permitted' ? 'Only under' : 'Never under'));
          box.appendChild(chips(arr(v[k]), k === 'excluded' ? 'bad' : 'ok'));
        });
        return box;
      }
      case 'policies': {
        var pb = el('div', 'cv-sub');
        arr(v).forEach(function (p) {
          var r = el('div', 'cv-pol');
          if (p.name) r.appendChild(tag(p.name, /\(EV\)/.test(p.name) ? 'ok' : 'info'));
          r.appendChild(data('code', 'cv-oid', p.oid));
          arr(p.cps).forEach(function (u) { r.appendChild(linkList([u])); });
          if (p.notice) r.appendChild(data('div', 'small muted', p.notice));
          pb.appendChild(r);
        });
        return pb;
      }
      case 'urls': return linkList(arr(v && v.urls).concat(arr(v && v.other)));
      case 'aia': {
        var ab = el('div', 'cv-sub');
        if (arr(v.ocsp).length) { ab.appendChild(el('div', 'small muted', 'OCSP')); ab.appendChild(linkList(v.ocsp)); }
        if (arr(v.ca_issuers).length) { ab.appendChild(el('div', 'small muted', 'The issuer’s certificate')); ab.appendChild(linkList(v.ca_issuers)); }
        if (arr(v.other).length) ab.appendChild(linkList(v.other));
        return ab;
      }
      case 'hex': return data('span', 'mono cv-hex', colons(v));
      case 'aki': {
        var kb = el('div', 'cv-sub');
        if (v.key_id) kb.appendChild(data('span', 'mono cv-hex', colons(v.key_id)));
        if (arr(v.issuer).length) kb.appendChild(nameChips(v.issuer));
        if (v.serial) kb.appendChild(data('span', 'mono small', 'serial ' + v.serial));
        return kb;
      }
      case 'scts': {
        var sb = el('div', 'cv-sub');
        sb.appendChild(el('div', 'small', arr(v).length + ' SCT(s): logged in Certificate Transparency'));
        arr(v).forEach(function (s) {
          var r = el('div', 'cv-sct');
          r.appendChild(data('span', 'mono cv-hex', s.log_id));
          r.appendChild(data('span', 'small muted', when(s.ts) + (s.sig ? ' · ' + s.sig : '')));
          sb.appendChild(r);
        });
        return sb;
      }
      case 'flag': return el('span', 'cv-chip', v === 'precertificate' ? 'a precertificate: not to be used' : 'the OCSP responder’s own certificate is not checked');
      case 'number': return data('span', '', String(v));
      case 'text': return data('span', '', String(v));
      case 'template': return data('span', 'mono', v.oid + (v.major !== null ? ' v' + v.major + (v.minor !== null ? '.' + v.minor : '') : ''));
      default: {
        var ob = el('div', 'cv-sub');
        ob.appendChild(el('div', 'small muted', e.unreadable ? 'could not be read: the bytes as they are' : 'not known here: the bytes as they are'));
        ob.appendChild(data('div', 'mono cv-hex cv-raw', colons(e.hex || '') + (e.length > 1024 ? ' …' : '')));
        return ob;
      }
    }
  }
  function extensionsCard(list, title) {
    var c = card(title || 'Extensions', 'list', 'cv-wide');
    if (!arr(list).length) { c.appendChild(el('p', 'muted small', 'None.')); return c; }
    var t = el('div', 'cv-exts');
    arr(list).forEach(function (e) {
      var r = el('div', 'cv-ext' + (e.critical ? ' crit' : ''));
      var h = el('div', 'cv-ext-h');
      h.appendChild(el('b', '', EXT[e.name] || (e.name === e.oid ? 'Unknown extension' : e.name)));
      h.appendChild(data('code', 'cv-oid', e.oid));
      if (e.critical) h.appendChild(tag('critical', 'warn'));
      r.appendChild(h);
      r.appendChild(extValue(e));
      t.appendChild(r);
    });
    c.appendChild(t);
    return c;
  }

  /* ---- the validity, as a bar ----------------------------------------------- */
  function lifeBar(from, to) {
    var box = el('div', 'cv-life');
    var total = Math.max(1, to - from), done = Math.min(1, Math.max(0, (nowS() - from) / total));
    var d = daysLeft(to);
    var bar = el('div', 'cv-life-bar ' + (nowS() < from ? 'warn' : daysTone(d)));
    var fill = el('div', 'cv-life-fill');
    fill.style.width = (done * 100).toFixed(1) + '%';
    bar.appendChild(fill);
    var mark = el('div', 'cv-life-now');
    mark.style.left = (done * 100).toFixed(1) + '%';
    bar.appendChild(mark);
    box.appendChild(bar);
    var ends = el('div', 'cv-life-ends');
    ends.appendChild(data('span', 'mono small', when(from)));
    ends.appendChild(el('span', 'small muted', Math.round(total / 86400) + ' days in all'));
    ends.appendChild(data('span', 'mono small', when(to)));
    box.appendChild(ends);
    return box;
  }

  /* ---- the detail of one thing ---------------------------------------------- */
  function certDetail(t, ans, go) {
    var wrap = el('div', 'cv-detail');
    var role = ROLE[t.role] || ROLE.leaf;
    var head = el('div', 'cv-head');
    head.appendChild(icon(role[2], 26, 'cv-head-ic'));
    var hw = el('div', 'cv-head-w');
    var h3 = el('h3', 'cv-head-t');
    h3.appendChild(data('span', '', t.cn || t.subject_dn || '(no name)'));
    hw.appendChild(h3);
    var sub = el('div', 'cv-head-s');
    sub.appendChild(tag(role[0], role[1]));
    if (t.origin === 'store') sub.appendChild(tag('from this server’s trust store - not in what you gave', 'ok'));
    sub.appendChild(daysTag(t.not_after, t.not_before));
    arr(t.aliases).forEach(function (a) { sub.appendChild(dtag(a, 'dim')); });
    if (arr(t.keys).length) sub.appendChild(tag('its private key is in the file', 'ok'));
    if (t.must_staple) sub.appendChild(tag('must-staple', 'warn'));
    hw.appendChild(sub);
    head.appendChild(hw);
    wrap.appendChild(head);

    var grid = el('div', 'cv-cards');
    var id = card('Who it is', 'person');
    id.appendChild(rdnTable(t.subject));
    id.appendChild(rows([['Distinguished name', t.subject_dn, {copy: true, mono: true}]]));
    grid.appendChild(id);

    var iss = card('Issued by', 'ca');
    iss.appendChild(rdnTable(t.issuer));
    var link = linkOf(ans, t.id);
    var parent = link ? thing(ans, link.parent) : null;
    if (t.self_signed) iss.appendChild(el('p', 'cv-note', 'Self-signed: it is its own issuer.'));
    else if (parent) {
      var lb = el('div', 'cv-linkline ' + (link.ok ? 'ok' : (link.ok === false ? 'bad' : '')));
      lb.appendChild(icon(link.ok ? 'check' : (link.ok === false ? 'close' : 'info'), 14));
      lb.appendChild(el('span', '', link.ok ? 'Signature checked: signed with the key of' : (link.ok === false ? 'The signature does not fit the key of' : 'Not checked:')));
      var pb = data('button', 'cv-jump', parent.cn || parent.subject_dn);
      pb.type = 'button';
      pb.onclick = function () { go(parent.id); };
      lb.appendChild(pb);
      if (link.ok === false && link.words) lb.appendChild(data('span', 'small', '(' + link.words + ')'));
      iss.appendChild(lb);
    } else iss.appendChild(el('p', 'cv-note warn', 'The issuer of this certificate is not in what you gave.'));
    grid.appendChild(iss);

    var val = card('Valid', 'clock');
    val.appendChild(lifeBar(t.not_before, t.not_after));
    val.appendChild(rows([['From', when(t.not_before) + '  (' + utc(t.not_before) + ')'], ['Until', when(t.not_after) + '  (' + utc(t.not_after) + ')']]));
    grid.appendChild(val);

    var key = card('Key and signature', 'key');
    var keyRows = [['Public key', keyLine(t.key)]];
    if (t.key && t.key.exponent) keyRows.push(['Exponent', String(t.key.exponent)]);
    keyRows.push(['SHA-256 of the public key', t.key && t.key.spki_sha256, {copy: true, mono: true}]);
    keyRows.push(['Signature algorithm', t.sig_alg]);
    keyRows.push(['Serial number', colons(t.serial), {copy: t.serial, mono: true}]);
    keyRows.push(['… in decimal', t.serial_dec, {mono: true}]);
    keyRows.push(['Version', 'v' + t.version]);
    key.appendChild(rows(keyRows));
    arr(t.keys).forEach(function (kid) {
      var k = thing(ans, kid);
      if (!k) return;
      var kl = el('div', 'cv-linkline ok');
      kl.appendChild(icon('key', 14));
      kl.appendChild(el('span', '', 'Its private key is in the file:'));
      var kb = data('button', 'cv-jump', keyLine(k.key) + (k.alias ? ' · ' + k.alias : ''));
      kb.type = 'button';
      kb.onclick = function () { go(k.id); };
      kl.appendChild(kb);
      key.appendChild(kl);
    });
    grid.appendChild(key);

    var fp = card('Fingerprints', 'shield');
    fp.appendChild(rows([['SHA-256', colons(t.sha256), {copy: t.sha256, mono: true}], ['SHA-1', colons(t.sha1), {copy: t.sha1, mono: true}],
                         t.ski ? ['Key identifier (SKI)', colons(t.ski), {copy: t.ski, mono: true}] : null,
                         t.aki ? ['Issuer’s key (AKI)', colons(t.aki), {copy: t.aki, mono: true}] : null]));
    grid.appendChild(fp);

    if (arr(t.names).length) {
      var nm = card('Names', 'globe');
      nm.appendChild(el('p', 'small muted', arr(t.names).length + ' name(s) it is valid for'));
      nm.appendChild(nameChips(t.names));
      grid.appendChild(nm);
    }
    var use = card('What it may be used for', 'check');
    var ur = [];
    ur.push(['Key usage', arr(t.key_usage).length ? chips(t.key_usage.map(function (x) { return wordChip(KU[x] || x, x); })) : null]);
    ur.push(['Extended key usage', arr(t.eku).length ? chips(t.eku.map(function (x) { return wordChip(EKU[x] || x, x); })) : null]);
    var bc = el('div', 'cv-chips');
    bc.appendChild(t.is_ca ? tag('a CA: may sign certificates', 'violet') : tag('not a CA', 'dim'));
    if (t.path_len !== null && t.path_len !== undefined) bc.appendChild(el('span', 'cv-chip', 'path length ' + t.path_len));
    ur.push(['Basic constraints', bc]);
    use.appendChild(rows(ur));
    grid.appendChild(use);

    if (arr(t.ocsp).length || arr(t.crl).length || arr(t.ca_issuers).length) {
      var wh = card('Where it is checked', 'net');
      var wr = [];
      if (arr(t.ocsp).length) wr.push(['OCSP', linkList(t.ocsp)]);
      if (arr(t.crl).length) wr.push(['CRL', linkList(t.crl)]);
      if (arr(t.ca_issuers).length) wr.push(['The issuer’s certificate', linkList(t.ca_issuers)]);
      wh.appendChild(rows(wr));
      grid.appendChild(wh);
    }
    wrap.appendChild(grid);
    wrap.appendChild(extensionsCard(t.extensions));
    wrap.appendChild(pemCard(t, 'The certificate (PEM)'));
    return wrap;
  }
  function pemCard(t, title) {
    var c = card(title, 'lock', 'cv-wide cv-pemcard');
    var btns = el('div', 'btnrow cv-pem-b');
    var cp = cmdButton('Copy', 'copy', 'small');
    cp.onclick = function () { copyText(t.pem, cp, 'the PEM was copied'); };
    btns.appendChild(cp);
    var dl = cmdButton('Download', 'download', 'small');
    dl.onclick = function () { saveFile(fileName(t), t.pem); };
    btns.appendChild(dl);
    c.querySelector('.cv-card-h').appendChild(btns);
    var d = el('details', 'cv-pem');
    var s = el('summary', '');
    s.appendChild(el('span', '', 'Show the PEM'));
    s.appendChild(data('span', 'small muted', ' · ' + (t.size || 0) + ' B DER'));
    d.appendChild(s);
    d.appendChild(data('pre', 'mono cv-pem-t', t.pem || ''));
    c.appendChild(d);
    return c;
  }
  function csrDetail(t, ans, go) {
    var wrap = el('div', 'cv-detail');
    var head = el('div', 'cv-head');
    head.appendChild(icon('cvcsr', 26, 'cv-head-ic'));
    var hw = el('div', 'cv-head-w');
    hw.appendChild(data('h3', 'cv-head-t', t.cn || t.subject_dn || '(no subject)'));
    var sub = el('div', 'cv-head-s');
    sub.appendChild(tag('certificate request (CSR)', 'info'));
    sub.appendChild(t.signature_ok === null ? tag('not checked', 'dim') : (t.signature_ok ? tag('signed by its own key ✓', 'ok') : tag('its signature does not fit its key ✗', 'crit')));
    hw.appendChild(sub);
    head.appendChild(hw);
    wrap.appendChild(head);
    var grid = el('div', 'cv-cards');
    grid.appendChild(csrCard(t, ans, go));
    wrap.appendChild(grid);
    wrap.appendChild(extensionsCard(t.extensions, 'Extensions it asks for'));
    wrap.appendChild(pemCard(t, 'The request (PEM)'));
    return wrap;
  }
  /** A CSR's card: its subject, names, key, signature. */
  function csrCard(t, ans, go) {
    var c = el('div', 'cv-csrcards');
    var id = card('Who it is for', 'person');
    if (arr(t.subject).length) id.appendChild(rdnTable(t.subject));
    else id.appendChild(el('p', 'muted small', 'An empty subject: only the names below.'));
    c.appendChild(id);
    var nm = card('Names', 'globe');
    if (arr(t.names).length) nm.appendChild(nameChips(t.names));
    else nm.appendChild(el('p', 'cv-note warn', 'No alternative names: only the common name.'));
    c.appendChild(nm);
    var k = card('Key and signature', 'key');
    var r = [['Public key', keyLine(t.key)], ['SHA-256 of the public key', t.key && t.key.spki_sha256, {copy: true, mono: true}],
             ['Signature algorithm', t.sig_alg],
             ['Signature', t.signature_ok === null ? tag('not checked', 'dim') : (t.signature_ok ? tag('right: signed by its own key', 'ok') : tag('wrong: not signed by its key', 'crit'))],
             ['Challenge password', t.challenge_password ? tag('there is one (not shown)', 'warn') : el('span', 'muted', 'none')]];
    if (arr(t.eku).length) r.push(['Extended key usage', chips(t.eku.map(function (x) { return wordChip(EKU[x] || x, x); }))]);
    if (arr(t.key_usage).length) r.push(['Key usage', chips(t.key_usage.map(function (x) { return wordChip(KU[x] || x, x); }))]);
    if (t.must_staple) r.push(['TLS feature', tag('OCSP must-staple', 'warn')]);
    arr(t.attributes).forEach(function (a) { r.push([a.name, a.value || '–']); });
    k.appendChild(rows(r));
    if (ans && arr(t.matches).length && go) {
      var m = thing(ans, t.matches[0]);
      var ml = el('div', 'cv-linkline ok');
      ml.appendChild(icon('cert', 14));
      ml.appendChild(el('span', '', 'A certificate with this key is in the file:'));
      var mb = data('button', 'cv-jump', m.cn || m.subject_dn);
      mb.type = 'button';
      mb.onclick = function () { go(m.id); };
      ml.appendChild(mb);
      k.appendChild(ml);
    }
    c.appendChild(k);
    return c;
  }
  function crlDetail(t, ans, go) {
    var wrap = el('div', 'cv-detail');
    var head = el('div', 'cv-head');
    head.appendChild(icon('cvcrl', 26, 'cv-head-ic'));
    var hw = el('div', 'cv-head-w');
    hw.appendChild(data('h3', 'cv-head-t', t.issuer_cn || t.issuer_dn));
    var sub = el('div', 'cv-head-s');
    sub.appendChild(tag('revocation list (CRL)', 'info'));
    if (t.next_update) sub.appendChild(t.next_update < nowS() ? tag('out of date', 'crit') : tag('current', 'ok'));
    if (t.signature_ok === true) sub.appendChild(tag('signed by its issuer ✓', 'ok'));
    if (t.signature_ok === false) sub.appendChild(tag('its signature does not fit its issuer ✗', 'crit'));
    hw.appendChild(sub);
    head.appendChild(hw);
    wrap.appendChild(head);
    var grid = el('div', 'cv-cards');
    var a = card('Issued by', 'ca');
    a.appendChild(rdnTable(t.issuer));
    if (t.issuer_id && go) {
      var b = data('button', 'cv-jump', (thing(ans, t.issuer_id) || {}).cn || t.issuer_dn);
      b.type = 'button';
      b.onclick = function () { go(t.issuer_id); };
      var ln = el('div', 'cv-linkline');
      ln.appendChild(el('span', '', 'Its issuer is in the file:'));
      ln.appendChild(b);
      a.appendChild(ln);
    }
    grid.appendChild(a);
    var u = card('Updates', 'clock');
    u.appendChild(rows([['This update', when(t.this_update)], ['Next update', t.next_update ? when(t.next_update) : null],
                        ['CRL number', t.number, {mono: true}], ['Signature algorithm', t.sig_alg],
                        ['Issuer’s key (AKI)', t.aki ? colons(t.aki) : null, {mono: true}],
                        ['Revoked certificates', String(t.count)]]));
    grid.appendChild(u);
    var rv = card('Revoked', 'ban', 'cv-wide');
    if (!t.count) rv.appendChild(el('p', 'muted small', 'Nothing is revoked.'));
    else {
      if (t.count > arr(t.revoked).length) rv.appendChild(el('p', 'small muted', 'The first ' + arr(t.revoked).length + ' of ' + t.count));
      var tb = el('table', 'plain tight cv-revoked');
      var hd = el('tr');
      ['Serial number', 'Revoked', 'Reason'].forEach(function (w) { hd.appendChild(el('th', '', w)); });
      var th = el('thead');
      th.appendChild(hd);
      tb.appendChild(th);
      var bd = el('tbody');
      arr(t.revoked).forEach(function (x) {
        var tr = el('tr');
        tr.appendChild(data('td', 'mono', x.serial));
        tr.appendChild(data('td', 'mono', when(x.at)));
        tr.appendChild(data('td', '', x.reason));
        bd.appendChild(tr);
      });
      tb.appendChild(bd);
      rv.appendChild(tb);
    }
    wrap.appendChild(grid);
    wrap.appendChild(rv);
    wrap.appendChild(pemCard(t, 'The CRL (PEM)'));
    return wrap;
  }
  function keyDetail(t, ans, go) {
    var wrap = el('div', 'cv-detail');
    var head = el('div', 'cv-head');
    head.appendChild(icon('key', 26, 'cv-head-ic'));
    var hw = el('div', 'cv-head-w');
    hw.appendChild(el('h3', 'cv-head-t', t.kind === 'pubkey' ? 'A public key' : 'A private key'));
    var sub = el('div', 'cv-head-s');
    if (t.key) sub.appendChild(dtag(keyLine(t.key), 'info'));
    if (t.alias) sub.appendChild(dtag(t.alias, 'dim'));
    if (t.encrypted) sub.appendChild(tag('was encrypted', 'ok'));
    else if (t.kind === 'key') sub.appendChild(tag('not encrypted', 'warn'));
    if (t.locked) sub.appendChild(tag(t.locked === 'wrong' ? 'the password is wrong' : 'locked: give its password', 'crit'));
    hw.appendChild(sub);
    head.appendChild(hw);
    wrap.appendChild(head);
    var grid = el('div', 'cv-cards');
    var c = card(t.kind === 'pubkey' ? 'The public key' : 'The private key', 'key');
    var r = [['Key', t.key ? keyLine(t.key) : (t.locked ? el('span', 'muted', 'cannot be read without its password') : (t.error || null))]];
    if (t.kind === 'key') {
      r.push(['Format', t.format]);
      r.push(['Encrypted with', t.cipher || (t.encrypted ? null : el('span', 'muted', 'nothing'))]);
    }
    r.push(['SHA-256 of the public key', t.pub_sha256 || null, {copy: true, mono: true}]);
    c.appendChild(rows(r));
    if (t.kind === 'key') c.appendChild(el('p', 'cv-note', 'The key itself is never shown and never leaves the server: only what it is.'));
    grid.appendChild(c);
    var m = card('Belongs to', 'cert');
    if (arr(t.matches).length) {
      arr(t.matches).forEach(function (id) {
        var x = thing(ans, id);
        var ln = el('div', 'cv-linkline ok');
        ln.appendChild(icon('check', 14));
        ln.appendChild(el('span', '', 'It fits the certificate'));
        var b = data('button', 'cv-jump', x.cn || x.subject_dn);
        b.type = 'button';
        b.onclick = function () { go(x.id); };
        ln.appendChild(b);
        m.appendChild(ln);
      });
    } else if (t.pub_sha256) m.appendChild(el('p', 'cv-note warn', 'No certificate in what you gave has this key.'));
    else m.appendChild(el('p', 'muted small', 'Which certificate it fits can be told once it is read.'));
    grid.appendChild(m);
    wrap.appendChild(grid);
    return wrap;
  }

  /* ---- the answer as a whole -------------------------------------------------- */
  function thing(ans, id) {
    for (var i = 0; i < ans.things.length; i++) if (ans.things[i].id === id) return ans.things[i];
    return null;
  }
  function linkOf(ans, childId) {
    for (var i = 0; i < arr(ans.chains).length; i++) {
      var ls = arr(ans.chains[i].links);
      for (var j = 0; j < ls.length; j++) if (ls[j].child === childId) return ls[j];
    }
    return null;
  }
  function counts(ans) {
    var n = {cert: 0, csr: 0, crl: 0, key: 0, pubkey: 0};
    ans.things.forEach(function (t) { if (t.origin !== 'store') n[t.kind] += 1; });
    var out = [];
    if (n.cert) out.push(n.cert === 1 ? '1 certificate' : n.cert + ' certificates');
    if (n.key) out.push(n.key === 1 ? '1 private key' : n.key + ' private keys');
    if (n.csr) out.push(n.csr === 1 ? '1 request' : n.csr + ' requests');
    if (n.crl) out.push(n.crl === 1 ? '1 CRL' : n.crl + ' CRLs');
    if (n.pubkey) out.push(n.pubkey === 1 ? '1 public key' : n.pubkey + ' public keys');
    return out;
  }
  function summary(ans) {
    var box = el('div', 'cv-sum');
    var top = el('div', 'cv-sum-t');
    top.appendChild(dtag(FORMAT[ans.format] || String(ans.format || '?').toUpperCase(), 'info'));
    if (ans.filename) top.appendChild(data('b', 'cv-file', ans.filename));
    top.appendChild(data('span', 'muted small', ans.size + ' B'));
    counts(ans).forEach(function (w) { top.appendChild(el('span', 'cv-count', w)); });
    box.appendChild(top);
    var c = ans.container || {};
    var facts = [];
    if (c.type === 'pkcs12') {
      if (c.mac) facts.push(['MAC', c.mac]);
      if (c.cert_encryption) facts.push(['Certificates encrypted with', c.cert_encryption]);
      if (c.key_encryption) facts.push(['Keys encrypted with', c.key_encryption]);
      if (c.legacy) facts.push(['', tag('legacy encryption (RC2/3DES): read with openssl -legacy', 'warn')]);
    } else if (c.type === 'jks' || c.type === 'jceks') {
      facts.push(['Keystore', c.type.toUpperCase() + ' v' + c.version]);
      facts.push(['Entries', String(c.count)]);
      facts.push(['Integrity', c.integrity === true ? tag('checked with the password ✓', 'ok')
                  : (c.integrity === false ? tag('does not pass: wrong password or changed', 'crit') : tag('not checked: no password given', 'warn'))]);
    } else if (c.type === 'pkcs7') {
      facts.push(['PKCS#7', el('span', '', c.certs + ' certificate(s), ' + c.crls + ' CRL(s), ' + c.signers + ' signer(s)')]);
    }
    if (facts.length) {
      var f = el('div', 'cv-sum-f');
      facts.forEach(function (p) {
        var it = el('span', 'cv-fact');
        if (p[0]) it.appendChild(el('span', 'muted', p[0]));
        it.appendChild(typeof p[1] === 'string' ? data('span', 'mono', p[1]) : p[1]);
        f.appendChild(it);
      });
      box.appendChild(f);
    }
    arr(ans.notes).forEach(function (n) { box.appendChild(data('div', 'cv-noteline', n)); });
    return box;
  }
  function chainWords(ch, ans) {
    var top = ch.top || {};
    var bad = arr(ch.links).some(function (l) { return l.ok === false; });
    if (bad) return tag('a signature in the chain does not fit', 'crit');
    if (top.missing) return tag('incomplete: the issuer of the last one is not here', 'warn');
    if (top.in_store) return tag('ends in a root this server trusts', 'ok');
    if (top.self_signed) return tag('ends in a root this server does not trust', 'warn');
    return null;
  }
  function station(t, ans, pick) {
    var role = ROLE[t.role] || ROLE.leaf;
    var st = el('button', 'cv-station r-' + (t.kind === 'cert' ? t.role : t.kind) + (t.origin === 'store' ? ' store' : ''));
    st.type = 'button';
    st.setAttribute('role', 'tab');
    st.dataset.id = t.id;
    var top = el('span', 'cv-station-t');
    var ic = {csr: 'cvcsr', crl: 'cvcrl', key: 'key', pubkey: 'key'}[t.kind] || role[2];
    top.appendChild(icon(ic, 15, 'cv-station-ic'));
    var title = t.kind === 'cert' || t.kind === 'csr' ? (t.cn || t.subject_dn || '?') : (t.kind === 'crl' ? (t.issuer_cn || t.issuer_dn) : (t.key ? keyLine(t.key) : (t.alias || '')));
    top.appendChild(title ? data('b', '', title) : el('b', '', t.kind === 'pubkey' ? 'A public key' : 'A private key'));
    st.appendChild(top);
    var sub = el('span', 'cv-station-s');
    if (t.kind === 'cert') {
      sub.appendChild(el('span', 'small muted', t.self_signed ? 'self-signed' : 'by'));
      if (!t.self_signed) sub.appendChild(data('span', 'small', t.issuer_cn || t.issuer_dn));
    } else if (t.kind === 'csr') sub.appendChild(el('span', 'small muted', arr(t.names).length + ' name(s)'));
    else if (t.kind === 'crl') sub.appendChild(el('span', 'small muted', t.count + ' revoked'));
    else sub.appendChild(el('span', 'small muted', t.kind === 'pubkey' ? 'a public key' : (t.readable ? 'a private key (not shown)' : 'a private key, locked')));
    st.appendChild(sub);
    var meta = el('span', 'cv-station-m');
    if (t.kind === 'cert') {
      meta.appendChild(tag(role[0], role[1]));
      meta.appendChild(daysTag(t.not_after, t.not_before));
      if (arr(t.keys).length) meta.appendChild(tag('key', 'ok'));
      if (t.origin === 'store') meta.appendChild(tag('trust store', 'ok'));
    } else if (t.kind === 'csr') meta.appendChild(t.signature_ok === null ? tag('not checked', 'dim') : (t.signature_ok ? tag('signature ✓', 'ok') : tag('signature ✗', 'crit')));
    else if (t.kind === 'crl') meta.appendChild(t.next_update && t.next_update < nowS() ? tag('out of date', 'crit') : tag('current', 'ok'));
    else if (t.kind === 'key') {
      if (arr(t.matches).length) meta.appendChild(tag('fits a certificate', 'ok'));
      if (t.locked) meta.appendChild(tag(t.locked === 'wrong' ? 'wrong password' : 'locked', 'crit'));
    }
    arr(t.aliases || (t.alias ? [t.alias] : [])).slice(0, 2).forEach(function (a) { meta.appendChild(dtag(a, 'dim')); });
    st.appendChild(meta);
    st.onclick = function () { pick(t.id); };
    return st;
  }
  function linkBox(l) {
    var b = el('span', 'cv-link ' + (l.ok ? 'ok' : (l.ok === false ? 'bad' : 'unk')));
    b.appendChild(icon(l.ok ? 'check' : (l.ok === false ? 'close' : 'info'), 13));
    b.appendChild(el('span', 'cv-link-w', l.ok ? 'signed by' : (l.ok === false ? 'does not fit' : 'not checked')));
    if (l.words && l.ok !== true) b.title = l.words;
    return b;
  }
  function endBox(ch) {
    var top = ch.top || {};
    if (top.missing) {
      var g = el('div', 'cv-station gap');
      var t = el('span', 'cv-station-t');
      t.appendChild(icon('cvgap', 15, 'cv-station-ic'));
      t.appendChild(el('b', '', 'Its issuer is not here'));
      g.appendChild(t);
      g.appendChild(data('span', 'cv-station-s small mono', top.missing));
      return [el('span', 'cv-link unk gapl'), g];
    }
    if (top.self_signed) {
      var e = el('span', 'cv-end ' + (top.in_store ? 'ok' : 'warn'));
      e.appendChild(icon(top.in_store ? 'shield' : 'info', 14));
      e.appendChild(el('span', '', top.in_store ? (top.added_from_store ? 'taken from this server’s trust store' : 'in this server’s trust store') : 'not in this server’s trust store'));
      return [e];
    }
    return [];
  }
  function rail(ch, ans, pick, n, many) {
    var box = el('div', 'cv-track');
    var h = el('div', 'cv-track-h');
    h.appendChild(el('b', '', many ? 'Chain ' + n : 'The chain'));
    h.appendChild(el('span', 'small muted', ch.items.length === 1 ? '1 certificate' : ch.items.length + ' certificates, the certificate first'));
    var w = chainWords(ch, ans);
    if (w) h.appendChild(w);
    box.appendChild(h);
    var line = el('div', 'cv-rail');
    line.setAttribute('role', 'tablist');
    ch.items.forEach(function (id, i) {
      if (i > 0) {
        var l = arr(ch.links)[i - 1];
        if (l) line.appendChild(linkBox(l));
      }
      line.appendChild(station(thing(ans, id), ans, pick));
    });
    endBox(ch).forEach(function (x) { line.appendChild(x); });
    box.appendChild(line);
    return box;
  }
  function yard(title, ids, ans, pick, words) {
    var box = el('div', 'cv-track');
    var h = el('div', 'cv-track-h');
    h.appendChild(el('b', '', title));
    if (words) h.appendChild(el('span', 'small muted', words));
    box.appendChild(h);
    var g = el('div', 'cv-yard');
    ids.forEach(function (id) { g.appendChild(station(thing(ans, id), ans, pick)); });
    box.appendChild(g);
    return box;
  }
  function entriesStrip(ans, pick) {
    var box = el('div', 'cv-entries');
    box.appendChild(el('span', 'small muted cv-entries-h', 'Entries'));
    ans.entries.filter(function (e) { return e.alias; }).forEach(function (e) {
      var b = el('button', 'cv-entry k-' + e.kind);
      b.type = 'button';
      b.appendChild(icon(e.kind === 'key' ? 'key' : (e.kind === 'secret' ? 'lock' : 'cert'), 13));
      b.appendChild(data('b', '', e.alias || '(no alias)'));
      b.appendChild(el('span', 'small muted', e.kind === 'key' ? 'private key + ' + Math.max(0, arr(e.items).length - 1) + ' certificate(s)'
        : (e.kind === 'secret' ? 'a secret key (not read)' : (e.kind === 'trusted' ? 'trusted certificate' : 'a certificate'))));
      if (e.created) b.appendChild(data('span', 'small muted', when(e.created)));
      var firstCert = arr(e.items).filter(function (id) { return /^c/.test(id); })[0] || arr(e.items)[0];
      if (firstCert) b.onclick = function () { pick(firstCert); };
      else b.disabled = true;
      box.appendChild(b);
    });
    return box;
  }

  /** The viewer of an answer, into `host`. */
  CV.render = function (host, ans, o) {
    o = o || {};
    clear(host);
    var page = el('div', 'cv-page');
    page.appendChild(summary(ans));
    if (o.before) page.appendChild(o.before);
    var shown = el('div', 'cv-shown');
    var stations = [];
    var pick = function (id) {
      var t = thing(ans, id);
      if (!t) return;
      stations.forEach(function (s) {
        var on = s.dataset.id === id;
        s.classList.toggle('on', on);
        s.setAttribute('aria-selected', on ? 'true' : 'false');
      });
      clear(shown);
      var d = t.kind === 'cert' ? certDetail(t, ans, pick) : (t.kind === 'csr' ? csrDetail(t, ans, pick)
        : (t.kind === 'crl' ? crlDetail(t, ans, pick) : keyDetail(t, ans, pick)));
      shown.appendChild(d);
      if (typeof explainWhatWasDrawn === 'function') { try { explainWhatWasDrawn(shown); } catch (e) { } }
    };
    var tracks = el('div', 'cv-tracks');
    var named = arr(ans.entries).filter(function (e) { return e.alias; });
    var keystore = /^(jks|jceks)$/.test(String(ans.format));
    if (named.length && (keystore || named.length > 1)) tracks.appendChild(entriesStrip(ans, pick));
    var chains = arr(ans.chains);
    var long = chains.filter(function (c) { return c.items.length > 1 || (c.top && c.top.missing); });
    var lone = chains.filter(function (c) { return long.indexOf(c) < 0; });
    if (long.length <= 1 && lone.length <= 1 && chains.length) {
      chains.forEach(function (c, i) { tracks.appendChild(rail(c, ans, pick, i + 1, chains.length > 1)); });
    } else {
      long.forEach(function (c, i) { tracks.appendChild(rail(c, ans, pick, i + 1, long.length > 1)); });
      if (lone.length) {
        tracks.appendChild(yard(long.length ? 'Other certificates' : 'Certificates', lone.map(function (c) { return c.items[0]; }), ans, pick,
                                lone.length + ' certificate(s), each by itself'));
      }
    }
    var rest = ans.things.filter(function (t) { return t.kind !== 'cert'; }).map(function (t) { return t.id; });
    if (rest.length) {
      var also = yard(chains.length ? 'Also in the file' : 'In the file', rest, ans, pick);
      if (chains.length) also.classList.add('also');
      tracks.appendChild(also);
    }
    page.appendChild(tracks);
    page.appendChild(shown);
    host.appendChild(page);
    stations = Array.prototype.slice.call(page.querySelectorAll('.cv-station[data-id]'));
    var first = o.pick || (chains.length ? chains[0].items[0] : (ans.things[0] && ans.things[0].id));
    if (first) pick(first);
  };

  CV.inspect = function (body) { return call(body); };
  CV.csrCard = function (t) { return csrCard(t, null, null); };

  /* ---- the popup ------------------------------------------------------------- */
  function wordsOf(e) { return String((e && e.message) || e || 'it went wrong'); }
  CV.open = function (o) {
    o = o || {};
    var held = {b64: o.data_b64 || '', name: o.filename || '', text: o.text || ''};
    var f = {};
    var ask, show;
    var sending = function (password, keyPassword, button) {
      var body = {filename: held.name || undefined, password: password || undefined, key_password: keyPassword || undefined};
      if (held.b64) body.data_b64 = held.b64; else body.text = held.text;
      if (!held.b64 && !String(held.text || '').trim()) { toast('drop a file or paste its text first', 'bad'); return; }
      if (button) busy(button, true);
      if (f.said) { f.said.className = 'cv-said'; f.said.textContent = tr('Reading it…'); }
      var ticket = modalTicket();
      call(body).then(function (ans) {
        if (!modalStill(ticket)) return;
        held.password = password;
        if (ans.password && ans.password.needed && !ans.things.length) { ask(ans); return; }
        show(ans);
      }).catch(function (e) {
        if (!modalStill(ticket)) return;
        if (button) busy(button, false);
        if (f.said) { f.said.className = 'cv-said bad'; f.said.textContent = wordsOf(e); } else toast(wordsOf(e), 'bad');
      });
    };
    var pwRow = function (ans, inside) {
      var box = el('div', 'cv-pw' + (ans.password.wrong ? ' wrong' : ''));
      var t = el('div', 'cv-pw-t');
      t.appendChild(icon('lock', 18));
      var w = el('div', '');
      w.appendChild(el('b', '', ans.password.wrong ? 'The password is wrong' : (inside ? 'Give the password to see everything' : 'The file is locked')));
      arr(ans.password.words).forEach(function (x) { w.appendChild(el('div', 'small', x)); });
      t.appendChild(w);
      box.appendChild(t);
      var row = el('div', 'cv-pw-row');
      var pw = secretBox('', 'the password of the file', 'mono');
      pw.autocomplete = 'off';
      var kp = secretBox('', 'the key’s own password, if it has another', 'mono');
      kp.autocomplete = 'off';
      var go = cmdButton('Open it', 'lock', 'primary');
      go.onclick = function () { sending(pw.value, kp.value, go); };
      [pw, kp].forEach(function (i) { i.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); go.click(); } }); });
      row.appendChild(pw);
      if (ans.format === 'jks' || ans.format === 'jceks') row.appendChild(kp);
      row.appendChild(go);
      box.appendChild(row);
      setTimeout(function () { try { pw.focus(); } catch (e) { } }, 0);
      return box;
    };
    var form = function (ans) {
      modal(o.title || 'Show a certificate', function (body) {
        var page = el('div', 'cv-page cv-ask');
        var lead = el('p', 'note', 'Any certificate, chain, request, CRL, key or keystore - PEM, CRT, CER, DER, P7B/P7C, PFX/P12, JKS, JCEKS, CSR, CRL, KEY, base64 or a ZIP of them. It is read and shown; nothing is kept and nothing changes. A private key is only described, never shown.');
        page.appendChild(lead);
        f.pw = el('div', 'cv-pwhost');
        if (ans) f.pw.appendChild(pwRow(ans, false));
        page.appendChild(f.pw);
        var cols = el('div', 'cv-ask-cols');
        var dz = (window.ACME_CERTS && window.ACME_CERTS.dropZone) ? window.ACME_CERTS.dropZone : null;
        var take = function (files) {
          var file = files[0];
          var r = new FileReader();
          r.onload = function () {
            var s = String(r.result || '');
            held.b64 = s.slice(s.indexOf(',') + 1);
            held.name = file.name;
            held.text = '';
            f.ta.value = '';
            f.drop._words.textContent = file.name + ' · ' + file.size + ' B';
            noI18n(f.drop._words);
            f.drop.classList.add('has');
            sending('', '', f.go);
          };
          r.onerror = function () { toast('the file could not be read', 'bad'); };
          r.readAsDataURL(file);
        };
        f.drop = dz ? dz('Drop the file here, or press to choose it', take, '', false) : el('div');
        f.drop.classList.add('cv-drop');
        var left = el('div', 'cv-ask-l');
        left.appendChild(f.drop);
        cols.appendChild(left);
        var right = el('div', 'cv-ask-r');
        right.appendChild(el('label', 'small muted', 'or paste it here'));
        f.ta = el('textarea', 'mono cv-paste');
        f.ta.rows = 9;
        f.ta.spellcheck = false;
        f.ta.placeholder = '-----BEGIN CERTIFICATE-----';
        f.ta.value = held.text || '';
        f.ta.addEventListener('input', function () {
          held.text = f.ta.value;
          if (f.ta.value.trim()) { held.b64 = ''; held.name = ''; f.drop.classList.remove('has'); }
        });
        right.appendChild(f.ta);
        cols.appendChild(right);
        page.appendChild(cols);
        f.said = el('div', 'cv-said');
        page.appendChild(f.said);
        body.appendChild(page);
      }, [{words: 'Close', close: true},
          {words: 'Show it', cls: 'primary', icon: 'eye', go: function (b) { f.go = b; sending(held.password || '', '', b); }}], 'certview');
      f.go = $('modal-foot') && $('modal-foot').querySelector('.btn.primary');
    };
    ask = function (ans) {
      if (!f.pw || !document.body.contains(f.pw)) { form(ans); return; }
      if (f.go) busy(f.go, false);
      if (f.said) { f.said.textContent = ''; }
      clear(f.pw);
      f.pw.appendChild(pwRow(ans, false));
    };
    show = function (ans) {
      var t0 = ans.things.filter(function (t) { return t.kind === 'cert'; })[0] || ans.things[0];
      var title = (o.title || 'Show a certificate');
      modal(title, function (body) {
        var before = null;
        if (ans.password && ans.password.needed) before = pwRow(ans, true);
        CV.render(body, ans, {before: before});
      }, [{words: 'Show another', icon: 'refresh', left: true, go: function () { held = {b64: '', name: '', text: ''}; f = {}; form(null); }},
          {words: 'Close', close: true, cls: 'primary'}], 'certview');
      var tt = $('modal-title');
      if (tt && t0) { clear(tt); tt.appendChild(document.createTextNode(tr(title) + ' · ')); tt.appendChild(data('span', '', t0.cn || t0.subject_dn || t0.issuer_cn || held.name || '')); }
    };
    var open = function () {
      if (held.b64 || String(held.text || '').trim()) {
        modal(o.title || 'Show a certificate', function (b) {
          var w = el('div', 'cv-wait');
          w.appendChild(icon('clock', 28));
          w.appendChild(el('p', '', 'Reading it…'));
          b.appendChild(w);
        }, [{words: 'Close', close: true}], 'certview');
        f.said = null;
        sending(o.password || '', '', null);
      } else form(null);
    };
    if ($('modal') && !$('modal').hidden) modalOver(open, o.back); else open();
  };
  function tr(words) {
    try { var got = typeof i18nText === 'function' ? i18nText(words) : null; return got || words; }
    catch (e) { return words; }
  }
  CV.tr = tr;
  CV.when = when;
  CV.keyLine = keyLine;
  CV.EKU = EKU;
})();
