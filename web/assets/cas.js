/* cas.js - an authority of acme's own changed after it was made: the popup
   "Edit…" (what is NOT inside its certificate: its name, the days it issues
   for, its CRL's days, the addresses put into what it signs, its default
   use, switched off, a note), "Renew its certificate…" (the same key and
   subject: a new validity, path length, name constraints) with "Install the
   answer…" for one under a CA elsewhere, and the section "Its certificates"
   (every version of it, with dates and fingerprints).

   certs.js draws the authority's popup (caPeek) and calls the parts added to
   window.ACME_CA_PEEK with its own pieces (caKit). The daemon's side is
   acmelib/certs/api_cas.py: POST cas/save, cas/renew, cas/install_cert,
   GET cas/versions, cas/dependents. Every question is asked in acme's own
   popup - never the browser's. */
'use strict';
(function () {
  function q(id) { return '?id=' + encodeURIComponent(String(id)); }
  function lines(v) { return String(v || '').split(/\n/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function note(text, cls) { return el('p', 'note' + (cls ? ' ' + cls : ''), text); }
  function saveText(text, file) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type: 'application/x-pem-file'}));
    a.download = file;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function fileName(c, tail) { return String(c.name || 'ca').replace(/[^A-Za-z0-9._-]+/g, '_') + tail; }
  function warnings(x) {
    (x && x.warnings || []).forEach(function (w) { toast(w, 'warn'); });
  }
  function spanDays(c) {
    if (!c.not_before || !c.not_after) return 3650;
    return Math.max(1, Math.round((Number(c.not_after) - Number(c.not_before) - 3600) / 86400));
  }

  /* ---- Edit… ------------------------------------------------------------- */
  function caEdit(c, d, kit) {
    var f = {};
    var pki = d.pki || {};
    var own = !!pki.own_urls;
    var names = kit.names().filter(function (n) { return n !== c.name; });
    modal('Edit ' + c.name, function (body) {
      body.appendChild(note('What an authority keeps beside its certificate: changed here at once, nothing has to be trusted anew. Its validity, path length and name constraints are inside its certificate - for those, Renew its certificate…'));
      var g = el('div', 'formgrid');
      f.name = textBox(c.name, 'Example Issuing CA', '');
      noI18n(f.name);
      var ni = formField('Name in acme', f.name, 'The sources that sign with it follow the new name, and so does its address on acme (/pki/) - the old address keeps answering, for the certificates that carry it.');
      ni.classList.add('ct-req');
      g.appendChild(ni);
      kit.guardName(f.name, true, names);
      f.days = kit.numberBox(c.days_default || 397, '397', 1, 36500);
      g.appendChild(formField('Issues for (days)', f.days, 'What a certificate it signs is valid for when nothing else is asked - never past its own end.'));
      f.crlDays = kit.numberBox(c.crl_days || 7, '7', 1, 365);
      g.appendChild(formField('CRL made anew every (days)', f.crlDays, 'How long each CRL is valid. The CRL is made again at once, and from then on at half that.'));
      body.appendChild(g);
      body.appendChild(el('h4', 'ct-formh', 'In what it signs from now on'));
      body.appendChild(note('Only certificates signed from now on carry these addresses; those signed before keep theirs until they are renewed.', 'small'));
      var pg = el('div', 'formgrid');
      f.own = switchBox(own);
      var of = formField('acme’s own addresses', f.own, 'Its CRL and certificate as acme publishes them at /pki/.');
      of.classList.add('wide');
      pg.appendChild(of);
      f.crlUrl = textBox(c.crl_url || '', 'http://pki.example.cz/issuing.crl', 'mono');
      noI18n(f.crlUrl);
      pg.appendChild(formField('CRL address', f.crlUrl, 'Empty: none.'));
      f.aia = textBox(c.aia_url || '', 'http://pki.example.cz/issuing.crt', 'mono');
      noI18n(f.aia);
      pg.appendChild(formField('AIA address', f.aia, 'Where its own certificate can be fetched. Empty: none.'));
      f.ocsp = textBox(c.ocsp_url || '', 'http://ocsp.example.cz/', 'mono');
      noI18n(f.ocsp);
      pg.appendChild(formField('OCSP address', f.ocsp, 'Of a responder of your own - acme runs none. Empty: none.'));
      var paint = function () {
        var on = !!f.own._get();
        f.crlUrl.disabled = on;
        f.aia.disabled = on;
        if (on && pki.urls) { f.crlUrl.value = pki.urls.crl || ''; f.aia.value = pki.urls.cert || ''; }
      };
      f.own.addEventListener('change', paint);
      paint();
      body.appendChild(pg);
      body.appendChild(el('h4', 'ct-formh', 'Signing'));
      var sg = el('div', 'formgrid');
      var ek = el('div', 'ct-ekus');
      var have = kit.arr(c.eku);
      f.eku = {};
      (kit.ekus || []).forEach(function (e) {
        var lab = el('label', 'set-check');
        var cb = el('input');
        cb.type = 'checkbox';
        cb.checked = have.indexOf(e[0]) >= 0;
        f.eku[e[0]] = cb;
        lab.appendChild(cb);
        lab.appendChild(el('span', '', e[1]));
        ek.appendChild(lab);
      });
      var ef = formField('Used for, when a request says nothing', ek, 'None ticked: TLS server and TLS client. A source sets its own.');
      ef.classList.add('wide');
      sg.appendChild(ef);
      f.off = switchBox(!!kit.truthy(c.disabled));
      var offField = formField('Switched off', f.off, 'It signs nothing while it is off. Its CRL is still made and published - what it signed before is still checked against it.');
      offField.classList.add('wide');
      sg.appendChild(offField);
      f.offSaid = el('div');
      offField.appendChild(f.offSaid);
      f.off.addEventListener('change', function () {
        clear(f.offSaid);
        if (!f.off._get() || kit.truthy(c.disabled)) return;
        kit.api('cas/dependents' + q(c.id)).then(function (x) {
          var parts = [];
          if (x.sources && x.sources.length) parts.push(['Sources', x.sources.join(', ')]);
          if (x.certs && x.certs.length) parts.push(['Certificates', x.certs.slice(0, 20).join(', ') + (x.certs.length > 20 ? ' …' : '')]);
          if (x.children && x.children.length) parts.push(['Authorities under it', x.children.join(', ')]);
          if (!parts.length) return;
          f.offSaid.appendChild(note('These rely on it - their renewals fail while it is off:', 'warn'));
          f.offSaid.appendChild(kvTable(parts.map(function (p) { return [p[0], kit.data('span', 'small mono', p[1])]; })));
        }).catch(function () { });
      });
      f.note = kit.areaBox(c.note || '', 'what it is for, who looks after it', 3, '');
      var nf = formField('Note', f.note);
      nf.classList.add('wide');
      sg.appendChild(nf);
      body.appendChild(sg);
    }, [{words: 'Close', close: true}, {words: 'Save', cls: 'primary', icon: 'save', go: function (b) {
      var name = f.name.value.trim();
      if (!name) { toast('it needs a name', 'bad'); f.name.focus(); return; }
      var body = {id: c.id, name: name, days_default: Number(f.days.value || 397),
        crl_days: Number(f.crlDays.value || 7), note: f.note.value, disabled: !!f.off._get(),
        ocsp_url: f.ocsp.value.trim(),
        eku: Object.keys(f.eku).filter(function (k) { return f.eku[k].checked; })};
      if (f.own._get()) { body.crl_url = 'own'; body.aia_url = 'own'; } else { body.crl_url = f.crlUrl.value.trim(); body.aia_url = f.aia.value.trim(); }
      busy(b, true);
      kit.api('cas/save', body).then(function (x) {
        toast(kit.said(x, 'saved'), 'good');
        warnings(x);
        closeModal();
        kit.loadCas();
      }).catch(kit.fail).then(function () { busy(b, false); });
    }}], 'medium');
  }

  /* ---- Renew its certificate… ------------------------------------------- */
  function caRenew(c, d, kit) {
    var f = {};
    var root = !!c.root;
    var elsewhere = !root && (c.external && kit.truthy(c.external) || !c.parent_id);
    modal('Renew the certificate of ' + c.name, function (body) {
      if (root) {
        body.appendChild(note('A root signs itself again - with the same key and the same name: a new serial number and new dates. What it signed stays valid: it verifies against the old certificate and the new one alike.'));
        var w = el('p', 'note warn');
        w.appendChild(el('b', '', 'Machines trust the certificate, not the key. '));
        w.appendChild(el('span', '', 'Give the new one to everything that trusts this root (Group Policy, the trust stores, MDM, Java) before the old one ends: '));
        w.appendChild(kit.data('b', '', kit.dayOnly(c.not_after)));
        body.appendChild(w);
      } else if (elsewhere) {
        body.appendChild(note('Its parent is a CA elsewhere: acme makes a request with the same key and the same name. Have it signed there (on AD CS with the Subordinate Certification Authority template) and install what comes back - until then it keeps signing with the certificate it has.'));
      } else {
        body.appendChild(note('It is signed again by the authority above it, with the same key and the same name. What it signed stays valid and nothing has to be trusted anew; the authorities under it get the new one in their chains, and servers send it once their certificates are renewed or deployed again.'));
      }
      var g = el('div', 'formgrid');
      f.days = kit.numberBox(spanDays(c), '3650', 1, 36500);
      g.appendChild(formField('Valid for (days)', f.days, root ? '10 years is usual for a root.' : 'Never past the end of the authority above it.'));
      var pl = c.path_len === null || c.path_len === undefined || c.path_len === '' || Number(c.path_len) < 0 ? '' : c.path_len;
      f.path = kit.numberBox(pl, 'no limit', 0, 9);
      g.appendChild(formField('Path length', f.path, 'How many authorities may still come under it. 0: it signs only certificates. Empty: no limit.'));
      f.nc = kit.areaBox(kit.arr(c.name_constraints).join('\n'), 'permitted;DNS:.example.cz\npermitted;IP:10.0.0.0/8\nexcluded;DNS:.public.example.cz', 3, 'mono');
      noI18n(f.nc);
      var nf = formField('Name constraints', f.nc, 'One a line. Narrower ones apply to what it signs from now on; a client checks what it signed before against the certificate it is given.');
      nf.classList.add('wide');
      g.appendChild(nf);
      body.appendChild(g);
      body.appendChild(note('A new key is a new authority: for that, create a new intermediate (or root) and move the sources to it.', 'small'));
    }, [{words: 'Close', close: true}, {words: elsewhere ? 'Make the request' : 'Renew it', cls: 'primary', icon: 'refresh', go: function (b) {
      var body = {id: c.id, days: Number(f.days.value || spanDays(c)),
        path_len: f.path.value === '' ? null : Number(f.path.value), name_constraints: lines(f.nc.value)};
      busy(b, true);
      kit.api('cas/renew', body, 120).then(function (x) {
        if (x.pending) { renewRequest(c, x.csr_pem, kit); kit.loadCas(); return; }
        toast(kit.said(x, 'renewed'), 'good');
        warnings(x);
        closeModal();
        kit.loadCas();
      }).catch(kit.fail).then(function () { busy(b, false); });
    }}], 'medium');
  }
  function renewRequest(c, csr, kit) {
    modal('The request of ' + c.name, function (body) {
      body.appendChild(note('Its own key, its own name: have it signed by the CA above it, then Install the answer… in its popup.'));
      var ta = kit.areaBox(csr, '', 10, 'mono ct-csr');
      ta.readOnly = true;
      noI18n(ta);
      body.appendChild(ta);
      var row = el('div', 'btnrow');
      var cp = cmdButton('Copy', 'copy', 'small');
      cp.onclick = function () { copyText(csr, cp, 'on the clipboard'); };
      row.appendChild(cp);
      var dl = cmdButton('Download', 'download', 'small');
      dl.onclick = function () { saveText(csr, fileName(c, '-renewal.csr')); };
      row.appendChild(dl);
      body.appendChild(row);
    }, [{words: 'Close', close: true}], 'medium');
  }
  function caInstall(c, kit) {
    var f = {};
    modal('Install the answer for ' + c.name, function (body) {
      body.appendChild(note('The certificate the CA above it signed for its request (PEM; a chain after it is taken too). It must be for its key and its name.'));
      f.cert = kit.pemBox('', '-----BEGIN CERTIFICATE-----', 6);
      body.appendChild(kit.wideField('The certificate', f.cert));
      f.chain = kit.pemBox('', 'the authorities above it - empty: as it was', 3);
      body.appendChild(kit.wideField('Chain', f.chain));
    }, [{words: 'Close', close: true}, {words: 'Install', cls: 'primary', icon: 'upload', go: function (b) {
      if (!f.cert._get()) { toast('paste the certificate', 'bad'); return; }
      busy(b, true);
      kit.api('cas/install_cert', {id: c.id, cert_pem: f.cert._get(), chain_pem: f.chain._get() || undefined}).then(function (x) {
        toast(kit.said(x, 'installed'), 'good');
        closeModal();
        kit.loadCas();
      }).catch(kit.fail).then(function () { busy(b, false); });
    }}], 'medium');
  }

  /* ---- Its certificates: every version ---------------------------------- */
  function versionsSection(c, back, grid, kit) {
    var sec = kit.section('Its certificates', 'Every certificate it has had - renewed with the same key and name, so what it signed verifies against each of them while it is valid.', true);
    var host = el('div');
    host.appendChild(el('p', 'muted small', 'Asking…'));
    sec._body.appendChild(host);
    if (c.renew_csr_pem) {
      var p = note('A request for its renewal waits for the CA above it.', 'warn');
      var again = cmdButton('Show the request', 'download', 'small');
      again.onclick = function () { kit.over(function () { renewRequest(c, c.renew_csr_pem, kit); }, back); };
      p.appendChild(again);
      sec._body.insertBefore(p, host);
    }
    grid.appendChild(sec);
    kit.api('cas/versions' + q(c.id)).then(function (x) {
      clear(host);
      var rows = x.rows || [];
      host.appendChild(listTable(['Version', 'Serial', 'Valid', 'SHA-256', 'Path length', 'State', 'Why', ''], rows, function (v) {
        var r = el('tr');
        r.appendChild(kit.td('', String(v.version || '')));
        r.appendChild(kit.td('', kit.data('span', 'mono small', v.serial || '')));
        r.appendChild(kit.td('small', kit.dayOnly(v.not_before) + ' – ' + kit.dayOnly(v.not_after)));
        r.appendChild(kit.td('', v.fingerprint ? kit.copyable(kit.fpWords(v.fingerprint).slice(0, 23) + '…', 'the fingerprint was copied') : '–'));
        r.appendChild(kit.td('small', v.path_len === null || v.path_len === undefined || Number(v.path_len) < 0 ? 'no limit' : String(v.path_len)));
        var st = el('td');
        if (v.current) st.appendChild(el('span', 'tag ok', 'now'));
        else if (v.valid) st.appendChild(el('span', 'tag info', 'still valid'));
        else st.appendChild(el('span', 'tag dim', 'has ended'));
        r.appendChild(st);
        var why = el('td', 'small');
        why.appendChild(el('span', '', v.why || ''));
        if (v.by_who) why.appendChild(kit.data('span', 'muted', ' · ' + v.by_who));
        r.appendChild(why);
        var tools = el('td', 'rowtools');
        if (v.cert_pem) {
          var dl = iconButton('download', 'Download this certificate (PEM)');
          dl.onclick = function (ev) { ev.stopPropagation(); saveText(v.cert_pem, fileName(c, '-v' + v.version + '.crt')); };
          tools.appendChild(dl);
        }
        r.appendChild(tools);
        return r;
      }, 'plain|No certificate yet'));
    }).catch(function () { clear(host); host.appendChild(el('p', 'muted small', 'Its versions could not be asked for.')); });
  }

  var part = {
    buttons: function (c, d, back, list, kit) {
      if (!kit.full) return;
      var at = list.length - 1;     /* before the primary button (Sign a CSR) */
      var add = [{words: 'Edit…', icon: 'edit', go: function () { kit.over(function () { caEdit(c, d, kit); }, back); }}];
      if (!c.pending) add.push({words: 'Renew its certificate…', icon: 'refresh', go: function () { kit.over(function () { caRenew(c, d, kit); }, back); }});
      if (c.renew_csr_pem || c.pending) add.push({words: 'Install the answer…', icon: 'upload', go: function () { kit.over(function () { caInstall(c, kit); }, back); }});
      Array.prototype.splice.apply(list, [Math.max(1, at), 0].concat(add));
    },
    sections: function (c, d, back, grid, kit) {
      if (c.pending) return;
      versionsSection(c, back, grid, kit);
    }
  };
  window.ACME_CA_PEEK = window.ACME_CA_PEEK || [];
  window.ACME_CA_PEEK.push(part);
}());
