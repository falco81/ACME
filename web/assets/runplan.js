/* runplan.js - "What happens": a certificate's run plan (1.0.20), in the
   page's largest popup. Opened only by a button - in an opened certificate
   (its footer, and beside Details) and on the last step of the wizard - over
   the popup it came from; Close goes back to it.

   GET /api/certs/run_plan?id= for a certificate as saved, POST {id?, draft}
   for the wizard's values (nothing saved). The daemon works it out without
   doing or contacting anything (acmelib/certs/runplan.py): every step of a
   renewal in phases - the key and the request, the source, the validation of
   each name, each deployment, what comes after - each step with its kind,
   words, and the exact call, command, file or record, secrets masked.

   Drawn with the page's own pieces (core.js: modal, el, noI18n, kvTable,
   cmdButton, iconMarkup, explain, copyText) and its colours (acme.css); the
   data (URLs, commands, JSON, paths) is never translated. */
'use strict';
(function () {
  var RP = window.ACME_RUNPLAN = window.ACME_RUNPLAN || {};

  ICONS.rpfile = '<path d="M6 3.5h8l4 4V20a.5.5 0 0 1-.5.5h-11A.5.5 0 0 1 6 20z"/><path d="M14 3.5V8h4"/><path d="M9 13h6M9 16.5h4"/>';
  ICONS.rpcall = '<path d="M4 12h12"/><path d="M12 7l5 5-5 5"/><path d="M20 5v14"/>';
  ICONS.rpread = '<path d="M20 12H8"/><path d="M12 7l-5 5 5 5"/><path d="M4 5v14"/>';
  ICONS.rpdns = '<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17"/><path d="M12 3.5c2.6 2.6 3.6 5.4 3.6 8.5s-1 5.9-3.6 8.5c-2.6-2.6-3.6-5.4-3.6-8.5s1-5.9 3.6-8.5z"/>';
  ICONS.rpsign = '<path d="M4 19.5h16"/><path d="M6 15.5l9.5-9.5 3 3L9 18.5H6z"/>';
  ICONS.rpstop = '<path d="M8.2 3.5h7.6l4.7 4.7v7.6l-4.7 4.7H8.2l-4.7-4.7V8.2z"/><path d="M12 8v5"/><path d="M12 16.2v.3"/>';

  var KINDS = {
    call: {icon: 'rpcall', words: 'a call to a device or an API', cls: 'call'},
    read: {icon: 'rpread', words: 'a question asked (nothing changes)', cls: 'read'},
    connect: {icon: 'plug', words: 'signing in, connecting', cls: 'connect'},
    file: {icon: 'rpfile', words: 'a file written or uploaded', cls: 'file'},
    command: {icon: 'terminal', words: 'a command run', cls: 'command'},
    dns: {icon: 'rpdns', words: 'a DNS record or question', cls: 'dns'},
    wait: {icon: 'clock', words: 'waiting', cls: 'wait'},
    check: {icon: 'check', words: 'a check', cls: 'check'},
    key: {icon: 'key', words: 'a key', cls: 'key'},
    sign: {icon: 'rpsign', words: 'something signed', cls: 'sign'},
    mail: {icon: 'mail', words: 'a message', cls: 'mail'},
    'delete': {icon: 'trash', words: 'something deleted', cls: 'delete'},
    save: {icon: 'save', words: 'saved, kept', cls: 'save'},
    info: {icon: 'info', words: 'what is so', cls: 'info'},
    stop: {icon: 'rpstop', words: 'cannot be told from here', cls: 'stop'}
  };
  var LEGEND = ['call', 'read', 'connect', 'file', 'command', 'dns', 'wait', 'check', 'key', 'sign', 'delete', 'save'];
  var PHASE_ICON = {key: 'key', source: 'source', validation: 'proof', deploy: 'deploy', checks: 'check', after: 'history'};
  var PHASE_LEDE = {
    key: 'Made here, on this machine, before anything is asked.',
    source: 'Where the certificate comes from, and every question asked of it.',
    validation: 'How each name is proved: what is put where, waited for, and taken away again.',
    deploy: 'Where it goes, in the order of its deployments: how acme connects, and everything it does there.',
    after: 'Who is told, and what happens next time.'
  };
  /* a certificate whose key the device makes (certs.csr_from): nothing is made here */
  var LEDE_DEVICE_KEY = 'Made on the device that keeps it: it makes the key and the request (CSR), the key never leaves it.';

  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function tr(words) {
    try { var got = typeof i18nText === 'function' ? i18nText(words) : null; return got || words; }
    catch (e) { return words; }
  }
  function icon(key, size, cls) {
    var s = el('span', cls || 'rp-ic');
    s.innerHTML = iconMarkup(key, size || 16);
    return s;
  }
  function call(o) {
    var capi = window.ACME_CERTS && window.ACME_CERTS.api;
    var go = capi || function (p, b) { return api(p.replace('?', '&'), b); };
    if (o.draft) return go('certs/run_plan', {id: o.id || undefined, draft: o.draft}, 180);
    return go('certs/run_plan?id=' + encodeURIComponent(o.id), undefined, 180);
  }

  /* ---- a piece of data, with its copy button -------------------------- */
  /* JSON as a person reads it: short objects and lists on one line. */
  function pretty(v) {
    if (v === null || v === undefined) return '';
    if (typeof v === 'string') return v;
    var flat = function (x) {
      if (x === null || typeof x !== 'object') return JSON.stringify(x);
      if (Array.isArray(x)) return '[' + x.map(flat).join(', ') + ']';
      return '{' + Object.keys(x).map(function (k) { return JSON.stringify(k) + ': ' + flat(x[k]); }).join(', ') + '}';
    };
    var go = function (x, ind) {
      var f = flat(x);
      if (x === null || typeof x !== 'object' || f.length + ind.length <= 96) return f;
      var pad = ind + '  ';
      if (Array.isArray(x)) return '[\n' + x.map(function (y) { return pad + go(y, pad); }).join(',\n') + '\n' + ind + ']';
      return '{\n' + Object.keys(x).map(function (k) { return pad + JSON.stringify(k) + ': ' + go(x[k], pad); }).join(',\n') + '\n' + ind + '}';
    };
    return go(v, '');
  }
  function copyBtn(text, title) {
    var b = iconButton('copy', title || 'Copy');
    b.classList.add('rp-copy');
    b.onclick = function (ev) { ev.stopPropagation(); copyText(text, b); };
    return b;
  }
  function codeBlock(text, cls, label) {
    var box = el('div', 'rp-code' + (cls ? ' ' + cls : ''));
    if (label) box.appendChild(el('div', 'rp-code-h', label));
    /* The stand-ins ‹…› are words, the rest is data (1.0.20): only they are translated. */
    text = String(text == null ? '' : text).replace(/‹([^‹›]{1,120})›/g, function (m, w) { return '‹' + tr(w) + '›'; })
      .replace(/•••• \(([^()]{1,80})\)/g, function (m, w) { return '•••• (' + tr(w) + ')'; });
    var pre = data('pre', 'mono');
    pre.textContent = text;
    box.appendChild(pre);
    box.appendChild(copyBtn(text));
    var lines = String(text).split('\n').length;
    if (lines > 16) {
      box.classList.add('folded');
      var more = el('button', 'btn small rp-more', '');
      more.type = 'button';
      var say = function () {
        clear(more);
        more.appendChild(el('span', '', box.classList.contains('folded') ? 'Show all' : 'Show less'));
        if (box.classList.contains('folded')) more.appendChild(data('span', 'rp-more-n', ' (' + lines + ')'));
      };
      say();
      more.onclick = function () { box.classList.toggle('folded'); say(); };
      box.appendChild(more);
    }
    return box;
  }
  function connRow(conn) {
    var cn = el('div', 'rp-conn');
    conn.forEach(function (c) {
      var chip = el('span', 'rp-conn-c' + (c[2] ? ' t-' + c[2] : ''));
      chip.appendChild(el('span', 'rp-conn-k', c[0]));
      var words = /^(yes|no|none|not |checked|Settings|UDP|TSIG|signed)/.test(String(c[1]));
      chip.appendChild(words ? el('span', 'rp-conn-v', c[1]) : data('span', 'rp-conn-v mono', c[1]));
      cn.appendChild(chip);
    });
    return cn;
  }
  function httpBlock(d) {
    var box = el('div', 'rp-http');
    var line = el('div', 'rp-http-line');
    line.appendChild(data('span', 'rp-method m-' + String(d.method || 'GET').toLowerCase(), d.method || 'GET'));
    line.appendChild(data('span', 'mono rp-url', d.url || ''));
    line.appendChild(copyBtn((d.method || 'GET') + ' ' + (d.url || '')));
    box.appendChild(line);
    /* the request as it goes on the wire (1.0.37): every header - the ones acme and
       Python add dimmed - and the body exactly as sent */
    /* how it is connected (1.0.37): address, TLS, SNI, the device's certificate, proxy */
    if (d.conn && d.conn.length) { var cr = connRow(d.conn); cr.classList.add('rp-dbg'); box.appendChild(cr); }
    var wire = d.wire && d.wire.headers ? d.wire : null;
    if (wire) {
      var ws = el('div', 'rp-hdrs rp-wire rp-dbg');
      ws.appendChild(data('span', 'rp-hdr mono rp-wire-line', wire.line || ''));
      wire.headers.forEach(function (h) {
        var row = data('span', 'rp-hdr mono' + (h[2] ? ' auto' : ''));
        row.appendChild(el('b', '', h[0] + ':'));
        row.appendChild(document.createTextNode(' ' + h[1]));
        if (h[2]) explain(row, tr('Added by acme for every request') + (/^≈/.test(String(h[1])) ? '. ' + tr('Worked out from a recording with stand-ins for the certificate and the secrets: the real length differs.') : ''));
        ws.appendChild(row);
      });
      box.appendChild(ws);
      var raw = [wire.line].concat(wire.headers.map(function (h) { return h[0] + ': ' + h[1]; })).join('\n') +
                '\n\n' + (wire.body === null || wire.body === undefined ? '' : String(wire.body));
      var cw = copyBtn(raw, tr('Copy the whole request'));
      cw.classList.add('rp-dbg');
      line.appendChild(cw);
      /* debug off: the headers the module set, as before */
      var mine = Object.keys(d.headers || {});
      if (mine.length) {
        var hp = el('div', 'rp-hdrs rp-nodbg');
        mine.forEach(function (k) {
          var h = data('span', 'rp-hdr mono');
          h.appendChild(el('b', '', k + ':'));
          h.appendChild(document.createTextNode(' ' + d.headers[k]));
          hp.appendChild(h);
        });
        box.appendChild(hp);
      }
      if (wire.body !== null && wire.body !== undefined && wire.body !== '') box.appendChild(codeBlock(pretty(d.body !== undefined && d.body !== null ? d.body : wire.body), 'rp-body', 'Body'));
      return box;
    }
    var hk = Object.keys(d.headers || {});
    if (hk.length) {
      var hs = el('div', 'rp-hdrs');
      hk.forEach(function (k) {
        var h = data('span', 'rp-hdr mono');
        h.appendChild(el('b', '', k + ':'));
        h.appendChild(document.createTextNode(' ' + d.headers[k]));
        hs.appendChild(h);
      });
      box.appendChild(hs);
    }
    if (d.body !== null && d.body !== undefined && d.body !== '') box.appendChild(codeBlock(pretty(d.body), 'rp-body', 'Body'));
    return box;
  }
  function pairsTable(pairs) {
    return kvTable((pairs || []).map(function (p) {
      var v = p[1];
      var shown = v === undefined || v === null || v === '' ? '–' : String(v);
      /* a value in words (not shown, yes, none pinned...) is translated; data never */
      var node = p[2] === 'words' ? el('span', 'rp-val', shown) : data('span', 'mono rp-val', shown);
      return [p[0], node];
    }));
  }
  function filesTable(files) {
    var t = el('table', 'plain tight rp-files');
    var hd = el('tr');
    ['Path', 'What', 'Mode', 'Owner', 'Size'].forEach(function (h) { hd.appendChild(el('th', '', h)); });
    var th = el('thead');
    th.appendChild(hd);
    t.appendChild(th);
    var tb = el('tbody');
    files.forEach(function (f) {
      var tr_ = el('tr');
      var p = el('td');
      p.appendChild(data('span', 'mono', f.full || f.path || ''));
      if (f.key) {
        var k = el('span', 'tag crit rp-tag', 'private key');
        p.appendChild(k);
      }
      tr_.appendChild(p);
      tr_.appendChild(el('td', 'muted', f.title || f.format || ''));
      tr_.appendChild(data('td', 'mono', f.mode || '–'));
      tr_.appendChild(data('td', 'mono', f.owner || '–'));
      tr_.appendChild(data('td', 'mono', f.size ? (f.exact === false ? '≈ ' : '') + bytes(f.size) : '–'));
      tb.appendChild(tr_);
    });
    t.appendChild(tb);
    var wrap = el('div', 'rp-files-wrap');
    wrap.appendChild(t);
    return wrap;
  }
  function fileFacts(d) {
    var box = el('div', 'rp-filefacts');
    var top = el('div', 'rp-http-line');
    top.appendChild(data('span', 'mono rp-url', d.path || ''));
    if (d.path) top.appendChild(copyBtn(d.path));
    box.appendChild(top);
    var chips = el('div', 'rp-chips');
    var chip = function (label, value) {
      if (value === undefined || value === null || value === '') return;
      var c = el('span', 'rp-chip');
      c.appendChild(el('span', 'muted', label));
      c.appendChild(data('b', 'mono', String(value)));
      chips.appendChild(c);
    };
    if (d.format) {
      var f = el('span', 'rp-chip');
      f.appendChild(el('span', 'muted', 'format'));
      f.appendChild(el('b', '', d.format));
      chips.appendChild(f);
    }
    chip('mode', d.mode);
    chip('owner', d.owner);
    if (d.size) chip('size', bytes(d.size));
    if (d.via === 'scp') chip('by', 'scp');
    if (chips.firstChild) box.appendChild(chips);
    if (d.text) box.appendChild(codeBlock(d.text));
    if (d.body) box.appendChild(codeBlock(d.body, 'rp-body', 'What it holds'));
    return box;
  }
  function recordBlock(r) {
    var text = [r.name, r.ttl ? String(r.ttl) : '', 'IN', r.type, r.value ? '"' + r.value + '"' : ''].filter(Boolean).join(' ');
    return codeBlock(text);
  }
  /* Bytes taken apart, as Wireshark shows a packet (1.0.37): its fields as a tree, its
     bytes under it - a field pointed at lights its bytes up. */
  function packetView(pk) {
    var box = el('div', 'rp-pkt');
    var h = el('div', 'rp-pkt-h');
    h.appendChild(data('span', 'rp-pkt-proto', (pk.proto || 'bytes').toUpperCase()));
    h.appendChild(data('span', 'rp-pkt-sum', pk.title || pk.summary || ''));
    h.appendChild(data('span', 'rp-pkt-n muted', pk.bytes + ' B'));
    box.appendChild(h);
    var cells = [];
    var bytesBox = el('div', 'rp-pkt-bytes mono');
    (pk.cells || []).forEach(function (c, i) {
      if (i % 16 === 0) {
        if (i) bytesBox.appendChild(el('br'));
        bytesBox.appendChild(data('span', 'rp-pkt-off', ('000' + i.toString(16)).slice(-4) + '  '));
      }
      var sp = data('span', 'rp-pkt-b' + (c === '••' ? ' hid' : ''), c);
      cells.push(sp);
      bytesBox.appendChild(sp);
      bytesBox.appendChild(document.createTextNode(i % 16 === 7 ? '  ' : ' '));
    });
    var light = function (off, ln, on) {
      for (var i = off; i < off + ln && i < cells.length; i++) cells[i].classList.toggle('lit', on);
    };
    if ((pk.fields || []).length) {
      var tree = el('div', 'rp-pkt-tree');
      pk.fields.forEach(function (f) {
        var row = el('div', 'rp-pkt-f' + (f[4] !== '' && f[4] !== undefined ? ' has-v' : '') + (/^\[Malformed/.test(f[3]) ? ' bad' : ''));
        row.style.paddingLeft = (8 + f[0] * 16) + 'px';
        row.appendChild(data('span', 'rp-pkt-k', f[3]));
        if (f[4] !== '' && f[4] !== undefined) {
          row.appendChild(data('span', 'rp-pkt-v mono', f[4]));
        }
        row.appendChild(data('span', 'rp-pkt-at muted mono', '[' + f[1] + (f[2] > 1 ? '..' + (f[1] + f[2] - 1) : '') + ']'));
        row.onmouseenter = function () { light(f[1], f[2], true); };
        row.onmouseleave = function () { light(f[1], f[2], false); };
        tree.appendChild(row);
      });
      box.appendChild(tree);
    }
    box.appendChild(bytesBox);
    return box;
  }
  function detailOf(st) {
    var d = st.detail;
    if (!d) return null;
    if (d.packets && d.packets.length) {
      var pw = el('div', 'rp-pkts');
      if (d.text) pw.appendChild(codeBlock(d.text));
      d.packets.forEach(function (pk) { pw.appendChild(packetView(pk)); });
      return pw;
    }
    if (d.url) return httpBlock(d);
    /* an SSH connection (1.0.37): its facts, then the ssh command as it runs, folded */
    if (d.pairs && d.command) {
      var sw = el('div', 'rp-pairs');
      sw.appendChild(pairsTable(d.pairs));
      var how = el('details', 'rp-raw rp-dbg');
      how.appendChild(el('summary', 'small muted', 'The ssh command, as it runs'));
      how.appendChild(codeBlock(d.command, 'rp-shell'));
      sw.appendChild(how);
      return sw;
    }
    if (d.conn && d.conn.length) {
      var wrapc = el('div', 'rp-withconn');
      var crw = connRow(d.conn);
      crw.classList.add('rp-dbg');
      wrapc.appendChild(crw);
      var inner = detailOf({detail: Object.assign({}, d, {conn: null})});
      if (inner) wrapc.appendChild(inner);
      return wrapc;
    }
    if (d.files) return filesTable(d.files);
    if (d.command) {
      var b = el('div', 'rp-cmd');
      /* The script of -EncodedCommand, readable (1.0.23); the command as it is sent stays
         above, folded - it is base64 nobody reads. */
      if (d.script) {
        b.appendChild(codeBlock(d.script, 'rp-ps', tr('PowerShell, as it runs')));
        var raw = el('details', 'rp-raw');
        raw.appendChild(el('summary', 'small muted', 'The command as it is sent (encoded)'));
        raw.appendChild(codeBlock(d.command, 'rp-shell'));
        b.appendChild(raw);
      } else b.appendChild(codeBlock(d.command, 'rp-shell'));
      if (d.input) b.appendChild(data('div', 'mono small muted rp-input', '< ' + d.input));
      return b;
    }
    if (d.record) return recordBlock(d.record);
    if (d.pairs) {
      var w = el('div', 'rp-pairs');
      w.appendChild(pairsTable(d.pairs));
      if (d.script) w.appendChild(codeBlock(d.script, 'rp-body', 'The script'));
      return w;
    }
    if (d.path) return fileFacts(d);
    if (d.text) return codeBlock(d.text);
    return null;
  }

  /* ---- one step ----------------------------------------------------------- */
  function stepRow(st, n) {
    if (st.kind === 'head') {
      var h = el('div', 'rp-sub');
      h.appendChild(el('span', '', st.words));
      return h;
    }
    var k = KINDS[st.kind] || KINDS.info;
    var row = el('div', 'rp-step k-' + k.cls + (st.branch ? ' branched' : ''));
    var mark = el('div', 'rp-mark');
    mark.appendChild(icon(k.icon, 15));
    explain(mark, k.words);
    row.appendChild(mark);
    var w = el('div', 'rp-w');
    var top = el('div', 'rp-top');
    top.appendChild(data('span', 'rp-n', n));
    top.appendChild(el('span', 'rp-words', st.words || ''));
    w.appendChild(top);
    var tags = el('span', 'rp-tags');
    if (st.branch) {
      var b = el('span', 'tag warn rp-tag', st.branch);
      tags.appendChild(b);
    }
    if (st.invented) {
      var iv = el('span', 'tag info rp-tag', 'the answer decides');
      explain(iv, 'Worked out without asking: what the device, the CA or DNS answers at the time decides what follows. Here it was taken as the first time - nothing there yet.');
      tags.appendChild(iv);
    }
    if (st.secret) tags.appendChild(el('span', 'tag crit rp-tag', 'holds the private key'));
    if (tags.firstChild) top.appendChild(tags);
    if (st.note) w.appendChild(el('div', 'rp-note', st.note));
    var det = detailOf(st);
    if (det) {
      if (st.debug) det.classList.add('rp-dbg');      /* a test's facts: debug details only */
      w.appendChild(det);
    }
    row.appendChild(w);
    return row;
  }
  function stepList(steps, prefix) {
    var box = el('div', 'rp-steps');
    var i = 0;
    (steps || []).forEach(function (st) {
      if (st.kind !== 'head') i += 1;
      box.appendChild(stepRow(st, prefix + '.' + i));
    });
    return box;
  }

  /* ---- a group: one validation, one deployment ------------------------- */
  /* the module's setup guide, of its version (1.0.95): how the other side is set up */
  function guideBtn(m) {
    if (!m || !m.family || !m.kind || !window.ACME_GUIDES) return null;
    var b = el('button', 'rp-guide');
    b.type = 'button';
    b.title = tr('Setup guide') + ' - ' + (m.title || m.kind);
    b.appendChild(icon('book', 13));
    b.appendChild(el('span', '', 'Setup guide'));
    b.onclick = function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      /* the module as the page knows it - its versions to choose among (1.0.96) */
      var p = (typeof plugOf === 'function' && plugOf(m.family, m.kind)) || {kind: m.kind, title: m.title || m.kind};
      window.ACME_GUIDES.show(p, m.family, m.version || '', {over: true});
    };
    return b;
  }
  function moduleChip(m) {
    var c = el('span', 'rp-mod');
    c.appendChild(data('b', '', m.name));
    c.appendChild(el('span', 'muted', m.title || m.kind));
    var gb = guideBtn(m);
    if (gb) c.appendChild(gb);
    return c;
  }
  function factsFold(title, pairs, open) {
    if (!pairs || !pairs.length) return null;
    var d = el('details', 'rp-facts');
    if (open) d.open = true;
    var s = el('summary', '');
    s.appendChild(icon('gear', 14));
    s.appendChild(el('span', '', title));
    s.appendChild(data('span', 'rp-count', String(pairs.length)));
    d.appendChild(s);
    d.appendChild(pairsTable(pairs));
    return d;
  }
  function groupCard(g, prefix, kind) {
    var card = el('section', 'rp-group' + (g.off || g.enabled === false ? ' off' : ''));
    var head = el('div', 'rp-group-h');
    head.appendChild(icon(kind === 'deploy' ? 'target' : kind === 'checks' ? 'check' : 'proof', 18, 'rp-gic'));
    var t = el('div', 'rp-group-t');
    var line = el('div', 'rp-group-name');
    line.appendChild(data('b', '', g.title));
    if (g.module) line.appendChild(el('span', 'tag info rp-tag', g.module.title || g.module.kind));
    var gb = g.module && guideBtn(g.module);
    if (gb) line.appendChild(gb);
    if (g.off) line.appendChild(el('span', 'tag warn rp-tag', kind === 'checks' ? 'the test is switched off' : 'the target is switched off'));
    else if (g.enabled === false) line.appendChild(el('span', 'tag warn rp-tag', 'switched off: skipped'));
    t.appendChild(line);
    if (g.host) t.appendChild(data('div', 'mono small muted', g.host));
    if (g.names) {
      var nb = el('div', 'rp-names');
      g.names.forEach(function (n) { nb.appendChild(data('span', 'rp-name', n)); });
      t.appendChild(nb);
    }
    head.appendChild(t);
    card.appendChild(head);
    var facts = el('div', 'rp-group-facts');
    var f1 = factsFold(kind === 'deploy' ? 'The target\'s settings' : kind === 'checks' ? 'The test\'s settings' : 'The validation\'s settings', g.facts);
    if (f1) facts.appendChild(f1);
    var f2 = factsFold('This deployment\'s options', g.options);
    if (f2) facts.appendChild(f2);
    if (facts.firstChild) card.appendChild(facts);
    if (g.per_name) {
      var pn = el('div', 'rp-pername' + (g.per_name.length > 1 ? ' many' : ''));
      g.per_name.forEach(function (p) {
        var col = el('div', 'rp-pn');
        if (g.per_name.length > 1 || (g.names || []).length > 1) {
          var nh = el('div', 'rp-forname');
          nh.appendChild(el('span', 'muted', 'For'));
          nh.appendChild(data('b', 'mono', p.name));
          col.appendChild(nh);
        }
        col.appendChild(stepList(p.steps, prefix));
        pn.appendChild(col);
      });
      card.appendChild(pn);
      if (g.more) card.appendChild(el('p', 'muted small rp-morenames', 'and ' + g.more + ' more name(s) the same way'));
    } else card.appendChild(stepList(g.steps, prefix));
    return card;
  }

  /* ---- the whole plan ----------------------------------------------------- */
  function hero(p) {
    var c = p.cert || {}, h = p.head || {};
    var box = el('div', 'rp-hero');
    var left = el('div', 'rp-hero-l');
    var t = el('div', 'rp-hero-t');
    t.appendChild(icon('cert', 22, 'rp-hero-ic'));
    t.appendChild(data('span', 'rp-hero-name', c.name || (c.names || [])[0] || ''));
    if (c.draft) t.appendChild(el('span', 'tag warn rp-tag', 'not saved yet'));
    else if (!c.issued) t.appendChild(el('span', 'tag info rp-tag', 'not issued yet'));
    left.appendChild(t);
    var nb = el('div', 'rp-names');
    (c.names || []).forEach(function (n) { nb.appendChild(data('span', 'rp-name', n)); });
    left.appendChild(nb);
    box.appendChild(left);
    var facts = el('div', 'rp-hero-facts');
    var fact = function (ic, label, node) {
      var f = el('div', 'rp-hf');
      f.appendChild(icon(ic, 16));
      var w = el('div', '');
      w.appendChild(el('div', 'rp-hf-l', label));
      var v = el('div', 'rp-hf-v');
      if (node && node.nodeType) v.appendChild(node); else v.textContent = node || '–';
      w.appendChild(v);
      f.appendChild(w);
      facts.appendChild(f);
    };
    var kv = el('span', '');
    kv.appendChild(data('span', 'mono', c.key_type + (c.key_type_alt ? ' + ' + c.key_type_alt : '')));
    if (c.csr_from) {
      /* made by the device, not here (certs.csr_from) */
      var kd = el('div', 'muted small');
      kd.appendChild(el('span', '', 'key made by'));
      kd.appendChild(document.createTextNode(' '));
      kd.appendChild(data('span', 'rp-hf-dev', c.csr_from));
      kv.appendChild(kd);
    }
    fact('key', 'Key', kv);
    fact('source', 'Source', h.source ? moduleChip(h.source) : el('span', 'muted', 'none'));
    var vs = el('span', 'rp-modlist');
    (h.validations || []).forEach(function (m) { vs.appendChild(moduleChip(m)); });
    fact('proof', 'Validation', (h.validations || []).length ? vs : el('span', 'muted', 'none needed'));
    var dn = el('span', '');
    dn.appendChild(data('b', 'rp-big', String(h.deploys || 0)));
    dn.appendChild(noI18n(el('span', 'muted', ' ' + nWord(h.deploys || 0, 'deployment(s)'))));
    fact('deploy', 'Deployed to', dn);
    var tn = el('span', '');
    tn.appendChild(data('b', 'rp-big', String(h.tests || 0)));
    tn.appendChild(noI18n(el('span', 'muted', ' ' + nWord(h.tests || 0, 'test(s)'))));
    fact('check', 'Tested by', tn);
    box.appendChild(facts);
    return box;
  }
  function safeLine() {
    var p = el('div', 'rp-safe');
    p.appendChild(icon('shield', 16));
    p.appendChild(el('span', '', 'Worked out without doing anything: no device, DNS server or CA was contacted and nothing was changed. Passwords, keys and tokens are never shown.'));
    return p;
  }
  function legend() {
    var box = el('div', 'rp-legend');
    LEGEND.forEach(function (k) {
      var o = KINDS[k];
      var it = el('span', 'rp-lg k-' + o.cls);
      var m = el('span', 'rp-mark small');
      m.appendChild(icon(o.icon, 12));
      it.appendChild(m);
      it.appendChild(el('span', '', o.words));
      box.appendChild(it);
    });
    var b1 = el('span', 'rp-lg');
    b1.appendChild(el('span', 'tag warn rp-tag', 'only the first time'));
    box.appendChild(b1);
    var b2 = el('span', 'rp-lg');
    b2.appendChild(el('span', 'tag info rp-tag', 'the answer decides'));
    box.appendChild(b2);
    return box;
  }
  /* Several deployments (1.0.23): a junction - the line of the plan branches into a
     track for each, a station at its end; the one picked is drawn below over the whole
     width, the others wait on their tracks. "All of them" lays every one out. */
  function countSteps(g) {
    var all = [];
    (g.per_name || [{steps: g.steps}]).forEach(function (p) { all = all.concat(p.steps || []); });
    return all;
  }
  function junction(groups, n, kind) {
    var wrap = el('div', 'rp-junction-wrap');
    var yard = el('div', 'rp-junction');
    yard.setAttribute('role', 'tablist');
    var shown = el('div', 'rp-junction-shown');
    var stations = [];
    var pick = function (i) {
      stations.forEach(function (st, j) {
        st.classList.toggle('on', i === j);
        st.setAttribute('aria-selected', i === j ? 'true' : 'false');
      });
      clear(shown);
      if (i < 0) {
        var grid = el('div', 'rp-groups many');
        groups.forEach(function (g, j) { grid.appendChild(groupCard(g, n + '.' + (j + 1), kind)); });
        shown.appendChild(grid);
      } else shown.appendChild(groupCard(groups[i], n + '.' + (i + 1), kind));
      explainWhatWasDrawn(shown);
    };
    groups.forEach(function (g, i) {
      var st = el('button', 'rp-station' + (g.off || g.enabled === false ? ' off' : ''));
      st.type = 'button';
      st.setAttribute('role', 'tab');
      var top = el('span', 'rp-station-t');
      top.appendChild(icon(kind === 'checks' ? 'check' : 'target', 15, 'rp-station-ic'));
      top.appendChild(data('b', '', g.title));
      st.appendChild(top);
      var sub = el('span', 'rp-station-s');
      if (g.module) sub.appendChild(el('span', 'tag info rp-tag', g.module.title || g.module.kind));
      if (g.host) sub.appendChild(data('span', 'mono small muted', g.host));
      st.appendChild(sub);
      var steps = countSteps(g);
      var meta = el('span', 'rp-station-m');
      meta.appendChild(noI18n(el('span', 'small muted', steps.length + ' ' + nWord(steps.length, 'step(s)'))));
      if (steps.some(function (x) { return x.secret; })) meta.appendChild(el('span', 'tag crit rp-tag', 'holds the private key'));
      if (g.off) meta.appendChild(el('span', 'tag warn rp-tag', kind === 'checks' ? 'the test is switched off' : 'the target is switched off'));
      else if (g.enabled === false) meta.appendChild(el('span', 'tag warn rp-tag', 'switched off: skipped'));
      st.appendChild(meta);
      st.onclick = function () { pick(i); };
      stations.push(st);
      yard.appendChild(st);
    });
    var allBtn = el('button', 'rp-station rp-station-all');
    allBtn.type = 'button';
    allBtn.setAttribute('role', 'tab');
    var at = el('span', 'rp-station-t');
    at.appendChild(icon('list', 15, 'rp-station-ic'));
    at.appendChild(el('b', '', 'All of them'));
    allBtn.appendChild(at);
    allBtn.appendChild(el('span', 'rp-station-s small muted', kind === 'checks'
      ? (groups.length === 1 ? '1 test side by side' : groups.length + ' tests side by side')
      : (groups.length === 1 ? '1 deployment side by side' : groups.length + ' deployments side by side')));
    allBtn.onclick = function () { pick(-1); };
    stations.push(allBtn);
    yard.appendChild(allBtn);
    var lead = el('p', 'muted small rp-junction-h', kind === 'checks' ? 'Pick a test: only it is shown below, over the whole width.' : 'Pick a deployment: only it is shown below, over the whole width.');
    wrap.appendChild(lead);
    wrap.appendChild(yard);
    wrap.appendChild(shown);
    pick(0);
    return wrap;
  }

  function phaseBlock(ph, n, cert) {
    var sec = el('section', 'rp-phase p-' + ph.key);
    sec.id = 'rp-phase-' + ph.key;
    var head = el('div', 'rp-phase-h');
    var num = el('div', 'rp-phase-n');
    num.appendChild(icon(PHASE_ICON[ph.key] || 'info', 18));
    head.appendChild(num);
    var t = el('div', 'rp-phase-t');
    var h3 = el('h3', '');
    h3.appendChild(data('span', 'rp-phase-no', String(n)));
    h3.appendChild(el('span', '', ph.title));
    t.appendChild(h3);
    var lede = ph.key === 'key' && cert && cert.csr_from ? LEDE_DEVICE_KEY : PHASE_LEDE[ph.key];
    if (lede) t.appendChild(el('p', 'muted rp-lede', lede));
    head.appendChild(t);
    if (ph.module) {
      var mc = moduleChip(ph.module);
      mc.classList.add('rp-phase-mod');
      head.appendChild(mc);
    }
    sec.appendChild(head);
    var body = el('div', 'rp-phase-b');
    var f = factsFold(ph.key === 'source' ? 'The source\'s settings' : 'Settings', ph.facts, false);
    if (f) body.appendChild(f);
    if (ph.steps && ph.steps.length) body.appendChild(stepList(ph.steps, String(n)));
    if (ph.groups && ph.groups.length > 1 && (ph.key === 'deploy' || ph.key === 'checks')) {
      body.appendChild(junction(ph.groups, n, ph.key));
    } else if (ph.groups && ph.groups.length) {
      var grid = el('div', 'rp-groups' + (ph.groups.length > 1 ? ' many' : ''));
      ph.groups.forEach(function (g, i) { grid.appendChild(groupCard(g, n + '.' + (i + 1), ph.key)); });
      body.appendChild(grid);
    }
    sec.appendChild(body);
    return sec;
  }
  function nav(p, scroller) {
    var box = el('nav', 'rp-nav');
    box.appendChild(el('div', 'rp-nav-h', 'Phases'));
    (p.phases || []).forEach(function (ph, i) {
      var b = el('button', 'rp-nav-b');
      b.type = 'button';
      b.appendChild(data('span', 'rp-nav-n', String(i + 1)));
      b.appendChild(el('span', '', ph.title));
      var count = 0;
      (ph.steps || []).forEach(function (s) { if (s.kind !== 'head') count++; });
      (ph.groups || []).forEach(function (g) {
        (g.steps || []).forEach(function (s) { if (s.kind !== 'head') count++; });
        (g.per_name || []).forEach(function (x) { (x.steps || []).forEach(function (s) { if (s.kind !== 'head') count++; }); });
      });
      b.appendChild(data('span', 'rp-count', String(count)));
      b.onclick = function () {
        var t = $('rp-phase-' + ph.key);
        if (t && scroller) scroller.scrollTo({top: t.offsetTop - 8, behavior: 'smooth'});
      };
      box.appendChild(b);
    });
    return box;
  }
  function draw(body, p) {
    clear(body);
    body.classList.add('rp-body');
    var page = el('div', 'rp-page');
    /* Debug details (1.0.37): off - as it was; on - everything sent, as it is sent */
    var dbgOn = false;
    try { dbgOn = window.localStorage.getItem('acme.rp.debug') === '1'; } catch (e) { }
    page.classList.toggle('rp-debug-off', !dbgOn);
    page.appendChild(hero(p));
    var sl = safeLine();
    var sw = el('label', 'rp-dbgsw');
    var cb = el('input');
    cb.type = 'checkbox';
    cb.checked = dbgOn;
    var knob = el('span', 'rp-dbgsw-k');
    sw.appendChild(cb);
    sw.appendChild(knob);
    sw.appendChild(el('span', '', 'Show debug details'));
    explain(sw, 'Every request as it goes on the wire - all its headers, the body as sent - how each connection is made (TLS, SNI, the device\'s certificate, the proxy, time limits), the ssh command with its options, and what a test says before TLS. Secrets stay hidden.');
    cb.onchange = function () {
      page.classList.toggle('rp-debug-off', !cb.checked);
      try { window.localStorage.setItem('acme.rp.debug', cb.checked ? '1' : '0'); } catch (e) { }
    };
    sl.appendChild(sw);
    page.appendChild(sl);
    page.appendChild(legend());
    var cols = el('div', 'rp-cols');
    cols.appendChild(nav(p, body));
    var line = el('div', 'rp-timeline');
    (p.phases || []).forEach(function (ph, i) { line.appendChild(phaseBlock(ph, i + 1, p.cert)); });
    cols.appendChild(line);
    page.appendChild(cols);
    if (p.recording) page.appendChild(el('p', 'ct-bad', p.recording));
    var foot = el('p', 'muted small rp-made');
    foot.appendChild(el('span', '', 'Worked out in'));
    var took = ((p.took_ms || 0) / 1000).toFixed(1);
    if (typeof numDecimal === 'function' && numDecimal() === ',') took = took.replace('.', ',');
    foot.appendChild(data('span', '', ' ' + took + ' s'));
    page.appendChild(foot);
    body.appendChild(page);
    explainWhatWasDrawn(body);
  }

  /** Opens the plan over what is open: {id} a certificate saved, {draft, id?} the
      wizard's values. */
  RP.open = function (o) {
    o = o || {};
    var open = function () {
      var title = 'What happens';
      var buttons = function () {
        return [{words: 'Close', close: true},
                {words: 'Work it out again', icon: 'refresh', go: function () { load(); }}];
      };
      var ticket = null;
      var load = function () {
        modal(title, function (b) {
          b.classList.add('rp-body');
          var w = el('div', 'rp-wait');
          w.appendChild(icon('clock', 28));
          w.appendChild(el('p', '', 'Working out what would happen - each module is run against a stand-in that answers and does nothing…'));
          b.appendChild(w);
        }, buttons(), 'runplan');
        if (o.name) {
          var t = $('modal-title');
          if (t) { clear(t); t.appendChild(document.createTextNode(tr('What happens') + ' · ')); t.appendChild(data('span', '', o.name)); }
        }
        ticket = modalTicket();
        call(o).then(function (d) {
          if (!modalStill(ticket)) return;
          draw($('modal-body'), d.plan || d);
        }).catch(function (e) {
          if (!modalStill(ticket)) return;
          var b = $('modal-body');
          clear(b);
          var p = el('p', 'ct-bad');
          p.textContent = String((e && e.message) || e);
          b.appendChild(p);
        });
      };
      load();
    };
    if ($('modal') && !$('modal').hidden) modalOver(open, o.back); else open();
  };
})();
