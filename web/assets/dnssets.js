/* dnssets.js - Settings → DNS: named sets of DNS servers, and which of them each
   function of acme asks (docs/dns-sets.md). The pane's markup is a host in
   admin/index.php (<div id="dnss-host">); this draws it from the daemon's
   GET /api/dnssets and changes it through acmelib/certs/api_dnssets.py:
   a set added, changed, deleted or tried (Test: a name looked up through it,
   every server, with timings), and a function given a set. Every popup is the
   page's own (modal, confirmThen) - never one of the browser's.
   A full administrator changes; anybody signed in sees and tries a set kept. */
'use strict';
(function () {
  var DS = {d: null, asked: 0};
  var QTYPES = ['A', 'AAAA', 'TXT', 'CNAME', 'NS', 'MX', 'SOA', 'CAA', 'SRV', 'PTR'];

  function full() { return !!(typeof ME === 'object' && ME && ME.role === 'fulladmin'); }
  function call(what, body) { return api(what ? 'dnssets/' + what : 'dnssets', body); }
  function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
  function cell(cls, child) {
    var td = el('td', cls || '');
    if (child instanceof Node) td.appendChild(child);
    else if (child !== undefined && child !== null) td.textContent = String(child);
    return td;
  }
  function protoWords(p) {
    return {udp: 'UDP, TCP when cut short', tcp: 'TCP only', dot: 'DNS over TLS'}[p] || p;
  }
  function saidOf(d, fallback) { return (d && d.message) || fallback; }

  function load() {
    var host = $('dnss-host');
    if (!host) return;
    var n = ++DS.asked;
    call('').then(function (d) {
      if (n !== DS.asked) return;
      DS.d = d || {};
      draw();
    }).catch(function (e) {
      clear(host);
      host.appendChild(el('div', 'card full', ''));
      oops(e);
    });
  }

  /* ---- the pane ----------------------------------------------------------- */
  function draw() {
    var host = $('dnss-host');
    var d = DS.d || {};
    clear(host);
    host.appendChild(setsCard(d));
    host.appendChild(usesCard(d));
  }

  function setsCard(d) {
    var card = el('div', 'card full dnss');
    var h = el('h2', '', 'DNS sets');
    var right = el('span', 'right btnrow');
    if (full()) {
      var add = cmdButton('Add a set', 'add', 'small primary');
      add.id = 'dnss-add';
      add.onclick = function () { editSet(null); };
      right.appendChild(add);
    }
    h.appendChild(right);
    card.appendChild(h);
    card.appendChild(el('p', 'note', 'Each set is a few DNS servers, one address a line (with :port where it is not 53), asked in their order until one answers. "The system\'s" is built in: the servers of /etc/resolv.conf, as the machine has them. Test looks a name up through a set and shows what each of its servers answered, and how fast.'));
    var used = d.used || {};
    card.appendChild(listTable(['Name', 'Servers', 'Protocol', {words: 'Timeout', cls: 'num'}, 'Used for', ''],
      d.sets || [], function (s) {
        var tr = el('tr', s.builtin ? 'dnss-builtin' : '');
        var nm = cell('', '');
        nm.appendChild(s.builtin ? el('b', '', s.name) : data('b', '', s.name));
        if (s.builtin) nm.appendChild(el('span', 'tag dim dnss-tag', 'built in'));
        if (s.note) nm.appendChild(s.builtin ? el('div', 'muted small', s.note) : data('div', 'muted small', s.note));
        tr.appendChild(nm);
        var sv = cell('mono small', '');
        (s.servers || []).forEach(function (x) { sv.appendChild(data('div', '', x)); });
        if (s.protocol === 'dot' && s.tls_name) sv.appendChild(data('div', 'muted', 'TLS: ' + s.tls_name));
        tr.appendChild(sv);
        tr.appendChild(cell('small', protoWords(s.protocol)));
        tr.appendChild(cell('num muted', s.builtin ? '–' : (s.timeout + ' s')));
        var u = cell('small', '');
        var list = used[s.name] || [];
        if (!list.length) u.appendChild(el('span', 'muted', 'nothing'));
        list.forEach(function (t) { u.appendChild(el('span', 'tag info dnss-tag', t)); });
        tr.appendChild(u);
        var tools = el('td', 'rowtools');
        var test = iconButton('play', 'Test: look a name up through this set');
        test.classList.add('dnss-test');
        test.onclick = function () { testSet(s); };
        tools.appendChild(test);
        if (full() && !s.builtin) {
          var ed = iconButton('edit', 'Edit this set');
          ed.classList.add('dnss-edit');
          ed.onclick = function () { editSet(s); };
          tools.appendChild(ed);
          var del = iconButton('trash', 'Delete this set');
          del.classList.add('dnss-del');
          del.onclick = function () { deleteSet(s, list); };
          tools.appendChild(del);
        }
        tr.appendChild(tools);
        return tr;
      }, 'plain dnss-sets|No set yet'));
    return card;
  }

  function usesCard(d) {
    var card = el('div', 'card full dnss');
    card.appendChild(el('h2', '', 'Which set each function asks'));
    card.appendChild(el('p', 'note', 'A function asks the set chosen here; "default" is the set it asks when nothing is chosen. A validation\'s own "Resolvers" and "Public resolvers" fields still come first, for that validation alone.'));
    var names = (d.sets || []).map(function (s) { return s.name; });
    card.appendChild(listTable(['Function', 'What it is used for', 'Asks'], d.purposes || [], function (p) {
      var tr = el('tr');
      tr.dataset.purpose = p.key;
      tr.appendChild(cell('', el('b', '', p.title)));
      tr.appendChild(cell('small muted dnss-says', p.says));
      var td = cell('dnss-pick', '');
      var pairs = [['', 'default: ' + p['default']]].concat(names.map(function (n) { return [n, n]; }));
      var sel = selectBox(pairs, p.chosen || '');
      sel.id = 'dnss-use-' + p.key;
      Array.prototype.forEach.call(sel.options, function (o, i) { if (i > 0 && o.value !== d.system) noI18n(o); });
      sel.disabled = !full();
      sel.onchange = function () {
        sel.disabled = true;
        call('assign', {purpose: p.key, set: sel.value}).then(function (r) {
          toast(saidOf(r, 'chosen'), 'good');
          load();
        }).catch(function (e) { sel.disabled = false; oops(e); });
      };
      td.appendChild(sel);
      if (p.how === 'legacy') {
        td.appendChild(el('div', 'muted small dnss-legacy',
          'asked now: ' + p.set + ' (' + p.legacy_value + '), set before this card - until a set is chosen here'));
      }
      tr.appendChild(td);
      return tr;
    }, 'plain dnss-uses'));
    if (d.fixed) card.appendChild(el('p', 'note dnss-fixed', d.fixed));
    return card;
  }

  /* ---- a set added or changed ------------------------------------------------ */
  function editSet(s) {
    var f = {};
    var isNew = !s;
    s = s || {name: '', servers: [], protocol: 'udp', tls_name: '', timeout: 3, note: ''};
    modal(isNew ? 'A new DNS set' : 'The DNS set ' + s.name, function (body) {
      body.appendChild(el('p', 'note', 'Addresses only - a DNS server is not looked up by a name. One a line: 192.0.2.53, 192.0.2.53:5353, 2001:db8::53 or [2001:db8::53]:5353.'));
      var g = el('div', 'formgrid');
      f.name = textBox(s.name, 'Company DNS', '');
      f.name.id = 'dnss-f-name';
      g.appendChild(formField('Name', f.name, 'Letters, digits, spaces and . _ @ + - (as every name in acme).'));
      f.servers = el('textarea', 'mono');
      f.servers.id = 'dnss-f-servers';
      f.servers.rows = 4;
      f.servers.spellcheck = false;
      f.servers.placeholder = '10.0.0.53\n10.0.1.53';
      f.servers.value = (s.servers || []).join('\n');
      noI18n(f.servers);
      var sf = formField('Servers', f.servers, 'Asked in this order until one answers; at most 8.');
      sf.classList.add('wide');
      g.appendChild(sf);
      f.protocol = selectBox([['udp', 'UDP, TCP when an answer is cut short'], ['tcp', 'TCP only'],
                              ['dot', 'DNS over TLS (port 853)']], s.protocol || 'udp');
      f.protocol.id = 'dnss-f-protocol';
      g.appendChild(formField('Protocol', f.protocol));
      f.tls = textBox(s.tls_name || '', 'cloudflare-dns.com', 'mono');
      noI18n(f.tls);
      var tf = formField('Server name for TLS', f.tls, 'Its certificate is checked against this name; empty: against its address.');
      g.appendChild(tf);
      f.timeout = textBox(String(s.timeout || 3), '3', '');
      f.timeout.type = 'number';
      f.timeout.min = '0.5';
      f.timeout.max = '30';
      f.timeout.step = '0.5';
      g.appendChild(formField('Timeout (seconds)', f.timeout, 'How long each server is waited for.'));
      f.note = textBox(s.note || '', '', '');
      noI18n(f.note);
      var nf = formField('Note', f.note);
      nf.classList.add('wide');
      g.appendChild(nf);
      body.appendChild(g);
      var showTls = function () { tf.hidden = f.protocol.value !== 'dot'; };
      f.protocol.onchange = showTls;
      showTls();
    }, [{words: 'Close', close: true},
        {words: 'Test', icon: 'play', go: function () {
          testSet({name: f.name.value.trim(), draft: fields(f)});
        }},
        {words: isNew ? 'Add it' : 'Save', cls: 'primary', icon: isNew ? 'add' : 'save', go: function (b) {
          var body = fields(f);
          if (!isNew) body.old_name = s.name;
          busy(b, true);
          call('save', body).then(function (r) {
            toast(saidOf(r, 'saved'), 'good');
            closeModal();
            load();
          }).catch(oops).then(function () { busy(b, false); });
        }}], 'medium');
  }
  function fields(f) {
    return {name: f.name.value.trim(), servers: f.servers.value, protocol: f.protocol.value,
            tls_name: f.tls.value.trim(), timeout: Number(f.timeout.value || 3), note: f.note.value.trim()};
  }

  function deleteSet(s, used) {
    var words = 'The DNS set <b>' + htmlText(s.name) + '</b> is deleted.';
    if (used && used.length) words += ' What asked it goes back to its default: ' + htmlText(used.join(', ')) + '.';
    confirmThen('Delete the DNS set', words, 'Delete it', function () {
      call('delete', {name: s.name}).then(function (r) { toast(saidOf(r, 'deleted'), 'good'); load(); }).catch(oops);
    });
  }

  /* ---- Test: a name looked up through a set --------------------------------- */
  function testSet(s) {
    var f = {};
    var title = s.draft ? 'Test the set as it is in the form' : 'Test the DNS set ' + s.name;
    modal(title, function (body) {
      body.appendChild(el('p', 'note', 'The name is asked of every server of the set at once, the way the set asks (its protocol, its timeout). Nothing is changed anywhere.'));
      var row = el('div', 'btnrow dnss-ask');
      f.q = textBox(DS.lastQ || '', 'example.com', 'mono');
      f.q.id = 'dnss-t-name';
      noI18n(f.q);
      f.t = selectBox(QTYPES.map(function (t) { return [t, t]; }), DS.lastT || 'A');
      f.t.id = 'dnss-t-type';
      noI18n(f.t);
      var go = cmdButton('Look it up', 'search', 'primary');
      go.id = 'dnss-t-go';
      row.appendChild(f.q);
      row.appendChild(f.t);
      row.appendChild(go);
      body.appendChild(row);
      f.out = el('div', 'dnss-result');
      body.appendChild(f.out);
      var run = function () {
        var q = f.q.value.trim();
        if (!q) { toast('which name?', 'bad'); return; }
        DS.lastQ = q;
        DS.lastT = f.t.value;
        var b = s.draft ? Object.assign({}, s.draft) : {name: s.name};
        b.qname = q;
        b.qtype = f.t.value;
        busy(go, true);
        clear(f.out);
        f.out.appendChild(el('p', 'muted', 'asking…'));
        call('test', b).then(function (r) { result(f.out, r.test || {}); })
          .catch(function (e) { clear(f.out); oops(e); })
          .then(function () { busy(go, false); });
      };
      go.onclick = run;
      f.q.onkeydown = function (e) { if (e.key === 'Enter') { e.preventDefault(); run(); } };
    }, [{words: 'Close', close: true}], 'medium');
  }

  function result(host, r) {
    clear(host);
    var head = el('div', 'dnss-head ' + (r.ok ? 'good' : 'bad'));
    if (r.ok) {
      var who = (r.tries || []).filter(function (t) { return t.server === r.answered_by; })[0] || {};
      head.appendChild(el('b', '', 'Answered by'));
      head.appendChild(data('span', 'mono', ' ' + r.answered_by + ' '));
      head.appendChild(el('span', 'muted', 'in ' + (who.ms || 0) + ' ms'));
    } else {
      head.appendChild(el('b', '', 'No server of the set answered'));
    }
    host.appendChild(head);
    var steps = el('div', 'steps dnss-tries');
    (r.tries || []).forEach(function (t) {
      var line = el('div', 'step ' + (t.ok ? 'ok' : 'bad'));
      var mark = el('span', 'step-mark');
      mark.innerHTML = iconMarkup(t.ok ? 'check' : 'cancel', 15);
      line.appendChild(mark);
      var words = el('span', 'step-words');
      words.appendChild(data('b', 'mono', t.server));
      words.appendChild(el('span', 'd', t.said));
      words.appendChild(el('span', 'd', t.ms + ' ms'));
      line.appendChild(words);
      steps.appendChild(line);
    });
    host.appendChild(steps);
    if (r.ok) {
      host.appendChild(listTable(['Name', {words: 'TTL', cls: 'num'}, 'Type', 'Value'], r.answers || [], function (a) {
        var tr = el('tr');
        tr.appendChild(cell('mono small', data('span', '', a.name)));
        tr.appendChild(cell('num muted', String(a.ttl)));
        tr.appendChild(cell('', data('span', 'tag dim', a.type)));
        tr.appendChild(cell('mono small dnss-val', data('span', '', a.value)));
        return tr;
      }, 'plain dnss-answers|The name has no record of that type'));
    }
  }

  window.ACME_EXTRA_PANES = window.ACME_EXTRA_PANES || {};
  window.ACME_EXTRA_PANES.dnssets = function () { load(); };
  /* A page that opened on this pane drew it before this file came. */
  if (typeof PANE === 'string' && PANE === 'dnssets') load();
})();
