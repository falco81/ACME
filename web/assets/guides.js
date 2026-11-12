/* guides.js - the setup guides of the modules (1.0.94, acmelib/certs/guides.py).

   For every source, validation, target and test - each version of it - a Markdown text
   saying how to set up the other side (the FortiGate, the DNS provider, the CA...) for acme.
   guideShow(): read-only, in a popup nearly the whole page, with its contents beside it;
   guideEdit(): a Markdown editor (toolbar, the text and how it will look side by side, the
   module's own text to start from or to give it back) - a full administrator's.

   Markdown is drawn here, never as HTML: every node made by hand (el, text nodes) - what a
   guide holds cannot run anything. Links open in a new tab, http(s) and mailto only. */
'use strict';
(function () {
  var FAM_WORDS = {issuer: 'Source', challenge: 'Validation', target: 'Target', check: 'Test'};

  function tr(w) {
    try { var got = typeof i18nText === 'function' ? i18nText(w) : null; return got || w; }
    catch (e) { return w; }
  }
  function txt(s) { return document.createTextNode(String(s)); }
  function lang() {
    try {
      var code = (typeof I18N !== 'undefined' && I18N && I18N.on && I18N.code) || document.documentElement.lang || 'en';
      return String(code).slice(0, 2) === 'cs' ? 'cs' : 'en';
    } catch (e) { return 'en'; }
  }

  /* ---- Markdown, drawn ------------------------------------------------------------------ */
  function slug(s, seen) {
    var b = String(s).toLowerCase().replace(/[^\wÀ-ɏ]+/g, '-').replace(/^-+|-+$/g, '') || 'part';
    var x = b, n = 2;
    while (seen[x]) x = b + '-' + (n++);
    seen[x] = 1;
    return x;
  }
  function safeHref(u) {
    u = String(u || '').trim();
    if (/^(https?:\/\/|mailto:)/i.test(u)) return u;
    if (/^#[\w-]+$/.test(u)) return u;
    return '';
  }
  /* inline: `code`, **bold**, *em* / _em_, ~~del~~, [text](url), <https://...> */
  function inline(parent, s) {
    var re = /\\([\\`*_{}\[\]()#+\-.!|~>])|(`+)([\s\S]*?[^`])\2(?!`)|\*\*([\s\S]+?)\*\*|__([\s\S]+?)__|~~([\s\S]+?)~~|\*([^*\s][\s\S]*?)\*|(^|[^\w])_([^_\s][\s\S]*?)_(?=[^\w]|$)|\[([^\]]+)\]\(([^)\s]+)(?:\s+"[^"]*")?\)|<(https?:\/\/[^>\s]+)>/g;
    var at = 0, m;
    var plain = function (t) {
      String(t).split('\n').forEach(function (part, k) { if (k) parent.appendChild(el('br')); if (part) parent.appendChild(txt(part)); });
    };
    while ((m = re.exec(s)) !== null) {
      if (m.index > at) plain(s.slice(at, m.index));
      if (m[1] !== undefined) { parent.appendChild(txt(m[1])); }
      else if (m[2]) { var c = el('code', 'gd-code'); c.textContent = m[3].replace(/^ (.*) $/, '$1'); parent.appendChild(c); }
      else if (m[4] !== undefined || m[5] !== undefined) { var b = el('strong'); inline(b, m[4] !== undefined ? m[4] : m[5]); parent.appendChild(b); }
      else if (m[6] !== undefined) { var d = el('del'); inline(d, m[6]); parent.appendChild(d); }
      else if (m[7] !== undefined) { var e = el('em'); inline(e, m[7]); parent.appendChild(e); }
      else if (m[9] !== undefined) { if (m[8]) parent.appendChild(txt(m[8])); var e2 = el('em'); inline(e2, m[9]); parent.appendChild(e2); }
      else if (m[10] !== undefined) {
        var href = safeHref(m[11]);
        if (href) {
          var a = el('a', 'gd-link');
          a.href = href;
          if (href.charAt(0) !== '#') { a.target = '_blank'; a.rel = 'noopener noreferrer'; }
          inline(a, m[10]);
          parent.appendChild(a);
        } else inline(parent, m[10]);
      } else if (m[12]) {
        var a2 = el('a', 'gd-link', m[12]); a2.href = m[12]; a2.target = '_blank'; a2.rel = 'noopener noreferrer';
        parent.appendChild(a2);
      }
      at = re.lastIndex;
    }
    if (at < s.length) plain(s.slice(at));
  }
  function cells(line) {
    var s = line.trim().replace(/^\|/, '').replace(/\|$/, '');
    var out = [], cur = '', esc = false;
    for (var i = 0; i < s.length; i++) {
      var ch = s.charAt(i);
      if (esc) { cur += ch; esc = false; continue; }
      if (ch === '\\') { esc = true; cur += ''; continue; }
      if (ch === '|') { out.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    out.push(cur.trim());
    return out;
  }
  function render(md, opts) {
    opts = opts || {};
    var root = el('div', 'gd-md');
    var lines = String(md || '').replace(/\r\n?/g, '\n').split('\n');
    var seen = {}, toc = [];
    var i = 0;
    var para = [];
    var flush = function () {
      if (!para.length) return;
      var p = el('p');
      /* one paragraph, its lines one text (1.0.94: **bold** or *italic* over a line's end was
         left as stars); a line ending in two spaces or a backslash breaks there */
      var whole = para.map(function (ln, k) {
        var t = ln.replace(/ {2,}$|\\$/, '').trim();
        return k < para.length - 1 ? t + (/ {2,}$|\\$/.test(ln) ? '\n' : ' ') : t;
      }).join('');
      inline(p, whole);
      root.appendChild(p);
      para = [];
    };
    var isList = function (ln) { return /^\s*([-*+]|\d{1,3}[.)])\s+/.test(ln); };
    while (i < lines.length) {
      var ln = lines[i];
      var fence = ln.match(/^\s*(```+|~~~+)\s*([\w+-]*)\s*$/);
      if (fence) {
        flush();
        var body = [], close = fence[1], fin = new RegExp('^ {0,' + ln.match(/^\s*/)[0].length + '}');
        i++;
        while (i < lines.length && lines[i].trim().indexOf(close) !== 0) { body.push(lines[i].replace(fin, '')); i++; }
        i++;
        root.appendChild(codeBlock(body.join('\n'), fence[2]));
        continue;
      }
      var h = ln.match(/^(#{1,6})\s+(.+?)\s*#*\s*$/);
      if (h) {
        flush();
        var lvl = h[1].length, he = el('h' + lvl, 'gd-h' + lvl);
        inline(he, h[2]);
        he.id = 'gd-' + slug(he.textContent, seen);
        if (lvl <= 3) toc.push({level: lvl, words: he.textContent, id: he.id});
        root.appendChild(he);
        i++;
        continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(ln)) { flush(); root.appendChild(el('hr')); i++; continue; }
      if (/^\s*>/.test(ln)) {
        flush();
        var q = [];
        while (i < lines.length && /^\s*>/.test(lines[i])) { q.push(lines[i].replace(/^\s*> ?/, '')); i++; }
        var bq = el('blockquote', 'gd-quote');
        var inner = render(q.join('\n'), {inner: true});
        while (inner.node.firstChild) bq.appendChild(inner.node.firstChild);
        root.appendChild(bq);
        continue;
      }
      if (/^\s*\|.*\|\s*$/.test(ln) && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1])) {
        flush();
        var head = cells(ln), aligns = cells(lines[i + 1]).map(function (c) {
          return /^:-+:$/.test(c) ? 'center' : (/-+:$/.test(c) ? 'right' : '');
        });
        i += 2;
        var wrap = el('div', 'gd-tablewrap');
        var t = el('table', 'gd-table'), thead = el('thead'), tr0 = el('tr');
        head.forEach(function (c, k) { var th = el('th'); if (aligns[k]) th.style.textAlign = aligns[k]; inline(th, c); tr0.appendChild(th); });
        thead.appendChild(tr0); t.appendChild(thead);
        var tb = el('tbody');
        while (i < lines.length && /^\s*\|.*\|\s*$/.test(lines[i])) {
          var r = el('tr');
          cells(lines[i]).forEach(function (c, k) { var td = el('td'); if (aligns[k]) td.style.textAlign = aligns[k]; inline(td, c); r.appendChild(td); });
          tb.appendChild(r);
          i++;
        }
        t.appendChild(tb); wrap.appendChild(t); root.appendChild(wrap);
        continue;
      }
      if (isList(ln)) {
        flush();
        var block = [];
        while (i < lines.length && (isList(lines[i]) || (/^\s{2,}\S/.test(lines[i]) && block.length) ||
               (!lines[i].trim() && i + 1 < lines.length && (isList(lines[i + 1]) || /^\s{2,}\S/.test(lines[i + 1])) && block.length))) {
          block.push(lines[i]); i++;
        }
        root.appendChild(list(block));
        continue;
      }
      if (!ln.trim()) { flush(); i++; continue; }
      para.push(ln);
      i++;
    }
    flush();
    return {node: root, toc: toc};
  }
  function list(block) {
    var base = block[0].match(/^\s*/)[0].length;
    var ordered = /^\s*\d/.test(block[0]);
    var L = el(ordered ? 'ol' : 'ul', 'gd-list');
    var start = ordered ? parseInt(block[0].trim(), 10) : 1;
    if (ordered && start > 1) L.start = start;
    var item = null, sub = [];
    var close = function () {
      if (!item) return;
      if (sub.length) {
        var lead = [], rest = [], k = 0;
        while (k < sub.length && !/^\s*([-*+]|\d{1,3}[.)])\s+/.test(sub[k]) && !/^\s*(```|~~~)/.test(sub[k])) { lead.push(sub[k].trim()); k++; }
        if (lead.length) item._raw += ' ' + lead.join(' ');
        rest = sub.slice(k);
        if (rest.length) {
          var cut = new RegExp('^ {0,' + Math.max(item._ind, base + 2) + '}');
          var inner = render(rest.map(function (x) { return x.replace(cut, ''); }).join('\n'), {inner: true});
          while (inner.node.firstChild) item.appendChild(inner.node.firstChild);
        }
      }
      inline(item._p, item._raw);
      L.appendChild(item);
      item = null; sub = [];
    };
    block.forEach(function (ln) {
      var m = ln.match(/^(\s*)([-*+]|\d{1,3}[.)])\s+(.*)$/);
      if (m && m[1].length <= base + 1) {
        close();
        item = el('li');
        var text = m[3];
        var task = text.match(/^\[([ xX])\]\s+(.*)$/);
        if (task) {
          item.classList.add('gd-task');
          var box = el('span', 'gd-check' + (task[1] !== ' ' ? ' on' : ''), task[1] !== ' ' ? '✓' : '');
          item.appendChild(box);
          text = task[2];
        }
        item._p = el('span');
        item._raw = text;
        item._ind = ln.length - m[3].length;   /* where the item's own text begins */
        item.insertBefore(item._p, null);
      } else if (item) {
        sub.push(ln);
      }
    });
    close();
    return L;
  }
  function codeBlock(code, langName) {
    var box = el('div', 'gd-pre');
    var bar = el('div', 'gd-pre-bar');
    bar.appendChild(el('span', 'gd-pre-lang', langName || 'text'));
    var copy = el('button', 'gd-copy', tr('Copy'));
    copy.type = 'button';
    copy.onclick = function () {
      var done = function () { copy.textContent = tr('Copied'); setTimeout(function () { copy.textContent = tr('Copy'); }, 1400); };
      try {
        if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(code).then(done, function () {});
        else {
          var ta = el('textarea'); ta.value = code; document.body.appendChild(ta); ta.select();
          document.execCommand('copy'); ta.remove(); done();
        }
      } catch (e) { /* nothing to do */ }
    };
    bar.appendChild(copy);
    box.appendChild(bar);
    var pre = el('pre'), c = el('code');
    c.textContent = code;
    pre.appendChild(c);
    box.appendChild(pre);
    if (typeof noI18n === 'function') noI18n(box);
    return box;
  }
  function draw(md) {
    var got = render(md);
    /* the guide is the author's text: not translated by the page */
    if (typeof noI18n === 'function') noI18n(got.node);
    return got;
  }

  /* ---- the popup that shows one ---------------------------------------------------------- */
  function versionsOf(p) {
    var out = [];
    (Array.isArray(p.versions) ? p.versions : []).forEach(function (v) { out.push([String(v.version || ''), v.version_label || (v.version ? v.version : tr('plain'))]); });
    if (!out.length) out.push([String(p.version || p.default_version || ''), p.version_label || '']);
    return out;
  }
  function ask(family, kind, version, lg, dflt) {
    return capiG('modules/guide' + '?' + ['family=' + encodeURIComponent(family), 'kind=' + encodeURIComponent(kind),
      'version=' + encodeURIComponent(version || ''), 'lang=' + lg].concat(dflt ? ['default=1'] : []).join('&'));
  }
  function capiG(path) {
    var q = '', at = path.indexOf('?');
    if (at >= 0) { q = path.slice(at + 1); path = path.slice(0, at); }
    var name = typeof window.ACME_CERTS_API === 'function' ? window.ACME_CERTS_API(path)
      : (window.ACME_CERTS_API_STYLE === 'dash' ? path.replace(/\//g, '-') : path);
    return api(name + (q ? '&' + q : ''), undefined, 30);
  }
  function capiPost(path, body) {
    var name = typeof window.ACME_CERTS_API === 'function' ? window.ACME_CERTS_API(path)
      : (window.ACME_CERTS_API_STYLE === 'dash' ? path.replace(/\//g, '-') : path);
    return api(name, body, 30);
  }
  function originWords(g) {
    return {written: 'written on the page Modules', module: 'carried by the module',
            shipped: 'shipped with acme', made: 'made from the module\'s fields - none written yet'}[g.origin] || '';
  }

  function guideShow(p, family, version, opt) {
    opt = opt || {};
    var kind = p.kind;
    var vers = versionsOf(p);
    var cur = {version: version === undefined || version === null ? String(p.version || '') : String(version), lang: lang()};
    var content = el('div', 'gd-content');
    var tocBox = el('nav', 'gd-toc');
    var meta = el('div', 'gd-meta');
    var load = function () {
      clear(content); clear(tocBox);
      content.appendChild(el('p', 'muted', 'Asking…'));
      return ask(family, kind, cur.version, cur.lang).then(function (g) {
        clear(content); clear(meta);
        var got = draw(g.md || '');
        content.appendChild(got.node);
        if (got.toc.length > 2) {
          tocBox.appendChild(el('div', 'gd-toc-h', 'Contents'));
          got.toc.forEach(function (t) {
            if (t.level === 1) return;
            var a = el('a', 'gd-toc-a lv' + t.level);
            a.textContent = t.words;
            if (typeof noI18n === 'function') noI18n(a);
            a.href = '#' + t.id;
            a.onclick = function (ev) { ev.preventDefault(); var x = document.getElementById(t.id); if (x) x.scrollIntoView({behavior: 'smooth', block: 'start'}); };
            tocBox.appendChild(a);
          });
        }
        tocBox.hidden = got.toc.length <= 2;
        meta.appendChild(el('span', 'tag ' + (g.origin === 'written' ? 'info' : (g.origin === 'made' ? 'dim' : 'ok')), originWords(g)));
        if (g.lang !== cur.lang) meta.appendChild(el('span', 'tag dim', 'in English - none in this language yet'));
        if (g.origin === 'written' && g.written_by) meta.appendChild(el('span', 'muted small', tr('by') + ' ' + g.written_by + (g.written_at ? ' · ' + stamp(g.written_at) : '')));
        cur.may = !!g.may;
        if (editB) editB.hidden = !cur.may;
      }).catch(function (e) { clear(content); content.appendChild(el('p', 'bad', String((e && e.message) || e))); });
    };
    var editB = null;
    var buttons = [{words: 'Close', close: true}];
    buttons.push({words: 'Edit the guide', icon: 'edit', cls: 'gd-editbtn', go: function () {
      editAny(p, family, cur.version, {lang: cur.lang});
    }});
    var show = function () {
      modal(tr('Setup guide') + ' · ' + (p.title || kind), function (body) {
        var head = el('div', 'gd-head');
        var left = el('div', 'gd-head-l');
        left.appendChild(el('span', 'tag dim', FAM_WORDS[family] || family));
        var kd = el('code', 'gd-kind', kind); if (typeof noI18n === 'function') noI18n(kd);
        left.appendChild(kd);
        head.appendChild(left);
        var right = el('div', 'gd-head-r');
        if (vers.length > 1 || cur.version) {
          var vs = selectBox(vers.map(function (v) { return [v[0], v[1] || (v[0] || tr('plain'))]; }), cur.version);
          if (typeof noI18n === 'function') noI18n(vs);
          vs.className += ' gd-vsel';
          vs.onchange = function () { cur.version = vs.value; load(); };
          var vl = el('label', 'gd-vlabel', 'Version');
          right.appendChild(vl);
          right.appendChild(vs);
        }
        var lg = el('div', 'gd-lang');
        [['cs', 'CS'], ['en', 'EN']].forEach(function (x) {
          var b = el('button', 'gd-langb' + (cur.lang === x[0] ? ' on' : ''), x[1]);
          b.type = 'button';
          if (typeof noI18n === 'function') noI18n(b);
          b.onclick = function () { cur.lang = x[0]; Array.prototype.forEach.call(lg.children, function (c) { c.classList.toggle('on', c === b); }); load(); };
          lg.appendChild(b);
        });
        right.appendChild(lg);
        head.appendChild(right);
        body.appendChild(head);
        body.appendChild(meta);
        var main = el('div', 'gd-main');
        main.appendChild(tocBox);
        main.appendChild(content);
        body.appendChild(main);
        setTimeout(function () { editB = $('modal-foot') && $('modal-foot').querySelector('.gd-editbtn'); if (editB) editB.hidden = !cur.may; load(); }, 0);
      }, buttons, 'gd-full');
    };
    /* over what is open (a form being filled is kept beneath, Close goes back to it) */
    if (opt.over && typeof modalOver === 'function') modalOver(show, opt.back); else show();
  }

  /* ---- the editor ---------------------------------------------------------------------- */
  var TOOLS = [
    ['H1', 'Heading 1', function (e) { lineStart(e, '# '); }],
    ['H2', 'Heading 2', function (e) { lineStart(e, '## '); }],
    ['H3', 'Heading 3', function (e) { lineStart(e, '### '); }],
    ['|'],
    ['B', 'Bold (Ctrl+B)', function (e) { around(e, '**', '**', 'bold'); }],
    ['I', 'Italic (Ctrl+I)', function (e) { around(e, '*', '*', 'italic'); }],
    ['S', 'Struck through', function (e) { around(e, '~~', '~~', 'text'); }],
    ['`', 'Code', function (e) { around(e, '`', '`', 'code'); }],
    ['|'],
    ['•', 'List', function (e) { lineStart(e, '- '); }],
    ['1.', 'Numbered list', function (e) { lineStart(e, '1. '); }],
    ['☐', 'Checklist', function (e) { lineStart(e, '- [ ] '); }],
    ['❝', 'Quote', function (e) { lineStart(e, '> '); }],
    ['|'],
    ['{ }', 'Code block (Ctrl+Shift+C)', function (e) { block(e, '```sh\n', '\n```', 'config system global\n    set admin-server-cert "acme"\nend'); }],
    ['▦', 'Table', function (e) { insert(e, '\n| Field | Value |\n|---|---|\n| | |\n'); }],
    ['🔗', 'Link (Ctrl+K)', function (e) { around(e, '[', '](https://)', 'words'); }],
    ['—', 'Line', function (e) { insert(e, '\n\n---\n\n'); }]
  ];
  function sel(t) { return {a: t.selectionStart, b: t.selectionEnd, v: t.value}; }
  function put(t, v, a, b) {
    t.focus();
    /* through the editing commands where they are (undo keeps working) */
    var old = t.value;
    t.setSelectionRange(0, old.length);
    var ok = false;
    try { ok = document.execCommand('insertText', false, v); } catch (e) { ok = false; }
    if (!ok || t.value !== v) t.value = v;
    t.setSelectionRange(a, b);
    t.dispatchEvent(new Event('input', {bubbles: true}));
  }
  function around(t, l, r, dflt) {
    var s = sel(t), mid = s.v.slice(s.a, s.b) || tr(dflt);
    put(t, s.v.slice(0, s.a) + l + mid + r + s.v.slice(s.b), s.a + l.length, s.a + l.length + mid.length);
  }
  function lineStart(t, mark) {
    var s = sel(t), v = s.v;
    var a = v.lastIndexOf('\n', s.a - 1) + 1, b = v.indexOf('\n', s.b); if (b < 0) b = v.length;
    var part = v.slice(a, b).split('\n').map(function (ln, k) {
      var clean = ln.replace(/^(#{1,6} |> |- \[[ xX]\] |[-*+] |\d+[.)] )/, '');
      var m = mark === '1. ' ? (k + 1) + '. ' : mark;
      return ln.indexOf(m) === 0 ? clean : m + clean;
    }).join('\n');
    put(t, v.slice(0, a) + part + v.slice(b), a, a + part.length);
  }
  function block(t, l, r, sample) {
    var s = sel(t), mid = s.v.slice(s.a, s.b) || sample;
    var pre = s.a && s.v.charAt(s.a - 1) !== '\n' ? '\n' : '';
    put(t, s.v.slice(0, s.a) + pre + l + mid + r + '\n' + s.v.slice(s.b), s.a + pre.length + l.length, s.a + pre.length + l.length + mid.length);
  }
  function insert(t, what) {
    var s = sel(t);
    put(t, s.v.slice(0, s.a) + what + s.v.slice(s.b), s.a + what.length, s.a + what.length);
  }

  function guideEdit(p, family, version, opt) {
    opt = opt || {};
    var kind = p.kind;
    var vers = versionsOf(p);
    var cur = {version: version === undefined || version === null ? String(p.version || '') : String(version), lang: opt.lang || lang(), base: '', origin: ''};
    var area, preview, said, wc, dirty = false;
    var setDirty = function (on) { dirty = on; if (said) said.classList.toggle('gd-dirty', on); };
    var paint = function () {
      clear(preview);
      preview.appendChild(draw(area.value).node);
      var w = (area.value.match(/\S+/g) || []).length;
      wc.textContent = w + ' ' + tr('words') + ' · ' + area.value.split('\n').length + ' ' + tr('lines');
    };
    var timer = null;
    var load = function () {
      said.textContent = tr('Asking…');
      return ask(family, kind, cur.version, cur.lang).then(function (g) {
        cur.origin = g.origin;
        /* another language's text is not taken as this one's: started from it, said */
        area.value = g.md || '';
        cur.loadedLang = g.lang;
        setDirty(false);
        paint();
        said.textContent = (g.origin === 'written' ? tr('written on the page') : (g.origin === 'made' ? tr('none written yet - this is made from its fields') : tr('the module\'s own text'))) +
          (g.lang !== cur.lang ? ' · ' + tr('in English - write it in this language') : '');
      }).catch(fail2);
    };
    var fail2 = function (e) { said.textContent = String((e && e.message) || e); said.className = 'bad small'; };
    var save = function (b) {
      busy(b, true);
      capiPost('modules/guide', {family: family, kind: kind, version: cur.version, lang: cur.lang, md: area.value}).then(function (d) {
        toast(d.message || 'kept', 'good');
        setDirty(false);
        load();
      }).catch(function (e) { toast(String((e && e.message) || e), 'bad'); }).then(function () { busy(b, false); });
    };
    var openEd = function () { modal(tr('Edit the setup guide') + ' · ' + (p.title || kind), function (body) {
      var head = el('div', 'gd-head');
      var left = el('div', 'gd-head-l');
      left.appendChild(el('span', 'tag dim', FAM_WORDS[family] || family));
      var kd = el('code', 'gd-kind', kind); if (typeof noI18n === 'function') noI18n(kd);
      left.appendChild(kd);
      head.appendChild(left);
      var right = el('div', 'gd-head-r');
      if (vers.length > 1 || cur.version) {
        var vs = selectBox(vers.map(function (v) { return [v[0], v[1] || (v[0] || tr('plain'))]; }), cur.version);
        if (typeof noI18n === 'function') noI18n(vs);
        vs.className += ' gd-vsel';
        vs.onchange = function () {
          if (dirty && !window.confirm(tr('Leave the changes not kept?'))) { vs.value = cur.version; return; }
          cur.version = vs.value; load();
        };
        right.appendChild(el('label', 'gd-vlabel', 'Version'));
        right.appendChild(vs);
      }
      var lg = el('div', 'gd-lang');
      [['cs', 'CS'], ['en', 'EN']].forEach(function (x) {
        var b = el('button', 'gd-langb' + (cur.lang === x[0] ? ' on' : ''), x[1]);
        b.type = 'button';
        if (typeof noI18n === 'function') noI18n(b);
        b.onclick = function () {
          if (dirty && !window.confirm(tr('Leave the changes not kept?'))) return;
          cur.lang = x[0];
          Array.prototype.forEach.call(lg.children, function (c) { c.classList.toggle('on', c === b); });
          load();
        };
        lg.appendChild(b);
      });
      right.appendChild(lg);
      head.appendChild(right);
      body.appendChild(head);

      var ed = el('div', 'gd-editor split');
      var bar = el('div', 'gd-toolbar');
      TOOLS.forEach(function (t) {
        if (t[0] === '|') { bar.appendChild(el('span', 'gd-sep')); return; }
        var b = el('button', 'gd-tool', t[0]);
        b.type = 'button';
        b.title = tr(t[1]);
        b.setAttribute('aria-label', tr(t[1]));
        if (typeof noI18n === 'function') noI18n(b);
        b.onclick = function () { t[2](area); };
        bar.appendChild(b);
      });
      var views = el('div', 'gd-views');
      [['edit', 'Write'], ['split', 'Side by side'], ['view', 'Preview']].forEach(function (x) {
        var b = el('button', 'gd-viewb' + (x[0] === 'split' ? ' on' : ''), x[1]);
        b.type = 'button';
        b.onclick = function () {
          ed.className = 'gd-editor ' + x[0];
          Array.prototype.forEach.call(views.children, function (c) { c.classList.toggle('on', c === b); });
          if (x[0] !== 'view') area.focus();
        };
        views.appendChild(b);
      });
      bar.appendChild(views);
      ed.appendChild(bar);
      var panes = el('div', 'gd-panes');
      area = el('textarea', 'gd-area');
      area.spellcheck = true;
      area.setAttribute('aria-label', tr('The guide, in Markdown'));
      if (typeof noI18n === 'function') noI18n(area);
      area.addEventListener('input', function () { setDirty(true); clearTimeout(timer); timer = setTimeout(paint, 120); });
      area.addEventListener('keydown', function (ev) {
        var k = ev.key.toLowerCase();
        if ((ev.ctrlKey || ev.metaKey) && k === 'b') { ev.preventDefault(); around(area, '**', '**', 'bold'); }
        else if ((ev.ctrlKey || ev.metaKey) && k === 'i') { ev.preventDefault(); around(area, '*', '*', 'italic'); }
        else if ((ev.ctrlKey || ev.metaKey) && k === 'k') { ev.preventDefault(); around(area, '[', '](https://)', 'words'); }
        else if ((ev.ctrlKey || ev.metaKey) && ev.shiftKey && k === 'c') { ev.preventDefault(); block(area, '```sh\n', '\n```', ''); }
        else if ((ev.ctrlKey || ev.metaKey) && k === 's') { ev.preventDefault(); var sb = $('modal-foot') && $('modal-foot').querySelector('.gd-savebtn'); if (sb) sb.click(); }
        else if (k === 'tab' && !ev.ctrlKey && !ev.altKey) {
          ev.preventDefault();
          var s = sel(area);
          if (ev.shiftKey) {
            var a = s.v.lastIndexOf('\n', s.a - 1) + 1;
            if (s.v.slice(a, a + 2) === '  ') put(area, s.v.slice(0, a) + s.v.slice(a + 2), Math.max(a, s.a - 2), Math.max(a, s.b - 2));
          } else insert(area, '  ');
        } else if (k === 'enter' && !ev.shiftKey) {
          /* a list goes on by itself; an empty item ends it */
          var s2 = sel(area), ls = s2.v.lastIndexOf('\n', s2.a - 1) + 1, line = s2.v.slice(ls, s2.a);
          var m = line.match(/^(\s*)([-*+] \[[ xX]\] |[-*+] |(\d+)([.)]) |> )/);
          if (m && s2.a === s2.b) {
            ev.preventDefault();
            if (line.trim() === m[2].trim()) { put(area, s2.v.slice(0, ls) + s2.v.slice(s2.a), ls, ls); return; }
            var next = m[3] ? (Number(m[3]) + 1) + m[4] + ' ' : m[2].replace(/\[[xX]\]/, '[ ]');
            insert(area, '\n' + m[1] + next);
          }
        }
      });
      var lpane = el('div', 'gd-pane gd-pane-l');
      lpane.appendChild(area);
      preview = el('div', 'gd-pane gd-pane-r gd-preview');
      panes.appendChild(lpane);
      panes.appendChild(preview);
      /* the preview follows the text as it is scrolled */
      area.addEventListener('scroll', function () {
        var r = area.scrollTop / Math.max(1, area.scrollHeight - area.clientHeight);
        preview.scrollTop = r * (preview.scrollHeight - preview.clientHeight);
      });
      ed.appendChild(panes);
      var foot = el('div', 'gd-edfoot');
      said = el('span', 'muted small gd-said', '');
      wc = el('span', 'muted small gd-wc', '');
      foot.appendChild(said);
      foot.appendChild(wc);
      ed.appendChild(foot);
      body.appendChild(ed);
      body.appendChild(el('p', 'muted small', 'Markdown: # headings, **bold**, *italic*, `code`, ```code blocks```, - lists, 1. numbered, | tables |, [links](https://…), > quotes. Kept in the database - on every node and in every backup; each version and language has its own.'));
      setTimeout(function () { load(); area.focus(); }, 0);
    }, [
      {words: 'Back to the module\'s own', cls: 'danger-soft', icon: 'undo', go: function (b) {
        confirmThen('Give the guide back to the module\'s own?', htmlText('What was written here for this version and language is taken away; the module\'s own text (or one made from its fields) is shown again.'),
          'Give it back', function () {
            capiPost('modules/guide', {family: family, kind: kind, version: cur.version, lang: cur.lang, md: ''}).then(function (d) {
              toast(d.message || 'done', 'good'); setDirty(false); load();
            }).catch(function (e) { toast(String((e && e.message) || e), 'bad'); });
          });
      }},
      {words: 'Close', close: true},
      {words: 'Show it', icon: 'eye', go: function () {
        if (dirty && !window.confirm(tr('Leave the changes not kept?'))) return;
        guideShow(p, family, cur.version);
      }},
      {words: 'Save', cls: 'primary gd-savebtn', icon: 'save', go: function (b) { save(b); }}
    ], 'gd-full'); };
    if (opt.over && typeof modalOver === 'function') modalOver(openEd, opt.back); else openEd();
  }

  /* the button a module's head carries (certs.js plugHead) */
  function guideButton(p, family, row) {
    var b = cmdButton('Setup guide', 'book', 'small gd-open');
    b.title = tr('How to set up the other side for acme - for this version');
    b.onclick = function (ev) {
      ev.preventDefault(); ev.stopPropagation();
      var v = row && row.version !== undefined ? row.version : (p.version !== undefined ? p.version : '');
      guideShow(p._base || p, family, v, {over: true});
    };
    return b;
  }

  /* the editor of its own file (guides-editor.js, 1.0.94): visual, Markdown, the Assistant */
  function editAny(p, family, version, opt) {
    if (window.ACME_GUIDE_EDITOR) return window.ACME_GUIDE_EDITOR.edit(p, family, version, opt);
    return guideEdit(p, family, version, opt);
  }
  window.ACME_GUIDES = {render: draw, show: guideShow, edit: editAny, button: guideButton};
})();
