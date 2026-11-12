/* guides.js - the setup guides of the modules (1.0.94, acmelib/certs/guides.py).

   For every source, validation, target and test - each version of it - a Markdown text
   saying how to set up the other side (the FortiGate, the DNS provider, the CA...) for acme.
   guideShow(): read-only, in a popup nearly the whole page, with its contents beside it;
   the editor (visual, Markdown, the assistant) is guides-editor.js - a full administrator's.

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
    var re = /\\([\\`*_{}\[\]()#+\-.!|~>])|(`+)([\s\S]*?[^`])\2(?!`)|\*\*([\s\S]+?)\*\*|__([\s\S]+?)__|~~([\s\S]+?)~~|\*([^*\s][\s\S]*?)\*|(^|[^\w])_([^_\s][\s\S]*?)_(?=[^\w]|$)|\[([^\]]+)\]\(((?:[^()\s]|\([^()\s]*\))+)(?:\s+"[^"]*")?\)|<(https?:\/\/[^>\s]+)>/g;
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
      if (esc) { cur += ch === '|' ? '|' : '\\' + ch; esc = false; continue; }
      if (ch === '\\') { esc = true; continue; }
      if (ch === '|') { out.push(cur.trim()); cur = ''; continue; }
      cur += ch;
    }
    if (esc) cur += '\\';
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
  /* a question over the window that is open (not the browser's own dialog): yes runs go */
  function sure(words, go, yesWords) {
    var host = document.getElementById('modal-box') || document.body;
    var old = host.querySelector(':scope > .gd-sure');
    if (old && old._end) old._end(); else if (old) old.remove();
    var veil = el('div', 'gd-sure');
    var box = el('div', 'gd-sure-box');
    box.setAttribute('role', 'alertdialog');
    box.appendChild(el('p', 'gd-sure-w', tr(words)));
    var row = el('div', 'gd-sure-row');
    /* what is asked here throws something away: red, and the focus on No (1.0.95: one Enter
       after Escape lost the edits) - as the other questions of the pages */
    var no = cmdButton('No, leave it', 'x', 'gd-sure-no');
    var yes = cmdButton(yesWords || 'Yes', 'check', 'danger gd-sure-yes');
    var end = function () { veil.remove(); document.removeEventListener('keydown', key, true); };
    var key = function (ev) {
      if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); end(); }
      else if (ev.key === 'Enter') {
        /* Enter presses what has the focus - "No" too; nothing focused in it: no */
        ev.preventDefault(); ev.stopPropagation();
        if (document.activeElement === yes) { end(); go(); } else end();
      } else if (ev.key === 'Tab') {
        /* the focus stays on its two buttons */
        ev.preventDefault();
        (document.activeElement === yes ? no : yes).focus();
      }
    };
    veil._end = end;
    no.onclick = end;
    yes.onclick = function () { end(); go(); };
    row.appendChild(no); row.appendChild(yes);
    box.appendChild(row);
    veil.appendChild(box);
    veil.addEventListener('mousedown', function (ev) { if (ev.target === veil) end(); });
    host.appendChild(veil);
    document.addEventListener('keydown', key, true);
    setTimeout(function () { no.focus(); }, 0);
  }
  /* the clipboard: the browser's own where the page is https, else the old way */
  function copyText(text, done) {
    var old = function () {
      try {
        var ta = el('textarea'); ta.value = text; ta.setAttribute('readonly', '');
        ta.style.position = 'fixed'; ta.style.opacity = '0';
        document.body.appendChild(ta); ta.select();
        var ok = document.execCommand('copy'); ta.remove();
        if (ok) done();
      } catch (e) { /* nothing to do */ }
    };
    try {
      if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(done, old);
      else old();
    } catch (e) { old(); }
  }
  /* in the guide shown: a command, a path, a value in the text is copied by a click */
  function copyable(node) {
    Array.prototype.forEach.call(node.querySelectorAll('code.gd-code'), function (c) {
      if (c.closest('pre, th, h1, h2, h3, h4, a') || !c.textContent.trim()) return;
      c.classList.add('gd-ccopy');
      c.title = tr('Click to copy');
      c.tabIndex = 0;
      var go = function () {
        copyText(c.textContent, function () {
          c.classList.add('gd-copied');
          setTimeout(function () { c.classList.remove('gd-copied'); }, 1200);
        });
      };
      c.addEventListener('click', go);
      c.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); go(); } });
    });
  }
  function codeBlock(code, langName) {
    var box = el('div', 'gd-pre');
    var bar = el('div', 'gd-pre-bar');
    bar.appendChild(el('span', 'gd-pre-lang', langName || 'text'));
    var copy = el('button', 'gd-copy');
    copy.type = 'button';
    copy.title = tr('Copy the whole block');
    var cw = el('span', '', tr('Copy'));
    copy.appendChild(el('span', 'gd-copy-ic', '⧉'));
    copy.appendChild(cw);
    copy.onclick = function () {
      copyText(code, function () {
        copy.classList.add('on'); cw.textContent = tr('Copied');
        setTimeout(function () { copy.classList.remove('on'); cw.textContent = tr('Copy'); }, 1400);
      });
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
  /* the version asked is among them (1.0.96: one not in the list showed "plain" over its text) */
  function withVersion(vers, v) {
    v = String(v || '');
    if (!vers.some(function (x) { return x[0] === v; })) vers.push([v, v || tr('plain')]);
    return vers;
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
    var cur = {version: version === undefined || version === null ? String(p.version || '') : String(version),
               lang: opt.lang === 'cs' || opt.lang === 'en' ? opt.lang : lang()};
    withVersion(vers, cur.version);
    var content = el('div', 'gd-content');
    var tocBox = el('nav', 'gd-toc');
    var meta = el('div', 'gd-meta');
    var load = function () {
      clear(content); clear(tocBox);
      content.appendChild(el('p', 'muted', 'Asking…'));
      return ask(family, kind, cur.version, cur.lang).then(function (g) {
        clear(content); clear(meta);
        var got = draw(g.md || '');
        copyable(got.node);
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
    toast(tr('The editor of the guides did not load - reload the page'), 'bad');
  }
  window.ACME_GUIDES = {sure: sure, render: draw, show: guideShow, edit: editAny, button: guideButton};
})();
