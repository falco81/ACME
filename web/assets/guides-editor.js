/* guides-editor.js - the editor of the setup guides (1.0.94; guides.js draws and shows them).

   Four ways to write, one text: Visual (what you see is what it will be - no Markdown to know),
   Markdown, Side by side, Preview. The Assistant beside it: whole parts of a guide to put in
   (the usual sections, a warning, CLI commands, the module's own fields as a table, steps), a
   start from somewhere (acme's own text of this version, another version's, the other
   language's, an outline), and the Markdown in a few lines.

   The visual editor is a contenteditable box: drawn from the Markdown by guides.js (every node
   made by hand) and read back into Markdown when it is left or saved. What is pasted into it
   is read the same way - its HTML taken apart in a document of its own (DOMParser: nothing in
   it runs) into Markdown and drawn again, so only what Markdown has comes in. */
'use strict';
(function () {
  var G = function () { return window.ACME_GUIDES || {}; };
  var FAM_WORDS = {issuer: 'Source', challenge: 'Validation', target: 'Target', check: 'Test'};
  var LANGS = ['sh', 'text', 'powershell', 'json', 'yaml', 'ini', 'sql', 'xml', 'python'];
  function tr(w) {
    try { var got = typeof i18nText === 'function' ? i18nText(w) : null; return got || w; }
    catch (e) { return w; }
  }
  function nn(x) { if (typeof noI18n === 'function') noI18n(x); return x; }
  function lang() {
    try {
      var code = (typeof I18N !== 'undefined' && I18N && I18N.on && I18N.code) || document.documentElement.lang || 'en';
      return String(code).slice(0, 2) === 'cs' ? 'cs' : 'en';
    } catch (e) { return 'en'; }
  }

  /* ---- HTML (the visual box, or what was pasted) read as Markdown ------------------------- */
  function ws(s) { return String(s).replace(/[\s ]+/g, ' '); }
  /* text that would read as Markdown kept as text: \* \` \_ (a _ inside a word is no mark) */
  function esc(s) { return String(s).replace(/\\/g, '\\\\').replace(/([*`])/g, '\\$1').replace(/(^|[^\w])_/g, '$1\\_').replace(/_(?=[^\w]|$)/g, '\\_'); }
  /* `code` - fenced by more backticks than it holds in a row, so none of its own is lost */
  function codeSpan(k) {
    var runs = String(k).match(/`+/g) || [], n = 0;
    runs.forEach(function (r) { n = Math.max(n, r.length); });
    var f = new Array(n + 2).join('`');
    var pad = n && (/^`|`$/.test(k) || /^ .* $/.test(k)) ? ' ' : (/^ .* $/.test(k) ? ' ' : '');
    return f + pad + k + pad + f;
  }
  /* a paragraph's line that would start a heading, list, quote, table or line: kept as text */
  function lead(p) {
    return String(p).replace(/^(\s*)(#{1,6}\s)/gm, '$1\\$2').replace(/^(\s*)>/gm, '$1\\>')
      .replace(/^(\s*)([-+])(\s)/gm, '$1\\$2$3').replace(/^(\s*)(\d{1,3})([.)])(\s)/gm, '$1$2\\$3$4')
      .replace(/^(\s*)\|/gm, '$1\\|').replace(/^(\s*)(-{3,}|_{3,})\s*$/gm, '$1\\$2');
  }
  function inl(node) {
    var out = '';
    Array.prototype.forEach.call(node.childNodes, function (c) {
      if (c.nodeType === 3) { out += esc(ws(c.nodeValue)); return; }
      if (c.nodeType !== 1) return;
      var t = c.tagName;
      if (c.classList && c.classList.contains('gd-check')) return;
      if (t === 'BR') { out += '  \n'; return; }
      if (/^(STRONG|B)$/.test(t)) { var b = inl(c).trim(); if (b) out += '**' + b + '**'; return; }
      if (/^(EM|I)$/.test(t)) { var e = inl(c).trim(); if (e) out += '*' + e + '*'; return; }
      if (/^(DEL|S|STRIKE)$/.test(t)) { var d = inl(c).trim(); if (d) out += '~~' + d + '~~'; return; }
      if (t === 'CODE' || t === 'KBD' || t === 'SAMP' || t === 'TT') { var k = c.textContent; if (k) out += codeSpan(k); return; }
      if (t === 'A') {
        var href = c.getAttribute('href') || '', words = inl(c).trim();
        if (/^(https?:|mailto:|#)/i.test(href) && words) out += '[' + words + '](' + href + ')'; else out += words;
        return;
      }
      if (/^(SCRIPT|STYLE|TEMPLATE|NOSCRIPT|IFRAME|OBJECT|SVG|IMG|VIDEO|AUDIO|SELECT|BUTTON)$/.test(t)) return;
      /* a span with bold or italic set by a style (pasted from a word processor) */
      var st = c.getAttribute && (c.getAttribute('style') || '');
      var inner = inl(c);
      if (/font-weight\s*:\s*(bold|[6-9]00)/i.test(st) && inner.trim()) inner = '**' + inner.trim() + '**';
      if (/font-style\s*:\s*italic/i.test(st) && inner.trim()) inner = '*' + inner.trim() + '*';
      out += inner;
    });
    return out;
  }
  var BLOCK = /^(P|DIV|H[1-6]|UL|OL|LI|BLOCKQUOTE|PRE|TABLE|HR|SECTION|ARTICLE|HEADER|FOOTER|MAIN|NAV|ASIDE|FIGURE|DL|DT|DD)$/;
  function hasBlocks(node) {
    return Array.prototype.some.call(node.childNodes, function (c) { return c.nodeType === 1 && BLOCK.test(c.tagName); });
  }
  function cell(x) { return inl(x).replace(/\s*\n\s*/g, ' ').replace(/\|/g, '\\|').trim(); }
  function list(el, depth) {
    var out = [], n = el.tagName === 'OL' ? (parseInt(el.getAttribute('start') || '1', 10) || 1) : 0;
    Array.prototype.forEach.call(el.children, function (li) {
      if (li.tagName !== 'LI') return;
      var pad = new Array(depth + 1).join('   ');
      var mark = el.tagName === 'OL' ? (n++) + '. ' : '- ';
      var chk = li.querySelector(':scope > .gd-check');
      if (chk) mark += chk.classList.contains('on') ? '[x] ' : '[ ] ';
      var text = '', subs = [];
      var indent = function (md) { var p2 = new Array(depth + 2).join('   '); return md.split('\n').map(function (x) { return x ? p2 + x : x; }).join('\n'); };
      var blockIn = function (c) {
        /* a block in an item (commands or a note under a step): kept under it, in its place */
        var host = document.createElement('div');
        host.appendChild(c.cloneNode(true));
        var s0 = c.querySelector && c.querySelector('select.gd-pre-sel');
        if (s0) { var s1 = host.querySelector('select.gd-pre-sel'); if (s1) s1.value = s0.value; }
        var md = blocks(host).trim();
        if (md) subs.push('\n' + indent(md) + '\n');
      };
      var loose = '';
      var flushLoose = function () { if (loose.trim()) subs.push('\n' + indent(loose.trim()) + '\n'); loose = ''; };
      Array.prototype.forEach.call(li.childNodes, function (c) {
        var isBlock = c.nodeType === 1 && (BLOCK.test(c.tagName) || c.classList.contains('gd-pre') || c.classList.contains('gd-tablewrap'));
        if (c.nodeType === 1 && c.classList.contains('gd-check')) return;
        if (c.nodeType === 1 && (c.tagName === 'UL' || c.tagName === 'OL')) { flushLoose(); subs.push(list(c, depth + 1)); return; }
        if (!isBlock) {
          var w = document.createElement('span');
          w.appendChild(c.cloneNode(true));
          if (subs.length) loose += inl(w); else text += inl(w);
          return;
        }
        flushLoose();
        if (!subs.length && !text.trim() && (c.tagName === 'P' || c.tagName === 'DIV') && !hasBlocks(c)) { text = inl(c); return; }
        blockIn(c);
      });
      flushLoose();
      out.push(pad + mark + text.replace(/\s*\n\s*/g, ' ').trim());
      subs.forEach(function (s) { out.push(s); });
    });
    return out.join('\n');
  }
  /* a block of code: fenced by more backticks than any line of it starts with */
  function fence(code, lg) {
    var n = 2;
    (String(code).match(/^\s*`+/gm) || []).forEach(function (r) { n = Math.max(n, r.trim().length); });
    var f = new Array(n + 2).join('`');
    return f + lg + '\n' + code + '\n' + f;
  }
  function blocks(node) {
    var out = [], para = '';
    var flush = function () { if (para.trim()) out.push(lead(para.trim())); para = ''; };
    Array.prototype.forEach.call(node.childNodes, function (c) {
      if (c.nodeType === 3) { para += esc(ws(c.nodeValue)); return; }
      if (c.nodeType !== 1) return;
      var t = c.tagName;
      if (/^(SCRIPT|STYLE|TEMPLATE|NOSCRIPT|IFRAME|OBJECT|HEAD|META|LINK|TITLE)$/.test(t)) return;
      if (c.classList.contains('gd-pre') || t === 'PRE') {
        flush();
        var pre = t === 'PRE' ? c : c.querySelector('pre');
        var sel = c.querySelector && c.querySelector('select.gd-pre-sel');
        var lg = sel ? sel.value : ((c.querySelector && c.querySelector('.gd-pre-lang')) ? c.querySelector('.gd-pre-lang').textContent : '');
        if (!lg && pre) { var cc = pre.querySelector('code'); var m = cc && /language-([\w+-]+)/.exec(cc.className || ''); if (m) lg = m[1]; }
        var code = pre ? pre.innerText !== undefined && pre.isConnected ? pre.innerText : pre.textContent : '';
        out.push(fence(String(code).replace(/\n+$/, ''), lg || ''));
        return;
      }
      if (/^H[1-6]$/.test(t)) { flush(); var h = inl(c).trim(); if (h) out.push(new Array(Number(t[1]) + 1).join('#') + ' ' + h); return; }
      if (t === 'UL' || t === 'OL') { flush(); var l = list(c, 0); if (l.trim()) out.push(l); return; }
      if (t === 'BLOCKQUOTE') { flush(); var q = blocks(c).trim(); if (q) out.push(q.split('\n').map(function (x) { return '> ' + x; }).join('\n').replace(/> $/gm, '>')); return; }
      if (t === 'HR') { flush(); out.push('---'); return; }
      if (t === 'TABLE' || (c.classList.contains('gd-tablewrap'))) {
        flush();
        var tbl = t === 'TABLE' ? c : c.querySelector('table');
        if (!tbl) return;
        var rows = Array.prototype.slice.call(tbl.querySelectorAll('tr'));
        if (!rows.length) return;
        var head = Array.prototype.map.call(rows[0].children, cell);
        var lines = ['| ' + head.join(' | ') + ' |', '|' + head.map(function () { return '---'; }).join('|') + '|'];
        rows.slice(1).forEach(function (r) {
          var cs = Array.prototype.map.call(r.children, cell);
          while (cs.length < head.length) cs.push('');
          lines.push('| ' + cs.slice(0, Math.max(head.length, cs.length)).join(' | ') + ' |');
        });
        out.push(lines.join('\n'));
        return;
      }
      if (t === 'BR') { para += '  \n'; return; }
      if (BLOCK.test(t)) {
        flush();
        if (/white-space\s*:\s*pre/i.test(c.getAttribute('style') || '') && c.children.length) {
          /* code copied from an editor (VS Code and the like): a line in a div each */
          var ls = Array.prototype.every.call(c.children, function (x) { return /^(DIV|P|BR)$/.test(x.tagName); })
            ? Array.prototype.map.call(c.children, function (x) { return x.tagName === 'BR' ? '' : x.textContent; }) : c.textContent.split('\n');
          out.push(fence(ls.join('\n').replace(/\n+$/, ''), ''));
        }
        else if (hasBlocks(c)) { var inner = blocks(c); if (inner.trim()) out.push(inner); }
        else { var p = inl(c).replace(/^\s+|\s+$/g, ''); if (p) out.push(lead(p)); }
        return;
      }
      /* inline element at block level: part of a paragraph */
      var wrap = document.createElement('span');
      wrap.appendChild(c.cloneNode(true));
      para += inl(wrap);
    });
    flush();
    return out.join('\n\n');
  }
  function toMd(root) { return blocks(root).replace(/\n{3,}/g, '\n\n').trim() + '\n'; }
  function fromHtml(html) {
    try {
      var doc = new DOMParser().parseFromString(String(html), 'text/html');
      return toMd(doc.body);
    } catch (e) { return ''; }
  }

  /* ---- the visual box: drawn for editing --------------------------------------------------- */
  function visualNodes(md) {
    var got = G().render ? G().render(md) : {node: el('div')};
    var root = got.node;
    /* code blocks: their text editable, their language a choice, the rest not */
    Array.prototype.slice.call(root.querySelectorAll('.gd-pre')).forEach(function (box) {
      var lg = (box.querySelector('.gd-pre-lang') || {}).textContent || 'text';
      var code = (box.querySelector('pre') || {}).textContent || '';
      box.replaceWith(codeBox(code, lg));
    });
    Array.prototype.slice.call(root.querySelectorAll('.gd-check')).forEach(function (c) {
      c.setAttribute('contenteditable', 'false');
      c.addEventListener('mousedown', function (ev) { ev.preventDefault(); c.classList.toggle('on'); c.textContent = c.classList.contains('on') ? '✓' : ''; c.dispatchEvent(new Event('input', {bubbles: true})); });
    });
    return root;
  }
  function codeBox(code, lg) {
    var box = el('div', 'gd-pre gd-pre-ed');
    box.setAttribute('contenteditable', 'false');
    var bar = el('div', 'gd-pre-bar');
    var sel = el('select', 'gd-pre-sel');
    var list = LANGS.slice();
    if (lg && list.indexOf(lg) < 0) list.push(lg);
    list.forEach(function (x) { var o = el('option', '', x); o.value = x; sel.appendChild(o); });
    sel.value = lg || 'text';
    nn(sel);
    bar.appendChild(sel);
    var rm = el('button', 'gd-pre-rm', '×');
    rm.type = 'button';
    rm.title = tr('Take this block away');
    rm.onclick = function () { var host = box.parentNode; box.remove(); if (host) host.dispatchEvent(new Event('input', {bubbles: true})); };
    bar.appendChild(rm);
    box.appendChild(bar);
    var pre = el('pre');
    pre.setAttribute('contenteditable', 'true');
    pre.setAttribute('spellcheck', 'false');
    pre.textContent = code;
    pre.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter') { ev.preventDefault(); document.execCommand('insertText', false, '\n'); }
      if (ev.key === 'Tab') { ev.preventDefault(); document.execCommand('insertText', false, '  '); }
    });
    box.appendChild(pre);
    nn(box);
    return box;
  }

  /* ---- what the Assistant puts in ----------------------------------------------------------- */
  function fieldsTable(p, cs) {
    var hidden = {verify: 1, verify_sni: 1, verify_tries: 1, verify_wait: 1, verify_served: 1};
    var rows = (p.fields || []).concat(p.deploy_fields || []).filter(function (f) { return f && f.key && !hidden[f.key]; });
    if (!rows.length) return '';
    var out = ['| ' + (cs ? 'Pole v acme | Co tam patří' : 'acme field | What goes there') + ' |', '|---|---|'];
    rows.slice(0, 60).forEach(function (f) {
      out.push('| ' + String(f.label || f.key).replace(/\|/g, '\\|') + ' | ' + String(f.help || '').replace(/\|/g, '\\|').replace(/\n/g, ' ') + ' |');
    });
    return out.join('\n');
  }
  function snippets(p, cs) {
    var title = p.title || p.kind;
    var S = cs ? {
      outline: ['# ' + title + ' - nastavení pro acme', '', 'Co acme na protějšku dělá a pro jaké verze je návod.', '',
        '## Co budete potřebovat', '', '- verze produktu', '- přístup z acme (adresa, port)', '',
        '## Nastavení ' + title, '', '1. Vytvořte uživatele s nejmenšími potřebnými právy.', '2. Povolte API a adresu acme.', '',
        '## Vyplnění v acme', '', fieldsTable(p, true), '', '## Kontrola', '', '- V acme stiskněte **Vyzkoušet**.', '',
        '## Časté problémy', '', '| Chyba | Řešení |', '|---|---|', '| 401 | Zkontrolujte token. |'].join('\n'),
      need: '## Co budete potřebovat\n\n- \n- ',
      setup: '## Nastavení ' + title + '\n\n1. \n2. \n3. ',
      fill: '## Vyplnění v acme\n\n' + (fieldsTable(p, true) || '| Pole | Hodnota |\n|---|---|\n| | |'),
      check: '## Kontrola\n\n- V acme stiskněte **Vyzkoušet** (Try).\n- Na protějšku ověřte: ',
      problems: '## Časté problémy\n\n| Chyba | Řešení |\n|---|---|\n| | |',
      warn: '> **Pozor:** ',
      tip: '> **Tip:** ',
      cli: '```sh\n\n```',
      steps: '1. \n2. \n3. '
    } : {
      outline: ['# ' + title + ' - setup for acme', '', 'What acme does there, and which versions this guide is for.', '',
        '## What you need', '', '- the product version', '- network access from acme (address, port)', '',
        '## Set up ' + title, '', '1. Create a user with the least rights needed.', '2. Allow the API and acme\'s address.', '',
        '## Fill in acme', '', fieldsTable(p, false), '', '## Check it', '', '- Press **Try** in acme.', '',
        '## Common problems', '', '| Error | Fix |', '|---|---|', '| 401 | Check the token. |'].join('\n'),
      need: '## What you need\n\n- \n- ',
      setup: '## Set up ' + title + '\n\n1. \n2. \n3. ',
      fill: '## Fill in acme\n\n' + (fieldsTable(p, false) || '| Field | Value |\n|---|---|\n| | |'),
      check: '## Check it\n\n- Press **Try** in acme.\n- On the other side, check: ',
      problems: '## Common problems\n\n| Error | Fix |\n|---|---|\n| | |',
      warn: '> **Warning:** ',
      tip: '> **Tip:** ',
      cli: '```sh\n\n```',
      steps: '1. \n2. \n3. '
    };
    return S;
  }

  /* ---- the editor -------------------------------------------------------------------------- */
  function edit(p, family, version, opt) {
    opt = opt || {};
    var kind = p.kind;
    var base = p._base || p;
    var vers = (Array.isArray(base.versions) && base.versions.length ? base.versions : [{version: p.version || '', version_label: p.version_label || ''}])
      .map(function (v) { return [String(v.version || ''), versionWords(v) || v.version || tr('plain')]; });
    var cur = {version: version === undefined || version === null ? String(p.version || '') : String(version),
               lang: opt.lang || lang(), mode: 'visual', origin: ''};
    var area, vis, preview, said, wc, assist, dirty = false, timer = null;
    var setDirty = function (on) { dirty = on; if (said) said.classList.toggle('gd-dirty', on); };
    var text = function () { return cur.mode === 'visual' ? toMd(vis) : area.value; };
    var paintPreview = function () {
      clear(preview);
      preview.appendChild(G().render(area.value).node);
    };
    var count = function () {
      var t = text();
      wc.textContent = (t.match(/\S+/g) || []).length + ' ' + tr('words') + ' · ' + t.split('\n').length + ' ' + tr('lines');
    };
    var setText = function (md) {
      area.value = md;
      clear(vis);
      var nodes = visualNodes(md);
      while (nodes.firstChild) vis.appendChild(nodes.firstChild);
      if (!vis.firstChild) vis.appendChild(el('p'));
      paintPreview();
      count();
    };
    var mode = function (m) {
      if (m === cur.mode) return;
      if (cur.mode === 'visual') area.value = toMd(vis);              /* leaving: read back */
      if (m === 'visual') setText(area.value);
      cur.mode = m;
      ed.className = 'gd-editor gd-mode-' + m + (assistOn ? ' gd-with-assist' : '');
      if (m === 'split' || m === 'view') paintPreview();
      Array.prototype.forEach.call(views.children, function (c) { c.classList.toggle('on', c.dataset.m === m); });
      toolsState();
      setTimeout(function () { (m === 'visual' ? vis : (m === 'view' ? preview : area)).focus(); }, 0);
    };
    var ask = function (ver, lg, dflt) {
      var q = ['family=' + encodeURIComponent(family), 'kind=' + encodeURIComponent(kind),
               'version=' + encodeURIComponent(ver || ''), 'lang=' + lg].concat(dflt ? ['default=1'] : []).join('&');
      var name = typeof window.ACME_CERTS_API === 'function' ? window.ACME_CERTS_API('modules/guide')
        : (window.ACME_CERTS_API_STYLE === 'dash' ? 'modules-guide' : 'modules/guide');
      return api(name + '&' + q, undefined, 30);
    };
    var post = function (body) {
      var name = typeof window.ACME_CERTS_API === 'function' ? window.ACME_CERTS_API('modules/guide')
        : (window.ACME_CERTS_API_STYLE === 'dash' ? 'modules-guide' : 'modules/guide');
      return api(name, body, 30);
    };
    var originWords = function (g) {
      /* the same words as the guide shown (1.0.95: "acme's own text" there, "shipped with
         acme" here, for one and the same) */
      return g.origin === 'written' ? tr('written on the page Modules') + (g.written_by ? ' · ' + g.written_by : '')
        : g.origin === 'module' ? tr('carried by the module')
        : g.origin === 'shipped' ? tr('shipped with acme')
        : tr('made from the module\'s fields - none written yet');
    };
    var load = function () {
      said.textContent = tr('Asking…');
      return ask(cur.version, cur.lang).then(function (g) {
        cur.origin = g.origin;
        setText(g.md || '');
        setDirty(false);
        stateTag.className = 'tag ' + (g.origin === 'written' ? 'info' : (g.origin === 'made' ? 'dim' : 'ok'));
        stateTag.textContent = originWords(g);
        said.textContent = g.lang !== cur.lang ? tr('this language has none yet: the English text is shown to start from') : '';
        resetB.disabled = !(g.origin === 'written' && g.lang === cur.lang);
      }).catch(function (e) { said.textContent = String((e && e.message) || e); });
    };
    var keep = function (b) {
      busy(b, true);
      post({family: family, kind: kind, version: cur.version, lang: cur.lang, md: text()}).then(function (d) {
        toast(tr(d.message || 'kept'), 'good');
        setDirty(false);              /* kept: Close does not ask, whatever the reading after it */
        load();
      }).catch(function (e) { toast(String((e && e.message) || e), 'bad'); }).then(function () { busy(b, false); });
    };
    var leave = function (go) { if (!dirty) return go(); G().sure('Leave the changes not kept?', go, 'Leave them'); };

    /* putting a part in, wherever the caret is */
    var put = function (md) {
      if (cur.mode === 'visual') {
        vis.focus();
        var sel = window.getSelection();
        var nodes = visualNodes(md);
        var frag = document.createDocumentFragment(), last = null;
        while (nodes.firstChild) { last = nodes.firstChild; frag.appendChild(last); }
        var r = sel.rangeCount && vis.contains(sel.getRangeAt(0).commonAncestorContainer) ? sel.getRangeAt(0) : null;
        if (!r) { vis.appendChild(frag); }
        else {
          /* at the block the caret is in: after it, never inside a heading or a list item */
          var blk = r.startContainer.nodeType === 1 ? r.startContainer : r.startContainer.parentNode;
          while (blk && blk.parentNode !== vis) blk = blk.parentNode;
          if (blk && blk.parentNode === vis) {
            var empty = !blk.textContent.trim() && !blk.querySelector('pre,table,hr');
            if (empty) blk.replaceWith(frag); else blk.after(frag);
          } else vis.appendChild(frag);
        }
        if (last && last.scrollIntoView) last.scrollIntoView({block: 'nearest'});
        setDirty(true); count();
      } else {
        var t = area, a = t.selectionStart, b = t.selectionEnd, v = t.value;
        var pre = a && v.charAt(a - 1) !== '\n' ? '\n\n' : (a && v.charAt(a - 2) !== '\n' ? '\n' : '');
        var ins = pre + md + '\n';
        t.focus();
        t.setSelectionRange(a, b);
        var ok = false;
        try { ok = document.execCommand('insertText', false, ins); } catch (e) { ok = false; }
        if (!ok) { t.value = v.slice(0, a) + ins + v.slice(b); }
        t.dispatchEvent(new Event('input', {bubbles: true}));
      }
    };

    /* the visual toolbar's own way, the Markdown one's own */
    var exec = function (cmd, val) { vis.focus(); try { document.execCommand(cmd, false, val); } catch (e) { /* not there */ } setDirty(true); count(); toolsState(); };
    var blockOf = function () {
      var s = window.getSelection();
      if (!s.rangeCount) return null;
      var n = s.getRangeAt(0).startContainer;
      while (n && n !== vis) { if (n.nodeType === 1 && /^(H[1-6]|P|BLOCKQUOTE|LI|PRE|TD|TH|DIV)$/.test(n.tagName)) return n; n = n.parentNode; }
      return null;
    };
    var heading = function (n) {
      var b = blockOf();
      exec('formatBlock', b && b.tagName === 'H' + n ? 'P' : 'H' + n);
    };
    var inlineCode = function () {
      var s = window.getSelection();
      if (!s.rangeCount || s.isCollapsed) { exec('insertHTML', '<code class="gd-code">' + 'code' + '</code>&nbsp;'); return; }
      var r = s.getRangeAt(0);
      var c = el('code', 'gd-code');
      c.textContent = r.toString();
      r.deleteContents();
      r.insertNode(c);
      setDirty(true);
    };
    var linkAsk = function () {
      var s = window.getSelection();
      var range = s.rangeCount ? s.getRangeAt(0).cloneRange() : null;
      var words = range ? range.toString() : '';
      linkPop(words, function (url, w) {
        if (cur.mode === 'visual') {
          vis.focus();
          var s2 = window.getSelection();
          s2.removeAllRanges();
          if (range) s2.addRange(range);
          if (words) exec('createLink', url);
          else { var a = el('a', 'gd-link', w || url); a.href = url; if (range) range.insertNode(a); else vis.appendChild(a); setDirty(true); }
        } else {
          var t = area, a1 = t.selectionStart, b1 = t.selectionEnd, w2 = t.value.slice(a1, b1) || w || url;
          t.focus(); t.setSelectionRange(a1, b1);
          try { document.execCommand('insertText', false, '[' + w2 + '](' + url + ')'); } catch (e) { t.value = t.value.slice(0, a1) + '[' + w2 + '](' + url + ')' + t.value.slice(b1); }
          t.dispatchEvent(new Event('input', {bubbles: true}));
        }
      });
    };
    var linkPop = function (words, done) {
      var pop = el('div', 'gd-pop');
      pop.appendChild(el('div', 'gd-pop-h', 'A link'));
      var u = el('input'); u.type = 'url'; u.placeholder = 'https://'; u.className = 'mono';
      var w = el('input'); w.type = 'text'; w.placeholder = tr('the words shown'); w.value = words || '';
      pop.appendChild(formField('Address', u));
      if (!words) pop.appendChild(formField('Words', w));
      var row = el('div', 'gd-pop-b');
      var no = cmdButton('Close', 'x', 'small'); no.onclick = function () { pop.remove(); };
      var go = cmdButton('Put it in', 'add', 'small primary');
      go.onclick = function () {
        var url = u.value.trim();
        if (!/^(https?:\/\/|mailto:)/i.test(url)) { toast(tr('a link is an https://, http:// or mailto: address'), 'bad'); u.focus(); return; }
        pop.remove(); done(url, w.value.trim());
      };
      var keys = function (ev) { if (ev.key === 'Enter') { ev.preventDefault(); ev.stopPropagation(); go.click(); } if (ev.key === 'Escape') { ev.preventDefault(); ev.stopPropagation(); pop.remove(); } };
      u.addEventListener('keydown', keys);
      w.addEventListener('keydown', keys);
      row.appendChild(no); row.appendChild(go);
      pop.appendChild(row);
      ed.appendChild(pop);
      setTimeout(function () { u.focus(); }, 0);
    };
    var tableIn = function () {
      if (cur.mode === 'visual') put(tr('| Field | Value |') === '| Field | Value |' ? '| Field | Value |\n|---|---|\n| | |\n| | |' : tr('| Field | Value |') + '\n|---|---|\n| | |\n| | |');
      else put('| Field | Value |\n|---|---|\n| | |');
    };
    var tableCmd = function (what) {
      var s = window.getSelection();
      if (!s.rangeCount) return;
      var n = s.getRangeAt(0).startContainer;
      while (n && n !== vis && !(n.nodeType === 1 && /^(TD|TH)$/.test(n.tagName))) n = n.parentNode;
      if (!n || n === vis) { toast(tr('put the caret in a table first'), 'bad'); return; }
      var row = n.parentNode, tbl = row.closest('table'), idx = Array.prototype.indexOf.call(row.children, n);
      if (what === 'row') {
        var nr = el('tr');
        Array.prototype.forEach.call(row.children, function () { nr.appendChild(el('td')); });
        var body = tbl.tBodies[0] || tbl.appendChild(el('tbody'));
        if (row.parentNode.tagName === 'THEAD') body.insertBefore(nr, body.firstChild); else row.after(nr);
      } else if (what === 'col') {
        Array.prototype.forEach.call(tbl.querySelectorAll('tr'), function (r) {
          var isHead = r.parentNode.tagName === 'THEAD';
          var c = el(isHead ? 'th' : 'td');
          var ref = r.children[idx];
          if (ref) ref.after(c); else r.appendChild(c);
        });
      } else if (what === 'delrow') {
        if (row.parentNode.tagName === 'THEAD') { toast(tr('the heading row stays'), 'bad'); return; }
        row.remove();
      } else if (what === 'delcol') {
        Array.prototype.forEach.call(tbl.querySelectorAll('tr'), function (r) { if (r.children[idx]) r.children[idx].remove(); });
        if (!tbl.querySelector('th,td')) { var w = tbl.closest('.gd-tablewrap') || tbl; w.remove(); }
      }
      setDirty(true);
    };
    var md = {
      around: function (l, r, d) {
        var t = area, a = t.selectionStart, b = t.selectionEnd, mid = t.value.slice(a, b) || tr(d);
        t.focus(); t.setSelectionRange(a, b);
        try { document.execCommand('insertText', false, l + mid + r); } catch (e) { t.value = t.value.slice(0, a) + l + mid + r + t.value.slice(b); }
        t.setSelectionRange(a + l.length, a + l.length + mid.length);
        t.dispatchEvent(new Event('input', {bubbles: true}));
      },
      line: function (mark) {
        var t = area, v = t.value, a = v.lastIndexOf('\n', t.selectionStart - 1) + 1, b = v.indexOf('\n', t.selectionEnd); if (b < 0) b = v.length;
        var part = v.slice(a, b).split('\n').map(function (ln, k) {
          var clean = ln.replace(/^(#{1,6} |> |- \[[ xX]\] |[-*+] |\d+[.)] )/, '');
          var m = mark === '1. ' ? (k + 1) + '. ' : mark;
          return ln.indexOf(m) === 0 ? clean : m + clean;
        }).join('\n');
        t.focus(); t.setSelectionRange(a, b);
        try { document.execCommand('insertText', false, part); } catch (e) { t.value = v.slice(0, a) + part + v.slice(b); }
        t.dispatchEvent(new Event('input', {bubbles: true}));
      }
    };
    var TOOLS = [
      {k: 'undo', i: '↶', t: 'Undo (Ctrl+Z)', v: function () { exec('undo'); }, m: function () { area.focus(); document.execCommand('undo'); }},
      {k: 'redo', i: '↷', t: 'Redo (Ctrl+Y)', v: function () { exec('redo'); }, m: function () { area.focus(); document.execCommand('redo'); }},
      {sep: 1},
      {k: 'h1', i: 'H1', t: 'Title', v: function () { heading(1); }, m: function () { md.line('# '); }},
      {k: 'h2', i: 'H2', t: 'Section heading', v: function () { heading(2); }, m: function () { md.line('## '); }},
      {k: 'h3', i: 'H3', t: 'Smaller heading', v: function () { heading(3); }, m: function () { md.line('### '); }},
      {k: 'p', i: '¶', t: 'Plain text', v: function () { exec('formatBlock', 'P'); }, m: function () { md.line(''); }},
      {sep: 1},
      {k: 'b', i: 'B', t: 'Bold (Ctrl+B)', v: function () { exec('bold'); }, m: function () { md.around('**', '**', 'bold'); }},
      {k: 'i', i: 'I', t: 'Italic (Ctrl+I)', v: function () { exec('italic'); }, m: function () { md.around('*', '*', 'italic'); }},
      {k: 's', i: 'S', t: 'Struck through', v: function () { exec('strikeThrough'); }, m: function () { md.around('~~', '~~', 'text'); }},
      {k: 'code', i: '‹›', t: 'Code in the text', v: inlineCode, m: function () { md.around('`', '`', 'code'); }},
      {k: 'link', i: '🔗', t: 'Link (Ctrl+K)', v: linkAsk, m: linkAsk},
      {sep: 1},
      {k: 'ul', i: '•≡', t: 'List', v: function () { exec('insertUnorderedList'); }, m: function () { md.line('- '); }},
      {k: 'ol', i: '1≡', t: 'Numbered steps', v: function () { exec('insertOrderedList'); }, m: function () { md.line('1. '); }},
      {k: 'quote', i: '❝', t: 'A note (quote)', v: function () { var b = blockOf(); exec('formatBlock', b && b.closest('blockquote') ? 'P' : 'BLOCKQUOTE'); }, m: function () { md.line('> '); }},
      {sep: 1},
      {k: 'pre', i: '{ }', t: 'Commands (code block)', v: function () { put('```sh\n\n```'); }, m: function () { put('```sh\n\n```'); }},
      {k: 'table', i: '▦', t: 'Table', v: tableIn, m: tableIn},
      {k: 'hr', i: '—', t: 'Dividing line', v: function () { exec('insertHorizontalRule'); }, m: function () { put('---'); }},
      {sep: 1, vis: 1},
      {k: 'row', i: '+▤', t: 'Table: a row below', vis: 1, v: function () { tableCmd('row'); }},
      {k: 'col', i: '+▥', t: 'Table: a column right', vis: 1, v: function () { tableCmd('col'); }},
      {k: 'delrow', i: '−▤', t: 'Table: take the row away', vis: 1, v: function () { tableCmd('delrow'); }},
      {k: 'delcol', i: '−▥', t: 'Table: take the column away', vis: 1, v: function () { tableCmd('delcol'); }}
    ];
    var toolEls = {};
    var toolsState = function () {
      if (ed && !ed.isConnected) { document.removeEventListener('selectionchange', toolsState); return; }
      if (!vis) return;
      var s = window.getSelection(), inT = false;
      if (cur.mode === 'visual' && s.rangeCount && vis.contains(s.getRangeAt(0).startContainer)) {
        var n = s.getRangeAt(0).startContainer;
        inT = !!(n.nodeType === 1 ? n : n.parentNode).closest('table');
        var state = function (c) { try { return document.queryCommandState(c); } catch (e) { return false; } };
        ['b:bold', 'i:italic', 's:strikeThrough', 'ul:insertUnorderedList', 'ol:insertOrderedList'].forEach(function (x) {
          var kv = x.split(':'); if (toolEls[kv[0]]) toolEls[kv[0]].classList.toggle('on', state(kv[1]));
        });
        var b = blockOf();
        ['h1', 'h2', 'h3'].forEach(function (h) { if (toolEls[h]) toolEls[h].classList.toggle('on', !!b && b.tagName === h.toUpperCase()); });
      } else Object.keys(toolEls).forEach(function (k) { toolEls[k].classList.remove('on'); });
      ['row', 'col', 'delrow', 'delcol'].forEach(function (k) { if (toolEls[k]) toolEls[k].hidden = !(cur.mode === 'visual' && inT); });
      Array.prototype.forEach.call(bar.querySelectorAll('.gd-sep.vis'), function (x) { x.hidden = !(cur.mode === 'visual' && inT); });
      bar.classList.toggle('gd-bar-off', cur.mode === 'view');
    };

    var ed, bar, views, stateTag, resetB, assistOn = window.innerWidth > 900, assistB;
    var openEd = function () { modal(tr('Edit the setup guide') + ' · ' + (p.title || kind), function (body) {
      /* the head: what it is, its version, its language, where its text is from */
      var head = el('div', 'gd-head');
      var left = el('div', 'gd-head-l');
      left.appendChild(el('span', 'tag dim', FAM_WORDS[family] || family));
      left.appendChild(nn(el('code', 'gd-kind', kind)));
      stateTag = el('span', 'tag dim', '');
      left.appendChild(stateTag);
      head.appendChild(left);
      var right = el('div', 'gd-head-r');
      if (vers.length > 1 || cur.version) {
        var vs = selectBox(vers, cur.version);
        nn(vs);
        vs.className += ' gd-vsel';
        vs.onchange = function () { var want = vs.value; vs.value = cur.version; leave(function () { vs.value = want; cur.version = want; load(); }); };
        right.appendChild(el('label', 'gd-vlabel', 'Version'));
        right.appendChild(vs);
      }
      var lg = el('div', 'gd-lang');
      [['cs', 'Čeština'], ['en', 'English']].forEach(function (x) {
        var b = el('button', 'gd-langb' + (cur.lang === x[0] ? ' on' : ''), x[1]);
        b.type = 'button';
        nn(b);
        b.onclick = function () {
          if (cur.lang === x[0]) return;
          leave(function () {
            cur.lang = x[0];
            Array.prototype.forEach.call(lg.children, function (c) { c.classList.toggle('on', c === b); });
            load();
          });
        };
        lg.appendChild(b);
      });
      right.appendChild(lg);
      head.appendChild(right);
      body.appendChild(head);

      ed = el('div', 'gd-editor gd-mode-visual' + (assistOn ? ' gd-with-assist' : ''));
      bar = el('div', 'gd-toolbar');
      TOOLS.forEach(function (t) {
        if (t.sep) { var sp = el('span', 'gd-sep' + (t.vis ? ' vis' : '')); bar.appendChild(sp); return; }
        var b = el('button', 'gd-tool gd-t-' + t.k, t.i);
        b.type = 'button';
        b.title = tr(t.t);
        b.setAttribute('aria-label', tr(t.t));
        nn(b);
        if (t.vis) b.hidden = true;
        b.addEventListener('mousedown', function (ev) { ev.preventDefault(); });     /* the selection stays */
        b.onclick = function () { if (cur.mode === 'visual') t.v(); else if (t.m) t.m(); if (cur.mode === 'split') paintPreview(); };
        toolEls[t.k] = b;
        bar.appendChild(b);
      });
      views = el('div', 'gd-views');
      [['visual', 'Visual'], ['markdown', 'Markdown'], ['split', 'Side by side'], ['view', 'Preview']].forEach(function (x) {
        var b = el('button', 'gd-viewb' + (x[0] === 'visual' ? ' on' : ''), x[1]);
        b.type = 'button';
        b.dataset.m = x[0];
        b.onclick = function () { mode(x[0]); };
        views.appendChild(b);
      });
      bar.appendChild(views);
      assistB = el('button', 'gd-assistb' + (assistOn ? ' on' : ''), 'Assistant');
      assistB.type = 'button';
      assistB.onclick = function () {
        assistOn = !assistOn;
        assistB.classList.toggle('on', assistOn);
        ed.classList.toggle('gd-with-assist', assistOn);
      };
      bar.appendChild(assistB);
      ed.appendChild(bar);

      var work = el('div', 'gd-work');
      var panes = el('div', 'gd-panes');
      /* visual */
      vis = el('div', 'gd-pane gd-visual gd-md');
      vis.setAttribute('contenteditable', 'true');
      vis.setAttribute('spellcheck', 'true');
      vis.setAttribute('role', 'textbox');
      vis.setAttribute('aria-multiline', 'true');
      vis.setAttribute('aria-label', tr('The guide'));
      nn(vis);
      vis.addEventListener('input', function () { setDirty(true); clearTimeout(timer); timer = setTimeout(count, 200); });
      vis.addEventListener('keyup', toolsState);
      vis.addEventListener('mouseup', toolsState);
      vis.addEventListener('paste', function (ev) {
        var cd = ev.clipboardData;
        if (!cd) return;
        var html = cd.getData('text/html'), plain = cd.getData('text/plain');
        var mdIn = html ? fromHtml(html) : '';
        if (!mdIn.trim() && plain) {
          /* Markdown pasted as text: drawn; plain words: as they are */
          if (/^(#{1,6} |[-*+] |\d+\. |```|> |\|.*\|)/m.test(plain)) mdIn = plain;
          else { ev.preventDefault(); document.execCommand('insertText', false, plain); return; }
        }
        if (!mdIn) return;
        ev.preventDefault();
        if (!/\n/.test(mdIn.trim()) && !/^(#|[-*+] |\d+\. |```|>|\|)/.test(mdIn.trim())) {
          var tmp = G().render(mdIn.trim()).node;
          var p0 = tmp.querySelector('p');
          if (p0) { var fr = document.createDocumentFragment(); while (p0.firstChild) fr.appendChild(p0.firstChild);
            var s = window.getSelection(); if (s.rangeCount) { var r = s.getRangeAt(0); r.deleteContents(); r.insertNode(fr); r.collapse(false); } setDirty(true); return; }
        }
        put(mdIn);
      });
      vis.addEventListener('keydown', function (ev) {
        var k = ev.key.toLowerCase(), c = ev.ctrlKey || ev.metaKey;
        if (c && k === 'k') { ev.preventDefault(); linkAsk(); }
        else if (c && k === 's') { ev.preventDefault(); var sb = $('modal-foot') && $('modal-foot').querySelector('.gd-savebtn'); if (sb) sb.click(); }
        else if (c && ev.altKey && /^[123]$/.test(k)) { ev.preventDefault(); heading(Number(k)); }
        else if (c && ev.altKey && k === '0') { ev.preventDefault(); exec('formatBlock', 'P'); }
      });
      panes.appendChild(vis);
      /* Markdown */
      area = el('textarea', 'gd-pane gd-area');
      area.spellcheck = true;
      area.setAttribute('aria-label', tr('The guide, in Markdown'));
      nn(area);
      area.addEventListener('input', function () { setDirty(true); clearTimeout(timer); timer = setTimeout(function () { if (cur.mode === 'split') paintPreview(); count(); }, 150); });
      area.addEventListener('keydown', function (ev) {
        var k = ev.key.toLowerCase(), c = ev.ctrlKey || ev.metaKey;
        if (c && k === 'b') { ev.preventDefault(); md.around('**', '**', 'bold'); }
        else if (c && k === 'i') { ev.preventDefault(); md.around('*', '*', 'italic'); }
        else if (c && k === 'k') { ev.preventDefault(); linkAsk(); }
        else if (c && k === 's') { ev.preventDefault(); var sb = $('modal-foot') && $('modal-foot').querySelector('.gd-savebtn'); if (sb) sb.click(); }
        else if (k === 'tab' && !c && !ev.altKey) { ev.preventDefault(); document.execCommand('insertText', false, '  '); }
        else if (k === 'enter' && !ev.shiftKey) {
          var a = area.selectionStart, ls = area.value.lastIndexOf('\n', a - 1) + 1, line = area.value.slice(ls, a);
          var m = line.match(/^(\s*)([-*+] \[[ xX]\] |[-*+] |(\d+)([.)]) |> )/);
          if (m && a === area.selectionEnd) {
            ev.preventDefault();
            if (line.trim() === m[2].trim()) { area.setSelectionRange(ls, a); document.execCommand('insertText', false, ''); return; }
            var next = m[3] ? (Number(m[3]) + 1) + m[4] + ' ' : m[2].replace(/\[[xX]\]/, '[ ]');
            document.execCommand('insertText', false, '\n' + m[1] + next);
          }
        }
      });
      area.addEventListener('scroll', function () {
        if (cur.mode !== 'split') return;
        var r = area.scrollTop / Math.max(1, area.scrollHeight - area.clientHeight);
        preview.scrollTop = r * (preview.scrollHeight - preview.clientHeight);
      });
      panes.appendChild(area);
      preview = el('div', 'gd-pane gd-preview');
      panes.appendChild(preview);
      work.appendChild(panes);

      /* the Assistant */
      assist = el('aside', 'gd-assist');
      var sec = function (title, sub) {
        var s = el('section', 'gd-as-sec');
        s.appendChild(el('div', 'gd-as-h', title));
        if (sub) s.appendChild(el('div', 'gd-as-sub', sub));
        assist.appendChild(s);
        return s;
      };
      var parts = sec('Put a part in', 'A part of a guide where the caret is - then fill it in.');
      var grid = el('div', 'gd-as-grid');
      [['outline', '☰', 'Whole outline', 'every usual section, the fields filled in'],
       ['need', '✓', 'What you need', 'versions, access'],
       ['setup', '⚙', 'Setting it up', 'numbered steps'],
       ['fill', '▦', 'Fill in acme', 'the module\'s fields as a table'],
       ['check', '🔎', 'Check it', 'how to verify'],
       ['problems', '⚠', 'Common problems', 'errors and fixes'],
       ['warn', '!', 'Warning', 'something to take care of'],
       ['tip', '💡', 'Tip', 'a good piece of advice'],
       ['cli', '›_', 'Commands', 'a block to copy'],
       ['steps', '1·2', 'Steps', 'a numbered list']].forEach(function (x) {
        var b = el('button', 'gd-as-card');
        b.type = 'button';
        var ic = el('span', 'gd-as-ic', x[1]); nn(ic);
        b.appendChild(ic);
        var w = el('span', 'gd-as-w');
        w.appendChild(el('b', '', x[2]));
        w.appendChild(el('small', '', x[3]));
        b.appendChild(w);
        b.addEventListener('mousedown', function (ev) { ev.preventDefault(); });
        b.onclick = function () {
          var S = snippets(p, cur.lang === 'cs');
          var doIt = function () { put(S[x[0]]); if (cur.mode === 'split') paintPreview(); };
          if (x[0] === 'outline' && text().trim()) return G().sure('Put the whole outline in, beside what is written?', doIt, 'Put it in');
          doIt();
        };
        grid.appendChild(b);
      });
      parts.appendChild(grid);

      var from = sec('Start from', 'Takes the place of what is in the editor - nothing is kept until you press Save.');
      var replacing = function (go) { if (!text().trim()) return go(); G().sure('Replace what is in the editor?', go, 'Replace it'); };
      var fromRow = function (words, sub, fn) {
        var b = el('button', 'gd-as-from');
        b.type = 'button';
        b.appendChild(el('b', '', words));
        if (sub) b.appendChild(nn(el('small', '', sub)));
        b.onclick = function () {
          replacing(function () {
            busy(b, true);
            fn().then(function (md2) { if (md2 !== null && md2 !== undefined) { setText(md2); setDirty(true); toast(tr('taken in - Save keeps it'), 'good'); } })
              .catch(function (e) { toast(String((e && e.message) || e), 'bad'); }).then(function () { busy(b, false); });
          });
        };
        from.appendChild(b);
      };
      fromRow('acme\'s own text of this version', null, function () { return ask(cur.version, cur.lang, true).then(function (g) { return g.md; }); });
      fromRow('The other language', null, function () { return ask(cur.version, cur.lang === 'cs' ? 'en' : 'cs').then(function (g) { return g.md; }); });
      if (vers.length > 1) {
        var vrow = el('div', 'gd-as-vrow');
        var vsel = selectBox(vers.filter(function (v) { return v[0] !== cur.version; }), (vers.filter(function (v) { return v[0] !== cur.version; })[0] || [''])[0]);
        nn(vsel);
        var vgo = cmdButton('Take it', 'download', 'small');
        vgo.onclick = function () {
          replacing(function () {
            busy(vgo, true);
            ask(vsel.value, cur.lang).then(function (g) { setText(g.md || ''); setDirty(true); toast(tr('taken in - Save keeps it'), 'good'); })
              .catch(function (e) { toast(String((e && e.message) || e), 'bad'); }).then(function () { busy(vgo, false); });
          });
        };
        vrow.appendChild(el('span', 'gd-as-vl', 'Another version'));
        vrow.appendChild(vsel);
        vrow.appendChild(vgo);
        from.appendChild(vrow);
      }
      fromRow('An empty outline', null, function () { return Promise.resolve(snippets(p, cur.lang === 'cs').outline + '\n'); });

      var help = sec('Markdown in brief', 'In Visual nothing of it is needed - the buttons do it.');
      var cheat = el('table', 'gd-cheat');
      [['# Title', 'Title'], ['## Section', 'Section heading'], ['**bold**', 'Bold'], ['*italic*', 'Italic'], ['`code`', 'Code in the text'],
       ['- item', 'List'], ['1. step', 'Numbered steps'], ['> note', 'A note'], ['```sh … ```', 'Commands'], ['| a | b |', 'Table'], ['[words](https://…)', 'Link']].forEach(function (x) {
        var r = el('tr');
        var c1 = el('td'); c1.appendChild(nn(el('code', 'gd-code', x[0])));
        r.appendChild(c1);
        r.appendChild(el('td', '', x[1]));
        cheat.appendChild(r);
      });
      help.appendChild(cheat);
      help.appendChild(el('div', 'gd-as-sub', 'Shortcuts: Ctrl+B bold, Ctrl+I italic, Ctrl+K link, Ctrl+Alt+1/2/3 headings, Ctrl+S save.'));
      work.appendChild(assist);
      ed.appendChild(work);

      var foot = el('div', 'gd-edfoot');
      said = el('span', 'muted small gd-said', '');
      wc = el('span', 'muted small gd-wc', '');
      foot.appendChild(said);
      foot.appendChild(wc);
      ed.appendChild(foot);
      body.appendChild(ed);
      setTimeout(function () {
        resetB = $('modal-foot') && $('modal-foot').querySelector('.gd-resetbtn');
        if (!resetB) resetB = {disabled: true};
        load().then(function () { vis.focus(); });
      }, 0);
      document.removeEventListener('selectionchange', toolsState);
      document.addEventListener('selectionchange', toolsState);
      /* Close, its x, Escape: what is not kept is asked about first */
      if (typeof modalLeaveGuard === 'function') modalLeaveGuard(function (go) {
        if (!dirty) return false;
        G().sure('Leave the changes not kept?', go, 'Leave them');
        return true;
      });
    }, [
      {words: 'Back to the default', cls: 'gd-resetbtn', noDanger: true, noConfirm: true, icon: 'undo', go: function () {
        G().sure('Give the guide back to its default? What was written over for this version and language is taken away: acme\'s own text (or the module\'s, or one made from its fields) is shown again.',
          function () {
            post({family: family, kind: kind, version: cur.version, lang: cur.lang, md: ''}).then(function (d) {
              toast(tr(d.message || 'done'), 'good'); setDirty(false); load();
            }).catch(function (e) { toast(String((e && e.message) || e), 'bad'); });
          });
      }},
      {words: 'Close', close: true},
      {words: 'Show it', icon: 'eye', go: function () {
        leave(function () { G().show(p, family, cur.version, {lang: cur.lang}); });
      }},
      {words: 'Save', cls: 'primary gd-savebtn', icon: 'save', go: function (b) { keep(b); }}
    ], 'gd-full gd-edbox'); };
    if (opt.over && typeof modalOver === 'function') modalOver(openEd, opt.back); else openEd();
  }

  window.ACME_GUIDE_EDITOR = {edit: edit, toMd: toMd, fromHtml: fromHtml};
})();
