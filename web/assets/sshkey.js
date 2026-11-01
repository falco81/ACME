/* sshkey.js - the SSH key of a module (a field of the type `sshkey`), drawn as
   isemon draws the key it reaches a firewall with (isemon 1.10.276, Reaching
   the firewall): the card's facts - Right now, Signing in with, the key, when
   it was made -, "How to set it up on ...", and the key box with its row of
   buttons, Make a key · Use my own · Download it · Forget it, and Try reaching
   it on the right, the public half under it to copy. The same words, the same
   order, the same confirmations.

   certs.js draws the module's form and hands a field of this type here
   (window.ACME_FIELD_TYPES.sshkey). The daemon's side is
   acmelib/certs/api_sshkeys.py: the private half is made there, kept sealed
   there, and never sent here - what this shows is its public half and its
   fingerprint. In a form not saved yet the key is a draft the daemon keeps,
   and the field's value is its token: saved, it becomes the target's key. */
'use strict';
(function () {
  var SK_INFO = null, SK_ASK = null;
  function skCall(what, body, wait) {
    return api('sshkey-' + what, body, wait);
  }
  function skInfo() {
    if (SK_INFO) return Promise.resolve(SK_INFO);
    if (!SK_ASK) {
      SK_ASK = skCall('info').then(function (d) { SK_INFO = d || {}; return SK_INFO; })
        .catch(function () { SK_ASK = null; return {can_keygen: true, from: []}; });
    }
    return SK_ASK;
  }
  function skRole() { return (typeof ME === 'object' && ME && ME.role) || 'readonly'; }
  function skFull() { return skRole() === 'fulladmin'; }
  function skManage() { return skFull() || skRole() === 'certadmin' || skRole() === 'tokenadmin'; }

  /* One fact of the card, a name and its value - isemon's kvInto. */
  function skKv(host, k, v, d2, why) {
    var line = el('div', 'kv');
    var key = el('span', 'k', k);
    if (why) explain(key, why);
    line.appendChild(key);
    var value = el('span', 'v');
    if (v instanceof Node) value.appendChild(v); else value.textContent = v;
    if (d2 instanceof Node) { var dd = el('span', 'd'); dd.appendChild(d2); value.appendChild(dd); }
    else if (d2) value.appendChild(el('span', 'd', d2));
    line.appendChild(value);
    host.appendChild(line);
    return line;
  }
  function skSave(text, file, type) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type: type || 'application/octet-stream'}));
    a.download = file;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  /* isemon's guide: steps, each with its commands to copy. */
  function skGuideCode(code) {
    var wrap = el('div', 'guide-code');
    wrap.appendChild(noI18n(el('pre', 'wrap mono', code)));
    var b = cmdButton('Copy', 'copy', 'small');
    b.onclick = function () { copyText(code, b, 'on the clipboard'); };
    wrap.appendChild(b);
    return wrap;
  }
  function skGuideStep(body, n, title, html, code) {
    var box = el('div', 'guide-step');
    var head = el('div', 'guide-head');
    head.appendChild(el('span', 'guide-n', String(n)));
    head.appendChild(el('span', '', title));
    box.appendChild(head);
    if (html) {
      var p = el('div', 'guide-words');
      p.innerHTML = html;
      box.appendChild(p);
    }
    if (code) box.appendChild(skGuideCode(code));
    body.appendChild(box);
  }
  function skGuideNote(body, html, kind) {
    var p = el('div', 'guide-note' + (kind ? ' ' + kind : ''));
    p.innerHTML = html;
    body.appendChild(p);
  }
  /* The sentences that name the machine at the other end ({W}: "the server",
     "the router"...), each said whole - web/lang/cs.json has each of them whole,
     for each machine, in its own grammatical case. {0} is a name. */
  var SK_T = {
    lede: "A key is better than a password: the key never leaves this machine and {W} holds only its public half.",
    guide: "How to set it up on {W}\u2026",
    guideWhy: "How to set {W} up for this machine, step by step, with its commands: the account, its key let in from acme alone, its host key.",
    keynote: "Made here, and it never leaves this machine except when you download it. Put the <b>public</b> half on {W}.",
    keynoteWhy: "The key is made here and never leaves this machine except when you download it. Put the public half on {W} and it will let acme in without a password. Keep the private half safe: anybody holding it can sign in as that account.",
    mkWhy: "Make a fresh ed25519 pair here (or RSA 4096, for something old that needs RSA). The private half stays on this machine and the public half is shown below for you to put on {W}. Any key already stored is replaced, so until the new public half is there this will not be able to sign in.",
    forgetWhy: "Delete the private key from this machine. Unless {W} is set to take a password instead, nothing here will reach it until a new key is made and put on it.",
    testWhy: "Sign in to {W} and ask it who acme is there. Nothing is written and nothing is changed - it is the quickest way to find out whether the address, the account and the key are right.",
    authWhy: "A key is better: it never leaves this machine, {W} holds only its public half, and it cannot be read out of the settings by anybody who gets this far.",
    fpWhy: "Its fingerprint, as ssh-keygen -lf says it of the public half - the same as {W} shows for the key it lets in.",
    copyWhy: "Click to copy. This is the half that goes ON {W}; the private half stays here.",
    make: "A fresh pair is made here. The private half stays on this machine and the public half is shown for you to put on {W}.",
    made: "a new key was made \u2014 put the public half on {W}",
    download: "The private half leaves this machine as a file. Anybody holding it can sign in to {W} as <code>{0}</code>. That it was downloaded, and by whom, is written into Events.",
    forget: "The private key is deleted from this machine. Unless {W} is set to take a password instead, nothing here will reach it until a new key is made and put on it.",
    answered: "This signed in to {W}, asked it who acme is there, and came back. Nothing was written and nothing was changed.",
    failed: "What ssh said when reaching {W}, step by step:",
    causes: "The usual causes, in the order they usually are: the public half of the key is not on {W} yet; the account may not sign in over ssh; its host key is not trusted yet; the address or port is wrong; or it is not reachable from this machine at all.",
    onAsRoot: "On {W}, as root - or use an account you have:",
    hostkey: "What {W} proves itself with - compare it with the fingerprint <b>Try reaching it</b> shows the first time:",
    generic: "<b>Make a key</b> below and put its public half where {W} takes keys for <code>{0}</code> - on most, <code>~/.ssh/authorized_keys</code> of that account, let in from acme alone:"
  };
  function skT(k, w, a) {
    var t = SK_T[k].split('{W}').join(w);
    return a === undefined ? t : t.split('{0}').join(a);
  }
  function skMono(t) { return '<code>' + htmlText(t) + '</code>'; }

  /* What the thing at the other end is called, by the kind of guide. */
  var SK_WORDS = {linux: 'the server', windows: 'the Windows server', mikrotik: 'the router',
                  pfsense: 'the firewall', opnsense: 'the firewall', generic: 'the machine'};
  var SK_KIND_WORDS = {http_ssh: 'the web servers', ssh_dns: 'the DNS server'};

  /* The guides: how the public half is put on each kind of machine, with its
     commands - the account, the key let in from acme alone, its host key. */
  function skGuideLinux(body, g) {
    var home = g.user === 'root' ? '/root' : '~' + g.user;
    skGuideNote(body, 'acme signs in as ' + skMono(g.user) + ' with the key made here and nothing '
      + 'else. The key is let in only from acme\u2019s own addresses'
      + ', with <code>from=</code> in front of it: copied anywhere else, it opens '
      + 'nothing.');
    var n = 1;
    if (g.user !== 'root') {
      skGuideStep(body, n++, 'An account for acme',
        skT('onAsRoot', g.words),
        'useradd -m -s /bin/sh ' + g.user);
    }
    skGuideStep(body, n++, 'Its key',
      '<b>Make a key</b> below and put its public half into <code>' + htmlText(home)
      + '/.ssh/authorized_keys</code>, let in from acme alone:',
      'install -d -m 700 -o ' + g.user + ' -g ' + g.user + ' ' + home + '/.ssh\n'
      + 'echo \'' + g.line + '\' >> ' + home + '/.ssh/authorized_keys\n'
      + 'chown ' + g.user + ': ' + home + '/.ssh/authorized_keys && chmod 600 ' + home
      + '/.ssh/authorized_keys');
    if (g.user === 'root' && g.sudo !== undefined) {
      skGuideNote(body, 'Rather not let root in? Put an account of its own into <i>User</i> and '
        + 'switch <i>Use sudo</i> on: this then says the sudoers line it needs too.');
    }
    if (g.user !== 'root') {
      skGuideStep(body, n++, 'sudo, without a password',
        'Not root: switch <i>Use sudo</i> on here, and let the account run what acme does there '
        + 'without being asked for a password (or give it the sudo password here):',
        'echo \'' + g.user + ' ALL=(root) NOPASSWD: ALL\' > /etc/sudoers.d/acme\n'
        + 'chmod 440 /etc/sudoers.d/acme && visudo -cf /etc/sudoers.d/acme');
    }
    skGuideStep(body, n++, 'Its host key', skT('hostkey', g.words),
      'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
  }
  function skGuideWindows(body, g) {
    skGuideNote(body, 'acme signs in to the Windows OpenSSH server as ' + skMono(g.user)
      + ', an administrator, with the key made here. For an account in Administrators, Windows '
      + 'reads the key from <code>administrators_authorized_keys</code> and nowhere '
      + 'else - and only while SYSTEM and Administrators alone may read that file.');
    skGuideStep(body, 1, 'The OpenSSH server',
      'In PowerShell, as an administrator:',
      'Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\n'
      + 'Set-Service -Name sshd -StartupType Automatic\nStart-Service sshd');
    skGuideStep(body, 2, 'Its key',
      '<b>Make a key</b> below and put its public half into the administrators\u2019 file, let '
      + 'in from acme alone, and the file readable by nobody else:',
      'Add-Content -Path C:\\ProgramData\\ssh\\administrators_authorized_keys -Value \''
      + g.line + '\'\n'
      + 'icacls.exe C:\\ProgramData\\ssh\\administrators_authorized_keys /inheritance:r '
      + '/grant "Administrators:F" /grant "SYSTEM:F"');
    skGuideStep(body, 3, 'Its host key', skT('hostkey', g.words),
      'ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub');
  }
  function skGuideMikrotik(body, g) {
    skGuideNote(body, 'acme signs in to the router over ssh as ' + skMono(g.user) + ' to put the '
      + 'certificate files there and import them. RouterOS 6 takes RSA keys only: there, '
      + '<b>Make a key</b> as RSA 4096.');
    skGuideStep(body, 1, 'An account that may put certificates there',
      'On the Mikrotik, a group allowed ssh, ftp, read and write, and an account in it:',
      '/user group add name=acme policy=ssh,ftp,read,write,api,rest-api,sensitive,!local,'
      + '!telnet,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!romon\n'
      + '/user add name=' + g.user + ' group=acme address=' + (g.fromList[0] || '0.0.0.0/0')
      + ' password=SOMETHING-LONG');
    skGuideStep(body, 2, 'Its key',
      '<b>Make a key</b> below, copy its public half into a file ' + skMono(g.file)
      + ' on the Mikrotik (<i>Files</i>, or scp) and import it for that account:',
      '/user ssh-keys import public-key-file=' + g.file + ' user=' + g.user);
    skGuideStep(body, 3, 'Its host key', skT('hostkey', g.words), '/ip ssh print');
  }
  function skGuidePf(body, g, opn) {
    skGuideNote(body, 'acme signs in over ssh as ' + skMono(g.user) + ' with the key made here.');
    skGuideStep(body, 1, 'Switch ssh on',
      opn ? '<b>System \u2192 Settings \u2192 Administration \u2192 Secure Shell</b>: enabled, '
            + 'and <i>Permit root user login</i> if the account is root.'
          : '<b>System \u2192 Advanced \u2192 Admin Access \u2192 Secure Shell</b>: enabled, '
            + 'with <i>Public Key Only</i>.');
    skGuideStep(body, 2, 'The account and its key',
      '<b>Make a key</b> below and put its public half into <b>Authorized keys</b> of the '
      + 'account <code>' + htmlText(g.user) + '</code> ('
      + (opn ? '<b>System \u2192 Access \u2192 Users</b>' : '<b>System \u2192 User Manager</b>')
      + '):', g.line);
    skGuideStep(body, 3, 'Its host key', skT('hostkey', g.words),
      'ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub');
  }
  function skGuideGeneric(body, g) {
    skGuideStep(body, 1, 'Its key', skT('generic', g.words, htmlText(g.user)), g.line);
  }
  var SK_GUIDES = {linux: skGuideLinux, windows: skGuideWindows, mikrotik: skGuideMikrotik,
                   pfsense: function (b, g) { skGuidePf(b, g, false); },
                   opnsense: function (b, g) { skGuidePf(b, g, true); },
                   generic: skGuideGeneric};
  function skFill(text, g) {
    return String(text || '').replace(/\{(pub|user|from|host|file|line)\}/g, function (all, k) {
      return g[k === 'pub' ? 'pubText' : k];
    });
  }
  function skGuide(c) {
    var how = c.howto();
    var g = c.guideFacts();
    var title = (typeof how === 'object' && how && how.title) || ('Setting it up: '
      + (c.plug.title || c.plug.kind || 'SSH'));
    modalOver(function () {
      modal(title, function (body) {
        body.classList.add('guide');
        body.classList.add('sshk-guide');
        if (how && typeof how === 'object') {
          if (how.note) skGuideNote(body, skFill(how.note, g));
          (how.steps || []).forEach(function (s, i) {
            skGuideStep(body, i + 1, skFill(s.title, g), skFill(s.html, g), s.code ? skFill(s.code, g) : '');
          });
        } else {
          (SK_GUIDES[how] || skGuideGeneric)(body, g);
        }
        if (!c.state.public) {
          skGuideNote(body, 'There is no key yet: the commands above say <code>'
            + 'ssh-ed25519 AAAA\u2026</code> where its public half goes. <b>Make a key</b> first and '
            + 'open this again - they are then the very commands to copy.', 'warn');
        }
        skGuideNote(body, 'Then, here: fill the settings in, <b>Save</b>, and <b>Try reaching it</b>.', '');
      }, [{words: 'Close', close: true}], 'medium');
    });
  }

  /* ---- the card ------------------------------------------------------------ */
  function sshkeyField(f, v, ctx) {
    ctx = ctx || {};
    var opts = ctx.opts || {};
    var values = ctx.values || {};
    var secrets = ctx.secrets || {};
    var row = opts.row || null;
    var plug = opts.plug || {};
    var family = opts.family || 'target';
    var meta = values[f.key + '.sshkey'];
    meta = meta && typeof meta === 'object' ? meta : {};
    var c = {f: f, plug: plug, family: family, row: row,
             state: {has: !!secrets[f.key], public: meta.public || '', fp: meta.fp || '',
                     type: meta.type || '', bits: meta.bits || 0, made: meta.made || null,
                     by: meta.by || '', how: meta.how || (secrets[f.key] ? 'pasted' : ''),
                     draft: ''}};
    var cur = function () {
      try { return (ctx.current && ctx.current()) || {}; } catch (e) { return {}; }
    };
    var nameNow = function () {
      return (row && row.name) || plug.title || plug.kind || 'it';
    };
    c.howto = function () { return f.howto || plug.sshkey_howto || 'generic'; };
    var words = (typeof c.howto() === 'string' && SK_WORDS[c.howto()]) || 'the machine';
    if (SK_KIND_WORDS[plug.kind]) words = SK_KIND_WORDS[plug.kind];
    var prefix = String(f.ssh_prefix || '');
    var userOf = function () {
      var x = cur();
      return String(x[f.user_key || prefix + 'user'] || x.user || 'root');
    };
    c.guideFacts = function () {
      var x = cur();
      var from = ((SK_INFO && SK_INFO.from) || []).filter(Boolean);
      var pub = c.state.public || 'ssh-ed25519 AAAA\u2026 acme';
      var file = 'acme-' + String(nameNow()).replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 60) + '.pub';
      return {user: userOf(), words: words, from: from.join(','), fromList: from, sudo: x.sudo,
              host: String(x.host || x.hosts || 'HOST'), file: file, pubText: pub,
              line: (from.length ? 'from="' + from.join(',') + '" ' : '') + pub};
    };
    var authNow = function () {
      if (!f.auth_key) return '';
      var a = cur()[f.auth_key];
      return a === undefined || a === null ? '' : String(a);
    };

    var card = el('div', 'card full sshk');
    var h2 = el('h2');
    h2.appendChild(el('span', '', String(f.label || 'The SSH key')));
    var when = el('span', 'right');
    h2.appendChild(when);
    card.appendChild(h2);
    var lede = el('p', 'note', skT('lede', words));
    card.appendChild(lede);
    var facts = el('div', 'sshk-facts');
    card.appendChild(facts);
    var gRow = el('div', 'btnrow');
    gRow.style.marginTop = '12px';
    var guide = cmdButton(skT('guide', words), 'info');
    explain(guide, skT('guideWhy', words));
    guide.onclick = function () { skInfo().then(function () { skGuide(c); }); };
    gRow.appendChild(guide);
    card.appendChild(gRow);

    var keybox = el('div', 'subpanel');
    keybox.style.marginTop = '16px';
    var keynote = el('p', 'note');
    keynote.innerHTML = skT('keynote', words);
    explain(keynote, skT('keynoteWhy', words));
    keybox.appendChild(keynote);
    var missing = el('p', 'note', 'ssh-keygen is not on this machine, so a key cannot be made or '
      + 'read here: dnf install openssh-clients. A password still works.');
    missing.style.color = 'var(--warn)';
    missing.hidden = true;
    keybox.appendChild(missing);
    var bar = el('div', 'btnrow');
    var mk = cmdButton('Make a key', 'key', 'admin-only');
    var own = cmdButton('Use my own', 'upload', 'admin-only');
    var down = cmdButton('Download it', 'download', 'admin-only');
    var forget = cmdButton('Forget it', 'forget', 'danger admin-only');
    var test = cmdButton('Try reaching it', 'pulse', 'primary');
    explain(mk, skT('mkWhy', words));
    explain(own, 'Use a private key you already have. Paste it whole, including its BEGIN and END '
      + 'lines, or read it from a file; its public half is worked out here so you do not have to '
      + 'hand that over as well. A passphrase it is locked with is asked for and checked.');
    explain(down, 'Download the private half as a file, for keeping somewhere safe or for using '
      + 'the same key elsewhere. It is written into Events that it was downloaded, and by whom.');
    explain(forget, skT('forgetWhy', words));
    explain(test, skT('testWhy', words));
    mk.dataset.sk = 'make'; own.dataset.sk = 'own'; down.dataset.sk = 'download';
    forget.dataset.sk = 'forget'; test.dataset.sk = 'try'; guide.dataset.sk = 'guide';
    [mk, own, down, forget].forEach(function (b) { bar.appendChild(b); });
    bar.appendChild(el('span', 'spacer'));
    bar.appendChild(test);
    keybox.appendChild(bar);
    var keyHost = el('div', 'sshk-key');
    keyHost.style.marginTop = '12px';
    keybox.appendChild(keyHost);
    card.appendChild(keybox);

    var ref = function () {
      var b = {family: family, kind: plug.kind, field: f.key, name: nameNow()};
      if (row && row.id) b.id = row.id;
      if (c.state.draft) b.draft = c.state.draft;
      return b;
    };
    var took = function (d) {
      d = d || {};
      c.state = {has: !!d.has, public: d.public || '', fp: d.fp || '', type: d.type || '',
                 bits: d.bits || 0, made: d.made || null, by: d.by || '', how: d.how || '',
                 locked: !!d.locked, draft: d.draft ? String(d.draft) : ''};
      paint();
      /* The form hears of it: what depends on the fields is drawn again. */
      try { card.dispatchEvent(new Event('change', {bubbles: true})); } catch (e) { }
    };

    var drawFacts = function () {
      clear(facts);
      var st = c.state;
      var tag = el('span');
      var on = !row || row.enabled === undefined || row.enabled === true || row.enabled === 1 || row.enabled === '1';
      var x = cur();
      var host = x.host || x.hosts;
      if (Array.isArray(host)) host = host.join(' ');
      var d2 = '';
      if (!on) tag.appendChild(el('span', 'tag dim', 'switched off'));
      else if (!host) tag.appendChild(el('span', 'tag dim', 'not set up'));
      else if (row && row.last_error) { tag.appendChild(el('span', 'tag crit', 'trouble')); d2 = String(row.last_error).slice(0, 300); }
      else if (row && row.last_ok) { tag.appendChild(el('span', 'tag ok', 'set up')); d2 = ago(row.last_ok); }
      else tag.appendChild(el('span', 'tag dim', row ? 'not tried yet' : 'not saved yet'));
      skKv(facts, 'Right now', tag, d2,
        'Switched off means nothing is ever done there, while everything about how to reach it '
        + 'stays where it is. Not set up means there is no address yet. Set up means the last '
        + 'time this tried to reach it, it got in. Trouble means the last time this tried to '
        + 'reach it, it could not - the words beside it are whatever ssh said.');
      var auth = authNow();
      var how = auth === 'password' ? 'a password'
        : (st.has ? 'a key this machine holds' : (f.auth_key ? 'a key \u2014 but there is none yet' : 'a password'));
      skKv(facts, 'Signing in with', how, '', skT('authWhy', words));
      if (st.has) {
        var kind = st.type ? (st.type === 'ED25519' ? 'Ed25519' : st.type + (st.bits ? ' ' + st.bits : '')) : 'a key';
        var fp = noI18n(el('span', 'mono', st.fp || '\u2013'));
        var kv = skKv(facts, 'The key', fp, kind, skT('fpWhy', words));
        kv.querySelector('.v').classList.add('sshk-fp');
        var made = st.how === 'made' ? 'made here' : (st.how === 'own' ? 'your own, given here' : 'your own key, pasted before');
        var line = null;
        if (st.made) {
          line = el('span');
          line.appendChild(el('span', '', made));
          if (st.by) {
            line.appendChild(document.createTextNode(' \u00b7 '));
            line.appendChild(el('span', '', 'by'));
            line.appendChild(document.createTextNode(' '));
            line.appendChild(noI18n(el('span', '', st.by)));
          }
          line.appendChild(document.createTextNode(' \u00b7 '));
          line.appendChild(el('span', '', ago(st.made)));
        }
        skKv(facts, st.how === 'made' ? 'Made' : 'Given', st.made ? stamp(st.made) : made, line);
        clear(when);
        if (st.made) {
          when.appendChild(el('span', '', st.how === 'made' ? 'made' : 'given'));
          when.appendChild(document.createTextNode(' '));
          when.appendChild(el('span', '', ago(st.made)));
        }
      } else {
        clear(when);
      }
      if (st.draft) {
        facts.appendChild(el('p', 'note sshk-draft', family === 'target'
          ? 'Not saved yet: the key is kept for this form, and becomes the target\u2019s when it is saved.'
          : 'Not saved yet: the key is kept for this form, and becomes the validation\u2019s when it is saved.'));
      }
    };
    var paint = function () {
      var info = SK_INFO || {can_keygen: true};
      var st = c.state;
      var full = skFull();
      var canKey = info.can_keygen !== false;
      missing.hidden = canKey;
      mk.disabled = !full || !canKey;
      own.disabled = !full || !canKey;
      down.disabled = !full || !st.has;
      forget.disabled = !full || !st.has;
      test.disabled = !skManage();
      drawFacts();
      clear(keyHost);
      if (!st.has || !st.public) {
        keyHost.appendChild(el('p', 'btnhelp', st.has
          ? 'A key is kept, and its public half cannot be worked out here.'
          : 'No key yet \u2014 make one, or let it sign in with a password.'));
        return;
      }
      keyHost.appendChild(el('p', 'btnhelp', 'The public half. Click it to copy.'));
      var code = noI18n(el('code', 'copyme', st.public));
      explain(code, skT('copyWhy', words));
      code.onclick = function () { copyText(st.public, code, 'the public key is on the clipboard'); };
      keyHost.appendChild(code);
    };

    mk.onclick = function () {
      var kind = f.key_type || 'ed25519';
      var replace = c.state.has;
      modalOver(function () {
        modal('Make a key for ' + nameNow(), function (body) {
          var p = el('p', 'note');
          p.innerHTML = skT('make', words);
          if (replace) {
            var p2 = el('p', 'note');
            p2.innerHTML = '<b>Any key already stored for it is replaced</b>, so until the new '
              + 'public half is on it this will not be able to sign in.';
            body.appendChild(p);
            p = p2;
          }
          body.appendChild(p);
          var sg = el('div', 'seg');
          [['ed25519', 'Ed25519 (the strongest, and short)'], ['rsa4096', 'RSA 4096 (where something old needs RSA)']].forEach(function (o) {
            var b = el('button', o[0] === kind ? 'on' : '', o[1]);
            b.type = 'button';
            b.onclick = function () {
              kind = o[0];
              Array.prototype.forEach.call(sg.children, function (x) { x.classList.remove('on'); });
              b.classList.add('on');
            };
            sg.appendChild(b);
          });
          var ff = formField('The kind', sg);
          ff.style.marginTop = '12px';
          body.appendChild(ff);
        }, [{words: 'No, leave it', close: true},
            {words: 'Make one', cls: replace ? 'danger' : 'primary', icon: 'key', go: function (b) {
              busy(b, true);
              var q = ref();
              q.key_type = kind;
              skCall('make', q, 150).then(function (d) {
                closeModal();
                toast(skT('made', words), 'good');
                took(d);
              }).catch(function (e) { busy(b, false); oops(e); });
            }}], true);
      });
    };

    own.onclick = function () {
      var area, pp;
      modalOver(function () {
        modal('Use my own key for ' + nameNow(), function (body) {
          var p = el('p', 'note');
          p.innerHTML = 'An OpenSSH private key, whole, including its <code>BEGIN</code> '
            + 'and <code>END</code> lines. It is kept in this machine\u2019s database, '
            + 'sealed, and never shown back. Its public half is worked out here, so you do not have '
            + 'to hand that over as well.';
          body.appendChild(p);
          area = noI18n(el('textarea', 'mono'));
          area.rows = 11;
          area.spellcheck = false;
          area.placeholder = '-----BEGIN OPENSSH PRIVATE KEY-----';
          body.appendChild(area);
          var fr = el('div', 'btnrow');
          fr.style.margin = '8px 0 4px';
          var pick = cmdButton('Read it from a file\u2026', 'upload', 'small');
          var input = el('input');
          input.type = 'file';
          input.hidden = true;
          pick.onclick = function () { input.click(); };
          input.onchange = function () {
            var file = input.files && input.files[0];
            input.value = '';
            if (!file) return;
            if (file.size > 65536) { toast('that file is far bigger than a key', 'warn'); return; }
            var r = new FileReader();
            r.onload = function () { area.value = String(r.result || '').trim(); };
            r.onerror = function () { toast('the file could not be read', 'bad'); };
            r.readAsText(file);
          };
          fr.appendChild(pick);
          fr.appendChild(input);
          body.appendChild(fr);
          pp = maskBox('', '', 'mono');
          noI18n(pp);
          var ppf = formField('Its passphrase, if it has one', pp,
            'Asked for here and checked at once: a key it does not open is refused. It is kept '
            + 'sealed beside the key, for ssh.');
          body.appendChild(ppf);
          setTimeout(function () { area.focus(); }, 60);
        }, [{words: 'Cancel', close: true},
            {words: 'Keep this key', cls: 'primary', icon: 'save', go: function (b) {
              busy(b, true);
              var q = ref();
              q.pem = area.value;
              q.passphrase = pp.value;
              skCall('use_own', q, 60).then(function (d) {
                closeModal();
                toast('the key was stored', 'good');
                took(d);
              }).catch(function (e) { busy(b, false); oops(e); });
            }}], 'medium');
      });
    };

    down.onclick = function () {
      modalOver(function () {
        confirmThen('Download the private key for ' + nameNow(),
          skT('download', words, htmlText(userOf() || 'that account')),
          'Download it', function () {
            var q = ref();
            q.half = 'private';
            skCall('download', q).then(function (d) {
              skSave(d.text, d.file, d.type);
            }).catch(oops);
          }, false);
      });
    };

    forget.onclick = function () {
      modalOver(function () {
        confirmThen('Forget the key for ' + nameNow(),
          skT('forget', words),
          'Forget it', function () {
            skCall('forget', ref()).then(function () {
              toast('the key is gone');
              took(null);
            }).catch(oops);
          });
      });
    };

    var stepLines = function (steps) {
      var box = el('div', 'joblines said sshk-steps');
      (steps || []).forEach(function (s) {
        var line = el('div', 'sshk-step ' + (s[1] || 'info'));
        var t = new Date((s[0] || 0) * 1000);
        line.appendChild(el('b', '', pad2(t.getHours()) + ':' + pad2(t.getMinutes()) + ':' + pad2(t.getSeconds())));
        line.appendChild(noI18n(el('span', '', String(s[2] || ''))));
        box.appendChild(line);
      });
      if (!box.children.length) box.appendChild(el('div', '', '(it said nothing)'));
      return box;
    };
    /* ---- the host keys it saw, into the form's "Host keys" -----------------
       Try reaching it says the host key(s) each machine shows (d.hostkeys,
       acmelib/certs/api_sshkeys.hostkey_report): a machine with none pinned
       gets its line (ed25519 first) added to the field at once; one whose
       pinned key is another is warned of, and replaced only when the person
       says so. Only the form changes: its Save keeps it, as any field. */
    var hkBox = function (key) {
      var item = key && ctx.form ? ctx.form.querySelector('[data-fkey="' + key + '"]') : null;
      var box = item ? item.querySelector('textarea, input') : null;
      return box ? {item: item, box: box} : null;
    };
    var hkLines = function (box) {
      return String(box.value || '').split(/\n/).map(function (x) { return x.trim(); }).filter(Boolean);
    };
    var hkBlob = function (line) {
      var p = String(line || '').trim().split(/\s+/);
      if (p[0] && p[0].charAt(0) === '@') p.shift();
      return /^(ssh-|ecdsa-|sk-)/.test(p[0] || '') ? (p[1] || '') : (p[2] || '');
    };
    var hkPut = function (hb, lines) {
      hb.box.value = lines.join('\n');
      /* in "More", closed: opened, so what changed is seen */
      var more = hb.item.closest('details');
      if (more && !more.open) more.open = true;
      hb.item.classList.add('sshk-hk-changed');
      hb.box.dispatchEvent(new Event('input', {bubbles: true}));
      hb.box.dispatchEvent(new Event('change', {bubbles: true}));
    };
    var hkFill = function (d) {
      var hb = hkBox(d.hostkey_field);
      var added = [];
      if (!hb) return {hb: null, added: added};
      var lines = hkLines(hb.box);
      (d.hostkeys || []).forEach(function (h) {
        if (h.status !== 'new' || !h.line) return;
        var blob = hkBlob(h.line);
        if (lines.some(function (x) { return hkBlob(x) === blob; })) return;
        lines.push(h.line);
        added.push(h);
      });
      if (added.length) hkPut(hb, lines);
      return {hb: hb, added: added};
    };
    var hkReplace = function (hb, h) {
      var pinned = (h.pinned || []).map(function (x) { return String(x).trim(); });
      var lines = hkLines(hb.box).filter(function (x) { return pinned.indexOf(x) < 0; });
      var blob = hkBlob(h.line);
      if (!lines.some(function (x) { return hkBlob(x) === blob; })) lines.push(h.line);
      hkPut(hb, lines);
    };
    var hkFpLine = function (where, fp) {
      var line = el('div', 'sshk-hk-fp');
      if (where) line.appendChild(noI18n(el('b', '', where)));
      line.appendChild(noI18n(el('span', 'mono', fp)));
      return line;
    };
    var hkReport = function (body, d, got) {
      var hk = d.hostkeys || [];
      if (!hk.length) return;
      var box = el('div', 'sshk-hk');
      box.dataset.sk = 'hostkeys';
      box.appendChild(el('h4', '', 'Host keys'));
      if (got.added.length) {
        var a = el('div', 'note good sshk-hk-added');
        a.appendChild(el('p', '', 'Added to the form\u2019s host keys \u2014 Save to keep them:'));
        got.added.forEach(function (h) { a.appendChild(hkFpLine(h.where, h.fp)); });
        box.appendChild(a);
      }
      var same = hk.filter(function (h) { return h.status === 'same'; });
      if (same.length) {
        var sm = el('div', 'note sshk-hk-same');
        sm.appendChild(el('p', '', 'Already pinned, and the same as shown:'));
        same.forEach(function (h) { sm.appendChild(hkFpLine(h.where, h.fp)); });
        box.appendChild(sm);
      }
      if (!got.hb) {
        var nf = hk.filter(function (h) { return h.status === 'new'; });
        if (nf.length) {
          var n = el('div', 'note sshk-hk-seen');
          n.appendChild(el('p', '', 'It shows:'));
          nf.forEach(function (h) { n.appendChild(hkFpLine(h.where, h.fp)); });
          box.appendChild(n);
        }
      }
      hk.filter(function (h) { return h.status === 'other'; }).forEach(function (h) {
        var w = el('div', 'note warn sshk-hk-other');
        w.dataset.where = h.where;
        w.appendChild(noI18n(el('b', '', h.where)));
        w.appendChild(el('p', '', 'It shows another host key than the one pinned. Somebody may be '
          + 'in between (a man-in-the-middle) - or the machine was reinstalled and has a new one. '
          + 'Compare it with the machine\u2019s own (ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub '
          + 'on it) before you replace it.'));
        var k1 = el('div', 'sshk-hk-pair');
        k1.appendChild(el('span', 'k', 'Pinned'));
        (h.pinned_fps && h.pinned_fps.length ? h.pinned_fps : h.pinned || []).forEach(function (fp) {
          k1.appendChild(hkFpLine('', fp));
        });
        w.appendChild(k1);
        var k2 = el('div', 'sshk-hk-pair');
        k2.appendChild(el('span', 'k', 'Shown now'));
        k2.appendChild(hkFpLine('', h.fp));
        w.appendChild(k2);
        if (got.hb && skFull()) {
          var rb = cmdButton('Replace with the key seen', 'refresh', 'small danger');
          rb.dataset.sk = 'hk-replace';
          var done = el('p', 'btnhelp', '');
          rb.onclick = function () {
            hkReplace(got.hb, h);
            rb.disabled = true;
            done.textContent = 'Replaced in the form \u2014 Save to keep it.';
            toast('the host key was replaced in the form - Save to keep it', 'good');
          };
          var r = el('div', 'btnrow');
          r.appendChild(rb);
          w.appendChild(r);
          w.appendChild(done);
        }
        box.appendChild(w);
      });
      body.appendChild(box);
    };
    test.onclick = function () {
      if (test.disabled) return;
      busy(test, true);
      var q = ref();
      q.config = cur();
      skCall('try', q, 150).then(function (d) {
        if (row) {
          if (d.reached) { row.last_ok = Date.now() / 1000; row.last_error = ''; }
          else row.last_error = d.said || 'it did not answer';
        }
        var got = skFull() ? hkFill(d) : {hb: null, added: []};
        if (got.added.length) toast('host keys added to the form - Save to keep them', 'good');
        if (d.reached) {
          modalOver(function () {
            modal('It answered', function (body) {
              body.appendChild(el('p', 'note', skT('answered', words)));
              hkReport(body, d, got);
              body.appendChild(stepLines(d.steps));
            }, [{words: 'Good', cls: 'primary', close: true}], true);
          });
        } else {
          modalOver(function () {
            modal('It did not answer', function (body) {
              body.appendChild(el('p', 'note', skT('failed', words)));
              hkReport(body, d, got);
              body.appendChild(stepLines(d.steps));
              body.appendChild(el('p', 'note', skT('causes', words)));
            }, [{words: 'Close', close: true}], true);
          });
        }
        drawFacts();
      }).catch(oops).then(function () { busy(test, false); });
    };

    /* A key kept before this card: its public half asked for once. */
    if (c.state.has && !c.state.public && row && row.id) {
      skCall('show', ref()).then(function (d) { if (d && d.has) took(d); }).catch(function () { });
    }
    skInfo().then(paint);
    paint();
    if (ctx.form) {
      ctx.form.addEventListener('change', function (e) { if (e.target !== card) drawFacts(); });
      ctx.form.addEventListener('input', debounce(drawFacts, 250));
    }
    explainWhatWasDrawn(card);
    return {input: card, item: card, wide: true,
            get: function () { return c.state.draft || ''; }};
  }

  window.ACME_FIELD_TYPES = window.ACME_FIELD_TYPES || {};
  window.ACME_FIELD_TYPES.sshkey = sshkeyField;
})();
