/* deployfiles.js - a deployment's files and the script after them, for the
   targets that write the certificate as files (ssh, windows_ssh, local: their
   module says `files_ui`).

   certs.js draws a deployment's form from the module's deploy_fields; for
   such a target it hands the form here (window.ACME_DEPLOY_UI.form) and gets
   the same {node, read, check, set} back. Drawn here:

     Files        quick layouts (one click fills the rows), a service's preset,
                  a row per file (format in words, path with its placeholders,
                  mode, owner), the password of PKCS#12 / keystore files (none,
                  set here, made by acme) - stored as the module's own `outputs`
                  lines ("format path [mode] [owner]"), so the command line and
                  older pages read the same thing.
     After them   nothing / a command already on the machine / a script written
                  here (a code box), the variables it gets beside it, ready
                  examples; the commands around it folded below.
     Beside them  what it will really be: each file with its path filled in,
                  its size and mode, what is wrong; the ACME_* variables with
                  their values - asked of the daemon (POST /api/deploys/preview)
                  as it is typed, worked out by the module itself.
     The test     POST /api/deploys/dry_run: the files into a temporary folder
                  on the target, the script run there with ACME_DRY_RUN=1.

   Everything else of the module's form is drawn by certs.js's fieldForm. */
'use strict';
(function () {
  var CT = window.ACME_CERTS = window.ACME_CERTS || {};
  var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
  var FULL = ROLE === 'fulladmin';
  var MANAGE = FULL || ROLE === 'certadmin' || ROLE === 'tokenadmin';
  var PFX = ['pfx', 'p12', 'p12-legacy', 'jks'];
  var KEYS = ['key-pem', 'key-rsa', 'key-der', 'combined-pem', 'pfx', 'p12', 'p12-legacy', 'jks'];
  var OWNED = ['preset', 'outputs', 'pfx_password_mode', 'pfx_password', 'jks_alias',
               'script_mode', 'script_path', 'script_args', 'script_interp', 'script_body'];
  var AROUND = ['pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd', 'command', 'post_ps'];
  /* Offered; any other mode of three or four octal digits is typed (1.0.65: 0700, 0750,
     0755... were not to be had). */
  var MODES = ['0600', '0640', '0644', '0400', '0440', '0444', '0700', '0750', '0755', '0660', '0664'];
  /* chmod as a popup of tick boxes (1.0.65), as mc's Chmod command: the special bits, then
     read / write / run for the owner, the group and the others; the octal number typed or
     worked out from the boxes, both ways. done(mode) - '' for the default. */
  var CHMOD_BITS = [
    [0o4000, 'set user ID on execution'], [0o2000, 'set group ID on execution'], [0o1000, 'sticky bit (restricted deletion)'],
    [0o400, 'read by owner'], [0o200, 'write by owner'], [0o100, 'execute/search by owner'],
    [0o40, 'read by group'], [0o20, 'write by group'], [0o10, 'execute/search by group'],
    [0o4, 'read by others'], [0o2, 'write by others'], [0o1, 'execute/search by others']];
  function chmodPopup(value, deflt, name, done) {
    var start = /^[0-7]{3,4}$/.test(String(value || '')) ? parseInt(value, 8) : parseInt(deflt, 8);
    var useDefault = !value;
    modalOver(function () {
      modal(tr('The mode of') + ' ' + (name || tr('the file')), function (body) {
        var grid = el('div', 'df-chmod');
        var boxes = [];
        var octal = textBox('', '0644', 'mono df-chmod-oct');
        octal.maxLength = 4;
        noI18n(octal);
        var dflt = el('label', 'df-chmod-dflt');
        var dcb = el('input');
        dcb.type = 'checkbox';
        dcb.checked = useDefault;
        dflt.appendChild(dcb);
        dflt.appendChild(el('span', '', tr('the default') + ' (' + deflt + ')'));
        var fromBits = function () {
          var v = 0;
          boxes.forEach(function (b) { if (b.cb.checked) v |= b.bit; });
          return v;
        };
        var paint = function (v) {
          boxes.forEach(function (b) { b.cb.checked = !!(v & b.bit); b.cb.disabled = dcb.checked; });
          octal.value = ('000' + v.toString(8)).slice(-4);
          octal.disabled = dcb.checked;
          octal.classList.remove('df-bad');
        };
        var groups = [['Special', 0, 3], ['Owner', 3, 6], ['Group', 6, 9], ['Others', 9, 12]];
        groups.forEach(function (g) {
          var col = el('fieldset', 'df-chmod-g');
          col.appendChild(el('legend', '', g[0]));
          CHMOD_BITS.slice(g[1], g[2]).forEach(function (bt) {
            var lab = el('label', 'df-chmod-row');
            var cb = el('input');
            cb.type = 'checkbox';
            cb.onchange = function () { paint(fromBits()); };
            lab.appendChild(cb);
            lab.appendChild(el('span', '', bt[1]));
            col.appendChild(lab);
            boxes.push({bit: bt[0], cb: cb});
          });
          grid.appendChild(col);
        });
        octal.oninput = function () {
          var t = octal.value.trim();
          if (/^[0-7]{3,4}$/.test(t)) {
            var v = parseInt(t, 8);
            boxes.forEach(function (b) { b.cb.checked = !!(v & b.bit); });
            octal.classList.remove('df-bad');
          } else {
            octal.classList.add('df-bad');
          }
        };
        dcb.onchange = function () { paint(dcb.checked ? parseInt(deflt, 8) : fromBits()); };
        /* Enter sets it, as the button does (1.0.79) */
        octal.onkeydown = function (e) {
          if (e.key !== 'Enter') return;
          e.preventDefault();
          /* this window's own foot - it may sit over another dialog */
          var up = octal.parentNode;
          while (up && !(up.querySelector && up.querySelector('.foot .primary'))) up = up.parentNode;
          var b = up && up.querySelector('.foot .primary');
          if (b) b.click();
        };
        body.appendChild(dflt);
        body.appendChild(grid);
        var row = el('div', 'df-chmod-octrow');
        row.appendChild(el('span', '', tr('Permissions (octal)')));
        row.appendChild(octal);
        body.appendChild(row);
        body._get = function () {
          if (dcb.checked) return '';
          var t = octal.value.trim();
          return /^[0-7]{3,4}$/.test(t) ? ('0' + t).slice(-4) : null;
        };
        paint(start);
        CHMOD_LAST = body;
      }, [{words: 'Close', close: true}, {words: 'Set', cls: 'primary', icon: 'check', go: function () {
        var v = CHMOD_LAST && CHMOD_LAST._get();
        if (v === null) { toast(tr('the mode is three or four octal digits, as 0644 or 0755'), 'bad'); return; }
        closeModal();
        done(v);
      }}], true);
    });
  }
  var CHMOD_LAST = null;
  /* Templates of the commands after the files (1.0.72): an application, then how it takes the
     new certificate - reloaded (no connection dropped), restarted, or stopped hard (every
     process of it ended, those left killed, then started) - each with the test of its
     configuration first. Fill test_cmd, reload_cmd and post_cmd; the person edits them after. */
  function hardCmd(unit, proc, test) {
    return (test ? test + ' && ' : '') + '{ systemctl stop ' + unit + '; pkill -TERM -x ' + proc +
      '; i=0; while pgrep -x ' + proc + ' >/dev/null && [ $i -lt 20 ]; do sleep 1; i=$((i+1)); done; pkill -KILL -x ' +
      proc + '; sleep 1; systemctl start ' + unit + ' && systemctl is-active --quiet ' + unit + '; }';
  }
  /* [key, title, group, unit, process (for the hard stop), test, reload (none: restart only), note] */
  var SVC_APPS = [
    ['nginx', 'nginx', 'Web servers', 'nginx', 'nginx', 'nginx -t', 'systemctl reload nginx'],
    ['httpd', 'Apache httpd (RHEL, Rocky, Alma, Fedora)', 'Web servers', 'httpd', 'httpd', 'apachectl configtest', 'systemctl reload httpd'],
    ['apache2', 'Apache 2 (Debian, Ubuntu)', 'Web servers', 'apache2', 'apache2', 'apache2ctl configtest', 'systemctl reload apache2'],
    ['lighttpd', 'lighttpd', 'Web servers', 'lighttpd', 'lighttpd', 'lighttpd -tt -f /etc/lighttpd/lighttpd.conf', ''],
    ['caddy', 'Caddy', 'Web servers', 'caddy', 'caddy', 'caddy validate --config /etc/caddy/Caddyfile', 'systemctl reload caddy'],
    ['haproxy', 'HAProxy', 'Proxies and load balancers', 'haproxy', 'haproxy', 'haproxy -c -q -f /etc/haproxy/haproxy.cfg', 'systemctl reload haproxy'],
    ['traefik', 'Traefik', 'Proxies and load balancers', 'traefik', 'traefik', '', '', 'A certificate in a file provider\'s directory is taken by itself - restart only when it is not.'],
    ['squid', 'Squid', 'Proxies and load balancers', 'squid', 'squid', 'squid -k parse', 'squid -k reconfigure'],
    ['hitch', 'Hitch', 'Proxies and load balancers', 'hitch', 'hitch', 'hitch --test --config=/etc/hitch/hitch.conf', 'systemctl reload hitch'],
    ['postfix', 'Postfix', 'Mail', 'postfix', '', 'postfix check', 'postfix reload'],
    ['dovecot', 'Dovecot', 'Mail', 'dovecot', 'dovecot', 'doveconf -n >/dev/null', 'systemctl reload dovecot'],
    ['exim4', 'Exim (Debian, exim4)', 'Mail', 'exim4', 'exim4', 'exim4 -bV >/dev/null', ''],
    ['exim', 'Exim (RHEL, exim)', 'Mail', 'exim', 'exim', 'exim -bV >/dev/null', ''],
    ['slapd', 'OpenLDAP (slapd)', 'Directories', 'slapd', 'slapd', 'slaptest -u', ''],
    ['postgresql', 'PostgreSQL', 'Databases', 'postgresql', '', '', 'systemctl reload postgresql', 'PostgreSQL 10 and later read the certificate again on a reload.'],
    ['mysql', 'MySQL 8', 'Databases', 'mysql', '', '', 'mysql -e "ALTER INSTANCE RELOAD TLS"', 'Reloaded without a restart; mysql must sign in by itself (as root through its socket, or ~/.my.cnf).'],
    ['mariadb', 'MariaDB 10.4+', 'Databases', 'mariadb', '', '', 'mariadb -e "FLUSH SSL"', 'Reloaded without a restart; mariadb must sign in by itself (as root through its socket, or ~/.my.cnf).'],
    ['pveproxy', 'Proxmox VE (pveproxy)', 'Panels and appliances', 'pveproxy', '', '', ''],
    ['pbs', 'Proxmox Backup Server', 'Panels and appliances', 'proxmox-backup-proxy', '', '', 'systemctl reload proxmox-backup-proxy'],
    ['webmin', 'Webmin', 'Panels and appliances', 'webmin', '', '', ''],
    ['cockpit', 'Cockpit', 'Panels and appliances', 'cockpit', '', '', ''],
    ['grafana', 'Grafana', 'Panels and appliances', 'grafana-server', '', '', ''],
    ['gitlab', 'GitLab (Omnibus)', 'Panels and appliances', '', '', '', 'gitlab-ctl hup nginx', 'Its bundled nginx is told to read the certificate again.'],
    ['vsftpd', 'vsftpd', 'File transfer', 'vsftpd', 'vsftpd', '', ''],
    ['proftpd', 'ProFTPD', 'File transfer', 'proftpd', 'proftpd', 'proftpd -t', 'systemctl reload proftpd'],
    ['tomcat', 'Tomcat', 'Application servers', 'tomcat', '', '', '', 'The unit is tomcat, tomcat9 or tomcat10 - change it if it is not.'],
    ['mosquitto', 'Mosquitto (MQTT)', 'Application servers', 'mosquitto', 'mosquitto', '', ''],
    ['docker', 'A Docker container', 'Containers', '', '', '', '', 'The container is called web here - change it to yours.'],
    ['any', 'Any systemd service', 'Any other', 'myservice', 'myservice', '', '*', 'Its unit and process name below; a test of its configuration can be added after.']
  ];
  var SVC_HOW = [
    ['reload', 'Reload', 'no downtime', 'The service reads the new certificate; no connection is dropped.'],
    ['restart', 'Restart', 'a moment', 'systemctl restart: the service stops and starts again.'],
    ['hard', 'Hard restart', 'a few seconds', 'Stopped, every process of it waited for (20 s at most), those left killed, then started and checked - for a service whose processes outlive a restart.']
  ];
  function svcCommands(app, how, unitAs, procAs) {
    var unit = unitAs || app[3], proc = procAs || app[4], test = app[5], rel = app[6];
    if (rel === '*') rel = 'systemctl reload ' + unit;
    var post = unit ? ['systemctl is-active --quiet ' + unit] : [];
    if (app[0] === 'docker') {
      return how === 'restart' ? {test_cmd: [], reload_cmd: ['docker restart ' + (unitAs || 'web')], post_cmd: []} : null;
    }
    if (how === 'reload') return rel ? {test_cmd: test ? [test] : [], reload_cmd: [rel], post_cmd: app[0] === 'gitlab' ? [] : post} : null;
    if (how === 'restart') return unit ? {test_cmd: test ? [test] : [], reload_cmd: ['systemctl restart ' + unit], post_cmd: post} : null;
    if (how === 'hard') return unit && proc ? {test_cmd: test ? [test] : [], reload_cmd: [hardCmd(unit, proc, test)], post_cmd: []} : null;
    return null;
  }
  var SVC_LAST = null;
  function svcTemplates(done) {
    var st = {app: null, how: '', unit: '', proc: ''};
    modalOver(function () {
      modal(tr('A template for the commands after the files'), function (body) {
        body.appendChild(el('p', 'note', 'Choose the application and how it takes the new certificate. The test, the reload and the check after are filled in - change them as you need.'));
        var wrap = el('div', 'df-tpl');
        var left = el('div', 'df-tpl-l');
        var find = el('input');
        find.type = 'search';
        find.className = 'ct-kind-find';
        find.placeholder = tr('an application…');
        left.appendChild(find);
        var list = el('div', 'df-tpl-list');
        left.appendChild(list);
        var right = el('div', 'df-tpl-r');
        wrap.appendChild(left);
        wrap.appendChild(right);
        body.appendChild(wrap);
        var drawList = function () {
          clear(list);
          var q = find.value.trim().toLowerCase(), group = '';
          SVC_APPS.forEach(function (a) {
            if (q && (a[1] + ' ' + a[0] + ' ' + a[3]).toLowerCase().indexOf(q) < 0) return;
            if (a[2] !== group) { group = a[2]; list.appendChild(el('div', 'df-tpl-g', group)); }
            var b = el('button', 'df-tpl-app' + (st.app === a ? ' on' : ''));
            b.type = 'button';
            var ic = el('span', 'df-tpl-ic');
            /* The two words that are not a name (1.0.77): in the page's language, the icon by
               the application - DK, SD - not by the English words. */
            var said = a[0] === 'docker' || a[0] === 'any' ? tr(a[1]) : a[1];
            ic.textContent = a[0] === 'docker' ? 'DK' : (a[0] === 'any' ? 'SD' : a[1].replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase());
            b.appendChild(noI18n(ic));
            b.appendChild(noI18n(el('span', 'df-tpl-n', said)));
            b.onclick = function () {
              st.app = a;
              st.unit = a[0] === 'docker' ? 'web' : a[3];
              find.blur();
              st.proc = a[4];
              st.how = ['reload', 'restart', 'hard'].filter(function (h) { return svcCommands(a, h); })[0];
              drawList();
              drawRight();
            };
            list.appendChild(b);
          });
          if (!list.children.length) list.appendChild(el('p', 'muted small', 'Nothing of that name - Any service below fits every other.'));
        };
        var drawRight = function () {
          clear(right);
          var a = st.app;
          if (!a) { right.appendChild(el('p', 'muted df-tpl-empty', 'Choose an application on the left.')); return; }
          right.appendChild(noI18n(el('h4', 'df-tpl-h', a[0] === 'docker' || a[0] === 'any' ? tr(a[1]) : a[1])));
          if (a[7]) right.appendChild(el('p', 'note small', a[7]));
          var seg = el('div', 'df-tpl-how');
          SVC_HOW.forEach(function (h) {
            var ok = !!svcCommands(a, h[0], st.unit, st.proc);
            var b = el('button', 'df-tpl-hw' + (st.how === h[0] ? ' on' : ''));
            b.type = 'button';
            b.disabled = !ok;
            b.appendChild(el('b', '', h[1]));
            b.appendChild(el('span', 'tag ' + (h[0] === 'reload' ? 'ok' : (h[0] === 'restart' ? 'info' : 'warn')), h[2]));
            b.appendChild(el('span', 'muted small', ok ? h[3] : (h[0] === 'reload' ? 'It cannot read a certificate again without a restart.' : 'Not for this one.')));
            b.onclick = function () { st.how = h[0]; drawRight(); };
            seg.appendChild(b);
          });
          right.appendChild(seg);
          var g = el('div', 'formgrid');
          if (a[0] === 'docker') {
            var cn = textBox(st.unit, 'web', 'mono');
            cn.oninput = function () { st.unit = cn.value.trim(); paintCmds(); };
            g.appendChild(formField('The container', cn));
          } else if (a[3]) {
            var un = textBox(st.unit, a[3], 'mono');
            un.oninput = function () { st.unit = un.value.trim(); paintCmds(); };
            g.appendChild(formField('The service (systemd unit)', un));
            if (st.how === 'hard') {
              var pr = textBox(st.proc, a[4], 'mono');
              pr.oninput = function () { st.proc = pr.value.trim(); paintCmds(); };
              g.appendChild(formField('Its process name', pr, 'pgrep -x / pkill -x'));
            }
          }
          if (g.children.length) right.appendChild(g);
          var cmds = el('div', 'df-tpl-cmds');
          right.appendChild(cmds);
          var paintCmds = function () {
            clear(cmds);
            var c = svcCommands(a, st.how, st.unit, st.proc);
            if (!c) return;
            [['test_cmd', 'Test command'], ['reload_cmd', 'Reload / restart'], ['post_cmd', 'After reloading']].forEach(function (k) {
              var box = el('div', 'df-tpl-cmd');
              box.appendChild(el('span', 'df-tpl-k', k[1]));
              var pre = el('pre', 'mono');
              pre.textContent = c[k[0]].length ? c[k[0]].join('\n') : '–';
              noI18n(pre);
              box.appendChild(pre);
              cmds.appendChild(box);
            });
          };
          paintCmds();
        };
        find.oninput = drawList;
        drawList();
        drawRight();
        setTimeout(function () { try { find.focus(); } catch (e) { } }, 50);
        SVC_LAST = st;
      }, [{words: 'Close', close: true}, {words: 'Use the template', cls: 'primary', icon: 'check', go: function () {
        var s = SVC_LAST;
        var c = s && s.app && svcCommands(s.app, s.how, s.unit, s.proc);
        if (!c) { toast(tr('choose the application'), 'bad'); return; }
        closeModal();
        done(c, s.app[1]);
      }}], 'large');
    });
  }
  /* Words in the page's language where i18n.js does not reach: the hint of a
     box marked as data (data-no-i18n) is never translated by it. (1.0.19) */
  function tr(s) {
    try { var got = typeof i18nText === 'function' ? i18nText(s) : null; return got || s; } catch (e) { return s; }
  }

  function arr(v) {
    if (Array.isArray(v)) return v;
    if (v === undefined || v === null || v === '') return [];
    return String(v).split(/\n/);
  }
  function lineList(v) {
    return arr(v).map(function (x) { return String(x).trim(); }).filter(function (x) { return x && x.charAt(0) !== '#'; });
  }
  function mono(text, cls) { return noI18n(el('span', 'mono' + (cls ? ' ' + cls : ''), text)); }
  function dirOf(p) {
    p = String(p || '');
    var at = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
    return at > 0 ? p.slice(0, at) : '';
  }
  function segOf(pairs, value, onPick) {
    var seg = el('div', 'seg df-seg');
    var set = function (v) {
      seg._value = v;
      Array.prototype.forEach.call(seg.children, function (b) { b.classList.toggle('on', b._v === v); });
    };
    pairs.forEach(function (p) {
      var b = el('button', '', p[1]);
      b.type = 'button';
      b._v = p[0];
      if (p[2]) b.title = p[2];
      b.onclick = function () { if (seg._off) return; set(p[0]); onPick(p[0]); };
      seg.appendChild(b);
    });
    seg._set = set;
    set(value);
    return seg;
  }
  function fieldOf(fields, key) { return fields.filter(function (f) { return f.key === key; })[0] || null; }

  /* ---- a box for code: line numbers, Tab indents, grows to 20 lines ---------- */
  function codeBox(value, opts) {
    opts = opts || {};
    var wrap = el('div', 'df-code');
    var gutter = noI18n(el('div', 'df-code-n'));
    var ta = el('textarea', 'df-code-t');
    ta.spellcheck = false;
    ta.setAttribute('autocapitalize', 'off');
    ta.setAttribute('autocomplete', 'off');
    ta.wrap = 'off';
    noI18n(ta);
    ta.value = value || '';
    if (opts.placeholder) ta.placeholder = opts.placeholder;
    if (opts.readOnly) { ta.readOnly = true; wrap.classList.add('ro'); }
    wrap.appendChild(gutter);
    wrap.appendChild(ta);
    var escaped = false;
    var paint = function () {
      var n = Math.max(1, ta.value.split('\n').length);
      var shown = Math.min(Math.max(n, opts.min || 8), opts.max || 20);
      ta.rows = shown;
      wrap.classList.toggle('df-code-scroll', n > (opts.max || 20));
      if (gutter._n !== n) {
        var s = [];
        for (var i = 1; i <= n; i++) s.push(i);
        gutter.textContent = s.join('\n');
        gutter._n = n;
      }
      gutter.scrollTop = ta.scrollTop;
    };
    ta.addEventListener('input', paint);
    ta.addEventListener('scroll', function () { gutter.scrollTop = ta.scrollTop; });
    ta.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { escaped = true; return; }
      if (e.key !== 'Tab' || ta.readOnly) { escaped = false; return; }
      /* Tab indents; Esc then Tab leaves the box (a keyboard is never caught in it). */
      if (escaped || e.ctrlKey || e.altKey || e.metaKey) { escaped = false; return; }
      e.preventDefault();
      var a = ta.selectionStart, z = ta.selectionEnd, v = ta.value;
      var unit = (wrap._indent && wrap._indent()) || '  ';
      if (a === z && !e.shiftKey) {
        ta.setRangeText(unit, a, z, 'end');
      } else {
        var from = v.lastIndexOf('\n', a - 1) + 1;
        var block = v.slice(from, z);
        var done = e.shiftKey
          ? block.replace(new RegExp('^(\\t| {1,' + unit.length + '})', 'gm'), '')
          : block.replace(/^/gm, unit);
        ta.setRangeText(done, from, z, 'select');
      }
      ta.dispatchEvent(new Event('input', {bubbles: true}));
    });
    wrap._input = ta;
    wrap._get = function () { return ta.value; };
    wrap._set = function (v) { ta.value = v || ''; paint(); ta.dispatchEvent(new Event('input', {bubbles: true})); };
    wrap._insert = function (text) {
      if (ta.readOnly) return;
      ta.focus();
      ta.setRangeText(text, ta.selectionStart, ta.selectionEnd, 'end');
      ta.dispatchEvent(new Event('input', {bubbles: true}));
    };
    setTimeout(paint, 0);
    paint();
    return wrap;
  }

  /* ---- the files, a row each --------------------------------------------- */
  function parseLine(line) {
    var parts = String(line || '').trim().split(/\s+/);
    var w = (parts[0] || '').toLowerCase().split('@');
    var row = {format: w[0] || 'fullchain-pem', variant: w[1] || '', path: parts[1] || '', mode: '', owner: ''};
    parts.slice(2).forEach(function (x) {
      if (/^0?[0-7]{3,4}$/.test(x)) row.mode = x.length === 3 ? '0' + x : x;
      else row.owner = x;
    });
    return row;
  }
  var ALIASES = {cert: 'cert-pem', crt: 'cert-pem', pem: 'cert-pem', der: 'cert-der', key: 'key-pem', privkey: 'key-pem',
                 rsa: 'key-rsa', chain: 'chain-pem', ca: 'chain-pem', fullchain: 'fullchain-pem', combined: 'combined-pem',
                 haproxy: 'combined-pem', p7: 'p7b', pkcs12: 'pfx', keystore: 'jks'};

  function filesPart(ui, values, ctx, changed) {
    var formats = ui.formats || [];
    var title = {}, what = {};
    formats.forEach(function (f) { title[f[0]] = f[1]; what[f[0]] = f[2]; });
    var win = ui.kind === 'windows', local = ui.kind === 'local';
    var withMode = !win, withOwner = !!ui.owners && !win;
    var box = el('div', 'df-files');
    var table = el('div', 'df-rows' + (withOwner ? ' own' : '') + (withMode ? '' : ' nomode'));
    var head = el('div', 'df-row df-head');
    ['Format', local ? 'Path inside the folder' : 'Path'].concat(withMode ? ['Mode'] : [], withOwner ? ['Owner[:group]'] : [], ['']).forEach(function (h) {
      head.appendChild(el('span', '', h));
    });
    table.appendChild(head);
    var rows = [];
    var lastPath = null;
    var dual = function () { return !!ctx.dual; };
    var addRow = function (r, at) {
      r = r || {format: 'fullchain-pem', variant: '', path: '', mode: '', owner: ''};
      r.format = ALIASES[r.format] || r.format;
      var line = el('div', 'df-row');
      var fcell = el('div', 'df-fcell');
      var fsel = el('select', 'df-fmt');
      formats.forEach(function (f) {
        var o = el('option', '', f[1]);
        o.value = f[0];
        o.title = f[2];
        fsel.appendChild(o);
      });
      if (!title[r.format]) { var x = el('option', '', r.format); x.value = r.format; fsel.appendChild(x); }
      fsel.value = r.format;
      fcell.appendChild(fsel);
      var vsel = selectBox([['', 'the main one'], ['alt', 'the twin'], ['ec', 'the ECDSA one'], ['rsa', 'the RSA one']], r.variant || '');
      vsel.className = 'df-var';
      vsel.title = 'Of a dual certificate: which of its two';
      vsel.hidden = !dual() && !r.variant;
      var says = el('span', 'df-what', what[r.format] || '');
      line.appendChild(fcell);
      var pcell = el('div', 'df-pcell');
      var base = local ? ((ctx.targetRow && ctx.targetRow.config && ctx.targetRow.config.base) || ui.base) : '';
      if (base) { var bl = mono(String(base).replace(/\/+$/, '') + '/', 'df-base'); bl.title = String(base); pcell.appendChild(bl); }
      var path = textBox(r.path, win ? 'C:/certs/{name}.pfx' : (local ? '{name}/fullchain.pem' : '/etc/ssl/acme/{name}.crt'), 'mono df-path');
      noI18n(path);
      path.addEventListener('focus', function () { lastPath = path; });
      pcell.appendChild(path);
      var pnote = el('span', 'df-pnote');
      line.appendChild(pcell);
      var msel = null, owner = null;
      if (withMode) {
        /* The mode chosen in a popup of tick boxes as chmod's dialog has them (1.0.65): read,
           write, run for the owner, the group and the others, and the special bits; the
           octal number beside them. Empty is the default (0600 for a key, 0644 for the rest). */
        msel = el('button', 'btn mono df-mode df-modebtn');
        msel.type = 'button';
        msel.value = r.mode || '';
        var paintMode = function () { msel.textContent = msel.value || tr('default'); };
        paintMode();
        msel.title = tr('the file\'s mode, as chmod takes it - empty: 0600 for a key, 0644 for the rest');
        noI18n(msel);
        msel.onclick = function () {
          var isKey = KEYS.indexOf(fsel.value) >= 0;
          chmodPopup(msel.value, isKey ? '0600' : '0644', path.value.trim(), function (v) {
            msel.value = v;
            paintMode();
            line.dispatchEvent(new Event('change', {bubbles: true}));
            changed();
          });
        };
        line.appendChild(msel);
      }
      if (withOwner) {
        owner = textBox(r.owner, 'root:root', 'mono df-owner');
        noI18n(owner);
        line.appendChild(owner);
      }
      var rm = iconButton('trash', 'Take this file away');
      rm.onclick = function () {
        rows = rows.filter(function (x) { return x.line !== line; });
        line.remove();
        changed();
      };
      line.appendChild(rm);
      /* Under the row: which of a dual certificate's two, what the format holds, what is wrong. */
      var sub = el('div', 'df-sub');
      sub.appendChild(vsel);
      sub.appendChild(says);
      sub.appendChild(pnote);
      line.appendChild(sub);
      var row = {line: line, fsel: fsel, vsel: vsel, path: path, msel: msel, owner: owner, says: says, pnote: pnote};
      row.read = function () {
        var p = path.value.trim();
        if (!p) return '';
        var bits = [fsel.value + (vsel.value ? '@' + vsel.value : ''), p];
        if (msel && msel.value.trim()) bits.push(msel.value.trim());
        if (owner && owner.value.trim()) bits.push(owner.value.trim());
        return bits.join(' ');
      };
      row.check = function () {
        var p = path.value.trim(), bad = '', warn = '';
        if (!p) bad = 'a path is needed';
        else if (/\s/.test(p)) bad = 'no spaces in a path';
        else if (!local && !/^\//.test(p) && !/^[A-Za-z]:[\\/]/.test(p)) bad = win ? 'the path must be absolute (start with C:/)' : 'the path must be absolute (start with /)';
        else if (/(^|[\\/])\.\.([\\/]|$)/.test(p)) bad = '.. is not allowed in a path';
        else if (/['"`$;&|<>]/.test(p)) bad = 'quotes, $ ; & | < > are not allowed in a path';
        else if (/[\\/]$/.test(p)) bad = 'that is a folder: give the file a name';
        else if (/\{(?!(name|cn|service|date|alt)\})[a-z_]+\}/.test(p)) bad = 'not a placeholder there is: ' + p.match(/\{[a-z_]+\}/)[0];
        if (msel && msel.value.trim() && !/^[0-7]{3,4}$/.test(msel.value.trim())) bad = bad || 'the mode is three or four octal digits, as 0644 or 0755';
        var m = msel && (msel.value.trim() || (KEYS.indexOf(fsel.value) >= 0 ? '0600' : '0644'));
        if (!bad && m && KEYS.indexOf(fsel.value) >= 0 && (parseInt(m, 8) & 4)) warn = 'anybody on the machine may read the key: 0600 or 0640';
        if (owner && owner.value.trim() && !/^[A-Za-z0-9_][A-Za-z0-9_.-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]*)?$/.test(owner.value.trim())) bad = bad || 'the owner is user or user:group';
        path.classList.toggle('df-bad', !!bad && !!p);
        if (msel) {
          msel.classList.toggle('df-warn', !!warn);
          msel.classList.toggle('df-bad', !!msel.value.trim() && !/^[0-7]{3,4}$/.test(msel.value.trim()));
        }
        pnote.textContent = bad && p ? bad : warn;
        pnote.className = 'df-pnote ' + (bad && p ? 'bad' : (warn ? 'warn' : ''));
        says.hidden = !!pnote.textContent;
        return bad;
      };
      fsel.addEventListener('change', function () { says.textContent = what[fsel.value] || ''; });
      line.addEventListener('input', function () { row.check(); });
      line.addEventListener('change', function () { row.check(); });
      if (at === undefined) { table.appendChild(line); rows.push(row); }
      row.check();
      if (!MANAGE) Array.prototype.forEach.call(line.querySelectorAll('input,select,button'), function (x) { x.disabled = true; });
      return row;
    };
    box.appendChild(table);
    var tools = el('div', 'df-tools');
    var add = cmdButton('Add a file', 'add', 'small');
    add.onclick = function () {
      var last = rows[rows.length - 1];
      var d = last ? dirOf(last.path.value.trim()) : '';
      var r = addRow({format: rows.length ? 'key-pem' : 'fullchain-pem', variant: '', path: d ? d + '/' : '', mode: '', owner: last && last.owner ? last.owner.value : ''});
      r.path.focus();
      changed();
    };
    if (MANAGE) tools.appendChild(add);
    var chips = el('div', 'df-chips');
    chips.appendChild(el('span', 'muted small', 'Into the path:'));
    (ui.vars || []).forEach(function (v) {
      var c = el('button', 'df-chip', v[0]);
      c.type = 'button';
      noI18n(c);
      c.title = v[1];
      c.onmousedown = function (e) { e.preventDefault(); };
      c.onclick = function () {
        var t = lastPath && document.body.contains(lastPath) ? lastPath : (rows[rows.length - 1] || {}).path;
        if (!t || !MANAGE) return;
        t.focus();
        t.setRangeText(v[0], t.selectionStart, t.selectionEnd, 'end');
        t.dispatchEvent(new Event('input', {bubbles: true}));
      };
      chips.appendChild(c);
    });
    tools.appendChild(chips);
    var asText = el('button', 'df-link', 'As text');
    asText.type = 'button';
    asText.title = 'The same files as lines "format path [mode] [owner]" - as the command line has them';
    tools.appendChild(asText);
    box.appendChild(tools);
    /* The same rows as text: one a line, as the command line and older pages have them. */
    var textArea = el('textarea', 'mono df-astext');
    noI18n(textArea);
    textArea.spellcheck = false;
    textArea.hidden = true;
    box.appendChild(textArea);
    var textMode = false;
    var setRows = function (list) {
      rows.forEach(function (r) { r.line.remove(); });
      rows = [];
      list.forEach(function (l) { addRow(parseLine(l)); });
    };
    asText.onclick = function () {
      textMode = !textMode;
      if (textMode) {
        textArea.value = rows.map(function (r) { return r.read(); }).filter(Boolean).join('\n');
        textArea.rows = Math.min(Math.max(rows.length + 1, 3), 14);
      } else {
        setRows(lineList(textArea.value));
      }
      table.hidden = textMode;
      add.hidden = textMode;
      chips.hidden = textMode;
      textArea.hidden = !textMode;
      asText.textContent = textMode ? 'As rows' : 'As text';
      changed();
    };
    textArea.addEventListener('input', changed);
    setRows(lineList(values.outputs));
    return {
      node: box,
      read: function () {
        if (textMode) return lineList(textArea.value);
        return rows.map(function (r) { return r.read(); }).filter(Boolean);
      },
      formats: function () {
        if (textMode) return lineList(textArea.value).map(function (l) { return ALIASES[parseLine(l).format] || parseLine(l).format; });
        return rows.filter(function (r) { return r.path.value.trim(); }).map(function (r) { return r.fsel.value; });
      },
      set: function (list) {
        if (textMode) asText.onclick();
        setRows(list);
        changed();
      },
      folder: function () {
        var r = rows.filter(function (x) { return x.path.value.trim(); })[0];
        var d = r ? dirOf(r.path.value.trim()) : '';
        return /\{dir\}/.test(d) ? '' : d;
      },
      check: function () {
        if (textMode) return '';
        var bad = '';
        rows.forEach(function (r) { var b = r.check(); if (b && !bad && r.path.value.trim()) bad = b; });
        /* none at all (1.0.80): saved, its deployment failed "no files to write" */
        if (!bad && !rows.some(function (r) { return r.path.value.trim(); })) bad = tr('no file is written - pick a layout or add a file');
        return bad;
      },
      dual: function (on) { rows.forEach(function (r) { r.vsel.hidden = !on && !r.vsel.value; }); }
    };
  }

  /* ---- the password of PKCS#12 / keystore files ---------------------------- */
  function passwordPart(values, secrets, fields, changed) {
    var box = el('div', 'df-pw');
    var isSet = !!secrets.pfx_password;
    var mode = String(values.pfx_password_mode || 'fixed');
    var fresh = false;
    var head = el('div', 'df-pw-h');
    head.appendChild(el('b', '', 'Password of the PKCS#12 / keystore files'));
    box.appendChild(head);
    var seg = segOf([['none', 'None', 'whoever can read the file has the key'],
                     ['fixed', 'Set here', 'the one you type below'],
                     ['generate', 'Made by acme', 'a random one, kept sealed with the deployment, given to the script as ACME_PASSWORD']],
                    mode, function () { paint(); changed(); });
    box.appendChild(seg);
    var line = el('div', 'df-pw-line');
    var pw = secretBox(CT.keptSecret ? CT.keptSecret(values.pfx_password) : '', tr(isSet ? 'set - leave empty to keep it' : 'not set'), 'mono');
    noI18n(pw);
    var made = el('div', 'df-pw-made');
    var again = cmdButton('Make a new one', 'refresh', 'small');
    again.onclick = function () { fresh = true; paint(); changed(); };
    var aliasF = fieldOf(fields, 'jks_alias');
    var alias = aliasF ? textBox(values.jks_alias || '', tr('the certificate\'s name'), 'mono') : null;
    if (alias) noI18n(alias);
    line.appendChild(pw);
    line.appendChild(made);
    box.appendChild(line);
    if (alias) {
      var al = el('div', 'df-alias');
      al.appendChild(el('span', 'muted small', 'Alias in the keystore'));
      al.appendChild(alias);
      box.appendChild(al);
    }
    var says = el('div', 'says df-pw-says');
    box.appendChild(says);
    var paint = function () {
      var m = seg._value;
      pw.hidden = m !== 'fixed';
      made.hidden = m !== 'generate';
      clear(made);
      if (m === 'generate') {
        var kept = mode === 'generate' && isSet && !fresh;
        if (kept) {
          made.appendChild(el('span', 'tag ok', 'kept'));
          var k = CT.keptSecret ? CT.keptSecret(values.pfx_password) : '';
          if (k) made.appendChild(mono(k));
          if (MANAGE) made.appendChild(again);
        } else {
          made.appendChild(el('span', 'tag info', fresh ? 'a new one on save' : 'made on save'));
        }
      }
      says.textContent = m === 'none' ? 'The files are not locked: whoever can read them has the key. A Java keystore always needs one.'
        : m === 'generate' ? 'A random password of 24 characters, kept sealed with this deployment and the same on every renewal; a full administrator sees it here as every secret. The script gets it as ACME_PASSWORD.'
          : 'Typed here, kept sealed. Empty: none (or what the service\'s preset says). The script gets it as ACME_PASSWORD.';
    };
    pw.addEventListener('input', changed);
    if (alias) alias.addEventListener('input', changed);
    paint();
    if (!MANAGE) { seg._off = true; pw.disabled = true; if (alias) alias.disabled = true; }
    return {
      node: box,
      read: function (o) {
        o.pfx_password_mode = seg._value;
        if (seg._value === 'fixed') o.pfx_password = pw.value;
        if (fresh) o.pfx_password_new = true;
        if (alias) o.jks_alias = alias.value.trim();
        return o;
      },
      set: function (m) { seg._set(m); paint(); }
    };
  }

  /* ---- after the files ------------------------------------------------------ */
  function scriptPart(ui, fields, values, ctx, changed) {
    var box = el('div', 'df-script');
    var tcfg = (ctx.targetRow && ctx.targetRow.config) || {};
    var tMode = String(tcfg.script_mode || 'none');
    var hasDefault = tMode === 'path' || tMode === 'inline';
    var mode = String(values.script_mode === undefined || values.script_mode === null ? '' : values.script_mode);
    var interps = ui.interps || [['bash', 'bash']];
    var pairs = [];
    if (hasDefault || mode === '') pairs.push(['', hasDefault ? 'As the target says' : 'Nothing', hasDefault ? 'the target\'s own script, set in its settings' : 'nothing is run after the files']);
    if (hasDefault || mode !== '') pairs.push(['none', 'Nothing', 'nothing is run after the files']);
    pairs.push(['path', 'A script on the machine', 'a command or script already there, with its arguments']);
    pairs.push(['inline', 'Written here', 'uploaded on every deployment, run, then deleted - always the current one']);
    var seg = segOf(pairs, mode, function () { paint(); changed(); });
    box.appendChild(seg);
    var inherited = el('div', 'df-inherit');
    box.appendChild(inherited);
    if (hasDefault) {
      inherited.appendChild(el('div', 'small muted', 'The target\'s default (its settings, a full administrator changes it there):'));
      if (tMode === 'path') {
        inherited.appendChild(mono(String(tcfg.script_path || '') + (tcfg.script_args ? ' ' + tcfg.script_args : ''), 'df-cmdline'));
      } else {
        var pre = noI18n(el('pre', 'df-pre', String(tcfg.script_body || '')));
        inherited.appendChild(pre);
      }
    }
    /* on the machine: its path and arguments */
    var pathBox = el('div', 'df-pathmode');
    var sp = textBox(values.script_path || '', win() ? 'C:/scripts/reload-certs.ps1' : '/usr/local/bin/reload-certs.sh', 'mono');
    noI18n(sp);
    var sa = textBox(values.script_args || '', '{name}', 'mono');
    noI18n(sa);
    var g = el('div', 'df-two');
    g.appendChild(formField('Command or script on the machine', sp, 'its absolute path; the ACME_* variables are set for it'));
    g.appendChild(formField('Its arguments', sa, '{name} {cn} {service} {date} are filled in'));
    pathBox.appendChild(g);
    box.appendChild(pathBox);
    /* written here: the interpreter, an example to start from, the code */
    var inl = el('div', 'df-inline');
    var bar = el('div', 'df-bar');
    var isel = selectBox(interps, values.script_interp || interps[0][0]);
    isel.className = 'df-interp';
    if (interps.length === 1) isel.disabled = true;
    bar.appendChild(el('span', 'muted small', 'Run with'));
    bar.appendChild(isel);
    var snipSel = null;
    if ((ui.snippets || []).length) {
      snipSel = selectBox([['', 'Start from an example…']].concat(ui.snippets.map(function (s, i) { return [String(i), s.title]; })), '');
      snipSel.className = 'df-snip';
      bar.appendChild(snipSel);
    }
    var argsIn = textBox(values.script_args || '', tr('arguments: {name}'), 'mono df-args');
    noI18n(argsIn);
    argsIn.title = tr('Its arguments - {name} {cn} {service} {date} are filled in');
    bar.appendChild(argsIn);
    var size = el('span', 'muted small df-size');
    bar.appendChild(size);
    inl.appendChild(bar);
    var replace = el('div', 'df-replace');
    replace.hidden = true;
    inl.appendChild(replace);
    var code = codeBox(values.script_body || '', {readOnly: !FULL, placeholder: win() ? '# PowerShell: $env:ACME_FILE_PFX, $env:ACME_DRY_RUN ...' : '#!/bin/bash\n# "$ACME_FILE_KEY_PEM", "$ACME_DRY_RUN" ...'});
    code._indent = function () { return isel.value === 'python3' || isel.value === 'powershell' ? '    ' : '  '; };
    inl.appendChild(code);
    var foot = el('div', 'says df-code-says');
    foot.textContent = !FULL ? 'Only a full administrator may change the script (it runs on the target).'
      : ctx.sudo ? 'Uploaded to the target\'s upload folder on every deployment under a name of its own, made executable, run through sudo, then deleted - what it prints goes into the job. Exit code other than 0: the deployment fails and the previous files are put back. On a test ACME_DRY_RUN is 1: change nothing then.'
        : 'Uploaded to the target\'s upload folder on every deployment under a name of its own, made executable, run, then deleted - what it prints goes into the job. Exit code other than 0: the deployment fails and the previous files are put back. On a test ACME_DRY_RUN is 1: change nothing then.';
    inl.appendChild(foot);
    box.appendChild(inl);
    if (snipSel) snipSel.onchange = function () {
      var s = ui.snippets[Number(snipSel.value)];
      snipSel.value = '';
      if (!s || !FULL) return;
      var put = function () {
        code._set(s.body);
        if (s.interp) isel.value = s.interp;
        replace.hidden = true;
        changed();
      };
      if (!code._get().trim()) { put(); return; }
      clear(replace);
      replace.appendChild(el('span', '', 'Replace what is written with the example?'));
      var yes = cmdButton('Replace it', 'undo', 'small');
      yes.onclick = put;
      var no = cmdButton('Keep mine', 'close', 'small');
      no.onclick = function () { replace.hidden = true; };
      replace.appendChild(yes);
      replace.appendChild(no);
      replace.hidden = false;
    };
    var bodyBytes = function () { try { return new Blob([code._get()]).size; } catch (e) { return code._get().length; } };
    var paint = function () {
      var m = seg._value;
      inherited.hidden = !(m === '' && hasDefault);
      pathBox.hidden = m !== 'path';
      inl.hidden = m !== 'inline';
      var n = bodyBytes(), most = ui.script_max || 65536;
      size.textContent = n ? bytes(n) + ' / ' + bytes(most) : '';
      size.classList.toggle('bad', n > most);
    };
    /* The arguments are one: typed in either place, both show it. */
    sa.addEventListener('input', function () { argsIn.value = sa.value; });
    argsIn.addEventListener('input', function () { sa.value = argsIn.value; });
    box.addEventListener('input', function () { paint(); changed(); });
    box.addEventListener('change', function () { paint(); changed(); });
    paint();
    if (!MANAGE) { seg._off = true; [sp, sa, isel, argsIn].forEach(function (x) { x.disabled = true; }); if (snipSel) snipSel.disabled = true; }
    if (!FULL && snipSel) snipSel.hidden = true;
    function win() { return ui.kind === 'windows'; }
    return {
      node: box,
      code: code,
      interp: function () { return isel.value; },
      mode: function () { return seg._value || (hasDefault ? tMode : 'none'); },
      read: function (o) {
        o.script_mode = seg._value;
        o.script_path = sp.value.trim();
        o.script_args = sa.value.trim();
        o.script_interp = isel.value;
        o.script_body = code._get();
        return o;
      },
      check: function () {
        var m = seg._value;
        if (m === 'path' && !sp.value.trim()) return 'the path of the script on the machine is needed';
        if (m === 'path' && !/^(\/|[A-Za-z]:[\\/])/.test(sp.value.trim())) return 'the script on the machine is named by its absolute path';
        if (m === 'inline' && !code._get().trim()) return 'the script written here is empty';
        if (m === 'inline' && bodyBytes() > (ui.script_max || 65536)) return 'the script is bigger than 64 KiB';
        return '';
      }
    };
  }

  /* ---- what it will be: the preview --------------------------------------------- */
  var LEVEL_TAG = {bad: 'crit', warn: 'warn', info: 'dim'};
  function previewPart(ui, ctx) {
    var box = el('div', 'df-side');
    var files = el('section', 'msect df-card');
    files.appendChild(el('h4', '', 'What it will be'));
    var fsub = el('p', 'msect-lede', '');
    files.appendChild(fsub);
    var flist = el('div', 'df-plist');
    files.appendChild(flist);
    var probs = el('div', 'df-probs');
    files.appendChild(probs);
    box.appendChild(files);
    var envCard = el('section', 'msect df-card');
    var eh = el('h4', '', 'What the script gets');
    envCard.appendChild(eh);
    envCard.appendChild(el('p', 'msect-lede', 'Its environment, the values as for this certificate now. Click one to put it into the script.'));
    var elist = el('div', 'df-env');
    envCard.appendChild(elist);
    box.appendChild(envCard);
    var test = el('section', 'msect df-card df-test');
    test.hidden = true;
    box.appendChild(test);
    var doc = {};
    (ui.env || []).forEach(function (e) { doc[e[0]] = e[1]; });
    var fmtTitle = {};
    (ui.formats || []).forEach(function (f) { fmtTitle[f[0]] = f[1]; });
    var insertOf = function (k) {
      var interp = ctx.interp ? ctx.interp() : 'bash';
      if (interp === 'powershell') return '$env:' + k;
      if (interp === 'python3') return 'os.environ[\'' + k + '\']';
      return '"$' + k + '"';
    };
    var drawEnv = function (env) {
      clear(elist);
      var keys = Object.keys(env || {});
      if (!keys.length) keys = (ui.env || []).map(function (e) { return e[0]; }).filter(function (k) { return k.indexOf('<') < 0; });
      keys.forEach(function (k) {
        var v = env ? env[k] : '';
        var line = el('button', 'df-envl');
        line.type = 'button';
        line.appendChild(mono(k, 'df-envk'));
        var val = noI18n(el('span', 'df-envv mono', v === undefined ? '' : String(v).replace(/\n/g, ' ⏎ ')));
        line.appendChild(val);
        var m = /^ACME_FILE_([A-Z0-9_]+?)(?:_(ALT|RSA|EC|ED))?(?:_(\d+))?$/.exec(k);
        var words = doc[k];
        if (!words && m) {
          var f = m[1].toLowerCase().replace(/_/g, '-');
          words = (m[2] ? 'the file of the ' + m[2] + ' one: ' : 'the file: ') + (fmtTitle[f] || f) + (m[3] ? ' #' + m[3] : '');
        }
        if (!words && k === 'ACME_ALT_FINGERPRINT') words = 'the twin\'s SHA-256 fingerprint (a dual certificate)';
        if (!words && k === 'ACME_ALT_KEY_TYPE') words = 'the kind of the twin\'s key';
        if (!words && k === 'ACME_DEPLOY_ID') words = 'the deployment\'s number in acme';
        if (!words && k === 'ACME_TEST_DIR') words = 'on a test: the temporary folder';
        if (words) line.title = words;
        line.onclick = function () { if (ctx.insert) ctx.insert(insertOf(k)); };
        elist.appendChild(line);
      });
    };
    var said = function (list) {
      clear(probs);
      (list || []).forEach(function (p) {
        var line = el('div', 'df-prob ' + (p.level || 'info'));
        line.appendChild(el('span', 'tag ' + (LEVEL_TAG[p.level] || 'dim'), p.level === 'bad' ? 'wrong' : (p.level === 'warn' ? 'mind' : 'note')));
        line.appendChild(el('span', '', p.words));
        probs.appendChild(line);
      });
    };
    var draw = function (d) {
      clear(flist);
      box.classList.remove('df-asking');
      if (!d) return;
      var list = d.files || [];
      fsub.textContent = d.cert ? (d.issued ? 'For ' + d.cert + ' as it is now - the paths filled in.' : d.cert + ' is not issued yet: its names, the sizes guessed.')
        : 'For a certificate of these names - the sizes guessed.';
      list.forEach(function (f) {
        var one = el('div', 'df-pf' + (f.key ? ' key' : ''));
        var top = el('div', 'df-pf-top');
        top.appendChild(mono(f.full || f.path, 'df-pf-path'));
        one.appendChild(top);
        var facts = el('div', 'df-pf-facts');
        facts.appendChild(el('span', 'tag ' + (f.key ? 'warn' : 'info'), f.title || f.format));
        if (f.variant || d.dual) facts.appendChild(el('span', 'tag dim', (f.family || '').toUpperCase() || f.variant));
        if (f.mode) facts.appendChild(mono(f.mode + (f.owner ? ' ' + f.owner : '')));
        facts.appendChild(el('span', 'muted', (f.exact ? '' : '~') + bytes(f.size)));
        one.appendChild(facts);
        flist.appendChild(one);
      });
      if (!list.length) flist.appendChild(el('p', 'muted small', 'No file yet.'));
      if (d.commands) {
        var cm = [];
        ['pre_cmd', 'test_cmd', 'reload_cmd', 'post_cmd'].forEach(function (k) { (d.commands[k] || []).forEach(function (c) { cm.push([k, c]); }); });
        if (cm.length) {
          var cw = el('div', 'df-pcmds');
          var names = {pre_cmd: 'before', test_cmd: 'test', reload_cmd: 'reload', post_cmd: 'after'};
          cm.forEach(function (x) {
            var l = el('div', '');
            l.appendChild(el('span', 'tag dim', names[x[0]]));
            l.appendChild(mono(' ' + x[1]));
            cw.appendChild(l);
          });
          flist.appendChild(cw);
        }
      }
      if (d.script) {
        var sl = el('div', 'df-pscript');
        sl.appendChild(el('span', 'tag violet', 'script'));
        sl.appendChild(document.createTextNode(' '));
        sl.appendChild(d.script.mode === 'path' ? mono(d.script.path + (d.script.args ? ' ' + d.script.args : ''))
          : el('span', '', (d.script.from === 'target' ? 'the target\'s, ' : '') + d.script.interp + ', ' + d.script.lines + ' lines'));
        flist.appendChild(sl);
      }
      /* Windows: the roles chosen (IIS, RDP, Exchange...) and the PowerShell that runs for them. */
      if (d.roles && (d.roles.on || []).length) {
        var rl = el('div', 'df-proles');
        rl.appendChild(el('span', 'tag violet', 'after the import'));
        d.roles.on.forEach(function (r) { rl.appendChild(el('span', 'tag dim', r.title || r.key)); });
        flist.appendChild(rl);
      }
      if (d.roles && d.roles.script) {
        var det = el('details', 'ct-more df-ps');
        det.appendChild(el('summary', '', 'PowerShell that will run'));
        var pre = noI18n(el('pre', 'df-pre mono', String(d.roles.script)));
        det.appendChild(pre);
        var cp = cmdButton('Copy', 'copy', 'small');
        cp.onclick = function () { copyText(String(d.roles.script), cp, 'on the clipboard'); };
        var cr = el('div', 'btnrow df-ps-tools');
        cr.appendChild(cp);
        det.appendChild(cr);
        if (box._psOpen) det.open = true;
        det.addEventListener('toggle', function () { box._psOpen = det.open; });
        flist.appendChild(det);
      }
      said(d.problems);
      drawEnv(d.env);
      envCard.hidden = !(d.script || ctx.scriptOn && ctx.scriptOn());
    };
    drawEnv(null);
    envCard.hidden = true;
    return {
      node: box,
      draw: draw,
      asking: function () { box.classList.add('df-asking'); },
      failed: function (e) {
        box.classList.remove('df-asking');
        said([{level: 'bad', words: 'the preview could not be made: ' + String((e && e.message) || e)}]);
      },
      showEnv: function (on) { envCard.hidden = !on; },
      test: function (d, err) {
        clear(test);
        test.hidden = false;
        test.appendChild(el('h4', '', 'The test'));
        if (err) {
          test.appendChild(el('p', 'ct-bad', String((err && err.message) || err)));
        } else {
          var good = d && d.ok !== false;
          var head = el('div', 'df-test-h');
          head.appendChild(el('span', 'tag ' + (good ? 'ok' : 'crit'), good ? 'passed' : 'failed'));
          head.appendChild(el('span', '', String((d && d.said) || '')));
          test.appendChild(head);
          if (d && d.steps && CT.jobLog) test.appendChild(CT.jobLog(d.steps));
        }
        try { test.scrollIntoView({block: 'nearest', behavior: 'smooth'}); } catch (e) { test.scrollIntoView(); }
      },
      testBusy: function () {
        clear(test);
        test.hidden = false;
        test.appendChild(el('h4', '', 'The test'));
        test.appendChild(el('p', 'muted ct-pulse', 'Signing in, making the files in a temporary folder, running the script with ACME_DRY_RUN=1…'));
      }
    };
  }

  /* ==========================================================================
     The whole form
     ========================================================================== */
  function form(p, fields, values, secrets, ctx) {
    var ui = p.files_ui || {};
    ctx = ctx || {};
    values = values || {};
    secrets = secrets || {};
    var win = ui.kind === 'windows';
    var node = el('div', 'df');
    var grid = el('div', 'df-grid');
    var main = el('div', 'df-main');
    grid.appendChild(main);
    node.appendChild(grid);
    var preview = null;
    var asked = 0;
    var later = debounce(function () { ask(); }, 450);
    var changed = function () { if (preview) later(); };
    var restFields = fields.filter(function (f) { return OWNED.indexOf(f.key) < 0 && AROUND.indexOf(f.key) < 0; });
    var aroundFields = fields.filter(function (f) { return AROUND.indexOf(f.key) >= 0; }).map(function (f) { return Object.assign({}, f, {advanced: false}); });
    var rest = CT.fieldForm(restFields, values, secrets, {none: false});
    var around = aroundFields.length ? CT.fieldForm(aroundFields, values, secrets, {none: false}) : null;

    /* -- Files -- */
    var fsec = el('section', 'msect df-sect');
    var fh = el('div', 'df-h');
    fh.appendChild(el('h4', '', win ? 'Files besides the machine store' : 'Files on the target'));
    fsec.appendChild(fh);
    fsec.appendChild(el('p', 'msect-lede', win ? 'Optional: the certificate written as files too, in any format - for a program that reads files rather than the store.'
      : 'Which files, in which format, where - a quick layout fills the rows, then change what you like.'));
    var quick = el('div', 'df-quick');
    (ui.layouts || []).forEach(function (l) {
      var b = el('button', 'df-lay', '');
      b.type = 'button';
      b.appendChild(el('b', '', l.title));
      b.appendChild(el('span', '', l.what));
      b.onclick = function () {
        var folder = files.folder() || l.folder;
        files.set(l.outputs.map(function (x) { return folder ? x.replace(/\{dir\}/g, folder) : x.replace(/\{dir\}\//g, ''); }));
        if (l.password && pw) { pw.set(l.password); }
        paintPw();
        changed();
      };
      quick.appendChild(b);
    });
    var presetF = fieldOf(fields, 'preset');
    var presetSel = null;
    if (presetF) {
      var pp = (presetF.options || []).map(function (o) { return [String(o[0]), String(o[1])]; });
      presetSel = selectBox(pp, values.preset || presetF['default'] || 'custom');
      presetSel.className = 'df-preset';
      var pw0 = el('label', 'df-presetw');
      pw0.appendChild(el('span', 'muted small', 'Service'));
      pw0.appendChild(presetSel);
      pw0.title = presetF.help || '';
      quick.appendChild(pw0);
      presetSel.onchange = function () {
        var want = (presetF.fills || {})[presetSel.value];
        if (!want) { changed(); return; }
        Object.keys(want).forEach(function (k) {
          if (k === 'outputs') files.set(lineList(want[k]));
          else if (k === 'jks_alias') { var a = node.querySelector('.df-alias input'); if (a) a.value = want[k]; }
          else if (around && AROUND.indexOf(k) >= 0) around.set(k, want[k]);
          else rest.set(k, want[k]);
        });
        paintPw();
        changed();
      };
    }
    if (MANAGE) fsec.appendChild(quick);
    var files = filesPart(ui, values, ctx, function () { paintPw(); changed(); });
    fsec.appendChild(files.node);
    var pw = passwordPart(values, secrets, fields, changed);
    fsec.appendChild(pw.node);
    var paintPw = function () {
      var fm = files.formats();
      pw.node.hidden = !fm.some(function (f) { return PFX.indexOf(f) >= 0; });
    };
    paintPw();

    /* -- After the files -- */
    var ssec = el('section', 'msect df-sect');
    ssec.appendChild(el('h4', '', 'After the files'));
    ssec.appendChild(el('p', 'msect-lede', win ? 'A PowerShell script run on the server once the certificate is imported and the files written.'
      : 'Restart what reads them: a script already on the machine, or one written here that acme uploads and runs every time - so it is always the current one.'));
    var script = scriptPart(ui, fields, values, ctx, changed);
    ssec.appendChild(script.node);
    if (around) {
      var det = el('details', 'ct-more df-around');
      det.appendChild(el('summary', '', 'Commands around the script'));
      var hint = el('p', 'muted small df-around-l', 'In this order: before writing · the files · test · the script · reload · after. A failing test, script or reload puts the previous files back.');
      det.appendChild(hint);
      det.appendChild(around.node);
      var anyCmd = aroundFields.some(function (f) { var v = values[f.key]; return Array.isArray(v) ? v.length : (v !== undefined && v !== null && String(v).trim() !== ''); });
      if (anyCmd) det.open = true;
      ssec.appendChild(det);
      /* From a template (1.0.72): the application and how it takes the certificate. */
      var tplRow = el('div', 'df-tpl-row');
      var tplB = el('button', 'btn cmd small');
      tplB.type = 'button';
      tplB.innerHTML = iconMarkup('list', 15);
      tplB.appendChild(el('span', '', 'From a template…'));
      tplB.onclick = function () {
        svcTemplates(function (c, title) {
          ['test_cmd', 'reload_cmd', 'post_cmd'].forEach(function (k) { around.set(k, c[k]); });
          det.open = true;
          toast(tr('Filled from the template') + ': ' + title, 'good');
        });
      };
      tplRow.appendChild(tplB);
      tplRow.appendChild(el('span', 'muted small', 'nginx, Apache, HAProxy, Postfix, Dovecot, PostgreSQL… - reload, restart or hard restart'));
      if (aroundFields.some(function (f) { return f.key === 'reload_cmd'; })) ssec.insertBefore(tplRow, det);
    }

    var rsec = null;
    if (restFields.length) {
      rsec = el('section', 'msect df-sect df-rest');
      rsec.appendChild(el('h4', '', win ? 'On the server' : 'The rest'));
      rsec.appendChild(rest.node);
    }
    if (win && rsec) main.appendChild(rsec);
    main.appendChild(fsec);
    main.appendChild(ssec);
    if (!win && rsec) main.appendChild(rsec);

    /* -- Beside them: what it will be -- */
    ctx.interp = script.interp;
    ctx.insert = function (t) { if (script.mode() === 'inline' || node.querySelector('.df-inline:not([hidden])')) script.code._insert(t); };
    ctx.scriptOn = function () { var m = script.mode(); return m === 'path' || m === 'inline'; };
    if (ctx.preview !== false && CT.api) {
      preview = previewPart(ui, ctx);
      grid.appendChild(preview.node);
    }
    var read = function () {
      var o = rest.read();
      if (around) Object.assign(o, around.read());
      if (presetSel) o.preset = presetSel.value;
      o.outputs = files.read();
      pw.read(o);
      script.read(o);
      return o;
    };
    var ask = function () {
      if (!preview || !ctx.target) return;
      var n = ++asked;
      preview.asking();
      var body = {target: ctx.target, options: read()};
      if (ctx.deploy_id) body.id = ctx.deploy_id;
      if (ctx.cert_id) body.cert_id = ctx.cert_id;
      if (ctx.names) body.names = ctx.names;
      if (ctx.key_type) { body.key_type = ctx.key_type; body.key_type_alt = ctx.key_type_alt || ''; }
      CT.api('deploys/preview', body).then(function (d) {
        if (n !== asked) return;
        if (d && d.dual !== undefined) { ctx.dual = !!d.dual; files.dual(ctx.dual); }
        preview.draw(d);
      }).catch(function (e) { if (n === asked) preview.failed(e); });
    };
    node.addEventListener('input', changed);
    node.addEventListener('change', changed);
    setTimeout(ask, 0);
    return {
      node: node,
      read: read,
      set: function (k, v) {
        if (k === 'outputs') { files.set(lineList(v)); return true; }
        if (around && AROUND.indexOf(k) >= 0) return around.set(k, v);
        return rest.set(k, v);
      },
      check: function () {
        return files.check() || script.check() || rest.check() || (around ? around.check() : '');
      },
      /* The test: what the form says now, tried on the target without putting anything in place. */
      test: function (button) {
        var bad = files.check() || script.check();
        if (bad) { toast(bad, 'bad'); return; }
        if (!ctx.cert_id) { toast('choose the certificate', 'bad'); return; }
        busy(button, true);
        if (preview) preview.testBusy();
        var body = {target: ctx.target, cert_id: ctx.cert_id, options: read(), run_script: true};
        if (ctx.deploy_id) body.id = ctx.deploy_id;
        CT.api('deploys/dry_run', body, 600).then(function (d) {
          toast(String((d && d.said) || 'done').split('\n')[0], d && d.ok !== false ? 'good' : 'bad');
          if (preview) preview.test(d);
        }).catch(function (e) {
          toast(String((e && e.message) || e), 'bad');
          if (preview) preview.test(null, e);
        }).then(function () { busy(button, false); });
      },
      /* the daemon's refusal of an option of these (hunt M round 3): its field marked */
      refused: function (words, field, label) { return rest.refused ? rest.refused(words, field, label) : words; },
      refresh: ask
    };
  }

  window.ACME_DEPLOY_UI = {form: form, codeBox: codeBox};
})();
