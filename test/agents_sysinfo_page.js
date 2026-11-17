// What the agent tells about its server (1.0.120, agents.js) in a page of its own, the API answered
// here (no daemon): the agent's card "The server", the line on each tile of Settings → Target
// agents and the Servers overview there.
//
//   node test/agents_sysinfo_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// cs-extra.json: {English: Czech}, added to web/lang/cs.json for the Czech pages.
//
// In English and in Czech, at 1400 and 390 px:
// * the card of a Linux agent (Rocky): the system large (its mark green), version and kernel, the
//   host, FQDN, domain and its addresses as chips, the CPU and its load, a memory bar, a bar per
//   disk (green; amber over 85 %, red over 95 %), the uptime and the start, the time zone and the
//   clock pill (green), SELinux, no restart pending, its services (running green, installed grey),
//   Python and OpenSSL; "Ask it now" asks it (POST agents/look);
// * the card of a Windows agent: Windows' mark, version and build, the AD domain, the roles
//   (IIS running, WinRM with its HTTPS listener), the clock far off (red), a restart pending, a
//   disk 97 % full (red);
// * an agent too old to tell: "update it"; one that has not said it yet: "Not said yet";
// * the tiles: each joined agent's system in a line, the uptime, the clock off and a full disk
//   flagged; the Servers overview: a row per server that told, sorted by a click on a heading,
//   filtered by platform;
// * nothing wider than the page or its card; no error in the console; in Czech nothing of it left
//   in English.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const shots = process.argv[4] || '';
  if (shots) fs.mkdirSync(shots, {recursive: true});
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const index = read('admin/index.php');
  const modalHtml = cut(index, '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const GB = 1024 * 1024 * 1024;
  const POL = {hash: 'ab'.repeat(32), files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}],
    units: {'nginx.service': ['reload']}, tests: [['nginx', '-t']], scripts: [], script_hashes: [], from: [], problems: []};
  const LINUX = {platform: 'linux', os: 'Rocky Linux 9.4 (Blue Onyx)', os_id: 'rocky', os_version: '9.4', os_like: 'rhel centos fedora',
    kernel: '5.14.0-427.22.1.el9_4.x86_64', arch: 'x86_64', machine: 'VMware, Inc. VMware7,1', hostname: 'web1',
    fqdn: 'web1.example.com', domain: 'example.com',
    addrs: [{if: 'ens192', ip: '10.20.30.41/24'}, {if: 'ens224', ip: '192.0.2.41/26'}, {if: 'ens192', ip: '2001:db8:20::41/64'}],
    cpu: 'Intel(R) Xeon(R) Gold 6338 CPU @ 2.00GHz', cores: 4, mem_total: 16 * GB, mem_avail: 9.2 * GB, load: [0.42, 0.37, 0.31],
    disks: [{path: '/', size: 50 * GB, free: 31 * GB, fs: 'xfs', used_pct: 38}, {path: '/etc', size: 50 * GB, free: 31 * GB, fs: 'xfs', used_pct: 38},
      {path: '/srv', size: 200 * GB, free: 26 * GB, fs: 'xfs', used_pct: 87}],
    boot: now - 86400 * 41 - 3600 * 5, tz: 'Europe/Prague', tz_offset: 60, selinux: 'enforcing', init: 'systemd', reboot: false,
    services: [{name: 'nginx', state: 'active'}, {name: 'postfix', state: 'active'}, {name: 'haproxy', state: 'present'}, {name: 'dovecot', state: 'active'}],
    python: '3.9.18', openssl: 'OpenSSL 3.0.7 1 Nov 2022', openssl_cli: 'OpenSSL 3.0.7 1 Nov 2022 (Library: OpenSSL 3.0.7 1 Nov 2022)',
    clock: now - 30, hash: 'cd'.repeat(32)};
  LINUX.disks.splice(1, 1);
  const UBUNTU = Object.assign({}, LINUX, {os: 'Ubuntu 24.04.1 LTS', os_id: 'ubuntu', os_version: '24.04', kernel: '6.8.0-45-generic', selinux: undefined,
    apparmor: true, hostname: 'mx1', fqdn: 'mx1.example.com', reboot: true, reboot_why: 'reboot-required (linux-image-6.8.0-48-generic)',
    disks: [{path: '/', size: 80 * GB, free: 7 * GB, fs: 'ext4', used_pct: 91.3}], boot: now - 86400 * 3,
    services: [{name: 'postfix', state: 'active'}, {name: 'dovecot', state: 'active'}]});
  const WIN = {platform: 'windows', os: 'Windows Server 2022 Standard', os_id: 'windows', os_version: '21H2', edition: 'ServerStandard',
    build: '10.0.20348.2340', kernel: '10.0.20348.2340', install: 'Server', arch: 'AMD64', machine: 'Microsoft Corporation Virtual Machine',
    hostname: 'IIS01', fqdn: 'IIS01.corp.example.com', domain: 'corp.example.com', ad_domain: 'CORP',
    addrs: [{if: '', ip: '10.20.40.12'}], cpu: 'AMD EPYC 7763 64-Core Processor', cores: 8, mem_total: 32 * GB, mem_avail: 1.4 * GB,
    disks: [{path: 'C:\\', size: 127 * GB, free: 3.8 * GB, used_pct: 97}, {path: 'D:\\', size: 500 * GB, free: 410 * GB, used_pct: 18}],
    boot: now - 86400 * 12, tz: 'Central Europe Standard Time', tz_offset: 60, reboot: true, reboot_why: 'Windows Update; files to rename at the restart',
    services: [{name: 'IIS', state: 'active'}, {name: 'AD CS', state: 'present'}, {name: 'RD Gateway', state: 'active'},
      {name: 'WinRM', state: 'active', detail: 'HTTPS listener'}, {name: 'SQL Server', state: 'active', detail: 'SQLEXPRESS'}],
    python: '3.12.7', openssl: 'OpenSSL 3.0.15 3 Sep 2024', clock: now - 200, hash: 'ef'.repeat(32)};
  const sys = (facts, skew, at) => ({state: 'ok', at: at, facts: facts, skew: skew, skew_at: at,
    skew_level: Math.abs(skew) > 120 ? 'bad' : (Math.abs(skew) > 60 ? 'warn' : 'ok'),
    uptime: Math.round(now - facts.boot), warnings: []});
  const row = (o) => Object.assign({mode: 'passive', state: 'answers', joined: true, version: '1.0.121', code_hash: 'c0de', last_seen: now - 12,
    cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 0, from: 0, problems: 0}}, o);
  const VIEW = {active: false, port: 8444, endpoints: [], node: 'acme1', nginx: null, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.121.tar.gz', version: '1.0.121', sha256: 'e3'.repeat(32), size: 41234, signed: true},
    commands: ['sha256sum acme-agent-1.0.121.tar.gz'],
    rows: [
      row({id: 1, name: 'web1', host: 'web1.example.com', agent_host: 'web1', os: LINUX.os, system: sys(LINUX, 0.4, now - 40)}),
      row({id: 2, name: 'mail-gw', mode: 'active', host: '', agent_host: 'mx1', os: UBUNTU.os, system: sys(UBUNTU, 74.2, now - 300)}),
      row({id: 3, name: 'iis-shop', platform: 'windows', kind: 'agent_windows', host: 'iis01.corp.example.com', agent_host: 'IIS01', os: 'Windows Server 2022 Standard (10.0.20348)',
           system: sys(WIN, -186.5, now - 90)}),
      row({id: 4, name: 'old-box', host: 'old.example.com', agent_host: 'old', version: '1.0.118', system: {state: 'old', facts: null, skew: null, warnings: []}}),
      {id: 5, name: 'new-box', mode: 'passive', state: 'joining', host: '10.1.2.3', version: '', joined: false, last_seen: null, cert_end: null, policy_summary: null, system: null}]};
  const one = (r) => Object.assign({}, r, {agent_id: 'ag-1234567890abcdef', shipped_code: 'c0de', key_fp: '3f'.repeat(32),
    policy: POL, policy_at: now - 10, pending: null, package: VIEW.package, commands: VIEW.commands, ca: VIEW.ca, port: 8444});
  const ONES = {1: one(VIEW.rows[0]), 3: one(VIEW.rows[2]), 4: one(VIEW.rows[3]),
    6: one(row({id: 6, name: 'quiet-one', host: 'q.example.com', agent_host: 'q', system: {state: 'unknown', facts: null, skew: null, warnings: []}}))};
  // the Czech words checked only where they are (web/lang/cs.json, or the file of them given)
  const MARK = 'The server’s clock against acme’s: in time.';
  const hasCs = !!extra[MARK] || read('lang/cs.json').indexOf(JSON.stringify(MARK).slice(1, -1)) >= 0;
  const EN = ['The server', 'Memory', 'Uptime', 'Processor', 'Services', 'Roles', 'restart pending', 'clock in time', 'clock far off',
    'free of', 'Ask it now', 'AD domain', 'Servers', 'The agent is too old to tell', 'Not said yet', 'disk full', 'No restart', 'started', 'Target'];
  try {
    for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 390], ['cs', 390]]) {
      let pack = 'null';
      if (lang === 'cs') {
        const all = JSON.parse(read('lang/cs.json'));
        const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
        for (const part of ['strings', 'patterns', 'rich']) {
          for (const e of Object.values(all[part] || {})) {
            if (!e || !e.source || !e.text) continue;
            if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
          }
        }
        for (const k of Object.keys(extra)) {
          if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k];
        }
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
        + '<style>' + read('assets/policybuilder.css') + '</style>'
        + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div></main>' + modalHtml
        + '<div class="toast" id="toast"></div>'
        + '<script>' + esc(read('assets/i18n.js')) + '</script>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
        + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONES = ' + JSON.stringify(ONES) + ';</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>' + esc(read('assets/agents.js')) + '</script>'
        + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
        + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
        + ' if (what === "agents") return c(VIEW);'
        + ' if (what.indexOf("agents/one") === 0) return c(ONES[decodeURIComponent(what.split("id=")[1])]);'
        + ' if (what === "agents/look") return c({agent: ONES[body.id]});'
        + ' if (what.indexOf("agents/design") === 0) return c({design: null});'
        + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; }, newCert: function () {}});</script>'
        + '</body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 2});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      page.on('console', (m) => { if (m.type() === 'error') out.errors.push(lang + width + ' console: ' + m.text()); });
      await page.setContent(html);
      await page.waitForTimeout(150);
      const tag = lang + width + '_';
      const fits = (sel) => page.evaluate((s) => {
        if (document.documentElement.scrollWidth > window.innerWidth + 1) return false;
        var box = document.querySelector(s);
        if (!box) return false;
        var r = box.getBoundingClientRect();
        return Array.prototype.every.call(box.querySelectorAll('*'), function (n) {
          var q = n.getBoundingClientRect();
          if (!q.width) return true;
          var ok = q.right <= r.right + 1 && q.left >= r.left - 1;
          if (!ok) window.WIDE = (window.WIDE || []).concat([n.className + ' ' + Math.round(q.right) + '>' + Math.round(r.right) + ' ' + (n.textContent || '').slice(0, 30)]);
          return ok;
        });
      }, sel);
      const english = (sel) => page.evaluate(([s, words]) => {
        var box = document.querySelector(s), t = '';
        if (box) {
          var w = document.createTreeWalker(box, NodeFilter.SHOW_TEXT);
          while (w.nextNode()) if (!w.currentNode.parentNode.closest('[data-no-i18n]')) t += w.currentNode.nodeValue + '\n';
        }
        return words.filter(function (w) { return t.indexOf(w) >= 0; });
      }, [sel, EN]);
      const card = async (id) => {
        await page.evaluate((i) => { var h = document.getElementById('card-host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.card({id: i, name: ONES[i].name, kind: ONES[i].kind})); }, id);
        await page.waitForTimeout(250);
      };
      // ---- the Linux agent's card
      await card(1);
      out.checks[tag + 'linux_card'] = await page.evaluate(() => {
        var s = document.querySelector('#card-host .ag-sys');
        return !!s && !!s.querySelector('.ag-sys-mark.d-green') && s.querySelector('.ag-sys-osn').textContent === 'Rocky Linux 9.4 (Blue Onyx)'
          && s.querySelectorAll('.ag-sys-ip').length === 3 && s.querySelectorAll('.ag-sys-disk').length === 2
          && s.querySelectorAll('.ag-sys-bar').length === 3 && !!s.querySelector('.ag-sys-disk .ag-sys-bar.warn') && !!s.querySelector('.ag-sys-disk .ag-sys-bar.ok')
          && s.querySelectorAll('.ag-sys-svc.on').length === 3 && s.querySelectorAll('.ag-sys-svc.off').length === 1
          && !!s.querySelector('.ag-sys-pills .ag-sys-pill.ok') && !s.querySelector('.ag-sys-pill.bad') && !s.querySelector('.ag-sys-pill.warn')
          && /x86_64/.test(s.querySelector('.ag-sys-sub').textContent) && !!s.querySelector('.ag-sys-load')
          && /3\.9\.18/.test(s.querySelector('.ag-sys-rt').textContent)
          && document.querySelectorAll('#card-host .ag-acts .btn').length === 5;
      });
      out.checks[tag + 'linux_card_fits'] = await fits('#card-host .ag-card');
      if (lang === 'cs' && hasCs) out.checks[tag + 'linux_card_czech'] = (await english('#card-host .ag-sys')).length === 0 || (out.errors.push(tag + 'english: ' + (await english('#card-host .ag-sys')).join(', ')), false);
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'card-linux-' + lang + width + '.png')});
      if (shots) await page.locator('#card-host .ag-sys').screenshot({path: path.join(shots, 'panel-linux-' + lang + width + '.png')});
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#card-host .ag-sys-ask').click(); });
      await page.waitForTimeout(250);
      out.checks[tag + 'ask_it_now'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/look' && x[1].id === 1; })
        && !!document.querySelector('#card-host .ag-sys'));
      // ---- the Windows agent's card
      await card(3);
      out.checks[tag + 'windows_card'] = await page.evaluate(() => {
        var s = document.querySelector('#card-host .ag-sys');
        return !!s && !!s.querySelector('.ag-sys-mark.d-win') && /20348\.2340/.test(s.querySelector('.ag-sys-sub').textContent)
          && /CORP/.test(s.textContent) && !!s.querySelector('.ag-sys-pill.bad') && !!s.querySelector('.ag-sys-pills .ag-sys-pill.warn')
          && !!s.querySelector('.ag-sys-disk .ag-sys-bar.bad') && s.querySelectorAll('.ag-sys-svc').length === 5
          && /HTTPS listener/.test(s.querySelector('.ag-sys-svcs').textContent) && /−187/.test(s.textContent);
      });
      out.checks[tag + 'windows_card_fits'] = await fits('#card-host .ag-card');
      if (lang === 'cs' && hasCs) { const left = await english('#card-host .ag-sys'); out.checks[tag + 'windows_card_czech'] = left.length === 0; if (left.length) out.errors.push(tag + 'english: ' + left.join(', ')); }
      if (shots) await page.locator('#card-host .ag-sys').screenshot({path: path.join(shots, 'panel-windows-' + lang + width + '.png')});
      // ---- too old, not said yet
      await card(4);
      out.checks[tag + 'old_agent'] = await page.evaluate(() => !!document.querySelector('#card-host .ag-sys-none.old') && !document.querySelector('#card-host .ag-sys-hero'));
      if (shots) await page.locator('#card-host .ag-sys').screenshot({path: path.join(shots, 'panel-old-' + lang + width + '.png')});
      await card(6);
      out.checks[tag + 'not_said'] = await page.evaluate(() => !!document.querySelector('#card-host .ag-sys-none:not(.old)') && !!document.querySelector('#card-host .ag-sys-ask'));
      if (lang === 'cs' && hasCs) out.checks[tag + 'none_czech'] = (await english('#card-host .ag-sys')).length === 0;
      await page.evaluate(() => { document.getElementById('card-host').innerHTML = ''; });
      // ---- the pane: the tiles' lines, the Servers overview
      await page.evaluate(() => ACME_AGENTS.pane());
      await page.waitForTimeout(250);
      out.checks[tag + 'tiles'] = await page.evaluate(() => {
        var t = document.querySelectorAll('#ag-list .ag-tile');
        if (t.length !== 5) return false;
        return !!t[0].querySelector('.ag-sys-tl .ag-sys-tos.d-green') && t[0].querySelectorAll('.ag-sys-tl .ag-sys-pill').length === 1
          && !!t[0].querySelector('.ag-sys-tl .ag-sys-pill.warn')
          && !!t[1].querySelector('.ag-sys-tl .ag-sys-pill.warn') && t[1].querySelectorAll('.ag-sys-tl .ag-sys-pill').length === 3
          && !!t[2].querySelector('.ag-sys-tos.d-win') && t[2].querySelectorAll('.ag-sys-tl .ag-sys-pill.bad').length === 2
          && !!t[3].querySelector('.ag-sys-tl .ag-sys-pill.dim') && !t[4].querySelector('.ag-sys-tl')
          && !!t[0].querySelector('.ag-sys-tup') && !!t[2].querySelector('.ag-sys-tup');
      });
      out.checks[tag + 'servers'] = await page.evaluate(() => {
        var s = document.querySelector('#ag-list .ag-srv');
        return !!s && s.querySelectorAll('tbody tr').length === 3 && s.querySelectorAll('thead th').length === 8
          && s.querySelectorAll('tbody .ag-sys-bar').length === 6;
      });
      out.checks[tag + 'servers_sort'] = await page.evaluate(() => {
        var names = function () { return Array.prototype.map.call(document.querySelectorAll('#ag-list .ag-srv tbody .ag-srv-name'), function (b) { return b.textContent; }).join(','); };
        var first = names() === 'iis-shop,mail-gw,web1';
        document.querySelector('#ag-list .ag-srv th.c-up .ag-srv-sort').click();       // the longest up first
        var up = names() === 'web1,iis-shop,mail-gw';
        document.querySelector('#ag-list .ag-srv th.c-skew .ag-srv-sort').click();     // the farthest clock first
        var sk = names() === 'iis-shop,mail-gw,web1';
        document.querySelector('#ag-list .ag-srv th.c-skew .ag-srv-sort').click();
        var back = names() === 'web1,mail-gw,iis-shop';
        document.querySelector('#ag-list .ag-srv th.c-name .ag-srv-sort').click();
        return first && up && sk && back && names() === 'iis-shop,mail-gw,web1';
      });
      out.checks[tag + 'servers_filter'] = await page.evaluate(() => {
        var seg = document.querySelector('#ag-list .ag-srv-seg');
        seg.querySelector('[data-f="windows"]').click();
        var w = document.querySelectorAll('#ag-list .ag-srv tbody .ag-srv-name').length === 1;
        seg.querySelector('[data-f="linux"]').click();
        var l = document.querySelectorAll('#ag-list .ag-srv tbody .ag-srv-name').length === 2;
        seg.querySelector('[data-f="all"]').click();
        document.querySelector('#ag-list .ag-srv tbody .ag-srv-name').click();
        return w && l && document.querySelectorAll('#ag-list .ag-srv tbody .ag-srv-name').length === 3 && window.OPENED === 'iis-shop';
      });
      out.checks[tag + 'pane_fits'] = await fits('#ag-list');
      if (!out.checks[tag + 'pane_fits']) out.errors.push(tag + 'wide: ' + JSON.stringify(await page.evaluate(() => (window.WIDE || []).slice(0, 4))));
      if (lang === 'cs' && hasCs) out.checks[tag + 'pane_czech'] = (await english('#ag-list .ag-srv')).length === 0 && (await english('#ag-list .ag-grid')).filter(function (w) { return w !== 'Target'; }).length === 0;
      if (shots) {
        await page.locator('#ag-list .ag-grid').scrollIntoViewIfNeeded();
        await page.waitForTimeout(400);
        await page.locator('#ag-list .ag-grid').screenshot({path: path.join(shots, 'tiles-' + lang + width + '.png')});
        await page.locator('#ag-list .ag-srv').screenshot({path: path.join(shots, 'servers-' + lang + width + '.png')});
      }
      await page.close();
    }
  } catch (e) {
    out.error = String((e && e.stack) || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
