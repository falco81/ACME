// Hunt R t4 (1.0.126) - the target agents' pages (agents.js) and the policy designer
// (policybuilder.js) in a browser, the API answered here (no daemon):
//
//   node test/hunt_rt4_agentsui_page.js /path/to/web [cs-extra.json]
//
// * the designer of a Windows server's agent with "From discovery": its nav had no Folders and
//   two buttons for the services ("Services", then "Units") - [3] was taken for the units;
// * a design saved from the command line (its text, no state) opened: a test's word with a "="
//   in it (postconf smtpd_tls_cert_file=/x) was taken out of the command line;
// * Save as this agent's design sends the builder's state as design_state - under `state` the
//   API refused it ("state is a piece of text here"): no design was ever saved from the page;
// * the saved design's "0 s ago" a text of its own (in Czech it stayed English);
// * the card's "What its policy allows" of a Windows agent: the machine store, IIS sites,
//   Remote Desktop, roles, read on the key, the Microsoft CA, discovery - it said "Nothing is
//   allowed yet" for a policy of only those; its folders with their readers (not "IIS_IUSRS:"
//   0666);
// * the deployment its policy blocked, on Windows: the lines without sudo.
// Prints one line of JSON: {ok, checks: {name: true|false}, errors, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] && fs.existsSync(process.argv[3]) ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const modalHtml = cut(read('admin/index.php'), '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const LPOL = {files: [{dir: '/srv/certs', owner: 'root', group: 'root', mode: 0o644}], units: {}, tests: [], scripts: [], script_hashes: [], from: [], problems: []};
  const WPOL = {files: [{dir: 'C:\\certs', owner: 'IIS_IUSRS', group: '', mode: 0o666, readers: ['IIS_IUSRS']}], units: {}, tests: [], scripts: [],
    script_hashes: [], from: [], problems: [], store: true, iis: ['Default Web Site'], rdp: true, roles: {sql: [], ccs: ['\\\\fs\\ccs']},
    key_read: ['NT SERVICE\\MyService'], adcs: [{ca: 'ca01.corp.example\\Corp CA', templates: ['WebServer']}], adcs_read: true, discover: ['*']};
  const LONE = {id: 1, name: 'web1', kind: 'agent', platform: 'linux', mode: 'passive', state: 'answers', joined: true, agent_id: 'ag-1', host: 'web1.example.com',
    version: '1.0.126', last_seen: now - 12, cert_end: now + 25 * 86400, policy: LPOL, policy_at: now, pending: null};
  const WONE = Object.assign({}, LONE, {id: 2, name: 'win1', kind: 'agent_windows', platform: 'windows', policy: WPOL});
  const LFACTS = {platform: 'linux', protected: ['/etc/sudoers.d'], parts: ['.ssh'], own: ['/etc/acme-agent'], verbs: ['reload', 'restart'], shells: ['sh', 'bash'],
    config_ok: ['/etc/ssl'], head: '# acme-agent policy\n', discover_kinds: ['nginx', 'apache'],
    limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const WFACTS = {platform: 'windows', roles: [['sql', 'SQL Server', null], ['ccs', 'IIS Central Certificate Store', 'path']], protected: ['C:\\Windows'], parts: ['.ssh'],
    own: ['C:\\ProgramData\\acme-agent'], verbs: ['restart', 'try-restart', 'start'], shells: ['cmd', 'powershell'], exec_ext: ['.exe'], config_ok: [],
    head: '# acme-agent policy (Windows)\n', discover_kinds: ['iis', 'rdp', 'store'], limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const DISC = {at: now - 60, found: [{kind: 'iis', title: 'IIS site', site: 'Default Web Site', items: [{kind: 'store'}, {kind: 'iis', site: 'Default Web Site'}]}], certs: []};
  const fold = (s) => String(s).replace(/\s+/g, ' ').trim();
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const build = (lang) => {
    let pack = 'null';
    if (lang === 'cs') {
      const all = JSON.parse(read('lang/cs.json'));
      const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
      for (const part of ['strings', 'patterns', 'rich']) {
        for (const e of Object.values(all[part] || {})) {
          if (!e || !e.source || !e.text || e.text === e.source) continue;
          if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
        }
      }
      for (const k of Object.keys(extra)) { if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k]; }
      pack = JSON.stringify(pk).replace(/</g, '\\u003c');
    }
    return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
      + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
      + '<style>' + read('assets/policybuilder.css') + '</style>'
      + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="host"></div></main>' + modalHtml
      + '<div class="toast" id="toast"></div>'
      + '<script>' + esc(read('assets/i18n.js')) + '</script>'
      + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
      + ' var LONE = ' + JSON.stringify(LONE) + '; var WONE = ' + JSON.stringify(WONE) + '; var LFACTS = ' + JSON.stringify(LFACTS) + ';'
      + ' var WFACTS = ' + JSON.stringify(WFACTS) + '; var DISC = ' + JSON.stringify(DISC) + ';</script>'
      + '<script>' + esc(read('assets/core.js')) + '</script>'
      + '<script>' + esc(read('assets/agents.js')) + '</script>'
      + '<script>' + esc(read('assets/policybuilder.js')) + '</script>'
      + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
      + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
      + ' if (what.indexOf("agents/builder?id=2") === 0) return c({agent: WONE, facts: WFACTS, templates: [], needs: [], acme_from: [], design: null, discovered: DISC});'
      + ' if (what.indexOf("agents/builder") === 0) return c({agent: LONE, facts: LFACTS, templates: [], needs: [], acme_from: [], design: null});'
      + ' if (what === "agents/design") { if (body.state !== undefined && typeof body.state === "object") return Promise.reject(new Error("state is a piece of text here"));'
      + '   return c({design: {n: 1, at: Date.now() / 1000, by: "tester", title: body.title, text: body.text, state: body.design_state, compare: {state: "unknown", added: [], removed: []}, history: []}}); }'
      + ' return c({}); }, over: function (open) { open(); }});</script>'
      + '</body></html>';
  };
  const pres = (page) => page.evaluate(() => Array.from(document.querySelectorAll('#modal pre')).map((p) => p.textContent).join('\n'));
  try {
    for (const lang of ['en', 'cs']) {
      const tag = lang + '_';
      const page = await browser.newPage({viewport: {width: 1400, height: 1000}});
      page.on('pageerror', (e) => out.errors.push(lang + ': ' + String(e)));
      await page.setContent(build(lang));
      await page.waitForTimeout(150);
      // ---- the Windows designer with "From discovery": Folders there, Services once, no Units
      await page.evaluate(() => ACME_POLICY_BUILDER.open({id: 2, name: 'win1', kind: 'agent_windows'}));
      await page.waitForTimeout(400);
      const nav = await page.evaluate(() => Array.from(document.querySelectorAll('.pb-nav-b')).map((b) => b.querySelector('span:not(.pb-nav-n):not(.ag-ic)').textContent.trim()));
      const ids = await page.evaluate(() => Array.from(document.querySelectorAll('.pb-sec')).map((s) => s.id));
      const W = await page.evaluate(() => { var t = function (w) { return (typeof i18nText === 'function' && i18nText(w)) || w; };
        return {f: t('Folders'), s: t('Services'), u: t('Units'), d: t('From discovery'), m: t('Machine store')}; });
      out.checks[tag + 'win_nav'] = nav.filter((x) => x === W.f).length === 1 && nav.filter((x) => x === W.s).length === 1 && nav.indexOf(W.u) < 0
        && nav.indexOf(W.d) === 2 && nav.indexOf(W.f) === 3 && nav.indexOf(W.s) === 4 && nav.indexOf(W.m) === 5;
      out.checks[tag + 'win_nav_all'] = nav.length === ids.length;
      await page.evaluate(() => closeModal(true));
      await page.waitForTimeout(100);
      // ---- a design's text opened: a test's word with "=" stays in the command line
      await page.evaluate(() => ACME_POLICY_BUILDER.open({id: 1, name: 'web1'}, {text: '# x\nallow test -- postconf -c /etc/postfix smtpd_tls_cert_file=/x\nallow file /srv/c owner=root:root mode=0640\n'}));
      await page.waitForTimeout(400);
      out.checks[tag + 'text_test_kv'] = /allow test -- postconf -c \/etc\/postfix smtpd_tls_cert_file=\/x/.test(await pres(page));
      await page.evaluate(() => closeModal(true));
      await page.evaluate(() => ACME_POLICY_BUILDER.open({id: 2, name: 'win1', kind: 'agent_windows'}, {text: 'allow test -- C:\\x.exe a=b\nallow store\nallow file C:\\certs readers=IIS_IUSRS\n'}));
      await page.waitForTimeout(400);
      out.checks[tag + 'text_test_kv_win'] = /allow test -- C:\\x\.exe a=b/.test(await pres(page));
      // a folder's readers said in the page's language (in Czech it stayed English)
      out.checks[tag + 'win_readers_said'] = await page.evaluate((lang) => { var t = document.getElementById('pb-s-files').textContent;
        return /IIS_IUSRS/.test(t) && (lang === 'en' ? /read by SYSTEM, the Administrators and IIS_IUSRS/.test(t) : !/read by SYSTEM/.test(t)); }, lang);
      await page.evaluate(() => closeModal(true));
      await page.waitForTimeout(100);
      // ---- what the designer says of a Windows policy, in the page's language (Czech: each
      // of these stayed English)
      out.checks[tag + 'win_words'] = await page.evaluate((lang) => {
        var K = ACME_POLICY_CORE; K.setFacts(WFACTS);
        var s = K.empty();
        s.files = [{dir: 'C:\\Windows\\x', readers: []}, {dir: '\\\\srv\\share', readers: []}, {dir: 'C:\\a.', readers: []}, {dir: 'C:\\b', readers: ['a"b']},
          {dir: 'C:\\PROGRA~1', readers: []}, {dir: 'C:\\c\\x.exe', readers: []}, {dir: 'C:\\a|b', readers: []}];
        s.tests = [['x.bat'], ['powershell', '-c', 'x']];
        s.iis = ['shop', 'shop']; s.key_read = ['a', 'a']; s.roles = [{role: 'sql', extra: 'C:\\x'}, {role: 'nope', extra: ''}];
        s.scripts = [{path: 'C:\\x.exe', sha256: ''}, {path: 'C:\\s\\y.ps1', sha256: ''}];
        s.units = [{name: 'a b', verbs: ['restart']}];
        var R = K.check(s), words = [];
        ['files', 'tests', 'iis', 'key_read', 'roles', 'scripts', 'units'].forEach(function (k) { R[k].forEach(function (v) { v.msgs.forEach(function (m) { words.push(m.words); }); }); });
        K.setFacts(LFACTS);
        var miss = words.filter(function (w) { return i18nText(w) === null; });
        window.MISS = miss;
        return words.length >= 14 && (lang === 'en' || !miss.length);
      }, lang);
      if (!out.checks[tag + 'win_words']) out.missing = await page.evaluate(() => window.MISS);
      // ---- Save: the state as design_state, saved; its time a text of its own
      await page.evaluate(() => { SENT.length = 0; ACME_POLICY_BUILDER.open({id: 1, name: 'web1'}); });
      await page.waitForTimeout(400);
      await page.evaluate(() => { document.querySelector('.pb-title').value = 'one'; document.querySelector('.pb-title').dispatchEvent(new Event('input')); document.querySelector('.pb-save .btnrow .btn').click(); });
      await page.waitForTimeout(400);
      out.checks[tag + 'save_sent'] = await page.evaluate(() => {
        var s = SENT.filter((x) => x[0] === 'agents/design')[0];
        return !!s && s[1].state === undefined && !!s[1].design_state && Array.isArray(s[1].design_state.files) && s[1].design_state.files[0].dir === '/srv/certs';
      });
      out.checks[tag + 'saved'] = await page.evaluate(() => /v1/.test(document.querySelector('.pb-save-st').textContent));
      const st = fold(await page.evaluate(() => document.querySelector('.pb-save-st').textContent));
      out.checks[tag + 'saved_ago'] = lang === 'en' ? / s ago · tester/.test(st) : !/ago/.test(st);
      await page.evaluate(() => closeModal(true));
      await page.waitForTimeout(100);
      // ---- the card's policy of a Windows agent
      await page.evaluate(() => { var h = document.getElementById('host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.policyView(WONE.policy, Date.now() / 1000)); });
      await page.waitForTimeout(150);
      const pv = await page.evaluate(() => ({groups: document.querySelectorAll('#host .ag-pol-g').length, none: !!document.querySelector('#host .ag-pol-none'),
        text: document.getElementById('host').textContent}));
      out.checks[tag + 'win_policy'] = pv.groups === 8 && !pv.none && pv.text.indexOf('Cert:\\LocalMachine\\My') >= 0 && pv.text.indexOf('Default Web Site') >= 0
        && pv.text.indexOf('ca01.corp.example\\Corp CA') >= 0 && pv.text.indexOf('NT SERVICE\\MyService') >= 0 && pv.text.indexOf('\\\\fs\\ccs') >= 0
        && pv.text.indexOf('IIS_IUSRS:') < 0 && pv.text.indexOf('0666') < 0 && pv.text.indexOf('IIS_IUSRS') >= 0;
      // ...only these: not "nothing is allowed"
      await page.evaluate(() => { var h = document.getElementById('host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.policyView(Object.assign({}, WONE.policy, {files: [], iis: [], rdp: false, roles: {}, key_read: [], adcs: [], adcs_read: false}), 0)); });
      out.checks[tag + 'win_policy_store_only'] = await page.evaluate(() => document.querySelectorAll('#host .ag-pol-g').length === 2 && !document.querySelector('#host .ag-pol-none'));
      // a Linux one as before, its discovery said
      await page.evaluate(() => { var h = document.getElementById('host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.policyView(Object.assign({}, LONE.policy, {discover: ['nginx']}), 0)); });
      out.checks[tag + 'linux_policy'] = await page.evaluate(() => document.querySelectorAll('#host .ag-pol-g').length === 2
        && /root:root/.test(document.getElementById('host').textContent) && /0644/.test(document.getElementById('host').textContent)
        && /nginx/.test(document.getElementById('host').textContent));
      // ---- the deployment its policy blocked: sudo on Linux only
      const blocked = await page.evaluate(() => {
        var b = {at: Date.now() / 1000, what: 'x', allow: ['acme-agent allow store']};
        var w = ACME_AGENTS.blockedBox({platform: 'windows', kind: 'agent_windows', blocked: b}).querySelector('pre').textContent;
        var l = ACME_AGENTS.blockedBox({platform: 'linux', kind: 'agent', blocked: {at: 0, what: 'x', allow: ['acme-agent allow unit nginx.service reload']}}).querySelector('pre').textContent;
        return [w, l];
      });
      out.checks[tag + 'blocked_win'] = blocked[0] === 'acme-agent allow store' && blocked[1] === 'sudo acme-agent allow unit nginx.service reload';
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
