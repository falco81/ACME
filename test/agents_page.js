// Target agents in the administration pages (agents.js, 1.0.116) - the pane Settings → Target
// agents, the agent's card on a target, its join wizard, and what a deployment needs of the
// agent's policy, drawn in a page of their own with the API answered here (no daemon).
//
//   node test/agents_page.js /path/to/web [cs-extra.json] [screenshot-folder]
//
// cs-extra.json: {English: Czech}, added to web/lang/cs.json for the Czech pages.
//
// In English and in Czech, at 1400 and 420 px:
// * the pane, active mode off: the hero says so, no endpoints; the package tile (name, version,
//   size, the badge, the SHA-256), the four install lines each with Copy; the authority's
//   fingerprint in groups; the tiles of the agents (state, mode, version, last heard, the end of
//   the certificate amber under 14 days, the policy's chips);
// * active mode on: the port and what the agents are given;
// * the card of a joined agent: its state, its policy (folders, units, tests, scripts), Join
//   again / Ask it now / Renew / Forget; an agent waiting to be confirmed: its fingerprint in
//   sixteen groups and "It is the same - confirm" (POST agents/confirm with that fingerprint);
// * the wizard: three steps on the rail, Make the join code (POST agents/code), the code and the
//   command with Copy, then the fingerprint to confirm;
// * a deployment's needs: allowed (green), needed (red, with the sudo line to copy), unknown;
// * phases 3 and 4: the card with a newer agent offered (Update the agent, where its policy allows
//   it - POST agents/update; else the line that allows it), the deployment its policy blocked,
//   the keys made on the server (Make a certificate with its key made here), the policy's tests,
//   connections and updates; the tiles' flags; a deployment's needs whose key is made there;
//   What happens (runplan.js) with each item of the agent's job judged by its policy;
// * 1.0.118, the policy builder (policybuilder.js): opened from the card ("Design its policy…"),
//   it starts from the agent's policy - the policy file in the agent's own words exactly; a
//   template adds its set (Postfix: its folder, its tests); a folder under a protected place is
//   red with the agent's words and left out of the file, one above them amber; a shell's -c
//   amber; what the deployments need added with one click (Add all); the one block to paste
//   (acme-agent policy apply - <<'EOF'), Copy, what changes against the server; Save as this
//   agent's design (POST agents/design with the very text); the card's saved design (matches /
//   differs with its lines, Open in the builder, Copy, Download, Delete…); the newer agent
//   updated now (asked first) and Update all agents… (who will be, who not and why);
// * nothing wider than the page; in Czech nothing of it left in English that has a translation.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const extra = process.argv[3] ? JSON.parse(fs.readFileSync(process.argv[3], 'utf-8')) : {};
  const shots = process.argv[4] || '';
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const ui = read('admin/certs-ui.php');
  const cut = (text, from, to) => { const i = text.indexOf(from); return text.slice(i, text.indexOf(to, i)); };
  const paneHtml = cut(ui, '<div class="ctl-pane" id="pane-agents"', '<div class="ctl-pane" id="pane-dnssrv"')
    .replace('class="ctl-pane" id="pane-agents" hidden', 'class="ctl-pane" id="pane-agents"');
  const index = read('admin/index.php');
  const modalHtml = cut(index, '<div class="modal" id="modal" hidden>', '<div class="toast" id="toast">');
  const fold = (s) => String(s).replace(/\s+/g, ' ').trim();
  const WORDS = ['acme proposes, the server decides', 'active mode off', 'The agent to install', 'Download', 'Copy',
    'acme’s agent authority', 'Targets with an agent', 'Last heard', 'Its certificate ends', 'Server', 'Agent',
    'answers', 'not heard from', 'passive', 'active', 'What its policy allows', 'Folders', 'Units', 'Tests and commands',
    'Join again…', 'Ask it now', 'Renew its certificate', 'Forget…', 'An agent asks to join', 'It is the same - confirm',
    'Install the agent', 'The join code', 'Confirm the fingerprint', 'Make the join code', 'The agent’s policy',
    'needs more on the server', 'Copy all the lines', 'On the server, as root', 'signed by acme’s release key',
    'A newer agent is offered', 'Update the agent', 'Its policy blocked the last deployment', 'Keys made on this server',
    'Make a certificate with its key made here', 'Tests from here', 'Connections for acme', 'Updates from acme',
    'newer agent offered', 'its policy blocks a deployment', 'allowed by the agent’s policy',
    'not allowed by the agent’s policy - the agent refuses the job', 'the agent cannot do it this way', 'nothing to judge yet'];
  const BWORDS = ['Design its policy…', 'acme proposes, the server decides', 'Start from', 'Templates', 'What the deployments need',
    'Folders', 'Units', 'Tests and commands', 'Scripts', 'Script hashes', 'Allow from', 'Tests from here', 'Connections for acme',
    'Updates from acme', 'Limits', 'On the server, as root', 'The policy file', 'As allow lines', 'One block to paste', 'What changes',
    'Download policy file', 'The design, kept in acme', 'Save as this agent’s design', 'Add all that the deployments need', 'Add a folder',
    'others', 'Add a unit', 'Add a command', 'Add a script', 'Add a hash', 'Add an address', 'Add a place', 'acme’s addresses'];
  const AGENT_SRC = fs.readFileSync(path.join(web, '..', 'deploy', 'agent', 'acme_agent.py'), 'utf-8');
  const HEAD = AGENT_SRC.split('POLICY_HEAD = """')[1].split('"""')[0];
  const PROT = AGENT_SRC.split('PROTECTED = (')[1].split(')')[0].match(/'[^']+'/g).map((x) => x.slice(1, -1));
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  const esc = (t) => t.replace(/<\/script/g, '<\\/script');
  const now = Date.now() / 1000;
  const POL = {hash: 'ab'.repeat(32), files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o640}],
    units: {'nginx.service': ['reload', 'restart']}, tests: [['nginx', '-t']], scripts: [],
    script_hashes: ['cd'.repeat(32)], from: ['192.0.2.10/32'], problems: []};
  const FP = '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7';
  const VIEW = {
    active: false, port: 8444, endpoints: [], node: 'acme1', nginx: null, shipped_code: 'c0de',
    ca: {fp: '9b'.repeat(32), end: now + 3650 * 86400, at: now - 86400},
    package: {name: 'acme-agent-1.0.116.tar.gz', version: '1.0.116', sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', size: 41234, signed: true},
    commands: ['sha256sum acme-agent-1.0.116.tar.gz', 'tar xzf acme-agent-1.0.116.tar.gz', 'cd acme-agent-1.0.116 && sudo ./install.sh', 'sudo acme-agent join CODE'],
    rows: [
      {id: 1, name: 'web1', mode: 'passive', state: 'answers', host: 'web1.example.com', agent_host: 'web1', version: '1.0.116', code_hash: 'c0de',
       last_seen: now - 12, cert_end: now + 25 * 86400, policy_summary: {files: 1, units: 1, tests: 1, scripts: 1, from: 1, problems: 0}},
      {id: 2, name: 'mail-gw', mode: 'active', state: 'quiet', host: '', agent_host: 'mx1.example.com', version: '1.0.115', code_hash: 'c0de',
       update: {offered: '1.0.116', newer: true, allowed: false, signed: true}, blocked: {what: 'restart postfix.service', allow: []}, keys_of: ['mail.example.com'],
       last_seen: now - 3600, cert_end: now + 6 * 86400, policy_summary: {files: 2, units: 2, tests: 0, scripts: 0, from: 0, problems: 1},
       last_error: 'the agent did not ask for the job in 90 s'},
      {id: 3, name: 'new-box', mode: 'passive', state: 'joining', host: '10.1.2.3', version: '', last_seen: null, cert_end: null, policy_summary: null}]
  };
  const ONE = {id: 1, name: 'web1', mode: 'passive', state: 'answers', joined: true, agent_id: 'ag-1234567890abcdef', host: 'web1.example.com',
    agent_host: 'web1', version: '1.0.116', code_hash: 'c0de', shipped_code: 'c0de', os: 'Rocky Linux 9.4 (Blue Onyx)', last_seen: now - 12,
    cert_end: now + 25 * 86400, key_fp: FP, policy: POL, policy_at: now - 300, pending: null, package: VIEW.package, commands: VIEW.commands,
    ca: VIEW.ca, port: 8444};
  const FACTS = {protected: PROT, parts: ['.ssh'], own: ['/etc/acme-agent', '/var/lib/acme-agent', '/var/lib/acme-agent-root', '/run/acme-agent'],
    verbs: ['reload', 'restart', 'try-reload-or-restart', 'reload-or-restart', 'try-restart'], shells: ['sh', 'bash', 'dash', 'zsh', 'python3'],
    config_ok: ['/etc/ssl', '/etc/pki'], head: HEAD, limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}};
  const TPL = [
    {key: 'nginx', title: 'nginx', group: 'Web servers', note: 'The same paths on RHEL and Debian (/etc/nginx/ssl).', files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o644}],
     units: {'nginx.service': ['reload']}, tests: [['nginx', '-t']], scripts: [], probe_local: true},
    {key: 'httpd', title: 'Apache httpd (RHEL, Rocky, Alma)', group: 'Web servers', files: [{dir: '/etc/ssl/acme', owner: 'root', group: 'root', mode: 0o644}],
     units: {'httpd.service': ['reload']}, tests: [['apachectl', '-t'], ['apachectl', 'configtest']], scripts: [], probe_local: true},
    {key: 'haproxy', title: 'HAProxy', group: 'Proxies and load balancers', files: [{dir: '/etc/haproxy/certs', owner: 'root', group: 'root', mode: 0o600}],
     units: {'haproxy.service': ['reload']}, tests: [['haproxy', '-c', '-q', '-f', '/etc/haproxy/haproxy.cfg']], scripts: [], probe_local: true},
    {key: 'postfix', title: 'Postfix', group: 'Mail', files: [{dir: '/etc/postfix/ssl', owner: 'root', group: 'root', mode: 0o644}],
     units: {}, tests: [['postfix', 'check'], ['postfix', 'reload']], scripts: [], probe_local: true},
    {key: 'zimbra', title: 'Zimbra', group: 'Mail', note: 'zmcertmgr deploycrt runs as zimbra.', files: [{dir: '/opt/zimbra/ssl/acme', owner: 'zimbra', group: 'zimbra', mode: 0o640}],
     units: {}, tests: [], scripts: [{path: '/usr/local/sbin/acme-zimbra-deploy.sh', sha256: ''}], probe_local: true},
    {key: 'docker', title: 'A Docker container', group: 'Containers', files: [{dir: '/srv/docker/certs', owner: 'root', group: 'root', mode: 0o644}],
     units: {}, tests: [['docker', 'restart', 'web']], scripts: [], probe_local: true},
    {key: 'folder', title: 'A folder for certificates', group: 'Any other', files: [{dir: '/etc/ssl/acme', owner: 'root', group: 'root', mode: 0o644}],
     units: {}, tests: [], scripts: [], probe_local: false}];
  const BNEEDS = [
    {id: 7, cert: 'www.example.com', enabled: true, items: [
      {kind: 'file', path: '/etc/nginx/ssl/www.crt', mode: 0o644, owner: 'root', group: 'root', allow: 'acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0644'},
      {kind: 'file', path: '/etc/nginx/ssl/www.key', mode: 0o600, owner: 'root', group: 'root', allow: 'acme-agent allow file /etc/nginx/ssl --owner root:root --mode 0600'},
      {kind: 'test', step: 'test', argv: ['nginx', '-t'], allow: 'acme-agent allow test -- nginx -t'},
      {kind: 'unit', step: 'reload', unit: 'nginx.service', verb: 'reload', allow: 'acme-agent allow unit nginx.service reload'},
      {kind: 'hash', hash: '4f'.repeat(32), interp: 'bash', allow: 'acme-agent allow script-hash ' + '4f'.repeat(32)},
      {kind: 'probe', local: true, hp: '127.0.0.1:443', allow: 'acme-agent allow probe local'}]},
    {id: 8, cert: 'mail.example.com', enabled: true, items: [
      {kind: 'file', path: '/etc/postfix/ssl/mail.crt', mode: 0o644, owner: 'root', group: 'root', allow: ''},
      {kind: 'file', path: '/etc/sudoers.d/acme', mode: 0o440, owner: 'root', group: 'root', allow: ''},
      {kind: 'test', step: 'test', argv: ['postfix', 'check'], allow: ''},
      {kind: 'any', step: 'reload', any: [{kind: 'unit', unit: 'postfix.service', verb: 'reload'}, {kind: 'unit', unit: 'postfix@-.service', verb: 'reload'}], allow: ''}]},
    {id: 9, cert: 'k8s.example.com', enabled: false, items: [], error: '"kubectl create secret … | kubectl apply -f -" is a line of a shell: the agent runs no shell'}];
  const DESIGN = {n: 2, at: now - 3600, by: 'anna', title: 'nginx on web1', note: 'Only the ssl folder - never /etc/nginx itself.',
    text: HEAD + 'allow file /etc/nginx/ssl owner=root:root mode=0644\nallow unit nginx.service reload\nallow test -- nginx -t\nallow probe local\n',
    state: {files: [{dir: '/etc/nginx/ssl', owner: 'root', group: 'root', mode: 0o644}], units: [{name: 'nginx.service', verbs: ['reload']}], tests: [['nginx', '-t']], probe_local: true},
    hash: 'aa', entries: 4, warnings: 0,
    compare: {state: 'differs', added: ['allow probe local'], removed: ['allow script-hash ' + 'cd'.repeat(32), 'allow from 192.0.2.10/32']},
    history: []};
  DESIGN.history = [Object.assign({}, DESIGN, {history: undefined}), {n: 1, at: now - 86400, by: 'anna', title: 'first try', text: HEAD, state: {}}];
  const NEEDS = {state: 'answers', policy_hash: POL.hash, target: {id: 1, name: 'web1'}, items: [
    {kind: 'file', label: 'file', what: '/etc/nginx/ssl/site.crt  0644 root:root', ok: true, allow: ''},
    {kind: 'file', label: 'file', what: '/etc/nginx/ssl/site.key  0600 root:root', ok: true, allow: ''},
    {kind: 'test', label: 'test', what: 'nginx -t', ok: true, allow: ''},
    {kind: 'reload', label: 'reload', what: 'systemctl reload nginx', ok: false, allow: 'acme-agent allow unit nginx.service reload'},
    {kind: 'script', label: 'the script written here', what: 'sha256 4f1c09aa…', ok: false, allow: 'acme-agent allow script-hash ' + '4f'.repeat(32)},
    {kind: 'post', label: 'after', what: '/usr/local/bin/notify.sh', ok: null, allow: 'acme-agent allow script /usr/local/bin/notify.sh'}]};
  // What happens of a certificate whose key the agent makes (as runplan.py works it out)
  const POLOK = {ok: true, allow: ''};
  const PLAN = {cert: {name: 'www.example.com', names: ['www.example.com'], key_type: 'ec-256', csr_from: 'web1', state: 'ok'},
    head: {}, took_ms: 2100, made: now, phases: [
      {key: 'key', title: 'Key and request', module: {name: 'web1', kind: 'agent', title: 'Server with acme-agent', family: 'target', version: ''}, steps: [
        {kind: 'key', words: 'The key and the request (CSR) are made on web1 by its acme-agent - a new key at every issue; acme holds none',
         detail: {pairs: [['Names', 'www.example.com'], ['Key type', 'ec-256'], ['Subject', 'CN=www.example.com']]}},
        {kind: 'connect', words: 'Sends a signed job (keygen) to the agent of web1', detail: {pairs: [['Mode', 'passive - acme connects to the agent', 'words'], ['Where', 'web1.example.com:8446', '']]}},
        {kind: 'key', words: 'The agent makes a new ec-256 key on web1 (its root side) and sends back only its CSR - the key never leaves that server'},
        {kind: 'file', words: 'The key will go into /etc/nginx/ssl/www.key', detail: {path: '/etc/nginx/ssl/www.key', mode: '0640', owner: 'root:nginx', format: 'key-pem'}, policy: POLOK}]},
      {key: 'deploy', title: 'Deployments', groups: [{title: 'web1', enabled: true, module: {name: 'web1', kind: 'agent', title: 'Server with acme-agent', family: 'target', version: ''}, steps: [
        {kind: 'connect', words: 'Sends a signed job (deploy) to the agent of web1', detail: {pairs: [['Mode', 'passive - acme connects to the agent', 'words']]}},
        {kind: 'file', words: 'The agent writes /etc/nginx/ssl/www.crt', detail: {path: '/etc/nginx/ssl/www.crt', mode: '0644', owner: 'root:root', format: 'fullchain-pem'}, policy: POLOK},
        {kind: 'file', words: 'The agent writes the key it made into /etc/nginx/ssl/www.key', agent_key: true, detail: {path: '/etc/nginx/ssl/www.key', mode: '0640', owner: 'root:nginx', format: 'key-pem'}, policy: POLOK,
         note: 'the key the agent made for this certificate - acme sends only the certificate (and its chain) that goes with it'},
        {kind: 'command', words: 'The agent tests nginx -t', detail: {command: 'nginx -t'}, policy: POLOK, note: 'no shell: a fixed command line'},
        {kind: 'command', words: 'The agent reloads systemctl reload nginx', detail: {command: 'systemctl reload nginx'}, note: 'no shell: a unit’s verb (systemctl)',
         policy: {ok: false, allow: 'acme-agent allow unit nginx.service reload'}},
        {kind: 'stop', level: 'bad', words: 'The agent’s policy does not allow 1 of it: the agent refuses the whole job before anything is written - allow it on the server first'}]}]}]};
  let packStrings = {};
  try {
    for (const [lang, width] of [['en', 1400], ['cs', 1400], ['en', 420], ['cs', 420]]) {
      let pack = 'null';
      if (lang === 'cs') {
        const all = JSON.parse(read('lang/cs.json'));
        const pk = {code: 'cs', strings: {}, patterns: [], rich: {}};
        const same = {};
        for (const part of ['strings', 'patterns', 'rich']) {
          for (const e of Object.values(all[part] || {})) {
            if (!e || !e.source || !e.text) continue;
            /* the same in Czech ("Server", "Agent"): translated as it is */
            if (e.text === e.source) { same[fold(e.source)] = true; continue; }
            if (part === 'patterns') pk.patterns.push([e.source, e.text]); else pk[part][e.source] = e.text;
          }
        }
        for (const k of Object.keys(extra)) {
          if (/\{\d/.test(k)) pk.patterns.push([k, extra[k]]); else pk.strings[k] = extra[k];
        }
        packStrings = {};
        for (const k of Object.keys(same)) packStrings[k] = k;
        for (const k of Object.keys(pk.strings)) packStrings[fold(k)] = pk.strings[k];
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
        + '<style>' + read('assets/acme.css') + '</style><style>' + read('assets/certs.css') + '</style><style>' + read('assets/agents.css') + '</style>'
        + '<style>' + read('assets/runplan.css') + '</style><style>' + read('assets/policybuilder.css') + '</style>'
        + '<script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main class="ctl-main">' + paneHtml + '<div id="card-host"></div><div id="needs-host"></div></main>' + modalHtml
        + '<div class="toast" id="toast"></div>'
        + '<script>' + esc(read('assets/i18n.js')) + '</script>'
        + '<script>var ME = {name: "tester", role: "fulladmin", prefs: {}}; var LIVE = {on: false}; var SENT = [];'
        + ' var VIEW = ' + JSON.stringify(VIEW) + '; var ONE = ' + JSON.stringify(ONE) + '; var NEEDS = ' + JSON.stringify(NEEDS) + ';'
        + ' var PLAN = ' + JSON.stringify(PLAN) + '; var POL = ' + JSON.stringify(POL) + '; var FACTS = ' + JSON.stringify(FACTS) + '; var TPL = ' + JSON.stringify(TPL) + ';'
        + ' var BNEEDS = ' + JSON.stringify(BNEEDS) + '; var DESIGN = ' + JSON.stringify(DESIGN) + '; var SAVED = null;</script>'
        + '<script>' + esc(read('assets/core.js')) + '</script>'
        + '<script>' + esc(read('assets/agents.js')) + '</script>'
        + '<script>' + esc(read('assets/policybuilder.js')) + '</script>'
        + '<script>window.ACME_CERTS = {api: function () { return Promise.resolve({plan: PLAN}); }};</script>'
        + '<script>' + esc(read('assets/runplan.js')) + '</script>'
        + '<script>ACME_AGENTS.init({capi: function (what, body) { SENT.push([what, body || null]);'
        + ' var c = function (x) { return Promise.resolve(JSON.parse(JSON.stringify(x))); };'
        + ' if (what === "agents") return c(VIEW);'
        + ' if (what.indexOf("agents/one") === 0) return c(ONE);'
        + ' if (what === "agents/look") return c({agent: ONE});'
        + ' if (what === "agents/code") return c({code: "ACAG1.eyJ2IjoxLCJ0IjoxLCJuIjoid2ViMSIsIm0iOiJwYXNzaXZlIiwiaSI6IjBhMWIyYzNkNGU1ZiIsInMiOiJ4eHh4In0", until: Date.now() / 1000 + 3600, mode: "passive", ca_fp: VIEW.ca.fp, endpoints: [], port: 8446, agent: ONE});'
        + ' if (what === "agents/confirm") return c({agent: Object.assign({}, ONE, {pending: null})});'
        + ' if (what === "agents/update") return c({said: "acme-agent 1.0.117 is installed", agent: ONE});'
        + ' if (what.indexOf("agents/builder") === 0) return c({agent: ONE, facts: FACTS, templates: TPL, needs: BNEEDS, acme_from: ["192.0.2.11", "192.0.2.12"], design: SAVED});'
        + ' if (what === "agents/design") { SAVED = {n: 1, at: Date.now() / 1000, by: "tester", title: body.title, note: body.note, text: body.text, state: body.state, compare: {state: "differs", added: [], removed: []}, history: []}; return c({design: SAVED}); }'
        + ' if (what.indexOf("agents/design?") === 0) return c({design: DESIGN});'
        + ' if (what === "agents/design/forget") return c({design: null});'
        + ' if (what === "agents/updates") return c({rows: [{id: 2, name: "mail-gw", mode: "active", version: "1.0.115", offered: "1.0.116", ok: true, why: ""},'
        + ' {id: 4, name: "db1", mode: "passive", version: "1.0.115", offered: "1.0.116", ok: false, why: "its policy has no allow self-update"}]});'
        + ' return c({}); }, over: function (open) { open(); }, openTarget: function (n) { window.OPENED = n; },'
        + ' newCert: function (row, host) { window.NEWCERT = [row.name, host]; }});</script>'
        + '</body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}, deviceScaleFactor: 2});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      await page.setContent(html);
      await page.waitForTimeout(150);
      const tag = lang + width + '_';
      // ---- the pane, active mode off
      await page.evaluate(() => ACME_AGENTS.pane());
      await page.waitForTimeout(200);
      out.checks[tag + 'pane_off'] = await page.evaluate(() => {
        var h = document.getElementById('ag-hero');
        return !!h.querySelector('.dbs-hero') && !h.querySelector('.ag-eps') && h.querySelectorAll('.ag-mode').length === 2
          && !!h.querySelector('.dbs-state') && !h.querySelector('.dbs-state.ok');
      });
      out.checks[tag + 'package'] = await page.evaluate(() => {
        var p = document.getElementById('ag-pkg');
        return p.querySelector('.ag-pkg-name').textContent === 'acme-agent-1.0.116.tar.gz' && !!p.querySelector('.ag-badge.ok')
          && p.querySelector('.ag-sha-v').textContent.length === 64 && p.querySelectorAll('.ag-cmd').length === 4
          && p.querySelectorAll('.ag-cmd .btn').length === 4 && !!p.querySelector('.btn.primary');
      });
      out.checks[tag + 'authority'] = await page.evaluate(() => document.querySelectorAll('#ag-ca .ag-fp-g').length === 16);
      out.checks[tag + 'tiles'] = await page.evaluate(() => {
        var t = document.querySelectorAll('#ag-list .ag-tile');
        if (t.length !== 3) return false;
        return !!t[0].querySelector('.dbs-state.ok') && !!t[1].querySelector('.dbs-state.warn') && !!t[1].querySelector('.ag-end.warn')
          && t[0].querySelectorAll('.ag-chip').length === 4 && !!t[1].querySelector('.ag-chip.bad') && !!t[2].querySelector('.ag-chip.unk')
          && !!t[1].querySelector('.ag-mode.active') && !!t[0].querySelector('.ag-mode.passive')
          && t[1].querySelectorAll('.ag-flag').length === 3 && !!t[1].querySelector('.ag-flag.bad') && !t[0].querySelector('.ag-flags');
      });
      await page.evaluate(() => document.querySelector('#ag-list .ag-name').click());
      out.checks[tag + 'open_target'] = await page.evaluate(() => window.OPENED === 'web1');
      out.checks[tag + 'pane_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#pane-agents').screenshot({path: path.join(shots, 'pane-off-' + lang + width + '.png')});
      // ---- active mode on
      await page.evaluate(() => { VIEW.active = true; VIEW.nginx = {port: 8444}; VIEW.endpoints = ['acme.example.com:8444', '192.0.2.11:8444', '192.0.2.12:8444']; return ACME_AGENTS.pane(); });
      await page.waitForTimeout(200);
      out.checks[tag + 'pane_on'] = await page.evaluate(() => {
        var h = document.getElementById('ag-hero');
        return !!h.querySelector('.dbs-hero.good') && !!h.querySelector('.dbs-state.ok') && h.querySelectorAll('.ag-ep').length === 3
          && h.querySelector('.ag-port').textContent === '8444';
      });
      if (shots) await page.locator('#ag-hero').screenshot({path: path.join(shots, 'pane-on-' + lang + width + '.png')});
      // ---- saved on (1.0.117): the pane asks again by itself until each node's nginx has the port
      out.checks[tag + 'settles'] = await page.evaluate(async () => {
        window.SETTINGS = {settings: [{key: 'certs_agents_active', value: 1}]};
        VIEW.active = true; VIEW.nginx = {port: 0};
        ACME_AGENTS.settle();
        await new Promise((r) => setTimeout(r, 300));
        var waiting = !!document.querySelector('#ag-hero .dbs-state.warn');
        VIEW.nginx = {port: 8444};                     // the root helper gave nginx the port
        await new Promise((r) => setTimeout(r, 4600));
        var on = !!document.querySelector('#ag-hero .dbs-state.ok');
        return waiting && on;
      });
      // ---- the card of a joined agent
      await page.evaluate(() => { document.getElementById('card-host').appendChild(ACME_AGENTS.card({id: 1, name: 'web1'})); });
      await page.waitForTimeout(200);
      out.checks[tag + 'card'] = await page.evaluate(() => {
        var c = document.querySelector('#card-host .ag-card');
        return !!c && !!c.querySelector('.dbs-state.ok') && c.querySelectorAll('.ag-pol-g').length === 5 && c.querySelectorAll('.ag-verb').length === 2
          && c.querySelectorAll('.ag-acts .btn').length === 5 && !c.querySelector('.ag-confirm');
      });
      out.checks[tag + 'card_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'card-' + lang + width + '.png')});
      // ---- phases 3 and 4 on the card: a newer agent (allowed), a blocked deployment, the keys
      await page.evaluate(() => {
        ONE.update = {offered: '1.0.117', newer: true, signed: true, allowed: true, last: null};
        ONE.blocked = {at: Date.now() / 1000 - 600, what: 'restart nginx.service', allow: ['acme-agent allow unit nginx.service restart']};
        ONE.keys_of = ['www.example.com', 'mail.example.com'];
        ONE.policy = Object.assign({}, ONE.policy, {probe_local: true, probe: ['www.example.com:443'], connect: ['10.0.5.21:22'], self_update: true});
        var h = document.getElementById('card-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'}));
      });
      await page.waitForTimeout(200);
      out.checks[tag + 'card_p3'] = await page.evaluate(() => {
        var c = document.querySelector('#card-host .ag-card');
        return !!c.querySelector('.ag-upd.can .btn.primary') && c.querySelector('.ag-ver.new').textContent === '1.0.117'
          && !!c.querySelector('.ag-blocked .ag-cmd') && c.querySelector('.ag-blocked .ag-cmd pre').textContent === 'sudo acme-agent allow unit nginx.service restart'
          && c.querySelectorAll('.ag-keycert').length === 2 && !!c.querySelector('.ag-keys .btn')
          && c.querySelectorAll('.ag-pol-g').length === 8;
      });
      out.checks[tag + 'card_p3_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'card-p3-' + lang + width + '.png')});
      await page.evaluate(() => document.querySelector('#card-host .ag-keys .btn').click());
      out.checks[tag + 'new_cert'] = await page.evaluate(() => window.NEWCERT && window.NEWCERT[0] === 'web1' && window.NEWCERT[1] === 'web1.example.com');
      await page.evaluate(() => document.querySelector('#card-host .ag-upd .btn.primary').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'update_asked_first'] = await page.evaluate(() => !SENT.some(function (x) { return x[0] === 'agents/update'; })
        && !document.getElementById('modal').hidden && /1\.0\.117/.test(document.getElementById('modal-body').textContent));
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'update-ask-' + lang + width + '.png')});
      await page.evaluate(() => document.querySelector('#modal-foot .btn.primary').click());
      await page.waitForTimeout(250);
      if (shots) await page.locator('#card-host .ag-upd').screenshot({path: path.join(shots, 'update-now-' + lang + width + '.png')});
      out.checks[tag + 'update_sent'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/update' && x[1].id === 1; }));
      // ...a newer one its policy does not let acme send: the way, and the line
      await page.evaluate(() => {
        ONE.update = {offered: '1.0.117', newer: true, signed: true, allowed: false, last: null};
        ONE.blocked = null;
        var h = document.getElementById('card-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'}));
      });
      await page.waitForTimeout(200);
      out.checks[tag + 'update_not_allowed'] = await page.evaluate(() => {
        var u = document.querySelector('#card-host .ag-upd');
        return !!u && !u.classList.contains('can') && !u.querySelector('.btn.primary') && u.querySelector('.ag-cmd pre').textContent === 'sudo acme-agent allow self-update';
      });
      if (shots) await page.locator('#card-host .ag-upd').screenshot({path: path.join(shots, 'update-not-allowed-' + lang + width + '.png')});
      await page.evaluate(() => { ONE.update = null; ONE.keys_of = []; ONE.policy = Object.assign({}, ONE.policy, {probe_local: false, probe: [], connect: [], self_update: false}); });
      // ---- an agent waiting to be confirmed
      await page.evaluate(() => {
        ONE.pending = {fp: '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7', host: 'web1', version: '1.0.116', confirmed: false, at: Date.now() / 1000};
        ONE.joined = false; ONE.state = 'joining'; ONE.policy = null; ONE.version = ''; ONE.last_seen = null; ONE.cert_end = null;
        var h = document.getElementById('card-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'}));
      });
      await page.waitForTimeout(200);
      out.checks[tag + 'confirm_box'] = await page.evaluate(() => {
        var b = document.querySelector('#card-host .ag-confirm');
        return !!b && b.querySelectorAll('.ag-fp-g').length === 16 && b.querySelector('.ag-fp').textContent.indexOf('3F9A') === 0;
      });
      if (shots) await page.locator('#card-host .ag-card').screenshot({path: path.join(shots, 'confirm-' + lang + width + '.png')});
      await page.evaluate(() => document.querySelector('#card-host .ag-confirm .btn.primary').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'confirm_sent'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/confirm' && x[1].fp === ONE.pending.fp && x[1].id === 1; }));
      // ---- the wizard
      await page.evaluate(() => { ONE.pending = null; ONE.joined = false; ONE.state = 'new'; ACME_AGENTS.wizard({id: 1, name: 'web1'}, ONE, function () {}); });
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_1'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return !document.getElementById('modal').hidden && m.querySelectorAll('.dbw-rail li').length === 3 && !!m.querySelector('.dbw-rail li.on')
          && m.querySelectorAll('.ag-cmd').length === 3 && !!m.querySelector('.ag-pkg');
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard1-' + lang + width + '.png')});
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(250);
      out.checks[tag + 'wizard_2'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return SENT.some(function (x) { return x[0] === 'agents/code'; }) && !!m.querySelector('.ag-code pre')
          && m.querySelector('.ag-code pre').textContent.indexOf('ACAG1.') === 0 && m.querySelectorAll('.dbw-rail li.done').length === 1
          && m.querySelector('.ag-cmd pre').textContent.indexOf('sudo acme-agent join ACAG1.') === 0;
      });
      out.checks[tag + 'wizard_fits'] = await page.evaluate(() => document.getElementById('modal-box').scrollWidth <= document.getElementById('modal-box').clientWidth + 1);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard2-' + lang + width + '.png')});
      await page.evaluate(() => { ONE.pending = {fp: '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7', host: 'web1', version: '1.0.116', confirmed: false}; });
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(1200);
      out.checks[tag + 'wizard_3'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return m.querySelectorAll('.dbw-rail li.done').length === 2 && !!m.querySelector('.ag-confirm') && m.querySelectorAll('.ag-fp-g').length === 16;
      });
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'wizard3-' + lang + width + '.png')});
      // (hunt 1.0.116) an active agent confirmed but its certificate not taken yet: "handing it
      // its certificate", not "has joined" - until it asks (the join no longer pending)
      await page.evaluate(() => { SENT.length = 0; ONE.mode = 'active'; ONE.joined = true; ONE.code_until = null;
        ONE.pending = {fp: '3f9a1c0e77d24b5a9e31c2f4d8a6b0e1f2c3d4e5a6b7c8d9e0f1a2b3c4d5e6f7', host: 'web1', version: '1.0.116', confirmed: true}; });
      await page.waitForTimeout(2900);
      out.checks[tag + 'wizard_active_handing'] = await page.evaluate(() => {
        var m = document.getElementById('modal-body');
        return !!m.querySelector('.ag-waiting') && !m.querySelector('.ag-done') && SENT.length > 0;
      });
      await page.evaluate(() => { ONE.pending = null; });
      await page.waitForTimeout(2900);
      out.checks[tag + 'wizard_active_done'] = await page.evaluate(() => !!document.querySelector('#modal-body .ag-done'));
      await page.evaluate(() => closeModal());
      // (hunt 1.0.116) a passive agent joined again: the wizard has acme reach it (agents/look) -
      // the agent joined before is still the target's until the new one is confirmed
      await page.evaluate(() => { SENT.length = 0; ONE.mode = 'passive'; ONE.joined = true; ONE.pending = null; ONE.code_until = Date.now() / 1000 + 3600;
        ACME_AGENTS.wizard({id: 1, name: 'web1'}, ONE, function () {}); });
      await page.waitForTimeout(300);
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(300);
      await page.locator('#modal-foot .btn.primary').click();
      await page.waitForTimeout(1200);
      out.checks[tag + 'wizard_rejoin_looks'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/look' && x[1].id === 1; })
        && !document.querySelector('#modal-body .ag-done'));
      await page.evaluate(() => { ONE.pending = null; ONE.joined = true; ONE.state = 'answers'; ONE.policy = VIEW.rows && ONE.policy || null; ONE.code_until = null; });
      await page.evaluate(() => closeModal());
      // ---- a deployment's needs
      await page.evaluate(() => { var t = document.getElementById('toast'); if (t) t.remove(); document.getElementById('pane-agents').hidden = true; document.getElementById('card-host').hidden = true;
        document.getElementById('needs-host').appendChild(ACME_AGENTS.needs(NEEDS)); });
      out.checks[tag + 'needs'] = await page.evaluate(() => {
        var n = document.querySelector('#needs-host .ag-needs');
        return n.querySelectorAll('.ag-need.ok').length === 3 && n.querySelectorAll('.ag-need.bad').length === 2 && n.querySelectorAll('.ag-need.unk').length === 1
          && n.querySelectorAll('.ag-need.bad .ag-cmd pre')[0].textContent === 'sudo acme-agent allow unit nginx.service reload'
          && !!n.querySelector('.ag-badge.bad') && !!n.querySelector('.ag-needs-all .btn');
      });
      out.checks[tag + 'needs_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#needs-host .ag-needs').screenshot({path: path.join(shots, 'needs-' + lang + width + '.png')});
      // ---- a deployment whose key the agent makes, and a test through it
      await page.evaluate(() => {
        var n2 = {state: 'answers', agent_key: true, items: [
          {kind: 'file', label: 'file', what: '/etc/nginx/ssl/www.crt  0644 root:root', ok: true, allow: ''},
          {kind: 'key', label: 'the key, made there', what: '/etc/nginx/ssl/www.key  0640 root:nginx', ok: true, allow: ''},
          {kind: 'reload', label: 'reload', what: 'systemctl reload nginx', ok: true, allow: ''},
          {kind: 'probe', label: 'test', what: '127.0.0.1:443', ok: false, allow: 'acme-agent allow probe local'}]};
        var h = document.getElementById('needs-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.needs(n2));
      });
      out.checks[tag + 'needs_key'] = await page.evaluate(() => {
        var n = document.querySelector('#needs-host .ag-needs');
        return !!n.querySelector('.ag-needs-key') && n.querySelectorAll('.ag-need.ok').length === 3
          && n.querySelector('.ag-need.bad .ag-cmd pre').textContent === 'sudo acme-agent allow probe local';
      });
      if (shots) await page.locator('#needs-host .ag-needs').screenshot({path: path.join(shots, 'needs-key-' + lang + width + '.png')});
      // (hunt 1.0.116) what the agent cannot do at all (a line of a shell, a key it makes in a
      // keystore) is not "allows all of it"; nor is a form with no file yet
      await page.evaluate(() => {
        var h = document.getElementById('needs-host'); h.innerHTML = '';
        h.appendChild(ACME_AGENTS.needs({state: 'answers', items: [], error: '"kubectl x | kubectl apply -f -" is a line of a shell: the agent runs no shell'}));
        h.appendChild(ACME_AGENTS.needs({state: 'answers', items: []}));
        h.appendChild(ACME_AGENTS.needs({state: 'answers', items: [{kind: 'file', label: 'file', what: '/usr/lib/x/a.pem  0644 root:root', ok: false, allow: '',
          why: '/usr/lib/x/a.pem is under /usr/lib - a file there gives root to whoever writes it; acme-agent never writes there, whatever the policy says'}]}));
      });
      out.checks[tag + 'needs_never'] = await page.evaluate(() => {
        var n = document.querySelectorAll('#needs-host .ag-needs')[2];
        return !!n.querySelector('.ag-need.bad .ag-need-why') && !n.querySelector('.ag-cmd');
      });
      out.checks[tag + 'needs_error_empty'] = await page.evaluate(() => {
        var n = document.querySelectorAll('#needs-host .ag-needs');
        return n.length === 3 && !!n[0].querySelector('.ag-badge.bad') && !n[0].querySelector('.ag-badge.ok')
          && !!n[1].querySelector('.ag-badge.dim') && !n[1].querySelector('.ag-badge.ok');
      });
      // ---- What happens of it (runplan.js): each item of the agent's job judged by its policy
      await page.evaluate(() => { document.getElementById('needs-host').hidden = true; ACME_RUNPLAN.open({id: 7, name: 'www.example.com'}); });
      await page.waitForTimeout(500);
      out.checks[tag + 'what_happens'] = await page.evaluate(() => {
        var b = document.getElementById('modal-body');
        return b.querySelectorAll('.rp-pol.ok').length === 4 && b.querySelectorAll('.rp-pol.bad').length === 1
          && b.querySelector('.rp-pol.bad .rp-code pre').textContent === 'sudo acme-agent allow unit nginx.service reload'
          && Array.prototype.some.call(b.querySelectorAll('.rp-tag'), function (t) { return t.textContent === 'the key made on the server' || t.textContent.length > 5; });
      });
      out.checks[tag + 'what_happens_fits'] = await page.evaluate(() => document.getElementById('modal-box').scrollWidth <= document.getElementById('modal-box').clientWidth + 1);
      if (shots) {
        await page.evaluate(() => { var g = document.querySelector('.rp-group, .rp-phase:last-child'); if (g) g.scrollIntoView(); });
        await page.locator('#modal-box').screenshot({path: path.join(shots, 'what-happens-' + lang + width + '.png')});
      }
      await page.evaluate(() => closeModal());
      // ---- 1.0.118: the policy builder
      await page.setViewportSize({width: width, height: 1300});
      await page.evaluate(() => { var t = document.getElementById('toast'); if (t) t.remove();
        ONE.pending = null; ONE.joined = true; ONE.state = 'answers'; ONE.mode = 'passive'; ONE.policy = POL; ONE.policy_at = Date.now() / 1000; ONE.design = null;
        var h = document.getElementById('card-host'); h.hidden = false; h.innerHTML = '';
        h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'})); });
      await page.waitForTimeout(250);
      await page.evaluate(() => { var b = Array.prototype.filter.call(document.querySelectorAll('#card-host .ag-acts .btn'), function (x) { return x.textContent.length && x.querySelector('svg'); }); b[b.length - 1].click(); });
      await page.waitForTimeout(400);
      const pre = () => page.evaluate(() => document.querySelector('#modal-body .pb-pre').textContent);
      const want0 = HEAD + ['allow file /etc/nginx/ssl owner=root:root mode=0640', 'allow unit nginx.service reload,restart', 'allow test -- nginx -t',
        'allow script-hash ' + 'cd'.repeat(32), 'allow from 192.0.2.10/32'].join('\n') + '\n';
      out.checks[tag + 'builder_from_server'] = await page.evaluate(() => !!document.querySelector('#modal-body .pb')
        && SENT.some(function (x) { return x[0].indexOf('agents/builder?id=1') === 0; })
        && document.querySelectorAll('#pb-s-files .pb-row').length === 1 && !!document.querySelector('.pb-seg-b.on')
        && document.querySelectorAll('.pb-tpl').length === 7) && (await pre()) === want0;
      out.checks[tag + 'builder_fits'] = await page.evaluate(() => document.getElementById('modal-box').scrollWidth <= document.getElementById('modal-box').clientWidth + 1
        && document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-top-' + lang + width + '.png')});
      // a template: Postfix's folder and tests
      await page.evaluate(() => { var t = Array.prototype.filter.call(document.querySelectorAll('.pb-tpl'), function (x) { return x.textContent.indexOf('Postfix') >= 0; })[0]; t.click(); });
      await page.waitForTimeout(150);
      out.checks[tag + 'builder_template'] = await page.evaluate(() => document.querySelectorAll('#pb-s-files .pb-row').length === 2
        && document.querySelector('.pb-pre').textContent.indexOf('allow file /etc/postfix/ssl owner=root:root mode=0644\nallow unit nginx.service reload,restart\nallow test -- nginx -t\nallow test -- postfix check\nallow test -- postfix reload\n') > 0
        && document.querySelector('.pb-pre').textContent.indexOf('allow probe local') > 0
        && Array.prototype.some.call(document.querySelectorAll('.pb-tpl.on'), function (x) { return x.textContent.indexOf('Postfix') >= 0; }));
      // validation: a protected place (red, left out), a folder above them (amber), a shell's -c (amber)
      const typeLast = async (sec, sel, value) => page.evaluate(([sec, sel, value]) => {
        var rows = document.querySelectorAll('#pb-s-' + sec + ' .pb-row'); var i = rows[rows.length - 1].querySelector(sel);
        i.value = value; i.dispatchEvent(new Event('input', {bubbles: true})); }, [sec, sel, value]);
      await page.evaluate(() => { document.querySelector('#pb-s-files .pb-sec-h .btn').click(); });
      await page.waitForTimeout(100);
      await typeLast('files', '.pb-path', '/etc/sudoers.d');
      await page.waitForTimeout(100);
      out.checks[tag + 'builder_protected'] = await page.evaluate(() => {
        var rows = document.querySelectorAll('#pb-s-files .pb-row'), r = rows[rows.length - 1];
        return r.classList.contains('bad') && r.querySelector('.pb-msg.bad').textContent.indexOf('/etc/sudoers.d') >= 0
          && document.querySelector('.pb-pre').textContent.indexOf('sudoers') < 0 && !!document.querySelector('.pb-badge.bad')
          && !!document.querySelector('.pb-nav-b.bad') && document.querySelector('.pb-stat.bad b').textContent === '1';
      });
      if (shots) { await page.evaluate(() => document.getElementById('pb-s-files').scrollIntoView()); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-folders-' + lang + width + '.png')}); }
      const h0 = await page.evaluate(() => { var rows = document.querySelectorAll('#pb-s-files .pb-row'); return rows[rows.length - 1].getBoundingClientRect().height; });
      await typeLast('files', '.pb-path', '/etc');
      await page.waitForTimeout(100);
      out.checks[tag + 'builder_above'] = await page.evaluate(() => {
        var rows = document.querySelectorAll('#pb-s-files .pb-row'), r = rows[rows.length - 1];
        return r.classList.contains('warn') && r.querySelector('.pb-msg.warn').textContent.indexOf('/etc/sudoers') > 0
          && document.querySelector('.pb-pre').textContent.indexOf('allow file /etc owner=root:root mode=0644') > 0 && !!document.querySelector('.pb-badge.warn');
      });
      await page.evaluate(() => { var rows = document.querySelectorAll('#pb-s-files .pb-row'); rows[rows.length - 1].querySelector('.pb-x').click(); });
      await page.evaluate(() => { document.querySelector('#pb-s-tests .pb-sec-h .btn').click(); });
      await page.waitForTimeout(100);
      await typeLast('tests', '.pb-cmd', 'sh -c "systemctl restart x; echo ok"');
      await page.waitForTimeout(100);
      out.checks[tag + 'builder_shell'] = await page.evaluate(() => {
        var rows = document.querySelectorAll('#pb-s-tests .pb-row'), r = rows[rows.length - 1];
        return r.classList.contains('warn') && r.querySelectorAll('.pb-tok').length === 3 && r.querySelector('.pb-msg.warn').textContent.indexOf('sh -c') >= 0
          && document.querySelector('.pb-pre').textContent.indexOf("allow test -- sh -c 'systemctl restart x; echo ok'") > 0;
      });
      if (shots) { await page.evaluate(() => document.getElementById('pb-s-tests').scrollIntoView()); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-tests-' + lang + width + '.png')}); }
      await page.evaluate(() => { var rows = document.querySelectorAll('#pb-s-tests .pb-row'); rows[rows.length - 1].querySelector('.pb-x').click(); });
      // what the deployments need: one click each, and all of it
      out.checks[tag + 'builder_needs'] = await page.evaluate(() => {
        var n = document.querySelectorAll('#pb-s-needs .pb-need');
        return n.length === 10 && document.querySelectorAll('#pb-s-needs .pb-need.never').length === 1
          && document.querySelector('#pb-s-needs .pb-need.never .pb-need-why').textContent.indexOf('/etc/sudoers.d') >= 0 && !!document.querySelector('#pb-s-needs .pb-dep .pb-msg.bad');
      });
      if (shots) { await page.evaluate(() => document.getElementById('pb-s-needs').scrollIntoView()); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-needs-' + lang + width + '.png')}); }
      await page.evaluate(() => document.querySelector('.pb-addall').click());
      await page.waitForTimeout(150);
      out.checks[tag + 'builder_add_all'] = await page.evaluate(() => document.querySelectorAll('#pb-s-needs .pb-need.no').length === 0
        && document.querySelectorAll('#pb-s-needs .pb-need.yes').length === 9 && document.querySelector('.pb-pre').textContent.indexOf('allow script-hash ' + '4f'.repeat(32)) > 0
        && document.querySelector('.pb-pre').textContent.indexOf('allow unit postfix.service reload') > 0 && document.querySelector('.pb-addall').disabled);
      // the outputs: allow lines, one block, what changes; Copy
      await page.evaluate(() => { window.copyText = function (t) { window.COPIED = t; }; document.querySelectorAll('.pb-tab')[2].click(); });
      const once = await pre();
      out.checks[tag + 'builder_one_block'] = once.indexOf("sudo acme-agent policy apply - <<'EOF'\n" + HEAD) === 0 && /\nEOF$/.test(once)
        && once.indexOf('allow file /etc/postfix/ssl owner=root:root mode=0644\n') > 0;
      await page.evaluate(() => document.querySelector('.pb-out-bar .btn.primary').click());
      out.checks[tag + 'builder_copy'] = await page.evaluate((once) => window.COPIED === once, once);
      await page.evaluate(() => document.querySelectorAll('.pb-tab')[1].click());
      out.checks[tag + 'builder_allow_lines'] = (await pre()).split('\n').indexOf('sudo acme-agent allow file /etc/postfix/ssl --owner root:root --mode 0644') >= 0
        && (await pre()).split('\n').indexOf('sudo acme-agent allow probe local') >= 0;
      await page.evaluate(() => document.querySelectorAll('.pb-tab')[3].click());
      out.checks[tag + 'builder_diff'] = await page.evaluate(() => {
        var p = document.querySelector('.pb-pre');
        return p.querySelectorAll('.pb-d.add').length >= 5 && p.querySelectorAll('.pb-d.del').length === 1
          && p.querySelector('.pb-d.del').textContent === '- allow file /etc/nginx/ssl owner=root:root mode=0640\n'
          && Array.prototype.some.call(p.querySelectorAll('.pb-d.add'), function (x) { return x.textContent === '+ allow probe local\n'; })
          && document.querySelector('.pb-tab-n').textContent !== '';
      });
      if (shots) { await page.evaluate(() => { document.querySelector('#modal-body').scrollTop = 0; }); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-diff-' + lang + width + '.png')}); }
      // switches: connect off by default, its warning when on; limits
      await page.evaluate(() => document.querySelector('#pb-s-connect .pb-switch').click());
      await page.waitForTimeout(100);
      out.checks[tag + 'builder_connect'] = await page.evaluate(() => !!document.querySelector('#pb-s-connect .pb-connect-warn') && document.querySelectorAll('#pb-s-connect .pb-row').length === 1);
      if (shots) { await page.evaluate(() => document.getElementById('pb-s-from').scrollIntoView()); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-more-' + lang + width + '.png')}); }
      await page.evaluate(() => document.querySelector('#pb-s-connect .pb-switch').click());
      // save as this agent's design
      await page.evaluate(() => { document.querySelectorAll('.pb-tab')[0].click(); var t = document.querySelector('.pb-title'); t.value = 'web1 - nginx and Postfix'; });
      const file = await pre();
      await page.evaluate(() => document.querySelector('.pb-save .btn').click());
      await page.waitForTimeout(200);
      out.checks[tag + 'builder_saved'] = await page.evaluate((file) => {
        var x = SENT.filter(function (y) { return y[0] === 'agents/design'; }).pop();
        return !!x && x[1].text === file && x[1].title === 'web1 - nginx and Postfix' && x[1].id === 1 && Array.isArray(x[1].state.files)
          && document.querySelector('.pb-save-st').textContent.indexOf('v1') >= 0;
      }, file);
      if (shots) { await page.evaluate(() => { var o = document.querySelector('.pb-out'); o.scrollIntoView(); }); await page.locator('#modal-box').screenshot({path: path.join(shots, 'builder-saved-' + lang + width + '.png')}); }
      if (lang === 'cs') {
        const text = await page.evaluate(() => document.getElementById('modal-box').innerText);
        const left = BWORDS.filter((w) => packStrings[fold(w)] === undefined || (text.indexOf(w) >= 0 && packStrings[fold(w)] !== w));
        out.checks[tag + 'builder_czech'] = !left.length;
        if (left.length) out['bleft_' + tag] = left;
      }
      await page.evaluate(() => closeModal(true));
      // ---- the saved design on the card
      await page.evaluate(() => { ONE.design = DESIGN; var h = document.getElementById('card-host'); h.innerHTML = ''; h.appendChild(ACME_AGENTS.card({id: 1, name: 'web1'})); });
      await page.waitForTimeout(250);
      out.checks[tag + 'card_design'] = await page.evaluate(() => {
        var d = document.querySelector('#card-host .ag-design');
        return !!d && d.classList.contains('differs') && d.querySelectorAll('.pb-d.add').length === 1 && d.querySelectorAll('.pb-d.del').length === 2
          && d.querySelectorAll('.btn').length === 5 && !!d.querySelector('.ag-design-hist') && d.textContent.indexOf('nginx on web1') >= 0;
      });
      if (shots) await page.locator('#card-host .ag-design').screenshot({path: path.join(shots, 'card-design-' + lang + width + '.png')});
      await page.evaluate(() => { window.copyText = function (t) { window.COPIED = t; }; document.querySelectorAll('#card-host .ag-design .btnrow .btn')[1].click(); });
      out.checks[tag + 'card_design_copy'] = await page.evaluate(() => window.COPIED === DESIGN.text);
      await page.evaluate(() => document.querySelector('#card-host .ag-design .btn.danger').click());
      await page.waitForTimeout(150);
      await page.evaluate(() => document.querySelector('#modal-foot .btn.danger').click());
      await page.waitForTimeout(200);
      out.checks[tag + 'card_design_forget'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/design/forget' && x[1].id === 1; }));
      await page.evaluate(() => { try { closeModal(); } catch (e) { } });
      // the builder opened again starts from the saved design
      await page.evaluate(() => { SAVED = DESIGN; ACME_POLICY_BUILDER.open({id: 1, name: 'web1'}, {}); });
      await page.waitForTimeout(400);
      out.checks[tag + 'builder_from_design'] = (await pre()) === DESIGN.text && await page.evaluate(() => document.querySelectorAll('.pb-seg-b').length === 3);
      await page.evaluate(() => { SAVED = null; closeModal(true); });
      // ---- Update all agents… (the pane)
      await page.evaluate(() => { document.getElementById('pane-agents').hidden = false; document.getElementById('card-host').hidden = true; ACME_AGENTS.pane(); });
      await page.waitForTimeout(250);
      await page.evaluate(() => document.querySelector('#ag-list .ag-list-h .btn').click());
      await page.waitForTimeout(250);
      out.checks[tag + 'update_all'] = await page.evaluate(() => document.querySelectorAll('#modal-body .ag-upd-one').length === 2
        && document.querySelectorAll('#modal-body .ag-upd-one.no').length === 1 && document.querySelector('#modal-body .ag-upd-one.no .why').textContent.length > 5
        && !!document.querySelector('#modal-foot .btn.primary'));
      if (shots) await page.locator('#modal-box').screenshot({path: path.join(shots, 'update-all-' + lang + width + '.png')});
      await page.evaluate(() => { SENT.length = 0; document.querySelector('#modal-foot .btn.primary').click(); });
      await page.waitForTimeout(300);
      out.checks[tag + 'update_all_sent'] = await page.evaluate(() => SENT.some(function (x) { return x[0] === 'agents/update' && x[1].id === 2; })
        && !SENT.some(function (x) { return x[0] === 'agents/update' && x[1].id === 4; }) && !document.querySelector('[data-upd="2"]').hidden);
      await page.setViewportSize({width: width, height: 900});
      if (lang === 'cs') {
        const text = await page.evaluate(() => document.body.innerText);
        const left = WORDS.filter((w) => packStrings[fold(w)] === undefined || (text.indexOf(w) >= 0 && packStrings[fold(w)] !== w));
        out.checks[tag + 'czech'] = !left.length;
        if (left.length) out['left_' + tag] = left;
      }
      await page.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
