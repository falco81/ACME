// The deployment form's files designer (deployfiles.js) for a read-only account (hunt R3):
// nothing in it can be clicked or typed into - the layouts, the script's and the password's
// modes, "As text", the chips, "From a template...", the module's other options.
//
//   node test/deployfiles_readonly_page.js ROLE
//
// Prints one line of JSON: {enabled: [what can still be clicked], buttons: n} - or {skip}.
const fs = require('fs');
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log(JSON.stringify({skip: 'no playwright: ' + e.message})); process.exit(0); }
const WEB = path.join(__dirname, '..', 'web', 'assets');
(async () => {
  const role = process.argv[2] || 'readonly';
  let browser;
  try {
    browser = await chromium.launch({args: ['--no-proxy-server']});
  } catch (e) {
    console.log(JSON.stringify({skip: 'chromium does not start: ' + String(e.message).slice(0, 200)}));
    return;
  }
  try {
    const page = await browser.newPage();
    await page.route('**/*', r => r.fulfill({status: 404, body: ''}));
    await page.setContent('<!doctype html><html><body><div id="host"></div></body></html>');
    await page.evaluate(r => { window.ME = {role: r}; }, role);
    await page.addScriptTag({content: fs.readFileSync(path.join(WEB, 'core.js'), 'utf8')});
    await page.addScriptTag({content: fs.readFileSync(path.join(WEB, 'deployfiles.js'), 'utf8')});
    const got = await page.evaluate(() => {
      var CT = window.ACME_CERTS;
      /* certs.js's fieldForm, as small as it can be: an input a field */
      CT.fieldForm = function (fields, values) {
        var node = document.createElement('div');
        fields.forEach(function (f) {
          var i = document.createElement(f.type === 'list' ? 'textarea' : 'input');
          i.name = f.key;
          i.value = values[f.key] || '';
          node.appendChild(i);
        });
        return {node: node, read: function () { return {}; }, set: function () { return true; },
                check: function () { return ''; }};
      };
      var p = {files_ui: {kind: 'posix', formats: [['fullchain-pem', 'Certificate + chain', ''], ['key-pem', 'Key', ''], ['pfx', 'PFX', '']],
                          vars: [['{name}', 'the name']], interps: [['bash', 'bash'], ['sh', 'sh']],
                          layouts: [{title: 'nginx', what: 'two files', outputs: ['fullchain-pem {dir}/a.crt'], folder: '/etc/ssl'}],
                          snippets: [{title: 'x', body: 'echo', interp: 'bash'}]}};
      var fields = [{key: 'outputs', type: 'list'}, {key: 'pfx_password_mode', type: 'select'},
                    {key: 'pfx_password', type: 'secret'}, {key: 'jks_alias', type: 'text'},
                    {key: 'script_mode', type: 'select'}, {key: 'script_body', type: 'textarea'},
                    {key: 'test_cmd', type: 'list'}, {key: 'reload_cmd', type: 'list'},
                    {key: 'service', type: 'text'}];
      var f = window.ACME_DEPLOY_UI.form(p, fields, {outputs: ['fullchain-pem /etc/ssl/a.crt', 'pfx /etc/ssl/a.pfx'],
                                                      script_mode: 'inline', script_body: 'echo hi'}, {}, {preview: false});
      document.getElementById('host').appendChild(f.node);
      var enabled = [];
      var all = f.node.querySelectorAll('button, input, select, textarea');
      Array.prototype.forEach.call(all, function (x) {
        if (x.disabled || x.readOnly || x.hidden) return;
        if (x.closest('[hidden]')) return;
        enabled.push(x.tagName.toLowerCase() + '.' + (x.className || x.name || '') + ':' + (x.textContent || x.value || '').trim().slice(0, 30));
      });
      return {enabled: enabled, buttons: f.node.querySelectorAll('button').length};
    });
    console.log(JSON.stringify(got));
  } catch (e) {
    console.log(JSON.stringify({error: String(e && e.stack || e).slice(0, 800)}));
  } finally {
    await browser.close();
  }
})();
