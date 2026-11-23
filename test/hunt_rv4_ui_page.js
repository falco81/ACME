// The pages' half of test/test_hunt_rv4_ui.py (hunt v4, ui: forms and dialogs).
//
//   node test/hunt_rv4_ui_page.js BASE_URL PASSWORD [screenshot-folder]
//
// English and Czech, 1400 and 390 px:
// - Settings → SSH keys, "Add a key for …": a line the daemon refuses keeps the popup and what
//   was pasted (it closed first and the key went with it), the button pressed once.
// - Settings → Backups, a destination's "Use my own" key: the same.
// - Settings → Export and import, a locked file with a wrong passphrase: the popup stays.
// - Certificates → Add a certificate: names pasted into "Paste many…" and not added are taken by
//   Next; with long names no step of the wizard is wider than the popup.
// - A new directory, "Show a person's attributes" with no servers: the daemon's refusal in Czech.
// Prints one line of JSON.
const { chromium } = require('playwright');
const path = require('path');

const LONG = 'segment-segment-segment-segment-segment.anotherpart-anotherpart-anotherpart.third-third-third-third-third.example.com';

(async () => {
  const [base, pass, shots] = process.argv.slice(2);
  const browser = await chromium.launch();
  const out = {errors: [], runs: []};
  try {
    for (const lang of ['en', 'cs']) for (const w of [1400, 390]) {
      const ctx = await browser.newContext({viewport: {width: w, height: w < 500 ? 844 : 900}, deviceScaleFactor: 1});
      await ctx.addCookies([{name: 'acme_lang', value: lang, url: base}]);
      const page = await ctx.newPage();
      const tag = `${lang}-${w}`;
      const run = {lang, w};
      page.on('pageerror', e => out.errors.push(tag + ': ' + String(e.message || e)));
      await page.goto(base + '/admin/index.php');
      await page.fill('#in-name', 'tester');
      await page.type('#in-pass', pass);
      await Promise.all([page.waitForNavigation(), page.click('#in-go')]);
      await page.waitForTimeout(1200);
      const shot = async name => { if (shots) await page.screenshot({path: path.join(shots, `rv4-${name}-${tag}.png`)}); };
      const popup = () => page.evaluate(() => ({open: !document.getElementById('modal').hidden,
        title: document.getElementById('modal-title').textContent,
        toast: (document.querySelector('#toast.show') || {}).textContent || ''}));
      const shut = async () => {
        for (let i = 0; i < 4; i++) {
          if (!await page.evaluate(() => !document.getElementById('modal').hidden)) break;
          await page.evaluate(() => closeModal(true));
          await page.waitForTimeout(250);
        }
      };

      // ---- SSH keys: a refused line ----
      await page.evaluate(() => { showTab('settings'); showPane('sshkeys'); });
      await page.waitForTimeout(1500);
      await page.evaluate(() => { SK.user = 'alice'; skAdd(); });
      await page.waitForSelector('#modal-body textarea');
      await page.fill('#modal-body textarea', 'ssh-ed25519 notakey me@laptop');
      run.skPresses = await page.evaluate(() => {
        toastAway();
        const b = document.querySelector('#modal-foot .btn.primary');
        let sent = 0;
        const was = window.api;
        window.api = function (what) { if (what === 'sshkeys') sent++; return was.apply(this, arguments); };
        b.click(); b.click();
        window.api = was;
        return sent;
      });
      await page.waitForFunction(() => document.querySelector('#toast.show'), null, {timeout: 20000});
      run.sk = await popup();
      run.sk.kept = await page.$eval('#modal-body textarea', t => t.value);
      await shot('sshkey');
      await shut();

      // ---- Backups: a destination's own key, refused ----
      await page.evaluate(() => { showPane('backup'); });
      await page.waitForFunction(() => typeof RB === 'object' && RB && RB.kinds, null, {timeout: 20000});
      await page.evaluate(() => rbEdit({kind: 'sftp'}));
      await page.waitForTimeout(500);
      await page.evaluate(() => {
        const f = rbEdit.form;
        f.name.value = 'NAS rv4'; f.host.value = 'backup.example.test'; f.user.value = 'acme-backup';
        const own = [...document.querySelectorAll('#modal-body button')].find(b => /^(Use my own|Použít vlastní)/.test(b.textContent.trim()));
        own.click();
      });
      await page.waitForSelector('#rb-paste-area');
      await page.fill('#rb-paste-area', '-----BEGIN OPENSSH PRIVATE KEY-----\nnot a key at all\n-----END OPENSSH PRIVATE KEY-----');
      await page.evaluate(() => { toastAway(); [...document.querySelectorAll('#modal-foot .btn.primary')].pop().click(); });
      await page.waitForFunction(() => document.querySelector('#toast.show'), null, {timeout: 20000});
      run.rb = await popup();
      run.rb.kept = await page.evaluate(() => ($('rb-paste-area') || {}).value || '');
      await shot('rbkey');
      await shut();

      // ---- Export and import: a locked file, a wrong passphrase ----
      await page.evaluate(() => { showPane('carry'); });
      await page.waitForTimeout(800);
      const bundle = await page.evaluate(() => api('export&secrets=1').then(d => JSON.stringify(d.bundle)));
      await page.setInputFiles('#ex-file', {name: 'locked.json', mimeType: 'application/json', buffer: Buffer.from(bundle)});
      await page.waitForFunction(() => !document.getElementById('modal').hidden && document.querySelector('#modal-body input[type=password]'), null, {timeout: 20000});
      await page.fill('#modal-body input[type=password]', 'not-the-passphrase');
      await page.evaluate(() => { toastAway(); [...document.querySelectorAll('#modal-foot .btn.primary')].pop().click(); });
      await page.waitForFunction(() => document.querySelector('#toast.show'), null, {timeout: 20000});
      run.imp = await popup();
      run.imp.kept = await page.$eval('#modal-body input[type=password]', i => i.value).catch(() => '');
      await shut();

      // ---- A new directory: the daemon's refusal in the page's language ----
      await page.evaluate(() => { showPane('people'); });
      await page.waitForTimeout(1200);
      await page.evaluate(() => { [...document.querySelectorAll('button')].find(x => /^(Add a directory|Přidat adresář)$/.test(x.textContent.trim()) && x.offsetParent).click(); });
      await page.waitForTimeout(800);
      await page.evaluate(() => {
        const b = [...document.querySelectorAll('#modal-box button')].find(x => /attributes|atributy/.test(x.textContent));
        const i = b.parentNode.querySelector('input') || b.closest('div').parentNode.querySelector('input');
        i.value = 'jnovak'; b.click();
      });
      await page.waitForFunction(() => document.querySelector('#modal-box .note.bad'), null, {timeout: 20000});
      await page.waitForTimeout(300);
      run.dirSaid = await page.$eval('#modal-box .note.bad', n => n.textContent);
      await shut();

      // ---- Add a certificate: names pasted, Next, long names in every step ----
      await page.evaluate(() => showTab('certs'));
      await page.waitForTimeout(1200);
      await page.evaluate(() => { [...document.querySelectorAll('button')].find(x => /^(Add a certificate|Přidat certifikát)$/.test(x.textContent.trim()) && x.offsetParent).click(); });
      await page.waitForTimeout(1000);
      await page.evaluate(() => { [...document.querySelectorAll('#modal-foot .btn.primary')].pop().click(); });
      await page.waitForTimeout(800);
      await page.evaluate(() => { [...document.querySelectorAll('#modal-body button')].find(x => /Paste many|Vložit více/.test(x.textContent)).click(); });
      const names = Array.from({length: 12}, (_, i) => 'host' + i + '.' + LONG);
      await page.evaluate(n => { const t = [...document.querySelectorAll('#modal-body textarea')].filter(x => x.offsetParent).pop(); t.value = n; t.dispatchEvent(new Event('input', {bubbles: true})); }, names.join('\n'));
      run.steps = [];
      for (let i = 0; i < 9; i++) {
        const step = await page.evaluate(() => {
          const b = document.getElementById('modal-body');
          return {step: ((document.querySelector('#modal-body .ct-wsteps .on .w') || {}).textContent || ''),
                  hs: b.scrollWidth - b.clientWidth, chips: document.querySelectorAll('#modal-body .ct-name:not(.cn)').length,
                  rows: document.querySelectorAll('#modal-body table.ct-cmaptable tbody tr').length};
        });
        await shot('wizard-' + i);
        const next = await page.evaluate(() => { toastAway(); const b = [...document.querySelectorAll('#modal-foot .btn.primary')].filter(x => !x.hidden && !x.disabled).pop(); const t = b ? b.textContent.trim() : ''; if (/^(Next|Další)$/.test(t)) b.click(); return t; });
        await page.waitForTimeout(900);
        step.toast = await page.evaluate(() => (document.querySelector('#toast.show') || {}).textContent || '');
        run.steps.push(step);
        if (!/^(Next|Další)$/.test(next)) break;
      }
      run.pageHs = await page.evaluate(() => document.scrollingElement.scrollWidth - innerWidth);
      await shut();
      out.runs.push(run);
      await ctx.close();
    }
  } catch (e) {
    out.error = String(e && e.stack || e);
  }
  await browser.close();
  console.log(JSON.stringify(out));
})();
