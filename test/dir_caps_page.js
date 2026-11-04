// Wrong directory passwords, each directory (admin.js, as otp 1.0.232) - the card of
// Settings → Accounts in a page of its own, no daemon needed: the API answered here.
//
//   node test/dir_caps_page.js /path/to/web [screenshot-folder]
//
// Drawn in English and in Czech, at 1300 and 390 px: every directory a card, the three ways
// of its cap, the domain's policy read (lockout, passwords, the fine-grained ones) and the
// recommendation; "Use it" fills the boxes only (one change waiting for the save bar), and
// the save sends the caps. Nothing in Czech left in English that has a translation.
// Prints one line of JSON: {ok, checks: {name: true|false}, error?}.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

(async () => {
  const web = process.argv[2];
  const shots = process.argv[3] || '';
  const read = (p) => fs.readFileSync(path.join(web, p), 'utf-8');
  const admin = read('assets/admin.js');
  const a = admin.indexOf('/* Wrong directory passwords, each directory');
  const b = admin.indexOf('/* How far a count has got towards its limit', a);
  const dp = admin.slice(a, b);
  const page0 = read('admin/index.php');
  const ca = page0.indexOf('<div class="card full fulladmin-only" id="dp-card">');
  const card = page0.slice(ca, page0.indexOf('<div id="dp-list"></div></div>', ca) + '<div id="dp-list"></div></div>'.length);
  const out = {checks: {}, errors: []};
  const browser = await chromium.launch();
  try {
    for (const [lang, width] of [['en', 1300], ['cs', 1300], ['cs', 390]]) {
      // As acme-page.php hands it to the page (acme_lang_pack).
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
        pack = JSON.stringify(pk).replace(/</g, '\\u003c');
      }
      const html = '<!doctype html><html class="dark"><head><meta charset="utf-8"><style>' + read('assets/acme.css')
        + '</style><script>window.ACME_LANG_PACK = ' + pack + ';</script></head><body><main style="padding:16px">'
        + card + '</main><div class="toast" id="toast"></div>'
        + '<script>' + read('assets/i18n.js').replace(/<\/script/g, '<\\/script') + '</script>'
        + '<script>' + read('assets/core.js').replace(/<\/script/g, '<\\/script') + '</script>'
        + '<script>var ADMIN = true, PENDING = {}, SENT = [], LOCKOUTS = 0;'
        + 'function pendingSet(k, p) { PENDING[k] = p; } function markDirtyCount() {} function loadLockouts() { LOCKOUTS++; }'
        + 'var CAPS = {directories: [{name: "corp", hosts: "dc1.corp.loc, dc2.corp.loc", tls: "ldaps", enabled: true,'
        + ' base: "DC=corp,DC=loc", tries: null, window_min: null}, {name: "lab", hosts: "dc.lab.loc", tls: "none",'
        + ' enabled: false, tries: 0}], setting: {tries: 3, window_min: 30}, in_use: true};'
        + 'var POL = {domain: "DC=corp,DC=loc", name: "corp", took_ms: 41, at: Date.now() / 1000,'
        + ' lockout: {threshold: 5, window_s: 1800, duration_s: 1800},'
        + ' password: {min_length: 12, history: 24, max_age_s: 3628800, min_age_s: 86400, complex: true, reversible: false},'
        + ' psos: [{name: "Admins PSO", precedence: 1, threshold: 3, window_s: 3600, min_length: 15, applies: ["Domain Admins"]}],'
        + ' recommend: {tries: 2, window_min: 60, threshold: 3, from: "the policy Admins PSO",'
        + ' why: "The policy Admins PSO locks an account after 3 wrong passwords: 2 here leave the person 1 of their own before it locks."}};'
        + 'api = function (what, body) { SENT.push(body); if (body.action === "pw_caps") return Promise.resolve(JSON.parse(JSON.stringify(CAPS)));'
        + ' if (body.action === "policy") return Promise.resolve({policy: POL});'
        + ' if (body.action === "pw_caps_save") return Promise.resolve({message: "saved"}); return Promise.reject(new Error("?")); };'
        + '</script><script>' + dp.replace(/<\/script/g, '<\\/script') + '</script></body></html>';
      const page = await browser.newPage({viewport: {width: width, height: 900}});
      page.on('pageerror', (e) => out.errors.push(lang + width + ': ' + String(e)));
      await page.setContent(html);
      await page.evaluate(() => loadDirCaps());
      await page.waitForTimeout(150);
      const tag = lang + width;
      out.checks[tag + '_two_cards'] = await page.evaluate(() => document.querySelectorAll('#dp-list .dp-dir').length === 2);
      out.checks[tag + '_off_one_cannot_read'] = await page.evaluate(() =>
        document.querySelectorAll('#dp-list .dp-dir')[1].querySelector('.dp-head button').disabled);
      await page.locator('#dp-list .dp-dir').first().locator('.dp-head button').click();
      await page.waitForTimeout(150);
      out.checks[tag + '_policy_drawn'] = await page.evaluate(() => {
        const c = document.querySelector('#dp-list .dp-dir');
        return c.querySelectorAll('.dp-tile').length === 3 && c.querySelectorAll('.dp-fact').length === 6
          && c.querySelectorAll('.dp-pso').length === 1 && !!c.querySelector('.dp-rec');
      });
      await page.locator('#dp-list .dp-rec button').click();
      await page.waitForTimeout(100);
      out.checks[tag + '_use_it_fills_only'] = await page.evaluate(() => {
        const c = document.querySelector('#dp-list .dp-dir');
        const nums = c.querySelectorAll('.dp-nums input');
        return nums[0].value === '2' && nums[1].value === '60' && !!PENDING.dirpw && c.classList.contains('changed')
          && SENT.every((s) => s.action !== 'pw_caps_save');
      });
      await page.evaluate(() => PENDING.dirpw.save());
      await page.waitForTimeout(100);
      out.checks[tag + '_saved'] = await page.evaluate(() => {
        const s = SENT.filter((x) => x.action === 'pw_caps_save')[0];
        return !!s && s.caps.corp.tries === 2 && s.caps.corp.window_min === 60 && s.caps.lab.tries === 0 && LOCKOUTS === 1;
      });
      if (lang === 'cs') {
        await page.locator('#dp-list .dp-dir').first().locator('.dp-head button').click();
        await page.waitForTimeout(150);
        const left = await page.evaluate(() => {
          const words = ['Read the domain', 'Account lockout', 'Password policy', 'Fine-grained', 'Recommended',
                         'As the setting above', 'Its own', 'No cap', 'The cap on these pages', 'wrong passwords',
                         'counted over', 'Use it', 'The domain says', 'Wrong directory passwords - each'];
          const t = document.querySelector('main').innerText;
          return words.filter((w) => t.indexOf(w) >= 0);
        });
        out.checks[tag + '_czech'] = left.length === 0;
        if (left.length) out['left_' + tag] = left;
      }
      out.checks[tag + '_fits'] = await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1);
      if (shots) await page.locator('#dp-card').screenshot({path: path.join(shots, 'dp-' + tag + '.png')});
      await page.close();
    }
  } catch (e) {
    out.error = String(e);
  }
  await browser.close();
  out.ok = !out.error && !out.errors.length && Object.values(out.checks).every(Boolean);
  console.log(JSON.stringify(out));
})();
