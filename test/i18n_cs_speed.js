// The page's translation (web/assets/i18n.js) with the whole Czech file, in node - no
// browser, no daemon. Hunt M: one job message of a deployment that failed on several
// targets took 47 s to translate and the Czech admin page stood still all that time.
//
//   node test/i18n_cs_speed.js /path/to/ACME
//
// Prints one line of JSON: {ms: {n: milliseconds}, got: {n: text}, said: {text: translation}}.
const vm = require('vm');
const fs = require('fs');
const path = require('path');

const root = process.argv[2];
const all = JSON.parse(fs.readFileSync(path.join(root, 'web', 'lang', 'cs.json'), 'utf8'));
// the pack as acme-page.php's acme_lang_pack() cuts it
const pack = {code: 'cs', strings: {}, patterns: [], rich: {}};
for (const part of ['strings', 'patterns', 'rich']) {
  for (const e of Object.values(all[part] || {})) {
    if (!e || typeof e !== 'object') continue;
    const from = String(e.source || ''), to = String(e.text || '');
    if (!from || !to || (to === from && part !== 'patterns')) continue;
    if (part === 'patterns') pack.patterns.push([from, to]); else pack[part][from] = to;
  }
}
const ctx = {window: {}, Map, Set, WeakMap, console, ACME_LANG_PACK: pack,
  document: {readyState: 'loading', addEventListener() {}, documentElement: {setAttribute() {}, classList: {remove() {}}},
             querySelectorAll: () => [], createTreeWalker() { return {nextNode: () => null}; }},
  MutationObserver: function () { this.observe = () => {}; this.takeRecords = () => []; }, setTimeout: () => {}};
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(path.join(root, 'web', 'assets', 'i18n.js'), 'utf8')
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;', ctx);
ctx.i18nInit(pack);

const parts = ['my-api: 10.1.2.3:8443 could not be reached: [Errno 111] Connection refused',
  'mikrotik-gw: 192.0.2.3 could not be reached: [Errno 113] No route to host',
  'self-push: the application said 422 (names): no slot here has a name this certificate holds (it holds a.example.com; the slots: node:acme1 localhost)',
  'raw-demo: the test mail-smtp after deploying here: 127.0.0.1:2525 cannot be reached: Connection refused'];
const message = (n) => n + ' of ' + n + ' deployment(s) failed - '
  + Array.from({length: n}, (x, i) => parts[i % 4].replace(/^([a-z-]+)/, '$1' + (i >= 4 ? i : ''))).join('; ');
const out = {ms: {}, got: {}, said: {}};
ctx.i18nText('warm up the translation');
for (const n of [1, 2, 3, 4, 10, 40]) {
  const t = process.hrtime.bigint();
  const got = ctx.i18nText(message(n));
  out.ms[n] = Number(process.hrtime.bigint() - t) / 1e6;
  out.got[n] = got;
}
for (const s of process.argv.slice(3)) out.said[s] = ctx.i18nText(s);
console.log(JSON.stringify(out));
