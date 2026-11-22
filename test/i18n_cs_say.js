// Texts translated by the page's i18n.js with the whole Czech file, in node (no browser).
//   node test/i18n_cs_say.js /path/to/ACME "text" ["text"...]
// Prints one line of JSON: {"text": "translation or null", ...}.
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
                + ';this.i18nText = i18nText; this.i18nInit = i18nInit;'
                + 'this.i18nForget = function () { I18N_SEEN.clear(); I18N_COST.clear(); };', ctx);
ctx.i18nInit(pack);
const said = {};
for (const s of process.argv.slice(3)) said[s] = ctx.i18nText(s);
console.log(JSON.stringify(said));
