/* ctxmenu-registry.js - what each kind of object is to the right button's menu (ctxmenu.js,
   1.0.138): how a row is read, what can be done with it (the code its own buttons and dialogs
   run - certs.js lends those as ACME_CERTS.ctx), what goes on the acme clipboard (never a
   secret), what a clone opens, and the acme command and the API call that make it.

   The pages other parts draw (Owners and teams, Request profiles, Target agents) are read here
   by their tables' and rows' classes, not changed. */
(function () {
'use strict';
var CX = window.ACME_CTX;
if (!CX || CX._registry) return;
CX._registry = true;

var FILL = CX.FILL;
function me() { return (typeof ME === 'object' && ME) || (typeof PORTAL_ME === 'object' && PORTAL_ME) || null; }
function role() { var m = me(); return (m && m.role) || 'readonly'; }
function FULL() { return role() === 'fulladmin'; }
function MANAGE() { var r = role(); return r === 'fulladmin' || r === 'certadmin' || r === 'tokenadmin'; }
function portal() { return !/\/admin\//.test(location.pathname); }
function H() { return (window.ACME_CERTS && window.ACME_CERTS.ctx) || null; }
function capi(path, body) {
  if (window.ACME_CERTS && window.ACME_CERTS.api) return window.ACME_CERTS.api(path, body);
  return api(path, body);
}
function arr(v) { return Array.isArray(v) ? v : (v === undefined || v === null || v === '' ? [] : [v]); }
function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
function tr(s) { try { var t = typeof i18nText === 'function' ? i18nText(String(s)) : null; return t || String(s); } catch (e) { return String(s); } }
function data(kind, cls, text) { return noI18n(el(kind, cls, text)); }
function qs(o) { return '?' + Object.keys(o).map(function (k) { return encodeURIComponent(k) + '=' + encodeURIComponent(o[k]); }).join('&'); }
var NOT_FULL = 'Only a full administrator may do that';
var NOT_MANAGE = 'Only a certificate administrator (or a full one) may do that';
function mayOn(c, cap) {
  if (!MANAGE()) return false;
  return !c || !Array.isArray(c.caps) || c.caps.indexOf(cap) >= 0;
}
function capWhy(c, cap) { return mayOn(c, cap) ? '' : (MANAGE() ? 'Your teams do not give you that on this certificate' : NOT_MANAGE); }
function rowsOf(d, k) { return arr(d && (d[k] || d.rows || d.items)); }
function taken(list) { return arr(list).map(function (x) { return x && (x.name || x); }); }

/* ==========================================================================
   Certificates
   ========================================================================== */
var CERT_KEYS = ['name', 'names', 'issuer', 'challenge', 'challenge_map', 'key_type', 'key_type_alt', 'csr_from',
                 'auto_renew', 'renew_days', 'reuse_key', 'tags', 'note', 'owner', 'enabled', 'profile'];
function certFull(c) { return capi('certs/one' + qs({id: c.id})).then(function (d) { return d.cert; }); }
function certBody(c) {
  var b = {};
  CERT_KEYS.forEach(function (k) { if (c[k] !== undefined && c[k] !== null && c[k] !== '') b[k] = c[k]; });
  if (b.profile) b.profile = CX.scrub(b.profile);
  return b;
}
function certCli(c) {
  var p = [['--cert-add', c.name], ['--names', arr(c.names).join(',')]];
  if (c.issuer) p.push(['--issuer', c.issuer]);
  if (c.challenge) p.push(['--challenge', c.challenge]);
  if (c.key_type) p.push(['--key-type', c.key_type]);
  if (c.key_type_alt) p.push(['--key-type-alt', c.key_type_alt]);
  if (c.csr_from) p.push(['--csr-from', c.csr_from]);
  if (c.owner) p.push(['--owner', c.owner]);
  if (c.note) p.push(['--note', c.note]);
  var set = function (k, v) { p.push(['--set', k + '=' + CX.setValue(v)]); };
  if (c.auto_renew !== undefined && c.auto_renew !== null && !(c.auto_renew === 1 || c.auto_renew === true)) set('auto_renew', false);
  if (c.renew_days) set('renew_days', c.renew_days);
  if (c.reuse_key === 1 || c.reuse_key === true) set('reuse_key', true);
  if (arr(c.tags).length) set('tags', arr(c.tags));
  Object.keys(obj(c.challenge_map)).forEach(function (n) { set('challenge_map.' + n, c.challenge_map[n]); });
  var walk = function (o, pre) {
    Object.keys(obj(o)).forEach(function (k) {
      var v = o[k];
      if (CX.secretKeyRe.test(k) || v === '' || v === null || v === undefined) return;
      if (v && typeof v === 'object' && !Array.isArray(v)) { if (k === 'over') return; walk(v, pre + k + '.'); return; }
      if (Array.isArray(v) && !v.length) return;
      set(pre + k, v);
    });
  };
  walk(CX.scrub(c.profile || {}), 'profile.');
  var notes = [];
  if (c.enabled === 0 || c.enabled === false) p.push(['--enabled', 'off']);
  if (obj(c.profile).over && Object.keys(obj(c.profile).over).length) notes.push('its own settings of the source and validations (profile.over) are in the API call');
  notes.push('then: acme --renew ' + CX.sh(c.name) + ' issues it now (a new key - never this one\'s)');
  return CX.cliText(p, notes);
}
function certCall(c) {
  var b = certBody(c);
  return {method: 'POST', path: 'certs/save', body: b, notes: ['no id: a new certificate (a new key, made when it is issued)']};
}
CX.type('cert', {
  label: 'Certificate', plural: 'certificates', icon: 'lock',
  key: function (c) { return c.id; }, nameOf: function (c) { return c.name; },
  idents: function (c) {
    return [['Name', c.name, 'lock'], ['Common name', c.cn, 'person'], ['Names', arr(c.names).join(', '), 'globe'],
            ['Serial', c.serial, 'list'], ['Fingerprint (SHA-256)', c.fingerprint, 'key'], ['ID', c.id, 'info']];
  },
  open: function (c) { if (window.ACME_CERTS) window.ACME_CERTS.certPeek(c.id); },
  actions: function (c) {
    var h = H();
    if (!h) return [];
    var asked = c.state === 'pending-approval' || c.state === 'declined';
    var out = [];
    var renewable = c.issuer && c.state !== 'revoked' && c.state !== 'pending' && !asked && c.state !== 'deleting' && c.state !== 'revoke-failed';
    out.push({label: 'Renew now', icon: 'refresh', off: !c.issuer ? 'It has no source - renewed by importing a new one' : (!renewable ? 'Not in this state' : capWhy(c, 'cert.renew')),
              go: function () { h.certRenew(c, null); }});
    out.push({label: 'Deploy now', icon: 'upload', off: !(Number(c.deploys) > 0) ? 'It is not deployed anywhere yet' : capWhy(c, 'deploy.run'),
              go: function () { h.certDeploy(c, null); }});
    out.push({label: 'Run its tests…', icon: 'play', off: capWhy(c, 'manage'), go: function () { h.runTestsDialog(c); }});
    out.push({label: 'Export…', icon: 'export', off: !c.not_after ? 'Nothing is issued yet' : capWhy(c, 'cert.edit'),
              go: function () { return capi('certs/one' + qs({id: c.id})).then(function (d) { h.exportDialog(d.cert, d.versions); }); }});
    out.push({label: 'Edit…', icon: 'edit', off: capWhy(c, 'cert.edit'),
              go: function () { return certFull(c).then(function (full) { h.certWizard(full); }); }});
    out.push({label: 'Revoke…', icon: 'ban', danger: true, off: !c.issuer || !c.not_after ? 'There is nothing issued by a source to revoke' : capWhy(c, 'cert.revoke'),
              go: function () { return certFull(c).then(function (full) { h.revokeDialog(full); }); }});
    out.push({label: 'Delete…', icon: 'trash', danger: true, off: capWhy(c, 'cert.delete'),
              go: function () { return certFull(c).then(function (full) { h.deleteDialog(full); }); }});
    return out;
  },
  events: function (c) { return c.name; },
  jobs: function (c) { return {cert_id: c.id, name: c.name}; },
  copyData: function (c) { return certFull(c).then(certBody); },
  cli: function (c) { return certFull(c).then(certCli); },
  curl: function (c) { return certFull(c).then(certCall); },
  mayClone: function (c) { return MANAGE() ? '' : NOT_MANAGE; },
  cloneNote: 'a new request with the same names and settings - never the same key',
  clone: function (c) {
    return certFull(c).then(function (full) { certNew(certBody(full)); });
  },
  mayAdd: function () { return MANAGE(); }, addRefused: NOT_MANAGE,
  add: function () { var b = document.getElementById('ct-add'); if (b) b.click(); },
  addWords: 'Add a certificate…',
  pasteNew: function (clip) { (clip.items || []).slice(0, 1).forEach(function (it) { certNew(it.data); }); },
  paste: {
    deployment: {words: 'Paste the deployment', off: function (clip, certs) { return certs.some(function (c) { return !mayOn(c, 'deploy.manage'); }) ? NOT_MANAGE : ''; },
                 go: function (clip, certs) { return pasteDeploys(clip, certs); }},
    tags: {words: 'Add the tags', off: function (clip, certs) { return certs.some(function (c) { return !mayOn(c, 'cert.edit'); }) ? NOT_MANAGE : ''; },
           go: function (clip, certs) { return addTags('cert', clip, certs); }}
  },
  bulk: function (list) { return certBulk(list); }
});
/** The wizard of a new certificate, filled in as another one: its names, source, validation,
    key type, renewal, profile, owner and tags - with a name of its own. */
function certNew(d) {
  var h = H();
  if (!h) return;
  return capi('certs' + qs({per: 1000})).then(function (x) {
    var c = Object.assign({}, d);
    delete c.id;
    c.name = CX.copyName(d.name, taken(rowsOf(x, 'certs')));
    h.certWizard(c, null, {});
  });
}
function certSkip(c, cap, also) {
  if (!mayOn(c, cap)) return MANAGE() ? 'your teams do not give you that on it' : 'not yours to change';
  return also ? also(c) : '';
}
function certBulk(list) {
  var h = H();
  var out = [];
  var asked = function (c) { return c.state === 'pending-approval' || c.state === 'declined'; };
  out.push({label: 'Renew them now…', icon: 'refresh', go: function () {
    CX.bulk({title: 'Renew {0} certificate(s) now?'.replace('{0}', list.length), icon: 'refresh', verb: 'a new certificate is asked for now',
             intro: 'A new certificate is asked for at once for each, due or not; the ones in use stay valid until they run out. One job each.',
             button: 'Renew now',
             items: list.map(function (c) {
               return {c: c, name: c.name, will: 'renewed now', skip: certSkip(c, 'cert.renew', function (x) {
                 return !x.issuer ? 'no source - imported or from an outside CA' : (x.state === 'revoked' || x.state === 'pending' || asked(x) || x.state === 'deleting' ? 'not in this state' : '');
               })};
             }),
             run: function (x) { return capi('certs/renew', {id: x.c.id, force: true}); },
             done: refresh});
  }});
  out.push({label: 'Deploy them now…', icon: 'upload', go: function () {
    CX.bulk({title: 'Deploy {0} certificate(s) now?'.replace('{0}', list.length), icon: 'upload', button: 'Deploy now',
             intro: 'Each is put again on every target it is deployed on, whether it changed or not.',
             items: list.map(function (c) {
               return {c: c, name: c.name, will: 'put on {0} target(s)'.replace('{0}', Number(c.deploys) || 0),
                       skip: certSkip(c, 'deploy.run', function (x) { return Number(x.deploys) > 0 ? '' : 'deployed nowhere'; })};
             }),
             run: function (x) { return capi('certs/deploy', {id: x.c.id}); }, done: refresh});
  }});
  ['on', 'off'].forEach(function (how) {
    out.push({label: how === 'on' ? 'Renew them by themselves' : 'Renew them only when asked', icon: how === 'on' ? 'check' : 'ban', go: function () {
      CX.bulk({title: (how === 'on' ? 'Renew {0} certificate(s) by themselves?' : 'Renew {0} certificate(s) only when asked?').replace('{0}', list.length),
               icon: how === 'on' ? 'check' : 'ban', button: 'Change them',
               intro: how === 'on' ? 'Each is renewed by itself before it runs out.' : 'None of them is renewed by itself any more - it stays valid and deployed until it runs out.',
               items: list.map(function (c) {
                 var on = c.auto_renew === undefined || c.auto_renew === 1 || c.auto_renew === true;
                 return {c: c, name: c.name, will: how === 'on' ? 'renewed by itself' : 'only when asked',
                         skip: certSkip(c, 'cert.auto', function (x) { return !x.issuer ? 'no source' : ((how === 'on') === on ? 'already so' : ''); })};
               }),
               run: function (x) { return capi('certs/auto', {id: x.c.id, auto_renew: how === 'on'}); }, done: refresh});
    }});
  });
  out.push({label: 'Give them to a team…', icon: 'people', off: window.ACME_TEAMS ? '' : 'Owners and teams are not on this page', go: function () {
    var pick = null;
    CX.bulk({title: 'Give {0} certificate(s) to a team?'.replace('{0}', list.length), icon: 'people', button: 'Give them',
             intro: 'Each certificate gets the team chosen here as its owner; what its members may do with it follows.',
             extra: function (body) {
               pick = window.ACME_TEAMS.ownerPicker('');
               body.appendChild(formField('The team', pick));
             },
             check: function () { var v = pickValue(pick); return v === null ? 'choose a team' : ''; },
             items: list.map(function (c) { return {c: c, name: c.name, will: c.owner ? 'now of {0}'.replace('{0}', c.owner) : 'of nobody now', skip: certSkip(c, 'cert.edit')}; }),
             run: function (x) { return capi('certs/save', {id: x.c.id, owner: pickValue(pick) || ''}); }, done: refresh});
  }});
  out.push({label: 'Add a tag to them…', icon: 'flag', go: function () {
    var box = null;
    CX.bulk({title: 'Add a tag to {0} certificate(s)?'.replace('{0}', list.length), icon: 'flag', button: 'Add the tag',
             intro: 'The tag is added beside the ones each already has.',
             extra: function (body) { box = textBox('', 'prod', ''); noI18n(box); body.appendChild(formField('The tag', box)); setTimeout(function () { box.focus(); }, 50); },
             check: function () { return String(box.value || '').trim() ? '' : 'write the tag'; },
             items: list.map(function (c) { return {c: c, name: c.name, will: 'the tag added', skip: certSkip(c, 'cert.edit')}; }),
             run: function (x) {
               var t = String(box.value || '').trim();
               var have = arr(x.c.tags);
               if (have.indexOf(t) >= 0) return {ok: true, said: tr('already has it')};
               return capi('certs/save', {id: x.c.id, tags: have.concat([t])});
             }, done: refresh});
  }});
  var clip = CX.clip();
  if (clip && clip.type === 'deployment') out.push({label: ['Paste the deployment ', {data: CX.clipName(clip)}], icon: 'import', go: function () { return pasteDeploys(clip, list); }});
  if (clip && clip.type === 'tags') out.push({label: ['Add the tags ', {data: CX.clipName(clip)}], icon: 'import', go: function () { return addTags('cert', clip, list); }});
  out.push({label: 'Copy their names', icon: 'globe', go: function () { CX.copy(list.map(function (c) { return arr(c.names).join(' '); }).join('\n')); }});
  out.push({label: 'Delete them…', icon: 'trash', danger: true, go: function () {
    var rev = null;
    CX.bulk({title: 'Delete {0} certificate(s)?'.replace('{0}', list.length), icon: 'trash', danger: true, button: 'Delete them',
             intro: 'Each is deleted from acme with its versions and deployments - this cannot be taken back. Nothing is removed from the targets.',
             extra: function (body) {
               rev = switchBox(true);
               body.appendChild(formField('Revoke each first', rev, 'Its CA is told it must not be trusted any more, then it is deleted; one whose revocation fails is kept.'));
             },
             items: list.map(function (c) { return {c: c, name: c.name, will: 'deleted', skip: certSkip(c, 'cert.delete')}; }),
             run: function (x) { var r = !!rev._get(); return capi('certs/delete', {id: x.c.id, revoke: r && x.c.issuer && x.c.not_after ? 1 : 0, reason: 'cessationOfOperation'}); },
             done: refresh});
  }});
  return out;
}
function pickValue(p) {
  if (!p) return null;
  if (typeof p._get === 'function') return p._get();
  var s = p.querySelector ? (p.matches && p.matches('select, input') ? p : p.querySelector('select, input')) : null;
  return s ? s.value : null;
}
function refresh() { if (window.ACME_CERTS && window.ACME_CERTS.refresh) window.ACME_CERTS.refresh(); }

/* ==========================================================================
   Deployments (a certificate on a target)
   ========================================================================== */
function depData(d) {
  return {target: d.target, options: CX.scrub(obj(d.options)), enabled: d.enabled === 0 ? 0 : 1, note: d.note || ''};
}
CX.type('deployment', {
  label: 'Deployment', plural: 'deployments', icon: 'upload',
  key: function (d) { return d.id; }, nameOf: function (d) { return (d.cert_name || d.cert || '') ? (d.cert_name || d.cert) + ' → ' + d.target : d.target; },
  idents: function (d) { return [['Target', d.target, 'net'], ['ID', d.id, 'info']]; },
  rowButtons: true, actions: function () { return []; },
  copyData: function (d) { return depData(d); },
  cli: function (d) {
    var p = [['--deploy-add', d.cert_name || d.cert || ('#' + d.cert_id), d.target]];
    var o = CX.scrub(obj(d.options));
    Object.keys(o).forEach(function (k) { if (o[k] !== '' && o[k] !== null && o[k] !== undefined && typeof o[k] !== 'object') p.push(['--set', k + '=' + CX.setValue(o[k])]); });
    var secrets = Object.keys(obj(d.options)).filter(function (k) { return !(k in o); });
    secrets.forEach(function (k) { p.push(['--set', k + '=-']); });
    if (d.enabled === 0) p.push(['--enabled', 'off']);
    return CX.cliText(p, secrets.length ? [secrets.join(', ') + ': ' + FILL + ' - asked for on the terminal (KEY=-)'] : []);
  },
  curl: function (d) {
    var b = depData(d);
    b.cert_id = d.cert_id;
    Object.keys(obj(d.options)).forEach(function (k) { if (!(k in b.options)) b.options[k] = FILL; });
    return {method: 'POST', path: 'deploys/save', body: b};
  },
  clone: function (d) { var h = H(); if (h) h.over(function () { window.ACME_CERTS.deployEdit({deploy: depData(d)}); }); },
  cloneNote: 'the same target and options on another certificate',
  mayClone: function (d) { return MANAGE() ? '' : NOT_MANAGE; },
  events: function (d) { return d.target; }
});
/** A deployment on the acme clipboard put on certificates: one opens its form (saved on
    Save), several are asked once and made one after another. */
function pasteDeploys(clip, certs) {
  var items = clip.items || [];
  if (certs.length === 1 && items.length === 1 && window.ACME_CERTS) {
    var dd = Object.assign({}, items[0].data, {cert_id: certs[0].id});
    window.ACME_CERTS.deployEdit({deploy: dd, cert: {id: certs[0].id, name: certs[0].name}});
    return;
  }
  var plan = [];
  certs.forEach(function (c) {
    items.forEach(function (it) {
      plan.push({c: c, d: it.data, name: c.name + ' → ' + it.data.target, will: 'deployed there from now on',
                 skip: !mayOn(c, 'deploy.manage') ? 'not yours to change' : ''});
    });
  });
  CX.bulk({title: 'Put {0} deployment(s) on the certificates?'.replace('{0}', plan.length), icon: 'upload', button: 'Make the deployments',
           intro: 'Each certificate is deployed on the target with the options copied; a secret option is never copied - one that needs it is refused and said here. Nothing is put on a target until the next deployment (Deploy now).',
           items: plan,
           run: function (x) { return capi('deploys/save', {cert_id: x.c.id, target: x.d.target, options: x.d.options || {}, enabled: x.d.enabled === 0 ? false : true}); },
           done: refresh});
}
function addTags(kind, clip, list) {
  var tags = [];
  (clip.items || []).forEach(function (it) { arr(it.data && it.data.tags).forEach(function (t) { if (tags.indexOf(t) < 0) tags.push(t); }); });
  CX.bulk({title: (kind === 'cert' ? 'Add the tags to {0} certificate(s)?' : 'Add the tags to {0} target(s)?').replace('{0}', list.length),
           icon: 'flag', button: 'Add the tags',
           intro: 'Added beside the ones each has: {0}'.replace('{0}', tags.join(', ')),
           items: list.map(function (o) { return {o: o, name: o.name, will: 'the tags added', skip: kind === 'cert' ? certSkip(o, 'cert.edit') : (FULL() ? '' : 'only a full administrator may')}; }),
           run: function (x) {
             var have = arr(x.o.tags), more = tags.filter(function (t) { return have.indexOf(t) < 0; });
             if (!more.length) return {ok: true, said: tr('already has them')};
             return kind === 'cert' ? capi('certs/save', {id: x.o.id, tags: have.concat(more)})
               : capi('targets/save', {id: x.o.id, tags: have.concat(more)});
           },
           done: function () { refresh(); var h = H(); if (h && kind !== 'cert') delete h.LISTS.targets; }});
}

/* ==========================================================================
   Sources, validations, targets, tests (the modules)
   ========================================================================== */
var FAM = {
  sources: {type: 'source', family: 'issuer', word: 'source', list: 'sources', label: 'Source', plural: 'sources', icon: 'download'},
  validation: {type: 'validation', family: 'challenge', word: 'validation', list: 'validations', label: 'Validation', plural: 'validations', icon: 'check'},
  targets: {type: 'target', family: 'target', word: 'target', list: 'targets', label: 'Target', plural: 'targets', icon: 'net'},
  tests: {type: 'test', family: 'check', word: 'check', list: 'tests', label: 'Test', plural: 'tests', icon: 'pulse'}
};
/** The secrets of a module's row: the fields its module keeps sealed, and what is set. */
function modSecrets(key, r) {
  var h = H();
  var out = Object.keys(h ? h.secretsOf(r) : {});
  var p = h ? h.plugVersion(h.plugOf(FAM[key].family, r.kind), r.version) : null;
  arr(p && p.fields).forEach(function (f) { if (f.type === 'secret' || f.secret || f.type === 'sshkey') { out.push(f.key); out.push(f.key + '.sshkey'); } });
  return out;
}
function modRow(key, r) {
  /* a row read by its name (an agent's tile): the whole row from the list */
  if (r && r.id && r.config) return Promise.resolve(r);
  var h = H();
  if (!h) return Promise.reject(new Error('the certificate manager is not on this page'));
  return h.loadRows(key).then(function (rows) {
    var got = rows.filter(function (x) { return (r.id && x.id === r.id) || x.name === r.name; })[0];
    if (!got) throw new Error('there is no such {0}'.replace('{0}', tr(FAM[key].label).toLowerCase()));
    return got;
  });
}
function modData(key, r) {
  var keep = {name: r.name, kind: r.kind, enabled: r.enabled === undefined ? 1 : r.enabled, note: r.note || '',
              config: CX.scrub(obj(r.config), modSecrets(key, r))};
  if (r.config && r.config._version !== undefined) keep.config._version = r.config._version;
  if (key === 'targets') keep.tags = arr(r.tags);
  if ((key === 'targets' || key === 'tests') && r.owner) keep.owner = r.owner;
  return keep;
}
function modCli(key, r) {
  var f = FAM[key];
  var d = modData(key, r);
  var p = [['--' + f.word + '-add', r.name], ['--kind', r.kind]];
  Object.keys(d.config).forEach(function (k) {
    var v = d.config[k];
    if (v === '' || v === null || v === undefined || /\.sshkey$/.test(k) || k === '_version') return;
    if (Array.isArray(v) && !v.length) return;
    p.push(['--set', k + '=' + CX.setValue(v)]);
  });
  var secrets = Object.keys(H() ? H().secretsOf(r) : {}).filter(function (k) { return (H().secretsOf(r))[k]; });
  var sshkeys = [];
  var pl = H() ? H().plugVersion(H().plugOf(f.family, r.kind), r.version) : null;
  arr(pl && pl.fields).forEach(function (fd) { if (fd.type === 'sshkey') sshkeys.push(fd.key); });
  secrets.filter(function (k) { return sshkeys.indexOf(k) < 0; }).forEach(function (k) { p.push(['--set', k + '=-']); });
  if (r.note) p.push(['--note', r.note]);
  if (r.enabled === 0 || r.enabled === false) p.push(['--enabled', 'off']);
  if ((key === 'targets' || key === 'tests') && r.owner) p.push(['--owner', r.owner]);
  var notes = [];
  var plain = secrets.filter(function (k) { return sshkeys.indexOf(k) < 0; });
  if (plain.length) notes.push(plain.join(', ') + ': ' + FILL + ' - KEY=- asks for it on the terminal (never written out)');
  if (sshkeys.length && secrets.some(function (k) { return sshkeys.indexOf(k) >= 0; })) notes.push('its SSH key: acme --' + f.word + '-key ' + CX.sh(r.name) + ' make (or own FILE)');
  if (key === 'targets' && arr(r.tags).length) notes.push('its tags (' + arr(r.tags).join(', ') + ') are in the API call');
  return CX.cliText(p, notes);
}
function modCall(key, r) {
  var d = modData(key, r);
  Object.keys(H() ? H().secretsOf(r) : {}).forEach(function (k) { if ((H().secretsOf(r))[k]) d.config[k] = FILL; });
  return {method: 'POST', path: FAM[key].list + '/save', body: d, notes: ['no id: a new ' + FAM[key].word]};
}
function modOpenForm(key, d, opts) {
  var h = H();
  if (!h) return;
  opts = opts || {};
  return Promise.all([h.plugins(true), h.loadRows(key, true)]).then(function (got) {
    var p = h.plugVersion(h.plugOf(FAM[key].family, d.kind), (d.config || {})._version);
    if (!p) throw new Error('the module {0} is not installed here'.replace('{0}', d.kind));
    var keep = {config: Object.assign({}, d.config || {}), name: CX.copyName(d.name, taken(got[1])), note: d.note || '',
                enabled: d.enabled === undefined ? true : !!d.enabled, tags: key === 'targets' ? arr(d.tags).join(' ') : undefined};
    if (opts.same) { keep.copyOf = opts.same.id; keep.like = opts.same; Object.keys(h.secretsOf(opts.same)).forEach(function (k) { keep.config[k] = (opts.same.config || {})[k] || keep.config[k]; }); }
    h.over(function () { h.modForm(key, null, p, false, keep); });
  });
}
/** Clone: the same credentials (copied by the server, never sent here) or new ones. */
function modClone(key, r) {
  return modRow(key, r).then(function (row) {
    var h = H();
    var sec = Object.keys(h.secretsOf(row)).filter(function (k) { return h.secretsOf(row)[k]; });
    var d = modData(key, row);
    if (!sec.length) return modOpenForm(key, d);
    modal('Clone', function (body) {
      body.classList.add('cxc');
      body.appendChild(el('p', 'note', 'It keeps a password, a token or a key. The copy can sign in with the same ones - acme copies them on the server when you save, they never come to this page - or you give it new ones.'));
      var g = el('div', 'cxc-choices');
      [['same', 'Use the same credentials', 'Copied on the server when the copy is saved; changing them later changes only the copy.', 'key'],
       ['new', 'Enter new credentials', 'The copy starts without them - fill them in the form.', 'edit']].forEach(function (o, i) {
        var b = el('button', 'cxc-ch' + (i === 0 ? ' on' : ''));
        b.type = 'button';
        b.dataset.how = o[0];
        var ic = el('span', 'cxc-ic');
        ic.innerHTML = iconMarkup(o[3], 18);
        b.appendChild(ic);
        var w = el('span', 'cxc-w');
        w.appendChild(el('b', '', o[1]));
        w.appendChild(el('span', '', o[2]));
        b.appendChild(w);
        b.onclick = function () {
          closeModal();
          if (o[0] === 'same') modOpenForm(key, Object.assign({}, d, {config: Object.assign({}, d.config)}), {same: row});
          else modOpenForm(key, d);
        };
        g.appendChild(b);
      });
      body.appendChild(g);
      var keys = el('p', 'muted small');
      keys.appendChild(el('span', '', 'Kept secret: '));
      keys.appendChild(data('span', 'mono', sec.join(', ')));
      body.appendChild(keys);
      setTimeout(function () { var f = body.querySelector('.cxc-ch'); if (f) f.focus(); }, 40);
    }, [{words: 'Cancel', close: true}], 'narrow');
    CX.nameTitle('Clone', row.name);
  });
}
function modPasteNew(key, clip) {
  var it = (clip.items || [])[0];
  if (!it) return;
  var h = H();
  /* the same credentials only from this acme, where the one copied still is */
  if (clip.origin === location.host && it.id && h) {
    return h.loadRows(key, true).then(function (rows) {
      var src = rows.filter(function (x) { return x.id === it.id && x.kind === it.data.kind; })[0];
      if (src) return modClone(key, src).then(function () { });
      return modOpenForm(key, it.data);
    });
  }
  return modOpenForm(key, it.data);
}
Object.keys(FAM).forEach(function (key) {
  var f = FAM[key];
  var def = {
    label: f.label, plural: f.plural, icon: f.icon,
    key: function (r) { return r.id || r.name; }, nameOf: function (r) { return r.name; },
    secrets: function () { return []; },
    idents: function (r) {
      var c = obj(r.config);
      return [['Name', r.name, f.icon], ['Kind', r.kind, 'list'], ['Address', c.host || c.hostname || c.address || c.url || c.server || '', 'globe'], ['ID', r.id, 'info']];
    },
    open: function (r) {
      var h = H();
      if (!h) return;
      return modRow(key, r).then(function (row) { if (key === 'targets') h.targetPeek(row); else h.modEdit(key, row); });
    },
    actions: function (r) {
      var h = H();
      if (!h) return [];
      var out = [];
      var full = function (fn) { return function () { return modRow(key, r).then(fn); }; };
      out.push({label: 'Test it now', icon: 'play', note: 'nothing is changed', off: MANAGE() ? '' : NOT_MANAGE, go: full(function (row) { h.modTest(key, row, null); })});
      var p = r.kind ? h.plugVersion(h.plugOf(f.family, r.kind), r.version) : null;
      arr(r.actions && r.actions.length ? r.actions : (p && p.actions) || []).forEach(function (a) {
        if (r.kind === 'acme_push' && a.key === 'discover') return;
        out.push({label: a.label || a.key, icon: 'gear', off: (a.changes !== false ? FULL() : MANAGE()) ? '' : (a.changes !== false ? NOT_FULL : NOT_MANAGE),
                  go: full(function (row) { h.modAction(key, row, a, null); })});
      });
      out.push({label: 'Edit…', icon: 'edit', off: FULL() ? '' : NOT_FULL, go: full(function (row) { h.modEdit(key, row); })});
      if (key !== 'tests') {
        out.push({label: r.is_default ? 'Have no default' : 'Make it the default', icon: 'star', off: FULL() ? '' : NOT_FULL,
                  go: full(function (row) { return h.setDefault(key, row, !row.is_default, null); })});
      }
      out.push({label: 'Take it away…', icon: 'trash', danger: true, off: FULL() ? '' : NOT_FULL, go: full(function (row) { h.modDelete(key, row); })});
      return out;
    },
    events: function (r) { return r.name; },
    copyData: function (r) { return modRow(key, r).then(function (row) { return modData(key, row); }); },
    cli: function (r) { return modRow(key, r).then(function (row) { return modCli(key, row); }); },
    curl: function (r) { return modRow(key, r).then(function (row) { return modCall(key, row); }); },
    mayClone: function () { return FULL() ? '' : NOT_FULL; },
    clone: function (r) { return modClone(key, r); },
    mayAdd: function () { return FULL(); },
    add: function () { var b = document.getElementById({sources: 'src-add', validation: 'val-add', targets: 'tg-add', tests: 'ts-add'}[key]); if (b) b.click(); },
    addWords: {sources: 'Add a source…', validation: 'Add a way of validation…', targets: 'Add a target…', tests: 'Add a test…'}[key],
    pasteNew: function (clip) { return modPasteNew(key, clip); },
    paste: {},
    bulk: function (list) { return modBulk(key, list); }
  };
  if (key === 'targets') {
    def.paste.tags = {words: 'Add the tags', off: function () { return FULL() ? '' : NOT_FULL; }, go: function (clip, list) { return addTags('target', clip, list); }};
    def.actions = (function (base) {
      return function (r) {
        var out = base(r);
        out.splice(1, 0, {label: 'Copy its tags', icon: 'flag', off: arr(r.tags).length ? '' : 'It has no tag',
                          go: function () { CX.clipSet('tags', [{name: arr(r.tags).join(', '), id: r.id, data: {tags: arr(r.tags)}}]); }});
        return out;
      };
    }(def.actions));
  }
  CX.type(f.type, def);
});
CX.type('tags', {label: 'Tags', plural: 'tags', icon: 'flag', key: function (x) { return x.name; }, nameOf: function (x) { return x.name; }});
function modBulk(key, list) {
  var h = H();
  var f = FAM[key];
  var out = [];
  out.push({label: 'Test them now…', icon: 'play', go: function () {
    CX.bulk({title: 'Test the {0} selected now?'.replace('{0}', list.length), icon: 'play', button: 'Test them',
             intro: 'Each is tried as it is saved - nothing is changed. One job each.',
             items: list.map(function (r) { return {r: r, name: r.name, will: 'tried', skip: MANAGE() ? '' : 'only a certificate administrator may'}; }),
             run: function (x) {
               return modRow(key, x.r).then(function (row) {
                 return fetch('?api=' + f.list + '/test', {method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json'},
                                                          body: JSON.stringify({id: row.id})}).then(function (res) { return res.json(); });
               }).then(function (d) { return {ok: d.ok !== false && !d.error, said: d.said || d.error, job_id: d.job_id}; });
             },
             done: function () { if (h) { delete h.LISTS[key]; } refresh(); }});
  }});
  ['on', 'off'].forEach(function (how) {
    out.push({label: how === 'on' ? 'Switch them on' : 'Switch them off', icon: how === 'on' ? 'check' : 'power', go: function () {
      CX.bulk({title: (how === 'on' ? 'Switch the {0} selected on?' : 'Switch the {0} selected off?').replace('{0}', list.length),
               icon: how === 'on' ? 'check' : 'power', button: how === 'on' ? 'Switch them on' : 'Switch them off',
               intro: how === 'on' ? 'Each is used again.' : 'Each is kept, but not used for anything until it is switched on.',
               items: list.map(function (r) {
                 var on = r.enabled === undefined || r.enabled === 1 || r.enabled === true;
                 return {r: r, name: r.name, will: how === 'on' ? 'switched on' : 'switched off', skip: !FULL() ? 'only a full administrator may' : ((how === 'on') === on ? 'already so' : '')};
               }),
               run: function (x) { return capi(f.list + '/save', {id: x.r.id, enabled: how === 'on'}); },
               done: function () { if (h) delete h.LISTS[key]; refresh(); }});
    }});
  });
  if (key === 'targets') {
    var clip = CX.clip();
    if (clip && clip.type === 'tags') out.push({label: ['Add the tags ', {data: CX.clipName(clip)}], icon: 'import', go: function () { return addTags('target', clip, list); }});
  }
  out.push({label: 'Copy them to the acme clipboard', icon: 'archive', go: function () { return CX.copyObjects(CX.types[f.type], list, {}); }});
  return out;
}

/* ==========================================================================
   Jobs
   ========================================================================== */
CX.type('job', {
  label: 'Job', plural: 'jobs', icon: 'history',
  key: function (j) { return j.id; }, nameOf: function (j) { return '#' + j.id + ' ' + (j.kind || '') + (j.cert_name ? ' · ' + j.cert_name : ''); },
  idents: function (j) { return [['ID', j.id, 'info'], ['Certificate', j.cert_name || '', 'lock'], ['Target', j.target || '', 'net']]; },
  open: function (j) { if (window.ACME_CERTS) window.ACME_CERTS.jobPeek(j.id); },
  rowButtons: true, actions: function (j) {
    var out = [];
    if (j.cert_id) out.push({label: 'Open its certificate', icon: 'lock', go: function () { window.ACME_CERTS.certPeek(j.cert_id); }});
    return out;
  },
  jobs: function (j) { return j.cert_id ? {cert_id: j.cert_id, name: j.cert_name} : null; },
  events: function (j) { return j.cert_name || j.target || ''; }
});

/* ==========================================================================
   Owners and teams, roles, tags (teams.js draws them; read here by their classes)
   ========================================================================== */
var TEAMS = {d: null, at: 0};
function teamsData(again) {
  if (TEAMS.d && !again && Date.now() - TEAMS.at < 15000) return Promise.resolve(TEAMS.d);
  return api('teams').then(function (d) { TEAMS.d = d; TEAMS.at = Date.now(); return d; });
}
function teamOf(name) {
  return teamsData(true).then(function (d) {
    var t = arr(d.teams).filter(function (x) { return String(x.name).toLowerCase() === String(name).toLowerCase(); })[0];
    if (!t) throw new Error('there is no team {0}'.replace('{0}', name));
    return t;
  });
}
function teamData(t) {
  return {name: t.name, kind: t.kind || 'team', parent: t.parent || '', description: t.description || '',
          contact_mail: t.contact_mail || '', contact_phone: t.contact_phone || '', note: t.note || '', policy: obj(t.policy)};
}
function teamsRedraw() {
  if (window.ACME_EXTRA_PANES && window.ACME_EXTRA_PANES.teams && typeof PANE === 'string' && PANE === 'teams') window.ACME_EXTRA_PANES.teams();
  if (window.ACME_TEAMS && window.ACME_TEAMS.load) window.ACME_TEAMS.load(true);
}
/** A team cloned: its kind, place in the tree, description, contacts, note and limits - no
    member - under a name of its own; saved only with Save. */
function teamForm(d, title) {
  var f = {};
  return teamsData(true).then(function (all) {
    modal(title || 'A copy of', function (body) {
      body.classList.add('cxc');
      body.appendChild(el('p', 'note', 'A new team with the same kind, place in the tree, description, contacts, note and limits. Its members are not copied - add them once it is saved.'));
      var g = el('div', 'formgrid');
      f.name = textBox(CX.copyName(d.name, taken(all.teams)), '', '');
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'Letters, digits, spaces and . _ @ + - (as every name in acme).'));
      f.parent = el('select');
      var none = el('option', '', '- at the top -');
      none.value = '';
      f.parent.appendChild(none);
      arr(all.teams).forEach(function (t) { var o = data('option', '', t.name); o.value = t.name; f.parent.appendChild(o); });
      f.parent.value = d.parent || '';
      g.appendChild(formField('Under', f.parent));
      f.desc = textBox(d.description || '', '', '');
      noI18n(f.desc);
      var df = formField('Description', f.desc);
      df.classList.add('wide');
      g.appendChild(df);
      f.mail = textBox(d.contact_mail || '', 'web-team@example.com', 'mono');
      noI18n(f.mail);
      g.appendChild(formField('Mail', f.mail));
      f.phone = textBox(d.contact_phone || '', '', '');
      noI18n(f.phone);
      g.appendChild(formField('Phone', f.phone));
      body.appendChild(g);
      var lim = Object.keys(obj(d.policy)).filter(function (k) { var v = d.policy[k]; return v !== null && v !== '' && !(Array.isArray(v) && !v.length); });
      var lp = el('div', 'cxc-facts');
      lp.appendChild(el('span', 'tag ' + (lim.length ? 'info' : 'dim'), lim.length ? '{0} limit(s) copied'.replace('{0}', lim.length) : 'no limit'));
      if (lim.length) lp.appendChild(data('span', 'mono small muted', lim.join(', ')));
      lp.appendChild(el('span', 'tag dim', 'no member'));
      body.appendChild(lp);
      setTimeout(function () { f.name.focus(); f.name.select(); }, 60);
    }, [{words: 'Cancel', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('teams/save', {name: f.name.value.trim(), kind: d.kind || 'team', parent: f.parent.value || '', description: f.desc.value.trim(),
                         contact_mail: f.mail.value.trim(), contact_phone: f.phone.value.trim(), note: d.note || '', policy: obj(d.policy), members: []})
        .then(function (r) { toast((r && r.message) || 'saved', 'good'); closeModal(); teamsRedraw(); })
        .catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
    CX.nameTitle(title || 'A copy of', d.name);
  });
}
function teamCli(t) {
  var p = [['--team-add', t.name]];
  if (t.kind && t.kind !== 'team') p.push(['--team-kind', t.kind]);
  if (t.parent) p.push(['--parent', t.parent]);
  if (t.description) p.push(['--description', t.description]);
  if (t.contact_mail) p.push(['--contact-mail', t.contact_mail]);
  if (t.note) p.push(['--note', t.note]);
  if (Object.keys(obj(t.policy)).length) p.push(['--policy', JSON.stringify(t.policy)]);
  var m = arr(t.members).map(function (x) {
    var o = {who: x.who || x.name || x};
    if (arr(x.roles).length) o.roles = x.roles;
    if (x.until) o.until = x.until;
    if (x.note) o.note = x.note;
    return o;
  });
  if (m.length) p.push(['--members', JSON.stringify(m)]);
  return CX.cliText(p, t.contact_phone ? ['its phone (' + t.contact_phone + ') is in the API call'] : []);
}
CX.type('team', {
  label: 'Team', plural: 'teams', icon: 'people',
  key: function (t) { return String(t.name).toLowerCase(); }, nameOf: function (t) { return t.name; },
  idents: function (t) { return [['Name', t.name, 'people']]; },
  open: function (t, c) { if (c && c.row && c.row.click) c.row.click(); },
  actions: function () { return []; },
  events: function (t) { return t.name; },
  copyData: function (t) { return teamOf(t.name).then(teamData); },
  cli: function (t) { return teamOf(t.name).then(teamCli); },
  curl: function (t) { return teamOf(t.name).then(function (x) { return {method: 'POST', path: 'teams/save', body: Object.assign(teamData(x), {members: arr(x.members)})}; }); },
  mayClone: function () { return FULL() ? '' : NOT_FULL; },
  cloneNote: 'a new team with the same settings and limits - without its members',
  clone: function (t) { return teamOf(t.name).then(function (x) { return teamForm(teamData(x)); }); },
  mayAdd: function () { return FULL(); },
  pasteNew: function (clip) { var it = (clip.items || [])[0]; if (it) return teamForm(it.data, 'A new team as'); },
  paste: {
    teamlimits: {words: 'Paste the limits', off: function () { return FULL() ? '' : NOT_FULL; }, go: function (clip, teams) {
      var lim = obj((clip.items[0] || {}).data && clip.items[0].data.policy);
      CX.bulk({title: 'Give {0} the limits of {1}?'.replace('{0}', teams.map(function (t) { return t.name; }).join(', ')).replace('{1}', CX.clipName(clip)),
               icon: 'shield', button: 'Give them the limits',
               intro: 'The limits of the team are replaced by these: {0}'.replace('{0}', Object.keys(lim).join(', ') || tr('no limit')),
               items: teams.map(function (t) { return {t: t, name: t.name, will: 'its limits replaced'}; }),
               run: function (x) { return api('teams/save', {name: x.t.name, old_name: x.t.name, policy: lim}); },
               done: teamsRedraw});
    }}
  }
});
CX.type('teamlimits', {label: 'Limits of a team', plural: 'limits', icon: 'shield', key: function (x) { return x.name; }, nameOf: function (x) { return x.name; }});
/* a team's own menu: its limits onto the clipboard */
(function () {
  var t = CX.types.team;
  t.actions = function (team) {
    return [{label: 'Copy its limits', icon: 'shield', go: function () {
      return teamOf(team.name).then(function (x) { CX.clipSet('teamlimits', [{name: x.name, id: x.name, data: {policy: obj(x.policy)}}]); });
    }}];
  };
}());
CX.scope({sel: '#tmx-tree', row: '.tmx-row', type: 'team', read: function (row) { return row.dataset.name ? {name: row.dataset.name} : null; }});

function roleOf(name) {
  return teamsData(true).then(function (d) {
    var r = arr(d.roles).filter(function (x) { return x.name === name; })[0];
    if (!r) throw new Error('there is no role {0}'.replace('{0}', name));
    return r;
  });
}
function roleForm(r) {
  var f = {};
  return teamsData(true).then(function (all) {
    modal('A copy of', function (body) {
      body.classList.add('cxc');
      var g = el('div', 'formgrid');
      f.name = textBox(CX.copyName(r.name, taken(all.roles)), '', '');
      noI18n(f.name);
      g.appendChild(formField('Name', f.name, 'Not a name of a built-in role or of an old right.'));
      f.desc = textBox(r.description || '', '', '');
      noI18n(f.desc);
      g.appendChild(formField('What it is for', f.desc));
      body.appendChild(g);
      var caps = el('div', 'cxc-facts');
      caps.appendChild(el('span', 'tag info', '{0} capabilities'.replace('{0}', arr(r.caps).length)));
      arr(r.caps).forEach(function (c) { caps.appendChild(data('span', 'tag dim mono', c)); });
      body.appendChild(caps);
    }, [{words: 'Cancel', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('roles/save', {name: f.name.value.trim(), description: f.desc.value.trim(), caps: arr(r.caps)})
        .then(function (x) { toast((x && x.message) || 'saved', 'good'); closeModal(); teamsRedraw(); })
        .catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
    CX.nameTitle('A copy of', r.name);
  });
}
CX.type('role', {
  label: 'Role', plural: 'roles', icon: 'shield',
  key: function (r) { return r.name; }, nameOf: function (r) { return r.name; },
  idents: function (r) { return [['Name', r.name, 'shield']]; },
  actions: function (r, c) {
    var out = [];
    var th = c && c.row;
    var ed = th && th.querySelector('.tmx-role-edit'), dl = th && th.querySelector('.tmx-role-del');
    if (ed) out.push({label: 'Change this role…', icon: 'edit', go: function () { ed.click(); }});
    if (dl) out.push({label: 'Delete this role…', icon: 'trash', danger: true, go: function () { dl.click(); }});
    return out;
  },
  copyData: function (r) { return roleOf(r.name).then(function (x) { return {name: x.name, description: x.description || '', caps: arr(x.caps)}; }); },
  cli: function (r) { return roleOf(r.name).then(function (x) { var p = [['--role-add', x.name], ['--caps', arr(x.caps).join(',')]]; if (x.description) p.push(['--description', x.description]); return CX.cliText(p); }); },
  curl: function (r) { return roleOf(r.name).then(function (x) { return {method: 'POST', path: 'roles/save', body: {name: x.name, description: x.description || '', caps: arr(x.caps)}}; }); },
  mayClone: function () { return FULL() ? '' : NOT_FULL; },
  clone: function (r, c) {
    var cp = c && c.row && c.row.querySelector('.tmx-role-copy');
    if (cp) { cp.click(); return; }
    return roleOf(r.name).then(roleForm);
  },
  mayAdd: function () { return FULL(); },
  pasteNew: function (clip) { var it = (clip.items || [])[0]; if (it) return roleForm(it.data); }
});
CX.scope({sel: '#tmx-matrix', row: 'thead th[data-role]', type: 'role', read: function (th) { return {name: th.dataset.role}; }});

CX.type('tag', {
  label: 'Tag', plural: 'tags', icon: 'flag',
  key: function (t) { return t.name; }, nameOf: function (t) { return t.name; },
  idents: function (t) { return [['Name', t.name, 'flag']]; },
  rowButtons: true, actions: function () { return []; },
  copyData: function (t) { return {name: t.name, colour: t.colour || '', description: t.description || ''}; },
  cli: function (t) { var p = [['--tag-add', t.name]]; if (t.colour) p.push(['--colour', t.colour]); if (t.description) p.push(['--note', t.description]); return CX.cliText(p); },
  curl: function (t) { return {method: 'POST', path: 'tags/save', body: {name: t.name, colour: t.colour || '', description: t.description || ''}}; },
  events: function (t) { return t.name; }
});
CX.scope({sel: '.tm-tags, #teams-host', row: 'tbody > tr.tm-tagrow', type: 'tag'});

/* ==========================================================================
   Request profiles (reqprofiles.js: its rows and cards carry data-name)
   ========================================================================== */
function profileOf(name) {
  return api('reqprofiles').then(function (d) {
    var p = arr(d.profiles).filter(function (x) { return x.name === name; })[0];
    if (!p) throw new Error('there is no request profile {0}'.replace('{0}', name));
    return p;
  });
}
function profileData(p) {
  var d = CX.scrub(p);
  ['used', 'problems', 'id', 'created', 'updated', 'created_by', 'updated_by', 'version', 'versions'].forEach(function (k) { delete d[k]; });
  return d;
}
function profileSave(d, title) {
  /* title: words, the name of the one it is made from beside them */
  var name = null;
  return api('reqprofiles').then(function (all) {
    modal(title, function (body) {
      body.classList.add('cxc');
      body.appendChild(el('p', 'note', 'A new request profile with these settings, under a name of its own. Open it afterwards to change anything.'));
      name = textBox(CX.copyName(d.name, taken(all.profiles)), '', '');
      noI18n(name);
      body.appendChild(formField('Name', name));
      var facts = el('div', 'cxc-facts');
      if (d.issuer) facts.appendChild(data('span', 'tag info', d.issuer));
      if (d.challenge) facts.appendChild(data('span', 'tag violet', d.challenge));
      arr(d.suffixes).forEach(function (s) { facts.appendChild(data('span', 'tag dim mono', s)); });
      body.appendChild(facts);
    }, [{words: 'Cancel', close: true}, {words: 'Add it', cls: 'primary', icon: 'add', go: function (b) {
      busy(b, true);
      api('reqprofiles/save', Object.assign({}, d, {name: name.value.trim()}))
        .then(function (r) { toast((r && r.message) || 'saved', 'good'); closeModal(); if (window.ACME_EXTRA_PANES && window.ACME_EXTRA_PANES.reqprofiles) window.ACME_EXTRA_PANES.reqprofiles(); })
        .catch(oops).then(function () { busy(b, false); });
    }}], 'medium');
    CX.nameTitle(title, d.name);
  });
}
CX.type('reqprofile', {
  label: 'Request profile', plural: 'request profiles', icon: 'list',
  key: function (p) { return p.name; }, nameOf: function (p) { return p.name; },
  idents: function (p) { return [['Name', p.name, 'list']]; },
  actions: function (p, c) {
    var row = c && c.row;
    var out = [];
    var ed = row && row.querySelector('.rp-edit'), del = row && row.querySelector('.rp-del');
    out.push({label: 'Edit…', icon: 'edit', off: ed ? '' : NOT_FULL, go: function () { ed.click(); }});
    out.push({label: 'Delete…', icon: 'trash', danger: true, off: del ? '' : NOT_FULL, go: function () { del.click(); }});
    return out;
  },
  open: function (p, c) { var ed = c && c.row && c.row.querySelector('.rp-edit'); if (ed) ed.click(); else if (c && c.row) c.row.click(); },
  events: function (p) { return p.name; },
  copyData: function (p) { return profileOf(p.name).then(profileData); },
  cli: function (p) {
    return profileOf(p.name).then(function (x) {
      return 'acme --api POST /api/reqprofiles/save - <<\'JSON\'\n' + JSON.stringify(profileData(x), null, 2) + '\nJSON\n'
        + '# a request profile has no option of its own: the route of the page, run as the command line\n';
    });
  },
  curl: function (p) { return profileOf(p.name).then(function (x) { return {method: 'POST', path: 'reqprofiles/save', body: profileData(x)}; }); },
  mayClone: function () { return FULL() ? '' : NOT_FULL; },
  clone: function (p, c) {
    var dup = c && c.row && c.row.querySelector('.rp-dup');
    if (dup) { dup.click(); return; }
    return profileOf(p.name).then(function (x) { return profileSave(profileData(x), 'A copy of'); });
  },
  mayAdd: function () { return FULL(); },
  add: function () { var b = document.getElementById('rp-add'); if (b) b.click(); },
  addWords: 'Add a request profile…',
  pasteNew: function (clip) { var it = (clip.items || [])[0]; if (it) return profileSave(it.data, 'A new request profile as'); }
});
CX.scope({sel: '#rp-host', row: '.rp-row', type: 'reqprofile', area: '#pane-reqprofiles', read: function (row) { return row.dataset.name ? (row._rec || {name: row.dataset.name}) : null; }});

/* ==========================================================================
   DNS sets (dnssets.js lends its form: ACME_DNSSETS)
   ========================================================================== */
function dnsData(s) { return {name: s.name, servers: arr(s.servers), protocol: s.protocol || 'udp', tls_name: s.tls_name || '', timeout: s.timeout || 3, note: s.note || ''}; }
CX.type('dnsset', {
  label: 'DNS set', plural: 'DNS sets', icon: 'globe',
  key: function (s) { return s.name; }, nameOf: function (s) { return s.name; },
  idents: function (s) { return [['Name', s.name, 'globe'], ['Servers', arr(s.servers).join(', '), 'net']]; },
  rowButtons: true, actions: function () { return []; },
  copyData: dnsData,
  cli: function (s) {
    var p = [['--dns-set-add', s.name], ['--servers', arr(s.servers).join(',')]];
    if (s.protocol && s.protocol !== 'udp') p.push(['--protocol', s.protocol]);
    if (s.tls_name) p.push(['--tls-name', s.tls_name]);
    if (s.timeout) p.push(['--dns-timeout', String(s.timeout)]);
    if (s.note) p.push(['--note', s.note]);
    return CX.cliText(p);
  },
  curl: function (s) { return {method: 'POST', path: 'dnssets/save', body: dnsData(s)}; },
  events: function (s) { return s.name; },
  mayClone: function () { return FULL() ? '' : NOT_FULL; },
  clone: function (s) { return dnsClone(dnsData(s)); },
  mayAdd: function () { return FULL(); },
  pasteNew: function (clip) { var it = (clip.items || [])[0]; if (it) return dnsClone(it.data); }
});
function dnsClone(d) {
  if (!window.ACME_DNSSETS) return;
  return api('dnssets').then(function (all) {
    window.ACME_DNSSETS.edit(null, Object.assign({}, d, {name: CX.copyName(d.name, taken(all.sets)), builtin: false, keep: false}));
  });
}
CX.scope({sel: '#pane-dnssets', row: 'table.dnss-sets > tbody > tr', type: 'dnsset', area: '#pane-dnssets .dnss'});

/* ==========================================================================
   Target agents (agents.js): a tile and a row of the servers' table are a target
   ========================================================================== */
function agentRead(row) {
  var n = row.querySelector('.dbs-tile-n, .ag-srv-name span');
  if (!n) return null;
  var name = n.textContent.trim();
  var h = H();
  var have = h && h.LISTS.targets ? h.LISTS.targets.filter(function (x) { return x.name === name; })[0] : null;
  return have || {name: name, kind: 'agent'};
}
CX.scope({sel: '#ag-list', row: '.ag-tile', type: 'target', read: agentRead});
CX.scope({sel: '#ag-list', row: 'table.ag-srv-t > tbody > tr', type: 'target', read: agentRead});

/* ==========================================================================
   The administration's own tables (admin.js)
   ========================================================================== */
CX.type('osuser', {
  label: 'User of the nodes', plural: 'users of the nodes', icon: 'person',
  key: function (u) { return u.name; }, nameOf: function (u) { return u.name; },
  idents: function (u) { return [['Name', u.name, 'person'], ['UID', u.uid, 'info']]; },
  rowButtons: true, actions: function () { return []; },
  copyData: function (u) { return {name: u.name, gecos: u.gecos || '', shell: u.shell || '', sudo: !!u.sudo}; },
  curl: function (u) { return {method: 'POST', path: 'osusers', body: {action: 'add', name: u.name, gecos: u.gecos || '', shell: u.shell || '', password: FILL, must_change: true, sudo: !!u.sudo, nodes: [FILL]}}; },
  events: function (u) { return u.name; },
  mayClone: function (u) { return !FULL() ? NOT_FULL : (u.root ? 'root is changed only on the machine itself' : ''); },
  cloneNote: 'a new user with the same full name, shell and sudo - and a password of its own',
  clone: function (u) { if (typeof osuAdd === 'function') osuAdd(undefined, u); },
  mayAdd: function () { return FULL(); },
  pasteNew: function (clip) { var it = (clip.items || [])[0]; if (it && typeof osuAdd === 'function') osuAdd(undefined, it.data); }
});
CX.scope({sel: '.osu-card', row: 'table.osu-table > tbody > tr', type: 'osuser', area: '.osu-card', read: function (row) {
  var n = row.querySelector('.osu-name');
  if (!n) return null;
  var name = n.textContent.trim();
  var u = {name: name};
  try { if (typeof osuRows === 'function' && typeof osuAny === 'function') u = Object.assign({}, osuAny(osuRows().by[name] || {}), {name: name}); } catch (e) { }
  return u;
}});

/* ==========================================================================
   Where the certificate manager's rows are
   ========================================================================== */
function certFilter(w) {
  var c = w.obj, box = document.getElementById('ct-q');
  if (!c || !box || !w.th) return null;
  var col = String(w.th.dataset.ck || '').toLowerCase();
  var q = function (v) { v = String(v); return /[\s(),"]/.test(v) ? '"' + v.replace(/"/g, '') + '"' : v; };
  if (col === 'state') return {box: box, term: 'state:' + c.state};
  if (col === 'name') return {box: box, term: 'name:' + q(c.name), shown: c.name};
  if (col === 'names') {
    var chip = w.target && w.target.closest && w.target.closest('.ct-name, .mono, span');
    var n = chip && arr(c.names).indexOf(chip.textContent.trim()) >= 0 ? chip.textContent.trim() : (arr(c.names)[0] || c.cn);
    return n ? {box: box, term: 'dns:' + q(n), shown: n} : null;
  }
  if (col === 'source') return c.issuer ? {box: box, term: 'source:' + q(c.issuer), shown: c.issuer} : null;
  if (col === 'renews') return {box: box, term: 'renew:' + (c.auto_renew === 0 || c.auto_renew === false ? 'no' : 'yes')};
  return null;
}
CX.scope({sel: '#ct-table', type: 'cert', filter: certFilter, paged: true, area: '#tab-certs .card'});
function modFilter(key) {
  return function (w) {
    var r = w.obj, box = document.getElementById({targets: 'tg-q', sources: 'src-q', validation: 'val-q', tests: 'ts-q'}[key]);
    if (!r || !box || !w.th) return null;
    var col = String(w.th.dataset.ck || '').toLowerCase();
    var q = function (v) { v = String(v); return /[\s(),"]/.test(v) ? '"' + v.replace(/"/g, '') + '"' : v; };
    if (col === 'name') return {box: box, term: 'name:' + q(r.name), shown: r.name};
    if (col === 'kind') return {box: box, term: 'kind:' + q(r.kind), shown: r.title || r.kind};
    if (col === 'state') {
      var off = r.enabled !== undefined && !(r.enabled === 1 || r.enabled === true);
      return off ? {box: box, term: 'on:no'} : {box: box, term: 'state:' + (r.last_error ? 'failing' : (r.last_ok ? 'ok' : '"never tried"'))};
    }
    return null;
  };
}
CX.scope({sel: '#tg-list', type: 'target', filter: modFilter('targets'), area: '#tab-targets .card'});
CX.scope({sel: '#src-list', type: 'source', filter: modFilter('sources'), area: '#tab-sources .card'});
CX.scope({sel: '#val-list', type: 'validation', filter: modFilter('validation'), area: '#tab-validation .card'});
CX.scope({sel: '#ts-list', type: 'test', filter: modFilter('tests'), area: '#tab-tests .card'});
CX.scope({sel: '#jb-table', type: 'job', paged: true});
CX.scope({sel: 'table.ct-jobs', type: 'job'});
CX.scope({sel: 'table.ct-deptable', type: 'deployment', read: function (row) { var r = row._rec; return r && r.target ? r : null; }});

/* ==========================================================================
   Events (admin.js): filtered by the page's own search (kind:, who:, node:)
   ========================================================================== */
CX.type('event', {
  label: 'Event', plural: 'events', icon: 'history',
  key: function (r) { return String(r.id || (r.ts + ':' + r.words)); }, nameOf: function (r) { return r.kind || ''; },
  idents: function (r) { return [['What it says', r.words, 'list'], ['Who', r.who, 'person']]; },
  rowButtons: true, actions: function () { return []; }
});
CX.scope({sel: '#ev-table', type: 'event', paged: true, filter: function (w) {
  var r = w.obj, box = document.getElementById('ev-q');
  if (!r || !box || !w.th) return null;
  var col = String(w.th.dataset.ck || '').toLowerCase();
  var q = function (v) { v = String(v); return /[\s(),"]/.test(v) ? '"' + v.replace(/"/g, '') + '"' : v; };
  if (col === 'kind' && r.kind) return {box: box, term: 'kind:' + q(r.kind), shown: textOfCell(w.cell) || r.kind};
  if (col === 'who' && r.who) return {box: box, term: 'who:' + q(r.who), shown: r.who};
  if (col === 'node' && r.node) return {box: box, term: 'node:' + q(r.node), shown: r.node};
  return null;
}});
function textOfCell(c) { return c ? String(c.textContent || '').replace(/\s+/g, ' ').trim() : ''; }

}());
