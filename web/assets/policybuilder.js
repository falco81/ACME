/* policybuilder.js - the policy builder of a target with acme-agent (1.0.118,
   docs/target-agent.md "Designing the policy"): the admin clicks the whole policy together -
   templates, what the target's deployments need, folders, units, tests, scripts, addresses,
   probes, connections, self-update, limits - checked live as the agent checks it
   (acme-agent policy check: the same lists, handed by acme from the agent's own program), and
   gets the policy FILE in the agent's own format, the `acme-agent allow` lines, and one block
   to paste on the server (acme-agent policy apply - <<'EOF'). acme never sends a policy: the
   server's root writes it. The design can be kept with the target in acme (documentation).

   Two halves: CORE (no page - node runs it in the tests: the same text the builder shows) and
   the builder itself. agents.js opens it: ACME_POLICY_BUILDER.open(row, opts). */
(function (root) {
'use strict';

/* =============================================================================================
   CORE - the policy as the agent reads and writes it (deploy/agent/acme_agent.py)
   ============================================================================================= */
var F = {
  protected: [], parts: ['.ssh'], own: ['/etc/acme-agent', '/var/lib/acme-agent', '/var/lib/acme-agent-root', '/run/acme-agent'],
  verbs: ['reload', 'restart', 'try-reload-or-restart', 'reload-or-restart', 'try-restart'],
  shells: ['sh', 'bash', 'dash', 'zsh', 'ksh', 'mksh', 'csh', 'tcsh', 'fish', 'busybox', 'python', 'python3', 'perl', 'ruby', 'php', 'node'],
  config_ok: ['/etc/ssl', '/etc/pki'], head: '',
  limits: {files: 20, size: 1048576, files_most: 200, size_most: 67108864}
};
function setFacts(f) { Object.keys(f || {}).forEach(function (k) { F[k] = f[k]; }); }

function Bad(words) { this.words = words; }
function arr(v) { return Array.isArray(v) ? v : []; }
function oct4(n) { return ('000' + (Number(n) || 0).toString(8)).slice(-4); }
/* shlex.quote */
function quote(s) {
  s = String(s);
  if (!s) return "''";
  if (!/[^\w@%+=:,.\/-]/.test(s)) return s;
  return "'" + s.replace(/'/g, "'\"'\"'") + "'";
}
/* shlex.split (posix, no comments) */
function split(text) {
  var out = [], cur = null, i = 0, t = String(text || '');
  while (i < t.length) {
    var c = t[i];
    if (/\s/.test(c)) { if (cur !== null) { out.push(cur); cur = null; } i++; continue; }
    if (cur === null) cur = '';
    if (c === "'") {
      var j = t.indexOf("'", i + 1);
      if (j < 0) throw new Bad('No closing quotation');
      cur += t.slice(i + 1, j); i = j + 1; continue;
    }
    if (c === '"') {
      i++;
      var closed = false;
      while (i < t.length) {
        var d = t[i];
        if (d === '\\' && i + 1 < t.length && (t[i + 1] === '"' || t[i + 1] === '\\')) { cur += t[i + 1]; i += 2; continue; }
        if (d === '"') { closed = true; i++; break; }
        cur += d; i++;
      }
      if (!closed) throw new Bad('No closing quotation');
      continue;
    }
    if (c === '\\') {
      if (i + 1 >= t.length) throw new Bad('No escaped character');
      cur += t[i + 1]; i += 2; continue;
    }
    cur += c; i++;
  }
  if (cur !== null) out.push(cur);
  return out;
}
function normPath(p) {
  var parts = [];
  String(p).split('/').forEach(function (x) {
    if (x === '' || x === '.') return;
    if (x === '..') { parts.pop(); return; }
    parts.push(x);
  });
  return '/' + parts.join('/');
}
/* norm_dir(real=False) */
function normDir(path) {
  var p = String(path === undefined || path === null ? '' : path).trim();
  if (!/^\/[^\x00-\x1f\x7f]{0,1023}$/.test(p) || p.indexOf('\\') >= 0) throw new Bad(JSON.stringify(p.slice(0, 120)) + ' is not an absolute path');
  var parts = p.split('/').filter(function (x) { return x !== '' && x !== '.'; });
  if (parts.indexOf('..') >= 0) throw new Bad('a path with .. in it: ' + p.slice(0, 120));
  return '/' + parts.join('/');
}
function under(path, top) {
  top = top.replace(/\/+$/, '') || '/';
  if (top === '/') return false;
  return path === top || path.indexOf(top + '/') === 0;
}
/* protected(): why a job never writes there, whatever the policy says - or '' */
function protectedWhy(path) {
  var i;
  for (i = 0; i < F.own.length; i++) {
    if (under(path, F.own[i])) return path + ' is acme-agent\'s own (' + F.own[i] + ') - never written by a job';
  }
  for (i = 0; i < F.protected.length; i++) {
    if (under(path, F.protected[i])) return path + ' is under ' + F.protected[i] + ' - a file there gives root to whoever writes it; acme-agent never writes there, whatever the policy says';
  }
  if (path.split('/').some(function (x) { return F.parts.indexOf(x) >= 0; })) return path + ' is in a .ssh folder - acme-agent never writes there';
  return '';
}
var OWNER_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$/;
var UNIT_RE = /^[A-Za-z0-9:_.@\\-]{1,128}$/;
var HOST_RE = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$/;
var HEX64 = /^[0-9a-f]{64}$/;
function normUnit(name) {
  name = String(name || '').trim();
  if (!UNIT_RE.test(name) || name[0] === '-') throw new Bad(JSON.stringify(name.slice(0, 80)) + ' is not a unit name');
  var tail = name.split('@').pop();
  if (tail.indexOf('.') < 0) name += '.service';
  return name;
}
function checkArgv(argv) {
  if (!Array.isArray(argv) || !argv.length || argv.length > 64) throw new Bad('a command is one to 64 words');
  var n = 0;
  argv.forEach(function (a) {
    a = String(a);
    if (!a || a.length > 1024 || /[\x00-\x1f\x7f]/.test(a)) throw new Bad('a word of a command holds a control character or is empty');
    n += a.length;
  });
  if (n > 4096) throw new Bad('a command is 4096 characters at most');
  return argv.map(String);
}
/* ipaddress: an address (str(ip_address)) or null */
function ip4(t) {
  var p = t.split('.');
  if (p.length !== 4) return null;
  var out = [];
  for (var i = 0; i < 4; i++) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p[i]) || Number(p[i]) > 255) return null;
    out.push(Number(p[i]));
  }
  return out;
}
function ip6(t) {
  if (!/^[0-9a-fA-F:.]+$/.test(t) || t.indexOf(':') < 0) return null;
  var tail4 = null;
  var m = t.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) { tail4 = ip4(m[2]); if (!tail4) return null; t = m[1] + '0:0'; }
  var halves = t.split('::');
  if (halves.length > 2) return null;
  var conv = function (s) { return s === '' ? [] : s.split(':'); };
  var a = conv(halves[0]), b = halves.length === 2 ? conv(halves[1]) : [];
  var all = a.concat(b);
  if (all.some(function (x) { return !/^[0-9a-fA-F]{1,4}$/.test(x); })) return null;
  var groups;
  if (halves.length === 2) {
    if (all.length > 7) return null;
    groups = a.concat(new Array(8 - all.length).fill('0'), b);
  } else {
    if (a.length !== 8) return null;
    groups = a;
  }
  var nums = groups.map(function (x) { return parseInt(x, 16); });
  if (tail4) { nums[6] = tail4[0] * 256 + tail4[1]; nums[7] = tail4[2] * 256 + tail4[3]; }
  return nums;
}
function ip6str(nums) {
  var best = -1, bestLen = 0, i = 0;
  while (i < 8) {
    if (nums[i] === 0) {
      var j = i;
      while (j < 8 && nums[j] === 0) j++;
      if (j - i > bestLen) { best = i; bestLen = j - i; }
      i = j;
    } else i++;
  }
  var h = nums.map(function (x) { return x.toString(16); });
  if (bestLen > 1) {
    var left = h.slice(0, best).join(':'), right = h.slice(best + bestLen).join(':');
    return left + '::' + right;
  }
  return h.join(':');
}
function ipAddress(t) {
  var v4 = ip4(t);
  if (v4) return v4.join('.');
  var v6 = ip6(t);
  return v6 ? ip6str(v6) : null;
}
/* str(ipaddress.ip_network(t, strict=False)) */
function ipNetwork(text) {
  var t = String(text || '').trim(), m = t.match(/^([^/]+)(?:\/(\d{1,3}))?$/);
  var bad = new Bad(JSON.stringify(t.slice(0, 60)) + ' is not an address or a network');
  if (!m) throw bad;
  var v4 = ip4(m[1]);
  if (v4) {
    var n = m[2] === undefined ? 32 : Number(m[2]);
    if (n > 32 || (m[2] !== undefined && !/^(0|[1-9][0-9]?)$/.test(m[2]))) throw bad;
    var v = ((v4[0] << 24) >>> 0) + (v4[1] << 16) + (v4[2] << 8) + v4[3];
    var mask = n === 0 ? 0 : ((0xffffffff << (32 - n)) >>> 0);
    v = (v & mask) >>> 0;
    return [v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255].join('.') + '/' + n;
  }
  var v6 = ip6(m[1]);
  if (v6) {
    var k = m[2] === undefined ? 128 : Number(m[2]);
    if (k > 128 || (m[2] !== undefined && !/^(0|[1-9][0-9]{0,2})$/.test(m[2]))) throw bad;
    var out = v6.map(function (g, i) {
      var bits = Math.max(0, Math.min(16, k - i * 16));
      return bits === 0 ? 0 : (g & ((0xffff << (16 - bits)) & 0xffff));
    });
    return ip6str(out) + '/' + k;
  }
  throw bad;
}
/* norm_hostport */
function normHostport(text) {
  var t = String(text || '').trim();
  var m = t.match(/^\[([0-9A-Fa-f:.]+)\]:([0-9]{1,5})$/) || t.match(/^([^\s:\[\]]+):([0-9]{1,5})$/);
  if (!m) throw new Bad(JSON.stringify(t.slice(0, 80)) + ' is not HOST:PORT ([v6 address]:PORT for IPv6)');
  var host = m[1].toLowerCase().replace(/\.+$/, ''), port = Number(m[2]);
  if (!(port > 0 && port < 65536)) throw new Bad(port + ' is not a port');
  var ip = ipAddress(host);
  if (ip) host = ip;
  else if (!HOST_RE.test(host) || host[0] === '-' || host.indexOf('..') >= 0) throw new Bad(JSON.stringify(host.slice(0, 80)) + ' is not a host name or an address');
  return host.indexOf(':') >= 0 ? '[' + host + ']:' + port : host + ':' + port;
}
function shellLine(argv) {
  var prog = String(argv[0] || '').split('/').pop();
  prog = prog.replace(/[0-9.]+$/, '') || prog;
  return F.shells.indexOf(prog) >= 0 && argv.slice(1).some(function (a) { return ['-c', '-e', '-E', '--command', '--eval'].indexOf(a) >= 0; });
}

/* ---- the builder's state ------------------------------------------------------------------ */
function empty() {
  return {files: [], units: [], tests: [], scripts: [], hashes: [], from: [], probe_local: false, probe: [],
    connect_on: false, connect: [], self_update: false, limits: {files: F.limits.files, size: F.limits.size}};
}
/** The state of a policy the agent said (policy_report). */
function fromPolicy(p) {
  var s = empty();
  if (!p) return s;
  s.files = arr(p.files).map(function (f) { return {dir: String(f.dir), owner: String(f.owner || 'root'), group: String(f.group || f.owner || 'root'), mode: Number(f.mode) & 511}; });
  s.units = Object.keys(p.units || {}).sort().map(function (u) { return {name: u, verbs: arr(p.units[u]).slice()}; });
  s.tests = arr(p.tests).map(function (t) { return arr(t).map(String); });
  s.scripts = arr(p.scripts).map(function (x) { return {path: String(x.path), sha256: String(x.sha256 || '')}; });
  s.hashes = arr(p.script_hashes).map(String);
  s.from = arr(p.from).map(String);
  s.probe_local = !!p.probe_local;
  s.probe = arr(p.probe).map(String);
  s.connect = arr(p.connect).map(String);
  s.connect_on = s.connect.length > 0;
  s.self_update = !!p.self_update;
  if (p.limits) s.limits = {files: Number(p.limits.files) || F.limits.files, size: Number(p.limits.size) || F.limits.size};
  return s;
}
/** A state kept (a design's): of the shapes the builder draws. */
function fromSaved(x) {
  var s = empty();
  if (!x || typeof x !== 'object') return s;
  s.files = arr(x.files).filter(function (f) { return f && typeof f === 'object'; }).map(function (f) {
    return {dir: String(f.dir || ''), owner: String(f.owner || ''), group: String(f.group || ''), mode: Number(f.mode) & 511};
  });
  s.units = arr(x.units).filter(function (u) { return u && typeof u === 'object'; }).map(function (u) { return {name: String(u.name || ''), verbs: arr(u.verbs).map(String)}; });
  s.tests = arr(x.tests).map(function (t) { return Array.isArray(t) ? t.map(String) : split(String(t)); });
  s.scripts = arr(x.scripts).filter(function (u) { return u && typeof u === 'object'; }).map(function (u) { return {path: String(u.path || ''), sha256: String(u.sha256 || '')}; });
  ['hashes', 'from', 'probe', 'connect'].forEach(function (k) { s[k] = arr(x[k]).map(String); });
  s.probe_local = !!x.probe_local;
  s.self_update = !!x.self_update;
  s.connect_on = !!x.connect_on || s.connect.length > 0;
  if (x.limits && typeof x.limits === 'object') s.limits = {files: Number(x.limits.files) || F.limits.files, size: Number(x.limits.size) || F.limits.size};
  return s;
}
function clone(s) { return JSON.parse(JSON.stringify(s)); }

/* ---- every item checked as the agent checks it ---------------------------------------------- */
function msg(level, code, words) { return {level: level, code: code, words: words}; }
function verdict(msgs) {
  var lv = 'ok';
  msgs.forEach(function (m) { if (m.level === 'bad') lv = 'bad'; else if (m.level === 'warn' && lv !== 'bad') lv = 'warn'; });
  return {level: lv, msgs: msgs};
}
/**
 * The whole state checked -> {files: [verdict], units, tests, scripts, hashes, from, probe,
 * connect, limits: {files, size}, lines: [the policy's lines], pins: [scripts without a hash],
 * counts: {entries, warn, bad}} - the agent's own words (acme-agent policy check).
 */
function check(s) {
  var R = {files: [], units: [], tests: [], scripts: [], hashes: [], from: [], probe: [], connect: [], limits: {}, pins: []};
  var pol = {files: [], units: {}, tests: [], scripts: [], hashes: [], from: [], probe: [], connect: []};
  var tops = F.protected.concat(F.own);
  var lastDir = {};
  /* folders: the last of one folder counts (as the agent reads it) */
  s.files.forEach(function (f, i) {
    var m = [], d = null;
    try {
      d = normDir(f.dir);
      if (d === '/') throw new Bad('the whole file system is no folder to allow');
      if (!OWNER_RE.test(String(f.owner || '')) || !OWNER_RE.test(String(f.group || ''))) throw new Bad('owner=USER:GROUP');
      var mode = Number(f.mode);
      if (!(mode >= 0 && mode <= 511)) throw new Bad('a mode is three octal digits (0640): ' + mode);
      var why = protectedWhy(d);
      if (why) {
        m.push(msg('bad', 'protected', why.replace(' - never written by a job', ' - no job ever writes there')));
        d = null;
      }
    } catch (e) {
      if (!(e instanceof Bad)) throw e;
      m.push(msg('bad', 'unread', e.words));
      d = null;
    }
    R.files.push({msgs: m, dir: d});
    if (d !== null) lastDir[d] = i;
  });
  s.files.forEach(function (f, i) {
    var r = R.files[i];
    if (r.dir === null) { R.files[i] = verdict(r.msgs); return; }
    var d = r.dir;
    if (lastDir[d] !== i) r.msgs.push(msg('warn', 'twice', 'files in ' + d + ' are said twice: only the last one counts'));
    else pol.files.push({dir: d, owner: String(f.owner), group: String(f.group), mode: Number(f.mode)});
    var und = tops.filter(function (t) { return under(t, d) && t !== d; });
    if (und.length) {
      r.msgs.push(msg('warn', 'above-protected', d + ' holds places no job ever writes (' + und.slice(0, 3).join(', ') + (und.length > 3 ? ' …' : '') + '): the rest of it is allowed - allow the narrowest folder that holds only certificates'));
    } else if (/^\/etc\/[^\/]+$/.test(d) && F.config_ok.indexOf(d) < 0) {
      r.msgs.push(msg('warn', 'config-folder', d + ' is a folder of configuration: acme could write a file the service then reads as root - allow its ssl or certs sub-folder where it can'));
    }
    if (Number(f.mode) & 73) r.msgs.push(msg('warn', 'exec-bits', 'mode ' + oct4(f.mode) + ': no file acme-agent writes is ever executable - its x bits are never given (' + oct4(Number(f.mode) & 438) + ' is what a file gets at most)'));
    R.files[i] = verdict(r.msgs);
  });
  var dirs = pol.files.map(function (f) { return f.dir; });
  function inside(p) { return dirs.filter(function (d) { return under(p, d) && p !== d; }); }
  /* units */
  s.units.forEach(function (u) {
    var m = [];
    try {
      var verbs = arr(u.verbs).filter(Boolean);
      var badv = verbs.filter(function (v) { return F.verbs.indexOf(v) < 0 && v !== 'is-active'; });
      if (badv.length || !verbs.length) throw new Bad('the verbs are ' + F.verbs.join(', '));
      var name = normUnit(u.name);
      var have = pol.units[name] || (pol.units[name] = []);
      verbs.forEach(function (v) { if (have.indexOf(v) < 0) have.push(v); });
    } catch (e) {
      if (!(e instanceof Bad)) throw e;
      m.push(msg('bad', 'unread', e.words));
    }
    R.units.push(verdict(m));
  });
  /* tests */
  var seenT = {};
  s.tests.forEach(function (t) {
    var m = [];
    try {
      /* a line typed that does not split (an open quotation): red, and left out - never the
         line it was before standing in the file for it */
      var argv = checkArgv(Array.isArray(t) ? t : split(String(t)));
      var k = JSON.stringify(argv);
      if (seenT[k]) m.push(msg('warn', 'twice', 'this command line is said twice'));
      else { seenT[k] = 1; pol.tests.push(argv); }
      if (shellLine(argv)) m.push(msg('warn', 'shell', argv.slice(0, 3).map(quote).join(' ') + ' runs what its command line says as root - a fixed script (allow script) says what it runs'));
      argv.forEach(function (w) {
        if (w[0] === '/' && inside(normPath(w)).length) m.push(msg('warn', 'runs-from', w + ' is in a folder allowed for files (' + inside(normPath(w))[0] + '): the test runs it, so a job never writes it'));
      });
    } catch (e) {
      if (!(e instanceof Bad)) throw e;
      m.push(msg('bad', 'unread', e.words));
    }
    R.tests.push(verdict(m));
  });
  /* scripts: by path, the last of one path counts; one without its hash is pinned on the server */
  var lastScript = {}, sp = [];
  s.scripts.forEach(function (x, i) {
    var p = null;
    try { p = normDir(x.path); } catch (e) { if (!(e instanceof Bad)) throw e; sp.push(e.words); return; }
    sp.push(null);
    lastScript[p] = i;
  });
  s.scripts.forEach(function (x, i) {
    var m = [];
    if (sp[i]) { R.scripts.push(verdict([msg('bad', 'unread', sp[i])])); return; }
    var p = normDir(x.path), h = String(x.sha256 || '').trim().toLowerCase();
    if (lastScript[p] !== i) m.push(msg('warn', 'twice', 'the script ' + p + ' is said twice: only the last one counts'));
    if (h && !HEX64.test(h)) m.push(msg('bad', 'unread', 'allow script PATH sha256=HEX (acme-agent allow script PATH pins it)'));
    else if (lastScript[p] === i) {
      if (h) pol.scripts.push({path: p, sha256: h});
      else { m.push(msg('info', 'pin', 'pinned on the server: sudo acme-agent allow script ' + quote(p))); R.pins.push(p); }
    }
    if (inside(p).length) m.push(msg('warn', 'runs-from', p + ' is in a folder allowed for files (' + inside(p)[0] + '): the policy runs it, so a job never writes it'));
    R.scripts.push(verdict(m));
  });
  s.hashes.forEach(function (h) {
    h = String(h || '').trim().toLowerCase();
    if (!HEX64.test(h)) { R.hashes.push(verdict([msg('bad', 'unread', 'allow script-hash HEX (64 hex digits, sha256)')])); return; }
    if (pol.hashes.indexOf(h) < 0) pol.hashes.push(h);
    R.hashes.push(verdict([]));
  });
  s.from.forEach(function (a) {
    try {
      var n = ipNetwork(a);
      if (pol.from.indexOf(n) < 0) pol.from.push(n);
      R.from.push(verdict([]));
    } catch (e) { if (!(e instanceof Bad)) throw e; R.from.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  s.probe.forEach(function (a) {
    try {
      var n = normHostport(a);
      if (pol.probe.indexOf(n) < 0) pol.probe.push(n);
      R.probe.push(verdict([]));
    } catch (e) { if (!(e instanceof Bad)) throw e; R.probe.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  (s.connect_on ? s.connect : []).forEach(function (a) {
    try {
      var n = normHostport(a);
      if (pol.connect.indexOf(n) < 0) pol.connect.push(n);
      R.connect.push(verdict([msg('warn', 'connect', 'acme may reach ' + n + ' through this server (a connector of SSH targets)')]));
    } catch (e) { if (!(e instanceof Bad)) throw e; R.connect.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  ['files', 'size'].forEach(function (k) {
    var v = Number(s.limits && s.limits[k]), top = k === 'files' ? F.limits.files_most : F.limits.size_most;
    R.limits[k] = (Math.floor(v) === v && v >= 1 && v <= top) ? verdict([]) : verdict([msg('bad', 'unread', 'limit ' + k + ' is 1 to ' + top)]);
  });
  /* the lines, as policy_lines writes them */
  var L = [];
  pol.files.forEach(function (f) { L.push('allow file ' + quote(f.dir) + ' owner=' + f.owner + ':' + f.group + ' mode=' + oct4(f.mode)); });
  Object.keys(pol.units).sort().forEach(function (u) { L.push('allow unit ' + u + ' ' + pol.units[u].join(',')); });
  pol.tests.forEach(function (t) { L.push('allow test -- ' + t.map(quote).join(' ')); });
  pol.scripts.forEach(function (x) { L.push('allow script ' + quote(x.path) + ' sha256=' + x.sha256); });
  pol.hashes.forEach(function (h) { L.push('allow script-hash ' + h); });
  pol.from.forEach(function (f) { L.push('allow from ' + f); });
  if (s.probe_local) L.push('allow probe local');
  pol.probe.forEach(function (c) { L.push('allow probe ' + c); });
  pol.connect.forEach(function (c) { L.push('allow connect ' + c); });
  if (s.self_update) L.push('allow self-update');
  if (R.limits.files.level === 'ok' && Number(s.limits.files) !== F.limits.files) L.push('limit files ' + Number(s.limits.files));
  if (R.limits.size.level === 'ok' && Number(s.limits.size) !== F.limits.size) L.push('limit size ' + Number(s.limits.size));
  R.lines = L;
  R.pol = pol;
  var counts = {entries: L.length, warn: 0, bad: 0};
  ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect'].forEach(function (k) {
    R[k].forEach(function (v) { if (v.level === 'bad') counts.bad++; else if (v.level === 'warn') counts.warn++; });
  });
  ['files', 'size'].forEach(function (k) { if (R.limits[k].level === 'bad') counts.bad++; });
  R.counts = counts;
  return R;
}
/** The policy file, as the agent writes it (its head, then the lines). */
function fileText(R) { return F.head + (R.lines.length ? R.lines.join('\n') + '\n' : ''); }
/** The same as `sudo acme-agent allow ...` lines (each adds to what is there). */
function allowLines(R) {
  var p = R.pol, out = [];
  p.files.forEach(function (f) { out.push('sudo acme-agent allow file ' + quote(f.dir) + ' --owner ' + f.owner + ':' + f.group + ' --mode ' + oct4(f.mode)); });
  Object.keys(p.units).sort().forEach(function (u) { out.push('sudo acme-agent allow unit ' + u + ' ' + p.units[u].join(',')); });
  p.tests.forEach(function (t) { out.push('sudo acme-agent allow test -- ' + t.map(quote).join(' ')); });
  p.scripts.map(function (x) { return x.path; }).concat(R.pins).forEach(function (x) { out.push('sudo acme-agent allow script ' + quote(x)); });
  p.hashes.forEach(function (h) { out.push('sudo acme-agent allow script-hash ' + h); });
  p.from.forEach(function (f) { out.push('sudo acme-agent allow from ' + f); });
  R.lines.forEach(function (l) {
    if (l.indexOf('allow probe ') === 0 || l.indexOf('allow connect ') === 0 || l === 'allow self-update') out.push('sudo acme-agent ' + l);
    if (l.indexOf('limit ') === 0) out.push('sudo acme-agent ' + l);
  });
  return out;
}
/** One block to paste on the server: the whole policy written (checked first there). */
function oneShot(R) {
  return "sudo acme-agent policy apply - <<'EOF'\n" + fileText(R) + 'EOF' +
    (R.pins.length ? '\n' + R.pins.map(function (p) { return 'sudo acme-agent allow script ' + quote(p); }).join('\n') : '');
}
/** The lines of two policies compared: [{op: ' '|'+'|'-', line}] (longest common run). */
function diff(a, b) {
  var n = a.length, m = b.length, i, j, t = [];
  for (i = 0; i <= n; i++) { t.push(new Array(m + 1).fill(0)); }
  for (i = n - 1; i >= 0; i--) for (j = m - 1; j >= 0; j--) t[i][j] = a[i] === b[j] ? t[i + 1][j + 1] + 1 : Math.max(t[i + 1][j], t[i][j + 1]);
  var out = [];
  i = 0; j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { out.push({op: ' ', line: a[i]}); i++; j++; }
    else if (t[i + 1][j] >= t[i][j + 1]) { out.push({op: '-', line: a[i]}); i++; }
    else { out.push({op: '+', line: b[j]}); j++; }
  }
  for (; i < n; i++) out.push({op: '-', line: a[i]});
  for (; j < m; j++) out.push({op: '+', line: b[j]});
  return out;
}

/* ---- what a deployment needs, against the state ------------------------------------------------ */
function deepest(R, path) {
  var best = null;
  R.pol.files.forEach(function (f) { if (path.indexOf(f.dir.replace(/\/+$/, '') + '/') === 0 && (!best || f.dir.length > best.dir.length)) best = f; });
  return best;
}
/** 'yes' (the state allows it), 'no' (add it), or the words why no policy ever allows it. */
function covers(s, R, it) {
  if (it.kind === 'any') {
    var got = arr(it.any).map(function (a) { return covers(s, R, a); });
    return got.indexOf('yes') >= 0 ? 'yes' : (got.indexOf('no') >= 0 ? 'no' : got[0] || 'no');
  }
  if (it.kind === 'file') {
    var why = protectedWhy(it.path);
    if (!why) {
      R.pol.scripts.forEach(function (x) { if (x.path === it.path) why = it.path + ' is a script the policy runs - never written by a job'; });
      R.pol.tests.forEach(function (t) { t.forEach(function (w) { if (!why && w[0] === '/' && normPath(w) === it.path) why = it.path + ' is named by a test the policy runs (' + t.map(quote).join(' ').slice(0, 200) + ') - never written by a job'; }); });
    }
    if (why) return why;
    if (Number(it.mode) & 73) return it.path + ': ' + oct4(it.mode) + ' - a file acme-agent writes is never executable';
    var rule = deepest(R, it.path);
    if (!rule) return 'no';
    var u = it.owner || rule.owner, g = it.group || (it.owner ? u : rule.group);
    if (u !== rule.owner || g !== rule.group) return 'no';
    return (Number(it.mode) & ~rule.mode) ? 'no' : 'yes';
  }
  if (it.kind === 'unit') {
    try { return arr(R.pol.units[normUnit(it.unit)]).indexOf(it.verb) >= 0 ? 'yes' : 'no'; } catch (e) { return 'no'; }
  }
  if (it.kind === 'test') {
    var k = JSON.stringify(arr(it.argv));
    return R.pol.tests.some(function (t) { return JSON.stringify(t) === k; }) ? 'yes' : 'no';
  }
  if (it.kind === 'script') {
    return R.pol.scripts.some(function (x) { return x.path === it.path; }) || R.pins.indexOf(it.path) >= 0 ? 'yes' : 'no';
  }
  if (it.kind === 'hash') return R.pol.hashes.indexOf(it.hash) >= 0 ? 'yes' : 'no';
  if (it.kind === 'probe') {
    if (it.local) return s.probe_local ? 'yes' : 'no';
    try { return R.pol.probe.indexOf(normHostport(it.hp)) >= 0 ? 'yes' : 'no'; } catch (e) { return 'no'; }
  }
  if (it.kind === 'limit') return Number(s.limits.files) >= Number(it.files) ? 'yes' : 'no';
  return 'no';
}
/** What allows `it` put into the state. */
function addNeed(s, it) {
  if (it.kind === 'any') { if (arr(it.any).length) addNeed(s, it.any[0]); return; }
  if (it.kind === 'file') {
    var d = it.path.replace(/\/[^\/]*$/, '') || '/', u = it.owner || 'root', g = it.group || it.owner || 'root';
    var have = s.files.filter(function (f) { return normPath(f.dir) === d; })[0];
    if (have) { have.owner = u; have.group = g; have.mode = (Number(have.mode) | Number(it.mode)) & 438; }
    else s.files.push({dir: d, owner: u, group: g, mode: Number(it.mode) & 438});
    return;
  }
  if (it.kind === 'unit') {
    var n;
    try { n = normUnit(it.unit); } catch (e) { n = it.unit; }
    var x = s.units.filter(function (y) { try { return normUnit(y.name) === n; } catch (e) { return false; } })[0];
    if (!x) { x = {name: n, verbs: []}; s.units.push(x); }
    if (x.verbs.indexOf(it.verb) < 0) x.verbs.push(it.verb);
    return;
  }
  if (it.kind === 'test') { s.tests.push(arr(it.argv).slice()); return; }
  if (it.kind === 'script') { s.scripts.push({path: it.path, sha256: ''}); return; }
  if (it.kind === 'hash') { s.hashes.push(it.hash); return; }
  if (it.kind === 'probe') { if (it.local) s.probe_local = true; else s.probe.push(it.hp); return; }
  if (it.kind === 'limit') { s.limits.files = Math.max(Number(s.limits.files) || 0, Number(it.files)); }
}
/** A template put into the state: its folders (one folder: its mode added to, its owner the
    template's), units, tests, scripts, probe. */
function addTemplate(s, t) {
  arr(t.files).forEach(function (f) {
    var have = s.files.filter(function (x) { return normPath(x.dir) === f.dir; })[0];
    if (have) { have.mode = Number(have.mode) | Number(f.mode); have.owner = f.owner; have.group = f.group; }
    else s.files.push({dir: f.dir, owner: f.owner, group: f.group, mode: Number(f.mode)});
  });
  Object.keys(t.units || {}).forEach(function (u) { t.units[u].forEach(function (v) { addNeed(s, {kind: 'unit', unit: u, verb: v}); }); });
  arr(t.tests).forEach(function (a) {
    var k = JSON.stringify(a);
    if (!s.tests.some(function (x) { return JSON.stringify(x) === k; })) s.tests.push(a.slice());
  });
  arr(t.scripts).forEach(function (x) { if (!s.scripts.some(function (y) { return y.path === x.path; })) s.scripts.push({path: x.path, sha256: x.sha256 || ''}); });
  if (t.probe_local) s.probe_local = true;
}
/** Whether all of a template is in the state already. */
function hasTemplate(s, R, t) {
  var x = clone(s);
  addTemplate(x, t);
  var a = check(x).lines.join('\n'), b = R.lines.join('\n');
  return a === b && JSON.stringify(x.scripts) === JSON.stringify(s.scripts);
}

var CORE = {setFacts: setFacts, facts: function () { return F; }, quote: quote, split: split, normDir: normDir, normUnit: normUnit,
  ipNetwork: ipNetwork, normHostport: normHostport, protectedWhy: protectedWhy, empty: empty, fromPolicy: fromPolicy,
  fromSaved: fromSaved, check: check, fileText: fileText, allowLines: allowLines, oneShot: oneShot, diff: diff, covers: covers,
  addNeed: addNeed, addTemplate: addTemplate, hasTemplate: hasTemplate, oct4: oct4, Bad: Bad};
if (typeof module === 'object' && module.exports) { module.exports = CORE; return; }
root.ACME_POLICY_CORE = CORE;

/* =============================================================================================
   THE BUILDER
   ============================================================================================= */
var ROLE = (typeof ME === 'object' && ME && ME.role) || 'readonly';
var FULL = ROLE === 'fulladmin';
function hands() { return (root.ACME_AGENTS && root.ACME_AGENTS.hands && root.ACME_AGENTS.hands()) || {}; }
function ask(path, body, wait) {
  var h = hands();
  if (!h.capi) return Promise.reject(new Error('the page is not ready'));
  return h.capi(path, body, wait);
}
function mono(text, cls) { return noI18n(el('span', 'mono' + (cls ? ' ' + cls : ''), text)); }
var SVG = {
  folder: '<path d="M3.5 6.5a2 2 0 0 1 2-2h4l2 2.2h7a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/>',
  wand: '<path d="M4 20L15 9"/><path d="M14 5v3M18.5 9.5h-3M17 6l-2 2"/><path d="M19 3l.6 1.4L21 5l-1.4.6L19 7l-.6-1.4L17 5l1.4-.6z"/>',
  hash: '<path d="M9 4L7 20M17 4l-2 16M4.5 9h16M3.5 15h16"/>',
  gauge: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/>'
};
function icon(key, size) {
  var s = noI18n(el('span', 'ag-ic'));
  s.innerHTML = SVG[key] ? '<svg viewBox="0 0 24 24" width="' + (size || 17) + '" height="' + (size || 17) + '" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + SVG[key] + '</svg>' : iconMarkup(key, size || 17);
  return s;
}
function abbr(t) {
  if (t.key === 'docker') return 'DK';
  if (t.key === 'systemd') return 'SD';
  if (t.key === 'folder') return '/';
  return String(t.title).replace(/[^A-Za-z0-9]/g, '').slice(0, 2).toUpperCase();
}
var NAMED = ['A Docker container', 'Any systemd service', 'A folder for certificates'];
function input(value, ph, cls) {
  var i = el('input', 'pb-in' + (cls ? ' ' + cls : ''));
  i.type = 'text';
  i.value = value === undefined || value === null ? '' : String(value);
  if (ph) i.placeholder = ph;
  i.spellcheck = false;
  i.autocomplete = 'off';
  return i;
}
function switcher(on, words, change) {
  var b = el('button', 'pb-switch' + (on ? ' on' : ''));
  b.type = 'button';
  b.setAttribute('role', 'switch');
  b.setAttribute('aria-checked', on ? 'true' : 'false');
  b.appendChild(noI18n(el('span', 'pb-knob')));
  b.appendChild(el('span', 'pb-switch-w', words));
  b.onclick = function () {
    var now = !b.classList.contains('on');
    b.classList.toggle('on', now);
    b.setAttribute('aria-checked', now ? 'true' : 'false');
    change(now);
  };
  return b;
}
function saveFile(name, text) {
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], {type: 'text/plain'}));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 2000);
}
var USERS = ['root', 'nginx', 'www-data', 'apache', 'haproxy', 'postfix', 'dovecot', 'Debian-exim', 'exim', 'tomcat', 'squid', 'proxy',
  'caddy', 'traefik', 'mysql', 'postgres', 'grafana', 'cockpit-ws', 'backup', 'mosquitto', 'openldap', 'ldap', 'zimbra', 'ssl-cert', 'www', 'lighttpd'];

/**
 * The builder of one target's agent policy. row: {id, name}; opts: {from: 'design'|'server'|
 * 'empty', state: a state to start from (a version of the design), done: after a save}.
 */
/* the builder being asked for (1.0.119: "Design its policy…" clicked twice while it was
   asked opened it twice) */
var OPENING = false;
function open(row, opts) {
  opts = opts || {};
  if (OPENING) return;
  var go = function () {
    if (OPENING) return;
    OPENING = true;
    ask('agents/builder?id=' + encodeURIComponent(row.id || row.name)).then(function (d) { OPENING = false; build(row, d, opts); }).catch(function (e) { OPENING = false; oops(e); });
  };
  var h = hands();
  if (h.over && opts.over !== false) h.over(go, opts.back); else go();
}
function build(row, d, opts) {
  setFacts(d.facts || {});
  var A = d.agent || {}, D = d.design || null;
  var serverState = fromPolicy(A.policy);
  var serverLines = A.policy ? check(serverState).lines : null;
  var version = !!(opts.state || opts.text);
  var B = {from: version ? 'version' : (opts.from || (D ? 'design' : 'server')), tab: 'file', q: ''};
  var S;
  function startFrom(w) {
    B.from = w;
    /* a version saved without its state (the command line): its lines, as the design's */
    if (w === 'version' && version) S = opts.state && Object.keys(opts.state).length ? fromSaved(opts.state) : fromPolicyText(opts.text);
    else if (w === 'design' && D) S = D.state && Object.keys(D.state).length ? fromSaved(D.state) : fromPolicyText(D.text);
    else if (w === 'empty') S = empty();
    else S = clone(serverState);
  }
  function fromPolicyText(text) {
    /* a design saved without its state (the command line): its lines, as the agent reads them */
    var s = empty();
    String(text || '').split('\n').forEach(function (l) {
      l = l.trim();
      if (!l || l[0] === '#') return;
      try {
        var w = split(l);
        if (w[0] === 'limit') { s.limits[w[1]] = Number(w[2]); return; }
        var kv = {}, rest = [];
        w.slice(2).forEach(function (x) { var m = x.match(/^([a-z0-9_-]+)=(.*)$/); if (m) kv[m[1]] = m[2]; else rest.push(x); });
        if (w[1] === 'file') { var o = (kv.owner || 'root:root').split(':'); s.files.push({dir: rest[0], owner: o[0], group: o[1] || o[0], mode: parseInt(kv.mode || '0644', 8)}); }
        else if (w[1] === 'unit') s.units.push({name: rest[0], verbs: String(rest[1] || '').split(',')});
        else if (w[1] === 'test') s.tests.push(rest[0] === '--' ? rest.slice(1) : rest);
        else if (w[1] === 'script') s.scripts.push({path: rest[0], sha256: kv.sha256 || ''});
        else if (w[1] === 'script-hash') s.hashes.push(rest[0]);
        else if (w[1] === 'from') s.from.push(rest[0]);
        else if (w[1] === 'probe') { if (rest[0] === 'local') s.probe_local = true; else s.probe.push(rest[0]); }
        else if (w[1] === 'connect') { s.connect.push(rest[0]); s.connect_on = true; }
        else if (w[1] === 'self-update') s.self_update = true;
      } catch (e) { /* a line the agent would not read: left out */ }
    });
    return s;
  }
  startFrom(B.from);
  var R = check(S);
  var refs = {};
  var sec = {};


  /* ---- the hero: where it starts from, how it reads ----------------------------------------- */
  function hero() {
    var h = el('div', 'pb-hero');
    var ic = noI18n(el('span', 'pb-hero-ic'));
    ic.appendChild(icon('shield', 26));
    h.appendChild(ic);
    var w = el('div', 'pb-hero-w');
    var t = el('div', 'pb-hero-t');
    t.appendChild(el('b', '', 'acme proposes, the server decides'));
    w.appendChild(t);
    w.appendChild(el('p', 'small', 'Click together what the agent may do on this server. acme never sends a policy: the result is copied to the server, where root writes it - checked there again, as here.'));
    var from = el('div', 'pb-from');
    from.appendChild(el('span', 'pb-k', 'Start from'));
    var seg = el('div', 'pb-seg');
    var choices = [['server', A.policy ? 'its policy on the server' : 'its policy (not said yet)']];
    if (D) choices.push(['design', 'the saved design']);
    if (version) choices.push(['version', 'the version opened']);
    choices.push(['empty', 'nothing']);
    choices.forEach(function (c) {
      var b = el('button', 'pb-seg-b' + (B.from === c[0] ? ' on' : ''), c[1]);
      b.type = 'button';
      b.onclick = function () {
        if (B.from === c[0]) return;
        startFrom(c[0]);
        Array.prototype.forEach.call(seg.children, function (x) { x.classList.remove('on'); });
        b.classList.add('on');
        drawAll();
        refresh();
      };
      seg.appendChild(b);
    });
    from.appendChild(seg);
    w.appendChild(from);
    h.appendChild(w);
    var st = el('div', 'pb-hero-st');
    refs.badge = el('span', 'pb-badge');
    st.appendChild(refs.badge);
    refs.stats = el('div', 'pb-stats');
    st.appendChild(refs.stats);
    h.appendChild(st);
    return h;
  }
  var SECTIONS = [
    ['tpl', 'Templates', 'wand'], ['needs', 'What the deployments need', 'check'], ['files', 'Folders', 'folder'],
    ['units', 'Units', 'refresh'], ['tests', 'Tests and commands', 'terminal'], ['scripts', 'Scripts', 'key'],
    ['hashes', 'Script hashes', 'hash'], ['from', 'Allow from', 'in'], ['probe', 'Tests from here', 'pulse'],
    ['connect', 'Connections for acme', 'plug'], ['update', 'Updates from acme', 'up'], ['limits', 'Limits', 'gauge']
  ];
  function nav() {
    var n = el('div', 'pb-nav');
    refs.nav = {};
    SECTIONS.forEach(function (x) {
      var b = el('button', 'pb-nav-b');
      b.type = 'button';
      b.appendChild(icon(x[2], 14));
      b.appendChild(el('span', '', x[1]));
      var c = noI18n(el('span', 'pb-nav-n', ''));
      b.appendChild(c);
      b.onclick = function () { if (sec[x[0]]) sec[x[0]].scrollIntoView({behavior: 'smooth', block: 'start'}); };
      refs.nav[x[0]] = {b: b, n: c};
      n.appendChild(b);
    });
    return n;
  }
  function section(key, title, ic, hint, addWords, add) {
    var s = el('section', 'pb-sec');
    s.id = 'pb-s-' + key;
    var h = el('div', 'pb-sec-h');
    var i = noI18n(el('span', 'pb-sec-ic'));
    i.appendChild(icon(ic, 17));
    h.appendChild(i);
    var w = el('div', 'pb-sec-w');
    w.appendChild(el('b', '', title));
    if (hint) w.appendChild(el('span', 'pb-sec-hint', hint));
    h.appendChild(w);
    if (addWords) {
      var b = cmdButton(addWords, 'add', 'small');
      b.onclick = add;
      h.appendChild(b);
    }
    s.appendChild(h);
    var body = el('div', 'pb-sec-b');
    s.appendChild(body);
    sec[key] = s;
    return {node: s, body: body};
  }
  function drawAll() {
    Object.keys(sec).forEach(function (k) { if (sec[k].parentNode) sec[k].remove(); });
    refs.rows = {};
    [drawTemplates, drawNeeds, drawFiles, drawUnits, drawTests, drawScripts, drawHashes, drawFrom, drawProbe, drawConnect, drawUpdate, drawLimits]
      .forEach(function (f) { refs.main.appendChild(f()); });
  }
  function redraw(key, fn) {
    var old = sec[key];
    var fresh = fn();
    old.parentNode.replaceChild(fresh, old);
    refresh();
  }
  /* a row's light and what it says - in its place, the row never jumps */
  function light() { return noI18n(el('span', 'pb-light')); }
  function said() { return el('div', 'pb-said'); }
  function paintRow(r, v, hint) {
    if (!r) return;
    r.row.classList.remove('ok', 'warn', 'bad');
    r.row.classList.add(v.level === 'info' ? 'ok' : v.level);
    clear(r.said);
    var ms = v.msgs;
    if (!ms.length && hint) { r.said.appendChild(el('span', 'pb-hint', hint)); return; }
    ms.forEach(function (m) {
      var x = el('div', 'pb-msg ' + m.level);
      x.appendChild(noI18n(el('span', 'pb-msg-mk', m.level === 'bad' ? '✕' : (m.level === 'warn' ? '!' : 'i'))));
      x.appendChild(el('span', '', m.words));
      r.said.appendChild(x);
    });
  }
  function rowShell(list, kind, i, remove) {
    var r = el('div', 'pb-row');
    var top = el('div', 'pb-row-top');
    top.appendChild(light());
    r.appendChild(top);
    var sd = said();
    r.appendChild(sd);
    var x = cmdButton('', 'close', 'small pb-x');
    x.setAttribute('aria-label', 'Take it away');
    x.title = 'Take it away';
    x.onclick = remove;
    var o = {row: r, top: top, said: sd, x: x};
    (refs.rows[kind] = refs.rows[kind] || [])[i] = o;
    return o;
  }

  /* ---- templates -------------------------------------------------------------------------- */
  function drawTemplates() {
    var s = section('tpl', 'Templates', 'wand', 'One click adds a coherent set: the folder with its owner and mode (as the deployment presets write it), the units and their verbs, the test, a test of what it serves.');
    var find = el('input', 'pb-find ct-kind-find');
    find.type = 'search';
    find.placeholder = 'an application…';
    find.value = B.q;
    s.body.appendChild(find);
    var g = el('div', 'pb-tpls');
    s.body.appendChild(g);
    refs.tpl = [];
    var drawT = function () {
      clear(g);
      refs.tpl = [];
      var q = find.value.trim().toLowerCase();
      arr(d.templates).forEach(function (t) {
        if (q && (t.title + ' ' + t.key + ' ' + t.group).toLowerCase().indexOf(q) < 0) return;
        var b = el('button', 'pb-tpl');
        b.type = 'button';
        b.appendChild(noI18n(el('span', 'pb-tpl-ic', abbr(t))));
        var w = el('span', 'pb-tpl-w');
        var nm = NAMED.indexOf(t.title) >= 0 ? el('span', 'pb-tpl-n', t.title) : noI18n(el('span', 'pb-tpl-n', t.title));
        w.appendChild(nm);
        var sub = arr(t.files).map(function (f) { return f.dir; }).concat(Object.keys(t.units || {})).join(' · ');
        w.appendChild(noI18n(el('span', 'pb-tpl-s', sub)));
        b.appendChild(w);
        var mk = noI18n(el('span', 'pb-tpl-mk', ''));
        b.appendChild(mk);
        if (t.note) explain(b, t.note);
        b.onclick = function () {
          addTemplate(S, t);
          drawAll();
          refresh();
          toast(tr('Added from the template') + ': ' + t.title, 'good');
        };
        refs.tpl.push({t: t, b: b, mk: mk});
        g.appendChild(b);
      });
      if (!g.children.length) g.appendChild(el('p', 'muted small', 'Nothing of that name - Any systemd service fits every other.'));
      paintTemplates();
    };
    /* what was searched stays when a template is clicked (all is drawn again) */
    find.oninput = function () { B.q = find.value; drawT(); };
    drawT();
    return s.node;
  }
  function paintTemplates() {
    arr(refs.tpl).forEach(function (x) {
      var on = hasTemplate(S, R, x.t);
      x.b.classList.toggle('on', on);
      x.mk.textContent = on ? '✓' : '+';
    });
  }
  function tr(w) { return typeof i18nText === 'function' ? (i18nText(w) || w) : w; }

  /* ---- what the deployments need ------------------------------------------------------------ */
  function needWords(it) {
    if (it.kind === 'any') return arr(it.any).map(needWords).join('  ||  ');
    if (it.kind === 'file') return it.path + '  ' + oct4(it.mode) + ' ' + (it.owner ? it.owner + ':' + (it.group || it.owner) : 'root:root');
    if (it.kind === 'unit') return 'systemctl ' + it.verb + ' ' + it.unit;
    if (it.kind === 'test') return arr(it.argv).map(quote).join(' ');
    if (it.kind === 'script') return it.path;
    if (it.kind === 'hash') return 'sha256 ' + it.hash.slice(0, 16) + '…';
    if (it.kind === 'probe') return it.hp;
    if (it.kind === 'limit') return it.files + ' files';
    return '';
  }
  var NEED_K = {file: 'file', unit: 'unit', test: 'command', script: 'script', hash: 'the script written in acme', probe: 'test', limit: 'limit', any: 'one of'};
  function drawNeeds() {
    var s = section('needs', 'What the deployments need', 'check', 'Each deployment to this target, as its form judges it: add what is missing with one click.');
    refs.needs = [];
    var deps = arr(d.needs);
    if (!deps.length) {
      s.body.appendChild(el('p', 'pb-empty', 'No deployment to this target yet - each one says here what it needs.'));
      return s.node;
    }
    var all = cmdButton('Add all that the deployments need', 'add', 'primary small pb-addall');
    all.onclick = function () {
      var n = 0;
      deps.forEach(function (dep) { arr(dep.items).forEach(function (it) { if (covers(S, R, it) === 'no') { addNeed(S, it); R = check(S); n++; } }); });
      drawAll();
      refresh();
      toast(n ? tr('Added') + ': ' + n : tr('the policy allows all of it already'), 'good');
    };
    refs.addAll = all;
    var br = el('div', 'pb-needs-top');
    br.appendChild(all);
    refs.needsSum = el('span', 'pb-needs-sum');
    br.appendChild(refs.needsSum);
    s.body.appendChild(br);
    deps.forEach(function (dep) {
      var c = el('div', 'pb-dep' + (dep.enabled ? '' : ' off'));
      var h = el('div', 'pb-dep-h');
      h.appendChild(icon('lock', 15));
      h.appendChild(noI18n(el('b', '', dep.cert)));
      if (!dep.enabled) h.appendChild(el('span', 'tag dim', 'switched off'));
      c.appendChild(h);
      if (dep.error) {
        var e = el('div', 'pb-msg bad');
        e.appendChild(noI18n(el('span', 'pb-msg-mk', '✕')));
        e.appendChild(el('span', '', String(dep.error)));
        c.appendChild(e);
      }
      arr(dep.items).forEach(function (it) {
        var r = el('div', 'pb-need');
        var mk = noI18n(el('span', 'pb-need-mk'));
        r.appendChild(mk);
        r.appendChild(el('span', 'pb-need-k', NEED_K[it.kind] || it.kind));
        r.appendChild(mono(needWords(it), 'pb-need-w'));
        var b = cmdButton('Add', 'add', 'small pb-need-add');
        b.onclick = function () { addNeed(S, it); drawAll(); refresh(); };
        r.appendChild(b);
        var why = el('div', 'pb-need-why');
        r.appendChild(why);
        refs.needs.push({it: it, r: r, mk: mk, b: b, why: why});
        c.appendChild(r);
      });
      s.body.appendChild(c);
    });
    return s.node;
  }
  function paintNeeds() {
    var miss = 0, ok = 0, never = 0;
    arr(refs.needs).forEach(function (x) {
      var v = covers(S, R, x.it);
      x.r.classList.remove('yes', 'no', 'never');
      clear(x.why);
      if (v === 'yes') { x.r.classList.add('yes'); x.mk.textContent = '✓'; ok++; }
      else if (v === 'no') { x.r.classList.add('no'); x.mk.textContent = '+'; miss++; }
      else { x.r.classList.add('never'); x.mk.textContent = '✕'; never++; x.why.appendChild(el('span', '', v)); }
    });
    if (refs.needsSum) {
      clear(refs.needsSum);
      refs.needsSum.appendChild(el('span', 'pb-ns ok', ok + ' allowed'));
      refs.needsSum.appendChild(el('span', 'pb-ns no', miss + ' missing'));
      if (never) refs.needsSum.appendChild(el('span', 'pb-ns never', never + ' never allowed'));
      refs.addAll.disabled = !miss;
    }
  }

  /* ---- folders ------------------------------------------------------------------------------ */
  function drawFiles() {
    var s = section('files', 'Folders', 'folder', 'Files in the folder and below it, owned so, at most that mode. Allow the narrowest folder that holds only certificates.',
      'Add a folder', function () { S.files.push({dir: '', owner: 'root', group: 'root', mode: 420}); redraw('files', drawFiles); focusLast('files'); });
    var dl = el('datalist');
    dl.id = 'pb-users';
    USERS.forEach(function (u) { var o = el('option'); o.value = u; dl.appendChild(o); });
    s.body.appendChild(noI18n(dl));
    S.files.forEach(function (f, i) {
      var o = rowShell(S.files, 'files', i, function () { S.files.splice(i, 1); redraw('files', drawFiles); });
      var p = input(f.dir, '/etc/nginx/ssl', 'mono pb-path');
      p.oninput = function () { f.dir = p.value.trim(); refresh(); };
      o.top.appendChild(p);
      var own = el('div', 'pb-owner');
      var u = input(f.owner, 'root', 'mono');
      u.setAttribute('list', 'pb-users');
      u.oninput = function () { f.owner = u.value.trim(); refresh(); };
      var g = input(f.group, 'root', 'mono');
      g.setAttribute('list', 'pb-users');
      g.oninput = function () { f.group = g.value.trim(); refresh(); };
      own.appendChild(u);
      own.appendChild(noI18n(el('span', 'pb-colon', ':')));
      own.appendChild(g);
      o.top.appendChild(own);
      o.top.appendChild(rwx(f));
      o.top.appendChild(o.x);
      o.row.classList.add('pb-file');
      s.body.appendChild(o.row);
    });
    if (!S.files.length) s.body.appendChild(el('p', 'pb-empty', 'No folder: acme can write no file here.'));
    return s.node;
  }
  function rwx(f) {
    var box = el('div', 'pb-rwx');
    var octal = noI18n(el('span', 'pb-oct mono'));
    var cells = [];
    [['owner', 6], ['group', 3], ['others', 0]].forEach(function (w) {
      var col = el('div', 'pb-rwx-c');
      col.appendChild(el('span', 'pb-rwx-k', w[0]));
      var bits = el('div', 'pb-rwx-bits');
      [['r', 4], ['w', 2], ['x', 1]].forEach(function (b) {
        var bit = b[1] << w[1];
        var btn = noI18n(el('button', 'pb-bit' + (b[0] === 'x' ? ' x' : ''), b[0]));
        btn.type = 'button';
        btn.setAttribute('aria-pressed', 'false');
        btn.title = w[0] + ' ' + {r: 'read', w: 'write', x: 'execute'}[b[0]];
        btn.onclick = function () { f.mode = (Number(f.mode) ^ bit) & 511; paint(); refresh(); };
        cells.push([btn, bit]);
        bits.appendChild(btn);
      });
      col.appendChild(bits);
      box.appendChild(col);
    });
    box.appendChild(octal);
    function paint() {
      cells.forEach(function (c) { var on = !!(Number(f.mode) & c[1]); c[0].classList.toggle('on', on); c[0].setAttribute('aria-pressed', on ? 'true' : 'false'); });
      octal.textContent = oct4(f.mode);
    }
    paint();
    return box;
  }
  function focusLast(kind) {
    var rows = refs.rows[kind] || [];
    var last = rows[rows.length - 1];
    if (last) { var i = last.top.querySelector('input'); if (i) try { i.focus(); } catch (e) { } }
  }

  /* ---- units -------------------------------------------------------------------------------- */
  function drawUnits() {
    var s = section('units', 'Units', 'refresh', 'systemctl VERB NAME - only the verbs chosen; after it the agent says whether the unit is active.',
      'Add a unit', function () { S.units.push({name: '', verbs: ['reload']}); redraw('units', drawUnits); focusLast('units'); });
    S.units.forEach(function (u, i) {
      var o = rowShell(S.units, 'units', i, function () { S.units.splice(i, 1); redraw('units', drawUnits); });
      var n = input(u.name, 'nginx.service', 'mono pb-unit');
      n.oninput = function () { u.name = n.value.trim(); refresh(); };
      o.top.appendChild(n);
      var chips = el('div', 'pb-verbs');
      F.verbs.forEach(function (v, k) {
        var c = noI18n(el('button', 'pb-verb' + (u.verbs.indexOf(v) >= 0 ? ' on' : '') + (k > 2 ? ' more' : ''), v));
        c.type = 'button';
        c.onclick = function () {
          var at = u.verbs.indexOf(v);
          if (at >= 0) u.verbs.splice(at, 1); else u.verbs.push(v);
          c.classList.toggle('on', at < 0);
          refresh();
        };
        chips.appendChild(c);
      });
      o.top.appendChild(chips);
      o.top.appendChild(o.x);
      s.body.appendChild(o.row);
    });
    if (!S.units.length) s.body.appendChild(el('p', 'pb-empty', 'No unit: acme reloads nothing here.'));
    return s.node;
  }

  /* ---- tests -------------------------------------------------------------------------------- */
  function drawTests() {
    var s = section('tests', 'Tests and commands', 'terminal', 'A command line exactly as written - a test, a reload or a command before / after. Never through a shell: a | ; $ > is a word like any other.',
      'Add a command', function () { S.tests.push([]); redraw('tests', drawTests); focusLast('tests'); });
    S.tests.forEach(function (t, i) {
      var o = rowShell(S.tests, 'tests', i, function () { S.tests.splice(i, 1); redraw('tests', drawTests); });
      var line = input(Array.isArray(t) ? t.map(quote).join(' ') : t, 'nginx -t', 'mono pb-cmd');
      var toks = noI18n(el('div', 'pb-toks'));
      var paintToks = function () {
        clear(toks);
        arr(S.tests[i]).forEach(function (w, k) {
          var c = el('span', 'pb-tok' + (/[|;&$`<>(){}*?!~]/.test(w) ? ' odd' : ''), w);
          c.title = 'argv[' + k + ']';
          toks.appendChild(c);
        });
      };
      line.oninput = function () {
        try { S.tests[i] = split(line.value); line.classList.remove('pb-bad-in'); } catch (e) { S.tests[i] = line.value; line.classList.add('pb-bad-in'); }
        paintToks();
        refresh();
      };
      o.top.appendChild(line);
      o.top.appendChild(o.x);
      o.row.insertBefore(toks, o.said);
      paintToks();
      s.body.appendChild(o.row);
    });
    if (!S.tests.length) s.body.appendChild(el('p', 'pb-empty', 'No command: a deployment here runs no test.'));
    return s.node;
  }

  /* ---- scripts and their hashes ------------------------------------------------------------- */
  function drawScripts() {
    var s = section('scripts', 'Scripts', 'key', 'A script on the server, by its path and its SHA-256: changed meanwhile, it is refused. Leave the hash empty to pin it on the server: sudo acme-agent allow script PATH reads it there and writes its hash.',
      'Add a script', function () { S.scripts.push({path: '', sha256: ''}); redraw('scripts', drawScripts); focusLast('scripts'); });
    S.scripts.forEach(function (x, i) {
      var o = rowShell(S.scripts, 'scripts', i, function () { S.scripts.splice(i, 1); redraw('scripts', drawScripts); });
      var p = input(x.path, '/usr/local/sbin/acme-hook.sh', 'mono pb-path');
      p.oninput = function () { x.path = p.value.trim(); refresh(); };
      var h = input(x.sha256, 'sha256 - empty: pinned on the server', 'mono pb-sha');
      h.oninput = function () { x.sha256 = h.value.trim(); refresh(); };
      o.top.appendChild(p);
      o.top.appendChild(h);
      o.top.appendChild(o.x);
      s.body.appendChild(o.row);
    });
    if (!S.scripts.length) s.body.appendChild(el('p', 'pb-empty', 'No script on the server.'));
    return s.node;
  }
  function drawHashes() {
    var s = section('hashes', 'Script hashes', 'hash', 'A script written in acme (a deployment’s “After the files”) runs only when its SHA-256 is here - change one letter of it and it is refused.',
      'Add a hash', function () { S.hashes.push(''); redraw('hashes', drawHashes); focusLast('hashes'); });
    var offer = [];
    arr(d.needs).forEach(function (dep) { arr(dep.items).forEach(function (it) { if (it.kind === 'hash') offer.push({h: it.hash, cert: dep.cert, interp: it.interp}); }); });
    if (offer.length) {
      var o2 = el('div', 'pb-offer');
      o2.appendChild(el('span', 'pb-k', 'The scripts of this target’s deployments'));
      offer.forEach(function (x) {
        var b = el('button', 'pb-chip-add');
        b.type = 'button';
        b.appendChild(noI18n(el('span', 'pb-chip-p', '+')));
        b.appendChild(noI18n(el('b', '', x.cert)));
        b.appendChild(mono(x.h.slice(0, 12) + '…'));
        b.disabled = S.hashes.map(function (y) { return String(y).toLowerCase(); }).indexOf(x.h) >= 0;
        b.onclick = function () { S.hashes.push(x.h); redraw('hashes', drawHashes); };
        o2.appendChild(b);
      });
      s.body.appendChild(o2);
    }
    S.hashes.forEach(function (x, i) {
      var o = rowShell(S.hashes, 'hashes', i, function () { S.hashes.splice(i, 1); redraw('hashes', drawHashes); });
      var h = input(x, '64 hex digits', 'mono pb-hash');
      h.oninput = function () { S.hashes[i] = h.value.trim(); refresh(); };
      o.top.appendChild(h);
      o.top.appendChild(o.x);
      s.body.appendChild(o.row);
    });
    return s.node;
  }

  /* ---- where from, what to, updates, limits ------------------------------------------------- */
  function listSection(key, title, ic, hint, addWords, ph, list, extra) {
    var draw = function () {
      var s = section(key, title, ic, hint, addWords, function () { list().push(''); redraw(key, draw); focusLast(key); });
      if (extra) extra(s.body);
      list().forEach(function (x, i) {
        var o = rowShell(list(), key, i, function () { list().splice(i, 1); redraw(key, draw); });
        var v = input(x, ph, 'mono pb-addr');
        v.oninput = function () { list()[i] = v.value.trim(); refresh(); };
        o.top.appendChild(v);
        o.top.appendChild(o.x);
        s.body.appendChild(o.row);
      });
      return s.node;
    };
    return draw;
  }
  var drawFrom = listSection('from', 'Allow from', 'in', 'A passive agent lets acme in only from these addresses (else from anywhere with acme’s certificate); anybody else is turned away before the TLS handshake.',
    'Add an address', '192.0.2.10 or 192.0.2.0/24', function () { return S.from; }, function (b) {
      if (A.mode === 'active') b.appendChild(el('p', 'note small', 'This agent is active: it connects to acme and listens on nothing - the addresses matter only if it is made passive.'));
      var mine = arr(d.acme_from);
      if (!mine.length) return;
      var o = el('div', 'pb-offer');
      o.appendChild(el('span', 'pb-k', 'acme’s addresses'));
      mine.forEach(function (a) {
        var c = el('button', 'pb-chip-add');
        c.type = 'button';
        c.appendChild(noI18n(el('span', 'pb-chip-p', '+')));
        c.appendChild(mono(a));
        c.disabled = S.from.indexOf(a) >= 0 || S.from.indexOf(a + '/32') >= 0;
        c.onclick = function () { S.from.push(a); redraw('from', drawFrom); };
        o.appendChild(c);
      });
      b.appendChild(o);
    });
  var drawProbe = listSection('probe', 'Tests from here', 'pulse', 'acme’s tests of what is served, connected from this server (Certificates → Tests, through the agent).',
    'Add a place', 'www.example.com:443', function () { return S.probe; }, function (b) {
      b.appendChild(switcher(S.probe_local, 'Anything on this server (127.0.0.1, ::1, localhost) - what the tests of its deployments need', function (on) { S.probe_local = on; refresh(); }));
    });
  function drawConnect() {
    var s = section('connect', 'Connections for acme', 'plug', 'acme reaches a host and port through this agent - the agent as the connector of SSH targets. Off unless you need it.');
    s.body.appendChild(switcher(S.connect_on, 'acme may connect through this server', function (on) {
      S.connect_on = on;
      if (on && !S.connect.length) S.connect.push('');
      redraw('connect', drawConnect);
    }));
    if (S.connect_on) {
      var w = el('div', 'note warn small pb-connect-warn');
      w.appendChild(el('span', '', 'Whoever controls a running acme could then reach each of these from this server. Name addresses rather than names where that matters, and only the hosts that need it.'));
      s.body.appendChild(w);
      S.connect.forEach(function (x, i) {
        var o = rowShell(S.connect, 'connect', i, function () { S.connect.splice(i, 1); redraw('connect', drawConnect); });
        var v = input(x, '10.0.5.21:22', 'mono pb-addr');
        v.oninput = function () { S.connect[i] = v.value.trim(); refresh(); };
        o.top.appendChild(v);
        o.top.appendChild(o.x);
        s.body.appendChild(o.row);
      });
      var add = cmdButton('Add a host', 'add', 'small');
      add.onclick = function () { S.connect.push(''); redraw('connect', drawConnect); focusLast('connect'); };
      var br = el('div', 'btnrow');
      br.appendChild(add);
      s.body.appendChild(br);
    }
    return s.node;
  }
  function drawUpdate() {
    var s = section('update', 'Updates from acme', 'up', 'acme may send a newer agent: only the package signed by the release key the agent was installed with, only a newer version - acme’s own package, never one from the internet.');
    s.body.appendChild(switcher(S.self_update, 'acme may update this agent', function (on) { S.self_update = on; refresh(); }));
    return s.node;
  }
  function drawLimits() {
    var s = section('limits', 'Limits', 'gauge', 'How much one deployment may write.');
    var g = el('div', 'pb-limits');
    [['files', 'Files in one deployment', 'files'], ['size', 'Bytes of one file', 'size']].forEach(function (x) {
      var c = el('label', 'pb-limit');
      c.appendChild(el('span', 'pb-k', x[1]));
      var w = el('div', 'pb-limit-w');
      var i = el('input', 'pb-in mono');
      i.type = 'number';
      i.min = '1';
      i.max = String(x[0] === 'files' ? F.limits.files_most : F.limits.size_most);
      i.value = String(S.limits[x[0]]);
      var hint = noI18n(el('span', 'pb-limit-h mono'));
      var paint = function () {
        var v = Number(S.limits[x[0]]);
        hint.textContent = x[0] === 'size' && isFinite(v) && v > 0 ? (v >= 1048576 ? (v / 1048576).toFixed(v % 1048576 ? 2 : 0) + ' MiB' : Math.round(v / 1024) + ' KiB') : '';
      };
      i.oninput = function () { S.limits[x[0]] = i.value === '' ? NaN : Number(i.value); paint(); refresh(); };
      w.appendChild(i);
      w.appendChild(hint);
      c.appendChild(w);
      var def = noI18n(el('span', 'pb-limit-d small muted', ''));
      def.textContent = '(' + (x[0] === 'files' ? F.limits.files : '1 MiB') + ')';
      c.appendChild(def);
      paint();
      g.appendChild(c);
      refs.rows['limit-' + x[0]] = [{row: c, said: (function () { var sd = said(); c.appendChild(sd); return sd; }()), top: c}];
    });
    s.body.appendChild(g);
    return s.node;
  }

  /* ---- the output: the file, the lines, one block, what changes ---------------------------- */
  var TABS = [['file', 'The policy file'], ['allow', 'As allow lines'], ['once', 'One block to paste'], ['diff', 'What changes']];
  function drawOut() {
    var o = refs.out;
    var card = el('div', 'pb-out-card');
    var h = el('div', 'pb-out-h');
    h.appendChild(icon('terminal', 16));
    h.appendChild(el('b', '', 'On the server, as root'));
    card.appendChild(h);
    var tabs = el('div', 'pb-tabs');
    tabs.setAttribute('role', 'tablist');
    refs.tabs = {};
    TABS.forEach(function (t) {
      var b = el('button', 'pb-tab' + (B.tab === t[0] ? ' on' : ''));
      b.type = 'button';
      b.setAttribute('role', 'tab');
      b.setAttribute('aria-selected', B.tab === t[0] ? 'true' : 'false');
      b.appendChild(el('span', '', t[1]));
      if (t[0] === 'diff') { refs.diffN = noI18n(el('span', 'pb-tab-n', '')); b.appendChild(refs.diffN); }
      b.onclick = function () { B.tab = t[0]; Object.keys(refs.tabs).forEach(function (k) { refs.tabs[k].classList.toggle('on', k === B.tab); refs.tabs[k].setAttribute('aria-selected', k === B.tab ? 'true' : 'false'); }); paintOut(); };
      refs.tabs[t[0]] = b;
      tabs.appendChild(b);
    });
    card.appendChild(tabs);
    refs.outSay = el('p', 'pb-out-say small');
    card.appendChild(refs.outSay);
    refs.pre = noI18n(el('pre', 'pb-pre mono'));
    card.appendChild(refs.pre);
    var bar = el('div', 'pb-out-bar');
    var cp = cmdButton('Copy', 'copy', 'primary small');
    cp.onclick = function () { copyText(outText(), cp, 'on the clipboard'); taken(); };
    refs.copy = cp;
    var dl = cmdButton('Download policy file', 'download', 'small');
    dl.onclick = function () { saveFile('policy', fileText(R)); taken(); };
    bar.appendChild(cp);
    bar.appendChild(dl);
    card.appendChild(bar);
    o.appendChild(card);
    o.appendChild(saveCard());
  }
  function outText() {
    if (B.tab === 'allow') return allowLines(R).join('\n');
    if (B.tab === 'once') return oneShot(R);
    if (B.tab === 'diff') return diff(serverLines || [], R.lines).filter(function (x) { return x.op !== ' '; }).map(function (x) { return x.op + ' ' + x.line; }).join('\n');
    return fileText(R);
  }
  var SAY = {
    file: '/etc/acme-agent/policy, root:root 0644 - in place of the one there: sudo acme-agent policy apply FILE (checked first; the one before kept).',
    allow: 'Each line adds to what the policy allows already - nothing is taken away. To make it exactly this, paste the one block.',
    once: 'Paste it whole into a root shell on the server: the agent checks it, writes it in place of the one there and says what changed. Ask it now on the card then shows it.',
    diff: 'Against its policy as the agent last said it: + is allowed by the design only, - only on the server now.'
  };
  function paintOut() {
    clear(refs.outSay);
    refs.outSay.appendChild(document.createTextNode(SAY[B.tab]));
    clear(refs.pre);
    refs.pre.classList.toggle('pb-diff', B.tab === 'diff');
    if (B.tab === 'diff') {
      if (!serverLines) { refs.pre.appendChild(el('span', 'pb-d-none', '')); refs.pre.firstChild.textContent = tr('Its policy is not known yet - Ask it now on the card.'); return; }
      var dd = diff(serverLines, R.lines);
      if (!dd.some(function (x) { return x.op !== ' '; })) { var same = el('span', 'pb-d-same', ''); same.textContent = tr('Nothing changes: the server allows exactly this.'); refs.pre.appendChild(same); return; }
      dd.forEach(function (x) {
        var l = el('span', 'pb-d ' + (x.op === '+' ? 'add' : (x.op === '-' ? 'del' : 'same')), '');
        l.textContent = x.op + ' ' + x.line + '\n';
        refs.pre.appendChild(l);
      });
      return;
    }
    var text = outText();
    if (B.tab === 'file') {
      var head = F.head;
      var hs = el('span', 'pb-c pb-head' + (B.head ? ' open' : ''), '');
      hs.textContent = head;
      hs.title = tr('the head of the file: what each entry is - click to fold or unfold');
      hs.onclick = function () { B.head = !B.head; hs.classList.toggle('open', B.head); };
      refs.pre.appendChild(hs);
      refs.pre.appendChild(document.createTextNode(text.slice(head.length) || ''));
      if (!R.lines.length) { var n = el('span', 'pb-c', ''); n.textContent = '# ' + tr('nothing is allowed: acme can do nothing here'); refs.pre.appendChild(n); }
      return;
    }
    refs.pre.textContent = text;
  }
  function saveCard() {
    var c = el('div', 'pb-save');
    var h = el('div', 'pb-out-h');
    h.appendChild(icon('save', 16));
    h.appendChild(el('b', '', 'The design, kept in acme'));
    c.appendChild(h);
    c.appendChild(el('p', 'small pb-save-say', 'Documentation only: acme never sends it to the server. The card then says whether the server’s policy matches it.'));
    refs.saveState = el('div', 'pb-save-st');
    c.appendChild(refs.saveState);
    paintSaved();
    if (!FULL) {
      c.appendChild(el('p', 'muted small', 'A full administrator saves a design.'));
      return c;
    }
    var t = input(D ? D.title : '', 'A title - nginx and Postfix on web1', 'pb-title');
    var n = el('textarea', 'pb-in pb-note');
    n.rows = 2;
    n.placeholder = 'A note - why it allows what it allows';
    n.value = D ? D.note || '' : '';
    c.appendChild(t);
    c.appendChild(n);
    var b = cmdButton('Save as this agent’s design', 'save', 'small');
    b.onclick = function () {
      if (R.counts.bad) { toast(tr('the design has lines the agent would not read - fix the red ones first'), 'bad'); return; }
      busy(b, true);
      ask('agents/design', {id: row.id || A.id, text: fileText(R), state: S, title: t.value.trim(), note: n.value.trim()}).then(function (x) {
        D = x.design;
        /* "Start from" offers the design just saved */
        if (refs.hero && refs.hero.parentNode) { var nh = hero(); refs.hero.parentNode.replaceChild(nh, refs.hero); refs.hero = nh; refresh(); }
        taken();
        paintSaved();
        toast(tr('the design is saved'), 'good');
        if (opts.done) opts.done(D);
      }).catch(oops).then(function () { busy(b, false); });
    };
    var br = el('div', 'btnrow');
    br.appendChild(b);
    c.appendChild(br);
    return c;
  }
  function paintSaved() {
    var w = refs.saveState;
    if (!w) return;
    clear(w);
    if (!D) { w.appendChild(el('span', 'muted small', 'No design is saved yet.')); return; }
    var p = el('span', 'pb-ver');
    p.appendChild(noI18n(el('b', '', 'v' + D.n)));
    if (D.title) p.appendChild(noI18n(el('span', '', ' ' + D.title)));
    w.appendChild(p);
    var m = el('span', 'muted small');
    m.appendChild(document.createTextNode(ago(D.at) + ' · '));
    m.appendChild(noI18n(document.createTextNode(String(D.by || ''))));
    w.appendChild(m);
    var same = D.text === fileText(R);
    w.appendChild(el('span', 'tag ' + (same ? 'ok' : 'warn'), same ? 'the same as here' : 'changed here'));
  }

  /* ---- everything checked again, in place -------------------------------------------------- */
  function refresh() {
    R = check(S);
    ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect'].forEach(function (k) {
      arr(refs.rows[k]).forEach(function (r, i) {
        if (!r || !R[k][i]) return;
        var hint = '';
        if (k === 'files') hint = 'files here at most ' + oct4(S.files[i].mode & 438) + ', owned by ' + S.files[i].owner + ':' + S.files[i].group;
        paintRow(r, R[k][i], hint ? hint : '');
      });
    });
    ['files', 'size'].forEach(function (k) {
      var r = arr(refs.rows['limit-' + k])[0];
      if (r) {
        clear(r.said);
        R.limits[k].msgs.forEach(function (m) { var x = el('div', 'pb-msg bad'); x.appendChild(el('span', '', m.words)); r.said.appendChild(x); });
        r.row.classList.toggle('bad', R.limits[k].level === 'bad');
      }
    });
    paintTemplates();
    paintNeeds();
    /* the hero and the nav */
    var c = R.counts;
    refs.badge.className = 'pb-badge ' + (c.bad ? 'bad' : (c.warn ? 'warn' : (c.entries ? 'ok' : 'dim')));
    clear(refs.badge);
    refs.badge.appendChild(noI18n(el('span', 'dot')));
    refs.badge.appendChild(el('span', '', c.bad ? 'lines left out - fix them' : (c.warn ? 'the agent takes it - look twice' : (c.entries ? 'the agent takes all of it' : 'allows nothing'))));
    clear(refs.stats);
    [['entries', c.entries, 'entries'], ['warn', c.warn, 'to look at'], ['bad', c.bad, 'left out']].forEach(function (x) {
      var s = el('span', 'pb-stat ' + x[0] + (x[1] ? '' : ' zero'));
      s.appendChild(noI18n(el('b', '', String(x[1]))));
      s.appendChild(el('span', '', x[2]));
      refs.stats.appendChild(s);
    });
    var N = {tpl: '', needs: '', files: S.files.length, units: S.units.length, tests: S.tests.length, scripts: S.scripts.length, hashes: S.hashes.length,
      from: S.from.length, probe: S.probe.length + (S.probe_local ? 1 : 0), connect: S.connect_on ? S.connect.length : 0, update: S.self_update ? '✓' : '', limits: ''};
    var lv = {files: R.files, units: R.units, tests: R.tests, scripts: R.scripts, hashes: R.hashes, from: R.from, probe: R.probe, connect: R.connect,
      limits: [R.limits.files, R.limits.size]};
    Object.keys(refs.nav).forEach(function (k) {
      var x = refs.nav[k];
      x.n.textContent = N[k] === '' || N[k] === 0 ? '' : String(N[k]);
      var l = arr(lv[k]);
      x.b.classList.toggle('bad', l.some(function (v) { return v.level === 'bad'; }));
      x.b.classList.toggle('warn', !l.some(function (v) { return v.level === 'bad'; }) && l.some(function (v) { return v.level === 'warn'; }));
    });
    if (k0(refs.needs)) {
      var miss = refs.needs.filter(function (x) { return covers(S, R, x.it) === 'no'; }).length;
      refs.nav.needs.n.textContent = miss ? String(miss) : '✓';
      refs.nav.needs.b.classList.toggle('warn', !!miss);
    }
    if (refs.diffN) {
      var dn = serverLines ? diff(serverLines, R.lines).filter(function (x) { return x.op !== ' '; }).length : 0;
      refs.diffN.textContent = dn ? String(dn) : '';
    }
    paintOut();
    paintSaved();
  }
  function k0(x) { return Array.isArray(x) && x.length; }
  /* copied, downloaded or saved: what was clicked together is not lost by Close (core.js asks
     before a popup with something typed in it goes) */
  function taken() { B.kept = fileText(R); try { MODAL_TYPED = 0; } catch (e) { } }
  /* drawn once everything below is defined */
  function show() {
    modal('Design the policy of ' + row.name, function (body) {
      var pb = el('div', 'pb');
      body.appendChild(pb);
      refs.hero = hero();
      pb.appendChild(refs.hero);
      var grid = el('div', 'pb-grid');
      var main = el('div', 'pb-main');
      var out = el('aside', 'pb-out');
      grid.appendChild(main);
      grid.appendChild(out);
      pb.appendChild(grid);
      refs.main = main;
      refs.out = out;
      main.appendChild(nav());
      drawAll();
      drawOut();
      refresh();
    }, [{words: 'Close', close: true}], 'large pb-box');
    explainWhatWasDrawn($('modal-body'));
    /* what was clicked together (a template, a need, a switch) and not copied, downloaded or
       saved is asked about before Close, its x or Escape take it away - only what was typed was */
    B.kept = fileText(R);
    if (typeof modalLeaveGuard === 'function') modalLeaveGuard(function (go) {
      var typed = typeof MODAL_TYPED !== 'undefined' && MODAL_TYPED && MODAL_TYPED === MODAL_GEN;
      if (fileText(R) === B.kept && !typed) return false;
      modalSure('Leave what was typed here?', go, 'Leave it');
      return true;
    });
  }
  show();
}

root.ACME_POLICY_BUILDER = {open: open, core: CORE};
}(typeof window !== 'undefined' ? window : this));
