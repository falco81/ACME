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
function setFacts(f) { F.platform = (f || {}).platform || 'linux'; Object.keys(f || {}).forEach(function (k) { F[k] = f[k]; }); }

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
/* ---- a Windows server's agent (1.0.120: acme_agent_win.py): its paths, words, services --------- */
function W() { return F.platform === 'windows'; }
/* acme_agent_win.wq: a word as typed in cmd.exe / PowerShell */
function wq(w) {
  w = String(w);
  if (w && !/[\s'"&|<>^%;,()`$]/.test(w)) return w;
  return (w.indexOf('"') >= 0 && w.indexOf("'") < 0) ? "'" + w + "'" : '"' + w + '"';
}
/* acme_agent_win.win_split: quotes as sh reads them, a backslash is a backslash */
function splitWin(text) {
  var out = [], cur = null, i = 0, t = String(text || '');
  while (i < t.length) {
    var c = t[i];
    if (/\s/.test(c)) { if (cur !== null) { out.push(cur); cur = null; } i++; continue; }
    if (cur === null) cur = '';
    if (c === "'" || c === '"') {
      var j = t.indexOf(c, i + 1);
      if (j < 0) throw new Bad('No closing quotation');
      cur += t.slice(i + 1, j); i = j + 1; continue;
    }
    cur += c; i++;
  }
  if (cur !== null) out.push(cur);
  return out;
}
var DEVICE_RE = /^(con|prn|aux|nul|com[0-9]|lpt[0-9]|conin\$|conout\$)(\..*)?$/i;
var SVC_RE = /^[A-Za-z0-9_.$@+-]{1,256}$/;
var ACCOUNT_RE = /^[^\x00-\x1f\x7f",=:*?<>|]{1,256}$/;
var SITE_RE = /^[^\x00-\x1f\x7f"]{1,256}$/;
/* acme_agent_win.norm_win: C:\folder as Windows writes it - or Bad */
function normWin(path) {
  var p = String(path === undefined || path === null ? '' : path).trim();
  if (!p || p.length > 1024 || /[\x00-\x1f\x7f]/.test(p)) throw new Bad(JSON.stringify(p.slice(0, 120)) + ' is not an absolute path (C:\\folder)');
  if (/^[\\\/][\\\/]/.test(p)) throw new Bad(p.slice(0, 120) + ' is a network (UNC) or device path - only a folder on a drive of this machine (C:\\folder)');
  p = p.replace(/\//g, '\\');
  var m = p.match(/^([A-Za-z]):\\([\s\S]*)$/);
  if (!m) throw new Bad(JSON.stringify(p.slice(0, 120)) + ' is not an absolute path (C:\\folder)');
  var parts = m[2].split('\\').filter(function (x) { return x !== '' && x !== '.'; });
  if (parts.indexOf('..') >= 0) throw new Bad('a path with .. in it: ' + p.slice(0, 120));
  parts.forEach(function (x) {
    if (x.indexOf(':') >= 0) throw new Bad(p.slice(0, 120) + ': a ":" after the drive (an alternate data stream) - refused');
    if (/[<>"|?*]/.test(x)) throw new Bad(p.slice(0, 120) + ' holds a character no Windows path holds');
    if (/[. ]$/.test(x)) throw new Bad(p.slice(0, 120) + ': a name ending in a dot or a space (Windows drops it) - write the name as it is');
    if (DEVICE_RE.test(x)) throw new Bad(p.slice(0, 120) + ': ' + x + ' is a device name (CON, NUL, COM1 ...) - refused');
    if (/~\d/.test(x)) throw new Bad(p.slice(0, 120) + ': ' + x + ' looks like a short (8.3) name - write the long name');
  });
  return m[1].toUpperCase() + ':\\' + parts.join('\\');
}
/* under, as Windows compares: no case, `\`, a `*` a whole name */
function underWin(path, top) {
  var t = String(top).replace(/\\+$/, '');
  if (/^[A-Za-z]:$/.test(t)) return false;
  var re = new RegExp('^' + t.split('\\').map(function (x) { return x === '*:' ? '[a-z]:' : (x === '*' ? '[^\\\\]+' : x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')); }).join('\\\\') + '(\\\\|$)', 'i');
  return re.test(path);
}
function protectedWhyWin(path) {
  var i;
  if (/^[A-Za-z]:\\?$/.test(path)) return path + ' is a drive\'s root - acme-agent never writes there';
  for (i = 0; i < F.own.length; i++) {
    if (underWin(path, F.own[i])) return path + ' is acme-agent\'s own (' + F.own[i] + ') - never written by a job';
  }
  for (i = 0; i < F.protected.length; i++) {
    if (underWin(path, F.protected[i])) return path + ' is under ' + F.protected[i] + ' - Windows runs (or loads) what is there; acme-agent never writes there, whatever the policy says';
  }
  if (path.split('\\').some(function (x) { return arr(F.parts).indexOf(x.toLowerCase()) >= 0; })) return path + ' is in a .ssh folder - acme-agent never writes there';
  var ext = (path.split('\\').pop().match(/\.[^.]*$/) || [''])[0].toLowerCase();
  if (ext && arr(F.exec_ext).indexOf(ext) >= 0) return path + ': a file Windows runs or loads as a program (' + ext + ') - acme-agent never writes one (the analogue of the x bit)';
  return '';
}
/* acme_agent_win._shell_line */
function shellLineWin(argv) {
  if (!argv.length) return false;
  var prog = String(argv[0]).split(/[\\\/]/).pop().toLowerCase().replace(/\.exe$/, '');
  prog = prog.replace(/[0-9.]+$/, '') || prog;
  var rest = argv.slice(1).map(function (a) { return String(a).toLowerCase(); });
  var any = function (f) { return rest.some(f); };
  if (prog === 'cmd') return any(function (a) { return a.indexOf('/c') === 0 || a.indexOf('/k') === 0; });
  if (prog === 'powershell' || prog === 'pwsh') {
    return any(function (a) { return ['-c', '-e', '-ec', '-enc'].indexOf(a) >= 0 || ['-comm', '-encodedc', '/c', '/e'].some(function (p) { return a.indexOf(p) === 0; }); })
      || !any(function (a) { return a === '-file' || a === '-f'; });
  }
  if (['wscript', 'cscript', 'mshta', 'rundll32'].indexOf(prog) >= 0) return true;
  if (['python', 'py', 'pythonw'].indexOf(prog) >= 0) return any(function (a) { return a === '-c' || a === '-m'; });
  return false;
}
function siteLine(site) { return /[\s"']/.test(site) ? '"' + site + '"' : site; }
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
  var s = {files: [], units: [], tests: [], scripts: [], hashes: [], from: [], probe_local: false, probe: [],
    connect_on: false, connect: [], self_update: false, discover: [], limits: {files: F.limits.files, size: F.limits.size}};
  if (W()) { s.store = false; s.iis = []; s.rdp = false; s.roles = []; s.key_read = []; s.adcs = []; s.adcs_read = false; }
  return s;
}
/* discovery (1.0.125): allow discover [KIND,KIND] - ['*'] every kind, else the kinds */
function discRows(x) {
  var v = Array.isArray(x) ? x : (typeof x === 'string' ? x.split(',') : []);
  return v.map(function (k) { return String(k).trim(); }).filter(Boolean);
}
/** The kinds a state allows, as the agent's discover_entry has them: ['*'], the kinds in the
    agent's own order, or null when one of them is no kind it knows (the line not read). */
function discKinds(list) {
  var known = arr(F.discover_kinds), v = discRows(list);
  if (!v.length) return [];
  if (v.indexOf('*') >= 0) return ['*'];
  if (v.some(function (k) { return known.indexOf(k) < 0; })) return null;
  return known.filter(function (k) { return v.indexOf(k) >= 0; });
}
function discLine(kinds) { return kinds[0] === '*' ? 'allow discover' : 'allow discover ' + kinds.join(','); }
function discCheck(s, R) {
  var k = discKinds(s.discover);
  R.discover = [];
  if (!discRows(s.discover).length) return [];
  if (k === null) {
    var bad = discRows(s.discover).filter(function (x) { return x !== '*' && arr(F.discover_kinds).indexOf(x) < 0; })[0];
    R.discover.push(verdict([msg('bad', 'unread', JSON.stringify(String(bad).slice(0, 40)) + ' is not a kind of service this agent discovers (' + arr(F.discover_kinds).join(', ') + ')')]));
    return [];
  }
  R.discover.push(verdict([msg('info', 'read-only', 'read-only: acme lists what the server runs and the certificates there - nothing is changed')]));
  return k;
}
/* 1.0.140 (A1): what a deployment may deploy - allow issuer sha256=HEX, allow names, require key
   local - as the agent's guard_entry reads them; their lines after discovery, before the limits */
var NAME_PAT = /^(\*\.)?[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$/;
function namePattern(w) {
  w = String(w || '').trim().toLowerCase().replace(/\.$/, '');
  var ip = ipAddress(w);
  if (ip) return ip;
  if (!NAME_PAT.test(w) || w.length > 253) throw new Bad(JSON.stringify(w.slice(0, 80)) + ' is not a name of a certificate (www.example.com, *.example.com or an address)');
  if (w.indexOf('*.') === 0 && w.slice(2).indexOf('.') < 0) throw new Bad(w + ' would allow every name under a top-level domain - name the domain (*.example.com)');
  return w;
}
function fpOf(x) { return String(x || '').replace(/[\s:]/g, '').toLowerCase(); }
function guardCheck(s, R, L) {
  var iss = [], names = [];
  R.issuers = [];
  R.names = [];
  R.guardMsg = null;
  arr(s.issuers).forEach(function (x) {
    var fp = fpOf(x);
    if (!HEX64.test(fp)) { R.issuers.push(verdict([msg('bad', 'unread', 'allow issuer sha256=HEX (the SHA-256 of a CA\'s certificate)')])); return; }
    if (iss.indexOf(fp) < 0) iss.push(fp);
    R.issuers.push(verdict([]));
  });
  arr(s.names).forEach(function (x) {
    if (String(x).trim() === '') return;          /* the one being typed */
    try {
      var n = namePattern(x);
      if (names.indexOf(n) < 0) names.push(n);
      R.names.push(verdict([]));
    } catch (e) { if (!(e instanceof Bad)) throw e; R.names.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  if (names.length && !iss.length) R.guardMsg = msg('warn', 'names-alone', 'allow names without allow issuer: a certificate of any CA for these names is deployed - name the CAs too (allow issuer sha256=...)');
  iss.forEach(function (fp) { L.push('allow issuer sha256=' + fp); });
  for (var i = 0; i < names.length; i += 8) L.push('allow names ' + names.slice(i, i + 8).join(' '));
  if (s.key_local) L.push('require key local');
  return {issuers: iss, names: names, key_local: !!s.key_local};
}
function guardLine(l) { return l.indexOf('allow issuer ') === 0 || l.indexOf('allow names ') === 0 || l === 'require key local'; }
function guardState(s, p) {
  if (arr(p.issuers).length) s.issuers = arr(p.issuers).map(String);
  if (arr(p.names).length) s.names = arr(p.names).map(String);
  if (p.key_local) s.key_local = true;
}
/* a Microsoft CA asked through the agent (1.0.125): [{ca, templates: [names] | ['*']}] */
function adcsRows(x) {
  return arr(x).filter(function (r) { return r && typeof r === 'object'; }).map(function (r) {
    var t = Array.isArray(r.templates) ? r.templates : String(r.templates || '').split(',');
    return {ca: String(r.ca || ''), templates: t.map(function (y) { return String(y).trim(); }).filter(Boolean)};
  });
}
/* the Windows roles (1.0.120): {role: [path | msi]} of the agent's policy -> rows {role, extra} */
function roleRows(x) {
  if (Array.isArray(x)) return x.filter(function (r) { return r && typeof r === 'object'; }).map(function (r) { return {role: String(r.role || ''), extra: String(r.extra || '')}; });
  var out = [];
  Object.keys(x || {}).sort().forEach(function (k) {
    var ex = arr(x[k]);
    if (!ex.length) out.push({role: k, extra: ''});
    ex.forEach(function (e) { out.push({role: k, extra: String(e)}); });
  });
  return out;
}
function roleInfo(key) { return arr(F.roles).filter(function (r) { return r[0] === key; })[0] || null; }
function winFile(f) { return {dir: String(f.dir || ''), readers: arr(f.readers).map(String)}; }
/** The state of a policy the agent said (policy_report). */
function fromPolicy(p) {
  var s = empty();
  if (!p) return s;
  s.files = arr(p.files).map(function (f) { return W() ? winFile(f) : {dir: String(f.dir), owner: String(f.owner || 'root'), group: String(f.group || f.owner || 'root'), mode: Number(f.mode) & 511}; });
  if (W()) { s.store = !!p.store; s.iis = arr(p.iis).map(String); s.rdp = !!p.rdp; s.roles = roleRows(p.roles); s.key_read = arr(p.key_read).map(String); s.adcs = adcsRows(p.adcs); s.adcs_read = !!p.adcs_read; }
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
  s.discover = discRows(p.discover);
  guardState(s, p);
  if (p.limits) s.limits = {files: Number(p.limits.files) || F.limits.files, size: Number(p.limits.size) || F.limits.size};
  return s;
}
/** A state kept (a design's): of the shapes the builder draws. */
function fromSaved(x) {
  var s = empty();
  if (!x || typeof x !== 'object') return s;
  s.files = arr(x.files).filter(function (f) { return f && typeof f === 'object'; }).map(function (f) {
    return W() ? winFile(f) : {dir: String(f.dir || ''), owner: String(f.owner || ''), group: String(f.group || ''), mode: Number(f.mode) & 511};
  });
  if (W()) { s.store = !!x.store; s.iis = arr(x.iis).map(String); s.rdp = !!x.rdp; s.roles = roleRows(x.roles); s.key_read = arr(x.key_read).map(String); s.adcs = adcsRows(x.adcs); s.adcs_read = !!x.adcs_read; }
  s.units = arr(x.units).filter(function (u) { return u && typeof u === 'object'; }).map(function (u) { return {name: String(u.name || ''), verbs: arr(u.verbs).map(String)}; });
  s.tests = arr(x.tests).map(function (t) { return Array.isArray(t) ? t.map(String) : split(String(t)); });
  s.scripts = arr(x.scripts).filter(function (u) { return u && typeof u === 'object'; }).map(function (u) { return {path: String(u.path || ''), sha256: String(u.sha256 || '')}; });
  ['hashes', 'from', 'probe', 'connect'].forEach(function (k) { s[k] = arr(x[k]).map(String); });
  s.probe_local = !!x.probe_local;
  s.self_update = !!x.self_update;
  s.discover = discRows(x.discover);
  s.connect_on = !!x.connect_on || s.connect.length > 0;
  guardState(s, x);
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
  if (W()) return checkWin(s);
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
  /* quoted as the agent's policy_lines (hunt R t5: a\x2d.service unquoted was read back as ax2d.service) */
  Object.keys(pol.units).sort().forEach(function (u) { L.push('allow unit ' + quote(u) + ' ' + pol.units[u].join(',')); });
  pol.tests.forEach(function (t) { L.push('allow test -- ' + t.map(quote).join(' ')); });
  pol.scripts.forEach(function (x) { L.push('allow script ' + quote(x.path) + ' sha256=' + x.sha256); });
  pol.hashes.forEach(function (h) { L.push('allow script-hash ' + h); });
  pol.from.forEach(function (f) { L.push('allow from ' + f); });
  if (s.probe_local) L.push('allow probe local');
  pol.probe.forEach(function (c) { L.push('allow probe ' + c); });
  pol.connect.forEach(function (c) { L.push('allow connect ' + c); });
  if (s.self_update) L.push('allow self-update');
  pol.discover = discCheck(s, R);
  if (pol.discover.length) L.push(discLine(pol.discover));
  pol.guard = guardCheck(s, R, L);
  if (R.limits.files.level === 'ok' && Number(s.limits.files) !== F.limits.files) L.push('limit files ' + Number(s.limits.files));
  if (R.limits.size.level === 'ok' && Number(s.limits.size) !== F.limits.size) L.push('limit size ' + Number(s.limits.size));
  R.lines = L;
  R.pol = pol;
  var counts = {entries: L.length, warn: R.guardMsg ? 1 : 0, bad: 0};
  ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect', 'discover', 'issuers', 'names'].forEach(function (k) {
    R[k].forEach(function (v) { if (v.level === 'bad') counts.bad++; else if (v.level === 'warn') counts.warn++; });
  });
  ['files', 'size'].forEach(function (k) { if (R.limits[k].level === 'bad') counts.bad++; });
  R.counts = counts;
  return R;
}
/** The state checked as a Windows server's agent checks it (acme_agent_win.py): folders with
    their readers, services, PowerShell scripts, the machine store, IIS sites, Remote Desktop. */
var ADCS_CA = /^[A-Za-z0-9][A-Za-z0-9.-]{0,252}\\[^\x00-\x1f\x7f"\\\/:*?<>|]{1,128}$/, ADCS_T = /^[A-Za-z0-9][A-Za-z0-9 _.()-]{0,63}$/;
function checkWin(s) {
  var R = {files: [], units: [], tests: [], scripts: [], hashes: [], from: [], probe: [], connect: [], iis: [], roles: [], key_read: [], adcs: [], limits: {}, pins: []};
  var pol = {files: [], units: {}, tests: [], scripts: [], hashes: [], from: [], probe: [], connect: [], iis: [], store: !!s.store, rdp: !!s.rdp, roles: {}, key_read: [], adcs: []};
  var tops = arr(F.protected).concat(arr(F.own));
  var lastDir = {};
  s.files.forEach(function (f, i) {
    var m = [], d = null;
    try {
      d = normWin(f.dir);
      if (/^[A-Za-z]:\\$/.test(d)) throw new Bad('a drive\'s root is no folder to allow');
      arr(f.readers).forEach(function (r) { if (!ACCOUNT_RE.test(String(r))) throw new Bad(JSON.stringify(String(r).slice(0, 80)) + ' is not an account (readers=ACCOUNT,ACCOUNT)'); });
      var why = protectedWhyWin(d);
      if (why) { m.push(msg('bad', 'protected', why.replace(' - never written by a job', ' - no job ever writes there'))); d = null; }
    } catch (e) {
      if (!(e instanceof Bad)) throw e;
      m.push(msg('bad', 'unread', e.words));
      d = null;
    }
    R.files.push({msgs: m, dir: d});
    if (d !== null) lastDir[d.toLowerCase()] = i;
  });
  s.files.forEach(function (f, i) {
    var r = R.files[i];
    if (r.dir === null) { R.files[i] = verdict(r.msgs); return; }
    var d = r.dir;
    if (lastDir[d.toLowerCase()] !== i) r.msgs.push(msg('warn', 'twice', 'files in ' + d + ' are said twice: only the last one counts'));
    else {
      var rd = [];
      arr(f.readers).map(function (x) { return String(x).trim(); }).filter(Boolean).forEach(function (x) { if (!rd.some(function (y) { return y.toLowerCase() === x.toLowerCase(); })) rd.push(x); });
      if (rd.length > 16) r.msgs.push(msg('bad', 'unread', 'readers= names sixteen accounts at most'));
      pol.files.push({dir: d, readers: rd});
    }
    var und = tops.filter(function (t) { return t.indexOf('*') < 0 && underWin(t, d) && t.toLowerCase() !== d.toLowerCase(); });
    if (/^[A-Za-z]:\\Users(\\[^\\]+)?$/i.test(d)) und.push(d + '\\...\\AppData');
    if (und.length) r.msgs.push(msg('warn', 'above-protected', d + ' holds places no job ever writes (' + und.slice(0, 3).join(', ') + (und.length > 3 ? ' …' : '') + '): the rest of it is allowed - allow the narrowest folder that holds only certificates'));
    R.files[i] = verdict(r.msgs);
  });
  var dirs = pol.files.map(function (f) { return f.dir; });
  function inside(p) { return dirs.filter(function (d) { return underWin(p, d) && p.toLowerCase() !== d.toLowerCase(); }); }
  s.units.forEach(function (u) {
    var m = [];
    try {
      var verbs = arr(u.verbs).filter(Boolean);
      if (verbs.filter(function (v) { return F.verbs.indexOf(v) < 0; }).length || !verbs.length) throw new Bad('the verbs are ' + F.verbs.join(', '));
      var name = String(u.name || '').trim();
      if (!SVC_RE.test(name) || name[0] === '-') throw new Bad(JSON.stringify(name.slice(0, 80)) + ' is not a service name');
      name = name.toLowerCase();
      var have = pol.units[name] || (pol.units[name] = []);
      verbs.forEach(function (v) { if (have.indexOf(v) < 0) have.push(v); });
    } catch (e) { if (!(e instanceof Bad)) throw e; m.push(msg('bad', 'unread', e.words)); }
    R.units.push(verdict(m));
  });
  var seenT = {};
  s.tests.forEach(function (t) {
    var m = [];
    try {
      var argv = checkArgv(Array.isArray(t) ? t : splitWin(String(t)));
      if (/\.(bat|cmd)$/i.test(argv[0])) throw new Bad(argv[0] + ' is a batch file: cmd.exe would read its arguments as commands - a program (.exe) or a script (allow script C:\\x.ps1)');
      var k = JSON.stringify(argv);
      if (seenT[k]) m.push(msg('warn', 'twice', 'this command line is said twice'));
      else { seenT[k] = 1; pol.tests.push(argv); }
      if (shellLineWin(argv)) m.push(msg('warn', 'shell', argv.slice(0, 3).map(wq).join(' ') + ' runs what its command line says as SYSTEM - a fixed script (allow script) says what it runs'));
      argv.forEach(function (w) {
        var p = null;
        try { if (/^[A-Za-z]:[\\\/]/.test(w)) p = normWin(w); } catch (e) { p = null; }
        if (p && inside(p).length) m.push(msg('warn', 'runs-from', w + ' is in a folder allowed for files (' + inside(p)[0] + '): the test runs it, so a job never writes it'));
      });
    } catch (e) { if (!(e instanceof Bad)) throw e; m.push(msg('bad', 'unread', e.words)); }
    R.tests.push(verdict(m));
  });
  var lastScript = {}, sp = [];
  s.scripts.forEach(function (x, i) {
    var p = null;
    try {
      p = normWin(x.path);
      if (!/\.ps1$/i.test(p)) throw new Bad('a script on Windows is a PowerShell script (.ps1) - a program is a test (allow test -- C:\\x.exe)');
    } catch (e) { if (!(e instanceof Bad)) throw e; sp.push(e.words); return; }
    sp.push(null);
    lastScript[p.toLowerCase()] = i;
  });
  s.scripts.forEach(function (x, i) {
    var m = [];
    if (sp[i]) { R.scripts.push(verdict([msg('bad', 'unread', sp[i])])); return; }
    var p = normWin(x.path), h = String(x.sha256 || '').trim().toLowerCase();
    if (lastScript[p.toLowerCase()] !== i) m.push(msg('warn', 'twice', 'the script ' + p + ' is said twice: only the last one counts'));
    if (h && !HEX64.test(h)) m.push(msg('bad', 'unread', 'allow script PATH sha256=HEX (acme-agent allow script PATH pins it)'));
    else if (lastScript[p.toLowerCase()] === i) {
      if (h) pol.scripts.push({path: p, sha256: h});
      else { m.push(msg('info', 'pin', 'pinned on the server: acme-agent allow script ' + wq(p))); R.pins.push(p); }
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
    try { var n = ipNetwork(a); if (pol.from.indexOf(n) < 0) pol.from.push(n); R.from.push(verdict([])); }
    catch (e) { if (!(e instanceof Bad)) throw e; R.from.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  s.probe.forEach(function (a) {
    try { var n = normHostport(a); if (pol.probe.indexOf(n) < 0) pol.probe.push(n); R.probe.push(verdict([])); }
    catch (e) { if (!(e instanceof Bad)) throw e; R.probe.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  (s.connect_on ? s.connect : []).forEach(function (a) {
    try {
      var n = normHostport(a);
      if (pol.connect.indexOf(n) < 0) pol.connect.push(n);
      R.connect.push(verdict([msg('warn', 'connect', 'acme may reach ' + n + ' through this server (a connector of SSH targets)')]));
    } catch (e) { if (!(e instanceof Bad)) throw e; R.connect.push(verdict([msg('bad', 'unread', e.words)])); }
  });
  arr(s.iis).forEach(function (x) {
    var site = String(x || '').trim();
    if (!SITE_RE.test(site)) { R.iis.push(verdict([msg('bad', 'unread', 'allow iis SITE (the name of an IIS site, or *)')])); return; }
    var m = [];
    if (pol.iis.some(function (y) { return y.toLowerCase() === site.toLowerCase(); })) m.push(msg('warn', 'twice', 'the site ' + site + ' is said twice'));
    else pol.iis.push(site);
    if (site === '*') m.push(msg('info', 'any', 'every IIS site of this server'));
    R.iis.push(verdict(m));
  });
  /* the Windows roles: allow role NAME [path=FOLDER (ccs) | msi=FILE (wac)] - acme_agent_win.role_entry */
  arr(s.roles).forEach(function (r) {
    var key = String(r.role || ''), info = roleInfo(key), ex = String(r.extra || '').trim(), m = [];
    if (!info) { R.roles.push(verdict([msg('bad', 'unread', 'allow role NAME - one of ' + arr(F.roles).map(function (x) { return x[0]; }).join(', '))])); return; }
    if (ex && !info[2]) { R.roles.push(verdict([msg('bad', 'unread', 'allow role ' + key + ' takes nothing more')])); return; }
    if (key === 'ccs' && !ex) { R.roles.push(verdict([msg('bad', 'unread', 'allow role ccs path=FOLDER (the folder of the Central Certificate Store: C:\\ccs or \\\\server\\share)')])); return; }
    if (ex) {
      if (/^\\\\[^\\\x00-\x1f\x7f\/:*?"<>|]+\\[^\x00-\x1f\x7f*?"<>|]+$/.test(ex) && key === 'ccs') ex = ex.replace(/\\+$/, '');
      else {
        try { ex = normWin(ex); } catch (e) { if (!(e instanceof Bad)) throw e; R.roles.push(verdict([msg('bad', 'unread', e.words)])); return; }
        if (key === 'wac' && !/\.msi$/i.test(ex)) { R.roles.push(verdict([msg('bad', 'unread', 'allow role wac msi=C:\\PATH\\WindowsAdminCenter.msi')])); return; }
        if (key === 'ccs') {
          if (/^[A-Z]:\\$/.test(ex)) { R.roles.push(verdict([msg('bad', 'unread', 'a drive\'s root is no folder of the Central Certificate Store')])); return; }
          var why = protectedWhyWin(ex);
          if (why) { R.roles.push(verdict([msg('bad', 'protected', why)])); return; }
        }
      }
    }
    var have = pol.roles[key] || (pol.roles[key] = []);
    if (ex) {
      if (have.some(function (y) { return y.toLowerCase() === ex.toLowerCase(); })) m.push(msg('warn', 'twice', 'the role ' + key + ' ' + ex + ' is said twice'));
      else have.push(ex);
    }
    if (key === 'wac' && ex) m.push(msg('info', 'msi', 'the agent may run this installer again (as SYSTEM) to set the certificate of a Windows Admin Center before 2410'));
    R.roles.push(verdict(m));
  });
  arr(s.key_read).forEach(function (a) {
    var acct = String(a || '').trim();
    if (!/^[^\x00-\x1f\x7f",=:*?<>|]{1,256}$/.test(acct)) { R.key_read.push(verdict([msg('bad', 'unread', 'allow key-read ACCOUNT ("NT SERVICE\\MyService", DOMAIN\\svc)')])); return; }
    var m = [];
    if (pol.key_read.some(function (y) { return y.toLowerCase() === acct.toLowerCase(); })) m.push(msg('warn', 'twice', 'the account ' + acct + ' is said twice'));
    else pol.key_read.push(acct);
    R.key_read.push(verdict(m));
  });
  /* a Microsoft CA (1.0.125): allow adcs "HOST\CA Name" template=A,B | template=* - acme_agent_wincert.adcs_entry */
  arr(s.adcs).forEach(function (r) {
    var ca = String(r.ca || '').trim(), ts = arr(r.templates).map(function (t) { return String(t).trim(); }).filter(Boolean), m = [];
    var bad = function (w) { R.adcs.push(verdict([msg('bad', 'unread', w)])); };
    if (!ADCS_CA.test(ca) || / $/.test(ca) || ca.indexOf('\\ ') >= 0) { bad('allow adcs "HOST\\CA Name" template=NAME,NAME - the CA\'s config string: its server, a backslash, its name'); return; }
    if (!ts.length) { bad('template= names a template or more (template=WebServer,WebServer2) or is * (any template of the CA)'); return; }
    if (ts.indexOf('*') >= 0 && ts.length > 1) { bad('template=* is any template of the CA - no names beside it'); return; }
    var badT = ts.filter(function (t) { return t !== '*' && !ADCS_T.test(t); });
    if (badT.length) { bad(JSON.stringify(badT[0]) + ' is not the name of a template (its name, not its display name: WebServer)'); return; }
    var mine = [];
    ts.forEach(function (t) { if (!mine.some(function (y) { return y.toLowerCase() === t.toLowerCase(); })) mine.push(t); });
    var have = pol.adcs.filter(function (x) { return x.ca.toLowerCase() === ca.toLowerCase(); })[0];
    if (have) {
      m.push(msg('warn', 'twice', 'the CA ' + ca + ' is said twice: its templates are taken together'));
      if (have.templates[0] === '*' || mine[0] === '*') have.templates = ['*'];
      else mine.forEach(function (t) { if (!have.templates.some(function (y) { return y.toLowerCase() === t.toLowerCase(); })) have.templates.push(t); });
    } else pol.adcs.push({ca: ca, templates: mine});
    if (mine[0] === '*') m.push(msg('info', 'any', 'any template this CA offers'));
    R.adcs.push(verdict(m));
  });
  if ((pol.iis.length || pol.rdp || Object.keys(pol.roles).length || pol.key_read.length) && !pol.store) R.storeMsg = msg('warn', 'no-store', 'IIS, Remote Desktop and the roles take the certificate from the machine store: allow store too');
  ['files', 'size'].forEach(function (k) {
    var v = Number(s.limits && s.limits[k]), top = k === 'files' ? F.limits.files_most : F.limits.size_most;
    R.limits[k] = (Math.floor(v) === v && v >= 1 && v <= top) ? verdict([]) : verdict([msg('bad', 'unread', 'limit ' + k + ' is 1 to ' + top)]);
  });
  var L = [];
  pol.files.forEach(function (f) { L.push('allow file ' + wq(f.dir) + (f.readers.length ? ' readers=' + wq(f.readers.join(',')) : '')); });
  Object.keys(pol.units).sort().forEach(function (u) { L.push('allow service ' + u + ' ' + pol.units[u].join(',')); });
  pol.tests.forEach(function (t) { L.push('allow test -- ' + t.map(wq).join(' ')); });
  pol.scripts.forEach(function (x) { L.push('allow script ' + wq(x.path) + ' sha256=' + x.sha256); });
  pol.hashes.forEach(function (h) { L.push('allow script-hash ' + h); });
  pol.from.forEach(function (f) { L.push('allow from ' + f); });
  if (s.probe_local) L.push('allow probe local');
  pol.probe.forEach(function (c) { L.push('allow probe ' + c); });
  pol.connect.forEach(function (c) { L.push('allow connect ' + c); });
  if (s.self_update) L.push('allow self-update');
  if (pol.store) L.push('allow store');
  pol.iis.forEach(function (x) { L.push('allow iis ' + siteLine(x)); });
  if (pol.rdp) L.push('allow rdp');
  Object.keys(pol.roles).sort().forEach(function (k) {
    var ex = pol.roles[k];
    if (!ex.length) L.push('allow role ' + k);
    ex.forEach(function (e) { L.push('allow role ' + k + ' ' + (k === 'wac' ? 'msi=' : 'path=') + siteLine(e)); });
  });
  pol.key_read.forEach(function (a) { L.push('allow key-read ' + siteLine(a)); });
  pol.discover = discCheck(s, R);
  if (pol.discover.length) L.push(discLine(pol.discover));
  pol.guard = guardCheck(s, R, L);
  /* template names with a space or brackets quoted, as the agent's adcs_names_word (hunt R t2:
     unquoted, the agent refused the whole line) */
  pol.adcs.forEach(function (x) { var n = x.templates.join(','); L.push('allow adcs "' + x.ca + '" template=' + (/[^A-Za-z0-9_.,*-]/.test(n) ? '"' + n + '"' : n)); });
  if (s.adcs_read) L.push('allow adcs-read');
  if (R.limits.files.level === 'ok' && Number(s.limits.files) !== F.limits.files) L.push('limit files ' + Number(s.limits.files));
  if (R.limits.size.level === 'ok' && Number(s.limits.size) !== F.limits.size) L.push('limit size ' + Number(s.limits.size));
  R.lines = L;
  R.pol = pol;
  var counts = {entries: L.length, warn: (R.storeMsg ? 1 : 0) + (R.guardMsg ? 1 : 0), bad: 0};
  ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect', 'iis', 'roles', 'key_read', 'adcs', 'discover', 'issuers', 'names'].forEach(function (k) {
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
  if (W()) return allowLinesWin(R);
  var p = R.pol, out = [];
  p.files.forEach(function (f) { out.push('sudo acme-agent allow file ' + quote(f.dir) + ' --owner ' + f.owner + ':' + f.group + ' --mode ' + oct4(f.mode)); });
  Object.keys(p.units).sort().forEach(function (u) { out.push('sudo acme-agent allow unit ' + quote(u) + ' ' + p.units[u].join(',')); });
  p.tests.forEach(function (t) { out.push('sudo acme-agent allow test -- ' + t.map(quote).join(' ')); });
  p.scripts.map(function (x) { return x.path; }).concat(R.pins).forEach(function (x) { out.push('sudo acme-agent allow script ' + quote(x)); });
  p.hashes.forEach(function (h) { out.push('sudo acme-agent allow script-hash ' + h); });
  p.from.forEach(function (f) { out.push('sudo acme-agent allow from ' + f); });
  R.lines.forEach(function (l) {
    if (l.indexOf('allow probe ') === 0 || l.indexOf('allow connect ') === 0 || l === 'allow self-update' || l.indexOf('allow discover') === 0) out.push('sudo acme-agent ' + l);
    if (guardLine(l)) out.push('sudo acme-agent ' + l);
    if (l.indexOf('limit ') === 0) out.push('sudo acme-agent ' + l);
  });
  return out;
}
/** Windows: the same, in an elevated prompt (no sudo). */
function allowLinesWin(R) {
  var p = R.pol, out = [], A = 'acme-agent ';
  p.files.forEach(function (f) { out.push(A + 'allow file ' + wq(f.dir) + (f.readers.length ? ' --readers ' + wq(f.readers.join(',')) : '')); });
  Object.keys(p.units).sort().forEach(function (u) { out.push(A + 'allow service ' + u + ' ' + p.units[u].join(',')); });
  p.tests.forEach(function (t) { out.push(A + 'allow test -- ' + t.map(wq).join(' ')); });
  p.scripts.map(function (x) { return x.path; }).concat(R.pins).forEach(function (x) { out.push(A + 'allow script ' + wq(x)); });
  p.hashes.forEach(function (h) { out.push(A + 'allow script-hash ' + h); });
  p.from.forEach(function (f) { out.push(A + 'allow from ' + f); });
  R.lines.forEach(function (l) {
    if (l.indexOf('allow probe ') === 0 || l.indexOf('allow connect ') === 0 || l === 'allow self-update' || l === 'allow store' ||
        l.indexOf('allow iis ') === 0 || l === 'allow rdp' || l.indexOf('allow role ') === 0 || l.indexOf('allow key-read ') === 0 ||
        l.indexOf('allow adcs ') === 0 || l === 'allow adcs-read' || l.indexOf('allow discover') === 0 ||
        guardLine(l) || l.indexOf('limit ') === 0) out.push(A + l);
  });
  return out;
}
/** Policy lines (a template's, a design's) as the commands that write them on the server
    (1.0.147): one `acme-agent ...` per entry - a file's owner=/mode= (Windows readers=) as the
    command's options, a script's sha256= read again there (allow script PATH pins it), the
    audit chain `audit on`. sudo only when asked (never on Windows: an elevated prompt). */
function asCommands(lines, win, sudo) {
  var A = (sudo && !win ? 'sudo ' : '') + 'acme-agent ', out = [], q = win ? wq : quote;
  arr(lines).forEach(function (raw) {
    var l = String(raw == null ? '' : raw).trim();
    if (!l || l.charAt(0) === '#') return;
    if (l === 'audit chain') { out.push(A + 'audit on'); return; }
    var w = null;
    try { w = win ? splitWin(l) : split(l); } catch (e) { w = null; }
    if (w && w[0] === 'allow' && (w[1] === 'file' || w[1] === 'script')) {
      var kv = {}, rest = [];
      w.slice(2).forEach(function (x) { var m = /^([a-z0-9_-]+)=(.*)$/.exec(x); if (m) kv[m[1]] = m[2]; else rest.push(x); });
      if (rest.length === 1) {
        if (w[1] === 'script') { out.push(A + 'allow script ' + q(rest[0])); return; }
        var c = A + 'allow file ' + q(rest[0]);
        if (win) { if (kv.readers) c += ' --readers ' + wq(kv.readers); }
        else { if (kv.owner) c += ' --owner ' + quote(kv.owner); if (kv.mode) c += ' --mode ' + quote(kv.mode); }
        out.push(c);
        return;
      }
    }
    out.push(A + l);
  });
  return out;
}
/** One block to paste on the server: the whole policy written (checked first there). */
function oneShot(R) {
  if (W()) {
    /* an elevated PowerShell: a here-string piped to the agent */
    return "@'\n" + fileText(R) + "'@ | acme-agent policy apply -" +
      (R.pins.length ? '\n' + R.pins.map(function (p) { return 'acme-agent allow script ' + wq(p); }).join('\n') : '');
  }
  return "sudo acme-agent policy apply - <<'EOF'\n" + fileText(R) + 'EOF' +
    (R.pins.length ? '\n' + R.pins.map(function (p) { return 'sudo acme-agent allow script ' + quote(p); }).join('\n') : '');
}
/* 1.0.148: a line of a policy or a command, coloured as the shell reads it - each word kept
   whole (a line wraps between words, a long path after a /), the text exactly the line */
function wbrText(x, w) {
  var bits = String(w).split(/(?<=\/)(?=[^\/])/);
  bits.forEach(function (b, i) { if (i) x.appendChild(document.createElement('wbr')); x.appendChild(document.createTextNode(b)); });
}
var VERBS = {allow: 1, limit: 1, require: 1, audit: 1, policy: 1};
function paintWords(t, l) {
  var parts = l.match(/\s+|'[^']*'?|"[^"]*"?|[^\s'"]+(?:'[^']*'?|"[^"]*"?|[^\s'"]+)*/g) || [l];
  var seen = 0, after = '';
  parts.forEach(function (w) {
    if (/^\s+$/.test(w)) { t.appendChild(document.createTextNode(w)); return; }
    var c = '';
    if (w === 'sudo') c = 'k-sudo';
    else if (w === 'acme-agent' || w === 'acme-agent.exe') c = 'k-bin';
    else if (VERBS[w] && (after === 'acme-agent' || seen === 0)) c = 'k-verb';
    else if (VERBS[after]) c = 'k-kind';
    else if (w === '--' || w === '-' || w === '|' || w === '<<\'EOF\'' || w === 'EOF' || w === "@'" || w === "'@") c = 'k-op';
    else if (/^--?[a-z]/.test(w)) c = 'k-opt';
    else if (/^[a-z][a-z0-9_-]*=/.test(w)) {
      var i = w.indexOf('=');
      var kv = el('span', 'k-w');
      var k = el('span', 'k-key');
      k.textContent = w.slice(0, i + 1);
      kv.appendChild(k);
      var v = el('span', 'k-val');
      wbrText(v, w.slice(i + 1));
      kv.appendChild(v);
      t.appendChild(kv);
      seen++; after = w;
      return;
    }
    else if (/^['"]/.test(w)) c = 'k-str';
    else if (/^[0-9]+$/.test(w)) c = 'k-num';
    var x = el('span', 'k-w' + (c ? ' ' + c : ''));
    wbrText(x, w);
    t.appendChild(x);
    seen++; after = w;
  });
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
function coversWin(s, R, it) {
  if (it.kind === 'store') return R.pol.store ? 'yes' : 'no';
  if (it.kind === 'rdp') return R.pol.rdp ? 'yes' : 'no';
  if (it.kind === 'iis') return R.pol.iis.some(function (x) { return x === '*' || x.toLowerCase() === String(it.site).toLowerCase(); }) ? 'yes' : 'no';
  if (it.kind === 'role') {
    var ex = R.pol.roles[it.role];
    if (!ex) return 'no';
    if (!it.extra) return 'yes';
    var want = String(it.extra).replace(/\//g, '\\').replace(/\\+$/, '').toLowerCase();
    return ex.some(function (y) { return y.replace(/\\+$/, '').toLowerCase() === want; }) ? 'yes' : 'no';
  }
  if (it.kind === 'key-read') return R.pol.key_read.some(function (y) { return y.toLowerCase() === String(it.account).toLowerCase(); }) ? 'yes' : 'no';
  if (it.kind === 'adcs') return R.pol.adcs.some(function (x) { return x.ca.toLowerCase() === String(it.ca).toLowerCase() && (x.templates[0] === '*' || x.templates.some(function (t) { return t.toLowerCase() === String(it.template).toLowerCase(); })); }) ? 'yes' : 'no';
  if (it.kind === 'file') {
    var path;
    try { path = normWin(it.path); } catch (e) { return e.words || 'not a path'; }
    var why = protectedWhyWin(path);
    if (!why) R.pol.scripts.forEach(function (x) { if (x.path.toLowerCase() === path.toLowerCase()) why = path + ' is a script the policy runs - never written by a job'; });
    if (why) return why;
    var best = null;
    R.pol.files.forEach(function (f) { if (underWin(path, f.dir) && (!best || f.dir.length > best.dir.length)) best = f; });
    return best ? 'yes' : 'no';
  }
  if (it.kind === 'unit') return arr(R.pol.units[String(it.unit).toLowerCase()]).indexOf(it.verb) >= 0 ? 'yes' : 'no';
  if (it.kind === 'script') return R.pol.scripts.some(function (x) { return x.path.toLowerCase() === String(it.path).toLowerCase(); }) || R.pins.indexOf(it.path) >= 0 ? 'yes' : 'no';
  return null;
}
function covers(s, R, it) {
  if (it.kind === 'discover') {
    var have = arr(R.pol.discover);
    if (have[0] === '*') return 'yes';
    var want = discRows(it.kinds);
    if (!want.length || want[0] === '*') return 'no';
    return want.every(function (k) { return have.indexOf(k) >= 0; }) ? 'yes' : 'no';
  }
  if (W()) { var w = coversWin(s, R, it); if (w !== null) return w; }
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
  if (it.kind === 'discover') {
    var now = discRows(s.discover), want = discRows(it.kinds);
    if (!want.length || want.indexOf('*') >= 0 || now.indexOf('*') >= 0) { s.discover = ['*']; return; }
    want.forEach(function (k) { if (now.indexOf(k) < 0) now.push(k); });
    s.discover = now;
    return;
  }
  if (W()) {
    if (it.kind === 'store') { s.store = true; return; }
    if (it.kind === 'rdp') { s.rdp = true; s.store = true; return; }
    if (it.kind === 'iis') { if (!arr(s.iis).some(function (x) { return x.toLowerCase() === String(it.site).toLowerCase(); })) s.iis.push(it.site); s.store = true; return; }
    if (it.kind === 'role') {
      s.roles = arr(s.roles);
      if (!s.roles.some(function (r) { return r.role === it.role && String(r.extra || '').toLowerCase() === String(it.extra || '').toLowerCase(); })) s.roles.push({role: it.role, extra: it.extra || ''});
      s.store = true;
      return;
    }
    if (it.kind === 'adcs') {
      s.adcs = arr(s.adcs);
      var ar = s.adcs.filter(function (x) { return String(x.ca).toLowerCase() === String(it.ca).toLowerCase(); })[0];
      if (!ar) { ar = {ca: it.ca, templates: []}; s.adcs.push(ar); }
      if (ar.templates[0] !== '*' && (it.template === '*' || !ar.templates.some(function (t) { return String(t).toLowerCase() === String(it.template).toLowerCase(); }))) {
        if (it.template === '*') ar.templates = ['*']; else ar.templates.push(it.template);
      }
      return;
    }
    if (it.kind === 'key-read') {
      s.key_read = arr(s.key_read);
      if (!s.key_read.some(function (y) { return y.toLowerCase() === String(it.account).toLowerCase(); })) s.key_read.push(it.account);
      s.store = true;
      return;
    }
    if (it.kind === 'file') {
      var wd = it.dir || String(it.path).replace(/[\\\/][^\\\/]*$/, '');
      if (!s.files.some(function (f) { return String(f.dir).toLowerCase() === wd.toLowerCase(); })) s.files.push({dir: wd, readers: []});
      return;
    }
    if (it.kind === 'unit') {
      var wx = s.units.filter(function (y) { return String(y.name).toLowerCase() === String(it.unit).toLowerCase(); })[0];
      if (!wx) { wx = {name: it.unit, verbs: []}; s.units.push(wx); }
      if (wx.verbs.indexOf(it.verb) < 0) wx.verbs.push(it.verb);
      return;
    }
  }
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
  if (W()) {
    arr(t.files).forEach(function (f) {
      var have = s.files.filter(function (x) { return String(x.dir).toLowerCase() === String(f.dir).toLowerCase(); })[0];
      if (have) arr(f.readers).forEach(function (r) { if (have.readers.indexOf(r) < 0) have.readers.push(r); });
      else s.files.push({dir: f.dir, readers: arr(f.readers).slice()});
    });
    if (t.store) s.store = true;
    if (t.rdp) s.rdp = true;
    arr(t.iis).forEach(function (x) { addNeed(s, {kind: 'iis', site: x}); });
    roleRows(t.roles).forEach(function (r) { addNeed(s, {kind: 'role', role: r.role, extra: r.extra}); });
    arr(t.key_read).forEach(function (a) { addNeed(s, {kind: 'key-read', account: a}); });
    adcsRows(t.adcs).forEach(function (r) { r.templates.forEach(function (x) { addNeed(s, {kind: 'adcs', ca: r.ca, template: x}); }); });
    if (t.adcs_read) s.adcs_read = true;
    Object.keys(t.units || {}).forEach(function (u) { t.units[u].forEach(function (v) { addNeed(s, {kind: 'unit', unit: u, verb: v}); }); });
    if (t.probe_local) s.probe_local = true;
    return;
  }
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
/** A fleet template's state (1.0.138, fleet.py: built-in or an administrator's own) added to the
    state: what it allows that is not there yet - nothing taken away. */
function mergeState(s, x) {
  var t = fromSaved(x);
  var tpl = {files: t.files, units: {}, tests: t.tests, scripts: t.scripts, probe_local: t.probe_local};
  t.units.forEach(function (u) { if (u.name) tpl.units[u.name] = arr(u.verbs).slice(); });
  if (W()) ['store', 'rdp', 'iis', 'roles', 'key_read', 'adcs', 'adcs_read'].forEach(function (k) { tpl[k] = t[k]; });
  addTemplate(s, tpl);
  ['hashes', 'from', 'probe', 'connect'].forEach(function (k) {
    arr(t[k]).forEach(function (v) { if (arr(s[k]).indexOf(v) < 0) s[k].push(v); });
  });
  if (t.connect.length) s.connect_on = true;
  if (t.self_update) s.self_update = true;
  if (discRows(t.discover).length) addNeed(s, {kind: 'discover', kinds: discRows(t.discover)});
  return s;
}
/** Whether all of a template is in the state already. */
function hasTemplate(s, R, t) {
  var x = clone(s);
  addTemplate(x, t);
  var a = check(x).lines.join('\n'), b = R.lines.join('\n');
  return a === b && JSON.stringify(x.scripts) === JSON.stringify(s.scripts);
}

var CORE = {setFacts: setFacts, facts: function () { return F; }, discKinds: discKinds, quote: quote, split: split, normDir: normDir, normUnit: normUnit,
  wq: wq, splitWin: splitWin, normWin: normWin, protectedWhyWin: protectedWhyWin,
  ipNetwork: ipNetwork, normHostport: normHostport, protectedWhy: protectedWhy, empty: empty, fromPolicy: fromPolicy,
  fromSaved: fromSaved, check: check, fileText: fileText, allowLines: allowLines, asCommands: asCommands, paintWords: paintWords, oneShot: oneShot, diff: diff, covers: covers,
  addNeed: addNeed, addTemplate: addTemplate, hasTemplate: hasTemplate, mergeState: mergeState, oct4: oct4, Bad: Bad,
  namePattern: namePattern};
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
  gauge: '<path d="M4 17a8 8 0 1 1 16 0"/><path d="M12 17l4-5"/>',
  screen: '<rect x="3" y="4.5" width="18" height="12" rx="2"/><path d="M8.5 20h7M12 16.5V20"/>',
  /* 1.0.140: a certificate with its seal - what the agent deploys */
  cert: '<rect x="3.5" y="4" width="17" height="12" rx="2"/><path d="M7.5 8h9M7.5 11h4"/><circle cx="16" cy="15.5" r="2.5"/><path d="M14.8 17.6l-.8 3 2-1 2 1-.8-3"/>'
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
var WIN_USERS = ['IIS_IUSRS', 'NT SERVICE\\W3SVC', 'NETWORK SERVICE', 'LOCAL SERVICE', 'Users', 'Authenticated Users'];
var OPENING = false;
function open(row, opts) {
  opts = opts || {};
  if (OPENING) return;
  var go = function () {
    if (OPENING) return;
    OPENING = true;
    /* 1.0.148: a fleet template on its own - no agent, no server (fleet.js "New template…") */
    var url = opts.template ? 'fleet/builder?platform=' + encodeURIComponent(opts.template.platform === 'windows' ? 'windows' : 'linux')
      : 'agents/builder?id=' + encodeURIComponent(row.id || row.name);
    ask(url).then(function (d) { OPENING = false; build(row, d, opts); }).catch(function (e) { OPENING = false; oops(e); });
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
  /* 1.0.138: opened from the fleet with a template (fleet.js): it is what the builder starts from */
  var TM = !!(opts.template && d.blank);
  var OT = TM ? opts.template : null;
  var FT = TM ? (OT.text || OT.state ? OT : null)
    : (opts.fleetTemplate && (opts.fleetTemplate.state || opts.fleetTemplate.text) ? opts.fleetTemplate : null);
  var B = {from: FT ? 'fleet' : (TM ? 'empty' : (version ? 'version' : (opts.from || (D ? 'design' : 'server')))), tab: 'file', q: '', fleet: null, sudo: true};
  try { B.sudo = localStorage.getItem('acme.pb.sudo') !== '0'; } catch (e) { /* the default: with sudo */ }
  var S;
  function startFrom(w) {
    B.from = w;
    /* a version saved without its state (the command line): its lines, as the design's */
    if (w === 'version' && version) S = opts.state && Object.keys(opts.state).length ? fromSaved(opts.state) : fromPolicyText(opts.text);
    else if (w === 'design' && D) S = D.state && Object.keys(D.state).length ? fromSaved(D.state) : fromPolicyText(D.text);
    else if (w === 'fleet' && FT) S = FT.state && Object.keys(FT.state).length ? fromSaved(FT.state) : fromPolicyText(FT.text);
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
        var w = W() ? splitWin(l) : split(l);
        /* 1.0.140 (A1): the same words on both platforms */
        if (w[0] === 'require' && w[1] === 'key' && w[2] === 'local') { s.key_local = true; return; }
        if (w[0] === 'allow' && w[1] === 'issuer') { var im = String(w[2] || '').match(/^sha256=(.*)$/); if (im) (s.issuers = arr(s.issuers)).push(fpOf(im[1])); return; }
        if (w[0] === 'allow' && w[1] === 'names') { s.names = arr(s.names).concat(w.slice(2)); return; }
        if (W()) {
          var wkv = {}, wr = [];
          w.slice(2).forEach(function (x) { var m = x.match(/^([a-z0-9_-]+)=(.*)$/); if (m) wkv[m[1]] = m[2]; else wr.push(x); });
          if (w[0] === 'limit') s.limits[w[1]] = Number(w[2]);
          else if (w[1] === 'file') s.files.push({dir: wr[0], readers: wkv.readers ? wkv.readers.split(',') : []});
          else if (w[1] === 'service' || w[1] === 'unit') s.units.push({name: wr[0], verbs: String(wr[1] || '').split(',')});
          else if (w[1] === 'test') s.tests.push(w[2] === '--' ? w.slice(3) : w.slice(2));
          else if (w[1] === 'script') s.scripts.push({path: wr[0], sha256: wkv.sha256 || ''});
          else if (w[1] === 'script-hash') s.hashes.push(wr[0]);
          else if (w[1] === 'from') s.from.push(wr[0]);
          else if (w[1] === 'probe') { if (wr[0] === 'local') s.probe_local = true; else s.probe.push(wr[0]); }
          else if (w[1] === 'connect') { s.connect.push(wr[0]); s.connect_on = true; }
          else if (w[1] === 'self-update') s.self_update = true;
          else if (w[1] === 'store') s.store = true;
          else if (w[1] === 'rdp') s.rdp = true;
          else if (w[1] === 'iis') s.iis.push(wr[0]);
          else if (w[1] === 'role') s.roles.push({role: wr[0], extra: wkv.path || wkv.msi || ''});
          else if (w[1] === 'key-read') s.key_read.push(wr[0]);
          else if (w[1] === 'adcs') s.adcs.push({ca: wr[0], templates: String(wkv.template || '').split(',')});
          else if (w[1] === 'adcs-read') s.adcs_read = true;
          else if (w[1] === 'discover') addNeed(s, {kind: 'discover', kinds: wr[0] ? wr[0].split(',') : ['*']});
          return;
        }
        if (w[0] === 'limit') { s.limits[w[1]] = Number(w[2]); return; }
        var kv = {}, rest = [];
        w.slice(2).forEach(function (x) { var m = x.match(/^([a-z0-9_-]+)=(.*)$/); if (m) kv[m[1]] = m[2]; else rest.push(x); });
        if (w[1] === 'file') { var o = (kv.owner || 'root:root').split(':'); s.files.push({dir: rest[0], owner: o[0], group: o[1] || o[0], mode: parseInt(kv.mode || '0644', 8)}); }
        else if (w[1] === 'unit') s.units.push({name: rest[0], verbs: String(rest[1] || '').split(',')});
        /* a test's words as they are: a word with = in it (postconf x=y) is the command's, not
           a key of the entry - it was taken out of the command line */
        else if (w[1] === 'test') s.tests.push(w[2] === '--' ? w.slice(3) : w.slice(2));
        else if (w[1] === 'script') s.scripts.push({path: rest[0], sha256: kv.sha256 || ''});
        else if (w[1] === 'script-hash') s.hashes.push(rest[0]);
        else if (w[1] === 'from') s.from.push(rest[0]);
        else if (w[1] === 'probe') { if (rest[0] === 'local') s.probe_local = true; else s.probe.push(rest[0]); }
        else if (w[1] === 'connect') { s.connect.push(rest[0]); s.connect_on = true; }
        else if (w[1] === 'self-update') s.self_update = true;
        else if (w[1] === 'discover') addNeed(s, {kind: 'discover', kinds: rest[0] ? rest[0].split(',') : ['*']});
      } catch (e) { /* a line the agent would not read: left out */ }
    });
    return s;
  }
  startFrom(B.from);
  /* 1.0.125: opened from what a discovery found ("Add to the policy", "Allow it…"): what that
     needs, ticked - Close asks before it is lost */
  arr(opts.add).forEach(function (it) { try { addNeed(S, it); } catch (e) { /* left out */ } });
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
    if (TM) w.appendChild(el('p', 'small', 'Click together what the agent may do on every server of this kind. Saved as a fleet template: agents and groups follow it, and the builder of each server starts from it. acme never sends a policy to a server.'));
    else w.appendChild(el('p', 'small', W() ? 'Click together what the agent may do on this server. acme never sends a policy: the result is copied to the server, where an administrator writes it - checked there again, as here.'
      : 'Click together what the agent may do on this server. acme never sends a policy: the result is copied to the server, where root writes it - checked there again, as here.'));
    var from = el('div', 'pb-from');
    from.appendChild(el('span', 'pb-k', 'Start from'));
    var seg = el('div', 'pb-seg');
    var choices = TM ? [] : [['server', A.policy ? 'its policy on the server' : 'its policy (not said yet)']];
    if (D) choices.push(['design', 'the saved design']);
    if (version) choices.push(['version', 'the version opened']);
    if (FT) choices.push(['fleet', TM ? 'the template' : 'the fleet template']);
    choices.push(['empty', 'nothing']);
    choices.forEach(function (c) {
      var b = el('button', 'pb-seg-b' + (B.from === c[0] ? ' on' : ''), c[1]);
      b.type = 'button';
      b.onclick = function () {
        if (B.from === c[0]) return;
        var go = function () {
          startFrom(c[0]);
          Array.prototype.forEach.call(seg.children, function (x) { x.classList.remove('on'); });
          b.classList.add('on');
          drawAll();
          refresh();
          B.startText = fileText(R);
        };
        /* hunt w9: what was clicked together or typed since it started from the one before was
           thrown away by one click here ("nothing" emptied every section) - asked first now,
           unless it was copied, downloaded or saved (taken) */
        if (B.startText !== undefined && R && fileText(R) !== B.startText && fileText(R) !== B.kept) modalSure('Start again from it? What was changed here is lost.', go, 'Start again');
        else go();
      };
      seg.appendChild(b);
    });
    from.appendChild(seg);
    w.appendChild(from);
    /* a new template: its platform, the builder of that platform's agent */
    if (TM && !OT.ref) {
      var pf = el('div', 'pb-from');
      pf.appendChild(el('span', 'pb-k', 'Platform'));
      var ps = el('div', 'pb-seg pb-plat');
      [['linux', 'Linux'], ['windows', 'Windows']].forEach(function (c) {
        var b = el('button', 'pb-seg-b' + ((W() ? 'windows' : 'linux') === c[0] ? ' on' : ''), c[1]);
        b.type = 'button';
        b.onclick = function () {
          if ((W() ? 'windows' : 'linux') === c[0]) return;
          var go = function () { closeModal(true); open(row, Object.assign({}, opts, {template: {platform: c[0], title: refs.title ? refs.title.value : '', note: refs.note ? refs.note.value : ''}})); };
          if (R && fileText(R) !== B.startText && fileText(R) !== B.kept) modalSure('Start again for the other platform? What was changed here is lost.', go, 'Start again');
          else go();
        };
        ps.appendChild(b);
      });
      pf.appendChild(ps);
      w.appendChild(pf);
    }
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
    ['connect', 'Connections for acme', 'plug'], ['discover', 'Discovery', 'search'], ['guard', 'What it deploys', 'cert'], ['update', 'Updates from acme', 'up'], ['limits', 'Limits', 'gauge']
  ];
  if (TM) SECTIONS = SECTIONS.filter(function (x) { return x[0] !== 'needs'; });
  /* 1.0.125: what the last discovery found on the server, with the lines each needs */
  var FOUND = arr(d.discovered && !d.discovered.refused && d.discovered.found).filter(function (f) { return arr(f.items).length; });
  if (FOUND.length) SECTIONS.splice(2, 0, ['found', 'From discovery', 'eye']);
  /* a Windows server's agent (1.0.120): services, and the machine store, IIS, Remote Desktop */
  if (W()) {
    /* by its key: with "From discovery" before it, [3] was Folders - its button gone, two of Units */
    var ui = SECTIONS.map(function (x) { return x[0]; }).indexOf('units');
    SECTIONS[ui] = ['units', 'Services', 'refresh'];
    SECTIONS.splice(ui + 1, 0, ['store', 'Machine store', 'lock'], ['iis', 'IIS sites', 'globe'], ['rdp', 'Remote Desktop', 'screen'],
      ['roles', 'Windows roles', 'wand'], ['key_read', 'Read on the key', 'key'], ['adcs', 'Microsoft CA (AD CS)', 'shield']);
  }
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
    (W() ? [drawTemplates, drawNeeds, drawFound, drawFiles, drawUnits, drawStore, drawIis, drawRdp, drawRoles, drawKeyRead, drawAdcs, drawTests, drawScripts, drawHashes, drawFrom, drawProbe, drawConnect, drawDiscover, drawGuard, drawUpdate, drawLimits]
      : [drawTemplates, drawNeeds, drawFound, drawFiles, drawUnits, drawTests, drawScripts, drawHashes, drawFrom, drawProbe, drawConnect, drawDiscover, drawGuard, drawUpdate, drawLimits])
      .forEach(function (f) { if (TM && f === drawNeeds) return; var n = f(); if (n) refs.main.appendChild(n); });
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
    var s = section('tpl', 'Templates', 'wand', W() ? 'One click adds a coherent set: the machine store, the IIS sites, Remote Desktop, a folder with its readers, a service and its verbs, a test of what it serves.'
      : 'One click adds a coherent set: the folder with its owner and mode (as the deployment presets write it), the units and their verbs, the test, a test of what it serves.');
    s.body.appendChild(fleetTemplates());
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
        var sub = arr(t.files).map(function (f) { return f.dir; }).concat(Object.keys(t.units || {}))
          .concat(t.store ? ['Cert:\\LocalMachine\\My'] : []).concat(arr(t.iis).map(function (x) { return 'IIS ' + x; })).concat(t.rdp ? ['RDP'] : [])
          .concat(roleRows(t.roles).map(function (r) { return 'role ' + r.role + (r.extra ? ' ' + r.extra : ''); }))
          .concat(adcsRows(t.adcs).map(function (r) { return 'AD CS ' + r.templates.join(',') + ' @ ' + r.ca; })).join(' · ');
        /* every word whole: wraps between them, a long path after a / */
        var sw = noI18n(el('span', 'pb-tpl-s'));
        String(sub).split(' · ').forEach(function (part, i) {
          if (i) sw.appendChild(document.createTextNode(' · '));
          var x = el('span', 'k-w');
          wbrText(x, part);
          sw.appendChild(x);
        });
        w.appendChild(sw);
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
  /* ---- the fleet's templates (1.0.138, fleet.py): whole policies - nginx web, Postfix + Dovecot,
     IIS, Remote Desktop ... and the administrators' own - one click adds all of one ---------- */
  function fleetTemplates() {
    var box = el('div', 'pb-fleet');
    var h = el('div', 'pb-fleet-h');
    h.appendChild(icon('people', 14));
    h.appendChild(el('b', '', 'Fleet templates'));
    h.appendChild(el('span', 'pb-sec-hint', 'whole policies kept in acme - the same for every server of a kind'));
    box.appendChild(h);
    var g = el('div', 'pb-tpls pb-fleet-l');
    box.appendChild(g);
    refs.ftpl = [];
    if (B.fleet === null) {
      B.fleet = 'asking';
      ask('fleet/templates?platform=' + encodeURIComponent(F.platform || 'linux')).then(function (x) {
        B.fleet = arr(x && x.templates);
        if (sec.tpl && sec.tpl.parentNode) redraw('tpl', drawTemplates);
      }).catch(function () { B.fleet = []; if (sec.tpl && sec.tpl.parentNode) redraw('tpl', drawTemplates); });
    }
    if (!Array.isArray(B.fleet)) { g.appendChild(el('p', 'muted small', 'Loading…')); return box; }
    if (!B.fleet.length) { g.appendChild(el('p', 'muted small', 'No fleet template for this platform.')); return box; }
    B.fleet.forEach(function (t) {
      var b = el('button', 'pb-tpl pb-ftpl' + (t.builtin ? '' : ' own'));
      b.type = 'button';
      b.appendChild(noI18n(el('span', 'pb-tpl-ic', abbr(t))));
      var w = el('span', 'pb-tpl-w');
      w.appendChild(t.builtin ? el('span', 'pb-tpl-n', t.title) : noI18n(el('span', 'pb-tpl-n', t.title)));
      var sub = el('span', 'pb-tpl-s pb-ftpl-s');
      sub.appendChild(el('span', '', t.builtin ? 'built-in' : 'yours'));
      sub.appendChild(noI18n(document.createTextNode(' · ')));
      var nl = arr(t.lines).length;
      sub.appendChild(el('span', '', nl + ' ' + (nl === 1 ? 'line' : 'lines')));
      w.appendChild(sub);
      b.appendChild(w);
      var mk = noI18n(el('span', 'pb-tpl-mk', ''));
      b.appendChild(mk);
      b.setAttribute('aria-label', tr('Add the fleet template') + ' ' + t.title);
      explain(b, (t.note ? t.note + '\n\n' : '') + arr(t.lines).join('\n'));
      b.onclick = function () {
        mergeState(S, t.state || {});
        drawAll();
        refresh();
        toast(tr('Added from the fleet template') + ': ' + t.title, 'good');
      };
      refs.ftpl.push({t: t, b: b, mk: mk});
      g.appendChild(b);
    });
    return box;
  }
  function paintTemplates() {
    arr(refs.ftpl).forEach(function (x) {
      var y = clone(S);
      mergeState(y, x.t.state || {});
      var on = check(y).lines.join('\n') === R.lines.join('\n');
      x.b.classList.toggle('on', on);
      x.mk.textContent = on ? '✓' : '+';
    });
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
    if (it.kind === 'discover') { var dk = discKinds(it.kinds) || []; return discLine(dk.length ? dk : ['*']); }
    if (W()) {
      if (it.kind === 'store') return 'Cert:\\LocalMachine\\My';
      if (it.kind === 'iis') return it.site;
      if (it.kind === 'rdp') return 'RDP-tcp';
      if (it.kind === 'role') return ((roleInfo(it.role) || [0, it.role])[1]) + (it.extra ? ' (' + it.extra + ')' : '');
      if (it.kind === 'key-read') return it.account;
      if (it.kind === 'adcs') return it.template + ' @ ' + it.ca;
      if (it.kind === 'file') return it.path;
      if (it.kind === 'unit') return ({restart: 'Restart-Service ', start: 'Start-Service ', 'try-restart': 'Restart-Service '}[it.verb] || it.verb + ' ') + it.unit;
      if (it.kind === 'test') return arr(it.argv).map(wq).join(' ');
    }
    if (it.kind === 'file') return it.path + '  ' + oct4(it.mode) + ' ' + (it.owner ? it.owner + ':' + (it.group || it.owner) : 'root:root');
    if (it.kind === 'unit') return 'systemctl ' + it.verb + ' ' + it.unit;
    if (it.kind === 'test') return arr(it.argv).map(quote).join(' ');
    if (it.kind === 'script') return it.path;
    if (it.kind === 'hash') return 'sha256 ' + it.hash.slice(0, 16) + '…';
    if (it.kind === 'probe') return it.hp;
    if (it.kind === 'limit') return it.files + ' files';
    return '';
  }
  var NEED_K = {file: 'file', unit: W() ? 'service' : 'unit', test: 'command', script: 'script', hash: 'the script written in acme', probe: 'test', limit: 'limit', any: 'one of',
    store: 'machine store', iis: 'IIS site', rdp: 'Remote Desktop', role: 'Windows role', 'key-read': 'read on the key', adcs: 'Microsoft CA',
    discover: 'discovery'};
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
  /* ---- discovery (1.0.125) ----------------------------------------------------------------- */
  var DISC_T = {nginx: 'nginx', apache: 'Apache httpd', haproxy: 'HAProxy', postfix: 'Postfix', dovecot: 'Dovecot', exim: 'Exim', tomcat: 'Tomcat',
    proxmox: 'Proxmox VE', pbs: 'Proxmox Backup Server', openldap: 'OpenLDAP', grafana: 'Grafana', cockpit: 'Cockpit', webmin: 'Webmin',
    vsftpd: 'vsftpd', mariadb: 'MySQL / MariaDB', files: 'certificate files', store: 'machine store', iis: 'IIS sites', rdp: 'Remote Desktop',
    sql: 'SQL Server', exchange: 'Exchange', adfs: 'AD FS', wap: 'Web Application Proxy', winrm: 'WinRM HTTPS', ldaps: 'LDAPS', sstp: 'SSTP VPN',
    ftp: 'IIS FTP', ccs: 'Central Certificate Store', rdgw: 'RD Gateway', rds: 'Remote Desktop Services', sharepoint: 'SharePoint',
    wac: 'Windows Admin Center', lync: 'Skype for Business'};
  function discToggle(k) {
    var now = discRows(S.discover);
    if (k === '*') S.discover = now[0] === '*' ? [] : ['*'];
    else if (now[0] === '*') S.discover = arr(F.discover_kinds).filter(function (x) { return x !== k; });
    else if (now.indexOf(k) >= 0) S.discover = now.filter(function (x) { return x !== k; });
    else S.discover = now.concat([k]);
    redraw('discover', drawDiscover);
  }
  function drawDiscover() {
    var s = section('discover', 'Discovery', 'search', W() ? 'acme may list what this server runs that takes certificates - the IIS sites and their bindings, the Remote Desktop listener, the roles, the machine store - read-only: nothing is changed, no key or password is read. Off unless it is here.'
      : 'acme may list what this server runs that takes certificates - the services, their files and the certificate each serves - read-only: nothing is changed, no key or password is read. Off unless it is here.');
    var now = discRows(S.discover), all = now[0] === '*';
    s.body.appendChild(switcher(all, 'every kind this agent knows (allow discover)', function () { discToggle('*'); }));
    var chips = el('div', 'pb-disc-kinds');
    arr(F.discover_kinds).forEach(function (k) {
      var on = all || now.indexOf(k) >= 0;
      var b = el('button', 'pb-chip-add' + (on ? ' on' : ''));
      b.type = 'button';
      b.disabled = all;
      b.appendChild(noI18n(el('span', 'pb-chip-p', on ? '✓' : '+')));
      b.appendChild(mono(k));
      b.appendChild(el('span', 'muted small', DISC_T[k] || k));
      b.onclick = function () { discToggle(k); };
      chips.appendChild(b);
    });
    s.body.appendChild(chips);
    refs.discSaid = said();
    s.body.appendChild(refs.discSaid);
    return s.node;
  }
  function drawFound() {
    if (!FOUND.length) return null;
    var v = d.discovered;
    var s = section('found', 'From discovery', 'eye', 'What the last discovery found on the server (' + ago(v.at) + '): each service with what a deployment there needs - add it with one click.');
    refs.found = [];
    var all = cmdButton('Add all that the services found need', 'add', 'small pb-addall');
    all.onclick = function () {
      var n = 0;
      FOUND.forEach(function (f) { arr(f.items).forEach(function (it) { if (covers(S, R, it) === 'no') { addNeed(S, it); R = check(S); n++; } }); });
      drawAll();
      refresh();
      toast(n ? tr('Added') + ': ' + n : tr('the policy allows all of it already'), 'good');
    };
    refs.foundAll = all;
    var br = el('div', 'pb-needs-top');
    br.appendChild(all);
    s.body.appendChild(br);
    FOUND.forEach(function (f) {
      var c = el('div', 'pb-found');
      var h = el('div', 'pb-found-h');
      var badge = noI18n(el('span', 'ag-dc-ic t-b', String(f.kind).slice(0, 2).toUpperCase()));
      h.appendChild(badge);
      h.appendChild(noI18n(el('b', '', f.title || DISC_T[f.kind] || f.kind)));
      var nm = arr(f.names).slice(0, 3).join(', ') || f.site || f.config || '';
      if (nm) h.appendChild(mono(nm, 'muted small'));
      c.appendChild(h);
      arr(f.items).forEach(function (it) {
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
        refs.found.push({it: it, r: r, mk: mk, b: b, why: why});
        c.appendChild(r);
      });
      s.body.appendChild(c);
    });
    return s.node;
  }
  function paintFound() {
    var miss = 0;
    arr(refs.found).forEach(function (x) {
      var v = covers(S, R, x.it);
      x.r.classList.remove('yes', 'no', 'never');
      clear(x.why);
      if (v === 'yes') { x.r.classList.add('yes'); x.mk.textContent = '✓'; }
      else if (v === 'no') { x.r.classList.add('no'); x.mk.textContent = '+'; miss++; }
      else { x.r.classList.add('never'); x.mk.textContent = '✕'; x.why.appendChild(el('span', '', v)); }
    });
    if (refs.foundAll) refs.foundAll.disabled = !miss;
    if (refs.nav && refs.nav.found) { refs.nav.found.n.textContent = miss ? String(miss) : '✓'; refs.nav.found.b.classList.toggle('warn', !!miss); }
    if (refs.discSaid) {
      clear(refs.discSaid);
      arr(R.discover).forEach(function (v) { v.msgs.forEach(function (m) {
        var x = el('div', 'pb-msg ' + m.level);
        x.appendChild(noI18n(el('span', 'pb-msg-mk', m.level === 'bad' ? '✕' : (m.level === 'warn' ? '!' : 'i'))));
        x.appendChild(el('span', '', m.words));
        refs.discSaid.appendChild(x);
      }); });
    }
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
  function drawFilesWin() {
    var s = section('files', 'Folders', 'folder', 'Files in the folder and below it. Readers: only SYSTEM, the Administrators and these accounts may read them (empty: the folder\'s own permissions). Allow the narrowest folder that holds only certificates.',
      'Add a folder', function () { S.files.push({dir: '', readers: []}); redraw('files', drawFiles); focusLast('files'); });
    var dl = el('datalist');
    dl.id = 'pb-users';
    WIN_USERS.forEach(function (u) { var o = el('option'); o.value = u; dl.appendChild(o); });
    s.body.appendChild(noI18n(dl));
    S.files.forEach(function (f, i) {
      var o = rowShell(S.files, 'files', i, function () { S.files.splice(i, 1); redraw('files', drawFiles); });
      var p = input(f.dir, 'C:\\certs', 'mono pb-path');
      p.oninput = function () { f.dir = p.value.trim(); refresh(); };
      o.top.appendChild(p);
      var rd = el('div', 'pb-owner pb-readers');
      rd.appendChild(el('span', 'pb-k', 'readers'));
      var r = input(arr(f.readers).join(', '), 'IIS_IUSRS, NT SERVICE\\W3SVC', 'mono');
      r.setAttribute('list', 'pb-users');
      r.oninput = function () { f.readers = r.value.split(',').map(function (x) { return x.trim(); }).filter(Boolean); refresh(); };
      rd.appendChild(r);
      o.top.appendChild(rd);
      o.top.appendChild(o.x);
      o.row.classList.add('pb-file');
      s.body.appendChild(o.row);
    });
    if (!S.files.length) s.body.appendChild(el('p', 'pb-empty', 'No folder: acme can write no file here.'));
    return s.node;
  }
  function drawFiles() {
    if (W()) return drawFilesWin();
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
    var s = W() ? section('units', 'Services', 'refresh', 'A Windows service: Restart-Service (restart), only when it runs (try-restart), Start-Service (start) - only the verbs chosen; after it the agent says its state.',
      'Add a service', function () { S.units.push({name: '', verbs: ['restart']}); redraw('units', drawUnits); focusLast('units'); })
      : section('units', 'Units', 'refresh', 'systemctl VERB NAME - only the verbs chosen; after it the agent says whether the unit is active.',
      'Add a unit', function () { S.units.push({name: '', verbs: ['reload']}); redraw('units', drawUnits); focusLast('units'); });
    S.units.forEach(function (u, i) {
      var o = rowShell(S.units, 'units', i, function () { S.units.splice(i, 1); redraw('units', drawUnits); });
      var n = input(u.name, W() ? 'W3SVC' : 'nginx.service', 'mono pb-unit');
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
    if (!S.units.length) s.body.appendChild(el('p', 'pb-empty', W() ? 'No service: acme restarts nothing here.' : 'No unit: acme reloads nothing here.'));
    return s.node;
  }

  /* ---- tests -------------------------------------------------------------------------------- */
  function drawTests() {
    var s = section('tests', 'Tests and commands', 'terminal', 'A command line exactly as written - a test, a reload or a command before / after. Never through a shell: a | ; $ > is a word like any other.',
      'Add a command', function () { S.tests.push([]); redraw('tests', drawTests); focusLast('tests'); });
    S.tests.forEach(function (t, i) {
      var o = rowShell(S.tests, 'tests', i, function () { S.tests.splice(i, 1); redraw('tests', drawTests); });
      var line = input(Array.isArray(t) ? t.map(W() ? wq : quote).join(' ') : t, W() ? 'iisreset /status' : 'nginx -t', 'mono pb-cmd');
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
        try { S.tests[i] = (W() ? splitWin : split)(line.value); line.classList.remove('pb-bad-in'); } catch (e) { S.tests[i] = line.value; line.classList.add('pb-bad-in'); }
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
      var p = input(x.path, W() ? 'C:\\scripts\\after.ps1' : '/usr/local/sbin/acme-hook.sh', 'mono pb-path');
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
  /* ---- a Windows server: the machine store, IIS sites, Remote Desktop ------------------------ */
  function drawStore() {
    var s = section('store', 'Machine store', 'lock', 'The certificate imported into Cert:\\LocalMachine\\My (its key not exportable unless the deployment says so); the older ones this agent imported for a deployment removed beyond its Keep - never one it did not import, never one still bound.');
    s.body.appendChild(switcher(S.store, 'acme may import certificates into the machine store', function (on) { S.store = on; refresh(); }));
    refs.storeSaid = said();
    s.body.appendChild(refs.storeSaid);
    return s.node;
  }
  var drawIis = listSection('iis', 'IIS sites', 'globe', 'The https bindings of these sites set to the new certificate (made when missing) - * for every site of this server.',
    'Add a site', 'Default Web Site', function () { return S.iis; });
  function drawRdp() {
    var s = section('rdp', 'Remote Desktop', 'screen', 'The certificate of the Remote Desktop listener (RDP-tcp); NETWORK SERVICE may read its key.');
    s.body.appendChild(switcher(S.rdp, 'acme may give the Remote Desktop listener its certificate', function (on) { S.rdp = on; refresh(); }));
    return s.node;
  }
  /* the Windows roles (1.0.120): what the OpenSSH target's roles do - the agent runs the same PowerShell */
  function drawRoles() {
    var s = section('roles', 'Windows roles', 'wand', 'The roles a deployment may set: AD FS, SQL Server, LDAPS, WinRM, Exchange, RD Gateway… - each by the fixed PowerShell inside the agent (the same as the OpenSSH target’s), given only the deployment’s values. The Central Certificate Store names its folder (the agent writes only there); an older Windows Admin Center the .msi it may run again.',
      'Add a role', function () { S.roles = arr(S.roles); S.roles.push({role: (arr(F.roles)[0] || [''])[0], extra: ''}); redraw('roles', drawRoles); focusLast('roles'); });
    arr(S.roles).forEach(function (r, i) {
      var o = rowShell(S.roles, 'roles', i, function () { S.roles.splice(i, 1); redraw('roles', drawRoles); });
      var sel = el('select', 'pb-in');
      arr(F.roles).forEach(function (x) {
        var op = el('option', '', x[1]);
        op.value = x[0];
        if (x[0] === r.role) op.selected = true;
        sel.appendChild(op);
      });
      var info = roleInfo(r.role), ex = null;
      sel.onchange = function () { r.role = sel.value; if (!(roleInfo(r.role) || [])[2]) r.extra = ''; redraw('roles', drawRoles); };
      o.top.appendChild(sel);
      if (info && info[2]) {
        ex = input(r.extra, info[2] === 'msi' ? 'msi: C:\\Install\\WindowsAdminCenter.msi (only before 2410)' : 'path: \\\\fileserver\\ccs', 'mono pb-addr');
        ex.oninput = function () { r.extra = ex.value.trim(); refresh(); };
        o.top.appendChild(ex);
      }
      o.top.appendChild(o.x);
      s.body.appendChild(o.row);
    });
    return s.node;
  }
  var drawKeyRead = listSection('key_read', 'Read on the key', 'key', 'Accounts a deployment may give read on the private key (Read on the key for, Key read of a role) - a service account, never Everyone.',
    'Add an account', 'NT SERVICE\\MyService', function () { S.key_read = arr(S.key_read); return S.key_read; });
  /* a Microsoft CA asked through this server (1.0.125, docs/ms-adcs-agent.md): each CA with
     the templates the agent may ask it for, loaded from the agent (GET /api/agents/adcs) */
  function adcsHas(ca, t) {
    var r = arr(S.adcs).filter(function (x) { return String(x.ca).toLowerCase() === String(ca).toLowerCase(); })[0];
    if (!r) return false;
    if (t === '*') return r.templates[0] === '*';
    return r.templates[0] === '*' || r.templates.some(function (y) { return String(y).toLowerCase() === String(t).toLowerCase(); });
  }
  function adcsToggle(ca, t) {
    S.adcs = arr(S.adcs);
    var r = S.adcs.filter(function (x) { return String(x.ca).toLowerCase() === String(ca).toLowerCase(); })[0];
    if (!r) { r = {ca: ca, templates: []}; S.adcs.push(r); }
    if (t === '*') r.templates = r.templates[0] === '*' ? [] : ['*'];
    else if (r.templates[0] === '*') r.templates = [t];
    else {
      var i = r.templates.map(function (y) { return String(y).toLowerCase(); }).indexOf(String(t).toLowerCase());
      if (i >= 0) r.templates.splice(i, 1); else r.templates.push(t);
    }
    if (!r.templates.length) S.adcs.splice(S.adcs.indexOf(r), 1);
    redraw('adcs', drawAdcs);
  }
  function drawAdcs() {
    var s = section('adcs', 'Microsoft CA (AD CS)', 'shield', 'The CAs this server may ask for certificates, as its computer account (Kerberos), and the templates of each - for the source “Microsoft AD CS (through acme-agent)”. acme sends only the CSR; the agent asks the CA itself.',
      'Add a CA', function () { S.adcs = arr(S.adcs); S.adcs.push({ca: '', templates: []}); redraw('adcs', drawAdcs); focusLast('adcs'); });
    s.body.appendChild(switcher(S.adcs_read, 'acme may list every CA of the domain and its templates (read-only) - else only the CAs named below', function (on) { S.adcs_read = on; refresh(); }));
    var bar = el('div', 'pb-offer pb-adcs-load');
    if (TM) bar.hidden = true;
    var load = cmdButton(B.adcsLoading ? 'Loading…' : 'Load the CAs and templates from the agent', 'refresh', 'small');
    load.disabled = !!B.adcsLoading;
    load.onclick = function () {
      B.adcsLoading = true;
      redraw('adcs', drawAdcs);
      // the agent asks the domain's CAs (up to two minutes each): not the 20 s of a read
      ask('agents/adcs?target=' + encodeURIComponent(row.name || row.id), null, 250).then(function (x) {
        B.adcsLoading = false; B.adcsList = x || {}; redraw('adcs', drawAdcs);
      }).catch(function (e) { B.adcsLoading = false; B.adcsList = {said: (e && e.message) || String(e), cas: []}; redraw('adcs', drawAdcs); });
    };
    bar.appendChild(load);
    bar.appendChild(el('span', 'pb-sec-hint', 'Read through the agent: what its policy on the server lets it list (allow adcs-read, or the CAs named).'));
    s.body.appendChild(bar);
    var L = B.adcsList;
    if (L) {
      if (!arr(L.cas).length) {
        var nw = el('div', 'pb-msg warn');
        nw.appendChild(noI18n(el('span', 'pb-msg-mk', '!')));
        nw.appendChild(noI18n(el('span', '', L.said || tr('The agent lists no CA.'))));
        s.body.appendChild(nw);
        arr(L.needs).forEach(function (n) { if (n.allow) s.body.appendChild(mono(n.allow, 'pb-adcs-allow')); });
      }
      arr(L.cas).forEach(function (c) {
        var box = el('div', 'pb-adcs-ca');
        var head = el('div', 'pb-adcs-h');
        head.appendChild(mono(c.config));
        if (c.name) head.appendChild(noI18n(el('span', 'muted small', c.name)));
        box.appendChild(head);
        var chips = el('div', 'pb-adcs-chips');
        var any = el('button', 'pb-chip-add' + (adcsHas(c.config, '*') ? ' on' : ''));
        any.type = 'button';
        any.appendChild(noI18n(el('span', 'pb-chip-p', adcsHas(c.config, '*') ? '✓' : '+')));
        any.appendChild(el('b', '', 'every template (*)'));
        any.onclick = function () { adcsToggle(c.config, '*'); };
        chips.appendChild(any);
        arr(c.templates).forEach(function (t) {
          var on = adcsHas(c.config, t.name);
          var b = el('button', 'pb-chip-add' + (on ? ' on' : ''));
          b.type = 'button';
          b.title = t.display || t.name;
          b.appendChild(noI18n(el('span', 'pb-chip-p', on ? '✓' : '+')));
          b.appendChild(mono(t.name));
          if (t.display && t.display !== t.name) b.appendChild(noI18n(el('span', 'muted small', t.display)));
          b.onclick = function () { adcsToggle(c.config, t.name); };
          chips.appendChild(b);
        });
        box.appendChild(chips);
        if (c.problem) {
          var pw = el('div', 'pb-msg warn');
          pw.appendChild(noI18n(el('span', 'pb-msg-mk', '!')));
          pw.appendChild(noI18n(el('span', '', c.problem)));
          box.appendChild(pw);
        }
        s.body.appendChild(box);
      });
    }
    arr(S.adcs).forEach(function (r, i) {
      var o = rowShell(S.adcs, 'adcs', i, function () { S.adcs.splice(i, 1); redraw('adcs', drawAdcs); });
      var ca = input(r.ca, 'ca01.example.local\\Example Issuing CA', 'mono pb-addr');
      ca.oninput = function () { r.ca = ca.value.trim(); refresh(); };
      var tp = input(r.templates.join(','), 'WebServer,WebServer2 or *', 'mono pb-addr');
      tp.oninput = function () { r.templates = tp.value.split(',').map(function (y) { return y.trim(); }).filter(Boolean); refresh(); };
      o.top.appendChild(ca);
      o.top.appendChild(tp);
      o.top.appendChild(o.x);
      s.body.appendChild(o.row);
    });
    if (!arr(S.adcs).length) s.body.appendChild(el('p', 'pb-empty', 'No CA - the agent asks none.'));
    return s.node;
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
  /* ---- 1.0.140 (A1): what a deployment may deploy - checked by the agent itself ------------- */
  var GD = d.guard || {cas: [], names: [], keys: null};
  function grouped4(fp) { return String(fp || '').toUpperCase().replace(/(.{4})(?=.)/g, '$1 '); }
  function gcard(ic, title, hint, on, words, change) {
    var c = el('div', 'pb-gcard' + (on ? ' on' : ''));
    var h = el('div', 'pb-gcard-h');
    var i = noI18n(el('span', 'pb-gcard-ic'));
    i.appendChild(icon(ic, 16));
    h.appendChild(i);
    var w = el('div', 'pb-gcard-w');
    w.appendChild(el('b', '', title));
    w.appendChild(el('span', 'pb-sec-hint', hint));
    h.appendChild(w);
    c.appendChild(h);
    var sw = switcher(on, words, change);
    sw.classList.add('pb-gcard-sw');
    c.appendChild(sw);
    var body = el('div', 'pb-gcard-b');
    c.appendChild(body);
    return {node: c, body: body};
  }
  function suggestedIssuers() {
    var here = arr(GD.cas).filter(function (c) { return c.here; });
    var roots = here.filter(function (c) { return c.root; });
    return (roots.length ? roots : here).map(function (c) { return c.fp; });
  }
  function drawGuard() {
    var s = section('guard', 'What it deploys', 'cert', W() ? 'The agent looks at the certificate itself before it imports or writes anything: who issued it, every name in it, whose key it is. Nothing of it is checked until you choose it here - then a running acme in the wrong hands cannot slip in a certificate of its own.'
      : 'The agent looks at the certificate itself before it writes anything: who issued it, every name in it, whose key it is. Nothing of it is checked until you choose it here - then a running acme in the wrong hands cannot slip in a certificate of its own.');
    var box = el('div', 'pb-guard');
    s.body.appendChild(box);
    refs.rows.issuers = [];
    refs.rows.names = [];
    /* allowed issuers */
    var isOn = arr(S.issuers).length > 0;
    var ci = gcard('shield', 'Allowed issuers', 'Every certificate written must chain to one of these CAs - the agent checks the signatures with openssl itself; the chain acme sends is never trusted.',
      isOn, 'Only certificates of these CAs', function (on) {
        S.issuers = on ? suggestedIssuers() : [];
        if (on && !S.issuers.length && arr(GD.cas).length) S.issuers = [GD.cas[0].fp];
        redraw('guard', drawGuard);
      });
    box.appendChild(ci.node);
    if (isOn) {
      var known = {};
      var list = el('div', 'pb-cas');
      list.setAttribute('role', 'group');
      list.setAttribute('aria-label', tr('Allowed issuers'));
      arr(GD.cas).forEach(function (c) {
        known[c.fp] = true;
        var on = S.issuers.map(fpOf).indexOf(c.fp) >= 0;
        var b = el('button', 'pb-ca' + (on ? ' on' : ''));
        b.type = 'button';
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        var mk = noI18n(el('span', 'pb-ca-mk', on ? '✓' : ''));
        b.appendChild(mk);
        var w = el('span', 'pb-ca-w');
        var t = el('span', 'pb-ca-t');
        t.appendChild(noI18n(el('b', '', c.title)));
        var tags = el('span', 'pb-ca-tags');
        tags.appendChild(el('span', 'pb-ca-tag ' + (c.root ? 'root' : 'int'), c.root ? 'root CA' : 'intermediate CA'));
        if (c.kind === 'authority') tags.appendChild(el('span', 'pb-ca-tag own', 'acme’s authority'));
        if (c.here) tags.appendChild(el('span', 'pb-ca-tag here', 'used here'));
        t.appendChild(tags);
        w.appendChild(t);
        var sub = el('span', 'pb-ca-s');
        sub.appendChild(mono(grouped4(c.fp.slice(0, 24)) + '\u00a0…'));
        var bits = [];
        if (arr(c.sources).length) bits.push(arr(c.sources).join(', '));
        if (c.certs) bits.push(c.certs === 1 ? '1 certificate' : c.certs + ' certificates');
        if (bits.length) sub.appendChild(el('span', 'pb-ca-src', bits.join(' · ')));
        w.appendChild(sub);
        b.appendChild(w);
        b.title = c.subject || c.title;
        b.onclick = function () {
          var cur = S.issuers.map(fpOf), at = cur.indexOf(c.fp);
          if (at >= 0) S.issuers.splice(at, 1); else S.issuers.push(c.fp);
          if (!S.issuers.length) S.issuers.push(c.fp);      /* switched off by the switch only */
          redraw('guard', drawGuard);
        };
        list.appendChild(b);
      });
      if (!arr(GD.cas).length) ci.body.appendChild(el('p', 'pb-empty', 'acme knows no CA yet (no certificate issued, no authority of its own) - give the SHA-256 of a CA’s certificate below.'));
      else ci.body.appendChild(list);
      /* one acme does not know: by its SHA-256 */
      S.issuers.forEach(function (x, i) {
        if (known[fpOf(x)]) return;
        var o = rowShell(S.issuers, 'issuers', i, function () { S.issuers.splice(i, 1); redraw('guard', drawGuard); });
        o.top.appendChild(el('span', 'pb-k', 'SHA-256'));
        var v = input(x, '64 hex digits of the CA’s certificate', 'mono pb-hash');
        v.setAttribute('aria-label', tr('SHA-256 of a CA’s certificate'));
        v.oninput = function () { S.issuers[i] = v.value.trim(); refresh(); };
        o.top.appendChild(v);
        o.top.appendChild(o.x);
        ci.body.appendChild(o.row);
      });
      var more = cmdButton('A CA acme does not know…', 'add', 'small');
      more.onclick = function () { S.issuers.push(''); redraw('guard', drawGuard); focusLast('issuers'); };
      var br = el('div', 'btnrow');
      br.appendChild(more);
      ci.body.appendChild(br);
    }
    /* allowed names */
    var nOn = arr(S.names).length > 0;
    var cn = gcard('globe', 'Allowed names', 'Every name in the certificate (its alternative names, a common name that is a name) must be one of these. *.example.com takes one label more: www.example.com, not example.com, not a.b.example.com.',
      nOn, 'Only these names', function (on) {
        S.names = on ? arr(GD.names).slice() : [];
        if (on && !S.names.length) S.names = [''];
        redraw('guard', drawGuard);
      });
    box.appendChild(cn.node);
    if (nOn) {
      var chips = el('div', 'pb-gnames');
      S.names.forEach(function (x, i) {
        var ch = el('span', 'pb-gname');
        if (x === '') {
          var fi = input('', 'www.example.com, *.example.com …', 'mono pb-gname-in');
          fi.setAttribute('aria-label', tr('A name'));
          fi.onkeydown = function (e) {
            if (e.key === 'Enter' || e.key === ',' || e.key === ' ') {
              e.preventDefault();
              var words = fi.value.split(/[\s,]+/).filter(Boolean);
              if (!words.length) return;
              S.names.splice.apply(S.names, [i, 1].concat(words));
              S.names.push('');
              redraw('guard', drawGuard);
              focusName();
            }
          };
          fi.onblur = function () {
            var words = fi.value.split(/[\s,]+/).filter(Boolean);
            if (!words.length) return;
            S.names.splice.apply(S.names, [i, 1].concat(words));
            redraw('guard', drawGuard);
          };
          chips.appendChild(fi);
          return;
        }
        ch.appendChild(mono(x));
        var bad = (function () { try { namePattern(x); return ''; } catch (e) { return e.words || String(e); } }());
        if (bad) { ch.classList.add('bad'); ch.title = bad; }
        var rm = el('button', 'pb-gname-x');
        rm.type = 'button';
        rm.setAttribute('aria-label', tr('Take it away') + ': ' + x);
        rm.textContent = '×';
        rm.onclick = function () { S.names.splice(i, 1); if (!S.names.length) S.names.push(''); redraw('guard', drawGuard); };
        ch.appendChild(rm);
        chips.appendChild(ch);
      });
      if (S.names.indexOf('') < 0) {
        var addn = el('button', 'pb-gname add');
        addn.type = 'button';
        addn.appendChild(noI18n(el('span', 'pb-chip-p', '+')));
        addn.appendChild(el('span', '', 'a name'));
        addn.onclick = function () { S.names.push(''); redraw('guard', drawGuard); focusName(); };
        chips.appendChild(addn);
      }
      cn.body.appendChild(chips);
      var missing = arr(GD.names).filter(function (n) { return S.names.indexOf(n) < 0 && !S.names.some(function (p) { return p.indexOf('*.') === 0 && n.split('.').slice(1).join('.') === p.slice(2) && n.indexOf('*.') !== 0; }); });
      if (missing.length) {
        var off = el('div', 'pb-offer');
        off.appendChild(el('span', 'pb-k', 'Deployed here, not allowed'));
        missing.slice(0, 12).forEach(function (n) {
          var b = el('button', 'pb-chip-add');
          b.type = 'button';
          b.appendChild(noI18n(el('span', 'pb-chip-p', '+')));
          b.appendChild(mono(n));
          b.onclick = function () { S.names = S.names.filter(Boolean); S.names.push(n); redraw('guard', drawGuard); };
          off.appendChild(b);
        });
        cn.body.appendChild(off);
      }
      refs.guardSaid = said();
      cn.body.appendChild(refs.guardSaid);
    } else refs.guardSaid = null;
    /* the key */
    var kOn = !!S.key_local;
    var ck = gcard('key', 'Key only from this server', W() ? 'The key must be one the agent made on this server (Key made by the device) - a certificate with acme’s key, or a PKCS#12 holding another key, is refused.'
      : 'The key must be one the agent made on this server (Key made by the device) - a certificate with acme’s key, or a file holding another key, is refused.',
      kOn, 'Only a key made on the server (require key local)', function (on) { S.key_local = on; redraw('guard', drawGuard); });
    box.appendChild(ck.node);
    var K = GD.keys;
    if (K && (K.agent || K.acme)) {
      var kst = el('div', 'pb-gkeys');
      var a1 = el('span', 'pb-ns ok');
      a1.textContent = K.agent === 1 ? '1 certificate: the key made here' : K.agent + ' certificates: the key made here';
      kst.appendChild(a1);
      if (K.acme) {
        var a2 = el('span', 'pb-ns ' + (kOn ? 'never' : 'no'));
        a2.textContent = K.acme === 1 ? '1 certificate: acme’s key' : K.acme + ' certificates: acme’s key';
        kst.appendChild(a2);
      }
      ck.body.appendChild(kst);
      if (kOn && K.acme) {
        var wn = el('div', 'note warn small');
        wn.appendChild(el('span', '', K.acme === 1 ? 'The agent would refuse the certificate deployed here with acme’s key - let its key be made on the server first.'
          : 'The agent would refuse the ' + K.acme + ' certificates deployed here with acme’s key - let their key be made on the server first.'));
        ck.body.appendChild(wn);
        if (root.ACME_AGENTKEYS && root.ACME_AGENTKEYS.switchDialog && K.switchable) {
          var sb = cmdButton('Switch to a key made on the server…', 'key', 'small');
          sb.onclick = function () { root.ACME_AGENTKEYS.switchDialog({target: row.name, ids: arr(K.switch_ids)}); };
          var sbr = el('div', 'btnrow');
          sbr.appendChild(sb);
          ck.body.appendChild(sbr);
        }
      }
    }
    return s.node;
  }
  function focusName() {
    setTimeout(function () { var x = sec.guard && sec.guard.querySelector('.pb-gname-in'); if (x) x.focus(); }, 0);
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
    h.appendChild(el('b', '', W() ? 'On the server, as an administrator' : 'On the server, as root'));
    card.appendChild(h);
    var tabs = el('div', 'pb-tabs');
    tabs.setAttribute('role', 'tablist');
    refs.tabs = {};
    TABS.forEach(function (t) {
      if (TM && t[0] === 'diff') return;
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
    /* 1.0.147: the commands with sudo or without (a root shell already) - kept for next time */
    var su = null;
    if (!W()) {
      su = el('button', 'pb-sudo' + (B.sudo ? ' on' : ''));
      su.type = 'button';
      su.setAttribute('aria-pressed', B.sudo ? 'true' : 'false');
      su.appendChild(noI18n(el('span', 'pb-sudo-mk', B.sudo ? '✓' : '')));
      su.appendChild(el('span', '', 'with sudo'));
      explain(su, 'The commands begin with sudo. Off: as they are typed in a root shell (sudo -i, su -).');
      su.onclick = function () {
        B.sudo = !B.sudo;
        try { localStorage.setItem('acme.pb.sudo', B.sudo ? '1' : '0'); } catch (e) { /* not kept */ }
        su.classList.toggle('on', B.sudo);
        su.setAttribute('aria-pressed', B.sudo ? 'true' : 'false');
        su.firstChild.textContent = B.sudo ? '✓' : '';
        paintOut();
      };
      refs.sudo = su;
    }
    card.appendChild(tabs);
    refs.outSay = el('p', 'pb-out-say small');
    card.appendChild(refs.outSay);
    /* a terminal window: its title says what it is, the lines below it */
    var term = el('div', 'pb-term');
    var tb = el('div', 'pb-term-bar');
    tb.appendChild(noI18n(el('span', 'pb-term-dots', '')));
    refs.termT = noI18n(el('span', 'pb-term-t', ''));
    tb.appendChild(refs.termT);
    refs.termN = el('span', 'pb-term-n', '');
    tb.appendChild(refs.termN);
    term.appendChild(tb);
    refs.pre = noI18n(el('pre', 'pb-pre mono k-code'));
    term.appendChild(refs.pre);
    card.appendChild(term);
    var bar = el('div', 'pb-out-bar');
    var cp = cmdButton('Copy', 'copy', 'primary small');
    cp.onclick = function () { copyText(outText(), cp, 'on the clipboard'); taken(); };
    refs.copy = cp;
    var dl = cmdButton('Download policy file', 'download', 'small');
    dl.onclick = function () { saveFile('policy', fileText(R)); taken(); };
    bar.appendChild(cp);
    bar.appendChild(dl);
    if (su) bar.appendChild(su);
    card.appendChild(bar);
    o.appendChild(card);
    o.appendChild(saveCard());
  }
  function noSudo(t) { return W() || B.sudo ? t : t.replace(/^sudo /gm, ''); }
  function outText() {
    if (B.tab === 'allow') return noSudo(allowLines(R).join('\n'));
    if (B.tab === 'once') return noSudo(oneShot(R));
    if (B.tab === 'diff') return diff(serverLines || [], R.lines).filter(function (x) { return x.op !== ' '; }).map(function (x) { return x.op + ' ' + x.line; }).join('\n');
    return fileText(R);
  }
  var SAY = {
    file: '/etc/acme-agent/policy, root:root 0644 - in place of the one there: sudo acme-agent policy apply FILE (checked first; the one before kept).',
    allow: 'Each line adds to what the policy allows already - nothing is taken away. To make it exactly this, paste the one block.',
    once: 'Paste it whole into a root shell on the server: the agent checks it, writes it in place of the one there and says what changed. Ask it now on the card then shows it.',
    diff: 'Against its policy as the agent last said it: + is allowed by the design only, - only on the server now.'
  };
  if (W()) {
    SAY.file = 'C:\\ProgramData\\acme-agent\\etc\\policy - in place of the one there: acme-agent policy apply FILE in an elevated prompt (checked first; the one before kept).';
    SAY.once = 'Paste it whole into an elevated PowerShell on the server (Run as administrator): the agent checks it, writes it in place of the one there and says what changed. Ask it now on the card then shows it.';
  }
  function termTitle() {
    if (B.tab === 'file') return W() ? 'C:\\ProgramData\\acme-agent\\etc\\policy' : '/etc/acme-agent/policy';
    if (B.tab === 'diff') return W() ? 'policy - the server → here' : 'policy · the server → here';
    return W() ? 'PowerShell (Administrator)' : (B.sudo ? 'bash · sudo' : 'bash · root');
  }
  function paintOut() {
    if (refs.termT) {
      refs.termT.textContent = termTitle();
      var nl = B.tab === 'diff' ? diff(serverLines || [], R.lines).filter(function (x) { return x.op !== ' '; }).length
        : (B.tab === 'allow' ? allowLines(R).length : R.lines.length);
      refs.termN.textContent = (B.tab === 'diff' ? 'changes: ' : (B.tab === 'allow' ? 'commands: ' : 'entries: ')) + nl;
      refs.pre.parentNode.className = 'pb-term t-' + B.tab;
    }
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
      codeLines(refs.pre, text.slice(head.length) || '', false);
      if (!R.lines.length) { var n = el('span', 'pb-c', ''); n.textContent = '# ' + tr('nothing is allowed: acme can do nothing here'); refs.pre.appendChild(n); }
      return;
    }
    codeLines(refs.pre, text, B.tab === 'allow');
  }
  /* 1.0.148: the output as lines - numbered, coloured as the shell reads them, wrapped under
     themselves (nothing cut off, no scrollbar across); "As allow lines" copies each one. The
     pre's text stays the text exactly (the numbers are drawn by the stylesheet). */
  function codeLines(pre, text, each) {
    var lines = String(text || '').split('\n');
    var nl = lines.length > 1 && lines[lines.length - 1] === '';
    if (nl) lines.pop();
    lines.forEach(function (l, i) { pre.appendChild(codeLine(l, each, nl || i < lines.length - 1)); });
  }
  function codeLine(l, each, nl) {
    var row = el('span', 'pb-ln');
    var t = el('span', 'pb-ln-t');
    if (/^\s*#/.test(l)) { t.className += ' k-com'; t.textContent = l; }
    else if (!l.trim()) t.textContent = '';
    else paintWords(t, l);
    row.appendChild(t);
    if (nl) row.appendChild(document.createTextNode('\n'));
    if (each && l.trim() && l.charAt(0) !== '#') {
      var b = el('button', 'pb-ln-cp');
      b.type = 'button';
      b.title = tr('Copy this command');
      b.setAttribute('aria-label', tr('Copy this command'));
      b.appendChild(icon('copy', 13));
      b.onclick = function (e) { e.stopPropagation(); copyText(l + '\n', null, 'on the clipboard'); b.classList.add('done'); setTimeout(function () { b.classList.remove('done'); }, 1200); taken(); };
      row.appendChild(b);
    }
    return row;
  }

  function tplCard() {
    var c = el('div', 'pb-save pb-save-tpl');
    var h = el('div', 'pb-out-h');
    h.appendChild(icon('people', 16));
    h.appendChild(el('b', '', OT.ref ? 'The fleet template' : 'A new fleet template'));
    c.appendChild(h);
    c.appendChild(el('p', 'small pb-save-say', OT.ref ? 'Each save is a new version of it; the agents that follow it then show whether they drift from it.' : 'Kept in acme: agents and groups follow it; acme never sends it to a server.'));
    var t = input(OT.title || '', 'A title - nginx on the web servers', 'pb-title');
    t.maxLength = 120;
    var n = el('textarea', 'pb-in pb-note');
    n.rows = 2;
    n.placeholder = 'A note - what it is for, why it allows what it allows';
    n.value = OT.note || '';
    refs.title = t;
    refs.note = n;
    c.appendChild(t);
    c.appendChild(n);
    var b = cmdButton(OT.ref ? 'Save a new version' : 'Save the template', 'save', 'primary small');
    b.onclick = function () {
      if (R.counts.bad) { toast(tr('the design has lines the agent would not read - fix the red ones first'), 'bad'); return; }
      var title = t.value.trim();
      if (!title) { toast(tr('give the template a title'), 'bad'); t.focus(); return; }
      if (!R.lines.length) { toast(tr('the template allows nothing yet - click together what the agent may do'), 'bad'); return; }
      busy(b, true);
      ask('fleet/template_save', {ref: OT.ref || '', title: title, note: n.value.trim(), platform: W() ? 'windows' : 'linux',
        text: fileText(R), design_state: S}).then(function (x) {
        taken();
        toast(tr('the fleet template is saved') + ': ' + ((x && x.template && x.template.title) || title), 'good');
        closeModal(true);
        if (opts.fleetDone) opts.fleetDone(x && x.template);
      }).catch(function (e) { busy(b, false); oops(e); });
    };
    var br = el('div', 'btnrow');
    br.appendChild(b);
    c.appendChild(br);
    return c;
  }
  function saveCard() {
    if (TM) return tplCard();
    var c = el('div', 'pb-save');
    var h = el('div', 'pb-out-h');
    h.appendChild(icon('save', 16));
    h.appendChild(el('b', '', 'The design, kept in acme'));
    c.appendChild(h);
    c.appendChild(el('p', 'small pb-save-say', 'Documentation only: acme never sends it to the server. The card then says whether the server’s policy matches it.'));
    refs.saveState = el('div', 'pb-save-st');
    c.appendChild(refs.saveState);
    paintSaved();
    /* the portal's team workspace (1.0.125): a member who manages the team's devices saves it */
    if (!FULL && !opts.maySave) {
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
      /* design_state: an object under `state` is refused by the API ("state is a piece of text
         here") - no design was ever saved from the page */
      ask('agents/design', {id: row.id || A.id, text: fileText(R), design_state: S, title: t.value.trim(), note: n.value.trim()}).then(function (x) {
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
    /* 1.0.138: the same policy kept as a fleet template (fleet.py) - other agents then follow it */
    if (FULL) {
      var fb = cmdButton('Save as a fleet template', 'people', 'small');
      fb.onclick = function () {
        if (R.counts.bad) { toast(tr('the design has lines the agent would not read - fix the red ones first'), 'bad'); return; }
        var title = t.value.trim() || (FT && FT.title) || '';
        if (!title) { toast(tr('give the template a title'), 'bad'); t.focus(); return; }
        busy(fb, true);
        ask('fleet/template_save', {ref: FT && !FT.builtin && FT.title === title ? FT.ref : '', title: title, note: n.value.trim(),
          platform: F.platform || 'linux', text: fileText(R), design_state: S}).then(function (x) {
          taken();
          B.fleet = null;
          if (sec.tpl && sec.tpl.parentNode) redraw('tpl', drawTemplates);
          toast(tr('the fleet template is saved') + ': ' + ((x && x.template && x.template.title) || title), 'good');
          if (opts.fleetDone) opts.fleetDone(x && x.template);
        }).catch(oops).then(function () { busy(fb, false); });
      };
      br.appendChild(fb);
    }
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
    /* the time a text of its own: "0 s ago · " as one was left in English in Czech */
    m.appendChild(el('span', '', ago(D.at)));
    m.appendChild(noI18n(document.createTextNode(' · ')));
    m.appendChild(noI18n(document.createTextNode(String(D.by || ''))));
    w.appendChild(m);
    var same = D.text === fileText(R);
    w.appendChild(el('span', 'tag ' + (same ? 'ok' : 'warn'), same ? 'the same as here' : 'changed here'));
  }

  /* ---- everything checked again, in place -------------------------------------------------- */
  function refresh() {
    R = check(S);
    ['files', 'units', 'tests', 'scripts', 'hashes', 'from', 'probe', 'connect', 'iis', 'roles', 'key_read', 'adcs', 'issuers'].forEach(function (k) {
      arr(refs.rows[k]).forEach(function (r, i) {
        if (!r || !R[k] || !R[k][i]) return;
        var hint = '';
        if (k === 'files' && W()) hint = arr(S.files[i].readers).length ? 'read by SYSTEM, the Administrators and ' + arr(S.files[i].readers).join(', ') : 'read as the folder\'s own permissions say';
        else if (k === 'files') hint = 'files here at most ' + oct4(S.files[i].mode & 438) + ', owned by ' + S.files[i].owner + ':' + S.files[i].group;
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
    if (refs.storeSaid) {
      clear(refs.storeSaid);
      if (R.storeMsg) { var sm = el('div', 'pb-msg warn'); sm.appendChild(noI18n(el('span', 'pb-msg-mk', '!'))); sm.appendChild(el('span', '', R.storeMsg.words)); refs.storeSaid.appendChild(sm); }
    }
    if (refs.guardSaid) {
      clear(refs.guardSaid);
      var gm = [];
      arr(R.names).forEach(function (v) { v.msgs.forEach(function (m) { gm.push(m); }); });
      if (R.guardMsg) gm.push(R.guardMsg);
      gm.forEach(function (m) { var x = el('div', 'pb-msg ' + m.level); x.appendChild(noI18n(el('span', 'pb-msg-mk', m.level === 'bad' ? '✕' : '!'))); x.appendChild(el('span', '', m.words)); refs.guardSaid.appendChild(x); });
    }
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
      from: S.from.length, probe: S.probe.length + (S.probe_local ? 1 : 0), connect: S.connect_on ? S.connect.length : 0, update: S.self_update ? '✓' : '', limits: '',
      store: S.store ? '✓' : '', iis: arr(S.iis).length, rdp: S.rdp ? '✓' : '', roles: arr(S.roles).length, key_read: arr(S.key_read).length,
      adcs: arr(S.adcs).length + (S.adcs_read ? 1 : 0),
      discover: discRows(S.discover)[0] === '*' ? '✓' : discRows(S.discover).length, found: '',
      guard: (arr(S.issuers).length ? 1 : 0) + (arr(S.names).filter(Boolean).length ? 1 : 0) + (S.key_local ? 1 : 0)};
    var lv = {files: R.files, units: R.units, tests: R.tests, scripts: R.scripts, hashes: R.hashes, from: R.from, probe: R.probe, connect: R.connect,
      limits: [R.limits.files, R.limits.size], iis: R.iis || [], store: R.storeMsg ? [{level: 'warn'}] : [], roles: R.roles || [], key_read: R.key_read || [],
      adcs: R.adcs || [], discover: R.discover || [], guard: arr(R.issuers).concat(arr(R.names), R.guardMsg ? [{level: 'warn'}] : [])};
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
    paintFound();
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
    modal(TM ? (OT.ref ? 'Edit the fleet template' : 'New fleet template') + (W() ? ' · Windows' : ' · Linux') : 'Design the policy of ' + row.name, function (body) {
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
    B.kept = B.startText = fileText(R);
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
