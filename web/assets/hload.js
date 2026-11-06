/* The performance meter in the header (1.0.48, from ai 1.0.72-1.0.76; docs/performance-meter.md):
   how busy this node is - CPU, memory, the disks, the network - every 3 s while the page is shown,
   for a full administrator who switched it on in Your account (off unless chosen). The details
   (each core, the disks, the filesystems, the cards, the processes) are asked only while a panel
   is open. Uses core.js's $, el, clear, noI18n, bytes, api, toast, oops. */
function prefs() { return (typeof ME === 'object' && ME && ME.prefs) || {}; }
function savePrefs(change) {
  return api('prefs', change).then(function (d) {
    if (typeof ME === 'object' && ME) ME.prefs = Object.assign({}, ME.prefs || {}, change);
    return d;
  });
}
function hlLive() { return typeof LIVE === 'object' && LIVE ? LIVE.on !== false : LIVE !== false; }
/* How busy the server is, in the header of the page (from ai 1.0.72-1.0.76).
   Plain JavaScript, no library. Needs the few helpers of helpers.js ($, el, clear,
   noI18n, bytes, api, prefs, savePrefs, LIVE, toast, oops) - or your own of the same names.

   Start it:     hloadLoop();          (polls every 3 s while the page is shown)
   The header:   <div class="hload" id="hload" hidden aria-live="off"></div>
   My account:   hloadPickers(host)    (the two rows of cards to choose the looks)
*/
/* How busy the server is, beside running (1.0.72): every 3 s while the page
   is shown and live, nothing while it is hidden; the daemon reads /proc only
   when asked. CPU, memory, the disks, the network. */
var HLOAD = {timer: null, busy: false};
/* a number with the page's decimal mark (1.0.51: "2.3 kB/s" beside "1,2 GB" in Czech) */
function hlDec(x, d) {
  var t = Number(x).toFixed(d);
  return (window.ACME_LANG && window.ACME_LANG !== 'en') ? t.replace('.', ',') : t;
}
function hlLoads(l) { return (l || []).map(function (x) { return hlDec(x, 2); }).join(' / '); }
function hloadRate(n) {
  if (n === null || n === undefined) return '–';
  if (n < 1024) return Math.round(n) + ' B/s';
  if (n < 1024 * 1024) return hlDec(n / 1024, n < 10240 ? 1 : 0) + ' kB/s';
  return hlDec(n / 1048576, n < 10485760 ? 1 : 0) + ' MB/s';
}
/* Four looks to choose from (1.0.72): pills with a bar, one plain line,
   small graphs of the last two minutes, rings. */
var HLOAD_KEEP = 40;
/* The graphs on a line of time (1.0.50): each reading where its time puts it, the whole moving on
   smoothly to the left between the readings (one SVG animation each, nothing redrawn by a
   timer), shown a few seconds behind - this node's readings come every 3 s, another node's
   every 5 s through the database - so a new one is always added beyond the right edge, never
   seen jumping in. Their scale follows the highest reading shown, slowly back down. */
/* one delay for every node (1.0.53): the graphs of both nodes move together, side by side */
var HL_WIN = 120, HL_OWN_D = 10, HL_PEER_D = 10, HL_OFF = [];
function hlNow() {
  var t = Date.now() / 1000 + (HLOAD.off || 0);
  if (!hlLive()) { if (!HLOAD.frozen) HLOAD.frozen = t; return HLOAD.frozen; }
  HLOAD.frozen = 0;
  return t;
}
function hlCalm() { try { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; } catch (e) { return false; } }
function hlGeom(hist, k, w, h, top, edge) {
  var vals = (hist || {})[k] || [], ts = hist && hist.t;
  var y = function (v) { return (h - 1 - (h - edge) * Math.min(1, (v || 0) / top)).toFixed(1); };
  if (!hist || !hist.live || !Array.isArray(ts) || ts.length !== vals.length) {
    return {pts: vals.map(function (v, i) { return [(i * w / (HLOAD_KEEP - 1)).toFixed(1), y(v)]; }), anim: ''};
  }
  var R = hlNow() - (hist.D || HL_OWN_D), L = R - HL_WIN, pts = [];
  for (var i = 0; i < vals.length; i++) {
    if (ts[i] < L && i + 1 < vals.length && ts[i + 1] <= L) continue;     /* one kept left of the edge */
    pts.push([(w * (ts[i] - L) / HL_WIN).toFixed(2), y(vals[i])]);
  }
  var anim = (hlCalm() || !hlLive()) ? '' : '<animateTransform attributeName="transform" type="translate" from="0 0" to="-' + w + ' 0" dur="' + HL_WIN + 's" fill="freeze"/>';
  return {pts: pts, anim: anim};
}
function hlTop(hist, k) {
  if (k === 'cpu' || k === 'mem') return 100;
  var vals = (hist || {})[k] || [], ts = hist && hist.t, m = 1024;
  var timed = !!(hist && hist.live && Array.isArray(ts) && ts.length === vals.length);
  var L = timed ? hlNow() - (hist.D || HL_OWN_D) - HL_WIN : -Infinity;
  for (var i = 0; i < vals.length; i++) if (!timed || ts[i] >= L) m = Math.max(m, vals[i] || 0);
  if (!timed) return m;
  var tp = hist.top || (hist.top = {}), was = tp[k], t = Date.now() / 1000;
  if (was && t - was.at < 1) return Math.max(was.v, m);
  var v = was ? Math.max(m, was.v * Math.pow(0.5, (t - was.at) / 15)) : m;
  tp[k] = {v: v, at: t};
  return v;
}
function hlJoin(pts) { return pts.map(function (p) { return p[0] + ',' + p[1]; }).join(' '); }
function hloadSpark(hist, k, max, cls) {
  var w = 56, h = 18;
  var svg = '<svg class="hl-spark ' + (cls || '') + '" viewBox="0 0 ' + w + ' ' + h + '" width="' + w + '" height="' + h + '" preserveAspectRatio="none" aria-hidden="true">';
  var g = hlGeom(hist, k, w, h, Math.max(max || 0, 1), 2);
  if (g.pts.length > 1) {
    svg += '<g>' + g.anim + '<polyline points="' + hlJoin(g.pts) + '" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></g>';
  }
  return svg + '</svg>';
}
/* paused (the live updates) or the page away: the graphs stop where they are */
function hlFreeze() {
  document.querySelectorAll('.hload svg, #hload-panel svg').forEach(function (v) { if (v.pauseAnimations) v.pauseAnimations(); });
}
function hlVal(v) {
  var s = noI18n(el('span', 'hl-v'));
  if (v.indexOf('<span') === 0) s.innerHTML = v; else s.textContent = v;
  return s;
}
/* How wide a bar is (1.0.48, as plexmon 2.7.2): exactly what it says - nothing at 0 %, a hairline
   for anything that rounds to 1 % or more. A bit of bar stood beside every "0 %". */
function hlWidth(pct) {
  pct = Number(pct) || 0;
  if (pct < 0.5) return 0;
  return Math.max(1, Math.min(100, pct));
}
function hloadRing(pct) {
  var r = 7, c = 2 * Math.PI * r, p = hlWidth(pct);
  return '<svg class="hl-ring" viewBox="0 0 18 18" width="18" height="18" aria-hidden="true"><circle cx="9" cy="9" r="' + r + '" class="hl-ring-bg"/>'
    + '<circle cx="9" cy="9" r="' + r + '" class="hl-ring-fg" stroke-dasharray="' + (c * p / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 9 9)"/></svg>';
}
function hloadDraw(d, into, asLook, opt) {
  /* into/asLook: a preview of a look drawn elsewhere (My account), from the
     sample numbers; it touches nothing of the real header (1.0.75).
     opt {live, hist, node}: another node of the cluster, drawn live from what it wrote (1.0.48). */
  opt = opt || {};
  var preview = !!into && !opt.live;
  var host = into || $('hload');
  if (!host) return;
  var hist;
  var mp = d.mem_total ? 100 * d.mem_used / d.mem_total : null;
  if (opt.live) hist = opt.hist || {cpu: [], mem: [], disk: [], net: []};
  else if (preview) hist = hpSample().hist;
  else {
    HLOAD.last = d;
    hist = HLOAD.hist || (HLOAD.hist = {cpu: [], mem: [], disk: [], net: [], t: [], live: true, D: HL_OWN_D});
    var tl = hist.t || [];
    /* each reading once, with its time (1.0.50); what is older than the graphs show let go */
    if (d.cpu !== undefined && d.at && !(tl.length && d.at <= tl[tl.length - 1] + 0.5)) {
      hist.cpu.push(d.cpu || 0); hist.mem.push(mp || 0);
      hist.disk.push((d.disk_rd || 0) + (d.disk_wr || 0)); hist.net.push((d.net_rx || 0) + (d.net_tx || 0));
      tl.push(d.at); hist.t = tl;
      while (tl.length > 2 && tl[1] < d.at - HL_WIN - 30) ['cpu', 'mem', 'disk', 'net', 't'].forEach(function (k) { hist[k].shift(); });
    }
  }
  var look = asLook || HLOAD.look || 'off';
  host.className = 'hload look-' + look + (preview ? ' hl-preview' : '') + (opt.node ? ' hl-peer' : '')
    + (opt.stale ? ' hl-stale' : '');
  clear(host);
  /* In a cluster each node's numbers under its name (1.0.48) */
  if (!preview && (opt.node || (HLOAD.peers && HLOAD.peers.length))) {
    var nn = noI18n(el('span', 'hl-node', opt.node || d.node || ''));
    if (opt.stale) nn.title = 'not read lately - the node may be away';
    host.appendChild(nn);
  }
  var tips = {
    cpu: 'The processor, busy over the last ' + (d.over_s || 3) + ' s, all ' + d.cores + ' core(s) together' + (d.load ? ' · load ' + hlLoads(d.load) : ''),
    mem: 'Memory in use (without what the kernel keeps as cache and gives back)' + (d.swap_used ? ' · swap in use ' + bytes(d.swap_used) : ''),
    disk: 'The disks: read ↓ and written ↑, every disk together',
    net: 'The network cards: down ↓ (in) and up ↑ (out), every card together - not the loopback nor the bridges of containers'
  };
  var cpuV = d.cpu === undefined ? '…' : Math.round(d.cpu) + ' %';
  var memV = d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '–';
  // fixed places for each number, so nothing beside them moves as they change (1.0.73)
  var two = function (a, b) { return '<span class="hl-r">↓' + hloadRate(a) + '</span><span class="hl-r">↑' + hloadRate(b) + '</span>'; };
  var diskV = two(d.disk_rd, d.disk_wr);
  var netV = two(d.net_rx, d.net_tx);
  var heat = function (c, pct) { if (pct === null || pct === undefined) return; c.classList.toggle('hot', pct >= 90); c.classList.toggle('warm', pct >= 70 && pct < 90); };
  if (look === 'line') {
    var line = el('span', 'hl-line');
    [['CPU', cpuV, 'cpu', d.cpu], ['RAM', memV, 'mem', mp], ['Disk', diskV, 'disk'], ['Net', netV, 'net']].forEach(function (x, i) {
      if (i) line.appendChild(el('span', 'hl-sep', '·'));
      var part = el('span', 'hl-part hl-' + x[2]);
      part.appendChild(el('span', 'hl-k', x[0]));
      part.appendChild(hlVal(x[1]));
      heat(part, x[3]);
      if (hpStyle() === 'off') part.title = tips[x[2]];
      part.dataset.k = x[2];
      part.tabIndex = 0;
      part.setAttribute('role', 'button');
      if (!preview) hloadPanelHooks(part, x[2]);
      line.appendChild(part);
    });
    host.appendChild(line);
  } else {
    [['CPU', cpuV, 'cpu', d.cpu, 100], ['RAM', memV, 'mem', mp, 100], ['Disk', diskV, 'disk', null, null], ['Net', netV, 'net', null, null]].forEach(function (x) {
      var c = el('span', 'hl hl-' + x[2]);
      c.title = tips[x[2]];
      if (look === 'rings' && x[3] !== null && x[3] !== undefined) {
        var ring = el('span', 'hl-ringbox'); ring.innerHTML = hloadRing(x[3]); c.appendChild(ring);
      }
      c.appendChild(el('span', 'hl-k', x[0]));
      c.appendChild(hlVal(x[1]));
      if (look === 'pills' && x[3] !== null && x[3] !== undefined) {
        var bar = el('span', 'hl-bar'), fill = el('span', '');
        fill.style.width = hlWidth(x[3]) + '%';
        bar.appendChild(fill); c.appendChild(bar);
      }
      if (look === 'graphs') {
        var g = el('span', 'hl-g');
        g.innerHTML = hloadSpark(hist, x[2], x[4] || hlTop(hist, x[2]));
        c.appendChild(g);
      }
      heat(c, x[3]);
      c.dataset.k = x[2];
      c.tabIndex = 0;
      c.setAttribute('role', 'button');
      if (hpStyle() !== 'off') c.removeAttribute('title');
      c.dataset.node = opt.node || '';
      if (!preview) hloadPanelHooks(c, x[2], opt.node || '');
      host.appendChild(c);
    });
  }
  host.hidden = false;
  if (!into && HLOAD.open) hloadPanelDraw();
}
/* The other nodes of a cluster (1.0.48): a row of numbers each, beside this node's - from what
   each wrote while this page watches; their graphs from their own last two minutes. */
function hloadPeersDraw() {
  var own = $('hload');
  if (!own) return;
  var peers = HLOAD.peers || [];
  var have = {};
  peers.forEach(function (pr) {
    var id = 'hload-peer-' + String(pr.node).replace(/[^A-Za-z0-9_-]/g, '_');
    have[id] = true;
    var box = $(id);
    if (!box) {
      box = el('div', 'hload hl-peer');
      box.id = id;
      box.setAttribute('aria-live', 'off');
      var after = own, sib = own.nextSibling;
      while (sib && sib.classList && sib.classList.contains('hl-peer')) { after = sib; sib = sib.nextSibling; }
      after.parentNode.insertBefore(box, after.nextSibling);
    }
    hloadDraw(pr, box, HLOAD.look, {live: true, hist: pr.hist, node: pr.node, stale: (pr.age || 0) > 20});
  });
  document.querySelectorAll('.hload.hl-peer').forEach(function (b) { if (!have[b.id]) b.remove(); });
  hloadFit();
}
/* On the row of the name and its state while it fits there with the account's buttons
   (1.0.49), on a row of its own under them when it does not - measured, as the name of the
   site, the look and the number of nodes make the room it needs; in one go, never painted
   in between. */
function hloadFit() {
  var head = document.querySelector('header'), box = document.querySelector('header .hloads');
  var btn = $('me-btn');
  if (!head || !box || !btn) return;
  head.classList.remove('hl-below');
  var b = box.getBoundingClientRect(), r = btn.getBoundingClientRect();
  if (b.height && r.top >= b.bottom - 2) head.classList.add('hl-below');
}
window.addEventListener('resize', function () {
  clearTimeout(HLOAD.fitT);
  HLOAD.fitT = setTimeout(hloadFit, 120);
});
/* Sample numbers for the previews in My account: a server with sensors, so
   every part shows (1.0.75). */
function hpSample() {
  if (HLOAD.sample) return HLOAD.sample;
  var h = {cpu: [], mem: [], disk: [], net: []};
  for (var i = 0; i < HLOAD_KEEP; i++) {
    h.cpu.push(48 + 28 * Math.sin(i / 4)); h.mem.push(30 + i * 0.15);
    h.disk.push((1 + Math.sin(i / 4 + 1)) * 9e7); h.net.push((1 + Math.sin(i / 4 + 2)) * 7e6);
  }
  var cores = [[96, 3900, 71], [12, 1200, 48], [88, 3800, 69], [4, 800, 46], [61, 3400, 62], [9, 1100, 47], [100, 4100, 84], [22, 2000, 51]]
    .map(function (c, n) { return {n: n, busy: c[0], mhz: c[1], temp: c[2]}; });
  HLOAD.sample = {hist: h,
    last: {cpu: 49, mem_used: 9.8e9, mem_total: 33.5e9, disk_rd: 190e6, disk_wr: 48e6, net_rx: 12.6e6, net_tx: 1.5e6, cores: 8, load: [3.92, 3.1, 2.71], over_s: 3},
    detail: {cores: cores, model: 'AMD Ryzen 7 5800X 8-Core Processor', temps: {cpu: [['Tctl', 73]], cores: {}, other: []},
      disks: [{name: 'nvme0n1', size: 1e12, model: 'Samsung SSD 980 PRO', rd: 190e6, wr: 48e6, util: 38, temp: 44},
              {name: 'sda', size: 4e12, model: 'WDC WD40EFRX', rd: 2.2e6, wr: 0, util: 3, temp: 36}],
      filesystems: [{mount: '/', kind: 'ext4', total: 984e9, used: 212e9}, {mount: '/srv', kind: 'xfs', total: 3.6e12, used: 3.1e12}],
      nics: [{name: 'eno1', state: 'up', speed: 1000, rx: 12.6e6, tx: 1.5e6, rx_all: 812e9, tx_all: 96e9}],
      top_cpu: [{name: 'node', pid: 1201, cpu: 187}, {name: 'claude', pid: 1302, cpu: 96}, {name: 'postgres', pid: 812, cpu: 41}],
      top_mem: [{name: 'node', pid: 1201, rss: 2.1e9}, {name: 'claude', pid: 1302, rss: 1.4e9}],
      uptime: 1051200, mem: {total: 33.5e9, available: 21.6e9, cached: 6.1e9, buffers: 0.3e9, swap_total: 8.6e9, swap_free: 8.6e9, shared: 120e6}, procs: 312}};
  return HLOAD.sample;
}
/* A picker as the terminal colours: a card for each choice with what it
   really looks like, drawn by the same code from the sample numbers. */
function hlPicker(choices, now, draw, pick) {
  var box = el('div', 'pal-pick hl-pick' + (draw === hlPreviewPanel ? ' hl-pick-p' : ''));
  choices.forEach(function (n) {
    var b = el('button', 'pal-card hl-card' + (n[0] === now ? ' on' : ''));
    b.type = 'button';
    b.dataset.v = n[0];
    var sw = el('div', 'pal-sw hl-sw');
    draw(sw, n[0]);
    b.appendChild(sw);
    b.appendChild(el('span', 'pal-name', n[1]));
    b.onclick = function () {
      box.querySelectorAll('.pal-card').forEach(function (x) { x.classList.toggle('on', x === b); });
      pick(n[0]);
    };
    box.appendChild(b);
  });
  return box;
}
function hlPreviewLook(sw, look) {
  if (look === 'off') { sw.appendChild(el('span', 'muted small hl-none', 'nothing in the header')); return; }
  var inner = el('div', 'hl-scale');
  var host = el('div', 'hload');
  inner.appendChild(host);
  hloadDraw(hpSample().last, host, look);
  sw.appendChild(inner);
}
function hlPreviewPanel(sw, st) {
  if (st === 'off') {
    var t = el('div', 'hl-tipbox');
    t.appendChild(el('span', 'hl-tipchip', 'CPU 49 %'));
    t.appendChild(el('span', 'hl-tip small', 'The processor, busy over the last 3 s, all 8 core(s) together'));
    sw.appendChild(t);
    return;
  }
  var smp = hpSample(), keep = [HLOAD.last, HLOAD.detail, HLOAD.hist, HLOAD.open];
  HLOAD.last = smp.last; HLOAD.detail = smp.detail; HLOAD.hist = smp.hist; HLOAD.open = 'cpu';
  var p = el('div', 'hl-panel hp-' + st + ' hl-prevpanel');
  p.style.width = (st === 'wide' ? 1180 : (st === 'table' ? 420 : 470)) + 'px';
  try {
    if (st === 'table') hpTable(p, 'cpu'); else if (st === 'map') hpMap(p, 'cpu'); else if (st === 'wide') hpWide(p); else hpTiles(p, 'cpu');
  } finally { HLOAD.last = keep[0]; HLOAD.detail = keep[1]; HLOAD.hist = keep[2]; HLOAD.open = keep[3]; }
  var inner = el('div', 'hl-scale hl-scale-p' + (st === 'wide' ? ' wide' : ''));
  inner.appendChild(p);
  sw.appendChild(inner);
}
/* The panel of one chip (1.0.73): pointed at (or tapped on an iPad), what is
   behind the number - each core with its frequency and temperature, the
   disks and the filesystems, the cards, the processes taking most, and the
   last two minutes larger. Read from the daemon only while it is open. */
function hloadPanelHooks(c, k, node) {
  c.onmouseenter = function () { if (matchMedia('(hover: hover)').matches) { HLOAD.pnode = node || ''; hloadPanelOpen(k, c); } };
  c.onmouseleave = function () { if (matchMedia('(hover: hover)').matches) hloadPanelSoon(); };
  c.onclick = function (e) {
    e.stopPropagation();
    if (HLOAD.open === k && (HLOAD.pnode || '') === (node || '')) hloadPanelClose();
    else { HLOAD.pnode = node || ''; hloadPanelOpen(k, c); }
  };
  c.onkeydown = function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); c.onclick(e); } if (e.key === 'Escape') hloadPanelClose(); };
}
function hloadPanelOpen(k, chip) {
  clearTimeout(HLOAD.shut);
  if (hpStyle() === 'off') return;
  HLOAD.open = k;
  HLOAD.chip = k;
  var p = $('hload-panel');
  if (!p) {
    p = el('div', 'hl-panel');
    p.id = 'hload-panel';
    p.onmouseenter = function () { clearTimeout(HLOAD.shut); };
    p.onmouseleave = function () { if (matchMedia('(hover: hover)').matches) hloadPanelSoon(); };
    p.onclick = function (e) { e.stopPropagation(); };
    document.body.appendChild(p);
    document.addEventListener('click', function () { if (HLOAD.open) hloadPanelClose(); });
    window.addEventListener('resize', function () { if (HLOAD.open) hloadPanelPlace(); });
  }
  p.hidden = false;
  hloadPanelDraw();
  hloadPanelPlace(chip);
  if (HLOAD.pnode || !HLOAD.detail || Date.now() - (HLOAD.detailAt || 0) > 2500) hloadTick(true);
}
function hloadPanelSoon() { clearTimeout(HLOAD.shut); HLOAD.shut = setTimeout(hloadPanelClose, 350); }
function hloadPanelClose() {
  HLOAD.open = null;
  var p = $('hload-panel');
  if (p) p.hidden = true;
  document.querySelectorAll('#hload .hl-open').forEach(function (c) { c.classList.remove('hl-open'); });
}
function hloadPanelPlace(chip) {
  var p = $('hload-panel');
  chip = chip || document.querySelector('.hload [data-k="' + HLOAD.chip + '"][data-node="' + (HLOAD.pnode || '') + '"]')
    || document.querySelector('#hload [data-k="' + HLOAD.chip + '"]');
  if (!p || !chip) return;
  var r = chip.getBoundingClientRect(), st = hpStyle();
  var w = Math.min(st === 'wide' ? 1180 : (st === 'table' ? 420 : 470), window.innerWidth - 16);
  var left = r.left;
  if (st === 'wide') { var hr = (chip.closest('.hload') || $('hload')).getBoundingClientRect(); left = hr.left; r = {bottom: hr.bottom, left: hr.left}; }
  p.style.width = w + 'px';
  p.style.left = Math.max(8, Math.min(window.innerWidth - w - 8, left)) + 'px';
  p.style.top = Math.round(r.bottom + 6) + 'px';
  p.style.maxHeight = Math.max(200, window.innerHeight - r.bottom - 20) + 'px';
}
function hlBar(pct, cls) {
  var b = el('span', 'hp-bar ' + (cls || ''));
  var f = el('span', '');
  f.style.width = hlWidth(pct) + '%';
  if (pct >= 90) b.classList.add('hot'); else if (pct >= 70) b.classList.add('warm');
  b.appendChild(f);
  return b;
}
function hlTemp(t) {
  if (t === null || t === undefined) return null;
  return el('span', 'hp-temp' + (t >= 85 ? ' hot' : (t >= 70 ? ' warm' : '')), Math.round(t) + ' °C');
}
function hlUp(sec) {
  sec = Math.round(sec || 0);
  var d = Math.floor(sec / 86400), h = Math.floor(sec % 86400 / 3600), m = Math.floor(sec % 3600 / 60);
  return (d ? d + ' d ' : '') + (d || h ? h + ' h ' : '') + m + ' min';
}
/* Four ways to show the details (1.0.74), chosen in My account: tiles, a
   table (as htop, good for many cores), a map of the cores with rings, or one
   wide panel with all four at once. */
var HP_STYLES = [['tiles', 'tiles - a card for each core'], ['table', 'a table - a row for each core (as htop)'],
                 ['map', 'a map of the cores with rings'], ['wide', 'one wide panel with everything at once'],
                 ['off', 'no details - only a short tip']];
function hpStyle() { var v = prefs().hpanel; return HP_STYLES.some(function (x) { return x[0] === v; }) ? v : 'tiles'; }
function hloadPanelDraw() {
  var p = $('hload-panel'), k = HLOAD.open;
  if (!p || !k) return;
  var st = hpStyle(), node = HLOAD.pnode || '';
  clear(p);
  p.className = 'hl-panel hp-' + st;
  document.querySelectorAll('.hload [data-k]').forEach(function (c) {
    c.classList.toggle('hl-open', (c.dataset.node || '') === node && (st !== 'wide' ? c.dataset.k === k : true));
  });
  /* Another node's: drawn from what it wrote, as this node's own is (1.0.48) */
  var keep = null;
  if (node) {
    var pr = (HLOAD.peers || []).filter(function (x) { return x.node === node; })[0];
    if (!pr) { HLOAD.pnode = ''; node = ''; }
    else {
      keep = [HLOAD.last, HLOAD.detail, HLOAD.hist];
      HLOAD.last = pr; HLOAD.detail = pr.detail || null; HLOAD.hist = pr.hist || {cpu: [], mem: [], disk: [], net: []};
    }
  }
  if (node || (HLOAD.peers && HLOAD.peers.length)) p.appendChild(noI18n(el('div', 'hl-pnode', node || (HLOAD.last && HLOAD.last.node) || '')));
  try {
    if (st === 'table') hpTable(p, k);
    else if (st === 'map') hpMap(p, k);
    else if (st === 'wide') hpWide(p);
    else hpTiles(p, k);
  } finally {
    if (keep) { HLOAD.last = keep[0]; HLOAD.detail = keep[1]; HLOAD.hist = keep[2]; }
  }
}
var HP_TITLE = {cpu: 'The processor', mem: 'Memory', disk: 'The disks', net: 'The network'};
function hpMax(k) { return hlTop(HLOAD.hist, k); }
/* a filled graph of the last two minutes, as wide as its box */
function hpArea(k, h, grid) {
  var w = 400, top = Math.max(hpMax(k), 1);
  var box = el('div', 'hp-area hl-' + k);
  var svg = '<svg viewBox="0 0 ' + w + ' ' + h + '" width="100%" height="' + h + '" preserveAspectRatio="none" aria-hidden="true">';
  if (grid) [0.25, 0.5, 0.75].forEach(function (g) { svg += '<line x1="0" x2="' + w + '" y1="' + h * g + '" y2="' + h * g + '" class="hp-grid" vector-effect="non-scaling-stroke"/>'; });
  var g = hlGeom(HLOAD.hist, k, w, h, top, 3);
  if (g.pts.length > 1) {
    var pts = hlJoin(g.pts);
    svg += '<g>' + g.anim + '<polygon points="' + g.pts[0][0] + ',' + h + ' ' + pts + ' ' + g.pts[g.pts.length - 1][0] + ',' + h + '" fill="currentColor" opacity=".16"/>';
    svg += '<polyline points="' + pts + '" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" vector-effect="non-scaling-stroke"/></g>';
  }
  box.innerHTML = svg + '</svg>';
  return box;
}
function hpRing(pct, label, cls, size) {
  size = size || 78;
  var r = size / 2 - 7, c = 2 * Math.PI * r, v = hlWidth(pct);
  var col = cls || (v >= 90 ? 'hot' : (v >= 70 ? 'warm' : ''));
  var box = el('span', 'hp-ring ' + col);
  box.innerHTML = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '" aria-hidden="true">'
    + '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" class="hp-ring-bg"/>'
    + '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" class="hp-ring-fg" stroke-dasharray="' + (c * v / 100).toFixed(1) + ' ' + c.toFixed(1) + '" transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')"/></svg>';
  box.appendChild(noI18n(el('span', 'hp-ring-v', label)));
  return box;
}
function hpTempCls(t) { return t >= 85 ? 'hot' : (t >= 70 ? 'warm' : 'ok'); }
function hpSec(p, title) { var s = el('div', 'hp-sec'); if (title) s.appendChild(el('div', 'hp-h', title)); p.appendChild(s); return s; }
function hpTd(tr, v, cls) { var td = el('td', cls || ''); if (v && v.nodeType) td.appendChild(v); else if (v !== null && v !== undefined) td.appendChild(noI18n(el('span', '', String(v)))); tr.appendChild(td); return td; }
function hpGHz(m) { return m ? (m >= 1000 ? hlDec(m / 1000, 1) + ' GHz' : m + ' MHz') : ''; }
function hpPct(v) { return v === null || v === undefined ? '…' : Math.round(v) + ' %'; }
function hpCpuTemp(x) { var t = ((x.temps || {}).cpu || [])[0]; return t ? t[1] : null; }
function hpNoTemp(host, x) {
  var tps = x.temps || {};
  if (!(tps.cpu || []).length && !Object.keys(tps.cores || {}).length)
    host.appendChild(el('p', 'muted small', 'No temperature: this machine has no sensors the kernel reads (a virtual machine has none).'));
}
function hpWait(p) { p.appendChild(el('p', 'muted small', 'reading…')); }
/* the same rows for memory and the network in every style but the tiles */
function hpMemRows(host, x) {
  var m = x.mem || {}, used = (m.total || 0) - (m.available || 0);
  var t = el('table', 'hp-t hp-kvt');
  [['In use', bytes(used)], ['Free for programs', bytes(m.available || 0)], ['Cache (given back when needed)', bytes((m.cached || 0) + (m.buffers || 0))],
   ['Shared', bytes(m.shared || 0)], ['Swap', m.swap_total ? bytes(m.swap_total - (m.swap_free || 0)) + ' / ' + bytes(m.swap_total) : null], ['Altogether', bytes(m.total || 0)]].forEach(function (r) {
    var tr = el('tr', ''); hpTd(tr, el('span', 'muted', r[0])); hpTd(tr, r[1] === null ? el('span', 'muted', 'none') : r[1], 'num'); t.appendChild(tr);
  });
  host.appendChild(t);
}
function hpProcs(host, list, what) {
  /* Each bar its real share (1.0.48, as plexmon 2.7.2/2.7.4): of one core for the processor (of
     the busiest when one takes more cores), of the memory in use - not of the busiest process,
     which gave a "0 %" a third of a bar. */
  var t = el('table', 'hp-t'), top = 100;
  var memAll = (HLOAD.last && (HLOAD.last.mem_used || HLOAD.last.mem_total)) || 0;
  list.forEach(function (q) { if (what === 'cpu') top = Math.max(top, q.cpu || 0); });
  list.slice(0, 5).forEach(function (q) {
    var tr = el('tr', ''), v = what === 'cpu' ? q.cpu : q.rss;
    var share = what === 'cpu' ? 100 * (v || 0) / top : (memAll ? 100 * (v || 0) / memAll : 0);
    hpTd(tr, q.name, 'mono hp-name'); hpTd(tr, hlBar(share, 'hp-info'), 'hp-barc');
    hpTd(tr, what === 'cpu' ? Math.round(v) + ' %' : bytes(v), 'num');
    t.appendChild(tr);
  });
  host.appendChild(t);
  if (!list.length) host.appendChild(el('p', 'muted small', 'nothing busy just now'));
}
function hpNicRows(host, x) {
  var t = el('table', 'hp-t');
  (x.nics || []).forEach(function (n) {
    var tr = el('tr', '');
    hpTd(tr, el('b', 'mono', n.name)); hpTd(tr, (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''), 'muted small');
    hpTd(tr, '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx), 'num'); t.appendChild(tr);
    var tr2 = el('tr', 'hp-sub'); hpTd(tr2, ''); hpTd(tr2, noI18n(el('span', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all))), 'hp-span2');
    tr2.lastChild.colSpan = 2; t.appendChild(tr2);
  });
  host.appendChild(t);
  if (!(x.nics || []).length) host.appendChild(el('p', 'muted small', 'no card'));
}
function hpDisks(x) { return (x.disks || []).filter(function (dk) { return dk.size > 64 * 1048576; }); }
function hpHead(p, k, extra) {
  var head = el('div', 'hp-head');
  head.appendChild(el('b', '', HP_TITLE[k]));
  if (extra) head.appendChild(extra);
  p.appendChild(head);
}
/* B - the table */
function hpTable(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var sum = {cpu: hpPct(d.cpu), mem: d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '',
             disk: '↓' + hloadRate(d.disk_rd) + ' ↑' + hloadRate(d.disk_wr), net: '↓' + hloadRate(d.net_rx) + ' ↑' + hloadRate(d.net_tx)}[k];
  var ex = el('span', 'muted small');
  ex.appendChild(noI18n(el('b', 'hp-sum', sum)));
  if (k === 'cpu' && x) { ex.appendChild(noI18n(el('span', '', ' · load ' + hlLoads(d.load)))); var ct = hpCpuTemp(x); if (ct !== null) { ex.appendChild(noI18n(el('span', '', ' · '))); ex.appendChild(hlTemp(ct)); } }
  hpHead(p, k, ex);
  p.appendChild(hpArea(k, 38));
  if (!x) return hpWait(p);
  if (k === 'cpu') {
    var t = el('table', 'hp-t hp-cores-t');
    (x.cores || []).forEach(function (c) {
      var tr = el('tr', '');
      hpTd(tr, 'cpu' + c.n, 'mono muted'); hpTd(tr, hlBar(c.busy), 'hp-barc'); hpTd(tr, hpPct(c.busy), 'num');
      hpTd(tr, hpGHz(c.mhz), 'num muted'); hpTd(tr, hlTemp(c.temp), 'num'); t.appendChild(tr);
    });
    p.appendChild(t);
    hpNoTemp(p, x);
    hpProcs(hpSec(p, 'Taking most of the processor'), x.top_cpu || [], 'cpu');
  } else if (k === 'mem') {
    hpMemRows(hpSec(p, ''), x);
    hpProcs(hpSec(p, 'Taking most memory'), x.top_mem || [], 'mem');
  } else if (k === 'disk') {
    var td = el('table', 'hp-t'), hr = el('tr', 'hp-th');
    ['disk', 'read', 'written', 'busy', '°C'].forEach(function (h, i) { hpTd(hr, el('span', '', h), i ? 'num' : ''); });
    td.appendChild(hr);
    hpDisks(x).forEach(function (dk) {
      var tr = el('tr', '');
      hpTd(tr, dk.name, 'mono'); hpTd(tr, hloadRate(dk.rd), 'num'); hpTd(tr, hloadRate(dk.wr), 'num'); hpTd(tr, hpPct(dk.util), 'num'); hpTd(tr, hlTemp(dk.temp), 'num');
      td.appendChild(tr);
    });
    p.appendChild(td);
    var s2 = hpSec(p, 'Filesystems'), tf = el('table', 'hp-t');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0, tr = el('tr', '');
      hpTd(tr, f.mount, 'mono hp-name'); hpTd(tr, hlBar(pct), 'hp-barc'); hpTd(tr, bytes(f.used) + ' / ' + bytes(f.total), 'num muted small'); hpTd(tr, Math.round(pct) + ' %', 'num');
      tf.appendChild(tr);
    });
    s2.appendChild(tf);
  } else hpNicRows(hpSec(p, ''), x);
}
/* C - the map of the cores and rings */
function hpMap(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var top = el('div', 'hp-top');
  var info = el('div', 'hp-info-col');
  info.appendChild(el('b', '', HP_TITLE[k]));
  if (k === 'cpu') {
    top.appendChild(hpRing(d.cpu, hpPct(d.cpu)));
    var ct = x ? hpCpuTemp(x) : null;
    if (ct !== null) top.appendChild(hpRing(ct, Math.round(ct) + '°', hpTempCls(ct) === 'ok' ? '' : hpTempCls(ct)));
    if (x) {
      if (x.model) info.appendChild(noI18n(el('div', 'muted small', x.model)));
      info.appendChild(noI18n(el('div', 'muted small', 'load ' + hlLoads(d.load) + ' · ' + hlUp(x.uptime))));
    }
  } else if (k === 'mem') {
    var mp = d.mem_total ? 100 * d.mem_used / d.mem_total : 0;
    top.appendChild(hpRing(mp, Math.round(mp) + ' %'));
    info.appendChild(noI18n(el('div', 'muted small', d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '')));
  } else {
    var a = k === 'disk' ? [d.disk_rd, d.disk_wr] : [d.net_rx, d.net_tx];
    info.appendChild(noI18n(el('div', 'hp-big', '↓' + hloadRate(a[0]) + '  ↑' + hloadRate(a[1]))));
  }
  top.appendChild(info);
  p.appendChild(top);
  p.appendChild(hpArea(k, 60, true));
  if (!x) return hpWait(p);
  if (k === 'cpu') {
    var s = hpSec(p, 'Map of the cores (colour = how busy, number = temperature)');
    var g = el('div', 'hp-heat');
    (x.cores || []).forEach(function (c) {
      var b = el('div', 'hp-cell'), v = c.busy || 0;
      b.style.background = 'hsl(' + Math.round(120 - 1.2 * v) + ',62%,' + Math.round(20 + v * 0.17) + '%)';
      b.appendChild(noI18n(el('span', 'hp-cell-n', String(c.n))));
      b.appendChild(noI18n(el('b', '', c.busy === null || c.busy === undefined ? '…' : Math.round(v) + '%')));
      b.appendChild(noI18n(el('span', 'hp-cell-t', c.temp !== null && c.temp !== undefined ? Math.round(c.temp) + '°' : hpGHz(c.mhz))));
      b.title = 'CPU ' + c.n + ' · ' + hpGHz(c.mhz);
      g.appendChild(b);
    });
    s.appendChild(g);
    hpNoTemp(s, x);
    var s3 = hpSec(p, 'Taking most of the processor'), w = el('div', 'hp-pills');
    (x.top_cpu || []).slice(0, 6).forEach(function (q) { var c = el('span', 'hp-pill'); c.appendChild(noI18n(el('span', 'mono', q.name))); c.appendChild(noI18n(el('b', '', Math.round(q.cpu) + ' %'))); w.appendChild(c); });
    s3.appendChild(w);
  } else if (k === 'mem') {
    hpMemRows(hpSec(p, ''), x);
    hpProcs(hpSec(p, 'Taking most memory'), x.top_mem || [], 'mem');
  } else if (k === 'disk') {
    var cards = el('div', 'hp-cards');
    hpDisks(x).forEach(function (dk) {
      var c = el('div', 'hp-card'), t = el('div', 'hp-card-top');
      t.appendChild(noI18n(el('b', 'mono', dk.name)));
      if (dk.temp !== null && dk.temp !== undefined) t.appendChild(hlTemp(dk.temp));
      c.appendChild(t);
      c.appendChild(noI18n(el('div', 'muted small hp-ell', bytes(dk.size) + (dk.model ? ' · ' + dk.model : ''))));
      c.appendChild(noI18n(el('div', 'hp-big', hpPct(dk.util))));
      c.appendChild(hlBar(dk.util));
      c.appendChild(noI18n(el('div', 'muted small', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))));
      cards.appendChild(c);
    });
    p.appendChild(cards);
    var s2 = hpSec(p, 'Filesystems'), rings = el('div', 'hp-rings');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0, one = el('div', 'hp-fsring');
      one.appendChild(hpRing(pct, Math.round(pct) + '%', null, 64));
      one.appendChild(noI18n(el('div', 'mono hp-ell', f.mount)));
      one.appendChild(noI18n(el('div', 'muted small', bytes(f.used) + ' / ' + bytes(f.total))));
      rings.appendChild(one);
    });
    s2.appendChild(rings);
  } else {
    var nc = el('div', 'hp-cards');
    (x.nics || []).forEach(function (n) {
      var c = el('div', 'hp-card'), t = el('div', 'hp-card-top');
      t.appendChild(noI18n(el('b', 'mono', n.name)));
      t.appendChild(noI18n(el('span', 'muted small', (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''))));
      c.appendChild(t);
      c.appendChild(noI18n(el('div', 'hp-big', '↓' + hloadRate(n.rx))));
      c.appendChild(noI18n(el('div', 'hp-big', '↑' + hloadRate(n.tx))));
      c.appendChild(noI18n(el('div', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all))));
      nc.appendChild(c);
    });
    p.appendChild(nc);
    if (!(x.nics || []).length) p.appendChild(el('p', 'muted small', 'no card'));
  }
}
/* D - one wide panel, the four side by side */
function hpWide(p) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var grid = el('div', 'hp-wide-grid');
  ['cpu', 'mem', 'disk', 'net'].forEach(function (k) {
    var col = el('div', 'hp-col' + (k === HLOAD.open ? ' hp-col-on' : ''));
    var head = el('div', 'hp-head');
    head.appendChild(el('b', '', HP_TITLE[k]));
    var sum = {cpu: hpPct(d.cpu), mem: d.mem_total ? bytes(d.mem_used) + ' / ' + bytes(d.mem_total) : '',
               disk: '↓' + hloadRate(d.disk_rd) + ' ↑' + hloadRate(d.disk_wr), net: '↓' + hloadRate(d.net_rx) + ' ↑' + hloadRate(d.net_tx)}[k];
    var ex = el('span', 'small');
    ex.appendChild(noI18n(el('span', 'hp-sum', sum)));
    if (k === 'cpu' && x) { var ct = hpCpuTemp(x); if (ct !== null) { ex.appendChild(noI18n(el('span', '', ' '))); ex.appendChild(hlTemp(ct)); } }
    head.appendChild(ex);
    col.appendChild(head);
    col.appendChild(hpArea(k, 34));
    if (!x) { hpWait(col); grid.appendChild(col); return; }
    if (k === 'cpu') {
      var t = el('table', 'hp-t');
      (x.cores || []).forEach(function (c) {
        var tr = el('tr', '');
        hpTd(tr, 'cpu' + c.n, 'mono muted'); hpTd(tr, hlBar(c.busy), 'hp-barc'); hpTd(tr, hpPct(c.busy), 'num'); hpTd(tr, hlTemp(c.temp), 'num');
        t.appendChild(tr);
      });
      col.appendChild(t);
      if (x.model) col.appendChild(noI18n(el('div', 'muted small hp-ell', x.model)));
      col.appendChild(noI18n(el('div', 'muted small', 'load ' + hlLoads(d.load) + ' · ' + hlUp(x.uptime))));
    } else if (k === 'mem') {
      hpMemRows(col, x);
      hpProcs(hpSec(col, 'Taking most memory'), (x.top_mem || []).slice(0, 4), 'mem');
    } else if (k === 'disk') {
      var td = el('table', 'hp-t');
      hpDisks(x).forEach(function (dk) {
        var tr = el('tr', '');
        hpTd(tr, dk.name, 'mono hp-name'); hpTd(tr, hlBar(dk.util), 'hp-barc'); hpTd(tr, hpPct(dk.util), 'num'); hpTd(tr, hlTemp(dk.temp), 'num');
        td.appendChild(tr);
        var tr2 = el('tr', 'hp-sub'); hpTd(tr2, ''); hpTd(tr2, noI18n(el('span', 'muted small', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))));
        tr2.lastChild.colSpan = 3; td.appendChild(tr2);
      });
      col.appendChild(td);
      var s2 = hpSec(col, 'Filesystems'), tf = el('table', 'hp-t');
      (x.filesystems || []).forEach(function (f) {
        var pct = f.total ? 100 * f.used / f.total : 0, tr = el('tr', '');
        hpTd(tr, f.mount, 'mono hp-name'); hpTd(tr, hlBar(pct), 'hp-barc'); hpTd(tr, Math.round(pct) + ' %', 'num'); tf.appendChild(tr);
      });
      s2.appendChild(tf);
    } else {
      var tn = el('table', 'hp-t');
      (x.nics || []).forEach(function (n) {
        var tr = el('tr', '');
        hpTd(tr, el('b', 'mono', n.name), 'hp-name');
        hpTd(tr, (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''), 'num muted small');
        tn.appendChild(tr);
        var tr2 = el('tr', 'hp-sub'); hpTd(tr2, noI18n(el('span', '', '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx)))); tr2.lastChild.colSpan = 2; tn.appendChild(tr2);
        var tr3 = el('tr', 'hp-sub'); hpTd(tr3, noI18n(el('span', 'muted small', '↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all)))); tr3.lastChild.colSpan = 2; tn.appendChild(tr3);
      });
      col.appendChild(tn);
      if (!(x.nics || []).length) col.appendChild(el('p', 'muted small', 'no card'));
    }
    grid.appendChild(col);
  });
  p.appendChild(grid);
  if (x) {
    var s = hpSec(p, 'Taking most of the processor'), w = el('div', 'hp-pills');
    (x.top_cpu || []).slice(0, 8).forEach(function (q) { var c = el('span', 'hp-pill'); c.appendChild(noI18n(el('span', 'mono', q.name))); c.appendChild(noI18n(el('b', '', Math.round(q.cpu) + ' %'))); w.appendChild(c); });
    s.appendChild(w);
  }
}
/* A - the tiles */
function hpTiles(p, k) {
  var d = HLOAD.last || {}, x = HLOAD.detail;
  var head = el('div', 'hp-head');
  head.appendChild(el('b', '', {cpu: 'The processor', mem: 'Memory', disk: 'The disks', net: 'The network'}[k]));
  var big = el('div', 'hp-graph');
  var max = hpMax(k);
  big.innerHTML = hloadSpark(HLOAD.hist, k, max).replace('width="56" height="18"', 'width="100%" height="54"');
  big.classList.add('hl-' + k);
  var scale = el('span', 'hp-scale muted small', k === 'cpu' || k === 'mem' ? '100 %' : hloadRate(max));
  head.appendChild(scale);
  p.appendChild(head);
  p.appendChild(big);
  p.appendChild(el('div', 'hp-span muted small', 'the last two minutes'));
  var sec = function (title) { var s = el('div', 'hp-sec'); if (title) s.appendChild(el('div', 'hp-h', title)); p.appendChild(s); return s; };
  var row = function (host, cells) { var r = el('div', 'hp-row'); cells.forEach(function (c) { if (c === null || c === undefined) { r.appendChild(el('span', '')); return; } r.appendChild(c.nodeType ? c : noI18n(el('span', '', String(c)))); }); host.appendChild(r); return r; };
  if (!x) { p.appendChild(el('p', 'muted small', 'reading…')); return; }
  var tps = x.temps || {};
  if (k === 'cpu') {
    var s1 = sec('');
    row(s1, [el('span', 'muted', 'Now'), noI18n(el('b', '', d.cpu === undefined ? '…' : Math.round(d.cpu) + ' %')), el('span', 'muted', 'load'), noI18n(el('span', '', hlLoads(d.load)))]).classList.add('hp-kv');
    if (x.model) row(s1, [noI18n(el('span', 'hp-wide muted small', x.model))]);
    row(s1, [el('span', 'muted', 'Up for'), noI18n(el('span', '', hlUp(x.uptime))), el('span', 'muted', 'processes'), noI18n(el('span', '', String(x.procs || '')))]).classList.add('hp-kv');
    (tps.cpu || []).forEach(function (t) { row(s1, [noI18n(el('span', 'muted', t[0])), hlTemp(t[1])]).classList.add('hp-kv'); });
    var s2 = sec('Each core');
    var grid = el('div', 'hp-cores');
    (x.cores || []).forEach(function (c) {
      var one = el('div', 'hp-core');
      var top = el('div', 'hp-core-top');
      top.appendChild(noI18n(el('b', '', 'CPU ' + c.n)));
      top.appendChild(noI18n(el('span', '', c.busy === null || c.busy === undefined ? '…' : Math.round(c.busy) + ' %')));
      one.appendChild(top);
      one.appendChild(hlBar(c.busy));
      var bot = el('div', 'hp-core-bot muted small');
      bot.appendChild(noI18n(el('span', '', c.mhz ? (c.mhz >= 1000 ? hlDec(c.mhz / 1000, 1) + ' GHz' : c.mhz + ' MHz') : '')));
      var t = hlTemp(c.temp);
      if (t) bot.appendChild(t);
      one.appendChild(bot);
      grid.appendChild(one);
    });
    s2.appendChild(grid);
    if (!(tps.cpu || []).length && !Object.keys(tps.cores || {}).length) s2.appendChild(el('p', 'muted small', 'No temperature: this machine has no sensors the kernel reads (a virtual machine has none).'));
    var s3 = sec('Taking most of the processor');
    (x.top_cpu || []).slice(0, 5).forEach(function (q) { row(s3, [noI18n(el('span', 'mono', q.name)), noI18n(el('span', 'muted small', 'pid ' + q.pid)), noI18n(el('span', 'num', Math.round(q.cpu) + ' %'))]); });
    if (!(x.top_cpu || []).length) s3.appendChild(el('p', 'muted small', 'nothing busy just now'));
  } else if (k === 'mem') {
    var m = x.mem || {}, used = (m.total || 0) - (m.available || 0);
    var s1m = sec('');
    s1m.appendChild(hlBar(m.total ? 100 * used / m.total : 0));
    [['In use', used], ['Free for programs', m.available], ['Cache (given back when needed)', (m.cached || 0) + (m.buffers || 0)], ['Shared', m.shared], ['Altogether', m.total]].forEach(function (r) {
      row(s1m, [el('span', 'muted', r[0]), noI18n(el('span', 'num', bytes(r[1] || 0)))]).classList.add('hp-kv2');
    });
    if (m.swap_total) {
      var su = m.swap_total - (m.swap_free || 0);
      row(s1m, [el('span', 'muted', 'Swap'), noI18n(el('span', 'num', bytes(su) + ' / ' + bytes(m.swap_total)))]).classList.add('hp-kv2');
    } else row(s1m, [el('span', 'muted', 'Swap'), el('span', 'num muted', 'none')]).classList.add('hp-kv2');
    var s2m = sec('Taking most memory');
    (x.top_mem || []).slice(0, 5).forEach(function (q) { row(s2m, [noI18n(el('span', 'mono', q.name)), noI18n(el('span', 'muted small', 'pid ' + q.pid)), noI18n(el('span', 'num', bytes(q.rss)))]); });
  } else if (k === 'disk') {
    var s1d = sec('Each disk');
    (x.disks || []).filter(function (dk) { return dk.size > 64 * 1048576; }).forEach(function (dk) {
      var r = row(s1d, [noI18n(el('b', 'mono', dk.name)), noI18n(el('span', 'muted small', bytes(dk.size) + (dk.model ? ' · ' + dk.model : ''))),
        noI18n(el('span', 'num', '↓' + hloadRate(dk.rd) + ' ↑' + hloadRate(dk.wr))), hlTemp(dk.temp)]);
      r.classList.add('hp-disk');
      var u = el('div', 'hp-util');
      u.appendChild(el('span', 'muted small', 'busy'));
      u.appendChild(hlBar(dk.util));
      u.appendChild(noI18n(el('span', 'small num', dk.util === undefined ? '…' : Math.round(dk.util) + ' %')));
      s1d.appendChild(u);
    });
    var s2d = sec('Filesystems');
    (x.filesystems || []).forEach(function (f) {
      var pct = f.total ? 100 * f.used / f.total : 0;
      var r = row(s2d, [noI18n(el('span', 'mono', f.mount)), noI18n(el('span', 'muted small', f.kind)), noI18n(el('span', 'num', bytes(f.used) + ' / ' + bytes(f.total)))]);
      r.classList.add('hp-fs');
      var b = el('div', 'hp-util');
      b.appendChild(hlBar(pct));
      b.appendChild(noI18n(el('span', 'small num', Math.round(pct) + ' %')));
      s2d.appendChild(b);
    });
  } else {
    var s1n = sec('Each card');
    (x.nics || []).forEach(function (n) {
      row(s1n, [noI18n(el('b', 'mono', n.name)), noI18n(el('span', 'muted small', (n.state || '') + (n.speed ? ' · ' + (n.speed >= 1000 ? n.speed / 1000 + ' Gb/s' : n.speed + ' Mb/s') : ''))),
        noI18n(el('span', 'num', '↓' + hloadRate(n.rx) + ' ↑' + hloadRate(n.tx)))]).classList.add('hp-nic');
      var since = el('span', 'muted small');
      since.appendChild(el('span', '', 'since start'));
      since.appendChild(noI18n(el('span', '', ' ↓' + bytes(n.rx_all) + ' ↑' + bytes(n.tx_all))));
      row(s1n, [el('span', ''), since]).classList.add('hp-nic2');
    });
    if (!(x.nics || []).length) s1n.appendChild(el('p', 'muted small', 'no card'));
  }
  var oth = tps.other || [];
  if (k === 'cpu' && oth.length) {
    var s4 = sec('Other sensors');
    oth.forEach(function (t) { row(s4, [noI18n(el('span', 'muted', t[0])), hlTemp(t[1])]).classList.add('hp-kv'); });
  }
}
function hloadTick(now) {
  if ($('hload') && !hlLive()) { hlNow(); hlFreeze(); }
  if (!$('hload') || (HLOAD.busy && !now) || document.hidden || !hlLive()) return;
  HLOAD.look = prefs().hload || 'graphs';        /* switched on in Settings → About (1.0.48) */
  if (HLOAD.look === 'off') {
    $('hload').hidden = true;
    document.querySelectorAll('.hload.hl-peer').forEach(function (b) { b.remove(); });
    return;
  }
  HLOAD.busy = true;
  var withDetail = !!HLOAD.open && !HLOAD.pnode;
  /* The first reading of a page asks the last two minutes too (1.0.48): loaded again (F5), the
     graphs go on from where they were, not drawn from nothing. And the other nodes of a cluster,
     the details of the one whose panel is open. */
  var withHist = !HLOAD.hist || !!HLOAD.wantHist;
  api('load&nodes=1' + (withDetail ? '&detail=1' : '') + (withHist ? '&hist=1' : '')
      + (HLOAD.open && HLOAD.pnode ? '&detail_of=' + encodeURIComponent(HLOAD.pnode) : '')).then(function (d) {
    if (d.off) {                    /* switched off in Settings → About meanwhile */
      HLOAD.look = 'off'; hloadPanelClose(); $('hload').hidden = true;
      document.querySelectorAll('.hload.hl-peer').forEach(function (b) { b.remove(); });
      return;
    }
    /* the page's clock against the server's: the least late of the last answers (1.0.50) */
    /* another node answers now (the VIP moved), or the server's clock was stepped (1.0.51):
       the graphs start again from its own last two minutes, the clocks measured anew */
    var est = d.now ? d.now - Date.now() / 1000 : null;
    if ((HLOAD.lastNode && d.node && d.node !== HLOAD.lastNode) ||
        (est !== null && HL_OFF.length && Math.abs(est - HLOAD.off) > 5)) {
      HL_OFF.length = 0;
      HLOAD.hist = null;
      HLOAD.wantHist = true;          /* its last two minutes asked with the next reading */
    }
    if (d.node) HLOAD.lastNode = d.node;
    if (est !== null) {
      HL_OFF.push(est);
      if (HL_OFF.length > 20) HL_OFF.shift();
      HLOAD.off = Math.max.apply(null, HL_OFF);
    }
    /* another node's readings on this node's clock, drawn further behind (they come every 5 s) */
    var tops = {};
    (HLOAD.peers || []).forEach(function (x) { if (x.hist && x.hist.top) tops[x.node] = x.hist.top; });
    HLOAD.peers = Array.isArray(d.peers) ? d.peers : [];
    HLOAD.peers.forEach(function (x) {
      if (!x.hist || !Array.isArray(x.hist.t)) return;
      var sh = Number(x.shift) || 0;
      x.hist.t = x.hist.t.map(function (t) { return t + sh; });
      x.hist.live = true; x.hist.D = HL_PEER_D; x.hist.top = tops[x.node];
    });
    /* the last details of each node kept, shown at once when its panel is opened (1.0.53) */
    HLOAD.pdetail = HLOAD.pdetail || {};
    HLOAD.peers.forEach(function (x) {
      if (x.detail) HLOAD.pdetail[x.node] = x.detail; else if (HLOAD.pdetail[x.node]) x.detail = HLOAD.pdetail[x.node];
    });
    if (d.detail) { HLOAD.detail = d.detail; HLOAD.detailAt = Date.now(); }
    if (withHist && (!HLOAD.hist || HLOAD.wantHist) && d.hist && Array.isArray(d.hist.cpu)) {
      HLOAD.wantHist = false;
      var seed = {live: true, D: HL_OWN_D};
      var ok = Array.isArray(d.hist.t) && d.hist.t.length === d.hist.cpu.length;
      ['cpu', 'mem', 'disk', 'net', 't'].forEach(function (k) { seed[k] = ok ? (d.hist[k] || []).slice() : []; });
      HLOAD.hist = seed;          /* this reading, the last of them, is not added twice below */
    }
    hloadDraw(d);
    hloadPeersDraw();
  }).catch(function () { }).then(function () { HLOAD.busy = false; });
}
function hloadLoop() {
  if (!$('hload')) return;
  clearInterval(HLOAD.timer);
  hloadTick();
  setTimeout(hloadTick, 1200);      /* the first rate needs a second reading */
  HLOAD.timer = setInterval(hloadTick, 3000);
}
document.addEventListener('visibilitychange', function () { if (!document.hidden) hloadTick(); });

/* The two pickers of My account (1.0.75): cards drawn by the same code from sample numbers. */
function hloadPickers(lsec) {
  if (!$('hload')) return;
  var HL_LOOKS = [['graphs', 'with a graph of the last two minutes'], ['pills', 'pills with a bar'],
                  ['line', 'one plain line'], ['rings', 'with rings'], ['off', 'not shown']];
  var g3 = el('div', 'hl-pickers');
  g3.appendChild(el('div', 'hl-pick-h', 'The load of the server in the header (CPU, RAM, the disks, the network)'));
  g3.appendChild(hlPicker(HL_LOOKS, prefs().hload || 'graphs', hlPreviewLook, function (v) {
    savePrefs({hload: v}).then(function () {
      HLOAD.look = v;
      if (v === 'off') { hloadPanelClose(); $('hload').hidden = true; } else if (HLOAD.last) hloadDraw(HLOAD.last); else hloadTick();
      toast('kept', 'good');
    }).catch(oops);
  }));
  /* and how its details look when a number is pointed at (1.0.74) */
  g3.appendChild(el('div', 'hl-pick-h', 'Its details, when a number is pointed at (or tapped)'));
  g3.appendChild(hlPicker(HP_STYLES, hpStyle(), hlPreviewPanel, function (v) {
    savePrefs({hpanel: v}).then(function () {
      if (v === 'off') hloadPanelClose(); else if (HLOAD.open) { hloadPanelDraw(); hloadPanelPlace(); }
      if (HLOAD.last) hloadDraw(HLOAD.last);
      toast('kept', 'good');
    }).catch(oops);
  }));
  lsec.appendChild(g3);
}

/* Started by itself where the page has its place (a full administrator's header); nothing is
   asked while the look is off. */
if (document.getElementById('hload')) hloadLoop();
