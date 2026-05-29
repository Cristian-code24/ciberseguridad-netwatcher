/* ============================================================
   NetWatcher v2.0 — Frontend Logic
   ============================================================ */

'use strict';

// ─── State ─────────────────────────────────────────────────────────────────
const state = {
  hosts: [],           // Array of host objects
  selectedIdx: null,   // Index in hosts[] currently selected
  scanning: false,
  scanId: null,
  scanStartTime: null,
  totalScanned: 0,
  nmapScanId: null,
  sortCol: 'ip',
  sortDir: 1,
};

// ─── Risk helpers ───────────────────────────────────────────────────────────
const HIGH_RISK  = new Set([23,135,137,138,139,445,1433,2375,3389,4444,5432,5900,6379,11211,27017,27018]);
const MED_RISK   = new Set([21,25,80,110,143,161,389,515,1080,2049,3306,4848,8080,8888,9200]);

const SECURITY_HINTS = {
  23:    { severity:'critical', msg:'Telnet: Transmite datos en texto plano. Reemplaza con SSH.' },
  21:    { severity:'high',     msg:'FTP: Credenciales sin cifrar. Usa SFTP o FTPS.' },
  135:   { severity:'high',     msg:'MS-RPC: Vector de ataque común en Windows.' },
  139:   { severity:'high',     msg:'NetBIOS: Protocolo obsoleto, deshabilita si no es necesario.' },
  445:   { severity:'critical', msg:'SMB: Vulnerable a EternalBlue (MS17-010) / WannaCry.' },
  3389:  { severity:'high',     msg:'RDP: Potencialmente vulnerable a BlueKeep (CVE-2019-0708).' },
  6379:  { severity:'critical', msg:'Redis: Sin autenticación puede llevar a RCE.' },
  27017: { severity:'critical', msg:'MongoDB: A menudo expuesto sin autenticación.' },
  11211: { severity:'critical', msg:'Memcached: Puede usarse para amplificación DDoS.' },
  4444:  { severity:'critical', msg:'¡Puerto común de Metasploit! Posible backdoor activo.' },
  2375:  { severity:'critical', msg:'Docker API sin TLS: acceso completo a contenedores.' },
  5900:  { severity:'high',     msg:'VNC: Asegúrate de tener contraseña fuerte.' },
  1433:  { severity:'high',     msg:'MSSQL: Base de datos expuesta. Restringe acceso.' },
  5432:  { severity:'high',     msg:'PostgreSQL: Base de datos expuesta. Restringe acceso.' },
  3306:  { severity:'medium',   msg:'MySQL: Base de datos expuesta. Asegura con firewall.' },
  9200:  { severity:'high',     msg:'Elasticsearch: A menudo expuesto sin autenticación.' },
  25:    { severity:'medium',   msg:'SMTP: Puede usarse como relay de spam si mal configurado.' },
  8888:  { severity:'medium',   msg:'Jupyter Notebook: Acceso a Python sin autenticación.' },
};

function guessOS(portDetails) {
  const p = new Set((portDetails || []).map(d => d.port));
  if (p.has(3389) && p.has(445))  return { label:'Windows',    icon:'🪟' };
  if (p.has(445) && !p.has(22))   return { label:'Windows',    icon:'🪟' };
  if (p.has(22) && p.has(111))    return { label:'Linux',       icon:'🐧' };
  if (p.has(22) && p.has(548))    return { label:'macOS',       icon:'🍎' };
  if (p.has(22) && !p.has(445))   return { label:'Linux/Unix',  icon:'🐧' };
  if (p.has(53) && p.size < 5)    return { label:'Router/IoT',  icon:'📡' };
  if (p.has(80) && p.size < 4)    return { label:'IoT Device',  icon:'📟' };
  return { label:'Desconocido', icon:'❓' };
}

function riskLabel(host) {
  const risk = host.risk;
  if (!risk) return 'UNKNOWN';
  return risk.level || 'UNKNOWN';
}

function portRisk(port) {
  if (HIGH_RISK.has(port)) return 'high';
  if (MED_RISK.has(port))  return 'medium';
  return '';
}

// ─── DOM refs ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const qs = (sel, root=document) => root.querySelector(sel);

const els = {
  matrixCanvas:   $('matrix-bg'),
  clock:          $('clock'),
  netStatus:      $('net-status'),
  statusDot:      $('status-dot'),
  statusLabel:    $('status-label'),
  headerCidr:     $('header-cidr'),

  // Scanner
  cidrInput:      $('cidr-input'),
  cidrHint:       $('cidr-hint'),
  autoDetectBtn:  $('auto-detect-btn'),
  arpScanBtn:     $('arp-scan-btn'),
  stopBtn:        $('stop-btn'),
  nMapIp:         $('nmap-ip'),
  nMapPorts:      $('nmap-ports'),
  nMapScanBtn:    $('nmap-scan-btn'),

  // Progress
  progressCard:   $('progress-card'),
  progressFill:   $('progress-bar-fill'),
  progressLabel:  $('progress-label'),
  progressCount:  $('progress-count'),

  // Stats
  statHosts:      $('stat-hosts'),
  statPorts:      $('stat-ports'),
  statHigh:       $('stat-high'),
  statTime:       $('stat-time'),

  // Table
  hostsTbody:     $('hosts-tbody'),
  filterInput:    $('filter-input'),
  riskFilter:     $('risk-filter'),
  hostCountBadge: $('host-count-badge'),

  // Log
  activityLog:    $('activity-log'),

  // Detail panel
  detailPlaceholder: $('detail-placeholder'),
  detailContent:  $('detail-content'),
  detailHostSum:  $('detail-host-summary'),
  detailPorts:    $('detail-ports'),
  detailNmapBtn:  $('detail-nmap-btn'),
  nmapStatus:     $('nmap-status'),
  nmapStatusTxt:  $('nmap-status-text'),
  riskSection:    $('risk-section'),
  riskBadgeLg:    $('risk-badge-lg'),
  riskHints:      $('risk-hints'),
  portsSection:   $('ports-section'),
  portGrid:       $('port-grid'),
  osSection:      $('os-section'),
  osGuess:        $('os-guess'),

  // Export
  exportCsvBtn:   $('export-csv-btn'),
  exportJsonBtn:  $('export-json-btn'),

  // Modal
  hostModal:      $('host-modal'),
  modalBackdrop:  $('modal-backdrop'),
  modalTitle:     $('modal-title'),
  modalBody:      $('modal-body'),
  modalCloseBtn:  $('modal-close-btn'),

  // Toast
  toastContainer: $('toast-container'),
};

// ─── Matrix Background ──────────────────────────────────────────────────────
class Matrix {
  constructor(canvas) {
    this.c = canvas;
    this.ctx = canvas.getContext('2d');
    this.chars = 'ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ01'.split('');
    this.drops = [];
    this.fs = 14;
    this.lastDraw = 0;
    this.resize();
    window.addEventListener('resize', () => this.resize());
    requestAnimationFrame(t => this.draw(t));
  }
  resize() {
    this.c.width  = window.innerWidth;
    this.c.height = window.innerHeight;
    const cols = Math.floor(this.c.width / this.fs);
    this.drops = Array.from({length: cols}, () => Math.random() * -50);
  }
  draw(t) {
    if (t - this.lastDraw < 60) { requestAnimationFrame(t => this.draw(t)); return; }
    this.lastDraw = t;
    const ctx = this.ctx;
    ctx.fillStyle = 'rgba(5,8,16,0.06)';
    ctx.fillRect(0, 0, this.c.width, this.c.height);
    ctx.fillStyle = 'rgba(0,255,159,0.18)';
    ctx.font = `${this.fs}px "JetBrains Mono", monospace`;
    for (let i = 0; i < this.drops.length; i++) {
      const ch = this.chars[Math.floor(Math.random() * this.chars.length)];
      ctx.fillText(ch, i * this.fs, this.drops[i] * this.fs);
      if (this.drops[i] * this.fs > this.c.height && Math.random() > 0.975) {
        this.drops[i] = 0;
      }
      this.drops[i]++;
    }
    requestAnimationFrame(t => this.draw(t));
  }
}

// ─── Clock ──────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  const h = String(now.getHours()).padStart(2,'0');
  const m = String(now.getMinutes()).padStart(2,'0');
  const s = String(now.getSeconds()).padStart(2,'0');
  els.clock.textContent = `${h}:${m}:${s}`;
}

// ─── Toast notifications ────────────────────────────────────────────────────
function toast(title, msg='', type='info', duration=4000) {
  const icons = { success:'✅', error:'❌', warn:'⚠️', info:'ℹ️' };
  const div = document.createElement('div');
  div.className = `toast toast-${type}`;
  div.innerHTML = `
    <div class="toast-icon">${icons[type]||'ℹ️'}</div>
    <div class="toast-body">
      <div class="toast-title">${esc(title)}</div>
      ${msg ? `<div class="toast-msg">${esc(msg)}</div>` : ''}
    </div>`;
  els.toastContainer.appendChild(div);
  setTimeout(() => {
    div.classList.add('fade-out');
    div.addEventListener('animationend', () => div.remove());
  }, duration);
}

// ─── Activity log ───────────────────────────────────────────────────────────
function logLine(msg, level='INFO') {
  const now = new Date();
  const ts = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}:${String(now.getSeconds()).padStart(2,'0')}`;
  const div = document.createElement('div');
  div.className = 'log-line';
  div.innerHTML = `<span class="log-ts">${ts}</span><span class="log-lvl ${level}">${level}</span><span class="log-msg">${esc(msg)}</span>`;
  els.activityLog.appendChild(div);
  els.activityLog.scrollTop = els.activityLog.scrollHeight;
  // Keep max 150 entries
  while (els.activityLog.childElementCount > 150) {
    els.activityLog.removeChild(els.activityLog.firstChild);
  }
}

// ─── Escape HTML ────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// ─── Counter animation ──────────────────────────────────────────────────────
function animCount(el, target, duration=600) {
  const start = parseInt(el.textContent) || 0;
  const startT = performance.now();
  const step = t => {
    const progress = Math.min((t - startT) / duration, 1);
    el.textContent = Math.round(start + (target - start) * progress);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function updateStats() {
  animCount(els.statHosts, state.hosts.length);
  const totalPorts = state.hosts.reduce((a,h) => a + (h.open_ports||[]).length, 0);
  animCount(els.statPorts, totalPorts);
  const highRisk = state.hosts.filter(h => riskLabel(h) === 'HIGH').length;
  animCount(els.statHigh, highRisk);
  els.hostCountBadge.textContent = state.hosts.length;
}

// ─── CIDR validation ────────────────────────────────────────────────────────
let cidrDebounce = null;
function validateCidrInput(cidr) {
  clearTimeout(cidrDebounce);
  if (!cidr) { els.cidrHint.textContent = ''; els.cidrInput.classList.remove('valid','invalid'); return; }
  cidrDebounce = setTimeout(async () => {
    try {
      const r = await fetch(`/api/validate-cidr?cidr=${encodeURIComponent(cidr)}`);
      const d = await r.json();
      if (d.valid) {
        els.cidrInput.classList.remove('invalid'); els.cidrInput.classList.add('valid');
        els.cidrHint.textContent = '✓ Rango CIDR válido'; els.cidrHint.className = 'field-hint ok';
      } else {
        els.cidrInput.classList.remove('valid'); els.cidrInput.classList.add('invalid');
        els.cidrHint.textContent = '✗ Formato inválido — usa ej: 192.168.1.0/24'; els.cidrHint.className = 'field-hint err';
      }
    } catch { /* silent */ }
  }, 400);
}

// ─── Auto-detect CIDR ──────────────────────────────────────────────────────
async function autoDetectCIDR() {
  els.autoDetectBtn.textContent = '⏳';
  try {
    const r = await fetch('/api/detect-cidr');
    const d = await r.json();
    if (d.success && d.cidr) {
      els.cidrInput.value = d.cidr;
      els.cidrInput.classList.add('valid');
      els.cidrHint.textContent = `✓ Red detectada: ${d.cidr}`; els.cidrHint.className = 'field-hint ok';
      els.statusDot.classList.add('online');
      els.statusLabel.textContent = 'Red detectada';
      els.headerCidr.textContent = d.cidr;
      logLine(`Red local detectada: ${d.cidr}`, 'OK');
    } else {
      toast('Sin red detectada', 'Introduce el CIDR manualmente.', 'warn');
    }
  } catch (e) {
    toast('Error al detectar red', e.message, 'error');
  } finally {
    els.autoDetectBtn.textContent = '🎯';
  }
}

// ─── Render host row ────────────────────────────────────────────────────────
function makeRiskBadge(level) {
  const labels = { HIGH:'🔴 ALTO', MEDIUM:'🟠 MEDIO', LOW:'🟡 BAJO', SAFE:'🟢 SEGURO', UNKNOWN:'⚪ —' };
  return `<span class="risk-badge risk-${level}">${labels[level]||level}</span>`;
}

function makePortChips(ports) {
  if (!ports || ports.length === 0) return '<span style="color:var(--color-muted);font-size:0.7rem">—</span>';
  const shown = ports.slice(0, 6);
  const chips = shown.map(p => {
    const cls = HIGH_RISK.has(p) ? 'danger' : MED_RISK.has(p) ? 'warn' : '';
    return `<span class="port-chip ${cls}">${p}</span>`;
  }).join('');
  const more = ports.length > 6 ? `<span class="port-chip" style="color:var(--color-muted)">+${ports.length-6}</span>` : '';
  return `<div class="port-chips">${chips}${more}</div>`;
}

function renderHostRow(host, idx) {
  const tr = document.createElement('tr');
  tr.dataset.idx = idx;
  tr.classList.add('row-new');
  const risk  = riskLabel(host);
  const ports = host.open_ports || [];
  const os    = guessOS(host.portDetails || []);
  tr.innerHTML = `
    <td><div class="row-num">${idx+1}</div></td>
    <td class="col-ip">
      <span class="mono">${esc(host.ip)}</span>
      <button class="copy-btn" data-copy="${esc(host.ip)}" title="Copiar IP">⎘</button>
    </td>
    <td class="col-mac">
      <span>${esc(host.mac||'—')}</span>
      <button class="copy-btn" data-copy="${esc(host.mac||'')}" title="Copiar MAC">⎘</button>
    </td>
    <td class="col-host">${esc(host.hostname||'N/A')}</td>
    <td class="col-vendor">
      <div class="vendor-cell">
        <span class="vendor-name">${esc(host.vendor||'Desconocido')}</span>
        <span class="os-hint">${os.icon} ${esc(os.label)}</span>
      </div>
    </td>
    <td class="col-risk">${makeRiskBadge(risk)}</td>
    <td class="col-ports">${makePortChips(ports)}</td>
    <td class="col-actions">
      <button class="scan-row-btn" data-idx="${idx}" title="Escanear puertos">🔬 Scan</button>
    </td>`;
  tr.addEventListener('click', e => {
    if (e.target.classList.contains('copy-btn')) {
      navigator.clipboard?.writeText(e.target.dataset.copy||'');
      toast('Copiado', e.target.dataset.copy, 'success', 1500);
      return;
    }
    if (e.target.classList.contains('scan-row-btn')) {
      selectHost(parseInt(e.target.dataset.idx));
      startNmapForSelected();
      return;
    }
    selectHost(idx);
  });
  return tr;
}

function selectHost(idx) {
  state.selectedIdx = idx;
  // Highlight row
  document.querySelectorAll('#hosts-tbody tr').forEach(r => r.classList.remove('selected'));
  const row = document.querySelector(`#hosts-tbody tr[data-idx="${idx}"]`);
  if (row) row.classList.add('selected');
  // Show detail panel
  showDetailPanel(state.hosts[idx]);
}

// ─── Host detail panel ──────────────────────────────────────────────────────
function showDetailPanel(host) {
  els.detailPlaceholder.style.display = 'none';
  els.detailContent.style.display = 'block';

  const os = guessOS(host.portDetails || []);
  els.detailHostSum.innerHTML = `
    <div class="host-ip mono">${esc(host.ip)}</div>
    <dl class="host-meta">
      <div>MAC: <span>${esc(host.mac||'—')}</span></div>
      <div>Hostname: <span>${esc(host.hostname||'N/A')}</span></div>
      <div>Vendor: <span>${esc(host.vendor||'Desconocido')}</span></div>
      <div>OS Estimado: <span>${os.icon} ${esc(os.label)}</span></div>
    </dl>`;

  // Nmap IP prefill
  els.nMapIp.value = host.ip;

  // If already has port data, render it
  if (host.portDetails && host.portDetails.length > 0) {
    renderPortData(host);
  } else {
    els.riskSection.style.display  = 'none';
    els.portsSection.style.display = 'none';
    els.osSection.style.display    = 'none';
  }
}

function renderPortData(host) {
  const ports  = host.portDetails || [];
  const risk   = host.risk || {};
  const os     = guessOS(ports);

  // Risk
  els.riskSection.style.display = '';
  const rl = risk.level || 'UNKNOWN';
  els.riskBadgeLg.className = `risk-badge-lg risk-badge risk-${rl}`;
  const rLabels = { HIGH:'🔴 ALTO', MEDIUM:'🟠 MEDIO', LOW:'🟡 BAJO', SAFE:'🟢 SEGURO', UNKNOWN:'—' };
  els.riskBadgeLg.textContent = rLabels[rl] || rl;

  // Security hints
  const hints = (risk.hints || []).slice(0, 5);
  els.riskHints.innerHTML = hints.map(h =>
    `<div class="risk-hint hint-${h.severity}">
       <span class="hint-port">${h.port}</span> — ${esc(h.msg)}
     </div>`
  ).join('');
  if (hints.length === 0) {
    els.riskHints.innerHTML = '<div style="color:var(--color-muted);font-size:0.72rem">Sin alertas de seguridad detectadas</div>';
  }

  // Ports grid
  els.portsSection.style.display = '';
  els.portGrid.innerHTML = ports.map(pd => {
    const cls = HIGH_RISK.has(pd.port) ? 'high' : MED_RISK.has(pd.port) ? 'medium' : '';
    return `<div class="port-item ${cls}" title="${esc(pd.service)}">
      <div class="port-num">${pd.port}</div>
      <div class="port-svc">${esc(pd.service||'?')}</div>
    </div>`;
  }).join('');

  // OS
  els.osSection.style.display = '';
  els.osGuess.textContent = `${os.icon} ${os.label}`;
}

// ─── Re-render table ────────────────────────────────────────────────────────
function reRenderTable() {
  const filter = els.filterInput.value.toLowerCase();
  const rFilter = els.riskFilter.value;

  const filtered = state.hosts.filter((h, i) => {
    const text = `${h.ip} ${h.mac} ${h.hostname} ${h.vendor}`.toLowerCase();
    if (filter && !text.includes(filter)) return false;
    if (rFilter && riskLabel(h) !== rFilter) return false;
    return true;
  });

  // Clear
  while (els.hostsTbody.firstChild) els.hostsTbody.removeChild(els.hostsTbody.firstChild);

  if (filtered.length === 0) {
    const tr = document.createElement('tr');
    tr.id = 'empty-state-row';
    tr.innerHTML = `<td colspan="8"><div class="empty-state">
      <div class="empty-icon">${filter || rFilter ? '🔎' : '🌐'}</div>
      <div class="empty-title">${filter || rFilter ? 'Sin resultados' : 'Sin hosts descubiertos'}</div>
      <div class="empty-sub">${filter || rFilter ? 'Prueba con otros filtros' : 'Introduce un rango CIDR e inicia el escaneo ARP'}</div>
    </div></td>`;
    els.hostsTbody.appendChild(tr);
    return;
  }

  // Find original indices
  filtered.forEach(h => {
    const origIdx = state.hosts.indexOf(h);
    els.hostsTbody.appendChild(renderHostRow(h, origIdx));
  });
}

function addHostRow(host) {
  state.hosts.push(host);
  const idx = state.hosts.length - 1;
  // Remove empty state
  const empty = $('empty-state-row');
  if (empty) empty.remove();
  // Add row
  els.hostsTbody.appendChild(renderHostRow(host, idx));
  updateStats();
}

// ─── ARP Scan ───────────────────────────────────────────────────────────────
async function startArpScan() {
  const cidr = els.cidrInput.value.trim();
  if (!cidr) { toast('Sin rango CIDR', 'Introduce un rango o usa auto-detectar.', 'warn'); return; }

  // Reset
  state.hosts = [];
  state.scanning = true;
  state.scanStartTime = Date.now();
  state.totalScanned = 0;

  els.arpScanBtn.disabled   = true;
  els.stopBtn.disabled      = false;
  els.exportCsvBtn.disabled  = true;
  els.exportJsonBtn.disabled = true;
  els.progressCard.style.display = '';
  document.body.classList.add('scanning-active');
  reRenderTable();
  updateStats();

  // Animate progress indeterminate
  animateProgress(true);
  logLine(`Iniciando escaneo ARP en ${cidr}...`, 'INFO');

  try {
    const r = await fetch('/api/scan/arp', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({cidr}),
    });
    const d = await r.json();
    if (!r.ok) { throw new Error(d.error || 'Error en el servidor'); }

    state.scanId = d.scan_id;
    const es = new EventSource(`/api/scan/stream/${d.scan_id}`);

    es.onmessage = e => {
      const msg = JSON.parse(e.data);

      if (msg.type === 'started') {
        logLine(`Escaneo iniciado en ${msg.cidr}`, 'OK');

      } else if (msg.type === 'host_found') {
        const host = msg.host;
        host.open_ports = [];
        host.portDetails = [];
        host.risk = null;
        addHostRow(host);
        logLine(`Host encontrado: ${host.ip} (${host.vendor||'Desconocido'})`, 'OK');

      } else if (msg.type === 'complete') {
        es.close();
        finishArpScan(msg.elapsed, msg.total);

      } else if (msg.type === 'cancelled') {
        es.close();
        finishArpScan(null, state.hosts.length, true);

      } else if (msg.type === 'error') {
        es.close();
        toast('Error de escaneo', msg.message, 'error');
        logLine(`Error: ${msg.message}`, 'ERROR');
        finishArpScan(null, state.hosts.length);
      }
    };

    es.onerror = () => {
      es.close();
      if (state.scanning) {
        toast('Conexión perdida', 'El stream SSE se cerró inesperadamente.', 'error');
        finishArpScan(null, state.hosts.length);
      }
    };

  } catch (e) {
    toast('Error al iniciar escaneo', e.message, 'error');
    logLine(`Error: ${e.message}`, 'ERROR');
    finishArpScan(null, 0);
  }
}

function finishArpScan(elapsed, total, cancelled=false) {
  state.scanning = false;
  els.arpScanBtn.disabled   = false;
  els.stopBtn.disabled       = true;
  els.progressCard.style.display = 'none';
  document.body.classList.remove('scanning-active');

  if (elapsed != null) {
    els.statTime.textContent = `${elapsed}s`;
  }

  const exportEnabled = state.hosts.length > 0;
  els.exportCsvBtn.disabled  = !exportEnabled;
  els.exportJsonBtn.disabled = !exportEnabled;

  if (cancelled) {
    logLine('Escaneo cancelado por el usuario.', 'WARN');
    toast('Escaneo cancelado', '', 'warn');
  } else if (total === 0) {
    logLine('Escaneo completado. Sin hosts encontrados.', 'WARN');
    toast('Sin hosts encontrados', 'Verifica que el rango CIDR es correcto y que tienes privilegios de administrador.', 'warn', 6000);
  } else {
    logLine(`Escaneo completado: ${total} host(s) encontrado(s) en ${elapsed}s.`, 'OK');
    toast('Escaneo completado', `${total} host(s) encontrado(s) en ${elapsed}s`, 'success');
  }
  updateStats();
}

let progressTimer = null;
function animateProgress(active) {
  clearInterval(progressTimer);
  if (!active) { els.progressFill.style.width = '100%'; return; }
  let pct = 5;
  els.progressFill.style.width = pct + '%';
  progressTimer = setInterval(() => {
    pct = Math.min(pct + Math.random() * 3, 90);
    els.progressFill.style.width = pct + '%';
    els.progressCount.textContent = `${state.hosts.length} hosts`;
    els.progressLabel.textContent = `Escaneando... ${state.hosts.length} host(s) encontrado(s)`;
  }, 300);
}

async function stopScan() {
  if (state.scanId) {
    fetch(`/api/scan/cancel/${state.scanId}`, {method:'POST'});
  }
  finishArpScan(null, state.hosts.length, true);
}

// ─── Nmap Scan ──────────────────────────────────────────────────────────────
async function startNmapScan(ip, ports, targetIdx) {
  logLine(`Iniciando escaneo de puertos en ${ip} (${ports})...`, 'INFO');
  els.nmapStatus.style.display = '';
  els.nmapStatusTxt.textContent = `Escaneando ${ip}...`;
  els.detailNmapBtn.disabled = true;

  try {
    const r = await fetch('/api/nmap', {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({ip, ports}),
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Error servidor');

    const es = new EventSource(`/api/nmap/stream/${d.scan_id}`);
    es.onmessage = e => {
      const msg = JSON.parse(e.data);
      if (msg.type === 'complete') {
        es.close();
        onNmapComplete(msg, targetIdx);
      } else if (msg.type === 'error') {
        es.close();
        els.nmapStatus.style.display = 'none';
        els.detailNmapBtn.disabled = false;
        toast('Error Nmap', msg.message, 'error');
        logLine(`Nmap error: ${msg.message}`, 'ERROR');
      }
    };
    es.onerror = () => {
      es.close();
      els.nmapStatus.style.display = 'none';
      els.detailNmapBtn.disabled = false;
      toast('Error SSE', 'Stream de Nmap cerrado inesperadamente.', 'error');
    };

  } catch(e) {
    els.nmapStatus.style.display = 'none';
    els.detailNmapBtn.disabled = false;
    toast('Error al iniciar Nmap', e.message, 'error');
  }
}

function onNmapComplete(msg, targetIdx) {
  els.nmapStatus.style.display = 'none';
  els.detailNmapBtn.disabled = false;

  const host = state.hosts[targetIdx];
  if (!host) return;

  host.portDetails = msg.ports || [];
  host.open_ports  = (msg.ports || []).map(p => p.port);
  host.risk        = msg.risk;

  logLine(`Puertos abiertos en ${msg.ip}: ${host.open_ports.length === 0 ? 'ninguno' : host.open_ports.join(', ')}`, 'OK');
  if (host.risk && host.risk.level === 'HIGH') {
    toast(`⚠️ Alto Riesgo — ${msg.ip}`, `Puertos críticos: ${host.risk.high_risk_ports.join(', ')}`, 'error', 6000);
  }

  // Update table row
  const row = document.querySelector(`#hosts-tbody tr[data-idx="${targetIdx}"]`);
  if (row) {
    row.cells[5].innerHTML = makeRiskBadge(host.risk?.level || 'UNKNOWN');
    row.cells[6].innerHTML = makePortChips(host.open_ports);
  }
  updateStats();

  // Re-render detail panel if selected
  if (state.selectedIdx === targetIdx) {
    renderPortData(host);
  }
}

function startNmapForSelected() {
  const idx = state.selectedIdx;
  if (idx == null) return;
  const host = state.hosts[idx];
  if (!host) return;
  const ports = els.detailPorts.value.trim() || '1-1024';
  startNmapScan(host.ip, ports, idx);
}

// ─── Export ─────────────────────────────────────────────────────────────────
async function exportAs(fmt) {
  if (state.hosts.length === 0) { toast('Sin datos', 'Realiza un escaneo primero.', 'warn'); return; }
  try {
    const r = await fetch(`/api/export/${fmt}`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({hosts: state.hosts}),
    });
    if (!r.ok) throw new Error('Error de servidor');
    const blob = await r.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    const cd   = r.headers.get('Content-Disposition') || '';
    const name = cd.match(/filename="([^"]+)"/)?.[1] || `netwatcher.${fmt}`;
    a.href = url; a.download = name; a.click();
    URL.revokeObjectURL(url);
    toast('Exportado', name, 'success');
    logLine(`Datos exportados como ${name}`, 'OK');
  } catch(e) {
    toast('Error al exportar', e.message, 'error');
  }
}

// ─── Modal ──────────────────────────────────────────────────────────────────
function openModal(host) {
  const risk = host.risk || {};
  const ports = host.portDetails || [];
  const os = guessOS(ports);
  els.modalTitle.textContent = `Host: ${host.ip}`;
  els.modalBody.innerHTML = `
    <div class="modal-section">
      <div class="modal-section-title">Información General</div>
      <dl class="modal-kv">
        <dt>IP</dt><dd>${esc(host.ip)}</dd>
        <dt>MAC</dt><dd>${esc(host.mac||'—')}</dd>
        <dt>Hostname</dt><dd>${esc(host.hostname||'N/A')}</dd>
        <dt>Vendor</dt><dd>${esc(host.vendor||'Desconocido')}</dd>
        <dt>OS Est.</dt><dd>${os.icon} ${esc(os.label)}</dd>
        <dt>Riesgo</dt><dd>${makeRiskBadge(risk.level||'UNKNOWN')}</dd>
      </dl>
    </div>
    ${ports.length > 0 ? `
    <div class="modal-section">
      <div class="modal-section-title">Puertos Abiertos (${ports.length})</div>
      <div class="port-grid">
        ${ports.map(p => {
          const cls = HIGH_RISK.has(p.port)?'high':MED_RISK.has(p.port)?'medium':'';
          return `<div class="port-item ${cls}"><div class="port-num">${p.port}</div><div class="port-svc">${esc(p.service||'?')}</div></div>`;
        }).join('')}
      </div>
    </div>` : ''}
    ${risk.hints && risk.hints.length > 0 ? `
    <div class="modal-section">
      <div class="modal-section-title">Alertas de Seguridad</div>
      <div class="risk-hints">
        ${risk.hints.map(h=>`<div class="risk-hint hint-${h.severity}"><span class="hint-port">${h.port}</span> — ${esc(h.msg)}</div>`).join('')}
      </div>
    </div>` : ''}`;
  els.hostModal.style.display = 'flex';
}

function closeModal() { els.hostModal.style.display = 'none'; }

// ─── Tab switching ──────────────────────────────────────────────────────────
function setupTabs() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const tab = btn.dataset.tab;
      document.querySelectorAll('.tab-btn').forEach(b => {
        b.classList.toggle('active', b.dataset.tab === tab);
        b.setAttribute('aria-selected', b.dataset.tab === tab);
      });
      document.querySelectorAll('.tab-pane').forEach(p => {
        p.classList.toggle('active', p.id === `pane-${tab}`);
      });
    });
  });
}

// ─── Event listeners ────────────────────────────────────────────────────────
function setupListeners() {
  // Clock
  setInterval(updateClock, 1000);
  updateClock();

  // CIDR
  els.cidrInput.addEventListener('input', e => validateCidrInput(e.target.value.trim()));
  els.autoDetectBtn.addEventListener('click', autoDetectCIDR);

  // Chips — CIDR
  document.querySelectorAll('.chip[data-cidr]').forEach(ch => {
    ch.addEventListener('click', () => {
      els.cidrInput.value = ch.dataset.cidr;
      validateCidrInput(ch.dataset.cidr);
    });
  });

  // Chips — ports
  document.querySelectorAll('.chip[data-ports]').forEach(ch => {
    ch.addEventListener('click', () => { els.nMapPorts.value = ch.dataset.ports; });
  });

  // ARP scan
  els.arpScanBtn.addEventListener('click', startArpScan);
  els.stopBtn.addEventListener('click', stopScan);

  // Nmap from sidebar tab
  els.nMapScanBtn.addEventListener('click', () => {
    const ip = els.nMapIp.value.trim();
    const ports = els.nMapPorts.value.trim() || '1-1024';
    if (!ip) { toast('Sin IP', 'Introduce la IP del objetivo.', 'warn'); return; }
    // Create a temp host if not in list
    let idx = state.hosts.findIndex(h => h.ip === ip);
    if (idx === -1) {
      const host = { ip, mac:'—', hostname:'N/A', vendor:'Desconocido', open_ports:[], portDetails:[], risk:null };
      state.hosts.push(host);
      idx = state.hosts.length - 1;
      reRenderTable();
    }
    selectHost(idx);
    startNmapScan(ip, ports, idx);
  });

  // Detail panel nmap
  els.detailNmapBtn.addEventListener('click', startNmapForSelected);

  // Filters
  els.filterInput.addEventListener('input', reRenderTable);
  els.riskFilter.addEventListener('change', reRenderTable);

  // Export
  els.exportCsvBtn.addEventListener('click', () => exportAs('csv'));
  els.exportJsonBtn.addEventListener('click', () => exportAs('json'));

  // Log clear
  $('clear-log-btn').addEventListener('click', () => {
    els.activityLog.innerHTML = '';
    logLine('Log limpiado.', 'INFO');
  });

  // Modal
  els.modalCloseBtn.addEventListener('click', closeModal);
  els.modalBackdrop.addEventListener('click', closeModal);
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeModal();
    if ((e.key === 'Enter') && !state.scanning) {
      if (document.activeElement !== els.cidrInput) return;
      startArpScan();
    }
  });

  // Keyboard shortcut: Ctrl+Enter = scan
  document.addEventListener('keydown', e => {
    if (e.ctrlKey && e.key === 'Enter' && !state.scanning) startArpScan();
  });
}

// ─── Init ───────────────────────────────────────────────────────────────────
function init() {
  new Matrix(els.matrixCanvas);
  setupTabs();
  setupListeners();
  logLine('NetWatcher v2.0 iniciado.', 'INFO');
  logLine('Usa Ctrl+Enter para iniciar el escaneo rápidamente.', 'INFO');
  // Auto-detect on load
  autoDetectCIDR();
}

document.addEventListener('DOMContentLoaded', init);
