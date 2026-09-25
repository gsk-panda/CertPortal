'use strict';

/**
 * Local status page for the agent: http://127.0.0.1:<port>/ (HTML, refreshes
 * itself) and /status.json. Bound to loopback only and read-only; it shows
 * no secrets. On Windows the MSI adds a Start menu shortcut to it.
 */

const http = require('http');

const CONNECTED_WITHIN_MS = 90 * 1000; // a long-poll returns at least every ~35s

function createStatus(info) {
  const state = {
    ...info,                 // version, controlPlane, agentName
    startedAt: new Date().toISOString(),
    phase: 'starting',       // starting | enrolling | running | stopped
    agentId: null,
    lastContactAt: null,     // last successful response from the portal
    lastError: null,
    lastErrorAt: null,
    jobsDone: 0,
    jobsFailed: 0,
    lastJob: null,
  };

  return {
    set(fields) { Object.assign(state, fields); },
    contact() { state.lastContactAt = new Date().toISOString(); },
    error(message) { state.lastError = message; state.lastErrorAt = new Date().toISOString(); },
    job(job, outcome) {
      if (outcome.status === 'done') state.jobsDone++; else state.jobsFailed++;
      state.lastJob = { id: job.id, op: job.op, status: outcome.status, error: outcome.error || null, at: new Date().toISOString() };
    },
    snapshot() {
      const connected = !!state.lastContactAt
        && Date.now() - Date.parse(state.lastContactAt) < CONNECTED_WITHIN_MS;
      return { connected, ...state };
    },
  };
}

const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function ago(iso) {
  if (!iso) return 'never';
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  const rel = s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
  return `${rel} <span class="dim">(${esc(iso.replace('T', ' ').slice(0, 19))} UTC)</span>`;
}

function headline(s) {
  if (s.connected) return ['ok', 'Connected', 'The agent is talking to CertPortal and waiting for work.'];
  if (s.phase === 'enrolling') return ['warn', 'Enrolling', 'Registering this agent with CertPortal using the enrollment token.'];
  if (s.phase === 'starting') return ['warn', 'Starting', 'The agent is starting up.'];
  if (s.phase === 'stopped') return ['bad', 'Stopped', s.lastError || 'The agent has stopped.'];
  return ['bad', 'Not connected', s.lastError ? `Last error: ${s.lastError}` : 'The agent has not reached CertPortal yet.'];
}

function page(s) {
  const [tone, title, detail] = headline(s);
  const job = s.lastJob
    ? `${esc(s.lastJob.op)} — ${esc(s.lastJob.status)}${s.lastJob.error ? `: ${esc(s.lastJob.error)}` : ''}, ${ago(s.lastJob.at)}`
    : 'none yet';
  const rows = [
    ['Portal', `<span class="mono">${esc(s.controlPlane)}</span>`],
    ['Agent', `${esc(s.agentName || '—')} <span class="dim mono">${esc(s.agentId || '')}</span>`],
    ['Version', esc(s.version)],
    ['Last contact', ago(s.lastContactAt)],
    ['Jobs', `${s.jobsDone} done, ${s.jobsFailed} failed`],
    ['Last job', job],
    ['Last error', s.lastError ? `${esc(s.lastError)}, ${ago(s.lastErrorAt)}` : 'none'],
    ['Running since', ago(s.startedAt)],
  ].map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join('');

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>CertPortal Agent — ${esc(title)}</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --text:#1c2230; --dim:#6b7280; --line:#e5e7eb; --ok:#15803d; --warn:#b45309; --bad:#b91c1c; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1115; --card:#181b22; --text:#e6e8ee; --dim:#9aa3b2; --line:#2a2f3a; --ok:#4ade80; --warn:#fbbf24; --bad:#f87171; } }
  body { margin:0; background:var(--bg); color:var(--text); font:15px/1.5 system-ui, "Segoe UI", sans-serif; }
  main { max-width:640px; margin:40px auto; padding:0 16px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:20px 24px; }
  h1 { font-size:14px; font-weight:600; color:var(--dim); margin:0 0 12px; letter-spacing:.02em; }
  .state { display:flex; align-items:center; gap:10px; font-size:22px; font-weight:650; }
  .dot { width:12px; height:12px; border-radius:50%; background:var(--${tone}); box-shadow:0 0 0 4px color-mix(in srgb, var(--${tone}) 20%, transparent); }
  .detail { color:var(--dim); margin:4px 0 16px 22px; }
  table { width:100%; border-collapse:collapse; }
  th, td { text-align:left; padding:8px 0; border-top:1px solid var(--line); vertical-align:top; }
  th { width:130px; color:var(--dim); font-weight:500; }
  .mono { font-family:ui-monospace, Consolas, monospace; font-size:13px; }
  .dim { color:var(--dim); font-size:13px; }
  footer { color:var(--dim); font-size:12px; margin-top:12px; }
</style></head>
<body><main>
  <div class="card">
    <h1>CERTPORTAL AGENT</h1>
    <div class="state"><span class="dot"></span>${esc(title)}</div>
    <div class="detail">${esc(detail)}</div>
    <table>${rows}</table>
  </div>
  <footer>Updates every 5 seconds. Shown only on this machine.</footer>
</main></body></html>`;
}

// Loopback only. The Host check stops a web page from reading this through
// DNS rebinding; there is nothing to change here, only to read.
function startStatusServer(status, port) {
  const allowedHosts = new Set([`127.0.0.1:${port}`, `localhost:${port}`, `[::1]:${port}`]);
  const server = http.createServer((req, res) => {
    const headers = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY' };
    if (!allowedHosts.has(String(req.headers.host).toLowerCase())) { res.writeHead(403, headers); return res.end(); }
    if (req.method !== 'GET') { res.writeHead(405, headers); return res.end(); }
    const s = status.snapshot();
    if (req.url === '/status.json') {
      res.writeHead(200, { ...headers, 'content-type': 'application/json' });
      return res.end(JSON.stringify(s, null, 2));
    }
    if (req.url === '/' || req.url.startsWith('/?')) {
      res.writeHead(200, { ...headers, 'content-type': 'text/html; charset=utf-8' });
      return res.end(page(s));
    }
    res.writeHead(404, headers); res.end();
  });
  server.on('error', (err) => console.warn(`[agent] status page unavailable on 127.0.0.1:${port}: ${err.message}`));
  server.listen(port, '127.0.0.1', () => console.log(`[agent] status page at http://127.0.0.1:${port}/`));
  server.unref();
  return server;
}

module.exports = { createStatus, startStatusServer };
