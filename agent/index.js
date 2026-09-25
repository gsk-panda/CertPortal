'use strict';

/**
 * CertPortal on-prem agent.
 *
 * Runs inside the customer network. Connects OUTBOUND to the control plane,
 * long-polls for jobs, executes them against firewalls/Panorama over the LAN
 * using the shared PAN-OS ops, and returns results. Nothing inbound is ever
 * opened — not to the agent, not to the firewall.
 *
 * Config (env):
 *   CONTROL_PLANE_URL   required, e.g. https://certportal.example
 *   ENROLL_TOKEN        one-time enrollment token (first run only)
 *   AGENT_NAME          informational
 *   AGENT_STATE_FILE    where to persist credentials (default /data/agent.json)
 *   CONTROL_PLANE_INSECURE  "true" to skip TLS verify to the control plane (self-signed)
 *   FIREWALL_CA_BUNDLE  PEM to authenticate firewall mgmt certs (verify_tls)
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { executeOp } = require('../src/services/panos/ops');

const CONTROL_PLANE = (process.env.CONTROL_PLANE_URL || '').replace(/\/+$/, '');
const STATE_FILE = process.env.AGENT_STATE_FILE || '/data/agent.json';
const VERSION = require('./package.json').version;

if (!CONTROL_PLANE) { console.error('CONTROL_PLANE_URL is required'); process.exit(1); }

// allow self-signed control-plane TLS when explicitly opted in
if (String(process.env.CONTROL_PLANE_INSECURE).toLowerCase() === 'true') {
  https.globalAgent.options.rejectUnauthorized = false;
}

function loadState() {
  try { return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8')); } catch { return null; }
}
function saveState(state) {
  fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
  fs.writeFileSync(STATE_FILE, JSON.stringify(state), { mode: 0o600 });
}

async function api(pathname, { method = 'GET', body, auth, timeoutMs = 30000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(CONTROL_PLANE + pathname, {
      method,
      headers: {
        'content-type': 'application/json',
        ...(auth ? { authorization: `Bearer ${auth}` } : {}),
        'x-agent-version': VERSION,
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: controller.signal,
    });
    return res;
  } finally { clearTimeout(t); }
}

async function enroll() {
  const token = process.env.ENROLL_TOKEN;
  if (!token) throw new Error('no saved credentials and ENROLL_TOKEN not set');
  const res = await api('/api/agent/enroll', { method: 'POST', body: { token, version: VERSION } });
  if (!res.ok) throw new Error(`enrollment failed: HTTP ${res.status} ${await res.text()}`);
  const creds = await res.json(); // { agentId, agentSecret }
  saveState(creds);
  console.log(`[agent] enrolled as ${creds.agentId}`);
  return creds;
}

async function runOnce(bearer) {
  // long-poll for a job
  let res;
  try {
    res = await api('/api/agent/jobs', { auth: bearer, timeoutMs: 35000 });
  } catch (err) {
    if (err.name === 'AbortError') return; // poll window elapsed; loop again
    throw err;
  }
  if (res.status === 204) return;                // idle
  if (res.status === 401) throw Object.assign(new Error('unauthorized'), { reauth: true });
  if (!res.ok) throw new Error(`poll failed: HTTP ${res.status}`);

  const { job } = await res.json();
  console.log(`[agent] job ${job.id} op=${job.op}`);
  let outcome;
  try {
    const result = await executeOp(job.payload);
    outcome = { status: 'done', result };
  } catch (err) {
    outcome = { status: 'failed', error: err.message };
    console.warn(`[agent] job ${job.id} failed: ${err.message}`);
  }
  await api(`/api/agent/jobs/${job.id}/result`, { method: 'POST', auth: bearer, body: outcome });
}

async function main() {
  let creds = loadState();
  if (!creds) creds = await enroll();
  const bearer = `${creds.agentId}.${creds.agentSecret}`;
  console.log(`[agent] CertPortal agent ${VERSION} → ${CONTROL_PLANE} (agent ${creds.agentId})`);

  let backoff = 1000;
  for (;;) {
    try {
      await runOnce(bearer);
      backoff = 1000; // reset on success
    } catch (err) {
      if (err.reauth) { console.error('[agent] credentials rejected — re-enroll required'); process.exit(1); }
      console.error(`[agent] ${err.message}; retrying in ${Math.round(backoff / 1000)}s`);
      await new Promise((r) => setTimeout(r, backoff));
      backoff = Math.min(backoff * 2, 30000);
    }
  }
}

main().catch((err) => { console.error('[agent] fatal:', err.message); process.exit(1); });
