'use strict';

/**
 * CertPortal on-prem agent.
 *
 * Runs inside the customer network. Connects OUTBOUND to the control plane,
 * long-polls for jobs, executes them against firewalls/Panorama over the LAN
 * using the shared PAN-OS ops, and returns results. Nothing inbound is ever
 * opened — not to the agent, not to the firewall.
 *
 * Config (env, or the config file — env wins):
 *   CONTROL_PLANE_URL   required, e.g. https://certportal.example
 *   ENROLL_TOKEN        one-time enrollment token (first run only)
 *   AGENT_NAME          informational
 *   AGENT_STATE_FILE    where to persist credentials (default <data dir>/agent.json)
 *   AGENT_CONFIG_FILE   JSON file holding any of these keys (default <data dir>/config.json)
 *   CONTROL_PLANE_INSECURE  "true" to skip TLS verify to the control plane (self-signed)
 *   FIREWALL_CA_BUNDLE  PEM to authenticate firewall mgmt certs (verify_tls)
 *   AGENT_STATUS_PORT   local status page on 127.0.0.1 (default 47801 on Windows,
 *                       off elsewhere; "off" disables)
 *
 * The data dir is /data (docker volume) or %ProgramData%\CertPortal\Agent on
 * Windows, where the MSI writes config.json via `certportal-agent configure`.
 *
 * Commands:
 *   (none)      run the agent
 *   configure   --url <u> [--token <t>] [--name <n>] [--insecure] — write the
 *               config file and lock its folder down (Windows installer uses this)
 *   purge       delete the data dir (Windows uninstaller uses this)
 *   set-recovery  make the Windows service restart after failures (installer)
 *   status      print the running agent's status (from its status page)
 *   --version   print the version
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const VERSION = require('./package.json').version;
const IS_WINDOWS = process.platform === 'win32';
const DATA_DIR = IS_WINDOWS
  ? path.join(process.env.ProgramData || 'C:\\ProgramData', 'CertPortal', 'Agent')
  : '/data';
const CONFIG_FILE = process.env.AGENT_CONFIG_FILE || path.join(DATA_DIR, 'config.json');
const CONFIG_KEYS = ['CONTROL_PLANE_URL', 'ENROLL_TOKEN', 'AGENT_NAME', 'AGENT_STATE_FILE',
  'CONTROL_PLANE_INSECURE', 'FIREWALL_CA_BUNDLE', 'AGENT_STATUS_PORT'];

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: 0o600 });
}

// On Windows the 0600 file mode is ignored, so the data folder's ACL is what
// protects the agent secret: SYSTEM + Administrators full, LocalService (the
// service account) modify, nothing inherited. SIDs avoid localized names.
function lockDownDataDir(dir, createdNow) {
  if (!IS_WINDOWS) return;
  // Take ownership first: ProgramData lets any user pre-create this folder.
  // If we just created it ourselves (as SYSTEM) nobody else can own it, so a
  // failure here is only fatal for a folder that already existed.
  try {
    run('icacls', [dir, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q']);
  } catch (err) {
    if (!createdNow) throw err;
    installerLog(`warning: ${err.message}`);
  }
  run('icacls', [dir, '/inheritance:r', '/grant:r',
    '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-19:(OI)(CI)M', '/T', '/C', '/Q']);
}

// The installer runs these commands with no console, where writing to stdout
// can itself fail, so they report to a log file instead and never inherit stdio.
// Only configure creates the data folder, so it can tell whether the folder
// existed before it (see lockDownDataDir); the other commands log only if it's there.
function installerLog(message, { create = true } = {}) {
  try {
    if (!create && !fs.existsSync(DATA_DIR)) return;
    const dir = path.join(DATA_DIR, 'logs');
    fs.mkdirSync(dir, { recursive: true });
    fs.appendFileSync(path.join(dir, 'installer.log'), `${new Date().toISOString()} ${message}\n`);
  } catch { /* nowhere left to report */ }
}

function run(cmd, args) {
  try {
    execFileSync(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  } catch (err) {
    const out = `${err.stdout || ''}${err.stderr || ''}`.trim();
    throw new Error(`${cmd} ${args.join(' ')} failed (${err.status ?? err.code}): ${out || err.message}`);
  }
}

function installerCommand(name, fn, opts) {
  try {
    fn();
    installerLog(`${name}: ok`, opts);
  } catch (err) {
    installerLog(`${name} failed: ${err.stack || err.message}`, opts);
    process.exitCode = 1;
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--insecure') out.insecure = true;
    else if (a.startsWith('--')) out[a.slice(2)] = argv[++i];
  }
  return out;
}

function configure(argv) {
  const args = parseArgs(argv);
  const current = readJson(CONFIG_FILE) || {};
  if (args.url) current.CONTROL_PLANE_URL = args.url;
  if (args.token) {
    // a new token means a fresh enrollment: drop any credentials from before
    current.ENROLL_TOKEN = args.token;
    fs.rmSync(current.AGENT_STATE_FILE || path.join(DATA_DIR, 'agent.json'), { force: true });
  }
  if (args.name) current.AGENT_NAME = args.name;
  if (args.insecure) current.CONTROL_PLANE_INSECURE = 'true';
  if (!current.CONTROL_PLANE_URL) throw new Error('--url is required');
  const dir = path.dirname(CONFIG_FILE);
  const createdNow = !fs.existsSync(dir);
  fs.mkdirSync(dir, { recursive: true });
  lockDownDataDir(dir, createdNow);
  writeJson(CONFIG_FILE, current);
}

// Service recovery: restart 10s after any failure, including a clean exit with
// an error code (failureflag), which is how WinSW reports the agent dying.
function setRecovery() {
  if (!IS_WINDOWS) throw new Error('set-recovery is only used by the Windows installer');
  run('sc.exe', ['failure', 'CertPortalAgent', 'reset=', '86400', 'actions=', 'restart/10000/restart/10000/restart/10000']);
  run('sc.exe', ['failureflag', 'CertPortalAgent', '1']);
}

// uninstall: remove the config, credentials and logs
function purge() {
  if (!IS_WINDOWS) throw new Error('purge is only used by the Windows uninstaller');
  fs.rmSync(DATA_DIR, { recursive: true, force: true });
}

// Config file values fill in anything not set in the environment. They go into
// process.env because the shared PAN-OS modules read their settings from there.
function loadConfig() {
  const file = readJson(CONFIG_FILE) || {};
  for (const key of CONFIG_KEYS) {
    if (process.env[key] === undefined && file[key] !== undefined && file[key] !== '') {
      process.env[key] = String(file[key]);
    }
  }
}

// the token is single-use; once enrolled, don't leave it lying around
function forgetEnrollToken() {
  const file = readJson(CONFIG_FILE);
  if (file && file.ENROLL_TOKEN) {
    delete file.ENROLL_TOKEN;
    try { writeJson(CONFIG_FILE, file); } catch (err) { console.warn(`[agent] could not update ${CONFIG_FILE}: ${err.message}`); }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function statusPort() {
  const v = String(process.env.AGENT_STATUS_PORT ?? (IS_WINDOWS ? '47801' : 'off')).toLowerCase();
  const port = parseInt(v, 10);
  return v === 'off' || !(port > 0) ? null : port;
}

async function printStatus() {
  loadConfig();
  const port = statusPort() || 47801;
  try {
    const res = await fetch(`http://127.0.0.1:${port}/status.json`);
    console.log(JSON.stringify(await res.json(), null, 2));
  } catch (err) {
    console.error(`agent not reachable on 127.0.0.1:${port} (${err.message}) — is the service running?`);
    process.exit(1);
  }
}

function agent() {
  loadConfig();
  const CONTROL_PLANE = (process.env.CONTROL_PLANE_URL || '').replace(/\/+$/, '');
  const STATE_FILE = process.env.AGENT_STATE_FILE || path.join(DATA_DIR, 'agent.json');
  if (!CONTROL_PLANE) { console.error(`CONTROL_PLANE_URL is required (env or ${CONFIG_FILE})`); process.exit(1); }

  const { executeOp } = require('../src/services/panos/ops');
  const { createStatus, startStatusServer } = require('./status');
  const status = createStatus({ version: VERSION, controlPlane: CONTROL_PLANE, agentName: process.env.AGENT_NAME || null });
  const port = statusPort();
  if (port) startStatusServer(status, port);

  // With a status page, stay up on a fatal error so the page can say what went
  // wrong (and the service doesn't restart-loop on a bad token); otherwise exit.
  function fatal(message) {
    console.error(`[agent] ${message}`);
    if (!port) process.exit(1);
    status.set({ phase: 'stopped' });
    status.error(message);
    setInterval(() => {}, 1 << 30);
  }

  // allow self-signed control-plane TLS when explicitly opted in
  if (String(process.env.CONTROL_PLANE_INSECURE).toLowerCase() === 'true') {
    https.globalAgent.options.rejectUnauthorized = false;
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

  // Network errors and 5xx are retried (the host may boot before its network is
  // up); a 4xx means the token is bad or already used, which retrying won't fix.
  async function enroll() {
    const token = process.env.ENROLL_TOKEN;
    if (!token) throw new Error('no saved credentials and ENROLL_TOKEN not set');
    status.set({ phase: 'enrolling' });
    let backoff = 1000;
    for (;;) {
      let res;
      try {
        res = await api('/api/agent/enroll', { method: 'POST', body: { token, version: VERSION } });
      } catch (err) {
        console.error(`[agent] enrollment: ${err.message}; retrying in ${Math.round(backoff / 1000)}s`);
        status.error(`can't reach CertPortal: ${err.cause?.message || err.message}`);
      }
      if (res && res.ok) {
        const creds = await res.json(); // { agentId, agentSecret }
        fs.mkdirSync(path.dirname(STATE_FILE), { recursive: true });
        writeJson(STATE_FILE, creds);
        forgetEnrollToken();
        console.log(`[agent] enrolled as ${creds.agentId}`);
        return creds;
      }
      if (res && res.status < 500) {
        throw new Error(`CertPortal rejected the enrollment token (HTTP ${res.status} ${await res.text()}). `
          + 'It may already be used; add a new agent in the portal and reinstall with its token.');
      }
      if (res) {
        console.error(`[agent] enrollment: HTTP ${res.status}; retrying in ${Math.round(backoff / 1000)}s`);
        status.error(`enrollment: CertPortal returned HTTP ${res.status}`);
      }
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 30000);
    }
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
    if (res.status === 401) throw Object.assign(new Error('unauthorized'), { reauth: true });
    if (!res.ok && res.status !== 204) throw new Error(`poll failed: HTTP ${res.status}`);
    status.contact();
    if (res.status === 204) return;                // idle

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
    status.job(job, outcome);
    await api(`/api/agent/jobs/${job.id}/result`, { method: 'POST', auth: bearer, body: outcome });
  }

  async function main() {
    let creds = readJson(STATE_FILE);
    if (!creds) creds = await enroll();
    const bearer = `${creds.agentId}.${creds.agentSecret}`;
    status.set({ phase: 'running', agentId: creds.agentId });
    console.log(`[agent] CertPortal agent ${VERSION} → ${CONTROL_PLANE} (agent ${creds.agentId})`);

    let backoff = 1000;
    for (;;) {
      try {
        await runOnce(bearer);
        backoff = 1000; // reset on success
      } catch (err) {
        if (err.reauth) return fatal('CertPortal rejected this agent\'s credentials (was it deleted in the portal?). Reinstall with a new enrollment token.');
        console.error(`[agent] ${err.message}; retrying in ${Math.round(backoff / 1000)}s`);
        status.error(err.cause?.message ? `can't reach CertPortal: ${err.cause.message}` : err.message);
        await sleep(backoff);
        backoff = Math.min(backoff * 2, 30000);
      }
    }
  }

  main().catch((err) => fatal(err.message));
}

const [cmd, ...rest] = process.argv.slice(2);
if (cmd === '--version' || cmd === 'version') console.log(VERSION);
else if (cmd === 'configure') installerCommand('configure', () => configure(rest));
else if (cmd === 'purge') purge(); // logging here would recreate the folder it just removed
else if (cmd === 'set-recovery') installerCommand('set-recovery', setRecovery, { create: false });
else if (cmd === 'status') printStatus();
else agent();
