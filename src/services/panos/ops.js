'use strict';

/**
 * Shared PAN-OS operation executor.
 *
 * A "payload" fully describes an operation against one firewall:
 *   { op, mgmtAddress, verifyTls, apiKey?, params? }
 *
 * The SAME function runs it whether we're the control plane talking to a
 * firewall directly, or the on-prem agent executing a leased job on the LAN.
 * This keeps direct-mode and agent-mode behaviour identical and makes adding
 * new operations a one-place change. Everything here must be runnable on the
 * agent (no DB, no control-plane-only deps).
 */

const crypto = require('crypto');
const tls = require('tls');
const { PanosClient } = require('./client');

/** Encrypt a PEM private key with a one-time passphrase for the PAN-OS import. */
function encryptKeyPem(keyPem, passphrase) {
  const keyObj = crypto.createPrivateKey(keyPem);
  return keyObj.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase });
}

/** Compare the TLS-served cert at host:port with the expected serial. */
function validateServedCertificate(endpoint, expectedSerial, { timeoutMs = 10000 } = {}) {
  const [host, portStr] = endpoint.split(':');
  const port = parseInt(portStr || '443', 10);
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs }, () => {
      const peer = socket.getPeerCertificate();
      socket.end();
      const norm = (s) => String(s || '').replace(/[:\s]/g, '').replace(/^0+/, '').toUpperCase();
      resolve({ ok: norm(peer.serialNumber) === norm(expectedSerial), servedSerial: peer.serialNumber });
    });
    socket.on('error', (err) => resolve({ ok: false, error: err.message }));
    socket.on('timeout', () => { socket.destroy(); resolve({ ok: false, error: 'TLS connection timed out' }); });
  });
}

/**
 * Full certificate deployment against one firewall: HA check → keypair import →
 * optional profile/portal/gateway bindings → commit → poll → post-deploy TLS
 * validation. Returns { commitJobId, validationOk, log }. Throws with step
 * context on failure. Runs identically on the control plane or an agent.
 */
async function executeDeploy({ mgmtAddress, verifyTls, apiKey, params }) {
  const p = params;
  const fw = new PanosClient({ mgmtAddress, apiKey, verifyTls });
  const log = [];

  if (p.haPeerAddress) {
    const ha = await fw.showHaState();
    if (ha.enabled) {
      log.push(`HA enabled (local=${ha.localState}); config sync propagates the cert to peer ${p.haPeerAddress}`);
      if (ha.localState && !/active/.test(ha.localState)) {
        log.push(`warning: local HA state "${ha.localState}" is not active`);
      }
    }
  }

  const passphrase = crypto.randomBytes(18).toString('base64url');
  const keyEncrypted = encryptKeyPem(p.keyPem, passphrase);
  await fw.importKeypair({
    name: p.panosCertName, certPem: p.certPem, chainPem: p.chainPem || '',
    keyPemEncrypted: keyEncrypted, passphrase,
  });

  if (p.sslTlsProfile) await fw.setSslTlsProfileCert(p.sslTlsProfile, p.panosCertName);
  if (p.gpPortal && p.sslTlsProfile) await fw.setGpPortalSslProfile(p.gpPortal, p.sslTlsProfile);
  if (p.gpGateway && p.sslTlsProfile) await fw.setGpGatewaySslProfile(p.gpGateway, p.sslTlsProfile);

  const commit = await fw.commit({ partial: p.partialCommit, adminUser: p.apiUsername });
  let commitJobId = commit.jobId || null;
  if (commit.jobId) {
    const job = await fw.waitForJob(commit.jobId);
    if (job.status !== 'FIN' || job.result !== 'OK') {
      throw new Error(`commit job ${commit.jobId} ${job.status}: ${job.details || job.result}`);
    }
  } else {
    log.push(commit.message || 'no changes to commit');
  }

  let validationOk = null;
  if (p.validateEndpoint) {
    const result = await validateServedCertificate(p.validateEndpoint, p.certSerial);
    validationOk = result.ok;
    if (!result.ok) {
      throw new Error(`post-deploy validation failed at ${p.validateEndpoint}: served serial ${result.servedSerial || 'n/a'} != expected ${p.certSerial}${result.error ? ` (${result.error})` : ''}`);
    }
  }
  return { commitJobId, validationOk, log };
}

async function executeOp(payload) {
  const { op, mgmtAddress, verifyTls = true, apiKey = null, params = {} } = payload;

  if (op === 'keygen') {
    const key = await PanosClient.keygen({
      mgmtAddress, username: params.username, password: params.password, verifyTls,
    });
    return { key };
  }

  if (op === 'deploy') {
    return executeDeploy({ mgmtAddress, verifyTls, apiKey, params });
  }

  const fw = new PanosClient({ mgmtAddress, apiKey, verifyTls });
  switch (op) {
    case 'system_info': {
      const info = await fw.showSystemInfo();
      const ha = await fw.showHaState();
      return { info, ha };
    }
    default:
      throw new Error(`unknown PAN-OS op: ${op}`);
  }
}

module.exports = { executeOp, executeDeploy, encryptKeyPem, validateServedCertificate };
