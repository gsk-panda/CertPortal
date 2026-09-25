'use strict';

/**
 * Minimal PAN-OS XML API client.
 *
 * mgmtAddress may be "host", "host:port", or a full "https://host:port" URL
 * (scheme prefix mainly used by the embedded mock).
 */

const fs = require('fs');
const https = require('https');
const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const { config } = require('../../config');

// parseTagValue:false — serials/versions/job ids must stay strings (leading zeros!)
const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_', parseTagValue: false });

// Optional CA bundle (PEM) used to *authenticate* the firewall's management
// certificate when verify_tls is on — e.g. the firewall's own mgmt cert or an
// internal CA. Lets on-prem deployments enforce TLS instead of trusting blindly.
let _caCache;
function firewallCa() {
  if (_caCache !== undefined) return _caCache;
  _caCache = null;
  if (config.firewallCaBundle) {
    try { _caCache = fs.readFileSync(config.firewallCaBundle); }
    catch (err) { console.error('[panos] FIREWALL_CA_BUNDLE unreadable:', err.message); }
  }
  return _caCache;
}

function buildAgent(verifyTls) {
  const ca = verifyTls ? firewallCa() : null;
  return new https.Agent({ rejectUnauthorized: !!verifyTls, ca: ca || undefined });
}

// PAN-OS management API is HTTPS-only. Ignore any scheme the caller supplied
// (an http:// address would otherwise dial tcp/80, which mgmt interfaces block)
// and always connect over https.
function baseUrl(mgmtAddress) {
  const hostPort = String(mgmtAddress).trim().replace(/^\w+:\/\//i, '').replace(/\/+$/, '');
  return `https://${hostPort}`;
}

class PanosApiError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'PanosApiError';
    this.code = code;
  }
}

class PanosClient {
  constructor({ mgmtAddress, apiKey = null, verifyTls = true, timeoutMs = 20000 }) {
    this.base = baseUrl(mgmtAddress);
    this.apiKey = apiKey;
    this.http = axios.create({
      baseURL: this.base,
      timeout: timeoutMs,
      httpsAgent: buildAgent(verifyTls),
      validateStatus: () => true,
    });
  }

  parseResponse(xmlText) {
    let doc;
    try {
      doc = parser.parse(xmlText);
    } catch (err) {
      throw new PanosApiError(`Invalid XML from firewall: ${String(xmlText).slice(0, 200)}`);
    }
    const resp = doc.response;
    if (!resp) throw new PanosApiError(`Unexpected response: ${String(xmlText).slice(0, 200)}`);
    const status = resp['@_status'];
    if (status !== 'success') {
      const msg = extractMsg(resp) || 'unknown error';
      throw new PanosApiError(`PAN-OS API error: ${msg}`, resp['@_code']);
    }
    return resp;
  }

  async get(params) {
    const res = await this.http.get('/api/', { params: { key: this.apiKey, ...params } });
    if (res.status >= 500) throw new PanosApiError(`HTTP ${res.status} from firewall`);
    return this.parseResponse(res.data);
  }

  /** Generate an API key from one-time credentials. The password is never stored. */
  static async keygen({ mgmtAddress, username, password, verifyTls = true, timeoutMs = 20000 }) {
    const http = axios.create({
      baseURL: baseUrl(mgmtAddress),
      timeout: timeoutMs,
      httpsAgent: buildAgent(verifyTls),
      validateStatus: () => true,
    });
    const body = new URLSearchParams({ type: 'keygen', user: username, password }).toString();
    const res = await http.post('/api/', body, { headers: { 'content-type': 'application/x-www-form-urlencoded' } });
    const doc = parser.parse(res.data);
    if (!doc.response || doc.response['@_status'] !== 'success') {
      throw new PanosApiError(`keygen failed: ${extractMsg(doc.response) || 'invalid credentials'}`);
    }
    return String(doc.response.result.key);
  }

  /** show system info → { hostname, serial, swVersion } */
  async showSystemInfo() {
    const resp = await this.get({ type: 'op', cmd: '<show><system><info></info></system></show>' });
    const sys = resp.result && resp.result.system;
    if (!sys) throw new PanosApiError('show system info returned no <system> block');
    return {
      hostname: str(sys.hostname),
      serial: str(sys.serial),
      swVersion: str(sys['sw-version']),
      model: str(sys.model),
    };
  }

  /** HA state; returns { enabled, localState, peerAddress } */
  async showHaState() {
    try {
      const resp = await this.get({ type: 'op', cmd: '<show><high-availability><state></state></high-availability></show>' });
      const r = resp.result || {};
      if (str(r.enabled) !== 'yes') return { enabled: false };
      const group = r.group || {};
      const local = (group['local-info']) || {};
      const peer = (group['peer-info']) || {};
      return {
        enabled: true,
        localState: str(local.state) || 'unknown',
        peerAddress: str(peer['mgmt-ip'] || '').split('/')[0] || null,
      };
    } catch (err) {
      // Older PAN-OS returns an error when HA is not configured
      return { enabled: false };
    }
  }

  /**
   * Import a certificate + private key as a PAN-OS "keypair" object.
   * The file is PEM: cert, then chain, then the private key encrypted with
   * a one-time passphrase (PAN-OS decrypts it using the passphrase param).
   * Re-importing under the same name overwrites the object in place, so
   * SSL/TLS Service Profiles that reference it never need editing.
   */
  async importKeypair({ name, certPem, chainPem = '', keyPemEncrypted, passphrase }) {
    const fileContent = [certPem.trim(), (chainPem || '').trim(), keyPemEncrypted.trim()]
      .filter(Boolean).join('\n') + '\n';
    const boundary = '----certportal' + Math.random().toString(16).slice(2);
    const body = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\n` +
        `Content-Disposition: form-data; name="file"; filename="${name}.pem"\r\n` +
        'Content-Type: application/octet-stream\r\n\r\n'
      ),
      Buffer.from(fileContent),
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    const res = await this.http.post('/api/', body, {
      params: {
        type: 'import',
        category: 'keypair',
        'certificate-name': name,
        format: 'pem',
        passphrase,
        key: this.apiKey,
      },
      headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
      maxBodyLength: 10 * 1024 * 1024,
    });
    return this.parseResponse(res.data);
  }

  /** Set config: bind cert to an SSL/TLS service profile (shared or vsys1). */
  async setSslTlsProfileCert(profileName, certName) {
    const xpath = `/config/shared/ssl-tls-service-profile/entry[@name='${xmlAttrEscape(profileName)}']`;
    return this.get({ type: 'config', action: 'set', xpath, element: `<certificate>${xmlEscape(certName)}</certificate>` });
  }

  /** Bind an SSL/TLS profile to a GlobalProtect portal (vsys1). */
  async setGpPortalSslProfile(portalName, profileName) {
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-portal/entry[@name='${xmlAttrEscape(portalName)}']/portal-config`;
    return this.get({ type: 'config', action: 'set', xpath, element: `<ssl-tls-service-profile>${xmlEscape(profileName)}</ssl-tls-service-profile>` });
  }

  /** Bind an SSL/TLS profile to a GlobalProtect gateway (vsys1). */
  async setGpGatewaySslProfile(gatewayName, profileName) {
    const xpath = `/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/global-protect/global-protect-gateway/entry[@name='${xmlAttrEscape(gatewayName)}']/remote-user-tunnel-configs/entry[@name='default']`;
    return this.get({ type: 'config', action: 'set', xpath, element: `<ssl-tls-service-profile>${xmlEscape(profileName)}</ssl-tls-service-profile>` });
  }

  /**
   * Commit. When partial=true, scope to the API key's admin so other
   * admins' uncommitted changes are untouched. Returns the job id.
   */
  async commit({ partial = false, adminUser = null } = {}) {
    let cmd = '<commit></commit>';
    if (partial && adminUser) {
      cmd = `<commit><partial><admin><member>${xmlEscape(adminUser)}</member></admin></partial></commit>`;
    }
    const resp = await this.get({ type: 'commit', cmd });
    const result = resp.result || {};
    const jobId = result.job !== undefined ? String(result.job) : null;
    if (!jobId) {
      // "no changes to commit" is a success without a job
      return { jobId: null, message: extractMsg(resp) || 'no changes to commit' };
    }
    return { jobId };
  }

  /** Poll a commit job until FIN/FAIL. Returns { status, result, details }. */
  async waitForJob(jobId, { intervalMs = 2000, timeoutMs = 10 * 60 * 1000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const resp = await this.get({ type: 'op', cmd: `<show><jobs><id>${xmlEscape(String(jobId))}</id></jobs></show>` });
      const job = resp.result && resp.result.job;
      if (job) {
        const status = str(job.status);
        if (status === 'FIN') {
          return { status: 'FIN', result: str(job.result), details: str(job.details && job.details.line) };
        }
        if (status === 'FAIL') {
          return { status: 'FAIL', result: str(job.result) || 'FAIL', details: str(job.details && job.details.line) };
        }
      }
      if (Date.now() > deadline) return { status: 'TIMEOUT', result: 'timeout waiting for commit job' };
      await new Promise((r) => setTimeout(r, intervalMs));
    }
  }
}

function str(v) {
  if (v === undefined || v === null) return '';
  if (typeof v === 'object') return str(v['#text']);
  return String(v);
}

function extractMsg(resp) {
  if (!resp) return '';
  const m = resp.msg;
  if (!m) return resp.result && resp.result.msg ? str(resp.result.msg) : '';
  if (typeof m === 'object') return str(m.line || m);
  return String(m);
}

function xmlEscape(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function xmlAttrEscape(s) {
  return xmlEscape(s).replace(/'/g, '&apos;').replace(/"/g, '&quot;');
}

module.exports = { PanosClient, PanosApiError };
