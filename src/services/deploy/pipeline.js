'use strict';

/**
 * Deployment orchestration (control-plane side).
 *
 * Gathers everything a deployment needs from the database, then hands the
 * firewall-touching work to `dispatch.runOp('deploy', …)`, which runs it either
 * directly (control plane → firewall) or on the assigned on-prem agent
 * (agent → firewall over the LAN). The actual import/commit/validate logic
 * lives in `services/panos/ops.js` so both paths are identical.
 *
 * Naming/rotation strategy: a fixed logical PAN-OS object name per deployment
 * (certportal-<sanitized-fqdn>); renewals re-import under the same name so
 * SSL/TLS Service Profiles never need editing.
 */

const { query } = require('../../db/pool');
const { decrypt } = require('../../crypto/envelope');
const { withHint } = require('../panos/hints');
const { validateServedCertificate, encryptKeyPem } = require('../panos/ops');
const { runOp } = require('../agent/dispatch');
const { audit } = require('../audit');
const { notifyOrg } = require('../notify');

function panosCertName(fqdn) {
  return ('certportal-' + fqdn.replace(/^\*\./, 'wildcard.').replace(/[^a-zA-Z0-9._-]/g, '-')).slice(0, 63);
}

/**
 * Run one deployment (a certificates×firewalls link row). Updates the row and
 * returns { ok, error? }. Routes direct or via agent transparently.
 */
async function runDeployment(deploymentId) {
  const { rows } = await query(
    `SELECT dep.*, c.cert_pem, c.chain_pem, c.key_pem_encrypted, c.serial AS cert_serial, c.org_id,
            f.name AS fw_name, f.mgmt_address, f.api_key_encrypted, f.verify_tls, f.partial_commit,
            f.api_username, f.ha_peer_address, f.agent_id
     FROM deployments dep
     JOIN certificates c ON c.id = dep.certificate_id
     JOIN firewalls f ON f.id = dep.firewall_id
     WHERE dep.id = $1`,
    [deploymentId]
  );
  if (!rows.length) throw new Error('deployment not found');
  const d = rows[0];
  if (!d.cert_pem || !d.key_pem_encrypted) throw new Error('certificate has not been issued yet');

  const setStatus = (status, extra = {}) => {
    const sets = ['status = $2'];
    const vals = [deploymentId, status];
    let i = 3;
    for (const [k, v] of Object.entries(extra)) { sets.push(`${k} = $${i++}`); vals.push(v); }
    return query(`UPDATE deployments SET ${sets.join(', ')} WHERE id = $1`, vals);
  };

  try {
    await setStatus('importing', { last_error: null });

    const firewall = {
      agent_id: d.agent_id, org_id: d.org_id, mgmt_address: d.mgmt_address,
      verify_tls: d.verify_tls, api_key_encrypted: d.api_key_encrypted,
    };
    const result = await runOp(firewall, 'deploy', {
      panosCertName: d.panos_cert_name,
      certPem: d.cert_pem,
      chainPem: d.chain_pem || '',
      keyPem: decrypt(d.key_pem_encrypted),
      sslTlsProfile: d.ssl_tls_profile,
      gpPortal: d.gp_portal,
      gpGateway: d.gp_gateway,
      validateEndpoint: d.validate_endpoint,
      certSerial: d.cert_serial,
      partialCommit: d.partial_commit,
      apiUsername: d.api_username,
      haPeerAddress: d.ha_peer_address,
    });
    (result.log || []).forEach((line) => console.log(`[deploy] ${d.fw_name}: ${line}`));

    await setStatus('deployed', { deployed_at: new Date(), validation_ok: result.validationOk, commit_job_id: result.commitJobId });
    await query(`UPDATE certificates SET status = 'deployed' WHERE id = $1`, [d.certificate_id]);
    await query('UPDATE firewalls SET last_seen = now(), status = $2 WHERE id = $1', [d.firewall_id, 'ok']);
    await audit({
      orgId: d.org_id, action: 'cert.deployed', targetType: 'deployment', targetId: deploymentId,
      detail: { firewall: d.fw_name, panosCertName: d.panos_cert_name, commitJob: result.commitJobId, validationOk: result.validationOk, viaAgent: !!d.agent_id },
    });
    return { ok: true };
  } catch (err) {
    const detailed = withHint(err.message);
    await setStatus('failed', { last_error: detailed, validation_ok: false });
    await audit({
      orgId: d.org_id, action: 'cert.deploy_failed', targetType: 'deployment', targetId: deploymentId,
      detail: { firewall: d.fw_name, error: detailed, viaAgent: !!d.agent_id },
    });
    await notifyOrg(d.org_id, 'deployment_failure',
      `Deployment failed: ${d.panos_cert_name} → ${d.fw_name}`,
      `Deploying certificate ${d.panos_cert_name} to firewall ${d.fw_name} (${d.mgmt_address}) failed:\n\n${detailed}`);
    return { ok: false, error: detailed };
  }
}

/** Deploy a certificate to every linked firewall. Returns per-deployment results. */
async function deployCertificateEverywhere(certId) {
  const { rows } = await query('SELECT id FROM deployments WHERE certificate_id = $1', [certId]);
  const results = [];
  for (const row of rows) {
    results.push({ deploymentId: row.id, ...(await runDeployment(row.id)) });
  }
  return results;
}

module.exports = { runDeployment, deployCertificateEverywhere, panosCertName, validateServedCertificate, encryptKeyPem };
