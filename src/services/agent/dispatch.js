'use strict';

/**
 * Route a PAN-OS operation either directly (control plane → firewall) or via an
 * on-prem agent, transparently. Callers don't care which — they get the result.
 */

const { decrypt } = require('../../crypto/envelope');
const { executeOp } = require('../panos/ops');
const agent = require('./service');

/** Low-level: run an op with explicit routing. */
async function runOpRaw({ agentId, orgId, op, mgmtAddress, verifyTls, apiKey = null, params = {} }) {
  const payload = { op, mgmtAddress, verifyTls, apiKey, params };
  if (agentId) {
    const jobId = await agent.enqueue(agentId, orgId, op, payload);
    return agent.awaitResult(jobId);
  }
  return executeOp(payload);
}

/** Run an op for an existing firewall row (decrypts its stored API key). */
async function runOp(firewall, op, params = {}) {
  return runOpRaw({
    agentId: firewall.agent_id || null,
    orgId: firewall.org_id,
    op,
    mgmtAddress: firewall.mgmt_address,
    verifyTls: firewall.verify_tls,
    apiKey: op === 'keygen' ? null : decrypt(firewall.api_key_encrypted),
    params,
  });
}

module.exports = { runOp, runOpRaw };
