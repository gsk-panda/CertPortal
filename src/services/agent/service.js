'use strict';

/**
 * Agent lifecycle + job queue (control-plane side).
 *
 * Trust model: an agent enrolls once with a one-time token and receives a
 * long-lived secret. Thereafter it authenticates every request with
 * `Authorization: Bearer <agentId>.<secret>`. All agent traffic is
 * agent-initiated (outbound), so nothing inbound to the customer network or
 * the firewall is ever required.
 */

const crypto = require('crypto');
const { pool, query } = require('../../db/pool');
const { encrypt, decrypt } = require('../../crypto/envelope');
const { audit } = require('../audit');

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

/** Create an agent record and return its one-time enrollment token. */
async function createAgent(orgId, name) {
  const token = crypto.randomBytes(24).toString('base64url');
  const { rows } = await query(
    `INSERT INTO agents (org_id, name, enrollment_token_hash) VALUES ($1,$2,$3) RETURNING id`,
    [orgId, name, sha256(token)]
  );
  await audit({ orgId, action: 'agent.created', targetType: 'agent', targetId: rows[0].id, detail: { name } });
  return { agentId: rows[0].id, enrollmentToken: token };
}

/** Exchange an enrollment token for a permanent agent secret. */
async function enroll({ token, version }) {
  const { rows } = await query('SELECT * FROM agents WHERE enrollment_token_hash = $1', [sha256(token)]);
  const agent = rows[0];
  if (!agent) throw new Error('invalid or already-used enrollment token');
  const secret = crypto.randomBytes(32).toString('base64url');
  await query(
    `UPDATE agents SET agent_secret_hash = $2, enrollment_token_hash = NULL,
       status = 'active', version = $3, last_seen = now() WHERE id = $1`,
    [agent.id, sha256(secret), version || null]
  );
  await audit({ orgId: agent.org_id, action: 'agent.enrolled', targetType: 'agent', targetId: agent.id, detail: { version } });
  return { agentId: agent.id, agentSecret: secret };
}

/** Authenticate a `Bearer <agentId>.<secret>` header; returns the agent row or null. */
async function authenticate(header) {
  if (!header || !header.startsWith('Bearer ')) return null;
  const raw = header.slice(7);
  const dot = raw.indexOf('.');
  if (dot === -1) return null;
  const agentId = raw.slice(0, dot);
  const secret = raw.slice(dot + 1);
  if (!/^[0-9a-f-]{36}$/i.test(agentId)) return null;
  const { rows } = await query('SELECT * FROM agents WHERE id = $1', [agentId]);
  const agent = rows[0];
  if (!agent || !agent.agent_secret_hash) return null;
  const a = Buffer.from(agent.agent_secret_hash);
  const b = Buffer.from(sha256(secret));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  return agent;
}

async function touch(agentId, version) {
  await query(`UPDATE agents SET last_seen = now(), status = 'active', version = COALESCE($2, version) WHERE id = $1`,
    [agentId, version || null]);
}

/** Enqueue a job for an agent. Payload is envelope-encrypted at rest. */
async function enqueue(agentId, orgId, op, payload) {
  const { rows } = await query(
    `INSERT INTO agent_jobs (agent_id, org_id, op, payload_encrypted)
     VALUES ($1,$2,$3,$4) RETURNING id`,
    [agentId, orgId, op, encrypt(JSON.stringify(payload))]
  );
  return rows[0].id;
}

/** Atomically lease the next queued job for an agent (or null). */
async function leaseNext(agentId) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `SELECT id, op, payload_encrypted FROM agent_jobs
       WHERE agent_id = $1 AND status = 'queued'
       ORDER BY created_at ASC FOR UPDATE SKIP LOCKED LIMIT 1`,
      [agentId]
    );
    if (!rows.length) { await client.query('COMMIT'); return null; }
    await client.query(`UPDATE agent_jobs SET status = 'leased', leased_at = now() WHERE id = $1`, [rows[0].id]);
    await client.query('COMMIT');
    return { id: rows[0].id, op: rows[0].op, payload: JSON.parse(decrypt(rows[0].payload_encrypted)) };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** Record a job result from the agent. Only the owning agent may complete it. */
async function complete(agentId, jobId, { status, result = null, error = null }) {
  const ok = status === 'done';
  const { rowCount } = await query(
    `UPDATE agent_jobs SET status = $3, result = $4, error = $5, completed_at = now(),
       payload_encrypted = NULL   -- drop any secrets once the job is finished
     WHERE id = $1 AND agent_id = $2 AND status = 'leased'`,
    [jobId, agentId, ok ? 'done' : 'failed', result ? JSON.stringify(result) : null, error]
  );
  return rowCount > 0;
}

/** Control-plane side: wait for a job to finish. Returns { result } or throws. */
async function awaitResult(jobId, { timeoutMs = 40000, pollMs = 400 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const { rows } = await query('SELECT status, result, error FROM agent_jobs WHERE id = $1', [jobId]);
    if (!rows.length) throw new Error('job disappeared');
    const j = rows[0];
    if (j.status === 'done') return j.result;
    if (j.status === 'failed') throw new Error(j.error || 'agent job failed');
    if (Date.now() > deadline) {
      await query(`UPDATE agent_jobs SET status = 'failed', error = 'timeout', payload_encrypted = NULL WHERE id = $1 AND status IN ('queued','leased')`, [jobId]);
      throw new Error('agent did not respond in time (is it running and enrolled?)');
    }
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

module.exports = {
  createAgent, enroll, authenticate, touch,
  enqueue, leaseNext, complete, awaitResult,
};
