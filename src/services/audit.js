'use strict';

const { query } = require('../db/pool');

const SECRET_KEYS = /(api[_-]?key|password|secret|token|credential|private|key_pem|passphrase)/i;

/** Deep-copy `detail` with values of secret-looking keys replaced. */
function redact(obj) {
  if (obj === null || obj === undefined) return obj;
  if (Array.isArray(obj)) return obj.map(redact);
  if (typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      out[k] = SECRET_KEYS.test(k) ? '[REDACTED]' : redact(v);
    }
    return out;
  }
  return obj;
}

/**
 * Append an audit event. Never throws (audit failure must not break the app),
 * but logs loudly.
 */
async function audit({ orgId = null, userId = null, action, targetType = null, targetId = null, detail = null, ip = null }) {
  try {
    await query(
      `INSERT INTO audit_log (org_id, user_id, action, target_type, target_id, detail, ip)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [orgId, userId, action, targetType, targetId ? String(targetId) : null,
       detail ? JSON.stringify(redact(detail)) : null, ip]
    );
  } catch (err) {
    console.error('[audit] failed to write audit event:', action, err.message);
  }
}

/** Express helper: audit using the request's user/org/ip. */
function auditReq(req, action, targetType, targetId, detail) {
  return audit({
    orgId: (req.session && req.session.user && req.session.user.orgId) || req.orgId || null,
    userId: (req.session && req.session.user && req.session.user.id) || null,
    action, targetType, targetId, detail,
    ip: req.ip,
  });
}

module.exports = { audit, auditReq, redact };
