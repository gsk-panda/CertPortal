'use strict';

/**
 * Renewal engine.
 *
 * Hourly sweep (node-cron):
 *   - due = auto_renew certs past their org's renewal threshold
 *     (default 66% of lifetime elapsed → ~day 31 of a 47-day cert)
 *   - failed certs are retried on an exponential backoff schedule
 *     (1h, 4h, 12h, 24h, then daily)
 *   - concurrency-safe: a Postgres advisory lock serializes the sweep
 *     across app instances, and each cert is claimed with
 *     SELECT ... FOR UPDATE SKIP LOCKED
 *   - notification on the 2nd consecutive failure
 * Also runs domain ownership re-verification and the
 * "expiring with no automation path" check.
 */

const cron = require('node-cron');
const { pool, query } = require('../../db/pool');
const { config } = require('../../config');
const { issueCertificate } = require('../acme/service');
const { deployCertificateEverywhere } = require('../deploy/pipeline');
const { reverifySweep } = require('../domainVerify');
const { notifyOrg } = require('../notify');
const { audit } = require('../audit');

const SWEEP_LOCK = 727002;
const BACKOFF_HOURS = [1, 4, 12, 24]; // then daily

function backoffHours(failures) {
  return BACKOFF_HOURS[Math.min(Math.max(failures - 1, 0), BACKOFF_HOURS.length - 1)];
}

/**
 * Certs due for renewal:
 *  - healthy certs past the org renewal threshold
 *  - failed certs whose backoff delay has elapsed
 * Domain must still be ownership-verified (lapsed verification pauses renewal).
 */
const DUE_SQL = `
  SELECT c.id
  FROM certificates c
  JOIN organizations o ON o.id = c.org_id
  JOIN domains d ON d.id = c.domain_id
  WHERE c.auto_renew
    AND o.status = 'active'
    AND d.ownership_verified
    AND c.status IN ('issued','deployed','failed','renewing')
    AND c.not_after IS NOT NULL
    AND now() >= c.not_before + (c.not_after - c.not_before) * (o.renewal_percent / 100.0)
    AND (
      c.renewal_failures = 0
      OR c.last_renewal_attempt IS NULL
      OR c.last_renewal_attempt + make_interval(hours =>
           (ARRAY[1,4,12,24])[least(greatest(c.renewal_failures,1),4)]) <= now()
    )
    -- stuck 'renewing' rows (e.g. app crash mid-renewal) become eligible after 2h
    AND (c.status <> 'renewing' OR coalesce(c.last_renewal_attempt, c.created_at) + interval '2 hours' <= now())
  ORDER BY c.not_after ASC
  FOR UPDATE OF c SKIP LOCKED
  LIMIT 20
`;

/** Renew one certificate: issue → deploy everywhere. Handles state + notifications. */
async function renewCertificate(certId, { trigger = 'scheduled' } = {}) {
  const before = (await query('SELECT * FROM certificates WHERE id = $1', [certId])).rows[0];
  if (!before) return { ok: false, error: 'certificate not found' };
  await query(
    `UPDATE certificates SET status = 'renewing', last_renewal_attempt = now() WHERE id = $1`,
    [certId]
  );
  try {
    await issueCertificate(certId);
    const results = await deployCertificateEverywhere(certId);
    const failed = results.filter((r) => !r.ok);
    if (failed.length) throw new Error(`deployment failed on ${failed.length}/${results.length} firewall(s): ${failed[0].error}`);
    if (!results.length) {
      // no linked firewalls: issuance alone is success
      await query(`UPDATE certificates SET status = 'issued' WHERE id = $1`, [certId]);
    }
    await notifyOrg(before.org_id, 'renewal_success',
      `Certificate renewed: ${(before.san_list || []).join(', ')}`,
      `Certificate ${(before.san_list || []).join(', ')} was renewed and deployed to ${results.length} firewall(s) (trigger: ${trigger}).`);
    return { ok: true };
  } catch (err) {
    const failures = (before.renewal_failures || 0) + 1;
    await query(
      `UPDATE certificates SET status = 'failed', renewal_failures = $2, last_error = $3 WHERE id = $1`,
      [certId, failures, err.message.slice(0, 1000)]
    );
    await audit({
      orgId: before.org_id, action: 'cert.renewal_failed', targetType: 'certificate', targetId: certId,
      detail: { error: err.message, consecutiveFailures: failures, trigger },
    });
    if (failures >= 2) {
      await notifyOrg(before.org_id, 'renewal_failure',
        `Renewal failing (${failures}x): ${(before.san_list || []).join(', ')}`,
        `Certificate ${(before.san_list || []).join(', ')} has failed to renew ${failures} consecutive times.\n\nLast error: ${err.message}\n\nNext retry in ~${backoffHours(failures)}h. It expires ${before.not_after}.`);
    }
    return { ok: false, error: err.message };
  }
}

/** One sweep pass. Returns number of certs processed. */
async function renewalSweep() {
  const lock = await query('SELECT pg_try_advisory_lock($1) AS got', [SWEEP_LOCK]);
  if (!lock.rows[0].got) {
    console.log('[renewal] another instance is sweeping; skipping');
    return 0;
  }
  try {
    let processed = 0;
    for (;;) {
      // claim a batch under the row locks, mark them, release the txn
      const client = await pool.connect();
      let ids;
      try {
        await client.query('BEGIN');
        ids = (await client.query(DUE_SQL)).rows.map((r) => r.id);
        if (ids.length) {
          await client.query(
            `UPDATE certificates SET status = 'renewing', last_renewal_attempt = now() WHERE id = ANY($1)`,
            [ids]
          );
        }
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      } finally {
        client.release();
      }
      if (!ids.length) break;
      for (const id of ids) {
        console.log(`[renewal] renewing certificate ${id}`);
        await renewCertificate(id);
        processed++;
      }
      if (ids.length < 20) break;
    }
    return processed;
  } finally {
    await query('SELECT pg_advisory_unlock($1)', [SWEEP_LOCK]);
  }
}

/** Warn orgs about certs that will expire but cannot auto-renew. */
async function expiringNoAutomationSweep() {
  const { rows } = await query(`
    SELECT c.id, c.org_id, c.san_list, c.not_after, c.auto_renew, d.ownership_verified, d.fqdn
    FROM certificates c JOIN domains d ON d.id = c.domain_id
    WHERE c.not_after IS NOT NULL
      AND c.not_after < now() + interval '14 days'
      AND c.not_after > now()
      AND (NOT c.auto_renew OR NOT d.ownership_verified)
      AND c.status <> 'revoked'`);
  for (const c of rows) {
    const reason = !c.auto_renew ? 'auto-renew is disabled' : `domain ${c.fqdn} ownership verification has lapsed`;
    await notifyOrg(c.org_id, 'cert_expiring_no_automation',
      `Certificate expiring with no automation path: ${(c.san_list || []).join(', ')}`,
      `Certificate ${(c.san_list || []).join(', ')} expires ${new Date(c.not_after).toISOString()} but will NOT auto-renew: ${reason}.`);
  }
  return rows.length;
}

let started = false;
function startScheduler() {
  if (started) return;
  started = true;
  cron.schedule(config.renewalCron, async () => {
    try {
      const n = await renewalSweep();
      if (n) console.log(`[renewal] sweep processed ${n} certificate(s)`);
      await reverifySweep();
    } catch (err) {
      console.error('[renewal] sweep error:', err.message);
    }
  });
  // daily: expiring-with-no-automation warnings
  cron.schedule('30 6 * * *', async () => {
    try { await expiringNoAutomationSweep(); } catch (err) {
      console.error('[renewal] expiry warning sweep error:', err.message);
    }
  });
  console.log(`[renewal] scheduler started (${config.renewalCron})`);
}

module.exports = { startScheduler, renewalSweep, renewCertificate, expiringNoAutomationSweep, backoffHours, DUE_SQL };
