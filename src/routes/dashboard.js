'use strict';

const express = require('express');
const { query } = require('../db/pool');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const certs = await query(`
      SELECT c.*, d.fqdn,
        extract(epoch FROM (c.not_after - now()))/86400.0 AS days_left,
        (SELECT count(*) FROM deployments dep WHERE dep.certificate_id = c.id)::int AS fw_count,
        c.not_before + (c.not_after - c.not_before) * ($2 / 100.0) AS renew_at
      FROM certificates c JOIN domains d ON d.id = c.domain_id
      WHERE c.org_id = $1 ORDER BY c.not_after ASC NULLS LAST`,
      [req.orgId, req.org.renewal_percent]);

    const failures = await query(`
      SELECT a.action, a.detail, a.created_at FROM audit_log a
      WHERE a.org_id = $1 AND a.action IN ('cert.renewal_failed','cert.deploy_failed')
      ORDER BY a.id DESC LIMIT 10`, [req.orgId]);

    const counts = { total: certs.rows.length, red: 0, yellow: 0, green: 0, failed: 0 };
    for (const c of certs.rows) {
      if (c.status === 'failed') counts.failed++;
      if (c.days_left === null || c.days_left === undefined) continue;
      if (c.days_left < 7) counts.red++;
      else if (c.days_left < 15) counts.yellow++;
      else counts.green++;
    }

    const domainsUnverified = await query(
      `SELECT count(*)::int AS n FROM domains WHERE org_id = $1 AND NOT ownership_verified`, [req.orgId]);

    res.render('dashboard/index', {
      title: 'Dashboard',
      certs: certs.rows,
      failures: failures.rows,
      counts,
      unverifiedDomains: domainsUnverified.rows[0].n,
    });
  } catch (err) { next(err); }
});

module.exports = router;
