'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');

const router = express.Router();

// Global dashboard: orgs + cert expiry overview
router.get('/', async (req, res, next) => {
  try {
    const orgs = await query(`
      SELECT o.*,
        (SELECT count(*) FROM users u WHERE u.org_id = o.id)::int AS user_count,
        (SELECT count(*) FROM certificates c WHERE c.org_id = o.id)::int AS cert_count,
        (SELECT count(*) FROM firewalls f WHERE f.org_id = o.id)::int AS firewall_count,
        (SELECT min(c.not_after) FROM certificates c WHERE c.org_id = o.id AND c.status IN ('issued','deployed')) AS next_expiry
      FROM organizations o ORDER BY o.created_at`);
    const expiring = await query(`
      SELECT c.id, c.san_list, c.not_after, c.status, c.renewal_failures, o.name AS org_name, o.id AS org_id
      FROM certificates c JOIN organizations o ON o.id = c.org_id
      WHERE c.not_after IS NOT NULL
      ORDER BY c.not_after ASC LIMIT 25`);
    res.render('admin/index', { title: 'Platform admin', orgs: orgs.rows, expiring: expiring.rows });
  } catch (err) { next(err); }
});

router.post('/orgs',
  validateBody(z.object({
    name: z.string().trim().min(2).max(120),
    contact_email: z.string().email().max(200),
    _csrf: z.string(),
  })),
  async (req, res, next) => {
    try {
      const { rows } = await query(
        `INSERT INTO organizations (name, contact_email) VALUES ($1,$2) RETURNING id`,
        [req.body.name, req.body.contact_email.toLowerCase()]
      );
      await auditReq(req, 'org.created', 'organization', rows[0].id, { name: req.body.name });
      req.session.flash = { type: 'success', message: `Organization "${req.body.name}" created.` };
      res.redirect('/admin');
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'An organization with that name already exists.' };
        return res.redirect('/admin');
      }
      next(err);
    }
  });

router.post('/orgs/:id/status',
  validateBody(z.object({ status: z.enum(['active', 'suspended']), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const { rowCount } = await query('UPDATE organizations SET status = $1 WHERE id = $2', [req.body.status, req.params.id]);
      if (rowCount) {
        await auditReq(req, req.body.status === 'suspended' ? 'org.suspended' : 'org.reactivated', 'organization', req.params.id);
      }
      res.redirect('/admin');
    } catch (err) { next(err); }
  });

// Enter an org (platform admin browsing a tenant). This is the ONLY place
// actingOrgId is set, and only after validating the org exists.
router.post('/orgs/:id/open', async (req, res, next) => {
  try {
    const { rows } = await query('SELECT id, name FROM organizations WHERE id = $1', [req.params.id]);
    if (!rows.length) return res.status(404).render('error', { title: 'Not found', message: 'No such organization.', status: 404 });
    req.session.actingOrgId = rows[0].id;
    await auditReq(req, 'org.opened_by_platform_admin', 'organization', rows[0].id);
    res.redirect('/dashboard');
  } catch (err) { next(err); }
});

router.post('/orgs/close', (req, res) => {
  delete req.session.actingOrgId;
  res.redirect('/admin');
});

// Global audit log
router.get('/audit', async (req, res, next) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
    const limit = 50;
    const { rows } = await query(`
      SELECT a.*, o.name AS org_name, u.email AS user_email
      FROM audit_log a
      LEFT JOIN organizations o ON o.id = a.org_id
      LEFT JOIN users u ON u.id = a.user_id
      ORDER BY a.id DESC LIMIT $1 OFFSET $2`, [limit, (page - 1) * limit]);
    res.render('audit/list', { title: 'Global audit log', entries: rows, page, global: true });
  } catch (err) { next(err); }
});

module.exports = router;
