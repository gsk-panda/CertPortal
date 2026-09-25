'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite, scopedRow } = require('../middleware/auth');
const { encrypt } = require('../crypto/envelope');
const { TYPES, providerFromRow } = require('../services/dns');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT p.id, p.type, p.label, p.created_at,
              (SELECT count(*) FROM domains d WHERE d.dns_provider_id = p.id)::int AS domain_count
       FROM dns_providers p WHERE p.org_id = $1 ORDER BY p.label`, [req.orgId]);
    res.render('dns/list', { title: 'DNS providers', providers: rows, types: TYPES });
  } catch (err) { next(err); }
});

router.get('/new', requireOrgWrite, (req, res) => {
  res.render('dns/form', { title: 'Add DNS provider', types: TYPES });
});

router.post('/', requireOrgWrite,
  validateBody(z.object({
    label: z.string().trim().min(1).max(80),
    type: z.enum(Object.keys(TYPES)),
    _csrf: z.string(),
  }).passthrough()),
  async (req, res, next) => {
    try {
      const def = TYPES[req.body.type];
      const creds = {};
      for (const f of def.fields) {
        const v = (req.body[`cred_${f.name}`] || '').trim();
        if (v) creds[f.name] = v;
      }
      const { rows } = await query(
        `INSERT INTO dns_providers (org_id, type, credentials_encrypted, label)
         VALUES ($1,$2,$3,$4) RETURNING id`,
        [req.orgId, req.body.type, def.fields.length ? encrypt(JSON.stringify(creds)) : null, req.body.label]
      );
      await auditReq(req, 'dns_provider.created', 'dns_provider', rows[0].id, { type: req.body.type, label: req.body.label });
      req.session.flash = { type: 'success', message: `DNS provider "${req.body.label}" added.` };
      res.redirect('/dns-providers');
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'A provider with that label already exists.' };
        return res.redirect('/dns-providers/new');
      }
      next(err);
    }
  });

router.post('/:id/test', validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const row = await scopedRow(req, 'dns_providers', req.params.id);
    if (!row) return res.status(404).render('error', { title: 'Not found', message: 'No such provider.', status: 404 });
    try {
      const provider = providerFromRow(row);
      const msg = await provider.test();
      req.session.flash = { type: 'success', message: `${row.label}: ${msg}` };
    } catch (err) {
      req.session.flash = { type: 'error', message: `${row.label}: test failed — ${err.message}` };
    }
    res.redirect('/dns-providers');
  } catch (err) { next(err); }
});

router.post('/:id/delete', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM dns_providers WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    if (rowCount) await auditReq(req, 'dns_provider.deleted', 'dns_provider', req.params.id);
    res.redirect('/dns-providers');
  } catch (err) { next(err); }
});

module.exports = router;
