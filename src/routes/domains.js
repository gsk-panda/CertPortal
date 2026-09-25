'use strict';

const crypto = require('crypto');
const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite, scopedRow } = require('../middleware/auth');
const { verifyDomain, verificationRecordName } = require('../services/domainVerify');
const { AcmeDnsCnameProvider } = require('../services/dns/providers/acmedns');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { config } = require('../config');
const { checkLimit } = require('../services/billing/entitlements');

const router = express.Router();

const FQDN_RE = /^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$/i;

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT d.*, p.label AS provider_label, p.type AS provider_type
       FROM domains d LEFT JOIN dns_providers p ON p.id = d.dns_provider_id
       WHERE d.org_id = $1 ORDER BY d.fqdn`, [req.orgId]);
    res.render('domains/list', {
      title: 'Domains',
      domains: rows,
      acmeDnsZone: config.acmeDns.zone,
      reverifyDays: config.domainReverifyDays,
    });
  } catch (err) { next(err); }
});

router.get('/new', requireOrgWrite, async (req, res, next) => {
  try {
    const providers = await query('SELECT id, label, type FROM dns_providers WHERE org_id = $1 ORDER BY label', [req.orgId]);
    res.render('domains/form', { title: 'Add domain', providers: providers.rows });
  } catch (err) { next(err); }
});

router.post('/', requireOrgWrite,
  validateBody(z.object({
    fqdn: z.string().trim().toLowerCase().regex(FQDN_RE, 'must be a valid FQDN (no wildcard here — wildcards are chosen at certificate creation)'),
    dns_provider_id: z.string().uuid(),
    _csrf: z.string(),
  })),
  async (req, res, next) => {
    try {
      const lim = await checkLimit(req, 'domains');
      if (!lim.ok) {
        req.session.flash = { type: 'error', message: `Your ${lim.plan.label} plan includes ${lim.limit} domain(s). Upgrade on the Billing page to add more.` };
        return res.redirect('/billing');
      }
      const provider = await scopedRow(req, 'dns_providers', req.body.dns_provider_id);
      if (!provider) {
        req.session.flash = { type: 'error', message: 'Unknown DNS provider.' };
        return res.redirect('/domains/new');
      }
      const token = 'certportal-' + crypto.randomBytes(24).toString('hex');
      const acmeDnsSub = provider.type === 'acme_dns_cname' ? crypto.randomUUID() : null;
      const { rows } = await query(
        `INSERT INTO domains (org_id, fqdn, dns_provider_id, verification_token, acme_dns_subdomain)
         VALUES ($1,$2,$3,$4,$5) RETURNING id`,
        [req.orgId, req.body.fqdn, provider.id, token, acmeDnsSub]
      );
      await auditReq(req, 'domain.created', 'domain', rows[0].id, { fqdn: req.body.fqdn, provider: provider.label });
      res.redirect(`/domains/${rows[0].id}`);
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'That domain is already registered in this organization.' };
        return res.redirect('/domains/new');
      }
      next(err);
    }
  });

router.get('/:id', async (req, res, next) => {
  try {
    const domain = await scopedRow(req, 'domains', req.params.id);
    if (!domain) return res.status(404).render('error', { title: 'Not found', message: 'No such domain.', status: 404 });
    const provider = domain.dns_provider_id
      ? (await query('SELECT id, label, type FROM dns_providers WHERE id = $1 AND org_id = $2', [domain.dns_provider_id, req.orgId])).rows[0]
      : null;
    res.render('domains/detail', {
      title: domain.fqdn,
      domain,
      provider,
      recordName: verificationRecordName(domain.fqdn),
      acmeDnsZone: config.acmeDns.zone,
      cnameTarget: domain.acme_dns_subdomain ? `${domain.acme_dns_subdomain}.${config.acmeDns.zone}` : null,
      reverifyDays: config.domainReverifyDays,
    });
  } catch (err) { next(err); }
});

router.post('/:id/verify', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const domain = await scopedRow(req, 'domains', req.params.id);
    if (!domain) return res.status(404).render('error', { title: 'Not found', message: 'No such domain.', status: 404 });
    const result = await verifyDomain(domain);
    req.session.flash = result.ok
      ? { type: 'success', message: `Ownership of ${domain.fqdn} verified.` }
      : { type: 'error', message: `Verification failed: ${result.error}` };
    res.redirect(`/domains/${domain.id}`);
  } catch (err) { next(err); }
});

// CNAME delegation: check the client's one-time CNAME is in place
router.post('/:id/check-cname', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const domain = await scopedRow(req, 'domains', req.params.id);
    if (!domain || !domain.acme_dns_subdomain) {
      return res.status(404).render('error', { title: 'Not found', message: 'No CNAME delegation registered for this domain.', status: 404 });
    }
    const provider = new AcmeDnsCnameProvider({}, { orgId: req.orgId });
    const target = `${domain.acme_dns_subdomain}.${config.acmeDns.zone}`;
    const ok = await provider.checkCname(domain.fqdn, target);
    req.session.flash = ok
      ? { type: 'success', message: `CNAME is correct: _acme-challenge.${domain.fqdn} → ${target}` }
      : { type: 'error', message: `CNAME not found. Create: _acme-challenge.${domain.fqdn} CNAME ${target}` };
    res.redirect(`/domains/${domain.id}`);
  } catch (err) { next(err); }
});

router.post('/:id/delete', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM domains WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    if (rowCount) await auditReq(req, 'domain.deleted', 'domain', req.params.id);
    res.redirect('/domains');
  } catch (err) { next(err); }
});

module.exports = router;
