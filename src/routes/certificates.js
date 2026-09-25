'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite, scopedRow } = require('../middleware/auth');
const { issueCertificate } = require('../services/acme/service');
const { deployCertificateEverywhere, runDeployment, panosCertName } = require('../services/deploy/pipeline');
const { renewCertificate } = require('../services/renewal/engine');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { checkLimit } = require('../services/billing/entitlements');

const router = express.Router();

// crude registrable-domain heuristic for Let's Encrypt rate-limit tracking
const SECOND_LEVEL = new Set(['co.uk', 'org.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'co.za', 'co.in']);
function registeredDomain(fqdn) {
  const parts = fqdn.replace(/^\*\./, '').split('.');
  if (parts.length <= 2) return parts.join('.');
  const lastTwo = parts.slice(-2).join('.');
  return SECOND_LEVEL.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

async function weeklyIssuanceCount(orgId, fqdn) {
  const reg = registeredDomain(fqdn);
  const { rows } = await query(
    `SELECT count(*)::int AS n FROM certificates c JOIN domains d ON d.id = c.domain_id
     WHERE c.org_id = $1 AND c.not_before > now() - interval '7 days'
       AND (d.fqdn = $2 OR d.fqdn LIKE '%' || $2)`,
    [orgId, reg]
  );
  return { registeredDomain: reg, count: rows[0].n };
}

/** Background issue → deploy. Errors land on the cert row for the UI. */
function issueAndDeployAsync(certId, orgId) {
  (async () => {
    try {
      await query(`UPDATE certificates SET last_renewal_attempt = now() WHERE id = $1`, [certId]);
      await issueCertificate(certId);
      const results = await deployCertificateEverywhere(certId);
      const failed = results.filter((r) => !r.ok);
      if (failed.length) {
        await query(`UPDATE certificates SET status = 'failed', last_error = $2, renewal_failures = renewal_failures + 1 WHERE id = $1`,
          [certId, `deployment failed: ${failed[0].error}`.slice(0, 1000)]);
      } else if (!results.length) {
        await query(`UPDATE certificates SET status = 'issued' WHERE id = $1`, [certId]);
      }
    } catch (err) {
      console.error(`[cert] issuance of ${certId} failed:`, err.message);
      await query(
        `UPDATE certificates SET status = 'failed', last_error = $2, renewal_failures = renewal_failures + 1 WHERE id = $1`,
        [certId, err.message.slice(0, 1000)]
      ).catch(() => {});
    }
  })();
}

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT c.*, d.fqdn, extract(epoch FROM (c.not_after - now()))/86400.0 AS days_left,
              (SELECT count(*) FROM deployments dep WHERE dep.certificate_id = c.id)::int AS fw_count
       FROM certificates c JOIN domains d ON d.id = c.domain_id
       WHERE c.org_id = $1 ORDER BY c.created_at DESC`, [req.orgId]);
    res.render('certs/list', { title: 'Certificates', certs: rows });
  } catch (err) { next(err); }
});

router.get('/new', requireOrgWrite, async (req, res, next) => {
  try {
    const domains = await query(
      `SELECT d.*, p.type AS provider_type, p.label AS provider_label
       FROM domains d LEFT JOIN dns_providers p ON p.id = d.dns_provider_id
       WHERE d.org_id = $1 ORDER BY d.fqdn`, [req.orgId]);
    const firewalls = await query('SELECT id, name, mgmt_address, status FROM firewalls WHERE org_id = $1 ORDER BY name', [req.orgId]);
    // rate-limit heads-up per registered domain
    const warnings = [];
    for (const d of domains.rows.filter((r) => r.ownership_verified)) {
      const { registeredDomain: reg, count } = await weeklyIssuanceCount(req.orgId, d.fqdn);
      if (count >= 40 && !warnings.some((w) => w.reg === reg)) {
        warnings.push({ reg, count });
      }
    }
    res.render('certs/new', { title: 'New certificate', domains: domains.rows, firewalls: firewalls.rows, warnings });
  } catch (err) { next(err); }
});

router.post('/', requireOrgWrite,
  validateBody(z.object({
    domain_id: z.string().uuid(),
    sans: z.string().max(2000).optional().or(z.literal('')),
    wildcard: z.string().optional(),
    key_type: z.enum(['ecdsa_p256', 'rsa_2048']).default('ecdsa_p256'),
    firewall_ids: z.union([z.array(z.string().uuid()), z.string().uuid()]).optional(),
    ssl_tls_profile: z.string().trim().max(120).optional().or(z.literal('')),
    gp_portal: z.string().trim().max(120).optional().or(z.literal('')),
    gp_gateway: z.string().trim().max(120).optional().or(z.literal('')),
    validate_endpoint: z.string().trim().max(260).optional().or(z.literal('')),
    _csrf: z.string(),
  })),
  async (req, res, next) => {
    try {
      const lim = await checkLimit(req, 'certificates');
      if (!lim.ok) {
        req.session.flash = { type: 'error', message: `Your ${lim.plan.label} plan includes ${lim.limit} certificate(s). Upgrade on the Billing page to add more.` };
        return res.redirect('/billing');
      }
      const domain = await scopedRow(req, 'domains', req.body.domain_id);
      if (!domain) {
        req.session.flash = { type: 'error', message: 'Unknown domain.' };
        return res.redirect('/certificates/new');
      }
      if (!domain.ownership_verified) {
        req.session.flash = { type: 'error', message: `Domain ${domain.fqdn} must pass ownership verification before certificates can be requested.` };
        return res.redirect('/certificates/new');
      }

      // Build SAN list: base (or wildcard) + extra SANs limited to the verified domain's scope
      const sans = [];
      if (req.body.wildcard === 'on') sans.push(`*.${domain.fqdn}`);
      sans.push(domain.fqdn);
      const extra = (req.body.sans || '').split(/[\s,]+/).map((s) => s.trim().toLowerCase()).filter(Boolean);
      for (const s of extra) {
        const bare = s.replace(/^\*\./, '');
        if (bare !== domain.fqdn && !bare.endsWith('.' + domain.fqdn)) {
          req.session.flash = { type: 'error', message: `SAN ${s} is outside the verified domain ${domain.fqdn}.` };
          return res.redirect('/certificates/new');
        }
        if (!sans.includes(s)) sans.push(s);
      }

      const cert = await query(
        `INSERT INTO certificates (org_id, domain_id, san_list, key_type, status)
         VALUES ($1,$2,$3,$4,'pending') RETURNING id`,
        [req.orgId, domain.id, JSON.stringify(sans), req.body.key_type]
      );
      const certId = cert.rows[0].id;

      const fwIds = [].concat(req.body.firewall_ids || []);
      for (const fwId of fwIds) {
        const fw = await scopedRow(req, 'firewalls', fwId);
        if (!fw) continue; // ignore ids outside the org
        await query(
          `INSERT INTO deployments (certificate_id, firewall_id, panos_cert_name, ssl_tls_profile, gp_portal, gp_gateway, validate_endpoint)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
          [certId, fw.id, panosCertName(sans[0]), req.body.ssl_tls_profile || null,
           req.body.gp_portal || null, req.body.gp_gateway || null, req.body.validate_endpoint || null]
        );
      }

      await auditReq(req, 'cert.requested', 'certificate', certId, { sans, keyType: req.body.key_type, firewalls: fwIds.length });
      issueAndDeployAsync(certId, req.orgId);
      req.session.flash = { type: 'success', message: 'Certificate requested — issuance is running.' };
      res.redirect(`/certificates/${certId}`);
    } catch (err) { next(err); }
  });

router.get('/:id', async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert) return res.status(404).render('error', { title: 'Not found', message: 'No such certificate.', status: 404 });
    const domain = (await query('SELECT * FROM domains WHERE id = $1', [cert.domain_id])).rows[0];
    const deployments = await query(
      `SELECT dep.*, f.name AS fw_name, f.mgmt_address FROM deployments dep
       JOIN firewalls f ON f.id = dep.firewall_id WHERE dep.certificate_id = $1 ORDER BY f.name`, [cert.id]);
    const timeline = await query(
      `SELECT action, detail, created_at FROM audit_log
       WHERE org_id = $1 AND ((target_type = 'certificate' AND target_id = $2) OR (target_type = 'deployment' AND target_id = ANY($3)))
       ORDER BY id DESC LIMIT 50`,
      [req.orgId, cert.id, deployments.rows.map((d) => String(d.id))]);
    res.render('certs/detail', {
      title: `Certificate — ${domain ? domain.fqdn : ''}`,
      cert, domain,
      deployments: deployments.rows,
      timeline: timeline.rows,
    });
  } catch (err) { next(err); }
});

// JSON status (UI polling + integration tests)
router.get('/:id/status.json', async (req, res) => {
  const cert = await scopedRow(req, 'certificates', req.params.id);
  if (!cert) return res.status(404).json({ error: 'not found' });
  const deployments = await query(
    'SELECT id, firewall_id, status, validation_ok, commit_job_id, last_error FROM deployments WHERE certificate_id = $1', [cert.id]);
  res.json({
    id: cert.id,
    status: cert.status,
    serial: cert.serial,
    not_before: cert.not_before,
    not_after: cert.not_after,
    last_error: cert.last_error,
    pending_challenges: cert.pending_challenges,
    deployments: deployments.rows,
  });
});

// manual DNS-01: operator confirms the TXT records exist
router.post('/:id/confirm-dns', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert) return res.status(404).render('error', { title: 'Not found', message: 'No such certificate.', status: 404 });
    await query('UPDATE certificates SET manual_confirmed_at = now() WHERE id = $1', [cert.id]);
    await auditReq(req, 'cert.manual_dns_confirmed', 'certificate', cert.id);
    req.session.flash = { type: 'success', message: 'Confirmed — checking propagation and continuing issuance.' };
    res.redirect(`/certificates/${cert.id}`);
  } catch (err) { next(err); }
});

router.post('/:id/renew', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert) return res.status(404).render('error', { title: 'Not found', message: 'No such certificate.', status: 404 });
    await auditReq(req, 'cert.manual_renew', 'certificate', cert.id);
    renewCertificate(cert.id, { trigger: 'manual' }); // background
    req.session.flash = { type: 'success', message: 'Renewal started.' };
    res.redirect(`/certificates/${cert.id}`);
  } catch (err) { next(err); }
});

router.post('/:id/redeploy', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert) return res.status(404).render('error', { title: 'Not found', message: 'No such certificate.', status: 404 });
    if (!cert.cert_pem) {
      req.session.flash = { type: 'error', message: 'Nothing to deploy — the certificate has not been issued yet.' };
      return res.redirect(`/certificates/${cert.id}`);
    }
    await auditReq(req, 'cert.manual_redeploy', 'certificate', cert.id);
    deployCertificateEverywhere(cert.id); // background
    req.session.flash = { type: 'success', message: 'Redeploy started on all linked firewalls.' };
    res.redirect(`/certificates/${cert.id}`);
  } catch (err) { next(err); }
});

router.post('/:id/deployments/:depId/run', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert) return res.status(404).render('error', { title: 'Not found', message: 'No such certificate.', status: 404 });
    const dep = (await query('SELECT id FROM deployments WHERE id = $1 AND certificate_id = $2', [req.params.depId, cert.id])).rows[0];
    if (!dep) return res.status(404).render('error', { title: 'Not found', message: 'No such deployment.', status: 404 });
    runDeployment(dep.id); // background
    req.session.flash = { type: 'success', message: 'Deployment started.' };
    res.redirect(`/certificates/${cert.id}`);
  } catch (err) { next(err); }
});

router.get('/:id/download/:what', async (req, res, next) => {
  try {
    const cert = await scopedRow(req, 'certificates', req.params.id);
    if (!cert || !cert.cert_pem) return res.status(404).render('error', { title: 'Not found', message: 'Certificate not available.', status: 404 });
    const fqdnSafe = (Array.isArray(cert.san_list) && cert.san_list[0] ? cert.san_list[0] : 'certificate').replace(/[^a-z0-9.-]/gi, '_');
    let body, name;
    if (req.params.what === 'cert') { body = cert.cert_pem; name = `${fqdnSafe}.crt`; }
    else if (req.params.what === 'chain') { body = cert.chain_pem || ''; name = `${fqdnSafe}.chain.crt`; }
    else if (req.params.what === 'fullchain') { body = [cert.cert_pem, cert.chain_pem].filter(Boolean).join('\n'); name = `${fqdnSafe}.fullchain.crt`; }
    else return res.status(404).render('error', { title: 'Not found', message: 'Unknown download.', status: 404 });
    res.setHeader('content-type', 'application/x-pem-file');
    res.setHeader('content-disposition', `attachment; filename="${name}"`);
    res.send(body);
  } catch (err) { next(err); }
});

router.post('/:id/delete', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM certificates WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    if (rowCount) await auditReq(req, 'cert.deleted', 'certificate', req.params.id);
    res.redirect('/certificates');
  } catch (err) { next(err); }
});

module.exports = router;
