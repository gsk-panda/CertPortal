'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite, scopedRow } = require('../middleware/auth');
const { encrypt, decrypt } = require('../crypto/envelope');
const { PanosClient } = require('../services/panos/client');
const { panosHint } = require('../services/panos/hints');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { config } = require('../config');
const { checkLimit } = require('../services/billing/entitlements');
const { runOp, runOpRaw } = require('../services/agent/dispatch');

/** Agents belonging to the org, for the firewall form's routing selector. */
async function orgAgents(orgId) {
  return (await query(`SELECT id, name, status FROM agents WHERE org_id = $1 ORDER BY name`, [orgId])).rows;
}

const router = express.Router();

// PAN-OS mgmt is HTTPS-only — store bare host[:port], never a scheme.
function normalizeMgmt(addr) {
  return String(addr || '').trim().replace(/^\w+:\/\//i, '').replace(/\/+$/, '');
}

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT id, name, mgmt_address, panos_version, serial, hostname, ha_peer_address,
              verify_tls, partial_commit, last_seen, status, created_at
       FROM firewalls WHERE org_id = $1 ORDER BY name`, [req.orgId]);
    res.render('firewalls/list', { title: 'Firewalls', firewalls: rows, portalPublicIp: config.portalPublicIp });
  } catch (err) { next(err); }
});

router.get('/new', requireOrgWrite, async (req, res, next) => {
  try {
    res.render('firewalls/form', { title: 'Add firewall', fw: null, portalPublicIp: config.portalPublicIp, agents: await orgAgents(req.orgId) });
  } catch (err) { next(err); }
});

const fwSchema = z.object({
  name: z.string().trim().min(1).max(80),
  mgmt_address: z.string().trim().min(1).max(255)
    .regex(/^(https?:\/\/)?[a-zA-Z0-9.:\-\[\]]+$/, 'hostname/IP (optionally host:port)'),
  auth_mode: z.enum(['api_key', 'credentials']),
  api_key: z.string().max(1024).optional().or(z.literal('')),
  username: z.string().max(120).optional().or(z.literal('')),
  password: z.string().max(500).optional().or(z.literal('')),
  ha_peer_address: z.string().trim().max(255).optional().or(z.literal('')),
  agent_id: z.string().uuid().optional().or(z.literal('')),
  verify_tls: z.string().optional(),
  partial_commit: z.string().optional(),
  _csrf: z.string(),
});

/** Resolve a submitted agent_id to one the org owns, or null (direct). */
async function resolveAgent(orgId, agentId) {
  if (!agentId) return null;
  const { rows } = await query('SELECT id FROM agents WHERE id = $1 AND org_id = $2', [agentId, orgId]);
  return rows.length ? rows[0].id : null;
}

router.post('/', requireOrgWrite, validateBody(fwSchema), async (req, res, next) => {
  try {
    const lim = await checkLimit(req, 'firewalls');
    if (!lim.ok) {
      req.session.flash = { type: 'error', message: `Your ${lim.plan.label} plan includes ${lim.limit} firewall(s). Upgrade on the Billing page to add more.` };
      return res.redirect('/billing');
    }
    const b = req.body;
    b.mgmt_address = normalizeMgmt(b.mgmt_address);
    const verifyTls = b.verify_tls === 'on';
    const agentId = await resolveAgent(req.orgId, b.agent_id);
    let apiKey = (b.api_key || '').trim();
    let apiUsername = (b.username || '').trim() || null;

    if (b.auth_mode === 'credentials') {
      if (!b.username || !b.password) {
        req.session.flash = { type: 'error', message: 'Username and password are required for keygen.' };
        return res.redirect('/firewalls/new');
      }
      // one-time keygen — runs on the agent when one is selected, else directly.
      // The password is used for this call only and never stored.
      const { key } = await runOpRaw({
        agentId, orgId: req.orgId, op: 'keygen',
        mgmtAddress: b.mgmt_address, verifyTls, params: { username: b.username, password: b.password },
      });
      apiKey = key;
    } else if (!apiKey) {
      req.session.flash = { type: 'error', message: 'Provide an API key or switch to username/password.' };
      return res.redirect('/firewalls/new');
    }

    const { rows } = await query(
      `INSERT INTO firewalls (org_id, name, mgmt_address, api_key_encrypted, ha_peer_address, verify_tls, partial_commit, api_username, agent_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
      [req.orgId, b.name, b.mgmt_address, encrypt(apiKey), b.ha_peer_address || null,
       verifyTls, b.partial_commit === 'on', apiUsername, agentId]
    );
    await auditReq(req, 'firewall.created', 'firewall', rows[0].id, { name: b.name, mgmt: b.mgmt_address, verifyTls });
    req.session.flash = { type: 'success', message: `Firewall "${b.name}" added. Run a connectivity test to confirm access.` };
    res.redirect('/firewalls');
  } catch (err) {
    if (err.code === '23505') {
      req.session.flash = { type: 'error', message: 'A firewall with that name already exists.' };
      return res.redirect('/firewalls/new');
    }
    if (err.name === 'PanosApiError' || err.code === 'ECONNREFUSED' || err.code === 'ETIMEDOUT' || /keygen/.test(err.message)) {
      req.session.flash = { type: 'error', message: `Could not generate API key: ${err.message}` };
      return res.redirect('/firewalls/new');
    }
    next(err);
  }
});

router.post('/:id/test', validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const fw = await scopedRow(req, 'firewalls', req.params.id);
    if (!fw) return res.status(404).render('error', { title: 'Not found', message: 'No such firewall.', status: 404 });
    try {
      // direct, or via the assigned agent — transparently
      const { info, ha } = await runOp(fw, 'system_info');
      await query(
        `UPDATE firewalls SET last_seen = now(), status = 'ok', hostname = $2, serial = $3, panos_version = $4,
           ha_peer_address = coalesce($5, ha_peer_address)
         WHERE id = $1`,
        [fw.id, info.hostname, info.serial, info.swVersion, ha.enabled ? ha.peerAddress : null]
      );
      await auditReq(req, 'firewall.test_ok', 'firewall', fw.id, { hostname: info.hostname, serial: info.serial, version: info.swVersion, ha: ha.enabled });
      req.session.flash = { type: 'success', message: `Connected: ${info.hostname} (${info.model || 'PAN-OS'} ${info.swVersion}, S/N ${info.serial})${ha.enabled ? ` — HA ${ha.localState}` : ''}` };
    } catch (err) {
      const authFail = /Invalid API key|403/i.test(err.message);
      await query(`UPDATE firewalls SET status = $2 WHERE id = $1`, [fw.id, authFail ? 'auth_failed' : 'unreachable']);
      await auditReq(req, 'firewall.test_failed', 'firewall', fw.id, { error: err.message });
      const hint = panosHint(err.message);
      req.session.flash = { type: 'error', message: `Connectivity test failed: ${err.message}` + (hint ? ` — ${hint}` : '') };
    }
    res.redirect('/firewalls');
  } catch (err) { next(err); }
});

router.get('/:id/edit', requireOrgWrite, async (req, res, next) => {
  try {
    const fw = await scopedRow(req, 'firewalls', req.params.id);
    if (!fw) return res.status(404).render('error', { title: 'Not found', message: 'No such firewall.', status: 404 });
    res.render('firewalls/form', { title: `Edit ${fw.name}`, fw, portalPublicIp: config.portalPublicIp, agents: await orgAgents(req.orgId) });
  } catch (err) { next(err); }
});

router.post('/:id', requireOrgWrite, validateBody(fwSchema.partial({ auth_mode: true })), async (req, res, next) => {
  try {
    const fw = await scopedRow(req, 'firewalls', req.params.id);
    if (!fw) return res.status(404).render('error', { title: 'Not found', message: 'No such firewall.', status: 404 });
    const b = req.body;
    b.mgmt_address = normalizeMgmt(b.mgmt_address);
    const agentId = await resolveAgent(req.orgId, b.agent_id);
    let apiKeyEnc = fw.api_key_encrypted;
    if (b.api_key) apiKeyEnc = encrypt(b.api_key.trim());
    else if (b.auth_mode === 'credentials' && b.username && b.password) {
      const { key } = await runOpRaw({
        agentId, orgId: req.orgId, op: 'keygen',
        mgmtAddress: b.mgmt_address, verifyTls: b.verify_tls === 'on', params: { username: b.username, password: b.password },
      });
      apiKeyEnc = encrypt(key);
    }
    await query(
      `UPDATE firewalls SET name=$2, mgmt_address=$3, api_key_encrypted=$4, ha_peer_address=$5,
        verify_tls=$6, partial_commit=$7, api_username=coalesce(nullif($8,''), api_username), agent_id=$10
       WHERE id=$1 AND org_id=$9`,
      [fw.id, b.name, b.mgmt_address, apiKeyEnc, b.ha_peer_address || null,
       b.verify_tls === 'on', b.partial_commit === 'on', b.username || '', req.orgId, agentId]
    );
    await auditReq(req, 'firewall.updated', 'firewall', fw.id, { name: b.name });
    req.session.flash = { type: 'success', message: 'Firewall updated.' };
    res.redirect('/firewalls');
  } catch (err) { next(err); }
});

router.post('/:id/delete', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    const { rowCount } = await query('DELETE FROM firewalls WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    if (rowCount) await auditReq(req, 'firewall.deleted', 'firewall', req.params.id);
    res.redirect('/firewalls');
  } catch (err) { next(err); }
});

module.exports = router;
