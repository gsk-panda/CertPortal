'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite } = require('../middleware/auth');
const { validateBody } = require('../middleware/validate');
const { createAgent } = require('../services/agent/service');
const { auditReq } = require('../services/audit');
const { config } = require('../config');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT a.id, a.name, a.status, a.version, a.last_seen, a.created_at,
              (a.enrollment_token_hash IS NOT NULL) AS awaiting_enrollment,
              (SELECT count(*) FROM firewalls f WHERE f.agent_id = a.id)::int AS firewall_count
       FROM agents a WHERE a.org_id = $1 ORDER BY a.name`, [req.orgId]);
    res.render('agents/list', {
      title: 'Agents',
      agents: rows,
      controlPlaneUrl: config.baseUrl,
      agentMsiUrl: config.agentMsiUrl,
      newAgent: req.session.newAgent || null,
    });
    if (req.session.newAgent) delete req.session.newAgent;
  } catch (err) { next(err); }
});

router.post('/', requireOrgWrite,
  validateBody(z.object({ name: z.string().trim().min(1).max(80), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const { agentId, enrollmentToken } = await createAgent(req.orgId, req.body.name);
      await auditReq(req, 'agent.created', 'agent', agentId, { name: req.body.name });
      // shown once so the operator can install the agent
      req.session.newAgent = { name: req.body.name, token: enrollmentToken };
      res.redirect('/agents');
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'An agent with that name already exists.' };
        return res.redirect('/agents');
      }
      next(err);
    }
  });

router.post('/:id/delete', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    // detach firewalls back to direct mode, then remove the agent
    await query('UPDATE firewalls SET agent_id = NULL WHERE agent_id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    const { rowCount } = await query('DELETE FROM agents WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
    if (rowCount) await auditReq(req, 'agent.deleted', 'agent', req.params.id);
    res.redirect('/agents');
  } catch (err) { next(err); }
});

module.exports = router;
