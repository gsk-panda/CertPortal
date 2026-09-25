'use strict';

/**
 * Machine API for on-prem agents. Token-authenticated (no cookies/CSRF).
 * Mounted before the session/CSRF middleware. All calls are agent-initiated.
 */

const express = require('express');
const { z } = require('zod');
const agent = require('../services/agent/service');

const router = express.Router();

// Enroll: exchange a one-time token for a permanent secret.
router.post('/enroll', async (req, res) => {
  const parsed = z.object({ token: z.string().min(8).max(200), version: z.string().max(60).optional() }).safeParse(req.body || {});
  if (!parsed.success) return res.status(400).json({ error: 'token required' });
  try {
    const creds = await agent.enroll(parsed.data);
    res.json(creds);
  } catch (err) {
    res.status(401).json({ error: err.message });
  }
});

// Everything below requires a valid agent bearer token.
async function requireAgent(req, res, next) {
  try {
    const a = await agent.authenticate(req.get('authorization'));
    if (!a) return res.status(401).json({ error: 'invalid agent credentials' });
    req.agent = a;
    next();
  } catch (err) { next(err); }
}

// Long-poll for the next job. 200 with a job, or 204 when idle.
router.get('/jobs', requireAgent, async (req, res, next) => {
  try {
    await agent.touch(req.agent.id, req.get('x-agent-version'));
    const deadline = Date.now() + 25000;
    for (;;) {
      const job = await agent.leaseNext(req.agent.id);
      if (job) return res.json({ job });
      if (Date.now() > deadline) return res.status(204).end();
      await new Promise((r) => setTimeout(r, 1000));
    }
  } catch (err) { next(err); }
});

// Submit a job result.
router.post('/jobs/:id/result', requireAgent, async (req, res, next) => {
  try {
    const parsed = z.object({
      status: z.enum(['done', 'failed']),
      result: z.any().optional(),
      error: z.string().max(2000).optional(),
    }).safeParse(req.body || {});
    if (!parsed.success) return res.status(400).json({ error: 'bad result' });
    const ok = await agent.complete(req.agent.id, req.params.id, parsed.data);
    if (!ok) return res.status(404).json({ error: 'no such leased job for this agent' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

module.exports = router;
