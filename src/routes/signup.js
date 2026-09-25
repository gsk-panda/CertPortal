'use strict';

const express = require('express');
const argon2 = require('argon2');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');

const { query, withTransaction } = require('../db/pool');
const { config } = require('../config');
const { audit } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { PLANS } = require('../services/billing/plans');

const router = express.Router();

const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

function guard(req, res, next) {
  if (!config.billing.enabled || !config.billing.signupEnabled) {
    return res.status(404).render('error', { title: 'Not available', message: 'Self-serve signup is not enabled.', status: 404 });
  }
  next();
}

router.get('/', guard, (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('auth/signup', { title: 'Create your free account', freeLimits: PLANS.free.limits });
});

router.post('/', guard, signupLimiter,
  validateBody(z.object({
    org_name: z.string().trim().min(2).max(120),
    email: z.string().email().max(200),
    password: z.string().min(12).max(500),
    password_confirm: z.string().min(1).max(500),
    _csrf: z.string(),
  }).refine((d) => d.password === d.password_confirm, {
    message: 'the two passwords do not match',
    path: ['password_confirm'],
  })),
  async (req, res, next) => {
    try {
      const email = req.body.email.toLowerCase();
      const exists = await query('SELECT 1 FROM users WHERE email = $1', [email]);
      if (exists.rows.length) {
        req.session.flash = { type: 'error', message: 'An account with that email already exists — sign in instead.' };
        return res.redirect('/signup');
      }
      const hash = await argon2.hash(req.body.password, { type: argon2.argon2id });
      const result = await withTransaction(async (client) => {
        const org = (await client.query(
          `INSERT INTO organizations (name, contact_email, plan, status)
           VALUES ($1,$2,'free','active') RETURNING id, name`,
          [req.body.org_name, email]
        )).rows[0];
        const user = (await client.query(
          `INSERT INTO users (org_id, email, password_hash, role) VALUES ($1,$2,$3,'client_admin') RETURNING id, email, role, org_id`,
          [org.id, email, hash]
        )).rows[0];
        return { org, user };
      });
      await audit({ orgId: result.org.id, userId: result.user.id, action: 'org.self_signup', targetType: 'organization', targetId: result.org.id, detail: { org: req.body.org_name, email }, ip: req.ip });

      await new Promise((resolve, reject) => req.session.regenerate((e) => e ? reject(e) : resolve()));
      req.session.user = { id: result.user.id, email: result.user.email, role: result.user.role, orgId: result.user.org_id };
      await query('UPDATE users SET last_login = now() WHERE id = $1', [result.user.id]);
      req.session.flash = { type: 'success', message: 'Welcome! Your free account is ready. Upgrade any time on the Billing page to add more.' };
      res.redirect('/dashboard');
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'That organization name or email is already taken.' };
        return res.redirect('/signup');
      }
      next(err);
    }
  });

module.exports = router;
