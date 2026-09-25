'use strict';

const crypto = require('crypto');
const express = require('express');
const argon2 = require('argon2');
const rateLimit = require('express-rate-limit');
const { authenticator } = require('otplib');
const { z } = require('zod');

const { query } = require('../db/pool');
const { decrypt } = require('../crypto/envelope');
const { audit } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { sendSystemMail } = require('../services/notify');
const { config } = require('../config');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many login attempts; try again later.',
});

function sessionUser(u) {
  return { id: u.id, email: u.email, role: u.role, orgId: u.org_id };
}

router.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('auth/login', { title: 'Sign in', next: req.query.next || '' });
});

router.post('/login', loginLimiter,
  validateBody(z.object({
    email: z.string().email().max(200),
    password: z.string().min(1).max(500),
    next: z.string().max(500).optional().default(''),
    _csrf: z.string(),
  })),
  async (req, res, next) => {
    try {
      const email = req.body.email.toLowerCase();
      const { rows } = await query('SELECT * FROM users WHERE email = $1', [email]);
      const user = rows[0];
      const ok = user && await argon2.verify(user.password_hash, req.body.password);
      if (!ok) {
        await audit({ action: 'login.failed', detail: { email }, ip: req.ip });
        req.session.flash = { type: 'error', message: 'Invalid email or password.' };
        return res.redirect('/login');
      }
      if (user.org_id) {
        const org = await query('SELECT status FROM organizations WHERE id = $1', [user.org_id]);
        if (!org.rows.length || org.rows[0].status !== 'active') {
          req.session.flash = { type: 'error', message: 'Your organization is suspended.' };
          return res.redirect('/login');
        }
      }
      const safeNext = /^\/[^/\\]/.test(req.body.next || '') ? req.body.next : '/';
      if (user.totp_secret) {
        req.session.pendingTotpUserId = user.id;
        req.session.pendingNext = safeNext;
        return res.redirect('/login/totp');
      }
      await finishLogin(req, user);
      res.redirect(safeNext);
    } catch (err) { next(err); }
  });

async function finishLogin(req, user) {
  await new Promise((resolve, reject) => req.session.regenerate((e) => e ? reject(e) : resolve()));
  req.session.user = sessionUser(user);
  await query('UPDATE users SET last_login = now() WHERE id = $1', [user.id]);
  await audit({ orgId: user.org_id, userId: user.id, action: 'login.success', ip: req.ip });
}

router.get('/login/totp', (req, res) => {
  if (!req.session.pendingTotpUserId) return res.redirect('/login');
  res.render('auth/totp', { title: 'Two-factor authentication' });
});

router.post('/login/totp', loginLimiter,
  validateBody(z.object({ code: z.string().regex(/^\d{6}$/), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const userId = req.session.pendingTotpUserId;
      if (!userId) return res.redirect('/login');
      const { rows } = await query('SELECT * FROM users WHERE id = $1', [userId]);
      const user = rows[0];
      if (!user || !user.totp_secret || !authenticator.verify({ token: req.body.code, secret: decrypt(user.totp_secret) })) {
        await audit({ userId, action: 'login.totp_failed', ip: req.ip });
        req.session.flash = { type: 'error', message: 'Invalid code.' };
        return res.redirect('/login/totp');
      }
      const nextUrl = req.session.pendingNext || '/';
      await finishLogin(req, user);
      res.redirect(nextUrl);
    } catch (err) { next(err); }
  });

router.post('/logout', (req, res) => {
  const user = req.session.user;
  req.session.destroy(() => {
    if (user) audit({ orgId: user.orgId, userId: user.id, action: 'logout', ip: req.ip });
    res.redirect('/login');
  });
});

// --- Password reset -----------------------------------------------------------

const resetLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });

router.get('/password-reset', (req, res) => res.render('auth/reset-request', { title: 'Reset password' }));

router.post('/password-reset', resetLimiter,
  validateBody(z.object({ email: z.string().email().max(200), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const email = req.body.email.toLowerCase();
      const { rows } = await query('SELECT id, email FROM users WHERE email = $1', [email]);
      if (rows.length) {
        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        await query(
          `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1,$2, now() + interval '1 hour')`,
          [rows[0].id, tokenHash]
        );
        const link = `${config.baseUrl}/password-reset/${token}`;
        const sent = await sendSystemMail(email, 'CertPortal password reset',
          `A password reset was requested for your CertPortal account.\n\nReset link (valid 1 hour): ${link}\n\nIf you did not request this, ignore this email.`);
        if (!sent) console.log(`[auth] password reset link for ${email} (SMTP not configured): ${link}`);
        await audit({ userId: rows[0].id, action: 'password_reset.requested', ip: req.ip });
      }
      req.session.flash = { type: 'success', message: 'If that address exists, a reset link has been sent.' };
      res.redirect('/login');
    } catch (err) { next(err); }
  });

router.get('/password-reset/:token', async (req, res, next) => {
  try {
    const row = await findResetToken(req.params.token);
    if (!row) return res.status(400).render('error', { title: 'Invalid link', message: 'This link is invalid or expired. Ask your administrator to send a new invitation, or use "Forgot your password?" on the sign-in page.', status: 400 });
    const invite = row.purpose === 'invite';
    res.render('auth/reset-form', {
      title: invite ? 'Welcome to CertPortal' : 'Choose a new password',
      token: req.params.token,
      invite,
      email: row.email,
    });
  } catch (err) { next(err); }
});

router.post('/password-reset/:token', resetLimiter,
  validateBody(z.object({
    password: z.string().min(12).max(500),
    password_confirm: z.string().min(1).max(500),
    _csrf: z.string(),
  }).refine((d) => d.password === d.password_confirm, {
    message: 'the two passwords do not match',
    path: ['password_confirm'],
  })),
  async (req, res, next) => {
    try {
      const row = await findResetToken(req.params.token);
      if (!row) return res.status(400).render('error', { title: 'Invalid link', message: 'This reset link is invalid or expired.', status: 400 });
      const hash = await argon2.hash(req.body.password, { type: argon2.argon2id });
      await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, row.user_id]);
      await query('UPDATE password_reset_tokens SET used_at = now() WHERE id = $1', [row.id]);
      const invite = row.purpose === 'invite';
      await audit({ userId: row.user_id, action: invite ? 'user.invite_accepted' : 'password_reset.completed', ip: req.ip });
      req.session.flash = {
        type: 'success',
        message: invite ? 'Your account is active — sign in with your new password.' : 'Password updated — sign in with your new password.',
      };
      res.redirect('/login');
    } catch (err) { next(err); }
  });

async function findResetToken(token) {
  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
  const { rows } = await query(
    `SELECT t.*, u.email FROM password_reset_tokens t
     JOIN users u ON u.id = t.user_id
     WHERE t.token_hash = $1 AND t.used_at IS NULL AND t.expires_at > now()`,
    [tokenHash]
  );
  return rows[0] || null;
}

module.exports = router;
