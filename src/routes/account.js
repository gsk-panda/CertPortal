'use strict';

const express = require('express');
const argon2 = require('argon2');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const { z } = require('zod');

const { query } = require('../db/pool');
const { encrypt, decrypt } = require('../crypto/envelope');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query('SELECT email, role, totp_secret, last_login FROM users WHERE id = $1', [req.session.user.id]);
    res.render('account/index', { title: 'My account', me: rows[0], totpEnabled: !!rows[0].totp_secret });
  } catch (err) { next(err); }
});

router.post('/password',
  validateBody(z.object({
    current: z.string().min(1),
    password: z.string().min(12).max(500),
    password_confirm: z.string().min(1).max(500),
    _csrf: z.string(),
  }).refine((d) => d.password === d.password_confirm, {
    message: 'the two passwords do not match',
    path: ['password_confirm'],
  })),
  async (req, res, next) => {
    try {
      const { rows } = await query('SELECT password_hash FROM users WHERE id = $1', [req.session.user.id]);
      if (!await argon2.verify(rows[0].password_hash, req.body.current)) {
        req.session.flash = { type: 'error', message: 'Current password is incorrect.' };
        return res.redirect('/account');
      }
      const hash = await argon2.hash(req.body.password, { type: argon2.argon2id });
      await query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.session.user.id]);
      await auditReq(req, 'account.password_changed', 'user', req.session.user.id);
      req.session.flash = { type: 'success', message: 'Password changed.' };
      res.redirect('/account');
    } catch (err) { next(err); }
  });

// --- TOTP enrollment -----------------------------------------------------------

router.post('/totp/start', async (req, res, next) => {
  try {
    const secret = authenticator.generateSecret();
    req.session.totpEnroll = secret;
    const uri = authenticator.keyuri(req.session.user.email, 'CertPortal', secret);
    const qr = await qrcode.toDataURL(uri);
    res.render('account/totp-setup', { title: 'Enable two-factor auth', qr, secret });
  } catch (err) { next(err); }
});

router.post('/totp/confirm',
  validateBody(z.object({ code: z.string().regex(/^\d{6}$/), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const secret = req.session.totpEnroll;
      if (!secret || !authenticator.verify({ token: req.body.code, secret })) {
        req.session.flash = { type: 'error', message: 'Code did not match — try again.' };
        return res.redirect('/account');
      }
      await query('UPDATE users SET totp_secret = $1 WHERE id = $2', [encrypt(secret), req.session.user.id]);
      delete req.session.totpEnroll;
      await auditReq(req, 'account.totp_enabled', 'user', req.session.user.id);
      req.session.flash = { type: 'success', message: 'Two-factor authentication enabled.' };
      res.redirect('/account');
    } catch (err) { next(err); }
  });

router.post('/totp/disable',
  validateBody(z.object({ code: z.string().regex(/^\d{6}$/), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const { rows } = await query('SELECT totp_secret FROM users WHERE id = $1', [req.session.user.id]);
      const enc = rows[0].totp_secret;
      if (!enc || !authenticator.verify({ token: req.body.code, secret: decrypt(enc) })) {
        req.session.flash = { type: 'error', message: 'Invalid code.' };
        return res.redirect('/account');
      }
      await query('UPDATE users SET totp_secret = NULL WHERE id = $1', [req.session.user.id]);
      await auditReq(req, 'account.totp_disabled', 'user', req.session.user.id);
      req.session.flash = { type: 'success', message: 'Two-factor authentication disabled.' };
      res.redirect('/account');
    } catch (err) { next(err); }
  });

module.exports = router;
