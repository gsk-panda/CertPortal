'use strict';

const express = require('express');
const argon2 = require('argon2');
const crypto = require('crypto');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite } = require('../middleware/auth');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { sendSystemMail } = require('../services/notify');
const { config } = require('../config');

const router = express.Router();

const INVITE_TTL_HOURS = 72;

/**
 * Create a set-password invite token for a user and email the sign-up link.
 * Returns { sent, link } — when the email could not be delivered the caller
 * shows the link to the admin so it can be shared out-of-band.
 */
async function sendInvite(user, orgName, invitedBy) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await query(
    `INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, purpose)
     VALUES ($1,$2, now() + make_interval(hours => $3), 'invite')`,
    [user.id, tokenHash, INVITE_TTL_HOURS]
  );
  const link = `${config.baseUrl}/password-reset/${token}`;
  const roleLabel = user.role === 'client_admin' ? 'Administrator' : 'Viewer (read-only)';
  const sent = await sendSystemMail(
    user.email,
    `You've been invited to CertPortal (${orgName})`,
    `Hello,

${invitedBy} has created a CertPortal account for you in the "${orgName}" organization.

What is CertPortal?
CertPortal automates SSL/TLS certificates for your Palo Alto Networks firewalls:
it obtains certificates from Let's Encrypt, renews them before they expire, deploys
them to your firewalls, and alerts your team if anything needs attention. With
certificate lifetimes shrinking to 47 days, automation replaces the manual renewal
routine entirely.

Your account
  Email: ${user.email}
  Role:  ${roleLabel}

Set your password to activate the account (link valid ${INVITE_TTL_HOURS} hours):

  ${link}

After signing in we recommend enabling two-factor authentication under "My account".
If you weren't expecting this invitation you can ignore this email — the account
stays inactive without a password.

— CertPortal (${config.baseUrl})`
  );
  return { sent, link };
}

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query(
      `SELECT u.id, u.email, u.role, u.last_login, u.totp_secret IS NOT NULL AS totp, u.created_at,
              EXISTS (SELECT 1 FROM password_reset_tokens t
                      WHERE t.user_id = u.id AND t.purpose = 'invite'
                        AND t.used_at IS NULL AND t.expires_at > now()) AS invite_pending
       FROM users u WHERE u.org_id = $1 ORDER BY u.created_at`,
      [req.orgId]
    );
    res.render('users/list', { title: 'Users', users: rows });
  } catch (err) { next(err); }
});

router.post('/', requireOrgWrite,
  validateBody(z.object({
    email: z.string().email().max(200),
    role: z.enum(['client_admin', 'client_viewer']),
    _csrf: z.string(),
  })),
  async (req, res, next) => {
    try {
      // unusable random password until the invite link sets a real one
      const hash = await argon2.hash(crypto.randomBytes(32).toString('base64url'), { type: argon2.argon2id });
      const { rows } = await query(
        `INSERT INTO users (org_id, email, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING id, email, role`,
        [req.orgId, req.body.email.toLowerCase(), hash, req.body.role]
      );
      const user = rows[0];
      await auditReq(req, 'user.created', 'user', user.id, { email: user.email, role: user.role });

      const { sent, link } = await sendInvite(user, req.org.name, req.session.user.email);
      await auditReq(req, 'user.invite_sent', 'user', user.id, { email: user.email, delivered: sent });
      req.session.flash = sent
        ? { type: 'success', message: `Invitation emailed to ${user.email} — they have ${INVITE_TTL_HOURS} hours to set a password.` }
        : { type: 'success', message: `User created, but the invitation email could not be sent. Share this set-password link with them securely (valid ${INVITE_TTL_HOURS}h): ${link}` };
      res.redirect('/users');
    } catch (err) {
      if (err.code === '23505') {
        req.session.flash = { type: 'error', message: 'A user with that email already exists.' };
        return res.redirect('/users');
      }
      next(err);
    }
  });

router.post('/:id/resend-invite', requireOrgWrite,
  validateBody(z.object({ _csrf: z.string() })),
  async (req, res, next) => {
    try {
      const { rows } = await query(
        'SELECT id, email, role, last_login FROM users WHERE id = $1 AND org_id = $2',
        [req.params.id, req.orgId]
      );
      const user = rows[0];
      if (!user) return res.status(404).render('error', { title: 'Not found', message: 'No such user.', status: 404 });
      if (user.last_login) {
        req.session.flash = { type: 'error', message: 'That user has already signed in — use the password reset flow instead.' };
        return res.redirect('/users');
      }
      // invalidate previous invites, then issue a fresh one
      await query(
        `UPDATE password_reset_tokens SET used_at = now()
         WHERE user_id = $1 AND purpose = 'invite' AND used_at IS NULL`,
        [user.id]
      );
      const { sent, link } = await sendInvite(user, req.org.name, req.session.user.email);
      await auditReq(req, 'user.invite_resent', 'user', user.id, { email: user.email, delivered: sent });
      req.session.flash = sent
        ? { type: 'success', message: `Invitation re-sent to ${user.email}.` }
        : { type: 'success', message: `Email could not be sent. Share this link securely (valid ${INVITE_TTL_HOURS}h): ${link}` };
      res.redirect('/users');
    } catch (err) { next(err); }
  });

router.post('/:id/delete', requireOrgWrite,
  validateBody(z.object({ _csrf: z.string() })),
  async (req, res, next) => {
    try {
      if (req.params.id === req.session.user.id) {
        req.session.flash = { type: 'error', message: 'You cannot delete your own account.' };
        return res.redirect('/users');
      }
      const { rowCount } = await query('DELETE FROM users WHERE id = $1 AND org_id = $2', [req.params.id, req.orgId]);
      if (rowCount) await auditReq(req, 'user.deleted', 'user', req.params.id);
      res.redirect('/users');
    } catch (err) { next(err); }
  });

module.exports = router;
