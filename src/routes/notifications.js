'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { requireOrgWrite } = require('../middleware/auth');
const { encrypt, decrypt } = require('../crypto/envelope');
const { auditReq } = require('../services/audit');
const { validateBody } = require('../middleware/validate');
const { notifyOrg } = require('../services/notify');

const router = express.Router();

const EVENTS = [
  ['renewal_success', 'Renewal success'],
  ['renewal_failure', 'Renewal failure'],
  ['deployment_failure', 'Deployment failure'],
  ['cert_expiring_no_automation', 'Certificate expiring with no automation path'],
  ['domain_verification_lapsed', 'Domain verification lapsed'],
];

router.get('/', async (req, res, next) => {
  try {
    const { rows } = await query('SELECT * FROM notification_settings WHERE org_id = $1', [req.orgId]);
    const settings = rows[0] || null;
    let smtp = {};
    if (settings && settings.smtp_encrypted) {
      try { smtp = JSON.parse(decrypt(settings.smtp_encrypted)); smtp.pass = smtp.pass ? '********' : ''; } catch (_) { /* ignore */ }
    }
    const log = await query('SELECT * FROM notification_log WHERE org_id = $1 ORDER BY id DESC LIMIT 20', [req.orgId]);
    res.render('notifications/index', {
      title: 'Notifications',
      settings, smtp,
      enabledEvents: settings ? settings.events : EVENTS.map((e) => e[0]),
      events: EVENTS,
      log: log.rows,
    });
  } catch (err) { next(err); }
});

router.post('/', requireOrgWrite,
  validateBody(z.object({
    smtp_host: z.string().trim().max(255).optional().or(z.literal('')),
    smtp_port: z.string().regex(/^\d*$/).optional().or(z.literal('')),
    smtp_user: z.string().max(255).optional().or(z.literal('')),
    smtp_pass: z.string().max(255).optional().or(z.literal('')),
    smtp_from: z.string().max(255).optional().or(z.literal('')),
    smtp_to: z.string().max(255).optional().or(z.literal('')),
    webhook_url: z.string().max(500).url().optional().or(z.literal('')),
    _csrf: z.string(),
  }).passthrough()),
  async (req, res, next) => {
    try {
      const events = EVENTS.map((e) => e[0]).filter((ev) => req.body[`event_${ev}`] === 'on');
      const existing = (await query('SELECT * FROM notification_settings WHERE org_id = $1', [req.orgId])).rows[0];

      let smtpEnc = existing ? existing.smtp_encrypted : null;
      if (req.body.smtp_host) {
        let pass = req.body.smtp_pass || '';
        if (pass === '********' && existing && existing.smtp_encrypted) {
          try { pass = JSON.parse(decrypt(existing.smtp_encrypted)).pass || ''; } catch (_) { pass = ''; }
        }
        smtpEnc = encrypt(JSON.stringify({
          host: req.body.smtp_host, port: req.body.smtp_port || '587',
          user: req.body.smtp_user || '', pass,
          from: req.body.smtp_from || '', to: req.body.smtp_to || '',
        }));
      } else {
        smtpEnc = null;
      }

      await query(
        `INSERT INTO notification_settings (org_id, smtp_encrypted, webhook_url, events, updated_at)
         VALUES ($1,$2,$3,$4, now())
         ON CONFLICT (org_id) DO UPDATE SET smtp_encrypted = $2, webhook_url = $3, events = $4, updated_at = now()`,
        [req.orgId, smtpEnc, req.body.webhook_url || null, JSON.stringify(events)]
      );
      await auditReq(req, 'notifications.updated', 'organization', req.orgId, { events, webhook: !!req.body.webhook_url, smtp: !!req.body.smtp_host });
      req.session.flash = { type: 'success', message: 'Notification settings saved.' };
      res.redirect('/notifications');
    } catch (err) { next(err); }
  });

router.post('/test', requireOrgWrite, validateBody(z.object({ _csrf: z.string() })), async (req, res, next) => {
  try {
    await notifyOrg(req.orgId, 'renewal_success', 'Test notification',
      'This is a test notification from CertPortal. If you can read this, delivery works.');
    req.session.flash = { type: 'success', message: 'Test notification dispatched — check the delivery log below.' };
    res.redirect('/notifications');
  } catch (err) { next(err); }
});

module.exports = router;
