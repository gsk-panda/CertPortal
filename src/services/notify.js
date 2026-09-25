'use strict';

/**
 * Notifications: per-org SMTP and/or webhook, with a global SMTP fallback
 * from env. Events: renewal_success, renewal_failure, deployment_failure,
 * cert_expiring_no_automation, domain_verification_lapsed.
 */

const nodemailer = require('nodemailer');
const axios = require('axios');
const { query } = require('../db/pool');
const { decrypt } = require('../crypto/envelope');
const { config } = require('../config');

async function logNotification(orgId, event, channel, subject, ok, detail) {
  try {
    await query(
      'INSERT INTO notification_log (org_id, event, channel, subject, ok, detail) VALUES ($1,$2,$3,$4,$5,$6)',
      [orgId, event, channel, subject, ok, detail ? String(detail).slice(0, 500) : null]
    );
  } catch (err) {
    console.error('[notify] failed to log notification:', err.message);
  }
}

function globalTransport() {
  if (!config.smtp.host) return null;
  return nodemailer.createTransport({
    host: config.smtp.host,
    port: config.smtp.port,
    secure: config.smtp.port === 465,
    auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
  });
}

/** System mail (password resets etc). Returns true when actually sent. */
async function sendSystemMail(to, subject, text) {
  const transport = globalTransport();
  if (!transport) return false;
  try {
    await transport.sendMail({ from: config.smtp.from, to, subject, text });
    return true;
  } catch (err) {
    console.error('[notify] system mail failed:', err.message);
    return false;
  }
}

/** Notify an org about an event through its configured channels. */
async function notifyOrg(orgId, event, subject, text, extra = {}) {
  const { rows } = await query('SELECT * FROM notification_settings WHERE org_id = $1', [orgId]);
  const settings = rows[0];
  const enabled = settings ? (settings.events || []) : [];
  if (settings && !enabled.includes(event)) return;

  // email
  let smtp = null, to = null;
  if (settings && settings.smtp_encrypted) {
    try {
      const conf = JSON.parse(decrypt(settings.smtp_encrypted));
      if (conf.host) {
        smtp = nodemailer.createTransport({
          host: conf.host,
          port: parseInt(conf.port || 587, 10),
          secure: parseInt(conf.port || 587, 10) === 465,
          auth: conf.user ? { user: conf.user, pass: conf.pass } : undefined,
        });
        to = conf.to;
      }
    } catch (err) {
      console.error('[notify] bad org SMTP config:', err.message);
    }
  }
  if (!smtp) {
    smtp = globalTransport();
    if (!to) {
      const org = await query('SELECT contact_email FROM organizations WHERE id = $1', [orgId]);
      to = org.rows.length ? org.rows[0].contact_email : null;
    }
  }
  if (smtp && to) {
    try {
      const fromAddr = (settings && settings.smtp_encrypted && JSON.parse(decrypt(settings.smtp_encrypted)).from) || config.smtp.from;
      await smtp.sendMail({ from: fromAddr, to, subject: `[CertPortal] ${subject}`, text });
      await logNotification(orgId, event, 'email', subject, true);
    } catch (err) {
      await logNotification(orgId, event, 'email', subject, false, err.message);
    }
  } else {
    console.log(`[notify] (no SMTP) org=${orgId} event=${event}: ${subject}`);
  }

  // webhook
  if (settings && settings.webhook_url) {
    try {
      await axios.post(settings.webhook_url, {
        source: 'certportal', event, subject, message: text, ...extra, timestamp: new Date().toISOString(),
      }, { timeout: 10000 });
      await logNotification(orgId, event, 'webhook', subject, true);
    } catch (err) {
      await logNotification(orgId, event, 'webhook', subject, false, err.message);
    }
  }
}

module.exports = { notifyOrg, sendSystemMail };
