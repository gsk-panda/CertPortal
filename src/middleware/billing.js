'use strict';

const { config } = require('../config');
const { inGoodStanding } = require('../services/billing/entitlements');

/**
 * Gate tenant features behind an active subscription. Applied to the
 * feature routers but NOT to /billing or /account, so a lapsed or legacy-trial-expired
 * customer can always reach the page where they pay. No-op when billing is off.
 * Platform admins acting inside an org are never gated.
 */
function billingGate(req, res, next) {
  if (!config.billing.enabled) return next();
  if (req.session.user && req.session.user.role === 'platform_admin') return next();
  if (inGoodStanding(req.org)) return next();
  const trial = req.org.plan === 'trial';
  req.session.flash = {
    type: 'error',
    message: trial
      ? 'Your free trial has ended. Choose a plan to keep using CertPortal.'
      : 'Your subscription is inactive. Update billing to restore access.',
  };
  return res.redirect('/billing');
}

module.exports = { billingGate };
