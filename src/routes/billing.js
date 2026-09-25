'use strict';

const express = require('express');
const { z } = require('zod');

const { query } = require('../db/pool');
const { config } = require('../config');
const { requireOrgWrite } = require('../middleware/auth');
const { validateBody } = require('../middleware/validate');
const { planForOrg, purchasablePlans } = require('../services/billing/plans');
const { inGoodStanding } = require('../services/billing/entitlements');
const billing = require('../services/billing/service');
const { auditReq } = require('../services/audit');

const router = express.Router();

async function usage(orgId) {
  const q = async (t) => (await query(`SELECT count(*)::int AS n FROM ${t} WHERE org_id = $1`, [orgId])).rows[0].n;
  return {
    firewalls: await q('firewalls'),
    domains: await q('domains'),
    certificates: await q('certificates'),
    agents: await q('agents'),
  };
}

router.get('/', async (req, res, next) => {
  try {
    const plan = planForOrg(req.org);
    const sub = (await query('SELECT * FROM subscriptions WHERE org_id = $1', [req.orgId])).rows[0] || null;
    res.render('billing/index', {
      title: 'Billing',
      plan,
      plans: purchasablePlans(),
      subscription: sub,
      standing: inGoodStanding(req.org),
      usage: await usage(req.orgId),
      trialEndsAt: req.org.trial_ends_at,
      stripeConfigured: !!config.billing.stripeSecretKey,
    });
  } catch (err) { next(err); }
});

router.post('/checkout', requireOrgWrite,
  validateBody(z.object({ plan: z.string().min(1), _csrf: z.string() })),
  async (req, res, next) => {
    try {
      if (!config.billing.stripeSecretKey) {
        req.session.flash = { type: 'error', message: 'Billing is not fully configured yet — contact support.' };
        return res.redirect('/billing');
      }
      const sub = (await query('SELECT stripe_subscription_id, status FROM subscriptions WHERE org_id = $1', [req.orgId])).rows[0];
      if (sub && sub.stripe_subscription_id && sub.status !== 'canceled') {
        // already subscribed: switch the existing subscription's plan
        await billing.changePlan(req.org, sub.stripe_subscription_id, req.body.plan);
        await auditReq(req, 'billing.plan_changed', 'organization', req.orgId, { plan: req.body.plan });
        req.session.flash = { type: 'success', message: 'Your plan has been changed. Any difference is prorated on your next invoice.' };
        return res.redirect('/billing');
      }
      const url = await billing.checkoutUrl(req.org, req.body.plan, {
        successUrl: `${config.baseUrl}/billing?checkout=success`,
        cancelUrl: `${config.baseUrl}/billing?checkout=cancelled`,
      });
      await auditReq(req, 'billing.checkout_started', 'organization', req.orgId, { plan: req.body.plan });
      res.redirect(303, url);
    } catch (err) {
      req.session.flash = { type: 'error', message: `Could not start checkout: ${err.message}` };
      res.redirect('/billing');
    }
  });

router.post('/portal', requireOrgWrite,
  validateBody(z.object({ _csrf: z.string() })),
  async (req, res, next) => {
    try {
      if (!config.billing.stripeSecretKey) {
        req.session.flash = { type: 'error', message: 'Billing portal is not available yet.' };
        return res.redirect('/billing');
      }
      const url = await billing.portalUrl(req.org, `${config.baseUrl}/billing`);
      res.redirect(303, url);
    } catch (err) {
      req.session.flash = { type: 'error', message: `Could not open the billing portal: ${err.message}` };
      res.redirect('/billing');
    }
  });

module.exports = router;
