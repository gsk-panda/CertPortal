'use strict';

/**
 * Stripe billing service. All Stripe calls live here behind a lazily-created
 * client so the rest of the app (and tests) don't depend on live keys.
 *
 * Subscription state is mirrored into the `subscriptions` table and reflected
 * onto the org: `organizations.plan` + `organizations.status` (an unpaid or
 * canceled subscription suspends the org, which already blocks its users and
 * pauses renewals).
 */

const { config } = require('../../config');
const { query } = require('../../db/pool');
const { audit } = require('../audit');
const { planKeyForPrice, PLANS } = require('./plans');

let _stripe;
function stripe() {
  if (!config.billing.stripeSecretKey) throw new Error('STRIPE_SECRET_KEY is not configured');
  if (!_stripe) _stripe = require('stripe')(config.billing.stripeSecretKey);
  return _stripe;
}

/** Ensure the org has a Stripe customer; returns the customer id. */
async function ensureCustomer(org) {
  const existing = await query('SELECT stripe_customer_id FROM subscriptions WHERE org_id = $1', [org.id]);
  if (existing.rows[0] && existing.rows[0].stripe_customer_id) return existing.rows[0].stripe_customer_id;
  const customer = await stripe().customers.create({
    name: org.name,
    email: org.contact_email,
    metadata: { org_id: org.id },
  });
  await query(
    `INSERT INTO subscriptions (org_id, stripe_customer_id) VALUES ($1,$2)
     ON CONFLICT (org_id) DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id, updated_at = now()`,
    [org.id, customer.id]
  );
  return customer.id;
}

/** Hosted Checkout for a plan. Returns the redirect URL. */
async function checkoutUrl(org, planKey, { successUrl, cancelUrl }) {
  const plan = PLANS[planKey];
  if (!plan || !plan.paid) throw new Error(`plan ${planKey} is not purchasable`);
  if (!plan.priceId) throw new Error(`no Stripe price configured for the ${planKey} plan`);
  const customerId = await ensureCustomer(org);
  const session = await stripe().checkout.sessions.create({
    mode: 'subscription',
    customer: customerId,
    line_items: [{ price: plan.priceId, quantity: 1 }],
    success_url: successUrl,
    cancel_url: cancelUrl,
    subscription_data: { metadata: { org_id: org.id } },
    metadata: { org_id: org.id, plan: planKey },
  });
  return session.url;
}

/**
 * Move an existing subscription to another paid plan (prorated). Used instead
 * of Checkout when the org already pays, so an upgrade never creates a second
 * subscription. Returns the updated Stripe subscription.
 */
async function changePlan(org, stripeSubscriptionId, planKey) {
  const plan = PLANS[planKey];
  if (!plan || !plan.paid) throw new Error(`plan ${planKey} is not purchasable`);
  if (!plan.priceId) throw new Error(`no Stripe price configured for the ${planKey} plan`);
  const current = await stripe().subscriptions.retrieve(stripeSubscriptionId);
  const updated = await stripe().subscriptions.update(stripeSubscriptionId, {
    items: [{ id: current.items.data[0].id, price: plan.priceId }],
    proration_behavior: 'create_prorations',
    metadata: { org_id: org.id, plan: planKey },
  });
  await applySubscription(org.id, updated);
  return updated;
}

/** Stripe-hosted billing portal (card, invoices, cancel). Returns the URL. */
async function portalUrl(org, returnUrl) {
  const customerId = await ensureCustomer(org);
  const session = await stripe().billingPortal.sessions.create({ customer: customerId, return_url: returnUrl });
  return session.url;
}

/** Verify a webhook payload and return the parsed event (throws on bad sig). */
function parseWebhook(rawBody, signature) {
  if (!config.billing.stripeWebhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET is not configured');
  return stripe().webhooks.constructEvent(rawBody, signature, config.billing.stripeWebhookSecret);
}

/**
 * Pure mapping: a Stripe subscription object -> the fields we persist.
 * Kept separate from I/O so it can be unit-tested without Stripe.
 */
function mapSubscription(sub) {
  const status = sub.status; // trialing|active|past_due|canceled|incomplete|unpaid
  const priceId = sub.items && sub.items.data && sub.items.data[0] && sub.items.data[0].price
    ? sub.items.data[0].price.id : null;
  const plan = planKeyForPrice(priceId) || (sub.metadata && sub.metadata.plan) || null;
  // whether this subscription grants access; the billing gate uses it. We do
  // NOT touch organizations.status here — that stays admin-controlled, so a
  // past-due customer can still reach /billing to fix their card.
  const inGoodStanding = status === 'active' || status === 'trialing';
  // a subscription that has ended returns the org to the free tier rather
  // than locking it out; existing resources stay, new ones need an upgrade.
  const orgPlan = status === 'canceled' ? 'free' : plan;
  const periodEnd = sub.current_period_end ? new Date(sub.current_period_end * 1000) : null;
  return { plan, orgPlan, status, inGoodStanding, periodEnd, stripeSubscriptionId: sub.id, customerId: sub.customer };
}

/** Apply a subscription-shaped change to our tables + the org. */
async function applySubscription(orgId, sub) {
  const m = mapSubscription(sub);
  await query(
    `INSERT INTO subscriptions (org_id, stripe_customer_id, stripe_subscription_id, plan, status, current_period_end, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6, now())
     ON CONFLICT (org_id) DO UPDATE SET
       stripe_customer_id = COALESCE(EXCLUDED.stripe_customer_id, subscriptions.stripe_customer_id),
       stripe_subscription_id = EXCLUDED.stripe_subscription_id,
       plan = COALESCE(EXCLUDED.plan, subscriptions.plan),
       status = EXCLUDED.status,
       current_period_end = EXCLUDED.current_period_end,
       updated_at = now()`,
    [orgId, m.customerId, m.stripeSubscriptionId, m.plan, m.status, m.periodEnd]
  );
  await query('UPDATE organizations SET plan = COALESCE($2, plan) WHERE id = $1', [orgId, m.orgPlan]);
  await audit({ orgId, action: 'billing.subscription_updated', targetType: 'organization', targetId: orgId,
    detail: { plan: m.plan, status: m.status } });
  return m;
}

/** Resolve the org for a Stripe object via metadata or the customer id. */
async function orgIdForEvent(obj) {
  if (obj.metadata && obj.metadata.org_id) return obj.metadata.org_id;
  const customerId = obj.customer || (obj.id && obj.object === 'customer' ? obj.id : null);
  if (customerId) {
    const { rows } = await query('SELECT org_id FROM subscriptions WHERE stripe_customer_id = $1', [customerId]);
    if (rows[0]) return rows[0].org_id;
  }
  return null;
}

/** Handle a verified Stripe event. Idempotent via billing_events. */
async function handleEvent(event) {
  const seen = await query('INSERT INTO billing_events (id, type) VALUES ($1,$2) ON CONFLICT (id) DO NOTHING RETURNING id',
    [event.id, event.type]);
  if (!seen.rows.length) return { duplicate: true };

  const obj = event.data.object;
  switch (event.type) {
    case 'checkout.session.completed': {
      const orgId = (obj.metadata && obj.metadata.org_id) || await orgIdForEvent(obj);
      if (orgId && obj.subscription) {
        const sub = await stripe().subscriptions.retrieve(obj.subscription);
        await applySubscription(orgId, sub);
      }
      break;
    }
    case 'customer.subscription.created':
    case 'customer.subscription.updated':
    case 'customer.subscription.deleted': {
      const orgId = await orgIdForEvent(obj);
      if (orgId) await applySubscription(orgId, obj);
      break;
    }
    case 'invoice.payment_failed': {
      const orgId = await orgIdForEvent(obj);
      if (orgId) {
        await query(`UPDATE subscriptions SET status = 'past_due', updated_at = now() WHERE org_id = $1`, [orgId]);
        await audit({ orgId, action: 'billing.payment_failed', targetType: 'organization', targetId: orgId });
      }
      break;
    }
    default:
      break; // ignore unhandled event types
  }
  return { handled: true };
}

module.exports = {
  ensureCustomer, checkoutUrl, changePlan, portalUrl, parseWebhook,
  mapSubscription, applySubscription, handleEvent, orgIdForEvent,
};
