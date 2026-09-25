'use strict';

const { query } = require('../../db/pool');
const { planForOrg, withinLimit } = require('./plans');

const TABLES = { firewalls: 'firewalls', domains: 'domains', certificates: 'certificates' };

/**
 * Check whether the org may create another `resource`. Returns
 * { ok, plan, count, limit }. When billing is disabled the plan is
 * unrestricted, so ok is always true.
 */
async function checkLimit(req, resource) {
  const plan = planForOrg(req.org);
  const table = TABLES[resource];
  if (!table) return { ok: true, plan };
  const { rows } = await query(`SELECT count(*)::int AS n FROM ${table} WHERE org_id = $1`, [req.orgId]);
  const count = rows[0].n;
  return { ok: withinLimit(plan, resource, count), plan, count, limit: plan.limits[resource] };
}

/**
 * Is the org in good billing standing? Grandfathered orgs (plan set, no
 * subscription — e.g. pre-billing tenants on 'enterprise') pass. Trials pass
 * until trial_ends_at. Paid plans need an active/trialing subscription.
 * req.org must include plan, trial_ends_at, sub_status (from tenantScope).
 */
function inGoodStanding(org) {
  if (org.plan === 'trial') {
    return !!org.trial_ends_at && new Date(org.trial_ends_at) > new Date();
  }
  // paid plan with no subscription row => grandfathered (pre-billing)
  if (!org.sub_status) return true;
  return org.sub_status === 'active' || org.sub_status === 'trialing';
}

module.exports = { checkLimit, inGoodStanding };
