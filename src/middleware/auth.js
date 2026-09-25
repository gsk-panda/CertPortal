'use strict';

/**
 * Authentication + tenant-scoping middleware.
 *
 * Tenancy model: req.orgId is ALWAYS derived server-side —
 *   - client users: their own users.org_id from the session
 *   - platform admins browsing a tenant: the org id stored in
 *     req.session.actingOrgId (set only through the platform-admin
 *     "open org" route which validates the org exists)
 * Client-supplied org ids in params/body/query are never trusted.
 */

const { query } = require('../db/pool');

const ROLES = ['platform_admin', 'client_admin', 'client_viewer'];

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  if (req.accepts('html')) return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  return res.status(401).json({ error: 'authentication required' });
}

/** Allow only the listed roles. */
function requireRole(...roles) {
  for (const r of roles) if (!ROLES.includes(r)) throw new Error(`unknown role ${r}`);
  return (req, res, next) => {
    const user = req.session && req.session.user;
    if (!user) return res.status(401).json({ error: 'authentication required' });
    if (!roles.includes(user.role)) {
      return res.status(403).render('error', { title: 'Forbidden', message: 'You do not have permission to do that.', status: 403 });
    }
    next();
  };
}

/**
 * Resolve req.orgId for tenant-owned routes and block suspended orgs.
 * Platform admins must have "entered" an org via /admin/orgs/:id/open.
 */
async function tenantScope(req, res, next) {
  try {
    const user = req.session.user;
    let orgId;
    if (user.role === 'platform_admin') {
      orgId = req.session.actingOrgId;
      if (!orgId) {
        return res.status(400).render('error', { title: 'No organization selected', message: 'Open an organization from the admin console first.', status: 400 });
      }
    } else {
      orgId = user.orgId;
    }
    const { rows } = await query(
      `SELECT o.id, o.name, o.status, o.renewal_percent, o.plan, o.trial_ends_at,
              (SELECT s.status FROM subscriptions s WHERE s.org_id = o.id) AS sub_status
       FROM organizations o WHERE o.id = $1`, [orgId]);
    if (!rows.length) {
      return res.status(404).render('error', { title: 'Organization not found', message: 'This organization no longer exists.', status: 404 });
    }
    const org = rows[0];
    if (org.status !== 'active' && user.role !== 'platform_admin') {
      return res.status(403).render('error', { title: 'Organization suspended', message: 'This organization is suspended. Contact your service provider.', status: 403 });
    }
    req.orgId = org.id;
    req.org = org;
    res.locals.currentOrg = org;
    next();
  } catch (err) {
    next(err);
  }
}

/** Write access within a tenant: client_admin, or platform_admin acting on an org. */
function requireOrgWrite(req, res, next) {
  const role = req.session.user.role;
  if (role === 'client_admin' || role === 'platform_admin') return next();
  return res.status(403).render('error', { title: 'Read-only account', message: 'Viewer accounts cannot make changes.', status: 403 });
}

/**
 * Fetch one tenant-owned row, enforcing org scope in SQL.
 * Usage: const fw = await scopedRow(req, 'firewalls', req.params.id);
 * Returns null when missing OR belonging to another org (indistinguishable
 * to the caller — no cross-tenant existence oracle).
 */
async function scopedRow(req, table, id, columns = '*') {
  const safe = /^[a-z_]+$/.test(table);
  if (!safe) throw new Error('bad table');
  if (!/^[0-9a-f-]{36}$/i.test(String(id))) return null;
  const { rows } = await query(`SELECT ${columns} FROM ${table} WHERE id = $1 AND org_id = $2`, [id, req.orgId]);
  return rows[0] || null;
}

module.exports = { requireAuth, requireRole, tenantScope, requireOrgWrite, scopedRow };
