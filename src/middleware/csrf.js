'use strict';

/**
 * Session-bound CSRF tokens (synchronizer token pattern).
 * A per-session random token is exposed to views as `csrfToken`;
 * every state-changing request must echo it in the `_csrf` body field
 * or `x-csrf-token` header. Comparison is constant-time.
 */

const crypto = require('crypto');

function csrfProtection(req, res, next) {
  if (req.session && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  res.locals.csrfToken = req.session ? req.session.csrfToken : '';

  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const sent = (req.body && req.body._csrf) || req.get('x-csrf-token') || '';
  const expected = (req.session && req.session.csrfToken) || '';
  const a = Buffer.from(String(sent));
  const b = Buffer.from(String(expected));
  const ok = expected && a.length === b.length && crypto.timingSafeEqual(a, b);
  if (!ok) {
    return res.status(403).render('error', { title: 'Session expired', message: 'Invalid CSRF token — please go back, refresh the page, and try again.', status: 403 });
  }
  next();
}

module.exports = { csrfProtection };
