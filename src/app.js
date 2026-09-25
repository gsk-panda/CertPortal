'use strict';

const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const helmet = require('helmet');

const { config } = require('./config');
const { pool } = require('./db/pool');
const { csrfProtection } = require('./middleware/csrf');
const { requireAuth, requireRole, tenantScope } = require('./middleware/auth');

function buildApp() {
  const app = express();

  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, 'views'));
  app.set('trust proxy', 1);

  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
  }));

  // Stripe webhook needs the raw body for signature verification, so it is
  // mounted before the body parsers, session, and CSRF.
  app.use('/webhooks', express.raw({ type: '*/*', limit: '1mb' }), require('./routes/webhooks'));

  app.use(express.urlencoded({ extended: false, limit: '256kb' }));
  app.use(express.json({ limit: '256kb' }));

  // Agent machine API: token-authenticated, no cookies/CSRF; mounted before
  // the session/CSRF middleware. All traffic is agent-initiated (outbound).
  app.use('/api/agent', require('./routes/agentApi'));

  app.use('/static', express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

  app.use(session({
    store: new PgSession({ pool, tableName: 'session' }),
    name: 'certportal.sid',
    secret: config.sessionSecret,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000,
    },
  }));

  app.use(csrfProtection);

  // common view locals
  app.use((req, res, next) => {
    res.locals.user = (req.session && req.session.user) || null;
    res.locals.actingOrgId = (req.session && req.session.actingOrgId) || null;
    res.locals.flash = req.session ? req.session.flash : null;
    if (req.session) delete req.session.flash;
    res.locals.acmeProduction = config.acme.isProduction;
    res.locals.billingEnabled = config.billing.enabled;
    res.locals.signupEnabled = config.billing.enabled && config.billing.signupEnabled;
    res.locals.path = req.path;
    next();
  });

  // routes
  app.use('/', require('./routes/auth'));
  app.use('/signup', require('./routes/signup'));
  app.use('/admin', requireAuth, requireRole('platform_admin'), require('./routes/admin'));

  const { billingGate } = require('./middleware/billing');
  const tenant = [requireAuth, tenantScope];              // billing page: reachable when lapsed
  const gated = [requireAuth, tenantScope, billingGate];  // feature pages: require good standing
  app.use('/dashboard', gated, require('./routes/dashboard'));
  app.use('/firewalls', gated, require('./routes/firewalls'));
  app.use('/dns-providers', gated, require('./routes/dnsProviders'));
  app.use('/domains', gated, require('./routes/domains'));
  app.use('/certificates', gated, require('./routes/certificates'));
  app.use('/users', gated, require('./routes/users'));
  app.use('/audit', gated, require('./routes/audit'));
  app.use('/notifications', gated, require('./routes/notifications'));
  app.use('/agents', gated, require('./routes/agents'));
  app.use('/billing', tenant, require('./routes/billing'));
  app.use('/account', requireAuth, require('./routes/account'));

  app.get('/', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
    if (req.session.user.role === 'platform_admin' && !req.session.actingOrgId) return res.redirect('/admin');
    return res.redirect('/dashboard');
  });

  app.get('/healthz', async (req, res) => {
    try {
      await pool.query('SELECT 1');
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ ok: false });
    }
  });

  app.use((req, res) => {
    res.status(404).render('error', { title: 'Not found', message: 'That page does not exist.', status: 404 });
  });

  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error('[app] unhandled error:', err);
    if (res.headersSent) return;
    res.status(500).render('error', { title: 'Server error', message: config.env === 'development' ? err.message : 'An unexpected error occurred.', status: 500 });
  });

  return app;
}

module.exports = { buildApp };
