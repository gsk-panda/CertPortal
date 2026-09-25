'use strict';

const LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
const LE_PRODUCTION = 'https://acme-v02.api.letsencrypt.org/directory';

function bool(v, dflt = false) {
  if (v === undefined || v === '') return dflt;
  return ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase());
}

function acmeDirectoryUrl() {
  if (process.env.ACME_DIRECTORY_URL) return process.env.ACME_DIRECTORY_URL;
  const mode = (process.env.ACME_DIRECTORY || 'staging').toLowerCase();
  if (mode === 'production') return LE_PRODUCTION;
  if (mode === 'staging') return LE_STAGING;
  return mode; // allow a raw URL in ACME_DIRECTORY too
}

const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  baseUrl: process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`,
  env: process.env.NODE_ENV || 'development',
  databaseUrl: process.env.DATABASE_URL || 'postgres://certportal:certportal@localhost:5432/certportal',
  masterKek: process.env.MASTER_KEK || '',
  masterKekPrevious: process.env.MASTER_KEK_PREVIOUS || '',
  sessionSecret: process.env.SESSION_SECRET || '',
  adminEmail: process.env.ADMIN_EMAIL || '',
  adminPassword: process.env.ADMIN_PASSWORD || '',
  acme: {
    directoryUrl: acmeDirectoryUrl(),
    insecure: bool(process.env.ACME_INSECURE, false),
    isProduction: acmeDirectoryUrl() === LE_PRODUCTION,
    LE_STAGING,
    LE_PRODUCTION,
  },
  acmeDns: {
    zone: (process.env.ACME_DNS_ZONE || 'acme.certportal.example').toLowerCase(),
    publicIp: process.env.ACME_DNS_PUBLIC_IP || '192.0.2.1',
    port: parseInt(process.env.ACME_DNS_PORT || '0', 10),
  },
  verifyDnsServer: process.env.VERIFY_DNS_SERVER || '',
  // Public source IP the portal connects to firewalls from (for the whitelist
  // hint on the firewalls page). Falls back to the acme-dns public IP.
  portalPublicIp: process.env.PORTAL_PUBLIC_IP || process.env.ACME_DNS_PUBLIC_IP || '',
  // Optional PEM bundle to trust the firewall management cert when verify_tls
  // is on (firewall's own mgmt cert, or an internal CA). Enables authenticated
  // TLS to the firewall on on-prem deployments.
  firewallCaBundle: process.env.FIREWALL_CA_BUNDLE || '',
  // Where the Agents page links to download the Windows agent installer.
  agentMsiUrl: process.env.AGENT_MSI_URL
    || 'https://github.com/gsk-panda/CertPortal/releases/latest/download/certportal-agent.msi',
  mockPanos: bool(process.env.MOCK_PANOS, false),
  mockPanosPort: parseInt(process.env.MOCK_PANOS_PORT || '9443', 10),
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || 'certportal@localhost',
  },
  billing: {
    enabled: bool(process.env.BILLING_ENABLED, false),
    signupEnabled: bool(process.env.SIGNUP_ENABLED, false),
    stripeSecretKey: process.env.STRIPE_SECRET_KEY || '',
    stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET || '',
    priceStarter: process.env.STRIPE_PRICE_STARTER || '',
    pricePro: process.env.STRIPE_PRICE_PRO || '',
    priceEnterprise: process.env.STRIPE_PRICE_ENTERPRISE || '',
  },
  cookieSecure: bool(process.env.COOKIE_SECURE, false),
  // Renewal engine
  renewalCron: process.env.RENEWAL_CRON || '0 * * * *', // hourly
  renewalDefaultPercent: parseInt(process.env.RENEWAL_DEFAULT_PERCENT || '66', 10),
  // Domain ownership re-verification interval (days)
  domainReverifyDays: parseInt(process.env.DOMAIN_REVERIFY_DAYS || '90', 10),
  disableScheduler: bool(process.env.DISABLE_SCHEDULER, false),
};

function validateConfig() {
  const errors = [];
  if (!config.masterKek) {
    errors.push('MASTER_KEK is required (32 bytes, base64).');
  } else {
    const buf = Buffer.from(config.masterKek, 'base64');
    if (buf.length !== 32) errors.push(`MASTER_KEK must decode to exactly 32 bytes (got ${buf.length}).`);
  }
  if (!config.sessionSecret || config.sessionSecret.length < 16) {
    errors.push('SESSION_SECRET is required (16+ characters).');
  }
  if (errors.length) {
    throw new Error('Configuration invalid:\n  - ' + errors.join('\n  - '));
  }
}

module.exports = { config, validateConfig };
