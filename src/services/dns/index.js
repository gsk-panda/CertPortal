'use strict';

/**
 * DNS provider plugin registry.
 *
 * Plugin interface:
 *   createTxtRecord(name, value)  — publish TXT at `name` (full FQDN)
 *   deleteTxtRecord(name, value)  — remove it (cleanup runs regardless of outcome)
 *   effectiveName(name)?          — where the TXT actually lives (CNAME delegation)
 *   test()                        — connectivity/credential check, returns message
 *   manual                        — true when an operator must create records
 * Propagation checking is shared: waitForTxt() queries the authoritative
 * nameservers of effectiveName(name) before ACME validation is triggered.
 */

const { CloudflareProvider } = require('./providers/cloudflare');
const { Route53Provider } = require('./providers/route53');
const { AzureDnsProvider } = require('./providers/azure');
const { GoDaddyProvider } = require('./providers/godaddy');
const { AcmeDnsCnameProvider } = require('./providers/acmedns');
const { ManualProvider } = require('./providers/manual');
const { decrypt } = require('../../crypto/envelope');

const TYPES = {
  cloudflare: {
    label: 'Cloudflare',
    fields: [{ name: 'api_token', label: 'API token (Zone:DNS:Edit)', secret: true }],
    make: (creds) => new CloudflareProvider(creds),
  },
  route53: {
    label: 'AWS Route53',
    fields: [
      { name: 'access_key_id', label: 'Access key ID (blank = instance role)' },
      { name: 'secret_access_key', label: 'Secret access key', secret: true },
      { name: 'region', label: 'Region (default us-east-1)' },
    ],
    make: (creds) => new Route53Provider(creds),
  },
  azure_dns: {
    label: 'Azure DNS',
    fields: [
      { name: 'tenant_id', label: 'Tenant ID' },
      { name: 'client_id', label: 'Client (app) ID' },
      { name: 'client_secret', label: 'Client secret', secret: true },
      { name: 'subscription_id', label: 'Subscription ID' },
      { name: 'resource_group', label: 'Resource group containing the DNS zones' },
    ],
    make: (creds) => new AzureDnsProvider(creds),
  },
  godaddy: {
    label: 'GoDaddy',
    fields: [
      { name: 'api_key', label: 'API key' },
      { name: 'api_secret', label: 'API secret', secret: true },
    ],
    make: (creds) => new GoDaddyProvider(creds),
  },
  acme_dns_cname: {
    label: 'CNAME delegation (no DNS credentials)',
    fields: [],
    make: (creds, ctx) => new AcmeDnsCnameProvider(creds, ctx),
  },
  manual: {
    label: 'Manual (copy-paste TXT records)',
    fields: [],
    make: () => new ManualProvider(),
  },
};

/** Instantiate a plugin from a dns_providers row. */
function providerFromRow(row) {
  const def = TYPES[row.type];
  if (!def) throw new Error(`Unknown DNS provider type ${row.type}`);
  const creds = row.credentials_encrypted ? JSON.parse(decrypt(row.credentials_encrypted)) : {};
  return def.make(creds, { orgId: row.org_id });
}

module.exports = { TYPES, providerFromRow };
