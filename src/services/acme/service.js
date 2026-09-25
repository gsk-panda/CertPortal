'use strict';

/**
 * ACME (RFC 8555) issuance — DNS-01 only.
 *
 * - one ACME account per organization (key stored encrypted)
 * - TXT propagation is confirmed against authoritative nameservers before
 *   the ACME server is told to validate (acme-client's own local-resolver
 *   check is disabled)
 * - TXT records are cleaned up regardless of outcome
 * - manual providers: challenges are parked on the certificate row until
 *   an operator confirms the records exist
 */

const https = require('https');
const crypto = require('crypto');
const acme = require('acme-client');
const { query } = require('../../db/pool');
const { encrypt, decrypt } = require('../../crypto/envelope');
const { config } = require('../../config');
const { providerFromRow } = require('../dns');
const { waitForTxt } = require('../dns/resolve');
const { audit } = require('../audit');

if (config.acme.insecure) {
  // Pebble test CA only — never set ACME_INSECURE in production
  acme.axios.defaults.httpsAgent = new https.Agent({ rejectUnauthorized: false });
}

acme.setLogger((msg) => {
  if (process.env.ACME_DEBUG) console.log('[acme]', msg);
});

/** Get or create the org's ACME account for the configured directory. */
async function getOrCreateAccount(orgId) {
  const dir = config.acme.directoryUrl;
  const existing = await query(
    'SELECT * FROM acme_accounts WHERE org_id = $1 AND directory_url = $2', [orgId, dir]
  );
  if (existing.rows.length) return existing.rows[0];

  const org = await query('SELECT contact_email FROM organizations WHERE id = $1', [orgId]);
  if (!org.rows.length) throw new Error('organization not found');
  const email = org.rows[0].contact_email;

  const accountKey = await acme.crypto.createPrivateEcdsaKey();
  const client = new acme.Client({ directoryUrl: dir, accountKey });
  await client.createAccount({ termsOfServiceAgreed: true, contact: [`mailto:${email}`] });
  const accountUrl = client.getAccountUrl();

  const { rows } = await query(
    `INSERT INTO acme_accounts (org_id, directory_url, account_url, account_key_encrypted, email)
     VALUES ($1,$2,$3,$4,$5)
     ON CONFLICT (org_id, directory_url) DO UPDATE SET account_url = EXCLUDED.account_url
     RETURNING *`,
    [orgId, dir, accountUrl, encrypt(accountKey.toString()), email]
  );
  await audit({ orgId, action: 'acme.account_created', detail: { directory: dir, email } });
  return rows[0];
}

function clientForAccount(account) {
  return new acme.Client({
    directoryUrl: account.directory_url,
    accountKey: decrypt(account.account_key_encrypted),
    accountUrl: account.account_url,
  });
}

function challengeName(identifier) {
  return `_acme-challenge.${identifier.replace(/^\*\./, '')}`;
}

async function appendPendingChallenge(certId, record) {
  await query(
    `UPDATE certificates
     SET pending_challenges = coalesce(pending_challenges, '[]'::jsonb) || $2::jsonb
     WHERE id = $1`,
    [certId, JSON.stringify([record])]
  );
}

/** Poll until the operator confirms manual DNS records (or timeout). */
async function waitForManualConfirmation(certId, { timeoutMs = 45 * 60 * 1000, pollMs = 3000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const { rows } = await query('SELECT manual_confirmed_at FROM certificates WHERE id = $1', [certId]);
    if (!rows.length) throw new Error('certificate deleted during manual confirmation');
    if (rows[0].manual_confirmed_at) return;
    if (Date.now() > deadline) throw new Error('timed out waiting for manual DNS confirmation');
    await new Promise((r) => setTimeout(r, pollMs));
  }
}

/**
 * Issue (or renew) the certificate row. On success updates cert_pem /
 * chain_pem / key_pem_encrypted / serial / validity and sets status=issued.
 * Throws on failure (caller handles status/backoff).
 */
async function issueCertificate(certId) {
  const { rows } = await query(
    `SELECT c.*, d.fqdn, d.ownership_verified, d.dns_provider_id
     FROM certificates c JOIN domains d ON d.id = c.domain_id WHERE c.id = $1`,
    [certId]
  );
  if (!rows.length) throw new Error('certificate not found');
  const cert = rows[0];
  if (!cert.ownership_verified) throw new Error(`domain ${cert.fqdn} ownership is not verified — issuance blocked`);

  const providerRow = (await query('SELECT * FROM dns_providers WHERE id = $1 AND org_id = $2', [cert.dns_provider_id, cert.org_id])).rows[0];
  if (!providerRow) throw new Error('DNS provider for this domain no longer exists');
  const provider = providerFromRow(providerRow);

  const account = await getOrCreateAccount(cert.org_id);
  const client = clientForAccount(account);

  const altNames = Array.isArray(cert.san_list) && cert.san_list.length ? cert.san_list : [cert.fqdn];
  const commonName = altNames[0];

  const key = cert.key_type === 'rsa_2048'
    ? await acme.crypto.createPrivateRsaKey(2048)
    : await acme.crypto.createPrivateEcdsaKey('P-256');
  const [, csr] = await acme.crypto.createCsr({ commonName, altNames }, key);

  // reset any manual-flow leftovers
  await query('UPDATE certificates SET pending_challenges = NULL, manual_confirmed_at = NULL WHERE id = $1', [certId]);

  const cleanups = [];
  let pem;
  try {
    pem = await client.auto({
      csr,
      email: account.email,
      termsOfServiceAgreed: true,
      challengePriority: ['dns-01'],
      skipChallengeVerification: true, // we verify against authoritative NS ourselves
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        if (challenge.type !== 'dns-01') throw new Error(`unsupported challenge type ${challenge.type}`);
        const name = challengeName(authz.identifier.value);
        cleanups.push({ name, value: keyAuthorization });
        await provider.createTxtRecord(name, keyAuthorization);

        // where does the record actually live (CNAME delegation)?
        const checkName = provider.effectiveName ? await provider.effectiveName(name) : name;

        if (provider.manual) {
          await appendPendingChallenge(certId, { name, value: keyAuthorization });
          console.log(`[acme] cert ${certId}: waiting for operator to publish TXT ${name}`);
          await waitForManualConfirmation(certId);
        }

        const seen = await waitForTxt(checkName, keyAuthorization, { attempts: provider.manual ? 20 : 12 });
        if (!seen) throw new Error(`TXT record for ${checkName} not visible on authoritative nameservers`);
      },
      challengeRemoveFn: async (authz, challenge, keyAuthorization) => {
        const name = challengeName(authz.identifier.value);
        try { await provider.deleteTxtRecord(name, keyAuthorization); } catch (err) {
          console.warn(`[acme] TXT cleanup failed for ${name}: ${err.message}`);
        }
      },
    });
  } finally {
    // belt & braces: cleanup any records acme-client didn't hand back to removeFn
    for (const c of cleanups) {
      try { await provider.deleteTxtRecord(c.name, c.value); } catch (_) { /* already gone */ }
    }
    await query('UPDATE certificates SET pending_challenges = NULL, manual_confirmed_at = NULL WHERE id = $1', [certId]);
  }

  // split leaf and chain
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  if (!blocks.length) throw new Error('ACME server returned no certificate');
  const leaf = blocks[0];
  const chain = blocks.slice(1).join('\n');
  const x509 = new crypto.X509Certificate(leaf);

  await query(
    `UPDATE certificates SET
       status = 'issued', cert_pem = $2, chain_pem = $3, key_pem_encrypted = $4,
       serial = $5, not_before = $6, not_after = $7, acme_account_id = $8,
       renewal_failures = 0, last_error = NULL
     WHERE id = $1`,
    [certId, leaf, chain, encrypt(key.toString()),
     x509.serialNumber, new Date(x509.validFrom), new Date(x509.validTo), account.id]
  );
  await audit({
    orgId: cert.org_id, action: 'cert.issued', targetType: 'certificate', targetId: certId,
    detail: { sans: altNames, serial: x509.serialNumber, notAfter: x509.validTo, directory: account.directory_url },
  });
  return { serial: x509.serialNumber, notAfter: x509.validTo };
}

module.exports = { issueCertificate, getOrCreateAccount };
