'use strict';

/**
 * Domain ownership verification: the client proves control by publishing
 *   _certportal-verify.<fqdn>  TXT  "<token>"
 * checked against the domain's AUTHORITATIVE nameservers. Verification
 * expires after DOMAIN_REVERIFY_DAYS (default 90); a scheduled sweep
 * re-checks, and on lapse pauses renewals + notifies the org.
 */

const { query } = require('../db/pool');
const { resolveTxtAuthoritative } = require('./dns/resolve');
const { audit } = require('./audit');
const { notifyOrg } = require('./notify');
const { config } = require('../config');

function verificationRecordName(fqdn) {
  return `_certportal-verify.${fqdn.replace(/^\*\./, '')}`;
}

/** Attempt verification now. Updates the row; returns { ok, error? }. */
async function verifyDomain(domain) {
  const name = verificationRecordName(domain.fqdn);
  try {
    const txts = await resolveTxtAuthoritative(name);
    if (!txts.includes(domain.verification_token)) {
      return { ok: false, error: `TXT found at ${name} but no value matches the expected token.` + (txts.length ? '' : ' (no records)') };
    }
  } catch (err) {
    return { ok: false, error: `DNS lookup for ${name} failed: ${err.message}` };
  }
  await query('UPDATE domains SET ownership_verified = true, verified_at = now() WHERE id = $1', [domain.id]);
  await audit({ orgId: domain.org_id, action: 'domain.verified', targetType: 'domain', targetId: domain.id, detail: { fqdn: domain.fqdn } });
  return { ok: true };
}

/** Sweep: re-verify domains older than the re-verify window; lapse on failure. */
async function reverifySweep() {
  const { rows } = await query(
    `SELECT * FROM domains WHERE ownership_verified = true
       AND verified_at < now() - make_interval(days => $1)`,
    [config.domainReverifyDays]
  );
  for (const domain of rows) {
    const result = await verifyDomain(domain);
    if (!result.ok) {
      await query('UPDATE domains SET ownership_verified = false WHERE id = $1', [domain.id]);
      await audit({ orgId: domain.org_id, action: 'domain.verification_lapsed', targetType: 'domain', targetId: domain.id, detail: { fqdn: domain.fqdn, error: result.error } });
      await notifyOrg(domain.org_id, 'domain_verification_lapsed',
        `Domain verification lapsed: ${domain.fqdn}`,
        `Ownership re-verification failed for ${domain.fqdn}: ${result.error}\n\nRenewals for certificates on this domain are paused until the domain is re-verified in CertPortal.`);
    }
  }
  return rows.length;
}

module.exports = { verifyDomain, reverifySweep, verificationRecordName };
