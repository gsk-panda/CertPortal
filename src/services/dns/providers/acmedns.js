'use strict';

/**
 * CNAME-delegation provider (acme-dns pattern).
 *
 * Each domain registers once and gets a stable subdomain
 * <uuid>.<ACME_DNS_ZONE>. The client creates a single permanent CNAME:
 *   _acme-challenge.<fqdn>  CNAME  <uuid>.<ACME_DNS_ZONE>
 * From then on all TXT records are written into the platform-controlled
 * zone (served by the built-in authoritative responder) and the client's
 * DNS never changes again.
 */

const { query } = require('../../../db/pool');
const { config } = require('../../../config');
const { resolveCnameAuthoritative } = require('../resolve');

class AcmeDnsCnameProvider {
  constructor(credentials, ctx = {}) {
    this.orgId = ctx.orgId;
  }

  /** Map _acme-challenge.<fqdn> to the delegated name in our zone. */
  async effectiveName(challengeName) {
    const fqdn = challengeName.replace(/^_acme-challenge\./, '');
    const { rows } = await query(
      `SELECT acme_dns_subdomain FROM domains
       WHERE org_id = $1 AND acme_dns_subdomain IS NOT NULL
         AND ($2 = fqdn OR $2 LIKE '%.' || fqdn OR fqdn = ANY(ARRAY[$2]))
       ORDER BY length(fqdn) DESC LIMIT 1`,
      [this.orgId, fqdn]
    );
    if (!rows.length) throw new Error(`No CNAME delegation registered covering ${fqdn} — register the domain first.`);
    return `${rows[0].acme_dns_subdomain}.${config.acmeDns.zone}`;
  }

  async createTxtRecord(name, value) {
    const target = await this.effectiveName(name);
    const subdomain = target.slice(0, -(config.acmeDns.zone.length + 1));
    await query('INSERT INTO acme_dns_records (subdomain, txt_value) VALUES ($1,$2)', [subdomain, value]);
  }

  async deleteTxtRecord(name, value) {
    const target = await this.effectiveName(name);
    const subdomain = target.slice(0, -(config.acmeDns.zone.length + 1));
    await query('DELETE FROM acme_dns_records WHERE subdomain = $1 AND txt_value = $2', [subdomain, value]);
  }

  /** Verify the client's one-time CNAME actually points at us. */
  async checkCname(fqdn, expectedTarget) {
    try {
      const cnames = await resolveCnameAuthoritative(`_acme-challenge.${fqdn}`);
      const normalized = cnames.map((c) => c.replace(/\.$/, '').toLowerCase());
      return normalized.includes(expectedTarget.replace(/\.$/, '').toLowerCase());
    } catch (err) {
      return false;
    }
  }

  async test() {
    return `OK — validation zone ${config.acmeDns.zone} (records served by CertPortal's DNS responder)`;
  }
}

module.exports = { AcmeDnsCnameProvider };
