'use strict';

/**
 * DNS lookups against AUTHORITATIVE nameservers (never the local resolver
 * cache): walk up the name to find the closest zone with NS records, resolve
 * those NS hosts, then query them directly.
 *
 * VERIFY_DNS_SERVER (host[:port]) overrides everything — used in tests to
 * point at pebble-challtestsrv.
 */

const dns = require('dns');
const { config } = require('../../config');

async function overrideResolver() {
  const r = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
  r.setServers([config.verifyDnsServer]);
  return r;
}

/** Find authoritative NS server IPs for the zone containing `name`. */
async function authoritativeServers(name) {
  const sys = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
  const labels = String(name).replace(/\.$/, '').split('.');
  for (let i = 0; i < labels.length - 1; i++) {
    const zone = labels.slice(i).join('.');
    let nsNames;
    try {
      nsNames = await sys.resolveNs(zone);
    } catch (err) {
      continue; // not a zone cut; go up one label
    }
    const ips = [];
    for (const ns of nsNames) {
      try { ips.push(...await sys.resolve4(ns)); } catch (_) { /* try next */ }
      if (ips.length >= 2) break;
    }
    if (ips.length) return { zone, servers: ips };
  }
  throw new Error(`Could not find authoritative nameservers for ${name}`);
}

/** Resolve TXT records for `name` from its authoritative NS. Returns string[]. */
async function resolveTxtAuthoritative(name) {
  let resolver;
  if (config.verifyDnsServer) {
    resolver = await overrideResolver();
  } else {
    const { servers } = await authoritativeServers(name);
    resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
    resolver.setServers(servers);
  }
  const records = await resolver.resolveTxt(name);
  return records.map((chunks) => chunks.join(''));
}

/** Resolve CNAME for `name` from its authoritative NS (or override). */
async function resolveCnameAuthoritative(name) {
  let resolver;
  if (config.verifyDnsServer) {
    resolver = await overrideResolver();
  } else {
    const { servers } = await authoritativeServers(name);
    resolver = new dns.promises.Resolver({ timeout: 4000, tries: 2 });
    resolver.setServers(servers);
  }
  return resolver.resolveCname(name);
}

/**
 * Wait until a TXT with `value` is visible at `name` on authoritative NS.
 * Retries with backoff. Returns true/false.
 */
async function waitForTxt(name, value, { attempts = 10, initialDelayMs = 2000, maxDelayMs = 30000 } = {}) {
  let delay = initialDelayMs;
  for (let i = 0; i < attempts; i++) {
    try {
      const txts = await resolveTxtAuthoritative(name);
      if (txts.includes(value)) return true;
    } catch (_) { /* NXDOMAIN / timeout: keep waiting */ }
    if (i < attempts - 1) {
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 1.7, maxDelayMs);
    }
  }
  return false;
}

module.exports = { authoritativeServers, resolveTxtAuthoritative, resolveCnameAuthoritative, waitForTxt };
