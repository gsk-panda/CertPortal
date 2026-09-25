'use strict';

/**
 * Translate raw PAN-OS / transport errors into a short, actionable hint for
 * the operator. Returns '' when nothing specific applies.
 */
function panosHint(message) {
  const m = String(message || '');
  if (/superuser privileges/i.test(m)) {
    return 'The firewall account needs the Superuser role — PAN-OS requires it to import a certificate keypair. Set Device → Administrators → (this user) → Role = Superuser, then commit.';
  }
  if (/not authorized for user role/i.test(m)) {
    return "The account's admin role is missing an XML API permission (Operational Requests). Grant it, or give the account the Superuser role.";
  }
  if (/invalid credential|invalid api key/i.test(m)) {
    return 'The API key was rejected. Edit this firewall and re-key it using username + password so CertPortal generates a fresh key, and confirm the address points at this firewall.';
  }
  if (/timeout|ETIMEDOUT|EHOSTUNREACH|ECONNREFUSED|ENOTFOUND|socket hang up|EAI_AGAIN/i.test(m)) {
    return 'CertPortal could not reach the firewall management API over HTTPS (TCP 443). Confirm the address is correct, the portal IP is permitted, and 443 reaches the management/XML-API interface.';
  }
  if (/key does not match|does not match certificate/i.test(m)) {
    return 'The certificate and private key do not match — retry the deployment; if it persists, re-issue the certificate.';
  }
  if (/certificate.*already exists|object.*exists/i.test(m)) {
    return 'A conflicting object name exists on the firewall. Remove it or let CertPortal overwrite on the next deploy.';
  }
  return '';
}

/** Append the hint to a raw error message (for storage / display). */
function withHint(message) {
  const hint = panosHint(message);
  return hint ? `${message} — ${hint}` : String(message || '');
}

module.exports = { panosHint, withHint };
