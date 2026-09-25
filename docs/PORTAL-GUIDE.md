# CertPortal — Portal Guide

CertPortal automates the entire SSL/TLS certificate lifecycle for Palo Alto
Networks firewalls: issuance from Let's Encrypt (DNS-01), scheduled renewal,
deployment to PAN-OS, commit, and post-deploy validation. After onboarding,
no manual steps are required.

This guide covers every page and option in the portal. It applies to the
hosted instance at **https://certportal.azotech.net** (emails arrive from
`noreply@azotech.net`).

---

## 1. Accounts, roles, and signing in

| Role | Scope | Can do |
|---|---|---|
| **Platform Admin** | All organizations | Create/suspend orgs, open any org, view global dashboards and audit |
| **Client Admin** | One organization | Manage users, DNS providers, domains, firewalls, certificates, notifications |
| **Client Viewer** | One organization | Read-only: see everything, change nothing |

- Anyone can **create a free account** at `/signup` (when self-serve signup
  is enabled). This creates their organization and makes them its Client
  Admin; they then invite their own team. The free plan includes 1 domain,
  1 certificate, 1 firewall and 1 agent and never expires; the **Billing**
  page upgrades to a paid plan for more. A Platform Admin can still create
  organizations and invite their first Client Admin directly. New users receive an email with a set-password link —
  passwords are never chosen by or shared with administrators.
- **Forgot password** on the sign-in page emails a single-use reset link
  (valid 1 hour).
- **My account** (sidebar, bottom): change your password (12+ characters) and
  enable **two-factor authentication** (TOTP). 2FA enrollment shows a QR code
  for any authenticator app and requires a confirmation code before it
  activates. Once enabled, sign-in asks for a 6-digit code.

---

## 2. Platform admin console (`/admin`)

Visible only to Platform Admins.

- **Organizations table** — every tenant with user/firewall/certificate counts
  and the soonest certificate expiry.
  - **Open** — enter the org and use the portal exactly as its admins see it
    (for onboarding and support). An "exit org" button in the sidebar returns
    you to the console. Everything you do inside is attributed to you in the
    audit log.
  - **Suspend / Reactivate** — suspension immediately blocks all of the org's
    users and pauses its certificate renewals; nothing is deleted.
- **Create organization** — name + contact email. The contact email is used to
  register the org's Let's Encrypt account and as the default notification
  recipient.
- **Global audit log** — every action across all tenants, newest first.
- **Certificates expiring soonest** — cross-tenant expiry watchlist.

---

## 3. Client dashboard

The landing page for client users. Shows:

- **Status tiles** — total certificates, and counts by health:
  - **Green** — more than 15 days remaining
  - **Yellow** — under 15 days (inside the normal renewal window)
  - **Red** — under 7 days (needs attention if not already renewing)
  - **Failing renewal** — certificates whose last renewal attempt failed
- **Unverified-domain banner** — issuance and renewal are paused for any
  domain that has not (or no longer) passed ownership verification.
- **Certificate table** — status, days remaining, projected renewal date
  ("Renews ~"), linked firewall count, and expiry for every certificate.
- **Recent failures** — the last renewal/deployment errors with messages.

---

## 4. DNS providers

CertPortal proves domain control to Let's Encrypt by publishing DNS TXT
records (DNS-01 — required for wildcards and for services like GlobalProtect
that can't answer HTTP challenges). A *DNS provider* tells the portal how
those records get published. All credentials are encrypted at rest.

| Type | Credentials | When to use |
|---|---|---|
| **Cloudflare** | API token (Zone → DNS → Edit) | Domain's DNS is on Cloudflare |
| **AWS Route53** | Access key + secret (or blank to use an instance role) | DNS on Route53 |
| **Azure DNS** | Service principal (tenant, client id/secret, subscription, resource group) | DNS on Azure |
| **GoDaddy** | API key + secret | DNS on GoDaddy |
| **CNAME delegation** | *None* | You don't want to hand over DNS credentials — one permanent CNAME per domain, then zero DNS work forever |
| **Manual** | None | Dev/testing only — an operator copies TXT records by hand at every issuance **and every renewal** |

- **Test** — verifies the credentials against the provider's API (e.g. lists
  zones) and reports what it can see.
- **Manual** providers cannot support unattended renewal — someone must be
  present each time. Use CNAME delegation instead for production domains
  where API credentials aren't available.

### CNAME delegation, explained

When a domain is registered with the CNAME-delegation provider, the portal
assigns it a permanent identity inside the platform-controlled zone
`acme.certportal.azotech.net`. You create **one** record at your DNS host:

```
_acme-challenge.vpn.example.com  CNAME  <uuid>.acme.certportal.azotech.net
```

Every future validation (including wildcards and renewals every ~6 weeks)
happens inside the platform's zone. Your DNS never changes again, and you
never share credentials. The domain page shows the exact record and a
**Check CNAME** button that confirms it resolves correctly.

---

## 5. Domains

A domain must pass **ownership verification** before any certificate can be
requested for it — this prevents one tenant requesting certificates for a
name they don't control.

**Add domain** — enter the FQDN (e.g. `vpn.example.com`) and pick the DNS
provider that will handle its validation records. Don't enter wildcards here;
wildcard coverage is chosen at certificate creation.

**Domain page:**

- **Ownership verification** — the portal shows a TXT record:
  ```
  _certportal-verify.vpn.example.com  TXT  "certportal-…token…"
  ```
  Create it at your DNS host and click **Verify**. The check queries your
  domain's *authoritative* nameservers directly (no cache), so it normally
  succeeds within a minute of saving the record.
- **Leave the record in place.** Verification is automatically re-checked
  every 90 days. If it lapses, renewals for that domain pause and the org is
  notified; click **Re-verify now** after restoring the record.
- **CNAME delegation panel** (delegation-provider domains only) — the exact
  one-time CNAME to create and the **Check CNAME** validator.

Deleting a domain deletes its certificates and their deployment links.

---

## 6. Firewalls

**Add firewall:**

| Field | Meaning |
|---|---|
| Display name | Label within the org |
| Management address | Hostname/IP (optionally `host:port`) of the PAN-OS management interface — the portal must be able to reach it. **Always connected over HTTPS**; any scheme you type is ignored. |
| **API key** | Paste an existing PAN-OS API key, **or** |
| **Username + password** | Used exactly once to call the PAN-OS `keygen` API; only the resulting key is stored (encrypted). The password is never saved. |
| HA peer address | Optional. The portal deploys to *this* member; PAN-OS config sync carries the certificate to the peer. Deploy logs state this explicitly. |
| Verify TLS certificate | **On** by default. Turn off only for self-signed management certs — a yellow badge flags firewalls running unverified. |
| Partial commit | Commits only the API user's changes, so other admins' uncommitted work is untouched. Recommended on shared boxes. |

- **Test** — calls `show system info`, records hostname / serial / PAN-OS
  version / HA state, and sets the status badge (`ok`, `unreachable`,
  `auth_failed`) plus "last seen".
- **PAN-OS account:** importing a certificate keypair via the API requires the
  **Superuser** role — PAN-OS has no narrower privilege for private-key import.
  Create a *dedicated* Superuser account used only by CertPortal (its key is
  encrypted and all actions audited); don't reuse an interactive admin. A
  connectivity test only needs operational-request rights, but deployment
  (keypair import) needs Superuser. Details in the project README.

**Whitelisting the portal's IP.** CertPortal connects outbound over HTTPS
(TCP 443) from a single fixed address, shown in a callout on the Firewalls
pages (for the hosted instance: `34.203.146.199`). If you restrict management
access, permit that source. The **"How to allow this IP"** button opens
step-by-step instructions for the management-interface permitted-IP list, the
data-plane Interface Mgmt Profile + security policy case, and NAT setups.

---

## 7. Certificates

### Creating a certificate (wizard)

**1 · Names**
- **Domain** — pick an ownership-verified domain.
- **Wildcard** — adds `*.domain` to the certificate (DNS-01 makes this possible).
- **Additional SANs** — extra names on the same certificate. They must be the
  domain itself or subdomains of it.
- **Key type** — ECDSA P-256 (default, smaller/faster) or RSA-2048.

**2 · Deployment targets**
- **Firewalls** — check every firewall that should receive this certificate.
  (You can also issue with none selected and just download the PEMs.)
- **SSL/TLS Service Profile** — optional. The portal binds the certificate to
  this profile via the config API. Because the portal always re-imports under
  the same PAN-OS object name (`certportal-<domain>`), the profile keeps
  working across renewals without ever being edited again.
- **GlobalProtect portal / gateway** — optional names; the portal binds the
  SSL/TLS profile to them (requires the profile field).
- **Post-deploy validation endpoint** — optional `host[:port]` (e.g.
  `vpn.example.com:443`). After every commit, the portal opens a TLS
  connection there and confirms the *served* certificate serial matches the
  one just deployed — proof the renewal actually took effect.

Submitting starts issuance in the background; the detail page live-updates.

### Certificate detail page

- **Status** — `pending` (issuing) → `issued` → `deployed`; `renewing` during
  renewal; `failed` with the error message shown; `revoked`.
- **Manual-DNS action panel** — when the domain uses the *Manual* provider,
  the required TXT records appear here with copy-paste boxes. Create them,
  click **"I created the records — continue"**, and the portal checks
  propagation on authoritative nameservers before telling Let's Encrypt to
  validate.
- **Renew now** — full renewal immediately (new key + certificate, deploy,
  commit, validate).
- **Redeploy** — pushes the *current* certificate to all linked firewalls
  again (use after adding a firewall or fixing connectivity).
- **Downloads** — `cert.pem`, `chain.pem`, `fullchain.pem`.
- **Deployments table** — per-firewall state machine
  (`importing → committing → validating → deployed`/`failed`), the PAN-OS
  object name, commit job ID, validation result, and a per-firewall **Run**
  button.
- **Timeline** — the certificate's full audit history.

### Automatic renewal

- The scheduler checks hourly. A certificate renews once **66% of its
  lifetime** has elapsed (per-organization setting) — for 47-day
  certificates that's around day 31, leaving ~16 days of retry headroom.
- Failures retry with backoff: 1 h → 4 h → 12 h → 24 h → daily. The org is
  emailed from the **second** consecutive failure; the dashboard flags the
  certificate immediately.
- Renewals pause when a domain's ownership verification lapses or the org is
  suspended, and a "certificate expiring with no automation path" warning is
  sent for certificates that can't self-renew.

---

## 8. Users

Client Admins manage their own team here. Admins never choose or see
anyone's password.

- **Invite user** — enter an email and role (**Admin** or **Viewer**).
  CertPortal emails the person a welcome message (from
  `noreply@azotech.net`) explaining what the platform does, with a link to
  set their own password. The link is single-use and valid for **72 hours**;
  the account stays inactive until they use it.
- **Invite pending / expired badges** — users who haven't activated yet are
  flagged; **Resend invite** issues a fresh link (and invalidates old ones).
- If the invitation email can't be delivered, the portal shows the
  set-password link to the admin instead, to share through another channel.
- Users can be deleted (not your own account). Audit history is retained,
  including invite sent/accepted events.

---

## 9. Notifications

Per-organization delivery settings for automated events:

| Event | Fires when |
|---|---|
| Renewal success | A certificate renewed and deployed |
| Renewal failure | A renewal attempt failed (emailed from 2nd consecutive failure) |
| Deployment failure | Import/commit/validation failed on a firewall |
| Expiring with no automation path | Cert expires <14 days and *can't* auto-renew (auto-renew off or verification lapsed) |
| Domain verification lapsed | 90-day re-verification failed |

- **Email** — by default, notifications go to the org contact address from
  the platform's mail system (`noreply@azotech.net`). Optionally enter your
  own SMTP server and recipient to route mail yourself.
- **Webhook** — a URL that receives JSON
  (`{source, event, subject, message, timestamp}`) for Slack/Teams bridges,
  ticketing, or monitoring.
- **Send test** — fires a test notification through both channels.
- **Recent deliveries** — log of every send with success/failure detail.

---

## 10. Audit log

Org-scoped, append-only record of every action: logins, user changes,
firewall/domain/DNS/certificate operations, issuances, deployments, renewals
(with who, when, from which IP). Secrets are redacted before storage.
Platform Admins additionally have the cross-tenant view at
**Platform admin → Global audit log**.

---

## Appendix A — Status reference

**Certificate:** `pending` (first issuance running) · `issued` (valid, not
deployed anywhere) · `deployed` (live on all linked firewalls) · `renewing` ·
`failed` (see error; retries per backoff) · `revoked`

**Deployment:** `pending` · `importing` · `committing` · `validating` ·
`deployed` · `failed`

**Firewall:** `ok` · `unreachable` · `auth_failed` · `unknown` (never tested)

**Days-left badges:** green ≥ 15 · yellow 7–14 · red < 7

## Appendix B — Typical client onboarding (10 minutes)

1. Sign in with the credentials your Platform Admin provided; change your
   password; enable 2FA.
2. **DNS providers → Add** — Cloudflare/Route53/Azure/GoDaddy credentials, or
   CNAME delegation if you'd rather not share any.
3. **Domains → Add** — enter the FQDN, create the verification TXT record,
   click **Verify** (plus the one-time CNAME if using delegation).
4. **Firewalls → Add** — management address + credentials for keygen;
   click **Test**.
5. **Certificates → New** — pick domain/wildcard/SANs, select firewalls,
   optionally bind an SSL/TLS profile and GP portal/gateway, set a validation
   endpoint, and issue.
6. Done. Renewal, deployment, commit, and validation are automatic from here;
   you'll only hear from the portal when something needs attention.
