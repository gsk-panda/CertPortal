# DECISIONS

Defaults chosen during implementation. Each was picked to be sensible for a
production multi-tenant deployment; all are overridable where noted.

## Stack & structure
- **Plain `pg` with parameterized queries, no ORM.** Fewer moving parts, SQL is
  visible and auditable, and the renewal engine needs explicit locking
  semantics (`FOR UPDATE SKIP LOCKED`, advisory locks) that are awkward through ORMs.
- **Express 5** (current on npm). Async errors propagate to the error handler natively.
- **zod** for input validation (typed schemas, good coercion story). Validation
  failures flash the first error and bounce to the referring form.
- **Migrations**: naive ordered `.sql` runner with a `schema_migrations` table and
  a Postgres advisory lock so multiple app instances can boot concurrently.
  Migrations run automatically at startup.

## Security
- **Envelope encryption is a real envelope**: per-record random 256-bit DEK
  (AES-256-GCM, random 12-byte IV) wrapped by the KEK (AES-256-GCM, own IV).
  Stored as `v1.<wrapIv>.<wrappedDek>.<wrapTag>.<dataIv>.<ct>.<dataTag>`.
  KEK rotation = re-wrap DEKs (`scripts/rotate-kek.js`); bulk data is never re-encrypted.
  `MASTER_KEK_PREVIOUS` gives a zero-downtime rotation window.
- **CSRF**: session-bound synchronizer token (the `csurf` package is deprecated).
  Constant-time comparison; token in a hidden field / `x-csrf-token` header.
- **CSP** via helmet: `default-src 'self'`, no inline scripts/styles anywhere
  (the TOTP QR is a `data:` image, allowed for `img-src` only).
- **Sessions**: `express-session` + `connect-pg-simple`, 12h rolling, httpOnly,
  sameSite=lax. `COOKIE_SECURE` defaults to true in `.env.example` but is a flag
  because lab deployments frequently start plain-HTTP.
- **Session fixation**: session regenerated on login.
- **Password policy**: argon2id, 12+ chars for new passwords. Password reset
  tokens are stored SHA-256-hashed, single-use, 1h expiry.
- **User onboarding is invite-based**: admins never set passwords. New users
  get an emailed set-password link (single-use, 72h, same hashed-token store
  with `purpose='invite'`); accounts hold an unusable random hash until
  activated. If email delivery fails, the link is surfaced to the inviting
  admin for out-of-band sharing. If no SMTP is
  configured, the reset link goes to the app log (documented; better than a
  dead feature in dev).
- **Login rate limit**: 20 attempts / 15 min / IP (express-rate-limit),
  5 / 15 min for password-reset endpoints.
- **Audit redaction**: any detail key matching /api_key|password|secret|token|
  credential|private|key_pem|passphrase/i is replaced with `[REDACTED]` before
  the row is written. Audit table is append-only, enforced with a DB trigger.
- **Platform admin tenancy**: platform admins "open" an org explicitly
  (`/admin/orgs/:id/open`); that org id lives in the server-side session
  (`actingOrgId`). Client-supplied org ids are never read anywhere.

## Multi-tenancy
- Roles: `platform_admin` (org_id NULL), `client_admin`, `client_viewer` —
  enforced by a DB CHECK constraint and `requireRole`/`requireOrgWrite` middleware.
- Every tenant query filters by `org_id` server-side (`tenantScope` middleware +
  `scopedRow` helper). Cross-tenant lookups return 404, indistinguishable from
  "does not exist".
- Suspending an org blocks its users at login *and* at every request, and the
  renewal engine skips suspended orgs.

## ACME
- **Staging directory by default**; `ACME_DIRECTORY=production` or a raw
  `ACME_DIRECTORY_URL` (Pebble in tests) switches it. A banner shows when
  production is active.
- **One ACME account per org per directory** (unique constraint), registered
  with the org's contact email; account key ECDSA P-256, stored encrypted.
- **DNS-01 only**, wildcard + SAN support. `challengePriority: ['dns-01']` and
  a hard error on anything else.
- **Propagation gating**: acme-client's own pre-validation is disabled
  (`skipChallengeVerification`) and replaced with a check against the domain's
  *authoritative* nameservers (NS discovery walking up the name, then direct
  queries). `VERIFY_DNS_SERVER` overrides for tests (challtestsrv).
- **Cleanup**: TXT records deleted in `challengeRemoveFn` *and* a belt-and-braces
  finally block, regardless of outcome.
- **Manual DNS flow**: challenges are parked in `certificates.pending_challenges`
  (jsonb); the UI shows copy-paste records; an operator confirm sets
  `manual_confirmed_at`, the issuance job (polling) resumes, and still waits for
  authoritative propagation. Timeout 45 min.
- **Key types**: ECDSA P-256 default, RSA-2048 optional — per certificate.
- **Rate limits**: issuance in the last 7 days is counted per registered domain
  (small built-in second-level-domain list; documented heuristic, not a full
  public-suffix implementation) and the wizard warns at ≥40 of Let's Encrypt's
  50/week.

## Domain ownership verification
- Token: `certportal-` + 48 hex chars in `_certportal-verify.<fqdn>` TXT.
- Lookup goes to authoritative nameservers, never the local resolver cache.
- Re-verification every 90 days (`DOMAIN_REVERIFY_DAYS`) by the hourly sweep;
  a lapse flips `ownership_verified=false`, pauses renewals (the due-query
  requires verification), and notifies the org.
- SANs on a certificate must equal or be subdomains of the verified domain.

## PAN-OS integration
- **Keypair import**: `type=import&category=keypair&format=pem` with a file of
  cert PEM + chain PEM + AES-256-CBC-encrypted PKCS#8 key, plus a one-time
  random passphrase parameter. This is the documented reliable path and works
  for both ECDSA and RSA keys (PKCS#12 generation in pure JS can't do EC).
  **PAN-OS requires the Superuser role for this import** (private-key import is
  not grantable via a custom admin-role privilege) — so the CertPortal firewall
  account must be a dedicated Superuser. Documented in the README/portal UI.
- **Naming/rotation**: fixed logical object name `certportal-<sanitized-fqdn>`
  per deployment; renewals overwrite the same object so SSL/TLS Service
  Profiles never need editing. Fallback (documented in README): versioned names
  + `type=config&action=set` on the profile.
- **Commit**: full commit by default; per-firewall toggle for partial commit
  scoped to the API admin (`<commit><partial><admin><member>`). Job polled
  every 2s until FIN/FAIL, 10 min timeout.
- **HA**: if a peer address is configured, HA state is queried before deploy;
  deployment goes to the configured member and the log states explicitly that
  PAN-OS config sync propagates the imported cert to the peer. A warning is
  logged when the local member isn't active.
- **GP portal/gateway binding** uses vsys1 xpaths (`localhost.localdomain`/
  `vsys1`) — the common single-vsys case; multi-vsys/Panorama is out of scope
  and documented as such.
- **Post-deploy validation**: TLS connect to a user-supplied `host[:port]`,
  compare served serial with issued serial (normalized hex).
- verify_tls defaults to **true**; disabling it is a per-firewall checkbox with
  a visible warning badge.

## Renewal engine
- Hourly cron (`RENEWAL_CRON`). Due = elapsed lifetime ≥ org's
  `renewal_percent` (default 66% ≈ day 31 of 47). Configurable per org.
- Backoff on failure: 1h, 4h, 12h, 24h, then daily — computed in SQL from
  `renewal_failures` + `last_renewal_attempt`. Notification from the 2nd
  consecutive failure; dashboard shows failing certs prominently.
- Concurrency: global `pg_try_advisory_lock` per sweep + `FOR UPDATE SKIP
  LOCKED` when claiming rows, so N app instances never double-renew.
- Certs stuck in `renewing` (crash mid-run) become eligible again after 2h.

## CNAME delegation (acme-dns pattern)
- The platform serves its own validation zone (`ACME_DNS_ZONE`) from a built-in
  minimal authoritative UDP DNS responder (TXT/SOA/NS/A) backed by the
  `acme_dns_records` table. Enabled with `ACME_DNS_PORT` (0 = off).
- Each domain registered with the `acme_dns_cname` provider gets a stable
  `<uuid>.<zone>` target; the client creates one permanent CNAME from
  `_acme-challenge.<fqdn>`. A "Check CNAME" button validates it against
  authoritative NS. Running an external acme-dns instead is documented.

## Mock / test mode
- `MOCK_PANOS=true` starts an in-process HTTPS XML API honoring keygen, show
  system info, HA state, keypair import (validates passphrase decryption and
  key/cert match!), config set, commit + job polling — plus a TLS "data plane"
  on port+1 that serves the last committed keypair, so post-deploy validation
  is exercised for real.
- E2E runs against Pebble + pebble-challtestsrv (compose `test` profile);
  domain verification and propagation checks point at challtestsrv via
  `VERIFY_DNS_SERVER`.

## Notifications
- Per-org SMTP (encrypted at rest) and/or webhook; global SMTP env fallback
  with the org contact email as recipient. All deliveries logged to
  `notification_log` and shown in the UI. Without any SMTP, events land in the
  app log rather than being dropped silently.

## Billing (SaaS, Phase 1)

- **Feature-flagged**: `BILLING_ENABLED` (default off). Off = the app behaves
  exactly as before — `planForOrg` returns an unrestricted pseudo-plan, no
  limits, no billing UI. Existing/self-hosted installs are unaffected.
- **Flat per-customer tiers** (trial/starter/pro/enterprise) defined in code
  (`services/billing/plans.js`); limits + feature flags per tier, Stripe Price
  IDs from env so the same code runs against test/live Stripe.
- **Grandfathering**: migration defaults existing orgs to `enterprise`
  (unrestricted); new self-serve signups start on `trial` with `trial_ends_at`.
- **org.status stays admin-controlled.** Billing standing is derived from the
  subscription row + trial window (`inGoodStanding`), enforced by a
  `billingGate` middleware on feature routers — but NOT on `/billing` or
  `/account`, so a past-due/expired customer can always reach the page to pay.
  A failed payment sets the subscription `past_due` (which gates features) but
  never flips `organizations.status`, avoiding a lock-out that blocks payment.
- **Stripe**: hosted Checkout for purchase, hosted Customer Portal for card/
  cancel; webhook (`/webhooks/stripe`, raw body, signature-verified, idempotent
  via `billing_events`) mirrors subscription state. All Stripe calls behind a
  lazy client so tests need no keys.
- **Self-serve signup** (`SIGNUP_ENABLED`) creates org + first client_admin and
  starts the trial — the only path that bypasses invite-only onboarding.

## On-prem agent (Phase 2)

- **Outbound-only connector.** Solves the "no external site with API access, no
  inbound" requirement for cloud SaaS. The agent runs in the customer network,
  dials out to the control plane, long-polls for jobs, executes them against
  firewalls over the LAN, and posts results. Nothing inbound to the agent or
  firewall.
- **Protocol**: `POST /api/agent/enroll` (one-time token → long-lived secret),
  `GET /api/agent/jobs` (long-poll lease, ~25s), `POST /api/agent/jobs/:id/result`.
  Bearer `agentId.secret` auth (secret stored sha256). Mounted before
  session/CSRF (machine API, no cookies).
- **Shared executor**: `services/panos/ops.js` runs an operation the same way in
  direct mode (control plane → firewall) and agent mode (agent → firewall), so
  behaviour is identical and new ops are a one-place change. `dispatch.runOp`
  transparently routes based on `firewalls.agent_id`.
- **Job queue**: `FOR UPDATE SKIP LOCKED` lease; payloads envelope-encrypted at
  rest and dropped once the job completes. Firewall creds/cert material are sent
  to the agent per-job over TLS (cloud-held-creds model; agent-held creds is a
  future option).
- **Per-firewall opt-in**: `agent_id` NULL = direct (unchanged behaviour for the
  on-prem app and existing installs); set = via agent.
- **Ops routed through the agent**: connectivity test, keygen, and full
  certificate deployment (import → bindings → commit → poll → post-deploy TLS
  validation). The deploy execution lives in `ops.executeDeploy` and runs on the
  agent (including the validation TLS connect, which happens from inside the LAN);
  `pipeline.runDeployment` only gathers inputs and records the result. So an
  agent-connected firewall gets the complete automated cert lifecycle with zero
  inbound access.

## Misc
- Timestamps display as UTC ISO throughout (ops tool; local-time ambiguity is worse).
- `users` deletion is hard delete; audit log rows persist (org/user ids kept as values).
- Certificates are not revoked at deletion (typically rotation, not compromise);
  revocation is a documented manual step.
