# CertPortal

Multi-tenant automation of the SSL/TLS certificate lifecycle for Palo Alto
Networks firewalls, built for the 47-day-certificate era (CA/B Forum SC-081).
Let's Encrypt (DNS-01 only) → automatic renewal → PAN-OS keypair import →
commit → post-deploy TLS validation. Zero manual steps after onboarding.

## Quick start (docker compose)

```bash
cp .env.example .env
# generate secrets
node -e "console.log('MASTER_KEK='+require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('SESSION_SECRET='+require('crypto').randomBytes(24).toString('hex'))"
# edit .env: MASTER_KEK, SESSION_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD

docker compose up -d --build
# → http://localhost:3000  (migrations run automatically; platform admin seeded from env)
```

Sign in with `ADMIN_EMAIL` / `ADMIN_PASSWORD`, create an organization, open it,
and onboard: DNS provider → domain (verify ownership) → firewall → certificate.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP listen port |
| `BASE_URL` | `http://localhost:3000` | Absolute URL used in emails |
| `DATABASE_URL` | — | Postgres connection string |
| `MASTER_KEK` | — (required) | 32 bytes base64; encrypts all secrets at rest |
| `MASTER_KEK_PREVIOUS` | — | Old KEK, set only during rotation |
| `SESSION_SECRET` | — (required) | Session cookie signing |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | — | Platform admin seeded on first boot |
| `ACME_DIRECTORY` | `staging` | `staging` \| `production` \| raw URL |
| `ACME_DIRECTORY_URL` | — | Overrides the above (Pebble in tests) |
| `ACME_INSECURE` | `false` | Skip ACME TLS verification (**Pebble only**) |
| `ACME_DNS_ZONE` | `acme.certportal.example` | CNAME-delegation validation zone |
| `ACME_DNS_PUBLIC_IP` | `192.0.2.1` | A record for `ns1.<zone>` |
| `ACME_DNS_PORT` | `0` (off) | UDP port of the built-in DNS responder |
| `VERIFY_DNS_SERVER` | — | Override resolver for TXT checks (tests) |
| `MOCK_PANOS` / `MOCK_PANOS_PORT` | `false` / `9443` | Embedded fake PAN-OS API |
| `RENEWAL_CRON` | `0 * * * *` | Renewal sweep schedule |
| `RENEWAL_DEFAULT_PERCENT` | `66` | Default renewal threshold (also per-org) |
| `DOMAIN_REVERIFY_DAYS` | `90` | Ownership re-verification interval |
| `SMTP_HOST/PORT/USER/PASS/FROM` | — | Global fallback mail transport |
| `COOKIE_SECURE` | `true` in example | Secure flag on session cookie |
| `DISABLE_SCHEDULER` | `false` | Turn off cron (tests) |

## Switching Let's Encrypt staging → production

Everything defaults to the **staging** directory (untrusted test certs, high
rate limits). When onboarding is proven:

1. Set `ACME_DIRECTORY=production` and restart.
2. Existing certs renew on their normal schedule against production (a new
   ACME account per org is registered automatically for the new directory);
   use **Renew now** on a cert to switch it immediately.
3. Watch the rate-limit warnings in the certificate wizard (50 certs /
   registered domain / week; 5 duplicates / week).

## Network placement

The app must reach:
- **Firewall management interfaces** (HTTPS, usually 443) — put the app in a
  management network or allow it through to mgmt ACLs. PAN-OS "permitted IP"
  lists on the management interface must include the CertPortal host.
- **Outbound 443** to the ACME directory (`acme-v02.api.letsencrypt.org` /
  staging equivalent) and to DNS provider APIs (Cloudflare/AWS/Azure/GoDaddy).
- **Outbound 53** for authoritative DNS lookups (ownership verification and
  propagation checks query the domains' own nameservers directly).
- If CNAME delegation is used, **inbound UDP 53** to the validation zone
  responder (see below).

Post-deploy validation opens a TLS connection from the app to the
GlobalProtect portal/gateway endpoint you configure (e.g. `vpn.client.com:443`).

## PAN-OS admin account for CertPortal

**Importing a certificate keypair (certificate + private key) via the XML API
requires the Superuser role.** PAN-OS deliberately gates private-key import
behind Superuser; there is no narrower admin-role privilege that permits it —
a custom role can authenticate, run operational requests, and commit, but the
keypair import step fails with *"You need superuser privileges to do that."*

Recommended setup:

- Create a **dedicated** administrator (Device → Administrators) with
  **Role = Superuser**, used only by CertPortal. Do not reuse an interactive
  admin login. Onboard it in CertPortal with username/password once — the app
  calls `type=keygen` and stores only the encrypted API key; the password is
  never saved.
- The key is encrypted at rest and every action is in the audit log, so a
  dedicated automation Superuser is the standard trade-off for cert automation.
- Commit scope: if other admins work on the box, enable **partial commit
  scoped to the API user** on the firewall entry in CertPortal so only its own
  changes are committed.

Diagnosing role errors:

| Symptom in CertPortal | Cause | Fix |
|---|---|---|
| Test: *"not authorized for user role"* | Role lacks XML API Operational Requests | Grant it, or use Superuser |
| Deploy: *"You need superuser privileges to do that"* | Account is not a Superuser | Set the account's role to Superuser and commit |
| Test/Deploy: *"Invalid Credential"* | Wrong/mangled API key, or key from a different device | Re-key via username/password in CertPortal |

## CNAME delegation zone setup (acme-dns pattern)

For clients who will not hand over DNS API credentials: they create **one**
permanent CNAME per domain and never touch DNS again.

1. Pick a zone you control, e.g. `acme.certportal.example`, and set
   `ACME_DNS_ZONE=acme.certportal.example`, `ACME_DNS_PORT=5353`,
   `ACME_DNS_PUBLIC_IP=<public IP of this app>`.
2. Publish (in the `certportal.example` zone at your DNS host):
   ```
   acme.certportal.example.      NS   ns1.acme.certportal.example.
   ns1.acme.certportal.example.  A    <public IP of this app>
   ```
3. Expose UDP 53 → the app's `ACME_DNS_PORT` (compose: uncomment the
   `53:5353/udp` port mapping; systemd: `AmbientCapabilities=CAP_NET_BIND_SERVICE`
   and `ACME_DNS_PORT=53`).
4. In CertPortal the client adds a DNS provider of type **CNAME delegation**,
   registers the domain, and creates the CNAME shown on the domain page:
   ```
   _acme-challenge.vpn.client.com.  CNAME  <uuid>.acme.certportal.example.
   ```
   The **Check CNAME** button validates it. All future TXT validations happen
   inside the platform zone.

Alternative: run [acme-dns](https://github.com/joohoi/acme-dns) and point the
delegation there; the built-in responder simply removes that dependency.

## Rotating MASTER_KEK

1. Generate a new key: `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
2. Set `MASTER_KEK=<new>` and `MASTER_KEK_PREVIOUS=<old>`; restart the app
   (decryption transparently falls back to the previous KEK).
3. Run `node scripts/rotate-kek.js` — re-wraps every stored secret's DEK under
   the new KEK (cheap; bulk data untouched).
4. Remove `MASTER_KEK_PREVIOUS`, restart. Store the old key offline until
   backups made under it have aged out.

## Backup & restore

- **Postgres is the only state.** `pg_dump certportal` on a schedule; restore
  with `pg_restore`/`psql` into a fresh database, then start the app (migrations
  are idempotent).
- A database backup is only useful together with the `MASTER_KEK` in use when
  it was taken — store the KEK in a secret manager, separately from the dumps.
- Private keys, firewall API keys, DNS credentials, TOTP seeds and ACME account
  keys are all encrypted in the dump; everything else is plaintext.
- The `session` table can be excluded (`--exclude-table-data session`).

## Mock mode & tests

```bash
# unit tests (needs the compose db running)
docker compose up -d db
npm test

# full E2E: Pebble (local ACME CA) + challtestsrv (DNS) + mock PAN-OS
docker compose --profile test up -d db pebble challtestsrv
npm run test:e2e     # prints PASS/FAIL per stage
```

No Docker? The same stack runs natively: Postgres on `localhost:5432`
(user/pass/db `certportal`), plus the official Windows/Linux release binaries of
[pebble](https://github.com/letsencrypt/pebble/releases):

```bash
pebble-challtestsrv -dnsserver :8053 -http01 "" -https01 "" -tlsalpn01 "" -doh "" -management :8055
PEBBLE_VA_NOSLEEP=1 pebble -config <config with local cert paths> -dnsserver 127.0.0.1:8053 -strict=false
npm run test:e2e
```

`MOCK_PANOS=true` on a normal run starts the embedded fake PAN-OS XML API
(https on `MOCK_PANOS_PORT`, fake GP portal TLS on port+1) so the whole
lifecycle can be demonstrated with no hardware: onboard the firewall as
`https://localhost:9443` with any username/password (verify TLS off), and use
`localhost:9444` as the post-deploy validation endpoint.

## Internal (on-prem) deployment

To run CertPortal entirely inside your network — no external site with API
access, no inbound connections — use the internal kit in
[`deploy/internal/`](deploy/internal/README.md). The firewall is reached over
the LAN, the app makes only outbound 443/53 connections (Let's Encrypt + DNS
API), and the portal is served over HTTPS from Caddy's internal CA. Set
`FIREWALL_CA_BUNDLE` to authenticate the firewall's management certificate.

## RHEL 9 / systemd (no Docker)

See `deploy/certportal.service` — install Node 20 + PostgreSQL 15/16, create
the `certportal` user, `npm ci --omit=dev`, fill `.env`, enable the unit.

## Architecture notes

- DNS-01 is mandatory (GP portals can't serve HTTP-01; wildcards need DNS-01).
- Renewal threshold defaults to 66% of lifetime (≈ day 31 for 47-day certs);
  configurable per organization.
- PAN-OS deployments overwrite a fixed certificate object name
  (`certportal-<fqdn>`) so SSL/TLS Service Profiles never need editing on
  renewal. If an overwrite is ever rejected, fall back to versioned names +
  a `config action=set` of `<certificate>` on the profile (the client library
  already exposes `setSslTlsProfileCert`).
- See `DECISIONS.md` for every default and trade-off.
