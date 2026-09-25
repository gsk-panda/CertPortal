# CertPortal — internal (on-prem) deployment

Runs CertPortal entirely inside your network as a Docker container. Designed to
satisfy IT security: **no external site has API access, and no inbound
connections are required.**

## Security model

```
        Internal LAN                          Internet (outbound 443 only)
  ┌───────────────────────┐
  │  Docker host           │   HTTPS (LAN)     ┌──────────────┐
  │  ┌─────────┐  ┌──────┐ │ ───────────────►  │  PAN-OS FW   │  (mgmt API, LAN)
  │  │ Caddy   │  │ app  │ │                   └──────────────┘
  │  │ :443    │──│:3000 │ │ ───────────────►  Let's Encrypt (issue/renew)
  │  └─────────┘  └──────┘ │ ───────────────►  DNS provider API (Cloudflare…)
  │        │      ┌──────┐ │ ───────────────►  DNS resolvers (validation)
  │   LAN users   │  db  │ │
  │               └──────┘ │
  └───────────────────────┘
```

- **No inbound from the internet.** Only Caddy's 80/443 are open, and only to
  LAN users browsing the portal.
- **The firewall is reached over the LAN.** Its management interface is never
  exposed publicly; the API key is generated and stored only on this host.
- **Outbound egress to allow** from the Docker host:
  - TCP 443 → `acme-v02.api.letsencrypt.org` (+ staging) and your DNS provider's
    API host (e.g. `api.cloudflare.com`)
  - UDP/TCP 53 → DNS (ownership + propagation checks)
  - TCP 443 (or your mgmt port) → the firewall management interface, on the LAN
  - optional: your internal SMTP relay

## Prerequisites

- A Linux (or Windows) host with Docker Engine + Compose v2.
- An internal DNS name for the portal (e.g. `certportal.corp.example`) pointing
  at this host, and a **public** DNS provider account (Cloudflare/Route53/…) for
  the domains whose certificates you manage — DNS-01 validation uses its API.

## Setup

```bash
cd deploy/internal
cp .env.internal.example .env

# generate secrets
node -e "console.log('MASTER_KEK='+require('crypto').randomBytes(32).toString('base64'))"
node -e "console.log('SESSION_SECRET='+require('crypto').randomBytes(24).toString('hex'))"
# edit .env: paste those, set POSTGRES_PASSWORD, ADMIN_*, PORTAL_HOSTNAME, BASE_URL

docker compose up -d --build
```

Browse to `https://<PORTAL_HOSTNAME>` and sign in with `ADMIN_EMAIL` /
`ADMIN_PASSWORD`.

### Trusting the portal certificate

Caddy issues the portal's cert from its own internal CA. To make browsers trust
it, distribute Caddy's root once (or click through the warning on the LAN):

```bash
docker compose cp caddy:/data/caddy/pki/authorities/local/root.crt ./certportal-root.crt
# push certportal-root.crt to clients via GPO / MDM, or import manually
```

## Secure connection to the firewall (recommended)

By default a firewall added with "verify TLS" **off** connects over HTTPS but
doesn't authenticate the mgmt certificate. To authenticate it:

1. Export the firewall's **management certificate** (Device → Certificate
   Management → Certificates → export the cert serving the mgmt interface), or
   your internal CA that signed it, as PEM.
2. Save it to `deploy/internal/ca/firewall-ca.pem`.
3. In `.env`, set `FIREWALL_CA_BUNDLE=/ca/firewall-ca.pem` and
   `docker compose up -d`.
4. When adding/editing the firewall in the portal, leave **Verify TLS on**.
   The mgmt cert's CN/SAN must match the address you use (use the hostname the
   cert is issued for; if you connect by IP the cert needs an IP SAN).

Best long-term option: once CertPortal is running, issue a certificate for the
firewall's management FQDN and deploy it to the mgmt interface, then verify
against a public root.

## PAN-OS account

The firewall account CertPortal uses must be a **dedicated Superuser** (PAN-OS
requires Superuser to import a certificate keypair). Onboard it with
username/password once — CertPortal calls keygen and stores only the encrypted
key. See the main README for the admin-account details.

## Backup

State lives in the `pgdata` volume plus your `MASTER_KEK`. Schedule
`docker compose exec db pg_dump -U certportal certportal` and store the dump
together with a copy of `MASTER_KEK` kept in a separate secret store.

## Staging → production

`ACME_DIRECTORY=staging` by default (untrusted test certs, high limits). When
onboarding is proven, set `ACME_DIRECTORY=production`, `docker compose up -d`,
and click **Renew now** on each certificate.
