-- CertPortal initial schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE organizations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name          text NOT NULL UNIQUE,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
  contact_email text NOT NULL,
  renewal_percent integer NOT NULL DEFAULT 66 CHECK (renewal_percent BETWEEN 10 AND 95),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid REFERENCES organizations(id) ON DELETE CASCADE, -- NULL => platform admin
  email         text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  role          text NOT NULL CHECK (role IN ('platform_admin','client_admin','client_viewer')),
  totp_secret   text,            -- encrypted; NULL => 2FA disabled
  last_login    timestamptz,
  created_at    timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT users_org_role CHECK (
    (role = 'platform_admin' AND org_id IS NULL) OR
    (role <> 'platform_admin' AND org_id IS NOT NULL)
  )
);
CREATE INDEX users_org_idx ON users(org_id);

CREATE TABLE password_reset_tokens (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash text NOT NULL,
  expires_at timestamptz NOT NULL,
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE firewalls (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id           uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name             text NOT NULL,
  mgmt_address     text NOT NULL,
  api_key_encrypted text NOT NULL,
  panos_version    text,
  serial           text,
  hostname         text,
  ha_peer_address  text,
  verify_tls       boolean NOT NULL DEFAULT true,
  partial_commit   boolean NOT NULL DEFAULT false,
  api_username     text,          -- admin name owning the API key (for partial commits)
  last_seen        timestamptz,
  status           text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown','ok','unreachable','auth_failed')),
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);
CREATE INDEX firewalls_org_idx ON firewalls(org_id);

CREATE TABLE dns_providers (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  type                  text NOT NULL CHECK (type IN ('cloudflare','route53','azure_dns','godaddy','acme_dns_cname','manual')),
  credentials_encrypted text,
  label                 text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, label)
);
CREATE INDEX dns_providers_org_idx ON dns_providers(org_id);

CREATE TABLE domains (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id             uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  fqdn               text NOT NULL,
  dns_provider_id    uuid REFERENCES dns_providers(id) ON DELETE SET NULL,
  ownership_verified boolean NOT NULL DEFAULT false,
  verification_token text NOT NULL,
  verified_at        timestamptz,
  -- acme-dns style CNAME delegation: per-domain slug under the platform zone
  acme_dns_subdomain text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, fqdn)
);
CREATE INDEX domains_org_idx ON domains(org_id);

CREATE TABLE acme_accounts (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id                uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  directory_url         text NOT NULL,
  account_url           text,
  account_key_encrypted text NOT NULL,
  email                 text NOT NULL,
  created_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, directory_url)
);

CREATE TABLE certificates (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id               uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  domain_id            uuid NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
  san_list             jsonb NOT NULL DEFAULT '[]',
  key_type             text NOT NULL DEFAULT 'ecdsa_p256' CHECK (key_type IN ('ecdsa_p256','rsa_2048')),
  acme_account_id      uuid REFERENCES acme_accounts(id) ON DELETE SET NULL,
  status               text NOT NULL DEFAULT 'pending'
                       CHECK (status IN ('pending','issued','deployed','renewing','failed','revoked')),
  not_before           timestamptz,
  not_after            timestamptz,
  serial               text,
  cert_pem             text,
  key_pem_encrypted    text,
  chain_pem            text,
  auto_renew           boolean NOT NULL DEFAULT true,
  last_renewal_attempt timestamptz,
  renewal_failures     integer NOT NULL DEFAULT 0,
  last_error           text,
  -- manual DNS-01 flow: challenge TXT records awaiting operator confirmation
  pending_challenges   jsonb,
  manual_confirmed_at  timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX certificates_org_idx ON certificates(org_id);
CREATE INDEX certificates_renewal_idx ON certificates(status, not_after);

CREATE TABLE deployments (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  certificate_id   uuid NOT NULL REFERENCES certificates(id) ON DELETE CASCADE,
  firewall_id      uuid NOT NULL REFERENCES firewalls(id) ON DELETE CASCADE,
  panos_cert_name  text NOT NULL,
  ssl_tls_profile  text,
  gp_portal        text,
  gp_gateway       text,
  validate_endpoint text,        -- host[:port] TLS-checked post-deploy
  deployed_at      timestamptz,
  commit_job_id    text,
  status           text NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','importing','committing','validating','deployed','failed')),
  last_error       text,
  validation_ok    boolean,
  created_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (certificate_id, firewall_id)
);
CREATE INDEX deployments_cert_idx ON deployments(certificate_id);

CREATE TABLE audit_log (
  id          bigserial PRIMARY KEY,
  org_id      uuid,
  user_id     uuid,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  detail      jsonb,
  ip          text,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_org_idx ON audit_log(org_id, created_at DESC);
-- append-only: revoke UPDATE/DELETE from app role happens operationally; enforce via trigger
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END; $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
  FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TABLE notification_settings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id        uuid NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  smtp_encrypted text,           -- JSON {host,port,user,pass,from,to} encrypted
  webhook_url   text,
  events        jsonb NOT NULL DEFAULT '["renewal_success","renewal_failure","deployment_failure","cert_expiring_no_automation","domain_verification_lapsed"]',
  updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_log (
  id         bigserial PRIMARY KEY,
  org_id     uuid,
  event      text NOT NULL,
  channel    text NOT NULL,
  subject    text,
  ok         boolean NOT NULL,
  detail     text,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- acme-dns CNAME-delegation TXT store served by the built-in DNS responder
CREATE TABLE acme_dns_records (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subdomain  text NOT NULL,      -- <uuid> under the platform validation zone
  txt_value  text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX acme_dns_records_sub_idx ON acme_dns_records(subdomain);

-- session store (connect-pg-simple)
CREATE TABLE IF NOT EXISTS "session" (
  "sid"    varchar NOT NULL COLLATE "default" PRIMARY KEY,
  "sess"   json NOT NULL,
  "expire" timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "session" ("expire");
