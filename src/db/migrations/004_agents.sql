-- On-prem agents (cloud control plane + outbound-only agent architecture).
CREATE TABLE agents (
  id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id               uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name                 text NOT NULL,
  enrollment_token_hash text,             -- present until the agent enrolls, then cleared
  agent_secret_hash    text,              -- sha256 of the long-lived agent secret
  status               text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','offline')),
  version              text,
  last_seen            timestamptz,
  created_at           timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, name)
);
CREATE INDEX agents_org_idx ON agents(org_id);

CREATE TABLE agent_jobs (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
  org_id            uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  op                text NOT NULL,
  payload_encrypted text,                 -- envelope-encrypted JSON (may carry secrets)
  status            text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued','leased','done','failed')),
  result            jsonb,
  error             text,
  leased_at         timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now(),
  completed_at      timestamptz
);
CREATE INDEX agent_jobs_lease_idx ON agent_jobs(agent_id, status, created_at);

-- A firewall may be reached via an agent (LAN, outbound-only) instead of
-- directly from the control plane. NULL = direct connection (legacy/on-prem app).
ALTER TABLE firewalls ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;
