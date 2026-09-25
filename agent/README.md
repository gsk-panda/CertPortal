# CertPortal on-prem agent

A lightweight connector you run **inside the customer network**. It lets the
CertPortal control plane manage firewalls it cannot reach directly — with **no
inbound access to the network or the firewall**.

## How it works

```
   Customer network                         CertPortal control plane (cloud)
 ┌────────────────────┐   outbound HTTPS   ┌──────────────────────────────┐
 │  agent container    │ ─────────────────►│  /api/agent/enroll           │
 │   • enrolls once     │  (agent-initiated)│  /api/agent/jobs  (long-poll)│
 │   • long-polls jobs  │◄─────────────────│  /api/agent/jobs/:id/result  │
 │   • talks to FW/LAN  │                   └──────────────────────────────┘
 └──────────┬─────────┘
            │ HTTPS (LAN)
     ┌──────▼──────┐
     │  PAN-OS FW  │   (management API, never exposed to the internet)
     └─────────────┘
```

The agent authenticates with a one-time enrollment token, receives a long-lived
secret, then repeatedly asks the control plane "any work for me?". When a job
arrives (test a firewall, generate a key, deploy a certificate…) it runs it over
the LAN and posts the result back. Every connection is opened *by the agent*.

## Run it

Create an agent in the portal (**Agents → Add**), copy the enrollment command:

```bash
docker run -d --name certportal-agent --restart unless-stopped \
  -e CONTROL_PLANE_URL=https://certportal.example \
  -e ENROLL_TOKEN=<one-time-token> \
  -e AGENT_NAME="datacenter-1" \
  -v certportal-agent:/data \
  certportal/agent:latest
```

The `/data` volume persists the agent's credentials so it re-uses them on
restart (the enrollment token is single-use). Then, on each firewall's edit
page, set **Connection → Via agent: datacenter-1**.

## Configuration

| Env | Purpose |
|---|---|
| `CONTROL_PLANE_URL` | Base URL of the control plane (required) |
| `ENROLL_TOKEN` | One-time enrollment token (first run only) |
| `AGENT_NAME` | Informational label |
| `AGENT_STATE_FILE` | Credential store (default `/data/agent.json`) |
| `CONTROL_PLANE_INSECURE` | `true` to accept a self-signed control-plane cert |
| `FIREWALL_CA_BUNDLE` | PEM to authenticate firewall mgmt certs when verify-TLS is on |

## Security

- Outbound-only; nothing listens on the agent.
- Credentials are stored `0600` in the state volume.
- Firewall API keys and certificate material are sent to the agent per-job over
  TLS and are dropped from the control plane's job record once the job completes.
- Build the image yourself from this repo to review exactly what runs.
