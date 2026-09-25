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

Create an agent in the portal (**Agents → Add**) and copy the install command it
shows. It shows one command for Windows and one for Docker.

### Windows (MSI)

Download `certportal-agent.msi` (linked from the Agents page; built by the
`Windows agent MSI` workflow and attached to `agent-v*` releases). Then, in an
administrator PowerShell:

```powershell
msiexec /i certportal-agent.msi CONTROL_PLANE_URL=https://certportal.example ENROLL_TOKEN=<one-time-token> AGENT_NAME="datacenter-1" /qb
```

Use `/qn` instead of `/qb` for a fully silent install (e.g. from Intune or
SCCM). The MSI:

- installs `certportal-agent.exe` (the agent with its own Node runtime, no
  prerequisites) and the WinSW service wrapper to `C:\Program Files\CertPortal\Agent`
- registers and starts the **CertPortal Agent** service (automatic start,
  `LocalService` account, restarts 10s after any crash)
- writes `CONTROL_PLANE_URL` / `ENROLL_TOKEN` / `AGENT_NAME` to
  `C:\ProgramData\CertPortal\Agent\config.json` and restricts that folder to
  SYSTEM, Administrators and LocalService. The token is removed from the file
  once the agent enrolls and is kept out of the install log.
- trusts the Windows certificate store (corporate CAs, TLS-inspecting proxies)
  and honours a machine-wide `HTTPS_PROXY`

Logs are in `C:\ProgramData\CertPortal\Agent\logs`. Installing a newer MSI
upgrades in place and keeps the enrollment; passing a new `ENROLL_TOKEN`
re-enrolls. Uninstalling (Apps & features, or `msiexec /x`) removes the service
and the ProgramData folder, credentials included; delete the agent in the
portal as well.

Build it yourself on Linux or macOS with Node 24 and msitools
(`apt install wixl msitools`):

```bash
cd agent && npm install && node windows/build.js --msi   # -> windows/dist/certportal-agent.msi
```

`agent/windows/test/install-test.ps1` installs the MSI against a mock control
plane and checks enrollment, permissions, crash restart and uninstall. CI runs
it on every change.

### Docker

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
| `AGENT_STATE_FILE` | Credential store (default `/data/agent.json`, Windows `%ProgramData%\CertPortal\Agent\agent.json`) |
| `AGENT_CONFIG_FILE` | Optional JSON file with any of these keys; env wins (default `config.json` next to the state file) |
| `CONTROL_PLANE_INSECURE` | `true` to accept a self-signed control-plane cert |
| `FIREWALL_CA_BUNDLE` | PEM to authenticate firewall mgmt certs when verify-TLS is on |

## Security

- Outbound-only; nothing listens on the agent.
- Credentials are stored `0600` in the state volume (on Windows, in a folder
  only SYSTEM, Administrators and the service account can read).
- Firewall API keys and certificate material are sent to the agent per-job over
  TLS and are dropped from the control plane's job record once the job completes.
- Build the image yourself from this repo to review exactly what runs.
