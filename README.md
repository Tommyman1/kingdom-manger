# 👑 Kingdom Manager v0.3

Kingdom Manager is a standalone, self-hosted Docker lifecycle, security, and automation platform for a trusted local homelab.

> ⚠️ **Security notice:** Kingdom Manager is designed to run on a trusted local network, VPN, or Tailscale network. Do **not** expose it directly to the public Internet. v0.3 can store service API credentials for monitoring. Those credentials are encrypted at rest, masked in the UI, and should be limited to the minimum read permissions needed. A future Kingdom Manager with Docker mutation permissions will be a highly privileged service.

## v0.3 scope

- Read-only Docker discovery through a restricted Docker socket proxy
- Container classification and Compose stack recognition
- Conservative safe-to-interrupt policy engine
- Persistent idle/grace state
- Integration framework with four permission modes: `OBSERVE`, `MONITOR`, `MANAGE`, `PROTECTED`
- Built-in Jellyfin activity integration
- Built-in n8n execution-state integration
- Generic HTTP JSON activity integration for future services
- Manual credential entry; no global secret harvesting
- Credentials encrypted with Fernet and stored in SQLite
- Automatic local encryption key at `/data/integration.key` when no key is supplied
- Integration test UI at `/integrations`
- Docker mutations remain disabled

## Security model

`kingdom-manager` never mounts `/var/run/docker.sock` directly. `kingdom-socket-proxy` is the only service with that mount and `POST=0` remains enabled, preventing Kingdom Manager from changing Docker through the proxy in this release.

For service APIs, use the least privilege possible. Kingdom Manager generally only needs enough access to answer questions such as "is anyone actively using this service?" or "is a job running?". Do not give it user-management, deletion, configuration-change, or administrative scopes unless a future feature explicitly requires them.

The default encryption key is generated inside the persistent `kingdom-manager-data` volume. Back up that volume/key with the database; losing the key means stored integration credentials cannot be decrypted. Never commit `/data/integration.key`, `.env`, API keys, tokens, or production credentials to GitHub.

## Deploy in Portainer

Use the repository as a Git-backed Portainer stack or build the image on the Docker host. The app uses internal port `8000`; do not publish it on the host. Nginx Proxy Manager can reach `kingdom-manager:8000` on the external `proxy` Docker network.

Keep these settings in v0.3:

```yaml
POST: "0"
ENABLE_MUTATIONS: "false"
```

After deployment, open:

```text
https://kingdom-manager-tail.kingdom.local/integrations
```

## Add Jellyfin

In **Integrations → Add integration**:

```text
Type: Jellyfin
Name: Jellyfin
Container: jellyfin
URL: http://jellyfin:8096
Permission: MONITOR
API key: <a read-only/minimum-access Jellyfin API key>
```

Press **Test** after saving. When the test succeeds, the dashboard activity engine will use Jellyfin session information and the existing 30-minute Jellyfin idle grace period.

## Add n8n

```text
Type: n8n
Name: n8n
Container: n8n
URL: http://n8n:5678
Permission: MONITOR
API key: <n8n API key with only the access needed to read executions>
```

Kingdom Manager only performs GET requests in the current n8n adapter.

## Add an unsupported service

Use **Generic HTTP** when a service exposes a JSON status endpoint.

Example response:

```json
{
  "jobs": {
    "running": 2
  }
}
```

Configure:

```text
URL: http://my-service:3000
Status path: /api/status
JSON field: jobs.running
Busy comparison: >
Value: 0
```

Kingdom Manager then treats `jobs.running > 0` as busy. An optional bearer token can be stored for authenticated GET endpoints.

## API

- `GET /health`
- `GET /api/containers`
- `GET /api/containers/{name}`
- `GET /api/stacks`
- `GET /api/integrations`
- `POST /api/integrations/{id}/test`
- `GET /api/security`
- `GET /api/workflows`

## Planned next steps

1. Add built-in Immich, Paperless, Navidrome, Audiobookshelf, and other activity adapters.
2. Add per-integration configurable idle grace periods.
3. Add update detection while staying read-only.
4. Add Trivy candidate-image scanning.
5. Add trusted container baselines and drift detection.
6. Add authenticated Kingdom Manager admin access before Docker mutation capability.
7. Only then add carefully scoped update/recreate/rollback permissions.
