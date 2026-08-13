# Kingdom Manager v0.1

Kingdom Manager is a standalone Docker lifecycle/security/automation platform for the Kingdom homelab.

## v0.1 scope

- Read-only Docker discovery
- Container status, health, image, network, labels and configuration inspection
- Activity/idle detector framework (conservative: UNKNOWN until a service-specific detector exists)
- Policy engine skeleton
- SQLite state store
- Security adapter slots for ClamAV, CrowdSec, Falco, Wazuh and Trivy
- Workflow migration slots for existing n8n workflows
- Small built-in dashboard
- Restricted Docker socket proxy with POST disabled

v0.1 intentionally cannot update, restart, stop, remove, or recreate containers.

## Deploy

Copy this folder to the server, then from the directory run:

```bash
docker compose up -d --build
```

Check:

```bash
docker ps --filter name=kingdom

docker logs kingdom-manager --tail 100
```

From another container attached to `kingdom-internal`:

```text
http://kingdom-manager:8000/health
```

For browser access, Kingdom Manager is attached to the existing external `proxy` network. In Nginx Proxy Manager create a proxy host pointing to:

```text
kingdom-manager:8000
```

Suggested hostname:

```text
kingdom-manager-tail.kingdom.local
```

Do not publish port 8000 on the host.

## API

- `GET /health`
- `GET /api/containers`
- `GET /api/containers/{name}`
- `GET /api/security`
- `GET /api/workflows`

## Planned build order

1. Service-specific idle detectors: Jellyfin, n8n, Immich, Paperless, ClamAV, generic HTTP services.
2. Registry/update detection.
3. Trivy scan gate for candidate images.
4. Trusted baseline capture and drift detection.
5. Explicit update policy and maintenance windows.
6. Safe updater with rollback. At this stage the socket proxy permissions must be deliberately expanded; never simply set broad Docker API access.
7. Falco/CrowdSec/Wazuh/ClamAV event ingestion.
8. Isolation and evidence-preservation workflow.
9. Trusted rebuild/recovery.
10. Gradual migration of proven n8n workflows.

## Security model

The application never mounts `/var/run/docker.sock` directly. `socket-proxy` is the only service with that mount. POST requests are disabled in v0.1, so Kingdom Manager's Docker access is observational only.

The `kingdom-internal` network is Docker-internal. Kingdom Manager also joins `proxy` solely so Nginx Proxy Manager can reach the dashboard. Remove the `proxy` network and Homepage URL if you want API-only container access.
