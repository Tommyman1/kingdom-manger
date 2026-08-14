# 👑 Kingdom Manager v1

Kingdom Manager is the control plane for the Kingdom Docker host. It does not replace Docker, ClamAV, CrowdSec, Falco, Wazuh, Trivy, or n8n; it coordinates them.

## What is implemented

- Container inventory and health/state dashboard
- Start, stop, restart, pause/unpause API
- Per-container safety policies
- CPU/network idle sampling
- Unexpected-stop auto-recovery (policy controlled)
- Docker configuration snapshots before disruptive actions
- Quarantine network isolation and network restoration
- Security-event ingestion and decision recording
- Falcosidekick webhook receiver
- Trivy image scans through an isolated runner
- Public-image update checks by pulling without recreating the container
- ClamAV / CrowdSec / Wazuh connectivity status
- Discord + n8n notification hooks
- Persistent SQLite event, policy, scan, decision, and snapshot history
- Automatic Monday weekly report notification
- Token-protected management API/dashboard

## Deliberate safety gates

`auto_isolate` defaults OFF. `auto_update` defaults OFF. A pulled update is never automatically installed in v1. `protected` prevents automatic isolation and some disruptive actions. Container deletion/recreation is intentionally not enabled until a restore test has proven that container's snapshot can be recreated correctly.

This is important: Docker's create-container API cannot safely replay every Compose/Portainer stack from raw inspect data. Kingdom Manager records the snapshot now, but automatic destructive rebuild should be stack-aware before it is enabled.

## Install on Kingdom

```bash
mkdir -p /home/tommytheog/Docker/kingdom-manager
cd /home/tommytheog/Docker/kingdom-manager
# copy the contents of this package here
cp .env.example .env
TOKEN=$(openssl rand -hex 32)
sed -i "s/CHANGE_ME_TO_A_LONG_RANDOM_TOKEN/$TOKEN/" .env
printf '\nKingdom Manager token: %s\n' "$TOKEN"
docker compose up -d --build
```

## Nginx Proxy Manager

- Domain: `kingdom-manager-tail.kingdom.local`
- Scheme: `http`
- Forward hostname: `kingdom-manager`
- Forward port: `8080`
- Websockets: on
- Keep it internal/Tailscale only.

## Connect existing ClamAV / CrowdSec / Wazuh

Kingdom Manager must share a Docker network with a service before it can address that service by container name. Do **not** expose their API ports on the host just to make the integration work. Instead, attach Kingdom Manager to the required internal network or attach the service to `kingdom-manager-internal` when appropriate.

Example:

```bash
docker network connect kingdom-manager-internal clamav
```

For CrowdSec/Wazuh, set their internal URL and API credential in `.env`.

## Falco

Point Falcosidekick's webhook output to:

`http://kingdom-manager:8080/api/security/falco`

Keep Falcosidekick on a network that can reach Kingdom Manager; the endpoint is intended for internal Docker traffic.

## Trivy

The included Trivy runner scans image references from the registry and keeps its vulnerability DB cache in a Docker volume. Custom local-only images that do not exist in a registry cannot be scanned by this runner mode yet.

## API token

The dashboard asks for `KM_API_TOKEN` once and stores it in browser local storage. Do not share the token. For additional defense, keep NPM access restricted to your Tailscale/internal DNS path.

## First policy recommendation

Keep `protected` ON for infrastructure such as Nginx Proxy Manager, Tailscale, Portainer, databases, Kingdom Manager itself, and other stateful services until each recovery path is tested. Enable `auto_isolate` only on containers where losing network access is preferable to continued operation during a critical alert.
