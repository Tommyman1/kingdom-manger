# Kingdom Manager v3.2.1 — Portainer Source-of-Truth Updates

## Goal
Keep Portainer-managed stacks authoritative during updates and rollback.

## Changes
- Auto-maps a container to its Portainer stack using `com.docker.compose.project`.
- Captures the exact Portainer StackFileContent plus stack ID, endpoint ID, service name and stack environment.
- Update apply redeploys through Portainer `PUT /api/stacks/{id}?endpointId=...`.
- Sends the unchanged saved stack content with `pullImage=true`; all volumes, networks, labels, environment and other Compose settings remain defined by Portainer.
- Post-deploy health observation verifies the recreated container is running and not unhealthy.
- Verifies the new container actually uses the candidate image ID before declaring success.
- Failed update automatically redeploys the original saved Portainer stack file.
- Manual rollback also restores through Portainer when the snapshot is Portainer-backed.
- Docker-inspect recreation remains a fallback for containers not managed by Portainer.
- Local Build containers remain excluded from registry auto-update.

## Configuration
Set:
- `PORTAINER_URL`
- `PORTAINER_API_KEY`

Optional:
- `PORTAINER_ENDPOINT_ID`
- `PORTAINER_STACK_ID` (fallback only)
- `PORTAINER_VERIFY_TLS`
- `KM_COMPOSE_SNAPSHOT_PATH`

No destructive database migration. Schema v17 adds `config_snapshots.stack_meta_json`.
