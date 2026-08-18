# Kingdom Manager v3.1.1 LTS

Kingdom Manager is a self-hosted Docker security and lifecycle control plane for a private homelab. v3.1 LTS consolidates the v3 update/rollback engine with disaster recovery validation, configuration drift detection, dependency mapping, backup-awareness, system simulation/validation, automated safe incident playbooks, and richer Discord notifications.

## Highlights

- Falco + Trivy + ClamAV + CrowdSec correlation.
- Five-dimension Kingdom Security Score: Threat, Vulnerability, Exposure, Monitoring, Trust.
- Scoped known-good approvals and adaptive Falco baselines.
- Incident investigation, evidence capture, playbooks, quarantine, and approval-gated recovery.
- Staged auto-update engine with immutable image/config rollback.
- Optional Portainer or mounted Compose snapshot capture.
- Disaster Recovery Center with non-destructive rollback dry-run checks.
- Stateful update backup-awareness.
- Configuration drift detection for privilege, ports, mounts, capabilities, networks, and other Docker configuration.
- Dependency map from shared networks and volumes.
- System Validation and non-destructive simulations.
- Discord embeds for security, update, rollback, sensor failure/recovery, and scheduled reports.
- Global maintenance mode to pause lifecycle/update automation during planned work.

## Safe defaults

```yaml
KM_PLAYBOOK_AUTO_ISOLATE: "false"
KM_PLAYBOOK_AUTO_RECOVER: "false"
KM_UPDATE_AUTO_APPLY: "false"
KM_UPDATE_ALLOW_STATEFUL: "false"
```

Safe investigation and staging can be automatic; high-impact operations remain gated until you deliberately opt in.

## Upgrade

Preserve:

```text
kingdom-manager-data
kingdom-manager-trivy-cache
```

The schema advances automatically to v15. The application creates database backups during destructive schema migration paths.

## Manual

Read `MANUAL.md` or the included **Kingdom Manager v3.1 LTS Operations Manual.pdf** before enabling automatic update application or destructive incident automation.

## First validation

```bash
curl -s http://127.0.0.1:8080/ready

TOKEN="$(docker exec kingdom-manager printenv KM_API_TOKEN)"
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:8080/api/system/validate
```

Then test Discord from the dashboard and perform one staged update + rollback on a disposable Ring-1 service.

## v3.1.1 Reliability & UI Audit

v3.1.1 hardens the v3.1 LTS control plane without changing the database schema.

Key changes:
- Lightweight `/api/auth/verify` unlock path; login no longer waits for Docker inventory or score evaluation.
- Shared persistent Docker HTTP client with bounded connection pooling and safe GET-only retry.
- Cached running/full container inventory with last-good fallback during transient Docker timeouts.
- Cached core sensor probes and short-lived security-score snapshots to eliminate duplicate expensive work.
- Progressive dashboard loading: core security state renders even if secondary history/report/container calls are delayed.
- Non-JSON proxy/backend responses are detected and reported clearly instead of producing `Unexpected token '<'`.
- Duplicate action guards, disabled/loading button states, and consistent button styling.
- Incident Investigate no longer triggers a second full dashboard refresh merely by marking the incident investigating.
- Incident `Scan Now`, evidence capture, and safe playbook calls have long-operation timeouts and explicit progress state.
- Dedicated `trivy-exec-proxy` restores Trivy command execution while keeping `EXEC=0` on the general Docker proxy.
- New `/api/system/performance` endpoint exposes cache age/coverage for troubleshooting.

### Deployment note
Keep your existing `kingdom-manager-data` and `kingdom-manager-trivy-cache` volumes. If your live compose contains Discord/CrowdSec credentials, copy those values into the v3.1.1 compose (or preferably an env/secrets mechanism) before redeploying; the distributed compose intentionally contains placeholders.
