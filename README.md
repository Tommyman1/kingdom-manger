# 👑 Kingdom Manager v1.4.1

v1.4.1 fixes sensor health and makes the Decision Engine easier to understand.

## Changes

- Falco health is now based on whether Kingdom Manager can reach Falco's private health listener on `falco:8765`, not whether a security alert happened recently.
- Falco alert freshness is shown separately as `Last event`.
- Falco's 24-hour view groups the noisiest rules so repeated Postgres/Pi-hole/NetAlertX alerts are easier to recognize as repeated behavior.
- The Decision Engine now shows Low/record decisions and a human-readable explanation when it deliberately refuses to escalate one-source noise.
- Trivy gets a low-impact automatic scanner: one running container per hour, oldest/unscanned first, with a 7-day rescan window.
- Trivy still cannot isolate a container by itself. CVEs are exposure evidence and normally lead to `recommend_update` or correlation context.

## Default automatic Trivy cadence

```text
Start after Kingdom Manager has been up ~2 minutes
Scan at most one running container per hour
Do not rescan the same container for 7 days
Skip Kingdom Manager's own control/scanner containers
```

Tune with:

```yaml
TRIVY_AUTO_SCAN_ENABLED: "true"
TRIVY_AUTO_SCAN_EVERY_SECONDS: "3600"
TRIVY_RESCAN_SECONDS: "604800"
```

## Important secrets

Preserve your existing `KM_API_TOKEN`, `CROWDSEC_API_KEY`, and `FALCO_WEBHOOK_SECRET` when upgrading. If a key has been exposed, rotate it before deployment.

## Expected security panel

```text
ClamAV     ok
CrowdSec   ok
Falco      ok   (health of sensor)
Trivy      ok
```

A quiet Falco sensor can remain `ok`; its last-event age is displayed separately.


## v1.4.1 live-test fixes

- Sentinel color now follows the security score: green → lime → amber → orange → red.
- Core sensor outages reduce monitoring confidence; the dashboard cannot claim 100/100 while Falco, ClamAV, CrowdSec, or Trivy is unavailable.
- Falco sample stack explicitly enables the private health listener on `8765`; no host port is published.
- Trivy automatic coverage starts after 45 seconds, scans at most one container every 30 minutes, and records scheduler state, last success, and last error in the dashboard.
- Trivy scan failures are visible instead of silently leaving `Scans (24h): 0`.

Keep your existing `kingdom-manager-data` volume and replace the placeholder CrowdSec key with your current rotated bouncer key before deployment.

## v1.6.1 — UI Recovery Policies + Incident Response

This release merges the planned v1.5 investigation layer and v1.6 recovery layer.

New capabilities:
- Incident Center: medium/high/critical correlations become persistent incidents.
- Evidence Vault: capture Docker state plus an on-demand Trivy scan into the incident record.
- Explain My Score endpoint and dashboard panel.
- Maintenance mode per container so planned work is recorded without escalating risk.
- Approval-gated recovery plans with a 15-minute default approval window.
- Dedicated recovery Docker socket proxy. DELETE access is isolated from the normal manager proxy.
- Recovery flow: snapshot -> isolate -> pull image -> recreate -> start -> Trivy verification.
- Hard protection prevents Kingdom Manager and its socket/Trivy helper containers from self-rebuild.

### Recovery safety
Recovery is OFF per container by default. To create a recovery plan, the container policy must have `allow_rebuild=true` and `protected=false`. Creating a plan does not execute it. Execution requires a separate authenticated `approve-and-run` request before the plan expires.

Back up persistent application data before enabling rebuilds. The recovery engine recreates container configuration; it does not repair corrupted application data inside bind mounts or named volumes.


### v1.6.1 recovery-policy UI
Recovery permissions are now managed directly from **Container Life & Controls**. Each container has database-backed toggles for **Approved Rebuild**, **Auto-Isolate**, **Auto-Restart**, and **Protected**. You do not need to add `allow_rebuild=true` labels to every Docker Compose file.

`Approved Rebuild` only permits a separately approved recovery plan to recreate that container; it does not enable automatic destructive recovery. `Protected` blocks isolation/rebuild actions until you deliberately disable protection.
