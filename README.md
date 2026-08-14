# 👑 Kingdom Manager v1.4.0

v1.4.0 fixes sensor health and makes the Decision Engine easier to understand.

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
