# 👑 Kingdom Manager v1.7.0

This release combines the planned **v1.6.2 trust/polish work** with **v1.7 reporting, history, and notifications**.

## What changed

### Automatic database migrations
Kingdom Manager now maintains a schema version in SQLite and automatically repairs the legacy `events` table shape that caused the `ts` / `source NOT NULL` upgrade failures. Before a destructive table migration it creates a SQLite backup in `/data` and preserves the old events table under a versioned `events_legacy_*` name.

You should not need to manually run `ALTER TABLE` for this upgrade.

### Incident workflow
- Incident Center has **Investigate**, **Capture Evidence**, and **Resolve** actions.
- Medium incidents are explicitly shown as needing review even when nothing qualifies as immediate/urgent attention.
- Evidence capture keeps the Docker snapshot + on-demand Trivy evidence flow from v1.6.

### Container Security Drawer
Click a container in the leaderboard or container list to open a focused security drawer showing:
- current container security score and exact risk factors
- trust/risk profile
- networks and mounts
- latest Trivy result
- recent security evidence
- Approved Rebuild / Auto-Isolate / Auto-Restart / Protected controls
- Scan Now, Restart, Isolate, and one-hour Maintenance Mode
- **Mark Expected** for individual Falco rule + container combinations

### Explain My Score
Containers only lose points when the backend can state a real source of the deduction. Correlation deductions now state the Decision Engine risk score and contributing engines instead of saying `No active correlated risk` while subtracting points.

### Trivy status
The card distinguishes the runner from the scheduler. During coverage it can show `SCANNING`, `ERROR`, or the underlying healthy state and displays the scheduler target/error.

### Activity feed
Raw database records are translated into a compact timeline with event-specific icons and summaries.

### Score history
A background sampler records Kingdom Security Score, monitoring confidence, and severity counters. The dashboard includes a 7-day score chart. History is retained for 90 days.

### Security recommendations
Kingdom Manager now generates prioritized recommendations for:
- unavailable core security engines
- running containers that have never been scanned by Trivy
- critical Trivy CVEs
- noisy Falco containers that may need a scoped known-good suppression
- open incidents that require review

### Discord + n8n reporting
Existing Discord and n8n outputs are now first-class notification/reporting channels.

Default behavior:
- live notifications are filtered below `KM_NOTIFY_MIN_SEVERITY` (`high` by default)
- a daily report is generated at 08:00 local time
- a weekly report is generated Monday at 09:00 local time
- manual **Send Daily** and **Send Weekly** buttons are available on the dashboard
- notification/report delivery results are stored in SQLite

No Discord or n8n endpoint is required; both remain optional.

## New environment values

```yaml
KM_NOTIFY_MIN_SEVERITY: "high"
KM_DAILY_REPORT_ENABLED: "true"
KM_DAILY_REPORT_HOUR: "8"
KM_WEEKLY_REPORT_WEEKDAY: "0"
KM_WEEKLY_REPORT_HOUR: "9"
KM_SCORE_HISTORY_INTERVAL_SECONDS: "900"
```

`KM_WEEKLY_REPORT_WEEKDAY` uses Python weekday numbering: Monday `0` through Sunday `6`.

## Safety

Controlled recovery remains approval-gated. `Approved Rebuild` does **not** perform an automatic rebuild by itself. Protected Kingdom core components remain hard-blocked from self-recovery.

Preserve the existing `kingdom-manager-data` and `kingdom-manager-trivy-cache` volumes. Replace the CrowdSec placeholder in `compose.yaml` with your current bouncer key before deployment; do not paste that secret into chat.

## Upgrade verification

After deployment:

```bash
docker ps --filter name=kingdom-manager \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}'

docker logs kingdom-manager --since 5m 2>&1 | \
  grep -iE 'migration|error|exception|traceback|trivy|report'
```

The footer should show **v1.7.0**. Trivy may continue the scan already in progress or choose the next oldest/unscanned running container after restart.
